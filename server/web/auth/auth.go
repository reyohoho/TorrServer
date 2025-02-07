package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"unsafe"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"server/log"
	"server/settings"
)

var authAccounts atomic.Value

func SetupAuth(engine *gin.Engine) {
	if !settings.HttpAuth {
		return
	}
	
	loadAccounts()

	engine.Use(func(c *gin.Context) {
		accs := authAccounts.Load().(gin.Accounts)
		if accs == nil {
			c.AbortWithStatus(401)
			return
		}
		BasicAuth(accs)(c)
	})
	
	go watchAccountsFile()
}

func loadAccounts() {
	accs := getAccounts()
	if accs != nil {
		authAccounts.Store(accs)
		log.TLogln("Auth accounts updated")
	}
}

func getAccounts() gin.Accounts {
	buf, err := os.ReadFile(filepath.Join(settings.Path, "accs.db"))
	if err != nil {
		log.TLogln("Error reading accs.db:", err)
		return nil
	}
	var accs gin.Accounts
	err = json.Unmarshal(buf, &accs)
	if err != nil {
		log.TLogln("Error parsing accs.db:", err)
		return nil
	}
	return accs
}

func watchAccountsFile() {
	accsPath := filepath.Join(settings.Path, "accs.db")
	var lastModTime time.Time

	for {
		time.Sleep(5 * time.Second)

		fileInfo, err := os.Stat(accsPath)
		if err != nil {
			log.TLogln("Error accessing accs.db:", err)
			continue
		}

		if fileInfo.ModTime().After(lastModTime) {
			log.TLogln("Detected change in accs.db, updating auth...")
			loadAccounts()
			lastModTime = fileInfo.ModTime()
		}
	}
}

type authPair struct {
	value string
	user  string
}
type authPairs []authPair

func (a authPairs) searchCredential(authValue string) (string, bool) {
	if authValue == "" {
		return "", false
	}
	for _, pair := range a {
		if pair.value == authValue {
			return pair.user, true
		}
	}
	return "", false
}

func BasicAuth(accounts gin.Accounts) gin.HandlerFunc {
	pairs := processAccounts(accounts)
	return func(c *gin.Context) {
		c.Set("auth_required", true)

		user, found := pairs.searchCredential(c.Request.Header.Get("Authorization"))
		if found {
			c.Set(gin.AuthUserKey, user)
		}
	}
}

func CheckAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !settings.HttpAuth {
			return
		}

		if _, ok := c.Get(gin.AuthUserKey); ok {
			return
		}

		c.Header("WWW-Authenticate", "Basic realm=Authorization Required")
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func processAccounts(accounts gin.Accounts) authPairs {
	pairs := make(authPairs, 0, len(accounts))
	for user, password := range accounts {
		value := authorizationHeader(user, password)
		pairs = append(pairs, authPair{
			value: value,
			user:  user,
		})
	}
	return pairs
}

func authorizationHeader(user, password string) string {
	base := user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString(StringToBytes(base))
}

func StringToBytes(s string) (b []byte) {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
