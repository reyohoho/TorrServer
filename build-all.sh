#!/bin/bash
export CGO_ENABLED=0

PLATFORMS=(
  'linux/amd64'
)

type setopt >/dev/null 2>&1

set_goarm() {
  if [[ "$1" =~ arm([5,7]) ]]; then
    GOARCH="arm"
    GOARM="${BASH_REMATCH[1]}"
    GO_ARM="GOARM=${GOARM}"
  else
    GOARM=""
    GO_ARM=""
  fi
}
# use softfloat for mips builds
set_gomips() {
  if [[ "$1" =~ mips ]]; then
    if [[ "$1" =~ mips(64) ]]; then MIPS64="${BASH_REMATCH[1]}"; fi
    GO_MIPS="GOMIPS${MIPS64}=softfloat"
  else
    GO_MIPS=""
  fi
}

GOBIN="go"

$GOBIN version

LDFLAGS="'-s -w -checklinkname=0'"
FAILURES=""
ROOT=${PWD}
OUTPUT="${ROOT}/dist/TorrServer"

#### Build web
echo "Build web"
export NODE_OPTIONS=--openssl-legacy-provider
$GOBIN run gen_web.go

#### Update api docs
echo "Build docs"
$GOBIN install github.com/swaggo/swag/cmd/swag@latest
cd "${ROOT}/server" || exit 1
swag init -g web/server.go --parseInternal --parseDepth 5

#### Build server
echo "Build server"
cd "${ROOT}/server" || exit 1
$GOBIN clean -i -r -cache # --modcache
$GOBIN mod tidy

BUILD_FLAGS="-ldflags=${LDFLAGS} -tags=nosqlite -trimpath"

#####################################
### X86 build section
#####

for PLATFORM in "${PLATFORMS[@]}"; do
  GOOS=${PLATFORM%/*}
  GOARCH=${PLATFORM#*/}
  set_goarm "$GOARCH"
  set_gomips "$GOARCH"
  BIN_FILENAME="${OUTPUT}-${GOOS}-${GOARCH}${GOARM}"
  if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
  CMD="GOOS=${GOOS} GOARCH=${GOARCH} ${GO_ARM} ${GO_MIPS} CGO_ENABLED=0 ${GOBIN} build ${BUILD_FLAGS} -o ${BIN_FILENAME} ./cmd"
  echo "${CMD}"
  eval "$CMD" || FAILURES="${FAILURES} ${GOOS}/${GOARCH}${GOARM}"
#  CMD="../upx -q ${BIN_FILENAME}"; # upx --brute produce much smaller binaries
#  echo "compress with ${CMD}"
#  eval "$CMD"
done

echo "Build AppImages"

APPIMAGE_TOOL="${ROOT}/appimagetool"

if [[ ! -x "${APPIMAGE_TOOL}" ]]; then
  curl -L -o "${APPIMAGE_TOOL}" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x "${APPIMAGE_TOOL}"
fi

build_appimage() {
  local ARCH_NAME="$1"
  local BINARY="$2"
  local APPIMAGE_ARCH="$3"
  local APPDIR="${ROOT}/TorrServer.AppDir"

  rm -rf "${APPDIR}"
  mkdir -p "${APPDIR}/usr/bin"

  cp "${OUTPUT}-${BINARY}" "${APPDIR}/usr/bin/torrserver"
  chmod +x "${APPDIR}/usr/bin/torrserver"

  cat > "${APPDIR}/torrserver.desktop" <<'EOF'
[Desktop Entry]
Name=TorrServer
Comment=Torrent streaming server
Exec=torrserver
Icon=torrserver
Type=Application
Categories=Network;FileTransfer;
Terminal=true
EOF

  cp "${ROOT}/web/public/icon.png" "${APPDIR}/torrserver.png"

  cat > "${APPDIR}/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
exec "${HERE}/usr/bin/torrserver" "$@"
EOF

  chmod +x "${APPDIR}/AppRun"

  ARCH="${APPIMAGE_ARCH}" \
    "${APPIMAGE_TOOL}" \
    "${APPDIR}" \
    "${OUTPUT}-linux-${ARCH_NAME}.AppImage"

  rm -rf "${APPDIR}"
}

build_appimage "amd64" "linux-amd64" "x86_64"

#####################################
### GStreamer build section
#####

GST_PLATFORMS=(
  'linux/amd64'
)

BUILD_FLAGS_GST="-ldflags=${LDFLAGS} -tags=nosqlite,gst -trimpath"

echo "Build GStreamer server"
for PLATFORM in "${GST_PLATFORMS[@]}"; do
  GOOS=${PLATFORM%/*}
  GOARCH=${PLATFORM#*/}
  BIN_FILENAME="${OUTPUT}-gst-${GOOS}-${GOARCH}"
  if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
  CMD="GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 ${GOBIN} build ${BUILD_FLAGS_GST} -o ${BIN_FILENAME} ./cmd"
  echo "${CMD}"
  eval "$CMD" || FAILURES="${FAILURES} gst/${GOOS}/${GOARCH}"
done

# eval errors
if [[ "${FAILURES}" != "" ]]; then
  echo ""
  echo "failed on: ${FAILURES}"
  exit 1
fi
