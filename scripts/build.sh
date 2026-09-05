#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"
mkdir -p "${BIN_DIR}"

APP_NAME="h2tunnel"
VERSION="1.1.0"

LDFLAGS="-s -w -X 'main.Version=${VERSION}'"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "linux/386"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "windows/386"
)

# Opt in with --update-deps (or UPDATE_GO_DEPS=1) to run
# "go get -u ./..." and "go mod tidy" before compiling.
UPDATE_GO_DEPS="${UPDATE_GO_DEPS:-0}"
for ARG in "$@"; do
  case "${ARG}" in
    --update-deps|--update-go-deps)
      UPDATE_GO_DEPS=1
      ;;
    *)
      echo "Unsupported argument: ${ARG}" >&2
      exit 2
      ;;
  esac
done

case "${UPDATE_GO_DEPS}" in
  1|true|TRUE|yes|YES)
    echo "=== Updating Go dependencies ==="
    (
      cd "${PROJECT_ROOT}"
      go get -u ./...
      go mod tidy
    )
    ;;
  0|false|FALSE|no|NO|"")
    ;;
  *)
    echo "UPDATE_GO_DEPS must be 0/1, true/false, or yes/no; got: ${UPDATE_GO_DEPS}" >&2
    exit 2
    ;;
esac

echo "=== Building ${APP_NAME} v${VERSION} ==="

for PLATFORM in "${PLATFORMS[@]}"; do
  GOOS="${PLATFORM%/*}"
  GOARCH="${PLATFORM#*/}"
  
  OUTPUT="${BIN_DIR}/${APP_NAME}_${GOOS}_${GOARCH}"
  if [ "${GOOS}" == "windows" ]; then
    OUTPUT="${OUTPUT}.exe"
  fi
  
  echo "--> Compiling ${GOOS}/${GOARCH}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -ldflags "${LDFLAGS}" -o "${OUTPUT}" "${PROJECT_ROOT}"
done

echo "=== Build Complete! Artifacts in ${BIN_DIR} ==="
