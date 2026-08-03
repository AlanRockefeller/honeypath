#!/usr/bin/env bash
set -euo pipefail

VERSION='10.4p1'
BUILD_ROOT="$HOME/src"
PREFIX="$HOME/.local/opt/openssh-$VERSION"
BASE_URL='https://cdn.openbsd.org/pub/OpenBSD/OpenSSH'
SRC_DIR="$BUILD_ROOT/openssh-$VERSION"
TARBALL="$BUILD_ROOT/openssh-$VERSION.tar.gz"

usage() {
    cat <<EOF
Usage: ${0##*/} [download|compile|install|all]

  download  Fetch and GPG-verify the OpenSSH $VERSION source tarball.
  compile   Extract, configure, build and run the regression tests.
  install   Install the built tree into $PREFIX.
  all       Run download, compile, then install.

With no argument the script asks interactively.
EOF
}

# Ask which phase to run when no argument was given.
prompt_action() {
    if [ ! -t 0 ]; then
        echo 'Not running interactively; pass download, compile, install or all.' >&2
        usage >&2
        exit 1
    fi

    printf 'OpenSSH %s\n' "$VERSION"
    printf '  1) download  - fetch and verify the source tarball\n'
    printf '  2) compile   - extract, configure, build and test\n'
    printf '  3) install   - install the built tree into the private prefix\n'
    printf '  4) all       - download, compile, then install\n'

    local reply
    while :; do
        read -r -p 'Select [1-4]: ' reply
        case "$reply" in
            1|d|download) ACTION='download'; return ;;
            2|c|compile)  ACTION='compile';  return ;;
            3|i|install)  ACTION='install';  return ;;
            4|a|all)      ACTION='all';      return ;;
            *) echo 'Please answer 1, 2, 3 or 4.' >&2 ;;
        esac
    done
}

do_download() {
    # Tools needed to fetch and verify the release. These are present on
    # almost every system, so only escalate if something is genuinely missing.
    local missing=()
    command -v curl >/dev/null || missing+=('curl')
    command -v gpg  >/dev/null || missing+=('gnupg' 'ca-certificates')

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Missing tools, installing: ${missing[*]}"
        sudo apt update
        sudo apt install -y "${missing[@]}"
    fi

    # Download the official portable release and its signature.
    mkdir -p "$BUILD_ROOT"
    cd "$BUILD_ROOT"

    curl -fLO "$BASE_URL/portable/openssh-$VERSION.tar.gz"
    curl -fLO "$BASE_URL/portable/openssh-$VERSION.tar.gz.asc"
    curl -fLO "$BASE_URL/RELEASE_KEY.asc"

    # Verify the release signature.
    gpg --import RELEASE_KEY.asc
    gpg --verify \
        "openssh-$VERSION.tar.gz.asc" \
        "openssh-$VERSION.tar.gz"

    printf '\nDownloaded and verified:\n%s\n' "$TARBALL"
}

do_compile() {
    if [ ! -f "$TARBALL" ]; then
        echo "Source tarball not found: $TARBALL" >&2
        echo "Run '${0##*/} download' first." >&2
        exit 1
    fi

    # Install compiler and development dependencies.
    sudo apt update
    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        zlib1g-dev \
        libedit-dev \
        libfido2-dev

    # Extract.
    cd "$BUILD_ROOT"
    rm -rf "$SRC_DIR"
    tar -xzf "$TARBALL"
    cd "$SRC_DIR"

    # Configure an isolated installation. Nothing is written to the prefix
    # here; that happens in the install phase.
    ./configure \
        --prefix="$PREFIX" \
        --sysconfdir="$PREFIX/etc" \
        --with-privsep-path="$PREFIX/var/empty" \
        --with-libedit

    # Compile and run the regression tests.
    make -j"$(nproc)"
    make tests

    printf '\nBuilt in:\n%s\n' "$SRC_DIR"
}

do_install() {
    if [ ! -f "$SRC_DIR/Makefile" ]; then
        echo "No configured build tree at: $SRC_DIR" >&2
        echo "Run '${0##*/} compile' first." >&2
        exit 1
    fi
    if [ ! -x "$SRC_DIR/ssh" ]; then
        echo "Build tree is not built yet: $SRC_DIR/ssh is missing." >&2
        echo "Run '${0##*/} compile' first." >&2
        exit 1
    fi

    cd "$SRC_DIR"

    # The privilege separation directory must exist before installing.
    mkdir -p "$PREFIX/var/empty"

    # Install into the private prefix; no sudo needed.
    make install

    # Confirm that the newly compiled client runs.
    "$PREFIX/bin/ssh" -V
    "$PREFIX/bin/scp" -V 2>&1 || true

    printf '\nInstalled under:\n%s\n' "$PREFIX"
}

ACTION="${1:-}"
case "$ACTION" in
    download|compile|install|all) ;;
    '') prompt_action ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "Unknown action: $ACTION" >&2; usage >&2; exit 1 ;;
esac

case "$ACTION" in
    download) do_download ;;
    compile)  do_compile ;;
    install)  do_install ;;
    all)      do_download; do_compile; do_install ;;
esac
