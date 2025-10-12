#! /bin/bash

if [[ -z "$AGAVE_TAG" ]]; then
    echo "$0: 'AGAVE_TAG' must be set for this script to run" >&2
    exit 1
fi

# smoelius: Install Agave prerequisites.
OS="$(uname -s)"
case "$OS" in
    Darwin)
        if [[ -n "$GITHUB_PATH" ]]; then
            brew install gnu-sed
            echo "$HOMEBREW_PREFIX/opt/gnu-sed/libexec/gnubin" >> $GITHUB_PATH
        fi
        ;;
    Ubuntu)
        sudo apt update
        sudo apt install libclang-dev libudev-dev llvm protobuf-compiler
        ;;
    *)
        echo "unrecognized operating system: $OS" >&2
        ;;
esac

set -x
set -euo pipefail

# smoelius: Clone Agave, checkout tag, and prepare to build.
git clone https://github.com/anza-xyz/agave || true
cd agave
git checkout .
git checkout "$AGAVE_TAG"
rm -rf bin

# smoelius: Declare `TOOLS`. Note that `solana` is not used directly, but it is called by Anchor.
TOOLS=(cargo-build-sbf solana-test-validator solana)

# smoelius: Patch Agave source. The last line prevents some unnecessary rebuilding. We do not build
# "dev-context-only-utils", which is why we get away with it.
sed -i '/^\[patch\.crates-io\]$/a solana-sbpf = { git = "https://github.com/trail-of-forks/sbpf-coverage" }' Cargo.toml
sed -i "/^binArgs=()$/i BINS=(${TOOLS[*]}); DCOU_BINS=()" scripts/cargo-install-all.sh
sed -i '/^check_dcou() {$/a return 1' scripts/cargo-install-all.sh

# smoelius: Sanity check that files changed.
! git diff --exit-code

# smoelius: Build the tools.
./scripts/cargo-install-all.sh .

# Prepare for upload.
rm -rf ../patched-agave-tools-"$AGAVE_TAG"
cp -r bin ../patched-agave-tools-"$AGAVE_TAG"
