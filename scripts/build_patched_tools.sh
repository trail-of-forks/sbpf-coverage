#! /bin/bash

if [[ -z "$AGAVE_TAG" ]]; then
    echo "$0: 'AGAVE_TAG' must be set for this script to run" >&2
    exit 1
fi

set -x
set -euo pipefail

# smoelius: Install Agave prerequisites.
OS="$(uname -s)"
case "$OS" in
    Darwin)
        brew install coreutils gnu-sed protobuf
        mkdir ~/lib || true
        ln -s /Library/Developer/CommandLineTools/usr/lib/libclang.dylib ~/lib/libclang.dylib || true
        export PATH="/opt/homebrew/opt/gnu-sed/libexec/gnubin:$PATH"
        ;;
    Linux)
        sudo apt update
        sudo apt install libclang-dev libudev-dev llvm protobuf-compiler
        ;;
    *)
        echo "unrecognized operating system: $OS" >&2
        ;;
esac

# smoelius: Clone Agave, checkout tag, and prepare to build.
git clone https://github.com/anza-xyz/agave || true
cd agave
git checkout .
git fetch --tags
git checkout "$AGAVE_TAG"
rm -rf bin

# smoelius: Declare `TOOLS`. Note that `solana` is not used directly, but it is called by Anchor.
TOOLS=(cargo-build-sbf solana-test-validator solana)

# smoelius: Patch Agave source. The last two lines eliminate some unnecessary building/rebuilding.
# We do not build "dev-context-only-utils", which is why we get away with the first of those two
# lines.
sed -i '/^\[patch\.crates-io\]$/a solana-sbpf = { git = "https://github.com/trail-of-forks/sbpf-coverage" }' Cargo.toml
sed -i "/^binArgs=()$/i BINS=(${TOOLS[*]}); DCOU_BINS=()" scripts/cargo-install-all.sh
sed -i '/^check_dcou() {$/a return 1' scripts/cargo-install-all.sh
sed -i '/\<install\>.*\<spl-token-cli\>/s/.*/# &/' scripts/cargo-install-all.sh

# smoelius: Sanity check that files changed.
! git diff --exit-code

# smoelius: Build the tools.
./scripts/cargo-install-all.sh .

# smoelius: Prepare for upload.
rm -rf ../patched-agave-tools-"$AGAVE_TAG"
mkdir ../patched-agave-tools-"$AGAVE_TAG"
tar cf ../patched-agave-tools-"$AGAVE_TAG"/bin.tar bin
