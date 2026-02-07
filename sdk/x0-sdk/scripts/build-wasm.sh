#!/bin/bash

# Build WASM modules for x0-zk-proofs
#
# This script compiles the Rust crate in programs/x0-zk-proofs to WebAssembly
# for multiple targets: Node.js, web browsers, and bundlers (webpack/rollup).
#
# Prerequisites:
# - Rust toolchain with wasm32-unknown-unknown target
# - wasm-pack (install: cargo install wasm-pack)
# - wasm-opt (install: apt install binaryen or cargo install wasm-opt)
#
# Usage:
#   bash scripts/build-wasm.sh

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Building x0-zk-proofs WASM modules${NC}"
echo -e "${GREEN}========================================${NC}"

# Get the script directory (sdk/x0-sdk/scripts)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SDK_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE_DIR="$(dirname "$(dirname "$SDK_DIR")")"
ZK_PROOFS_DIR="$WORKSPACE_DIR/programs/x0-zk-proofs"

echo -e "${YELLOW}Workspace:${NC} $WORKSPACE_DIR"
echo -e "${YELLOW}ZK Proofs:${NC} $ZK_PROOFS_DIR"
echo -e "${YELLOW}SDK:${NC} $SDK_DIR"
echo ""

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo -e "${RED}Error: wasm-pack not found${NC}"
    echo "Install it with: cargo install wasm-pack"
    exit 1
fi

# Check if wasm-opt is installed
if ! command -v wasm-opt &> /dev/null; then
    echo -e "${RED}Error: wasm-opt not found${NC}"
    echo "Install it with: apt install binaryen (or cargo install wasm-opt)"
    exit 1
fi

# Check if wasm32-unknown-unknown target is installed
if ! rustup target list | grep -q "wasm32-unknown-unknown (installed)"; then
    echo -e "${YELLOW}Installing wasm32-unknown-unknown target...${NC}"
    rustup target add wasm32-unknown-unknown
fi

# Change to the ZK proofs directory
cd "$ZK_PROOFS_DIR"

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf "$SDK_DIR/wasm" 2>/dev/null || true

# Build for Node.js
echo ""
echo -e "${GREEN}Building for Node.js...${NC}"
wasm-pack build \
    --target nodejs \
    --out-dir "$SDK_DIR/wasm/nodejs" \
    --release \
    --scope x0-protocol

# Apply aggressive wasm-opt for Node.js with proper feature flags
echo -e "${YELLOW}Applying aggressive optimizations to Node.js build...${NC}"
wasm-opt -Oz \
    --enable-bulk-memory \
    --enable-sign-ext \
    --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    --strip-debug \
    --strip-producers \
    --dce \
    --vacuum \
    --gufa \
    --closed-world \
    --inline-functions-with-loops \
    --simplify-globals-optimizing \
    --remove-unused-module-elements \
    "$SDK_DIR/wasm/nodejs/x0_zk_proofs_bg.wasm" \
    -o "$SDK_DIR/wasm/nodejs/x0_zk_proofs_bg.wasm"

# Build for web browsers
echo ""
echo -e "${GREEN}Building for web browsers...${NC}"
wasm-pack build \
    --target web \
    --out-dir "$SDK_DIR/wasm/web" \
    --release \
    --scope x0-protocol

# Apply aggressive wasm-opt for web with proper feature flags
echo -e "${YELLOW}Applying aggressive optimizations to web build...${NC}"
wasm-opt -Oz \
    --enable-bulk-memory \
    --enable-sign-ext \
    --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    --strip-debug \
    --strip-producers \
    --dce \
    --vacuum \
    --gufa \
    --closed-world \
    --inline-functions-with-loops \
    --simplify-globals-optimizing \
    --remove-unused-module-elements \
    "$SDK_DIR/wasm/web/x0_zk_proofs_bg.wasm" \
    -o "$SDK_DIR/wasm/web/x0_zk_proofs_bg.wasm"

# Build for bundlers (webpack, rollup, parcel)
echo ""
echo -e "${GREEN}Building for bundlers...${NC}"
wasm-pack build \
    --target bundler \
    --out-dir "$SDK_DIR/wasm/bundler" \
    --release \
    --scope x0-protocol

# Apply aggressive wasm-opt for bundler with proper feature flags
echo -e "${YELLOW}Applying aggressive optimizations to bundler build...${NC}"
wasm-opt -Oz \
    --enable-bulk-memory \
    --enable-sign-ext \
    --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    --strip-debug \
    --strip-producers \
    --dce \
    --vacuum \
    --gufa \
    --closed-world \
    --inline-functions-with-loops \
    --simplify-globals-optimizing \
    --remove-unused-module-elements \
    "$SDK_DIR/wasm/bundler/x0_zk_proofs_bg.wasm" \
    -o "$SDK_DIR/wasm/bundler/x0_zk_proofs_bg.wasm"

# Check binary sizes
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build complete! Binary sizes:${NC}"
echo -e "${GREEN}========================================${NC}"

for target in nodejs web bundler; do
    wasm_file="$SDK_DIR/wasm/$target/x0_zk_proofs_bg.wasm"
    if [ -f "$wasm_file" ]; then
        size=$(du -h "$wasm_file" | cut -f1)
        gzipped_size=$(gzip -c "$wasm_file" | wc -c | awk '{print int($1/1024) "K"}')
        echo -e "${YELLOW}$target:${NC}"
        echo "  Raw:      $size"
        echo "  Gzipped:  $gzipped_size"
    fi
done

# Check if size is under 1MB gzipped (target)
nodejs_wasm="$SDK_DIR/wasm/nodejs/x0_zk_proofs_bg.wasm"
if [ -f "$nodejs_wasm" ]; then
    gzipped_bytes=$(gzip -c "$nodejs_wasm" | wc -c)
    gzipped_mb=$(echo "scale=2; $gzipped_bytes / 1048576" | bc)

    echo ""
    if (( $(echo "$gzipped_mb < 1.0" | bc -l) )); then
        echo -e "${GREEN}✓ WASM binary is under 1MB gzipped target: ${gzipped_mb}MB${NC}"
    else
        echo -e "${YELLOW}⚠ WASM binary exceeds 1MB gzipped target: ${gzipped_mb}MB${NC}"
        echo "  Note: ZK proof libraries are inherently large. Consider:"
        echo "  - Moving proof generation server-side for web apps"
        echo "  - Lazy-loading proofs only when needed"
        echo "  - Using feature flags to disable unused proof systems"
    fi
fi

echo ""
echo -e "${GREEN}WASM modules built successfully!${NC}"
echo ""
echo "Output directories:"
echo "  Node.js:  $SDK_DIR/wasm/nodejs/"
echo "  Web:      $SDK_DIR/wasm/web/"
echo "  Bundler:  $SDK_DIR/wasm/bundler/"
echo ""