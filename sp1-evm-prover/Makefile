# x0 SP1 EVM (Base) State Prover — Build & Test
#
# Proves that a Locked() event was emitted on Base EVM by X0LockContract,
# enabling trustless USDC release on Solana via the SP1 STARK verifier.
#
# Prerequisites:
#   - Rust nightly toolchain
#   - SP1 toolchain: curl -L https://sp1.succinct.xyz | bash && sp1up
#   - Base RPC endpoint (Alchemy, Infura, etc.)
#
# Quick start:
#   make build      # Build guest ELF + host binary
#   make test       # Run all unit tests
#   make mock-proof # Generate a mock proof (see below for required env vars)

.PHONY: build build-guest build-host check test \
        mock-proof network-proof clean fmt clippy help

# ============================================================================
# Build Targets
# ============================================================================

## Build everything: guest ELF + host binary
build: build-guest build-host

## Build the SP1 guest ELF (requires cargo-prove from SP1 toolchain)
build-guest:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Building SP1 EVM verifier guest program..."
	@echo "══════════════════════════════════════════════════════"
	cd guest && cargo prove build
	@echo "Guest ELF: guest/elf/riscv32im-succinct-zkvm-elf"
	@ls -la guest/elf/riscv32im-succinct-zkvm-elf 2>/dev/null || echo "  (not yet built)"

## Build the host binary (release mode)
build-host:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Building EVM host prover..."
	@echo "══════════════════════════════════════════════════════"
	cargo build -p x0-sp1-evm-host --release

# ============================================================================
# Test Targets
# ============================================================================

## Run all tests
test:
	cargo test --workspace

# ============================================================================
# Quality
# ============================================================================

## Type-check without building
check:
	cargo check --workspace

## Format all code
fmt:
	cargo fmt --all

## Run clippy lints
clippy:
	cargo clippy --workspace -- -D warnings

# ============================================================================
# Proof Generation
# ============================================================================

## Generate a mock proof (for testing without real SP1 proving)
## Usage: make mock-proof TX_HASH=0x... BASE_RPC_URL=https://...
mock-proof:
ifndef TX_HASH
	$(error TX_HASH is required. Usage: make mock-proof TX_HASH=0x... BASE_RPC_URL=https://...)
endif
ifndef BASE_RPC_URL
	$(error BASE_RPC_URL is required. Usage: make mock-proof TX_HASH=0x... BASE_RPC_URL=https://...)
endif
	@echo "Generating mock proof for tx $(TX_HASH)..."
	RUST_LOG=info cargo run -p x0-sp1-evm-host --release -- prove \
		--rpc-url $(BASE_RPC_URL) \
		--tx-hash $(TX_HASH) \
		--mock \
		--output proof.bin \
		--public-inputs-output public_inputs.json
	@echo "Proof:    proof.bin ($$(wc -c < proof.bin) bytes)"
	@echo "PubInput: public_inputs.json"

## Generate a real compressed proof
real-proof:
ifndef TX_HASH
	$(error TX_HASH is required)
endif
ifndef BASE_RPC_URL
	$(error BASE_RPC_URL is required)
endif
	RUST_LOG=info cargo run -p x0-sp1-evm-host --release -- prove \
		--rpc-url $(BASE_RPC_URL) \
		--tx-hash $(TX_HASH) \
		--output proof.bin \
		--public-inputs-output public_inputs.json

## Verify an existing proof
verify:
	cargo run -p x0-sp1-evm-host --release -- verify \
		--proof proof.bin \
		--public-inputs public_inputs.json

# ============================================================================
# Cleanup
# ============================================================================

## Remove all build artifacts
clean:
	cargo clean
	rm -f proof.bin public_inputs.json

# ============================================================================
# Help
# ============================================================================

## Show this help
help:
	@echo "x0 SP1 EVM (Base) State Prover"
	@echo ""
	@echo "Targets:"
	@echo "  build        Build guest ELF + host binary"
	@echo "  build-guest  Build SP1 guest ELF (requires cargo-prove)"
	@echo "  build-host   Build host binary (release)"
	@echo "  check        Type-check workspace"
	@echo "  test         Run unit tests"
	@echo "  mock-proof   Generate mock proof (TX_HASH= BASE_RPC_URL=)"
	@echo "  real-proof   Generate real STARK proof (TX_HASH= BASE_RPC_URL=)"
	@echo "  verify       Verify an existing proof"
	@echo "  fmt          Format code"
	@echo "  clippy       Run clippy lints"
	@echo "  clean        Remove build artifacts"
	@echo "  help         Show this help"
