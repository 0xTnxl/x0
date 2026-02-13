# x0 SP1 Solana State Prover — Build & Test
#
# Prerequisites:
#   - Rust nightly toolchain (see rust-toolchain.toml)
#   - SP1 toolchain: curl -L https://sp1.succinct.xyz | bash && sp1up
#   - Solana CLI (optional, for devnet testing)
#
# Quick start:
#   make build      # Build guest ELF + host binary
#   make test       # Run all unit tests
#   make mock-proof # Generate a mock proof (requires devnet + deployed bridge)

.PHONY: build build-guest build-host check test test-unit test-integration \
        mock-proof clean fmt clippy help

# ============================================================================
# Build Targets
# ============================================================================

## Build everything: guest ELF + host binary
build: build-guest build-host

## Build the SP1 guest ELF (requires cargo-prove from SP1 toolchain)
build-guest:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Building SP1 guest program..."
	@echo "══════════════════════════════════════════════════════"
	cd guest && cargo prove build
	@echo "Guest ELF: guest/elf/solana-state-verifier"
	@ls -la guest/elf/solana-state-verifier 2>/dev/null || echo "  (not yet built)"

## Build the host binary (release mode)
build-host:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Building host prover..."
	@echo "══════════════════════════════════════════════════════"
	cargo build -p x0-sp1-solana-host --release

# ============================================================================
# Test Targets
# ============================================================================

## Run all tests (unit + doc)
test: test-unit

## Run unit tests across all workspace crates
test-unit:
	cargo test --workspace

## Run integration tests (requires devnet access)
test-integration:
	RUST_LOG=info cargo test -p x0-sp1-solana-host --test integration -- --ignored --nocapture

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
## Usage: make mock-proof BRIDGE_PROGRAM_ID=<id> NONCE=<n>
mock-proof:
ifndef BRIDGE_PROGRAM_ID
	$(error BRIDGE_PROGRAM_ID is required. Usage: make mock-proof BRIDGE_PROGRAM_ID=<id> NONCE=<n>)
endif
ifndef NONCE
	$(error NONCE is required. Usage: make mock-proof BRIDGE_PROGRAM_ID=<id> NONCE=<n>)
endif
	@echo "Generating mock proof for nonce $(NONCE)..."
	RUST_LOG=info cargo run -p x0-sp1-solana-host --release -- \
		--rpc-url $${SOLANA_RPC_URL:-https://api.devnet.solana.com} \
		--bridge-program $(BRIDGE_PROGRAM_ID) \
		--nonce $(NONCE) \
		--mode mock \
		--output proof.bin \
		--public-values-output public_values.bin
	@echo "Proof:  proof.bin ($$(wc -c < proof.bin) bytes)"
	@echo "PubVal: public_values.bin ($$(wc -c < public_values.bin) bytes)"

## Generate a real compressed proof via SP1 network
network-proof:
ifndef BRIDGE_PROGRAM_ID
	$(error BRIDGE_PROGRAM_ID is required)
endif
ifndef NONCE
	$(error NONCE is required)
endif
ifndef SP1_PRIVATE_KEY
	$(error SP1_PRIVATE_KEY is required for network proving)
endif
	RUST_LOG=info cargo run -p x0-sp1-solana-host --release -- \
		--rpc-url $${SOLANA_RPC_URL:-https://api.devnet.solana.com} \
		--bridge-program $(BRIDGE_PROGRAM_ID) \
		--nonce $(NONCE) \
		--mode network \
		--output proof.bin \
		--public-values-output public_values.bin

# ============================================================================
# Cleanup
# ============================================================================

## Remove all build artifacts
clean:
	cargo clean
	rm -f guest/elf/solana-state-verifier
	rm -f proof.bin public_values.bin

# ============================================================================
# Help
# ============================================================================

## Show this help
help:
	@echo "x0 SP1 Solana State Prover"
	@echo ""
	@echo "Targets:"
	@echo "  build            Build guest ELF + host binary"
	@echo "  build-guest      Build SP1 guest ELF (requires cargo-prove)"
	@echo "  build-host       Build host binary (release)"
	@echo "  check            Type-check workspace"
	@echo "  test             Run unit tests"
	@echo "  test-unit        Run unit tests"
	@echo "  test-integration Run integration tests (requires devnet)"
	@echo "  mock-proof       Generate mock proof (BRIDGE_PROGRAM_ID= NONCE=)"
	@echo "  network-proof    Generate real proof via SP1 network"
	@echo "  fmt              Format code"
	@echo "  clippy           Run clippy lints"
	@echo "  clean            Remove build artifacts"
	@echo "  help             Show this help"
