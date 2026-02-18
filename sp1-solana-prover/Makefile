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
	@ELF=target/elf-compilation/riscv64im-succinct-zkvm-elf/release/solana-state-verifier; \
	 if [ -f "$$ELF" ]; then \
	   mkdir -p guest/elf; \
	   cp $$ELF guest/elf/solana-state-verifier; \
	   echo "Guest ELF copied to guest/elf/solana-state-verifier ($$(wc -c < guest/elf/solana-state-verifier) bytes)"; \
	 else \
	   echo "WARNING: ELF not found at $$ELF"; \
	 fi

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

## Generate a mock proof using the SP1 mock prover (no ZK overhead, ~seconds)
##
## Required env vars:
##   BRIDGE_PROGRAM_ID  x0-bridge program ID on Solana
##
## Optional env vars:
##   SOLANA_RPC_URL       Solana RPC endpoint (default: devnet)
##   NONCE                BridgeOutMessage nonce to prove (default: 0)
##   QUORUM_TIMEOUT_SECS  Max wait for quorum (default: 120)
##   SKIP_QUORUM_WAIT=1   Skip quorum enforcement
##   OUTPUT_PROOF         Output proof file (default: mock_proof.bin)
##   OUTPUT_PUBLIC_VALUES Output public values file (default: mock_public_values.bin)
##
## Example:
##   SOLANA_RPC_URL=https://api.devnet.solana.com \
##   BRIDGE_PROGRAM_ID=4FuyK... \
##   NONCE=0 \
##   SKIP_QUORUM_WAIT=1 \
##   make mock-proof
mock-proof:
ifndef BRIDGE_PROGRAM_ID
	$(error BRIDGE_PROGRAM_ID is required)
endif
	@echo "Generating mock proof for BRIDGE_PROGRAM_ID=$(BRIDGE_PROGRAM_ID) NONCE=$${NONCE:-0}..."
	RUST_LOG=info cargo run -p x0-sp1-solana-host --example mock_proof --release
	@[ -f mock_proof.bin ] && echo "Proof:  mock_proof.bin ($$(wc -c < mock_proof.bin) bytes)" || true
	@[ -f mock_public_values.bin ] && echo "PubVal: mock_public_values.bin ($$(wc -c < mock_public_values.bin) bytes)" || true

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
