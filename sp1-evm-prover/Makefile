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
	@ELF=target/elf-compilation/riscv64im-succinct-zkvm-elf/release/evm-verifier; \
	 if [ -f "$$ELF" ]; then \
	   mkdir -p guest/elf; \
	   cp $$ELF guest/elf/riscv32im-succinct-zkvm-elf; \
	   echo "Guest ELF copied to guest/elf/riscv32im-succinct-zkvm-elf ($$(wc -c < guest/elf/riscv32im-succinct-zkvm-elf) bytes)"; \
	 else \
	   echo "WARNING: ELF not found at $$ELF"; \
	 fi

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

## Generate a mock proof using the SP1 mock prover (no ZK overhead, ~seconds)
##
## Required env vars:
##   BASE_RPC_URLS   Comma-separated Base RPC endpoints (≥2)
##   ETH_L1_RPC_URL  Ethereum L1 RPC (for finality verification)
##   TX_HASH         Target transaction hash (0x-prefixed)
##
## Optional env vars:
##   BRIDGE_PROGRAM_ID  Solana bridge program (auto-fetches anchor if set)
##   SOLANA_RPC_URL     Solana RPC (default: mainnet-beta)
##   SKIP_SOLANA_ANCHOR=1 + ANCHOR_BLOCK + ANCHOR_HASH  (skip Solana)
##   LOCK_CONTRACT       Filter logs by contract address
##   MIN_CONSENSUS       RPC consensus threshold (default: 2)
##   OUTPUT_PROOF        Output proof file (default: mock_proof.bin)
##   OUTPUT_PUBLIC_INPUTS Output public inputs file (default: mock_public_inputs.json)
##
## Example:
##   BASE_RPC_URLS=https://mainnet.base.org,https://base.llamarpc.com \
##   ETH_L1_RPC_URL=https://eth.llamarpc.com \
##   SKIP_SOLANA_ANCHOR=1 ANCHOR_BLOCK=12345678 ANCHOR_HASH=0xdeadbeef... \
##   TX_HASH=0xabc123... \
##   make mock-proof
mock-proof:
ifndef TX_HASH
	$(error TX_HASH is required)
endif
ifndef BASE_RPC_URLS
	$(error BASE_RPC_URLS is required (comma-separated, ≥2 endpoints))
endif
ifndef ETH_L1_RPC_URL
	$(error ETH_L1_RPC_URL is required)
endif
	@echo "Generating mock proof for tx $(TX_HASH)..."
	RUST_LOG=info cargo run -p x0-sp1-evm-host --example mock_proof --release
	@[ -f mock_proof.bin ] && echo "Proof:    mock_proof.bin ($$(wc -c < mock_proof.bin) bytes)" || true
	@[ -f mock_public_inputs.json ] && echo "PubInput: mock_public_inputs.json" || true

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
