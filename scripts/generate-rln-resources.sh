#!/usr/bin/env bash
# Generate and verify RLN v3 resources with a TEST-ONLY trusted setup.
set -euo pipefail

CRATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rln-resources.XXXXXXXX")"
RES="$WORK/resources/tree_depth_20/rln_single"
TOOL="$CRATE_ROOT/target/release/r1cs-permute"
SNARK="$WORK/snarkjs/cli.js"
CIRCUIT="$WORK/circom-rln/circuits/rln_single.circom"
INPUT="$CRATE_ROOT/benches/fixtures/rln_single_input.json"
mkdir -p "$RES"
echo "Working directory: $WORK"
echo "WARNING: generated keys use public test entropy and are not suitable for production."

# Check out the versions used to generate the bundled test resources.
git clone https://github.com/vacp2p/circom-rln.git "$WORK/circom-rln"
git -C "$WORK/circom-rln" checkout 2cef30b0c49ee2016396c9992ebfc94ce45f5b6b
git clone https://github.com/mghazwi/snarkjs.git "$WORK/snarkjs"
git -C "$WORK/snarkjs" checkout ae1408b9e898363aa079c2a5c3c645e391eed770
git clone https://github.com/iden3/circom-witnesscalc.git "$WORK/circom-witnesscalc"
git -C "$WORK/circom-witnesscalc" checkout 5cb365b6e4d9052ecc69d4567fcf5bc061c20e94
npm ci --prefix "$WORK/circom-rln" --omit=dev --ignore-scripts
npm ci --prefix "$WORK/snarkjs" --omit=dev --ignore-scripts
cargo build --release --features zkey-reader --manifest-path "$CRATE_ROOT/Cargo.toml"
cargo build --manifest-path "$WORK/circom-witnesscalc/Cargo.toml" --bin build-circuit --bin calc-witness

# Compile the circuit and its matching witness graph.
circom "$CIRCUIT" --O2 --r1cs --wasm --sym \
  -l "$WORK/circom-rln/node_modules" -o "$WORK"
"$WORK/circom-witnesscalc/target/debug/build-circuit" "$CIRCUIT" "$RES/graph.bin" \
  -l "$WORK/circom-rln/node_modules"

# Derive dynamic indices, add public rows, and permute the matrices.
"$TOOL" mask-rln "$RES/graph.bin" "$WORK/rln_single.r1cs" "$WORK/indices.txt"
"$TOOL" permute "$WORK/rln_single.r1cs" "$WORK/permuted.r1cs" \
  "$WORK/indices.txt" "$RES/layout.json" "$RES/graph.bin"

# Generate and verify a test-only key for the permuted circuit.
node "$SNARK" powersoftau new bn128 13 "$WORK/pot0.ptau"
node "$SNARK" powersoftau contribute "$WORK/pot0.ptau" "$WORK/pot1.ptau" \
  --name=local-test -e=local-test-entropy
node "$SNARK" powersoftau prepare phase2 "$WORK/pot1.ptau" "$WORK/pot-final.ptau"
node "$SNARK" groth16 setup "$WORK/permuted.r1cs" "$WORK/pot-final.ptau" "$WORK/key0.zkey"
node "$SNARK" zkey contribute "$WORK/key0.zkey" "$WORK/final.zkey" \
  --name=local-test -e=local-test-entropy
node "$SNARK" zkey verify "$WORK/permuted.r1cs" "$WORK/pot-final.ptau" "$WORK/final.zkey"

# Pack the key with the matrices from the permuted R1CS.
"$TOOL" pack "$WORK/permuted.r1cs" "$WORK/final.zkey" "$RES/rln_final.arkzkey"

# Compare witness generators and verify a v3 proof.
node "$WORK/rln_single_js/generate_witness.js" "$WORK/rln_single_js/rln_single.wasm" \
  "$INPUT" "$WORK/wasm.wtns"
"$WORK/circom-witnesscalc/target/debug/calc-witness" "$RES/graph.bin" "$INPUT" "$WORK/graph.wtns"
cmp "$WORK/wasm.wtns" "$WORK/graph.wtns"
K="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["subgroup_size"])' "$RES/layout.json")"
"$TOOL" check-proof "$RES/rln_final.arkzkey" "$WORK/wasm.wtns" "$WORK/indices.txt" "$K"
echo "Generated test resources: $RES"
