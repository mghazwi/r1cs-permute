# RLN R1CS permutation

This crate prepares Circom BN254 resources for subgroup-optimized dynamic
Groth16 v3. It derives the dynamic witness indices, adds the public-input
rows, permutes the R1CS, and packs the matching proving key and matrices.
It uses the permutation from [dynamic-groth16](https://github.com/logos-storage/dynamic-groth16).

The bundled **test-only** resources follow ZeroKit's naming:

```text
resources/tree_depth_20/rln_single/
  graph.bin            witness graph
  rln_final.arkzkey    proving key and permuted A/B/C matrices
  layout.json          subgroup size, dynamic indices, and hashes
```

These keys were generated with public test entropy and are not suitable for
production. The reader supports Circom R1CS v1 for BN254 with standard header,
constraint, and wire-label sections; custom sections are not supported.

## Commands

Run commands using `cargo run --release -- [command] ...`, or use the built
`target/release/r1cs-permute` binary.

| Command | Purpose |
|---|---|
| `mask-rln <graph> <input.r1cs> <indices.txt>` | Derive dynamic full-witness indices from ZeroKit's RLN partial-input policy. |
| `permute <input.r1cs> <output.r1cs> <indices.txt> <layout.json> [graph]` | Add public rows and permute the matrices. The optional RLN graph checks the indices and records its hash. |
| `pack <permuted.r1cs> <input.zkey> <output.arkzkey>` | Combine the snarkjs proving key with the complete permuted R1CS matrices. Requires `--features zkey-reader`. |
| `check-proof <packed.arkzkey> <witness.wtns> <indices.txt> <K>` | Compare a v3 proof with ordinary Groth16 and verify it, using fixed test randomness. |
| `check-mask <first.wtns> <second.wtns> <indices.txt>` | Check that witness entries changed between two samples are covered by the dynamic indices. |

`mask-rln` marks `messageId`, `x`, `externalNullifier`, and, for multi-message
RLN, `selectorUsed` as dynamic. It propagates unknownness through the witness
graph. The R1CS and graph must come from the same circuit and witness ordering;
the witness-count check alone does not prove this. For another circuit, supply
a complete dynamic-index file directly to `permute`. Indices use the full
witness ordering, include dependent intermediate and output wires, and exclude
constant one at index zero.

## Circuit to resources and proof

The following runs from the workspace root and creates **local test keys**.
It requires Rust, Node/npm, Circom, `protoc`, and these checkouts:

```sh
git clone https://github.com/vacp2p/circom-rln.git
git -C circom-rln checkout 2cef30b0c49ee2016396c9992ebfc94ce45f5b6b
git clone https://github.com/mghazwi/snarkjs.git snarkjs-local
git -C snarkjs-local checkout ae1408b9e898363aa079c2a5c3c645e391eed770
git clone https://github.com/iden3/circom-witnesscalc.git
git -C circom-witnesscalc checkout 5cb365b6e4d9052ecc69d4567fcf5bc061c20e94
npm ci --prefix circom-rln --omit=dev --ignore-scripts
npm ci --prefix snarkjs-local --omit=dev --ignore-scripts
cargo build --release --features zkey-reader --manifest-path r1cs-permute/Cargo.toml
cargo build --manifest-path circom-witnesscalc/Cargo.toml --bin build-circuit --bin calc-witness
```

The snarkjs fork is already patched; run its source CLI with `node`, not a
separately installed or prebuilt snarkjs executable.

> **Warning:** The patched snarkjs setup assumes that all public rows,
> including constant one, are already in the R1CS. Use it only with an R1CS
> prepared for that convention. **TODO:** Support both ordinary R1CS files
> and files with already-included public rows explicitly.

```sh
ROOT="$(pwd)"
WORK="$(mktemp -d)"
RES="$WORK/resources/tree_depth_20/rln_single"
mkdir -p "$RES"
TOOL="$ROOT/r1cs-permute/target/release/r1cs-permute"
SNARK="$ROOT/snarkjs-local/cli.js"
CIRCUIT="$ROOT/circom-rln/circuits/rln_single.circom"
INPUT="$ROOT/r1cs-permute/benches/fixtures/rln_single_input.json"

# Compile the circuit and its matching witness graph. The tested Circom
# version is 2.2.2; use --O2 to match the witnesscalc configuration.
circom "$CIRCUIT" --O2 --r1cs --wasm --sym \
  -l "$ROOT/circom-rln/node_modules" -o "$WORK"
"$ROOT/circom-witnesscalc/target/debug/build-circuit" "$CIRCUIT" "$RES/graph.bin" \
  -l "$ROOT/circom-rln/node_modules"

# Find dynamic witness entries and put affected rows on a subgroup.
"$TOOL" mask-rln "$RES/graph.bin" "$WORK/rln_single.r1cs" "$WORK/indices.txt"
"$TOOL" permute "$WORK/rln_single.r1cs" "$WORK/permuted.r1cs" \
  "$WORK/indices.txt" "$RES/layout.json" "$RES/graph.bin"

# LOCAL TEST SETUP ONLY: public test entropy; do not use these keys in production.
# Power 13 is sufficient for this circuit's 8192-point domain.
node "$SNARK" powersoftau new bn128 13 "$WORK/pot0.ptau"
node "$SNARK" powersoftau contribute "$WORK/pot0.ptau" "$WORK/pot1.ptau" \
  --name=local-test -e=local-test-entropy
node "$SNARK" powersoftau prepare phase2 "$WORK/pot1.ptau" "$WORK/pot-final.ptau"
node "$SNARK" groth16 setup "$WORK/permuted.r1cs" "$WORK/pot-final.ptau" "$WORK/key0.zkey"
node "$SNARK" zkey contribute "$WORK/key0.zkey" "$WORK/final.zkey" \
  --name=local-test -e=local-test-entropy
node "$SNARK" zkey verify "$WORK/permuted.r1cs" "$WORK/pot-final.ptau" "$WORK/final.zkey"

# Pack the proving key and matching permuted matrices.
"$TOOL" pack "$WORK/permuted.r1cs" "$WORK/final.zkey" "$RES/rln_final.arkzkey"

# Compare the graph and Circom WASM witnesses, then check a v3 proof.
node "$WORK/rln_single_js/generate_witness.js" "$WORK/rln_single_js/rln_single.wasm" \
  "$INPUT" "$WORK/wasm.wtns"
"$ROOT/circom-witnesscalc/target/debug/calc-witness" "$RES/graph.bin" "$INPUT" "$WORK/graph.wtns"
cmp "$WORK/wasm.wtns" "$WORK/graph.wtns"
K="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["subgroup_size"])' "$RES/layout.json")"
"$TOOL" check-proof "$RES/rln_final.arkzkey" "$WORK/wasm.wtns" "$WORK/indices.txt" "$K"
echo "Generated test resources: $RES"
```

The `pack` serialization format is based on
[ark-zkey](https://github.com/seemenkina/ark-zkey). Its `ark-circom` reader
still reads and discards matrices internally; the final matrices come from
the R1CS. Dimension checks cannot prove key/R1CS correspondence, so run
`zkey verify` as above. The current ZeroKit proving path must be adapted to
the included public-row layout before consuming these resources.

For unit tests, run `cargo test --offline`. For Criterion benchmark commands
and results, see [benches/README.md](benches/README.md).
