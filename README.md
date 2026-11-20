# RLN R1CS permutation

This crate prepares Circom BN254 resources for subgroup-optimized dynamic Groth16 v3. It identifies dynamic witness entries, adds public-input rows, permutes the constraint matrices and packs them with a matching proving key. The permutation uses [dynamic-groth16](https://github.com/logos-storage/dynamic-groth16).

## Generate RLN resources

From the crate root, run:

```sh
./scripts/generate-rln-resources.sh
```

The script requires Git, Rust/Cargo, Node/npm, Python 3, `protoc` and Circom (tested with version 2.2.2). It downloads pinned versions of the RLN circuit, witness calculator and [patched snarkjs fork](https://github.com/mghazwi/snarkjs). It builds the tools and leaves all generated files in a new temporary directory, whose path it prints; it does not replace the bundled resources.

The script performs these steps. The examples below assume the tools and circuit are available, a prepared test `pot-final.ptau` exists, and an `output` directory has been created. Paths are relative to the crate root.

1. **Compile the RLN circuit.** Generate its R1CS and Circom WASM, then build the matching witness graph.

   ```sh
   circom ../circom-rln/circuits/rln_single.circom --O2 --r1cs --wasm --sym -l ../circom-rln/node_modules -o output
   ../circom-witnesscalc/target/debug/build-circuit ../circom-rln/circuits/rln_single.circom output/graph.bin -l ../circom-rln/node_modules
   ```

2. **Find dynamic witness entries.** Apply ZeroKit's RLN partial-input policy to the graph and save the affected witness indices.

   ```sh
   target/release/r1cs-permute mask-rln output/graph.bin output/rln_single.r1cs output/indices.txt
   ```

3. **Prepare the circuit for v3.** Add public-input rows and permute constraints so rows affected by dynamic variables lie on a subgroup. Save the subgroup size and layout metadata.

   ```sh
   target/release/r1cs-permute permute output/rln_single.r1cs output/permuted.r1cs output/indices.txt output/layout.json output/graph.bin
   ```

4. **Generate and verify a test proving key.** Use patched snarkjs and the prepared test powers-of-tau file with the permuted R1CS.

   ```sh
   node ../snarkjs/cli.js groth16 setup output/permuted.r1cs output/pot-final.ptau output/final.zkey
   node ../snarkjs/cli.js zkey verify output/permuted.r1cs output/pot-final.ptau output/final.zkey
   ```

5. **Pack resources.** Combine the proving key with the permuted A/B/C matrices in an `.arkzkey` file.

   ```sh
   target/release/r1cs-permute pack output/permuted.r1cs output/final.zkey output/rln_final.arkzkey
   ```

6. **Check proving.** Given a witness, compare and verify a v3 proof against ordinary Groth16. The final argument is the subgroup size from `output/layout.json` (512 for the bundled RLN example).

   ```sh
   target/release/r1cs-permute check-proof output/rln_final.arkzkey output/witness.wtns output/indices.txt 512
   ```

The final resource directory contains:

```text
resources/tree_depth_20/rln_single/
  graph.bin            witness graph
  rln_final.arkzkey    proving key and permuted A/B/C matrices
  layout.json          subgroup size, dynamic indices and hashes
```

A test-only copy of these resources is included in the crate. ZeroKit's current proving path needs to be adapted to the included public-row layout before it can consume them.

## Commands

Build with `cargo build --release --features zkey-reader`, then run the binary at `target/release/r1cs-permute`. The `pack` command requires the `zkey-reader` feature.

| Command | Purpose |
| --- | --- |
| `mask-rln <graph> <input.r1cs> <indices.txt>` | Derive dynamic witness indices from the RLN graph. |
| `permute <input.r1cs> <output.r1cs> <indices.txt> <layout.json> [graph]` | Add public rows and permute the matrices. The optional graph checks the indices and records its hash. |
| `pack <permuted.r1cs> <input.zkey> <output.arkzkey>` | Pack the proving key with the matrices from the permuted R1CS. |
| `check-proof <packed.arkzkey> <witness.wtns> <indices.txt> <K>` | Compare and verify v3 and ordinary proofs using fixed test randomness. |
| `check-mask <first.wtns> <second.wtns> <indices.txt>` | Check that entries changed between two sample witnesses are covered by the dynamic indices. |

`mask-rln` treats `messageId`, `x`, `externalNullifier`, and, for multi-message RLN, `selectorUsed` as dynamic, then propagates that status through the graph. Indices use full witness ordering, exclude constant one at index zero, and include dependent intermediate and output wires. The graph and R1CS must come from the same circuit and witness ordering; matching witness counts alone cannot establish this. For another circuit, supply its dynamic indices to `permute` directly.

The R1CS reader supports Circom R1CS v1 for BN254 with standard header, constraint and wire-label sections, but not custom sections. The `pack` format is based on [ark-zkey](https://github.com/seemenkina/ark-zkey); its `ark-circom` reader parses and discards the zkey matrices, and the packed matrices come from the R1CS. Dimension checks cannot establish that a key matches an R1CS, so verify the zkey as the script does.

## Tests and benchmarks

Run unit tests with `cargo test`. For Criterion commands and results, see [benches/README.md](benches/README.md).
