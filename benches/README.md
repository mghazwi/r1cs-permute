# RLN benchmarks

Criterion measures setup, partial-proof preprocessing, and proof finishing for the bundled RLN single-message circuit (domain N = 8192, subgroup K = 512, 505 dynamic variables). V1 has no dynamic setup. The benchmark checks that all three versions produce the same valid proof before measuring; timings exclude resource loading, witness generation and verification. The bundled key uses a test-only setup.

Quick-run mean estimates on the local machine, in milliseconds:

| Phase | Version | Single thread | Parallel (11 threads) |
| --- | --- | ---: | ---: |
| Setup | V2 | 15,245.79 | 3,404.19 |
| Setup | V3 | 8,585.55 | 2,906.82 |
| Preprocess | V1 | 208.69 | 26.38 |
| Preprocess | V2 | 12,263.06 | 3,001.17 |
| Preprocess | V3 | 6,478.74 | 2,441.31 |
| Finish | V1 | 80.07 | 28.86 |
| Finish | V2 | 34.28 | 12.83 |
| Finish | V3 | 28.08 | 8.35 |

These are short `--quick` measurements, not rigorous performance estimates; timings vary by machine and load. The parallel run used the default Rayon pool, with `RAYON_NUM_THREADS` unset.

From the crate root, after dependencies are cached:

```sh
cargo bench --offline --bench rln -- --quick
cargo bench --offline --bench rln --features parallel -- --quick
```

Remove `--quick` for Criterion's longer measurements. Do not enable the `zkey-reader` feature when benchmarking: it enables parallel arkworks dependencies even in the single-threaded configuration.
