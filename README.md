# KZG Rust

Rust port of https://github.com/ethereum/c-kzg-4844 . Uses the blst rust bindings for all bls functionality.

Tries to be almost a line to line port of the C code in `c_kzg_4844.c` while rearranging some consts and utils into
their own rust modules. Runs same test vectors from the original repository.

## Minimal feature

Compiling this crate with `--features="minimal"` sets `FIELD_ELEMENTS_PER_BLOB` to 4. This allows for testing with reduced
blob sizes for running on CI.

## Benchmarks
```bash
cargo bench
```
