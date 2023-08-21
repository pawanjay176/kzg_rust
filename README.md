# KZG Rust

Rust port of https://github.com/ethereum/c-kzg-4844 . Uses the blst rust bindings for all bls functionality.

Tries to be almost a line to line port of the C code in `c_kzg_4844.c` while rearranging some consts and utils into
their own rust modules. Runs same test vectors from the original repository.

The crate exports 2 modules: `kzg_mainnet` and `kzg_minimal` which correspond to the mainnet and minimal spec variants
in the [ethereum consensus specs](https://github.com/ethereum/consensus-specs/tree/dev/presets)

## Benchmarks
```bash
cargo bench
```
