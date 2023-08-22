# KZG Rust

Rust port of https://github.com/ethereum/c-kzg-4844 . Uses the blst rust bindings for all BLS functionality.

Tries to be almost a line to line port of the C code in `c_kzg_4844.c` while rearranging some consts and utils into
their own rust modules. Runs same test vectors from the original repository.

The crate exports 2 modules: `kzg_mainnet` and `kzg_minimal` which correspond to the mainnet and minimal spec variants
in the [ethereum consensus specs](https://github.com/ethereum/consensus-specs/tree/dev/presets)

Each module contains the following:

Following constants:
- `FIELD_ELEMENTS_PER_BLOB`
- `BYTES_PER_BLOB`

A `Kzg` struct with the associated methods:

- `load_trusted_setup`
- `load_trusted_setup_file`
- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_blob_kzg_proof`
- `verify_kzg_proof`
- `verify_blob_kzg_proof`
- `verify_blob_kzg_proof_batch`

The following structs with specified values of the `FIELD_ELEMENTS_PER_BLOB` constant which refers to either mainnet or minimal spec parameters:
- `Blob`
- `KzgSettings`
- `TrustedSetup`

The `TrustedSetup` struct is provided as an additional helper struct in this library to parse trusted setups in the json format provided in the 
[ethereum consensus specs](https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/testing_trusted_setups.json)



## Benchmarks
```bash
cargo bench
```
