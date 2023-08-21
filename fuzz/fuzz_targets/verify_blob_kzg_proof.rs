#![no_main]

use kzg_rust::kzg_mainnet::*;
use kzg_rust::MainnetFuzzTarget;
use libfuzzer_sys::fuzz_target;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref TRUSTED_SETUP_CKZG: c_kzg::KzgSettings =
        c_kzg::KzgSettings::load_trusted_setup_file(std::path::PathBuf::from(
            "../trusted_setup.txt"
        ))
        .unwrap();
    pub static ref TRUSTED_SETUP_RUST: kzg_rust::kzg_mainnet::KzgSettings =
        kzg_rust::kzg_mainnet::Kzg::load_trusted_setup_from_file("../testing_trusted_setups.json")
            .unwrap();
}

fuzz_target!(|data: MainnetFuzzTarget| {
    let MainnetFuzzTarget {
        blob: rust_blob,
        commitment: rust_commitment,
        proof: rust_proof,
    } = data;
    let ckzg_blob = c_kzg::Blob::from_bytes(&*rust_blob.clone().to_bytes()).unwrap();
    let ckzg_commitment =
        c_kzg::Bytes48::from_bytes(rust_commitment.clone().to_bytes().as_slice()).unwrap();
    let ckzg_proof = c_kzg::Bytes48::from_bytes(rust_proof.clone().to_bytes().as_slice()).unwrap();
    // verify_blob_kzg_proof
    let ckzg_result = c_kzg::KzgProof::verify_blob_kzg_proof(
        ckzg_blob.clone(),
        ckzg_commitment,
        ckzg_proof,
        &*TRUSTED_SETUP_CKZG,
    );

    let rust_result = Kzg::verify_blob_kzg_proof(
        &rust_blob,
        &rust_commitment,
        &rust_proof,
        &&*TRUSTED_SETUP_RUST,
    );

    if ckzg_result.is_err() {
        assert!(rust_result.is_err());
    } else {
        assert_eq!(rust_result.unwrap(), ckzg_result.unwrap());
    }
});
