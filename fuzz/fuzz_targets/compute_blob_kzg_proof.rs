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
        proof: _rust_proof,
    } = data;
    let ckzg_blob = c_kzg::Blob::from_bytes(&*rust_blob.clone().to_bytes()).unwrap();
    let ckzg_commitment =
        c_kzg::Bytes48::from_bytes(rust_commitment.clone().to_bytes().as_slice()).unwrap();
    // compute_blob_kzg_proof
    let ckzg_proof = c_kzg::KzgProof::compute_blob_kzg_proof(
        ckzg_blob.clone(),
        ckzg_commitment,
        &*TRUSTED_SETUP_CKZG,
    );

    let rust_proof =
        Kzg::compute_blob_kzg_proof(&rust_blob, &rust_commitment, &*TRUSTED_SETUP_RUST);

    if ckzg_proof.is_err() {
        assert!(rust_proof.is_err());
    } else {
        assert_eq!(
            ckzg_proof.unwrap().to_bytes().into_inner(),
            rust_proof.unwrap().to_bytes()
        );
    }
});
