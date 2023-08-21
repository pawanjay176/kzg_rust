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
        commitment: _rust_commitment,
        proof: _rust_proof,
    } = data;

    let ckzg_blob = c_kzg::Blob::from_bytes(&*rust_blob.clone().to_bytes()).unwrap();
    // blob_to_kzg_commitment
    let ckzg_commitment =
        c_kzg::KzgCommitment::blob_to_kzg_commitment(ckzg_blob.clone(), &*TRUSTED_SETUP_CKZG);

    let rust_commitment = Kzg::blob_to_kzg_commitment(&rust_blob, &*TRUSTED_SETUP_RUST);

    if ckzg_commitment.is_err() {
        assert!(rust_commitment.is_err());
    }
    else {
        assert_eq!(
            ckzg_commitment.unwrap().to_bytes().into_inner(),
            rust_commitment.unwrap().to_bytes()
        );
    }


});
