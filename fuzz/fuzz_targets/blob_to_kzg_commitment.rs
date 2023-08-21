#![no_main]

use kzg_rust::kzg_mainnet::*;
use libfuzzer_sys::fuzz_target;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref TRUSTED_SETUP_CKZG: c_kzg::KzgSettings =
        c_kzg::KzgSettings::load_trusted_setup_file(
            std::path::PathBuf::from("../trusted_setup.txt")
        )
        .unwrap();
    pub static ref TRUSTED_SETUP_RUST: kzg_rust::kzg_mainnet::KzgSettings =
        kzg_rust::kzg_mainnet::Kzg::load_trusted_setup_from_file("../testing_trusted_setups.json")
            .unwrap();
}

fuzz_target!(|data: &[u8]| {
    if data.len() != BYTES_PER_BLOB {
        return;
    }

    if let Ok(ckzg_blob) = c_kzg::Blob::from_bytes(data) {
        let rustkzg_blob = Blob::from_bytes(data).unwrap();

        // blob_to_kzg_commitment
        let ckzg_commitment =
            c_kzg::KzgCommitment::blob_to_kzg_commitment(ckzg_blob.clone(), &*TRUSTED_SETUP_CKZG)
                .unwrap();
        let rustkzg_commitment =
            Kzg::blob_to_kzg_commitment(&rustkzg_blob, &*TRUSTED_SETUP_RUST).unwrap();

        assert_eq!(ckzg_commitment.to_bytes().into_inner(), rustkzg_commitment.to_bytes());
    }
});
