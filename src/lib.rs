mod consts;
mod kzg;
mod test_formats;
mod trusted_setup;
mod utils;
use arbitrary::Arbitrary;

pub use consts::{
    BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_G1, BYTES_PER_G2, BYTES_PER_PROOF,
};
pub use kzg::{kzg_mainnet, kzg_minimal, Bytes32, Bytes48, Error, KzgCommitment, KzgProof};

pub(crate) use kzg::BlobGeneric;

#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub struct MainnetFuzzTarget {
    pub blob: kzg_mainnet::Blob,
    pub commitment: KzgCommitment,
    pub proof: KzgProof,
}

#[cfg(test)]
#[cfg(not(feature = "minimal"))]
mod tests {
    use super::kzg_mainnet::*;
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use test_formats::*;

    const TRUSTED_SETUP: &str = "testing_trusted_setups.json";
    const BLOB_TO_KZG_COMMITMENT_TESTS: &str = "tests/blob_to_kzg_commitment/*/*/*";
    const COMPUTE_KZG_PROOF_TESTS: &str = "tests/compute_kzg_proof/*/*/*";
    const COMPUTE_BLOB_KZG_PROOF_TESTS: &str = "tests/compute_blob_kzg_proof/*/*/*";
    const VERIFY_KZG_PROOF_TESTS: &str = "tests/verify_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_TESTS: &str = "tests/verify_blob_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: &str = "tests/verify_blob_kzg_proof_batch/*/*/*";

    #[test]
    fn test_blob_to_kzg_commitment() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(BLOB_TO_KZG_COMMITMENT_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: blob_to_kzg_commitment_test::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let Ok(blob) = test.input.get_blob() else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::blob_to_kzg_commitment(&blob, &kzg_settings) {
                Ok(res) => assert_eq!(res.0.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_compute_kzg_proof() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(z)) = (test.input.get_blob(), test.input.get_z()) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::compute_kzg_proof(&blob, &z, &kzg_settings) {
                Ok((proof, y)) => {
                    assert_eq!(proof.0.bytes, test.get_output().unwrap().0.bytes);
                    assert_eq!(y.bytes, test.get_output().unwrap().1.bytes);
                }
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_compute_blob_kzg_proof() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment)) = (test.input.get_blob(), test.input.get_commitment())
            else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::compute_blob_kzg_proof(&blob, &KzgCommitment(commitment), &kzg_settings) {
                Ok(res) => assert_eq!(res.0.bytes, test.get_output().unwrap().bytes),

                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: test_formats::verify_kzg_proof::Test =
                serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };
            match Kzg::verify_kzg_proof(
                &KzgCommitment(commitment),
                &z,
                &y,
                &KzgProof(proof),
                &kzg_settings,
            ) {
                Ok(res) => {
                    assert_eq!(res, test.get_output().unwrap());
                }
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_blob_kzg_proof() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment), Ok(proof)) = (
                test.input.get_blob(),
                test.input.get_commitment(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match Kzg::verify_blob_kzg_proof(
                &blob,
                &KzgCommitment(commitment),
                &KzgProof(proof),
                &kzg_settings,
            ) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_blob_kzg_proof_batch() {
        let kzg_settings = Kzg::load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(&test_file).unwrap();
            let test: verify_blob_kzg_proof_batch::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blobs), Ok(commitments), Ok(proofs)) = (
                test.input.get_blobs(),
                test.input.get_commitments(),
                test.input.get_proofs(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };
            match Kzg::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),

                _ => assert!(test.get_output().is_none()),
            }
        }
    }
}
