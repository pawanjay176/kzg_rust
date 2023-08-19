#![allow(dead_code)]

use super::BYTES_PER_BLOB;
use crate::{Blob, Error, KzgCommitment, KzgProof};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    blobs: Vec<String>,
    commitments: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_blobs(&self) -> Result<Vec<Blob<BYTES_PER_BLOB>>, Error> {
        let mut v: Vec<Blob<BYTES_PER_BLOB>> = Vec::new();
        for blob in &self.blobs {
            v.push(Blob::from_hex(blob)?);
        }
        Ok(v)
    }

    pub fn get_commitments(&self) -> Result<Vec<KzgCommitment>, Error> {
        self.commitments
            .iter()
            .map(|s| KzgCommitment::from_hex(s))
            .collect::<Result<Vec<KzgCommitment>, Error>>()
    }

    pub fn get_proofs(&self) -> Result<Vec<KzgProof>, Error> {
        self.proofs
            .iter()
            .map(|s| KzgProof::from_hex(s))
            .collect::<Result<Vec<KzgProof>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<bool>,
}

impl Test {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
