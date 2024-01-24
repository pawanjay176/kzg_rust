use crate::consts::*;
use crate::utils::*;
use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};
use std::fs::File;
use std::path::Path;

use BLST_ERROR::BLST_SUCCESS;

#[derive(Debug)]
pub enum Error {
    /// The supplied data is invalid in some way.
    BadArgs(String),
    /// Internal error - this should never occur.
    InternalError,
    /// The provided bytes are of incorrect length.
    InvalidBytesLength(String),
    /// Error when converting from hex to bytes.
    InvalidHexFormat(String),
    /// The provided trusted setup params are invalid.
    InvalidTrustedSetup(String),
}

/**
 * Stores the setup and parameters needed for computing KZG proofs.
 */
#[derive(Debug, Default)]
pub struct KzgSettings {
    /** The length of `roots_of_unity`, a power of 2. */
    max_width: u64,
    /** Powers of the primitive root of unity determined by
     * `SCALE2_ROOT_OF_UNITY` in bit-reversal permutation order,
     * length `max_width`. */
    roots_of_unity: Vec<fr_t>,
    /** G1 group elements from the trusted setup,
     * in Lagrange form bit-reversal permutation. */
    g1_values: Vec<g1_t>,
    /** G2 group elements from the trusted setup. */
    g2_values: Vec<g2_t>,
}

impl KzgSettings {
    /// Initializes a trusted setup from `FIELD_ELEMENTS_PER_BLOB` g1 points
    /// and 65 g2 points in byte format.
    pub fn load_trusted_setup(
        g1_bytes: Vec<[u8; BYTES_PER_G1]>,
        g2_bytes: Vec<[u8; BYTES_PER_G2]>,
    ) -> Result<Self, Error> {
        if g1_bytes.len() != FIELD_ELEMENTS_PER_BLOB {
            return Err(Error::InvalidTrustedSetup(format!(
                "Invalid number of g1 points in trusted setup. Expected {} got {}",
                FIELD_ELEMENTS_PER_BLOB,
                g1_bytes.len()
            )));
        }
        if g2_bytes.len() != TRUSTED_SETUP_NUM_G2_POINTS {
            return Err(Error::InvalidTrustedSetup(format!(
                "Invalid number of g2 points in trusted setup. Expected {} got {}",
                TRUSTED_SETUP_NUM_G2_POINTS,
                g2_bytes.len()
            )));
        }

        let g1_points = g1_bytes.into_iter().fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x);
            acc
        });
        let g2_points = g2_bytes.into_iter().fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x);
            acc
        });
        load_trusted_setup(
            g1_points,
            g2_points,
            FIELD_ELEMENTS_PER_BLOB,
            TRUSTED_SETUP_NUM_G2_POINTS,
        )
    }
}

/// Converts a hex string (with or without the 0x prefix) to bytes.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Error> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| Error::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

#[derive(Debug, Clone, PartialEq)]
struct Polynomial {
    evals: Box<[fr_t; FIELD_ELEMENTS_PER_BLOB]>,
}

impl Default for Polynomial {
    fn default() -> Self {
        Self {
            evals: Box::new([fr_t::default(); FIELD_ELEMENTS_PER_BLOB]),
        }
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Bytes32 {
    pub(crate) bytes: [u8; 32],
}

impl Bytes32 {
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 32 {
            return Err(Error::BadArgs(format!(
                "Bytes32 length error. Expected 32, got {}",
                b.len()
            )));
        }
        let mut arr = [0; 32];
        arr.copy_from_slice(b);
        Ok(Bytes32 { bytes: arr })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Bytes48 {
    pub(crate) bytes: [u8; 48],
}

impl Bytes48 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 48 {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                32,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 48];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

impl Default for Bytes48 {
    fn default() -> Self {
        Self { bytes: [0; 48] }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Blob {
    bytes: Box<[u8; BYTES_PER_BLOB]>,
}

impl Blob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_BLOB,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; BYTES_PER_BLOB];
        new_bytes.copy_from_slice(bytes);
        Ok(Self {
            bytes: Box::new(new_bytes),
        })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct KzgCommitment(pub Bytes48);

impl KzgCommitment {
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Ok(Self(Bytes48::from_bytes(&hex_to_bytes(hex_str)?)?))
    }

    pub fn to_bytes(self) -> [u8; BYTES_PER_COMMITMENT] {
        self.0.bytes
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct KzgProof(pub Bytes48);

impl KzgProof {
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Ok(Self(Bytes48::from_bytes(&hex_to_bytes(hex_str)?)?))
    }

    pub fn to_bytes(self) -> [u8; BYTES_PER_PROOF] {
        self.0.bytes
    }
}

impl From<[u8; BYTES_PER_COMMITMENT]> for KzgCommitment {
    fn from(value: [u8; BYTES_PER_COMMITMENT]) -> Self {
        Self(Bytes48 { bytes: value })
    }
}

impl From<[u8; BYTES_PER_PROOF]> for KzgProof {
    fn from(value: [u8; BYTES_PER_PROOF]) -> Self {
        Self(Bytes48 { bytes: value })
    }
}

impl From<[u8; BYTES_PER_BLOB]> for Blob {
    fn from(value: [u8; BYTES_PER_BLOB]) -> Self {
        Self {
            bytes: Box::new(value),
        }
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; 48]> for Bytes48 {
    fn from(value: [u8; 48]) -> Self {
        Self { bytes: value }
    }
}

use std::ops::{Deref, DerefMut};

impl Deref for Bytes32 {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for Bytes48 {
    type Target = [u8; 48];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for Blob {
    type Target = [u8; BYTES_PER_BLOB];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Deref for KzgProof {
    type Target = [u8; BYTES_PER_PROOF];
    fn deref(&self) -> &Self::Target {
        &self.0.bytes
    }
}

impl Deref for KzgCommitment {
    type Target = [u8; BYTES_PER_COMMITMENT];
    fn deref(&self) -> &Self::Target {
        &self.0.bytes
    }
}

/// Deserialize a `Blob` (array of bytes) into a `Polynomial` (array of field elements).
fn blob_to_polynomial(blob: &Blob) -> Result<Polynomial, Error> {
    let mut poly = Polynomial::default();
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        let start_bytes = i * BYTES_PER_FIELD_ELEMENT;
        let end_bytes = start_bytes + BYTES_PER_FIELD_ELEMENT;
        let field_bytes = Bytes32::from_bytes(&blob.bytes[start_bytes..end_bytes])?;
        poly.evals[i] = bytes_to_bls_field(&field_bytes)?;
    }
    Ok(poly)
}

/// Return the Fiat-Shamir challenge required to verify `blob` and
/// `commitment`.
///
/// Note: using commitment_bytes instead of `g1_t` like the c code since
/// we seem to be doing unnecessary conversions.
fn compute_challenge(blob: &Blob, commitment_bytes: &Bytes48) -> Result<fr_t, Error> {
    let mut bytes = vec![0u8; CHALLENGE_INPUT_SIZE];
    let mut offset = 0;

    /* Copy domain separator */
    bytes[offset..offset + DOMAIN_STR_LENGTH]
        .copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN.as_bytes());
    offset += DOMAIN_STR_LENGTH;

    /* Copy polynomial degree (16-bytes, big-endian) */
    bytes[offset..offset + std::mem::size_of::<u64>()]
        .copy_from_slice(bytes_from_uint64(0u64).as_slice());
    offset += std::mem::size_of::<u64>();
    bytes[offset..offset + std::mem::size_of::<u64>()]
        .copy_from_slice(bytes_from_uint64(FIELD_ELEMENTS_PER_BLOB as u64).as_slice());
    offset += std::mem::size_of::<u64>();

    /* Copy blob */
    bytes[offset..offset + BYTES_PER_BLOB].copy_from_slice(blob.bytes.as_slice());
    offset += BYTES_PER_BLOB;

    /* Copy commitment */
    // Check if commitment bytes are a valid g1 point
    if bytes_to_kzg_commitment(commitment_bytes).is_err() {
        return Err(Error::BadArgs("Invalid commitment bytes".to_string()));
    }
    bytes[offset..offset + BYTES_PER_COMMITMENT].copy_from_slice(commitment_bytes.bytes.as_slice());
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */
    assert_eq!(offset, CHALLENGE_INPUT_SIZE);

    let mut eval_challenge = Bytes32::default();
    unsafe {
        blst_sha256(
            eval_challenge.bytes.as_mut_ptr(),
            bytes.as_ptr(),
            CHALLENGE_INPUT_SIZE,
        );
    }
    Ok(hash_to_bls_field(&eval_challenge))
}

///////////////////////////////////////////////////////////////////////////////
// Polynomials Functions
///////////////////////////////////////////////////////////////////////////////

/// Evaluate a polynomial in evaluation form at a given point.
fn evaluate_polynomial_in_evaluation_form(
    p: &Polynomial,
    x: &fr_t,
    s: &KzgSettings,
) -> Result<fr_t, Error> {
    let mut inverses_in = [fr_t::default(); FIELD_ELEMENTS_PER_BLOB];
    let mut tmp = blst_fr::default();
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        /*
         * If the point to evaluate at is one of the evaluation points by which
         * the polynomial is given, we can just return the result directly.
         * Note that special-casing this is necessary, as the formula below
         * would divide by zero otherwise.
         */
        if fr_equal(x, &s.roots_of_unity[i]) {
            return Ok(p.evals[i]);
        }
        unsafe {
            blst_fr_sub(&mut tmp, x, &s.roots_of_unity[i]);
            inverses_in[i] = tmp;
        }
    }
    let inverses = fr_batch_inv(&inverses_in)?;

    let mut res = FR_ZERO;
    let mut tmp = fr_t::default();
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        unsafe {
            blst_fr_mul(&mut tmp, &inverses[i], &s.roots_of_unity[i]);
            blst_fr_mul(&mut tmp, &tmp, &p.evals[i]);
            blst_fr_add(&mut res, &res, &tmp);
        }
    }
    res = fr_div(res, fr_from_uint64(FIELD_ELEMENTS_PER_BLOB as u64));
    unsafe {
        blst_fr_sub(
            &mut tmp,
            &fr_pow(*x, FIELD_ELEMENTS_PER_BLOB as u64),
            &FR_ONE,
        );
        blst_fr_mul(&mut res, &res, &tmp);
    }
    Ok(res)
}

///////////////////////////////////////////////////////////////////////////////
// KZG Functions
///////////////////////////////////////////////////////////////////////////////

/// Compute a KZG commitment from a polynomial.
fn poly_to_kzg_commitment(p: &Polynomial, s: &KzgSettings) -> Result<g1_t, Error> {
    g1_lincomb_fast(&s.g1_values, p.evals.as_slice())
}

/// Convert a blob to a KZG commitment.
fn blob_to_kzg_commitment(blob: &Blob, s: &KzgSettings) -> Result<KzgCommitment, Error> {
    let poly = blob_to_polynomial(blob)?;
    let commitment = poly_to_kzg_commitment(&poly, s)?;
    let commitment_bytes = bytes_from_g1(&commitment);
    Ok(KzgCommitment(commitment_bytes))
}

/// Helper function: Verify KZG proof claiming that `p(z) == y`.
fn verify_kzg_proof_impl(
    commitment: &g1_t,
    z: &fr_t,
    y: &fr_t,
    proof: &g1_t,
    s: &KzgSettings,
) -> bool {
    /* Calculate: X_minus_z */
    let x_g2 = g2_mul(&G2_GENERATOR, z);
    let x_minus_z = g2_sub(&s.g2_values[1], &x_g2);

    /* Calculate: P_minus_y */
    let y_g1 = g1_mul(&G1_GENERATOR, y);
    let p_minus_y = g1_sub(commitment, &y_g1);

    /* Verify: P - y = Q * (X - z) */
    pairings_verify(&p_minus_y, &G2_GENERATOR, proof, &x_minus_z)
}

/// Verify a KZG proof claiming that `p(z) == y`.
fn verify_kzg_proof(
    commitment_bytes: &KzgCommitment,
    z_bytes: &Bytes32,
    y_bytes: &Bytes32,
    proof_bytes: &KzgProof,
    s: &KzgSettings,
) -> Result<bool, Error> {
    let commitment = bytes_to_kzg_commitment(&commitment_bytes.0)?;
    let z = bytes_to_bls_field(z_bytes)?;
    let y = bytes_to_bls_field(y_bytes)?;
    let proof = bytes_to_kzg_proof(&proof_bytes.0)?;

    /* Call helper to do pairings check */
    Ok(verify_kzg_proof_impl(&commitment, &z, &y, &proof, s))
}

/// Compute KZG proof for polynomial in Lagrange form at position `z`.
fn compute_kzg_proof(
    blob: &Blob,
    z_bytes: &Bytes32,
    s: &KzgSettings,
) -> Result<(KzgProof, Bytes32), Error> {
    let poly = blob_to_polynomial(blob)?;
    let fr_z = bytes_to_bls_field(z_bytes)?;

    let (proof, fr_y) = compute_kzg_proof_impl(&poly, &fr_z, s)?;
    let y_bytes = bytes_from_bls_field(&fr_y);
    Ok((proof, y_bytes))
}

/// Helper function for `compute_kzg_proof()` and
/// `compute_blob_kzg_proof()`.
fn compute_kzg_proof_impl(
    polynomial: &Polynomial,
    z: &fr_t,
    s: &KzgSettings,
) -> Result<(KzgProof, fr_t), Error> {
    let mut q = Polynomial::default();
    let y_out = evaluate_polynomial_in_evaluation_form(polynomial, z, s)?;
    let mut inverses_in = [fr_t::default(); FIELD_ELEMENTS_PER_BLOB];
    let mut m = 0usize;
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        if fr_equal(z, &s.roots_of_unity[i]) {
            /* We are asked to compute a KZG proof inside the domain */
            m = i + 1;
            inverses_in[i] = FR_ONE;
            continue;
        }
        // (p_i - y) / (ω_i - z)
        unsafe {
            blst_fr_sub(&mut q.evals[i], &polynomial.evals[i], &y_out);
            blst_fr_sub(&mut inverses_in[i], &s.roots_of_unity[i], z);
        }
    }

    let mut inverses = fr_batch_inv(&inverses_in)?;

    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        unsafe {
            blst_fr_mul(&mut q.evals[i], &q.evals[i], &inverses[i]);
        }
    }

    let mut tmp = fr_t::default();
    /* ω_{m-1} == z */
    if m != 0 {
        m -= 1;
        q.evals[m] = FR_ZERO;
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            if i == m {
                continue;
            }
            unsafe {
                /* Build denominator: z * (z - ω_i) */
                blst_fr_sub(&mut tmp, z, &s.roots_of_unity[i]);
                blst_fr_mul(&mut inverses_in[i], &tmp, z);
            }
        }

        inverses = fr_batch_inv(&inverses_in)?;

        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            if i == m {
                continue;
            }
            unsafe {
                /* Build numerator: ω_i * (p_i - y) */
                blst_fr_sub(&mut tmp, &polynomial.evals[i], &y_out);
                blst_fr_mul(&mut tmp, &tmp, &s.roots_of_unity[i]);
                /* Do the division: (p_i - y) * ω_i / (z * (z - ω_i)) */
                blst_fr_mul(&mut tmp, &tmp, &inverses[i]);
                blst_fr_add(&mut q.evals[m], &q.evals[m], &tmp);
            }
        }
    }
    let out_g1 = g1_lincomb_fast(&s.g1_values, q.evals.as_slice())?;

    let proof = bytes_from_g1(&out_g1);
    Ok((KzgProof(proof), y_out))
}

/// Given a blob and a commitment, return the KZG proof that is used to verify
/// it against the commitment. This function does not verify that the commitment
/// is correct with respect to the blob.
fn compute_blob_kzg_proof(
    blob: &Blob,
    commitment_bytes: &KzgCommitment,
    s: &KzgSettings,
) -> Result<KzgProof, Error> {
    let poly = blob_to_polynomial(blob)?;
    /* Compute the challenge for the given blob/commitment */
    let evaluation_challenge_fr = compute_challenge(blob, &commitment_bytes.0)?;

    /* Call helper function to compute proof and y */
    compute_kzg_proof_impl(&poly, &evaluation_challenge_fr, s).map(|(proof, _)| proof)
}

/// Given a blob and its proof, verify that it corresponds to the provided commitment.
fn verify_blob_kzg_proof(
    blob: &Blob,
    commitment_bytes: &KzgCommitment,
    proof_bytes: &KzgProof,
    s: &KzgSettings,
) -> Result<bool, Error> {
    let poly = blob_to_polynomial(blob)?;
    let commitment = bytes_to_kzg_commitment(&commitment_bytes.0)?;
    let proof = bytes_to_kzg_proof(&proof_bytes.0)?;
    /* Compute challenge for the blob/commitment */
    let eveluation_challenge_fr = compute_challenge(blob, &commitment_bytes.0)?;

    /* Evaluate challenge to get y */
    let y_fr = evaluate_polynomial_in_evaluation_form(&poly, &eveluation_challenge_fr, s)?;

    Ok(verify_kzg_proof_impl(
        &commitment,
        &eveluation_challenge_fr,
        &y_fr,
        &proof,
        s,
    ))
}

/// Helper function for `verify_blob_kzg_proof_batch()`: actually perform the
/// verification.
///
/// NOTE: This function assumes that `n` is trusted and that all input arrays
/// contain `n` elements. `n` should be the actual size of the arrays and not
/// read off a length field in the protocol.
///
/// This function only works for `n > 0`.
fn verify_kzg_proof_batch(
    commitments_g1: &[g1_t],
    zs_fr: &[fr_t],
    ys_fr: &[fr_t],
    proofs_g1: &[g1_t],
    s: &KzgSettings,
) -> Result<bool, Error> {
    let n = commitments_g1.len();

    if n == 0 {
        return Err(Error::BadArgs(
            "verify_kzg_proof_batch empty input".to_string(),
        ));
    }

    /* Compute the random lincomb challenges */
    let r_powers = compute_r_powers(commitments_g1, zs_fr, ys_fr, proofs_g1)?;

    let mut c_minus_y: Vec<_> = (0..n).map(|_| g1_t::default()).collect();
    let mut r_times_z: Vec<_> = (0..n).map(|_| fr_t::default()).collect();

    /* Compute \sum r^i * Proof_i */
    let proof_lincomb = g1_lincomb_naive(proofs_g1, &r_powers)?;

    for i in 0..n {
        /* Get [y_i] */
        let ys_encrypted = g1_mul(&G1_GENERATOR, &ys_fr[i]);
        /* Get C_i - [y_i] */
        c_minus_y[i] = g1_sub(&commitments_g1[i], &ys_encrypted);
        /* Get r^i * z_i */
        unsafe {
            blst_fr_mul(&mut r_times_z[i], &r_powers[i], &zs_fr[i]);
        }
    }
    /* Get \sum r^i z_i Proof_i */
    let proof_z_lincomb = g1_lincomb_naive(proofs_g1, &r_times_z)?;

    let c_minus_y_lincomb = g1_lincomb_naive(&c_minus_y, &r_powers)?;

    let mut rhs_g1 = blst_p1::default();
    /* Get C_minus_y_lincomb + proof_z_lincomb */
    unsafe {
        blst_p1_add_or_double(&mut rhs_g1, &c_minus_y_lincomb, &proof_z_lincomb);
    }

    /* Do the pairing check! */
    let res = pairings_verify(&proof_lincomb, &s.g2_values[1], &rhs_g1, &G2_GENERATOR);
    Ok(res)
}

/// Given a list of blobs and blob KZG proofs, verify that they correspond to the
/// provided commitments.
///
/// NOTE: This function assumes that `n` is trusted and that all input arrays
/// contain `n` elements. `n` should be the actual size of the arrays and not
/// read off a length field in the protocol.
///
/// This function accepts if called with `n==0`.
fn verify_blob_kzg_proof_batch(
    blobs: &[Blob],
    commitment_bytes: &[KzgCommitment],
    proof_bytes: &[KzgProof],
    s: &KzgSettings,
) -> Result<bool, Error> {
    let n = blobs.len();
    if blobs.len() != commitment_bytes.len() || commitment_bytes.len() != proof_bytes.len() {
        return Err(Error::BadArgs(format!(
            "Inconsistent lengths, blobs: {}, commitments: {}, proofs: {}",
            blobs.len(),
            commitment_bytes.len(),
            proof_bytes.len()
        )));
    }
    /* Exit early if we are given zero blobs */
    if n == 0 {
        return Ok(true);
    }

    /* For a single blob, just do a regular single verification */
    if n == 1 {
        return verify_blob_kzg_proof(&blobs[0], &commitment_bytes[0], &proof_bytes[0], s);
    }
    // Note: Potentially paralellizable
    /* Convert each commitment to a g1 point */
    let mut commitments_g1: Vec<_> = (0..n).map(|_| g1_t::default()).collect();

    /* Convert each proof to a g1 point */
    let mut proofs_g1: Vec<_> = (0..n).map(|_| g1_t::default()).collect();

    let mut evaluation_challenges_fr: Vec<_> = (0..n).map(|_| fr_t::default()).collect();
    let mut ys_fr: Vec<_> = (0..n).map(|_| fr_t::default()).collect();

    for i in 0..n {
        /* Convert each commitment to a g1 point */
        commitments_g1[i] = bytes_to_kzg_commitment(&commitment_bytes[i].0)?;
        /* Convert each blob from bytes to a poly */
        let polynomial = blob_to_polynomial(&blobs[i])?;

        evaluation_challenges_fr[i] = compute_challenge(&blobs[i], &commitment_bytes[i].0)?;

        ys_fr[i] =
            evaluate_polynomial_in_evaluation_form(&polynomial, &evaluation_challenges_fr[i], s)?;

        proofs_g1[i] = bytes_to_kzg_proof(&proof_bytes[i].0)?;
    }

    let res = verify_kzg_proof_batch(
        &commitments_g1,
        &evaluation_challenges_fr,
        &ys_fr,
        &proofs_g1,
        s,
    )?;
    Ok(res)
}

///////////////////////////////////////////////////////////////////////////////
// Trusted Setup Functions
///////////////////////////////////////////////////////////////////////////////

/// Reverse the bit order in a 32 bit integer.
fn reverse_bits(mut n: u32, order: u32) -> u32 {
    assert!(order.is_power_of_two());
    let order = order.ilog2();
    let mut result = 0;
    for _ in 0..order {
        result <<= 1;
        result |= n & 1;
        n >>= 1;
    }
    result
}

/// Reorder an array in reverse bit order of its indices.
///
/// NOTE: Unline the C code which swaps in place, this function returns a new vector.
/// We leverage rust generics to accept a vector of arbitrary type instead of dealing with void * pointers like in the
/// C code.
fn bit_reversal_permutation<T: Copy>(values: Vec<T>, n: usize) -> Result<Vec<T>, Error> {
    if values.is_empty() || n >> 32 != 0 || !n.is_power_of_two() || n.ilog2() == 0 {
        return Err(Error::BadArgs(
            "bit_reversal_permutation: invalid args".to_string(),
        ));
    }

    let mut res = Vec::with_capacity(n);
    for i in 0..n {
        let bit_reversed_i = reverse_bits(i as u32, n as u32);
        res.push(values[bit_reversed_i as usize]);
    }

    Ok(res)
}

/// Generate powers of a root of unity in the field.
fn expand_root_of_unity(root: &fr_t, width: u64) -> Result<Vec<fr_t>, Error> {
    let mut res: Vec<blst_fr> = (0..width + 1).map(|_| blst_fr::default()).collect();
    res[0] = FR_ONE;
    res[1] = *root;

    let mut i = 2usize;
    let mut tmp = blst_fr::default();

    while !fr_is_one(&res[i - 1]) {
        if i > width as usize {
            return Err(Error::BadArgs(
                "expand_root_of_unity: i > width".to_string(),
            ));
        }
        unsafe {
            blst_fr_mul(&mut tmp, &res[i - 1], root);
        }
        res[i] = tmp;
        i += 1;
    }

    if !fr_is_one(&res[width as usize]) {
        return Err(Error::BadArgs(
            "expand_root_of_unity: assertion failed".to_string(),
        ));
    }
    Ok(res)
}

/// Initialize the roots of unity.
fn compute_roots_of_unity(max_scale: u32) -> Result<Vec<fr_t>, Error> {
    /* Calculate the max width */
    let max_width = 1 << max_scale;

    /* Get the root of unity */
    if max_scale >= SCALE2_ROOT_OF_UNITY.len() as u32 {
        return Err(Error::BadArgs(
            "compute_roots_of_unity: max_scale too large".to_string(),
        ));
    }

    let mut root_of_unity = fr_t::default();
    unsafe {
        blst_fr_from_uint64(
            &mut root_of_unity,
            SCALE2_ROOT_OF_UNITY[max_scale as usize].as_ptr(),
        );
    }

    /*
     * Allocate an array to store the expanded roots of unity. We do this
     * instead of re-using roots_of_unity_out because the expansion requires
     * max_width+1 elements.
     */

    /* Populate the roots of unity */
    let mut expanded_roots = expand_root_of_unity(&root_of_unity, max_width)?;
    /* Copy all but the last root to the roots of unity */
    // NOTE: deviating from c code here
    expanded_roots.pop();

    /* Permute the roots of unity */
    let roots_of_unity_out = bit_reversal_permutation(expanded_roots, max_width as usize)?;

    Ok(roots_of_unity_out)
}

/// Basic sanity check that the trusted setup was loaded in Lagrange form.
fn is_trusted_setup_in_lagrange_form(s: &KzgSettings) -> Result<(), Error> {
    /* Trusted setup is too small; we can't work with this */
    if s.g1_values.len() < 2 || s.g2_values.len() < 2 {
        return Err(Error::BadArgs(
            "is_trusted_setup_in_lagrange_form: invalid args".to_string(),
        ));
    }

    /*
     * If the following pairing equation checks out:
     *     e(G1_SETUP[1], G2_SETUP[0]) ?= e(G1_SETUP[0], G2_SETUP[1])
     * then the trusted setup was loaded in monomial form.
     * If so, error out since we want the trusted setup in Lagrange form.
     */
    let is_monomial_form = pairings_verify(
        &s.g1_values[1],
        &s.g2_values[0],
        &s.g1_values[0],
        &s.g2_values[1],
    );

    if is_monomial_form {
        Err(Error::BadArgs(
            "is_trusted_setup_in_lagrange_form: not in monomial form".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Load trusted setup into a KzgSettings struct.
fn load_trusted_setup(
    g1_bytes: Vec<u8>,
    g2_bytes: Vec<u8>,
    n1: usize,
    n2: usize,
) -> Result<KzgSettings, Error> {
    let mut kzg_settings = KzgSettings::default();

    /* Sanity check in case this is called directly */

    if n1 != FIELD_ELEMENTS_PER_BLOB || n2 != TRUSTED_SETUP_NUM_G2_POINTS {
        return Err(Error::BadArgs(
            "load_trusted_setup invalid params".to_string(),
        ));
    }

    /* 1<<max_scale is the smallest power of 2 >= n1 */
    let mut max_scale = 0;
    while (1 << max_scale) < n1 {
        max_scale += 1;
    }

    /* Set the max_width */
    kzg_settings.max_width = 1 << max_scale;

    /* Convert all g1 bytes to g1 points */
    for i in 0..n1 {
        let mut g1_affine = blst_p1_affine::default();
        unsafe {
            let err = blst_p1_uncompress(&mut g1_affine, &g1_bytes[BYTES_PER_G1 * i]);
            if err != BLST_SUCCESS {
                return Err(Error::BadArgs(
                    "load_trusted_setup Invalid g1 bytes".to_string(),
                ));
            }
            let mut tmp = g1_t::default();
            blst_p1_from_affine(&mut tmp, &g1_affine);
            kzg_settings.g1_values.push(tmp);
        }
    }
    /* Convert all g2 bytes to g2 points */
    for i in 0..n2 {
        let mut g2_affine = blst_p2_affine::default();
        unsafe {
            let err = blst_p2_uncompress(&mut g2_affine, &g2_bytes[BYTES_PER_G2 * i]);
            if err != BLST_SUCCESS {
                return Err(Error::BadArgs(
                    "load_trusted_setup invalid g2 bytes".to_string(),
                ));
            }
            let mut tmp = g2_t::default();
            blst_p2_from_affine(&mut tmp, &g2_affine);
            kzg_settings.g2_values.push(tmp);
        }
    }

    /* Make sure the trusted setup was loaded in Lagrange form */
    is_trusted_setup_in_lagrange_form(&kzg_settings)?;

    /* Compute roots of unity and permute the G1 trusted setup */
    let roots_of_unity = compute_roots_of_unity(max_scale)?;
    kzg_settings.roots_of_unity = roots_of_unity;
    let bit_reversed_permutation = bit_reversal_permutation(kzg_settings.g1_values, n1)?;
    kzg_settings.g1_values = bit_reversed_permutation;

    Ok(kzg_settings)
}

/// Load trusted setup from a file.
///
/// The file format is `n1 n2 g1_1 g1_2 ... g1_n1 g2_1 ... g2_n2` where
/// the first two numbers are in decimal and the remainder are hexstrings
/// and any whitespace can be used as separators.
fn load_trusted_setup_file<P: AsRef<Path>>(trusted_setup_file: P) -> Result<KzgSettings, Error> {
    let file = File::open(trusted_setup_file).map_err(|e| {
        Error::InvalidTrustedSetup(format!("Failed to open trusted setup file: {:?}", e))
    })?;

    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(file);

    let mut lines = reader.lines();

    let Some(Ok(field_elements_per_blob)) = lines.next() else {
        return Err(Error::InvalidTrustedSetup(
            "Trusted setup file does not contain valid FIELD_ELEMENTS_PER_BLOB on line 1"
                .to_string(),
        ));
    };
    let field_elements_per_blob: usize = field_elements_per_blob.parse().map_err(|_| {
        Error::InvalidTrustedSetup("FIELD_ELEMENTS_PER_BLOB is not a valid integer".to_string())
    })?;
    if field_elements_per_blob != FIELD_ELEMENTS_PER_BLOB {
        return Err(Error::InvalidTrustedSetup(format!(
            "Invalid trusted setup for chosen preset. \
            Selected preset FIELD_ELEMENTS_PER_BLBO: {} \
            FIELD_ELEMENTS_PER_BLOB value in file: {}",
            FIELD_ELEMENTS_PER_BLOB, field_elements_per_blob
        )));
    }

    let Some(Ok(num_g2_points)) = lines.next() else {
        return Err(Error::InvalidTrustedSetup(
            "Trusted setup file does not contain valid NUM_G2_POINTS on line 2".to_string(),
        ));
    };
    let num_g2_points: usize = num_g2_points.parse().map_err(|_| {
        Error::InvalidTrustedSetup("FIELD_ELEMENTS_PER_BLOB is not a valid integer".to_string())
    })?;

    if num_g2_points != 65 {
        return Err(Error::InvalidTrustedSetup(format!(
            "Invalid trusted setup for chosen preset. \
            Selected preset NUM_G2_POINTS: {} \
            NUM_G2_POINTS value in file: {}",
            65, num_g2_points
        )));
    }

    let mut g1_bytes = Vec::new();
    for _ in 0..field_elements_per_blob {
        let g1_point = hex_to_bytes(
            &lines
                .next()
                .ok_or_else(|| {
                    Error::InvalidTrustedSetup("Invalid number of g1 points in file".to_string())
                })?
                .map_err(|_| Error::InvalidTrustedSetup("Invalid g1 point string".to_string()))?,
        )?;
        g1_bytes.extend_from_slice(&g1_point);
    }

    let mut g2_bytes = Vec::new();
    for _ in 0..num_g2_points {
        let g2_point = hex_to_bytes(
            &lines
                .next()
                .ok_or_else(|| {
                    Error::InvalidTrustedSetup("Invalid number of g2 points in file".to_string())
                })?
                .map_err(|_| Error::InvalidTrustedSetup("Invalid g2 point string".to_string()))?,
        )?;
        g2_bytes.extend_from_slice(&g2_point);
    }

    load_trusted_setup(g1_bytes, g2_bytes, field_elements_per_blob, num_g2_points)
}

/// A wrapper struct that exposes interface functions from the C code
/// as struct methods.
pub struct Kzg;

impl Kzg {
    /// Loads a trusted setup in the format described below and
    /// returns a `KzgSettings` struct.
    ///
    /// The file format is as follows:
    ///
    /// FIELD_ELEMENTS_PER_BLOB
    /// 65 # This is fixed and is used for providing multiproofs up to 64 field elements.
    /// `FIELD_ELEMENT_PER_BLOB` lines with each line containing a hex encoded g1 byte value.
    /// 65 lines with each line containing a hex encoded g2 byte value.
    pub fn load_trusted_setup_file<P: AsRef<Path>>(
        trusted_setup_file: P,
    ) -> Result<KzgSettings, Error> {
        load_trusted_setup_file(trusted_setup_file)
    }

    /// Loads a trusted setup and returns a `KzgSettings` struct.
    ///
    /// The `g1_bytes` and `g2_bytes` need to be extracted and parsed from a file
    /// and then passed into this function.
    pub fn load_trusted_setup(
        g1_bytes: Vec<[u8; BYTES_PER_G1]>,
        g2_bytes: Vec<[u8; BYTES_PER_G2]>,
    ) -> Result<KzgSettings, Error> {
        KzgSettings::load_trusted_setup(g1_bytes, g2_bytes)
    }

    /// Return the `KzgCommitment` corresponding to the `Blob`.
    pub fn blob_to_kzg_commitment(
        blob: &Blob,
        s: &KzgSettings,
    ) -> Result<KzgCommitment, Error> {
        blob_to_kzg_commitment(blob, s)
    }

    /// Compute the `KzgProof` given the `Blob` at the point corresponding to field element `z`.
    pub fn compute_kzg_proof(
        blob: &Blob,
        z_bytes: &Bytes32,
        s: &KzgSettings,
    ) -> Result<(KzgProof, Bytes32), Error> {
        compute_kzg_proof(blob, z_bytes, s)
    }

    /// Compute the `KzgProof` given the `Blob` and `KzgCommitment`.
    pub fn compute_blob_kzg_proof(
        blob: &Blob,
        commitment_bytes: &KzgCommitment,
        s: &KzgSettings,
    ) -> Result<KzgProof, Error> {
        compute_blob_kzg_proof(blob, commitment_bytes, s)
    }

    /// Verify a KZG proof claiming that `p(z) == y`.
    pub fn verify_kzg_proof(
        commitment_bytes: &KzgCommitment,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &KzgProof,
        s: &KzgSettings,
    ) -> Result<bool, Error> {
        verify_kzg_proof(commitment_bytes, z_bytes, y_bytes, proof_bytes, s)
    }

    /// Given a blob and its proof, verify that it corresponds to the provided commitment.
    pub fn verify_blob_kzg_proof(
        blob: &Blob,
        commitment_bytes: &KzgCommitment,
        proof_bytes: &KzgProof,
        s: &KzgSettings,
    ) -> Result<bool, Error> {
        verify_blob_kzg_proof(
            blob,
            commitment_bytes,
            proof_bytes,
            s,
        )
    }

    /// Given a list of blobs and blob KZG proofs, verify that they correspond to the
    /// provided commitments.
    pub fn verify_blob_kzg_proof_batch(
        blobs: &[Blob],
        commitment_bytes: &[KzgCommitment],
        proof_bytes: &[KzgProof],
        s: &KzgSettings,
    ) -> Result<bool, Error> {
        verify_blob_kzg_proof_batch(
            blobs,
            commitment_bytes,
            proof_bytes,
            s,
        )
    }
}
