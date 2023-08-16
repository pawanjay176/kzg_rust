mod consts;
mod test_formats;
pub mod trusted_setup;
mod utils;

use crate::consts::*;
pub use crate::consts::{
    BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF,
    FIELD_ELEMENTS_PER_BLOB,
};
use crate::utils::*;

use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};
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
        if g1_bytes.len() != TRUSTED_SETUP_NUM_G1_POINTS {
            return Err(Error::InvalidTrustedSetup(format!(
                "Invalid number of g1 points in trusted setup. Expected {} got {}",
                TRUSTED_SETUP_NUM_G1_POINTS,
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
            TRUSTED_SETUP_NUM_G1_POINTS,
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
    bytes: [u8; 32],
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
    bytes: [u8; 48],
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

/// Note: using commitment_bytes instead of g1_t like the c code since
/// we seem to be doing unnecessary conversions
fn compute_challenge(blob: &Blob, commitment_bytes: &Bytes48) -> Result<fr_t, Error> {
    let mut bytes = [0u8; CHALLENGE_INPUT_SIZE];
    let mut offset = 0;

    /* Copy domain separator */
    bytes[offset..offset + DOMAIN_STR_LENGTH]
        .copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN.as_bytes());
    offset += DOMAIN_STR_LENGTH;

    /* Copy polynomial degree (16-bytes, big-endian) */
    bytes[offset..offset + std::mem::size_of::<u64>()]
        .copy_from_slice(0u64.to_be_bytes().as_slice());
    offset += std::mem::size_of::<u64>();
    bytes[offset..offset + std::mem::size_of::<u64>()]
        .copy_from_slice(FIELD_ELEMENTS_PER_BLOB.to_be_bytes().as_slice());
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
    assert_eq!(offset, { CHALLENGE_INPUT_SIZE });

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

fn g1_lincomb_naive(p: &[g1_t], coeffs: &[fr_t]) -> g1_t {
    assert_eq!(p.len(), coeffs.len());
    let len = p.len();

    let mut tmp;
    let mut res = G1_IDENTITY;
    for i in 0..len {
        tmp = g1_mul(&p[i], &coeffs[i]);
        unsafe { blst_p1_add_or_double(&mut res, &res, &tmp) }
    }
    res
}

fn g1_lincomb_fast(p: &[g1_t], coeffs: &[fr_t]) -> Result<g1_t, Error> {
    let len = p.len();
    if len < 8 {
        return Ok(g1_lincomb_naive(p, coeffs));
    }
    let scratch_size: usize;
    let mut res = g1_t::default();
    unsafe {
        scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(len);
    }
    let mut scratch: Vec<_> = (0..scratch_size).map(|_| 0u64).collect();
    let mut p_affine: Vec<_> = (0..len).map(|_| blst_p1_affine::default()).collect();
    let mut scalars: Vec<_> = (0..len).map(|_| blst_scalar::default()).collect();

    /* Transform the points to affine representation */
    unsafe {
        let p_arg: [_; 2] = [p.as_ptr(), std::ptr::null()];
        blst_p1s_to_affine(p_affine.as_mut_ptr(), p_arg.as_ptr(), len);

        /* Transform the field elements to 256-bit scalars */
        for i in 0..len {
            blst_scalar_from_fr(&mut scalars[i], &coeffs[i])
        }

        /* Call the Pippenger implementation */
        // WARNING: potential segfault here
        let scalars_arg: [_; 2] = [scalars[0].b.as_ptr(), std::ptr::null()];
        let points_arg: [_; 2] = [p_affine.as_ptr(), std::ptr::null()];
        blst_p1s_mult_pippenger(
            &mut res,
            points_arg.as_ptr(),
            len,
            scalars_arg.as_ptr(),
            255,
            scratch.as_mut_ptr(),
        );
    }

    Ok(res)
}

fn compute_powers(x: &fr_t, n: usize) -> Vec<fr_t> {
    let mut current_power = FR_ONE;
    let mut res = Vec::with_capacity(n);
    for _ in 0..n {
        res.push(current_power);
        unsafe {
            blst_fr_mul(&mut current_power, &current_power, x);
        }
    }
    res
}

///////////////////////////////////////////////////////////////////////////////
// Polynomials Functions
///////////////////////////////////////////////////////////////////////////////

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
        if *x == s.roots_of_unity[i] {
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
    res = fr_div(res, fr_from_u64(FIELD_ELEMENTS_PER_BLOB as u64));
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

fn poly_to_kzg_commitment(p: &Polynomial, s: &KzgSettings) -> Result<g1_t, Error> {
    g1_lincomb_fast(&s.g1_values, p.evals.as_slice())
}

pub fn blob_to_kzg_commitment(blob: &Blob, s: &KzgSettings) -> Result<KzgCommitment, Error> {
    let poly = blob_to_polynomial(blob)?;
    let commitment = poly_to_kzg_commitment(&poly, s)?;
    let commitment_bytes = bytes_from_g1(&commitment);
    Ok(KzgCommitment(commitment_bytes))
}

pub fn compute_kzg_proof(
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

pub fn compute_blob_kzg_proof(
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
        if *z == s.roots_of_unity[i] {
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

pub fn verify_kzg_proof(
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

pub fn verify_blob_kzg_proof(
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

fn compute_r_powers(
    commitments_g1: &[g1_t],
    zs_fr: &[fr_t],
    ys_fr: &[fr_t],
    proofs_g1: &[g1_t],
) -> Result<Vec<fr_t>, Error> {
    let n = commitments_g1.len();
    let input_size = DOMAIN_STR_LENGTH
        + std::mem::size_of::<u64>()
        + std::mem::size_of::<u64>()
        + (n * (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF));

    let mut bytes: Vec<u8> = Vec::with_capacity(input_size);
    /* Copy domain separator */
    bytes.extend_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN.as_bytes());

    /* Copy degree of the polynomial */
    bytes.extend_from_slice(&FIELD_ELEMENTS_PER_BLOB.to_be_bytes());

    /* Copy number of commitments */
    bytes.extend_from_slice(&n.to_be_bytes());

    for i in 0..n {
        /* Copy commitment */
        bytes.extend_from_slice(&bytes_from_g1(&commitments_g1[i]).bytes);
        /* Copy z */
        bytes.extend_from_slice(&bytes_from_bls_field(&zs_fr[i]).bytes);
        /* Copy y */
        bytes.extend_from_slice(&bytes_from_bls_field(&ys_fr[i]).bytes);
        /* Copy proof */
        bytes.extend_from_slice(&bytes_from_g1(&proofs_g1[i]).bytes);
    }
    if bytes.len() != input_size {
        return Err(Error::InternalError);
    }
    /* Now let's create the challenge! */
    let mut r_bytes = Bytes32::default();
    unsafe {
        blst_sha256(r_bytes.bytes.as_mut_ptr(), bytes.as_ptr(), input_size);
    }
    let r = hash_to_bls_field(&r_bytes);
    Ok(compute_powers(&r, n))
}

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
    let proof_lincomb = g1_lincomb_naive(proofs_g1, &r_powers);

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
    let proof_z_lincomb = g1_lincomb_naive(proofs_g1, &r_times_z);

    let c_minus_y_lincomb = g1_lincomb_naive(&c_minus_y, &r_powers);

    let mut rhs_g1 = blst_p1::default();
    /* Get C_minus_y_lincomb + proof_z_lincomb */
    unsafe {
        blst_p1_add_or_double(&mut rhs_g1, &c_minus_y_lincomb, &proof_z_lincomb);
    }

    /* Do the pairing check! */
    let res = pairings_verify(&proof_lincomb, &s.g2_values[1], &rhs_g1, &G2_GENERATOR);
    Ok(res)
}

pub fn verify_blob_kzg_proof_batch(
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

/// NOTE: Not swapping in place like the c code, returns a new vector
fn bit_reversal_permutation<T: Copy>(values: Vec<T>, n: usize) -> Result<Vec<T>, Error> {
    if values.is_empty() || n >> 32 != 0 || !n.is_power_of_two() || n.ilog2() == 0 {
        return Err(Error::BadArgs(
            "bit_reversal_permutation invalid args".to_string(),
        ));
    }

    let mut res = Vec::with_capacity(n);
    for i in 0..n {
        let bit_reversed_i = reverse_bits(i as u32, n as u32);
        res.push(values[bit_reversed_i as usize]);
    }

    Ok(res)
}

fn expand_root_of_unity(root: &fr_t, width: u64) -> Result<Vec<fr_t>, Error> {
    let mut res: Vec<blst_fr> = (0..width + 1).map(|_| blst_fr::default()).collect();
    res[0] = FR_ONE;
    res[1] = *root;

    let mut i = 2usize;
    let mut tmp = blst_fr::default();

    while !fr_is_one(&res[i - 1]) {
        if i > width as usize {
            return Err(Error::BadArgs("expand_root_of_unity i > width".to_string()));
        }
        unsafe {
            blst_fr_mul(&mut tmp, &res[i - 1], root);
        }
        res[i] = tmp;
        i += 1;
    }

    if !fr_is_one(&res[width as usize]) {
        return Err(Error::BadArgs(
            "expand_root_of_unity assertion failed".to_string(),
        ));
    }
    Ok(res)
}

fn compute_roots_of_unity(max_scale: u32) -> Result<Vec<fr_t>, Error> {
    /* Calculate the max width */
    let max_width = 1 << max_scale;

    /* Get the root of unity */
    if max_scale >= SCALE2_ROOT_OF_UNITY.len() as u32 {
        return Err(Error::BadArgs(
            "compute_roots_of_unity max_scale too large".to_string(),
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

fn is_trusted_setup_in_lagrange_form(s: &KzgSettings) -> Result<(), Error> {
    /* Trusted setup is too small; we can't work with this */
    if s.g1_values.len() < 2 || s.g2_values.len() < 2 {
        return Err(Error::BadArgs(
            "is_trusted_setup_in_lagrange_form invalid args".to_string(),
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
            "is_trusted_setup_in_lagrange_form monomial form".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn load_trusted_setup(
    g1_bytes: Vec<u8>,
    g2_bytes: Vec<u8>,
    n1: usize,
    n2: usize,
) -> Result<KzgSettings, Error> {
    let mut kzg_settings = KzgSettings::default();

    /* Sanity check in case this is called directly */

    if n1 != TRUSTED_SETUP_NUM_G1_POINTS || n2 != TRUSTED_SETUP_NUM_G2_POINTS {
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

pub fn load_trusted_setup_from_file<P: AsRef<Path>>(
    trusted_setup_json_file: P,
) -> Result<KzgSettings, Error> {
    let trusted_setup_file = std::fs::File::open(trusted_setup_json_file)
        .map_err(|e| Error::InvalidTrustedSetup(e.to_string()))?;
    let trusted_setup: trusted_setup::TrustedSetup =
        serde_json::from_reader(&trusted_setup_file).unwrap();
    let n1 = trusted_setup.g1_len();
    let n2 = trusted_setup.g2_len();
    let g1_points = trusted_setup
        .g1_points()
        .into_iter()
        .fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x);
            acc
        });
    let g2_points = trusted_setup
        .g2_points()
        .into_iter()
        .fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x);
            acc
        });
    load_trusted_setup(g1_points, g2_points, n1, n2)
}

#[cfg(test)]
#[cfg(not(feature = "minimal"))]
mod tests {
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
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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

            match blob_to_kzg_commitment(&blob, &kzg_settings) {
                Ok(res) => assert_eq!(res.0.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_compute_kzg_proof() {
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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

            match compute_kzg_proof(&blob, &z, &kzg_settings) {
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
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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

            match compute_blob_kzg_proof(&blob, &KzgCommitment(commitment), &kzg_settings) {
                Ok(res) => assert_eq!(res.0.bytes, test.get_output().unwrap().bytes),

                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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
            match verify_kzg_proof(
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
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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

            match verify_blob_kzg_proof(
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
        let kzg_settings = load_trusted_setup_from_file(TRUSTED_SETUP).unwrap();
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
            match verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),

                _ => assert!(test.get_output().is_none()),
            }
        }
    }
}
