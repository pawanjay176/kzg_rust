use crate::consts::*;
use crate::kzg::{Bytes32, Bytes48, Error};
use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};
use BLST_ERROR::BLST_SUCCESS;

/* Helper Functions */

/// Test whether the operand is one in the finite field.
///
/// NOTE: deviates from c_kzg_4844.c to use rust's `PartialEq` impl.
pub(crate) fn fr_is_one(p: &fr_t) -> bool {
    let mut a = [0u64; 4];
    unsafe {
        blst_uint64_from_fr(a.as_mut_ptr(), p);
    }
    a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0
}

/// Test whether the operand is zero in the finite field.
///
/// NOTE: deviates from c_kzg_4844.c to use rust's `PartialEq` impl.
pub(crate) fn fr_is_zero(p: &fr_t) -> bool {
    *p == FR_ZERO
}

/// Divide a field element by another.
///
/// NOTE: The behaviour for `b == 0` is unspecified.
pub(crate) fn fr_div(a: fr_t, b: fr_t) -> fr_t {
    let mut tmp = blst_fr::default();
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_eucl_inverse(&mut tmp, &b);
        blst_fr_mul(&mut res, &a, &tmp);
        res
    }
}

/// Exponentiation of a field element `a` to `n`.
///
/// Uses square and multiply for `log(n)` performance.
///
/// NOTE: A 64-bit exponent is sufficient for our needs here.
pub(crate) fn fr_pow(a: fr_t, mut n: u64) -> fr_t {
    let mut tmp = a;
    let mut res = FR_ONE;

    unsafe {
        loop {
            if n & 1 != 0 {
                blst_fr_mul(&mut res, &res, &tmp);
            }

            n >>= 1;
            if n == 0 {
                break;
            }
            blst_fr_sqr(&mut tmp, &tmp);
        }
        res
    }
}

/// Create a field element from a single 64-bit unsigned integer.
///
/// This can only generate a tiny fraction of possible field elements,
/// and is mostly useful for testing.
pub(crate) fn fr_from_uint64(n: u64) -> fr_t {
    let vals = [n, 0, 0, 0];
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut res, vals.as_ptr());
        res
    }
}

/// Montgomery batch inversion in finite field.
///
/// This function only supports non zero lengths of `a`.
/// Note: Returns `Error::BadArgs` if zero is found in the input slice.
pub(crate) fn fr_batch_inv(a: &[fr_t]) -> Result<Vec<fr_t>, Error> {
    if a.is_empty() {
        return Err(Error::BadArgs("fr_batch_inv input is empty".to_string()));
    }
    let mut res: Vec<fr_t> = Vec::with_capacity(a.len());
    let mut accumulator = FR_ONE;
    for elem in a {
        res.push(accumulator);
        unsafe {
            blst_fr_mul(&mut accumulator, &accumulator, elem);
        }
    }
    // Bail on zero input
    if fr_is_zero(&accumulator) {
        return Err(Error::BadArgs("fr_batch_inv zero input".to_string()));
    }

    unsafe {
        blst_fr_eucl_inverse(&mut accumulator, &accumulator);
    }

    for i in (0..a.len()).rev() {
        unsafe {
            blst_fr_mul(&mut res[i], &res[i], &accumulator);
            blst_fr_mul(&mut accumulator, &accumulator, &a[i]);
        }
    }

    Ok(res)
}

/// Multiply a G1 group element by a field element.
pub(crate) fn g1_mul(a: &g1_t, b: &fr_t) -> g1_t {
    let mut s = blst_scalar::default();
    let mut res = g1_t::default();
    unsafe {
        blst_scalar_from_fr(&mut s, b);
        // The last argument is the number of bits in the scalar
        blst_p1_mult(
            &mut res,
            a,
            s.b.as_ptr(),
            8 * std::mem::size_of::<blst_scalar>(),
        );
        res
    }
}

/// Multiply a G2 group element by a field element.
pub(crate) fn g2_mul(a: &g2_t, b: &fr_t) -> g2_t {
    let mut s = blst_scalar::default();
    let mut res = g2_t::default();
    unsafe {
        blst_scalar_from_fr(&mut s, b);
        // The last argument is the number of bits in the scalar
        blst_p2_mult(
            &mut res,
            a,
            s.b.as_ptr(),
            8 * std::mem::size_of::<blst_scalar>(),
        );
        res
    }
}

/// Subtraction of G1 group elements.
///
/// Returns `a - b`
pub(crate) fn g1_sub(a: &g1_t, b: &g1_t) -> g1_t {
    let mut b_neg = *b;
    let mut res = g1_t::default();
    unsafe {
        blst_p1_cneg(&mut b_neg, true);
        blst_p1_add_or_double(&mut res, a, &b_neg);
    }
    res
}

/// Subtraction of G2 group elements.
///
/// Returns `a - b`
pub(crate) fn g2_sub(a: &g2_t, b: &g2_t) -> g2_t {
    let mut b_neg = *b;
    let mut res = g2_t::default();
    unsafe {
        blst_p2_cneg(&mut b_neg, true);
        blst_p2_add_or_double(&mut res, a, &b_neg);
    }
    res
}

/// Perform pairings and test whether the outcomes are equal in `G_T`.
///
/// Tests whether `e(a1, a2) == e(b1, b2)`.
///
pub(crate) fn pairings_verify(a1: &g1_t, a2: &g2_t, b1: &g1_t, b2: &g2_t) -> bool {
    let (mut loop0, mut loop1, mut gt_point) = Default::default();
    let (mut aa1, mut bb1) = Default::default();
    let (mut aa2, mut bb2) = Default::default();

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    let mut a1_neg = *a1;
    unsafe {
        blst_p1_cneg(&mut a1_neg, true);
        blst_p1_to_affine(&mut aa1, &a1_neg);
        blst_p1_to_affine(&mut bb1, b1);
        blst_p2_to_affine(&mut aa2, a2);
        blst_p2_to_affine(&mut bb2, b2);

        blst_miller_loop(&mut loop0, &aa2, &aa1);
        blst_miller_loop(&mut loop1, &bb2, &bb1);

        blst_fp12_mul(&mut gt_point, &loop0, &loop1);
        blst_final_exp(&mut gt_point, &gt_point);

        blst_fp12_is_one(&gt_point)
    }
}

///////////////////////////////////////////////////////////////////////////////
// Bytes Conversion Helper Functions
///////////////////////////////////////////////////////////////////////////////

/// Serialize a G1 group element into bytes.
pub(crate) fn bytes_from_g1(g1_point: &g1_t) -> Bytes48 {
    let mut bytes = Bytes48::default();
    unsafe {
        blst_p1_compress(bytes.bytes.as_mut_ptr(), g1_point);
    }
    bytes
}

/// Serialize a BLS field element into bytes.
pub fn bytes_from_bls_field(field_element: &fr_t) -> Bytes32 {
    let mut s = blst_scalar::default();
    let mut res = Bytes32::default();
    unsafe {
        blst_scalar_from_fr(&mut s, field_element);
        blst_bendian_from_scalar(res.bytes.as_mut_ptr(), &s);
    }
    res
}

/// Serialize a 64-bit unsigned integer into big endian bytes.
pub(crate) fn bytes_from_uint64(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

///////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
///////////////////////////////////////////////////////////////////////////////

/// Map bytes to a BLS field element.
pub(crate) fn hash_to_bls_field(b: &Bytes32) -> fr_t {
    let mut tmp = blst_scalar::default();
    let mut res = fr_t::default();
    unsafe {
        blst_scalar_from_bendian(&mut tmp, b.bytes.as_ptr());
        blst_fr_from_scalar(&mut res, &tmp);
    }
    res
}

/// Convert untrusted bytes to a trusted and validated BLS scalar field
/// element.
pub(crate) fn bytes_to_bls_field(b: &Bytes32) -> Result<fr_t, Error> {
    let mut tmp = blst_scalar::default();
    let mut res = fr_t::default();
    unsafe {
        blst_scalar_from_bendian(&mut tmp, b.bytes.as_ptr());
        if !blst_scalar_fr_check(&tmp) {
            return Err(Error::BadArgs(
                "bytes_to_bls_field Invalid bytes32".to_string(),
            ));
        }
        blst_fr_from_scalar(&mut res, &tmp);
        Ok(res)
    }
}

/// Perform BLS validation required by the types `KZGProof` and `KZGCommitment`.
///
/// Note: This function deviates from the spec because it returns (via an
/// output argument) the g1 point. This way is more efficient (faster)
/// but the function name is a bit misleading.
pub(crate) fn validate_kzg_g1(b: &Bytes48) -> Result<g1_t, Error> {
    let mut p1_affine = blst_p1_affine::default();
    let mut res = g1_t::default();

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */

    unsafe {
        let ret = blst_p1_uncompress(&mut p1_affine, b.bytes.as_ptr());
        if ret != BLST_SUCCESS {
            return Err(Error::BadArgs(format!(
                "validate_kzg_g1 blst_p1_uncompress failed err {:?}",
                res
            )));
        }
        blst_p1_from_affine(&mut res, &p1_affine);
        /* The point at infinity is accepted! */
        if blst_p1_is_inf(&res) {
            return Ok(res);
        }
        /* The point must be on the right subgroup */
        if !blst_p1_in_g1(&res) {
            return Err(Error::BadArgs(
                "validate_kzg_g1 not in right subgroup".to_string(),
            ));
        }
    }
    Ok(res)
}

/// Convert untrusted bytes into a trusted and validated KZGCommitment.
pub fn bytes_to_kzg_commitment(b: &Bytes48) -> Result<g1_t, Error> {
    validate_kzg_g1(b)
}

/// Convert untrusted bytes into a trusted and validated KZGProof.
pub fn bytes_to_kzg_proof(b: &Bytes48) -> Result<g1_t, Error> {
    validate_kzg_g1(b)
}

/// Calculate a linear combination of G1 group elements.
///
/// Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n`
/// where `n` is `len - 1`.
///
/// This function computes the result naively without using Pippenger's
/// algorithm.
pub(crate) fn g1_lincomb_naive(p: &[g1_t], coeffs: &[fr_t]) -> g1_t {
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

///  Calculate a linear combination of G1 group elements.
///
///  Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n`
///  where `n` is `len - 1`.
///
///  NOTE: This function **MUST NOT** be called with the point at infinity in `p`.
///
///  While this function is significantly faster than
///  `g1_lincomb_naive()`, we refrain from using it in security-critical places
///  (like verification) because the blst Pippenger code has not been
///  audited. In those critical places, we prefer using `g1_lincomb_naive()` which
///  is much simpler.
///
///  For the benefit of future generations (since Blst has no documentation to
///  speak of), there are two ways to pass the arrays of scalars and points
///  into blst_p1s_mult_pippenger().
///
///  1. Pass `points` as an array of pointers to the points, and pass
///     `scalars` as an array of pointers to the scalars, each of length p.len().
///  2. Pass an array where the first element is a pointer to the contiguous
///     array of points and the second is null, and similarly for scalars.
///
///  We do the second of these to save memory here.
pub(crate) fn g1_lincomb_fast(p: &[g1_t], coeffs: &[fr_t]) -> Result<g1_t, Error> {
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

/// Compute and return [ x^0, x^1, ..., x^{n-1} ].
pub(crate) fn compute_powers(x: &fr_t, n: usize) -> Vec<fr_t> {
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

/// Compute random linear combination challenge scalars for batch verification.
pub(crate) fn compute_r_powers<const FIELD_ELEMENTS_PER_BLOB: usize>(
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
