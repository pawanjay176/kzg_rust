use crate::consts::*;
use crate::{Bytes32, Bytes48, Error};
use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};
use BLST_ERROR::BLST_SUCCESS;

/* Helper Functions */

pub(crate) fn fr_is_one(p: &fr_t) -> bool {
    *p == FR_ONE
}

pub(crate) fn fr_is_zero(p: &fr_t) -> bool {
    *p == FR_ZERO
}

pub(crate) fn fr_div(a: fr_t, b: fr_t) -> fr_t {
    let mut tmp = blst_fr::default();
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_eucl_inverse(&mut tmp, &b);
        blst_fr_mul(&mut res, &a, &tmp);
        res
    }
}

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

pub(crate) fn fr_from_u64(n: u64) -> fr_t {
    let vals = [n, 0, 0, 0];
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut res, vals.as_ptr());
        res
    }
}

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

pub(crate) fn g1_sub(a: &g1_t, b: &g1_t) -> g1_t {
    let mut b_neg = *b;
    let mut res = g1_t::default();
    unsafe {
        blst_p1_cneg(&mut b_neg, true);
        blst_p1_add_or_double(&mut res, a, &b_neg);
    }
    res
}

pub(crate) fn g2_sub(a: &g2_t, b: &g2_t) -> g2_t {
    let mut b_neg = *b;
    let mut res = g2_t::default();
    unsafe {
        blst_p2_cneg(&mut b_neg, true);
        blst_p2_add_or_double(&mut res, a, &b_neg);
    }
    res
}

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

pub(crate) fn bytes_from_g1(g1_point: &g1_t) -> Bytes48 {
    let mut bytes = Bytes48::default();
    unsafe {
        blst_p1_compress(bytes.bytes.as_mut_ptr(), g1_point);
    }
    bytes
}

pub fn bytes_from_bls_field(field_element: &fr_t) -> Bytes32 {
    let mut s = blst_scalar::default();
    let mut res = Bytes32::default();
    unsafe {
        blst_scalar_from_fr(&mut s, field_element);
        blst_bendian_from_scalar(res.bytes.as_mut_ptr(), &s);
    }
    res
}

///////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
///////////////////////////////////////////////////////////////////////////////

pub(crate) fn hash_to_bls_field(b: &Bytes32) -> fr_t {
    let mut tmp = blst_scalar::default();
    let mut res = fr_t::default();
    unsafe {
        blst_scalar_from_bendian(&mut tmp, b.bytes.as_ptr());
        blst_fr_from_scalar(&mut res, &tmp);
    }
    res
}

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

pub fn bytes_to_kzg_commitment(b: &Bytes48) -> Result<g1_t, Error> {
    validate_kzg_g1(b)
}

pub fn bytes_to_kzg_proof(b: &Bytes48) -> Result<g1_t, Error> {
    validate_kzg_g1(b)
}
