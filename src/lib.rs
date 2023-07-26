mod test_formats;
pub mod trusted_setup;
use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};

use BLST_ERROR::BLST_SUCCESS;

#[derive(Debug)]
pub enum KzgError {
    #[doc = "< The supplied data is invalid in some way."]
    BadArgs(String),
    #[doc = "< Internal error - this should never occur."]
    InternalError,
    InvalidBytesLength(String),
    InvalidHexFormat(String),
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

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

pub const CHALLENGE_INPUT_SIZE: usize =
    DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT;

pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

/// Domain seperator for the Fiat-Shamir protocol.
const FIAT_SHAMIR_PROTOCOL_DOMAIN: &str = "FSBLOBVERIFY_V1_";

/// Domain sepearator for a random challenge.
const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &str = "RCKZGBATCH___V1_";

/// Length of above domain strings.
pub const DOMAIN_STR_LENGTH: usize = 16;

/// The number of bytes in a g1 point.
pub const BYTES_PER_G1: usize = 48;

/// The number of bytes in a g2 point.
pub const BYTES_PER_G2: usize = 96;

/// The number of g1 points in a trusted setup.
pub const TRUSTED_SETUP_NUM_G1_POINTS: usize = FIELD_ELEMENTS_PER_BLOB;

/// The number of g2 points in a trusted setup.
pub const TRUSTED_SETUP_NUM_G2_POINTS: usize = 65;

/// Deserialized form of the G1 identity/infinity point
pub const G1_IDENTITY: g1_t = g1_t {
    x: blst::blst_fp { l: [0; 6] },
    y: blst::blst_fp { l: [0; 6] },
    z: blst::blst_fp { l: [0; 6] },
};

/// The G1 generator.
pub const G1_GENERATOR: g1_t = g1_t {
    x: blst::blst_fp {
        l: [
            0x5cb38790fd530c16,
            0x7817fc679976fff5,
            0x154f95c7143ba1c1,
            0xf0ae6acdf3d0e747,
            0xedce6ecc21dbf440,
            0x120177419e0bfb75,
        ],
    },
    y: blst::blst_fp {
        l: [
            0xbaac93d50ce72271,
            0x8c22631a7918fd8e,
            0xdd595f13570725ce,
            0x51ac582950405194,
            0x0e1c8c3fad0059c0,
            0x0bbc3efc5008a26a,
        ],
    },
    z: blst::blst_fp {
        l: [
            0x760900000002fffd,
            0xebf4000bc40c0002,
            0x5f48985753c758ba,
            0x77ce585370525745,
            0x5c071a97a256ec6d,
            0x15f65ec3fa80e493,
        ],
    },
};

/// The G2 generator.
pub const G2_GENERATOR: g2_t = g2_t {
    x: blst::blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0xf5f28fa202940a10,
                    0xb3f5fb2687b4961a,
                    0xa1a893b53e2ae580,
                    0x9894999d1a3caee9,
                    0x6f67b7631863366b,
                    0x058191924350bcd7,
                ],
            },
            blst_fp {
                l: [
                    0xa5a9c0759e23f606,
                    0xaaa0c59dbccd60c3,
                    0x3bb17e18e2867806,
                    0x1b1ab6cc8541b367,
                    0xc2b6ed0ef2158547,
                    0x11922a097360edf3,
                ],
            },
        ],
    },
    y: blst::blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0x4c730af860494c4a,
                    0x597cfa1f5e369c5a,
                    0xe7e6856caa0a635a,
                    0xbbefb5e96e0d495f,
                    0x07d3a975f0ef25a2,
                    0x0083fd8e7e80dae5,
                ],
            },
            blst_fp {
                l: [
                    0xadc0fc92df64b05d,
                    0x18aa270a2b1461dc,
                    0x86adac6a3be4eba0,
                    0x79495c4ec93da33a,
                    0xe7175850a43ccaed,
                    0x0b2bc2a163de1bf2,
                ],
            },
        ],
    },
    z: blst::blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0x760900000002fffd,
                    0xebf4000bc40c0002,
                    0x5f48985753c758ba,
                    0x77ce585370525745,
                    0x5c071a97a256ec6d,
                    0x15f65ec3fa80e493,
                ],
            },
            blst_fp {
                l: [
                    0x0000000000000000,
                    0x0000000000000000,
                    0x0000000000000000,
                    0x0000000000000000,
                    0x0000000000000000,
                    0x0000000000000000,
                ],
            },
        ],
    },
};

const SCALE2_ROOT_OF_UNITY: [[u64; 4]; 32] = [
    [
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0xffffffff00000000,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ],
    [
        0x0001000000000000,
        0xec03000276030000,
        0x8d51ccce760304d0,
        0x0000000000000000,
    ],
    [
        0x7228fd3397743f7a,
        0xb38b21c28713b700,
        0x8c0625cd70d77ce2,
        0x345766f603fa66e7,
    ],
    [
        0x53ea61d87742bcce,
        0x17beb312f20b6f76,
        0xdd1c0af834cec32c,
        0x20b1ce9140267af9,
    ],
    [
        0x360c60997369df4e,
        0xbf6e88fb4c38fb8a,
        0xb4bcd40e22f55448,
        0x50e0903a157988ba,
    ],
    [
        0x8140d032f0a9ee53,
        0x2d967f4be2f95155,
        0x14a1e27164d8fdbd,
        0x45af6345ec055e4d,
    ],
    [
        0x5130c2c1660125be,
        0x98d0caac87f5713c,
        0xb7c68b4d7fdd60d0,
        0x6898111413588742,
    ],
    [
        0x4935bd2f817f694b,
        0x0a0865a899e8deff,
        0x6b368121ac0cf4ad,
        0x4f9b4098e2e9f12e,
    ],
    [
        0x4541b8ff2ee0434e,
        0xd697168a3a6000fe,
        0x39feec240d80689f,
        0x095166525526a654,
    ],
    [
        0x3c28d666a5c2d854,
        0xea437f9626fc085e,
        0x8f4de02c0f776af3,
        0x325db5c3debf77a1,
    ],
    [
        0x4a838b5d59cd79e5,
        0x55ea6811be9c622d,
        0x09f1ca610a08f166,
        0x6d031f1b5c49c834,
    ],
    [
        0xe206da11a5d36306,
        0x0ad1347b378fbf96,
        0xfc3e8acfe0f8245f,
        0x564c0a11a0f704f4,
    ],
    [
        0x6fdd00bfc78c8967,
        0x146b58bc434906ac,
        0x2ccddea2972e89ed,
        0x485d512737b1da3d,
    ],
    [
        0x034d2ff22a5ad9e1,
        0xae4622f6a9152435,
        0xdc86b01c0d477fa6,
        0x56624634b500a166,
    ],
    [
        0xfbd047e11279bb6e,
        0xc8d5f51db3f32699,
        0x483405417a0cbe39,
        0x3291357ee558b50d,
    ],
    [
        0xd7118f85cd96b8ad,
        0x67a665ae1fcadc91,
        0x88f39a78f1aeb578,
        0x2155379d12180caa,
    ],
    [
        0x08692405f3b70f10,
        0xcd7f2bd6d0711b7d,
        0x473a2eef772c33d6,
        0x224262332d8acbf4,
    ],
    [
        0x6f421a7d8ef674fb,
        0xbb97a3bf30ce40fd,
        0x652f717ae1c34bb0,
        0x2d3056a530794f01,
    ],
    [
        0x194e8c62ecb38d9d,
        0xad8e16e84419c750,
        0xdf625e80d0adef90,
        0x520e587a724a6955,
    ],
    [
        0xfece7e0e39898d4b,
        0x2f69e02d265e09d9,
        0xa57a6e07cb98de4a,
        0x03e1c54bcb947035,
    ],
    [
        0xcd3979122d3ea03a,
        0x46b3105f04db5844,
        0xc70d0874b0691d4e,
        0x47c8b5817018af4f,
    ],
    [
        0xc6e7a6ffb08e3363,
        0xe08fec7c86389bee,
        0xf2d38f10fbb8d1bb,
        0x0abe6a5e5abcaa32,
    ],
    [
        0x5616c57de0ec9eae,
        0xc631ffb2585a72db,
        0x5121af06a3b51e3c,
        0x73560252aa0655b2,
    ],
    [
        0x92cf4deb77bd779c,
        0x72cf6a8029b7d7bc,
        0x6e0bcd91ee762730,
        0x291cf6d68823e687,
    ],
    [
        0xce32ef844e11a51e,
        0xc0ba12bb3da64ca5,
        0x0454dc1edc61a1a3,
        0x019fe632fd328739,
    ],
    [
        0x531a11a0d2d75182,
        0x02c8118402867ddc,
        0x116168bffbedc11d,
        0x0a0a77a3b1980c0d,
    ],
    [
        0xe2d0a7869f0319ed,
        0xb94f1101b1d7a628,
        0xece8ea224f31d25d,
        0x23397a9300f8f98b,
    ],
    [
        0xd7b688830a4f2089,
        0x6558e9e3f6ac7b41,
        0x99e276b571905a7d,
        0x52dd465e2f094256,
    ],
    [
        0x474650359d8e211b,
        0x84d37b826214abc6,
        0x8da40c1ef2bb4598,
        0x0c83ea7744bf1bee,
    ],
    [
        0x694341f608c9dd56,
        0xed3a181fabb30adc,
        0x1339a815da8b398f,
        0x2c6d4e4511657e1e,
    ],
    [
        0x63e7cb4906ffc93f,
        0xf070bb00e28a193d,
        0xad1715b02e5713b5,
        0x4b5371495990693f,
    ],
];

/// The zero field element.
const FR_ZERO: fr_t = fr_t { l: [0, 0, 0, 0] };

/// This is 1 in Blst's `blst_fr` limb representation. Crazy but true.
const FR_ONE: fr_t = fr_t {
    l: [
        0x00000001fffffffe,
        0x5884b7fa00034802,
        0x998c4fefecbc4ff5,
        0x1824b159acc5056f,
    ],
};

/// Converts a hex string (with or without the 0x prefix) to bytes.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct Polynomial {
    evals: [fr_t; FIELD_ELEMENTS_PER_BLOB],
}

impl Default for Polynomial {
    fn default() -> Self {
        Self {
            evals: [fr_t::default(); FIELD_ELEMENTS_PER_BLOB],
        }
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Bytes32 {
    bytes: [u8; 32],
}

impl Bytes32 {
    pub fn from_bytes(b: &[u8]) -> Result<Self, KzgError> {
        if b.len() != 32 {
            return Err(KzgError::BadArgs(format!(
                "Bytes32 length error. Expected 32, got {}",
                b.len()
            )));
        }
        let mut arr = [0; 32];
        arr.copy_from_slice(b);
        Ok(Bytes32 { bytes: arr })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Bytes48 {
    bytes: [u8; 48],
}

impl Bytes48 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KzgError> {
        if bytes.len() != 48 {
            return Err(KzgError::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                32,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 48];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

impl Default for Bytes48 {
    fn default() -> Self {
        Self { bytes: [0; 48] }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Blob {
    bytes: [u8; BYTES_PER_BLOB],
}

impl Blob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KzgError> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(KzgError::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_BLOB,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; BYTES_PER_BLOB];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_bytes(&hex_to_bytes(hex_str)?)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct KzgCommitment(pub Bytes48);

impl KzgCommitment {
    pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Ok(Self(Bytes48::from_bytes(&hex_to_bytes(hex_str)?)?))
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct KzgProof(pub Bytes48);

impl KzgProof {
    pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Ok(Self(Bytes48::from_bytes(&hex_to_bytes(hex_str)?)?))
    }
}

/* Helper Functions */

fn fr_is_one(p: &fr_t) -> bool {
    *p == FR_ONE
}

fn fr_is_zero(p: &fr_t) -> bool {
    *p == FR_ZERO
}

fn fr_div(a: fr_t, b: fr_t) -> fr_t {
    let mut tmp = blst_fr::default();
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_eucl_inverse(&mut tmp, &b);
        blst_fr_mul(&mut res, &a, &tmp);
        res
    }
}

fn fr_pow(a: fr_t, mut n: u64) -> fr_t {
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

fn fr_from_u64(n: u64) -> fr_t {
    let vals = [n, 0, 0, 0];
    let mut res = blst_fr::default();
    unsafe {
        blst_fr_from_uint64(&mut res, vals.as_ptr());
        res
    }
}

fn fr_batch_inv(a: &[fr_t]) -> Result<Vec<fr_t>, KzgError> {
    if a.is_empty() {
        return Err(KzgError::BadArgs("fr_batch_inv input is empty".to_string()));
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
        return Err(KzgError::BadArgs("fr_batch_inv zero input".to_string()));
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

fn g1_mul(a: &g1_t, b: &fr_t) -> g1_t {
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

fn g2_mul(a: &g2_t, b: &fr_t) -> g2_t {
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

fn g1_sub(a: &g1_t, b: &g1_t) -> g1_t {
    let mut b_neg = *b;
    let mut res = g1_t::default();
    unsafe {
        blst_p1_cneg(&mut b_neg, true);
        blst_p1_add_or_double(&mut res, a, &b_neg);
    }
    res
}

fn g2_sub(a: &g2_t, b: &g2_t) -> g2_t {
    let mut b_neg = *b;
    let mut res = g2_t::default();
    unsafe {
        blst_p2_cneg(&mut b_neg, true);
        blst_p2_add_or_double(&mut res, a, &b_neg);
    }
    res
}

fn pairings_verify(a1: &g1_t, a2: &g2_t, b1: &g1_t, b2: &g2_t) -> bool {
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

pub fn bytes_from_g1(g1_point: &g1_t) -> Bytes48 {
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

fn hash_to_bls_field(b: &Bytes32) -> fr_t {
    let mut tmp = blst_scalar::default();
    let mut res = fr_t::default();
    unsafe {
        blst_scalar_from_bendian(&mut tmp, b.bytes.as_ptr());
        blst_fr_from_scalar(&mut res, &tmp);
    }
    res
}

fn bytes_to_bls_field(b: &Bytes32) -> Result<fr_t, KzgError> {
    let mut tmp = blst_scalar::default();
    let mut res = fr_t::default();
    unsafe {
        blst_scalar_from_bendian(&mut tmp, b.bytes.as_ptr());
        if !blst_scalar_fr_check(&tmp) {
            return Err(KzgError::BadArgs(
                "bytes_to_bls_field Invalid bytes32".to_string(),
            ));
        }
        blst_fr_from_scalar(&mut res, &tmp);
        Ok(res)
    }
}

fn validate_kzg_g1(b: &Bytes48) -> Result<g1_t, KzgError> {
    let mut p1_affine = blst_p1_affine::default();
    let mut res = g1_t::default();

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */

    unsafe {
        let ret = blst_p1_uncompress(&mut p1_affine, b.bytes.as_ptr());
        if ret != BLST_SUCCESS {
            return Err(KzgError::BadArgs(format!(
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
            return Err(KzgError::BadArgs(
                "validate_kzg_g1 not in right subgroup".to_string(),
            ));
        }
    }
    Ok(res)
}

pub fn bytes_to_kzg_commitment(b: &Bytes48) -> Result<g1_t, KzgError> {
    validate_kzg_g1(b)
}

pub fn bytes_to_kzg_proof(b: &Bytes48) -> Result<g1_t, KzgError> {
    validate_kzg_g1(b)
}

fn blob_to_polynomial(blob: &Blob) -> Result<Polynomial, KzgError> {
    let mut poly = Polynomial {
        evals: [Default::default(); FIELD_ELEMENTS_PER_BLOB],
    };
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
fn compute_challenge(blob: &Blob, commitment_bytes: &Bytes48) -> Result<fr_t, KzgError> {
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
        return Err(KzgError::BadArgs("Invalid commitment bytes".to_string()));
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

fn g1_lincomb_fast(p: &[g1_t], coeffs: &[fr_t]) -> Result<g1_t, KzgError> {
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
) -> Result<fr_t, KzgError> {
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

fn poly_to_kzg_commitment(p: &Polynomial, s: &KzgSettings) -> Result<g1_t, KzgError> {
    g1_lincomb_fast(&s.g1_values, &p.evals)
}

pub fn blob_to_kzg_commitment(blob: &Blob, s: &KzgSettings) -> Result<KzgCommitment, KzgError> {
    let poly = blob_to_polynomial(blob)?;
    let commitment = poly_to_kzg_commitment(&poly, s)?;
    let commitment_bytes = bytes_from_g1(&commitment);
    Ok(KzgCommitment(commitment_bytes))
}

pub fn compute_kzg_proof(
    blob: &Blob,
    z_bytes: &Bytes32,
    s: &KzgSettings,
) -> Result<(KzgProof, Bytes32), KzgError> {
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
) -> Result<KzgProof, KzgError> {
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
) -> Result<(KzgProof, fr_t), KzgError> {
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
    let out_g1 = g1_lincomb_fast(&s.g1_values, &q.evals)?;

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
) -> Result<bool, KzgError> {
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
) -> Result<bool, KzgError> {
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
) -> Result<Vec<fr_t>, KzgError> {
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
        return Err(KzgError::InternalError);
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
) -> Result<bool, KzgError> {
    let n = commitments_g1.len();

    if n == 0 {
        return Err(KzgError::BadArgs(
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
) -> Result<bool, KzgError> {
    let n = blobs.len();
    if blobs.len() != commitment_bytes.len() || commitment_bytes.len() != proof_bytes.len() {
        return Err(KzgError::BadArgs(format!(
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
fn bit_reversal_permutation<T: Copy>(values: Vec<T>, n: usize) -> Result<Vec<T>, KzgError> {
    if values.is_empty() || n >> 32 != 0 || !n.is_power_of_two() || n.ilog2() == 0 {
        return Err(KzgError::BadArgs(
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

fn expand_root_of_unity(root: &fr_t, width: u64) -> Result<Vec<fr_t>, KzgError> {
    let mut res: Vec<blst_fr> = (0..width + 1).map(|_| blst_fr::default()).collect();
    res[0] = FR_ONE;
    res[1] = *root;

    let mut i = 2usize;
    let mut tmp = blst_fr::default();

    while !fr_is_one(&res[i - 1]) {
        if i > width as usize {
            return Err(KzgError::BadArgs(
                "expand_root_of_unity i > width".to_string(),
            ));
        }
        unsafe {
            blst_fr_mul(&mut tmp, &res[i - 1], root);
        }
        res[i] = tmp;
        i += 1;
    }

    if !fr_is_one(&res[width as usize]) {
        return Err(KzgError::BadArgs(
            "expand_root_of_unity assertion failed".to_string(),
        ));
    }
    Ok(res)
}

fn compute_roots_of_unity(max_scale: u32) -> Result<Vec<fr_t>, KzgError> {
    /* Calculate the max width */
    let max_width = 1 << max_scale;

    /* Get the root of unity */
    if max_scale >= SCALE2_ROOT_OF_UNITY.len() as u32 {
        return Err(KzgError::BadArgs(
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

fn is_trusted_setup_in_lagrange_form(s: &KzgSettings) -> Result<(), KzgError> {
    /* Trusted setup is too small; we can't work with this */
    if s.g1_values.len() < 2 || s.g2_values.len() < 2 {
        return Err(KzgError::BadArgs(
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
        Err(KzgError::BadArgs(
            "is_trusted_setup_in_lagrange_form monomial form".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn load_trusted_setup(
    g1_bytes: Vec<u8>,
    g2_bytes: Vec<u8>,
    n1: usize,
    n2: usize,
) -> Result<KzgSettings, KzgError> {
    let mut kzg_settings = KzgSettings::default();

    /* Sanity check in case this is called directly */

    if n1 != TRUSTED_SETUP_NUM_G1_POINTS || n2 != TRUSTED_SETUP_NUM_G2_POINTS {
        return Err(KzgError::BadArgs(
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
                return Err(KzgError::BadArgs(
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
                return Err(KzgError::BadArgs(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use test_formats::*;
    use trusted_setup::TrustedSetup;

    const TRUSTED_SETUP: &[u8] = include_bytes!("../testing_trusted_setups.json");
    const BLOB_TO_KZG_COMMITMENT_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/blob_to_kzg_commitment/*/*/*";
    const COMPUTE_KZG_PROOF_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/compute_kzg_proof/*/*/*";
    const COMPUTE_BLOB_KZG_PROOF_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/compute_blob_kzg_proof/*/*/*";
    const VERIFY_KZG_PROOF_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/verify_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/verify_blob_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: &str =
        "/Users/pawan/ethereum/c-kzg-4844/tests/verify_blob_kzg_proof_batch/*/*/*";

    fn load_trusted_setup_from_file() -> KzgSettings {
        let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP).unwrap();
        let n1 = trusted_setup.g1_len();
        let n2 = trusted_setup.g2_len();
        dbg!(n1, n2);
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
        load_trusted_setup(g1_points, g2_points, n1, n2).unwrap()
    }

    #[test]
    fn test_blob_to_kzg_commitment() {
        let kzg_settings = load_trusted_setup_from_file();
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
        let kzg_settings = load_trusted_setup_from_file();
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
        let kzg_settings = load_trusted_setup_from_file();
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
        let kzg_settings = load_trusted_setup_from_file();
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
        let kzg_settings = load_trusted_setup_from_file();
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
        let kzg_settings = load_trusted_setup_from_file();
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
