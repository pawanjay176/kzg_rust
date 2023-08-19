use blst::*;
use blst::{blst_fr as fr_t, blst_p1 as g1_t, blst_p2 as g2_t};

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;


pub const fn challenge_input_size<const BYTES_PER_BLOB: usize>() -> usize {
    DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT
}

/// Domain seperator for the Fiat-Shamir protocol.
pub const FIAT_SHAMIR_PROTOCOL_DOMAIN: &str = "FSBLOBVERIFY_V1_";

/// Domain sepearator for a random challenge.
pub const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &str = "RCKZGBATCH___V1_";

/// Length of above domain strings.
pub const DOMAIN_STR_LENGTH: usize = 16;

/// The number of bytes in a g1 point.
pub const BYTES_PER_G1: usize = 48;

/// The number of bytes in a g2 point.
pub const BYTES_PER_G2: usize = 96;

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

pub const SCALE2_ROOT_OF_UNITY: [[u64; 4]; 32] = [
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
pub const FR_ZERO: fr_t = fr_t { l: [0, 0, 0, 0] };

/// This is 1 in Blst's `blst_fr` limb representation. Crazy but true.
pub const FR_ONE: fr_t = fr_t {
    l: [
        0x00000001fffffffe,
        0x5884b7fa00034802,
        0x998c4fefecbc4ff5,
        0x1824b159acc5056f,
    ],
};
