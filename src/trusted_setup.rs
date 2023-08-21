use crate::{BYTES_PER_G1, BYTES_PER_G2};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

/// Wrapper over a BLS G1 point's byte representation.
#[derive(Debug, Clone, PartialEq)]
struct G1Point([u8; BYTES_PER_G1]);

/// Wrapper over a BLS G2 point's byte representation.
#[derive(Debug, Clone, PartialEq)]
struct G2Point([u8; BYTES_PER_G2]);

/// Contains the trusted setup parameters that are required to instantiate a
/// `c_kzg::KzgSettings` object.
///
/// The serialize/deserialize implementations are written according to
/// the format specified in the the ethereum consensus specs trusted setup files.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/testing_trusted_setups.json
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedSetupGeneric<const FIELD_ELEMENTS_PER_BLOB: usize> {
    #[serde(rename = "setup_G1_lagrange")]
    #[serde(deserialize_with = "deserialize_g1_points::<__D, FIELD_ELEMENTS_PER_BLOB>")]
    g1_points: Vec<G1Point>,
    #[serde(rename = "setup_G2")]
    g2_points: Vec<G2Point>,
}

impl<const FIELD_ELEMENTS_PER_BLOB: usize> TrustedSetupGeneric<FIELD_ELEMENTS_PER_BLOB> {
    pub fn g1_points(&self) -> Vec<[u8; BYTES_PER_G1]> {
        self.g1_points.iter().map(|p| p.0).collect()
    }

    pub fn g2_points(&self) -> Vec<[u8; BYTES_PER_G2]> {
        self.g2_points.iter().map(|p| p.0).collect()
    }

    pub fn g1_len(&self) -> usize {
        self.g1_points.len()
    }
    pub fn g2_len(&self) -> usize {
        self.g2_points.len()
    }
}

impl Serialize for G1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let point = hex::encode(self.0);
        serializer.serialize_str(&point)
    }
}

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let point = hex::encode(self.0);
        serializer.serialize_str(&point)
    }
}

impl<'de> Deserialize<'de> for G1Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G1PointVisitor;

        impl<'de> Visitor<'de> for G1PointVisitor {
            type Value = G1Point;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A 48 byte hex encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G1 point: {}", e)))?;
                if point.len() != BYTES_PER_G1 {
                    return Err(de::Error::custom(format!(
                        "G1 point has invalid length. Expected {} got {}",
                        BYTES_PER_G1,
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G1];
                res.copy_from_slice(&point);
                Ok(G1Point(res))
            }
        }

        deserializer.deserialize_str(G1PointVisitor)
    }
}

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G2PointVisitor;

        impl<'de> Visitor<'de> for G2PointVisitor {
            type Value = G2Point;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A 96 byte hex encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G2 point: {}", e)))?;
                if point.len() != BYTES_PER_G2 {
                    return Err(de::Error::custom(format!(
                        "G2 point has invalid length. Expected {} got {}",
                        BYTES_PER_G2,
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G2];
                res.copy_from_slice(&point);
                Ok(G2Point(res))
            }
        }

        deserializer.deserialize_str(G2PointVisitor)
    }
}

fn deserialize_g1_points<'de, D, const FIELD_ELEMENTS_PER_BLOB: usize>(deserializer: D) -> Result<Vec<G1Point>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut decoded: Vec<G1Point> = serde::de::Deserialize::deserialize(deserializer)?;
    // FIELD_ELEMENTS_PER_BLOB is a compile time parameter that
    // depends on whether lighthouse is compiled with minimal or mainnet features.
    // Minimal and mainnet trusted setup parameters differ only by the
    // number of G1 points they contain.
    //
    // Hence, we truncate the number of G1 points after deserialisation
    // to ensure that we have the right number of g1 points in the
    // trusted setup.
    decoded.truncate(FIELD_ELEMENTS_PER_BLOB);
    Ok(decoded)
}

fn strip_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
}
