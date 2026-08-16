use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
use crate::crypto::{DefaultCurve, EcPoint, Scalar};

pub fn curve_point_to_hex<C: Curve>(p: &C::Point) -> String {
    hex::encode(p.compress().as_ref())
}

pub fn hex_to_curve_point<C: Curve>(hex_str: &str) -> Result<C::Point, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    C::Point::from_compressed(&bytes).ok_or_else(|| "Invalid EC point".to_string())
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

pub fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    Scalar::from_canonical_bytes(&bytes).ok_or_else(|| "non-canonical scalar encoding".to_string())
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    curve_point_to_hex::<DefaultCurve>(p)
}

pub fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    hex_to_curve_point::<DefaultCurve>(hex_str)
}
