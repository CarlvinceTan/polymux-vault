//! A software WebAuthn authenticator for passkeys held in the vault: it makes
//! ES256 (P-256) keys and signs sign-in challenges with them, for a browser
//! that asks the vault directly instead of going through CDP.
//!
//! Attestation is always "none", and the AAGUID is all zeros, so a site learns
//! nothing about where the passkey lives.

use anyhow::{Context, Result};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};

/// COSE algorithm id for ECDSA with P-256 and SHA-256.
pub const ES256: i64 = -7;

const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED_CREDENTIAL: u8 = 0x40;
const CREDENTIAL_ID_LEN: usize = 16;
const AAGUID: [u8; 16] = [0; 16];

/// A passkey just made: what the vault keeps and what the site is sent.
pub struct MadeKey {
    pub credential_id: Vec<u8>,
    pub private_key_pem: String,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// SubjectPublicKeyInfo DER, as `getPublicKey()` returns it.
    pub public_key_der: Vec<u8>,
}

/// What a sign-in sends back besides the client data.
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    /// ASN.1 DER ECDSA signature over authenticator data then client data hash.
    pub signature: Vec<u8>,
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no system randomness: {error}"))?;
    Ok(bytes)
}

/// Touch ID was passed before the vault was asked, so the user is both present
/// and verified. A passkey that travels with the database is backed up.
fn flags(backed_up: bool) -> u8 {
    let mut flags = USER_PRESENT | USER_VERIFIED;
    if backed_up {
        flags |= BACKUP_ELIGIBLE | BACKED_UP;
    }
    flags
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// Makes a new passkey for `rp_id`.
pub fn make(rp_id: &str, backed_up: bool) -> Result<MadeKey> {
    let key = loop {
        // Almost every 32 random bytes are a valid P-256 scalar.
        if let Ok(key) = SigningKey::from_slice(&random_bytes(32)?) {
            break key;
        }
    };
    let credential_id = random_bytes(CREDENTIAL_ID_LEN)?;
    let point = key.verifying_key().to_sec1_point(false);
    let point = point.as_bytes();
    // Uncompressed SEC1: 0x04, then x, then y.
    let (x, y) = (&point[1..33], &point[33..65]);

    let mut authenticator_data = Vec::with_capacity(160);
    authenticator_data.extend_from_slice(&rp_id_hash(rp_id));
    authenticator_data.push(flags(backed_up) | ATTESTED_CREDENTIAL);
    authenticator_data.extend_from_slice(&0u32.to_be_bytes());
    authenticator_data.extend_from_slice(&AAGUID);
    authenticator_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    authenticator_data.extend_from_slice(&credential_id);
    authenticator_data.extend_from_slice(&cose_es256_key(x, y));

    Ok(MadeKey {
        attestation_object: attestation_none(&authenticator_data),
        private_key_pem: key
            .to_pkcs8_pem(LineEnding::LF)
            .context("encode the private key")?
            .to_string(),
        public_key_der: key
            .verifying_key()
            .to_public_key_der()
            .context("encode the public key")?
            .as_bytes()
            .to_vec(),
        credential_id,
        authenticator_data,
    })
}

/// Signs a sign-in for `rp_id` with a stored key.
pub fn assert(
    private_key_pem: &str,
    rp_id: &str,
    client_data_hash: &[u8],
    sign_count: u32,
    backed_up: bool,
) -> Result<Assertion> {
    let key = SigningKey::from_pkcs8_pem(private_key_pem)
        .context("only ES256 (P-256) passkeys can sign here")?;
    let mut authenticator_data = Vec::with_capacity(37);
    authenticator_data.extend_from_slice(&rp_id_hash(rp_id));
    authenticator_data.push(flags(backed_up));
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(client_data_hash);
    let signature: Signature = key.sign(&signed);
    Ok(Assertion {
        authenticator_data,
        signature: signature.to_der().as_bytes().to_vec(),
    })
}

// The few CBOR shapes WebAuthn needs, in canonical form.

fn cbor_head(major: u8, value: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
}

fn cbor_int(value: i64, out: &mut Vec<u8>) {
    if value >= 0 {
        cbor_head(0, value as u64, out);
    } else {
        cbor_head(1, (-1 - value) as u64, out);
    }
}

fn cbor_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn cbor_text(text: &str, out: &mut Vec<u8>) {
    cbor_head(3, text.len() as u64, out);
    out.extend_from_slice(text.as_bytes());
}

/// COSE_Key for an EC2 P-256 public key: kty 2, alg -7, crv 1, x, y.
fn cose_es256_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    cbor_head(5, 5, &mut out);
    for (label, value) in [(1, 2), (3, ES256), (-1, 1)] {
        cbor_int(label, &mut out);
        cbor_int(value, &mut out);
    }
    cbor_int(-2, &mut out);
    cbor_bytes(x, &mut out);
    cbor_int(-3, &mut out);
    cbor_bytes(y, &mut out);
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": <bytes>}`.
fn attestation_none(authenticator_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(authenticator_data.len() + 32);
    cbor_head(5, 3, &mut out);
    cbor_text("fmt", &mut out);
    cbor_text("none", &mut out);
    cbor_text("attStmt", &mut out);
    cbor_head(5, 0, &mut out);
    cbor_text("authData", &mut out);
    cbor_bytes(authenticator_data, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };

    #[test]
    fn a_made_key_signs_what_its_public_key_verifies() {
        let made = make("example.com", true).unwrap();
        assert_eq!(made.credential_id.len(), CREDENTIAL_ID_LEN);
        assert_eq!(&made.authenticator_data[..32], &rp_id_hash("example.com"));
        assert_eq!(made.authenticator_data[32], 0x5d);

        let hash = Sha256::digest(b"{\"type\":\"webauthn.get\"}");
        let assertion = assert(&made.private_key_pem, "example.com", &hash, 0, true).unwrap();
        assert_eq!(assertion.authenticator_data.len(), 37);
        assert_eq!(assertion.authenticator_data[32], 0x1d);

        let public = VerifyingKey::from_public_key_der(&made.public_key_der).unwrap();
        let signature = Signature::from_der(&assertion.signature).unwrap();
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&hash);
        public.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn the_attestation_object_is_canonical_cbor() {
        let made = make("example.com", false).unwrap();
        let object = &made.attestation_object;
        // map(3), "fmt", "none", "attStmt", map(0), "authData", bytes(len)
        assert_eq!(&object[..5], &[0xa3, 0x63, b'f', b'm', b't']);
        assert_eq!(&object[5..10], &[0x64, b'n', b'o', b'n', b'e']);
        assert_eq!(object[10], 0x67);
        assert_eq!(object[18], 0xa0);
        assert_eq!(object[19], 0x68);
        let length = made.authenticator_data.len();
        assert_eq!(&object[28..30], &[0x58, length as u8]);
        assert_eq!(&object[30..], &made.authenticator_data[..]);
        // The COSE key closes the authenticator data: map(5) with kty, alg, crv, x, y.
        let cose = &made.authenticator_data[55 + CREDENTIAL_ID_LEN..];
        assert_eq!(&cose[..7], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        assert_eq!(&cose[7..10], &[0x21, 0x58, 0x20]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(cose.len(), 77);
    }

    #[test]
    fn a_non_p256_key_is_refused() {
        // Ed25519 PKCS#8 for a throwaway test key; it protects nothing.
        let ed25519 = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFvuuKIkjNnZEKWVmpgLHl10xEY8yCJQ3WsGtegl1+15\n-----END PRIVATE KEY-----\n";
        assert!(assert(ed25519, "example.com", &[0; 32], 0, false).is_err());
    }
}
