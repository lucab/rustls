use msgs::enums::{SignatureAlgorithm, SignatureScheme};
use util;
use key;
use error::TLSError;

use untrusted;

use ring;
use ring::signature;
use ring::signature::RSAKeyPair;
use webpki;

use std::sync::Arc;
use std::mem;

/// An abstract signing key.
pub trait SigningKey : Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer : Send + Sync {
    /// Signs `message` using the selected scheme.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError>;

    /// Reveals which scheme will be used when you call `sign()`.
    fn get_scheme(&self) -> SignatureScheme;
}

/// A packaged together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response and/or SCT.
#[derive(Clone)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<key::Certificate>,

    /// The certified key.
    pub key: Arc<Box<SigningKey>>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,

    /// An optional collection of SCTs from CT logs, proving the
    /// certificate is included on those logs.  This must be
    /// a `SignedCertificateTimestampList` encoding; see RFC6962.
    pub sct_list: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<key::Certificate>, key: Arc<Box<SigningKey>>) -> CertifiedKey {
        CertifiedKey {
            cert: cert,
            key: key,
            ocsp: None,
            sct_list: None,
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&key::Certificate, ()> {
        self.cert.get(0).ok_or(())
    }

    /// Steal ownership of the certificate chain.
    pub fn take_cert(&mut self) -> Vec<key::Certificate> {
        mem::replace(&mut self.cert, Vec::new())
    }

    /// Return true if there's an OCSP response.
    pub fn has_ocsp(&self) -> bool {
        self.ocsp.is_some()
    }

    /// Steal ownership of the OCSP response.
    pub fn take_ocsp(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.ocsp, None)
    }

    /// Return true if there's an SCT list.
    pub fn has_sct_list(&self) -> bool {
        self.sct_list.is_some()
    }

    /// Steal ownership of the SCT list.
    pub fn take_sct_list(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.sct_list, None)
    }

    /// Check the certificate chain for validity:
    /// - it should be non-empty list
    /// - the first certificate should be parsable as a x509v3,
    /// - the first certificate should quote the given server name
    ///   (if provided)
    ///
    /// These checks are not security-sensitive.  They are the
    /// *server* attempting to detect accidental misconfiguration.
    pub fn cross_check_end_entity_cert(&self, name: Option<webpki::DNSNameRef>) -> Result<(), TLSError> {
        // Always reject an empty certificate chain.
        let end_entity_cert = self.end_entity_cert().map_err(|()| {
            TLSError::General("No end-entity certificate in certificate chain".to_string())
        })?;

        // Reject syntactically-invalid end-entity certificates.
        let end_entity_cert = webpki::EndEntityCert::from(
            untrusted::Input::from(end_entity_cert.as_ref())).map_err(|_| {
                TLSError::General("End-entity certificate in certificate \
                                  chain is syntactically invalid".to_string())
        })?;

        if let Some(name) = name {
            // If SNI was offered then the certificate must be valid for
            // that hostname. Note that this doesn't fully validate that the
            // certificate is valid; it only validates that the name is one
            // that the certificate is valid for, if the certificate is
            // valid.
            if !end_entity_cert.verify_is_valid_for_dns_name(name).is_ok() {
                return Err(TLSError::General("The server certificate is not \
                                             valid for the given name".to_string()));
            }
        }

        Ok(())
    }
}

/// A `SigningKey` for RSA-PKCS1 or RSA-PSS
pub struct RSASigningKey {
    key: Arc<RSAKeyPair>,
}

static ALL_RSA_SCHEMES: &'static [SignatureScheme] = &[
     SignatureScheme::RSA_PSS_SHA512,
     SignatureScheme::RSA_PSS_SHA384,
     SignatureScheme::RSA_PSS_SHA256,
     SignatureScheme::RSA_PKCS1_SHA512,
     SignatureScheme::RSA_PKCS1_SHA384,
     SignatureScheme::RSA_PKCS1_SHA256,
];

impl RSASigningKey {
    /// Make a new `RSASigningKey` from a DER encoding, in either
    /// PKCS#1 or PKCS#8 format.
    pub fn new(der: &key::PrivateKey) -> Result<RSASigningKey, ()> {
        RSAKeyPair::from_der(untrusted::Input::from(&der.0))
            .or_else(|_| RSAKeyPair::from_pkcs8(untrusted::Input::from(&der.0)))
            .map(|s| {
                 RSASigningKey {
                     key: Arc::new(s),
                 }
            })
            .map_err(|_| ())
    }
}

impl SigningKey for RSASigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<Signer>> {
        util::first_in_both(ALL_RSA_SCHEMES, offered)
            .map(|scheme| RSASigner::new(self.key.clone(), scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

struct RSASigner {
    key: Arc<RSAKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static signature::RSAEncoding
}

impl RSASigner {
    fn new(key: Arc<RSAKeyPair>, scheme: SignatureScheme) -> Box<Signer> {
        let encoding: &signature::RSAEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        Box::new(RSASigner { key, scheme, encoding })
    }
}

impl Signer for RSASigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let rng = ring::rand::SystemRandom::new();
        let mut signer = signature::RSASigningState::new(self.key.clone())
            .map_err(|_| TLSError::General("signing state creation failed".to_string()))?;

        signer.sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| TLSError::General("signing failed".to_string()))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// Regression test for https://github.com/ctz/rustls/issues/74.
#[test]
fn test_ghissue_74() {
    let pem = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2P6jXiRYufQCSVS6qsqmE1ZLQIcfcJMZjl5qg+a6VD9s71yh
0hxu0ow3Fzc7yeh3fvn+2sVFvlMlZ6pu0RVE1Qad4qvnRtEldRuQYcq4Qw6D/3Tq
veyNVsO7NaAl6Eu9yw3XNGdG7eqVyrrFUnYXJ0OipY6LnywCs35G7EAUrmW++dH0
ArndtEqb8uPrD7P2E7f4tU6TZaQpvZnPy/PVWUe8k4VeyEvQASIN6RSIj7gEMlXs
ye4jgFyQmZcvF7cko3/bhWSG6YD4/LmFyEx1gjQk6qEHRXm8j5W1CvSUG544GBne
LzoWIo87uuQAMXk/ZXtgMnHOetLO4lC8Q19VewIDAQABAoIBAHAPyOSUVrHpnsiq
FiCfuPahiQlQ/t6PSRJqFg36ON3LR4Gxz+wHPQBE4yp9HsZd5GBR0NjAKg1pORb5
QHN/zWVKHn1yE2VSG0sIKh8mptQSif6CLbxZjoBxYpwGEa2Od/yGME5iy5GQpTzm
CYNVcw2W80cWf2p7OwXhP9VAHq4U785ahK6x4H+hjMBJRoRy6Zeqz+w/xCyq56fv
xM3qIk8JqhDztU+Ln0x/bug3Xry/CcSsdZL2wxlZwfaD8NpB0GQbaDBfOXVTGdil
8rGLnN7hCUO9AJqpsCUyEVRkB4xBW3CgZU+DpBf6vSKstFsRZMSg32GCHVU7dh/6
TI8xqxkCgYEA4hjr+yqSmhRi5TF3LW36+7z0eDya+82rQcdqry358SRRu1/ZlAda
/N38Qvir0Cj385Jw2wX8HYverry0VJbsGz5OBCB1dXP6HQ81JBCR8oqgtX8anGvl
JsmQRte2gVVeFPe1VsDBxrmUKhZXUSpPwjGIr3OlvsIbeugCPcfxaN8CgYEA9bGF
8MmFREtB2ZS6wZjoSivjcoAhslI3qzmLf+jQU34/a0fiLKa3muYZ+ZDKsh9ZSljK
366BvJ1bU/osnSSuukrtQ88qZpJJvdU9EwTqcNr8L7+1jZArrN/hbB/LARhu1sjG
Fq9O2v8/D1Uo/cjzcFBaaA2rbpXVP4OcXDyWOuUCgYBtsK+T/BSBwhA0p2ntVWUl
ioeEacq7DQ3f7NJ6SLDw57DrWdYiNetTsJK5HxGj/KxGtC4iZGXrI7eWSKCoRUwo
73JEGEdEA089l+otJAjahZzwUMjlSIc06Scg53h4iKULQR3uB7g7JD+Yp5wXGZL2
YLeyf0XTJTLVzwd/V6hsOwKBgQDqNtgTaVhEeWWF0JWT9nsCMgJ55ZG510zASnQk
dEEcRs6YK4d9v1RqMo5ybUf9M4tAJ5MGVunQb0Vfsa6UAyMZ7lFuge/OpgfsEnpN
RjNjcC5WKnAdSmGIREg1db1lBvCqiezkNSx78jUgHbOc8tK2r7LvXJCfM/B8wq7s
8sjXzQKBgQCFtN2BRQj4oyl4itaQCGoWdRZLYJOY5G2tm/Gd+wHQK3FubrMJyZpC
IKhnvhlWh9ghNozMDPaCss22QQyxN2kQdD1oeR05R0bH50OTbnkqrm15hgNhqLGy
nV1B8Jh1Mo2CsI3HmIj9WhBo5Xmv1UqfKq3H30IVvtLSE+xa6qgTlQ==
-----END RSA PRIVATE KEY-----"#;
    let priv_key = key::PrivateKey(pem.to_string().into_bytes());
    let signer = RSASigningKey::new(&priv_key);
    signer.expect("invalid key data");
}
