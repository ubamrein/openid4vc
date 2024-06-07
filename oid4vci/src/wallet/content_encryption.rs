// Copyright (c) 2024 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::bail;
use base64::Engine;
use hmac::{Hmac, Mac};
use libaes::Cipher;
use rsa::rand_core::OsRng;
use oid4vc_core::jwt::base64_url_decode;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use rsa::traits::PublicKeyParts;

use crate::credential_request::{CredentialResponseEncryptionKey, CredentialResponseEncryptionSpecification};

type HmacSha256 = Hmac<Sha256>;

pub trait ContentDecryptor {
    fn public_key(&self) -> CredentialResponseEncryptionKey;
    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification;
    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<Vec<u8>>;
}

pub struct RsaOAEP256 {
    private_key: RsaPrivateKey,
}

impl RsaOAEP256 {
    pub fn new() -> Self {
        // this should never fail, except for some weird entropy issues, but then it's ok to panic
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        Self {
            private_key
        }
    }
}

impl ContentDecryptor for RsaOAEP256 {
    fn public_key(&self) -> CredentialResponseEncryptionKey {
        let public_key = self.private_key.to_public_key();
        let exponent = public_key.e().to_bytes_be();
        let e = base64_encode_bytes(&exponent);
        let n = public_key.n().to_bytes_be();
        let n = base64_encode_bytes(&n);
        CredentialResponseEncryptionKey::Rsa {
            alg: "RSA-OAEP-256".to_string(),
            n,
            e,
            kid: "rsa-key".to_string(),
            r#use: "enc".to_string(),
            kty: "RSA".to_string(),
        }
    }

    fn encryption_specification(&self) -> CredentialResponseEncryptionSpecification {
        let jwk = self.public_key();
        CredentialResponseEncryptionSpecification {
            jwk,
            enc: "A128CBC-HS256".to_string(),
            alg: "RSA-OAEP-256".to_string(),
        }
    }

    fn decrypt(&self, encrypted_token_response: &str) -> anyhow::Result<Vec<u8>> {
        let split_parts = encrypted_token_response.split('.').collect::<Vec<_>>();
        let [header, encrypted_key, iv, payload, authentication_tag, ..] = split_parts.as_slice() else {
            bail!("too less arguments");
        };
        let oaep = rsa::Oaep::new_with_mgf_hash::<Sha256, Sha256>();

        let decrypted_key = self.private_key
            .decrypt(
                oaep,
                &base64_url_decode(&encrypted_key.as_bytes()).map_err(|e| anyhow::anyhow!(e))?,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
        if decrypted_key.len() != 32 {
            bail!("Key length is incorrect");
        }
        let Ok(iv) = base64_url_decode(iv) else {
            bail!("could not decode IV");
        };
        let Ok(data) = base64_url_decode(payload) else {
            bail!("could not decode payload");
        };

        let Ok(authentication_tag) = base64_url_decode(authentication_tag) else {
            bail!("Could not decode header");
        };
        let mut key = [0; 16];
        let mut hmac_key = [0; 16];
        // first 16 bytes are for hmac second 16 bytes are for aes128CBC
        key.copy_from_slice(&decrypted_key[16..]);
        hmac_key.copy_from_slice(&decrypted_key[..16]);

        let mut hmac_content = header.as_bytes().to_vec();
        hmac_content.extend(&iv);
        hmac_content.extend(&data);
        let authenticated_data_size = (header.len() as u64) * 8;
        hmac_content.extend(authenticated_data_size.to_be_bytes());
        let Ok(mut hmac) = HmacSha256::new_from_slice(&hmac_key) else {
            bail!("Could not initialize hmac");
        };
        hmac.update(&hmac_content);
        let auth_tag = hmac.finalize().into_bytes().to_vec();

        if &auth_tag[..16] != &authentication_tag[..] {
            bail!("authentication tag comparison failed\n calculated: {:?}\n provided: {authentication_tag:?} ", &auth_tag[..16]);
        }

        let cipher = Cipher::new_128(&key);
        Ok(cipher.cbc_decrypt(&iv, &data))
    }
}

pub fn base64_encode_bytes<T: AsRef<[u8]>>(bytes: &T) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

pub fn base64_decode_bytes<T: AsRef<[u8]>>(bytes: &T) -> anyhow::Result<Vec<u8>> {
    let Ok(result) = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(bytes.as_ref()) else {
        bail!("Could not decode");
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use hmac::Mac;
    use oid4vc_core::jwt::base64_url_encode;
    use rsa::{rand_core::OsRng, traits::PublicKeyParts};

    use crate::wallet::content_encryption::{base64_encode_bytes, HmacSha256};

    #[test]
    fn test_rsa_mod() {
        let privatekey = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_key = privatekey.to_public_key();
        let exponent = pub_key.e().to_bytes_be();

        let e = base64_encode_bytes(&exponent);
        let n = pub_key.n().to_bytes_be();
        let n = base64_encode_bytes(&n);
        println!("{:?}", exponent);
        println!("{}", pub_key.e().to_string());
        println!("{}", e);
    }

    #[test]
    fn test_hmac_rfc() {
        let additional_data: Vec<u8> = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
            120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
            74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
            50, 73, 110, 48].to_vec();
        let iv: Vec<u8> = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
            101].to_vec();
        let ciphertext: Vec<u8> = [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
            75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
            112, 56, 102].to_vec();
        let authentication_tag: Vec<u8> = [246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
            191].to_vec();

        // let mut hmac_data = additional_data.clone();
        // hmac_data.extend(iv);
        // hmac_data.extend(ciphertext);
        // hmac_data.extend((additional_data.len() * 8).to_be_bytes());
        let hmac_key: Vec<u8> = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
            206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
            44, 207].to_vec();
        let mut auth_tag = HmacSha256::new_from_slice(&hmac_key[..16]).unwrap();
        let mut hmac_data = additional_data.clone();
        hmac_data.extend(&iv);
        hmac_data.extend(&ciphertext);
        hmac_data.extend(&(additional_data.len() * 8).to_be_bytes());
        auth_tag.update(&hmac_data);

        let auth_tag = auth_tag.finalize().into_bytes().to_vec();
        assert_eq!(&auth_tag[..16], &authentication_tag[..]);
    }
}
