use kerberos_crypto::Key;
use kerberos_crypto::KerberosCipher;

use kerberos_constants::etypes::{AES128_CTS_HMAC_SHA1_96,AES256_CTS_HMAC_SHA1_96,RC4_HMAC};

pub struct KerberosUser {
	pub domain: String,
	pub username: String,
	pub credential : Key,
	pub encryption_key : Vec<u8>,
	pub custom_salt: Option<Vec<u8>>
}

impl KerberosUser {
	pub fn from_password(domain: &str, username: &str, password: &str) -> Result<KerberosUser,KerberosUserError> {
		let mut user = KerberosUser {
			domain: domain.to_string().to_ascii_uppercase(),
			username: username.to_string(),
			credential: Key::Secret(password.to_string()),
			encryption_key: Vec::new(),
			custom_salt: None
		};
		Ok(user)
	}
	
	pub fn from_ntlm_hash(domain: &str, username: &str, hash: &[u8]) -> Result<KerberosUser,KerberosUserError> {
		if hash.len() != 16 {
			let e = KerberosUserError::InvalidHashSize(hash.len());
			return Err(e);
		}
		let mut key : [u8;16] = [0;16];
		for i in 0..16 {
			key[i] = hash[i];
		}
	
		let mut user = KerberosUser {
			domain: domain.to_string(),
			username: username.to_string(),
			credential: Key::RC4Key(key),
			encryption_key: Vec::new(),
			custom_salt: None
		};
		Ok(user)
	}
	
	pub fn from_aes_key(domain: &str, username: &str, raw_key: &[u8]) -> Result<KerberosUser,KerberosUserError> {
		// 32 bytes is AES256, 16 bytes is AES128
		let key : Key = match raw_key.len() {
			16 => {
				let mut key : [u8;16] = [0;16];
				for i in 0..16 {
					key[i] = raw_key[i];
				}
				Key::AES128Key(key)
			},
			32 => {
				let mut key : [u8;32] = [0;32];
				for i in 0..32 {
					key[i] = raw_key[i];
				}
				Key::AES256Key(key)
			},
			invalid_len => {
				let e = KerberosUserError::InvalidKeySize(invalid_len);
				return Err(e);
			}
		};
		
		let mut user = KerberosUser {
			domain: domain.to_string(),
			username: username.to_string(),
			credential: key,
			encryption_key: Vec::new(),
			custom_salt: None
		};
		Ok(user)
	}
	
	pub fn set_salt(&mut self, salt : &str) {
		let bytes = salt.as_bytes().to_vec();
		self.custom_salt = Some(bytes);
	}
	
	pub fn get_salt(&self) -> Vec<u8> {
		match &self.custom_salt {
			Some(salt) => salt.to_vec(),
			None => self.get_cipher().generate_salt(&self.domain, &self.username)
		}
	}

	pub fn generate_encryption_key(&mut self) {
		let cipher = self.get_cipher();
		match &self.credential {
			Key::Secret(password) => {
				let salt = self.get_salt();
				self.encryption_key = cipher.generate_key_from_string(&password, &salt);
			},
			Key::RC4Key(key) => {
				self.encryption_key = key.to_vec();
			},
			Key::AES128Key(key) => {
				self.encryption_key = key.to_vec();
			},
			Key::AES256Key(key) => {
				self.encryption_key = key.to_vec();
			}
		}
	}

	pub fn get_etype(&self) -> i32 {
		match &self.credential {
			Key::Secret(_) => AES256_CTS_HMAC_SHA1_96,
			Key::RC4Key(_) => RC4_HMAC,
			Key::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
			Key::AES256Key(_) =>AES256_CTS_HMAC_SHA1_96
		}
	}
	
	pub fn get_cipher(&self) -> Box<dyn KerberosCipher> {
		let etype = self.get_etype();
		kerberos_crypto::new_kerberos_cipher(etype).unwrap()
	}
}

#[derive(Debug)]
pub enum KerberosUserError {
	InvalidHashSize(usize),
	InvalidKeySize(usize)
}
