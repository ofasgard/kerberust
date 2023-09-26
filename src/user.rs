use crate::ticket::KerberosTicket;

use kerberos_crypto::Key;
use kerberos_crypto::KerberosCipher;

use kerberos_constants::etypes::{AES128_CTS_HMAC_SHA1_96,AES256_CTS_HMAC_SHA1_96,RC4_HMAC};

use std::fmt;

pub struct KerberosUser {
	pub domain: String,
	pub username: String,
	pub credential : Key,
	pub etype : i32,
	pub encryption_key : Vec<u8>,
	pub custom_salt: Option<Vec<u8>>,
	pub tgt : Option<KerberosTicket>
}

impl KerberosUser {
	pub fn from_password(domain: &str, username: &str, password: &str, salt: Option<&String>) -> Result<KerberosUser,KerberosUserError> {
		let mut user = KerberosUser {
			domain: domain.to_string().to_ascii_uppercase(),
			username: username.to_string(),
			credential: Key::Secret(password.to_string()),
			etype: AES256_CTS_HMAC_SHA1_96,
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None
		};
		
		if let Some(salt_str) = salt {
			user.set_salt(&salt_str);
		}
		
		user.generate_encryption_key();
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
			domain: domain.to_string().to_ascii_uppercase(),
			username: username.to_string(),
			credential: Key::RC4Key(key),
			etype: RC4_HMAC,
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None
		};
		
		user.generate_encryption_key();
		Ok(user)
	}
	
	pub fn from_aes_key(domain: &str, username: &str, raw_key: &[u8]) -> Result<KerberosUser,KerberosUserError> {
		let key : Key;
		let etype : i32;
	
		// 32 bytes is AES256, 16 bytes is AES128
		match raw_key.len() {
			16 => {
				let mut key_bytes : [u8;16] = [0;16];
				for i in 0..16 {
					key_bytes[i] = raw_key[i];
				}
				key = Key::AES128Key(key_bytes);
				etype = AES128_CTS_HMAC_SHA1_96;
			},
			32 => {
				let mut key_bytes : [u8;32] = [0;32];
				for i in 0..32 {
					key_bytes[i] = raw_key[i];
				}
				key = Key::AES256Key(key_bytes);
				etype = AES256_CTS_HMAC_SHA1_96;
			},
			invalid_len => {
				let e = KerberosUserError::InvalidKeySize(invalid_len);
				return Err(e);
			}
		}
		
		let mut user = KerberosUser {
			domain: domain.to_string().to_ascii_uppercase(),
			username: username.to_string(),
			credential: key,
			etype: etype,
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None
		};
		
		user.generate_encryption_key();
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

	pub fn get_cipher(&self) -> Box<dyn KerberosCipher> {
		kerberos_crypto::new_kerberos_cipher(self.etype).unwrap()
	}

	pub fn generate_encryption_key(&mut self) {
		match &self.credential {
			Key::Secret(password) => {
				let cipher = self.get_cipher();
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
	
	pub fn set_tgt(&mut self, ticket : KerberosTicket) {
		self.tgt = Some(ticket);
	}
	
	pub fn is_authenticated(&self) -> bool {
		match &self.tgt {
			Some(_) => true,
			None => false
		}
	}
}

#[derive(Debug)]
pub enum KerberosUserError {
	InvalidHashSize(usize),
	InvalidKeySize(usize)
}

impl fmt::Display for KerberosUserError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match &self {
			KerberosUserError::InvalidHashSize(size) => write!(f, "Invalid NTLM hash size: {}", size),
			KerberosUserError::InvalidKeySize(size) => write!(f, "Invalid AES key size: {}", size),
		}
	}
}
