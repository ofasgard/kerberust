use kerberos_asn1::Ticket;
use kerberos_asn1::EncryptionKey;
use kerberos_asn1::AsRep;
use kerberos_asn1::EncAsRepPart;
use kerberos_asn1::Asn1Object;

use kerberos_crypto::Key;
use kerberos_crypto::KerberosCipher;

use kerberos_constants::etypes::{AES128_CTS_HMAC_SHA1_96,AES256_CTS_HMAC_SHA1_96,RC4_HMAC};
use kerberos_constants::key_usages::KEY_USAGE_AS_REP_ENC_PART;

pub struct KerberosUser {
	pub domain: String,
	pub username: String,
	pub credential : Key,
	pub encryption_key : Vec<u8>,
	pub custom_salt: Option<Vec<u8>>,
	pub tgt : Option<Ticket>,
	pub tgt_session_key : Option<EncryptionKey>
}

impl KerberosUser {
	pub fn from_password(domain: &str, username: &str, password: &str) -> Result<KerberosUser,KerberosUserError> {
		let user = KerberosUser {
			domain: domain.to_string().to_ascii_uppercase(),
			username: username.to_string(),
			credential: Key::Secret(password.to_string()),
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None,
			tgt_session_key: None
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
	
		let user = KerberosUser {
			domain: domain.to_string(),
			username: username.to_string(),
			credential: Key::RC4Key(key),
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None,
			tgt_session_key: None
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
		
		let user = KerberosUser {
			domain: domain.to_string(),
			username: username.to_string(),
			credential: key,
			encryption_key: Vec::new(),
			custom_salt: None,
			tgt: None,
			tgt_session_key: None
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
	
	pub fn decrypt_ticket(&mut self, asrep : &AsRep) -> Result<(),KerberosUserError> {
		// Extracted the ecnrypted part of the ASREP response and decrypt it with our key.
		let encrypted_data : Vec<u8> = asrep.enc_part.cipher.to_vec();
		let decrypted_data = match self.get_cipher().decrypt(&self.encryption_key, KEY_USAGE_AS_REP_ENC_PART, &encrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosUserError::TicketDecryptionError(e))
		};
		
		// Parse the decrypted data into an EncAsRepPart.
		let parsed_data = match EncAsRepPart::parse(&decrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosUserError::TicketParsingError(e))
		};
		let enc_as_rep_part = parsed_data.1;
		
		// Extract the ticket and the decrypted session key.
		self.tgt = Some(asrep.ticket.clone());
		self.tgt_session_key = Some(enc_as_rep_part.key.clone());
		
		Ok(())
	}
}

#[derive(Debug)]
pub enum KerberosUserError {
	InvalidHashSize(usize),
	InvalidKeySize(usize),
	TicketDecryptionError(kerberos_crypto::Error),
	TicketParsingError(kerberos_asn1::Error)
}
