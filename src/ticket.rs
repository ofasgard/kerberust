use crate::user::KerberosUser;

use kerberos_asn1::Ticket;
use kerberos_asn1::EncKdcRepPart;
use kerberos_asn1::EncryptionKey;
use kerberos_asn1::AsRep;
use kerberos_asn1::EncAsRepPart;
use kerberos_asn1::Asn1Object;

use kerberos_constants::key_usages::KEY_USAGE_AS_REP_ENC_PART;

/// Represents a kerberos ticket, including the decrypted data from a KDC response which is required to use it.

pub struct KerberosTicket {
	pub ticket : Ticket,
	pub response : EncKdcRepPart
}

// Constructors

impl KerberosTicket {
	pub fn from_asrep(asrep : &AsRep, user : &KerberosUser) -> Result<KerberosTicket,KerberosTicketError> {
		// Extracted the encrypted part of the ASREP response and decrypt it with the user's key.
		let encrypted_data : Vec<u8> = asrep.enc_part.cipher.to_vec();
		let decrypted_data = match user.get_cipher().decrypt(&user.encryption_key, KEY_USAGE_AS_REP_ENC_PART, &encrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosTicketError::DecryptionError(e))
		};
		
		// Parse the decrypted data into an EncAsRepPart.
		let parsed_data = match EncAsRepPart::parse(&decrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosTicketError::ParsingError(e))
		};
		let enc_as_rep_part = parsed_data.1;
		
		// Extract the ticket and the decrypted session key.
		let ticket = KerberosTicket {
			ticket: asrep.ticket.clone(),
			response: enc_as_rep_part.into()
		};
				
		Ok(ticket)
	}
}

// Methods

impl KerberosTicket {	
	pub fn get_session_key(&self) -> EncryptionKey {
		// Get the session key, required to use the ticket, from the decrypted KDC response.
		self.response.key.clone()
	}
}

#[derive(Debug)]
pub enum KerberosTicketError {
	DecryptionError(kerberos_crypto::Error),
	ParsingError(kerberos_asn1::Error)
}
