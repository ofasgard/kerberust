use crate::user::KerberosUser;

use kerberos_asn1::Ticket;
use kerberos_asn1::EncKdcRepPart;
use kerberos_asn1::EncryptionKey;
use kerberos_asn1::AsRep;
use kerberos_asn1::TgsRep;
use kerberos_asn1::EncAsRepPart;
use kerberos_asn1::EncTgsRepPart;
use kerberos_asn1::PrincipalName;
use kerberos_asn1::KrbCredInfo;
use kerberos_asn1::EncKrbCredPart;
use kerberos_asn1::EncryptedData;
use kerberos_asn1::KrbCred;
use kerberos_asn1::Asn1Object;

use kerberos_constants::protocol_version::PVNO;
use kerberos_constants::etypes::NO_ENCRYPTION;
use kerberos_constants::key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY;
use kerberos_constants::key_usages::KEY_USAGE_AS_REP_ENC_PART;
use kerberos_constants::principal_names::NT_PRINCIPAL;
use kerberos_constants::message_types::KRB_CRED;

/// Represents a kerberos ticket, including the decrypted data from a KDC response which is required to use it.

#[derive(Clone)]
pub struct KerberosTicket {
	pub ticket : Ticket,
	pub response : EncKdcRepPart,
	pub crealm : String,
	pub cname : PrincipalName
}

// Constructors

impl KerberosTicket {
	pub fn from_asrep(asrep : &AsRep, user : &KerberosUser) -> Result<KerberosTicket,KerberosTicketError> {
		// Extract the encrypted part of the ASREP response and decrypt it with the user's key.
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
			response: enc_as_rep_part.into(),
			crealm: asrep.crealm.to_string(),
			cname: asrep.cname.clone()
		};
				
		Ok(ticket)
	}
	
	pub fn from_tgsrep(tgsrep : &TgsRep, tgt : &KerberosTicket) -> Result<KerberosTicket,KerberosTicketError> {
		// Prepare the TGT cipher and session key.
		let etype = tgt.get_session_key().keytype;
		let session_key = tgt.get_session_key().keyvalue;
		let cipher = kerberos_crypto::new_kerberos_cipher(etype).unwrap();
	
		// Extract the encrypted part of the TGSREP response and decrypt it with the TGT session key.
		let encrypted_data : Vec<u8> = tgsrep.enc_part.cipher.to_vec();
		let decrypted_data = match cipher.decrypt(&session_key, KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY, &encrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosTicketError::DecryptionError(e))
		};
		
		// Parse the decrypted data into an EncTgsRepPart.
		let parsed_data = match EncTgsRepPart::parse(&decrypted_data) {
			Ok(data) => data,
			Err(e) => return Err(KerberosTicketError::ParsingError(e))
		};
		let enc_tgs_rep_part = parsed_data.1;
		
		// Extract the ticket and decrypted session key.
		let ticket = KerberosTicket {
			ticket: tgsrep.ticket.clone(),
			response: enc_tgs_rep_part.into(),
			crealm: tgsrep.crealm.to_string(),
			cname: tgsrep.cname.clone()
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
	
	pub fn dump_to_kirbi(&self, domain : &str, username : &str) -> Vec<u8> {
		// Convert the ticket to a KRB-CRED and dump it as raw bytes.
		// This is the ticket format used by Mimikatz.
		let principal = PrincipalName {
			name_type: NT_PRINCIPAL,
			name_string: vec![username.to_string()]
		};
		
		let credinfo = KrbCredInfo {
			key: self.response.key.clone(),
			prealm: Some(domain.to_string()),
			pname: Some(principal),
			flags: Some(self.response.flags.clone()),
			authtime: Some(self.response.authtime.clone()),
			starttime: self.response.starttime.clone(),
			endtime: Some(self.response.endtime.clone()),
			renew_till: self.response.renew_till.clone(),
			srealm: Some(self.response.srealm.clone()),
			sname: Some(self.response.sname.clone()),
			caddr: self.response.caddr.clone()
		};
		
		let mut credpart = EncKrbCredPart::default();
		credpart.ticket_info = vec![credinfo];
		let data = EncryptedData::new(NO_ENCRYPTION, None, credpart.build());
		
		let krbcred = KrbCred {
			pvno: PVNO,
			msg_type: KRB_CRED,
			tickets: vec![self.ticket.clone()],
			enc_part: data
		};
		
		krbcred.build()
	}
}

#[derive(Debug)]
pub enum KerberosTicketError {
	DecryptionError(kerberos_crypto::Error),
	ParsingError(kerberos_asn1::Error)
}
