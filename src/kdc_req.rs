use crate::user::KerberosUser;
use crate::ticket::KerberosTicket;

use kerberos_asn1::KdcReqBody;
use kerberos_asn1::AsReq;
use kerberos_asn1::ApReq;
use kerberos_asn1::TgsReq;
use kerberos_asn1::PaData;
use kerberos_asn1::KerbPaPacRequest;
use kerberos_asn1::PaEncTsEnc;
use kerberos_asn1::EncryptedData;
use kerberos_asn1::PrincipalName;
use kerberos_asn1::ApOptions;
use kerberos_asn1::Authenticator;
use kerberos_asn1::Asn1Object;

use kerberos_constants::kdc_options::{CANONICALIZE,FORWARDABLE,PROXIABLE,RENEWABLE,RENEWABLE_OK};
use kerberos_constants::message_types::{KRB_AS_REQ,KRB_AP_REQ,KRB_TGS_REQ};
use kerberos_constants::key_usages::{KEY_USAGE_AS_REQ_TIMESTAMP,KEY_USAGE_TGS_REQ_AUTHEN};
use kerberos_constants::etypes::{RC4_HMAC,DES_CBC_MD5};
use kerberos_constants::pa_data_types::{PA_PAC_REQUEST,PA_ENC_TIMESTAMP,PA_TGS_REQ};
use kerberos_constants::principal_names::{NT_PRINCIPAL,NT_SRV_INST};
use kerberos_constants::protocol_version::PVNO;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use rand;
use rand::Rng;

pub struct KdcRequestBuilder {
	body: KdcReqBody,
	padata: Vec<PaData>
}

impl KdcRequestBuilder {
	pub fn new() -> Self {
		Self { 
			body: KdcReqBody::default(),
			padata: Vec::new()
		}
	}
}

// Helper functions for KdcReqBody

impl KdcRequestBuilder {	
	fn set_kdc_option(&mut self, option : u32) {
		self.body.kdc_options.flags |= option;
	}
	
	fn set_realm(&mut self, realm : &str) {
		self.body.realm = realm.to_string();
	}
	
	fn set_cname(&mut self, principal_type : i32, name : Vec<String>) {
		let principal = PrincipalName {
			name_type: principal_type,
			name_string: name
		};
		self.body.cname = Some(principal);
	}
	
	fn set_sname(&mut self, principal_type : i32, name : Vec<String>) {
		let principal = PrincipalName {
			name_type: principal_type,
			name_string: name
		};
		self.body.sname = Some(principal);
	}
	
	fn set_till(&mut self, time : DateTime<Utc>) {
		self.body.till = time.into();
	}
	
	fn set_rtime(&mut self, time : DateTime<Utc>) {
		self.body.rtime = Some(time.into());
	}
	
	fn set_nonce(&mut self) {
		self.body.nonce = rand::thread_rng().gen();
	}
	
	fn add_etype(&mut self, etype : i32) {
		self.body.etypes.push(etype);
	}
}

// Helper functions for PaData

impl KdcRequestBuilder {
	fn request_pac(&mut self) {
		let pac_request = KerbPaPacRequest::new(true);
		let padata = PaData::new(PA_PAC_REQUEST, pac_request.build());
		self.padata.push(padata);
	}
	
	fn add_encrypted_timestamp(&mut self, user : &KerberosUser) {
		let timestamp = PaEncTsEnc::from(Utc::now());
		let cipher = user.get_cipher();
		let encrypted_timestamp = cipher.encrypt(&user.encryption_key, KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp.build());
		let encrypted_data = EncryptedData::new(user.etype, None, encrypted_timestamp);
		let padata = PaData::new(PA_ENC_TIMESTAMP, encrypted_data.build());
		self.padata.push(padata);
	}
	
	fn add_apreq(&mut self, user : &KerberosUser, ticket : &KerberosTicket) {
		// Build an Authenticator for the provided user.
		let mut authenticator = Authenticator::default();
		authenticator.crealm = user.domain.to_string();
		authenticator.cname = PrincipalName {
			name_type: NT_PRINCIPAL,
			name_string: vec![user.username.to_string()]
		};
		
		// Encrypt the Authenticator with the correct cipher and the session key.
		let etype = ticket.get_session_key().keytype;
		let session_key = ticket.get_session_key().keyvalue;
		let cipher = kerberos_crypto::new_kerberos_cipher(etype).unwrap();
		let encrypted_authenticator = cipher.encrypt(&session_key, KEY_USAGE_TGS_REQ_AUTHEN, &authenticator.build());
		let encrypted_data = EncryptedData {
			etype: user.etype, 
			kvno: None,
			cipher: encrypted_authenticator
		};
	
		// Build the APREQ with the ticket and encrypted authenticator.
		let apreq = ApReq {
			pvno: PVNO,
			msg_type: KRB_AP_REQ,
			ap_options: ApOptions::default(),
			ticket: ticket.ticket.clone(),
			authenticator: encrypted_data
		};
		
		// Add the PaData.
		let padata = PaData::new(PA_TGS_REQ, apreq.build());
		self.padata.push(padata);
	}
}

// ASREQ

impl KdcRequestBuilder {
	fn build_asreq_body(&mut self, user : &KerberosUser) {
		// Set KDC options.
		self.set_kdc_option(FORWARDABLE);
		self.set_kdc_option(PROXIABLE);
		self.set_kdc_option(RENEWABLE);
		
		// Set realm to user domain.
		self.set_realm(&user.domain);
		
		// Set cname to username.
		self.set_cname(NT_PRINCIPAL, vec![user.username.to_string()]);
		
		// Set sname to the krbtgt SPN ("krbtgt/somedomain.local").
		self.set_sname(NT_PRINCIPAL, vec!["krbtgt".to_string(), user.domain.to_string()]);
		
		// Set expiry dates at some point in the future.
		let expiry = Utc::now() + Duration::days(90);
		self.set_till(expiry);
		self.set_rtime(expiry);
		
		// Set a random nonce.
		self.set_nonce();
		
		// Add desired encryption type.
		self.add_etype(user.etype);
	}
	
	fn build_asreq_padata(&mut self, user : &KerberosUser) {
		// Add a pre-authentication request to padata.
		self.request_pac();
		// Add a timestamp encrypted with the user's password/hash/key.
		self.add_encrypted_timestamp(user);
	}
	
	pub fn build_asreq(&mut self, user : &KerberosUser) -> AsReq {
		self.build_asreq_body(&user);
		self.build_asreq_padata(&user);
	
		AsReq {
			pvno: PVNO,
			msg_type: KRB_AS_REQ,
			padata: Some(self.padata.clone()),
			req_body: self.body.clone()
		}
	}
}

// TGSREQ

impl KdcRequestBuilder {	
	fn build_tgsreq_body(&mut self, user : &KerberosUser, spn : &str, domain : &str) {
		// Set KDC options.
		self.set_kdc_option(CANONICALIZE);
		self.set_kdc_option(FORWARDABLE);
		self.set_kdc_option(RENEWABLE);
		self.set_kdc_option(RENEWABLE_OK);
		
		// Set realm to provided domain.
		self.set_realm(domain);
		
		//Set sname to the SPN we want to request.
		let spn_vec = spn.split("/").map(|s| s.to_string()).collect();
		self.set_sname(NT_SRV_INST, spn_vec);
		
		// Set expiry dates at some point in the future.
		let expiry = Utc::now() + Duration::days(90);
		self.set_till(expiry);
		
		// Set a random nonce.
		self.set_nonce();
		
		// Add desired encryption type, along with a selection of others.
		self.add_etype(RC4_HMAC);
		self.add_etype(DES_CBC_MD5);
		self.add_etype(user.etype);
	}
	
	fn build_tgsreq_padata(&mut self, user : &KerberosUser, ticket : &KerberosTicket) {
		// Add an APREQ to padata.
		self.add_apreq(user, ticket);
	}
	
	pub fn build_tgsreq(&mut self, user : &KerberosUser, ticket : &KerberosTicket, spn : &str, domain : &str) -> TgsReq {
		self.build_tgsreq_body(user, spn, domain);
		self.build_tgsreq_padata(user, ticket);
		
		TgsReq {
			pvno: PVNO,
			msg_type: KRB_TGS_REQ,
			padata: Some(self.padata.clone()),
			req_body : self.body.clone()
		}
	}
}
