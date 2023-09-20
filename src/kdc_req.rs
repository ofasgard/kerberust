use crate::user::KerberosUser;

use kerberos_asn1::KdcReqBody;
use kerberos_asn1::AsReq;
use kerberos_asn1::PaData;
use kerberos_asn1::KerbPaPacRequest;
use kerberos_asn1::PaEncTsEnc;
use kerberos_asn1::EncryptedData;
use kerberos_asn1::PrincipalName;
use kerberos_asn1::Asn1Object;

use kerberos_constants::kdc_options::{FORWARDABLE,PROXIABLE,RENEWABLE};
use kerberos_constants::principal_names::NT_PRINCIPAL;
use kerberos_constants::protocol_version::PVNO;
use kerberos_constants::message_types::KRB_AS_REQ;
use kerberos_constants::pa_data_types::PA_PAC_REQUEST;
use kerberos_constants::pa_data_types::PA_ENC_TIMESTAMP;
use kerberos_constants::key_usages::KEY_USAGE_AS_REQ_TIMESTAMP;

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
		self.body.realm = realm.to_string()
	}
	
	fn set_cname(&mut self, name : Vec<String>) {
		let principal = PrincipalName {
			name_type: NT_PRINCIPAL,
			name_string: name
		};
		self.body.cname = Some(principal);
	}
	
	fn set_sname(&mut self, name : Vec<String>) {
		let principal = PrincipalName {
			name_type: NT_PRINCIPAL,
			name_string: name
		};
		self.body.sname = Some(principal);
	}
	
	fn set_from(&mut self, time : DateTime<Utc>) {
		self.body.from = Some(time.into());
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
	
	fn set_address(&mut self) {
		todo!();
	}
	
	fn set_enc_authorization_data(&mut self) {
		todo!();
	}
	
	fn set_additional_tickets(&mut self) {
		todo!();
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
		let encrypted_data = EncryptedData::new(user.get_etype(), None, encrypted_timestamp);
		let padata = PaData::new(PA_ENC_TIMESTAMP, encrypted_data.build());
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
		self.set_cname(vec![user.username.to_string()]);
		
		// Set sname to the krbtgt SPN ("krbtgt/somedomain.local").
		self.set_sname(vec!["krbtgt".to_string(), user.domain.to_string()]);
		
		// Set expiry dates at some point in the future.
		let expiry = Utc::now() + Duration::days(90);
		self.set_till(expiry);
		self.set_rtime(expiry);
		
		// Set a random nonce.
		self.set_nonce();
		
		// Add desired encryption type.
		self.add_etype(user.get_etype());
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
