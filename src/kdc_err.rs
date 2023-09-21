use kerberos_asn1::KrbError;
use kerberos_asn1::PaData;
use kerberos_asn1::MethodData;
use kerberos_asn1::EtypeInfo;
use kerberos_asn1::EtypeInfo2;
use kerberos_asn1::Asn1Object;

pub fn parse_salt(krb_err : &KrbError) -> Result<String,()> {
	// Attempt to parse a KrbError and extract the salt that was expected by the KDC.
	// This is useful because some AD environments use 'samAccountName' for logins, but 'userPrincipalName' for the salt.
	if let Some(bytes) = &krb_err.e_data {
		// Parse the error data as a sequence of PaData structures.
		let parsed_method_data = MethodData::parse(&bytes).unwrap();
		let padatas : Vec<PaData> = parsed_method_data.1;
		for padata in padatas {
			// Try to interpret each PaData in the e-data as both ETYPEINFO and ETYPEINFO2.
			// If either succeeds, then extract the salt and return it.
			if let Ok(etypeinfo) = EtypeInfo::parse(&padata.padata_value) {
				// For ETypeInfoEntry, the salt is a Vec<u8>.
				let entry = &etypeinfo.1[0];
				if let Some(salt) = &entry.salt {
					let salt_string = String::from_utf8_lossy(&salt).to_string();
					return Ok(salt_string);
				}
			}
			if let Ok(etypeinfo) = EtypeInfo2::parse(&padata.padata_value) {
				// For ETypeInfoEntry2, the salt is a String.
				let entry = &etypeinfo.1[0];
				if let Some(salt) = &entry.salt {
					return Ok(salt.to_string());
				}
			}			
		}
	}
	
	Err(())
}
