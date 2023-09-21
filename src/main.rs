use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;
use kerberust::ticket::KerberosTicket;
use kerberust::net::KerberosResponse;

fn main() {
	let key = vec![];
	let mut user = KerberosUser::from_aes_key("<domain>", "<user>", &key).unwrap();
	user.generate_encryption_key();
	
	let mut builder = KdcRequestBuilder::new();
	let asreq = builder.build_asreq(&user);
	
	dbg!(&asreq);

	let response = kerberust::net::send_asreq("<target>:88", &asreq).unwrap();

	match response {
		KerberosResponse::AsRep(asrep) => {
			println!("Successfully parsed ASREP!");
			let ticket = KerberosTicket::from_asrep(&asrep, &user).unwrap();
			user.set_ticket(ticket);
			if let Some(tgt) = &user.tgt {
				dbg!(&tgt.ticket);
				dbg!(tgt.get_session_key());
			}
		},
		KerberosResponse::KrbError(err) => {
			println!("Kerberos error {}", err.error_code);
			if let Some(text) = err.e_text {
				println!("Error text: {}", text);
			}
			if let Some(bytes) = err.e_data {
				println!("Error data: {:02X?}", bytes);
			}
		},
		KerberosResponse::Raw(bytes) => println!("Failed to parse {} bytes as a Kerberos response.", bytes.len())
	}	
}

// TODO:
// Code to convert TGT and SessionKey into a KRBCRED structure, suitable for conversion into a .kirbi file (kerberos_asn1::KrbCred)
// Sometimes you have to set the salt manually, because it doesn't match the samAccountName and uses the userPrincipalName instead :(
//	When you get error 24 in response to a bad key, the "error data" part of the KrbError does include the correct salt to use

