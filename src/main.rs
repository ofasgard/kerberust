use kerberust::kdc_err;

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

	let response = kerberust::net::send_asreq("<domain>:88", &asreq).unwrap();

	match response {
		KerberosResponse::AsRep(asrep) => {
			println!("Successfully parsed ASREP!");
			let ticket = KerberosTicket::from_asrep(&asrep, &user).unwrap();
			user.set_tgt(ticket);
			if let Some(tgt) = &user.tgt {
				let tgt_bytes = tgt.dump_to_kirbi(&user.domain, &user.username);
				std::fs::write("<path>", tgt_bytes).unwrap();
				println!("Dumped to file");
			}
		},
		KerberosResponse::KrbError(err) => {
			println!("Kerberos error {}", &err.error_code);
			if let Some(text) = &err.e_text {
				println!("Error text: {}", text);
			}
			if let Some(bytes) = &err.e_data {
				println!("Error data: {:02X?}", bytes);
			}
			if let Ok(salt) = kdc_err::parse_salt(&err) {
				println!("Desired salt: {}", salt);
			}
		},
		KerberosResponse::Raw(bytes) => println!("Failed to parse {} bytes as a Kerberos response.", bytes.len())
	}	
}
