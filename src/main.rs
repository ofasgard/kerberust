use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;
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
			dbg!(asrep);
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
// Extract TGT from AsRep
// Sometimes you have to set the salt manually, because it doesn't match the samAccountName and uses the userPrincipalName instead :(
