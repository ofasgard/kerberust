use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;

use kerberos_asn1::AsRep;
use kerberos_asn1::KrbError;
use kerberos_asn1::Asn1Object;


fn main() {
	let mut user = KerberosUser::from_password("<domain>", "<username>", "<password>").unwrap();
	user.set_salt("DOMAINupn");
	user.generate_encryption_key();
	println!("{:02X?}", &user.encryption_key);
	
	let mut builder = KdcRequestBuilder::new();
	let asreq = builder.build_asreq(&user);
	
	dbg!(&asreq);

	let response = kerberust::net::send_request("<target>:88", &asreq.build()).unwrap();
	dbg!(&response);
	println!("{}", String::from_utf8_lossy(&response));
	
	let parse_result = AsRep::parse(&response);
	match parse_result {
		Ok(asrep) => {
			dbg!(asrep);
		}
		Err(e) => {
			dbg!(e);
			let err = KrbError::parse(&response).expect("couldn't parse asrep or error...");
			dbg!(err);
		}
	}
}

// TODO:
// Sometimes you have to set the salt manually, because it doesn't match the samAccountName and uses the userPrincipalName instead :(
