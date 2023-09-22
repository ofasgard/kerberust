use kerberust::kdc_err;

use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;
use kerberust::ticket::KerberosTicket;
use kerberust::net::KerberosResponse;

const USERNAME : &str = "<user>";
const DOMAIN : &str = "<domain>";

const TARGET : &str = "<target>:88";
const TGT_PATH : &str = "<path>";
const TGS_PATH : &str = "<path>";

const SPN : (&str,&str) = ("<spn>", "<spn>");

fn main() {
	let key : Vec<u8> = vec![];
	let mut user = KerberosUser::from_aes_key(DOMAIN, USERNAME, &key).unwrap();
	user.generate_encryption_key();
	
	let mut builder = KdcRequestBuilder::new();
	let asreq = builder.build_asreq(&user);
	
	dbg!(&asreq);

	let response = kerberust::net::send_asreq(TARGET, &asreq).unwrap();

	match response {
		KerberosResponse::AsRep(asrep) => {
			println!("Successfully parsed ASREP!");
			let ticket = KerberosTicket::from_asrep(&asrep, &user).unwrap();
			user.set_tgt(ticket);
			if let Some(tgt) = &user.tgt {
				let tgt_bytes = tgt.dump_to_kirbi(&user.domain, &user.username);
				std::fs::write(TGT_PATH, tgt_bytes).unwrap();
				println!("Dumped to file");
			}
		},
		KerberosResponse::TgsRep(_) => {
			println!("Received a TGS-REP in response to an AS-REQ");
			return;
		}
		KerberosResponse::KrbError(err) => {
			println!("Kerberos error {}", &err.error_code);
			if let Some(text) = &err.e_text {
				println!("Error text: {}", text);
				return;
			}
			if let Some(bytes) = &err.e_data {
				println!("Error data: {:02X?}", bytes);
				return;
			}
			if let Ok(salt) = kdc_err::parse_salt(&err) {
				println!("Desired salt: {}", salt);
				return;
			}
		},
		KerberosResponse::Raw(bytes) => {
			println!("Failed to parse {} bytes as a Kerberos response.", bytes.len());
			return;
		}
	}	
	
	if !user.is_authenticated() {
		println!("User has no ticket?? Cannot proceed.");
		return;
	}
	
	let spn = vec![SPN.0.to_string(), SPN.1.to_string()];
	
	let mut builder = KdcRequestBuilder::new();
	let ticket = &user.tgt.as_ref().unwrap();
	let tgsreq = builder.build_tgsreq(&user, ticket, &spn, &user.domain);
	
	dbg!(&tgsreq);
	
	let response = kerberust::net::send_tgsreq(TARGET, &tgsreq).unwrap();
	match response {
		KerberosResponse::AsRep(_) => {
			println!("Received a AS-REP in response to a TGS-REQ");
			return
		},
		KerberosResponse::TgsRep(tgsrep) => {
			println!("Successfully parsed TGSREP!");
			let service_ticket = KerberosTicket::from_tgsrep(&tgsrep, &ticket).unwrap();
			let service_ticket_bytes = service_ticket.dump_to_kirbi(&user.domain, &spn.join("/"));
			std::fs::write(TGS_PATH, service_ticket_bytes).unwrap();
			println!("Dumped to file");
		}
		KerberosResponse::KrbError(err) => {
			println!("Kerberos error {}", &err.error_code);
			if let Some(text) = &err.e_text {
				println!("Error text: {}", text);
				return;
			}
			if let Some(bytes) = &err.e_data {
				println!("Error data: {:02X?}", bytes);
				return;
			}
			if let Ok(salt) = kdc_err::parse_salt(&err) {
				println!("Desired salt: {}", salt);
				return;
			}
		},
		KerberosResponse::Raw(bytes) => {
			println!("Failed to parse {} bytes as a Kerberos response.", bytes.len());
			return;
		}
	}
}
