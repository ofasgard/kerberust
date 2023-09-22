use kerberust::kdc_err;

use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;
use kerberust::ticket::KerberosTicket;
use kerberust::ticket::KerberosTicketError;
use kerberust::net::KerberosResponse;

/// A tool to request a specific service ticket from the KDC, using credentials.

const USERNAME : &str = "<user>";
const DOMAIN : &str = "<domain>";

const TARGET : &str = "<target>:88";

const SPN : (&str,&str) = ("<spn>", "<spn>");

const OUTPUT : &str = "<path>";

fn main() {
	// Process credentials and generate user encryption key.
	// Currently using hardcoded credentials rather than parameters (TODO)
	let key : Vec<u8> = vec![];
	let mut user = KerberosUser::from_aes_key(DOMAIN, USERNAME, &key).unwrap();
	user.generate_encryption_key();
	
	// Build an ASREQ request.
	let mut builder = KdcRequestBuilder::new();
	let asreq = builder.build_asreq(&user);
	
	// Send the ASREQ request.
	// Currently the target is hardcoded rather than supplied by parameter (TODO)
	println!("[+] Sending ASREQ...");
	let asreq_response = match kerberust::net::send_asreq(TARGET, &asreq) {
		Ok(response) => response,
		Err(e) => {
			println!("[-] Failed to send ASREQ: {}", e.to_string());
			return;
		}
	};
	
	// Check what we got in return.
	let asrep = match asreq_response {
		KerberosResponse::AsRep(asrep) => asrep,
		KerberosResponse::KrbError(err) => {
			println!("[-] Received a Kerberos error in response to the ASREQ.");
			println!("{}", kdc_err::format_error(&err));
			return;
		},
		KerberosResponse::TgsRep(_) => {
			println!("[-] Received a TGSREP in response to the ASREQ.");
			return;
		}
		KerberosResponse::Raw(bytes) => {
			println!("[-] Failed to parse {} bytes as a Kerberos response.", bytes.len());
			return;
		}
	};
	
	// Parse the TGT from the ASREP.
	println!("[+] Received ASREP!");
	let tgt = match KerberosTicket::from_asrep(&asrep, &user) {
		Ok(ticket) => ticket,
		Err(e) => match e {
			KerberosTicketError::DecryptionError(decrypt_err) => {
				println!("[-] Failed to decrypt the TGT:");
				println!("{:?}", decrypt_err);
				return;
			},
			KerberosTicketError::ParsingError(parse_err) => {
				println!("[-] Failed to parse the TGT:");
				println!("{:?}", parse_err);
				return;
			}
		}
	};
	
	println!("[+] Successfully decrypted TGT!");
	user.set_tgt(tgt);
	
	// Build a TGSREQ request.
	// Currently using a hardcoded SPN rather than one supplied as a parameter (TODO)
	let spn = vec![SPN.0.to_string(), SPN.1.to_string()];
	
	let mut builder = KdcRequestBuilder::new();
	let tgt = &user.tgt.as_ref().unwrap();	// We just set the ticket, so it's OK to unwrap.
	let tgsreq = builder.build_tgsreq(&user, tgt, &spn, &user.domain);
	
	// Send the TGSREQ request.
	// Currently the target is hardcoded rather than supplied by parameter (TODO)
	println!("[+] Sending TGSREQ...");
	let tgsreq_response = match kerberust::net::send_tgsreq(TARGET, &tgsreq) {
		Ok(response) => response,
		Err(e) => {
			println!("[-] Failed to send TGSREQ: {}", e.to_string());
			return;
		}
	};
	
	// Check what we got in return.
	let tgsrep = match tgsreq_response {
		KerberosResponse::TgsRep(tgsrep) => tgsrep,
		KerberosResponse::KrbError(err) => {
			println!("[-] Received a Kerberos error in response to the ASREQ.");
			println!("{}", kdc_err::format_error(&err));
			return;
		},
		KerberosResponse::AsRep(_) => {
			println!("[-] Received an ASREP in response to the TGSREQ.");
			return;
		}
		KerberosResponse::Raw(bytes) => {
			println!("[-] Failed to parse {} bytes as a Kerberos response.", bytes.len());
			return;
		}
	};
	
	// Parse the service ticket from the TGSREP.
	println!("[+] Received TGSREP!");
	let service_ticket = match KerberosTicket::from_tgsrep(&tgsrep, &tgt) {
		Ok(ticket) => ticket,
		Err(e) => match e {
			KerberosTicketError::DecryptionError(decrypt_err) => {
				println!("[-] Failed to decrypt the service ticket:");
				println!("{:?}", decrypt_err);
				return;
			},
			KerberosTicketError::ParsingError(parse_err) => {
				println!("[-] Failed to parse the service ticket:");
				println!("{:?}", parse_err);
				return;
			}
		}
	};
	
	// Finally, dump the service ticket to a file.
	// Currently the path is hardcoded rather than supplied by parameter (TODO)
	println!("[+] Successfully parsed service ticket!");
	let service_ticket_bytes = service_ticket.dump_to_kirbi(&user.domain, &spn.join("/"));
	std::fs::write(OUTPUT, service_ticket_bytes).unwrap();
	
	println!("[!] Written to '{}'", OUTPUT);
}
