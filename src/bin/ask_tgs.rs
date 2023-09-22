use kerberust::kdc_err;

use kerberust::kdc_req::KdcRequestBuilder;
use kerberust::user::KerberosUser;
use kerberust::ticket::KerberosTicket;
use kerberust::ticket::KerberosTicketError;
use kerberust::net::KerberosResponse;

use clap::Command;
use clap::arg;

/// A tool to request a specific service ticket from the KDC and dump it to a KIRBI file.

fn ask_tgs(user : &mut KerberosUser, spn : &str, server : &str, port : i32, output_path : &str) {
	let connection_str = format!("{}:{}", server, port);
	let spn_vec = spn.split("/").map(|s| s.to_string()).collect();

	// Build an ASREQ request.
	let mut builder = KdcRequestBuilder::new();
	let asreq = builder.build_asreq(&user);
	
	// Send the ASREQ request.
	println!("[+] Sending ASREQ...");
	let asreq_response = match kerberust::net::send_asreq(&connection_str, &asreq) {
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
	let mut builder = KdcRequestBuilder::new();
	let tgt = &user.tgt.as_ref().unwrap();	// We just set the ticket, so it's OK to unwrap.
	let tgsreq = builder.build_tgsreq(&user, tgt, &spn_vec, &user.domain);
	
	// Send the TGSREQ request.
	println!("[+] Sending TGSREQ...");
	let tgsreq_response = match kerberust::net::send_tgsreq(&connection_str, &tgsreq) {
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
	println!("[+] Successfully parsed service ticket!");
	let service_ticket_bytes = service_ticket.dump_to_kirbi(&user.domain, &spn);
	std::fs::write(output_path, service_ticket_bytes).unwrap();
	
	println!("[!] Written to '{}'", output_path);
}

fn main() {
	// Only AES key is supported for now, and it's hardcoded (TODO)
	let key : Vec<u8> = vec![];
	
	let matches = Command::new("AskTgs")
		.about("A tool to request a specific service ticket from the KDC and dump it to a KIRBI file.")
		.arg(arg!(--domain <DOMAIN>).required(true))
		.arg(arg!(--user <USER>).required(true))
		.arg(arg!(--spn <SPN>).required(true))
		.arg(arg!(--outfile <PATH>).required(true))
		.arg(arg!(--kdc <HOST>).required(false))
		.arg(arg!(--port <PORT>).required(false))
		.get_matches();
	
	let domain = matches.get_one::<String>("domain").unwrap();
	let username = matches.get_one::<String>("user").unwrap();
	let spn = matches.get_one::<String>("spn").unwrap();
	let path = matches.get_one::<String>("outfile").unwrap();
	
	let server = match matches.get_one::<String>("kdc") {
		Some(server_str) => server_str,
		None => domain
	};
	
	let port = match matches.get_one::<i32>("port") {
		Some(port_int) => *port_int,
		None => 88
	};
	
	let mut user = KerberosUser::from_aes_key(domain, username, &key).unwrap();
	user.generate_encryption_key();
	
	ask_tgs(&mut user, spn, server, port, path);
}
