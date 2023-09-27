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
			println!("[-] Received a Kerberos error in response to the TGSREQ.");
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
	let matches = Command::new("AskTgs")
		.about("A tool to request a specific service ticket from the KDC and dump it to a KIRBI file.")
		.arg(arg!(--domain <DOMAIN>).short('d').required(true).help("Domain/realm to authenticate to."))
		.arg(arg!(--user <USER>).short('u').required(true).help("Username to authenticate with."))
		.arg(arg!(--password <PASSWORD>).short('p').required(false).help("Password to authenticate with."))
		.arg(arg!(--ntlm <HASH>).short('n').required(false).help("NTLM hash to authenticate with."))
		.arg(arg!(--key <KEY>).short('k').required(false).help("128 or 256-bit AES key to authenticate with."))
		.arg(arg!(--salt <SALT>).short('s').required(false).help("Custom salt to be used with the password (optional)."))
		.arg(arg!(--spn <SPN>).short('S').required(true).help("Service principal name to request a ticket for."))
		.arg(arg!(--outfile <PATH>).short('O').required(true).help("Output path to write the requested ticket to (in KIRBI format)."))
		.arg(arg!(--kdc <HOST>).short('K').required(false).help("IP address or hostname for the KDC, if different from the domain."))
		.arg(arg!(--port <PORT>).short('P').required(false).help("Port number to use for the KDC, if different from the default port."))
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
	
	// If a password (with optional salt) was provided.
	match matches.get_one::<String>("password") {
		Some(password_str) => {
			let salt = matches.get_one::<String>("salt");
			let mut user = match KerberosUser::from_password(domain, username, &password_str, salt) {
				Ok(user) => user,
				Err(e) => {
					println!("[-] {}", e);
					return;
				}
			};
			ask_tgs(&mut user, spn, server, port, path);
			return;
		},
		None => ()
	}
	
	// If an NTLM hash was provided.
	match matches.get_one::<String>("ntlm") {
		Some(hash_str) => {
			let hash : Vec<u8> = match hex::decode(hash_str) {
				Ok(key) => key,
				Err(e) => {
					println!("[-] Failed to decode NTLM hash: {}", e);
					return;
				}
			};
			let mut user = match KerberosUser::from_ntlm_hash(domain, username, &hash) {
				Ok(user) => user,
				Err(e) => {
					println!("[-] {}", e);
					return;
				}
			};
			ask_tgs(&mut user, spn, server, port, path);
			return;
		},
		None => ()
	}
	
	// If an AES key was provided.
	match matches.get_one::<String>("key") {
		Some(key_str) => {
			let key : Vec<u8> = match hex::decode(key_str) {
				Ok(key) => key,
				Err(e) => {
					println!("[-] Failed to decode AES key: {}", e);
					return;
				}
			};
			let mut user = match KerberosUser::from_aes_key(domain, username, &key) {
				Ok(user) => user,
				Err(e) => {
					println!("[-] {}", e);
					return;
				}
			};
			ask_tgs(&mut user, spn, server, port, path);
			return;
		},
		None => ()
	}
	
	println!("[-] You must provide one of the following: --password, --ntlm, or --key.");
}
