use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

fn calculate_big_endian_size(buf : &[u8]) -> Vec<u8> {
	// Calculate the 4-byte big-endian size of a byte buffer.
	let size = buf.len() as u32;
	size.to_be_bytes().to_vec()
}

fn parse_big_endian_size(buf : [u8;4]) -> u32 {
	// Parse a 4-byte big-endian representation of a byte buffer's size.
	u32::from_be_bytes(buf)
}

pub fn pack_request(raw : &[u8]) -> Vec<u8> {
	// To send a request to Kerberos, we must pack it with 4 leading bytes, which contain the big-endian size of the request.
	let mut request : Vec<u8> = Vec::new();

	let mut raw_size = calculate_big_endian_size(raw);
	let mut raw_request = raw.to_vec();
	
	request.append(&mut raw_size);
	request.append(&mut raw_request);
	request
}

pub fn send_request(server : &str, request : &[u8]) -> Result<Vec<u8>,Error> {
	// Establish the connection.
	let mut conn = TcpStream::connect(server)?;
	
	// Pack and send the request.
	let packed_request = pack_request(request);
	conn.write(&packed_request)?;
	
	// Read the first 4 bytes to determine the size of the response.
	let mut size_buf : [u8;4] = [0;4];
	conn.read_exact(&mut size_buf)?;
	let size = parse_big_endian_size(size_buf);
	
	// Read the remainder of the response into a vector.
	let mut resp : Vec<u8> = Vec::new();
	resp.resize(size as usize, 0);
	conn.read_exact(&mut resp)?;
	
	Ok(resp)
}
