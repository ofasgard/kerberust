# Kerberust

A simple kerberoasting tool written from scratch in Rust. Currently compiles to a single binary, `ask_tgs` which can be used to request tickets directly from a domain controller. 

```text
A tool to request a specific service ticket from the KDC and dump it to a KIRBI file.

Usage: ask_tgs [OPTIONS] --domain <DOMAIN> --user <USER> --outfile <PATH>

Options:
  -d, --domain <DOMAIN>      Domain/realm to authenticate to.
  -u, --user <USER>          Username to authenticate with.
  -p, --password <PASSWORD>  Password to authenticate with.
  -n, --ntlm <HASH>          NTLM hash to authenticate with.
  -k, --key <KEY>            128 or 256-bit AES key to authenticate with.
  -s, --salt <SALT>          Custom salt to be used with the password (optional).
  -S, --target-spn <SPN>     Service principal name to request a ticket for. [HTTP/somedomain.local]
  -U, --target-user <SPN>    Username to request a ticket for. [USER@SOMEDOMAIN.LOCAL]
  -O, --outfile <PATH>       Output path to write the requested ticket to (in KIRBI format).
  -K, --kdc <HOST>           IP address or hostname for the KDC, if different from the domain.
  -P, --port <PORT>          Port number to use for the KDC, if different from the default port.
  -h, --help                 Print help
```

To install, simply invoke `cargo build --release` or `cargo install --path .` to install it to your user path.

Relies on the `kerberos_asn1` under the hood. Support for AS-REP roasting is planned for the future.
