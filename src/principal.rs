use kerberos_asn1::PrincipalName;
use kerberos_constants::principal_names::{NT_PRINCIPAL,NT_ENTERPRISE,NT_SRV_INST};

pub enum SPN {
	NtPrincipal(String),
	NtEnterprise(String),
	NtSrvInst(String)
}

impl SPN {
	pub fn to_principal_name(&self) -> PrincipalName {
		match self {
			SPN::NtPrincipal(spn_string) => PrincipalName {
				name_type: NT_PRINCIPAL,
				name_string: spn_string.split("/").map(|s| s.to_string()).collect()
			},
			SPN::NtEnterprise(spn_string) => PrincipalName {
				name_type: NT_ENTERPRISE,
				name_string: spn_string.split("/").map(|s| s.to_string()).collect()
			},
			SPN::NtSrvInst(spn_string) => PrincipalName {
				name_type: NT_SRV_INST,
				name_string: spn_string.split("/").map(|s| s.to_string()).collect()
			}
		}
	}
	
	pub fn to_string(&self) -> String {
		match self {
			SPN::NtPrincipal(s) => s.to_string(),
			SPN::NtEnterprise(s) => s.to_string(),
			SPN::NtSrvInst(s) => s.to_string()
		}
	}
}
