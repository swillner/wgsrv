use ipnetwork::IpNetwork;
use std::error::Error;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr};

pub fn get_nth_ip(network: &IpNetwork, n: u32) -> Result<IpNetwork, Box<dyn Error>> {
    let ip = match network {
        IpNetwork::V4(network) => network.nth(n).map(IpAddr::V4),
        IpNetwork::V6(network) => {
            let n = u128::from(n);
            if n < network.size() {
                Some(IpAddr::V6(Ipv6Addr::from(
                    u128::from(network.network()) + n,
                )))
            } else {
                None
            }
        }
    }
    .ok_or(format!("Could not get ip #{} in network {}", n, network))?;
    Ok(IpNetwork::new(ip, network.prefix())?)
}

pub fn user_confirm(prompt: &str) -> bool {
    print!("{} [y/N] ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.to_lowercase().starts_with('y')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_indexed_ipv4_address() {
        let network = "10.0.0.0/24".parse().unwrap();
        let ip = get_nth_ip(&network, 42).unwrap();

        assert_eq!(ip.to_string(), "10.0.0.42/24");
    }

    #[test]
    fn gets_indexed_ipv6_address() {
        let network = "fd00::/120".parse().unwrap();
        let ip = get_nth_ip(&network, 42).unwrap();

        assert_eq!(ip.to_string(), "fd00::2a/120");
    }

    #[test]
    fn preserves_prefix_length() {
        let network = "192.0.2.64/26".parse().unwrap();
        let ip = get_nth_ip(&network, 1).unwrap();

        assert_eq!(ip.prefix(), 26);
    }

    #[test]
    fn rejects_out_of_range_index() {
        let network = "192.0.2.0/31".parse().unwrap();

        assert!(get_nth_ip(&network, 2).is_err());
    }
}
