use ipnetwork::IpNetwork;
use std::error::Error;
use std::io::{self, Write};

pub fn get_nth_ip(network: &IpNetwork, n: u32) -> Result<IpNetwork, Box<dyn Error>> {
    let ip = network
        .iter()
        .nth(n as usize)
        .ok_or(format!("Could not get ip #{} in network {}", n, network))?;
    Ok(IpNetwork::new(ip, network.prefix())?)
}

pub fn user_confirm(prompt: &str) -> bool {
    print!("{} [y/N] ", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.to_lowercase().starts_with('y')
}

pub fn unknown_network_error(name: &str, available: &[String]) -> Box<dyn Error> {
    if available.is_empty() {
        format!("Network '{}' not found. No networks configured.", name).into()
    } else {
        format!(
            "Network '{}' not found. Available networks: {}",
            name,
            available.join(", ")
        )
        .into()
    }
}

pub fn unknown_peer_error(name: &str, network: &str, available: &[String]) -> Box<dyn Error> {
    if available.is_empty() {
        format!(
            "Peer '{}' not found in network '{}'. No peers configured.",
            name, network
        )
        .into()
    } else {
        format!(
            "Peer '{}' not found in network '{}'. Available peers: {}",
            name,
            network,
            available.join(", ")
        )
        .into()
    }
}
