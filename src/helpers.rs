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
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.to_lowercase().starts_with('y')
}
