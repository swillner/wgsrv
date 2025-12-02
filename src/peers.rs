use crate::helpers::{get_nth_ip, unknown_network_error, unknown_peer_error, user_confirm};
use crate::settings::{PeerConf, Settings};
use clap::Subcommand;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::info;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::SystemTime;
use termion::color;
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

#[derive(Subcommand)]
pub enum Command {
    /// Delete a peer from a network
    #[command(visible_alias = "rm")]
    Delete {
        /// Name of the network
        #[arg()]
        network: String,

        /// Name of the peer to delete
        #[arg()]
        peer: String,
    },
    /// List all peers in a network with their status
    #[command(visible_alias = "ls")]
    List {
        /// Name of the network
        #[arg()]
        network: String,
    },
    /// Start registration server for new peers
    Register {
        /// Name of the network to register peers in
        #[arg()]
        network: String,

        /// Address and port to listen on for peer connections
        #[arg(long, default_value = "0.0.0.0:52001")]
        listen: SocketAddr,
    },
    /// Show details of a specific peer
    Show {
        /// Name of the network
        #[arg()]
        network: String,

        /// Name of the peer to show
        #[arg()]
        peer: String,
    },
}

impl Command {
    pub fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        let available_networks: Vec<String> = settings.networks.keys().cloned().collect();

        match self {
            Command::Delete { network, peer } => {
                delete(settings, network, peer, &available_networks)
            }
            Command::List { network } => list(&settings, network, &available_networks),
            Command::Register { network, listen } => {
                register(settings, network, listen, &available_networks)
            }
            Command::Show { network, peer } => show(&settings, network, peer, &available_networks),
        }
    }
}

fn delete(
    mut settings: Settings,
    network_name: String,
    peer_name: String,
    available_networks: &[String],
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or_else(|| unknown_network_error(&network_name, available_networks))?;
    let available_peers: Vec<String> = network.peers.keys().cloned().collect();
    let peer = network
        .peers
        .remove(&peer_name)
        .ok_or_else(|| unknown_peer_error(&peer_name, &network_name, &available_peers))?;
    if user_confirm(&format!(
        "Delete peer {} with public key {}?",
        peer_name,
        peer.public_key.to_base64()
    )) {
        let wg_interface = network_name.parse()?;
        DeviceUpdate::new()
            .remove_peer_by_key(&peer.public_key)
            .apply(&wg_interface, Backend::Kernel)?;
        settings.persist()?;
    }
    Ok(())
}

fn format_secs(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{}d {:02}:{:02}:{:02}", days, hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn list(
    settings: &Settings,
    network_name: String,
    available_networks: &[String],
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(&network_name)
        .ok_or_else(|| unknown_network_error(&network_name, available_networks))?;
    let wg_interface = network_name.parse()?;
    let device = Device::get(&wg_interface, Backend::Kernel)?;
    let now = SystemTime::now();
    let peer_infos = device
        .peers
        .iter()
        .map(|p| (p.config.public_key.to_base64(), p))
        .collect::<HashMap<_, _>>();

    // Table header
    println!(
        "{:>13}  {:16}  {:16}  {:39}  {:>10}  {:>10}",
        "Handshake", "Name", "IPv4", "IPv6", "Sent", "Received"
    );
    println!("{}", "-".repeat(113));

    for (name, peer) in network.peers.iter().sorted_by_key(|(_, p)| p.id) {
        let peer_info = peer_infos.get(&peer.public_key.to_base64());
        let (state_color, handshake, tx_bytes, rx_bytes): (
            Box<dyn color::Color>,
            String,
            String,
            String,
        ) = if let Some(peer_info) = peer_info {
            let tx_bytes = format_bytes(peer_info.stats.tx_bytes);
            let rx_bytes = format_bytes(peer_info.stats.rx_bytes);
            if let Some(handshake) = peer_info.stats.last_handshake_time {
                let handshake = now.duration_since(handshake)?.as_secs();
                let state_color: Box<dyn color::Color> = if handshake > 300 {
                    Box::new(color::Yellow)
                } else {
                    Box::new(color::Green)
                };
                (state_color, format_secs(handshake), tx_bytes, rx_bytes)
            } else {
                (Box::new(color::Red), "-".to_string(), tx_bytes, rx_bytes)
            }
        } else {
            (
                Box::new(color::Cyan),
                "(not active)".to_string(),
                "-".to_string(),
                "-".to_string(),
            )
        };
        println!(
            "{}{:>13}  {:16}  {:16}  {:39}  {:>10}  {:>10}{}",
            color::Fg(state_color.as_ref()),
            handshake,
            name,
            get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?.ip(),
            get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?.ip(),
            tx_bytes,
            rx_bytes,
            color::Fg(color::Reset)
        );
    }
    Ok(())
}

fn register(
    mut settings: Settings,
    network_name: String,
    listen: SocketAddr,
    available_networks: &[String],
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or_else(|| unknown_network_error(&network_name, available_networks))?;
    let listener = TcpListener::bind(listen)?;
    info!("Waiting for peer to connect...");
    match listener.accept() {
        Ok((socket, _addr)) => {
            info!("Peer connected");
            let mut reader = BufReader::new(socket.try_clone()?);

            let peer_name = {
                let mut peer_name = String::new();
                reader.read_line(&mut peer_name)?;
                peer_name.pop(); // remove newline
                if peer_name.len() < 3 {
                    return Err("Invalid peer name".into());
                }
                if network.peers.contains_key(&peer_name) {
                    return Err("Peer already registered".into());
                }
                peer_name
            };

            let peer_public_key = {
                let mut peer_public_key = String::new();
                reader.read_line(&mut peer_public_key)?;
                peer_public_key.pop(); // remove newline
                Key::from_base64(&peer_public_key)?
            };

            let used_peer_ids: Vec<u32> = network.peers.values().map(|p| p.id).collect();
            let peer_id = (2..)
                .find(|id| !used_peer_ids.contains(id))
                .ok_or("No more valid slots in network")?;
            let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer_id)?;
            let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer_id)?;

            if !user_confirm(&format!(
                "Register peer {} with public key {} with ips {} and {}?",
                peer_name,
                peer_public_key.to_base64(),
                ip4.ip(),
                ip6.ip(),
            )) {
                return Err("User cancelled".into());
            }

            let public_key = network.private_key.generate_public();
            write!(
                BufWriter::new(socket.try_clone()?),
                "[Interface]
Address = {},{}
MTU = 1280 # otherwise ssh over wireguard hangs
PrivateKey = PRIVATE_KEY

[Peer]
PublicKey = {}
AllowedIPs = {},{}
Endpoint = HOST_IP:{}
",
                ip4,
                ip6,
                public_key.to_base64(),
                network.net4,
                network.net6,
                network.port
            )?;

            let wg_interface = network_name.parse()?;
            let peer = PeerConfigBuilder::new(&peer_public_key)
                .replace_allowed_ips()
                .add_allowed_ip(ip4.ip(), 32)
                .add_allowed_ip(ip6.ip(), 128);
            DeviceUpdate::new()
                .add_peer(peer)
                .apply(&wg_interface, Backend::Kernel)?;

            network.peers.insert(
                peer_name,
                PeerConf {
                    public_key: peer_public_key,
                    id: peer_id,
                },
            );

            settings.persist()
        }
        Err(e) => Err(e.into()),
    }
}

fn show(
    settings: &Settings,
    network_name: String,
    peer_name: String,
    available_networks: &[String],
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(&network_name)
        .ok_or_else(|| unknown_network_error(&network_name, available_networks))?;
    let available_peers: Vec<String> = network.peers.keys().cloned().collect();
    let peer = network
        .peers
        .get(&peer_name)
        .ok_or_else(|| unknown_peer_error(&peer_name, &network_name, &available_peers))?;
    let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?;
    let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?;
    info!("Peer {} in {}:", peer_name, network.domain);
    info!("  Public key: {}", peer.public_key.to_base64());
    info!("  IPv4: {}", ip4.ip());
    info!("  IPv6: {}", ip6.ip());
    Ok(())
}
