use crate::helpers::{get_nth_ip, user_confirm};
use crate::settings::{PeerConf, Settings};
use clap::Subcommand;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::SystemTime;
use termion::color;
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

#[derive(Subcommand)]
pub enum Command {
    Delete {
        #[arg()]
        network: String,

        #[arg()]
        peer: String,
    },
    List {
        #[arg()]
        network: String,
    },
    Register {
        #[arg()]
        network: String,

        #[arg(long, default_value = "0.0.0.0:52001")]
        listen: SocketAddr,

        #[arg(long)]
        preshared_key: bool,
    },
    Show {
        #[arg()]
        network: String,

        #[arg()]
        peer: String,
    },
}

impl Command {
    pub fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        match self {
            Command::Delete { network, peer } => delete(settings, network, peer),
            Command::List { network } => list(&settings, network),
            Command::Register {
                network,
                listen,
                preshared_key,
            } => register(settings, network, listen, preshared_key),
            Command::Show { network, peer } => show(&settings, network, peer),
        }
    }
}

fn delete(
    mut settings: Settings,
    network_name: String,
    peer_name: String,
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or("Unknown network")?;
    let peer = network.peers.remove(&peer_name).ok_or("Unknown peer")?;
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

fn read_required_line<R: BufRead>(reader: &mut R, field: &str) -> Result<String, Box<dyn Error>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(format!("Missing {}", field).into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn first_available_peer_id(used_ids: impl IntoIterator<Item = u32>) -> Result<u32, Box<dyn Error>> {
    let used_ids = used_ids.into_iter().collect::<HashSet<_>>();
    (2..)
        .find(|id| !used_ids.contains(id))
        .ok_or("No more valid slots in network".into())
}

fn render_client_config(
    ip4: &IpNetwork,
    ip6: &IpNetwork,
    server_public_key: &Key,
    network4: &IpNetwork,
    network6: &IpNetwork,
    port: u16,
    preshared_key: Option<&str>,
) -> String {
    let preshared_key = preshared_key
        .map(|key| format!("PresharedKey = {}\n", key))
        .unwrap_or_default();

    format!(
        "[Interface]
Address = {},{}
MTU = 1280 # otherwise ssh over wireguard hangs
PrivateKey = PRIVATE_KEY

[Peer]
PublicKey = {}
{preshared_key}AllowedIPs = {},{}
Endpoint = HOST_IP:{}
",
        ip4,
        ip6,
        server_public_key.to_base64(),
        network4,
        network6,
        port,
    )
}

fn list(settings: &Settings, network_name: String) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(&network_name)
        .ok_or("Unknown network")?;
    let wg_interface = network_name.parse()?;
    let device = Device::get(&wg_interface, Backend::Kernel)?;
    let now = SystemTime::now();
    let peer_infos = device
        .peers
        .iter()
        .map(|p| (p.config.public_key.to_base64(), p))
        .collect::<HashMap<_, _>>();
    println!(
        "  {: >13} {: <16} {: <16} {: <16} {: <10} {: <10}",
        "Handshake", "Name", "IPv4", "IPv6", "Sent", "Received"
    );
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
                "x".to_string(),
                "".to_string(),
                "".to_string(),
            )
        };
        println!(
            "  {}{: >13} {: <16} {: <16} {: <16} {: <10} {: <10}{}",
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
    use_preshared_key: bool,
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or("Unknown network")?;
    let listener = TcpListener::bind(listen)?;
    println!("Waiting for peer to connect...");
    match listener.accept() {
        Ok((socket, _addr)) => {
            println!("Peer connected");
            let mut reader = BufReader::new(socket.try_clone()?);

            let peer_name = {
                let peer_name = read_required_line(&mut reader, "peer name")?;
                if peer_name.len() < 3 {
                    return Err("Invalid peer name".into());
                }
                if network.peers.contains_key(&peer_name) {
                    return Err("Peer already registered".into());
                }
                peer_name
            };

            let peer_public_key = {
                let peer_public_key = read_required_line(&mut reader, "peer public key")?;
                Key::from_base64(&peer_public_key)?
            };

            let peer_id = first_available_peer_id(network.peers.values().map(|p| p.id))?;
            let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer_id)?;
            let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer_id)?;
            let preshared_key = use_preshared_key.then(Key::generate_preshared);

            if !user_confirm(&format!(
                "Register peer {} with public key {} with ips {} and {}?",
                peer_name,
                peer_public_key.to_base64(),
                ip4.ip(),
                ip6.ip(),
            )) {
                return Err("User cancelled".into());
            }

            let preshared_key_for_client = if let Some(key) = &preshared_key {
                if user_confirm("Send preshared key over the unencrypted registration connection?")
                {
                    Some(key.to_base64())
                } else {
                    println!("Preshared key for {}: {}", peer_name, key.to_base64());
                    println!("Copy this key to the client out of band.");
                    Some("PRESHARED_KEY".to_string())
                }
            } else {
                None
            };

            let public_key = network.private_key.get_public();
            let config = render_client_config(
                &ip4,
                &ip6,
                &public_key,
                &IpNetwork::V4(network.net4),
                &IpNetwork::V6(network.net6),
                network.port,
                preshared_key_for_client.as_deref(),
            );
            BufWriter::new(socket.try_clone()?).write_all(config.as_bytes())?;

            let wg_interface = network_name.parse()?;
            let mut peer = PeerConfigBuilder::new(&peer_public_key)
                .replace_allowed_ips()
                .add_allowed_ip(ip4.ip(), 32)
                .add_allowed_ip(ip6.ip(), 128);
            if let Some(key) = &preshared_key {
                peer = peer.set_preshared_key(key.clone());
            }
            DeviceUpdate::new()
                .add_peer(peer)
                .apply(&wg_interface, Backend::Kernel)?;

            network.peers.insert(
                peer_name,
                PeerConf {
                    public_key: peer_public_key,
                    preshared_key,
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
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(&network_name)
        .ok_or("Unknown network")?;
    let peer = network.peers.get(&peer_name).ok_or("Unknown peer")?;
    let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?;
    let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?;
    println!(
        "Peer {} in {}:
  Public key: {}
  IPv4: {}
  IPv6: {}",
        peer_name,
        network.domain,
        peer.public_key.to_base64(),
        ip4.ip(),
        ip6.ip()
    );
    if let Some(preshared_key) = &peer.preshared_key {
        println!("  Preshared key: {}", preshared_key.to_base64());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_lf_terminated_line() {
        let mut reader = Cursor::new("peer\n");

        assert_eq!(
            read_required_line(&mut reader, "peer name").unwrap(),
            "peer"
        );
    }

    #[test]
    fn reads_crlf_terminated_line() {
        let mut reader = Cursor::new("peer\r\n");

        assert_eq!(
            read_required_line(&mut reader, "peer name").unwrap(),
            "peer"
        );
    }

    #[test]
    fn keeps_eof_terminated_line_intact() {
        let mut reader = Cursor::new("peer");

        assert_eq!(
            read_required_line(&mut reader, "peer name").unwrap(),
            "peer"
        );
    }

    #[test]
    fn rejects_missing_required_line() {
        let mut reader = Cursor::new("");

        assert!(read_required_line(&mut reader, "peer name").is_err());
    }

    #[test]
    fn finds_first_available_peer_id_from_two() {
        assert_eq!(first_available_peer_id([2, 4, 5]).unwrap(), 3);
    }

    #[test]
    fn uses_two_when_no_peer_ids_are_used() {
        assert_eq!(first_available_peer_id([]).unwrap(), 2);
    }

    #[test]
    fn renders_client_config_with_preshared_key_placeholder() {
        let config = render_client_config(
            &"10.0.0.2/24".parse().unwrap(),
            &"fd00::2/64".parse().unwrap(),
            &Key::zero(),
            &"10.0.0.0/24".parse().unwrap(),
            &"fd00::/64".parse().unwrap(),
            51820,
            Some("PRESHARED_KEY"),
        );

        assert!(config.contains("PresharedKey = PRESHARED_KEY\n"));
    }
}
