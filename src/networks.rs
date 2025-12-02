use crate::helpers::{get_nth_ip, unknown_network_error, user_confirm};
use crate::settings::{NetworkConf, Settings};
use clap::Subcommand;
use futures::{future, stream::TryStreamExt};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;
use log::info;
use netlink_packet_route::route::RouteAttribute;
use rtnetlink::IpVersion;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use wireguard_control::{Backend, DeviceUpdate, KeyPair, PeerConfigBuilder};

#[derive(Subcommand)]
pub enum Command {
    /// Create a new WireGuard network
    Add {
        /// Name of the network (used as interface name)
        #[arg()]
        name: String,

        /// IPv4 network in CIDR notation (e.g., 10.0.0.0/24)
        #[arg(long)]
        net4: Ipv4Network,

        /// IPv6 network in CIDR notation (e.g., fd00::/64)
        #[arg(long)]
        net6: Ipv6Network,

        /// UDP port for WireGuard to listen on
        #[arg()]
        port: u16,
    },
    /// Delete an existing network
    #[command(visible_alias = "rm")]
    Delete {
        /// Name of the network to delete
        #[arg()]
        name: String,
    },
    /// Bring network(s) down
    Down {
        /// Network name (if omitted, all networks are brought down)
        #[arg()]
        name: Option<String>,
    },
    /// List all configured networks
    #[command(visible_alias = "ls")]
    List,
    /// Show details of a specific network
    Show {
        /// Name of the network to show
        #[arg()]
        name: String,
    },
    /// Bring network(s) up
    Up {
        /// Network name (if omitted, all networks are brought up)
        #[arg()]
        name: Option<String>,
    },
}

impl Command {
    pub fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        let available_networks: Vec<String> = settings.networks.keys().cloned().collect();

        match self {
            Command::Add {
                name,
                net4,
                net6,
                port,
            } => add(settings, name, net4, net6, port),
            Command::Delete { name } => delete(settings, &name, &available_networks),
            Command::Down { name } => with_netlink_handle(|handle| async move {
                if let Some(name) = name {
                    if !settings.networks.contains_key(&name) {
                        return Err(unknown_network_error(&name, &available_networks));
                    }
                    down(&name, &handle).await
                } else {
                    for (name, _) in &settings.networks {
                        down(&name, &handle).await?;
                    }
                    Ok(())
                }
            }),
            Command::List => list(&settings),
            Command::Show { name } => show(&settings, &name, &available_networks),
            Command::Up { name } => with_netlink_handle(|handle| async move {
                if let Some(name) = name {
                    let network = settings
                        .networks
                        .get(&name)
                        .ok_or_else(|| unknown_network_error(&name, &available_networks))?;
                    up(&name, network, &handle).await
                } else {
                    for (name, network) in &settings.networks {
                        up(&name, network, &handle).await?;
                    }
                    Ok(())
                }
            }),
        }
    }
}

fn add(
    mut settings: Settings,
    name: String,
    net4: Ipv4Network,
    net6: Ipv6Network,
    port: u16,
) -> Result<(), Box<dyn Error>> {
    let network = settings.networks.get(&name);
    if network.is_some() {
        return Err("Network already exists".into());
    }
    let network = NetworkConf {
        domain: name.clone(),
        net4,
        net6,
        port,
        private_key: KeyPair::generate().private,
        peers: HashMap::new(),
    };
    with_netlink_handle(|handle| async move {
        up(&name, &network, &handle).await?;
        settings.networks.insert(name, network);
        settings.persist()?;
        Ok(())
    })
}

fn delete(mut settings: Settings, name: &str, available: &[String]) -> Result<(), Box<dyn Error>> {
    if !settings.networks.contains_key(name) {
        return Err(unknown_network_error(name, available));
    }
    if user_confirm(&format!("Delete network {}?", name)) {
        with_netlink_handle(|handle| async move {
            let iface = Interface::new(name, &handle).await?;
            iface.delete().await?;
            settings.networks.remove(name);
            settings.persist()?;
            Ok(())
        })?;
    }
    Ok(())
}

async fn down(name: &str, handle: &rtnetlink::Handle) -> Result<(), Box<dyn Error>> {
    info!("Shutting down network: {}", name);
    let iface = Interface::new(name, handle).await?;
    iface.down().await
}

fn list(settings: &Settings) -> Result<(), Box<dyn Error>> {
    info!("Networks:");
    for (name, network) in &settings.networks {
        info!(
            "  {}: {} ({} peers)",
            name,
            network.net4,
            network.peers.len()
        );
    }
    Ok(())
}

fn show(settings: &Settings, name: &str, available: &[String]) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(name)
        .ok_or_else(|| unknown_network_error(name, available))?;
    info!("Network: {}", network.domain);
    info!("  IPv4: {}", network.net4);
    info!("  IPv6: {}", network.net6);
    info!("  Port: {}", network.port);
    info!("  Private key: {}", network.private_key.to_base64());
    info!("  Peers:");
    for (name, peer) in network.peers.iter().sorted_by_key(|(_, p)| p.id) {
        info!(
            "    {}: {}",
            name,
            get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?.ip()
        );
    }
    Ok(())
}

async fn up(
    name: &str,
    network: &NetworkConf,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn Error>> {
    info!("Initializing network: {}", name);
    let wg_interface = name.parse()?;
    let mut update = DeviceUpdate::new()
        .set_private_key(network.private_key.clone())
        .set_public_key(network.private_key.generate_public())
        .set_listen_port(network.port)
        .replace_peers();
    for (peer_name, peer) in &network.peers {
        let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?;
        let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?;
        info!("Adding peer {}: {} {}", peer_name, ip4, ip6);
        let peer = PeerConfigBuilder::new(&peer.public_key)
            .replace_allowed_ips()
            .add_allowed_ip(ip4.ip(), 32)
            .add_allowed_ip(ip6.ip(), 128);
        update = update.add_peer(peer);
    }
    update.apply(&wg_interface, Backend::Kernel)?;
    let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), 1)?;
    let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), 1)?;
    let iface = Interface::new(name, handle).await?;
    iface.up(Some(1280)).await?;
    iface.clear().await?;
    iface.add_address(&ip4).await?;
    iface.add_address(&ip6).await
}

#[tokio::main]
async fn with_netlink_handle<F, Fut, R>(f: F) -> Result<R, Box<dyn Error>>
where
    F: FnOnce(rtnetlink::Handle) -> Fut,
    Fut: Future<Output = Result<R, Box<dyn Error>>>,
{
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    f(handle).await
}

struct Interface<'a> {
    index: u32,
    handle: &'a rtnetlink::Handle,
}

fn map_netlink_error(e: rtnetlink::Error) -> Box<dyn Error> {
    match e {
        rtnetlink::Error::NetlinkError(e) => e.to_io().into(),
        rtnetlink::Error::UnexpectedMessage(_) => "Unexpected netlink message".into(),
        _ => e.into(),
    }
}

impl<'a> Interface<'a> {
    pub async fn new(name: &str, handle: &'a rtnetlink::Handle) -> Result<Self, Box<dyn Error>> {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        if let Some(link) = links.try_next().await.map_err(map_netlink_error)? {
            Ok(Self {
                index: link.header.index,
                handle,
            })
        } else {
            handle
                .link()
                .add()
                .name(name.to_string())
                .execute()
                .await
                .map_err(map_netlink_error)?;
            let mut links = handle.link().get().match_name(name.to_string()).execute();
            let link = links
                .try_next()
                .await
                .map_err(map_netlink_error)?
                .ok_or("Link not found after creation")?;
            Ok(Self {
                index: link.header.index,
                handle,
            })
        }
    }

    pub async fn down(&self) -> Result<(), Box<dyn Error>> {
        self.handle
            .link()
            .set(self.index)
            .down()
            .execute()
            .await
            .map_err(map_netlink_error)
    }

    pub async fn up(&self, mtu: Option<u32>) -> Result<(), Box<dyn Error>> {
        let mut req = self.handle.link().set(self.index);
        if let Some(mtu) = mtu {
            req = req.mtu(mtu);
        }
        req.up().execute().await.map_err(map_netlink_error)
    }

    pub async fn delete_routes(&self) -> Result<(), Box<dyn Error>> {
        for version in [IpVersion::V4, IpVersion::V6] {
            let routes = self
                .handle
                .route()
                .get(version)
                .execute()
                .try_filter(|route| {
                    future::ready(
                        route.attributes.iter().find_map(|attribute| {
                            if let RouteAttribute::Oif(iface) = attribute {
                                Some(*iface)
                            } else {
                                None
                            }
                        }) == Some(self.index),
                    )
                })
                .try_collect::<Vec<_>>()
                .await
                .map_err(map_netlink_error)?;
            for route in routes {
                self.handle
                    .route()
                    .del(route)
                    .execute()
                    .await
                    .map_err(map_netlink_error)?;
            }
        }
        Ok(())
    }

    pub async fn delete_addresses(&self) -> Result<(), Box<dyn Error>> {
        let addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute()
            .try_collect::<Vec<_>>()
            .await
            .map_err(map_netlink_error)?;
        for address in addresses {
            self.handle
                .address()
                .del(address)
                .execute()
                .await
                .map_err(map_netlink_error)?;
        }
        Ok(())
    }

    pub async fn add_address(&self, ipn: &IpNetwork) -> Result<(), Box<dyn Error>> {
        self.handle
            .address()
            .add(self.index, ipn.ip(), ipn.prefix())
            .execute()
            .await
            .map_err(map_netlink_error)
    }

    pub async fn clear(&self) -> Result<(), Box<dyn Error>> {
        self.delete_routes().await?;
        self.delete_addresses().await
    }

    pub async fn delete(&self) -> Result<(), Box<dyn Error>> {
        self.handle
            .link()
            .del(self.index)
            .execute()
            .await
            .map_err(map_netlink_error)
    }
}
