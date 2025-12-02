# wgsrv

A command-line tool for managing WireGuard VPN networks on Linux.

## Features

- Create and manage multiple WireGuard networks with IPv4 and IPv6 support
- Dynamic peer registration with automatic IP assignment
- Monitor peer connection statistics (handshake times, data transfer)
- Systemd integration for automatic network startup

## Installation

```bash
cargo build --release
sudo cp target/release/wgsrv /usr/local/bin/
```

### Systemd Service (Optional)

To automatically bring up networks on boot:

```bash
sudo cp wgsrv.service /etc/systemd/system/
sudo systemctl enable wgsrv
```

## Usage

### Network Management

```bash
# Create a new network
wgsrv network add mynet --net4 10.0.0.0/24 --net6 fd00::/64 51820

# List all networks
wgsrv network list    # or: wgsrv net ls

# Show network details
wgsrv network show mynet

# Bring network up/down
wgsrv network up mynet
wgsrv network down mynet

# Bring all networks up/down
wgsrv network up
wgsrv network down

# Delete a network
wgsrv network delete mynet    # or: wgsrv net rm mynet
```

### Peer Management

```bash
# List peers with connection status
wgsrv peer list mynet    # or: wgsrv peer ls mynet

# Show peer details
wgsrv peer show mynet alice

# Delete a peer
wgsrv peer delete mynet alice    # or: wgsrv peer rm mynet alice

# Start registration server for new peers
wgsrv peer register mynet --listen 0.0.0.0:52001
```

## Registering a New Peer

Peer registration uses a simple client-server protocol. The server operator runs `wgsrv peer register` and the client uses the provided script.

### On the Server

```bash
# Start the registration server (waits for one client connection)
wgsrv peer register mynet --listen 0.0.0.0:52001
```

The server will wait for a client to connect and prompt for confirmation before adding the peer.

### On the Client

Use the `register-client.sh` script:

```bash
# Basic usage
./scripts/register-client.sh vpn.example.com:52001 my-laptop

# With persistent keepalive (for mobile clients behind NAT)
./scripts/register-client.sh vpn.example.com:52001 my-phone --keepalive
```

The script will:
1. Generate a WireGuard key pair
2. Connect to the server and send the registration request
3. Receive the configuration from the server
4. Optionally save it to `/etc/wireguard/wg0.conf`
5. Optionally enable the interface on boot (systemd)
6. Optionally bring up the connection immediately

#### Script Options

```
Usage: register-client.sh [OPTIONS] <HOST[:PORT]> <PEER_NAME>

Options:
  -h, --help       Show help message
  -k, --keepalive  Automatically add PersistentKeepalive = 25

Environment variables:
  PRIVATE_KEY    Use existing private key instead of generating one
  PUBLIC_KEY     Use existing public key instead of deriving from private key
  ALWAYS_ANSWER  Auto-answer prompts (for non-interactive use)
```

## Configuration

The default configuration file is `/etc/wireguard/wgsrv.json`. You can specify a different path with `--settings`.

### Verbosity

```bash
wgsrv -v ...      # Debug output
wgsrv -vv ...     # Trace output
wgsrv -q ...      # Quiet mode (errors only)
```

## Requirements

- Linux (uses netlink for network interface management)
- WireGuard kernel module or wireguard-tools
- Root privileges for network operations

## License

MIT
