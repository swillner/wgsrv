#!/usr/bin/env bash
set -e

COLOR_ORANGE='\033[0;33m'
COLOR_LIGHT_GRAY='\033[0;37m'
COLOR_RED='\033[0;31m'
COLOR_CLEAR='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <HOST[:PORT]> <PEER_NAME>

Register this machine as a new WireGuard peer with a wgsrv server.

Arguments:
  HOST[:PORT]    Server hostname or IP (default port: 52001)
  PEER_NAME      Name for this peer (minimum 3 characters)

Options:
  -h, --help     Show this help message
  -k, --keepalive  Automatically add PersistentKeepalive = 25

Environment variables:
  PRIVATE_KEY    Use existing private key instead of generating one
  PUBLIC_KEY     Use existing public key instead of deriving from private key
  ALWAYS_ANSWER  Auto-answer prompts (for non-interactive use)

Examples:
  $(basename "$0") vpn.example.com laptop
  $(basename "$0") 192.168.1.1:52001 phone --keepalive
EOF
}

error() {
    echo -e "${COLOR_RED}Error: $1${COLOR_CLEAR}" >&2
    exit 1
}

get_response () {
    local question=$1
    local default_indicator=$2
    local response
    if [[ -z "$ALWAYS_ANSWER" ]]
    then
        echo -e -n "$COLOR_ORANGE$question$COLOR_CLEAR $COLOR_LIGHT_GRAY$default_indicator$COLOR_CLEAR " > /dev/tty
        read -r response < /dev/tty
    else
        response=$ALWAYS_ANSWER
    fi
    echo "$response"
}

ask_user () {
    local question=$1
    local default=$2
    local default_indicator
    if [[ "$default" = "y" ]]
    then
        default_indicator="[Y/n]"
    else
        default_indicator="[y/N]"
    fi
    local response
    response=$(get_response "$question" "$default_indicator")
    case $response in
        [yY][eE][sS]|[yY]|'')
            if [[ "$default" != "y" && "$response" == "" ]]
            then
                return 1
            else
                return 0
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# Parse arguments
ADD_KEEPALIVE=false
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -k|--keepalive)
            ADD_KEEPALIVE=true
            shift
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

set -- "${POSITIONAL_ARGS[@]}"

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

HOST="$1"
PEER_NAME="$2"

# Validate peer name (server requires minimum 3 characters)
if [[ ${#PEER_NAME} -lt 3 ]]; then
    error "Peer name must be at least 3 characters long"
fi

# Parse host and port
PORT=$(cut -d ':' -f 2 -s <<<"$HOST")
PORT=${PORT:-52001}
HOST=$(cut -d ':' -f 1 <<<"$HOST")

# Resolve hostname to IP
HOST_IP=$(getent ahostsv4 "$HOST" 2>/dev/null | head -n 1 | cut -d ' ' -f 1)
if [[ -z "$HOST_IP" ]]; then
    error "Could not resolve hostname: $HOST"
fi

# Generate keys if not provided
[[ -n "$PRIVATE_KEY" ]] || PRIVATE_KEY=$(wg genkey)
[[ -n "$PUBLIC_KEY" ]] || PUBLIC_KEY=$(wg pubkey <<<"$PRIVATE_KEY")

echo -e "${COLOR_ORANGE}Adding peer $PEER_NAME to $HOST with public key $PUBLIC_KEY - please confirm on server...${COLOR_CLEAR}" >&2

# Connect to server and send registration request
if ! res=$(nc -w 30 "$HOST" "$PORT" 2>&1 <<EOF
$PEER_NAME
$PUBLIC_KEY
EOF
); then
    error "Failed to connect to server at $HOST:$PORT"
fi

if [[ -z "$res" ]]; then
    error "No response from server - registration may have been rejected"
fi

res="${res//PRIVATE_KEY/$PRIVATE_KEY}"
res="${res//HOST_IP/$HOST_IP}"

echo -e "${COLOR_ORANGE}Received configuration:${COLOR_CLEAR}" >&2
echo -e "$res"

if ask_user "Set as wireguard configuration" "y"
then
    # Add keepalive if requested via flag or interactively
    if [[ "$ADD_KEEPALIVE" == "true" ]] || ask_user "Add persistent keepalive?" "n"
    then
        res=$(cat <<EOF
$res
PersistentKeepalive = 25
EOF
           )
    fi
    default_filename="/etc/wireguard/wg0.conf"
    filename=$(get_response "Filename for the configuration" "$default_filename")
    [[ -n "$filename" ]] || filename="$default_filename"
    echo "$res" | sudo tee "$filename" > /dev/null
    sudo chmod og-rwx "$filename"
    echo -e "${COLOR_ORANGE}Configuration saved to $filename${COLOR_CLEAR}" >&2

    # Extract interface name from filename (e.g., /etc/wireguard/wg0.conf -> wg0)
    interface_name=$(basename "$filename" .conf)

    # Check if systemd is available and offer to enable on boot
    if command -v systemctl &>/dev/null; then
        if ask_user "Enable WireGuard interface on boot (via systemd)?" "y"
        then
            sudo systemctl enable "wg-quick@${interface_name}.service"
            echo -e "${COLOR_ORANGE}Enabled wg-quick@${interface_name}.service to start on boot${COLOR_CLEAR}" >&2
        fi
    fi

    # Offer to bring up the interface now
    if ask_user "Bring up WireGuard interface now?" "y"
    then
        if command -v systemctl &>/dev/null; then
            sudo systemctl start "wg-quick@${interface_name}.service"
        else
            sudo wg-quick up "$filename"
        fi
        echo -e "${COLOR_ORANGE}WireGuard interface $interface_name is now active${COLOR_CLEAR}" >&2

        # Show connection status
        echo -e "${COLOR_ORANGE}Connection status:${COLOR_CLEAR}" >&2
        sudo wg show "$interface_name"
    fi
fi
