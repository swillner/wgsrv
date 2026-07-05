#!/usr/bin/env bash
set -euo pipefail

COLOR_ORANGE='\033[0;33m'
COLOR_LIGHT_GRAY='\033[0;37m'
COLOR_CLEAR='\033[0m'
MANUAL_REQUEST_BEGIN='-----BEGIN WGSRV CLIENT REQUEST-----'
MANUAL_REQUEST_END='-----END WGSRV CLIENT REQUEST-----'
MANUAL_CONFIG_BEGIN='-----BEGIN WGSRV CLIENT CONFIG-----'
MANUAL_CONFIG_END='-----END WGSRV CLIENT CONFIG-----'

usage() {
    printf 'Usage: %s [--manual] HOST[:PORT] PEER_NAME\n' "${0##*/}" >&2
}

info() {
    printf '%b%s%b\n' "$COLOR_ORANGE" "$*" "$COLOR_CLEAR" >&2
}

die() {
    info "$*"
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

prompt() {
    local question=$1
    local default_value=$2
    local response

    if [[ ! -t 0 && ! -r /dev/tty ]]; then
        printf '%s\n' "$default_value"
        return
    fi

    printf '%b%s%b %b%s%b ' \
        "$COLOR_ORANGE" "$question" "$COLOR_CLEAR" \
        "$COLOR_LIGHT_GRAY" "$default_value" "$COLOR_CLEAR" >/dev/tty
    read -r response </dev/tty
    printf '%s\n' "$response"
}

ask_user() {
    local question=$1
    local default=$2
    local default_indicator response

    if [[ "$default" = "y" ]]; then
        default_indicator='[Y/n]'
    else
        default_indicator='[y/N]'
    fi

    response=$(prompt "$question" "$default_indicator")

    case $response in
        [yY] | [yY][eE][sS])
            return 0
            ;;
        '')
            [[ "$default" = "y" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

parse_host() {
    local server=$1

    HOST=$server
    PORT=52001

    if [[ $server =~ ^\[(.+)\]:([0-9]+)$ ]]; then
        HOST=${BASH_REMATCH[1]}
        PORT=${BASH_REMATCH[2]}
    elif [[ $server == *:* && $server != *:*:* ]]; then
        HOST=${server%:*}
        PORT=${server##*:}
    fi

    [[ -n "$HOST" ]] || die "Invalid host"
    [[ $PORT =~ ^[0-9]+$ ]] || die "Invalid port: $PORT"
    ((PORT > 0 && PORT <= 65535)) || die "Invalid port: $PORT"
}

resolve_endpoint_host() {
    local host=$1
    local resolved

    if command -v getent >/dev/null 2>&1; then
        read -r resolved _ < <(getent ahostsv4 "$host" 2>/dev/null || true) || true
        if [[ -n "${resolved:-}" ]]; then
            printf '%s\n' "$resolved"
            return
        fi
    fi

    printf '%s\n' "$host"
}

register_peer() {
    local err_file nc_status
    need_command nc
    need_command timeout

    err_file=$(mktemp)

    if RESPONSE=$(printf '%s\n%s\n' "$PEER_NAME" "$PUBLIC_KEY" | timeout 30 nc "$HOST" "$PORT" 2>"$err_file"); then
        :
    else
        nc_status=$?
        cat "$err_file" >&2
        rm -f "$err_file"
        die "Could not register peer with $HOST:$PORT (exit $nc_status)"
    fi

    rm -f "$err_file"
    [[ -n "$RESPONSE" ]] || die "Server returned an empty configuration"
}

read_until_marker() {
    local end_marker=$1
    local block='' line
    local input=/dev/stdin

    if [[ -r /dev/tty ]]; then
        input=/dev/tty
    fi

    while IFS= read -r line; do
        line=${line%$'\r'}
        block+="$line"$'\n'
        if [[ $line == "$end_marker" ]]; then
            printf '%s' "$block"
            return
        fi
    done <"$input"

    die "Missing end marker: $end_marker"
}

manual_register_peer() {
    info "Copy this request block to the server:"
    printf '%s\n' "$MANUAL_REQUEST_BEGIN"
    printf 'Name: %s\n' "$PEER_NAME"
    printf 'PublicKey: %s\n' "$PUBLIC_KEY"
    printf '%s\n' "$MANUAL_REQUEST_END"

    info "Paste server config block, ending with $MANUAL_CONFIG_END:"
    RESPONSE=$(read_until_marker "$MANUAL_CONFIG_END")

    [[ $RESPONSE == *"$MANUAL_CONFIG_BEGIN"* ]] || die "Missing config begin marker"
    [[ $RESPONSE == *"$MANUAL_CONFIG_END"* ]] || die "Missing config end marker"
    RESPONSE=${RESPONSE#*"$MANUAL_CONFIG_BEGIN"}
    RESPONSE=${RESPONSE#$'\n'}
    RESPONSE=${RESPONSE%"$MANUAL_CONFIG_END"}
    RESPONSE=${RESPONSE%$'\n'}
    [[ -n "$RESPONSE" ]] || die "Server returned an empty configuration"
}

install_config() {
    local filename=$1
    local tmp status
    need_command sudo
    need_command install

    tmp=$(mktemp)

    printf '%s\n' "$RESPONSE" >"$tmp"
    if sudo install -m 600 "$tmp" "$filename"; then
        rm -f "$tmp"
    else
        status=$?
        rm -f "$tmp"
        return "$status"
    fi
}

service_for_config() {
    local filename=$1

    if [[ $filename == /etc/wireguard/*.conf ]]; then
        local name=${filename##*/}
        name=${name%.conf}
        if [[ $name =~ ^[A-Za-z0-9_.=-]+$ ]]; then
            printf 'wg-quick@%s.service\n' "$name"
        fi
    fi
}

MANUAL=false
if [[ ${1:-} == "--manual" ]]; then
    MANUAL=true
    shift
fi

[[ $# -eq 2 ]] || {
    usage
    exit 2
}

need_command wg
need_command mktemp

parse_host "$1"
PEER_NAME=$2
[[ $PEER_NAME != *$'\n'* && $PEER_NAME != *$'\r'* ]] || die "Peer name must be a single line"

if [[ -z "${PRIVATE_KEY:-}" ]]; then
    PRIVATE_KEY=$(wg genkey)
fi
if [[ -z "${PUBLIC_KEY:-}" ]]; then
    PUBLIC_KEY=$(wg pubkey <<<"$PRIVATE_KEY")
fi

ENDPOINT_HOST=$(resolve_endpoint_host "$HOST")

if [[ $MANUAL == true ]]; then
    info "Adding peer $PEER_NAME to $HOST:$PORT manually with public key $PUBLIC_KEY"
    manual_register_peer
else
    info "Adding peer $PEER_NAME to $HOST:$PORT with public key $PUBLIC_KEY - please confirm on server..."
    register_peer
fi

RESPONSE=${RESPONSE//PRIVATE_KEY/$PRIVATE_KEY}
RESPONSE=${RESPONSE//HOST_IP/$ENDPOINT_HOST}
if [[ $RESPONSE == *'PresharedKey = PRESHARED_KEY'* ]]; then
    PRESHARED_KEY=$(prompt "Preshared key shown on the server" "")
    [[ -n "$PRESHARED_KEY" ]] || die "Preshared key is required"
    RESPONSE=${RESPONSE//PRESHARED_KEY/$PRESHARED_KEY}
fi

info "Received configuration:"
printf '%s\n' "$RESPONSE"

if ask_user "Set as wireguard configuration" "y"; then
    if ask_user "Add persistent keepalive?" "n"; then
        RESPONSE="$RESPONSE
PersistentKeepalive = 25"
    fi

    default_filename='/etc/wireguard/wg0.conf'
    filename=$(prompt "Filename for the configuration" "$default_filename")
    [[ -n "$filename" ]] || filename=$default_filename

    install_config "$filename"
    info "Installed $filename"

    service=$(service_for_config "$filename")
    if [[ -n "${service:-}" ]] && ask_user "Restart $service" "n"; then
        need_command systemctl
        sudo systemctl restart "$service"
    fi
fi
