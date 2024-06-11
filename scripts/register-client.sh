#!/usr/bin/env bash
set -e

COLOR_ORANGE='\033[0;33m'
COLOR_LIGHT_GRAY='\033[0;37m'
COLOR_CLEAR='\033[0m'

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

[[ -n "$PRIVATE_KEY" ]] || PRIVATE_KEY=$(wg genkey)
[[ -n "$PUBLIC_KEY" ]] || PUBLIC_KEY=$(wg pubkey <<<"$PRIVATE_KEY")

HOST=${1:?${COLOR_ORANGE}No host given${COLOR_CLEAR}}
PEER_NAME=${2:?${COLOR_ORANGE}No peer name given${COLOR_CLEAR}}
PORT=$(cut -d ':' -f 2 -s <<<"$HOST")
PORT=${PORT:-52001}
HOST=$(cut -d ':' -f 1 <<<"$HOST")
HOST_IP=$(getent ahostsv4 "$HOST" | head -n 1 | cut -d ' ' -f 1)

echo -e "${COLOR_ORANGE}Adding peer $PEER_NAME to $HOST with public key $PUBLIC_KEY - please confirm on server...${COLOR_CLEAR}" >&2

res=$(nc -v "$HOST" "$PORT" <<EOF
$PEER_NAME
$PUBLIC_KEY
EOF
   )

if [[ -z "$res" ]]
then
    echo -e "${COLOR_ORANGE}An error occured${COLOR_CLEAR}" >&2
    exit 1
fi

res="${res//PRIVATE_KEY/$PRIVATE_KEY}"
res="${res//HOST_IP/$HOST_IP}"

echo -e "${COLOR_ORANGE}Received configuration:${COLOR_CLEAR}" >&2
echo -e "$res"

if ask_user "Set as wireguard configuration" "y"
then
    if ask_user "Add persistent keepalive?" "n"
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
fi
