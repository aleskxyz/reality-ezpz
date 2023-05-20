#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -e
declare -A defaults
declare -A config_file
declare -A args
declare -A config
declare -A users

default_path="${HOME}/reality"
xray_image="teddysun/xray:1.8.1"
warp_image="aleskxyz/warp-svc:1.2"
singbox_image="gzxhwq/sing-box:v1.3-beta10"

BACKTITLE=RealityEZPZ
MENU="Select an option:"
HEIGHT=30
WIDTH=60
CHOICE_HEIGHT=20

defaults[transport]=tcp
defaults[domain]=www.google.com
defaults[port]=443
defaults[safenet]=OFF
defaults[natvps]=OFF
defaults[warp]=OFF
defaults[warp_license]=""
defaults[core]="singbox"

config_items=(
  "core"
  "public_key"
  "private_key"
  "short_id"
  "transport"
  "domain"
  "server"
  "port"
  "safenet"
  "natvps"
  "warp"
  "warp_license"
)

domain_regex="^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
path_regex="^/.*"
port_regex="^[1-9][0-9]*$"
warp_license_regex="^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}$"
username_regex="^[a-zA-Z0-9]+$"

function show_help {
  echo ""
  echo "Usage: reality-ezpz.sh [-t|--transport=tcp|h2|grpc] [-d|--domain=<domain>] [--regenerate] [--default] [-r|--restart] [-p|--path=<path>] [-s|--enable-safenet] [--disable-safenet] [--port=<port>] [--enable-natvps] [--disable-natvps] [--warp-license=<license>] [-w|--enable-warp] [--disable-warp] [-c|--core=xray|singbox] [-m|--menu] [-u|--uninstall]"
  echo "  -t, --transport        Transport protocol (h2, grpc, tcp, default: ${defaults[transport]})"
  echo "  -d, --domain           Domain to use as SNI (default: ${defaults[domain]})"
  echo "      --regenerate       Regenerate public and private keys"
  echo "      --default          Restore default configuration"
  echo "  -r  --restart          Restart services"
  echo "  -u, --uninstall        Uninstall reality"
  echo "  -p, --path             Absolute path to configuration directory (default: ${default_path})"
  echo "  -s  --enable-safenet   Enable blocking malware and adult content"
  echo "      --disable-safenet  Disable block malware and adult content"
  echo "      --port             Server port (default: ${defaults[port]})"
  echo "      --enable-natvps    Enable natvps.net support"
  echo "      --disble-natvps    Disable natvps.net support"
  echo "      --warp-license     Add Cloudflare warp+ license"
  echo "  -w  --enable-warp      Enable Cloudflare warp"
  echo "      --disable-warp     Disable Cloudflare warp"
  echo "  -c  --core             Select core (xray, singbox, default: ${defaults[core]})"
  echo "  -m  --menu             Show menu"
  echo "  -h, --help             Display this help message"
  return 1
}

function parse_args {
  local opts
  opts=$(getopt -o t:d:ruwsp:c:mh --long transport:,domain:,regenerate,default,restart,uninstall,path:,enable-safenet,disable-safenet,port:,enable-natvps,disable-natvps,warp-license:,enable-warp,disable-warp,core,menu,help -- "$@")
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  eval set -- "$opts"
  while true; do
    case $1 in
      -t|--transport)
        args[transport]="$2"
        case ${args[transport]} in
          tcp|h2|grpc)
            shift 2
            ;;
          *)
            echo "Invalid transport protocol: ${args[transport]}"
            return 1
            ;;
        esac
        ;;
      -d|--domain)
        args[domain]="$2"
        if ! [[ ${args[domain]} =~ $domain_regex ]]; then
          echo "Invalid domain: ${args[domain]}"
          return 1
        fi
        shift 2
        ;;
      --regenerate)
        args[regenerate]=true
        shift
        ;;
      --default)
        args[default]=true
        shift
        ;;
      -r|--restart)
        args[restart]=true
        shift
        ;;
      -u|--uninstall)
        args[uninstall]=true
        shift
        ;;
      -p|--path)
        args[path]="$2"
        if ! [[ ${args[path]} =~ $path_regex ]]; then
          echo "Use absolute path: ${args[path]}"
          return 1
        fi
        shift 2
        ;;
      -s|--enable-safenet)
        local enable_safenet=true
        shift
        ;;
      --disable-safenet)
        local disable_safenet=true
        shift
        ;;
      --port)
        args[port]="$2"
        if ! [[ ${args[port]} =~ $port_regex ]]; then
          echo "Invalid port number: ${args[port]}"
          return 1
        elif ((args[port] < 1 || args[port] > 65535)); then
          echo "Port number out of range: ${args[port]}"
          return 1
        fi
        shift 2
        ;;
      --enable-natvps)
        local enable_natvps=true
        shift
        ;;
      --disable-natvps)
        local disable_natvps=true
        shift
        ;;
      --warp-license)
        args[warp_license]="$2"
        if ! [[ ${args[warp_license]} =~ $warp_license_regex ]]; then
          echo "Invalid warp license: ${args[warp_license]}"
          return 1
        fi
        shift 2
        ;;
      -w|--enable-warp)
        local enable_warp=true
        shift
        ;;
      --disable-warp)
        local disable_warp=true
        shift
        ;;
      -c|--core)
        args[core]="$2"
        case ${args[core]} in
          xray|singbox)
            shift 2
            ;;
          *)
            echo "Invalid core: ${args[core]}"
            return 1
            ;;
        esac
        ;;
      -m|--menu)
        args[menu]=true
        shift
        ;;
      -h|--help)
        return 1
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Unknown option: $1"
        return 1
        ;;
    esac
  done

  if [[ -z ${args[path]} ]]; then
    args[path]="${default_path}"
  fi

  if [[ ${args[uninstall]} == true ]]; then
    uninstall
  fi

  if [[ -n ${args[warp_license]} ]] && [[ $disable_warp == true ]]; then
    echo "--warp-license cannot be used with --disable-warp"
    return 1
  fi

  if [[ $enable_warp == true ]] && [[ $disable_warp == true ]]; then
    echo "--enable-warp and --disable-warp cannot be used together"
    return 1
  fi

  if [[ -n ${args[warp_license]} ]]; then
    args[warp]=ON
  fi

  if [[ $enable_warp == true ]]; then
    args[warp]=ON
  fi

  if [[ $disable_warp == true ]]; then
    args[warp]=OFF
  fi

  if [[ $enable_natvps == true ]] && [[ $disable_natvps == true ]]; then
    echo "--enable-natvps and --disable-natvps cannot be used together"
    return 1
  fi

  if [[ $enable_natvps == true ]]; then
    args[natvps]=ON
  fi

  if [[ $disable_natvps == true ]]; then
    args[natvps]=OFF
  fi

  if [[ $enable_safenet == true ]] && [[ $disable_safenet == true ]]; then
    echo "--enable-safenet and --disable-safenet cannot be used together"
    return 1
  fi

  if [[ $enable_safenet == true ]]; then
    args[safenet]=ON
  fi

  if [[ $disable_safenet == true ]]; then
    args[safenet]=OFF
  fi
}

function dict_expander {
  local -n dict=$1
  for key in "${!dict[@]}"; do
    echo "${key} ${dict[$key]}"
  done
}

function parse_config_file {
  if [[ ! -r "${config_file_path}" ]]; then
    generate_keys
    return 0
  fi
  while read -r line; do
    if [[ "${line}" =~ ^\s*# ]] || [[ "${line}" =~ ^\s*$ ]]; then
      continue
    fi
    IFS="=" read -r key value <<< "${line}"
    config_file["${key}"]="${value}"
  done < "${config_file_path}"
  if [[ -z "${config_file[public_key]}" || \
        -z "${config_file[private_key]}" || \
        -z "${config_file[short_id]}" ]]; then
    generate_keys
  fi
  return 0
}

function parse_users_file {
  mkdir -p "$config_path"
  touch "${users_file_path}"
  while read -r line; do
    if [[ "${line}" =~ ^\s*# ]] || [[ "${line}" =~ ^\s*$ ]]; then
      continue
    fi
    IFS="=" read -r key value <<< "${line}"
    users["${key}"]="${value}"
  done < "${users_file_path}"
  if [[ ${#users[@]} -eq 0 ]]; then
    users['RealityEZPZ']=$(cat /proc/sys/kernel/random/uuid)
    echo "RealityEZPZ=${users['RealityEZPZ']}" >> "${users_file_path}"
    return 0
  fi
  return 0
}

function build_config {
  if [[ ${args[regenerate]} == true ]]; then
    generate_keys
  fi
  for item in "${config_items[@]}"; do
    if [[ -n ${args["${item}"]} ]]; then
      config["${item}"]="${args[${item}]}"
    elif [[ -n ${config_file["${item}"]} ]]; then
      config["${item}"]="${config_file[${item}]}"
    else
      config["${item}"]="${defaults[${item}]}"
    fi
  done
  if [[ ${args[default]} == true ]]; then
    local defaults_items=("${!defaults[@]}")
    for item in "${defaults_items[@]}"; do
      config["${item}"]="${defaults[${item}]}"
    done
    return 0
  fi
  config[server_ip]=$(ip route get 1.1.1.1 | grep -oP '(?<=src )(\d{1,3}\.){3}\d{1,3}')
  config[public_ip]=$(curl -fsSL --ipv4 http://ifconfig.io)
  if [[ ! ${config[server]} =~ $domain_regex ]]; then
    config[server]="${config[public_ip]}"
  fi
  if [[ "${config[natvps]}" == "ON" ]]; then
    natvps_check_port
  fi
  if [[ "${args[natvps]}" == "OFF" ]] && [[ -z ${args[port]} ]] && [[ "${config_file[natvps]}" == "ON" ]]; then
    config[port]="${defaults[port]}"
  fi
}

function update_config_file {
  mkdir -p "${config_path}"
  touch "${config_file_path}"
  for item in "${config_items[@]}"; do
    if grep -q "^${item}=" "${config_file_path}"; then
      sed -i "s/^${item}=.*/${item}=${config[${item}]}/" "${config_file_path}"
    else
      echo "${item}=${config[${item}]}" >> "${config_file_path}"
    fi
  done
}

function update_users_file {
  rm -f "${users_file_path}"
  for user in "${!users[@]}"; do
    echo "${user}=${users[${user}]}" >> "${users_file_path}"
  done
}

function natvps_check_port {
  local first_port
  local last_port
  first_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"01
  last_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"20
  if ((config[port] >= first_port && config[port] <= last_port)); then
    return 0
  fi
  for port in $(seq "${first_port}" "${last_port}"); do
    if ! lsof -i :"${port}" > /dev/null; then
      config[port]=$port
      return 0
    fi
  done
  echo "Error: Free port was not found."
  return 1
}

function generate_keys {
  local key_pair
  key_pair=$(sudo docker run --rm ${xray_image} xray x25519)
  config_file[public_key]=$(echo "${key_pair}"|grep -oP '(?<=Public key: ).*')
  config_file[private_key]=$(echo "${key_pair}"|grep -oP '(?<=Private key: ).*')
  config_file[short_id]=$(openssl rand -hex 8)
}

function uninstall {
  if docker compose > /dev/null 2>&1; then
    sudo docker compose --project-directory "${args[path]}" down || true
  elif which docker-compose > /dev/null 2>&1; then
    sudo docker-compose --project-directory "${args[path]}" down || true
  fi
  rm -rf "${args[path]}"
  exit 0
}

function install_packages {
  if ! which jq qrencode whiptail > /dev/null 2>&1; then
    if which apt > /dev/null 2>&1; then
      sudo apt update
      sudo apt install qrencode jq whiptail -y
      return 0
    fi
    if which yum > /dev/null 2>&1; then
      sudo yum makecache
      sudo yum install epel-release -y || true
      sudo yum install qrencode jq whiptail -y
      return 0
    fi
    echo "OS is not supported!"
    return 1
  fi
}

function install_docker {
  if ! which docker > /dev/null 2>&1; then
    curl -fsSL https://get.docker.com | sudo bash
    sudo systemctl enable --now docker
    docker_cmd="docker compose"
    return 0
  fi
  if docker compose > /dev/null 2>&1; then
    docker_cmd="docker compose"
    return 0
  fi
  if which docker-compose > /dev/null 2>&1; then
    docker_cmd="docker-compose"
    return 0
  fi
  sudo curl -SL https://github.com/docker/compose/releases/download/v2.17.2/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
  docker_cmd="docker-compose"
  return 0
}

function generate_docker_compose {
  cat >"${config_path}/docker-compose.yml" <<EOF
version: "3"
networks:
  reality:
    driver: bridge
    ipam:
      config:
      - subnet: 10.255.255.0/24
        gateway: 10.255.255.1
services:
$(if [[ ${config[core]} == xray ]]; then
echo "
  xray:
    image: ${xray_image}
    ports:
    $([[ ${config[port]} -eq 443 ]] && echo '- 80:8080' || true)
    - ${config[port]}:8443
    restart: always
    environment:
      TZ: Etc/UTC
    volumes:
    - ./xray.conf:/etc/xray/config.json
    networks:
    - reality"
fi
)
$(if [[ ${config[core]} == singbox ]]; then
echo "
  singbox:
    image: ${singbox_image}
    ports:
    $([[ ${config[port]} -eq 443 ]] && echo '- 80:8080' || true)
    - ${config[port]}:8443
    restart: always
    environment:
      TZ: Etc/UTC
    volumes:
    - ./singbox.conf:/etc/sing-box/config.json
    networks:
    - reality"
fi
)
$(if [[ ${config[warp]} == ON ]]; then
echo "
  warp:
    image: ${warp_image}
    expose:
    - 1080
    restart: always
    environment:
      FAMILIES_MODE: $([[ ${config[safenet]} == ON ]] && echo 'full' || echo 'off')
      WARP_LICENSE: ${config[warp_license]}
    volumes:
    - ./warp:/var/lib/cloudflare-warp
    networks:
      reality:
        ipv4_address: 10.255.255.10"
fi
)
EOF
}

function generate_xray_config {
  local users_object=""
  for user in "${!users[@]}"; do
    if [ -n "$users_object" ]; then
      users_object="${users_object},"
    fi
    users_object=${users_object}"{\"id\": \"${users[${user}]}\", \"flow\": \"$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)\", \"email\": \"${user}\"}"
  done
  cat >"${config_path}/xray.conf" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [$([[ ${config[safenet]} == ON ]] && echo '"tcp+local://1.1.1.3","tcp+local://1.0.0.3"' || echo '"tcp+local://1.1.1.1","tcp+local://1.0.0.1"')
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 8080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "${config[domain]}",
        "port": 80,
        "network": "tcp"
      }
    },
    {
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [${users_object}],
        "decryption": "none"
      },
      "streamSettings": {
        $([[ ${config[transport]} == 'grpc' ]] && echo '"grpcSettings": {"serviceName": "grpc"},' || true)
        "network": "${config[transport]}",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${config[domain]}:443",
          "xver": 0,
          "serverNames": [
            "${config[domain]}"
          ],
          "privateKey": "${config[private_key]}",
          "maxTimeDiff": 60000,
          "shortIds": [
            "${config[short_id]}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    $([[ ${config[warp]} == ON ]] && echo '{"protocol": "socks","settings": {"servers": [{"address": "10.255.255.10","port": 1080}]}},' || echo '{"protocol": "freedom"},')
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          $([[ ${config[warp]} == OFF ]] && echo '"geoip:cn", "geoip:ir",')
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10",
          "geoip:private"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "port": "25, 587, 465, 2525",
        "network": "tcp",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": [
          $([[ ${config[safenet]} == ON ]] && echo '"geosite:category-porn",' || true)
          "geosite:category-ads-all",
          "domain:pushnotificationws.com",
          "domain:sunlight-leds.com",
          "domain:icecyber.org"
        ]
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 120
      }
    }
  }
}
EOF
}

function generate_singbox_config {
  local users_object=""
  for user in "${!users[@]}"; do
    if [ -n "$users_object" ]; then
      users_object="${users_object},"
    fi
    users_object=${users_object}"{\"uuid\": \"${users[${user}]}\", \"flow\": \"$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)\", \"name\": \"${user}\"}"
  done
  cat >"${config_path}/singbox.conf" <<EOF
{
  "log": {
    "level": "warning",
    "timestamp": true
  },
  "dns": {
    "servers": [
    $([[ ${config[safenet]} == ON ]] && echo '{"address": "tcp://1.1.1.3", "detour": "dns"},{"address": "tcp://1.0.0.3", "detour": "dns"}' || echo '{"address": "tcp://1.1.1.1", "detour": "dns"},{"address": "tcp://1.0.0.1", "detour": "dns"}')
    ],
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "direct",
      "listen": "::",
      "listen_port": 8080,
      "network": "tcp",
      "override_address": "${config[domain]}",
      "override_port": 80
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": 8443,
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "ipv4_only",
      "users": [${users_object}],
      "tls": {
        "enabled": true,
        "server_name": "${config[domain]}",
        "alpn": [],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${config[domain]}",
            "server_port": 443
          },
          "private_key": "${config[private_key]}",
          "short_id": [
            "${config[short_id]}"
          ],
          "max_time_difference": "1m"
        }
      }
      $( if [[ ${config[transport]} == h2 ]]; then
      echo ',"transport": {"type": "http"}'
      fi
      if [[ ${config[transport]} == grpc ]]; then
      echo ',"transport": {"type": "grpc","service_name": "grpc"}'
      fi )
    }
  ],
  "outbounds": [
    $([[ ${config[warp]} == ON ]] && echo '{"type": "socks","server": "10.255.255.10", "server_port": 1080, "version": "5", "udp_over_tcp": {"enabled": true, "version": 2}},' || echo '{"type": "direct"},')
    {
      "type": "direct",
      "tag": "dns"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "geoip": [
          $([[ ${config[warp]} == OFF ]] && echo '"cn", "ir",')
          "private"
        ],
        "outbound": "block"
      },
      {
        "geosite": [
          $([[ ${config[safenet]} == ON ]] && echo '"category-porn",' || true)
          "category-ads-all"
        ],
        "outbound": "block"
      },
      {
        "ip_cidr": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outbound": "block"
      },
      {
        "network": "tcp",
        "port": [
          25,
          587,
          465,
          2525
        ],
        "outbound": "block"
      },
      {
        "domain": [
          "pushnotificationws.com",
          "sunlight-leds.com",
          "icecyber.org"
        ],
        "outbound": "block"
      }
    ]
  }
}
EOF
}

function print_client_configuration {
  local username=$1
  local client_config
  client_config="vless://${users[${username}]}@${config[server]}:${config[port]}?security=reality&encryption=none&alpn=h2,http/1.1&pbk=${config[public_key]}&headerType=none&fp=chrome&type=${config[transport]}&flow=$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)&sni=${config[domain]}&sid=${config[short_id]}$([[ ${config[transport]} == 'grpc' ]] && echo '&mode=gun&serviceName=grpc' || true)#${username}"
  echo ""
  echo "=================================================="
  echo "Client configuration:"
  echo ""
  echo "$client_config"
  echo ""
  echo "Or you can scan the QR code:"
  echo ""
  qrencode -t ansiutf8 "${client_config}"
}

function upgrade {
  local uuid
  uuid=$(grep '^uuid=' "${config_file_path}" 2> /dev/null | cut -d= -f2 || true)
  if [[ -n $uuid ]]; then
    sed -i '/^uuid=/d' "${users_file_path}"
    echo "RealityEZPZ=${uuid}" >> "${users_file_path}"
    sed -i 's/=true/=ON/g; s/=false/=OFF/g' "${users_file_path}"
  fi
}

function main_menu {
  local selection
  local exit_status
  while true; do
    selection=$(whiptail --clear --backtitle "$BACKTITLE" --title "Server Management" \
      --menu "$MENU" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      --ok-button "Select" \
      --cancel-button "Exit" \
      "1" "Add New User" \
      "2" "Delete User" \
      "3" "View User" \
      "4" "Restart Services" \
      "5" "Regenrate keys" \
      "6" "Configuration" \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ exit_status -ne 0 ]]; then
      break
    fi
    case $selection in
      1 )
        add_user_menu
        ;;
      2 )
        delete_user_menu
        ;;
      3 )
        view_user_menu
        ;;
      4 )
        restart_menu
        ;;
      5 )
        regenerate_menu
        ;;
      6 )
        configuration_menu
        ;;
    esac
  done
}

function add_user_menu {
  local username
  local exit_status
  local message
  while true; do
    username=$(whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "Add New User" \
      --inputbox "Enter username:" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ exit_status -ne 0 ]]; then
      break
    fi
    if [[ ! $username =~ $username_regex ]]; then
      message_box "Invalid Username" "Username can only contains A-Z, a-z and 0-9"
      continue
    fi
    if [[ -n ${users[$username]} ]]; then
      message_box "Invalid Username" "\"${username}\" already exists."
      continue
    fi
    users[$username]=$(cat /proc/sys/kernel/random/uuid)
    update_users_file
    whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "Add New User" \
      --yes-button "View User" \
      --no-button "Return" \
      --yesno "User \"${username}\" has been created." \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    exit_status=$?
    if [[ exit_status -ne 0 ]]; then
      break
    fi
    view_user_menu "${username}"
  done   
}

function delete_user_menu {
  local username
  local exit_status
  while true; do
    username=$(list_users_menu "Delete User")
    if [[ $? -ne 0 ]]; then
      return 0
    fi
    whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "Delete User" \
      --yesno "Are you sure you want to delete $username?" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    exit_status=$?
    if [[ exit_status -eq 0 ]]; then
      unset users["${username}"]
      update_users_file
      message_box "Delete User" "User \"${username}\" has been deleted."
    fi
  done
}

function view_user_menu {
  local username
  local exit_status
  while true; do
    if [[ $# -gt 0 ]]; then
      username=$1
    else
      username=$(list_users_menu "View User")
      if [[ $? -ne 0 ]]; then
        return 0
      fi
    fi
    whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "${username} details" \
      --yes-button "View QR" \
      --no-button "Return" \
      --yesno "
Remaks: ${username}
Address: ${config[server]}
Port: ${config[port]}
ID: ${users[$username]}
Flow: $([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision-udp443' || true)
Network: ${config[transport]}$([[ ${config[transport]} == 'grpc' ]] && echo "\ngRPC mode: multi\ngRPC serviceName: grpc" || true)
TLS: reality
SNI: ${config[domain]}
Fingerprint: chrome
PublicKey: ${config[public_key]}
ShortId: ${config[short_id]}" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    exit_status=$?
    if [[ exit_status -eq 0 ]]; then
      clear
      print_client_configuration "${username}"
      echo
      echo "Press Enter to return ..."
      read
    fi
  if [[ $# -gt 0 ]]; then
    return 0
  fi
  done
}

function list_users_menu {
  local title=$1
  local options
  local selection
  local exit_status
  options=$(dict_expander users)
  selection=$(whiptail --clear --noitem --backtitle "$BACKTITLE" --title "$title" \
    --menu "Select the user" $HEIGHT $WIDTH $CHOICE_HEIGHT $options \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ exit_status -ne 0 ]]; then
    return 1
  fi
  echo "${selection}"
}

function restart_menu {
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Restart Services" \
    --yesno "Are you sure to restart services?" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
  exit_status=$?
  if [[ exit_status -eq 0 ]]; then
    restart_docker_compose
  fi
}

function regenerate_menu {
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Regenrate keys" \
    --yesno "Are you sure to regenerate keys?" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
  exit_status=$?
  if [[ exit_status -eq 0 ]]; then
    generate_keys
    config[public_key]=${config_file[public_key]}
    config[private_key]=${config_file[private_key]}
    config[short_id]=${config_file[short_id]}
    update_config_file
    message_box "Regenerate keys" "All keys has been regenerated."
  fi
}

function configuration_menu {
  local selection
  local exit_status
  while true; do
    selection=$(whiptail --clear --backtitle "$BACKTITLE" --title "Configuration" \
      --menu "Select an option:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "1" "Core" \
      "2" "Server Address" \
      "3" "Transport" \
      "4" "SNI Domain" \
      "5" "Port" \
      "6" "Safe Internet" \
      "7" "WARP" \
      "8" "WARP+ License" \
      "9" "natvps" \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ exit_status -ne 0 ]]; then
      break
    fi
    case $selection in
      1 )
        config_core_menu
        ;;
      2 )
        config_server_menu
        ;;
      3 )
        config_transport_menu
        ;;
      4 )
        config_sni_domain_menu
        ;;
      5 )
        config_port_menu
        ;;
      6 )
        config_safenet_menu
        ;;
      7 )
        config_warp_menu
        ;;
      8 )
        config_warp_license_menu
        ;;
      9 )
        config_natvps_menu
        ;;
    esac
  done
}

function config_core_menu {
  local core
  local exit_status
  core=$(whiptail --clear --backtitle "$BACKTITLE" --title "Core" \
    --radiolist --noitem "Select a core engine:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "xray" "$([[ "${config[core]}" == 'xray' ]] && echo 'on' || echo 'off')" \
    "singbox" "$([[ "${config[core]}" == 'singbox' ]] && echo 'on' || echo 'off')" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ $exit_status -eq 0 ]]; then
    config[core]=$core
    update_config_file
  fi
}

function config_server_menu {
  local server
  local exit_status
  server=$(whiptail --clear --backtitle "$BACKTITLE" --title "Server Address" \
    --inputbox "Enter Server IP or Domain:" $HEIGHT $WIDTH "${config["server"]}" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ exit_status -eq 0 ]]; then
    config[server]="${server}"
    update_config_file 
  fi
}

function config_transport_menu {
  local transport
  local exit_status
  transport=$(whiptail --clear --backtitle "$BACKTITLE" --title "Transport" \
    --radiolist --noitem "Select a transport protocol:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "tcp" "$([[ "${config[transport]}" == 'tcp' ]] && echo 'on' || echo 'off')" \
    "h2" "$([[ "${config[transport]}" == 'h2' ]] && echo 'on' || echo 'off')" \
    "grpc" "$([[ "${config[transport]}" == 'grpc' ]] && echo 'on' || echo 'off')" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ $exit_status -eq 0 ]]; then
    config[transport]=$transport
    update_config_file
  fi
}

function config_sni_domain_menu {
  local sni_domain
  local exit_status
  while true; do
    sni_domain=$(whiptail --clear --backtitle "$BACKTITLE" --title "SNI Domain" \
      --inputbox "Enter SNI domain:" $HEIGHT $WIDTH "${config[domain]}" \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ $exit_status -ne 0 ]]; then
      break
    fi
    if [[ ! $sni_domain =~ $domain_regex ]]; then
      message_box "Invalid Domain" "\"${sni_domain}\" in not a valid domain."
      continue
    fi
    config[domain]=$sni_domain
    update_config_file
    break
  done
}

function config_port_menu {
  local port
  local exit_status
  while true; do
    port=$(whiptail --clear --backtitle "$BACKTITLE" --title "Port" \
      --inputbox "Enter port number:" $HEIGHT $WIDTH "${config[port]}" \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ $exit_status -ne 0 ]]; then
      break
    fi
    if [[ ! $port =~ $port_regex ]]; then
      message_box "Invalid Port" "Port must be an integer"
      continue
    fi
    if ((port < 1 || port > 65535)); then
      message_box "Invalid Port" "Port must be between 1 to 65535"
      continue
    fi
    if [[ ${config[natvps]} == ON ]]; then
      local first_port
      local last_port
      first_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"01
      last_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"20
      if ((port < first_port || port > last_port)); then
        message_box "Invalid Port" "natvps.net is enabled.\nThe port must be between ${first_port} and ${last_port}."
        continue
      fi
    fi
    config[port]=$port
    update_config_file
    break
  done
}

function config_safenet_menu {
  local safenet
  local exit_status
  safenet=$(whiptail --clear --backtitle "$BACKTITLE" --title "Safe Internet" \
    --checklist --notags "Enable Safe Internet:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "safenet" "Enable Safe Internet" "${config[safenet]}" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ $exit_status -eq 0 ]]; then
    config[safenet]=$([[ $safenet == '"safenet"' ]] && echo ON || echo OFF)
    update_config_file
  fi
}

function config_warp_menu {
  local warp
  local exit_status
  warp=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP" \
    --checklist --notags "Enable WARP:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "warp" "Enable WARP" "${config[warp]}" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ $exit_status -eq 0 ]]; then
    config[warp]=$([[ $warp == '"warp"' ]] && echo ON || echo OFF)
    if [[ ${config[warp]} == 'ON' ]]; then
      config_warp_license_menu
    fi
    update_config_file
  fi
}

function config_warp_license_menu {
  local warp_license
  local exit_status
  while true; do
    warp_license=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP+ License" \
      --inputbox "Enter WARP+ License:" $HEIGHT $WIDTH "${config[warp_license]}" \
      3>&1 1>&2 2>&3)
    exit_status=$?
    if [[ $exit_status -ne 0 ]]; then
      config[warp]=OFF
      update_config_file
      break
    fi
    if [[ ! $warp_license =~ $warp_license_regex ]]; then
      message_box "Invalid Input" "Invalid WARP+ License"
      continue
    fi
    config[warp_license]=$warp_license
    update_config_file
    break
  done
}

function config_natvps_menu {
  local natvps
  local exit_status
  natvps=$(whiptail --clear --backtitle "$BACKTITLE" --title "natvps.net" \
    --checklist --notags "natvps.net server:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "natvps" "natvps.net server" "${config[natvps]}" \
    3>&1 1>&2 2>&3)
  exit_status=$?
  if [[ $exit_status -eq 0 ]]; then
    config[natvps]=$([[ $natvps == '"natvps"' ]] && echo ON || echo OFF)
    natvps_check_port
    update_config_file
  fi
}

function restart_docker_compose {
  sudo ${docker_cmd} --project-directory ${config_path} down --remove-orphans || true
  sudo ${docker_cmd} --project-directory ${config_path} up -d --remove-orphans
}

function message_box {
  local title=$1
  local message=$2
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "$title" \
    --msgbox "$message" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
}

parse_args "$@" || show_help
config_path="${args[path]}"
config_file_path="${config_path}/config"
users_file_path="${config_path}/users"
install_packages
install_docker
upgrade
parse_config_file
parse_users_file
build_config
update_config_file
if [[ ${args[menu]} == 'true' ]]; then
  set +e
  main_menu
  set -e
fi
parse_users_file
old_compose_file_md5=$(md5sum "${config_path}/docker-compose.yml" 2> /dev/null | cut -f1 -d' ' || true)
old_xray_file_md5=$(md5sum "${config_path}/xray.conf" 2> /dev/null | cut -f1 -d' ' || true)
old_singbox_file_md5=$(md5sum "${config_path}/singbox.conf" 2> /dev/null | cut -f1 -d' ' || true)
generate_docker_compose
generate_xray_config
generate_singbox_config
new_compose_file_md5=$(md5sum "${config_path}/docker-compose.yml" 2> /dev/null | cut -f1 -d' ' || true)
new_xray_file_md5=$(md5sum "${config_path}/xray.conf" 2> /dev/null | cut -f1 -d' ' || true)
new_singbox_file_md5=$(md5sum "${config_path}/singbox.conf" 2> /dev/null | cut -f1 -d' ' || true)
if [[ "${args[restart]}" == "true" || \
      "${old_compose_file_md5}" != "${new_compose_file_md5}" || \
      "${old_xray_file_md5}" != "${new_xray_file_md5}" || \
      "${old_singbox_file_md5}" != "${new_singbox_file_md5}" ]]; then
  restart_docker_compose
fi
if [[ ${#users[@]} -eq 1 ]]; then
  print_client_configuration "${!users[@]}"
fi
exit 0
