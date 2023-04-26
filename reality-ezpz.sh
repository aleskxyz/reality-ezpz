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
declare -A file
declare -A args
declare -A config

default_path="${HOME}/reality"
xray_image="teddysun/xray:1.8.1"
warp_image="aleskxyz/warp-svc:1.2"

defaults[transport]=tcp
defaults[domain]=www.google.com
defaults[port]=443
defaults[safenet]=false
defaults[natvps]=false
defaults[warp]=false

config_items=(
  "uuid"
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

function show_help {
  echo ""
  echo "Usage: reality-ezpz.sh [-t|--transport=h2|grpc|tcp] [-d|--domain=<domain>] [-r|--regenerate] [--default] [-p|--path=<path>] [-s|--enable-safenet] [--disable-safenet] [--port=<port>] [--enable-natvps] [--disable-natvps] [--warp-license=<license>] [-w|--enable-warp] [--disable-warp] [-u|--uninstall]"
  echo "  -t, --transport        Transport protocol to use (default: ${defaults[transport]})"
  echo "  -d, --domain           Domain to use (default: ${defaults[domain]})"
  echo "  -r, --regenerate       Delete existing user and create new one"
  echo "      --default          Restore default configuration"
  echo "  -u, --uninstall        Uninstall reality"
  echo "  -p, --path             Absolute path to configuration directory (default: ${default_path})"
  echo "  -s  --enable-safenet   Enable blocking malware and adult content"
  echo "      --disable-safenet  Disable block malware and adult content"
  echo "      --port             Server port !!Do not change it!! (default: ${defaults[port]})"
  echo "      --enable-natvps    Enable natvps.net support"
  echo "      --disble-natvps    Disable natvps.net support"
  echo "      --warp-license     Add Cloudflare warp+ license"
  echo "  -w  --enable-warp      Enable Cloudflare warp"
  echo "      --disable-warp     Disable Cloudflare warp"
  echo "  -h, --help             Display this help message"
  return 1
}

function parse_args {
  local domain_regex="^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
  local path_regex="^/.*"
  local port_regex="^[0-9]+$"
  local warp_license_regex="^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}$"
  local opts
  opts=$(getopt -o t:d:ruwsp:h --long transport:,domain:,regenerate,default,uninstall,path:,enable-safenet,disable-safenet,port:,enable-natvps,disable-natvps,warp-license:,enable-warp,disable-warp,help -- "$@")
  if [ $? -ne 0 ]; then
    return 1
  fi
  eval set -- "$opts"
  while true; do
    case $1 in
      -t|--transport)
      args[transport]="$2"
      case ${args[transport]} in
        h2|grpc|tcp)
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
      -r|--regenerate)
      args[regenerate]=true
      shift
      ;;
      --default)
      args[default]=true
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
    args[warp]=true
  fi

  if [[ $enable_warp == true ]]; then
    args[warp]=true
  fi

  if [[ $disable_warp == true ]]; then
    args[warp]=false
  fi

  if [[ $enable_natvps == true ]] && [[ $disable_natvps == true ]]; then
    echo "--enable-natvps and --disable-natvps cannot be used together"
    return 1
  fi

  if [[ $enable_natvps == true ]]; then
    args[natvps]=true
  fi

  if [[ $disable_natvps == true ]]; then
    args[natvps]=false
  fi

  if [[ $enable_safenet == true ]] && [[ $disable_safenet == true ]]; then
    echo "--enable-safenet and --disable-safenet cannot be used together"
    return 1
  fi

  if [[ $enable_safenet == true ]]; then
    args[safenet]=true
  fi

  if [[ $disable_safenet == true ]]; then
    args[safenet]=false
  fi
}

function parse_config_file {
  if [[ ! -e "${config_file}" ]]; then
    generate_keys
    return 0
  fi
  source "${config_file}"
  if [[ -z $uuid || \
        -z $public_key || \
        -z $private_key || \
        -z $short_id ]]; then
    generate_keys
  fi
  for item in "${config_items[@]}"; do
    file["${item}"]="${!item}"
  done
}

function build_config {
  if [[ ${args[regenerate]} == true ]]; then
    generate_keys
  fi
  for item in "${config_items[@]}"; do
    if [[ -n ${args["${item}"]} ]]; then
      config["${item}"]="${args[${item}]}"
    elif [[ -n ${file["${item}"]} ]]; then
      config["${item}"]="${file[${item}]}"
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
  if [[ ${config[natvps]} == true ]]; then
    natvps_check_port
  fi
  if [[ ${args[natvps]} == false ]] && [[ -z ${args[port]} ]] && [[ ${file[natvps]} == true ]]; then
    config[port]="${defaults[port]}"
  fi
}

function update_config_file {
  mkdir -p "${config_path}"
  touch "${config_file}"
  for item in "${config_items[@]}"; do
    if grep -q "^${item}=" "${config_file}"; then
      sed -i "s/^${item}=.*/${item}=${config[${item}]}/" "${config_file}"
    else
      echo "${item}=${config[${item}]}" >> "${config_file}"
    fi
  done
}

function natvps_check_port {
  local first_port
  local last_port
  first_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"01
  last_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"20
  if ((config[port] >= first_port && config[port] <= last_port)); then
    if ! lsof -i :"${config[port]}" > /dev/null; then
      return 0
    fi
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
  args[uuid]=$(cat /proc/sys/kernel/random/uuid)
  args[public_key]=$(echo "${key_pair}"|grep -oP '(?<=Public key: ).*')
  args[private_key]=$(echo "${key_pair}"|grep -oP '(?<=Private key: ).*')
  args[short_id]=$(openssl rand -hex 8)
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
  if ! which jq qrencode > /dev/null 2>&1; then
    if which apt > /dev/null 2>&1; then
      sudo apt update
      sudo apt install qrencode jq -y
      return 0
    fi
    if which yum > /dev/null 2>&1; then
      sudo yum makecache
      sudo yum install epel-release -y || true
      sudo yum install qrencode jq -y
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
services:
  xray:
    image: ${xray_image}
    ports:
    $([[ ${config[port]} -eq 443 ]] && echo '- 80:8080' || true)
    - ${config[port]}:8443
    restart: always
    environment:
    - "TZ=Etc/UTC"
    volumes:
    - ./xray.conf:/etc/xray/config.json
$(if [[ ${config[warp]} == true ]]; then
echo "  warp:
    image: ${warp_image}
    expose:
    - 1080
    restart: always
    environment:
      FAMILIES_MODE: $([[ ${config[safenet]} == true ]] && echo 'full' || echo 'off')
      WARP_LICENSE: ${config[warp_license]}
    volumes:
    - ./warp:/var/lib/cloudflare-warp"
fi
)
EOF
}

function generate_xray_config {
cat >"${config_path}/xray.conf" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [$([[ ${config[safenet]} == true ]] && echo '"tcp+local://1.1.1.3","tcp+local://1.0.0.3"' || echo '"tcp+local://1.1.1.1","tcp+local://1.0.0.1"')
    $([[ ${config[warp]} == true ]] && echo ',{"address": "localhost","domains": ["full:warp"]}' || true)]
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
        "clients": [
          {
            "id": "${config[uuid]}",
            "flow": "$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)"
          }
        ],
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
    $([[ ${config[warp]} == true ]] && echo '{"protocol": "socks","settings": {"servers": [{"address": "warp","port": 1080}]}},' || echo '{"protocol": "freedom"},')
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
          $([[ ${config[warp]} == false ]] && echo '"geoip:cn", "geoip:ir",')
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
          $([[ ${config[safenet]} == true ]] && echo '"geosite:category-porn",' || true)
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

function print_client_configuration {
  client_config="vless://${config[uuid]}@${config[public_ip]}:${config[port]}?security=reality&encryption=none&alpn=h2,http/1.1&pbk=${config[public_key]}&headerType=none&fp=chrome&type=${config[transport]}&flow=$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision-udp443' || true)&sni=${config[domain]}&sid=${config[short_id]}$([[ ${config[transport]} == 'grpc' ]] && echo '&mode=multi&serviceName=grpc' || true)#RealityEZPZ"
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

parse_args "$@" || show_help
config_path="${args[path]}"
config_file="${config_path}/config"
install_packages
install_docker
parse_config_file
sudo ${docker_cmd} --project-directory ${config_path} down || true
build_config
update_config_file
generate_docker_compose
generate_xray_config
sudo ${docker_cmd} --project-directory ${config_path} up -d
print_client_configuration
exit 0
