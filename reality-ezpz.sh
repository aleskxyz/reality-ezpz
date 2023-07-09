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
declare -A path
declare -A service
declare -A md5
declare -A regex
declare -A image

config_path="/opt/reality-ezpz"
compose_project='reality-ezpz'
tgbot_project='tgbot'
BACKTITLE=RealityEZPZ
MENU="Select an option:"
HEIGHT=30
WIDTH=60
CHOICE_HEIGHT=20

image[xray]="teddysun/xray:1.8.3"
image[sing-box]="gzxhwq/sing-box:v1.3.0"
image[nginx]="nginx:1.24.0"
image[certbot]="certbot/certbot:v2.6.0"
image[haproxy]="haproxy:2.8.0"
image[python]="python:3.11-alpine"

defaults[transport]=tcp
defaults[domain]=www.google.com
defaults[port]=443
defaults[safenet]=OFF
defaults[warp]=OFF
defaults[warp_license]=""
defaults[warp_private_key]=""
defaults[warp_token]=""
defaults[warp_id]=""
defaults[warp_client_id]=""
defaults[warp_interface_ipv4]=""
defaults[warp_interface_ipv6]=""
defaults[core]=sing-box
defaults[security]=reality
defaults[server]=$(curl -fsSL --ipv4 https://ifconfig.io)
defaults[tgbot]=OFF
defaults[tgbot_token]=""
defaults[tgbot_admins]=""

config_items=(
  "core"
  "security"
  "service_path"
  "public_key"
  "private_key"
  "short_id"
  "transport"
  "domain"
  "server"
  "port"
  "safenet"
  "warp"
  "warp_license"
  "warp_private_key"
  "warp_token"
  "warp_id"
  "warp_client_id"
  "warp_interface_ipv4"
  "warp_interface_ipv6"
  "tgbot"
  "tgbot_token"
  "tgbot_admins"
)

regex[domain]="^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
regex[port]="^[1-9][0-9]*$"
regex[warp_license]="^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}$"
regex[username]="^[a-zA-Z0-9]+$"
regex[ip]="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
regex[tgbot_token]="^[0-9]{8,10}:[a-zA-Z0-9_-]{35}$"
regex[tgbot_admins]="^[a-zA-Z][a-zA-Z0-9_]{4,31}(,[a-zA-Z][a-zA-Z0-9_]{4,31})*$"

function show_help {
  echo ""
  echo "Usage: reality-ezpz.sh [-t|--transport=tcp|http|grpc|ws] [-d|--domain=<domain>] [--server=<server>] [--regenerate] [--default]
  [-r|--restart] [--enable-safenet=true|false] [--port=<port>] [-c|--core=xray|sing-box]
  [--enable-warp=true|false] [--warp-license=<license>] [--security=reality|letsencrypt|selfsigned] [-m|--menu] [--show-server-config] 
  [--add-user=<username>] [--lists-users] [--show-user=<username>] [--delete-user=<username>] [-u|--uninstall]"
  echo ""
  echo "  -t, --transport <tcp|http|grpc|ws> Transport protocol (ws, http, grpc, ws, default: ${defaults[transport]})"
  echo "  -d, --domain <domain>     Domain to use as SNI (default: ${defaults[domain]})"
  echo "      --server <server>     IP address or domain name of server (Must be a valid domain if using letsencrypt security)"
  echo "      --regenerate          Regenerate public and private keys"
  echo "      --default             Restore default configuration"
  echo "  -r  --restart             Restart services"
  echo "  -u, --uninstall           Uninstall reality"
  echo "      --enable-safenet <true|false> Enable or disable safenet (blocking malware and adult content)"
  echo "      --port <port>         Server port (default: ${defaults[port]})"
  echo "      --enable-warp <true|false> Enable or disable Cloudflare warp"
  echo "      --warp-license <warp-license> Add Cloudflare warp+ license"
  echo "  -c  --core <sing-box|xray> Select core (xray, sing-box, default: ${defaults[core]})"
  echo "      --security <reality|letsencrypt|selfsigned> Select type of TLS encryption (reality, letsencrypt, selfsigned, default: ${defaults[security]})" 
  echo "  -m  --menu                Show menu"
  echo "      --enable-tgbot <true|false> Enable Telegram bot for user management"
  echo "      --tgbot-token <token> Token of Telegram bot"
  echo "      --tgbot-admins <telegram-username> Usernames of telegram bot admins (Comma separated list of usernames without leading '@')"
  echo "      --show-server-config  Print server configuration"
  echo "      --add-user <username> Add new user"
  echo "      --list-users          List all users"
  echo "      --show-user <username> Shows the config and QR code of the user"
  echo "      --delete-user <username> Delete the user"
  echo "  -h, --help                Display this help message"
  return 1
}

function parse_args {
  local opts
  opts=$(getopt -o t:d:ruc:mh --long transport:,domain:,server:,regenerate,default,restart,uninstall,enable-safenet:,port:,warp-license:,enable-warp:,core:,security:,menu,show-server-config,add-user:,list-users,show-user:,delete-user:,enable-tgbot:,tgbot-token:,tgbot-admins:,help -- "$@")
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  eval set -- "$opts"
  while true; do
    case $1 in
      -t|--transport)
        args[transport]="$2"
        case ${args[transport]} in
          tcp|http|grpc|ws)
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
        if ! [[ ${args[domain]} =~ ${regex[domain]} ]]; then
          echo "Invalid domain: ${args[domain]}"
          return 1
        fi
        shift 2
        ;;
      --server)
        args[server]="$2"
        if ! [[ ${args[server]} =~ ${regex[domain]} || ${args[server]} =~ ${regex[ip]} ]]; then
          echo "Invalid server: ${args[domain]}"
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
      --enable-safenet)
        case "$2" in
          true|false)
            $2 && args[safenet]=ON || args[safenet]=OFF
            shift 2
            ;;
          *)
            echo "Invalid safenet option: $2"
            return 1
            ;;
        esac
        ;;
      --enable-warp)
        case "$2" in
          true|false)
            $2 && args[warp]=ON || args[warp]=OFF
            shift 2
            ;;
          *)
            echo "Invalid warp option: $2"
            return 1
            ;;
        esac
        ;;
      --port)
        args[port]="$2"
        if ! [[ ${args[port]} =~ ${regex[port]} ]]; then
          echo "Invalid port number: ${args[port]}"
          return 1
        elif ((args[port] < 1 || args[port] > 65535)); then
          echo "Port number out of range: ${args[port]}"
          return 1
        fi
        shift 2
        ;;
      --warp-license)
        args[warp_license]="$2"
        if ! [[ ${args[warp_license]} =~ ${regex[warp_license]} ]]; then
          echo "Invalid warp license: ${args[warp_license]}"
          return 1
        fi
        shift 2
        ;;
      -c|--core)
        args[core]="$2"
        case ${args[core]} in
          xray|sing-box)
            shift 2
            ;;
          *)
            echo "Invalid core: ${args[core]}"
            return 1
            ;;
        esac
        ;;
      --security)
        args[security]="$2"
        case ${args[security]} in
          reality|letsencrypt|selfsigned)
            shift 2
            ;;
          *)
            echo "Invalid TLS security option: ${args[security]}"
            return 1
            ;;
        esac
        ;;
      -m|--menu)
        args[menu]=true
        shift
        ;;
      --enable-tgbot)
        case "$2" in
          true|false)
            $2 && args[tgbot]=ON || args[tgbot]=OFF
            shift 2
            ;;
          *)
            echo "Invalid enable-tgbot option: $2"
            return 1
            ;;
        esac
        ;;
      --tgbot-token)
        args[tgbot_token]="$2"
        if [[ ! ${args[tgbot_token]} =~ ${regex[tgbot_token]} ]]; then
          echo "Invalid Telegram Bot Token: ${args[tgbot_token]}"
          return 1
        fi 
        if ! curl -sSfL "https://api.telegram.org/bot${args[tgbot_token]}/getMe" >/dev/null 2>&1; then
          echo "Invalid Telegram Bot Token: Telegram Bot Token is incorrect. Check it again."
          return 1
        fi
        shift 2
        ;;
      --tgbot-admins)
        args[tgbot_admins]="$2"
        if [[ ! ${args[tgbot_admins]} =~ ${regex[tgbot_admins]} || $tgbot_admins =~ .+_$ || $tgbot_admins =~ .+_,.+ ]]; then
          echo "Invalid Telegram Bot Admins Username: ${args[tgbot_admins]}\nThe usernames must separated by ',' without leading '@' character or any extra space."
         return 1
        fi
        shift 2
        ;;
      --show-server-config)
        args[server-config]=true
        shift
        ;;
      --add-user)
        args[add_user]="$2"
        if ! [[ ${args[add_user]} =~ ${regex[username]} ]]; then
          echo "Invalid username: ${args[add_user]}\nUsername can only contains A-Z, a-z and 0-9"
          return 1
        fi
        shift 2
        ;;
      --list-users)
        args[list_users]=true
        shift
        ;;
      --show-user)
        args[show_config]="$2"
        shift 2
        ;;
      --delete-user)
        args[delete_user]="$2"
        shift 2
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

  if [[ ${args[uninstall]} == true ]]; then
    uninstall
  fi

  if [[ -n ${args[warp_license]} ]]; then
    args[warp]=ON
  fi

}

function dict_expander {
  local -n dict=$1
  for key in "${!dict[@]}"; do
    echo "${key} ${dict[$key]}"
  done
}

function parse_config_file {
  if [[ ! -r "${path[config]}" ]]; then
    generate_keys
    return 0
  fi
  while IFS= read -r line; do
    if [[ "${line}" =~ ^\s*# ]] || [[ "${line}" =~ ^\s*$ ]]; then
      continue
    fi
    key=$(echo "$line" | cut -d "=" -f 1)
    value=$(echo "$line" | cut -d "=" -f 2-)
    config_file["${key}"]="${value}"
  done < "${path[config]}"
  if [[ -z "${config_file[public_key]}" || \
        -z "${config_file[private_key]}" || \
        -z "${config_file[short_id]}" || \
        -z "${config_file[service_path]}" ]]; then
    generate_keys
  fi
  return 0
}

function parse_users_file {
  mkdir -p "$config_path"
  touch "${path[users]}"
  while read -r line; do
    if [[ "${line}" =~ ^\s*# ]] || [[ "${line}" =~ ^\s*$ ]]; then
      continue
    fi
    IFS="=" read -r key value <<< "${line}"
    users["${key}"]="${value}"
  done < "${path[users]}"
  if [[ -n ${args[add_user]} ]]; then
    if [[ -z "${users["${args[add_user]}"]}" ]]; then
      users["${args[add_user]}"]=$(cat /proc/sys/kernel/random/uuid)
    else
      echo 'User "'"${args[add_user]}"'" already exists.'
    fi
  fi
  if [[ -n ${args[delete_user]} ]]; then
    if [[ -n "${users["${args[delete_user]}"]}" ]]; then
      if [[ ${#users[@]} -eq 1 ]]; then
        echo -e "You cannot delete the only user.\nAt least one user is needed.\nCreate a new user, then delete this one."
        exit 1
      fi
      unset users["${args[delete_user]}"]
    else
      echo "User "${args[delete_user]}" does not exists."
      exit 1
    fi
  fi
  if [[ ${#users[@]} -eq 0 ]]; then
    users[RealityEZPZ]=$(cat /proc/sys/kernel/random/uuid)
    echo "RealityEZPZ=${users[RealityEZPZ]}" >> "${path[users]}"
    return 0
  fi
  return 0
}

function restore_defaults {
  local defaults_items=("${!defaults[@]}")
  local keep=false
  local exclude_list=(
    "warp_license"
    "tgbot_token"
  )
  if [[ -n ${config[warp_id]} && -n ${config[warp_token]} ]]; then
    warp_delete_account "${config[warp_id]}" "${config[warp_token]}"
  fi
  for item in "${defaults_items[@]}"; do
    keep=false
    for i in "${exclude_list[@]}"; do
      if [[ "${i}" == "${item}" ]]; then
        keep=true
        break
      fi
    done
    if [[ ${keep} == true ]]; then
      continue
    fi
    config["${item}"]="${defaults[${item}]}"
  done
}

function build_config {
  local free_80=true
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
    restore_defaults
    return 0
  fi
  if [[ ${config[tgbot]} == 'ON' && -z ${config[tgbot_token]} ]]; then
    echo 'To enable Telegram bot, you have to give the token of bot with --tgbot-token option.'
    exit 1
  fi
  if [[ ${config[tgbot]} == 'ON' && -z ${config[tgbot_admins]} ]]; then
    echo 'To enable Telegram bot, you have to give the list of authorized Telegram admins username with --tgbot-admins option.'
    exit 1
  fi
  if [[ ${config[warp]} == 'ON' && -z ${config[warp_license]} ]]; then
    echo 'To enable WARP+, you have to give WARP+ license with --warp-license option.'
    exit 1
  fi
  if [[ ! ${config[server]} =~ ${regex[domain]} && ${config[security]} == 'letsencrypt' ]]; then
    echo 'You have to assign a domain to server with "--server <domain>" option if you want to use "letsencrypt" as TLS certifcate.'
    exit 1
  fi
  if [[ ${config[transport]} == 'ws' && ${config[security]} == 'reality' ]]; then
    echo 'You cannot use "ws" transport with "reality" TLS certificate. Use other transports or change TLS certifcate to letsencrypt or selfsigned'
    exit 1
  fi
  if [[ ${config[security]} == 'letsencrypt' && ${config[port]} -ne 443 ]]; then
    if lsof -i :80 >/dev/null 2>&1; then
      free_80=false
      for container in $(${docker_cmd} -p ${compose_project} ps -q); do
        if docker port "${container}"| grep '0.0.0.0:80' >/dev/null 2>&1; then
          free_80=true
          break
        fi
      done
    fi
    if [[ ${free_80} != 'true' ]]; then
      echo 'Port 80 must be free if you want to use "letsencrypt" as the security option.'
      exit 1
    fi
  fi
  if [[ -n "${args[security]}" && "${args[security]}" == 'reality' && "${config_file[security]}" != 'reality' ]]; then
    config[domain]="${defaults[domain]}"
  fi
  if [[ -n "${args[security]}" && "${args[security]}" != 'reality' && "${config_file[security]}" == 'reality' ]]; then
    config[domain]="${config[server]}"
  fi
  if [[ -n "${args[server]}" && "${config[security]}" != 'reality' ]]; then
    config[domain]="${config[server]}"
  fi
  if [[ -n "${args[warp]}" && "${args[warp]}" == 'OFF' && "${config_file[warp]}" == 'ON' ]]; then
    if [[ -n ${config[warp_id]} && -n ${config[warp_token]} ]]; then
      warp_delete_account "${config[warp_id]}" "${config[warp_token]}"
    fi
  fi
  if { [[ -n "${args[warp]}" && "${args[warp]}" == 'ON' && "${config_file[warp]}" == 'OFF' ]] || \
       [[ "${config[warp]}" == 'ON' && ( -z ${config[warp_private_key]} || \
                                         -z ${config[warp_token]} || \
                                         -z ${config[warp_id]} || \
                                         -z ${config[warp_client_id]} || \
                                         -z ${config[warp_interface_ipv4]} || \
                                         -z ${config[warp_interface_ipv6]} ) ]]; }; then
    config[warp]='OFF'
    warp_create_account || exit 1
    warp_add_license "${config[warp_id]}" "${config[warp_token]}" "${config[warp_license]}" || exit 1
    config[warp]='ON'
  fi
  if [[ -n ${args[warp_license]} && -n ${config_file[warp_license]} && "${args[warp_license]}" != "${config_file[warp_license]}" ]]; then
    if ! warp_add_license "${config[warp_id]}" "${config[warp_token]}" "${args[warp_license]}"; then
      config[warp]='OFF'
      config[warp_license]=""
      warp_delete_account "${config[warp_id]}" "${config[warp_token]}"
      echo "WARP has been disabled due to the license error."
    fi 
  fi
}

function update_config_file {
  mkdir -p "${config_path}"
  touch "${path[config]}"
  for item in "${config_items[@]}"; do
    if grep -q "^${item}=" "${path[config]}"; then
      sed -i "s|^${item}=.*|${item}=${config[${item}]}|" "${path[config]}"
    else
      echo "${item}=${config[${item}]}" >> "${path[config]}"
    fi
  done
  check_reload
}

function update_users_file {
  rm -f "${path[users]}"
  for user in "${!users[@]}"; do
    echo "${user}=${users[${user}]}" >> "${path[users]}"
  done
  check_reload
}

function generate_keys {
  local key_pair
  key_pair=$(docker run --rm ${image[xray]} xray x25519)
  config_file[public_key]=$(echo "${key_pair}" | grep 'Public key:' | awk '{print $3}')
  config_file[private_key]=$(echo "${key_pair}" | grep 'Private key:' | awk '{print $3}')
  config_file[short_id]=$(openssl rand -hex 8)
  config_file[service_path]=$(openssl rand -hex 4)
}

function uninstall {
  if docker compose >/dev/null 2>&1; then
    docker compose --project-directory "${config_path}" down --timeout 2 || true
    docker compose --project-directory "${config_path}" -p ${compose_project} down --timeout 2 || true
    docker compose --project-directory "${config_path}/tgbot" -p ${tgbot_project} down --timeout 2 || true
  elif which docker-compose >/dev/null 2>&1; then
    docker-compose --project-directory "${config_path}" down --timeout 2 || true
    docker-compose --project-directory "${config_path}" -p ${compose_project} down --timeout 2 || true
    docker-compose --project-directory "${config_path}/tgbot" -p ${tgbot_project} down --timeout 2 || true
  fi
  rm -rf "${config_path}"
  exit 0
}

function install_packages {
  if ! which qrencode whiptail jq >/dev/null 2>&1; then
    if which apt >/dev/null 2>&1; then
      apt update
      apt install qrencode whiptail jq -y
      return 0
    fi
    if which yum >/dev/null 2>&1; then
      yum makecache
      yum install epel-release -y || true
      yum install qrencode newt jq -y
      return 0
    fi
    echo "OS is not supported!"
    return 1
  fi
}

function install_docker {
  if ! which docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | bash
    systemctl enable --now docker
    docker_cmd="docker compose"
    return 0
  fi
  if docker compose >/dev/null 2>&1; then
    docker_cmd="docker compose"
    return 0
  fi
  if which docker-compose >/dev/null 2>&1; then
    docker_cmd="docker-compose"
    return 0
  fi
  curl -fsSL https://github.com/docker/compose/releases/download/v2.17.2/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  docker_cmd="docker-compose"
  return 0
}

function generate_docker_compose {
  cat >"${path[compose]}" <<EOF
version: "3"
networks:
  reality:
    driver: bridge
    ipam:
      config:
      - subnet: 10.255.255.0/24
        gateway: 10.255.255.1
services:
  engine:
    image: ${image[${config[core]}]}
    $([[ ${config[security]} == 'reality' ]] && echo "ports:" || true)
    $([[ ${config[security]} == 'reality' && ${config[port]} -eq 443 ]] && echo '- 80:8080' || true)
    $([[ ${config[security]} == 'reality' ]] && echo "- ${config[port]}:8443" || true)
    $([[ ${config[security]} != 'reality' ]] && echo "expose:" || true)
    $([[ ${config[security]} != 'reality' ]] && echo "- 8443" || true)
    restart: always
    environment:
      TZ: Etc/UTC
    volumes:
    - ./${path[engine]#${config_path}/}:/etc/${config[core]}/config.json
    $([[ ${config[security]} != 'reality' ]] && { [[ ${config[transport]} == 'http' ]] || [[ ${config[transport]} == 'tcp' ]]; } && echo "- ./${path[server_crt]#${config_path}/}:/etc/${config[core]}/server.crt" || true)
    $([[ ${config[security]} != 'reality' ]] && { [[ ${config[transport]} == 'http' ]] || [[ ${config[transport]} == 'tcp' ]]; } && echo "- ./${path[server_key]#${config_path}/}:/etc/${config[core]}/server.key" || true)
    networks:
    - reality
$(if [[ ${config[security]} != 'reality' ]]; then
echo "
  nginx:
    image: ${image[nginx]}
    expose:
    - 80
    restart: always
    networks:
    - reality
  haproxy:
    image: ${image[haproxy]}
    ports:
    $([[ ${config[security]} == 'letsencrypt' || ${config[port]} -eq 443 ]] && echo '- 80:80' || true)
    - ${config[port]}:443
    restart: always
    volumes:
    - ./${path[haproxy]#${config_path}/}:/usr/local/etc/haproxy/haproxy.cfg
    - ./${path[server_pem]#${config_path}/}:/usr/local/etc/haproxy/server.pem
    networks:
    - reality"
fi)
$(if [[ ${config[security]} == 'letsencrypt' ]]; then
echo "
  certbot:
    build:
      context: ./certbot
    expose:
    - 80
    restart: always
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./certbot/data:/etc/letsencrypt
    - ./$(dirname "${path[server_pem]#${config_path}/}"):/certificate
    - ./${path[certbot_deployhook]#${config_path}/}:/deployhook.sh
    - ./${path[certbot_startup]#${config_path}/}:/startup.sh
    networks:
    - reality
    entrypoint: /bin/sh
    command: /startup.sh"
fi)
EOF
}

function generate_tgbot_compose {
  cat >"${path[tgbot_compose]}" <<EOF
version: "3"
services:
  tgbot:
    build: ./
    restart: always
    environment:
      BOT_TOKEN: ${config[tgbot_token]}
      BOT_ADMIN: ${config[tgbot_admins]}
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ../:/opt/reality-ezpz
EOF
}

function generate_haproxy_config {
  cat >"${path[haproxy]}" << EOF
global
  ssl-default-bind-options ssl-min-ver TLSv1.2
defaults
  retries 3
  option http-server-close
  timeout connect 5s
  timeout client 5s
  timeout client-fin 1s
  timeout server-fin 1s
  timeout server 5s
  timeout tunnel 300s
  timeout http-keep-alive 1s
  timeout http-request 5s
  timeout queue 15s
  timeout tarpit 5s
frontend http
  mode http
  bind :80
  $([[ ${config[security]} == 'letsencrypt' ]] && echo 'use_backend certbot if { path_beg /.well-known/acme-challenge }' || true)
  $([[ ${config[security]} == 'letsencrypt' ]] && echo 'acl letsencrypt-acl path_beg /.well-known/acme-challenge' || true)
  $([[ ${config[security]} == 'letsencrypt' ]] && echo 'redirect scheme https if !letsencrypt-acl' || true)
  use_backend default
frontend tls
  bind :443 $([[ ${config[transport]} != 'tcp' ]] && echo 'ssl crt /usr/local/etc/haproxy/server.pem alpn h2,http/1.1' || true)
  mode $([[ ${config[transport]} != 'tcp' ]] && echo 'http' || echo 'tcp')
  $([[ ${config[transport]} != 'tcp' ]] && echo "http-request set-header Host ${config[server]}" || true)
  $([[ ${config[security]} == 'letsencrypt' && ${config[transport]} != 'tcp' ]] && echo 'use_backend certbot if { path_beg /.well-known/acme-challenge }' || true)
  use_backend engine $([[ ${config[transport]} != 'tcp' ]] && echo "if { path_beg /${config[service_path]} }" || true)
  $([[ ${config[transport]} != 'tcp' ]] && echo 'use_backend default' || true)
backend engine
  retry-on conn-failure empty-response response-timeout
  mode $([[ ${config[transport]} != 'tcp' ]] && echo 'http' || echo 'tcp')
  server engine engine:8443 check tfo $([[ ${config[transport]} == 'grpc' ]] && echo 'proto h2' || true) $([[ ${config[transport]} == 'http' ]] && echo 'ssl verify none' "$([[ ${config[core]} == sing-box ]] && echo 'proto h2' || true)" || true)
$([[ ${config[security]} == 'letsencrypt' ]] && echo 'backend certbot' || true)
$([[ ${config[security]} == 'letsencrypt' ]] && echo '  mode http' || true)
$([[ ${config[security]} == 'letsencrypt' ]] && echo '  server certbot certbot:80' || true)
backend default
  mode http
  server nginx nginx:80
EOF
}

function generate_certbot_script {
  cat >"${path[certbot_startup]}" << EOF
#!/bin/sh
trap exit TERM
fullchain_path=/etc/letsencrypt/live/${config[server]}/fullchain.pem
if [[ -r "\${fullchain_path}" ]]; then
  fullchain_fingerprint=\$(openssl x509 -noout -fingerprint -sha256 -in "\${fullchain_path}" 2>/dev/null |\
awk -F= '{print \$2}' | tr -d : | tr '[:upper:]' '[:lower:]')
  installed_fingerprint=\$(openssl x509 -noout -fingerprint -sha256 -in /certificate/server.pem 2>/dev/null |\
awk -F= '{print \$2}' | tr -d : | tr '[:upper:]' '[:lower:]')
  if [[ \$fullchain_fingerprint != \$installed_fingerprint ]]; then
    /deployhook.sh /certificate ${compose_project} ${config[server]} ${service[server_crt]} $([[ ${config[transport]} != 'tcp' ]] && echo "${service[server_pem]}" || true)
  fi
fi
while true; do
  response=\$(curl -skL --max-time 3 http://${config[server]})
  if echo "\$response" | grep 'Welcome to nginx!' >/dev/null; then
    break
  fi
  echo "Domain ${config[server]} is not pointing to the server"
  sleep 5
done
while true; do
  certbot certonly -n \\
    --standalone \\
    --key-type ecdsa \\
    --elliptic-curve secp256r1 \\
    --agree-tos \\
    --register-unsafely-without-email \\
    -d ${config[server]} \\
    --deploy-hook "/deployhook.sh /certificate ${compose_project} ${config[server]} ${service[server_crt]} $([[ ${config[transport]} != 'tcp' ]] && echo "${service[server_pem]}" || true)"
  sleep 1h &
  wait \${!}
done
EOF
}

function generate_certbot_deployhook {
  cat >"${path[certbot_deployhook]}" << EOF
#!/bin/sh
cert_path=\$1
compose_project=\$2
domain=\$3
renewed_path=/etc/letsencrypt/live/\$domain
cat "\$renewed_path/fullchain.pem" > "\$cert_path/server.crt"
cat "\$renewed_path/privkey.pem" > "\$cert_path/server.key"
cat "\$renewed_path/fullchain.pem" "\$renewed_path/privkey.pem" > "\$cert_path/server.pem"
i=4
while [ \$i -le \$# ]; do
  eval service=\\\${\$i}
  docker compose -p "${compose_project}" restart --timeout 2 "\$service"
  i=\$((i+1))
done
EOF
  chmod +x "${path[certbot_deployhook]}"
}

function generate_certbot_dockerfile {
  cat >"${path[certbot_dockerfile]}" << EOF
FROM ${image[certbot]}
RUN apk add --no-cache docker-cli-compose curl
EOF
}

function generate_tgbot_dockerfile {
  cat >"${path[tgbot_dockerfile]}" << EOF
FROM ${image[python]}
WORKDIR /opt/reality-ezpz/tgbot
RUN apk add --no-cache docker-cli-compose curl bash newt libqrencode sudo openssl jq
RUN pip install --no-cache-dir python-telegram-bot==13.5
CMD [ "python", "./tgbot.py" ]
EOF
}

function download_tgbot_script {
  curl -fsSL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/tgbot.py -o "${path[tgbot_script]}"
}

function generate_selfsigned_certificate {
  openssl ecparam -name prime256v1 -genkey -out "${path[server_key]}"
  openssl req -new -key "${path[server_key]}" -out /tmp/server.csr -subj "/CN=${config[server]}"
  openssl x509 -req -days 365 -in /tmp/server.csr -signkey "${path[server_key]}" -out "${path[server_crt]}"
  cat "${path[server_key]}" "${path[server_crt]}" > "${path[server_pem]}"
  rm -f /tmp/server.csr
}

function generate_engine_config {
  local users_object=""
  local reality_object=""
  local tls_object=""
  local warp_object=""
  if [[ ${config[core]} == 'sing-box' ]]; then
    reality_object='"tls": {
      "enabled": true,
      "server_name": "'"${config[domain]}"'",
      "alpn": [],
      "reality": {
        "enabled": true,
        "handshake": {
          "server": "'"${config[domain]}"'",
          "server_port": 443
        },
        "private_key": "'"${config[private_key]}"'",
        "short_id": ["'"${config[short_id]}"'"],
        "max_time_difference": "1m"
      }
    }'
    tls_object='"tls": {
      "enabled": true,
      "certificate_path": "/etc/sing-box/server.crt",
      "key_path": "/etc/sing-box/server.key"
    }'
    if [[ ${config[warp]} == 'ON' ]]; then
      warp_object='{
        "type": "wireguard",
        "server": "engage.cloudflareclient.com",
        "server_port": 2408,
        "system_interface": false,
        "local_address": [
          "'"${config[warp_interface_ipv4]}"'/32",
          "'"${config[warp_interface_ipv6]}"'/128"
        ],
        "private_key": "'"${config[warp_private_key]}"'",
        "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "reserved": '"$(warp_decode_reserved "${config[warp_client_id]}")"',
        "mtu": 1280
      },'
    fi
    for user in "${!users[@]}"; do
      if [ -n "$users_object" ]; then
        users_object="${users_object},"$'\n'
      fi
      users_object=${users_object}'{"uuid": "'"${users[${user}]}"'", "flow": "'"$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)"'", "name": "'"${user}"'"}'
    done
    cat >"${path[engine]}" <<EOF
{
  "log": {
    "level": "error",
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
      $(if [[ ${config[security]} == 'reality' ]]; then
        echo "${reality_object}"
      elif [[ ${config[transport]} == 'http' || ${config[transport]} == 'tcp' ]]; then
        echo "${tls_object}"
      else
        echo '"tls":{"enabled": false}'
      fi)
      $( if [[ ${config[transport]} == http ]]; then
      echo ',"transport": {"type": "http", "host": ["'"${config[server]}"'"], "path": "/'"${config[service_path]}"'"}'
      fi
      if [[ ${config[transport]} == grpc ]]; then
      echo ',"transport": {"type": "grpc","service_name": "'"${config[service_path]}"'"}'
      fi 
      if [[ ${config[transport]} == ws ]]; then
      echo ',"transport": {"type": "ws", "headers": {"Host": "'"${config[server]}"'"}, "path": "/'"${config[service_path]}"'"}'
      fi
      )
    }
  ],
  "outbounds": [
    $([[ ${config[warp]} == ON ]] && echo "${warp_object}" || echo '{"type": "direct"},')
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
  fi
  if [[ ${config[core]} == 'xray' ]]; then
    reality_object='"security":"reality",
    "realitySettings":{
      "show": false,
      "dest": "'"${config[domain]}"':443",
      "xver": 0,
      "serverNames": ["'"${config[domain]}"'"],
      "privateKey": "'"${config[private_key]}"'",
      "maxTimeDiff": 60000,
      "shortIds": ["'"${config[short_id]}"'"]
    }'
    tls_object='"security": "tls",
    "tlsSettings": {
      "certificates": [{
        "oneTimeLoading": true,
        "certificateFile": "/etc/xray/server.crt",
        "keyFile": "/etc/xray/server.key"
      }]
    }'
    if [[ ${config[warp]} == 'ON' ]]; then
      warp_object='{
        "protocol": "wireguard",
        "settings": {
          "secretKey": "'"${config[warp_private_key]}"'",
          "address": [
            "'"${config[warp_interface_ipv4]}"'/32",
            "'"${config[warp_interface_ipv6]}"'/128"
          ],
          "peers": [
            {
              "endpoint": "engage.cloudflareclient.com:2408",
              "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            }
          ],
          "mtu": 1280
        }
      },'
    fi
    for user in "${!users[@]}"; do
      if [ -n "$users_object" ]; then
        users_object="${users_object},"$'\n'
      fi
      users_object=${users_object}'{"id": "'"${users[${user}]}"'", "flow": "'"$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)"'", "email": "'"${user}"'"}'
    done
    cat >"${path[engine]}" <<EOF
{
  "log": {
    "loglevel": "error"
  },
  "dns": {
    "servers": [$([[ ${config[safenet]} == ON ]] && echo '"tcp+local://1.1.1.3","tcp+local://1.0.0.3"' || echo '"tcp+local://1.1.1.1","tcp+local://1.0.0.1"')]
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
        $([[ ${config[transport]} == 'grpc' ]] && echo '"grpcSettings": {"serviceName": "'"${config[service_path]}"'"},' || true)
        $([[ ${config[transport]} == 'ws' ]] && echo '"wsSettings": {"headers": {"Host": "'"${config[server]}"'"}, "path": "/'"${config[service_path]}"'"},' || true)
        $([[ ${config[transport]} == 'http' ]] && echo '"httpSettings": {"host":["'"${config[server]}"'"], "path": "/'"${config[service_path]}"'"},' || true)
        "network": "${config[transport]}",
        $(if [[ ${config[security]} == 'reality' ]]; then
          echo "${reality_object}"
        elif [[ ${config[transport]} == 'http' || ${config[transport]} == 'tcp' ]]; then
          echo "${tls_object}"
        else
          echo '"security":"none"'
        fi)
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
    $([[ ${config[warp]} == ON ]] && echo "${warp_object}" || echo '{"protocol": "freedom"},')
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
  fi
}

function generate_config {
  generate_docker_compose
  generate_engine_config
  if [[ ${config[security]} != "reality" ]]; then
    mkdir -p "${config_path}/certificate"
    generate_haproxy_config
    if [[ ! -r "${path[server_pem]}" || ! -r "${path[server_crt]}" || ! -r "${path[server_key]}" ]]; then
      generate_selfsigned_certificate
    fi
  fi
  if [[ ${config[security]} == "letsencrypt" ]]; then
    mkdir -p "${config_path}/certbot"
    generate_certbot_deployhook
    generate_certbot_dockerfile
    generate_certbot_script
  fi
  if [[ ${config[tgbot]} == "ON" ]]; then
    mkdir -p "${config_path}/tgbot"
    generate_tgbot_compose
    generate_tgbot_dockerfile
    download_tgbot_script
  fi
}

function print_client_configuration {
  local username=$1
  local client_config
  client_config="vless://"
  client_config="${client_config}${users[${username}]}"
  client_config="${client_config}@${config[server]}"
  client_config="${client_config}:${config[port]}"
  client_config="${client_config}?security=$([[ ${config[security]} == 'reality' ]] && echo reality || echo tls)"
  client_config="${client_config}&encryption=none"
  client_config="${client_config}&alpn=$([[ ${config[transport]} == 'ws' ]] && echo 'http/1.1' || echo 'h2,http/1.1')"
  client_config="${client_config}&headerType=none"
  client_config="${client_config}&fp=chrome"
  client_config="${client_config}&type=${config[transport]}"
  client_config="${client_config}&flow=$([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)"
  client_config="${client_config}&sni=${config[domain]}"
  client_config="${client_config}$([[ ${config[transport]} == 'ws' || ${config[transport]} == 'http' ]] && echo "&host=${config[server]}" || true)"
  client_config="${client_config}$([[ ${config[security]} == 'reality' ]] && echo "&pbk=${config[public_key]}" || true)"
  client_config="${client_config}$([[ ${config[security]} == 'reality' ]] && echo "&sid=${config[short_id]}" || true)"
  client_config="${client_config}$([[ ${config[transport]} == 'ws' || ${config[transport]} == 'http' ]] && echo "&path=%2F${config[service_path]}" || true)"
  client_config="${client_config}$([[ ${config[transport]} == 'grpc' ]] && echo '&mode=gun' || true)"
  client_config="${client_config}$([[ ${config[transport]} == 'grpc' ]] && echo "&serviceName=${config[service_path]}" || true)"
  client_config="${client_config}#${username}"
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
  local warp_token
  local warp_id
  if [[ -e "${HOME}/reality/config" ]]; then
    ${docker_cmd} --project-directory "${HOME}/reality" down --remove-orphans --timeout 2
    mv -f "${HOME}/reality" /opt/reality-ezpz
  fi
  uuid=$(grep '^uuid=' "${path[config]}" 2>/dev/null | cut -d= -f2 || true)
  if [[ -n $uuid ]]; then
    sed -i '/^uuid=/d' "${path[users]}"
    echo "RealityEZPZ=${uuid}" >> "${path[users]}"
    sed -i 's|=true|=ON|g; s|=false|=OFF|g' "${path[users]}"
  fi
  rm -f "${config_path}/xray.conf"
  rm -f "${config_path}/singbox.conf"
  if ! ${docker_cmd} ls | grep ${compose_project} >/dev/null && [[ -r ${path[compose]} ]]; then
    ${docker_cmd} --project-directory ${config_path} down --remove-orphans --timeout 2
  fi
  if [[ -r ${path[config]} ]]; then
    sed -i 's|transport=h2|transport=http|g' "${path[config]}"
    sed -i 's|core=singbox|core=sing-box|g' "${path[config]}"
    sed -i 's|security=tls-invalid|security=selfsigned|g' "${path[config]}"
    sed -i 's|security=tls-valid|security=letsencrypt|g' "${path[config]}"
  fi
  for key in "${!path[@]}"; do
    if [[ -d "${path[$key]}" ]]; then
      rm -rf "${path[$key]}"
    fi
  done
  if [[ -d "${config_path}/warp" ]]; then
    ${docker_cmd} --project-directory ${config_path} -p ${compose_project} down --remove-orphans --timeout 2 || true
    warp_token=$(cat ${config_path}/warp/reg.json | jq -r '.api_token')
    warp_id=$(cat ${config_path}/warp/reg.json | jq -r '.registration_id')
    warp_api "DELETE" "/reg/${warp_id}" "" "${warp_token}" >/dev/null 2>&1 || true
    rm -rf "${config_path}/warp"
  fi
}

function main_menu {
  local selection
  while true; do
    selection=$(whiptail --clear --backtitle "$BACKTITLE" --title "Server Management" \
      --menu "$MENU" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      --ok-button "Select" \
      --cancel-button "Exit" \
      "1" "Add New User" \
      "2" "Delete User" \
      "3" "View User" \
      "4" "View Server Config" \
      "5" "Configuration" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
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
        view_config_menu
        ;;
      5 )
        configuration_menu
        ;;
    esac
  done
}

function add_user_menu {
  local username
  local message
  while true; do
    username=$(whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "Add New User" \
      --inputbox "Enter username:" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! $username =~ ${regex[username]} ]]; then
      message_box "Invalid Username" "Username can only contains A-Z, a-z and 0-9"
      continue
    fi
    if [[ -n ${users[$username]} ]]; then
      message_box "Invalid Username" '"'"${username}"'" already exists.'
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
      --yesno 'User "'"${username}"'" has been created.' \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    if [[ $? -ne 0 ]]; then
      break
    fi
    view_user_menu "${username}"
  done   
}

function delete_user_menu {
  local username
  while true; do
    username=$(list_users_menu "Delete User")
    if [[ $? -ne 0 ]]; then
      return 0
    fi
    if [[ ${#users[@]} -eq 1 ]]; then
      message_box "Delete User" "You cannot delete the only user.\nAt least one user is needed.\nCreate a new user, then delete this one."
      continue
    fi
    whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "Delete User" \
      --yesno "Are you sure you want to delete $username?" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    if [[ $? -ne 0 ]]; then
      continue
    fi
    unset users["${username}"]
    update_users_file
    message_box "Delete User" 'User "'"${username}"'" has been deleted.'
  done
}

function view_user_menu {
  local username
  local user_config
  while true; do
    if [[ $# -gt 0 ]]; then
      username=$1
    else
      username=$(list_users_menu "View User")
      if [[ $? -ne 0 ]]; then
        return 0
      fi
    fi
    user_config=$(echo "
Remaks: ${username}
Address: ${config[server]}
Port: ${config[port]}
ID: ${users[$username]}
Flow: $([[ ${config[transport]} == 'tcp' ]] && echo 'xtls-rprx-vision' || true)
Network: ${config[transport]}
$([[ ${config[transport]} == 'ws' || ${config[transport]} == 'http' ]] && echo "Host Header: ${config[server]}" || true)
$([[ ${config[transport]} == 'ws' || ${config[transport]} == 'http' ]] && echo "Path: /${config[service_path]}" || true)
$([[ ${config[transport]} == 'grpc' ]] && echo 'gRPC mode: gun' || true)
$([[ ${config[transport]} == 'grpc' ]] && echo 'gRPC serviceName: '"${config[service_path]}" || true)
TLS: $([[ ${config[security]} == 'reality' ]] && echo 'reality' || echo 'tls')
SNI: ${config[domain]}
ALPN: $([[ ${config[transport]} == 'ws' ]] && echo 'http/1.1' || echo 'h2,http/1.1')
Fingerprint: chrome
$([[ ${config[security]} == 'reality' ]] && echo "PublicKey: ${config[public_key]}" || true)
$([[ ${config[security]} == 'reality' ]] && echo "ShortId: ${config[short_id]}" || true)
    " | tr -s '\n')
    whiptail \
      --clear \
      --backtitle "$BACKTITLE" \
      --title "${username} details" \
      --yes-button "View QR" \
      --no-button "Return" \
      --yesno "${user_config}" \
      $HEIGHT $WIDTH \
      3>&1 1>&2 2>&3
    if [[ $? -eq 0 ]]; then
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
  options=$(dict_expander users)
  selection=$(whiptail --clear --noitem --backtitle "$BACKTITLE" --title "$title" \
    --menu "Select the user" $HEIGHT $WIDTH $CHOICE_HEIGHT $options \
    3>&1 1>&2 2>&3)
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  echo "${selection}"
}

function show_server_config {
  local server_config
  server_config="Core: ${config[core]}"
  server_config=$server_config$'\n'"Server Address: ${config[server]}"
  server_config=$server_config$'\n'"Domain SNI: ${config[domain]}"
  server_config=$server_config$'\n'"Port: ${config[port]}"
  server_config=$server_config$'\n'"Transport: ${config[transport]}"
  server_config=$server_config$'\n'"Security: ${config[security]}"
  server_config=$server_config$'\n'"Safenet: ${config[safenet]}"
  server_config=$server_config$'\n'"WARP: ${config[warp]}"
  server_config=$server_config$'\n'"WARP License: ${config[warp_license]}"
  server_config=$server_config$'\n'"Telegram Bot: ${config[tgbot]}"
  server_config=$server_config$'\n'"Telegram Bot Token: ${config[tgbot_token]}"
  server_config=$server_config$'\n'"Telegram Bot Admins: ${config[tgbot_admins]}"
  echo "${server_config}"
}

function view_config_menu {
  local server_config
  server_config=$(show_server_config)
  message_box "Server Configuration" "${server_config}"
}

function restart_menu {
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Restart Services" \
    --yesno "Are you sure to restart services?" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
  if [[ $? -ne 0 ]]; then
    return
  fi
  restart_docker_compose
  if [[ ${config[tgbot]} == 'ON' ]]; then
    restart_tgbot_compose
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
  if [[ $? -ne 0 ]]; then
    return
  fi
  generate_keys
  config[public_key]=${config_file[public_key]}
  config[private_key]=${config_file[private_key]}
  config[short_id]=${config_file[short_id]}
  update_config_file
  message_box "Regenerate keys" "All keys has been regenerated."
}

function restore_defaults_menu {
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Restore Default Config" \
    --yesno "Are you sure to restore default configuration?" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
  if [[ $? -ne 0 ]]; then
    return
  fi
  restore_defaults
  update_config_file
  message_box "Restore Default Config" "All configurations has been restored to their defaults."
}

function configuration_menu {
  local selection
  while true; do
    selection=$(whiptail --clear --backtitle "$BACKTITLE" --title "Configuration" \
      --menu "Select an option:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "1" "Core" \
      "2" "Server Address" \
      "3" "Transport" \
      "4" "SNI Domain" \
      "5" "Security" \
      "6" "Port" \
      "7" "Safe Internet" \
      "8" "WARP" \
      "9" "Telegram Bot" \
      "10" "Restart Services" \
      "11" "Regenerate Keys" \
      "12" "Restore Defaults" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
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
        config_security_menu
        ;;
      6 )
        config_port_menu
        ;;
      7 )
        config_safenet_menu
        ;;
      8 )
        config_warp_menu
        ;;
      9 )
        config_tgbot_menu
        ;;
      10 )
        restart_menu
        ;;
      11 )
        regenerate_menu
        ;;
      12 )
        restore_defaults_menu
        ;;
    esac
  done
}

function config_core_menu {
  local core
  core=$(whiptail --clear --backtitle "$BACKTITLE" --title "Core" \
    --radiolist --noitem "Select a core engine:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "xray" "$([[ "${config[core]}" == 'xray' ]] && echo 'on' || echo 'off')" \
    "sing-box" "$([[ "${config[core]}" == 'sing-box' ]] && echo 'on' || echo 'off')" \
    3>&1 1>&2 2>&3)
  if [[ $? -ne 0 ]]; then
    return
  fi
  config[core]=$core
  update_config_file
}

function config_server_menu {
  local server
  while true; do
    server=$(whiptail --clear --backtitle "$BACKTITLE" --title "Server Address" \
      --inputbox "Enter Server IP or Domain:" $HEIGHT $WIDTH "${config["server"]}" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! ${server} =~ ${regex[domain]} && ${config[security]} == 'letsencrypt' ]]; then
      message_box 'Invalid Configuration' 'You have to assign a valid domain to server if you want to use "letsencrypt" certificate.'
      continue
    fi
    if [[ -z ${server} ]]; then
      server="${defaults[server]}"
    fi
    config[server]="${server}"
    if [[ ${config[security]} != 'reality' ]]; then
      config[domain]="${server}"
    fi
    update_config_file
    break
  done
}

function config_transport_menu {
  local transport
  while true; do
    transport=$(whiptail --clear --backtitle "$BACKTITLE" --title "Transport" \
      --radiolist --noitem "Select a transport protocol:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "tcp" "$([[ "${config[transport]}" == 'tcp' ]] && echo 'on' || echo 'off')" \
      "http" "$([[ "${config[transport]}" == 'http' ]] && echo 'on' || echo 'off')" \
      "grpc" "$([[ "${config[transport]}" == 'grpc' ]] && echo 'on' || echo 'off')" \
      "ws" "$([[ "${config[transport]}" == 'ws' ]] && echo 'on' || echo 'off')" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ${transport} == 'ws' && ${config[security]} == 'reality' ]]; then
      message_box 'Invalid Configuration' 'You cannot use "ws" transport with "reality" TLS certificate. Use other transports or change TLS certifcate to "letsencrypt" or "selfsigned"'
      continue
    fi
    config[transport]=$transport
    update_config_file
    break
  done
}

function config_sni_domain_menu {
  local sni_domain
  while true; do
    sni_domain=$(whiptail --clear --backtitle "$BACKTITLE" --title "SNI Domain" \
      --inputbox "Enter SNI domain:" $HEIGHT $WIDTH "${config[domain]}" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! $sni_domain =~ ${regex[domain]} ]]; then
      message_box "Invalid Domain" '"'"${sni_domain}"'" in not a valid domain.'
      continue
    fi
    config[domain]=$sni_domain
    update_config_file
    break
  done
}

function config_security_menu {
  local security
  local free_80=true
  while true; do
    security=$(whiptail --clear --backtitle "$BACKTITLE" --title "Security Type" \
      --radiolist --noitem "Select a security type:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "reality" "$([[ "${config[security]}" == 'reality' ]] && echo 'on' || echo 'off')" \
      "letsencrypt" "$([[ "${config[security]}" == 'letsencrypt' ]] && echo 'on' || echo 'off')" \
      "selfsigned" "$([[ "${config[security]}" == 'selfsigned' ]] && echo 'on' || echo 'off')" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! ${config[server]} =~ ${regex[domain]} && ${security} == 'letsencrypt' ]]; then
      message_box 'Invalid Configuration' 'You have to assign a valid domain to server if you want to use "letsencrypt" as security type'
      continue
    fi
    if [[ ${config[transport]} == 'ws' && ${security} == 'reality' ]]; then
      message_box 'Invalid Configuration' 'You cannot use "reality" TLS certificate with "ws" transport protocol. Change TLS certifcate to "letsencrypt" or "selfsigned" or use other transport protocols'
      continue
    fi
    if [[ ${security} == 'letsencrypt' && ${config[port]} -ne 443 ]]; then
      if lsof -i :80 >/dev/null 2>&1; then
        free_80=false
        for container in $(${docker_cmd} -p ${compose_project} ps -q); do
          if docker port "${container}" | grep '0.0.0.0:80' >/dev/null 2>&1; then
            free_80=true
            break
          fi
        done
      fi
      if [[ ${free_80} != 'true' ]]; then
        message_box 'Port 80 must be free if you want to use "letsencrypt" as the security option.'
        continue
      fi
    fi
    if [[ ${security} != 'reality' ]]; then
      config[domain]="${config[server]}"
    fi
    if [[ ${security} == 'reality' ]]; then
      config[domain]="${defaults[domain]}"
    fi
    config[security]="${security}"
    update_config_file
    break
  done
}

function config_port_menu {
  local port
  while true; do
    port=$(whiptail --clear --backtitle "$BACKTITLE" --title "Port" \
      --inputbox "Enter port number:" $HEIGHT $WIDTH "${config[port]}" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! $port =~ ${regex[port]} ]]; then
      message_box "Invalid Port" "Port must be an integer"
      continue
    fi
    if ((port < 1 || port > 65535)); then
      message_box "Invalid Port" "Port must be between 1 to 65535"
      continue
    fi
    config[port]=$port
    update_config_file
    break
  done
}

function config_safenet_menu {
  local safenet
  safenet=$(whiptail --clear --backtitle "$BACKTITLE" --title "Safe Internet" \
    --radiolist --noitem "Enable blocking malware and adult content" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "Enable" "$([[ "${config[safenet]}" == 'ON' ]] && echo 'on' || echo 'off')" \
    "Disable" "$([[ "${config[safenet]}" == 'OFF' ]] && echo 'on' || echo 'off')" \
    3>&1 1>&2 2>&3)
  if [[ $? -ne 0 ]]; then
    return
  fi
  config[safenet]=$([[ $safenet == 'Enable' ]] && echo ON || echo OFF)
  update_config_file
}

function config_warp_menu {
  local warp
  local warp_license
  local error
  local temp_file
  local exit_code
  local old_warp=${config[warp]}
  local old_warp_license=${config[warp_license]}
  while true; do
    warp=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP" \
      --radiolist --noitem "Enable WARP:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "Enable" "$([[ "${config[warp]}" == 'ON' ]] && echo 'on' || echo 'off')" \
      "Disable" "$([[ "${config[warp]}" == 'OFF' ]] && echo 'on' || echo 'off')" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ $warp == 'Disable' ]]; then
      config[warp]=OFF
      if [[ -n ${config[warp_id]} && -n ${config[warp_token]} ]]; then
        warp_delete_account "${config[warp_id]}" "${config[warp_token]}"
      fi
      return
    fi
    if [[ -z ${config[warp_private_key]} || \
          -z ${config[warp_token]} || \
          -z ${config[warp_id]} || \
          -z ${config[warp_client_id]} || \
          -z ${config[warp_interface_ipv4]} || \
          -z ${config[warp_interface_ipv6]} ]]; then
      temp_file=$(mktemp)
      warp_create_account > "${temp_file}"
      exit_code=$?
      error=$(< "${temp_file}")
      rm -f "${temp_file}"
      if [[ ${exit_code} -ne 0 ]]; then
        message_box "WARP account creation error" "${error}"
        continue
      fi
    fi
    config[warp]=ON
    while true; do
      warp_license=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP+ License" \
        --inputbox "Enter WARP+ License:" $HEIGHT $WIDTH "${config[warp_license]}" \
        3>&1 1>&2 2>&3)
      if [[ $? -ne 0 ]]; then
        break
      fi
      if [[ ! $warp_license =~ ${regex[warp_license]} ]]; then
        message_box "Invalid Input" "Invalid WARP+ License"
        continue
      fi
      temp_file=$(mktemp)
      warp_add_license "${config[warp_id]}" "${config[warp_token]}" "${warp_license}" > "${temp_file}"
      exit_code=$?
      error=$(< "${temp_file}")
      rm -f "${temp_file}"
      if [[ ${exit_code} -ne 0 ]]; then
        message_box "WARP license error" "${error}"
        continue
      fi
      return
    done
  done
  config[warp]=$old_warp
  config[warp_license]=$old_warp_license
}

function config_tgbot_menu {
  local tgbot
  local tgbot_token
  local tgbot_admins
  local old_tgbot=${config[tgbot]}
  local old_tgbot_token=${config[tgbot_token]}
  local old_tgbot_admins=${config[tgbot_admins]}
  while true; do
    tgbot=$(whiptail --clear --backtitle "$BACKTITLE" --title "Enable Telegram Bot" \
      --radiolist --noitem "Enable Telegram Bot:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "Enable" "$([[ "${config[tgbot]}" == 'ON' ]] && echo 'on' || echo 'off')" \
      "Disable" "$([[ "${config[tgbot]}" == 'OFF' ]] && echo 'on' || echo 'off')" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ $tgbot == 'Disable' ]]; then
      config[tgbot]=OFF
      update_config_file
      return
    fi
    config[tgbot]=ON
    while true; do
      tgbot_token=$(whiptail --clear --backtitle "$BACKTITLE" --title "Telegram Bot Token" \
        --inputbox "Enter Telegram Bot Token:" $HEIGHT $WIDTH "${config[tgbot_token]}" \
        3>&1 1>&2 2>&3)
      if [[ $? -ne 0 ]]; then
        break
      fi
      if [[ ! $tgbot_token =~ ${regex[tgbot_token]} ]]; then
        message_box "Invalid Input" "Invalid Telegram Bot Token"
        continue
      fi 
      if ! curl -sSfL "https://api.telegram.org/bot${tgbot_token}/getMe" >/dev/null 2>&1; then
        message_box "Invalid Input" "Telegram Bot Token is incorrect. Check it again."
        continue
      fi
      config[tgbot_token]=$tgbot_token
      while true; do
        tgbot_admins=$(whiptail --clear --backtitle "$BACKTITLE" --title "Telegram Bot Admins" \
          --inputbox "Enter Telegram Bot Admins (Seperate multiple admins by comma ',' without leading '@'):" $HEIGHT $WIDTH "${config[tgbot_admins]}" \
          3>&1 1>&2 2>&3)
        if [[ $? -ne 0 ]]; then
          break
        fi
        if [[ ! $tgbot_admins =~ ${regex[tgbot_admins]} || $tgbot_admins =~ .+_$ || $tgbot_admins =~ .+_,.+ ]]; then
          message_box "Invalid Input" "Invalid Username\nThe usernames must separated by ',' without leading '@' character or any extra space."
          continue
        fi
        config[tgbot_admins]=$tgbot_admins
        update_config_file
        return
      done
    done
  done
  config[tgbot]=$old_tgbot
  config[tgbot_token]=$old_tgbot_token
  config[tgbot_admins]=$old_tgbot_admins
}

function restart_docker_compose {
  ${docker_cmd} --project-directory ${config_path} -p ${compose_project} down --remove-orphans --timeout 2 || true
  ${docker_cmd} --project-directory ${config_path} -p ${compose_project} up --build -d --remove-orphans --build
}

function restart_tgbot_compose {
  ${docker_cmd} --project-directory ${config_path}/tgbot -p ${tgbot_project} down --remove-orphans --timeout 2 || true
  ${docker_cmd} --project-directory ${config_path}/tgbot -p ${tgbot_project} up --build -d --remove-orphans --build
}

function restart_container {
  if [[ -z "$(${docker_cmd} ls | grep "${path[compose]}" | grep running || true)" ]]; then
    restart_docker_compose
    return
  fi
  if ${docker_cmd} --project-directory ${config_path} -p ${compose_project} ps --services "$1" | grep "$1"; then
    ${docker_cmd} --project-directory ${config_path} -p ${compose_project} restart --timeout 2 "$1"
  fi
}

function warp_api {
  local verb=$1
  local resource=$2
  local data=$3
  local token=$4
  local team_token=$5
  local endpoint=https://api.cloudflareclient.com/v0a2158
  local temp_file
  local error
  local command
  local headers=(
    "User-Agent: okhttp/3.12.1"
    "CF-Client-Version: a-6.10-2158"
    "Content-Type: application/json"
  )
  temp_file=$(mktemp)
  if [[ -n ${token} ]]; then
    headers+=("Authorization: Bearer ${token}")
  fi
  if [[ -n ${team_token} ]]; then
    headers+=("Cf-Access-Jwt-Assertion: ${team_token}")
  fi
  command="curl -sLX ${verb} -w '%{http_code}' -o ${temp_file} ${endpoint}${resource}"
  for header in "${headers[@]}"; do
    command+=" -H '${header}'"
  done
  if [[ -n ${data} ]]; then
    command+=" -d '${data}'"
  fi
  response_code=$(( $(eval "${command}" || true) ))
  response_body=$(cat "${temp_file}")
  rm -f "${temp_file}"
  if [[ response_code -eq 0 ]]; then
    return 1
  fi
  if [[ response_code -gt 399 ]]; then
    error=$(echo "${response_body}" | jq -r '.errors[0].message' 2> /dev/null || true)
    if [[ ${error} != 'null' ]]; then
      echo "${error}"
    fi
    return 2
  fi
  echo "${response_body}"
}

function warp_create_account {
  local key_pair
  local public_key
  local private_key
  local install_id
  local fcm_token
  local tos
  local data
  local response
  local error
  key_pair=$(curl -fsSL https://wg.cloudflare.now.cc)
  public_key=$(echo "${key_pair}" | grep 'PublicKey' | awk '{print $2}')
  private_key=$(echo "${key_pair}" | grep 'PrivateKey' | awk '{print $2}')
  install_id=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 22)
  fcm_token="${install_id}:APA91b$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 134)"
  tos=$(date +"%Y-%m-%dT%H:%M:%S.000Z")
  data='{
    "key":"'${public_key}'",
    "install_id":"'${install_id}'",
    "fcm_token":"'${fcm_token}'",
    "tos":"'${tos}'",
    "model":"PC",
    "serial_number":"'${install_id}'",
    "locale":"en_US"
  }'
  response=$(warp_api "POST" "/reg" "${data}")
  if [[ $? -ne 0 ]]; then
    if [[ -n ${response} ]]; then
      echo "${response}"
    fi
    return 1
  fi
  config[warp_private_key]="${private_key}"
  config[warp_token]=$(echo "${response}" | jq -r '.token')
  config[warp_id]=$(echo "${response}" | jq -r '.id')
  config[warp_client_id]=$(echo "${response}" | jq -r '.config.client_id')
  config[warp_interface_ipv4]=$(echo "${response}" | jq -r '.config.interface.addresses.v4')
  config[warp_interface_ipv6]=$(echo "${response}" | jq -r '.config.interface.addresses.v6')
  update_config_file
}

function warp_add_license {
  local id=$1
  local token=$2
  local license=$3
  local data
  local response
  data='{"license": "'$license'"}'
  response=$(warp_api "PUT" "/reg/${id}/account" "${data}" "${token}")
  if [[ $? -ne 0 ]]; then
    if [[ -n ${response} ]]; then
      echo "${response}"
    fi
    return 1
  fi
  config[warp_license]=${license}
  update_config_file
}

function warp_delete_account {
  local id=$1
  local token=$2
  warp_api "DELETE" "/reg/${id}" "" "${token}" >/dev/null 2>&1 || true
  config[warp_private_key]=""
  config[warp_token]=""
  config[warp_id]=""
  config[warp_client_id]=""
  config[warp_interface_ipv4]=""
  config[warp_interface_ipv6]=""
  update_config_file
}

function warp_decode_reserved {
  client_id=$1
  reserved=$(echo "${client_id}" | base64 -d | xxd -p | fold -w2 | while read HEX; do printf '%d ' "0x${HEX}"; done | awk '{print "["$1", "$2", "$3"]"}')
  echo "${reserved}"
}

function check_reload {
  declare -A restart
  generate_config
  for key in "${!path[@]}"; do
    if [[ "${md5["$key"]}" != $(get_md5 "${path[$key]}") ]]; then
      restart["${service["$key"]}"]='true'
      md5["$key"]=$(get_md5 "${path[$key]}")
    fi
  done
  if [[ "${restart[tgbot]}" == 'true' && "${config[tgbot]}" == 'ON' ]]; then
    restart_tgbot_compose
  fi
  if [[ "${config[tgbot]}" == 'OFF' ]]; then
    ${docker_cmd} --project-directory ${config_path}/tgbot -p ${tgbot_project} down --remove-orphans --timeout 2 >/dev/null 2>&1 || true
  fi
  if [[ "${restart[compose]}" == 'true' ]]; then
    restart_docker_compose
    return
  fi
  for key in "${!restart[@]}"; do
    if [[ $key != 'none' && $key != 'tgbot' ]]; then
      restart_container "${key}"
    fi
  done
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

function get_md5 {
  local file_path
  file_path=$1
  md5sum "${file_path}" 2>/dev/null | cut -f1 -d' ' || true
}

function generate_file_list {
  path[config]="${config_path}/config"
  path[users]="${config_path}/users"
  path[compose]="${config_path}/docker-compose.yml"
  path[engine]="${config_path}/engine.conf"
  path[haproxy]="${config_path}/haproxy.cfg"
  path[certbot_deployhook]="${config_path}/certbot/deployhook.sh"
  path[certbot_dockerfile]="${config_path}/certbot/Dockerfile"
  path[certbot_startup]="${config_path}/certbot/startup.sh"
  path[server_pem]="${config_path}/certificate/server.pem"
  path[server_key]="${config_path}/certificate/server.key"
  path[server_crt]="${config_path}/certificate/server.crt"
  path[tgbot_script]="${config_path}/tgbot/tgbot.py"
  path[tgbot_dockerfile]="${config_path}/tgbot/Dockerfile"
  path[tgbot_compose]="${config_path}/tgbot/docker-compose.yml"

  service[config]='none'
  service[users]='none'
  service[compose]='compose'
  service[engine]='engine'
  service[haproxy]='haproxy'
  service[certbot_deployhook]='certbot'
  service[certbot_dockerfile]='compose'
  service[certbot_startup]='certbot'
  service[server_pem]='haproxy'
  service[server_key]='engine'
  service[server_crt]='engine'
  service[tgbot_script]='tgbot'
  service[tgbot_dockerfile]='compose'
  service[tgbot_compose]='tgbot'

  for key in "${!path[@]}"; do
    md5["$key"]=$(get_md5 "${path[$key]}")
  done
}

function tune_kernel {
  cat >/etc/sysctl.d/99-reality-ezpz.conf <<EOF
fs.file-max = 200000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.netfilter.nf_conntrack_max=1000000
EOF
  sysctl -qp /etc/sysctl.d/99-reality-ezpz.conf >/dev/null 2>&1 || true
}

parse_args "$@" || show_help
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi
generate_file_list
install_packages
install_docker
upgrade
parse_config_file
parse_users_file
build_config
update_config_file
update_users_file
tune_kernel

if [[ ${args[menu]} == 'true' ]]; then
  set +e
  main_menu
  set -e
fi
if [[ ${args[restart]} == 'true' ]]; then
  restart_docker_compose
  if [[ ${config[tgbot]} == 'ON' ]]; then
    restart_tgbot_compose
  fi
fi
if [[ -z "$(${docker_cmd} ls | grep "${path[compose]}" | grep running || true)" ]]; then
  restart_docker_compose
fi
if [[ -z "$(${docker_cmd} ls | grep "${path[tgbot_compose]}" | grep running || true)" && ${config[tgbot]} == 'ON' ]]; then
  restart_tgbot_compose
fi
if [[ ${args[server-config]} == true ]]; then
  show_server_config
  exit 0
fi
if [[ -n ${args[list_users]} ]]; then
  for user in "${!users[@]}"; do
    echo "${user}"
  done
  exit 0
fi
if [[ ${#users[@]} -eq 1 ]]; then
  username="${!users[@]}"
fi
if [[ -n ${args[show_config]} ]]; then
  username="${args[show_config]}"
  if [[ -z "${users["${username}"]}" ]]; then
    echo 'User "'"$username"'" does not exists.'
    exit 1
  fi
fi
if [[ -n ${args[add_user]} ]]; then
  username="${args[add_user]}"
fi
if [[ -n $username ]]; then
  print_client_configuration "${username}"
fi
exit 0
