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

default_path="${HOME}/reality"
compose_project='reality-ezpz'
BACKTITLE=RealityEZPZ
MENU="Select an option:"
HEIGHT=30
WIDTH=60
CHOICE_HEIGHT=20

image[xray]="teddysun/xray:1.8.3"
image[warp]="aleskxyz/warp-svc:1.2"
image[sing-box]="gzxhwq/sing-box:v1.3-rc2"
image[nginx]="nginx:1.24.0"
image[certbot]="certbot/certbot:v2.6.0"
image[haproxy]="haproxy:2.8.0"

defaults[transport]=tcp
defaults[domain]=www.google.com
defaults[port]=443
defaults[safenet]=OFF
defaults[natvps]=OFF
defaults[warp]=OFF
defaults[warp_license]=""
defaults[core]=sing-box
defaults[security]=reality
defaults[server]=$(curl -fsSL --ipv4 https://ifconfig.io)

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
  "natvps"
  "warp"
  "warp_license"
)

regex[domain]="^[a-zA-Z0-9]+([-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
regex[path]="^/.*"
regex[port]="^[1-9][0-9]*$"
regex[warp_license]="^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{8}$"
regex[username]="^[a-zA-Z0-9]+$"
regex[ip]="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

function show_help {
  echo ""
  echo "Usage: reality-ezpz.sh [-t|--transport=tcp|http|grpc|ws] [-d|--domain=<domain>] [--server=<server>] [--regenerate] [--default]
  [-r|--restart] [-p|--path=<path>] [--enable-safenet=true|false] [--port=<port>] [--enable-natvps=true|false] [-c|--core=xray|sing-box]
  [--enable-warp=true|false] [--warp-license=<license>] [--security=reality|tls-valid|tls-invalid] [-m|--menu] [--show-server-config] 
  [--add-user=<username>] [--lists-users] [--show-user=<username>] [--delete-user=<username>] [-u|--uninstall]"
  echo ""
  echo "  -t, --transport <tcp|http|grpc|ws> Transport protocol (ws, http, grpc, ws, default: ${defaults[transport]})"
  echo "  -d, --domain <domain>     Domain to use as SNI (default: ${defaults[domain]})"
  echo "      --server <server>     IP address or domain name of server (Must be a valid domain if using tls-valid security)"
  echo "      --regenerate          Regenerate public and private keys"
  echo "      --default             Restore default configuration"
  echo "  -r  --restart             Restart services"
  echo "  -u, --uninstall           Uninstall reality"
  echo "  -p, --path <path>         Absolute path to configuration directory (default: ${default_path})"
  echo "      --enable-safenet <true|false> Enable or disable safenet (blocking malware and adult content)"
  echo "      --port <port>         Server port (default: ${defaults[port]})"
  echo "      --enable-natvps <true|false> Enable or disable natvps.net support"
  echo "      --enable-warp <true|false> Enable or disable Cloudflare warp"
  echo "      --warp-license <warp-license> Add Cloudflare warp+ license"
  echo "  -c  --core <sing-box|xray> Select core (xray, sing-box, default: ${defaults[core]})"
  echo "      --security <reality|tls-valid|tls-invalid> Select type of TLS encryption (reality, tls-valid, tls-invalid, default: ${defaults[security]})" 
  echo "  -m  --menu                Show menu"
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
  opts=$(getopt -o t:d:rup:c:mh --long transport:,domain:,server:,regenerate,default,restart,uninstall,path:,enable-safenet:,port:,enable-natvps:,warp-license:,enable-warp:,core:,security:,menu,show-server-config,add-user:,list-users,show-user:,delete-user:,help -- "$@")
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
      -p|--path)
        args[path]="$2"
        if ! [[ ${args[path]} =~ ${regex[path]} ]]; then
          echo "Use absolute path: ${args[path]}"
          return 1
        fi
        shift 2
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
      --enable-natvps)
        case "$2" in
          true|false)
            $2 && args[natvps]=ON || args[natvps]=OFF
            shift 2
            ;;
          *)
            echo "Invalid natvps option: $2"
            return 1
            ;;
        esac
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
          reality|tls-valid|tls-invalid)
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
      --show-server-config)
        args[server-config]=true
        shift
        ;;
      --add-user)
        args[add_user]="$2"
        if ! [[ ${args[add_user]} =~ ${regex[username]} ]]; then
          echo "Invalid username: ${args[warp_license]}\nUsername can only contains A-Z, a-z and 0-9"
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

  if [[ -z ${args[path]} ]]; then
    args[path]="${default_path}"
  fi

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
  while read -r line; do
    if [[ "${line}" =~ ^\s*# ]] || [[ "${line}" =~ ^\s*$ ]]; then
      continue
    fi
    IFS="=" read -r key value <<< "${line}"
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
  for item in "${defaults_items[@]}"; do
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
  if [[ ! ${config[server]} =~ ${regex[domain]} && ${config[security]} == 'tls-valid' ]]; then
    echo 'You have to assign a domain to server with "--server <domain>" option if you want to use "tls-valid" as TLS certifcate.'
    exit 1
  fi
  if [[ ${config[transport]} == 'ws' && ${config[security]} == 'reality' ]]; then
    echo 'You cannot use "ws" transport with "reality" TLS certificate. Use other transports or change TLS certifcate to tls-valid or tls-invalid'
    exit 1
  fi
  if [[ ${config[security]} == 'tls-valid' && "${config[natvps]}" == "ON" ]]; then
    echo 'You cannot use "tls-valid" certificate with "natvps". Use reality or tls-invalid'
    exit 1
  fi
  if [[ ${config[security]} == 'tls-valid' && ${config[port]} -ne 443 ]]; then
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
      echo 'Port 80 must be free if you want to use "tls-valid" as the security option.'
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
  config[server_ip]=$(ip route get 1.1.1.1 | grep -oP '(?<=src )(\d{1,3}\.){3}\d{1,3}')
  if [[ "${config[natvps]}" == "ON" ]]; then
    natvps_check_port
  fi
  if [[ "${args[natvps]}" == "OFF" ]] && [[ -z ${args[port]} ]] && [[ "${config_file[natvps]}" == "ON" ]]; then
    config[port]="${defaults[port]}"
  fi
}

function update_config_file {
  mkdir -p "${config_path}"
  touch "${path[config]}"
  for item in "${config_items[@]}"; do
    if grep -q "^${item}=" "${path[config]}"; then
      sed -i "s/^${item}=.*/${item}=${config[${item}]}/" "${path[config]}"
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

function natvps_check_port {
  local first_port
  local last_port
  first_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"01
  last_port="$(echo "${config[server_ip]}" | awk -F. '{print $4}')"20
  if ((config[port] >= first_port && config[port] <= last_port)); then
    return 0
  fi
  for port in $(seq "${first_port}" "${last_port}"); do
    if ! lsof -i :"${port}" >/dev/null; then
      config[port]=$port
      return 0
    fi
  done
  echo "Error: Free port was not found."
  return 1
}

function generate_keys {
  local key_pair
  key_pair=$(sudo docker run --rm ${image[xray]} xray x25519)
  config_file[public_key]=$(echo "${key_pair}"|grep -oP '(?<=Public key: ).*')
  config_file[private_key]=$(echo "${key_pair}"|grep -oP '(?<=Private key: ).*')
  config_file[short_id]=$(openssl rand -hex 8)
  config_file[service_path]=$(openssl rand -hex 4)
}

function uninstall {
  if docker compose >/dev/null 2>&1; then
    sudo docker compose --project-directory "${args[path]}" down --timeout 2 || true
    sudo docker compose --project-directory "${args[path]}" -p ${compose_project} down --timeout 2 || true
  elif which docker-compose >/dev/null 2>&1; then
    sudo docker-compose --project-directory "${args[path]}" down --timeout 2 || true
    sudo docker-compose --project-directory "${args[path]}" -p ${compose_project} down --timeout 2 || true
  fi
  rm -rf "${args[path]}"
  exit 0
}

function install_packages {
  if ! which jq qrencode whiptail >/dev/null 2>&1; then
    if which apt >/dev/null 2>&1; then
      sudo apt update
      sudo apt install qrencode jq whiptail -y
      return 0
    fi
    if which yum >/dev/null 2>&1; then
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
  if ! which docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | sudo bash
    sudo systemctl enable --now docker
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
  sudo curl -SL https://github.com/docker/compose/releases/download/v2.17.2/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
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
    $([[ ${config[security]} != 'reality' && ${config[transport]} == 'http' || ${config[transport]} == 'tcp' ]] && echo "- ./${path[server_crt]#${config_path}/}:/etc/${config[core]}/server.crt" || true)
    $([[ ${config[security]} != 'reality' && ${config[transport]} == 'http' || ${config[transport]} == 'tcp' ]] && echo "- ./${path[server_key]#${config_path}/}:/etc/${config[core]}/server.key" || true)
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
    $([[ ${config[security]} == 'tls-valid' || ${config[port]} -eq 443 ]] && echo '- 80:80' || true)
    - ${config[port]}:443
    restart: always
    volumes:
    - ./${path[haproxy]#${config_path}/}:/usr/local/etc/haproxy/haproxy.cfg
    - ./${path[server_pem]#${config_path}/}:/usr/local/etc/haproxy/server.pem
    networks:
    - reality"
fi)
$(if [[ ${config[security]} == 'tls-valid' ]]; then
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
$(if [[ ${config[warp]} == ON ]]; then
echo "
  warp:
    image: ${image[warp]}
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
fi)
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
  $([[ ${config[security]} == 'tls-valid' ]] && echo 'use_backend certbot if { path_beg /.well-known/acme-challenge }' || true)
  $([[ ${config[security]} == 'tls-valid' ]] && echo 'acl letsencrypt-acl path_beg /.well-known/acme-challenge' || true)
  $([[ ${config[security]} != 'reality' ]] && echo 'redirect scheme https if !letsencrypt-acl' || true)
  use_backend default
frontend tls
  bind :443 $([[ ${config[transport]} != 'tcp' ]] && echo 'ssl crt /usr/local/etc/haproxy/server.pem alpn h2,http/1.1' || true)
  mode $([[ ${config[transport]} != 'tcp' ]] && echo 'http' || echo 'tcp')
  $([[ ${config[transport]} != 'tcp' ]] && echo "http-request set-header Host ${config[server]}" || true)
  $([[ ${config[security]} == 'tls-valid' && ${config[transport]} != 'tcp' ]] && echo 'use_backend certbot if { path_beg /.well-known/acme-challenge }' || true)
  use_backend engine $([[ ${config[transport]} != 'tcp' ]] && echo "if { path_beg /${config[service_path]} }" || true)
  $([[ ${config[transport]} != 'tcp' ]] && echo 'use_backend default' || true)
backend engine
  retry-on conn-failure empty-response response-timeout
  mode $([[ ${config[transport]} != 'tcp' ]] && echo 'http' || echo 'tcp')
  server engine engine:8443 check tfo $([[ ${config[transport]} == 'grpc' ]] && echo 'proto h2' || true) $([[ ${config[transport]} == 'http' ]] && echo 'ssl verify none' "$([[ ${config[core]} == sing-box ]] && echo 'proto h2' || true)" || true)
$([[ ${config[security]} == 'tls-valid' ]] && echo 'backend certbot' || true)
$([[ ${config[security]} == 'tls-valid' ]] && echo '  mode http' || true)
$([[ ${config[security]} == 'tls-valid' ]] && echo '  server certbot certbot:80' || true)
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
  if [[ ${config[core]} == 'sing-box' ]]; then
  reality_object='"tls": {"enabled": true,"server_name": "'"${config[domain]}"'","alpn": [],"reality": {"enabled": true,"handshake": {"server": "'"${config[domain]}"'","server_port": 443},"private_key": "'"${config[private_key]}"'","short_id": ["'"${config[short_id]}"'"],"max_time_difference": "1m"}}'
  tls_object='"tls": {"enabled": true, "certificate_path": "/etc/sing-box/server.crt", "key_path": "/etc/sing-box/server.key"}'
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
fi
  if [[ ${config[core]} == 'xray' ]]; then
  reality_object='"security":"reality","realitySettings":{"show": false,"dest": "'"${config[domain]}"':443","xver": 0,"serverNames": ["'"${config[domain]}"'"],"privateKey": "'"${config[private_key]}"'","maxTimeDiff": 60000,"shortIds": ["'"${config[short_id]}"'"]}'
  tls_object='"security": "tls","tlsSettings": {"certificates": [{"oneTimeLoading": true, "certificateFile": "/etc/xray/server.crt", "keyFile": "/etc/xray/server.key"}]}'
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
  if [[ ${config[security]} == "tls-valid" ]]; then
    mkdir -p "${config_path}/certbot"
    generate_certbot_deployhook
    generate_certbot_dockerfile
    generate_certbot_script
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
  uuid=$(grep '^uuid=' "${path[config]}" 2>/dev/null | cut -d= -f2 || true)
  if [[ -n $uuid ]]; then
    sed -i '/^uuid=/d' "${path[users]}"
    echo "RealityEZPZ=${uuid}" >> "${path[users]}"
    sed -i 's/=true/=ON/g; s/=false/=OFF/g' "${path[users]}"
  fi
  rm -f "${config_path}/xray.conf"
  rm -f "${config_path}/singbox.conf"
  if ! sudo ${docker_cmd} ls | grep ${compose_project} >/dev/null && [[ -r ${path[compose]} ]]; then
    sudo ${docker_cmd} --project-directory ${config_path} down --remove-orphans --timeout 2
  fi
  if [[ -r ${path[config]} ]]; then
    sed -i 's/transport=h2/transport=http/g' "${path[config]}"
    sed -i 's/core=singbox/core=sing-box/g' "${path[config]}"
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
    if [[ $? -eq 0 ]]; then
      unset users["${username}"]
      update_users_file
      message_box "Delete User" 'User "'"${username}"'" has been deleted.'
    fi
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
Fingerprint: randomized
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
  server_config=$server_config$'\n'"natvps: ${config[natvps]}"
  server_config=$server_config$'\n'"WARP: ${config[warp]}"
  server_config=$server_config$'\n'"WARP License: ${config[warp_license]}"
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
  if [[ $? -eq 0 ]]; then
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
  if [[ $? -eq 0 ]]; then
    generate_keys
    config[public_key]=${config_file[public_key]}
    config[private_key]=${config_file[private_key]}
    config[short_id]=${config_file[short_id]}
    update_config_file
    message_box "Regenerate keys" "All keys has been regenerated."
  fi
}

function restore_defaults_menu {
  whiptail \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Restore Default Config" \
    --yesno "Are you sure to restore default configuration?" \
    $HEIGHT $WIDTH \
    3>&1 1>&2 2>&3
  if [[ $? -eq 0 ]]; then
    restore_defaults
    update_config_file
    message_box "Restore Default Config" "All configurations has been restored to them defaults."
  fi
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
      "9" "WARP+ License" \
      "10" "natvps" \
      "11" "Restart Services" \
      "12" "Regenerate Keys" \
      "13" "Restore Defaults" \
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
        config_warp_license_menu
        ;;
      10 )
        config_natvps_menu
        ;;
      11 )
        restart_menu
        ;;
      12 )
        regenerate_menu
        ;;
      13 )
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
  if [[ $? -eq 0 ]]; then
    config[core]=$core
    update_config_file
  fi
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
    if [[ ! ${server} =~ ${regex[domain]} && ${config[security]} == 'tls-valid' ]]; then
      message_box 'Invalid Configuration' 'You have to assign a valid domain to server if you want to use "tls-valid" certificate.'
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
      message_box 'Invalid Configuration' 'You cannot use "ws" transport with "reality" TLS certificate. Use other transports or change TLS certifcate to "tls-valid" or "tls-invalid"'
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
      "tls-valid" "$([[ "${config[security]}" == 'tls-valid' ]] && echo 'on' || echo 'off')" \
      "tls-invalid" "$([[ "${config[security]}" == 'tls-invalid' ]] && echo 'on' || echo 'off')" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      break
    fi
    if [[ ! ${config[server]} =~ ${regex[domain]} && ${security} == 'tls-valid' ]]; then
      message_box 'Invalid Configuration' 'You have to assign a valid domain to server if you want to use "tls-valid" as security type'
      continue
    fi
    if [[ ${config[transport]} == 'ws' && ${security} == 'reality' ]]; then
      message_box 'Invalid Configuration' 'You cannot use "reality" TLS certificate with "ws" transport protocol. Change TLS certifcate to "tls-valid" or "tls-invalid" or use other transport protocols'
      continue
    fi
    if [[ "${config[natvps]}" == "ON" && ${security} == 'tls-valid' ]]; then
      message_box 'Invalid Configuration' 'You cannot use "tls-valid" certificate with "natvps". Use reality or tls-invalid'
      continue
    fi
    if [[ ${security} == 'tls-valid' && ${config[port]} -ne 443 ]]; then
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
        message_box 'Port 80 must be free if you want to use "tls-valid" as the security option.'
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
  safenet=$(whiptail --clear --backtitle "$BACKTITLE" --title "Safe Internet" \
    --checklist --notags "Enable blocking malware and adult content" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "safenet" "Enable Safe Internet" "${config[safenet]}" \
    3>&1 1>&2 2>&3)
  if [[ $? -eq 0 ]]; then
    config[safenet]=$([[ $safenet == '"safenet"' ]] && echo ON || echo OFF)
    update_config_file
  fi
}

function config_warp_menu {
  local warp
  warp=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP" \
    --checklist --notags "Enable WARP:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "warp" "Enable WARP" "${config[warp]}" \
    3>&1 1>&2 2>&3)
  if [[ $? -eq 0 ]]; then
    config[warp]=$([[ $warp == '"warp"' ]] && echo ON || echo OFF)
    if [[ ${config[warp]} == 'ON' ]]; then
      config_warp_license_menu
    fi
    update_config_file
  fi
}

function config_warp_license_menu {
  local warp_license
  while true; do
    warp_license=$(whiptail --clear --backtitle "$BACKTITLE" --title "WARP+ License" \
      --inputbox "Enter WARP+ License:" $HEIGHT $WIDTH "${config[warp_license]}" \
      3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
      config[warp]=OFF
      update_config_file
      break
    fi
    if [[ ! $warp_license =~ ${regex[warp_license]} ]]; then
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
  natvps=$(whiptail --clear --backtitle "$BACKTITLE" --title "natvps.net" \
    --checklist --notags "natvps.net server:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
    "natvps" "natvps.net server" "${config[natvps]}" \
    3>&1 1>&2 2>&3)
  if [[ $? -eq 0 ]]; then
    if [[ $natvps == '"natvps"' && ${config[security]} == 'tls-valid' ]]; then
      message_box 'Invalid Configuration' 'You cannot use "tls-valid" certificate with "natvps". Use reality or tls-invalid'
      return
    fi
    config[natvps]=$([[ $natvps == '"natvps"' ]] && echo ON || echo OFF)
    natvps_check_port
    update_config_file
  fi
}

function restart_docker_compose {
  sudo ${docker_cmd} --project-directory ${config_path} -p ${compose_project} down --remove-orphans --timeout 2 || true
  sudo ${docker_cmd} --project-directory ${config_path} -p ${compose_project} up --build -d --remove-orphans --build
}

function restart_container {
  if [[ -z "$(sudo ${docker_cmd} ls | grep "${path[compose]}" | grep running || true)" ]]; then
    restart_docker_compose
    return
  fi
  if ${docker_cmd} --project-directory ${config_path} -p ${compose_project} ps --services "$1" | grep "$1"; then
    sudo ${docker_cmd} --project-directory ${config_path} -p ${compose_project} restart --timeout 2 "$1"
  fi
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
  if [[ "${restart[compose]}" == 'true' ]]; then
    restart_docker_compose
    return
  fi
  for key in "${!restart[@]}"; do
    if [[ $key != 'none' ]]; then
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
  sysctl -qp /etc/sysctl.d/99-reality-ezpz.conf
}

parse_args "$@" || show_help
config_path="${args[path]}"
generate_file_list
install_packages
install_docker
upgrade
parse_config_file
parse_users_file
build_config
update_config_file
update_users_file
if [[ ${config[natvps]} == 'OFF' ]]; then
  tune_kernel
fi
if [[ ${args[menu]} == 'true' ]]; then
  set +e
  main_menu
  set -e
fi
if [[ ${args[restart]} == 'true' ]]; then
  restart_docker_compose
fi
if [[ -z "$(sudo ${docker_cmd} ls | grep "${path[compose]}" | grep running || true)" ]]; then
  restart_docker_compose
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
