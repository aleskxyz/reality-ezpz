#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Run as root"
  exit
fi
if ! command -v qrencode > /dev/null 2>&1; then
  echo "Updating repsitories ..."
  apt update -qq > /dev/null 2>&1
  echo "Installing qrencode ..."
  apt install qrencode -y -qq > /dev/null 2>&1
fi
if ! command -v docker > /dev/null 2>&1; then
  echo "Installing docker ..."
  curl -fsSL https://get.docker.com | bash > /dev/null 2>&1
fi
if [[ ! -e 'config' ]]; then
  if [[ $# -eq 0 ]]; then
    echo "domain is mandatory for the first run"
    exit 1
  fi
key_pair=$(docker run -q --rm teddysun/xray:1.8.0 xray x25519)
cat >config <<EOF
domain=$1
server=$(curl -s ifconfig.me)
uuid=$(cat /proc/sys/kernel/random/uuid)
public_key=$(echo "${key_pair}"|grep -oP '(?<=Public key: ).*')
private_key=$(echo "${key_pair}"|grep -oP '(?<=Private key: ).*')
short_id=$(openssl rand -hex 8)
EOF
fi

. config

cat >docker-compose.yml <<EOF
version: "3"
services:
  xray:
    image: teddysun/xray:1.8.0
    ports:
    - 80:8080
    - 443:8443
    restart: always
    environment:
    - "TZ=Etc/UTC"
    volumes:
    - ./xray.conf:/etc/xray/config.json
EOF

cat >xray.conf <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 8080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "${domain}",
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
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",
          "xver": 0,
          "serverNames": [
            "${domain}"
          ],
          "privateKey": "${private_key}",
          "maxTimeDiff": 60000,
          "shortIds": [
            "${short_id}"
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
    {
      "protocol": "freedom"
    },
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
          "geoip:private",
          "geoip:ir"
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
        "outboundTag": "block",
        "domain": [
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

docker compose down
docker compose up -d

config="vless://${uuid}@${server}:443?security=reality&encryption=none&alpn=h2,http/1.1&pbk=${public_key}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${domain}&sid=${short_id}#reality"
echo ""
echo "Client configuration:"
echo ""
echo "$config"
echo ""
echo "Or you can scan the QR code:"
echo ""
qrencode -t ansiutf8 $config
