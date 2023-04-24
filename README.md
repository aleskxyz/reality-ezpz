# reality-ezpz
You can install and configure reality protocol on your linux server by executing a single command.

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and reality (xray) configuration
* Create Cloudflare warp account and configure warp as outbound
* Generates client configuration string and QRcode

Features:
* Generates client configuration string
* Generates client configuration QRcode
* You can regenerate configuration and keys
* You can change SNI domain
* You can change transport protocol
* You can block malware and adult contents
* Supports natvps.net servers
* Use Cloudflare WARP to hide your outbound traffic
* Supports Cloudflare warp+
* Install with a single command

Supported OS:
* Ubuntu 22.04
* Ubuntu 20.04
* Ubuntu 18.04
* Debian 11
* Debian 10
* CentOS Stream 9
* CentOS Stream 8
* CentOS 7
* Fedora 37

## Quick Start
You can start using this script with default configuration by copy and paste the line below in terminal:
```
bash <(curl -sL https://bit.ly/realityez)
```
or (if the above command dosen't work):
```
bash <(curl -sL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh)
```
After a while you will get confgiuration string and QR code:
![image](https://user-images.githubusercontent.com/39186039/232563871-0140e10a-22b4-4653-9bc9-cdba519a8b41.png)

## Clients
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNg/releases)
- iOS
  - [Wings X](https://apps.apple.com/app/wings-x-client/id6446119727)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN/releases)

## Advanced Configuration
You can change script defaults by using different arguments.

~~Notice: You need to mention non-default options each time when you want to run the script, otherwise it will use its default options and overwrite you existing configurations.~~

Your configuration will be saved and restored in each execution.

### Change SNI domain
Default SNI domain is `www.google.com`.

You can change it by using `--domain` or `-d` options:
```
bash <(curl -sL https://bit.ly/realityez) -d yahoo.com
```
### Change transport protocol
Default transport protocol is `tcp`.

You can change it by using `--transport` or `-t` options:
```
bash <(curl -sL https://bit.ly/realityez) -t h2
```
Valid options are `tcp`,`h2` and `grpc`.
### Block malware and adult contents
You can block malware and adult contents by using `--enable-safenet` or `-s` options:
```
bash <(curl -sL https://bit.ly/realityez) -s
```
You can disable this feature by using `--disable-safenet` option.
### Installing on natvps.net servers
By using `--enable-natvps` option you can use this script on natvps.net servers:
```
bash <(curl -sL https://bit.ly/realityez) --enable-natvps
```
This script will find first available port automatically so you don't need to use `--port` option while using it.

You can disable feature with `--disable-natvps` option.

It seems that natvps.net servers have some dns configuration problems and the `curl` package is not installed in them by default.

You can solve these problems by running this command:
```
grep -q "^DNS=1.1.1.1$" /etc/systemd/resolved.conf || echo "DNS=1.1.1.1" >> /etc/systemd/resolved.conf && systemctl restart systemd-resolved && apt update && apt install curl -y
```
### Regenerate user account
You can regenerate user account by using `--regenerate` or `-r` options:
```
bash <(curl -sL https://bit.ly/realityez) -r
```
All other configuration will be same as before.
### Restore default configuration
You can restore default configuration by using `--default` option.
```
bash <(curl -sL https://bit.ly/realityez) --default
```
User account will not change with this option.
### Uninstall
You can delete configuration and services by using `--uninstall` or `-u` options:
```
bash <(curl -sL https://bit.ly/realityez) -u
```
### Change configuration path
Default configuration path is `$HOME/reality`.

You can change it by using `--path` or `-p` options:
```
bash <(curl -sL https://bit.ly/realityez) -p /opt/reality
```
The path should be absolute path.
### Change port
Notice: Do not change default port. This may block your IP!

Default port is `443`.

You can change it by using `--port` option:
```
bash <(curl -sL https://bit.ly/realityez) --port 8443
```
## Cloudflare WARP
This script uses official Cloudflare WARP client for connecting to Cloudflare network and send all outbound traffic to Cloudflare server. So your servers address will be masked by Cloudflare IPs. This gives you a better web surffing experience due to less captcha challenges and also resolves some websites limitations on your servers IP.

You can enable Cloudflare WARP by using `-w` or `--enable-warp` options. This script will create and register a free WAPR account and use it.
```
bash <(curl -sL https://bit.ly/realityez) --enable-warp
```
Free account has traffic limitation and lower performance in comparison with WARP+ account which needs license.

You can either buy an WARP+ Unlimited license or get a free WARP+ license from this telegram bot: https://t.me/generatewarpplusbot

After getting a license from that telegram bot, you can use the license for your server with `--warp-license` option:
```
bash <(curl -sL https://bit.ly/realityez) --warp-license aaaaaaaa-bbbbbbbb-cccccccc
```
You can use each warp+ license on 4 devices only.

You can disable Cloudflare WARP by using `--disable-warp` option:
```
bash <(curl -sL https://bit.ly/realityez) --disable-warp
```
## Example
You can combine different options together.

We want to setup a server with these configurations:
* `grpc` transport protocol
* `www.wikipedia.org` as SNI domain
* Block adult contents
* Enable Cloudflare WARP
* Set Cloudflare WARP+ license

So we need to execute this command:
```
bash <(curl -sL https://bit.ly/realityez) -t grpc -d www.wikipedia.com -s -w --warp-license d34tgvde-gf73xvsj-23acfbg7
```
or
```
bash <(curl -sL https://bit.ly/realityez) --transport grpc --domain www.wikipedia.com --enable-safenet -enable-warp --warp-license d34tgvde-gf73xvsj-23acfbg7
```
