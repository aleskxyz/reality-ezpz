# reality-ezpz
Install and configure vless with reality or TLS on your linux server by executing a single command!

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and sing-box/xray configuration for vless protocol for reality and tls
* Create Cloudflare warp account and configure warp as outbound
* Generates client configuration string and QRcode
* Gets and renews valid certificate from Letsencrypt for TLS encryption
* Fine-tunes kernel tunables
* Is designed by taking security considerations into account  to make the server undetectable
* Provides a Telegram bot to manage users from Telegram

Features:
* Generates client configuration string
* Generates client configuration QRcode
* You can choose between xray or sing-box core
* You can choose between reality or TLS security protocol
* You can use a Text-based user interface (TUI)
* You can create multiple user accounts
* You can regenerate configuration and keys
* You can change SNI domain
* You can change transport protocol (tcp, http, grpc, ws)
* You can get valid TLS certificate with Letsencrypt
* You can block malware and adult contents
* Use Cloudflare WARP to hide your outbound traffic
* Supports Cloudflare warp+
* Install with a single command
* Telegram bot for user management

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
You can start using this script with default configuration by copy and paste the line below in terminal.

This command will configure `sing-box` with `reality` security protocol over `tcp` transport protocol on port `443` for `www.google.com` SNI domain by default:
```
bash <(curl -sL https://bit.ly/realityez)
```
or (if the above command dosen't work):
```
bash <(curl -sL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh)
```
After a while you will get configuration string and QR code:
![image](https://user-images.githubusercontent.com/39186039/232563871-0140e10a-22b4-4653-9bc9-cdba519a8b41.png)

You can run TUI with `-m` or `--menu` option:
```
bash <(curl -sL https://bit.ly/realityez) -m
```
And then you will see management menu in your terminal:
![image](https://github.com/aleskxyz/reality-ezpz/assets/39186039/a727148c-1a11-4702-80f3-ab8b46d916af)

You can also enable Telegram bot with `--enable-tgbot` option and manage users from with your Telegram bot ([More Info](#telegram-bot))
<p align="center">
<img src="https://github.com/aleskxyz/reality-ezpz/assets/39186039/7e31383a-e00b-426e-9324-6d58f36e7da0" width="300">
</p>

Help message of the script:
```
Usage: reality-ezpz.sh [-t|--transport=tcp|http|grpc|ws] [-d|--domain=<domain>] [--server=<server>] [--regenerate] [--default]
  [-r|--restart] [--enable-safenet=true|false] [--port=<port>] [-c|--core=xray|sing-box]
  [--enable-warp=true|false] [--warp-license=<license>] [--security=reality|letsencrypt|selfsigned] [-m|--menu] [--show-server-config] 
  [--add-user=<username>] [--lists-users] [--show-user=<username>] [--delete-user=<username>] [-u|--uninstall]

  -t, --transport <tcp|http|grpc|ws> Transport protocol (http, grpc, tcp default: tcp)
  -d, --domain <domain>     Domain to use as SNI (default: www.google.com)
      --server <server>     IP address or domain name of server (Must be a valid domain if using ws)
      --regenerate          Regenerate public and private keys
      --default             Restore default configuration
  -r  --restart             Restart services
  -u, --uninstall           Uninstall reality
      --enable-safenet <true|false> Enable or disable safenet (blocking malware and adult content)
      --port <port>         Server port (default: 443)
      --enable-warp <true|false> Enable or disable Cloudflare warp
      --warp-license <warp-license> Add Cloudflare warp+ license
  -c  --core <sing-box|xray> Select core (xray, sing-box, default: sing-box)
      --security <reality|letsencrypt|selfsigned> Select type of TLS encryption (reality, letsencrypt, selfsigned, default: reality)
  -m  --menu                Show menu
      --enable-tgbot <true|false> Enable Telegram bot for user management
      --tgbot-token <token> Token of Telegram bot
      --tgbot-admins <telegram-username> Usernames of telegram bot admins (Comma separated list of usernames without leading '@')
      --show-server-config  Print server configuration
      --add-user <username> Add new user
      --list-users          List all users
      --show-user <username> Shows the config and QR code of the user
      --delete-user <username> Delete the user
  -h, --help                Display this help message
```

## Clients
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNg/releases)
  - [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)
- iOS
  - [FoXray](https://apps.apple.com/app/foxray/id6448898396)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN/releases)

## Security Options
This script can configure the service with 3 types of security options:
- reality
- letsencrypt
- selfsigned

By default `reality` is configured but you can change the security protocol with `--security` option.

The `letsencrypt` option will use Letsencrypt to get a valid certificate for you server. So you have to assign a valid domain or subdomain to your server with `--server <domain>` option.

The `selfsigned` option is same as `letsencrypt` but the certificates are self-signed and you don't need to assign a domain or subdomain to your server.

## Compatibility and recommendation
CDN compatibility table:

|   | Cloudflare | ArvanCloud |
| ------------ | ------------ | ------------ |
| reality | :x: | :x: |
| selfsigned | :heavy_check_mark: | :heavy_check_mark: |
| letsencrypt | :heavy_check_mark: | :heavy_check_mark: |
| tcp  | :x:  | :x:  |
| http  | :x:  | :heavy_check_mark:  |
| grpc  | :heavy_check_mark:  | :heavy_check_mark:  |
| ws  | :heavy_check_mark:  | :heavy_check_mark:  |

- You need to enable `grpc` or `websocket` in Cloudflare if you want to use the corresponding transport protocols.
- You have to configure CDN provider to use HTTPS for connecting to your server.
- The `ws` transport protocol is not compatible with `reality` security option.
- Avoid using `tcp` transport protocol with `letsencrypt` or `selfsigned` security options.
- Avoid using `selfsigned` security option. Get a domain and use `letsencrypt` option.
- Do not change the port to something other than `443`.
- The `sing-box` core has better performance.
- Using [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) for Android is recommended.

## User Management
You can add, view and delete multiple user account with this script easily!

### Add User
You can add additional user by using `--add-user` option:
```
bash <(curl -sL https://bit.ly/realityez) --add-user user1
```
This command will create `test1` as a new user.

Notice: Username can only contains A-Z, a-z and 0-9

### List Users
You can view a list of all users by using `--list-users` option:
```
bash <(curl -sL https://bit.ly/realityez) --list-users
```

### Show User Configuration
You can get config string and QR code of the user for importing by using `--show-user` option:
```
bash <(curl -sL https://bit.ly/realityez) --show-user user1
```
This command will print config string and QR code of `user1`

### Delete User
You can delete a user by using `--delete-user` option:
```
bash <(curl -sL https://bit.ly/realityez) --delete-user user1
```
This command will delete `user1`

## Advanced Configuration
You can change script defaults by using different arguments.

Your configuration will be saved and restored in each execution. So You can run the script multiple time with out any problem.

### Change SNI domain
Reality protocol will use the public certificate of SNI domain.

Default SNI domain is `www.google.com`.

You can change it by using `--domain` or `-d` options:
```
bash <(curl -sL https://bit.ly/realityez) -d yahoo.com
```
### Change transport protocol
Default transport protocol is `tcp`.

You can change it by using `--transport` or `-t` options:
```
bash <(curl -sL https://bit.ly/realityez) -t http
```
Valid options are `tcp`,`http`, `grpc` and `ws`.

`ws` is not compatible with reality protocol. You have to use `letsencrypt` or `selfsigned` with it.

### Block malware and adult contents
You can block malware and adult contents by using `--enable-safenet` option:
```
bash <(curl -sL https://bit.ly/realityez) --enable-safenet true
```
You can disable this feature with `--enable-safenet false` option.

### Get runnig configuration
You can get the running configuration with `--show-server-config` option:
```
bash <(curl -sL https://bit.ly/realityez) --show-server-config
```

### Regenerate configuration keys
You can regenerate keys by using `--regenerate` option:
```
bash <(curl -sL https://bit.ly/realityez) --regenerate
```
All other configuration will be same as before.

### Restart services
You can restart the service by using `-r` or `--restart` options:
```
bash <(curl -sL https://bit.ly/realityez) -r
```

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

### Change port
Notice: Do not change default port. This may block your IP!

Default port is `443`.

In case of using `letsencrypt` security option, port `80` has to be available for Letsencrypt challenge.

You can change it by using `--port` option:
```
bash <(curl -sL https://bit.ly/realityez) --port 8443
```

### Change engine core
Default engine core is sing-box but you can also switch to xray by using `--core` or `-c` options:
```
bash <(curl -sL https://bit.ly/realityez) -c xray
```
Valid options are `xray` and `sing-box`.

### Text-based user interface (TUI)
You can also use the TUI for changing the configuration of the service.

To access to TUI you can use `-m` or `--menu` options:
```
bash <(curl -sL https://bit.ly/realityez) -m
```

## Telegram Bot
You can manage users with Telegram Bot.

You should get a Telegram bot token from `@BotFather` Telegram account.

Then you can enable Telegram bot by using this command as an example:
```
bash <(curl -sL https://bit.ly/realityez) --enable-tgbot true --tgbot-token <telegram-bot-token> --tgbot-admins=<your-telegram-username>
```
In the command above you have to provide a comma separated list of Telegram usernames (without leading '@') which are authorized to use Telegram bot.

You can disable Telegram bot with this command:
```
bash <(curl -sL https://bit.ly/realityez) --enable-tgbot false
```

## Cloudflare WARP
This script uses official Cloudflare WARP client for connecting to Cloudflare network and send all outbound traffic to Cloudflare server. So your servers address will be masked by Cloudflare IPs. This gives you a better web surffing experience due to less captcha challenges and also resolves some websites limitations on your servers IP.

You can enable Cloudflare WARP by using `--enable-warp true` option. This script will create and register a free WAPR account and use it.
```
bash <(curl -sL https://bit.ly/realityez) --enable-warp true
```
Free account has traffic limitation and lower performance in comparison with WARP+ account which needs license.

You can either buy an WARP+ Unlimited license or get a free WARP+ license from this telegram bot: https://t.me/generatewarpplusbot

After getting a license from that telegram bot, you can use the license for your server with `--warp-license` option:
```
bash <(curl -sL https://bit.ly/realityez) --warp-license aaaaaaaa-bbbbbbbb-cccccccc
```
You can use each warp+ license on 4 devices only.

You can disable Cloudflare WARP with `--enable-warp false`:
```
bash <(curl -sL https://bit.ly/realityez) --enable-warp false
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
bash <(curl -sL https://bit.ly/realityez) --transport=grpc --domain=www.wikipedia.com --enable-safenet=true --enable-warp=true --warp-license=26z9i0ld-WG0wy324-rA703nZ2
```
