# reality-ezpz
You can install and configure reality protocol on your linux server by executing a single command.

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and reality (xray) configuration
* Generates client configuration string and QRcode

Features:
* Generates client configuration string
* Generates client configuration QRcode
* You can regenerate configuration and keys
* You can change SNI domain
* You can change transport protocol
* You can block malware and adult contents

This script is designed for Ubuntu and Debian.

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

## Advanced Configuration
You can change script defaults by using different arguments.

Notice: You need to mention non-default options each time when you want to run the script, otherwise it will use its default options and overwrite you existing configurations.

### Change SNI domain
Default SNI domain is `www.google.com`.

You can change it by using `--domain` or `-d` options:
```
bash <(curl -sL https://bit.ly/realityez) -d yahoo.com
```
### Change transport protocol
Default transport protocol is `tcp`.

You can change it by using `--trans` or `-t` options:
```
bash <(curl -sL https://bit.ly/realityez) -t h2
```
Valid options are `tcp`,`h2` and `grpc`.
### Block malware and adult contents
You can block malware and adult contents by using `--safenet` or `-s` options:
```
bash <(curl -sL https://bit.ly/realityez) -s
```
### Regenerate configuration and keys
You can regenerate all the configuration and keys by using `--regenerate` or `-r` options:
```
bash <(curl -sL https://bit.ly/realityez) -r
```
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
## Example
You can combine different options together.

We want to create a reality account that:
* Uses `grpc` transport protocol
* Uses `www.wikipedia.org` as SNI domain
* Changes default path to `/opt/xray`
* Blocks adult contents

So we need to execute this command:
```
bash <(curl -sL https://bit.ly/realityez) -t grpc -d www.wikipedia.com -p /opt/xray -s
```
