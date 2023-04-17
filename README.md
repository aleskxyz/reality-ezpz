# reality-ezpz
You can install and configure reality protocol on your linux server by executing a single command.

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and reality (xray) configuration
* Generates client configuration string and QRcode

## Quick start
Install everything with a single commmad with default config:
```
curl -sL https://bit.ly/realityez|bash
```

## Custom Installation
```
mkdir reality
cd reality
curl -fsSL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh -o reality-ezpz.sh
sudo bash reality-ezpz.sh <domain> <install_path>
```
In the above command, you should replace `<domain>` with the domain that your server pretends to host. (default: yandex.com)

You can also replace `<install_path>` with the path that you want this script store its files there. (default: $HOME/reality)

After first run, a file named `config` will be created that stores all of your configuration.

## Output
![image](https://user-images.githubusercontent.com/39186039/232563871-0140e10a-22b4-4653-9bc9-cdba519a8b41.png)
