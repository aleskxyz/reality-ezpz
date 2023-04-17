# reality-ezpz
You can install and configure reality protocol on your linux server by executing a single command.

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and reality (xray) configuration
* Generates client configuration string and QRcode

Installation:
```
mkdir reality
cd reality
curl -fsSL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh -o reality-ezpz.sh
sudo bash reality-ezpz.sh <domain>
```
In the above command, you should replace `<domain>` with the domain that your server pretends to host.

After first run, a file named `config` will be created that stores all of your configuration.

In subsequent execution of `reality-ezpz.sh` you don't need to specify `<domain>`
