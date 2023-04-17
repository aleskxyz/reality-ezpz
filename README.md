# reality-ezpz
You can install and configure reality protocol on your linux server by executing a single command.

This script:
* Installs docker with compose plugin in your server
* Generates docker-compose.yml and reality (xray) configuration
* Generates client configuration string and QRcode

This script is designed for Ubuntu and Debian.

## Installation
Copy and pase the line below in terminal:
```
bash <(curl -sL https://bit.ly/realityez)
```
After a while you will get confgiuration string and QR code:
![image](https://user-images.githubusercontent.com/39186039/232563871-0140e10a-22b4-4653-9bc9-cdba519a8b41.png)

## Generate new configuration
If you want to remove old configuration and generate new configuration, copy and pase this line:
```
bash <(curl -sL https://bit.ly/realityez) regenerate
```

## Customization
This script stores configurations in `$HOME/reality` and uses the TLS of `yandex.com`

You can edit these defaults by downloading the script in your server and edit first lines.