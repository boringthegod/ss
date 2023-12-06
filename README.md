# SS

# Description

(another) **Subdomain Scanner**

Tool which concatenates **several existing subdomain recognition tools** in order to have the greatest completeness.

It **removes subdomains that no longer exist**, and **discovers related IPs and groups everything by ASNs in a JSON format**.

Combine it with [jsoncrack](https://github.com/AykutSarac/jsoncrack.com) to get a global view of an organization's assets: :

![](https://cdn.discordapp.com/attachments/890363963483758644/1182079679633559572/image.png?ex=6583647d&is=6570ef7d&hm=7a5e1bad0f8042993cef26b9cc2440ffa48e0b5a7db7a566bd8d0f60ae564cc3&)

*Full view from: [here](https://cdn.discordapp.com/attachments/890363963483758644/1182079679633559572/image.png)*

All subdomains and IPs discovered are also written to their respective files.

# Requirements

- [Python 3](https://www.python.org/download/releases/3.0/)

- [Go](https://go.dev/doc/install)

- Launchable Docker without `sudo` : https://docs.docker.com/engine/install/linux-postinstall/

- Install python3 dependencies : `pip3 install -r requirements.txt`

- Have [httpx](https://github.com/projectdiscovery/httpx#installation-instructions) , [dnxs](https://github.com/projectdiscovery/dnsx#installation-instructions) and [subfinder](https://github.com/projectdiscovery/subfinder#installation) installed 

- [reconftw](https://github.com/six2dez/reconftw) docker image : `docker pull six2dez/reconftw:main`

- [rcrt](https://github.com/hessman/rcrt) docker image : `docker pull hessman/rcrt`

- [Sudomy](https://github.com/screetsec/Sudomy) docker image : `docker pull screetsec/sudomy:v1.1.9-dev`

- You need to make the crt.sh file executable : `chmod +x crt.sh`

# Usage

All you have to do is run it by putting the **main domain name** after the `-d` argument 

If, for example, you're running the tool from a VPS and want to **easily retrieve the .JSON file** from your computer, just add the `-u` argument and it will automatically be temporarily hosted on [https://pype.sellan.fr/](https://pype.sellan.fr/) (Free, fast, log-free file hosting) as soon as the scan is complete.


```bash
usage: ss.py [-h] -d DOMAIN [-u]

Recognition tool for sub-domains, IPs and ASNs linked to a domain

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Specifies the domain name to be scanned. Example: -d google.com
  -u, --upload          Activate the upload of results to https://pype.sellan.fr

Examples:
  ./ss.py -d google.com -u
```

## Demo

![](https://cdn.discordapp.com/attachments/890363963483758644/1182080572827390023/image.png)