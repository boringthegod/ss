# SS

# Description

(another) **Subdomain Scanner**

Tool which concatenates **several existing subdomain recognition tools** in order to have the greatest completeness.

It **removes subdomains that no longer exist**, and **discovers related IPs and groups everything by ASNs in a JSON format**.

Combine it with [jsoncrack](https://github.com/AykutSarac/jsoncrack.com) to get a global view of an organization's assets: :

![](https://cdn.discordapp.com/attachments/890363963483758644/1182079679633559572/image.png?ex=6583647d&is=6570ef7d&hm=7a5e1bad0f8042993cef26b9cc2440ffa48e0b5a7db7a566bd8d0f60ae564cc3&)

*Full view from: [here](https://cdn.discordapp.com/attachments/846346170971848724/1175393559147450369/jsoncrack.com1.png)*

All subdomains and IPs discovered are also written to their respective files.

# Requirements

- [Python 3](https://www.python.org/download/releases/3.0/)

- [Go](https://go.dev/doc/install)

- Launchable Docker without `sudo` : https://docs.docker.com/engine/install/linux-postinstall/

- Install python3 dependencies : `pip3 install -r requirements.txt`

- Have [httpx](https://github.com/projectdiscovery/httpx#installation-instructions) (On several distros, you'll have the wrong **httpx binary installed by default**, so `sudo apt remove python3-httpx` and install the correct httpx, [dnxs](https://github.com/projectdiscovery/dnsx#installation-instructions) and [subfinder](https://github.com/projectdiscovery/subfinder#installation) installed 

- [reconftw](https://github.com/six2dez/reconftw) docker image : `docker pull six2dez/reconftw:main`

- [rcrt](https://github.com/hessman/rcrt) docker image : `docker pull hessman/rcrt`

- [Sudomy](https://github.com/screetsec/Sudomy) docker image : `docker pull screetsec/sudomy:v1.1.9-dev`

- You need to make the crt.sh file executable : `chmod +x crt.sh`

## or with Docker

`docker pull ghcr.io/boringthegod/ss:latest`

Then run the tool, **remembering to set the -u argument to get the output results**, as the docker closes at the end of the scan.

`docker run -it --privileged ghcr.io/boringthegod/ss:latest -d google.com -u`

or full scan for an organization : `docker run -it --privileged -v /absolute/path/to/norautodomains.txt:/root/ss/norautodomains.txt ghcr.io/boringthegod/ss -f norautodomains.txt -o Norauto -u`

The **"privileged"** option is mandatory, as this docker will launch Dockers during the scan and therefore needs these permissions.

# Usage

All you have to do is run it by putting the **main domain name** after the `-d` argument 

If, for example, you're running the tool from a VPS and want to **easily retrieve the .JSON file** from your computer, just add the `-u` argument and it will automatically be temporarily hosted on [https://pype.sellan.fr/](https://pype.sellan.fr/) (Free, fast, log-free file hosting) as soon as the scan is complete.

It can also scan multiple domains if you place them all in one file with one domain per line. Place file name after `-f` argument.

Behind the `-o` argument, specify the name of the organization so as to have a JSON rendering that starts from this name and lists the main domains underneath, followed by the scan of each of them.

```bash
usage: ss.py [-h] [-d DOMAINS] [-f FILE] [-u] [-o ORG]

Recognition tool for sub-domains, IPs and ASNs linked to a domain

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        Specifies the domain name to be scanned. Example: -d google.com
  -f FILE, --file FILE  Specifies a file with one domain per line to be scanned. Example: -f domains.txt
  -u, --upload          Activate the upload of results to https://pype.sellan.fr
  -o ORG, --org ORG     Specifies the organization name for the JSON output. Example: -o Leclerc

Examples:
  ./ss.py -d google.com -u
  ./ss.py -f domains.txt -o Leclerc -u
```

## Demo

### Example 1 : Classic domain scan
![](https://cdn.discordapp.com/attachments/890363963483758644/1182080572827390023/image.png)

### Example 2 : Scanning an entire organization with multiple domains

Example for scanning an entire organization. For example, you have this list of domains: 

![](https://cdn.discordapp.com/attachments/890363963483758644/1184499530901766164/carbon.png)

You can scan it with the following command: 

![](https://cdn.discordapp.com/attachments/890363963483758644/1184512003813937192/carbon1.png)

And it produces a complete JSON of the organization, which you can find [here](https://cdn.discordapp.com/attachments/890363963483758644/1184512425819639959/Norauto.json)
