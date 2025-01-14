#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import glob
import re
import argparse
import socket
import json
import shutil
import requests
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from termcolor import colored
from halo import Halo
import tldextract




def run_docker_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if process.returncode != 0:
            print(f"Error: {error.decode('utf-8')}")
            return None

        return output.decode('utf-8', 'ignore').strip()

    except Exception as e:
        print(f"Exception occurred: {e}")
        return None


def run_subfinder_and_tools(domain):
    output_file = os.path.join(output_path, "exc2.txt")
    command = f"subfinder -d {domain} | dnsx | httpx -o {output_file}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process.communicate()

    with open(os.path.join(output_path, "exc2.txt"), "r") as file:
        return file.read()


def run_reconftw_scan(domain):
    command = f'docker run -it --rm -v "${{PWD}}/reconftw.cfg":\'/reconftw/reconftw.cfg\' -v "${{PWD}}/Recon/":\'/reconftw/Recon/\' six2dez/reconftw:main -d {domain} -s'
    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def run_sudomy_scan(domain):
    sudomy_cmd = f"docker run -v \"{os.getcwd()}/output:/usr/lib/sudomy/output\" -e \"SHODAN_API=your_shodan_api\" -t --rm screetsec/sudomy:v1.1.9-dev -d {domain}"
    return run_docker_command(sudomy_cmd)


def run_reconftw_and_append(domain, output_path):
    run_reconftw_scan(domain)
    append_to_oui_txt(domain, output_path)


def run_and_process_curl_command(domain, output_path):
    curl_cmd = f"curl -s \"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey\""

    process = subprocess.Popen(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = process.communicate()

    curl_output = output.decode('utf-8', 'ignore')

    processed_curl_output = "\n".join(curl_output.splitlines())

    output_file_path = os.path.join(output_path, "oui.txt")
    with open(output_file_path, "a") as file:
        file.write(processed_curl_output)


def run_crt_scan(domain, output_path):
    crt_cmd = f"./crt.sh -d {domain}"
    crt_output = run_docker_command(crt_cmd)
    append_to_file(os.path.join(output_path, "oui.txt"), crt_output)


def get_asn(ip):
    try:
        result = subprocess.run(['as-lookup', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if "No routing origin data" in result.stdout:
            return None
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_asn_shadowserver(ip):
    try:
        result = subprocess.run(['as-lookup', '-s', 'shadowserver', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return None


def tester_sous_domaine(sous_domaine, sortie, verrou):
    for protocole in ['http://', 'https://']:
        url = protocole + sous_domaine
        try:
            response = requests.get(url, timeout=5)
            with verrou:
                sortie.write(url + '\n')
            break
        except requests.RequestException:
            continue

def tester_sous_domaines(fichier, fichier_sortie):
    verrou = Lock()
    with open(fichier, 'r') as file, open(fichier_sortie, 'w') as sortie:
        sous_domaines = [ligne.strip() for ligne in file]
        with ThreadPoolExecutor(max_workers=10) as executor:
            [executor.submit(tester_sous_domaine, sd, sortie, verrou) for sd in sous_domaines]



def find_and_append_subdomains(output_dir, domain, filename):
    pattern = os.path.join(output_dir, "*", domain, "subdomain.txt")

    subdomain_files = glob.glob(pattern)
    if subdomain_files:
        for sub_file in subdomain_files:
            with open(sub_file, "r") as file:
                content = file.read()
                append_to_file(filename, content)
    else:
        print(f"Aucun subdomain.txt trouvé pour le domaine : {domain}")


def run_with_spinner(command, spinner_text):
    with Halo(text=spinner_text, spinner='dots'):
        return command()


def delete_directories(directories):
    for directory in directories:
        try:
            shutil.rmtree(directory)
        except OSError as e:
            pass


def append_to_file(filename, content):
    with open(filename, "a") as file:
        file.write(content)


def create_directory_structure(domain):
    parts = domain.split('.')
    main_dir = parts[0]
    sub_dir = parts[1] if len(parts) > 1 else 'generic'

    path = os.path.join(main_dir, sub_dir)
    os.makedirs(path, exist_ok=True)
    return path


def create_recon_directory():
    if not os.path.exists("Recon"):
        os.makedirs("Recon")


def append_to_oui_txt(domain, output_path):
    subdomains_file_path = f"Recon/{domain}/subdomains/subdomains.txt"
    oui_txt_path = os.path.join(output_path, "oui.txt")
    if os.path.exists(subdomains_file_path):
        with open(subdomains_file_path, "r") as file:
            content = file.read()
        with open(oui_txt_path, "a") as file:
            file.write(content)
    else:
        print(f"Le fichier {subdomains_file_path} n'existe pas.")


def extract_asn(full_asn_string):
    match = re.search(r'AS\d+ \| [A-Z]{2} \| .+', full_asn_string)
    if match:
        return match.group(0)
    else:
        return None


def delete_files(file_paths):
    for file_path in file_paths:
        try:
            os.remove(file_path)
        except OSError as e:
            print(f"Error deleting file {file_path}: {e.strerror}")


def extract_unique_ips(json_file_path, output_file_path4):
    unique_ips = set()

    with open(json_file_path, 'r') as file:
        data = json.load(file)

        for key in data:
            for entry in data[key]:
                ip = entry['IP']
                unique_ips.add(ip)

    with open(output_file_path4, 'w') as file:
        for ip in unique_ips:
            file.write(ip + '\n')


def parse_text_to_json(file_path):
    with open(os.path.join(output_path, file_path), 'r') as file:
        lines = file.readlines()

    asn_data = {}
    current_asn = None
    current_asn_name = ""

    for line in lines:
        if line.startswith('ASN:'):
            current_asn = line.strip().replace('ASN: ', '')
            asn_data[current_asn] = []
        elif line.strip().startswith('IP:'):
            ip_parts = line.strip().split(' - Domaines liés: ')
            ip = ip_parts[0].strip().replace('IP: ', '')
            domains = ip_parts[1].split(', ') if len(ip_parts) > 1 else []
            asn_data[current_asn].append({'IP': ip, 'SubDomains': domains})

    return asn_data


def validate_domain(domain_string):
    domains = domain_string.split(',')
    validated_domains = []
    for domain in domains:
        domain = re.sub(r'^https?://', '', domain)

        if domain.count('.') < 1:
            raise argparse.ArgumentTypeError(f"Invalid domain: {domain}")

        validated_domains.append(domain)

    return validated_domains

def zip_screenshots(output_directory, zip_name):
    shutil.make_archive(zip_name, 'zip', output_directory)

def process_curl_output(curl_output):
    lines = curl_output.splitlines()
    processed_lines = set()
    for line in lines:
        line = line.replace('http://', '').replace('https://', '').split('/')[0]
        line = line.split(':')[0].replace('www.', '')
        processed_lines.add(line)
    return sorted(processed_lines)


def upload_file(filepath):
    upload_command = f"curl -s -T {filepath} https://pype.sellan.fr"
    try:
        result = subprocess.run(upload_command, shell=True, stdout=subprocess.PIPE, text=True, check=True)
        output_lines = result.stdout.strip().split('\n')
        return output_lines[-1]
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'upload du fichier {filepath}: {e}")
        return None


def parse_arguments():
    parser = argparse.ArgumentParser(description='Recognition tool for sub-domains, IPs and ASNs linked to a domain')
    parser.add_argument('-d', '--domains', type=validate_domain,
                        help='Specifies the domain name to be scanned. Example: -d google.com')
    parser.add_argument('-f', '--file', type=str,
                        help='Specifies a file with one domain per line to be scanned. Example: -f domains.txt')
    parser.add_argument('-u', '--upload', action='store_true',
                        help='Activate the upload of results to https://pype.sellan.fr')
    parser.add_argument('-o', '--org', type=str,
                        help='Specifies the organization name for the JSON output. Example: -o Leclerc')
    parser.add_argument('-vs', '--validsubdo', action='store_true',
                        help='Do an additional scan to get only the subdomains that respond')
    parser.add_argument('-gw', '--gowitness', action='store_true',
                        help='Activate Gowitness for screenshotting the webpages of valid subdomains')
    parser.add_argument('-zs', '--zipscreenshot', action='store_true',
                        help='Zip the screenshots taken by Gowitness and upload them to pype.sellan.fr')
    return parser


if __name__ == "__main__":
    parser = parse_arguments()

    if len(sys.argv) == 1 or 'help' in sys.argv:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        args = parser.parse_args()
    except argparse.ArgumentTypeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    domains = args.domains if args.domains else []

    if args.file:
        with open(args.file, 'r') as file:
            domains.extend([line.strip() for line in file if line.strip()])
    org_name = args.org
    org_data = {org_name: []} if org_name else None
    upload = args.upload
    validsubdo = args.validsubdo
    gowitness = args.gowitness
    zipscreenshot = args.zipscreenshot

    for domain in domains:

        create_recon_directory()

        nomjson = domain
        output_path = create_directory_structure(domain)

        docker_cmd = f"docker run --rm hessman/rcrt -t {domain} -r -l 1 -d cloudflare.com cloudflaressl.com"
        docker_output = run_with_spinner(lambda: run_docker_command(docker_cmd), "Scan rcrt in progress")
        with open(os.path.join(output_path, "oui.txt"), "w") as file:
            file.write(docker_output)

        subfinder_output = run_with_spinner(lambda: run_subfinder_and_tools(domain), "Scan subfinder in progress")
        with open(os.path.join(output_path, "oui.txt"), "a") as file:
            file.write(subfinder_output)

        sudomy_output = run_with_spinner(lambda: run_sudomy_scan(domain), "Scan sudomy in progress")

        append_to_file(os.path.join(output_path, "oui.txt"), open(os.path.join(output_path, "exc2.txt"), "r").read())
        find_and_append_subdomains("output", domain, os.path.join(output_path, "oui.txt"))

        run_with_spinner(lambda: run_reconftw_and_append(domain, output_path), "Scan reconftw in progress")

        run_with_spinner(lambda: run_and_process_curl_command(domain, output_path), "Scan Web archive in progress")

        run_with_spinner(lambda: run_crt_scan(domain, output_path), "Scan crt.sh in progress")

        with open(os.path.join(output_path, "oui.txt"), 'r') as file:
            content = file.read()

        urls = re.findall(r'\b(?:[\w-]+\.)+{}\b'.format({domain}.pop()), content)

        unique_urls = list(set(urls))

        unique_urls.sort()

        with open(os.path.join(output_path, 'urls_uniques.txt'), 'w') as file:
            for url in unique_urls:
                file.write(url + '\n')

        with open(os.path.join(output_path, 'urls_uniques.txt'), 'r') as file:
            domains = [line.strip() for line in file if line.strip()]

        ip_domain_map = {}

        asn_ip_domain_map = {}

        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                if ip in ip_domain_map:
                    ip_domain_map[ip].append(domain)
                else:
                    ip_domain_map[ip] = [domain]
            except socket.gaierror:
                pass

        asn_ip_domain_map_intermediate = {}

        ips_sans_asn = []

        for ip, domains in ip_domain_map.items():
            full_asn_string = get_asn(ip)
            if full_asn_string:
                asn_only = extract_asn(full_asn_string)
                if asn_only and asn_only not in asn_ip_domain_map_intermediate:
                    asn_ip_domain_map_intermediate[asn_only] = []
                asn_ip_domain_map_intermediate[asn_only].append((ip, domains))
            else:
                ips_sans_asn.append(ip)

        for ip in ips_sans_asn:
            asn_shadowserver = get_asn_shadowserver(ip)
            if asn_shadowserver:
                asn_only = extract_asn(asn_shadowserver)
                if asn_only:
                    if asn_only not in asn_ip_domain_map_intermediate:
                        asn_ip_domain_map_intermediate[asn_only] = []
                    asn_ip_domain_map_intermediate[asn_only].append((ip, ip_domain_map[ip]))

        with open(os.path.join(output_path, 'asn_ip_domain_map_clean.txt'), 'w') as file:
            for asn, ip_domains in asn_ip_domain_map_intermediate.items():
                file.write(f"ASN: {asn}\n")
                for ip, domains in ip_domains:
                    domain_list = ', '.join(domains)
                    file.write(f"  IP: {ip} - Domaines liés: {domain_list}\n")
                file.write("\n")

        file_path = 'asn_ip_domain_map_clean.txt'

        parsed_json = parse_text_to_json(file_path)

        json_filename = f"{nomjson}.ASN.json"
        json_file_path = os.path.join(output_path, json_filename)

        with open(json_file_path, 'w') as json_file:
            json.dump(parsed_json, json_file, indent=4)

        print(f"The data have been written in {json_filename}")

        files_to_delete = [os.path.join(output_path, 'asn_ip_domain_map_clean.txt'),
                        os.path.join(output_path, 'exc2.txt'),
                        os.path.join(output_path, 'oui.txt')]
        delete_files(files_to_delete)

        delete_directories(["output", "Recon"])

        with open(json_file_path, 'r') as file:
            data = json.load(file)

        nombre_asn = len(data)
        nombre_ips = sum(len(asn) for asn in data.values())
        nombre_domaines = sum(len(ip['SubDomains']) for asn in data.values() for ip in asn)

        output_file_path4 = os.path.join(output_path, 'ips_unique.txt')
        extract_unique_ips(json_file_path, output_file_path4)

        print(colored(f"Number of ASNs found : {nombre_asn}", 'red'))
        print(colored(f"Number of IPs found : {nombre_ips}", 'green'))
        print(colored(f"Number of subdomains found : {nombre_domaines}", 'blue'))
        print()

        if upload:
            url = upload_file(json_file_path)
            if url:
                print(f"File uploaded successfully : {url}")
                print()

        if org_name:
            with open(json_file_path, 'r') as json_file:
                domain_data = json.load(json_file)
        
            extracted = tldextract.extract(domain)
            clean_domain = f"{extracted.domain}.{extracted.suffix}"
        
            org_data[org_name].append({clean_domain: domain_data})
    if org_data:
        with open(f"{org_name}.json", 'w') as json_file:
            json.dump(org_data, json_file, indent=4)

        jsonorg_file_path = f"{org_name}.json"
        all_subdomains = set()
        all_ips = set()

        with open(jsonorg_file_path, 'r') as file:
            data = json.load(file)
            for org, domains in data.items():
                for domain_info in domains:
                    for domain, asns in domain_info.items():
                        all_subdomains.add(domain)
                        for asn, ips in asns.items():
                            for ip_info in ips:
                                ip = ip_info["IP"]
                                all_ips.add(ip)
                                for subdomain in ip_info.get("SubDomains", []):
                                    all_subdomains.add(subdomain)

        sorted_ips = sorted(all_ips, key=lambda ip: tuple(int(part) for part in ip.split('.')))

        with open(f"{org_name}_allsubdomainurl.txt", 'w') as file:
            for subdomain in sorted(all_subdomains):
                file.write(subdomain + '\n')

        with open(f"{org_name}_allips.txt", 'w') as file:
            for ip in sorted_ips:
                file.write(ip + '\n')

        if validsubdo:
            run_with_spinner(
                lambda: tester_sous_domaines(f"{org_name}_allsubdomainurl.txt", f"{org_name}_valid_subdomains.txt"),
                "Subdomain cleanup in progress...")

        if validsubdo and gowitness:
            gowitness_command = lambda: subprocess.run(
                f"gowitness --disable-db --fullpage file -f {f'{org_name}_valid_subdomains.txt'}", shell=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run_with_spinner(gowitness_command, "Screenshots in progress...")

            

        if validsubdo and zipscreenshot and gowitness:
            def zip_and_upload():
                screenshots_directory = "screenshots"
                zip_name = f"{org_name}_screenshots"
                zip_screenshots(screenshots_directory, zip_name)
                zip_file_path = f"{zip_name}.zip"
                return upload_file(zip_file_path)


            upload_url = run_with_spinner(zip_and_upload, "Archiving and uploading screenshots in progress...")
            if upload_url:
                print(f"Screenshot ZIP file uploaded successfully : {upload_url}")
            else:
                print("ZIP file upload failed.")

    if upload and org_name:
        org_json_path = f"{org_name}.json"
        if os.path.exists(org_json_path):
            url = upload_file(org_json_path)
            if url:
                print(f"Complete JSON file of the organization uploaded successfully : {url}")
        else:
            print(f"The JSON file for organization {org_name} does not exist or could not be found.")

