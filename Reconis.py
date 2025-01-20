#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import shutil
import logging
import json
import atexit
import xml.etree.ElementTree as ET
import readline
import glob
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Constants and Configurations
CURRENT_DIR = os.getcwd()
OUTPUT_DIR = os.path.join(CURRENT_DIR, 'output')
LOG_DIR = os.path.join(OUTPUT_DIR, 'logs')
SCAN_DIR = os.path.join(OUTPUT_DIR, 'scans')
NMAP_SCAN_DIR = os.path.join(SCAN_DIR, 'nmap')
SEARCHSPLOIT_DIR = os.path.join(SCAN_DIR, 'searchsploit')
ENUM4LINUX_DIR = os.path.join(SCAN_DIR, 'enum4linux')
CHERRYTREE_DIR = os.path.join(OUTPUT_DIR, 'cherrytree')
DEFAULT_DIR_BUSTER_FILE = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
TOOLS = ["nmap", "feroxbuster", "enum4linux", "searchsploit"]

# Create necessary directories
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(NMAP_SCAN_DIR, exist_ok=True)
os.makedirs(SEARCHSPLOIT_DIR, exist_ok=True)
os.makedirs(ENUM4LINUX_DIR, exist_ok=True)
os.makedirs(CHERRYTREE_DIR, exist_ok=True)

# Initialize loggers
info_logger = logging.getLogger('ReconisInfoLogger')
info_logger.setLevel(logging.INFO)

error_logger = logging.getLogger('ReconisErrorLogger')
error_logger.setLevel(logging.ERROR)

command_logger = logging.getLogger('ReconisCommandLogger')
command_logger.setLevel(logging.INFO)

# Create handlers
info_handler = logging.FileHandler(os.path.join(LOG_DIR, 'info.log'))
error_handler = logging.FileHandler(os.path.join(LOG_DIR, 'error.log'))
command_handler = logging.FileHandler(os.path.join(LOG_DIR, 'commands.log'))

# Create formatters
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

info_handler.setFormatter(formatter)
error_handler.setFormatter(formatter)
command_handler.setFormatter(formatter)

# Add handlers to loggers
info_logger.addHandler(info_handler)
error_logger.addHandler(error_handler)
command_logger.addHandler(command_handler)

# Utility Functions

def log_command(command, command_type=""):
    command_message = f"=== {command_type} ===\n{command}\n{'=' * 25}\n"
    command_logger.info(command_message)

def log_info(message):
    info_logger.info(message)

def log_error(message):
    error_logger.error(message)

def reset_terminal():
    os.system('stty sane')
    os.system('stty erase "^h"')

def setup_readline():
    def complete(text, state):
        return (glob.glob(text + '*') + [None])[state]

    readline.set_completer(complete)
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def read_file(filepath):
    with open(filepath, 'r') as file:
        return file.read()

def save_results(output, filepath):
    with open(filepath, 'w') as file:
        file.write(output)

def run_in_new_terminal(command):
    terminals = [
        {
            'name': 'gnome-terminal',
            'args': ['--', 'bash', '-c', f'{command}; exec bash']
        },
        {
            'name': 'xfce4-terminal',
            'args': ['--hold', '-e', f'bash -c "{command}; exec bash"']
        },
        {
            'name': 'xterm',
            'args': ['-hold', '-e', f'{command}; exec bash']
        },
    ]
    for term in terminals:
        if shutil.which(term['name']):
            try:
                full_command = [term['name']] + term['args']
                subprocess.Popen(full_command)
                return
            except Exception as e:
                log_error(f"Error running {term['name']}: {e}")
    print(Fore.RED + "No supported terminal emulator found to run commands in new terminal windows.")
    log_error("No supported terminal emulator found to run commands in new terminal windows.")

def print_separator():
    print(Fore.CYAN + "+" * 60)

# Classes

class ToolChecker:
    @staticmethod
    def check_tools():
        missing_tools = [tool for tool in TOOLS if not shutil.which(tool)]
        if missing_tools:
            print(Fore.RED + "The following tools are missing: " + ", ".join(missing_tools))
            return False
        return True

class NmapScanner:
    def __init__(self, ip):
        self.ip = ip
        self.open_ports = []
        self.detailed_scan_results = ""
        self.xml_filename = ""
        self.normal_filename = ""
        self.quick_scan_normal_filename = ""
        self.quick_scan_xml_filename = ""

    def run_scan(self, scan_options, protocol='tcp', scan_type='full', output_xml=False, output_normal=False):
        xml_filename = None
        normal_filename = None
        command = ["nmap"] + scan_options.split() + [self.ip]
        if output_xml:
            xml_filename = os.path.join(
                NMAP_SCAN_DIR,
                f"nmap_output_{scan_type}_{protocol}_{self.ip.replace('.', '_')}.xml"
            )
            command += ["-oX", xml_filename]
        if output_normal:
            normal_filename = os.path.join(
                NMAP_SCAN_DIR,
                f"nmap_output_{scan_type}_{protocol}_{self.ip.replace('.', '_')}.txt"
            )
            command += ["-oN", normal_filename]
        log_command(' '.join(command), "Nmap Scan")
        log_info(f"Running Nmap {scan_type} {protocol.upper()} scan: {' '.join(command)}")
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate()
        return_code = process.returncode

        if return_code != 0:
            print(
                Fore.RED
                + f"Error during Nmap {scan_type} {protocol.upper()} scan on {self.ip}: {stderr.strip()}"
            )
            log_error(
                f"Error during Nmap {scan_type} {protocol.upper()} scan on {self.ip}: {stderr.strip()}"
            )
            error_occurred = True
        else:
            error_occurred = False
            if stderr.strip():
                # Log stderr messages as warnings or info
                log_info(
                    f"Nmap {scan_type} {protocol.upper()} scan warnings: {stderr.strip()}"
                )
        return stdout, xml_filename, normal_filename, error_occurred

    def extract_open_ports(self, nmap_output_file, protocol='tcp'):
        try:
            tree = ET.parse(nmap_output_file)
            root = tree.getroot()
            open_ports = []
            for host in root.findall('host'):
                if host.find('ports') is not None:
                    for port in host.find('ports').findall('port'):
                        state = port.find('state').attrib['state']
                        if state == 'open':
                            port_id = port.attrib['portid']
                            service_elem = port.find('service')
                            if service_elem is not None:
                                service = service_elem.attrib.get('name', 'unknown')
                                product = service_elem.attrib.get('product', '')
                                version = service_elem.attrib.get('version', '')
                                extra_info = service_elem.attrib.get('extrainfo', '')
                                banner = f"{product} {version} {extra_info}".strip()
                                version_info = f"{product} {version} {extra_info}".strip()
                            else:
                                service = 'unknown'
                                banner = ''
                                version_info = ''
                            open_ports.append(
                                (port_id, service.strip(), banner.strip(), version_info.strip())
                            )
            return open_ports
        except ET.ParseError:
            print(Fore.RED + "Error parsing Nmap XML output.")
            log_error("Error parsing Nmap XML output.")
            return []
        except Exception as e:
            print(Fore.RED + f"Unexpected error during parsing Nmap XML output: {e}")
            log_error(f"Unexpected error during parsing Nmap XML output: {e}")
            return []

    def handle_scanning(self, filename, protocol='tcp'):
        quickscan_options = "-T4 -Pn --open -p-"
        if protocol == 'udp':
            quickscan_options = "-sU -T4 --open --top-ports 100"
        print(f"[+] Starting quick {protocol.upper()} scan on {self.ip}...")
        quick_scan_results, quick_xml_filename, quick_normal_filename, quick_scan_error = self.run_scan(
            quickscan_options, protocol, scan_type='quick', output_xml=True, output_normal=True
        )
        if quick_scan_error:
            print(
                Fore.RED
                + f"Error encountered during quick {protocol.upper()} scan. Check logs for details."
            )
            log_error(f"Error encountered during quick {protocol.upper()} scan.")
        else:
            print(f"[✓] Quick {protocol.upper()} scan completed.")
        print_separator()

        self.quick_scan_xml_filename = quick_xml_filename
        self.quick_scan_normal_filename = quick_normal_filename

        if quick_xml_filename and os.path.exists(quick_xml_filename):
            self.open_ports = self.extract_open_ports(quick_xml_filename, protocol)
        else:
            print(Fore.RED + f"Quick scan XML file {quick_xml_filename} not found.")
            log_error(f"Quick scan XML file {quick_xml_filename} not found.")
            self.open_ports = []

        if not self.open_ports:
            print(
                Fore.YELLOW
                + f"No open {protocol.upper()} ports found. Skipping detailed scan."
            )
            return "", "", "", True

        ports = ','.join([port for port, _, _, _ in self.open_ports])
        fullscan_options = f"-T4 -Pn -A -p{ports}"
        if protocol == 'udp':
            fullscan_options = f"-sU -A -T4 -p{ports}"
        print(
            f"[+] Starting detailed {protocol.upper()} scan on {len(self.open_ports)} open ports..."
        )
        self.detailed_scan_results, self.xml_filename, self.normal_filename, full_scan_error = self.run_scan(
            fullscan_options, protocol, scan_type='full', output_xml=True, output_normal=True
        )
        if full_scan_error:
            print(
                Fore.RED
                + f"Error encountered during detailed {protocol.upper()} scan. Check logs for details."
            )
            log_error(f"Error encountered during detailed {protocol.upper()} scan.")
        else:
            print(f"[✓] Detailed {protocol.upper()} scan completed.")
        return self.detailed_scan_results, self.xml_filename, self.normal_filename, False

class FeroxbusterScanner:
    def __init__(self, ip, open_ports, domains_list, custom_wordlist=None):
        self.ip = ip
        self.open_ports = open_ports
        self.custom_wordlist = custom_wordlist
        self.domains_list = domains_list

    @staticmethod
    def is_http_service(service, banner, port):
        http_indicators = ["http", "https", "nginx", "apache", "web", "www", "gitea", "httpd"]
        service_info = f"{service} {banner}".lower()
        # Check if any HTTP indicator is in service name or banner
        if any(indicator in service_info for indicator in http_indicators):
            return True
        # Common HTTP ports
        common_http_ports = ['80', '81', '443', '8080', '8000', '8443', '3000', '5000', '8008', '8888']
        if port in common_http_ports:
            return True
        return False

    @staticmethod
    def determine_extensions(service_banner):
        extension_mapping = {
            "apache": ["php", "html", "js", "css", "xml"],
            "nginx": ["html", "js", "css", "php"],
            "iis": ["asp", "aspx", "html", "js", "css"],
            "wordpress": ["php", "html", "css", "js", "xml"],
            "joomla": ["php", "html", "js"],
            "drupal": ["php", "html", "js"],
            "gitea": ["go", "html", "js", "css"]
        }
        default_extensions = ["html", "php", "js"]
        selected_extensions = set(default_extensions)
        for key, extensions in extension_mapping.items():
            if key in service_banner.lower():
                selected_extensions.update(extensions)
        return list(selected_extensions)

    def create_feroxbuster_command(self, port, service, banner):
        best_domain = HostUpdater.determine_best_domain(port, self.ip, self.domains_list)
        extensions = self.determine_extensions(banner)
        extensions_string = ",".join(extensions)
        status_codes = "200,301,302,307,308,403,401"
        wordlist = self.custom_wordlist if self.custom_wordlist else DEFAULT_DIR_BUSTER_FILE
        if wordlist and not os.path.exists(wordlist):
            print(Fore.RED + f"Wordlist file {wordlist} does not exist. Using feroxbuster's default wordlist.")
            wordlist = None
        wordlist_option = f"-w {wordlist}" if wordlist else ""

        # Determine protocol
        protocol = 'http'
        if 'https' in service.lower() or 'https' in banner.lower() or port in ['443', '8443']:
            protocol = 'https'

        return f"feroxbuster --url {protocol}://{best_domain}:{port} {wordlist_option} -x {extensions_string} -s {status_codes} -t 50 -r"

    def execute(self):
        print(f"[+] Starting Feroxbuster scans...")
        for port, service, banner, _ in self.open_ports:
            if self.is_http_service(service, banner, port):
                feroxbuster_cmd = self.create_feroxbuster_command(port, service, banner)
                run_in_new_terminal(feroxbuster_cmd)
        print(f"[✓] Feroxbuster scans initiated in new terminal windows.")

class VulnScanner:
    def __init__(self, ip, open_ports, filename, protocol='tcp'):
        self.ip = ip
        self.open_ports = open_ports
        self.filename = filename
        self.protocol = protocol
        self.vuln_scan_data = {}

    def run_vuln_scan(self):
        if not self.open_ports:
            log_info(f"No open {self.protocol.upper()} ports found. Skipping vulnerability scan.")
            print(Fore.YELLOW + f"No open {self.protocol.upper()} ports found. Skipping vulnerability scan.")
            return (self.protocol, {})
        vuln_scan_options = "-sV --script=vuln"
        ports = ','.join([port for port, _, _, _ in self.open_ports])
        command = ["nmap", "-Pn"]
        if self.protocol == 'udp':
            command.append("-sU")
        command += vuln_scan_options.split() + ["-p", ports, self.ip]
        normal_output_file = os.path.join(NMAP_SCAN_DIR, f"{self.filename}_full_{self.protocol}_vulnscan.txt")
        command += ["-oN", normal_output_file]
        log_command(' '.join(command), "Nmap Vulnerability Scan")
        log_info(f"Running {self.protocol.upper()} vulnerability scan: {' '.join(command)}")
        print(f"[+] Running Nmap {self.protocol.upper()} vulnerability scan on ports: {ports}")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(Fore.RED + f"Error during Nmap {self.protocol.upper()} vulnerability scan: {result.stderr.strip()}")
            log_error(f"Error during {self.protocol.upper()} vulnerability scan: {result.stderr.strip()}")
            return (self.protocol, {})
        else:
            if result.stderr.strip():
                log_info(f"Nmap {self.protocol.upper()} vulnerability scan warnings: {result.stderr.strip()}")

        save_results(result.stdout, normal_output_file)
        log_info(f"Vulnerability scan complete. Results saved.")
        print(f"[✓] Nmap {self.protocol.upper()} vulnerability scan completed.")
        cleaned_output = self.process_nmap_file(result.stdout)
        self.vuln_scan_data = self.parse_vuln_scan_output(cleaned_output)
        return (self.protocol, self.vuln_scan_data)

    def process_nmap_file(self, data):
        port_details_regex = re.compile(r'^(\d+/\w+)\s+open')
        end_pattern = re.compile(r'^Service detection performed\.')
        unrecognized_pattern = re.compile(r'^\d+ service unrecognized despite returning data')

        capturing = False
        current_port = None
        ports_info = {}

        for line in data.splitlines():
            line = line.strip()

            if end_pattern.match(line) or unrecognized_pattern.match(line):
                break

            port_match = port_details_regex.match(line)
            if port_match:
                current_port = port_match.group(1)
                ports_info[current_port] = {
                    'details': line + '\n',
                    'additional_info': ''
                }
                capturing = True
            elif capturing and current_port:
                if 'service unrecognized despite returning data' in line:
                    continue
                ports_info[current_port]['additional_info'] += line + '\n'

        cleaned_data = ""
        for port, info in ports_info.items():
            cleaned_data += f"Port: {port}\nDetails:\n{info['details']}"
            if info['additional_info'].strip():
                cleaned_data += f"Additional Info:\n{info['additional_info']}"
            cleaned_data += "----------\n"

        return cleaned_data

    def parse_vuln_scan_output(self, data):
        ports_info = {}
        lines = data.split('\n')
        current_port = None

        for line in lines:
            line = line.strip()
            if line.startswith('Port:'):
                current_port = line.split()[1].split('/')[0]
                ports_info[current_port] = []
            elif current_port and not line.startswith('----------'):
                ports_info[current_port].append(line)

        for port, info_lines in ports_info.items():
            ports_info[port] = "\n".join(info_lines) if info_lines else "No vulnerability data"

        return ports_info

class SearchsploitAnalyzer:
    @staticmethod
    def execute(xml_filename, protocol='tcp'):
        if not xml_filename:
            print(Fore.YELLOW + f"No Nmap XML file for {protocol.upper()}. Skipping Searchsploit analysis.")
            return
        print(f"[+] Running Searchsploit for {protocol.upper()}...")
        searchsploit_output_file = os.path.join(SEARCHSPLOIT_DIR, f"searchsploit_{protocol}.json")
        searchsploit_command = ["searchsploit", "--nmap", xml_filename, "-j"]
        log_command(' '.join(searchsploit_command), f"Searchsploit {protocol.upper()}")
        try:
            result = subprocess.run(searchsploit_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                print(Fore.RED + f"Error during Searchsploit {protocol.upper()} analysis.")
                log_error(f"Error during Searchsploit {protocol.upper()} analysis. Stderr: {result.stderr.strip()}")
                return
            stdout_content = result.stdout.strip()
            if not stdout_content:
                print(Fore.YELLOW + f"No Searchsploit results for {protocol.upper()}.")
                return
            # Save stdout to file
            with open(searchsploit_output_file, 'w') as file:
                file.write(stdout_content)
            # Process the results
            SearchsploitAnalyzer.process_results(searchsploit_output_file)
            print(f"[✓] Searchsploit analysis for {protocol.upper()} completed.")
        except Exception as e:
            print(Fore.RED + f"Exception during Searchsploit execution: {str(e)}")
            log_error(f"Exception during Searchsploit execution: {str(e)}")

    @staticmethod
    def process_results(json_file):
        try:
            with open(json_file, 'r') as file:
                content = file.read()
            decoder = json.JSONDecoder()
            pos = 0
            filtered_data = {}
            content_length = len(content)
            while pos < content_length:
                # Skip any whitespace or newlines
                while pos < content_length and content[pos] in [' ', '\n', '\r', '\t']:
                    pos += 1
                if pos >= content_length:
                    break
                data, idx = decoder.raw_decode(content, pos)
                pos = idx
                for exploit in data.get('RESULTS_EXPLOIT', []):
                    port = exploit.get('Port', '')
                    title = exploit.get('Title', '')
                    path = exploit.get('Path', '')
                    if port not in filtered_data:
                        filtered_data[port] = []
                    filtered_data[port].append({
                        'title': title,
                        'path': path
                    })
        except json.JSONDecodeError as e:
            print(Fore.RED + f"Error processing Searchsploit results: {str(e)}")
            log_error(f"Error processing Searchsploit results: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"Unexpected error processing Searchsploit results: {str(e)}")
            log_error(f"Unexpected error processing Searchsploit results: {str(e)}")
        else:
            # Save the combined results
            with open(json_file, 'w') as file:
                json.dump(filtered_data, file, indent=4)

    @staticmethod
    def map_searchsploit_to_ports(port_vulnerabilities, open_ports, searchsploit_results_file):
        if not os.path.exists(searchsploit_results_file):
            for port, service, _, version_info in open_ports:
                if port not in port_vulnerabilities:
                    port_vulnerabilities[port] = {}
                port_vulnerabilities[port].update({
                    'service': service,
                    'exploits': ['No exploits found in Searchsploit'],
                    'version_info': version_info
                })
            return

        with open(searchsploit_results_file, 'r') as file:
            searchsploit_data = json.load(file)

        for port, service, banner, version_info in open_ports:
            exploits = searchsploit_data.get(port, [])
            if port not in port_vulnerabilities:
                port_vulnerabilities[port] = {}
            port_vulnerabilities[port].update({
                "service": service,
                "exploits": exploits if exploits else ["No exploits found in Searchsploit"],
                "version_info": version_info
            })

        # Save the combined results
        with open(searchsploit_results_file, 'w') as file:
            json.dump(port_vulnerabilities, file, indent=4)

class Enum4LinuxScanner:
    @staticmethod
    def run(ip):
        print(f"[+] Running enum4linux...")
        command = ["enum4linux", "-a", ip]
        log_command(' '.join(command), "Enum4linux")
        log_info(f"Running enum4linux: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return_code = process.returncode
        enum4linux_output_file = os.path.join(ENUM4LINUX_DIR, 'enum4linux_output.txt')
        save_results(stdout, enum4linux_output_file)
        print(f"[✓] Enum4linux scan completed.")
        if return_code != 0:
            print(Fore.RED + f"Error during enum4linux scan: {stderr.strip()}")
            log_error(f"Error during enum4linux scan: {stderr.strip()}")
        else:
            if stderr.strip():
                log_info(f"Enum4linux scan warnings: {stderr.strip()}")
        return stdout

class HostUpdater:
    @staticmethod
    def update_hosts_file(ip_address, nmap_xml_output_file):
        try:
            tree = ET.parse(nmap_xml_output_file)
            root = tree.getroot()
        except (FileNotFoundError, TypeError, ET.ParseError):
            print(Fore.RED + f"Error: File {nmap_xml_output_file} not found or invalid XML.")
            log_error(f"Error: File {nmap_xml_output_file} not found or invalid XML.")
            return []
        
        hostnames = HostUpdater.extract_hostnames(root, ip_address)
        unique_hostnames = list(set(hostnames))

        if ip_address and unique_hostnames:
            try:
                with open("/etc/hosts", "r") as hosts_file:
                    current_hosts = hosts_file.readlines()
            except PermissionError:
                print(Fore.RED + "Permission denied when accessing /etc/hosts.")
                log_error("Permission denied when accessing /etc/hosts.")
                return unique_hostnames
            except FileNotFoundError:
                current_hosts = []

            ip_indices = [i for i, line in enumerate(current_hosts) if line.startswith(ip_address)]
            existing_hostnames = set()

            for index in ip_indices:
                existing_hostnames.update(current_hosts[index].strip().split()[1:])

            missing_hostnames = [hostname for hostname in unique_hostnames if hostname not in existing_hostnames]

            if missing_hostnames:
                if ip_indices:
                    # Remove any duplicates before updating
                    all_hostnames = current_hosts[ip_indices[0]].strip().split()[1:] + missing_hostnames
                    all_hostnames = list(set(all_hostnames))
                    current_hosts[ip_indices[0]] = ip_address + " " + " ".join(all_hostnames) + "\n"
                else:
                    new_entry = f"{ip_address} " + " ".join(unique_hostnames) + "\n"
                    current_hosts.append(new_entry)

                try:
                    with open("/etc/hosts", "w") as hosts_file:
                        hosts_file.writelines(current_hosts)
                    print_separator()
                    print(Fore.GREEN + f"Added the following entries to /etc/hosts: {', '.join(missing_hostnames)}")
                    log_info(f"Added the following entries to /etc/hosts: {', '.join(missing_hostnames)}")
                except PermissionError:
                    print(Fore.RED + "Permission denied when writing to /etc/hosts.")
                    log_error("Permission denied when writing to /etc/hosts.")
            else:
                print_separator()
                print(Fore.YELLOW + "No new entries were added to /etc/hosts.")
                log_info("No new entries were added to /etc/hosts.")
        else:
            print_separator()
            print(Fore.YELLOW + "No new entries were added to /etc/hosts.")
            log_info("No new entries were added to /etc/hosts.")
        return unique_hostnames

    @staticmethod
    def extract_hostnames(root, ip_address):
        hostnames = set()
        try:
            # Iterate over each host in the Nmap XML output
            for host in root.findall('host'):
                # Extract hostnames from the <hostnames> section
                for hostname in host.findall('hostnames/hostname'):
                    name = hostname.get('name')
                    if name and name != ip_address:
                        hostnames.add(name)

                # Extract hostnames from SSL certificate information in <ports>
                for port in host.findall('ports/port'):
                    service = port.find('service')
                    if service is not None:
                        # Extract hostnames from service hostname attribute
                        service_hostname = service.get('hostname')
                        if service_hostname and service_hostname != ip_address:
                            hostnames.add(service_hostname)

                        # Extract hostnames from SSL certificates in service scripts
                        for script in port.findall('script'):
                            if script.get('id') in ['ssl-cert', 'tls-cert']:
                                output = script.get('output', '')

                                # Extract commonName (CN)
                                cn_matches = re.findall(r'commonName=([^\s,;/]+)', output)
                                for cn in cn_matches:
                                    if cn and cn != ip_address:
                                        hostnames.add(cn)

                                # Extract DNS names from SAN (Subject Alternative Name)
                                dns_matches = re.findall(r'DNS:([^\s,;/]+)', output)
                                for dns_name in dns_matches:
                                    if dns_name and dns_name != ip_address:
                                        hostnames.add(dns_name)

                # Extract hostnames from SSL certificates at the host level
                for script in host.findall('hostscript/script'):
                    if script.get('id') in ['ssl-cert', 'tls-cert']:
                        output = script.get('output', '')

                        # Extract commonName (CN)
                        cn_matches = re.findall(r'commonName=([^\s,;/]+)', output)
                        for cn in cn_matches:
                            if cn and cn != ip_address:
                                hostnames.add(cn)

                        # Extract DNS names from SAN
                        dns_matches = re.findall(r'DNS:([^\s,;/]+)', output)
                        for dns_name in dns_matches:
                            if dns_name and dns_name != ip_address:
                                hostnames.add(dns_name)

                # Extract hostnames from service info
                for script in host.findall('script'):
                    output = script.get('output', '')

                    # Extract hostnames from general script output
                    host_matches = re.findall(r'Host:\s*([^\s;]+)', output)
                    for host_match in host_matches:
                        if host_match and host_match != ip_address:
                            hostnames.add(host_match)

            return list(hostnames)
        except Exception as e:
            print(Fore.RED + f"Error extracting hostnames from XML: {e}")
            log_error(f"Error extracting hostnames from XML: {e}")
            return []




    @staticmethod
    def extract_redirects(nmap_output):
        redirects = re.findall(r'Did not follow redirect to (http[s]?://\S+)', nmap_output)
        redirect_hostnames = [re.sub(r'^http[s]?://', '', redirect).split('/')[0] for redirect in redirects]
        return redirect_hostnames

    @staticmethod
    def score_domain(domain, port, ip):
        url = f"http://{domain}:{port}"
        score = 0

        try:
            curl_command = ["curl", "-I", "--connect-timeout", "3", url]
            curl_output = subprocess.run(curl_command, capture_output=True, text=True)
            curl_stdout = curl_output.stdout.strip()

            status_code = None
            for line in curl_stdout.splitlines():
                if line.startswith("HTTP/"):
                    status_code = int(line.split()[1])
                    break

            if status_code == 200:
                score += 50
            elif status_code in [301, 302]:
                score += 30
                if domain in curl_stdout:
                    score += 40
                else:
                    score += 20
            elif status_code == 403:
                score += 10
            elif status_code == 404:
                score += 0
            else:
                score += 5

            content_length = None
            for line in curl_stdout.splitlines():
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split()[1])
                    except ValueError:
                        content_length = None
                    break

            if content_length:
                if content_length > 1000:
                    score += 20
                else:
                    score += 10

            if "Set-Cookie" in curl_stdout:
                score += 20

        except Exception as e:
            log_error(f"Failed to score {domain}:{port} due to error: {str(e)}")

        return domain, score

    @staticmethod
    def determine_best_domain(port, ip, domains_list):
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_domain = {executor.submit(HostUpdater.score_domain, domain, port, ip): domain for domain in
                                domains_list + [ip]}
            best_domain = None
            best_score = -1
            ip_score = -1

            for future in as_completed(future_to_domain):
                domain, score = future.result()
                if domain == ip:
                    ip_score = score
                if score > best_score:
                    best_domain = domain
                    best_score = score

            if ip_score >= best_score:
                best_domain = ip

            log_info(f"Best domain for port {port} is {best_domain} with a score of {best_score}")

            return best_domain

class DocumentGenerator:
    @staticmethod
    def create_cherrytree_node(parent, title, text=""):
        """
        Creates a CherryTree node with the given title and text.
        """
        node = ET.SubElement(parent, 'node')
        node.set('name', title)
        rich_text = ET.SubElement(node, 'rich_text')
        rich_text.text = text
        return node

    @staticmethod
    def create_document_structure(ip, open_ports, open_udp_ports, detailed_scan_results, detailed_udp_scan_results,
                                  filename, tcp_port_vulnerabilities, udp_port_vulnerabilities,
                                  enum4linux_output=None):
        """
        Creates the CherryTree XML document structure without Pango markup, integrates vulnerabilities directly
        under each port node with version information and Searchsploit results.
        """
        print_separator()
        print(Fore.CYAN + "Creating document structure...")

        root = ET.Element('cherrytree')

        # Main Node
        main_node = DocumentGenerator.create_cherrytree_node(root, f"Target IP/Hostname: {ip}")

        # Scanning and Enumeration Node
        scan_enum_node = DocumentGenerator.create_cherrytree_node(main_node, "Scanning and Enumeration")

        # Full Nmap Scan Nodes
        tcp_scan_text = detailed_scan_results + "\n" if detailed_scan_results else "No detailed TCP scan results available.\n"
        tcp_scan_node = DocumentGenerator.create_cherrytree_node(scan_enum_node, "Full Nmap Scan (TCP)", tcp_scan_text)

        if open_udp_ports:
            udp_scan_text = detailed_udp_scan_results + "\n" if detailed_udp_scan_results else "No detailed UDP scan results available.\n"
            udp_scan_node = DocumentGenerator.create_cherrytree_node(scan_enum_node, "Full Nmap Scan (UDP)", udp_scan_text)
        else:
            udp_scan_node = DocumentGenerator.create_cherrytree_node(scan_enum_node, "Full Nmap Scan (UDP)", "No open UDP ports were found.\n")

        # Enum4linux Results
        if enum4linux_output:
            clean_enum4linux_output = remove_ansi_escape_sequences(enum4linux_output)
            enum4linux_text = f"Command Used: enum4linux -a {ip}\n\n{clean_enum4linux_output}\n"
            enum4linux_node = DocumentGenerator.create_cherrytree_node(scan_enum_node, "Enum4linux Results", enum4linux_text)

        # Process TCP Ports
        if open_ports:
            for port, service, banner, version_info in open_ports:
                port_title = f"Port {port} ({service})"
                port_text = "Take notes here.\n"
                port_node = DocumentGenerator.create_cherrytree_node(tcp_scan_node, port_title, port_text)

                # Version Info and Searchsploit Results
                version_info_text = f"Version Info: {version_info}\n\n" if version_info else "Version Info: Not available\n\n"
                searchsploit_vuln = tcp_port_vulnerabilities.get(port, {}).get('exploits', ["No exploits found in Searchsploit"])
                searchsploit_text = version_info_text + "\n".join([
                    f"- {exploit.get('title', 'No Title')} | Path: {exploit.get('path', 'No Path')}"
                    if isinstance(exploit, dict) else f"- {exploit}"
                    for exploit in searchsploit_vuln
                ]) + "\n"
                searchsploit_node = DocumentGenerator.create_cherrytree_node(port_node, "Searchsploit Results", searchsploit_text)

                # Nmap Vulnerability Scan Results
                nmap_vuln = tcp_port_vulnerabilities.get(port, {}).get('vuln_scan', "No vulnerability data")
                nmap_vuln_text = nmap_vuln + "\n" if nmap_vuln else "No vulnerability data available.\n"
                nmap_vuln_node = DocumentGenerator.create_cherrytree_node(port_node, "Nmap Vulnerability Scan Results", nmap_vuln_text)
        else:
            tcp_scan_node.text = "No open TCP ports were found.\n"

        # Process UDP Ports
        if open_udp_ports:
            for port, service, banner, version_info in open_udp_ports:
                port_title = f"Port {port} ({service})"
                port_text = "Take notes here.\n"
                port_node = DocumentGenerator.create_cherrytree_node(udp_scan_node, port_title, port_text)

                # Version Info and Searchsploit Results
                version_info_text = f"Version Info: {version_info}\n\n" if version_info else "Version Info: Not available\n\n"
                searchsploit_vuln = udp_port_vulnerabilities.get(port, {}).get('exploits', ["No exploits found in Searchsploit"])
                searchsploit_text = version_info_text + "\n".join([
                    f"- {exploit.get('title', 'No Title')} | Path: {exploit.get('path', 'No Path')}"
                    if isinstance(exploit, dict) else f"- {exploit}"
                    for exploit in searchsploit_vuln
                ]) + "\n"
                searchsploit_node = DocumentGenerator.create_cherrytree_node(port_node, "Searchsploit Results", searchsploit_text)

                # Nmap Vulnerability Scan Results
                nmap_vuln = udp_port_vulnerabilities.get(port, {}).get('vuln_scan', "No vulnerability data")
                nmap_vuln_text = nmap_vuln + "\n" if nmap_vuln else "No vulnerability data available.\n"
                nmap_vuln_node = DocumentGenerator.create_cherrytree_node(port_node, "Nmap Vulnerability Scan Results", nmap_vuln_text)
        else:
            udp_scan_node.text = "No open UDP ports were found.\n"

        # Exploitation Node
        exploitation_node = DocumentGenerator.create_cherrytree_node(main_node, "Exploitation", "Take notes here.\n")

        # Reporting Node
        reporting_node = DocumentGenerator.create_cherrytree_node(main_node, "Reporting", "Take notes here.\n")

        # Save the CherryTree document
        tree = ET.ElementTree(root)
        cherrytree_filename = os.path.join(CHERRYTREE_DIR, f"{filename}_structure.ctd")
        tree.write(cherrytree_filename, encoding='utf-8', xml_declaration=True)
        print(Fore.GREEN + f"CherryTree structure saved to {cherrytree_filename}")
        print_separator()

class UserInputHandler:
    @staticmethod
    def get_ip_address():
        while True:
            ip = input(Fore.YELLOW + "Enter the IP address: ").strip()
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                print(Fore.RED + "Invalid IP address. Please try again.")

    @staticmethod
    def get_filename(prompt):
        return input(Fore.YELLOW + prompt).strip()

    @staticmethod
    def get_yes_no(prompt, default=None):
        yes = ['y', 'yes']
        no = ['n', 'no']
        default_prompt = ''
        if default is True:
            default_prompt = ' [Y/n]'
        elif default is False:
            default_prompt = ' [y/N]'
        while True:
            choice = input(Fore.YELLOW + prompt + default_prompt + ": ").strip().lower()
            if choice == '' and default is not None:
                return default
            elif choice in yes:
                return True
            elif choice in no:
                return False
            else:
                print(Fore.RED + "Invalid input. Please enter 'y' or 'n'.")

    @staticmethod
    def get_file_path(prompt):
        setup_readline()
        while True:
            file_path = input(Fore.YELLOW + prompt).strip()
            if os.path.exists(file_path):
                return file_path
            print(Fore.RED + "Invalid file path. Please try again.")

# Main Execution

def main():
    atexit.register(reset_terminal)

    if not ToolChecker.check_tools():
        print(Fore.RED + "Some tools required by this script are not installed. Please install them to proceed.")
        sys.exit(1)

    print_separator()
    default_all = UserInputHandler.get_yes_no("Do you want to run all tasks by default?", default=True)
    print_separator()
    ip = UserInputHandler.get_ip_address()
    print_separator()

    # Nmap scans are mandatory
    filename = UserInputHandler.get_filename("Enter the filename to save Nmap scan results: ")
    print_separator()

    # Create separate NmapScanner instances for TCP and UDP
    nmap_tcp_scanner = NmapScanner(ip)
    detailed_scan_results, xml_filename, normal_filename, tcp_error = nmap_tcp_scanner.handle_scanning(filename, 'tcp')
    print_separator()
    nmap_udp_scanner = NmapScanner(ip)
    detailed_udp_scan_results, udp_xml_filename, udp_normal_filename, udp_error = nmap_udp_scanner.handle_scanning(filename, 'udp')

    # Use xml_filename (TCP XML file)
    domains_list = HostUpdater.update_hosts_file(ip, xml_filename)

    # Extract open ports for TCP
    if xml_filename and os.path.exists(xml_filename):
        open_ports = nmap_tcp_scanner.extract_open_ports(xml_filename)
    else:
        print(Fore.RED + f"TCP scan XML file {xml_filename} not found.")
        log_error(f"TCP scan XML file {xml_filename} not found.")
        open_ports = []

    # Extract open ports for UDP
    if udp_xml_filename and os.path.exists(udp_xml_filename):
        open_udp_ports = nmap_udp_scanner.extract_open_ports(udp_xml_filename, protocol='udp')
    else:
        print(Fore.RED + f"UDP scan XML file {udp_xml_filename} not found.")
        log_error(f"UDP scan XML file {udp_xml_filename} not found.")
        open_udp_ports = []

    if default_all:
        run_feroxbuster = True
        run_nmap_vuln_scan = True
        run_searchsploit = True
        run_enum4linux_scan = True
        use_default_wordlist = True
        custom_wordlist = None
    else:
        run_feroxbuster = UserInputHandler.get_yes_no("Do you want to run Feroxbuster scans?", default=True)
        if run_feroxbuster:
            use_default_wordlist = UserInputHandler.get_yes_no("Do you want to use the default wordlist for Feroxbuster?", default=True)
            if not use_default_wordlist:
                custom_wordlist = UserInputHandler.get_file_path("Enter the path to your custom wordlist: ")
            else:
                custom_wordlist = None
        run_nmap_vuln_scan = UserInputHandler.get_yes_no("Do you want to run Nmap vulnerability scans?", default=True)
        run_searchsploit = UserInputHandler.get_yes_no("Do you want to run Searchsploit analysis?", default=True)
        run_enum4linux_scan = UserInputHandler.get_yes_no("Do you want to run Enum4linux scan?", default=True)

    print_separator()

    futures = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        tcp_port_vulnerabilities = {}
        udp_port_vulnerabilities = {}
        if run_nmap_vuln_scan:
            if open_ports:
                vuln_scanner = VulnScanner(ip, open_ports, filename, 'tcp')
                futures.append(executor.submit(vuln_scanner.run_vuln_scan))
            else:
                print(Fore.YELLOW + "No open TCP ports to scan for vulnerabilities.")
                log_info("No open TCP ports to scan for vulnerabilities.")
            if open_udp_ports:
                udp_vuln_scanner = VulnScanner(ip, open_udp_ports, filename, 'udp')
                futures.append(executor.submit(udp_vuln_scanner.run_vuln_scan))
            else:
                print(Fore.YELLOW + "No open UDP ports to scan for vulnerabilities.")
                log_info("No open UDP ports to scan for vulnerabilities.")
        if run_feroxbuster:
            if open_ports:
                feroxbuster_scanner = FeroxbusterScanner(ip, open_ports, domains_list, custom_wordlist)
                feroxbuster_scanner.execute()
            else:
                print(Fore.YELLOW + "No open ports found. Skipping Feroxbuster scans.")
                log_info("No open ports found. Skipping Feroxbuster scans.")
        if run_searchsploit:
            if xml_filename and os.path.exists(xml_filename):
                SearchsploitAnalyzer.execute(xml_filename, 'tcp')
            else:
                print(Fore.YELLOW + "No Nmap XML file available for TCP. Skipping Searchsploit analysis for TCP.")
            if udp_xml_filename and os.path.exists(udp_xml_filename):
                SearchsploitAnalyzer.execute(udp_xml_filename, 'udp')
            else:
                print(Fore.YELLOW + "No Nmap XML file available for UDP. Skipping Searchsploit analysis for UDP.")
        if run_enum4linux_scan:
            futures.append(executor.submit(Enum4LinuxScanner.run, ip))

        enum4linux_output = None
        for future in as_completed(futures):
            result = future.result()
            if isinstance(result, tuple) and len(result) == 2:
                protocol, vuln_scan_data = result
                if protocol == 'tcp':
                    for port in vuln_scan_data:
                        tcp_port_vulnerabilities.setdefault(port, {})['vuln_scan'] = vuln_scan_data[port]
                elif protocol == 'udp':
                    for port in vuln_scan_data:
                        udp_port_vulnerabilities.setdefault(port, {})['vuln_scan'] = vuln_scan_data[port]
            elif isinstance(result, str) and run_enum4linux_scan:
                enum4linux_output = result

    if run_searchsploit and open_ports:
        tcp_searchsploit_results = os.path.join(SEARCHSPLOIT_DIR, 'searchsploit_tcp.json')
        SearchsploitAnalyzer.map_searchsploit_to_ports(tcp_port_vulnerabilities, open_ports, tcp_searchsploit_results)
        if open_udp_ports:
            udp_searchsploit_results = os.path.join(SEARCHSPLOIT_DIR, 'searchsploit_udp.json')
            SearchsploitAnalyzer.map_searchsploit_to_ports(udp_port_vulnerabilities, open_udp_ports, udp_searchsploit_results)

    tcp_scan_results = read_file(normal_filename) if normal_filename else ""
    udp_scan_results = read_file(udp_normal_filename) if udp_normal_filename else ""
    DocumentGenerator.create_document_structure(
        ip,
        open_ports,
        open_udp_ports,
        tcp_scan_results,
        udp_scan_results,
        filename,
        tcp_port_vulnerabilities,
        udp_port_vulnerabilities,
        enum4linux_output
    )

    reset_terminal()


if __name__ == "__main__":
    main()

