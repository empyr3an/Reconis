#!/usr/bin/env python3

import sys
import subprocess
import xml.etree.ElementTree as ET
import re
import platform
import shutil
import json
import os
import glob
import readline
import logging
import requests
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import threading
import time
import atexit

# Initialize logging for complete logs
logging.basicConfig(filename='complete_logs.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_command(command, command_type=""):
    with open('commands_used.log', 'a') as file:
        file.write(f"=== {command_type} ===\n")
        file.write(command + '\n')
        file.write("-" * 25 + "\n")

def log_complete(message):
    logging.info("\n" + "=" * 80 + "\n" + message + "\n" + "=" * 80 + "\n")

def check_and_install_tools():
    tools = ["nmap", "feroxbuster", "gnome-terminal", "enum4linux"]
    missing_tools = [tool for tool in tools if not shutil.which(tool)]
    if missing_tools:
        print("The following tools are missing: " + ", ".join(missing_tools))
        return False
    return True

def extract_ip_address(nmap_output):
    match = re.search(r'Nmap scan report for (\S+)', nmap_output)
    return match.group(1) if match else "Unknown"

def run_in_new_terminal(command):
    if platform.system() == "Windows":
        subprocess.Popen(['start', 'cmd', '/k', command], shell=True)
    elif platform.system() == "Linux":
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{command}; exec bash"])
    elif platform.system() == "Darwin":
        subprocess.Popen(['open', '-a', 'Terminal', command])

def handle_nmap_scan(ip, scan_options, protocol='tcp', output_xml=False):
    xml_filename = None
    command = f"nmap {scan_options} {ip}"
    log_command(command, "Nmap Scan")
    if output_xml:
        xml_filename = f"nmap_output_{protocol}_{ip.replace('.', '_')}.xml"
        command += f" -oX {xml_filename}"

    log_complete(f"Running Nmap {protocol} scan: {command}")
    print(f"Running Nmap {protocol} scan: {command}")

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if stderr:
        print(f"Error during Nmap {protocol} scan on {ip}: {stderr}")
        log_complete(f"Error during Nmap {protocol} scan on {ip}: {stderr}")

    return stdout, xml_filename, bool(stderr)

def extract_open_ports(nmap_output, protocol='tcp'):
    lines = nmap_output.splitlines()
    open_ports = []
    for line in lines:
        if 'open' in line and f'/{protocol}' in line:
            parts = line.split()
            port = parts[0].split('/')[0].strip()
            service = parts[2].strip()
            banner = " ".join(parts[3:]).lower()
            open_ports.append((port, service, banner, line.strip()))
    return open_ports

def save_results(output, filename):
    with open(filename, 'w') as file:
        file.write(output)

def create_cherrytree_node(parent, title, text=""):
    node = ET.SubElement(parent, 'node', custom_icon_id='1', foreground='', is_bold='False', name=title,
                         prog_lang='custom-colors', readonly='', tags='', ts_creation='', ts_lastsave='')
    ET.SubElement(node, 'rich_text').text = text
    return node

def determine_extensions(service_banner):
    extension_mapping = {
        "apache": ["php", "html", "js", "css", "xml"], 
        "nginx": ["html", "js", "css", "php"],
        "iis": ["asp", "aspx", "html", "js", "css"], 
        "wordpress": ["php", "html", "css", "js", "xml"],
        "joomla": ["php", "html", "js"], 
        "drupal": ["php", "html", "js"]
    }
    default_extensions = ["html", "php", "js"]
    selected_extensions = set(default_extensions)
    for key, extensions in extension_mapping.items():
        if key in service_banner.lower():
            selected_extensions.update(extensions)
    return list(selected_extensions)

def is_http_service(service):
    http_indicators = ["http", "https", "nginx", "apache", "web", "www"]
    return any(indicator in service.lower() for indicator in http_indicators)

# Define the directory path and default file for directory busting
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DIR_BUSTING_FOLDER = os.path.join(SCRIPT_DIR, 'wordlists')
DEFAULT_DIR_BUSTER_FILE = os.path.join(DIR_BUSTING_FOLDER, 'directory-list-2.3-medium.txt')

domains_list = []

def create_feroxbuster_command(ip, port, service_banner, custom_wordlist=None):
    best_domain = determine_best_domain(port, ip)
    extensions = determine_extensions(service_banner)
    extensions_string = ",".join(extensions)
    status_codes = "200,301,302,307,308"
    wordlist = custom_wordlist if custom_wordlist else DEFAULT_DIR_BUSTER_FILE
    return f"feroxbuster --url http://{best_domain}:{port} -w {wordlist} -x {extensions_string} -s {status_codes} -t 50 -r; exec bash"

def display_help():
    help_text = """
    Usage: python3 nmapscan.py [options] <filename>
    Options:
    -h           Display this help message.
    -ns          Skip Nmap scanning and only generate CherryTree document from existing data (exact filename required).
    -no-fero     Skip running Feroxbuster in a new terminal.
    Example:
    python3 nmapscan.py -ns Lame_fullscan.txt
    python3 nmapscan.py 192.168.1.1 new_scan
    """
    print(help_text)
    sys.exit(0)

def process_nmap_file(data):
    port_details_regex = re.compile(r'^(\d+/tcp)')
    end_pattern = re.compile(
        r'^Service detection performed\. Please report any incorrect results at https:\/\/nmap\.org\/submit\/ \.$')
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
            current_port = port_match.group(0)
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
        cleaned_data += "Port: " + port + '\n' + "Details:\n" + info['details']
        if info['additional_info'].strip():
            cleaned_data += "Additional Info:\n" + info['additional_info']
        cleaned_data += "----------\n"

    return cleaned_data

def run_vuln_scan(ip, open_ports, filename, protocol='tcp'):
    if not open_ports:
        log_complete(f"No open {protocol} ports found. Skipping vulnerability scan.")
        return {}

    vuln_scan_options = "-sV --script=vuln"
    ports = ','.join([port for port, _, _, _ in open_ports])
    command = f"nmap -Pn {vuln_scan_options} -p{ports} {ip}"
    log_command(command, "Nmap Vulnerability Scan")
    log_complete(f"Running {protocol} vulnerability scan: {command}")
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stderr:
        log_complete(f"Error during {protocol} vulnerability scan: {result.stderr}")

    cleaned_output = process_nmap_file(result.stdout)
    save_results(cleaned_output, f"{filename}_{protocol}_vulnscan.txt")
    log_complete(f"Vulnerability scan complete. Results cleaned and saved in {filename}_{protocol}_vulnscan.txt")

    return parse_vuln_scan_output(cleaned_output)

def parse_vuln_scan_output(data):
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
        ports_info[port] = "\n".join(info_lines) if info_lines else "No vulnerability scan data"

    return ports_info

def handle_scanning(ip, filename, protocol='tcp'):
    quickscan_options = "-T4 -Pn --open -p-"
    if protocol == 'udp':
        quickscan_options = "-sU -T4 --open --top-ports 100"
    print(f"Running quick {protocol} scan on {ip}...", end='', flush=True)
    quick_scan_results, _, quick_scan_error = handle_nmap_scan(ip, quickscan_options, protocol)
    if quick_scan_error:
        print(f"Error encountered during quick {protocol} scan. Check logs for details.")
        log_complete(f"Error encountered during quick {protocol} scan.")
    save_results(quick_scan_results, f"{filename}_quickscan_{protocol}.txt")
    print(f"\rQuick {protocol} scan complete. Results saved in {filename}_quickscan_{protocol}.txt", flush=True)
    print("-" * 50)

    open_ports = extract_open_ports(quick_scan_results, protocol)
    if not open_ports:
        print(f"No open {protocol} ports found. Skipping detailed scan.")
        return "No open ports found.", None, True

    fullscan_options = f"-T4 -Pn -A -p{','.join([port for port, _, _, _ in open_ports])}"
    if protocol == 'udp':
        fullscan_options = f"-sU -A -T4 -p{','.join([port for port, _, _, _ in open_ports])}"
    print(f"Running detailed {protocol} scan on {len(open_ports)} open ports...", end='', flush=True)
    detailed_scan_results, xml_filename, full_scan_error = handle_nmap_scan(ip, fullscan_options, protocol, output_xml=True)
    if full_scan_error:
        print(f"Error encountered during detailed {protocol} scan. Check logs for details.")
        log_complete(f"Error encountered during detailed {protocol} scan.")
    save_results(detailed_scan_results, f"{filename}_fullscan_{protocol}.txt")
    print(f"\rDetailed {protocol} scan complete. Results saved in {filename}_fullscan_{protocol}.txt", flush=True)

    return detailed_scan_results, xml_filename, False

def handle_udp_scan(ip, filename):
    quick_udp_options = "-sU -T4 --open --top-ports 100"
    print(f"Running quick UDP scan on {ip}...", end='', flush=True)
    quick_udp_results, _, quick_udp_error = handle_nmap_scan(ip, quick_udp_options, 'udp')
    if quick_udp_error:
        print("Error encountered during quick UDP scan. Check logs for details.")
        log_complete("Error encountered during quick UDP scan.")
    save_results(quick_udp_results, f"{filename}_quickscan_udp.txt")
    print(f"\rQuick UDP scan complete. Results saved in {filename}_quickscan_udp.txt", flush=True)
    print("-" * 50)

    open_udp_ports = extract_open_ports(quick_udp_results, protocol='udp')
    if open_udp_ports:
        udp_ports = ','.join([port for port, _, _, _ in open_udp_ports])
        full_udp_options = f"-sU -A -T4 -p{udp_ports}"
        print(f"Running detailed UDP scan on {len(open_udp_ports)} open ports...", end='', flush=True)
        full_udp_results, _, full_udp_error = handle_nmap_scan(ip, full_udp_options, 'udp')
        if full_udp_error:
            print("Error encountered during detailed UDP scan. Check logs for details.")
            log_complete("Error encountered during detailed UDP scan.")
        save_results(full_udp_results, f"{filename}_fullscan_udp.txt")
        print(f"\rDetailed UDP scan complete. Results saved in {filename}_fullscan_udp.txt", flush=True)
    else:
        print("No open UDP ports found. Skipping detailed UDP scan.")
        full_udp_results = "No open UDP ports found."

    return full_udp_results, open_udp_ports

def process_searchsploit_results(json_file):
    with open(json_file, 'r') as file:
        file_content = file.read().strip()

    json_objects = []
    obj_str = ''
    depth = 0
    for char in file_content:
        if char == '{':
            depth += 1
        if depth > 0:
            obj_str += char
        if char == '}':
            depth -= 1
            if depth == 0:
                json_objects.append(obj_str)
                obj_str = ''

    filtered_data = []

    for obj in json_objects:
        try:
            data = json.loads(obj)
        except json.JSONDecodeError as e:
            print("Failed to decode JSON:", e)
            continue

        if data['RESULTS_EXPLOIT']:
            search_section = f"SEARCH: {data['SEARCH']}"
            titles = [exploit['Title'] for exploit in data['RESULTS_EXPLOIT']]
            filtered_data.append({'search_term': search_section, 'titles': titles})

    with open(json_file, 'w') as file:
        json.dump(filtered_data, file, indent=4)

def map_searchsploit_to_ports(open_ports, searchsploit_results_file):
    if not os.path.exists(searchsploit_results_file):
        print(f"No Searchsploit data available in {searchsploit_results_file}")
        return {port: {'service': service, 'exploits': 'No exploits found'} for port, service, _, _ in open_ports}

    with open(searchsploit_results_file, 'r') as file:
        searchsploit_data = json.load(file)

    port_vulnerabilities = {}
    service_exploit_cache = {}

    for port, service, banner, version_info in open_ports:
        if service in service_exploit_cache:
            port_vulnerabilities[port] = {
                "service": service,
                "exploits": service_exploit_cache[service],
                "version_info": version_info
            }
        else:
            port_vulnerabilities[port] = {
                "service": service,
                "exploits": "No exploits found in Searchsploit",
                "version_info": version_info
            }

            for entry in searchsploit_data:
                search_term = entry['search_term'].split(': ')[1].lower()
                if search_term in banner.lower():
                    port_vulnerabilities[port]['exploits'] = entry['titles']
                    service_exploit_cache[service] = entry['titles']
                    break

    with open(searchsploit_results_file, 'w') as file:
        json.dump(port_vulnerabilities, file, indent=4)

    return port_vulnerabilities

def extract_vuln_scan_host_scripts(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read()
        start = content.find('Host script results:')
        if start == -1:
            return "No host script results found."

        end = content.find('----------', start)
        if end == -1:
            end = len(content)

        return content[start:end].strip()
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"An error occurred: {str(e)}"

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def create_document_structure(ip, open_ports, open_udp_ports, detailed_scan_results, detailed_udp_scan_results, filename, run_feroxbuster, port_vulnerabilities, udp_port_vulnerabilities, enum4linux_output=None):
    print("-" * 50)
    print("Creating document structure...")
    tcp_vuln_scan_filename = f"{filename}_tcp_vulnscan.txt"
    udp_vuln_scan_filename = f"{filename}_udp_vulnscan.txt"
    if os.path.exists(tcp_vuln_scan_filename):
        tcp_host_scripts = extract_vuln_scan_host_scripts(tcp_vuln_scan_filename)
        tcp_vuln_scan_data = parse_vuln_scan_output(read_file(tcp_vuln_scan_filename))
    else:
        tcp_host_scripts = "Not available"
        tcp_vuln_scan_data = {}

    if os.path.exists(udp_vuln_scan_filename):
        udp_host_scripts = extract_vuln_scan_host_scripts(udp_vuln_scan_filename)
        udp_vuln_scan_data = parse_vuln_scan_output(read_file(udp_vuln_scan_filename))
    else:
        udp_host_scripts = "Not available"
        udp_vuln_scan_data = {}

    root = ET.Element('cherrytree')
    main_node = create_cherrytree_node(root, f"Target IP/Hostname: {ip}")
    main_node.find('rich_text').text = "Host script results: " + tcp_host_scripts + "\n" + udp_host_scripts

    scan_enum_node = create_cherrytree_node(main_node, "Scanning and Enumeration")
    scan_enum_node.find('rich_text').text = "Take notes here"

    tcp_scan_node = create_cherrytree_node(scan_enum_node, "Full Nmap Scan (TCP)", text=detailed_scan_results)
    udp_scan_node = create_cherrytree_node(scan_enum_node, "Full Nmap Scan (UDP)", text=detailed_udp_scan_results)

    for port, service, banner, version_info in open_ports:
        port_node = create_cherrytree_node(tcp_scan_node, f"Port {port} ({service})")
        port_node.find('rich_text').text = "Take notes here\n\n"

        exploits_info = port_vulnerabilities.get(port, {}).get('exploits', [])
        exploit_text = f"Version Info: {version_info}\n\n" + "Searchsploit Results:\n\n" + "\n".join(exploits_info) if exploits_info else "No exploits found in Searchsploit\n"
        port_info_text = f"{exploit_text}"

        create_cherrytree_node(port_node, "Searchsploit", text=port_info_text)
        vuln_scan_text = tcp_vuln_scan_data.get(port, "No vulnerability scan data")
        create_cherrytree_node(port_node, "Nmap Vuln Scan", text=vuln_scan_text)

    if open_udp_ports:
        for port, service, banner, version_info in open_udp_ports:
            port_node = create_cherrytree_node(udp_scan_node, f"Port {port} ({service})")
            port_node.find('rich_text').text = "Take notes here\n\n"

            exploits_info = udp_port_vulnerabilities.get(port, {}).get('exploits', [])
            exploit_text = f"Version Info: {version_info}\n\n" + "Searchsploit Results:\n\n" + "\n".join(exploits_info) if exploits_info else "No exploits found in Searchsploit\n"
            port_info_text = f"{exploit_text}"

            create_cherrytree_node(port_node, "Searchsploit", text=port_info_text)
            vuln_scan_text = udp_vuln_scan_data.get(port, "No vulnerability scan data")
            create_cherrytree_node(port_node, "Nmap Vuln Scan", text=vuln_scan_text)
    else:
        udp_scan_node.find('rich_text').text = "No open UDP ports were found."

    if enum4linux_output:
        clean_enum4linux_output = remove_ansi_escape_sequences(enum4linux_output)
        enum4linux_text = f"Command Used: enum4linux -a {ip}\n\n{clean_enum4linux_output}"
        create_cherrytree_node(scan_enum_node, "Enum4linux Results", text=enum4linux_text)

    exploitation_node = create_cherrytree_node(main_node, "Exploitation")
    exploitation_node.find('rich_text').text = "Take Notes Here"

    reporting_node = create_cherrytree_node(main_node, "Reporting")
    reporting_node.find('rich_text').text = "Take Notes Here"

    tree = ET.ElementTree(root)
    cherrytree_filename = f"{filename}_structure.ctd"
    tree.write(cherrytree_filename, encoding='utf-8', xml_declaration=True)
    print(f"CherryTree structure saved to {cherrytree_filename}")
    print("-" * 50)

def setup_readline():
    def complete(text, state):
        return (glob.glob(text+'*')+[None])[state]
    readline.set_completer(complete)
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")

def get_ip_address():
    while True:
        ip = input("Enter the IP address: ")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return ip
        else:
            print("Invalid IP address. Please try again.")

def get_nmap_scan_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input("Do you want to run an Nmap scan? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_nmap_file_path():
    setup_readline()
    while True:
        file_path = input("Enter the file path of the existing Nmap scan data: ")
        if os.path.exists(file_path):
            return file_path
        print("Invalid file path. Please try again.")

def get_feroxbuster_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input("Do you want to run Feroxbuster? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_feroxbuster_file_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input(f"Do you want to use the default file for directory busting? (Make sure you have the wordlists directory downloaded) (y/n) : ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_feroxbuster_file_path():
    setup_readline()
    while True:
        file_path = input("Enter the custom file path for directory busting: ")
        if os.path.exists(file_path):
            return file_path
        print("Invalid file path. Please try again.")

def get_vuln_scan_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input("Do you want to run the Nmap vulnerability scan? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_udp_scan_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input("Do you want to run a UDP scan? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_searchsploit_option(default_all=False):
    if default_all:
        return True
    while True:
        choice = input("Do you want to include Searchsploit? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def get_enum4linux_option():
    while True:
        choice = input("Do you want to run enum4linux? (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid choice. Please enter 'y' or 'n'.")

def spinner(task_name):
    spinner_chars = ['|', '/', '-', '\\']
    while True:
        for char in spinner_chars:
            yield f'\r{task_name}... {char}'

def execute_feroxbuster(ip, open_ports, custom_wordlist):
    spinner_gen = spinner("Running Feroxbuster")
    spinner_thread = threading.Thread(target=show_spinner, args=(spinner_gen,))
    spinner_thread.start()
    threading.current_thread().do_run = True
    for port, service, banner, _ in open_ports:
        if is_http_service(service):
            feroxbuster_cmd = create_feroxbuster_command(ip, port, banner, custom_wordlist)
            run_in_new_terminal(feroxbuster_cmd)
    spinner_thread.do_run = False
    spinner_thread.join()
    print("\rFeroxbuster scan complete.                      ")

def execute_searchsploit(xml_filename, protocol='tcp'):
    spinner_gen = spinner(f"Running Searchsploit for {protocol}")
    spinner_thread = threading.Thread(target=show_spinner, args=(spinner_gen,))
    spinner_thread.start()
    threading.current_thread().do_run = True
    searchsploit_command = f"searchsploit --nmap {xml_filename} -j > searchsploit_{protocol}.json"
    log_command(searchsploit_command, f"Searchsploit {protocol.capitalize()}")
    subprocess.run(searchsploit_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process_searchsploit_results(f'searchsploit_{protocol}.json')
    spinner_thread.do_run = False
    spinner_thread.join()
    print(f"\rSearchsploit analysis for {protocol} complete.")

def run_enum4linux(ip):
    spinner_gen = spinner("Running enum4linux")
    spinner_thread = threading.Thread(target=show_spinner, args=(spinner_gen,))
    spinner_thread.start()
    threading.current_thread().do_run = True
    command = f"enum4linux -a {ip}"
    log_command(command, "Enum4linux")
    log_complete(f"Running enum4linux: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    spinner_thread.do_run = False
    spinner_thread.join()
    print("\renum4linux scan complete.                      ")
    if stderr:
        log_complete(f"Error during enum4linux scan: {stderr}")
    return stdout

def run_vuln_scan_task(ip, open_ports, filename, protocol='tcp'):
    spinner_gen = spinner(f"Running {protocol} vulnerability scan")
    spinner_thread = threading.Thread(target=show_spinner, args=(spinner_gen,))
    spinner_thread.start()
    threading.current_thread().do_run = True
    result = run_vuln_scan(ip, open_ports, filename, protocol)
    spinner_thread.do_run = False
    spinner_thread.join()
    print(f"\r{protocol.capitalize()} vulnerability scan complete.                      ")
    return result

def show_spinner(spinner_gen):
    thread = threading.current_thread()
    thread.do_run = True
    for char in spinner_gen:
        if thread.do_run:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.1)
        else:
            break

def monitor_tasks(futures):
    for future in as_completed(futures):
        try:
            result = future.result()
            return result  # Capture the result
        except Exception as exc:
            print(f"Task generated an exception: {exc}")

def determine_os(nmap_output):
    os_detection = re.search(r'OS details: (.+)', nmap_output)
    os_guesses = re.findall(r'OS CPE: (cpe:/o:[^:]+)', nmap_output)
    os_services = re.findall(r'^\d+/tcp\s+open\s+[^\s]+\s+(.+)$', nmap_output, re.MULTILINE)
    os_detailed = re.search(r'Aggressive OS guesses: (.+)', nmap_output)
    
    os_keywords = {
        'linux': ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'red hat', 'kali'],
        'windows': ['windows', 'microsoft']
    }
    
    os_type = None
    os_version = "Unknown"
    
    if os_detection:
        detected_os = os_detection.group(1).lower()
        os_version = os_detection.group(1)
        for os_key, keywords in os_keywords.items():
            if any(keyword in detected_os for keyword in keywords):
                os_type = os_key
                break
    
    if not os_type and os_guesses:
        for guess in os_guesses:
            for os_key, keywords in os_keywords.items():
                if any(keyword in guess for keyword in keywords):
                    os_type = os_key
                    os_version = guess
                    break
    
    if not os_type and os_detailed:
        detailed_os = os_detailed.group(1).lower()
        os_version = os_detailed.group(1)
        for os_key, keywords in os_keywords.items():
            if any(keyword in detailed_os for keyword in keywords):
                os_type = os_key
                break
    
    if not os_type:
        for service in os_services:
            service_lower = service.lower()
            for os_key, keywords in os_keywords.items():
                if any(keyword in service_lower for keyword in keywords):
                    os_type = os_key
                    break
    
    return os_type, os_version

def extract_hosts_info(nmap_output):
    ip_address = re.search(r'Nmap scan report for (\S+)', nmap_output)
    if ip_address:
        ip_address = ip_address.group(1)
    
    os_type, os_version = determine_os(nmap_output)
    
    domain_name = re.search(r'DNS_Domain_Name: (\S+)', nmap_output)
    computer_name = re.search(r'DNS_Computer_Name: (\S+)', nmap_output)
    
    netbios_domain_name = re.search(r'NetBIOS_Domain_Name: (\S+)', nmap_output)
    netbios_computer_name = re.search(r'NetBIOS_Computer_Name: (\S+)', nmap_output)
    
    hostnames = {}
    
    if domain_name:
        hostnames[domain_name.group(1).lower()] = "Domain Name"
    
    if computer_name:
        full_dns_name = computer_name.group(1).lower()
        if not full_dns_name.endswith(domain_name.group(1).lower()):
            full_dns_name = f"{full_dns_name}.{domain_name.group(1).lower()}"
        hostnames[full_dns_name] = "FQDN"
        hostnames[computer_name.group(1).split('.')[0]] = "Hostname"

    if netbios_domain_name and netbios_computer_name:
        netbios_entry = f"{netbios_computer_name.group(1).lower()}.{netbios_domain_name.group(1).lower()}"
        hostnames[netbios_entry] = "NetBIOS FQDN"
        hostnames[netbios_computer_name.group(1)] = "NetBIOS Name"
    
    return os_type, os_version, ip_address, hostnames

def extract_redirects(nmap_output):
    redirects = re.findall(r'Did not follow redirect to (http[s]?://\S+)', nmap_output)
    redirect_hostnames = [re.sub(r'^http[s]?://', '', redirect).split('/')[0] for redirect in redirects]
    return redirect_hostnames

def extract_domains_from_hosts(ip_address):
    domains = []
    with open("/etc/hosts", "r") as hosts_file:
        for line in hosts_file:
            if line.startswith(ip_address):
                entries = line.strip().split()
                for entry in entries[1:]:
                    if entry not in domains:
                        domains.append(entry)
    return domains

def update_hosts_file_from_nmap_output(ip_address, nmap_output_file):
    global domains_list
    try:
        with open(nmap_output_file, 'r') as file:
            nmap_output = file.read()
    except FileNotFoundError:
        print(f"Error: File {nmap_output_file} not found.")
        sys.exit(1)
    
    os_type, os_version, _, hostnames = extract_hosts_info(nmap_output)
    redirect_hostnames = extract_redirects(nmap_output)
    
    # Combine hostnames and remove duplicates
    all_hostnames = list(hostnames.keys()) + redirect_hostnames
    unique_hostnames = list(dict.fromkeys(all_hostnames))
    
    if ip_address and unique_hostnames:
        # Store unique hostnames for later use
        domains_list = unique_hostnames
        
        # Read the current contents of /etc/hosts
        try:
            with open("/etc/hosts", "r") as hosts_file:
                current_hosts = hosts_file.readlines()
        except FileNotFoundError:
            current_hosts = []
        
        # Check all occurrences of the IP address
        ip_indices = [i for i, line in enumerate(current_hosts) if line.startswith(ip_address)]
        existing_hostnames = set()
        
        for index in ip_indices:
            existing_hostnames.update(current_hosts[index].strip().split()[1:])
        
        missing_hostnames = [hostname for hostname in unique_hostnames if hostname not in existing_hostnames]
        
        if missing_hostnames:
            if ip_indices:
                current_hosts[ip_indices[0]] = current_hosts[ip_indices[0]].strip() + " " + " ".join(missing_hostnames) + "\n"
            else:
                new_entry = f"{ip_address} " + " ".join(unique_hostnames) + "\n"
                current_hosts.append(new_entry)
            
            with open("/etc/hosts", "w") as hosts_file:
                hosts_file.writelines(current_hosts)
            
            print("-" * 50)
            print(f"Added the following entries to /etc/hosts: {', '.join(missing_hostnames)}")
            log_command(f"Added the following entries to /etc/hosts: {', '.join(missing_hostnames)}", "Hosts Update")
        else:
            print("-" * 50)
            print("No new entries were added to /etc/hosts.")
            log_command("No new entries were added to /etc/hosts.", "Hosts Update")
    else:
        print("-" * 50)
        print("No new entries were added to /etc/hosts.")
        log_command("No new entries were added to /etc/hosts.", "Hosts Update")

    # Extract all domains associated with the IP from /etc/hosts
    domains_list.extend(extract_domains_from_hosts(ip_address))

def score_domain(domain, port, ip):
    url = f"http://{domain}:{port}"
    score = 0

    try:
        # Execute the curl command and capture the output
        curl_command = f"curl -I {url}"
        curl_output = subprocess.run(curl_command, shell=True, capture_output=True, text=True)
        curl_stdout = curl_output.stdout.strip()

        # Extract status code manually from the curl output
        status_code = None
        for line in curl_stdout.splitlines():
            if line.startswith("HTTP/"):
                status_code = int(line.split()[1])
                break

        # Scoring based on Status Code
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

        # Scoring based on Content-Length
        content_length = None
        for line in curl_stdout.splitlines():
            if line.lower().startswith("content-length:"):
                content_length = int(line.split()[1])
                break
        
        if content_length:
            if content_length > 1000:
                score += 20
            else:
                score += 10

        # Scoring based on Set-Cookie header
        if "Set-Cookie" in curl_stdout:
            score += 20

    except Exception as e:
        log_command(f"Failed to score {domain}:{port} due to error: {str(e)}", "Domain Scoring")

    return domain, score


def determine_best_domain(port, ip):
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(score_domain, domain, port, ip): domain for domain in domains_list + [ip]}
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

        # Always default to IP if its score matches the best score
        if ip_score >= best_score:
            best_domain = ip

        log_complete(f"Best domain for port {port} is {best_domain} with a score of {best_score}")

        return best_domain



def reset_terminal():
    os.system('stty sane')
    os.system('stty erase "^h"')

def main():
    # Register the terminal reset function to be called on exit
    atexit.register(reset_terminal)

    tools_ready = check_and_install_tools()
    if not tools_ready:
        print("Some tools required by this script are not installed. Please install them to proceed.")
        sys.exit(1)

    print("-" * 50)
    default_all = input("Do you want to run all tasks by default? (y/n): ").lower() == 'y'
    ip = get_ip_address()
    print("-" * 50)
    run_nmap_scan = get_nmap_scan_option(default_all)

    if run_nmap_scan:
        filename = input("Enter the filename to save Nmap scan results: ")
        print("-" * 50)
        detailed_scan_results, xml_filename, tcp_error = handle_scanning(ip, filename, 'tcp')
        print("-" * 50)  # Added separator line
        detailed_udp_scan_results, udp_xml_filename, udp_error = handle_scanning(ip, filename, 'udp')

        # Update hosts file using the correct TCP scan file
        update_hosts_file_from_nmap_output(ip, f"{filename}_fullscan_tcp.txt")

    else:
        filename = get_nmap_file_path()
        try:
            with open(filename, 'r') as file:
                detailed_scan_results = file.read()
            ip = extract_ip_address(detailed_scan_results)
            xml_filename = f"nmap_output_tcp_{ip.replace('.', '_')}.xml"
            detailed_udp_scan_results = ""  # Since no UDP scan was run

            # Update hosts file using the correct file provided by the user
            update_hosts_file_from_nmap_output(ip, filename)

        except FileNotFoundError:
            print(f"Error: File {filename} not found.")
            sys.exit(1)

    open_ports = extract_open_ports(detailed_scan_results)
    open_udp_ports = extract_open_ports(detailed_udp_scan_results, protocol='udp') if run_nmap_scan else []

    print("-" * 50)

    run_feroxbuster = get_feroxbuster_option(default_all)
    if run_feroxbuster:
        use_default_wordlist = get_feroxbuster_file_option(default_all)
        custom_wordlist = None
        if not use_default_wordlist:
            custom_wordlist = get_feroxbuster_file_path()

    run_nmap_vuln_scan = get_vuln_scan_option(default_all)
    run_searchsploit = run_nmap_scan and get_searchsploit_option(default_all)
    
    futures = []
    with ProcessPoolExecutor(max_workers=4) as executor:
        if run_nmap_vuln_scan:
            futures.append(executor.submit(run_vuln_scan_task, ip, open_ports, filename, 'tcp'))
            if open_udp_ports:
                futures.append(executor.submit(run_vuln_scan_task, ip, open_udp_ports, filename, 'udp'))
        if run_feroxbuster:
            futures.append(executor.submit(execute_feroxbuster, ip, open_ports, custom_wordlist))
        if run_searchsploit:
            futures.append(executor.submit(execute_searchsploit, xml_filename, 'tcp'))
            if not udp_error and run_nmap_scan:
                futures.append(executor.submit(execute_searchsploit, udp_xml_filename, 'udp'))
        
        monitor_tasks(futures)

    tcp_port_vulnerabilities = map_searchsploit_to_ports(open_ports, 'searchsploit_tcp.json') if run_searchsploit else {}
    udp_port_vulnerabilities = map_searchsploit_to_ports(open_udp_ports, 'searchsploit_udp.json') if run_searchsploit else {}
    create_document_structure(ip, open_ports, open_udp_ports, detailed_scan_results, detailed_udp_scan_results, filename, run_feroxbuster, tcp_port_vulnerabilities, udp_port_vulnerabilities)

    # Reset terminal to ensure visibility of typed commands
    reset_terminal()

if __name__ == "__main__":
    main()

