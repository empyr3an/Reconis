
# Reconis

Reconis is a tool designed to automate the network enumeration and reconnaissance phases of penetration testing. It simplifies various tasks, making it especially useful for those preparing for OSCP, working on HTB challenges, or engaging in network security assessments.

## About the Name
The name "Reconis" is a blend of "Recon" (short for reconnaissance) and "Kronos" (inspired by the Greek god of time). It symbolizes a tool that helps save time during the reconnaissance process.

## Features of Reconis:
1. Automated Nmap Scans (TCP and UDP):
   Reconis automates both quick and detailed Nmap scans. It handles TCP and UDP scans, and you can choose to output results in XML format for further analysis. It also identifies and logs any errors during scanning, so you know exactly what went wrong if something doesn’t work as expected.
   
2. Vulnerability Scanning:
   After identifying open ports, Reconis can run Nmap’s vulnerability scripts (`-sV --script=vuln`) on those ports to check for known issues. The output is cleaned and saved to a file, making it easy to review later.
   
3. Searchsploit Integration:
   The tool integrates with Searchsploit to automatically map discovered services to known vulnerabilities. It processes the JSON output from Searchsploit, filters relevant exploits, and logs them for each service. If Searchsploit doesn't find any exploits, the tool will indicate this in the results.
   
4. /etc/hosts Management:
   Reconis automatically updates the `/etc/hosts` file with domains discovered during scans. Before adding entries, it checks for duplicates to keep the file clean. It extracts domain names and hostnames from the Nmap output and adds them to the hosts file, ensuring proper resolution during further testing.
   
5. Enum4linux Support:
   For Windows environments, Reconis can automate the use of Enum4linux to enumerate SMB shares, users, and other details. The output is cleaned of ANSI escape sequences for readability and is saved for easy reference.
   
6. Domain Scoring (Experimental):
   This feature scores domains based on HTTP headers and status codes to help prioritize which ones might be worth a closer look. It uses a curl command to inspect HTTP responses, scoring domains based on factors like status codes, content length, and the presence of cookies. The best domain for further testing is selected automatically.
   
7. Feroxbuster Integration:
   Reconis integrates with Feroxbuster to automate directory and file discovery on web servers. The tool customizes the file extensions based on the web server detected (e.g., PHP for Apache, ASPX for IIS). You can use the default wordlist provided or specify a custom one if you need something specific.
   
8. CherryTree Documentation:
   All findings from Nmap scans, vulnerability scans, and SMB enumeration are documented in a CherryTree format. The document is structured with nodes for scanning and enumeration, exploitation, and reporting. Each service and port has its own section, including notes, Searchsploit results, and vulnerability scan data.
   
9. Comprehensive Logging:
   Every command executed by Reconis is logged, along with its output. This includes errors and any updates made to system files like `/etc/hosts`. The logging ensures transparency and makes troubleshooting easier.
   
10. Interactive Prompts:
    The tool provides interactive prompts with validation and tab completion, making it user-friendly. You can choose whether to run certain tasks like Feroxbuster or vulnerability scans based on your needs. The prompts guide you through the process, but the script also allows for modifications if you want to customize the commands.

11. Tool Check and Installation:
    Before starting, Reconis checks if required tools (like Nmap, Feroxbuster, Enum4linux) are installed. If any tools are missing, it informs you, so you can install them before proceeding.

## Installation

To get started with Reconis, follow these steps:

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/empyr3an/Reconis.git
    cd Reconis
    ```

2. **Install Dependencies**:
    Ensure you have the required tools installed (e.g., Nmap, Feroxbuster, Enum4linux). You may need to install additional packages via `apt`, `pip`, or your package manager.

3. **Ensure Wordlist Directory is Included**:
    Make sure that the `wordlists` directory is present in the same directory as `Reconis.py`. This directory should contain the wordlists used by Feroxbuster for directory busting.

4. **Run the Script Locally**:
    ```bash
    python3 Reconis.py
    ```

## Running Reconis Globally in Kali Linux

There are two methods to run Reconis globally, allowing you to execute it from anywhere in your terminal:

### Method 1: Using a Symbolic Link

1. **Create a Symbolic Link to Reconis in `/usr/local/bin/`**:
    - This method allows you to run the script globally without moving it, keeping the `wordlists` directory in the same location as the script.
    ```bash
    sudo ln -s /path/to/your/Reconis.py /usr/local/bin/reconis
    sudo chmod +x /path/to/your/Reconis.py
    ```
    - Replace `/path/to/your/Reconis.py` with the actual path to the `Reconis.py` file.

2. **Ensure the Wordlist Directory is Accessible**:
    - The `wordlists` directory should remain in the same directory as `Reconis.py`. The script will still reference it correctly because the symbolic link allows the script to be run from anywhere without moving it.

3. **Run Reconis Globally**:
    - You can now run Reconis from anywhere by simply typing:
    ```bash
    reconis
    ```

### Method 2: Moving the Script and Wordlists to `/usr/local/bin/`

1. **Move Reconis and the Wordlists Directory**:
    - If you prefer to move the script to `/usr/local/bin/`, you also need to move the `wordlists` directory.
    ```bash
    sudo mv /path/to/your/Reconis.py /usr/local/bin/reconis
    sudo mv /path/to/your/wordlists /usr/local/bin/wordlists
    sudo chmod +x /usr/local/bin/reconis
    ```
    - Replace `/path/to/your/` with the actual paths to the `Reconis.py` file and the `wordlists` directory.

2. **Run Reconis Globally**:
    - You can now run Reconis from anywhere by simply typing:
    ```bash
    reconis
    ```

## Usage

Reconis is designed to be flexible and interactive. Simply run the script and follow the prompts to perform various reconnaissance tasks.

```bash
reconis
```

You can customize the options as needed, and the script will guide you through the process.

## Contributing

Contributions are welcome! If you encounter any issues, have suggestions, or want to contribute to the development of Reconis, feel free to submit a pull request or open an issue.

## License

Reconis is provided under the following conditions:

- You may use, modify, and distribute this software for personal and educational purposes.
- You may not publish this software as your own or use it in commercial products without permission from the author.
- Proper attribution to the original author must be maintained.

## Disclaimer

Reconis is provided as-is, without any warranty. Use it responsibly and only on systems where you have permission to do so.



