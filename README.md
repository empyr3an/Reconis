
# Reconis

Reconis is a tool designed to automate the network enumeration and reconnaissance phases of penetration testing. It simplifies various tasks, making it especially useful for those preparing for OSCP, working on HTB challenges, or engaging in network security assessments.

## About the Name
The name "Reconis" is a blend of "Recon" (short for reconnaissance) and "Kronos" (inspired by the Greek god of time). It symbolizes a tool that helps save time during the reconnaissance process.

## Features

- **Automated Nmap Scans**: Perform quick and detailed scans to identify open ports and services.
- **TCP and UDP Support**: Flexibility to scan both TCP and UDP ports depending on your needs.
- **Vulnerability Scanning**: Optionally run Nmap’s vulnerability scanning scripts to identify potential issues.
- **Searchsploit Integration**: Map discovered services to known vulnerabilities for quick exploitation reference.
- **/etc/hosts Management**: Automatically update the hosts file with domains extracted from scans to ensure smooth resolution.
- **Enum4linux Support**: Automate SMB enumeration on Windows environments.
- **Domain Scoring** (Experimental): A feature to prioritize domains based on HTTP headers and status codes for further testing.
- **Feroxbuster Integration**: Discover hidden directories and files on web servers.
- **CherryTree Documentation**: Generate structured reports in CherryTree format for easy documentation.
- **Comprehensive Logging**: Logs all commands and outputs for transparency and troubleshooting.
- **Interactive Prompts**: User-friendly prompts with validation and tab completion for ease of use.

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
    sudo chmod +x /usr/local/bin/reconis
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
