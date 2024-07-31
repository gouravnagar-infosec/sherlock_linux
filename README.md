# Sherlock: Advanced Interactive Linux System Artifact Collector

## Description
Sherlock is a versatile and interactive Bash script designed for collecting a comprehensive range of system artifacts from a Linux environment. The script aims to simplify the collection of critical system information for analysis, forensic investigation, and security assessments. This tool is particularly useful for system administrators, security analysts, and incident responders who require a robust and automated method to gather system data efficiently.

## Features
- **Interactive Menu:** User-friendly interface for selecting specific artifacts to collect.
- **Parallel Processing:** Utilizes multiple CPU threads to expedite data collection.
- **Extensive Coverage:** Collects system information, user accounts, network configurations, process details, installed packages, file system data, log files, cron jobs, SSH configuration, firewall rules, browser and email artifacts, audit logs, memory dumps, container and VM information, and system configuration files.
- **Encryption:** Option to enable encryption of collected data for secure storage and transfer.
- **Automated Analysis:** Provides initial analysis such as counting unique IP addresses and listing top processes by CPU usage.
- **Logging:** Detailed logs of all actions performed and any warnings encountered.

## Usage
To run Sherlock, ensure you have the necessary dependencies (`tar`, `openssl`, `parallel`, `date`) installed on your system. The script must be executed with root privileges.

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/sherlock.git
   cd sherlock
   ```

2. Make the script executable:
   ```sh
   chmod +x sherlock.sh
   ```

3. Run the script as root:
   ```sh
   sudo ./sherlock.sh
   ```

Follow the interactive prompts to select the artifacts you wish to collect. The collected data will be stored in a timestamped directory (`sherlock_evidence_<timestamp>`).

## Requirements
- Linux environment
- Bash shell
- Root privileges
- Dependencies: `tar`, `openssl`, `parallel`, `date`

## License
Sherlock is released under the MIT License. See the `LICENSE` file for more details.

## Author
Gourav Nagar

For any inquiries or contributions, please feel free to reach out or submit a pull request.

---

**Note:** Ensure the script is executed with caution, especially on production systems, as it involves collecting extensive system data and could impact performance during its execution.
