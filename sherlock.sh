#!/bin/bash

# Sherlock: Advanced Interactive Linux System Artifact Collector
# Author: Gourav Nagar
# Version: 1.0

set -e

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Load dependencies
for dep in tar openssl parallel date; do
    if ! command -v $dep &> /dev/null; then
        echo "Error: $dep is not installed. Please install it and try again." >&2
        exit 1
    fi
done

# Global variables
START_TIME=$(date +%s)
EXECUTING_USER=$(whoami)
OUTPUT_DIR="sherlock_evidence_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/sherlock.log"
REPORT_FILE="$OUTPUT_DIR/report.txt"
THREADS=$(nproc)
ENCRYPTION_KEY=""
SCRIPT_VERSION="1.0"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Progress indicator function
progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Function to collect artifacts with progress indicator
collect_artifact() {
    local source="$1"
    local destination="$2"
    
    if [ -e "$source" ]; then
        (cp -R "$source" "$destination" 2>/dev/null || log "WARNING: Failed to copy $source") &
        progress $!
    else
        log "WARNING: $source not found"
    fi
}

# Function to safely execute commands
safe_execute() {
    local cmd="$1"
    local output_file="$2"
    
    ($cmd > "$output_file" 2>/dev/null || log "WARNING: Failed to execute '$cmd'") &
    progress $!
}

# Function to prompt user for yes/no input
prompt_yes_no() {
    local prompt="$1"
    local response
    while true; do
        read -p "$prompt (y/n): " response
        case $response in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Main menu function
main_menu() {
    echo "Sherlock: Advanced Interactive Linux System Artifact Collector"
    echo "Author: Gourav Nagar"
    echo "Version: $SCRIPT_VERSION"
    echo "Select the artifacts you want to collect:"
    echo "1. System Information"
    echo "2. User Information"
    echo "3. Network Information"
    echo "4. Process Information"
    echo "5. Installed Packages"
    echo "6. File System Information"
    echo "7. Log Files"
    echo "8. Cron Jobs"
    echo "9. SSH Configuration"
    echo "10. Firewall Rules"
    echo "11. Browser Artifacts"
    echo "12. Email Artifacts"
    echo "13. Audit Logs"
    echo "14. Memory Dump"
    echo "15. Container and VM Information"
    echo "16. System Configuration Files"
    echo "17. Collect All"
    echo "18. Save/Load Collection Profile"
    echo "19. Enable Encryption"
    echo "20. Run Automated Analysis"
    echo "21. Exit"
}

# Function to collect system information
collect_system_info() {
    log "Collecting system information"
    mkdir -p "$OUTPUT_DIR/system"
    safe_execute "uname -a && lsb_release -a && dmidecode" "$OUTPUT_DIR/system/system_info.txt"
}

# Function to collect user information
collect_user_info() {
    log "Collecting user information"
    mkdir -p "$OUTPUT_DIR/users"
    safe_execute "getent passwd && last -n 1000 && w" "$OUTPUT_DIR/users/user_accounts.txt"
}

# Function to collect network information
collect_network_info() {
    log "Collecting network information"
    mkdir -p "$OUTPUT_DIR/network"
    safe_execute "ifconfig -a && ip addr && netstat -tuln && ss -tuln && arp -a && cat /etc/resolv.conf && lsof -i && route -n" "$OUTPUT_DIR/network/network_info.txt"
}

# Function to collect process information
collect_process_info() {
    log "Collecting process information"
    mkdir -p "$OUTPUT_DIR/processes"
    safe_execute "ps auxf" "$OUTPUT_DIR/processes/running_processes.txt"
}

# Function to collect installed packages
collect_installed_packages() {
    log "Collecting installed packages"
    mkdir -p "$OUTPUT_DIR/packages"
    if command -v dpkg > /dev/null; then
        safe_execute "dpkg -l" "$OUTPUT_DIR/packages/installed_packages.txt"
    elif command -v rpm > /dev/null; then
        safe_execute "rpm -qa" "$OUTPUT_DIR/packages/installed_packages.txt"
    elif command -v pacman > /dev/null; then
        safe_execute "pacman -Q" "$OUTPUT_DIR/packages/installed_packages.txt"
    fi
}

# Function to collect file system information
collect_filesystem_info() {
    log "Collecting file system information"
    mkdir -p "$OUTPUT_DIR/filesystem"
    safe_execute "df -h && mount && lsblk -f" "$OUTPUT_DIR/filesystem/filesystem_info.txt"
    safe_execute "find / -type f \( -perm -4000 -o -perm -2000 \) -ls" "$OUTPUT_DIR/filesystem/suid_sgid_files.txt"
    safe_execute "find / -type f -name '.*' -ls" "$OUTPUT_DIR/filesystem/hidden_files.txt"
}

# Function to collect log files
collect_log_files() {
    log "Collecting log files"
    mkdir -p "$OUTPUT_DIR/logs"
    for log in syslog auth.log messages kern.log dmesg boot.log; do
        collect_artifact "/var/log/$log" "$OUTPUT_DIR/logs/"
    done
}

# Function to collect cron jobs
collect_cron_jobs() {
    log "Collecting cron jobs"
    mkdir -p "$OUTPUT_DIR/cron_jobs"
    for user in /var/spool/cron/*; do
        collect_artifact "$user" "$OUTPUT_DIR/cron_jobs/"
    done
    collect_artifact "/etc/crontab" "$OUTPUT_DIR/cron_jobs/"
    collect_artifact "/etc/cron.d" "$OUTPUT_DIR/cron_jobs/"
}

# Function to collect SSH configuration
collect_ssh_config() {
    log "Collecting SSH configuration"
    mkdir -p "$OUTPUT_DIR/ssh_config"
    collect_artifact "/etc/ssh" "$OUTPUT_DIR/ssh_config/"
}

# Function to collect firewall rules
collect_firewall_rules() {
    log "Collecting firewall rules"
    mkdir -p "$OUTPUT_DIR/firewall"
    if command -v iptables > /dev/null; then
        safe_execute "iptables-save" "$OUTPUT_DIR/firewall/iptables_rules.txt"
    fi
    if command -v ufw > /dev/null; then
        safe_execute "ufw status verbose" "$OUTPUT_DIR/firewall/ufw_status.txt"
    fi
}

# Function to collect browser artifacts
collect_browser_artifacts() {
    log "Collecting browser artifacts"
    mkdir -p "$OUTPUT_DIR/browser"
    for user_home in /home/*; do
        collect_artifact "$user_home/.mozilla" "$OUTPUT_DIR/browser/"
        collect_artifact "$user_home/.config/google-chrome" "$OUTPUT_DIR/browser/"
        collect_artifact "$user_home/.config/chromium" "$OUTPUT_DIR/browser/"
    done
}

# Function to collect email artifacts
collect_email_artifacts() {
    log "Collecting email artifacts"
    mkdir -p "$OUTPUT_DIR/email"
    for user_home in /home/*; do
        collect_artifact "$user_home/.thunderbird" "$OUTPUT_DIR/email/"
        collect_artifact "$user_home/.mozilla-thunderbird" "$OUTPUT_DIR/email/"
    done
}

# Function to collect audit logs
collect_audit_logs() {
    log "Collecting audit logs"
    mkdir -p "$OUTPUT_DIR/audit"
    collect_artifact "/var/log/audit" "$OUTPUT_DIR/audit/"
}

# Function to collect memory dump
collect_memory_dump() {
    log "Collecting memory dump"
    mkdir -p "$OUTPUT_DIR/memory"
    if [ -r "/dev/mem" ]; then
        dd if=/dev/mem of="$OUTPUT_DIR/memory/memory.dump" bs=1M count=1024 2>/dev/null
    else
        log "WARNING: Unable to access /dev/mem"
    fi
}

# Function to collect container and VM information
collect_container_vm_info() {
    log "Collecting container and VM information"
    mkdir -p "$OUTPUT_DIR/containers"
    if command -v docker > /dev/null; then
        safe_execute "docker ps -a" "$OUTPUT_DIR/containers/docker_containers.txt"
        safe_execute "docker images" "$OUTPUT_DIR/containers/docker_images.txt"
    fi
    if command -v virsh > /dev/null; then
        safe_execute "virsh list --all" "$OUTPUT_DIR/containers/virsh_vms.txt"
    fi
}

# Function to collect system configuration files
collect_system_config() {
    log "Collecting system configuration files"
    mkdir -p "$OUTPUT_DIR/config"
    collect_artifact "/etc/passwd" "$OUTPUT_DIR/config/"
    collect_artifact "/etc/shadow" "$OUTPUT_DIR/config/"
    collect_artifact "/etc/group" "$OUTPUT_DIR/config/"
    collect_artifact "/etc/sudoers" "$OUTPUT_DIR/config/"
    safe_execute "systemctl list-units --type=service" "$OUTPUT_DIR/config/systemd_services.txt"
    collect_artifact "/etc/hosts" "$OUTPUT_DIR/config/"
    collect_artifact "/etc/network" "$OUTPUT_DIR/config/"
}

# Function to save/load collection profile
manage_profile() {
    local choice
    echo "1. Save current profile"
    echo "2. Load profile"
    read -p "Enter your choice: " choice

    case $choice in
        1)
            read -p "Enter profile name: " profile_name
            declare -a selected_options
            for i in "${!options_selected[@]}"; do
                if [ ${options_selected[$i]} -eq 1 ]; then
                    selected_options+=($i)
                fi
            done
            echo "${selected_options[@]}" > "$profile_name.profile"
            log "Profile saved as $profile_name.profile"
            ;;
        2)
            read -p "Enter profile name to load: " profile_name
            if [ -f "$profile_name.profile" ]; then
                IFS=' ' read -r -a loaded_options < "$profile_name.profile"
                options_selected=([1]=0 [2]=0 [3]=0 [4]=0 [5]=0 [6]=0 [7]=0 [8]=0 [9]=0 [10]=0 [11]=0 [12]=0 [13]=0 [14]=0 [15]=0 [16]=0)
                for opt in "${loaded_options[@]}"; do
                    options_selected[$opt]=1
                done
                log "Profile $profile_name loaded"
            else
                log "Profile not found: $profile_name.profile"
            fi
            ;;
        *)
            log "Invalid choice"
            ;;
    esac
}

# Function to enable encryption
enable_encryption() {
    read -s -p "Enter encryption password: " ENCRYPTION_KEY
    echo
    log "Encryption enabled"
}

# Function to run automated analysis
run_analysis() {
    log "Running automated analysis"
    mkdir -p "$OUTPUT_DIR/analysis"
    
    # Example: Count unique IP addresses in network info
    if [ -f "$OUTPUT_DIR/network/network_info.txt" ]; then
        grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$OUTPUT_DIR/network/network_info.txt" | sort | uniq -c > "$OUTPUT_DIR/analysis/unique_ips.txt"
    fi
    
    # Example: List top 10 processes by CPU usage
    if [ -f "$OUTPUT_DIR/processes/running_processes.txt" ]; then
        sort -nrk 3,3 "$OUTPUT_DIR/processes/running_processes.txt" | head -n 10 > "$OUTPUT_DIR/analysis/top_cpu_processes.txt"
    fi
    
    # Add more analysis tasks here
    
    log "Analysis complete. Results in $OUTPUT_DIR/analysis/"
}

# Function to format time
format_time() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    printf "%02d:%02d:%02d" $hours $minutes $secs
}

# Main loop
options_selected=([1]=0 [2]=0 [3]=0 [4]=0 [5]=0 [6]=0 [7]=0 [8]=0 [9]=0 [10]=0 [11]=0 [12]=0 [13]=0 [14]=0 [15]=0 [16]=0)

while true; do
    main_menu
    read -p "Enter your choice (1-21): " choice
    case $choice in
        1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)
            options_selected[$choice]=1
            ;;
        17)
            for i in {1..16}; do
                options_selected[$i]=1
            done
            ;;
        18)
            manage_profile
            continue
            ;;
        19)
            enable_encryption
            continue
            ;;
        20)
            run_analysis
            continue
            ;;
        21)
            break
            ;;
        *)
            echo "Invalid option. Please try again."
            continue
            ;;
    esac

    # Perform selected collections in parallel
    log "Starting artifact collection"
    for i in {1..16}; do
        if [ ${options_selected[$i]} -eq 1 ]; then
            case $i in
                1) collect_system_info ;;
                2) collect_user_info ;;
                3) collect_network_info ;;
                4) collect_process_info ;;
                5) collect_installed_packages ;;
                6) collect_filesystem_info ;;
                7) collect_log_files ;;
                8) collect_cron_jobs ;;
                9) collect_ssh_config ;;
                10) collect_firewall_rules ;;
                11) collect_browser_artifacts ;;
                12) collect_email_artifacts ;;
                13) collect_audit_logs ;;
                14) collect_memory_dump ;;
                15) collect_container_vm_info ;;
                16) collect_system_config ;;
            esac
        fi
    done | parallel -j $THREADS

    log "Artifact collection complete for this selection."
    if ! prompt_yes_no "Do you want to collect more artifacts?"; then
        break