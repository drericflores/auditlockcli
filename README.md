AuditLock CLI
AuditLock CLI is a command-line security scanner for Linux systems, designed to help users identify potential security vulnerabilities and misconfigurations. It performs various checks, including SSH configuration, SUID/SGID file analysis, world-writable file detection, network port scanning, firewall status, password policy enforcement, and kernel parameter auditing.

This tool is a refactored version of an existing C++ application, adapted for command-line use without GUI dependencies.

Features
Full System Audit: Comprehensive scan covering all checks.

SSH Configuration Check: Verifies PermitRootLogin setting.

SUID/SGID File Scan: Identifies potentially risky SUID/SGID binaries.

World-Writable File Scan: Detects insecure world-writable files and directories.

Network Port Scan: Lists listening TCP/UDP ports and associated processes.

Firewall Status Check: Assesses UFW or Firewalld status and default policies.

Password Policy Audit: Reviews /etc/login.defs for password strength, age, and reuse policies.

Kernel Parameters (Sysctl) Check: Verifies critical kernel security settings.

Outdated Packages Check: Identifies outdated apt packages requiring updates.

Prerequisites
Before you can compile and run AuditLock CLI, ensure you have the following:

C++ Compiler: A C++17 compatible compiler (e.g., GCC 7 or newer).

System Utilities:

lsof: For network port scanning. Install with sudo apt install lsof (Debian/Ubuntu).

ufw or firewalld: For firewall checks. One of these should be installed and preferably active.

apt: For outdated package checks (specific to Debian/Ubuntu-based systems).

pkexec: For executing commands requiring elevated privileges (e.g., apt update, ufw status verbose). This will prompt for your user password graphically.

Compilation
Save the files:
Ensure you have the following three files in the same directory:

SecurityScanner.h

SecurityScanner.cpp

main.cpp

Compile with g++:
Open your terminal, navigate to the directory containing the files, and run the compilation command:

g++ -std=c++17 SecurityScanner.cpp main.cpp -o auditlock_cli

If you encounter linking errors related to std::filesystem (e.g., "undefined reference to std::filesystem::..."), you might need to explicitly link the stdc++fs library:

g++ -std=c++17 SecurityScanner.cpp main.cpp -o auditlock_cli -lstdc++fs

A successful compilation will produce an executable file named auditlock_cli.

Usage
Run auditlock_cli from your terminal with the desired option:

./auditlock_cli [OPTIONS]

Available Options:
--full-audit: Performs a comprehensive security audit, running all available checks.

--password-policy: Checks only the password policy settings.

--kernel-params: Checks only the kernel security parameters (sysctl).

--outdated-packages: Checks only for outdated software packages.

--help, -h: Displays the usage information and available options.

Examples:
# Run a full system audit
./auditlock_cli --full-audit

# Check only the password policy
./auditlock_cli --password-policy

# Display help message
./auditlock_cli --help

Important Notes on Execution:
Elevated Privileges: Some checks (e.g., updating package lists, checking firewall status) require root privileges. The tool uses pkexec for these commands, which will typically open a graphical dialog prompting you for your user password. You must enter your password for these checks to proceed.

Output: The tool prints its findings directly to the console, using ANSI escape codes for color-coded messages (e.g., blue for info, green for good, yellow for risky, red for dangerous, cyan for section headers).

Progress: For long-running scans like SUID/SGID and world-writable file checks, a progress percentage will be updated on the same line in your terminal.

Licensing and Disclaimer
This project is open-source and licensed under the MIT License. For the full license text, please refer to the LICENSE file in the root of this repository.

Disclaimer:

This software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

You are solely responsible for any actions taken based on the output of this tool. The developers are not responsible for any direct, indirect, incidental, special, consequential, or exemplary damages, including but not limited to, damages for loss of profits, goodwill, use, data, or other intangible losses resulting from the use or inability to use this software. Always back up your system and consult with a security professional before making critical changes.
