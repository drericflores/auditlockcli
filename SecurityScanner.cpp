#include "SecurityScanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>      // For popen, pclose
#include <sys/stat.h>  // For stat() system call
#include <string.h>    // For strerror (converts errno to string)
#include <regex>       // For std::regex
#include <filesystem>  // For std::filesystem (C++17)
#include <set>         // For std::set

namespace fs = std::filesystem;

SecurityScanner::SecurityScanner(LogCallback log_cb, ProgressCallback progress_cb)
    : _logMessage(log_cb), _scanProgress(progress_cb) {}

// Helper function to execute a command and return its stdout and stderr
std::pair<std::string, std::string> SecurityScanner::executeCommand(const std::string &command) {
    std::string stdOut;
    std::string stdErr;
    char buffer[128];

    // Execute command and capture stdout
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        stdErr = "Failed to run command: " + command;
        return {stdOut, stdErr};
    }
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            stdOut += buffer;
        }
    } catch (...) {
        pclose(pipe);
        stdErr = "Error reading command output for: " + command;
        return {stdOut, stdErr};
    }

    int exitCode = pclose(pipe);

    // In popen, the high-order byte of the return value is the exit status.
    // However, if the command couldn't be run (e.g., command not found), popen returns -1.
    // And on some systems, the exit status might be directly returned.
    // A more robust check might involve WEXITSTATUS from sys/wait.h for actual exit status,
    // but for simplicity, we check if it's 0 or 256 (0 << 8).
    // `grep` often exits with 1 if no match, which is not an error for us.
    if (exitCode != 0 && exitCode != 256 && exitCode != (1 << 8)) { // 256 is 0 << 8 (successful exit) and (1 << 8) is 1 (no match for grep)
        std::cerr << "Command failed: " << command << " Exit code: " << (exitCode >> 8) << std::endl;
        // Indicate failure by returning empty stdout if exit code is genuinely an error
        stdErr = "Command failed with exit code: " + std::to_string(exitCode >> 8);
        return {"", stdErr};
    }

    // Trim whitespace from stdout and stderr
    size_t first = stdOut.find_first_not_of(" \t\n\r");
    size_t last = stdOut.find_last_not_of(" \t\n\r");
    if (std::string::npos == first) stdOut.clear();
    else stdOut = stdOut.substr(first, (last - first + 1));

    // Stderr capture with popen is trickier, often requires redirecting stderr to stdout
    // For now, we only capture stdout as per original QProcess usage.
    // If stderr is crucial, the command string should be adjusted, e.g., "cmd 2>&1"

    return {stdOut, stdErr}; // stdErr will be empty for now unless explicitly handled
}

// Helper function for executing commands that require elevated privileges via pkexec
std::pair<std::string, std::string> SecurityScanner::executePrivilegedCommand(const std::string &command) {
    // pkexec itself might prompt for a graphical password.
    // We append "2>&1" to capture stderr into stdout
    std::string full_command = "pkexec sh -c \"" + command + "\" 2>&1";
    std::string stdOut;
    char buffer[128];

    FILE* pipe = popen(full_command.c_str(), "r");
    if (!pipe) {
        std::string stdErr = "Failed to run privileged command (popen failed): " + command;
        _logMessage("ERROR: " + stdErr, "danger");
        return {"", stdErr};
    }
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            stdOut += buffer;
        }
    } catch (...) {
        pclose(pipe);
        std::string stdErr = "Error reading privileged command output for: " + command;
        _logMessage("ERROR: " + stdErr, "danger");
        return {"", stdErr};
    }

    int exitCode = pclose(pipe);

    // Trim whitespace
    size_t first = stdOut.find_first_not_of(" \t\n\r");
    size_t last = stdOut.find_last_not_of(" \t\n\r");
    if (std::string::npos == first) stdOut.clear();
    else stdOut = stdOut.substr(first, (last - first + 1));

    if (exitCode != 0 && exitCode != 256 && exitCode != (1 << 8)) { // Check for actual non-zero exit
        _logMessage("Privileged command failed: " + command + " Exit code: " + std::to_string(exitCode >> 8), "danger");
        return {"", stdOut}; // stdOut might contain error messages from pkexec/command
    }
    return {stdOut, ""}; // No separate stderr captured from popen
}


// The main function that dispatches based on which audit was triggered
bool SecurityScanner::runFullAudit() {
    bool allGood = true; // Overall security status for the triggered audit
    std::vector<std::string> issues; // List of specific issues found

    _logMessage("Starting LockAudit system scan...\n", "info");
    _logMessage("Initiating Full System Audit.", "info");

    // --- Progress Setup for Full Audit ---
    int total_major_phases = 8; // SSH, SUID, WW, Ports, Firewall, Pass, Kernel, Packages
    int current_major_phase_index = 0;
    // For CLI, we can just print percentage updates
    // _scanProgress(0); // Emit 0% initially

    // Lambda to update overall progress (called after each major phase)
    auto updateMainProgress = [&]() {
        current_major_phase_index++;
        int progress = static_cast<int>((current_major_phase_index / static_cast<double>(total_major_phases)) * 100);
        _scanProgress(progress);
    };
    // -------------------------------------

    // Common skip directories for recursive file system scans
    std::set<std::string> commonSkipDirs = {
        "/proc", "/sys", "/dev", "/run", "/var/run", "/tmp", "/var/tmp",
        "/snap", // Snap mounts many SUID/SGID files in read-only mounts, which are legitimate
        "/var/lib/snapd/snaps", // Also part of snap system
        "/home", // Users should not typically have SUID files in their home directories
        "/media", "/mnt" // Removable media mount points
    };

    // --- SECTION HEADER ---
    _logMessage("\n--- SSH Configuration ---\n", "section_header");
    _checkSshRootLogin(allGood, issues);
    updateMainProgress();

    // --- SECTION HEADER ---
    _logMessage("\n--- SUID/SGID Files Scan ---\n", "section_header");
    _logMessage("\nScanning for SUID/SGID files (could take a while)...\n", "info");
    std::vector<std::string> safeSuid = {
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/su", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/pkexec", "/usr/bin/fusermount3",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        "/usr/libexec/polkit-agent-helper-1",
        "/usr/sbin/mount.cifs", "/usr/sbin/pppd",
        "/usr/lib/snapd/snap-confine",
        "/usr/lib/xorg/Xorg.wrap",
        "/usr/share/code/chrome-sandbox",
        "/usr/share/discord/chrome-sandbox"
    };
    long long suid_ww_progress_counter = 0; // Use long long for potentially large file counts
    _scanSuid("/", safeSuid, allGood, issues, suid_ww_progress_counter, commonSkipDirs);
    updateMainProgress(); // Mark SUID phase as done

    // --- SECTION HEADER ---
    _logMessage("\n--- World-Writable Files Scan ---\n", "section_header");
    _logMessage("\nChecking for world-writable files in /etc, /root, /var (excluding common safe ones)...\n", "info");
    std::vector<std::string> stickyBitOkPaths = { "/tmp", "/var/tmp", "/dev/shm", "/var/crash", "/var/lock", "/var/run/lock" };
    _scanWorldWritable("/", stickyBitOkPaths, allGood, issues, suid_ww_progress_counter, commonSkipDirs); // Continues counter from SUID scan
    updateMainProgress(); // Mark World-Writable phase as done

    // --- SECTION HEADER ---
    _logMessage("\n--- Network Ports ---\n", "section_header");
    _scanPorts(allGood, issues);
    updateMainProgress();

    // --- SECTION HEADER ---
    _logMessage("\n--- Firewall Status ---\n", "section_header");
    _checkFirewall(allGood, issues);
    updateMainProgress();

    // --- SECTION HEADER ---
    _logMessage("\n--- Password Policy ---\n", "section_header");
    _checkPasswordPolicy(allGood, issues);
    updateMainProgress();

    // --- SECTION HEADER ---
    _logMessage("\n--- Kernel Parameters (Sysctl) ---\n", "section_header");
    _checkKernelParams(allGood, issues);
    updateMainProgress();

    // --- SECTION HEADER ---
    _logMessage("\n--- Outdated Packages ---\n", "section_header");
    _checkOutdatedPackages(allGood, issues);
    updateMainProgress(); // Mark Outdated Packages phase as done

    _logMessage("\nLockAudit scan complete.", "info");

    // Report final issues
    if (!issues.empty()) {
        _logMessage("\n--- Summary of Issues Found ---", "section_header");
        for (const auto& issue : issues) {
            _logMessage("- " + issue, "risky");
        }
        _logMessage("\nOverall Status: Some issues found. Please review the recommendations above.", "danger");
    } else {
        _logMessage("\nOverall Status: All checks passed. Your system appears to be secure.", "good");
    }

    return allGood;
}

bool SecurityScanner::runPasswordPolicyCheck() {
    bool allGood = true;
    std::vector<std::string> issues;
    _logMessage("Initiating Password Policy Audit.", "info");
    _logMessage("\n--- Password Policy ---\n", "section_header");
    _checkPasswordPolicy(allGood, issues);
    if (!issues.empty()) {
        _logMessage("\n--- Summary of Issues Found ---", "section_header");
        for (const auto& issue : issues) {
            _logMessage("- " + issue, "risky");
        }
        _logMessage("\nOverall Status: Some password policy issues found.", "danger");
    } else {
        _logMessage("\nOverall Status: Password policy checks passed.", "good");
    }
    return allGood;
}

bool SecurityScanner::runKernelParamsCheck() {
    bool allGood = true;
    std::vector<std::string> issues;
    _logMessage("Initiating Kernel Parameters (Sysctl) Audit.", "info");
    _logMessage("\n--- Kernel Parameters (Sysctl) ---\n", "section_header");
    _checkKernelParams(allGood, issues);
    if (!issues.empty()) {
        _logMessage("\n--- Summary of Issues Found ---", "section_header");
        for (const auto& issue : issues) {
            _logMessage("- " + issue, "risky");
        }
        _logMessage("\nOverall Status: Some kernel parameter issues found.", "danger");
    } else {
        _logMessage("\nOverall Status: Kernel parameter checks passed.", "good");
    }
    return allGood;
}

bool SecurityScanner::runOutdatedPackagesCheck() {
    bool allGood = true;
    std::vector<std::string> issues;
    _logMessage("Initiating Outdated Packages Audit (requires 'apt' and internet access).", "info");
    _logMessage("\n--- Outdated Packages ---\n", "section_header");
    _checkOutdatedPackages(allGood, issues);
    if (!issues.empty()) {
        _logMessage("\n--- Summary of Issues Found ---", "section_header");
        for (const auto& issue : issues) {
            _logMessage("- " + issue, "risky");
        }
        _logMessage("\nOverall Status: Outdated packages found.", "danger");
    } else {
        _logMessage("\nOverall Status: Outdated package check passed.", "good");
    }
    return allGood;
}

// --- Private Helper Functions for Core Audit Phases ---

void SecurityScanner::_checkSshRootLogin(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("Checking SSH root login status...", "info");
    std::ifstream sshd_config("/etc/ssh/sshd_config");
    if (sshd_config.is_open()) {
        std::string line;
        bool rootLoginPermitted = false;
        while (std::getline(sshd_config, line)) {
            // Trim whitespace
            size_t first = line.find_first_not_of(" \t");
            if (std::string::npos == first) continue; // Empty line
            line = line.substr(first);

            if (line.rfind("#", 0) == 0 || line.empty()) continue; // Ignore comments and empty lines

            // Case-insensitive search for "PermitRootLogin"
            if (line.size() >= 15 && line.substr(0, 15) == "PermitRootLogin") { // Check length to avoid out of bounds
                std::string value_part = line.substr(15);
                // Convert to lowercase for case-insensitive comparison
                std::transform(value_part.begin(), value_part.end(), value_part.begin(), ::tolower);

                if (value_part.find("yes") != std::string::npos ||
                    value_part.find("without-password") != std::string::npos ||
                    value_part.find("prohibit-password") != std::string::npos) {
                    rootLoginPermitted = true;
                    break;
                }
            }
        }
        sshd_config.close();

        if (rootLoginPermitted) {
            _logMessage("[DANGEROUS] SSH root login is enabled. This is a security risk.", "danger");
            issues.push_back("SSH root login enabled");
            allGood = false;
            _logMessage("  Recommendation: Edit /etc/ssh/sshd_config and change 'PermitRootLogin yes' to 'PermitRootLogin no' (or 'without-password', 'prohibit-password' if necessary for specific setups) and restart sshd service (e.g., sudo systemctl restart sshd). Use 'sudo' for administrative tasks via a regular user account.", "info");
        } else {
            _logMessage("[GOOD] SSH root login is disabled or restricted.", "good");
        }
    } else {
        _logMessage("[INFO] Could not open /etc/ssh/sshd_config. Error: " + std::string(strerror(errno)), "info");
    }
}

void SecurityScanner::_scanSuid(const std::string &path, const std::vector<std::string> &safeSuid, bool &allGood, std::vector<std::string> &issues, long long &progress_counter, const std::set<std::string>& skipDirs) {
    try {
        for (const auto& entry : fs::directory_iterator(path)) {
            std::string absolutePath = entry.path().string();

            if (entry.is_directory()) {
                bool skip = false;
                for (const std::string &skipDir : skipDirs) {
                    if (absolutePath == skipDir || absolutePath.rfind(skipDir + "/", 0) == 0) { // startsWith equivalent
                        skip = true;
                        break;
                    }
                }
                if (!skip) {
                    // Recurse into subdirectories
                    _scanSuid(absolutePath, safeSuid, allGood, issues, progress_counter, skipDirs);
                }
            } else if (entry.is_regular_file()) {
                progress_counter++;
                if (progress_counter % 500 == 0) {
                    _scanProgress(static_cast<int>(progress_counter / 100)); // Arbitrary scaling for progress
                }

                struct stat st;
                if (stat(absolutePath.c_str(), &st) == 0) {
                    if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) {
                        bool is_safe = false;
                        for (const std::string& safe_path : safeSuid) {
                            if (absolutePath == safe_path) {
                                is_safe = true;
                                break;
                            }
                        }

                        if (is_safe) {
                            _logMessage("[GOOD] SUID/SGID file: " + absolutePath + " (OK)", "good");
                        } else {
                            if (absolutePath.find("chrome-sandbox") != std::string::npos ||
                                absolutePath.find("electron") != std::string::npos) {
                                _logMessage("[INFO] SUID/SGID sandbox: " + absolutePath + " (Common for browsers/Electron apps)", "info");
                            } else {
                                _logMessage("[RISKY] SUID/SGID file: " + absolutePath + " (Review if necessary)", "risky");
                                issues.push_back("SUID/SGID: " + absolutePath);
                                allGood = false;
                                _logMessage("  Recommendation: Verify this SUID/SGID file is legitimate and from a trusted source. If unsure or unneeded, consider removing the associated package (e.g., sudo apt remove <package-name>). Check if it's a known vulnerability source for privilege escalation.", "info");
                            }
                        }
                    }
                } else {
                    _logMessage("[INFO] Cannot stat file '" + absolutePath + "' (Error: " + std::string(strerror(errno)) + ")", "info");
                }
            }
        }
    } catch (const fs::filesystem_error& ex) {
        // Handle permissions errors or other filesystem issues gracefully
        _logMessage("[WARNING] File system scan error in " + path + ": " + ex.what(), "risky");
    }
}

void SecurityScanner::_scanWorldWritable(const std::string &path, const std::vector<std::string> &stickyBitOkPaths, bool &allGood, std::vector<std::string> &issues, long long &progress_counter, const std::set<std::string>& skipDirs) {
    try {
        for (const auto& entry : fs::directory_iterator(path)) {
            std::string absolutePath = entry.path().string();

            bool skip = false;
            for (const std::string &skipDir : skipDirs) {
                if (absolutePath == skipDir || absolutePath.rfind(skipDir + "/", 0) == 0) { // startsWith equivalent
                    skip = true;
                    break;
                }
            }
            if (skip) continue;

            progress_counter++;
            if (progress_counter % 500 == 0) {
                _scanProgress(static_cast<int>(progress_counter / 100)); // Arbitrary scaling for progress
            }

            struct stat st;
            if (stat(absolutePath.c_str(), &st) == 0) {
                if (st.st_mode & S_IWOTH) { // If world-writable bit is set
                    bool isStickyBitSet = (st.st_mode & S_ISVTX); // Check for sticky bit (S_ISVTX)

                    if (isStickyBitSet) {
                        bool isLegitSticky = false;
                        for (const std::string &okPath : stickyBitOkPaths) {
                            if (absolutePath == okPath || absolutePath.rfind(okPath + "/", 0) == 0) {
                                isLegitSticky = true;
                                break;
                            }
                        }
                        if (isLegitSticky) {
                            _logMessage("[GOOD] World-writable (sticky bit): " + absolutePath + " (Standard for temp directories)", "good");
                        } else {
                            _logMessage("[RISKY] World-writable (sticky bit, non-standard): " + absolutePath + " (Review)", "risky");
                            issues.push_back("World-writable (sticky bit, non-standard): " + absolutePath);
                            allGood = false;
                            _logMessage("  Recommendation: This directory or file is world-writable with a sticky bit, but is not a standard temporary location. Review its purpose. If unintended, remove world-write permissions (e.g., sudo chmod o-w " + absolutePath + ").", "info");
                        }
                    } else { // World-writable without sticky bit
                        if (entry.is_directory()) {
                            _logMessage("[DANGER] World-writable DIRECTORY (no sticky bit): " + absolutePath + " (Critical Risk!)", "danger");
                            issues.push_back("World-writable DIR: " + absolutePath);
                            allGood = false;
                            _logMessage("  Recommendation: This directory is highly insecure. Remove world-write permissions immediately (e.g., sudo chmod o-w " + absolutePath + " or sudo chmod 755 " + absolutePath + " if safe). This could allow any user to delete/create/modify files within it.", "info");
                        } else { // World-writable file
                            _logMessage("[RISKY] World-writable FILE: " + absolutePath + " (Review)", "risky");
                            issues.push_back("World-writable FILE: " + absolutePath);
                            allGood = false;
                            _logMessage("  Recommendation: This file is world-writable. Remove world-write permissions unless specifically intended (e.g., sudo chmod o-w " + absolutePath + " or sudo chmod 644 " + absolutePath + " if safe). An attacker could modify its contents.", "info");
                        }
                    }
                }
            } else {
                _logMessage("[INFO] Cannot stat file '" + absolutePath + "' (Error: " + std::string(strerror(errno)) + ")", "info");
            }

            if (entry.is_directory()) {
                // Recurse into subdirectories, also checking the specific skipDirs again
                _scanWorldWritable(absolutePath, stickyBitOkPaths, allGood, issues, progress_counter, skipDirs);
            }
        }
    } catch (const fs::filesystem_error& ex) {
        _logMessage("[WARNING] File system scan error in " + path + ": " + ex.what(), "risky");
    }
}


void SecurityScanner::_scanPorts(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("Checking listening TCP/UDP ports and associated processes (requires 'lsof')...\n", "info");
    std::pair<std::string, std::string> result = executeCommand("lsof -i -P -n");
    std::string lsofOutput = result.first;
    std::string lsofError = result.second; // This will likely be empty from current executeCommand

    std::istringstream iss(lsofOutput);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    if (lsofOutput.empty() || lines.empty() || lines.at(0).find("COMMAND") == std::string::npos) {
        _logMessage("[WARNING] 'lsof' command failed or not found. Cannot perform detailed port scan. Error: " + (lsofError.empty() ? "No output or permission denied" : lsofError), "risky");
        issues.push_back("Detailed port scan failed (lsof issue)");
        _logMessage("  Recommendation: Ensure 'lsof' is installed (sudo apt install lsof) and your user has permissions to execute it. This tool is crucial for detailed port analysis.", "info");
        return;
    }

    // No specific "RISKY" or "DANGER" flags for ports here, as UFW handles blocking.
    // This section is purely informational to list what's listening internally.
    // The firewall check will determine if external access is blocked.

    for (size_t i = 1; i < lines.size(); ++i) { // Start from 1 to skip header
        std::string current_line = lines.at(i);
        std::istringstream line_stream(current_line);
        std::vector<std::string> parts;
        std::string part;
        while (line_stream >> part) {
            parts.push_back(part);
        }

        if (parts.size() < 9) continue;

        std::string command = parts.at(0);
        std::string pid = parts.at(1);
        std::string type = parts.at(7); // e.g., IPv4
        std::string protocol_full = parts.at(8); // e.g., TCP, UDP
        std::string name = parts.at(9); // e.g., *:22, 127.0.0.1:631

        std::regex re(":\\d+");
        std::smatch match;
        std::string port_str;
        if (std::regex_search(name, match, re)) {
            port_str = match.str().substr(1); // Extract port number, remove leading ':'
        } else {
            continue; // No port found in the expected format
        }

        _logMessage("[INFO] Open " + protocol_full + " Port: " + port_str + " (" + type + ") - Process: " + command + " (PID: " + pid + ")", "info");
    }
}

void SecurityScanner::_checkFirewall(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("\nChecking firewall status and configuration...\n", "info");

    std::pair<std::string, std::string> ufwResult = executePrivilegedCommand("ufw status verbose");
    std::string ufwStatusVerbose = ufwResult.first;

    if (ufwStatusVerbose.find("Status: active") != std::string::npos) {
        _logMessage("[GOOD] UFW firewall is active.", "good");

        if (ufwStatusVerbose.find("Default: deny (incoming)") == std::string::npos) {
            _logMessage("[RISKY] UFW default incoming policy is NOT 'deny'. System is more exposed.", "risky");
            issues.push_back("UFW default incoming policy is not 'deny'");
            allGood = false;
            _logMessage("  Recommendation: Set UFW's default incoming policy to 'deny' (sudo ufw default deny incoming). This blocks all incoming connections by default, enhancing security. Then, add specific 'allow' rules for services you need (e.g., sudo ufw allow ssh).", "info");
        } else {
            _logMessage("[GOOD] UFW default incoming policy is 'deny'.", "good");
        }
        if (ufwStatusVerbose.find("Default: allow (outgoing)") == std::string::npos) {
            _logMessage("[RISKY] UFW default outgoing policy is NOT 'allow'. This may restrict your system's outbound connectivity.", "risky");
            _logMessage("  Recommendation: Set UFW's default outgoing policy to 'allow' (sudo ufw default allow outgoing). Then, if necessary, add specific 'deny' rules for unwanted outbound connections.", "info");
        } else {
            _logMessage("[GOOD] UFW default outgoing policy is 'allow'.", "good");
        }

    } else {
        std::pair<std::string, std::string> firewallDResult = executeCommand("firewall-cmd --state");
        std::string firewallDState = firewallDResult.first;

        if (firewallDState.find("running") != std::string::npos) {
            _logMessage("[GOOD] Firewalld is active.", "good");
            _logMessage("  Recommendation: Ensure Firewalld is configured to only allow necessary incoming traffic. Use 'sudo firewall-cmd --list-all' to review rules and zones.", "info");
        } else {
            _logMessage("[DANGER] No active firewall detected. Please enable a firewall immediately.", "danger");
            allGood = false;
            issues.push_back("No active firewall detected");
            _logMessage("  Recommendation: Enable a firewall immediately. For Pop!_OS/Ubuntu, UFW is recommended (sudo ufw enable). After enabling, configure specific rules for services you need (e.g., sudo ufw allow ssh).", "info");
        }
    }
}

void SecurityScanner::_checkPasswordPolicy(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("Initiating Password Policy Audit.", "info");
    std::ifstream loginDefs("/etc/login.defs");
    if (loginDefs.is_open()) {
        std::string line;
        int minLen = 6;
        int maxDays = 99999;
        int minDays = 0;
        std::string encryptMethod = "UNKNOWN";

        while (std::getline(loginDefs, line)) {
            size_t first = line.find_first_not_of(" \t");
            if (std::string::npos == first) continue;
            line = line.substr(first);

            if (line.rfind("#", 0) == 0 || line.empty()) continue;

            std::istringstream iss(line);
            std::string key;
            iss >> key;

            if (key == "PASS_MIN_LEN") {
                iss >> minLen;
            } else if (key == "PASS_MAX_DAYS") {
                iss >> maxDays;
            } else if (key == "PASS_MIN_DAYS") {
                iss >> minDays;
            } else if (key == "ENCRYPT_METHOD") {
                iss >> encryptMethod;
            }
        }
        loginDefs.close();

        _logMessage("  Password Policy from /etc/login.defs:", "info");

        // Min Length Check
        _logMessage("  - Minimum Length: " + std::to_string(minLen), minLen < 8 ? "risky" : "good");
        if (minLen < 8) {
            allGood = false;
            issues.push_back("Weak password min length (" + std::to_string(minLen) + " < 8)");
            _logMessage("    Recommendation: Increase PASS_MIN_LEN to 8 or more in /etc/login.defs and ensure PAM modules (e.g., pam_cracklib.so or pam_pwquality.so) enforce strong complexity rules (e.g., sudo nano /etc/pam.d/common-password).", "info");
        }

        // Max Days Check
        _logMessage("  - Maximum Days: " + std::to_string(maxDays), maxDays > 180 ? "risky" : "good");
        if (maxDays > 180) {
            allGood = false;
            issues.push_back("Password max days too long (" + std::to_string(maxDays) + " > 180)");
            _logMessage("    Recommendation: Reduce PASS_MAX_DAYS to 90-180 in /etc/login.defs to enforce regular password changes. This helps mitigate risks from compromised credentials.", "info");
        }

        // Min Days Check
        _logMessage("  - Minimum Days (change freq): " + std::to_string(minDays), minDays > 0 ? "good" : "risky");
        if (minDays == 0) {
            allGood = false;
            issues.push_back("Password min days is 0 (allows immediate change)");
            _logMessage("    Recommendation: Set PASS_MIN_DAYS to a value greater than 0 (e.g., 1) in /etc/login.defs to prevent users from immediately changing a newly set password back. This ensures a password is used for a minimum period.", "info");
        }

        _logMessage("  - Encryption Method: " + encryptMethod + " (Requires PAM configuration check for full strength analysis)", "info");

    } else {
        _logMessage("[RISKY] Could not open /etc/login.defs to check password policy. Error: " + std::string(strerror(errno)), "risky");
        issues.push_back("Could not check password policy (file access error)");
        allGood = false;
        _logMessage("  Recommendation: Verify file permissions for /etc/login.defs. It should typically be readable by all (e.g., chmod 644 /etc/login.defs).", "info");
    }
}

void SecurityScanner::_checkKernelParams(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("Initiating Kernel Parameters (Sysctl) Audit.", "info");
    struct SysctlCheck { std::string param; std::string expected; std::string description; };
    SysctlCheck sysctlChecks[] = {
        {"net.ipv4.ip_forward", "0", "IP Forwarding (should be 0 for desktop systems)"},
        {"kernel.randomize_va_space", "2", "Address Space Layout Randomization (ASLR) (should be 2 for strong randomization)"},
        {"net.ipv4.tcp_syncookies", "1", "TCP SYN Cookies (protect against SYN flood attacks)"},
        {"net.ipv4.conf.all.rp_filter", "1", "Source validation (anti-spoofing for all interfaces)"},
        {"net.ipv4.conf.default.rp_filter", "1", "Source validation (anti-spoofing for default interface)"}
    };

    for (const auto& check : sysctlChecks) {
        std::pair<std::string, std::string> result = executeCommand("sysctl -n " + check.param);
        std::string value = result.first;
        std::string errorOutput = result.second; // This will likely be empty from current executeCommand

        if (value.empty() && !errorOutput.empty()) {
            _logMessage("[INFO] Could not retrieve sysctl parameter: " + check.param + " (Error: " + errorOutput + ")", "info");
        } else if (value.empty()) {
            _logMessage("[INFO] Could not retrieve sysctl parameter: " + check.param + " (No value found, might not exist)", "info");
        }
        else if (value == check.expected) {
            _logMessage("[GOOD] " + check.description + ": " + value + " (Expected: " + check.expected + ")", "good");
        } else {
            _logMessage("[RISKY] " + check.description + ": " + value + " (Expected: " + check.expected + "). Consider changing to expected value.", "risky");
            allGood = false;
            issues.push_back("Sysctl: " + check.param + " expected " + check.expected + ", got " + value);
            _logMessage("  Recommendation: To set this permanently, create/edit a file in /etc/sysctl.d/ (e.g., /etc/sysctl.d/99-security.conf) and add the line '" + check.param + " = " + check.expected + "'. Then apply with 'sudo sysctl -p'.", "info");
        }
    }
}

void SecurityScanner::_checkOutdatedPackages(bool &allGood, std::vector<std::string> &issues) {
    _logMessage("Initiating Outdated Packages Audit (requires 'apt' and internet access).", "info");

    _logMessage("Running 'pkexec apt update' to refresh package lists...", "info");
    std::pair<std::string, std::string> aptUpdateResult = executePrivilegedCommand("apt update");
    std::string aptUpdateOutput = aptUpdateResult.first;

    // Check for "E:" or "failed to fetch" in output, which indicate update failure
    if (aptUpdateOutput.find("E:") != std::string::npos || aptUpdateOutput.find("failed to fetch") != std::string::npos || aptUpdateOutput.empty()) {
        _logMessage("[DANGER] 'pkexec apt update' failed. Check internet connection, repository configuration, or pkexec permissions.", "danger");
        if (!aptUpdateOutput.empty()) _logMessage("Error output from apt update:\n" + aptUpdateOutput, "danger");
        issues.push_back("Outdated packages check failed (apt update error)");
        allGood = false;
        _logMessage("  Recommendation: Ensure your internet connection is active. Verify entries in /etc/apt/sources.list and /etc/apt/sources.list.d/ are correct. Run 'sudo apt update' in a terminal to check for specific error messages.", "info");
        return;
    } else {
        _logMessage("'pkexec apt update' successful. Checking for upgradable packages...", "info");
    }

    std::pair<std::string, std::string> aptListResult = executeCommand("apt list --upgradable");
    std::string aptListUpgradable = aptListResult.first;
    std::string aptListError = aptListResult.second;

    if (!aptListError.empty() && aptListUpgradable.empty()) {
        _logMessage("[WARNING] 'apt list --upgradable' failed. Error: " + aptListError, "risky");
        issues.push_back("Outdated packages check failed (apt list error)");
        allGood = false;
        return;
    }

    std::istringstream iss(aptListUpgradable);
    std::string line;
    std::vector<std::string> upgradablePackages;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            upgradablePackages.push_back(line);
        }
    }

    if (upgradablePackages.size() > 1) { // Size 1 is just the header "Listing..."
        _logMessage("[RISKY] Outdated packages found. Update your system regularly for security patches:", "risky");
        allGood = false;
        for (size_t i = 1; i < upgradablePackages.size(); ++i) {
            std::string pkgLine = upgradablePackages.at(i);
            _logMessage(" - " + pkgLine, "risky");
            // Extract package name before the first '/'
            size_t slash_pos = pkgLine.find('/');
            if (slash_pos != std::string::npos) {
                 issues.push_back("Outdated package: " + pkgLine.substr(0, slash_pos));
            } else {
                 issues.push_back("Outdated package: " + pkgLine);
            }
        }
        _logMessage("  Recommendation: Run 'sudo apt update && sudo apt upgrade' in your terminal to apply all pending security and feature updates. Reboot if a kernel or critical system component was updated.", "info");
    } else {
        _logMessage("[GOOD] No outdated packages found. Your system is up to date.", "good");
    }
}