#ifndef SECURITYSCANNER_H
#define SECURITYSCANNER_H

#include <string>
#include <vector>
#include <utility> // For std::pair
#include <functional> // For std::function
#include <set> // For skipping directories in recursive scans

class SecurityScanner {
public:
    // Callback types for logging and progress reporting
    using LogCallback = std::function<void(const std::string& message, const std::string& type)>;
    using ProgressCallback = std::function<void(int progress)>;

    // Constructor takes logging and progress callbacks
    SecurityScanner(LogCallback log_cb, ProgressCallback progress_cb);

    // Public methods to trigger specific scans
    bool runFullAudit();
    bool runPasswordPolicyCheck();
    bool runKernelParamsCheck();
    bool runOutdatedPackagesCheck();

private:
    LogCallback _logMessage;
    ProgressCallback _scanProgress;

    // Helper function to execute a command and return its stdout and stderr
    std::pair<std::string, std::string> executeCommand(const std::string &command);
    // Helper function for executing commands that require elevated privileges via pkexec
    std::pair<std::string, std::string> executePrivilegedCommand(const std::string &command);

    // Core Audit Phases (private helper functions)
    void _checkSshRootLogin(bool &allGood, std::vector<std::string> &issues);
    void _scanSuid(const std::string &path, const std::vector<std::string> &safeSuid, bool &allGood, std::vector<std::string> &issues, long long &progress_counter, const std::set<std::string>& skipDirs);
    void _scanWorldWritable(const std::string &path, const std::vector<std::string> &stickyBitOkPaths, bool &allGood, std::vector<std::string> &issues, long long &progress_counter, const std::set<std::string>& skipDirs);
    void _scanPorts(bool &allGood, std::vector<std::string> &issues);
    void _checkFirewall(bool &allGood, std::vector<std::string> &issues);
    void _checkPasswordPolicy(bool &allGood, std::vector<std::string> &issues);
    void _checkKernelParams(bool &allGood, std::vector<std::string> &issues);
    void _checkOutdatedPackages(bool &allGood, std::vector<std::string> &issues);
};

#endif // SECURITYSCANNER_H