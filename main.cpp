#include "SecurityScanner.h"
#include <iostream>
#include <string>
#include <vector>
#include <map> // For color codes

// ANSI escape codes for text color
const std::map<std::string, std::string> COLORS = {
    {"reset", "\033[0m"},
    {"info", "\033[0;34m"},       // Blue
    {"good", "\033[0;32m"},       // Green
    {"risky", "\033[0;33m"},      // Yellow
    {"danger", "\033[0;31m"},     // Red
    {"section_header", "\033[1;36m"} // Cyan Bold
};

// Callback function to print messages to console with color
void console_log_message(const std::string& message, const std::string& type) {
    std::string color = COLORS.count(type) ? COLORS.at(type) : COLORS.at("reset");
    std::cout << color << message << COLORS.at("reset") << std::endl;
}

// Callback function to print progress to console
void console_progress_update(int progress) {
    // For CLI, a simple percentage output might be sufficient, or a custom progress bar.
    // To avoid spamming, only print every 5% for example, or based on specific events.
    static int last_progress = -1;
    if (progress != last_progress) { // Only update if progress changed
        if (progress % 5 == 0 || progress == 0 || progress == 100) { // Update every 5% or at start/end
            std::cout << "\r" << COLORS.at("info") << "Scan Progress: " << progress << "%" << COLORS.at("reset") << std::flush;
            if (progress == 100) {
                std::cout << std::endl; // New line after completion
            }
        }
        last_progress = progress;
    }
}

// Function to print usage information
void print_usage(const std::string& program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Perform various security audits on your Linux system.\n\n"
              << "Options:\n"
              << "  --full-audit           Perform a comprehensive security audit.\n"
              << "  --password-policy      Check password policy settings.\n"
              << "  --kernel-params        Check kernel security parameters (sysctl).\n"
              << "  --outdated-packages    Check for outdated software packages (requires 'apt').\n"
              << "  --help, -h             Display this help message.\n\n"
              << "Example:\n"
              << "  " << program_name << " --full-audit\n"
              << "  " << program_name << " --password-policy\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string arg = argv[1];
    SecurityScanner scanner(console_log_message, console_progress_update);
    bool overall_success = true;

    if (arg == "--full-audit") {
        overall_success = scanner.runFullAudit();
    } else if (arg == "--password-policy") {
        overall_success = scanner.runPasswordPolicyCheck();
    } else if (arg == "--kernel-params") {
        overall_success = scanner.runKernelParamsCheck();
    } else if (arg == "--outdated-packages") {
        overall_success = scanner.runOutdatedPackagesCheck();
    } else if (arg == "--help" || arg == "-h") {
        print_usage(argv[0]);
        return 0;
    } else {
        std::cerr << COLORS.at("danger") << "Error: Unknown option '" << arg << "'" << COLORS.at("reset") << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return overall_success ? 0 : 1; // Return 0 for success, 1 for issues found
}