#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>

// Function to execute a system command and get the result
std::string exec(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to ping a device and check connectivity
bool ping(const std::string& ipAddress) {
    std::string cmd = "ping -c 1 " + ipAddress + " > /dev/null 2>&1"; // For Unix-based systems
    std::string result = exec(cmd);
    return result.find("1 packets transmitted, 1 received") != std::string::npos;
}

int main() {
    // List of IP addresses to ping
    std::string ipAddresses[] = {"192.168.1.10", "192.168.1.11", "192.168.1.12"};

    for (const auto& ip : ipAddresses) {
        if (ping(ip)) {
            std::cout << ip << " is up." << std::endl;
        } else {
            std::cout << ip << " is down." << std::endl;
        }
    }

    return 0;
}
