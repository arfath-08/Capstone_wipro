#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

// Function to check if a device is up or down
bool is_device_up(const std::string& device_ip) {
    std::string command = "ping -c 1 " + device_ip + " > /dev/null 2>&1";
    return std::system(command.c_str()) == 0;
}

// Function to get the current configuration from a file
std::string get_current_configuration(const std::string& config_file_path) {
    std::ifstream config_file(config_file_path);
    if (!config_file) {
        std::cerr << "Error opening configuration file." << std::endl;
        return "";
    }
    std::string current_config((std::istreambuf_iterator<char>(config_file)),
                               std::istreambuf_iterator<char>());
    return current_config;
}

// Function to check if the current configuration matches the required configuration
bool is_configuration_compliant(const std::string& current_config, const std::string& required_config) {
    return current_config == required_config;
}

int main() {
    std::string device_ip = "192.168.1.1";  // Example IP address
    std::string config_file_path = "current_config.txt";  // Path to the current configuration file
    std::string required_config = "hostname router1\ninterface GigabitEthernet0/1\nip_address 192.168.1.1\n";

    // Check if the device is up or down
    if (is_device_up(device_ip)) {
        std::cout << "Device " << device_ip << " is UP." << std::endl;
    } else {
        std::cout << "Device " << device_ip << " is DOWN." << std::endl;
    }

    // Check if the configuration is compliant
    std::string current_config = get_current_configuration(config_file_path);
    if (is_configuration_compliant(current_config, required_config)) {
        std::cout << "Configuration is compliant." << std::endl;
    } else {
        std::cout << "Configuration is not compliant." << std::endl;
    }

    return 0;
}
