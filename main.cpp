#include <iostream>
#include <unordered_map>
#include <string>

// Mock function to simulate SNMP data retrieval
std::unordered_map<std::string, std::string> mockSnmpGet(const std::string& device) {
    std::unordered_map<std::string, std::string> data;
    if (device == "device1") {
        data["hostname"] = "device1";
        data["interface"] = "f0/0";
        data["ip_address"] = "192.168.1.1";
    } else if (device == "device2") {
        data["hostname"] = "device2";
        data["interface"] = "f0/1";
        data["ip_address"] = "192.168.2.1";
    } else {
        data["hostname"] = "unknown";
    }

    return data;
}

// Mock function to simulate device reachability
bool isDeviceUp(const std::string& device) {
    // Simulate a basic check
    return device == "device1" || device == "device2"; // Simulate that both devices are up
}

// Function to check compliance
bool checkCompliance(const std::unordered_map<std::string, std::string>& deviceData,
                      const std::unordered_map<std::string, std::string>& expectedConfig) {
    for (const auto& [key, value] : expectedConfig) {
        auto it = deviceData.find(key);
        if (it == deviceData.end() || it->second != value) {
            return false;
        }
    }
    return true;
}

int main() {
    // Define expected configurations
    std::unordered_map<std::string, std::string> expectedConfig1 = {
        {"hostname", "device1"},
        {"interface", "f0/0"},
        {"ip_address", "192.168.1.1"}
        
    };

    std::unordered_map<std::string, std::string> expectedConfig2 = {
        {"hostname", "device2"},
        {"interface", "f0/1"},
        {"ip_address", "192.168.2.1"}
        
    };

    // Devices to monitor
    std::string devices[] = {"device1", "device2"};

    for (const auto& device : devices) {
        // Check if device is up
        bool isUp = isDeviceUp(device);

        if (isUp) {
            // Fetch data from device (mocked)
            auto deviceData = mockSnmpGet(device);

            // Check compliance
            bool isCompliant = false;
            if (device == "device1") {
                isCompliant = checkCompliance(deviceData, expectedConfig1);
            } else if (device == "device2") {
                isCompliant = checkCompliance(deviceData, expectedConfig2);
            }

            // Print results
            std::cout << "Device " << device << " is " << (isUp ? "Up" : "Down") << std::endl;
            if (isUp) {
                std::cout << "Compliance: " << (isCompliant ? "Compliant" : "Not Compliant") << std::endl;
            }
        } else {
            std::cout << "Device " << device << " is Down" << std::endl;
        }
    }

    return 0;
}
