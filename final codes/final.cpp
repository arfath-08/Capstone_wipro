#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <chrono>
#include <utility>

// Constants
const int MONITOR_INTERVAL = 60; // Monitor interval in seconds
const int PING_TIMEOUT = 1;      // Ping timeout in seconds

// Enum to represent device status
enum DeviceStatus { UP, DOWN };

// Function prototypes
std::string snmp_get(const std::string &ip, const std::string &oid);
DeviceStatus monitor_device(const std::string &ip);
bool ping(const std::string &ip); // Added function prototype

// Compliance check function
bool check_compliance(const std::string &ip, const std::string &oid, const std::string &expected_value);

// Function to monitor and check compliance of a device
void monitor_and_check_compliance(const std::string &ip, const std::vector<std::pair<std::string, std::string>> &compliance_rules);

#endif // NETWORK_MONITOR_H
