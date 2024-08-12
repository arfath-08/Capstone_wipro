
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
 
#define PACKET_SIZE 64
#define PING_TIMEOUT 1 // 1 second
#define MONITOR_INTERVAL 10 // 10 seconds
#define SNMP_COMMUNITY "public"
#define SNMP_VERSION SNMP_VERSION_2c
 
// Device status enum
enum DeviceStatus {
    UP,
    DOWN
};
 
// Calculate checksum for ICMP packet
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
 
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}
 
// Send a single ping request
bool ping(const std::string &ip) {
    int sockfd;
    struct sockaddr_in addr;
    struct icmp icmp_packet;
    struct timeval tv;
 
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket error");
        return false;
    }
 
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
 
    // Create ICMP packet
    memset(&icmp_packet, 0, sizeof(icmp_packet));
    icmp_packet.icmp_type = ICMP_ECHO;
    icmp_packet.icmp_code = 0;
    icmp_packet.icmp_id = getpid();
    icmp_packet.icmp_seq = 0;
    icmp_packet.icmp_cksum = checksum(&icmp_packet, sizeof(icmp_packet));
 
    // Set socket timeout
    tv.tv_sec = PING_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
 
    // Send ICMP packet
    if (sendto(sockfd, &icmp_packet, sizeof(icmp_packet), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        perror("Sendto error");
        close(sockfd);
        return false;
    }
 
    // Receive response
    char buf[PACKET_SIZE];
    socklen_t addr_len = sizeof(addr);
    if (recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len) <= 0) {
        close(sockfd);
        return false; // No response
    }
 
    close(sockfd);
    return true; // Host is alive
}
 
// Query a device's SNMP configuration
std::string snmp_get(const std::string &ip, const std::string &oid_str) {
    struct snmp_session session, *sess_handle;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    struct variable_list *vars;
    int status;
 
    snmp_sess_init(&session);
    session.peername = strdup(ip.c_str());
    session.version = SNMP_VERSION;
    session.community = (u_char *)SNMP_COMMUNITY;
    session.community_len = strlen(SNMP_COMMUNITY);
 
    SOCK_STARTUP;
    sess_handle = snmp_open(&session);
 
    if (!sess_handle) {
        snmp_perror("snmp_open");
        SOCK_CLEANUP;
        return "";
    }
 
    pdu = snmp_pdu_create(SNMP_PDU_GET);
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
 
    if (!snmp_parse_oid(oid_str.c_str(), anOID, &anOID_len)) {
        snmp_perror("snmp_parse_oid");
        snmp_close(sess_handle);
        SOCK_CLEANUP;
        return "";
    }
 
    snmp_add_null_var(pdu, anOID, anOID_len);
    status = snmp_synch_response(sess_handle, pdu, &response);
 
    std::string result;
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for (vars = response->variables; vars; vars = vars->next_variable) {
            char buffer[1024];
            snprint_value(buffer, sizeof(buffer), vars->name, vars->name_length, vars);
            result = buffer;
        }
    } else {
        if (status == STAT_SUCCESS) {
            std::cerr << "SNMP Error: " << snmp_errstring(response->errstat) << std::endl;
        } else if (status == STAT_TIMEOUT) {
            std::cerr << "SNMP Timeout for " << ip << std::endl;
        } else {
            snmp_sess_perror("snmp_synch_response", sess_handle);
        }
    }
 
    if (response) snmp_free_pdu(response);
    snmp_close(sess_handle);
    SOCK_CLEANUP;
 
    return result;
}
 
// Monitor device status (up/down)
DeviceStatus monitor_device(const std::string &ip) {
    if (ping(ip)) {
        std::cout << "Device " << ip << " is UP." << std::endl;
        return UP;
    } else {
        std::cout << "Device " << ip << " is DOWN." << std::endl;
        return DOWN;
    }
}
 
// Compliance check function
bool check_compliance(const std::string &ip, const std::string &oid, const std::string &expected_value) {
    std::string actual_value = snmp_get(ip, oid);
    if (actual_value == expected_value) {
        std::cout << "Device " << ip << " is COMPLIANT for OID " << oid << "." << std::endl;
        return true;
    } else {
        std::cout << "Device " << ip << " is NON-COMPLIANT for OID " << oid << ". Expected: " << expected_value << ", Got: " << actual_value << std::endl;
        return false;
    }
}
 
// Function to monitor and check compliance of a device
void monitor_and_check_compliance(const std::string &ip, const std::vector<std::pair<std::string, std::string>> &compliance_rules) {
    while (true) {
        DeviceStatus status = monitor_device(ip);
        if (status == UP) {
            for (const auto &rule : compliance_rules) {
                check_compliance(ip, rule.first, rule.second);
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(MONITOR_INTERVAL));
    }
}
 
// Main function to start monitoring and compliance checks
int main() {
    std::string base_ip = "192.168.1."; // Adjust to your network's base IP
    int start = 1, end = 10; // Adjust the range according to your network
 
    // Compliance rules: (OID, expected value)
    std::vector<std::pair<std::string, std::string>> compliance_rules = {
        {"1.3.6.1.2.1.1.5.0", "Expected_Device_Name"}, // sysName.0 OID
        {"1.3.6.1.2.1.1.1.0", "Expected_Device_Description"} // sysDescr.0 OID
    };
 
    // Start monitoring and compliance check threads for each device
    std::vector<std::thread> threads;
    for (int i = start; i <= end; ++i) {
        std::string ip = base_ip + std::to_string(i);
        threads.push_back(std::thread(monitor_and_check_compliance, ip, compliance_rules));
    }
 
    // Join all threads
    for (auto &t : threads) {
        t.join();
    }
 
    return 0;
}
