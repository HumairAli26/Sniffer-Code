# Sniffer-Code
This project is a Python-based network packet sniffer and analyzer built using the powerful Scapy library. It provides an intuitive way to capture, inspect, and analyze live network traffic in real time. The script is designed for students, developers, and security enthusiasts who want to explore how network packets work at a fundamental level.

When executed, the program starts sniffing packets from a specified network interface (by default enp0s3, but you can change it). For each captured packet, it extracts and displays key information such as the source IP address, destination IP address, and transport layer details. This makes it easier to visualize communication happening across the network.

The tool has built-in support for DNS traffic analysis. It specifically identifies DNS queries and logs the requested domain name, helping users monitor which hostnames are being looked up. This feature is particularly useful for detecting suspicious or unusual DNS requests in real-world scenarios.

Another highlight of this sniffer is its ability to detect and display HTTP traffic. By analyzing raw payload data, it recognizes common HTTP methods like GET, POST, and HEAD. Once detected, it prints the HTTP request line along with headers, offering a quick glance at what kind of web requests are being sent from the host machine. If the payload is fragmented or incomplete, the script still logs the raw data for further inspection.

The code includes proper error handling to avoid crashes when encountering undecodable payloads. Instead, it safely attempts to decode using UTF-8 and skips over problematic data. Additionally, the output is formatted with timestamps and clear separators, making packet logs easy to read and review.

This project can serve multiple purposes:

Learning tool for understanding network protocols like IP, DNS, and HTTP.

Debugging utility for developers working on network applications.

Security analysis aid for monitoring suspicious DNS queries or HTTP traffic.

Overall, this Python packet sniffer is a simple yet powerful way to dive into the world of network analysis. With just a few lines of code, it provides deep insights into live traffic, making it a valuable addition for learners and professionals interested in networking and cybersecurity.
