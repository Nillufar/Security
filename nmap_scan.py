import nmap

# Create an Nmap object
nm = nmap.PortScanner()

# Scan a host or network
nm.scan('127.0.0.1', '8080')  # Scan localhost for port 8080

# Print the scan results
print("Scan info:")
print(nm.all_hosts())  # List all the hosts that were scanned
print(nm['127.0.0.1'].state())  # Check the state of the host (up or down)

# Check for TCP open ports
if 'tcp' in nm['127.0.0.1']:
    print("Open TCP Ports:", nm['127.0.0.1']['tcp'].keys())
else:
    print("No open TCP ports found.")
