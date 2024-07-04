import ipaddress
import socket
# Assuming you have the snmp_helper library installed (see installation instructions below)
import snmp_helper


def scan_for_snmp_devices(ip_range, community="public"):
    """
    Scans the specified IP range for SNMP-enabled devices using the given community string.

    Args:
        ip_range (str): A valid IP range in CIDR notation (e.g., "192.168.1.0/24").
        community (str, optional): The SNMP community string to use for authentication. Defaults to "public".

    Returns:
        list: A list of dictionaries containing discovered device information:
            - ip (str): IP address of the device.
            - reachable (bool): Whether the device was reachable.
            - snmp_enabled (bool): Whether the device responded to an SNMP request.
    """

    discovered_devices = []
    for ip in ipaddress.ip_network(ip_range):
        device = {"ip": str(ip), "reachable": False, "snmp_enabled": False}
        try:
            # Check basic reachability using a simple TCP ping
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Set a timeout to avoid slow responses
                result = sock.connect_ex((device["ip"], 161))  # SNMP port
                device["reachable"] = result == 0
        except Exception:
            pass

        if device["reachable"]:
            try:
                # If reachable, attempt a basic SNMP GET to confirm SNMP support
                snmp_value = snmp_helper.snmpget(
                    device["ip"], community, "SNMPv2-MIB::sysObjectID.0")
                device["snmp_enabled"] = snmp_value is not None
            except Exception:
                pass

        discovered_devices.append(device)

    return discovered_devices


def monitor_snmp_traffic(device_info, oid):
    """
    Monitors traffic on an SNMP-enabled device using the specified OID.

    Args:
        device_info (dict): Dictionary containing device information with keys:
            - ip (str): IP address of the device.
            - community (str, optional): The SNMP community string (if provided).
        oid (str): OID (Object Identifier) of the traffic metric to monitor.

    Returns:
        int or float: The retrieved traffic value, or None on error.
    """

    if "community" in device_info:
        community = device_info["community"]
    else:
        community = "public"  # Use default if not provided

    # Call helper function
    return monitor_snmp_traffic(device_info["ip"], community, oid)


def main():
    """
    Main function to configure scan parameters and monitor traffic.

    You can modify this section to:
    - Read scan range and OID from a configuration file or command-line arguments.
    - Implement error handling for invalid IP ranges or OIDs.
    - Log scan results and traffic data to a file or database.
    """

    ip_range = "192.168.1.0/24"
    oid = "IF-MIB::ifInOctets.1"  # Example OID for incoming traffic

    discovered_devices = scan_for_snmp_devices(ip_range)

    for device in discovered_devices:
        if device["reachable"] and device["snmp_enabled"]:
            traffic_value = monitor_snmp_traffic(device, oid)
            if traffic_value is not None:
                print(
                    f"Device {device['ip']}: Traffic on OID {oid} = {traffic_value}")


if __name__ == "__main__":
    main()
