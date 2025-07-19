# network_utils.py

import psutil

def list_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        ip = None
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
        interfaces.append({"name": iface, "ip": ip})
    return interfaces

def get_iface_ip(interface_name):
    addrs = psutil.net_if_addrs().get(interface_name, [])
    for addr in addrs:
        if addr.family.name == "AF_INET":
            return addr.address
    return None
