from scapy.all import *
from scapy.arch.windows import *
import sys

with open("scapy_debug.txt", "w") as f:
    f.write(f"Scapy Version: {conf.version}\n")
    f.write("Dir scapy.arch.windows:\n")
    f.write(str(dir(sys.modules['scapy.arch.windows'])) + "\n\n")
    
    try:
        f.write("get_windows_if_list():\n")
        f.write(str(get_windows_if_list()) + "\n\n")
    except Exception as e:
        f.write(f"get_windows_if_list error: {e}\n\n")

    try:
        f.write("conf.ifaces:\n")
        f.write(str(conf.ifaces) + "\n\n")
    except Exception as e:
        f.write(f"conf.ifaces error: {e}\n\n")
