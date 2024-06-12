from enum import Enum

class Protocol(Enum):
    IPv4 = 0x0800
    ICMP = 1
    TCP = 6
    UDP = 17