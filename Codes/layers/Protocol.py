from enum import enum

class Protocol(enum):
    IPv4 = 0x0800
    ICMP = 1
    TCP = 6
    UDP = 17