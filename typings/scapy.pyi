from typing import Any

# Minimal stub for the scapy surfaces GHOSTWIRE touches (scapy is untyped and
# populates many attrs dynamically). Models only what we use.

class Scapy_Exception(Exception): ...

class Packet:
    time: Any
    def __len__(self) -> int: ...
    def haslayer(self, layer: Any) -> bool: ...
    def __getitem__(self, item: Any) -> Any: ...

class IP(Packet):
    src: str
    dst: str
    ttl: int

class IPv6(Packet):
    src: str
    dst: str
    hlim: int

class TCP(Packet):
    sport: int
    dport: int
    seq: int
    ack: int
    payload: Any
    flags: Any

class UDP(Packet):
    sport: int
    dport: int
    payload: Any

class ICMP(Packet):
    type: int
    code: int
    payload: Any

class Raw(Packet):
    def __init__(self, load: bytes = ...) -> None: ...
    load: bytes

class Ether(Packet):
    def __init__(self, src: str = ..., dst: str = ..., **kw: Any) -> None: ...

class PcapReader:
    def __init__(self, filename: str) -> None: ...
    def __iter__(self) -> Any: ...
    def __enter__(self) -> "PcapReader": ...
    def __exit__(self, *exc: Any) -> None: ...

def wrpcap(filename: str, pkt: Any) -> None: ...
def rdpcap(filename: str) -> Any: ...

# scapy.all re-exports the above.
class all:  # placeholder module
    ICMP: type
    IP: type
    IPv6: type
    TCP: type
    UDP: type
    Raw: type
    Ether: type
    PcapReader: type
    Scapy_Exception: type
    wrpcap: Any
    rdpcap: Any