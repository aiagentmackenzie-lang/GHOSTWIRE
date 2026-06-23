from typing import Any

# Minimal stub for the dpkt surfaces GHOSTWIRE touches. dpkt is untyped; this
# models only what we use so mypy can follow our code without a blanket
# ignore_missing_imports.

class NeedData(Exception): ...
class UnpackError(Exception): ...

class pcap:
    @staticmethod
    def Reader(f: Any) -> Any: ...
    @staticmethod
    def pcapng(f: Any) -> Any: ...

class ethernet:
    class Ethernet:
        data: Any
        src: bytes
        dst: bytes
        type: int
        def __init__(self, buf: bytes) -> None: ...

class ip:
    class IP:
        src: bytes
        dst: bytes
        ttl: int
        data: Any
        def __init__(self, buf: bytes = ...) -> None: ...

class ip6:
    class IP6:
        src: bytes
        dst: bytes
        hlim: int
        data: Any
        def __init__(self, buf: bytes = ...) -> None: ...

class tcp:
    class TCP:
        sport: int
        dport: int
        data: Any
        flags: int
        seq: int
        ack: int
        win: int

class udp:
    class UDP:
        sport: int
        dport: int
        data: Any

class icmp:
    class ICMP:
        type: int
        code: int
        data: Any

class icmp6:
    class ICMP6:
        type: int
        code: int
        data: Any

class _DpktSub:
    # dpkt.dpkt.NeedData / dpkt.dpkt.UnpackError are real exceptions; model them
    # as BaseException subclasses so `except dpkt.dpkt.NeedData` type-checks.
    class NeedData(BaseException): ...
    class UnpackError(BaseException): ...


# `dpkt.dpkt` is accessed as a submodule attribute on the dpkt package.
dpkt: _DpktSub