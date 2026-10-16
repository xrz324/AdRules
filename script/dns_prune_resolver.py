#!/usr/bin/env python3
"""DNS wire-format and retry primitives used by the prune scheduler."""

from __future__ import annotations

import random
import socket
import struct
import threading
import time
from typing import Optional, Tuple

try:
    from dns_prune_model import DnsReply
except ImportError:  # Support ``python -m script.dns_prune_resolver``.
    from .dns_prune_model import DnsReply  # type: ignore[no-redef]


QTYPE_A = 1
QTYPE_AAAA = 28
QCLASS_IN = 1


def encode_qname(domain: str) -> bytes:
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("empty domain")

    labels = domain.split(".")
    output = bytearray()
    for label in labels:
        if not label:
            raise ValueError(f"invalid label in domain: {domain}")
        label_bytes = label.encode("idna")
        if len(label_bytes) > 63:
            raise ValueError(f"label too long in domain: {domain}")
        output.append(len(label_bytes))
        output.extend(label_bytes)
    output.append(0)
    return bytes(output)


def build_query(domain: str, qtype: int) -> Tuple[int, bytes]:
    query_id = random.randint(0, 0xFFFF)
    flags = 0x0100
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    question = encode_qname(domain) + struct.pack("!HH", qtype, QCLASS_IN)
    return query_id, header + question


def udp_query_once(
    resolver: str,
    domain: str,
    qtype: int,
    timeout_ms: int,
) -> DnsReply:
    query_id, packet = build_query(domain, qtype)
    timeout_s = max(0.05, timeout_ms / 1000.0)

    is_ipv6 = ":" in resolver
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    address = (resolver, 53, 0, 0) if is_ipv6 else (resolver, 53)

    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        sock.sendto(packet, address)
        data, _ = sock.recvfrom(4096)
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001 - cleanup must not mask probe errors.
            pass

    if len(data) < 12:
        raise ValueError("short dns reply")

    response_id, flags, _qd, ancount, nscount, _ar = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if response_id != query_id:
        raise ValueError("dns reply id mismatch")
    return DnsReply(rcode=flags & 0x000F, ancount=ancount, nscount=nscount)


def query_with_retries(
    resolver: str,
    domain: str,
    qtype: int,
    timeout_ms: int,
    retries: int,
    jitter_ms: int,
    semaphore: Optional[threading.BoundedSemaphore],
    retry_backoff_ms: int = 30,
) -> Tuple[str, Optional[DnsReply]]:
    """Return ``(answer-kind, reply)`` for one resolver query."""

    attempts = max(1, 1 + max(0, retries))
    for attempt in range(1, attempts + 1):
        if jitter_ms > 0:
            time.sleep(random.uniform(0, jitter_ms / 1000.0))
        try:
            if semaphore is None:
                reply = udp_query_once(resolver, domain, qtype, timeout_ms)
            else:
                with semaphore:
                    reply = udp_query_once(resolver, domain, qtype, timeout_ms)
        except Exception:  # noqa: BLE001 - isolate one resolver failure.
            # The resolver boundary is deliberately conservative: any socket
            # or packet error is retried and ultimately becomes ``error``.
            reply = None
        else:
            if reply.rcode == 0 and reply.ancount > 0:
                return "answer", reply
            if reply.rcode == 0 and reply.ancount == 0:
                return "nodata", reply
            if reply.rcode == 3:
                return "nxdomain", reply
            return "error", reply

        if attempt < attempts:
            backoff_ms = max(0, int(retry_backoff_ms))
            if backoff_ms > 0:
                time.sleep(backoff_ms * (2 ** max(0, attempt - 1)) / 1000.0)
    return "error", None
