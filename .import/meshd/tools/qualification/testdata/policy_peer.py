#!/usr/bin/env python3
"""Bounded TCP and UDP peer used by the Linux policy qualification harness."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import os
import secrets
import selectors
import signal
import socket
import sys
import threading
import time
from collections.abc import Sequence


CHALLENGE_PREFIX = b"meshtransit-policy-v1:"
CHALLENGE_SIZE = len(CHALLENGE_PREFIX) + 32
MAX_MESSAGE_SIZE = 64
PROBE_BLOCKED = 10
PROBE_INVALID_RESPONSE = 20
SOCKET_TIMEOUT_SECONDS = 1.0
BLOCKED_ERRNOS = frozenset(
    {
        None,
        errno.EACCES,
        errno.EADDRNOTAVAIL,
        errno.ECONNREFUSED,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
    }
)


class PolicyPeer:
    def __init__(self, addresses: Sequence[str], tcp_port: int, udp_port: int) -> None:
        self._addresses = tuple(parse_address(value) for value in addresses)
        self._tcp_port = validate_port(tcp_port)
        self._udp_port = validate_port(udp_port)
        self._selector = selectors.DefaultSelector()
        self._sockets: list[socket.socket] = []

    def open(self) -> None:
        try:
            for address in self._addresses:
                self._open_listener(address, socket.SOCK_STREAM, self._tcp_port)
                self._open_listener(address, socket.SOCK_DGRAM, self._udp_port)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        for listener in self._sockets:
            self._selector.unregister(listener)
            listener.close()
        self._sockets.clear()
        self._selector.close()

    def serve(self, stop: threading.Event) -> None:
        while not stop.is_set():
            for key, _ in self._selector.select(timeout=0.2):
                listener = key.fileobj
                if not isinstance(listener, socket.socket):
                    continue
                if listener.type & socket.SOCK_STREAM:
                    self._serve_tcp(listener)
                else:
                    self._serve_udp(listener)

    def _open_listener(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address, socket_type: int, port: int) -> None:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        listener = socket.socket(family, socket_type)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((str(address), port))
        if socket_type == socket.SOCK_STREAM:
            listener.listen(8)
        listener.setblocking(False)
        self._selector.register(listener, selectors.EVENT_READ)
        self._sockets.append(listener)

    @staticmethod
    def _serve_tcp(listener: socket.socket) -> None:
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            return
        with connection:
            connection.settimeout(SOCKET_TIMEOUT_SECONDS)
            message = bytearray()
            try:
                while len(message) < CHALLENGE_SIZE:
                    chunk = connection.recv(CHALLENGE_SIZE - len(message))
                    if not chunk:
                        return
                    message.extend(chunk)
                if valid_challenge(message):
                    connection.sendall(message)
            except (ConnectionError, TimeoutError, OSError):
                return

    @staticmethod
    def _serve_udp(listener: socket.socket) -> None:
        try:
            message, source = listener.recvfrom(MAX_MESSAGE_SIZE + 1)
        except BlockingIOError:
            return
        if not valid_challenge(message):
            return
        try:
            listener.sendto(message, source)
        except OSError:
            return


def parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in value:
        raise ValueError("scoped addresses are unsupported")
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("address must be unicast")
    return address


def validate_port(value: int) -> int:
    if value < 1024 or value > 65535:
        raise ValueError("port must be between 1024 and 65535")
    return value


def valid_challenge(message: bytes | bytearray) -> bool:
    return len(message) == CHALLENGE_SIZE and message.startswith(CHALLENGE_PREFIX)


def create_challenge() -> bytes:
    return CHALLENGE_PREFIX + secrets.token_bytes(32)


def classify_socket_error(error: BaseException) -> int:
    if isinstance(error, OSError) and error.errno not in BLOCKED_ERRNOS:
        return PROBE_INVALID_RESPONSE
    return PROBE_BLOCKED


def write_ready_file(path: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, b"ready\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def probe(protocol: str, source_text: str, address_text: str, port: int, timeout: float) -> int:
    source = parse_address(source_text)
    address = parse_address(address_text)
    if source.version != address.version:
        raise ValueError("source and destination address families must match")
    port = validate_port(port)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    challenge = create_challenge()

    try:
        with socket.socket(family, socket_type) as connection:
            connection.settimeout(timeout)
            connection.bind((str(source), 0))
            connection.connect((str(address), port))
            connection.sendall(challenge)
            response = bytearray()
            while len(response) < len(challenge):
                chunk = connection.recv(len(challenge) - len(response))
                if not chunk:
                    break
                response.extend(chunk)
    except (ConnectionError, TimeoutError, OSError) as error:
        result = classify_socket_error(error)
        if result == PROBE_INVALID_RESPONSE:
            print(f"probe infrastructure error: errno={error.errno}", file=sys.stderr)
        return result

    if secrets.compare_digest(response, challenge):
        return 0
    return PROBE_INVALID_RESPONSE


def serve_command(args: argparse.Namespace) -> int:
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    peer = PolicyPeer(args.address, args.tcp_port, args.udp_port)
    peer.open()
    try:
        write_ready_file(args.ready_file)
        peer.serve(stop)
    finally:
        peer.close()
    return 0


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def self_test() -> int:
    if classify_socket_error(OSError(errno.EADDRNOTAVAIL, "address removed")) != PROBE_BLOCKED:
        raise RuntimeError("removed source address must classify as blocked")
    if classify_socket_error(OSError(errno.EINVAL, "invalid argument")) != PROBE_INVALID_RESPONSE:
        raise RuntimeError("unexpected socket errors must classify as infrastructure failures")

    tcp_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    stop = threading.Event()
    peer = PolicyPeer(("127.0.0.1", "::1"), tcp_port, udp_port)
    peer.open()
    thread = threading.Thread(target=peer.serve, args=(stop,), daemon=True)
    thread.start()
    try:
        for address in ("127.0.0.1", "::1"):
            if probe("tcp", address, address, tcp_port, 1.0) != 0:
                raise RuntimeError(f"TCP self-test failed for {address}")
            if probe("udp", address, address, udp_port, 1.0) != 0:
                raise RuntimeError(f"UDP self-test failed for {address}")
    finally:
        stop.set()
        thread.join(timeout=2)
        peer.close()
    if thread.is_alive():
        raise RuntimeError("server did not stop")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="run bounded TCP and UDP echo listeners")
    serve_parser.add_argument("--address", action="append", required=True)
    serve_parser.add_argument("--tcp-port", type=int, required=True)
    serve_parser.add_argument("--udp-port", type=int, required=True)
    serve_parser.add_argument("--ready-file", required=True)

    probe_parser = subparsers.add_parser("probe", help="send one authenticated-format echo challenge")
    probe_parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    probe_parser.add_argument("--source-address", required=True)
    probe_parser.add_argument("--address", required=True)
    probe_parser.add_argument("--port", type=int, required=True)
    probe_parser.add_argument("--timeout", type=float, default=2.0)

    subparsers.add_parser("self-test", help="exercise dual-stack TCP and UDP locally")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            return serve_command(args)
        if args.command == "probe":
            if args.timeout < 0.2 or args.timeout > 10:
                parser.error("timeout must be between 0.2 and 10 seconds")
            return probe(args.protocol, args.source_address, args.address, args.port, args.timeout)
        return self_test()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"policy-peer: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
