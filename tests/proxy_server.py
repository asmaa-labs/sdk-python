"""A real loopback HTTP proxy that tunnels CONNECT and records what crosses it."""

from __future__ import annotations

import socket
import ssl
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Self


@dataclass
class Tunnel:
    method: str
    target: str
    headers: dict[str, str]


class Proxy(AbstractContextManager["Proxy"]):
    """Answers each CONNECT with `status`; a 200 pipes bytes to `routes[target]`.

    `stall` accepts a request and never answers it. `received` holds every byte a
    client sent, tunnel contents included, so a test can show what the proxy saw.
    `tls` makes the proxy itself an HTTPS endpoint.
    """

    def __init__(
        self,
        routes: dict[str, tuple[str, int]] | None = None,
        *,
        status: int = 200,
        stall: bool = False,
        tls: ssl.SSLContext | None = None,
    ) -> None:
        self.tunnels: list[Tunnel] = []
        self.received = bytearray()
        self._routes = routes or {}
        self._status = status
        self._stall = stall
        self._tls = tls
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        # accept() wakes up regularly, so closing the proxy never waits on it.
        self._listener.settimeout(0.05)
        self.port = self._listener.getsockname()[1]
        self.url = f"{'http' if tls is None else 'https'}://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._closed.set()
        self._thread.join(timeout=2)
        self._listener.close()

    def _serve(self) -> None:
        while not self._closed.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _record(self, data: bytes) -> None:
        with self._lock:
            self.received.extend(data)

    def _handle(self, client: socket.socket) -> None:
        client.settimeout(5)
        if self._tls is not None:
            try:
                client = self._tls.wrap_socket(client, server_side=True)
            except OSError:
                client.close()
                return
        with client:
            try:
                self._exchange(client)
            except OSError:
                pass

    def _exchange(self, client: socket.socket) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(65536)
            if not chunk:
                return
            self._record(chunk)
            head += chunk
        request, _, early = head.partition(b"\r\n\r\n")
        line, *fields = request.decode("latin-1").split("\r\n")
        method, target, _ = line.split(" ", 2)
        headers = {
            name.strip().lower(): value.strip()
            for name, _, value in (field.partition(":") for field in fields)
        }
        with self._lock:
            self.tunnels.append(Tunnel(method, target, headers))
        if self._stall:
            self._closed.wait(5)
            return
        status = 405 if method != "CONNECT" else self._status
        if status != 200:
            client.sendall(
                f"HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\n"
                "Connection: close\r\n\r\n".encode()
            )
            return
        with socket.create_connection(self._routes[target], timeout=5) as upstream:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            upstream.sendall(early)
            self._pipe(client, upstream)

    def _pipe(self, client: socket.socket, upstream: socket.socket) -> None:
        def forward(source: socket.socket, sink: socket.socket, record: bool) -> None:
            try:
                while data := source.recv(65536):
                    if record:
                        self._record(data)
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                for end in (source, sink):
                    try:
                        end.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        back = threading.Thread(target=forward, args=(upstream, client, False), daemon=True)
        back.start()
        forward(client, upstream, True)
        back.join(timeout=5)
