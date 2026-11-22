"""Choose the HTTP proxy that tunnels a client's HTTPS requests, if any.

The clients ignore ambient HTTP settings (`trust_env=False`) except the proxy
variables the Proofline CLI reads: `HTTPS_PROXY`, then `ALL_PROXY`, unless
`NO_PROXY` matches the origin's host. The order, the uppercase-first names and
the `NO_PROXY` rules follow the CLI's HTTP client, which follows curl. Unlike
the CLI, a proxy setting the SDK cannot use refuses construction instead of
quietly becoming a direct connection.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from pydantic import SecretStr

# The first variable of a pair that is set wins, even when it is empty.
HTTPS_VARIABLES = ("HTTPS_PROXY", "https_proxy")
ALL_VARIABLES = ("ALL_PROXY", "all_proxy")
NO_PROXY_VARIABLES = ("NO_PROXY", "no_proxy")


@dataclass(frozen=True)
class Proxy:
    """An HTTP or HTTPS proxy that tunnels requests with CONNECT.

    `url` has no credentials; the username and password go to the proxy alone.
    """

    url: str
    username: str | None = field(default=None, repr=False)
    password: SecretStr | None = field(default=None, repr=False)

    @property
    def auth(self) -> tuple[str, str] | None:
        if self.username is None:
            return None
        return self.username, "" if self.password is None else self.password.get_secret_value()


def _unusable(variable: str | None) -> ValueError:
    # The value can carry a password, so the message names only where it came from.
    if variable is None:
        return ValueError(
            "Use an http:// or https:// proxy URL with a host, such as http://proxy.example:3128."
        )
    return ValueError(
        f"{variable} must be an http:// or https:// proxy URL with a host; SOCKS is not"
        " supported. To connect without a proxy, add the Proofline host to NO_PROXY."
    )


def parse(value: str, variable: str | None = None) -> Proxy:
    """Read a proxy URL. A value without a scheme names an HTTP proxy, as in the CLI.

    variable names the environment variable the value came from, if any.
    """
    text = value.strip()
    if "://" not in text:
        text = f"http://{text}"
    try:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        host = parts.hostname
        parts.port
    except ValueError:
        raise _unusable(variable) from None
    if scheme not in ("http", "https") or not host or any(ord(c) <= 32 for c in text):
        raise _unusable(variable)
    # Like the CLI, keep only the scheme and authority; a path or query names nothing.
    authority = parts.netloc.rpartition("@")[2]
    username = None if parts.username is None else unquote(parts.username)
    password = None if parts.password is None else SecretStr(unquote(parts.password))
    return Proxy(f"{scheme}://{authority}", username, password)


def bypassed(no_proxy: str, host: str) -> bool:
    """Apply curl's NO_PROXY rules to one host name or IP address."""
    try:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        address = None
    name = host.lower()
    for entry in (part.strip() for part in no_proxy.split(",")):
        if entry == "*":
            return True
        if not entry:
            continue
        if address is not None:
            # An IP address matches only addresses and CIDR ranges, never names.
            try:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        # A name matches itself and its subdomains; a leading dot changes nothing.
        suffix = entry.lower().removeprefix(".")
        if name == suffix or name.endswith(f".{suffix}"):
            return True
    return False


def _first(environ: Mapping[str, str], names: tuple[str, str]) -> tuple[str, str] | None:
    for name in names:
        if name in environ:
            return name, environ[name]
    return None


def select(explicit: str | None, base_url: str, environ: Mapping[str, str]) -> Proxy | None:
    """The proxy for one client's origin: the explicit one, else the environment's."""
    parts = urlsplit(base_url)
    if parts.scheme != "https" or parts.hostname is None:
        # Plain HTTP reaches only a literal loopback address, which no proxy can reach.
        if explicit is not None:
            raise ValueError("A proxy applies only to an HTTPS origin.")
        return None
    if explicit is not None:
        return parse(explicit)
    if "REQUEST_METHOD" in environ:
        # Under CGI a request header can set proxy variables, so the CLI reads none.
        return None
    no_proxy = _first(environ, NO_PROXY_VARIABLES)
    if no_proxy is not None and bypassed(no_proxy[1], parts.hostname):
        return None
    for names in (HTTPS_VARIABLES, ALL_VARIABLES):
        found = _first(environ, names)
        if found is not None and found[1].strip():
            return parse(found[1], found[0])
    return None
