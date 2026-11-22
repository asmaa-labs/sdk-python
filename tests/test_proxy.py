from __future__ import annotations

import base64
import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from proofline import AsyncProoflineClient, ProoflineClient, ProoflineError, RepositoryNames, _proxy

from .fixtures import FINDING, ORG, REPOSITORY, REVIEW, TOKEN, finding
from .http_server import Reply, Request, Server
from .proxy_server import Proxy

Client = ProoflineClient | AsyncProoflineClient
MODES = pytest.mark.parametrize("mode", ["sync", "async"])
ORIGIN_HOST = "proofline.test"
PROXY_USER = "sdk@corp"
PROXY_PASSWORD = "pä:ss-proxy-canary"
EXPORT = {"from_time": "2026-11-01T00:00:00Z", "to_time": "2026-11-15T00:00:00Z"}


@dataclass(frozen=True)
class Certificates:
    authority: Path
    chain: Path
    key: Path

    def server(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.chain, self.key)
        return context


@pytest.fixture(scope="session")
def certificates(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    """A private authority and one certificate for proofline.test and 127.0.0.1."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.fail("openssl is required to issue the certificates of the local TLS peers.")
    directory = tmp_path_factory.mktemp("tls")

    def run(*args: str) -> None:
        subprocess.run([openssl, *args], cwd=directory, check=True, capture_output=True)

    curve = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes")
    run(
        "req",
        "-x509",
        *curve,
        "-days",
        "2",
        "-subj",
        "/CN=Proofline SDK test authority",
        "-keyout",
        "authority.key",
        "-out",
        "authority.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    run("req", *curve, "-subj", f"/CN={ORIGIN_HOST}", "-keyout", "peer.key", "-out", "peer.csr")
    (directory / "peer.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{ORIGIN_HOST},IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    run(
        "x509",
        "-req",
        "-in",
        "peer.csr",
        "-CA",
        "authority.pem",
        "-CAkey",
        "authority.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-sha256",
        "-extfile",
        "peer.ext",
        "-out",
        "peer.pem",
    )
    return Certificates(directory / "authority.pem", directory / "peer.pem", directory / "peer.key")


@asynccontextmanager
async def session(mode: str, url: str, **kwargs: Any) -> AsyncIterator[Client]:
    if mode == "sync":
        with ProoflineClient(SecretStr(TOKEN), base_url=url, **kwargs) as client:
            yield client
    else:
        async with AsyncProoflineClient(SecretStr(TOKEN), base_url=url, **kwargs) as async_client:
            yield async_client


async def call(target: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    result = getattr(target, name)(*args, **kwargs)
    return await result if hasattr(result, "__await__") else result


def names(request: Request, index: int) -> Reply:
    if request.path.endswith("/repository-names"):
        return Reply(body={"repositories": [{"id": str(REPOSITORY), "full_name": "repo/name"}]})
    return Reply(body=finding())


def resolve_only(monkeypatch: pytest.MonkeyPatch, mapped: dict[str, str]) -> list[str]:
    """Resolve mapped names to their addresses; any other name than a literal fails."""
    original = socket.getaddrinfo
    lookups: list[str] = []

    def lookup(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        # anyio passes the IDNA-encoded name as bytes.
        name = host.decode() if isinstance(host, bytes) else str(host)
        lookups.append(name)
        if name in mapped:
            return original(mapped[name], port, *args, **kwargs)
        if name != "127.0.0.1":
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    return lookups


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


@pytest.mark.parametrize(
    ("environ", "url", "auth"),
    [
        ({}, None, None),
        ({"HTTPS_PROXY": "http://proxy.internal:3128"}, "http://proxy.internal:3128", None),
        ({"https_proxy": "http://lower.internal:3128"}, "http://lower.internal:3128", None),
        # Like the CLI, the uppercase name wins, and a set but empty one hides the other.
        (
            {"HTTPS_PROXY": "http://upper.internal:1", "https_proxy": "http://lower.internal:1"},
            "http://upper.internal:1",
            None,
        ),
        (
            {"HTTPS_PROXY": "", "https_proxy": "http://lower.internal:1", "ALL_PROXY": "all:2"},
            "http://all:2",
            None,
        ),
        ({"all_proxy": "http://all.internal:3128"}, "http://all.internal:3128", None),
        ({"HTTPS_PROXY": "proxy.internal:3128"}, "http://proxy.internal:3128", None),
        ({"HTTPS_PROXY": " HTTPS://Proxy.Internal/a?b#c "}, "https://Proxy.Internal", None),
        (
            {"HTTPS_PROXY": "http://sdk%40corp:pa%3Ass@[::1]:3128"},
            "http://[::1]:3128",
            ("sdk@corp", "pa:ss"),
        ),
        ({"HTTPS_PROXY": "http://user@proxy.internal:1"}, "http://proxy.internal:1", ("user", "")),
        (
            {"HTTPS_PROXY": "http://s%C3%BC:p%C3%A4@proxy.internal:1"},
            "http://proxy.internal:1",
            ("sü", "pä"),
        ),
        # HTTP_PROXY names a proxy for plain HTTP, which a Proofline origin never uses.
        ({"HTTP_PROXY": "http://plain.internal:3128"}, None, None),
        ({"HTTPS_PROXY": "http://proxy.internal:3128", "REQUEST_METHOD": "GET"}, None, None),
    ],
)
def test_environment_proxy_follows_the_cli_variables_and_order(
    environ: dict[str, str], url: str | None, auth: tuple[str, str] | None
) -> None:
    selected = _proxy.select(None, "https://proofline.sh", environ)
    assert (selected and selected.url) == url
    assert (selected and selected.auth) == auth


@pytest.mark.parametrize(
    ("no_proxy", "host", "bypassed"),
    [
        ("proofline.sh", "proofline.sh", True),
        ("proofline.sh", "api.proofline.sh", True),
        (".proofline.sh", "proofline.sh", True),
        (".proofline.sh", "api.proofline.sh", True),
        ("PROOFLINE.SH", "proofline.sh", True),
        (" example.com , proofline.sh ", "proofline.sh", True),
        ("proofline.sh", "notproofline.sh", False),
        ("api.proofline.sh", "proofline.sh", False),
        ("*", "proofline.sh", True),
        ("*", "10.1.2.3", True),
        ("*.proofline.sh", "api.proofline.sh", False),
        ("proofline.sh:443", "proofline.sh", False),
        ("10.0.0.0/8", "10.1.2.3", True),
        ("10.0.0.0/8", "11.1.2.3", False),
        ("10.1.2.3", "10.1.2.3", True),
        ("fd00::/8", "fd12::1", True),
        ("::1", "::1", True),
        ("localhost", "127.0.0.1", False),
        ("", "proofline.sh", False),
        (" , ,", "proofline.sh", False),
    ],
)
def test_no_proxy_follows_curl_host_rules(no_proxy: str, host: str, bypassed: bool) -> None:
    assert _proxy.bypassed(no_proxy, host) is bypassed


def test_no_proxy_and_an_explicit_proxy_decide_before_the_environment_proxy() -> None:
    proxied = {"HTTPS_PROXY": "http://proxy.internal:3128", "NO_PROXY": "proofline.sh"}
    assert _proxy.select(None, "https://api.proofline.sh", proxied) is None
    assert _proxy.select(None, "https://proofline.example", proxied) is not None
    # A matching NO_PROXY reaches the origin directly without reading the proxy value.
    unusable = {**proxied, "HTTPS_PROXY": "socks5://proxy.internal:1080"}
    assert _proxy.select(None, "https://proofline.sh", unusable) is None
    explicit = _proxy.select("http://chosen.internal:8080", "https://proofline.sh", proxied)
    assert explicit is not None and explicit.url == "http://chosen.internal:8080"
    cgi = {**proxied, "REQUEST_METHOD": "GET", "NO_PROXY": ""}
    assert _proxy.select("http://chosen.internal:8080", "https://proofline.sh", cgi) is not None


@MODES
@pytest.mark.parametrize(
    "value",
    [
        "socks5://sdk:pa-proxy-canary@proxy.internal:1080",
        "ftp://sdk:pa-proxy-canary@proxy.internal",
        "http://sdk:pa-proxy-canary@:3128",
        "http://sdk:pa-proxy-canary@proxy.internal:99999",
        "http://sdk:pa proxy-canary@proxy.internal:3128",
    ],
)
def test_unusable_proxy_settings_refuse_the_client_without_disclosing_them(
    mode: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ProoflineClient if mode == "sync" else AsyncProoflineClient
    with pytest.raises(ValueError) as explicit:
        client(TOKEN, proxy=value)
    assert "proxy-canary" not in str(explicit.value)
    monkeypatch.setenv("ALL_PROXY", value)
    with pytest.raises(ValueError) as ambient:
        client(TOKEN)
    assert "ALL_PROXY" in str(ambient.value)
    assert "NO_PROXY" in str(ambient.value)
    assert "proxy-canary" not in str(ambient.value)
    assert "proxy-canary" not in repr(_proxy.parse("http://sdk:pa-proxy-canary@proxy.internal"))


@MODES
async def test_plain_http_loopback_origins_never_use_a_proxy(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    with Server(names) as server:
        async with session(mode, server.url) as client:
            assert isinstance(await call(client, "list_repositories", ORG), RepositoryNames)
        assert len(server.requests) == 1
        with pytest.raises(ValueError):
            async with session(mode, server.url, proxy="http://127.0.0.1:9"):
                pass


@MODES
async def test_requests_tunnel_through_the_proxy_and_keep_the_token_inside_tls(
    mode: str, certificates: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates.authority))
    # Only the proxy resolves the origin, so this machine needs no DNS for it.
    lookups = resolve_only(monkeypatch, {})
    with Server(names, tls=certificates.server()) as origin:
        target = f"{ORIGIN_HOST}:{origin.port}"
        with Proxy({target: ("127.0.0.1", origin.port)}) as proxy:
            address = f"http://sdk%40corp:p%C3%A4%3Ass-proxy-canary@127.0.0.1:{proxy.port}"
            async with session(mode, f"https://{target}", proxy=address) as client:
                repositories = await call(client, "list_repositories", ORG)
                assert repositories.repositories[0].full_name == "repo/name"
                assert (await call(client, "get_finding", ORG, FINDING)).id == FINDING
    assert ORIGIN_HOST not in lookups
    assert proxy.tunnels and {tunnel.target for tunnel in proxy.tunnels} == {target}
    for tunnel in proxy.tunnels:
        assert tunnel.method == "CONNECT"
        assert tunnel.headers["proxy-authorization"] == basic(PROXY_USER, PROXY_PASSWORD)
        assert "authorization" not in tunnel.headers
    assert TOKEN.encode() not in proxy.received
    assert [request.headers["Authorization"] for request in origin.requests] == [
        f"Bearer {TOKEN}"
    ] * 2
    assert {request.headers["Host"] for request in origin.requests} == {target}
    assert "Proxy-Authorization" not in origin.requests[0].headers


@MODES
async def test_environment_proxy_tunnels_and_no_proxy_connects_directly(
    mode: str, certificates: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates.authority))
    resolve_only(monkeypatch, {ORIGIN_HOST: "127.0.0.1"})
    with Server(names, tls=certificates.server()) as origin:
        target = f"{ORIGIN_HOST}:{origin.port}"
        with Proxy({target: ("127.0.0.1", origin.port)}) as proxy:
            monkeypatch.setenv("HTTPS_PROXY", proxy.url)
            monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
            async with session(mode, f"https://{target}") as client:
                await call(client, "list_repositories", ORG)
            assert [tunnel.target for tunnel in proxy.tunnels] == [target]
            monkeypatch.setenv("NO_PROXY", f"localhost,.{ORIGIN_HOST}")
            async with session(mode, f"https://{target}") as client:
                await call(client, "list_repositories", ORG)
            assert len(proxy.tunnels) == 1
    assert len(origin.requests) == 2


@MODES
async def test_an_https_proxy_is_verified_and_carries_the_origin_tls_inside_its_own(
    mode: str, certificates: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    resolve_only(monkeypatch, {})
    with Server(names, tls=certificates.server()) as origin:
        target = f"{ORIGIN_HOST}:{origin.port}"
        routes = {target: ("127.0.0.1", origin.port)}
        with Proxy(routes, tls=certificates.server()) as proxy:
            # The system roots do not trust the private authority, so neither TLS starts.
            async with session(mode, f"https://{target}", proxy=proxy.url) as client:
                with pytest.raises(ProoflineError) as untrusted:
                    await call(client, "list_repositories", ORG)
            assert untrusted.value.type == "urn:proofline:sdk:transport-unavailable"
            assert proxy.tunnels == []
            monkeypatch.setenv("SSL_CERT_FILE", str(certificates.authority))
            async with session(mode, f"https://{target}", proxy=proxy.url) as client:
                assert isinstance(await call(client, "list_repositories", ORG), RepositoryNames)
    assert [tunnel.target for tunnel in proxy.tunnels] == [target]
    assert TOKEN.encode() not in proxy.received
    assert len(origin.requests) == 1


@MODES
async def test_an_unreachable_proxy_is_reported_like_an_unreachable_api(mode: str) -> None:
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    async with session(mode, f"https://{ORIGIN_HOST}", proxy=f"http://127.0.0.1:{port}") as client:
        with pytest.raises(ProoflineError) as unreachable:
            await call(client, "get_finding", ORG, FINDING)
    assert unreachable.value.type == "urn:proofline:sdk:transport-unavailable"


@MODES
@pytest.mark.parametrize("status", [403, 407, 502])
async def test_a_refused_tunnel_names_the_proxy_status_on_every_surface(
    mode: str, status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_only(monkeypatch, {})
    with Proxy(status=status) as proxy:
        monkeypatch.setenv("HTTPS_PROXY", proxy.url)
        async with session(mode, f"https://{ORIGIN_HOST}") as client:
            attempts: list[tuple[Any, str, tuple[Any, ...], dict[str, Any]]] = [
                (client, "get_finding", (ORG, FINDING), {}),
                (client, "export_reviews", (ORG, "findings"), EXPORT),
                (client.knowledge, "list_wiki_pages", ("owner/name",), {}),
                (client, "wait_for_review", (ORG, REVIEW), {"timeout": 5}),
            ]
            for target, name, args, kwargs in attempts:
                with pytest.raises(ProoflineError) as refused:
                    await call(target, name, *args, **kwargs)
                assert refused.value.status == 0
                assert refused.value.type == "urn:proofline:sdk:proxy-refused"
                assert refused.value.detail == (
                    f"The proxy refused to open a tunnel to the Proofline API (HTTP {status})."
                )
    # One CONNECT per call: a refused tunnel is never retried, and no token reaches it.
    assert [tunnel.target for tunnel in proxy.tunnels] == [f"{ORIGIN_HOST}:443"] * 4
    assert all("authorization" not in tunnel.headers for tunnel in proxy.tunnels)
    assert TOKEN.encode() not in proxy.received


@MODES
async def test_a_silent_proxy_ends_at_the_request_timeout_and_the_wait_deadline(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve_only(monkeypatch, {})
    with Proxy(stall=True) as proxy:
        async with session(mode, f"https://{ORIGIN_HOST}", proxy=proxy.url, timeout=0.2) as client:
            started = time.monotonic()
            with pytest.raises(ProoflineError) as stalled:
                await call(client, "get_finding", ORG, FINDING)
            assert stalled.value.type == "urn:proofline:sdk:timeout"
            assert time.monotonic() - started < 2
        async with session(mode, f"https://{ORIGIN_HOST}", proxy=proxy.url) as client:
            started = time.monotonic()
            result = await call(client, "wait_for_review", ORG, REVIEW, timeout=0.3)
            assert result.status == "TIMED_OUT"
            assert time.monotonic() - started < 2
    assert {tunnel.target for tunnel in proxy.tunnels} == {f"{ORIGIN_HOST}:443"}
