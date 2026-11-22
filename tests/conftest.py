from __future__ import annotations

import pytest

from proofline._proxy import ALL_VARIABLES, HTTPS_VARIABLES, NO_PROXY_VARIABLES


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    # Clients read proxy variables, so each test starts without the developer's.
    for name in (*HTTPS_VARIABLES, *ALL_VARIABLES, *NO_PROXY_VARIABLES, "REQUEST_METHOD"):
        monkeypatch.delenv(name, raising=False)
