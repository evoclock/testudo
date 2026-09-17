# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""D1-D8 discovery tests: probe contract against real local HTTP fixtures,
address-class eligibility, credential-store boundary, caps, and rate
limits."""

from __future__ import annotations

import http.server
import json
import socket
import threading

import pytest

from testudo.seats.address_classes import is_discovery_eligible, is_loopback
from testudo.seats.credentials import key_state
from testudo.seats.discovery import (
    MAX_ADDRESSES,
    MAX_CANDIDATES,
    MAX_PORTS,
    ScanRateLimiter,
    apply_scan_caps,
    merge_candidates,
)
from testudo.seats.probe import LOCAL_PORTS, probe_models


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _ModelsHandler(http.server.BaseHTTPRequestHandler):
    model_id = "fixture-model"
    content_type = "application/json"
    payload: bytes | None = None

    def do_GET(self) -> None:
        if self.path != "/v1/models":
            self.send_error(404)
            return
        body = (
            self.payload
            if self.payload is not None
            else json.dumps({"data": [{"id": self.model_id}]}).encode()
        )
        self.send_response(200)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def model_server():
    handler = type("H", (_ModelsHandler,), {})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, handler
    server.shutdown()


class TestProbeContract:
    def test_valid_response(self, model_server) -> None:
        server, _ = model_server
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert result.ok and result.models == ("fixture-model",)

    def test_wrong_content_type(self, model_server) -> None:
        server, handler = model_server
        handler.content_type = "text/html"
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "wrong-content-type"

    def test_malformed_json(self, model_server) -> None:
        server, handler = model_server
        handler.payload = b"{not json"
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "malformed-json"

    def test_oversized_response(self, model_server) -> None:
        server, handler = model_server
        handler.payload = b'{"data": []}' + b" " * (1024 * 1024 + 10)
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "too-large"

    def test_1001_models_rejected(self, model_server) -> None:
        server, handler = model_server
        handler.payload = json.dumps({"data": [{"id": f"m{i}"} for i in range(1001)]}).encode()
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "bad-data-array"

    def test_1000_models_accepted(self, model_server) -> None:
        server, handler = model_server
        handler.payload = json.dumps({"data": [{"id": f"m{i}"} for i in range(1000)]}).encode()
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert result.ok and len(result.models) == 1000

    def test_invalid_model_id_rejected(self, model_server) -> None:
        server, handler = model_server
        handler.payload = json.dumps({"data": [{"id": "bad id with spaces"}]}).encode()
        port = server.server_address[1]
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "invalid-model-id"

    def test_closed_port(self) -> None:
        port = _free_port()
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert not result.ok and result.reason == "connection-failed"

    def test_direct_connection_ignores_proxy_environment(self, model_server, monkeypatch) -> None:
        server, _ = model_server
        port = server.server_address[1]
        # a poisoned proxy environment must not affect the direct probe
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("all_proxy", "socks5://127.0.0.1:1")
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert result.ok

    def test_only_get_v1_models_sent(self, model_server) -> None:
        server, _ = model_server
        port = server.server_address[1]
        # the handler 404s anything but /v1/models; the probe must not be
        # redirected or write
        result = probe_models("127.0.0.1", port, "127.0.0.1")
        assert result.ok

    def test_local_ports_constant(self) -> None:
        assert LOCAL_PORTS == (8000, 8080, 8893, 30000, 1234, 11434)


class TestAddressClasses:
    def test_eligible(self) -> None:
        for address in ("127.0.0.1", "::1", "10.0.0.5", "172.16.1.1", "192.168.1.1", "100.64.0.2"):
            assert is_discovery_eligible(address), address

    def test_ineligible(self) -> None:
        for address in (
            "8.8.8.8",
            "224.0.0.1",  # multicast
            "169.254.1.1",  # link-local
            "0.0.0.0",  # unspecified
            "255.255.255.255",  # broadcast
            "fe80::1",  # v6 link-local
        ):
            assert not is_discovery_eligible(address), address

    def test_loopback_helper(self) -> None:
        assert is_loopback("127.0.0.1")
        assert is_loopback("::1")
        assert not is_loopback("10.0.0.1")


class TestCredentials:
    def test_key_state_reports_absent_without_keyring(self, monkeypatch) -> None:
        import sys

        monkeypatch.delitem(sys.modules, "keyring", raising=False)
        monkeypatch.setattr(
            "builtins.__import__",
            lambda name, *a, **k: (
                (_ for _ in ()).throw(ImportError(name))
                if name == "keyring"
                else __import__(name, *a, **k)
            ),
        )
        state = key_state("openai")
        assert state.state == "error: credential-store"

    def test_key_bytes_never_in_state(self, monkeypatch) -> None:
        # with no keyring backend, the state is an error, never key material
        state = key_state("openai")
        assert "sk-" not in state.state
        assert state.provider_id == "openai"


class TestMergeAndCaps:
    def test_source_priority_order(self) -> None:
        candidates = merge_candidates(
            [
                ("known-hosts", "192.168.1.5", ["192.168.1.5"]),
                ("tailscale", "100.64.0.2", ["100.64.0.2"]),
                ("mdns", "192.168.1.9", ["192.168.1.9"]),
            ]
        )
        assert [candidate.source for candidate in candidates] == [
            "tailscale",
            "mdns",
            "known-hosts",
        ]

    def test_merge_by_canonical_address(self) -> None:
        candidates = merge_candidates(
            [
                ("mdns", "192.168.1.5", ["192.168.1.5"]),
                ("known-hosts", "192.168.1.5", ["192.168.1.5"]),
            ]
        )
        assert len(candidates) == 1
        assert candidates[0].source == "mdns"  # higher priority wins

    def test_candidate_caps(self) -> None:
        raw = [("mdns", f"192.168.1.{i}", [f"192.168.1.{i}"]) for i in range(MAX_CANDIDATES + 10)]
        candidates, limits = apply_scan_caps(merge_candidates(raw))
        assert len(candidates) == MAX_CANDIDATES
        assert limits.dropped_candidates == 10

    def test_address_cap(self) -> None:
        candidates, limits = apply_scan_caps(
            [
                merge_candidates(
                    [
                        ("mdns", "192.168.1.1", [f"10.0.0.{i}" for i in range(20)]),
                    ]
                )[0]
            ]
        )
        assert len(candidates[0].addresses) == MAX_ADDRESSES
        assert limits.dropped_addresses == 12

    def test_port_cap_and_observed_ports(self) -> None:
        candidate = merge_candidates([("mdns", "192.168.1.1", ["192.168.1.1"])])[0]
        candidate.observed_ports = [9000, 9001, 9002]  # newest first; only two admitted
        ports = candidate.port_set(LOCAL_PORTS)
        assert len(ports) == MAX_PORTS
        assert 9000 in ports and 9001 in ports
        assert 9002 not in ports  # third observed port dropped

    def test_selected_address_lexical(self) -> None:
        candidate = merge_candidates(
            [("mdns", "192.168.1.1", ["10.0.0.9", "10.0.0.2", "10.0.0.5"])]
        )[0]
        assert candidate.selected_address() == "10.0.0.2"


class TestRateLimits:
    def test_one_scan_per_rolling_10s(self) -> None:
        limiter = ScanRateLimiter()
        keys = frozenset({"a"})
        admitted, _ = limiter.admit(keys, now=100.0)
        assert admitted
        admitted, next_time = limiter.admit(keys, now=105.0)
        assert not admitted
        assert next_time == 130.0  # same set also blocked by the 30 s rescan window
        admitted, _ = limiter.admit(keys, now=130.5)
        assert admitted

    def test_no_rescan_same_set_within_30s(self) -> None:
        limiter = ScanRateLimiter()
        keys = frozenset({"a"})
        admitted, _ = limiter.admit(keys, now=100.0)
        assert admitted
        # interval elapsed but same set
        admitted, next_time = limiter.admit(keys, now=111.0)
        assert not admitted
        assert next_time == 130.0
        # a different set is admitted after the 10s interval
        admitted, _ = limiter.admit(frozenset({"b"}), now=111.0)
        assert admitted

    def test_memory_only_state_resets(self) -> None:
        limiter = ScanRateLimiter()
        limiter.admit(frozenset({"a"}), now=100.0)
        fresh = ScanRateLimiter()  # a restarted bridge has no state
        admitted, _ = fresh.admit(frozenset({"a"}), now=100.5)
        assert admitted
