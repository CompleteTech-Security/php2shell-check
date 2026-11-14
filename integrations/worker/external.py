"""Bounded external profile execution using the maintained passive Checker.

The caller supplies the real pinned/admitted transport and TLS probe. This
module never supplies authorization, retries, a resolver, a proxy or a new
scanner implementation. There are deliberately zero automatic retries.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from http.client import HTTPException
import math
import re
import time
from urllib.parse import urljoin, urlsplit
from urllib.request import Request

from wordpress_check import Checker, Response, assess_php2shell, origin

from .network import RequestOrigin
from .profiles import PROFILE_ID, ProfileError, profile_manifest, validate_binding


CONTACT = "https://complete.tech/services/website-security/"
_RESTRICTED = {401, 403, 407, 429, 451}
_REDIRECTS = {301, 302, 303, 307, 308}
_INDICATORS = (
    ("possible_sensitive_indicator", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("possible_sensitive_indicator", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("possible_sensitive_indicator", re.compile(rb"\baws_secret_access_key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{20,}", re.I)),
    ("possible_compromise_indicator", re.compile(rb"\b(?:hacked|defaced)\s+by\b", re.I)),
)


class ProfileStopped(Exception):
    """A fixed reason only: raw target data must not enter errors or logs."""

    def __init__(self, reason):
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason):
            reason = "profile_stopped"
        self.reason = reason
        super().__init__(reason)


def _indicators(raw: bytes):
    for reason, pattern in _INDICATORS:
        if pattern.search(raw):
            raise ProfileStopped(reason)


def check_sensitive_response(raw: bytes) -> None:
    """Validate accumulated decoded bytes without retaining or echoing them."""
    if type(raw) is not bytes:
        raise ProfileStopped("response_body_invalid")
    _indicators(raw)


def _headers(message, maximum):
    pairs = list(message.raw_items()) if hasattr(message, "raw_items") else list(message.items())
    total = 2
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or not isinstance(value, str):
            raise ProfileStopped("response_headers_invalid")
        encoded = (key + ": " + value + "\r\n").encode("utf-8", errors="replace")
        total += len(encoded)
        if total > maximum:
            raise ProfileStopped("response_header_limit")
        _indicators(encoded)
        name = key.lower()
        result[name] = result.get(name, "") + (", " if name in result else "") + value
    return result


class _State:
    def __init__(self, limits, clock):
        self.limits, self.clock = limits, clock
        self._last_now = None
        self.deadline = self.now() + limits["active_seconds"]
        self.last_started = -math.inf
        self.body_bytes = 0
        self.redirects = 0

    def now(self):
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ProfileStopped("clock_invalid")
        if self._last_now is not None and value < self._last_now:
            raise ProfileStopped("clock_anomaly")
        self._last_now = value
        return value

    def remaining(self):
        value = self.deadline - self.now()
        if value <= 0:
            raise ProfileStopped("active_time_limit")
        return value

    def pace(self, delay=1.0):
        wait = max(delay, self.limits["min_interval_ms"] / 1000) - (self.now() - self.last_started)
        if wait > 0:
            if wait >= self.remaining():
                raise ProfileStopped("active_time_limit")
            time.sleep(wait)
        self.remaining()
        self.last_started = self.now()

    def consume(self, raw):
        if type(raw) is not bytes:
            raise ProfileStopped("response_body_invalid")
        if len(raw) > self.limits["response_body_bytes"]:
            raise ProfileStopped("response_body_limit")
        self.body_bytes += len(raw)
        if self.body_bytes > self.limits["aggregate_body_bytes"]:
            raise ProfileStopped("aggregate_body_limit")
        _indicators(raw)
        self.remaining()


class _ManifestOpener:
    def __init__(self, transport, host, services, state):
        self.transport, self.host, self.services, self.state = transport, host, set(services), state

    def _validate(self, value):
        try:
            parts = urlsplit(value)
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except (TypeError, ValueError):
            raise ProfileStopped("request_out_of_scope") from None
        if (parts.hostname != self.host or (parts.scheme, port) not in self.services
                or parts.username is not None or parts.password is not None
                or parts.path not in {"", "/", "/robots.txt"} or parts.query or parts.fragment):
            raise ProfileStopped("request_out_of_scope")
        return parts

    def open(self, request, timeout=None):
        parts = self._validate(request.full_url)
        if request.get_method() not in {"GET", "HEAD"} or request.data is not None:
            raise ProfileStopped("request_method_forbidden")
        self.state.remaining()
        response = self.transport.open(request, timeout=min(timeout or 10, 10, self.state.remaining()))
        try:
            self.state.remaining()
            headers = _headers(response.headers, self.state.limits["response_header_bytes"])
            if response.code in _RESTRICTED:
                raise ProfileStopped("access_restricted")
            if 500 <= response.code <= 599:
                raise ProfileStopped("server_error")
            if response.code in _REDIRECTS:
                self.state.redirects += 1
                if self.state.redirects > self.state.limits["redirect_hops"]:
                    raise ProfileStopped("redirect_limit")
                location = headers.get("location")
                if not location:
                    raise ProfileStopped("redirect_invalid")
                destination = self._validate(urljoin(request.full_url, location))
                if (destination.path or "/") != (parts.path or "/") or (parts.scheme == "https" and destination.scheme == "http"):
                    raise ProfileStopped("redirect_out_of_scope")
            return response
        except BaseException:
            response.close()
            raise


class _ExternalChecker(Checker):
    def __init__(self, opener, state, authorized_origins):
        super().__init__(timeout=10, delay=1, contact=CONTACT, authorized_origins=authorized_origins)
        self.opener, self.state = opener, state
        self.responses = []
        self.robots_allowed = False

    def _request(self, url, limit, delay):
        # Unlike the general CLI's optional disposable request worker, this
        # always uses the caller's guarded transport and shared profile clock.
        self.state.pace(max(self.delay, delay or 0))
        self.last_request[origin(url)] = self.state.now()
        return self._fetch(url, limit)

    def policy(self, url, authorized=None):
        self.robots_allowed = False
        delay = super().policy(url, authorized)
        self.robots_allowed = True
        return delay

    def _fetch(self, url, limit):
        request = Request(url, headers={"User-Agent": self.user_agent, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1", "Accept-Encoding": "identity"})
        with self.opener.open(request, timeout=min(10, self.state.remaining())) as response:
            headers = _headers(response.headers, self.state.limits["response_header_bytes"])
            if headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                # A bounded decoder may normalize this header to identity. Never
                # decompress arbitrary target content in a second code path.
                raise ProfileStopped("content_encoding_unavailable")
            raw = response.read(min(limit, self.state.limits["response_body_bytes"]) + 1)
            self.state.consume(raw)
            charset = response.headers.get_content_charset() if hasattr(response.headers, "get_content_charset") else None
            try:
                body = raw.decode(charset or "utf-8", errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
            self.responses.append((urlsplit(url).path or "/", response.code))
            return Response(response.code, headers, body, False)


def _record(check_id, service, outcome, evidence):
    return {"id": check_id, "service": service, "outcome": outcome, "evidence": evidence}


def _head(checker, url, service):
    checker.state.pace()
    request = Request(url, method="HEAD", headers={"User-Agent": checker.user_agent, "Accept-Encoding": "identity"})
    with checker.opener.open(request, timeout=min(10, checker.state.remaining())) as response:
        # HEAD metadata is inspected, but a body is never read, even if a server
        # incorrectly sends one. Closing the response discards it.
        headers = _headers(response.headers, checker.state.limits["response_header_bytes"])
        checker.state.remaining()
        if not 200 <= response.code < 300:
            return _record("security_header_presence", service, "unknown", {"reason": "non_successful_response", "http_status": response.code})
        return _record("security_header_presence", service, "observed", {
            "http_status": response.code, "hsts": "strict-transport-security" in headers,
            "csp": "content-security-policy" in headers, "frame_control": "x-frame-options" in headers,
            "mime_options": "x-content-type-options" in headers,
        })


def _tls(probe, service_value, service_name, state):
    state.pace()
    result = probe(dict(service_value))
    state.remaining()
    if (type(result) is not dict or set(result) != {"verified", "protocol", "not_after"}
            or result["verified"] is not True
            or type(result["protocol"]) is not str
            or result["protocol"] not in {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
            or type(result["not_after"]) is not str or len(result["not_after"]) > 20):
        raise ProfileStopped("tls_evidence_invalid")
    expiry = result["not_after"]
    if expiry:
        try:
            parsed = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ")
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != expiry:
                raise ValueError
        except ValueError:
            raise ProfileStopped("tls_evidence_invalid") from None
    return _record("tls_certificate", service_name, "observed", {
        "verification": "verified", "protocol": result["protocol"], "not_after": expiry,
    })


def execute_external(target, profile_sha256, services, *, transport_factory, tls_probe, clock=time.monotonic):
    """Execute this exact profile with externally enforced, durable admission.

    ``transport_factory(service_dict)`` must return the caller's real pinned,
    bounded and admitted opener. ``tls_probe(service_dict)`` must perform one
    independently admitted verified TLS-only connection and return only
    ``{verified: True, protocol, not_after}``. Missing dependencies refuse before
    target traffic. Neither callback may accept user-supplied network options.
    """
    selected = validate_binding(PROFILE_ID, profile_sha256, services)
    scope, canonical = RequestOrigin.from_target(target)
    if canonical != target or (scope.initial_scheme, scope.initial_port) not in selected:
        raise ProfileError("profile_target_mismatch")
    if not callable(transport_factory) or not callable(tls_probe):
        raise ProfileError("profile_transport_unavailable")
    manifest = profile_manifest()
    state = _State(manifest["limits"], clock)
    records, results = [], []
    origins = [f"{scheme}://{scope.hostname}" for scheme, _port in selected]
    for scheme, port in selected:
        value = {"scheme": scheme, "port": port}
        service_name = f"{scheme}:{port}"
        url = f"{scheme}://{scope.hostname}/"
        state.remaining()
        opener = _ManifestOpener(transport_factory(dict(value)), scope.hostname, selected, state)
        checker = _ExternalChecker(opener, state, origins)
        result = checker.check(url)
        results.append(((scheme, port), result))
        robots_codes = [code for path, code in checker.responses if path == "/robots.txt"]
        records.append(_record("robots_policy", service_name, "observed" if checker.robots_allowed else "blocked", {
            "http_status": robots_codes[-1] if robots_codes else None, "allowed": checker.robots_allowed,
        }))
        success = result.fetch_status == "ok"
        records.append(_record("public_header_triage", service_name, "observed" if success else "unknown", {
            "http_status": result.http_status, "fetch_status": result.fetch_status,
        }))
        if success and checker.robots_allowed:
            records.append(_head(checker, url, service_name))
        else:
            records.append(_record("security_header_presence", service_name, "unknown", {"reason": "service_not_assessed"}))
        if scheme != "https":
            records.append(_record("tls_certificate", service_name, "not_selected", {"reason": "https_not_selected"}))
        elif success and checker.robots_allowed:
            try:
                records.append(_tls(tls_probe, value, service_name, state))
            except (OSError, HTTPException):
                records.append(_record("tls_certificate", service_name, "blocked", {"reason": "tls_verification_failed"}))
        else:
            records.append(_record("tls_certificate", service_name, "unknown", {"reason": "service_not_assessed"}))
    primary = next(result for service, result in results if service == (scope.initial_scheme, scope.initial_port))
    output = asdict(primary)
    output["input_url"] = target
    for name in ("title", "server", "powered_by", "wordpress_version"):
        output[name] = ""
    for name in ("evidence", "asset_version_hints", "notes", "php_evidence"):
        output[name] = []
    complete_services = all(result.fetch_status == "ok" for _service, result in results)
    if complete_services:
        candidates = sorted({candidate for _service, result in results for candidate in result.php_version_candidates
                             if re.fullmatch(r"[0-9][A-Za-z0-9.+_~:-]{0,63}", candidate)})
        if len(candidates) > 32:
            candidates = []
        output["php_version_candidates"] = candidates
        output["php_version"] = candidates[0] if len(candidates) == 1 else ""
        if any(result.php_evidence for _service, result in results):
            output["php_evidence"] = ["PHP was mentioned in public response headers; raw values were discarded."]
    else:
        # Do not present a successful port's version as the assessment of an
        # incompletely observed selected service set.
        output["php_version_candidates"], output["php_version"], output["wordpress_version"] = [], "", ""
        if output["fetch_status"] == "ok":
            output["status"] = "uncertain"
    output.update(assess_php2shell(output["php_version"], version_candidates=output["php_version_candidates"] or None,
                                  php_hint=bool(output["php_evidence"]) or output["status"] in {"wordpress", "likely_wordpress"}))
    output.update({"profile_id": PROFILE_ID, "profile_sha256": profile_sha256,
                   "services": [dict(value) for value in services], "checks": records,
                   "manual_remainder": [{"id": item["check_id"], "status": "not_assessed"} for item in manifest["manual_remainder"]]})
    return output
