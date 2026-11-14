"""Connection-time scope and public-address enforcement for worker requests."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from email.message import Message
import threading
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit



MAX_URL_LENGTH = 4096

_BOUNDARY_REASONS = frozenset({
    "profile_connection_outstanding", "profile_rate_exceeded", "profile_duration_exhausted",
    "profile_http_budget_exhausted", "profile_tls_budget_exhausted", "profile_kind_invalid",
    "profile_byte_budget_exhausted", "profile_scope_changed", "profile_headers_too_large",
    "profile_request_timeout", "profile_peer_mismatch", "profile_tunnel_forbidden",
    "profile_sensitive_indicator", "profile_access_challenge", "profile_compromise_indicator",
    "profile_access_restricted", "profile_service_unavailable", "profile_encoding_unsupported",
    "profile_encoding_invalid", "profile_body_too_large", "profile_response_failed",
    "profile_response_closed", "profile_content_rejected", "profile_timeout_invalid",
    "profile_method_forbidden", "profile_connection_failed", "profile_tls_out_of_scope",
    "profile_tls_metadata_invalid", "profile_tls_failed", "profile_dns_invalid",
    "profile_dns_failed", "profile_dns_timeout", "profile_redirect_budget_exhausted",
    "profile_response_truncated", "profile_framing_invalid",
    "possible_sensitive_indicator", "possible_compromise_indicator",
})


class BoundaryViolation(Exception):
    """A log-safe profile refusal which the public checker must not swallow."""

    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in _BOUNDARY_REASONS else "profile_boundary_refused"
        super().__init__(self.reason)


@dataclass(frozen=True)
class ProfileScope:
    """The explicit service subset signed for external-web-v1, never inferred."""

    hostname: str
    services: tuple[tuple[str, int], ...]

    @classmethod
    def from_target(cls, target, services):
        origin, normalized = RequestOrigin.from_target(target)
        if target != normalized or not isinstance(services, (list, tuple)) or not services:
            raise ValueError("invalid_profile_scope")
        checked = []
        for item in services:
            if not isinstance(item, dict) or set(item) != {"scheme", "port"}:
                raise ValueError("invalid_profile_scope")
            scheme, port = item["scheme"], item["port"]
            if type(scheme) is not str or type(port) is not int or (scheme, port) not in {("http", 80), ("https", 443)}:
                raise ValueError("invalid_profile_scope")
            checked.append((scheme, port))
        if checked != sorted(set(checked)) or (origin.initial_scheme, origin.initial_port) not in checked:
            raise ValueError("invalid_profile_scope")
        return cls(origin.hostname, tuple(checked)), normalized

    def validate_request(self, value, *, mark_upgrade=True):
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ValueError("request_out_of_scope")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("request_out_of_scope")
        try:
            parts = urlsplit(value)
            host = _canonical_host(parts.hostname or "")
            service = (parts.scheme, _effective_port(parts))
        except ValueError as exc:
            raise ValueError("request_out_of_scope") from exc
        if (host != self.hostname or service not in self.services
                or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment or parts.path not in {"", "/", "/robots.txt"}):
            raise ValueError("request_out_of_scope")
        return service[0], service[1], host, parts.path or "/"


class ProfileMeter:
    """Local second boundary; durable reservations remain the server's authority.

    Counts never reset or refund after an attempted admission. A refused or
    interrupted attempt cannot be retried with a fresh local budget.
    """

    def __init__(self, *, monotonic=time.monotonic):
        self._clock = monotonic
        self._lock = threading.RLock()
        self.started = monotonic()
        self.last = None
        self.http_used = self.tls_used = self.body_used = self.wire_used = 0
        self.redirects = 0
        self.inflight = False
        self.failure = None
        self.binding = None

    def bind(self, value):
        with self._lock:
            if self.binding is not None and self.binding != value:
                self.refuse("profile_scope_changed")
            self.binding = value

    def refuse(self, reason):
        self.failure = self.failure or BoundaryViolation(reason).reason
        raise BoundaryViolation(self.failure)

    def check(self):
        if self.failure:
            raise BoundaryViolation(self.failure)
        elapsed = self._clock() - self.started
        if elapsed < 0 or elapsed >= 600:
            self.refuse("profile_duration_exhausted")

    def begin(self, kind):
        with self._lock:
            self.check()
            if self.inflight:
                self.refuse("profile_connection_outstanding")
            now = self._clock()
            if self.last is not None and now - self.last < 1:
                self.refuse("profile_rate_exceeded")
            if kind == "http":
                if self.http_used >= 100:
                    self.refuse("profile_http_budget_exhausted")
                self.http_used += 1
            elif kind == "tls":
                if self.tls_used >= 20:
                    self.refuse("profile_tls_budget_exhausted")
                self.tls_used += 1
            else:
                self.refuse("profile_kind_invalid")
            self.inflight = True
            self.last = now

    def admitted(self):
        with self._lock:
            self.last = self._clock()

    def redirect(self):
        with self._lock:
            self.check()
            self.redirects += 1
            if self.redirects > 3:
                self.refuse("profile_redirect_budget_exhausted")

    def consume(self, count, *, wire=False):
        with self._lock:
            self.check()
            name = "wire_used" if wire else "body_used"
            if type(count) is not int or count < 0 or getattr(self, name) + count > 5 * 1024 * 1024:
                self.refuse("profile_byte_budget_exhausted")
            setattr(self, name, getattr(self, name) + count)

    def done(self):
        with self._lock:
            self.inflight = False


def _canonical_host(value: str) -> str:
    if not value or "%" in value or value.endswith("."):
        raise ValueError("invalid_host")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            host = value.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError) as exc:
            raise ValueError("invalid_host") from exc
        labels = host.split(".")
        label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
        if (
            not host
            or len(host) > 253
            or len(labels) < 2
            or any(not label_pattern.fullmatch(label) for label in labels)
        ):
            raise ValueError("invalid_host")
        return host
    raise ValueError("ip_literal_not_allowed")


def _effective_port(parts) -> int:
    try:
        explicit = parts.port
    except ValueError as exc:
        raise ValueError("invalid_port") from exc
    if explicit is None:
        return 443 if parts.scheme.lower() == "https" else 80
    return explicit


def _host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


@dataclass(frozen=True)
class RequestOrigin:
    """One authorized hostname with a narrowly defined HTTP-to-HTTPS upgrade."""

    hostname: str
    initial_scheme: str
    initial_port: int
    upgraded: bool = field(default=False, compare=False, repr=False)

    @classmethod
    def from_target(cls, value: str) -> tuple["RequestOrigin", str]:
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ValueError("invalid_target")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("invalid_target")
        try:
            parts = urlsplit(value)
            host_raw = parts.hostname
            scheme = parts.scheme.lower()
            port = _effective_port(parts)
        except ValueError as exc:
            raise ValueError("invalid_target") from exc
        if scheme not in {"http", "https"} or not host_raw:
            raise ValueError("invalid_target")
        if parts.username is not None or parts.password is not None:
            raise ValueError("invalid_target")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ValueError("target_must_be_origin" )
        if (scheme, port) not in {("http", 80), ("https", 443)}:
            raise ValueError("invalid_port")
        host = _canonical_host(host_raw)
        origin = cls(host, scheme, port)
        explicit_port = parts.port
        port_suffix = f":{explicit_port}" if explicit_port is not None and explicit_port != port else ""
        normalized = f"{scheme}://{_host_for_url(host)}{port_suffix}/"
        return origin, normalized

    def validate_request(self, value: str, *, mark_upgrade: bool = True) -> tuple[str, int, str, str]:
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ValueError("request_out_of_scope")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("request_out_of_scope")
        try:
            parts = urlsplit(value)
            raw_host = parts.hostname
            scheme = parts.scheme.lower()
            port = _effective_port(parts)
        except ValueError as exc:
            raise ValueError("request_out_of_scope") from exc
        if scheme not in {"http", "https"} or not raw_host:
            raise ValueError("request_out_of_scope")
        if parts.username is not None or parts.password is not None:
            raise ValueError("request_out_of_scope")
        try:
            host = _canonical_host(raw_host)
        except ValueError as exc:
            raise ValueError("request_out_of_scope") from exc
        if host != self.hostname:
            raise ValueError("request_out_of_scope")
        if (scheme, port) not in {("http", 80), ("https", 443)}:
            raise ValueError("request_out_of_scope")
        if self.initial_scheme == "https":
            if (scheme, port) != ("https", 443):
                raise ValueError("request_out_of_scope")
        elif scheme == "https":
            if (self.initial_port, port) != (80, 443):
                raise ValueError("request_out_of_scope")
            if mark_upgrade:
                object.__setattr__(self, "upgraded", True)
        else:
            if self.upgraded:
                raise ValueError("request_downgrade_blocked")
            if (self.initial_scheme, self.initial_port) != ("http", 80):
                raise ValueError("request_out_of_scope")
        target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        return scheme, port, host, target


# Explicit special-purpose ranges, listed rather than inferred: Python's ipaddress `is_global`
# differs between versions (3.10 through 3.14 disagree on several of these), and a destination
# check must not depend on the interpreter. Anything in these ranges is never a customer's site.
DENIED_V4 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",  # "this" network
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, cloud metadata
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes the broadcast address
    )
)
DENIED_V6 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",  # IPv4-mapped
        "64:ff9b::/96",  # NAT64
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments, includes Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "3fff::/20",  # documentation (RFC 9637)
        "5f00::/16",  # SRv6 SIDs
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)


def _public_addresses(host: str, port: int, resolver=socket.getaddrinfo):
    """Resolve afresh and reject the entire answer set if any address is non-public."""
    try:
        answers = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise socket.gaierror("DNS lookup failed") from exc
    if not answers:
        raise socket.gaierror("DNS returned no addresses")
    checked = []
    seen = set()
    for answer in answers:
        if len(answer) < 5:
            raise ValueError("invalid_dns_answer")
        family, socktype, _protocol, _canonname, sockaddr = answer
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype not in {0, socket.SOCK_STREAM}:
            raise ValueError("invalid_dns_answer")
        try:
            text = sockaddr[0]
            if "%" in text:
                raise ValueError("non_public_address")
            address = ipaddress.ip_address(text)
        except (IndexError, ValueError) as exc:
            raise ValueError("invalid_dns_answer") from exc
        unsafe = (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_private
        )
        if isinstance(address, ipaddress.IPv4Address):
            unsafe = unsafe or any(address in network for network in DENIED_V4)
        if isinstance(address, ipaddress.IPv6Address):
            unsafe = unsafe or address.ipv4_mapped is not None or address.is_site_local
            unsafe = unsafe or address not in ipaddress.ip_network("2000::/3")
            unsafe = unsafe or any(address in network for network in DENIED_V6)
        if unsafe:
            raise ValueError("non_public_address")
        key = (family, address.compressed)
        if key not in seen:
            seen.add(key)
            checked.append((family, address.compressed))
    if not checked:
        raise ValueError("invalid_dns_answer")
    return checked


def _connect_socket(family, address: str, port: int, timeout, source_address=None):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        sock.connect(sockaddr)
        return sock
    except BaseException:
        sock.close()
        raise


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, *, pinned_family, pinned_address, timeout=None, before_connect=None, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._pinned_family = pinned_family
        self._pinned_address = pinned_address
        self._before_connect = before_connect

    def connect(self):
        if self._before_connect is not None:
            self._before_connect()
        self.sock = _connect_socket(
            self._pinned_family, self._pinned_address, self.port, self.timeout, self.source_address
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, *, pinned_family, pinned_address, timeout=None, context=None, before_connect=None, **kwargs):
        super().__init__(host, port, timeout=timeout, context=context or ssl.create_default_context(), **kwargs)
        self._pinned_family = pinned_family
        self._pinned_address = pinned_address
        self._before_connect = before_connect

    def connect(self):
        if self._tunnel_host:
            raise OSError("tunnels are disabled")
        if self._before_connect is not None:
            self._before_connect()
        raw = _connect_socket(
            self._pinned_family, self._pinned_address, self.port, self.timeout, self.source_address
        )
        try:
            # Keep the authorized hostname for SNI and certificate-name verification.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _ManagedResponse:
    def __init__(self, response, connection, on_close=None):
        self._response = response
        self._connection = connection
        self._on_close = on_close
        self.code = response.status
        self.headers = response.headers

    def read(self, size=-1):
        return self._response.read(size)

    def close(self):
        try:
            self._response.close()
        finally:
            try:
                self._connection.close()
            finally:
                if self._on_close is not None:
                    self._on_close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class PinnedOpener:
    """urllib-compatible single request transport with no proxies or auto-redirects.

    With an admission ``guard`` (the scanner child), every request first obtains a
    one-request admission from the supervisor, re-checks that it is still fresh
    immediately before connecting, and reports completion. Without a guard (the
    fixed WordPress API client and offline tests) no target is contacted.
    """

    def __init__(self, scope: RequestOrigin, *, resolver=socket.getaddrinfo, ssl_context=None, guard=None):
        self.scope = scope
        self.resolver = resolver
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.guard = guard

    def open(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        # Scope validation happens before DNS resolution, so cross-host redirects do not
        # make even a DNS request for an unauthorized hostname.
        scheme, port, host, target = self.scope.validate_request(url)
        answers = _public_addresses(host, port, self.resolver)
        family, address = answers[0]
        guard = self.guard
        if guard is not None:
            # No grant, no connection. Raises before any socket is opened.
            guard.admit()
        try:
            connection_type = PinnedHTTPSConnection if scheme == "https" else PinnedHTTPConnection
            kwargs = {"pinned_family": family, "pinned_address": address, "timeout": timeout}
            if guard is not None:
                kwargs["before_connect"] = guard.ensure_fresh
            if scheme == "https":
                kwargs["context"] = self.ssl_context
            connection = connection_type(host, port, **kwargs)
            headers = dict(request.header_items()) if hasattr(request, "header_items") else {}
            headers["Connection"] = "close"
            method = request.get_method() if hasattr(request, "get_method") else "GET"
            body = getattr(request, "data", None)
            try:
                connection.request(method, target, body=body, headers=headers)
                response = connection.getresponse()
                return _ManagedResponse(response, connection, guard.done if guard is not None else None)
            except BaseException:
                connection.close()
                raise
        except BaseException:
            if guard is not None:
                guard.done()
            raise


class _HeaderReader:
    """Bound bytes below HTTP transfer decoding, including chunk metadata."""

    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.used = stream, maximum, 0
        self.body = False
        self.body_used = 0
        self.on_body = None

    def _body_count(self, count):
        self.body_used += count
        if self.on_body is not None:
            self.on_body(count)
        if self.body_used > 262144:
            raise BoundaryViolation("profile_body_too_large")

    def readline(self, size=-1):
        remaining = self.maximum - self.used + 1
        if self.body:
            remaining = min(remaining, 262144 - self.body_used + 1)
        value = self.stream.readline(remaining if size < 0 else min(size, remaining))
        self.used += len(value)
        if self.body:
            self._body_count(len(value))
            if not value:
                raise BoundaryViolation("profile_response_truncated")
        if self.used > self.maximum:
            raise BoundaryViolation("profile_headers_too_large")
        return value

    def read(self, size=-1):
        if not self.body:
            raise BoundaryViolation("profile_framing_invalid")
        remaining = 262144 - self.body_used + 1
        value = self.stream.read(remaining if size < 0 else min(size, remaining))
        self._body_count(len(value))
        return value

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def begin(self):
        self._wire_reader = _HeaderReader(self.fp, 32768)
        self.fp = self._wire_reader
        super().begin()
        # Keep the bounded wrapper: chunk extensions, CRLF delimiters and
        # trailers are parsed later by HTTPResponse.read(), not by begin().
        self._wire_reader.body = True


class _RequestDeadline:
    """A total deadline holding a duplicate raw FD, even after getresponse().

    http.client can relinquish connection.sock while the response stream still
    owns it. Shutting down the duplicate interrupts header/body/TLS trickles
    without taking a buffered reader lock in the timer thread.
    """

    def __init__(self, seconds, *, monotonic=time.monotonic):
        self._clock = monotonic
        self.until = monotonic() + seconds
        self.expired = False
        self._closed = False
        self._socket = None
        self._lock = threading.Lock()
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        with self._lock:
            if self._closed:
                return
            self.expired = True
            sock = self._socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def attach(self, sock):
        duplicate = sock.dup()
        with self._lock:
            if self._closed or self.expired:
                duplicate.close()
                raise BoundaryViolation("profile_request_timeout")
            self._socket = duplicate

    def remaining(self):
        remaining = self.until - self._clock()
        if self.expired or remaining <= 0:
            raise BoundaryViolation("profile_request_timeout")
        return min(10.0, remaining)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sock, self._socket = self._socket, None
        self._timer.cancel()
        if sock is not None:
            sock.close()


def _profile_socket(connection, deadline):
    """Publish the raw socket to the deadline before any connect/handshake."""
    connection._before_connect()
    sock = socket.socket(connection._pinned_family, socket.SOCK_STREAM)
    connection.sock = sock
    try:
        sock.settimeout(deadline.remaining())
        deadline.attach(sock)
        address = connection._pinned_address
        target = (address, connection.port, 0, 0) if connection._pinned_family == socket.AF_INET6 else (address, connection.port)
        sock.connect(target)
        if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(address):
            raise BoundaryViolation("profile_peer_mismatch")
        deadline.remaining()
        return sock
    except BaseException:
        sock.close()
        connection.sock = None
        raise


class _ProfileHTTPConnection(PinnedHTTPConnection):
    response_class = _BoundedHTTPResponse

    def connect(self):
        self.sock = _profile_socket(self, self._deadline)


class _ProfileHTTPSConnection(PinnedHTTPSConnection):
    response_class = _BoundedHTTPResponse

    def connect(self):
        if self._tunnel_host:
            raise BoundaryViolation("profile_tunnel_forbidden")
        raw = _profile_socket(self, self._deadline)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            self._deadline.remaining()
        except BaseException:
            raw.close()
            self.sock = None
            raise


def _default_content_validator(body, headers):
    """Stop on explicit indicators without classifying or retaining their values."""
    header_text = "\n".join(str(name) + ":" + str(value) for name, value in headers.items()).encode("utf-8", "replace")
    lower = body.lower() + b"\n" + header_text.lower()
    if (b"-----begin " in lower and b"private key-----" in lower) or b"aws_secret_access_key" in lower:
        raise BoundaryViolation("possible_sensitive_indicator")
    if b"cf-chl-" in lower or b"__cf_chl" in lower:
        raise BoundaryViolation("profile_access_challenge")
    if re.search(rb"\bhacked\s+by\b", lower):
        raise BoundaryViolation("possible_compromise_indicator")


class _ExternalResponse:
    def __init__(self, response, connection, deadline, meter, done, *, method, validator):
        self._response, self._connection, self._deadline = response, connection, deadline
        self._meter, self._done = meter, done
        self._method, self._validator = method, validator
        self._closed = False
        self._buffer = None
        self._position = 0
        self.code = response.status
        self.headers = Message()
        for name, value in response.headers.items():
            self.headers[name] = value
        self.original_headers = tuple(response.headers.items())
        encodings = self.headers.get_all("Content-Encoding", [])
        self._encoding = (encodings[0] if len(encodings) == 1 else "identity").strip().lower()
        self._encoding_count = len(encodings)
        if self._encoding == "gzip" and self._encoding_count == 1 and method != "HEAD":
            # Decoding is guaranteed before read() can return any bytes. Make
            # that interface explicit for callers which inspect headers first.
            del self.headers["Content-Encoding"]
            del self.headers["Content-Length"]
            self.headers["Content-Encoding"] = "identity"
        reader = getattr(response, "_wire_reader", None)
        self._wire_accounted = isinstance(reader, _HeaderReader)
        if self._wire_accounted:
            reader.on_body = lambda count: meter.consume(count, wire=True)
        self.decoded = False

    def _load(self):
        if self._buffer is not None:
            return
        try:
            self._deadline.remaining()
            if self.code in {401, 403, 407, 429}:
                raise BoundaryViolation("profile_access_restricted")
            if self.code >= 500:
                raise BoundaryViolation("profile_service_unavailable")
            if self._encoding_count > 1:
                raise BoundaryViolation("profile_encoding_unsupported")
            encoding = self._encoding
            if encoding not in {"", "identity", "gzip"}:
                raise BoundaryViolation("profile_encoding_unsupported")
            lengths = self.headers.get_all("Content-Length", []) if encoding != "gzip" else [
                value for name, value in self.original_headers if name.lower() == "content-length"]
            transfers = self.headers.get_all("Transfer-Encoding", [])
            if (len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers)
                    or (transfers and transfers[0].strip().lower() != "chunked")
                    or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0].strip()))):
                raise BoundaryViolation("profile_framing_invalid")
            if self._method == "HEAD":
                # No body read, including when a server incorrectly supplies one.
                self._validator(b"", self.headers)
                self._buffer = b""
                self.decoded = True
                return
            if lengths and int(lengths[0]) > 262144:
                raise BoundaryViolation("profile_body_too_large")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
            result = bytearray()
            wire = 0
            while True:
                self._deadline.remaining()
                chunk = self._response.read(min(8192, 262144 - wire + 1))
                self._deadline.remaining()
                if not chunk:
                    if getattr(self._response, "length", None) not in {None, 0}:
                        raise BoundaryViolation("profile_response_truncated")
                    break
                wire += len(chunk)
                if not self._wire_accounted:
                    self._meter.consume(len(chunk), wire=True)
                if wire > 262144:
                    raise BoundaryViolation("profile_body_too_large")
                decoded = decoder.decompress(chunk, 262144 - len(result) + 1) if decoder else chunk
                self._meter.consume(len(decoded))
                if len(result) + len(decoded) > 262144:
                    raise BoundaryViolation("profile_body_too_large")
                result.extend(decoded)
                if decoder and (decoder.unconsumed_tail or decoder.unused_data):
                    raise BoundaryViolation("profile_encoding_invalid")
            if decoder and not decoder.eof:
                raise BoundaryViolation("profile_encoding_invalid")
            self._validator(bytes(result), self.headers)
            self._buffer = bytes(result)
            if encoding == "gzip":
                # Checker receives decoded bytes; it must not attempt a second
                # decode or reject a decoded robots file as compressed text.
                del self.headers["Content-Encoding"]
                del self.headers["Content-Length"]
                self.headers["Content-Encoding"] = "identity"
            self.decoded = True
        except BaseException as exc:
            self._buffer = None
            reason = exc.reason if isinstance(exc, BoundaryViolation) else "profile_response_failed"
            category = getattr(exc, "reason", None)
            if type(category) is str and category in {"possible_sensitive_indicator", "possible_compromise_indicator"}:
                # The executor's validator has the same two fixed operational
                # categories; never copy arbitrary exception text or reasons.
                reason = category
            self._meter.failure = self._meter.failure or reason
            try:
                self.close()
            finally:
                self._meter.refuse(reason)

    def read(self, size=-1):
        if self._closed:
            raise BoundaryViolation("profile_response_closed")
        if type(size) is not int or size < -1:
            raise ValueError("invalid_read_size")
        self._load()
        stop = len(self._buffer) if size < 0 else min(len(self._buffer), self._position + size)
        value = self._buffer[self._position:stop]
        self._position = stop
        return value

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            try:
                self._connection.close()
            finally:
                self._deadline.close()
                self._done()
                self._buffer = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class ExternalPinnedOpener:
    """Manifest-bound transport; separate from the frozen r2-header-v1 adapter."""

    def __init__(self, scope, guard, *, profile_sha256, meter, body_validator=None, ssl_context=None,
                 monotonic=time.monotonic, wait=time.sleep):
        from .profiles import PROFILE_ID, validate_binding
        if not isinstance(scope, ProfileScope) or not isinstance(meter, ProfileMeter):
            raise ValueError("invalid_profile_transport")
        if _canonical_host(scope.hostname) != scope.hostname or getattr(guard, "kind", None) != "external":
            raise ValueError("invalid_profile_transport")
        services = [{"scheme": scheme, "port": port} for scheme, port in scope.services]
        validate_binding(PROFILE_ID, profile_sha256, services)
        self.scope, self.guard, self.meter = scope, guard, meter
        self.ssl_context = ssl_context or ssl.create_default_context()
        if not self.ssl_context.check_hostname or self.ssl_context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("profile_tls_verification_required")
        def validate(body, headers):
            _default_content_validator(body, headers)
            if body_validator is not None and body_validator(body, headers) is False:
                raise BoundaryViolation("profile_content_rejected")
        self._validator = validate
        self._clock, self._wait = monotonic, wait
        self.meter.bind((scope.hostname, scope.services, profile_sha256))

    def _begin(self, kind, timeout):
        self.meter.check()
        if self.meter.inflight:
            self.meter.refuse("profile_connection_outstanding")
        # Bounded pacing before requesting the authoritative reservation. Stop
        # admission is still checked afterwards, so waiting cannot grant traffic.
        while self.meter.last is not None:
            self.meter.check()
            remaining = 1 - (self._clock() - self.meter.last)
            if remaining <= 0:
                break
            self._wait(min(0.05, remaining))
        self.meter.begin(kind)
        if timeout is None:
            timeout = 10.0
        if type(timeout) not in {int, float} or not 0 < timeout <= 10:
            self.meter.done()
            self.meter.refuse("profile_timeout_invalid")
        deadline = None
        try:
            self.guard.admit(kind=kind)
            # The server may conservatively hold the previous reservation for
            # eleven seconds. Waiting for permission does not start a target
            # request. The supervisor still kills admitted work at ten seconds
            # from the authoritative grant's issue time.
            deadline = _RequestDeadline(timeout, monotonic=self._clock)
            deadline.remaining()
            self.guard.ensure_fresh()
            self.meter.admitted()
            return deadline
        except BaseException:
            if deadline is not None:
                deadline.close()
            self.guard.done()
            self.meter.done()
            raise

    def _addresses(self, host, port, deadline):
        from .network_dns import DNSFailure, resolve_answers
        try:
            answers = resolve_answers(host, port, deadline.remaining())
            return _public_addresses(host, port, lambda *_args, **_kw: answers)
        except DNSFailure as exc:
            raise BoundaryViolation(str(exc)) from exc

    def _connection(self, scheme, port, host, deadline):
        answers = self._addresses(host, port, deadline)
        family, address = answers[0]
        connection_type = _ProfileHTTPSConnection if scheme == "https" else _ProfileHTTPConnection
        options = dict(pinned_family=family, pinned_address=address, timeout=deadline.remaining(),
                       before_connect=self.guard.ensure_fresh)
        if scheme == "https":
            options["context"] = self.ssl_context
        connection = connection_type(host, port, **options)
        connection._deadline = deadline
        return connection

    def _done(self):
        try:
            self.guard.done()
        finally:
            self.meter.done()

    def open(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        scheme, port, host, target = self.scope.validate_request(url)
        method = request.get_method() if hasattr(request, "get_method") else "GET"
        if method not in {"GET", "HEAD"} or getattr(request, "data", None) is not None:
            raise BoundaryViolation("profile_method_forbidden")
        if method == "HEAD" and target != "/":
            raise BoundaryViolation("profile_method_forbidden")
        deadline = self._begin("http", timeout)
        connection = None
        try:
            connection = self._connection(scheme, port, host, deadline)
            supplied = dict(request.header_items()) if hasattr(request, "header_items") else {}
            # Never forward credentials, cookies, proxies, caller Host or body
            # negotiation from the application into a target request.
            allowed = {name: value for name, value in supplied.items() if name.lower() in {"user-agent", "accept"}}
            allowed.update({"Connection": "close", "Accept-Encoding": "identity"})
            connection.request(method, target, headers=allowed)
            response = connection.getresponse()
            deadline.remaining()
            if response.status in {301, 302, 303, 307, 308}:
                self.meter.redirect()
            return _ExternalResponse(response, connection, deadline, self.meter, self._done,
                                     method=method, validator=self._validator)
        except BaseException as exc:
            reason = "profile_request_timeout" if deadline.expired else (
                exc.reason if isinstance(exc, BoundaryViolation) else "profile_connection_failed")
            self.meter.failure = self.meter.failure or BoundaryViolation(reason).reason
            try:
                if connection is not None:
                    connection.close()
            finally:
                try:
                    deadline.close()
                finally:
                    try:
                        self._done()
                    finally:
                        self.meter.refuse(reason)

    def inspect_tls(self, url, timeout=None):
        scheme, port, host, target = self.scope.validate_request(url)
        if scheme != "https" or target != "/":
            raise BoundaryViolation("profile_tls_out_of_scope")
        deadline = self._begin("tls", timeout)
        connection = None
        try:
            connection = self._connection(scheme, port, host, deadline)
            connection.connect()
            certificate = connection.sock.getpeercert()
            protocol = connection.sock.version()
            if type(protocol) is not str or not protocol:
                raise BoundaryViolation("profile_tls_metadata_invalid")
            expiry = certificate.get("notAfter")
            not_after = ""
            if type(expiry) is str:
                from datetime import datetime, timezone
                not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            deadline.remaining()
            return {"verified": True, "protocol": protocol, "not_after": not_after}
        except BaseException as exc:
            reason = "profile_request_timeout" if deadline.expired else (
                exc.reason if isinstance(exc, BoundaryViolation) else "profile_tls_failed")
            self.meter.refuse(reason)
        finally:
            if connection is not None:
                connection.close()
            deadline.close()
            self._done()
