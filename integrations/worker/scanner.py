"""Unprivileged one-job scanner entry point. Invoked only by the supervisor."""

from __future__ import annotations

import json
import os
import signal
import socket
import sys

from dataclasses import asdict

from wordpress_check import Checker

from .admission import AdmissionRefused, ChildAdmission
from .control import ControlError, fetch_challenge_file, lookup_txt, system_resolver
from .network import PinnedOpener, RequestOrigin


MAX_INPUT_BYTES = 8192
MAX_OUTPUT_BYTES = 32 * 1024
CHILD_WALL_SECONDS = 175
CONTACT = "https://complete.tech/services/website-security/"


def _write(value, exit_code: int) -> int:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        encoded = b'{"ok":false,"error":"invalid_scanner_output"}'
        exit_code = 2
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = b'{"ok":false,"error":"output_overflow"}'
        exit_code = 2
    try:
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        return 2
    return exit_code


def _admission_channel():
    """Open the supervisor socket named by CT_ADMISSION_FD. Without it, nothing is contacted."""
    raw = os.environ.get("CT_ADMISSION_FD", "")
    if not raw.isdigit() or not 3 <= int(raw) <= 1023:
        return None
    try:
        channel = socket.socket(fileno=int(raw))
    except (OSError, ValueError):
        return None
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
        channel.close()
        return None
    return channel


def _control(task, scope, guard):
    """One exact-target control check: a single TXT lookup or HTTPS request, once admitted."""
    method = "dns_txt" if task == "control_dns" else "https_file"
    try:
        if task == "control_dns":
            observed = lookup_txt(scope.hostname, system_resolver(), guard)
            outcome = "observed" if observed else "not_found"
        else:
            outcome, observed = fetch_challenge_file(PinnedOpener(scope, guard=guard), scope.hostname)
    except AdmissionRefused as exc:
        reason = str(exc)
        slug = reason if reason.startswith("admission_") else "admission_" + reason
        return _write({"ok": False, "error": slug[:64]}, 2)
    except ControlError:
        outcome, observed = "error", []
    return _write({"ok": True, "control": {"method": method, "outcome": outcome, "observed": observed}}, 0)


def _timeout(_signum, _frame):
    raise TimeoutError("scanner_timeout")


def main() -> int:
    if not sys.platform.startswith("linux") or os.geteuid() != 65534:
        return _write({"ok": False, "error": "scanner_isolation_unavailable"}, 2)
    try:
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(CHILD_WALL_SECONDS)
    except (AttributeError, OSError, ValueError):
        return _write({"ok": False, "error": "scanner_deadline_unavailable"}, 2)
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return _write({"ok": False, "error": "scanner_input_too_large"}, 2)
        data = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(data, dict)
            or set(data) not in ({"target"}, {"target", "task"}, {"target", "profile_id", "profile_sha256", "services"})
            or not isinstance(data["target"], str)
            or data.get("task", "scan") not in {"scan", "control_dns", "control_https"}
        ):
            return _write({"ok": False, "error": "invalid_scanner_input"}, 2)
        task = data.get("task", "scan")
        scope, target = RequestOrigin.from_target(data["target"])
        if target != data["target"]:
            return _write({"ok": False, "error": "invalid_scanner_input"}, 2)
        external = "profile_id" in data
        if external:
            from .profiles import validate_binding
            from .network import ProfileScope
            services = validate_binding(data["profile_id"], data["profile_sha256"], data["services"])
            if (scope.initial_scheme, scope.initial_port) not in services:
                return _write({"ok": False, "error": "invalid_scanner_input"}, 2)
            external_scope, _ = ProfileScope.from_target(target, data["services"])
        channel = _admission_channel()
        if channel is None:
            # Fail closed: a scanner that cannot ask for admission never sends a request.
            return _write({"ok": False, "error": "admission_channel_unavailable"}, 2)
        guard = ChildAdmission(channel, kind="external" if external else "control" if task != "scan" else "http")
        if task != "scan":
            return _control(task, scope, guard)
        if external:
            from .external import execute_external, check_sensitive_response
            from .network import ExternalPinnedOpener, ProfileMeter
            # One meter and full selected-service scope survive every executor
            # factory call. No per-service reset, separate TLS channel or key.
            opener = ExternalPinnedOpener(external_scope, guard,
                profile_sha256=data["profile_sha256"], meter=ProfileMeter(),
                body_validator=lambda body, _headers: check_sensitive_response(body))
            tls_url = "https://" + scope.hostname + "/"
            result = execute_external(target, data["profile_sha256"], data["services"],
                transport_factory=lambda _service: opener,
                tls_probe=lambda _service: opener.inspect_tls(tls_url))
            return _write({"ok": True, "result": result}, 0)
        checker = Checker(timeout=10.0, delay=1.0, contact=CONTACT)
        checker.opener = PinnedOpener(scope, guard=guard)
        try:
            result = checker.check(target)
        except AdmissionRefused as exc:
            # Not a fetch error: a refused admission ends the run as a failure.
            reason = str(exc)
            slug = reason if reason.startswith("admission_") else "admission_" + reason
            return _write({"ok": False, "error": slug[:64]}, 2)
        return _write({"ok": True, "result": asdict(result)}, 0)
    except TimeoutError:
        return _write({"ok": False, "error": "scanner_timeout"}, 2)
    except BaseException:
        # The parent captures and discards stderr; never expose exception text here.
        return _write({"ok": False, "error": "scanner_failed"}, 2)
    finally:
        try:
            signal.alarm(0)
        except (AttributeError, OSError, ValueError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
