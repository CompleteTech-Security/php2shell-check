"""Bounded system DNS lookup for the isolated external profile scanner.

The helper receives no admission descriptor, authentication key or configurable
resolver. Its process remains in the scanner's process group for outer cleanup.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


_LOOKUP = """import json,socket,sys
try:
 a=socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)
 if not 0<len(a)<=256: raise ValueError()
 b=json.dumps(a,separators=(',',':'),ensure_ascii=True).encode('ascii')
 if len(b)>16384: raise ValueError()
 sys.stdout.buffer.write(b)
except BaseException:
 sys.exit(2)
"""


class DNSFailure(Exception):
    pass


def resolve_answers(host, port, timeout):
    """Resolve once in a killable process; never leave a timed-out resolver alive."""
    if (not isinstance(host, str) or not host.isascii() or not host
            or type(port) is not int or port not in {80, 443}
            or type(timeout) not in {int, float} or not 0 < timeout <= 10):
        raise DNSFailure("profile_dns_invalid")
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", _LOOKUP, host, str(port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True, env={"PATH": os.defpath, "LC_ALL": "C"},
        )
        try:
            output, _ = process.communicate(timeout=timeout)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        if process.returncode or not 0 < len(output) <= 16384:
            raise DNSFailure("profile_dns_failed")
        value = json.loads(output.decode("ascii"))
        if type(value) is not list or not 0 < len(value) <= 256:
            raise DNSFailure("profile_dns_failed")
        return value
    except subprocess.TimeoutExpired as exc:
        raise DNSFailure("profile_dns_timeout") from exc
    except (OSError, ValueError, UnicodeError) as exc:
        raise DNSFailure("profile_dns_failed") from exc

