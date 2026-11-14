# Unpublished automatic external profile

`external-web-v1` is an integration-only candidate. The public single-file
checker keeps its existing interface. These sources do not provision a worker,
adopt an agreement, authorize a customer target, or enable the WordPress queue.

The canonical manifest is `integrations/profiles/external-web-v1.json`, pinned
by SHA-256 `1f2a19c959570157ee9df788141ae1e21b8f67aba8c6ce99b768efbd42eb7a37`.
Changing those bytes requires a separately reviewed profile and new assent;
neither configuration nor a retry can widen a saved authorization. A job binds
the manifest identity and explicit selected HTTP/80 and HTTPS/443 services.

The manifest permits robots policy, public homepage header/version triage,
security-header presence and a verified TLS certificate observation. It permits
only the selected hostname, root and robots paths. Advertised versions remain
evidence rather than verified runtime or exploitability. Internal configuration,
runtime/backport confirmation and compromise investigation remain unassessed.
No title, HTML, arbitrary header value, asset URL or raw certificate is retained
in the typed result. Possible sensitive-data or compromise indicators stop the
whole job with a fixed category; they do not initiate investigation.

The worker uses one meter and one admitted transport across every check,
redirect and selected service. DNS answers are bounded, private/reserved answers
are refused, and accepted addresses are pinned while preserving Host and TLS
SNI. A disposable resolver receives no authentication key or admission channel.
HTTP framing, header bytes, wire and decompressed body bytes and total request
time are bounded. HEAD observations do not read an unsolicited response body.

Each HTTP or TLS connection needs a fresh supervisor grant bound to the saved
profile. The manifest ceilings are 100 HTTP transactions, 20 additional TLS
checks, 600 active seconds, 5 MiB aggregate body bytes, 256 KiB per response,
32 KiB headers, ten seconds per request, one connection and at most one check
per second. The implementation can stop earlier: it reserves the full response
and time allowance before connecting, does not refund reservations or retry
automatically, and retains the existing 175-second child/180-second supervisor
limits. A restarted or uncertain job never acquires a fresh budget or rescans.

Source tests use injected transports, mocks and ephemeral local fixtures. They
do not establish production egress enforcement or customer authorization.
Before deployment, the matching WordPress binding must pass real disposable
database and controlled-network acceptance tests, including cancellation,
expiry, exact-target authority, mailbox/report recipients, budgets, retained
evidence and rollback. The current-base candidate still needs exact-head CI
and two fresh independent reviews. Site release and activation are separate
coordinated operations; keep the candidate disabled until those prerequisites
are verified.
