# Unpublished external WordPress binding (#27)

This future source extends the maintained queue plugin with schema 9: an exact
immutable profile digest, explicit selected services, and durable cumulative
HTTP/TLS/body/active-time reservations. The existing `r2-header-v1` profile and
wire messages retain their defaults. External claims and result callbacks add
only `profile_id`, `profile_sha256`, and `services`; start/admit messages retain
their existing shape. Missing or changed bindings refuse work. Configuration
still defaults to disabled and no production release or customer consent is
established by this source.

Before creating or continuing an external job, the core independently reads the
frozen automatic envelope through the separate G2 adapter and checks its raw
metadata, canonical release/profile snapshots, exact Target Summary, signer
and acceptance digests, encoded post representation and fixed UTC expiry.
The automatic contract's identity header ends before its separately checked
canonical Summary. Legacy contract validation retains its existing boundaries.

External results retain only the fixed typed observation vocabulary, bounded
version tokens and the maintained Checker's public interpretation vocabulary.
Unknown check fields, raw page/title/header text, arbitrary interpretation
strings, unselected services and changed manifest identities are refused.
Conservative reservations charge 256 KiB and 10 seconds per HTTP admission,
and 10 seconds per TLS-only admission, without refunds. New connections wait
until the prior reservation's bounded timeout has elapsed. These conservative
rules can stop before the disclosed maximum counts.

Pure source checks (no WordPress bootstrap, database, DNS, HTTP or mail):

```sh
php integrations/wordpress/standalone-tests/external-profile.php
php integrations/wordpress/standalone-tests/report-access.php
php integrations/wordpress/standalone-tests/manual-lifecycle.php
```

For a combined G1/G2 frozen-evidence test, pass an isolated G2 source root and
an explicitly **SYNTHETIC** canonical generator release. The fixture calls the
actual route decoder, persistence producer/readback/copy helpers, and core
`ct_scan_validate_saved_request()` using synthetic WordPress API stores. It
covers Unicode, ampersands, apostrophes, exact summary/signature/expiry binding,
immutable-field tampering, duplicate metadata and altered post representation.
It does not invoke acceptance, create a queue job, adopt a release, or mail.
The optional trusted WordPress `kses.php` path adds the real pure entity
normalizer without bootstrapping WordPress.

```sh
CT_AUTO_CROSS_G2_ROOT=/isolated/G2-source \
CT_AUTO_CROSS_RELEASE=/private/SYNTHETIC/release.json \
CT_AUTO_CROSS_KSES=/trusted/wp-includes/kses.php \
php integrations/wordpress/standalone-tests/automatic-evidence-cross.php
```

`integrations/wordpress/tests/external-reservations.php` is a separate disposable
WordPress/database fixture source. It tests real schema columns, committed
reservations, stale-row CAS refusal, inflight exclusion and restored malformed
state using an owned fixture row. It does not represent a real external
acceptance or target scan. It has not been executed locally in this recovery.
Run only through the reviewed fixture support and an allocated protected
mutation slot; never run it against production.

Actual database concurrency, the full accepted automatic route/outbox/queue
lifecycle, mailbox and authority gates, worker/result/report delivery, rollback,
exact-head CI and two fresh final reviews remain required. The upstream
lifecycle fixes also remain a dependency. This future branch does not satisfy
those gates, enable scans, or close the related issues.
