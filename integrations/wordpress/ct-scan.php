<?php
/**
 * Plugin Name: CompleteTech Authorized PHP2Shell Scan Queue
 * Description: Confirmation-gated, one-target PHP2Shell screening queue for Promo Requests.
 * Version: 0.2.0
 *
 * This MU plugin stores authorization and job state locally. It never starts a
 * scanner process. The external worker talks to the signed REST routes below.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'CT_SCAN_DEFAULT_TERMS_VERSION' ) ) {
	define( 'CT_SCAN_DEFAULT_TERMS_VERSION', '2026-10-21-r2' );
}

if ( ! defined( 'CT_SCAN_SCHEMA_VERSION' ) ) {
	// 9 adds immutable external-profile service bindings and conservative cumulative reservations.
	define( 'CT_SCAN_SCHEMA_VERSION', '9' );
}

/**
 * Execution profiles. A job freezes its profile id at creation, and the limits
 * live here in code rather than in editable configuration, so a later setting
 * cannot broaden an existing authorization. `r2-header-v1` is the current
 * homepage-header screening: robots.txt (at most six hops) plus the homepage
 * (at most six hops, with at most one HTTP-to-HTTPS origin change) is at most
 * 20 requests. Unknown profiles are refused.
 */
function ct_scan_current_profile() {
	$profile = ct_scan_config()['execution_profile'];
	return ct_scan_profile_limits( $profile ) ? $profile : '';
}

/** The reviewed external profile is immutable. A changed or missing artifact is not a new permission. */
function ct_scan_external_profile_manifest() {
	static $loaded = null;
	if ( null !== $loaded ) {
		return $loaded;
	}
	$loaded = false;
	$paths = array( __DIR__ . '/ct-scan-profiles/external-web-v1.json', dirname( __DIR__ ) . '/profiles/external-web-v1.json' );
	if ( defined( 'CT_SCAN_PROFILE_MANIFEST_DIR' ) && is_string( CT_SCAN_PROFILE_MANIFEST_DIR ) && '/' === substr( CT_SCAN_PROFILE_MANIFEST_DIR, 0, 1 ) && false === strpos( CT_SCAN_PROFILE_MANIFEST_DIR, "\0" ) ) {
		array_unshift( $paths, rtrim( CT_SCAN_PROFILE_MANIFEST_DIR, '/' ) . '/external-web-v1.json' );
	}
	foreach ( $paths as $path ) {
		if ( is_link( $path ) || ! is_file( $path ) || ! is_readable( $path ) || filesize( $path ) > 65536 ) {
			continue;
		}
		$bytes = file_get_contents( $path );
		if ( ! is_string( $bytes ) || strlen( $bytes ) > 65536 || ! hash_equals( ct_scan_external_profile_digest(), hash( 'sha256', $bytes ) ) ) {
			continue;
		}
		$value = json_decode( $bytes, true );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $value ) || 1 !== ( $value['schema_version'] ?? null )
			|| 'external-web-v1' !== ( $value['profile_id'] ?? null )
			|| wp_json_encode( ct_scan_canonicalize( $value ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" !== $bytes ) {
			continue;
		}
		$loaded = $value;
		break;
	}
	return $loaded;
}

/** Set to the exact reviewed manifest bytes when the implementation is integrated. */
function ct_scan_external_profile_digest() {
	return '1f2a19c959570157ee9df788141ae1e21b8f67aba8c6ce99b768efbd42eb7a37';
}

/** Canonical selected services are explicit; target normalization cannot add another service. */
function ct_scan_external_services( $services, $target = null ) {
	if ( ! is_array( $services ) || ! ct_scan_is_list( $services ) || count( $services ) < 1 || count( $services ) > 2 ) {
		return false;
	}
	$canonical = array();
	foreach ( array( array( 'port' => 80, 'scheme' => 'http' ), array( 'port' => 443, 'scheme' => 'https' ) ) as $allowed ) {
		foreach ( $services as $service ) {
			if ( ! is_array( $service ) || ! ct_scan_expected_keys( $service, array( 'scheme', 'port' ) )
				|| ! is_string( $service['scheme'] ) || ! is_int( $service['port'] ) ) {
				return false;
			}
			if ( $service['scheme'] === $allowed['scheme'] && $service['port'] === $allowed['port'] ) {
				if ( in_array( $allowed, $canonical, true ) ) { return false; }
				$canonical[] = $allowed;
			}
		}
	}
	if ( count( $canonical ) !== count( $services ) ) { return false; }
	foreach ( $services as $i => $service ) { if ( $service['scheme'] !== $canonical[$i]['scheme'] || $service['port'] !== $canonical[$i]['port'] ) { return false; } }
	if ( null !== $target ) {
		$normalized = ct_scan_normalize_target( $target );
		if ( is_wp_error( $normalized ) || $normalized !== $target ) { return false; }
		$parts = is_string( $target ) ? wp_parse_url( $target ) : false;
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) { return false; }
		$initial = array( 'port' => $parts['port'] ?? ( 'https' === $parts['scheme'] ? 443 : 80 ), 'scheme' => $parts['scheme'] );
		if ( ! in_array( $initial, $canonical, true ) ) { return false; }
	}
	return $canonical;
}

/** Read the four complete profile bindings; r2 never acquires external permissions from these fields. */
function ct_scan_external_saved_binding( $request_id, $target ) {
	$values = array();
	foreach ( array( '_ct_terms_profile_id', '_ct_terms_profile_sha256', '_ct_terms_scope_services', '_ct_terms_profile_snapshot', '_ct_terms_authorization_expires_at' ) as $key ) {
		$rows = get_post_meta( $request_id, $key, false );
		if ( ! is_array( $rows ) || 1 !== count( $rows ) || ! is_string( $rows[0] ) ) { return false; }
		$values[ $key ] = $rows[0];
	}
	$manifest = ct_scan_external_profile_manifest();
	if ( ! $manifest || 'external-web-v1' !== $values['_ct_terms_profile_id']
		|| ! hash_equals( ct_scan_external_profile_digest(), $values['_ct_terms_profile_sha256'] )
		|| ! hash_equals( ct_scan_external_profile_digest(), hash( 'sha256', $values['_ct_terms_profile_snapshot'] ) ) ) { return false; }
	$services = json_decode( $values['_ct_terms_scope_services'], true );
	$services = JSON_ERROR_NONE === json_last_error() ? ct_scan_external_services( $services, $target ) : false;
	if ( false === $services || wp_json_encode( ct_scan_canonicalize( $services ), JSON_UNESCAPED_SLASHES ) !== $values['_ct_terms_scope_services'] ) { return false; }
	if ( ! ct_scan_utc_parse( $values['_ct_terms_authorization_expires_at'] ) ) { return false; }
	return array( 'profile_id' => 'external-web-v1', 'profile_sha256' => ct_scan_external_profile_digest(), 'services' => $services, 'expires_at_utc' => $values['_ct_terms_authorization_expires_at'] );
}

/** A site adapter supplies a frozen envelope; it cannot substitute a boolean for core validation. */
function ct_scan_external_evidence( $request_id, $fields, $binding ) {
	if ( ! function_exists( 'ct_scan_read_automatic_evidence_v1' ) ) { return false; }
	try { $envelope = ct_scan_read_automatic_evidence_v1( $request_id, $fields ); } catch ( Throwable $error ) { return false; }
	$map = array(
		'release_sha256' => '_ct_auto_release_sha256', 'release_snapshot' => '_ct_auto_release_snapshot',
		'terms_version' => '_ct_terms_version', 'terms_html' => '_ct_terms_snapshot', 'terms_sha256' => '_ct_terms_sha256',
		'acceptance_statement' => '_ct_terms_statement', 'profile_id' => '_ct_terms_profile_id', 'profile_sha256' => '_ct_terms_profile_sha256',
		'profile_snapshot' => '_ct_terms_profile_snapshot', 'scope_services_json' => '_ct_terms_scope_services',
		'target' => '_ct_scan_target', 'legal_name' => '_ct_terms_client_legal_name', 'signer_name' => '_ct_terms_signer_name',
		'signer_role' => '_ct_terms_signer_role', 'typed_signature' => '_ct_terms_typed_signature', 'email' => '_ct_scan_email', 'referrer' => '_ct_ref',
		'summary_text' => '_ct_summary_text', 'summary_sha256' => '_ct_summary_sha256', 'expires_at_utc' => '_ct_terms_authorization_expires_at',
		'accepted_at_utc' => '_ct_terms_accepted_at', 'idempotency_key' => '_ct_auto_idempotency_key', 'evidence_sha256' => '_ct_auto_evidence_sha256',
		'review_id' => '_ct_auto_review_id', 'review_issued_at_utc' => '_ct_auto_review_issued_at', 'review_expires_at_utc' => '_ct_auto_review_expires_at',
	);
	if ( ! is_array( $envelope ) || ! ct_scan_expected_keys( $envelope, array_merge( array_keys( $map ), array( 'scope_services' ) ) ) ) { return false; }
	foreach ( $map as $field => $key ) {
		$rows = get_post_meta( $request_id, $key, false );
		if ( ! is_string( $envelope[$field] ) || strlen( $envelope[$field] ) > 1048576 || ! is_array( $rows ) || 1 !== count( $rows ) || ! is_string( $rows[0] ) || ! hash_equals( $rows[0], $envelope[$field] ) ) { return false; }
	}
	foreach ( array( 'release_sha256', 'terms_sha256', 'profile_sha256', 'summary_sha256', 'evidence_sha256' ) as $field ) {
		if ( ! preg_match( '/\A[a-f0-9]{64}\z/', $envelope[$field] ) ) { return false; }
	}
	foreach ( array( 'idempotency_key', 'review_id' ) as $field ) {
		if ( ! preg_match( '/\A[A-Za-z0-9_~-]{16,128}\z/', $envelope[$field] ) ) { return false; }
	}
	$services = ct_scan_external_services( $envelope['scope_services'], $envelope['target'] );
	if ( false === $services || $services !== $binding['services'] || 'external-web-v1' !== $envelope['profile_id']
		|| ! hash_equals( $binding['profile_sha256'], $envelope['profile_sha256'] ) || ! hash_equals( $binding['expires_at_utc'], $envelope['expires_at_utc'] )
		|| wp_json_encode( ct_scan_canonicalize( $services ), JSON_UNESCAPED_SLASHES ) !== $envelope['scope_services_json']
		|| ! hash_equals( $envelope['release_sha256'], hash( 'sha256', $envelope['release_snapshot'] ) )
		|| ! hash_equals( $envelope['terms_sha256'], hash( 'sha256', $envelope['terms_html'] ) )
		|| ! hash_equals( $envelope['summary_sha256'], hash( 'sha256', $envelope['summary_text'] ) ) ) { return false; }
	$release = json_decode( $envelope['release_snapshot'], true );
	if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $release ) || 1 !== ( $release['schema_version'] ?? null )
		|| ! isset( $release['release'], $release['profile'], $release['terms'], $release['copy'] ) || ! is_array( $release['release'] ) || ! is_array( $release['profile'] ) || ! is_array( $release['terms'] ) || ! is_array( $release['copy'] )
		|| wp_json_encode( ct_scan_canonicalize( $release ), JSON_UNESCAPED_SLASHES ) . "\n" !== $envelope['release_snapshot']
		|| ( $release['release']['terms_version'] ?? null ) !== $envelope['terms_version']
		|| ( $release['profile']['profile_id'] ?? null ) !== $envelope['profile_id'] || ( $release['profile']['sha256'] ?? null ) !== $envelope['profile_sha256']
		|| ( $release['profile']['manifest_json'] ?? null ) !== $envelope['profile_snapshot']
		|| ( $release['terms']['html'] ?? null ) !== $envelope['terms_html'] || ( $release['terms']['sha256'] ?? null ) !== $envelope['terms_sha256']
		|| ( $release['copy']['acceptance_statement'] ?? null ) !== $envelope['acceptance_statement']
		|| 2592000 !== ( $release['release']['authorization_max_seconds'] ?? null ) ) { return false; }
	if ( ! preg_match( '/\A(\d{4}-\d{2}-\d{2})-r[1-9][0-9]{0,2}\z/', $envelope['terms_version'], $version_match ) || ! ct_scan_utc_parse( $version_match[1] . 'T00:00:00Z' ) ) { return false; }
	$contract = get_post_meta( $request_id, '_ct_terms_contract', false );
	$plain = $release['terms']['plain_text'] ?? null;
	if ( ! is_string( $plain ) || '' === $plain || strlen( $plain ) > 524288 || ! is_array( $contract ) || 1 !== count( $contract ) || ! is_string( $contract[0] ) ) { return false; }
	$parts = explode( "\nTERMS AS ACCEPTED\n", $contract[0], 2 );
	if ( 2 !== count( $parts ) || ! hash_equals( $plain, $parts[1] ) ) { return false; }
	$format = get_post_meta( $request_id, '_ct_auto_contract_format', false );
	$post = get_post( $request_id );
	$technical_raw = get_post_meta( $request_id, '_ct_auto_technical_snapshot', false );
	$technical_sha = get_post_meta( $request_id, '_ct_auto_technical_sha256', false );
	$terms_url = get_post_meta( $request_id, '_ct_terms_url', false );
	if ( ! is_array( $format ) || array( 'escaped-pre-v1' ) !== $format || ! $post || ! is_array( $technical_raw ) || 1 !== count( $technical_raw ) || ! is_string( $technical_raw[0] )
		|| strlen( $technical_raw[0] ) > 8192 || ! is_array( $technical_sha ) || 1 !== count( $technical_sha ) || ! is_string( $technical_sha[0] )
		|| ! hash_equals( hash( 'sha256', $technical_raw[0] ), $technical_sha[0] ) || ! is_array( $terms_url ) || 1 !== count( $terms_url ) || ! is_string( $terms_url[0] ) ) { return false; }
	$technical = json_decode( $technical_raw[0], true );
	if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $technical ) || ! ct_scan_expected_keys( $technical, array( 'client_ip', 'remote_addr', 'ip_source', 'user_agent', 'idempotency_key', 'evidence_sha256', 'accepted_at_utc' ) )
		|| wp_json_encode( ct_scan_canonicalize( $technical ), JSON_UNESCAPED_SLASHES ) !== $technical_raw[0] ) { return false; }
	foreach ( array( 'client_ip' => '_ct_terms_ip', 'remote_addr' => '_ct_terms_remote_addr', 'ip_source' => '_ct_terms_ip_source', 'user_agent' => '_ct_terms_user_agent' ) as $field => $key ) {
		$values = get_post_meta( $request_id, $key, false );
		if ( ! is_string( $technical[$field] ) || strlen( $technical[$field] ) > 1024 || ! is_array( $values ) || 1 !== count( $values ) || $values[0] !== $technical[$field] ) { return false; }
	}
	foreach ( array( 'idempotency_key', 'evidence_sha256', 'accepted_at_utc' ) as $field ) { if ( $technical[$field] !== $envelope[$field] ) { return false; } }
	$context = array( 'schema_version' => 1, 'envelope' => $envelope, 'technical' => $technical, 'terms_url' => $terms_url[0] );
	$body = 'CT-AUTO-EVIDENCE-V1 ' . base64_encode( wp_json_encode( ct_scan_canonicalize( $context ), JSON_UNESCAPED_SLASHES ) ) . "\n" . ct_scan_automatic_contract_body_v1( $contract[0] );
	if ( $post->post_content !== $body ) { return false; }
	$accepted = ct_scan_utc_parse( $envelope['accepted_at_utc'] );
	$issued = ct_scan_utc_parse( $envelope['review_issued_at_utc'] );
	$review_end = ct_scan_utc_parse( $envelope['review_expires_at_utc'] );
	$expires = ct_scan_utc_parse( $envelope['expires_at_utc'] );
	$cap = ct_scan_utc_parse( $release['release']['authorization_cap_utc'] ?? null );
	if ( ! $accepted || ! $issued || ! $review_end || ! $expires || ! $cap || $issued > $accepted || $accepted > $review_end
		|| $review_end->getTimestamp() - $issued->getTimestamp() > 900 || $expires <= $accepted || $expires > $accepted->modify( '+30 days' ) || $expires > $cap ) { return false; }
	$without_digest = $envelope;
	unset( $without_digest['evidence_sha256'] );
	$canonical = wp_json_encode( ct_scan_canonicalize( $without_digest ), JSON_UNESCAPED_SLASHES );
	$whole = get_post_meta( $request_id, '_ct_auto_envelope', false );
	if ( ! is_string( $canonical ) || ! hash_equals( $envelope['evidence_sha256'], hash( 'sha256', $canonical ) ) || ! is_array( $whole ) || 1 !== count( $whole )
		|| $whole[0] !== wp_json_encode( ct_scan_canonicalize( $envelope ), JSON_UNESCAPED_SLASHES ) ) { return false; }
	return $envelope;
}

/** Disclosed limits of the exact-target control check. */
function ct_scan_control_limits() {
	return array(
		'max_attempts'    => 3,
		'min_interval_ms' => 60000,
		'max_bytes'       => 4096,
		'timeout_ms'      => 10000,
		'valid_ms'        => 1000,
		'lease_seconds'   => 120,
		'path'            => '/.well-known/ct-scan-challenge.txt',
		'dns_label'       => '_ct-scan-challenge',
		'dns_prefix'      => 'ct-scan-verify=',
	);
}

function ct_scan_profile_limits( $profile_id ) {
	if ( ! is_string( $profile_id ) ) { return false; }
	if ( 'external-web-v1' === $profile_id ) {
		$manifest = ct_scan_external_profile_manifest();
		if ( ! $manifest || ! isset( $manifest['limits'] ) || ! is_array( $manifest['limits'] ) ) { return false; }
		return array_merge( $manifest['limits'], array( 'http_requests' => 100, 'min_interval_ms' => 1000, 'valid_ms' => 1000, 'timeout_ms' => 10000 ) );
	}
	$profiles = array(
		'r2-header-v1' => array(
			'http_requests'   => 20,
			// At most one request per second for the target, enforced centrally.
			'min_interval_ms' => 1000,
			// Disclosed bounds: an admission may be used for one second, and one
			// admitted request may finish within the ten-second timeout.
			'valid_ms'        => 1000,
			'timeout_ms'      => 10000,
		),
	);
	return is_string( $profile_id ) && isset( $profiles[ $profile_id ] ) ? $profiles[ $profile_id ] : false;
}

/** Load the secret-bearing settings without ever rendering their values. */
function ct_scan_config() {
	static $config = null;
	if ( null !== $config ) {
		return $config;
	}

	$config = array(
		'enabled'                  => false,
		'execution_profile'        => 'r2-header-v1',
		'supported_terms_version'  => CT_SCAN_DEFAULT_TERMS_VERSION,
		'expected_checker_revision'=> '',
		'expected_rules_as_of'     => '2026-10-21',
		'worker_hmac_secret'       => '',
		'authorization_end_at'     => '2026-12-20T23:59:59Z',
		'confirmation_ttl_hours'   => 168,
		'global_daily_limit'       => 20,
		'target_daily_limit'       => 1,
		'job_retention_days'       => 365,
		// Email the verified contact their accepted copy after confirmation (off by default).
		'send_accepted_copy'       => false,
		// An explicit decision for every terms version the integration serves: array( '<version>' => 'strict' | 'legacy' ).
		// `strict` (also what an unlisted version gets) requires bound evidence and proof of control of the
		// exact target. `legacy` grandfathers an r2-or-earlier acceptance flow and is honoured ONLY for those versions.
		// The integration refuses to enable unless supported_terms_version has an entry here.
		'terms_policy'             => array(),
		// The admission guard is advisory to a scanner that ignores it; only enforced network egress
		// (allow the customer's HTTP/HTTPS, deny private/metadata ranges) makes it a boundary. The
		// operator must state, deliberately, that this exists. See docs/WORDPRESS.md "Egress".
		'egress_enforced'          => false,
		// Owner decisions (2026-10-22): findings 12 months; signed authorization evidence 6 years
		// after request closure, except r2 and earlier acceptances, which keep 3 years from acceptance.
		'evidence_retention_years' => 6,
		'legacy_retention_years'   => 3,
		// How long a deletion tombstone is kept: longer than the longest backup rotation (90 days).
		'tombstone_retention_days' => 120,
	);

	$path = defined( 'CT_SCAN_PRIVATE_CONFIG' )
		? CT_SCAN_PRIVATE_CONFIG
		: WP_CONTENT_DIR . '/ct-scan-private/config.php';
	if ( ! is_string( $path ) || ! is_readable( $path ) ) {
		return $config;
	}

	try {
		$loaded = include $path;
	} catch ( Throwable $error ) {
		return $config;
	}
	if ( ! is_array( $loaded ) ) {
		return $config;
	}
	$config = array_merge( $config, $loaded );
	$config['enabled'] = true === $config['enabled']
		&& is_string( $config['worker_hmac_secret'] )
		&& strlen( $config['worker_hmac_secret'] ) >= 32
		&& true === $config['egress_enforced']
		&& ct_scan_policy_declared( $config )
		&& false !== ct_scan_profile_limits( $config['execution_profile'] )
		&& ( 'external-web-v1' !== $config['execution_profile'] || ( ! ct_scan_is_legacy_version( $config['supported_terms_version'] ) && 'strict' === $config['terms_policy'][ $config['supported_terms_version'] ] ) )
		&& is_string( $config['expected_checker_revision'] )
		&& 1 === preg_match( '/\A[a-f0-9]{40}\z/i', $config['expected_checker_revision'] )
		&& is_string( $config['supported_terms_version'] )
		&& '' !== $config['supported_terms_version'];

	return $config;
}

/**
 * r2 and earlier acceptances (versions `YYYY-MM-DD-rN` up to `2026-10-21-r2`) are the only ones that may be
 * grandfathered. A version that cannot be parsed is NOT legacy.
 */
function ct_scan_is_legacy_version( $version ) {
	if ( ! is_string( $version ) || ! preg_match( '/\A(\d{4}-\d{2}-\d{2})-r([1-9]\d{0,2})\z/', $version, $m ) ) {
		return false;
	}
	$date = explode( '-', $m[1] );
	if ( ! checkdate( (int) $date[1], (int) $date[2], (int) $date[0] ) ) {
		return false;
	}
	return $m[1] < '2026-10-21' || ( '2026-10-21' === $m[1] && (int) $m[2] <= 2 );
}

/**
 * The requirement a terms version carries. STRICT is the default for every version: bound evidence (and,
 * where the control gate exists, proof of control of the exact target). `legacy` is honoured only when the
 * operator listed that exact version AND it is an r2-or-earlier version, so a new version can never inherit
 * the grandfathered flow by omission or by configuration.
 */
function ct_scan_terms_policy( $version ) {
	$config = ct_scan_config();
	$policy = is_array( $config['terms_policy'] ) && is_string( $version ) && isset( $config['terms_policy'][ $version ] ) ? $config['terms_policy'][ $version ] : '';
	return ( 'legacy' === $policy && ct_scan_is_legacy_version( $version ) ) ? 'legacy' : 'strict';
}

/** The integration serves one terms version; its policy must be an explicit, valid decision. */
function ct_scan_policy_declared( $config ) {
	$version = $config['supported_terms_version'];
	if ( ! is_string( $version ) || '' === $version || ! is_array( $config['terms_policy'] ) || ! isset( $config['terms_policy'][ $version ] ) ) {
		return false;
	}
	$policy = $config['terms_policy'][ $version ];
	return 'strict' === $policy || ( 'legacy' === $policy && ct_scan_is_legacy_version( $version ) );
}

/**
 * The canonical signer-aware Target Summary for strict terms versions. It is deterministic from the
 * accepted request fields and the code-defined profile limits. Returns '' for an unknown profile.
 */
function ct_scan_target_summary( $target, $legal_name, $signer_name, $signer_role, $email, $profile = null, $services = null, $expires_at_utc = null ) {
	$profile = null === $profile ? ct_scan_current_profile() : $profile;
	$limits  = ct_scan_profile_limits( $profile );
	if ( ! $limits || ! is_string( $target ) || ! is_string( $legal_name ) || ! is_string( $signer_name ) || ! is_string( $signer_role ) || ! is_string( $email )
		|| '' === $legal_name || '' === $signer_name || '' === $signer_role || '' === $email ) {
		return '';
	}
	if ( 'external-web-v1' === $profile ) {
		$services = ct_scan_external_services( $services, $target );
		if ( false === $services || ! ct_scan_utc_parse( $expires_at_utc ) ) { return ''; }
		$names = array_map( static function ( $service ) { return $service['scheme'] . ':' . $service['port']; }, $services );
		return 'Website (scan scope): ' . $target . "\n"
			. 'Client legal name: ' . $legal_name . "\n"
			. 'Signer: ' . $signer_name . "\n"
			. 'Signer role: ' . $signer_role . "\n"
			. 'Client email: ' . $email . "\n"
			. 'Selected services: ' . implode( ', ', $names ) . "\n"
			. 'Profile: external-web-v1' . "\n"
			. 'Profile SHA-256: ' . ct_scan_external_profile_digest() . "\n"
			. "Limits: at most 100 HTTP transactions, 20 additional TLS-only checks, 600 cumulative active seconds, 5242880 body bytes; one connection at a time and at most one check per second\n"
			. "Response limits: 262144 decompressed body bytes, 32768 header bytes, 10 seconds per request; no more than two transient retries and three redirect hops per check\n"
			. 'Authorization expires (UTC): ' . $expires_at_utc . "\n"
			. "Early closure: completion, cancellation, or an earlier accepted deadline ends new target requests\n";
	}
	return 'Website (scan scope): ' . $target . "\n"
		. 'Client legal name: ' . $legal_name . "\n"
		. 'Signer: ' . $signer_name . "\n"
		. 'Signer role: ' . $signer_role . "\n"
		. 'Client email: ' . $email . "\n"
		. 'Profile: ' . $profile . "\n"
		. 'Limits: this website only (HTTP 80 / HTTPS 443); at most ' . (int) $limits['http_requests'] . ' requests, one at a time, at most one per second, ' . (int) ( $limits['timeout_ms'] / 1000 ) . " seconds each\n"
		. "Authorization: expires 60 days after acceptance (never after the published window end), or when the request closes\n";
}

/** The frozen r2-and-earlier Target Summary, used only for explicitly grandfathered legacy acceptances. */
function ct_scan_legacy_target_summary( $target, $name, $email, $profile = null ) {
	$profile = null === $profile ? ct_scan_current_profile() : $profile;
	$limits  = ct_scan_profile_limits( $profile );
	if ( ! $limits || ! is_string( $target ) || ! is_string( $name ) || ! is_string( $email ) ) {
		return '';
	}
	return 'Website (scan scope): ' . $target . "\n"
		. 'Client contact: ' . $name . "\n"
		. 'Client email: ' . $email . "\n"
		. 'Profile: ' . $profile . "\n"
		. 'Limits: this website only (HTTP 80 / HTTPS 443); at most ' . (int) $limits['http_requests'] . ' requests, one at a time, at most one per second, ' . (int) ( $limits['timeout_ms'] / 1000 ) . " seconds each\n"
		. "Authorization: expires 60 days after acceptance (never after the published window end), or when the request closes\n";
}

function ct_scan_enabled() {
	$config = ct_scan_config();
	return ! empty( $config['enabled'] );
}

function ct_scan_jobs_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_jobs';
}

function ct_scan_tombstones_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_tombstones';
}

function ct_scan_nonces_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_nonces';
}

/** Create plugin tables once; MU plugins do not receive activation hooks. */
function ct_scan_maybe_install_schema() {
	$previous = get_option( 'ct_scan_schema_version' );
	if ( $previous === CT_SCAN_SCHEMA_VERSION ) {
		return;
	}
	// A failed upgrade must not re-run dbDelta on every public request: back off for five minutes.
	if ( get_transient( 'ct_scan_schema_backoff' ) ) {
		return;
	}
	global $wpdb;
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$charset = $wpdb->get_charset_collate();
	$jobs    = ct_scan_jobs_table();
	$nonces  = ct_scan_nonces_table();
	$sql     = "CREATE TABLE {$jobs} (
		job_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		request_id bigint(20) unsigned NOT NULL,
		target_origin varchar(512) NOT NULL,
		scope_hash char(64) NOT NULL,
		terms_version varchar(64) NOT NULL,
		terms_hash char(64) NOT NULL,
		terms_accepted_at datetime NOT NULL,
		authorization_expires_at datetime NOT NULL,
		contact_email varchar(320) NOT NULL,
		contact_name varchar(190) NOT NULL,
		referrer varchar(128) NOT NULL,
		status varchar(32) NOT NULL,
		created_at datetime NOT NULL,
		confirmation_token_hash char(64) NULL,
		stop_token_hash char(64) NULL,
		confirmation_expires_at datetime NULL,
		confirmation_email_status varchar(16) NOT NULL DEFAULT 'pending',
		confirmed_at datetime NULL,
		lease_hash char(64) NULL,
		lease_until datetime NULL,
		attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
		started_at datetime NULL,
		finished_at datetime NULL,
		outcome varchar(16) NULL,
		error_code varchar(64) NULL,
		checker_revision char(40) NULL,
		result_json longtext NULL,
		receipt_hash char(64) NULL,
		manual_remainder_status varchar(16) NOT NULL DEFAULT 'pending',
		manual_remainder_notes longtext NULL,
		manual_remainder_completed_at datetime NULL,
		report_notification_status varchar(16) NOT NULL DEFAULT 'not_sent',
		report_notification_at datetime NULL,
		report_access_token_hash char(64) NULL,
		report_access_expires_at datetime NULL,
		report_access_used_at datetime NULL,
		report_delivered_at datetime NULL,
		closure_source varchar(32) NULL,
		closed_by bigint(20) unsigned NULL,
		closure_reason varchar(64) NULL,
		revoked_at datetime NULL,
		profile_id varchar(32) NOT NULL DEFAULT 'r2-header-v1',
		profile_sha256 char(64) NULL,
		services_json varchar(256) NULL,
		http_admitted smallint(5) unsigned NOT NULL DEFAULT 0,
		tls_admitted smallint(5) unsigned NOT NULL DEFAULT 0,
		reserved_body_bytes int(10) unsigned NOT NULL DEFAULT 0,
		reserved_active_ms int(10) unsigned NOT NULL DEFAULT 0,
		inflight_until_ms bigint(20) unsigned NULL,
		reservation_version tinyint(1) unsigned NOT NULL DEFAULT 0,
		last_admit_ms bigint(20) unsigned NULL,
		summary_sha256 char(64) NULL,
		bound_required tinyint(1) unsigned NOT NULL DEFAULT 0,
		accepted_copy_status varchar(16) NOT NULL DEFAULT 'not_sent',
		accepted_copy_at datetime NULL,
		control_required tinyint(1) unsigned NOT NULL DEFAULT 0,
		control_state varchar(12) NOT NULL DEFAULT 'none',
		control_token_hash char(64) NULL,
		control_page_hash char(64) NULL,
		control_requested_method varchar(12) NULL,
		control_attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
		control_last_attempt_ms bigint(20) unsigned NULL,
		control_leased_ms bigint(20) unsigned NULL,
		control_admitted tinyint(1) unsigned NOT NULL DEFAULT 0,
		control_lease_hash char(64) NULL,
		control_lease_until datetime NULL,
		control_method varchar(16) NULL,
		control_verified_at datetime NULL,
		control_valid_until datetime NULL,
		control_evidence text NULL,
		closed_at datetime NULL,
		retain_until datetime NULL,
		hold_reason varchar(190) NULL,
		hold_until datetime NULL,
		hold_set_by bigint(20) unsigned NULL,
		hold_set_at datetime NULL,
		hold_released_by bigint(20) unsigned NULL,
		hold_released_at datetime NULL,
		identity char(32) NULL,
		retention_checked_at datetime NULL,
		PRIMARY KEY  (job_id),
		UNIQUE KEY request_id (request_id),
		KEY status_created (status,created_at),
		KEY scope_created (scope_hash,created_at),
		KEY authorization_expires_at (authorization_expires_at),
		KEY confirmation_token_hash (confirmation_token_hash),
		KEY stop_token_hash (stop_token_hash),
		KEY retain_until (retain_until)
	) {$charset};";
	dbDelta( $sql );
	// Deletion tombstones: identifiers only, no personal data. A restored backup cannot resurrect a
	// deleted record because maintenance deletes anything that matches a tombstone again.
	$tombstones = ct_scan_tombstones_table();
	dbDelta( "CREATE TABLE {$tombstones} (
		tombstone_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		job_id bigint(20) unsigned NOT NULL,
		request_id bigint(20) unsigned NOT NULL,
		scope_mac char(64) NOT NULL,
		created_at datetime NOT NULL,
		deleted_at datetime NOT NULL,
		reason varchar(32) NOT NULL,
		identity char(32) NULL,
		PRIMARY KEY  (tombstone_id),
		UNIQUE KEY identity (job_id,request_id,scope_mac,created_at),
		KEY deleted_at (deleted_at)
	) {$charset};" );
	$sql = "CREATE TABLE {$nonces} (
		nonce_hash char(64) NOT NULL,
		expires_at datetime NOT NULL,
		PRIMARY KEY  (nonce_hash),
		KEY expires_at (expires_at)
	) {$charset};";
	dbDelta( $sql );
	$required = array(
		$jobs   => array( 'job_id', 'request_id', 'target_origin', 'scope_hash', 'terms_version', 'terms_hash', 'terms_accepted_at', 'authorization_expires_at', 'status', 'lease_hash', 'result_json', 'receipt_hash', 'report_notification_status', 'report_notification_at', 'report_delivered_at', 'closure_source', 'closed_by', 'closure_reason', 'report_access_token_hash', 'report_access_expires_at', 'report_access_used_at', 'stop_token_hash', 'profile_id', 'http_admitted', 'last_admit_ms', 'summary_sha256', 'bound_required', 'accepted_copy_status', 'accepted_copy_at', 'control_required', 'control_state', 'control_token_hash', 'control_page_hash', 'control_requested_method', 'control_attempts', 'control_last_attempt_ms', 'control_leased_ms', 'control_admitted', 'control_lease_hash', 'control_lease_until', 'control_method', 'control_verified_at', 'control_valid_until', 'control_evidence', 'closed_at', 'retain_until', 'hold_reason', 'hold_until', 'hold_set_by', 'hold_set_at', 'hold_released_by', 'hold_released_at', 'identity', 'retention_checked_at', 'profile_sha256', 'services_json', 'tls_admitted', 'reserved_body_bytes', 'reserved_active_ms', 'inflight_until_ms', 'reservation_version' ),
		$nonces => array( 'nonce_hash', 'expires_at' ),
		$tombstones => array( 'tombstone_id', 'job_id', 'request_id', 'scope_mac', 'created_at', 'deleted_at', 'reason', 'identity' ),
	);
	foreach ( $required as $table => $columns ) {
		$found = $wpdb->get_col( "SHOW COLUMNS FROM {$table}", 0 );
		if ( ! is_array( $found ) || array_diff( $columns, $found ) ) {
			// Loud once per back-off window, and bounded. The worker API stays refused (fail closed).
			error_log( 'ct-scan: database upgrade to schema ' . CT_SCAN_SCHEMA_VERSION . ' is incomplete for ' . $table . '; the worker API stays refused. Retrying in 5 minutes. Restore from backup or repair the table.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			set_transient( 'ct_scan_schema_backoff', '1', 5 * MINUTE_IN_SECONDS );
			return;
		}
	}
	delete_transient( 'ct_scan_schema_backoff' );
	if ( is_string( $previous ) && '' !== $previous && version_compare( $previous, '3', '<' ) ) {
		// A job that started before request counting existed has no record of what it already
		// sent: it gets no fresh budget, so its remaining admissions are refused.
		$limits = ct_scan_profile_limits( ct_scan_current_profile() );
		$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET http_admitted = %d WHERE status = 'running'", (int) $limits['http_requests'] ) );
	}
	update_option( 'ct_scan_schema_version', CT_SCAN_SCHEMA_VERSION, false );
}
add_action( 'init', 'ct_scan_maybe_install_schema', 2 );

/** Normalize a visitor-supplied URL to the exact authorized HTTP(S) origin. */
function ct_scan_normalize_target( $url ) {
	$bad = function ( $message ) {
		return new WP_Error( 'ct_scan_invalid_target', $message );
	};
	if ( ! is_string( $url ) ) {
		return $bad( 'The website address must be text.' );
	}
	if ( '' === $url || strlen( $url ) > 2048 || preg_match( '/[\x00-\x20\x7f]/', $url ) ) {
		return $bad( 'Enter one valid public website address.' );
	}
	$url = trim( $url );
	$parts = wp_parse_url( $url );
	if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
		return $bad( 'Include a complete http:// or https:// website address.' );
	}
	$scheme = strtolower( $parts['scheme'] );
	$host   = strtolower( $parts['host'] );
	if ( ! in_array( $scheme, array( 'http', 'https' ), true )
		|| isset( $parts['user'] ) || isset( $parts['pass'] )
		|| isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
		return $bad( 'Use an HTTP or HTTPS address without credentials, a query, or a fragment.' );
	}
	$port = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	if ( ( 'https' === $scheme && 443 !== $port ) || ( 'http' === $scheme && 80 !== $port ) ) {
		return $bad( 'Only the standard HTTP and HTTPS ports are allowed.' );
	}
	if ( isset( $parts['path'] ) && '' !== $parts['path'] && '/' !== $parts['path'] ) {
		return $bad( 'Enter the website homepage so the authorized scope is explicit.' );
	}
	if ( false !== strpos( $host, '%' ) || false !== inet_pton( trim( $host, '[]' ) ) ) {
		return $bad( 'IP address literals are not allowed.' );
	}
	if ( preg_match( '/\A(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\z/i', $host ) ) {
		return $bad( 'Numeric IP address forms are not allowed.' );
	}
	if ( strlen( $host ) > 253 || substr( $host, -1 ) === '.' || false !== strpos( $host, '..' ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$labels = explode( '.', $host );
	if ( count( $labels ) < 2 ) {
		return $bad( 'Use a public hostname with at least two labels.' );
	}
	foreach ( $labels as $label ) {
		if ( strlen( $label ) > 63 || ! preg_match( '/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/i', $label ) ) {
			return $bad( 'The website hostname is not valid.' );
		}
	}
	$tld = end( $labels );
	if ( strlen( $tld ) < 2 || ctype_digit( $tld ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$private_suffixes = array( 'localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'test', 'example', 'invalid', 'onion' );
	if ( in_array( $tld, $private_suffixes, true ) || 'localhost' === $host ) {
		return $bad( 'Local and reserved hostnames are not allowed.' );
	}
	return $scheme . '://' . $host . '/';
}

function ct_scan_utc_now() {
	return gmdate( 'Y-m-d H:i:s' );
}

function ct_scan_utc_parse( $value ) {
	if ( ! is_string( $value ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/', $value ) ) {
		return false;
	}
	try {
		$date = new DateTimeImmutable( $value, new DateTimeZone( 'UTC' ) );
		return $date->format( 'Y-m-d\TH:i:s\Z' ) === $value ? $date : false;
	} catch ( Throwable $error ) {
		return false;
	}
}

/** Pure producer helpers use the same versioned records the independent reader checks below. */
function ct_scan_authority_digest_v1( $legal_name, $signer_name, $signer_role, $signature ) {
	foreach ( array( $legal_name, $signer_name, $signer_role, $signature ) as $value ) {
		$length = is_string( $value ) ? ( function_exists( 'mb_strlen' ) ? mb_strlen( $value, 'UTF-8' ) : strlen( $value ) ) : 0;
		if ( ! is_string( $value ) || '' === $value || trim( $value ) !== $value || $length > 120 || preg_match( '/[\x00-\x1f\x7f<>]/', $value ) || sanitize_text_field( $value ) !== $value ) { return false; }
	}
	if ( ! hash_equals( $signer_name, $signature ) ) { return false; }
	return hash( 'sha256', 'Client legal name: ' . $legal_name . "\nSigner full name: " . $signer_name . "\nSigner role (stated): " . $signer_role . "\nTyped signature: " . $signature . "\n" );
}

function ct_scan_acceptance_digest_v1( $terms_version, $terms_sha256, $summary_sha256, $authority_sha256, $statement, $accepted_at_utc ) {
	if ( ! is_string( $terms_version ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}-r[1-9][0-9]{0,2}\z/', $terms_version )
		|| ! is_string( $statement ) || '' === $statement || strlen( $statement ) > 8192 || ! ct_scan_utc_parse( $accepted_at_utc ) ) { return false; }
	foreach ( array( $terms_sha256, $summary_sha256, $authority_sha256 ) as $hash ) {
		if ( ! is_string( $hash ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $hash ) ) { return false; }
	}
	return hash( 'sha256', 'Terms version: ' . $terms_version . "\nTerms SHA-256: " . $terms_sha256 . "\nTarget Summary SHA-256: " . $summary_sha256 . "\nSigner evidence SHA-256: " . $authority_sha256 . "\nAcceptance statement SHA-256: " . hash( 'sha256', $statement ) . "\nAccepted at (UTC): " . $accepted_at_utc . "\n" );
}

/** Preserve raw signed bytes without asking WordPress to treat untrusted identity text as markup. */
function ct_scan_automatic_contract_body_v1( $contract ) {
	if ( ! is_string( $contract ) || '' === $contract || strlen( $contract ) > 1048576 || 1 !== preg_match( '//u', $contract ) ) { return false; }
	return 'CT-AUTOMATIC-CONTRACT-BASE64: ' . base64_encode( $contract ) . "\n<pre>" . htmlspecialchars( $contract, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ) . '</pre>';
}

function ct_scan_meta_string( $post_id, $key ) {
	$value = get_post_meta( $post_id, $key, true );
	return is_string( $value ) ? $value : '';
}

/**
 * Evidence binding. A "bound" acceptance retains the exact terms bytes that the signer was
 * shown and the exact Target Summary, each next to the digest the signer's form carried:
 *
 *   _ct_terms_binding        '1' marks the acceptance as bound
 *   _ct_terms_snapshot       the terms bytes as displayed (the immutable artifact)
 *   _ct_terms_sha256         SHA-256 of those bytes
 *   _ct_terms_shown_digest   the digest the rendered form carried (must equal the above)
 *   _ct_summary_text         the Target Summary as displayed ("Label: value" lines)
 *   _ct_summary_sha256       SHA-256 of that text
 *   _ct_summary_shown_digest the digest the form carried for the summary
 *
 * Any partial or mismatched set refuses the job (and cancels a queued or running one via
 * ct_scan_authorization_is_live). Every version must be bound (the `strict` policy, which is the default)
 * unless the operator grandfathered an r2-or-earlier version as `legacy` in config `terms_policy`.
 */
function ct_scan_check_bound_evidence( $request_id, $terms_hash, $identity, $required, $profile ) {
	// get_post_meta( ..., true ) silently returns the first of several rows, so an evidence key that
	// holds more than one value is ambiguous: refuse rather than pick one.
	foreach ( array( '_ct_terms_binding', '_ct_terms_snapshot', '_ct_terms_sha256', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest', '_ct_terms_client_legal_name', '_ct_terms_signer_name', '_ct_terms_signer_role', '_ct_terms_typed_signature', '_ct_terms_authority_sha256', '_ct_terms_evidence_sha256', '_ct_terms_statement' ) as $key ) {
		if ( count( (array) get_post_meta( $request_id, $key, false ) ) > 1 ) {
			return new WP_Error( 'ct_scan_evidence_duplicate', 'The saved acceptance holds more than one value for a piece of evidence.' );
		}
	}
	$marker  = ct_scan_meta_string( $request_id, '_ct_terms_binding' );
	$partial = false;
	foreach ( array( '_ct_terms_snapshot', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest', '_ct_terms_client_legal_name', '_ct_terms_signer_name', '_ct_terms_signer_role', '_ct_terms_typed_signature', '_ct_terms_authority_sha256', '_ct_terms_evidence_sha256', '_ct_terms_statement' ) as $key ) {
		if ( '' !== ct_scan_meta_string( $request_id, $key ) ) {
			$partial = true;
		}
	}
	if ( '1' !== $marker ) {
		if ( $required || '' !== $marker || $partial ) {
			return new WP_Error( 'ct_scan_binding_required', 'The saved acceptance does not carry the required bound evidence.' );
		}
		return array( 'bound' => false, 'summary_sha256' => null, 'required' => false );
	}
	$snapshot = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary  = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	if ( '' === $snapshot || strlen( $snapshot ) > 524288 || '' === $summary || strlen( $summary ) > 8192 ) {
		return new WP_Error( 'ct_scan_binding_mismatch', 'The retained terms or Target Summary is missing or oversized.' );
	}
	$snapshot_hash = hash( 'sha256', $snapshot );
	$summary_hash  = hash( 'sha256', $summary );
	// A list of [computed, recorded] pairs, never keyed by the computed hash: byte-identical terms and
	// Summary would share a key and silently drop the terms comparison.
	$checks = array(
		array( $snapshot_hash, $terms_hash ),
		array( $snapshot_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_terms_shown_digest' ) ) ),
		array( $summary_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_summary_sha256' ) ) ),
		array( $summary_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_summary_shown_digest' ) ) ),
	);
	foreach ( $checks as $check ) {
		list( $computed, $value ) = $check;
		if ( ! is_string( $value ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $value ) || ! hash_equals( $computed, $value ) ) {
			return new WP_Error( 'ct_scan_binding_mismatch', 'The retained evidence does not match the digest the signer was shown.' );
		}
	}
	// The Target Summary must be exactly the canonical text of the authorized request (website, client,
	// profile, limits, authorization period): nothing before, between or after, so no decoy or appended
	// instruction can ride along, and the limits the signer saw are the limits the job runs under.
	if ( ! empty( $identity['strict_authority'] ) ) {
		$expected = ct_scan_target_summary( $identity['target'], $identity['legal_name'], $identity['signer_name'], $identity['signer_role'], $identity['email'], $profile, $identity['services'] ?? null, $identity['expires_at_utc'] ?? null );
	} else {
		$expected = ct_scan_legacy_target_summary( $identity['target'], $identity['name'], $identity['email'], $profile );
	}
	if ( '' === $expected || ! hash_equals( $expected, $summary ) ) {
		return new WP_Error( 'ct_scan_binding_mismatch', 'The retained Target Summary is not the canonical summary of the authorized request.' );
	}
	return array( 'bound' => true, 'summary_sha256' => $summary_hash, 'required' => (bool) $required );
}

/** Validate the versioned client/signer evidence independently from the display form. */
function ct_scan_read_signer_evidence( $request_id, $terms_version, $terms_hash, $summary_hash, $accepted_raw, $contact_name, $contract, $required ) {
	if ( ! $required ) {
		return array( 'strict' => false, 'legal_name' => '', 'signer_name' => '', 'signer_role' => '', 'authority_sha256' => '' );
	}
	$keys = array(
		'legal_name'  => '_ct_terms_client_legal_name',
		'signer_name' => '_ct_terms_signer_name',
		'signer_role' => '_ct_terms_signer_role',
		'signature'   => '_ct_terms_typed_signature',
	);
	$authority = array();
	foreach ( $keys as $field => $meta_key ) {
		$values = (array) get_post_meta( $request_id, $meta_key, false );
		$value  = ct_scan_meta_string( $request_id, $meta_key );
		$length = function_exists( 'mb_strlen' ) ? mb_strlen( $value, 'UTF-8' ) : strlen( $value );
		if ( 1 !== count( $values ) || '' === $value || trim( $value ) !== $value || $length > 120
			|| preg_match( '/[\x00-\x1f\x7f<>]/', $value ) || sanitize_text_field( $value ) !== $value ) {
			return new WP_Error( 'ct_scan_signer_evidence_missing', 'The saved client and signer evidence is incomplete or ambiguous.' );
		}
		$authority[ $field ] = $value;
	}
	if ( ! hash_equals( $contact_name, $authority['signer_name'] ) || ! hash_equals( $authority['signer_name'], $authority['signature'] ) ) {
		return new WP_Error( 'ct_scan_signer_evidence_mismatch', 'The saved signer does not match the signed request contact.' );
	}
	$authority_record = 'Client legal name: ' . $authority['legal_name'] . "\n"
		. 'Signer full name: ' . $authority['signer_name'] . "\n"
		. 'Signer role (stated): ' . $authority['signer_role'] . "\n"
		. 'Typed signature: ' . $authority['signature'] . "\n";
	$authority_hash = hash( 'sha256', $authority_record );
	$statement      = ct_scan_meta_string( $request_id, '_ct_terms_statement' );
	$accepted_at    = ct_scan_utc_parse( $accepted_raw );
	if ( ! preg_match( '/\A[a-f0-9]{64}\z/', (string) $summary_hash ) || '' === $statement || ! $accepted_at || $accepted_at->format( 'Y-m-d\\TH:i:s\\Z' ) !== $accepted_raw ) {
		return new WP_Error( 'ct_scan_signer_evidence_mismatch', 'The signed acceptance statement or time is missing or invalid.' );
	}
	$evidence_record = 'Terms version: ' . $terms_version . "\n"
		. 'Terms SHA-256: ' . $terms_hash . "\n"
		. 'Target Summary SHA-256: ' . $summary_hash . "\n"
		. 'Signer evidence SHA-256: ' . $authority_hash . "\n"
		. 'Acceptance statement SHA-256: ' . hash( 'sha256', $statement ) . "\n"
		. 'Accepted at (UTC): ' . $accepted_raw . "\n";
	$evidence_hash = hash( 'sha256', $evidence_record );
	if ( ! hash_equals( $authority_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_terms_authority_sha256' ) ) )
		|| ! hash_equals( $evidence_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_terms_evidence_sha256' ) ) ) ) {
		return new WP_Error( 'ct_scan_signer_evidence_mismatch', 'The saved signer and acceptance digests do not match their source values.' );
	}
	$header_parts = explode( "\nTERMS AS ACCEPTED\n", $contract, 2 );
	if ( 2 !== count( $header_parts ) ) {
		return new WP_Error( 'ct_scan_signer_contract_mismatch', 'The filled-in agreement has no unambiguous accepted-terms boundary.' );
	}
	$contract_header = $header_parts[0];
	$contract_lines = array(
		'Client legal name'  => $authority['legal_name'],
		'Client contact'     => $authority['signer_name'],
		'Signer role (stated)' => $authority['signer_role'],
		'Typed signature'    => $authority['signature'],
	);
	foreach ( $contract_lines as $label => $expected ) {
		if ( 1 !== preg_match_all( '/^' . preg_quote( $label, '/' ) . ':[ \\t]*(.*)$/m', $contract_header, $matches ) || trim( $matches[1][0] ) !== $expected ) {
			return new WP_Error( 'ct_scan_signer_contract_mismatch', 'The filled-in agreement does not match the saved client and signer fields.' );
		}
	}
	foreach ( array( 'Signer evidence SHA-256' => $authority_hash, 'Acceptance evidence SHA-256' => $evidence_hash ) as $label => $expected ) {
		if ( 1 !== preg_match_all( '/^' . preg_quote( $label, '/' ) . ':[ \\t]*([a-f0-9]{64})$/m', $contract_header, $matches ) || ! hash_equals( $expected, $matches[1][0] ) ) {
			return new WP_Error( 'ct_scan_signer_contract_mismatch', 'The filled-in agreement omits or changes its signed evidence digest.' );
		}
	}
	return array(
		'strict'          => true,
		'legal_name'      => $authority['legal_name'],
		'signer_name'     => $authority['signer_name'],
		'signer_role'     => $authority['signer_role'],
		'authority_sha256'=> $authority_hash,
	);
}

/** Check the saved request and acceptance snapshot before any job is created. */
function ct_scan_validate_saved_request( $request_id, $fields, $require_current_terms = true, $frozen_expiry = '', $frozen = null, $allow_expired = false ) {
	// Authorization is judged on what the database holds now, never on an object-cache copy.
	clean_post_cache( (int) $request_id );
	$config = ct_scan_config();
	$profile = is_array( $frozen ) ? (string) $frozen['profile'] : ct_scan_current_profile();
	$post   = get_post( $request_id );
	if ( ! $post || 'ct_promo_request' !== $post->post_type || 'private' !== $post->post_status ) {
		return new WP_Error( 'ct_scan_request_missing', 'The saved private request could not be verified.' );
	}
	if ( ! is_array( $fields ) ) {
		return new WP_Error( 'ct_scan_fields_invalid', 'The saved request fields could not be verified.' );
	}
	foreach ( array( 'target', 'email', 'name', 'referrer' ) as $key ) {
		if ( ! isset( $fields[ $key ] ) || ! is_string( $fields[ $key ] ) ) {
			return new WP_Error( 'ct_scan_fields_incomplete', 'The saved request fields are incomplete.' );
		}
	}
	$target = ct_scan_normalize_target( $fields['target'] );
	if ( is_wp_error( $target ) || $target !== $fields['target'] ) {
		return new WP_Error( 'ct_scan_target_mismatch', 'The saved authorized target is not in normalized form.' );
	}
	$email = sanitize_email( $fields['email'] );
	$name  = sanitize_text_field( $fields['name'] );
	$ref   = sanitize_title( $fields['referrer'] );
	if ( ! is_email( $email ) || $email !== $fields['email'] || '' === $name || $name !== $fields['name']
		|| '' === $ref || $ref !== $fields['referrer'] ) {
		return new WP_Error( 'ct_scan_contact_mismatch', 'The saved contact or referral fields are incomplete.' );
	}
	foreach ( array(
		'_ct_scan_target' => $target,
		'_ct_scan_email'  => $email,
		'_ct_scan_name'   => $name,
		'_ct_ref'         => $ref,
	) as $key => $expected ) {
		if ( ct_scan_meta_string( $request_id, $key ) !== $expected ) {
			return new WP_Error( 'ct_scan_request_readback_mismatch', 'The saved request did not match its authorization event.' );
		}
	}
	if ( '1' !== ct_scan_meta_string( $request_id, '_ct_terms_saved' ) ) {
		return new WP_Error( 'ct_scan_acceptance_incomplete', 'A complete saved terms acceptance is required.' );
	}
	$terms_version = ct_scan_meta_string( $request_id, '_ct_terms_version' );
	$terms_url     = ct_scan_meta_string( $request_id, '_ct_terms_url' );
	$terms_hash    = strtolower( ct_scan_meta_string( $request_id, '_ct_terms_sha256' ) );
	$accepted_raw  = ct_scan_meta_string( $request_id, '_ct_terms_accepted_at' );
	$contract      = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$accepted_at   = ct_scan_utc_parse( $accepted_raw );
	if ( ( $require_current_terms && $terms_version !== $config['supported_terms_version'] ) || '' === $terms_url
		|| ! preg_match( '/\A[a-f0-9]{64}\z/', $terms_hash ) || ! $accepted_at
		|| '' === trim( $contract ) ) {
		return new WP_Error( 'ct_scan_acceptance_stale', 'The saved terms acceptance is missing or no longer current.' );
	}
	if ( $accepted_at->getTimestamp() > time() + 300 ) {
		return new WP_Error( 'ct_scan_acceptance_time_invalid', 'The saved acceptance time could not be verified.' );
	}
	$expected_lines = array(
		'Client contact'       => $name,
		'Client email'         => $email,
		'Website (scan scope)' => $target,
		'Referred by'          => $ref,
	);
	foreach ( $expected_lines as $label => $expected ) {
		if ( ! preg_match( '/^' . preg_quote( $label, '/' ) . ':\s*(.*)$/m', $contract, $match ) || trim( $match[1] ) !== $expected ) {
			return new WP_Error( 'ct_scan_contract_mismatch', 'The saved acceptance copy does not match the authorized request fields.' );
		}
	}
	$stored_contract = 'external-web-v1' === $profile ? ct_scan_automatic_contract_body_v1( $contract ) : $contract;
	if ( false === $stored_contract || false === strpos( $post->post_content, $stored_contract ) ) {
		return new WP_Error( 'ct_scan_contract_readback_mismatch', 'The saved acceptance copy could not be read back from the request.' );
	}
	// A job's evidence requirement and profile are frozen when it is created, so a later
	// configuration change can neither relax nor tighten an authorization already given.
	$bound_required = is_array( $frozen ) ? (bool) $frozen['bound_required'] : 'strict' === ct_scan_terms_policy( $terms_version );
	$profile        = is_array( $frozen ) ? (string) $frozen['profile'] : ct_scan_current_profile();
	$profile_binding = null;
	$automatic = null;
	$identity_contract = $contract;
	if ( 'external-web-v1' === $profile ) {
		$profile_binding = ct_scan_external_saved_binding( $request_id, $target );
		if ( ! $bound_required || ct_scan_is_legacy_version( $terms_version ) || ! $profile_binding ) {
			return new WP_Error( 'ct_scan_profile_binding_invalid', 'The saved automatic profile authorization could not be verified.' );
		}
		$automatic = ct_scan_external_evidence( $request_id, $fields, $profile_binding );
		if ( ! $automatic || $automatic['target'] !== $target || $automatic['email'] !== $email || $automatic['signer_name'] !== $name || $automatic['referrer'] !== $ref ) {
			return new WP_Error( 'ct_scan_automatic_evidence_invalid', 'The saved automatic acceptance envelope could not be verified.' );
		}
		if ( is_array( $frozen ) && ( ! isset( $frozen['profile_sha256'], $frozen['services_json'] ) || ! is_string( $frozen['profile_sha256'] )
			|| ! hash_equals( $profile_binding['profile_sha256'], $frozen['profile_sha256'] ) || $frozen['services_json'] !== $automatic['scope_services_json'] ) ) {
			return new WP_Error( 'ct_scan_profile_binding_changed', 'The accepted services or profile no longer match the frozen job.' );
		}
		// The automatic representation separately binds its exact canonical Summary.
		// Its repeated identity labels are not a second signer header. Keep legacy
		// all-header checks unchanged and check the automatic header independently.
		$sections = explode( "\n\n", $contract, 2 );
		$terms = explode( "\nTERMS AS ACCEPTED\n", $contract, 2 );
		if ( 2 !== count( $sections ) || 2 !== count( $terms ) || $sections[1] !== $automatic['summary_text'] . "\nTERMS AS ACCEPTED\n" . $terms[1] ) {
			return new WP_Error( 'ct_scan_contract_mismatch', 'The automatic header and canonical Summary boundary could not be verified.' );
		}
		$identity_contract = $sections[0] . "\nTERMS AS ACCEPTED\n" . $terms[1];
	}
	$signer = ct_scan_read_signer_evidence( $request_id, $terms_version, $terms_hash, ct_scan_meta_string( $request_id, '_ct_summary_sha256' ), $accepted_raw, $name, $identity_contract, $bound_required );
	if ( is_wp_error( $signer ) ) {
		return $signer;
	}
	if ( $signer['strict'] ) {
		$expected_lines = array_merge( $expected_lines, array(
			'Client legal name'   => $signer['legal_name'],
			'Signer role (stated)' => $signer['signer_role'],
			'Typed signature'     => $signer['signer_name'],
		) );
		foreach ( $expected_lines as $label => $expected ) {
			if ( 1 !== preg_match_all( '/^' . preg_quote( $label, '/' ) . ':[ \\t]*(.*)$/m', $identity_contract, $matches ) || trim( $matches[1][0] ) !== $expected ) {
				return new WP_Error( 'ct_scan_contract_mismatch', 'The saved acceptance copy does not match the authorized request fields.' );
			}
		}
	}
	$summary_identity = array(
		'target'           => $target,
		'email'            => $email,
		'name'             => $name,
		'strict_authority' => $signer['strict'],
		'legal_name'       => $signer['legal_name'],
		'signer_name'      => $signer['signer_name'],
		'signer_role'      => $signer['signer_role'],
		'services'         => $profile_binding['services'] ?? null,
		'expires_at_utc'   => $profile_binding['expires_at_utc'] ?? null,
	);
	$bound = ct_scan_check_bound_evidence( $request_id, $terms_hash, $summary_identity, $bound_required, $profile );
	if ( is_wp_error( $bound ) ) {
		return $bound;
	}
	if ( 'external-web-v1' === $profile ) {
		$expires = ct_scan_utc_parse( $profile_binding['expires_at_utc'] );
		if ( ! $expires || $expires > $accepted_at->modify( '+30 days' ) || $expires <= $accepted_at
			|| ( '' !== $frozen_expiry && $expires->format( 'Y-m-d H:i:s' ) !== $frozen_expiry ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The frozen automatic authorization expiry could not be verified.' );
		}
		if ( $require_current_terms ) {
			$window_end = ct_scan_utc_parse( $config['authorization_end_at'] );
			if ( ! $window_end || $expires > $window_end ) { return new WP_Error( 'ct_scan_expiry_invalid', 'The displayed authorization exceeds the configured publication window.' ); }
		}
	} elseif ( $require_current_terms ) {
		$window_end = ct_scan_utc_parse( $config['authorization_end_at'] );
		if ( ! $window_end ) {
			return new WP_Error( 'ct_scan_config_invalid', 'The authorization end date is not configured.' );
		}
		$expires = $accepted_at->modify( '+60 days' );
		if ( $window_end < $expires ) {
			$expires = $window_end;
		}
	} else {
		if ( ! preg_match( '/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\z/', $frozen_expiry ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		try {
			$expires = new DateTimeImmutable( $frozen_expiry, new DateTimeZone( 'UTC' ) );
		} catch ( Throwable $error ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		if ( $expires > $accepted_at->modify( '+60 days' ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry exceeds its accepted window.' );
		}
	}
	if ( ! $allow_expired && $expires <= new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) ) {
		return new WP_Error( 'ct_scan_authorization_expired', 'The scan authorization window has expired.' );
	}
	return array(
		'post'                  => $post,
		'target'                => $target,
		'email'                 => $email,
		'name'                  => $name,
		'referrer'              => $ref,
		'legal_name'            => $signer['legal_name'],
		'signer_name'           => $signer['signer_name'],
		'signer_role'           => $signer['signer_role'],
		'authority_sha256'      => $signer['authority_sha256'],
		'terms_version'         => $terms_version,
		'terms_hash'            => $terms_hash,
		'terms_accepted_at'     => $accepted_at->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'authorization_expires' => $expires->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'summary_sha256'        => $bound['summary_sha256'],
		'bound_required'        => $bound_required,
		'profile_id'            => $profile,
		'profile_sha256'        => $profile_binding['profile_sha256'] ?? null,
		'services_json'         => $automatic['scope_services_json'] ?? null,
	);
}

/** Acquire the per-site MySQL advisory lock used to serialize state changes. */
function ct_scan_lock_acquire( $wait_seconds = 0 ) {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	// Worker paths never wait (they fail closed and retry). Customer stop and
	// operator revocation may wait briefly so a concurrent admission cannot make
	// a cancellation spuriously fail.
	$wait = max( 0, min( 5, (int) $wait_seconds ) );
	return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, $wait ) );
}

function ct_scan_lock_release() {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) );
}

/**
 * Queue-disabled manual closure may proceed only while its caller owns the same queue lock and a
 * successful current-schema read proves that this request has never entered the scan queue.
 */
function ct_scan_manual_closure_ready( $request_id ) {
	global $wpdb;
	if ( ( ! is_int( $request_id ) && ! ( is_string( $request_id ) && ctype_digit( $request_id ) ) )
		|| (int) $request_id <= 0 || (string) (int) $request_id !== (string) $request_id
		|| get_option( 'ct_scan_schema_version' ) !== CT_SCAN_SCHEMA_VERSION ) {
		return false;
	}
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	$wpdb->last_error = '';
	$owns_lock = $wpdb->get_var( $wpdb->prepare( 'SELECT IS_USED_LOCK(%s) = CONNECTION_ID()', $name ) );
	if ( '' !== (string) $wpdb->last_error || '1' !== (string) $owns_lock ) {
		return false;
	}
	$wpdb->last_error = '';
	$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_jobs_table() . ' WHERE request_id = %d LIMIT 1', (int) $request_id ) );
	return '' === (string) $wpdb->last_error && null === $row;
}

/** A manual final-close marker is fail-closed, including when its owning archive plugin is unavailable. */
function ct_scan_manual_queue_blocked( $request_id ) {
	global $wpdb;
	// The caller holds the queue lock. Read the database directly: another process may
	// repopulate a persistent whole-post metadata cache after an invalidation.
	$wpdb->last_error = '';
	$markers = $wpdb->get_col( $wpdb->prepare(
		"SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = %d AND meta_key = %s",
		$request_id,
		'_ct_archive_manual_lifecycle'
	) );
	if ( '' !== (string) $wpdb->last_error || ! is_array( $markers ) ) {
		return true;
	}
	if ( array() === $markers ) {
		return false;
	}
	if ( 1 !== count( $markers ) || ! is_string( $markers[0] ) || ! function_exists( 'ct_archive_manual_queue_blocked' ) ) {
		return true;
	}
	// The archive plugin strictly decodes and verifies this exact raw marker and its binding.
	return false !== ct_archive_manual_queue_blocked( $request_id, $markers[0] );
}

function ct_scan_mark_request_status( $request_id, $status, $detail = '' ) {
	update_post_meta( $request_id, '_ct_scan_status', sanitize_key( $status ) );
	if ( '' !== $detail ) {
		update_post_meta( $request_id, '_ct_scan_status_detail', sanitize_key( $detail ) );
	} else {
		delete_post_meta( $request_id, '_ct_scan_status_detail' );
	}
}

function ct_scan_safe_notice( $request_id, $code ) {
	ct_scan_mark_request_status( $request_id, 'not_queued', $code );
	return new WP_Error( 'ct_scan_' . sanitize_key( $code ), 'The request was retained, but the scan was not queued.' );
}

/**
 * Single event entry point. The theme calls this only after durable readback;
 * the plugin repeats that readback and never infers scope from post text.
 */
function ct_scan_on_request_ready( $request_id, $fields ) {
	$request_id = absint( $request_id );
	if ( ! $request_id || ! ct_scan_enabled() ) {
		if ( $request_id ) {
			return ct_scan_safe_notice( $request_id, 'disabled' );
		}
		return new WP_Error( 'ct_scan_request_id_invalid', 'The saved request could not be identified.' );
	}
	$config = ct_scan_config();
	$token  = bin2hex( random_bytes( 32 ) );
	// Separate long-lived token for the customer's Stop link; only its hash is stored.
	$stop_token = bin2hex( random_bytes( 32 ) );
	$now    = time();
	$ttl    = max( 1, min( 168, absint( $config['confirmation_ttl_hours'] ) ) );
	$created = gmdate( 'Y-m-d H:i:s', $now );
	$confirm_expires = gmdate( 'Y-m-d H:i:s', $now + ( $ttl * HOUR_IN_SECONDS ) );
	$jobs = ct_scan_jobs_table();
	global $wpdb;
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_safe_notice( $request_id, 'queue_busy' );
	}
	try {
		if ( ct_scan_manual_queue_blocked( $request_id ) ) {
			return ct_scan_safe_notice( $request_id, 'manual_final_close' );
		}
		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
		if ( $existing ) {
			update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
			update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
			if ( ! empty( $existing->identity ) ) {
				update_post_meta( $request_id, '_ct_scan_identity', $existing->identity );
			}
			update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
			ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
			return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
		}
		if ( get_post_meta( $request_id, '_ct_scan_event_recorded', true ) ) {
			return new WP_Error( 'ct_scan_duplicate_event', 'This request already has a scan event.' );
		}
		$accepted = ct_scan_validate_saved_request( $request_id, $fields );
		if ( is_wp_error( $accepted ) ) {
			return ct_scan_safe_notice( $request_id, $accepted->get_error_code() );
		}
		$scope_hash = hash( 'sha256', $accepted['target'] );
		$since = gmdate( 'Y-m-d H:i:s', $now - DAY_IN_SECONDS );
		$global_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE created_at >= %s", $since ) );
		$target_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE scope_hash = %s AND created_at >= %s", $scope_hash, $since ) );
		if ( $global_count >= min( 1000, max( 1, absint( $config['global_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'global_quota' );
		}
		if ( $target_count >= min( 10, max( 1, absint( $config['target_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'target_quota' );
		}
		$identity = bin2hex( random_bytes( 16 ) );
		$inserted = $wpdb->insert(
			$jobs,
			array(
				'request_id'               => $request_id,
				'target_origin'            => $accepted['target'],
				'scope_hash'               => $scope_hash,
				'terms_version'            => $accepted['terms_version'],
				'terms_hash'               => $accepted['terms_hash'],
				'terms_accepted_at'        => $accepted['terms_accepted_at'],
				'authorization_expires_at' => $accepted['authorization_expires'],
				'contact_email'            => $accepted['email'],
				'contact_name'             => $accepted['name'],
				'referrer'                 => $accepted['referrer'],
				'status'                   => 'awaiting_confirmation',
				'created_at'               => $created,
				'confirmation_token_hash'  => hash( 'sha256', $token ),
				'confirmation_expires_at'  => $confirm_expires,
				'stop_token_hash'          => hash( 'sha256', $stop_token ),
				'profile_id'               => $accepted['profile_id'],
				'profile_sha256'           => $accepted['profile_sha256'],
				'services_json'            => $accepted['services_json'],
				'reservation_version'      => 'external-web-v1' === $accepted['profile_id'] ? 1 : 0,
				'summary_sha256'           => $accepted['summary_sha256'],
				'bound_required'           => $accepted['bound_required'] ? 1 : 0,
				// Opaque identity mirrored on the private request: lets a deletion tombstone recognise
				// the same record after a restore without matching on recyclable numeric ids.
				'identity'                 => $identity,
				// Frozen at creation: a later configuration change cannot relax an existing job. Every version is strict
				// (requires control of the exact target) unless an r2-or-earlier version was explicitly grandfathered.
				// A profile broader than the r2 header screening can never run without target control.
				'control_required'         => ( 'strict' === ct_scan_terms_policy( $accepted['terms_version'] ) || 'r2-header-v1' !== ct_scan_current_profile() ) ? 1 : 0,
			),
			null
		);
		if ( 1 !== $inserted ) {
			$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
			if ( $existing ) {
				update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
				update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
				if ( ! empty( $existing->identity ) ) {
					update_post_meta( $request_id, '_ct_scan_identity', $existing->identity );
				}
				update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
				ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
				return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
			}
			return ct_scan_safe_notice( $request_id, 'queue_write_failed' );
		}
		$job_id = (int) $wpdb->insert_id;
		update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
		update_post_meta( $request_id, '_ct_scan_job_id', $job_id );
		update_post_meta( $request_id, '_ct_scan_identity', $identity );
		update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $accepted['authorization_expires'] );
		ct_scan_mark_request_status( $request_id, 'awaiting_confirmation' );
	} finally {
		ct_scan_lock_release();
	}

	$url = add_query_arg(
		array( 'action' => 'ct_scan_confirm', 'token' => $token ),
		admin_url( 'admin-post.php' )
	);
	$stop_url = add_query_arg(
		array( 'action' => 'ct_scan_stop', 'stop' => $stop_token ),
		admin_url( 'admin-post.php' )
	);
	$subject = 'Confirm your authorized PHP2Shell screening';
	$message = "A request was saved to screen the website you authorized.\n\n"
		. "To confirm and allow one passive check of " . wp_parse_url( $accepted['target'], PHP_URL_HOST ) . ", open this link and press Confirm. Opening the link alone does not authorize a scan:\n\n"
		. $url . "\n\nThis confirmation expires in {$ttl} hours. If you did not submit this request, ignore this message. Mailbox confirmation shows control of this email address; it does not independently prove domain ownership.\n\n"
		. "To stop this screening at any time, open this link and press Stop. Opening the link alone changes nothing:\n\n"
		. $stop_url . "\n";
	$mail_status = 'unknown';
	$pending = $wpdb->update( $jobs, array( 'confirmation_email_status' => 'unknown' ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'pending' ), array( '%s' ), array( '%d', '%s' ) );
	if ( 1 !== $pending ) {
		update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
		return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => 'unknown' );
	}
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
	try {
		$mail_status = wp_mail( $accepted['email'], $subject, $message ) ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$mail_status = 'unknown';
	}
	$wpdb->update( $jobs, array( 'confirmation_email_status' => $mail_status ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', $mail_status );
	return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => $mail_status );
}
add_action( 'ct_promo_request_ready', 'ct_scan_on_request_ready', 10, 2 );

function ct_scan_row( $job_id ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE job_id = %d", absint( $job_id ) ) );
}

/** Does this job require proof of control of the exact target? A missing value counts as required. */
function ct_scan_control_required( $row ) {
	return ! is_object( $row ) || ! isset( $row->control_required ) || ! empty( $row->control_required );
}

function ct_scan_authorization_is_live( $row ) {
	if ( ! is_object( $row ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
		|| strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		return false;
	}
	if ( ct_scan_meta_string( (int) $row->request_id, '_ct_scan_authorization_expires_at' ) !== $row->authorization_expires_at ) {
		return false;
	}
	// A job that required proof of control of the exact target is runnable only while that proof stands.
	if ( ct_scan_control_required( $row ) && in_array( $row->status, array( 'queued', 'leased', 'running' ), true ) ) {
		if ( empty( $row->control_verified_at )
			|| ( ! empty( $row->control_valid_until ) && strtotime( $row->control_valid_until . ' UTC' ) <= time() ) ) {
			return false;
		}
	}
	$fields = array(
		'target'   => $row->target_origin,
		'email'    => $row->contact_email,
		'name'     => $row->contact_name,
		'referrer' => $row->referrer,
	);
	$accepted = ct_scan_validate_saved_request( (int) $row->request_id, $fields, false, $row->authorization_expires_at, array( 'bound_required' => ! empty( $row->bound_required ), 'profile' => (string) $row->profile_id, 'profile_sha256' => $row->profile_sha256 ?? null, 'services_json' => $row->services_json ?? null ) );
	if ( is_wp_error( $accepted ) ) {
		return false;
	}
	return hash_equals( $row->scope_hash, hash( 'sha256', $accepted['target'] ) )
		&& hash_equals( $row->terms_hash, $accepted['terms_hash'] )
		&& $row->terms_version === $accepted['terms_version']
		&& $row->terms_accepted_at === $accepted['terms_accepted_at']
		&& $row->authorization_expires_at === $accepted['authorization_expires']
		// The retained Target Summary is part of the authorization: it cannot change afterwards.
		&& ( null === $accepted['summary_sha256']
			? empty( $row->summary_sha256 )
			: ( is_string( $row->summary_sha256 ) && hash_equals( $row->summary_sha256, $accepted['summary_sha256'] ) ) );
}

/** Reconcile bounded leases and apply the published data-retention windows. */
function ct_scan_maintenance_locked() {
	global $wpdb;
	$table = ct_scan_jobs_table();
	$now   = ct_scan_utc_now();
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'authorization_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL, confirmation_token_hash = NULL, control_token_hash = NULL, control_page_hash = NULL, control_lease_hash = NULL, control_lease_until = NULL, control_state = 'none' WHERE status IN ('awaiting_confirmation','awaiting_control','queued','leased','running') AND authorization_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'confirmation_expired', finished_at = %s, confirmation_token_hash = NULL WHERE status = 'awaiting_confirmation' AND confirmation_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET control_state = 'pending', control_lease_hash = NULL, control_lease_until = NULL WHERE status = 'awaiting_control' AND control_state = 'checking' AND control_lease_until <= %s",
		$now
	) );
	// Every check was spent (even if the last result never arrived): the job is blocked, not left waiting.
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'blocked', error_code = 'target_control_failed', finished_at = %s, control_state = 'none', control_token_hash = NULL, control_page_hash = NULL, control_lease_hash = NULL, control_lease_until = NULL WHERE status = 'awaiting_control' AND control_state = 'pending' AND control_attempts >= %d",
		$now,
		ct_scan_control_limits()['max_attempts']
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'queued', lease_hash = NULL, lease_until = NULL WHERE status = 'leased' AND lease_until <= %s AND attempts = 0",
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'failed_unknown', outcome = 'failed', error_code = 'lease_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL WHERE status = 'running' AND lease_until <= %s",
		$now,
		$now
	) );
	$queued = $wpdb->get_results( "SELECT job_id,request_id,target_origin,scope_hash,terms_version,terms_hash,terms_accepted_at,authorization_expires_at,contact_email,contact_name,referrer,revoked_at,report_delivered_at,summary_sha256,bound_required,profile_id,profile_sha256,services_json,status,control_required,control_verified_at,control_valid_until FROM {$table} WHERE status = 'queued'" );
	foreach ( (array) $queued as $row ) {
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => $now, 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		}
	}
	$nonce_table = ct_scan_nonces_table();
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$nonce_table} WHERE expires_at < %s", gmdate( 'Y-m-d H:i:s', time() - 600 ) ) );

}

/** Statuses from which a job never runs again; final request closure requires a separate trusted event. */
function ct_scan_terminal_statuses() {
	return array( 'completed', 'failed', 'failed_unknown', 'cancelled', 'expired', 'blocked' );
}

/** Does this job hold a lease for target traffic: a leased or running scan, or a control check being made? */
function ct_scan_job_holds_lease( $row ) {
	return in_array( $row->status, array( 'leased', 'running' ), true )
		|| ( 'awaiting_control' === $row->status && 'checking' === $row->control_state );
}

function ct_scan_terminal_sql() {
	return "'" . implode( "','", ct_scan_terminal_statuses() ) . "'";
}

/**
 * A stored UTC datetime we are willing to compute a deletion date from: the exact `Y-m-d H:i:s`
 * shape, a real calendar date, and not earlier than 2020 (zero dates, which PHP silently parses
 * into year -1, and other restore/migration debris are refused rather than guessed at).
 */
function ct_scan_valid_datetime( $value ) {
	if ( ! is_string( $value ) || ! preg_match( '/\A(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\z/', $value, $m ) || (int) $m[1] < 2020 || (int) $m[1] > 2200 ) {
		return false;
	}
	if ( ! checkdate( (int) $m[2], (int) $m[3], (int) $m[1] ) || (int) $m[4] > 23 || (int) $m[5] > 59 || (int) $m[6] > 59 ) {
		return false;
	}
	return true;
}

/**
 * A final close is trusted only when its source, actor, reason and UTC timestamp form one of the two
 * server-written events. Missing/null fields mean pending; terminal status and `finished_at` are not closure.
 */
function ct_scan_closure_metadata_trusted( $row ) {
	if ( ! is_object( $row ) ) {
		return false;
	}
	foreach ( array( 'status', 'created_at', 'terms_accepted_at', 'closed_at', 'closure_source', 'closed_by', 'closure_reason', 'report_delivered_at', 'report_access_used_at' ) as $field ) {
		if ( ! property_exists( $row, $field ) ) {
			return false;
		}
	}
	if ( ! in_array( $row->status, ct_scan_terminal_statuses(), true )
		|| ! ct_scan_valid_datetime( $row->created_at )
		|| ! ct_scan_valid_datetime( $row->terms_accepted_at )
		|| ! ct_scan_valid_datetime( $row->closed_at )
		|| $row->closed_at < $row->created_at
		|| $row->closed_at < $row->terms_accepted_at ) {
		return false;
	}
	$latest_trusted = gmdate( 'Y-m-d H:i:s', time() + ct_scan_clock_skew_limit_seconds() );
	if ( $row->closed_at > $latest_trusted ) {
		return false;
	}
	if ( ! is_string( $row->closure_reason ) || '' === $row->closure_reason ) {
		return false;
	}
	$actor_is_integer = is_int( $row->closed_by ) || ( is_string( $row->closed_by ) && ctype_digit( $row->closed_by ) );
	if ( ! $actor_is_integer ) {
		return false;
	}
	if ( 'report_delivery' === $row->closure_source ) {
		return 0 === (int) $row->closed_by
			&& '0' === (string) $row->closed_by
			&& 'report_delivered' === $row->closure_reason
			&& ct_scan_valid_datetime( $row->report_delivered_at )
			&& ct_scan_valid_datetime( $row->report_access_used_at )
			&& $row->report_access_used_at === $row->report_delivered_at
			&& $row->report_delivered_at === $row->closed_at;
	}
	if ( 'admin_final_close' === $row->closure_source ) {
		return (int) $row->closed_by > 0
			&& null === $row->report_delivered_at
			&& null === $row->report_access_used_at
			&& $row->closure_reason === $row->status;
	}
	return false;
}

/**
 * Findings presence is a SQL NULL question, never PHP truthiness: '0' and '' are stored values.
 * Missing columns or unexpected non-string data mean unknown and must preserve the complete row.
 * Returns true (present), false (both explicit SQL NULL), or null (unknown schema/value).
 */
function ct_scan_findings_presence( $row ) {
	if ( ! is_object( $row ) ) {
		return null;
	}
	foreach ( array( 'result_json', 'manual_remainder_notes' ) as $field ) {
		if ( ! property_exists( $row, $field ) || ( null !== $row->$field && ! is_string( $row->$field ) ) ) {
			return null;
		}
	}
	return null !== $row->result_json || null !== $row->manual_remainder_notes;
}

/** Shared prerequisites for ordinary and restored-row deletion; legacy policy never excuses backwards dates. */
function ct_scan_retention_dates_trusted( $row ) {
	if ( ! is_object( $row ) ) {
		return false;
	}
	foreach ( array( 'created_at', 'terms_accepted_at', 'closed_at', 'retain_until' ) as $field ) {
		if ( ! property_exists( $row, $field ) || ! ct_scan_valid_datetime( $row->$field ) ) {
			return false;
		}
	}
	return $row->closed_at >= $row->created_at && $row->closed_at >= $row->terms_accepted_at;
}

/**
 * Canonical mailbox confirmation is proof only within its original acceptance/creation window.
 * A prepared report may be retrieved after traffic authorization expires: the confirmation itself,
 * not the current retrieval time, must have occurred by that frozen authorization deadline.
 */
function ct_scan_confirmation_metadata_trusted( $row, $now = null ) {
	if ( ! is_object( $row ) ) {
		return false;
	}
	$now = null === $now ? ct_scan_utc_now() : $now;
	if ( ! ct_scan_valid_datetime( $now ) ) {
		return false;
	}
	foreach ( array( 'confirmed_at', 'created_at', 'terms_accepted_at', 'authorization_expires_at' ) as $field ) {
		if ( ! property_exists( $row, $field ) || ! ct_scan_valid_datetime( $row->$field ) ) {
			return false;
		}
	}
	return $row->confirmed_at >= $row->created_at && $row->confirmed_at >= $row->terms_accepted_at
		&& $row->confirmed_at <= $now && $row->confirmed_at <= $row->authorization_expires_at;
}

/** Findings and any served report remain until their trusted delivery or final-close timestamp plus 366 days. */
function ct_scan_findings_retain_until( $row ) {
	if ( ! ct_scan_closure_metadata_trusted( $row ) ) {
		return false;
	}
	$base = 'report_delivery' === $row->closure_source ? $row->report_delivered_at : $row->closed_at;
	try {
		return ( new DateTimeImmutable( $base, new DateTimeZone( 'UTC' ) ) )->modify( '+366 days' )->format( 'Y-m-d H:i:s' );
	} catch ( Throwable $error ) {
		return false;
	}
}

/** The longest retention period honoured, so every derived date stays a valid (pre-2200) date. */
function ct_scan_max_retention_years() {
	return 100;
}

/**
 * A retention period in whole years, never below its floor: 3 for r2-and-earlier acceptances, 6 for
 * everything else. A value that is not a plain positive number (a word, null, a boolean, an array, 0,
 * negative) means "the floor", never "shorter", and fractions round down but never below the floor.
 * A value above ct_scan_max_retention_years() (which would push the deletion date past 2200, where no
 * date is trusted and the record would be kept forever) is clamped to that maximum and logged once.
 */
function ct_scan_clamp_years( $years, $floor = 3 ) {
	static $warned = false;
	$floor = max( 3, (int) $floor );
	if ( ( ! is_int( $years ) && ! is_float( $years ) && ! ( is_string( $years ) && is_numeric( $years ) ) ) || ! is_finite( (float) $years ) ) {
		return $floor;
	}
	if ( (float) $years > ct_scan_max_retention_years() ) {
		if ( ! $warned ) {
			$warned = true;
			error_log( 'ct-scan: a configured retention period above ' . ct_scan_max_retention_years() . ' years was clamped to ' . ct_scan_max_retention_years() . ' years.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
		return max( $floor, ct_scan_max_retention_years() );
	}
	return max( $floor, (int) $years );
}


/**
 * When the signed authorization evidence of a job may be deleted: r2 and earlier acceptances three
 * years from acceptance; every other version six years after the request's closure (owner decision,
 * 2026-10-22). Returns false, and the job is then never deleted, if the base date is not trustworthy.
 * Month/year arithmetic that overflows (Feb 29) lands later, never earlier.
 */
function ct_scan_retain_until( $row ) {
	$config = ct_scan_config();
	if ( ct_scan_is_legacy_version( $row->terms_version ) ) {
		$years = ct_scan_clamp_years( $config['legacy_retention_years'], 3 );
		$base  = $row->terms_accepted_at;
	} else {
		if ( ! ct_scan_closure_metadata_trusted( $row ) ) {
			return false;
		}
		$years = ct_scan_clamp_years( $config['evidence_retention_years'], 6 );
		$base  = $row->closed_at;
	}
	if ( ! ct_scan_valid_datetime( $base ) ) {
		return false;
	}
	try {
		return ( new DateTimeImmutable( $base, new DateTimeZone( 'UTC' ) ) )->modify( '+' . $years . ' years' )->format( 'Y-m-d H:i:s' );
	} catch ( Throwable $error ) {
		return false;
	}
}

/** The grace period after a hold expires before its job becomes deletable (nothing vanishes the minute a hold lapses). */
function ct_scan_hold_grace_days() {
	return 3;
}

/** The complete nullable hold tuple; all destructive paths validate and compare the same state. */
function ct_scan_hold_fields() {
	return array( 'hold_reason', 'hold_until', 'hold_set_by', 'hold_set_at', 'hold_released_by', 'hold_released_at' );
}

/** A database actor id is positive and canonical; NULL/zero/coercible non-ids are not evidence. */
function ct_scan_positive_actor_id( $value ) {
	return ( is_int( $value ) && $value > 0 )
		|| ( is_string( $value ) && 1 === preg_match( '/\A[1-9]\d*\z/', $value ) && (string) (int) $value === $value && (int) $value > 0 );
}

/** Only a complete absent tuple or a trustworthy elapsed/released hold can permit cleanup. */
function ct_scan_job_on_hold( $row, $now ) {
	if ( ! is_object( $row ) || ! ct_scan_valid_datetime( $now ) ) {
		return true;
	}
	$all_null = true;
	foreach ( ct_scan_hold_fields() as $field ) {
		if ( ! property_exists( $row, $field ) ) {
			return true;
		}
		$all_null = $all_null && null === $row->$field;
	}
	if ( $all_null ) {
		return false;
	}
	// Any partial or contradictory tuple is a damaged hold, never an absent hold.
	if ( ! is_string( $row->hold_reason ) || '' === $row->hold_reason || '0' === $row->hold_reason
		|| trim( $row->hold_reason ) !== $row->hold_reason || preg_match( '/[\x00-\x1f\x7f]/', $row->hold_reason )
		|| ! ct_scan_valid_datetime( $row->hold_until ) || ! ct_scan_valid_datetime( $row->hold_set_at )
		|| ! ct_scan_positive_actor_id( $row->hold_set_by )
		|| $row->hold_set_at > $row->hold_until || $row->hold_set_at > $now ) {
		return true;
	}
	$release_absent = null === $row->hold_released_by && null === $row->hold_released_at;
	if ( ! $release_absent && ( ! ct_scan_positive_actor_id( $row->hold_released_by )
		|| ! ct_scan_valid_datetime( $row->hold_released_at ) || $row->hold_released_at < $row->hold_set_at
		|| $row->hold_released_at > $now || $row->hold_until > $row->hold_released_at ) ) {
		return true;
	}
	$grace_end = ( new DateTimeImmutable( $row->hold_until, new DateTimeZone( 'UTC' ) ) )->modify( '+' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	return $grace_end > $now;
}

/**
 * The earliest date this job's evidence may be deleted, judged from the row today: the period derived from
 * the row under today's configuration (so a longer period configured after closure is honoured), and never
 * less than three years after the record's creation. False if a base date cannot be trusted.
 *
 * A record is created within moments of the acceptance it records, so a derived date within a day of
 * "creation + 3 years" is accepted as it is. A derived date more than a day short of that (in practice: an
 * r2-or-earlier acceptance dated more than a day before its record was created, the stated acceptance date
 * and the plugin's own creation stamp disagreeing) is replaced by three full years from creation. That date
 * is later than the promised three years from acceptance, and it is a definite date rather than "never".
 */
function ct_scan_required_retain_until( $row ) {
	$derived = ct_scan_retain_until( $row );
	if ( false === $derived || ! ct_scan_valid_datetime( $row->created_at ) ) {
		return false;
	}
	try {
		$created = new DateTimeImmutable( $row->created_at, new DateTimeZone( 'UTC' ) );
		if ( $derived >= $created->modify( '+3 years -1 day' )->format( 'Y-m-d H:i:s' ) ) {
			return $derived;
		}
		return max( $derived, $created->modify( '+3 years' )->format( 'Y-m-d H:i:s' ) );
	} catch ( Throwable $error ) {
		return false;
	}
}

/**
 * What retention may do with this job now: array( 'keep' | 'extend' | 'delete', $date ). Every date involved
 * must be trustworthy, the job terminal and not held, or it is kept. A stored deletion date earlier than the
 * one required today (ct_scan_required_retain_until()) is never honoured: it is EXTENDED to the required date
 * ($date), and the job is deleted only when that later date arrives. A stored date is never shortened.
 */
function ct_scan_deletion_decision( $row, $now ) {
	if ( ! in_array( $row->status, ct_scan_terminal_statuses(), true ) || ct_scan_job_on_hold( $row, $now ) ) {
		return array( 'keep', null );
	}
	// A job without its opaque identity (not yet reached by the identity backfill) is kept until it has one:
	// deleting it would leave a tombstone that cannot recognise its restored request.
	if ( ! isset( $row->identity ) || ! is_string( $row->identity ) || '' === $row->identity ) {
		return array( 'keep', null );
	}
	if ( ! ct_scan_retention_dates_trusted( $row ) ) {
		return array( 'keep', null );
	}
	if ( ct_scan_is_legacy_version( $row->terms_version ) ) {
		if ( ! ct_scan_valid_datetime( $row->terms_accepted_at ) ) {
			return array( 'keep', null );
		}
	} elseif ( ! ct_scan_closure_metadata_trusted( $row ) ) {
		return array( 'keep', null );
	}
	$required = ct_scan_required_retain_until( $row );
	if ( false === $required ) {
		return array( 'keep', null );
	}
	$has_findings = ct_scan_findings_presence( $row );
	if ( null === $has_findings ) {
		return array( 'keep', null );
	}
	if ( $has_findings ) {
		$findings_until = ct_scan_findings_retain_until( $row );
		if ( false === $findings_until || $findings_until > $now ) {
			return array( 'keep', null );
		}
	}
	if ( $row->retain_until < $required ) {
		return array( 'extend', $required );
	}
	return array( $row->retain_until <= $now ? 'delete' : 'keep', null );
}

/** May this job's records be deleted now? Only when ct_scan_deletion_decision() says so; anything doubtful is kept. */
function ct_scan_deletion_allowed( $row, $now ) {
	return 'delete' === ct_scan_deletion_decision( $row, $now )[0];
}

/**
 * May the tombstone loop delete this job row (one that a tombstone recognises) now, as far as its retention
 * deadline is concerned? The loop cannot tell a row restored from a backup from a live row whose retention
 * deletion wrote its tombstone and then failed part-way, so it never deletes a row before the deadline that
 * retention itself would apply today: the later of the stored retain_until (never shortened) and the date
 * required under today's configuration (ct_scan_required_retain_until()). A longer period configured after a
 * failed deletion therefore protects that row exactly as it protects any other.
 *
 * When that date cannot be derived (no valid closure for a current-version acceptance, or a damaged
 * creation date), keep the row. A tombstone alone cannot establish a trustworthy current retention
 * deadline for a restored or damaged copy.
 */
function ct_scan_tombstone_deadline_passed( $row, $now ) {
	if ( ct_scan_job_on_hold( $row, $now ) || ! ct_scan_retention_dates_trusted( $row ) ) {
		return false;
	}
	$required = ct_scan_required_retain_until( $row );
	if ( false === $required ) {
		return false;
	}
	$deadline = $required;
	if ( isset( $row->retain_until ) && ct_scan_valid_datetime( $row->retain_until ) && $row->retain_until > $deadline ) {
		$deadline = $row->retain_until;
	}
	if ( $deadline > $now ) {
		return false;
	}
	$has_findings = ct_scan_findings_presence( $row );
	if ( null === $has_findings ) {
		return false;
	}
	if ( $has_findings ) {
		$findings_until = ct_scan_findings_retain_until( $row );
		if ( false === $findings_until || $findings_until > $now ) {
			return false;
		}
	}
	return true;
}

/**
 * Did the query just run fail? Retention never mistakes a failed query for "nothing to do" (or, worse, for
 * "no live record uses this id"): the caller stops that step and keeps the records. Logged once until a
 * retention run completes without a failed query.
 */
function ct_scan_retention_query_failed( $step ) {
	global $wpdb;
	if ( '' === (string) $wpdb->last_error ) {
		return false;
	}
	$GLOBALS['ct_scan_retention_query_failure'] = true;
	if ( ! get_option( 'ct_scan_retention_query_warned' ) ) {
		error_log( 'ct-scan: retention step "' . $step . '" stopped: a database query failed; the records are kept and the step is retried on a later run. Logged once until a run completes without a failed query.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		update_option( 'ct_scan_retention_query_warned', $step, false );
	}
	return true;
}

/**
 * A tombstone must not let anyone who reads it (a backup, a database export) test whether a given website
 * was ever a customer: the scope is stored as a keyed MAC, not as the plain hash of the hostname.
 */
function ct_scan_tombstone_mac( $scope_hash ) {
	return hash_hmac( 'sha256', (string) $scope_hash, wp_salt( 'secure_auth' ) . '|ct-scan-tombstone-v1' );
}

/** Remember a deleted record by identifier only, so a restored backup cannot bring it back. */
function ct_scan_record_tombstone( $row, $reason ) {
	global $wpdb;
	$result = $wpdb->query( $wpdb->prepare(
		'INSERT IGNORE INTO ' . ct_scan_tombstones_table() . ' (job_id, request_id, scope_mac, created_at, deleted_at, reason, identity) VALUES (%d, %d, %s, %s, %s, %s, %s)',
		(int) $row->job_id,
		(int) $row->request_id,
		ct_scan_tombstone_mac( $row->scope_hash ),
		$row->created_at,
		ct_scan_utc_now(),
		substr( sanitize_key( $reason ), 0, 32 ),
		is_string( $row->identity ) ? $row->identity : ''
	) );
	return false !== $result;
}

/**
 * Delete one job and its linked request, whatever status that post is in. True only if the job row is gone
 * and a tombstone exists.
 *
 * The request post is deleted only when it provably belongs to this job (post ids can be recycled after a
 * restore). For a retention deletion, a post that does not carry exactly the job's (non-empty) opaque
 * identity keeps everything (nothing is deleted; retried later). For a restored job row recognised by its tombstone
 * ($tombstone_identity given), the post is deleted only if it carries exactly that identity; otherwise the
 * post is another record and is left alone while the restored row itself is deleted again.
 */
function ct_scan_delete_job_records( $row, $reason, $tombstone_identity = null ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	clean_post_cache( (int) $row->request_id );
	$wpdb->last_error = '';
	$post = $wpdb->get_row( $wpdb->prepare( "SELECT ID, post_type FROM {$wpdb->posts} WHERE ID = %d LIMIT 1", (int) $row->request_id ) );
	if ( ct_scan_retention_query_failed( 'delete_post_read' ) ) {
		return false;
	}
	$ours = is_object( $post ) && 'ct_promo_request' === $post->post_type && (int) $post->ID === (int) $row->request_id;
	if ( $ours ) {
		$post_identity = ct_scan_meta_string( (int) $post->ID, '_ct_scan_identity' );
		if ( null !== $tombstone_identity ) {
			$ours = is_string( $tombstone_identity ) && '' !== $tombstone_identity && hash_equals( $tombstone_identity, $post_identity );
		} elseif ( ! is_string( $row->identity ) || '' === $row->identity || ! hash_equals( $row->identity, $post_identity ) ) {
			// Only an exact, non-empty identity match proves the post is this job's (an empty or different
			// identity may be a recycled id): keep everything and retry later.
			return false;
		}
	}
	if ( ! ct_scan_record_tombstone( $row, $reason ) ) {
		return false;
	}
	// Scrub personal fields first so a failure part-way never leaves contact data behind a deleted link.
	$personal_scrubbed = $wpdb->update( $table, array( 'contact_email' => '', 'contact_name' => '' ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s' ), array( '%d' ) );
	if ( false === $personal_scrubbed ) {
		return false;
	}
	if ( 0 === $personal_scrubbed ) {
		$scrubbed = $wpdb->get_row( $wpdb->prepare( "SELECT contact_email,contact_name FROM {$table} WHERE job_id = %d", (int) $row->job_id ) );
		if ( ! $scrubbed || '' !== $scrubbed->contact_email || '' !== $scrubbed->contact_name ) {
			return false;
		}
	}
	// The request carries the contact details and the full contract copy: delete it in any status
	// (a trashed or re-published copy must not outlive the job that pointed to it).
	if ( $ours ) {
		if ( ! wp_delete_post( (int) $row->request_id, true ) ) {
			return false;
		}
	}
	return false !== $wpdb->delete( $table, array( 'job_id' => (int) $row->job_id ), array( '%d' ) );
}

/**
 * Retention is NOT done under the queue lock. Only one retention run at a time (its own advisory lock);
 * the non-destructive steps are single statements; every deletion takes the queue lock for that one job
 * only (no waiting: a busy queue means "try again next run"), re-reads the row under it and re-checks
 * every condition, so Stop, claims and admissions are never delayed for more than one job's deletion
 * and a hold placed a moment ago is honoured.
 */
function ct_scan_retention_lock_name() {
	global $wpdb;
	return 'ctscanret_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 22 );
}

function ct_scan_retention_lock_acquire() {
	global $wpdb;
	return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', ct_scan_retention_lock_name() ) );
}

function ct_scan_retention_lock_release() {
	global $wpdb;
	$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', ct_scan_retention_lock_name() ) );
}

/** Run retention now (`$force`) or at most about once a minute. Returns true if a run happened. */
function ct_scan_retention_run( $force = false ) {
	if ( ! $force && get_transient( 'ct_scan_retention_last' ) ) {
		return false;
	}
	if ( ! ct_scan_retention_lock_acquire() ) {
		return false;
	}
	try {
		set_transient( 'ct_scan_retention_last', '1', 55 );
		ct_scan_retention_steps( ct_scan_utc_now() );
	} finally {
		ct_scan_retention_lock_release();
	}
	return true;
}

/** Retention from a request path (worker poll, admin page): a failure keeps the records and is logged, never propagated. */
function ct_scan_retention_run_safely() {
	try {
		return ct_scan_retention_run();
	} catch ( Throwable $error ) {
		error_log( 'ct-scan: a retention run failed (' . get_class( $error ) . '); records are kept and the run is retried later.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		return false;
	}
}

/** At most this many deletion attempts per retention run, shared by every deleting step. */
function ct_scan_retention_batch_limit() {
	return 50;
}

/** The largest disagreement tolerated between the PHP clock and the database clock before deletions stop. */
function ct_scan_clock_skew_limit_seconds() {
	return 300;
}

/**
 * Deletion is refused when the server clock looks wrong: if the PHP clock and the database clock disagree
 * by more than five minutes (one of them jumped, forwards or backwards), or if any job carries a (plausible)
 * timestamp later than "now" (a clock that jumped backwards, a bad restore). A forward jump of both clocks
 * together cannot be detected here.
 */
function ct_scan_clock_is_sane( $now ) {
	global $wpdb;
	$db_now = $wpdb->get_var( 'SELECT UTC_TIMESTAMP()' );
	if ( ! is_string( $db_now ) || ! ct_scan_valid_datetime( $db_now ) || abs( strtotime( $db_now . ' UTC' ) - time() ) > ct_scan_clock_skew_limit_seconds() ) {
		return false;
	}
	$table  = ct_scan_jobs_table();
	$limit  = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '+5 minutes' )->format( 'Y-m-d H:i:s' );
	foreach ( array( 'created_at', 'finished_at', 'closed_at', 'terms_accepted_at' ) as $column ) {
		$newest = $wpdb->get_var( "SELECT MAX({$column}) FROM {$table} WHERE {$column} < '2200-01-01 00:00:00'" );
		if ( ct_scan_retention_query_failed( 'clock' ) || ( is_string( $newest ) && $newest > $limit ) ) {
			return false;
		}
	}
	return $now >= '2020-01-01 00:00:00' && $now < '2200-01-01 00:00:00';
}

/** Log a clock that stops deletions once per occurrence (not on every run); forget it once the clock is sane again. */
function ct_scan_note_clock_state( $sane ) {
	$flag = 'ct_scan_retention_clock_warned';
	if ( ! $sane && ! get_option( $flag ) ) {
		error_log( 'ct-scan: retention deletions skipped: the server clock disagrees with the database clock or is earlier than a stored job timestamp. Logged once until the clock is consistent again.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		update_option( $flag, ct_scan_utc_now(), false );
	} elseif ( $sane && get_option( $flag ) ) {
		delete_option( $flag );
	}
}

/**
 * Act on one job if, under the queue lock and from a fresh read, retention may: delete it, or extend a
 * stored deletion date that is earlier than the one required today (compare-and-set, never shorter).
 * Returns 'deleted'|'extended'|'kept'|'failed'|'busy'.
 */
function ct_scan_delete_if_due( $job_id, $now ) {
	global $wpdb;
	if ( ! ct_scan_lock_acquire() ) {
		return 'busy';
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return 'kept';
		}
		list( $action, $until ) = ct_scan_deletion_decision( $row, $now );
		if ( 'extend' === $action ) {
			$updated = $wpdb->update( ct_scan_jobs_table(), array( 'retain_until' => $until, 'retention_checked_at' => null ), array( 'job_id' => (int) $row->job_id, 'retain_until' => $row->retain_until ), array( '%s', '%s' ), array( '%d', '%s' ) );
			return 1 === $updated ? 'extended' : 'kept';
		}
		if ( 'delete' !== $action ) {
			return 'kept';
		}
		return ct_scan_delete_job_records( $row, 'retention' ) ? 'deleted' : 'failed';
	} finally {
		ct_scan_lock_release();
	}
}

/** Clear due findings only from a freshly read, strictly trusted event under the queue lock. */
function ct_scan_purge_findings_if_due( $job_id, $now ) {
	global $wpdb;
	if ( ! ct_scan_valid_datetime( $now ) ) {
		return 'kept';
	}
	if ( ! ct_scan_lock_acquire() ) {
		return 'busy';
	}
	try {
		$wpdb->last_error = '';
		$row = ct_scan_row( $job_id );
		if ( ct_scan_retention_query_failed( 'findings_read' ) ) {
			return 'failed';
		}
		if ( ! is_object( $row ) || ! isset( $row->job_id ) || (int) $row->job_id < 1 || (int) $row->job_id !== (int) $job_id ) {
			return 'kept';
		}
		$fields = array_merge( array( 'status', 'created_at', 'terms_accepted_at', 'closed_at', 'closure_source', 'closed_by', 'closure_reason', 'report_delivered_at', 'report_access_used_at', 'result_json', 'manual_remainder_notes' ), ct_scan_hold_fields() );
		foreach ( $fields as $field ) {
			if ( ! property_exists( $row, $field ) ) {
				return 'kept';
			}
		}
		$until = ct_scan_findings_retain_until( $row );
		if ( false === $until || $until > $now || ct_scan_job_on_hold( $row, $now )
			|| true !== ct_scan_findings_presence( $row ) ) {
			return 'kept';
		}
		// The advisory lock serializes supported writers. Binary predicates additionally refuse an
		// intervening case-only mutation on normal case-insensitive WordPress table collations.
		$where = array( 'job_id = %d' );
		$values = array( (int) $row->job_id );
		foreach ( $fields as $field ) {
			if ( null === $row->$field ) {
				$where[] = $field . ' IS NULL';
			} else {
				$where[] = 'BINARY ' . $field . ' = BINARY %s';
				$values[] = (string) $row->$field;
			}
		}
		$wpdb->last_error = '';
		$changed = $wpdb->query( $wpdb->prepare(
			'UPDATE ' . ct_scan_jobs_table() . ' SET result_json = NULL, manual_remainder_notes = NULL WHERE ' . implode( ' AND ', $where ),
			...$values
		) );
		if ( ct_scan_retention_query_failed( 'findings_write' ) || false === $changed ) {
			return 'failed';
		}
		return 1 === $changed ? 'cleared' : 'kept';
	} finally {
		ct_scan_lock_release();
	}
}

/** Bounded cursor prevents malformed or not-yet-due findings rows starving later candidates. */
function ct_scan_purge_findings_batch( $now, $deadline ) {
	global $wpdb;
	$cursor = max( 0, (int) get_option( 'ct_scan_findings_cursor', 0 ) );
	$wpdb->last_error = '';
	$rows = $wpdb->get_results( $wpdb->prepare(
		'SELECT job_id FROM ' . ct_scan_jobs_table() . ' WHERE (result_json IS NOT NULL OR manual_remainder_notes IS NOT NULL) AND job_id > %d ORDER BY job_id ASC LIMIT 100',
		$cursor
	) );
	if ( ct_scan_retention_query_failed( 'findings_candidates' ) ) {
		return;
	}
	$finished = true;
	foreach ( (array) $rows as $row ) {
		if ( microtime( true ) > $deadline || 'busy' === ct_scan_purge_findings_if_due( (int) $row->job_id, $now ) ) {
			$finished = false;
			break;
		}
		$cursor = (int) $row->job_id;
	}
	update_option( 'ct_scan_findings_cursor', $finished && count( (array) $rows ) < 100 ? '0' : (string) $cursor, false );
}

function ct_scan_retention_steps( $now ) {
	global $wpdb;
	$table    = ct_scan_jobs_table();
	$terminal = ct_scan_terminal_sql();
	$deadline = microtime( true ) + 3.0;
	$GLOBALS['ct_scan_retention_query_failure'] = false;
	// 0. A job that can run again is not closed: forget any closure stamped on it. (Clears dates only: keeps data.)
	// If this fails, nothing below may run: a job that can run again could still carry an old deletion date.
	$wpdb->query( "UPDATE {$table} SET closed_at = NULL, retain_until = NULL WHERE status NOT IN ({$terminal}) AND (closed_at IS NOT NULL OR retain_until IS NOT NULL)" );
	if ( ct_scan_retention_query_failed( 'reopen' ) ) {
		return;
	}
	// Everything below stamps "now" or deletes. Refuse all of it if the clock cannot be trusted, so a wrong
	// clock's "now" is never stamped as a closure, a deletion date or an examination time.
	$sane = ct_scan_clock_is_sane( $now );
	ct_scan_note_clock_state( $sane );
	if ( ! $sane ) {
		return;
	}
	// 1. A terminal status records when scanner work stopped, not when the request was finally closed.
	// Only the authenticated admin-close action or a successful one-time report redemption may write
	// trusted closure metadata. Legacy `closed_at` values remain untrusted without that v8 evidence.
	// A row judged doubtful is re-examined at most daily, so doubtful rows can never starve the rest.
	$recheck = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-1 day' )->format( 'Y-m-d H:i:s' );
	// 1b. Jobs that predate the opaque identity get one (and so does their request) so a restored request
	// can be recognised after deletion. The request's identity is adopted or written only when that post
	// provably belongs to this job (its _ct_scan_job_id is this job's id); a request post that names another
	// job (a recycled id) is left alone, and so is the job, which then stays without identity and is kept.
	// Paged from a stored cursor (wrapping around) so such rows can never starve later ones.
	$identity_cursor = max( 0, (int) get_option( 'ct_scan_identity_cursor', 0 ) );
	$anonymous       = $wpdb->get_results( $wpdb->prepare( "SELECT job_id,request_id,identity FROM {$table} WHERE (identity IS NULL OR identity = '') AND job_id > %d ORDER BY job_id ASC LIMIT 100", $identity_cursor ) );
	$anonymous_failed = ct_scan_retention_query_failed( 'identity' );
	foreach ( $anonymous_failed ? array() : (array) $anonymous as $row ) {
		$identity_cursor = (int) $row->job_id;
		clean_post_cache( (int) $row->request_id );
		$post = get_post( (int) $row->request_id );
		if ( $post && 'ct_promo_request' === $post->post_type ) {
			if ( (string) (int) $row->job_id !== ct_scan_meta_string( (int) $row->request_id, '_ct_scan_job_id' ) ) {
				continue; // The post names another job (or none): touch neither; the job is kept.
			}
			// Adopt an identity the request already carries; otherwise mint one for both.
			$carried  = ct_scan_meta_string( (int) $row->request_id, '_ct_scan_identity' );
			$identity = 1 === preg_match( '/\A[a-f0-9]{32}\z/', $carried ) ? $carried : bin2hex( random_bytes( 16 ) );
			if ( 1 === $wpdb->update( $table, array( 'identity' => $identity ), array( 'job_id' => (int) $row->job_id, 'identity' => $row->identity ), array( '%s' ), array( '%d', '%s' ) ) && $identity !== $carried ) {
				update_post_meta( (int) $row->request_id, '_ct_scan_identity', $identity );
			}
		} else {
			// No request post of ours under that id: the job gets an identity of its own; no post is touched
			// (ct_scan_delete_job_records() never deletes a post that is not this job's request).
			$wpdb->update( $table, array( 'identity' => bin2hex( random_bytes( 16 ) ) ), array( 'job_id' => (int) $row->job_id, 'identity' => $row->identity ), array( '%s' ), array( '%d', '%s' ) );
		}
	}
	if ( ! $anonymous_failed ) {
		update_option( 'ct_scan_identity_cursor', count( (array) $anonymous ) < 100 ? '0' : (string) $identity_cursor, false );
	}
	// 2. The evidence deletion date is set at closure; later it may only be extended (step 4), never shortened.
	// An untrustworthy base leaves it NULL (kept).
	$unset = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE closed_at IS NOT NULL AND retain_until IS NULL AND (retention_checked_at IS NULL OR retention_checked_at < %s) ORDER BY job_id ASC LIMIT 200", $recheck ) );
	foreach ( ct_scan_retention_query_failed( 'retain_until' ) ? array() : (array) $unset as $row ) {
		$when = ct_scan_retain_until( $row );
		if ( false !== $when ) {
			$wpdb->update( $table, array( 'retain_until' => $when ), array( 'job_id' => (int) $row->job_id, 'retain_until' => null ), array( '%s' ), array( '%d', '%s' ) );
		} else {
			$wpdb->update( $table, array( 'retention_checked_at' => $now ), array( 'job_id' => (int) $row->job_id ), array( '%s' ), array( '%d' ) );
		}
	}
	// 3. Candidate selection only locates findings. The exact PHP trusted-event validator
	// decides under the queue lock, followed by a binary compare-and-set.
	ct_scan_purge_findings_batch( $now, $deadline );
	$grace_edge = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	// 4. Evidence: delete what has outlived its retain_until (extending a date that is shorter than today's
	// rules require), except under a hold. One budget of deletion attempts for the whole run (steps 4 and 5).
	$deletions_left = ct_scan_retention_batch_limit();
	$due = $wpdb->get_results( $wpdb->prepare(
		"SELECT job_id FROM {$table} WHERE retain_until IS NOT NULL AND retain_until <= %s AND closed_at IS NOT NULL AND status IN ({$terminal}) AND identity IS NOT NULL AND identity <> '' AND (hold_reason IS NULL OR (hold_until >= '2020-01-01 00:00:00' AND hold_until <= %s)) AND (retention_checked_at IS NULL OR retention_checked_at < %s) ORDER BY retain_until ASC LIMIT 50",
		$now,
		$grace_edge,
		$recheck
	) );
	foreach ( ct_scan_retention_query_failed( 'evidence' ) ? array() : (array) $due as $row ) {
		if ( $deletions_left < 1 || microtime( true ) > $deadline ) {
			break; // enough for one run: continue next time
		}
		$outcome = ct_scan_delete_if_due( (int) $row->job_id, $now );
		if ( 'busy' === $outcome ) {
			break; // the queue is in use: continue next time
		}
		if ( 'deleted' === $outcome || 'failed' === $outcome ) {
			--$deletions_left;
		}
		if ( 'kept' === $outcome || 'failed' === $outcome ) {
			// Doubtful or failed: keep it, and look at it again tomorrow rather than on every run.
			$wpdb->update( $table, array( 'retention_checked_at' => $now ), array( 'job_id' => (int) $row->job_id ), array( '%s' ), array( '%d' ) );
		}
	}
	// 5. A restored backup must not resurrect deleted records: delete matches again (same budget).
	ct_scan_apply_tombstones( $now, $deadline, $deletions_left );
	$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . ct_scan_tombstones_table() . ' WHERE deleted_at < %s', ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . max( 90, (int) ct_scan_config()['tombstone_retention_days'] ) . ' days' )->format( 'Y-m-d H:i:s' ) ) );
	ct_scan_retention_query_failed( 'tombstone_expiry' ); // a failure only keeps tombstones longer
	if ( empty( $GLOBALS['ct_scan_retention_query_failure'] ) && get_option( 'ct_scan_retention_query_warned' ) ) {
		delete_option( 'ct_scan_retention_query_warned' );
	}
}

/**
 * Delete again any job row (and linked request) that a deletion tombstone recognises after a restore.
 * A job row matches on its numeric identifiers AND creation time AND scope; its request post is deleted with
 * it only if the post carries the tombstone's opaque identity (a recycled post id is another record). A
 * request post whose job row was not restored matches only on the opaque identity recorded at creation, and
 * only when no job row currently uses that request or job id (recycled auto-increment ids must never reach a
 * live record). Holds are honoured. Every attempt counts against $deletions_left (shared with step 4).
 */
function ct_scan_apply_tombstones( $now, $deadline = null, &$deletions_left = null ) {
	global $wpdb;
	$table    = ct_scan_jobs_table();
	$stones   = ct_scan_tombstones_table();
	$deadline = null === $deadline ? microtime( true ) + 3.0 : $deadline;
	if ( null === $deletions_left ) {
		$deletions_left = ct_scan_retention_batch_limit();
	}
	// Candidates by numeric ids and creation time; the keyed scope MAC is compared in PHP, under the lock.
	// Rows that cannot be acted on now (held or in grace, holding a lease) are excluded in SQL. The rest are
	// paged by key from where the previous run stopped, wrapping around once, so rows that are skipped or
	// whose deletion keeps failing can never starve later restored rows.
	$grace_edge = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	// Tombstone IDs are globally unique. Persisting that cursor avoids resetting to id 0 when several
	// tombstones share one job_id and a run stops between pages.
	$cursor     = max( 0, (int) get_option( 'ct_scan_tombstone_id_cursor', 0 ) );
	$after_id   = $cursor;
	$upper      = PHP_INT_MAX;
	$wrapped    = 0 === $cursor;
	$finished   = false;
	// Part of the budget is left for the restored-post loop below, so restored job rows whose deletion keeps
	// failing can never starve it.
	$post_reserve = intdiv( max( 0, (int) $deletions_left ), 5 );
	for ( $page = 0; $page < 40 && ! $finished; $page++ ) {
		$ghosts = $wpdb->get_results( $wpdb->prepare(
			'SELECT j.job_id, t.tombstone_id, t.scope_mac, t.identity FROM ' . $table . ' j INNER JOIN ' . $stones . ' t ON t.job_id = j.job_id AND t.request_id = j.request_id AND t.created_at = j.created_at'
			. ' WHERE t.tombstone_id > %d AND t.tombstone_id <= %d'
			. " AND (j.hold_reason IS NULL OR (j.hold_until >= '2020-01-01 00:00:00' AND j.hold_until <= %s))"
			. " AND j.status NOT IN ('leased','running') AND NOT (j.status = 'awaiting_control' AND COALESCE(j.control_state, '') = 'checking')"
			. ' ORDER BY t.tombstone_id ASC LIMIT 50',
			$after_id,
			$upper,
			$grace_edge
		) );
		if ( ct_scan_retention_query_failed( 'tombstone_rows' ) ) {
			break; // never "no candidates": stop here and continue from the stored cursor next run
		}
		if ( empty( $ghosts ) ) {
			if ( $wrapped ) {
				$finished = true;
				break;
			}
			// Reached the end: start again from the beginning, up to where this run started.
			$wrapped  = true;
			$after_id = 0;
			$upper    = $cursor;
			continue;
		}
		foreach ( (array) $ghosts as $ghost ) {
			if ( $deletions_left <= $post_reserve ) {
				// This loop's share of the budget is spent: the next run continues from here.
				break 2;
			}
			if ( microtime( true ) > $deadline || ! ct_scan_lock_acquire() ) {
				// Out of time, or the queue is busy: the next run continues from here.
				update_option( 'ct_scan_tombstone_id_cursor', (string) $after_id, false );
				return;
			}
			$after_id  = (int) $ghost->tombstone_id;
			try {
				$row = ct_scan_row( (int) $ghost->job_id );
				// A restored row that holds a live lease (a scan, or a control check in progress) is left until the
				// lease ends (bounded; maintenance reclaims it): deleting it would free the one-at-a-time gate while
				// target traffic for it may still be in flight. Re-checked here under the lock.
				// The row is also kept until the retention deadline that applies to it today has passed: a live row
				// whose retention deletion wrote this tombstone and then failed part-way looks exactly like a restored
				// one, and a period raised since must protect it (ct_scan_tombstone_deadline_passed()).
				if ( $row && hash_equals( (string) $ghost->scope_mac, ct_scan_tombstone_mac( $row->scope_hash ) ) && ! ct_scan_job_on_hold( $row, $now ) && ! ct_scan_job_holds_lease( $row ) && ct_scan_tombstone_deadline_passed( $row, $now ) ) {
					--$deletions_left;
					// A failure leaves the row (and is retried next run); it never stops the other candidates.
					ct_scan_delete_job_records( $row, 'restored', (string) $ghost->identity );
				}
			} finally {
				ct_scan_lock_release();
			}
		}
	}
	update_option( 'ct_scan_tombstone_id_cursor', $finished ? '0' : (string) $after_id, false );
	// A restored request post whose job row was not restored: matched in SQL on the opaque identity
	// (never on recyclable numeric ids alone) AND on the job id the post names, and only where no job row
	// currently uses that request or job id, so a live record can never be reached. Re-checked under the
	// lock before each deletion. Paged by tombstone id from where the previous run stopped, wrapping around
	// once, so posts whose deletion is refused (a filter, the database) can never starve later ones.
	$postmeta     = $wpdb->postmeta;
	$post_cursor  = max( 0, (int) get_option( 'ct_scan_restored_post_cursor', 0 ) );
	$after_stone  = $post_cursor;
	$upper_stone  = PHP_INT_MAX;
	$post_wrapped = 0 === $post_cursor;
	$post_done    = false;
	for ( $page = 0; $page < 40 && ! $post_done; $page++ ) {
		$restored = $wpdb->get_results( $wpdb->prepare(
			'SELECT t.tombstone_id, t.job_id, t.request_id, t.identity FROM ' . $stones . ' t'
			. ' INNER JOIN ' . $wpdb->posts . " p ON p.ID = t.request_id AND p.post_type = 'ct_promo_request'"
			. ' INNER JOIN ' . $postmeta . " m ON m.post_id = t.request_id AND m.meta_key = '_ct_scan_identity' AND CAST(m.meta_value AS BINARY) = CAST(t.identity AS BINARY)"
			. ' INNER JOIN ' . $postmeta . " k ON k.post_id = t.request_id AND k.meta_key = '_ct_scan_job_id' AND CAST(k.meta_value AS BINARY) = CAST(t.job_id AS BINARY)"
			. " WHERE t.identity IS NOT NULL AND t.identity <> '' AND t.tombstone_id > %d AND t.tombstone_id <= %d"
			. ' AND NOT EXISTS (SELECT 1 FROM ' . $table . ' j WHERE j.request_id = t.request_id OR j.job_id = t.job_id)'
			. ' GROUP BY t.tombstone_id, t.job_id, t.request_id, t.identity ORDER BY t.tombstone_id ASC LIMIT 50',
			$after_stone,
			$upper_stone
		) );
		if ( ct_scan_retention_query_failed( 'tombstone_posts' ) ) {
			break; // never "no candidates": stop here and continue from the stored cursor next run
		}
		if ( empty( $restored ) ) {
			if ( $post_wrapped ) {
				$post_done = true;
				break;
			}
			// Reached the end: start again from the beginning, up to where this run started.
			$post_wrapped = true;
			$after_stone  = 0;
			$upper_stone  = $post_cursor;
			continue;
		}
		foreach ( (array) $restored as $stone ) {
			if ( $deletions_left < 1 || microtime( true ) > $deadline || ! ct_scan_lock_acquire() ) {
				// Out of budget or time, or the queue is busy: the next run continues from here.
				update_option( 'ct_scan_restored_post_cursor', (string) $after_stone, false );
				return;
			}
			$after_stone = (int) $stone->tombstone_id;
			try {
				$live = $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$table} WHERE request_id = %d OR job_id = %d LIMIT 1", (int) $stone->request_id, (int) $stone->job_id ) );
				if ( ct_scan_retention_query_failed( 'tombstone_posts' ) ) {
					// A failed lookup is not "no live record": keep the post and stop; the next run retries from here.
					update_option( 'ct_scan_restored_post_cursor', (string) max( 0, $after_stone - 1 ), false );
					return;
				}
				clean_post_cache( (int) $stone->request_id );
				if ( ! $live && hash_equals( (string) $stone->identity, ct_scan_meta_string( (int) $stone->request_id, '_ct_scan_identity' ) ) && (string) $stone->job_id === ct_scan_meta_string( (int) $stone->request_id, '_ct_scan_job_id' ) ) {
					--$deletions_left;
					if ( ! wp_delete_post( (int) $stone->request_id, true ) ) {
						// Refused (a filter or the database): the post is kept and retried on a later pass. This
						// attempt has been counted and the cursor moves on, so one stuck post can neither spin nor
						// block the rest.
						clean_post_cache( (int) $stone->request_id );
					}
				}
			} finally {
				ct_scan_lock_release();
			}
		}
	}
	update_option( 'ct_scan_restored_post_cursor', $post_done ? '0' : (string) $after_stone, false );
}

/**
 * Place a preservation hold. A hold that still protects the job (unexpired, or inside its grace period) and
 * has not been released is never replaced: a second "place hold" (a stale tab, two administrators, a direct
 * POST) is refused with 'hold_active', so it can neither move the expiry earlier nor erase the stated purpose
 * and who set it. To change a standing hold, release it first (the job stays protected through the grace
 * period), then place the new one. A released hold in its grace period may be replaced, but never by a hold
 * that ends earlier. The write is a compare-and-set on the hold values read under the queue lock.
 */
function ct_scan_admin_set_hold( $job_id, $reason, $days ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'hold_forbidden', 'Only an administrator can place a hold.' );
	}
	$reason = is_string( $reason ) ? trim( wp_strip_all_tags( $reason ) ) : '';
	$days   = is_numeric( $days ) ? (int) $days : 0;
	if ( strlen( $reason ) < 20 || strlen( $reason ) > 190 || $days < 1 || $days > 730 ) {
		return new WP_Error( 'hold_invalid', 'State the purpose (20 to 190 characters) and a duration of 1 to 730 days.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return new WP_Error( 'hold_unavailable', 'This job no longer exists.' );
		}
		$now   = ct_scan_utc_now();
		$until = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '+' . $days . ' days' )->format( 'Y-m-d H:i:s' );
		if ( ct_scan_job_on_hold( $row, $now ) && ( empty( $row->hold_released_at ) || ! ct_scan_valid_datetime( $row->hold_until ) || $row->hold_until > $until ) ) {
			return new WP_Error( 'hold_active', 'This job already has a preservation hold; it was not changed. Release it first to place a different one.' );
		}
		$updated = $wpdb->update(
			ct_scan_jobs_table(),
			array( 'hold_reason' => $reason, 'hold_until' => $until, 'hold_set_by' => (int) $user->ID, 'hold_set_at' => $now, 'hold_released_by' => null, 'hold_released_at' => null ),
			array( 'job_id' => (int) $row->job_id, 'hold_reason' => $row->hold_reason, 'hold_until' => $row->hold_until, 'hold_released_at' => $row->hold_released_at ),
			array( '%s', '%s', '%d', '%s', '%d', '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( false === $updated ) {
			return new WP_Error( 'hold_write_failed', 'The hold could not be recorded.' );
		}
		if ( 1 !== $updated ) {
			return new WP_Error( 'hold_changed', 'The hold changed while this request was handled; reload the queue and try again.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

/**
 * The identity of one specific hold (its purpose, expiry, setter and when it was set), carried by the
 * "Release hold" form, so a release can only ever end the hold the administrator was looking at.
 */
function ct_scan_hold_identity( $row ) {
	return hash( 'sha256', implode( "\n", array( 'ct-scan-hold-v1', (string) $row->job_id, (string) $row->hold_reason, (string) $row->hold_until, (string) $row->hold_set_at, (string) $row->hold_set_by ) ) );
}

/**
 * Release the hold identified by $expected_hold (ct_scan_hold_identity() of the hold shown to the
 * administrator). A stale form (the hold was released and a different one placed since, by another
 * administrator or in another tab) is refused with 'hold_changed' and changes nothing. The write is a
 * compare-and-set on the hold's values as read under the queue lock.
 */
function ct_scan_admin_release_hold( $job_id, $expected_hold = '' ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'hold_forbidden', 'Only an administrator can release a hold.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->hold_reason ) || ! empty( $row->hold_released_at ) ) {
			return new WP_Error( 'hold_unavailable', 'This job has no hold to release.' );
		}
		if ( ! is_string( $expected_hold ) || 1 !== preg_match( '/\A[a-f0-9]{64}\z/', $expected_hold ) || ! hash_equals( ct_scan_hold_identity( $row ), $expected_hold ) ) {
			return new WP_Error( 'hold_changed', 'The hold changed since the queue was loaded; it was not released.' );
		}
		// Releasing ends the hold now, it does not erase it: the purpose stays (with who released it and
		// when), and the job keeps the same three-day grace as a hold that expires. A hold that already
		// expired keeps its own (earlier) end, so a release never lengthens it.
		$now     = ct_scan_utc_now();
		$until   = ( ct_scan_valid_datetime( $row->hold_until ) && $row->hold_until < $now ) ? $row->hold_until : $now;
		$updated = $wpdb->update(
			ct_scan_jobs_table(),
			array( 'hold_until' => $until, 'hold_released_by' => (int) $user->ID, 'hold_released_at' => $now ),
			array( 'job_id' => (int) $row->job_id, 'hold_reason' => $row->hold_reason, 'hold_until' => $row->hold_until, 'hold_set_at' => $row->hold_set_at, 'hold_set_by' => $row->hold_set_by, 'hold_released_at' => null ),
			array( '%s', '%d', '%s' ),
			array( '%d', '%s', '%s', '%s', '%d', '%s' )
		);
		if ( false === $updated ) {
			return new WP_Error( 'hold_write_failed', 'The hold could not be released.' );
		}
		if ( 1 !== $updated ) {
			return new WP_Error( 'hold_changed', 'The hold changed since the queue was loaded; it was not released.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_maintain() {
	if ( ! ct_scan_lock_acquire() ) {
		return false;
	}
	try {
		ct_scan_maintenance_locked();
	} finally {
		ct_scan_lock_release();
	}
	// Retention runs after the queue lock is released (see ct_scan_retention_run()); a failure there never
	// breaks the admin page.
	ct_scan_retention_run_safely();
	return true;
}

function ct_scan_confirmation_token_from_request( $source ) {
	if ( ! isset( $source['token'] ) || ! is_string( $source['token'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['token'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_confirmation_markup( $job_id, $token, $nonce, $target, $terms_version, $accepted_at ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	$accepted_label = esc_html( str_replace( ' ', 'T', $accepted_at ) . 'Z (UTC)' );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirm website screening</title><body><main><h1>Confirm your website screening</h1><p>Confirm one passive check of this exact website origin:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>Terms version accepted: <strong>' . esc_html( $terms_version ) . '</strong><br>Acceptance recorded: <strong>' . $accepted_label . '</strong></p><p>Opening this page alone does not authorize a scan. This confirms control of the request email address; it does not independently prove domain ownership.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_confirm"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="token" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Confirm one passive screening</button></form></main></body></html>';
}

function ct_scan_send_confirmation_page( $message, $status = 200, $markup = '' ) {
	nocache_headers();
	status_header( $status );
	header( 'Content-Type: text/html; charset=UTF-8' );
	header( 'Referrer-Policy: no-referrer' );
	header( 'X-Content-Type-Options: nosniff' );
	header( "Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'" );
	if ( '' === $markup ) {
		$markup = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Website screening</title><body><main><h1>Website screening</h1><p>' . esc_html( $message ) . '</p></main></body></html>';
	}
	echo $markup; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- markup is assembled from escaped fields above.
	exit;
}

/**
 * The state change behind the confirmation POST (the caller has verified the form and nonce).
 * Returns array( message, http status, optional page markup ).
 */
function ct_scan_confirm_job( $job_id, $token ) {
	if ( ! ct_scan_lock_acquire() ) {
		return array( 'The request is temporarily busy. Please try again.', 503, '' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	$message = 'This confirmation link is invalid or expired.';
	$response_status = 410;
	$control_markup = '';
	try {
		$row = ct_scan_row( $job_id );
		if ( $row && 'awaiting_confirmation' === $row->status && ! empty( $row->confirmation_token_hash )
			&& hash_equals( $row->confirmation_token_hash, hash( 'sha256', $token ) )
			&& strtotime( $row->confirmation_expires_at . ' UTC' ) > time() && ct_scan_authorization_is_live( $row ) ) {
			// Mailbox control is not control of the website: a job that requires target control waits
			// for it. The challenge token is shown once; only its hash is stored.
			$needs_control = ct_scan_control_required( $row );
			// Two independent secrets: the challenge value (published by design, so world-readable) and
			// the page capability that lets the holder request checks (never published).
			$control_page  = $needs_control ? bin2hex( random_bytes( 32 ) ) : '';
			$control_token = $needs_control ? ct_scan_control_challenge( $row, $control_page ) : '';
			$fields        = array( 'status' => $needs_control ? 'awaiting_control' : 'queued', 'confirmed_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null, 'confirmation_expires_at' => null );
			if ( $needs_control ) {
				$fields['control_token_hash'] = hash( 'sha256', $control_token );
				$fields['control_page_hash']  = hash( 'sha256', $control_page );
				$fields['control_state']      = 'pending';
			}
			$updated = $wpdb->update(
				$table,
				$fields,
				array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_token_hash' => $row->confirmation_token_hash ),
				array_fill( 0, count( $fields ), '%s' ),
				array( '%d', '%s', '%s' )
			);
			if ( 1 === $updated ) {
				if ( $needs_control ) {
					ct_scan_mark_request_status( (int) $row->request_id, 'awaiting_control' );
					$control_markup = ct_scan_control_markup( $row, $control_page, '', 0 );
					$message = 'Your email is confirmed. No screening will run until control of the website is shown.';
				} else {
					ct_scan_mark_request_status( (int) $row->request_id, 'queued' );
					$message = 'Your screening is confirmed and queued. It will run once, within the authorization window.';
				}
				$response_status = 200;
			}
		}
	} finally {
		ct_scan_lock_release();
	}
	if ( 200 === $response_status ) {
		try {
			ct_scan_send_accepted_copy( $job_id );
		} catch ( Throwable $error ) {
			// The copy is independent of the confirmed, queued job.
			unset( $error );
		}
	}
	return array( $message, $response_status, $control_markup );
}

function ct_scan_confirmation_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_confirmation_token_from_request( $_GET );
		if ( '' === $token ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 404 );
		}
		$row = ct_scan_row_by_confirmation_hash( hash( 'sha256', $token ) );
		if ( ! $row || 'awaiting_confirmation' !== $row->status || strtotime( $row->confirmation_expires_at . ' UTC' ) <= time()
			|| ! ct_scan_authorization_is_live( $row ) ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 410 );
		}
		$nonce = wp_create_nonce( 'ct_scan_confirm_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_confirmation_markup( (int) $row->job_id, $token, $nonce, $row->target_origin, $row->terms_version, $row->terms_accepted_at ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the confirmation form to continue.', 405 );
	}
	$token  = ct_scan_confirmation_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_confirm_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This confirmation form is invalid or expired.', 403 );
	}
	list( $message, $response_status, $markup ) = ct_scan_confirm_job( $job_id, $token );
	ct_scan_send_confirmation_page( $message, $response_status, $markup );
}

/**
 * Send the verified contact a retainable copy of what they accepted. Runs after mailbox
 * confirmation, independently of scanning: a failure here never cancels, delays or repeats a
 * scan, and a send is attempted at most once per job (the status is claimed with a
 * compare-and-set before mail is handed off, and an uncertain outcome is never resent).
 * Transport acceptance is not receipt. Off unless config `send_accepted_copy` is true.
 * TODO(owner): review the wording of this message before enabling.
 * Returns 'disabled', 'sent', 'unknown', 'already_handled', or a WP_Error.
 */
function ct_scan_send_accepted_copy( $job_id ) {
	global $wpdb;
	if ( ! ct_scan_enabled() || empty( ct_scan_config()['send_accepted_copy'] ) ) {
		return 'disabled';
	}
	$table = ct_scan_jobs_table();
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		// Same recipient rule as the report path: confirmed, and still the address the signer authorized.
		if ( ! $row || ! ct_scan_confirmation_metadata_trusted( $row ) || ! is_email( $row->contact_email )
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_email' ) !== $row->contact_email
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_version' ) !== $row->terms_version
			|| strtolower( ct_scan_meta_string( (int) $row->request_id, '_ct_terms_sha256' ) ) !== $row->terms_hash ) {
			return new WP_Error( 'accepted_copy_unavailable', 'The accepted copy requires the confirmed, authorized recipient.' );
		}
		// Re-checked under the queue lock right before the claim: a job that was cancelled, stopped,
		// expired or whose evidence changed since confirmation gets no copy. A confirmed job waiting for
		// proof of target control is live (confirmation sends the copy then); control gates the scan, not the copy.
		if ( ! in_array( $row->status, array( 'awaiting_control', 'queued', 'leased', 'running' ), true ) || ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'accepted_copy_unavailable', 'The accepted copy requires a live authorization.' );
		}
		$claimed = $wpdb->update(
			$table,
			array( 'accepted_copy_status' => 'unknown', 'accepted_copy_at' => ct_scan_utc_now() ),
			array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'not_sent', 'confirmed_at' => $row->confirmed_at, 'created_at' => $row->created_at, 'terms_accepted_at' => $row->terms_accepted_at, 'authorization_expires_at' => $row->authorization_expires_at ),
			array( '%s', '%s' ),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);
		if ( 1 !== $claimed ) {
			return 'already_handled';
		}
	} finally {
		ct_scan_lock_release();
	}
	$request_id = (int) $row->request_id;
	$contract   = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$snapshot   = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary    = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	$bound      = '1' === ct_scan_meta_string( $request_id, '_ct_terms_binding' ) && $row->summary_sha256 === hash( 'sha256', $summary ) && hash( 'sha256', $snapshot ) === $row->terms_hash;
	$lines = array(
		'This is the copy of the free PHP2Shell screening agreement and scope that you accepted. Please keep it for your records.',
		'',
		'Website (scan scope): ' . $row->target_origin,
		'Terms version: ' . $row->terms_version,
		'Terms SHA-256: ' . $row->terms_hash,
		'Accepted (UTC): ' . $row->terms_accepted_at,
		'Mailbox confirmed (UTC): ' . $row->confirmed_at,
		'Authorization expires (UTC): ' . $row->authorization_expires_at,
	);
	$attachments = array();
	$tempdir     = '';
	if ( $bound ) {
		$lines[] = 'Target Summary SHA-256: ' . $row->summary_sha256;
		$lines[] = '';
		$lines[] = 'Target Summary as shown to you:';
		$lines[] = $summary;
		// A private, randomly named directory: the attachment is never at a predictable path.
		$candidate = rtrim( sys_get_temp_dir(), '/\\' ) . '/ctat-' . bin2hex( random_bytes( 12 ) );
		if ( @mkdir( $candidate, 0700 ) ) {
			$tempdir = $candidate;
			$path    = $tempdir . '/accepted-terms-' . (int) $row->job_id . '-' . preg_replace( '/[^A-Za-z0-9._-]/', '', $row->terms_version ) . '-' . substr( $row->terms_hash, 0, 12 ) . '.html';
			$written = @file_put_contents( $path, $snapshot );
			// Attach only bytes that reproduce the recorded hash.
			if ( strlen( $snapshot ) === $written && hash_file( 'sha256', $path ) === $row->terms_hash ) {
				$attachments[] = $path;
				$lines[]       = 'The attached file contains the exact terms text you were shown; its SHA-256 is the value above.';
			}
		}
	}
	$lines[] = '';
	$lines[] = $contract;
	$status  = 'unknown';
	try {
		$sent   = wp_mail( $row->contact_email, 'Your accepted PHP2Shell screening agreement', implode( "\n", $lines ), '', $attachments );
		$status = $sent ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$status = 'unknown';
	}
	if ( '' !== $tempdir ) {
		foreach ( (array) glob( $tempdir . '/*' ) as $leftover ) {
			@unlink( $leftover );
		}
		@rmdir( $tempdir );
	}
	$wpdb->update( $table, array( 'accepted_copy_status' => $status ), array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	return 'accepted' === $status ? 'sent' : 'unknown';
}

function ct_scan_row_by_confirmation_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE confirmation_token_hash = %s LIMIT 1", $hash ) );
}
add_action( 'admin_post_nopriv_ct_scan_confirm', 'ct_scan_confirmation_handler' );
add_action( 'admin_post_ct_scan_confirm', 'ct_scan_confirmation_handler' );


/**
 * Exact-target control. Mailbox confirmation shows control of an email address, not of the website.
 * For jobs frozen with control_required the customer proves control of the exact hostname by
 * publishing the challenge as a DNS TXT record at `_ct-scan-challenge.<host>` (value
 * `ct-scan-verify=<token>`) or serving it at `https://<host>/.well-known/ct-scan-challenge.txt`, then
 * asks for a check. At most three checks, one minute apart, each one TXT lookup or one HTTPS request
 * (fixed path, no redirects, 4 KiB, 10 s). A recorded manual authority review can stand in. A failed
 * challenge never falls back to a scan: after three failures the job is `blocked`.
 * TODO(owner): the wording of these customer-facing pages is functional only.
 */
/**
 * The challenge value shown to the customer. It is derived from the page capability with a keyed
 * hash, so the page can show it again without storing it, while someone who reads the published
 * challenge learns nothing that lets them open the page and use up the checks.
 */
function ct_scan_control_challenge( $row, $page_token ) {
	return hash_hmac( 'sha256', 'ct-scan-challenge-v1|' . (int) $row->job_id . '|' . $row->scope_hash, $page_token );
}

function ct_scan_control_markup( $row, $page_token, $notice, $attempts_used ) {
	$limits    = ct_scan_control_limits();
	$host      = (string) wp_parse_url( $row->target_origin, PHP_URL_HOST );
	$challenge = ct_scan_control_challenge( $row, $page_token );
	$action    = esc_url( admin_url( 'admin-post.php' ) );
	$nonce     = wp_create_nonce( 'ct_scan_control_' . (int) $row->job_id . '_' . $page_token );
	$link      = esc_url( add_query_arg( array( 'action' => 'ct_scan_control', 'job' => (int) $row->job_id, 'ctl' => $page_token ), admin_url( 'admin-post.php' ) ) );
	$html  = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Show control of your website</title><body><main><h1>Show control of your website</h1>';
	if ( '' !== $notice ) {
		$html .= '<p><strong>' . esc_html( $notice ) . '</strong></p>';
	}
	$html .= '<p>No screening runs until control of <strong>' . esc_html( $host ) . '</strong> is shown. Publish ONE of the following, then press Check.</p>';
	$html .= '<p>DNS TXT record at <code>' . esc_html( $limits['dns_label'] . '.' . $host ) . '</code> with the value:<br><code>' . esc_html( $limits['dns_prefix'] . $challenge ) . '</code><br><small>The TXT record must be at that exact name: a CNAME there is not followed. Wait until the record is visible in public DNS before checking; a check made too early can be answered from a cached "no record" and still uses one of your checks.</small></p>';
	$html .= '<p>or the file <code>https://' . esc_html( $host . $limits['path'] ) . '</code> whose entire content is:<br><code>' . esc_html( $challenge ) . '</code></p>';
	$html .= '<p>Keep this page\'s address private: it is the only way to return here and to request checks. Checks used: ' . (int) $attempts_used . ' of ' . (int) $limits['max_attempts'] . '; at least one minute apart.</p>';
	$html .= '<form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_control"><input type="hidden" name="job" value="' . esc_attr( (string) (int) $row->job_id ) . '"><input type="hidden" name="ctl" value="' . esc_attr( $page_token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '">';
	$html .= '<label><input type="radio" name="method" value="dns_txt" checked> I published the DNS record</label><br><label><input type="radio" name="method" value="https_file"> I published the file</label><br><button type="submit">Check now</button></form>';
	$html .= '<p><small>Return address: ' . $link . '</small></p></main></body></html>';
	return $html;
}

function ct_scan_control_token_from_request( $source ) {
	if ( ! isset( $source['ctl'] ) || ! is_string( $source['ctl'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['ctl'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

/** Schedule one control check for the customer's chosen method, under the disclosed limits. */
function ct_scan_request_control_check( $job_id, $token, $method ) {
	global $wpdb;
	$limits = ct_scan_control_limits();
	if ( ! in_array( $method, array( 'dns_txt', 'https_file' ), true ) ) {
		return new WP_Error( 'control_method_invalid', 'Choose the DNS record or the file.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The request is temporarily busy. Please try again.' );
	}
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_page_hash ) || ! hash_equals( $row->control_page_hash, hash( 'sha256', $token ) )
			|| ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'control_link_invalid', 'This link is invalid or expired.' );
		}
		if ( 'pending' !== $row->control_state ) {
			return new WP_Error( 'control_check_in_progress', 'A check is already scheduled or running.' );
		}
		$now_ms = (int) floor( microtime( true ) * 1000 );
		if ( (int) $row->control_attempts >= $limits['max_attempts'] ) {
			return new WP_Error( 'control_attempts_exhausted', 'All checks were used.' );
		}
		if ( null !== $row->control_last_attempt_ms && $now_ms < (int) $row->control_last_attempt_ms + $limits['min_interval_ms'] ) {
			return new WP_Error( 'control_too_soon', 'Wait at least one minute between checks.' );
		}
		$updated = $wpdb->update(
			$table,
			array( 'control_state' => 'requested', 'control_requested_method' => $method ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'pending', 'control_attempts' => (int) $row->control_attempts ),
			array( '%s', '%s' ),
			array( '%d', '%s', '%s', '%d' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'control_write_failed', 'The check could not be scheduled. Please try again.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return 'scheduled';
}

function ct_scan_control_handler() {
	$method_http = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	$source      = 'POST' === $method_http ? $_POST : $_GET;
	$token       = ct_scan_control_token_from_request( $source );
	$job_id      = isset( $source['job'] ) && is_scalar( $source['job'] ) ? absint( wp_unslash( $source['job'] ) ) : 0;
	if ( ! in_array( $method_http, array( 'GET', 'POST' ), true ) ) {
		ct_scan_send_confirmation_page( 'Use the link you were given.', 405 );
	}
	if ( ! $job_id || '' === $token ) {
		ct_scan_send_confirmation_page( 'This link is invalid or expired.', 404 );
	}
	$row = ct_scan_row( $job_id );
	if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_page_hash ) || ! hash_equals( $row->control_page_hash, hash( 'sha256', $token ) ) || ! ct_scan_authorization_is_live( $row ) ) {
		ct_scan_send_confirmation_page( 'This link is invalid or expired.', 410 );
	}
	if ( 'GET' === $method_http ) {
		ct_scan_send_confirmation_page( '', 200, ct_scan_control_markup( $row, $token, '', (int) $row->control_attempts ) );
	}
	if ( ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] ) || ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_control_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This form is invalid or expired. Open the link again.', 403 );
	}
	$choice = isset( $_POST['method'] ) && is_string( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';
	$result = ct_scan_request_control_check( $job_id, $token, $choice );
	$notice = array(
		'scheduled'                 => 'Check scheduled. It runs within a minute; return to this page to see the outcome.',
		'control_check_in_progress' => 'A check is already scheduled or running.',
		'control_too_soon'          => 'Wait at least one minute between checks.',
		'control_attempts_exhausted' => 'All checks were used.',
		'control_method_invalid'    => 'Choose the DNS record or the file.',
		'queue_busy'                => 'The request is temporarily busy. Please try again.',
	);
	$key     = is_wp_error( $result ) ? $result->get_error_code() : $result;
	$current = ct_scan_row( $job_id );
	$current = $current ? $current : $row;
	ct_scan_send_confirmation_page( '', 200, ct_scan_control_markup( $current, $token, isset( $notice[ $key ] ) ? $notice[ $key ] : 'The check could not be scheduled.', (int) $current->control_attempts ) );
}
add_action( 'admin_post_nopriv_ct_scan_control', 'ct_scan_control_handler' );
add_action( 'admin_post_ct_scan_control', 'ct_scan_control_handler' );

/** Recorded manual authority review: names the reviewer, evidence, target, time and expiry. */
function ct_scan_admin_record_authority_review( $job_id, $evidence_note ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'authority_review_forbidden', 'Only an administrator can record an authority review.' );
	}
	$note = is_string( $evidence_note ) ? trim( wp_strip_all_tags( $evidence_note ) ) : '';
	if ( strlen( $note ) < 20 || strlen( $note ) > 1000 ) {
		return new WP_Error( 'authority_review_evidence_required', 'Describe the evidence reviewed (20 to 1000 characters).' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_required ) || ! empty( $row->revoked_at ) || ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'authority_review_unavailable', 'This job is not waiting for target control.' );
		}
		if ( 'checking' === $row->control_state ) {
			return new WP_Error( 'authority_review_check_in_progress', 'A DNS or file check for this job is in progress. Wait for its result (at most two minutes), then reload this page and record the review if the job is still waiting.' );
		}
		$now      = ct_scan_utc_now();
		$evidence = wp_json_encode( array(
			'method'      => 'manual_review',
			'reviewer_id' => (int) $user->ID,
			'reviewer'    => sanitize_user( $user->user_login, true ),
			'target'      => $row->target_origin,
			'evidence'    => $note,
			'reviewed_at' => $now,
			'valid_until' => $row->authorization_expires_at,
		), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$updated  = $wpdb->update(
			$table,
			array( 'status' => 'queued', 'control_state' => 'none', 'control_method' => 'manual_review', 'control_verified_at' => $now, 'control_valid_until' => $row->authorization_expires_at, 'control_evidence' => $evidence, 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => $row->control_state ),
			array_fill( 0, 10, '%s' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'authority_review_write_failed', 'The review could not be durably recorded.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'queued' );
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_stop_token_from_request( $source ) {
	if ( ! isset( $source['stop'] ) || ! is_string( $source['stop'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['stop'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_row_by_stop_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE stop_token_hash = %s LIMIT 1", $hash ) );
}

/**
 * Customer stop: request-bound and idempotent, serialized with claims, starts, results and
 * request admissions by the queue lock. A cancelled job is rejected by the start, admit and
 * result endpoints. A request already admitted when the stop commits may finish within its
 * ten-second timeout; no further request is admitted. Waits briefly for the lock so that a
 * concurrent admission cannot make the customer's stop fail.
 * Returns 'stopped', 'already_stopped', 'already_finished', or a WP_Error.
 */
function ct_scan_customer_stop( $job_id, $token ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The request is temporarily busy. Please try again.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->stop_token_hash ) || '' === $token || ! hash_equals( $row->stop_token_hash, hash( 'sha256', $token ) ) ) {
			return new WP_Error( 'stop_link_invalid', 'This stop link is invalid.' );
		}
		if ( 'cancelled' === $row->status ) {
			return 'already_stopped';
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			return 'already_finished';
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'cancelled', 'error_code' => 'customer_stopped', 'finished_at' => $now, 'confirmation_token_hash' => null, 'confirmation_expires_at' => null, 'lease_hash' => null, 'lease_until' => null, 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ),
			array( 'job_id' => (int) $row->job_id, 'status' => $row->status ),
			null,
			array( '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'stop_write_failed', 'The stop could not be recorded. Please try again or contact support@complete.tech.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'customer_stopped' );
	} finally {
		ct_scan_lock_release();
	}
	return 'stopped';
}

function ct_scan_stop_markup( $job_id, $token, $nonce, $target ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Stop website screening</title><body><main><h1>Stop your website screening</h1><p>Stop the screening of this website:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>No new screening will start after you press Stop. A check that has already started may finish its current requests. Opening this page alone changes nothing.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_stop"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="stop" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Stop screening</button></form></main></body></html>';
}

function ct_scan_stop_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_stop_token_from_request( $_GET );
		$row   = '' === $token ? null : ct_scan_row_by_stop_hash( hash( 'sha256', $token ) );
		if ( ! $row ) {
			ct_scan_send_confirmation_page( 'This stop link is invalid.', 404 );
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			ct_scan_send_confirmation_page( 'cancelled' === $row->status ? 'This screening is already stopped.' : 'This screening has already finished. Nothing further will run.' );
		}
		$nonce = wp_create_nonce( 'ct_scan_stop_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_stop_markup( (int) $row->job_id, $token, $nonce, $row->target_origin ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the stop form to continue.', 405 );
	}
	$token  = ct_scan_stop_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_stop_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This stop form is invalid or expired. Open the stop link again.', 403 );
	}
	$result = ct_scan_customer_stop( $job_id, $token );
	if ( is_wp_error( $result ) ) {
		ct_scan_send_confirmation_page( $result->get_error_message(), 'queue_busy' === $result->get_error_code() ? 503 : 410 );
	}
	$messages = array(
		'stopped'          => 'Your screening is stopped. No new screening will start.',
		'already_stopped'  => 'This screening is already stopped.',
		'already_finished' => 'This screening has already finished. Nothing further will run.',
	);
	ct_scan_send_confirmation_page( $messages[ $result ] );
}
add_action( 'admin_post_nopriv_ct_scan_stop', 'ct_scan_stop_handler' );
add_action( 'admin_post_ct_scan_stop', 'ct_scan_stop_handler' );

function ct_scan_rest_response( $status, $payload ) {
	return new WP_REST_Response( $payload, (int) $status );
}

function ct_scan_rest_error( $status, $code ) {
	return ct_scan_rest_response( $status, array( 'error' => sanitize_key( $code ) ) );
}

/** Authenticate and consume a unique, short-lived worker nonce. */
function ct_scan_rest_authenticate( WP_REST_Request $request, $route ) {
	if ( ! ct_scan_enabled() || get_option( 'ct_scan_schema_version' ) !== CT_SCAN_SCHEMA_VERSION ) {
		return new WP_Error( 'ct_scan_disabled', 'Worker API is disabled.', array( 'status' => 503 ) );
	}
	$body = $request->get_body();
	if ( ! is_string( $body ) || strlen( $body ) > 65536 ) {
		return new WP_Error( 'ct_scan_body_too_large', 'Request body is too large.', array( 'status' => 413 ) );
	}
	$timestamp = $request->get_header( 'x-ct-timestamp' );
	$nonce     = $request->get_header( 'x-ct-nonce' );
	$signature = $request->get_header( 'x-ct-signature' );
	if ( ! is_string( $timestamp ) || ! preg_match( '/\A[0-9]{10}\z/', $timestamp )
		|| abs( time() - (int) $timestamp ) > 300
		|| ! is_string( $nonce ) || ! preg_match( '/\A[a-f0-9]{32}\z/i', $nonce )
		|| ! is_string( $signature ) || ! preg_match( '/\A[a-f0-9]{64}\z/i', $signature ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	$signing = $timestamp . "\n" . strtolower( $nonce ) . "\nPOST\n" . $route . "\n" . hash( 'sha256', $body );
	$expected = hash_hmac( 'sha256', $signing, ct_scan_config()['worker_hmac_secret'] );
	if ( ! hash_equals( $expected, strtolower( $signature ) ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	global $wpdb;
	$table = ct_scan_nonces_table();
	$nonce_hash = hash( 'sha256', strtolower( $nonce ) );
	$inserted = $wpdb->query( $wpdb->prepare(
		"INSERT IGNORE INTO {$table} (nonce_hash, expires_at) VALUES (%s, %s)",
		$nonce_hash,
		gmdate( 'Y-m-d H:i:s', time() + 600 )
	) );
	if ( 1 !== $inserted ) {
		return new WP_Error( 'ct_scan_replay', 'Worker authentication failed.', array( 'status' => 409 ) );
	}
	return $body;
}

function ct_scan_decode_request_body( $body ) {
	$data = json_decode( $body, true );
	if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
		return new WP_Error( 'ct_scan_json_invalid', 'Expected a JSON object.' );
	}
	return $data;
}

function ct_scan_expected_keys( $data, $keys ) {
	$actual = array_keys( $data );
	sort( $actual );
	sort( $keys );
	return $actual === $keys;
}

function ct_scan_is_list( $value ) {
	return is_array( $value ) && ( array() === $value || array_keys( $value ) === range( 0, count( $value ) - 1 ) );
}

function ct_scan_claim( WP_REST_Request $request ) {
	$response = ct_scan_claim_locked( $request );
	// The worker polls this route every few seconds; retention piggybacks on it, outside the queue lock, and
	// only on a poll that hands out no job, so a lease is never delayed by a retention run.
	if ( $response instanceof WP_REST_Response && 200 === $response->get_status() ) {
		$data = $response->get_data();
		if ( is_array( $data ) && array_key_exists( 'job', $data ) && null === $data['job'] ) {
			ct_scan_retention_run_safely(); // retention must never affect a claim
		}
	}
	return $response;
}

function ct_scan_claim_locked( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/claim' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array() ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		// One piece of target traffic at a time worker-wide: a scan, or a control check in progress.
		$active = $wpdb->get_var( "SELECT job_id FROM {$table} WHERE status IN ('leased','running') OR (status = 'awaiting_control' AND control_state = 'checking') LIMIT 1" );
		if ( $active ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'queued' AND attempts = 0 ORDER BY created_at ASC, job_id ASC LIMIT 1" );
		if ( ! $row ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$profile_fields = ct_scan_job_profile_fields( $row );
		if ( false === $profile_fields ) { return ct_scan_rest_error( 410, 'profile_binding_invalid' ); }
		$lease       = bin2hex( random_bytes( 32 ) );
		$expiry      = strtotime( $row->authorization_expires_at . ' UTC' );
		$lease_until = min( time() + 300, $expiry );
		if ( $lease_until <= time() ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'leased', 'lease_hash' => hash( 'sha256', $lease ), 'lease_until' => gmdate( 'Y-m-d H:i:s', $lease_until ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'queued', 'attempts' => 0 ),
			array( '%s', '%s', '%s' ),
			array( '%d', '%s', '%d' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 503, 'claim_race' );
		}
		return ct_scan_rest_response( 200, array(
			'job' => array_merge( $profile_fields, array(
				'id'          => (int) $row->job_id,
				'target'      => $row->target_origin,
				'scope_hash'  => $row->scope_hash,
				'terms_hash'  => $row->terms_hash,
				'expires_at'  => (int) $expiry,
				'lease'       => $lease,
				'lease_until' => (int) $lease_until,
			) ),
		) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_callback_payload( $data ) {
	if ( ! isset( $data['id'], $data['lease'], $data['scope_hash'] ) || ! is_int( $data['id'] ) || $data['id'] < 1
		|| ! is_string( $data['lease'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['lease'] )
		|| ! is_string( $data['scope_hash'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['scope_hash'] ) ) {
		return false;
	}
	return true;
}

/** Frozen additive wire fields. Legacy jobs never acquire the automatic profile. */
function ct_scan_job_profile_fields( $row ) {
	if ( 'r2-header-v1' === ( $row->profile_id ?? null ) ) { return array(); }
	if ( 'external-web-v1' !== ( $row->profile_id ?? null ) || ! isset( $row->profile_sha256, $row->services_json, $row->target_origin )
		|| ! is_string( $row->profile_sha256 ) || ! is_string( $row->services_json )
		|| ! hash_equals( ct_scan_external_profile_digest(), $row->profile_sha256 ) || ! ct_scan_external_profile_manifest() ) { return false; }
	$services = json_decode( $row->services_json, true );
	$services = JSON_ERROR_NONE === json_last_error() ? ct_scan_external_services( $services, $row->target_origin ) : false;
	if ( false === $services || wp_json_encode( ct_scan_canonicalize( $services ), JSON_UNESCAPED_SLASHES ) !== $row->services_json ) { return false; }
	return array( 'profile_id' => 'external-web-v1', 'profile_sha256' => $row->profile_sha256, 'services' => $services );
}

function ct_scan_result_profile_matches( $data, $row ) {
	$profile = ct_scan_job_profile_fields( $row );
	if ( false === $profile ) { return false; }
	$keys = array( 'id', 'lease', 'scope_hash', 'outcome', 'result', 'error', 'checker_revision' );
	if ( ! ct_scan_expected_keys( $data, array_merge( $keys, array_keys( $profile ) ) ) ) { return false; }
	foreach ( $profile as $key => $value ) {
		if ( 'services' === $key ) {
			if ( ct_scan_external_services( $data[$key], $row->target_origin ) !== $value ) { return false; }
		} elseif ( ! is_string( $data[$key] ) || ! hash_equals( $value, $data[$key] ) ) { return false; }
	}
	return true;
}

function ct_scan_start( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/start' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash' ) ) || ! ct_scan_callback_payload( $data ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row || 'leased' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( strtotime( $row->lease_until . ' UTC' ) <= time() || 0 !== (int) $row->attempts ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		$now = ct_scan_utc_now();
		$authorization_expiry = strtotime( $row->authorization_expires_at . ' UTC' );
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'running', 'attempts' => 1, 'started_at' => $now, 'lease_until' => gmdate( 'Y-m-d H:i:s', min( time() + 300, $authorization_expiry ) ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'leased', 'attempts' => 0, 'lease_hash' => $row->lease_hash ),
			array( '%s', '%d', '%s', '%s' ),
			array( '%d', '%s', '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'start_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'running' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

/**
 * Per-request admission decision. The sandboxed scanner holds no key: before every
 * connection to the target, the supervisor asks this guard through the signed
 * `admit` route. The caller MUST hold the queue lock, so this decision is
 * serialized with customer stop, operator revocation, expiry, lease changes and
 * every other admission. Returns array( http_status, payload ).
 *
 * `http` reserves one request from the frozen profile's budget and records the
 * admission time in the same compare-and-set update; the reservation is consumed
 * at once and is valid for ct_scan_profile_limits()['valid_ms']. `probe` only
 * reports whether the job is still live (no budget, no pacing).
 *
 * Nothing here is permissive on failure: an unknown profile, a clock that moved
 * backwards, a failed write, or an unconfirmed recipient is a refusal.
 */
function ct_scan_admit_locked( $data, $now_ms ) {
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$refuse = static function ( $status, $reason, $extra = array() ) {
		return array( (int) $status, array_merge( array( 'ok' => false, 'reason' => sanitize_key( $reason ) ), $extra ) );
	};
	// No table-wide maintenance here: probes run every couple of seconds under the same
	// lock as Stop, so this path stays short. Expiry and lease are checked on the row.
	$row = ct_scan_row( $data['id'] );
	if ( ! $row ) {
		return $refuse( 410, 'job_not_found' );
	}
	if ( 'running' === $row->status && strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'error_code' => 'authorization_expired', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null, 'confirmation_token_hash' => null ), array( 'job_id' => (int) $row->job_id, 'status' => 'running' ), array( '%s', '%s', '%s', '%s', '%s', '%s' ), array( '%d', '%s' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'expired', 'authorization_expired' );
		return $refuse( 410, 'job_expired' );
	}
	if ( 'cancelled' === $row->status ) {
		return $refuse( 410, 'job_cancelled' );
	}
	if ( 'expired' === $row->status ) {
		return $refuse( 410, 'job_expired' );
	}
	if ( 'running' !== $row->status || 1 !== (int) $row->attempts ) {
		return $refuse( 410, 'job_not_running' );
	}
	if ( empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
		|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
		return $refuse( 410, 'lease_invalid_or_expired' );
	}
	if ( ! ct_scan_confirmation_metadata_trusted( $row ) ) {
		return $refuse( 410, 'recipient_unconfirmed' );
	}
	if ( ! ct_scan_authorization_is_live( $row ) ) {
		$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		return $refuse( 410, 'authorization_revoked_or_expired' );
	}
	$limits = ct_scan_profile_limits( $row->profile_id );
	if ( ! $limits ) {
		return $refuse( 410, 'profile_unknown' );
	}
	if ( 'external-web-v1' === $row->profile_id ) {
		return ct_scan_external_admit_locked( $row, $data, $now_ms );
	}
	if ( ! in_array( $data['kind'], array( 'http', 'probe' ), true ) ) { return $refuse( 400, 'admission_kind_invalid' ); }
	if ( 'probe' === $data['kind'] ) {
		return array( 200, array( 'ok' => true, 'live' => true ) );
	}
	$last = null === $row->last_admit_ms ? null : (int) $row->last_admit_ms;
	if ( null !== $last ) {
		if ( $now_ms + $limits['min_interval_ms'] < $last ) {
			// The clock moved backwards by more than the pacing interval: do not guess.
			return $refuse( 410, 'clock_anomaly' );
		}
		$wait = $last + $limits['min_interval_ms'] - $now_ms;
		if ( $wait > 0 ) {
			return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => (int) min( $wait, $limits['min_interval_ms'] ) ) );
		}
	}
	$used = (int) $row->http_admitted;
	if ( $used >= $limits['http_requests'] ) {
		return $refuse( 409, 'budget_exhausted' );
	}
	$updated = $wpdb->update(
		$table,
		array( 'http_admitted' => $used + 1, 'last_admit_ms' => $now_ms ),
		array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash, 'http_admitted' => $used ),
		array( '%d', '%d' ),
		array( '%d', '%s', '%s', '%d' )
	);
	if ( 1 !== $updated ) {
		return $refuse( 503, 'admission_write_failed' );
	}
	return array( 200, array(
		'ok'             => true,
		'admitted'       => true,
		'sequence'       => $used + 1,
		'valid_ms'       => (int) $limits['valid_ms'],
		'timeout_ms'     => (int) $limits['timeout_ms'],
		'http_remaining' => (int) ( $limits['http_requests'] - $used - 1 ),
	) );
}

/** Read numeric database fields without silently turning malformed state into a fresh budget. */
function ct_scan_external_counter( $value, $maximum ) {
	if ( is_bool( $value ) || ( ! is_int( $value ) && ! is_string( $value ) ) || ! preg_match( '/\A(?:0|[1-9][0-9]{0,15})\z/', (string) $value ) ) { return false; }
	$number = (int) $value;
	return $number >= 0 && $number <= $maximum ? $number : false;
}

/** Caller already holds the queue lock and checked live authorization, recipient and lease. */
function ct_scan_external_admit_locked( $row, $data, $now_ms ) {
	global $wpdb;
	$refuse = static function ( $status, $reason, $extra = array() ) { return array( $status, array_merge( array( 'ok' => false, 'reason' => $reason ), $extra ) ); };
	if ( ! is_int( $now_ms ) || $now_ms < 1577836800000 || ! in_array( $data['kind'], array( 'http', 'tls', 'probe' ), true ) ) { return $refuse( 400, 'admission_kind_invalid' ); }
	$fields = array( 'http_admitted' => 100, 'tls_admitted' => 20, 'reserved_body_bytes' => 5242880, 'reserved_active_ms' => 600000, 'reservation_version' => 1 );
	$state = array();
	foreach ( $fields as $field => $maximum ) {
		if ( ! property_exists( $row, $field ) || false === ( $state[$field] = ct_scan_external_counter( $row->$field, $maximum ) ) ) { return $refuse( 410, 'budget_state_invalid' ); }
	}
	if ( 1 !== $state['reservation_version'] || ! isset( $row->profile_sha256, $row->services_json ) || ! is_string( $row->profile_sha256 ) || ! is_string( $row->services_json )
		|| ! hash_equals( ct_scan_external_profile_digest(), $row->profile_sha256 ) || ! ct_scan_external_profile_manifest()
		|| $state['reserved_body_bytes'] !== $state['http_admitted'] * 262144 || $state['reserved_active_ms'] !== ( $state['http_admitted'] + $state['tls_admitted'] ) * 10000
		|| ! property_exists( $row, 'last_admit_ms' ) || ! property_exists( $row, 'inflight_until_ms' ) || ! isset( $row->started_at ) || ! ct_scan_valid_datetime( $row->started_at ) ) { return $refuse( 410, 'budget_state_invalid' ); }
	$services = json_decode( $row->services_json, true );
	$services = JSON_ERROR_NONE === json_last_error() ? ct_scan_external_services( $services, $row->target_origin ) : false;
	if ( false === $services || wp_json_encode( ct_scan_canonicalize( $services ), JSON_UNESCAPED_SLASHES ) !== $row->services_json ) { return $refuse( 410, 'profile_binding_invalid' ); }
	$count = $state['http_admitted'] + $state['tls_admitted'];
	$last = null === $row->last_admit_ms ? null : ct_scan_external_counter( $row->last_admit_ms, PHP_INT_MAX );
	$until = null === $row->inflight_until_ms ? null : ct_scan_external_counter( $row->inflight_until_ms, PHP_INT_MAX );
	if ( ( 0 === $count && ( null !== $last || null !== $until ) ) || ( $count > 0 && ( false === $last || false === $until || null === $last || null === $until || $until !== $last + 11000 ) ) ) { return $refuse( 410, 'budget_state_invalid' ); }
	$started_ms = strtotime( $row->started_at . ' UTC' ) * 1000;
	if ( $now_ms < $started_ms || ( null !== $last && $now_ms < $last ) ) { return $refuse( 410, 'clock_anomaly' ); }
	if ( $now_ms - $started_ms >= 600000 ) { return $refuse( 409, 'active_budget_exhausted' ); }
	if ( 'probe' === $data['kind'] ) { return array( 200, array( 'ok' => true, 'live' => true ) ); }
	if ( null !== $until && $now_ms < $until ) { return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => $until - $now_ms ) ); }
	$is_http = 'http' === $data['kind'];
	if ( ! $is_http && ! in_array( array( 'port' => 443, 'scheme' => 'https' ), $services, true ) ) { return $refuse( 410, 'service_not_selected' ); }
	$body = $is_http ? 262144 : 0;
	if ( ( $is_http && $state['http_admitted'] >= 100 ) || ( ! $is_http && $state['tls_admitted'] >= 20 ) || $state['reserved_body_bytes'] + $body > 5242880 || $state['reserved_active_ms'] + 10000 > 600000 ) { return $refuse( 409, 'budget_exhausted' ); }
	$updated = $wpdb->update( ct_scan_jobs_table(), array(
		'http_admitted' => $state['http_admitted'] + ( $is_http ? 1 : 0 ), 'tls_admitted' => $state['tls_admitted'] + ( $is_http ? 0 : 1 ),
		'reserved_body_bytes' => $state['reserved_body_bytes'] + $body, 'reserved_active_ms' => $state['reserved_active_ms'] + 10000,
		'last_admit_ms' => $now_ms, 'inflight_until_ms' => $now_ms + 11000,
	), array(
		'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash, 'profile_sha256' => $row->profile_sha256,
		'http_admitted' => $row->http_admitted, 'tls_admitted' => $row->tls_admitted, 'reserved_body_bytes' => $row->reserved_body_bytes,
		'reserved_active_ms' => $row->reserved_active_ms, 'last_admit_ms' => $row->last_admit_ms, 'inflight_until_ms' => $row->inflight_until_ms,
		'reservation_version' => 1, 'services_json' => $row->services_json,
	) );
	if ( 1 !== $updated ) { return $refuse( 503, 'admission_write_failed' ); }
	return array( 200, array( 'ok' => true, 'admitted' => true, 'sequence' => $count + 1, 'valid_ms' => 1000, 'timeout_ms' => 10000,
		'http_remaining' => 100 - $state['http_admitted'] - ( $is_http ? 1 : 0 ), 'kind' => $data['kind'], 'profile_sha256' => $row->profile_sha256,
		'tls_remaining' => 20 - $state['tls_admitted'] - ( $is_http ? 0 : 1 ), 'body_bytes_remaining' => 5242880 - $state['reserved_body_bytes'] - $body,
		'active_ms_remaining' => 600000 - $state['reserved_active_ms'] - 10000,
	) );
}

function ct_scan_admit( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/admit' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash', 'kind' ) ) || ! ct_scan_callback_payload( $data )
		|| ! is_string( $data['kind'] ) || ! in_array( $data['kind'], array( 'http', 'tls', 'probe', 'control', 'control_probe' ), true ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		// Fail closed: a refusal here ends the screening rather than risking an unserialized send.
		return ct_scan_rest_response( 503, array( 'ok' => false, 'reason' => 'queue_busy' ) );
	}
	try {
		$now_ms   = (int) floor( microtime( true ) * 1000 );
		$decision = in_array( $data['kind'], array( 'control', 'control_probe' ), true )
			? ct_scan_admit_control_locked( $data, $now_ms )
			: ct_scan_admit_locked( $data, $now_ms );
	} catch ( Throwable $error ) {
		$decision = array( 503, array( 'ok' => false, 'reason' => 'admission_error' ) );
	} finally {
		ct_scan_lock_release();
	}
	return ct_scan_rest_response( $decision[0], $decision[1] );
}

function ct_scan_clean_result_line( $value, $limit = 500 ) {
	return is_string( $value ) && strlen( $value ) <= $limit;
}

function ct_scan_result_url_matches_scope( $url, $target ) {
	if ( ! is_string( $url ) || '' === $url || strlen( $url ) > 4096 ) {
		return false;
	}
	$parts = wp_parse_url( $url );
	$base  = wp_parse_url( $target );
	if ( ! is_array( $parts ) || ! is_array( $base ) || empty( $parts['scheme'] ) || empty( $parts['host'] )
		|| isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
		return false;
	}
	$scheme = strtolower( $parts['scheme'] );
	$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	$base_port = 'https' === $base['scheme'] ? 443 : 80;
	return in_array( $scheme, array( 'http', 'https' ), true )
		&& strtolower( $parts['host'] ) === $base['host']
		&& $port === ( 'https' === $scheme ? 443 : 80 )
		&& ( 'https' !== $base['scheme'] || 'https' === $scheme );
}

/** Accept only the reviewed fixed observation vocabulary, never raw target material. */
function ct_scan_external_check_valid( $check ) {
	if ( ! is_array( $check ) || ! ct_scan_expected_keys( $check, array( 'id', 'service', 'outcome', 'evidence' ) )
		|| ! is_string( $check['id'] ) || ! is_string( $check['service'] ) || ! is_string( $check['outcome'] ) || ! is_array( $check['evidence'] ) ) { return false; }
	$id = $check['id']; $outcome = $check['outcome']; $e = $check['evidence'];
	if ( 'not_selected' === $outcome ) { return 'tls_certificate' === $id && 'http:80' === $check['service'] && array( 'reason' => 'https_not_selected' ) === $e; }
	if ( ct_scan_expected_keys( $e, array( 'reason', 'http_status' ) ) ) {
		return 'security_header_presence' === $id && 'unknown' === $outcome && 'non_successful_response' === $e['reason']
			&& is_int( $e['http_status'] ) && $e['http_status'] >= 100 && $e['http_status'] <= 599 && ( $e['http_status'] < 200 || $e['http_status'] >= 300 );
	}
	if ( ct_scan_expected_keys( $e, array( 'reason' ) ) ) {
		return ( 'unknown' === $outcome && in_array( $id, array( 'security_header_presence', 'tls_certificate' ), true ) && 'service_not_assessed' === $e['reason'] )
			|| ( 'tls_certificate' === $id && 'blocked' === $outcome && 'tls_verification_failed' === $e['reason'] );
	}
	$fields = array(
		'robots_policy' => array( 'http_status', 'allowed' ),
		'public_header_triage' => array( 'http_status', 'fetch_status' ),
		'security_header_presence' => array( 'http_status', 'hsts', 'csp', 'frame_control', 'mime_options' ),
		'tls_certificate' => array( 'verification', 'protocol', 'not_after' ),
	);
	if ( ! isset( $fields[$id] ) || ! ct_scan_expected_keys( $e, $fields[$id] ) ) { return false; }
	if ( array_key_exists( 'http_status', $e ) && null !== $e['http_status'] && ( ! is_int( $e['http_status'] ) || $e['http_status'] < 100 || $e['http_status'] > 599 ) ) { return false; }
	if ( 'robots_policy' === $id ) { return is_bool( $e['allowed'] ) && ( $e['allowed'] ? 'observed' : 'blocked' ) === $outcome; }
	if ( 'public_header_triage' === $id ) {
		return is_string( $e['fetch_status'] ) && in_array( $e['fetch_status'], array( 'ok', 'blocked', 'timeout', 'dns_error' ), true )
			&& ( 'ok' === $e['fetch_status'] ? 'observed' : 'unknown' ) === $outcome
			&& ( 'ok' !== $e['fetch_status'] || ( is_int( $e['http_status'] ) && $e['http_status'] >= 200 && $e['http_status'] < 300 ) );
	}
	if ( 'security_header_presence' === $id ) {
		if ( 'observed' !== $outcome || ! is_int( $e['http_status'] ) || $e['http_status'] < 200 || $e['http_status'] >= 300 ) { return false; }
		foreach ( array( 'hsts', 'csp', 'frame_control', 'mime_options' ) as $key ) { if ( ! is_bool( $e[$key] ) ) { return false; } }
		return true;
	}
	return 'observed' === $outcome && 'verified' === $e['verification'] && is_string( $e['protocol'] )
		&& in_array( $e['protocol'], array( 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3' ), true ) && is_string( $e['not_after'] )
		&& ( '' === $e['not_after'] || false !== ct_scan_utc_parse( $e['not_after'] ) );
}

function ct_scan_validate_external_result( $result, $row, $stored_snapshot = false ) {
	$bad = static function () { return new WP_Error( 'result_profile_invalid', 'result_profile_invalid' ); };
	$binding = ct_scan_job_profile_fields( $row );
	if ( ! is_array( $result ) || false === $binding || empty( $binding ) ) { return $bad(); }
	foreach ( $binding as $key => $value ) {
		if ( ! array_key_exists( $key, $result ) ) { return $bad(); }
		if ( 'services' === $key ) {
			if ( ct_scan_external_services( $result[$key], $row->target_origin ) !== $value ) { return $bad(); }
		} elseif ( ! is_string( $result[$key] ) || ! hash_equals( $value, $result[$key] ) ) { return $bad(); }
	}
	if ( ! isset( $result['checks'], $result['manual_remainder'] ) || ! is_array( $result['checks'] ) || ! ct_scan_is_list( $result['checks'] ) ) { return $bad(); }
	$core = $result;
	foreach ( array( 'profile_id', 'profile_sha256', 'services', 'checks', 'manual_remainder' ) as $key ) { unset( $core[$key] ); }
	$legacy = clone $row; $legacy->profile_id = 'r2-header-v1';
	// The common result validator keeps the classifier/status/date/size contract intact.
	if ( is_wp_error( ct_scan_validate_result( $core, $legacy, $stored_snapshot ) ) ) { return $bad(); }
	$final = wp_parse_url( $core['final_url'] );
	$service = is_array( $final ) && isset( $final['scheme'] ) ? array( 'port' => $final['port'] ?? ( 'https' === $final['scheme'] ? 443 : 80 ), 'scheme' => $final['scheme'] ) : null;
	if ( ! in_array( $service, $binding['services'], true ) ) { return $bad(); }
	foreach ( array( 'server', 'powered_by', 'title', 'wordpress_version' ) as $key ) { if ( '' !== $core[$key] ) { return $bad(); } }
	foreach ( array( 'evidence', 'asset_version_hints', 'notes' ) as $key ) { if ( array() !== $core[$key] ) { return $bad(); } }
	if ( array() !== $core['php_evidence'] && array( 'PHP was mentioned in public response headers; raw values were discarded.' ) !== $core['php_evidence'] ) { return $bad(); }
	if ( count( $core['php_version_candidates'] ) > 32 ) { return $bad(); }
	foreach ( $core['php_version_candidates'] as $candidate ) { if ( ! preg_match( '/\A[0-9][A-Za-z0-9.+_~:-]{0,63}\z/', $candidate ) ) { return $bad(); } }
	$candidates = array_values( array_unique( $core['php_version_candidates'] ) ); sort( $candidates, SORT_STRING );
	if ( $candidates !== $core['php_version_candidates'] || $core['php_version'] !== ( 1 === count( $candidates ) ? $candidates[0] : '' ) ) { return $bad(); }
	// The maintained Checker owns classification. Permit its bounded public vocabulary,
	// not another target-controlled text channel disguised as interpretation or sources.
	$sources = array( 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w', 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp', 'https://ubuntu.com/security/notices/USN-8948-1' );
	if ( $sources !== $core['php2shell_sources'] || ! in_array( $core['php2shell_fixed_version'], array( '', '8.2.35', '8.3.36', '8.4.27', '8.5.12' ), true ) ) { return $bad(); }
	$notes = array(
		'Passive metadata only. Runtime SAPI, vendor backports, configuration, and exploitability are not verified.',
		'A PHP-related indicator was observed, but no complete PHP version was disclosed.',
		'No public PHP version was disclosed; lack of a header does not establish that PHP is absent.',
		'Conflicting PHP versions: ' . implode( ', ', $candidates ),
	);
	foreach ( $candidates as $candidate ) {
		$notes[] = "Cannot safely compare PHP version '" . $candidate . "' with the upstream release table.";
		$notes[] = 'PHP ' . $candidate . ' contains a build qualifier. Confirm the exact vendor package; its upstream base alone cannot establish patch status.';
		if ( preg_match( '/\A([0-9]+)\.([0-9]+)\.[0-9]+/', $candidate, $m ) ) { $notes[] = 'PHP ' . (int) $m[1] . '.' . (int) $m[2] . " is outside this rule snapshot's upstream 8.2-8.5 fix table. No safety conclusion is made."; }
		$notes[] = 'Advertised PHP ' . $candidate . ' is older than the ' . $core['php2shell_fixed_version'] . ' upstream fix for both listed CVEs.';
		$notes[] = 'Advertised PHP ' . $candidate . ' is at or above the ' . $core['php2shell_fixed_version'] . ' upstream fix. This is not a verified clean bill of health.';
	}
	if ( count( $core['php2shell_notes'] ) > 2 ) { return $bad(); }
	foreach ( $core['php2shell_notes'] as $note ) { if ( ! in_array( $note, $notes, true ) ) { return $bad(); } }
	$recommendations = array(
		'Ask the site administrator to verify the deployed PHP package and applicable vendor security updates.',
		'Confirm that the advertised version is the deployed, patched runtime and follow the current vendor advisory.',
		'Prioritize administrator review. Verify vendor backports and the actual runtime; install the vendor security update or upstream PHP ' . $core['php2shell_fixed_version'] . ' or newer in this branch.',
	);
	if ( ! in_array( $core['php2shell_recommendation'], $recommendations, true ) ) { return $bad(); }
	$expected = array();
	foreach ( $binding['services'] as $selected ) {
		foreach ( array( 'robots_policy', 'public_header_triage', 'security_header_presence', 'tls_certificate' ) as $id ) { $expected[$id . '|' . $selected['scheme'] . ':' . $selected['port']] = true; }
	}
	if ( count( $expected ) !== count( $result['checks'] ) ) { return $bad(); }
	foreach ( $result['checks'] as $check ) {
		if ( ! ct_scan_external_check_valid( $check ) ) { return $bad(); }
		$key = $check['id'] . '|' . $check['service'];
		if ( ! isset( $expected[$key] ) ) { return $bad(); }
		unset( $expected[$key] );
	}
	$manual = array();
	foreach ( array( 'runtime_and_backport_confirmation', 'internal_configuration_review', 'compromise_investigation' ) as $id ) { $manual[] = array( 'id' => $id, 'status' => 'not_assessed' ); }
	if ( $manual !== $result['manual_remainder'] ) { return $bad(); }
	$encoded = wp_json_encode( $result );
	return is_string( $encoded ) && strlen( $encoded ) <= 32768 ? $encoded : $bad();
}

/** Validate the small, single-result checker payload before persisting it. */
function ct_scan_validate_result( $result, $row, $stored_snapshot = false ) {
	if ( 'external-web-v1' === ( $row->profile_id ?? null ) ) { return ct_scan_validate_external_result( $result, $row, $stored_snapshot ); }
	if ( ! is_array( $result ) || count( $result ) > 64 ) {
		return new WP_Error( 'result_invalid', 'result_invalid' );
	}
	$required = array(
		'input_url', 'final_url', 'status', 'fetch_status', 'http_status', 'wordpress_version', 'php_version', 'server', 'powered_by', 'title',
		'evidence', 'asset_version_hints', 'notes', 'checked_at', 'php_version_candidates', 'php_evidence', 'php2shell_status',
		'php2shell_version_status', 'php2shell_fixed_version', 'php2shell_exploitability', 'php2shell_cves', 'php2shell_rules_as_of',
		'php2shell_sources', 'php2shell_notes', 'php2shell_recommendation',
	);
	if ( ! ct_scan_expected_keys( $result, $required ) ) {
		return new WP_Error( 'result_schema_mismatch', 'result_schema_mismatch' );
	}
	$version_states = array( 'version_not_disclosed', 'conflicting_versions', 'unrecognized_or_partial_version', 'branch_requires_vendor_review', 'prerelease_unverified', 'vendor_build_unverified', 'below_upstream_fix', 'at_or_above_upstream_fix' );
	$config = ct_scan_config();
	if ( ! is_string( $result['input_url'] ) || $result['input_url'] !== $row->target_origin
		|| ! is_string( $result['final_url'] )
		|| ! in_array( $result['status'], array( 'wordpress', 'likely_wordpress', 'no_evidence', 'uncertain', 'blocked', 'error' ), true )
		|| ! in_array( $result['fetch_status'], array( 'ok', 'blocked', 'timeout', 'dns_error' ), true )
		|| ! in_array( $result['php2shell_status'], array( 'potentially_affected', 'fixed_version_reported', 'unknown' ), true )
		|| ! is_string( $result['php2shell_version_status'] ) || ! in_array( $result['php2shell_version_status'], $version_states, true )
		|| 'not_tested' !== $result['php2shell_exploitability']
		|| ! is_string( $result['php2shell_rules_as_of'] ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}\z/', $result['php2shell_rules_as_of'] )
		|| ! checkdate( (int) substr( $result['php2shell_rules_as_of'], 5, 2 ), (int) substr( $result['php2shell_rules_as_of'], 8, 2 ), (int) substr( $result['php2shell_rules_as_of'], 0, 4 ) )
		|| ( ! $stored_snapshot && $result['php2shell_rules_as_of'] !== $config['expected_rules_as_of'] )
		|| ! is_string( $result['checked_at'] ) || strlen( $result['checked_at'] ) > 64
		|| ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/', $result['checked_at'] )
		|| ! is_string( $result['php_version'] ) || strlen( $result['php_version'] ) > 128
		|| ! is_string( $result['wordpress_version'] ) || strlen( $result['wordpress_version'] ) > 128
		|| ! is_string( $result['php2shell_fixed_version'] ) || strlen( $result['php2shell_fixed_version'] ) > 32 ) {
		return new WP_Error( 'result_semantics_invalid', 'result_semantics_invalid' );
	}
	if ( '' !== $result['final_url'] && ! ct_scan_result_url_matches_scope( $result['final_url'], $row->target_origin ) ) {
		return new WP_Error( 'result_scope_mismatch', 'result_scope_mismatch' );
	}
	if ( null !== $result['http_status'] && ( ! is_int( $result['http_status'] ) || $result['http_status'] < 100 || $result['http_status'] > 599 ) ) {
		return new WP_Error( 'result_http_status_invalid', 'result_http_status_invalid' );
	}
	foreach ( array( 'server', 'powered_by', 'title', 'php2shell_recommendation' ) as $key ) {
		if ( ! ct_scan_clean_result_line( $result[ $key ], 2048 ) ) {
			return new WP_Error( 'result_text_invalid', 'result_text_invalid' );
		}
	}
	foreach ( array( 'evidence', 'asset_version_hints', 'notes', 'php_version_candidates', 'php_evidence', 'php2shell_cves', 'php2shell_sources', 'php2shell_notes' ) as $key ) {
		if ( ! is_array( $result[ $key ] ) || ! ct_scan_is_list( $result[ $key ] ) || count( $result[ $key ] ) > 100 ) {
			return new WP_Error( 'result_list_invalid', 'result_list_invalid' );
		}
		foreach ( $result[ $key ] as $entry ) {
			$limit = in_array( $key, array( 'php_version_candidates' ), true ) ? 128 : 2048;
			if ( ! ct_scan_clean_result_line( $entry, $limit ) ) {
				return new WP_Error( 'result_list_item_invalid', 'result_list_item_invalid' );
			}
		}
	}
	if ( array_values( $result['php2shell_cves'] ) !== array( 'CVE-2026-109618', 'CVE-2026-109619' ) ) {
		return new WP_Error( 'result_cves_invalid', 'result_cves_invalid' );
	}
	$encoded = wp_json_encode( $result );
	if ( ! is_string( $encoded ) || strlen( $encoded ) > 32768 ) {
		return new WP_Error( 'result_too_large', 'result_too_large' );
	}
	return $encoded;
}

function ct_scan_canonicalize( $value ) {
	if ( ! is_array( $value ) ) {
		return $value;
	}
	if ( ct_scan_is_list( $value ) ) {
		return array_map( 'ct_scan_canonicalize', $value );
	}
	ksort( $value, SORT_STRING );
	foreach ( $value as $key => $item ) {
		$value[ $key ] = ct_scan_canonicalize( $item );
	}
	return $value;
}

function ct_scan_result( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/result' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	$keys = array( 'id', 'lease', 'scope_hash', 'outcome', 'result', 'error', 'checker_revision' );
	if ( is_wp_error( $data ) || ( ! ct_scan_expected_keys( $data, $keys ) && ! ct_scan_expected_keys( $data, array_merge( $keys, array( 'profile_id', 'profile_sha256', 'services' ) ) ) ) || ! ct_scan_callback_payload( $data )
		|| ! in_array( $data['outcome'], array( 'completed', 'failed' ), true ) || ! is_string( $data['checker_revision'] )
		|| ! preg_match( '/\A[a-f0-9]{40}\z/', $data['checker_revision'] ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$config = ct_scan_config();
	if ( ! hash_equals( strtolower( $config['expected_checker_revision'] ), strtolower( $data['checker_revision'] ) ) ) {
		return ct_scan_rest_error( 422, 'checker_revision_mismatch' );
	}
	$encoded_result = null;
	if ( 'completed' === $data['outcome'] ) {
		if ( ! is_array( $data['result'] ) || '' !== $data['error'] ) {
			return ct_scan_rest_error( 400, 'result_invalid' );
		}
	} else {
		if ( null !== $data['result'] || ! is_string( $data['error'] ) || ! preg_match( '/\A[a-z][a-z0-9_]{0,63}\z/', $data['error'] ) ) {
			return ct_scan_rest_error( 400, 'failure_receipt_invalid' );
		}
	}
	$canonical = wp_json_encode( ct_scan_canonicalize( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	if ( ! is_string( $canonical ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$receipt_hash = hash( 'sha256', $canonical );
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row ) {
			return ct_scan_rest_error( 410, 'job_not_found' );
		}
		if ( ! ct_scan_result_profile_matches( $data, $row ) ) { return ct_scan_rest_error( 422, 'profile_binding_invalid' ); }
		if ( in_array( $row->status, array( 'completed', 'failed' ), true ) && ! empty( $row->receipt_hash ) ) {
			return hash_equals( $row->receipt_hash, $receipt_hash )
				? ct_scan_rest_response( 200, array( 'ok' => true ) )
				: ct_scan_rest_error( 409, 'receipt_conflict' );
		}
		if ( in_array( $row->status, array( 'cancelled', 'expired', 'failed_unknown' ), true ) ) {
			return ct_scan_rest_error( 410, 'job_permanently_rejected' );
		}
		if ( 'running' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		if ( 'completed' === $data['outcome'] ) {
			// A completed result is only credible if the guard admitted at least one request for this job.
			if ( (int) $row->http_admitted < 1 ) {
				return ct_scan_rest_error( 409, 'no_admission' );
			}
			$encoded_result = ct_scan_validate_result( $data['result'], $row );
			if ( is_wp_error( $encoded_result ) ) {
				return ct_scan_rest_error( 422, $encoded_result->get_error_code() );
			}
		}
		$state = 'completed' === $data['outcome'] ? 'completed' : 'failed';
		$updated = $wpdb->update(
			$table,
			array(
				'status'           => $state,
				'outcome'          => $data['outcome'],
				'error_code'       => 'failed' === $data['outcome'] ? $data['error'] : null,
				'checker_revision' => strtolower( $data['checker_revision'] ),
				'result_json'      => $encoded_result,
				'receipt_hash'     => $receipt_hash,
				'finished_at'      => ct_scan_utc_now(),
				'lease_hash'       => null,
				'lease_until'      => null,
			),
			array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash ),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'result_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, $state, 'failed' === $state ? $data['error'] : '' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

/**
 * Admission for the single request of a control check (kind `control`) or a liveness probe of a
 * control task (`control_probe`). Same contract as ct_scan_admit_locked(): called under the queue
 * lock, refuses on any doubt, and consumes the attempt in the same compare-and-set as the decision.
 * The check budget is the disclosed three attempts, one minute apart.
 */
function ct_scan_admit_control_locked( $data, $now_ms ) {
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$limits = ct_scan_control_limits();
	$refuse = static function ( $status, $reason, $extra = array() ) {
		return array( (int) $status, array_merge( array( 'ok' => false, 'reason' => sanitize_key( $reason ) ), $extra ) );
	};
	$row = ct_scan_row( $data['id'] );
	if ( ! $row ) {
		return $refuse( 410, 'job_not_found' );
	}
	if ( 'awaiting_control' === $row->status && strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'error_code' => 'authorization_expired', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control' ), null, array( '%d', '%s' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'expired', 'authorization_expired' );
		return $refuse( 410, 'job_expired' );
	}
	if ( 'cancelled' === $row->status ) {
		return $refuse( 410, 'job_cancelled' );
	}
	if ( 'expired' === $row->status ) {
		return $refuse( 410, 'job_expired' );
	}
	if ( 'awaiting_control' !== $row->status || empty( $row->control_required ) ) {
		return $refuse( 410, 'job_not_awaiting_control' );
	}
	if ( 'checking' !== $row->control_state || empty( $row->control_lease_hash ) || ! hash_equals( $row->control_lease_hash, hash( 'sha256', $data['lease'] ) )
		|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->control_lease_until . ' UTC' ) <= time() ) {
		return $refuse( 410, 'lease_invalid_or_expired' );
	}
	if ( ! ct_scan_confirmation_metadata_trusted( $row ) ) {
		return $refuse( 410, 'recipient_unconfirmed' );
	}
	if ( ! ct_scan_authorization_is_live( $row ) ) {
		$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		return $refuse( 410, 'authorization_revoked_or_expired' );
	}
	if ( 'control_probe' === $data['kind'] ) {
		return array( 200, array( 'ok' => true, 'live' => true ) );
	}
	// One lease, one check: a lease that was already admitted is never admitted again, however
	// long it has left. The lease (two minutes) outlives the one-minute interval between checks.
	if ( ! empty( $row->control_admitted ) ) {
		return $refuse( 409, 'already_admitted' );
	}
	$used = (int) $row->control_attempts;
	if ( $used >= $limits['max_attempts'] ) {
		return $refuse( 409, 'budget_exhausted' );
	}
	if ( null !== $row->control_last_attempt_ms ) {
		$last = (int) $row->control_last_attempt_ms;
		if ( $now_ms + $limits['min_interval_ms'] < $last ) {
			return $refuse( 410, 'clock_anomaly' );
		}
		$wait = $last + $limits['min_interval_ms'] - $now_ms;
		if ( $wait > 0 ) {
			return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => (int) $wait ) );
		}
	}
	$updated = $wpdb->update(
		$table,
		array( 'control_attempts' => $used + 1, 'control_last_attempt_ms' => $now_ms, 'control_admitted' => 1 ),
		array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'checking', 'control_lease_hash' => $row->control_lease_hash, 'control_attempts' => $used, 'control_admitted' => 0 ),
		array( '%d', '%d', '%d' ),
		array( '%d', '%s', '%s', '%s', '%d', '%d' )
	);
	if ( 1 !== $updated ) {
		return $refuse( 503, 'admission_write_failed' );
	}
	return array( 200, array(
		'ok'             => true,
		'admitted'       => true,
		'sequence'       => $used + 1,
		'valid_ms'       => (int) $limits['valid_ms'],
		'timeout_ms'     => (int) $limits['timeout_ms'],
		'http_remaining' => (int) ( $limits['max_attempts'] - $used - 1 ),
	) );
}

/** Worker: take one scheduled control check. Consumes nothing; the attempt is consumed at admission. */
function ct_scan_control_claim( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/control/claim' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array() ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$limits = ct_scan_control_limits();
	try {
		ct_scan_maintenance_locked();
		$busy = $wpdb->get_var( "SELECT job_id FROM {$table} WHERE status IN ('leased','running') OR (status = 'awaiting_control' AND control_state = 'checking') LIMIT 1" );
		if ( $busy ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'awaiting_control' AND control_state = 'requested' ORDER BY job_id ASC LIMIT 1" );
		if ( ! $row ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		if ( ! ct_scan_authorization_is_live( $row ) || ! ct_scan_confirmation_metadata_trusted( $row ) || ! in_array( $row->control_requested_method, array( 'dns_txt', 'https_file' ), true ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none' ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$lease       = bin2hex( random_bytes( 32 ) );
		$expiry      = strtotime( $row->authorization_expires_at . ' UTC' );
		$lease_until = min( time() + $limits['lease_seconds'], $expiry );
		if ( $lease_until <= time() ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$updated = $wpdb->update(
			$table,
			array( 'control_state' => 'checking', 'control_lease_hash' => hash( 'sha256', $lease ), 'control_lease_until' => gmdate( 'Y-m-d H:i:s', $lease_until ), 'control_leased_ms' => (int) floor( microtime( true ) * 1000 ), 'control_admitted' => 0 ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'requested' ),
			array( '%s', '%s', '%s', '%d', '%d' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 503, 'claim_race' );
		}
		return ct_scan_rest_response( 200, array(
			'task' => array(
				'id'          => (int) $row->job_id,
				'target'      => $row->target_origin,
				'scope_hash'  => $row->scope_hash,
				'method'      => $row->control_requested_method,
				'expires_at'  => (int) $expiry,
				'lease'       => $lease,
				'lease_until' => (int) $lease_until,
			),
		) );
	} finally {
		ct_scan_lock_release();
	}
}

/** Does an observed value show the challenge? Only hashes of the token are stored. */
function ct_scan_control_value_matches( $method, $value, $token_hash ) {
	$limits = ct_scan_control_limits();
	if ( ! is_string( $value ) || ! is_string( $token_hash ) ) {
		return false;
	}
	if ( 'dns_txt' === $method ) {
		$prefix = $limits['dns_prefix'];
		if ( 0 !== strpos( $value, $prefix ) ) {
			return false;
		}
		$token = substr( $value, strlen( $prefix ) );
	} else {
		// Editors on some systems save a UTF-8 byte-order mark first; it is not part of the value.
		if ( 0 === strncmp( $value, "\xEF\xBB\xBF", 3 ) ) {
			$value = substr( $value, 3 );
		}
		$token = trim( $value, " \t\r\n" );
	}
	return 1 === preg_match( '/\A[a-f0-9]{64}\z/', $token ) && hash_equals( $token_hash, hash( 'sha256', $token ) );
}

/** Worker: report the outcome of the one admitted control request. */
function ct_scan_control_result( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/control/result' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	$limits = ct_scan_control_limits();
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash', 'method', 'outcome', 'observed' ) ) || ! ct_scan_callback_payload( $data )
		|| ! in_array( $data['method'], array( 'dns_txt', 'https_file' ), true ) || ! in_array( $data['outcome'], array( 'observed', 'not_found', 'error' ), true )
		|| ! is_array( $data['observed'] ) || ! ct_scan_is_list( $data['observed'] ) || count( $data['observed'] ) > 8 ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$total = 0;
	foreach ( $data['observed'] as $value ) {
		if ( ! is_string( $value ) || strlen( $value ) > $limits['max_bytes'] ) {
			return ct_scan_rest_error( 400, 'request_invalid' );
		}
		$total += strlen( $value );
	}
	if ( $total > $limits['max_bytes'] || ( 'observed' !== $data['outcome'] && array() !== $data['observed'] ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row || 'awaiting_control' !== $row->status || 'checking' !== $row->control_state || empty( $row->control_lease_hash )
			|| ! hash_equals( $row->control_lease_hash, hash( 'sha256', $data['lease'] ) ) || ! hash_equals( $row->scope_hash, $data['scope_hash'] )
			|| strtotime( $row->control_lease_until . ' UTC' ) <= time() || $row->control_requested_method !== $data['method'] ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		// The result of a check counts only if the guard admitted that check under this lease.
		if ( empty( $row->control_admitted ) || null === $row->control_last_attempt_ms || null === $row->control_leased_ms || (int) $row->control_last_attempt_ms < (int) $row->control_leased_ms ) {
			return ct_scan_rest_error( 409, 'no_admission' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		$matched = '';
		if ( 'observed' === $data['outcome'] ) {
			foreach ( $data['observed'] as $value ) {
				if ( ct_scan_control_value_matches( $data['method'], $value, (string) $row->control_token_hash ) ) {
					$matched = $value;
					break;
				}
			}
		}
		$now = ct_scan_utc_now();
		if ( '' !== $matched ) {
			$evidence = wp_json_encode( array(
				'method'          => $data['method'],
				'attempt'         => (int) $row->control_attempts,
				'checked_at'      => $now,
				'target'          => $row->target_origin,
				'observed_sha256' => hash( 'sha256', $matched ),
			), JSON_UNESCAPED_SLASHES );
			$update = array( 'status' => 'queued', 'control_state' => 'none', 'control_method' => $data['method'], 'control_verified_at' => $now, 'control_valid_until' => $row->authorization_expires_at, 'control_evidence' => $evidence, 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null );
			$state  = 'queued';
		} elseif ( (int) $row->control_attempts >= $limits['max_attempts'] ) {
			$update = array( 'status' => 'blocked', 'error_code' => 'target_control_failed', 'finished_at' => $now, 'control_state' => 'none', 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null, 'control_evidence' => wp_json_encode( array( 'method' => $data['method'], 'attempt' => (int) $row->control_attempts, 'last_outcome' => $data['outcome'] ) ) );
			$state  = 'blocked';
		} else {
			$update = array( 'control_state' => 'pending', 'control_lease_hash' => null, 'control_lease_until' => null, 'control_evidence' => wp_json_encode( array( 'method' => $data['method'], 'attempt' => (int) $row->control_attempts, 'last_outcome' => $data['outcome'] ) ) );
			$state  = 'awaiting_control';
		}
		$updated = $wpdb->update(
			$table,
			$update,
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'checking', 'control_lease_hash' => $row->control_lease_hash ),
			array_fill( 0, count( $update ), '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'result_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, $state, 'blocked' === $state ? 'target_control_failed' : '' );
		return ct_scan_rest_response( 200, array( 'ok' => true, 'verified' => '' !== $matched ) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_register_rest_routes() {
	register_rest_route( 'ct-scan/v1', '/claim', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_claim',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/start', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_start',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/admit', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_admit',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/control/claim', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_control_claim',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/control/result', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_control_result',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/result', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_result',
		'permission_callback' => '__return_true',
	) );
}
add_action( 'rest_api_init', 'ct_scan_register_rest_routes' );

function ct_scan_terminal_status( $status ) {
	return in_array( $status, ct_scan_terminal_statuses(), true );
}

function ct_scan_email_safe_text( $value, $max = 2000 ) {
	if ( ! is_string( $value ) ) {
		return '';
	}
	$value = wp_strip_all_tags( $value );
	$value = preg_replace( '/https?:\/\/[^\s<>"\']+/i', '[URL omitted]', $value );
	$value = preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+/', ' ', $value );
	$value = preg_replace( '/[ \t]+/', ' ', $value );
	$value = preg_replace( '/\n{3,}/', "\n\n", $value );
	return substr( trim( $value ), 0, $max );
}

function ct_scan_build_report_body( $row ) {
	if ( ! is_object( $row ) || ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status || '' === trim( (string) $row->manual_remainder_notes ) ) {
		return new WP_Error( 'report_not_ready', 'The scan and manual remainder are not ready for a reviewed report.' );
	}
	$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
	if ( ! is_string( $host ) || '' === $host ) {
		return new WP_Error( 'report_target_invalid', 'The saved target could not be verified.' );
	}
	$lines = array(
		'PHP2Shell passive screening and manual review',
		'Authorized target host: ' . $host,
		'Terms version: ' . $row->terms_version,
		'Terms accepted (UTC): ' . $row->terms_accepted_at,
		'',
		'PHP2Shell passive screening',
	);
	if ( 'completed' === $row->status ) {
		if ( ! is_string( $row->result_json ) || '' === $row->result_json ) {
			return new WP_Error( 'report_result_missing', 'The stored PHP2Shell result is unavailable.' );
		}
		$result = json_decode( $row->result_json, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$validated = ct_scan_validate_result( $result, $row, true );
		if ( is_wp_error( $validated ) ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$labels = array(
			'potentially_affected'   => 'Potentially affected: an advertised PHP version is below an upstream fix threshold; an administrator should verify the actual package and vendor backports.',
			'fixed_version_reported' => 'Fixed version reported: the public advertisement meets an upstream threshold; this does not verify the running package or prove safety.',
			'unknown'               => 'Unknown: public evidence did not support a reliable version classification.',
		);
		$lines[] = 'Screen status: ' . $labels[ $result['php2shell_status'] ];
		$lines[] = 'WordPress detection: ' . $result['status'];
		$lines[] = 'Fetch status: ' . $result['fetch_status'];
		$lines[] = 'HTTP status: ' . ( null === $result['http_status'] ? 'unavailable' : (string) $result['http_status'] );
		$lines[] = 'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : ct_scan_email_safe_text( $result['php_version'], 128 ) );
		$lines[] = 'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available for this advertised version' : $result['php2shell_fixed_version'] );
		$lines[] = 'PHP2Shell rules date: ' . $result['php2shell_rules_as_of'];
		$lines[] = 'Exploitability: not tested; no exploit payloads were sent.';
		$lines[] = 'Limit: this passive screen reads public robots policy, page content, and headers. It cannot verify the deployed runtime, vendor backports, or patch state.';
		$evidence = array_slice( $result['php_evidence'], 0, 10 );
		if ( $evidence ) {
			$lines[] = 'Observed PHP-related header evidence:';
			foreach ( $evidence as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 500 );
			}
		}
		$notes = array_slice( $result['php2shell_notes'], 0, 10 );
		if ( $notes ) {
			$lines[] = 'Interpretation notes:';
			foreach ( $notes as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 1000 );
			}
		}
	} else {
		$lines[] = 'No PHP2Shell classification was produced.';
		$lines[] = 'Execution state: ' . $row->status . ( $row->error_code ? ' (' . sanitize_key( $row->error_code ) . ')' : '' );
		$lines[] = 'No rescan was started while preparing this report.';
	}
	$lines[] = '';
	$lines[] = 'Other checks in the accepted service terms (manual remainder)';
	$lines[] = ct_scan_email_safe_text( $row->manual_remainder_notes, 12000 );
	$lines[] = '';
	$lines[] = 'This report is limited to the evidence above. It does not establish confirmed exploitation or a verified clean bill of health.';
	return implode( "\n", $lines ) . "\n";
}

function ct_scan_admin_revoke( $job_id ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->report_delivered_at ) ) {
			return new WP_Error( 'job_unavailable', 'This job cannot be revoked.' );
		}
		$now = ct_scan_utc_now();
		// revoked_at invalidates redemption. Retain the non-secret hash/expiry as durable proof
		// that an unused v8 notification carried a link, so an admin can truthfully close without a report.
		$update = array( 'revoked_at' => $now, 'confirmation_token_hash' => null, 'lease_hash' => null, 'lease_until' => null, 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null );
		if ( ! ct_scan_terminal_status( $row->status ) ) {
			$update['status'] = 'cancelled';
			$update['error_code'] = 'operator_revoked';
			$update['finished_at'] = $now;
		}
		$updated = $wpdb->update( $table, $update, array( 'job_id' => (int) $row->job_id, 'status' => $row->status, 'report_delivered_at' => null ), null, array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'revoke_write_failed', 'The authorization state could not be durably updated. No success was recorded.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, ct_scan_terminal_status( $row->status ) ? $row->status : 'cancelled', 'operator_revoked' );
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_save_manual_remainder( $job_id, $notes ) {
	if ( ! is_string( $notes ) ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter the completed manual review notes.' );
	}
	$notes = trim( sanitize_textarea_field( wp_unslash( $notes ) ) );
	if ( '' === $notes || strlen( $notes ) > 12000 ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter manual review notes of 1 to 12,000 characters.' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return new WP_Error( 'manual_review_unavailable', 'This job cannot receive manual review.' );
		}
		foreach ( array( 'closure_source', 'closed_by', 'closure_reason', 'report_delivered_at', 'report_access_used_at' ) as $field ) {
			if ( ! property_exists( $row, $field ) ) {
				return new WP_Error( 'manual_review_schema_missing', 'The report and closure state could not be verified.' );
			}
		}
		if ( ! ct_scan_terminal_status( $row->status ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at ) || ! empty( $row->report_access_used_at )
			|| null !== $row->closure_source || null !== $row->closed_by || null !== $row->closure_reason
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'manual_review_not_ready', 'Manual completion is available only for a terminal request with no recorded closure, revocation, or report delivery.' );
		}
		$updated = $wpdb->update( $table, array( 'manual_remainder_status' => 'complete', 'manual_remainder_notes' => $notes, 'manual_remainder_completed_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null, 'revoked_at' => null ), array( '%s', '%s', '%s' ), array( '%d', '%s', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'manual_review_write_failed', 'The manual review could not be durably saved.' );
		}
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

/** Return whether a job still matches its saved private request and is eligible for a report. */
function ct_scan_validate_report_job( $row, $token = '', $require_capability = false, $for_send = false ) {
	if ( ! is_object( $row ) || ! isset( $row->job_id, $row->request_id, $row->contact_email, $row->terms_version, $row->terms_hash )
		|| ! property_exists( $row, 'report_access_token_hash' ) || ! property_exists( $row, 'report_access_expires_at' ) || ! property_exists( $row, 'report_access_used_at' )
		|| ! property_exists( $row, 'closed_at' ) || ! property_exists( $row, 'closure_source' ) || ! property_exists( $row, 'closed_by' ) || ! property_exists( $row, 'closure_reason' ) || ! property_exists( $row, 'report_delivered_at' ) ) {
		return new WP_Error( 'report_schema_missing', 'The saved report access state could not be verified.' );
	}
	$allowed_notification_states = $for_send ? array( 'not_sent', 'failed' ) : array( 'accepted', 'unknown' );
	if ( ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
		|| ! in_array( $row->report_notification_status, $allowed_notification_states, true ) ) {
		return new WP_Error( 'report_access_unavailable', 'This report is no longer available.' );
	}
	// A prior closure reason/source is authoritative. Only legacy rows with no closure metadata may
	// receive the report-delivery closure stamp below, replacing the old maintenance-only timestamp.
	if ( null !== $row->closure_source || null !== $row->closed_by || null !== $row->closure_reason ) {
		return new WP_Error( 'report_closure_unavailable', 'The report closure state cannot be replaced.' );
	}
	if ( ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status || '' === trim( (string) $row->manual_remainder_notes ) ) {
		return new WP_Error( 'report_not_ready', 'The reviewed report is not ready.' );
	}
	if ( ! ct_scan_confirmation_metadata_trusted( $row ) ) {
		return new WP_Error( 'report_recipient_unconfirmed', 'The report recipient did not confirm the request.' );
	}
	clean_post_cache( (int) $row->request_id );
	$post = get_post( (int) $row->request_id );
	if ( ! $post || 'ct_promo_request' !== $post->post_type || 'private' !== $post->post_status
		|| (string) (int) $row->job_id !== ct_scan_meta_string( (int) $row->request_id, '_ct_scan_job_id' ) ) {
		return new WP_Error( 'report_request_mismatch', 'The original request and job no longer match.' );
	}
	if ( ! is_email( $row->contact_email )
		|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_email' ) !== $row->contact_email
		|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_version' ) !== $row->terms_version
		|| strtolower( ct_scan_meta_string( (int) $row->request_id, '_ct_terms_sha256' ) ) !== $row->terms_hash
		|| ! preg_match( '/\A[a-f0-9]{64}\z/', (string) $row->terms_hash )
		|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_authorization_expires_at' ) !== $row->authorization_expires_at ) {
		return new WP_Error( 'report_contact_changed', 'The original authorized recipient or acceptance could not be verified.' );
	}
	// Scan authorization expires for target traffic, not for delivery of a prepared report to the
	// already-confirmed recipient. Re-read the immutable saved acceptance without applying that
	// scan-only expiry gate, and compare its complete accepted tuple with the job row.
	$fields = array(
		'target'   => (string) $row->target_origin,
		'email'    => (string) $row->contact_email,
		'name'     => (string) $row->contact_name,
		'referrer' => (string) $row->referrer,
	);
	$accepted = ct_scan_validate_saved_request(
		(int) $row->request_id,
		$fields,
		false,
		(string) $row->authorization_expires_at,
		array( 'bound_required' => ! empty( $row->bound_required ), 'profile' => (string) $row->profile_id, 'profile_sha256' => $row->profile_sha256 ?? null, 'services_json' => $row->services_json ?? null ),
		true
	);
	if ( is_wp_error( $accepted )
		|| ! hash_equals( (string) $row->scope_hash, hash( 'sha256', (string) ( $accepted['target'] ?? '' ) ) )
		|| ! hash_equals( (string) $row->terms_hash, (string) ( $accepted['terms_hash'] ?? '' ) )
		|| $row->terms_version !== ( $accepted['terms_version'] ?? null )
		|| $row->terms_accepted_at !== ( $accepted['terms_accepted_at'] ?? null )
		|| $row->authorization_expires_at !== ( $accepted['authorization_expires'] ?? null )
		|| ( null === ( $accepted['summary_sha256'] ?? null )
			? ! empty( $row->summary_sha256 )
			: ( ! is_string( $row->summary_sha256 ) || ! hash_equals( $row->summary_sha256, $accepted['summary_sha256'] ) ) ) ) {
		return new WP_Error( 'report_acceptance_mismatch', 'The saved acceptance no longer matches the report job.' );
	}
	// A missing control_required value is deliberately treated as required by ct_scan_control_required().
	if ( ct_scan_control_required( $row ) ) {
		if ( empty( $row->control_verified_at ) || ! ct_scan_valid_datetime( (string) $row->control_verified_at )
			|| ! in_array( $row->control_method ?? null, array( 'dns_txt', 'https_file', 'manual_review' ), true )
			|| ! ct_scan_valid_datetime( (string) ( $row->control_valid_until ?? '' ) )
			|| $row->control_valid_until !== $row->authorization_expires_at
			|| $row->control_verified_at < $row->created_at || $row->control_verified_at < $row->terms_accepted_at
			|| $row->control_verified_at < $row->confirmed_at || $row->control_verified_at > ct_scan_utc_now()
			|| $row->control_verified_at > $row->control_valid_until ) {
			return new WP_Error( 'report_target_unverified', 'Control of the exact target was not verified for the authorized scan window.' );
		}
	}
	if ( $require_capability ) {
		if ( ! is_string( $token ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $token )
			|| ! is_string( $row->report_access_token_hash ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $row->report_access_token_hash )
			|| ! hash_equals( $row->report_access_token_hash, hash( 'sha256', $token ) )
			|| ! empty( $row->report_access_used_at ) || ! ct_scan_valid_datetime( (string) $row->report_access_expires_at )
			|| strtotime( $row->report_access_expires_at . ' UTC' ) <= time() ) {
			return new WP_Error( 'report_capability_invalid', 'The report capability is invalid, expired, or already used.' );
		}
	}
	$body = ct_scan_build_report_body( $row );
	return $body;
}

function ct_scan_report_access_page_markup( $job_id, $token ) {
	return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive"><title>Reviewed website report</title></head><body><main><h1>Your reviewed website report is ready</h1><p>Continue to view the report. Opening this page has not used the access link.</p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ct_scan_report_access"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="key" value="' . esc_attr( $token ) . '"><button type="submit">View report</button></form></main></body></html>';
}

function ct_scan_report_document_markup( $body ) {
	return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive"><title>Reviewed website report</title></head><body><main><h1>Reviewed website report</h1><pre>' . esc_html( $body ) . '</pre></main></body></html>';
}

function ct_scan_report_unavailable_markup() {
	return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive"><title>Website report</title></head><body><main><h1>Website report</h1><p>This report link is invalid, expired, already used, or no longer authorized.</p></main></body></html>';
}

/** Build report responses without output so the single-use transition is easy to exercise with synthetic state. */
function ct_scan_report_access_response( $method, $job_id, $token ) {
	$method = strtoupper( (string) $method );
	if ( ! in_array( $method, array( 'GET', 'POST' ), true ) ) {
		return array( 'status' => 405, 'body' => ct_scan_report_unavailable_markup() );
	}
	$job_id = absint( $job_id );
	if ( ! $job_id || ! is_string( $token ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $token ) ) {
		return array( 'status' => 404, 'body' => ct_scan_report_unavailable_markup() );
	}
	if ( 'GET' === $method ) {
		$row = ct_scan_row( $job_id );
		$validated = ct_scan_validate_report_job( $row, $token, true );
		if ( is_wp_error( $validated ) ) {
			return array( 'status' => 410, 'body' => ct_scan_report_unavailable_markup() );
		}
		return array( 'status' => 200, 'body' => ct_scan_report_access_page_markup( $job_id, $token ) );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return array( 'status' => 503, 'body' => ct_scan_report_unavailable_markup() );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		$body = ct_scan_validate_report_job( $row, $token, true );
		if ( is_wp_error( $body ) ) {
			return array( 'status' => 410, 'body' => ct_scan_report_unavailable_markup() );
		}
		$now = ct_scan_utc_now();
		if ( ! ct_scan_valid_datetime( $now ) || ! ct_scan_valid_datetime( $row->created_at ) || ! ct_scan_valid_datetime( $row->terms_accepted_at )
			|| $now < $row->created_at || $now < $row->terms_accepted_at || ! ct_scan_clock_is_sane( $now ) ) {
			return array( 'status' => 503, 'body' => ct_scan_report_unavailable_markup() );
		}
		$data = array(
			'report_access_used_at'      => $now,
			'report_delivered_at'        => $now,
			'report_access_token_hash'   => null,
			'report_access_expires_at'   => null,
			'closed_at'                  => $now,
			'closure_source'             => 'report_delivery',
			'closed_by'                  => 0,
			'closure_reason'             => 'report_delivered',
		);
		$where = array(
			'job_id'                     => (int) $row->job_id,
			'request_id'                 => (int) $row->request_id,
			'target_origin'              => $row->target_origin,
			'scope_hash'                 => $row->scope_hash,
			'contact_email'              => $row->contact_email,
			'contact_name'               => $row->contact_name,
			'referrer'                   => $row->referrer,
			'terms_version'              => $row->terms_version,
			'terms_hash'                 => $row->terms_hash,
			'terms_accepted_at'          => $row->terms_accepted_at,
			'authorization_expires_at'   => $row->authorization_expires_at,
			'status'                     => $row->status,
			'confirmed_at'               => $row->confirmed_at,
			'created_at'                 => $row->created_at,
			'control_required'           => ct_scan_control_required( $row ) ? 1 : 0,
			'control_method'             => $row->control_method ?? null,
			'control_verified_at'        => $row->control_verified_at ?? null,
			'control_valid_until'         => $row->control_valid_until ?? null,
			'manual_remainder_status'    => $row->manual_remainder_status,
			'manual_remainder_notes'     => $row->manual_remainder_notes,
			'result_json'                => $row->result_json ?? null,
			'report_notification_status' => $row->report_notification_status,
			'report_access_token_hash'   => $row->report_access_token_hash,
			'report_access_expires_at'   => $row->report_access_expires_at,
			'report_access_used_at'      => null,
			'report_delivered_at'        => null,
			'closed_at'                  => $row->closed_at,
			'closure_source'             => null,
			'closed_by'                  => null,
			'closure_reason'             => null,
			'revoked_at'                 => null,
		);
		$updated = $wpdb->update( $table, $data, $where );
		if ( false === $updated ) {
			return array( 'status' => 503, 'body' => ct_scan_report_unavailable_markup() );
		}
		if ( 1 !== $updated ) {
			return array( 'status' => 410, 'body' => ct_scan_report_unavailable_markup() );
		}
		try {
			update_post_meta( (int) $row->request_id, '_ct_scan_report_delivered_at', $now );
		} catch ( Throwable $error ) {
			// The jobs table is the authoritative delivery record. A mirror failure must not suppress a served report.
		}
		return array( 'status' => 200, 'body' => ct_scan_report_document_markup( $body ) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_report_access_headers() {
	return array(
		'Content-Type'           => 'text/html; charset=UTF-8',
		'Cache-Control'          => 'no-store, no-cache, must-revalidate, max-age=0, private',
		'Pragma'                 => 'no-cache',
		'Expires'                => 'Wed, 11 Jan 1984 05:00:00 GMT',
		'Referrer-Policy'        => 'no-referrer',
		'X-Robots-Tag'           => 'noindex, nofollow, noarchive, nosnippet',
		'X-Content-Type-Options' => 'nosniff',
		'X-Frame-Options'        => 'DENY',
		'Content-Security-Policy'=> "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
	);
}

/** Is there trustworthy evidence that no report body was delivered, so an admin may close without a report? */
function ct_scan_no_report_close_eligible( $row ) {
	if ( ! is_object( $row ) ) {
		return false;
	}
	foreach ( array( 'status', 'report_notification_status', 'report_access_token_hash', 'report_access_expires_at', 'report_access_used_at', 'report_delivered_at', 'closure_source', 'closed_by', 'closure_reason' ) as $field ) {
		if ( ! property_exists( $row, $field ) ) {
			return false;
		}
	}
	if ( ! in_array( $row->status, ct_scan_terminal_statuses(), true )
		|| null !== $row->closure_source || null !== $row->closed_by || null !== $row->closure_reason
		|| null !== $row->report_delivered_at || null !== $row->report_access_used_at ) {
		return false;
	}
	$has_unredeemed_link = is_string( $row->report_access_token_hash )
		&& 1 === preg_match( '/\A[a-f0-9]{64}\z/', $row->report_access_token_hash )
		&& is_string( $row->report_access_expires_at )
		&& ct_scan_valid_datetime( $row->report_access_expires_at )
		&& in_array( $row->report_notification_status, array( 'accepted', 'unknown', 'failed' ), true );
	$never_sent = 'not_sent' === $row->report_notification_status
		&& null === $row->report_access_token_hash
		&& null === $row->report_access_expires_at;
	return $has_unredeemed_link || $never_sent;
}

function ct_scan_report_access_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	$source = 'POST' === $method ? $_POST : $_GET;
	$job_id = isset( $source['job_id'] ) && is_scalar( $source['job_id'] ) ? absint( wp_unslash( $source['job_id'] ) ) : 0;
	$token  = isset( $source['key'] ) && is_string( $source['key'] ) ? strtolower( wp_unslash( $source['key'] ) ) : '';
	$response = ct_scan_report_access_response( $method, $job_id, $token );
	$status = (int) $response['status'];
	if ( function_exists( 'status_header' ) ) {
		status_header( $status );
	} else {
		http_response_code( $status );
	}
	if ( function_exists( 'nocache_headers' ) ) {
		nocache_headers();
	}
	foreach ( ct_scan_report_access_headers() as $name => $value ) {
		header( $name . ': ' . $value );
	}
	echo $response['body']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- response markup escapes the report body and capability fields.
	exit;
}
add_action( 'admin_post_nopriv_ct_scan_report_access', 'ct_scan_report_access_handler' );
add_action( 'admin_post_ct_scan_report_access', 'ct_scan_report_access_handler' );

/** Record the operator's final review of a terminal job; terminal status alone never closes a request. */
function ct_scan_admin_close( $job_id, $reason ) {
	global $wpdb;
	$user = wp_get_current_user();
	$user_id = ( is_object( $user ) && isset( $user->ID ) && is_numeric( $user->ID ) ) ? (int) $user->ID : 0;
	if ( ! $user || ! $user->exists() || $user_id < 1 || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'close_forbidden', 'Only an authenticated administrator can record final closure.' );
	}
	$job_id = absint( $job_id );
	if ( ! $job_id || ! is_string( $reason ) || ! in_array( $reason, ct_scan_terminal_statuses(), true ) ) {
		return new WP_Error( 'close_invalid', 'Select a valid terminal status as the closure reason.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return new WP_Error( 'close_unavailable', 'This job no longer exists.' );
		}
		foreach ( array( 'status', 'created_at', 'terms_accepted_at', 'closed_at', 'closure_source', 'closed_by', 'closure_reason', 'report_delivered_at', 'report_notification_status', 'report_access_token_hash', 'report_access_expires_at', 'report_access_used_at' ) as $field ) {
			if ( ! property_exists( $row, $field ) ) {
				return new WP_Error( 'close_schema_missing', 'The final-close state could not be verified.' );
			}
		}
		if ( ! in_array( $row->status, ct_scan_terminal_statuses(), true ) || $reason !== $row->status ) {
			return new WP_Error( 'close_reason_mismatch', 'The reason must match the job’s saved terminal status.' );
		}
		if ( null !== $row->closure_source || null !== $row->closed_by || null !== $row->closure_reason || null !== $row->report_delivered_at || null !== $row->report_access_used_at ) {
			return new WP_Error( 'close_already_recorded', 'This job already has closure or report-delivery metadata.' );
		}
		if ( ! ct_scan_no_report_close_eligible( $row ) ) {
			// Pre-v8 `accepted`/`unknown` mail may have contained the report itself; without the v8
			// single-use capability fields, its delivery outcome cannot be truthfully called no-report.
			return new WP_Error( 'close_report_ambiguous', 'The earlier report-delivery state cannot be verified; leave this request pending for review.' );
		}
		$now = ct_scan_utc_now();
		if ( ! ct_scan_valid_datetime( $now ) || ! ct_scan_valid_datetime( $row->created_at ) || ! ct_scan_valid_datetime( $row->terms_accepted_at )
			|| $now < $row->created_at || $now < $row->terms_accepted_at || ! ct_scan_clock_is_sane( $now ) ) {
			return new WP_Error( 'close_clock_untrusted', 'The server and database clocks or saved acceptance dates could not be verified; nothing was closed.' );
		}
		$updated = $wpdb->update(
			ct_scan_jobs_table(),
			array(
				'closed_at'                => $now,
				'closure_source'           => 'admin_final_close',
				'closed_by'                => $user_id,
				'closure_reason'           => $reason,
				'report_access_token_hash' => null,
				'report_access_expires_at' => null,
				'report_access_used_at'    => null,
				'report_delivered_at'      => null,
			),
			array(
				'job_id'                    => (int) $row->job_id,
				'status'                    => $row->status,
				'created_at'                => $row->created_at,
				'terms_accepted_at'         => $row->terms_accepted_at,
				'closed_at'                 => $row->closed_at,
				'closure_source'            => null,
				'closed_by'                 => null,
				'closure_reason'            => null,
				'report_delivered_at'       => null,
				'report_notification_status'=> $row->report_notification_status,
				'report_access_token_hash'  => $row->report_access_token_hash,
				'report_access_expires_at'  => $row->report_access_expires_at,
				'report_access_used_at' => null,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s' ),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		if ( false === $updated ) {
			return new WP_Error( 'close_write_failed', 'Final closure could not be durably recorded.' );
		}
		if ( 1 !== $updated ) {
			return new WP_Error( 'close_changed', 'This job changed while final closure was being recorded; reload and review it again.' );
		}
		try {
			update_post_meta( (int) $row->request_id, '_ct_scan_closed_at', $now );
			update_post_meta( (int) $row->request_id, '_ct_scan_closure_source', 'admin_final_close' );
			update_post_meta( (int) $row->request_id, '_ct_scan_closed_by', $user_id );
			update_post_meta( (int) $row->request_id, '_ct_scan_closure_reason', $reason );
		} catch ( Throwable $error ) {
			// The jobs table is authoritative. A mirror failure cannot roll back the authenticated closure.
		}
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_send_report( $job_id ) {
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'report_send_unavailable', 'This report cannot be sent in its current state.' );
		}
		$body = ct_scan_validate_report_job( $row, '', false, true );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		if ( ! property_exists( $row, 'report_access_token_hash' ) || ! property_exists( $row, 'report_access_expires_at' ) || ! property_exists( $row, 'report_access_used_at' ) ) {
			return new WP_Error( 'report_schema_missing', 'The saved report access state could not be verified.' );
		}
		$token = bin2hex( random_bytes( 32 ) );
		$now = ct_scan_utc_now();
		// The scan window controls target traffic. A report link gets its own short lifetime and
		// remains deliverable after scan authorization expires.
		$expiry = time() + ( 7 * 24 * 60 * 60 );
		$access_expires = gmdate( 'Y-m-d H:i:s', $expiry );
		$updated = $wpdb->update(
			$table,
			array(
				'report_notification_status' => 'unknown',
				'report_notification_at' => $now,
				'report_access_token_hash' => hash( 'sha256', $token ),
				'report_access_expires_at' => $access_expires,
				'report_access_used_at' => null,
			),
			array(
				'job_id' => (int) $row->job_id,
				'request_id' => (int) $row->request_id,
				'status' => $row->status,
				'confirmed_at' => $row->confirmed_at,
				'created_at' => $row->created_at,
				'terms_accepted_at' => $row->terms_accepted_at,
				'authorization_expires_at' => $row->authorization_expires_at,
				'report_notification_status' => $row->report_notification_status,
				'report_delivered_at' => null,
				'revoked_at' => null,
				'report_access_used_at' => null,
			),
			array( '%s', '%s', '%s', '%s', '%s' ),
			array( '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_state_write_failed', 'The one-time send state could not be durably recorded. No email was sent.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', 'unknown' );
		$url = add_query_arg(
			array( 'action' => 'ct_scan_report_access', 'job_id' => (int) $row->job_id, 'key' => $token ),
			admin_url( 'admin-post.php' )
		);
		$mail_body = "A reviewed report for a request you confirmed is ready.\n\nView your report using this one-time link, which expires within seven days:\n" . $url . "\n\nIf you did not make this request, you can ignore this email.\n";
		$status = 'unknown';
		try {
			if ( wp_mail( $row->contact_email, 'Your reviewed website report is ready', $mail_body ) ) {
				$status = 'accepted';
			}
		} catch ( Throwable $error ) {
			$status = 'unknown';
		}
		if ( 'accepted' === $status ) {
			$updated = $wpdb->update(
				$table,
				array( 'report_notification_status' => 'accepted', 'report_notification_at' => ct_scan_utc_now() ),
				array( 'job_id' => (int) $row->job_id, 'report_notification_status' => 'unknown', 'report_delivered_at' => null, 'revoked_at' => null ),
				array( '%s', '%s' ),
				array( '%d', '%s', '%s', '%s' )
			);
			if ( 1 !== $updated ) {
				return new WP_Error( 'report_state_write_failed', 'The email outcome could not be durably recorded. Its status remains unknown; do not resend.' );
			}
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', $status );
	}
	finally {
		ct_scan_lock_release();
	}
	return 'accepted' === $status ? true : new WP_Error( 'report_transport_unknown', 'The mail transport did not confirm acceptance. Check delivery logs before attempting another send.' );
}

function ct_scan_admin_action_handler() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to manage scan requests.', 'ct-scan' ), '', array( 'response' => 403 ) );
	}
	$job_id = isset( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	$action = isset( $_POST['ct_scan_operation'] ) && is_string( $_POST['ct_scan_operation'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_operation'] ) ) : '';
	if ( ! $job_id || ! in_array( $action, array( 'revoke', 'manual_complete', 'send_report', 'authority_review', 'set_hold', 'release_hold', 'final_close' ), true ) ) {
		wp_die( esc_html__( 'The requested action is invalid.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	check_admin_referer( 'ct_scan_admin_' . $action . '_' . $job_id );
	$confirmations = array(
		'revoke'          => 'ct_scan_revoke_confirm',
		'manual_complete' => 'ct_scan_review_confirm',
		'send_report'     => 'ct_scan_send_confirm',
		'authority_review' => 'ct_scan_authority_confirm',
		'set_hold'        => 'ct_scan_hold_confirm',
		'release_hold'    => 'ct_scan_hold_release_confirm',
		'final_close'     => 'ct_scan_final_close_confirm',
	);
	$confirm_key = $confirmations[ $action ];
	if ( ! isset( $_POST[ $confirm_key ] ) || ! is_string( $_POST[ $confirm_key ] ) || '1' !== wp_unslash( $_POST[ $confirm_key ] ) ) {
		wp_die( esc_html__( 'Confirm this action before continuing.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	if ( 'revoke' === $action ) {
		$result = ct_scan_admin_revoke( $job_id );
	} elseif ( 'manual_complete' === $action ) {
		$result = ct_scan_admin_save_manual_remainder( $job_id, isset( $_POST['manual_remainder_notes'] ) && is_string( $_POST['manual_remainder_notes'] ) ? $_POST['manual_remainder_notes'] : '' );
	} elseif ( 'send_report' === $action ) {
		$result = ct_scan_admin_send_report( $job_id );
	} elseif ( 'set_hold' === $action ) {
		$result = ct_scan_admin_set_hold( $job_id, isset( $_POST['ct_scan_hold_reason'] ) && is_string( $_POST['ct_scan_hold_reason'] ) ? wp_unslash( $_POST['ct_scan_hold_reason'] ) : '', isset( $_POST['ct_scan_hold_days'] ) && is_scalar( $_POST['ct_scan_hold_days'] ) ? wp_unslash( $_POST['ct_scan_hold_days'] ) : 0 );
	} elseif ( 'release_hold' === $action ) {
		$result = ct_scan_admin_release_hold( $job_id, isset( $_POST['ct_scan_hold_identity'] ) && is_string( $_POST['ct_scan_hold_identity'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_hold_identity'] ) ) : '' );
	} elseif ( 'authority_review' === $action ) {
		$result = ct_scan_admin_record_authority_review( $job_id, isset( $_POST['ct_scan_authority_note'] ) && is_string( $_POST['ct_scan_authority_note'] ) ? wp_unslash( $_POST['ct_scan_authority_note'] ) : '' );
	} elseif ( 'final_close' === $action ) {
		$result = ct_scan_admin_close( $job_id, isset( $_POST['ct_scan_close_reason'] ) && is_string( $_POST['ct_scan_close_reason'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_close_reason'] ) ) : '' );
	}
	$notice = is_wp_error( $result ) ? $result->get_error_code() : 'updated';
	$url = add_query_arg( array( 'page' => 'ct-scan-queue', 'ct_scan_notice' => sanitize_key( $notice ) ), admin_url( 'edit.php?post_type=ct_promo_request' ) );
	wp_safe_redirect( $url );
	exit;
}
add_action( 'admin_post_ct_scan_admin_action', 'ct_scan_admin_action_handler' );

function ct_scan_admin_form( $job_id, $operation, $label, $extra = '' ) {
	$nonce = wp_nonce_field( 'ct_scan_admin_' . $operation . '_' . $job_id, '_wpnonce', true, false );
	return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:4px 8px 4px 0"><input type="hidden" name="action" value="ct_scan_admin_action"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="ct_scan_operation" value="' . esc_attr( $operation ) . '">' . $nonce . $extra . '<button class="button" type="submit">' . esc_html( $label ) . '</button></form>';
}

/** Offer final close only from an authenticated admin edit screen for a terminal job with pending metadata. */
function ct_scan_admin_add_final_close_metabox() {
	if ( ! current_user_can( 'manage_options' ) || ! function_exists( 'add_meta_box' ) ) {
		return;
	}
	add_meta_box( 'ct_scan_final_close', 'Scan request final closure', 'ct_scan_admin_render_final_close_metabox', 'ct_promo_request', 'side', 'high' );
}
add_action( 'add_meta_boxes_ct_promo_request', 'ct_scan_admin_add_final_close_metabox' );

function ct_scan_admin_render_final_close_metabox( $post ) {
	if ( ! current_user_can( 'manage_options' ) || ! is_object( $post ) || empty( $post->ID ) ) {
		return;
	}
	global $wpdb;
	$wpdb->last_error = '';
	$row = $wpdb->get_row( $wpdb->prepare(
		'SELECT job_id,status,created_at,terms_accepted_at,closed_at,closure_source,closed_by,closure_reason,report_delivered_at,report_notification_status,report_access_token_hash,report_access_expires_at,report_access_used_at FROM ' . ct_scan_jobs_table() . ' WHERE request_id = %d LIMIT 1',
		(int) $post->ID
	) );
	if ( '' !== (string) $wpdb->last_error || ! is_object( $row ) || ! in_array( $row->status, ct_scan_terminal_statuses(), true ) ) {
		return;
	}
	foreach ( array( 'created_at', 'terms_accepted_at', 'closed_at', 'closure_source', 'closed_by', 'closure_reason', 'report_delivered_at', 'report_notification_status', 'report_access_token_hash', 'report_access_expires_at', 'report_access_used_at' ) as $field ) {
		if ( ! property_exists( $row, $field ) ) {
			return;
		}
	}
	echo '<p>Report transport: ' . esc_html( sanitize_key( (string) $row->report_notification_status ) ) . '. Report delivered: ' . ( null !== $row->report_delivered_at ? esc_html( $row->report_delivered_at . ' UTC' ) : 'not confirmed' ) . '.</p>';
	if ( ct_scan_closure_metadata_trusted( $row ) ) {
		echo '<p>Final closure: ' . esc_html( $row->closure_source . ' at ' . $row->closed_at . ' UTC, actor ' . (int) $row->closed_by . ', reason ' . $row->closure_reason ) . '.</p>';
		return;
	}
	if ( null !== $row->closure_source || null !== $row->closed_by || null !== $row->closure_reason || null !== $row->report_delivered_at || null !== $row->report_access_used_at ) {
		echo '<p>Closure metadata is present but does not pass validation; leave the request pending for review.</p>';
		return;
	}
	if ( ! ct_scan_no_report_close_eligible( $row ) ) {
		echo '<p>The older report-delivery state is ambiguous. Leave this request pending until the delivery history is reconciled.</p>';
		return;
	}
	// The editor already has its own post form. Keep its controls and nonce ownership intact;
	// the private queue provides the independent authenticated, nonce-protected POST form.
	$url = admin_url( 'edit.php?post_type=ct_promo_request&page=ct-scan-queue' );
	echo '<p>Terminal status does not close the request. Review the delivery state and record an explicit no-report final closure in the private queue.</p>';
	echo '<p><a href="' . esc_url( $url ) . '">Open private queue to review final closure</a></p>';
}

/** One line summarizing a recorded manual authority review, for the admin queue. */
function ct_scan_control_evidence_line( $row ) {
	$evidence = json_decode( (string) $row->control_evidence, true );
	if ( ! is_array( $evidence ) ) {
		return 'unreadable';
	}
	return sprintf( '%s at %s UTC, valid until %s UTC: %s', (string) ( $evidence['reviewer'] ?? '?' ), (string) ( $evidence['reviewed_at'] ?? '?' ), (string) ( $evidence['valid_until'] ?? '?' ), (string) ( $evidence['evidence'] ?? '' ) );
}

function ct_scan_admin_result_details( $row ) {
	if ( ! is_object( $row ) || 'completed' !== $row->status || ! is_string( $row->result_json ) || '' === $row->result_json ) {
		return '';
	}
	$result = json_decode( $row->result_json, true );
	if ( JSON_ERROR_NONE !== json_last_error() || is_wp_error( ct_scan_validate_result( $result, $row, true ) ) ) {
		return '<p>Stored result failed its integrity and schema check.</p>';
	}
	$lines = array(
		'PHP2Shell status: ' . $result['php2shell_status'],
		'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : $result['php_version'] ),
		'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available' : $result['php2shell_fixed_version'] ),
		'Rules date: ' . $result['php2shell_rules_as_of'],
		'Exploitability: not tested; no exploit payloads were sent.',
	);
	$html = '<details><summary>Private stored PHP2Shell evidence and summary</summary><pre>' . esc_html( implode( "\n", $lines ) ) . '</pre>';
	foreach ( array( 'php_evidence' => 'Observed PHP evidence', 'php2shell_notes' => 'Assessment notes', 'php2shell_sources' => 'Assessment sources' ) as $key => $label ) {
		if ( empty( $result[ $key ] ) ) {
			continue;
		}
		$html .= '<p><strong>' . esc_html( $label ) . '</strong></p><ul>';
		foreach ( array_slice( $result[ $key ], 0, 20 ) as $entry ) {
			$html .= '<li><code>' . esc_html( $entry ) . '</code></li>';
		}
		$html .= '</ul>';
	}
	if ( '' !== $result['php2shell_recommendation'] ) {
		$html .= '<p><strong>Recommendation:</strong> ' . esc_html( $result['php2shell_recommendation'] ) . '</p>';
	}
	return $html . '</details>';
}

/** Private report/retention controls. Only authenticated administrators can see this queue. */
function ct_scan_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	ct_scan_maintain();
	global $wpdb;
	$table = ct_scan_jobs_table();
	$rows  = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC, job_id DESC LIMIT 100" );
	echo '<div class="wrap"><h1>PHP2Shell screening queue</h1>';
	echo '<p>Worker API: <strong>' . ( ct_scan_enabled() ? 'enabled' : 'disabled' ) . '</strong>. This page never displays the worker secret. The screening covers public passive evidence only; broader checks remain manual.</p>';
	if ( isset( $_GET['ct_scan_notice'] ) && is_string( $_GET['ct_scan_notice'] ) ) {
		$notice = sanitize_key( wp_unslash( $_GET['ct_scan_notice'] ) );
		$messages = array(
			'close_report_ambiguous' => 'Final close was not recorded: an earlier report-delivery state is ambiguous and needs reconciliation.',
			'close_already_recorded' => 'Final close was not recorded: closure or report delivery is already recorded.',
			'close_changed' => 'Final close was not recorded: the saved job changed while you reviewed it. Reload the queue and check the current state.',
			'hold_active' => 'Not changed: this job already has a preservation hold. A second hold cannot replace or shorten it; release the existing hold first, then place the new one.',
		);
		echo '<div class="notice notice-info"><p>' . esc_html( $messages[ $notice ] ?? $notice ) . '</p></div>';
	}
	if ( empty( $rows ) ) {
		echo '<p>No screening jobs are stored.</p></div>';
		return;
	}
	echo '<table class="widefat striped"><thead><tr><th>Job / request</th><th>Authorized scope and terms</th><th>Execution / final close</th><th>Confirmation / report</th><th>Manual remainder and actions</th></tr></thead><tbody>';
	foreach ( $rows as $row ) {
		$request_url = admin_url( 'post.php?post=' . (int) $row->request_id . '&action=edit' );
		$trusted_close = ct_scan_closure_metadata_trusted( $row );
		$closure = $trusted_close
			? $row->closure_source . ' at ' . $row->closed_at . ' UTC (actor ' . (int) $row->closed_by . ', reason ' . sanitize_key( $row->closure_reason ) . ')'
			: 'pending; terminal status or legacy timestamp is not final closure';
		$retain = ct_scan_valid_datetime( (string) $row->retain_until ) ? $row->retain_until . ' UTC' : 'pending / kept';
		$exec = 'Status: ' . sanitize_key( (string) $row->status )
			. "\nAttempts: " . (int) $row->attempts
			. "\nOutcome: " . ( $row->outcome ? sanitize_key( (string) $row->outcome ) : 'pending' )
			. "\nTarget control: " . ( ct_scan_control_required( $row ) ? ( $row->control_verified_at ? sanitize_key( (string) $row->control_method ) . ' at ' . $row->control_verified_at . ' UTC' : 'required, not shown (' . (int) $row->control_attempts . ' of 3 checks used)' ) : 'not required' )
			. "\nFinal close: " . $closure
			. "\nSigned-evidence deletion date: " . $retain
			. "\nError: " . ( $row->error_code ? sanitize_key( (string) $row->error_code ) : '—' )
			. ( 'manual_review' === $row->control_method ? "\nAuthority review: " . ct_scan_control_evidence_line( $row ) : '' )
			. "\nChecker revision: " . ( $row->checker_revision ? substr( (string) $row->checker_revision, 0, 12 ) . '…' : '—' );
		$delivery = $trusted_close && 'report_delivery' === $row->closure_source ? $row->report_delivered_at . ' UTC' : 'not confirmed';
		$link_state = is_string( $row->report_access_token_hash ) && 1 === preg_match( '/\A[a-f0-9]{64}\z/', $row->report_access_token_hash ) && ct_scan_valid_datetime( (string) $row->report_access_expires_at )
			? 'one-time link issued; expires ' . $row->report_access_expires_at . ' UTC'
			: 'no active one-time link';
		$mail = 'Confirmation email: ' . sanitize_key( (string) $row->confirmation_email_status )
			. "\nReport transport: " . sanitize_key( (string) $row->report_notification_status )
			. "\nReport delivery: " . $delivery
			. "\nReport access: " . $link_state
			. "\nRevoked: " . ( $row->revoked_at ? $row->revoked_at . ' UTC' : 'no' );
		echo '<tr><td><a href="' . esc_url( $request_url ) . '">Job #' . (int) $row->job_id . ' / request #' . (int) $row->request_id . '</a><br>Created ' . esc_html( (string) $row->created_at ) . ' UTC</td>';
		echo '<td><code>' . esc_html( (string) $row->target_origin ) . '</code><br>Terms ' . esc_html( (string) $row->terms_version ) . '<br>Accepted ' . esc_html( (string) $row->terms_accepted_at ) . ' UTC<br>Expires ' . esc_html( (string) $row->authorization_expires_at ) . ' UTC<br>Scope hash <code>' . esc_html( substr( (string) $row->scope_hash, 0, 16 ) ) . '…</code></td>';
		echo '<td><pre>' . esc_html( $exec ) . '</pre>' . ct_scan_admin_result_details( $row ) . '</td><td><pre>' . esc_html( $mail ) . '</pre></td><td>';
		if ( is_string( $row->manual_remainder_notes ) && '' !== $row->manual_remainder_notes ) {
			echo '<details><summary>Manual remainder (' . esc_html( sanitize_key( (string) $row->manual_remainder_status ) ) . ')</summary><pre>' . esc_html( (string) $row->manual_remainder_notes ) . '</pre></details>';
		}
		$closure_pending = null === $row->closure_source && null === $row->closed_by && null === $row->closure_reason && null === $row->report_delivered_at && null === $row->report_access_used_at;
		if ( ct_scan_terminal_status( $row->status ) && $closure_pending ) {
			$notes = esc_textarea( (string) $row->manual_remainder_notes );
			if ( empty( $row->revoked_at ) && in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
				$extra = '<br><textarea name="manual_remainder_notes" rows="4" cols="42" maxlength="12000" placeholder="Record the remaining checks, limitations, and any omitted checks.">' . $notes . '</textarea><br><label><input type="checkbox" name="ct_scan_review_confirm" value="1" required> I reviewed these manual findings and limitations.</label> ';
				echo ct_scan_admin_form( (int) $row->job_id, 'manual_complete', 'Save manual remainder', $extra );
			}
			$preview = ct_scan_build_report_body( $row );
			if ( ! is_wp_error( $preview ) ) {
				echo '<details><summary>Reviewed customer report preview</summary><pre>' . esc_html( $preview ) . '</pre></details>';
				if ( empty( $row->revoked_at ) && in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
					echo ct_scan_admin_form( (int) $row->job_id, 'send_report', 'Email one-time report link', '<label><input type="checkbox" name="ct_scan_send_confirm" value="1" required> Send a one-time link to the saved, confirmed email contact.</label> ' );
				}
			} elseif ( 'complete' === $row->manual_remainder_status ) {
				echo '<p>' . esc_html( $preview->get_error_message() ) . '</p>';
			}
			if ( ct_scan_no_report_close_eligible( $row ) ) {
				$reason = (string) $row->status;
				$extra = '<input type="hidden" name="ct_scan_close_reason" value="' . esc_attr( $reason ) . '"><label><input type="checkbox" name="ct_scan_final_close_confirm" value="1" required> I reviewed the report-delivery state and confirm no report was delivered before final closure (' . esc_html( $reason ) . ').</label> ';
				echo ct_scan_admin_form( (int) $row->job_id, 'final_close', 'Record no-report final close', $extra );
			} else {
				echo '<p>Final close is unavailable: the earlier report-delivery state is ambiguous or needs reconciliation.</p>';
			}
		}
		if ( 'awaiting_control' === $row->status && empty( $row->revoked_at ) ) {
			echo ct_scan_admin_form( (int) $row->job_id, 'authority_review', 'Record authority review', '<br><textarea name="ct_scan_authority_note" rows="3" cols="42" maxlength="1000" placeholder="Evidence reviewed that this client controls this exact website (who, what, when)."></textarea><br><label><input type="checkbox" name="ct_scan_authority_confirm" value="1" required> I reviewed evidence that this client controls the exact website above.</label> ' );
		}
		$on_hold = ct_scan_job_on_hold( $row, ct_scan_utc_now() );
		if ( $on_hold && empty( $row->hold_released_at ) ) {
			echo '<p>Preservation hold until ' . esc_html( (string) $row->hold_until ) . ' UTC: ' . esc_html( (string) $row->hold_reason ) . '</p>' . ct_scan_admin_form( (int) $row->job_id, 'release_hold', 'Release hold', '<input type="hidden" name="ct_scan_hold_identity" value="' . esc_attr( ct_scan_hold_identity( $row ) ) . '"><label><input type="checkbox" name="ct_scan_hold_release_confirm" value="1" required> Release this hold.</label> ' );
		} else {
			if ( $on_hold ) {
				echo '<p>Preservation hold released ' . esc_html( (string) $row->hold_released_at ) . ' UTC (records kept for a further ' . (int) ct_scan_hold_grace_days() . ' days): ' . esc_html( (string) $row->hold_reason ) . '</p>';
			}
			echo ct_scan_admin_form( (int) $row->job_id, 'set_hold', 'Place preservation hold', '<br><input type="text" name="ct_scan_hold_reason" maxlength="190" size="40" placeholder="Narrow purpose, e.g. dispute #123 about this job"> <input type="number" name="ct_scan_hold_days" min="1" max="730" value="90"> days<br><label><input type="checkbox" name="ct_scan_hold_confirm" value="1" required> Preserve this job’s records for this stated purpose only.</label> ' );
		}
		if ( empty( $row->revoked_at ) && empty( $row->report_delivered_at ) ) {
			echo ct_scan_admin_form( (int) $row->job_id, 'revoke', 'Revoke authorization', '<label><input type="checkbox" name="ct_scan_revoke_confirm" value="1" required> Revoke this request and block further execution or report access.</label> ' );
		}
		echo '</td></tr>';
	}
	echo '</tbody></table></div>';
}

function ct_scan_register_admin_menu() {
	add_submenu_page( 'edit.php?post_type=ct_promo_request', 'PHP2Shell screening queue', 'PHP2Shell queue', 'manage_options', 'ct-scan-queue', 'ct_scan_admin_page' );
}
add_action( 'admin_menu', 'ct_scan_register_admin_menu', 30 );

function ct_scan_add_request_meta_box() {
	add_meta_box( 'ct-scan-request-status', 'PHP2Shell screening', 'ct_scan_request_meta_box', 'ct_promo_request', 'side', 'high' );
}
add_action( 'add_meta_boxes_ct_promo_request', 'ct_scan_add_request_meta_box' );

function ct_scan_request_meta_box( $post ) {
	if ( ! is_object( $post ) || empty( $post->ID ) ) {
		return;
	}
	$job_id = absint( get_post_meta( $post->ID, '_ct_scan_job_id', true ) );
	$row = $job_id ? ct_scan_row( $job_id ) : null;
	if ( ! $row ) {
		echo '<p>No scan job is linked to this request.</p>';
		return;
	}
	$close_state = ct_scan_closure_metadata_trusted( $row )
		? $row->closure_source . ' at ' . $row->closed_at . ' UTC'
		: 'pending / unverified';
	$delivery = ct_scan_closure_metadata_trusted( $row ) && 'report_delivery' === $row->closure_source
		? $row->report_delivered_at . ' UTC'
		: 'not confirmed';
	echo '<p>Status: <strong>' . esc_html( (string) $row->status ) . '</strong></p><p>Target: <code>' . esc_html( (string) $row->target_origin ) . '</code></p><p>Terms: ' . esc_html( (string) $row->terms_version ) . ' / <code>' . esc_html( substr( (string) $row->terms_hash, 0, 16 ) ) . '…</code></p><p>Confirmation email: ' . esc_html( (string) $row->confirmation_email_status ) . '</p><p>Attempts: ' . (int) $row->attempts . ' · report transport: ' . esc_html( (string) $row->report_notification_status ) . '</p><p>Report delivery: ' . esc_html( $delivery ) . '</p><p>Final close: ' . esc_html( $close_state ) . '</p><p><a href="' . esc_url( admin_url( 'edit.php?post_type=ct_promo_request&page=ct-scan-queue' ) ) . '">Open private queue</a></p>';
}
