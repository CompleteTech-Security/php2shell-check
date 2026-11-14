<?php
// Pure WordPress API doubles only: no bootstrap, database, DNS, HTTP or mail.
define( 'ABSPATH', __DIR__ );
define( 'WP_CONTENT_DIR', __DIR__ . '/absent-private-config' );
class WP_Error { private $code; function __construct( $code = '', $message = '' ) { $this->code = $code; } function get_error_code() { return $this->code; } }
function is_wp_error( $v ) { return $v instanceof WP_Error; }
function add_action( ...$args ) {}
function wp_parse_url( $v ) { return parse_url( $v ); }
function wp_json_encode( $v, $flags = 0 ) { return json_encode( $v, $flags ); }
function get_post_meta( $id, $key, $single = true ) { $v = $GLOBALS['meta'][$id][$key] ?? array(); return $single ? ( $v[0] ?? '' ) : $v; }
function sanitize_text_field( $v ) { return trim( strip_tags( $v ) ); }
class ExternalDb {
 public $prefix = 'wp_'; public $row; public $fail = false; public $updates = 0;
 function update( $table, $data, $where, $format = null, $where_format = null ) {
  if ( $this->fail ) { return 0; }
  foreach ( $where as $key => $value ) { if ( (string) ( $this->row->$key ?? '' ) !== (string) $value ) { return 0; } }
  foreach ( $data as $key => $value ) { $this->row->$key = $value; }
  ++$this->updates; return 1;
 }
}
require dirname( __DIR__ ) . '/ct-scan.php';
$n = 0;
function check( $condition, $message ) { global $n; if ( ! $condition ) { fwrite( STDERR, 'FAIL: ' . $message . "\n" ); exit( 1 ); } ++$n; }
function row_fixture() {
 return (object) array( 'job_id' => 1, 'status' => 'running', 'lease_hash' => str_repeat( 'a', 64 ), 'target_origin' => 'https://fixture.example.net/', 'profile_id' => 'external-web-v1', 'profile_sha256' => ct_scan_external_profile_digest(), 'services_json' => '[{"port":443,"scheme":"https"}]', 'http_admitted' => 0, 'tls_admitted' => 0, 'reserved_body_bytes' => 0, 'reserved_active_ms' => 0, 'reservation_version' => 1, 'last_admit_ms' => null, 'inflight_until_ms' => null, 'started_at' => '2026-11-14 00:00:00' );
}
function result_fixture( $row ) {
 $r = array( 'input_url' => $row->target_origin, 'final_url' => $row->target_origin, 'status' => 'no_evidence', 'fetch_status' => 'ok', 'http_status' => 200, 'wordpress_version' => '', 'php_version' => '', 'server' => '', 'powered_by' => '', 'title' => '', 'evidence' => array(), 'asset_version_hints' => array(), 'notes' => array(), 'checked_at' => '2026-11-14T00:00:00Z', 'php_version_candidates' => array(), 'php_evidence' => array(), 'php2shell_status' => 'unknown', 'php2shell_version_status' => 'version_not_disclosed', 'php2shell_fixed_version' => '', 'php2shell_exploitability' => 'not_tested', 'php2shell_cves' => array( 'CVE-2026-109618', 'CVE-2026-109619' ), 'php2shell_rules_as_of' => '2026-10-21', 'php2shell_sources' => array( 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w', 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp', 'https://ubuntu.com/security/notices/USN-8948-1' ), 'php2shell_notes' => array( 'Passive metadata only. Runtime SAPI, vendor backports, configuration, and exploitability are not verified.', 'No public PHP version was disclosed; lack of a header does not establish that PHP is absent.' ), 'php2shell_recommendation' => 'Ask the site administrator to verify the deployed PHP package and applicable vendor security updates.' );
 $r = array_merge( $r, ct_scan_job_profile_fields( $row ) );
 $r['checks'] = array(
  array( 'id' => 'robots_policy', 'service' => 'https:443', 'outcome' => 'observed', 'evidence' => array( 'http_status' => 200, 'allowed' => true ) ),
  array( 'id' => 'public_header_triage', 'service' => 'https:443', 'outcome' => 'observed', 'evidence' => array( 'http_status' => 200, 'fetch_status' => 'ok' ) ),
  array( 'id' => 'security_header_presence', 'service' => 'https:443', 'outcome' => 'observed', 'evidence' => array( 'http_status' => 200, 'hsts' => true, 'csp' => false, 'frame_control' => true, 'mime_options' => false ) ),
  array( 'id' => 'tls_certificate', 'service' => 'https:443', 'outcome' => 'observed', 'evidence' => array( 'verification' => 'verified', 'protocol' => 'TLSv1.3', 'not_after' => '2027-01-01T00:00:00Z' ) ),
 );
 $r['manual_remainder'] = array(); foreach ( array( 'runtime_and_backport_confirmation', 'internal_configuration_review', 'compromise_investigation' ) as $id ) { $r['manual_remainder'][] = array( 'id' => $id, 'status' => 'not_assessed' ); } return $r;
}
$row = row_fixture(); $binding = ct_scan_job_profile_fields( $row );
check( false !== ct_scan_external_profile_manifest(), 'exact immutable manifest loads' );
check( 'r2-header-v1' === ct_scan_current_profile() && false === ct_scan_config()['enabled'], 'legacy remains disabled default' );
check( 3 === count( $binding ) && 443 === $binding['services'][0]['port'], 'external claim has exact additive binding' );
$legacy = clone $row; $legacy->profile_id = 'r2-header-v1'; check( array() === ct_scan_job_profile_fields( $legacy ), 'legacy claim has no new fields' );
$bad = clone $row; $bad->profile_sha256 = str_repeat( '0', 64 ); check( false === ct_scan_job_profile_fields( $bad ), 'digest tamper refuses claim' );
check( false === ct_scan_external_services( array( array( 'scheme' => 'http', 'port' => 80 ) ), $row->target_origin ), 'primary service cannot be omitted' );
$base = array( 'id' => 1, 'lease' => str_repeat( 'a', 64 ), 'scope_hash' => str_repeat( 'b', 64 ), 'outcome' => 'completed', 'result' => array(), 'error' => '', 'checker_revision' => str_repeat( 'c', 40 ) );
check( ct_scan_result_profile_matches( array_merge( $base, $binding ), $row ), 'callback exact binding accepted' );
check( ! ct_scan_result_profile_matches( $base, $row ), 'external callback cannot shed binding' );
check( ct_scan_result_profile_matches( $base, $legacy ), 'legacy callback unchanged' );
check( ! ct_scan_result_profile_matches( array_merge( $base, $binding ), $legacy ), 'legacy cannot gain external binding' );
$valid = result_fixture( $row ); check( ! is_wp_error( ct_scan_validate_result( $valid, $row ) ), 'typed external result accepted' );
foreach ( array( 'title', 'server', 'powered_by', 'wordpress_version' ) as $key ) { $bad = $valid; $bad[$key] = 'RAW PRIVATE'; check( is_wp_error( ct_scan_validate_result( $bad, $row ) ), 'raw text refused ' . $key ); }
foreach ( array( 'evidence', 'notes', 'asset_version_hints', 'php_evidence' ) as $key ) { $bad = $valid; $bad[$key] = array( 'RAW PRIVATE' ); check( is_wp_error( ct_scan_validate_result( $bad, $row ) ), 'raw list refused ' . $key ); }
foreach ( array(
 'missing check' => function ( &$r ) { array_pop( $r['checks'] ); },
 'duplicate check' => function ( &$r ) { $r['checks'][1] = $r['checks'][0]; },
 'unselected service' => function ( &$r ) { $r['checks'][0]['service'] = 'http:80'; },
 'raw interpretation' => function ( &$r ) { $r['php2shell_notes'] = array( 'RAW PRIVATE' ); },
 'raw recommendation' => function ( &$r ) { $r['php2shell_recommendation'] = 'RAW PRIVATE'; },
 'raw source' => function ( &$r ) { $r['php2shell_sources'][] = 'https://secret.invalid/'; },
 'unknown evidence' => function ( &$r ) { $r['checks'][0]['evidence']['secret'] = 'raw'; },
 'boolean status' => function ( &$r ) { $r['checks'][0]['evidence']['http_status'] = true; },
 'unknown TLS' => function ( &$r ) { $r['checks'][3]['evidence']['protocol'] = 'raw'; },
 'invalid TLS date' => function ( &$r ) { $r['checks'][3]['evidence']['not_after'] = '2027-02-31T00:00:00Z'; },
 'manual assessment' => function ( &$r ) { $r['manual_remainder'][0]['status'] = 'safe'; },
 'extra schema' => function ( &$r ) { $r['secret'] = true; },
 'unaccepted redirect' => function ( &$r ) { $r['final_url'] = 'http://fixture.example.net/'; },
) as $label => $change ) { $bad = $valid; $change( $bad ); check( is_wp_error( ct_scan_validate_result( $bad, $row ) ), $label . ' refused' ); }
$core = $valid; foreach ( array( 'profile_id', 'profile_sha256', 'services', 'checks', 'manual_remainder' ) as $key ) { unset( $core[$key] ); }
check( ! is_wp_error( ct_scan_validate_result( $core, $legacy ) ), 'legacy result schema unchanged' );
check( is_wp_error( ct_scan_validate_result( $core, $row ) ), 'external result cannot use legacy schema' );
$now = strtotime( '2026-11-14 00:00:00 UTC' ) * 1000;
$GLOBALS['wpdb'] = new ExternalDb(); $GLOBALS['wpdb']->row = clone $row;
$decision = ct_scan_external_admit_locked( clone $GLOBALS['wpdb']->row, array( 'kind' => 'http' ), $now );
check( 200 === $decision[0] && 262144 === $GLOBALS['wpdb']->row->reserved_body_bytes && 10000 === $GLOBALS['wpdb']->row->reserved_active_ms, 'HTTP reservation durably charged before grant' );
check( 11 === count( $decision[1] ) && 99 === $decision[1]['http_remaining'], 'exact grant schema' );
check( 429 === ct_scan_external_admit_locked( clone $GLOBALS['wpdb']->row, array( 'kind' => 'tls' ), $now + 1000 )[0], 'inflight connection cannot overlap' );
check( 200 === ct_scan_external_admit_locked( clone $GLOBALS['wpdb']->row, array( 'kind' => 'tls' ), $now + 11000 )[0], 'separate TLS reservation accepted after prior timeout' );
check( 1 === $GLOBALS['wpdb']->row->tls_admitted && 262144 === $GLOBALS['wpdb']->row->reserved_body_bytes, 'TLS never refunds or consumes body' );
foreach ( array( true, -1, '00', '1e2', null, 101 ) as $value ) { $bad = clone $row; $bad->http_admitted = $value; check( 410 === ct_scan_external_admit_locked( $bad, array( 'kind' => 'http' ), $now )[0], 'malformed counter refuses' ); }
$bad = clone $row; $bad->http_admitted = 20; $bad->reserved_body_bytes = 5242880; $bad->reserved_active_ms = 200000; $bad->last_admit_ms = $now; $bad->inflight_until_ms = $now + 11000;
check( 409 === ct_scan_external_admit_locked( $bad, array( 'kind' => 'http' ), $now + 11000 )[0], 'aggregate body ceiling cannot be reset' );
$GLOBALS['wpdb']->fail = true;
check( 503 === ct_scan_external_admit_locked( clone $row, array( 'kind' => 'http' ), $now )[0], 'failed CAS grants nothing' );
echo 'PASS ' . $n . " external-profile source checks; no WordPress/database/network/mail execution\n";
