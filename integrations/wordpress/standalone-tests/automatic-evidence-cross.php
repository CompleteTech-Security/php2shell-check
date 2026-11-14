<?php
// Cross-source frozen readback fixture. Actual G1 and G2 code, synthetic WP stores.
// No WordPress bootstrap, queue creation, database, network or mail execution.
$g2 = getenv( 'CT_AUTO_CROSS_G2_ROOT' );
$release_path = getenv( 'CT_AUTO_CROSS_RELEASE' );
if ( ! $g2 || ! $release_path ) { fwrite( STDERR, "Provide explicit G2 source root and SYNTHETIC release path.\n" ); exit( 2 ); }
require __DIR__ . '/external-profile.php';
function clean_post_cache( $id ) {}
function get_post( $id ) { return $GLOBALS['posts'][$id] ?? null; }
function get_posts( $args ) { return array(); }
function sanitize_email( $v ) { return filter_var( $v, FILTER_SANITIZE_EMAIL ); }
function is_email( $v ) { return false !== filter_var( $v, FILTER_VALIDATE_EMAIL ); }
function sanitize_title( $v ) { return strtolower( preg_replace( '/[^a-z0-9-]/i', '', $v ) ); }
function wp_slash( $v ) { return is_array( $v ) ? array_map( 'wp_slash', $v ) : ( is_string( $v ) ? addslashes( $v ) : $v ); }
function wp_unslash( $v ) { return is_array( $v ) ? array_map( 'wp_unslash', $v ) : ( is_string( $v ) ? stripslashes( $v ) : $v ); }
function add_post_meta( $id, $key, $value, $unique = false ) { if ( $unique && isset( $GLOBALS['meta'][$id][$key] ) ) { return false; } $GLOBALS['meta'][$id][$key][] = wp_unslash( $value ); return true; }
require $g2 . '/mu-plugins/ct-auto-scan-authorization.php';
require $g2 . '/mu-plugins/ct-auto-scan-persistence.php';
$raw = file_get_contents( $release_path );
$release = ct_auto_scan_decode_release_snapshot_v1( $raw, hash( 'sha256', $raw ) );
check( ! is_wp_error( $release ), 'actual route decoder validates actual generator SYNTHETIC bundle' );
$b = $release['bundle']; $now = time();
$e = array(
 'release_sha256' => hash( 'sha256', $raw ), 'release_snapshot' => $raw,
 'terms_version' => $b['release']['terms_version'], 'terms_html' => $b['terms']['html'], 'terms_sha256' => $b['terms']['sha256'], 'acceptance_statement' => $b['copy']['acceptance_statement'],
 'profile_id' => 'external-web-v1', 'profile_sha256' => $b['profile']['sha256'], 'profile_snapshot' => $b['profile']['manifest_json'],
 'scope_services' => array( array( 'port' => 443, 'scheme' => 'https' ) ), 'scope_services_json' => '[{"port":443,"scheme":"https"}]',
 'target' => 'https://fixture.example.net/', 'legal_name' => "R&D Café O'Connor LLC", 'signer_name' => 'Zoë & Renée', 'signer_role' => "Owner's authorized representative", 'typed_signature' => 'Zoë & Renée', 'email' => 'fixture@example.net', 'referrer' => 'direct',
 'summary_text' => '', 'summary_sha256' => '', 'expires_at_utc' => gmdate( 'Y-m-d\TH:i:s\Z', $now + 3600 ), 'accepted_at_utc' => gmdate( 'Y-m-d\TH:i:s\Z', $now ),
 'idempotency_key' => hash( 'sha256', 'SYNTHETIC cross-source idempotency' ), 'evidence_sha256' => '', 'review_id' => hash( 'sha256', 'SYNTHETIC cross-source review' ), 'review_issued_at_utc' => gmdate( 'Y-m-d\TH:i:s\Z', $now - 10 ), 'review_expires_at_utc' => gmdate( 'Y-m-d\TH:i:s\Z', $now + 590 ),
);
$e['summary_text'] = ct_scan_target_summary( $e['target'], $e['legal_name'], $e['signer_name'], $e['signer_role'], $e['email'], $e['profile_id'], $e['scope_services'], $e['expires_at_utc'] );
$e['summary_sha256'] = hash( 'sha256', $e['summary_text'] ); $e['evidence_sha256'] = ct_auto_scan_envelope_sha256( $e );
check( ! is_wp_error( ct_auto_persist_validate_envelope( $e ) ), 'actual G2 validates full Unicode envelope against actual G1 summary/digests' );
$t = array( 'client_ip' => '198.51.100.7', 'remote_addr' => '198.51.100.7', 'ip_source' => 'remote_addr', 'user_agent' => 'Synthetic offline cross fixture', 'idempotency_key' => $e['idempotency_key'], 'evidence_sha256' => $e['evidence_sha256'], 'accepted_at_utc' => $e['accepted_at_utc'] );
$context = array( 'schema_version' => 1, 'envelope' => $e, 'technical' => $t, 'terms_url' => 'https://fixture.example.net/agreement/' );
$body = ct_auto_persist_body( $context );
$kses = getenv( 'CT_AUTO_CROSS_KSES' );
if ( $kses ) { require_once $kses; $normalized = wp_kses_normalize_entities( $body ); check( $body === $normalized, 'actual WP entity normalizer preserves escaped Unicode/ampersand body' ); $body = $normalized; }
$GLOBALS['posts'][101] = (object) array( 'ID' => 101, 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_name' => 'ct-auto-' . $e['idempotency_key'], 'post_content' => $body );
check( true === ct_auto_persist_readback( 101, $context, true ), 'actual G2 writes and byte-checks all immutable fields into WP API doubles' );
$fields = array( 'target' => $e['target'], 'email' => $e['email'], 'name' => $e['signer_name'], 'referrer' => $e['referrer'] );
$frozen = array( 'bound_required' => true, 'profile' => 'external-web-v1', 'profile_sha256' => $e['profile_sha256'], 'services_json' => $e['scope_services_json'] );
$expiry = gmdate( 'Y-m-d H:i:s', $now + 3600 );
$check_request = function () use ( $fields, $frozen, $expiry ) { return ct_scan_validate_saved_request( 101, $fields, false, $expiry, $frozen ); };
$accepted = $check_request();
check( ! is_wp_error( $accepted ), 'actual G1 independently validates actual G2 retained envelope, post and metadata' . ( is_wp_error( $accepted ) ? ': ' . $accepted->get_error_code() : '' ) );
check( $accepted['legal_name'] === $e['legal_name'] && $accepted['signer_name'] === $e['signer_name'] && $accepted['authorization_expires'] === $expiry, 'Unicode legal identity and exact signed expiry survive readback' );
check( ct_scan_automatic_copy_v1( 101, 'email_queued' ) === $b['copy']['email_queued'], 'actual copy provider reads frozen release while activation remains off' );
$original = $GLOBALS['meta'][101]; $original_body = $GLOBALS['posts'][101]->post_content;
foreach ( array( '_ct_terms_profile_sha256', '_ct_terms_scope_services', '_ct_terms_authorization_expires_at', '_ct_summary_text', '_ct_terms_typed_signature', '_ct_auto_technical_snapshot', '_ct_auto_envelope' ) as $key ) {
 $GLOBALS['meta'][101] = $original; $GLOBALS['meta'][101][$key][0] .= 'tamper'; check( is_wp_error( $check_request() ), 'actual core refuses changed immutable ' . $key );
}
$GLOBALS['meta'][101] = $original; $GLOBALS['meta'][101]['_ct_terms_signer_name'][] = $e['signer_name']; check( is_wp_error( $check_request() ), 'actual core refuses duplicate signer evidence' );
$GLOBALS['meta'][101] = $original; $GLOBALS['posts'][101]->post_content .= '<p>injected</p>'; check( is_wp_error( $check_request() ), 'actual core refuses changed post representation' );
$GLOBALS['posts'][101]->post_content = $original_body;
$wrong = $frozen; $wrong['services_json'] = '[{"port":80,"scheme":"http"}]'; check( is_wp_error( ct_scan_validate_saved_request( 101, $fields, false, $expiry, $wrong ) ), 'actual core refuses changed frozen job service' );
check( false === ct_scan_config()['enabled'] && ! defined( 'CT_AUTO_SCAN_AUTH_ENABLED' ), 'cross-source validation never activates route or queue' );
echo 'PASS ' . $n . " aggregate external/cross-source checks; synthetic WP stores only, no acceptance/queue/database/mail/network execution\n";
