<?php
/**
 * Disposable database fixture for the external reservation primitive only.
 * Uses an owned R2 fixture row relabelled with explicit synthetic external bindings;
 * this is NOT an external authorization, route/worker integration or a scan.
 */
require __DIR__ . '/support.php';
global $wpdb;
ct_test_purge_fixtures();
add_filter( 'pre_wp_mail', '__return_true' );
$columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . ct_scan_jobs_table(), 0 );
foreach ( array( 'profile_sha256', 'services_json', 'tls_admitted', 'reserved_body_bytes', 'reserved_active_ms', 'inflight_until_ms', 'reservation_version' ) as $column ) {
 ct_test_assert( in_array( $column, $columns, true ), 'Missing external reservation column ' . $column );
}
ct_test_assert( '9' === CT_SCAN_SCHEMA_VERSION && CT_SCAN_SCHEMA_VERSION === get_option( 'ct_scan_schema_version' ), 'Schema9 upgrade incomplete.' );
ct_test_assert( false !== ct_scan_external_profile_manifest(), 'Reviewed immutable external manifest unavailable.' );
$fixture = ct_test_running_job( 'external-reservation.example.net' );
$id = $fixture['job_id'];
try {
 ct_test_assert( ct_scan_lock_acquire(), 'Cannot own reservation fixture queue lock.' );
 try {
  $now = (int) floor( microtime( true ) * 1000 );
  $services = wp_json_encode( ct_scan_canonicalize( array( array( 'port' => 443, 'scheme' => 'https' ) ) ), JSON_UNESCAPED_SLASHES );
  ct_test_assert( 1 === $wpdb->update( ct_scan_jobs_table(), array( 'profile_id' => 'external-web-v1', 'profile_sha256' => ct_scan_external_profile_digest(), 'services_json' => $services, 'reservation_version' => 1, 'started_at' => gmdate( 'Y-m-d H:i:s', (int) floor( $now / 1000 ) ) ), array( 'job_id' => $id ) ), 'Cannot prepare owned synthetic profile row.' );
  $before = ct_scan_row( $id );
  $grant = ct_scan_external_admit_locked( $before, array( 'kind' => 'http' ), $now );
  $after = ct_scan_row( $id );
  ct_test_assert( 200 === $grant[0] && 1 === (int) $after->http_admitted && 262144 === (int) $after->reserved_body_bytes && 10000 === (int) $after->reserved_active_ms, 'Database did not commit reservations before grant.' );
  ct_test_assert( 503 === ct_scan_external_admit_locked( $before, array( 'kind' => 'http' ), $now )[0] && 1 === (int) ct_scan_row( $id )->http_admitted, 'Stale concurrent CAS granted or recharged a reservation.' );
  ct_test_assert( 429 === ct_scan_external_admit_locked( $after, array( 'kind' => 'tls' ), $now + 1000 )[0], 'An inflight HTTP reservation overlapped TLS.' );
  $tls = ct_scan_external_admit_locked( $after, array( 'kind' => 'tls' ), $now + 11000 );
  $after = ct_scan_row( $id );
  ct_test_assert( 200 === $tls[0] && 1 === (int) $after->tls_admitted && 262144 === (int) $after->reserved_body_bytes && 20000 === (int) $after->reserved_active_ms, 'TLS reservation did not preserve cumulative database body charge.' );
  $bad = clone $after; $bad->reserved_body_bytes = 0;
  ct_test_assert( 410 === ct_scan_external_admit_locked( $bad, array( 'kind' => 'http' ), $now + 22000 )[0], 'Inconsistent restored reservation state received new budget.' );
  $bad = clone $after; $bad->reservation_version = 0;
  ct_test_assert( 410 === ct_scan_external_admit_locked( $bad, array( 'kind' => 'http' ), $now + 22000 )[0], 'Legacy row was silently promoted to external reservation protocol.' );
 } finally { ct_scan_lock_release(); }
} finally { ct_test_purge_fixtures(); }
echo "External reservation database fixture passed; no external authorization or target traffic.\n";
