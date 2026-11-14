<?php
// Standalone retention-policy regression test. No WordPress bootstrap, database, or network.
// Usage: php tests/ct-scan-retention.php mu-plugins/ct-scan.php
define( 'ABSPATH', __DIR__ );
define( 'DB_NAME', 'ct-scan-test' );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/ct-scan-retention-test-' . getmypid() );

class WP_Error {
}

function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_option( $key, $default = false ) { return $default; }
function update_option( ...$args ) { return true; }
function delete_option( ...$args ) { return true; }
function wp_salt( $scheme = 'auth' ) { return 'synthetic-retention-salt'; }

require $argv[1];

function retention_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function retention_plus_days( $value, $days ) {
	return ( new DateTimeImmutable( $value, new DateTimeZone( 'UTC' ) ) )->modify( '+' . (int) $days . ' days' )->format( 'Y-m-d H:i:s' );
}

function retention_plus_years( $value, $years ) {
	return ( new DateTimeImmutable( $value, new DateTimeZone( 'UTC' ) ) )->modify( '+' . (int) $years . ' years' )->format( 'Y-m-d H:i:s' );
}

$accepted = '2024-01-14 12:30:00';
$closed   = '2024-01-15 12:30:00';
$delivery = '2025-04-01 09:00:00';

$admin_closed = (object) array(
	'terms_version'      => '2026-11-13-r3',
	'terms_accepted_at'  => $accepted,
	'created_at'         => $accepted,
	'status'             => 'completed',
	'closed_at'          => $closed,
	'closure_source'     => 'admin_final_close',
	'closed_by'          => 42,
	'closure_reason'     => 'completed',
	'report_delivered_at'=> null,
	'report_access_used_at' => null,
);

$report_delivered = (object) array(
	'terms_version'      => '2026-11-13-r3',
	'terms_accepted_at'  => $accepted,
	'created_at'         => $accepted,
	'status'             => 'completed',
	'closed_at'          => $delivery,
	'closure_source'     => 'report_delivery',
	'closed_by'          => 0,
	'closure_reason'     => 'report_delivered',
	'report_delivered_at'=> $delivery,
	'report_access_used_at' => $delivery,
);

retention_assert(
	retention_plus_days( $delivery, 366 ) === ct_scan_findings_retain_until( $report_delivered ),
	'Findings/reports were not retained for 366 days after the confirmed report-delivery timestamp.'
);

retention_assert(
	retention_plus_days( $closed, 366 ) === ct_scan_findings_retain_until( $admin_closed ),
	'Undelivered findings/reports were not retained for 366 days after explicit final close.'
);

retention_assert(
	retention_plus_years( $closed, 6 ) === ct_scan_retain_until( $admin_closed ),
	'Future-version signed evidence was not retained for six years after trusted final close.'
);

$legacy = (object) array(
	'terms_version'     => '2026-10-21-r2',
	'terms_accepted_at' => $accepted,
	'created_at'        => $accepted,
	'status'            => 'completed',
	'closed_at'         => null,
	'closure_source'    => null,
	'closed_by'         => null,
	'closure_reason'    => null,
	'report_delivered_at' => null,
	'report_access_used_at' => null,
);

retention_assert(
	retention_plus_years( $accepted, 3 ) === ct_scan_retain_until( $legacy ),
	'r2-or-earlier signed evidence was not retained for three years from acceptance.'
);

// Terminal status and finished_at are evidence that work stopped, not an explicit final closure.
$terminal_but_open = (object) array(
	'terms_version'      => '2026-11-13-r3',
	'terms_accepted_at'  => $accepted,
	'created_at'         => $accepted,
	'status'             => 'completed',
	'finished_at'        => $closed,
	'closed_at'          => null,
	'closure_source'     => null,
	'closed_by'          => null,
	'closure_reason'     => null,
	'report_delivered_at'=> null,
	'report_access_used_at' => null,
);

retention_assert( false === ct_scan_retain_until( $terminal_but_open ), 'A terminal status/finished_at was treated as explicit final close.' );
retention_assert( false === ct_scan_findings_retain_until( $terminal_but_open ), 'Findings got a deadline before explicit final close or report delivery.' );
$legacy_terminal = (object) array_merge(
	(array) $terminal_but_open,
	array(
		'closed_at'              => $closed, // a pre-v8 maintenance timestamp
		'retain_until'           => '2025-01-15 12:30:00',
		'identity'               => str_repeat( 'a', 32 ),
		'result_json'            => '{"finding":"synthetic"}',
		'manual_remainder_notes' => 'synthetic finding',
		'hold_reason'            => null,
		'hold_until'             => null,
	)
);
retention_assert(
	array( 'keep', null ) === ct_scan_deletion_decision( $legacy_terminal, '2026-01-16 00:00:00' ),
	'A legacy maintenance timestamp allowed a current-version job and findings to be deleted without a trusted closure event.'
);

foreach ( array(
	(object) array_merge( (array) $admin_closed, array( 'closure_source' => null, 'closed_by' => null, 'closure_reason' => null ) ),
	(object) array_merge( (array) $admin_closed, array( 'closed_by' => 0 ) ),
	(object) array_merge( (array) $admin_closed, array( 'closure_reason' => 'other' ) ),
	(object) array_merge( (array) $admin_closed, array( 'closure_reason' => 'failed' ) ),
	(object) array_merge( (array) $admin_closed, array( 'closed_at' => '2024-01-13 12:30:00' ) ),
	(object) array_merge( (array) $admin_closed, array( 'closed_at' => gmdate( 'Y-m-d H:i:s', time() + 3600 ) ) ),
	(object) array_merge( (array) $report_delivered, array( 'closed_by' => null ) ),
	(object) array_merge( (array) $report_delivered, array( 'report_delivered_at' => null ) ),
	(object) array_merge( (array) $report_delivered, array( 'report_delivered_at' => '2025-03-31 09:00:00' ) ),
	(object) array_merge( (array) $report_delivered, array( 'report_access_used_at' => '2025-03-31 09:00:00' ) ),
	(object) array_merge( (array) $report_delivered, array( 'closure_reason' => 'completed' ) ),
	(object) array_diff_key( (array) $admin_closed, array( 'report_delivered_at' => true ) ),
	(object) array_diff_key( (array) $report_delivered, array( 'report_access_used_at' => true ) ),
) as $invalid ) {
	retention_assert( false === ct_scan_retain_until( $invalid ), 'Untrusted closure metadata was accepted for evidence retention.' );
	retention_assert( false === ct_scan_findings_retain_until( $invalid ), 'Untrusted closure/delivery metadata was accepted for findings retention.' );
}

// Legacy evidence still requires a valid non-backwards closure before deletion, even without findings.
$legacy_due = (object) array_merge( (array) $legacy, array(
	'terms_accepted_at' => '2021-01-01 00:00:00',
	'created_at' => '2021-01-01 00:00:00',
	'closed_at' => '2021-01-02 00:00:00',
	'retain_until' => '2024-01-01 00:00:00',
	'identity' => str_repeat( 'b', 32 ),
	'hold_reason' => null,
	'hold_until' => null,
	'result_json' => null,
	'manual_remainder_notes' => null,
) );
retention_assert( 'delete' === ct_scan_deletion_decision( $legacy_due, '2026-01-16 00:00:00' )[0], 'A valid due legacy evidence-only row was not eligible.' );
foreach ( array( null, '2020-12-31 23:59:59', 'invalid' ) as $invalid_close ) {
	$damaged = (object) array_merge( (array) $legacy_due, array( 'closed_at' => $invalid_close ) );
	retention_assert( array( 'keep', null ) === ct_scan_deletion_decision( $damaged, '2026-01-16 00:00:00' ), 'Legacy evidence was deleted despite a missing, invalid, or backwards closure.' );
}

$plugin_source = file_get_contents( $argv[1] );
retention_assert( is_string( $plugin_source ), 'The scan source could not be read for the no-auto-close regression check.' );
retention_assert(
	false === stripos( $plugin_source, 'closed_at = COALESCE(finished_at' ),
	'The retention source still derives request closure from terminal finished_at.'
);
foreach ( array(
	"closure_source = 'report_delivery'",
	"closed_by = 0",
	"report_delivered_at = closed_at",
	"report_access_used_at = report_delivered_at",
	"closure_source = 'admin_final_close'",
	"closed_by > 0",
	'closure_reason = status',
	'report_delivered_at IS NULL',
	'report_access_used_at IS NULL',
) as $required_purge_guard ) {
	retention_assert( false !== strpos( $plugin_source, $required_purge_guard ), 'The findings purge no longer guards on trusted event field: ' . $required_purge_guard );
}

echo "Scan findings and evidence retention checks passed.\n";
