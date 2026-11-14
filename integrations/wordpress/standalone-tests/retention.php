<?php
// Standalone retention-policy regression test. No WordPress bootstrap, database, or network.
// Usage: php tests/ct-scan-retention.php mu-plugins/ct-scan.php
define( 'ABSPATH', __DIR__ );
define( 'DB_NAME', 'ct-scan-test' );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/ct-scan-retention-test-' . getmypid() );

class WP_Error {
}

function absint( $value ) { return abs( (int) $value ); }
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
	(object) array_merge( (array) $admin_closed, array( 'closure_source' => 'ADMIN_FINAL_CLOSE' ) ),
	(object) array_merge( (array) $admin_closed, array( 'closure_reason' => 'COMPLETED' ) ),
	(object) array_merge( (array) $admin_closed, array( 'status' => 'COMPLETED' ) ),
	(object) array_merge( (array) $report_delivered, array( 'closed_at' => '2024-02-00 00:00:00', 'report_delivered_at' => '2024-02-00 00:00:00', 'report_access_used_at' => '2024-02-00 00:00:00' ) ),
	(object) array_merge( (array) $report_delivered, array( 'closed_at' => '2024-02-30 00:00:00', 'report_delivered_at' => '2024-02-30 00:00:00', 'report_access_used_at' => '2024-02-30 00:00:00' ) ),
	(object) array_merge( (array) $report_delivered, array( 'closure_source' => 'REPORT_DELIVERY' ) ),
	(object) array_merge( (array) $report_delivered, array( 'closure_reason' => 'REPORT_DELIVERED' ) ),
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
// Destructive behavior is tested through the actual fresh-read helper, not SQL source text.
class FakeFindingsDb {
	public $prefix = 'wp_';
	public $last_error = '';
	public $row;
	public $snapshot;
	public $locked = false;
	public $busy = false;
	public $read_error = false;
	public $write_error = false;
	public $query_count = 0;
	public $reads = 0;
	public $before_write;
	public function prepare( $query, ...$args ) { return $query; }
	public function get_var( $query ) {
		if ( false !== strpos( $query, 'GET_LOCK' ) ) {
			if ( $this->busy || $this->locked ) { return 0; }
			$this->locked = true;
			return 1;
		}
		if ( false !== strpos( $query, 'RELEASE_LOCK' ) ) { $this->locked = false; return 1; }
		return null;
	}
	public function get_row( $query ) {
		++$this->reads;
		retention_assert( $this->locked, 'Findings were read without acquiring the queue lock.' );
		if ( $this->read_error ) { $this->last_error = 'Synthetic read failure'; return null; }
		$this->snapshot = $this->row ? clone $this->row : null;
		return $this->row ? clone $this->row : null;
	}
	public function query( $query ) {
		++$this->query_count;
		retention_assert( $this->locked, 'Findings mutation escaped its queue lock.' );
		if ( $this->before_write ) { $callback = $this->before_write; $this->before_write = null; $callback( $this ); }
		if ( $this->write_error ) { $this->last_error = 'Synthetic write failure'; return false; }
		// Model a compare-and-set against the fresh snapshot. The hosted database suite exercises actual SQL predicates.
		if ( serialize( $this->snapshot ) !== serialize( $this->row ) ) { return 0; }
		$this->row->result_json = null;
		$this->row->manual_remainder_notes = null;
		return 1;
	}
}
$purge_now = '2026-01-16 00:00:00';
$purge_base = (object) array_merge( (array) $admin_closed, array(
	'job_id' => 31, 'hold_reason' => null, 'hold_until' => null,
	'result_json' => '{"synthetic":"finding"}', 'manual_remainder_notes' => 'Synthetic findings',
) );
foreach ( array(
	array( 'closed_at' => '2024-02-00 00:00:00' ),
	array( 'closed_at' => '2024-02-30 00:00:00' ),
	array( 'created_at' => '2024-01-00 00:00:00' ),
	array( 'terms_accepted_at' => '2024-01-00 00:00:00' ),
	array( 'closure_source' => 'ADMIN_FINAL_CLOSE' ),
	array( 'status' => 'COMPLETED' ),
	array( 'closure_reason' => 'COMPLETED' ),
	array( 'hold_reason' => 'Synthetic active hold', 'hold_until' => '2027-01-01 00:00:00' ),
	array( 'hold_reason' => 'Synthetic damaged hold', 'hold_until' => null ),
) as $overrides ) {
	$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
	$db->row = (object) array_merge( (array) $purge_base, $overrides );
	retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ), 'Untrusted/held findings were eligible for destructive purge.' );
	retention_assert( 0 === $db->query_count && null !== $db->row->result_json && null !== $db->row->manual_remainder_notes && ! $db->locked, 'Untrusted/held findings were mutated or their queue lock leaked.' );
}
$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
$db->row = clone $purge_base;
retention_assert( 'cleared' === ct_scan_purge_findings_if_due( 31, $purge_now ), 'A valid due event did not clear its findings.' );
retention_assert( 1 === $db->query_count && null === $db->row->result_json && null === $db->row->manual_remainder_notes && ! $db->locked, 'Valid findings were not atomically cleared under the lock.' );
$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
$db->row = clone $purge_base;
$db->before_write = static function ( $database ) { $database->row->hold_reason = 'Concurrent hold'; $database->row->hold_until = '2027-01-01 00:00:00'; };
retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ) && null !== $db->row->result_json && null !== $db->row->manual_remainder_notes, 'A concurrently committed hold was overwritten by findings purge.' );
$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
$db->row = clone $purge_base;
$db->busy = true;
retention_assert( 'busy' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->reads && 0 === $db->query_count, 'An unavailable queue lock allowed read or purge.' );
$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
$db->row = clone $purge_base;
$db->read_error = true;
retention_assert( 'failed' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->query_count && ! $db->locked, 'A failed fresh read was treated as purge authority.' );
$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
$db->row = clone $purge_base;
$db->write_error = true;
retention_assert( 'failed' === ct_scan_purge_findings_if_due( 31, $purge_now ) && null !== $db->row->result_json && ! $db->locked, 'A failed CAS write was reported as successful or leaked its lock.' );
foreach ( array( null, 'invalid', '0000-00-00 00:00:00', '2020-12-31 23:59:59' ) as $invalid_close ) {
	$damaged = (object) array_merge( (array) $legacy_due, array( 'closed_at' => $invalid_close ) );
	retention_assert( false === ct_scan_tombstone_deadline_passed( $damaged, $purge_now ), 'A tombstone bypassed the ordinary legacy closure invariant.' );
}
foreach ( array( null, 'invalid', '2024-02-00 00:00:00' ) as $invalid_deadline ) {
	$damaged = (object) array_merge( (array) $legacy_due, array( 'retain_until' => $invalid_deadline ) );
	retention_assert( false === ct_scan_tombstone_deadline_passed( $damaged, $purge_now ), 'A tombstone bypassed the ordinary stored-deadline invariant.' );
}
retention_assert( true === ct_scan_tombstone_deadline_passed( $legacy_due, $purge_now ), 'A valid due legacy tombstone lost its three-year acceptance policy.' );

echo "Scan findings and evidence retention checks passed.\n";
