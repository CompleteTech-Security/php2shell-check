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

function retention_no_hold( $overrides = array() ) {
	return array_merge( array( 'hold_reason' => null, 'hold_until' => null, 'hold_set_by' => null,
		'hold_set_at' => null, 'hold_released_by' => null, 'hold_released_at' => null ), $overrides );
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
	retention_no_hold(),
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
$legacy_due = (object) array_merge( (array) $legacy, retention_no_hold(), array(
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
$purge_base = (object) array_merge( (array) $admin_closed, retention_no_hold(), array(
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
	array( 'hold_reason' => '0', 'hold_until' => null ),
	array( 'hold_reason' => '', 'hold_until' => '0000-00-00 00:00:00' ),
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

// SQL NULL state, never PHP truthiness, determines whether findings still need their own deadline.
foreach ( array( 'manual_remainder_notes', 'result_json' ) as $column ) {
	foreach ( array( '0', '', 'ordinary synthetic finding' ) as $value ) {
		foreach ( array( 'recent', 'missing', 'due' ) as $event ) {
			$row = (object) array_merge( (array) $legacy_due, array( $column => $value,
				'closed_at' => 'due' === $event ? '2024-01-02 00:00:00' : '2026-01-15 00:00:00',
				'closure_source' => 'missing' === $event ? null : 'admin_final_close',
				'closed_by' => 'missing' === $event ? null : 42,
				'closure_reason' => 'missing' === $event ? null : 'completed',
			) );
			retention_assert( true === ct_scan_findings_presence( $row ), 'A non-NULL string was classified as absent findings.' );
			retention_assert( ( 'due' === $event ? 'delete' : 'keep' ) === ct_scan_deletion_decision( $row, $purge_now )[0], "Findings value bypassed its independent deadline ($column/$event)." );
			retention_assert( ( 'due' === $event ) === ct_scan_tombstone_deadline_passed( $row, $purge_now ), "A tombstone bypassed the independent findings deadline ($column/$event)." );
		}
	}
}
retention_assert( false === ct_scan_findings_presence( $legacy_due ) && 'delete' === ct_scan_deletion_decision( $legacy_due, $purge_now )[0], 'The genuine SQL NULL/NULL legacy evidence-only control was not eligible.' );
foreach ( array( 'result_json', 'manual_remainder_notes' ) as $column ) {
	$missing = clone $legacy_due; unset( $missing->$column );
	retention_assert( null === ct_scan_findings_presence( $missing ) && 'keep' === ct_scan_deletion_decision( $missing, $purge_now )[0] && false === ct_scan_tombstone_deadline_passed( $missing, $purge_now ), 'Missing findings columns were mistaken for known NULL evidence-only data.' );
	$GLOBALS['wpdb'] = $db = new FakeFindingsDb(); $db->row = clone $purge_base; unset( $db->row->$column );
	retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->query_count, 'Missing findings columns permitted purge.' );
	foreach ( array( 0, false, array(), (object) array() ) as $ambiguous ) {
		$damaged = (object) array_merge( (array) $legacy_due, array( $column => $ambiguous ) );
		retention_assert( null === ct_scan_findings_presence( $damaged ) && 'keep' === ct_scan_deletion_decision( $damaged, $purge_now )[0] && false === ct_scan_tombstone_deadline_passed( $damaged, $purge_now ), 'Ambiguous non-string findings were treated as absent.' );
		$GLOBALS['wpdb'] = $db = new FakeFindingsDb(); $db->row = (object) array_merge( (array) $purge_base, array( $column => $ambiguous ) );
		retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->query_count, 'Ambiguous non-string findings permitted purge.' );
	}
}

// A hold is absent only when its complete six-column tuple is explicitly SQL NULL.
$hold_fields = array_keys( retention_no_hold() );
$orphan_values = array( 'hold_until' => '2027-01-01 00:00:00', 'hold_set_by' => 42,
	'hold_set_at' => '2025-12-01 00:00:00', 'hold_released_by' => 42, 'hold_released_at' => '2026-01-01 00:00:00' );
foreach ( $orphan_values as $column => $value ) {
	$row = (object) array_merge( (array) $legacy_due, array( $column => $value ) );
	retention_assert( true === ct_scan_job_on_hold( $row, $purge_now ) && 'keep' === ct_scan_deletion_decision( $row, $purge_now )[0] && false === ct_scan_tombstone_deadline_passed( $row, $purge_now ), 'An orphaned hold field allowed evidence or tombstone deletion.' );
	$GLOBALS['wpdb'] = $db = new FakeFindingsDb();
	$db->row = (object) array_merge( (array) $purge_base, array( $column => $value ) );
	retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->query_count && null !== $db->row->result_json, 'An orphaned hold field allowed findings purge.' );
}
foreach ( $hold_fields as $column ) {
	$row = clone $legacy_due; unset( $row->$column );
	retention_assert( true === ct_scan_job_on_hold( $row, $purge_now ) && 'keep' === ct_scan_deletion_decision( $row, $purge_now )[0] && false === ct_scan_tombstone_deadline_passed( $row, $purge_now ), 'An incomplete hold projection allowed deletion.' );
	$GLOBALS['wpdb'] = $db = new FakeFindingsDb(); $db->row = clone $purge_base; unset( $db->row->$column );
	retention_assert( 'kept' === ct_scan_purge_findings_if_due( 31, $purge_now ) && 0 === $db->query_count, 'An incomplete hold projection allowed findings purge.' );
}
foreach ( array(
	'absent' => retention_no_hold(),
	'expired' => retention_no_hold( array( 'hold_reason' => 'Synthetic valid expired hold.', 'hold_until' => '2026-01-10 00:00:00', 'hold_set_by' => 42, 'hold_set_at' => '2026-01-01 00:00:00' ) ),
	'released' => retention_no_hold( array( 'hold_reason' => 'Synthetic valid released hold.', 'hold_until' => '2026-01-10 00:00:00', 'hold_set_by' => 42, 'hold_set_at' => '2026-01-01 00:00:00', 'hold_released_by' => 43, 'hold_released_at' => '2026-01-10 00:00:00' ) ),
) as $case => $hold ) {
	$row = (object) array_merge( (array) $legacy_due, $hold );
	retention_assert( false === ct_scan_job_on_hold( $row, $purge_now ) && 'delete' === ct_scan_deletion_decision( $row, $purge_now )[0] && true === ct_scan_tombstone_deadline_passed( $row, $purge_now ), "A valid known hold control prevented due cleanup ($case)." );
	$GLOBALS['wpdb'] = $db = new FakeFindingsDb(); $db->row = (object) array_merge( (array) $purge_base, $hold );
	retention_assert( 'cleared' === ct_scan_purge_findings_if_due( 31, $purge_now ), "A valid known hold control prevented due findings purge ($case)." );
}
$backwards_acceptance = (object) array_merge( (array) $legacy_due, array( 'terms_accepted_at' => '2021-01-01 00:04:00', 'closed_at' => '2021-01-01 00:02:00', 'retain_until' => '2024-01-01 00:04:00' ) );
retention_assert( 'keep' === ct_scan_deletion_decision( $backwards_acceptance, $purge_now )[0] && false === ct_scan_tombstone_deadline_passed( $backwards_acceptance, $purge_now ), 'A legacy closure before acceptance was deleted.' );
$valid_acceptance = clone $backwards_acceptance; $valid_acceptance->closed_at = '2021-01-01 00:05:00';
retention_assert( 'delete' === ct_scan_deletion_decision( $valid_acceptance, $purge_now )[0] && true === ct_scan_tombstone_deadline_passed( $valid_acceptance, $purge_now ), 'A valid due legacy acceptance lost its three-year anchor.' );
foreach ( array( '2024-02-30-r1', '2024-13-01-r1', '0000-01-01-r1', '2024-02-29-r0', '2024-02-29-r01' ) as $version ) {
	retention_assert( false === ct_scan_is_legacy_version( $version ), 'An invalid calendar version was grandfathered into the legacy policy.' );
	$invalid_version = (object) array_merge( (array) $admin_closed, array( 'terms_version' => $version ) );
	retention_assert( retention_plus_years( $invalid_version->closed_at, 6 ) === ct_scan_retain_until( $invalid_version ), 'A malformed version did not retain the conservative trusted-close six-year policy.' );
	$invalid_version->closure_source = null;
	retention_assert( false === ct_scan_retain_until( $invalid_version ), 'A malformed version permitted evidence expiry without trusted closure.' );
}
retention_assert( true === ct_scan_is_legacy_version( '2024-02-29-r1' ), 'A valid leap-day legacy version was refused.' );

echo "Scan findings and evidence retention checks passed.\n";
