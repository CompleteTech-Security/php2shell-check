<?php
// Standalone synthetic tombstone-retention regressions. No WordPress bootstrap, database, or network.
// Usage: php tests/ct-scan-tombstones.php mu-plugins/ct-scan.php
define( 'ABSPATH', __DIR__ );
define( 'DB_NAME', 'ct-scan-tombstone-test' );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/ct-scan-tombstone-test-' . getmypid() );

class WP_Error {
}

class FakeTombstoneDb {
	public $prefix = 'wp_';
	public $posts = 'wp_posts';
	public $postmeta = 'wp_postmeta';
	public $last_error = '';
	public $last_args = array();
	public $stones = array();
	public $tombstone_queries = array();
	public $lock_attempts = 0;
	public $lock_fail_on_attempt = 0;
	public $post_read_mode = 'missing';
	public $tombstone_inserts = 0;
	public $scrub_updates = 0;
	public $job_deletes = 0;
	public $post_deletes = 0;
	public $restored_row = null;

	public function prepare( $query, ...$args ) {
		$this->last_args = $args;
		return (string) $query;
	}

	public function get_results( $query ) {
		$this->last_error = '';
		if ( false !== strpos( $query, 'SELECT j.job_id, t.tombstone_id' ) ) {
			$lower = 0;
			$upper = PHP_INT_MAX;
			if ( false !== strpos( $query, 'j.job_id > %d' ) && count( $this->last_args ) >= 4 ) {
				// Legacy composite cursor: (job_id, tombstone_id, upper job_id).
				$lower = (int) $this->last_args[2];
				$upper = (int) $this->last_args[3];
			} elseif ( count( $this->last_args ) >= 2 ) {
				// Global tombstone_id cursor: (lower tombstone_id, upper tombstone_id).
				$lower = (int) $this->last_args[0];
				$upper = (int) $this->last_args[1];
			}
			$matches = array_values( array_filter( $this->stones, static function ( $stone ) use ( $lower, $upper ) {
				return (int) $stone->tombstone_id > $lower && (int) $stone->tombstone_id <= $upper;
			} ) );
			usort( $matches, static function ( $a, $b ) {
				return (int) $a->tombstone_id <=> (int) $b->tombstone_id;
			} );
			$matches = array_slice( $matches, 0, 50 );
			$this->tombstone_queries[] = array(
				'lower' => $lower,
				'upper' => $upper,
				'ids'   => array_map( static function ( $stone ) { return (int) $stone->tombstone_id; }, $matches ),
			);
			return $matches;
		}
		if ( false !== strpos( $query, 'SELECT t.tombstone_id' ) ) {
			return array();
		}
		return array();
	}

	public function get_row( $query ) {
		$this->last_error = '';
		if ( false !== strpos( $query, $this->posts ) ) {
			return $this->read_post();
		}
		if ( false !== strpos( $query, 'contact_email,contact_name' ) ) {
			return (object) array( 'contact_email' => '', 'contact_name' => '' );
		}
		if ( false !== strpos( $query, 'SELECT * FROM wp_ct_scan_jobs' ) && $this->restored_row ) { return clone $this->restored_row; }
		// The tombstone-row pagination case deliberately uses no restored/live job row.
		return null;
	}

	public function read_post() {
		$this->last_error = '';
		if ( 'error' === $this->post_read_mode ) {
			$this->last_error = 'synthetic WordPress post-read failure';
			return null;
		}
		if ( 'missing' === $this->post_read_mode ) {
			return null;
		}
		return (object) array( 'ID' => 900, 'post_type' => 'ct_promo_request' );
	}

	public function get_var( $query ) {
		if ( false !== strpos( $query, 'GET_LOCK' ) ) {
			++$this->lock_attempts;
			return $this->lock_fail_on_attempt === $this->lock_attempts ? '0' : '1';
		}
		if ( false !== strpos( $query, 'RELEASE_LOCK' ) ) {
			return '1';
		}
		return null;
	}

	public function query( $query ) {
		if ( false !== strpos( $query, 'INSERT IGNORE INTO' ) && false !== strpos( $query, 'ct_scan_tombstones' ) ) {
			++$this->tombstone_inserts;
		}
		return 1;
	}

	public function update( $table, $data, $where, $data_format = null, $where_format = null ) {
		if ( false !== strpos( $table, 'ct_scan_jobs' ) && isset( $data['contact_email'], $data['contact_name'] ) ) {
			++$this->scrub_updates;
		}
		return 1;
	}

	public function delete( $table, $where, $where_format = null ) {
		if ( false !== strpos( $table, 'ct_scan_jobs' ) ) {
			++$this->job_deletes;
		}
		return 1;
	}
}

function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_option( $key, $default = false ) { return $GLOBALS['test_options'][ $key ] ?? $default; }
function update_option( $key, $value, $autoload = null ) { $GLOBALS['test_options'][ $key ] = $value; return true; }
function delete_option( $key ) { unset( $GLOBALS['test_options'][ $key ] ); return true; }
function wp_salt( $scheme = 'auth' ) { return 'synthetic-tombstone-salt'; }
function absint( $value ) { return abs( (int) $value ); }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) ); }
function clean_post_cache( $post_id ) {}
function get_post( $post_id ) { return $GLOBALS['wpdb']->read_post(); }
function get_post_meta( $post_id, $key = '', $single = false ) { return $single ? '' : array(); }
function wp_delete_post( $post_id, $force_delete = false ) { ++$GLOBALS['wpdb']->post_deletes; return true; }

$GLOBALS['test_options'] = array();
$GLOBALS['wpdb']         = new FakeTombstoneDb();
require $argv[1];

function tombstone_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function tombstone_cursor_max_id() {
	$max = 0;
	foreach ( $GLOBALS['test_options'] as $key => $value ) {
		if ( false === strpos( (string) $key, 'tombstone' ) || false === strpos( (string) $key, 'cursor' ) ) {
			continue;
		}
		$encoded = is_scalar( $value ) ? (string) $value : json_encode( $value );
		if ( is_string( $encoded ) && preg_match_all( '/\d+/', $encoded, $matches ) ) {
			foreach ( $matches[0] as $number ) {
				$number = (int) $number;
				if ( $number >= 100 && $number < 1000000 ) {
					$max = max( $max, $number );
				}
			}
		}
	}
	return $max;
}

// Use one job id with many distinct tombstone ids to catch a persisted job-only cursor.
for ( $id = 101; $id <= 160; ++$id ) {
	$GLOBALS['wpdb']->stones[] = (object) array(
		'job_id'       => 7,
		'tombstone_id' => $id,
		'scope_mac'    => str_repeat( 'a', 64 ),
		'identity'     => str_repeat( 'b', 32 ),
	);
}
$GLOBALS['wpdb']->lock_fail_on_attempt = 7;
$remaining = 100;
ct_scan_apply_tombstones( gmdate( 'Y-m-d H:i:s' ), microtime( true ) + 30, $remaining );
$saved_tombstone_id = tombstone_cursor_max_id();
tombstone_assert( $saved_tombstone_id >= 101 && $saved_tombstone_id <= 106, 'A pause did not persist the last processed tombstone_id for a shared job_id.' );

// The next invocation must query after the saved tombstone_id. The row whose lock failed is retried first.
$GLOBALS['wpdb']->lock_attempts        = 0;
$GLOBALS['wpdb']->lock_fail_on_attempt = 1;
$query_count_before                    = count( $GLOBALS['wpdb']->tombstone_queries );
ct_scan_apply_tombstones( gmdate( 'Y-m-d H:i:s' ), microtime( true ) + 30, $remaining );
$next_queries = array_slice( $GLOBALS['wpdb']->tombstone_queries, $query_count_before );
tombstone_assert( ! empty( $next_queries ), 'The resumed retention pass did not query tombstones.' );
tombstone_assert( $next_queries[0]['lower'] === $saved_tombstone_id, 'The resumed query did not use the persisted tombstone_id cursor.' );
tombstone_assert( isset( $next_queries[0]['ids'][0] ) && $next_queries[0]['ids'][0] === $saved_tombstone_id + 1, 'The resumed query restarted at an earlier tombstone_id instead of advancing.' );

// A database error while reading the linked request post is not the same as a successful missing-post read.
$GLOBALS['wpdb'] = new FakeTombstoneDb();
$GLOBALS['wpdb']->post_read_mode = 'error';
$job = (object) array(
	'job_id'        => 41,
	'request_id'    => 900,
	'created_at'    => '2024-01-01 00:00:00',
	'scope_hash'    => hash( 'sha256', 'synthetic.example' ),
	'identity'      => str_repeat( 'c', 32 ),
	'contact_email' => 'private@example.invalid',
	'contact_name'  => 'Synthetic Client',
);
tombstone_assert( false === ct_scan_delete_job_records( $job, 'retention' ), 'A failed post read did not stop the deletion attempt.' );
tombstone_assert(
	0 === $GLOBALS['wpdb']->tombstone_inserts
		&& 0 === $GLOBALS['wpdb']->scrub_updates
		&& 0 === $GLOBALS['wpdb']->job_deletes
		&& 0 === $GLOBALS['wpdb']->post_deletes,
	'A failed post read wrote a tombstone, scrubbed data, or deleted the job.'
);

// A successful read that finds no post remains a distinct, permitted absence case.
$GLOBALS['wpdb'] = new FakeTombstoneDb();
$GLOBALS['wpdb']->post_read_mode = 'missing';
tombstone_assert( true === ct_scan_delete_job_records( $job, 'retention' ), 'A successfully-read absent post prevented the job retention cleanup.' );
tombstone_assert(
	1 === $GLOBALS['wpdb']->tombstone_inserts
		&& 1 === $GLOBALS['wpdb']->scrub_updates
		&& 1 === $GLOBALS['wpdb']->job_deletes
		&& 0 === $GLOBALS['wpdb']->post_deletes,
	'The successful missing-post case did not delete only the job after recording its tombstone.'
);

// A matched tombstone cannot bypass the date invariants required by ordinary legacy deletion.
$legacy_restored = (object) array(
	'job_id' => 41, 'request_id' => 900, 'scope_hash' => hash( 'sha256', 'https://legacy-restored.example.net/' ),
	'identity' => str_repeat( 'c', 32 ), 'contact_email' => 'fixture@example.invalid', 'contact_name' => 'Synthetic Client',
	'terms_version' => '2026-10-21-r2', 'terms_accepted_at' => '2021-01-01 00:00:00',
	'created_at' => '2021-01-01 00:00:00', 'closed_at' => '2021-01-02 00:00:00',
	'retain_until' => '2024-01-01 00:00:00', 'status' => 'failed',
	'hold_reason' => null, 'hold_until' => null, 'hold_set_by' => null, 'hold_set_at' => null, 'hold_released_by' => null, 'hold_released_at' => null, 'result_json' => null, 'manual_remainder_notes' => null,
	'closure_source' => null, 'closed_by' => null, 'closure_reason' => null, 'report_delivered_at' => null, 'report_access_used_at' => null,
);
foreach ( array(
	'missing-close' => array( 'closed_at' => null ),
	'invalid-close' => array( 'closed_at' => 'invalid' ),
	'zero-close' => array( 'closed_at' => '0000-00-00 00:00:00' ),
	'partial-close' => array( 'closed_at' => '2021-01-00 00:00:00' ),
	'backwards-close' => array( 'closed_at' => '2020-12-31 23:59:59' ),
	'missing-deadline' => array( 'retain_until' => null ),
	'invalid-deadline' => array( 'retain_until' => 'invalid' ),
	'partial-deadline' => array( 'retain_until' => '2024-02-00 00:00:00' ),
	'valid' => array(),
) as $case => $overrides ) {
	$GLOBALS['test_options'] = array();
	$GLOBALS['wpdb'] = $database = new FakeTombstoneDb();
	$database->restored_row = (object) array_merge( (array) $legacy_restored, $overrides );
	$database->stones[] = (object) array( 'job_id' => 41, 'tombstone_id' => 501,
		'scope_mac' => ct_scan_tombstone_mac( $database->restored_row->scope_hash ), 'identity' => str_repeat( 'c', 32 ) );
	$normal = ct_scan_deletion_decision( $database->restored_row, '2026-01-16 00:00:00' );
	$budget = 100;
	ct_scan_apply_tombstones( '2026-01-16 00:00:00', microtime( true ) + 30, $budget );
	if ( 'valid' === $case ) {
		tombstone_assert( 'delete' === $normal[0] && 1 === $database->tombstone_inserts && 1 === $database->scrub_updates && 1 === $database->job_deletes, 'A valid due legacy row was not deleted through its matched tombstone.' );
	} else {
		tombstone_assert( 'keep' === $normal[0] && 0 === $database->tombstone_inserts && 0 === $database->scrub_updates && 0 === $database->job_deletes && 0 === $database->post_deletes, "A matched tombstone bypassed the ordinary legacy date invariant ($case)." );
	}
}

function tombstone_test_complete_row( $row, $expected_delete, $label ) {
	$GLOBALS['test_options'] = array();
	$GLOBALS['wpdb'] = $database = new FakeTombstoneDb();
	$database->restored_row = clone $row;
	$database->stones[] = (object) array( 'job_id' => 41, 'tombstone_id' => 501,
		'scope_mac' => ct_scan_tombstone_mac( $row->scope_hash ), 'identity' => str_repeat( 'c', 32 ) );
	$normal = ct_scan_deletion_decision( $row, '2026-01-16 00:00:00' );
	tombstone_assert( ( $expected_delete ? 'delete' : 'keep' ) === $normal[0], 'Ordinary retention mismatch: ' . $label );
	$budget = 100;
	ct_scan_apply_tombstones( '2026-01-16 00:00:00', microtime( true ) + 30, $budget );
	tombstone_assert( ( $expected_delete ? 1 : 0 ) === $database->job_deletes
		&& ( $expected_delete ? 1 : 0 ) === $database->scrub_updates
		&& ( $expected_delete ? 1 : 0 ) === $database->tombstone_inserts, 'Matched tombstone violated retention: ' . $label );
}
foreach ( array( 'manual_remainder_notes', 'result_json' ) as $column ) {
	foreach ( array( '0', '', 'ordinary synthetic finding' ) as $value ) {
		foreach ( array( 'recent', 'missing', 'due' ) as $event ) {
			$row = (object) array_merge( (array) $legacy_restored, array( $column => $value,
				'closed_at' => 'due' === $event ? '2024-01-02 00:00:00' : '2026-01-15 00:00:00',
				'closure_source' => 'missing' === $event ? null : 'admin_final_close', 'closed_by' => 'missing' === $event ? null : 42,
				'closure_reason' => 'missing' === $event ? null : 'failed',
			) );
			tombstone_test_complete_row( $row, 'due' === $event, "$column/$value/$event" );
		}
	}
}
tombstone_test_complete_row( $legacy_restored, true, 'genuine NULL/NULL findings absence' );
foreach ( array( 'manual_remainder_notes', 'result_json' ) as $column ) {
	$row = clone $legacy_restored; unset( $row->$column );
	tombstone_test_complete_row( $row, false, 'missing findings column ' . $column );
	$row = clone $legacy_restored; $row->$column = 0;
	tombstone_test_complete_row( $row, false, 'ambiguous numeric findings ' . $column );
}
foreach ( array( 'hold_until' => '2027-01-01 00:00:00', 'hold_set_by' => 42, 'hold_set_at' => '2026-01-01 00:00:00', 'hold_released_by' => 42, 'hold_released_at' => '2026-01-01 00:00:00' ) as $column => $value ) {
	$row = clone $legacy_restored; $row->$column = $value;
	tombstone_test_complete_row( $row, false, 'orphan hold column ' . $column );
}
foreach ( array( '0', '' ) as $purpose ) {
	$row = clone $legacy_restored; $row->hold_reason = $purpose;
	tombstone_test_complete_row( $row, false, 'malformed non-NULL purpose ' . json_encode( $purpose ) );
}
foreach ( array( 'hold_reason', 'hold_until', 'hold_set_by', 'hold_set_at', 'hold_released_by', 'hold_released_at' ) as $column ) {
	$row = clone $legacy_restored; unset( $row->$column );
	tombstone_test_complete_row( $row, false, 'missing hold column ' . $column );
}
foreach ( array( false, true ) as $released ) {
	$row = (object) array_merge( (array) $legacy_restored, array( 'hold_reason' => 'Synthetic expired hold.', 'hold_until' => '2026-01-10 00:00:00', 'hold_set_by' => 42, 'hold_set_at' => '2026-01-01 00:00:00', 'hold_released_by' => $released ? 43 : null, 'hold_released_at' => $released ? '2026-01-10 00:00:00' : null ) );
	tombstone_test_complete_row( $row, true, $released ? 'valid released hold after grace' : 'valid expired hold after grace' );
}
$row = (object) array_merge( (array) $legacy_restored, array( 'terms_accepted_at' => '2021-01-01 00:04:00', 'closed_at' => '2021-01-01 00:02:00', 'retain_until' => '2024-01-01 00:04:00' ) );
tombstone_test_complete_row( $row, false, 'creation before closure before acceptance' );
$row->closed_at = '2021-01-01 00:05:00';
tombstone_test_complete_row( $row, true, 'closure after creation and acceptance, legacy three-year deadline' );

echo "Scan tombstone regressions passed.\n";
