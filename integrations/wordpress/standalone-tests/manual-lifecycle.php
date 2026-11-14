<?php
// Synthetic request-lifecycle lock/queue guards. No WordPress bootstrap, network, or database.
define( 'ABSPATH', __DIR__ );
define( 'DB_NAME', 'manual-lifecycle-fixture' );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/no-scan-config-fixture' );
class WP_Error { public $code; function __construct( $code, $message = '' ) { $this->code = $code; } }
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function get_option( $key ) { return $GLOBALS['schema'] ?? CT_SCAN_SCHEMA_VERSION; }
function wp_cache_delete( $id, $group ) { ++$GLOBALS['cache_deletes']; unset( $GLOBALS['cached_markers'] ); }
function get_post_meta( $id, $key, $single = true ) {
	if ( array_key_exists( 'cached_markers', $GLOBALS ) ) { return $GLOBALS['cached_markers']; }
	if ( ! empty( $GLOBALS['meta_error'] ) ) { $GLOBALS['wpdb']->last_error = 'synthetic failure'; }
	return $GLOBALS['markers'] ?? array();
}
class ManualFixtureDb {
	public $prefix = 'wp_';
	public $postmeta = 'wp_postmeta';
	public $last_error = '';
	public $owns = false;
	public $row = null;
	public $query_error = false;
	public $lock_error = false;
	public $reads = 0;
	function prepare( $query, ...$args ) { return $query; }
	function get_var( $query ) { if ( $this->lock_error ) { $this->last_error = 'synthetic failure'; } return $this->owns ? 1 : 0; }
	function get_col( $query ) { if ( ! empty( $GLOBALS['meta_error'] ) ) { $this->last_error = 'synthetic failure'; } return $GLOBALS['markers'] ?? array(); }
	function get_row( $query ) { ++$this->reads; if ( $this->query_error ) { $this->last_error = 'synthetic failure'; } return $this->row; }
}
$GLOBALS['cache_deletes'] = 0;
$GLOBALS['wpdb'] = new ManualFixtureDb();
require dirname( __DIR__ ) . '/ct-scan.php';
$count = 0;
function check_manual( $ok, $message ) { global $count; ++$count; if ( ! $ok ) { throw new RuntimeException( $message ); } }
$db = $GLOBALS['wpdb'];
check_manual( false === ct_scan_manual_closure_ready( 805 ), 'Manual close accepted without owning the queue lock.' );
check_manual( 0 === $db->reads, 'Manual close queried queue before proving lock ownership.' );
$db->owns = true;
check_manual( true === ct_scan_manual_closure_ready( 805 ), 'Successful locked empty-queue read was refused.' );
foreach ( array( 0, -805, '0805', '805x', 805.0, null, true, array() ) as $bad ) {
	check_manual( false === ct_scan_manual_closure_ready( $bad ), 'Noncanonical request identity was accepted.' );
}
$GLOBALS['schema'] = '7';
check_manual( false === ct_scan_manual_closure_ready( 805 ), 'Manual close accepted stale schema.' );
$GLOBALS['schema'] = CT_SCAN_SCHEMA_VERSION;
$db->row = (object) array( 'job_id' => 1 );
check_manual( false === ct_scan_manual_closure_ready( 805 ), 'Manual close accepted an existing queued request.' );
$db->row = null; $db->query_error = true;
check_manual( false === ct_scan_manual_closure_ready( 805 ), 'Failed queue read was mistaken for no job.' );
$db->query_error = false; $db->lock_error = true;
check_manual( false === ct_scan_manual_closure_ready( 805 ), 'Failed lock ownership read was accepted.' );
$db->lock_error = false;
check_manual( false === ct_scan_manual_queue_blocked( 805 ), 'Absent marker blocked enqueue.' );
$GLOBALS['meta_error'] = true;
check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'Metadata read failure allowed enqueue.' );
$GLOBALS['meta_error'] = false; $GLOBALS['markers'] = array( '' );
$GLOBALS['cached_markers'] = array();
check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'A cached absent marker permitted enqueue after another request closed.' );
check_manual( array_key_exists( 'cached_markers', $GLOBALS ), 'Direct marker read unexpectedly depended on the metadata cache.' );
check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'Present malformed marker allowed enqueue without its verifier.' );
// Conditional declaration intentionally follows the missing-plugin regression.
if ( ! function_exists( 'ct_archive_manual_queue_blocked' ) ) {
	function ct_archive_manual_queue_blocked( $id, $fresh_raw ) { $GLOBALS['passed_raw'] = $fresh_raw; return $GLOBALS['verdict']; }
}
foreach ( array( true, null, 0, '', 'false', array() ) as $bad_verdict ) {
	$GLOBALS['verdict'] = $bad_verdict;
	check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'An untrusted verifier result permitted enqueue.' );
}
$GLOBALS['verdict'] = false;
$GLOBALS['markers'] = array( 'fresh serialized marker' );
check_manual( false === ct_scan_manual_queue_blocked( 805 ), 'An explicitly validated reopened request was blocked.' );
check_manual( 'fresh serialized marker' === $GLOBALS['passed_raw'], 'Verifier did not receive the exact fresh database marker.' );
$GLOBALS['markers'] = array( 'one', 'two' );
check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'Duplicate lifecycle markers permitted enqueue.' );
$GLOBALS['markers'] = array( array() );
check_manual( true === ct_scan_manual_queue_blocked( 805 ), 'Nonstring raw database marker permitted enqueue.' );
echo $count . " manual lifecycle guards passed.\n";
