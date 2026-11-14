<?php
// Standalone report-delivery regression test. WordPress, database, and mail are synthetic;
// this test does not make HTTP, DNS, or worker calls.
define( 'ABSPATH', __DIR__ );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/ct-scan-report-access-' . getmypid() );
define( 'DB_NAME', 'ct_scan_report_test' );

class WP_Error {
	private $code;
	private $message;
	function __construct( $code = '', $message = '' ) { $this->code = $code; $this->message = $message; }
	function get_error_code() { return $this->code; }
	function get_error_message() { return $this->message; }
}

class FakeScanUser {
	public $ID;
	function __construct( $id = 0 ) { $this->ID = $id; }
	function exists() { return $this->ID > 0; }
}

class FakeScanDb {
	public $prefix = 'wp_';
	public $last_error = '';
	public $row;
	public $locked = false;
	public $fail_next_update = false;
	public $zero_next_update = false;
	public $during_redemption = null;
	public $updates = array();
	function prepare( $query, ...$args ) { return $query; }
	function get_var( $query ) {
		if ( false !== strpos( $query, 'GET_LOCK' ) ) {
			if ( $this->locked ) { return 0; }
			$this->locked = true;
			return 1;
		}
		if ( false !== strpos( $query, 'RELEASE_LOCK' ) ) {
			$this->locked = false;
			return 1;
		}
		if ( false !== strpos( $query, 'SELECT UTC_TIMESTAMP()' ) ) {
			return gmdate( 'Y-m-d H:i:s' );
		}
		if ( false !== strpos( $query, 'SELECT MAX(' ) ) {
			return null;
		}
		return null;
	}
	function get_row( $query ) {
		if ( ! $this->row || ! preg_match( '/SELECT (.+) FROM wp_ct_scan_jobs/', $query, $match ) ) { return null; }
		if ( '*' === trim( $match[1] ) ) { return clone $this->row; }
		// Apply the actual SELECT projection: missing validator fields must not be supplied by the fake.
		$projected = new stdClass();
		foreach ( explode( ',', $match[1] ) as $field ) {
			$field = trim( $field );
			if ( property_exists( $this->row, $field ) ) { $projected->$field = $this->row->$field; }
		}
		return $projected;
	}
	function update( $table, $data, $where, $format = null, $where_format = null ) {
		$this->updates[] = array( $data, $where );
		if ( isset( $data['report_delivered_at'] ) && null !== $data['report_delivered_at']
			&& isset( $data['report_access_used_at'] ) && null !== $data['report_access_used_at'] && $this->during_redemption ) {
			$callback = $this->during_redemption;
			$this->during_redemption = null;
			$callback();
		}
		if ( $this->fail_next_update ) {
			$this->fail_next_update = false;
			return false;
		}
		if ( $this->zero_next_update ) {
			$this->zero_next_update = false;
			return 0;
		}
		foreach ( $where as $key => $expected ) {
			$actual = $this->row->$key ?? null;
			if ( null === $expected ? null !== $actual : ( null === $actual || (string) $actual !== (string) $expected ) ) {
				return 0;
			}
		}
		foreach ( $data as $key => $value ) { $this->row->$key = $value; }
		return 1;
	}
}

$GLOBALS['actions'] = array();
$GLOBALS['meta'] = array();
$GLOBALS['posts'] = array();
$GLOBALS['mail_sends'] = array();
$GLOBALS['mail_result'] = false;
$GLOBALS['current_user'] = new FakeScanUser( 0 );
$GLOBALS['current_user_can_manage'] = false;
$GLOBALS['wpdb'] = new FakeScanDb();
$GLOBALS['submenu_pages'] = array();

function add_action( $name, $callback, $priority = 10, $accepted_args = 1 ) { $GLOBALS['actions'][ $name ][] = $callback; }
function add_filter( $name, $callback, $priority = 10, $accepted_args = 1 ) {}
function add_submenu_page( ...$args ) { $GLOBALS['submenu_pages'][] = $args; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function absint( $value ) { return abs( (int) $value ); }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function wp_strip_all_tags( $value ) { return strip_tags( (string) $value ); }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }
function wp_unslash( $value ) { return is_string( $value ) ? stripslashes( $value ) : $value; }
function clean_post_cache( $id ) {}
function get_post( $id ) { return $GLOBALS['posts'][ $id ] ?? null; }
function get_post_meta( $id, $key, $single = true ) {
	if ( ! $single ) { return array_key_exists( $key, $GLOBALS['meta'][ $id ] ?? array() ) ? array( $GLOBALS['meta'][ $id ][ $key ] ) : array(); }
	return $GLOBALS['meta'][ $id ][ $key ] ?? '';
}
function update_post_meta( $id, $key, $value ) { $GLOBALS['meta'][ $id ][ $key ] = $value; return true; }
function delete_post_meta( $id, $key ) { unset( $GLOBALS['meta'][ $id ][ $key ] ); return true; }
function wp_get_current_user() { return $GLOBALS['current_user']; }
function current_user_can( $capability ) { return 'manage_options' === $capability && ! empty( $GLOBALS['current_user_can_manage'] ); }
function get_current_user_id() { return (int) $GLOBALS['current_user']->ID; }
function is_user_logged_in() { return $GLOBALS['current_user']->exists(); }
function sanitize_email( $value ) { return filter_var( trim( (string) $value ), FILTER_SANITIZE_EMAIL ); }
function is_email( $value ) { return is_string( $value ) && false !== filter_var( $value, FILTER_VALIDATE_EMAIL ); }
function sanitize_text_field( $value ) { return trim( strip_tags( (string) $value ) ); }
function sanitize_textarea_field( $value ) { return trim( strip_tags( (string) $value ) ); }
function sanitize_title( $value ) { return strtolower( trim( preg_replace( '/[^a-z0-9-]+/i', '-', (string) $value ), '-' ) ); }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $value ) ); }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); }
function admin_url( $path = '' ) { return 'https://complete.tech/wp-admin/' . ltrim( $path, '/' ); }
function add_query_arg( $args, $url ) { return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $args, '', '&', PHP_QUERY_RFC3986 ); }
function wp_mail( $to, $subject, $body, $headers = array() ) {
	$GLOBALS['mail_sends'][] = array( 'to' => $to, 'subject' => $subject, 'body' => $body, 'headers' => $headers );
	return $GLOBALS['mail_result'];
}

require dirname( __DIR__ ) . '/ct-scan.php';

ct_scan_register_admin_menu();
check(
	isset( $GLOBALS['submenu_pages'][0][4], $GLOBALS['submenu_pages'][0][5] )
		&& 'ct-scan-queue' === $GLOBALS['submenu_pages'][0][4]
		&& 'ct_scan_admin_page' === $GLOBALS['submenu_pages'][0][5]
		&& in_array( 'ct_scan_register_admin_menu', $GLOBALS['actions']['admin_menu'] ?? array(), true ),
	'the authenticated admin menu registers the report, delivery-status, and final-close queue page'
);

function check( $condition, $message ) {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
	echo "PASS: {$message}\n";
}

function fixture_reset( $notification_status = 'not_sent' ) {
	$job_id = 417;
	$request_id = 902;
	$accepted_epoch = time() - 3600;
	$accepted_iso = gmdate( 'Y-m-d\TH:i:s\Z', $accepted_epoch );
	$accepted_sql = gmdate( 'Y-m-d H:i:s', $accepted_epoch );
	$expiry = gmdate( 'Y-m-d H:i:s', time() + 20 * 86400 );
	$terms_hash = hash( 'sha256', 'synthetic accepted terms' );
	$contract = "Client contact: Fixture Reviewer\nClient email: fixture@example.net\nWebsite (scan scope): https://fixture.example.net/\nReferred by: direct\n";
	$GLOBALS['posts'][ $request_id ] = (object) array(
		'post_type' => 'ct_promo_request',
		'post_status' => 'private',
		'post_content' => "Synthetic request\n" . $contract,
	);
	$GLOBALS['meta'][ $request_id ] = array(
		'_ct_scan_job_id' => (string) $job_id,
		'_ct_scan_target' => 'https://fixture.example.net/',
		'_ct_scan_email' => 'fixture@example.net',
		'_ct_scan_name' => 'Fixture Reviewer',
		'_ct_scan_authorization_expires_at' => $expiry,
		'_ct_ref' => 'direct',
		'_ct_terms_saved' => '1',
		'_ct_terms_version' => '2026-10-21-r2',
		'_ct_terms_url' => 'https://complete.tech/fixture-terms/',
		'_ct_terms_sha256' => $terms_hash,
		'_ct_terms_accepted_at' => $accepted_iso,
		'_ct_terms_contract' => $contract,
	);
	$GLOBALS['wpdb']->row = (object) array(
		'job_id' => $job_id,
		'request_id' => $request_id,
		'target_origin' => 'https://fixture.example.net/',
		'scope_hash' => hash( 'sha256', 'https://fixture.example.net/' ),
		'terms_version' => '2026-10-21-r2',
		'terms_hash' => $terms_hash,
		'terms_accepted_at' => $accepted_sql,
		'created_at' => $accepted_sql,
		'finished_at' => gmdate( 'Y-m-d H:i:s', time() - 1800 ),
		'authorization_expires_at' => $expiry,
		'contact_email' => 'fixture@example.net',
		'contact_name' => 'Fixture Reviewer',
		'referrer' => 'direct',
		'status' => 'failed',
		'confirmed_at' => $accepted_sql,
		'revoked_at' => null,
		'report_delivered_at' => null,
		'report_notification_status' => $notification_status,
		'report_notification_at' => null,
		'report_access_token_hash' => null,
		'report_access_expires_at' => null,
		'report_access_used_at' => null,
		'closed_at' => gmdate( 'Y-m-d H:i:s', time() - 1800 ), // Legacy maintenance-only terminal timestamp.
		'closure_source' => null,
		'closed_by' => null,
		'closure_reason' => null,
		'manual_remainder_status' => 'complete',
		'manual_remainder_notes' => 'Synthetic private finding marker 9f7e; comparison 2 < 3 & reviewed.',
		'error_code' => 'fixture_failure',
		'profile_id' => 'r2-header-v1',
		'bound_required' => 0,
		'summary_sha256' => null,
		'control_required' => 1,
		'control_state' => 'none',
		'control_method' => 'dns_txt',
		'control_verified_at' => gmdate( 'Y-m-d H:i:s', time() - 600 ),
		'control_valid_until' => $expiry,
	);
	$GLOBALS['wpdb']->locked = false;
	$GLOBALS['wpdb']->fail_next_update = false;
	$GLOBALS['wpdb']->zero_next_update = false;
	$GLOBALS['wpdb']->during_redemption = null;
	$GLOBALS['mail_sends'] = array();
	$GLOBALS['mail_result'] = false;
	$GLOBALS['current_user'] = new FakeScanUser( 0 );
	$GLOBALS['current_user_can_manage'] = false;
	return array( $job_id, $request_id );
}

function send_fixture_link( $mail_result = false ) {
	list( $job_id ) = fixture_reset();
	$GLOBALS['mail_result'] = $mail_result;
	$result = ct_scan_admin_send_report( $job_id );
	check( 'unknown' === $GLOBALS['wpdb']->row->report_notification_status || 'accepted' === $GLOBALS['wpdb']->row->report_notification_status, 'report mail state is persisted' );
	check( 1 === count( $GLOBALS['mail_sends'] ), 'one generic report-link email was attempted' );
	return array( $job_id, $GLOBALS['mail_sends'][0] );
}

list( $job_id, $request_id ) = fixture_reset();
$pending_closed_at = $GLOBALS['wpdb']->row->closed_at;
check(
	'failed' === $GLOBALS['wpdb']->row->status
		&& null === $GLOBALS['wpdb']->row->closure_source
		&& null === $GLOBALS['wpdb']->row->closed_by
		&& null === $GLOBALS['wpdb']->row->closure_reason
		&& $pending_closed_at === $GLOBALS['wpdb']->row->closed_at,
	'a terminal scan and legacy maintenance timestamp remain pending without explicit closure metadata'
);
$GLOBALS['wpdb']->fail_next_update = true;
$failed_send = ct_scan_admin_send_report( $job_id );
check( is_wp_error( $failed_send ) && 'report_state_write_failed' === $failed_send->get_error_code(), 'send state write failure is reported' );
check( 0 === count( $GLOBALS['mail_sends'] ), 'no email is sent when the capability state cannot be stored' );

list( $job_id, $mail ) = send_fixture_link( false );
check( is_wp_error( ct_scan_admin_send_report( $job_id ) ), 'unknown mail outcome is not retried' );
check( 1 === count( $GLOBALS['mail_sends'] ), 'unknown mail outcome sends at most once' );
check( 'fixture@example.net' === $mail['to'] && 'Your reviewed website report is ready' === $mail['subject'], 'report notification goes to the confirmed recipient with a generic subject' );
check( false === strpos( $mail['body'], 'fixture.example.net' ) && false === strpos( $mail['body'], 'Fixture Reviewer' ) && false === strpos( $mail['body'], '9f7e' ), 'email contains no target, recipient name, or report findings' );
check( 1 === preg_match( '#https://complete\.tech/wp-admin/admin-post\.php\?[^\s]+#', $mail['body'], $url_match ), 'email contains only a report access URL' );
$query = array();
parse_str( (string) parse_url( $url_match[0], PHP_URL_QUERY ), $query );
$token = $query['key'] ?? '';
check( 64 === strlen( $token ) && 1 === preg_match( '/\A[a-f0-9]{64}\z/', $token ), 'email capability has 256 bits of URL-safe entropy' );
check( array( 'action', 'job_id', 'key' ) === array_keys( $query ), 'URL contains only the route, object id, and opaque capability' );
check( hash( 'sha256', $token ) === $GLOBALS['wpdb']->row->report_access_token_hash, 'only a one-way hash of the email capability is stored' );

$get = ct_scan_report_access_response( 'GET', $job_id, $token );
check( 200 === $get['status'] && false !== strpos( $get['body'], 'View report' ), 'GET renders an explicit POST form' );
check( false === strpos( $get['body'], '9f7e' ) && false === strpos( $get['body'], '2 &lt; 3' ), 'GET and link previews never reveal report content' );
$closed_at_before_get = $GLOBALS['wpdb']->row->closed_at;
check(
	empty( $GLOBALS['wpdb']->row->report_access_used_at )
		&& empty( $GLOBALS['wpdb']->row->report_delivered_at )
		&& null === $GLOBALS['wpdb']->row->closure_source
		&& null === $GLOBALS['wpdb']->row->closed_by
		&& null === $GLOBALS['wpdb']->row->closure_reason
		&& $closed_at_before_get === $GLOBALS['wpdb']->row->closed_at,
	'GET does not consume the capability, serve the report, or create trusted closure metadata'
);
$headers = ct_scan_report_access_headers();
check( false !== strpos( $headers['Cache-Control'], 'no-store' ) && 'no-referrer' === $headers['Referrer-Policy'] && false !== strpos( $headers['X-Robots-Tag'], 'noindex' ) && 'nosniff' === $headers['X-Content-Type-Options'], 'access responses disable caching, referrers, indexing, and MIME sniffing' );
check( false !== strpos( $headers['Content-Security-Policy'], "default-src 'none'" ) && false !== strpos( $headers['Content-Security-Policy'], "form-action 'self'" ), 'access page blocks external resources and limits form submission to this site' );
check( 1 !== preg_match( '/<(?:script|iframe|img|link|style)\b|\bsrc\s*=/i', $get['body'] ), 'the access page loads no scripts, stylesheets, frames, or external assets' );

$GLOBALS['wpdb']->fail_next_update = true;
$write_failed = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 503 === $write_failed['status'] && false === strpos( $write_failed['body'], '9f7e' ), 'redemption write failure serves no report' );
check( $token !== '' && hash( 'sha256', $token ) === $GLOBALS['wpdb']->row->report_access_token_hash && empty( $GLOBALS['wpdb']->row->report_delivered_at ), 'failed redemption leaves the capability unconsumed and report unserved' );

$GLOBALS['wpdb']->zero_next_update = true;
$cas_lost = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $cas_lost['status'] && false === strpos( $cas_lost['body'], '9f7e' ), 'a lost compare-and-set race fails closed without serving the report' );
check( hash( 'sha256', $token ) === $GLOBALS['wpdb']->row->report_access_token_hash && empty( $GLOBALS['wpdb']->row->report_delivered_at ), 'a compare-and-set miss leaves the capability unserved' );

$GLOBALS['meta'][ $request_id ]['_ct_scan_email'] = 'changed@example.net';
$recipient_changed = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $recipient_changed['status'] && false === strpos( $recipient_changed['body'], '9f7e' ), 'a changed saved recipient cannot redeem the capability' );
$GLOBALS['meta'][ $request_id ]['_ct_scan_email'] = 'fixture@example.net';
$GLOBALS['meta'][ $request_id ]['_ct_terms_version'] = 'changed-version';
$terms_version_changed = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $terms_version_changed['status'], 'a changed saved terms version cannot redeem the capability' );
$GLOBALS['meta'][ $request_id ]['_ct_terms_version'] = '2026-10-21-r2';
$GLOBALS['meta'][ $request_id ]['_ct_terms_sha256'] = str_repeat( 'b', 64 );
$terms_hash_changed = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $terms_hash_changed['status'], 'a changed saved terms hash cannot redeem the capability' );
$GLOBALS['meta'][ $request_id ]['_ct_terms_sha256'] = $GLOBALS['wpdb']->row->terms_hash;

$GLOBALS['wpdb']->row->confirmed_at = null;
$unconfirmed = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $unconfirmed['status'], 'an unconfirmed recipient cannot redeem the capability' );
$GLOBALS['wpdb']->row->confirmed_at = $GLOBALS['wpdb']->row->terms_accepted_at;

$GLOBALS['wpdb']->row->control_valid_until = gmdate( 'Y-m-d H:i:s', time() - 1 );
$control_expired = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $control_expired['status'], 'expired exact-target control blocks report access' );
$GLOBALS['wpdb']->row->control_valid_until = $GLOBALS['wpdb']->row->authorization_expires_at;

$GLOBALS['wpdb']->row->report_access_expires_at = gmdate( 'Y-m-d H:i:s', time() - 1 );
$expired = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $expired['status'] && empty( $GLOBALS['wpdb']->row->report_delivered_at ), 'expired capability cannot serve the report' );
$GLOBALS['wpdb']->row->report_access_expires_at = gmdate( 'Y-m-d H:i:s', time() + 3600 );

$malformed = ct_scan_report_access_response( 'POST', $job_id, 'not-a-capability' );
check( 404 === $malformed['status'] && false === strpos( $malformed['body'], '9f7e' ), 'malformed capability is rejected without report disclosure' );

$GLOBALS['wpdb']->row->control_required = 0;
unset( $GLOBALS['wpdb']->row->control_required ); // missing field is interpreted as required
$GLOBALS['wpdb']->row->control_verified_at = '';
$missing_control = ct_scan_report_access_response( 'GET', $job_id, $token );
check( 410 === $missing_control['status'], 'a missing control-required field fails closed when proof is absent' );
$GLOBALS['wpdb']->row->control_required = 1;
$GLOBALS['wpdb']->row->control_verified_at = gmdate( 'Y-m-d H:i:s', time() - 600 );

$race = null;
$GLOBALS['wpdb']->during_redemption = function () use ( $job_id, $token, &$race ) {
	$race = ct_scan_report_access_response( 'POST', $job_id, $token );
};
$served = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 200 === $served['status'] && 503 === $race['status'], 'the queue lock serializes simultaneous capability POSTs' );
check( ! empty( $GLOBALS['wpdb']->row->report_access_used_at ) && ! empty( $GLOBALS['wpdb']->row->report_delivered_at ), 'successful POST atomically consumes the capability and marks the report served' );
check( $GLOBALS['wpdb']->row->report_delivered_at === $GLOBALS['wpdb']->row->closed_at && 'report_delivery' === $GLOBALS['wpdb']->row->closure_source && 0 === $GLOBALS['wpdb']->row->closed_by && 'report_delivered' === $GLOBALS['wpdb']->row->closure_reason, 'successful POST anchors closure to the same server time and trusted report-delivery source' );
check( false !== strpos( $served['body'], 'Synthetic private finding marker 9f7e' ) && false !== strpos( $served['body'], '2 &lt; 3 &amp; reviewed' ) && false === strpos( $served['body'], '<script' ), 'the report is escaped in the one successful POST response' );
$replay = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $replay['status'] && false === strpos( $replay['body'], '9f7e' ), 'a replay cannot serve the report twice' );
check( ! empty( $GLOBALS['meta'][ $request_id ]['_ct_scan_report_delivered_at'] ), 'served timestamp is mirrored to request metadata only after the successful POST' );

list( $job_id, $mail ) = send_fixture_link( true );
$query = array();
preg_match( '#https://complete\.tech/wp-admin/admin-post\.php\?[^\s]+#', $mail['body'], $link_match );
parse_str( (string) parse_url( $link_match[0] ?? '', PHP_URL_QUERY ), $query );
$token = $query['key'] ?? '';
$GLOBALS['meta'][ $GLOBALS['wpdb']->row->request_id ]['_ct_scan_job_id'] = '999';
$request_mismatch = ct_scan_report_access_response( 'GET', $job_id, $token );
check( 410 === $request_mismatch['status'], 'capability use requires the exact saved request-to-job linkage' );

list( $job_id ) = send_fixture_link( true );
$token = '';
foreach ( $GLOBALS['mail_sends'] as $sent ) {
	if ( preg_match( '#key=([a-f0-9]{64})#', $sent['body'], $match ) ) { $token = $match[1]; }
}
$revoked = ct_scan_admin_revoke( $job_id );
check( true === $revoked && ! empty( $GLOBALS['wpdb']->row->revoked_at ), 'authorization revocation is durably recorded before further report access' );
$after_revoke = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $after_revoke['status'] && false === strpos( $after_revoke['body'], '9f7e' ), 'revoked authorization blocks report access' );
check( ct_scan_no_report_close_eligible( $GLOBALS['wpdb']->row ), 'revoking an unused v8 link retains non-secret proof that no findings were emailed' );
check( is_string( $GLOBALS['wpdb']->row->report_access_token_hash ) && is_string( $GLOBALS['wpdb']->row->report_access_expires_at ), 'revocation preserves hashed v8 link provenance while denying redemption' );
$GLOBALS['current_user'] = new FakeScanUser( 71 );
$GLOBALS['current_user_can_manage'] = true;
$revoked_close = ct_scan_admin_close( $job_id, $GLOBALS['wpdb']->row->status );
check( true === $revoked_close && ct_scan_closure_metadata_trusted( $GLOBALS['wpdb']->row ) && 'admin_final_close' === $GLOBALS['wpdb']->row->closure_source, 'an authenticated administrator can finalize an unused revoked v8 link without claiming report delivery' );
check( 410 === ct_scan_report_access_response( 'POST', $job_id, $token )['status'], 'finalizing a revoked link never revives redemption' );


list( $job_id, $mail ) = send_fixture_link( true );
preg_match( '#key=([a-f0-9]{64})#', $mail['body'], $match );
$token = $match[1] ?? '';
$GLOBALS['wpdb']->row->closure_source = 'other_closure';
$existing_closure = ct_scan_report_access_response( 'POST', $job_id, $token );
check( 410 === $existing_closure['status'] && empty( $GLOBALS['wpdb']->row->report_delivered_at ), 'existing closure metadata blocks replacement and report serving' );

list( $job_id, $request_id ) = fixture_reset();
$GLOBALS['wpdb']->row->status = 'completed';
$GLOBALS['wpdb']->row->result_json = '';
$invalid_report = ct_scan_admin_send_report( $job_id );
check( is_wp_error( $invalid_report ) && 'report_result_missing' === $invalid_report->get_error_code(), 'report schema/readiness validation still blocks sending an incomplete result' );
check( 0 === count( $GLOBALS['mail_sends'] ), 'invalid report content is never emailed' );

list( $job_id ) = fixture_reset();
$pending_timestamp = $GLOBALS['wpdb']->row->closed_at;
$pending = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $pending ), 'a terminal row cannot be finalized without an authenticated administrator' );
check(
	$pending_timestamp === $GLOBALS['wpdb']->row->closed_at
		&& null === $GLOBALS['wpdb']->row->closure_source
		&& null === $GLOBALS['wpdb']->row->closed_by
		&& null === $GLOBALS['wpdb']->row->closure_reason,
	'missing actor and closure metadata leave the row pending without rewriting its legacy timestamp'
);

$GLOBALS['current_user'] = new FakeScanUser( 41 );
$GLOBALS['current_user_can_manage'] = false;
$unauthorized = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $unauthorized ) && null === $GLOBALS['wpdb']->row->closure_source, 'a positive user without manage_options cannot finalize the request' );

$GLOBALS['current_user_can_manage'] = true;
$GLOBALS['current_user'] = new FakeScanUser( 0 );
$missing_actor = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $missing_actor ) && null === $GLOBALS['wpdb']->row->closed_by, 'manage_options without a positive authenticated user ID cannot finalize the request' );

$GLOBALS['current_user'] = new FakeScanUser( 41 );
$missing_delivery_column = clone $GLOBALS['wpdb']->row;
unset( $missing_delivery_column->report_delivered_at );
check(
	! ct_scan_no_report_close_eligible( $missing_delivery_column ),
	'a missing report-delivery column is not treated as an explicit SQL NULL or no-report proof'
);
$invalid_reason = ct_scan_admin_close( $job_id, 'closed_without_report' );
$mismatched_reason = ct_scan_admin_close( $job_id, 'completed' );
check( is_wp_error( $invalid_reason ) && is_wp_error( $mismatched_reason ), 'final closure rejects unrecognized reasons and reasons that do not match the terminal status' );
check( null === $GLOBALS['wpdb']->row->closure_source && null === $GLOBALS['wpdb']->row->closed_by && null === $GLOBALS['wpdb']->row->closure_reason, 'invalid final-close attempts persist no closure metadata' );

$old_timestamp = $GLOBALS['wpdb']->row->closed_at;
$closed = ct_scan_admin_close( $job_id, 'failed' );
check( true === $closed, 'an authenticated administrator can explicitly close a terminal request with its allowlisted reason' );
check(
	'admin_final_close' === $GLOBALS['wpdb']->row->closure_source
		&& 41 === (int) $GLOBALS['wpdb']->row->closed_by
		&& 'failed' === $GLOBALS['wpdb']->row->closure_reason
		&& null === $GLOBALS['wpdb']->row->report_delivered_at
		&& null === $GLOBALS['wpdb']->row->report_access_used_at,
	'admin final close stores its source, positive actor, exact reason, and undelivered state'
);
$close_write = end( $GLOBALS['wpdb']->updates );
check(
	isset( $close_write[0] )
		&& array_key_exists( 'report_delivered_at', $close_write[0] )
		&& null === $close_write[0]['report_delivered_at']
		&& array_key_exists( 'report_access_used_at', $close_write[0] )
		&& null === $close_write[0]['report_access_used_at'],
	'the final-close database write explicitly stores SQL NULL for both delivery timestamps'
);
$closed_epoch = strtotime( $GLOBALS['wpdb']->row->closed_at . ' UTC' );
check(
	$GLOBALS['wpdb']->row->closed_at !== $old_timestamp
		&& is_int( $closed_epoch )
		&& $closed_epoch >= strtotime( $GLOBALS['wpdb']->row->terms_accepted_at . ' UTC' )
		&& abs( time() - $closed_epoch ) <= 10,
	'final close replaces the legacy timestamp with a trustworthy server time after acceptance'
);
$closed_at = $GLOBALS['wpdb']->row->closed_at;
$duplicate_close = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $duplicate_close ) && $closed_at === $GLOBALS['wpdb']->row->closed_at, 'a repeated final-close action cannot replace trusted closure evidence' );
$edit_after_close = ct_scan_admin_save_manual_remainder( $job_id, 'Attempted post-close edit.' );
check( is_wp_error( $edit_after_close ) && 'admin_final_close' === $GLOBALS['wpdb']->row->closure_source, 'a final-closed request cannot have its reviewed findings rewritten' );

list( $job_id ) = fixture_reset( 'accepted' );
$GLOBALS['current_user'] = new FakeScanUser( 58 );
$GLOBALS['current_user_can_manage'] = true;
$legacy_mail_ambiguous = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $legacy_mail_ambiguous ) && 'close_report_ambiguous' === $legacy_mail_ambiguous->get_error_code() && null === $GLOBALS['wpdb']->row->closure_source, 'a pre-v8 accepted full-report email without a single-use-link record cannot be mislabeled as no-report closure' );

list( $job_id ) = fixture_reset( 'accepted' );
$GLOBALS['current_user'] = new FakeScanUser( 59 );
$GLOBALS['current_user_can_manage'] = true;
$GLOBALS['wpdb']->row->report_access_token_hash = str_repeat( 'a', 64 );
$GLOBALS['wpdb']->row->report_access_expires_at = gmdate( 'Y-m-d H:i:s', time() + 3600 );
$unredeemed_link_close = ct_scan_admin_close( $job_id, 'failed' );
check(
	true === $unredeemed_link_close
		&& 'admin_final_close' === $GLOBALS['wpdb']->row->closure_source
		&& null === $GLOBALS['wpdb']->row->report_access_token_hash
		&& null === $GLOBALS['wpdb']->row->report_access_expires_at
		&& ct_scan_closure_metadata_trusted( $GLOBALS['wpdb']->row ),
	'an unused report link can be invalidated by an authenticated no-report close, and the persisted event has trusted v8 actor/source fields'
);

foreach ( array( 'completed', 'failed', 'failed_unknown', 'cancelled', 'expired', 'blocked' ) as $terminal_reason ) {
	list( $job_id ) = fixture_reset();
	$GLOBALS['wpdb']->row->status = $terminal_reason;
	$GLOBALS['current_user'] = new FakeScanUser( 53 );
	$GLOBALS['current_user_can_manage'] = true;
	$terminal_closed = ct_scan_admin_close( $job_id, $terminal_reason );
	check(
		true === $terminal_closed
			&& 'admin_final_close' === $GLOBALS['wpdb']->row->closure_source
			&& 53 === (int) $GLOBALS['wpdb']->row->closed_by
			&& $terminal_reason === $GLOBALS['wpdb']->row->closure_reason,
		'admin final close accepts and records terminal reason ' . $terminal_reason
	);
}

list( $job_id ) = fixture_reset();
$GLOBALS['current_user'] = new FakeScanUser( 61 );
$GLOBALS['current_user_can_manage'] = true;
$GLOBALS['wpdb']->row->status = 'running';
$nonterminal_close = ct_scan_admin_close( $job_id, 'failed' );
check( is_wp_error( $nonterminal_close ) && null === $GLOBALS['wpdb']->row->closure_source, 'a running request cannot be finalized by an administrator' );

function render_final_close_box( $request_id ) {
	ob_start();
	ct_scan_admin_render_final_close_metabox( (object) array( 'ID' => $request_id ) );
	return ob_get_clean();
}

list( $job_id, $request_id ) = fixture_reset();
$GLOBALS['current_user'] = new FakeScanUser( 72 );
$GLOBALS['current_user_can_manage'] = true;
check( true === ct_scan_admin_close( $job_id, 'failed' ), 'metabox admin-close fixture persists a trusted final event' );
$admin_markup = render_final_close_box( $request_id );
check( false !== strpos( $admin_markup, 'Final closure: admin_final_close' ) && false === strpos( $admin_markup, 'does not pass validation' ), 'actual metabox projection recognizes a trusted administrator closure' );

list( $job_id, $mail ) = send_fixture_link( true );
preg_match( '#key=([a-f0-9]{64})#', $mail['body'], $key_match );
check( 200 === ct_scan_report_access_response( 'POST', $job_id, $key_match[1] )['status'], 'metabox report fixture redeems its one-time capability' );
$GLOBALS['current_user'] = new FakeScanUser( 73 );
$GLOBALS['current_user_can_manage'] = true;
$report_markup = render_final_close_box( $GLOBALS['wpdb']->row->request_id );
check( false !== strpos( $report_markup, 'Final closure: report_delivery' ) && false === strpos( $report_markup, 'does not pass validation' ), 'actual metabox projection recognizes trusted report retrieval' );
$GLOBALS['wpdb']->row->created_at = '2024-02-00 00:00:00';
check( false !== strpos( render_final_close_box( $GLOBALS['wpdb']->row->request_id ), 'does not pass validation' ), 'metabox still warns on malformed trusted-event dates' );

list( $job_id, $request_id ) = fixture_reset();
$GLOBALS['current_user'] = new FakeScanUser( 74 );
$GLOBALS['current_user_can_manage'] = true;
$pending_markup = render_final_close_box( $request_id );
check( false === stripos( $pending_markup, '<form' ) && false !== strpos( $pending_markup, 'page=ct-scan-queue' ), 'edit-screen metabox links to the private queue without nesting an action form' );
$dom_path = getenv( 'CT_SCAN_METABOX_DOM_FIXTURE' );
if ( false !== $dom_path && '' !== $dom_path ) {
	if ( file_exists( $dom_path ) || is_link( $dom_path ) ) { throw new RuntimeException( 'DOM fixture output already exists.' ); }
	$html = '<!doctype html><html><body><form id="post" method="post" action="https://complete.tech/wp-admin/post.php"><input name="action" value="editpost"><input name="_wpnonce" value="fixture-post-save-nonce"><div id="ct-final-close">' . $pending_markup . '</div><button id="update" type="submit">Update post</button></form></body></html>';
	$handle = fopen( $dom_path, 'x' );
	if ( ! $handle ) { throw new RuntimeException( 'DOM fixture output could not be created.' ); }
	chmod( $dom_path, 0600 ); fwrite( $handle, $html ); fclose( $handle );
}

echo "Report access checks passed.\n";
