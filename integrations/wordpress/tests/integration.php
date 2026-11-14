<?php
/**
 * Disposable WordPress + MariaDB integration checks for the MU plugin.
 * Run only with the repository's `fixture-only` Docker Compose environment.
 */
require __DIR__ . '/support.php';

// Canonical scope normalization and control-character rejection.
ct_test_assert( 'https://example.com/' === ct_scan_normalize_target( 'https://EXAMPLE.com/' ), 'Canonical origin must have lowercase host and trailing slash.' );
foreach ( array( "https://example.com/\n", 'https://example.com/path', 'https://127.0.0.1/', 'https://user@example.com/', 'https://example.com:8443/' ) as $bad_target ) {
	ct_test_assert( is_wp_error( ct_scan_normalize_target( $bad_target ) ), 'Invalid target accepted: ' . bin2hex( $bad_target ) );
}

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
$mail_calls = array();
$mail_mode = true;
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail_calls, &$mail_mode ) {
	$mail_calls[] = $atts;
	return $mail_mode;
}, 10, 2 );

/** Exercise the recipient's one-time POST; a transport result alone never proves delivery. */
function ct_test_redeem_report( $job_id, $mail ) {
	ct_test_assert( isset( $mail['message'] ) && 1 === preg_match( '/[?&]key=([a-f0-9]{64})/', $mail['message'], $match ), 'Report capability missing from the captured fixture notification.' );
	ct_test_assert( false === strpos( $mail['message'], 'PHP2Shell status:' ), 'Notification email leaked report findings.' );
	$preview = ct_scan_report_access_response( 'GET', $job_id, $match[1] );
	ct_test_assert( 200 === $preview['status'] && null === ct_scan_row( $job_id )->report_delivered_at, 'A preview consumed the report capability or falsely recorded delivery.' );
	$response = ct_scan_report_access_response( 'POST', $job_id, $match[1] );
	ct_test_assert( 200 === $response['status'], 'Explicit report redemption did not serve the reviewed report.' );
	$closed = ct_scan_row( $job_id );
	ct_test_assert( ct_scan_closure_metadata_trusted( $closed ) && 'report_delivery' === $closed->closure_source, 'Report redemption did not persist trusted closure evidence.' );
	ct_test_assert( 410 === ct_scan_report_access_response( 'POST', $job_id, $match[1] )['status'], 'A report capability was reusable.' );
}

// Manual no-queue closure and enqueue share a real database lock; cached absence is not authority.
list( $manual_id, $manual_fields ) = ct_test_request( 'manual-close-fixture.example.net' );
$request_ids[] = $manual_id;
ct_test_assert( false === ct_scan_manual_closure_ready( $manual_id ), 'Manual closure did not require connection-owned queue lock.' );
ct_test_assert( ct_scan_lock_acquire(), 'Manual closure fixture could not acquire the queue lock.' );
try {
	ct_test_assert( true === ct_scan_manual_closure_ready( $manual_id ), 'Successful locked empty-queue read refused manual closure readiness.' );
} finally {
	ct_scan_lock_release();
}
ct_test_assert( array() === get_post_meta( $manual_id, '_ct_archive_manual_lifecycle', false ), 'Unexpected fixture marker before race.' );
// Direct SQL models another request committing after this process cached the absent marker.
ct_test_assert( 1 === $wpdb->insert( $wpdb->postmeta, array( 'post_id' => $manual_id, 'meta_key' => '_ct_archive_manual_lifecycle', 'meta_value' => serialize( array( 'state' => 'closed' ) ) ) ), 'Could not persist the independent manual marker fixture.' );
$manual_mail_before = count( $mail_calls );
$manual_event = ct_scan_on_request_ready( $manual_id, $manual_fields );
ct_test_assert( is_wp_error( $manual_event ) && 'manual_final_close' === get_post_meta( $manual_id, '_ct_scan_status_detail', true ), 'A cached absent marker or missing archive verifier permitted enqueue.' );
ct_test_assert( 0 === (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE request_id = %d", $manual_id ) ) && count( $mail_calls ) === $manual_mail_before, 'A manually closed fixture created a job or confirmation email.' );

// A new accepted request creates one confirmation-gated immutable job.
list( $request_id, $fields ) = ct_test_request( 'queue-fixture.example.net' );
$request_ids[] = $request_id;
$event = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( is_array( $event ) && 'awaiting_confirmation' === $event['status'], 'Accepted request was not queued for confirmation.' );
ct_test_assert( 1 === (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE request_id=%d", $request_id ) ), 'Expected exactly one durable job.' );
$row = ct_scan_row( $event['job_id'] );
ct_test_assert( hash( 'sha256', $fields['target'] ) === $row->scope_hash, 'Scope hash must cover the exact canonical target.' );
ct_test_assert( ct_scan_lock_acquire(), 'Existing-job fixture could not acquire the queue lock.' );
try {
	ct_test_assert( false === ct_scan_manual_closure_ready( $request_id ), 'An existing queued request permitted no-queue manual closure.' );
} finally {
	ct_scan_lock_release();
}

ct_test_assert( 'accepted' === $row->confirmation_email_status, 'Confirmation mail acceptance state was not recorded.' );
ct_test_assert( false !== strpos( $mail_calls[0]['message'], 'token=' ), 'Confirmation link missing from the captured fixture email.' );
ct_test_assert( 1 === preg_match( '/[?&]stop=([a-f0-9]{64})/', $mail_calls[0]['message'], $stop_match ), 'Stop link missing from the captured fixture email.' );
ct_test_assert( 1 === preg_match( '/token=([a-f0-9]{64})/', $mail_calls[0]['message'], $confirm_match ) && $confirm_match[1] !== $stop_match[1], 'Stop and confirmation tokens must differ.' );
ct_test_assert( hash( 'sha256', $stop_match[1] ) === $row->stop_token_hash && false === strpos( wp_json_encode( $row ), $stop_match[1] ), 'Only the stop token hash may be stored.' );

// Duplicate hook delivery is database-idempotent even when the event meta is absent.
delete_post_meta( $request_id, '_ct_scan_event_recorded' );
$duplicate = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( ! is_wp_error( $duplicate ) && ! empty( $duplicate['duplicate'] ) && (int) $duplicate['job_id'] === (int) $event['job_id'], 'Duplicate event created a second job or changed state.' );

// Customer stop: wrong tokens fail, a finished job is not reopened, and a stopped job can never be claimed or started.
list( $stop_id, $stop_fields ) = ct_test_request( 'stop-fixture.example.net' );
$request_ids[] = $stop_id;
$mail_before = count( $mail_calls );
$stop_event = ct_scan_on_request_ready( $stop_id, $stop_fields );
preg_match( '/[?&]stop=([a-f0-9]{64})/', $mail_calls[ $mail_before ]['message'], $stop_match );
$stop_token = $stop_match[1];
$stop_row = ct_scan_row_by_stop_hash( hash( 'sha256', $stop_token ) );
ct_test_assert( $stop_row && (int) $stop_row->job_id === (int) $stop_event['job_id'], 'Stop token must resolve only to its own job.' );
ct_test_assert( is_wp_error( ct_scan_customer_stop( $stop_event['job_id'], str_repeat( 'a', 64 ) ) ), 'A wrong stop token was accepted.' );
ct_test_assert( is_wp_error( ct_scan_customer_stop( $event['job_id'], $stop_token ) ), 'A stop token stopped a different job.' );
ct_test_assert( 'awaiting_confirmation' === ct_scan_row( $stop_event['job_id'] )->status, 'A rejected stop changed job state.' );
ct_test_queue_job( $stop_event['job_id'] );
$stop_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$stop_claimed = $stop_claim->get_data()['job'];
ct_test_assert( (int) $stop_claimed['id'] === (int) $stop_event['job_id'], 'Fixture expected the stop job to be claimed.' );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $stop_event['job_id'], $stop_token ), 'A leased job was not stopped by its customer.' );
$stopped = ct_scan_row( $stop_event['job_id'] );
ct_test_assert( 'cancelled' === $stopped->status && 'customer_stopped' === $stopped->error_code && empty( $stopped->lease_hash ) && empty( $stopped->revoked_at ), 'Customer stop must cancel and clear the lease without operator revocation.' );
ct_test_assert( 'cancelled' === get_post_meta( $stop_id, '_ct_scan_status', true ), 'Request status did not record the stop.' );
$late_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $stop_claimed['id'], 'lease' => $stop_claimed['lease'], 'scope_hash' => $stop_claimed['scope_hash'] ) );
ct_test_assert( 410 === $late_start->get_status(), 'A stopped job was started by a stale lease.' );
$late_result = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', array( 'id' => $stop_claimed['id'], 'lease' => $stop_claimed['lease'], 'scope_hash' => $stop_claimed['scope_hash'], 'outcome' => 'completed', 'result' => ct_test_result( $stop_fields['target'] ), 'error' => '', 'checker_revision' => str_repeat( 'a', 40 ) ) );
ct_test_assert( 410 === $late_result->get_status(), 'A stopped job accepted a late result.' );
ct_test_assert( 'already_stopped' === ct_scan_customer_stop( $stop_event['job_id'], $stop_token ), 'Repeated stop must be idempotent.' );
$no_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $no_claim->get_status() && empty( $no_claim->get_data()['job'] ), 'A stopped job must never be claimed again.' );

// Confirmed queue: claim, start-before-work, validated result, and exact receipt retry.
ct_test_queue_job( $event['job_id'] );
$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $claim->get_status() && is_array( $claim->get_data()['job'] ), 'Signed claim did not return a job.' );
$claimed = $claim->get_data()['job'];
ct_test_assert( $claimed['target'] === $fields['target'] && is_int( $claimed['expires_at'] ) && is_int( $claimed['lease_until'] ), 'Claim fields or Unix timestamps are misaligned.' );
$start_payload = array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'] );
$start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', $start_payload );
ct_test_assert( 200 === $start->get_status() && true === $start->get_data()['ok'], 'Start callback was not acknowledged.' );
$run = array(
	'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'], 'outcome' => 'completed',
	'result' => ct_test_result( $fields['target'] ), 'error' => '', 'checker_revision' => str_repeat( 'a', 40 ),
);
// A completed result is not credible unless the guard admitted at least one request for the job.
$unadmitted = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 409 === $unadmitted->get_status() && 'no_admission' === $unadmitted->get_data()['error'] && 'running' === ct_scan_row( $claimed['id'] )->status, 'A completed result was accepted for a job that never had a request admitted.' );
ct_test_assert( 200 === ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'], 'kind' => 'http' ) )->get_status(), 'Fixture admission was refused.' );
$result = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $result->get_status() && true === $result->get_data()['ok'], 'Valid checker receipt was not acknowledged.' );
$retry = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $retry->get_status(), 'An exact receipt retry must be idempotent.' );
$changed = $run;
$changed['result']['title'] = 'Different valid receipt';
$conflict = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $changed );
ct_test_assert( 409 === $conflict->get_status(), 'Changed receipt must conflict.' );
$stale = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), null, time() - 301 );
ct_test_assert( 401 === $stale->get_status(), 'Stale HMAC timestamp must be rejected.' );
$replay_nonce = bin2hex( random_bytes( 16 ) );
$replay1 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
$replay2 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
ct_test_assert( 200 === $replay1->get_status() && 409 === $replay2->get_status(), 'Authenticated nonce replay was not rejected.' );

// Reports preserve old result snapshots, escape evidence, freeze after first send, and separate acceptance from delivery.
$stored = ct_scan_row( $event['job_id'] );
$snapshot = ct_test_result( $fields['target'] );
$snapshot['php2shell_rules_as_of'] = '2024-02-29';
$wpdb->update( $jobs, array( 'result_json' => wp_json_encode( $snapshot ) ), array( 'job_id' => (int) $event['job_id'] ) );
$stored = ct_scan_row( $event['job_id'] );
ct_test_assert( is_wp_error( ct_scan_validate_result( $snapshot, $stored ) ), 'New receipts must match current configured rules date.' );
ct_test_assert( ! is_wp_error( ct_scan_validate_result( $snapshot, $stored, true ) ), 'Stored report snapshot must remain valid after rules-date changes.' );
$admin_details = ct_scan_admin_result_details( $stored );
ct_test_assert( false !== strpos( $admin_details, 'Private stored PHP2Shell evidence' ) && false === strpos( $admin_details, '<script>' ), 'Private result details must render escaped evidence for reviewers.' );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $event['job_id'], 'Reviewed the remaining service scope.' ), 'Manual remainder did not save.' );
$preview = ct_scan_build_report_body( ct_scan_row( $event['job_id'] ) );
ct_test_assert( ! is_wp_error( $preview ) && false !== strpos( $preview, '2024-02-29' ), 'Reviewed report did not retain the frozen rule snapshot.' );
ct_test_assert( false === strpos( $preview, '<script>' ), 'HTML in observed evidence must not appear as executable markup.' );
ct_test_assert( true === ct_scan_admin_send_report( $event['job_id'] ), 'Reviewed report send was not accepted by the isolated mail fixture.' );
ct_test_assert( 'accepted' === ct_scan_row( $event['job_id'] )->report_notification_status, 'Report transport and delivery state were conflated.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $event['job_id'], 'Edited after send' ) ), 'Report details must freeze after a send attempt.' );
ct_test_redeem_report( $event['job_id'], end( $mail_calls ) );

// A revoked unused v8 link stays unredeemable but retains proof for authenticated no-report closure.
list( $revoked_id, $revoked_fields ) = ct_test_request( 'revoked-link-close-fixture.example.net' );
$request_ids[] = $revoked_id;
$revoked_event = ct_scan_on_request_ready( $revoked_id, $revoked_fields );
ct_test_queue_job( $revoked_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $revoked_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $revoked_event['job_id'], 'Synthetic reviewed no-report lifecycle.' ), 'Revoked-link fixture manual review failed.' );
ct_test_assert( true === ct_scan_admin_send_report( $revoked_event['job_id'] ), 'Revoked-link notification fixture failed.' );
$revoked_mail = end( $mail_calls );
ct_test_assert( 1 === preg_match( '/[?&]key=([a-f0-9]{64})/', $revoked_mail['message'], $revoked_key ), 'Revoked-link fixture capability missing.' );
ct_test_assert( true === ct_scan_admin_revoke( $revoked_event['job_id'] ), 'Unused report link could not be revoked.' );
$revoked_row = ct_scan_row( $revoked_event['job_id'] );
ct_test_assert( ct_scan_no_report_close_eligible( $revoked_row ) && is_string( $revoked_row->report_access_token_hash ), 'Revocation destroyed non-secret link-only provenance.' );
ct_test_assert( 410 === ct_scan_report_access_response( 'POST', $revoked_event['job_id'], $revoked_key[1] )['status'] && null === ct_scan_row( $revoked_event['job_id'] )->report_delivered_at, 'Revoked capability exposed findings or falsely recorded retrieval.' );
$close_admin = wp_insert_user( array( 'user_login' => 'ct_close_' . wp_generate_password( 8, false ), 'user_pass' => wp_generate_password(), 'role' => 'administrator' ) );
ct_test_assert( ! is_wp_error( $close_admin ), 'Synthetic closure administrator could not be created.' );
wp_set_current_user( $close_admin );
ct_test_assert( true === ct_scan_admin_close( $revoked_event['job_id'], 'failed' ), 'Authenticated no-report closure of an unused revoked link was refused.' );
$closed_revoked = ct_scan_row( $revoked_event['job_id'] );
ct_test_assert( ct_scan_closure_metadata_trusted( $closed_revoked ) && 'admin_final_close' === $closed_revoked->closure_source && (int) $close_admin === (int) $closed_revoked->closed_by, 'Revoked-link final closure lacks its trusted event.' );
ob_start(); ct_scan_admin_render_final_close_metabox( (object) array( 'ID' => $revoked_id ) ); $closed_metabox = ob_get_clean();
ct_test_assert( false !== strpos( $closed_metabox, 'Final closure: admin_final_close' ) && false === strpos( $closed_metabox, 'does not pass validation' ), 'Actual database metabox projection rejected the saved administrator event.' );
ct_test_assert( 410 === ct_scan_report_access_response( 'POST', $revoked_event['job_id'], $revoked_key[1] )['status'], 'Final closure revived the revoked capability.' );
wp_set_current_user( 0 );
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user( $close_admin );

// An expired, never-confirmed request cannot receive detailed findings, even after manual review.
list( $unconfirmed_id, $unconfirmed_fields ) = ct_test_request( 'unconfirmed-report-fixture.example.net' );
$request_ids[] = $unconfirmed_id;
$unconfirmed_event = ct_scan_on_request_ready( $unconfirmed_id, $unconfirmed_fields );
$wpdb->update( $jobs, array( 'status' => 'expired', 'error_code' => 'confirmation_expired', 'finished_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null ), array( 'job_id' => (int) $unconfirmed_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unconfirmed_event['job_id'], 'Operator notes entered after expiry.' ), 'Unconfirmed fixture manual notes failed.' );
$mail_count = count( $mail_calls );
$unconfirmed_send = ct_scan_admin_send_report( $unconfirmed_event['job_id'] );
ct_test_assert( is_wp_error( $unconfirmed_send ) && 'report_recipient_unconfirmed' === $unconfirmed_send->get_error_code(), 'An unconfirmed recipient was allowed a detailed report.' );
ct_test_assert( count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unconfirmed_event['job_id'] )->report_notification_status, 'A refused unconfirmed report must not send or change send state.' );

// Confirmation evidence is validated as stored by MariaDB, not by PHP truthiness. The disposable
// session deliberately permits zero and impossible dates so readback proves these are real DATETIME
// values the validator must reject. No scanner/worker traffic is needed to prepare these reports.
$confirmation_sql_mode = $wpdb->get_var( 'SELECT @@SESSION.sql_mode' );
ct_test_assert( is_string( $confirmation_sql_mode ), 'Could not read the disposable session SQL mode.' );
ct_test_assert( false !== $wpdb->query( "SET SESSION sql_mode = 'ALLOW_INVALID_DATES'" ), 'Could not configure the disposable invalid-date storage fixture.' );
try {
	foreach ( array( 'zero', 'partial_zero', 'invalid_calendar', 'before_acceptance', 'before_creation', 'future', 'after_authorization', 'missing' ) as $confirmation_case ) {
		list( $confirmation_id, $confirmation_fields ) = ct_test_request( 'confirmation-' . str_replace( '_', '-', $confirmation_case ) . '-fixture.example.net' );
		$request_ids[] = $confirmation_id;
		$confirmation_accepted_epoch = time() - 3600;
		update_post_meta( $confirmation_id, '_ct_terms_accepted_at', gmdate( 'Y-m-d\TH:i:s\Z', $confirmation_accepted_epoch ) );
		$confirmation_event = ct_scan_on_request_ready( $confirmation_id, $confirmation_fields );
		ct_test_assert( is_array( $confirmation_event ), 'Confirmation matrix request was not queued: ' . $confirmation_case );
		$confirmation_job_id = (int) $confirmation_event['job_id'];
		ct_test_queue_job( $confirmation_job_id );
		ct_test_assert( 1 === $wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now(), 'created_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 60 ), 'confirmed_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 120 ) ), array( 'job_id' => $confirmation_job_id ) ), 'Could not prepare terminal confirmation fixture: ' . $confirmation_case );
		ct_test_assert( true === ct_scan_admin_save_manual_remainder( $confirmation_job_id, 'Synthetic confirmation chronology review.' ), 'Could not prepare reviewed confirmation fixture: ' . $confirmation_case );
		$confirmation_good = ct_scan_row( $confirmation_job_id );
		ct_test_assert( ct_scan_confirmation_metadata_trusted( $confirmation_good ), 'Confirmation matrix positive prerequisite was invalid: ' . $confirmation_case );
		$confirmation_accepted_epoch = strtotime( $confirmation_good->terms_accepted_at . ' UTC' );
		switch ( $confirmation_case ) {
			case 'zero': $confirmation_changes = array( 'confirmed_at' => '0000-00-00 00:00:00' ); break;
			case 'partial_zero': $confirmation_changes = array( 'confirmed_at' => '2024-02-00 00:00:00' ); break;
			case 'invalid_calendar': $confirmation_changes = array( 'confirmed_at' => '2024-02-30 00:00:00' ); break;
			case 'before_acceptance': $confirmation_changes = array( 'created_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch - 60 ), 'confirmed_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch - 1 ) ); break;
			case 'before_creation': $confirmation_changes = array( 'created_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 600 ), 'confirmed_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 300 ) ); break;
			case 'future': $confirmation_changes = array( 'confirmed_at' => gmdate( 'Y-m-d H:i:s', time() + 3600 ) ); break;
			case 'after_authorization': $confirmation_changes = array( 'authorization_expires_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 60 ), 'confirmed_at' => gmdate( 'Y-m-d H:i:s', $confirmation_accepted_epoch + 120 ) ); break;
			case 'missing': $confirmation_changes = array( 'confirmed_at' => null ); break;
		}
		$confirmation_restore = array();
		foreach ( $confirmation_changes as $confirmation_field => $confirmation_value ) {
			$confirmation_restore[ $confirmation_field ] = $confirmation_good->$confirmation_field;
		}
		ct_test_assert( 1 === $wpdb->update( $jobs, $confirmation_changes, array( 'job_id' => $confirmation_job_id ) ), 'Invalid confirmation fixture update did not change exactly one row: ' . $confirmation_case );
		$confirmation_bad = ct_scan_row( $confirmation_job_id );
		foreach ( $confirmation_changes as $confirmation_field => $confirmation_value ) {
			ct_test_assert( $confirmation_value === $confirmation_bad->$confirmation_field, 'Invalid confirmation fixture did not survive DATETIME storage exactly: ' . $confirmation_case . '/' . $confirmation_field );
		}
		update_post_meta( $confirmation_id, '_ct_scan_authorization_expires_at', $confirmation_bad->authorization_expires_at );
		if ( 'before_creation' === $confirmation_case ) {
			ct_test_assert( $confirmation_bad->confirmed_at >= $confirmation_bad->terms_accepted_at && $confirmation_bad->confirmed_at <= ct_scan_utc_now() && $confirmation_bad->confirmed_at < $confirmation_bad->created_at, 'Before-creation fixture did not isolate the creation chronology boundary.' );
		}
		if ( 'after_authorization' === $confirmation_case ) {
			ct_test_assert( $confirmation_bad->confirmed_at >= $confirmation_bad->created_at && $confirmation_bad->confirmed_at >= $confirmation_bad->terms_accepted_at && $confirmation_bad->confirmed_at <= ct_scan_utc_now() && $confirmation_bad->confirmed_at > $confirmation_bad->authorization_expires_at, 'After-authorization fixture did not isolate the frozen deadline boundary.' );
		}
		ct_test_assert( false === ct_scan_confirmation_metadata_trusted( $confirmation_bad ), 'Stored invalid confirmation passed its evidence validator: ' . $confirmation_case );
		$confirmation_mail_count = count( $mail_calls );
		$confirmation_refused = ct_scan_admin_send_report( $confirmation_job_id );
		ct_test_assert( is_wp_error( $confirmation_refused ) && 'report_recipient_unconfirmed' === $confirmation_refused->get_error_code(), 'Stored invalid confirmation was not refused before notification: ' . $confirmation_case );
		ct_test_assert( count( $mail_calls ) === $confirmation_mail_count && 'not_sent' === ct_scan_row( $confirmation_job_id )->report_notification_status, 'Invalid confirmation sent mail or altered notification state: ' . $confirmation_case );
		ct_test_assert( 1 === $wpdb->update( $jobs, $confirmation_restore, array( 'job_id' => $confirmation_job_id ) ), 'Could not restore notification positive control: ' . $confirmation_case );
		update_post_meta( $confirmation_id, '_ct_scan_authorization_expires_at', $confirmation_good->authorization_expires_at );
		ct_test_assert( true === ct_scan_admin_send_report( $confirmation_job_id ), 'Valid confirmation notification positive control failed: ' . $confirmation_case );
		$confirmation_mail = end( $mail_calls );
		ct_test_assert( 1 === preg_match( '/[?&]key=([a-f0-9]{64})/', $confirmation_mail['message'], $confirmation_key ), 'Confirmation matrix report capability missing.' );
		ct_test_assert( 1 === $wpdb->update( $jobs, $confirmation_changes, array( 'job_id' => $confirmation_job_id ) ), 'Could not persist invalid confirmation before retrieval: ' . $confirmation_case );
		update_post_meta( $confirmation_id, '_ct_scan_authorization_expires_at', $confirmation_bad->authorization_expires_at );
		$confirmation_response = ct_scan_report_access_response( 'POST', $confirmation_job_id, $confirmation_key[1] );
		$confirmation_after = ct_scan_row( $confirmation_job_id );
		ct_test_assert( 410 === $confirmation_response['status'] && false === strpos( $confirmation_response['body'], 'Synthetic confirmation chronology review.' ) && null === $confirmation_after->report_access_used_at && null === $confirmation_after->report_delivered_at, 'Invalid stored confirmation exposed findings or recorded delivery: ' . $confirmation_case );
		ct_test_assert( 1 === $wpdb->update( $jobs, $confirmation_restore, array( 'job_id' => $confirmation_job_id ) ), 'Could not restore retrieval positive control: ' . $confirmation_case );
		update_post_meta( $confirmation_id, '_ct_scan_authorization_expires_at', $confirmation_good->authorization_expires_at );
		ct_test_assert( 200 === ct_scan_report_access_response( 'POST', $confirmation_job_id, $confirmation_key[1] )['status'], 'Valid confirmation retrieval positive control failed: ' . $confirmation_case );
	}

	// DATETIME canonicalizes an ISO separator on insert: it cannot preserve that noncanonical PHP
	// string. Assert the actual storage normalization and keep that valid canonical value usable;
	// standalone tests separately reject noncanonical strings passed directly to the validator.
	list( $normalized_id, $normalized_fields ) = ct_test_request( 'confirmation-normalized-fixture.example.net' );
	$request_ids[] = $normalized_id;
	$normalized_event = ct_scan_on_request_ready( $normalized_id, $normalized_fields );
	ct_test_assert( is_array( $normalized_event ), 'Canonicalization control request did not queue.' );
	ct_test_queue_job( $normalized_event['job_id'] );
	$normalized_good = ct_scan_row( $normalized_event['job_id'] );
	$normalized_iso = str_replace( ' ', 'T', $normalized_good->confirmed_at );
	ct_test_assert( false !== $wpdb->update( $jobs, array( 'confirmed_at' => $normalized_iso ), array( 'job_id' => (int) $normalized_event['job_id'] ) ), 'DATETIME ISO separator control could not be stored.' );
	$normalized_row = ct_scan_row( $normalized_event['job_id'] );
	ct_test_assert( $normalized_good->confirmed_at === $normalized_row->confirmed_at && $normalized_iso !== $normalized_row->confirmed_at && ct_scan_confirmation_metadata_trusted( $normalized_row ), 'DATETIME did not canonicalize the ISO separator into valid confirmation evidence.' );
	$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $normalized_event['job_id'] ) );
	ct_test_assert( true === ct_scan_admin_save_manual_remainder( $normalized_event['job_id'], 'Synthetic canonicalized datetime review.' ), 'Canonicalized control manual review failed.' );
	ct_test_assert( true === ct_scan_admin_send_report( $normalized_event['job_id'] ), 'Canonicalized DATETIME notification positive control failed.' );
	ct_test_redeem_report( $normalized_event['job_id'], end( $mail_calls ) );
} finally {
	ct_test_assert( false !== $wpdb->query( $wpdb->prepare( 'SET SESSION sql_mode = %s', $confirmation_sql_mode ) ), 'Could not restore the disposable session SQL mode.' );
}

// Traffic authorization expiry does not retroactively erase valid mailbox confirmation. This is
// an original legacy no-control fixture, with confirmation inside its frozen historical window.
list( $historical_id, $historical_fields ) = ct_test_request( 'historical-confirmation-fixture.example.net' );
$request_ids[] = $historical_id;
$historical_accepted_epoch = time() - 3 * 86400;
update_post_meta( $historical_id, '_ct_terms_accepted_at', gmdate( 'Y-m-d\TH:i:s\Z', $historical_accepted_epoch ) );
$historical_event = ct_scan_on_request_ready( $historical_id, $historical_fields );
ct_test_assert( is_array( $historical_event ), 'Historical confirmation fixture did not queue.' );
$historical_expiry = gmdate( 'Y-m-d H:i:s', time() - 86400 );
ct_test_assert( 1 === $wpdb->update( $jobs, array(
	'status' => 'failed', 'finished_at' => ct_scan_utc_now(), 'created_at' => gmdate( 'Y-m-d H:i:s', $historical_accepted_epoch + 60 ),
	'confirmed_at' => gmdate( 'Y-m-d H:i:s', $historical_accepted_epoch + 120 ), 'authorization_expires_at' => $historical_expiry,
	'confirmation_token_hash' => null, 'confirmation_expires_at' => null,
), array( 'job_id' => (int) $historical_event['job_id'] ) ), 'Historical confirmation fixture update failed.' );
update_post_meta( $historical_id, '_ct_scan_authorization_expires_at', $historical_expiry );
$historical_row = ct_scan_row( $historical_event['job_id'] );
ct_test_assert( 0 === (int) $historical_row->control_required && ct_scan_confirmation_metadata_trusted( $historical_row ) && ! ct_scan_authorization_is_live( $historical_row ), 'Historical positive control did not isolate valid confirmation from expired traffic authorization.' );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $historical_event['job_id'], 'Synthetic report prepared after traffic authorization expired.' ), 'Historical report manual review failed.' );
ct_test_assert( true === ct_scan_admin_send_report( $historical_event['job_id'] ), 'Valid historical confirmation was refused a prepared report notification.' );
ct_test_redeem_report( $historical_event['job_id'], end( $mail_calls ) );

// Unknown mail outcomes remain one-shot; explicit recipient redemption still records actual report access.
list( $unknown_id, $unknown_fields ) = ct_test_request( 'unknown-mail-fixture.example.net' );
$request_ids[] = $unknown_id;
$unknown_event = ct_scan_on_request_ready( $unknown_id, $unknown_fields );
ct_test_queue_job( $unknown_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $unknown_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'No remaining work was performed in this fixture.' ), 'Unknown-mail fixture manual notes failed.' );
$mail_mode = false;
$mail_count = count( $mail_calls );
$fail_send_state_once = true;
$fail_send_state_filter = static function ( $query ) use ( &$fail_send_state_once, $jobs ) {
	if ( $fail_send_state_once && false !== strpos( $query, "SET `report_notification_status` = 'unknown'" ) && false !== strpos( $query, $jobs ) ) {
		$fail_send_state_once = false;
		return preg_replace( '/ WHERE /', ' WHERE 1=0 AND ', $query, 1 );
	}
	return $query;
};
add_filter( 'query', $fail_send_state_filter );
$write_failure = ct_scan_admin_send_report( $unknown_event['job_id'] );
remove_filter( 'query', $fail_send_state_filter );
ct_test_assert( is_wp_error( $write_failure ) && count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'A failed durable one-time send write must not send email.' );
$unknown_send = ct_scan_admin_send_report( $unknown_event['job_id'] );
ct_test_assert( is_wp_error( $unknown_send ) && 'unknown' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'Unconfirmed mail must remain unknown and must not be retried.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'Altered content' ) ), 'Report contents changed after an unknown send outcome.' );
ct_test_redeem_report( $unknown_event['job_id'], end( $mail_calls ) );
$mail_mode = true;

// The recorded terms hash is compared case-insensitively at report time (the job stores it lowercased).
list( $upper_id, $upper_fields ) = ct_test_request( 'upper-hash-report-fixture.example.net' );
$request_ids[] = $upper_id;
update_post_meta( $upper_id, '_ct_terms_sha256', strtoupper( get_post_meta( $upper_id, '_ct_terms_sha256', true ) ) );
$upper_event = ct_scan_on_request_ready( $upper_id, $upper_fields );
ct_test_assert( is_array( $upper_event ), 'A request with an upper-case terms hash was refused.' );
ct_test_queue_job( $upper_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $upper_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $upper_event['job_id'], 'No remaining work was performed in this fixture.' ), 'Upper-case hash fixture manual notes failed.' );
ct_test_assert( true === ct_scan_admin_send_report( $upper_event['job_id'] ), 'An upper-case recorded terms hash blocked the reviewed report.' );

// Old requests are never backfilled, and any changed saved target permanently cancels authorization.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'legacy-fixture.example.net' );
$request_ids[] = $legacy_id;
delete_post_meta( $legacy_id, '_ct_terms_saved' );
$legacy_event = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
ct_test_assert( is_wp_error( $legacy_event ) && ! $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$jobs} WHERE request_id=%d", $legacy_id ) ), 'A legacy request without the durable acceptance marker was backfilled.' );

list( $changed_id, $changed_fields ) = ct_test_request( 'changed-target-fixture.example.net' );
$request_ids[] = $changed_id;
$changed_event = ct_scan_on_request_ready( $changed_id, $changed_fields );
ct_test_assert( ! is_wp_error( $changed_event ), 'Changed-target fixture setup failed.' );
update_post_meta( $changed_id, '_ct_scan_target', 'https://different-fixture.example.net/' );
ct_test_assert( ! ct_scan_authorization_is_live( ct_scan_row( $changed_event['job_id'] ) ), 'A changed saved target remained authorized.' );
ct_test_queue_job( $changed_event['job_id'] );
$changed_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $changed_claim->get_status() && null === $changed_claim->get_data()['job'] && 'cancelled' === ct_scan_row( $changed_event['job_id'] )->status, 'A changed-target job was claimable instead of being canceled.' );

// Revocation while leased prevents start; an expired running lease is terminal and never rescanned.
list( $revoked_id, $revoked_fields ) = ct_test_request( 'revoked-fixture.example.net' );
$request_ids[] = $revoked_id;
$revoked_event = ct_scan_on_request_ready( $revoked_id, $revoked_fields );
ct_test_queue_job( $revoked_event['job_id'] );
$revoked_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$revoked_job = $revoked_claim->get_data()['job'];
ct_test_assert( is_array( $revoked_job ), 'Expected to claim the revocation fixture.' );
ct_test_assert( true === ct_scan_admin_revoke( $revoked_job['id'] ), 'Admin revocation did not persist.' );
$revoked_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $revoked_job['id'], 'lease' => $revoked_job['lease'], 'scope_hash' => $revoked_job['scope_hash'] ) );
ct_test_assert( 410 === $revoked_start->get_status() && 'cancelled' === ct_scan_row( $revoked_job['id'] )->status, 'Revoked authorization allowed worker start.' );

list( $lease_id, $lease_fields ) = ct_test_request( 'expired-lease-fixture.example.net' );
$request_ids[] = $lease_id;
$lease_event = ct_scan_on_request_ready( $lease_id, $lease_fields );
ct_test_queue_job( $lease_event['job_id'] );
$lease_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_job = $lease_claim->get_data()['job'];
ct_test_assert( is_array( $lease_job ), 'Expected to claim the expired-lease fixture.' );
$lease_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $lease_job['id'], 'lease' => $lease_job['lease'], 'scope_hash' => $lease_job['scope_hash'] ) );
ct_test_assert( 200 === $lease_start->get_status(), 'Expired-lease fixture did not enter running state.' );
$wpdb->update( $jobs, array( 'lease_until' => gmdate( 'Y-m-d H:i:s', time() - 5 ) ), array( 'job_id' => (int) $lease_job['id'] ) );
$after_expiry_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_row = ct_scan_row( $lease_job['id'] );
ct_test_assert( 200 === $after_expiry_claim->get_status() && null === $after_expiry_claim->get_data()['job'] && 'failed_unknown' === $lease_row->status && 1 === (int) $lease_row->attempts, 'An expired running lease was automatically rescanned or not marked unknown.' );

// Calendar-based retention clears result/manual content at 12 months, and only removes the exact private linked request at 3 years.
list( $retention_id, $retention_fields ) = ct_test_request( 'retention-fixture.example.net' );
$request_ids[] = $retention_id;
$retention_event = ct_scan_on_request_ready( $retention_id, $retention_fields );
$old_finished = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-13 months' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => $old_finished, 'closed_at' => $old_finished, 'closure_source' => 'admin_final_close', 'closed_by' => 1, 'closure_reason' => 'failed', 'report_delivered_at' => null, 'report_access_used_at' => null, 'created_at' => $old_finished, 'terms_accepted_at' => $old_finished, 'result_json' => '{}', 'manual_remainder_notes' => 'private notes' ), array( 'job_id' => (int) $retention_event['job_id'] ) );
ct_test_maintain();
$retained = ct_scan_row( $retention_event['job_id'] );
ct_test_assert( $retained && null === $retained->result_json && null === $retained->manual_remainder_notes && get_post( $retention_id ), '12-month cleanup must clear result/manual data but retain the request evidence.' );
$three_years = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-3 years -1 day' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => $three_years, 'finished_at' => $three_years, 'closed_at' => $three_years, 'created_at' => $three_years, 'retain_until' => null ), array( 'job_id' => (int) $retention_event['job_id'] ) );
$hold_delete = static function ( $check, $post ) use ( $retention_id ) {
	return (int) $retention_id === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $hold_delete, 10, 2 );
ct_test_maintain();
remove_filter( 'pre_delete_post', $hold_delete, 10 );
ct_test_assert( ct_scan_row( $retention_event['job_id'] ) && get_post( $retention_id ) && '' === ct_scan_row( $retention_event['job_id'] )->contact_email && '' === ct_scan_row( $retention_event['job_id'] )->contact_name, 'Failed three-year post deletion must retain the job link while scrubbing contact fields.' );
ct_test_maintain();
ct_test_assert( ! ct_scan_row( $retention_event['job_id'] ) && ! get_post( $retention_id ), 'Three-year cleanup must remove the exact linked private request and job.' );

// Remove only records created by this test.
foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "WordPress integration checks passed.\n";
