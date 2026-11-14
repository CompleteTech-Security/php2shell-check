<?php
// Offline cross-language bridge only. STDIN contains synthetic worker callback JSON.
// No WordPress bootstrap, database, HTTP, DNS, mail, secrets, or customer records.
require __DIR__ . '/external-profile-bootstrap.php';
$raw = stream_get_contents( STDIN, 131073 );
$v = strlen( $raw ) <= 131072 ? json_decode( $raw, true ) : null;
$accepted = false; $error = 'bridge_schema';
if ( is_array( $v ) && ct_scan_expected_keys( $v, array( 'target', 'binding', 'callback' ) )
 && is_string( $v['target'] ) && is_array( $v['binding'] ) && ct_scan_expected_keys( $v['binding'], array( 'profile_id', 'profile_sha256', 'services' ) )
 && is_array( $v['callback'] ) ) {
 $row = (object) array( 'target_origin' => $v['target'], 'profile_id' => $v['binding']['profile_id'], 'profile_sha256' => $v['binding']['profile_sha256'], 'services_json' => wp_json_encode( ct_scan_canonicalize( $v['binding']['services'] ), JSON_UNESCAPED_SLASHES ) );
 $callback = $v['callback']; $error = 'profile_binding_invalid';
 if ( ct_scan_callback_payload( $callback ) && ct_scan_result_profile_matches( $callback, $row ) ) {
  $error = 'callback_semantics_invalid';
  if ( 'completed' === $callback['outcome'] && '' === $callback['error'] ) {
   $result = ct_scan_validate_result( $callback['result'], $row );
   $accepted = ! is_wp_error( $result ); $error = $accepted ? '' : $result->get_error_code();
  } elseif ( 'failed' === $callback['outcome'] && null === $callback['result'] && is_string( $callback['error'] ) && preg_match( '/\A[a-z][a-z0-9_]{0,63}\z/', $callback['error'] ) ) {
   $accepted = true; $error = '';
  }
 }
}
echo json_encode( array( 'accepted' => $accepted, 'error' => $error ) ) . "\n";
