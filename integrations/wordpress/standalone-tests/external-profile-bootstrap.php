<?php
// Pure WordPress API doubles only: no bootstrap, database, DNS, HTTP or mail.
define( 'ABSPATH', __DIR__ );
define( 'WP_CONTENT_DIR', __DIR__ . '/absent-private-config' );
class WP_Error { private $code; function __construct( $code = '', $message = '' ) { $this->code = $code; } function get_error_code() { return $this->code; } }
function is_wp_error( $v ) { return $v instanceof WP_Error; }
function add_action( ...$args ) {}
function wp_parse_url( $v ) { return parse_url( $v ); }
function wp_json_encode( $v, $flags = 0 ) { return json_encode( $v, $flags ); }
function get_post_meta( $id, $key, $single = true ) { $v = $GLOBALS['meta'][$id][$key] ?? array(); return $single ? ( $v[0] ?? '' ) : $v; }
function sanitize_text_field( $v ) { return trim( strip_tags( $v ) ); }
class ExternalDb {
 public $prefix = 'wp_'; public $row; public $fail = false; public $updates = 0;
 function update( $table, $data, $where, $format = null, $where_format = null ) {
  if ( $this->fail ) { return 0; }
  foreach ( $where as $key => $value ) { if ( (string) ( $this->row->$key ?? '' ) !== (string) $value ) { return 0; } }
  foreach ( $data as $key => $value ) { $this->row->$key = $value; }
  ++$this->updates; return 1;
 }
}
require dirname( __DIR__ ) . '/ct-scan.php';
