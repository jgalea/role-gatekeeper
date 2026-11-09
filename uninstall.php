<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

define( 'ROLEWRIGHT_DIR', plugin_dir_path( __FILE__ ) );

require_once ROLEWRIGHT_DIR . 'includes/modules/audit/uninstall.php';

global $wpdb;

$rolewright_patterns = array(
	$wpdb->esc_like( 'rolewright_' ) . '%',
	$wpdb->esc_like( '_transient_rolewright_' ) . '%',
	$wpdb->esc_like( '_transient_timeout_rolewright_' ) . '%',
);

foreach ( $rolewright_patterns as $rolewright_pattern ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $rolewright_pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	if ( is_multisite() ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $rolewright_pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
}

$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE meta_key IN ('_rolewright_roles', '_rolewright_message')" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE meta_key LIKE '\\_rolewright\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

wp_clear_scheduled_hook( 'rolewright_audit_prune' );
