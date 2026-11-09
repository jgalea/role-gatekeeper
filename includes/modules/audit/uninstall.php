<?php
// Included by the plugin's uninstall.php. Drops the audit table only when the setting says so.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$rolewright_audit_settings = get_option( 'rolewright_audit_settings', array() );
if ( is_array( $rolewright_audit_settings ) && ! empty( $rolewright_audit_settings['delete_on_uninstall'] ) ) {
	global $wpdb;
	$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'rolewright_audit' ) . '`' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
	delete_option( 'rolewright_audit_schema' );
	delete_option( 'rolewright_audit_settings' );
	wp_clear_scheduled_hook( 'rolewright_audit_prune' );
}
unset( $rolewright_audit_settings );
