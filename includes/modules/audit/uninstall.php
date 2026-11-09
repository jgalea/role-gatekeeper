<?php
// Included by the plugin's uninstall.php. Drops the audit table only when the setting says so.
// On multisite: on every site when the setting is on for the site running the uninstall,
// otherwise on each site that turned it on itself.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$rolewright_audit_drop = function ( bool $force ) {
	global $wpdb;
	$settings = get_option( 'rolewright_audit_settings', array() );
	if ( ! $force && ! ( is_array( $settings ) && ! empty( $settings['delete_on_uninstall'] ) ) ) {
		return;
	}
	$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'rolewright_audit' ) . '`' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
	delete_option( 'rolewright_audit_schema' );
	delete_option( 'rolewright_audit_settings' );
	wp_clear_scheduled_hook( 'rolewright_audit_prune' );
};

$rolewright_audit_settings = get_option( 'rolewright_audit_settings', array() );
$rolewright_audit_all      = is_array( $rolewright_audit_settings ) && ! empty( $rolewright_audit_settings['delete_on_uninstall'] );
if ( is_multisite() ) {
	$rolewright_audit_sites = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $rolewright_audit_sites as $rolewright_audit_site ) {
		switch_to_blog( (int) $rolewright_audit_site );
		$rolewright_audit_drop( $rolewright_audit_all );
		restore_current_blog();
	}
	unset( $rolewright_audit_sites, $rolewright_audit_site );
} else {
	$rolewright_audit_drop( false );
}
unset( $rolewright_audit_settings, $rolewright_audit_all, $rolewright_audit_drop );
