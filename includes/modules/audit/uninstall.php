<?php
// Included by the plugin's uninstall.php. Drops the audit table only when the setting says so.
// On multisite: on every site when the setting is on for the site running the uninstall,
// otherwise on each site that turned it on itself.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$rolegate_audit_drop = function ( bool $force ) {
	global $wpdb;
	$settings = get_option( 'rolegate_audit_settings', array() );
	if ( ! $force && ! ( is_array( $settings ) && ! empty( $settings['delete_on_uninstall'] ) ) ) {
		return;
	}
	$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'rolegate_audit' ) . '`' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
	delete_option( 'rolegate_audit_schema' );
	delete_option( 'rolegate_audit_settings' );
	wp_clear_scheduled_hook( 'rolegate_audit_prune' );
};

$rolegate_audit_settings = get_option( 'rolegate_audit_settings', array() );
$rolegate_audit_all      = is_array( $rolegate_audit_settings ) && ! empty( $rolegate_audit_settings['delete_on_uninstall'] );
if ( is_multisite() ) {
	$rolegate_audit_sites = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $rolegate_audit_sites as $rolegate_audit_site ) {
		switch_to_blog( (int) $rolegate_audit_site );
		$rolegate_audit_drop( $rolegate_audit_all );
		restore_current_blog();
	}
	unset( $rolegate_audit_sites, $rolegate_audit_site );
} else {
	$rolegate_audit_drop( false );
}
unset( $rolegate_audit_settings, $rolegate_audit_all, $rolegate_audit_drop );
