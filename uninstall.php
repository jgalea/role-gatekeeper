<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( ! defined( 'ROLEGATE_DIR' ) ) {
	define( 'ROLEGATE_DIR', plugin_dir_path( __FILE__ ) );
}

require_once ROLEGATE_DIR . 'includes/modules/audit/uninstall.php';

global $wpdb;

$rolegate_patterns = array(
	$wpdb->esc_like( 'rolegate_' ) . '%',
	$wpdb->esc_like( '_transient_rolegate_' ) . '%',
	$wpdb->esc_like( '_transient_timeout_rolegate_' ) . '%',
);

// Cleans one site: options, post meta and the rolegate_* caps on every role. Written
// straight to the tables so a missing table or another plugin's option filter can't stop it.
$rolegate_clean_site = function () use ( $wpdb, $rolegate_patterns ) {
	$suppress = $wpdb->suppress_errors( true );
	foreach ( $rolegate_patterns as $pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
	$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE meta_key LIKE '\\_rolegate\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

	$key   = $wpdb->get_blog_prefix() . 'user_roles';
	$raw   = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$roles = is_string( $raw ) ? maybe_unserialize( $raw ) : null;
	if ( is_array( $roles ) ) {
		$changed = false;
		foreach ( $roles as $slug => $data ) {
			if ( ! isset( $data['capabilities'] ) || ! is_array( $data['capabilities'] ) ) {
				continue;
			}
			foreach ( array_keys( $data['capabilities'] ) as $cap ) {
				if ( 0 === strpos( (string) $cap, 'rolegate_' ) ) {
					unset( $roles[ $slug ]['capabilities'][ $cap ] );
					$changed = true;
				}
			}
		}
		if ( $changed ) {
			$wpdb->update( $wpdb->options, array( 'option_value' => maybe_serialize( $roles ) ), array( 'option_name' => $key ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		}
	}
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_delete( 'notoptions', 'options' );
	wp_cache_delete( $key, 'options' );
	$wpdb->suppress_errors( $suppress );
};

if ( is_multisite() ) {
	$rolegate_sites = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $rolegate_sites as $rolegate_site ) {
		switch_to_blog( (int) $rolegate_site );
		try {
			$rolegate_clean_site();
		} finally {
			restore_current_blog();
		}
	}
	foreach ( $rolegate_patterns as $rolegate_pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $rolegate_pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
	unset( $rolegate_sites, $rolegate_site, $rolegate_pattern );
} else {
	$rolegate_clean_site();
}

$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", 'rolegate_rescue_token' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", 'rolegate_disabled' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
if ( function_exists( 'wp_cache_flush_group' ) ) {
	wp_cache_flush_group( 'user_meta' );
}

wp_clear_scheduled_hook( 'rolegate_audit_prune' );
