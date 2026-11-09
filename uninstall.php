<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( ! defined( 'ROLEWRIGHT_DIR' ) ) {
	define( 'ROLEWRIGHT_DIR', plugin_dir_path( __FILE__ ) );
}

require_once ROLEWRIGHT_DIR . 'includes/modules/audit/uninstall.php';

global $wpdb;

$rolewright_patterns = array(
	$wpdb->esc_like( 'rolewright_' ) . '%',
	$wpdb->esc_like( '_transient_rolewright_' ) . '%',
	$wpdb->esc_like( '_transient_timeout_rolewright_' ) . '%',
);

// Cleans one site: options, post meta and the rolewright_* caps on every role. Written
// straight to the tables so a missing table or another plugin's option filter can't stop it.
$rolewright_clean_site = function () use ( $wpdb, $rolewright_patterns ) {
	$suppress = $wpdb->suppress_errors( true );
	foreach ( $rolewright_patterns as $pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
	$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE meta_key LIKE '\\_rolewright\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

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
				if ( 0 === strpos( (string) $cap, 'rolewright_' ) ) {
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
	$rolewright_sites = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $rolewright_sites as $rolewright_site ) {
		switch_to_blog( (int) $rolewright_site );
		try {
			$rolewright_clean_site();
		} finally {
			restore_current_blog();
		}
	}
	foreach ( $rolewright_patterns as $rolewright_pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $rolewright_pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
	unset( $rolewright_sites, $rolewright_site, $rolewright_pattern );
} else {
	$rolewright_clean_site();
}

$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", 'rolewright_rescue_token' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
if ( function_exists( 'wp_cache_flush_group' ) ) {
	wp_cache_flush_group( 'user_meta' );
}

wp_clear_scheduled_hook( 'rolewright_audit_prune' );
