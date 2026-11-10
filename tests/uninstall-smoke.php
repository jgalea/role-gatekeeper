<?php
/**
 * Run last: wp eval-file wp-content/plugins/role-gatekeeper/tests/uninstall-smoke.php
 *
 * Runs uninstall.php in place (never `wp plugin uninstall` on the bind-mounted plugin),
 * checks what it removed, then puts the plugin's caps and module settings back.
 */

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Enforcer;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

$rw_pass = 0;
$rw_fail = 0;
$rw_ok   = function ( $cond, $label ) use ( &$rw_pass, &$rw_fail ) {
	if ( $cond ) {
		++$rw_pass;
		echo 'PASS ' . $label . "\n";
	} else {
		++$rw_fail;
		echo 'FAIL ' . $label . "\n";
	}
};

global $wpdb;
$rw_raw_roles = function () use ( $wpdb ) {
	$raw = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $wpdb->get_blog_prefix() . 'user_roles' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$val = maybe_unserialize( $raw );
	return is_array( $val ) ? $val : array();
};
$rw_plugin_caps = function ( array $roles ) {
	$out = array();
	foreach ( $roles as $slug => $data ) {
		foreach ( array_keys( (array) ( $data['capabilities'] ?? array() ) ) as $cap ) {
			if ( 0 === strpos( (string) $cap, 'rolegate_' ) ) {
				$out[] = $slug . ':' . $cap;
			}
		}
	}
	return $out;
};
$rw_probe_count = function () use ( $wpdb ) {
	return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s", 'rolegate_uninstall_probe' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
};

$rw_admin = get_users(
	array(
		'role'   => 'administrator',
		'number' => 1,
		'fields' => 'ID',
	)
);
$rw_admin = (int) $rw_admin[0];
$rw_keep  = array();
foreach ( array( 'rolegate_modules', 'rolegate_automation' ) as $rw_opt ) {
	$rw_keep[ $rw_opt ] = get_option( $rw_opt, null );
}

update_user_meta( $rw_admin, 'rolegate_disabled', '1' );
update_user_meta( $rw_admin, 'rolegate_rescue_token', array( 'hash' => str_repeat( 'a', 64 ), 'expires' => time() + 900 ) );
update_option( 'rolegate_uninstall_probe', 1, false );
Enforcer::as_system(
	function () {
		get_role( 'editor' )->add_cap( Caps::VIEW_AUDIT );
	}
);

$rw_sub_ok     = 0;
$rw_sub_broken = 0;
if ( is_multisite() ) {
	$rw_sub_ok = (int) wp_insert_site(
		array(
			'domain' => wp_parse_url( home_url(), PHP_URL_HOST ),
			'path'   => '/rw-uninstall-' . wp_rand( 1000, 9999 ) . '/',
			'title'  => 'Uninstall probe',
		)
	);
	$rw_sub_broken = (int) wp_insert_site(
		array(
			'domain' => wp_parse_url( home_url(), PHP_URL_HOST ),
			'path'   => '/rw-broken-' . wp_rand( 1000, 9999 ) . '/',
			'title'  => 'Broken probe',
		)
	);
	switch_to_blog( $rw_sub_ok );
	update_option( 'rolegate_uninstall_probe', 1, false );
	Enforcer::as_system(
		function () {
			get_role( 'administrator' )->add_cap( Caps::MANAGE );
			get_role( 'editor' )->add_cap( Caps::VIEW_AUDIT );
		}
	);
	$rw_ok( 1 === $rw_probe_count() && $rw_plugin_caps( $rw_raw_roles() ), 'multisite: the subsite holds plugin options and caps before uninstall (setup)' );
	restore_current_blog();
	switch_to_blog( $rw_sub_broken );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->options}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->postmeta}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
	restore_current_blog();
}

$rw_ok( 1 === $rw_probe_count() && $rw_plugin_caps( $rw_raw_roles() ) && get_user_meta( $rw_admin, 'rolegate_rescue_token', true ), 'before: options, caps and the rescue token exist (setup)' );

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	define( 'WP_UNINSTALL_PLUGIN', plugin_basename( ROLEGATE_FILE ) );
}
include ROLEGATE_DIR . 'uninstall.php';
$rw_ok( true, 'uninstall.php ran to the end without a fatal error' );

wp_cache_delete( $rw_admin, 'user_meta' );
$rw_ok( 0 === $rw_probe_count(), 'options: rolegate_* options are removed on the current site' );
$rw_ok( array() === $rw_plugin_caps( $rw_raw_roles() ), 'caps: no role keeps a rolegate_* cap' );
$rw_ok( ! get_user_meta( $rw_admin, 'rolegate_rescue_token', true ), 'user meta: the rescue token is removed' );
$rw_ok( metadata_exists( 'user', $rw_admin, 'rolegate_disabled' ), 'user meta: the disabled-account flag is kept while delete-on-uninstall is off' );
if ( is_multisite() ) {
	switch_to_blog( $rw_sub_ok );
	$rw_ok( 0 === $rw_probe_count() && array() === $rw_plugin_caps( $rw_raw_roles() ), 'multisite: subsite options and caps are removed too' );
	restore_current_blog();
}

// Restore what the rest of the suite expects.
wp_roles()->for_site();
Caps::grant_to_administrator();
foreach ( $rw_keep as $rw_opt => $rw_val ) {
	if ( null !== $rw_val ) {
		update_option( $rw_opt, $rw_val, false );
	}
}
if ( is_multisite() ) {
	require_once ABSPATH . 'wp-admin/includes/ms.php';
	foreach ( array( $rw_sub_ok, $rw_sub_broken ) as $rw_site ) {
		if ( $rw_site ) {
			wp_delete_site( $rw_site );
		}
	}
}
$rw_ok( ! empty( get_role( 'administrator' )->capabilities[ Caps::MANAGE ] ), 'restore: the administrator role has the plugin caps again' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
