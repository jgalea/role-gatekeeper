<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/login-redirects-smoke.php
 */

use Rolegate\Modules\Login_Redirects\Login_Redirects_Module;
use Rolegate\Modules\Login_Redirects\Login_Redirects_Settings;
use Rolegate\Modules\Login_Redirects\Resolver;
use Rolegate\Modules\Safety\Caps;

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

$rw_suffix = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users  = array();
$rw_orig   = get_option( Login_Redirects_Settings::OPTION, null );
$rw_make   = function ( $login, $roles ) use ( &$rw_users, $rw_suffix ) {
	$roles = (array) $roles;
	$id    = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_suffix,
			'user_email' => $login . '_' . $rw_suffix . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => array_shift( $roles ),
		)
	);
	if ( is_wp_error( $id ) ) {
		echo 'SETUP ERROR ' . $id->get_error_message() . "\n";
		exit( 1 );
	}
	foreach ( $roles as $role ) {
		get_userdata( $id )->add_role( $role );
	}
	$rw_users[] = (int) $id;
	return get_userdata( $id );
};
$rw_store = function ( array $over ) {
	update_option( Login_Redirects_Settings::OPTION, array_merge( Login_Redirects_Settings::defaults(), $over ), false );
};

try {
	$home = home_url( '/' );
	$rw_ok( true === ( new Login_Redirects_Module() )->default_enabled() && 'login-redirects' === ( new Login_Redirects_Module() )->id(), 'module id and default' );
	$m = new Login_Redirects_Module();
	$m->init();
	$rw_ok( false !== has_filter( 'login_redirect', array( Resolver::class, 'filter_login' ) ) && false !== has_filter( 'logout_redirect', array( Resolver::class, 'filter_logout' ) ), 'module hooks login_redirect and logout_redirect' );

	$sub    = $rw_make( 'rw_lr_sub', 'subscriber' );
	$editor = $rw_make( 'rw_lr_editor', 'editor' );
	$multi  = $rw_make( 'rw_lr_multi', array( 'subscriber', 'editor' ) );

	// Save-time validation.
	$ok = Login_Redirects_Settings::sanitize(
		array(
			'rules'    => array(
				'subscriber' => array(
					'login'   => '/account/',
					'logout'  => '/goodbye/',
					'landing' => '/welcome/',
				),
				'editor'     => array( 'login' => $home . 'newsroom/' ),
			),
			'priority' => array(
				'editor'     => 1,
				'subscriber' => 2,
			),
		)
	);
	$rw_ok( is_array( $ok ) && home_url( '/account/' ) === $ok['rules']['subscriber']['login'] && array( 'editor', 'subscriber' ) === $ok['priority'], 'save: relative paths become site URLs, priority order kept' );
	$bad = array(
		'off-site URL'       => 'https://evil.example/landing',
		'protocol-relative'  => '//evil.example/x',
		'javascript scheme'  => 'javascript:alert(1)',
		'backslash trick'    => 'https:\\\\evil.example',
		'login page'         => wp_login_url(),
		'userinfo trick'     => 'https://' . wp_parse_url( $home, PHP_URL_HOST ) . '@evil.example/',
		'newline injection'  => "/ok\r\nLocation: https://evil.example",
	);
	foreach ( $bad as $label => $url ) {
		$res = Login_Redirects_Settings::sanitize( array( 'rules' => array( 'subscriber' => array( 'login' => $url ) ) ) );
		$rw_ok( is_wp_error( $res ), 'open redirect refused at save: ' . $label );
	}
	$res = Login_Redirects_Settings::sanitize( array( 'rules' => array( 'subscriber' => array( 'logout' => admin_url() ) ) ) );
	$rw_ok( is_wp_error( $res ), 'logout redirect into wp-admin refused (it would bounce to the login page)' );
	$res = Login_Redirects_Settings::sanitize( array( 'rules' => array( 'subscriber' => array( 'login' => admin_url( 'profile.php' ) ) ) ) );
	$rw_ok( is_array( $res ), 'login redirect into wp-admin allowed' );
	$res = Login_Redirects_Settings::sanitize( array( 'rules' => array( 'nonexistent_role' => array( 'login' => '/x/' ) ) ) );
	$rw_ok( is_array( $res ) && array() === $res['rules'], 'unknown roles are dropped' );

	// Runtime: per-role redirects.
	$rw_store( $ok );
	$rw_ok( home_url( '/account/' ) === Resolver::filter_login( admin_url(), '', $sub ), 'login: subscriber goes to their page' );
	$rw_ok( home_url( '/goodbye/' ) === Resolver::filter_logout( 'wp-login.php?loggedout=true', '', $sub ), 'logout: subscriber goes to their page' );
	$rw_ok( admin_url() === Resolver::filter_login( admin_url(), '', $rw_make( 'rw_lr_author', 'author' ) ), 'login: a role without a rule keeps the WordPress default' );
	$rw_ok( 'wp-login.php?loggedout=true' === Resolver::filter_logout( 'wp-login.php?loggedout=true', '', $editor ), 'logout: a role without a rule keeps the default' );
	$err = new WP_Error( 'x', 'x' );
	$rw_ok( admin_url() === Resolver::filter_login( admin_url(), '', $err ), 'login: failed logins are left alone' );

	// Multiple roles and priority.
	$rw_ok( home_url( '/newsroom/' ) === Resolver::filter_login( admin_url(), '', $multi ), 'priority: editor (1) beats subscriber (2) for a two-role user' );
	$rw_store( array_merge( $ok, array( 'priority' => array( 'subscriber', 'editor' ) ) ) );
	$rw_ok( home_url( '/account/' ) === Resolver::filter_login( admin_url(), '', $multi ), 'priority: flipping the order flips the result' );
	$rw_store( array_merge( $ok, array( 'priority' => array() ) ) );
	$rw_ok( in_array( Resolver::filter_login( admin_url(), '', $multi ), array( home_url( '/account/' ), home_url( '/newsroom/' ) ), true ), 'priority: unlisted roles still resolve' );
	$rw_ok( array( 'editor', 'subscriber' ) === Resolver::ordered_roles( array( 'subscriber', 'editor' ), array( 'editor', 'subscriber', 'author' ) ), 'ordered_roles follows the priority list' );
	$rw_store(
		array(
			'rules'    => array(
				'subscriber' => array( 'login' => '/account/' ),
				'editor'     => array( 'logout' => '/bye/' ),
			),
			'priority' => array( 'editor', 'subscriber' ),
		)
	);
	$rw_ok( home_url( '/account/' ) === Resolver::filter_login( admin_url(), '', $multi ), 'priority: first role without a value for the field is skipped' );
	$rw_ok( home_url( '/bye/' ) === Resolver::filter_logout( 'x', '', $multi ), 'priority: logout resolves independently of login' );

	// Landing page fallback.
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'landing' => '/welcome/' ) ) ) );
	$rw_ok( home_url( '/welcome/' ) === Resolver::filter_login( admin_url(), '', $sub ), 'landing: used when the role has no login redirect' );
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => '/account/', 'landing' => '/welcome/' ) ) ) );
	$rw_ok( home_url( '/account/' ) === Resolver::filter_login( admin_url(), '', $sub ), 'landing: login redirect wins over the landing page' );

	// Requested destinations.
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => '/account/' ) ) ) );
	$mine = home_url( '/members/report/' );
	$rw_ok( $mine === Resolver::filter_login( $mine, $mine, $sub ), 'requested: a same-site redirect_to is respected by default' );
	$rw_store( array( 'override' => true, 'rules' => array( 'subscriber' => array( 'login' => '/account/' ) ) ) );
	$rw_ok( home_url( '/account/' ) === Resolver::filter_login( $mine, $mine, $sub ), 'requested: override setting forces the role redirect' );

	// Open-redirect attempts.
	$evil = 'https://evil.example/steal';
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => '/account/' ) ) ) );
	$out = Resolver::filter_login( $evil, $evil, $sub );
	$rw_ok( home_url( '/account/' ) === $out, 'open redirect: off-site redirect_to is dropped, role page used' );
	$rw_store( array() );
	$out = Resolver::filter_login( $evil, $evil, $sub );
	$rw_ok( false === strpos( $out, 'evil.example' ), 'open redirect: off-site redirect_to dropped even with no rules (' . $out . ')' );
	foreach ( array( '//evil.example', 'https:\\\\evil.example', 'javascript:alert(1)', 'https://' . wp_parse_url( $home, PHP_URL_HOST ) . '.evil.example/' ) as $attempt ) {
		$out = Resolver::filter_login( $attempt, $attempt, $sub );
		$rw_ok( false === strpos( $out, 'evil.example' ) && 0 !== strpos( $out, 'javascript' ), 'open redirect: refused ' . $attempt );
	}
	$out = Resolver::filter_logout( $evil, $evil, $sub );
	$rw_ok( false === strpos( $out, 'evil.example' ), 'open redirect: off-site logout redirect_to refused' );

	// A hostile value written straight into the option is still refused at runtime.
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => 'https://evil.example/', 'logout' => '//evil.example/', 'landing' => 'javascript:alert(1)' ) ) ) );
	$rw_ok( admin_url() === Resolver::filter_login( admin_url(), '', $sub ), 'stored off-site login value ignored at runtime' );
	$rw_ok( 'wp-login.php?loggedout=true' === Resolver::filter_logout( 'wp-login.php?loggedout=true', '', $sub ), 'stored off-site logout value ignored at runtime' );

	// Loops.
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => wp_login_url(), 'logout' => admin_url( 'index.php' ) ) ) ) );
	$rw_ok( admin_url() === Resolver::filter_login( admin_url(), '', $sub ), 'loop: stored login-page target ignored' );
	$rw_ok( 'x' === Resolver::filter_logout( 'x', '', $sub ), 'loop: stored wp-admin logout target ignored' );

	// Real wp-login.php round trip using the core filter chain.
	$rw_store( array( 'rules' => array( 'subscriber' => array( 'login' => '/account/' ) ) ) );
	$final = apply_filters( 'login_redirect', admin_url(), '', $sub );
	$rw_ok( home_url( '/account/' ) === $final && home_url( '/account/' ) === wp_validate_redirect( $final, admin_url() ), 'filter chain: login_redirect result passes wp_validate_redirect' );

	// Change event and permissions.
	$events = array();
	$listen = function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	};
	add_action( 'rolegate_changed', $listen, 10, 2 );
	Login_Redirects_Settings::save( $ok, 1 );
	remove_action( 'rolegate_changed', $listen, 10 );
	$rw_ok( 1 === count( $events ) && 'access.updated' === $events[0][0] && 'login-redirects' === $events[0][1]['target'] && 1 === $events[0][1]['actor'] && is_array( $events[0][1]['before'] ) && $events[0][1]['after'] === $ok, 'rolegate_changed fires access.updated' );
	wp_set_current_user( $sub->ID );
	$rw_ok( ! current_user_can( Caps::MANAGE_ACCESS ), 'page: subscribers cannot manage login redirects' );
	wp_set_current_user( 0 );
} finally {
	foreach ( array_unique( $rw_users ) as $uid ) {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
	}
	if ( null === $rw_orig ) {
		delete_option( Login_Redirects_Settings::OPTION );
	} else {
		update_option( Login_Redirects_Settings::OPTION, $rw_orig, false );
	}
}
$rw_ok( ! get_user_by( 'login', 'rw_lr_sub_' . $rw_suffix ), 'cleanup: temp users removed' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
