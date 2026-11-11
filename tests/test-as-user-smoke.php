<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/test-as-user-smoke.php
 */

use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Test_As_User\Switcher;

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
$rw_code = function ( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : true;
};

$rw_suffix = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users  = array();
$rw_make   = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
	wp_set_current_user( 1 );
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_suffix,
			'user_email' => $login . '_' . $rw_suffix . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $role,
		)
	);
	if ( is_wp_error( $id ) ) {
		echo 'SETUP ERROR ' . $id->get_error_message() . "\n";
		exit( 1 );
	}
	get_userdata( $id )->set_role( $role );
	$rw_users[] = (int) $id;
	return (int) $id;
};
$rw_role = 'rw_tau_' . $rw_suffix;

try {
	$admin  = $rw_make( 'rw_tau_admin', 'administrator' );
	$admin2 = $rw_make( 'rw_tau_admin2', 'administrator' );
	$editor = $rw_make( 'rw_tau_editor', 'editor' );
	$sub    = $rw_make( 'rw_tau_sub', 'subscriber' );
	$sub2   = $rw_make( 'rw_tau_sub2', 'subscriber' );

	$rw_ok( true === Switcher::check( $admin, $editor ), 'an administrator may test as an editor' );
	$rw_ok( true === Switcher::check( $admin, $sub ), 'an administrator may test as a subscriber' );
	$rw_ok( 'rolegate_test_self' === $rw_code( Switcher::check( $admin, $admin ) ), 'testing as yourself is refused' );
	$rw_ok( 'rolegate_test_missing' === $rw_code( Switcher::check( $admin, 99999999 ) ) || 'rolegate_test_denied' === $rw_code( Switcher::check( $admin, 99999999 ) ), 'a missing user is refused' );
	$rw_ok( 'rolegate_test_denied' === $rw_code( Switcher::check( $sub, $sub2 ) ), 'a subscriber cannot test as anyone' );
	$rw_ok( 'rolegate_test_denied' === $rw_code( Switcher::check( $editor, $sub ) ), 'an editor without the user-management capability cannot test as a subscriber' );

	// A user manager with fewer permissions than the target can't climb.
	add_role( $rw_role, 'RW test manager', array( 'read' => true, 'list_users' => true, 'edit_users' => true, Caps::MANAGE_USERS => true ) );
	$mgr = $rw_make( 'rw_tau_mgr', $rw_role );
	wp_set_current_user( $mgr );
	$rw_ok( true === Switcher::check( $mgr, $sub ), 'a user manager may test as a subscriber, who holds only read' );
	$rw_ok( true !== Switcher::check( $mgr, $editor ), 'a user manager cannot test as an editor (permissions they lack)' );
	$rw_ok( 'rolegate_test_above' === $rw_code( Switcher::check( $mgr, $admin ) ) || 'rolegate_test_denied' === $rw_code( Switcher::check( $mgr, $admin ) ), 'a user manager cannot test as an administrator' );

	// A target holding an extra cap the manager lacks is refused, even a harmless one.
	get_userdata( $sub2 )->add_cap( 'rw_extra_cap' );
	$rw_ok( 'rolegate_test_above' === $rw_code( Switcher::check( $mgr, $sub2 ) ), 'a target with one extra capability the actor lacks is refused' );

	// Disabled accounts and nesting.
	wp_set_current_user( $admin );
	Accounts::write( $sub, true );
	$rw_ok( 'rolegate_test_disabled' === $rw_code( Switcher::check( $admin, $sub ) ), 'a disabled account cannot be tested as' );
	Accounts::write( $sub, false );

	// No cookie, no origin: a forged value is rejected.
	wp_set_current_user( $editor );
	$rw_ok( null === Switcher::origin(), 'origin: none without the cookie' );
	$_COOKIE[ Switcher::COOKIE ] = $admin . '|' . ( time() + 3000 ) . '|' . str_repeat( 'a', 64 );
	$rw_ok( null === Switcher::origin(), 'origin: a forged signature is rejected' );
	$_COOKIE[ Switcher::COOKIE ] = $admin . '|' . ( time() - 5 ) . '|' . str_repeat( 'a', 64 );
	$rw_ok( null === Switcher::origin(), 'origin: an expired value is rejected' );
	$_COOKIE[ Switcher::COOKIE ] = 'garbage';
	$rw_ok( null === Switcher::origin(), 'origin: malformed value is rejected' );
	unset( $_COOKIE[ Switcher::COOKIE ] );
	wp_set_current_user( 0 );
} finally {
	unset( $_COOKIE[ Switcher::COOKIE ] );
	remove_role( $rw_role );
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( array_unique( $rw_users ) as $uid ) {
		is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
	}
}
$rw_ok( ! get_user_by( 'login', 'rw_tau_sub_' . $rw_suffix ), 'cleanup: temp users removed' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
