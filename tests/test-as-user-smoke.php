<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/test-as-user-smoke.php
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Audit\Store;
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

	// Real requests: a test session is marked on the server, and old sessions die when it starts and ends.
	$rw_base    = getenv( 'RW_HTTP_BASE' ) ? rtrim( (string) getenv( 'RW_HTTP_BASE' ), '/' ) : 'http://wordpress';
	$rw_home    = wp_parse_url( home_url( '/' ) );
	$rw_host    = (string) $rw_home['host'] . ( ! empty( $rw_home['port'] ) ? ':' . $rw_home['port'] : '' );
	$rw_mods    = get_option( Plugin::OPTION_MODULES, null );
	$rw_modsarr = is_array( $rw_mods ) ? $rw_mods : array();
	update_option( Plugin::OPTION_MODULES, array_merge( $rw_modsarr, array( 'test-as-user' => true ) ) );
	$rw_pw = 'rw-' . wp_generate_password( 16, false );
	add_role( $rw_role . '_h', 'RW http manager', array( 'read' => true, 'list_users' => true, 'edit_users' => true, Caps::MANAGE_USERS => true ) );
	$hm1 = $rw_make( 'rw_tau_hm1', $rw_role . '_h' );
	$hm2 = $rw_make( 'rw_tau_hm2', $rw_role . '_h' );
	$hs  = $rw_make( 'rw_tau_hs', 'subscriber' );
	foreach ( array( $hm1, $hm2, $hs ) as $rw_uid ) {
		wp_set_password( $rw_pw, $rw_uid );
	}
	$rw_jar = static function ( array $jar, $response ) {
		foreach ( (array) wp_remote_retrieve_cookies( $response ) as $c ) {
			if ( '' === (string) $c->value || ( $c->expires && $c->expires < time() ) ) {
				unset( $jar[ $c->name ] );
			} else {
				$jar[ $c->name ] = $c->value;
			}
		}
		return $jar;
	};
	$rw_req = function ( $method, $path, array $jar = array(), array $body = array() ) use ( $rw_base, $rw_host, $rw_jar ) {
		$cookies = array();
		foreach ( $jar as $name => $value ) {
			$cookies[] = new WP_Http_Cookie( array( 'name' => $name, 'value' => $value ) );
		}
		$r = wp_remote_request(
			$rw_base . $path,
			array(
				'method'      => $method,
				'redirection' => 0,
				'timeout'     => 30,
				'headers'     => array( 'Host' => $rw_host ),
				'cookies'     => $cookies,
				'body'        => $body ? $body : null,
			)
		);
		if ( is_wp_error( $r ) ) {
			return array( 'code' => 0, 'body' => $r->get_error_message(), 'location' => '', 'jar' => $jar );
		}
		return array(
			'code'     => (int) wp_remote_retrieve_response_code( $r ),
			'body'     => (string) wp_remote_retrieve_body( $r ),
			'location' => (string) wp_remote_retrieve_header( $r, 'location' ),
			'jar'      => $rw_jar( $jar, $r ),
		);
	};
	$rw_signin = function ( $uid ) use ( $rw_req, $rw_pw ) {
		$r = $rw_req( 'POST', '/wp-login.php', array( 'wordpress_test_cookie' => 'WP Cookie check' ), array( 'log' => get_userdata( $uid )->user_login, 'pwd' => $rw_pw, 'wp-submit' => 'Log In', 'redirect_to' => admin_url() ) );
		return $r['jar'];
	};
	$rw_in = function ( array $jar ) use ( $rw_req ) {
		$r = $rw_req( 'GET', '/wp-admin/profile.php', $jar );
		return 200 === $r['code'];
	};
	$rw_audit_count = function () {
		return Store::table_exists() ? (int) Store::query( array( 'type' => 'user.test_started' ), 1, 50 )['total'] : 0;
	};
	$rw_path_of = function ( $url ) {
		return (string) wp_parse_url( $url, PHP_URL_PATH ) . '?' . (string) wp_parse_url( $url, PHP_URL_QUERY );
	};

	$rw_jar1 = $rw_signin( $hm1 );
	$rw_ok( $rw_in( $rw_jar1 ), 'http setup: the first manager signs in' );
	$rw_page = $rw_req( 'GET', '/wp-admin/users.php', $rw_jar1 );
	$rw_link = preg_match( '#href="([^"]*action=rolegate_test_start&(?:amp;|\#038;)?user=' . $hm2 . '[^"]*)"#', $rw_page['body'], $m ) ? html_entity_decode( $m[1] ) : '';
	$rw_ok( '' !== $rw_link, 'http setup: users.php offers "Test as this user" for the second manager' );
	$rw_start = $rw_req( 'GET', $rw_path_of( $rw_link ), $rw_jar1 );
	$rw_ok( 302 === $rw_start['code'], 'http: starting a test session redirects (' . $rw_start['code'] . ')' );
	$rw_test_jar = $rw_start['jar'];
	$rw_ok( ! $rw_in( $rw_jar1 ), 'start: the actor\'s previous session cookie no longer signs in' );
	$rw_ok( $rw_in( $rw_test_jar ), 'start: the test session signs in' );

	$rw_logged_cookie = '';
	foreach ( $rw_test_jar as $name => $value ) {
		if ( 0 === strpos( $name, 'wordpress_logged_in_' ) ) {
			$rw_logged_cookie = $value;
		}
	}
	wp_set_current_user( $hm2 );
	$_COOKIE[ LOGGED_IN_COOKIE ] = $rw_logged_cookie;
	$rw_nonce_hs                 = wp_create_nonce( Switcher::START . $hs );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( 0 );
	$rw_no_origin = $rw_test_jar;
	unset( $rw_no_origin[ Switcher::COOKIE ] );
	$rw_before_audit = $rw_audit_count();
	$rw_nested       = $rw_req( 'GET', '/wp-admin/admin-post.php?action=' . Switcher::START . '&user=' . $hs . '&_wpnonce=' . $rw_nonce_hs, $rw_no_origin );
	$rw_ok( 403 === $rw_nested['code'] && false !== strpos( $rw_nested['body'], 'Switch back to your own account first' ), 'nesting: a second test session is refused even with the origin cookie dropped (' . $rw_nested['code'] . ')' );
	$rw_ok( $rw_audit_count() === $rw_before_audit, 'nesting: no test_started entry is logged for the refused attempt' );

	$rw_page = $rw_req( 'GET', '/wp-admin/profile.php', $rw_test_jar );
	$rw_stop = preg_match( '#href="([^"]*action=rolegate_test_stop[^"]*)"#', $rw_page['body'], $m ) ? html_entity_decode( $m[1] ) : '';
	$rw_ok( '' !== $rw_stop, 'http setup: the banner carries the way back' );
	$rw_back = $rw_req( 'GET', $rw_path_of( $rw_stop ), $rw_test_jar );
	$rw_ok( 302 === $rw_back['code'] && $rw_in( $rw_back['jar'] ), 'stop: switching back signs the actor in again (' . $rw_back['code'] . ')' );
	$rw_ok( ! $rw_in( $rw_test_jar ), 'stop: the captured test session cookie no longer signs in' );
	$rw_replay = $rw_req( 'GET', $rw_path_of( $rw_stop ), $rw_test_jar );
	$rw_ok( $rw_in( $rw_back['jar'] ) && ! $rw_in( $rw_replay['jar'] ), 'stop: replaying the captured cookies doesn\'t switch back again' );
	update_option( Plugin::OPTION_MODULES, $rw_modsarr );
	remove_role( $rw_role . '_h' );
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
