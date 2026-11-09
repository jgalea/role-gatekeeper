<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/safety-smoke.php
 */

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Enforcer;
use Rolewright\Modules\Safety\Guard;
use Rolewright\Modules\Safety\Rescue;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/admin.php';

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

$rw_suffix  = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_role    = 'rw_t_promoter_' . $rw_suffix;
$rw_users   = array();
$rw_mails   = array();
$rw_ips     = array();
$rw_make    = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
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
	$rw_users[] = (int) $id;
	return (int) $id;
};
$rw_has_role = function ( $id, $role ) {
	clean_user_cache( $id );
	$u = get_userdata( $id );
	return $u && in_array( $role, (array) $u->roles, true );
};
$rw_die_handler = function () {
	return function ( $message ) {
		throw new \RuntimeException( is_wp_error( $message ) ? $message->get_error_message() : wp_strip_all_tags( (string) $message ) );
	};
};
$rw_capture_mail = function ( $short, $atts ) use ( &$rw_mails ) {
	$rw_mails[] = $atts;
	return true;
};

wp_set_current_user( 0 );
add_filter( 'wp_die_handler', $rw_die_handler );
add_filter( 'pre_wp_mail', $rw_capture_mail, 10, 2 );

try {
	add_role( $rw_role, 'RW test promoter', array( 'read' => true, 'promote_users' => true, 'edit_users' => true, 'list_users' => true ) );
	$admin    = $rw_make( 'rw_admin', 'administrator' );
	$admin2   = $rw_make( 'rw_admin2', 'administrator' );
	$admin3   = $rw_make( 'rw_admin3', 'administrator' );
	$promoter = $rw_make( 'rw_promoter', $rw_role );
	$victim   = $rw_make( 'rw_victim', 'subscriber' );

	// Caps.
	Caps::grant_to_administrator();
	$admin_role = get_role( 'administrator' );
	$rw_ok( ! Guard::missing( Caps::all(), $admin_role->capabilities ), 'administrator role holds every rolewright cap' );
	$rw_ok( \Rolewright\Core\Settings::CAP === Caps::MANAGE, 'Caps::MANAGE matches Settings::CAP' );
	$leaked = false;
	foreach ( wp_roles()->roles as $name => $data ) {
		if ( 'administrator' !== $name && array_intersect( Caps::all(), array_keys( array_filter( (array) $data['capabilities'] ) ) ) ) {
			$leaked = true;
		}
	}
	$rw_ok( ! $leaked, 'no other role carries rolewright caps' );
	Enforcer::as_system(
		function () use ( $admin_role ) {
			$admin_role->remove_cap( Caps::MANAGE );
		}
	);
	$rw_ok( ! get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'setup: rolewright_manage removed from administrator' );
	Caps::grant_to_administrator();
	$rw_ok( get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'self-heal re-adds rolewright_manage' );
	$rw_net_gated = is_multisite() && \Rolewright\Core\Plugin::is_enabled( 'multisite' ) && ! apply_filters( 'rolewright_multisite_site_admin_access', false, get_userdata( $admin ) );
	$rw_ok( $rw_net_gated ? ! user_can( $admin, Caps::MANAGE ) : ( user_can( $admin, Caps::MANAGE ) && ( is_multisite() || user_can( $admin, Caps::MANAGE_ROLES ) ) ), 'administrator user can rolewright_manage (and _roles on single site); with the multisite module on, a site administrator needs the network grant' );
	$rw_ok( ! user_can( $promoter, Caps::MANAGE ), 'promoter cannot rolewright_manage' );

	// Guard basics.
	$crit = Guard::critical_caps();
	$rw_ok( ! Guard::missing( array( 'manage_options', 'promote_users', 'edit_users', 'install_plugins', 'unfiltered_html', 'manage_network', 'manage_network_users', 'rolewright_manage', 'rolewright_view_audit' ), $crit ), 'critical_caps has the required set' );
	$rw_ok( Guard::is_critical_cap( 'manage_network_foo' ) && Guard::is_critical_cap( 'rolewright_anything' ) && ! Guard::is_critical_cap( 'edit_posts' ), 'is_critical_cap prefix rules' );
	$rw_ok( Guard::is_protected_role( 'administrator' ) && Guard::is_protected_role( (string) get_option( 'default_role' ) ) && ! Guard::is_protected_role( 'editor' ), 'protected roles' );

	$rw_ok( 'edit_widgets_x' === Guard::sanitize_cap_name( ' Edit_Widgets_X ' ), 'sanitize_cap_name lowercases and trims' );
	$rw_ok( 'shop:manage-orders' === Guard::sanitize_cap_name( 'shop:manage-orders' ), 'sanitize_cap_name allows : and -' );
	$rw_ok( false === Guard::sanitize_cap_name( '' ), 'sanitize_cap_name rejects empty' );
	$rw_ok( false === Guard::sanitize_cap_name( '12345' ), 'sanitize_cap_name rejects numeric-only' );
	$rw_ok( false === Guard::sanitize_cap_name( 'editor' ), 'sanitize_cap_name rejects role-name collision' );
	$rw_ok( false === Guard::sanitize_cap_name( 'bad cap!' ), 'sanitize_cap_name rejects bad characters' );
	$rw_ok( false === Guard::sanitize_cap_name( str_repeat( 'a', 192 ) ), 'sanitize_cap_name rejects > 191 chars' );

	// Escalation rules.
	$rw_ok( ! Guard::can_assign_role( $promoter, 'administrator', $victim ), 'promoter cannot assign administrator to another user' );
	$rw_ok( ! Guard::can_assign_role( $promoter, 'administrator', $promoter ), 'promoter cannot assign administrator to self' );
	$rw_ok( ! Guard::can_assign_role( $promoter, 'administrator', 0 ), 'promoter cannot assign administrator to a new user' );
	$rw_ok( ! Guard::can_assign_role( $promoter, 'editor', $victim ), 'promoter cannot assign editor (unfiltered_html) to another user' );
	$rw_ok( ! Guard::can_assign_role( $promoter, 'author', $promoter ), 'promoter cannot assign self a role with caps they lack' );
	$rw_ok( Guard::can_assign_role( $promoter, 'author', $victim ), 'promoter can assign author to a subscriber' );
	$rw_ok( ! Guard::can_assign_role( $promoter, 'subscriber', $admin ), 'promoter cannot change an administrator\'s role' );
	$rw_ok( Guard::can_assign_role( $admin, 'administrator', $victim ), 'administrator can assign administrator' );
	$rw_ok( ! Guard::can_act_on_user( $promoter, $admin ) && Guard::can_act_on_user( $admin, $promoter ), 'can_act_on_user respects critical-cap level' );
	$rw_ok( ! Guard::can_grant_cap( $promoter, 'manage_options' ), 'promoter cannot grant manage_options' );
	$rw_ok( ! Guard::can_grant_cap( $promoter, 'rolewright_manage' ), 'promoter cannot grant rolewright_manage' );
	$rw_ok( Guard::can_grant_cap( $promoter, 'list_users' ), 'promoter can grant a cap they hold' );
	$rw_ok( ! Guard::can_grant_cap( $promoter, 'rw_custom_' . $rw_suffix ), 'promoter cannot grant a cap they lack without rolewright_manage_caps' );
	$rw_ok( Guard::can_grant_cap( $admin, 'rw_custom_' . $rw_suffix ), 'administrator can grant a new custom cap' );

	// wp-admin paths as the promoter.
	wp_set_current_user( $promoter );
	$editable = get_editable_roles();
	$rw_ok( ! isset( $editable['administrator'] ) && ! isset( $editable['editor'] ) && isset( $editable['subscriber'] ), 'editable_roles hides administrator and editor from promoter' );
	$rw_ok( ! current_user_can( 'edit_user', $admin ) && ! current_user_can( 'promote_user', $admin ), 'map_meta_cap: promoter cannot edit or promote an administrator' );
	$rw_ok( current_user_can( 'promote_user', $victim ), 'map_meta_cap: promoter can still promote a subscriber' );

	$profile_post = function ( $uid, $role ) {
		$u     = get_userdata( $uid );
		$_POST = array(
			'role'     => $role,
			'email'    => $u ? $u->user_email : '',
			'nickname' => $u ? $u->user_login : '',
		);
	};
	foreach ( array( 'other' => $victim, 'self' => $promoter ) as $who => $uid ) {
		$profile_post( $uid, 'administrator' );
		$_REQUEST = array( 'user_id' => $uid );
		try {
			$res = edit_user( $uid );
		} catch ( \RuntimeException $e ) {
			$res = new WP_Error( 'died', $e->getMessage() );
		}
		$rw_ok( is_wp_error( $res ) && ! $rw_has_role( $uid, 'administrator' ), "profile form: promoter cannot make $who an administrator" );
	}
	$_POST    = array(
		'user_login' => 'rw_new_' . $rw_suffix,
		'email'      => 'rw_new_' . $rw_suffix . '@example.com',
		'pass1'      => 'Rw-' . wp_generate_password( 20 ),
		'role'       => 'administrator',
	);
	$_POST['pass2'] = $_POST['pass1'];
	$_REQUEST       = array();
	try {
		$res = edit_user();
	} catch ( \RuntimeException $e ) {
		$res = new WP_Error( 'died', $e->getMessage() );
	}
	$created = get_user_by( 'login', 'rw_new_' . $rw_suffix );
	if ( $created ) {
		$rw_users[] = (int) $created->ID;
	}
	$rw_ok( is_wp_error( $res ) && ! $created, 'new-user form: promoter cannot create an administrator' );

	$_REQUEST = array( 'action' => 'promote', 'new_role' => 'administrator', 'users' => array( $victim, $promoter ) );
	$bulk     = get_editable_roles();
	$rw_ok( empty( $bulk['administrator'] ), 'bulk change role: administrator not offered (users.php dies on it)' );
	$_REQUEST = array();
	$_POST    = array();

	foreach ( array( 'other' => $victim, 'self' => $promoter ) as $who => $uid ) {
		$u = get_userdata( $uid );
		$u->set_role( 'administrator' );
		$rw_ok( ! $rw_has_role( $uid, 'administrator' ), "storage backstop: set_role('administrator') on $who is refused" );
		$u = get_userdata( $uid );
		$u->add_role( 'administrator' );
		$rw_ok( ! $rw_has_role( $uid, 'administrator' ), "storage backstop: add_role('administrator') on $who is refused" );
		$u = get_userdata( $uid );
		$u->add_cap( 'manage_options' );
		clean_user_cache( $uid );
		$rw_ok( ! user_can( $uid, 'manage_options' ), "storage backstop: per-user manage_options on $who is refused" );
	}
	$level = (int) get_user_meta( $victim, $GLOBALS['wpdb']->get_blog_prefix() . 'user_level', true );
	$rw_ok( $level < 8, 'user_level not raised by a refused promotion' );
	$u = get_userdata( $victim );
	$u->set_role( 'author' );
	$rw_ok( $rw_has_role( $victim, 'author' ), 'promoter can still make a subscriber an author' );
	$u->set_role( 'subscriber' );

	// REST.
	$rw_mixed_users = 'U' . 'sers';
	$rest = function ( $method, $route, $params ) {
		$req = new WP_REST_Request( $method, $route );
		foreach ( $params as $k => $v ) {
			$req->set_param( $k, $v );
		}
		return rest_do_request( $req );
	};
	$r = $rest( 'POST', '/wp/v2/users/' . $victim, array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $victim, 'administrator' ), 'REST: promoter cannot make another user an administrator (status ' . $r->get_status() . ')' );
	$r = $rest( 'POST', '/wp/v2/users/me', array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $promoter, 'administrator' ), 'REST: promoter cannot make self an administrator (status ' . $r->get_status() . ')' );
	$r = $rest(
		'POST',
		'/wp/v2/users',
		array(
			'username' => 'rw_rest_' . $rw_suffix,
			'email'    => 'rw_rest_' . $rw_suffix . '@example.com',
			'password' => wp_generate_password( 24 ),
			'roles'    => array( 'administrator' ),
		)
	);
	$rest_created = get_user_by( 'login', 'rw_rest_' . $rw_suffix );
	if ( $rest_created ) {
		$rw_users[] = (int) $rest_created->ID;
	}
	$rw_ok( $r->is_error() && ( ! $rest_created || ! in_array( 'administrator', (array) $rest_created->roles, true ) ), 'REST: promoter cannot create an administrator (status ' . $r->get_status() . ')' );
	$r = $rest( 'POST', '/wp/v2/users/' . $admin, array( 'first_name' => 'X' ) );
	$rw_ok( $r->is_error(), 'REST: promoter cannot edit an administrator (status ' . $r->get_status() . ')' );
	$r = $rest( 'POST', '/WP/V2/' . $rw_mixed_users . '/' . $victim, array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $victim, 'administrator' ), 'REST: upper-case route cannot bypass the guard (status ' . $r->get_status() . ')' );
	$r = $rest( 'POST', '/wp/v2/' . $rw_mixed_users . '/ME', array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $promoter, 'administrator' ), 'REST: mixed-case /me route cannot bypass the guard (status ' . $r->get_status() . ')' );

	$guard_req = new WP_REST_Request( 'POST', '/WP/V2/' . $rw_mixed_users . '/' . $victim );
	$guard_req->set_param( 'roles', array( 'administrator' ) );
	$guard_out = ( new Rolewright\Modules\Safety\Enforcer() )->rest_guard( null, array(), $guard_req );
	$rw_ok( is_wp_error( $guard_out ), 'REST guard itself refuses an upper-case users route' );

	$old_default = get_option( 'default_role' );
	update_option( 'default_role', 'administrator' );
	$rw_ok( get_option( 'default_role' ) === $old_default, 'default_role: promoter cannot set the registration role to administrator' );

	// Roles option backstop as the promoter.
	get_role( $rw_role )->add_cap( 'manage_options' );
	wp_roles()->for_site();
	$rw_ok( ! get_role( $rw_role )->has_cap( 'manage_options' ), 'roles backstop: promoter cannot add manage_options to own role' );
	$rw_ok( true !== Guard::assert_can_modify_role( $promoter, $rw_role, array_merge( get_role( $rw_role )->capabilities, array( 'manage_options' => true ) ) ), 'assert_can_modify_role refuses self-grant of manage_options' );
	$err = Guard::assert_can_modify_role( $promoter, 'editor', array( 'read' => true ) );
	$rw_ok( is_wp_error( $err ) && 'rolewright_role_above_actor' === $err->get_error_code(), 'assert_can_modify_role refuses changes to a role above the actor' );

	// Administrator as actor.
	wp_set_current_user( $admin );
	$u = get_userdata( $victim );
	$u->set_role( 'editor' );
	$rw_ok( $rw_has_role( $victim, 'editor' ), 'administrator can make a user an editor' );
	$r = $rest( 'POST', '/wp/v2/users/' . $victim, array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( ! $r->is_error() && $rw_has_role( $victim, 'administrator' ), 'REST: administrator can still promote to administrator' );
	get_userdata( $victim )->set_role( 'subscriber' );

	$admin_caps = get_role( 'administrator' )->capabilities;
	$no_manage  = $admin_caps;
	unset( $no_manage[ Caps::MANAGE ] );
	$no_read = $admin_caps;
	unset( $no_read['read'] );
	$no_roles = $admin_caps;
	unset( $no_roles[ Caps::MANAGE_ROLES ] );
	$rw_ok( Guard::would_lock_out( $admin, array( 'administrator' => $no_manage ) ), 'lockout: removing rolewright_manage from own role' );
	$rw_ok( Guard::would_lock_out( $admin, array( 'administrator' => $no_read ) ), 'lockout: removing read from own role' );
	$rw_ok( Guard::would_lock_out( $admin, array( 'administrator' => $no_roles ) ), 'lockout: no role left with rolewright_manage_roles' );
	$rw_ok( Guard::would_lock_out( $admin, array( 'administrator' => null ) ), 'lockout: deleting own role' );
	$rw_ok( ! Guard::would_lock_out( $admin, array( 'editor' => array( 'read' => true ) ) ), 'no lockout: editing another role' );
	$rw_ok( Guard::lockout_reasons( array( 'r' ), array(), array( 'r' => array( 'read' => true ) ) ) === array( 'manage', 'no_manager_role' ), 'lockout_reasons pure function' );

	$err = Guard::assert_can_modify_role( $admin, 'administrator', $no_manage );
	$rw_ok( is_wp_error( $err ) && 'rolewright_protected_role' === $err->get_error_code(), 'assert_can_modify_role: administrator keeps rolewright caps' );
	$no_opts = $admin_caps;
	unset( $no_opts['manage_options'] );
	$err = Guard::assert_can_modify_role( $admin, 'administrator', $no_opts );
	$rw_ok( is_wp_error( $err ) && 'rolewright_protected_role' === $err->get_error_code(), 'assert_can_modify_role: administrator keeps manage_options' );
	$err = Guard::assert_can_modify_role( $admin, 'editor', array_merge( get_role( 'editor' )->capabilities, array( 'Bad Cap!' => true ) ) );
	$rw_ok( is_wp_error( $err ) && 'rolewright_invalid_cap' === $err->get_error_code(), 'assert_can_modify_role: invalid cap name' );
	$rw_ok( true === Guard::assert_can_modify_role( $admin, 'editor', array_merge( get_role( 'editor' )->capabilities, array( 'rw_custom_' . $rw_suffix => true ) ) ), 'assert_can_modify_role: administrator adds a custom cap to editor' );
	$rw_ok( is_wp_error( Guard::assert_can_delete_role( $admin, 'administrator' ) ) && is_wp_error( Guard::assert_can_delete_role( $admin, (string) get_option( 'default_role' ) ) ), 'assert_can_delete_role: protected roles' );
	$rw_ok( is_wp_error( Guard::assert_can_rename_role( $admin, 'administrator' ) ), 'assert_can_rename_role: administrator' );

	wp_set_current_user( 0 );
	get_role( 'administrator' )->remove_cap( 'manage_options' );
	wp_roles()->for_site();
	$rw_ok( get_role( 'administrator' )->has_cap( 'manage_options' ), 'roles backstop: administrator keeps manage_options even without a logged-in user' );

	// Rescue.
	Enforcer::as_system(
		function () {
			foreach ( Caps::all() as $cap ) {
				get_role( 'administrator' )->remove_cap( $cap );
			}
		}
	);
	$rw_ok( ! get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'setup: administrator locked out of Rolewright' );
	$ip_a     = '203.0.113.' . wp_rand( 1, 250 );
	$ip_b     = '198.51.100.' . wp_rand( 1, 250 );
	$ip_c     = '192.0.2.' . wp_rand( 1, 250 );
	$rw_ips   = array( $ip_a, $ip_b, $ip_c );
	$rw_mails = array();
	Rescue::request( 'nobody_' . $rw_suffix . '@example.com', $ip_a );
	Rescue::request( get_userdata( $promoter )->user_email, $ip_a );
	$rw_ok( 0 === count( $rw_mails ), 'rescue: no mail for unknown or non-admin addresses' );
	Rescue::request( get_userdata( $admin )->user_email, $ip_b );
	$rw_ok( 1 === count( $rw_mails ) && get_userdata( $admin )->user_email === $rw_mails[0]['to'], 'rescue: mail sent to the admin address only' );
	$token = '';
	if ( $rw_mails && preg_match( '/token=([a-f0-9]{64})/', (string) $rw_mails[0]['message'], $m ) ) {
		$token = $m[1];
	}
	$stored = get_user_meta( $admin, Rescue::META, true );
	$rw_ok( 64 === strlen( $token ) && is_array( $stored ) && hash( 'sha256', $token ) === $stored['hash'] && $stored['hash'] !== $token, 'rescue: 32-byte token, stored hashed' );
	$rw_ok( $stored['expires'] - time() <= 900 && $stored['expires'] - time() > 880, 'rescue: 15 minute expiry' );
	$rw_ok( is_wp_error( Rescue::consume( $admin, str_repeat( 'a', 64 ), $ip_b ) ), 'rescue: wrong token refused' );
	$rw_ok( true === Rescue::consume( $admin, $token, $ip_b ), 'rescue: valid token accepted' );
	$rw_ok( get_role( 'administrator' )->has_cap( Caps::MANAGE ) && ! Guard::missing( Caps::all(), get_role( 'administrator' )->capabilities ), 'rescue: rolewright caps restored to administrator' );
	$rw_ok( 0 === get_current_user_id(), 'rescue: does not log anyone in' );
	$rw_ok( is_wp_error( Rescue::consume( $admin, $token, $ip_b ) ), 'rescue: token works once' );

	Rescue::request( get_userdata( $admin )->user_email, $ip_c );
	$stored            = get_user_meta( $admin, Rescue::META, true );
	$stored['expires'] = time() - 1;
	update_user_meta( $admin, Rescue::META, $stored );
	$token2 = preg_match( '/token=([a-f0-9]{64})/', (string) end( $rw_mails )['message'], $m ) ? $m[1] : '';
	$rw_ok( '' !== $token2 && is_wp_error( Rescue::consume( $admin, $token2, $ip_c ) ), 'rescue: expired token refused' );

	$before = count( $rw_mails );
	Rescue::request( get_userdata( $admin )->user_email, $ip_c );
	Rescue::request( get_userdata( $admin )->user_email, $ip_c );
	$rw_ok( count( $rw_mails ) === $before + 1, 'rescue: per-account limit of 3 per hour' );

	$before = count( $rw_mails );
	Rescue::request( get_userdata( $admin2 )->user_email, $ip_a );
	Rescue::request( get_userdata( $admin3 )->user_email, $ip_a );
	$rw_ok( count( $rw_mails ) === $before + 1, 'rescue: per-IP limit of 3 per hour' );

	if ( is_multisite() ) {
		$rw_ok( ! user_can( $admin, Caps::MANAGE_ROLES ), 'multisite: site admin cannot use rolewright_manage_roles by default' );
	} else {
		echo "SKIP multisite checks (single site)\n";
	}
} catch ( \Throwable $e ) {
	$rw_ok( false, 'uncaught ' . get_class( $e ) . ': ' . $e->getMessage() . ' @ ' . basename( $e->getFile() ) . ':' . $e->getLine() );
}

// Cleanup.
wp_set_current_user( 0 );
$_POST    = array();
$_REQUEST = array();
remove_filter( 'wp_die_handler', $rw_die_handler );
remove_filter( 'pre_wp_mail', $rw_capture_mail, 10 );
if ( is_multisite() ) {
	require_once ABSPATH . 'wp-admin/includes/ms.php';
}
$ip_d     = '198.18.0.' . wp_rand( 1, 250 );
$rw_ips[] = $ip_d;
delete_transient( 'rolewright_rl_' . md5( 'acct|' . $admin ) );
delete_user_meta( $admin, Rescue::META );
add_filter( 'rolewright_rescue_defer_mail', '__return_true' );
add_filter( 'rolewright_rescue_can_detach', '__return_false' );
$rw_mails = array();
add_filter( 'pre_wp_mail', $rw_capture_mail, 10, 2 );
Rescue::request( get_userdata( $admin )->user_email, $ip_d );
$rw_ok( 0 === count( $rw_mails ) && ! get_user_meta( $admin, Rescue::META, true ) && false !== wp_next_scheduled( Rescue::HOOK_DELIVER, array( $admin ) ), 'rescue: with no way to detach, delivery is scheduled and nothing runs in the request' );
Rescue::deliver_by_id( $admin );
$rw_ok( 1 === count( $rw_mails ) && is_array( get_user_meta( $admin, Rescue::META, true ) ), 'rescue: the scheduled delivery sends the mail and stores the hashed token' );
wp_clear_scheduled_hook( Rescue::HOOK_DELIVER, array( 0 ) );
Rescue::request( 'nobody_' . $rw_suffix . '@example.com', $ip_d );
$rw_ok( false !== wp_next_scheduled( Rescue::HOOK_DELIVER, array( 0 ) ) && 0 === count( $rw_mails ) - 1, 'rescue: an unknown address schedules the same kind of event, so scheduling cost is not a signal' );
Rescue::deliver_by_id( 0 );
$rw_ok( 1 === count( $rw_mails ), 'rescue: the decoy event sends nothing' );
wp_clear_scheduled_hook( Rescue::HOOK_DELIVER, array( 0 ) );
remove_filter( 'pre_wp_mail', $rw_capture_mail, 10 );
wp_clear_scheduled_hook( Rescue::HOOK_DELIVER, array( $admin ) );
remove_filter( 'rolewright_rescue_defer_mail', '__return_true' );
remove_filter( 'rolewright_rescue_can_detach', '__return_false' );
delete_user_meta( $admin, Rescue::META );
foreach ( array_unique( $rw_users ) as $uid ) {
	if ( is_multisite() ) {
		wpmu_delete_user( $uid );
	} else {
		wp_delete_user( $uid );
	}
}
remove_role( $rw_role );
Enforcer::as_system(
	function () use ( $rw_suffix ) {
		get_role( 'editor' )->remove_cap( 'rw_custom_' . $rw_suffix );
	}
);
Caps::grant_to_administrator();
foreach ( $rw_ips as $ip ) {
	foreach ( array( 'ip|', 'use|' ) as $p ) {
		delete_transient( 'rolewright_rl_' . md5( $p . $ip ) );
	}
}
foreach ( array_unique( $rw_users ) as $uid ) {
	delete_transient( 'rolewright_rl_' . md5( 'acct|' . $uid ) );
}
$rw_ok( get_role( 'administrator' )->has_cap( 'manage_options' ) && get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'cleanup: administrator role intact' );
$rw_ok( ! get_role( $rw_role ) && ! get_user_by( 'login', 'rw_admin_' . $rw_suffix ), 'cleanup: temp role and users removed' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}

