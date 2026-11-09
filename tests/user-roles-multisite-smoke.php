<?php
/**
 * Needs a multisite install. Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/user-roles-multisite-smoke.php
 */

use Rolegate\Modules\User_Roles\Profile;
use Rolegate\Modules\User_Roles\Users;
use Rolegate\Modules\User_Roles\Users_List;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}
if ( ! is_multisite() ) {
	echo "FAIL this test needs a multisite install\n";
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/admin.php';
set_current_screen( 'users' );

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
$rw_site   = 0;
$rw_main   = get_current_blog_id();
$rw_make   = function ( $login, $role, $blog ) use ( &$rw_users, $rw_suffix ) {
	$id = wpmu_create_user( $login . '_' . $rw_suffix, wp_generate_password( 24 ), $login . '_' . $rw_suffix . '@example.com' );
	if ( ! $id ) {
		echo 'SETUP ERROR could not create ' . $login . "\n";
		exit( 1 );
	}
	$rw_users[] = (int) $id;
	add_user_to_blog( $blog, $id, $role );
	if ( get_main_site_id() !== $blog ) {
		remove_user_from_blog( $id, get_main_site_id() );
	}
	return (int) $id;
};
$rw_member = function ( $id ) use ( $rw_main ) {
	clean_user_cache( $id );
	return is_user_member_of_blog( $id, $rw_main );
};

wp_set_current_user( 0 );
try {
	$site = wp_insert_site(
		array(
			'domain' => (string) get_network()->domain,
			'path'   => '/rw-other-' . $rw_suffix . '/',
			'title'  => 'Other',
		)
	);
	$rw_ok( ! is_wp_error( $site ), 'setup: second site created' );
	$rw_site = is_wp_error( $site ) ? 0 : (int) $site;

	$site_admin = $rw_make( 'rw_ms_siteadmin', 'administrator', $rw_main );
	$member     = $rw_make( 'rw_ms_member', 'subscriber', $rw_main );
	$outsider   = $rw_make( 'rw_ms_outsider', 'subscriber', $rw_site );
	$super      = $rw_make( 'rw_ms_super', 'subscriber', $rw_main );
	grant_super_admin( $super );

	$rw_ok( ! is_super_admin( $site_admin ), 'setup: site admin is not a super admin' );
	$rw_ok( ! $rw_member( $outsider ) && is_user_member_of_blog( $outsider, $rw_site ), 'setup: outsider belongs only to the other site' );
	$rw_ok( user_can( $site_admin, 'promote_user', $outsider ), 'setup: core alone lets a site admin promote_user any network user' );

	// Users::check_roles_change / change_roles.
	$res = Users::check_roles_change( $site_admin, $outsider, array( 'author' ), array() );
	$rw_ok( is_wp_error( $res ) && 'rolegate_not_site_member' === $res->get_error_code(), 'roles: site admin cannot change a user outside this site' );
	$res = Users::change_roles( $site_admin, $outsider, array( 'author' ), array() );
	$rw_ok( is_wp_error( $res ) && ! $rw_member( $outsider ), 'roles: change_roles refuses and the outsider is not added to this site' );
	$res = Users::change_roles( $site_admin, $member, array( 'author' ), array() );
	$rw_ok( true === $res && in_array( 'author', get_userdata( $member )->roles, true ), 'roles control: site admin can still change a member of this site' );
	Users::change_roles( $site_admin, $member, array(), array( 'author' ) );

	// Bulk.
	$list = new Users_List();
	wp_set_current_user( $site_admin );
	$_POST    = array( '_wpnonce' => wp_create_nonce( 'bulk-users' ) );
	$_REQUEST = $_POST;
	$out      = $list->handle_bulk( admin_url( 'users.php' ), 'rolegate_add:contributor', array( $outsider, $member ) );
	parse_str( (string) wp_parse_url( $out, PHP_URL_QUERY ), $q );
	$rw_ok( '1' === ( $q['rolegate_done'] ?? '' ) && '1' === ( $q['rolegate_skip'] ?? '' ) && ! $rw_member( $outsider ), 'bulk: outsider skipped, member changed' );
	$rw_ok( in_array( 'contributor', get_userdata( $member )->roles, true ), 'bulk control: member got the role' );
	Users::change_roles( $site_admin, $member, array(), array( 'contributor' ) );

	// Caps editor path.
	$grant = function () {
		return true;
	};
	add_filter( 'rolegate_multisite_site_admin_access', $grant );
	$res = Users::check_caps_change( $site_admin, $outsider, array( 'read' ), array() );
	$rw_ok( is_wp_error( $res ) && 'rolegate_not_site_member' === $res->get_error_code(), 'caps: per-user capability change on an outsider is refused (' . ( is_wp_error( $res ) ? $res->get_error_code() : 'allowed' ) . ')' );
	$res = Users::change_caps( $site_admin, $outsider, array( 'read' ), array() );
	$rw_ok( is_wp_error( $res ) && ! $rw_member( $outsider ), 'caps: change_caps refuses and adds nothing' );
	remove_filter( 'rolegate_multisite_site_admin_access', $grant );

	// Profile save path.
	$profile = new Profile();
	$_POST   = array(
		'rolegate_user_roles_present' => '1',
		'rolegate_user_roles'         => array( 'author' ),
		'rolegate_user_nonce'         => wp_create_nonce( 'rolegate_user_' . $outsider ),
	);
	$errors = new WP_Error();
	$profile->validate( $errors, true, (object) array( 'ID' => $outsider, 'role' => 'subscriber' ) );
	$rw_ok( in_array( 'rolegate_not_site_member', $errors->get_error_codes(), true ), 'profile: saving extra roles for an outsider is refused' );
	ob_start();
	$profile->render_profile( get_userdata( $outsider ) );
	$html = (string) ob_get_clean();
	$rw_ok( '' === $html, 'profile: no roles or caps section is shown for an outsider' );
	$_POST = array(
		'rolegate_user_roles_present' => '1',
		'rolegate_user_roles'         => array( 'author' ),
		'rolegate_user_nonce'         => wp_create_nonce( 'rolegate_user_' . $member ),
	);
	$errors = new WP_Error();
	$profile->validate( $errors, true, (object) array( 'ID' => $member, 'role' => 'subscriber' ) );
	$rw_ok( ! in_array( 'rolegate_not_site_member', $errors->get_error_codes(), true ), 'profile control: a member is not refused for membership' );

	// Super admin is exempt.
	wp_set_current_user( $super );
	$rw_ok( true === Users::check_site_member( $super, $outsider ), 'super admin: membership check passes' );
	$res = Users::change_roles( $super, $outsider, array( 'author' ), array() );
	$rw_ok( true === $res && $rw_member( $outsider ), 'super admin: can give an outsider a role on this site' );
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
} finally {
	$_POST    = array();
	$_REQUEST = array();
	wp_set_current_user( 0 );
	foreach ( $rw_users as $id ) {
		revoke_super_admin( $id );
		wpmu_delete_user( $id );
	}
	if ( $rw_site ) {
		wp_delete_site( $rw_site );
	}
}

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
