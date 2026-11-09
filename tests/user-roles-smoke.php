<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/user-roles-smoke.php
 */

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\User_Roles\Profile;
use Rolewright\Modules\User_Roles\Users;
use Rolewright\Modules\User_Roles\Users_List;

if ( ! defined( 'ABSPATH' ) ) {
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
$rw_roles  = array( 'rw_t_promoter_' . $rw_suffix, 'rw_t_pu_' . $rw_suffix, 'rw_t_usermgr_' . $rw_suffix );
$rw_users  = array();
$rw_events = array();
$rw_make   = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
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
$rw_roles_of = function ( $id ) {
	clean_user_cache( $id );
	$u = get_userdata( $id );
	$r = $u ? array_values( (array) $u->roles ) : array();
	sort( $r );
	return $r;
};
$rw_post = function ( array $extra ) use ( &$rw_users ) {
	$_POST    = $extra;
	$_REQUEST = $extra;
};
$rw_edit = function ( $id, $actor, array $fields ) use ( $rw_post ) {
	wp_set_current_user( $actor );
	$u = get_userdata( $id );
	$rw_post(
		array_merge(
			array(
				'email'                         => $u->user_email,
				'nickname'                      => $u->user_login,
				'rolewright_user_nonce'         => wp_create_nonce( 'rolewright_user_' . $id ),
			),
			$fields
		)
	);
	add_filter( 'wp_die_handler', $rw_die = function () {
		return function ( $message ) {
			throw new \RuntimeException( is_wp_error( $message ) ? $message->get_error_message() : wp_strip_all_tags( (string) $message ) );
		};
	} );
	try {
		do_action( $id === $actor ? 'personal_options_update' : 'edit_user_profile_update', $id );
		$out = edit_user( $id );
	} catch ( \RuntimeException $e ) {
		$out = new \WP_Error( 'died', $e->getMessage() );
	}
	remove_filter( 'wp_die_handler', $rw_die );
	return $out;
};
add_action(
	'rolewright_changed',
	function ( $type, $data ) use ( &$rw_events ) {
		$rw_events[] = array( $type, $data );
	},
	10,
	2
);
$rw_last_event = function ( $type ) use ( &$rw_events ) {
	for ( $i = count( $rw_events ) - 1; $i >= 0; $i-- ) {
		if ( $rw_events[ $i ][0] === $type ) {
			return $rw_events[ $i ][1];
		}
	}
	return null;
};

( new Profile() )->register();
$rw_list = new Users_List();
$rw_list->register();

try {
	add_role( $rw_roles[0], 'RW promoter', array( 'read' => true, 'promote_users' => true, 'edit_users' => true, 'list_users' => true ) );
	add_role( $rw_roles[1], 'RW promote only', array( 'read' => true, 'promote_users' => true, 'list_users' => true ) );
	add_role( $rw_roles[2], 'RW user manager', array( 'read' => true, 'promote_users' => true, 'edit_users' => true, 'list_users' => true, Caps::MANAGE_USERS => true ) );
	Caps::grant_to_administrator();

	$admin    = $rw_make( 'rw_admin', 'administrator' );
	$admin2   = $rw_make( 'rw_admin2', 'administrator' );
	$promoter = $rw_make( 'rw_promoter', $rw_roles[0] );
	$pu       = $rw_make( 'rw_pu', $rw_roles[1] );
	$usermgr  = $rw_make( 'rw_usermgr', $rw_roles[2] );
	$victim   = $rw_make( 'rw_victim', 'subscriber' );
	$victim2  = $rw_make( 'rw_victim2', 'subscriber' );

	// Reading.
	$rw_ok( array( 'subscriber' ) === Users::get_roles( $victim ), 'get_roles returns the primary role' );
	$rw_ok( array() === Users::get_roles( 999999 ), 'get_roles on a missing user is empty' );
	add_filter( 'rolewright_user_roles', $f = function ( $r ) {
		$r[] = 'virtual';
		return $r;
	} );
	$rw_ok( in_array( 'virtual', Users::get_roles( $victim ), true ), 'get_roles honors rolewright_user_roles' );
	remove_filter( 'rolewright_user_roles', $f );

	// Admin changes roles.
	$res = Users::change_roles( $admin, $victim, array( 'author', 'contributor' ), array() );
	$rw_ok( true === $res && array( 'author', 'contributor', 'subscriber' ) === $rw_roles_of( $victim ), 'admin adds two roles' );
	$ev = $rw_last_event( 'user.roles' );
	$rw_ok( $ev && $admin === $ev['actor'] && $victim === $ev['target'] && array( 'subscriber' ) === $ev['before']['roles'] && 3 === count( $ev['after']['roles'] ), 'user.roles event carries actor, target, before and after' );
	$n = count( $rw_events );
	Users::change_roles( $admin, $victim, array( 'author' ), array() );
	$rw_ok( count( $rw_events ) === $n, 'no event when nothing changed' );
	$res = Users::change_roles( $admin, $victim, array(), array( 'contributor' ) );
	$rw_ok( true === $res && array( 'author', 'subscriber' ) === $rw_roles_of( $victim ), 'admin removes a role' );
	$res = Users::change_roles( $admin, $victim, array(), array( 'author', 'subscriber' ) );
	$rw_ok( true === $res && array() === $rw_roles_of( $victim ), 'a user can end up with no role' );
	Users::change_roles( $admin, $victim, array( 'subscriber' ), array() );

	// Self and unknown.
	$res = Users::change_roles( $admin, $admin, array( 'editor' ), array() );
	$rw_ok( is_wp_error( $res ) && 'rolewright_self_role' === $res->get_error_code(), 'admin cannot change own roles' );
	$res = Users::change_roles( $admin, $victim, array( 'no_such_role_x' ), array() );
	$rw_ok( is_wp_error( $res ), 'unknown role refused' );
	$res = Users::change_roles( $admin, $admin2, array(), array( 'administrator' ) );
	$rw_ok( true === $res, 'admin can remove Administrator from another admin when two exist' );
	Users::change_roles( $admin, $admin2, array( 'administrator' ), array() );

	// Escalation: promote_users holders.
	foreach ( array( $promoter, $pu ) as $who ) {
		wp_set_current_user( $who );
		$label = $who === $promoter ? 'promoter' : 'promote-only user';
		$res   = Users::change_roles( $who, $victim, array( 'administrator' ), array() );
		$rw_ok( is_wp_error( $res ) && ! in_array( 'administrator', $rw_roles_of( $victim ), true ), $label . ' cannot add administrator' );
		$res = Users::change_roles( $who, $victim, array( 'editor' ), array() );
		$rw_ok( is_wp_error( $res ) && ! in_array( 'editor', $rw_roles_of( $victim ), true ), $label . ' cannot add editor (unfiltered_html)' );
		$res = Users::change_roles( $who, $who, array( 'author' ), array() );
		$rw_ok( is_wp_error( $res ), $label . ' cannot self-assign' );
		$res = Users::change_roles( $who, $admin, array(), array( 'administrator' ) );
		$rw_ok( is_wp_error( $res ) && in_array( 'administrator', $rw_roles_of( $admin ), true ), $label . ' cannot strip a user above them' );
		$res = Users::change_roles( $who, $admin, array( 'subscriber' ), array() );
		$rw_ok( is_wp_error( $res ), $label . ' cannot touch an administrator' );
	}
	$res = Users::change_roles( $promoter, $victim2, array( 'author' ), array() );
	$rw_ok( true === $res && in_array( 'author', $rw_roles_of( $victim2 ), true ), 'promoter can still assign a role with no critical caps' );
	Users::change_roles( $admin, $victim2, array(), array( 'author' ) );

	// Bulk.
	$rw_bulk_as = function ( $who ) use ( $rw_post ) {
		wp_set_current_user( $who );
		$rw_post( array( '_wpnonce' => wp_create_nonce( 'bulk-users' ) ) );
	};
	$rw_bulk_as( $admin );
	$out = $rw_list->handle_bulk( admin_url( 'users.php' ), 'rolewright_add:contributor', array( $victim, $victim2, $admin ) );
	parse_str( (string) wp_parse_url( $out, PHP_URL_QUERY ), $q );
	$rw_ok( '2' === ( $q['rolewright_done'] ?? '' ) && '1' === ( $q['rolewright_skip'] ?? '' ) && in_array( 'contributor', $rw_roles_of( $victim ), true ) && ! in_array( 'contributor', $rw_roles_of( $admin ), true ), 'bulk add: two users changed, own account skipped' );
	$out = $rw_list->handle_bulk( admin_url( 'users.php' ), 'rolewright_remove:contributor', array( $victim, $victim2 ) );
	$rw_ok( ! in_array( 'contributor', $rw_roles_of( $victim ), true ) && ! in_array( 'contributor', $rw_roles_of( $victim2 ), true ), 'bulk remove role' );
	$rw_ok( $rw_list->handle_bulk( 'x', 'delete', array( 1 ) ) === 'x', 'bulk handler ignores other actions' );
	$rw_bulk_as( $pu );
	$out = $rw_list->handle_bulk( admin_url( 'users.php' ), 'rolewright_add:editor', array( $victim, $victim2 ) );
	parse_str( (string) wp_parse_url( $out, PHP_URL_QUERY ), $q );
	$rw_ok( '0' === ( $q['rolewright_done'] ?? '' ) && '2' === ( $q['rolewright_skip'] ?? '' ) && ! in_array( 'editor', $rw_roles_of( $victim ), true ), 'promote-only user cannot bulk add editor' );
	$out = $rw_list->handle_bulk( admin_url( 'users.php' ), 'rolewright_add:administrator', array( $victim ) );
	$rw_ok( ! in_array( 'administrator', $rw_roles_of( $victim ), true ), 'promote-only user cannot bulk add administrator' );
	$rw_post( array( '_wpnonce' => 'bad' ) );
	$died = false;
	add_filter( 'wp_die_handler', $h = function () {
		return function () {
			throw new \RuntimeException( 'die' );
		};
	} );
	try {
		wp_set_current_user( $admin );
		$rw_list->handle_bulk( admin_url( 'users.php' ), 'rolewright_add:contributor', array( $victim ) );
	} catch ( \RuntimeException $e ) {
		$died = true;
	}
	remove_filter( 'wp_die_handler', $h );
	$rw_ok( $died && ! in_array( 'contributor', $rw_roles_of( $victim ), true ), 'bulk with a bad nonce dies and changes nothing' );
	$rw_post( array() );

	// Profile flow.
	$res = $rw_edit( $victim, $admin, array( 'role' => 'author', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'contributor', 'subscriber' ) ) );
	$rw_ok( ! is_wp_error( $res ) && array( 'author', 'contributor', 'subscriber' ) === $rw_roles_of( $victim ) && 'author' === get_userdata( $victim )->roles[0], 'profile save: primary plus extras' );
	$ev = $rw_last_event( 'user.roles' );
	$rw_ok( $ev && $victim === $ev['target'] && array( 'subscriber' ) === $ev['before']['roles'] && 3 === count( $ev['after']['roles'] ), 'profile save fires user.roles with before/after' );
	$res = $rw_edit( $victim, $admin, array( 'role' => 'editor', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'contributor' ) ) );
	$rw_ok( ! is_wp_error( $res ) && array( 'contributor', 'editor' ) === $rw_roles_of( $victim ), 'profile save: changing primary and unticking extras drops them' );
	$res = $rw_edit( $victim, $admin, array( 'role' => '', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'contributor' ) ) );
	$rw_ok( ! is_wp_error( $res ) && array( 'contributor' ) === $rw_roles_of( $victim ), 'profile save: no primary role, extras kept' );
	$res = $rw_edit( $victim, $admin, array( 'role' => '', 'rolewright_user_roles_present' => '1' ) );
	$rw_ok( ! is_wp_error( $res ) && array() === $rw_roles_of( $victim ), 'profile save: a user with no roles at all' );
	$res = $rw_edit( $victim, $admin, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_nonce' => 'bad' ) );
	$rw_ok( is_wp_error( $res ) && array( 'subscriber' ) !== $rw_roles_of( $victim ), 'profile save with a bad nonce is refused' );
	Users::change_roles( $admin, $victim, array( 'subscriber' ), array() );

	$res = $rw_edit( $victim, $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'editor' ) ) );
	$rw_ok( is_wp_error( $res ) && array( 'subscriber' ) === $rw_roles_of( $victim ), 'promoter cannot add editor as extra on the profile screen' );
	$res = $rw_edit( $victim, $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'administrator' ) ) );
	$rw_ok( is_wp_error( $res ) && array( 'subscriber' ) === $rw_roles_of( $victim ), 'promoter cannot add administrator as extra on the profile screen' );
	$res = $rw_edit( $victim, $promoter, array( 'role' => 'administrator', 'rolewright_user_roles_present' => '1' ) );
	$rw_ok( is_wp_error( $res ) && array( 'subscriber' ) === $rw_roles_of( $victim ), 'promoter cannot set administrator as primary on the profile screen' );
	$res = $rw_edit( $victim, $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'author' ) ) );
	$rw_ok( ! is_wp_error( $res ) && array( 'author', 'subscriber' ) === $rw_roles_of( $victim ), 'promoter can add a harmless extra role on the profile screen' );
	Users::change_roles( $admin, $victim, array(), array( 'author' ) );
	$before_self = $rw_roles_of( $promoter );
	$rw_edit( $promoter, $promoter, array( 'role' => 'administrator', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'administrator' ) ) );
	$rw_ok( $before_self === $rw_roles_of( $promoter ), 'own profile save cannot change own roles' );
	$res = $rw_edit( $admin, $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1' ) );
	$rw_ok( array( 'administrator' ) === $rw_roles_of( $admin ) && ! user_can( $promoter, 'edit_user', $admin ), 'promoter cannot demote an administrator on the profile screen' );

	// New user.
	$rw_new = function ( $actor, array $fields ) use ( $rw_post, $rw_suffix, &$rw_users ) {
		wp_set_current_user( $actor );
		$login = 'rw_new' . wp_rand( 1000, 9999 ) . '_' . $rw_suffix;
		$rw_post(
			array_merge(
				array(
					'action'                => 'createuser',
					'user_login'            => $login,
					'email'                 => $login . '@example.com',
					'pass1'                 => 'Xy9!longPassw0rdzz',
					'pass2'                 => 'Xy9!longPassw0rdzz',
					'rolewright_user_nonce' => wp_create_nonce( 'rolewright_user_0' ),
				),
				$fields
			)
		);
		$id = edit_user();
		if ( ! is_wp_error( $id ) ) {
			$rw_users[] = (int) $id;
		}
		return $id;
	};
	$id = $rw_new( $admin, array( 'role' => 'author', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'contributor' ) ) );
	$rw_ok( ! is_wp_error( $id ) && array( 'author', 'contributor' ) === $rw_roles_of( $id ), 'new user: primary plus extra role' );
	$ev = $rw_last_event( 'user.roles' );
	$rw_ok( $ev && ! is_wp_error( $id ) && $id === $ev['target'] && array() === $ev['before']['roles'] && 2 === count( $ev['after']['roles'] ), 'new user fires user.roles from an empty before' );
	$id = $rw_new( $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'editor' ) ) );
	$rw_ok( is_wp_error( $id ), 'promoter cannot create a user with an editor extra role' );
	$id = $rw_new( $promoter, array( 'role' => 'subscriber', 'rolewright_user_roles_present' => '1', 'rolewright_user_roles' => array( 'administrator' ) ) );
	$rw_ok( is_wp_error( $id ), 'promoter cannot create a user with an administrator extra role' );

	// Per-user capabilities.
	$cap = 'rw_t_cap_' . $rw_suffix;
	$rw_ok( ! user_can( $victim, 'edit_pages' ), 'setup: victim lacks edit_pages' );
	$res = $rw_edit( $victim, $admin, array( 'role' => 'subscriber', 'rolewright_user_caps_present' => '1', 'rolewright_user_caps' => array( 'edit_pages' ), 'rolewright_user_cap_new' => strtoupper( $cap ) ) );
	clean_user_cache( $victim );
	$rw_ok( ! is_wp_error( $res ) && user_can( $victim, 'edit_pages' ) && user_can( $victim, $cap ), 'admin grants a listed and a typed capability on the profile' );
	$ev = $rw_last_event( 'user.caps' );
	$rw_ok( $ev && $victim === $ev['target'] && array() === $ev['before']['caps'] && isset( $ev['after']['caps']['edit_pages'] ), 'user.caps event carries before and after' );
	$res = $rw_edit( $victim, $admin, array( 'role' => 'subscriber', 'rolewright_user_caps_present' => '1', 'rolewright_user_caps' => array( 'edit_pages' ) ) );
	clean_user_cache( $victim );
	$rw_ok( ! is_wp_error( $res ) && user_can( $victim, 'edit_pages' ) && ! user_can( $victim, $cap ), 'unticked capability is revoked' );
	$res = $rw_edit( $victim, $admin, array( 'role' => 'subscriber', 'rolewright_user_caps_present' => '1', 'rolewright_user_caps' => array() ) );
	clean_user_cache( $victim );
	$rw_ok( array() === Users::direct_caps( $victim ) && array( 'subscriber' ) === $rw_roles_of( $victim ), 'revoking all leaves the role intact' );
	$res = Users::change_caps( $admin, $victim, array( 'bad cap!' ), array() );
	$rw_ok( is_wp_error( $res ) && 'rolewright_invalid_cap' === $res->get_error_code(), 'invalid capability name refused' );
	$res = Users::change_caps( $admin, $victim, array( 'subscriber' ), array() );
	$rw_ok( is_wp_error( $res ), 'a role name cannot be written as a capability' );
	$res = Users::change_caps( $admin, $admin, array( 'edit_pages' ), array() );
	$rw_ok( is_wp_error( $res ) && 'rolewright_self_caps' === $res->get_error_code(), 'cannot change own capabilities' );

	foreach ( array( $promoter, $pu ) as $who ) {
		$res = Users::change_caps( $who, $victim, array( 'edit_pages' ), array() );
		$rw_ok( is_wp_error( $res ) && ! user_can( $victim, 'edit_pages' ), 'user without rolewright_manage_users cannot grant per-user caps' );
	}
	$res = $rw_edit( $victim, $promoter, array( 'role' => 'subscriber', 'rolewright_user_caps_present' => '1', 'rolewright_user_caps' => array( 'manage_options' ) ) );
	clean_user_cache( $victim );
	$rw_ok( ! user_can( $victim, 'manage_options' ), 'promoter cannot grant manage_options through the profile screen' );
	foreach ( array( 'manage_options', 'install_plugins', 'unfiltered_html', Caps::MANAGE_ROLES, 'edit_pages' ) as $c ) {
		$res = Users::change_caps( $usermgr, $victim, array( $c ), array() );
		$rw_ok( is_wp_error( $res ) && ! user_can( $victim, $c ), 'user manager cannot grant ' . $c . ' without holding it' );
	}
	$res = Users::change_caps( $usermgr, $victim, array( 'read' ), array() );
	$rw_ok( true === $res && isset( Users::direct_caps( $victim )['read'] ), 'user manager can grant a cap they hold' );
	$res = Users::change_caps( $usermgr, $victim, array(), array( 'read' ) );
	$rw_ok( true === $res && array() === Users::direct_caps( $victim ), 'user manager can revoke it' );
	$res = Users::change_caps( $usermgr, $admin, array( 'read' ), array() );
	$rw_ok( is_wp_error( $res ), 'user manager cannot edit capabilities of an administrator' );
	$res = Users::change_roles( $usermgr, $victim, array( 'editor' ), array() );
	$rw_ok( is_wp_error( $res ), 'user manager cannot assign editor' );

	// Users without a role.
	$norole = $rw_make( 'rw_norole', 'subscriber' );
	$onlycap = $rw_make( 'rw_onlycap', 'subscriber' );
	Users::change_roles( $admin, $norole, array(), array( 'subscriber' ) );
	Users::change_roles( $admin, $onlycap, array(), array( 'subscriber' ) );
	Users::change_caps( $admin, $onlycap, array( 'read' ), array() );
	$q = new \WP_User_Query( array( 'fields' => 'ID', 'meta_query' => Users::no_role_meta_query() ) );
	$ids = array_map( 'intval', $q->get_results() );
	$rw_ok( in_array( $norole, $ids, true ) && in_array( $onlycap, $ids, true ), 'no-role query finds users with no roles, including one with only a direct cap' );
	$rw_ok( ! in_array( $admin, $ids, true ) && ! in_array( $victim, $ids, true ), 'no-role query excludes users with roles' );
	$rw_ok( count( $ids ) >= 2 && Users::count_no_role() === count( $ids ), 'count_no_role equals the query result (' . count( $ids ) . ')' );
	$counts = Users::counts();
	$expect = count( get_users( array( 'role' => 'subscriber', 'fields' => 'ID' ) ) );
	$rw_ok( $expect > 0 && $counts['roles']['subscriber'] === $expect && $counts['total'] >= $expect && $counts['none'] === count( $ids ), 'counts() per-role matches a role query (' . $expect . ' subscribers)' );
	Users::change_roles( $admin, $victim, array( 'author' ), array() );
	$counts2 = Users::counts();
	$rw_ok( $counts2['roles']['author'] === $counts['roles']['author'] + 1 && $counts2['roles']['subscriber'] === $counts['roles']['subscriber'], 'a second role raises that role count without lowering the first' );
	Users::change_roles( $admin, $victim, array(), array( 'author' ) );
	$out = Users::count_no_role();
	$rw_ok( true === Users::change_roles( $admin, $norole, array( 'subscriber' ), array() ) && Users::count_no_role() === $out - 1, 'assigning a role removes the user from the no-role set' );
	$_GET = array( 'rolewright_no_role' => '1' );
	$views = $rw_list->views( array( 'all' => '<a href="x" class="current" aria-current="page">All</a>' ) );
	$rw_ok( isset( $views['rolewright_none'] ) && false === strpos( $views['all'], 'current' ) && false !== strpos( $views['rolewright_none'], 'current' ), 'views add a current No role link' );
	$GLOBALS['pagenow'] = 'users.php';
	wp_set_current_user( $admin );
	$wpq = new \WP_User_Query( array( 'fields' => 'ID' ) );
	$ids = array_map( 'intval', $wpq->get_results() );
	$rw_ok( in_array( $onlycap, $ids, true ) && ! in_array( $admin, $ids, true ), 'users.php?rolewright_no_role=1 lists only users without a role' );
	$_GET = array();
	unset( $GLOBALS['pagenow'] );

	// Column.
	$cols = $rw_list->columns( array( 'cb' => 'x', 'username' => 'Username', 'role' => 'Role', 'posts' => 'Posts' ) );
	$rw_ok( ! isset( $cols['role'] ) && 'Roles' === $cols['rolewright_roles'] && array_keys( $cols ) === array( 'cb', 'username', 'rolewright_roles', 'posts' ), 'Roles column replaces the core Role column in place' );
	Users::change_roles( $admin, $victim, array( 'author' ), array() );
	$html = $rw_list->column( '', 'rolewright_roles', $victim );
	$rw_ok( false !== strpos( $html, 'role=subscriber' ) && false !== strpos( $html, 'role=author' ) && false !== strpos( $html, ', ' ), 'Roles column lists every role with filter links' );
	$rw_ok( false !== strpos( $rw_list->column( '', 'rolewright_roles', $onlycap ), 'rolewright_no_role=1' ), 'Roles column links users without a role to the filter' );
	$rw_ok( 'keep' === $rw_list->column( 'keep', 'other', $victim ), 'other columns pass through' );

	// Bulk action list.
	wp_set_current_user( $admin );
	$acts = $rw_list->bulk_actions( array() );
	$rw_ok( isset( $acts['rolewright_add:editor'], $acts['rolewright_remove:editor'] ), 'admin sees add and remove role bulk actions' );
	wp_set_current_user( $pu );
	$acts = $rw_list->bulk_actions( array() );
	$rw_ok( ! isset( $acts['rolewright_add:administrator'], $acts['rolewright_add:editor'] ), 'promote-only user is not offered administrator or editor' );
	wp_set_current_user( $victim );
	$rw_ok( array( 'a' => 1 ) === $rw_list->bulk_actions( array( 'a' => 1 ) ), 'users without promote_users get no bulk actions' );

	// Module metadata.
	$mod = new \Rolewright\Modules\User_Roles\User_Roles_Module();
	$rw_ok( 'user-roles' === $mod->id() && $mod->default_enabled(), 'module id and default' );
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
}

wp_set_current_user( 0 );
foreach ( $rw_users as $id ) {
	wp_delete_user( $id );
}
foreach ( $rw_roles as $r ) {
	remove_role( $r );
}
$_POST    = array();
$_REQUEST = array();

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
