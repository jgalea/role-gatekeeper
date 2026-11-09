<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/roles-smoke.php
 */

use Rolewright\Modules\Roles\Role_List;
use Rolewright\Modules\Roles\Role_Service;
use Rolewright\Modules\Roles\Role_Store;
use Rolewright\Modules\Safety\Caps;

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

$rw_events = array();
add_action(
	'rolewright_changed',
	function ( $type, $data ) use ( &$rw_events ) {
		$rw_events[] = array( $type, $data );
	},
	10,
	2
);
$rw_last = function ( $type ) use ( &$rw_events ) {
	foreach ( array_reverse( $rw_events ) as $e ) {
		if ( $e[0] === $type ) {
			return $e[1];
		}
	}
	return null;
};

$rw_suffix = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users  = array();
$rw_make   = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_suffix,
			'user_email' => $login . '_' . $rw_suffix . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $role,
		)
	);
	$rw_users[] = (int) $id;
	return (int) $id;
};

$rw_admin = $rw_make( 'rw_roles_admin', 'administrator' );
wp_set_current_user( $rw_admin );
$rw_orig_default = (string) get_option( 'default_role' );
$rw_orig_extras  = Role_Service::extra_default_roles();

// Create, rename, clone.
$slug = Role_Service::create( $rw_admin, 'RW Tester ' . $rw_suffix );
$rw_ok( is_string( $slug ) && get_role( $slug ), 'create: role exists' );
$rw_ok( array( 'read' => true ) === Role_Store::caps( $slug ), 'create: starts with read only' );
$rw_ok( is_array( $rw_last( 'role.created' ) ) && $rw_last( 'role.created' )['target'] === $slug && $rw_last( 'role.created' )['actor'] === $rw_admin, 'create: fires role.created with actor and target' );
$rw_ok( is_wp_error( Role_Service::create( $rw_admin, 'RW Tester ' . $rw_suffix ) ), 'create: duplicate refused' );
$rw_ok( is_wp_error( Role_Service::create( $rw_admin, '' ) ), 'create: empty name refused' );
$rw_ok( is_wp_error( Role_Service::create( $rw_admin, 'read' ) ), 'create: name equal to a capability refused' );

$rw_ok( true === Role_Service::rename( $rw_admin, $slug, 'RW Renamed ' . $rw_suffix ), 'rename: ok' );
$rw_ok( 'RW Renamed ' . $rw_suffix === Role_Store::name( $slug ) && 'RW Renamed ' . $rw_suffix === wp_roles()->get_names()[ $slug ], 'rename: stored and visible in role names' );
$ev = $rw_last( 'role.renamed' );
$rw_ok( $ev && $ev['before']['name'] === 'RW Tester ' . $rw_suffix && $ev['after']['name'] === 'RW Renamed ' . $rw_suffix, 'rename: event carries before and after' );
$rw_ok( is_wp_error( Role_Service::rename( $rw_admin, 'administrator', 'Boss' ) ), 'rename: administrator refused' );

$rw_src = Role_Service::create( $rw_admin, 'RW Source ' . $rw_suffix, array( 'read' => true, 'edit_posts' => true, 'upload_files' => true ) );
$rw_cl  = Role_Service::clone_role( $rw_admin, $rw_src, 'RW Clone ' . $rw_suffix );
$rw_ok( is_string( $rw_cl ) && Role_Store::caps( $rw_cl ) === Role_Store::caps( $rw_src ), 'clone: copies the caps' );
$rw_ok( is_wp_error( Role_Service::clone_role( $rw_admin, 'no_such_role', 'Nope' ) ), 'clone: unknown source refused' );

// Cloning a role the actor can't match is refused (escalation).
$rw_low_role = Role_Service::create( $rw_admin, 'RW Lowmgr ' . $rw_suffix, array( 'read' => true, Caps::MANAGE_ROLES => true, Caps::MANAGE => true ) );
$rw_low      = $rw_make( 'rw_roles_low', is_string( $rw_low_role ) ? $rw_low_role : 'subscriber' );
wp_set_current_user( $rw_low );
$rw_ok( is_wp_error( Role_Service::clone_role( $rw_low, 'administrator', 'RW Admin Copy ' . $rw_suffix ) ), 'clone: low-privilege manager can\'t clone administrator' );
wp_set_current_user( $rw_admin );

// Delete.
$rw_ok( is_wp_error( Role_Service::delete( $rw_admin, 'administrator' ) ), 'delete: administrator refused' );
$rw_ok( is_wp_error( Role_Service::delete( $rw_admin, (string) get_option( 'default_role' ) ) ), 'delete: default role refused' );
$rw_ok( is_wp_error( Role_Service::delete( $rw_admin, 'no_such_role' ) ), 'delete: unknown role refused' );

$rw_used = Role_Service::create( $rw_admin, 'RW Used ' . $rw_suffix );
$rw_uid  = $rw_make( 'rw_roles_used', $rw_used );
$rw_ok( is_wp_error( Role_Service::delete( $rw_admin, $rw_used ) ), 'delete: role with users refused' );
$counts = Role_Store::user_counts();
$rw_ok( isset( $counts[ $rw_used ] ) && 1 === $counts[ $rw_used ], 'list: user count is 1 for the used role' );
$rw_ok( Role_Store::granted_count( Role_Store::caps( $rw_src ) ) === 3, 'list: cap count is 3 for the source role' );

$out = Role_Service::delete_unused( $rw_admin, array( $rw_cl, $rw_used, 'administrator' ) );
$rw_ok( array( $rw_cl ) === $out['deleted'] && isset( $out['errors'][ $rw_used ] ) && isset( $out['errors']['administrator'] ), 'bulk delete: removes only the unused unprotected role' );
$rw_ok( ! get_role( $rw_cl ) && get_role( $rw_used ) && get_role( 'administrator' ), 'bulk delete: others untouched' );
$ev = $rw_last( 'role.deleted' );
$rw_ok( $ev && $ev['target'] === $rw_cl && ! empty( $ev['before']['caps'] ), 'delete: event carries the deleted caps' );

// Default roles.
$rw_ok( is_wp_error( Role_Service::set_default( $rw_admin, 'administrator' ) ), 'default: administrator refused' );
$rw_ok( is_wp_error( Role_Service::set_default( $rw_admin, 'subscriber', array( 'editor' ) ) ), 'default: extra role with powerful caps refused' );
$rw_ok( true === Role_Service::set_default( $rw_admin, 'contributor', array( $rw_src ) ), 'default: set contributor plus an extra' );
$rw_ok( 'contributor' === get_option( 'default_role' ) && array( $rw_src ) === Role_Service::extra_default_roles(), 'default: options stored' );
$ev = $rw_last( 'role.default_set' );
$rw_ok( $ev && $ev['after']['default'] === 'contributor', 'default: fires role.default_set' );
$new = wp_insert_user(
	array(
		'user_login' => 'rw_reg_' . $rw_suffix,
		'user_email' => 'rw_reg_' . $rw_suffix . '@example.com',
		'user_pass'  => wp_generate_password( 24 ),
	)
);
$rw_users[] = (int) $new;
clean_user_cache( $new );
$nu = get_userdata( $new );
$rw_ok( in_array( 'contributor', (array) $nu->roles, true ) && in_array( $rw_src, (array) $nu->roles, true ), 'default: new user gets the default and the extra role' );
Role_Service::set_default( $rw_admin, $rw_orig_default ? $rw_orig_default : 'subscriber', $rw_orig_extras );

// Reset.
$rw_ed = get_role( 'editor' );
$rw_ed->add_cap( 'rw_plugin_added_' . $rw_suffix );
$rw_custom_before = Role_Store::caps( $rw_src );
$backups_before   = count( Role_Service::backups() );
$res              = Role_Service::reset( $rw_admin );
$rw_ok( true === $res, 'reset: ok' );
$rw_ok( ! get_role( 'editor' )->has_cap( 'rw_plugin_added_' . $rw_suffix ), 'reset: plugin-added cap removed from editor' );
$rw_ok( get_role( 'administrator' )->has_cap( Caps::MANAGE_ROLES ) && get_role( 'administrator' )->has_cap( 'manage_options' ), 'reset: administrator keeps core and Rolewright caps' );
$rw_ok( get_role( 'editor' )->has_cap( 'edit_others_posts' ) && ! get_role( 'subscriber' )->has_cap( 'edit_posts' ), 'reset: core roles match WordPress defaults' );
$rw_ok( get_role( $rw_src ) && Role_Store::caps( $rw_src ) === $rw_custom_before, 'reset: custom roles are kept' );
$bk = Role_Service::backups();
$rw_ok( count( $bk ) === $backups_before + 1 && isset( $bk[0]['roles']['editor']['caps'][ 'rw_plugin_added_' . $rw_suffix ] ), 'reset: backup holds the roles as they were' );
$ev = $rw_last( 'roles.reset' );
$rw_ok( $ev && isset( $ev['before']['roles']['editor'] ), 'reset: fires roles.reset with before' );

// A reset that would lock the actor out is rolled back.
$bk_n = count( Role_Service::backups() );
wp_set_current_user( $rw_admin );
$core_mgr = $rw_make( 'rw_roles_coremgr', 'editor' );
get_role( 'editor' )->add_cap( Caps::MANAGE );
get_role( 'editor' )->add_cap( Caps::MANAGE_ROLES );
wp_set_current_user( $core_mgr );
$res = Role_Service::reset( $core_mgr );
$rw_ok( is_wp_error( $res ) && 'rolewright_lockout' === $res->get_error_code(), 'reset: refused and rolled back when the actor would lose access' );
$rw_ok( get_role( 'editor' )->has_cap( Caps::MANAGE_ROLES ), 'reset: roles restored after the refused reset' );
$rw_ok( count( Role_Service::backups() ) === $bk_n, 'reset: refused reset leaves no stray backup' );
wp_set_current_user( $rw_admin );

// Admin page renders and the handler-level checks hold.
$rw_idle = Role_Service::create( $rw_admin, 'RW Idle ' . $rw_suffix );
ob_start();
( new Role_List() )->render();
$html = ob_get_clean();
$rw_ok( false !== strpos( $html, 'wp-list-table' ) && false !== strpos( $html, esc_html( 'RW Renamed ' . $rw_suffix ) ), 'page: list table renders with the role name' );
$rw_ok( false !== strpos( $html, 'name="op" value="reset"' ) && false !== strpos( $html, 'confirm_reset' ), 'page: reset form with confirmation box' );
$rw_ok( false !== strpos( $html, '_wpnonce' ), 'page: forms carry a nonce' );
$rw_ok( 1 === preg_match( '/name="roles\[\]" value="' . preg_quote( $rw_idle, '/' ) . '"/', $html ) && 0 === preg_match( '/name="roles\[\]" value="administrator"/', $html ), 'page: only deletable roles get a bulk checkbox' );

wp_set_current_user( $rw_low );
$rw_ok( ! current_user_can( 'edit_users' ) && ( current_user_can( Caps::MANAGE_ROLES ) ), 'page: the manage-roles cap gates access (low manager holds it, has no extra powers)' );

// Cleanup.
wp_set_current_user( $rw_admin );
get_role( 'editor' )->remove_cap( Caps::MANAGE );
get_role( 'editor' )->remove_cap( Caps::MANAGE_ROLES );
foreach ( array_unique( $rw_users ) as $uid ) {
	wp_delete_user( $uid );
}
foreach ( array( $slug, $rw_src, $rw_cl, $rw_used, $rw_low_role, $rw_idle ) as $r ) {
	if ( is_string( $r ) && get_role( $r ) ) {
		remove_role( $r );
	}
}
update_option( Role_Service::OPTION_BACKUPS, array() );
update_option( Role_Service::OPTION_EXTRA, $rw_orig_extras );
Caps::grant_to_administrator();
$rw_ok( ! get_role( $slug ) && ! get_user_by( 'login', 'rw_roles_admin_' . $rw_suffix ), 'cleanup: temp roles and users removed' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
