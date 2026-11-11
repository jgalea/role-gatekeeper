<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/automation-smoke.php
 */

use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Automation\Abilities;
use Rolegate\Modules\Automation\Automation_Module;
use Rolegate\Modules\Automation\Defaults;
use Rolegate\Modules\Automation\Ops;
use Rolegate\Modules\Automation\Rest_Routes;
use Rolegate\Modules\Safety\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

// Multisite: site administrators hold rolegate_* caps only when the network grants it; these checks are about role-based access, so grant it.
if ( is_multisite() ) {
	add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/admin.php';

global $wpdb;

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
$code = function ( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : '';
};

$sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$users = array();
$roles = array();
$make  = function ( $login, $role ) use ( &$users, $sfx ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $sfx,
			'user_email' => $login . '_' . $sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $role,
		)
	);
	$users[] = $id;
	return $id;
};
$role_caps = function ( $slug ) {
	$r = get_role( $slug );
	return $r ? $r->capabilities : null;
};

$admin = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
$admin = (int) $admin[0];
wp_set_current_user( $admin );
delete_option( Automation_Module::OPTION_SETTINGS );

$events = array();
add_action(
	'rolegate_changed',
	function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	},
	10,
	2
);
$types = function () use ( &$events ) {
	return array_column( $events, 0 );
};

// A limited manager: can manage roles, caps and users, does not hold manage_options.
$mgr_slug = 'rw_auto_mgr_' . $sfx;
$roles[]  = $mgr_slug;
add_role( $mgr_slug, 'Auto Mgr', array( 'read' => true, 'promote_users' => true, Caps::MANAGE => true, Caps::MANAGE_ROLES => true, Caps::MANAGE_CAPS => true, Caps::MANAGE_USERS => true ) );
$mgr = $make( 'rw_auto_mgr', $mgr_slug );

// Role operations, shell actor (0).
$a = 'rw_auto_a_' . $sfx;
$roles[] = $a;
$res = Ops::add_role( 0, 'Auto A ' . $sfx, $a, array( 'read', 'edit_posts' ) );
$rw_ok( $a === $res && ! empty( $role_caps( $a )['edit_posts'] ), 'add_role creates a role with caps' );
$rw_ok( in_array( 'role.created', $types(), true ) && 'role.created' === $events[0][0] && 'Auto A ' . $sfx === $events[0][1]['after']['name'], 'add_role fires rolegate_changed role.created with before and after' );
$rw_ok( 'rolegate_role_exists' === $code( Ops::add_role( 0, 'Dup', $a, array() ) ), 'add_role refuses an existing slug' );
$rw_ok( 'rolegate_invalid_cap' === $code( Ops::add_role( 0, 'Bad Caps', 'rw_auto_bad_' . $sfx, array( 'Bad Cap!' ) ) ), 'add_role refuses an invalid cap name' );
$rw_ok( null === get_role( 'rw_auto_bad_' . $sfx ), 'refused add_role left nothing behind' );
$b = 'rw_auto_b_' . $sfx;
$roles[] = $b;
$res = Ops::clone_role( 0, $a, 'Auto B', $b );
$rw_ok( $b === $res && ! empty( $role_caps( $b )['edit_posts'] ), 'clone_role copies the capabilities' );
$rw_ok( true === Ops::change_role_caps( 0, $b, array( 'moderate_comments' ), array( 'edit_posts' ), array( 'delete_posts' ) ), 'change_role_caps applies add, remove and deny' );
$c = $role_caps( $b );
$rw_ok( ! empty( $c['moderate_comments'] ) && ! isset( $c['edit_posts'] ) && isset( $c['delete_posts'] ) && false === $c['delete_posts'], 'caps were granted, removed and denied' );
$last = end( $events );
$rw_ok( 'caps.updated' === $last[0] && $b === $last[1]['target'] && ! empty( $last[1]['after']['caps']['moderate_comments'] ), 'change_role_caps fires caps.updated' );
$rw_ok( true === Ops::change_role_caps( 0, $b, array( 'manage_options' ), array() ), 'shell actor may grant a critical cap (no actor to hold it)' );
Ops::change_role_caps( 0, $b, array(), array( 'manage_options' ) );

$rw_ok( 'rolegate_protected_role' === $code( Ops::delete_role( 0, 'administrator' ) ), 'administrator can\'t be deleted' );
$rw_ok( 'rolegate_protected_role' === $code( Ops::delete_role( 0, get_option( 'default_role' ) ) ), 'default role can\'t be deleted' );
$rw_ok( 'rolegate_protected_role' === $code( Ops::change_role_caps( 0, 'administrator', array(), array( Caps::MANAGE_ROLES ) ) ), 'administrator can\'t lose Role Gatekeeper caps even for the shell' );
$rw_ok( 'rolegate_protected_role' === $code( Ops::change_role_caps( 0, 'administrator', array(), array( 'manage_options' ) ) ), 'administrator can\'t lose critical caps' );

// Guard applies to a named actor. With the role hierarchy on, own-role edits are refused before the lockout check.
$own_role_codes = \Rolegate\Core\Plugin::is_enabled( 'deny-hierarchy' ) ? array( 'rolegate_lockout', 'rolegate_role_above_position' ) : array( 'rolegate_lockout' );
$rw_ok( 'rolegate_cap_not_held' === $code( Ops::change_role_caps( $mgr, $a, array( 'manage_options' ), array() ) ), 'named actor can\'t grant a critical cap they lack' );
$rw_ok( empty( $role_caps( $a )['manage_options'] ), 'refused grant changed nothing' );
$rw_ok( in_array( $code( Ops::change_role_caps( $mgr, $mgr_slug, array(), array( Caps::MANAGE ) ) ), $own_role_codes, true ), 'named actor can\'t remove their own access' );
$rw_ok( 'rolegate_cannot_assign' === $code( Ops::assign_role( $mgr, $mgr, 'administrator' ) ) || 'rolegate_cannot_assign' === $code( Ops::assign_role( $mgr, $make( 'rw_auto_victim', 'subscriber' ), 'administrator' ) ), 'named actor can\'t hand out the administrator role' );

// Reset.
$ed_orig = $role_caps( 'editor' );
get_role( 'editor' )->add_cap( 'rw_junk_' . $sfx );
get_role( 'editor' )->remove_cap( 'moderate_comments' );
$stored_before = wp_json_encode( get_option( wp_roles()->role_key ) );
$defaults      = Defaults::core_roles();
$rw_ok( 5 === count( $defaults ) && ! empty( $defaults['editor']['edit_others_posts'] ) && ! empty( $defaults['administrator']['manage_options'] ), 'Defaults reads the five core roles from core' );
$rw_ok( wp_json_encode( get_option( wp_roles()->role_key ) ) === $stored_before && ! empty( wp_roles()->roles['editor'] ), 'reading the defaults did not touch the stored roles' );
$rw_ok( true === Ops::reset_role( 0, 'editor' ), 'reset_role runs' );
$c = $role_caps( 'editor' );
$rw_ok( empty( $c[ 'rw_junk_' . $sfx ] ) && ! empty( $c['moderate_comments'] ) && $c == $defaults['editor'], 'reset restores the WordPress default caps and drops extras' );
$last = end( $events );
$rw_ok( 'caps.updated' === $last[0] && 'editor' === $last[1]['target'], 'reset fires caps.updated' );
$rw_ok( 'rolegate_not_core_role' === $code( Ops::reset_role( 0, $a ) ), 'reset refuses a custom role' );
$rw_ok( true === Ops::reset_role( 0, 'administrator' ) && ! empty( $role_caps( 'administrator' )[ Caps::MANAGE_ROLES ] ) && ! empty( $role_caps( 'administrator' )[ Caps::VIEW_AUDIT ] ), 'resetting administrator keeps the Role Gatekeeper caps' );

// Users.
$u = $make( 'rw_auto_u', 'subscriber' );
$rw_ok( true === Ops::assign_role( 0, $u, $a ) && in_array( $a, get_userdata( $u )->roles, true ), 'assign_role adds the role' );
$last = end( $events );
$rw_ok( 'user.roles' === $last[0] && $u === (int) $last[1]['target'] && in_array( $a, $last[1]['after']['roles'], true ) && ! in_array( $a, $last[1]['before']['roles'], true ), 'assign_role fires user.roles with before and after' );
$rw_ok( 'rolegate_already_has_role' === $code( Ops::assign_role( 0, $u, $a ) ), 'assigning a role the user has is refused' );
$rw_ok( true === Ops::unassign_role( 0, $u, $a ) && ! in_array( $a, get_userdata( $u )->roles, true ), 'unassign_role removes it' );
$rw_ok( 'rolegate_lockout' === $code( Ops::unassign_role( $mgr, $mgr, $mgr_slug ) ), 'named actor can\'t unassign the role that gives them access' );
$rw_ok( 'rolegate_user_lacks_role' === $code( Ops::unassign_role( 0, $u, $a ) ), 'unassigning a role the user lacks is refused' );
$sum = Ops::user_summary( $u );
$rw_ok( ! is_wp_error( $sum ) && in_array( 'read', $sum['capabilities'], true ) && array( 'subscriber' ) === $sum['roles'], 'user_summary lists roles and effective caps' );

// Audit module saw the shell and actor events (it listens on the same hook).
$rw_ok( (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Store::table() . " WHERE type = 'user.roles' AND target = '" . (int) $u . "'" ) >= 2, 'audit log recorded the automation changes' ); // phpcs:ignore

// Export and import.
$data = Ops::export_data( array( $b, 'administrator' ) );
$rw_ok( 'rolegate' === $data['format'] && 1 === $data['version'] && isset( $data['roles'][ $b ]['capabilities'] ) && isset( $data['roles']['administrator'] ) && 2 === count( $data['roles'] ), 'export has the portability file format and the chosen roles' );
$import = array(
	'format'  => 'rolegate',
	'version' => 1,
	'roles'   => array(
		$b                      => array( 'name' => 'Auto B', 'capabilities' => array( 'read' => true, 'upload_files' => true ) ),
		'rw_auto_new_' . $sfx   => array( 'name' => 'Imported', 'capabilities' => array( 'read' => true, 'manage_options' => true ) ),
	),
);
$roles[] = 'rw_auto_new_' . $sfx;
$before_b = $role_caps( $b );
$res      = Ops::import_json( 0, wp_json_encode( $import ), true );
$rw_ok( ! is_wp_error( $res ) && 'overwrite' === $res['rows'][ $b ]['action'] && 'create' === $res['rows'][ 'rw_auto_new_' . $sfx ]['action'], 'dry run reports overwrite and create' );
$rw_ok( array( 'manage_options' ) === $res['rows'][ 'rw_auto_new_' . $sfx ]['stripped'], 'dry run shows the critical cap that would be stripped' );
$rw_ok( $role_caps( $b ) === $before_b && null === get_role( 'rw_auto_new_' . $sfx ) && array() === $res['applied'], 'dry run wrote nothing' );
$n_events = count( $events );
$res = Ops::import_json( 0, wp_json_encode( $import ), false );
$rw_ok( ! is_wp_error( $res ) && 2 === count( $res['applied'] ) && ! empty( $role_caps( $b )['upload_files'] ) && ! empty( $role_caps( 'rw_auto_new_' . $sfx )['read'] ), 'import applies the roles' );
$rw_ok( empty( $role_caps( 'rw_auto_new_' . $sfx )['manage_options'] ), 'import strips the critical cap from the new role' );
$rw_ok( count( $events ) > $n_events && 'import.applied' === end( $events )[0], 'import fires per-role events and import.applied' );
$bad = $import;
$bad['roles']['administrator'] = array( 'name' => 'Administrator', 'capabilities' => array( 'read' => true ) );
$res = Ops::import_json( 0, wp_json_encode( $bad ), false );
$rw_ok( 'rolegate_import_blocked' === $code( $res ) && ! empty( $role_caps( 'administrator' )['manage_options'] ), 'a file naming the administrator role is refused and changes nothing' );
$rw_ok( 'rolegate_import_json' === $code( Ops::import_json( 0, '{nope', true ) ) && 'rolegate_import_format' === $code( Ops::import_json( 0, '{"roles":{}}', true ) ), 'malformed and foreign files are refused' );
$inv = $import;
$inv['roles']['rw_auto_inv_' . $sfx] = array( 'name' => 'Inv', 'capabilities' => array( 'Bad Cap!' => true ) );
$res = Ops::import_json( 0, wp_json_encode( $inv ), true );
$rw_ok( ! is_wp_error( $res ) && $res['rejected'] && ! empty( $res['rows'][ 'rw_auto_inv_' . $sfx ] ) && array() === $res['rows'][ 'rw_auto_inv_' . $sfx ]['final'], 'invalid capability names are rejected' );

// WP-CLI, in process.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	( new Automation_Module() )->init();
	$run = function ( $cmd ) {
		return WP_CLI::runcommand( $cmd, array( 'return' => 'all', 'launch' => false, 'exit_error' => false ) );
	};
	wp_set_current_user( 0 );
	$r = $run( 'rolegate role list --format=json' );
	$rw_ok( 0 === $r->return_code && false !== strpos( $r->stdout, '"slug":"administrator"' ), 'wp rolegate role list' );
	$c1 = 'rw_auto_cli_' . $sfx;
	$roles[] = $c1;
	$r = $run( 'rolegate role add "CLI Role" --slug=' . $c1 . ' --caps=read,edit_posts' );
	$rw_ok( 0 === $r->return_code && ! empty( $role_caps( $c1 )['edit_posts'] ), 'wp rolegate role add' );
	$c2 = 'rw_auto_cli2_' . $sfx;
	$roles[] = $c2;
	$r = $run( 'rolegate role clone ' . $c1 . ' "CLI Two" --slug=' . $c2 );
	$rw_ok( 0 === $r->return_code && ! empty( $role_caps( $c2 )['edit_posts'] ), 'wp rolegate role clone' );
	$r = $run( 'rolegate cap add ' . $c2 . ' moderate_comments' );
	$rw_ok( 0 === $r->return_code && ! empty( $role_caps( $c2 )['moderate_comments'] ), 'wp rolegate cap add' );
	$r = $run( 'rolegate cap remove ' . $c2 . ' moderate_comments' );
	$rw_ok( 0 === $r->return_code && empty( $role_caps( $c2 )['moderate_comments'] ), 'wp rolegate cap remove' );
	$r = $run( 'rolegate cap list ' . $c2 . ' --format=json' );
	$rw_ok( 0 === $r->return_code && false !== strpos( $r->stdout, '"cap":"edit_posts"' ), 'wp rolegate cap list <role>' );
	$r = $run( 'rolegate cap list --format=json' );
	$rw_ok( 0 === $r->return_code && false !== strpos( $r->stdout, '"cap":"read"' ), 'wp rolegate cap list' );
	$r = $run( 'rolegate user assign ' . (int) $u . ' ' . $c1 );
	$rw_ok( 0 === $r->return_code && in_array( $c1, get_userdata( $u )->roles, true ), 'wp rolegate user assign' );
	$r = $run( 'rolegate user roles ' . (int) $u );
	$rw_ok( 0 === $r->return_code && false !== strpos( $r->stdout, $c1 ), 'wp rolegate user roles' );
	$r = $run( 'rolegate user unassign ' . (int) $u . ' ' . $c1 );
	$rw_ok( 0 === $r->return_code && ! in_array( $c1, get_userdata( $u )->roles, true ), 'wp rolegate user unassign' );
	$r = $run( 'rolegate role delete ' . $c2 . ' --yes' );
	$rw_ok( 0 === $r->return_code && null === get_role( $c2 ), 'wp rolegate role delete' );
	$r = $run( 'rolegate role delete administrator --yes' );
	$rw_ok( 0 !== $r->return_code && ! empty( get_role( 'administrator' ) ), 'wp rolegate role delete refuses administrator' );
	get_role( 'editor' )->add_cap( 'rw_junk2_' . $sfx );
	$r = $run( 'rolegate role reset editor --yes' );
	$rw_ok( 0 === $r->return_code && empty( $role_caps( 'editor' )[ 'rw_junk2_' . $sfx ] ), 'wp rolegate role reset' );
	$file = sys_get_temp_dir() . '/rw-auto-' . $sfx . '.json';
	$r    = $run( 'rolegate export --roles=' . $c1 . ' --file=' . $file );
	$rw_ok( 0 === $r->return_code && is_file( $file ) && isset( json_decode( (string) file_get_contents( $file ), true )['roles'][ $c1 ] ), 'wp rolegate export' );
	$exp = json_decode( (string) file_get_contents( $file ), true );
	$exp['roles'][ $c1 ]['capabilities']['upload_files'] = true;
	file_put_contents( $file, wp_json_encode( $exp ) );
	$r = $run( 'rolegate import ' . $file . ' --dry-run' );
	$rw_ok( 0 === $r->return_code && false !== strpos( $r->stdout, 'overwrite' ) && empty( $role_caps( $c1 )['upload_files'] ), 'wp rolegate import --dry-run writes nothing' );
	$r = $run( 'rolegate import ' . $file . ' --yes' );
	$rw_ok( 0 === $r->return_code && ! empty( $role_caps( $c1 )['upload_files'] ), 'wp rolegate import' );
	@unlink( $file ); // phpcs:ignore
	wp_set_current_user( $mgr );
	$r = $run( 'rolegate cap add ' . $c1 . ' manage_options' );
	$rw_ok( 0 !== $r->return_code && empty( $role_caps( $c1 )['manage_options'] ), 'CLI as a named user can\'t escalate' );
	wp_set_current_user( $u );
	$r = $run( 'rolegate role list' );
	$rw_ok( 0 !== $r->return_code, 'CLI as a named user without Role Gatekeeper caps is refused' );
	wp_set_current_user( $admin );
} else {
	echo "SKIP wp-cli tests (not running under WP-CLI)\n";
}

// REST.
wp_set_current_user( $admin );
$server                  = new WP_REST_Server();
$GLOBALS['wp_rest_server'] = $server;
add_action( 'rest_api_init', array( new Rest_Routes(), 'register' ) );
do_action( 'rest_api_init', $server );
$call = function ( $method, $route, $params = array() ) use ( $server ) {
	$req = new WP_REST_Request( $method, '/rolegate/v1' . $route );
	foreach ( $params as $k => $v ) {
		$req->set_param( $k, $v );
	}
	return $server->dispatch( $req );
};
$status = function ( $r ) {
	return $r->get_status();
};
$r = $call( 'GET', '/roles' );
$rw_ok( 200 === $status( $r ) && count( $r->get_data() ) >= 5, 'REST GET /roles' );
$r = $call( 'GET', '/roles/editor' );
$rw_ok( 200 === $status( $r ) && ! empty( $r->get_data()['capabilities']['edit_others_posts'] ), 'REST GET /roles/editor' );
$rw_ok( 404 === $status( $call( 'GET', '/roles/nope_' . $sfx ) ), 'REST unknown role is 404' );
$r = $call( 'GET', '/caps' );
$rw_ok( 200 === $status( $r ) && isset( $r->get_data()['read'] ), 'REST GET /caps' );
$r = $call( 'GET', '/users/' . $u . '/caps' );
$rw_ok( 200 === $status( $r ) && in_array( 'read', $r->get_data()['capabilities'], true ), 'REST GET /users/<id>/caps effective caps' );
$r = $call( 'POST', '/roles', array( 'name' => 'REST Role' ) );
$rw_ok( 403 === $status( $r ) && 'rolegate_read_only' === $r->as_error()->get_error_code(), 'REST writes are refused by default, even for an administrator' );
$rw_ok( 403 === $status( $call( 'POST', '/roles/' . $a . '/caps', array( 'add' => array( 'read' ) ) ) ) && 403 === $status( $call( 'POST', '/users/' . $u . '/roles', array( 'assign' => array( $a ) ) ) ) && 403 === $status( $call( 'DELETE', '/roles/' . $a ) ), 'every REST write route is read-only by default' );
wp_set_current_user( $u );
$rw_ok( in_array( $status( $call( 'GET', '/roles' ) ), array( 401, 403 ), true ), 'REST read needs the Role Gatekeeper capability' );
wp_set_current_user( 0 );
$rw_ok( in_array( $status( $call( 'GET', '/roles' ) ), array( 401, 403 ), true ), 'REST read refuses anonymous callers' );

update_option( Automation_Module::OPTION_SETTINGS, array( 'rest_writes' => true, 'abilities_writes' => false ) );
wp_set_current_user( $admin );
$rest_slug = 'rw_auto_rest_' . $sfx;
$roles[]   = $rest_slug;
$r         = $call( 'POST', '/roles', array( 'name' => 'REST Role', 'slug' => $rest_slug, 'capabilities' => array( 'read' ) ) );
$rw_ok( 201 === $status( $r ) && $rest_slug === $r->get_data()['slug'], 'REST POST /roles creates a role once writes are on' );
$r = $call( 'POST', '/roles/' . $rest_slug . '/caps', array( 'add' => array( 'edit_posts' ) ) );
$rw_ok( 200 === $status( $r ) && ! empty( $role_caps( $rest_slug )['edit_posts'] ), 'REST POST /roles/<slug>/caps adds a cap' );
$r = $call( 'POST', '/roles/' . $rest_slug . '/caps', array( 'add' => array( 'manage_options' ) ) );
$rw_ok( 409 === $status( $r ) && empty( $role_caps( $rest_slug )['manage_options'] ), 'REST asks for confirm before a critical cap' );
$r = $call( 'POST', '/roles/' . $rest_slug . '/caps', array( 'add' => array( 'manage_options' ), 'confirm' => true ) );
$rw_ok( 200 === $status( $r ) && ! empty( $role_caps( $rest_slug )['manage_options'] ), 'REST applies a critical cap with confirm' );
$r = $call( 'POST', '/users/' . $u . '/roles', array( 'assign' => array( $rest_slug ) ) );
$rw_ok( 409 === $status( $r ), 'REST asks for confirm before assigning a role that holds critical caps' );
$r = $call( 'POST', '/users/' . $u . '/roles', array( 'assign' => array( $a ) ) );
$rw_ok( 200 === $status( $r ) && in_array( $a, get_userdata( $u )->roles, true ), 'REST POST /users/<id>/roles assigns a role' );
$r = $call( 'POST', '/users/' . $u . '/roles', array( 'unassign' => array( $a ) ) );
$rw_ok( 200 === $status( $r ) && ! in_array( $a, get_userdata( $u )->roles, true ), 'REST unassigns a role' );
$r = $call( 'DELETE', '/roles/administrator', array( 'confirm' => true ) );
$rw_ok( 403 === $status( $r ) && ! empty( get_role( 'administrator' ) ), 'REST can\'t delete administrator even with confirm' );
$r = $call( 'DELETE', '/roles/' . $rest_slug );
$rw_ok( 409 === $status( $r ), 'REST asks for confirm before deleting a role that holds critical caps' );
$r = $call( 'DELETE', '/roles/' . $rest_slug, array( 'confirm' => true ) );
$rw_ok( 200 === $status( $r ) && null === get_role( $rest_slug ), 'REST DELETE /roles/<slug> with confirm' );

wp_set_current_user( $mgr );
$r = $call( 'POST', '/roles/' . $a . '/caps', array( 'add' => array( 'manage_options' ), 'confirm' => true ) );
$rw_ok( 403 === $status( $r ) && empty( $role_caps( $a )['manage_options'] ), 'REST write by a limited user can\'t escalate, even with confirm' );
$r = $call( 'POST', '/roles/' . $mgr_slug . '/caps', array( 'remove' => array( Caps::MANAGE ), 'confirm' => true ) );
$rw_ok( 403 === $status( $r ) && ! empty( $role_caps( $mgr_slug )[ Caps::MANAGE ] ), 'REST write that would lock the caller out is refused' );
wp_set_current_user( $u );
$rw_ok( in_array( $status( $call( 'POST', '/roles', array( 'name' => 'x' ) ) ), array( 401, 403 ), true ), 'REST write by a user without the cap is refused' );
wp_set_current_user( $admin );

// Abilities API.
if ( function_exists( 'wp_register_ability' ) && function_exists( 'wp_get_ability' ) ) {
	$register = function () {
		global $wp_filter;
		$saved = array(
			'wp_abilities_api_categories_init' => $wp_filter['wp_abilities_api_categories_init'] ?? null,
			'wp_abilities_api_init'            => $wp_filter['wp_abilities_api_init'] ?? null,
		);
		unset( $wp_filter['wp_abilities_api_categories_init'], $wp_filter['wp_abilities_api_init'] );
		$abilities = new Abilities();
		add_action( 'wp_abilities_api_categories_init', array( $abilities, 'register_category' ) );
		add_action( 'wp_abilities_api_init', array( $abilities, 'register' ) );
		$before = error_reporting( 0 );
		do_action( 'wp_abilities_api_categories_init' );
		do_action( 'wp_abilities_api_init' );
		error_reporting( $before );
		foreach ( $saved as $hook => $obj ) {
			if ( null === $obj ) {
				unset( $wp_filter[ $hook ] );
			} else {
				$wp_filter[ $hook ] = $obj;
			}
		}
	};
	$names = array( 'list-roles', 'get-role', 'list-capabilities', 'get-user-capabilities', 'add-role-capability', 'remove-role-capability', 'assign-user-role', 'unassign-user-role', 'delete-role' );
	$has   = function ( $n ) {
		return wp_has_ability( 'rolegate/' . $n );
	};
	$clear = function () use ( $names, $has ) {
		foreach ( $names as $n ) {
			if ( $has( $n ) ) {
				wp_unregister_ability( 'rolegate/' . $n );
			}
		}
	};
	$clear();
	delete_option( Automation_Module::OPTION_SETTINGS );
	$register();
	$list = wp_get_ability( 'rolegate/list-roles' );
	$rw_ok( $list && ! $has( 'add-role-capability' ) && ! $has( 'delete-role' ), 'abilities: only read abilities are registered by default' );
	$res = $list ? $list->execute() : null;
	$rw_ok( is_array( $res ) && count( $res['roles'] ) >= 5, 'abilities: list-roles runs for an administrator' );
	$get = wp_get_ability( 'rolegate/get-user-capabilities' );
	$res = $get ? $get->execute( array( 'user' => $u ) ) : null;
	$rw_ok( is_array( $res ) && in_array( 'read', $res['capabilities'], true ), 'abilities: get-user-capabilities' );
	wp_set_current_user( $u );
	$res = $list ? $list->execute() : null;
	$rw_ok( is_wp_error( $res ), 'abilities: a user without the cap can\'t run list-roles' );
	wp_set_current_user( $admin );
	$meta = $list ? $list->get_meta() : array();
	$rw_ok( ! empty( $meta['annotations']['readonly'] ), 'abilities: read abilities are marked read-only' );

	$clear();
	update_option( Automation_Module::OPTION_SETTINGS, array( 'rest_writes' => false, 'abilities_writes' => true ) );
	$register();
	$add = wp_get_ability( 'rolegate/add-role-capability' );
	$rw_ok( $add && $has( 'delete-role' ), 'abilities: write abilities appear when the setting allows' );
	$res = $add->execute( array( 'role' => $a, 'capability' => 'upload_files' ) );
	$rw_ok( ! is_wp_error( $res ) && ! empty( $role_caps( $a )['upload_files'] ), 'abilities: a harmless change runs without confirm' );
	$res = $add->execute( array( 'role' => $a, 'capability' => 'manage_options' ) );
	$rw_ok( 'rolegate_confirm_required' === $code( $res ) && empty( $role_caps( $a )['manage_options'] ), 'abilities: a risky change is refused without confirm' );
	$res = $add->execute( array( 'role' => $a, 'capability' => 'manage_options', 'confirm' => true ) );
	$rw_ok( ! is_wp_error( $res ) && ! empty( $role_caps( $a )['manage_options'] ), 'abilities: a risky change runs with confirm' );
	$rem = wp_get_ability( 'rolegate/remove-role-capability' );
	$res = $rem->execute( array( 'role' => 'administrator', 'capability' => Caps::MANAGE, 'confirm' => true ) );
	$rw_ok( 'rolegate_protected_role' === $code( $res ) && ! empty( $role_caps( 'administrator' )[ Caps::MANAGE ] ), 'abilities: confirm does not override the lockout and protection rules' );
	wp_set_current_user( $mgr );
	$res = $add->execute( array( 'role' => $a, 'capability' => 'edit_users', 'confirm' => true ) );
	$rw_ok( is_wp_error( $res ) && empty( $role_caps( $a )['edit_users'] ), 'abilities: a limited caller can\'t escalate through an ability' );
	$res = $rem->execute( array( 'role' => $mgr_slug, 'capability' => Caps::MANAGE, 'confirm' => true ) );
	$rw_ok( in_array( $code( $res ), $own_role_codes, true ), 'abilities: a lockout is refused' );
	wp_set_current_user( $admin );
	$clear();
} else {
	echo "SKIP abilities tests (Abilities API not available)\n";
}

// Role changes need WordPress's promote_user check and can't remove the last active administrator.
$np_slug = 'rw_auto_np_' . $sfx;
$roles[] = $np_slug;
add_role( $np_slug, 'Auto No Promote', array( 'read' => true, Caps::MANAGE_USERS => true ) );
$np     = $make( 'rw_auto_np', $np_slug );
$np_vic = $make( 'rw_auto_npvic', 'subscriber' );
$rw_ok( ! user_can( $np, 'promote_user', $np_vic ), 'promote setup: the manager can\'t promote users' );
$rw_ok( 'rolegate_cannot_promote' === $code( Ops::assign_role( $np, $np_vic, 'author' ) ) && ! in_array( 'author', get_userdata( $np_vic )->roles, true ), 'assign_role: refused without promote_user' );
$rw_ok( 'rolegate_cannot_promote' === $code( Ops::unassign_role( $np, $np_vic, 'subscriber' ) ) && in_array( 'subscriber', get_userdata( $np_vic )->roles, true ), 'unassign_role: refused without promote_user' );
$rw_ok( true === Ops::assign_role( 0, $np_vic, 'author' ), 'promote control: the shell actor is unaffected' );
update_option( Automation_Module::OPTION_SETTINGS, array( 'rest_writes' => true, 'abilities_writes' => false ) );
wp_set_current_user( $np );
$r = $call( 'POST', '/users/' . $np_vic . '/roles', array( 'unassign' => array( 'author' ) ) );
$rw_ok( 403 === $status( $r ) && in_array( 'author', get_userdata( $np_vic )->roles, true ), 'REST users/<id>/roles: refused without promote_user' );
wp_set_current_user( $admin );

$la_keep  = 'rw_auto_keep_' . $sfx;
$roles[]  = $la_keep;
add_role( $la_keep, 'Auto Keeper', array( 'read' => true, Caps::MANAGE => true, Caps::MANAGE_USERS => true, 'promote_users' => true ) );
$la_admin = $make( 'rw_auto_la', 'administrator' );
get_userdata( $la_admin )->add_role( $la_keep );
$la_other = array_values( array_diff( array_map( 'intval', get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) ) ), array( $la_admin ) ) );
\Rolegate\Modules\Safety\Enforcer::as_system(
	function () use ( $la_other, $la_keep ) {
		foreach ( $la_other as $id ) {
			$u = get_userdata( $id );
			$u->add_role( 'subscriber' );
			$u->remove_role( 'administrator' );
		}
	}
);
$rw_ok( array( $la_admin ) === array_map( 'intval', get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) ) ), 'last admin setup: one administrator' );
wp_set_current_user( $la_admin );
$rw_ok( 'rolegate_last_admin' === $code( Ops::unassign_role( $la_admin, $la_admin, 'administrator' ) ) && in_array( 'administrator', get_userdata( $la_admin )->roles, true ), 'unassign_role: the last administrator keeps the role' );
$r = $call( 'POST', '/users/' . $la_admin . '/roles', array( 'unassign' => array( 'administrator' ), 'confirm' => true ) );
$rw_ok( 400 === $status( $r ) && in_array( 'administrator', get_userdata( $la_admin )->roles, true ), 'REST users/<id>/roles: the last administrator keeps the role' );
$rw_ok( 'rolegate_last_admin' === $code( Ops::unassign_role( 0, $la_admin, 'administrator' ) ), 'unassign_role: the shell can\'t remove the last administrator either' );
$la_dis = $make( 'rw_auto_ladis', 'administrator' );
\Rolegate\Modules\Disabled_Users\Accounts::write( $la_dis, true );
$rw_ok( 'rolegate_last_admin' === $code( Ops::unassign_role( 0, $la_admin, 'administrator' ) ), 'unassign_role: a disabled administrator doesn\'t count as a second one' );
\Rolegate\Modules\Disabled_Users\Accounts::write( $la_dis, false );
$rw_ok( true === Ops::unassign_role( 0, $la_admin, 'administrator' ), 'last admin control: allowed once an active second administrator exists' );
wp_set_current_user( $admin );
\Rolegate\Modules\Safety\Enforcer::as_system(
	function () use ( $la_other ) {
		foreach ( $la_other as $id ) {
			$u = get_userdata( $id );
			$u->add_role( 'administrator' );
			$u->remove_role( 'subscriber' );
		}
	}
);
delete_option( Automation_Module::OPTION_SETTINGS );

// Cleanup.
delete_option( Automation_Module::OPTION_SETTINGS );
foreach ( $users as $id ) {
	is_multisite() ? wpmu_delete_user( $id ) : wp_delete_user( $id );
}
foreach ( $roles as $r ) {
	remove_role( $r );
}
get_role( 'editor' )->remove_cap( 'rw_junk_' . $sfx );
get_role( 'editor' )->remove_cap( 'rw_junk2_' . $sfx );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
exit( $rw_fail ? 1 : 0 );
