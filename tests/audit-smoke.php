<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/audit-smoke.php
 */

use Rolegate\Modules\Audit\Audit_Module;
use Rolegate\Modules\Audit\Audit_Page;
use Rolegate\Modules\Audit\Diff;
use Rolegate\Modules\Audit\Permissions;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Safety\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
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
$count = function ( $where = '1=1' ) use ( $wpdb ) {
	return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Store::table() . ' WHERE ' . $where ); // phpcs:ignore
};
$last = function () use ( $wpdb ) {
	return $wpdb->get_row( 'SELECT * FROM ' . Store::table() . ' ORDER BY id DESC LIMIT 1' ); // phpcs:ignore
};

$admin = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
$admin = (int) $admin[0];
wp_set_current_user( $admin );
// The revert fixtures use site-level managers; on multisite those need site admin access on.
add_filter( 'rolegate_multisite_site_admin_access', '__return_true' );

// Schema.
$rw_ok( Store::SCHEMA_VERSION === get_option( Store::OPTION_SCHEMA ), 'schema version option set' );
$rw_ok( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', Store::table() ) ) === Store::table(), 'audit table exists' );
$cols = $wpdb->get_col( 'DESC ' . Store::table() ); // phpcs:ignore
$rw_ok( array() === array_intersect( $cols, array( 'ip', 'email', 'user_login', 'user_agent' ) ), 'table has no raw IP, email or user agent column' );
update_option( Store::OPTION_SCHEMA, '0' );
$wpdb->query( 'DROP TABLE ' . Store::table() ); // phpcs:ignore
Store::maybe_upgrade();
$rw_ok( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', Store::table() ) ) === Store::table() && Store::SCHEMA_VERSION === get_option( Store::OPTION_SCHEMA ), 'maybe_upgrade recreates the table when the schema version differs' );
$rw_ok( false !== wp_next_scheduled( Store::CRON_HOOK ) || ( Store::schedule() || false !== wp_next_scheduled( Store::CRON_HOOK ) ), 'daily prune cron is scheduled' );
$rw_ok( 180 === Audit_Module::settings()['retention_days'], 'default retention is 180 days' );

// Recording.
$wpdb->query( 'TRUNCATE TABLE ' . Store::table() ); // phpcs:ignore
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
do_action(
	'rolegate_changed',
	'caps.updated',
	array(
		'actor'  => $admin,
		'target' => 'editor',
		'before' => array( 'caps' => array( 'read' => true, 'edit_posts' => true ) ),
		'after'  => array( 'caps' => array( 'read' => true, 'moderate_comments' => true, 'edit_posts' => false ) ),
	)
);
$row  = $last();
$diff = json_decode( $row->diff, true );
$rw_ok( 'caps.updated' === $row->type && 'editor' === $row->target && (int) $row->actor_id === $admin, 'caps.updated recorded with type, target and actor' );
$rw_ok( array( 'moderate_comments' ) === $diff['caps']['added'] && array( 'edit_posts' ) === $diff['caps']['removed'] && array( 'edit_posts' ) === $diff['caps']['denied'], 'diff holds added, removed and denied cap names' );
$rw_ok( 64 === strlen( $row->ip_hash ) && false === strpos( wp_json_encode( $row ), '203.0.113.9' ), 'IP stored only as a 64 char hash' );
$rw_ok( hash_hmac( 'sha256', '203.0.113.9', wp_salt( 'auth' ) ) === $row->ip_hash, 'IP hash uses the site salt' );
$rw_ok( '[]' === $row->detail || '{}' === $row->detail || is_array( json_decode( $row->detail, true ) ), 'detail is structured data only' );

do_action( 'rolegate_changed', 'user.roles', array( 'actor' => $admin, 'target' => 5, 'before' => array( 'roles' => array( 'editor' ) ), 'after' => array( 'roles' => array( 'editor', 'author' ) ) ) );
$diff = json_decode( $last()->diff, true );
$rw_ok( array( 'author' ) === $diff['roles']['added'] && array() === $diff['roles']['removed'], 'user.roles records role slug diff' );

do_action( 'rolegate_escalation_blocked', 'user', 7, 9, array( 'manage_options' ) );
$row = $last();
$rw_ok( 'escalation.blocked' === $row->type && 7 === (int) $row->actor_id && '9' === $row->target && array( 'manage_options' ) === json_decode( $row->diff, true )['caps']['added'], 'rolegate_escalation_blocked recorded' );
do_action( 'rolegate_rescue_used', 3 );
$row = $last();
$rw_ok( 'rescue.used' === $row->type && 3 === (int) $row->actor_id, 'rolegate_rescue_used recorded' );
unset( $_SERVER['REMOTE_ADDR'] );
do_action( 'rolegate_changed', 'Bad Type!', array( 'actor' => 1 ) );
$rw_ok( 'rescue.used' === $last()->type, 'malformed type is ignored' );

// Filters and pagination.
$wpdb->query( 'TRUNCATE TABLE ' . Store::table() ); // phpcs:ignore
for ( $i = 0; $i < 25; $i++ ) {
	do_action( 'rolegate_changed', 'caps.updated', array( 'actor' => 11, 'target' => 'r' . $i, 'before' => array(), 'after' => array( 'x' . $i ) ) );
}
do_action( 'rolegate_changed', 'role.created', array( 'actor' => 12, 'target' => 'solo', 'before' => array(), 'after' => array( 'name' => 'Solo', 'caps' => array( 'read' => true ) ) ) );
$page1 = Store::query( array(), 1, 20 );
$page2 = Store::query( array(), 2, 20 );
$rw_ok( 26 === $page1['total'] && 20 === count( $page1['rows'] ) && 6 === count( $page2['rows'] ), 'pagination: 26 rows split 20 + 6' );
$rw_ok( 1 === Store::query( array( 'actor' => 12 ), 1, 20 )['total'], 'filter by actor' );
$rw_ok( 1 === Store::query( array( 'type' => 'role.created' ), 1, 20 )['total'], 'filter by type' );
$wpdb->update( Store::table(), array( 'created_at' => '2020-01-15 10:00:00' ), array( 'target' => 'r0' ) );
$rw_ok( 1 === Store::query( array( 'from' => '2020-01-15', 'to' => '2020-01-15' ), 1, 20 )['total'] && 25 === Store::query( array( 'from' => '2020-01-16' ), 1, 50 )['total'], 'filter by date range' );

// Pruning.
update_option( Audit_Module::OPTION_SETTINGS, array( 'retention_days' => 30, 'delete_on_uninstall' => false ) );
$before = $count();
$gone   = Store::prune();
$rw_ok( 1 === $gone && $count() === $before - 1 && 0 === $count( "created_at < '2021-01-01'" ), 'prune removes only entries older than the retention window' );
update_option( Audit_Module::OPTION_SETTINGS, array( 'retention_days' => 0, 'delete_on_uninstall' => false ) );
$rw_ok( 1 === Audit_Module::settings()['retention_days'], 'retention is clamped to at least one day' );
delete_option( Audit_Module::OPTION_SETTINGS );
$wpdb->query( 'TRUNCATE TABLE ' . Store::table() ); // phpcs:ignore

// Diff helpers.
$d = Diff::caps( array( 'a' => true, 'b' => false ), array( 'a' => false, 'b' => true, 'c' => true ) );
$rw_ok( array( 'c', 'b' ) === $d['added'] || array( 'b', 'c' ) === $d['added'] || ( in_array( 'c', $d['added'], true ) && in_array( 'b', $d['added'], true ) ), 'Diff::caps lists granted names' );
$rw_ok( Diff::undo_caps( array( 'a' => false, 'b' => true, 'c' => true ), $d ) === array( 'a' => true, 'b' => false ), 'Diff::undo_caps restores the earlier set' );

// Reverts.
$logged = function ( $type ) use ( $wpdb ) {
	return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Store::table() . ' WHERE type = %s ORDER BY id DESC LIMIT 1', $type ) ); // phpcs:ignore
};

// role.created
$slug       = 'rw_audit_a_' . $sfx;
$roles[]    = $slug;
add_role( $slug, 'Audit A', array( 'read' => true, 'edit_posts' => true ) );
do_action( 'rolegate_changed', 'role.created', array( 'actor' => $admin, 'target' => $slug, 'before' => array(), 'after' => array( 'name' => 'Audit A', 'caps' => array( 'read' => true, 'edit_posts' => true ) ) ) );
$entry = $logged( 'role.created' );
$rw_ok( Reverter::can_revert_row( $entry ), 'role.created entry is revertible' );
$res = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( true === $res && null === get_role( $slug ), 'reverting role.created deletes the role' );
$rev = $logged( 'role.deleted' );
$rw_ok( $rev && (int) $rev->reverted_of === (int) $entry->id && (int) Store::get( (int) $entry->id )->reverted_by === (int) $rev->id, 'revert wrote its own audit entry and linked both rows' );
$res = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( is_wp_error( $res ) && 'rolegate_audit_already_reverted' === $res->get_error_code(), 'an entry can\'t be reverted twice' );

// role.deleted (revert the revert re-creates the role from the diff and label)
$res = Reverter::revert( (int) $rev->id, $admin );
$restored = get_role( $slug );
$rw_ok( true === $res && $restored && ! empty( $restored->capabilities['edit_posts'] ) && 'Audit A' === wp_roles()->role_names[ $slug ], 'reverting role.deleted restores the role with name and caps' );

// role.renamed
$roles_obj = wp_roles();
$roles_obj->roles[ $slug ]['name'] = 'Audit Renamed';
$roles_obj->role_names[ $slug ]    = 'Audit Renamed';
update_option( $roles_obj->role_key, $roles_obj->roles );
do_action( 'rolegate_changed', 'role.renamed', array( 'actor' => $admin, 'target' => $slug, 'before' => array( 'name' => 'Audit A' ), 'after' => array( 'name' => 'Audit Renamed' ) ) );
$res = Reverter::revert( (int) $logged( 'role.renamed' )->id, $admin );
$rw_ok( true === $res && 'Audit A' === wp_roles()->role_names[ $slug ], 'reverting role.renamed restores the old name' );

// caps.updated
get_role( $slug )->add_cap( 'moderate_comments' );
do_action( 'rolegate_changed', 'caps.updated', array( 'actor' => $admin, 'target' => $slug, 'before' => array( 'caps' => array( 'read' => true, 'edit_posts' => true ) ), 'after' => array( 'caps' => array( 'read' => true, 'edit_posts' => true, 'moderate_comments' => true ) ) ) );
$entry = $logged( 'caps.updated' );
$res   = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( true === $res && empty( get_role( $slug )->capabilities['moderate_comments'] ) && ! empty( get_role( $slug )->capabilities['edit_posts'] ), 'reverting caps.updated removes only the logged addition' );

// caps.updated: escalation refused (actor lacks the critical cap the revert would restore)
$mgr_slug = 'rw_audit_mgr_' . $sfx;
$roles[]  = $mgr_slug;
$mgr_caps = array( 'read' => true, 'list_users' => true, 'edit_users' => true, 'promote_users' => true, Caps::MANAGE => true, Caps::MANAGE_ROLES => true, Caps::MANAGE_CAPS => true, Caps::MANAGE_USERS => true, Caps::VIEW_AUDIT => true );
add_role( $mgr_slug, 'Audit Mgr', $mgr_caps );
$mgr = $make( 'rw_audit_mgr', $mgr_slug );
$rw_ok( user_can( $mgr, Caps::VIEW_AUDIT ), 'fixture: manager holds audit cap but not manage_options' );
do_action( 'rolegate_changed', 'caps.updated', array( 'actor' => $admin, 'target' => $slug, 'before' => array( 'caps' => array( 'read' => true, 'edit_posts' => true, 'manage_options' => true ) ), 'after' => array( 'caps' => array( 'read' => true, 'edit_posts' => true ) ) ) );
$entry = $logged( 'caps.updated' );
wp_set_current_user( $mgr );
$res = Reverter::revert( (int) $entry->id, $mgr );
$rw_ok( is_wp_error( $res ) && 'rolegate_cap_not_held' === $res->get_error_code() && empty( get_role( $slug )->capabilities['manage_options'] ), 'revert refused when it would escalate (critical cap not held by actor)' );

// caps.updated: lockout refused
do_action( 'rolegate_changed', 'caps.updated', array( 'actor' => $admin, 'target' => $mgr_slug, 'before' => array( 'caps' => array( 'read' => true, Caps::MANAGE_ROLES => true, Caps::MANAGE_CAPS => true, Caps::VIEW_AUDIT => true ) ), 'after' => array( 'caps' => $mgr_caps ) ) );
$entry = $logged( 'caps.updated' );
$res   = Reverter::revert( (int) $entry->id, $mgr );
$rw_ok( is_wp_error( $res ) && in_array( $res->get_error_code(), \Rolegate\Core\Plugin::is_enabled( 'deny-hierarchy' ) ? array( 'rolegate_lockout', 'rolegate_role_above_position' ) : array( 'rolegate_lockout' ), true ) && ! empty( get_role( $mgr_slug )->capabilities[ Caps::MANAGE ] ), 'revert refused when it would lock the actor out (the hierarchy may refuse own-role edits first)' );

// no permission
$plain = $make( 'rw_audit_plain', 'editor' );
$res   = Reverter::revert( (int) $entry->id, $plain );
$rw_ok( is_wp_error( $res ) && 'rolegate_audit_forbidden' === $res->get_error_code(), 'revert refused for a user without the audit and manage caps' );
wp_set_current_user( $admin );

// user.roles
$u = $make( 'rw_audit_u', 'editor' );
( new WP_User( $u ) )->add_role( 'author' );
do_action( 'rolegate_changed', 'user.roles', array( 'actor' => $admin, 'target' => $u, 'before' => array( 'roles' => array( 'editor' ) ), 'after' => array( 'roles' => array( 'editor', 'author' ) ) ) );
$res = Reverter::revert( (int) $logged( 'user.roles' )->id, $admin );
$rw_ok( true === $res && array( 'editor' ) === array_values( get_userdata( $u )->roles ), 'reverting user.roles removes the added role' );
// user.roles escalation: restoring administrator on a user, by an actor who is not one
$u2 = $make( 'rw_audit_u2', 'editor' );
do_action( 'rolegate_changed', 'user.roles', array( 'actor' => $admin, 'target' => $u2, 'before' => array( 'roles' => array( 'administrator' ) ), 'after' => array( 'roles' => array( 'editor' ) ) ) );
$entry = $logged( 'user.roles' );
$mgr2  = $make( 'rw_audit_mgr2', $mgr_slug );
wp_set_current_user( $mgr2 );
$res = Reverter::revert( (int) $entry->id, $mgr2 );
$rw_ok( is_wp_error( $res ) && in_array( $res->get_error_code(), array( 'rolegate_cannot_assign', 'rolegate_user_above_actor' ), true ) && ! in_array( 'administrator', get_userdata( $u2 )->roles, true ), 'user.roles revert refused when it would hand out a role above the actor' );
wp_set_current_user( $admin );

// user.caps
$ud = new WP_User( $u );
$ud->add_cap( 'rw_audit_cap_' . $sfx );
do_action( 'rolegate_changed', 'user.caps', array( 'actor' => $admin, 'target' => $u, 'before' => array( 'caps' => array() ), 'after' => array( 'caps' => array( 'rw_audit_cap_' . $sfx => true ) ) ) );
$res = Reverter::revert( (int) $logged( 'user.caps' )->id, $admin );
$rw_ok( true === $res && empty( get_userdata( $u )->caps[ 'rw_audit_cap_' . $sfx ] ), 'reverting user.caps removes the per-user cap' );

// Reverts that would lift a deny or unmask a critical cap, by an actor without manage_options.
// The storage backstop is off here so the reverter's own checks are what refuses.
$rw_no_backstop = function () {
	return false;
};
add_filter( 'rolegate_storage_backstop', $rw_no_backstop );
$opts_slug = 'rw_audit_opts_' . $sfx;
$deny_slug = 'rw_audit_deny_' . $sfx;
$roles[]   = $opts_slug;
$roles[]   = $deny_slug;
add_role( $opts_slug, 'Audit Opts', array( 'read' => true, 'manage_options' => true ) );
add_role( $deny_slug, 'Audit Deny', array( 'read' => true, 'manage_options' => false ) );
$mgr3 = $make( 'rw_audit_mgr3', $mgr_slug );
$rw_ok( user_can( $mgr3, Caps::VIEW_AUDIT ) && user_can( $mgr3, Caps::MANAGE_USERS ) && ! user_can( $mgr3, 'manage_options' ), 'fixture: manager holds audit and user caps but not manage_options' );

$t1 = $make( 'rw_audit_t1', $opts_slug );
( new WP_User( $t1 ) )->add_cap( 'manage_options', false );
clean_user_cache( $t1 );
$rw_ok( ! user_can( $t1, 'manage_options' ), 'fixture: per-user deny masks manage_options' );
do_action( 'rolegate_changed', 'user.caps', array( 'actor' => $admin, 'target' => $t1, 'before' => array( 'caps' => array() ), 'after' => array( 'caps' => array( 'manage_options' => false ) ) ) );
$entry = $logged( 'user.caps' );
wp_set_current_user( $mgr3 );
$res = Reverter::revert( (int) $entry->id, $mgr3 );
wp_set_current_user( $admin );
clean_user_cache( $t1 );
// On multisite core already refuses edit_user to a site admin, so the code differs there.
$rw_t1_code = is_multisite() ? array( 'rolegate_cap_not_held', 'rolegate_user_above_actor' ) : array( 'rolegate_cap_not_held' );
$rw_ok( is_wp_error( $res ) && in_array( $res->get_error_code(), $rw_t1_code, true ) && ! user_can( $t1, 'manage_options' ) && array_key_exists( 'manage_options', get_userdata( $t1 )->caps ), 'user.caps revert refused when it would lift a per-user deny on manage_options' );

$t2 = $make( 'rw_audit_t2', 'subscriber' );
( new WP_User( $t2 ) )->add_cap( 'manage_options', false );
do_action( 'rolegate_changed', 'user.caps', array( 'actor' => $admin, 'target' => $t2, 'before' => array( 'caps' => array( 'manage_options' => true ) ), 'after' => array( 'caps' => array( 'manage_options' => false ) ) ) );
$entry = $logged( 'user.caps' );
wp_set_current_user( $mgr3 );
$res = Reverter::revert( (int) $entry->id, $mgr3 );
wp_set_current_user( $admin );
clean_user_cache( $t2 );
$rw_ok( is_wp_error( $res ) && ! user_can( $t2, 'manage_options' ), 'user.caps revert refused when it would flip a per-user deny on manage_options to a grant' );

$t3 = $make( 'rw_audit_t3', $opts_slug );
( new WP_User( $t3 ) )->add_role( $deny_slug );
clean_user_cache( $t3 );
$rw_ok( ! user_can( $t3, 'manage_options' ), 'fixture: a second role\'s deny masks manage_options' );
do_action( 'rolegate_changed', 'user.roles', array( 'actor' => $admin, 'target' => $t3, 'before' => array( 'roles' => array( $opts_slug ) ), 'after' => array( 'roles' => array( $opts_slug, $deny_slug ) ) ) );
$entry = $logged( 'user.roles' );
wp_set_current_user( $mgr3 );
$res = Reverter::revert( (int) $entry->id, $mgr3 );
wp_set_current_user( $admin );
clean_user_cache( $t3 );
$rw_ok( is_wp_error( $res ) && 'rolegate_user_above_actor' === $res->get_error_code() && ! user_can( $t3, 'manage_options' ) && in_array( $deny_slug, get_userdata( $t3 )->roles, true ), 'user.roles revert refused when removing a role would unmask manage_options' );

$t4 = $make( 'rw_audit_t4', 'subscriber' );
do_action( 'rolegate_changed', 'user.roles', array( 'actor' => $admin, 'target' => $t4, 'before' => array( 'roles' => array( 'subscriber', $opts_slug ) ), 'after' => array( 'roles' => array( 'subscriber' ) ) ) );
$entry = $logged( 'user.roles' );
wp_set_current_user( $mgr3 );
$res = Reverter::revert( (int) $entry->id, $mgr3 );
wp_set_current_user( $admin );
clean_user_cache( $t4 );
$rw_ok( is_wp_error( $res ) && ! user_can( $t4, 'manage_options' ), 'user.roles revert refused when it would restore an admin-level role' );

do_action( 'rolegate_changed', 'caps.updated', array( 'actor' => $admin, 'target' => $deny_slug, 'before' => array( 'caps' => array( 'read' => true ) ), 'after' => array( 'caps' => array( 'read' => true, 'manage_options' => false ) ) ) );
$entry = $logged( 'caps.updated' );
wp_set_current_user( $mgr3 );
$res = Reverter::revert( (int) $entry->id, $mgr3 );
wp_set_current_user( $admin );
$rw_ok( is_wp_error( $res ) && 'rolegate_cap_not_held' === $res->get_error_code() && array_key_exists( 'manage_options', get_role( $deny_slug )->capabilities ), 'caps.updated revert refused when it would lift a role deny on manage_options' );

$res = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( true === $res && ! array_key_exists( 'manage_options', get_role( $deny_slug )->capabilities ), 'an administrator can still revert the role deny' );
remove_filter( 'rolegate_storage_backstop', $rw_no_backstop );

// roles.reset, role.default_set, caps.options_updated, access.updated
$ed_before = wp_roles()->roles['editor']['capabilities'];
$ed_after  = $ed_before;
unset( $ed_after['moderate_comments'] );
get_role( 'editor' )->remove_cap( 'moderate_comments' );
do_action( 'rolegate_changed', 'roles.reset', array( 'actor' => $admin, 'target' => 'core', 'before' => array( 'roles' => array( 'editor' => array( 'name' => 'Editor', 'caps' => $ed_before ) ) ), 'after' => array( 'roles' => array( 'editor' => array( 'name' => 'Editor', 'caps' => $ed_after ) ) ) ) );
$entry = $logged( 'roles.reset' );
$rw_ok( $entry && array( 'moderate_comments' ) === json_decode( $entry->diff, true )['role_caps']['editor']['removed'], 'roles.reset logged with a per-role cap diff' );
$res = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( true === $res && ! empty( get_role( 'editor' )->capabilities['moderate_comments'] ), 'reverting roles.reset restores the pre-reset caps' );

$lock_slug = 'rw_audit_lock_' . $sfx;
$roles[]   = $lock_slug;
add_role( $lock_slug, 'Lock', array( 'read' => true, Caps::MANAGE => true, Caps::VIEW_AUDIT => true, Caps::MANAGE_ROLES => true ) );
$lu = $make( 'rw_audit_lock', $lock_slug );
do_action( 'rolegate_changed', 'roles.reset', array( 'actor' => $admin, 'target' => 'core', 'before' => array( 'roles' => array( $lock_slug => array( 'name' => 'Lock', 'caps' => array( 'read' => true, Caps::VIEW_AUDIT => true, Caps::MANAGE_ROLES => true ) ) ) ), 'after' => array( 'roles' => array( $lock_slug => array( 'name' => 'Lock', 'caps' => array( 'read' => true, Caps::MANAGE => true, Caps::VIEW_AUDIT => true, Caps::MANAGE_ROLES => true ) ) ) ) ) );
$entry = $logged( 'roles.reset' );
wp_set_current_user( $lu );
$res = Reverter::revert( (int) $entry->id, $lu );
wp_set_current_user( $admin );
$rw_ok( is_wp_error( $res ) && ! empty( get_role( $lock_slug )->capabilities[ Caps::MANAGE ] ), 'roles.reset revert re-checks lockout and refuses' );

$def_before = get_option( 'default_role' );
do_action( 'rolegate_changed', 'role.default_set', array( 'actor' => $admin, 'target' => 'author', 'before' => array( 'default' => $def_before, 'extras' => array() ), 'after' => array( 'default' => 'author', 'extras' => array( 'contributor' ) ) ) );
update_option( 'default_role', 'author' );
update_option( 'rolegate_extra_default_roles', array( 'contributor' ), false );
$entry = $logged( 'role.default_set' );
$res   = Reverter::revert( (int) $entry->id, $admin );
$rw_ok( true === $res && get_option( 'default_role' ) === $def_before && array() === get_option( 'rolegate_extra_default_roles' ), 'reverting role.default_set restores default and extras' );
update_option( 'default_role', $def_before );
delete_option( 'rolegate_extra_default_roles' );
do_action( 'rolegate_changed', 'caps.options_updated', array( 'actor' => $admin, 'target' => 'options', 'before' => array( 'sets' => array() ), 'after' => array( 'sets' => array( 'x' ) ) ) );
do_action( 'rolegate_changed', 'access.updated', array( 'actor' => $admin, 'target' => 'edit-scope:settings', 'before' => array(), 'after' => array() ) );
$rw_ok( $logged( 'caps.options_updated' ) && 'options' === $logged( 'caps.options_updated' )->target && $logged( 'access.updated' ) && 'edit-scope:settings' === $logged( 'access.updated' )->target, 'caps.options_updated and access.updated are logged' );

// Module and automation settings changes are logged with what was switched on and off.
$mods_before = get_option( 'rolegate_modules' );
$mods_on     = array();
foreach ( \Rolegate\Core\Plugin::modules() as $m ) {
	if ( \Rolegate\Core\Plugin::is_enabled( $m->id() ) && 'login-redirects' !== $m->id() ) {
		$mods_on[] = $m->id();
	}
}
$mods_res = \Rolegate\Core\Settings::apply_modules( $admin, $mods_on );
$mods_row = $logged( 'modules.updated' );
$mods_d   = $mods_row ? json_decode( (string) $mods_row->diff, true ) : array();
$rw_ok( true === $mods_res && $mods_row && (int) $mods_row->actor_id === $admin && in_array( 'login-redirects', (array) ( $mods_d['settings']['disabled'] ?? array() ), true ), 'switching a module off is logged as modules.updated with the module listed' );
update_option( 'rolegate_modules', $mods_before, false );
$auto_before = get_option( \Rolegate\Modules\Automation\Automation_Module::OPTION_SETTINGS );
$auto_res    = \Rolegate\Modules\Automation\Automation_Page::apply(
	$admin,
	array(
		'rest_writes'      => empty( $auto_before['rest_writes'] ),
		'abilities_writes' => ! empty( $auto_before['abilities_writes'] ),
	)
);
$auto_row    = $logged( 'automation.updated' );
$auto_d      = $auto_row ? json_decode( (string) $auto_row->diff, true ) : array();
$rw_ok( true === $auto_res && $auto_row && ( in_array( 'rest_writes', (array) ( $auto_d['settings']['enabled'] ?? array() ), true ) || in_array( 'rest_writes', (array) ( $auto_d['settings']['disabled'] ?? array() ), true ) ), 'changing automation writes is logged as automation.updated' );
update_option( \Rolegate\Modules\Automation\Automation_Module::OPTION_SETTINGS, $auto_before, false );
$rw_ok( ! Reverter::can_revert_row( (object) array( 'type' => 'modules.updated', 'reverted_by' => 0 ) ), 'modules.updated is not revertible' );

// not revertible
$rw_ok( ! Reverter::can_revert_row( (object) array( 'type' => 'rescue.used', 'reverted_by' => 0 ) ), 'rescue.used is not revertible' );

// Permissions viewer.
$cap = 'rw_audit_view_' . $sfx;
get_role( $slug )->add_cap( $cap );
$holder = $make( 'rw_audit_holder', $slug );
$direct = $make( 'rw_audit_direct', 'subscriber' );
( new WP_User( $direct ) )->add_cap( $cap );
$data = Permissions::holders( $cap );
$by   = array();
foreach ( $data['users'] as $row ) {
	$by[ $row['id'] ] = $row;
}
$rw_ok( 1 === count( $data['roles'] ) && $slug === $data['roles'][0]['slug'] && 'granted' === $data['roles'][0]['state'], 'permissions viewer lists the role holding the cap' );
$rw_ok( isset( $by[ $holder ] ) && array( 'role:' . $slug ) === $by[ $holder ]['sources'] && $by[ $holder ]['effective'], 'permissions viewer: user holds it through a role' );
$rw_ok( isset( $by[ $direct ] ) && array( 'user' ) === $by[ $direct ]['sources'], 'permissions viewer: user holds it directly' );
$rw_ok( 2 === count( $data['users'] ), 'permissions viewer lists exactly the two holders' );
$rw_ok( array() === Permissions::holders( 'rw_nobody_has_this_' . $sfx )['users'], 'permissions viewer returns nothing for an unheld cap' );

// Admin page.
$wpdb->query( 'TRUNCATE TABLE ' . Store::table() ); // phpcs:ignore
do_action( 'rolegate_changed', 'role.created', array( 'actor' => $admin, 'target' => 'rw_page_' . $sfx, 'before' => array(), 'after' => array( 'name' => 'Page', 'caps' => array( 'read' => true ) ) ) );
$_GET = array( 'page' => 'role-gatekeeper-audit' );
ob_start();
( new Audit_Page() )->render();
$html = ob_get_clean();
$rw_ok( false !== strpos( $html, 'rw_page_' . $sfx ) && false !== strpos( $html, 'rolegate_audit_revert' ) && false !== strpos( $html, 'name="actor"' ), 'audit page renders the entry, filters and a revert form' );
$_GET = array( 'page' => 'role-gatekeeper-audit', 'actor' => '999999' );
ob_start();
( new Audit_Page() )->render();
$html = ob_get_clean();
$rw_ok( false !== strpos( $html, 'Nothing logged yet' ), 'an actor filter with no entries shows no rows' );
$_GET = array( 'page' => 'role-gatekeeper-audit', 'tab' => 'permissions', 'cap' => $cap );
ob_start();
( new Audit_Page() )->render();
$html = ob_get_clean();
$rw_ok( false !== strpos( $html, 'rw_audit_holder_' . $sfx ), 'permissions tab renders holders' );
$_GET = array();

wp_set_current_user( $plain );
$rw_ok( ! current_user_can( Caps::VIEW_AUDIT ), 'fixture: plain user lacks the audit cap' );
add_filter(
	'wp_die_handler',
	function () {
		return function () {
			throw new Exception( 'died' );
		};
	}
);
$_POST = array( 'entry' => '1' );
$died  = false;
try {
	( new Audit_Page() )->handle_revert();
} catch ( Exception $e ) {
	$died = 'died' === $e->getMessage();
}
$rw_ok( $died, 'revert handler refuses a user without the audit cap' );
wp_set_current_user( $admin );
$died = false;
try {
	( new Audit_Page() )->handle_revert();
} catch ( Exception $e ) {
	$died = 'died' === $e->getMessage();
}
$rw_ok( $died, 'revert handler refuses a request without a nonce' );
$_POST = array();

// Multisite: a new subsite gets its own table; a site without one creates it on the first write.
$rw_subs        = array();
$rw_has_table   = function ( $blog_id ) use ( $wpdb ) {
	$t = $wpdb->get_blog_prefix( $blog_id ) . 'rolegate_audit';
	return $t === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) );
};
if ( is_multisite() ) {
	$rw_net    = get_network();
	$rw_subs[] = wp_insert_site( array( 'domain' => $rw_net->domain, 'path' => '/rwaudit-a-' . $sfx . '/', 'user_id' => $admin ) );
	$rw_ok( is_int( $rw_subs[0] ) && $rw_has_table( $rw_subs[0] ), 'multisite: a new subsite gets its own audit table' );
	switch_to_blog( $rw_subs[0] );
	do_action( 'rolegate_changed', 'role.created', array( 'actor' => $admin, 'target' => 'rw_sub_' . $sfx, 'before' => array(), 'after' => array( 'name' => 'Sub', 'caps' => array( 'read' => true ) ) ) );
	$rw_row = $last();
	restore_current_blog();
	$rw_ok( $rw_row && 'rw_sub_' . $sfx === $rw_row->target, 'multisite: a change on the subsite lands in its log' );

	remove_action( 'wp_initialize_site', array( Store::class, 'on_initialize_site' ), 20 );
	$rw_subs[] = wp_insert_site( array( 'domain' => $rw_net->domain, 'path' => '/rwaudit-b-' . $sfx . '/', 'user_id' => $admin ) );
	add_action( 'wp_initialize_site', array( Store::class, 'on_initialize_site' ), 20 );
	$rw_ok( ! $rw_has_table( $rw_subs[1] ), 'fixture: second subsite has no audit table' );
	switch_to_blog( $rw_subs[1] );
	$wpdb->last_error = '';
	$rw_empty         = Store::query( array(), 1, 20 );
	$rw_ok( 0 === $rw_empty['total'] && null === Store::get( 1 ) && '' === $wpdb->last_error, 'multisite: reading a missing table returns nothing without a database error' );
	do_action( 'rolegate_changed', 'role.created', array( 'actor' => $admin, 'target' => 'rw_sub_b_' . $sfx, 'before' => array(), 'after' => array( 'name' => 'Sub B', 'caps' => array( 'read' => true ) ) ) );
	$rw_row = $last();
	$rw_err = $wpdb->last_error;
	restore_current_blog();
	$rw_ok( $rw_has_table( $rw_subs[1] ) && $rw_row && 'rw_sub_b_' . $sfx === $rw_row->target && '' === $rw_err, 'multisite: the first write creates the missing table and lands' );
}

// Uninstall.
wp_set_current_user( $admin );
update_option( Audit_Module::OPTION_SETTINGS, array( 'retention_days' => 180, 'delete_on_uninstall' => false ) );
include ROLEGATE_DIR . 'includes/modules/audit/uninstall.php';
$rw_ok( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', Store::table() ) ) === Store::table(), 'uninstall keeps the table when the setting is off' );
foreach ( $rw_subs as $rw_sub ) {
	switch_to_blog( $rw_sub );
	Store::install();
	restore_current_blog();
}
$rw_ok( ! $rw_subs || ( $rw_has_table( $rw_subs[0] ) && $rw_has_table( $rw_subs[1] ) ), 'fixture: every subsite has an audit table before uninstall' );
update_option( Audit_Module::OPTION_SETTINGS, array( 'retention_days' => 180, 'delete_on_uninstall' => true ) );
include ROLEGATE_DIR . 'includes/modules/audit/uninstall.php';
$rw_ok( null === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', Store::table() ) ), 'uninstall drops the table when the setting is on' );
if ( $rw_subs ) {
	$rw_ok( ! $rw_has_table( $rw_subs[0] ) && ! $rw_has_table( $rw_subs[1] ), 'multisite: uninstall drops the table on every subsite' );
	foreach ( $rw_subs as $rw_sub ) {
		wp_delete_site( $rw_sub );
	}
}

// Cleanup.
Store::install();
foreach ( $users as $id ) {
	wp_delete_user( $id );
}
foreach ( $roles as $r ) {
	remove_role( $r );
}
delete_option( Audit_Module::OPTION_SETTINGS );
$wpdb->query( 'TRUNCATE TABLE ' . Store::table() ); // phpcs:ignore

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
exit( $rw_fail ? 1 : 0 );
