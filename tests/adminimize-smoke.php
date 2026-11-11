<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/adminimize-smoke.php
 * Known-bad control: RW_BYPASS_MIGRATOR=1 skips the migrator calls, so every assertion about carried-over rules must fail.
 *
 * Seeds the option Adminimize keeps (mw_adminimize) and checks the dry run, apply, idempotence,
 * what is listed as not carried over, the guards that stop a wider or narrower result, and revert.
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Admin_Ui\Engine;
use Rolegate\Modules\Admin_Ui\Rules;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Portability\Backups;
use Rolegate\Modules\Portability\Migrator;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

if ( is_multisite() ) {
	add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );
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

$rw_bypass = (bool) getenv( 'RW_BYPASS_MIGRATOR' );
$rw_apply  = function ( $actor ) use ( $rw_bypass ) {
	return $rw_bypass ? array( 'status' => 'bypassed', 'errors' => array(), 'migration_id' => '', 'plan' => array() ) : Migrator::apply( 'adminimize', $actor );
};

$rw_sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users = array();
$rw_roles = array( 'rw_adm_ed', 'rw_adm_pre', 'rw_adm_allow', 'rw_adm_mgr', 'rw_adm_two' );
$rw_opts  = array( 'mw_adminimize', Rules::OPTION, Migrator::RECORDS, Backups::OPTION, Plugin::OPTION_MODULES );
$rw_saved = array();
foreach ( $rw_opts as $rw_o ) {
	$rw_saved[ $rw_o ] = get_option( $rw_o, null );
}
$rw_make = function ( $login, $role ) use ( &$rw_users, $rw_sfx ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_sfx,
			'user_email' => $login . '_' . $rw_sfx . '@example.com',
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
$rw_find = function ( array $rows, string $action, string $needle ) {
	foreach ( $rows as $row ) {
		if ( $row['action'] === $action && ( false !== strpos( $row['item'], $needle ) || false !== strpos( $row['detail'], $needle ) ) ) {
			return true;
		}
	}
	return false;
};

foreach ( $rw_roles as $rw_r ) {
	remove_role( $rw_r );
}
add_role( 'rw_adm_ed', 'Adm Editor', array( 'read' => true, 'edit_posts' => true ) );
add_role( 'rw_adm_pre', 'Adm Pre', array( 'read' => true ) );
add_role( 'rw_adm_allow', 'Adm Allow', array( 'read' => true ) );
add_role( 'rw_adm_mgr', 'Adm Manager', array( 'read' => true, \Rolegate\Modules\Safety\Caps::MANAGE_ROLES => true ) );
add_role( 'rw_adm_two', 'Adm Two', array( 'read' => true ) );

\Rolegate\Modules\Safety\Caps::grant_to_administrator();
$rw_admin = $rw_make( 'rw_adm_admin', 'administrator' );
if ( is_multisite() ) {
	grant_super_admin( $rw_admin );
}
$rw_ed_user = $rw_make( 'rw_adm_ed_user', 'rw_adm_ed' );
$rw_editor  = $rw_make( 'rw_adm_editor', 'editor' );

$rw_key = function ( $group, $role ) {
	return 'mw_adminimize_disabled_' . $group . '_' . $role . '_items';
};
$rw_seed = array(
	$rw_key( 'menu', 'rw_adm_ed' )                  => array( 'tools.php', 'edit-comments.php', 'profile.php', 'edit.php?post_type=page' ),
	$rw_key( 'submenu', 'rw_adm_ed' )               => array( 'options-general.php__3' ),
	$rw_key( 'dashboard_option', 'rw_adm_ed' )      => array( 'dashboard_quick_press', 'dashboard_primary', 'not an id!' ),
	$rw_key( 'admin_bar', 'rw_adm_ed' )             => array( 'wp-logo', 'comments', 'new-content', 'my-account' ),
	$rw_key( 'admin_bar_frontend', 'rw_adm_ed' )    => array( 'wp-logo', 'comments', 'search' ),
	$rw_key( 'global_option', 'rw_adm_ed' )         => array( '#wpfooter' ),
	$rw_key( 'metaboxes_post', 'rw_adm_ed' )        => array( '#titlediv' ),
	$rw_key( 'menu', 'rw_adm_pre' )                 => array( 'tools.php', 'upload.php' ),
	$rw_key( 'menu', 'rw_adm_allow' )               => array( 'tools.php' ),
	$rw_key( 'menu', 'rw_adm_mgr' )                 => array( 'tools.php' ),
	$rw_key( 'menu', 'administrator' )              => array( 'tools.php' ),
	$rw_key( 'menu', 'rw_adm_gone' )                => array( 'tools.php' ),
	$rw_key( 'menu', 'rw_adm_two' )                 => array(),
	'_mw_adminimize_footer'                         => 1,
	'mw_adminimize_dashboard_widgets'               => array( 'dashboard_primary' => array() ),
);
update_option( 'mw_adminimize', $rw_seed );
update_option(
	Rules::OPTION,
	array(
		'roles' => array(
			'rw_adm_pre'   => array( 'menu' => array( 'model' => 'deny', 'items' => array( 'upload.php' ) ) ),
			'rw_adm_allow' => array( 'menu' => array( 'model' => 'allow', 'items' => array( 'index.php' ) ) ),
		),
		'users' => array(),
	)
);
Rules::flush_cache();
delete_option( Migrator::RECORDS );
$rw_mods = (array) get_option( Plugin::OPTION_MODULES, array() );
update_option( Plugin::OPTION_MODULES, array_merge( $rw_mods, array( 'admin-ui' => true ) ) );

$rw_seeded = count( array_filter( array_keys( $rw_seed ), function ( $k ) {
	return 0 === strpos( $k, 'mw_adminimize_disabled_' );
} ) );
$rw_ok( 13 === $rw_seeded && 4 === count( $rw_seed[ $rw_key( 'menu', 'rw_adm_ed' ) ] ), 'input: ' . $rw_seeded . ' Adminimize role lists seeded, 4 menu items for the main role' );

$rw_state = function () {
	return md5( serialize( array( get_option( Rules::OPTION ), get_option( Migrator::RECORDS ), get_option( Backups::OPTION ), get_option( Plugin::OPTION_MODULES ), get_option( 'mw_adminimize' ) ) ) );
};
$rw_hidden = function ( $user_id ) {
	Rules::flush_cache();
	return Rules::effective_for_user( $user_id );
};

// Authority.
$rw_ok( is_wp_error( Migrator::plan( 'adminimize', $rw_editor ) ), 'authority: an editor cannot plan a migration' );
$rw_ok( is_wp_error( Migrator::apply( 'adminimize', $rw_editor ) ), 'authority: an editor cannot apply a migration' );
$rw_ok( ! is_wp_error( Migrator::plan( 'adminimize', 0 ) ), 'authority: the WP-CLI shell actor can plan' );
$rw_ok( null === $rw_hidden( $rw_ed_user ), 'control: the role hides nothing before the migration' );

// Dry run.
$rw_before = $rw_state();
$rw_plan   = Migrator::plan( 'adminimize', $rw_admin );
$rw_ok( ! is_wp_error( $rw_plan ) && $rw_plan['detected'] && count( $rw_plan['rows'] ) >= 10, 'dry run: Adminimize detected, ' . ( is_wp_error( $rw_plan ) ? 0 : count( $rw_plan['rows'] ) ) . ' rows' );
$rw_ok( $rw_before === $rw_state(), 'dry run: nothing written' );
$rw_rule = $rw_plan['ops']['access']['rw_adm_ed'] ?? array();
$rw_ok( array( 'tools.php', 'edit-comments.php', 'edit.php?post_type=page' ) === ( $rw_rule['menu']['items'] ?? null ), 'dry run: top-level menu items planned, profile.php left out' );
$rw_ok( array( 'dashboard_quick_press', 'dashboard_primary' ) === ( $rw_rule['metaboxes']['dashboard'] ?? null ), 'dry run: dashboard widgets planned, invalid id left out' );
$rw_ok( array( 'wp-logo', 'comments' ) === ( $rw_rule['admin_bar'] ?? null ), 'dry run: only toolbar items hidden in both places are planned' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'new-content' ) && $rw_find( $rw_plan['rows'], 'skip', 'search' ), 'dry run: toolbar items hidden in one place only are reported' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'profile.php' ), 'dry run: the profile page is reported as not hideable' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'not an id!' ), 'dry run: the invalid widget id is reported' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'Hidden submenu items' ), 'not migrated: submenu items listed' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'Hidden global options' ) && $rw_find( $rw_plan['rows'], 'skip', 'Hidden fields on the post' ), 'not migrated: global options and post screen fields listed' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', '_mw_adminimize_footer' ), 'not migrated: other settings listed by name' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'never restricts administrators' ), 'not migrated: administrator role listed' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', 'rw_adm_gone' ), 'not migrated: roles that no longer exist listed' );
$rw_ok( $rw_find( $rw_plan['rows'], 'blocked', 'rw_adm_mgr' ), 'dry run: a role that manages Role Gatekeeper is refused' );
$rw_ok( $rw_find( $rw_plan['rows'], 'conflict', 'rw_adm_allow' ), 'dry run: a role with a menu allow list is kept as it is' );
$rw_ok( ! isset( $rw_plan['ops']['access']['rw_adm_mgr'] ) && ! isset( $rw_plan['ops']['access']['rw_adm_allow'] ) && ! isset( $rw_plan['ops']['access']['administrator'] ) && ! isset( $rw_plan['ops']['access']['rw_adm_gone'] ), 'dry run: nothing planned for refused, kept, administrator or missing roles' );
$rw_ok( array( 'upload.php', 'tools.php' ) === ( $rw_plan['ops']['access']['rw_adm_pre']['menu']['items'] ?? null ), 'dry run: an existing rule keeps its items and gains the new one' );
$rw_ok( 2 === count( $rw_plan['ops']['access'] ?? array() ), 'dry run: two roles planned' );

// Apply.
$rw_backups0 = count( Backups::all() );
$rw_res      = $rw_apply( $rw_admin );
$rw_ok( ! is_wp_error( $rw_res ) && 'applied' === $rw_res['status'] && ! $rw_res['errors'], 'apply: applied without errors' . ( ! is_wp_error( $rw_res ) && ! empty( $rw_res['errors'] ) ? ' (' . implode( ' ', $rw_res['errors'] ) . ')' : '' ) );
$rw_eff = $rw_hidden( $rw_ed_user );
$rw_ok( null !== $rw_eff && array( 'tools.php', 'edit-comments.php', 'edit.php?post_type=page' ) === $rw_eff['menu_deny'], 'apply: menu items hidden for the role' );
$rw_ok( null !== $rw_eff && Engine::key_blocked( 'tools.php', null, $rw_eff, false ) && ! Engine::key_blocked( 'upload.php', null, $rw_eff, false ), 'apply: a hidden item is blocked and an unlisted one is not' );
$rw_ok( null !== $rw_eff && array( 'dashboard_quick_press', 'dashboard_primary' ) === ( $rw_eff['metaboxes']['dashboard'] ?? null ), 'apply: dashboard widgets hidden for the role' );
$rw_ok( null !== $rw_eff && array( 'wp-logo', 'comments' ) === $rw_eff['admin_bar'], 'apply: toolbar items hidden for the role' );
$rw_ok( null === $rw_hidden( $rw_editor ), 'apply: other roles are not restricted' );
$rw_ok( array( 'upload.php', 'tools.php' ) === Rules::get( 'role', 'rw_adm_pre' )['menu']['items'], 'apply: existing rule extended' );
$rw_ok( 'allow' === Rules::get( 'role', 'rw_adm_allow' )['menu']['model'] && array( 'index.php' ) === Rules::get( 'role', 'rw_adm_allow' )['menu']['items'], 'apply: allow-list role untouched' );
$rw_ok( empty( Rules::all()['roles']['rw_adm_mgr'] ) && empty( Rules::all()['roles']['administrator'] ), 'apply: manager and administrator roles have no rule' );
$rw_ok( $rw_seed === get_option( 'mw_adminimize' ), 'apply: Adminimize option untouched' );
$rw_ok( ! $rw_bypass && count( Backups::all() ) === min( $rw_backups0 + 1, Backups::KEEP ), 'apply: role backup taken' );
$rw_rec = $rw_res['migration_id'] ? Migrator::record( $rw_res['migration_id'] ) : null;
$rw_ok( $rw_rec && 2 === count( $rw_rec['access'] ), 'apply: two roles recorded' );

// Idempotence.
$rw_mid   = $rw_state();
$rw_again = $rw_apply( $rw_admin );
$rw_ok( ! $rw_bypass && ! is_wp_error( $rw_again ) && 'unchanged' === $rw_again['status'] && $rw_mid === $rw_state(), 'idempotent: second run changes nothing and says so' );

// Audit and revert.
$rw_audit = Plugin::is_enabled( 'audit' ) && Store::table_exists();
if ( $rw_audit ) {
	$rw_row = null;
	foreach ( Store::query( array( 'type' => 'migration.applied' ), 1, 20 )['rows'] as $r ) {
		$d = json_decode( (string) $r->detail, true );
		if ( $rw_res['migration_id'] && isset( $d['migration_id'] ) && $d['migration_id'] === $rw_res['migration_id'] ) {
			$rw_row = $r;
		}
	}
	$rw_ok( $rw_row && Reverter::can_revert_row( $rw_row ), 'audit: migration.applied logged and revertible' );
} else {
	echo "NOTE audit module off: skipping the audit-row assertion\n";
}

// A rule changed after the migration blocks the revert.
Rules::save( $rw_admin, 'role', 'rw_adm_pre', array( 'menu' => array( 'model' => 'deny', 'items' => array( 'upload.php', 'tools.php', 'plugins.php' ) ) ) );
$rw_blocked = $rw_res['migration_id'] ? Migrator::revert( $rw_res['migration_id'], $rw_admin ) : new WP_Error( 'x', 'bypassed' );
$rw_ok( is_wp_error( $rw_blocked ) && 'rolegate_migration_changed' === $rw_blocked->get_error_code() && null !== $rw_hidden( $rw_ed_user ), 'revert: refused, and nothing reverted, when a rule changed since' );
Rules::save( $rw_admin, 'role', 'rw_adm_pre', array( 'menu' => array( 'model' => 'deny', 'items' => array( 'upload.php', 'tools.php' ) ) ) );

$rw_rev = $rw_res['migration_id'] ? Migrator::revert( $rw_res['migration_id'], $rw_admin ) : new WP_Error( 'x', 'bypassed' );
$rw_ok( true === $rw_rev, 'revert: succeeded' . ( is_wp_error( $rw_rev ) ? ' (' . $rw_rev->get_error_message() . ')' : '' ) );
$rw_ok( null === $rw_hidden( $rw_ed_user ), 'revert: the role hides nothing again' );
$rw_ok( array( 'upload.php' ) === Rules::get( 'role', 'rw_adm_pre' )['menu']['items'], 'revert: only the item the migration added is removed' );
$rw_ok( array( 'index.php' ) === Rules::get( 'role', 'rw_adm_allow' )['menu']['items'], 'revert: allow-list role still untouched' );

// Flags that would hide more or block more are not migrated.
update_option( 'mw_adminimize', array_merge( $rw_seed, array( 'mw_adminimize_multiple_roles' => 1 ) ) );
$rw_multi = Migrator::plan( 'adminimize', $rw_admin );
$rw_ok( ! Migrator::has_changes( $rw_multi['ops'] ) && $rw_find( $rw_multi['rows'], 'skip', 'every role hides it' ), 'multiple roles: nothing carried over, reason shown' );
update_option( 'mw_adminimize', array_merge( $rw_seed, array( 'mw_adminimize_prevent_page_access' => 1 ) ) );
$rw_noblock = Migrator::plan( 'adminimize', $rw_admin );
$rw_ok( $rw_find( $rw_noblock['rows'], 'skip', 'only hides these items' ) && empty( $rw_noblock['ops']['access']['rw_adm_ed']['menu']['items'] ), 'page access left open: menu items not carried over' );
$rw_ok( array( 'dashboard_quick_press', 'dashboard_primary' ) === ( $rw_noblock['ops']['access']['rw_adm_ed']['metaboxes']['dashboard'] ?? null ), 'page access left open: dashboard widgets still carried over' );

// Not detected.
delete_option( 'mw_adminimize' );
$rw_none = Migrator::plan( 'adminimize', $rw_admin );
$rw_ok( ! $rw_none['detected'] && ! Migrator::has_changes( $rw_none['ops'] ), 'no Adminimize data: not detected, nothing to change' );

// Cleanup.
require_once ABSPATH . 'wp-admin/includes/user.php';
if ( is_multisite() ) {
	revoke_super_admin( $rw_admin );
}
foreach ( $rw_users as $rw_id ) {
	if ( is_multisite() ) {
		require_once ABSPATH . 'wp-admin/includes/ms.php';
		wpmu_delete_user( $rw_id );
	} else {
		wp_delete_user( $rw_id );
	}
}
foreach ( $rw_roles as $rw_r ) {
	remove_role( $rw_r );
}
foreach ( $rw_saved as $rw_o => $rw_v ) {
	if ( null === $rw_v ) {
		delete_option( $rw_o );
	} else {
		update_option( $rw_o, $rw_v );
	}
}
Rules::flush_cache();

echo "\n{$rw_pass} passed, {$rw_fail} failed\n";
if ( $rw_fail ) {
	exit( 1 );
}
