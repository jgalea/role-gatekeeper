<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/disable-user-login-smoke.php
 * Known-bad control: RW_BYPASS_MIGRATOR=1 skips the migrator's apply step, so the apply assertions must fail.
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Portability\Disable_User_Login_Migration;
use Rolegate\Modules\Portability\Disable_Users_Migration;
use Rolegate\Modules\Portability\Migrator;
use Rolegate\Modules\Safety\Caps;

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

if ( is_multisite() ) {
	echo "SKIP single-site test\n";
	exit( 0 );
}

const RW_DUL_META = '_is_disabled';

$rw_sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users = array();
$rw_make  = function ( $login, $role ) use ( &$rw_users, $rw_sfx ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_sfx,
			'user_email' => $login . '_' . $rw_sfx . '@example.com',
			'user_pass'  => 'Rw-' . $rw_sfx . '-pass!9',
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
$rw_find = function ( array $rows, $action, $needle ) {
	foreach ( $rows as $row ) {
		if ( $row['action'] === $action && ( false !== strpos( $row['item'], $needle ) || false !== strpos( $row['detail'], $needle ) ) ) {
			return true;
		}
	}
	return false;
};
$rw_apply = function ( $actor ) {
	if ( getenv( 'RW_BYPASS_MIGRATOR' ) ) {
		return array( 'status' => 'bypassed', 'errors' => array(), 'migration_id' => '' );
	}
	return Migrator::apply( 'disable-user-login', $actor );
};

$rw_orig_modules  = get_option( Plugin::OPTION_MODULES, null );
$rw_orig_records  = get_option( Migrator::RECORDS, null );
$rw_orig_settings = get_option( 'disable_user_login_settings', null );
$rw_pre_mgr       = Accounts::active_managers();
if ( ! get_current_user_id() ) {
	$rw_first = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
	wp_set_current_user( $rw_first ? (int) $rw_first[0] : 0 );
}

try {
	foreach ( $rw_pre_mgr as $rw_id ) {
		Accounts::write( $rw_id, true );
	}
	Caps::grant_to_administrator();
	$rw_map                   = Plugin::enabled_map();
	$rw_map['disabled-users'] = true;
	update_option( Plugin::OPTION_MODULES, $rw_map );

	$rw_a = $rw_make( 'rw_dul_a', 'administrator' );
	$rw_b = $rw_make( 'rw_dul_b', 'administrator' );
	$rw_ok( array( $rw_a, $rw_b ) === Accounts::active_managers(), 'setup: the two test administrators are the only active managers' );

	$rw_ok( in_array( 'disable-user-login', array_keys( Migrator::sources() ), true ), 'migration: Disable User Login is a registered source' );
	$rw_ok( Disable_User_Login_Migration::META === RW_DUL_META && 'disable-user-login/disable-user-login.php' === Disable_User_Login_Migration::PLUGIN, 'migration: source meta key and plugin file match the plugin\'s own' );

	$rw_none = Migrator::plan( 'disable-user-login', $rw_a );
	$rw_ok( ! is_wp_error( $rw_none ) && ! $rw_none['detected'] && ! Migrator::has_changes( $rw_none['ops'] ), 'migration plan: nothing detected when the plugin left no data' );

	$rw_m = array();
	foreach ( array( 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7' ) as $rw_k ) {
		$rw_m[ $rw_k ] = $rw_make( 'rw_dul_' . $rw_k, 'subscriber' );
	}
	foreach ( array( 'm1', 'm2', 'm3', 'm4', 'm5', 'm7' ) as $rw_k ) {
		update_user_meta( $rw_m[ $rw_k ], RW_DUL_META, 1 );
	}
	update_user_meta( $rw_m['m6'], RW_DUL_META, 0 );
	update_user_meta( $rw_a, RW_DUL_META, 1 );
	update_user_meta( $rw_m['m1'], 'ja_disable_user', '1' );
	update_option( 'disable_user_login_settings', array( 'disabled_message' => 'rw-marker-' . $rw_sfx ) );
	Accounts::write( $rw_m['m7'], true );

	$rw_flagged = array( $rw_m['m1'], $rw_m['m2'], $rw_m['m3'], $rw_m['m4'], $rw_m['m5'] );
	$rw_all     = array_merge( $rw_flagged, array( $rw_m['m7'], $rw_a ) );
	$rw_sorted  = $rw_all;
	sort( $rw_sorted );
	$rw_ok( 7 === count( $rw_sorted ) && 5 === count( $rw_flagged ), 'setup: 7 flagged users of which 5 are migratable (expected input size)' );
	$rw_ok( $rw_sorted === Disable_Users_Migration::flagged( RW_DUL_META ), 'migration: the 7 users with _is_disabled = 1 are found, and no others' );
	$rw_ok( ! in_array( $rw_m['m6'], Disable_Users_Migration::flagged( RW_DUL_META ), true ), 'migration: a user with _is_disabled = 0 is not flagged' );

	$rw_snap = function () use ( $rw_m, $rw_a, $rw_b ) {
		$out = array();
		foreach ( array_merge( array_values( $rw_m ), array( $rw_a, $rw_b ) ) as $id ) {
			clean_user_cache( $id );
			$out[ $id ] = array( get_user_meta( $id, 'rolegate_disabled', true ), get_user_meta( $id, RW_DUL_META, true ) );
		}
		return $out;
	};

	$rw_before = $rw_snap();
	$rw_plan   = Migrator::plan( 'disable-user-login', $rw_a );
	$rw_ok( ! is_wp_error( $rw_plan ) && $rw_plan['detected'] && 'Disable User Login' === $rw_plan['label'] && 'disable-user-login' === $rw_plan['source'], 'migration plan: detected' );
	$rw_ok( $rw_before === $rw_snap(), 'migration plan: nothing written' );
	$rw_ok( $rw_flagged === $rw_plan['ops']['users'], 'migration plan: the five flagged, not yet disabled users are planned' );
	$rw_ok( $rw_find( $rw_plan['rows'], 'add', 'rw_dul_m1' ) && $rw_find( $rw_plan['rows'], 'unchanged', 'Already' ) && $rw_find( $rw_plan['rows'], 'blocked', 'your own account' ), 'migration plan: rows for the carry-over, the already disabled user and the actor' );
	$rw_ok( ! in_array( $rw_a, $rw_plan['ops']['users'], true ) && ! in_array( $rw_m['m7'], $rw_plan['ops']['users'], true ), 'migration plan: the actor and the already disabled user are left out' );
	$rw_ok( in_array( 'Disable User Login', array_column( $rw_plan['rows'], 'area' ), true ), 'migration plan: reports the source plugin\'s own data is left as it is' );

	$rw_ap = $rw_apply( $rw_a );
	$rw_ok( ! is_wp_error( $rw_ap ) && 'applied' === $rw_ap['status'] && ! $rw_ap['errors'], 'migration apply: applied without errors' . ( ! is_wp_error( $rw_ap ) && $rw_ap['errors'] ? ' (' . implode( ' ', $rw_ap['errors'] ) . ')' : '' ) );
	$rw_all_on = true;
	foreach ( $rw_flagged as $rw_id ) {
		$rw_all_on = $rw_all_on && Accounts::is_disabled( $rw_id );
	}
	$rw_ok( $rw_all_on && ! Accounts::is_disabled( $rw_m['m6'] ) && ! Accounts::is_disabled( $rw_a ), 'migration apply: flagged users disabled; unflagged user and actor untouched' );
	$rw_kept = true;
	foreach ( $rw_all as $rw_id ) {
		$rw_kept = $rw_kept && '1' === get_user_meta( $rw_id, RW_DUL_META, true );
	}
	$rw_ok( $rw_kept && '0' === get_user_meta( $rw_m['m6'], RW_DUL_META, true ), 'migration apply: _is_disabled is left as it was on every user' );
	$rw_ok( get_option( 'disable_user_login_settings' ) === array( 'disabled_message' => 'rw-marker-' . $rw_sfx ), 'migration apply: the plugin\'s settings option is untouched' );
	$rw_ok( '1' === get_user_meta( $rw_m['m1'], 'ja_disable_user', true ), 'migration apply: another plugin\'s flag is untouched' );
	$rw_rec = ! is_wp_error( $rw_ap ) && ! empty( $rw_ap['migration_id'] ) ? Migrator::record( $rw_ap['migration_id'] ) : null;
	$rw_ok( $rw_rec && $rw_flagged === $rw_rec['users'] && 'disable-user-login' === ( $rw_rec['source'] ?? '' ), 'migration apply: migrated ids recorded in rolegate_migrations' );
	$rw_ok( false !== strpos( Migrator::summary( (array) $rw_rec ), '5 disabled accounts' ), 'migration apply: summary names the count' );

	$rw_mid   = $rw_snap();
	$rw_again = $rw_apply( $rw_a );
	$rw_ok( ! is_wp_error( $rw_again ) && 'unchanged' === $rw_again['status'] && $rw_mid === $rw_snap(), 'migration: second apply changes nothing' );

	$rw_audit = Plugin::is_enabled( 'audit' ) && Store::table_exists();
	if ( $rw_audit ) {
		$rw_row = null;
		foreach ( Store::query( array( 'type' => 'migration.applied' ), 1, 50 )['rows'] as $rw_r ) {
			$rw_d = json_decode( (string) $rw_r->detail, true );
			if ( $rw_rec && isset( $rw_d['migration_id'] ) && $rw_d['migration_id'] === $rw_ap['migration_id'] ) {
				$rw_row = $rw_r;
			}
		}
		$rw_ok( $rw_row && Reverter::can_revert_row( $rw_row ), 'migration audit: migration.applied logged and revertible' );
		$rw_rv = $rw_row ? Reverter::revert( (int) $rw_row->id, $rw_a ) : new WP_Error( 'x', 'no row' );
	} else {
		echo "NOTE audit module off: audit assertions skipped\n";
		$rw_rv = $rw_rec ? Migrator::revert( $rw_ap['migration_id'], $rw_a ) : new WP_Error( 'x', 'no record' );
	}
	$rw_ok( true === $rw_rv, 'migration revert: succeeded' . ( is_wp_error( $rw_rv ) ? ' (' . $rw_rv->get_error_message() . ')' : '' ) );
	$rw_all_off = true;
	foreach ( $rw_flagged as $rw_id ) {
		$rw_all_off = $rw_all_off && ! Accounts::is_disabled( $rw_id );
	}
	$rw_ok( $rw_all_off && Accounts::is_disabled( $rw_m['m7'] ), 'migration revert: migrated users enabled again; the user disabled before stays disabled' );
	$rw_kept = true;
	foreach ( $rw_all as $rw_id ) {
		$rw_kept = $rw_kept && '1' === get_user_meta( $rw_id, RW_DUL_META, true );
	}
	$rw_ok( $rw_kept, 'migration revert: _is_disabled still untouched' );

	$rw_deny_target = $rw_make( 'rw_dul_n2', 'subscriber' );
	$rw_allow       = $rw_make( 'rw_dul_n1', 'subscriber' );
	update_user_meta( $rw_deny_target, RW_DUL_META, 1 );
	update_user_meta( $rw_allow, RW_DUL_META, 1 );
	$rw_deny = function ( $ok, $actor, $target ) use ( $rw_deny_target ) {
		return $target === $rw_deny_target ? false : $ok;
	};
	add_filter( 'rolegate_can_act_on_user', $rw_deny, 10, 3 );
	$rw_p3 = Migrator::plan( 'disable-user-login', $rw_a );
	$rw_ok( in_array( $rw_allow, $rw_p3['ops']['users'], true ) && ! in_array( $rw_deny_target, $rw_p3['ops']['users'], true ) && $rw_find( $rw_p3['rows'], 'blocked', 'rw_dul_n2' ), 'migration authority: a user the actor can\'t act on is left out of the plan and reported' );
	remove_filter( 'rolegate_can_act_on_user', $rw_deny, 10 );

	if ( Migrator::is_shell( 0 ) ) {
		update_user_meta( $rw_b, RW_DUL_META, 1 );
		$rw_sp = Migrator::plan( 'disable-user-login', 0 );
		$rw_ok( ! in_array( $rw_a, $rw_sp['ops']['users'], true ) && in_array( $rw_b, $rw_sp['ops']['users'], true ) && $rw_find( $rw_sp['rows'], 'blocked', 'last active user' ), 'migration plan (shell): when every manager is flagged, one stays enabled' );
	} else {
		echo "NOTE not running under WP-CLI: shell actor check skipped\n";
	}
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
}

wp_set_current_user( 0 );
foreach ( $rw_users as $rw_id ) {
	delete_user_meta( $rw_id, 'rolegate_disabled' );
	wp_delete_user( $rw_id );
}
foreach ( $rw_pre_mgr as $rw_id ) {
	Accounts::write( $rw_id, false );
}
if ( null === $rw_orig_modules ) {
	delete_option( Plugin::OPTION_MODULES );
} else {
	update_option( Plugin::OPTION_MODULES, $rw_orig_modules );
}
if ( null === $rw_orig_records ) {
	delete_option( Migrator::RECORDS );
} else {
	update_option( Migrator::RECORDS, $rw_orig_records );
}
if ( null === $rw_orig_settings ) {
	delete_option( 'disable_user_login_settings' );
} else {
	update_option( 'disable_user_login_settings', $rw_orig_settings );
}

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
