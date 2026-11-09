<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/migration-smoke.php
 *
 * Seeds data in the formats Members and User Role Editor store, then checks the dry run,
 * apply, idempotence, revert through the audit log, and that the effective capabilities
 * after the migration equal the ones Members' deny-wins rule produced before.
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Content_Access\Content_Settings;
use Rolegate\Modules\Deny_Hierarchy\Denials;
use Rolegate\Modules\Portability\Backups;
use Rolegate\Modules\Portability\Migrator;
use Rolegate\Modules\Roles\Role_Service;

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

$rw_sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users = array();
$rw_posts = array();
$rw_roles = array( 'rw_mig_author', 'rw_mig_accountant', 'rw_mig_writer', 'rw_mig_extra', 'rw_mig_power' );
$rw_opts  = array( 'members_settings', 'members_active_addons', 'user_role_editor', 'ure_role_additional_options_values', Denials::OPTION, Content_Settings::OPTION, Role_Service::OPTION_EXTRA, Migrator::RECORDS, Backups::OPTION, 'default_role', Plugin::OPTION_MODULES );
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
$rw_post = function ( $title, $content = 'Body' ) use ( &$rw_posts ) {
	$id         = wp_insert_post(
		array(
			'post_title'   => $title,
			'post_content' => $content,
			'post_status'  => 'publish',
			'post_type'    => 'post',
		)
	);
	$rw_posts[] = (int) $id;
	return (int) $id;
};

// Members' deny-wins rule, as its user_has_cap filter applies it.
$rw_members_filter = function ( $allcaps, $caps, $args, $user ) {
	if ( 1 >= count( (array) $user->roles ) ) {
		return $allcaps;
	}
	$denied = array_keys( (array) $allcaps, false );
	foreach ( (array) $user->roles as $role ) {
		$obj = get_role( $role );
		if ( $obj ) {
			$denied = array_merge( $denied, array_keys( (array) $obj->capabilities, false ) );
		}
	}
	foreach ( $denied as $cap ) {
		$allcaps[ $cap ] = false;
	}
	return $allcaps;
};

// Seed: roles carrying false caps, as Members stores a deny.
foreach ( $rw_roles as $rw_r ) {
	remove_role( $rw_r );
}
add_role( 'rw_mig_author', 'Mig Author', array( 'read' => true, 'edit_posts' => true, 'delete_posts' => true, 'upload_files' => true ) );
add_role( 'rw_mig_accountant', 'Mig Accountant', array( 'read' => true, 'edit_posts' => false, 'delete_posts' => false, 'view_rw_reports' => true ) );
add_role( 'rw_mig_writer', 'Mig Writer', array( 'read' => true, 'edit_posts' => true, 'publish_posts' => false, 'upload_files' => false ) );
add_role( 'rw_mig_extra', 'Mig Extra', array( 'read' => true ) );
add_role( 'rw_mig_power', 'Mig Power', array( 'read' => true, 'list_users' => true ) );

$rw_admin = $rw_make( 'rw_mig_admin', 'administrator' );
if ( is_multisite() ) {
	grant_super_admin( $rw_admin );
}
$rw_both = $rw_make( 'rw_mig_both', 'rw_mig_author' );
get_userdata( $rw_both )->add_role( 'rw_mig_accountant' );
$rw_writer = $rw_make( 'rw_mig_wr', 'rw_mig_writer' );
get_userdata( $rw_writer )->add_role( 'rw_mig_extra' );
$rw_editor = $rw_make( 'rw_mig_ed', 'editor' );

update_option(
	'members_settings',
	array(
		'role_manager'              => 1,
		'content_permissions'       => 1,
		'private_blog'              => 0,
		'content_permissions_error' => 'Sorry, <em>members</em> only.<script>alert(1)</script>',
		'explicit_denied_caps'      => true,
	)
);
update_option( 'members_active_addons', array( 'members-block-permissions' ) );
update_option(
	'user_role_editor',
	array(
		'other_default_roles' => array( 'rw_mig_extra', 'rw_mig_power', 'rw_mig_gone' ),
		'ure_caps_readable'   => 1,
		'show_admin_role'     => 1,
		'rw_pro_only_setting' => 1,
	)
);
delete_option( Denials::OPTION );
delete_option( Content_Settings::OPTION );
update_option( Role_Service::OPTION_EXTRA, array(), false );
Denials::reset_cache();

$rw_p1 = $rw_post( 'Members restricted' );
add_post_meta( $rw_p1, '_members_access_role', 'rw_mig_author' );
add_post_meta( $rw_p1, '_members_access_role', 'rw_mig_accountant' );
add_post_meta( $rw_p1, '_members_access_error', '<p>Members only <script>x()</script><a href="https://example.com">join</a></p>' );
$rw_p2 = $rw_post( 'Message only' );
add_post_meta( $rw_p2, '_members_access_error', 'Message only' );
$rw_p4 = $rw_post( 'Legacy meta' );
add_post_meta( $rw_p4, '_role', 'rw_mig_writer' );
$rw_p5 = $rw_post( 'Own rule' );
add_post_meta( $rw_p5, '_members_access_role', 'rw_mig_author' );
update_post_meta( $rw_p5, Access::META_ROLES, array( 'editor' ) );
$rw_p6 = $rw_post( 'Gone role' );
add_post_meta( $rw_p6, '_members_access_role', 'rw_mig_gone' );

$rw_blocks = '<!-- wp:paragraph {"blockPermissionsCondition":"=","blockPermissionsType":"user-status","blockPermissionsUserStatus":"logged-in"} -->' . "\n" . '<p>Members area</p>' . "\n" . '<!-- /wp:paragraph -->' . "\n\n"
	. '<!-- wp:group {"blockPermissionsCondition":"=","blockPermissionsType":"role","blockPermissionsRoles":["rw_mig_author"]} -->' . "\n" . '<div class="wp-block-group"><!-- wp:paragraph {"blockPermissionsCondition":"!=","blockPermissionsType":"user-status","blockPermissionsUserStatus":"logged-in"} -->' . "\n" . '<p>Nested</p>' . "\n" . '<!-- /wp:paragraph --></div>' . "\n" . '<!-- /wp:group -->' . "\n\n"
	. '<!-- wp:paragraph {"blockPermissionsCondition":"=","blockPermissionsType":"cap","blockPermissionsCap":"edit_posts"} -->' . "\n" . '<p>Cap rule</p>' . "\n" . '<!-- /wp:paragraph -->' . "\n\n"
	. '<!-- wp:paragraph {"blockPermissionsCondition":"!=","blockPermissionsType":"role","blockPermissionsRoles":["rw_mig_author"]} -->' . "\n" . '<p>Not authors</p>' . "\n" . '<!-- /wp:paragraph -->';
$rw_p3     = $rw_post( 'Blocks' );
global $wpdb;
$wpdb->update( $wpdb->posts, array( 'post_content' => $rw_blocks ), array( 'ID' => $rw_p3 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
clean_post_cache( $rw_p3 );

$rw_state = function () use ( $rw_p1, $rw_p2, $rw_p3, $rw_p4, $rw_p5 ) {
	return md5(
		serialize(
			array(
				get_option( Denials::OPTION ),
				get_option( Content_Settings::OPTION ),
				get_option( Role_Service::OPTION_EXTRA ),
				get_option( Migrator::RECORDS ),
				get_option( Backups::OPTION ),
				get_option( Plugin::OPTION_MODULES ),
				get_post_meta( $rw_p1 ),
				get_post_meta( $rw_p2 ),
				get_post_meta( $rw_p4 ),
				get_post_meta( $rw_p5 ),
				get_post( $rw_p3 )->post_content,
			)
		)
	);
};
$rw_find = function ( array $rows, string $action, string $needle ) {
	foreach ( $rows as $row ) {
		if ( $row['action'] === $action && ( false !== strpos( $row['item'], $needle ) || false !== strpos( $row['detail'], $needle ) ) ) {
			return true;
		}
	}
	return false;
};

// Snapshot with Members' semantics active.
add_filter( 'user_has_cap', $rw_members_filter, 10, 4 );
$rw_snap = Migrator::snapshot();
remove_filter( 'user_has_cap', $rw_members_filter, 10 );
$rw_set  = 'set:rw_mig_accountant+rw_mig_author';
$rw_ok( count( $rw_snap['entries'] ) >= 7 && count( $rw_snap['universe'] ) > 50, 'snapshot: has entries (' . count( $rw_snap['entries'] ) . ') over a cap universe (' . count( $rw_snap['universe'] ) . ')' );
$rw_ok( isset( $rw_snap['entries'][ $rw_set ] ) && ! in_array( 'edit_posts', $rw_snap['entries'][ $rw_set ]['caps'], true ) && in_array( 'upload_files', $rw_snap['entries'][ $rw_set ]['caps'], true ), 'snapshot: deny-wins role set lacks edit_posts and keeps upload_files' );
$rw_ok( isset( $rw_snap['entries']['role:rw_mig_author'] ) && 64 === strlen( $rw_snap['entries']['role:rw_mig_author']['sha256'] ), 'snapshot: single roles are hashed' );

// Control: without Members' rule and before the migration, verify must see a difference.
$rw_ctl = Migrator::compare( $rw_snap );
$rw_ok( ! is_wp_error( $rw_ctl ) && $rw_ctl['entries'] === count( $rw_snap['entries'] ) && count( $rw_ctl['differences'] ) > 0, 'verify control: unmigrated site without the deny rule shows differences (' . ( is_wp_error( $rw_ctl ) ? 'error' : count( $rw_ctl['differences'] ) ) . ')' );
$rw_ok( is_wp_error( Migrator::compare( array( 'format' => 'rolegate-capsnap', 'entries' => array(), 'universe' => array( 'read' ) ) ) ), 'verify: an empty snapshot is refused, not passed' );

// Authority.
$rw_ok( is_wp_error( Migrator::plan( 'members', $rw_editor ) ), 'authority: an editor cannot plan a migration' );
$rw_ok( is_wp_error( Migrator::apply( 'members', $rw_editor ) ), 'authority: an editor cannot apply a migration' );
$rw_ok( ! is_wp_error( Migrator::plan( 'members', 0 ) ), 'authority: the WP-CLI shell actor can plan' );

// Dry run writes nothing.
$rw_before = $rw_state();
$rw_plan   = Migrator::plan( 'members', $rw_admin );
$rw_ok( ! is_wp_error( $rw_plan ) && $rw_plan['detected'], 'dry run: Members detected' );
$rw_ok( $rw_before === $rw_state(), 'dry run: nothing written' );
$rw_ok( isset( $rw_plan['ops']['denials']['rw_mig_accountant'] ) && isset( $rw_plan['ops']['denials']['rw_mig_writer'] ), 'dry run: plans denials for both roles with false caps' );
$rw_ok( $rw_find( $rw_plan['rows'], 'conflict', '#' . $rw_p5 ), 'dry run: post with its own rule is kept as is' );
$rw_ok( $rw_find( $rw_plan['rows'], 'skip', '#' . $rw_p6 ), 'dry run: post limited to a missing role is skipped with a line' );
$rw_ok( $rw_find( $rw_plan['rows'], 'add', '#' . $rw_p3 ) && isset( $rw_plan['ops']['blocks'][ $rw_p3 ] ), 'dry run: block rules planned' );
$rw_ok( $rw_find( $rw_plan['rows'], 'add', 'capability' ) && $rw_find( $rw_plan['rows'], 'add', 'hidden from chosen roles' ), 'dry run: cap and hide-from-roles block rules reported as not carried over' );
$rw_ok( 'Sorry, <em>members</em> only.alert(1)' === $rw_plan['ops']['content_message'], 'dry run: default message planned through the message kses' );

// Apply.
$rw_backups0 = count( Backups::all() );
$rw_res      = Migrator::apply( 'members', $rw_admin );
$rw_ok( ! is_wp_error( $rw_res ) && 'applied' === $rw_res['status'] && ! $rw_res['errors'], 'apply: applied without errors' . ( ! is_wp_error( $rw_res ) && $rw_res['errors'] ? ' (' . implode( ' ', $rw_res['errors'] ) . ')' : '' ) );
Denials::reset_cache();
$rw_ok( array( 'delete_posts', 'edit_posts' ) === Denials::for_role( 'rw_mig_accountant' ), 'apply: accountant denials carried over' );
$rw_ok( array( 'publish_posts', 'upload_files' ) === Denials::for_role( 'rw_mig_writer' ), 'apply: writer denials carried over' );
$rw_ok( false === get_role( 'rw_mig_accountant' )->capabilities['edit_posts'], 'apply: role\'s own false values untouched' );
$rw_r1 = Migrator::post_rules( $rw_p1 );
$rw_ok( array( 'rw_mig_author', 'rw_mig_accountant' ) === $rw_r1['roles'], 'apply: post roles from every Members meta row' );
$rw_ok( false === strpos( $rw_r1['message'], '<script' ) && false !== strpos( $rw_r1['message'], '<a href="https://example.com">join</a>' ), 'apply: post message through the kses rules' );
$rw_ok( 'Message only' === Migrator::post_rules( $rw_p2 )['message'] && ! Migrator::post_rules( $rw_p2 )['roles'], 'apply: message-only post gets the message, no restriction' );
$rw_ok( array( 'rw_mig_writer' ) === Migrator::post_rules( $rw_p4 )['roles'], 'apply: legacy _role meta carried over' );
$rw_ok( array( 'editor' ) === Migrator::post_rules( $rw_p5 )['roles'], 'apply: existing rule left alone' );
$rw_ok( 2 === count( get_post_meta( $rw_p1, '_members_access_role' ) ) && '' !== get_post_meta( $rw_p1, '_members_access_error', true ) && array( 'rw_mig_writer' ) === get_post_meta( $rw_p4, '_role' ), 'apply: Members post meta untouched' );
$rw_blocks_after = parse_blocks( get_post( $rw_p3 )->post_content );
$rw_ok( 'logged_in' === ( $rw_blocks_after[0]['attrs']['rolegateMode'] ?? '' ) && 'logged-in' === ( $rw_blocks_after[0]['attrs']['blockPermissionsUserStatus'] ?? '' ), 'apply: user-status block mapped, Members attributes kept' );
$rw_ok( 'roles' === ( $rw_blocks_after[2]['attrs']['rolegateMode'] ?? '' ) && array( 'rw_mig_author' ) === ( $rw_blocks_after[2]['attrs']['rolegateRoles'] ?? null ), 'apply: role block mapped' );
$rw_ok( 'logged_out' === ( $rw_blocks_after[2]['innerBlocks'][0]['attrs']['rolegateMode'] ?? '' ), 'apply: nested "not logged in" block mapped to logged out' );
$rw_ok( ! isset( $rw_blocks_after[4]['attrs']['rolegateMode'] ) && ! isset( $rw_blocks_after[6]['attrs']['rolegateMode'] ), 'apply: cap and hide-from-roles blocks left alone' );
$rw_ok( 'Sorry, <em>members</em> only.alert(1)' === Content_Settings::default_message(), 'apply: default message stored' );
$rw_ok( count( Backups::all() ) === min( $rw_backups0 + 1, Backups::KEEP ) && 'migrate-members' === Backups::all()[0]['source'], 'apply: role backup taken' );
$rw_rec = Migrator::record( $rw_res['migration_id'] );
$rw_ok( $rw_rec && in_array( $rw_p1, $rw_rec['post_ids'], true ) && in_array( $rw_p3, $rw_rec['post_ids'], true ) && ! in_array( $rw_p5, $rw_rec['post_ids'], true ), 'apply: touched post ids recorded' );
$rw_ok( 'Members only' === wp_strip_all_tags( wpautop( Access::sanitize_message( 'Members only' ) ) ) && false !== strpos( Access::notice_html( $rw_p4 ), 'Sorry, <em>members</em> only.' ), 'content access: a post without its own message shows the default message' );

// Effective caps equal Members' deny-wins result, without Members.
$rw_cmp = Migrator::compare( $rw_snap );
$rw_ok( ! is_wp_error( $rw_cmp ) && $rw_cmp['entries'] === count( $rw_snap['entries'] ) && 0 === count( $rw_cmp['differences'] ), 'verify: 0 differences across ' . ( is_wp_error( $rw_cmp ) ? 0 : $rw_cmp['entries'] ) . ' entries after migration' . ( ! is_wp_error( $rw_cmp ) && $rw_cmp['differences'] ? ' (' . wp_json_encode( $rw_cmp['differences'] ) . ')' : '' ) );
$rw_ok( ! user_can( $rw_both, 'edit_posts' ) && user_can( $rw_both, 'upload_files' ), 'deny wins: two-role user lacks edit_posts and keeps upload_files' );

// Idempotence.
$rw_mid   = $rw_state();
$rw_again = Migrator::apply( 'members', $rw_admin );
$rw_ok( ! is_wp_error( $rw_again ) && 'unchanged' === $rw_again['status'] && $rw_mid === $rw_state(), 'idempotent: second run changes nothing and says so' );
$rw_ok( ! Migrator::has_changes( Migrator::plan( 'members', $rw_admin )['ops'] ), 'idempotent: preview shows nothing left to carry over' );

// URE.
$rw_uplan = Migrator::plan( 'ure', $rw_admin );
$rw_ok( $rw_uplan['detected'] && array( 'rw_mig_extra' ) === $rw_uplan['ops']['extras'], 'ure: extra default role planned' );
$rw_ok( $rw_find( $rw_uplan['rows'], 'blocked', 'rw_mig_power' ) && $rw_find( $rw_uplan['rows'], 'skip', 'rw_mig_gone' ), 'ure: powerful and missing roles reported' );
$rw_ok( $rw_find( $rw_uplan['rows'], 'skip', 'rw_pro_only_setting' ), 'ure: unknown (Pro) settings reported and left alone' );
$rw_ok( $rw_find( $rw_uplan['rows'], 'info', 'WordPress itself' ), 'ure: roles and caps reported as carried over untouched' );
$rw_ures = Migrator::apply( 'ure', $rw_admin );
$rw_ok( ! is_wp_error( $rw_ures ) && 'applied' === $rw_ures['status'] && array( 'rw_mig_extra' ) === Role_Service::extra_default_roles(), 'ure: extra default role applied' );
$rw_ok( 'unchanged' === Migrator::apply( 'ure', $rw_admin )['status'], 'ure: idempotent' );
$rw_ure_opt = get_option( 'user_role_editor' );
$rw_ok( is_array( $rw_ure_opt ) && 3 === count( $rw_ure_opt['other_default_roles'] ), 'ure: its own option untouched' );

// Revert through the audit log.
$rw_audit = Plugin::is_enabled( 'audit' ) && Store::table_exists();
if ( $rw_audit ) {
	$rw_rows = Store::query( array( 'type' => 'migration.applied' ), 1, 20 )['rows'];
	$rw_row  = null;
	foreach ( $rw_rows as $r ) {
		$d = json_decode( (string) $r->detail, true );
		if ( isset( $d['migration_id'] ) && $d['migration_id'] === $rw_res['migration_id'] ) {
			$rw_row = $r;
		}
	}
	$rw_ok( $rw_row && Reverter::can_revert_row( $rw_row ), 'audit: migration.applied logged and revertible' );
	$rw_rev = $rw_row ? Reverter::revert( (int) $rw_row->id, $rw_admin ) : new WP_Error( 'x', 'no row' );
	$rw_ok( true === $rw_rev, 'audit: revert succeeded' . ( is_wp_error( $rw_rev ) ? ' (' . $rw_rev->get_error_message() . ')' : '' ) );
	$rw_ok( $rw_row && is_wp_error( Reverter::revert( (int) $rw_row->id, $rw_admin ) ), 'audit: a second revert is refused' );
} else {
	echo "NOTE audit module off: reverting through Migrator::revert\n";
	$rw_rev = Migrator::revert( $rw_res['migration_id'], $rw_admin );
	$rw_ok( true === $rw_rev, 'revert: succeeded' );
}
Denials::reset_cache();
$rw_ok( ! Denials::for_role( 'rw_mig_accountant' ) && ! Denials::for_role( 'rw_mig_writer' ), 'revert: previous denial map restored' );
$rw_ok( ! metadata_exists( 'post', $rw_p1, Access::META_ROLES ) && ! metadata_exists( 'post', $rw_p1, Access::META_MESSAGE ) && ! metadata_exists( 'post', $rw_p2, Access::META_MESSAGE ), 'revert: added post meta removed' );
$rw_ok( array( 'editor' ) === Migrator::post_rules( $rw_p5 )['roles'], 'revert: rule the migration didn\'t add is kept' );
$rw_ok( get_post( $rw_p3 )->post_content === $rw_blocks, 'revert: block content restored byte for byte' );
$rw_ok( '' === Content_Settings::default_message(), 'revert: default message restored' );
$rw_ok( 2 === count( get_post_meta( $rw_p1, '_members_access_role' ) ), 'revert: Members data still untouched' );
$rw_ok( true === Migrator::revert( $rw_ures['migration_id'], $rw_admin ) && array() === Role_Service::extra_default_roles(), 'revert: URE extra default roles restored' );

// Cleanup.
remove_filter( 'user_has_cap', $rw_members_filter, 10 );
require_once ABSPATH . 'wp-admin/includes/user.php';
foreach ( $rw_posts as $rw_id ) {
	wp_delete_post( $rw_id, true );
}
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
Denials::reset_cache();

echo "\n{$rw_pass} passed, {$rw_fail} failed\n";
if ( $rw_fail ) {
	exit( 1 );
}
