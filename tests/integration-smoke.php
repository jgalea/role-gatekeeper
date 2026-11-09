<?php
/**
 * Cross-module checks. Needs every module on except site-access:
 * wp option update rolegate_modules '{"deny-hierarchy":true,"automation":true,...}' --format=json
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/integration-smoke.php
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Admin_Ui\Rules as Ui_Rules;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Automation\Ops;
use Rolegate\Modules\Capabilities\Cap_Service;
use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Deny_Hierarchy\Denials;
use Rolegate\Modules\Deny_Hierarchy\Hierarchy;
use Rolegate\Modules\Edit_Scope\Rules as Scope_Rules;
use Rolegate\Modules\Portability\Exporter;
use Rolegate\Modules\Portability\Importer;
use Rolegate\Modules\Portability\Sections;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Enforcer;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\User_Roles\Users;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';

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
$code    = function ( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : '';
};

foreach ( array( 'roles', 'capabilities', 'user-roles', 'deny-hierarchy', 'content-access', 'admin-ui', 'edit-scope', 'portability', 'audit', 'automation' ) as $rw_id ) {
	if ( ! Plugin::is_enabled( $rw_id ) ) {
		echo "SETUP ERROR module $rw_id is off; turn every module but site-access on\n";
		exit( 1 );
	}
}

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
	if ( is_wp_error( $id ) ) {
		echo 'SETUP ERROR ' . $id->get_error_message() . "\n";
		exit( 1 );
	}
	$users[] = (int) $id;
	return (int) $id;
};
$events = array();
add_action(
	'rolegate_changed',
	function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	},
	10,
	2
);
$count = function ( $type ) use ( &$events ) {
	return count( array_filter( array_column( $events, 0 ), function ( $t ) use ( $type ) {
		return $t === $type;
	} ) );
};
$logged = function ( $type ) use ( $wpdb ) {
	return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Store::table() . ' WHERE type = %s ORDER BY id DESC LIMIT 1', $type ) ); // phpcs:ignore
};

$saved_opts = array();
foreach ( array( Denials::OPTION, Hierarchy::OPTION, Ui_Rules::OPTION, Scope_Rules::OPTION, Scope_Rules::SETTINGS ) as $opt ) {
	$saved_opts[ $opt ] = get_option( $opt, null );
}

$admin = $make( 'rw_int_admin', 'administrator' );
	// On multisite a site administrator is not the site's owner: core keeps edit_user for super admins and Role Gatekeeper keeps its manage caps for them. The single-site administrator maps to a super admin.
	if ( is_multisite() ) {
		grant_super_admin( $admin );
		add_action( 'wpmu_delete_user', 'revoke_super_admin', 1 );
		add_action( 'delete_user', 'revoke_super_admin', 1 );
	}
wp_set_current_user( $admin );

try {
	// One change, one event, one audit row.
	$events = array();
	$slug   = Role_Service::create( $admin, 'Int A ' . $sfx, array( 'read' => true, 'edit_posts' => true ) );
	$roles[] = $slug;
	$rw_ok( is_string( $slug ) && 1 === $count( 'role.created' ) && 1 === count( $events ), 'roles: create fires role.created once and nothing else' );
	$rw_ok( (bool) $logged( 'role.created' ) && $slug === $logged( 'role.created' )->target, 'audit: role.created logged' );

	$events = array();
	$res    = Cap_Service::update_role( $admin, $slug, array( 'read', 'edit_posts', 'upload_files' ) );
	$rw_ok( is_array( $res ) && 1 === $count( 'caps.updated' ) && 1 === count( $events ), 'capabilities: one update fires caps.updated once' );
	$entry = $logged( 'caps.updated' );
	$rw_ok( true === Reverter::revert( (int) $entry->id, $admin ) && empty( get_role( $slug )->capabilities['upload_files'] ), 'audit: caps.updated from the capabilities module reverts' );

	$member = $make( 'rw_int_member', 'subscriber' );
	$events = array();
	$res    = Users::change_roles( $admin, $member, array( $slug ), array() );
	$rw_ok( true === $res && 1 === $count( 'user.roles' ) && 1 === count( $events ), 'user-roles: one change fires user.roles once' );
	$entry = $logged( 'user.roles' );
	$rw_ok( true === Reverter::revert( (int) $entry->id, $admin ) && ! in_array( $slug, get_userdata( $member )->roles, true ), 'audit: user.roles from the user-roles module reverts' );

	$events = array();
	$res    = Users::change_caps( $admin, $member, array( 'upload_files' ), array() );
	$rw_ok( ! is_wp_error( $res ) && 1 === $count( 'user.caps' ), 'user-roles: per-user cap change fires user.caps once' );
	$entry = $logged( 'user.caps' );
	clean_user_cache( $member );
	$rw_ok( $entry && true === Reverter::revert( (int) $entry->id, $admin ) && ! user_can( $member, 'upload_files' ), 'audit: user.caps reverts' );

	$events = array();
	$res    = Ops::assign_role( $admin, $member, $slug );
	$rw_ok( true === $res && 1 === $count( 'user.roles' ) && 1 === count( $events ), 'automation: assign fires user.roles once' );
	$entry = $logged( 'user.roles' );
	$rw_ok( true === Reverter::revert( (int) $entry->id, $admin ) && ! in_array( $slug, get_userdata( $member )->roles, true ), 'audit: user.roles from automation reverts' );

	$events = array();
	$rw_ok( true === Denials::save( $admin, $slug, array( 'edit_posts' ) ) && 1 === $count( 'access.updated' ), 'deny-hierarchy: a denial fires access.updated once' );
	$rw_ok( (bool) $logged( 'access.updated' ), 'audit: deny change logged' );
	$events = array();
	$rw_ok( true === Hierarchy::save_positions( $admin, array( $slug => 40 ) ) && 1 === $count( 'access.updated' ), 'deny-hierarchy: a position change fires access.updated once' );

	$events = array();
	$rw_ok( true === Ui_Rules::save( $admin, 'role', $slug, array( 'blocks' => array( 'widgets' ) ) ) && 1 === $count( 'access.updated' ), 'admin-ui: a rule save fires access.updated once' );
	$events = array();
	$rule   = Scope_Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => $slug, 'mode' => 'allow', 'by' => 'author', 'ids' => array( $admin ) ) );
	$rw_ok( is_array( $rule ) && 1 === $count( 'access.updated' ), 'edit-scope: adding a rule fires access.updated once' );

	$post_id = wp_insert_post( array( 'post_title' => 'Int ' . $sfx, 'post_status' => 'publish', 'post_type' => 'post', 'post_author' => $admin ) );
	$events  = array();
	Access::save_rules( (int) $post_id, array( 'editor' ), '' );
	$rw_ok( 1 === $count( 'access.updated' ), 'content-access: a post rule save fires access.updated once' );
	$audit_access = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Store::table() . ' WHERE type = %s AND target = %s', 'access.updated', (string) $post_id ) ); // phpcs:ignore
	$rw_ok( 1 === $audit_access, 'audit: content-access change logged once' );

	// Hierarchy, roles, capabilities and user-roles vetoes together.
	$mid_role = 'rw_int_mid_' . $sfx;
	$top_role = 'rw_int_top_' . $sfx;
	$roles[]  = $mid_role;
	$roles[]  = $top_role;
	add_role( $mid_role, 'Int Mid', array( 'read' => true, 'edit_posts' => true, Caps::MANAGE => true, Caps::MANAGE_ROLES => true, Caps::MANAGE_CAPS => true, Caps::MANAGE_USERS => true, 'promote_users' => true, 'list_users' => true, 'edit_users' => true ) );
	add_role( $top_role, 'Int Top', array( 'read' => true, 'edit_posts' => true ) );
	Hierarchy::save_positions( $admin, array( $mid_role => 50, $top_role => 60, $slug => 10 ) );
	$mid  = $make( 'rw_int_mid', $mid_role );
	$high = $make( 'rw_int_high', $top_role );
	wp_set_current_user( $mid );
	$rw_ok( 'rolegate_role_above_position' === $code( Cap_Service::update_role( $mid, $top_role, array( 'read' ) ) ), 'hierarchy veto: capabilities refuses a role above the actor' );
	$rw_ok( 'rolegate_role_above_position' === $code( Role_Service::delete( $mid, $top_role ) ), 'hierarchy veto: roles refuses deleting a role above the actor' );
	$rw_ok( is_wp_error( Users::change_roles( $mid, $member, array( $top_role ), array() ) ), 'hierarchy veto: user-roles refuses assigning a role above the actor' );
	$rw_ok( is_wp_error( Users::change_roles( $mid, $high, array( $slug ), array() ) ), 'hierarchy veto: user-roles refuses acting on a user above the actor' );
	$rw_ok( is_array( Cap_Service::update_role( $mid, $slug, array( 'read', 'edit_posts' ) ) ), 'control: a role below the actor can be edited' );
	$rw_ok( true === Users::change_roles( $mid, $member, array( $slug ), array() ), 'control: a role below the actor can be assigned' );
	$rw_ok( 'rolegate_cap_not_held' === $code( Cap_Service::update_role( $mid, $slug, array( 'read', 'manage_options' ) ) ), 'Guard still refuses a critical cap below the hierarchy' );
	$rw_ok( is_wp_error( Ops::assign_role( $mid, $member, $top_role ) ), 'hierarchy veto: automation assign refuses a role above the actor' );
	wp_set_current_user( $admin );
	$shell   = 'rw_int_shell_' . $sfx;
	$roles[] = $shell;
	$rw_ok( $shell === Ops::add_role( 0, 'Int Shell ' . $sfx, $shell, array( 'read' ) ), 'automation shell: the hierarchy does not block the shell actor' );
	$rw_ok( 'rolegate_protected_role' === $code( Ops::delete_role( 0, 'administrator' ) ), 'automation shell: Guard still protects the administrator role with the hierarchy on' );
	$rw_ok( 90 <= Hierarchy::default_position_for_caps( array( Caps::MANAGE_ROLES => true ) ) && 90 <= Hierarchy::default_position_for_caps( array( Caps::MANAGE_USERS => true ) ), 'hierarchy: Role Gatekeeper manager caps rank a role with the user managers' );

	// Hierarchy positions follow the roles that exist.
	$gone = 'rw_int_gone_' . $sfx;
	add_role( $gone, 'Gone', array( 'read' => true ) );
	Hierarchy::save_positions( $admin, array( $gone => 30 ) );
	$rw_ok( 30 === Hierarchy::role_position( $gone ), 'fixture: stored position applies' );
	remove_role( $gone );
	$rw_ok( ! array_key_exists( $gone, Hierarchy::stored() ), 'hierarchy: removing a role forgets its stored position' );
	add_role( $gone, 'Gone again', array( 'read' => true ) );
	$rw_ok( 0 === Hierarchy::role_position( $gone ), 'hierarchy: a new role with an old slug starts from the default position' );
	Hierarchy::save_positions( $admin, array( $gone => 30 ) );
	$all_roles = get_option( $wpdb->get_blog_prefix() . 'user_roles' );
	unset( $all_roles[ $gone ] );
	Enforcer::as_system(
		function () use ( $wpdb, $all_roles ) {
			update_option( $wpdb->get_blog_prefix() . 'user_roles', $all_roles );
		}
	);
	wp_roles()->for_site();
	$rw_ok( ! array_key_exists( $gone, Hierarchy::stored() ), 'hierarchy: rewriting the roles option drops positions of roles it no longer has' );
	$rw_ok( -1 === Hierarchy::role_position( $gone ), 'hierarchy: the position cache follows a roles option rewrite' );
	update_option( Hierarchy::OPTION, array_merge( Hierarchy::stored(), array( 'rw_int_ghost_' . $sfx => 95 ) ), true );
	$rw_ok( ! array_key_exists( 'rw_int_ghost_' . $sfx, Hierarchy::positions() ) && -1 === Hierarchy::role_position( 'rw_int_ghost_' . $sfx ), 'hierarchy: a stored position for a role that does not exist is ignored' );

	// Guard::cap_exists sees caps no role lists yet.
	register_post_type(
		'rw_int_book',
		array(
			'public'          => false,
			'capability_type' => array( 'rw_int_book', 'rw_int_books' ),
			'map_meta_cap'    => true,
		)
	);
	$rw_ok( Guard::cap_exists( 'edit_rw_int_books' ) && Guard::cap_exists( 'publish_rw_int_books' ), 'Guard::cap_exists sees post-type capabilities' );
	$rw_ok( Guard::cap_exists( 'edit_post' ) && Guard::cap_exists( 'promote_user' ), 'Guard::cap_exists sees meta capabilities' );
	$rw_ok( ! Guard::cap_exists( 'rw_int_nothing_' . $sfx ), 'control: Guard::cap_exists is false for an unknown name' );

	// Importer refuses a new role slug that is a capability name.
	$payload = Importer::normalize(
		array(
			'manage_options'    => array( 'name' => 'X', 'capabilities' => array( 'read' => true ) ),
			'edit_posts'        => array( 'name' => 'Y', 'capabilities' => array( 'read' => true ) ),
			'edit_rw_int_books' => array( 'name' => 'Z', 'capabilities' => array( 'read' => true ) ),
			'manage_network_x'  => array( 'name' => 'C', 'capabilities' => array( 'read' => true ) ),
			'rw_int_ok_' . $sfx => array( 'name' => 'OK', 'capabilities' => array( 'read' => true ) ),
		),
		array(),
		'file'
	);
	$rw_ok( is_array( $payload ) && array( 'rw_int_ok_' . $sfx ) === array_keys( $payload['roles'] ), 'importer: role slugs equal to a capability, a post-type cap or a critical cap name are skipped' );
	$rw_ok( false === Importer::sanitize_role_slug( 'manage_options' ) && false === Importer::sanitize_role_slug( 'edit_posts' ) && false === Importer::sanitize_role_slug( 'rolegate_manage' ), 'importer: sanitize_role_slug refuses capability and critical names' );
	$rw_ok( 'editor' === Importer::sanitize_role_slug( 'editor' ), 'control: an existing role slug is accepted' );

	// Content-access strips visibility attributes written with JSON unicode escapes.
	// An editor keeps unfiltered_html on single site, so core's kses leaves the block JSON alone and only the plugin's guard can strip it.
	$author = $make( 'rw_int_author', 'editor' );
	wp_set_current_user( $author );
	// Written with JSON unicode escapes (u004d is M, u0052 is R), so the attribute names never appear literally.
	$bs      = chr( 92 );
	$escaped = '<!-- wp:paragraph {"rolegate' . $bs . 'u004dode":"hide","rolegate' . $bs . 'u0052oles":["editor"]} --><p>x</p><!-- /wp:paragraph -->';
	$rw_ok( false === strpos( $escaped, 'rolegateMode' ), 'fixture: the escaped content does not contain the attribute name literally' );
	$pid     = wp_insert_post( wp_slash( array( 'post_title' => 'Esc ' . $sfx, 'post_content' => $escaped, 'post_status' => 'draft', 'post_author' => $author ) ) );
	$blocks  = parse_blocks( (string) get_post_field( 'post_content', $pid ) );
	$rw_ok( $pid && empty( $blocks[0]['attrs']['rolegateMode'] ) && empty( $blocks[0]['attrs']['rolegateRoles'] ), 'content-access: a user without manage_access can\'t add escaped visibility attributes' );
	wp_set_current_user( $admin );
	$pid2    = wp_insert_post( wp_slash( array( 'post_title' => 'Esc2 ' . $sfx, 'post_content' => $escaped, 'post_status' => 'draft', 'post_author' => $admin ) ) );
	$blocks  = parse_blocks( (string) get_post_field( 'post_content', $pid2 ) );
	$rw_ok( 'hide' === ( $blocks[0]['attrs']['rolegateMode'] ?? '' ), 'control: a user with manage_access keeps them' );
	wp_delete_post( (int) $pid, true );
	wp_delete_post( (int) $pid2, true );

	// Portability sections.
	$sections = Sections::all();
	$rw_ok( isset( $sections['deny'], $sections['admin-ui'], $sections['edit-scope'] ), 'portability: deny, admin-ui and edit-scope sections are registered' );
	$file = Exporter::build( array( $slug ), array( 'deny', 'admin-ui', 'edit-scope' ), $admin );
	$rw_ok( array( 'edit_posts' ) === ( $file['sections']['deny']['denied'][ $slug ] ?? null ) && 10 === ( $file['sections']['deny']['positions'][ $slug ] ?? null ), 'portability: export carries denials and positions' );
	$rw_ok( isset( $file['sections']['admin-ui']['roles'][ $slug ] ) && 1 === count( $file['sections']['edit-scope']['rules'] ?? array() ), 'portability: export carries admin-ui and edit-scope rules' );

	// Change everything, then import the file back.
	Denials::save( $admin, $slug, array() );
	Ui_Rules::save( $admin, 'role', $slug, array() );
	Scope_Rules::delete( $admin, (string) $rule['id'] );
	Hierarchy::save_positions( $admin, array( $slug => 5 ) );
	$json    = Exporter::to_json( $file );
	$parsed  = Importer::parse( $json );
	$plan    = Importer::plan( $parsed, $admin );
	$rw_ok( empty( $plan['sections']['deny']['blocked'] ) && ! empty( $plan['sections']['deny']['summary'] ), 'portability: deny section previews' );
	$events  = array();
	$applied = Importer::apply( $parsed, $admin, array( 'roles' => array(), 'sections' => array( 'deny', 'admin-ui', 'edit-scope' ) ) );
	$rw_ok( is_array( $applied ) && array( 'deny', 'admin-ui', 'edit-scope' ) === $applied['sections'] && ! $applied['errors'], 'portability: sections import' );
	$rw_ok( array( 'edit_posts' ) === Denials::for_role( $slug ) && 10 === Hierarchy::role_position( $slug ), 'portability: denials and positions restored' );
	$rw_ok( array( 'widgets' ) === Ui_Rules::get( 'role', $slug )['blocks'] && 1 === count( Scope_Rules::all() ), 'portability: admin-ui and edit-scope rules restored' );
	$rw_ok( 1 === $count( 'import.applied' ) && $count( 'access.updated' ) >= 3, 'portability: import.applied once, plus each module\'s own access.updated' );
	$applied_again = Importer::apply( $parsed, $admin, array( 'roles' => array(), 'sections' => array( 'edit-scope' ) ) );
	$rw_ok( is_array( $applied_again ) && 1 === count( Scope_Rules::all() ), 'portability: edit-scope rules replace, re-importing does not duplicate' );

	// Import goes through each module's checks.
	$bad = $parsed;
	$bad['sections']['deny'] = array( 'denied' => array( 'administrator' => array( Caps::MANAGE ) ) );
	$res = Importer::apply( $bad, $admin, array( 'roles' => array(), 'sections' => array( 'deny' ) ) );
	$rw_ok( is_wp_error( $res ) || ! empty( $res['errors'] ), 'portability: a deny on the administrator\'s Role Gatekeeper caps is refused' );
	$rw_ok( ! in_array( Caps::MANAGE, Denials::for_role( 'administrator' ), true ), 'portability: refused deny section wrote nothing' );

	$lim_role = 'rw_int_lim_' . $sfx;
	$roles[]  = $lim_role;
	add_role( $lim_role, 'Int Lim', array( 'read' => true, Caps::MANAGE => true, Caps::MANAGE_ACCESS => true, Caps::IMPORT => true, Caps::MANAGE_ROLES => true ) );
	$lim = $make( 'rw_int_lim', $lim_role );
	wp_set_current_user( $lim );
	$esc = $parsed;
	$esc['sections']['deny'] = array( 'denied' => array( $slug => array( 'edit_posts', 'manage_options' ) ) );
	$res = Importer::apply( $esc, $lim, array( 'roles' => array(), 'sections' => array( 'deny' ) ) );
	$rw_ok( ( is_wp_error( $res ) || ! empty( $res['errors'] ) ) && ! in_array( 'manage_options', Denials::for_role( $slug ), true ), 'portability: a limited importer can\'t deny a critical cap it lacks' );
	$esc['sections']['deny'] = array( 'positions' => array( $slug => 99 ) );
	$res = Importer::apply( $esc, $lim, array( 'roles' => array(), 'sections' => array( 'deny' ) ) );
	$rw_ok( ( is_wp_error( $res ) || ! empty( $res['errors'] ) ) && 10 === Hierarchy::role_position( $slug ), 'portability: a limited importer can\'t move a role above itself' );
	$esc['sections']['admin-ui'] = array( 'roles' => array( 'administrator' => array( 'blocks' => array( 'widgets' ) ) ) );
	$res = Importer::apply( $esc, $lim, array( 'roles' => array(), 'sections' => array( 'admin-ui' ) ) );
	$rw_ok( ( is_wp_error( $res ) || ! empty( $res['errors'] ) ) && array() === Ui_Rules::get( 'role', 'administrator' )['blocks'], 'portability: admin-ui section can\'t restrict the administrator role' );
	$esc['sections']['edit-scope'] = array( 'rules' => array( array( 'subject_type' => 'role', 'subject' => 'administrator', 'mode' => 'allow', 'by' => 'author', 'ids' => array( 1 ) ) ) );
	$before_rules = Scope_Rules::all();
	$res = Importer::apply( $esc, $lim, array( 'roles' => array(), 'sections' => array( 'edit-scope' ) ) );
	$rw_ok( ( is_wp_error( $res ) || ! empty( $res['errors'] ) ) && $before_rules === Scope_Rules::all(), 'portability: a refused edit-scope import leaves the existing rules in place' );
	wp_set_current_user( $admin );

	// Multisite: automation reaches only members of the current site.
	if ( is_multisite() ) {
		$outsider = wpmu_create_user( 'rw_int_out_' . $sfx, wp_generate_password( 24 ), 'rw_int_out_' . $sfx . '@example.com' );
		$users[]  = (int) $outsider;
		remove_user_from_blog( (int) $outsider, get_current_blog_id() );
		$site_admin = $make( 'rw_int_siteadm', 'administrator' );
		wp_set_current_user( $site_admin );
		$rw_ok( 'rolegate_not_site_member' === $code( Ops::assign_role( $site_admin, (int) $outsider, 'subscriber' ) ), 'multisite automation: assign refuses a user from another site' );
		$rw_ok( 'rolegate_not_site_member' === $code( Ops::unassign_role( $site_admin, (int) $outsider, 'subscriber' ) ), 'multisite automation: unassign refuses a user from another site' );
		$rw_ok( 'rolegate_not_site_member' === $code( Ops::user_summary( (int) $outsider, $site_admin ) ), 'multisite automation: user read refuses a user from another site' );
		$rw_ok( ! is_user_member_of_blog( (int) $outsider, get_current_blog_id() ), 'multisite automation: refused assign added nothing' );
		$rw_ok( ! is_wp_error( Ops::user_summary( $member, $site_admin ) ), 'control: a site member can be read' );
		wp_set_current_user( $admin );
	}
} finally {
	wp_set_current_user( $admin );
	unregister_post_type( 'rw_int_book' );
	foreach ( $saved_opts as $opt => $val ) {
		if ( null === $val ) {
			delete_option( $opt );
		} else {
			update_option( $opt, $val );
		}
	}
	Denials::reset_cache();
	Hierarchy::reset_cache();
	Ui_Rules::flush_cache();
	Scope_Rules::flush();
	if ( isset( $post_id ) ) {
		wp_delete_post( (int) $post_id, true );
	}
	foreach ( $users as $uid ) {
		is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
	}
	foreach ( $roles as $r ) {
		remove_role( $r );
	}
	if ( isset( $gone ) ) {
		remove_role( $gone );
	}
}

echo "\n{$rw_pass} passed, {$rw_fail} failed\n";
exit( $rw_fail ? 1 : 0 );
