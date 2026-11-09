<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/hardening-smoke.php
 *
 * Regression checks for the final security review: role slugs that collide with
 * capabilities, module and automation settings authority, default-role critical caps,
 * per-user caps turning into roles, post__in leaks, REST rule meta, rescue timing and
 * self-targeted reverts.
 */

use Rolegate\Core\Settings;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Automation\Automation_Module;
use Rolegate\Modules\Automation\Automation_Page;
use Rolegate\Modules\Automation\Ops;
use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Portability\Importer;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Enforcer;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\Safety\Rescue;
use Rolegate\Modules\User_Roles\Users;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

if ( is_multisite() ) {
	add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );
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
$rw_code = function ( $result ) {
	return is_wp_error( $result ) ? $result->get_error_code() : 'ok';
};

$rw_events = array();
add_action(
	'rolegate_changed',
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
$rw_roles  = array();
$rw_posts  = array();
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

$rw_admin = $rw_make( 'rw_hard_admin', 'administrator' );
$rw_sub   = $rw_make( 'rw_hard_sub', 'subscriber' );
wp_set_current_user( $rw_admin );

// 1. Role slugs that collide with capabilities.
$rw_network = array( 'manage_network', 'manage_network_users', 'manage_network_options', 'manage_network_plugins', 'manage_network_themes', 'manage_sites', 'create_sites', 'delete_sites', 'upgrade_network', 'setup_network' );
foreach ( $rw_network as $rw_cap ) {
	$rw_ok( 'rolegate_reserved_slug' === $rw_code( Guard::valid_new_role_slug( $rw_cap ) ), "slug: network cap {$rw_cap} is refused" );
}
foreach ( array( 'manage_options', 'edit_users', 'rolegate_manage', 'unfiltered_html' ) as $rw_cap ) {
	$rw_ok( 'rolegate_reserved_slug' === $rw_code( Guard::valid_new_role_slug( $rw_cap ) ), "slug: critical cap {$rw_cap} is refused" );
}
$rw_ok( 'rolegate_role_exists' === $rw_code( Guard::valid_new_role_slug( 'edit_posts' ) ), 'slug: an existing cap (edit_posts) is refused' );
$rw_ok( 'rolegate_role_exists' === $rw_code( Guard::valid_new_role_slug( 'editor' ) ), 'slug: an existing role is refused' );
$rw_ok( 'rolegate_invalid_name' === $rw_code( Guard::valid_new_role_slug( 'Bad Slug' ) ), 'slug: an invalid name is refused' );
$rw_ok( true === Guard::valid_new_role_slug( 'rw_fresh_' . $rw_suffix ), 'slug: a fresh name passes (control)' );

$rw_r = Role_Service::create( $rw_admin, 'Manage Network', array( 'read' => true ) );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'manage_network' ), 'roles screen: "Manage Network" is refused' );
$rw_r = Role_Service::create( $rw_admin, 'Manage Network Options', array( 'read' => true ) );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'manage_network_options' ), 'roles screen: "Manage Network Options" is refused' );
$rw_r = Role_Service::create( $rw_admin, 'Manage Sites', array( 'read' => true ) );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'manage_sites' ), 'roles screen: "Manage Sites" is refused' );
$rw_r = Role_Service::clone_role( $rw_admin, 'subscriber', 'Manage Network Users' );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'manage_network_users' ), 'roles screen: clone to "Manage Network Users" is refused' );
$rw_r = Ops::add_role( $rw_admin, 'Net', 'manage_network_users', array( 'read' ) );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'manage_network_users' ), 'automation: add_role manage_network_users is refused' );
$rw_r = Ops::clone_role( $rw_admin, 'subscriber', 'Sites', 'create_sites' );
$rw_ok( is_wp_error( $rw_r ) && ! get_role( 'create_sites' ), 'automation: clone_role to create_sites is refused' );
$rw_json = wp_json_encode(
	array(
		'format'  => Ops::FORMAT,
		'version' => Ops::VERSION,
		'roles'   => array(
			'manage_sites' => array(
				'name'         => 'Sites',
				'capabilities' => array( 'read' => true ),
			),
		),
	)
);
$rw_r    = Ops::import_json( $rw_admin, $rw_json, false );
$rw_ok( ! get_role( 'manage_sites' ), 'automation: import_json does not create manage_sites' );
$rw_ok( false === Importer::sanitize_role_slug( 'manage_network' ) && false === Importer::sanitize_role_slug( 'setup_network' ), 'portability: importer refuses network cap slugs' );

$rw_row = Store::insert(
	array(
		'type'        => 'role.deleted',
		'actor_id'    => $rw_admin,
		'target'      => 'manage_network_options',
		'diff'        => array( 'caps' => array( 'removed' => array( 'read' ) ) ),
		'detail'      => array( 'label' => 'Net' ),
		'ip_hash'     => '',
		'reverted_of' => 0,
	)
);
$rw_r   = $rw_row ? Reverter::revert( $rw_row, $rw_admin ) : new WP_Error( 'no_row' );
$rw_ok( $rw_row && is_wp_error( $rw_r ) && ! get_role( 'manage_network_options' ), 'audit: reverting a role.deleted for manage_network_options is refused' );

if ( is_multisite() && class_exists( '\\Rolegate\\Modules\\Multisite\\Network_Sync' ) ) {
	$rw_out = \Rolegate\Modules\Multisite\Network_Sync::apply_to_site(
		get_current_blog_id(),
		array(
			'manage_network' => array(
				'name'         => 'Net',
				'capabilities' => array( 'read' => true ),
			),
		),
		'replace',
		$rw_admin
	);
	$rw_ok( 0 === $rw_out['roles'] && $rw_out['errors'] && ! get_role( 'manage_network' ), 'network sync: copying a manage_network role is refused' );
}

// Defence in depth: a role named after a critical cap that already exists grants nothing.
Enforcer::as_system(
	function () use ( $rw_sub ) {
		add_role( 'manage_network_options', 'Planted', array( 'read' => true ) );
		add_role( 'manage_options', 'Planted 2', array( 'read' => true ) );
		$u = get_userdata( $rw_sub );
		$u->add_role( 'manage_network_options' );
		$u->add_role( 'manage_options' );
	}
);
$rw_roles[] = 'manage_network_options';
$rw_roles[] = 'manage_options';
$rw_pup     = get_userdata( $rw_sub );
$rw_ok( in_array( 'manage_network_options', (array) $rw_pup->roles, true ), 'planted: subscriber holds the planted role (setup)' );
$rw_ok( ! user_can( $rw_sub, 'manage_network_options' ) && ! user_can( $rw_sub, 'manage_options' ), 'planted: holding a role named after a critical cap does not grant the cap' );
$rw_ok( ! in_array( 'manage_network_options', Guard::user_critical_caps( $rw_sub ), true ) && ! in_array( 'manage_options', Guard::user_critical_caps( $rw_sub ), true ), 'planted: Guard does not count the role name as a held cap' );
$rw_ok( user_can( $rw_admin, 'manage_options' ), 'planted: administrator still holds manage_options (control)' );
$rw_ok( ! Guard::can_assign_role( $rw_admin, 'manage_network_options', $rw_sub ) || Guard::is_super( $rw_admin ), 'planted: an actor without the cap may not assign the colliding role' );
$rw_admin2 = $rw_make( 'rw_hard_admin2', 'subscriber' );
get_userdata( $rw_admin2 )->add_role( 'manage_network_options' );
$rw_ok( ! in_array( 'manage_network_options', (array) get_userdata( $rw_admin2 )->roles, true ) || Guard::is_super( $rw_admin ), 'planted: the user-meta backstop refuses giving the colliding role' );
Enforcer::as_system(
	function () use ( $rw_sub ) {
		$u = get_userdata( $rw_sub );
		$u->remove_role( 'manage_network_options' );
		$u->remove_role( 'manage_options' );
		remove_role( 'manage_network_options' );
		remove_role( 'manage_options' );
	}
);
add_role( 'manage_sites', 'Planted 3', array( 'read' => true ) );
$rw_stored = get_option( $GLOBALS['wpdb']->get_blog_prefix() . 'user_roles' );
$rw_ok( is_array( $rw_stored ) && isset( $rw_stored['subscriber'] ) && ! isset( $rw_stored['manage_sites'] ), 'planted: the roles-option backstop refuses storing a new role named after a network cap' );
if ( get_role( 'manage_sites' ) ) {
	Enforcer::as_system(
		function () {
			remove_role( 'manage_sites' );
		}
	);
}

// 4. Per-user caps and roles, both orders. On multisite core refuses edit_user to a site
// admin, so the per-user cap edits run as a super admin there.
$rw_boss   = 'rw_seo_boss_' . $rw_suffix;
$rw_capper = $rw_admin;
if ( is_multisite() ) {
	$rw_supers = get_super_admins();
	$rw_capper = (int) get_user_by( 'login', $rw_supers[0] )->ID;
}
$rw_r = Users::change_caps( $rw_capper, $rw_sub, array( $rw_boss ), array() );
$rw_ok( true === $rw_r && ! empty( get_userdata( $rw_sub )->caps[ $rw_boss ] ), 'cap then role: per-user cap granted (setup)' );
$rw_r = Role_Service::create( $rw_admin, 'Rw Seo Boss ' . $rw_suffix, array( 'read' => true, 'edit_others_posts' => true ) );
$rw_ok( 'rolegate_slug_held_as_cap' === $rw_code( $rw_r ) && ! get_role( $rw_boss ), 'cap then role: roles screen refuses a slug held as a per-user cap' );
$rw_r = Ops::add_role( $rw_admin, 'Boss', $rw_boss, array( 'read' ) );
$rw_ok( 'rolegate_slug_held_as_cap' === $rw_code( $rw_r ) && ! get_role( $rw_boss ), 'cap then role: automation refuses a slug held as a per-user cap' );
$rw_ok( ! user_can( $rw_sub, 'edit_others_posts' ) && ! in_array( $rw_boss, (array) get_userdata( $rw_sub )->roles, true ), 'cap then role: the holder did not become a member' );

$rw_lead = Role_Service::create( $rw_admin, 'Rw Lead ' . $rw_suffix, array( 'read' => true ) );
$rw_roles[] = is_string( $rw_lead ) ? $rw_lead : '';
$rw_r       = Users::change_caps( $rw_capper, $rw_sub, array( (string) $rw_lead ), array() );
$rw_ok( is_string( $rw_lead ) && is_wp_error( $rw_r ) && ! in_array( $rw_lead, (array) get_userdata( $rw_sub )->roles, true ), 'role then cap: a per-user cap named after an existing role is refused' );
if ( ! get_role( 'shop_manager' ) ) {
	$rw_r = Users::change_caps( $rw_capper, $rw_sub, array( 'shop_manager' ), array() );
	$rw_ok( 'rolegate_cap_is_role' === $rw_code( $rw_r ), 'role then cap: a per-user cap named after a known plugin role (shop_manager) is refused' );
}

// 2. Module and automation settings need administrator-level authority.
$rw_lead_caps = array_merge( get_role( 'editor' )->capabilities, array( Caps::MANAGE => true, Caps::MANAGE_USERS => true, 'promote_users' => true ) );
add_role( 'rw_hard_lead', 'Hard Lead', $rw_lead_caps );
$rw_roles[]   = 'rw_hard_lead';
$rw_delegate  = $rw_make( 'rw_hard_lead', 'rw_hard_lead' );
$rw_mod_orig  = get_option( 'rolegate_modules' );
$rw_auto_orig = get_option( Automation_Module::OPTION_SETTINGS );
$rw_enabled   = array();
foreach ( \Rolegate\Core\Plugin::modules() as $rw_m ) {
	if ( \Rolegate\Core\Plugin::is_enabled( $rw_m->id() ) ) {
		$rw_enabled[] = $rw_m->id();
	}
}
$rw_ok( user_can( $rw_delegate, Caps::MANAGE ) && ! Settings::can_change( $rw_delegate ), 'modules: a rolegate_manage delegate is not a settings authority' );
$rw_ok( Settings::can_change( $rw_admin ), 'modules: a full administrator is a settings authority (control)' );
$rw_r = Settings::apply_modules( $rw_delegate, array_diff( $rw_enabled, array( 'deny-hierarchy', 'content-access' ) ) );
$rw_ok( 'rolegate_not_authority' === $rw_code( $rw_r ) && get_option( 'rolegate_modules' ) === $rw_mod_orig, 'modules: a delegate cannot switch modules off' );
$rw_r = Automation_Page::apply(
	$rw_delegate,
	array(
		'rest_writes'      => true,
		'abilities_writes' => true,
	)
);
$rw_ok( 'rolegate_not_authority' === $rw_code( $rw_r ) && get_option( Automation_Module::OPTION_SETTINGS ) === $rw_auto_orig, 'automation: a delegate cannot switch writes on' );

if ( in_array( 'deny-hierarchy', $rw_enabled, true ) ) {
	$rw_den_orig = get_option( 'rolegate_denied_caps' );
	update_option( 'rolegate_denied_caps', array( 'administrator' => array( 'moderate_comments' ) ) );
	\Rolegate\Modules\Deny_Hierarchy\Denials::reset_cache();
	$rw_r = Settings::apply_modules( $rw_admin, array_diff( $rw_enabled, array( 'deny-hierarchy' ) ) );
	$rw_ok( 'rolegate_module_applies_to_actor' === $rw_code( $rw_r ) && get_option( 'rolegate_modules' ) === $rw_mod_orig, 'modules: an admin cannot switch off a module whose rules apply to them' );
	update_option( 'rolegate_denied_caps', $rw_den_orig ? $rw_den_orig : array() );
	\Rolegate\Modules\Deny_Hierarchy\Denials::reset_cache();
}
$rw_off = in_array( 'login-redirects', $rw_enabled, true ) ? 'login-redirects' : 'portability';
$rw_r   = Settings::apply_modules( $rw_admin, array_diff( $rw_enabled, array( $rw_off ) ) );
$rw_ev  = $rw_last( 'modules.updated' );
$rw_ok( true === $rw_r && $rw_ev && ! empty( $rw_ev['before'][ $rw_off ] ) && empty( $rw_ev['after'][ $rw_off ] ) && $rw_admin === $rw_ev['actor'], 'modules: an authority switching a module off fires modules.updated with before and after' );
update_option( 'rolegate_modules', $rw_mod_orig, false );
$rw_r  = Automation_Page::apply(
	$rw_admin,
	array(
		'rest_writes'      => true,
		'abilities_writes' => false,
	)
);
$rw_ev = $rw_last( 'automation.updated' );
$rw_ok( true === $rw_r && $rw_ev && ! empty( $rw_ev['after']['rest_writes'] ) && empty( $rw_ev['before']['rest_writes'] ) === empty( $rw_auto_orig['rest_writes'] ), 'automation: an authority change fires automation.updated with before and after' );
update_option( Automation_Module::OPTION_SETTINGS, $rw_auto_orig, false );

// 3. Default registration roles can't gain critical caps.
$rw_default_orig = (string) get_option( 'default_role' );
$rw_extra_orig   = get_option( Role_Service::OPTION_EXTRA, array() );
update_option( 'default_role', 'subscriber' );
$rw_sub_caps = get_role( 'subscriber' )->capabilities;
$rw_r        = Guard::assert_can_modify_role( $rw_admin, 'subscriber', array_merge( $rw_sub_caps, array( 'edit_users' => true, 'promote_users' => true ) ) );
$rw_ok( 'rolegate_default_too_powerful' === $rw_code( $rw_r ), 'default role: adding critical caps to the default role is refused' );
$rw_ok( true === Guard::assert_can_modify_role( $rw_admin, 'subscriber', array_merge( $rw_sub_caps, array( 'upload_files' => true ) ) ), 'default role: a non-critical addition passes (control)' );
add_role( 'rw_hard_extra', 'Hard Extra', array( 'read' => true ) );
$rw_roles[] = 'rw_hard_extra';
update_option( Role_Service::OPTION_EXTRA, array( 'rw_hard_extra' ) );
$rw_r = Guard::assert_can_modify_role( $rw_admin, 'rw_hard_extra', array( 'read' => true, 'unfiltered_html' => true ) );
$rw_ok( 'rolegate_default_too_powerful' === $rw_code( $rw_r ), 'default role: adding a critical cap to an extra default role is refused' );
update_option( Role_Service::OPTION_EXTRA, array() );
$rw_ok( true === Guard::assert_can_modify_role( $rw_admin, 'rw_hard_extra', array( 'read' => true, 'unfiltered_html' => true ) ), 'default role: the same change on a non-default role passes (control)' );

Enforcer::as_system(
	function () {
		get_role( 'subscriber' )->add_cap( 'edit_users' );
	}
);
add_filter( 'rolegate_trust_anonymous_user_creation', '__return_false' );
wp_set_current_user( 0 );
$rw_anon = $rw_make( 'rw_hard_anon', 'subscriber' );
wp_set_current_user( $rw_admin );
remove_filter( 'rolegate_trust_anonymous_user_creation', '__return_false' );
Enforcer::as_system(
	function () {
		get_role( 'subscriber' )->remove_cap( 'edit_users' );
	}
);
$rw_ok( $rw_anon && ! in_array( 'subscriber', (array) get_userdata( $rw_anon )->roles, true ), 'registration: an anonymous registrant does not keep a default role that carries a critical cap' );
wp_set_current_user( 0 );
add_filter( 'rolegate_trust_anonymous_user_creation', '__return_false' );
$rw_anon2 = $rw_make( 'rw_hard_anon2', 'subscriber' );
remove_filter( 'rolegate_trust_anonymous_user_creation', '__return_false' );
wp_set_current_user( $rw_admin );
$rw_ok( in_array( 'subscriber', (array) get_userdata( $rw_anon2 )->roles, true ), 'registration: an ordinary default role is kept (control)' );
update_option( 'default_role', $rw_default_orig );
update_option( Role_Service::OPTION_EXTRA, $rw_extra_orig );

// 5. Restricted posts and direct lookups.
if ( class_exists( Access::class ) && \Rolegate\Core\Plugin::is_enabled( 'content-access' ) ) {
	$rw_secret = wp_insert_post(
		array(
			'post_title'  => 'Rw secret ' . $rw_suffix,
			'post_name'   => 'rw-secret-' . $rw_suffix,
			'post_status' => 'publish',
			'post_type'   => 'post',
		)
	);
	$rw_open   = wp_insert_post(
		array(
			'post_title'  => 'Rw open ' . $rw_suffix,
			'post_status' => 'publish',
			'post_type'   => 'post',
		)
	);
	$rw_page   = wp_insert_post(
		array(
			'post_title'  => 'Rw page ' . $rw_suffix,
			'post_name'   => 'rw-page-' . $rw_suffix,
			'post_status' => 'publish',
			'post_type'   => 'page',
		)
	);
	$rw_posts  = array( $rw_secret, $rw_open, $rw_page );
	update_post_meta( $rw_secret, Access::META_ROLES, array( 'administrator' ) );
	update_post_meta( $rw_page, Access::META_ROLES, array( 'administrator' ) );
	Access::flush();
	wp_set_current_user( 0 );
	$rw_ids = function ( $args ) {
		$q = new WP_Query( array_merge( array( 'fields' => 'ids', 'ignore_sticky_posts' => true, 'post_type' => 'any' ), $args ) );
		return array_map( 'intval', $q->posts );
	};
	$rw_ok( array() === $rw_ids( array( 'post__in' => array( $rw_secret ) ) ), 'post__in: a restricted post is not returned to a visitor' );
	$rw_ok( array( $rw_open ) === $rw_ids( array( 'post__in' => array( $rw_secret, $rw_open ) ) ), 'post__in: open posts in the same list still come back (control)' );
	$rw_ok( array() === wp_list_pluck( get_posts( array( 'include' => array( $rw_secret ) ) ), 'ID' ), 'get_posts include: a restricted post is not returned' );
	$rw_ok( array() === $rw_ids( array( 'p' => $rw_secret ) ), 'p=: a restricted post is not returned by a secondary query' );
	$rw_ok( array() === $rw_ids( array( 'page_id' => $rw_page ) ), 'page_id=: a restricted page is not returned' );
	$rw_ok( array() === $rw_ids( array( 'name' => 'rw-secret-' . $rw_suffix ) ), 'name=: a restricted post is not returned' );
	$rw_ok( array() === $rw_ids( array( 'pagename' => 'rw-page-' . $rw_suffix ) ), 'pagename=: a restricted page is not returned' );
	$rw_ok( ! in_array( $rw_secret, $rw_ids( array( 's' => 'Rw secret ' . $rw_suffix ) ), true ), 'search: a restricted post is not found' );
	$rw_args = apply_filters( 'wp_sitemaps_posts_query_args', array( 'post__in' => array( $rw_secret ) ), 'post' );
	$rw_ok( ! in_array( $rw_secret, array_map( 'intval', (array) $rw_args['post__in'] ), true ), 'sitemaps: a restricted post is removed from post__in' );
	$rw_ok( array( $rw_open ) === $rw_ids( array( 'p' => $rw_open ) ), 'p=: an open post is returned (control)' );

	// 6c. The rule meta is not readable over REST by users who can't edit the post.
	update_post_meta( $rw_open, Access::META_ROLES, array( 'subscriber', 'administrator' ) );
	update_post_meta( $rw_open, Access::META_MESSAGE, 'Members only ' . $rw_suffix );
	Access::flush();
	do_action( 'rest_api_init', rest_get_server() );
	wp_set_current_user( $rw_sub );
	$rw_resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/posts/' . $rw_open ) );
	$rw_data = $rw_resp->get_data();
	$rw_ok( 200 === $rw_resp->get_status() && empty( $rw_data['meta'][ Access::META_ROLES ] ) && empty( $rw_data['meta'][ Access::META_MESSAGE ] ), 'REST: a viewer without edit rights does not see the rule meta' );
	wp_set_current_user( $rw_admin );
	$rw_resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/posts/' . $rw_open ) );
	$rw_data = $rw_resp->get_data();
	$rw_ok( ! empty( $rw_data['meta'][ Access::META_ROLES ] ), 'REST: an editor of the post still sees the rule meta (control)' );
}
wp_set_current_user( $rw_admin );

// 6b. Rescue request timing does not depend on whether the address is an admin.
add_filter( 'pre_wp_mail', '__return_true' );
$rw_time = function ( $email, $ip ) {
	$t = microtime( true );
	$r = Rescue::request( $email, $ip );
	return array( microtime( true ) - $t, $r );
};
$rw_unknown = $rw_time( 'nobody_' . $rw_suffix . '@example.com', '203.0.113.' . wp_rand( 1, 250 ) );
$rw_known   = $rw_time( get_userdata( $rw_admin )->user_email, '198.51.100.' . wp_rand( 1, 250 ) );
remove_filter( 'pre_wp_mail', '__return_true' );
$rw_ok( true === $rw_known[1] && false === $rw_unknown[1], 'rescue: the eligible address gets a link, the unknown one does not (setup)' );
$rw_ok( $rw_unknown[0] >= Rescue::FLOOR - 0.01 && $rw_known[0] >= Rescue::FLOOR - 0.01 && abs( $rw_known[0] - $rw_unknown[0] ) < 0.1, sprintf( 'rescue: both paths take the floor time (unknown %.3fs, admin %.3fs)', $rw_unknown[0], $rw_known[0] ) );
delete_user_meta( $rw_admin, Rescue::META );

// 6d. Reverts never target the actor's own roles or per-user caps.
foreach (
	array(
		array( 'user.roles', array( 'roles' => array( 'added' => array( 'subscriber' ) ) ), 'rolegate_self_role' ),
		array( 'user.caps', array( 'caps' => array( 'added' => array( 'rw_self_' . $rw_suffix ) ) ), 'rolegate_self_caps' ),
	) as $rw_case
) {
	$rw_row = Store::insert(
		array(
			'type'        => $rw_case[0],
			'actor_id'    => $rw_admin,
			'target'      => (string) $rw_admin,
			'diff'        => $rw_case[1],
			'detail'      => array(),
			'ip_hash'     => '',
			'reverted_of' => 0,
		)
	);
	$rw_r   = $rw_row ? Reverter::revert( $rw_row, $rw_admin ) : new WP_Error( 'no_row' );
	$rw_ok( $rw_case[2] === $rw_code( $rw_r ), "audit: reverting {$rw_case[0]} on the actor's own account is refused" );
}
$rw_ok( in_array( 'administrator', (array) get_userdata( $rw_admin )->roles, true ), 'audit: the actor kept the administrator role' );

// 7b. Known plugin admin caps are critical, and sites can extend the list.
foreach ( array( 'manage_woocommerce', 'view_woocommerce_reports', 'gform_full_access', 'gravityforms_edit_forms', 'wpseo_manage_options' ) as $rw_cap ) {
	$rw_ok( Guard::is_critical_cap( $rw_cap ), "critical: {$rw_cap}" );
}
$rw_extend = function ( $caps ) {
	$caps[] = 'rw_site_admin_cap';
	return $caps;
};
add_filter( 'rolegate_critical_caps', $rw_extend );
$rw_ok( Guard::is_critical_cap( 'rw_site_admin_cap' ), 'critical: the filter extends the list' );
remove_filter( 'rolegate_critical_caps', $rw_extend );

// Cleanup.
wp_set_current_user( $rw_admin );
foreach ( $rw_posts as $rw_p ) {
	wp_delete_post( $rw_p, true );
}
Enforcer::as_system(
	function () use ( $rw_users, $rw_roles ) {
		foreach ( array_unique( $rw_users ) as $uid ) {
			is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
		}
		foreach ( $rw_roles as $r ) {
			if ( is_string( $r ) && '' !== $r && get_role( $r ) ) {
				remove_role( $r );
			}
		}
	}
);
Caps::grant_to_administrator();

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
