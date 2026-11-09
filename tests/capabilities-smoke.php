<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/capabilities-smoke.php
 */

use Rolegate\Modules\Capabilities\Cap_Catalog;
use Rolegate\Modules\Capabilities\Cap_Editor;
use Rolegate\Modules\Capabilities\Cap_Service;
use Rolegate\Modules\Capabilities\Cap_Sets;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Roles\Role_Store;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Enforcer;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

// Multisite: site administrators hold rolegate_* caps only when the network grants it; these checks are about role-based access, so grant it.
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

$rw_snapshot = Role_Store::all();
$rw_opts     = array(
	Cap_Catalog::OPTION_CUSTOM => get_option( Cap_Catalog::OPTION_CUSTOM, null ),
	Cap_Sets::OPTION_SETS      => get_option( Cap_Sets::OPTION_SETS, null ),
	Cap_Sets::OPTION_CPT       => get_option( Cap_Sets::OPTION_CPT, null ),
);

$rw_admin = $rw_make( 'rw_caps_admin', 'administrator' );
wp_set_current_user( $rw_admin );

// Catalog: grouping and labels.
$cpt = Cap_Catalog::post_type_caps();
$rw_ok( 'posts' === Cap_Catalog::group_of( 'edit_others_posts', $cpt ), 'catalog: edit_others_posts is in posts' );
$rw_ok( 'pages' === Cap_Catalog::group_of( 'publish_pages', $cpt ), 'catalog: publish_pages is in pages' );
$rw_ok( 'settings' === Cap_Catalog::group_of( 'manage_options', $cpt ), 'catalog: manage_options is in settings' );
$rw_ok( 'users' === Cap_Catalog::group_of( 'promote_users', $cpt ) && 'plugins' === Cap_Catalog::group_of( 'activate_plugins', $cpt ) && 'themes' === Cap_Catalog::group_of( 'switch_themes', $cpt ), 'catalog: users, plugins, themes groups' );
$rw_ok( 'media' === Cap_Catalog::group_of( 'upload_files', $cpt ) && 'tools' === Cap_Catalog::group_of( 'import', $cpt ) && 'appearance' === Cap_Catalog::group_of( 'edit_theme_options', $cpt ) && 'general' === Cap_Catalog::group_of( 'read', $cpt ), 'catalog: media, tools, appearance, general groups' );
$rw_ok( 'deprecated' === Cap_Catalog::group_of( 'level_7' ) && 'deprecated' === Cap_Catalog::group_of( 'edit_files' ), 'catalog: level and legacy caps are deprecated' );
$rw_ok( 'plugin:woocommerce' === Cap_Catalog::group_of( 'manage_woocommerce' ) && 'plugin:woocommerce' === Cap_Catalog::group_of( 'edit_shop_orders' ), 'catalog: WooCommerce caps grouped' );
$rw_ok( 'plugin:bbpress' === Cap_Catalog::group_of( 'keep_gate' ) && 'plugin:edd' === Cap_Catalog::group_of( 'view_shop_reports' ) && 'plugin:give' === Cap_Catalog::group_of( 'view_give_reports' ), 'catalog: bbPress, EDD, GiveWP caps grouped' );
$rw_ok( 'plugin:acf' === Cap_Catalog::group_of( 'acf_manage_x' ) && 'plugin:metabox' === Cap_Catalog::group_of( 'mb_edit' ), 'catalog: ACF and Meta Box caps grouped' );
$rw_ok( 'custom' === Cap_Catalog::group_of( 'rw_reports_' . $rw_suffix ), 'catalog: unknown cap goes to custom' );
$rw_ok( 'Edit others posts' === Cap_Catalog::label( 'edit_others_posts' ) && 'User level 4' === Cap_Catalog::label( 'level_4' ), 'catalog: human-readable labels' );
$groups = Cap_Catalog::grouped( Cap_Catalog::universe() );
$rw_ok( array_slice( array_keys( $groups ), 0, 3 ) === array( 'general', 'posts', 'pages' ), 'catalog: core groups come first in order' );

// Editing a role.
$rw_role = Role_Service::create( $rw_admin, 'RW Caps ' . $rw_suffix, array( 'read' => true, 'edit_posts' => true, 'delete_posts' => true ) );
$rw_member = $rw_make( 'rw_caps_member', $rw_role );
$res = Cap_Service::update_role( $rw_admin, $rw_role, array( 'read', 'edit_posts', 'upload_files' ) );
$rw_ok( is_array( $res ) && array( 'upload_files' ) === $res['added'] && array( 'delete_posts' ) === $res['removed'], 'update: reports added and removed caps' );
$caps = Role_Store::caps( $rw_role );
$rw_ok( ! empty( $caps['upload_files'] ) && empty( $caps['delete_posts'] ) && ! empty( $caps['edit_posts'] ), 'update: role caps changed in storage' );
$ev = $rw_last( 'caps.updated' );
$rw_ok( $ev && $ev['target'] === $rw_role && isset( $ev['before']['caps']['delete_posts'] ) && ! isset( $ev['after']['caps']['delete_posts'] ), 'update: caps.updated carries before and after' );

$res = Cap_Service::update_role( $rw_admin, $rw_role, array( 'read', 'edit_posts', 'upload_files' ), null, array( 'rw_reports_' . $rw_suffix ) );
$rw_ok( is_array( $res ) && ! empty( Role_Store::caps( $rw_role )[ 'rw_reports_' . $rw_suffix ] ), 'custom cap: added and granted to the role' );
$rw_ok( in_array( 'rw_reports_' . $rw_suffix, Cap_Catalog::custom_caps(), true ), 'custom cap: remembered in the custom list' );
$rw_ok( is_wp_error( Cap_Service::update_role( $rw_admin, $rw_role, array( 'read' ), null, array( 'Bad Cap!' ) ) ), 'custom cap: invalid name refused' );
$rw_ok( is_wp_error( Cap_Service::update_role( $rw_admin, $rw_role, array( 'read' ), null, array( 'editor' ) ) ), 'custom cap: role name refused as capability' );

// Levels.
$res = Cap_Service::update_role( $rw_admin, $rw_role, array( 'read', 'edit_posts', 'upload_files', 'rw_reports_' . $rw_suffix ), 3 );
$caps = Role_Store::caps( $rw_role );
$rw_ok( ! empty( $caps['level_0'] ) && ! empty( $caps['level_3'] ) && empty( $caps['level_4'] ) && 3 === Cap_Service::level_of( $caps ), 'level: 3 gives level_0 to level_3 only' );
clean_user_cache( $rw_member );
$rw_ok( 3 === (int) get_user_meta( $rw_member, $GLOBALS['wpdb']->get_blog_prefix() . 'user_level', true ), 'level: existing users get the new user_level' );
Cap_Service::update_role( $rw_admin, $rw_role, array( 'read', 'edit_posts', 'upload_files', 'rw_reports_' . $rw_suffix ), -1 );
$rw_ok( -1 === Cap_Service::level_of( Role_Store::caps( $rw_role ) ), 'level: none removes the level caps' );

// Escalation: a caps manager can't hand out critical caps they lack.
$rw_mgr_role = Role_Service::create( $rw_admin, 'RW Capmgr ' . $rw_suffix, array( 'read' => true, Caps::MANAGE => true, Caps::MANAGE_CAPS => true, Caps::MANAGE_ROLES => true ) );
$rw_mgr      = $rw_make( 'rw_caps_mgr', $rw_mgr_role );
wp_set_current_user( $rw_mgr );
$res = Cap_Service::update_role( $rw_mgr, $rw_role, array( 'read', 'edit_posts', 'manage_options' ) );
$rw_ok( is_wp_error( $res ) && 'rolegate_cap_not_held' === $res->get_error_code(), 'escalation: can\'t grant manage_options without holding it' );
$res = Cap_Service::update_role( $rw_mgr, 'administrator', array( 'read' ) );
$rw_ok( is_wp_error( $res ), 'escalation: can\'t edit the administrator role' );

// Lockout and self-edit confirmation.
$res = Cap_Service::update_role( $rw_mgr, $rw_mgr_role, array( 'read', Caps::MANAGE_CAPS, Caps::MANAGE_ROLES ) );
$rw_ok( is_wp_error( $res ) && 'rolegate_confirm' === $res->get_error_code() && array( Caps::MANAGE ) === $res->get_error_data()['removed'], 'self-edit: removing a cap from own role asks for confirmation' );
// With the role hierarchy on, a user below the top can't edit their own role at all.
$rw_hier    = \Rolegate\Core\Plugin::is_enabled( 'deny-hierarchy' );
$rw_refused = function ( $res, $code ) use ( $rw_hier ) {
	return is_wp_error( $res ) && ( $code === $res->get_error_code() || ( $rw_hier && 'rolegate_role_above_position' === $res->get_error_code() ) );
};
$res = Cap_Service::update_role( $rw_mgr, $rw_mgr_role, array( 'read', Caps::MANAGE_CAPS, Caps::MANAGE_ROLES ), null, array(), true );
$rw_ok( $rw_refused( $res, 'rolegate_lockout' ), 'lockout: confirmed removal of rolegate_manage is still refused' );
$res = Cap_Service::update_role( $rw_mgr, $rw_mgr_role, array( Caps::MANAGE, Caps::MANAGE_CAPS, Caps::MANAGE_ROLES ), null, array(), true );
$rw_ok( $rw_refused( $res, 'rolegate_lockout' ), 'lockout: removing read from own role refused' );
$res = Cap_Service::update_role( $rw_mgr, $rw_mgr_role, array( 'read', Caps::MANAGE, Caps::MANAGE_CAPS, Caps::MANAGE_ROLES, 'upload_files' ) );
$rw_ok( $rw_hier ? $rw_refused( $res, '' ) : is_array( $res ), 'self-edit: adding a cap to own role needs no confirmation (refused under the hierarchy)' );
$res = Cap_Service::update_role( $rw_mgr, $rw_mgr_role, array( 'read', Caps::MANAGE, Caps::MANAGE_CAPS, Caps::MANAGE_ROLES ), null, array(), true );
$rw_ok( $rw_hier ? $rw_refused( $res, '' ) : ( is_array( $res ) && array( 'upload_files' ) === $res['removed'] ), 'self-edit: confirmed harmless removal goes through (refused under the hierarchy)' );
wp_set_current_user( $rw_admin );
$res = Cap_Service::update_role( $rw_admin, 'administrator', array_diff( array_keys( array_filter( Role_Store::caps( 'administrator' ) ) ), array( Caps::MANAGE_ROLES ) ), null, array(), true );
$rw_ok( is_wp_error( $res ) && 'rolegate_protected_role' === $res->get_error_code(), 'lockout: administrator can\'t lose rolegate_manage_roles' );

// Deleting custom caps.
$cc = 'rw_reports_' . $rw_suffix;
$rw_ok( is_wp_error( Cap_Service::delete_custom_cap( $rw_admin, 'edit_posts' ) ), 'delete cap: core cap refused' );
$rw_ok( is_wp_error( Cap_Service::delete_custom_cap( $rw_admin, Caps::MANAGE ) ), 'delete cap: Role Gatekeeper cap refused' );
get_role( 'editor' )->add_cap( $cc );
$gone = Cap_Service::delete_custom_cap( $rw_admin, $cc );
$rw_ok( is_array( $gone ) && in_array( $rw_role, $gone, true ) && in_array( 'editor', $gone, true ), 'delete cap: removed from every role holding it' );
$rw_ok( ! array_key_exists( $cc, Role_Store::caps( $rw_role ) ) && ! array_key_exists( $cc, Role_Store::caps( 'editor' ) ) && ! in_array( $cc, Cap_Catalog::custom_caps(), true ), 'delete cap: gone from roles and the custom list' );

// Extra cap sets.
$types_before = Cap_Sets::eligible_post_types();
register_post_type( 'rwbook', array( 'public' => true, 'show_ui' => true, 'labels' => array( 'name' => 'RW Books' ) ) );
$rw_ok( isset( Cap_Sets::eligible_post_types()['rwbook'] ), 'cpt: a plain custom post type is offered' );
$res = Cap_Service::save_options( $rw_admin, array( 'create', 'terms', 'privacy' ), array( 'rwbook' ) );
$rw_ok( true === $res, 'options: saved' );
$rw_ok( array( 'create', 'terms', 'privacy' ) === Cap_Sets::enabled() && array( 'rwbook' ) === Cap_Sets::cpt_own(), 'options: stored' );
$ed = Role_Store::caps( 'editor' );
$rw_ok( ! empty( $ed['create_posts'] ) && ! empty( $ed['create_pages'] ) && ! empty( $ed['edit_categories'] ) && ! empty( $ed['assign_post_tags'] ), 'options: editor got create and category/tag caps' );
$au = Role_Store::caps( 'author' );
$rw_ok( ! empty( $au['create_posts'] ) && empty( $au['create_pages'] ) && ! empty( $au['assign_categories'] ) && empty( $au['edit_categories'] ), 'options: author got only what its core caps justify' );
$ad = Role_Store::caps( 'administrator' );
$rw_ok( is_multisite() ? empty( $ad['manage_privacy_options'] ) && empty( $ed['manage_privacy_options'] ) : ! empty( $ad['manage_privacy_options'] ) && ! empty( $ad['export_others_personal_data'] ) && empty( $ed['manage_privacy_options'] ), 'options: privacy caps went to roles with manage_options only (single sites only; none added on multisite)' );
$rw_ok( ! empty( $ed['edit_rwbooks'] ) && ! empty( $ed['edit_others_rwbooks'] ) && empty( $au['edit_others_rwbooks'] ) && ! empty( $au['publish_rwbooks'] ), 'cpt: own caps granted by matching core post caps' );
$ev = $rw_last( 'caps.options_updated' );
$rw_ok( $ev && isset( $ev['before']['sets'], $ev['after']['sets'] ) && array( 'create', 'terms', 'privacy' ) === $ev['after']['sets'], 'options: fires caps.options_updated with before and after' );

$sets = new Cap_Sets();
$args = $sets->post_type_args( array(), 'post' );
$rw_ok( 'create_posts' === $args['capabilities']['create_posts'], 'filter: post type args map create_posts' );
$args = $sets->taxonomy_args( array(), 'post_tag' );
$rw_ok( 'edit_post_tags' === $args['capabilities']['edit_terms'], 'filter: tag taxonomy gets its own caps' );
$rw_ok( array( 'manage_privacy_options' ) === $sets->privacy_caps( array( 'manage_options' ), 'manage_privacy_options' ) || is_multisite(), 'filter: privacy cap maps to itself' );
$rw_tx    = 0;
$rw_count = function ( $t, $text, $domain ) use ( &$rw_tx ) {
	if ( 'role-gatekeeper' === $domain ) {
		++$rw_tx;
	}
	return $t;
};
add_filter( 'gettext', $rw_count, 10, 3 );
Cap_Sets::enabled();
Cap_Sets::is_enabled( 'privacy' );
$sets->privacy_caps( array( 'manage_options' ), 'manage_privacy_options' );
$sets->post_type_args( array(), 'post' );
$sets->taxonomy_args( array(), 'category' );
remove_filter( 'gettext', $rw_count, 10 );
$rw_ok( 0 === $rw_tx, 'filters that can run before init translate nothing (' . $rw_tx . ' strings)' );
$rw_ok( array_keys( Cap_Sets::definitions() ) === Cap_Sets::SET_IDS, 'set ids match the labelled definitions' );
unregister_post_type( 'rwbook' );
register_post_type( 'rwbook', array( 'public' => true, 'show_ui' => true ) );
$obj = get_post_type_object( 'rwbook' );
$rw_ok( 'edit_rwbooks' === $obj->cap->edit_posts && 'edit_others_rwbooks' === $obj->cap->edit_others_posts, 'cpt: registered post type uses its own capability names' );
$rw_ok( user_can( get_userdata( $rw_admin ), 'edit_rwbooks' ), 'cpt: administrator can use the new capability' );

// The editor page.
wp_set_current_user( $rw_admin );
$_REQUEST['role'] = $rw_role;
ob_start();
( new Cap_Editor() )->render();
$html = ob_get_clean();
$rw_ok( false !== strpos( $html, 'id="rw-caps-form"' ) && false !== strpos( $html, '_wpnonce' ), 'page: editor form and nonce render' );
$rw_ok( false !== strpos( $html, 'id="rw-search"' ) && false !== strpos( $html, 'class="rw-all"' ), 'page: search filter and select-all render' );
$rw_ok( 1 === preg_match( '/<fieldset class="rw-group rw-deprecated" data-group="deprecated" hidden>/', $html ), 'page: deprecated group is hidden by default' );
$rw_ok( 0 === preg_match( '/name="caps\[\]" value="level_/', $html ) && false !== strpos( $html, 'id="rw-level"' ), 'page: level caps are edited through the level select' );
$rw_ok( 1 === preg_match( '/name="caps\[\]" value="upload_files" checked/', $html ) && 0 === preg_match( '/name="caps\[\]" value="manage_options" checked/', $html ), 'page: current caps are ticked for the chosen role' );
$rw_ok( false !== strpos( $html, 'name="sets[]" value="privacy"' ) && false !== strpos( $html, 'name="cpts[]"' ), 'page: extra sets and post type options render' );
$rw_ok( false !== strpos( $html, 'name="new_caps"' ), 'page: add custom capability field renders' );
unset( $_REQUEST['role'] );

// Cleanup.
unregister_post_type( 'rwbook' );
Enforcer::as_system(
	function () use ( $rw_snapshot ) {
		$restore = array();
		foreach ( $rw_snapshot as $slug => $data ) {
			$restore[ $slug ] = array(
				'name'         => $data['name'],
				'capabilities' => $data['caps'],
			);
		}
		Role_Store::replace_all( $restore );
	}
);
foreach ( $rw_opts as $name => $value ) {
	null === $value ? delete_option( $name ) : update_option( $name, $value );
}
foreach ( array_unique( $rw_users ) as $uid ) {
	is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
}
Caps::grant_to_administrator();
$rw_ok( ! get_role( $rw_role ) && ! get_role( $rw_mgr_role ) && ! get_role( 'editor' )->has_cap( 'create_posts' ), 'cleanup: roles back to the starting state' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
