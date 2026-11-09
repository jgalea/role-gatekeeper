<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/admin-ui-smoke.php
 */

use Rolegate\Modules\Admin_Ui\Discovery;
use Rolegate\Modules\Admin_Ui\Engine;
use Rolegate\Modules\Admin_Ui\Enforcer;
use Rolegate\Modules\Admin_Ui\Rules;
use Rolegate\Modules\Safety\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

// Multisite: site administrators hold rolegate_* caps only when the network grants it; these checks are about role-based access, so grant it.
if ( is_multisite() ) {
	add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );
	// Core only lets site administrators manage plugins when the network enables the Plugins menu.
	$rw_saved_menu_items = get_site_option( 'menu_items' );
	update_site_option( 'menu_items', array( 'plugins' => 1 ) );
}

require_once ABSPATH . 'wp-admin/includes/admin.php';
require_once ABSPATH . WPINC . '/class-wp-admin-bar.php';

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

$sfx     = substr( md5( (string) microtime( true ) ), 0, 6 );
$r_mgr   = 'rw_t_mgr_' . $sfx;
$r_rest  = 'rw_t_rest_' . $sfx;
$r_view  = 'rw_t_view_' . $sfx;
$r_high  = 'rw_t_high_' . $sfx;
$users   = array();
$make    = function ( $login, $role ) use ( &$users, $sfx ) {
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
$code_of = function ( $r ) {
	return is_wp_error( $r ) ? $r->get_error_code() : 'ok';
};

$saved_globals = array(
	'menu'     => $GLOBALS['menu'] ?? null,
	'submenu'  => $GLOBALS['submenu'] ?? null,
	'pagenow'  => $GLOBALS['pagenow'] ?? null,
	'plugin'   => $GLOBALS['plugin_page'] ?? null,
	'boxes'    => $GLOBALS['wp_meta_boxes'] ?? null,
	'rules'    => get_option( Rules::OPTION, null ),
	'seen'     => get_option( Discovery::OPTION, null ),
);

add_filter(
	'wp_die_handler',
	function () {
		return function ( $message ) {
			throw new \RuntimeException( is_wp_error( $message ) ? $message->get_error_message() : wp_strip_all_tags( (string) $message ) );
		};
	}
);
$redirect_to = null;
remove_all_filters( 'wp_redirect' );
add_filter(
	'wp_redirect',
	function ( $location ) use ( &$redirect_to ) {
		$redirect_to = $location;
		return false;
	}
);
$events = array();
add_action(
	'rolegate_changed',
	function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	},
	10,
	2
);

delete_option( Rules::OPTION );
Rules::flush_cache();

try {
	$admin = $make( 'rw_admin', 'administrator' );
	wp_set_current_user( $admin );
	add_role(
		$r_mgr,
		'RW mgr',
		array(
			'read'                     => true,
			Caps::MANAGE               => true,
			Caps::MANAGE_ACCESS        => true,
			'activate_plugins'         => true,
			'delete_plugins'           => true,
			'switch_themes'            => true,
			'edit_theme_options'       => true,
			'edit_posts'               => true,
			'list_users'               => true,
		)
	);
	add_role(
		$r_rest,
		'RW restricted',
		array(
			'read'               => true,
			'edit_posts'         => true,
			'list_users'         => true,
			'activate_plugins'   => true,
			'delete_plugins'     => true,
			'switch_themes'      => true,
			'edit_theme_options' => true,
		)
	);
	add_role( $r_view, 'RW viewer', array( 'read' => true, Caps::MANAGE => true, 'edit_posts' => true ) );
	add_role( $r_high, 'RW high', array( 'read' => true, 'manage_options' => true ) );
	// With the role hierarchy on, the manager must rank above the users it restricts.
	update_option( 'rolegate_role_positions', array_merge( (array) get_option( 'rolegate_role_positions', array() ), array( $r_mgr => 50 ) ), false );
	$mgr     = $make( 'rw_mgr', $r_mgr );
	get_userdata( $mgr )->add_role( $r_view );
	$rest    = $make( 'rw_rest', $r_rest );
	$rest2   = $make( 'rw_rest2', $r_rest );
	$editor  = $make( 'rw_editor', 'editor' );

	$menu    = array(
		2  => array( 'Dashboard', 'read', 'index.php' ),
		5  => array( 'Posts', 'edit_posts', 'edit.php' ),
		20 => array( 'Pages', 'edit_posts', 'edit.php?post_type=page' ),
		70 => array( 'Users', 'list_users', 'users.php' ),
		75 => array( 'Tools', 'edit_posts', 'tools.php' ),
		80 => array( 'Settings', 'edit_posts', 'options-general.php' ),
		71 => array( 'Role Gatekeeper', 'read', 'role-gatekeeper' ),
		60 => array( 'Appearance', 'edit_theme_options', 'themes.php' ),
	);
	$submenu = array(
		'index.php'           => array( array( 'Home', 'read', 'index.php' ), array( 'Updates', 'read', 'update-core.php' ) ),
		'edit.php'            => array( array( 'All Posts', 'edit_posts', 'edit.php' ), array( 'Categories', 'edit_posts', 'edit-tags.php?taxonomy=category' ) ),
		'users.php'           => array( array( 'All Users', 'list_users', 'users.php' ), array( 'Profile', 'read', 'profile.php' ) ),
		'tools.php'           => array( array( 'Available Tools', 'edit_posts', 'tools.php' ), array( 'Import', 'edit_posts', 'import.php' ) ),
		'options-general.php' => array( array( 'General', 'edit_posts', 'options-general.php' ), array( 'Plugin Page', 'edit_posts', 'my-plugin-page' ) ),
		'role-gatekeeper'          => array( array( 'Modules', 'read', 'role-gatekeeper' ), array( 'Admin interface', 'read', 'role-gatekeeper-admin-ui' ) ),
		'themes.php'          => array( array( 'Themes', 'edit_theme_options', 'themes.php' ), array( 'Widgets', 'edit_theme_options', 'widgets.php' ), array( 'Menus', 'edit_theme_options', 'nav-menus.php' ) ),
	);
	Discovery::set_snapshot( $menu, $submenu );

	// Sanitizing and exempt items.
	$dirty = Rules::sanitize(
		array(
			'menu'      => array( 'model' => 'bogus', 'items' => array( 'users.php', '<script>', 'a b', str_repeat( 'x', 300 ) ) ),
			'blocks'    => array( 'widgets', 'nope' ),
			'plugins'   => array( 'locked' => array( 'hello.php', '../../evil.php', plugin_basename( ROLEGATE_FILE ), 'x.txt' ) ),
			'metaboxes' => array( 'post' => array( 'postcustom', 'bad id!' ), 'Bad Type' => array() ),
		)
	);
	$rw_ok( 'deny' === $dirty['menu']['model'] && array( 'users.php' ) === $dirty['menu']['items'], 'sanitize: unknown model falls back to deny, junk slugs dropped' );
	$rw_ok( array( 'widgets' ) === $dirty['blocks'], 'sanitize: unknown block ids dropped' );
	$rw_ok( array( 'hello.php' ) === $dirty['plugins']['locked'], 'sanitize: traversal, non-php and the Role Gatekeeper plugin itself dropped from plugin lists' );
	$rw_ok( array( 'postcustom' ) === ( $dirty['metaboxes']['post'] ?? array() ) && 1 === count( $dirty['metaboxes'] ), 'sanitize: meta box ids validated' );

	$deny_profile = Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'profile.php' ) ) ) );
	$rw_ok( 'rolegate_exempt_item' === $code_of( $deny_profile ), 'profile page cannot be blocked from the menu' );
	$deny_sub = Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'users.php|profile.php' ) ) ) );
	$rw_ok( 'rolegate_exempt_item' === $code_of( $deny_sub ), 'profile submenu entry cannot be blocked' );
	$deny_bar = Rules::save( $mgr, 'role', $r_rest, array( 'admin_bar' => array( 'my-account' ) ) );
	$rw_ok( 'rolegate_exempt_item' === $code_of( $deny_bar ), 'my-account toolbar node cannot be hidden' );
	$rw_ok( 'rolegate_protected_role' === $code_of( Rules::save( $mgr, 'role', 'administrator', array( 'blocks' => array( 'widgets' ) ) ) ), 'Administrator role cannot be restricted' );
	$rw_ok( 'rolegate_protected_user' === $code_of( Rules::save( $mgr, 'user', (string) $admin, array( 'blocks' => array( 'widgets' ) ) ) ), 'administrator user cannot be restricted' );
	$rw_ok( 'rolegate_no_role' === $code_of( Rules::save( $mgr, 'role', 'nonexistent_' . $sfx, array( 'blocks' => array( 'widgets' ) ) ) ), 'unknown role refused' );
	$rw_ok( 'rolegate_forbidden' === $code_of( Rules::save( $editor, 'role', $r_rest, array( 'blocks' => array( 'widgets' ) ) ) ), 'actor without the access capability refused' );
	$rw_ok( false === get_option( Rules::OPTION, false ), 'refused saves stored nothing' );

	// Lockout pre-check.
	$empty_allow = Rules::save( $mgr, 'role', $r_view, array( 'menu' => array( 'model' => 'allow', 'items' => array() ) ) );
	$rw_ok( 'rolegate_lockout' === $code_of( $empty_allow ) && in_array( 'empty_allow_list', (array) $empty_allow->get_error_data()['reasons'], true ), 'allow model with nothing selected refused for the actor own role (lockout)' );
	$self_user = Rules::save( $mgr, 'user', (string) $mgr, array( 'menu' => array( 'model' => 'allow', 'items' => array( 'role-gatekeeper' ) ) ) );
	$rw_ok( 'rolegate_lockout' === $code_of( $self_user ), 'allow list with only the Role Gatekeeper entry refused for the actor own user rule' );
	$rw_ok( false === get_option( Rules::OPTION, false ), 'lockout refusals stored nothing' );
	$rw_ok( 'ok' === $code_of( Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'allow', 'items' => array() ) ) ) ), 'empty allow list is fine for a role the actor does not hold' );
	Rules::save( $mgr, 'role', $r_rest, array() );
	$rw_ok( 'ok' === $code_of( Rules::save( $mgr, 'role', $r_view, array( 'menu' => array( 'model' => 'allow', 'items' => array( 'index.php', 'edit.php' ) ) ) ) ), 'allow list with real entries accepted for the actor own role' );
	Rules::save( $mgr, 'role', $r_view, array() );
	$rw_ok( 'ok' === $code_of( Rules::save( $mgr, 'role', $r_view, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'role-gatekeeper', 'role-gatekeeper|role-gatekeeper-admin-ui', 'users.php' ) ) ) ) ), 'denying the Role Gatekeeper menu for a role holding the manage cap is accepted but never enforced' );

	$eff_mgr = Rules::effective_for_user( $mgr );
	$rw_ok( null !== $eff_mgr, 'effective rules computed for the manager' );
	$can_manage = user_can( $mgr, Caps::MANAGE );
	$rw_ok( $can_manage, 'manager holds the manage cap' );
	$rw_ok( null === Engine::decide( 'admin.php', 'role-gatekeeper-admin-ui', array(), $menu, $submenu, $eff_mgr, true ), 'Role Gatekeeper admin-ui page is reachable even when its menu is in the deny list' );
	$rw_ok( null === Engine::decide( 'admin.php', 'role-gatekeeper', array(), $menu, $submenu, $eff_mgr, true ), 'Role Gatekeeper top page reachable despite deny' );
	$rw_ok( 'menu' === Engine::decide( 'admin.php', 'role-gatekeeper-admin-ui', array(), $menu, $submenu, $eff_mgr, false ), 'control: without the manage cap the same deny does block (exemption is what protects it)' );
	wp_set_current_user( $mgr );
	$GLOBALS['menu']    = $menu;
	$GLOBALS['submenu'] = $submenu;
	( new Enforcer() )->hide_menu();
	$slugs = array_map(
		function ( $i ) {
			return $i[2];
		},
		$GLOBALS['menu']
	);
	$rw_ok( in_array( 'role-gatekeeper', $slugs, true ) && ! in_array( 'users.php', $slugs, true ), 'hide_menu removes users.php but keeps the Role Gatekeeper menu for a manage-cap holder' );
	wp_set_current_user( $admin );
	$GLOBALS['menu']    = $menu;
	$GLOBALS['submenu'] = $submenu;
	Rules::save( $mgr, 'role', $r_view, array() );

	// Change event with before/after.
	$events = array();
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'users.php', 'tools.php|import.php' ) ), 'blocks' => array( 'widgets', 'nav_menus' ), 'themes_locked' => 1 ) );
	$ev = $events ? $events[0] : null;
	$rw_ok( $ev && 'access.updated' === $ev[0] && $r_rest === $ev[1]['target'] && $mgr === $ev[1]['actor'] && array() === $ev[1]['before'] && array( 'users.php', 'tools.php|import.php' ) === $ev[1]['after']['menu']['items'], 'access.updated fired with actor, target, empty before and the stored after' );
	$events = array();
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'users.php' ) ), 'blocks' => array( 'widgets' ), 'themes_locked' => 1 ) );
	$rw_ok( $events && array( 'users.php', 'tools.php|import.php' ) === $events[0][1]['before']['menu']['items'] && array( 'users.php' ) === $events[0][1]['after']['menu']['items'], 'second save carries the previous rule as before (revertable)' );
	$events = array();
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'users.php' ) ), 'blocks' => array( 'widgets' ), 'themes_locked' => 1 ) );
	$rw_ok( ! $events, 'unchanged save fires no event' );

	// Role rules need authority over the target role.
	$rw_ok( 'rolegate_role_above_actor' === $code_of( Rules::save( $mgr, 'role', $r_high, array( 'blocks' => array( 'widgets' ) ) ) ), 'role holding a critical cap the actor lacks (manage_options) cannot be restricted' );
	$rw_ok( 'rolegate_manager_role' === $code_of( Rules::save( $admin, 'role', $r_mgr, array( 'blocks' => array( 'widgets' ) ) ) ), 'role holding a rolegate_manage_* cap cannot be restricted, even by an administrator' );
	$rw_ok( 'rolegate_manager_role' === $code_of( Rules::save( $mgr, 'role', $r_mgr, array( 'blocks' => array( 'widgets' ) ) ) ), 'actor cannot restrict their own manager role' );
	$planted                       = Rules::all();
	$planted['roles'][ $r_high ]   = array_replace_recursive( Engine::empty_rule(), array( 'blocks' => array( 'widgets' ) ) );
	$planted['roles'][ $r_mgr ]    = array_replace_recursive( Engine::empty_rule(), array( 'blocks' => array( 'widgets' ) ) );
	update_option( Rules::OPTION, $planted );
	Rules::flush_cache();
	$rw_ok( 'rolegate_role_above_actor' === $code_of( Rules::save( $mgr, 'role', $r_high, array( 'blocks' => array( 'nav_menus' ) ) ) ), 'existing rule on a higher role cannot be updated by the actor' );
	$rw_ok( 'rolegate_role_above_actor' === $code_of( Rules::save( $mgr, 'role', $r_high, array() ) ), 'existing rule on a higher role cannot be deleted by the actor' );
	$rw_ok( isset( Rules::all()['roles'][ $r_high ] ), 'refused update/delete left the stored rule untouched' );
	$rw_ok( 'rolegate_manager_role' === $code_of( Rules::save( $admin, 'role', $r_mgr, array( 'blocks' => array( 'nav_menus' ) ) ) ), 'existing rule on a manager role cannot be changed' );
	$rw_ok( 'ok' === $code_of( Rules::save( $mgr, 'role', $r_mgr, array() ) ) && ! isset( Rules::all()['roles'][ $r_mgr ] ), 'a stale rule on a manager role can still be cleared by someone with authority over it' );
	$rw_ok( 'ok' === $code_of( Rules::save( $admin, 'role', $r_high, array() ) ) && ! isset( Rules::all()['roles'][ $r_high ] ), 'control: administrator can clear the higher role rule' );
	$rw_ok( 'ok' === $code_of( Rules::save( $admin, 'role', $r_high, array( 'blocks' => array( 'widgets' ) ) ) ), 'control: administrator can restrict a role holding manage_options' );
	Rules::save( $admin, 'role', $r_high, array() );

	// Direct-URL enforcement.
	wp_set_current_user( $rest );
	Rules::flush_cache();
	$GLOBALS['pagenow']     = 'users.php';
	$GLOBALS['plugin_page'] = null;
	$redirect_to            = null;
	$enf                    = new Enforcer();
	$enf->guard_request();
	$rw_ok( is_string( $redirect_to ) && false === strpos( $redirect_to, 'users.php' ) && 0 === strpos( $redirect_to, admin_url() ), 'denied users.php redirects to another admin page: ' . (string) $redirect_to );
	$rw_ok( $redirect_to === admin_url( 'index.php' ), 'redirect target is the first allowed menu item' );

	$GLOBALS['pagenow'] = 'user-edit.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'user-edit.php (hidden page under Users) is blocked with its parent' );

	$GLOBALS['pagenow'] = 'import.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'import.php is open once its submenu entry was removed from the deny list (control: no false positive)' );

	$GLOBALS['pagenow'] = 'edit.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'an unlisted screen is not redirected' );

	$GLOBALS['pagenow'] = 'profile.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'profile.php is never redirected' );

	$GLOBALS['pagenow'] = 'widgets.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'widgets.php blocked by the Appearance block' );

	$GLOBALS['pagenow']     = 'admin.php';
	$GLOBALS['plugin_page'] = 'my-plugin-page';
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'options-general.php|my-plugin-page' ) ) ) );
	wp_set_current_user( $rest );
	$redirect_to = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'plugin-added submenu page (?page=slug) blocked by its key' );

	$GLOBALS['pagenow']     = 'themes.php';
	$GLOBALS['plugin_page'] = null;
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'themes.php' ) ) ) );
	wp_set_current_user( $rest );
	foreach ( array( 'themes.php', 'widgets.php', 'nav-menus.php' ) as $pg ) {
		$GLOBALS['pagenow'] = $pg;
		$redirect_to        = null;
		$enf->guard_request();
		$rw_ok( null !== $redirect_to, "denying the Appearance parent blocks $pg" );
	}

	// Allow model.
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'allow', 'items' => array( 'index.php', 'index.php|index.php', 'edit.php', 'edit.php|edit.php' ) ) ) );
	wp_set_current_user( $rest );
	$GLOBALS['pagenow'] = 'tools.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( $redirect_to === admin_url( 'index.php' ), 'allow model: unlisted tools.php redirects to the first allowed item' );
	$GLOBALS['pagenow'] = 'edit.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'allow model: listed edit.php open' );
	$GLOBALS['pagenow'] = 'edit-tags.php';
	$_GET['taxonomy']   = 'category';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'allow model: edit-tags.php?taxonomy=category blocked when only edit.php is listed' );
	unset( $_GET['taxonomy'] );
	$GLOBALS['pagenow'] = 'profile.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'allow model: profile.php still open' );
	$GLOBALS['pagenow'] = 'edit.php';
	$_GET['post_type']  = 'page';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'allow model: edit.php?post_type=page blocked (different menu entry)' );
	unset( $_GET['post_type'] );
	$GLOBALS['menu']    = $menu;
	$GLOBALS['submenu'] = $submenu;
	$enf->hide_menu();
	$slugs = array_map(
		function ( $i ) {
			return $i[2];
		},
		$GLOBALS['menu']
	);
	$rw_ok( array( 'index.php', 'edit.php', 'users.php' ) === array_values( array_intersect( $slugs, array( 'index.php', 'edit.php', 'users.php', 'tools.php', 'themes.php', 'options-general.php', 'edit.php?post_type=page' ) ) ), 'allow model: hide_menu leaves the listed top-level items plus Users, which keeps only Profile' );
	$rw_ok( array( 'profile.php' ) === array_column( $GLOBALS['submenu']['users.php'] ?? array(), 2 ), 'allow model: Profile stays reachable under Users' );
	$rw_ok( count( $GLOBALS['submenu']['edit.php'] ?? array() ) === 1, 'allow model: unlisted submenu entry removed from a kept parent' );

	// Administrator unaffected by the same rules.
	wp_set_current_user( $admin );
	$GLOBALS['pagenow'] = 'tools.php';
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'administrator is never redirected' );
	$rw_ok( null === Rules::effective_for_user( $admin ), 'administrator has no effective restrictions' );

	// Per-user rule applies on top of the role rule.
	Rules::save( $mgr, 'role', $r_rest, array() );
	Rules::save( $mgr, 'user', (string) $rest2, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'tools.php' ) ) ) );
	wp_set_current_user( $rest2 );
	$GLOBALS['pagenow'] = 'tools.php';
	$GLOBALS['menu']    = $menu;
	$GLOBALS['submenu'] = $submenu;
	$redirect_to        = null;
	$enf->guard_request();
	$rw_ok( null !== $redirect_to, 'per-user rule blocks that user' );
	wp_set_current_user( $rest );
	$redirect_to = null;
	$enf->guard_request();
	$rw_ok( null === $redirect_to, 'per-user rule does not affect another user of the same role' );
	Rules::save( $mgr, 'user', (string) $rest2, array() );

	// Meta boxes, dashboard widgets, admin bar.
	global $wp_meta_boxes;
	$wp_meta_boxes['post']['normal']['core']['postcustom'] = array( 'id' => 'postcustom', 'title' => 'Custom Fields' );
	$wp_meta_boxes['post']['side']['core']['submitdiv']    = array( 'id' => 'submitdiv', 'title' => 'Publish' );
	$wp_meta_boxes['dashboard']['normal']['core']['dashboard_site_health'] = array( 'id' => 'dashboard_site_health', 'title' => 'Site Health' );
	$disc = new Discovery();
	$disc->record_post_boxes( 'post' );
	$disc->record_dashboard();
	$seen = Discovery::seen();
	$rw_ok( 'Custom Fields' === ( $seen['metaboxes']['post']['postcustom'] ?? '' ) && isset( $seen['metaboxes']['dashboard']['dashboard_site_health'] ), 'meta boxes and dashboard widgets recorded at runtime (ids and titles only)' );

	$bar = new WP_Admin_Bar();
	$bar->add_node( array( 'id' => 'wp-logo', 'title' => 'WP' ) );
	$bar->add_node( array( 'id' => 'comments', 'title' => 'Comments' ) );
	$bar->add_node( array( 'id' => 'my-account', 'title' => 'Howdy' ) );
	$disc->record_bar( $bar );
	$rw_ok( isset( Discovery::seen()['bar']['comments'] ), 'toolbar nodes recorded' );

	Rules::save(
		$mgr,
		'role',
		$r_rest,
		array(
			'metaboxes' => array( 'post' => array( 'postcustom' ), 'dashboard' => array( 'dashboard_site_health' ) ),
			'admin_bar' => array( 'wp-logo', 'comments' ),
			'plugins'   => array( 'model' => 'deny', 'locked' => array( 'hello.php' ), 'hidden' => array( 'akismet/akismet.php' ) ),
			'themes_locked' => 1,
			'blocks'    => array( 'widgets', 'nav_menus' ),
		)
	);
	wp_set_current_user( $rest );
	$enf->hide_post_boxes( 'post' );
	$rw_ok( false === $wp_meta_boxes['post']['normal']['core']['postcustom'] && is_array( $wp_meta_boxes['post']['side']['core']['submitdiv'] ), 'listed meta box removed, others kept' );
	$enf->hide_dashboard_widgets();
	$rw_ok( false === $wp_meta_boxes['dashboard']['normal']['core']['dashboard_site_health'], 'dashboard widget removed' );
	$enf->hide_bar_nodes( $bar );
	$rw_ok( null === $bar->get_node( 'wp-logo' ) && null === $bar->get_node( 'comments' ) && null !== $bar->get_node( 'my-account' ), 'toolbar nodes removed, my-account kept' );
	$wp_meta_boxes['post']['normal']['core']['postcustom'] = array( 'id' => 'postcustom', 'title' => 'Custom Fields' );
	wp_set_current_user( $editor );
	$enf->hide_post_boxes( 'post' );
	$rw_ok( is_array( $wp_meta_boxes['post']['normal']['core']['postcustom'] ), 'meta box rule does not apply to another role' );

	// Plugin access.
	wp_set_current_user( $rest );
	$rw_ok( ! user_can( $rest, 'activate_plugin', 'hello.php' ) && ! user_can( $rest, 'deactivate_plugin', 'hello.php' ) && ! user_can( $rest, 'delete_plugin', 'hello.php' ), 'locked plugin: activate, deactivate and delete caps refused' );
	$rw_ok( user_can( $rest, 'activate_plugin', plugin_basename( ROLEGATE_FILE ) ), 'unlisted plugin still manageable' );
	$rw_ok( ! user_can( $rest, 'activate_plugin', 'akismet/akismet.php' ), 'hidden plugin cannot be managed either' );
	$rw_ok( user_can( $admin, 'activate_plugin', 'hello.php' ), 'administrator can still manage the locked plugin' );
	$list = $enf->filter_plugin_list( array( 'akismet/akismet.php' => array(), 'hello.php' => array() ) );
	$rw_ok( array( 'hello.php' ) === array_keys( $list ), 'hidden plugin removed from the plugin list, locked one stays visible' );
	$threw = false;
	try {
		do_action( 'activate_plugin', 'hello.php', false );
	} catch ( \RuntimeException $e ) {
		$threw = true;
	}
	$rw_ok( $threw, 'activate_plugin action refuses a locked plugin (covers bulk activation)' );
	$threw = false;
	try {
		do_action( 'delete_plugin', 'hello.php' );
	} catch ( \RuntimeException $e ) {
		$threw = true;
	}
	$rw_ok( $threw, 'delete_plugin action refuses a locked plugin' );
	$threw = false;
	try {
		do_action( 'deactivate_plugin', 'akismet/akismet.php', false );
	} catch ( \RuntimeException $e ) {
		$threw = true;
	}
	$rw_ok( $threw, 'deactivate_plugin action refuses a hidden plugin' );
	$threw = false;
	try {
		do_action( 'activate_plugin', plugin_basename( ROLEGATE_FILE ), false );
	} catch ( \RuntimeException $e ) {
		$threw = true;
	}
	$rw_ok( ! $threw, 'activate_plugin action lets an unlisted plugin through' );

	// Allow model for plugins.
	Rules::save( $mgr, 'role', $r_rest, array( 'plugins' => array( 'model' => 'allow', 'locked' => array( 'akismet/akismet.php' ) ) ) );
	wp_set_current_user( $rest );
	$rw_ok( user_can( $rest, 'activate_plugin', 'akismet/akismet.php' ) && ! user_can( $rest, 'activate_plugin', 'hello.php' ), 'plugin allow model: only the listed plugin may be toggled' );

	// REST.
	Rules::save( $mgr, 'role', $r_rest, array( 'blocks' => array( 'widgets', 'nav_menus' ), 'plugins' => array( 'model' => 'deny', 'hidden' => array( 'hello.php' ) ) ) );
	wp_set_current_user( $rest );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/widgets' ) );
	$rw_ok( 403 === $resp->get_status(), 'REST /wp/v2/widgets refused with 403 for the blocked role' );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/menus' ) );
	$rw_ok( 403 === $resp->get_status(), 'REST /wp/v2/menus refused with 403 for the blocked role' );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/plugins/hello' ) );
	$rw_ok( 404 === $resp->get_status(), 'REST hidden plugin route returns 404' );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/plugins' ) );
	$ids  = wp_list_pluck( (array) $resp->get_data(), 'plugin' );
	$rw_ok( 200 === $resp->get_status() && $ids && ! in_array( 'hello', $ids, true ), 'REST plugin list omits the hidden plugin (' . count( $ids ) . ' listed)' );
	$resp = rest_do_request( new WP_REST_Request( 'POST', '/wp/v2/plugins/hello' ) );
	$rw_ok( in_array( $resp->get_status(), array( 403, 404 ), true ), 'REST write to a hidden plugin refused' );
	wp_set_current_user( $admin );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/plugins' ) );
	$rw_ok( 200 === $resp->get_status() && in_array( 'hello', wp_list_pluck( (array) $resp->get_data(), 'plugin' ), true ), 'control: administrator still sees the plugin over REST' );

	$rw_ok( '/wp/v2/widgets' === Enforcer::normalize_route( '//WP/v2//Widgets/' ), 'route normaliser lowercases, collapses slashes and strips the trailing slash' );
	wp_set_current_user( $rest );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/WP/V2/Widgets' ) );
	$rw_ok( 403 === $resp->get_status(), 'REST /WP/V2/Widgets (mixed case) refused with 403, got ' . $resp->get_status() );
	$guarded = $enf->rest_guard( null, array(), new WP_REST_Request( 'GET', '//wp/v2/widgets/' ) );
	$rw_ok( is_wp_error( $guarded ) && 403 === ( $guarded->get_error_data()['status'] ?? 0 ), 'REST //wp/v2/widgets/ (extra slashes) refused with 403' );
	$guarded = $enf->rest_guard( null, array(), new WP_REST_Request( 'GET', '/wp/v2/Menu-Items/5' ) );
	$rw_ok( is_wp_error( $guarded ), 'REST /wp/v2/Menu-Items/5 refused' );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/Plugins/hello' ) );
	$rw_ok( 404 === $resp->get_status(), 'REST /wp/v2/Plugins/hello (mixed case) returns 404 for a hidden plugin, got ' . $resp->get_status() );
	$guarded = $enf->rest_guard( null, array(), new WP_REST_Request( 'POST', '//wp/v2/plugins/Hello/' ) );
	$rw_ok( is_wp_error( $guarded ), 'REST //wp/v2/plugins/Hello/ refused' );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/Plugins' ) );
	$ids  = wp_list_pluck( (array) $resp->get_data(), 'plugin' );
	$rw_ok( 200 === $resp->get_status() && $ids && ! in_array( 'hello', $ids, true ), 'REST /wp/v2/Plugins (mixed case) list omits the hidden plugin (' . count( $ids ) . ' listed)' );
	$guarded = $enf->rest_guard( null, array(), new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
	$rw_ok( null === $guarded, 'control: unrelated REST route passes the guard' );
	wp_set_current_user( $admin );
	$resp = rest_do_request( new WP_REST_Request( 'GET', '/WP/V2/Widgets' ) );
	$rw_ok( 200 === $resp->get_status(), 'control: administrator reaches /WP/V2/Widgets' );

	// Core ajax actions behind blocked features.
	$ajax = function ( $user, $action, $post = array() ) use ( $enf ) {
		wp_set_current_user( $user );
		$_REQUEST['action'] = $action;
		$_POST              = $post;
		$code               = 'ok';
		add_filter( 'wp_doing_ajax', '__return_true' );
		$h = function () {
			return function ( $message, $title = '', $args = array() ) {
				throw new \DomainException( 'ajax', is_int( $title ) ? $title : (int) ( $args['response'] ?? 0 ) );
			};
		};
		add_filter( 'wp_die_ajax_handler', $h );
		try {
			$enf->guard_ajax();
		} catch ( \DomainException $e ) {
			$code = 'die:' . $e->getCode();
		}
		remove_filter( 'wp_die_ajax_handler', $h );
		remove_filter( 'wp_doing_ajax', '__return_true' );
		unset( $_REQUEST['action'] );
		$_POST = array();
		return $code;
	};
	Rules::save( $mgr, 'role', $r_rest, array( 'blocks' => array( 'widgets', 'nav_menus', 'customizer' ), 'plugins' => array( 'model' => 'deny', 'locked' => array( 'hello.php' ) ) ) );
	foreach ( array( 'save-widget', 'widgets-order', 'update-widget', 'add-menu-item', 'menu-locations-save', 'menu-quick-search', 'menu-get-metabox', 'customize_save' ) as $act ) {
		$rw_ok( 'die:403' === $ajax( $rest, $act ), "ajax $act refused with 403 while its block is on" );
	}
	foreach ( array( 'update-plugin', 'delete-plugin', 'activate-plugin' ) as $act ) {
		$rw_ok( 'die:403' === $ajax( $rest, $act, array( 'plugin' => 'hello.php', 'slug' => 'hello-dolly' ) ), "ajax $act refused for a locked plugin" );
	}
	$rw_ok( 'die:403' === $ajax( $rest, 'toggle-auto-updates', array( 'type' => 'plugin', 'asset' => 'hello.php' ) ), 'ajax toggle-auto-updates refused for a locked plugin' );
	$rw_ok( 'die:403' === $ajax( $rest, 'toggle-auto-updates', array( 'type' => 'Plugin', 'asset' => 'hello.php' ) ), 'ajax toggle-auto-updates: type parsed like core (case-insensitive)' );
	$rw_ok( 'die:403' === $ajax( $rest, 'toggle-auto-updates', array( 'type' => 'plugin', 'asset' => 'hello%2Ephp' ) ), 'ajax toggle-auto-updates: asset url-decoded like core' );
	$rw_ok( 'die:403' === $ajax( $rest, 'toggle-auto-updates', array( 'type' => 'PLUGIN', 'asset' => 'hello%2ephp' ) ), 'ajax toggle-auto-updates: upper-case type and lower-case percent escape still refused' );
	$rw_ok( 'die:403' === $ajax( $rest, 'update-plugin', array( 'plugin' => 'hello%2Ephp', 'slug' => 'hello-dolly' ) ), 'ajax update-plugin: percent-encoded plugin name refused' );
	$rw_ok( 'die:403' === $ajax( $rest, 'update-plugin', array( 'plugin' => 'Hello.PHP', 'slug' => 'hello-dolly' ) ), 'ajax update-plugin: case-varied plugin name refused' );
	$rw_ok( 'die:403' === $ajax( $rest, 'toggle-auto-updates', array( 'type' => 'plugin', 'asset' => 'HELLO%2Ephp' ) ), 'ajax toggle-auto-updates: case-varied, percent-encoded asset refused' );
	$rw_ok( 'ok' === $ajax( $rest, 'update-plugin', array( 'plugin' => 'akismet/akismet.php', 'slug' => 'akismet' ) ), 'control: ajax update-plugin allowed for an unlocked plugin' );
	$rw_ok( 'ok' === $ajax( $rest, 'install-plugin', array( 'slug' => 'akismet' ) ), 'control: ajax install-plugin allowed under the deny model' );
	$rw_ok( 'ok' === $ajax( $rest, 'heartbeat' ), 'control: unrelated ajax action allowed' );
	$rw_ok( 'ok' === $ajax( $admin, 'save-widget' ), 'control: administrator ajax save-widget allowed' );
	Rules::save( $mgr, 'role', $r_rest, array( 'plugins' => array( 'model' => 'allow', 'locked' => array( 'akismet/akismet.php' ) ) ) );
	$rw_ok( 'die:403' === $ajax( $rest, 'install-plugin', array( 'slug' => 'akismet' ) ), 'ajax install-plugin refused under the plugin allow model' );
	$rw_ok( 'ok' === $ajax( $rest, 'save-widget' ), 'control: ajax save-widget allowed once the widgets block is gone' );
	Rules::save( $mgr, 'role', $r_rest, array( 'menu' => array( 'model' => 'deny', 'items' => array( 'themes.php' ) ) ) );
	$rw_ok( 'die:403' === $ajax( $rest, 'save-widget' ) && 'die:403' === $ajax( $rest, 'add-menu-item' ), 'ajax widget and menu actions refused when the Appearance menu (their screens) is denied' );
	wp_set_current_user( $rest );
	$_REQUEST['action'] = 'save-widget';
	$threw              = false;
	try {
		$enf->guard_ajax();
	} catch ( \Throwable $e ) {
		$threw = true;
	}
	unset( $_REQUEST['action'] );
	$rw_ok( ! $threw, 'guard_ajax is a no-op outside ajax requests' );

	// Theme switching and customizer.
	Rules::save( $mgr, 'role', $r_rest, array( 'themes_locked' => 1, 'blocks' => array( 'widgets', 'nav_menus' ) ) );
	wp_set_current_user( $rest );
	$rw_ok( 'old-theme' === apply_filters( 'pre_update_option_stylesheet', 'new-theme', 'old-theme' ) && 'old-theme' === apply_filters( 'pre_update_option_template', 'new-theme', 'old-theme' ), 'theme switch write is reverted to the old value for a locked role' );
	$GLOBALS['pagenow'] = 'themes.php';
	$_GET['action']     = 'activate';
	$threw              = false;
	try {
		$enf->guard_request();
	} catch ( \RuntimeException $e ) {
		$threw = true;
	}
	unset( $_GET['action'] );
	$rw_ok( $threw, 'themes.php?action=activate refused for a locked role' );
	$comps = apply_filters( 'customize_loaded_components', array( 'widgets', 'nav_menus', 'custom_css' ) );
	$rw_ok( array( 'custom_css' ) === array_values( $comps ), 'customizer widgets and menus components removed' );
	wp_set_current_user( $admin );
	$rw_ok( 'new-theme' === apply_filters( 'pre_update_option_stylesheet', 'new-theme', 'old-theme' ), 'control: administrator can switch themes' );

	// Settings page registered under the Role Gatekeeper menu with the module capability.
	$rw_ok( class_exists( '\Rolegate\Modules\Admin_Ui\Admin_Page' ) && 'role-gatekeeper-admin-ui' === \Rolegate\Modules\Admin_Ui\Admin_Page::SLUG, 'page slug is role-gatekeeper-admin-ui' );
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . basename( $e->getFile() ) . ':' . $e->getLine() . "\n";
}

// Cleanup.
if ( is_multisite() ) {
	update_site_option( 'menu_items', $rw_saved_menu_items );
}
wp_set_current_user( 0 );
require_once ABSPATH . 'wp-admin/includes/user.php';
foreach ( $users as $uid ) {
	is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
}
remove_role( $r_mgr );
remove_role( $r_rest );
remove_role( $r_view );
remove_role( $r_high );
foreach ( array( Rules::OPTION => 'rules', Discovery::OPTION => 'seen' ) as $opt => $k ) {
	if ( null === $saved_globals[ $k ] ) {
		delete_option( $opt );
	} else {
		update_option( $opt, $saved_globals[ $k ] );
	}
}
Rules::flush_cache();
$GLOBALS['menu']           = $saved_globals['menu'];
$GLOBALS['submenu']        = $saved_globals['submenu'];
$GLOBALS['wp_meta_boxes']  = $saved_globals['boxes'];

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail ) {
	exit( 1 );
}
