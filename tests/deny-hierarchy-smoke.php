<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/deny-hierarchy-smoke.php
 */

use Rolewright\Modules\Deny_Hierarchy\Denials;
use Rolewright\Modules\Deny_Hierarchy\Deny_Hierarchy_Module;
use Rolewright\Modules\Deny_Hierarchy\Effective;
use Rolewright\Modules\Deny_Hierarchy\Hierarchy;
use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Enforcer;
use Rolewright\Modules\Safety\Guard;

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

if ( ! \Rolewright\Core\Plugin::is_enabled( 'deny-hierarchy' ) ) {
	( new Deny_Hierarchy_Module() )->init();
}

$rw_s         = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_roles     = array();
$rw_users     = array();
$rw_events    = array();
$rw_old_deny  = get_option( Denials::OPTION, null );
$rw_old_pos   = get_option( Hierarchy::OPTION, null );
$rw_role      = function ( $slug, $caps ) use ( &$rw_roles, $rw_s ) {
	$name = 'rw_t_' . $slug . '_' . $rw_s;
	Enforcer::as_system(
		function () use ( $name, $slug, $caps ) {
			add_role( $name, 'RW test ' . $slug, $caps );
		}
	);
	$rw_roles[] = $name;
	return $name;
};
$rw_make      = function ( $login, $roles ) use ( &$rw_users, $rw_s ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_s,
			'user_email' => $login . '_' . $rw_s . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => '',
		)
	);
	if ( is_wp_error( $id ) ) {
		echo 'SETUP ERROR ' . $id->get_error_message() . "\n";
		exit( 1 );
	}
	$u = new WP_User( $id );
	foreach ( (array) $roles as $r ) {
		$u->add_role( $r );
	}
	$rw_users[] = (int) $id;
	return (int) $id;
};
$rw_has_role  = function ( $id, $role ) {
	clean_user_cache( $id );
	$u = get_userdata( $id );
	return $u && in_array( $role, (array) $u->roles, true );
};
$rw_fresh_can = function ( $id, $cap ) {
	clean_user_cache( $id );
	return user_can( new WP_User( $id ), $cap );
};
$rw_listener  = function ( $type, $data ) use ( &$rw_events ) {
	$rw_events[] = array( $type, $data );
};
$rw_rest      = function ( $method, $route, $params = array() ) {
	$req = new WP_REST_Request( $method, $route );
	foreach ( $params as $k => $v ) {
		$req->set_param( $k, $v );
	}
	return rest_do_request( $req );
};
$rw_code      = function ( $res ) {
	return is_wp_error( $res ) ? $res->get_error_code() : ( true === $res ? 'true' : 'other' );
};

add_action( 'rolewright_changed', $rw_listener, 10, 2 );
wp_set_current_user( 0 );
delete_option( Denials::OPTION );
delete_option( Hierarchy::OPTION );

try {
	$manager_caps = array(
		'read'          => true,
		'list_users'    => true,
		'edit_users'    => true,
		'promote_users' => true,
		'create_users'  => true,
		'delete_users'  => true,
	);
	$r_manager = $rw_role( 'manager', $manager_caps );
	$r_peer    = $rw_role( 'peer', array( 'read' => true ) );
	$r_senior  = $rw_role( 'senior', array( 'read' => true, 'edit_posts' => true ) );
	$r_junior  = $rw_role( 'junior', array( 'read' => true ) );
	$r_denyer  = $rw_role( 'denyer', array( 'read' => true ) );
	$r_ops     = $rw_role( 'ops', array( 'read' => true, Caps::MANAGE => true, Caps::MANAGE_ACCESS => true ) );

	$admin   = $rw_make( 'rw_admin', array( 'administrator' ) );
	$admin2  = $rw_make( 'rw_admin2', array( 'administrator', $r_junior ) );
	$manager = $rw_make( 'rw_manager', array( $r_manager ) );
	$peer    = $rw_make( 'rw_peer', array( $r_peer ) );
	$senior  = $rw_make( 'rw_senior', array( $r_senior ) );
	$junior  = $rw_make( 'rw_junior', array( $r_junior ) );
	$junior2 = $rw_make( 'rw_junior2', array( $r_junior ) );
	$multi_a = $rw_make( 'rw_multi_a', array( 'author', $r_denyer ) );
	$multi_b = $rw_make( 'rw_multi_b', array( $r_denyer, 'author' ) );
	$ops     = $rw_make( 'rw_ops', array( $r_ops, $r_junior ) );

	// Deny wins across roles.
	$rw_ok( $rw_fresh_can( $multi_a, 'edit_posts' ) && $rw_fresh_can( $multi_b, 'edit_posts' ), 'baseline: author grants edit_posts before any denial' );
	$res = Denials::save( $admin, $r_denyer, array( 'edit_posts' ) );
	$rw_ok( true === $res, 'admin denies edit_posts on the denyer role (' . $rw_code( $res ) . ')' );
	$rw_ok( ! $rw_fresh_can( $multi_a, 'edit_posts' ), 'deny wins: [author, denyer] loses edit_posts' );
	$rw_ok( ! $rw_fresh_can( $multi_b, 'edit_posts' ), 'deny wins regardless of role order: [denyer, author]' );
	$rw_post = wp_insert_post( array( 'post_title' => 'rw deny ' . $rw_s, 'post_author' => $multi_a, 'post_status' => 'draft' ) );
	$rw_ok( $rw_post && ! user_can( $multi_a, 'edit_post', $rw_post ), 'deny reaches meta caps that map to the denied primitive (edit own post)' );
	wp_delete_post( $rw_post, true );
	( new WP_User( $multi_a ) )->add_cap( 'edit_posts' );
	$rw_ok( ! $rw_fresh_can( $multi_a, 'edit_posts' ), 'deny beats a per-user grant' );
	$rw_ok( $rw_fresh_can( $multi_a, 'publish_posts' ), 'deny leaves other caps alone' );
	$rw_ok( empty( Guard::user_caps( $multi_a )['edit_posts'] ), 'Guard sees effective caps (denied cap subtracted)' );
	$rw_ok( $rw_fresh_can( $senior, 'edit_posts' ), 'users without the denying role keep the cap' );
	$last = end( $rw_events );
	$rw_ok( $last && 'access.updated' === $last[0] && $r_denyer === $last[1]['target'] && array() === $last[1]['before']['denied'] && array( 'edit_posts' ) === $last[1]['after']['denied'] && $admin === $last[1]['actor'], 'rolewright_changed access.updated fired with actor, target, before, after' );

	$view = Effective::for_user( new WP_User( $multi_a ) );
	$row  = isset( $view['caps']['edit_posts'] ) ? $view['caps']['edit_posts'] : null;
	$rw_ok( $row && array( 'author' ) === $row['granted_by'] && $row['user_grant'] && array( $r_denyer ) === $row['denied_by'] && ! $row['effective'], 'effective viewer: source role, per-user grant, denying role, result' );
	$rw_ok( ! empty( $view['caps']['publish_posts']['effective'] ) && array( 'author' ) === $view['caps']['publish_posts']['granted_by'], 'effective viewer: granted cap shows its source role' );

	// Per-request cache: no option reads once loaded.
	$reads   = 0;
	$counter = function ( $pre ) use ( &$reads ) {
		++$reads;
		return $pre;
	};
	Denials::map();
	add_filter( 'pre_option_' . Denials::OPTION, $counter );
	for ( $i = 0; $i < 50; $i++ ) {
		user_can( $multi_a, 'edit_posts' );
		user_can( $senior, 'read' );
	}
	remove_filter( 'pre_option_' . Denials::OPTION, $counter );
	$rw_ok( 0 === $reads, 'denial map cached per request (0 option reads over 100 checks)' );

	$res = Denials::save( $admin, $r_denyer, array() );
	$rw_ok( true === $res && $rw_fresh_can( $multi_b, 'edit_posts' ), 'lifting the denial restores the grant (cache invalidated)' );
	Denials::save( $admin, $r_denyer, array( 'edit_posts' ) );

	// Admin protection.
	foreach ( array( Caps::MANAGE, Caps::MANAGE_ROLES, 'manage_options', 'read' ) as $cap ) {
		$res = Denials::save( $admin, 'administrator', array( $cap ) );
		$rw_ok( is_wp_error( $res ) && 'rolewright_protected_role' === $res->get_error_code(), "administrator role cannot be denied $cap (" . $rw_code( $res ) . ')' );
	}
	$rw_ok( array() === Denials::for_role( 'administrator' ), 'no administrator denial was stored' );
	$rw_ok( true === Denials::save( $admin, $r_junior, array( Caps::MANAGE, Caps::MANAGE_ROLES, 'edit_posts' ) ), 'setup: deny plugin caps on a secondary role of an administrator' );
	$rw_ok( $rw_fresh_can( $admin2, Caps::MANAGE ) && $rw_fresh_can( $admin2, Caps::MANAGE_ROLES ), 'administrator with a denying secondary role keeps plugin caps' );
	$rw_ok( ! empty( Guard::user_caps( $admin2 )[ Caps::MANAGE ] ), 'Guard still sees plugin caps on that administrator' );
	$rw_ok( ! $rw_fresh_can( $admin2, 'edit_posts' ), 'other denials still apply to that administrator' );
	$rw_ok( ! $rw_fresh_can( $ops, Caps::MANAGE ), 'non-administrator holding the same role loses rolewright_manage' );
	Denials::save( $admin, $r_junior, array() );

	// Direct option tampering cannot strip an administrator of plugin caps either.
	update_option( Denials::OPTION, array( 'administrator' => array( Caps::MANAGE ) ) );
	$rw_ok( $rw_fresh_can( $admin, Caps::MANAGE ), 'administrator keeps rolewright_manage even if the option lists it' );
	update_option( Denials::OPTION, array( $r_denyer => array( 'edit_posts' ) ) );

	// read on own role, lockout, escalation through lifting.
	$res = Denials::save( $admin2, $r_junior, array( 'read' ) );
	$rw_ok( is_wp_error( $res ) && 'rolewright_lockout' === $res->get_error_code(), 'cannot deny read on a role the actor holds (' . $rw_code( $res ) . ')' );
	$rw_ok( true === Denials::save( $admin, $r_peer, array( 'read' ) ), 'can deny read on a role the actor does not hold' );
	Denials::save( $admin, $r_peer, array() );

	$rw_ok( true === Hierarchy::save_positions( $admin, array( $r_ops => 80 ) ), 'setup: ops role at 80' );
	$res = Denials::save( $ops, $r_junior, array( Caps::MANAGE ) );
	$rw_ok( is_wp_error( $res ) && 'rolewright_lockout' === $res->get_error_code() && in_array( 'manage', (array) $res->get_error_data()['reasons'], true ), 'refuses a denial set that locks the actor out of Rolewright (' . $rw_code( $res ) . ')' );
	$rw_ok( $rw_fresh_can( $ops, Caps::MANAGE ), 'lockout attempt left the actor\'s access intact' );

	Denials::save( $admin, $r_junior, array( 'edit_posts' ) );
	$res = Denials::save( $ops, $r_junior, array() );
	$rw_ok( is_wp_error( $res ) && 'rolewright_cap_not_held' === $res->get_error_code(), 'cannot lift a denial on a cap the actor does not hold (' . $rw_code( $res ) . ')' );
	Denials::save( $admin, $r_junior, array() );

	$res = Denials::save( $admin, $r_junior, array( 'Bad Cap!' ) );
	$rw_ok( is_wp_error( $res ) && 'rolewright_invalid_cap' === $res->get_error_code(), 'invalid cap name refused' );
	$res = Denials::save( $admin, 'no_such_role_' . $rw_s, array( 'read' ) );
	$rw_ok( is_wp_error( $res ) && 'rolewright_no_role' === $res->get_error_code(), 'unknown role refused' );

	// Hierarchy defaults and positions.
	$rw_ok( 100 === Hierarchy::role_position( 'administrator' ) && 70 === Hierarchy::role_position( 'editor' ) && 20 === Hierarchy::role_position( 'author' ) && 0 === Hierarchy::role_position( 'subscriber' ), 'default positions: admin 100, editor 70, author 20, subscriber 0' );
	$rw_ok( 90 === Hierarchy::role_position( $r_manager ) && Guard::can_assign_role( $manager, 'author', $junior ), 'unconfigured user-manager role defaults to 90 and keeps assigning lower roles' );
	$rw_ok( is_wp_error( Hierarchy::save_positions( $admin, array( 'administrator' => 50 ) ) ), 'administrator position is fixed' );
	$rw_ok( is_wp_error( Hierarchy::save_positions( $admin, array( $r_senior => 150 ) ) ) && is_wp_error( Hierarchy::save_positions( $admin, array( $r_senior => 'x' ) ) ), 'out-of-range and non-numeric positions refused' );
	$before_events = count( $rw_events );
	$res           = Hierarchy::save_positions( $admin, array( $r_manager => 50, $r_peer => 50, $r_senior => 60, $r_junior => 10, $r_denyer => 5 ) );
	$rw_ok( true === $res && 60 === Hierarchy::role_position( $r_senior ) && 50 === Hierarchy::user_position( $manager ), 'admin sets positions' );
	$last = end( $rw_events );
	$rw_ok( count( $rw_events ) === $before_events + 1 && 'access.updated' === $last[0] && 'role_positions' === $last[1]['target'] && isset( $last[1]['before']['positions'], $last[1]['after']['positions'][ $r_senior ] ), 'positions change fires access.updated with before/after' );

	// Rules as the manager (position 50, holds promote/edit/delete users).
	$rw_ok( Guard::can_assign_role( $manager, $r_junior, $junior2 ), 'manager can assign a role below to a user below' );
	$rw_ok( ! Guard::can_assign_role( $manager, $r_senior, $junior2 ), 'manager cannot assign a role above (Guard alone would allow it)' );
	$rw_ok( ! Guard::can_assign_role( $manager, $r_peer, $junior2 ), 'manager cannot assign a role at the same position' );
	$rw_ok( ! Guard::can_assign_role( $manager, $r_manager, 0 ), 'manager cannot assign own role to a new user' );
	$rw_ok( ! Guard::can_assign_role( $manager, $r_junior, $manager ), 'manager cannot change own role, even downwards' );
	$rw_ok( ! Guard::can_assign_role( $manager, $r_junior, $senior ), 'manager cannot reassign a user above' );
	$rw_ok( ! Guard::can_act_on_user( $manager, $senior ) && ! Guard::can_act_on_user( $manager, $peer ) && Guard::can_act_on_user( $manager, $junior ), 'can_act_on_user: above and peer refused, below allowed' );
	$rw_ok( true !== Hierarchy::assert_can_manage_role( $manager, $r_senior ) && true !== Hierarchy::assert_can_manage_role( $manager, $r_manager ) && true === Hierarchy::assert_can_manage_role( $manager, $r_junior ), 'assert_can_manage_role: own and higher roles refused' );
	$res = Denials::save( $manager, $r_senior, array( 'edit_posts' ) );
	$rw_ok( is_wp_error( $res ) && 'rolewright_role_above_position' === $res->get_error_code(), 'manager cannot set denials on a role above' );
	$rw_ok( is_wp_error( Hierarchy::save_positions( $manager, array( $r_senior => 10 ) ) ), 'manager cannot move a role above them' );
	$rw_ok( is_wp_error( Hierarchy::save_positions( $manager, array( $r_junior => 50 ) ) ), 'manager cannot raise a role to their own position' );
	$rw_ok( true === Hierarchy::save_positions( $manager, array( $r_junior => 40 ) ) && 40 === Hierarchy::role_position( $r_junior ), 'manager can move a role below them to a position below them' );
	Hierarchy::save_positions( $admin, array( $r_junior => 10 ) );

	wp_set_current_user( $manager );
	$editable = get_editable_roles();
	$rw_ok( ! isset( $editable['administrator'] ) && ! isset( $editable[ $r_senior ] ) && ! isset( $editable[ $r_peer ] ) && ! isset( $editable[ $r_manager ] ) && isset( $editable[ $r_junior ] ) && isset( $editable['subscriber'] ), 'editable_roles hides administrator, higher and same-level roles' );
	$rw_ok( ! current_user_can( 'edit_user', $senior ) && ! current_user_can( 'delete_user', $senior ) && ! current_user_can( 'promote_user', $peer ) && current_user_can( 'edit_user', $junior ), 'meta caps: cannot edit/delete/promote users at or above' );

	// Users list.
	$GLOBALS['pagenow']        = 'users.php';
	$GLOBALS['current_screen'] = WP_Screen::get( 'users' );
	$listed                    = array_map( 'intval', ( new WP_User_Query( array( 'fields' => 'ID', 'number' => -1 ) ) )->get_results() );
	$rw_ok( ! in_array( $admin, $listed, true ) && ! in_array( $senior, $listed, true ) && in_array( $junior, $listed, true ) && in_array( $peer, $listed, true ), 'users list hides administrators and higher-role users, keeps peers and lower' );
	$by_role = array_map( 'intval', ( new WP_User_Query( array( 'fields' => 'ID', 'role' => 'administrator' ) ) )->get_results() );
	$rw_ok( array() === $by_role, 'users list filtered by role=administrator returns nobody' );
	$views = Hierarchy::filter_user_views(
		array(
			'all'           => '<a href="#">All <span class="count">(999)</span></a>',
			'administrator' => '<a href="#">Administrator <span class="count">(2)</span></a>',
			$r_junior       => '<a href="#">Junior <span class="count">(1)</span></a>',
		)
	);
	$rw_ok( ! isset( $views['administrator'] ) && isset( $views[ $r_junior ] ) && false === strpos( $views['all'], '(999)' ), 'users list views drop hidden roles and recount All' );
	unset( $GLOBALS['current_screen'] );
	$GLOBALS['pagenow'] = 'index.php';

	// REST bypass attempts as the manager.
	$r = $rw_rest( 'POST', '/wp/v2/users/' . $junior2, array( 'roles' => array( $r_senior ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $junior2, $r_senior ), 'REST: cannot give a user a higher role (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'POST', '/wp/v2/users/' . $junior2, array( 'roles' => array( $r_peer ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $junior2, $r_peer ), 'REST: cannot give a same-level role (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'POST', '/wp/v2/users/' . $senior, array( 'roles' => array( $r_junior ) ) );
	$rw_ok( $r->is_error() && $rw_has_role( $senior, $r_senior ), 'REST: cannot demote a higher user (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'POST', '/wp/v2/users/' . $peer, array( 'first_name' => 'X' ) );
	$rw_ok( $r->is_error(), 'REST: cannot edit a peer (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'POST', '/wp/v2/users/me', array( 'roles' => array( $r_junior ) ) );
	$rw_ok( $r->is_error() && $rw_has_role( $manager, $r_manager ) && ! $rw_has_role( $manager, $r_junior ), 'REST: cannot change own role via /users/me (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'POST', '/wp/v2/users/' . $manager, array( 'roles' => array( $r_manager, $r_senior ) ) );
	$rw_ok( $r->is_error() && ! $rw_has_role( $manager, $r_senior ), 'REST: cannot add a higher role to self by id (status ' . $r->get_status() . ')' );
	$r       = $rw_rest(
		'POST',
		'/wp/v2/users',
		array(
			'username' => 'rw_rest_' . $rw_s,
			'email'    => 'rw_rest_' . $rw_s . '@example.com',
			'password' => wp_generate_password( 24 ),
			'roles'    => array( $r_senior ),
		)
	);
	$created = get_user_by( 'login', 'rw_rest_' . $rw_s );
	if ( $created ) {
		$rw_users[] = (int) $created->ID;
	}
	$rw_ok( $r->is_error() && ( ! $created || ! in_array( $r_senior, (array) $created->roles, true ) ), 'REST: cannot create a user with a higher role (status ' . $r->get_status() . ')' );
	$r = $rw_rest( 'DELETE', '/wp/v2/users/' . $senior, array( 'force' => true, 'reassign' => $manager ) );
	$rw_ok( $r->is_error() && get_userdata( $senior ), 'REST: cannot delete a higher user (status ' . $r->get_status() . ')' );
	$r   = $rw_rest( 'GET', '/wp/v2/users', array( 'context' => 'edit', 'per_page' => 100 ) );
	$ids = $r->is_error() ? array( -1 ) : array_map( 'intval', wp_list_pluck( $r->get_data(), 'id' ) );
	$rw_ok( ! in_array( $admin, $ids, true ) && ! in_array( $senior, $ids, true ) && in_array( $junior, $ids, true ), 'REST: user listing hides administrators and higher-role users' );
	$r = $rw_rest( 'GET', '/wp/v2/users', array( 'context' => 'edit', 'roles' => array( 'administrator' ) ) );
	$rw_ok( ! $r->is_error() && array() === $r->get_data(), 'REST: ?roles=administrator returns nothing' );
	$r = $rw_rest( 'GET', '/wp/v2/users/' . $admin, array( 'context' => 'edit' ) );
	$rw_ok( $r->is_error(), 'REST: cannot read an administrator in edit context (status ' . $r->get_status() . ')' );

	$r = $rw_rest( 'POST', '/wp/v2/users/' . $junior2, array( 'roles' => array( 'subscriber' ) ) );
	$rw_ok( ! $r->is_error() && $rw_has_role( $junior2, 'subscriber' ), 'REST control: manager can still assign a lower role to a lower user' );
	$r = $rw_rest( 'DELETE', '/wp/v2/users/' . $junior2, array( 'force' => true, 'reassign' => $manager ) );
	$rw_ok( ! $r->is_error() && ! get_userdata( $junior2 ), 'REST control: manager can still delete a lower user' );

	// Top of the hierarchy is unaffected.
	wp_set_current_user( $admin );
	$rw_ok( Guard::can_assign_role( $admin, $r_senior, $junior ) && Guard::can_assign_role( $admin, 'administrator', $junior ) && Guard::can_act_on_user( $admin, $admin2 ), 'administrator is not limited by the hierarchy' );
	$rw_ok( array() === Hierarchy::hidden_roles_for( $admin ), 'administrator sees every role' );
	wp_set_current_user( 0 );
} catch ( \Throwable $e ) {
	$rw_ok( false, 'uncaught ' . get_class( $e ) . ': ' . $e->getMessage() . ' @ ' . basename( $e->getFile() ) . ':' . $e->getLine() );
}

// Cleanup.
wp_set_current_user( 0 );
unset( $GLOBALS['current_screen'] );
remove_action( 'rolewright_changed', $rw_listener, 10 );
foreach ( array_unique( $rw_users ) as $uid ) {
	if ( get_userdata( $uid ) ) {
		wp_delete_user( $uid );
	}
}
foreach ( $rw_roles as $r ) {
	remove_role( $r );
}
foreach ( array( Denials::OPTION => $rw_old_deny, Hierarchy::OPTION => $rw_old_pos ) as $opt => $old ) {
	if ( null === $old ) {
		delete_option( $opt );
	} else {
		update_option( $opt, $old );
	}
}
Denials::reset_cache();
Hierarchy::reset_cache();
$rw_ok( ! get_role( 'rw_t_manager_' . $rw_s ) && ! get_user_by( 'login', 'rw_admin_' . $rw_s ) && get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'cleanup: temp roles and users removed, administrator intact' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
