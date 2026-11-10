<?php
/**
 * Needs a multisite install with the plugin network-activated. Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/disabled-users-multisite-smoke.php
 * The cookie request to a subsite's wp-admin needs the multisite rewrite rules (.htaccess) in place.
 * Base URL for the cookie request: RW_HTTP_BASE (default http://wordpress, the wp-env web container), Host header from the network domain.
 */

use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Disabled_Users\Users_List;
use Rolegate\Modules\Portability\Disable_Users_Migration;
use Rolegate\Modules\Portability\Migrator;
use Rolegate\Modules\Safety\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}
if ( ! is_multisite() ) {
	echo "FAIL this test needs a multisite install\n";
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
$rw_code = function ( $res ) {
	return is_wp_error( $res ) ? $res->get_error_code() : ( true === $res ? 'true' : 'other' );
};

add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );

$rw_sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_pw    = 'Rw-' . $rw_sfx . '-pass!9';
$rw_users = array();
$rw_sites = array();
$rw_main  = get_main_site_id();
$rw_make  = function ( $login, $role, array $blogs ) use ( &$rw_users, $rw_sfx, $rw_pw, $rw_main ) {
	$id = wpmu_create_user( $login . '_' . $rw_sfx, $rw_pw, $login . '_' . $rw_sfx . '@example.com' );
	if ( ! $id ) {
		echo 'SETUP ERROR could not create ' . $login . "\n";
		exit( 1 );
	}
	$rw_users[] = (int) $id;
	foreach ( $blogs as $blog ) {
		add_user_to_blog( $blog, $id, $role );
	}
	if ( ! in_array( $rw_main, $blogs, true ) ) {
		remove_user_from_blog( $id, $rw_main );
	}
	return (int) $id;
};
$rw_login_of = function ( $id ) {
	clean_user_cache( $id );
	return get_userdata( $id )->user_login;
};
$rw_post = function ( array $extra ) {
	$_POST    = $extra;
	$_REQUEST = $extra;
};
$rw_http_base = getenv( 'RW_HTTP_BASE' ) ? rtrim( (string) getenv( 'RW_HTTP_BASE' ), '/' ) : 'http://wordpress';
$rw_host      = (string) get_network()->domain;

$rw_pre_mgr      = array();
$rw_pre_disabled = array();
$rw_switched     = false;

try {
	foreach ( array( 'a', 'b' ) as $rw_k ) {
		$site = wp_insert_site(
			array(
				'domain' => (string) get_network()->domain,
				'path'   => '/rw-' . $rw_k . '-' . $rw_sfx . '/',
				'title'  => 'RW ' . $rw_k,
			)
		);
		if ( is_wp_error( $site ) ) {
			echo 'SETUP ERROR ' . $site->get_error_message() . "\n";
			exit( 1 );
		}
		$rw_sites[ $rw_k ] = (int) $site;
	}
	$rw_a = $rw_sites['a'];
	$rw_b = $rw_sites['b'];
	$rw_ok( $rw_a > 1 && $rw_b > 1 && $rw_a !== $rw_b, 'setup: two subsites created' );

	foreach ( array( $rw_a, $rw_b ) as $rw_blog ) {
		switch_to_blog( $rw_blog );
		Caps::grant_to_administrator();
		restore_current_blog();
	}

	$rw_sadmin  = $rw_make( 'rw_dm_siteadmin', 'administrator', array( $rw_a ) );
	$rw_member  = $rw_make( 'rw_dm_member', 'subscriber', array( $rw_a, $rw_b ) );
	$rw_member2 = $rw_make( 'rw_dm_member2', 'subscriber', array( $rw_a ) );
	$rw_out_b   = $rw_make( 'rw_dm_only_b', 'subscriber', array( $rw_b ) );
	$rw_super   = $rw_make( 'rw_dm_super', 'administrator', array( $rw_a, $rw_b ) );
	$rw_super2  = $rw_make( 'rw_dm_super2', 'subscriber', array( $rw_a ) );
	grant_super_admin( $rw_super );
	grant_super_admin( $rw_super2 );
	$rw_ok( ! is_super_admin( $rw_sadmin ) && is_super_admin( $rw_super ) && is_super_admin( $rw_super2 ), 'setup: a site admin and two super admins' );

	switch_to_blog( $rw_a );
	$rw_switched = true;
	$rw_ok( get_current_blog_id() === $rw_a && is_user_member_of_blog( $rw_member, $rw_a ) && ! is_user_member_of_blog( $rw_out_b, $rw_a ) && is_user_member_of_blog( $rw_out_b, $rw_b ), 'setup: working on subsite A; the only-B user is not a member of A' );

	// Other managers out of the way, so the last-manager rule can be exercised. Restored at the end.
	$rw_pre_mgr = array_values( array_diff( Accounts::active_managers(), array( $rw_super, $rw_super2, $rw_sadmin ) ) );
	foreach ( $rw_pre_mgr as $rw_id ) {
		Accounts::write( $rw_id, true );
	}
	$rw_trio = array( $rw_sadmin, $rw_super, $rw_super2 );
	sort( $rw_trio );
	$rw_ok( $rw_trio === Accounts::active_managers(), 'setup: the three test users are the only active managers on A (' . implode( ',', Accounts::active_managers() ) . ')' );

	// Actor rules. On multisite a site admin needs manage_network_users (core's edit_user rule), and gets a clear error without it.
	$rw_res = Accounts::check( $rw_sadmin, $rw_member, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_needs_network_users' === $rw_res->get_error_code(), 'actor: a site admin without manage_network_users gets the network-users error, not "holds capabilities" (' . $rw_code( $rw_res ) . ')' );
	get_userdata( $rw_sadmin )->add_cap( 'manage_network_users' );
	$rw_res = Accounts::check( $rw_sadmin, $rw_out_b, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_not_site_member' === $rw_res->get_error_code(), 'actor: a site admin cannot disable a user outside their site (' . $rw_code( $rw_res ) . ')' );
	$rw_res = Accounts::change( $rw_sadmin, $rw_out_b, true );
	$rw_ok( is_wp_error( $rw_res ) && ! Accounts::is_disabled( $rw_out_b ) && '' === (string) get_user_meta( $rw_out_b, 'rolegate_disabled', true ), 'actor: change() refuses and the outsider carries no disabled flag' );
	$rw_res = Accounts::change( $rw_sadmin, $rw_member, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_member ), 'actor control: the same site admin can disable a member of their site' );
	$rw_res = Accounts::change( $rw_sadmin, $rw_member, false );
	$rw_ok( true === $rw_res && ! Accounts::is_disabled( $rw_member ), 'actor control: and enable them again' );
	Accounts::write( $rw_out_b, true );
	$rw_res = Accounts::change( $rw_sadmin, $rw_out_b, false );
	$rw_ok( is_wp_error( $rw_res ) && Accounts::is_disabled( $rw_out_b ), 'actor: a site admin cannot enable an outsider either' );
	Accounts::write( $rw_out_b, false );

	$rw_ok( is_user_member_of_blog( $rw_super, $rw_a ), 'setup: the super admin is a member of A, so only the authority rule applies' );
	$rw_res = Accounts::change( $rw_sadmin, $rw_super, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_user_above_actor' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_super ), 'actor: a site admin cannot disable a super admin (' . $rw_code( $rw_res ) . ')' );

	$rw_res = Accounts::change( $rw_super, $rw_out_b, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_out_b ), 'actor: a super admin can disable a user who is not a member of A' );
	$rw_res = Accounts::change( $rw_super, $rw_member2, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_member2 ), 'actor: a super admin can disable a member of A' );
	$rw_res = Accounts::change( $rw_super, $rw_sadmin, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_sadmin ), 'actor: a super admin can disable a site admin' );
	$rw_res = Accounts::change( $rw_super, $rw_super2, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_super2 ), 'actor: a super admin can disable another super admin' );
	Accounts::write( $rw_sadmin, false );
	Accounts::write( $rw_super2, false );
	Accounts::write( $rw_member2, false );
	Accounts::write( $rw_out_b, false );

	// Disabled on A, refused on B.
	$rw_res = Accounts::change( $rw_super, $rw_member, true );
	$rw_ok( true === $rw_res && '1' === get_user_meta( $rw_member, 'rolegate_disabled', true ), 'cross-site: a member of A and B is disabled from A; the flag is plain user meta' );
	restore_current_blog();
	$rw_switched = false;
	switch_to_blog( $rw_b );
	$rw_ok( Accounts::is_disabled( $rw_member ), 'cross-site: the account reads as disabled on subsite B' );
	$rw_lr = wp_authenticate( $rw_login_of( $rw_member ), $rw_pw );
	$rw_ok( is_wp_error( $rw_lr ) && 'rolegate_disabled' === $rw_lr->get_error_code(), 'cross-site: login on subsite B with the right password is refused (' . $rw_code( $rw_lr ) . ')' );
	$rw_tok = WP_Session_Tokens::get_instance( $rw_member )->create( time() + HOUR_IN_SECONDS );
	$rw_ck  = wp_generate_auth_cookie( $rw_member, time() + HOUR_IN_SECONDS, 'logged_in', $rw_tok );
	$rw_ok( (int) $rw_member === (int) wp_validate_auth_cookie( $rw_ck, 'logged_in' ), 'cross-site control: a session minted after disabling still validates as a cookie on B' );
	$_COOKIE[ LOGGED_IN_COOKIE ] = $rw_ck;
	$rw_ok( false === apply_filters( 'determine_current_user', false ), 'cross-site: the cookie no longer identifies the user on subsite B' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );

	$rw_path = (string) wp_parse_url( get_home_url( $rw_b, '/' ), PHP_URL_PATH ) . 'wp-admin/profile.php';
	$rw_get  = function ( $id ) use ( $rw_http_base, $rw_host, $rw_path ) {
		$tok = WP_Session_Tokens::get_instance( $id )->create( time() + HOUR_IN_SECONDS );
		$ck  = wp_generate_auth_cookie( $id, time() + HOUR_IN_SECONDS, 'logged_in', $tok );
		$ak  = wp_generate_auth_cookie( $id, time() + HOUR_IN_SECONDS, 'auth', $tok );
		$r   = wp_remote_get(
			$rw_http_base . $rw_path,
			array(
				'redirection' => 0,
				'timeout'     => 30,
				'headers'     => array(
					'Host'   => $rw_host,
					'Cookie' => LOGGED_IN_COOKIE . '=' . rawurlencode( $ck ) . '; ' . AUTH_COOKIE . '=' . rawurlencode( $ak ),
				),
			)
		);
		return is_wp_error( $r ) ? array( 'code' => 0, 'loc' => $r->get_error_message() ) : array( 'code' => (int) wp_remote_retrieve_response_code( $r ), 'loc' => (string) wp_remote_retrieve_header( $r, 'location' ) );
	};
	$rw_h = $rw_get( $rw_member );
	$rw_ok( in_array( $rw_h['code'], array( 302, 401, 403 ), true ), 'cross-site HTTP: a disabled user\'s valid cookies are refused on B\'s wp-admin, not served the profile page (HTTP ' . $rw_h['code'] . ' ' . $rw_h['loc'] . ')' );
	Accounts::write( $rw_member, false );
	$rw_h = $rw_get( $rw_member );
	$rw_ok( 200 === $rw_h['code'], 'cross-site HTTP control: once enabled, the same user\'s cookie reaches B\'s wp-admin (HTTP ' . $rw_h['code'] . ' ' . $rw_h['loc'] . ')' );
	$rw_lr = wp_authenticate( $rw_login_of( $rw_member ), $rw_pw );
	$rw_ok( $rw_lr instanceof WP_User, 'cross-site control: an enabled user logs in on B' );
	restore_current_blog();

	// Last network manager.
	switch_to_blog( $rw_a );
	$rw_switched = true;
	$rw_res = Accounts::check( $rw_super, $rw_super2, true );
	$rw_ok( true === $rw_res, 'last manager control: with three active managers a super admin can be disabled' );
	Accounts::write( $rw_sadmin, true );
	Accounts::write( $rw_super2, true );
	$rw_ok( array( $rw_super ) === Accounts::active_managers(), 'last manager setup: one active manager, a super admin' );
	$rw_res = Accounts::check( $rw_sadmin, $rw_super, true );
	$rw_ok( is_wp_error( $rw_res ), 'last manager: a site admin cannot disable them (' . $rw_code( $rw_res ) . ')' );
	$rw_res = Accounts::check( $rw_super2, $rw_super, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_last_manager' === $rw_res->get_error_code(), 'last manager: another super admin cannot disable them (' . $rw_code( $rw_res ) . ')' );
	$rw_res = Accounts::change( $rw_super2, $rw_super, true );
	$rw_ok( is_wp_error( $rw_res ) && ! Accounts::is_disabled( $rw_super ), 'last manager: change() refuses and the flag stays off' );
	$rw_res = Accounts::check( $rw_super2, $rw_super, false );
	$rw_ok( true === $rw_res, 'last manager control: enabling them is not blocked by the rule' );
	Accounts::write( $rw_super, false );
	Accounts::write( $rw_sadmin, false );
	Accounts::write( $rw_super2, true );
	Accounts::write( $rw_super, true );
	$rw_ok( array( $rw_sadmin ) === Accounts::active_managers(), 'last manager setup: the only active manager is the site admin' );
	$rw_res = Accounts::check( $rw_super2, $rw_sadmin, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_last_manager' === $rw_res->get_error_code(), 'last manager: a super admin cannot disable the last site-level manager (' . $rw_code( $rw_res ) . ')' );
	Accounts::write( $rw_super, false );
	Accounts::write( $rw_super2, false );

	// Bulk actions on subsite A's users.php.
	$rw_list = new Users_List();
	$rw_bulk = function ( $who, $action, array $ids ) use ( $rw_list, $rw_post ) {
		wp_set_current_user( $who );
		$rw_post( array( '_wpnonce' => wp_create_nonce( 'bulk-users' ) ) );
		$out = $rw_list->handle_bulk( admin_url( 'users.php' ), $action, $ids );
		parse_str( (string) wp_parse_url( $out, PHP_URL_QUERY ), $q );
		return $q;
	};
	$rw_q = $rw_bulk( $rw_sadmin, Users_List::DISABLE, array( $rw_member, $rw_member2, $rw_out_b, $rw_super, $rw_sadmin ) );
	$rw_ok( '2' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '3' === ( $rw_q['rolegate_dis_skip'] ?? '' ), 'bulk: a site admin disables the two members; the outsider, the super admin and themself are skipped (done ' . ( $rw_q['rolegate_dis_done'] ?? '?' ) . ', skip ' . ( $rw_q['rolegate_dis_skip'] ?? '?' ) . ')' );
	$rw_ok( Accounts::is_disabled( $rw_member ) && Accounts::is_disabled( $rw_member2 ) && ! Accounts::is_disabled( $rw_out_b ) && ! Accounts::is_disabled( $rw_super ) && ! Accounts::is_disabled( $rw_sadmin ), 'bulk: only the members of A carry the flag afterwards' );
	Accounts::write( $rw_out_b, true );
	$rw_q = $rw_bulk( $rw_sadmin, Users_List::ENABLE, array( $rw_member, $rw_out_b ) );
	$rw_ok( '1' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '1' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && ! Accounts::is_disabled( $rw_member ) && Accounts::is_disabled( $rw_out_b ), 'bulk: enabling by a site admin skips an outsider and leaves them disabled' );
	Accounts::write( $rw_out_b, false );
	Accounts::write( $rw_member2, false );
	$rw_q = $rw_bulk( $rw_super, Users_List::DISABLE, array( $rw_member, $rw_out_b, $rw_sadmin, $rw_super2 ) );
	$rw_ok( '4' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '0' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && Accounts::is_disabled( $rw_out_b ) && Accounts::is_disabled( $rw_super2 ), 'bulk: a super admin disables a member, an outsider, a site admin and another super admin' );
	Accounts::write( $rw_member, false );
	Accounts::write( $rw_out_b, false );
	Accounts::write( $rw_sadmin, false );
	Accounts::write( $rw_super2, true );
	Accounts::write( $rw_sadmin, true );
	$rw_q = $rw_bulk( $rw_super2, Users_List::DISABLE, array( $rw_super ) );
	$rw_ok( '0' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '1' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && ! Accounts::is_disabled( $rw_super ), 'bulk: the last active manager is skipped' );
	Accounts::write( $rw_super2, false );
	Accounts::write( $rw_sadmin, false );
	wp_set_current_user( $rw_sadmin );
	$rw_ok( isset( $rw_list->bulk_actions( array() )[ Users_List::DISABLE ] ), 'bulk: the actions are offered to the site admin on A' );
	$rw_post( array() );

	// Migration from Disable Users.
	$rw_ja = function ( $id, $val ) {
		update_user_meta( $id, 'ja_disable_user', $val );
	};
	$rw_m_a1  = $rw_make( 'rw_dm_ja_a1', 'subscriber', array( $rw_a ) );
	$rw_m_ab  = $rw_make( 'rw_dm_ja_ab', 'subscriber', array( $rw_a, $rw_b ) );
	$rw_m_b   = $rw_make( 'rw_dm_ja_b', 'subscriber', array( $rw_b ) );
	$rw_m_b2  = $rw_make( 'rw_dm_ja_b2', 'author', array( $rw_b ) );
	$rw_m_a0  = $rw_make( 'rw_dm_ja_a0', 'subscriber', array( $rw_a ) );
	$rw_m_sup = $rw_make( 'rw_dm_ja_sup', 'subscriber', array( $rw_a ) );
	grant_super_admin( $rw_m_sup );
	$rw_ja( $rw_m_a1, '1' );
	$rw_ja( $rw_m_ab, '1' );
	$rw_ja( $rw_m_b, '1' );
	$rw_ja( $rw_m_b2, '1' );
	$rw_ja( $rw_m_a0, '0' );
	$rw_ja( $rw_m_sup, '1' );
	$rw_in_a = array( $rw_m_a1, $rw_m_ab, $rw_m_sup );
	sort( $rw_in_a );

	$rw_flag_a = Disable_Users_Migration::flagged();
	$rw_ok( $rw_in_a === $rw_flag_a, 'migration: on A, flagged() holds only the members of A who have ja_disable_user = 1 (' . implode( ',', $rw_flag_a ) . ' vs ' . implode( ',', $rw_in_a ) . ')' );
	$rw_ok( ! in_array( $rw_m_b, $rw_flag_a, true ) && ! in_array( $rw_m_b2, $rw_flag_a, true ), 'migration: flagged() leaves out users who belong only to B' );
	$rw_ok( ! in_array( $rw_m_a0, $rw_flag_a, true ), 'migration: a member of A with ja_disable_user = 0 is not flagged' );

	$rw_plan = Migrator::plan( 'disable-users', $rw_super );
	$rw_ops  = is_wp_error( $rw_plan ) ? array() : $rw_plan['ops']['users'];
	sort( $rw_ops );
	$rw_ok( ! is_wp_error( $rw_plan ) && $rw_plan['detected'] && $rw_in_a === $rw_ops, 'migration plan: a super admin on A plans exactly the three members of A (' . implode( ',', $rw_ops ) . ')' );
	$rw_ok( ! in_array( $rw_m_b, $rw_ops, true ) && ! in_array( $rw_m_b2, $rw_ops, true ), 'migration plan: nothing for users outside A' );
	$rw_plan_s = Migrator::plan( 'disable-users', $rw_sadmin );
	$rw_ops_s  = is_wp_error( $rw_plan_s ) ? array() : $rw_plan_s['ops']['users'];
	sort( $rw_ops_s );
	$rw_exp_s = array( $rw_m_a1, $rw_m_ab );
	sort( $rw_exp_s );
	$rw_ok( ! is_wp_error( $rw_plan_s ) && $rw_exp_s === $rw_ops_s, 'migration plan: a site admin\'s plan drops the flagged super admin (' . implode( ',', $rw_ops_s ) . ')' );
	$rw_blocked = false;
	if ( ! is_wp_error( $rw_plan_s ) ) {
		foreach ( $rw_plan_s['rows'] as $rw_row ) {
			if ( 'blocked' === ( $rw_row['action'] ?? '' ) && false !== strpos( (string) ( $rw_row['item'] ?? '' ), 'rw_dm_ja_sup' ) ) {
				$rw_blocked = true;
			}
		}
	}
	$rw_ok( $rw_blocked, 'migration plan: a blocked row names the super admin the site admin cannot change' );

	$rw_ap = Migrator::apply( 'disable-users', $rw_super );
	$rw_ok( ! is_wp_error( $rw_ap ) && 'applied' === $rw_ap['status'] && ! $rw_ap['errors'], 'migration apply on A: applied without errors' . ( ! is_wp_error( $rw_ap ) && $rw_ap['errors'] ? ' (' . implode( ' ', $rw_ap['errors'] ) . ')' : '' ) );
	$rw_ok( Accounts::is_disabled( $rw_m_a1 ) && Accounts::is_disabled( $rw_m_ab ) && Accounts::is_disabled( $rw_m_sup ), 'migration apply on A: the members of A are disabled' );
	$rw_ok( ! Accounts::is_disabled( $rw_m_b ) && ! Accounts::is_disabled( $rw_m_b2 ) && '' === (string) get_user_meta( $rw_m_b, 'rolegate_disabled', true ), 'migration apply on A: users who belong only to B are not flagged' );
	$rw_ok( ! Accounts::is_disabled( $rw_m_a0 ), 'migration apply on A: the member with ja_disable_user = 0 is untouched' );
	$rw_ok( '1' === get_user_meta( $rw_m_b, 'ja_disable_user', true ), 'migration apply on A: Disable Users\' own flag is left as it was' );
	$rw_rec = ! is_wp_error( $rw_ap ) ? Migrator::record( $rw_ap['migration_id'] ) : null;
	$rw_rec_users = $rw_rec ? $rw_rec['users'] : array();
	sort( $rw_rec_users );
	$rw_ok( $rw_rec && $rw_in_a === $rw_rec_users, 'migration apply on A: the record lists the three members only' );
	restore_current_blog();
	$rw_switched = false;

	switch_to_blog( $rw_b );
	$rw_flag_b = Disable_Users_Migration::flagged();
	$rw_exp_b  = array( $rw_m_ab, $rw_m_b, $rw_m_b2 );
	sort( $rw_exp_b );
	$rw_ok( $rw_exp_b === $rw_flag_b, 'migration: on B, flagged() holds the members of B only (' . implode( ',', $rw_flag_b ) . ')' );
	$rw_plan_b = Migrator::plan( 'disable-users', $rw_super );
	$rw_ops_b  = is_wp_error( $rw_plan_b ) ? array() : $rw_plan_b['ops']['users'];
	sort( $rw_ops_b );
	$rw_exp_ob = array( $rw_m_b, $rw_m_b2 );
	sort( $rw_exp_ob );
	$rw_ok( $rw_exp_ob === $rw_ops_b && ! in_array( $rw_m_a1, $rw_ops_b, true ), 'migration plan on B: the two B-only users are planned; the shared user is already disabled and the A-only user is absent' );
	restore_current_blog();
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
} finally {
	while ( ms_is_switched() ) {
		restore_current_blog();
	}
	$_POST    = array();
	$_REQUEST = array();
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( 0 );
	foreach ( $rw_pre_mgr as $rw_id ) {
		Accounts::write( $rw_id, false );
	}
	foreach ( $rw_users as $rw_id ) {
		revoke_super_admin( $rw_id );
		wpmu_delete_user( $rw_id );
	}
	foreach ( $rw_sites as $rw_id ) {
		wp_delete_site( $rw_id );
	}
}

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
