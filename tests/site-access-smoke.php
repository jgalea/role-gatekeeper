<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/site-access-smoke.php
 */

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Enforcer;
use Rolewright\Modules\Safety\Rescue;
use Rolewright\Modules\Site_Access\Admin_Gate;
use Rolewright\Modules\Site_Access\Gate;
use Rolewright\Modules\Site_Access\Redirects;
use Rolewright\Modules\Site_Access\Site_Access_Module;
use Rolewright\Modules\Site_Access\Site_Access_Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
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

$rw_suffix  = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users   = array();
$rw_mails   = array();
$rw_orig    = get_option( Site_Access_Settings::OPTION, null );
$rw_make    = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_suffix,
			'user_email' => $login . '_' . $rw_suffix . '@example.com',
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
$rw_set = function ( array $over ) {
	update_option( Site_Access_Settings::OPTION, array_merge( Site_Access_Settings::defaults(), $over ), false );
};
$rw_req = function ( array $over = array() ) {
	return array_merge(
		array(
			'path'       => '/some-page',
			'logged_in'  => false,
			'member'     => true,
			'is_feed'    => false,
			'is_rest'    => false,
			'script'     => 'index.php',
			'login_path' => Gate::login_path(),
			'query_keys' => array(),
			'xmlrpc_on'  => true,
		),
		$over
	);
};
$rw_capture_mail = function ( $short, $atts ) use ( &$rw_mails ) {
	$rw_mails[] = $atts;
	return true;
};
add_filter( 'pre_wp_mail', $rw_capture_mail, 10, 2 );
wp_set_current_user( 0 );

try {
	$on   = array( 'private_enabled' => true );
	$defs = Site_Access_Settings::defaults();

	$mod = new Site_Access_Module();
	$rw_ok( false === $mod->default_enabled(), 'module is off by default' );
	$rw_ok( false === $defs['private_enabled'] && false === $defs['admin_gate'], 'private mode and admin gate are off by default' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req(), $defs ), 'off: anonymous request allowed' );

	// Confirmation on enabling.
	$err = Site_Access_Settings::sanitize( array( 'private_enabled' => '1' ), $defs, 1 );
	$rw_ok( is_wp_error( $err ) && 'rolewright_confirm' === $err->get_error_code(), 'enabling private mode without confirmation is refused' );
	$okc = Site_Access_Settings::sanitize( array( 'private_enabled' => '1', 'confirm_private' => '1' ), $defs, 1 );
	$rw_ok( is_array( $okc ) && true === $okc['private_enabled'], 'enabling with confirmation is accepted' );
	$again = Site_Access_Settings::sanitize( array( 'private_enabled' => '1' ), $on + $defs, 1 );
	$rw_ok( is_array( $again ), 'already-on mode saves without asking again' );

	// Basic decisions.
	$s = array_merge( $defs, $on );
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req(), $s ), 'on: anonymous page request goes to login' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'logged_in' => true ) ), $s ), 'on: logged-in user allowed' );
	$rw_ok( Gate::DENY === Gate::decide( $rw_req( array( 'logged_in' => true, 'member' => false ) ), $s ), 'on: logged-in non-member gets a 403, not a redirect (no loop)' );

	// Loop checks.
	$login_path = Gate::login_path();
	$rw_ok( '/wp-login.php' === $login_path, 'default login path is /wp-login.php' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => $login_path, 'query_keys' => array( 'redirect_to', 'action' ) ) ), $s ), 'loop: the login page itself is never redirected' );
	$step1 = Gate::decide( $rw_req(), $s );
	$step2 = Gate::decide( $rw_req( array( 'path' => $login_path ) ), $s );
	$rw_ok( Gate::LOGIN === $step1 && Gate::ALLOW === $step2, 'loop: page -> login ends at the login page in two hops' );
	$custom = function () {
		return home_url( '/members-login/' );
	};
	add_filter( 'login_url', $custom );
	$cp = Gate::login_path();
	$rw_ok( '/members-login' === $cp && Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/members-login', 'login_path' => $cp ) ), $s ), 'loop: custom login URL via login_url filter stays open' );
	remove_filter( 'login_url', $custom );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/sso/callback', 'exempt_paths' => array( '/sso/callback' ) ) ), $s ), 'custom login helpers can be exempted via exempt paths' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'script' => 'wp-login.php', 'path' => '/wp-login.php', 'query_keys' => array( 'action' ) ) ), $s ), 'password reset and rescue route on wp-login.php stay open' );

	// Script exemptions.
	foreach ( array( 'wp-cron.php', 'admin-ajax.php', 'admin-post.php', 'wp-login.php' ) as $script ) {
		$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'script' => $script, 'path' => null ) ), $s ), 'exempt script: ' . $script );
	}
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'script' => 'xmlrpc.php', 'path' => null ) ), $s ), 'xmlrpc.php open when XML-RPC is enabled' );
	$rw_ok( Gate::ALLOW !== Gate::decide( $rw_req( array( 'script' => 'xmlrpc.php', 'path' => null, 'xmlrpc_on' => false ) ), $s ), 'xmlrpc.php not exempted when XML-RPC is disabled' );

	// Feeds and REST.
	$rw_ok( Gate::DENY === Gate::decide( $rw_req( array( 'is_feed' => true, 'path' => '/feed' ) ), $s ), 'feed: anonymous refused when feeds are private' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'is_feed' => true, 'path' => '/feed' ) ), array_merge( $s, array( 'private_feed' => false ) ) ), 'feed: open when the feed option is off' );
	$gate = new Gate();
	$gate->register();
	$rw_ok( false !== has_filter( 'rest_authentication_errors', array( $gate, 'on_rest_auth' ) ) && false !== has_action( 'template_redirect', array( $gate, 'on_template_redirect' ) ), 'gate registers its REST and template_redirect hooks' );
	$rw_ok( 101 === has_filter( 'rest_authentication_errors', array( $gate, 'on_rest_auth' ) ), 'REST: decision runs after core\'s cookie and nonce check (priority 101)' );
	$rw_ok( false !== has_filter( 'rest_pre_dispatch', array( $gate, 'on_rest_pre_dispatch' ) ), 'REST: rest_pre_dispatch re-check is registered' );
	remove_filter( 'rest_authentication_errors', array( $gate, 'on_rest_auth' ), 101 );
	remove_filter( 'rest_pre_dispatch', array( $gate, 'on_rest_pre_dispatch' ), 10 );
	remove_filter( 'request', array( Gate::class, 'remember_request_vars' ), PHP_INT_MIN );
	remove_action( 'template_redirect', array( $gate, 'on_template_redirect' ), 0 );
	$GLOBALS['wp']->query_vars['rest_route'] = '/wp/v2/posts';
	$rw_set( $on );
	$res = $gate->on_rest_auth( null );
	$rw_ok( is_wp_error( $res ) && 401 === $res->get_error_data()['status'], 'REST: anonymous request gets 401' );
	$res = $gate->on_rest_auth( true );
	$rw_ok( is_wp_error( $res ) && 401 === $res->get_error_data()['status'], 'REST: a true result with no logged-in user (cookie without nonce, downgraded by core) gets 401' );
	$prev = new WP_Error( 'x', 'x' );
	$rw_ok( $prev === $gate->on_rest_auth( $prev ), 'REST: earlier errors are returned untouched' );
	$admin_id = $rw_make( 'rw_sa_admin', 'administrator' );
	wp_set_current_user( $admin_id );
	$rw_ok( null === $gate->on_rest_auth( null ), 'REST: logged-in or application-password user passes' );
	$rw_ok( true === $gate->on_rest_auth( true ), 'REST: request authenticated by another method (user set) passes' );
	wp_set_current_user( 0 );
	// Core order: cookie user present at 99, core drops it at 100 when there is no nonce, the gate decides at 101.
	global $wp_rest_auth_cookie;
	$rw_saved_cookie_flag = $wp_rest_auth_cookie;
	$rw_ok( false !== has_filter( 'rest_authentication_errors', 'rest_cookie_check_errors' ), 'REST: core cookie check is hooked' );
	add_filter( 'rest_authentication_errors', array( $gate, 'on_rest_auth' ), 101 );
	unset( $_REQUEST['_wpnonce'], $_SERVER['HTTP_X_WP_NONCE'] );
	wp_set_current_user( $admin_id );
	$wp_rest_auth_cookie = true;
	$res = apply_filters( 'rest_authentication_errors', null );
	$rw_ok( is_wp_error( $res ) && 'rolewright_private_site' === $res->get_error_code() && 0 === get_current_user_id(), 'REST: valid cookie without a nonce is treated as anonymous and refused' );
	wp_set_current_user( $admin_id );
	$wp_rest_auth_cookie = false;
	$res = apply_filters( 'rest_authentication_errors', null );
	$rw_ok( ! is_wp_error( $res ) && $admin_id === get_current_user_id(), 'REST: user set by application password or another auth plugin passes the full chain' );
	remove_filter( 'rest_authentication_errors', array( $gate, 'on_rest_auth' ), 101 );
	$wp_rest_auth_cookie = $rw_saved_cookie_flag;
	wp_set_current_user( 0 );
	$rw_set( array( 'private_enabled' => true, 'private_rest' => false ) );
	$rw_ok( null === $gate->on_rest_auth( null ), 'REST: open when the REST option is off' );
	$rw_set( $on );
	$exempt_rest = function () {
		return array( '/wp-json/public/v1/ping' );
	};
	add_filter( 'rolewright_site_access_exempt_rest_routes', $exempt_rest );
	$GLOBALS['wp']->query_vars['rest_route'] = '/public/v1/ping';
	$rw_ok( null === $gate->on_rest_auth( null ), 'REST: a route exempted by filter stays open' );
	remove_filter( 'rolewright_site_access_exempt_rest_routes', $exempt_rest );
	unset( $GLOBALS['wp']->query_vars['rest_route'] );

	// Allow-list.
	$sl = array_merge( $s, array( 'allow_paths' => array( '/contact', '/blog/*', '/' ) ) );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/contact' ) ), $sl ), 'allow-list: exact path' );
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req( array( 'path' => '/contact/team' ) ), $sl ), 'allow-list: exact entry does not open sub-paths' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/blog' ) ), $sl ) && Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/blog/2026/post' ) ), $sl ), 'allow-list: wildcard opens the base and everything below' );
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req( array( 'path' => '/blogger' ) ), $sl ), 'allow-list: /blog/* does not open /blogger' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => Gate::normalize_path( '/CONTACT/' ) ) ), $sl ), 'allow-list: matching is case-insensitive and ignores a trailing slash' );
	$rw_ok( null === Gate::normalize_path( '/blog/../private' ) && Gate::LOGIN === Gate::decide( $rw_req( array( 'path' => null ) ), $sl ), 'allow-list: dot segments never match' );
	$rw_ok( null === Gate::normalize_path( '/blog/%2e%2e/private' ), 'allow-list: encoded dot segments never match' );
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req( array( 'path' => '/', 'query_keys' => array( 'p' ) ) ), $sl ), 'allow-list: open home page does not open /?p=ID' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'path' => '/', 'query_keys' => array( 'utm_source' ) ) ), $sl ), 'allow-list: tracking parameters do not close an open path' );
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req( array( 'path' => '/contact', 'query_mismatch' => true ) ), $sl ), 'allow-list: parsed query vars that differ from the path\'s rewrite close an open path' );
	$pub = (array) $GLOBALS['wp']->public_query_vars;
	$exp = Gate::rewrite_query_vars( 'pagename=contact', $pub );
	$rw_ok( array( 'pagename' => 'contact' ) === $exp, 'allow-list: rewrite-only vars for a page path' );
	$rw_ok( ! Gate::query_vars_differ( array( 'pagename' => 'contact', 'paged' => '2' ), $exp ), 'allow-list: same page with paging is not a mismatch' );
	$rw_ok( Gate::query_vars_differ( array( 'pagename' => 'contact', 'page_id' => '42' ), $exp ), 'allow-list: page_id added on top of the rewrite is a mismatch' );
	$rw_ok( Gate::query_vars_differ( array( 'pagename' => 'contact', 'p' => '42' ), $exp ), 'allow-list: p added on top of the rewrite is a mismatch' );
	$rw_ok( Gate::query_vars_differ( array( 'pagename' => 'secret' ), $exp ), 'allow-list: a replaced pagename is a mismatch' );
	$rw_ok( Gate::query_vars_differ( array( 's' => 'x' ), Gate::rewrite_query_vars( '', $pub ) ), 'allow-list: a search on the front page is a mismatch' );
	$rw_ok( ! Gate::query_vars_differ( array(), Gate::rewrite_query_vars( '', $pub ) ), 'allow-list: plain front page is not a mismatch' );
	$rw_saved_wp = array( $GLOBALS['wp']->matched_query, $GLOBALS['wp']->query_vars );
	$GLOBALS['wp']->matched_query = 'pagename=contact';
	Gate::remember_request_vars( array( 'pagename' => 'contact', 'page_id' => '42' ) );
	$rw_ok( true === Gate::resolved_query_differs(), 'allow-list: POSTed page_id merged by WordPress is detected after parsing' );
	Gate::remember_request_vars( array( 'pagename' => 'contact' ) );
	$rw_ok( false === Gate::resolved_query_differs(), 'allow-list: the allow-listed page itself is not flagged' );
	list( $GLOBALS['wp']->matched_query, $GLOBALS['wp']->query_vars ) = $rw_saved_wp;
	Gate::remember_request_vars( $GLOBALS['wp']->query_vars );
	$rw_ok( '' === Site_Access_Settings::clean_path( 'https://evil.example/x' ) && '' === Site_Access_Settings::clean_path( '//evil.example' ) && '' === Site_Access_Settings::clean_path( '/*' ), 'allow-list input: full URLs and a root wildcard are dropped' );
	$rw_ok( '/blog/*' === Site_Access_Settings::clean_path( 'Blog/*?x=1' ) && '/contact' === Site_Access_Settings::clean_path( '/Contact/' ), 'allow-list input: cleaned to lowercase /path forms' );
	$rw_ok( '/..' !== Site_Access_Settings::clean_path( '/../x' ) && '' === Site_Access_Settings::clean_path( '/../x' ), 'allow-list input: dot segments dropped' );

	// Path relative to a subdirectory install.
	$rw_ok( '/' === Gate::relative_path( '/index.php' ) && '/about' === Gate::relative_path( '/index.php/About/' ), 'paths: /index.php prefix is ignored' );

	// Admin gate.
	$editor = $rw_make( 'rw_sa_editor', 'editor' );
	$sub    = $rw_make( 'rw_sa_sub', 'subscriber' );
	$gated  = array_merge( $defs, array( 'admin_gate' => true, 'admin_gate_cap' => 'edit_posts', 'toolbar_hide_roles' => array( 'editor' ) ) );
	$rw_ok( Admin_Gate::is_gated( get_userdata( $sub ), $gated ), 'admin gate: subscriber is redirected' );
	$rw_ok( ! Admin_Gate::is_gated( get_userdata( $editor ), $gated ), 'admin gate: editor with edit_posts passes' );
	$rw_ok( ! Admin_Gate::is_gated( get_userdata( $admin_id ), array_merge( $gated, array( 'admin_gate_cap' => 'rw_nobody_has_this' ) ) ), 'admin gate: administrator is never gated, even with an impossible capability' );
	$rw_ok( ! Admin_Gate::is_gated( get_userdata( $sub ), $defs ), 'admin gate: off means nobody is gated' );
	$mgr = $rw_make( 'rw_sa_mgr', 'subscriber' );
	get_userdata( $mgr )->add_cap( Caps::MANAGE );
	$rw_ok( ! Admin_Gate::is_gated( get_userdata( $mgr ), $gated ), 'admin gate: a user with Rolewright manage access is never gated' );
	$rw_ok( home_url( '/' ) === Admin_Gate::target( $gated ), 'admin gate: default target is the home page' );
	foreach ( array( admin_url( 'index.php' ), wp_login_url(), 'https://evil.example/phish', '//evil.example', home_url( '/wp-admin/profile.php' ) ) as $bad ) {
		$tgt = Admin_Gate::target( array_merge( $gated, array( 'admin_redirect' => $bad ) ) );
		$rw_ok( home_url( '/' ) === $tgt, 'admin gate: stored target refused at runtime: ' . $bad );
	}
	$rw_ok( home_url( '/account/' ) === Admin_Gate::target( array_merge( $gated, array( 'admin_redirect' => home_url( '/account/' ) ) ) ), 'admin gate: a same-site page is used as the target' );
	$tgt_path = (string) wp_parse_url( Admin_Gate::target( $gated ), PHP_URL_PATH );
	$rw_ok( false === strpos( $tgt_path, 'wp-admin' ) && false === strpos( $tgt_path, 'wp-login' ), 'loop: gate target is outside wp-admin and the login page' );
	$e1 = Site_Access_Settings::sanitize( array( 'admin_gate' => '1', 'admin_gate_cap' => 'edit_posts', 'admin_redirect' => admin_url() ), $defs, $admin_id );
	$e2 = Site_Access_Settings::sanitize( array( 'admin_gate' => '1', 'admin_gate_cap' => 'edit_posts', 'admin_redirect' => 'https://evil.example/' ), $defs, $admin_id );
	$e3 = Site_Access_Settings::sanitize( array( 'admin_gate' => '1', 'admin_gate_cap' => 'rw_nobody_has_this' ), $defs, $admin_id );
	$e4 = Site_Access_Settings::sanitize( array( 'admin_gate' => '1', 'admin_gate_cap' => 'edit_posts' ), $defs, $sub );
	$rw_ok( is_wp_error( $e1 ) && is_wp_error( $e2 ), 'save: redirect URL into wp-admin or off-site is refused' );
	$rw_ok( is_wp_error( $e3 ) && 'rolewright_self_lockout' === $e3->get_error_code(), 'save: choosing a capability you lack is refused' );
	$rw_ok( is_wp_error( $e4 ), 'save: a user who lacks the chosen capability cannot set it' );

	// Toolbar.
	update_option( Site_Access_Settings::OPTION, array_merge( $gated, array( 'toolbar_hide_gated' => true ) ), false );
	$ab = new Admin_Gate();
	wp_set_current_user( $editor );
	$rw_ok( false === $ab->filter_toolbar( true ), 'toolbar: hidden for a role in the hide list' );
	wp_set_current_user( $sub );
	$rw_ok( false === $ab->filter_toolbar( true ), 'toolbar: hidden for gated users' );
	update_option( Site_Access_Settings::OPTION, array_merge( $gated, array( 'toolbar_hide_gated' => false, 'toolbar_hide_roles' => array() ) ), false );
	$rw_ok( true === $ab->filter_toolbar( true ), 'toolbar: shown when neither rule applies' );
	wp_set_current_user( $admin_id );
	update_option( Site_Access_Settings::OPTION, array_merge( $gated, array( 'toolbar_hide_roles' => array( 'editor' ) ) ), false );
	$rw_ok( true === $ab->filter_toolbar( true ), 'toolbar: shown for a role not in the list' );
	wp_set_current_user( 0 );

	// Change event.
	$events = array();
	$listen = function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	};
	add_action( 'rolewright_changed', $listen, 10, 2 );
	$rw_set( array() );
	Site_Access_Settings::save( array_merge( $defs, array( 'private_enabled' => true ) ), $admin_id );
	remove_action( 'rolewright_changed', $listen, 10 );
	$rw_ok( 1 === count( $events ) && 'access.updated' === $events[0][0] && $admin_id === $events[0][1]['actor'] && false === $events[0][1]['before']['private_enabled'] && true === $events[0][1]['after']['private_enabled'], 'rolewright_changed fires access.updated with actor, before and after' );

	// Locked-out administrator with private mode on: the rescue route stays reachable.
	$rw_set( array( 'private_enabled' => true, 'admin_gate' => true, 'admin_gate_cap' => 'rw_nobody_has_this' ) );
	Enforcer::as_system(
		function () {
			$role = get_role( 'administrator' );
			foreach ( Caps::all() as $cap ) {
				$role->remove_cap( $cap );
			}
		}
	);
	clean_user_cache( $admin_id );
	$adm = get_userdata( $admin_id );
	$rw_ok( ! $adm->has_cap( Caps::MANAGE ), 'lockout: administrator has lost the Rolewright caps' );
	$locked_settings = Site_Access_Settings::get();
	$rw_ok( Gate::LOGIN === Gate::decide( $rw_req(), $locked_settings ), 'lockout: anonymous visitors still go to the login page' );
	$rw_ok( Gate::ALLOW === Gate::decide( $rw_req( array( 'script' => 'wp-login.php', 'path' => '/wp-login.php', 'query_keys' => array( 'action' ) ) ), $locked_settings ), 'lockout: wp-login.php?action=rolewright_rescue is reachable' );
	$rw_ok( ! Admin_Gate::is_gated( $adm, $locked_settings ), 'lockout: the locked-out administrator is not redirected away from wp-admin' );
	$rw_ok( false !== has_action( 'login_footer' ) && has_action( 'login_form_' . Rescue::ACTION_REQUEST ), 'lockout: rescue hooks are registered' );
	$ip = '198.51.100.' . wp_rand( 2, 250 );
	delete_transient( 'rolewright_rl_' . md5( 'ip|' . $ip ) );
	delete_transient( 'rolewright_rl_' . md5( 'acct|' . $admin_id ) );
	delete_transient( 'rolewright_rl_' . md5( 'use|' . $ip ) );
	$rw_ok( true === Rescue::request( $adm->user_email, $ip ), 'lockout: rescue mail goes out while private mode is on' );
	$token = ( $rw_mails && preg_match( '/token=([a-f0-9]{64})/', (string) end( $rw_mails )['message'], $m ) ) ? $m[1] : '';
	$rw_ok( true === Rescue::consume( $admin_id, $token, $ip ), 'lockout: rescue link restores the Rolewright caps' );
	clean_user_cache( $admin_id );
	$rw_ok( get_userdata( $admin_id )->has_cap( Caps::MANAGE ), 'lockout: administrator can manage Rolewright again' );
	delete_transient( 'rolewright_rl_' . md5( 'ip|' . $ip ) );
	delete_transient( 'rolewright_rl_' . md5( 'use|' . $ip ) );
	delete_transient( 'rolewright_rl_' . md5( 'acct|' . $admin_id ) );

	// Settings page access.
	wp_set_current_user( $sub );
	$rw_ok( ! current_user_can( Caps::MANAGE_ACCESS ), 'page: a subscriber lacks the access-management capability' );
	wp_set_current_user( $admin_id );
	$rw_ok( current_user_can( Caps::MANAGE_ACCESS ), 'page: an administrator holds it' );
	wp_set_current_user( 0 );
} finally {
	remove_filter( 'pre_wp_mail', $rw_capture_mail, 10 );
	Caps::grant_to_administrator();
	foreach ( array_unique( $rw_users ) as $uid ) {
		if ( is_multisite() ) {
			wpmu_delete_user( $uid );
		} else {
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $uid );
		}
		delete_transient( 'rolewright_rl_' . md5( 'acct|' . $uid ) );
	}
	if ( null === $rw_orig ) {
		delete_option( Site_Access_Settings::OPTION );
	} else {
		update_option( Site_Access_Settings::OPTION, $rw_orig, false );
	}
}
$rw_ok( get_role( 'administrator' )->has_cap( Caps::MANAGE ), 'cleanup: administrator role intact' );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
