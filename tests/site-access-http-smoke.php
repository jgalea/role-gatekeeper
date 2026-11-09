<?php
/**
 * Real HTTP requests against the running site with private mode on.
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/site-access-http-smoke.php
 * Base URL: RW_HTTP_BASE (default http://wordpress, the wp-env web container), Host header from home_url().
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Site_Access\Gate;
use Rolegate\Modules\Site_Access\Site_Access_Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}
require_once ABSPATH . 'wp-admin/includes/user.php';

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

$rw_base   = getenv( 'RW_HTTP_BASE' ) ? rtrim( (string) getenv( 'RW_HTTP_BASE' ), '/' ) : 'http://wordpress';
$rw_host   = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) . ( wp_parse_url( home_url( '/' ), PHP_URL_PORT ) ? ':' . wp_parse_url( home_url( '/' ), PHP_URL_PORT ) : '' );
$rw_suffix = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_posts  = array();
$rw_users  = array();
$rw_apps   = array();

$rw_orig_perma   = get_option( 'permalink_structure' );
$rw_orig_modules = get_option( Plugin::OPTION_MODULES, null );
$rw_orig_access  = get_option( Site_Access_Settings::OPTION, null );

$rw_http = function ( $method, $path, array $opts = array() ) use ( $rw_base, $rw_host ) {
	$args = array(
		'method'      => $method,
		'redirection' => 0,
		'timeout'     => 20,
		'headers'     => array_merge( array( 'Host' => $rw_host ), $opts['headers'] ?? array() ),
		'cookies'     => $opts['cookies'] ?? array(),
	);
	if ( isset( $opts['body'] ) ) {
		$args['body'] = $opts['body'];
	}
	$r = wp_remote_request( $rw_base . $path, $args );
	if ( is_wp_error( $r ) ) {
		return array( 'code' => 0, 'body' => $r->get_error_message(), 'location' => '' );
	}
	return array(
		'code'     => (int) wp_remote_retrieve_response_code( $r ),
		'body'     => (string) wp_remote_retrieve_body( $r ),
		'location' => (string) wp_remote_retrieve_header( $r, 'location' ),
	);
};
$rw_set = function ( array $over ) {
	update_option( Site_Access_Settings::OPTION, array_merge( Site_Access_Settings::defaults(), $over ), false );
};

try {
	global $wp_rewrite;
	$wp_rewrite->set_permalink_structure( '/%postname%/' );
	flush_rewrite_rules( false );
	$mods                  = is_array( $rw_orig_modules ) ? $rw_orig_modules : array();
	$mods['site-access']   = true;
	update_option( Plugin::OPTION_MODULES, $mods );

	$open_mark   = 'RWOPENMARK' . $rw_suffix;
	$secret_mark = 'RWSECRETMARK' . $rw_suffix;
	$open_slug   = 'rw-open-' . $rw_suffix;
	$open        = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Open ' . $rw_suffix, 'post_name' => $open_slug, 'post_content' => $open_mark ) );
	$secret_page = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Hidden page ' . $rw_suffix, 'post_name' => 'rw-hidden-' . $rw_suffix, 'post_content' => $secret_mark ) );
	$secret_post = wp_insert_post( array( 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => 'Hidden post ' . $rw_suffix, 'post_name' => 'rw-hidden-post-' . $rw_suffix, 'post_content' => $secret_mark ) );
	$rw_posts    = array( $open, $secret_page, $secret_post );

	$probe = $rw_http( 'GET', '/' );
	$rw_ok( $probe['code'] >= 200 && $probe['code'] < 400, 'setup: web container reachable at ' . $rw_base . ' (HTTP ' . $probe['code'] . ')' );
	$rw_set( array() );
	$plain = $rw_http( 'GET', '/' . $open_slug . '/' );
	$rw_ok( 200 === $plain['code'] && false !== strpos( $plain['body'], $open_mark ), 'control: private mode off, allow-listed page loads' );
	$leak = $rw_http( 'POST', '/' . $open_slug . '/', array( 'body' => array( 'page_id' => $secret_page ) ) );
	$rw_ok( false !== strpos( $leak['body'], $secret_mark ), 'control: with private mode off WordPress does serve the POSTed page_id on that path' );

	$rw_set(
		array(
			'private_enabled' => true,
			'private_feed'    => true,
			'private_rest'    => true,
			'allow_paths'     => array( '/' . $open_slug ),
		)
	);
	$is_login = function ( $r ) {
		return 302 === $r['code'] && false !== strpos( $r['location'], 'wp-login.php' );
	};

	// Allow-list.
	$r = $rw_http( 'GET', '/' . $open_slug . '/' );
	$rw_ok( 200 === $r['code'] && false !== strpos( $r['body'], $open_mark ), 'allow-list: the allow-listed page loads anonymously' );
	$r = $rw_http( 'GET', '/' . $open_slug . '/?utm_source=x' );
	$rw_ok( 200 === $r['code'] && false !== strpos( $r['body'], $open_mark ), 'allow-list: tracking parameters still load it' );
	$r = $rw_http( 'POST', '/' . $open_slug . '/', array( 'body' => array( 'message' => 'hi' ) ) );
	$rw_ok( 200 === $r['code'] && false !== strpos( $r['body'], $open_mark ), 'allow-list: a POST without query vars still loads it' );
	$r = $rw_http( 'GET', '/rw-hidden-' . $rw_suffix . '/' );
	$rw_ok( $is_login( $r ) && false === strpos( $r['body'], $secret_mark ), 'allow-list: a page outside the list goes to login' );
	foreach (
		array(
			'GET page_id'  => array( 'GET', '/' . $open_slug . '/?page_id=' . $secret_page, array() ),
			'GET p'        => array( 'GET', '/' . $open_slug . '/?p=' . $secret_post, array() ),
			'POST page_id' => array( 'POST', '/' . $open_slug . '/', array( 'body' => array( 'page_id' => $secret_page ) ) ),
			'POST p'       => array( 'POST', '/' . $open_slug . '/', array( 'body' => array( 'p' => $secret_post ) ) ),
			'POST name'    => array( 'POST', '/' . $open_slug . '/', array( 'body' => array( 'name' => 'rw-hidden-post-' . $rw_suffix ) ) ),
			'POST s'       => array( 'POST', '/' . $open_slug . '/', array( 'body' => array( 's' => $secret_mark ) ) ),
		) as $label => $c
	) {
		$r = $rw_http( $c[0], $c[1], $c[2] );
		$rw_ok( $is_login( $r ) && false === strpos( $r['body'], $secret_mark ), 'allow-list: ' . $label . ' on the allow-listed path goes to login and leaks nothing (HTTP ' . $r['code'] . ')' );
	}

	// Feeds.
	$r = $rw_http( 'GET', '/feed/' );
	$rw_ok( 403 === $r['code'] && false === strpos( $r['body'], $secret_mark ), 'feed: anonymous gets 403 when feeds are private' );

	// Users and credentials.
	$uid        = wp_insert_user( array( 'user_login' => 'rw_http_' . $rw_suffix, 'user_email' => 'rw_http_' . $rw_suffix . '@example.com', 'user_pass' => wp_generate_password( 24 ), 'role' => 'editor' ) );
	$rw_users[] = $uid;
	$exp        = time() + HOUR_IN_SECONDS;
	$token      = WP_Session_Tokens::get_instance( $uid )->create( $exp );
	$cookie     = wp_generate_auth_cookie( $uid, $exp, 'logged_in', $token );
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookie;
	wp_set_current_user( $uid );
	$nonce = wp_create_nonce( 'wp_rest' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( 0 );
	$jar = array( LOGGED_IN_COOKIE => $cookie );

	$r = $rw_http( 'GET', '/feed/', array( 'cookies' => $jar ) );
	$rw_ok( 200 === $r['code'], 'feed: logged-in cookie reads the feed (HTTP ' . $r['code'] . ')' );

	// REST.
	$route = '/wp-json/wp/v2/posts';
	$r     = $rw_http( 'GET', $route );
	$rw_ok( 401 === $r['code'] && false === strpos( $r['body'], $secret_mark ), 'REST: anonymous gets 401' );
	$r = $rw_http( 'GET', '/?rest_route=/wp/v2/posts' );
	$rw_ok( 401 === $r['code'], 'REST: anonymous via ?rest_route gets 401' );
	$r = $rw_http( 'GET', $route, array( 'cookies' => $jar ) );
	$rw_ok( 401 === $r['code'] && false === strpos( $r['body'], $secret_mark ), 'REST: valid auth cookie without a nonce gets 401 (HTTP ' . $r['code'] . ')' );
	$r = $rw_http( 'GET', $route, array( 'cookies' => $jar, 'headers' => array( 'X-WP-Nonce' => 'deadbeef00' ) ) );
	$rw_ok( in_array( $r['code'], array( 401, 403 ), true ) && false === strpos( $r['body'], $secret_mark ), 'REST: valid auth cookie with a bad nonce is refused (HTTP ' . $r['code'] . ')' );
	$r = $rw_http( 'GET', $route, array( 'cookies' => $jar, 'headers' => array( 'X-WP-Nonce' => $nonce ) ) );
	$rw_ok( 200 === $r['code'] && false !== strpos( $r['body'], $secret_mark ), 'REST: valid auth cookie with its nonce gets 200' );
	$r = $rw_http( 'GET', '/wp-json/wp/v2/users/me', array( 'cookies' => $jar, 'headers' => array( 'X-WP-Nonce' => $nonce ) ) );
	$me = json_decode( $r['body'], true );
	$rw_ok( 200 === $r['code'] && (int) ( $me['id'] ?? 0 ) === $uid, 'REST: cookie plus nonce is the right user' );

	if ( wp_is_application_passwords_available_for_user( get_userdata( $uid ) ) ) {
		$created = WP_Application_Passwords::create_new_application_password( $uid, array( 'name' => 'rw-http-' . $rw_suffix ) );
		$rw_ok( ! is_wp_error( $created ), 'setup: application password created' );
		if ( ! is_wp_error( $created ) ) {
			$rw_apps[] = array( $uid, $created[1]['uuid'] );
			$basic     = array( 'Authorization' => 'Basic ' . base64_encode( 'rw_http_' . $rw_suffix . ':' . $created[0] ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			$r         = $rw_http( 'GET', '/wp-json/wp/v2/users/me', array( 'headers' => $basic ) );
			$me        = json_decode( $r['body'], true );
			$rw_ok( 200 === $r['code'] && (int) ( $me['id'] ?? 0 ) === $uid, 'REST: application password passes (HTTP ' . $r['code'] . ')' );
			$bad = array( 'Authorization' => 'Basic ' . base64_encode( 'rw_http_' . $rw_suffix . ':wrong wrong wrong' ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			$r   = $rw_http( 'GET', $route, array( 'headers' => $bad ) );
			$rw_ok( 200 !== $r['code'] && false === strpos( $r['body'], $secret_mark ), 'REST: a wrong application password is refused (HTTP ' . $r['code'] . ')' );
		}
	} else {
		$rw_ok( false, 'setup: application passwords are not available in this environment' );
	}

	// Toggles.
	$rw_set( array( 'private_enabled' => true, 'private_feed' => false, 'private_rest' => false, 'allow_paths' => array( '/' . $open_slug ) ) );
	$r = $rw_http( 'GET', $route );
	$rw_ok( 200 === $r['code'], 'toggle: REST open to anonymous when the REST option is off' );
	$r = $rw_http( 'GET', '/feed/' );
	$rw_ok( 200 === $r['code'], 'toggle: feed open to anonymous when the feed option is off' );
	$r = $rw_http( 'GET', '/rw-hidden-' . $rw_suffix . '/' );
	$rw_ok( $is_login( $r ), 'toggle: pages stay private with both options off' );
	$rw_set( array( 'private_enabled' => false ) );
	$r = $rw_http( 'GET', $route );
	$rw_ok( 200 === $r['code'], 'toggle: REST open with private mode off' );

	// rest_pre_dispatch re-check, in-process. REST_REQUEST is defined last because it can't be undone.
	$rw_set( array( 'private_enabled' => true, 'private_rest' => true ) );
	$gate = new Gate();
	$req  = new WP_REST_Request( 'GET', '/wp/v2/posts' );
	wp_set_current_user( 0 );
	$rw_ok( null === $gate->on_rest_pre_dispatch( null, rest_get_server(), $req ), 'pre_dispatch: internal REST calls outside a REST request are left alone' );
	if ( ! defined( 'REST_REQUEST' ) ) {
		define( 'REST_REQUEST', true );
	}
	$res = $gate->on_rest_pre_dispatch( null, rest_get_server(), $req );
	$rw_ok( is_wp_error( $res ) && 401 === $res->get_error_data()['status'], 'pre_dispatch: anonymous dispatch is refused after authentication finished' );
	$res = $gate->on_rest_pre_dispatch( null, rest_get_server(), new WP_REST_Request( 'GET', '/wp/v2/pages' ) );
	$rw_ok( is_wp_error( $res ), 'pre_dispatch: embedded or batched sub-requests are refused too' );
	wp_set_current_user( $uid );
	$rw_ok( null === $gate->on_rest_pre_dispatch( null, rest_get_server(), $req ), 'pre_dispatch: logged-in user passes' );
	wp_set_current_user( 0 );
	$rw_ok( 'x' === $gate->on_rest_pre_dispatch( 'x', rest_get_server(), $req ), 'pre_dispatch: an earlier short-circuit result is kept' );
	$rw_set( array( 'private_enabled' => true, 'private_rest' => false ) );
	$rw_ok( null === $gate->on_rest_pre_dispatch( null, rest_get_server(), $req ), 'pre_dispatch: REST option off leaves it alone' );
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
} finally {
	wp_set_current_user( 0 );
	foreach ( $rw_apps as $a ) {
		WP_Application_Passwords::delete_application_password( $a[0], $a[1] );
	}
	foreach ( $rw_users as $u ) {
		WP_Session_Tokens::get_instance( $u )->destroy_all();
		wp_delete_user( $u );
	}
	foreach ( $rw_posts as $p ) {
		wp_delete_post( $p, true );
	}
	if ( null === $rw_orig_access ) {
		delete_option( Site_Access_Settings::OPTION );
	} else {
		update_option( Site_Access_Settings::OPTION, $rw_orig_access, false );
	}
	if ( null === $rw_orig_modules ) {
		delete_option( Plugin::OPTION_MODULES );
	} else {
		update_option( Plugin::OPTION_MODULES, $rw_orig_modules );
	}
	$wp_rewrite->set_permalink_structure( (string) $rw_orig_perma );
	flush_rewrite_rules( false );
}

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
if ( $rw_fail > 0 ) {
	exit( 1 );
}
