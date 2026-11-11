<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/disable-users-smoke.php
 * Known-bad control: RW_REMOVE_LOGIN_HOOK=1 removes the authenticate hook first, so the login assertions must fail.
 * Base URL for the REST and XML-RPC checks: RW_HTTP_BASE (default http://wordpress, the wp-env web container), Host header from home_url().
 */

use Rolegate\Core\Plugin;
use Rolegate\Modules\Audit\Reverter;
use Rolegate\Modules\Audit\Store;
use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Disabled_Users\Profile_Field;
use Rolegate\Modules\Disabled_Users\Users_List;
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
	add_filter( 'rolegate_multisite_site_admin_access', '__return_true', 20 );
}
add_filter( 'wp_is_application_passwords_available', '__return_true' );
add_filter( 'application_password_is_api_request', '__return_true' );

$rw_sfx    = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_pw     = 'Rw-' . $rw_sfx . '-pass!9';
$rw_users  = array();
$rw_events = array();
$rw_role   = 'rw_dis_mgr_' . $rw_sfx;
$rw_make   = function ( $login, $role ) use ( &$rw_users, $rw_sfx, $rw_pw ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $rw_sfx,
			'user_email' => $login . '_' . $rw_sfx . '@example.com',
			'user_pass'  => $rw_pw,
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
$rw_login_of = function ( $id ) {
	clean_user_cache( $id );
	return get_userdata( $id )->user_login;
};
$rw_post = function ( array $extra ) {
	$_POST    = $extra;
	$_REQUEST = $extra;
};
add_action(
	'rolegate_changed',
	function ( $type, $data ) use ( &$rw_events ) {
		$rw_events[] = array( $type, $data );
	},
	10,
	2
);
$rw_last_event = function ( $type ) use ( &$rw_events ) {
	for ( $i = count( $rw_events ) - 1; $i >= 0; $i-- ) {
		if ( $rw_events[ $i ][0] === $type ) {
			return $rw_events[ $i ][1];
		}
	}
	return null;
};
$rw_die = function () {
	return function ( $message ) {
		throw new \RuntimeException( is_wp_error( $message ) ? $message->get_error_message() : wp_strip_all_tags( (string) $message ) );
	};
};
$rw_base = getenv( 'RW_HTTP_BASE' ) ? rtrim( (string) getenv( 'RW_HTTP_BASE' ), '/' ) : 'http://wordpress';
$rw_host = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) . ( wp_parse_url( home_url( '/' ), PHP_URL_PORT ) ? ':' . wp_parse_url( home_url( '/' ), PHP_URL_PORT ) : '' );
$rw_http = function ( $method, $path, array $headers = array(), $body = null ) use ( $rw_base, $rw_host ) {
	$args = array(
		'method'      => $method,
		'redirection' => 0,
		'timeout'     => 20,
		'headers'     => array_merge( array( 'Host' => $rw_host ), $headers ),
	);
	if ( null !== $body ) {
		$args['body'] = $body;
	}
	$r = wp_remote_request( $rw_base . $path, $args );
	if ( is_wp_error( $r ) ) {
		return array( 'code' => 0, 'body' => $r->get_error_message() );
	}
	return array(
		'code' => (int) wp_remote_retrieve_response_code( $r ),
		'body' => (string) wp_remote_retrieve_body( $r ),
	);
};
$rw_audit_rows = function ( $type, $target = null ) {
	if ( ! Plugin::is_enabled( 'audit' ) || ! Store::table_exists() ) {
		return array();
	}
	$out = array();
	foreach ( Store::query( array( 'type' => $type ), 1, 50 )['rows'] as $row ) {
		if ( null === $target || (string) $row->target === (string) $target ) {
			$out[] = $row;
		}
	}
	return $out;
};

$rw_orig_modules = get_option( Plugin::OPTION_MODULES, null );
$rw_orig_records = get_option( Migrator::RECORDS, null );
$rw_pre_mgr      = Accounts::active_managers();
$rw_roles        = array( $rw_role );
global $pagenow;
$rw_orig_pagenow = $pagenow;

try {
	foreach ( $rw_pre_mgr as $rw_id ) {
		Accounts::write( $rw_id, true );
	}
	add_role( $rw_role, 'RW disable manager', array( 'read' => true, 'edit_users' => true, 'list_users' => true, Caps::MANAGE_USERS => true ) );
	Caps::grant_to_administrator();

	$rw_mod = Plugin::modules()['disabled-users'] ?? null;
	$rw_ok( $rw_mod && 'disabled-users' === $rw_mod->id() && $rw_mod->default_enabled() && Plugin::is_enabled( 'disabled-users' ), 'module discovered and on by default' );

	if ( getenv( 'RW_REMOVE_LOGIN_HOOK' ) ) {
		global $wp_filter;
		foreach ( (array) $wp_filter['authenticate']->callbacks[ PHP_INT_MAX ] as $rw_cb ) {
			remove_filter( 'authenticate', $rw_cb['function'], PHP_INT_MAX );
		}
		echo "CONTROL authenticate hook removed for this run\n";
	}

	$rw_a      = $rw_make( 'rw_dis_a', 'administrator' );
	$rw_b      = $rw_make( 'rw_dis_b', 'administrator' );
	$rw_victim = $rw_make( 'rw_dis_victim', 'author' );
	$rw_v2     = $rw_make( 'rw_dis_v2', 'subscriber' );
	$rw_v3     = $rw_make( 'rw_dis_v3', 'subscriber' );
	$rw_mgr    = $rw_make( 'rw_dis_mgr', $rw_role );
	$rw_plain  = $rw_make( 'rw_dis_plain', 'author' );
	if ( is_multisite() ) {
		grant_super_admin( $rw_a );
		grant_super_admin( $rw_b );
	}
	$rw_ok( array( $rw_a, $rw_b ) === Accounts::active_managers(), 'setup: the two test administrators are the only active managers (' . implode( ',', Accounts::active_managers() ) . ')' );

	$rw_login = function ( $id ) use ( $rw_login_of, $rw_pw ) {
		return wp_authenticate( $rw_login_of( $id ), $rw_pw );
	};

	// Login, session, cookie, application password, REST, XML-RPC.
	$rw_ok( $rw_login( $rw_victim ) instanceof WP_User, 'control: an enabled user logs in' );
	$rw_tokens = WP_Session_Tokens::get_instance( $rw_victim );
	$rw_token  = $rw_tokens->create( time() + HOUR_IN_SECONDS );
	$rw_ok( $rw_tokens->verify( $rw_token ), 'control: a session exists before disabling' );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $rw_victim, time() + HOUR_IN_SECONDS, 'logged_in', $rw_token );
	$rw_ok( (int) $rw_victim === (int) apply_filters( 'determine_current_user', false ), 'control: a valid cookie identifies an enabled user' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	list( $rw_app_pw ) = WP_Application_Passwords::create_new_application_password( $rw_victim, array( 'name' => 'rw-' . $rw_sfx ) );
	$rw_app_login      = $rw_login_of( $rw_victim );
	$rw_ok( wp_authenticate_application_password( null, $rw_app_login, $rw_app_pw ) instanceof WP_User, 'control: an application password authenticates an enabled user' );
	$rw_auth_header = array( 'Authorization' => 'Basic ' . base64_encode( $rw_app_login . ':' . $rw_app_pw ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	$rw_rest        = function () use ( $rw_http, $rw_auth_header ) {
		return $rw_http( 'GET', '/index.php?rest_route=/wp/v2/users/me', $rw_auth_header );
	};
	$rw_xmlrpc = function () use ( $rw_http, $rw_app_login, $rw_app_pw ) {
		$xml = '<?xml version="1.0"?><methodCall><methodName>wp.getProfile</methodName><params><param><value><int>1</int></value></param><param><value><string>' . $rw_app_login . '</string></value></param><param><value><string>' . $rw_app_pw . '</string></value></param></params></methodCall>';
		return $rw_http( 'POST', '/xmlrpc.php', array( 'Content-Type' => 'text/xml' ), $xml );
	};
	$rw_r = $rw_rest();
	$rw_ok( 200 === $rw_r['code'] && (int) $rw_victim === (int) ( json_decode( $rw_r['body'], true )['id'] ?? 0 ), 'control: REST users/me with the application password returns the user (HTTP ' . $rw_r['code'] . ')' );
	$rw_x = $rw_xmlrpc();
	$rw_ok( 200 === $rw_x['code'] && false !== strpos( $rw_x['body'], 'user_id' ), 'control: XML-RPC with the application password works (HTTP ' . $rw_x['code'] . ')' );

	$rw_res = Accounts::change( $rw_a, $rw_victim, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_victim ) && '1' === get_user_meta( $rw_victim, 'rolegate_disabled', true ), 'admin disables a user; meta rolegate_disabled is 1' );
	$rw_lr = $rw_login( $rw_victim );
	$rw_ok( is_wp_error( $rw_lr ) && 'rolegate_disabled' === $rw_lr->get_error_code() && 'This account has been disabled.' === $rw_lr->get_error_message(), 'login with the right password is refused with a plain message' );
	$rw_bad = wp_authenticate( $rw_login_of( $rw_victim ), 'wrong-' . $rw_pw );
	$rw_ok( is_wp_error( $rw_bad ) && 'rolegate_disabled' !== $rw_bad->get_error_code(), 'a wrong password on a disabled account gets the ordinary error (no status leak)' );
	$rw_ok( false === WP_Session_Tokens::get_instance( $rw_victim )->verify( $rw_token ), 'existing session destroyed when disabled' );
	$rw_tokens2                   = WP_Session_Tokens::get_instance( $rw_victim )->create( time() + HOUR_IN_SECONDS );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $rw_victim, time() + HOUR_IN_SECONDS, 'logged_in', $rw_tokens2 );
	$rw_ok( (int) $rw_victim === (int) wp_validate_auth_cookie( $_COOKIE[ LOGGED_IN_COOKIE ], 'logged_in' ), 'control: a session minted after disabling still validates as a cookie' );
	$rw_ok( false === apply_filters( 'determine_current_user', false ), 'a valid cookie no longer identifies the disabled user' );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	WP_Session_Tokens::get_instance( $rw_victim )->destroy_all();
	$rw_ae = wp_authenticate_application_password( null, $rw_app_login, $rw_app_pw );
	$rw_ok( is_wp_error( $rw_ae ), 'application password refused for a disabled user' . ( is_wp_error( $rw_ae ) ? ' (' . $rw_ae->get_error_code() . ')' : '' ) );
	$rw_r = $rw_rest();
	$rw_ok( 401 === $rw_r['code'], 'REST request with the application password gets 401 (HTTP ' . $rw_r['code'] . ')' );
	$rw_x = $rw_xmlrpc();
	$rw_ok( 200 === $rw_x['code'] && false !== strpos( $rw_x['body'], '<fault>' ) && false === strpos( $rw_x['body'], 'user_id' ), 'XML-RPC login refused with a fault' );
	$rw_ev = $rw_last_event( 'user.disabled' );
	$rw_ok( $rw_ev && $rw_a === $rw_ev['actor'] && $rw_victim === $rw_ev['target'] && false === $rw_ev['before']['disabled'] && true === $rw_ev['after']['disabled'], 'user.disabled event carries actor, target, before and after' );
	$rw_n = count( $rw_events );
	$rw_noop = Accounts::change( $rw_a, $rw_victim, true );
	$rw_ok( is_wp_error( $rw_noop ) && 'rolegate_disabled_noop' === $rw_noop->get_error_code() && count( $rw_events ) === $rw_n, 'disabling an already disabled account changes nothing and logs nothing' );

	$rw_res = Accounts::change( $rw_a, $rw_victim, false );
	$rw_ok( true === $rw_res && ! Accounts::is_disabled( $rw_victim ) && ! metadata_exists( 'user', $rw_victim, 'rolegate_disabled' ), 'enabling removes the flag' );
	$rw_ok( $rw_login( $rw_victim ) instanceof WP_User, 'login works again after enabling' );
	$rw_r = $rw_rest();
	$rw_ok( 200 === $rw_r['code'], 'REST works again after enabling (HTTP ' . $rw_r['code'] . ')' );

	// Control: the login assertion depends on the authenticate hook.
	Accounts::change( $rw_a, $rw_v2, true );
	global $wp_filter;
	$rw_saved_cb = isset( $wp_filter['authenticate']->callbacks[ PHP_INT_MAX ] ) ? $wp_filter['authenticate']->callbacks[ PHP_INT_MAX ] : array();
	foreach ( $rw_saved_cb as $rw_cb ) {
		remove_filter( 'authenticate', $rw_cb['function'], PHP_INT_MAX );
	}
	$rw_unguarded = wp_authenticate( $rw_login_of( $rw_v2 ), $rw_pw );
	foreach ( $rw_saved_cb as $rw_cb ) {
		add_filter( 'authenticate', $rw_cb['function'], PHP_INT_MAX, 1 );
	}
	$rw_guarded = wp_authenticate( $rw_login_of( $rw_v2 ), $rw_pw );
	$rw_ok( $rw_saved_cb && $rw_unguarded instanceof WP_User && is_wp_error( $rw_guarded ) && 'rolegate_disabled' === $rw_guarded->get_error_code(), 'known-bad control: with the authenticate hook removed a disabled user logs in; with it restored the login is refused' );
	Accounts::change( $rw_a, $rw_v2, false );

	// Self, last manager, authority.
	$rw_res = Accounts::change( $rw_a, $rw_a, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_self_disable' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_a ), 'an administrator cannot disable their own account' );
	$rw_res = Accounts::change( $rw_plain, $rw_v2, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_cannot_manage_users' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_v2 ), 'a user without the manage-users capability cannot disable accounts' );
	$rw_res = Accounts::change( $rw_mgr, $rw_a, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_user_above_actor' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_a ), 'a user manager cannot disable an administrator above them' );
	$rw_res = Accounts::change( $rw_mgr, $rw_v2, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_v2 ), 'control: the same user manager can disable an ordinary user' );
	Accounts::change( $rw_mgr, $rw_v2, false );
	$rw_ok( true === Accounts::check( $rw_a, $rw_b, true ), 'control: with two active managers either may be disabled' );
	$rw_res = Accounts::change( $rw_a, $rw_b, true );
	$rw_ok( true === $rw_res && Accounts::is_disabled( $rw_b ) && array( $rw_a ) === Accounts::active_managers(), 'one manager disabled, the other is now the only active manager' );
	$rw_res = Accounts::change( $rw_b, $rw_a, true );
	$rw_ok( is_wp_error( $rw_res ) && 'rolegate_last_manager' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_a ), 'the last active manager cannot be disabled by anyone' );
	$rw_ok( ! Accounts::is_last_manager( $rw_v2 ), 'a non-manager is never the last manager' );

	// Fixture shortcut: the guard resets a disabled current user, so a disabled administrator can only "act" with that reset switched off.
	$rw_acting_disabled = function ( callable $fn ) {
		global $wp_filter;
		$saved = $wp_filter['set_current_user']->callbacks[ PHP_INT_MAX ] ?? array();
		unset( $wp_filter['set_current_user']->callbacks[ PHP_INT_MAX ] );
		try {
			return $fn();
		} finally {
			if ( $saved ) {
				$wp_filter['set_current_user']->callbacks[ PHP_INT_MAX ] = $saved;
			}
		}
	};
	$rw_render = function ( $target, $actor ) {
		wp_set_current_user( $actor );
		ob_start();
		( new Profile_Field() )->render( get_userdata( $target ) );
		return (string) ob_get_clean();
	};
	$rw_html = $rw_acting_disabled( function () use ( $rw_render, $rw_a, $rw_b ) { return $rw_render( $rw_a, $rw_b ); } );
	$rw_ok( false !== strpos( $rw_html, 'rolegate_disabled_user' ) && preg_match( '/name="rolegate_disabled_user"[^>]*disabled/', $rw_html ), 'profile: the last manager\'s checkbox is shown locked' );
	$rw_html = $rw_render( $rw_v2, $rw_a );
	$rw_ok( false !== strpos( $rw_html, 'name="rolegate_disabled_user"' ) && ! preg_match( '/name="rolegate_disabled_user"[^>]*disabled/', $rw_html ) && false !== strpos( $rw_html, 'rolegate_disabled_nonce' ), 'profile: an ordinary user shows an enabled checkbox and a nonce' );
	$rw_ok( '' === $rw_render( $rw_a, $rw_a ), 'profile: nothing is rendered on your own account' );
	$rw_ok( '' === $rw_render( $rw_v2, $rw_plain ), 'profile: nothing is rendered for a user who cannot manage users' );
	Accounts::change( $rw_a, $rw_b, false );

	// Profile form save.
	( new Profile_Field() )->register();
	$rw_edit = function ( $id, $actor, array $fields, $nonce = true ) use ( $rw_post, $rw_die ) {
		wp_set_current_user( $actor );
		$u = get_userdata( $id );
		$rw_post(
			array_merge(
				array(
					'email'    => $u->user_email,
					'nickname' => $u->user_login,
				),
				$nonce ? array( 'rolegate_disabled_nonce' => wp_create_nonce( 'rolegate_disabled_' . $id ) ) : array(),
				$fields
			)
		);
		add_filter( 'wp_die_handler', $rw_die );
		try {
			do_action( $id === $actor ? 'personal_options_update' : 'edit_user_profile_update', $id );
			$out = edit_user( $id );
		} catch ( \RuntimeException $e ) {
			$out = new \WP_Error( 'died', $e->getMessage() );
		}
		remove_filter( 'wp_die_handler', $rw_die );
		return $out;
	};
	$rw_out = $rw_edit( $rw_v2, $rw_a, array( 'rolegate_disabled_present' => '1', 'rolegate_disabled_user' => '1' ) );
	$rw_ok( ! is_wp_error( $rw_out ) && Accounts::is_disabled( $rw_v2 ), 'profile save: ticking the box disables the account' );
	$rw_ev = $rw_last_event( 'user.disabled' );
	$rw_ok( $rw_ev && $rw_v2 === $rw_ev['target'] && true === $rw_ev['after']['disabled'], 'profile save: the change is logged' );
	$rw_out = $rw_edit( $rw_v2, $rw_a, array( 'rolegate_disabled_present' => '1', 'display_name' => 'RW changed' ) );
	$rw_ok( ! is_wp_error( $rw_out ) && ! Accounts::is_disabled( $rw_v2 ), 'profile save: clearing the box enables the account' );
	$rw_out = $rw_edit( $rw_v2, $rw_a, array( 'rolegate_disabled_present' => '1', 'rolegate_disabled_user' => '1' ), false );
	$rw_ok( is_wp_error( $rw_out ) && ! Accounts::is_disabled( $rw_v2 ), 'profile save: a missing nonce is refused and nothing changes' );
	$rw_out = $rw_edit( $rw_v2, $rw_a, array( 'display_name' => 'RW again' ) );
	$rw_ok( ! is_wp_error( $rw_out ) && ! Accounts::is_disabled( $rw_v2 ), 'profile save: a form without the section leaves the status alone' );
	Accounts::change( $rw_a, $rw_v2, true );
	$rw_out = $rw_edit( $rw_v2, $rw_a, array( 'display_name' => 'RW third' ) );
	$rw_ok( ! is_wp_error( $rw_out ) && Accounts::is_disabled( $rw_v2 ), 'profile save: a form without the section does not enable a disabled account' );
	Accounts::change( $rw_a, $rw_v2, false );
	$rw_out = $rw_edit( $rw_plain, $rw_plain, array( 'rolegate_disabled_present' => '1', 'rolegate_disabled_user' => '1' ) );
	$rw_ok( ! Accounts::is_disabled( $rw_plain ), 'profile save: a user cannot disable themselves through the form' );
	$rw_out = $rw_edit( $rw_victim, $rw_plain, array( 'rolegate_disabled_present' => '1', 'rolegate_disabled_user' => '1' ) );
	$rw_ok( ! Accounts::is_disabled( $rw_victim ), 'profile save: a user without authority cannot disable another account' );
	$rw_post( array() );

	// Users list.
	$rw_list = new Users_List();
	$rw_list->register();
	wp_set_current_user( $rw_a );
	Accounts::change( $rw_a, $rw_v3, true );
	$rw_cols = $rw_list->columns( array( 'cb' => '', 'username' => 'Username' ) );
	$rw_ok( isset( $rw_cols['rolegate_disabled'] ) && 'cb' === array_key_first( $rw_cols ), 'list: an Account column is added' );
	$rw_ok( false !== strpos( $rw_list->column( '', 'rolegate_disabled', $rw_v3 ), 'Disabled' ) && '' === $rw_list->column( '', 'rolegate_disabled', $rw_victim ) && 'keep' === $rw_list->column( 'keep', 'other', $rw_v3 ), 'list: the column marks disabled users only' );
	$rw_views = $rw_list->views( array( 'all' => '<a href="x" class="current" aria-current="page">All</a>' ) );
	$rw_ok( isset( $rw_views['rolegate_disabled'] ) && false !== strpos( $rw_views['rolegate_disabled'], 'rolegate_disabled=1' ) && false !== strpos( $rw_views['rolegate_disabled'], '(' . count( get_users( array( 'fields' => 'ID', 'meta_key' => 'rolegate_disabled', 'meta_value' => '1' ) ) ) . ')' ), 'list: a Disabled view with its count' );
	$pagenow               = 'users.php';
	$_GET['rolegate_disabled'] = '1';
	$rw_q                  = new WP_User_Query( array( 'fields' => 'ID', 'include' => array( $rw_victim, $rw_v2, $rw_v3 ) ) );
	$rw_ok( array( (string) $rw_v3 ) === array_map( 'strval', $rw_q->get_results() ), 'list: the Disabled view lists only disabled users' );
	unset( $_GET['rolegate_disabled'] );
	$rw_q = new WP_User_Query( array( 'fields' => 'ID', 'include' => array( $rw_victim, $rw_v2, $rw_v3 ) ) );
	$rw_ok( 3 === count( $rw_q->get_results() ), 'list: without the filter every user is listed' );
	$pagenow = $rw_orig_pagenow;
	Accounts::change( $rw_a, $rw_v3, false );

	// Bulk actions.
	$rw_acts = $rw_list->bulk_actions( array() );
	$rw_ok( isset( $rw_acts['rolegate_disable'], $rw_acts['rolegate_enable'] ), 'bulk: Disable and Enable offered to a user manager' );
	wp_set_current_user( $rw_plain );
	$rw_ok( ! $rw_list->bulk_actions( array() ), 'bulk: nothing offered to a user without the capability' );
	$rw_bulk = function ( $who, $action, array $ids ) use ( $rw_list, $rw_post ) {
		wp_set_current_user( $who );
		$rw_post( array( '_wpnonce' => wp_create_nonce( 'bulk-users' ) ) );
		$out = $rw_list->handle_bulk( admin_url( 'users.php' ), $action, $ids );
		parse_str( (string) wp_parse_url( $out, PHP_URL_QUERY ), $q );
		return $q;
	};
	$rw_q = $rw_bulk( $rw_a, 'rolegate_disable', array( $rw_v2, $rw_v3, $rw_a ) );
	$rw_ok( 'disable' === ( $rw_q['rolegate_dis_mode'] ?? '' ) && '2' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '1' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && Accounts::is_disabled( $rw_v2 ) && Accounts::is_disabled( $rw_v3 ) && ! Accounts::is_disabled( $rw_a ), 'bulk disable: two disabled, own account skipped' );
	$rw_q = $rw_bulk( $rw_a, 'rolegate_enable', array( $rw_v2, $rw_v3, $rw_victim ) );
	$rw_ok( 'enable' === ( $rw_q['rolegate_dis_mode'] ?? '' ) && '2' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '1' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && ! Accounts::is_disabled( $rw_v2 ) && ! Accounts::is_disabled( $rw_v3 ), 'bulk enable: two enabled, an already enabled account skipped' );
	$rw_q = $rw_bulk( $rw_a, 'rolegate_disable', array( $rw_b, $rw_a ) );
	$rw_ok( '1' === ( $rw_q['rolegate_dis_done'] ?? '' ) && Accounts::is_disabled( $rw_b ), 'bulk disable: the second manager goes' );
	$rw_q = $rw_acting_disabled( function () use ( $rw_bulk, $rw_a, $rw_b ) { return $rw_bulk( $rw_b, 'rolegate_disable', array( $rw_a ) ); } );
	$rw_ok( '0' === ( $rw_q['rolegate_dis_done'] ?? '' ) && '1' === ( $rw_q['rolegate_dis_skip'] ?? '' ) && ! Accounts::is_disabled( $rw_a ), 'bulk disable: the last active manager is skipped' );
	Accounts::change( $rw_a, $rw_b, false );
	$rw_q = $rw_bulk( $rw_mgr, 'rolegate_disable', array( $rw_a, $rw_b ) );
	$rw_ok( '0' === ( $rw_q['rolegate_dis_done'] ?? '' ) && ! Accounts::is_disabled( $rw_a ) && ! Accounts::is_disabled( $rw_b ), 'bulk disable: a user manager cannot disable administrators' );
	$rw_ok( 'x' === $rw_list->handle_bulk( 'x', 'delete', array( 1 ) ), 'bulk handler ignores other actions' );
	add_filter( 'wp_die_handler', $rw_die );
	wp_set_current_user( $rw_plain );
	$rw_post( array( '_wpnonce' => wp_create_nonce( 'bulk-users' ) ) );
	$rw_threw = false;
	try {
		$rw_list->handle_bulk( admin_url( 'users.php' ), 'rolegate_disable', array( $rw_v2 ) );
	} catch ( \RuntimeException $e ) {
		$rw_threw = true;
	}
	$rw_ok( $rw_threw && ! Accounts::is_disabled( $rw_v2 ), 'bulk: a user without the capability is refused' );
	wp_set_current_user( $rw_a );
	$rw_post( array( '_wpnonce' => 'bad' ) );
	$rw_threw = false;
	try {
		$rw_list->handle_bulk( admin_url( 'users.php' ), 'rolegate_disable', array( $rw_v2 ) );
	} catch ( \Throwable $e ) {
		$rw_threw = true;
	}
	remove_filter( 'wp_die_handler', $rw_die );
	$rw_ok( $rw_threw && ! Accounts::is_disabled( $rw_v2 ), 'bulk: a bad nonce is refused' );
	$rw_post( array() );

	// Audit.
	if ( Plugin::is_enabled( 'audit' ) && Store::table_exists() ) {
		Accounts::change( $rw_a, $rw_v2, true );
		$rw_rows = $rw_audit_rows( 'user.disabled', $rw_v2 );
		$rw_row  = $rw_rows ? $rw_rows[0] : null;
		$rw_det  = $rw_row ? json_decode( (string) $rw_row->detail, true ) : array();
		$rw_ok( $rw_row && (int) $rw_row->actor_id === $rw_a && false === $rw_det['disabled_before'] && true === $rw_det['disabled_after'], 'audit: the disable is recorded with actor, target and before/after' );
		$rw_ok( $rw_row && Reverter::can_revert_row( $rw_row ), 'audit: the entry is revertible' );
		wp_set_current_user( $rw_plain );
		$rw_deny = $rw_row ? Reverter::revert( (int) $rw_row->id, $rw_plain ) : null;
		$rw_ok( is_wp_error( $rw_deny ) && Accounts::is_disabled( $rw_v2 ), 'audit: a user without the capabilities cannot revert it' );
		$rw_rev = $rw_row ? Reverter::revert( (int) $rw_row->id, $rw_a ) : new WP_Error( 'x', 'no row' );
		$rw_ok( true === $rw_rev && ! Accounts::is_disabled( $rw_v2 ), 'audit: revert enables the account again' . ( is_wp_error( $rw_rev ) ? ' (' . $rw_rev->get_error_message() . ')' : '' ) );
		$rw_after = $rw_audit_rows( 'user.disabled', $rw_v2 );
		$rw_ok( count( $rw_after ) >= 2 && (int) $rw_after[0]->reverted_of === (int) $rw_row->id && (int) Store::get( (int) $rw_row->id )->reverted_by === (int) $rw_after[0]->id, 'audit: the revert is logged and linked to the original' );
		$rw_ok( $rw_row && is_wp_error( Reverter::revert( (int) $rw_row->id, $rw_a ) ), 'audit: a second revert is refused' );
		$rw_enable_row = $rw_after[0];
		Accounts::change( $rw_a, $rw_v2, true );
		$rw_ok( true === Reverter::revert( (int) $rw_enable_row->id, $rw_a ) && Accounts::is_disabled( $rw_v2 ), 'audit: reverting an enable entry disables the account again' );
		Accounts::change( $rw_a, $rw_v2, false );
		Accounts::change( $rw_b, $rw_a, true );
		Accounts::change( $rw_b, $rw_a, false );
		$rw_e   = $rw_audit_rows( 'user.disabled', $rw_a )[0];
		$rw_res = Reverter::revert( (int) $rw_e->id, $rw_a );
		$rw_ok( is_wp_error( $rw_res ) && 'rolegate_self_disable' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_a ), 'audit: a revert cannot disable your own account' );
		Accounts::change( $rw_a, $rw_b, true );
		$rw_res = Reverter::revert( (int) $rw_e->id, $rw_b );
		$rw_ok( is_wp_error( $rw_res ) && 'rolegate_last_manager' === $rw_res->get_error_code() && ! Accounts::is_disabled( $rw_a ), 'audit: a revert cannot disable the last active manager' );
		Accounts::change( $rw_a, $rw_b, false );
	} else {
		echo "NOTE audit module off: audit assertions skipped\n";
	}

	// Migration from Disable Users.
	$rw_m = array();
	foreach ( array( 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7' ) as $rw_k ) {
		$rw_m[ $rw_k ] = $rw_make( 'rw_dis_' . $rw_k, 'subscriber' );
	}
	foreach ( array( 'm1', 'm2', 'm3', 'm4', 'm5', 'm7' ) as $rw_k ) {
		update_user_meta( $rw_m[ $rw_k ], 'ja_disable_user', '1' );
	}
	update_user_meta( $rw_m['m6'], 'ja_disable_user', '0' );
	update_user_meta( $rw_a, 'ja_disable_user', '1' );
	Accounts::write( $rw_m['m7'], true );
	$rw_flagged = array( $rw_m['m1'], $rw_m['m2'], $rw_m['m3'], $rw_m['m4'], $rw_m['m5'] );
	$rw_ja_all  = array_merge( $rw_flagged, array( $rw_m['m7'], $rw_a ) );
	$rw_snap    = function () use ( $rw_m, $rw_a, $rw_b ) {
		$out = array();
		foreach ( array_merge( array_values( $rw_m ), array( $rw_a, $rw_b ) ) as $id ) {
			clean_user_cache( $id );
			$out[ $id ] = array( get_user_meta( $id, 'rolegate_disabled', true ), get_user_meta( $id, 'ja_disable_user', true ) );
		}
		return $out;
	};
	$rw_find = function ( array $rows, $action, $needle ) {
		foreach ( $rows as $row ) {
			if ( $row['action'] === $action && ( false !== strpos( $row['item'], $needle ) || false !== strpos( $row['detail'], $needle ) ) ) {
				return true;
			}
		}
		return false;
	};

	$rw_ok( in_array( 'disable-users', array_keys( Migrator::sources() ), true ), 'migration: Disable Users is a registered source' );
	$rw_ja_sorted = $rw_ja_all;
	sort( $rw_ja_sorted );
	$rw_ok( $rw_ja_sorted === Disable_Users_Migration::flagged(), 'migration: the ' . count( $rw_ja_sorted ) . ' users with ja_disable_user = 1 are found, and no others' );
	$rw_ok( ! in_array( $rw_m['m6'], Disable_Users_Migration::flagged(), true ), 'migration: a user with ja_disable_user = 0 is not flagged' );
	$rw_before = $rw_snap();
	$rw_plan   = Migrator::plan( 'disable-users', $rw_a );
	$rw_ok( ! is_wp_error( $rw_plan ) && $rw_plan['detected'] && 'Disable Users' === $rw_plan['label'], 'migration plan: detected' );
	$rw_ok( $rw_before === $rw_snap(), 'migration plan: nothing written' );
	$rw_ok( $rw_flagged === $rw_plan['ops']['users'], 'migration plan: the five flagged, not yet disabled users are planned' );
	$rw_ok( $rw_find( $rw_plan['rows'], 'add', 'rw_dis_m1' ) && $rw_find( $rw_plan['rows'], 'unchanged', 'Already' ) && $rw_find( $rw_plan['rows'], 'blocked', 'your own account' ), 'migration plan: rows for the carry-over, the already disabled user and the actor' );
	$rw_ok( ! in_array( $rw_a, $rw_plan['ops']['users'], true ) && ! in_array( $rw_m['m7'], $rw_plan['ops']['users'], true ), 'migration plan: the actor and the already disabled user are left out' );

	$rw_t1 = WP_Session_Tokens::get_instance( $rw_m['m1'] );
	$rw_s1 = $rw_t1->create( time() + HOUR_IN_SECONDS );
	$rw_ap = Migrator::apply( 'disable-users', $rw_a );
	$rw_ok( ! is_wp_error( $rw_ap ) && 'applied' === $rw_ap['status'] && ! $rw_ap['errors'], 'migration apply: applied without errors' . ( ! is_wp_error( $rw_ap ) && $rw_ap['errors'] ? ' (' . implode( ' ', $rw_ap['errors'] ) . ')' : '' ) );
	$rw_all_on = true;
	foreach ( $rw_flagged as $rw_id ) {
		$rw_all_on = $rw_all_on && Accounts::is_disabled( $rw_id );
	}
	$rw_ok( $rw_all_on && ! Accounts::is_disabled( $rw_m['m6'] ) && ! Accounts::is_disabled( $rw_a ), 'migration apply: flagged users disabled; unflagged user and actor untouched' );
	$rw_ja_kept = true;
	foreach ( $rw_ja_all as $rw_id ) {
		$rw_ja_kept = $rw_ja_kept && '1' === get_user_meta( $rw_id, 'ja_disable_user', true );
	}
	$rw_ok( $rw_ja_kept && '0' === get_user_meta( $rw_m['m6'], 'ja_disable_user', true ), 'migration apply: ja_disable_user is left as it was on every user' );
	$rw_ok( false === WP_Session_Tokens::get_instance( $rw_m['m1'] )->verify( $rw_s1 ), 'migration apply: sessions of migrated users destroyed' );
	$rw_lm = wp_authenticate( $rw_login_of( $rw_m['m2'] ), $rw_pw );
	$rw_ok( is_wp_error( $rw_lm ) && 'rolegate_disabled' === $rw_lm->get_error_code(), 'migration apply: a migrated user can no longer log in' );
	$rw_rec = ! is_wp_error( $rw_ap ) ? Migrator::record( $rw_ap['migration_id'] ) : null;
	$rw_ok( $rw_rec && $rw_flagged === $rw_rec['users'], 'migration apply: migrated ids recorded' );
	$rw_ok( false !== strpos( Migrator::summary( (array) $rw_rec ), '5 disabled accounts' ), 'migration apply: summary names the count' );
	$rw_mid   = $rw_snap();
	$rw_again = Migrator::apply( 'disable-users', $rw_a );
	$rw_ok( ! is_wp_error( $rw_again ) && 'unchanged' === $rw_again['status'] && $rw_mid === $rw_snap(), 'migration: second apply changes nothing' );
	$rw_ok( ! Migrator::has_changes( Migrator::plan( 'disable-users', $rw_a )['ops'] ), 'migration: the next preview shows nothing left' );

	if ( Plugin::is_enabled( 'audit' ) && Store::table_exists() ) {
		$rw_mrow = null;
		foreach ( $rw_audit_rows( 'migration.applied' ) as $rw_r ) {
			$rw_d = json_decode( (string) $rw_r->detail, true );
			if ( isset( $rw_d['migration_id'] ) && $rw_d['migration_id'] === $rw_ap['migration_id'] ) {
				$rw_mrow = $rw_r;
			}
		}
		$rw_ok( $rw_mrow && Reverter::can_revert_row( $rw_mrow ), 'migration audit: migration.applied logged and revertible' );
		$rw_rv = $rw_mrow ? Reverter::revert( (int) $rw_mrow->id, $rw_a ) : new WP_Error( 'x', 'no row' );
		$rw_ok( true === $rw_rv, 'migration audit: revert succeeded' . ( is_wp_error( $rw_rv ) ? ' (' . $rw_rv->get_error_message() . ')' : '' ) );
		$rw_ok( $rw_mrow && is_wp_error( Reverter::revert( (int) $rw_mrow->id, $rw_a ) ), 'migration audit: a second revert is refused' );
	} else {
		$rw_rv = Migrator::revert( $rw_ap['migration_id'], $rw_a );
		$rw_ok( true === $rw_rv, 'migration revert: succeeded' );
	}
	$rw_all_off = true;
	foreach ( $rw_flagged as $rw_id ) {
		$rw_all_off = $rw_all_off && ! Accounts::is_disabled( $rw_id );
	}
	$rw_ok( $rw_all_off && Accounts::is_disabled( $rw_m['m7'] ), 'migration revert: migrated users enabled again; the user disabled before stays disabled' );
	$rw_ja_kept = true;
	foreach ( $rw_ja_all as $rw_id ) {
		$rw_ja_kept = $rw_ja_kept && '1' === get_user_meta( $rw_id, 'ja_disable_user', true );
	}
	$rw_ok( $rw_ja_kept, 'migration revert: ja_disable_user still untouched' );
	$rw_ok( ! Plugin::is_enabled( 'audit' ) || ! Store::table_exists() || ( $rw_audit_rows( 'user.disabled', $rw_m['m2'] ) && false === json_decode( (string) $rw_audit_rows( 'user.disabled', $rw_m['m2'] )[0]->detail, true )['disabled_after'] ), 'migration revert: each re-enabled account gets its own audit entry' );
	$rw_ok( $rw_login( $rw_m['m2'] ) instanceof WP_User, 'migration revert: a reverted user logs in again' );

	// Module off: the migration switches it on, revert puts it back.
	$rw_map                   = Plugin::enabled_map();
	$rw_map['disabled-users'] = false;
	update_option( Plugin::OPTION_MODULES, $rw_map );
	$rw_mp = Migrator::plan( 'disable-users', $rw_a );
	$rw_ok( array( 'disabled-users' ) === $rw_mp['ops']['modules'] && $rw_find( $rw_mp['rows'], 'add', 'Switch on' ), 'migration plan: switches the module on when it is off' );
	$rw_ap2 = Migrator::apply( 'disable-users', $rw_a );
	$rw_ok( ! is_wp_error( $rw_ap2 ) && 'applied' === $rw_ap2['status'] && Plugin::is_enabled( 'disabled-users' ) && Accounts::is_disabled( $rw_m['m1'] ), 'migration apply: module switched on and users disabled' );
	$rw_rv2 = Migrator::revert( $rw_ap2['migration_id'], $rw_a );
	$rw_ok( true === $rw_rv2 && ! Plugin::is_enabled( 'disabled-users' ) && ! Accounts::is_disabled( $rw_m['m1'] ), 'migration revert: module and users restored' );
	update_option( Plugin::OPTION_MODULES, $rw_orig_modules ? $rw_orig_modules : array() );

	// The actor's own authority bounds the migration.
	$rw_n1 = $rw_make( 'rw_dis_n1', 'subscriber' );
	$rw_n2 = $rw_make( 'rw_dis_n2', 'subscriber' );
	update_user_meta( $rw_n1, 'ja_disable_user', '1' );
	update_user_meta( $rw_n2, 'ja_disable_user', '1' );
	$rw_deny = function ( $ok, $actor, $target ) use ( $rw_n2 ) {
		return $target === $rw_n2 ? false : $ok;
	};
	add_filter( 'rolegate_can_act_on_user', $rw_deny, 10, 3 );
	$rw_ap3 = null;
	$rw_p3  = Migrator::plan( 'disable-users', $rw_a );
	$rw_ok( in_array( $rw_n1, $rw_p3['ops']['users'], true ) && ! in_array( $rw_n2, $rw_p3['ops']['users'], true ) && $rw_find( $rw_p3['rows'], 'blocked', 'rw_dis_n2' ), 'migration authority: a user the actor can\'t act on is left out of the plan and reported' );
	$rw_ap3 = Migrator::apply( 'disable-users', $rw_a );
	$rw_ok( ! is_wp_error( $rw_ap3 ) && Accounts::is_disabled( $rw_n1 ) && ! Accounts::is_disabled( $rw_n2 ), 'migration authority: apply disables the allowed user and not the one above the actor' );
	remove_filter( 'rolegate_can_act_on_user', $rw_deny, 10 );
	if ( Migrator::is_shell( 0 ) ) {
		add_filter( 'rolegate_can_act_on_user', $rw_deny, 10, 3 );
		$rw_ok( in_array( $rw_n2, Migrator::plan( 'disable-users', 0 )['ops']['users'], true ), 'migration authority: the shell actor keeps WP-CLI\'s own reach' );
		remove_filter( 'rolegate_can_act_on_user', $rw_deny, 10 );
	}

	// Revert only touches accounts whose flag is as the migration left it.
	Accounts::change( $rw_a, $rw_m['m1'], false );
	Accounts::change( $rw_a, $rw_m['m1'], true );
	$rw_rv3 = ! is_wp_error( $rw_ap3 ) ? Migrator::revert( $rw_ap3['migration_id'], $rw_a ) : null;
	$rw_ok( is_wp_error( $rw_rv3 ) && 'rolegate_migration_changed' === $rw_rv3->get_error_code() && false !== strpos( $rw_rv3->get_error_message(), 'rw_dis_m1' ), 'migration revert: an account someone re-disabled on purpose is reported and blocks the revert' );
	$rw_ok( Accounts::is_disabled( $rw_n1 ) && Accounts::is_disabled( $rw_m['m1'] ) && Accounts::is_disabled( $rw_m['m2'] ), 'migration revert: nothing was re-enabled when an account had changed' );
	foreach ( array_merge( array_values( array_slice( $rw_m, 0, 5 ) ), array( $rw_n1 ) ) as $rw_id ) {
		Accounts::write( $rw_id, false );
	}

	// Shell actor: the last active manager stays enabled.
	if ( Migrator::is_shell( 0 ) ) {
		update_user_meta( $rw_b, 'ja_disable_user', '1' );
		$rw_sp = Migrator::plan( 'disable-users', 0 );
		$rw_ok( ! in_array( $rw_a, $rw_sp['ops']['users'], true ) && in_array( $rw_b, $rw_sp['ops']['users'], true ) && $rw_find( $rw_sp['rows'], 'blocked', 'last active user' ), 'migration plan (shell): when every manager is flagged, one stays enabled' );
		delete_user_meta( $rw_b, 'ja_disable_user' );
	} else {
		echo "NOTE not running under WP-CLI: shell actor check skipped\n";
	}
	delete_user_meta( $rw_a, 'ja_disable_user' );

	// The last active administrator can't be disabled or demoted, and disabled administrators don't count as a second one.
	$rw_all_admins = array_map( 'intval', get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) ) );
	$rw_parked     = array();
	foreach ( array_diff( $rw_all_admins, array( $rw_a, $rw_b ) ) as $rw_id ) {
		if ( ! Accounts::is_disabled( $rw_id ) ) {
			Accounts::write( $rw_id, true );
			$rw_parked[] = $rw_id;
		}
	}
	$rw_owner_role = $rw_role . '_own';
	$rw_roles[]    = $rw_owner_role;
	\Rolegate\Modules\Safety\Enforcer::as_system(
		function () use ( $rw_owner_role ) {
			add_role( $rw_owner_role, 'RW owner', get_role( 'administrator' )->capabilities );
		}
	);
	wp_set_current_user( $rw_a );
	$rw_owner = $rw_make( 'rw_dis_owner', $rw_owner_role );
	wp_set_current_user( 0 );
	Accounts::write( $rw_a, false );
	Accounts::write( $rw_b, true );
	$rw_code = function ( $res ) {
		return is_wp_error( $res ) ? $res->get_error_code() : 'ok';
	};
	$rw_ok( 'rolegate_last_admin' === $rw_code( Accounts::check( $rw_owner, $rw_a, true ) ), 'last admin: the only active administrator can\'t be disabled even when another user can manage the plugin (' . $rw_code( Accounts::check( $rw_owner, $rw_a, true ) ) . ')' );
	$rw_ok( 'rolegate_last_admin' === $rw_code( \Rolegate\Modules\User_Roles\Users::check_last_admin( $rw_a, array( 'administrator' ), array() ) ), 'last admin: removing the role is refused while the other administrator is disabled' );
	Accounts::write( $rw_b, false );
	$rw_ok( 'ok' === $rw_code( Accounts::check( $rw_owner, $rw_a, true ) ) && true === \Rolegate\Modules\User_Roles\Users::check_last_admin( $rw_a, array( 'administrator' ), array() ), 'last admin control: both allowed once a second administrator is enabled' );

	// Per-user capability holders are found as managers (LIKE value isn't escaped twice).
	$rw_percap = $rw_make( 'rw_dis_percap', 'subscriber' );
	\Rolegate\Modules\Safety\Enforcer::as_system(
		function () use ( $rw_percap ) {
			get_userdata( $rw_percap )->add_cap( Caps::MANAGE );
		}
	);
	$rw_ok( in_array( $rw_percap, Accounts::active_managers(), true ), 'per-user rolegate_manage holder is an active manager' );
	$rw_under = 'rw_dis_u_' . $rw_sfx;
	$rw_roles[] = $rw_under;
	add_role( $rw_under, 'RW underscore', array( 'read' => true ) );
	$rw_uid = $rw_make( 'rw_dis_under', $rw_under );
	$rw_nr  = new \WP_User_Query( array( 'fields' => 'ID', 'meta_query' => \Rolegate\Modules\User_Roles\Users::no_role_meta_query() ) ); // phpcs:ignore WordPress.DB.SlowDBQuery
	$rw_ok( ! in_array( $rw_uid, array_map( 'intval', $rw_nr->get_results() ), true ), 'a user whose role slug contains an underscore is not in the No role view' );
	// Scheduled disabling.
	$rw_sched = $rw_make( 'rw_dis_sched', 'subscriber' );
	$rw_ok( 'rolegate_disable_date_past' === $rw_code( Accounts::schedule( $rw_a, $rw_sched, time() - 60 ) ), 'schedule: a date in the past is refused' );
	$rw_ok( true === Accounts::schedule( $rw_a, $rw_sched, time() + DAY_IN_SECONDS ) && ! Accounts::is_disabled( $rw_sched ) && (int) get_user_meta( $rw_sched, Accounts::DUE_META, true ) > time(), 'schedule: a future date is stored and the account stays enabled' );
	Accounts::apply_due( $rw_sched );
	$rw_ok( ! Accounts::is_disabled( $rw_sched ), 'schedule: apply_due leaves an account whose date has not come' );
	update_user_meta( $rw_sched, Accounts::DUE_META, time() - 5 );
	$rw_ok( $rw_login( $rw_sched ) instanceof WP_Error && 'rolegate_disabled' === $rw_login( $rw_sched )->get_error_code() && Accounts::is_disabled( $rw_sched ) && ! get_user_meta( $rw_sched, Accounts::DUE_META, true ), 'schedule: a login after the date is refused and the account is disabled' );
	$rw_sched2 = $rw_make( 'rw_dis_sched2', 'subscriber' );
	update_user_meta( $rw_sched2, Accounts::DUE_META, time() - 5 );
	Accounts::apply_due_all();
	$rw_ok( Accounts::is_disabled( $rw_sched2 ), 'schedule: the daily job disables accounts that are due' );
	Accounts::write( $rw_b, true );
	Accounts::write( $rw_a, false );
	update_user_meta( $rw_a, Accounts::DUE_META, time() - 5 );
	Accounts::apply_due( $rw_a );
	$rw_ok( ! Accounts::is_disabled( $rw_a ), 'schedule: the last active administrator is never disabled by a date' );
	delete_user_meta( $rw_a, Accounts::DUE_META );
	Accounts::write( $rw_b, false );

	// Custom login message.
	Accounts::write( $rw_victim, true );
	$rw_default_msg = $rw_login( $rw_victim );
	$rw_ok( $rw_default_msg instanceof WP_Error && 'This account has been disabled.' === $rw_default_msg->get_error_message(), 'login message: the default text when none is set' );
	update_option( Accounts::MESSAGE_OPTION, 'Contact the front desk.', false );
	$rw_custom_msg = $rw_login( $rw_victim );
	$rw_ok( $rw_custom_msg instanceof WP_Error && 'rolegate_disabled' === $rw_custom_msg->get_error_code() && 'Contact the front desk.' === $rw_custom_msg->get_error_message(), 'login message: the custom text is shown to a disabled account' );
	delete_option( Accounts::MESSAGE_OPTION );
	Accounts::write( $rw_victim, false );

	// Code that sets the current user or the auth cookie itself, and password resets.
	Accounts::write( $rw_victim, true );
	wp_set_current_user( $rw_victim );
	$rw_ok( 0 === get_current_user_id() && ! current_user_can( 'read' ), 'wp_set_current_user() on a disabled account resolves to nobody' );
	wp_set_current_user( 0 );
	$rw_tokens = count( \WP_Session_Tokens::get_instance( $rw_victim )->get_all() );
	wp_set_auth_cookie( $rw_victim, false );
	$rw_ok( count( \WP_Session_Tokens::get_instance( $rw_victim )->get_all() ) === $rw_tokens, 'wp_set_auth_cookie() for a disabled account leaves no session behind' );
	$rw_ok( false === apply_filters( 'allow_password_reset', true, $rw_victim ), 'password reset is not allowed for a disabled account' );
	Accounts::write( $rw_victim, false );
	wp_set_current_user( $rw_victim );
	$rw_ok( get_current_user_id() === $rw_victim && true === apply_filters( 'allow_password_reset', true, $rw_victim ), 'control: an enabled account keeps its current user and password reset' );
	wp_set_current_user( 0 );
	foreach ( $rw_parked as $rw_id ) {
		Accounts::write( $rw_id, false );
	}
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
}

wp_set_current_user( 0 );
$pagenow = $rw_orig_pagenow;
unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
foreach ( $rw_users as $rw_id ) {
	delete_user_meta( $rw_id, 'rolegate_disabled' );
	if ( is_multisite() ) {
		revoke_super_admin( $rw_id );
		require_once ABSPATH . 'wp-admin/includes/ms.php';
		wpmu_delete_user( $rw_id );
	} else {
		wp_delete_user( $rw_id );
	}
}
foreach ( $rw_roles as $rw_r ) {
	remove_role( $rw_r );
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
$_POST    = array();
$_REQUEST = array();

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
