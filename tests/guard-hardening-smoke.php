<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/guard-hardening-smoke.php --user=<administrator>
 */

use Rolegate\Modules\Audit\Audit_Module;
use Rolegate\Modules\Audit\Audit_Page;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Enforcer;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Safety\Rescue;
use Rolegate\Modules\Safety\Stripped_Notice;

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

$rw_admin = get_current_user_id();
$rw_sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users = array();
$rw_roles = array();

try {
	// Privacy capabilities can take over other people's data, so they are critical.
	foreach ( array( 'export_others_personal_data', 'erase_others_personal_data', 'manage_privacy_options' ) as $rw_cap ) {
		$rw_ok( Guard::is_critical_cap( $rw_cap ), 'critical: ' . $rw_cap );
	}

	$rw_ok( Guard::is_critical_cap( 'wpcode_edit_snippets' ) && Guard::is_critical_cap( 'wpcode_activate_snippets' ), 'critical: WPCode snippet capabilities' );

	// Audit settings need a full site authority, not only rolegate_manage.
	$rw_role = 'rw_t_aud_' . $rw_sfx;
	$rw_roles[] = $rw_role;
	Enforcer::as_system(
		function () use ( $rw_role ) {
			add_role( $rw_role, 'RW audit manager', array( 'read' => true, Caps::MANAGE => true, Caps::VIEW_AUDIT => true ) );
		}
	);
	$rw_user = wp_insert_user(
		array(
			'user_login' => 'rw_t_aud_' . $rw_sfx,
			'user_email' => 'rw_t_aud_' . $rw_sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $rw_role,
		)
	);
	$rw_users[] = $rw_user;
	$rw_before  = get_option( Audit_Module::OPTION_SETTINGS, null );
	wp_set_current_user( $rw_user );
	$_POST    = array(
		'_wpnonce'            => wp_create_nonce( 'rolegate_audit_settings' ),
		'retention_days'      => '7',
		'delete_on_uninstall' => '1',
	);
	$_REQUEST = $_POST;
	add_filter(
		'wp_die_handler',
		$rw_die = function () {
			return function ( $message ) {
				throw new \RuntimeException( 'died' );
			};
		}
	);
	$rw_died = false;
	try {
		( new Audit_Page() )->handle_settings();
	} catch ( \RuntimeException $e ) {
		$rw_died = 'died' === $e->getMessage();
	}
	remove_filter( 'wp_die_handler', $rw_die );
	$rw_ok( $rw_died && get_option( Audit_Module::OPTION_SETTINGS, null ) === $rw_before, 'audit settings: a manager who isn\'t a site authority can\'t save them' );

	wp_set_current_user( $rw_admin );
	// Rescue limits: one visitor can't use up an administrator's bucket for everyone else; the login link can be hidden.
	$rw_resc = wp_insert_user(
		array(
			'user_login' => 'rw_t_resc_' . $rw_sfx,
			'user_email' => 'rw_t_resc_' . $rw_sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'administrator',
		)
	);
	$rw_users[] = $rw_resc;
	$rw_mails   = 0;
	add_filter( 'rolegate_rescue_defer_mail', '__return_false' );
	add_filter(
		'pre_wp_mail',
		$rw_mail = function () use ( &$rw_mails ) {
			++$rw_mails;
			return false;
		}
	);
	$rw_email = get_userdata( $rw_resc )->user_email;
	for ( $i = 0; $i < 4; $i++ ) {
		Rescue::request( $rw_email, '198.51.100.10' . $rw_sfx );
	}
	$rw_ok( 3 === $rw_mails, 'rescue: one address from one IP is limited to three links an hour (' . $rw_mails . ')' );
	Rescue::request( $rw_email, '203.0.113.7' . $rw_sfx );
	$rw_ok( 4 === $rw_mails, 'rescue: another visitor can still request a link for the same address' );
	remove_filter( 'pre_wp_mail', $rw_mail );
	remove_filter( 'rolegate_rescue_defer_mail', '__return_false' );
	ob_start();
	( new Rescue() )->footer_link();
	$rw_link = ob_get_clean();
	add_filter( 'rolegate_rescue_show_link', '__return_false' );
	ob_start();
	( new Rescue() )->footer_link();
	$rw_hidden = ob_get_clean();
	remove_filter( 'rolegate_rescue_show_link', '__return_false' );
	$rw_ok( false !== strpos( $rw_link, 'rolegate_rescue' ) && '' === $rw_hidden, 'rescue: the login page link shows by default and can be hidden' );

	// Extra default roles apply to self-registrations only.
	$rw_extra_role = 'rw_t_extra_' . $rw_sfx;
	$rw_roles[]    = $rw_extra_role;
	Enforcer::as_system(
		function () use ( $rw_extra_role ) {
			add_role( $rw_extra_role, 'RW extra', array( 'read' => true ) );
		}
	);
	$rw_orig_extra = get_option( Role_Service::OPTION_EXTRA, null );
	update_option( Role_Service::OPTION_EXTRA, array( $rw_extra_role ), false );
	wp_set_current_user( $rw_admin );
	$rw_by_admin = wp_insert_user(
		array(
			'user_login' => 'rw_t_byadm_' . $rw_sfx,
			'user_email' => 'rw_t_byadm_' . $rw_sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'subscriber',
		)
	);
	wp_set_current_user( 0 );
	$rw_self = wp_insert_user(
		array(
			'user_login' => 'rw_t_self_' . $rw_sfx,
			'user_email' => 'rw_t_self_' . $rw_sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'subscriber',
		)
	);
	$rw_users[] = $rw_by_admin;
	$rw_users[] = $rw_self;
	$rw_ok( ! in_array( $rw_extra_role, get_userdata( $rw_by_admin )->roles, true ), 'extra default roles: not added to a user an administrator creates' );
	$rw_ok( in_array( $rw_extra_role, get_userdata( $rw_self )->roles, true ), 'extra default roles: added to a self-registration' );
	if ( null === $rw_orig_extra ) {
		delete_option( Role_Service::OPTION_EXTRA );
	} else {
		update_option( Role_Service::OPTION_EXTRA, $rw_orig_extra, false );
	}

	// A role stripped from an anonymously created account is surfaced in an admin notice.
	$rw_orig_stripped = get_option( Stripped_Notice::OPTION, null );
	delete_option( Stripped_Notice::OPTION );
	wp_set_current_user( 0 );
	$rw_anon = wp_insert_user(
		array(
			'user_login' => 'rw_t_anon_' . $rw_sfx,
			'user_email' => 'rw_t_anon_' . $rw_sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'administrator',
		)
	);
	$rw_users[] = $rw_anon;
	$rw_ok( ! in_array( 'administrator', get_userdata( $rw_anon )->roles, true ) && in_array( $rw_anon, array_map( 'intval', (array) get_option( Stripped_Notice::OPTION, array() ) ), true ), 'stripped registration: the account is recorded for the admin notice' );
	if ( null === $rw_orig_stripped ) {
		delete_option( Stripped_Notice::OPTION );
	} else {
		update_option( Stripped_Notice::OPTION, $rw_orig_stripped, false );
	}
	wp_set_current_user( $rw_admin );

	// Multisite: capabilities WordPress reserves for super admins aren't held by site administrators.
	if ( is_multisite() ) {
		$rw_site_admin = wp_insert_user(
			array(
				'user_login' => 'rw_t_sa_' . $rw_sfx,
				'user_email' => 'rw_t_sa_' . $rw_sfx . '@example.com',
				'user_pass'  => wp_generate_password( 24 ),
				'role'       => 'administrator',
			)
		);
		$rw_users[] = $rw_site_admin;
		$rw_held    = Guard::user_caps( $rw_site_admin );
		$rw_ok( empty( $rw_held['edit_plugins'] ) && empty( $rw_held['unfiltered_html'] ) && ! empty( $rw_held['manage_options'] ), 'multisite: a site administrator doesn\'t hold super-admin-only capabilities' );
		$rw_ok( ! in_array( 'edit_plugins', Guard::critical_subset( array( 'edit_plugins' => true, 'manage_options' => true ) ), true ), 'multisite: super-admin-only capabilities aren\'t required of the actor' );
	}
} catch ( \Throwable $e ) {
	++$rw_fail;
	echo 'FAIL exception: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . "\n";
}

wp_set_current_user( 0 );
$_POST    = array();
$_REQUEST = array();
Enforcer::as_system(
	function () use ( $rw_users, $rw_roles ) {
		foreach ( $rw_users as $rw_id ) {
			wp_delete_user( $rw_id );
		}
		foreach ( $rw_roles as $rw_r ) {
			remove_role( $rw_r );
		}
	}
);

echo sprintf( "\n%d passed, %d failed\n", $rw_pass, $rw_fail );
exit( $rw_fail ? 1 : 0 );
