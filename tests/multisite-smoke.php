<?php
/**
 * Run on a multisite install: wp eval-file wp-content/plugins/rolewright/tests/multisite-smoke.php
 * Set RW_MS_SITES to change how many subsites it creates (default 104, so paging past
 * get_sites()'s 100-site default is exercised).
 */

use Rolewright\Modules\Multisite\Multisite_Module;
use Rolewright\Modules\Multisite\Network_Sync;
use Rolewright\Modules\Portability\Role_Store;
use Rolewright\Modules\Safety\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}
if ( ! is_multisite() ) {
	echo "SKIP not a multisite install\n";
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
$rw_count   = getenv( 'RW_MS_SITES' ) ? max( 3, (int) getenv( 'RW_MS_SITES' ) ) : 104;
$rw_sites   = array();
$rw_users   = array();
$rw_main    = get_main_site_id();
$rw_role    = 'rw_t_sync_' . $rw_suffix;
$rw_opt_sa  = get_site_option( Multisite_Module::OPTION_SITE_ADMIN, null );
$rw_opt_bt  = get_site_option( Multisite_Module::OPTION_BATCH, null );
$rw_super   = 0;
foreach ( get_super_admins() as $login ) {
	$u = get_user_by( 'login', $login );
	if ( $u ) {
		$rw_super = (int) $u->ID;
		break;
	}
}
$rw_make = function ( $login ) use ( &$rw_users, $rw_suffix ) {
	$id = wpmu_create_user( $login . '_' . $rw_suffix, wp_generate_password( 24 ), $login . '_' . $rw_suffix . '@example.com' );
	if ( ! $id ) {
		echo "SETUP ERROR user\n";
		exit( 1 );
	}
	$rw_users[] = (int) $id;
	return (int) $id;
};
$rw_events = array();
add_action(
	'rolewright_changed',
	function ( $type, $data ) use ( &$rw_events ) {
		$rw_events[] = array( $type, $data );
	},
	10,
	2
);
$rw_run = function ( $job, $actor ) {
	$rounds = 0;
	while ( is_array( $job ) && ! $job['finished'] && $rounds < 1000 ) {
		$job = Network_Sync::run_batch( $job, $actor );
		++$rounds;
	}
	return array( $job, $rounds );
};
$rw_role_on = function ( $site, $slug ) {
	switch_to_blog( $site );
	$r = Role_Store::get( $slug );
	restore_current_blog();
	return $r;
};

try {
	$rw_ok( $rw_super > 0, 'found a super admin' );
	$rw_ok( false !== has_action( 'network_admin_menu', array( \Rolewright\Core\Plugin::modules()['multisite'], 'menu' ) ), 'network admin page registered on multisite' );
	$rw_ok( false !== has_filter( 'rolewright_multisite_site_admin_access' ), 'site-admin access filter registered' );

	$rw_net = get_network();
	for ( $i = 0; $i < $rw_count; $i++ ) {
		$id = wp_insert_site(
			array(
				'domain'  => $rw_net->domain,
				'path'    => $rw_net->path . 'rwt' . $rw_suffix . $i . '/',
				'title'   => 'RW test ' . $i,
				'user_id' => $rw_super,
			)
		);
		if ( is_wp_error( $id ) ) {
			echo 'SETUP ERROR ' . $id->get_error_message() . "\n";
			exit( 1 );
		}
		$rw_sites[] = (int) $id;
	}
	$rw_total = (int) get_sites( array( 'count' => true, 'number' => 0 ) );
	$rw_ok( $rw_total === count( $rw_sites ) + count( array_diff( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ), $rw_sites ) ), 'site count is consistent' );
	echo 'INFO network has ' . $rw_total . " sites\n";

	switch_to_blog( $rw_main );
	add_role( $rw_role, 'RW sync', array( 'read' => true, 'edit_posts' => true, 'rw_t_cap_' . $rw_suffix => true ) );
	restore_current_blog();

	// Escalation: only super admins may start or continue.
	$rw_plain = $rw_make( 'rw_plain' );
	add_user_to_blog( $rw_main, $rw_plain, 'administrator' );
	$rw_err = Network_Sync::start( $rw_plain, $rw_main, array( $rw_role ), 'replace', false );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_forbidden' === $rw_err->get_error_code(), 'site administrator cannot start apply-to-all-sites' );

	update_site_option( Multisite_Module::OPTION_BATCH, 40 );
	wp_set_current_user( $rw_super );
	$rw_job = Network_Sync::start( $rw_super, $rw_main, array( $rw_role ), 'replace', false );
	$rw_ok( is_array( $rw_job ) && $rw_total === $rw_job['total'], 'job counts every site, not only the first 100' );
	$rw_err = Network_Sync::run_batch( $rw_job, $rw_plain );
	$rw_ok( is_wp_error( $rw_err ), 'another user cannot continue the job' );

	$rw_events = array();
	list( $rw_job, $rw_rounds ) = $rw_run( $rw_job, $rw_super );
	$rw_ok( $rw_job['finished'] && $rw_rounds >= (int) ceil( $rw_total / 40 ), 'job ran in batches (' . $rw_rounds . ' rounds)' );
	$rw_ok( $rw_total === $rw_job['offset'], 'every site was visited' );
	$rw_missing = 0;
	$rw_src     = $rw_role_on( $rw_main, $rw_role );
	foreach ( $rw_sites as $site ) {
		$r = $rw_role_on( $site, $rw_role );
		if ( ! $r || ! Role_Store::same_caps( $r['capabilities'], $rw_src['capabilities'] ) ) {
			++$rw_missing;
		}
	}
	$rw_ok( 0 === $rw_missing, 'role copied exactly to all ' . count( $rw_sites ) . ' test sites' );
	$rw_last = end( $rw_sites );
	$rw_ok( null !== $rw_role_on( $rw_last, $rw_role ), 'site beyond position 100 got the role' );
	$rw_created = array_filter(
		$rw_events,
		function ( $e ) use ( $rw_role ) {
			return 'role.created' === $e[0] && $rw_role === $e[1]['target'] && isset( $e[1]['site_id'] );
		}
	);
	$rw_ok( count( $rw_created ) === count( $rw_sites ), 'role.created fired once per site with site_id' );

	// Merge vs replace.
	$rw_s1 = $rw_sites[0];
	switch_to_blog( $rw_s1 );
	get_role( $rw_role )->add_cap( 'rw_t_local_' . $rw_suffix );
	restore_current_blog();
	switch_to_blog( $rw_main );
	get_role( $rw_role )->add_cap( 'upload_files' );
	$rw_def = Role_Store::get( $rw_role );
	restore_current_blog();
	Network_Sync::apply_to_site( $rw_s1, array( $rw_role => $rw_def ), 'merge', $rw_super );
	$r = $rw_role_on( $rw_s1, $rw_role );
	$rw_ok( ! empty( $r['capabilities'][ 'rw_t_local_' . $rw_suffix ] ) && ! empty( $r['capabilities']['upload_files'] ), 'caps-only mode adds and keeps local caps' );
	Network_Sync::apply_to_site( $rw_s1, array( $rw_role => $rw_def ), 'replace', $rw_super );
	$r = $rw_role_on( $rw_s1, $rw_role );
	$rw_ok( empty( $r['capabilities'][ 'rw_t_local_' . $rw_suffix ] ) && Role_Store::same_caps( $r['capabilities'], $rw_def['capabilities'] ), 'sync mode makes the role identical' );

	// Guard runs per site.
	$rw_admin_before = $rw_role_on( $rw_s1, 'administrator' );
	$rw_res          = Network_Sync::apply_to_site(
		$rw_s1,
		array(
			'administrator' => array(
				'name'         => 'Administrator',
				'capabilities' => array( 'read' => true ),
			),
		),
		'replace',
		$rw_super
	);
	$rw_ok( 0 === $rw_res['roles'] && $rw_res['errors'], 'stripping administrator refused on each site' );
	$rw_ok( Role_Store::same_caps( $rw_admin_before['capabilities'], $rw_role_on( $rw_s1, 'administrator' )['capabilities'] ), 'administrator unchanged' );
	$rw_res = Network_Sync::apply_to_site(
		$rw_s1,
		array(
			'rw_t_bad' => array(
				'name'         => 'Bad',
				'capabilities' => array( 'bad cap!' => true ),
			),
		),
		'replace',
		$rw_super
	);
	$rw_ok( $rw_res['errors'] && null === $rw_role_on( $rw_s1, 'rw_t_bad' ), 'invalid cap names refused per site' );

	// Push roles and users.
	$rw_u1 = $rw_make( 'rw_push1' );
	$rw_u2 = $rw_make( 'rw_push2' );
	add_user_to_blog( $rw_main, $rw_u1, $rw_role );
	add_user_to_blog( $rw_main, $rw_u2, 'editor' );
	add_user_to_blog( $rw_s1, $rw_u2, 'subscriber' );
	$rw_few = array_slice( $rw_sites, 0, 3 );
	update_site_option( Multisite_Module::OPTION_BATCH, 200 );
	$rw_job = Network_Sync::start( $rw_super, $rw_main, array(), 'replace', true );
	list( $rw_job ) = $rw_run( $rw_job, $rw_super );
	$rw_member = 0;
	foreach ( $rw_sites as $site ) {
		if ( is_user_member_of_blog( $rw_u1, $site ) && in_array( $rw_role, (array) ( new \WP_User( $rw_u1, '', $site ) )->roles, true ) ) {
			++$rw_member;
		}
	}
	$rw_ok( count( $rw_sites ) === $rw_member, 'user pushed to every site with their role' );
	$rw_ok( array( 'subscriber' ) === array_values( ( new \WP_User( $rw_u2, '', $rw_s1 ) )->roles ), 'existing member keeps their role' );
	$rw_ok( in_array( 'editor', ( new \WP_User( $rw_u2, '', $rw_few[1] ) )->roles, true ), 'non-member added with source role' );

	// Site administrators and Rolewright pages.
	$rw_sa = $rw_make( 'rw_siteadmin' );
	add_user_to_blog( $rw_s1, $rw_sa, 'administrator' );
	switch_to_blog( $rw_s1 );
	Caps::grant_to_administrator();
	delete_site_option( Multisite_Module::OPTION_SITE_ADMIN );
	$rw_ok( ! user_can( $rw_sa, Caps::MANAGE ), 'site admin blocked from Rolewright pages by default' );
	$rw_ok( ! user_can( $rw_sa, Caps::IMPORT ), 'site admin cannot import by default' );
	$rw_ok( user_can( $rw_super, Caps::MANAGE ) && user_can( $rw_super, Caps::IMPORT ), 'super admin keeps access' );
	update_site_option( Multisite_Module::OPTION_SITE_ADMIN, true );
	$rw_ok( user_can( $rw_sa, Caps::MANAGE ) && user_can( $rw_sa, Caps::MANAGE_ROLES ), 'network setting lets site admins in' );
	restore_current_blog();
	delete_site_option( Multisite_Module::OPTION_SITE_ADMIN );
	switch_to_blog( $rw_main );
	$rw_ok( ! user_can( $rw_plain, Caps::MANAGE ), 'main-site administrator who is not super admin is blocked too' );
	restore_current_blog();
} finally {
	wp_set_current_user( 0 );
	require_once ABSPATH . 'wp-admin/includes/ms.php';
	foreach ( $rw_sites as $site ) {
		wp_delete_site( $site );
	}
	foreach ( $rw_users as $id ) {
		wpmu_delete_user( $id );
	}
	switch_to_blog( $rw_main );
	remove_role( $rw_role );
	restore_current_blog();
	null === $rw_opt_sa ? delete_site_option( Multisite_Module::OPTION_SITE_ADMIN ) : update_site_option( Multisite_Module::OPTION_SITE_ADMIN, $rw_opt_sa );
	null === $rw_opt_bt ? delete_site_option( Multisite_Module::OPTION_BATCH ) : update_site_option( Multisite_Module::OPTION_BATCH, $rw_opt_bt );
}

echo "\n{$rw_pass} passed, {$rw_fail} failed\n";
if ( $rw_fail ) {
	exit( 1 );
}
