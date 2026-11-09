<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/portability-smoke.php
 */

use Rolewright\Modules\Portability\Backups;
use Rolewright\Modules\Portability\Exporter;
use Rolewright\Modules\Portability\Importer;
use Rolewright\Modules\Portability\Role_Store;
use Rolewright\Modules\Portability\Sources;

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

global $wpdb;
$rw_suffix   = substr( md5( (string) microtime( true ) ), 0, 6 );
$rw_users    = array();
$rw_roles    = array();
$rw_backups0 = get_option( Backups::OPTION, null );
$rw_ure_key  = $wpdb->get_blog_prefix() . 'backup_user_roles';
$rw_ure0     = get_option( $rw_ure_key, null );
$rw_make     = function ( $login, $role ) use ( &$rw_users, $rw_suffix ) {
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
$rw_file = function ( array $roles, array $extra = array() ) {
	return (string) wp_json_encode(
		array_merge(
			array(
				'format'  => 'rolewright',
				'version' => 1,
				'roles'   => $roles,
			),
			$extra
		)
	);
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

$rw_role_importer = 'rw_t_importer_' . $rw_suffix;
$rw_roles[]       = $rw_role_importer;
add_role( $rw_role_importer, 'RW importer', array( 'read' => true, 'edit_posts' => true, 'rolewright_manage' => true, 'rolewright_import' => true, 'rolewright_manage_roles' => true, 'rolewright_manage_caps' => true ) );

$rw_admin    = $rw_make( 'rw_admin', 'administrator' );
$rw_importer = $rw_make( 'rw_importer', $rw_role_importer );
$rw_editor   = $rw_make( 'rw_editor', 'editor' );

try {
	$rw_ok( isset( \Rolewright\Core\Plugin::modules()['portability'] ), 'module discovered' );
	$rw_ok( false !== has_action( 'admin_post_rolewright_portability_apply' ), 'apply handler registered' );

	// Export.
	$rw_payload = Exporter::build( array( 'editor', 'no_such_role' ), array(), $rw_admin );
	$rw_ok( 'rolewright' === $rw_payload['format'] && 1 === $rw_payload['version'], 'export has format and version' );
	$rw_ok( array( 'editor' ) === array_keys( $rw_payload['roles'] ), 'export holds only existing selected roles' );
	$rw_ok( Role_Store::same_caps( $rw_payload['roles']['editor']['capabilities'], get_role( 'editor' )->capabilities ), 'export caps match the live role' );

	// Malformed and hostile input.
	$rw_err = Importer::parse( '{"format":"rolewright","version":1,"roles":{' );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_json' === $rw_err->get_error_code(), 'malformed JSON rejected' );
	$rw_err = Importer::parse( '' );
	$rw_ok( is_wp_error( $rw_err ), 'empty input rejected' );
	$rw_big = $rw_file( array( 'rw_big' => array( 'capabilities' => array( 'read' => true ) ) ), array( 'pad' => str_repeat( 'a', 600000 ) ) );
	$rw_err = Importer::parse( $rw_big );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_too_large' === $rw_err->get_error_code(), 'giant payload rejected by size' );
	$rw_many = array();
	for ( $i = 0; $i < 101; $i++ ) {
		$rw_many[ 'rw_many_' . $i ] = array( 'capabilities' => array( 'read' => true ) );
	}
	$rw_err = Importer::parse( $rw_file( $rw_many ) );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_too_many' === $rw_err->get_error_code(), 'too many roles rejected' );
	$rw_caps_many = array();
	for ( $i = 0; $i < 1001; $i++ ) {
		$rw_caps_many[ 'rw_c_' . $i ] = true;
	}
	$rw_err = Importer::parse( $rw_file( array( 'rw_x' => array( 'capabilities' => $rw_caps_many ) ) ) );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_too_many_caps' === $rw_err->get_error_code(), 'too many caps rejected' );
	$rw_err = Importer::parse( str_repeat( '[', 50 ) . str_repeat( ']', 50 ) );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_json' === $rw_err->get_error_code(), 'deep nesting rejected' );
	$rw_err = Importer::parse( '{"format":"other","version":1,"roles":{}}' );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_format' === $rw_err->get_error_code(), 'foreign format rejected' );
	$rw_err = Importer::parse( '{"format":"rolewright","version":99,"roles":{}}' );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_version' === $rw_err->get_error_code(), 'future version rejected' );
	$rw_err = Importer::parse( '{"format":"rolewright","version":"1","roles":{}}' );
	$rw_ok( is_wp_error( $rw_err ), 'string version rejected' );
	$rw_err = Importer::parse( '{"format":"rolewright","version":1,"roles":"x"}' );
	$rw_ok( is_wp_error( $rw_err ) && 'rolewright_import_schema' === $rw_err->get_error_code(), 'roles not an object rejected' );

	$rw_dirty = Importer::parse(
		$rw_file(
			array(
				'../evil'            => array( 'capabilities' => array( 'read' => true ) ),
				'Upper'              => array( 'capabilities' => array( 'read' => true ) ),
				'rw_t_dirty'         => array(
					'name'         => '<script>alert(1)</script>Dirty',
					'capabilities' => array( 'read' => true, 'bad cap!' => true, '<b>x</b>' => true, 'editor' => true, 'rw_ok_cap' => 'yes', 'rw_num' => 1 ),
				),
				'rw_t_nocaps'        => array( 'name' => 'x' ),
			)
		)
	);
	$rw_ok( ! is_wp_error( $rw_dirty ), 'dirty file still parses' );
	$rw_ok( array( 'rw_t_dirty' ) === array_keys( $rw_dirty['roles'] ), 'invalid role slugs and roles without caps dropped' );
	$rw_ok( array( 'read' => true, 'rw_num' => true ) === $rw_dirty['roles']['rw_t_dirty']['capabilities'], 'invalid cap names, role-name caps and non-bool values dropped' );
	$rw_ok( false === strpos( $rw_dirty['roles']['rw_t_dirty']['name'], '<' ), 'role name stripped of markup' );
	$rw_ok( count( $rw_dirty['rejected'] ) >= 6, 'every dropped entry is listed for the preview' );

	// Create, as administrator.
	wp_set_current_user( $rw_admin );
	$rw_new  = 'rw_t_new_' . $rw_suffix;
	$rw_roles[] = $rw_new;
	$rw_p    = Importer::parse( $rw_file( array( $rw_new => array( 'name' => 'New', 'capabilities' => array( 'read' => true, 'edit_posts' => true, 'rw_t_custom_' . $rw_suffix => true ) ) ) ) );
	$rw_plan = Importer::plan( $rw_p, $rw_admin );
	$rw_ok( 'create' === $rw_plan['roles'][ $rw_new ]['action'] && '' === $rw_plan['roles'][ $rw_new ]['blocked'], 'preview shows create' );
	$rw_ok( array( 'rw_t_custom_' . $rw_suffix ) === $rw_plan['roles'][ $rw_new ]['new_custom'], 'preview lists new custom caps' );
	$rw_ok( null === get_role( $rw_new ), 'preview writes nothing' );
	$rw_events = array();
	$rw_res    = Importer::apply( $rw_p, $rw_admin, array( 'roles' => array( $rw_new ) ) );
	$rw_ok( is_array( $rw_res ) && array( $rw_new ) === $rw_res['roles'], 'apply creates the role' );
	$rw_ok( get_role( $rw_new ) && get_role( $rw_new )->has_cap( 'rw_t_custom_' . $rw_suffix ), 'created role carries its caps' );
	$rw_ev = $rw_events ? $rw_events[0] : null;
	$rw_ok( $rw_ev && 'import.applied' === $rw_ev[0] && $rw_admin === $rw_ev[1]['actor'] && array_key_exists( $rw_new, $rw_ev[1]['before']['roles'] ) && null === $rw_ev[1]['before']['roles'][ $rw_new ], 'import.applied fired with before state' );
	$rw_bk = is_array( $rw_res ) ? Backups::get( $rw_res['backup_id'] ) : null;
	$rw_ok( $rw_bk && isset( $rw_bk['roles']['administrator'] ) && ! isset( $rw_bk['roles'][ $rw_new ] ), 'backup holds the roles from before the import' );

	// Replace vs merge on an existing role.
	$rw_p2   = Importer::parse( $rw_file( array( $rw_new => array( 'name' => 'New', 'capabilities' => array( 'read' => true, 'upload_files' => true ) ) ) ) );
	$rw_plan = Importer::plan( $rw_p2, $rw_admin, 'replace' );
	$rw_ok( 'overwrite' === $rw_plan['roles'][ $rw_new ]['action'], 'preview shows overwrite' );
	$rw_ok( in_array( 'edit_posts', $rw_plan['roles'][ $rw_new ]['removed'], true ) && in_array( 'upload_files', $rw_plan['roles'][ $rw_new ]['added'], true ), 'preview lists removed and added caps' );
	$rw_plan = Importer::plan( $rw_p2, $rw_admin, 'merge' );
	$rw_ok( array() === $rw_plan['roles'][ $rw_new ]['removed'], 'merge mode removes nothing' );
	Importer::apply( $rw_p2, $rw_admin, array( 'roles' => array( $rw_new ), 'mode' => 'merge' ) );
	$rw_ok( get_role( $rw_new )->has_cap( 'edit_posts' ) && get_role( $rw_new )->has_cap( 'upload_files' ), 'merge keeps old caps and adds new' );

	// Administrator overwrite attempt.
	$rw_admin_caps = get_role( 'administrator' )->capabilities;
	$rw_hostile    = Importer::parse( $rw_file( array( 'administrator' => array( 'name' => 'Administrator', 'capabilities' => array( 'read' => true ) ) ) ) );
	$rw_plan       = Importer::plan( $rw_hostile, $rw_admin );
	$rw_ok( '' !== $rw_plan['roles']['administrator']['blocked'], 'administrator overwrite blocked in preview' );
	$rw_res = Importer::apply( $rw_hostile, $rw_admin, array( 'roles' => array( 'administrator' ) ) );
	$rw_ok( is_wp_error( $rw_res ), 'administrator overwrite refused on apply' );
	$rw_ok( Role_Store::same_caps( $rw_admin_caps, get_role( 'administrator' )->capabilities ), 'administrator caps unchanged' );
	$rw_def = (string) get_option( 'default_role' );
	$rw_res = Importer::apply( Importer::parse( $rw_file( array( $rw_def => array( 'capabilities' => array( 'read' => true, 'edit_posts' => true ) ) ) ) ), $rw_admin, array( 'roles' => array( $rw_def ) ) );
	$rw_ok( is_wp_error( $rw_res ) && ! get_role( $rw_def )->has_cap( 'edit_posts' ), 'default role overwrite refused' );

	// Non-admin importer.
	wp_set_current_user( $rw_importer );
	$rw_own = Importer::plan( Importer::parse( $rw_file( array( $rw_role_importer => array( 'capabilities' => array( 'read' => true, 'manage_options' => true ) ) ) ) ), $rw_importer );
	$rw_ok( '' !== $rw_own['roles'][ $rw_role_importer ]['blocked'], 'own role overwrite blocked' );

	$rw_html = 'rw_t_html_' . $rw_suffix;
	$rw_roles[] = $rw_html;
	$rw_ph   = Importer::parse( $rw_file( array( $rw_html => array( 'capabilities' => array( 'read' => true, 'unfiltered_html' => true, 'rolewright_manage_roles' => true ) ) ) ) );
	$rw_plan = Importer::plan( $rw_ph, $rw_importer );
	$rw_ok( in_array( 'unfiltered_html', $rw_plan['roles'][ $rw_html ]['critical'], true ) && in_array( 'rolewright_manage_roles', $rw_plan['roles'][ $rw_html ]['critical'], true ), 'preview flags critical caps (unfiltered_html, rolewright_*)' );
	$rw_res = Importer::apply( $rw_ph, $rw_importer, array( 'roles' => array( $rw_html ), 'confirm_critical' => array( $rw_html ) ) );
	$rw_ok( is_wp_error( $rw_res ) && null === get_role( $rw_html ), 'confirmed unfiltered_html refused for an actor who lacks it' );
	$rw_res = Importer::apply( $rw_ph, $rw_importer, array( 'roles' => array( $rw_html ) ) );
	$rw_ok( is_array( $rw_res ) && get_role( $rw_html ) && ! get_role( $rw_html )->has_cap( 'unfiltered_html' ) && ! get_role( $rw_html )->has_cap( 'rolewright_manage_roles' ), 'unconfirmed critical caps are stripped' );

	$rw_res = Importer::apply( array( 'roles' => array( 'rw_t_tamper' => array( 'name' => 'T', 'capabilities' => array( 'read' => true, 'manage options' => true ) ) ), 'sections' => array() ), $rw_importer, array( 'roles' => array( 'rw_t_tamper' ) ) );
	$rw_roles[] = 'rw_t_tamper';
	$rw_ok( is_array( $rw_res ) && get_role( 'rw_t_tamper' ) && ! array_key_exists( 'manage options', get_role( 'rw_t_tamper' )->capabilities ), 'payload is re-validated on apply' );

	wp_set_current_user( $rw_editor );
	$rw_res = Importer::apply( $rw_p, $rw_editor, array( 'roles' => array( $rw_new ) ) );
	$rw_ok( is_wp_error( $rw_res ) && 'rolewright_forbidden' === $rw_res->get_error_code(), 'actor without rolewright_import refused' );

	// Admin confirms a critical cap they hold.
	wp_set_current_user( $rw_admin );
	$rw_res = Importer::apply( $rw_ph, $rw_admin, array( 'roles' => array( $rw_html ), 'confirm_critical' => array( $rw_html ) ) );
	$rw_ok( is_array( $rw_res ) && get_role( $rw_html )->has_cap( 'unfiltered_html' ), 'confirmed critical cap granted when the actor holds it' );

	// Other-plugin source.
	$rw_ure_role = 'rw_t_ure_' . $rw_suffix;
	$rw_roles[]  = $rw_ure_role;
	update_option( $rw_ure_key, array( $rw_ure_role => array( 'name' => 'From backup', 'capabilities' => array( 'read' => true, 'bad cap' => true ) ) ), false );
	$rw_ok( isset( Sources::available()['ure_backup'] ), 'stored role backup offered as a source' );
	$rw_src = Sources::load( 'ure_backup' );
	$rw_ok( ! is_wp_error( $rw_src ) && array( 'read' => true ) === $rw_src['roles'][ $rw_ure_role ]['capabilities'] && 'ure_backup' === $rw_src['source'], 'source goes through the same validation' );
	$rw_ok( null === get_role( $rw_ure_role ), 'reading a source writes nothing' );

	// Sections.
	$rw_section_store = array( 'rule' => 1 );
	$rw_section_hook  = function ( $sections ) use ( &$rw_section_store ) {
		$sections['rwtest'] = array(
			'label'   => 'Test rules',
			'cap'     => 'rolewright_manage_access',
			'export'  => function () use ( &$rw_section_store ) {
				return $rw_section_store;
			},
			'preview' => function ( $data ) {
				return is_array( $data ) ? array( 'rules: ' . count( $data ) ) : new \WP_Error( 'bad', 'bad' );
			},
			'import'  => function ( $data, $actor ) use ( &$rw_section_store ) {
				$before           = $rw_section_store;
				$rw_section_store = $data;
				return $before;
			},
		);
		return $sections;
	};
	add_filter( 'rolewright_portability_sections', $rw_section_hook );
	$rw_out = Exporter::build( array(), array( 'rwtest' ), $rw_admin );
	$rw_ok( isset( $rw_out['sections']['rwtest'] ) && array( 'rule' => 1 ) === $rw_out['sections']['rwtest'], 'registered section exported' );
	$rw_out2 = Exporter::build( array(), array( 'rwtest' ), $rw_editor );
	$rw_ok( ! isset( $rw_out2['sections'] ), 'section not exported for an actor without its cap' );
	$rw_ps = Importer::parse( $rw_file( array(), array( 'sections' => array( 'rwtest' => array( 'rule' => 2, 'x' => 3 ), 'unknown' => array() ) ) ) );
	$rw_plan = Importer::plan( $rw_ps, $rw_admin );
	$rw_ok( array( 'rules: 2' ) === $rw_plan['sections']['rwtest']['summary'], 'section previewed' );
	$rw_events = array();
	$rw_res    = Importer::apply( $rw_ps, $rw_admin, array( 'sections' => array( 'rwtest' ) ) );
	$rw_ok( is_array( $rw_res ) && array( 'rule' => 2, 'x' => 3 ) === $rw_section_store, 'section imported' );
	$rw_ok( $rw_events && array( 'rule' => 1 ) === $rw_events[0][1]['before']['sections']['rwtest'], 'section before state in the event' );
	remove_filter( 'rolewright_portability_sections', $rw_section_hook );

	// Handlers: capability and nonce.
	$rw_die = function () {
		return function ( $message ) {
			throw new \RuntimeException( is_wp_error( $message ) ? $message->get_error_message() : wp_strip_all_tags( (string) $message ) );
		};
	};
	add_filter( 'wp_die_handler', $rw_die );
	add_filter( 'wp_die_ajax_handler', $rw_die );
	wp_set_current_user( $rw_editor );
	$rw_threw = false;
	try {
		do_action( 'admin_post_rolewright_portability_apply' );
	} catch ( \RuntimeException $e ) {
		$rw_threw = true;
	}
	$rw_ok( $rw_threw, 'apply handler refuses a user without the cap' );
	wp_set_current_user( $rw_admin );
	$_POST['token'] = 'abc';
	$_REQUEST       = $_POST;
	$rw_threw       = false;
	try {
		do_action( 'admin_post_rolewright_portability_apply' );
	} catch ( \RuntimeException $e ) {
		$rw_threw = true;
	}
	$rw_ok( $rw_threw, 'apply handler refuses a missing nonce' );
	$_POST    = array();
	$_REQUEST = array();
	remove_filter( 'wp_die_handler', $rw_die );
	remove_filter( 'wp_die_ajax_handler', $rw_die );
} finally {
	wp_set_current_user( 0 );
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( $rw_users as $id ) {
		wp_delete_user( $id );
	}
	foreach ( $rw_roles as $role ) {
		remove_role( $role );
	}
	null === $rw_backups0 ? delete_option( Backups::OPTION ) : update_option( Backups::OPTION, $rw_backups0, false );
	null === $rw_ure0 ? delete_option( $rw_ure_key ) : update_option( $rw_ure_key, $rw_ure0, false );
}

echo "\n{$rw_pass} passed, {$rw_fail} failed\n";
if ( $rw_fail ) {
	exit( 1 );
}
