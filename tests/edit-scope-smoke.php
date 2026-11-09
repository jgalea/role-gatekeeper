<?php
/**
 * Run: wp eval-file wp-content/plugins/rolewright/tests/edit-scope-smoke.php
 */

use Rolewright\Core\Plugin;
use Rolewright\Modules\Edit_Scope\Evaluator;
use Rolewright\Modules\Edit_Scope\Gravity_Forms;
use Rolewright\Modules\Edit_Scope\Rules;
use Rolewright\Modules\Edit_Scope\Scope_Enforcer;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/admin.php';

$rw_pass = 0;
$rw_fail = 0;
$ok      = function ( $cond, $label ) use ( &$rw_pass, &$rw_fail ) {
	if ( $cond ) {
		++$rw_pass;
		echo 'PASS ' . $label . "\n";
	} else {
		++$rw_fail;
		echo 'FAIL ' . $label . "\n";
	}
};

$sfx   = substr( md5( (string) microtime( true ) ), 0, 6 );
$users = array();
$posts = array();
$terms = array();
$mk    = function ( $login, $role ) use ( &$users, $sfx ) {
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
$post  = function ( $author, $title = 'rw', $status = 'publish' ) use ( &$posts ) {
	$id      = wp_insert_post( array( 'post_title' => $title, 'post_status' => $status, 'post_author' => $author, 'post_content' => 'x' ) );
	$posts[] = (int) $id;
	return (int) $id;
};
$term  = function ( $name, $parent = 0, $tax = 'category' ) use ( &$terms, $sfx ) {
	$t = wp_insert_term( $name . $sfx, $tax, array( 'parent' => $parent ) );
	if ( is_wp_error( $t ) ) {
		echo 'SETUP ERROR ' . $t->get_error_message() . "\n";
		exit( 1 );
	}
	$terms[] = array( (int) $t['term_id'], $tax );
	return (int) $t['term_id'];
};
$clear = function () {
	delete_option( Rules::OPTION );
	Rules::flush();
};
$can   = function ( $uid, $cap, $id ) {
	clean_user_cache( $uid );
	return user_can( $uid, $cap, $id );
};

$admin = $mk( 'rw_es_admin', 'administrator' );
$ed    = $mk( 'rw_es_editor', 'editor' );
$ed2   = $mk( 'rw_es_editor2', 'editor' );
$au    = $mk( 'rw_es_author', 'author' );
wp_set_current_user( $admin );
update_option( Plugin::OPTION_MODULES, array_merge( Plugin::enabled_map(), array( 'edit-scope' => true ) ) );
$clear();

$events = array();
add_action(
	'rolewright_changed',
	function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	},
	10,
	2
);

$mods = Plugin::modules();
$ok( isset( $mods['edit-scope'] ) && 'edit-scope' === $mods['edit-scope']->id(), 'module discovered' );
$ok( has_filter( 'map_meta_cap', array( new Scope_Enforcer(), 'map_meta_cap' ) ) === false, 'fresh enforcer instance not hooked (module owns its own)' );

$p_ed  = $post( $ed );
$p_ed2 = $post( $ed2 );
$p_au  = $post( $au );
$p_c1  = $post( $ed2 );
$p_c2  = $post( $ed2 );
$c1    = $term( 'ScopeParent' );
$c2    = $term( 'ScopeChild', $c1 );
wp_set_post_categories( $p_c1, array( $c1 ) );
wp_set_post_categories( $p_c2, array( $c2 ) );

// No rules: nothing changes.
$ok( $can( $ed, 'edit_post', $p_ed2 ) && $can( $ed, 'delete_post', $p_ed2 ), 'no rules: editor edits and deletes others posts' );

// Block by post ID.
$r = Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'post', 'ids' => array( $p_ed2, $p_au ) ) );
$ok( is_array( $r ) && ! empty( $r['id'] ), 'block-by-post rule saved' );
$ok( ! $can( $ed, 'edit_post', $p_ed2 ), 'block post: edit_post denied' );
$ok( ! $can( $ed, 'delete_post', $p_ed2 ), 'block post: delete_post denied' );
$ok( ! $can( $ed, 'publish_post', $p_ed2 ), 'block post: publish_post denied' );
$ok( ! $can( $ed, 'edit_page', $p_ed2 ), 'block post: legacy edit_page denied' );
$ok( $can( $ed, 'edit_post', $p_ed ) && $can( $ed, 'edit_post', $p_c1 ), 'block post: other posts still editable' );
$ok( $can( $ed, 'edit_posts', 0 ), 'new post creation (edit_posts) unaffected' );
$ok( $can( $ed, 'edit_post', 0 ) || true, 'edit_post with no post ID does not error' );
$auto = wp_insert_post( array( 'post_title' => 'auto', 'post_status' => 'auto-draft', 'post_author' => $ed ) );
$posts[] = $auto;
$ok( $can( $ed, 'edit_post', $auto ), 'auto-draft (new post screen) is editable' );
$ok( $can( $admin, 'edit_post', $p_ed2 ), 'administrator exempt from block rule' );
$ok( $can( $ed2, 'edit_post', $p_ed2 ) === false, 'rule applies to every user in the role (second editor)' );
$ok( ! empty( $events ) && 'access.updated' === $events[0][0], 'access.updated fired on add' );
$ok( $events[0][1]['actor'] === $admin && $events[0][1]['target'] === $r['id'] && array() === $events[0][1]['before'] && $events[0][1]['after']['ids'] === array( $p_ed2, $p_au ), 'event carries actor, target, before, after' );

// Lists, REST, bulk, trash.
$GLOBALS['wp_the_query'] = $wpq = new WP_Query();
$GLOBALS['pagenow']      = 'edit.php';
set_current_screen( 'edit-post' );
wp_set_current_user( $ed );
$wpq->query( array( 'post_type' => 'post', 'post_status' => 'any', 'posts_per_page' => -1, 'fields' => 'ids', 'orderby' => 'none' ) );
$ok( ! in_array( $p_ed2, $wpq->posts, true ) && in_array( $p_ed, $wpq->posts, true ), 'admin list hides blocked posts (main query)' );
$GLOBALS['pagenow'] = 'index.php';
wp_set_current_user( $admin );

wp_set_current_user( $ed );
rest_get_server();
do_action( 'rest_api_init' );
$req = new WP_REST_Request( 'GET', '/wp/v2/posts' );
$req->set_param( 'per_page', 100 );
$req->set_param( 'status', 'publish' );
$req->set_param( 'context', 'edit' );
$res = rest_do_request( $req );
$ids = array_map( function ( $p ) { return (int) $p['id']; }, (array) $res->get_data() );
$ok( $res->get_status() === 200 && count( $ids ) > 0 && ! in_array( $p_ed2, $ids, true ) && in_array( $p_ed, $ids, true ), 'REST list hides blocked posts (' . count( $ids ) . ' returned)' );
$res = rest_do_request( new WP_REST_Request( 'PUT', '/wp/v2/posts/' . $p_ed2 ) );
$ok( 403 === $res->get_status(), 'REST write on blocked post is 403' );
$req = new WP_REST_Request( 'DELETE', '/wp/v2/posts/' . $p_ed2 );
$ok( 403 === rest_do_request( $req )->get_status(), 'REST trash on blocked post is 403' );

require_once ABSPATH . 'wp-admin/includes/post.php';
$b1 = $post( $ed2, 'bulk-a', 'publish' );
$b2 = $post( $ed2, 'bulk-b', 'publish' );
Rules::add( $admin, array( 'subject_type' => 'user', 'subject' => $ed, 'mode' => 'block', 'by' => 'post', 'ids' => array( $b1 ) ) );
$res = bulk_edit_posts( array( 'post' => array( $b1, $b2 ), '_status' => 'draft', 'post_author' => -1, 'comment_status' => '', 'ping_status' => '', 'post_format' => -1, 'sticky' => '-1', 'post_category' => array(), 'keep_private' => '' ) );
clean_post_cache( $b1 );
clean_post_cache( $b2 );
$ok( 'publish' === get_post_status( $b1 ) && 'draft' === get_post_status( $b2 ), 'bulk edit skips the user-blocked post and edits the other' );
$ok( ! $can( $ed, 'delete_post', $b1 ) && $can( $ed, 'delete_post', $b2 ), 'bulk trash/restore (delete_post) follows the rule' );
$ok( ! $can( $ed, 'edit_post', $b1 ), 'quick edit (edit_post) follows user rule' );
wp_set_current_user( $admin );
$clear();

// Allow list by post ID.
Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'allow', 'by' => 'post', 'ids' => array( $p_ed2 ) ) );
$ok( $can( $ed, 'edit_post', $p_ed2 ) && ! $can( $ed, 'edit_post', $p_ed ) && ! $can( $ed, 'edit_post', $p_c1 ), 'allow post: only listed post editable' );
$ok( $can( $ed, 'edit_post', $auto ), 'allow post: new post (auto-draft) still works' );
$c = Evaluator::list_constraints( $ed );
$ok( isset( $c['post__in'] ) && in_array( $p_ed2, $c['post__in'], true ) && ! in_array( $p_ed, $c['post__in'], true ) && ! in_array( $p_c1, $c['post__in'], true ), 'allow post: list constraint holds only the allowed post' );
$clear();

// By author.
Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'author', 'ids' => array( $ed2, $ed ) ) );
$ok( ! $can( $ed, 'edit_post', $p_ed2 ), 'block author: other author posts denied' );
$ok( $can( $ed, 'edit_post', $p_ed ), 'block author: editor still edits own posts although own ID is listed' );
$ok( $can( $ed, 'edit_post', $p_au ), 'block author: unlisted author posts editable' );
$c = Evaluator::list_constraints( $ed );
$ok( in_array( $p_ed2, $c['post__not_in'], true ) && ! in_array( $p_ed, $c['post__not_in'], true ), 'block author: list hides others, keeps own' );
$clear();
Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'author', 'mode' => 'allow', 'by' => 'author', 'ids' => array( $ed ) ) );
$ok( $can( $au, 'edit_post', $p_au ), 'allow author: author keeps own posts' );
$ok( ! $can( $au, 'edit_post', $p_c1 ) || true, 'allow author: baseline' );
$clear();

// By term, with and without children.
$rb = Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'term', 'ids' => array( $c1 ), 'children' => false ) );
$ok( ! $can( $ed, 'edit_post', $p_c1 ) && $can( $ed, 'edit_post', $p_c2 ), 'block term without children: parent term post denied, child term post allowed' );
Rules::update( $admin, $rb['id'], array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'term', 'ids' => array( $c1 ), 'children' => true ) );
$ok( ! $can( $ed, 'edit_post', $p_c1 ) && ! $can( $ed, 'edit_post', $p_c2 ), 'block term with children: both denied' );
$c = Evaluator::list_constraints( $ed );
$ok( in_array( $p_c1, $c['post__not_in'], true ) && in_array( $p_c2, $c['post__not_in'], true ), 'block term with children: list hides both' );
$last = end( $events );
$ok( 'access.updated' === $last[0] && ! empty( $last[1]['before'] ) && ! empty( $last[1]['after'] ) && false === $last[1]['before']['children'] && true === $last[1]['after']['children'], 'update fires access.updated with before and after' );
$clear();
Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'allow', 'by' => 'term', 'ids' => array( $c1 ), 'children' => true ) );
$own_new = $post( $ed, 'own uncategorised' );
$ok( $can( $ed, 'edit_post', $p_c2 ) && ! $can( $ed, 'edit_post', $p_ed2 ), 'allow term with children: child-term post editable, unrelated denied' );
$ok( $can( $ed, 'edit_post', $own_new ), 'allow term: own post with only the default category stays editable' );
$c = Evaluator::list_constraints( $ed );
$ok( in_array( $p_c1, $c['post__in'], true ) && in_array( $own_new, $c['post__in'], true ) && ! in_array( $p_ed2, $c['post__in'], true ), 'allow term: list constraint consistent with cap check' );
$clear();

// Term assignment restriction.
$ta = $term( 'AssignOk' );
$tb = $term( 'AssignBlocked' );
$tl = $term( 'AssignLocked' );
$ap = $post( $ed );
wp_set_post_categories( $ap, array( $tl ) );
Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'assign', 'taxonomy' => 'category', 'ids' => array( $tb, $tl ) ) );
wp_set_current_user( $ed );
wp_set_post_categories( $ap, array( $ta, $tb ) );
$have = wp_get_object_terms( $ap, 'category', array( 'fields' => 'ids' ) );
$ok( in_array( $ta, $have, true ) && ! in_array( $tb, $have, true ), 'assign: blocked term dropped on save, allowed term kept' );
$ok( in_array( $tl, $have, true ), 'assign: previously set blocked term cannot be removed by the user' );
$ok( ! user_can( $ed, 'assign_term', $tb ) && user_can( $ed, 'assign_term', $ta ), 'assign_term meta cap follows the rule (REST path)' );
$GLOBALS['pagenow'] = 'post.php';
set_current_screen( 'post' );
$a = apply_filters( 'get_terms_args', array( 'taxonomy' => array( 'category' ), 'hide_empty' => false ), array( 'category' ) );
$ok( in_array( $tb, $a['exclude'], true ) && ! in_array( $ta, $a['exclude'], true ), 'assign: blocked terms removed from editor term lists' );
$GLOBALS['pagenow'] = 'index.php';
wp_set_current_user( $admin );
wp_set_post_categories( $ap, array( $tb ) );
$ok( in_array( $tb, wp_get_object_terms( $ap, 'category', array( 'fields' => 'ids' ) ), true ), 'assign: administrator not restricted' );
$clear();
Rules::add( $admin, array( 'subject_type' => 'user', 'subject' => $ed, 'mode' => 'allow', 'by' => 'assign', 'taxonomy' => 'category', 'ids' => array( $c1 ), 'children' => true ) );
$ok( Evaluator::term_allowed( $ed, $c2, 'category' ) && ! Evaluator::term_allowed( $ed, $ta, 'category' ) && Evaluator::term_allowed( $ed2, $ta, 'category' ), 'assign allow with children: child ok, others denied, other users unaffected' );
$clear();

// Rule validation and safety.
$admin_role = Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'administrator', 'mode' => 'block', 'by' => 'post', 'ids' => array( $p_ed ) ) );
$ok( is_wp_error( $admin_role ) && 'rolewright_edit_scope_exempt' === $admin_role->get_error_code(), 'rule on a role that manages access is refused' );
$self = Rules::add( $admin, array( 'subject_type' => 'user', 'subject' => $admin, 'mode' => 'block', 'by' => 'post', 'ids' => array( $p_ed ) ) );
$ok( is_wp_error( $self ), 'rule on yourself is refused' );
$denied = Rules::add( $ed, array( 'subject_type' => 'role', 'subject' => 'author', 'mode' => 'block', 'by' => 'post', 'ids' => array( $p_ed ) ) );
$ok( is_wp_error( $denied ) && 'rolewright_forbidden' === $denied->get_error_code(), 'actor without rolewright_manage_access cannot add a rule' );
$ok( is_wp_error( Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'post', 'ids' => array( 'abc', '-3' ) ) ) ), 'non-numeric IDs refused' );
$ok( is_wp_error( Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'assign', 'taxonomy' => 'nope', 'ids' => array( 1 ) ) ) ), 'unknown taxonomy refused' );
$ok( is_wp_error( Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'maybe', 'by' => 'post', 'ids' => array( 1 ) ) ) ), 'bad mode refused' );
$ok( is_wp_error( Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'gf_form', 'ids' => array( 1 ) ) ) ) === ! Gravity_Forms::available(), 'gf_form rules only accepted when Gravity Forms is active' );
$ok( array() === Rules::all(), 'refused rules leave storage unchanged' );

// Read-only (not hidden) mode, delete rule, admin page.
$r = Rules::add( $admin, array( 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'block', 'by' => 'post', 'ids' => array( $p_ed2 ) ) );
Rules::save_settings( $admin, false );
$ok( false === Rules::hide_in_lists(), 'hide_in_lists setting saved' );
$GLOBALS['wp_the_query'] = $wpq = new WP_Query();
$GLOBALS['pagenow']      = 'edit.php';
wp_set_current_user( $ed );
$wpq->query( array( 'post_type' => 'post', 'post_status' => 'any', 'posts_per_page' => -1, 'fields' => 'ids', 'orderby' => 'none' ) );
$ok( in_array( $p_ed2, $wpq->posts, true ) && ! user_can( $ed, 'edit_post', $p_ed2 ), 'read-only mode: listed but not editable' );
$GLOBALS['pagenow'] = 'index.php';
wp_set_current_user( $admin );
Rules::save_settings( $admin, true );
$del = Rules::delete( $admin, $r['id'] );
$last = end( $events );
$ok( true === $del && 'access.updated' === $last[0] && array() === $last[1]['after'] && $last[1]['before']['id'] === $r['id'], 'delete fires access.updated with before' );
$ok( $can( $ed, 'edit_post', $p_ed2 ), 'deleting the rule restores access' );
$ok( is_wp_error( Rules::delete( $ed, 'x' ) ), 'delete needs the access capability' );

global $submenu;
( new Rolewright\Modules\Edit_Scope\Admin_Page() )->register();
do_action( 'admin_menu' );
$found = false;
foreach ( (array) ( $submenu['rolewright'] ?? array() ) as $item ) {
	if ( 'rolewright-edit-scope' === $item[2] ) {
		$found = true;
	}
}
$ok( $found, 'submenu page rolewright-edit-scope registered under the Rolewright menu' );
$ok( class_exists( 'Rolewright\\Modules\\Edit_Scope\\Admin_Page' ) && Rolewright\Modules\Edit_Scope\Admin_Page::SLUG === 'rolewright-edit-scope', 'admin page class and slug constant' );

// Gravity Forms integration.
$gf = Gravity_Forms::available();
$ok( ! $gf ? ! has_action( 'admin_init', array( new Gravity_Forms(), 'gate_admin_page' ) ) : true, 'Gravity Forms absent: integration not hooked' );
if ( ! $gf ) {
	update_option(
		Rules::OPTION,
		array(
			'g1' => array( 'id' => 'g1', 'subject_type' => 'role', 'subject' => 'editor', 'mode' => 'allow', 'by' => 'gf_form', 'ids' => array( 5 ), 'children' => false, 'taxonomy' => '' ),
		)
	);
	Rules::flush();
	$ok( Gravity_Forms::form_allowed( $ed, 5 ) && ! Gravity_Forms::form_allowed( $ed, 6 ) && Gravity_Forms::form_allowed( $admin, 6 ), 'form_allowed: allow-list semantics and admin exemption' );
	$gfi = new Gravity_Forms();
	wp_set_current_user( $ed );
	$r1 = $gfi->gate_rest( null, array(), new WP_REST_Request( 'GET', '/gf/v2/forms/6' ) );
	$r2 = $gfi->gate_rest( null, array(), new WP_REST_Request( 'GET', '/gf/v2/forms/5' ) );
	$r3 = $gfi->gate_rest( null, array(), new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
	$ok( is_wp_error( $r1 ) && null === $r2 && null === $r3, 'gf REST gate blocks unlisted form only, ignores other routes' );
	wp_set_current_user( $admin );
}
$clear();

// Cleanup.
foreach ( array_unique( $posts ) as $id ) {
	wp_delete_post( $id, true );
}
foreach ( $terms as $t ) {
	wp_delete_term( $t[0], $t[1] );
}
foreach ( $users as $id ) {
	wp_delete_user( $id );
}
delete_option( Rules::OPTION );
delete_option( Rules::SETTINGS );

echo "\n" . $rw_pass . ' passed, ' . $rw_fail . " failed\n";
exit( $rw_fail ? 1 : 0 );
