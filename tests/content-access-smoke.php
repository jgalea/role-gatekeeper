<?php
/**
 * Run: wp eval-file wp-content/plugins/role-gatekeeper/tests/content-access-smoke.php
 *
 * Front-end checks make real HTTP requests to the site. Inside wp-env the CLI container
 * reaches the web container as "wordpress", so set ROLEGATE_TEST_BASE (and optionally
 * ROLEGATE_TEST_HOST) when running somewhere else.
 */

use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Content_Access\Menu_Visibility;
use Rolegate\Modules\Content_Access\Post_Editor;
use Rolegate\Modules\Content_Access\Query_Guard;
use Rolegate\Modules\Content_Access\Visibility;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/post.php';

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

$base = getenv( 'ROLEGATE_TEST_BASE' ) ? getenv( 'ROLEGATE_TEST_BASE' ) : 'http://wordpress';
$host = getenv( 'ROLEGATE_TEST_HOST' ) ? getenv( 'ROLEGATE_TEST_HOST' ) : (string) wp_parse_url( home_url(), PHP_URL_HOST ) . ( wp_parse_url( home_url(), PHP_URL_PORT ) ? ':' . wp_parse_url( home_url(), PHP_URL_PORT ) : '' );

$sfx    = substr( md5( (string) microtime( true ) ), 0, 6 );
$role   = 'rw_t_member_' . $sfx;
$secret = 'Zq' . $sfx . 'Vault';
$msg    = 'Members only notice ' . $sfx;

add_role( $role, 'RW Test Member', array( 'read' => true ) );

$cpt      = 'rw_t_doc';
$cpt_base = 'rw-docs-' . $sfx;
register_post_type( $cpt, array( 'public' => true, 'show_in_rest' => true, 'rest_base' => $cpt_base, 'supports' => array( 'title', 'editor' ) ) );
register_block_type( 'rwtest/secret', array( 'render_callback' => function () { return '<p>SECRETBLOCK</p>'; } ) );

$users = array();
$mk    = function ( $login, $r ) use ( &$users, $sfx ) {
	$id = wp_insert_user(
		array(
			'user_login' => $login . '_' . $sfx,
			'user_email' => $login . '_' . $sfx . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => $r,
		)
	);
	$users[] = $id;
	return $id;
};
$u_right  = $mk( 'right', $role );
$u_wrong  = $mk( 'wrong', 'subscriber' );
$u_editor = $mk( 'editor', 'editor' );
$u_author = $mk( 'author', 'author' );
$admin_id = (int) get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) )[0];
$actors   = array(
	'logged-out' => 0,
	'wrong-role' => $u_wrong,
	'right-role' => $u_right,
);

wp_set_current_user( $admin_id );

$posts = array();
$mkp   = function ( $title, $content, $date, $excerpt = '' ) use ( &$posts, $admin_id ) {
	$id = wp_insert_post(
		array(
			'post_title'   => $title,
			'post_content' => $content,
			'post_excerpt' => $excerpt,
			'post_status'  => 'publish',
			'post_author'  => $admin_id,
			'post_date'    => $date,
		)
	);
	$posts[] = $id;
	return $id;
};
$p_old = $mkp( 'Public Older ' . $sfx, 'public older body', '2020-01-01 10:00:00' );
$p_sec = $mkp( 'Secret Title ' . $secret, 'Secret body ' . $secret . ' findme' . $sfx, '2020-01-02 10:00:00', 'Secret excerpt ' . $secret );
$p_new = $mkp( 'Public Newer ' . $sfx, 'public newer body', '2020-01-03 10:00:00' );

$att = wp_insert_attachment(
	array(
		'post_title'     => 'Secret attachment ' . $secret,
		'post_mime_type' => 'image/png',
		'post_status'    => 'inherit',
	),
	false,
	$p_sec
);
$posts[] = $att;

$d_sec = wp_insert_post( array( 'post_type' => $cpt, 'post_title' => 'Doc ' . $secret, 'post_content' => 'Doc body ' . $secret, 'post_status' => 'publish', 'post_author' => $admin_id ) );
$posts[] = $d_sec;

Access::save_rules( $p_sec, array( $role ), $msg );
Access::save_rules( $d_sec, array( $role ), $msg );

$rules = Access::rules( $p_sec );
$rw_ok( array( $role ) === $rules['roles'] && $msg === $rules['message'], 'rules saved and read back' );
$rw_ok( Access::is_restricted( $att ), 'attachment inherits the rule of its parent post' );

$permalink = function ( $id ) {
	return (string) wp_make_link_relative( get_permalink( $id ) );
};
$cookie = function ( $uid ) {
	if ( ! $uid ) {
		return array();
	}
	return array( LOGGED_IN_COOKIE => wp_generate_auth_cookie( $uid, time() + 3600, 'logged_in' ) );
};
$fetch  = function ( $path, $uid ) use ( $base, $host, $cookie ) {
	$headers = array( 'Host' => $host );
	$jar     = array();
	foreach ( $cookie( $uid ) as $k => $v ) {
		$jar[] = $k . '=' . $v;
	}
	if ( $jar ) {
		$headers['Cookie'] = implode( '; ', $jar );
	}
	$r = wp_remote_get(
		$base . $path,
		array(
			'headers'     => $headers,
			'redirection' => 5,
			'timeout'     => 30,
			'sslverify'   => false,
		)
	);
	if ( is_wp_error( $r ) ) {
		return array( 0, '', array(), $r->get_error_message() );
	}
	return array( (int) wp_remote_retrieve_response_code( $r ), (string) wp_remote_retrieve_body( $r ), wp_remote_retrieve_headers( $r ), '' );
};

$_SERVER['HTTP_HOST'] = $host;
list( $code ) = $fetch( $permalink( $p_new ), 0 );
$rw_ok( 200 === $code, 'HTTP loopback works (public post returns 200, got ' . $code . ')' );

foreach ( $actors as $who => $uid ) {
	$right = ( 'right-role' === $who );

	list( $code, $body, $headers ) = $fetch( $permalink( $p_sec ), $uid );
	$rw_ok( ( $right ? 200 : 403 ) === $code, "single view status for $who (got $code)" );
	$rw_ok( $right === ( false !== strpos( $body, 'Secret body ' . $secret ) ), "single view content shown only to right role ($who)" );
	if ( ! $right ) {
		$rw_ok( false === strpos( $body, $secret ), "single view leaks no title, content or excerpt for $who" );
		$rw_ok( false !== strpos( $body, $msg ), "single view shows the custom message for $who" );
		$rw_ok( ( 'logged-out' === $who ) === ( false !== strpos( $body, '>Log in</a>' ) ), "single view login link only for logged-out ($who)" );
	}
	$cc = strtolower( (string) ( $headers['cache-control'] ?? '' ) );
	$rw_ok( false !== strpos( $cc, 'no-cache' ) || false !== strpos( $cc, 'no-store' ), "protected page sent nocache headers for $who" );

	list( , $body ) = $fetch( '/', $uid );
	$rw_ok( false !== strpos( $body, 'Public Newer ' . $sfx ), "archive (home) lists public post for $who" );
	$rw_ok( $right === ( false !== strpos( $body, $secret ) ), "archive (home) shows protected post only to right role ($who)" );

	list( , $body ) = $fetch( (string) wp_make_link_relative( get_year_link( 2020 ) ), $uid );
	$rw_ok( $right === ( false !== strpos( $body, $secret ) ), "date archive shows protected post only to right role ($who)" );

	list( , $body ) = $fetch( '/?s=findme' . $sfx, $uid );
	$rw_ok( $right === ( false !== strpos( $body, 'Secret Title' ) ), "search shows protected post only to right role ($who)" );
	$rw_ok( $right || false === strpos( $body, $secret ), "search leaks nothing for $who" );

	list( $code, $body ) = $fetch( '/?feed=rss2', $uid );
	$rw_ok( 200 === $code && false !== strpos( $body, 'Public Newer ' . $sfx ), "feed works for $who" );
	$rw_ok( $right === ( false !== strpos( $body, $secret ) ), "feed includes protected post only for right role ($who)" );

	wp_set_current_user( $uid );
	$res  = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
	$json = wp_json_encode( $res->get_data() );
	$ids  = wp_list_pluck( (array) $res->get_data(), 'id' );
	$rw_ok( in_array( $p_new, $ids, true ), "REST list contains public post for $who" );
	$rw_ok( $right === in_array( $p_sec, $ids, true ), "REST list contains protected post only for right role ($who)" );
	$rw_ok( $right || false === strpos( $json, $secret ), "REST list leaks no title or excerpt for $who" );

	$req = new WP_REST_Request( 'GET', '/wp/v2/posts/' . $p_sec );
	$res = rest_do_request( $req );
	$rw_ok( ( $right ? 200 : 404 ) === $res->get_status(), "REST single status for $who (got " . $res->get_status() . ')' );
	$rw_ok( $right || false === strpos( wp_json_encode( $res->get_data() ), $secret ), "REST single leaks nothing for $who" );

	foreach ( array( '/WP/V2/POSTS/' . $p_sec, '/Wp/v2/Posts/' . $p_sec, '/wp/v2/' . $cpt_base . '/' . $d_sec, '/WP/V2/' . strtoupper( $cpt_base ) . '/' . $d_sec ) as $route ) {
		$res = rest_do_request( new WP_REST_Request( 'GET', $route ) );
		$rw_ok( ( $right ? 200 : 404 ) === $res->get_status() && ( $right || false === strpos( wp_json_encode( $res->get_data() ), $secret ) ), "REST $route status and no leak for $who (got " . $res->get_status() . ')' );
	}
	$req = new WP_REST_Request( 'GET', '/wp/v2/search' );
	$req->set_param( 'search', 'findme' . $sfx );
	$res  = rest_do_request( $req );
	$sids = wp_list_pluck( (array) $res->get_data(), 'id' );
	$rw_ok( $right === in_array( $p_sec, $sids, true ) && ( $right || false === strpos( wp_json_encode( $res->get_data() ), $secret ) ), "REST /wp/v2/search lists protected post only for right role ($who)" );
	$req = new WP_REST_Request( 'GET', '/wp/v2/search' );
	$req->set_param( 'search', 'Doc ' . $secret );
	$req->set_param( 'subtype', $cpt );
	$res = rest_do_request( $req );
	$rw_ok( $right || false === strpos( wp_json_encode( $res->get_data() ), $secret ), "REST /wp/v2/search on the custom post type leaks nothing for $who" );
	$req = new WP_REST_Request( 'GET', '/oembed/1.0/embed' );
	$req->set_param( 'url', get_permalink( $p_sec ) );
	$res = rest_do_request( $req );
	$rw_ok( $right === ( false !== strpos( wp_json_encode( $res->get_data() ), $secret ) ), "REST oEmbed shows the protected title only to right role ($who, got " . $res->get_status() . ')' );
	$rw_ok( ( $right ? $p_sec : 0 ) === (int) apply_filters( 'oembed_request_post_id', $p_sec, get_permalink( $p_sec ) ) && $right === is_array( get_oembed_response_data( $p_sec, 600 ) ), "oEmbed post id and response data refused for $who" );
	$rw_ok( $right === ( false !== strpos( get_the_title( $p_sec ), $secret ) ) && $right === ( false !== strpos( apply_filters( 'the_title', 'Secret Title ' . $secret, $p_sec ), $secret ) ), "the_title masked for $who" );
	$rw_ok( $right === ( false !== strpos( get_the_excerpt( $p_sec ), $secret ) ), "get_the_excerpt masked for $who" );
	$GLOBALS['wp_the_query'] = $GLOBALS['wp_query'] = new WP_Query(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride
	$GLOBALS['wp_query']->query( array( 'p' => $p_sec ) );
	$parts = apply_filters( 'document_title_parts', array( 'title' => 'Secret Title ' . $secret ) );
	$wpt   = apply_filters( 'wp_title', 'Secret Title ' . $secret, '|', 'right' );
	$rw_ok( $right === ( false !== strpos( $parts['title'], $secret ) ) && $right === ( false !== strpos( $wpt, $secret ) ), "document title and wp_title masked for $who" );
	$GLOBALS['wp_the_query'] = $GLOBALS['wp_query'] = new WP_Query(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride

	$res = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/media/' . $att ) );
	$rw_ok( ( $right ? 200 : 404 ) === $res->get_status(), "REST attachment of protected post status for $who (got " . $res->get_status() . ')' );

	$q = new WP_Query( array( 'post_type' => 'attachment', 'post_status' => 'inherit', 'fields' => 'ids' ) );
	$rw_ok( $right === in_array( $att, $q->posts, true ), "attachment query lists protected attachment only for right role ($who)" );

	$GLOBALS['post'] = get_post( $p_new ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride
	$prev            = get_adjacent_post( false, '', true );
	$rw_ok( $prev && ( $right ? $p_sec : $p_old ) === (int) $prev->ID, "adjacent-post link skips protected post for $who" );

	$sm = wp_remote_get( $base . '/wp-sitemap-posts-post-1.xml', array( 'headers' => array( 'Host' => $host ), 'redirection' => 5 ) );
	if ( 'logged-out' === $who ) {
		$xml = wp_remote_retrieve_body( $sm );
		$rw_ok( false !== strpos( $xml, get_permalink( $p_new ) ) && false === strpos( $xml, get_permalink( $p_sec ) ), 'sitemap lists the public post and omits the protected one' );
	}

	$sc = function ( $s ) {
		return trim( do_shortcode( $s ) );
	};
	$rw_ok( ( $right ? 'IN' : '' ) === $sc( '[rolegate_if roles="' . $role . ',nonexistent"]IN[/rolegate_if]' ), "[rolegate_if] for $who" );
	$rw_ok( ( $uid ? 'LI' : '' ) === $sc( '[rolegate_logged_in]LI[/rolegate_logged_in]' ), "[rolegate_logged_in] for $who" );
	$rw_ok( ( $uid ? '' : 'LO' ) === $sc( '[rolegate_logged_out]LO[/rolegate_logged_out]' ), "[rolegate_logged_out] for $who" );
	$form = $sc( '[rolegate_login_form]' );
	$rw_ok( $uid ? '' === $form : ( false !== strpos( $form, 'wp-login.php' ) && false !== strpos( $form, 'rolegate-login-form' ) ), "[rolegate_login_form] for $who" );

	$blocks = do_blocks(
		'<!-- wp:paragraph {"rolegateMode":"roles","rolegateRoles":["' . $role . '"]} --><p>BR</p><!-- /wp:paragraph -->' .
		'<!-- wp:paragraph {"rolegateMode":"logged_out"} --><p>BO</p><!-- /wp:paragraph -->' .
		'<!-- wp:paragraph {"rolegateMode":"logged_in"} --><p>BI</p><!-- /wp:paragraph -->' .
		'<!-- wp:paragraph --><p>BA</p><!-- /wp:paragraph -->'
	);
	$rw_ok( $right === ( false !== strpos( $blocks, 'BR' ) ), "block visibility by role for $who" );
	$rw_ok( ! $uid === ( false !== strpos( $blocks, 'BO' ) ), "block visibility logged-out for $who" );
	$rw_ok( (bool) $uid === ( false !== strpos( $blocks, 'BI' ) ), "block visibility logged-in for $who" );
	$rw_ok( false !== strpos( $blocks, 'BA' ), "block without rule always shown for $who" );

	$widget = new WP_Widget_Text();
	$shown  = apply_filters( 'widget_display_callback', array( 'rolegate_mode' => 'roles', 'rolegate_roles' => array( $role ) ), $widget, array() );
	$rw_ok( $right === is_array( $shown ), "classic widget visibility by role for $who" );
	$shown = apply_filters( 'widget_display_callback', array( 'title' => 'x' ), $widget, array() );
	$rw_ok( is_array( $shown ), "classic widget without rule shown for $who" );

	$menu_id = wp_create_nav_menu( 'rw-menu-' . $sfx . '-' . $who );
	$i_open  = wp_update_nav_menu_item( $menu_id, 0, array( 'menu-item-title' => 'Open', 'menu-item-url' => 'http://example.com/open', 'menu-item-status' => 'publish' ) );
	$i_role  = wp_update_nav_menu_item( $menu_id, 0, array( 'menu-item-title' => 'RoleOnly', 'menu-item-url' => 'http://example.com/r', 'menu-item-status' => 'publish' ) );
	$i_kid   = wp_update_nav_menu_item( $menu_id, 0, array( 'menu-item-title' => 'Child', 'menu-item-url' => 'http://example.com/k', 'menu-item-status' => 'publish', 'menu-item-parent-id' => $i_role ) );
	$i_post  = wp_update_nav_menu_item( $menu_id, 0, array( 'menu-item-title' => 'SecretLink', 'menu-item-object' => 'post', 'menu-item-object-id' => $p_sec, 'menu-item-type' => 'post_type', 'menu-item-status' => 'publish' ) );
	update_post_meta( $i_role, Menu_Visibility::META_MODE, 'roles' );
	update_post_meta( $i_role, Menu_Visibility::META_ROLES, array( $role ) );
	$titles = wp_list_pluck( (array) wp_get_nav_menu_items( $menu_id ), 'title' );
	$rw_ok( in_array( 'Open', $titles, true ), "menu item without rule shown for $who" );
	$rw_ok( $right === in_array( 'RoleOnly', $titles, true ), "menu item role rule for $who" );
	$rw_ok( $right === in_array( 'Child', $titles, true ), "menu child follows hidden parent for $who" );
	$rw_ok( $right === in_array( 'SecretLink', $titles, true ), "menu item pointing at protected post hidden for $who" );
	wp_delete_nav_menu( $menu_id );
	wp_set_current_user( $admin_id );
}

list( $code, $body ) = $fetch( '/wp-json/oembed/1.0/embed?url=' . rawurlencode( get_permalink( $p_sec ) ), 0 );
$rw_ok( 404 === $code && false === strpos( $body, $secret ), 'HTTP oEmbed endpoint gives a logged-out visitor 404 and no title (got ' . $code . ')' );
list( $code, $body ) = $fetch( '/wp-json/oembed/1.0/embed?url=' . rawurlencode( get_permalink( $p_new ) ), 0 );
$rw_ok( 200 === $code && false !== strpos( $body, 'Public Newer' ), 'HTTP oEmbed still works for a public post (got ' . $code . ')' );
$head = ! method_exists( Query_Guard::class, 'scrub_head' ) ? 'no scrub ' . $secret : Query_Guard::scrub_head( '<title>x</title><meta property="og:title" content="Secret Title ' . $secret . '" /><meta name="description" content="d" /><meta name="twitter:title" content="t" /><script type="application/ld+json">{"headline":"Secret Title ' . $secret . '"}</script><link rel="x" title="Secret Title ' . $secret . '">', array( 'Secret Title ' . $secret ) );
$rw_ok( false === strpos( $head, $secret ) && false === strpos( $head, 'og:title' ) && false === strpos( $head, 'ld+json' ) && false !== strpos( $head, '<title>x</title>' ), 'head scrub removes Open Graph, description, JSON-LD and title copies' );

// Block renderer preview and saved visibility attributes.
$p_edp = wp_insert_post( array( 'post_title' => 'editor own', 'post_status' => 'draft', 'post_author' => $u_editor ) );
$p_aup = wp_insert_post( array( 'post_title' => 'author own', 'post_status' => 'draft', 'post_author' => $u_author ) );
$pat   = wp_insert_post( array( 'post_type' => 'wp_block', 'post_title' => 'pattern ' . $sfx, 'post_status' => 'publish', 'post_content' => '<!-- wp:paragraph {"rolegateMode":"roles","rolegateRoles":["administrator"]} --><p>PATTERNSECRET</p><!-- /wp:paragraph -->' ) );
array_push( $posts, $p_edp, $p_aup, $pat );
$render = function ( $name, $post_id, $attrs ) {
	$r = new WP_REST_Request( 'GET', '/wp/v2/block-renderer/' . $name );
	$r->set_query_params( array( 'post_id' => $post_id, 'context' => 'edit', 'attributes' => $attrs ) );
	$res = rest_do_request( $r );
	return array( $res->get_status(), wp_json_encode( $res->get_data() ) );
};
$hide = array( 'rolegateMode' => 'roles', 'rolegateRoles' => array( 'administrator' ) );
wp_set_current_user( $u_editor );
list( $code, $json ) = $render( 'rwtest/secret', $p_edp, $hide );
$rw_ok( 200 === $code && false !== strpos( $json, 'SECRETBLOCK' ), 'editor preview shows the block being edited despite its role rule (got ' . $code . ')' );
list( $code, $json ) = $render( 'core/block', $p_edp, array( 'ref' => $pat ) );
$rw_ok( 200 === $code && false === strpos( $json, 'PATTERNSECRET' ), 'editor preview still hides nested blocks the viewer may not see (got ' . $code . ')' );
$rw_ok( method_exists( Visibility::class, 'preview_active' ) && ! Visibility::preview_active(), 'preview flag cleared when the request ends' );
wp_set_current_user( $u_author );
list( $code, $json ) = $render( 'rwtest/secret', $p_edp, $hide );
$rw_ok( 200 !== $code && false === strpos( $json, 'SECRETBLOCK' ), 'author cannot render hidden block content for a post they cannot edit (got ' . $code . ')' );
$sticky = do_blocks( '<!-- wp:paragraph {"rolegateMode":"roles","rolegateRoles":["administrator"]} --><p>STICKY</p><!-- /wp:paragraph -->' );
$rw_ok( false === strpos( $sticky, 'STICKY' ), 'block filtering applies again after a block-renderer request' );
list( $code, $json ) = $render( 'rwtest/secret', $p_aup, $hide );
$rw_ok( 200 === $code && false !== strpos( $json, 'SECRETBLOCK' ), 'author preview of a block in their own post still works (got ' . $code . ')' );

$hidden_block = '<!-- wp:paragraph {"rolegateMode":"roles","rolegateRoles":["administrator"]} --><p>KEEP</p><!-- /wp:paragraph -->';
wp_set_current_user( $u_editor );
$sp = wp_insert_post( array( 'post_title' => 'attr save', 'post_status' => 'draft', 'post_content' => $hidden_block ) );
$posts[] = $sp;
$rw_ok( false === strpos( get_post( $sp )->post_content, 'rolegateMode' ) && false !== strpos( get_post( $sp )->post_content, 'KEEP' ), 'visibility attributes stripped when a user without the access capability saves them' );
$r = new WP_REST_Request( 'POST', '/wp/v2/posts' );
$r->set_body_params( array( 'title' => 'rest attr', 'status' => 'draft', 'content' => $hidden_block ) );
$res = rest_do_request( $r );
$rid = (int) ( $res->get_data()['id'] ?? 0 );
$posts[] = $rid;
$rw_ok( $rid && false === strpos( get_post( $rid )->post_content, 'rolegateMode' ), 'visibility attributes stripped on a REST save by a user without the access capability (status ' . $res->get_status() . ' ' . ( $res->is_error() ? $res->get_data()['code'] : get_post( $rid )->post_content ) . ')' );
wp_set_current_user( $admin_id );
$kp = wp_insert_post( array( 'post_title' => 'attr keep', 'post_status' => 'draft', 'post_author' => $u_editor, 'post_content' => $hidden_block ) );
$posts[] = $kp;
$rw_ok( false !== strpos( get_post( $kp )->post_content, 'rolegateMode' ), 'a user with the access capability can set visibility attributes' );
wp_set_current_user( $u_editor );
wp_update_post( array( 'ID' => $kp, 'post_content' => '<!-- wp:paragraph --><p>new intro</p><!-- /wp:paragraph -->' . str_replace( 'KEEP', 'KEEP edited', $hidden_block ) . '<!-- wp:paragraph {"rolegateMode":"logged_in"} --><p>ADDED</p><!-- /wp:paragraph -->' ) );
$kc = get_post( $kp )->post_content;
$rw_ok( false !== strpos( $kc, '"rolegateRoles":["administrator"]} --><p>KEEP edited' ) && false === strpos( $kc, '"logged_in"' ) && false !== strpos( $kc, 'ADDED' ), 'existing visibility attributes preserved, new ones stripped, on an edit by a user without the capability' );
wp_set_current_user( $admin_id );

wp_set_current_user( $u_editor );
list( $code, $body ) = array( 0, '' );
$rw_ok( Access::can_view( $p_sec ), 'a user who can edit the post still views it' );
wp_set_current_user( $admin_id );

$events = array();
add_action(
	'rolegate_changed',
	function ( $type, $data ) use ( &$events ) {
		$events[] = array( $type, $data );
	},
	10,
	2
);

$res = rest_do_request( ( function () use ( $p_new, $role ) {
	$r = new WP_REST_Request( 'POST', '/wp/v2/posts/' . $p_new );
	$r->set_body_params( array( 'meta' => array( '_rolegate_roles' => array( $role, 'not_a_role' ), '_rolegate_message' => 'Hi <script>alert(1)</script><b>x</b>' ) ) );
	return $r;
} )() );
$after_rest = Access::rules( $p_new );
$rw_ok( 200 === $res->get_status() && array( $role ) === $after_rest['roles'], 'block-editor save (REST meta) stores rules and drops unknown roles (status ' . $res->get_status() . ')' );
$rw_ok( false === strpos( $after_rest['message'], '<script' ), 'message is stripped of script tags on save' );
$rw_ok( 1 === count( $events ) && 'access.updated' === $events[0][0] && $p_new === $events[0][1]['target'] && array() === $events[0][1]['before']['roles'] && array( $role ) === $events[0][1]['after']['roles'] && $admin_id === $events[0][1]['actor'], 'rolegate_changed access.updated fired once for the REST save with before and after' );
$rw_ok( false === strpos( Access::notice_html( $p_new ), '<script' ), 'denied notice html is escaped' );

$events = array();
$_POST  = array(
	'_rolegate_access_nonce' => wp_create_nonce( Post_Editor::NONCE ),
	'rolegate_roles'         => array(),
	'rolegate_message'       => '',
);
( new Post_Editor() )->save_meta_box( $p_new, get_post( $p_new ) );
$_POST = array();
$rw_ok( ! Access::is_restricted( $p_new ) && 1 === count( $events ) && array( $role ) === $events[0][1]['before']['roles'], 'classic meta box save clears rules and fires access.updated with before' );

$events = array();
$_POST  = array( 'rolegate_roles' => array( $role ) );
( new Post_Editor() )->save_meta_box( $p_new, get_post( $p_new ) );
$_POST = array();
$rw_ok( ! Access::is_restricted( $p_new ) && ! $events, 'classic save without a nonce changes nothing' );

wp_set_current_user( $u_editor );
$res = rest_do_request( ( function () use ( $p_new, $role ) {
	$r = new WP_REST_Request( 'POST', '/wp/v2/posts/' . $p_new );
	$r->set_body_params( array( 'meta' => array( '_rolegate_roles' => array( $role ) ) ) );
	return $r;
} )() );
$rw_ok( ! Access::is_restricted( $p_new ), 'a user without the access capability cannot set rules over REST (status ' . $res->get_status() . ')' );
$_POST = array( '_rolegate_access_nonce' => wp_create_nonce( Post_Editor::NONCE ), 'rolegate_roles' => array( $role ), 'rolegate_message' => '' );
( new Post_Editor() )->save_meta_box( $p_new, get_post( $p_new ) );
$_POST = array();
$rw_ok( ! Access::is_restricted( $p_new ), 'a user without the access capability cannot set rules from the meta box' );
wp_set_current_user( $admin_id );

$events = array();
$_POST  = array( 'rolegate_menu' => array( 999001 => array( 'nonce' => 'bad', 'mode' => 'logged_in' ) ) );
( new Menu_Visibility() )->save( 1, 999001 );
$_POST = array();
$rw_ok( ! $events && '' === (string) get_post_meta( 999001, Menu_Visibility::META_MODE, true ), 'menu item save refuses a bad nonce' );

// Cleanup.
foreach ( array_reverse( $posts ) as $pid ) {
	wp_delete_post( $pid, true );
}
foreach ( $users as $uid ) {
	is_multisite() ? wpmu_delete_user( $uid ) : wp_delete_user( $uid );
}
remove_role( $role );
unregister_block_type( 'rwtest/secret' );

echo "\nPASS: $rw_pass FAIL: $rw_fail\n";
exit( $rw_fail ? 1 : 0 );
