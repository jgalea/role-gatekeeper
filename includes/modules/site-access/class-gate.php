<?php
namespace Rolegate\Modules\Site_Access;

defined( 'ABSPATH' ) || exit;

/**
 * Private-site mode. Front-end requests go through template_redirect, REST through
 * rest_authentication_errors (after core's cookie check) and rest_pre_dispatch. Scripts that never reach those hooks (wp-login.php, wp-cron.php,
 * admin-ajax.php, xmlrpc.php) are untouched; decide() also exempts them so a custom front-end
 * login page, the rescue route and password reset can't be caught by mistake.
 */
final class Gate {
	const ALLOW = 'allow';
	const LOGIN = 'login';
	const DENY  = 'deny';

	const EXEMPT_SCRIPTS = array( 'wp-login.php', 'wp-cron.php', 'admin-ajax.php', 'admin-post.php', 'xmlrpc.php', 'wp-signup.php', 'wp-activate.php' );

	public function register(): void {
		add_action( 'template_redirect', array( $this, 'on_template_redirect' ), 0 );
		add_filter( 'request', array( __CLASS__, 'remember_request_vars' ), PHP_INT_MIN );
		add_filter( 'rest_authentication_errors', array( $this, 'on_rest_auth' ), 101 );
		add_filter( 'rest_pre_dispatch', array( $this, 'on_rest_pre_dispatch' ), 10, 3 );
	}

	/** @var array|null Query vars as WordPress parsed them, before other plugins filter them. */
	private static $request_vars = null;

	/**
	 * @param array $vars
	 * @return array
	 */
	public static function remember_request_vars( $vars ) {
		self::$request_vars = is_array( $vars ) ? $vars : array();
		return $vars;
	}

	/** Vars that only page through or flag the same resolved object. */
	const NEUTRAL_QUERY_VARS = array( 'paged', 'page', 'cpage', 'error' );

	/**
	 * Public query vars the rewrite rule alone produces for a request, with the same
	 * post-type and taxonomy handling WP::parse_request() applies.
	 *
	 * @param string   $matched_query Query string of the matched rewrite rule, empty when none matched.
	 * @param string[] $public_vars
	 */
	public static function rewrite_query_vars( string $matched_query, array $public_vars ): array {
		$perma = array();
		if ( '' !== $matched_query ) {
			parse_str( $matched_query, $perma );
		}
		$post_type_vars = array();
		foreach ( get_post_types( array(), 'objects' ) as $type => $obj ) {
			if ( is_post_type_viewable( $obj ) && $obj->query_var ) {
				$post_type_vars[ $obj->query_var ] = $type;
			}
		}
		$out = array();
		foreach ( $public_vars as $var ) {
			if ( ! isset( $perma[ $var ] ) ) {
				continue;
			}
			$out[ $var ] = is_array( $perma[ $var ] ) ? $perma[ $var ] : (string) $perma[ $var ];
			if ( '' !== $out[ $var ] && isset( $post_type_vars[ $var ] ) ) {
				$out['post_type'] = $post_type_vars[ $var ];
				$out['name']      = $out[ $var ];
			}
		}
		foreach ( get_taxonomies( array(), 'objects' ) as $tax ) {
			if ( $tax->query_var && isset( $out[ $tax->query_var ] ) && is_string( $out[ $tax->query_var ] ) ) {
				$out[ $tax->query_var ] = str_replace( ' ', '+', $out[ $tax->query_var ] );
			}
		}
		if ( isset( $out['post_type'] ) && ! is_array( $out['post_type'] ) && ! in_array( $out['post_type'], get_post_types( array( 'publicly_queryable' => true ) ), true ) ) {
			unset( $out['post_type'] );
		}
		return function_exists( 'wp_resolve_numeric_slug_conflicts' ) ? wp_resolve_numeric_slug_conflicts( $out ) : $out;
	}

	/**
	 * True when the resolved query vars point somewhere other than the rewrite of the path,
	 * which only happens when they came from the query string or the POST body.
	 *
	 * @param array $resolved Query vars after parsing.
	 * @param array $expected Output of rewrite_query_vars().
	 */
	public static function query_vars_differ( array $resolved, array $expected ): bool {
		foreach ( array_unique( array_merge( array_keys( $resolved ), array_keys( $expected ) ) ) as $key ) {
			if ( in_array( $key, self::NEUTRAL_QUERY_VARS, true ) ) {
				continue;
			}
			$a = $resolved[ $key ] ?? '';
			$b = $expected[ $key ] ?? '';
			if ( is_array( $a ) || is_array( $b ) ) {
				if ( (array) $a != (array) $b ) { // phpcs:ignore Universal.Operators.StrictComparisons
					return true;
				}
				continue;
			}
			if ( (string) $a !== (string) $b ) {
				return true;
			}
		}
		return false;
	}

	public static function resolved_query_differs(): bool {
		$wp = $GLOBALS['wp'] ?? null;
		if ( ! $wp instanceof \WP ) {
			return false;
		}
		$public   = (array) $wp->public_query_vars;
		$resolved = null !== self::$request_vars ? self::$request_vars : (array) $wp->query_vars;
		$resolved = array_intersect_key( $resolved, array_flip( $public ) );
		$expected = self::rewrite_query_vars( (string) $wp->matched_query, $public );
		return self::query_vars_differ( $resolved, $expected );
	}

	/**
	 * @param string $path Request path relative to the site root, as returned by normalize_path().
	 */
	public static function path_allowed( string $path, array $allow_paths ): bool {
		foreach ( $allow_paths as $entry ) {
			$entry = (string) $entry;
			if ( '' === $entry ) {
				continue;
			}
			if ( '*' === substr( $entry, -1 ) ) {
				$base = rtrim( substr( $entry, 0, -1 ), '/' );
				if ( '' !== $base && ( $path === $base || 0 === strpos( $path, $base . '/' ) ) ) {
					return true;
				}
			} elseif ( $path === $entry ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Lowercased, decoded, slash-collapsed path with a leading slash and no trailing one.
	 * Null when it holds a dot segment or control characters, so it never matches anything.
	 */
	public static function normalize_path( string $path ): ?string {
		$path = rawurldecode( $path );
		if ( preg_match( '/[\x00-\x1f\x7f\\\\]/', $path ) ) {
			return null;
		}
		$segments = array();
		foreach ( explode( '/', $path ) as $segment ) {
			if ( '' === $segment ) {
				continue;
			}
			if ( '.' === $segment || '..' === $segment ) {
				return null;
			}
			$segments[] = strtolower( $segment );
		}
		return '/' . implode( '/', $segments );
	}

	/** Request path relative to the site's own path, or null when it can't be trusted. */
	public static function current_path(): ?string {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return self::relative_path( $path );
	}

	public static function relative_path( string $path ): ?string {
		$norm = self::normalize_path( $path );
		if ( null === $norm ) {
			return null;
		}
		$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$home = self::normalize_path( $home );
		if ( null !== $home && '/' !== $home ) {
			if ( $norm === $home ) {
				$norm = '/';
			} elseif ( 0 === strpos( $norm, $home . '/' ) ) {
				$norm = substr( $norm, strlen( $home ) );
			}
		}
		if ( 0 === strpos( $norm, '/index.php' ) ) {
			$rest = substr( $norm, strlen( '/index.php' ) );
			$norm = '' === $rest ? '/' : $rest;
		}
		return $norm;
	}

	private static function query_vars_present( array $query_keys ): bool {
		$public = isset( $GLOBALS['wp']->public_query_vars ) ? (array) $GLOBALS['wp']->public_query_vars : array( 'p', 'page_id', 'name', 'pagename', 'attachment_id', 'cat', 'tag', 's', 'author', 'm', 'post_type', 'feed', 'preview', 'page', 'paged', 'error', 'static', 'rest_route' );
		return (bool) array_intersect( $query_keys, array_merge( $public, array( 'rest_route' ) ) );
	}

	/**
	 * @param array $req {
	 *     @type string|null $path       Normalized request path, null when untrusted.
	 *     @type bool        $logged_in
	 *     @type bool        $member     Logged-in user may use this site (multisite membership).
	 *     @type bool        $is_feed
	 *     @type bool        $is_rest
	 *     @type string      $script     Basename of the PHP entry point, if known.
	 *     @type string      $login_path Normalized path of the login page.
	 *     @type string[]    $query_keys Keys present in the query string or the POST body.
	 *     @type bool        $query_mismatch The parsed query vars differ from what the path's rewrite resolves to.
	 *     @type bool        $xmlrpc_on
	 * }
	 */
	public static function decide( array $req, array $settings ): string {
		if ( empty( $settings['private_enabled'] ) ) {
			return self::ALLOW;
		}
		$script = isset( $req['script'] ) ? (string) $req['script'] : '';
		if ( in_array( $script, self::EXEMPT_SCRIPTS, true ) && ( 'xmlrpc.php' !== $script || ! empty( $req['xmlrpc_on'] ) ) ) {
			return self::ALLOW;
		}
		$path = isset( $req['path'] ) ? $req['path'] : null;
		if ( ! empty( $req['logged_in'] ) ) {
			return ( ! isset( $req['member'] ) || $req['member'] ) ? self::ALLOW : self::DENY;
		}
		if ( ! empty( $req['is_feed'] ) && empty( $settings['private_feed'] ) ) {
			return self::ALLOW;
		}
		if ( ! empty( $req['is_rest'] ) && empty( $settings['private_rest'] ) ) {
			return self::ALLOW;
		}
		if ( null !== $path ) {
			if ( ! empty( $req['login_path'] ) && $path === $req['login_path'] ) {
				return self::ALLOW;
			}
			$exempt = isset( $req['exempt_paths'] ) ? (array) $req['exempt_paths'] : array();
			$list   = array_merge( (array) $settings['allow_paths'], $exempt );
			if ( self::path_allowed( $path, $list ) && empty( $req['query_mismatch'] ) && ! self::query_vars_present( isset( $req['query_keys'] ) ? (array) $req['query_keys'] : array() ) ) {
				return self::ALLOW;
			}
		}
		return ( ! empty( $req['is_feed'] ) || ! empty( $req['is_rest'] ) ) ? self::DENY : self::LOGIN;
	}

	public static function login_path(): ?string {
		$path = (string) wp_parse_url( wp_login_url(), PHP_URL_PATH );
		return self::relative_path( $path );
	}

	private static function context( bool $is_rest ): array {
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$user   = wp_get_current_user();
		$in     = $user->exists();
		$member = true;
		if ( $in && is_multisite() && ! is_super_admin( $user->ID ) ) {
			$member = is_user_member_of_blog( $user->ID, get_current_blog_id() );
		}
		return array(
			'path'           => self::current_path(),
			'logged_in'      => $in,
			'member'         => $member,
			'is_feed'        => ! $is_rest && function_exists( 'is_feed' ) && is_feed(),
			'is_rest'        => $is_rest,
			'script'         => $script,
			'login_path'     => self::login_path(),
			'query_keys'     => array_values( array_unique( array_merge( array_map( 'strval', array_keys( $_GET ) ), array_map( 'strval', array_keys( $_POST ) ) ) ) ), // phpcs:ignore WordPress.Security.NonceVerification
			'query_mismatch' => ! $is_rest && self::resolved_query_differs(),
			'xmlrpc_on'      => (bool) apply_filters( 'xmlrpc_enabled', true ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, read to learn whether XML-RPC is on.
			'exempt_paths'   => array_filter( array_map( array( __CLASS__, 'normalize_path' ), (array) apply_filters( 'rolegate_site_access_exempt_paths', array() ) ) ),
		);
	}

	public function on_template_redirect(): void {
		$settings = Site_Access_Settings::get();
		if ( empty( $settings['private_enabled'] ) ) {
			return;
		}
		$req = self::context( false );
		if ( apply_filters( 'rolegate_site_access_is_login_request', false, $req ) ) {
			return;
		}
		$decision = self::decide( $req, $settings );
		if ( self::ALLOW === $decision ) {
			return;
		}
		nocache_headers();
		if ( self::LOGIN === $decision ) {
			$origin = (string) wp_parse_url( home_url( '/' ), PHP_URL_SCHEME ) . '://' . (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
			$port   = wp_parse_url( home_url( '/' ), PHP_URL_PORT );
			$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$back   = $origin . ( $port ? ':' . $port : '' ) . $uri;
			wp_safe_redirect( wp_login_url( $back ), 302, 'Role Gatekeeper' );
			exit;
		}
		wp_die( esc_html__( 'You need to be logged in to see this site.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
	}

	/**
	 * Runs after core's cookie check (priority 100), which drops a cookie-authenticated user
	 * without a valid REST nonce back to anonymous, so is_user_logged_in() is the final identity.
	 *
	 * @param mixed $result
	 * @return mixed
	 */
	public function on_rest_auth( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? (string) $GLOBALS['wp']->query_vars['rest_route'] : '';
		$error = self::rest_refusal( $route );
		return $error ? $error : $result;
	}

	/**
	 * Re-checks every dispatched REST request, including embedded and batched ones, once
	 * authentication has finished.
	 *
	 * @param mixed            $result
	 * @param \WP_REST_Server  $server
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function on_rest_pre_dispatch( $result, $server, $request ) {
		if ( null !== $result || ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		$error = self::rest_refusal( (string) $request->get_route() );
		return $error ? $error : $result;
	}

	private static function rest_refusal( string $route ): ?\WP_Error {
		$settings = Site_Access_Settings::get();
		if ( empty( $settings['private_enabled'] ) || empty( $settings['private_rest'] ) ) {
			return null;
		}
		$req                 = self::context( true );
		$req['path']         = self::normalize_path( '/' . rest_get_url_prefix() . '/' . ltrim( $route, '/' ) );
		$req['query_keys']   = array();
		$req['exempt_paths'] = array_filter( array_map( array( __CLASS__, 'normalize_path' ), (array) apply_filters( 'rolegate_site_access_exempt_rest_routes', array() ) ) );
		if ( self::ALLOW === self::decide( $req, $settings ) ) {
			return null;
		}
		return new \WP_Error( 'rolegate_private_site', __( 'You need to be logged in to use this site.', 'role-gatekeeper' ), array( 'status' => 401 ) );
	}

	/** Used by the settings page to mention what the gate won't touch. */
	public static function exempt_summary(): array {
		return array(
			'wp-login.php (login, password reset, the Role Gatekeeper rescue link)',
			'wp-cron.php',
			'admin-ajax.php and admin-post.php',
			'xmlrpc.php when XML-RPC is enabled',
			'logged-in REST requests, including application passwords',
		);
	}
}
