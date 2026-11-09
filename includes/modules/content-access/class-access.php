<?php
namespace Rolegate\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

final class Access {
	const META_ROLES   = '_rolegate_roles';
	const META_MESSAGE = '_rolegate_message';

	/** @var array<int,array> */
	private static $snapshots = array();

	/** @var array<int,array<int,int[]>>|null */
	private static $protected = null;

	/** @var array<int,int[]> */
	private static $hidden = array();

	public static function register(): void {
		add_action( 'added_post_meta', array( __CLASS__, 'flush' ) );
		add_action( 'updated_post_meta', array( __CLASS__, 'flush' ) );
		add_action( 'deleted_post_meta', array( __CLASS__, 'flush' ) );
		add_action( 'deleted_post', array( __CLASS__, 'flush' ) );
		add_action( 'set_current_user', array( __CLASS__, 'flush' ) );
		add_filter( 'update_post_metadata', array( __CLASS__, 'capture' ), 1, 3 );
		add_filter( 'add_post_metadata', array( __CLASS__, 'capture' ), 1, 3 );
		add_filter( 'delete_post_metadata', array( __CLASS__, 'capture' ), 1, 3 );
		add_action( 'shutdown', array( __CLASS__, 'fire_pending' ) );
	}

	public static function flush(): void {
		self::$protected = null;
		self::$hidden    = array();
	}

	/** @return string[] */
	public static function allowed_roles(): array {
		return array_keys( wp_roles()->roles );
	}

	/** @param mixed $value */
	public static function sanitize_roles( $value ): array {
		if ( is_string( $value ) ) {
			$value = explode( ',', $value );
		}
		if ( ! is_array( $value ) ) {
			return array();
		}
		$known = self::allowed_roles();
		$out   = array();
		foreach ( $value as $role ) {
			$role = is_scalar( $role ) ? sanitize_key( (string) $role ) : '';
			if ( '' !== $role && in_array( $role, $known, true ) ) {
				$out[ $role ] = $role;
			}
		}
		return array_values( $out );
	}

	/** @param mixed $value */
	public static function sanitize_message( $value ): string {
		return wp_kses( is_scalar( $value ) ? (string) $value : '', self::message_tags() );
	}

	public static function message_tags(): array {
		return array(
			'a'      => array(
				'href'  => true,
				'title' => true,
			),
			'strong' => array(),
			'em'     => array(),
			'br'     => array(),
			'p'      => array(),
		);
	}

	/** @return array{roles:string[],message:string,source:int} */
	public static function rules( int $post_id ): array {
		$source = $post_id;
		$post   = get_post( $post_id );
		if ( $post && 'attachment' === $post->post_type && $post->post_parent ) {
			$source = (int) $post->post_parent;
		}
		$roles   = get_post_meta( $source, self::META_ROLES, true );
		$message = get_post_meta( $source, self::META_MESSAGE, true );
		return array(
			'roles'   => is_array( $roles ) ? self::sanitize_roles( $roles ) : array(),
			'message' => is_string( $message ) ? $message : '',
			'source'  => $source,
		);
	}

	public static function is_restricted( int $post_id ): bool {
		return (bool) self::rules( $post_id )['roles'];
	}

	public static function can_view( int $post_id ): bool {
		$rules = self::rules( $post_id );
		if ( ! $rules['roles'] ) {
			return true;
		}
		$allowed = current_user_can( 'edit_post', $post_id );
		if ( ! $allowed ) {
			foreach ( $rules['roles'] as $role ) {
				if ( current_user_can( $role ) ) {
					$allowed = true;
					break;
				}
			}
		}
		return (bool) apply_filters( 'rolegate_can_view_post', $allowed, $post_id, wp_get_current_user() );
	}

	public static function is_denied( int $post_id ): bool {
		return $post_id > 0 && ! self::can_view( $post_id );
	}

	/** Visibility rule shared by blocks, widgets and menu items. */
	public static function matches( string $mode, array $roles ): bool {
		switch ( $mode ) {
			case 'logged_in':
				$ok = is_user_logged_in();
				break;
			case 'logged_out':
				$ok = ! is_user_logged_in();
				break;
			case 'roles':
				$ok = false;
				if ( is_user_logged_in() ) {
					foreach ( self::sanitize_roles( $roles ) as $role ) {
						if ( current_user_can( $role ) ) {
							$ok = true;
							break;
						}
					}
				}
				break;
			default:
				return true;
		}
		if ( is_user_logged_in() ) {
			self::mark_uncacheable();
		}
		return $ok;
	}

	public static function sanitize_mode( $mode ): string {
		$mode = is_scalar( $mode ) ? (string) $mode : '';
		return in_array( $mode, array( 'logged_in', 'logged_out', 'roles' ), true ) ? $mode : 'all';
	}

	public static function mark_uncacheable(): void {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- the constant caching plugins look for.
		}
		if ( ! headers_sent() ) {
			nocache_headers();
		}
	}

	/** @return array<int,int[]> post id => roles, for every post carrying a rule */
	public static function protected_map(): array {
		if ( null !== self::$protected ) {
			return self::$protected;
		}
		global $wpdb;
		self::$protected = array();
		$rows            = $wpdb->get_results( $wpdb->prepare( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = %s", self::META_ROLES ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		foreach ( (array) $rows as $row ) {
			$roles = maybe_unserialize( $row->meta_value );
			if ( is_array( $roles ) && $roles ) {
				self::$protected[ (int) $row->post_id ] = $roles;
			}
		}
		return self::$protected;
	}

	/** @return int[] ids the current user may not view, attachments of those posts included */
	public static function hidden_ids(): array {
		$uid = get_current_user_id();
		if ( isset( self::$hidden[ $uid ] ) ) {
			return self::$hidden[ $uid ];
		}
		$hidden = array();
		foreach ( array_keys( self::protected_map() ) as $id ) {
			if ( ! self::can_view( $id ) ) {
				$hidden[] = $id;
			}
		}
		if ( $hidden ) {
			global $wpdb;
			$marks  = implode( ',', array_fill( 0, count( $hidden ), '%d' ) );
			$kids   = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_parent IN ($marks)", $hidden ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders
			$hidden = array_merge( $hidden, array_map( 'intval', (array) $kids ) );
		}
		self::$hidden[ $uid ] = array_values( array_unique( $hidden ) );
		return self::$hidden[ $uid ];
	}

	public static function notice_html( int $post_id ): string {
		$rules   = self::rules( $post_id );
		$message = '' !== trim( $rules['message'] ) ? $rules['message'] : Content_Settings::default_message();
		if ( '' !== trim( $message ) ) {
			$html = wpautop( self::sanitize_message( $message ) );
		} else {
			$html = '<p>' . esc_html__( "You don't have permission to view this content.", 'role-gatekeeper' ) . '</p>';
		}
		if ( ! is_user_logged_in() ) {
			$html .= '<p><a href="' . esc_url( wp_login_url( (string) get_permalink( $post_id ) ) ) . '">' . esc_html__( 'Log in', 'role-gatekeeper' ) . '</a></p>';
		}
		return (string) apply_filters( 'rolegate_denied_message_html', $html, $post_id );
	}

	/**
	 * Writes both meta values; the change event is fired from here once the writes are done.
	 *
	 * @param string[] $roles
	 */
	public static function save_rules( int $post_id, array $roles, string $message ): void {
		$roles   = self::sanitize_roles( $roles );
		$message = self::sanitize_message( $message );
		if ( $roles ) {
			update_post_meta( $post_id, self::META_ROLES, $roles );
		} else {
			delete_post_meta( $post_id, self::META_ROLES );
		}
		if ( '' !== trim( $message ) ) {
			update_post_meta( $post_id, self::META_MESSAGE, $message );
		} else {
			delete_post_meta( $post_id, self::META_MESSAGE );
		}
		self::fire_if_changed( $post_id );
	}

	/** @param mixed $check */
	public static function capture( $check, $object_id, $meta_key ) {
		$object_id = (int) $object_id;
		if ( ( self::META_ROLES === $meta_key || self::META_MESSAGE === $meta_key ) && ! isset( self::$snapshots[ $object_id ] ) ) {
			self::$snapshots[ $object_id ] = self::current_state( $object_id );
		}
		return $check;
	}

	private static function current_state( int $post_id ): array {
		$roles   = get_post_meta( $post_id, self::META_ROLES, true );
		$message = get_post_meta( $post_id, self::META_MESSAGE, true );
		return array(
			'roles'   => is_array( $roles ) ? array_values( $roles ) : array(),
			'message' => is_string( $message ) ? $message : '',
		);
	}

	public static function fire_if_changed( int $post_id ): void {
		if ( ! isset( self::$snapshots[ $post_id ] ) ) {
			return;
		}
		$before = self::$snapshots[ $post_id ];
		unset( self::$snapshots[ $post_id ] );
		$after = self::current_state( $post_id );
		if ( $before === $after ) {
			return;
		}
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => get_current_user_id(),
				'target' => $post_id,
				'scope'  => 'post',
				'before' => $before,
				'after'  => $after,
			)
		);
	}

	public static function fire_pending(): void {
		foreach ( array_keys( self::$snapshots ) as $post_id ) {
			self::fire_if_changed( (int) $post_id );
		}
	}

	public static function fire_scoped( string $scope, string $target, array $before, array $after ): void {
		if ( $before === $after ) {
			return;
		}
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => get_current_user_id(),
				'target' => $target,
				'scope'  => $scope,
				'before' => $before,
				'after'  => $after,
			)
		);
	}
}
