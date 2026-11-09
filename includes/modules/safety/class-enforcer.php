<?php
namespace Rolewright\Modules\Safety;

defined( 'ABSPATH' ) || exit;

/**
 * Applies Guard where WordPress itself assigns roles and caps, so the rules hold for
 * wp-admin forms, bulk actions, REST, other modules and other plugins alike.
 *
 * Interactive paths (dropdowns, profile save, REST) get the full rule set. The storage
 * backstops (user caps meta and the roles option) only block critical-cap escalation and
 * administrator damage, so ordinary plugin role assignments keep working.
 */
final class Enforcer {
	/** @var int */
	private static $system = 0;

	/** @var array<int,bool> */
	private static $blocked_users = array();

	public function register(): void {
		add_filter( 'editable_roles', array( $this, 'editable_roles' ), PHP_INT_MAX );
		add_filter( 'map_meta_cap', array( $this, 'map_meta_cap' ), PHP_INT_MAX, 4 );
		add_action( 'user_profile_update_errors', array( $this, 'profile_errors' ), PHP_INT_MAX, 3 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'rest_guard' ), PHP_INT_MAX, 3 );
		add_filter( 'update_user_metadata', array( $this, 'user_meta_guard' ), PHP_INT_MAX, 4 );
		add_filter( 'add_user_metadata', array( $this, 'user_meta_guard' ), PHP_INT_MAX, 4 );
		add_action( 'user_register', array( $this, 'after_register' ), PHP_INT_MAX );
		add_filter( 'pre_update_option', array( $this, 'roles_option_guard' ), PHP_INT_MAX, 3 );
		add_filter( 'pre_update_option_default_role', array( $this, 'default_role_guard' ), PHP_INT_MAX, 2 );
	}

	/**
	 * Runs $fn with the storage backstops off. For the plugin's own maintenance (cap
	 * self-heal, rescue), never for anything a user requested.
	 *
	 * @param callable $fn
	 * @return mixed
	 */
	public static function as_system( callable $fn ) {
		++self::$system;
		try {
			return $fn();
		} finally {
			--self::$system;
		}
	}

	private static function actor(): int {
		if ( self::$system > 0 || ! function_exists( 'get_current_user_id' ) || ( ! did_action( 'set_current_user' ) && ! did_action( 'init' ) ) ) {
			return 0;
		}
		return (int) get_current_user_id();
	}

	/**
	 * The user whose role the current request is changing, when it is the actor
	 * (own profile, own row in a bulk change). Used to apply the self-assignment rule
	 * to the role dropdowns.
	 */
	private function request_targets_self( int $actor ): bool {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only context detection; the saving code checks nonces.
		if ( defined( 'IS_PROFILE_PAGE' ) && IS_PROFILE_PAGE ) {
			return true;
		}
		if ( isset( $_REQUEST['user_id'] ) && (int) $_REQUEST['user_id'] === $actor ) {
			return true;
		}
		if ( isset( $_REQUEST['users'] ) && is_array( $_REQUEST['users'] ) && in_array( $actor, array_map( 'intval', wp_unslash( $_REQUEST['users'] ) ), true ) ) {
			return true;
		}
		// phpcs:enable
		return false;
	}

	/**
	 * @param array $roles
	 * @return array
	 */
	public function editable_roles( $roles ) {
		$actor = self::actor();
		if ( ! $actor || ! is_array( $roles ) || Guard::is_super( $actor ) ) {
			return $roles;
		}
		$target = $this->request_targets_self( $actor ) ? $actor : 0;
		foreach ( array_keys( $roles ) as $role ) {
			if ( ! Guard::can_assign_role( $actor, (string) $role, $target ) ) {
				unset( $roles[ $role ] );
			}
		}
		return $roles;
	}

	/**
	 * @param string[] $caps
	 * @param string   $cap
	 * @param int      $user_id
	 * @param array    $args
	 * @return string[]
	 */
	public function map_meta_cap( $caps, $cap, $user_id, $args ) {
		if ( ! in_array( $cap, array( 'promote_user', 'edit_user', 'delete_user', 'remove_user' ), true ) || empty( $args[0] ) ) {
			return $caps;
		}
		$target = (int) $args[0];
		if ( $target !== (int) $user_id && ! Guard::can_act_on_user( (int) $user_id, $target ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	/**
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param \stdClass $user
	 */
	public function profile_errors( $errors, $update, $user ): void {
		$actor = self::actor();
		if ( ! $actor || empty( $user->role ) ) {
			return;
		}
		$target = ( $update && ! empty( $user->ID ) ) ? (int) $user->ID : 0;
		if ( ! Guard::can_assign_role( $actor, (string) $user->role, $target ) ) {
			$errors->add( 'rolewright_role_not_allowed', __( 'You can\'t give that role: it carries capabilities you don\'t hold.', 'rolewright' ) );
		}
	}

	/**
	 * @param mixed            $response
	 * @param array            $handler
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function rest_guard( $response, $handler, $request ) {
		if ( is_wp_error( $response ) || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}
		if ( ! preg_match( '#^/+wp/v2/users(?:/+(\d+|me))?/*$#i', $request->get_route(), $m ) || 'GET' === $request->get_method() ) {
			return $response;
		}
		$actor = self::actor();
		if ( ! $actor || Guard::is_super( $actor ) ) {
			return $response;
		}
		$target = 0;
		if ( isset( $m[1] ) ) {
			$target = 'me' === strtolower( $m[1] ) ? $actor : (int) $m[1];
		}
		if ( $target && 'DELETE' !== $request->get_method() && ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolewright_user_above_actor', __( 'You can\'t edit a user who holds capabilities you don\'t have.', 'rolewright' ), array( 'status' => 403 ) );
		}
		$roles = $request->get_param( 'roles' );
		if ( null === $roles ) {
			return $response;
		}
		foreach ( (array) $roles as $role ) {
			if ( ! Guard::can_assign_role( $actor, (string) $role, $target ) ) {
				return new \WP_Error( 'rolewright_role_not_allowed', __( 'You can\'t give that role: it carries capabilities you don\'t hold.', 'rolewright' ), array( 'status' => 403 ) );
			}
		}
		return $response;
	}

	/**
	 * Backstop on the user capabilities meta: no request by a logged-in user may give
	 * anyone a critical cap that user does not hold, or change a user who holds critical
	 * caps the actor lacks.
	 *
	 * @param null|bool $check
	 * @param int       $object_id
	 * @param string    $meta_key
	 * @param mixed     $meta_value
	 * @return null|bool
	 */
	public function user_meta_guard( $check, $object_id, $meta_key, $meta_value ) {
		global $wpdb;
		if ( null !== $check ) {
			return $check;
		}
		$prefix = $wpdb->get_blog_prefix();
		if ( $prefix . 'user_level' === $meta_key ) {
			return isset( self::$blocked_users[ (int) $object_id ] ) ? false : $check;
		}
		if ( $prefix . 'capabilities' !== $meta_key ) {
			return $check;
		}
		$actor = self::actor();
		if ( ! $actor || Guard::is_super( $actor ) || ! apply_filters( 'rolewright_storage_backstop', true, 'user', $object_id ) ) {
			return $check;
		}
		$target = (int) $object_id;
		$old    = get_user_meta( $target, $meta_key, true );
		$old    = is_array( $old ) ? $old : array();
		$new    = is_array( $meta_value ) ? $meta_value : array();

		$roles_caps = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles_caps[ $name ] = (array) $data['capabilities'];
		}
		$expand = function ( array $meta ) use ( $roles_caps ) {
			$meta  = Guard::normalize_caps( $meta );
			$roles = array_keys( array_filter( array_intersect_key( $meta, $roles_caps ) ) );
			return Guard::critical_subset( Guard::caps_from_roles( $roles, $roles_caps, $meta ) );
		};
		$before = $expand( $old );
		$after  = $expand( $new );

		$actor_critical = $actor === $target ? $before : Guard::user_critical_caps( $actor );
		$gained         = array_diff( $after, $before );
		$blocked        = (bool) Guard::missing( $gained, $actor_critical );
		if ( ! $blocked && $actor !== $target && Guard::missing( $before, $actor_critical ) && Guard::normalize_caps( $old ) !== Guard::normalize_caps( $new ) ) {
			$blocked = true;
		}
		if ( ! $blocked ) {
			return $check;
		}
		self::$blocked_users[ $target ] = true;
		do_action( 'rolewright_escalation_blocked', 'user', $actor, $target, array_values( $gained ) );
		return false;
	}

	/**
	 * A new user created in a logged-in request must not end up above the actor, whatever
	 * set the role.
	 */
	public function after_register( $user_id ): void {
		$actor = self::actor();
		if ( ! $actor || Guard::is_super( $actor ) || (int) $user_id === $actor ) {
			return;
		}
		$extra = Guard::missing( Guard::user_critical_caps( (int) $user_id ), Guard::user_critical_caps( $actor ) );
		if ( ! $extra ) {
			return;
		}
		$user = get_userdata( (int) $user_id );
		if ( $user ) {
			self::as_system(
				function () use ( $user ) {
					$user->set_role( '' );
				}
			);
			do_action( 'rolewright_escalation_blocked', 'new_user', $actor, (int) $user_id, $extra );
		}
	}

	/**
	 * The role new registrations get is a role assignment. A logged-in non-super-admin may only
	 * pick a role they could assign themselves.
	 *
	 * @param mixed $value
	 * @param mixed $old
	 * @return mixed
	 */
	public function default_role_guard( $value, $old ) {
		$actor = self::actor();
		if ( ! $actor || Guard::is_super( $actor ) || self::$system > 0 || $value === $old ) {
			return $value;
		}
		if ( ! Guard::can_assign_role( $actor, (string) $value, 0 ) ) {
			do_action( 'rolewright_escalation_blocked', 'default_role', $actor, 0, array( (string) $value ) );
			return $old;
		}
		return $value;
	}

	/**
	 * Backstop on the roles option: no logged-in non-super-admin request may give a role
	 * a critical cap the actor lacks, and nobody may strip the administrator role of its
	 * critical caps or delete it.
	 *
	 * @param mixed  $value
	 * @param string $option
	 * @param mixed  $old
	 * @return mixed
	 */
	public function roles_option_guard( $value, $option, $old ) {
		global $wpdb;
		if ( $wpdb->get_blog_prefix() . 'user_roles' !== $option || self::$system > 0 || ! is_array( $value ) || ! is_array( $old ) ) {
			return $value;
		}
		if ( ! apply_filters( 'rolewright_storage_backstop', true, 'roles', 0 ) ) {
			return $value;
		}
		$caps_of = function ( array $roles, string $name ) {
			return isset( $roles[ $name ]['capabilities'] ) && is_array( $roles[ $name ]['capabilities'] ) ? $roles[ $name ]['capabilities'] : array();
		};

		$reason = '';
		$detail = array();
		if ( isset( $old['administrator'] ) ) {
			$lost = Guard::missing( Guard::critical_subset( $caps_of( $old, 'administrator' ) ), $caps_of( $value, 'administrator' ) );
			if ( ! isset( $value['administrator'] ) || $lost ) {
				$reason = 'administrator';
				$detail = $lost;
			}
		}

		$actor = self::actor();
		if ( ! $reason && $actor && ! Guard::is_super( $actor ) ) {
			$user = get_userdata( $actor );
			if ( $user ) {
				$old_caps = array();
				foreach ( $old as $name => $data ) {
					$old_caps[ $name ] = $caps_of( $old, (string) $name );
				}
				$user_caps = (array) $user->caps;
				$actor_now = Guard::critical_subset( Guard::caps_from_roles( (array) $user->roles, $old_caps, $user_caps ) );
				if ( in_array( 'administrator', (array) $user->roles, true ) ) {
					$actor_now = array_values( array_unique( array_merge( $actor_now, Guard::critical_subset( $caps_of( $old, 'administrator' ) ) ) ) );
				}
				foreach ( $value as $name => $data ) {
					$gained = array_diff( Guard::critical_subset( $caps_of( $value, (string) $name ) ), Guard::critical_subset( $caps_of( $old, (string) $name ) ) );
					$missing = Guard::missing( $gained, $actor_now );
					if ( $missing ) {
						$reason = 'escalation';
						$detail = array_merge( $detail, $missing );
					}
				}
			}
		}

		if ( ! $reason ) {
			return $value;
		}
		do_action( 'rolewright_escalation_blocked', 'roles', $actor, $reason, array_values( array_unique( $detail ) ) );
		return $old;
	}
}
