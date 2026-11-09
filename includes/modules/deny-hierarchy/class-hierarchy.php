<?php
namespace Rolewright\Modules\Deny_Hierarchy;

use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Role positions (0-99, Administrator fixed at 100). A user's position is the highest
 * position among their roles. Below the top, a user can't edit, delete or assign roles at
 * or above their own position, can't act on users at or above it, can't change their own
 * roles, and doesn't see users of higher roles in the Users list or REST.
 */
final class Hierarchy {
	const OPTION       = 'rolewright_role_positions';
	const TOP          = 100;
	const MAX_EDITABLE = 99;

	/** @var array<string,int>|null */
	private static $positions = null;

	public static function register(): void {
		add_filter( 'rolewright_can_assign_role', array( __CLASS__, 'filter_can_assign_role' ), 10, 4 );
		add_filter( 'rolewright_can_act_on_user', array( __CLASS__, 'filter_can_act_on_user' ), 10, 3 );
		add_action( 'pre_get_users', array( __CLASS__, 'hide_users_in_list' ) );
		add_filter( 'rest_user_query', array( __CLASS__, 'hide_users_in_rest' ), 10, 2 );
		add_filter( 'views_users', array( __CLASS__, 'filter_user_views' ) );
		foreach ( array( 'add_option_', 'update_option_', 'delete_option_' ) as $hook ) {
			add_action( $hook . self::OPTION, array( __CLASS__, 'reset_cache' ) );
		}
		add_action( 'add_role', array( __CLASS__, 'reset_cache' ) );
		add_action( 'remove_role', array( __CLASS__, 'reset_cache' ) );
	}

	public static function reset_cache(): void {
		self::$positions = null;
	}

	/** @return array<string,int> stored positions only */
	public static function stored(): array {
		$raw = get_option( self::OPTION, array() );
		$out = array();
		if ( is_array( $raw ) ) {
			foreach ( $raw as $role => $pos ) {
				if ( 'administrator' !== $role && is_numeric( $pos ) ) {
					$out[ (string) $role ] = max( 0, min( self::MAX_EDITABLE, (int) $pos ) );
				}
			}
		}
		return $out;
	}

	/**
	 * Position for a role with nothing stored: ten times its highest legacy user level, so
	 * core roles rank Editor 70, Author 20, Contributor 10, Subscriber 0. A role that
	 * manages users ranks at least 90, so turning the module on doesn't stop an existing
	 * user-manager role from assigning the roles it could assign before.
	 */
	public static function default_position( string $role ): int {
		if ( 'administrator' === $role ) {
			return self::TOP;
		}
		$obj = get_role( $role );
		return $obj ? self::default_position_for_caps( (array) $obj->capabilities ) : 0;
	}

	/**
	 * Position a role with these caps would get when nothing is stored for it.
	 *
	 * @param array $caps list or map
	 */
	public static function default_position_for_caps( array $caps ): int {
		$pos = 0;
		foreach ( Guard::normalize_caps( $caps ) as $cap => $grant ) {
			if ( ! $grant ) {
				continue;
			}
			if ( preg_match( '/^level_(\d+)$/', (string) $cap, $m ) ) {
				$pos = max( $pos, (int) $m[1] * 10 );
			} elseif ( in_array( $cap, array( 'promote_users', 'edit_users', 'create_users', 'delete_users' ), true ) ) {
				$pos = max( $pos, 90 );
			}
		}
		return min( self::MAX_EDITABLE, $pos );
	}

	/** @return array<string,int> every existing role => position */
	public static function positions(): array {
		if ( null === self::$positions ) {
			$stored = self::stored();
			$out    = array();
			foreach ( array_keys( wp_roles()->roles ) as $role ) {
				$role = (string) $role;
				if ( 'administrator' === $role ) {
					$out[ $role ] = self::TOP;
				} else {
					$out[ $role ] = isset( $stored[ $role ] ) ? $stored[ $role ] : self::default_position( $role );
				}
			}
			arsort( $out );
			self::$positions = $out;
		}
		return self::$positions;
	}

	public static function role_position( string $role ): int {
		$all = self::positions();
		return isset( $all[ $role ] ) ? $all[ $role ] : -1;
	}

	/** Highest position among the user's roles; -1 with no role, TOP for a super admin. */
	public static function user_position( int $user_id ): int {
		if ( Guard::is_super( $user_id ) ) {
			return self::TOP;
		}
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user ) {
			return -1;
		}
		$pos = -1;
		foreach ( (array) $user->roles as $role ) {
			$pos = max( $pos, self::role_position( (string) $role ) );
		}
		return $pos;
	}

	public static function is_top( int $user_id ): bool {
		return self::user_position( $user_id ) >= self::TOP;
	}

	public static function can_manage_role( int $actor_id, string $role ): bool {
		if ( self::is_top( $actor_id ) ) {
			return true;
		}
		return self::role_position( $role ) < self::user_position( $actor_id );
	}

	/**
	 * For modules that edit, delete or rename roles: refuses a role at or above the
	 * actor's position.
	 *
	 * @return true|\WP_Error
	 */
	public static function assert_can_manage_role( int $actor_id, string $role ) {
		if ( self::can_manage_role( $actor_id, $role ) ) {
			return true;
		}
		return new \WP_Error(
			'rolewright_role_above_position',
			__( 'That role is at or above your own position in the role hierarchy.', 'rolewright' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Position $role would sit at with $new_caps: its stored position if one is set,
	 * otherwise the default for those caps.
	 *
	 * @param array $new_caps list or map
	 */
	public static function projected_position( string $role, array $new_caps ): int {
		if ( 'administrator' === $role ) {
			return self::TOP;
		}
		$stored = self::stored();
		return isset( $stored[ $role ] ) ? $stored[ $role ] : self::default_position_for_caps( $new_caps );
	}

	/**
	 * Refuses a create or cap change that would leave the role at or above the actor.
	 *
	 * @param array $new_caps list or map
	 * @return true|\WP_Error
	 */
	public static function assert_can_place_role( int $actor_id, string $role, array $new_caps ) {
		if ( self::is_top( $actor_id ) || self::projected_position( $role, $new_caps ) < self::user_position( $actor_id ) ) {
			return true;
		}
		return new \WP_Error(
			'rolewright_role_above_position',
			__( 'That change would put the role at or above your own position in the role hierarchy.', 'rolewright' ),
			array( 'status' => 403 )
		);
	}

	public static function can_act_on_user( int $actor_id, int $target_id ): bool {
		if ( $actor_id === $target_id || self::is_top( $actor_id ) ) {
			return true;
		}
		return self::user_position( $target_id ) < self::user_position( $actor_id );
	}

	/**
	 * Roles strictly above the user's position, whose users are hidden from them.
	 *
	 * @return string[]
	 */
	public static function hidden_roles_for( int $user_id ): array {
		if ( $user_id <= 0 || self::is_top( $user_id ) ) {
			return array();
		}
		$mine = self::user_position( $user_id );
		$out  = array();
		foreach ( self::positions() as $role => $pos ) {
			if ( $pos > $mine ) {
				$out[] = $role;
			}
		}
		return $out;
	}

	/**
	 * @param bool   $allowed
	 * @param int    $actor_id
	 * @param string $role
	 * @param int    $target_id
	 * @return bool
	 */
	public static function filter_can_assign_role( $allowed, $actor_id, $role, $target_id ) {
		$actor_id  = (int) $actor_id;
		$target_id = (int) $target_id;
		if ( ! $allowed || $actor_id <= 0 || self::is_top( $actor_id ) ) {
			return $allowed;
		}
		if ( $target_id > 0 && $target_id === $actor_id ) {
			$user = get_userdata( $actor_id );
			return $user && in_array( (string) $role, (array) $user->roles, true );
		}
		if ( ! self::can_manage_role( $actor_id, (string) $role ) ) {
			return false;
		}
		return $target_id > 0 ? self::can_act_on_user( $actor_id, $target_id ) : true;
	}

	/**
	 * @param bool $allowed
	 * @param int  $actor_id
	 * @param int  $target_id
	 * @return bool
	 */
	public static function filter_can_act_on_user( $allowed, $actor_id, $target_id ) {
		if ( ! $allowed || (int) $actor_id <= 0 ) {
			return $allowed;
		}
		return self::can_act_on_user( (int) $actor_id, (int) $target_id );
	}

	/**
	 * @param \WP_User_Query $query
	 */
	public static function hide_users_in_list( $query ): void {
		global $pagenow;
		if ( ! is_admin() || wp_doing_ajax() || 'users.php' !== $pagenow || ! $query instanceof \WP_User_Query ) {
			return;
		}
		$hidden = self::hidden_roles_for( get_current_user_id() );
		if ( $hidden ) {
			$current = (array) $query->get( 'role__not_in' );
			$query->set( 'role__not_in', array_values( array_unique( array_merge( $current, $hidden ) ) ) );
		}
	}

	/**
	 * @param array            $args
	 * @param \WP_REST_Request $request
	 * @return array
	 */
	public static function hide_users_in_rest( $args, $request ) {
		$hidden = self::hidden_roles_for( get_current_user_id() );
		if ( $hidden && is_array( $args ) ) {
			$current              = isset( $args['role__not_in'] ) ? (array) $args['role__not_in'] : array();
			$args['role__not_in'] = array_values( array_unique( array_merge( $current, $hidden ) ) );
		}
		return $args;
	}

	/**
	 * @param array<string,string> $views
	 * @return array<string,string>
	 */
	public static function filter_user_views( $views ) {
		$hidden = self::hidden_roles_for( get_current_user_id() );
		if ( ! $hidden || ! is_array( $views ) ) {
			return $views;
		}
		foreach ( $hidden as $role ) {
			unset( $views[ $role ] );
		}
		if ( isset( $views['all'] ) ) {
			$total        = ( new \WP_User_Query(
				array(
					'role__not_in' => $hidden,
					'fields'       => 'ID',
					'number'       => 1,
					'count_total'  => true,
				)
			) )->get_total();
			$views['all'] = preg_replace( '/\(\d[\d,.\s]*\)/', '(' . number_format_i18n( $total ) . ')', $views['all'], 1 );
		}
		return $views;
	}

	/**
	 * Replaces positions for the given roles. Below the top, the actor can only move roles
	 * that sit below them, and only to positions below their own.
	 *
	 * @param array<string,mixed> $changes role => position
	 * @return true|\WP_Error
	 */
	public static function save_positions( int $actor_id, array $changes ) {
		$stored = self::stored();
		$after  = $stored;
		$mine   = self::user_position( $actor_id );
		$top    = self::is_top( $actor_id );
		foreach ( $changes as $role => $pos ) {
			$role = (string) $role;
			if ( ! get_role( $role ) ) {
				return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
			}
			if ( ! is_numeric( $pos ) || (int) $pos != $pos ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual -- accepts "5" and 5, refuses "5.5".
				return new \WP_Error( 'rolewright_bad_position', __( 'Positions must be whole numbers.', 'rolewright' ) );
			}
			$pos = (int) $pos;
			if ( 'administrator' === $role ) {
				if ( self::TOP !== $pos ) {
					return new \WP_Error( 'rolewright_protected_role', __( 'The Administrator role always sits at the top of the hierarchy.', 'rolewright' ) );
				}
				continue;
			}
			if ( $pos < 0 || $pos > self::MAX_EDITABLE ) {
				/* translators: %d: highest allowed position */
				return new \WP_Error( 'rolewright_bad_position', sprintf( __( 'Positions run from 0 to %d.', 'rolewright' ), self::MAX_EDITABLE ) );
			}
			if ( $pos === self::role_position( $role ) ) {
				continue;
			}
			if ( ! $top && ( self::role_position( $role ) >= $mine || $pos >= $mine ) ) {
				return new \WP_Error(
					'rolewright_role_above_position',
					__( 'You can only move roles below your own position, and only to positions below it.', 'rolewright' ),
					array( 'status' => 403 )
				);
			}
			$after[ $role ] = $pos;
		}
		if ( $after === $stored ) {
			return true;
		}
		ksort( $after );
		update_option( self::OPTION, $after, true );
		self::reset_cache();
		do_action(
			'rolewright_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => 'role_positions',
				'rule'   => 'hierarchy',
				'before' => array( 'positions' => $stored ),
				'after'  => array( 'positions' => $after ),
			)
		);
		return true;
	}
}
