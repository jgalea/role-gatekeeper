<?php
namespace Rolegate\Modules\Deny_Hierarchy;

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Per-role denied capabilities. A deny on any of a user's roles removes the cap from that
 * user, whatever their other roles or per-user caps grant. Stored as role => cap list in
 * the rolegate_denied_caps option.
 */
final class Denials {
	const OPTION = 'rolegate_denied_caps';

	/** @var array<string,string[]>|null */
	private static $map = null;

	/** @var array<string,array<string,string[]>> */
	private static $user_cache = array();

	public static function register(): void {
		add_filter( 'user_has_cap', array( __CLASS__, 'filter_user_has_cap' ), PHP_INT_MAX - 1, 4 );
		add_filter( 'rolegate_guard_user_caps', array( __CLASS__, 'filter_guard_caps' ), 10, 2 );
		foreach ( array( 'add_option_', 'update_option_', 'delete_option_' ) as $hook ) {
			add_action( $hook . self::OPTION, array( __CLASS__, 'reset_cache' ) );
		}
	}

	public static function reset_cache(): void {
		self::$map        = null;
		self::$user_cache = array();
	}

	/**
	 * @return array<string,string[]> role => denied caps
	 */
	public static function map(): array {
		if ( null === self::$map ) {
			$raw = get_option( self::OPTION, array() );
			$map = array();
			if ( is_array( $raw ) ) {
				foreach ( $raw as $role => $caps ) {
					if ( is_array( $caps ) && $caps ) {
						$map[ (string) $role ] = array_values( array_unique( array_map( 'strval', $caps ) ) );
					}
				}
			}
			self::$map = $map;
		}
		return self::$map;
	}

	/** @return string[] */
	public static function for_role( string $role ): array {
		$map = self::map();
		return isset( $map[ $role ] ) ? $map[ $role ] : array();
	}

	/**
	 * Denials that apply to the user, after protections: administrators always keep the
	 * plugin's own caps.
	 *
	 * @return array<string,string[]> cap => roles that deny it
	 */
	public static function for_user( \WP_User $user ): array {
		$map = self::map();
		if ( ! $map || ! $user->ID ) {
			return array();
		}
		$roles = array_values( array_filter( (array) $user->roles, 'is_string' ) );
		$key   = $user->ID . '|' . implode( ',', $roles );
		if ( isset( self::$user_cache[ $key ] ) ) {
			return self::$user_cache[ $key ];
		}
		$admin  = in_array( 'administrator', $roles, true );
		$denied = array();
		foreach ( $roles as $role ) {
			if ( empty( $map[ $role ] ) ) {
				continue;
			}
			foreach ( $map[ $role ] as $cap ) {
				if ( $admin && ( 'read' === $cap || Guard::is_critical_cap( $cap ) || in_array( $cap, Caps::all(), true ) ) ) {
					continue;
				}
				$denied[ $cap ][] = $role;
			}
		}
		self::$user_cache[ $key ] = $denied;
		return $denied;
	}

	/**
	 * @param array<string,bool> $allcaps
	 * @param string[]           $caps
	 * @param array              $args
	 * @param \WP_User           $user
	 * @return array<string,bool>
	 */
	public static function filter_user_has_cap( $allcaps, $caps, $args, $user ) {
		if ( ! $user instanceof \WP_User || ! is_array( $allcaps ) ) {
			return $allcaps;
		}
		foreach ( self::for_user( $user ) as $cap => $roles ) {
			$allcaps[ $cap ] = false;
		}
		return $allcaps;
	}

	/**
	 * Lets the safety Guard see effective caps, so escalation and lockout checks treat a
	 * denied cap as not held.
	 *
	 * @param array<string,bool> $caps
	 * @param \WP_User           $user
	 * @return array<string,bool>
	 */
	public static function filter_guard_caps( $caps, $user ) {
		if ( ! is_array( $caps ) || ! $user instanceof \WP_User ) {
			return $caps;
		}
		foreach ( self::for_user( $user ) as $cap => $roles ) {
			unset( $caps[ $cap ] );
		}
		return $caps;
	}

	/**
	 * A denial the plugin refuses to store whoever asks: the administrator role keeps
	 * read, its critical caps and the plugin's own caps.
	 */
	public static function is_protected( string $role, string $cap ): bool {
		return 'administrator' === $role && ( 'read' === $cap || Guard::is_critical_cap( $cap ) );
	}

	/**
	 * Lockout reasons if the denial map became $map_after. Adds deny-wins on top of
	 * Guard's per-role check: a deny on any of the actor's roles counts.
	 *
	 * @param array<string,string[]> $map_after
	 * @return string[]
	 */
	public static function lockout_reasons_for( int $actor_id, array $map_after ): array {
		$user = $actor_id > 0 ? get_userdata( $actor_id ) : false;
		if ( ! $user || Guard::is_super( $actor_id ) ) {
			return array();
		}
		$roles_after = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$caps = Guard::normalize_caps( (array) $data['capabilities'] );
			foreach ( isset( $map_after[ $name ] ) ? $map_after[ $name ] : array() as $cap ) {
				$caps[ $cap ] = false;
			}
			$roles_after[ $name ] = $caps;
		}
		$reasons = Guard::would_lock_out( $actor_id, $roles_after ) ? Guard::lockout_reasons_for( $actor_id, $roles_after ) : array();

		$own   = array();
		$admin = in_array( 'administrator', (array) $user->roles, true );
		foreach ( (array) $user->roles as $role ) {
			foreach ( isset( $map_after[ $role ] ) ? $map_after[ $role ] : array() as $cap ) {
				$own[ $cap ] = true;
			}
		}
		if ( isset( $own['read'] ) ) {
			$reasons[] = 'read';
		}
		if ( isset( $own[ Caps::MANAGE ] ) && ! $admin ) {
			$reasons[] = 'manage';
		}
		return array_values( array_unique( $reasons ) );
	}

	/**
	 * Checks replacing $role's denial list with $denied. Callers still check
	 * Caps::MANAGE_ACCESS and a nonce.
	 *
	 * @param string[] $denied
	 * @return string[]|\WP_Error the clean list, or why it was refused
	 */
	public static function validate( int $actor_id, string $role, array $denied ) {
		if ( ! get_role( $role ) ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ) );
		}
		$shell = self::is_shell( $actor_id );
		if ( ! $shell ) {
			$allowed = Hierarchy::assert_can_manage_role( $actor_id, $role );
			if ( is_wp_error( $allowed ) ) {
				return $allowed;
			}
		}
		$super = Guard::is_super( $actor_id ) || $shell;
		if ( ! $super ) {
			$above = Guard::missing( Guard::critical_subset( (array) get_role( $role )->capabilities ), Guard::user_caps( $actor_id ) );
			if ( $above ) {
				return new \WP_Error(
					'rolegate_role_above_actor',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'You can\'t change denials on this role because it holds capabilities you don\'t have: %s.', 'role-gatekeeper' ), implode( ', ', $above ) )
				);
			}
		}

		if ( ! $super ) {
			$page = 1;
			do {
				$holders = get_users(
					array(
						'role'   => $role,
						'fields' => 'ID',
						'number' => 500,
						'paged'  => $page++,
					)
				);
				foreach ( $holders as $holder_id ) {
					if ( (int) $holder_id !== $actor_id && ! Guard::can_act_on_user( $actor_id, (int) $holder_id ) ) {
						return new \WP_Error( 'rolegate_holder_above_actor', __( 'You can\'t change denials on this role because some users who hold it have more capabilities than you.', 'role-gatekeeper' ) );
					}
				}
			} while ( 500 === count( $holders ) );
		}

		$clean   = array();
		$invalid = array();
		foreach ( $denied as $cap ) {
			$cap = is_string( $cap ) ? $cap : '';
			if ( Guard::cap_exists( $cap ) ) {
				$clean[] = $cap;
				continue;
			}
			$name = Guard::sanitize_cap_name( $cap );
			if ( false === $name ) {
				$invalid[] = $cap;
			} else {
				$clean[] = $name;
			}
		}
		if ( $invalid ) {
			return new \WP_Error(
				'rolegate_invalid_cap',
				/* translators: %s: comma-separated capability names */
				sprintf( __( 'These capability names are not valid: %s.', 'role-gatekeeper' ), implode( ', ', array_map( 'sanitize_text_field', $invalid ) ) )
			);
		}
		$clean = array_values( array_unique( $clean ) );
		sort( $clean );

		if ( ! $super ) {
			$unheld = array();
			foreach ( array_diff( $clean, self::for_role( $role ) ) as $cap ) {
				if ( Guard::is_critical_cap( $cap ) && ! Guard::can_grant_cap( $actor_id, $cap ) ) {
					$unheld[] = $cap;
				}
			}
			if ( $unheld ) {
				return new \WP_Error(
					'rolegate_role_above_actor',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'You can\'t deny these capabilities because you don\'t hold them yourself: %s.', 'role-gatekeeper' ), implode( ', ', $unheld ) )
				);
			}
		}

		$protected = array();
		foreach ( $clean as $cap ) {
			if ( self::is_protected( $role, $cap ) ) {
				$protected[] = $cap;
			}
		}
		if ( $protected ) {
			return new \WP_Error(
				'rolegate_protected_role',
				/* translators: %s: comma-separated capability names */
				sprintf( __( 'The Administrator role can\'t be denied these capabilities: %s.', 'role-gatekeeper' ), implode( ', ', $protected ) )
			);
		}

		$actor = get_userdata( $actor_id );
		if ( $actor && in_array( 'read', $clean, true ) && in_array( $role, (array) $actor->roles, true ) ) {
			return new \WP_Error( 'rolegate_lockout', __( 'You can\'t deny the read capability on your own role.', 'role-gatekeeper' ), array( 'reasons' => array( 'read' ) ) );
		}

		if ( ! $super ) {
			$not_allowed = array();
			foreach ( array_diff( self::for_role( $role ), $clean ) as $cap ) {
				if ( ! Guard::can_grant_cap( $actor_id, $cap ) ) {
					$not_allowed[] = $cap;
				}
			}
			if ( $not_allowed ) {
				return new \WP_Error(
					'rolegate_cap_not_held',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'Lifting a denial grants the capability back, and you don\'t hold these yourself: %s.', 'role-gatekeeper' ), implode( ', ', $not_allowed ) )
				);
			}
		}

		$after          = self::map();
		$after[ $role ] = $clean;
		$reasons        = $shell ? self::manager_reasons( $after ) : self::lockout_reasons_for( $actor_id, $after );
		if ( $reasons ) {
			return new \WP_Error(
				'rolegate_lockout',
				/* translators: %s: reason codes */
				sprintf( __( 'These denials would lock you out (%s).', 'role-gatekeeper' ), implode( ', ', $reasons ) ),
				array( 'reasons' => $reasons )
			);
		}
		return $clean;
	}

	/**
	 * A WP-CLI session with no --user: there is no actor whose holdings bound the change,
	 * so only the checks that don't depend on an actor run.
	 */
	public static function is_shell( int $actor_id ): bool {
		return $actor_id <= 0 && defined( 'WP_CLI' ) && WP_CLI;
	}

	/**
	 * @param array<string,string[]> $map_after
	 * @return string[] no_manager_role when no role keeps rolegate_manage_roles undenied.
	 */
	private static function manager_reasons( array $map_after ): array {
		foreach ( wp_roles()->roles as $name => $data ) {
			$caps = Guard::normalize_caps( (array) $data['capabilities'] );
			if ( ! empty( $caps[ Caps::MANAGE_ROLES ] ) && ! in_array( Caps::MANAGE_ROLES, isset( $map_after[ $name ] ) ? $map_after[ $name ] : array(), true ) ) {
				return array();
			}
		}
		return array( 'no_manager_role' );
	}

	/**
	 * Validates and stores $role's denial list, then fires rolegate_changed.
	 *
	 * @param string[] $denied
	 * @return true|\WP_Error
	 */
	public static function save( int $actor_id, string $role, array $denied ) {
		$clean = self::validate( $actor_id, $role, $denied );
		if ( is_wp_error( $clean ) ) {
			return $clean;
		}
		$before = self::for_role( $role );
		if ( $before === $clean ) {
			return true;
		}
		$map = self::map();
		if ( $clean ) {
			$map[ $role ] = $clean;
		} else {
			unset( $map[ $role ] );
		}
		update_option( self::OPTION, $map, true );
		self::reset_cache();
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => $role,
				'rule'   => 'deny',
				'before' => array( 'denied' => $before ),
				'after'  => array( 'denied' => $clean ),
			)
		);
		return true;
	}
}
