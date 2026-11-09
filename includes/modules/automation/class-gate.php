<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;
use Rolewright\Modules\User_Roles\Users;

defined( 'ABSPATH' ) || exit;

/**
 * Guard assertions for every automation surface. Actor 0 is a shell session with no --user:
 * the checks about what the actor holds are skipped (there is no actor), everything else
 * still applies: valid names, protected roles, and a role left that can manage roles.
 */
final class Gate {
	/** @return true|\WP_Error */
	public static function modify_role( int $actor, string $role, array $new_caps ) {
		if ( $actor > 0 ) {
			return Guard::assert_can_modify_role( $actor, $role, $new_caps );
		}
		$ok = self::drop_actor_checks(
			self::as_shell(
				function () use ( $role, $new_caps ) {
					return Guard::assert_can_modify_role( 0, $role, $new_caps );
				}
			)
		);
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		return self::manager_role_left( array( $role => Guard::normalize_caps( $new_caps ) ) );
	}

	/** @return true|\WP_Error */
	public static function delete_role( int $actor, string $role ) {
		if ( $actor > 0 ) {
			return Guard::assert_can_delete_role( $actor, $role );
		}
		$ok = self::drop_actor_checks(
			self::as_shell(
				function () use ( $role ) {
					return Guard::assert_can_delete_role( 0, $role );
				}
			)
		);
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		return self::manager_role_left( array( $role => null ) );
	}

	/** @return true|\WP_Error */
	public static function rename_role( int $actor, string $role ) {
		if ( $actor > 0 ) {
			return Guard::assert_can_rename_role( $actor, $role );
		}
		return self::drop_actor_checks(
			self::as_shell(
				function () use ( $role ) {
					return Guard::assert_can_rename_role( 0, $role );
				}
			)
		);
	}

	/**
	 * Runs a Guard assertion for the shell actor. The shell has no role, so a role
	 * hierarchy would rank it below everything; that veto is about what the actor holds and
	 * is dropped here, so Guard's own checks (names, protected roles) still run.
	 *
	 * @return true|\WP_Error
	 */
	private static function as_shell( callable $fn ) {
		$drop = function ( $veto ) {
			if ( $veto instanceof \WP_Error && 'rolewright_role_above_position' === $veto->get_error_code() ) {
				return null;
			}
			return $veto;
		};
		add_filter( 'rolewright_role_change_veto', $drop, PHP_INT_MAX );
		try {
			return $fn();
		} finally {
			remove_filter( 'rolewright_role_change_veto', $drop, PHP_INT_MAX );
		}
	}

	/** @return true|\WP_Error */
	public static function assign_role( int $actor, string $role, int $target ) {
		if ( ! get_role( $role ) ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
		}
		if ( $actor > 0 && ! Guard::can_assign_role( $actor, $role, $target ) ) {
			return new \WP_Error( 'rolewright_cannot_assign', __( 'You can\'t assign that role to this user.', 'rolewright' ) );
		}
		return true;
	}

	/**
	 * On multisite a named actor may only touch users who belong to the current site, the
	 * same rule the user-roles screens apply. The shell actor keeps WP-CLI's own reach.
	 *
	 * @return true|\WP_Error
	 */
	public static function site_member( int $actor, int $target ) {
		if ( $actor <= 0 ) {
			return true;
		}
		$ok = Users::check_site_member( $actor, $target );
		if ( is_wp_error( $ok ) ) {
			$ok->add_data( array( 'status' => 404 ) );
		}
		return $ok;
	}

	/** @return true|\WP_Error */
	public static function act_on_user( int $actor, int $target ) {
		if ( $actor > 0 && ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolewright_user_above_actor', __( 'You can\'t change a user who holds capabilities you don\'t have.', 'rolewright' ) );
		}
		return true;
	}

	/** @return true|\WP_Error */
	public static function grant_cap( int $actor, string $cap ) {
		if ( false === Guard::sanitize_cap_name( $cap ) && ! Guard::cap_exists( $cap ) ) {
			return new \WP_Error( 'rolewright_invalid_cap', __( 'That is not a valid capability name.', 'rolewright' ) );
		}
		if ( $actor > 0 && ! Guard::can_grant_cap( $actor, $cap ) ) {
			return new \WP_Error(
				'rolewright_cap_not_held',
				/* translators: %s: capability name */
				sprintf( __( 'You can\'t grant a capability you don\'t hold yourself: %s.', 'rolewright' ), $cap )
			);
		}
		return true;
	}

	/**
	 * A change to the actor's own roles or per-user caps must leave them with read and
	 * Rolewright access.
	 *
	 * @param string[]           $roles_after
	 * @param array<string,bool> $user_caps_after
	 * @return true|\WP_Error
	 */
	public static function self_lockout( int $actor, int $target, array $roles_after, array $user_caps_after ) {
		if ( $actor <= 0 || $actor !== $target || Guard::is_super( $actor ) ) {
			return true;
		}
		$roles_caps = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles_caps[ $name ] = Guard::normalize_caps( (array) $data['capabilities'] );
		}
		$reasons = array_diff( Guard::lockout_reasons( $roles_after, $user_caps_after, $roles_caps ), array( 'no_manager_role' ) );
		if ( $reasons ) {
			return new \WP_Error( 'rolewright_lockout', __( 'This change would lock you out of your own account or of Rolewright.', 'rolewright' ), array( 'reasons' => array_values( $reasons ) ) );
		}
		return true;
	}

	/**
	 * Whether the change touches anything that can take over a site. Used by surfaces that
	 * ask for an explicit confirmation.
	 *
	 * @param string[] $caps Capability names being granted or removed.
	 */
	public static function is_risky( string $role, array $caps ): bool {
		if ( Guard::is_protected_role( $role ) ) {
			return true;
		}
		foreach ( $caps as $cap ) {
			if ( Guard::is_critical_cap( (string) $cap ) ) {
				return true;
			}
		}
		$obj = get_role( $role );
		return $obj && (bool) Guard::critical_subset( (array) $obj->capabilities );
	}

	/** @return \WP_Error|null Error when the change is risky and the caller did not confirm it. */
	public static function confirm_error( bool $confirmed, string $role, array $caps ): ?\WP_Error {
		if ( ! $confirmed && self::is_risky( $role, $caps ) ) {
			return new \WP_Error( 'rolewright_confirm_required', __( 'This change touches a protected role or a capability that can take over the site. Send confirm=true to proceed.', 'rolewright' ), array( 'status' => 409 ) );
		}
		return null;
	}

	/** @param true|\WP_Error $result */
	private static function drop_actor_checks( $result ) {
		if ( is_wp_error( $result ) && in_array( $result->get_error_code(), array( 'rolewright_role_above_actor', 'rolewright_cap_not_held' ), true ) ) {
			return true;
		}
		return $result;
	}

	/**
	 * @param array<string,array<string,bool>|null> $proposed
	 * @return true|\WP_Error
	 */
	private static function manager_role_left( array $proposed ) {
		$roles = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles[ $name ] = Guard::normalize_caps( (array) $data['capabilities'] );
		}
		foreach ( $proposed as $name => $caps ) {
			if ( null === $caps ) {
				unset( $roles[ $name ] );
			} else {
				$roles[ $name ] = $caps;
			}
		}
		foreach ( $roles as $caps ) {
			if ( ! empty( $caps[ Caps::MANAGE_ROLES ] ) ) {
				return true;
			}
		}
		return new \WP_Error( 'rolewright_lockout', __( 'This change would leave no role that can manage roles (rolewright_manage_roles).', 'rolewright' ), array( 'reasons' => array( 'no_manager_role' ) ) );
	}
}
