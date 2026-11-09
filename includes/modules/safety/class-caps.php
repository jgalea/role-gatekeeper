<?php
namespace Rolegate\Modules\Safety;

defined( 'ABSPATH' ) || exit;

/**
 * The plugin's own capabilities. They live on the administrator role only, and super
 * admins pass through is_super_admin().
 */
final class Caps {
	const MANAGE        = 'rolegate_manage';
	const MANAGE_ROLES  = 'rolegate_manage_roles';
	const MANAGE_CAPS   = 'rolegate_manage_caps';
	const MANAGE_USERS  = 'rolegate_manage_users';
	const MANAGE_ACCESS = 'rolegate_manage_access';
	const IMPORT        = 'rolegate_import';
	const VIEW_AUDIT    = 'rolegate_view_audit';

	/** @var bool */
	private static $healed = false;

	/** @return string[] */
	public static function all(): array {
		return array(
			self::MANAGE,
			self::MANAGE_ROLES,
			self::MANAGE_CAPS,
			self::MANAGE_USERS,
			self::MANAGE_ACCESS,
			self::IMPORT,
			self::VIEW_AUDIT,
		);
	}

	/**
	 * Caps that, on multisite, only super admins may use unless
	 * `rolegate_multisite_site_admin_access` returns true.
	 *
	 * @return string[]
	 */
	public static function network_restricted(): array {
		return array( self::MANAGE_ROLES, self::MANAGE_CAPS, self::MANAGE_USERS, self::MANAGE_ACCESS, self::IMPORT );
	}

	/**
	 * Adds every missing plugin cap to the administrator role. Returns the caps it added.
	 *
	 * @return string[]
	 */
	public static function grant_to_administrator(): array {
		$role = get_role( 'administrator' );
		if ( ! $role ) {
			return array();
		}
		$added = array();
		foreach ( self::all() as $cap ) {
			if ( empty( $role->capabilities[ $cap ] ) ) {
				$added[] = $cap;
			}
		}
		if ( $added ) {
			Enforcer::as_system(
				function () use ( $role, $added ) {
					foreach ( $added as $cap ) {
						$role->add_cap( $cap );
					}
				}
			);
		}
		return $added;
	}

	public static function self_heal(): void {
		if ( self::$healed ) {
			return;
		}
		self::$healed = true;
		self::grant_to_administrator();
	}

	/**
	 * Runs late on user_has_cap. Administrators always keep the plugin caps their role
	 * carries (no per-user or deny override can take them away), and on multisite the
	 * management caps are reserved for super admins.
	 *
	 * @param array<string,bool> $allcaps
	 * @param string[]           $caps
	 * @param array              $args
	 * @param \WP_User           $user
	 * @return array<string,bool>
	 */
	public static function filter_user_has_cap( $allcaps, $caps, $args, $user ) {
		if ( ! $user instanceof \WP_User || ! $user->ID ) {
			return $allcaps;
		}
		foreach ( Guard::role_name_caps_of( $user ) as $cap ) {
			$allcaps[ $cap ] = false;
		}
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			$admin = get_role( 'administrator' );
			if ( $admin ) {
				foreach ( self::all() as $cap ) {
					if ( ! empty( $admin->capabilities[ $cap ] ) ) {
						$allcaps[ $cap ] = true;
					}
				}
			}
		}
		if ( is_multisite() && ! is_super_admin( $user->ID ) && ! apply_filters( 'rolegate_multisite_site_admin_access', false, $user ) ) {
			foreach ( self::network_restricted() as $cap ) {
				$allcaps[ $cap ] = false;
			}
		}
		return $allcaps;
	}
}
