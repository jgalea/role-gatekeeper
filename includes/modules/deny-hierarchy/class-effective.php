<?php
namespace Rolegate\Modules\Deny_Hierarchy;

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Explains a user's capabilities: which roles grant each one, which roles deny it, and
 * the result after every user_has_cap filter (this module's denials and the safety
 * module's administrator protection included).
 */
final class Effective {
	/**
	 * @return array{roles:string[],position:int,super:bool,caps:array<string,array{granted_by:string[],user_grant:bool,denied_by:string[],denial_ignored:bool,effective:bool}>}
	 */
	public static function for_user( \WP_User $user ): array {
		$roles   = array_values( array_filter( (array) $user->roles, 'is_string' ) );
		$all     = wp_roles()->roles;
		$denials = Denials::for_user( $user );
		$admin   = in_array( 'administrator', $roles, true );
		$rows    = array();

		$row = function () {
			return array(
				'granted_by'     => array(),
				'user_grant'     => false,
				'denied_by'      => array(),
				'denial_ignored' => false,
				'effective'      => false,
			);
		};
		foreach ( $roles as $role ) {
			$caps = isset( $all[ $role ] ) ? Guard::normalize_caps( (array) $all[ $role ]['capabilities'] ) : array();
			foreach ( $caps as $cap => $grant ) {
				if ( ! isset( $rows[ $cap ] ) ) {
					$rows[ $cap ] = $row();
				}
				if ( $grant ) {
					$rows[ $cap ]['granted_by'][] = $role;
				}
			}
			foreach ( Denials::for_role( $role ) as $cap ) {
				if ( ! isset( $rows[ $cap ] ) ) {
					$rows[ $cap ] = $row();
				}
				if ( $admin && in_array( $cap, Caps::all(), true ) ) {
					$rows[ $cap ]['denial_ignored'] = true;
				}
			}
		}
		foreach ( Guard::normalize_caps( (array) $user->caps ) as $cap => $grant ) {
			if ( isset( $all[ $cap ] ) ) {
				continue;
			}
			if ( ! isset( $rows[ $cap ] ) ) {
				$rows[ $cap ] = $row();
			}
			$rows[ $cap ]['user_grant'] = $grant;
		}
		foreach ( $denials as $cap => $by ) {
			$rows[ $cap ]['denied_by'] = $by;
		}

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, run to compute the caps the user really has.
		$allcaps = apply_filters( 'user_has_cap', (array) $user->allcaps, array_keys( $rows ), array( '', $user->ID ), $user );
		$super   = Guard::is_super( $user->ID );
		foreach ( $rows as $cap => &$r ) {
			$r['effective'] = $super || ! empty( $allcaps[ $cap ] );
		}
		unset( $r );
		ksort( $rows );

		return array(
			'roles'    => $roles,
			'position' => Hierarchy::user_position( $user->ID ),
			'super'    => $super,
			'caps'     => $rows,
		);
	}
}
