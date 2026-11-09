<?php
namespace Rolewright\Modules\Capabilities;

use Rolewright\Modules\Roles\Role_Store;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Cap_Service {
	/**
	 * Replace the granted set of one role.
	 *
	 * @param string[]    $granted     Capabilities ticked in the editor.
	 * @param int|null    $level       Role level 0-10, -1 for none, null to leave level caps alone.
	 * @param string[]    $new_custom  Custom capability names to create and grant.
	 * @param bool        $confirm_self The actor confirmed removing caps from a role they hold.
	 * @return array{removed:string[],added:string[]}|\WP_Error
	 */
	public static function update_role( int $actor, string $role, array $granted, ?int $level = null, array $new_custom = array(), bool $confirm_self = false ) {
		if ( ! get_role( $role ) ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
		}

		$custom = array();
		foreach ( $new_custom as $raw ) {
			$clean = Guard::sanitize_cap_name( (string) $raw );
			if ( false === $clean ) {
				return new \WP_Error(
					'rolewright_invalid_cap',
					/* translators: %s: capability name */
					sprintf( __( '"%s" is not a valid capability name. Use lowercase letters, numbers, underscores, hyphens or colons, and avoid role names.', 'rolewright' ), $raw )
				);
			}
			$custom[] = $clean;
		}

		$current  = Role_Store::caps( $role );
		$universe = array_diff( Cap_Catalog::universe( $custom ), self::level_caps() );
		$granted  = array_values( array_intersect( array_merge( $granted, $custom ), $universe ) );

		$new = $current;
		foreach ( $universe as $cap ) {
			if ( in_array( $cap, $granted, true ) ) {
				$new[ $cap ] = true;
			} elseif ( isset( $current[ $cap ] ) && $current[ $cap ] ) {
				unset( $new[ $cap ] );
			}
		}
		if ( null !== $level ) {
			foreach ( self::level_caps() as $cap ) {
				unset( $new[ $cap ] );
			}
			for ( $i = 0; $i <= $level; $i++ ) {
				$new[ 'level_' . $i ] = true;
			}
		}

		$added   = array_values( array_diff( array_keys( array_filter( $new ) ), array_keys( array_filter( $current ) ) ) );
		$removed = array_values( array_diff( array_keys( array_filter( $current ) ), array_keys( array_filter( $new ) ) ) );

		$user = get_userdata( $actor );
		if ( $removed && ! $confirm_self && $user && in_array( $role, (array) $user->roles, true ) ) {
			return new \WP_Error(
				'rolewright_confirm',
				__( 'This removes capabilities from a role you hold yourself. Confirm to continue.', 'rolewright' ),
				array( 'removed' => $removed )
			);
		}

		$ok = Guard::assert_can_modify_role( $actor, $role, $new );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}

		if ( $new !== $current ) {
			Role_Store::set_caps( $role, $new );
		}
		if ( $custom ) {
			self::remember_custom( $custom );
		}
		if ( null !== $level && $new !== $current ) {
			self::refresh_user_levels( $role );
		}
		if ( $new !== $current ) {
			self::fire( $actor, $role, $current, $new );
		}
		return array(
			'removed' => $removed,
			'added'   => $added,
		);
	}

	/**
	 * Removes a custom capability from every role and from the custom list.
	 *
	 * @return string[]|\WP_Error roles it was removed from
	 */
	public static function delete_custom_cap( int $actor, string $cap ) {
		$stored = Cap_Catalog::custom_caps();
		if ( 'custom' !== Cap_Catalog::group_of( $cap, Cap_Catalog::post_type_caps() ) && ! in_array( $cap, $stored, true ) ) {
			return new \WP_Error( 'rolewright_not_custom', __( 'Only custom capabilities can be deleted.', 'rolewright' ) );
		}
		if ( Guard::is_critical_cap( $cap ) ) {
			return new \WP_Error( 'rolewright_protected_cap', __( 'This capability is protected and can\'t be deleted.', 'rolewright' ) );
		}

		$plan = array();
		foreach ( Role_Store::all() as $slug => $data ) {
			if ( array_key_exists( $cap, $data['caps'] ) ) {
				$after = $data['caps'];
				unset( $after[ $cap ] );
				$ok = Guard::assert_can_modify_role( $actor, $slug, $after );
				if ( is_wp_error( $ok ) ) {
					return $ok;
				}
				$plan[ $slug ] = array( $data['caps'], $after );
			}
		}
		foreach ( $plan as $slug => $pair ) {
			Role_Store::set_caps( $slug, $pair[1] );
			self::fire( $actor, $slug, $pair[0], $pair[1] );
		}
		update_option( Cap_Catalog::OPTION_CUSTOM, array_values( array_diff( $stored, array( $cap ) ) ), false );
		return array_keys( $plan );
	}

	/**
	 * @param string[] $sets
	 * @param string[] $cpts
	 * @return true|\WP_Error
	 */
	public static function save_options( int $actor, array $sets, array $cpts ) {
		$sets = array_values( array_intersect( Cap_Sets::SET_IDS, $sets ) );
		$cpts = array_values( array_intersect( array_keys( Cap_Sets::eligible_post_types() ), $cpts ) );

		$roles = array();
		foreach ( Role_Store::all() as $slug => $data ) {
			$roles[ $slug ] = $data['caps'];
		}
		$grants = Cap_Sets::grants_for( $sets, $cpts, $roles );

		$plan = array();
		foreach ( $grants as $slug => $add ) {
			$after = $roles[ $slug ];
			foreach ( $add as $cap ) {
				$after[ $cap ] = true;
			}
			$ok = Guard::assert_can_modify_role( $actor, $slug, $after );
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
			$plan[ $slug ] = $after;
		}

		$before = array(
			'sets'    => Cap_Sets::enabled(),
			'cpt_own' => Cap_Sets::cpt_own(),
		);
		foreach ( $plan as $slug => $after ) {
			Role_Store::set_caps( $slug, $after );
			self::fire( $actor, $slug, $roles[ $slug ], $after );
		}
		update_option( Cap_Sets::OPTION_SETS, $sets, false );
		update_option( Cap_Sets::OPTION_CPT, $cpts, false );
		do_action(
			'rolewright_changed',
			'caps.options_updated',
			array(
				'actor'  => $actor,
				'target' => 'options',
				'before' => $before,
				'after'  => array(
					'sets'    => $sets,
					'cpt_own' => $cpts,
				),
			)
		);
		return true;
	}

	/** @return string[] */
	public static function level_caps(): array {
		$out = array();
		for ( $i = 0; $i <= 10; $i++ ) {
			$out[] = 'level_' . $i;
		}
		return $out;
	}

	/** Highest level_N the role holds, or -1. */
	public static function level_of( array $caps ): int {
		$level = -1;
		for ( $i = 0; $i <= 10; $i++ ) {
			if ( ! empty( $caps[ 'level_' . $i ] ) ) {
				$level = $i;
			}
		}
		return $level;
	}

	private static function remember_custom( array $caps ): void {
		$stored = Cap_Catalog::custom_caps();
		$merged = array_values( array_unique( array_merge( $stored, $caps ) ) );
		if ( $merged !== $stored ) {
			update_option( Cap_Catalog::OPTION_CUSTOM, $merged, false );
		}
	}

	private static function refresh_user_levels( string $role ): void {
		foreach ( get_users( array( 'role' => $role ) ) as $user ) {
			$user->update_user_level_from_caps();
		}
	}

	private static function fire( int $actor, string $role, array $before, array $after ): void {
		do_action(
			'rolewright_changed',
			'caps.updated',
			array(
				'actor'  => $actor,
				'target' => $role,
				'before' => array( 'caps' => $before ),
				'after'  => array( 'caps' => $after ),
			)
		);
	}
}
