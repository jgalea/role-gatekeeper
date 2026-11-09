<?php
namespace Rolegate\Modules\Roles;

defined( 'ABSPATH' ) || exit;

/**
 * Single-write access to the roles option. Callers run the Guard assertions first.
 */
final class Role_Store {
	/** @return array<string,array{name:string,caps:array<string,bool>}> */
	public static function all(): array {
		$out = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			$out[ $slug ] = array(
				'name' => isset( $data['name'] ) ? (string) $data['name'] : $slug,
				'caps' => isset( $data['capabilities'] ) ? (array) $data['capabilities'] : array(),
			);
		}
		return $out;
	}

	/** @return array<string,bool> */
	public static function caps( string $role ): array {
		$obj = get_role( $role );
		return $obj ? (array) $obj->capabilities : array();
	}

	public static function name( string $role ): string {
		$roles = wp_roles()->roles;
		return isset( $roles[ $role ]['name'] ) ? (string) $roles[ $role ]['name'] : $role;
	}

	public static function granted_count( array $caps ): int {
		return count( array_filter( $caps ) );
	}

	/** @return array<string,int> role slug => users holding it */
	public static function user_counts(): array {
		$counts = count_users();
		return isset( $counts['avail_roles'] ) ? array_map( 'intval', $counts['avail_roles'] ) : array();
	}

	public static function add( string $slug, string $name, array $caps ): void {
		$wp_roles                        = wp_roles();
		$wp_roles->roles[ $slug ]        = array(
			'name'         => $name,
			'capabilities' => $caps,
		);
		$wp_roles->role_objects[ $slug ] = new \WP_Role( $slug, $caps );
		$wp_roles->role_names[ $slug ]   = $name;
		self::persist();
	}

	public static function set_caps( string $role, array $caps ): void {
		$wp_roles = wp_roles();
		if ( ! isset( $wp_roles->roles[ $role ] ) ) {
			return;
		}
		$wp_roles->roles[ $role ]['capabilities'] = $caps;
		if ( isset( $wp_roles->role_objects[ $role ] ) ) {
			$wp_roles->role_objects[ $role ]->capabilities = $caps;
		}
		self::persist();
	}

	public static function rename( string $role, string $name ): void {
		$wp_roles = wp_roles();
		if ( ! isset( $wp_roles->roles[ $role ] ) ) {
			return;
		}
		$wp_roles->roles[ $role ]['name'] = $name;
		$wp_roles->role_names[ $role ]    = $name;
		self::persist();
	}

	public static function remove( string $role ): void {
		$wp_roles = wp_roles();
		unset( $wp_roles->roles[ $role ], $wp_roles->role_objects[ $role ], $wp_roles->role_names[ $role ] );
		self::persist();
	}

	/** Replace the whole option, used by reset. */
	public static function replace_all( array $roles ): void {
		$wp_roles               = wp_roles();
		$wp_roles->roles        = $roles;
		$wp_roles->role_objects = array();
		$wp_roles->role_names   = array();
		foreach ( $roles as $slug => $data ) {
			$wp_roles->role_objects[ $slug ] = new \WP_Role( $slug, (array) $data['capabilities'] );
			$wp_roles->role_names[ $slug ]   = $data['name'];
		}
		self::persist();
	}

	private static function persist(): void {
		$wp_roles = wp_roles();
		update_option( $wp_roles->role_key, $wp_roles->roles );
	}
}
