<?php
namespace Rolewright\Modules\Portability;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes the current site's roles option in one go, so a multi-role change
 * passes the safety backstop as a single diff and either lands whole or not at all.
 */
final class Role_Store {
	public static function option_name(): string {
		global $wpdb;
		return $wpdb->get_blog_prefix() . 'user_roles';
	}

	/**
	 * @return array<string,array{name:string,capabilities:array<string,bool>}>
	 */
	public static function all(): array {
		$roles = get_option( self::option_name(), array() );
		$out   = array();
		foreach ( is_array( $roles ) ? $roles : array() as $slug => $data ) {
			$out[ (string) $slug ] = array(
				'name'         => isset( $data['name'] ) ? (string) $data['name'] : (string) $slug,
				'capabilities' => isset( $data['capabilities'] ) && is_array( $data['capabilities'] ) ? array_map( 'boolval', $data['capabilities'] ) : array(),
			);
		}
		return $out;
	}

	/**
	 * @return array{name:string,capabilities:array<string,bool>}|null
	 */
	public static function get( string $slug ): ?array {
		$all = self::all();
		return isset( $all[ $slug ] ) ? $all[ $slug ] : null;
	}

	/**
	 * Applies role definitions (slug => [name, capabilities]) or deletions (slug => null)
	 * in one option write, then checks that the write landed.
	 *
	 * @param array<string,array|null> $changes
	 * @return true|\WP_Error
	 */
	public static function write( array $changes ) {
		$key   = self::option_name();
		$roles = get_option( $key, array() );
		$roles = is_array( $roles ) ? $roles : array();
		foreach ( $changes as $slug => $def ) {
			if ( null === $def ) {
				unset( $roles[ $slug ] );
				continue;
			}
			$roles[ $slug ] = array(
				'name'         => (string) $def['name'],
				'capabilities' => array_map( 'boolval', (array) $def['capabilities'] ),
			);
		}
		update_option( $key, $roles );
		wp_cache_delete( $key, 'options' );
		wp_cache_delete( 'alloptions', 'options' );
		$after = self::all();
		foreach ( $changes as $slug => $def ) {
			$ok = null === $def ? ! isset( $after[ $slug ] ) : ( isset( $after[ $slug ] ) && self::same_caps( $after[ $slug ]['capabilities'], (array) $def['capabilities'] ) );
			if ( ! $ok ) {
				wp_roles()->for_site();
				return new \WP_Error( 'rolewright_write_refused', __( 'The roles could not be saved. The safety net refused the change or another plugin reverted it.', 'rolewright' ) );
			}
		}
		wp_roles()->for_site();
		return true;
	}

	public static function same_caps( array $a, array $b ): bool {
		$a = array_map( 'boolval', $a );
		$b = array_map( 'boolval', $b );
		ksort( $a );
		ksort( $b );
		return $a === $b;
	}
}
