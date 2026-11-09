<?php
namespace Rolewright\Modules\Portability;

defined( 'ABSPATH' ) || exit;

/**
 * Full snapshots of the site's roles taken before each import, newest first.
 */
final class Backups {
	const OPTION = 'rolewright_import_backups';
	const KEEP   = 10;

	public static function store( int $actor, array $roles, string $source ): string {
		$list = self::all();
		$id   = gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false, false );
		array_unshift(
			$list,
			array(
				'id'     => $id,
				'time'   => time(),
				'actor'  => $actor,
				'source' => $source,
				'roles'  => $roles,
			)
		);
		$keep = max( 1, (int) apply_filters( 'rolewright_import_backups_keep', self::KEEP ) );
		update_option( self::OPTION, array_slice( $list, 0, $keep ), false );
		return $id;
	}

	/** @return array[] */
	public static function all(): array {
		$list = get_option( self::OPTION, array() );
		return is_array( $list ) ? array_values( array_filter( $list, 'is_array' ) ) : array();
	}

	public static function get( string $id ): ?array {
		foreach ( self::all() as $backup ) {
			if ( isset( $backup['id'] ) && $backup['id'] === $id ) {
				return $backup;
			}
		}
		return null;
	}
}
