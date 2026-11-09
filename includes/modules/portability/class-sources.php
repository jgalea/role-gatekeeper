<?php
namespace Rolegate\Modules\Portability;

defined( 'ABSPATH' ) || exit;

/**
 * Role sets other role plugins keep in the database, offered as import sources. Read
 * only when the user picks one; the result goes through the same validation and
 * preview as an uploaded file.
 */
final class Sources {
	/**
	 * @return array<string,array{label:string,read:callable}>
	 */
	public static function all(): array {
		global $wpdb;
		$prefix  = $wpdb->get_blog_prefix();
		$sources = array(
			'ure_backup' => array(
				'label' => __( 'User Role Editor: its saved copy of the roles from before its first change', 'role-gatekeeper' ),
				'read'  => function () use ( $prefix ) {
					return get_option( $prefix . 'backup_user_roles', null );
				},
			),
		);
		$sources = apply_filters( 'rolegate_portability_import_sources', $sources );
		$out     = array();
		foreach ( is_array( $sources ) ? $sources : array() as $id => $source ) {
			if ( is_array( $source ) && isset( $source['label'], $source['read'] ) && is_callable( $source['read'] ) ) {
				$out[ sanitize_key( (string) $id ) ] = array(
					'label' => (string) $source['label'],
					'read'  => $source['read'],
				);
			}
		}
		return $out;
	}

	/** @return array<string,string> id => label, only sources that hold roles on this site. */
	public static function available(): array {
		$out = array();
		foreach ( self::all() as $id => $source ) {
			$roles = call_user_func( $source['read'] );
			if ( is_array( $roles ) && $roles ) {
				$out[ $id ] = $source['label'];
			}
		}
		return $out;
	}

	/**
	 * @return array|\WP_Error Normalized payload.
	 */
	public static function load( string $id ) {
		$all = self::all();
		if ( ! isset( $all[ $id ] ) ) {
			return new \WP_Error( 'rolegate_import_source', __( 'Unknown import source.', 'role-gatekeeper' ) );
		}
		$roles = call_user_func( $all[ $id ]['read'] );
		if ( ! is_array( $roles ) || ! $roles ) {
			return new \WP_Error( 'rolegate_import_source', __( 'That source holds no roles on this site.', 'role-gatekeeper' ) );
		}
		$size = strlen( (string) wp_json_encode( $roles ) );
		if ( $size > Importer::max_bytes() ) {
			return new \WP_Error( 'rolegate_import_too_large', __( 'That source is larger than the import size limit.', 'role-gatekeeper' ) );
		}
		return Importer::normalize( $roles, array(), $id );
	}
}
