<?php
namespace Rolegate\Modules\Portability;

defined( 'ABSPATH' ) || exit;

final class Exporter {
	/**
	 * @param string[] $roles    Role slugs; unknown slugs are ignored.
	 * @param string[] $sections Section ids the actor may export.
	 */
	public static function build( array $roles, array $sections, int $actor ): array {
		$all = Role_Store::all();
		$out = array();
		foreach ( $roles as $slug ) {
			$slug = (string) $slug;
			if ( isset( $all[ $slug ] ) ) {
				$out[ $slug ] = $all[ $slug ];
			}
		}
		$extra = array();
		foreach ( Sections::all() as $id => $section ) {
			if ( in_array( $id, $sections, true ) && user_can( $actor, $section['cap'] ) ) {
				$extra[ $id ] = call_user_func( $section['export'] );
			}
		}
		$payload = array(
			'format'      => Importer::FORMAT,
			'version'     => Importer::VERSION,
			'exported_at' => gmdate( 'c' ),
			'roles'       => $out,
		);
		if ( $extra ) {
			$payload['sections'] = $extra;
		}
		return $payload;
	}

	public static function to_json( array $payload ): string {
		return (string) wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}
}
