<?php
namespace Rolewright\Modules\Portability;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Extra data a role file can carry next to the roles, such as access rules or deny
 * rules. The module that owns the data registers it with `rolewright_portability_sections`:
 *
 *     $sections['deny'] = array(
 *         'label'   => 'Deny rules',
 *         'cap'     => Caps::MANAGE_ACCESS,
 *         'export'  => callable(): array,
 *         'preview' => callable( mixed $data ): string[]|WP_Error, // validates, lists what changes
 *         'import'  => callable( mixed $data, int $actor ): array|WP_Error, // returns the previous state
 *     );
 *
 * `import` must validate again and run the owner's own Guard checks; it returns the
 * previous state so the audit module can revert it.
 */
final class Sections {
	/**
	 * @return array<string,array{label:string,cap:string,export:callable,preview:callable,import:callable}>
	 */
	public static function all(): array {
		$raw = apply_filters( 'rolewright_portability_sections', array() );
		$out = array();
		foreach ( is_array( $raw ) ? $raw : array() as $id => $section ) {
			$id = sanitize_key( (string) $id );
			if ( '' === $id || ! is_array( $section ) ) {
				continue;
			}
			if ( ! isset( $section['export'], $section['preview'], $section['import'] ) || ! is_callable( $section['export'] ) || ! is_callable( $section['preview'] ) || ! is_callable( $section['import'] ) ) {
				continue;
			}
			$out[ $id ] = array(
				'label'   => isset( $section['label'] ) ? (string) $section['label'] : $id,
				'cap'     => isset( $section['cap'] ) ? (string) $section['cap'] : Caps::MANAGE_ACCESS,
				'export'  => $section['export'],
				'preview' => $section['preview'],
				'import'  => $section['import'],
			);
		}
		return $out;
	}
}
