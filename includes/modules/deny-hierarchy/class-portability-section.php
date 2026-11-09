<?php
namespace Rolegate\Modules\Deny_Hierarchy;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Role denials and hierarchy positions in a role file. Import goes through Denials::save and
 * Hierarchy::save_positions, so every Guard and hierarchy check applies. Only the roles the
 * file lists change; the rest keep their denials and positions.
 */
final class Portability_Section {
	public static function register( $sections ) {
		$sections         = is_array( $sections ) ? $sections : array();
		$sections['deny'] = array(
			'label'   => __( 'Denied capabilities and role positions', 'role-gatekeeper' ),
			'cap'     => Caps::MANAGE_ACCESS,
			'export'  => array( __CLASS__, 'export' ),
			'preview' => array( __CLASS__, 'preview' ),
			'import'  => array( __CLASS__, 'import' ),
		);
		return $sections;
	}

	public static function export(): array {
		return array(
			'denied'    => Denials::map(),
			'positions' => Hierarchy::stored(),
		);
	}

	/**
	 * @param mixed $data
	 * @return array{denied:array<string,string[]>,positions:array<string,int>}|\WP_Error
	 */
	private static function parse( $data ) {
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'rolegate_bad_section', __( 'The deny section is not in the expected format.', 'role-gatekeeper' ) );
		}
		$out = array(
			'denied'    => array(),
			'positions' => array(),
		);
		foreach ( (array) ( $data['denied'] ?? array() ) as $role => $caps ) {
			$role = sanitize_key( (string) $role );
			if ( '' === $role || ! is_array( $caps ) ) {
				return new \WP_Error( 'rolegate_bad_section', __( 'The deny section is not in the expected format.', 'role-gatekeeper' ) );
			}
			$out['denied'][ $role ] = array_values( array_filter( $caps, 'is_string' ) );
		}
		foreach ( (array) ( $data['positions'] ?? array() ) as $role => $pos ) {
			$role = sanitize_key( (string) $role );
			if ( '' === $role || ! is_numeric( $pos ) ) {
				return new \WP_Error( 'rolegate_bad_section', __( 'The deny section is not in the expected format.', 'role-gatekeeper' ) );
			}
			$out['positions'][ $role ] = $pos;
		}
		return $out;
	}

	/** @return string[]|\WP_Error */
	public static function preview( $data ) {
		$parsed = self::parse( $data );
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}
		$actor = get_current_user_id();
		$lines = array();
		foreach ( $parsed['denied'] as $role => $caps ) {
			if ( ! get_role( $role ) ) {
				/* translators: %s: role slug */
				$lines[] = sprintf( __( 'Denials for %s: applied only if the role exists after this import.', 'role-gatekeeper' ), $role );
				continue;
			}
			$clean = Denials::validate( $actor, $role, $caps );
			if ( is_wp_error( $clean ) ) {
				return $clean;
			}
			/* translators: 1: role slug, 2: comma-separated capability names */
			$lines[] = sprintf( __( 'Denials for %1$s: %2$s', 'role-gatekeeper' ), $role, $clean ? implode( ', ', $clean ) : __( 'none', 'role-gatekeeper' ) );
		}
		foreach ( $parsed['positions'] as $role => $pos ) {
			/* translators: 1: role slug, 2: position number */
			$lines[] = sprintf( __( 'Position of %1$s: %2$d', 'role-gatekeeper' ), $role, (int) $pos );
		}
		return $lines;
	}

	/** @return array|\WP_Error the previous denials and positions */
	public static function import( $data, int $actor ) {
		$parsed = self::parse( $data );
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}
		$before = self::export();
		foreach ( $parsed['denied'] as $role => $caps ) {
			if ( ! get_role( $role ) ) {
				continue;
			}
			$ok = Denials::save( $actor, $role, $caps );
			if ( is_wp_error( $ok ) ) {
				return self::restore( $before, $ok );
			}
		}
		$positions = array_filter(
			$parsed['positions'],
			function ( $role ) {
				return (bool) get_role( (string) $role );
			},
			ARRAY_FILTER_USE_KEY
		);
		if ( $positions ) {
			$ok = Hierarchy::save_positions( $actor, $positions );
			if ( is_wp_error( $ok ) ) {
				return self::restore( $before, $ok );
			}
		}
		return $before;
	}

	/** A section applies all of its roles or none: puts back what the earlier roles changed. */
	private static function restore( array $before, \WP_Error $error ): \WP_Error {
		update_option( Denials::OPTION, $before['denied'], true );
		update_option( Hierarchy::OPTION, $before['positions'], true );
		Denials::reset_cache();
		Hierarchy::reset_cache();
		return $error;
	}
}
