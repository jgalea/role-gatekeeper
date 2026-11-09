<?php
namespace Rolegate\Modules\Audit;

use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Cap-set and role-list diffs. A cap set is a map of name => bool (false is an explicit deny).
 */
final class Diff {
	/**
	 * Accepts a list, a map, or a wrapper holding one under "caps" or "capabilities".
	 *
	 * @param mixed $state
	 * @return array<string,bool>
	 */
	public static function caps_map( $state ): array {
		if ( ! is_array( $state ) ) {
			return array();
		}
		foreach ( array( 'caps', 'capabilities' ) as $key ) {
			if ( isset( $state[ $key ] ) && is_array( $state[ $key ] ) ) {
				$state = $state[ $key ];
				break;
			}
		}
		return Guard::normalize_caps( $state );
	}

	/**
	 * @param mixed $state
	 * @return string[]
	 */
	public static function role_list( $state ): array {
		if ( is_array( $state ) && isset( $state['roles'] ) && is_array( $state['roles'] ) ) {
			$state = $state['roles'];
		}
		if ( ! is_array( $state ) ) {
			return array();
		}
		$out = array();
		foreach ( $state as $key => $value ) {
			$role = is_int( $key ) ? $value : ( $value ? $key : '' );
			if ( is_string( $role ) && '' !== $role ) {
				$out[] = $role;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @param array<string,bool> $before
	 * @param array<string,bool> $after
	 * @return array{added:string[],removed:string[],denied:string[],undenied:string[]}
	 */
	public static function caps( array $before, array $after ): array {
		$out = array(
			'added'    => array(),
			'removed'  => array(),
			'denied'   => array(),
			'undenied' => array(),
		);
		foreach ( $after as $cap => $grant ) {
			if ( $grant && empty( $before[ $cap ] ) ) {
				$out['added'][] = (string) $cap;
			}
			if ( ! $grant && ( ! isset( $before[ $cap ] ) || $before[ $cap ] ) ) {
				$out['denied'][] = (string) $cap;
			}
		}
		foreach ( $before as $cap => $grant ) {
			if ( $grant && empty( $after[ $cap ] ) ) {
				$out['removed'][] = (string) $cap;
			}
			if ( ! $grant && ( ! isset( $after[ $cap ] ) || $after[ $cap ] ) ) {
				$out['undenied'][] = (string) $cap;
			}
		}
		return $out;
	}

	/**
	 * @param string[] $before
	 * @param string[] $after
	 * @return array{added:string[],removed:string[]}
	 */
	public static function roles( array $before, array $after ): array {
		return array(
			'added'   => array_values( array_diff( $after, $before ) ),
			'removed' => array_values( array_diff( $before, $after ) ),
		);
	}

	/**
	 * Undo a caps diff on top of a current cap set.
	 *
	 * @param array<string,bool> $current
	 * @param array              $diff
	 * @return array<string,bool>
	 */
	public static function undo_caps( array $current, array $diff ): array {
		foreach ( array_merge( (array) ( $diff['added'] ?? array() ), (array) ( $diff['denied'] ?? array() ) ) as $cap ) {
			unset( $current[ (string) $cap ] );
		}
		foreach ( (array) ( $diff['removed'] ?? array() ) as $cap ) {
			$current[ (string) $cap ] = true;
		}
		foreach ( (array) ( $diff['undenied'] ?? array() ) as $cap ) {
			$current[ (string) $cap ] = false;
		}
		return $current;
	}

	public static function is_empty( array $diff ): bool {
		foreach ( $diff as $list ) {
			if ( ! empty( $list ) ) {
				return false;
			}
		}
		return true;
	}
}
