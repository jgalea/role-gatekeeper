<?php
namespace Rolewright\Modules\Edit_Scope;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Edit scope rules in a role file. The file's rules replace the site's. Post, term and author
 * IDs are kept as they are, so they match only on the same site or a copy of it; user
 * subjects travel by login. Import goes through Rules::delete and Rules::add, with all of
 * their checks.
 */
final class Portability_Section {
	public static function register( $sections ) {
		$sections               = is_array( $sections ) ? $sections : array();
		$sections['edit-scope'] = array(
			'label'   => __( 'Edit scope rules', 'rolewright' ),
			'cap'     => Caps::MANAGE_ACCESS,
			'export'  => array( __CLASS__, 'export' ),
			'preview' => array( __CLASS__, 'preview' ),
			'import'  => array( __CLASS__, 'import' ),
		);
		return $sections;
	}

	public static function export(): array {
		$rules = array();
		foreach ( Rules::all() as $rule ) {
			if ( 'user' === ( $rule['subject_type'] ?? '' ) ) {
				$user = get_userdata( (int) $rule['subject'] );
				if ( ! $user ) {
					continue;
				}
				$rule['subject'] = $user->user_login;
			}
			unset( $rule['id'] );
			$rules[] = $rule;
		}
		return array(
			'rules'         => $rules,
			'hide_in_lists' => Rules::hide_in_lists(),
		);
	}

	/**
	 * @param mixed $data
	 * @return array{rules:array<int,array>,skipped:string[],hide_in_lists:?bool}|\WP_Error
	 */
	private static function parse( $data ) {
		if ( ! is_array( $data ) || ! isset( $data['rules'] ) || ! is_array( $data['rules'] ) ) {
			return new \WP_Error( 'rolewright_bad_section', __( 'The edit scope section is not in the expected format.', 'rolewright' ) );
		}
		$out = array(
			'rules'         => array(),
			'skipped'       => array(),
			'hide_in_lists' => isset( $data['hide_in_lists'] ) ? (bool) $data['hide_in_lists'] : null,
		);
		foreach ( $data['rules'] as $rule ) {
			if ( ! is_array( $rule ) ) {
				return new \WP_Error( 'rolewright_bad_section', __( 'The edit scope section is not in the expected format.', 'rolewright' ) );
			}
			if ( 'user' === ( $rule['subject_type'] ?? '' ) ) {
				$user = get_user_by( 'login', (string) ( $rule['subject'] ?? '' ) );
				if ( ! $user ) {
					$out['skipped'][] = sanitize_user( (string) ( $rule['subject'] ?? '' ), true );
					continue;
				}
				$rule['subject'] = (string) $user->ID;
			}
			$out['rules'][] = $rule;
		}
		return $out;
	}

	/** @return string[]|\WP_Error */
	public static function preview( $data ) {
		$parsed = self::parse( $data );
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}
		$lines = array(
			/* translators: 1: number of rules in the file, 2: number of rules on this site */
			sprintf( __( '%1$d rules replace the %2$d rules on this site.', 'rolewright' ), count( $parsed['rules'] ), count( Rules::all() ) ),
		);
		foreach ( $parsed['skipped'] as $login ) {
			/* translators: %s: user login */
			$lines[] = sprintf( __( 'Rule for user %s: no user with that login here, skipped.', 'rolewright' ), $login );
		}
		return $lines;
	}

	/** @return array|\WP_Error the previous rules and settings */
	public static function import( $data, int $actor ) {
		if ( ! user_can( $actor, Caps::MANAGE_ACCESS ) ) {
			return new \WP_Error( 'rolewright_forbidden', __( 'You do not have permission to change access rules.', 'rolewright' ) );
		}
		$parsed = self::parse( $data );
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}
		$before   = Rules::all();
		$settings = get_option( Rules::SETTINGS, array() );
		$result   = array(
			'rules'         => $before,
			'hide_in_lists' => Rules::hide_in_lists(),
		);
		foreach ( array_keys( $before ) as $id ) {
			$ok = Rules::delete( $actor, (string) $id );
			if ( is_wp_error( $ok ) ) {
				return self::restore( $before, $settings, $ok );
			}
		}
		foreach ( $parsed['rules'] as $rule ) {
			$ok = Rules::add( $actor, $rule );
			if ( is_wp_error( $ok ) ) {
				return self::restore( $before, $settings, $ok );
			}
		}
		if ( null !== $parsed['hide_in_lists'] && $parsed['hide_in_lists'] !== $result['hide_in_lists'] ) {
			Rules::save_settings( $actor, $parsed['hide_in_lists'] );
		}
		return $result;
	}

	/** A section applies all of its rules or none. */
	private static function restore( array $rules, $settings, \WP_Error $error ): \WP_Error {
		update_option( Rules::OPTION, $rules, false );
		update_option( Rules::SETTINGS, $settings, false );
		Rules::flush();
		return $error;
	}
}
