<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Parses, validates, previews and applies a role file. Every entry point re-validates,
 * so a stored payload can't be tampered into something the preview didn't show.
 */
final class Importer {
	const FORMAT          = 'rolegate';
	const VERSION         = 1;
	const MAX_BYTES       = 524288;
	const MAX_ROLES       = 100;
	const MAX_CAPS        = 1000;
	const MAX_DEPTH       = 8;
	const ROLE_MAX_LENGTH = 64;
	const NAME_MAX_LENGTH = 191;

	public static function max_bytes(): int {
		return max( 1024, (int) apply_filters( 'rolegate_import_max_bytes', self::MAX_BYTES ) );
	}

	/**
	 * @return array|\WP_Error Normalized payload: version, roles, sections, rejected.
	 */
	public static function parse( string $json ) {
		if ( strlen( $json ) > self::max_bytes() ) {
			return new \WP_Error(
				'rolegate_import_too_large',
				/* translators: %s: size limit, for example 512 KB */
				sprintf( __( 'The file is larger than the %s limit.', 'role-gatekeeper' ), size_format( self::max_bytes() ) )
			);
		}
		$json = trim( $json );
		if ( '' === $json ) {
			return new \WP_Error( 'rolegate_import_empty', __( 'The file is empty.', 'role-gatekeeper' ) );
		}
		$data = json_decode( $json, true, self::MAX_DEPTH );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
			return new \WP_Error( 'rolegate_import_json', __( 'The file is not valid JSON, or it is nested too deeply.', 'role-gatekeeper' ) );
		}
		if ( ! isset( $data['format'] ) || self::FORMAT !== $data['format'] ) {
			return new \WP_Error( 'rolegate_import_format', __( 'This is not a Role Gatekeeper role file.', 'role-gatekeeper' ) );
		}
		if ( ! isset( $data['version'] ) || ! is_int( $data['version'] ) || $data['version'] < 1 || $data['version'] > self::VERSION ) {
			return new \WP_Error( 'rolegate_import_version', __( 'The file was made by a version of Role Gatekeeper this site does not understand.', 'role-gatekeeper' ) );
		}
		if ( ! isset( $data['roles'] ) || ! is_array( $data['roles'] ) ) {
			return new \WP_Error( 'rolegate_import_schema', __( 'The file has no roles list.', 'role-gatekeeper' ) );
		}
		$sections = isset( $data['sections'] ) && is_array( $data['sections'] ) ? $data['sections'] : array();
		return self::normalize( $data['roles'], $sections, 'file' );
	}

	/**
	 * Validates role definitions from any source into the payload shape. Invalid role
	 * slugs and cap names are dropped and listed under `rejected`; nothing is rewritten.
	 *
	 * @param mixed $roles
	 * @return array|\WP_Error
	 */
	public static function normalize( $roles, array $sections, string $source ) {
		if ( ! is_array( $roles ) ) {
			return new \WP_Error( 'rolegate_import_schema', __( 'The roles list is malformed.', 'role-gatekeeper' ) );
		}
		if ( count( $roles ) > self::MAX_ROLES ) {
			return new \WP_Error(
				'rolegate_import_too_many',
				/* translators: %d: maximum number of roles */
				sprintf( __( 'The file lists more than %d roles.', 'role-gatekeeper' ), self::MAX_ROLES )
			);
		}
		$out      = array();
		$rejected = array();
		foreach ( $roles as $slug => $def ) {
			$slug  = (string) $slug;
			$clean = self::sanitize_role_slug( $slug );
			if ( false === $clean ) {
				/* translators: %s: role slug as found in the file */
				$rejected[] = sprintf( __( 'Role "%s" skipped: not a valid role name.', 'role-gatekeeper' ), self::printable( $slug ) );
				continue;
			}
			if ( ! is_array( $def ) || ! isset( $def['capabilities'] ) || ! is_array( $def['capabilities'] ) ) {
				/* translators: %s: role slug */
				$rejected[] = sprintf( __( 'Role "%s" skipped: no capability list.', 'role-gatekeeper' ), $clean );
				continue;
			}
			if ( count( $def['capabilities'] ) > self::MAX_CAPS ) {
				return new \WP_Error(
					'rolegate_import_too_many_caps',
					/* translators: 1: role slug, 2: maximum number of capabilities */
					sprintf( __( 'Role "%1$s" lists more than %2$d capabilities.', 'role-gatekeeper' ), $clean, self::MAX_CAPS )
				);
			}
			$caps = array();
			foreach ( $def['capabilities'] as $cap => $grant ) {
				if ( is_int( $cap ) ) {
					$val = true;
					$cap = is_string( $grant ) ? $grant : '';
				} else {
					$val = $grant;
					$cap = (string) $cap;
				}
				$ok = Guard::sanitize_cap_name( $cap );
				if ( false === $ok || $ok !== $cap || ( ! is_bool( $val ) && 0 !== $val && 1 !== $val ) ) {
					/* translators: 1: capability name as found in the file, 2: role slug */
					$rejected[] = sprintf( __( 'Capability "%1$s" in role "%2$s" skipped: not a valid capability name or value.', 'role-gatekeeper' ), self::printable( (string) $cap ), $clean );
					continue;
				}
				$caps[ $ok ] = (bool) $val;
			}
			$name = isset( $def['name'] ) && is_string( $def['name'] ) ? sanitize_text_field( $def['name'] ) : '';
			$name = '' === $name ? $clean : mb_substr( $name, 0, self::NAME_MAX_LENGTH );

			$out[ $clean ] = array(
				'name'         => $name,
				'capabilities' => $caps,
			);
		}
		$known = array_keys( Sections::all() );
		$kept  = array();
		foreach ( $sections as $id => $section_data ) {
			$id = sanitize_key( (string) $id );
			if ( in_array( $id, $known, true ) ) {
				$kept[ $id ] = $section_data;
			} else {
				/* translators: %s: section id */
				$rejected[] = sprintf( __( 'Section "%s" skipped: no module on this site handles it.', 'role-gatekeeper' ), self::printable( $id ) );
			}
		}
		return array(
			'version'  => self::VERSION,
			'source'   => sanitize_key( $source ),
			'roles'    => $out,
			'sections' => $kept,
			'rejected' => $rejected,
		);
	}

	/**
	 * Role slugs follow the cap-name rules, except that an existing role's own name is
	 * allowed (that is what an overwrite targets).
	 *
	 * @return string|false
	 */
	public static function sanitize_role_slug( string $slug ) {
		if ( strlen( $slug ) > self::ROLE_MAX_LENGTH ) {
			return false;
		}
		$clean = Guard::sanitize_cap_name( $slug );
		if ( false === $clean && wp_roles()->is_role( $slug ) && preg_match( '/^[a-z0-9_\-]+$/', $slug ) ) {
			$clean = $slug;
		}
		if ( false === $clean || $clean !== $slug || false !== strpos( $clean, ':' ) ) {
			return false;
		}
		// WordPress counts a user's role name as one of their capabilities, so a new role must not share a capability's name.
		if ( ! wp_roles()->is_role( $clean ) && ( Guard::cap_exists( $clean ) || Guard::is_critical_cap( $clean ) || true !== Guard::valid_new_role_slug( $clean ) ) ) {
			return false;
		}
		return $clean;
	}

	private static function printable( string $text ): string {
		return mb_substr( (string) preg_replace( '/[^\x20-\x7E]/', '?', $text ), 0, 80 );
	}

	/**
	 * What applying the payload would do, per role. Never writes.
	 *
	 * @param string $mode replace (the file's cap set replaces the role's) or merge (adds only).
	 * @return array{roles:array<string,array>,sections:array<string,array>,rejected:string[]}
	 */
	public static function plan( array $payload, int $actor, string $mode = 'replace' ): array {
		$current     = Role_Store::all();
		$actor_user  = get_userdata( $actor );
		$actor_roles = $actor_user ? (array) $actor_user->roles : array();
		$protected   = Guard::protected_roles();
		$rows        = array();

		foreach ( $payload['roles'] as $slug => $def ) {
			$exists   = isset( $current[ $slug ] );
			$before   = $exists ? $current[ $slug ]['capabilities'] : array();
			$incoming = $def['capabilities'];
			$final    = 'merge' === $mode && $exists ? array_merge( $before, $incoming ) : $incoming;

			$critical = array();
			foreach ( $final as $cap => $grant ) {
				if ( $grant && empty( $before[ $cap ] ) && Guard::is_critical_cap( $cap ) ) {
					$critical[] = $cap;
				}
			}
			$stripped = $final;
			foreach ( $critical as $cap ) {
				unset( $stripped[ $cap ] );
			}

			$row = array(
				'slug'       => $slug,
				'name'       => $def['name'],
				'exists'     => $exists,
				'action'     => $exists ? 'overwrite' : 'create',
				'blocked'    => '',
				'added'      => array_keys( array_filter( array_diff_key( $final, array_filter( $before ) ) ) ),
				'removed'    => array_keys( array_filter( array_diff_key( array_filter( $before ), array_filter( $final ) ) ) ),
				'denied'     => array_keys( array_diff_key( self::denies( $final ), self::denies( $before ) ) ),
				'new_custom' => array(),
				'critical'   => $critical,
				'final'      => $final,
				'stripped'   => $stripped,
			);
			foreach ( array_keys( $final ) as $cap ) {
				if ( ! Guard::cap_exists( $cap ) ) {
					$row['new_custom'][] = $cap;
				}
			}
			if ( $exists && Role_Store::same_caps( $before, $final ) && $current[ $slug ]['name'] === $def['name'] ) {
				$row['action'] = 'unchanged';
			}

			if ( in_array( $slug, $protected, true ) && $exists ) {
				$row['blocked'] = __( 'Protected role. Imports never overwrite it.', 'role-gatekeeper' );
			} elseif ( in_array( $slug, $actor_roles, true ) ) {
				$row['blocked'] = __( 'This is your own role. Imports never overwrite it.', 'role-gatekeeper' );
			} elseif ( 'unchanged' !== $row['action'] ) {
				$check = Guard::assert_can_modify_role( $actor, $slug, $stripped );
				if ( is_wp_error( $check ) ) {
					$row['blocked'] = $check->get_error_message();
				}
			}
			$rows[ $slug ] = $row;
		}

		$sections = array();
		foreach ( Sections::all() as $id => $section ) {
			if ( ! array_key_exists( $id, $payload['sections'] ) ) {
				continue;
			}
			$allowed         = user_can( $actor, $section['cap'] );
			$summary         = $allowed ? call_user_func( $section['preview'], $payload['sections'][ $id ] ) : new \WP_Error( 'rolegate_forbidden', __( 'You do not have permission to import this section.', 'role-gatekeeper' ) );
			$sections[ $id ] = array(
				'label'   => $section['label'],
				'summary' => is_wp_error( $summary ) ? array() : array_map( 'strval', (array) $summary ),
				'blocked' => is_wp_error( $summary ) ? $summary->get_error_message() : '',
			);
		}

		return array(
			'roles'    => $rows,
			'sections' => $sections,
			'rejected' => $payload['rejected'],
		);
	}

	private static function denies( array $caps ): array {
		return array_filter(
			$caps,
			function ( $grant ) {
				return false === $grant;
			}
		);
	}

	/**
	 * Applies the chosen roles and sections. All-or-nothing for roles: if any selected
	 * role fails a check, nothing is written.
	 *
	 * @param array $args roles (slugs), confirm_critical (slugs whose critical caps the actor
	 *                    confirmed), sections (ids), mode (replace|merge).
	 * @return array|\WP_Error Result with backup_id, roles applied, sections applied.
	 */
	public static function apply( array $payload, int $actor, array $args ) {
		if ( ! $actor || ! user_can( $actor, Caps::IMPORT ) ) {
			return new \WP_Error( 'rolegate_forbidden', __( 'You do not have permission to import roles.', 'role-gatekeeper' ) );
		}
		$check = self::normalize( $payload['roles'] ?? null, (array) ( $payload['sections'] ?? array() ), (string) ( $payload['source'] ?? 'file' ) );
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$payload  = $check;
		$mode     = isset( $args['mode'] ) && 'merge' === $args['mode'] ? 'merge' : 'replace';
		$selected = array_map( 'strval', (array) ( $args['roles'] ?? array() ) );
		$confirm  = array_map( 'strval', (array) ( $args['confirm_critical'] ?? array() ) );
		$plan     = self::plan( $payload, $actor, $mode );

		$changes = array();
		$errors  = array();
		foreach ( $selected as $slug ) {
			if ( ! isset( $plan['roles'][ $slug ] ) ) {
				continue;
			}
			$row = $plan['roles'][ $slug ];
			if ( $row['blocked'] ) {
				$errors[] = $slug . ': ' . $row['blocked'];
				continue;
			}
			if ( 'unchanged' === $row['action'] ) {
				continue;
			}
			$caps  = in_array( $slug, $confirm, true ) ? $row['final'] : $row['stripped'];
			$guard = Guard::assert_can_modify_role( $actor, $slug, $caps );
			if ( is_wp_error( $guard ) ) {
				$errors[] = $slug . ': ' . $guard->get_error_message();
				continue;
			}
			$changes[ $slug ] = array(
				'name'         => $row['name'],
				'capabilities' => $caps,
			);
		}

		$section_ids = array_intersect( array_map( 'sanitize_key', (array) ( $args['sections'] ?? array() ) ), array_keys( $plan['sections'] ) );
		foreach ( $section_ids as $id ) {
			if ( $plan['sections'][ $id ]['blocked'] ) {
				$errors[] = $id . ': ' . $plan['sections'][ $id ]['blocked'];
			}
		}

		if ( $changes ) {
			$proposed = array();
			foreach ( $changes as $slug => $def ) {
				$proposed[ $slug ] = $def['capabilities'];
			}
			$reasons = Guard::lockout_reasons_for( $actor, $proposed );
			if ( $reasons ) {
				$errors[] = __( 'Applying these roles together would lock you out.', 'role-gatekeeper' );
			}
		}
		if ( $errors ) {
			return new \WP_Error( 'rolegate_import_blocked', __( 'Nothing was imported.', 'role-gatekeeper' ) . ' ' . implode( ' ', $errors ) );
		}
		if ( ! $changes && ! $section_ids ) {
			return new \WP_Error( 'rolegate_import_nothing', __( 'Nothing to import: no changed role or section was selected.', 'role-gatekeeper' ) );
		}

		$current = Role_Store::all();
		$before  = array();
		foreach ( array_keys( $changes ) as $slug ) {
			$before[ $slug ] = isset( $current[ $slug ] ) ? $current[ $slug ] : null;
		}
		$backup_id = Backups::store( $actor, $current, $payload['source'] );

		if ( $changes ) {
			$written = Role_Store::write( $changes );
			if ( is_wp_error( $written ) ) {
				return $written;
			}
		}

		$sections_before = array();
		$sections_after  = array();
		$all_sections    = Sections::all();
		foreach ( $section_ids as $id ) {
			$result = call_user_func( $all_sections[ $id ]['import'], $payload['sections'][ $id ], $actor );
			if ( is_wp_error( $result ) ) {
				foreach ( array_reverse( $sections_before, true ) as $done => $state ) {
					call_user_func( $all_sections[ $done ]['import'], $state, $actor );
				}
				if ( $changes ) {
					Role_Store::write( $before );
				}
				return new \WP_Error( 'rolegate_import_failed', __( 'Nothing was imported.', 'role-gatekeeper' ) . ' ' . $id . ': ' . $result->get_error_message() );
			}
			$sections_before[ $id ] = $result;
			$sections_after[ $id ]  = $payload['sections'][ $id ];
		}

		do_action(
			'rolegate_changed',
			'import.applied',
			array(
				'actor'     => $actor,
				'target'    => implode( ',', array_merge( array_keys( $changes ), $section_ids ) ),
				'before'    => array(
					'roles'    => $before,
					'sections' => $sections_before,
				),
				'after'     => array(
					'roles'    => $changes,
					'sections' => $sections_after,
				),
				'backup_id' => $backup_id,
				'source'    => $payload['source'],
			)
		);

		return array(
			'backup_id' => $backup_id,
			'roles'     => array_keys( $changes ),
			'sections'  => array_keys( $sections_after ),
			'errors'    => $errors,
		);
	}
}
