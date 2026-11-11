<?php
namespace Rolegate\Modules\Automation;

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\User_Roles\Users;

defined( 'ABSPATH' ) || exit;

/**
 * Role, capability and user-role operations shared by WP-CLI, REST and Abilities. Every write
 * goes through Gate (Guard assertions) and announces itself with rolegate_changed.
 */
final class Ops {
	const FORMAT  = 'rolegate';
	const VERSION = 1;

	/** @return array<int,array{slug:string,name:string,caps:int,users:int,protected:bool}> */
	public static function list_roles(): array {
		$counts = count_users();
		$counts = isset( $counts['avail_roles'] ) ? $counts['avail_roles'] : array();
		$out    = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			$out[] = array(
				'slug'      => (string) $slug,
				'name'      => (string) $data['name'],
				'caps'      => count( array_filter( (array) $data['capabilities'] ) ),
				'users'     => isset( $counts[ $slug ] ) ? (int) $counts[ $slug ] : 0,
				'protected' => Guard::is_protected_role( (string) $slug ),
			);
		}
		return $out;
	}

	/** @return array{slug:string,name:string,capabilities:array<string,bool>,protected:bool}|\WP_Error */
	public static function get_role( string $slug ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		return array(
			'slug'         => $slug,
			'name'         => self::role_name( $slug ),
			'capabilities' => Guard::normalize_caps( (array) $role->capabilities ),
			'protected'    => Guard::is_protected_role( $slug ),
		);
	}

	/**
	 * @param string[] $caps
	 * @return string|\WP_Error The new role's slug.
	 */
	public static function add_role( int $actor, string $name, string $slug, array $caps ) {
		$name = sanitize_text_field( $name );
		if ( '' === $name ) {
			return new \WP_Error( 'rolegate_invalid_name', __( 'Enter a role name.', 'role-gatekeeper' ) );
		}
		$slug = '' === $slug ? self::slug_from( $name ) : strtolower( trim( $slug ) );
		if ( '' === $slug ) {
			return new \WP_Error( 'rolegate_invalid_name', __( 'That name can\'t be turned into a role slug.', 'role-gatekeeper' ) );
		}
		$valid = Guard::valid_new_role_slug( $slug );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$caps = Guard::normalize_caps( $caps );
		$ok   = Gate::modify_role( $actor, $slug, $caps );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		add_role( $slug, $name, $caps );
		self::fire(
			'role.created',
			$actor,
			$slug,
			array(),
			array(
				'name' => $name,
				'caps' => $caps,
			)
		);
		return $slug;
	}

	/** @return string|\WP_Error The copy's slug. */
	public static function clone_role( int $actor, string $source, string $name, string $slug ) {
		$from = get_role( $source );
		if ( ! $from ) {
			return new \WP_Error( 'rolegate_no_role', __( 'The role to copy does not exist.', 'role-gatekeeper' ) );
		}
		return self::add_role( $actor, $name, $slug, Guard::normalize_caps( (array) $from->capabilities ) );
	}

	/** @return true|\WP_Error */
	public static function delete_role( int $actor, string $slug ) {
		if ( ! get_role( $slug ) ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$ok = Gate::delete_role( $actor, $slug );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$members = get_users(
			array(
				'role'   => $slug,
				'number' => 1,
				'fields' => 'ID',
			)
		);
		if ( $members ) {
			return new \WP_Error( 'rolegate_role_in_use', __( 'The role still has users. Move them to another role first.', 'role-gatekeeper' ) );
		}
		$before = self::get_role( $slug );
		remove_role( $slug );
		self::fire(
			'role.deleted',
			$actor,
			$slug,
			array(
				'name' => $before['name'],
				'caps' => $before['capabilities'],
			),
			array()
		);
		return true;
	}

	/** @return true|\WP_Error */
	public static function reset_role( int $actor, string $slug ) {
		$defaults = Defaults::for_role( $slug );
		if ( null === $defaults ) {
			return new \WP_Error( 'rolegate_not_core_role', __( 'Only the WordPress core roles can be reset.', 'role-gatekeeper' ) );
		}
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ) );
		}
		if ( 'administrator' === $slug ) {
			foreach ( Caps::all() as $cap ) {
				$defaults[ $cap ] = true;
			}
		}
		return self::apply_role_caps( $actor, $slug, $defaults );
	}

	/**
	 * @param array<string,bool> $new Full new cap set.
	 * @return true|\WP_Error
	 */
	public static function apply_role_caps( int $actor, string $slug, array $new ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$current = Guard::normalize_caps( (array) $role->capabilities );
		$new     = Guard::normalize_caps( $new );
		$ok      = Gate::modify_role( $actor, $slug, $new );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		if ( $current === $new ) {
			return true;
		}
		foreach ( array_keys( array_diff_key( $current, $new ) ) as $cap ) {
			$role->remove_cap( $cap );
		}
		foreach ( $new as $cap => $grant ) {
			if ( ! array_key_exists( $cap, $current ) || $current[ $cap ] !== $grant ) {
				$role->add_cap( $cap, $grant );
			}
		}
		self::fire( 'caps.updated', $actor, $slug, array( 'caps' => $current ), array( 'caps' => $new ) );
		return true;
	}

	/**
	 * @param string[] $add    Caps to grant.
	 * @param string[] $remove Caps to take away.
	 * @param string[] $deny   Caps to deny explicitly.
	 * @return true|\WP_Error
	 */
	public static function change_role_caps( int $actor, string $slug, array $add, array $remove, array $deny = array() ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$new = Guard::normalize_caps( (array) $role->capabilities );
		foreach ( $add as $cap ) {
			$cap = self::clean_cap( (string) $cap, $new );
			if ( is_wp_error( $cap ) ) {
				return $cap;
			}
			$new[ $cap ] = true;
		}
		foreach ( $deny as $cap ) {
			$cap = self::clean_cap( (string) $cap, $new );
			if ( is_wp_error( $cap ) ) {
				return $cap;
			}
			$new[ $cap ] = false;
		}
		foreach ( $remove as $cap ) {
			unset( $new[ strtolower( trim( (string) $cap ) ) ] );
		}
		return self::apply_role_caps( $actor, $slug, $new );
	}

	/** @return array<string,string[]> capability => role slugs that grant it */
	public static function caps_by_role(): array {
		$out = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			foreach ( Guard::normalize_caps( (array) $data['capabilities'] ) as $cap => $grant ) {
				if ( $grant ) {
					$out[ $cap ][] = (string) $slug;
				} elseif ( ! isset( $out[ $cap ] ) ) {
					$out[ $cap ] = array();
				}
			}
		}
		ksort( $out );
		return $out;
	}

	/** @return array{id:int,login:string,roles:string[],direct:array<string,bool>,capabilities:string[]}|\WP_Error */
	public static function user_summary( int $user_id, int $actor = 0 ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$ok = Gate::site_member( $actor, $user_id );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$caps = array_keys( Guard::user_caps( $user_id ) );
		sort( $caps );
		return array(
			'id'           => $user_id,
			'login'        => (string) $user->user_login,
			'roles'        => array_values( (array) $user->roles ),
			'direct'       => self::direct_caps( $user ),
			'capabilities' => $caps,
		);
	}

	/** @return true|\WP_Error */
	public static function assign_role( int $actor, int $target, string $role ) {
		$user = get_userdata( $target );
		if ( ! $user ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$ok = Gate::site_member( $actor, $target );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		if ( in_array( $role, (array) $user->roles, true ) ) {
			return new \WP_Error( 'rolegate_already_has_role', __( 'The user already has that role.', 'role-gatekeeper' ) );
		}
		foreach ( array( Gate::promote_user( $actor, $target ), Gate::assign_role( $actor, $role, $target ), Gate::act_on_user( $actor, $target ) ) as $ok ) {
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
		}
		$before = array_values( (array) $user->roles );
		$after  = array_merge( $before, array( $role ) );
		$ok     = Gate::self_lockout( $actor, $target, $after, self::direct_caps( $user ) );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$user->add_role( $role );
		self::fire( 'user.roles', $actor, (string) $target, array( 'roles' => $before ), array( 'roles' => array_values( (array) get_userdata( $target )->roles ) ) );
		return true;
	}

	/** @return true|\WP_Error */
	public static function unassign_role( int $actor, int $target, string $role ) {
		$user = get_userdata( $target );
		if ( ! $user ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ), array( 'status' => 404 ) );
		}
		$ok = Gate::site_member( $actor, $target );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		if ( ! in_array( $role, (array) $user->roles, true ) ) {
			return new \WP_Error( 'rolegate_user_lacks_role', __( 'The user doesn\'t have that role.', 'role-gatekeeper' ) );
		}
		foreach ( array( Gate::promote_user( $actor, $target ), Gate::act_on_user( $actor, $target ) ) as $ok ) {
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
		}
		$before = array_values( (array) $user->roles );
		$after  = array_values( array_diff( $before, array( $role ) ) );
		$ok     = Users::check_last_admin( $target, $before, $after );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$ok     = Gate::self_lockout( $actor, $target, $after, self::direct_caps( $user ) );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$user->remove_role( $role );
		self::fire( 'user.roles', $actor, (string) $target, array( 'roles' => $before ), array( 'roles' => array_values( (array) get_userdata( $target )->roles ) ) );
		return true;
	}

	/** @param string[] $roles Empty exports every role. */
	public static function export_data( array $roles = array() ): array {
		$out = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			if ( $roles && ! in_array( $slug, $roles, true ) ) {
				continue;
			}
			$out[ $slug ] = array(
				'name'         => (string) $data['name'],
				'capabilities' => Guard::normalize_caps( (array) $data['capabilities'] ),
			);
		}
		return array(
			'format'      => self::FORMAT,
			'version'     => self::VERSION,
			'exported_at' => gmdate( 'c' ),
			'roles'       => $out,
		);
	}

	/**
	 * Direct import path, used when the portability module's importer can't run (no actor, or
	 * its class is missing). Same rules: protected roles and the actor's own roles are never
	 * overwritten, critical caps the role doesn't already have are stripped, every role passes
	 * the Guard, and nothing is written unless every selected role passes.
	 *
	 * @return array{rows:array<string,array>,rejected:string[],applied:string[]}|\WP_Error
	 */
	public static function import_json( int $actor, string $json, bool $dry_run ) {
		$data = json_decode( trim( $json ), true, 8 );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
			return new \WP_Error( 'rolegate_import_json', __( 'The file is not valid JSON.', 'role-gatekeeper' ) );
		}
		if ( ( $data['format'] ?? '' ) !== self::FORMAT || ! isset( $data['version'] ) || ! is_int( $data['version'] ) || $data['version'] < 1 || $data['version'] > self::VERSION ) {
			return new \WP_Error( 'rolegate_import_format', __( 'This is not a Role Gatekeeper role file this version understands.', 'role-gatekeeper' ) );
		}
		if ( ! isset( $data['roles'] ) || ! is_array( $data['roles'] ) || count( $data['roles'] ) > 100 ) {
			return new \WP_Error( 'rolegate_import_schema', __( 'The file has no usable roles list.', 'role-gatekeeper' ) );
		}

		$user        = $actor > 0 ? get_userdata( $actor ) : false;
		$actor_roles = $user ? (array) $user->roles : array();
		$rows        = array();
		$rejected    = array();
		foreach ( $data['roles'] as $slug => $def ) {
			$slug = strtolower( (string) $slug );
			if ( ! is_array( $def ) || ! isset( $def['capabilities'] ) || ! is_array( $def['capabilities'] ) || count( $def['capabilities'] ) > 1000 ) {
				$rejected[] = $slug . ': no capability list';
				continue;
			}
			$exists = (bool) get_role( $slug );
			if ( ! $exists ) {
				$valid = Guard::valid_new_role_slug( $slug );
				if ( is_wp_error( $valid ) ) {
					$rejected[] = $slug . ': ' . $valid->get_error_message();
					continue;
				}
			}
			$incoming = array();
			foreach ( $def['capabilities'] as $cap => $grant ) {
				if ( is_int( $cap ) ) {
					$cap   = is_string( $grant ) ? $grant : '';
					$grant = true;
				}
				$clean = Guard::sanitize_cap_name( (string) $cap );
				if ( false === $clean || $clean !== (string) $cap || ( ! is_bool( $grant ) && 0 !== $grant && 1 !== $grant ) ) {
					if ( ! Guard::cap_exists( (string) $cap ) ) {
						$rejected[] = $slug . ': invalid capability ' . substr( preg_replace( '/[^\x20-\x7E]/', '?', (string) $cap ), 0, 60 );
						continue;
					}
				}
				$incoming[ (string) $cap ] = (bool) $grant;
			}
			$before   = $exists ? Guard::normalize_caps( (array) get_role( $slug )->capabilities ) : array();
			$stripped = array();
			$final    = $incoming;
			foreach ( array_keys( $final ) as $cap ) {
				if ( ! empty( $final[ $cap ] ) && empty( $before[ $cap ] ) && Guard::is_critical_cap( (string) $cap ) ) {
					$stripped[] = (string) $cap;
					unset( $final[ $cap ] );
				}
			}
			$name = isset( $def['name'] ) && is_string( $def['name'] ) && '' !== trim( $def['name'] ) ? mb_substr( sanitize_text_field( $def['name'] ), 0, 191 ) : $slug;
			$row  = array(
				'slug'     => $slug,
				'name'     => $name,
				'action'   => $exists ? ( $before === $final ? 'unchanged' : 'overwrite' ) : 'create',
				'added'    => array_keys( array_filter( array_diff_key( $final, array_filter( $before ) ) ) ),
				'removed'  => array_keys( array_filter( array_diff_key( array_filter( $before ), array_filter( $final ) ) ) ),
				'stripped' => $stripped,
				'blocked'  => '',
				'final'    => $final,
			);
			if ( $exists && Guard::is_protected_role( $slug ) ) {
				$row['blocked'] = __( 'Protected role. Imports never overwrite it.', 'role-gatekeeper' );
			} elseif ( in_array( $slug, $actor_roles, true ) ) {
				$row['blocked'] = __( 'This is the acting user\'s own role. Imports never overwrite it.', 'role-gatekeeper' );
			} elseif ( 'unchanged' !== $row['action'] ) {
				$check = Gate::modify_role( $actor, $slug, $final );
				if ( is_wp_error( $check ) ) {
					$row['blocked'] = $check->get_error_message();
				}
			}
			$rows[ $slug ] = $row;
		}

		$applied = array();
		if ( ! $dry_run ) {
			foreach ( $rows as $row ) {
				if ( $row['blocked'] ) {
					return new \WP_Error( 'rolegate_import_blocked', sprintf( /* translators: 1: role slug, 2: reason */ __( 'Nothing was imported. Role %1$s: %2$s', 'role-gatekeeper' ), $row['slug'], $row['blocked'] ), array( 'rows' => $rows ) );
				}
			}
			$changes_before = array();
			$changes_after  = array();
			foreach ( $rows as $slug => $row ) {
				if ( 'unchanged' === $row['action'] ) {
					continue;
				}
				if ( 'create' === $row['action'] ) {
					add_role( $slug, $row['name'], $row['final'] );
					self::fire(
						'role.created',
						$actor,
						$slug,
						array(),
						array(
							'name' => $row['name'],
							'caps' => $row['final'],
						)
					);
					$changes_before[ $slug ] = array();
				} else {
					$role                    = get_role( $slug );
					$changes_before[ $slug ] = Guard::normalize_caps( (array) $role->capabilities );
					foreach ( array_keys( array_diff_key( $changes_before[ $slug ], $row['final'] ) ) as $cap ) {
						$role->remove_cap( $cap );
					}
					foreach ( $row['final'] as $cap => $grant ) {
						if ( ! array_key_exists( $cap, $changes_before[ $slug ] ) || $changes_before[ $slug ][ $cap ] !== $grant ) {
							$role->add_cap( $cap, $grant );
						}
					}
					self::fire( 'caps.updated', $actor, $slug, array( 'caps' => $changes_before[ $slug ] ), array( 'caps' => $row['final'] ) );
				}
				$changes_after[ $slug ] = $row['final'];
				$applied[]              = $slug;
			}
			if ( $applied ) {
				self::fire( 'import.applied', $actor, implode( ',', $applied ), array( 'roles' => $changes_before ), array( 'roles' => $changes_after ) );
			}
		}
		return array(
			'rows'     => $rows,
			'rejected' => $rejected,
			'applied'  => $applied,
		);
	}

	public static function slug_from( string $name ): string {
		return sanitize_key( str_replace( ' ', '_', strtolower( $name ) ) );
	}

	public static function role_name( string $slug ): string {
		$names = wp_roles()->role_names;
		return isset( $names[ $slug ] ) ? (string) $names[ $slug ] : $slug;
	}

	/** @return array<string,bool> */
	private static function direct_caps( \WP_User $user ): array {
		$out = array();
		foreach ( (array) $user->caps as $cap => $grant ) {
			if ( ! in_array( $cap, (array) $user->roles, true ) ) {
				$out[ (string) $cap ] = (bool) $grant;
			}
		}
		return $out;
	}

	/**
	 * @param array<string,bool> $current
	 * @return string|\WP_Error
	 */
	private static function clean_cap( string $cap, array $current ) {
		$cap = strtolower( trim( $cap ) );
		if ( array_key_exists( $cap, $current ) ) {
			return $cap;
		}
		$clean = Guard::sanitize_cap_name( $cap );
		if ( false === $clean ) {
			if ( Guard::cap_exists( $cap ) ) {
				return $cap;
			}
			return new \WP_Error(
				'rolegate_invalid_cap',
				/* translators: %s: capability name */
				sprintf( __( 'Not a valid capability name: %s.', 'role-gatekeeper' ), substr( preg_replace( '/[^\x20-\x7E]/', '?', $cap ), 0, 60 ) )
			);
		}
		return $clean;
	}

	public static function fire( string $type, int $actor, string $target, array $before, array $after ): void {
		do_action(
			'rolegate_changed',
			$type,
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => $before,
				'after'  => $after,
			)
		);
	}
}
