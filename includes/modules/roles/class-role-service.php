<?php
namespace Rolewright\Modules\Roles;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Enforcer;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Role_Service {
	const OPTION_BACKUPS = 'rolewright_roles_backups';
	const OPTION_EXTRA   = 'rolewright_extra_default_roles';
	const MAX_BACKUPS    = 5;
	const CORE_ROLES     = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );

	/** @return string|\WP_Error slug */
	public static function create( int $actor, string $name, array $caps = array( 'read' => true ) ) {
		$name = trim( wp_strip_all_tags( $name ) );
		$slug = self::slug_from( $name );
		if ( '' === $name || '' === $slug ) {
			return new \WP_Error( 'rolewright_invalid_name', __( 'Enter a role name.', 'rolewright' ) );
		}
		$valid = Guard::valid_new_role_slug( $slug );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$caps = Guard::normalize_caps( $caps );
		$ok   = Guard::assert_can_modify_role( $actor, $slug, $caps );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		Role_Store::add( $slug, $name, $caps );
		do_action(
			'rolewright_changed',
			'role.created',
			array(
				'actor'  => $actor,
				'target' => $slug,
				'before' => array(),
				'after'  => array(
					'name' => $name,
					'caps' => $caps,
				),
			)
		);
		return $slug;
	}

	/** @return string|\WP_Error slug of the copy */
	public static function clone_role( int $actor, string $source, string $name ) {
		if ( ! get_role( $source ) ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
		}
		$veto = apply_filters( 'rolewright_role_change_veto', null, 'clone', $actor, $source );
		if ( $veto instanceof \WP_Error ) {
			return $veto;
		}
		return self::create( $actor, $name, Role_Store::caps( $source ) );
	}

	/** @return true|\WP_Error */
	public static function rename( int $actor, string $role, string $name ) {
		$name = trim( wp_strip_all_tags( $name ) );
		if ( '' === $name ) {
			return new \WP_Error( 'rolewright_invalid_name', __( 'Enter a role name.', 'rolewright' ) );
		}
		if ( ! get_role( $role ) ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
		}
		$ok = Guard::assert_can_rename_role( $actor, $role );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$before = Role_Store::name( $role );
		Role_Store::rename( $role, $name );
		do_action(
			'rolewright_changed',
			'role.renamed',
			array(
				'actor'  => $actor,
				'target' => $role,
				'before' => array( 'name' => $before ),
				'after'  => array( 'name' => $name ),
			)
		);
		return true;
	}

	/** @return true|\WP_Error */
	public static function delete( int $actor, string $role ) {
		$ok = Guard::assert_can_delete_role( $actor, $role );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$counts = Role_Store::user_counts();
		if ( ! empty( $counts[ $role ] ) ) {
			return new \WP_Error(
				'rolewright_role_in_use',
				/* translators: %s: role name */
				sprintf( __( 'The %s role still has users. Move them to another role first.', 'rolewright' ), Role_Store::name( $role ) )
			);
		}
		$before = array(
			'name' => Role_Store::name( $role ),
			'caps' => Role_Store::caps( $role ),
		);
		Role_Store::remove( $role );
		self::forget_extra_default( $role );
		do_action(
			'rolewright_changed',
			'role.deleted',
			array(
				'actor'  => $actor,
				'target' => $role,
				'before' => $before,
				'after'  => array(),
			)
		);
		return true;
	}

	/**
	 * @param string[] $roles
	 * @return array{deleted:string[],errors:array<string,string>}
	 */
	public static function delete_unused( int $actor, array $roles ): array {
		$out = array(
			'deleted' => array(),
			'errors'  => array(),
		);
		foreach ( array_unique( $roles ) as $role ) {
			$res = self::delete( $actor, (string) $role );
			if ( is_wp_error( $res ) ) {
				$out['errors'][ $role ] = $res->get_error_message();
			} else {
				$out['deleted'][] = $role;
			}
		}
		return $out;
	}

	/** @return string[] */
	public static function extra_default_roles(): array {
		$stored = get_option( self::OPTION_EXTRA, array() );
		return is_array( $stored ) ? array_values( array_filter( array_map( 'strval', $stored ) ) ) : array();
	}

	/**
	 * Roles that hold a critical capability can't be handed out at registration.
	 *
	 * @param string[] $extras
	 * @return true|\WP_Error
	 */
	public static function set_default( int $actor, string $role, array $extras = array() ) {
		$extras = array_values( array_diff( array_unique( $extras ), array( $role ) ) );
		foreach ( array_merge( array( $role ), $extras ) as $r ) {
			if ( ! get_role( $r ) ) {
				return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
			}
			if ( Guard::critical_subset( Role_Store::caps( $r ) ) ) {
				return new \WP_Error(
					'rolewright_default_too_powerful',
					/* translators: %s: role name */
					sprintf( __( 'The %s role holds powerful capabilities and can\'t be given to new registrations.', 'rolewright' ), Role_Store::name( $r ) )
				);
			}
			if ( ! Guard::can_assign_role( $actor, $r, 0 ) ) {
				return new \WP_Error(
					'rolewright_cannot_assign',
					/* translators: %s: role name */
					sprintf( __( 'You can\'t assign the %s role.', 'rolewright' ), Role_Store::name( $r ) )
				);
			}
		}
		$before = array(
			'default' => (string) get_option( 'default_role' ),
			'extras'  => self::extra_default_roles(),
		);
		update_option( 'default_role', $role );
		update_option( self::OPTION_EXTRA, $extras, false );
		do_action(
			'rolewright_changed',
			'role.default_set',
			array(
				'actor'  => $actor,
				'target' => $role,
				'before' => $before,
				'after'  => array(
					'default' => $role,
					'extras'  => $extras,
				),
			)
		);
		return true;
	}

	/** @param int $user_id */
	public static function apply_extra_defaults( $user_id ): void {
		$extras = self::extra_default_roles();
		$user   = $extras ? get_userdata( (int) $user_id ) : false;
		if ( ! $user ) {
			return;
		}
		Enforcer::as_system(
			function () use ( $user, $extras ) {
				foreach ( $extras as $role ) {
					if ( get_role( $role ) && ! Guard::critical_subset( Role_Store::caps( $role ) ) && ! in_array( $role, (array) $user->roles, true ) ) {
						$user->add_role( $role );
					}
				}
			}
		);
	}

	/**
	 * Core roles go back to WordPress defaults and custom roles stay as they are. The roles
	 * stored before the reset are kept as a backup.
	 *
	 * @return true|\WP_Error
	 */
	public static function reset( int $actor ) {
		$defaults = self::core_defaults();
		$ok       = self::assert_can_reset( $actor, $defaults );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}

		$before = Role_Store::all();
		$backup = self::store_backup( $actor, $before );

		$custom = array();
		foreach ( $before as $slug => $data ) {
			if ( ! in_array( $slug, self::CORE_ROLES, true ) ) {
				$custom[ $slug ] = array(
					'name'         => $data['name'],
					'capabilities' => $data['caps'],
				);
			}
		}

		Enforcer::as_system(
			function () use ( $custom, $defaults ) {
				$roles = $defaults;
				foreach ( $custom as $slug => $data ) {
					$roles[ $slug ] = $data;
				}
				Role_Store::replace_all( $roles );
				Caps::grant_to_administrator();
			}
		);

		if ( Guard::would_lock_out( $actor, array() ) ) {
			Enforcer::as_system(
				function () use ( $before ) {
					$restore = array();
					foreach ( $before as $slug => $data ) {
						$restore[ $slug ] = array(
							'name'         => $data['name'],
							'capabilities' => $data['caps'],
						);
					}
					Role_Store::replace_all( $restore );
				}
			);
			self::drop_backup( $backup );
			return new \WP_Error( 'rolewright_lockout', __( 'The reset would lock you out of Rolewright, so the roles were put back as they were.', 'rolewright' ) );
		}

		do_action(
			'rolewright_changed',
			'roles.reset',
			array(
				'actor'  => $actor,
				'target' => 'core',
				'before' => array( 'roles' => $before ),
				'after'  => array( 'roles' => Role_Store::all() ),
			)
		);
		return true;
	}

	/**
	 * WordPress's default core roles, built in a throwaway WP_Roles so the live roles and
	 * the stored option are untouched.
	 *
	 * @return array<string,array{name:string,capabilities:array<string,bool>}>
	 */
	public static function core_defaults(): array {
		require_once ABSPATH . 'wp-admin/includes/schema.php';
		global $wp_roles;
		$live              = $wp_roles;
		$tmp               = new \WP_Roles();
		$tmp->use_db       = false;
		$tmp->roles        = array();
		$tmp->role_objects = array();
		$tmp->role_names   = array();
		$wp_roles          = $tmp; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- restored below.
		try {
			populate_roles();
			$roles = $tmp->roles;
		} finally {
			$wp_roles = $live; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
		$out = array();
		foreach ( self::CORE_ROLES as $slug ) {
			if ( isset( $roles[ $slug ] ) ) {
				$out[ $slug ] = array(
					'name'         => (string) $roles[ $slug ]['name'],
					'capabilities' => Guard::normalize_caps( (array) $roles[ $slug ]['capabilities'] ),
				);
			}
		}
		if ( isset( $out['administrator'] ) ) {
			foreach ( Caps::all() as $cap ) {
				$out['administrator']['capabilities'][ $cap ] = true;
			}
		}
		return $out;
	}

	/**
	 * A reset rewrites every core role, so the actor must be a super admin or hold every
	 * critical cap the defaults carry, and each core role's new cap set must pass the Guard.
	 *
	 * @param array<string,array{name:string,capabilities:array<string,bool>}> $defaults
	 * @return true|\WP_Error
	 */
	private static function assert_can_reset( int $actor, array $defaults ) {
		if ( ! $defaults ) {
			return new \WP_Error( 'rolewright_reset_failed', __( 'The default roles could not be built, so nothing was changed.', 'rolewright' ) );
		}
		if ( ! Guard::is_super( $actor ) ) {
			$needed = array();
			foreach ( $defaults as $data ) {
				$needed = array_merge( $needed, Guard::critical_subset( $data['capabilities'] ) );
			}
			$lacking = Guard::missing( array_values( array_unique( $needed ) ), Guard::user_caps( $actor ) );
			if ( $lacking ) {
				return new \WP_Error(
					'rolewright_role_above_actor',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'Resetting the core roles needs every capability they carry by default, and you don\'t hold these: %s.', 'rolewright' ), implode( ', ', $lacking ) )
				);
			}
		}
		foreach ( $defaults as $slug => $data ) {
			$ok = Guard::assert_can_modify_role( $actor, $slug, $data['capabilities'] );
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
		}
		return true;
	}

	/** @return array<int,array{id:string,time:int,actor:int,roles:array}> */
	public static function backups(): array {
		$stored = get_option( self::OPTION_BACKUPS, array() );
		return is_array( $stored ) ? $stored : array();
	}

	public static function slug_from( string $name ): string {
		$slug = sanitize_key( str_replace( ' ', '_', strtolower( $name ) ) );
		return preg_match( '/^\d+$/', $slug ) ? '' : $slug;
	}

	private static function store_backup( int $actor, array $roles ): string {
		$id      = wp_generate_password( 12, false );
		$backups = self::backups();
		array_unshift(
			$backups,
			array(
				'id'    => $id,
				'time'  => time(),
				'actor' => $actor,
				'roles' => $roles,
			)
		);
		update_option( self::OPTION_BACKUPS, array_slice( $backups, 0, self::MAX_BACKUPS ), false );
		return $id;
	}

	private static function drop_backup( string $id ): void {
		$keep = array();
		foreach ( self::backups() as $b ) {
			if ( $b['id'] !== $id ) {
				$keep[] = $b;
			}
		}
		update_option( self::OPTION_BACKUPS, $keep, false );
	}

	private static function forget_extra_default( string $role ): void {
		$extras = self::extra_default_roles();
		if ( in_array( $role, $extras, true ) ) {
			update_option( self::OPTION_EXTRA, array_values( array_diff( $extras, array( $role ) ) ), false );
		}
	}
}
