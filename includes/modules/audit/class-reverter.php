<?php
namespace Rolewright\Modules\Audit;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Restores the state before a logged change, through the same Guard assertions the original
 * change needed. The result fires rolewright_changed with revert_of, which the recorder logs.
 */
final class Reverter {
	const TYPES = array( 'role.created', 'role.deleted', 'role.renamed', 'caps.updated', 'user.roles', 'user.caps', 'roles.reset', 'role.default_set' );

	/** Capabilities the actor needs, per type. */
	public static function required_caps( string $type ): array {
		switch ( $type ) {
			case 'role.created':
			case 'role.deleted':
			case 'role.renamed':
			case 'roles.reset':
			case 'role.default_set':
				return array( Caps::VIEW_AUDIT, Caps::MANAGE_ROLES );
			case 'caps.updated':
				return array( Caps::VIEW_AUDIT, Caps::MANAGE_CAPS );
			case 'user.roles':
				return array( Caps::VIEW_AUDIT, Caps::MANAGE_USERS );
			case 'user.caps':
				return array( Caps::VIEW_AUDIT, Caps::MANAGE_USERS, Caps::MANAGE_CAPS );
		}
		return array();
	}

	public static function can_revert_row( object $row ): bool {
		return in_array( $row->type, self::TYPES, true ) && 0 === (int) $row->reverted_by;
	}

	/** @return true|\WP_Error */
	public static function revert( int $entry_id, int $actor ) {
		$row = Store::get( $entry_id );
		if ( ! $row ) {
			return new \WP_Error( 'rolewright_audit_missing', __( 'That log entry no longer exists.', 'rolewright' ) );
		}
		if ( ! in_array( $row->type, self::TYPES, true ) ) {
			return new \WP_Error( 'rolewright_audit_not_revertible', __( 'This kind of entry can\'t be reverted.', 'rolewright' ) );
		}
		if ( (int) $row->reverted_by > 0 ) {
			return new \WP_Error( 'rolewright_audit_already_reverted', __( 'This entry was already reverted.', 'rolewright' ) );
		}
		foreach ( self::required_caps( $row->type ) as $cap ) {
			if ( ! user_can( $actor, $cap ) ) {
				return new \WP_Error( 'rolewright_audit_forbidden', __( 'You don\'t have permission to revert this change.', 'rolewright' ) );
			}
		}

		$diff   = json_decode( (string) $row->diff, true );
		$diff   = is_array( $diff ) ? $diff : array();
		$detail = json_decode( (string) $row->detail, true );
		$detail = is_array( $detail ) ? $detail : array();

		switch ( $row->type ) {
			case 'role.created':
				return self::revert_created( $entry_id, $actor, (string) $row->target );
			case 'role.deleted':
				return self::revert_deleted( $entry_id, $actor, (string) $row->target, $diff, $detail );
			case 'role.renamed':
				return self::revert_renamed( $entry_id, $actor, (string) $row->target, $detail );
			case 'caps.updated':
				return self::revert_role_caps( $entry_id, $actor, (string) $row->target, $diff );
			case 'user.roles':
				return self::revert_user_roles( $entry_id, $actor, (int) $row->target, $diff );
			case 'roles.reset':
				return self::revert_roles_reset( $entry_id, $actor, $diff, $detail );
			case 'role.default_set':
				return self::revert_default_set( $entry_id, $actor, $detail );
			case 'user.caps':
				return self::revert_user_caps( $entry_id, $actor, (int) $row->target, $diff );
		}
		return new \WP_Error( 'rolewright_audit_not_revertible', __( 'This kind of entry can\'t be reverted.', 'rolewright' ) );
	}

	/** @return true|\WP_Error */
	private static function revert_created( int $entry_id, int $actor, string $slug ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist any more.', 'rolewright' ) );
		}
		$users = get_users(
			array(
				'role'   => $slug,
				'number' => 1,
				'fields' => 'ID',
			)
		);
		if ( $users ) {
			return new \WP_Error( 'rolewright_role_in_use', __( 'The role still has users. Move them to another role first.', 'rolewright' ) );
		}
		$ok = Guard::assert_can_delete_role( $actor, $slug );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$before = array(
			'name' => self::role_name( $slug ),
			'caps' => Guard::normalize_caps( (array) $role->capabilities ),
		);
		remove_role( $slug );
		self::announce( 'role.deleted', $entry_id, $actor, $slug, $before, array() );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_deleted( int $entry_id, int $actor, string $slug, array $diff, array $detail ) {
		if ( get_role( $slug ) ) {
			return new \WP_Error( 'rolewright_role_exists', __( 'A role with that name already exists.', 'rolewright' ) );
		}
		$caps = Diff::undo_caps( array(), (array) ( $diff['caps'] ?? array() ) );
		$ok   = Guard::assert_can_modify_role( $actor, $slug, $caps );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$label = isset( $detail['label'] ) && '' !== $detail['label'] ? (string) $detail['label'] : $slug;
		add_role( $slug, $label, $caps );
		self::announce(
			'role.created',
			$entry_id,
			$actor,
			$slug,
			array(),
			array(
				'name' => $label,
				'caps' => $caps,
			)
		);
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_renamed( int $entry_id, int $actor, string $slug, array $detail ) {
		$old = isset( $detail['old_label'] ) ? (string) $detail['old_label'] : '';
		if ( '' === $old ) {
			return new \WP_Error( 'rolewright_audit_not_revertible', __( 'The previous name was not recorded.', 'rolewright' ) );
		}
		if ( ! get_role( $slug ) ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist any more.', 'rolewright' ) );
		}
		$ok = Guard::assert_can_rename_role( $actor, $slug );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$current = self::role_name( $slug );
		$roles   = wp_roles();
		$roles->roles[ $slug ]['name'] = $old;
		$roles->role_names[ $slug ]    = $old;
		update_option( $roles->role_key, $roles->roles );
		self::announce( 'role.renamed', $entry_id, $actor, $slug, array( 'name' => $current ), array( 'name' => $old ) );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_role_caps( int $entry_id, int $actor, string $slug, array $diff ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist any more.', 'rolewright' ) );
		}
		$current = Guard::normalize_caps( (array) $role->capabilities );
		$new     = Diff::undo_caps( $current, (array) ( $diff['caps'] ?? array() ) );
		$ok      = Guard::assert_can_modify_role( $actor, $slug, $new );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		foreach ( array_keys( array_diff_key( $current, $new ) ) as $cap ) {
			$role->remove_cap( $cap );
		}
		foreach ( $new as $cap => $grant ) {
			if ( ! array_key_exists( $cap, $current ) || $current[ $cap ] !== $grant ) {
				$role->add_cap( $cap, $grant );
			}
		}
		self::announce( 'caps.updated', $entry_id, $actor, $slug, array( 'caps' => $current ), array( 'caps' => $new ) );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_user_roles( int $entry_id, int $actor, int $target, array $diff ) {
		$user = get_userdata( $target );
		if ( ! $user ) {
			return new \WP_Error( 'rolewright_no_user', __( 'That user does not exist any more.', 'rolewright' ) );
		}
		$add    = array_map( 'strval', (array) ( $diff['roles']['removed'] ?? array() ) );
		$remove = array_map( 'strval', (array) ( $diff['roles']['added'] ?? array() ) );
		$before = array_values( (array) $user->roles );
		$after  = array_values( array_unique( array_merge( array_diff( $before, $remove ), $add ) ) );
		if ( ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolewright_user_above_actor', __( 'You can\'t change a user who holds capabilities you don\'t have.', 'rolewright' ) );
		}
		foreach ( $add as $role ) {
			if ( ! get_role( $role ) ) {
				return new \WP_Error( 'rolewright_no_role', __( 'A role from this entry does not exist any more.', 'rolewright' ) );
			}
			if ( ! Guard::can_assign_role( $actor, $role, $target ) ) {
				return new \WP_Error( 'rolewright_cannot_assign', __( 'You can\'t assign a role from this entry.', 'rolewright' ) );
			}
		}
		$lock = self::self_lockout( $actor, $target, $after, null, $user );
		if ( is_wp_error( $lock ) ) {
			return $lock;
		}
		foreach ( $remove as $role ) {
			$user->remove_role( $role );
		}
		foreach ( $add as $role ) {
			$user->add_role( $role );
		}
		self::announce( 'user.roles', $entry_id, $actor, (string) $target, array( 'roles' => $before ), array( 'roles' => array_values( (array) get_userdata( $target )->roles ) ) );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_user_caps( int $entry_id, int $actor, int $target, array $diff ) {
		$user = get_userdata( $target );
		if ( ! $user ) {
			return new \WP_Error( 'rolewright_no_user', __( 'That user does not exist any more.', 'rolewright' ) );
		}
		$current = array();
		foreach ( (array) $user->caps as $cap => $grant ) {
			if ( ! in_array( $cap, (array) $user->roles, true ) ) {
				$current[ (string) $cap ] = (bool) $grant;
			}
		}
		$new = Diff::undo_caps( $current, (array) ( $diff['caps'] ?? array() ) );
		if ( ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolewright_user_above_actor', __( 'You can\'t change a user who holds capabilities you don\'t have.', 'rolewright' ) );
		}
		foreach ( $new as $cap => $grant ) {
			if ( $grant && empty( $current[ $cap ] ) && ! Guard::can_grant_cap( $actor, $cap ) ) {
				return new \WP_Error(
					'rolewright_cap_not_held',
					/* translators: %s: capability name */
					sprintf( __( 'You can\'t grant a capability you don\'t hold yourself: %s.', 'rolewright' ), $cap )
				);
			}
		}
		$lock = self::self_lockout( $actor, $target, array_values( (array) $user->roles ), $new, $user );
		if ( is_wp_error( $lock ) ) {
			return $lock;
		}
		foreach ( array_keys( array_diff_key( $current, $new ) ) as $cap ) {
			$user->remove_cap( $cap );
		}
		foreach ( $new as $cap => $grant ) {
			if ( ! array_key_exists( $cap, $current ) || $current[ $cap ] !== $grant ) {
				$user->add_cap( $cap, $grant );
			}
		}
		self::announce( 'user.caps', $entry_id, $actor, (string) $target, array( 'caps' => $current ), array( 'caps' => $new ) );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_roles_reset( int $entry_id, int $actor, array $diff, array $detail ) {
		$plan = (array) ( $diff['role_caps'] ?? array() );
		if ( ! $plan ) {
			return new \WP_Error( 'rolewright_audit_not_revertible', __( 'Nothing was recorded to restore.', 'rolewright' ) );
		}
		$proposed = array();
		$current  = array();
		foreach ( $plan as $slug => $d ) {
			$slug              = (string) $slug;
			$role              = get_role( $slug );
			$current[ $slug ]  = $role ? Guard::normalize_caps( (array) $role->capabilities ) : array();
			$proposed[ $slug ] = Diff::undo_caps( $current[ $slug ], (array) $d );
			$ok                = Guard::assert_can_modify_role( $actor, $slug, $proposed[ $slug ] );
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
		}
		if ( Guard::lockout_reasons_for( $actor, $proposed ) ) {
			return new \WP_Error( 'rolewright_lockout', __( 'This revert would lock you out of Rolewright.', 'rolewright' ), array( 'reasons' => Guard::lockout_reasons_for( $actor, $proposed ) ) );
		}
		$labels = (array) ( $detail['labels'] ?? array() );
		\Rolewright\Modules\Safety\Enforcer::as_system(
			function () use ( $proposed, $current, $labels ) {
				foreach ( $proposed as $slug => $new ) {
					$role = get_role( $slug );
					if ( ! $role ) {
						add_role( $slug, ! empty( $labels[ $slug ] ) ? (string) $labels[ $slug ] : $slug, $new );
						continue;
					}
					foreach ( array_keys( array_diff_key( $current[ $slug ], $new ) ) as $cap ) {
						$role->remove_cap( $cap );
					}
					foreach ( $new as $cap => $grant ) {
						if ( ! array_key_exists( $cap, $current[ $slug ] ) || $current[ $slug ][ $cap ] !== $grant ) {
							$role->add_cap( $cap, $grant );
						}
					}
				}
			}
		);
		$wrap = function ( array $sets ) {
			$out = array();
			foreach ( $sets as $slug => $caps ) {
				$out[ $slug ] = array( 'caps' => $caps );
			}
			return $out;
		};
		self::announce( 'roles.reset', $entry_id, $actor, 'core', array( 'roles' => $wrap( $current ) ), array( 'roles' => $wrap( $proposed ) ) );
		return true;
	}

	/** @return true|\WP_Error */
	private static function revert_default_set( int $entry_id, int $actor, array $detail ) {
		$default = (string) ( $detail['default_before'] ?? '' );
		$extras  = array_values( array_diff( array_map( 'strval', (array) ( $detail['extras_before'] ?? array() ) ), array( $default ) ) );
		if ( '' === $default ) {
			return new \WP_Error( 'rolewright_audit_not_revertible', __( 'The previous default role was not recorded.', 'rolewright' ) );
		}
		foreach ( array_merge( array( $default ), $extras ) as $role ) {
			$obj = get_role( $role );
			if ( ! $obj ) {
				return new \WP_Error( 'rolewright_no_role', __( 'A role from this entry does not exist any more.', 'rolewright' ) );
			}
			if ( Guard::critical_subset( (array) $obj->capabilities ) ) {
				return new \WP_Error( 'rolewright_cannot_assign', __( 'A role holding critical capabilities can\'t be a default role.', 'rolewright' ) );
			}
		}
		$now_extras = get_option( 'rolewright_extra_default_roles', array() );
		$before     = array(
			'default' => (string) get_option( 'default_role' ),
			'extras'  => is_array( $now_extras ) ? array_values( $now_extras ) : array(),
		);
		update_option( 'default_role', $default );
		update_option( 'rolewright_extra_default_roles', $extras, false );
		self::announce(
			'role.default_set',
			$entry_id,
			$actor,
			$default,
			$before,
			array(
				'default' => $default,
				'extras'  => $extras,
			)
		);
		return true;
	}

	/**
	 * Refuses a change to the actor's own roles or per-user caps that leaves them without read
	 * or Rolewright access.
	 *
	 * @param string[]           $roles
	 * @param array<string,bool>|null $user_caps Null keeps the user's current per-user caps.
	 * @return true|\WP_Error
	 */
	private static function self_lockout( int $actor, int $target, array $roles, ?array $user_caps, \WP_User $user ) {
		if ( $actor !== $target || Guard::is_super( $actor ) ) {
			return true;
		}
		$roles_caps = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles_caps[ $name ] = Guard::normalize_caps( (array) $data['capabilities'] );
		}
		if ( null === $user_caps ) {
			$user_caps = array();
			foreach ( (array) $user->caps as $cap => $grant ) {
				if ( ! in_array( $cap, (array) $user->roles, true ) ) {
					$user_caps[ $cap ] = (bool) $grant;
				}
			}
		}
		$reasons = array_diff( Guard::lockout_reasons( $roles, $user_caps, $roles_caps ), array( 'no_manager_role' ) );
		if ( $reasons ) {
			return new \WP_Error( 'rolewright_lockout', __( 'This revert would lock you out of your own account or of Rolewright.', 'rolewright' ), array( 'reasons' => array_values( $reasons ) ) );
		}
		return true;
	}

	private static function role_name( string $slug ): string {
		$names = wp_roles()->role_names;
		return isset( $names[ $slug ] ) ? (string) $names[ $slug ] : $slug;
	}

	private static function announce( string $type, int $entry_id, int $actor, string $target, array $before, array $after ): void {
		do_action(
			'rolewright_changed',
			$type,
			array(
				'actor'     => $actor,
				'target'    => $target,
				'before'    => $before,
				'after'     => $after,
				'revert_of' => $entry_id,
			)
		);
	}
}
