<?php
namespace Rolewright\Modules\Safety;

defined( 'ABSPATH' ) || exit;

/**
 * The escalation and lockout rules every module codes against. Methods have no side
 * effects; they read the current roles and users and answer a question.
 *
 * "Holding" a cap means the user's roles or per-user caps grant it (WP_User::$allcaps),
 * passed through the `rolewright_guard_user_caps` filter so deny rules can subtract.
 * Constants such as DISALLOW_FILE_MODS are deliberately ignored here.
 */
final class Guard {
	const CAP_MAX_LENGTH = 191;

	/** @var string[] */
	private static $base_critical = array(
		'manage_options',
		'edit_users',
		'create_users',
		'delete_users',
		'promote_users',
		'list_users',
		'remove_users',
		'install_plugins',
		'activate_plugins',
		'update_plugins',
		'delete_plugins',
		'edit_plugins',
		'install_themes',
		'edit_themes',
		'switch_themes',
		'update_themes',
		'delete_themes',
		'edit_files',
		'update_core',
		'unfiltered_html',
		'unfiltered_upload',
		'manage_network',
		'manage_network_users',
		'manage_network_plugins',
		'manage_network_themes',
		'manage_network_options',
		'manage_sites',
		'create_sites',
		'delete_sites',
		'upgrade_network',
		'setup_network',
		'level_8',
		'level_9',
		'level_10',
	);

	/**
	 * Caps whose holder can take over the site. Always includes every rolewright_* cap.
	 * Any cap starting with manage_network or rolewright_ is treated as critical even
	 * when not listed (see is_critical_cap()).
	 *
	 * @return string[]
	 */
	public static function critical_caps(): array {
		$caps = apply_filters( 'rolewright_critical_caps', self::$base_critical );
		$caps = is_array( $caps ) ? array_map( 'strval', $caps ) : self::$base_critical;
		return array_values( array_unique( array_merge( $caps, Caps::all() ) ) );
	}

	public static function is_critical_cap( string $cap ): bool {
		if ( 0 === strpos( $cap, 'rolewright_' ) || 0 === strpos( $cap, 'manage_network' ) ) {
			return true;
		}
		return in_array( $cap, self::critical_caps(), true );
	}

	/**
	 * Accepts a cap list (['read', 'edit_posts']) or a cap map (['read' => true]) and
	 * returns the map form with boolean values.
	 *
	 * @param array $caps
	 * @return array<string,bool>
	 */
	public static function normalize_caps( array $caps ): array {
		$out = array();
		foreach ( $caps as $key => $value ) {
			if ( is_int( $key ) ) {
				$out[ (string) $value ] = true;
			} else {
				$out[ (string) $key ] = (bool) $value;
			}
		}
		return $out;
	}

	/**
	 * The critical caps a cap set grants (denied caps excluded).
	 *
	 * @param array $caps List or map, see normalize_caps().
	 * @return string[]
	 */
	public static function critical_subset( array $caps ): array {
		$out = array();
		foreach ( self::normalize_caps( $caps ) as $cap => $grant ) {
			if ( $grant && self::is_critical_cap( $cap ) ) {
				$out[] = $cap;
			}
		}
		sort( $out );
		return $out;
	}

	/**
	 * Members of $needed that $held does not grant.
	 *
	 * @param string[] $needed
	 * @param array    $held List or map.
	 * @return string[]
	 */
	public static function missing( array $needed, array $held ): array {
		$held = self::normalize_caps( $held );
		$out  = array();
		foreach ( $needed as $cap ) {
			if ( empty( $held[ $cap ] ) ) {
				$out[] = $cap;
			}
		}
		return $out;
	}

	/**
	 * Merges role caps then per-user caps the way WP_User::get_role_caps() does.
	 *
	 * @param string[]                         $role_names  Roles the user has.
	 * @param array<string,array<string,bool>> $roles_caps  role => cap map.
	 * @param array                            $user_caps   Per-user caps (role-name keys are ignored).
	 * @return array<string,bool>
	 */
	public static function caps_from_roles( array $role_names, array $roles_caps, array $user_caps = array() ): array {
		$all = array();
		foreach ( $role_names as $role ) {
			if ( isset( $roles_caps[ $role ] ) && is_array( $roles_caps[ $role ] ) ) {
				$all = array_merge( $all, self::normalize_caps( $roles_caps[ $role ] ) );
			}
		}
		foreach ( self::normalize_caps( $user_caps ) as $cap => $grant ) {
			if ( ! isset( $roles_caps[ $cap ] ) ) {
				$all[ $cap ] = $grant;
			}
		}
		return $all;
	}

	/**
	 * Pure lockout check. Returns reason codes: 'read', 'manage', 'no_manager_role'.
	 *
	 * @param string[]                         $actor_roles
	 * @param array                            $actor_user_caps
	 * @param array<string,array<string,bool>> $roles_after role => cap map after the change.
	 * @return string[]
	 */
	public static function lockout_reasons( array $actor_roles, array $actor_user_caps, array $roles_after ): array {
		$caps    = self::caps_from_roles( $actor_roles, $roles_after, $actor_user_caps );
		$reasons = array();
		if ( empty( $caps['read'] ) ) {
			$reasons[] = 'read';
		}
		if ( empty( $caps[ Caps::MANAGE ] ) ) {
			$reasons[] = 'manage';
		}
		$manager = false;
		foreach ( $roles_after as $role_caps ) {
			$role_caps = self::normalize_caps( (array) $role_caps );
			if ( ! empty( $role_caps[ Caps::MANAGE_ROLES ] ) ) {
				$manager = true;
				break;
			}
		}
		if ( ! $manager ) {
			$reasons[] = 'no_manager_role';
		}
		return $reasons;
	}

	public static function is_super( int $user_id ): bool {
		return $user_id > 0 && is_multisite() && is_super_admin( $user_id );
	}

	/**
	 * Caps the user holds (granted only).
	 *
	 * @return array<string,bool>
	 */
	public static function user_caps( int $user_id ): array {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user ) {
			return array();
		}
		$caps = array();
		foreach ( (array) $user->allcaps as $cap => $grant ) {
			if ( $grant ) {
				$caps[ (string) $cap ] = true;
			}
		}
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			$admin = get_role( 'administrator' );
			foreach ( Caps::all() as $cap ) {
				if ( $admin && ! empty( $admin->capabilities[ $cap ] ) ) {
					$caps[ $cap ] = true;
				}
			}
		}
		$caps = apply_filters( 'rolewright_guard_user_caps', $caps, $user );
		return is_array( $caps ) ? $caps : array();
	}

	/**
	 * @return string[]
	 */
	public static function user_critical_caps( int $user_id ): array {
		if ( self::is_super( $user_id ) ) {
			return self::critical_caps();
		}
		return self::critical_subset( self::user_caps( $user_id ) );
	}

	/**
	 * Roles that need special care: administrator (no delete, rename, or removal of
	 * critical caps) and the default role (no delete).
	 */
	public static function is_protected_role( string $role ): bool {
		return in_array( $role, self::protected_roles(), true );
	}

	/** @return string[] */
	public static function protected_roles(): array {
		$roles   = apply_filters( 'rolewright_protected_roles', array( 'administrator', (string) get_option( 'default_role', 'subscriber' ) ) );
		$roles   = is_array( $roles ) ? array_map( 'strval', $roles ) : array();
		$roles[] = 'administrator';
		return array_values( array_unique( $roles ) );
	}

	/**
	 * True when the actor may act on (edit, promote, delete, remove) the target user:
	 * the target holds no critical cap the actor lacks, and is not a super admin unless
	 * the actor is one.
	 */
	public static function can_act_on_user( int $actor_id, int $target_id ): bool {
		if ( $actor_id === $target_id || self::is_super( $actor_id ) ) {
			return true;
		}
		if ( self::is_super( $target_id ) ) {
			return false;
		}
		if ( self::missing( self::user_critical_caps( $target_id ), self::user_critical_caps( $actor_id ) ) ) {
			return false;
		}
		return (bool) apply_filters( 'rolewright_can_act_on_user', true, $actor_id, $target_id );
	}

	/**
	 * Whether the actor may give $role to $target_id (0 = a user not yet created).
	 * The actor must hold every critical cap the role carries; for themselves, every cap
	 * the role carries; and may not act on a user above them.
	 */
	public static function can_assign_role( int $actor_id, string $role, int $target_id ): bool {
		if ( self::is_super( $actor_id ) ) {
			return true;
		}
		$role_obj = get_role( $role );
		if ( ! $role_obj ) {
			return false;
		}
		$actor_caps = self::user_caps( $actor_id );
		if ( self::missing( self::critical_subset( $role_obj->capabilities ), $actor_caps ) ) {
			return false;
		}
		if ( $target_id > 0 && $target_id === $actor_id ) {
			$granted = array_keys( array_filter( self::normalize_caps( $role_obj->capabilities ) ) );
			if ( self::missing( $granted, $actor_caps ) ) {
				return false;
			}
		} elseif ( $target_id > 0 && ! self::can_act_on_user( $actor_id, $target_id ) ) {
			return false;
		}
		return (bool) apply_filters( 'rolewright_can_assign_role', true, $actor_id, $role, $target_id );
	}

	/**
	 * Whether the actor may hand $cap to a role or user. Critical caps need the actor to
	 * hold them. Other caps need the actor to hold them or hold rolewright_manage_caps
	 * (so new custom caps can be created and handed out).
	 */
	public static function can_grant_cap( int $actor_id, string $cap ): bool {
		if ( self::is_super( $actor_id ) ) {
			return true;
		}
		if ( false === self::sanitize_cap_name( $cap ) && ! self::cap_exists( $cap ) ) {
			return false;
		}
		$held = self::user_caps( $actor_id );
		if ( self::is_critical_cap( $cap ) ) {
			return ! empty( $held[ $cap ] );
		}
		if ( empty( $held[ $cap ] ) && empty( $held[ Caps::MANAGE_CAPS ] ) ) {
			return false;
		}
		return (bool) apply_filters( 'rolewright_can_grant_cap', true, $actor_id, $cap );
	}

	/**
	 * True when applying the change would leave the actor without read, without
	 * rolewright_manage, or leave no role on the site holding rolewright_manage_roles.
	 *
	 * @param array<string,array|null> $proposed_role_caps_by_role role => full new cap
	 *        set (list or map); null means the role is deleted. Roles not listed keep
	 *        their current caps.
	 */
	public static function would_lock_out( int $actor_id, array $proposed_role_caps_by_role ): bool {
		return (bool) self::lockout_reasons_for( $actor_id, $proposed_role_caps_by_role );
	}

	/**
	 * @param array<string,array|null> $proposed_role_caps_by_role
	 * @return string[]
	 */
	public static function lockout_reasons_for( int $actor_id, array $proposed_role_caps_by_role ): array {
		if ( $actor_id <= 0 || self::is_super( $actor_id ) ) {
			return array();
		}
		$user = get_userdata( $actor_id );
		if ( ! $user ) {
			return array();
		}
		$roles = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles[ $name ] = self::normalize_caps( (array) $data['capabilities'] );
		}
		foreach ( $proposed_role_caps_by_role as $name => $caps ) {
			if ( null === $caps ) {
				unset( $roles[ $name ] );
			} else {
				$roles[ (string) $name ] = self::normalize_caps( (array) $caps );
			}
		}
		$user_caps = (array) $user->caps;
		foreach ( (array) $user->roles as $role ) {
			unset( $user_caps[ $role ] );
		}
		$actor_roles = array_values( array_filter( (array) $user->roles, 'is_string' ) );
		$caps_before = self::caps_from_roles( $actor_roles, $roles, $user_caps );
		if ( in_array( 'administrator', $actor_roles, true ) && isset( $roles['administrator'] ) && empty( $caps_before[ Caps::MANAGE ] ) && ! empty( $roles['administrator'][ Caps::MANAGE ] ) ) {
			$user_caps[ Caps::MANAGE ] = true;
		}
		return self::lockout_reasons( $actor_roles, $user_caps, $roles );
	}

	/**
	 * Valid names: lowercase a-z, 0-9, underscore, hyphen and colon, up to 191 chars,
	 * not numeric-only and not the name of an existing role. Input is trimmed and
	 * lowercased first; anything else is rejected rather than rewritten.
	 *
	 * @return string|false
	 */
	public static function sanitize_cap_name( string $cap ) {
		$cap = strtolower( trim( $cap ) );
		if ( '' === $cap || strlen( $cap ) > self::CAP_MAX_LENGTH ) {
			return false;
		}
		if ( ! preg_match( '/^[a-z0-9_:\-]+$/', $cap ) || ctype_digit( $cap ) ) {
			return false;
		}
		if ( function_exists( 'wp_roles' ) && wp_roles()->is_role( $cap ) ) {
			return false;
		}
		return $cap;
	}

	public static function cap_exists( string $cap ): bool {
		foreach ( wp_roles()->roles as $data ) {
			if ( array_key_exists( $cap, (array) $data['capabilities'] ) ) {
				return true;
			}
		}
		$meta = array( 'edit_post', 'delete_post', 'read_post', 'publish_post', 'edit_page', 'delete_page', 'read_page', 'edit_user', 'delete_user', 'remove_user', 'promote_user', 'add_user', 'create_user', 'edit_term', 'delete_term', 'assign_term', 'manage_post_tags', 'upload_files', 'customize', 'delete_site', 'manage_privacy_options' );
		if ( in_array( $cap, $meta, true ) ) {
			return true;
		}
		$catalog = '\\Rolewright\\Modules\\Capabilities\\Cap_Catalog';
		return class_exists( $catalog ) && in_array( $cap, $catalog::universe(), true );
	}

	/**
	 * Every check a module must pass before replacing a role's cap set: cap names, the
	 * administrator's protected caps, the actor's level relative to the role, caps the
	 * actor may grant, and self-lockout. Callers still check their own permission cap
	 * (for example rolewright_manage_roles) and nonce.
	 *
	 * @param string $role     Role name. A role that does not exist yet is treated as empty.
	 * @param array  $new_caps Full new cap set, list or map (false = explicit deny).
	 * @return true|\WP_Error
	 */
	public static function assert_can_modify_role( int $actor_id, string $role, array $new_caps ) {
		$veto = apply_filters( 'rolewright_role_change_veto', null, 'modify', $actor_id, $role, $new_caps );
		if ( $veto instanceof \WP_Error ) {
			return $veto;
		}

		$new     = self::normalize_caps( $new_caps );
		$obj     = get_role( $role );
		$current = $obj ? self::normalize_caps( (array) $obj->capabilities ) : array();

		$invalid = array();
		foreach ( array_keys( $new ) as $cap ) {
			if ( ! array_key_exists( $cap, $current ) && false === self::sanitize_cap_name( $cap ) ) {
				$invalid[] = $cap;
			}
		}
		if ( $invalid ) {
			return new \WP_Error(
				'rolewright_invalid_cap',
				/* translators: %s: comma-separated capability names */
				sprintf( __( 'These capability names are not valid: %s. Use lowercase letters, numbers, underscores, hyphens or colons, and avoid role names.', 'rolewright' ), implode( ', ', $invalid ) )
			);
		}

		if ( 'administrator' === $role ) {
			$lost = array();
			foreach ( self::critical_subset( $current ) as $cap ) {
				if ( empty( $new[ $cap ] ) ) {
					$lost[] = $cap;
				}
			}
			foreach ( Caps::all() as $cap ) {
				if ( empty( $new[ $cap ] ) && ! in_array( $cap, $lost, true ) ) {
					$lost[] = $cap;
				}
			}
			if ( $lost ) {
				return new \WP_Error(
					'rolewright_protected_role',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'The Administrator role must keep these capabilities: %s.', 'rolewright' ), implode( ', ', $lost ) )
				);
			}
		}

		if ( ! self::is_super( $actor_id ) ) {
			$above = self::missing( self::critical_subset( $current ), self::user_caps( $actor_id ) );
			if ( $above ) {
				return new \WP_Error(
					'rolewright_role_above_actor',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'You can\'t change this role because it holds capabilities you don\'t have: %s.', 'rolewright' ), implode( ', ', $above ) )
				);
			}
		}

		$not_allowed = array();
		foreach ( $new as $cap => $grant ) {
			if ( $grant && empty( $current[ $cap ] ) && ! self::can_grant_cap( $actor_id, $cap ) ) {
				$not_allowed[] = $cap;
			}
		}
		if ( $not_allowed ) {
			return new \WP_Error(
				'rolewright_cap_not_held',
				/* translators: %s: comma-separated capability names */
				sprintf( __( 'You can\'t grant capabilities you don\'t hold yourself: %s.', 'rolewright' ), implode( ', ', $not_allowed ) )
			);
		}

		$reasons = self::lockout_reasons_for( $actor_id, array( $role => $new ) );
		if ( $reasons ) {
			return self::lockout_error( $reasons );
		}
		return true;
	}

	/**
	 * @return true|\WP_Error
	 */
	public static function assert_can_delete_role( int $actor_id, string $role ) {
		$veto = apply_filters( 'rolewright_role_change_veto', null, 'delete', $actor_id, $role );
		if ( $veto instanceof \WP_Error ) {
			return $veto;
		}

		if ( self::is_protected_role( $role ) ) {
			return new \WP_Error(
				'rolewright_protected_role',
				/* translators: %s: role name */
				sprintf( __( 'The %s role is protected and can\'t be deleted.', 'rolewright' ), $role )
			);
		}
		$obj = get_role( $role );
		if ( ! $obj ) {
			return new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
		}
		if ( ! self::is_super( $actor_id ) ) {
			$above = self::missing( self::critical_subset( (array) $obj->capabilities ), self::user_caps( $actor_id ) );
			if ( $above ) {
				return new \WP_Error(
					'rolewright_role_above_actor',
					/* translators: %s: comma-separated capability names */
					sprintf( __( 'You can\'t delete this role because it holds capabilities you don\'t have: %s.', 'rolewright' ), implode( ', ', $above ) )
				);
			}
		}
		$reasons = self::lockout_reasons_for( $actor_id, array( $role => null ) );
		return $reasons ? self::lockout_error( $reasons ) : true;
	}

	/**
	 * @return true|\WP_Error
	 */
	public static function assert_can_rename_role( int $actor_id, string $role ) {
		$veto = apply_filters( 'rolewright_role_change_veto', null, 'rename', $actor_id, $role );
		if ( $veto instanceof \WP_Error ) {
			return $veto;
		}

		if ( 'administrator' === $role ) {
			return new \WP_Error( 'rolewright_protected_role', __( 'The Administrator role can\'t be renamed.', 'rolewright' ) );
		}
		$obj = get_role( $role );
		if ( $obj && ! self::is_super( $actor_id ) && self::missing( self::critical_subset( (array) $obj->capabilities ), self::user_caps( $actor_id ) ) ) {
			return new \WP_Error( 'rolewright_role_above_actor', __( 'You can\'t rename a role that holds capabilities you don\'t have.', 'rolewright' ) );
		}
		return true;
	}

	/**
	 * @param string[] $reasons
	 */
	private static function lockout_error( array $reasons ): \WP_Error {
		$text  = array(
			'read'            => __( 'you would lose the read capability', 'rolewright' ),
			'manage'          => __( 'you would lose access to Rolewright (rolewright_manage)', 'rolewright' ),
			'no_manager_role' => __( 'no role would be left that can manage roles (rolewright_manage_roles)', 'rolewright' ),
		);
		$parts = array();
		foreach ( $reasons as $r ) {
			$parts[] = isset( $text[ $r ] ) ? $text[ $r ] : $r;
		}
		return new \WP_Error(
			'rolewright_lockout',
			/* translators: %s: list of reasons */
			sprintf( __( 'This change would lock you out: %s.', 'rolewright' ), implode( '; ', $parts ) ),
			array( 'reasons' => $reasons )
		);
	}
}
