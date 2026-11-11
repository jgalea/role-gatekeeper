<?php
namespace Rolegate\Modules\User_Roles;

use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Users {
	/**
	 * Role slugs of a user, primary role first.
	 *
	 * @return string[]
	 */
	public static function get_roles( $user_id ): array {
		$user  = get_userdata( (int) $user_id );
		$roles = $user ? array_values( array_map( 'strval', (array) $user->roles ) ) : array();
		/**
		 * Filters the role slugs reported for a user.
		 *
		 * @param string[] $roles
		 * @param int      $user_id
		 */
		$roles = apply_filters( 'rolegate_user_roles', $roles, (int) $user_id );
		return is_array( $roles ) ? array_values( $roles ) : array();
	}

	/**
	 * Roles as stored, without the rolegate_user_roles filter.
	 *
	 * @return string[]
	 */
	public static function raw_roles( int $user_id ): array {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;
		return $user ? array_values( array_map( 'strval', (array) $user->roles ) ) : array();
	}

	/**
	 * Capabilities stored on the user itself and set to true, without role entries.
	 *
	 * @return array<string,bool>
	 */
	public static function direct_caps( int $user_id ): array {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;
		$out  = array();
		if ( ! $user ) {
			return $out;
		}
		$roles = wp_roles()->role_names;
		foreach ( (array) $user->caps as $cap => $grant ) {
			if ( $grant && ! isset( $roles[ $cap ] ) ) {
				$out[ (string) $cap ] = true;
			}
		}
		ksort( $out );
		return $out;
	}

	public static function role_url( string $role ): string {
		return add_query_arg( 'role', rawurlencode( $role ), admin_url( 'users.php' ) );
	}

	public static function no_role_url(): string {
		return add_query_arg( 'rolegate_no_role', '1', admin_url( 'users.php' ) );
	}

	/**
	 * meta_query that matches users holding no role on this site.
	 */
	public static function no_role_meta_query(): array {
		global $wpdb;
		$key    = $wpdb->get_blog_prefix() . 'capabilities';
		$groups = array( 'relation' => 'AND' );
		foreach ( array_keys( wp_roles()->role_names ) as $role ) {
			$groups[] = array(
				'key'     => $key,
				'value'   => '"' . (string) $role . '";b:1',
				'compare' => 'NOT LIKE',
			);
		}
		return array(
			'relation' => 'OR',
			array(
				'key'     => $key,
				'compare' => 'NOT EXISTS',
			),
			$groups,
		);
	}

	public static function count_no_role(): int {
		$query = new \WP_User_Query(
			array(
				'fields'      => 'ID',
				'number'      => 1,
				'count_total' => true,
				'meta_query'  => self::no_role_meta_query(), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
			)
		);
		return (int) $query->get_total();
	}

	/**
	 * Users per role (a user with several roles counts once under each), users without a role, and the total.
	 *
	 * @return array{total:int,roles:array<string,int>,none:int}
	 */
	public static function counts(): array {
		$raw   = count_users();
		$roles = array();
		foreach ( array_keys( wp_roles()->role_names ) as $slug ) {
			$roles[ $slug ] = isset( $raw['avail_roles'][ $slug ] ) ? (int) $raw['avail_roles'][ $slug ] : 0;
		}
		return array(
			'total' => (int) $raw['total_users'],
			'roles' => $roles,
			'none'  => self::count_no_role(),
		);
	}

	/**
	 * Roles the actor may hand to the target, honoring the editable roles list.
	 *
	 * @return string[]
	 */
	public static function assignable_roles( int $actor, int $target ): array {
		if ( ! function_exists( 'get_editable_roles' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}
		$out = array();
		foreach ( array_keys( get_editable_roles() ) as $role ) {
			if ( Guard::can_assign_role( $actor, (string) $role, $target ) ) {
				$out[] = (string) $role;
			}
		}
		return $out;
	}

	/**
	 * On multisite, only super admins may change users who don't belong to the current site.
	 *
	 * @return true|\WP_Error
	 */
	public static function check_site_member( int $actor, int $target ) {
		if ( ! is_multisite() || $target <= 0 || Guard::is_super( $actor ) ) {
			return true;
		}
		if ( ! is_user_member_of_blog( $target, get_current_blog_id() ) ) {
			return new \WP_Error( 'rolegate_not_site_member', __( 'That user is not a member of this site.', 'role-gatekeeper' ) );
		}
		return true;
	}

	/**
	 * Refuses a role change that leaves the site without an enabled administrator.
	 *
	 * @param string[] $before
	 * @param string[] $after
	 * @return true|\WP_Error
	 */
	public static function check_last_admin( int $target, array $before, array $after ) {
		if ( ! in_array( 'administrator', $before, true ) || in_array( 'administrator', $after, true ) || self::has_other_active_admin( $target ) ) {
			return true;
		}
		return new \WP_Error( 'rolegate_last_admin', __( 'The last active administrator can\'t lose the Administrator role.', 'role-gatekeeper' ) );
	}

	public static function has_other_active_admin( int $target ): bool {
		$admins = get_users(
			array(
				'role'    => 'administrator',
				'fields'  => 'ID',
				'exclude' => array( $target ),
			)
		);
		foreach ( $admins as $id ) {
			if ( ! Accounts::is_blocked( (int) $id ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string[] $add
	 * @param string[] $remove
	 * @return true|\WP_Error
	 */
	public static function check_roles_change( int $actor, int $target, array $add, array $remove ) {
		if ( $target > 0 && ! get_userdata( $target ) ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ) );
		}
		$member = self::check_site_member( $actor, $target );
		if ( true !== $member ) {
			return $member;
		}
		if ( $actor > 0 && $target === $actor ) {
			return new \WP_Error( 'rolegate_self_role', __( 'You can\'t change your own roles.', 'role-gatekeeper' ) );
		}
		if ( $target > 0 ? ! user_can( $actor, 'promote_user', $target ) : ! user_can( $actor, 'promote_users' ) ) {
			return new \WP_Error( 'rolegate_cannot_promote', __( 'You can\'t change the roles of this user.', 'role-gatekeeper' ) );
		}
		if ( $target > 0 && ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolegate_user_above_actor', __( 'This user holds capabilities you don\'t have.', 'role-gatekeeper' ) );
		}
		foreach ( $add as $role ) {
			if ( ! get_role( $role ) ) {
				return new \WP_Error( 'rolegate_no_role', __( 'That role does not exist.', 'role-gatekeeper' ) );
			}
			if ( ! Guard::can_assign_role( $actor, $role, $target ) ) {
				return new \WP_Error( 'rolegate_role_not_allowed', __( 'You can\'t give that role: it carries capabilities you don\'t hold.', 'role-gatekeeper' ) );
			}
		}
		if ( $target > 0 ) {
			$before = self::raw_roles( $target );
			$ok     = self::check_last_admin( $target, $before, array_values( array_unique( array_merge( array_diff( $before, $remove ), $add ) ) ) );
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
		}
		return true;
	}

	/**
	 * Adds and removes roles on one user, checked and logged.
	 *
	 * @param string[] $add
	 * @param string[] $remove
	 * @return true|\WP_Error
	 */
	public static function change_roles( int $actor, int $target, array $add, array $remove ) {
		$add    = self::clean_slugs( $add );
		$remove = array_diff( self::clean_slugs( $remove ), $add );
		$ok     = self::check_roles_change( $actor, $target, $add, $remove );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$user   = get_userdata( $target );
		$before = self::raw_roles( $target );
		foreach ( $remove as $role ) {
			if ( in_array( $role, $before, true ) ) {
				$user->remove_role( $role );
			}
		}
		foreach ( $add as $role ) {
			$user->add_role( $role );
		}
		clean_user_cache( $target );
		$after = self::raw_roles( $target );
		if ( array_diff( $add, $after ) || array_intersect( $remove, $after ) ) {
			self::announce_roles( $actor, $target, $before, $after );
			return new \WP_Error( 'rolegate_blocked', __( 'The change was refused by the safety rules.', 'role-gatekeeper' ) );
		}
		self::announce_roles( $actor, $target, $before, $after );
		return true;
	}

	/**
	 * @param string[] $before
	 * @param string[] $after
	 */
	public static function announce_roles( int $actor, int $target, array $before, array $after ): void {
		$a = $before;
		$b = $after;
		sort( $a );
		sort( $b );
		if ( $a === $b ) {
			return;
		}
		do_action(
			'rolegate_changed',
			'user.roles',
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => array( 'roles' => array_values( $before ) ),
				'after'  => array( 'roles' => array_values( $after ) ),
			)
		);
	}

	/**
	 * @param string[] $add
	 * @param string[] $remove
	 * @return array{0:string[],1:string[]}|\WP_Error
	 */
	public static function check_caps_change( int $actor, int $target, array $add, array $remove ) {
		if ( ! user_can( $actor, \Rolegate\Modules\Safety\Caps::MANAGE_USERS ) ) {
			return new \WP_Error( 'rolegate_cannot_manage_users', __( 'You can\'t edit user capabilities.', 'role-gatekeeper' ) );
		}
		if ( ! get_userdata( $target ) ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ) );
		}
		$member = self::check_site_member( $actor, $target );
		if ( true !== $member ) {
			return $member;
		}
		if ( $target === $actor ) {
			return new \WP_Error( 'rolegate_self_caps', __( 'You can\'t change your own capabilities.', 'role-gatekeeper' ) );
		}
		if ( ! user_can( $actor, 'edit_user', $target ) || ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolegate_user_above_actor', __( 'This user holds capabilities you don\'t have.', 'role-gatekeeper' ) );
		}
		$existing = self::direct_caps( $target );
		$clean    = array();
		foreach ( $add as $cap ) {
			if ( isset( $existing[ $cap ] ) ) {
				continue;
			}
			$name = Guard::sanitize_cap_name( (string) $cap );
			if ( false === $name ) {
				return new \WP_Error( 'rolegate_invalid_cap', sprintf( /* translators: %s: capability name */ __( '"%s" is not a valid capability name.', 'role-gatekeeper' ), $cap ) );
			}
			if ( Guard::is_role_slug_name( $name ) ) {
				return new \WP_Error( 'rolegate_cap_is_role', sprintf( /* translators: %s: capability name */ __( '"%s" is a role name, so it can\'t be a per-user capability. Assign the role instead.', 'role-gatekeeper' ), $name ) );
			}
			if ( ! Guard::can_grant_cap( $actor, $name ) ) {
				return new \WP_Error( 'rolegate_cap_not_held', sprintf( /* translators: %s: capability name */ __( 'You can\'t grant "%s": you don\'t hold it.', 'role-gatekeeper' ), $name ) );
			}
			$clean[] = $name;
		}
		$drop = array();
		foreach ( $remove as $cap ) {
			if ( isset( $existing[ $cap ] ) && Guard::can_grant_cap( $actor, $cap ) ) {
				$drop[] = $cap;
			}
		}
		return array( array_values( array_unique( $clean ) ), $drop );
	}

	/**
	 * Grants and revokes per-user capabilities, checked and logged.
	 *
	 * @param string[] $add
	 * @param string[] $remove
	 * @return true|\WP_Error
	 */
	public static function change_caps( int $actor, int $target, array $add, array $remove ) {
		$plan = self::check_caps_change( $actor, $target, $add, $remove );
		if ( is_wp_error( $plan ) ) {
			return $plan;
		}
		return self::apply_caps( $actor, $target, $plan[0], $plan[1] );
	}

	/**
	 * @param string[] $add  Already validated.
	 * @param string[] $drop Already validated.
	 * @return true|\WP_Error
	 */
	public static function apply_caps( int $actor, int $target, array $add, array $drop ) {
		$user   = get_userdata( $target );
		$before = self::direct_caps( $target );
		foreach ( $drop as $cap ) {
			$user->remove_cap( $cap );
		}
		foreach ( $add as $cap ) {
			$user->add_cap( $cap, true );
		}
		clean_user_cache( $target );
		$after = self::direct_caps( $target );
		self::announce_caps( $actor, $target, $before, $after );
		foreach ( $add as $cap ) {
			if ( ! isset( $after[ $cap ] ) ) {
				return new \WP_Error( 'rolegate_blocked', __( 'The change was refused by the safety rules.', 'role-gatekeeper' ) );
			}
		}
		return true;
	}

	/**
	 * @param array<string,bool> $before
	 * @param array<string,bool> $after
	 */
	public static function announce_caps( int $actor, int $target, array $before, array $after ): void {
		if ( $before === $after ) {
			return;
		}
		do_action(
			'rolegate_changed',
			'user.caps',
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => array( 'caps' => $before ),
				'after'  => array( 'caps' => $after ),
			)
		);
	}

	/**
	 * @param array $slugs
	 * @return string[]
	 */
	public static function clean_slugs( array $slugs ): array {
		$out = array();
		foreach ( $slugs as $slug ) {
			if ( is_string( $slug ) && '' !== $slug ) {
				$out[] = sanitize_text_field( $slug );
			}
		}
		return array_values( array_unique( $out ) );
	}
}
