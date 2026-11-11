<?php
namespace Rolegate\Modules\Disabled_Users;

use Rolegate\Core\Plugin;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\User_Roles\Users;

defined( 'ABSPATH' ) || exit;

final class Accounts {
	const META = 'rolegate_disabled';

	public static function is_disabled( int $user_id ): bool {
		return $user_id > 0 && '1' === (string) get_user_meta( $user_id, self::META, true );
	}

	public static function is_blocked( int $user_id ): bool {
		return Plugin::is_enabled( 'disabled-users' ) && self::is_disabled( $user_id );
	}

	public static function meta_id( int $user_id ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT umeta_id FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s ORDER BY umeta_id DESC LIMIT 1", $user_id, self::META ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Sets or clears the flag and ends the user's sessions when disabling. No checks, no log entry.
	 */
	public static function write( int $user_id, bool $disabled ): void {
		if ( $disabled ) {
			update_user_meta( $user_id, self::META, '1' );
			\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		} else {
			delete_user_meta( $user_id, self::META );
		}
	}

	/**
	 * Ids of the enabled users who hold rolegate_manage.
	 *
	 * @return int[]
	 */
	public static function active_managers(): array {
		global $wpdb;
		$roles = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			if ( ! empty( $data['capabilities'][ Caps::MANAGE ] ) ) {
				$roles[] = (string) $slug;
			}
		}
		$ids = $roles ? get_users(
			array(
				'role__in' => $roles,
				'fields'   => 'ID',
			)
		) : array();
		$own = get_users(
			array(
				'fields'     => 'ID',
				'meta_query' => array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
					array(
						'key'     => $wpdb->get_blog_prefix() . 'capabilities',
						'value'   => '"' . Caps::MANAGE . '";b:1',
						'compare' => 'LIKE',
					),
				),
			)
		);
		$ids = array_merge( $ids, $own );
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( $user ) {
					$ids[] = $user->ID;
				}
			}
		}
		$out = array();
		foreach ( array_unique( array_map( 'intval', $ids ) ) as $id ) {
			if ( ! self::is_disabled( $id ) && user_can( $id, Caps::MANAGE ) ) {
				$out[] = $id;
			}
		}
		sort( $out );
		return $out;
	}

	public static function is_last_manager( int $user_id ): bool {
		$managers = self::active_managers();
		return in_array( $user_id, $managers, true ) && 1 === count( $managers );
	}

	/**
	 * Whether the actor may change this user's account status, before the last-manager rule.
	 *
	 * @return true|\WP_Error
	 */
	public static function check_actor( int $actor, int $target ) {
		if ( ! get_userdata( $target ) ) {
			return new \WP_Error( 'rolegate_no_user', __( 'That user does not exist.', 'role-gatekeeper' ) );
		}
		if ( $actor > 0 && $target === $actor ) {
			return new \WP_Error( 'rolegate_self_disable', __( 'You can\'t disable your own account.', 'role-gatekeeper' ) );
		}
		if ( ! user_can( $actor, Caps::MANAGE_USERS ) ) {
			return new \WP_Error( 'rolegate_cannot_manage_users', __( 'You can\'t disable or enable accounts.', 'role-gatekeeper' ) );
		}
		$member = Users::check_site_member( $actor, $target );
		if ( true !== $member ) {
			return $member;
		}
		if ( is_multisite() && ! is_super_admin( $actor ) && ! user_can( $actor, 'manage_network_users' ) ) {
			return new \WP_Error( 'rolegate_needs_network_users', __( 'On a multisite network, only super admins and users who can manage network users can disable or enable accounts.', 'role-gatekeeper' ) );
		}
		if ( ! user_can( $actor, 'edit_user', $target ) || ! Guard::can_act_on_user( $actor, $target ) ) {
			return new \WP_Error( 'rolegate_user_above_actor', __( 'This user holds capabilities you don\'t have.', 'role-gatekeeper' ) );
		}
		return true;
	}

	/**
	 * @return true|\WP_Error
	 */
	public static function check( int $actor, int $target, bool $disable ) {
		$ok = self::check_actor( $actor, $target );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		if ( $disable && self::is_last_manager( $target ) ) {
			return new \WP_Error( 'rolegate_last_manager', __( 'This is the last active user who can manage Role Gatekeeper, so the account can\'t be disabled.', 'role-gatekeeper' ) );
		}
		if ( $disable && in_array( 'administrator', Users::raw_roles( $target ), true ) && ! Users::has_other_active_admin( $target ) ) {
			return new \WP_Error( 'rolegate_last_admin', __( 'This is the last active administrator, so the account can\'t be disabled.', 'role-gatekeeper' ) );
		}
		return true;
	}

	/**
	 * Disables or enables one account, checked and logged. A revert passes the id of the
	 * entry it undoes and is allowed to restate the current state.
	 *
	 * @return true|\WP_Error
	 */
	public static function change( int $actor, int $target, bool $disable, int $revert_of = 0 ) {
		$ok = self::check( $actor, $target, $disable );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$before = self::is_disabled( $target );
		if ( $before === $disable && ! $revert_of ) {
			return new \WP_Error( 'rolegate_disabled_noop', $disable ? __( 'That account is already disabled.', 'role-gatekeeper' ) : __( 'That account is already enabled.', 'role-gatekeeper' ) );
		}
		self::write( $target, $disable );
		$data = array(
			'actor'  => $actor,
			'target' => $target,
			'before' => array( 'disabled' => $before ),
			'after'  => array( 'disabled' => $disable ),
		);
		if ( $revert_of ) {
			$data['revert_of'] = $revert_of;
		}
		do_action( 'rolegate_changed', 'user.disabled', $data );
		return true;
	}
}
