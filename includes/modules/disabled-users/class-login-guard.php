<?php
namespace Rolegate\Modules\Disabled_Users;

defined( 'ABSPATH' ) || exit;

final class Login_Guard {
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), PHP_INT_MAX );
		add_filter( 'determine_current_user', array( $this, 'current_user' ), PHP_INT_MAX );
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'app_passwords' ), PHP_INT_MAX, 2 );
	}

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function authenticate( $user ) {
		if ( $user instanceof \WP_User && Accounts::is_disabled( $user->ID ) ) {
			return new \WP_Error( 'rolegate_disabled', __( 'This account has been disabled.', 'role-gatekeeper' ) );
		}
		return $user;
	}

	/**
	 * @param int|false $user_id
	 * @return int|false
	 */
	public function current_user( $user_id ) {
		return $user_id && Accounts::is_disabled( (int) $user_id ) ? false : $user_id;
	}

	/**
	 * @param bool     $available
	 * @param \WP_User $user
	 */
	public function app_passwords( $available, $user ): bool {
		return $available && ! ( $user instanceof \WP_User && Accounts::is_disabled( $user->ID ) );
	}
}
