<?php
namespace Rolegate\Modules\Disabled_Users;

defined( 'ABSPATH' ) || exit;

final class Login_Guard {
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), PHP_INT_MAX );
		add_filter( 'determine_current_user', array( $this, 'current_user' ), PHP_INT_MAX );
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'app_passwords' ), PHP_INT_MAX, 2 );
		add_action( 'set_current_user', array( $this, 'reset_current_user' ), PHP_INT_MAX );
		add_filter( 'send_auth_cookies', array( $this, 'send_cookies' ), PHP_INT_MAX, 6 );
		add_filter( 'allow_password_reset', array( $this, 'allow_reset' ), PHP_INT_MAX, 2 );
	}

	public function reset_current_user(): void {
		$id = get_current_user_id();
		if ( $id && Accounts::is_disabled( $id ) ) {
			wp_set_current_user( 0 );
		}
	}

	/**
	 * Code that signs a user in itself (magic links, SSO) ends up here after WordPress has created the session token.
	 *
	 * @param bool   $send
	 * @param int    $expire
	 * @param int    $expiration
	 * @param int    $user_id
	 * @param string $scheme
	 * @param string $token
	 */
	public function send_cookies( $send, $expire, $expiration, $user_id, $scheme, $token ): bool {
		if ( $send && $user_id && Accounts::is_disabled( (int) $user_id ) ) {
			\WP_Session_Tokens::get_instance( (int) $user_id )->destroy( (string) $token );
			return false;
		}
		return (bool) $send;
	}

	/**
	 * @param bool|\WP_Error $allow
	 * @param int            $user_id
	 * @return bool|\WP_Error
	 */
	public function allow_reset( $allow, $user_id ) {
		return Accounts::is_disabled( (int) $user_id ) ? false : $allow;
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
