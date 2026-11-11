<?php
namespace Rolegate\Modules\Test_As_User;

use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Switcher {
	const COOKIE      = 'rolegate_test_origin';
	const START       = 'rolegate_test_start';
	const STOP        = 'rolegate_test_stop';
	const DURATION    = HOUR_IN_SECONDS;
	const SESSION_KEY = 'rolegate_test_origin';

	public function register(): void {
		add_action( 'admin_post_' . self::START, array( $this, 'start' ) );
		add_action( 'admin_post_' . self::STOP, array( $this, 'stop' ) );
		add_filter( 'user_row_actions', array( $this, 'row_action' ), 10, 2 );
		add_action( 'admin_bar_menu', array( $this, 'bar_node' ), 1000 );
		add_action( 'wp_footer', array( $this, 'banner' ) );
		add_action( 'admin_footer', array( $this, 'banner' ) );
		add_action( 'clear_auth_cookie', array( __CLASS__, 'forget' ) );
	}

	/**
	 * Why the actor can't test as the target, or true. Stricter than the other user rules:
	 * the target must hold nothing the actor lacks, so the session can never do more than the actor can.
	 *
	 * @return true|\WP_Error
	 */
	public static function check( int $actor, int $target ) {
		$deny = static function ( string $code, string $message ) {
			return new \WP_Error( $code, $message );
		};
		if ( $actor <= 0 || $actor === $target ) {
			return $deny( 'rolegate_test_self', __( 'Pick another user.', 'role-gatekeeper' ) );
		}
		if ( self::origin() || self::session_actor() ) {
			return $deny( 'rolegate_test_nested', __( 'Switch back to your own account first.', 'role-gatekeeper' ) );
		}
		if ( ! user_can( $actor, Caps::MANAGE_USERS ) || ! user_can( $actor, 'edit_user', $target ) ) {
			return $deny( 'rolegate_test_denied', __( 'You cannot test as this user.', 'role-gatekeeper' ) );
		}
		$user = get_userdata( $target );
		if ( ! $user ) {
			return $deny( 'rolegate_test_missing', __( 'That user does not exist.', 'role-gatekeeper' ) );
		}
		if ( Accounts::is_disabled( $target ) ) {
			return $deny( 'rolegate_test_disabled', __( 'That account is disabled.', 'role-gatekeeper' ) );
		}
		if ( Guard::is_super( $target ) || ! Guard::can_act_on_user( $actor, $target ) ) {
			return $deny( 'rolegate_test_above', __( 'That user has permissions you do not have.', 'role-gatekeeper' ) );
		}
		// Role names and the deprecated level_N flags show up as capability keys on every user; they aren't permissions.
		$wanted = array_filter(
			array_diff( array_keys( array_filter( Guard::user_caps( $target ) ) ), (array) $user->roles ),
			static function ( $cap ) {
				return ! preg_match( '/^level_\d+$/', (string) $cap );
			}
		);
		if ( ! Guard::is_super( $actor ) && Guard::missing( $wanted, Guard::user_caps( $actor ) ) ) {
			return $deny( 'rolegate_test_above', __( 'That user has permissions you do not have.', 'role-gatekeeper' ) );
		}
		return true;
	}

	public function row_action( $actions, $user ) {
		if ( $user instanceof \WP_User && true === self::check( get_current_user_id(), $user->ID ) ) {
			$url                         = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::START . '&user=' . $user->ID ), self::START . $user->ID );
			$actions['rolegate_test_as'] = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Test as this user', 'role-gatekeeper' ) . '</a>';
		}
		return $actions;
	}

	public function start(): void {
		$actor  = get_current_user_id();
		$target = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
		check_admin_referer( self::START . $target );
		$ok = self::check( $actor, $target );
		if ( is_wp_error( $ok ) ) {
			wp_die(
				esc_html( $ok->get_error_message() ),
				'',
				array(
					'response'  => 403,
					'back_link' => true,
				)
			);
		}
		$expires = time() + self::DURATION;
		$limit   = static function () {
			return Switcher::DURATION;
		};
		$token   = '';
		$capture = static function ( $cookie, $expire, $expiration, $user_id, $scheme, $session_token ) use ( &$token ) {
			$token = (string) $session_token;
		};
		$mark    = static function ( $session ) use ( $actor ) {
			$session[ Switcher::SESSION_KEY ] = $actor;
			return $session;
		};
		add_filter( 'auth_cookie_expiration', $limit, 99 );
		add_filter( 'attach_session_information', $mark );
		add_action( 'set_logged_in_cookie', $capture, 10, 6 );
		wp_destroy_current_session();
		wp_clear_auth_cookie();
		wp_set_current_user( $target );
		wp_set_auth_cookie( $target, false );
		remove_filter( 'auth_cookie_expiration', $limit, 99 );
		remove_filter( 'attach_session_information', $mark );
		remove_action( 'set_logged_in_cookie', $capture, 10 );
		if ( '' === $token ) {
			wp_clear_auth_cookie();
			wp_die( esc_html__( 'Could not start the test session.', 'role-gatekeeper' ), '', array( 'response' => 500 ) );
		}
		self::remember( $actor, $target, $expires, $token );
		do_action(
			'rolegate_changed',
			'user.test_started',
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => array(),
				'after'  => array( 'until' => $expires ),
			)
		);
		wp_safe_redirect( admin_url() );
		exit;
	}

	public function stop(): void {
		$origin = self::origin();
		if ( ! $origin ) {
			wp_safe_redirect( admin_url() );
			exit;
		}
		check_admin_referer( self::STOP );
		$actor  = $origin['actor'];
		$target = get_current_user_id();
		$user   = get_userdata( $actor );
		wp_destroy_current_session();
		if ( ! $user || Accounts::is_disabled( $actor ) ) {
			wp_clear_auth_cookie();
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		wp_clear_auth_cookie();
		wp_set_current_user( $actor );
		wp_set_auth_cookie( $actor, false );
		do_action(
			'rolegate_changed',
			'user.test_ended',
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => array(),
				'after'  => array(),
			)
		);
		wp_safe_redirect( admin_url( 'users.php' ) );
		exit;
	}

	/**
	 * The signed-in account that started the current test session, or null. The cookie is signed and
	 * bound to this login session, so it can't be forged, replayed in another session or kept after expiry.
	 *
	 * @return array{actor:int,expires:int}|null
	 */
	public static function origin(): ?array {
		if ( ! is_user_logged_in() || empty( $_COOKIE[ self::COOKIE ] ) || ! is_string( $_COOKIE[ self::COOKIE ] ) ) {
			return null;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) );
		if ( 3 !== count( $parts ) ) {
			return null;
		}
		list( $actor, $expires, $sig ) = $parts;
		$actor                         = (int) $actor;
		$expires                       = (int) $expires;
		if ( $actor <= 0 || $expires < time() || ! hash_equals( self::sign( $actor, get_current_user_id(), $expires ), $sig ) ) {
			return null;
		}
		return array(
			'actor'   => $actor,
			'expires' => $expires,
		);
	}

	/**
	 * The account that started the current login session as a test session, kept on the server with the session itself,
	 * so dropping the cookie doesn't hide that a test session is running.
	 */
	private static function session_actor(): int {
		if ( ! is_user_logged_in() ) {
			return 0;
		}
		$session = \WP_Session_Tokens::get_instance( get_current_user_id() )->get( wp_get_session_token() );
		return is_array( $session ) && ! empty( $session[ self::SESSION_KEY ] ) ? (int) $session[ self::SESSION_KEY ] : 0;
	}

	private static function sign( int $actor, int $target, int $expires ): string {
		return hash_hmac( 'sha256', $actor . '|' . $target . '|' . $expires . '|' . wp_get_session_token(), wp_salt( 'auth' ) );
	}

	private static function remember( int $actor, int $target, int $expires, string $token ): void {
		$value = $actor . '|' . $expires . '|' . hash_hmac( 'sha256', $actor . '|' . $target . '|' . $expires . '|' . $token, wp_salt( 'auth' ) );
		setcookie( self::COOKIE, $value, $expires, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
		$_COOKIE[ self::COOKIE ] = $value;
	}

	public static function forget(): void {
		if ( isset( $_COOKIE[ self::COOKIE ] ) ) {
			setcookie( self::COOKIE, '', time() - YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
			unset( $_COOKIE[ self::COOKIE ] );
		}
	}

	public function bar_node( $bar ): void {
		$origin = self::origin();
		if ( ! $origin ) {
			return;
		}
		$bar->add_node(
			array(
				'id'    => 'rolegate-test-exit',
				'title' => esc_html( $this->label( $origin ) ),
				'href'  => $this->stop_url(),
				'meta'  => array( 'class' => 'rolegate-test-exit' ),
			)
		);
	}

	public function banner(): void {
		$origin = self::origin();
		if ( ! $origin ) {
			return;
		}
		echo '<div role="status" style="position:fixed;left:0;right:0;bottom:0;z-index:2147483000;background:#b32d2e;color:#fff;font:600 14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;padding:10px 16px;text-align:center">';
		echo esc_html( $this->label( $origin, false ) ) . ' <a href="' . esc_url( $this->stop_url() ) . '" style="color:#fff;text-decoration:underline;margin-left:8px">' . esc_html__( 'Switch back', 'role-gatekeeper' ) . '</a></div>';
	}

	private function stop_url(): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=' . self::STOP ), self::STOP );
	}

	/** @param array{actor:int,expires:int} $origin */
	private function label( array $origin, bool $with_action = true ): string {
		$me    = wp_get_current_user();
		$owner = get_userdata( $origin['actor'] );
		/* translators: 1: tested user, 2: own account */
		$text = sprintf( __( 'Testing as %1$s (you are %2$s).', 'role-gatekeeper' ), $me->display_name, $owner ? $owner->display_name : '' );
		return $with_action ? $text . ' ' . __( 'Switch back', 'role-gatekeeper' ) : $text;
	}
}
