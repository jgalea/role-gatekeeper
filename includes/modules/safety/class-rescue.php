<?php
namespace Rolewright\Modules\Safety;

defined( 'ABSPATH' ) || exit;

/**
 * One-time emailed link that puts the rolewright_* caps back on the administrator role.
 * It never logs anyone in and never reveals whether an address belongs to an account.
 */
final class Rescue {
	const ACTION_REQUEST = 'rolewright_rescue';
	const ACTION_USE     = 'rolewright_rescue_use';
	const META           = 'rolewright_rescue_token';
	const TTL            = 900;
	const LIMIT          = 3;
	const WINDOW         = HOUR_IN_SECONDS;

	public function register(): void {
		add_action( 'login_footer', array( $this, 'footer_link' ) );
		add_action( 'login_form_' . self::ACTION_REQUEST, array( $this, 'request_page' ) );
		add_action( 'login_form_' . self::ACTION_USE, array( $this, 'use_page' ) );
	}

	public static function client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return (string) apply_filters( 'rolewright_rescue_client_ip', $ip );
	}

	public static function is_eligible( \WP_User $user ): bool {
		return in_array( 'administrator', (array) $user->roles, true ) || is_super_admin( $user->ID );
	}

	/**
	 * Counts one hit against $key and reports whether it is still within the limit.
	 */
	private static function hit( string $key ): bool {
		$name  = 'rolewright_rl_' . md5( $key );
		$state = get_transient( $name );
		if ( ! is_array( $state ) || empty( $state['start'] ) || $state['start'] + self::WINDOW < time() ) {
			$state = array(
				'start' => time(),
				'count' => 0,
			);
		}
		++$state['count'];
		set_transient( $name, $state, self::WINDOW );
		return $state['count'] <= self::LIMIT;
	}

	/**
	 * Handles a link request. Returns true only when an email went out; callers must not
	 * show that to the visitor.
	 */
	public static function request( string $email, string $ip ): bool {
		if ( ! self::hit( 'ip|' . $ip ) ) {
			return false;
		}
		$email = sanitize_email( $email );
		$user  = $email ? get_user_by( 'email', $email ) : false;
		if ( ! $user || ! self::hit( 'acct|' . $user->ID ) || ! self::is_eligible( $user ) ) {
			return false;
		}
		$token = bin2hex( random_bytes( 32 ) );
		update_user_meta(
			$user->ID,
			self::META,
			array(
				'hash'    => hash( 'sha256', $token ),
				'expires' => time() + self::TTL,
			)
		);
		$url  = add_query_arg(
			array(
				'action' => self::ACTION_USE,
				'uid'    => $user->ID,
				'token'  => $token,
			),
			wp_login_url()
		);
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] Rolewright access link', 'rolewright' ), $site );
		$body    = sprintf(
			/* translators: 1: site URL, 2: rescue link */
			__( "Someone asked to restore Rolewright access for the administrator role on %1\$s.\n\nOpen this link within 15 minutes to restore it. It works once and does not log you in:\n\n%2\$s\n\nIf you didn't ask for this, ignore this email; nothing changes.", 'rolewright' ),
			home_url( '/' ),
			$url
		);
		return (bool) wp_mail( $user->user_email, $subject, $body );
	}

	/**
	 * Validates and spends a token, then restores the caps.
	 *
	 * @return true|\WP_Error
	 */
	public static function consume( int $uid, string $token, string $ip ) {
		$generic = new \WP_Error( 'rolewright_rescue_invalid', __( 'This link is invalid or has expired. Request a new one.', 'rolewright' ) );
		if ( ! self::hit( 'use|' . $ip ) || $uid <= 0 || ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return $generic;
		}
		$stored = get_user_meta( $uid, self::META, true );
		if ( ! is_array( $stored ) || empty( $stored['hash'] ) || empty( $stored['expires'] ) ) {
			return $generic;
		}
		if ( (int) $stored['expires'] < time() ) {
			delete_user_meta( $uid, self::META );
			return $generic;
		}
		if ( ! hash_equals( (string) $stored['hash'], hash( 'sha256', $token ) ) ) {
			return $generic;
		}
		delete_user_meta( $uid, self::META );
		$user = get_userdata( $uid );
		if ( ! $user || ! self::is_eligible( $user ) || ! get_role( 'administrator' ) ) {
			return $generic;
		}
		Caps::grant_to_administrator();
		do_action( 'rolewright_rescue_used', $uid );
		return true;
	}

	public function footer_link(): void {
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( in_array( $action, array( self::ACTION_REQUEST, self::ACTION_USE ), true ) ) {
			return;
		}
		printf(
			'<p style="text-align:center;margin-top:12px"><a href="%s">%s</a></p>',
			esc_url( add_query_arg( 'action', self::ACTION_REQUEST, wp_login_url() ) ),
			esc_html__( 'Locked out of Rolewright?', 'rolewright' )
		);
	}

	public function request_page(): void {
		$message = '';
		if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( ! isset( $_POST['_rwnonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_rwnonce'] ) ), self::ACTION_REQUEST ) ) {
				wp_die( esc_html__( 'The form expired. Go back and try again.', 'rolewright' ), '', array( 'response' => 403 ) );
			}
			$email = isset( $_POST['rolewright_email'] ) ? sanitize_email( wp_unslash( $_POST['rolewright_email'] ) ) : '';
			self::request( $email, self::client_ip() );
			$message = __( 'If that address belongs to an administrator account, a one-time link is on its way. It expires in 15 minutes.', 'rolewright' );
		}

		login_header( __( 'Restore Rolewright access', 'rolewright' ), $message ? '<p class="message">' . esc_html( $message ) . '</p>' : '' );
		?>
		<form method="post" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION_REQUEST, wp_login_url() ) ); ?>">
			<p><?php esc_html_e( 'Enter the email address of an administrator account. We will email a one-time link that gives the Administrator role its Rolewright capabilities back.', 'rolewright' ); ?></p>
			<p>
				<label for="rolewright_email"><?php esc_html_e( 'Administrator email', 'rolewright' ); ?></label>
				<input type="email" name="rolewright_email" id="rolewright_email" class="input" required autocomplete="email" />
			</p>
			<input type="hidden" name="_rwnonce" value="<?php echo esc_attr( wp_create_nonce( self::ACTION_REQUEST ) ); ?>" />
			<p class="submit"><input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Email me a link', 'rolewright' ); ?>" /></p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Back to log in', 'rolewright' ); ?></a></p>
		<?php
		login_footer();
		exit;
	}

	public function use_page(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- the one-time token is the credential.
		$uid   = isset( $_REQUEST['uid'] ) ? absint( $_REQUEST['uid'] ) : 0;
		$token = isset( $_REQUEST['token'] ) ? sanitize_key( wp_unslash( $_REQUEST['token'] ) ) : '';
		// phpcs:enable
		$error = '';

		if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$result = self::consume( $uid, $token, self::client_ip() );
			if ( true === $result ) {
				wp_safe_redirect( admin_url( 'admin.php?page=' . \Rolewright\Core\Settings::MENU_SLUG ) );
				exit;
			}
			$error = $result->get_error_message();
		}

		login_header( __( 'Restore Rolewright access', 'rolewright' ), $error ? '<div id="login_error">' . esc_html( $error ) . '</div>' : '' );
		?>
		<form method="post" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION_USE, wp_login_url() ) ); ?>">
			<p><?php esc_html_e( 'Confirm to give the Administrator role its Rolewright capabilities back. You will then be sent to log in.', 'rolewright' ); ?></p>
			<input type="hidden" name="uid" value="<?php echo esc_attr( (string) $uid ); ?>" />
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<p class="submit"><input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Restore access', 'rolewright' ); ?>" /></p>
		</form>
		<?php
		login_footer();
		exit;
	}
}
