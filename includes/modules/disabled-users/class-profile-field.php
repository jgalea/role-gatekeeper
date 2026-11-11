<?php
namespace Rolegate\Modules\Disabled_Users;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Profile_Field {
	/** @var array<int,bool> */
	private static $plan = array();

	public function register(): void {
		add_action( 'edit_user_profile', array( $this, 'render' ) );
		add_action( 'user_profile_update_errors', array( $this, 'validate' ), 20, 3 );
		add_action( 'profile_update', array( $this, 'apply' ), 20 );
	}

	public function render( $user ): void {
		$actor = get_current_user_id();
		if ( ! $user instanceof \WP_User || ! $actor || true !== Accounts::check_actor( $actor, $user->ID ) ) {
			return;
		}
		$disabled = Accounts::is_disabled( $user->ID );
		$locked   = ! $disabled && Accounts::is_last_manager( $user->ID );
		wp_nonce_field( 'rolegate_disabled_' . $user->ID, 'rolegate_disabled_nonce' );
		echo '<h2>' . esc_html__( 'Account status', 'role-gatekeeper' ) . '</h2>';
		echo '<input type="hidden" name="rolegate_disabled_present" value="1" />';
		echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Disable account', 'role-gatekeeper' ) . '</th><td>';
		printf(
			'<label><input type="checkbox" name="rolegate_disabled_user" value="1" %1$s %2$s /> %3$s</label>',
			checked( $disabled, true, false ),
			disabled( $locked, true, false ),
			esc_html__( 'This user can\'t log in. The account, posts and byline stay.', 'role-gatekeeper' )
		);
		$info = $disabled ? get_user_meta( $user->ID, Accounts::INFO_META, true ) : array();
		if ( is_array( $info ) && ! empty( $info['at'] ) ) {
			$by   = ! empty( $info['by'] ) ? get_userdata( (int) $info['by'] ) : false;
			$when = wp_date( get_option( 'date_format' ), (int) $info['at'] );
			/* translators: 1: date, 2: username */
			$text = $by ? sprintf( __( 'Disabled on %1$s by %2$s.', 'role-gatekeeper' ), $when, $by->user_login ) : sprintf( /* translators: %s: date */ __( 'Disabled on %s.', 'role-gatekeeper' ), $when );
			echo '<p class="description">' . esc_html( $text );
			if ( current_user_can( Caps::VIEW_AUDIT ) && \Rolegate\Core\Plugin::is_enabled( 'audit' ) ) {
				echo ' <a href="' . esc_url( add_query_arg( array( 'page' => \Rolegate\Modules\Audit\Audit_Page::SLUG, 'type' => 'user.disabled' ), admin_url( 'admin.php' ) ) ) . '">' . esc_html__( 'View in the audit log', 'role-gatekeeper' ) . '</a>';
			}
			echo '</p>';
		}
		if ( $locked ) {
			echo '<p class="description">' . esc_html__( 'This is the last active user who can manage Role Gatekeeper.', 'role-gatekeeper' ) . '</p>';
		}
		echo '</td></tr></table>';
	}

	/**
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param \stdClass $user
	 */
	public function validate( $errors, $update, $user ): void {
		$actor = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence marker only; the nonce is verified below.
		if ( ! $update || ! $actor || empty( $_POST['rolegate_disabled_present'] ) ) {
			return;
		}
		$target = (int) $user->ID;
		if ( $target === $actor ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput -- verified on the next line.
		$nonce = isset( $_POST['rolegate_disabled_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rolegate_disabled_nonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'rolegate_disabled_' . $target ) ) {
			$errors->add( 'rolegate_disabled_nonce', __( 'The account status section of this form has expired. Reload the page and try again.', 'role-gatekeeper' ) );
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		$want = ! empty( $_POST['rolegate_disabled_user'] );
		if ( Accounts::is_disabled( $target ) === $want ) {
			return;
		}
		$ok = Accounts::check( $actor, $target, $want );
		if ( is_wp_error( $ok ) ) {
			$errors->add( $ok->get_error_code(), $ok->get_error_message() );
			return;
		}
		self::$plan[ $target ] = $want;
	}

	public function apply( $user_id ): void {
		$user_id = (int) $user_id;
		if ( ! isset( self::$plan[ $user_id ] ) ) {
			return;
		}
		$want = self::$plan[ $user_id ];
		unset( self::$plan[ $user_id ] );
		Accounts::change( get_current_user_id(), $user_id, $want );
	}
}
