<?php
namespace Rolegate\Modules\Disabled_Users;

use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Settings_Page {
	const SLUG   = 'role-gatekeeper-disabled-accounts';
	const ACTION = 'rolegate_save_disabled_message';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'save' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Disabled accounts', 'role-gatekeeper' ),
			__( 'Disabled accounts', 'role-gatekeeper' ),
			Caps::MANAGE_USERS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function save(): void {
		if ( ! current_user_can( Caps::MANAGE_USERS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$message = isset( $_POST['rolegate_disabled_message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rolegate_disabled_message'] ) ) : '';
		$message = function_exists( 'mb_substr' ) ? mb_substr( $message, 0, 300 ) : substr( $message, 0, 300 );
		if ( '' === $message ) {
			delete_option( Accounts::MESSAGE_OPTION );
		} else {
			update_option( Accounts::MESSAGE_OPTION, $message, false );
		}
		wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'admin.php?page=' . self::SLUG ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_USERS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'Disabled accounts', 'role-gatekeeper' ) . '</h1>';
		if ( isset( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display flag only.
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		$count = Accounts::count_disabled();
		echo '<p>' . ( $count ? sprintf(
			/* translators: 1: number of accounts, 2: opening link tag, 3: closing link tag */
			esc_html( _n( '%1$s account is disabled. %2$sView it%3$s.', '%1$s accounts are disabled. %2$sView them%3$s.', $count, 'role-gatekeeper' ) ),
			esc_html( number_format_i18n( $count ) ),
			'<a href="' . esc_url( admin_url( 'users.php?rolegate_disabled=1' ) ) . '">',
			'</a>'
		) : esc_html__( 'No accounts are disabled.', 'role-gatekeeper' ) ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
		wp_nonce_field( self::ACTION );
		echo '<table class="form-table" role="presentation"><tr><th scope="row"><label for="rolegate_disabled_message">' . esc_html__( 'Login message', 'role-gatekeeper' ) . '</label></th><td>';
		printf(
			'<textarea id="rolegate_disabled_message" name="rolegate_disabled_message" rows="3" maxlength="300" class="large-text" placeholder="%1$s">%2$s</textarea>',
			esc_attr__( 'This account has been disabled.', 'role-gatekeeper' ),
			esc_textarea( Accounts::custom_message() )
		);
		echo '<p class="description">' . esc_html__( 'Shown on the login screen when a disabled user tries to sign in, for example who to contact. Plain text, up to 300 characters.', 'role-gatekeeper' ) . '</p>';
		echo '</td></tr></table>';
		submit_button( __( 'Save changes', 'role-gatekeeper' ) );
		echo '</form></div>';
	}
}
