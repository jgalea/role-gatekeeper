<?php
namespace Rolegate\Modules\Content_Access;

use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Site-wide content access settings: the message shown on restricted content that has no
 * message of its own.
 */
final class Content_Settings {
	const OPTION = 'rolegate_content_access_settings';
	const SLUG   = 'role-gatekeeper-content-access';

	/** @return array{default_message:string} */
	public static function get(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		return array(
			'default_message' => isset( $stored['default_message'] ) && is_string( $stored['default_message'] ) ? $stored['default_message'] : '',
		);
	}

	public static function default_message(): string {
		return self::get()['default_message'];
	}

	/**
	 * Stores the settings after the same kses rules the post editor applies to a message.
	 * Callers check Caps::MANAGE_ACCESS and a nonce.
	 *
	 * @param array{default_message?:string} $settings
	 */
	public static function save( int $actor_id, array $settings ): void {
		$before = self::get();
		$after  = array(
			'default_message' => trim( Access::sanitize_message( isset( $settings['default_message'] ) ? $settings['default_message'] : '' ) ),
		);
		if ( $before === $after ) {
			return;
		}
		update_option( self::OPTION, $after, false );
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => 'content-access',
				'scope'  => 'settings',
				'before' => $before,
				'after'  => $after,
			)
		);
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolegate_content_settings', array( $this, 'handle' ) );
	}

	public function menu(): void {
		add_submenu_page( Settings::MENU_SLUG, __( 'Content access', 'role-gatekeeper' ), __( 'Content access', 'role-gatekeeper' ), Caps::MANAGE_ACCESS, self::SLUG, array( $this, 'render' ) );
	}

	public function handle(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolegate_content_settings' );
		$message = isset( $_POST['default_message'] ) ? (string) wp_unslash( $_POST['default_message'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized with the message kses rules in save().
		self::save( get_current_user_id(), array( 'default_message' => $message ) );
		wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'admin.php?page=' . self::SLUG ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'Content access', 'role-gatekeeper' ) . '</h1>';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display flag only.
		if ( isset( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_content_settings" />';
		wp_nonce_field( 'rolegate_content_settings' );
		echo '<table class="form-table" role="presentation"><tbody><tr><th scope="row"><label for="rolegate-default-message">' . esc_html__( 'Default message', 'role-gatekeeper' ) . '</label></th><td>';
		printf( '<textarea id="rolegate-default-message" name="default_message" rows="4" class="large-text">%s</textarea>', esc_textarea( self::default_message() ) );
		echo '<p class="description">' . esc_html__( 'Shown on restricted content that has no message of its own. Links, paragraphs, line breaks, bold and italic are kept.', 'role-gatekeeper' ) . '</p>';
		echo '</td></tr></tbody></table>';
		submit_button( __( 'Save settings', 'role-gatekeeper' ) );
		echo '</form></div>';
	}
}
