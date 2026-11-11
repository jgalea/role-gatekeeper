<?php
namespace Rolegate\Modules\Safety;

use Rolegate\Core\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Tells administrators when roles were removed from an account created with nobody logged in.
 */
final class Stripped_Notice {
	const OPTION = 'rolegate_stripped_accounts';
	const ACTION = 'rolegate_dismiss_stripped';

	public function register(): void {
		add_action( 'rolegate_escalation_blocked', array( $this, 'record' ), 10, 4 );
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'dismiss' ) );
	}

	public function record( $kind, $actor, $target ): void {
		if ( 'new_user' !== $kind || (int) $actor > 0 ) {
			return;
		}
		$ids   = (array) get_option( self::OPTION, array() );
		$ids[] = (int) $target;
		update_option( self::OPTION, array_slice( array_values( array_unique( $ids ) ), -20 ), false );
	}

	public function render(): void {
		global $pagenow;
		$on_screen = 'users.php' === $pagenow || ( isset( $_GET['page'] ) && 0 === strpos( sanitize_key( wp_unslash( $_GET['page'] ) ), 'role-gatekeeper' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- screen check only.
		$ids       = (array) get_option( self::OPTION, array() );
		if ( ! $on_screen || ! $ids || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}
		$text  = sprintf(
			/* translators: %s: number of accounts */
			_n( 'Roles that can change the site were removed from %s account created while nobody was logged in.', 'Roles that can change the site were removed from %s accounts created while nobody was logged in.', count( $ids ), 'role-gatekeeper' ),
			number_format_i18n( count( $ids ) )
		);
		$links = '<a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION ), self::ACTION ) ) . '">' . esc_html__( 'Dismiss', 'role-gatekeeper' ) . '</a>';
		if ( Plugin::is_enabled( 'audit' ) && current_user_can( Caps::VIEW_AUDIT ) ) {
			$links = '<a href="' . esc_url( admin_url( 'admin.php?page=role-gatekeeper-audit' ) ) . '">' . esc_html__( 'View the audit log', 'role-gatekeeper' ) . '</a> | ' . $links;
		}
		printf( '<div class="notice notice-warning"><p>%s %s</p></div>', esc_html( $text ), $links ); // phpcs:ignore WordPress.Security.EscapeOutput -- links are escaped above.
	}

	public function dismiss(): void {
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		delete_option( self::OPTION );
		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url( 'users.php' ) );
		exit;
	}
}
