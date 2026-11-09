<?php
namespace Rolegate\Modules\Login_Redirects;

use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Login_Redirects_Page {
	const SLUG   = 'role-gatekeeper-login-redirects';
	const ACTION = 'rolegate_save_login_redirects';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'save' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Login redirects', 'role-gatekeeper' ),
			__( 'Login redirects', 'role-gatekeeper' ),
			Caps::MANAGE_ACCESS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function save(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$raw   = isset( $_POST['rw'] ) && is_array( $_POST['rw'] ) ? wp_unslash( $_POST['rw'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$actor = get_current_user_id();
		$clean = Login_Redirects_Settings::sanitize( $raw );
		$page  = admin_url( 'admin.php?page=' . self::SLUG );
		if ( is_wp_error( $clean ) ) {
			set_transient( 'rolegate_lr_err_' . $actor, $clean->get_error_message(), 60 );
			wp_safe_redirect( add_query_arg( 'rw_error', '1', $page ) );
			exit;
		}
		Login_Redirects_Settings::save( $clean, $actor );
		wp_safe_redirect( add_query_arg( 'updated', '1', $page ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		$s   = Login_Redirects_Settings::get();
		$uid = get_current_user_id();
		echo '<div class="wrap"><h1>' . esc_html__( 'Login redirects', 'role-gatekeeper' ) . '</h1>';
		if ( isset( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		if ( isset( $_GET['rw_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = get_transient( 'rolegate_lr_err_' . $uid );
			delete_transient( 'rolegate_lr_err_' . $uid );
			if ( is_string( $msg ) && '' !== $msg ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $msg ) . '</p></div>';
			}
		}
		echo '<p>' . esc_html__( 'Leave a field empty to keep WordPress behaviour. URLs must be pages on this site. A user with several roles gets the first matching role in priority order (lowest number first).', 'role-gatekeeper' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
		wp_nonce_field( self::ACTION );
		echo '<div class="rw-scroll" style="overflow-x:auto"><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Role', 'role-gatekeeper' ) . '</th><th>' . esc_html__( 'After login', 'role-gatekeeper' ) . '</th><th>' . esc_html__( 'After logout', 'role-gatekeeper' ) . '</th><th>' . esc_html__( 'Default landing page', 'role-gatekeeper' ) . '</th><th>' . esc_html__( 'Priority', 'role-gatekeeper' ) . '</th></tr></thead><tbody>';
		$position = 1;
		$order    = array_flip( (array) $s['priority'] );
		$field_labels = array(
			'login'   => __( 'After login', 'role-gatekeeper' ),
			'logout'  => __( 'After logout', 'role-gatekeeper' ),
			'landing' => __( 'Default landing page', 'role-gatekeeper' ),
		);
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			printf( '<tr><td>%s</td>', esc_html( translate_user_role( $name ) ) );
			foreach ( Login_Redirects_Settings::FIELDS as $field ) {
				$value = isset( $s['rules'][ $slug ][ $field ] ) ? (string) $s['rules'][ $slug ][ $field ] : '';
				printf(
					'<td><input type="text" class="regular-text" name="rw[rules][%1$s][%2$s]" value="%3$s" aria-label="%4$s" /></td>',
					esc_attr( $slug ),
					esc_attr( $field ),
					esc_attr( $value ),
					esc_attr( translate_user_role( $name ) . ': ' . $field_labels[ $field ] )
				);
			}
			printf(
				'<td><input type="number" min="1" class="small-text" name="rw[priority][%1$s]" value="%2$d" aria-label="%3$s" /></td></tr>',
				esc_attr( $slug ),
				absint( isset( $order[ $slug ] ) ? (int) $order[ $slug ] + 1 : 100 + $position ),
				esc_attr( translate_user_role( $name ) . ': ' . __( 'Priority', 'role-gatekeeper' ) )
			);
			++$position;
		}
		echo '</tbody></table></div>';
		printf(
			'<p><label><input type="checkbox" name="rw[override]" value="1" %s /> %s</label></p>',
			checked( ! empty( $s['override'] ), true, false ),
			esc_html__( 'Apply the role redirect even when the login form asked for a specific page.', 'role-gatekeeper' )
		);
		submit_button( __( 'Save changes', 'role-gatekeeper' ) );
		echo '</form></div>';
	}
}
