<?php
namespace Rolegate\Modules\Site_Access;

use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Site_Access_Page {
	const SLUG   = 'role-gatekeeper-site-access';
	const ACTION = 'rolegate_save_site_access';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'save' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Site access', 'role-gatekeeper' ),
			__( 'Site access', 'role-gatekeeper' ),
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
		$clean = Site_Access_Settings::sanitize( $raw, Site_Access_Settings::get(), $actor );
		$page  = admin_url( 'admin.php?page=' . self::SLUG );
		if ( is_wp_error( $clean ) ) {
			set_transient( 'rolegate_sa_err_' . $actor, $clean->get_error_message(), 60 );
			wp_safe_redirect( add_query_arg( 'rw_error', '1', $page ) );
			exit;
		}
		Site_Access_Settings::save( $clean, $actor );
		wp_safe_redirect( add_query_arg( 'updated', '1', $page ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		$s   = Site_Access_Settings::get();
		$uid = get_current_user_id();
		echo '<div class="wrap"><h1>' . esc_html__( 'Site access', 'role-gatekeeper' ) . '</h1>';
		if ( isset( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		if ( isset( $_GET['rw_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = get_transient( 'rolegate_sa_err_' . $uid );
			delete_transient( 'rolegate_sa_err_' . $uid );
			if ( is_string( $msg ) && '' !== $msg ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $msg ) . '</p></div>';
			}
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
		wp_nonce_field( self::ACTION );

		echo '<h2>' . esc_html__( 'Private site', 'role-gatekeeper' ) . '</h2><table class="form-table" role="presentation"><tbody>';
		$this->check_row( __( 'Private-site mode', 'role-gatekeeper' ), 'private_enabled', ! empty( $s['private_enabled'] ), __( 'Visitors must log in to see any page.', 'role-gatekeeper' ) );
		if ( empty( $s['private_enabled'] ) ) {
			echo '<tr><th scope="row">' . esc_html__( 'Confirmation', 'role-gatekeeper' ) . '</th><td><label><input type="checkbox" name="rw[confirm_private]" value="1" /> ' . esc_html__( 'I understand visitors will be sent to the login page.', 'role-gatekeeper' ) . '</label>';
			echo '<p class="description">' . esc_html( $this->recovery_note() ) . '</p></td></tr>';
		} else {
			echo '<tr><th scope="row">' . esc_html__( 'Recovery', 'role-gatekeeper' ) . '</th><td><p class="description">' . esc_html( $this->recovery_note() ) . '</p></td></tr>';
		}
		$this->check_row( __( 'Feeds', 'role-gatekeeper' ), 'private_feed', ! empty( $s['private_feed'] ), __( 'Require login for RSS and Atom feeds.', 'role-gatekeeper' ) );
		$this->check_row( __( 'REST API', 'role-gatekeeper' ), 'private_rest', ! empty( $s['private_rest'] ), __( 'Require login for REST requests. Application passwords keep working.', 'role-gatekeeper' ) );
		echo '<tr><th scope="row"><label for="rw-allow">' . esc_html__( 'Open paths', 'role-gatekeeper' ) . '</label></th><td>';
		printf( '<textarea id="rw-allow" name="rw[allow_paths]" rows="5" class="large-text code">%s</textarea>', esc_textarea( implode( "\n", (array) $s['allow_paths'] ) ) );
		echo '<p class="description">' . esc_html__( 'One path per line, such as /contact or /blog/*. These stay public.', 'role-gatekeeper' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Always left open: ', 'role-gatekeeper' ) . esc_html( implode( '; ', Gate::exempt_summary() ) ) . '</p></td></tr>';
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'wp-admin access', 'role-gatekeeper' ) . '</h2><table class="form-table" role="presentation"><tbody>';
		$this->check_row( __( 'Limit wp-admin', 'role-gatekeeper' ), 'admin_gate', ! empty( $s['admin_gate'] ), __( 'Send users without the capability below to the redirect URL.', 'role-gatekeeper' ) );
		printf(
			'<tr><th scope="row"><label for="rw-cap">%1$s</label></th><td><input id="rw-cap" name="rw[admin_gate_cap]" type="text" class="regular-text code" value="%2$s" /><p class="description">%3$s</p></td></tr>',
			esc_html__( 'Capability needed', 'role-gatekeeper' ),
			esc_attr( $s['admin_gate_cap'] ),
			esc_html__( 'Administrators and anyone with Role Gatekeeper management access are never redirected.', 'role-gatekeeper' )
		);
		printf(
			'<tr><th scope="row"><label for="rw-redir">%1$s</label></th><td><input id="rw-redir" name="rw[admin_redirect]" type="text" class="regular-text" value="%2$s" placeholder="%3$s" /></td></tr>',
			esc_html__( 'Redirect URL', 'role-gatekeeper' ),
			esc_attr( $s['admin_redirect'] ),
			esc_attr( home_url( '/' ) )
		);
		$this->check_row( __( 'Toolbar for those users', 'role-gatekeeper' ), 'toolbar_hide_gated', ! empty( $s['toolbar_hide_gated'] ), __( 'Hide the admin toolbar for users who are redirected.', 'role-gatekeeper' ) );
		echo '<tr><th scope="row">' . esc_html__( 'Hide toolbar for roles', 'role-gatekeeper' ) . '</th><td>';
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="rw[toolbar_hide_roles][]" value="%1$s" %2$s /> %3$s</label>',
				esc_attr( $slug ),
				checked( in_array( $slug, (array) $s['toolbar_hide_roles'], true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '</td></tr></tbody></table>';
		submit_button( __( 'Save changes', 'role-gatekeeper' ) );
		echo '</form></div>';
	}

	private function check_row( string $label, string $key, bool $on, string $help ): void {
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="rw[%2$s]" value="1" %3$s /> %4$s</label></td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			checked( $on, true, false ),
			esc_html( $help )
		);
	}

	private function recovery_note(): string {
		return __( 'If you are ever locked out, wp-login.php stays open and has a "Locked out of Role Gatekeeper?" link. You can also add define( \'ROLEGATE_DISABLE_SITE_ACCESS\', true ); to wp-config.php to switch every rule on this page off.', 'role-gatekeeper' );
	}
}
