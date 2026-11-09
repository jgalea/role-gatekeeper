<?php
namespace Rolewright\Modules\Site_Access;

use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Site_Access_Page {
	const SLUG   = 'rolewright-site-access';
	const ACTION = 'rolewright_save_site_access';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'save' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Site access', 'rolewright' ),
			__( 'Site access', 'rolewright' ),
			Caps::MANAGE_ACCESS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function save(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$raw   = isset( $_POST['rw'] ) && is_array( $_POST['rw'] ) ? wp_unslash( $_POST['rw'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$actor = get_current_user_id();
		$clean = Site_Access_Settings::sanitize( $raw, Site_Access_Settings::get(), $actor );
		$page  = admin_url( 'admin.php?page=' . self::SLUG );
		if ( is_wp_error( $clean ) ) {
			set_transient( 'rolewright_sa_err_' . $actor, $clean->get_error_message(), 60 );
			wp_safe_redirect( add_query_arg( 'rw_error', '1', $page ) );
			exit;
		}
		Site_Access_Settings::save( $clean, $actor );
		wp_safe_redirect( add_query_arg( 'updated', '1', $page ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		$s   = Site_Access_Settings::get();
		$uid = get_current_user_id();
		echo '<div class="wrap"><h1>' . esc_html__( 'Site access', 'rolewright' ) . '</h1>';
		if ( isset( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'rolewright' ) . '</p></div>';
		}
		if ( isset( $_GET['rw_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = get_transient( 'rolewright_sa_err_' . $uid );
			delete_transient( 'rolewright_sa_err_' . $uid );
			if ( is_string( $msg ) && '' !== $msg ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $msg ) . '</p></div>';
			}
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
		wp_nonce_field( self::ACTION );

		echo '<h2>' . esc_html__( 'Private site', 'rolewright' ) . '</h2><table class="form-table" role="presentation"><tbody>';
		$this->check_row( __( 'Private-site mode', 'rolewright' ), 'private_enabled', ! empty( $s['private_enabled'] ), __( 'Visitors must log in to see any page.', 'rolewright' ) );
		if ( empty( $s['private_enabled'] ) ) {
			echo '<tr><th scope="row">' . esc_html__( 'Confirmation', 'rolewright' ) . '</th><td><label><input type="checkbox" name="rw[confirm_private]" value="1" /> ' . esc_html__( 'I understand visitors will be sent to the login page.', 'rolewright' ) . '</label>';
			echo '<p class="description">' . esc_html( $this->recovery_note() ) . '</p></td></tr>';
		} else {
			echo '<tr><th scope="row">' . esc_html__( 'Recovery', 'rolewright' ) . '</th><td><p class="description">' . esc_html( $this->recovery_note() ) . '</p></td></tr>';
		}
		$this->check_row( __( 'Feeds', 'rolewright' ), 'private_feed', ! empty( $s['private_feed'] ), __( 'Require login for RSS and Atom feeds.', 'rolewright' ) );
		$this->check_row( __( 'REST API', 'rolewright' ), 'private_rest', ! empty( $s['private_rest'] ), __( 'Require login for REST requests. Application passwords keep working.', 'rolewright' ) );
		echo '<tr><th scope="row"><label for="rw-allow">' . esc_html__( 'Open paths', 'rolewright' ) . '</label></th><td>';
		printf( '<textarea id="rw-allow" name="rw[allow_paths]" rows="5" class="large-text code">%s</textarea>', esc_textarea( implode( "\n", (array) $s['allow_paths'] ) ) );
		echo '<p class="description">' . esc_html__( 'One path per line, such as /contact or /blog/*. These stay public.', 'rolewright' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Always left open: ', 'rolewright' ) . esc_html( implode( '; ', Gate::exempt_summary() ) ) . '</p></td></tr>';
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'wp-admin access', 'rolewright' ) . '</h2><table class="form-table" role="presentation"><tbody>';
		$this->check_row( __( 'Limit wp-admin', 'rolewright' ), 'admin_gate', ! empty( $s['admin_gate'] ), __( 'Send users without the capability below to the redirect URL.', 'rolewright' ) );
		printf(
			'<tr><th scope="row"><label for="rw-cap">%1$s</label></th><td><input id="rw-cap" name="rw[admin_gate_cap]" type="text" class="regular-text code" value="%2$s" /><p class="description">%3$s</p></td></tr>',
			esc_html__( 'Capability needed', 'rolewright' ),
			esc_attr( $s['admin_gate_cap'] ),
			esc_html__( 'Administrators and anyone with Rolewright management access are never redirected.', 'rolewright' )
		);
		printf(
			'<tr><th scope="row"><label for="rw-redir">%1$s</label></th><td><input id="rw-redir" name="rw[admin_redirect]" type="text" class="regular-text" value="%2$s" placeholder="%3$s" /></td></tr>',
			esc_html__( 'Redirect URL', 'rolewright' ),
			esc_attr( $s['admin_redirect'] ),
			esc_attr( home_url( '/' ) )
		);
		$this->check_row( __( 'Toolbar for those users', 'rolewright' ), 'toolbar_hide_gated', ! empty( $s['toolbar_hide_gated'] ), __( 'Hide the admin toolbar for users who are redirected.', 'rolewright' ) );
		echo '<tr><th scope="row">' . esc_html__( 'Hide toolbar for roles', 'rolewright' ) . '</th><td>';
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="rw[toolbar_hide_roles][]" value="%1$s" %2$s /> %3$s</label>',
				esc_attr( $slug ),
				checked( in_array( $slug, (array) $s['toolbar_hide_roles'], true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '</td></tr></tbody></table>';
		submit_button( __( 'Save changes', 'rolewright' ) );
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
		return __( 'If you are ever locked out, wp-login.php stays open and has a "Locked out of Rolewright?" link. You can also add define( \'ROLEWRIGHT_DISABLE_SITE_ACCESS\', true ); to wp-config.php to switch every rule on this page off.', 'rolewright' );
	}
}
