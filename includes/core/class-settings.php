<?php
namespace Rolewright\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Top-level "Rolewright" menu and the module on/off page. Modules attach their own
 * pages with add_submenu_page( Settings::MENU_SLUG, ... ) on admin_menu priority 10.
 */
final class Settings {
	const MENU_SLUG = 'rolewright';
	const CAP       = 'rolewright_manage';

	public function init(): void {
		add_action( 'admin_menu', array( $this, 'menu' ), 5 );
		add_action( 'admin_post_rolewright_save_modules', array( $this, 'save' ) );
	}

	public function menu(): void {
		add_menu_page(
			__( 'Rolewright', 'rolewright' ),
			__( 'Rolewright', 'rolewright' ),
			self::CAP,
			self::MENU_SLUG,
			array( $this, 'render' ),
			'dashicons-admin-network',
			71
		);
	}

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'Rolewright', 'rolewright' ) . '</h1>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolewright_save_modules" />';
		wp_nonce_field( 'rolewright_save_modules' );
		echo '<table class="form-table" role="presentation"><tbody>';
		foreach ( Plugin::modules() as $module ) {
			$locked = ( 'safety' === $module->id() );
			printf(
				'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="modules[%2$s]" value="1" %3$s %4$s /> %5$s</label></td></tr>',
				esc_html( $module->title() ),
				esc_attr( $module->id() ),
				checked( Plugin::is_enabled( $module->id() ) || $locked, true, false ),
				disabled( $locked, true, false ),
				esc_html( $module->description() )
			);
		}
		echo '</tbody></table>';
		submit_button( __( 'Save modules', 'rolewright' ) );
		echo '</form></div>';
	}

	public function save(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolewright_save_modules' );
		$posted = isset( $_POST['modules'] ) && is_array( $_POST['modules'] ) ? array_map( 'sanitize_key', array_keys( wp_unslash( $_POST['modules'] ) ) ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only the keys are read, each through sanitize_key.
		$map    = array();
		foreach ( Plugin::modules() as $module ) {
			$map[ $module->id() ] = in_array( $module->id(), $posted, true );
		}
		$map['safety'] = true;
		update_option( Plugin::OPTION_MODULES, $map, false );
		wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'admin.php?page=' . self::MENU_SLUG ) ) );
		exit;
	}
}
