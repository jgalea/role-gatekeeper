<?php
namespace Rolegate\Modules\Automation;

use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Automation_Page {
	const SLUG = 'role-gatekeeper-automation';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolegate_automation_save', array( $this, 'save' ) );
	}

	public function menu(): void {
		add_submenu_page( Settings::MENU_SLUG, __( 'Automation', 'role-gatekeeper' ), __( 'Automation', 'role-gatekeeper' ), Caps::MANAGE, self::SLUG, array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		$settings = Automation_Module::settings();
		$can_edit = Settings::can_change( get_current_user_id() );
		echo '<div class="wrap"><h1>' . esc_html__( 'Automation', 'role-gatekeeper' ) . '</h1>';
		// phpcs:ignore WordPress.Security.NonceVerification -- display flag only.
		if ( isset( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		echo '<p>' . esc_html__( 'The REST routes (rolegate/v1) and abilities are read-only until you switch writes on. Every request runs with the caller\'s own capabilities and the same safety checks as the admin screens. WP-CLI runs as the user passed with --user.', 'role-gatekeeper' ) . '</p>';
		if ( ! $can_edit ) {
			echo '<p>' . esc_html__( 'Only an administrator who holds every administrator capability can change these settings.', 'role-gatekeeper' ) . '</p>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="rolegate_automation_save" />';
		wp_nonce_field( 'rolegate_automation_save' );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="rest_writes" value="1" %2$s %4$s /> %3$s</label></td></tr>',
			esc_html__( 'REST API', 'role-gatekeeper' ),
			checked( $settings['rest_writes'], true, false ),
			esc_html__( 'Allow changes (create and delete roles, change capabilities, assign roles)', 'role-gatekeeper' ),
			disabled( ! $can_edit, true, false )
		);
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="abilities_writes" value="1" %2$s %4$s /> %3$s</label></td></tr>',
			esc_html__( 'Abilities API', 'role-gatekeeper' ),
			checked( $settings['abilities_writes'], true, false ),
			esc_html__( 'Register abilities that change roles (risky changes still need an explicit confirm flag)', 'role-gatekeeper' ),
			disabled( ! $can_edit, true, false )
		);
		echo '</tbody></table>';
		if ( $can_edit ) {
			submit_button();
		}
		echo '</form></div>';
	}

	public function save(): void {
		if ( ! current_user_can( Caps::MANAGE ) || ! Settings::can_change( get_current_user_id() ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolegate_automation_save' );
		self::apply(
			get_current_user_id(),
			array(
				'rest_writes'      => ! empty( $_POST['rest_writes'] ),
				'abilities_writes' => ! empty( $_POST['abilities_writes'] ),
			)
		);
		wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'admin.php?page=' . self::SLUG ) ) );
		exit;
	}

	/**
	 * @param array{rest_writes:bool,abilities_writes:bool} $new
	 * @return true|\WP_Error
	 */
	public static function apply( int $actor, array $new ) {
		if ( ! Settings::can_change( $actor ) ) {
			return new \WP_Error( 'rolegate_not_authority', __( 'Only an administrator who holds every administrator capability can change these settings.', 'role-gatekeeper' ) );
		}
		$before = Automation_Module::settings();
		$before = array(
			'rest_writes'      => ! empty( $before['rest_writes'] ),
			'abilities_writes' => ! empty( $before['abilities_writes'] ),
		);
		$after  = array(
			'rest_writes'      => ! empty( $new['rest_writes'] ),
			'abilities_writes' => ! empty( $new['abilities_writes'] ),
		);
		update_option( Automation_Module::OPTION_SETTINGS, $after, false );
		if ( $before !== $after ) {
			do_action(
				'rolegate_changed',
				'automation.updated',
				array(
					'actor'  => $actor,
					'target' => 'automation',
					'before' => $before,
					'after'  => $after,
				)
			);
		}
		return true;
	}
}
