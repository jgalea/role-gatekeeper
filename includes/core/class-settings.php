<?php
namespace Rolegate\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Top-level "Role Gatekeeper" menu and the module on/off page. Modules attach their own
 * pages with add_submenu_page( Settings::MENU_SLUG, ... ) on admin_menu priority 10.
 */
final class Settings {
	const MENU_SLUG = 'role-gatekeeper';
	const CAP       = 'rolegate_manage';

	public function init(): void {
		add_action( 'admin_menu', array( $this, 'menu' ), 5 );
		add_action( 'admin_post_rolegate_save_modules', array( $this, 'save' ) );
	}

	public function menu(): void {
		add_menu_page(
			__( 'Role Gatekeeper', 'role-gatekeeper' ),
			__( 'Role Gatekeeper', 'role-gatekeeper' ),
			self::CAP,
			self::MENU_SLUG,
			array( $this, 'render' ),
			'dashicons-admin-network',
			71
		);
	}

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		$can_edit = self::can_change( get_current_user_id() );
		echo '<div class="wrap"><h1>' . esc_html__( 'Role Gatekeeper', 'role-gatekeeper' ) . '</h1>';
		// phpcs:disable WordPress.Security.NonceVerification -- display flags only.
		if ( isset( $_GET['refused'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Nothing was saved: a module you tried to switch off currently applies rules to your own account. Ask a super admin.', 'role-gatekeeper' ) . '</p></div>';
		} elseif ( isset( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Modules saved.', 'role-gatekeeper' ) . '</p></div>';
		}
		// phpcs:enable
		if ( ! $can_edit ) {
			echo '<p>' . esc_html__( 'Only an administrator who holds every administrator capability can switch modules on or off.', 'role-gatekeeper' ) . '</p>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_save_modules" />';
		wp_nonce_field( 'rolegate_save_modules' );
		echo '<table class="form-table" role="presentation"><tbody>';
		foreach ( Plugin::modules() as $module ) {
			$locked = ( 'safety' === $module->id() ) || ! $can_edit;
			printf(
				'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="modules[%2$s]" value="1" %3$s %4$s /> %5$s</label></td></tr>',
				esc_html( $module->title() ),
				esc_attr( $module->id() ),
				checked( Plugin::is_enabled( $module->id() ) || 'safety' === $module->id(), true, false ),
				disabled( $locked, true, false ),
				esc_html( $module->description() )
			);
		}
		echo '</tbody></table>';
		if ( $can_edit ) {
			submit_button( __( 'Save modules', 'role-gatekeeper' ) );
		}
		echo '</form></div>';
	}

	/**
	 * Plugin-wide settings need an administrator-level authority, not just rolegate_manage.
	 */
	public static function can_change( int $user_id ): bool {
		return \Rolegate\Modules\Safety\Guard::is_site_authority( $user_id );
	}

	/**
	 * Modules from $turning_off whose rules currently apply to the user. Modules answer
	 * through the rolegate_module_restricts_user filter. Super admins are never refused.
	 *
	 * @param string[] $turning_off
	 * @return string[]
	 */
	public static function restricting_modules( int $user_id, array $turning_off ): array {
		if ( is_multisite() && is_super_admin( $user_id ) ) {
			return array();
		}
		$out = array();
		foreach ( $turning_off as $id ) {
			if ( apply_filters( 'rolegate_module_restricts_user', false, (string) $id, $user_id ) ) {
				$out[] = (string) $id;
			}
		}
		return $out;
	}

	/**
	 * Saves the module map for $actor after the authority and self-restriction checks,
	 * and fires rolegate_changed (modules.updated).
	 *
	 * @param string[] $enabled_ids
	 * @return true|\WP_Error
	 */
	public static function apply_modules( int $actor, array $enabled_ids ) {
		$shell = $actor <= 0 && defined( 'WP_CLI' ) && WP_CLI;
		if ( ! $shell && ! self::can_change( $actor ) ) {
			return new \WP_Error( 'rolegate_not_authority', __( 'Only an administrator who holds every administrator capability can switch modules on or off.', 'role-gatekeeper' ) );
		}
		$before = array();
		$after  = array();
		foreach ( Plugin::modules() as $module ) {
			$before[ $module->id() ] = Plugin::is_enabled( $module->id() );
			$after[ $module->id() ]  = in_array( $module->id(), $enabled_ids, true );
		}
		$after['safety']  = true;
		$before['safety'] = true;
		$turning_off      = array_keys( array_filter( $before ) );
		$turning_off      = array_values(
			array_filter(
				$turning_off,
				function ( $id ) use ( $after ) {
					return empty( $after[ $id ] );
				}
			)
		);
		$restricting      = self::restricting_modules( $actor, $turning_off );
		if ( $restricting ) {
			return new \WP_Error( 'rolegate_module_applies_to_actor', __( 'A module you tried to switch off currently applies rules to your own account.', 'role-gatekeeper' ), array( 'modules' => $restricting ) );
		}
		if ( $before === $after ) {
			return true;
		}
		update_option( Plugin::OPTION_MODULES, $after, false );
		do_action(
			'rolegate_changed',
			'modules.updated',
			array(
				'actor'  => $actor,
				'target' => 'modules',
				'before' => $before,
				'after'  => $after,
			)
		);
		return true;
	}

	public function save(): void {
		if ( ! current_user_can( self::CAP ) || ! self::can_change( get_current_user_id() ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolegate_save_modules' );
		$posted = isset( $_POST['modules'] ) && is_array( $_POST['modules'] ) ? array_map( 'sanitize_key', array_keys( wp_unslash( $_POST['modules'] ) ) ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only the keys are read, each through sanitize_key.
		$result = self::apply_modules( get_current_user_id(), $posted );
		$flag   = is_wp_error( $result ) ? 'refused' : 'updated';
		wp_safe_redirect( add_query_arg( $flag, '1', admin_url( 'admin.php?page=' . self::MENU_SLUG ) ) );
		exit;
	}
}
