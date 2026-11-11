<?php
namespace Rolegate\Modules\Disabled_Users;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Disabled_Users_Module extends Module {
	public function id(): string {
		return 'disabled-users';
	}

	public function title(): string {
		return __( 'Disabled accounts', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Block individual users from logging in while keeping their account and posts. Covers the login form, existing sessions, REST, XML-RPC and application passwords, with a user screen checkbox and bulk actions.', 'role-gatekeeper' );
	}

	public function init(): void {
		( new Login_Guard() )->register();
		add_action( Accounts::DUE_HOOK, array( Accounts::class, 'apply_due_all' ) );
		if ( ! wp_next_scheduled( Accounts::DUE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', Accounts::DUE_HOOK );
		}
		if ( ! is_admin() ) {
			return;
		}
		add_filter( 'rolegate_module_warning', array( $this, 'module_warning' ), 10, 2 );
		add_filter( 'plugin_action_links_' . plugin_basename( ROLEGATE_FILE ), array( $this, 'confirm_deactivate' ) );
		add_action( 'admin_notices', array( $this, 'plugins_notice' ) );
		( new Profile_Field() )->register();
		( new Users_List() )->register();
		( new Settings_Page() )->register();
	}

	public function module_warning( $text, $id ) {
		$count = 'disabled-users' === $id ? Accounts::count_disabled() : 0;
		if ( ! $count ) {
			return $text;
		}
		/* translators: %s: number of accounts */
		return sprintf( _n( '%s account is disabled. Switching this module off lets it log in again.', '%s accounts are disabled. Switching this module off lets them log in again.', $count, 'role-gatekeeper' ), number_format_i18n( $count ) );
	}

	public function confirm_deactivate( $links ) {
		$count = Accounts::count_disabled();
		if ( $count && isset( $links['deactivate'] ) ) {
			/* translators: %s: number of accounts */
			$message             = sprintf( _n( '%s disabled account will be able to log in again. Deactivate anyway?', '%s disabled accounts will be able to log in again. Deactivate anyway?', $count, 'role-gatekeeper' ), number_format_i18n( $count ) );
			$links['deactivate'] = str_replace( '<a ', '<a onclick="' . esc_attr( 'return confirm(' . wp_json_encode( $message ) . ');' ) . '" ', $links['deactivate'] );
		}
		return $links;
	}

	public function plugins_notice(): void {
		global $pagenow;
		$count = 'plugins.php' === $pagenow && current_user_can( 'activate_plugins' ) ? Accounts::count_disabled() : 0;
		if ( ! $count ) {
			return;
		}
		/* translators: %s: number of accounts */
		$text = sprintf( _n( 'Role Gatekeeper is blocking %s disabled account. Deactivating or deleting the plugin lets it log in again.', 'Role Gatekeeper is blocking %s disabled accounts. Deactivating or deleting the plugin lets them log in again.', $count, 'role-gatekeeper' ), number_format_i18n( $count ) );
		printf( '<div class="notice notice-warning"><p>%s</p></div>', esc_html( $text ) );
	}
}
