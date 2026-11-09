<?php
namespace Rolegate\Modules\Site_Access;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Site_Access_Module extends Module {
	public function id(): string {
		return 'site-access';
	}

	public function title(): string {
		return __( 'Site access', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Private-site mode, wp-admin access by role and toolbar hiding. Off until you switch it on.', 'role-gatekeeper' );
	}

	public function default_enabled(): bool {
		return false;
	}

	public function init(): void {
		add_filter( 'rolegate_module_restricts_user', array( __CLASS__, 'restricts_user' ), 10, 3 );
		if ( defined( 'ROLEGATE_DISABLE_SITE_ACCESS' ) && ROLEGATE_DISABLE_SITE_ACCESS ) {
			return;
		}
		( new Gate() )->register();
		( new Admin_Gate() )->register();
		if ( is_admin() ) {
			( new Site_Access_Page() )->register();
		}
	}

	/**
	 * @param bool   $restricts
	 * @param string $module
	 * @param int    $user_id
	 */
	public static function restricts_user( $restricts, $module, $user_id ): bool {
		if ( $restricts || 'site-access' !== $module ) {
			return (bool) $restricts;
		}
		$user = get_userdata( (int) $user_id );
		return $user && Admin_Gate::is_gated( $user, Site_Access_Settings::get() );
	}
}
