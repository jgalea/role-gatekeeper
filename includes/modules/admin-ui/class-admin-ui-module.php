<?php
namespace Rolegate\Modules\Admin_Ui;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Admin_Ui_Module extends Module {
	public function id(): string {
		return 'admin-ui';
	}

	public function title(): string {
		return __( 'Admin interface', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Hide and block admin menu items, meta boxes, dashboard widgets, Appearance screens, plugin actions, theme switching and toolbar items per role or user.', 'role-gatekeeper' );
	}

	public function init(): void {
		add_filter( 'rolegate_module_restricts_user', array( __CLASS__, 'restricts_user' ), 10, 3 );
		( new Enforcer() )->register();
		( new Discovery() )->register();
		add_filter( 'rolegate_portability_sections', array( Portability_Section::class, 'register' ) );
		if ( is_admin() ) {
			( new Admin_Page() )->register();
		}
	}

	/**
	 * @param bool   $restricts
	 * @param string $module
	 * @param int    $user_id
	 */
	public static function restricts_user( $restricts, $module, $user_id ): bool {
		if ( $restricts || 'admin-ui' !== $module ) {
			return (bool) $restricts;
		}
		$rule = Rules::effective_for_user( (int) $user_id );
		return null !== $rule && ! Engine::is_empty( $rule );
	}
}
