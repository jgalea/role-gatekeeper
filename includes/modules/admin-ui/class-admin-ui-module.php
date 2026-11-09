<?php
namespace Rolewright\Modules\Admin_Ui;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Admin_Ui_Module extends Module {
	public function id(): string {
		return 'admin-ui';
	}

	public function title(): string {
		return __( 'Admin interface', 'rolewright' );
	}

	public function description(): string {
		return __( 'Hide and block admin menu items, meta boxes, dashboard widgets, Appearance screens, plugin actions, theme switching and toolbar items per role or user.', 'rolewright' );
	}

	public function init(): void {
		( new Enforcer() )->register();
		( new Discovery() )->register();
		add_filter( 'rolewright_portability_sections', array( Portability_Section::class, 'register' ) );
		if ( is_admin() ) {
			( new Admin_Page() )->register();
		}
	}
}
