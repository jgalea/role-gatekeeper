<?php
namespace Rolewright\Modules\Edit_Scope;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Edit_Scope_Module extends Module {
	public function id(): string {
		return 'edit-scope';
	}

	public function title(): string {
		return __( 'Edit scope', 'rolewright' );
	}

	public function description(): string {
		return __( 'Limit what a role or user can edit by post ID, author or term, and which terms they can assign.', 'rolewright' );
	}

	public function default_enabled(): bool {
		return true;
	}

	public function init(): void {
		add_action( 'update_option_' . Rules::OPTION, array( Rules::class, 'flush' ) );
		add_action( 'add_option_' . Rules::OPTION, array( Rules::class, 'flush' ) );
		( new Scope_Enforcer() )->register();
		add_filter( 'rolewright_portability_sections', array( Portability_Section::class, 'register' ) );
		if ( Gravity_Forms::available() ) {
			( new Gravity_Forms() )->register();
		}
		if ( is_admin() ) {
			( new Admin_Page() )->register();
		}
	}
}
