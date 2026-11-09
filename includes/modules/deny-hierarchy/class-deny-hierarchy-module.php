<?php
namespace Rolewright\Modules\Deny_Hierarchy;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Deny_Hierarchy_Module extends Module {
	/** @var bool */
	private static $registered = false;

	public function id(): string {
		return 'deny-hierarchy';
	}

	public function title(): string {
		return __( 'Deny capabilities and role hierarchy', 'rolewright' );
	}

	public function description(): string {
		return __( 'Deny capabilities per role (a deny beats any grant), rank roles so users can only manage roles below their own, hide higher roles from lower managers, and view any user\'s effective capabilities.', 'rolewright' );
	}

	public function default_enabled(): bool {
		return false;
	}

	public function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		Denials::register();
		Hierarchy::register();
		if ( is_admin() ) {
			( new Admin_Page() )->register();
		}
	}
}
