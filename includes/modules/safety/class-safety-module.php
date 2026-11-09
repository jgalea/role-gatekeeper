<?php
namespace Rolegate\Modules\Safety;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Safety_Module extends Module {
	public function id(): string {
		return 'safety';
	}

	public function title(): string {
		return __( 'Safety net', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Stops privilege escalation and self-lockout, protects the Administrator role, and offers an emailed rescue link. Always on.', 'role-gatekeeper' );
	}

	public function default_enabled(): bool {
		return true;
	}

	public function init(): void {
		add_action( 'rolegate_activate', array( Caps::class, 'grant_to_administrator' ) );
		add_action( 'init', array( Caps::class, 'self_heal' ), 1 );
		add_filter( 'user_has_cap', array( Caps::class, 'filter_user_has_cap' ), PHP_INT_MAX, 4 );
		( new Enforcer() )->register();
		( new Rescue() )->register();
	}
}
