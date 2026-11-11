<?php
namespace Rolegate\Modules\Test_As_User;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Test_As_User_Module extends Module {
	public function id(): string {
		return 'test-as-user';
	}

	public function title(): string {
		return __( 'Test as this user', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Sign in as a user with fewer permissions than you for up to an hour to see the site as they do, with a banner and a one-click way back to your own account.', 'role-gatekeeper' );
	}

	public function default_enabled(): bool {
		return false;
	}

	public function init(): void {
		( new Switcher() )->register();
	}
}
