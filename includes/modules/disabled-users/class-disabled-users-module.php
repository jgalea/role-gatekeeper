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
		if ( ! is_admin() ) {
			return;
		}
		( new Profile_Field() )->register();
		( new Users_List() )->register();
	}
}
