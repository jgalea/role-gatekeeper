<?php
namespace Rolegate\Modules\User_Roles;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class User_Roles_Module extends Module {
	public function id(): string {
		return 'user-roles';
	}

	public function title(): string {
		return __( 'User roles', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Several roles per user, per-user capabilities, bulk add and remove role, a Roles column and a filter for users without a role.', 'role-gatekeeper' );
	}

	public function init(): void {
		if ( ! is_admin() ) {
			return;
		}
		( new Profile() )->register();
		( new Users_List() )->register();
	}
}
