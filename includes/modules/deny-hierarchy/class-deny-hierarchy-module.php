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
		add_filter(
			'rolewright_role_change_veto',
			function ( $veto, $op, $actor, $role ) {
				if ( $veto instanceof \WP_Error ) {
					return $veto;
				}
				$check = Hierarchy::assert_can_manage_role( (int) $actor, (string) $role );
				return is_wp_error( $check ) ? $check : $veto;
			},
			10,
			4
		);
		if ( is_admin() ) {
			( new Admin_Page() )->register();
		}
	}
}
