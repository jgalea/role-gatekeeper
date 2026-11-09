<?php
namespace Rolegate\Modules\Edit_Scope;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Edit_Scope_Module extends Module {
	public function id(): string {
		return 'edit-scope';
	}

	public function title(): string {
		return __( 'Edit scope', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Limit what a role or user can edit by post ID, author or term, and which terms they can assign.', 'role-gatekeeper' );
	}

	public function default_enabled(): bool {
		return true;
	}

	public function init(): void {
		add_filter( 'rolegate_module_restricts_user', array( __CLASS__, 'restricts_user' ), 10, 3 );
		add_action( 'update_option_' . Rules::OPTION, array( Rules::class, 'flush' ) );
		add_action( 'add_option_' . Rules::OPTION, array( Rules::class, 'flush' ) );
		( new Scope_Enforcer() )->register();
		add_filter( 'rolegate_portability_sections', array( Portability_Section::class, 'register' ) );
		if ( Gravity_Forms::available() ) {
			( new Gravity_Forms() )->register();
		}
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
		if ( $restricts || 'edit-scope' !== $module ) {
			return (bool) $restricts;
		}
		return (bool) Rules::for_user( (int) $user_id );
	}
}
