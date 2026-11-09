<?php
namespace Rolegate\Modules\Roles;

use Rolegate\Core\Module;
use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Roles_Module extends Module {
	const SLUG   = 'role-gatekeeper-roles';
	const ACTION = 'rolegate_roles';

	public function id(): string {
		return 'roles';
	}

	public function title(): string {
		return __( 'Role manager', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Add, rename, clone and delete roles, set the default registration roles, and reset roles to WordPress defaults.', 'role-gatekeeper' );
	}

	public function init(): void {
		add_action( 'user_register', array( Role_Service::class, 'apply_extra_defaults' ), 20 );
		if ( is_admin() ) {
			add_action( 'admin_menu', array( $this, 'menu' ) );
			add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
		}
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Roles', 'role-gatekeeper' ),
			__( 'Roles', 'role-gatekeeper' ),
			Caps::MANAGE_ROLES,
			self::SLUG,
			array( new Role_List(), 'render' )
		);
	}

	public static function page_url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'admin.php' ) );
	}

	public function handle(): void {
		if ( ! current_user_can( Caps::MANAGE_ROLES ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$actor = get_current_user_id();
		$op    = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$role  = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
		$name  = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$msg   = '';
		$err   = null;

		switch ( $op ) {
			case 'create':
				$res = Role_Service::create( $actor, $name );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					/* translators: %s: role name */
					$msg = sprintf( __( 'Role "%s" added.', 'role-gatekeeper' ), $name );
				}
				break;

			case 'clone':
				$res = Role_Service::clone_role( $actor, $role, $name );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					/* translators: %s: role name */
					$msg = sprintf( __( 'Role "%s" created with the same capabilities.', 'role-gatekeeper' ), $name );
				}
				break;

			case 'rename':
				$res = Role_Service::rename( $actor, $role, $name );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					$msg = __( 'Role renamed.', 'role-gatekeeper' );
				}
				break;

			case 'delete':
				$res = Role_Service::delete( $actor, $role );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					$msg = __( 'Role deleted.', 'role-gatekeeper' );
				}
				break;

			case 'bulk_delete':
				$roles = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['roles'] ) ) : array();
				if ( ! $roles ) {
					$err = new \WP_Error( 'rolegate_nothing', __( 'Select at least one role.', 'role-gatekeeper' ) );
					break;
				}
				$out = Role_Service::delete_unused( $actor, $roles );
				$msg = $out['deleted']
					/* translators: %d: number of roles */
					? sprintf( _n( '%d role deleted.', '%d roles deleted.', count( $out['deleted'] ), 'role-gatekeeper' ), count( $out['deleted'] ) )
					: '';
				if ( $out['errors'] ) {
					$err = new \WP_Error( 'rolegate_bulk', implode( ' ', array_values( $out['errors'] ) ) );
				}
				break;

			case 'default':
				$extras = isset( $_POST['extras'] ) && is_array( $_POST['extras'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['extras'] ) ) : array();
				$res    = Role_Service::set_default( $actor, $role, $extras );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					$msg = __( 'Default registration roles saved.', 'role-gatekeeper' );
				}
				break;

			case 'reset':
				if ( empty( $_POST['confirm_reset'] ) ) {
					$err = new \WP_Error( 'rolegate_confirm', __( 'Tick the confirmation box to reset the roles.', 'role-gatekeeper' ) );
					break;
				}
				$res = Role_Service::reset( $actor );
				if ( is_wp_error( $res ) ) {
					$err = $res;
				} else {
					$msg = __( 'Core roles are back to WordPress defaults. The previous roles were saved as a backup.', 'role-gatekeeper' );
				}
				break;

			default:
				$err = new \WP_Error( 'rolegate_unknown', __( 'Unknown action.', 'role-gatekeeper' ) );
		}

		$notices = array();
		if ( '' !== $msg ) {
			$notices[] = array( 'success', $msg );
		}
		if ( $err ) {
			$notices[] = array( 'error', $err->get_error_message() );
		}
		set_transient( 'rolegate_roles_notice_' . $actor, $notices, 60 );
		wp_safe_redirect( self::page_url() );
		exit;
	}
}
