<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * rolewright/v1. Reads need the matching Rolewright capability. Writes additionally need the
 * "allow changes" setting; they run as the signed-in caller through the same Guard checks as
 * the admin screens and never elevate.
 */
final class Rest_Routes {
	const NS = 'rolewright/v1';

	private const SLUG = '(?P<slug>[A-Za-z0-9_:\-]+)';

	public function register(): void {
		$read  = function ( string $cap ) {
			return function () use ( $cap ) {
				return current_user_can( $cap ) ? true : new \WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to do that.', 'rolewright' ), array( 'status' => rest_authorization_required_code() ) );
			};
		};
		$write = function ( string $cap ) {
			return function () use ( $cap ) {
				if ( ! Automation_Module::settings()['rest_writes'] ) {
					return new \WP_Error( 'rolewright_read_only', __( 'The Rolewright REST API is read-only. Enable changes under Rolewright > Automation.', 'rolewright' ), array( 'status' => 403 ) );
				}
				return current_user_can( $cap ) ? true : new \WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to do that.', 'rolewright' ), array( 'status' => rest_authorization_required_code() ) );
			};
		};
		$list  = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);

		register_rest_route(
			self::NS,
			'/roles',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'list_roles' ),
					'permission_callback' => $read( Caps::MANAGE_ROLES ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'create_role' ),
					'permission_callback' => $write( Caps::MANAGE_ROLES ),
					'args'                => array(
						'name'         => array(
							'type'     => 'string',
							'required' => true,
						),
						'slug'         => array( 'type' => 'string' ),
						'capabilities' => $list,
					),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/roles/' . self::SLUG,
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_role' ),
					'permission_callback' => $read( Caps::MANAGE_ROLES ),
				),
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'delete_role' ),
					'permission_callback' => $write( Caps::MANAGE_ROLES ),
					'args'                => array( 'confirm' => array( 'type' => 'boolean' ) ),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/roles/' . self::SLUG . '/caps',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'change_caps' ),
				'permission_callback' => $write( Caps::MANAGE_CAPS ),
				'args'                => array(
					'add'     => $list,
					'remove'  => $list,
					'deny'    => $list,
					'confirm' => array( 'type' => 'boolean' ),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/caps',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'list_caps' ),
				'permission_callback' => $read( Caps::MANAGE_CAPS ),
			)
		);
		register_rest_route(
			self::NS,
			'/users/(?P<id>\d+)/caps',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'user_caps' ),
				'permission_callback' => $read( Caps::MANAGE_USERS ),
			)
		);
		register_rest_route(
			self::NS,
			'/users/(?P<id>\d+)/roles',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'change_user_roles' ),
				'permission_callback' => $write( Caps::MANAGE_USERS ),
				'args'                => array(
					'assign'   => $list,
					'unassign' => $list,
					'confirm'  => array( 'type' => 'boolean' ),
				),
			)
		);
	}

	public function list_roles() {
		return rest_ensure_response( Ops::list_roles() );
	}

	public function get_role( \WP_REST_Request $request ) {
		return $this->respond( Ops::get_role( (string) $request['slug'] ) );
	}

	public function list_caps() {
		return rest_ensure_response( Ops::caps_by_role() );
	}

	public function user_caps( \WP_REST_Request $request ) {
		return $this->respond( Ops::user_summary( (int) $request['id'], get_current_user_id() ) );
	}

	public function create_role( \WP_REST_Request $request ) {
		$caps = $request->get_param( 'capabilities' );
		$slug = Ops::add_role( get_current_user_id(), (string) $request['name'], (string) $request['slug'], is_array( $caps ) ? $caps : array( 'read' ) );
		if ( is_wp_error( $slug ) ) {
			return $this->error( $slug );
		}
		$response = rest_ensure_response( Ops::get_role( $slug ) );
		$response->set_status( 201 );
		return $response;
	}

	public function delete_role( \WP_REST_Request $request ) {
		$slug    = (string) $request['slug'];
		$confirm = Gate::confirm_error( (bool) $request['confirm'], $slug, array() );
		if ( $confirm ) {
			return $this->error( $confirm );
		}
		$result = Ops::delete_role( get_current_user_id(), $slug );
		return is_wp_error( $result ) ? $this->error( $result ) : rest_ensure_response( array( 'deleted' => $slug ) );
	}

	public function change_caps( \WP_REST_Request $request ) {
		$slug   = (string) $request['slug'];
		$add    = (array) $request->get_param( 'add' );
		$remove = (array) $request->get_param( 'remove' );
		$deny   = (array) $request->get_param( 'deny' );
		$ask    = Gate::confirm_error( (bool) $request['confirm'], $slug, array_merge( $add, $remove, $deny ) );
		if ( $ask ) {
			return $this->error( $ask );
		}
		$result = Ops::change_role_caps( get_current_user_id(), $slug, $add, $remove, $deny );
		return is_wp_error( $result ) ? $this->error( $result ) : $this->respond( Ops::get_role( $slug ) );
	}

	public function change_user_roles( \WP_REST_Request $request ) {
		$id       = (int) $request['id'];
		$assign   = array_map( 'strval', (array) $request->get_param( 'assign' ) );
		$unassign = array_map( 'strval', (array) $request->get_param( 'unassign' ) );
		foreach ( $assign as $role ) {
			if ( ! get_role( $role ) ) {
				return $this->error( new \WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) ) );
			}
			$ask = Gate::confirm_error( (bool) $request['confirm'], $role, array() );
			if ( $ask ) {
				return $this->error( $ask );
			}
		}
		foreach ( $assign as $role ) {
			$result = Ops::assign_role( get_current_user_id(), $id, $role );
			if ( is_wp_error( $result ) ) {
				return $this->error( $result );
			}
		}
		foreach ( $unassign as $role ) {
			$result = Ops::unassign_role( get_current_user_id(), $id, $role );
			if ( is_wp_error( $result ) ) {
				return $this->error( $result );
			}
		}
		return $this->respond( Ops::user_summary( $id, get_current_user_id() ) );
	}

	/** @param mixed $data */
	private function respond( $data ) {
		return is_wp_error( $data ) ? $this->error( $data ) : rest_ensure_response( $data );
	}

	private function error( \WP_Error $error ): \WP_Error {
		$data = $error->get_error_data();
		if ( is_array( $data ) && isset( $data['status'] ) ) {
			return $error;
		}
		$forbidden = array( 'rolewright_lockout', 'rolewright_protected_role', 'rolewright_cap_not_held', 'rolewright_role_above_actor', 'rolewright_cannot_assign', 'rolewright_user_above_actor' );
		$status    = in_array( $error->get_error_code(), $forbidden, true ) ? 403 : 400;
		$data      = is_array( $data ) ? $data : array();
		return new \WP_Error( $error->get_error_code(), $error->get_error_message(), array_merge( $data, array( 'status' => $status ) ) );
	}
}
