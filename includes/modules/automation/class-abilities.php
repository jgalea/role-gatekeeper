<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress Abilities API registration. Reads are always registered; abilities that change
 * roles only when the setting allows it, and risky changes need confirm = true. Everything
 * runs as the calling user through the same Guard checks as the other surfaces.
 */
final class Abilities {
	const CATEGORY = 'rolewright';

	public function register_category(): void {
		if ( function_exists( 'wp_register_ability_category' ) ) {
			wp_register_ability_category(
				self::CATEGORY,
				array(
					'label'       => __( 'Rolewright', 'rolewright' ),
					'description' => __( 'Roles, capabilities and user roles.', 'rolewright' ),
				)
			);
		}
	}

	public function register(): void {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}
		$str  = array( 'type' => 'string' );
		$bool = array( 'type' => 'boolean' );

		$this->add(
			'list-roles',
			__( 'List roles', 'rolewright' ),
			__( 'Lists every role with its slug, name, capability count and user count.', 'rolewright' ),
			Caps::MANAGE_ROLES,
			null,
			true,
			function () {
				return array( 'roles' => Ops::list_roles() );
			}
		);
		$this->add(
			'get-role',
			__( 'Get a role', 'rolewright' ),
			__( 'Returns a role\'s name and capabilities.', 'rolewright' ),
			Caps::MANAGE_ROLES,
			$this->schema( array( 'role' => $str ), array( 'role' ) ),
			true,
			function ( $input ) {
				return Ops::get_role( (string) ( $input['role'] ?? '' ) );
			}
		);
		$this->add(
			'list-capabilities',
			__( 'List capabilities', 'rolewright' ),
			__( 'Lists every capability and the roles that grant it.', 'rolewright' ),
			Caps::MANAGE_CAPS,
			null,
			true,
			function () {
				return array( 'capabilities' => Ops::caps_by_role() );
			}
		);
		$this->add(
			'get-user-capabilities',
			__( 'Get a user\'s effective capabilities', 'rolewright' ),
			__( 'Returns the roles, per-user capabilities and effective capabilities of a user.', 'rolewright' ),
			Caps::MANAGE_USERS,
			$this->schema( array( 'user' => array( 'type' => 'integer' ) ), array( 'user' ) ),
			true,
			function ( $input ) {
				return Ops::user_summary( (int) ( $input['user'] ?? 0 ), get_current_user_id() );
			}
		);

		if ( ! Automation_Module::settings()['abilities_writes'] ) {
			return;
		}

		$this->add(
			'add-role-capability',
			__( 'Grant a capability to a role', 'rolewright' ),
			__( 'Grants a capability to a role. Needs confirm = true when the role is protected or the capability can take over the site.', 'rolewright' ),
			Caps::MANAGE_CAPS,
			$this->schema(
				array(
					'role'       => $str,
					'capability' => $str,
					'confirm'    => $bool,
				),
				array( 'role', 'capability' )
			),
			false,
			function ( $input ) {
				return $this->change_caps( $input, true );
			}
		);
		$this->add(
			'remove-role-capability',
			__( 'Remove a capability from a role', 'rolewright' ),
			__( 'Removes a capability from a role. Needs confirm = true when the role is protected or the capability can take over the site. Changes that would lock the caller out are refused.', 'rolewright' ),
			Caps::MANAGE_CAPS,
			$this->schema(
				array(
					'role'       => $str,
					'capability' => $str,
					'confirm'    => $bool,
				),
				array( 'role', 'capability' )
			),
			false,
			function ( $input ) {
				return $this->change_caps( $input, false );
			}
		);
		$this->add(
			'assign-user-role',
			__( 'Give a user a role', 'rolewright' ),
			__( 'Adds a role to a user. Needs confirm = true when the role is protected or holds capabilities that can take over the site.', 'rolewright' ),
			Caps::MANAGE_USERS,
			$this->schema(
				array(
					'user'    => array( 'type' => 'integer' ),
					'role'    => $str,
					'confirm' => $bool,
				),
				array( 'user', 'role' )
			),
			false,
			function ( $input ) {
				$role = (string) ( $input['role'] ?? '' );
				$ask  = Gate::confirm_error( ! empty( $input['confirm'] ), $role, array() );
				if ( $ask ) {
					return $ask;
				}
				$result = Ops::assign_role( get_current_user_id(), (int) ( $input['user'] ?? 0 ), $role );
				return is_wp_error( $result ) ? $result : Ops::user_summary( (int) $input['user'], get_current_user_id() );
			}
		);
		$this->add(
			'unassign-user-role',
			__( 'Take a role away from a user', 'rolewright' ),
			__( 'Removes a role from a user. Changes that would lock the caller out are refused.', 'rolewright' ),
			Caps::MANAGE_USERS,
			$this->schema(
				array(
					'user' => array( 'type' => 'integer' ),
					'role' => $str,
				),
				array( 'user', 'role' )
			),
			false,
			function ( $input ) {
				$result = Ops::unassign_role( get_current_user_id(), (int) ( $input['user'] ?? 0 ), (string) ( $input['role'] ?? '' ) );
				return is_wp_error( $result ) ? $result : Ops::user_summary( (int) $input['user'], get_current_user_id() );
			}
		);
		$this->add(
			'delete-role',
			__( 'Delete a role', 'rolewright' ),
			__( 'Deletes a role that has no users. Needs confirm = true when the role is protected or holds capabilities that can take over the site.', 'rolewright' ),
			Caps::MANAGE_ROLES,
			$this->schema(
				array(
					'role'    => $str,
					'confirm' => $bool,
				),
				array( 'role' )
			),
			false,
			function ( $input ) {
				$role = (string) ( $input['role'] ?? '' );
				$ask  = Gate::confirm_error( ! empty( $input['confirm'] ), $role, array() );
				if ( $ask ) {
					return $ask;
				}
				$result = Ops::delete_role( get_current_user_id(), $role );
				return is_wp_error( $result ) ? $result : array( 'deleted' => $role );
			}
		);
	}

	/** @param mixed $input */
	private function change_caps( $input, bool $grant ) {
		$role = (string) ( $input['role'] ?? '' );
		$cap  = (string) ( $input['capability'] ?? '' );
		$ask  = Gate::confirm_error( ! empty( $input['confirm'] ), $role, array( $cap ) );
		if ( $ask ) {
			return $ask;
		}
		$result = $grant
			? Ops::change_role_caps( get_current_user_id(), $role, array( $cap ), array() )
			: Ops::change_role_caps( get_current_user_id(), $role, array(), array( $cap ) );
		return is_wp_error( $result ) ? $result : Ops::get_role( $role );
	}

	private function schema( array $properties, array $required ): array {
		return array(
			'type'                 => 'object',
			'properties'           => $properties,
			'required'             => $required,
			'additionalProperties' => false,
		);
	}

	private function add( string $name, string $label, string $description, string $cap, ?array $input, bool $readonly, callable $run ): void {
		$args = array(
			'label'               => $label,
			'description'         => $description,
			'category'            => self::CATEGORY,
			'execute_callback'    => $run,
			'permission_callback' => function () use ( $cap ) {
				return current_user_can( $cap );
			},
			'meta'                => array(
				'show_in_rest' => true,
				'annotations'  => array(
					'readonly'    => $readonly,
					'destructive' => ! $readonly,
				),
			),
		);
		if ( null !== $input ) {
			$args['input_schema'] = $input;
		}
		wp_register_ability( self::CATEGORY . '/' . $name, $args );
	}
}
