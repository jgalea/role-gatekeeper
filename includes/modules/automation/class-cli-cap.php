<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

class Cli_Cap extends Cli_Base {
	/**
	 * Grant a capability to a role.
	 *
	 * ## OPTIONS
	 *
	 * <role>
	 * : Role slug.
	 *
	 * <cap>
	 * : Capability name.
	 *
	 * [--deny]
	 * : Store an explicit deny instead of a grant.
	 */
	public function add( $args, $assoc ) {
		$actor = self::actor( array( Caps::MANAGE_CAPS ) );
		if ( ! empty( $assoc['deny'] ) ) {
			self::check( Ops::change_role_caps( $actor, $args[0], array(), array(), array( $args[1] ) ) );
		} else {
			self::check( Ops::change_role_caps( $actor, $args[0], array( $args[1] ), array() ) );
		}
		\WP_CLI::success( 'Updated ' . $args[0] . '.' );
	}

	/**
	 * Remove a capability from a role.
	 *
	 * ## OPTIONS
	 *
	 * <role>
	 * : Role slug.
	 *
	 * <cap>
	 * : Capability name.
	 */
	public function remove( $args ) {
		$actor = self::actor( array( Caps::MANAGE_CAPS ) );
		self::check( Ops::change_role_caps( $actor, $args[0], array(), array( $args[1] ) ) );
		\WP_CLI::success( 'Updated ' . $args[0] . '.' );
	}

	/**
	 * List capabilities, or the capabilities of one role.
	 *
	 * ## OPTIONS
	 *
	 * [<role>]
	 * : Role slug.
	 *
	 * [--format=<format>]
	 * : table, json, csv or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * @subcommand list
	 */
	public function list_( $args, $assoc ) {
		self::actor( array( Caps::MANAGE_CAPS ) );
		$rows = array();
		if ( isset( $args[0] ) ) {
			$role = self::check( Ops::get_role( $args[0] ) );
			foreach ( $role['capabilities'] as $cap => $grant ) {
				$rows[] = array(
					'cap'   => $cap,
					'state' => $grant ? 'granted' : 'denied',
				);
			}
			\WP_CLI\Utils\format_items( $assoc['format'] ?? 'table', $rows, array( 'cap', 'state' ) );
			return;
		}
		foreach ( Ops::caps_by_role() as $cap => $roles ) {
			$rows[] = array(
				'cap'   => $cap,
				'roles' => implode( ',', $roles ),
			);
		}
		\WP_CLI\Utils\format_items( $assoc['format'] ?? 'table', $rows, array( 'cap', 'roles' ) );
	}
}
