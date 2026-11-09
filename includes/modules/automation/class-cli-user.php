<?php
namespace Rolegate\Modules\Automation;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

class Cli_User extends Cli_Base {
	/**
	 * Show a user's roles and effective capabilities.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * [--format=<format>]
	 * : table, json or yaml.
	 * ---
	 * default: table
	 * ---
	 */
	public function roles( $args, $assoc ) {
		self::actor( array( Caps::MANAGE_USERS ) );
		$summary = self::check( Ops::user_summary( self::user_id( $args[0] ) ) );
		if ( 'json' === ( $assoc['format'] ?? '' ) ) {
			\WP_CLI::print_value( $summary, array( 'format' => 'json' ) );
			return;
		}
		\WP_CLI::line( 'Roles: ' . implode( ', ', $summary['roles'] ) );
		\WP_CLI::line( 'Capabilities: ' . count( $summary['capabilities'] ) );
	}

	/**
	 * Give a user a role.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * <role>
	 * : Role slug.
	 */
	public function assign( $args ) {
		$actor = self::actor( array( Caps::MANAGE_USERS ) );
		self::check( Ops::assign_role( $actor, self::user_id( $args[0] ), $args[1] ) );
		\WP_CLI::success( 'Gave ' . $args[0] . ' the ' . $args[1] . ' role.' );
	}

	/**
	 * Take a role away from a user.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * <role>
	 * : Role slug.
	 */
	public function unassign( $args ) {
		$actor = self::actor( array( Caps::MANAGE_USERS ) );
		self::check( Ops::unassign_role( $actor, self::user_id( $args[0] ), $args[1] ) );
		\WP_CLI::success( 'Removed the ' . $args[1] . ' role from ' . $args[0] . '.' );
	}
}
