<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Manage roles. Runs as the user given with --user; with no user it acts as the shell
 * (the Guard rules about protected roles, valid names and lockout still apply).
 */
class Cli_Role extends Cli_Base {
	/**
	 * List roles.
	 *
	 * ## OPTIONS
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
		self::actor( array( Caps::MANAGE_ROLES ) );
		\WP_CLI\Utils\format_items( $assoc['format'] ?? 'table', Ops::list_roles(), array( 'slug', 'name', 'caps', 'users', 'protected' ) );
	}

	/**
	 * Create a role.
	 *
	 * ## OPTIONS
	 *
	 * <name>
	 * : Display name.
	 *
	 * [--slug=<slug>]
	 * : Role slug. Defaults to the sanitized name.
	 *
	 * [--caps=<caps>]
	 * : Comma-separated capabilities. Defaults to read.
	 */
	public function add( $args, $assoc ) {
		$actor = self::actor( array( Caps::MANAGE_ROLES ) );
		$caps  = isset( $assoc['caps'] ) ? self::csv( $assoc['caps'] ) : array( 'read' );
		$slug  = self::check( Ops::add_role( $actor, $args[0], (string) ( $assoc['slug'] ?? '' ), $caps ) );
		\WP_CLI::success( 'Created role ' . $slug . '.' );
	}

	/**
	 * Copy a role.
	 *
	 * ## OPTIONS
	 *
	 * <source>
	 * : Slug of the role to copy.
	 *
	 * <name>
	 * : Display name of the copy.
	 *
	 * [--slug=<slug>]
	 * : Slug of the copy.
	 */
	public function clone( $args, $assoc ) {
		$actor = self::actor( array( Caps::MANAGE_ROLES ) );
		$slug  = self::check( Ops::clone_role( $actor, $args[0], $args[1], (string) ( $assoc['slug'] ?? '' ) ) );
		\WP_CLI::success( 'Created role ' . $slug . ' from ' . $args[0] . '.' );
	}

	/**
	 * Delete a role that has no users.
	 *
	 * ## OPTIONS
	 *
	 * <role>
	 * : Role slug.
	 *
	 * [--yes]
	 * : Skip the confirmation.
	 */
	public function delete( $args, $assoc ) {
		$actor = self::actor( array( Caps::MANAGE_ROLES ) );
		\WP_CLI::confirm( 'Delete the ' . $args[0] . ' role?', $assoc );
		self::check( Ops::delete_role( $actor, $args[0] ) );
		\WP_CLI::success( 'Deleted role ' . $args[0] . '.' );
	}

	/**
	 * Reset a core role to WordPress's default capabilities. Capabilities other plugins added
	 * to that role are removed; the change is logged and can be reverted from the audit log.
	 *
	 * ## OPTIONS
	 *
	 * <role>
	 * : administrator, editor, author, contributor or subscriber.
	 *
	 * [--yes]
	 * : Skip the confirmation.
	 */
	public function reset( $args, $assoc ) {
		$actor = self::actor( array( Caps::MANAGE_ROLES ) );
		\WP_CLI::confirm( 'Reset ' . $args[0] . ' to the WordPress defaults? Capabilities added by other plugins are removed.', $assoc );
		self::check( Ops::reset_role( $actor, $args[0] ) );
		\WP_CLI::success( 'Reset role ' . $args[0] . '.' );
	}
}
