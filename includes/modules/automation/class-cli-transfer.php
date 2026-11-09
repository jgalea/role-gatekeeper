<?php
namespace Rolegate\Modules\Automation;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

class Cli_Transfer extends Cli_Base {
	/**
	 * Export roles as JSON.
	 *
	 * ## OPTIONS
	 *
	 * [--roles=<roles>]
	 * : Comma-separated role slugs. Defaults to all.
	 *
	 * [--file=<file>]
	 * : Write to this file instead of standard output.
	 */
	public static function export( $args, $assoc ) {
		self::actor( array( Caps::MANAGE_ROLES ) );
		$json = (string) wp_json_encode( Ops::export_data( self::csv( $assoc['roles'] ?? '' ) ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( ! empty( $assoc['file'] ) ) {
			if ( false === file_put_contents( $assoc['file'], $json . "\n" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				\WP_CLI::error( 'Could not write ' . $assoc['file'] );
			}
			\WP_CLI::success( 'Exported to ' . $assoc['file'] . '.' );
			return;
		}
		\WP_CLI::line( $json );
	}

	/**
	 * Import roles from a JSON file made by export.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to the JSON file.
	 *
	 * [--dry-run]
	 * : Show what would change and write nothing.
	 *
	 * [--yes]
	 * : Skip the confirmation.
	 */
	public static function import( $args, $assoc ) {
		$actor = self::actor( array( Caps::IMPORT ) );
		if ( ! is_readable( $args[0] ) ) {
			\WP_CLI::error( 'Cannot read ' . $args[0] );
		}
		$dry  = ! empty( $assoc['dry-run'] );
		$json = (string) file_get_contents( $args[0] ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( strlen( $json ) > 524288 ) {
			\WP_CLI::error( 'The file is larger than 512 KB.' );
		}
		if ( ! $dry ) {
			\WP_CLI::confirm( 'Apply this import?', $assoc );
		}
		$result = self::check( Ops::import_json( $actor, $json, $dry ) );
		$rows   = array();
		foreach ( $result['rows'] as $row ) {
			$rows[] = array(
				'role'     => $row['slug'],
				'action'   => $row['blocked'] ? 'blocked' : $row['action'],
				'added'    => count( $row['added'] ),
				'removed'  => count( $row['removed'] ),
				'stripped' => implode( ',', $row['stripped'] ),
				'note'     => $row['blocked'],
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'role', 'action', 'added', 'removed', 'stripped', 'note' ) );
		foreach ( $result['rejected'] as $line ) {
			\WP_CLI::warning( $line );
		}
		\WP_CLI::success( $dry ? 'Dry run, nothing changed.' : 'Imported ' . count( $result['applied'] ) . ' role(s).' );
	}
}
