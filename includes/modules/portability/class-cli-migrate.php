<?php
namespace Rolegate\Modules\Portability;

defined( 'ABSPATH' ) || exit;

/**
 * Carries another role plugin's data over to Role Gatekeeper. Previews by default.
 */
final class Cli_Migrate {
	/**
	 * Carries Members data over: denied capabilities, content and block permissions, settings.
	 *
	 * ## OPTIONS
	 *
	 * [--dry-run]
	 * : Show what would change and write nothing. The default.
	 *
	 * [--apply]
	 * : Apply the changes shown in the preview.
	 *
	 * [--confirm-private]
	 * : Also switch on private-site mode when Members has it on.
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @param array $args
	 * @param array $assoc
	 */
	public function members( $args, $assoc ): void {
		$this->run( 'members', (array) $assoc );
	}

	/**
	 * Carries User Role Editor data over: extra default roles, and lists its settings.
	 *
	 * ## OPTIONS
	 *
	 * [--dry-run]
	 * : Show what would change and write nothing. The default.
	 *
	 * [--apply]
	 * : Apply the changes shown in the preview.
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @param array $args
	 * @param array $assoc
	 */
	public function ure( $args, $assoc ): void {
		$this->run( 'ure', (array) $assoc );
	}

	/**
	 * Carries the Disable Users flag over: every account it disabled is disabled here too.
	 * The flag Disable Users stored is left as it is.
	 *
	 * ## OPTIONS
	 *
	 * [--dry-run]
	 * : Show what would change and write nothing. The default.
	 *
	 * [--apply]
	 * : Apply the changes shown in the preview.
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @subcommand disable-users
	 *
	 * @param array $args
	 * @param array $assoc
	 */
	public function disable_users( $args, $assoc ): void {
		$this->run( 'disable-users', (array) $assoc );
	}

	/**
	 * Writes the effective capabilities of every role, every role combination users hold
	 * and every user with capabilities of their own, to compare after a migration.
	 *
	 * ## OPTIONS
	 *
	 * --file=<path>
	 * : Where to write the JSON snapshot.
	 *
	 * @param array $args
	 * @param array $assoc
	 */
	public function snapshot( $args, $assoc ): void {
		$this->authorize();
		$file = (string) ( $assoc['file'] ?? '' );
		if ( '' === $file ) {
			\WP_CLI::error( 'Pass --file=<path>.' );
		}
		$snap = Migrator::snapshot();
		if ( ! $snap['entries'] ) {
			\WP_CLI::error( 'Nothing to snapshot: no roles found.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI writes a local file the operator named.
		if ( false === file_put_contents( $file, wp_json_encode( $snap, JSON_PRETTY_PRINT ) ) ) {
			\WP_CLI::error( 'Could not write ' . $file );
		}
		\WP_CLI::success( sprintf( 'Wrote %d entries over %d capabilities to %s.', count( $snap['entries'] ), count( $snap['universe'] ), $file ) );
	}

	/**
	 * Recomputes a snapshot and lists every difference. Exits 1 when there is one.
	 *
	 * ## OPTIONS
	 *
	 * --file=<path>
	 * : The snapshot written by `wp rolegate migrate snapshot`.
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @param array $args
	 * @param array $assoc
	 */
	public function verify( $args, $assoc ): void {
		$this->authorize();
		$file = (string) ( $assoc['file'] ?? '' );
		if ( '' === $file || ! is_readable( $file ) ) {
			\WP_CLI::error( 'Pass --file=<path> pointing at a snapshot.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file the operator named.
		$snap   = json_decode( (string) file_get_contents( $file ), true );
		$result = Migrator::compare( is_array( $snap ) ? $snap : array() );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		$diffs = $result['differences'];
		if ( 'json' === ( $assoc['format'] ?? 'table' ) ) {
			\WP_CLI::line( (string) wp_json_encode( $result ) );
		} elseif ( $diffs ) {
			$rows = array();
			foreach ( $diffs as $d ) {
				$rows[] = array(
					'entry'  => $d['label'],
					'lost'   => implode( ', ', $d['lost'] ),
					'gained' => implode( ', ', $d['gained'] ),
					'note'   => $d['note'],
				);
			}
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'entry', 'lost', 'gained', 'note' ) );
		}
		$summary = sprintf( '%d difference(s) across %d entries over %d capabilities.', count( $diffs ), $result['entries'], count( (array) $snap['universe'] ) );
		if ( $diffs ) {
			\WP_CLI::warning( $summary );
			\WP_CLI::halt( 1 );
		}
		\WP_CLI::success( $summary );
	}

	private function authorize(): int {
		$actor = get_current_user_id();
		$ok    = Migrator::authorize( $actor );
		if ( is_wp_error( $ok ) ) {
			\WP_CLI::error( $ok->get_error_message() );
		}
		return $actor;
	}

	private function run( string $source, array $assoc ): void {
		$actor = $this->authorize();
		$apply = ! empty( $assoc['apply'] );
		if ( $apply && ! empty( $assoc['dry-run'] ) ) {
			\WP_CLI::error( 'Pass either --dry-run or --apply, not both.' );
		}
		$opts   = array( 'confirm_private' => ! empty( $assoc['confirm-private'] ) );
		$format = 'json' === ( $assoc['format'] ?? 'table' ) ? 'json' : 'table';

		$result = $apply ? Migrator::apply( $source, $actor, $opts ) : Migrator::plan( $source, $actor, $opts );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		$plan = $apply ? $result['plan'] : $result;

		if ( 'json' === $format ) {
			\WP_CLI::line(
				(string) wp_json_encode(
					array(
						'source'       => $source,
						'detected'     => $plan['detected'],
						'status'       => $apply ? $result['status'] : ( Migrator::has_changes( $plan['ops'] ) ? 'dry-run' : 'unchanged' ),
						'rows'         => $plan['rows'],
						'migration_id' => $apply ? $result['migration_id'] : '',
						'backup_id'    => $apply ? $result['backup_id'] : '',
						'errors'       => $apply ? $result['errors'] : array(),
					)
				)
			);
		} else {
			$labels = Migrator::action_labels();
			$rows   = array();
			foreach ( $plan['rows'] as $row ) {
				$rows[] = array(
					'area'   => $row['area'],
					'item'   => $row['item'],
					'action' => $labels[ $row['action'] ] ?? $row['action'],
					'detail' => $row['detail'],
				);
			}
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'area', 'item', 'action', 'detail' ) );
		}

		if ( ! $plan['detected'] ) {
			\WP_CLI::warning( 'Nothing to migrate: no data from this plugin was found.' );
			return;
		}
		if ( ! $apply ) {
			if ( Migrator::has_changes( $plan['ops'] ) ) {
				\WP_CLI::log( 'Dry run: nothing was written. Run again with --apply to carry these over.' );
			} else {
				\WP_CLI::success( 'Nothing to change: everything is already carried over.' );
			}
			return;
		}
		if ( 'unchanged' === $result['status'] ) {
			\WP_CLI::success( 'Nothing to change: everything is already carried over.' );
			return;
		}
		foreach ( $result['errors'] as $error ) {
			\WP_CLI::warning( $error );
		}
		\WP_CLI::success( sprintf( 'Migration %s applied. Roles backed up as %s. Revert it from the audit log.', $result['migration_id'], $result['backup_id'] ) );
	}
}
