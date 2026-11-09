<?php
namespace Rolewright\Modules\Audit;

defined( 'ABSPATH' ) || exit;

final class Store {
	const SCHEMA_VERSION = '1';
	const OPTION_SCHEMA  = 'rolewright_audit_schema';
	const CRON_HOOK      = 'rolewright_audit_prune';

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'rolewright_audit';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	created_at datetime NOT NULL,
	type varchar(40) NOT NULL,
	actor_id bigint(20) unsigned NOT NULL DEFAULT 0,
	target varchar(191) NOT NULL DEFAULT '',
	diff longtext NOT NULL,
	detail longtext NOT NULL,
	ip_hash char(64) NOT NULL DEFAULT '',
	reverted_of bigint(20) unsigned NOT NULL DEFAULT 0,
	reverted_by bigint(20) unsigned NOT NULL DEFAULT 0,
	PRIMARY KEY  (id),
	KEY created_at (created_at),
	KEY type (type),
	KEY actor_id (actor_id)
) {$charset};"
		);
		update_option( self::OPTION_SCHEMA, self::SCHEMA_VERSION, false );
	}

	public static function maybe_upgrade(): void {
		if ( get_option( self::OPTION_SCHEMA ) !== self::SCHEMA_VERSION ) {
			self::install();
		}
	}

	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/** @return int Rows deleted. */
	public static function prune(): int {
		global $wpdb;
		$days   = Audit_Module::settings()['retention_days'];
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$table  = self::table();
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * @param array{type:string,actor_id:int,target:string,diff:array,detail:array,ip_hash:string,reverted_of:int} $row
	 * @return int Insert id, 0 on failure.
	 */
	public static function insert( array $row ): int {
		global $wpdb;
		$ok = $wpdb->insert(
			self::table(),
			array(
				'created_at'  => gmdate( 'Y-m-d H:i:s' ),
				'type'        => $row['type'],
				'actor_id'    => $row['actor_id'],
				'target'      => $row['target'],
				'diff'        => wp_json_encode( $row['diff'] ),
				'detail'      => wp_json_encode( $row['detail'] ),
				'ip_hash'     => $row['ip_hash'],
				'reverted_of' => $row['reverted_of'],
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d' )
		);
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	public static function mark_reverted( int $id, int $by ): void {
		global $wpdb;
		$wpdb->update( self::table(), array( 'reverted_by' => $by ), array( 'id' => $id ), array( '%d' ), array( '%d' ) );
	}

	/** @return object|null */
	public static function get( int $id ) {
		global $wpdb;
		$table = self::table();
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * @param array{actor?:int,type?:string,from?:string,to?:string} $filters Dates are Y-m-d in UTC.
	 * @return array{rows:object[],total:int}
	 */
	public static function query( array $filters, int $page, int $per_page ): array {
		global $wpdb;
		$table = self::table();
		$where = array( '1=1' );
		$args  = array();
		if ( ! empty( $filters['actor'] ) ) {
			$where[] = 'actor_id = %d';
			$args[]  = (int) $filters['actor'];
		}
		if ( ! empty( $filters['type'] ) ) {
			$where[] = 'type = %s';
			$args[]  = $filters['type'];
		}
		if ( ! empty( $filters['from'] ) ) {
			$where[] = 'created_at >= %s';
			$args[]  = $filters['from'] . ' 00:00:00';
		}
		if ( ! empty( $filters['to'] ) ) {
			$where[] = 'created_at <= %s';
			$args[]  = $filters['to'] . ' 23:59:59';
		}
		$clause = implode( ' AND ', $where );
		$offset = max( 0, ( $page - 1 ) * $per_page );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$clause}";
		$total     = (int) ( $args ? $wpdb->get_var( $wpdb->prepare( $count_sql, $args ) ) : $wpdb->get_var( $count_sql ) );
		$rows_sql  = "SELECT * FROM {$table} WHERE {$clause} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows      = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $args, array( $per_page, $offset ) ) ) );
		// phpcs:enable
		return array(
			'rows'  => is_array( $rows ) ? $rows : array(),
			'total' => $total,
		);
	}

	/** @return string[] */
	public static function types(): array {
		global $wpdb;
		$table = self::table();
		return array_map( 'strval', (array) $wpdb->get_col( "SELECT DISTINCT type FROM {$table} ORDER BY type" ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/** @return int[] */
	public static function actors(): array {
		global $wpdb;
		$table = self::table();
		return array_map( 'intval', (array) $wpdb->get_col( "SELECT DISTINCT actor_id FROM {$table} ORDER BY actor_id" ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}
}
