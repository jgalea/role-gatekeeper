<?php
namespace Rolegate\Modules\Disabled_Users;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Users_List {
	const DISABLE = 'rolegate_disable';
	const ENABLE  = 'rolegate_enable';

	public function register(): void {
		add_filter( 'manage_users_columns', array( $this, 'columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'column' ), 10, 3 );
		add_filter( 'views_users', array( $this, 'views' ) );
		add_action( 'pre_get_users', array( $this, 'filter_disabled' ) );
		add_filter( 'bulk_actions-users', array( $this, 'bulk_actions' ) );
		add_filter( 'handle_bulk_actions-users', array( $this, 'handle_bulk' ), 10, 3 );
		add_action( 'admin_notices', array( $this, 'notice' ) );
		add_action( 'admin_head-users.php', array( $this, 'styles' ) );
		if ( is_multisite() ) {
			add_filter( 'manage_users-network_columns', array( $this, 'columns' ) );
			add_filter( 'views_users-network', array( $this, 'views' ) );
			add_filter( 'bulk_actions-users-network', array( $this, 'bulk_actions' ) );
			add_filter( 'handle_network_bulk_actions-users-network', array( $this, 'handle_bulk' ), 10, 3 );
			add_action( 'network_admin_notices', array( $this, 'notice' ) );
			add_action( 'admin_head-users.php', array( $this, 'styles' ) );
		}
	}

	public function styles(): void {
		$ids = get_users(
			array(
				'fields'     => 'ID',
				'number'     => 200,
				'meta_key'   => Accounts::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value' => '1', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
			)
		);
		if ( ! $ids ) {
			return;
		}
		$selectors = array();
		foreach ( $ids as $id ) {
			$selectors[] = '#user-' . (int) $id . ' .column-username strong a::after';
		}
		$label = str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), ' (' . wp_strip_all_tags( __( 'Disabled', 'role-gatekeeper' ) ) . ')' );
		echo '<style>' . implode( ',', $selectors ) . '{content:"' . $label . '";font-weight:400;color:#b32d2e}.rolegate-state{font-weight:600;color:#b32d2e}</style>'; // phpcs:ignore WordPress.Security.EscapeOutput -- ids are integers; the label is escaped for a CSS string.
	}

	/**
	 * @param array $columns
	 * @return array
	 */
	public function columns( $columns ) {
		$columns['rolegate_disabled'] = __( 'Status', 'role-gatekeeper' );
		return $columns;
	}

	/**
	 * @param string $output
	 * @param string $column
	 * @param int    $user_id
	 * @return string
	 */
	public function column( $output, $column, $user_id ) {
		if ( 'rolegate_disabled' !== $column ) {
			return $output;
		}
		return Accounts::is_disabled( (int) $user_id ) ? '<strong class="rolegate-state">' . esc_html__( 'Disabled', 'role-gatekeeper' ) . '</strong>' : '';
	}

	private static function filtering(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only list filter.
		return ! empty( $_GET['rolegate_disabled'] );
	}

	private static function list_url(): string {
		return add_query_arg( 'rolegate_disabled', '1', admin_url( 'users.php' ) );
	}

	private static function meta_query(): array {
		return array(
			array(
				'key'   => Accounts::META,
				'value' => '1',
			),
		);
	}

	/**
	 * @param array $views
	 * @return array
	 */
	public function views( $views ) {
		$count   = Accounts::count_disabled();
		$current = self::filtering();
		if ( ! $count && ! $current ) {
			return $views;
		}
		if ( $current && isset( $views['all'] ) ) {
			$views['all'] = str_replace( ' class="current" aria-current="page"', '', $views['all'] );
		}
		$views['rolegate_disabled'] = sprintf(
			'<a href="%s"%s>%s <span class="count">(%s)</span></a>',
			esc_url( self::list_url() ),
			$current ? ' class="current" aria-current="page"' : '',
			esc_html__( 'Disabled', 'role-gatekeeper' ),
			esc_html( number_format_i18n( $count ) )
		);
		return $views;
	}

	/**
	 * @param \WP_User_Query $query
	 */
	public function filter_disabled( $query ): void {
		global $pagenow;
		if ( 'users.php' !== $pagenow || ! self::filtering() || ! current_user_can( 'list_users' ) ) {
			return;
		}
		$existing = $query->get( 'meta_query' );
		$mine     = self::meta_query();
		$query->set( 'meta_query', $existing ? array_merge( array( 'relation' => 'AND' ), array( $existing ), $mine ) : $mine ); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
	}

	/**
	 * @param array $actions
	 * @return array
	 */
	public function bulk_actions( $actions ) {
		if ( current_user_can( Caps::MANAGE_USERS ) ) {
			$actions[ self::DISABLE ] = __( 'Disable accounts', 'role-gatekeeper' );
			$actions[ self::ENABLE ]  = __( 'Enable accounts', 'role-gatekeeper' );
		}
		return $actions;
	}

	/**
	 * @param string $sendback
	 * @param string $action
	 * @param int[]  $user_ids
	 * @return string
	 */
	public function handle_bulk( $sendback, $action, $user_ids ) {
		if ( self::DISABLE !== $action && self::ENABLE !== $action ) {
			return $sendback;
		}
		check_admin_referer( 'bulk-users' );
		if ( ! current_user_can( Caps::MANAGE_USERS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		$disable = self::DISABLE === $action;
		$actor   = get_current_user_id();
		$done    = 0;
		$skip    = 0;
		$why     = array();
		foreach ( array_unique( array_map( 'intval', (array) $user_ids ) ) as $id ) {
			$result = Accounts::change( $actor, $id, $disable );
			if ( true === $result ) {
				++$done;
			} else {
				++$skip;
				$user  = get_userdata( $id );
				$why[] = array( $user ? $user->user_login : '#' . $id, $result->get_error_message() );
			}
		}
		set_transient( 'rolegate_dis_skipped_' . $actor, array_slice( $why, 0, 10 ), 5 * MINUTE_IN_SECONDS );
		$keys = array( 'rolegate_dis_mode', 'rolegate_dis_done', 'rolegate_dis_skip' );
		return add_query_arg(
			array(
				'rolegate_dis_mode' => $disable ? 'disable' : 'enable',
				'rolegate_dis_done' => $done,
				'rolegate_dis_skip' => $skip,
			),
			remove_query_arg( $keys, $sendback ? $sendback : admin_url( 'users.php' ) )
		);
	}

	public function notice(): void {
		global $pagenow;
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result counters.
		if ( 'users.php' !== $pagenow || ! isset( $_GET['rolegate_dis_mode'], $_GET['rolegate_dis_done'], $_GET['rolegate_dis_skip'] ) ) {
			return;
		}
		$disabled = 'disable' === $_GET['rolegate_dis_mode'];
		$done     = (int) $_GET['rolegate_dis_done'];
		$skip     = (int) $_GET['rolegate_dis_skip'];
		// phpcs:enable
		if ( $disabled ) {
			/* translators: %s: number of users */
			$text = sprintf( _n( '%s account disabled.', '%s accounts disabled.', $done, 'role-gatekeeper' ), number_format_i18n( $done ) );
		} else {
			/* translators: %s: number of users */
			$text = sprintf( _n( '%s account enabled.', '%s accounts enabled.', $done, 'role-gatekeeper' ), number_format_i18n( $done ) );
		}
		if ( $skip ) {
			/* translators: %s: number of users */
			$text .= ' ' . sprintf( _n( '%s user was skipped.', '%s users were skipped.', $skip, 'role-gatekeeper' ), number_format_i18n( $skip ) );
		}
		$list = '';
		$why  = $skip ? get_transient( 'rolegate_dis_skipped_' . get_current_user_id() ) : false;
		delete_transient( 'rolegate_dis_skipped_' . get_current_user_id() );
		if ( is_array( $why ) && $why ) {
			$list = '<ul style="list-style:disc;margin-inline-start:2em">';
			foreach ( $why as $row ) {
				$list .= '<li>' . esc_html( $row[0] . ': ' . $row[1] ) . '</li>';
			}
			$list .= '</ul>';
		}
		printf( '<div class="notice notice-%s is-dismissible"><p>%s</p>%s</div>', $skip && ! $done ? 'warning' : 'success', esc_html( $text ), $list ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above.
	}
}
