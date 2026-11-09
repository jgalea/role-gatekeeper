<?php
namespace Rolegate\Modules\User_Roles;

defined( 'ABSPATH' ) || exit;

final class Users_List {
	const ADD    = 'rolegate_add:';
	const REMOVE = 'rolegate_remove:';

	public function register(): void {
		add_filter( 'manage_users_columns', array( $this, 'columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'column' ), 10, 3 );
		add_filter( 'views_users', array( $this, 'views' ) );
		add_action( 'pre_get_users', array( $this, 'filter_no_role' ) );
		add_filter( 'bulk_actions-users', array( $this, 'bulk_actions' ) );
		add_filter( 'handle_bulk_actions-users', array( $this, 'handle_bulk' ), 10, 3 );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	/**
	 * @param array $columns
	 * @return array
	 */
	public function columns( $columns ) {
		$out = array();
		foreach ( (array) $columns as $key => $label ) {
			if ( 'role' === $key ) {
				$out['rolegate_roles'] = __( 'Roles', 'role-gatekeeper' );
			} else {
				$out[ $key ] = $label;
			}
		}
		if ( ! isset( $out['rolegate_roles'] ) ) {
			$out['rolegate_roles'] = __( 'Roles', 'role-gatekeeper' );
		}
		return $out;
	}

	/**
	 * @param string $output
	 * @param string $column
	 * @param int    $user_id
	 * @return string
	 */
	public function column( $output, $column, $user_id ) {
		if ( 'rolegate_roles' !== $column ) {
			return $output;
		}
		$names = wp_roles()->role_names;
		$parts = array();
		foreach ( Users::get_roles( (int) $user_id ) as $role ) {
			$parts[] = sprintf(
				'<a href="%s">%s</a>',
				esc_url( Users::role_url( $role ) ),
				esc_html( translate_user_role( $names[ $role ] ?? $role ) )
			);
		}
		if ( ! $parts ) {
			return '<a href="' . esc_url( Users::no_role_url() ) . '">' . esc_html__( 'No role', 'role-gatekeeper' ) . '</a>';
		}
		return implode( ', ', $parts );
	}

	private static function filtering(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only list filter.
		return ! empty( $_GET['rolegate_no_role'] );
	}

	/**
	 * @param array $views
	 * @return array
	 */
	public function views( $views ) {
		$count = Users::count_no_role();
		if ( ! $count && ! self::filtering() ) {
			return $views;
		}
		$current = self::filtering();
		if ( $current && isset( $views['all'] ) ) {
			$views['all'] = str_replace( ' class="current" aria-current="page"', '', $views['all'] );
		}
		$views['rolegate_none'] = sprintf(
			'<a href="%s"%s>%s <span class="count">(%s)</span></a>',
			esc_url( Users::no_role_url() ),
			$current ? ' class="current" aria-current="page"' : '',
			esc_html__( 'No role', 'role-gatekeeper' ),
			esc_html( number_format_i18n( $count ) )
		);
		return $views;
	}

	/**
	 * @param \WP_User_Query $query
	 */
	public function filter_no_role( $query ): void {
		global $pagenow;
		if ( 'users.php' !== $pagenow || ! self::filtering() || ! current_user_can( 'list_users' ) || $query->get( 'role' ) ) {
			return;
		}
		$query->set( 'meta_query', Users::no_role_meta_query() ); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
	}

	/**
	 * @param array $actions
	 * @return array
	 */
	public function bulk_actions( $actions ) {
		if ( ! current_user_can( 'promote_users' ) ) {
			return $actions;
		}
		if ( ! function_exists( 'get_editable_roles' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}
		foreach ( get_editable_roles() as $slug => $role ) {
			/* translators: %s: role name */
			$actions[ self::ADD . $slug ] = sprintf( __( 'Add role: %s', 'role-gatekeeper' ), translate_user_role( $role['name'] ) );
		}
		foreach ( get_editable_roles() as $slug => $role ) {
			/* translators: %s: role name */
			$actions[ self::REMOVE . $slug ] = sprintf( __( 'Remove role: %s', 'role-gatekeeper' ), translate_user_role( $role['name'] ) );
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
		$adding   = 0 === strpos( (string) $action, self::ADD );
		$removing = 0 === strpos( (string) $action, self::REMOVE );
		if ( ! $adding && ! $removing ) {
			return $sendback;
		}
		check_admin_referer( 'bulk-users' );
		$actor = get_current_user_id();
		if ( ! current_user_can( 'promote_users' ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		$role = substr( (string) $action, strlen( $adding ? self::ADD : self::REMOVE ) );
		$done = 0;
		$skip = 0;
		foreach ( array_unique( array_map( 'intval', (array) $user_ids ) ) as $id ) {
			$result = $adding ? Users::change_roles( $actor, $id, array( $role ), array() ) : Users::change_roles( $actor, $id, array(), array( $role ) );
			if ( true === $result ) {
				++$done;
			} else {
				++$skip;
			}
		}
		return add_query_arg(
			array(
				'rolegate_done' => $done,
				'rolegate_skip' => $skip,
			),
			remove_query_arg( array( 'rolegate_done', 'rolegate_skip' ), $sendback ? $sendback : admin_url( 'users.php' ) )
		);
	}

	public function notice(): void {
		global $pagenow;
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result counters.
		if ( 'users.php' !== $pagenow || ! isset( $_GET['rolegate_done'], $_GET['rolegate_skip'] ) ) {
			return;
		}
		$done = (int) $_GET['rolegate_done'];
		$skip = (int) $_GET['rolegate_skip'];
		// phpcs:enable
		/* translators: %s: number of users */
		$text = sprintf( _n( 'Roles changed for %s user.', 'Roles changed for %s users.', $done, 'role-gatekeeper' ), number_format_i18n( $done ) );
		if ( $skip ) {
			/* translators: %s: number of users */
			$text .= ' ' . sprintf( _n( '%s user was skipped: your own account, a user above you, or a role you can\'t assign.', '%s users were skipped: your own account, users above you, or a role you can\'t assign.', $skip, 'role-gatekeeper' ), number_format_i18n( $skip ) );
		}
		printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', $skip && ! $done ? 'warning' : 'success', esc_html( $text ) );
	}
}
