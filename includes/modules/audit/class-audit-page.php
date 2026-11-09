<?php
namespace Rolewright\Modules\Audit;

use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Audit_Page {
	const SLUG     = 'rolewright-audit';
	const PER_PAGE = 20;

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolewright_audit_revert', array( $this, 'handle_revert' ) );
		add_action( 'admin_post_rolewright_audit_settings', array( $this, 'handle_settings' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Audit log', 'rolewright' ),
			__( 'Audit log', 'rolewright' ),
			Caps::VIEW_AUDIT,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	private function url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'admin.php' ) );
	}

	private function notice( string $type, string $message ): void {
		set_transient( 'rolewright_audit_notice_' . get_current_user_id(), array( $type, $message ), 60 );
	}

	public function handle_revert(): void {
		if ( ! current_user_can( Caps::VIEW_AUDIT ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		$id = isset( $_POST['entry'] ) ? absint( $_POST['entry'] ) : 0;
		check_admin_referer( 'rolewright_audit_revert_' . $id );
		$result = Reverter::revert( $id, get_current_user_id() );
		if ( is_wp_error( $result ) ) {
			$this->notice( 'error', $result->get_error_message() );
		} else {
			$this->notice( 'success', __( 'The change was reverted.', 'rolewright' ) );
		}
		wp_safe_redirect( $this->url() );
		exit;
	}

	public function handle_settings(): void {
		if ( ! current_user_can( Caps::MANAGE ) || ! current_user_can( Caps::VIEW_AUDIT ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolewright_audit_settings' );
		update_option(
			Audit_Module::OPTION_SETTINGS,
			array(
				'retention_days'      => isset( $_POST['retention_days'] ) ? max( 1, min( 3650, absint( $_POST['retention_days'] ) ) ) : 180,
				'delete_on_uninstall' => ! empty( $_POST['delete_on_uninstall'] ),
			),
			false
		);
		$this->notice( 'success', __( 'Settings saved.', 'rolewright' ) );
		wp_safe_redirect( $this->url( array( 'tab' => 'settings' ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::VIEW_AUDIT ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification -- read-only tab selection.
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'log';
		$tab  = in_array( $tab, array( 'log', 'permissions', 'settings' ), true ) ? $tab : 'log';
		$tabs = array(
			'log'         => __( 'Log', 'rolewright' ),
			'permissions' => __( 'Permissions viewer', 'rolewright' ),
			'settings'    => __( 'Settings', 'rolewright' ),
		);

		echo '<div class="wrap"><h1>' . esc_html__( 'Audit log', 'rolewright' ) . '</h1>';
		$key    = 'rolewright_audit_notice_' . get_current_user_id();
		$notice = get_transient( $key );
		if ( is_array( $notice ) ) {
			delete_transient( $key );
			printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( 'success' === $notice[0] ? 'success' : 'error' ), esc_html( (string) $notice[1] ) );
		}
		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $slug => $label ) {
			printf(
				'<a class="nav-tab%1$s" href="%2$s">%3$s</a>',
				$slug === $tab ? ' nav-tab-active' : '',
				esc_url( $this->url( array( 'tab' => $slug ) ) ),
				esc_html( $label )
			);
		}
		echo '</nav>';

		if ( 'permissions' === $tab ) {
			$this->render_permissions();
		} elseif ( 'settings' === $tab ) {
			$this->render_settings();
		} else {
			$this->render_log();
		}
		echo '</div>';
	}

	private function render_log(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only filters.
		$actor = isset( $_GET['actor'] ) ? absint( $_GET['actor'] ) : 0;
		$type  = isset( $_GET['type'] ) ? sanitize_text_field( wp_unslash( $_GET['type'] ) ) : '';
		$from  = isset( $_GET['from'] ) ? $this->date( sanitize_text_field( wp_unslash( $_GET['from'] ) ) ) : '';
		$to    = isset( $_GET['to'] ) ? $this->date( sanitize_text_field( wp_unslash( $_GET['to'] ) ) ) : '';
		$paged = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:enable
		$types = Store::types();
		$type  = in_array( $type, $types, true ) ? $type : '';

		echo '<form method="get" style="margin:1em 0">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" />';
		echo '<label>' . esc_html__( 'Actor', 'rolewright' ) . ' <select name="actor"><option value="0">' . esc_html__( 'Anyone', 'rolewright' ) . '</option>';
		foreach ( Store::actors() as $id ) {
			printf( '<option value="%1$d"%2$s>%3$s</option>', (int) $id, selected( $actor, $id, false ), esc_html( $this->actor_label( $id ) ) );
		}
		echo '</select></label> ';
		echo '<label>' . esc_html__( 'Type', 'rolewright' ) . ' <select name="type"><option value="">' . esc_html__( 'All types', 'rolewright' ) . '</option>';
		foreach ( $types as $t ) {
			printf( '<option value="%1$s"%2$s>%1$s</option>', esc_attr( $t ), selected( $type, $t, false ) );
		}
		echo '</select></label> ';
		echo '<label>' . esc_html__( 'From', 'rolewright' ) . ' <input type="date" name="from" value="' . esc_attr( $from ) . '" /></label> ';
		echo '<label>' . esc_html__( 'To', 'rolewright' ) . ' <input type="date" name="to" value="' . esc_attr( $to ) . '" /></label> ';
		submit_button( __( 'Filter', 'rolewright' ), 'secondary', '', false );
		echo '</form>';

		$result = Store::query(
			array(
				'actor' => $actor,
				'type'  => $type,
				'from'  => $from,
				'to'    => $to,
			),
			$paged,
			self::PER_PAGE
		);

		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'When', 'rolewright' ), __( 'Type', 'rolewright' ), __( 'Actor', 'rolewright' ), __( 'Target', 'rolewright' ), __( 'Changes', 'rolewright' ), '' ) as $head ) {
			echo '<th scope="col">' . esc_html( $head ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( ! $result['rows'] ) {
			echo '<tr><td colspan="6">' . esc_html__( 'Nothing logged yet.', 'rolewright' ) . '</td></tr>';
		}
		foreach ( $result['rows'] as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( get_date_from_gmt( $row->created_at, 'Y-m-d H:i' ) ) . '</td>';
			echo '<td><code>' . esc_html( $row->type ) . '</code>' . ( '' !== self::type_label( (string) $row->type ) ? '<br>' . esc_html( self::type_label( (string) $row->type ) ) : '' ) . ( (int) $row->reverted_by ? ' <em>' . esc_html__( '(reverted)', 'rolewright' ) . '</em>' : '' ) . ( (int) $row->reverted_of ? ' <em>' . esc_html__( '(revert)', 'rolewright' ) . '</em>' : '' ) . '</td>';
			echo '<td>' . esc_html( $this->actor_label( (int) $row->actor_id ) ) . '</td>';
			echo '<td>' . esc_html( $this->target_label( $row ) ) . '</td>';
			echo '<td>' . wp_kses(
				$this->changes_html( $row ),
				array(
					'code' => array(),
					'br'   => array(),
				)
			) . '</td>';
			echo '<td>';
			if ( Reverter::can_revert_row( $row ) ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
				echo '<input type="hidden" name="action" value="rolewright_audit_revert" /><input type="hidden" name="entry" value="' . (int) $row->id . '" />';
				wp_nonce_field( 'rolewright_audit_revert_' . (int) $row->id );
				submit_button( __( 'Revert', 'rolewright' ), 'small', '', false );
				echo '</form>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';

		$pages = (int) ceil( $result['total'] / self::PER_PAGE );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'      => add_query_arg( 'paged', '%#%', $this->url( array_filter( compact( 'actor', 'type', 'from', 'to' ) ) ) ),
						'format'    => '',
						'current'   => $paged,
						'total'     => $pages,
						'prev_text' => '&laquo;',
						'next_text' => '&raquo;',
					)
				)
			);
			echo '</div></div>';
		}
	}

	private function render_permissions(): void {
		// phpcs:ignore WordPress.Security.NonceVerification -- read-only lookup.
		$cap = isset( $_GET['cap'] ) ? strtolower( trim( sanitize_text_field( wp_unslash( $_GET['cap'] ) ) ) ) : '';
		echo '<form method="get" style="margin:1em 0"><input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" /><input type="hidden" name="tab" value="permissions" />';
		echo '<label>' . esc_html__( 'Capability', 'rolewright' ) . ' <input type="text" name="cap" list="rolewright-caps" value="' . esc_attr( $cap ) . '" class="regular-text" /></label> ';
		echo '<datalist id="rolewright-caps">';
		foreach ( Permissions::known_caps() as $known ) {
			echo '<option value="' . esc_attr( $known ) . '"></option>';
		}
		echo '</datalist>';
		submit_button( __( 'Who has it?', 'rolewright' ), 'secondary', '', false );
		echo '</form>';
		if ( '' === $cap ) {
			return;
		}

		$data = Permissions::holders( $cap );
		echo '<h2>' . esc_html__( 'Roles', 'rolewright' ) . '</h2>';
		if ( ! $data['roles'] ) {
			echo '<p>' . esc_html__( 'No role lists this capability.', 'rolewright' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Role', 'rolewright' ) . '</th><th>' . esc_html__( 'Slug', 'rolewright' ) . '</th><th>' . esc_html__( 'State', 'rolewright' ) . '</th></tr></thead><tbody>';
			foreach ( $data['roles'] as $role ) {
				printf( '<tr><td>%1$s</td><td><code>%2$s</code></td><td>%3$s</td></tr>', esc_html( $role['name'] ), esc_html( $role['slug'] ), esc_html( 'granted' === $role['state'] ? __( 'Granted', 'rolewright' ) : __( 'Denied', 'rolewright' ) ) );
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Users', 'rolewright' ) . '</h2>';
		if ( ! $data['users'] ) {
			echo '<p>' . esc_html__( 'No user holds this capability.', 'rolewright' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'User', 'rolewright' ) . '</th><th>' . esc_html__( 'Source', 'rolewright' ) . '</th><th>' . esc_html__( 'Effective now', 'rolewright' ) . '</th></tr></thead><tbody>';
			foreach ( $data['users'] as $user ) {
				$sources = array();
				foreach ( $user['sources'] as $source ) {
					$sources[] = 'user' === $source ? __( 'Set on the user', 'rolewright' ) : sprintf( /* translators: %s: role slug */ __( 'Role: %s', 'rolewright' ), substr( $source, 5 ) );
				}
				printf(
					'<tr><td>%1$s (%2$s)</td><td>%3$s</td><td>%4$s</td></tr>',
					esc_html( $user['name'] ),
					esc_html( $user['login'] ),
					esc_html( implode( ', ', $sources ) ),
					esc_html( $user['effective'] ? __( 'Yes', 'rolewright' ) : __( 'No (denied)', 'rolewright' ) )
				);
			}
			echo '</tbody></table>';
			if ( $data['truncated'] ) {
				/* translators: %d: number of users shown */
				echo '<p>' . esc_html( sprintf( __( 'Showing the first %d users.', 'rolewright' ), Permissions::USER_LIMIT ) ) . '</p>';
			}
		}
	}

	private function render_settings(): void {
		$settings = Audit_Module::settings();
		$can_edit = current_user_can( Caps::MANAGE );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="rolewright_audit_settings" />';
		wp_nonce_field( 'rolewright_audit_settings' );
		echo '<table class="form-table" role="presentation"><tbody>';
		echo '<tr><th scope="row"><label for="rw-retention">' . esc_html__( 'Keep entries for (days)', 'rolewright' ) . '</label></th><td><input id="rw-retention" type="number" min="1" max="3650" name="retention_days" value="' . (int) $settings['retention_days'] . '"' . disabled( ! $can_edit, true, false ) . ' /></td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'On uninstall', 'rolewright' ) . '</th><td><label><input type="checkbox" name="delete_on_uninstall" value="1"' . checked( $settings['delete_on_uninstall'], true, false ) . disabled( ! $can_edit, true, false ) . ' /> ' . esc_html__( 'Delete the audit table when the plugin is deleted', 'rolewright' ) . '</label></td></tr>';
		echo '</tbody></table>';
		if ( $can_edit ) {
			submit_button( __( 'Save settings', 'rolewright' ) );
		}
		echo '</form>';
	}

	private function date( string $value ): string {
		return preg_match( '/^\d{4}-\d{2}-\d{2}$/', $value ) ? $value : '';
	}

	private function actor_label( int $id ): string {
		if ( $id <= 0 ) {
			return __( 'System / CLI', 'rolewright' );
		}
		$user = get_userdata( $id );
		return $user ? $user->user_login : sprintf( /* translators: %d: user id */ __( 'User #%d (deleted)', 'rolewright' ), $id );
	}

	private function target_label( object $row ): string {
		if ( 0 === strpos( $row->type, 'user.' ) && ctype_digit( (string) $row->target ) ) {
			$user = get_userdata( (int) $row->target );
			return $user ? $user->user_login : '#' . $row->target;
		}
		return (string) $row->target;
	}

	private function changes_html( object $row ): string {
		$diff   = json_decode( (string) $row->diff, true );
		$detail = json_decode( (string) $row->detail, true );
		$lines  = array();
		if ( is_array( $detail ) ) {
			if ( ! empty( $detail['old_label'] ) || ! empty( $detail['new_label'] ) ) {
				$lines[] = esc_html( ( $detail['old_label'] ?? '' ) . ' -> ' . ( $detail['new_label'] ?? '' ) );
			}
			if ( ! empty( $detail['label'] ) ) {
				$lines[] = esc_html( $detail['label'] );
			}
		}
		$groups = array(
			'caps'     => array(
				'added'    => __( 'Granted', 'rolewright' ),
				'removed'  => __( 'Removed', 'rolewright' ),
				'denied'   => __( 'Denied', 'rolewright' ),
				'undenied' => __( 'Deny lifted', 'rolewright' ),
			),
			'roles'    => array(
				'added'   => __( 'Roles added', 'rolewright' ),
				'removed' => __( 'Roles removed', 'rolewright' ),
			),
			'settings' => array(
				'enabled'  => __( 'Switched on', 'rolewright' ),
				'disabled' => __( 'Switched off', 'rolewright' ),
			),
		);
		foreach ( (array) ( $diff['role_caps'] ?? array() ) as $slug => $d ) {
			$lines[] = '<code>' . esc_html( (string) $slug ) . '</code>: ' . esc_html(
				/* translators: 1: granted count, 2: removed count */
				sprintf( __( '%1$d granted, %2$d removed', 'rolewright' ), count( (array) ( $d['added'] ?? array() ) ), count( (array) ( $d['removed'] ?? array() ) ) )
			);
		}
		if ( is_array( $detail ) && ! empty( $detail['default_after'] ) ) {
			$lines[] = esc_html( ( $detail['default_before'] ?? '' ) . ' -> ' . $detail['default_after'] );
		}
		foreach ( $groups as $group => $labels ) {
			foreach ( $labels as $key => $label ) {
				$names = isset( $diff[ $group ][ $key ] ) ? (array) $diff[ $group ][ $key ] : array();
				if ( ! $names ) {
					continue;
				}
				$shown = array_slice( $names, 0, 12 );
				$text  = '<code>' . implode( '</code> <code>', array_map( 'esc_html', $shown ) ) . '</code>';
				if ( count( $names ) > 12 ) {
					/* translators: %d: number of additional items */
					$text .= ' ' . esc_html( sprintf( __( '+%d more', 'rolewright' ), count( $names ) - 12 ) );
				}
				$lines[] = esc_html( $label ) . ': ' . $text;
			}
		}
		return implode( '<br>', $lines );
	}

	private static function type_label( string $type ): string {
		$labels = array(
			'modules.updated'    => __( 'Modules switched on or off', 'rolewright' ),
			'automation.updated' => __( 'Automation settings changed', 'rolewright' ),
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : '';
	}
}
