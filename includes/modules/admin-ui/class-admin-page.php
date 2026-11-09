<?php
namespace Rolewright\Modules\Admin_Ui;

use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Admin_Page {
	const SLUG = 'rolewright-admin-ui';

	private $hook = '';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolewright_admin_ui_save', array( $this, 'handle_save' ) );
		add_action( 'admin_post_rolewright_admin_ui_refresh', array( $this, 'handle_refresh' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	public function menu(): void {
		$this->hook = (string) add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Admin interface', 'rolewright' ),
			__( 'Admin interface', 'rolewright' ),
			Caps::MANAGE_ACCESS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function assets( $hook ): void {
		if ( $hook !== $this->hook ) {
			return;
		}
		wp_enqueue_style( 'rolewright-admin-ui', ROLEWRIGHT_URL . 'assets/admin-ui/admin-ui.css', array(), ROLEWRIGHT_VERSION );
		wp_enqueue_script( 'rolewright-admin-ui', ROLEWRIGHT_URL . 'assets/admin-ui/admin-ui.js', array(), ROLEWRIGHT_VERSION, true );
	}

	private static function page_url( string $scope, string $target, array $extra = array() ): string {
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					$scope => $target,
				),
				$extra
			),
			admin_url( 'admin.php' )
		);
	}

	private static function menu_label( $title ): string {
		$title = preg_replace( '#<span[^>]*>.*?</span>#is', '', (string) $title );
		return trim( wp_strip_all_tags( (string) $title ) );
	}

	public function handle_save(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolewright_admin_ui_save' );
		$scope  = isset( $_POST['scope'] ) && 'user' === $_POST['scope'] ? 'user' : 'role';
		$target = isset( $_POST['target'] ) ? sanitize_text_field( wp_unslash( $_POST['target'] ) ) : '';
		$raw    = isset( $_POST['rule'] ) && is_array( $_POST['rule'] ) ? wp_unslash( $_POST['rule'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized in Rules::sanitize().
		$result = Rules::save( get_current_user_id(), $scope, $target, $raw );
		$args   = array();
		if ( is_wp_error( $result ) ) {
			set_transient( 'rolewright_admin_ui_err_' . get_current_user_id(), $result->get_error_message(), MINUTE_IN_SECONDS );
			$args['rw_error'] = 1;
		} else {
			$args['rw_saved'] = 1;
		}
		wp_safe_redirect( self::page_url( $scope, $target, $args ) );
		exit;
	}

	public function handle_refresh(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolewright_admin_ui_refresh' );
		Discovery::refresh();
		$scope  = isset( $_POST['scope'] ) && 'user' === $_POST['scope'] ? 'user' : 'role';
		$target = isset( $_POST['target'] ) ? sanitize_text_field( wp_unslash( $_POST['target'] ) ) : '';
		wp_safe_redirect( self::page_url( $scope, $target, array( 'rw_refreshed' => 1 ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$scope  = isset( $_GET['user'] ) ? 'user' : 'role';
		$target = isset( $_GET[ $scope ] ) ? sanitize_text_field( wp_unslash( $_GET[ $scope ] ) ) : '';
		// phpcs:enable

		echo '<div class="wrap rw-admin-ui"><h1>' . esc_html__( 'Admin interface', 'rolewright' ) . '</h1>';
		$this->notices();

		$roles = array();
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			if ( 'administrator' !== $slug ) {
				$roles[ $slug ] = translate_user_role( $name );
			}
		}
		if ( 'role' === $scope && '' === $target && $roles ) {
			$target = (string) key( $roles );
		}

		$this->picker( $roles, $scope, $target );

		$valid = false;
		if ( 'role' === $scope ) {
			$valid = isset( $roles[ $target ] );
		} else {
			$u     = get_userdata( absint( $target ) );
			$valid = $u && ! is_super_admin( $u->ID ) && ! in_array( 'administrator', (array) $u->roles, true );
			if ( $u && ! $valid ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Administrators cannot be restricted.', 'rolewright' ) . '</p></div>';
			}
			if ( $valid ) {
				$target = (string) $u->ID;
			}
		}
		if ( ! $valid ) {
			echo '</div>';
			return;
		}

		$rule = Rules::get( $scope, $target );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="rw-form">';
		echo '<input type="hidden" name="action" value="rolewright_admin_ui_save" />';
		echo '<input type="hidden" name="scope" value="' . esc_attr( $scope ) . '" />';
		echo '<input type="hidden" name="target" value="' . esc_attr( $target ) . '" />';
		wp_nonce_field( 'rolewright_admin_ui_save' );

		$this->section_menu( $rule );
		$this->section_screens( $rule );
		$this->section_boxes( $rule );
		$this->section_plugins( $rule );
		$this->section_theme_and_bar( $rule );

		submit_button( __( 'Save restrictions', 'rolewright' ) );
		echo '</form>';
		echo '<form id="rw-refresh-form" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolewright_admin_ui_refresh" />';
		echo '<input type="hidden" name="scope" value="' . esc_attr( $scope ) . '" />';
		echo '<input type="hidden" name="target" value="' . esc_attr( $target ) . '" />';
		wp_nonce_field( 'rolewright_admin_ui_refresh' );
		echo '</form></div>';
	}

	private function notices(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['rw_saved'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Restrictions saved.', 'rolewright' ) . '</p></div>';
		}
		if ( isset( $_GET['rw_refreshed'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Meta box and dashboard widget lists refreshed.', 'rolewright' ) . '</p></div>';
		}
		if ( isset( $_GET['rw_error'] ) ) {
			$key = 'rolewright_admin_ui_err_' . get_current_user_id();
			$msg = get_transient( $key );
			delete_transient( $key );
			if ( is_string( $msg ) && '' !== $msg ) {
				echo '<div class="notice notice-error"><p>' . esc_html( $msg ) . '</p></div>';
			}
		}
		// phpcs:enable
	}

	private function picker( array $roles, string $scope, string $target ): void {
		echo '<div class="rw-picker">';
		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" />';
		echo '<label for="rw-role">' . esc_html__( 'Role', 'rolewright' ) . '</label> ';
		echo '<select id="rw-role" name="role">';
		foreach ( $roles as $slug => $name ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $slug ), selected( 'role' === $scope && $target === $slug, true, false ), esc_html( $name ) );
		}
		echo '</select> ';
		submit_button( __( 'Edit role', 'rolewright' ), 'secondary', '', false );
		echo '</form>';
		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" />';
		echo '<label for="rw-user">' . esc_html__( 'Or a single user (ID)', 'rolewright' ) . '</label> ';
		echo '<input type="number" min="1" id="rw-user" name="user" value="' . esc_attr( 'user' === $scope ? $target : '' ) . '" class="small-text" /> ';
		submit_button( __( 'Edit user', 'rolewright' ), 'secondary', '', false );
		echo '</form></div>';
	}

	private function model_radios( string $name, string $current, string $deny_label, string $allow_label ): void {
		echo '<p class="rw-model">';
		printf( '<label><input type="radio" name="%1$s" value="deny" %2$s /> %3$s</label> ', esc_attr( $name ), checked( 'deny' === $current, true, false ), esc_html( $deny_label ) );
		printf( '<label><input type="radio" name="%1$s" value="allow" %2$s /> %3$s</label>', esc_attr( $name ), checked( 'allow' === $current, true, false ), esc_html( $allow_label ) );
		echo '</p>';
	}

	private function section_menu( array $rule ): void {
		$menu    = Discovery::menu();
		$submenu = Discovery::submenu();
		ksort( $menu );
		$items = $rule['menu']['items'];

		echo '<h2>' . esc_html__( 'Admin menu', 'rolewright' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Blocked items disappear from the menu and their addresses redirect to the first page the user can open. The Rolewright menu and the profile page are never blocked.', 'rolewright' ) . '</p>';
		$this->model_radios( 'rule[menu][model]', $rule['menu']['model'], __( 'Block the selected items', 'rolewright' ), __( 'Block everything except the selected items', 'rolewright' ) );
		echo '<div class="rw-tree">';
		foreach ( $menu as $item ) {
			$slug = (string) ( $item[2] ?? '' );
			if ( '' === $slug || 0 === strpos( $slug, 'separator' ) ) {
				continue;
			}
			$label = self::menu_label( $item[0] ?? '' );
			if ( '' === $label ) {
				$label = $slug;
			}
			echo '<div class="rw-group"><label class="rw-parent-label"><input type="checkbox" class="rw-parent" name="rule[menu][items][]" value="' . esc_attr( $slug ) . '" data-group="' . esc_attr( $slug ) . '" ' . checked( in_array( $slug, $items, true ), true, false ) . ' /> <strong>' . esc_html( $label ) . '</strong></label>';
			if ( ! empty( $submenu[ $slug ] ) ) {
				echo '<ul>';
				foreach ( $submenu[ $slug ] as $sub ) {
					$sslug = (string) $sub[2];
					$key   = $slug . '|' . $sslug;
					$slab  = self::menu_label( $sub[0] ?? '' );
					printf(
						'<li><label><input type="checkbox" class="rw-child" data-group="%1$s" name="rule[menu][items][]" value="%2$s" %3$s /> %4$s</label></li>',
						esc_attr( $slug ),
						esc_attr( $key ),
						checked( in_array( $key, $items, true ), true, false ),
						esc_html( '' !== $slab ? $slab : $sslug )
					);
				}
				echo '</ul>';
			}
			echo '</div>';
		}
		echo '</div>';
	}

	private function section_screens( array $rule ): void {
		echo '<h2>' . esc_html__( 'Appearance and editing screens', 'rolewright' ) . '</h2><ul>';
		foreach ( Engine::block_defs() as $id => $def ) {
			printf(
				'<li><label><input type="checkbox" name="rule[blocks][]" value="%1$s" %2$s /> %3$s</label></li>',
				esc_attr( $id ),
				checked( in_array( $id, $rule['blocks'], true ), true, false ),
				esc_html( $def['label'] )
			);
		}
		echo '</ul>';
	}

	private function section_boxes( array $rule ): void {
		$seen = Discovery::seen()['metaboxes'];
		echo '<h2>' . esc_html__( 'Meta boxes and dashboard widgets', 'rolewright' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'The list is learned as screens load. Refresh re-reads every editable post type and the dashboard.', 'rolewright' ) . ' ';
		echo '<button type="submit" class="button" form="rw-refresh-form">' . esc_html__( 'Refresh list', 'rolewright' ) . '</button></p>';
		if ( ! $seen ) {
			echo '<p>' . esc_html__( 'Nothing recorded yet. Use Refresh list.', 'rolewright' ) . '</p>';
		}
		foreach ( $seen as $type => $boxes ) {
			if ( 'dashboard' === $type ) {
				$heading = __( 'Dashboard widgets', 'rolewright' );
			} else {
				$obj     = get_post_type_object( $type );
				$heading = $obj ? $obj->labels->singular_name : $type;
			}
			echo '<details class="rw-box-group"><summary>' . esc_html( $heading ) . '</summary><ul>';
			foreach ( $boxes as $id => $title ) {
				printf(
					'<li><label><input type="checkbox" name="rule[metaboxes][%1$s][]" value="%2$s" %3$s /> %4$s <code>%2$s</code></label></li>',
					esc_attr( $type ),
					esc_attr( $id ),
					checked( in_array( $id, $rule['metaboxes'][ $type ] ?? array(), true ), true, false ),
					esc_html( $title )
				);
			}
			echo '</ul></details>';
		}
	}

	private function section_plugins( array $rule ): void {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$own = plugin_basename( ROLEWRIGHT_FILE );
		echo '<h2>' . esc_html__( 'Plugins', 'rolewright' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Hidden plugins disappear from the plugin list. Locked plugins cannot be activated, deactivated or deleted, in the admin or over REST.', 'rolewright' ) . '</p>';
		$this->model_radios( 'rule[plugins][model]', $rule['plugins']['model'], __( 'Lock the selected plugins', 'rolewright' ), __( 'Lock every plugin except the selected ones', 'rolewright' ) );
		echo '<table class="widefat striped rw-plugins"><thead><tr><th>' . esc_html__( 'Plugin', 'rolewright' ) . '</th><th>' . esc_html__( 'Locked / allowed', 'rolewright' ) . '</th><th>' . esc_html__( 'Hidden', 'rolewright' ) . '</th></tr></thead><tbody>';
		foreach ( get_plugins() as $file => $data ) {
			if ( $file === $own ) {
				continue;
			}
			printf(
				'<tr><td>%1$s</td><td><input type="checkbox" name="rule[plugins][locked][]" value="%2$s" %3$s /></td><td><input type="checkbox" name="rule[plugins][hidden][]" value="%2$s" %4$s /></td></tr>',
				esc_html( $data['Name'] ),
				esc_attr( $file ),
				checked( in_array( $file, $rule['plugins']['locked'], true ), true, false ),
				checked( in_array( $file, $rule['plugins']['hidden'], true ), true, false )
			);
		}
		echo '</tbody></table>';
	}

	private function section_theme_and_bar( array $rule ): void {
		echo '<h2>' . esc_html__( 'Themes', 'rolewright' ) . '</h2>';
		echo '<p><label><input type="checkbox" name="rule[themes_locked]" value="1" ' . checked( ! empty( $rule['themes_locked'] ), true, false ) . ' /> ' . esc_html__( 'Cannot switch the active theme', 'rolewright' ) . '</label></p>';

		echo '<h2>' . esc_html__( 'Toolbar', 'rolewright' ) . '</h2>';
		$bar = Discovery::seen()['bar'];
		foreach ( Engine::protected_bar_nodes() as $node ) {
			unset( $bar[ $node ] );
		}
		if ( ! $bar ) {
			echo '<p>' . esc_html__( 'Toolbar items are learned as pages load. Open another admin page and come back.', 'rolewright' ) . '</p>';
			return;
		}
		echo '<ul class="rw-bar">';
		foreach ( $bar as $id => $title ) {
			printf(
				'<li><label><input type="checkbox" name="rule[admin_bar][]" value="%1$s" %2$s /> %3$s <code>%1$s</code></label></li>',
				esc_attr( $id ),
				checked( in_array( $id, $rule['admin_bar'], true ), true, false ),
				esc_html( $title )
			);
		}
		echo '</ul>';
	}
}
