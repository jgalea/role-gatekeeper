<?php
namespace Rolewright\Modules\Admin_Ui;

use Rolewright\Modules\Safety\Caps;
use WP_Error;

defined( 'ABSPATH' ) || exit;

final class Enforcer {
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'hide_menu' ), 9999 );
		add_action( 'admin_init', array( $this, 'guard_request' ), 1 );
		add_action( 'admin_init', array( $this, 'guard_ajax' ), 1 );
		add_action( 'add_meta_boxes', array( $this, 'hide_post_boxes' ), 9999, 1 );
		add_action( 'wp_dashboard_setup', array( $this, 'hide_dashboard_widgets' ), 9999 );
		add_action( 'admin_bar_menu', array( $this, 'hide_bar_nodes' ), 9999 );

		add_filter( 'map_meta_cap', array( $this, 'map_plugin_caps' ), 20, 4 );
		add_filter( 'all_plugins', array( $this, 'filter_plugin_list' ) );
		add_action( 'activate_plugin', array( $this, 'refuse_plugin_action' ), 0, 1 );
		add_action( 'deactivate_plugin', array( $this, 'refuse_plugin_action' ), 0, 1 );
		add_action( 'delete_plugin', array( $this, 'refuse_plugin_action' ), 0, 1 );
		add_filter( 'pre_update_option_stylesheet', array( $this, 'keep_theme' ), 10, 2 );
		add_filter( 'pre_update_option_template', array( $this, 'keep_theme' ), 10, 2 );
		add_filter( 'customize_loaded_components', array( $this, 'filter_customizer' ) );
		add_filter( 'rest_request_before_callbacks', array( $this, 'rest_guard' ), 10, 3 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'rest_filter_plugin_list' ), 10, 3 );
	}

	private static function eff( int $user_id = 0 ): ?array {
		return Rules::effective_for_user( $user_id ? $user_id : get_current_user_id() );
	}

	private static function can_manage( int $user_id = 0 ): bool {
		return user_can( $user_id ? $user_id : get_current_user_id(), Caps::MANAGE );
	}

	public function hide_menu(): void {
		$eff = self::eff();
		if ( null === $eff ) {
			return;
		}
		global $menu, $submenu;
		$can_manage = self::can_manage();
		$pages      = Engine::blocked_pages( $eff );
		$children   = array();
		foreach ( (array) $submenu as $parent => $items ) {
			foreach ( $items as $item ) {
				$children[ $parent ][] = (string) $item[2];
			}
		}
		foreach ( $children as $parent => $slugs ) {
			foreach ( $slugs as $slug ) {
				if ( Engine::key_blocked( $parent . '|' . $slug, (string) $parent, $eff, $can_manage ) || ( in_array( Engine::page_of_slug( $slug ), $pages, true ) && ! Engine::is_exempt_key( $slug, $can_manage ) ) ) {
					remove_submenu_page( (string) $parent, $slug );
				}
			}
		}
		foreach ( (array) $menu as $item ) {
			$slug = (string) ( $item[2] ?? '' );
			if ( '' === $slug || 0 === strpos( $slug, 'separator' ) ) {
				continue;
			}
			$kids = $children[ $slug ] ?? array();
			if ( Engine::top_blocked( $slug, $kids, $eff, $can_manage ) ) {
				remove_menu_page( $slug );
				continue;
			}
			if ( $kids && empty( $submenu[ $slug ] ) ) {
				remove_menu_page( $slug );
			}
		}
	}

	/** Redirect or refuse direct requests to blocked admin screens. */
	public function guard_request(): void {
		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}
		global $pagenow, $plugin_page;
		if ( in_array( $pagenow, array( 'admin-ajax.php', 'admin-post.php', 'async-upload.php' ), true ) ) {
			return;
		}
		$eff = self::eff();
		if ( null === $eff ) {
			return;
		}
		$query = array();
		foreach ( array( 'post_type', 'taxonomy' ) as $arg ) {
			if ( isset( $_GET[ $arg ] ) && is_scalar( $_GET[ $arg ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$query[ $arg ] = sanitize_key( wp_unslash( $_GET[ $arg ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			}
		}
		if ( 'post.php' === $pagenow && isset( $_GET['post'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$type = get_post_type( absint( $_GET['post'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( $type ) {
				$query['_post_type_resolved'] = $type;
			}
		}
		$can_manage = self::can_manage();

		if ( 'themes.php' === $pagenow && $eff['themes_locked'] && isset( $_GET['action'] ) && 'activate' === $_GET['action'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			wp_die( esc_html__( 'You are not allowed to switch themes.', 'rolewright' ), '', array( 'response' => 403 ) );
		}

		$reason = Engine::decide( (string) $pagenow, $plugin_page ? (string) $plugin_page : null, $query, Discovery::menu(), Discovery::submenu(), $eff, $can_manage );
		if ( null === $reason ) {
			return;
		}
		$url = Engine::first_allowed_url(
			Discovery::menu(),
			Discovery::submenu(),
			$eff,
			$can_manage,
			function ( $cap ) {
				return '' === $cap || current_user_can( $cap );
			}
		);
		if ( wp_safe_redirect( $url ) ) {
			exit;
		}
	}

	/**
	 * Core ajax actions that perform the work of a blockable screen, as action => [ block id, screens ].
	 * The action is refused when the block is on or any of the screens is blocked for the user.
	 */
	public static function ajax_actions(): array {
		$widgets  = array( 'widgets', array( 'widgets.php' ) );
		$menus    = array( 'nav_menus', array( 'nav-menus.php' ) );
		$custom   = array( 'customizer', array( 'customize.php' ) );
		$themes   = array( 'theme_browser', array( 'theme-install.php' ) );
		$editors  = array( 'file_editors', array( 'theme-editor.php', 'plugin-editor.php' ) );
		return array(
			'save-widget'                            => $widgets,
			'widgets-order'                          => $widgets,
			'update-widget'                          => $widgets,
			'delete-inactive-widgets'                => $widgets,
			'add-menu-item'                          => $menus,
			'menu-locations-save'                    => $menus,
			'menu-quick-search'                      => $menus,
			'menu-get-metabox'                       => $menus,
			'load-available-menu-items-customizer'   => $menus,
			'search-available-menu-items-customizer' => $menus,
			'customize-nav-menus-insert-auto-draft'  => $menus,
			'customize_save'                         => $custom,
			'customize_trash'                        => $custom,
			'customize_override_changeset_lock'      => $custom,
			'customize_dismiss_autosave_or_lock'     => $custom,
			'customize_load_themes'                  => $custom,
			'install-theme'                          => $themes,
			'update-theme'                           => $themes,
			'delete-theme'                           => $themes,
			'edit-theme-plugin-file'                 => $editors,
		);
	}

	/** Plugin ajax actions that act on the plugin file posted as `plugin`. */
	public static function plugin_ajax_actions(): array {
		return array( 'activate-plugin', 'update-plugin', 'delete-plugin', 'toggle-auto-updates' );
	}

	/** Refuse core ajax actions that reach a feature blocked for the user. */
	public function guard_ajax(): void {
		if ( ! wp_doing_ajax() || ! isset( $_REQUEST['action'] ) || ! is_scalar( $_REQUEST['action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$eff = self::eff();
		if ( null === $eff ) {
			return;
		}
		$action = sanitize_text_field( wp_unslash( (string) $_REQUEST['action'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::ajax_blocked( $action, $eff ) ) {
			wp_die( -1, 403 );
		}
	}

	private static function ajax_blocked( string $action, array $eff ): bool {
		$can_manage = self::can_manage();
		$screen_blocked = function ( array $pages ) use ( $eff, $can_manage ): bool {
			foreach ( $pages as $page ) {
				if ( null !== Engine::decide( $page, null, array(), Discovery::menu(), Discovery::submenu(), $eff, $can_manage ) ) {
					return true;
				}
			}
			return false;
		};

		$map = self::ajax_actions();
		if ( isset( $map[ $action ] ) ) {
			return in_array( $map[ $action ][0], $eff['blocks'], true ) || $screen_blocked( $map[ $action ][1] );
		}
		if ( 'install-plugin' === $action ) {
			return null !== $eff['plugins_allow'] || $screen_blocked( array( 'plugin-install.php' ) );
		}
		if ( in_array( $action, self::plugin_ajax_actions(), true ) ) {
			// phpcs:disable WordPress.Security.NonceVerification.Missing -- core verifies the nonce after this check.
			$type = isset( $_POST['type'] ) && is_scalar( $_POST['type'] ) ? sanitize_key( wp_unslash( (string) $_POST['type'] ) ) : '';
			if ( 'toggle-auto-updates' === $action && 'theme' === $type ) {
				return false;
			}
			$key    = 'toggle-auto-updates' === $action ? 'asset' : 'plugin';
			$raw    = isset( $_POST[ $key ] ) && is_scalar( $_POST[ $key ] ) ? wp_unslash( (string) $_POST[ $key ] ) : '';
			$plugin = '' === $raw ? '' : plugin_basename( sanitize_text_field( urldecode( $raw ) ) );
			// phpcs:enable
			return '' !== $plugin && self::plugin_blocked( $plugin, $eff );
		}
		return false;
	}

	public function hide_post_boxes( $post_type ): void {
		$eff = self::eff();
		if ( null === $eff || ! is_string( $post_type ) || empty( $eff['metaboxes'][ $post_type ] ) ) {
			return;
		}
		foreach ( $eff['metaboxes'][ $post_type ] as $id ) {
			foreach ( array( 'normal', 'side', 'advanced' ) as $context ) {
				remove_meta_box( $id, $post_type, $context );
			}
		}
	}

	public function hide_dashboard_widgets(): void {
		$eff = self::eff();
		if ( null === $eff || empty( $eff['metaboxes']['dashboard'] ) ) {
			return;
		}
		foreach ( $eff['metaboxes']['dashboard'] as $id ) {
			foreach ( array( 'normal', 'side', 'column3', 'column4' ) as $context ) {
				remove_meta_box( $id, 'dashboard', $context );
			}
		}
	}

	public function hide_bar_nodes( $bar ): void {
		$eff = self::eff();
		if ( null === $eff || ! $bar instanceof \WP_Admin_Bar ) {
			return;
		}
		foreach ( $eff['admin_bar'] as $node ) {
			if ( ! in_array( $node, Engine::protected_bar_nodes(), true ) ) {
				$bar->remove_node( $node );
			}
		}
	}

	private static function plugin_blocked( string $plugin, array $eff ): bool {
		return $plugin !== plugin_basename( ROLEWRIGHT_FILE ) && ( Engine::plugin_locked( $plugin, $eff ) || in_array( $plugin, $eff['plugins_hide'], true ) );
	}

	public function map_plugin_caps( $caps, $cap, $user_id, $args ) {
		if ( ! in_array( $cap, array( 'activate_plugin', 'deactivate_plugin', 'delete_plugin' ), true ) || empty( $args[0] ) || ! is_string( $args[0] ) ) {
			return $caps;
		}
		$eff = self::eff( (int) $user_id );
		if ( null !== $eff && self::plugin_blocked( $args[0], $eff ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	public function filter_plugin_list( $plugins ) {
		$eff = self::eff();
		if ( null === $eff || ! is_array( $plugins ) ) {
			return $plugins;
		}
		foreach ( $eff['plugins_hide'] as $file ) {
			if ( $file !== plugin_basename( ROLEWRIGHT_FILE ) ) {
				unset( $plugins[ $file ] );
			}
		}
		return $plugins;
	}

	public function refuse_plugin_action( $plugin ): void {
		$eff = self::eff();
		if ( null !== $eff && is_string( $plugin ) && self::plugin_blocked( $plugin, $eff ) ) {
			wp_die( esc_html__( 'You are not allowed to change this plugin.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
	}

	public function keep_theme( $value, $old ) {
		$eff = self::eff();
		if ( null !== $eff && $eff['themes_locked'] && $value !== $old ) {
			return $old;
		}
		return $value;
	}

	public function filter_customizer( $components ) {
		$eff = self::eff();
		if ( null === $eff || ! is_array( $components ) ) {
			return $components;
		}
		$map = array(
			'widgets'   => 'widgets',
			'nav_menus' => 'nav_menus',
		);
		foreach ( $map as $block => $component ) {
			if ( in_array( $block, $eff['blocks'], true ) ) {
				$components = array_values( array_diff( $components, array( $component ) ) );
			}
		}
		return $components;
	}

	/** WordPress matches REST routes case-insensitively and strips extra slashes, so compare the same way. */
	public static function normalize_route( string $route ): string {
		$route = strtolower( (string) preg_replace( '#/+#', '/', $route ) );
		$route = untrailingslashit( $route );
		return '' === $route ? '/' : ( '/' === $route[0] ? $route : '/' . $route );
	}

	public function rest_guard( $response, $handler, $request ) {
		$eff = self::eff();
		if ( null === $eff || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}
		$route = self::normalize_route( (string) $request->get_route() );
		foreach ( Engine::blocked_rest_prefixes( $eff ) as $prefix ) {
			$prefix = strtolower( $prefix );
			if ( $route === $prefix || 0 === strpos( $route, $prefix . '/' ) ) {
				return new WP_Error( 'rolewright_blocked', __( 'This area is not available to your account.', 'rolewright' ), array( 'status' => 403 ) );
			}
		}
		if ( preg_match( '#^/wp/v2/plugins/(.+)$#i', $route, $m ) ) {
			$file = strtolower( rawurldecode( $m[1] ) ) . '.php';
			if ( in_array( $file, array_map( 'strtolower', $eff['plugins_hide'] ), true ) ) {
				return new WP_Error( 'rest_plugin_not_found', __( 'Plugin not found.', 'rolewright' ), array( 'status' => 404 ) );
			}
		}
		return $response;
	}

	public function rest_filter_plugin_list( $result, $handler, $request ) {
		$eff = self::eff();
		if ( null === $eff || ! $eff['plugins_hide'] || ! $request instanceof \WP_REST_Request || '/wp/v2/plugins' !== self::normalize_route( (string) $request->get_route() ) || ! $result instanceof \WP_REST_Response ) {
			return $result;
		}
		$data = $result->get_data();
		if ( is_array( $data ) ) {
			$hidden = array_map(
				function ( $f ) {
					return preg_replace( '/\.php$/', '', $f );
				},
				$eff['plugins_hide']
			);
			$data   = array_values(
				array_filter(
					$data,
					function ( $item ) use ( $hidden ) {
						return ! is_array( $item ) || ! isset( $item['plugin'] ) || ! in_array( $item['plugin'], $hidden, true );
					}
				)
			);
			$result->set_data( $data );
		}
		return $result;
	}
}
