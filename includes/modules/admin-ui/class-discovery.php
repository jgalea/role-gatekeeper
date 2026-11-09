<?php
namespace Rolegate\Modules\Admin_Ui;

defined( 'ABSPATH' ) || exit;

/**
 * Learns what exists at runtime: the admin menu, meta boxes, dashboard widgets and toolbar nodes.
 * Only ids and titles are kept; rules store slugs alone.
 */
final class Discovery {
	const OPTION = 'rolegate_admin_ui_seen';

	/** @var array{menu:array,submenu:array} */
	private static $snapshot = array(
		'menu'    => array(),
		'submenu' => array(),
	);

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'snapshot_menu' ), 9998 );
		add_action( 'add_meta_boxes', array( $this, 'record_post_boxes' ), 9998, 1 );
		add_action( 'wp_dashboard_setup', array( $this, 'record_dashboard' ), 9998 );
		add_action( 'admin_bar_menu', array( $this, 'record_bar' ), 9998 );
	}

	public function snapshot_menu(): void {
		global $menu, $submenu;
		self::set_snapshot( is_array( $menu ) ? $menu : array(), is_array( $submenu ) ? $submenu : array() );
	}

	public static function set_snapshot( array $menu, array $submenu ): void {
		self::$snapshot = array(
			'menu'    => $menu,
			'submenu' => $submenu,
		);
	}

	public static function menu(): array {
		return self::$snapshot['menu'];
	}

	public static function submenu(): array {
		return self::$snapshot['submenu'];
	}

	public static function seen(): array {
		$seen = get_option( self::OPTION, array() );
		$seen = is_array( $seen ) ? $seen : array();
		return array(
			'metaboxes' => isset( $seen['metaboxes'] ) && is_array( $seen['metaboxes'] ) ? $seen['metaboxes'] : array(),
			'bar'       => isset( $seen['bar'] ) && is_array( $seen['bar'] ) ? $seen['bar'] : array(),
		);
	}

	private static function remember( string $kind, string $group, array $found ): void {
		if ( ! $found ) {
			return;
		}
		$seen = self::seen();
		if ( 'bar' === $kind ) {
			$current = $seen['bar'];
			$merged  = array_merge( $current, $found );
			if ( $merged !== $current ) {
				$seen['bar'] = $merged;
				update_option( self::OPTION, $seen, false );
			}
			return;
		}
		$current = $seen['metaboxes'][ $group ] ?? array();
		$merged  = array_merge( $current, $found );
		if ( $merged !== $current ) {
			$seen['metaboxes'][ $group ] = $merged;
			ksort( $seen['metaboxes'] );
			update_option( self::OPTION, $seen, false );
		}
	}

	private static function collect( string $screen ): array {
		global $wp_meta_boxes;
		$found = array();
		foreach ( (array) ( $wp_meta_boxes[ $screen ] ?? array() ) as $contexts ) {
			foreach ( (array) $contexts as $priorities ) {
				foreach ( (array) $priorities as $id => $box ) {
					if ( false === $box || ! is_array( $box ) || ! preg_match( '/^[A-Za-z0-9_\-]+$/', (string) $id ) ) {
						continue;
					}
					$title        = trim( wp_strip_all_tags( (string) ( $box['title'] ?? '' ) ) );
					$found[ $id ] = '' !== $title ? $title : (string) $id;
				}
			}
		}
		return $found;
	}

	public function record_post_boxes( $post_type ): void {
		if ( is_string( $post_type ) && '' !== $post_type ) {
			self::remember( 'metaboxes', sanitize_key( $post_type ), self::collect( $post_type ) );
		}
	}

	public function record_dashboard(): void {
		self::remember( 'metaboxes', 'dashboard', self::collect( 'dashboard' ) );
	}

	public function record_bar( $bar ): void {
		if ( ! $bar instanceof \WP_Admin_Bar ) {
			return;
		}
		$found = array();
		foreach ( (array) $bar->get_nodes() as $node ) {
			if ( ! empty( $node->group ) || ! preg_match( '/^[A-Za-z0-9_\-]+$/', (string) $node->id ) ) {
				continue;
			}
			$title              = trim( wp_strip_all_tags( (string) $node->title ) );
			$found[ $node->id ] = '' !== $title ? $title : (string) $node->id;
		}
		self::remember( 'bar', '', $found );
	}

	/** Re-run meta box registration for every editable post type and the dashboard. Called from the settings page only. */
	public static function refresh(): int {
		global $wp_meta_boxes, $current_screen;
		foreach ( array( 'admin', 'template', 'post', 'meta-boxes', 'dashboard' ) as $inc ) {
			require_once ABSPATH . 'wp-admin/includes/' . $inc . '.php';
		}
		// phpcs:disable WordPress.WP.GlobalVariablesOverride.Prohibited -- core registers meta boxes into these globals; they are emptied for the scan and restored at the end.
		$saved_screen      = $current_screen;
		$saved_boxes       = $wp_meta_boxes;
		$seen              = self::seen();
		$seen['metaboxes'] = array();
		update_option( self::OPTION, $seen, false );

		foreach ( get_post_types( array( 'show_ui' => true ), 'names' ) as $type ) {
			set_current_screen( $type );
			$wp_meta_boxes[ $type ] = array();
			$post                   = new \WP_Post(
				(object) array(
					'ID'          => 0,
					'post_type'   => $type,
					'post_status' => 'auto-draft',
				)
			);
			if ( function_exists( 'register_and_do_post_meta_boxes' ) ) {
				register_and_do_post_meta_boxes( $post );
			} else {
				do_action( 'add_meta_boxes', $type, $post );
			}
		}
		set_current_screen( 'dashboard' );
		$wp_meta_boxes['dashboard'] = array();
		wp_dashboard_setup();

		$wp_meta_boxes  = $saved_boxes;
		$current_screen = $saved_screen;
		// phpcs:enable WordPress.WP.GlobalVariablesOverride.Prohibited
		$count = 0;
		foreach ( self::seen()['metaboxes'] as $boxes ) {
			$count += count( $boxes );
		}
		return $count;
	}
}
