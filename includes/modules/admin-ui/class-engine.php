<?php
namespace Rolewright\Modules\Admin_Ui;

defined( 'ABSPATH' ) || exit;

/**
 * Pure decision logic. Menu keys: a top-level item is its slug, a submenu item is "parent|slug".
 */
final class Engine {
	/** Appearance and editor screens that can be blocked as a unit. */
	public static function block_defs(): array {
		return array(
			'widgets'       => array(
				'label' => __( 'Widgets screen and widget editing', 'rolewright' ),
				'pages' => array( 'widgets.php' ),
				'rest'  => array( '/wp/v2/widgets', '/wp/v2/sidebars', '/wp/v2/widget-types' ),
			),
			'nav_menus'     => array(
				'label' => __( 'Navigation menu editing', 'rolewright' ),
				'pages' => array( 'nav-menus.php' ),
				'rest'  => array( '/wp/v2/menus', '/wp/v2/menu-items', '/wp/v2/navigation' ),
			),
			'theme_browser' => array(
				'label' => __( 'Theme browser and theme installer', 'rolewright' ),
				'pages' => array( 'themes.php', 'theme-install.php' ),
				'rest'  => array(),
			),
			'customizer'    => array(
				'label' => __( 'Customizer', 'rolewright' ),
				'pages' => array( 'customize.php' ),
				'rest'  => array(),
			),
			'file_editors'  => array(
				'label' => __( 'Theme and plugin file editors', 'rolewright' ),
				'pages' => array( 'theme-editor.php', 'plugin-editor.php' ),
				'rest'  => array(),
			),
			'site_editor'   => array(
				'label' => __( 'Site editor', 'rolewright' ),
				'pages' => array( 'site-editor.php' ),
				'rest'  => array(),
			),
		);
	}

	/** Admin bar nodes that can never be hidden: they lead to the profile and logout. */
	public static function protected_bar_nodes(): array {
		return array( 'my-account', 'user-actions', 'user-info', 'edit-profile', 'logout' );
	}

	public static function empty_rule(): array {
		return array(
			'menu'          => array(
				'model' => 'deny',
				'items' => array(),
			),
			'blocks'        => array(),
			'metaboxes'     => array(),
			'plugins'       => array(
				'model'  => 'deny',
				'locked' => array(),
				'hidden' => array(),
			),
			'themes_locked' => false,
			'admin_bar'     => array(),
		);
	}

	public static function is_empty( array $rule ): bool {
		$rule = array_replace_recursive( self::empty_rule(), $rule );
		return 'deny' === $rule['menu']['model'] && empty( $rule['menu']['items'] ) && empty( $rule['blocks'] ) && empty( $rule['metaboxes'] ) &&
			'deny' === $rule['plugins']['model'] && empty( $rule['plugins']['locked'] ) && empty( $rule['plugins']['hidden'] ) &&
			empty( $rule['themes_locked'] ) && empty( $rule['admin_bar'] );
	}

	/**
	 * Combine the rules that apply to one user. Deny lists are unioned; allow lists are unioned
	 * across the rules that use the allow model, and null when none does.
	 *
	 * @param array[] $rules
	 */
	public static function merge( array $rules ): array {
		$out = array(
			'menu_deny'     => array(),
			'menu_allow'    => null,
			'blocks'        => array(),
			'metaboxes'     => array(),
			'plugins_deny'  => array(),
			'plugins_allow' => null,
			'plugins_hide'  => array(),
			'themes_locked' => false,
			'admin_bar'     => array(),
		);
		foreach ( $rules as $rule ) {
			$rule = array_replace_recursive( self::empty_rule(), $rule );
			if ( 'allow' === $rule['menu']['model'] ) {
				$out['menu_allow'] = array_values( array_unique( array_merge( (array) $out['menu_allow'], $rule['menu']['items'] ) ) );
			} else {
				$out['menu_deny'] = array_values( array_unique( array_merge( $out['menu_deny'], $rule['menu']['items'] ) ) );
			}
			if ( 'allow' === $rule['plugins']['model'] ) {
				$out['plugins_allow'] = array_values( array_unique( array_merge( (array) $out['plugins_allow'], $rule['plugins']['locked'] ) ) );
			} else {
				$out['plugins_deny'] = array_values( array_unique( array_merge( $out['plugins_deny'], $rule['plugins']['locked'] ) ) );
			}
			$out['plugins_hide']  = array_values( array_unique( array_merge( $out['plugins_hide'], $rule['plugins']['hidden'] ) ) );
			$out['blocks']        = array_values( array_unique( array_merge( $out['blocks'], $rule['blocks'] ) ) );
			$out['admin_bar']     = array_values( array_unique( array_merge( $out['admin_bar'], $rule['admin_bar'] ) ) );
			$out['themes_locked'] = $out['themes_locked'] || ! empty( $rule['themes_locked'] );
			foreach ( $rule['metaboxes'] as $type => $ids ) {
				$out['metaboxes'][ $type ] = array_values( array_unique( array_merge( $out['metaboxes'][ $type ] ?? array(), $ids ) ) );
			}
		}
		return $out;
	}

	public static function blocked_pages( array $eff ): array {
		$defs  = self::block_defs();
		$pages = array();
		foreach ( $eff['blocks'] as $id ) {
			if ( isset( $defs[ $id ] ) ) {
				$pages = array_merge( $pages, $defs[ $id ]['pages'] );
			}
		}
		return $pages;
	}

	public static function blocked_rest_prefixes( array $eff ): array {
		$defs = self::block_defs();
		$out  = array();
		foreach ( $eff['blocks'] as $id ) {
			if ( isset( $defs[ $id ] ) ) {
				$out = array_merge( $out, $defs[ $id ]['rest'] );
			}
		}
		return $out;
	}

	public static function page_of_slug( string $slug ): string {
		$pos = strpos( $slug, '?' );
		return false === $pos ? $slug : substr( $slug, 0, $pos );
	}

	/** Keys that no rule may block. $can_manage covers the whole Rolewright menu. */
	public static function is_exempt_key( string $key, bool $can_manage ): bool {
		$slug = false !== strpos( $key, '|' ) ? substr( $key, strpos( $key, '|' ) + 1 ) : $key;
		if ( 'profile.php' === self::page_of_slug( $slug ) ) {
			return true;
		}
		if ( $can_manage ) {
			$parent = false !== strpos( $key, '|' ) ? substr( $key, 0, strpos( $key, '|' ) ) : $key;
			return 'rolewright' === $parent || 0 === strpos( $slug, 'rolewright-' );
		}
		return false;
	}

	/**
	 * Whether the menu entry is blocked for a user with the merged rules $eff.
	 *
	 * @param string      $key    Item key.
	 * @param string|null $parent Parent slug for submenu items, null for top-level.
	 */
	public static function key_blocked( string $key, ?string $parent, array $eff, bool $can_manage ): bool {
		if ( self::is_exempt_key( $key, $can_manage ) ) {
			return false;
		}
		if ( in_array( $key, $eff['menu_deny'], true ) || ( null !== $parent && in_array( $parent, $eff['menu_deny'], true ) ) ) {
			return true;
		}
		if ( null !== $eff['menu_allow'] ) {
			return ! in_array( $key, $eff['menu_allow'], true );
		}
		return false;
	}

	/** Top-level entry with no submenu children left: blocked in allow mode only when no child is allowed either. */
	public static function top_blocked( string $slug, array $children_slugs, array $eff, bool $can_manage ): bool {
		if ( self::is_exempt_key( $slug, $can_manage ) ) {
			return false;
		}
		if ( in_array( $slug, $eff['menu_deny'], true ) ) {
			return true;
		}
		if ( null !== $eff['menu_allow'] ) {
			if ( in_array( $slug, $eff['menu_allow'], true ) ) {
				return false;
			}
			foreach ( $children_slugs as $child ) {
				if ( ! self::key_blocked( $slug . '|' . $child, $slug, $eff, $can_manage ) ) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * Menu keys a request resolves to, using the registered menu.
	 *
	 * @param array $query Query args (post_type, taxonomy).
	 * @return array<int,array{0:string,1:?string}> Pairs of [key, parent].
	 */
	public static function request_entries( string $pagenow, ?string $plugin_page, array $query, array $menu, array $submenu ): array {
		$specific = array();
		$generic  = array( $pagenow );
		if ( $plugin_page ) {
			$specific[] = $plugin_page;
			$generic    = array();
		} else {
			$pt  = isset( $query['post_type'] ) ? (string) $query['post_type'] : '';
			$tax = isset( $query['taxonomy'] ) ? (string) $query['taxonomy'] : '';
			if ( '' !== $pt ) {
				$specific[] = $pagenow . '?post_type=' . $pt;
			}
			if ( '' !== $tax ) {
				if ( '' !== $pt ) {
					$specific[] = $pagenow . '?taxonomy=' . $tax . '&post_type=' . $pt;
				}
				$specific[] = $pagenow . '?taxonomy=' . $tax;
			}
			if ( 'post.php' === $pagenow && isset( $query['_post_type_resolved'] ) ) {
				$rt         = (string) $query['_post_type_resolved'];
				$specific[] = 'post' === $rt ? 'edit.php' : 'edit.php?post_type=' . $rt;
			}
			if ( 'user-edit.php' === $pagenow ) {
				$specific[] = 'users.php';
			}
		}
		$found = self::match_entries( $specific, $menu, $submenu );
		if ( ! $found && $generic ) {
			$found = self::match_entries( $generic, $menu, $submenu );
		}
		return $found;
	}

	private static function match_entries( array $cands, array $menu, array $submenu ): array {
		$found = array();
		foreach ( $menu as $item ) {
			$slug = (string) ( $item[2] ?? '' );
			if ( in_array( $slug, $cands, true ) ) {
				$found[] = array( $slug, null );
			}
		}
		foreach ( $submenu as $parent => $items ) {
			foreach ( $items as $item ) {
				$slug = (string) ( $item[2] ?? '' );
				if ( in_array( $slug, $cands, true ) ) {
					$found[] = array( $parent . '|' . $slug, (string) $parent );
				}
			}
		}
		return $found;
	}

	/**
	 * Decide a request. Returns the blocking reason or null.
	 */
	public static function decide( string $pagenow, ?string $plugin_page, array $query, array $menu, array $submenu, array $eff, bool $can_manage ): ?string {
		if ( in_array( $pagenow, self::blocked_pages( $eff ), true ) && ! self::is_exempt_key( $pagenow, $can_manage ) ) {
			return 'page';
		}
		if ( 'profile.php' === $pagenow ) {
			return null;
		}
		$entries = self::request_entries( $pagenow, $plugin_page, $query, $menu, $submenu );
		if ( ! $entries ) {
			return null;
		}
		foreach ( $entries as $entry ) {
			if ( self::is_exempt_key( $entry[0], $can_manage ) ) {
				return null;
			}
		}
		$allowed = false;
		foreach ( $entries as $entry ) {
			if ( in_array( $entry[0], $eff['menu_deny'], true ) || ( null !== $entry[1] && in_array( $entry[1], $eff['menu_deny'], true ) ) ) {
				return 'menu';
			}
			if ( null === $eff['menu_allow'] || in_array( $entry[0], $eff['menu_allow'], true ) ) {
				$allowed = true;
			}
		}
		return $allowed ? null : 'menu';
	}

	public static function plugin_locked( string $plugin, array $eff ): bool {
		if ( in_array( $plugin, $eff['plugins_deny'], true ) ) {
			return true;
		}
		return null !== $eff['plugins_allow'] && ! in_array( $plugin, $eff['plugins_allow'], true );
	}

	public static function menu_url( string $parent, string $slug ): string {
		if ( false !== strpos( $slug, '.php' ) && ( $parent === $slug || false === strpos( $slug, 'page=' ) ) && file_exists( ABSPATH . 'wp-admin/' . self::page_of_slug( $slug ) ) ) {
			return admin_url( $slug );
		}
		if ( '' !== $parent && 'admin.php' !== $parent && false !== strpos( $parent, '.php' ) && file_exists( ABSPATH . 'wp-admin/' . self::page_of_slug( $parent ) ) ) {
			return admin_url( $parent . ( false === strpos( $parent, '?' ) ? '?' : '&' ) . 'page=' . rawurlencode( $slug ) );
		}
		return admin_url( 'admin.php?page=' . rawurlencode( $slug ) );
	}

	/** First menu destination the user can open, or profile.php. */
	public static function first_allowed_url( array $menu, array $submenu, array $eff, bool $can_manage, callable $can ): string {
		ksort( $menu );
		foreach ( $menu as $item ) {
			$slug = (string) ( $item[2] ?? '' );
			if ( '' === $slug || 0 === strpos( $slug, 'separator' ) || ! $can( (string) $item[1] ) ) {
				continue;
			}
			$children = array();
			foreach ( $submenu[ $slug ] ?? array() as $sub ) {
				$children[] = (string) $sub[2];
			}
			if ( self::top_blocked( $slug, $children, $eff, $can_manage ) ) {
				continue;
			}
			foreach ( $submenu[ $slug ] ?? array() as $sub ) {
				if ( $can( (string) $sub[1] ) && ! self::key_blocked( $slug . '|' . $sub[2], $slug, $eff, $can_manage ) ) {
					return self::menu_url( $slug, (string) $sub[2] );
				}
			}
			if ( ! $children && ! self::key_blocked( $slug, null, $eff, $can_manage ) ) {
				return self::menu_url( '', $slug );
			}
		}
		return admin_url( 'profile.php' );
	}
}
