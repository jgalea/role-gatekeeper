<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Plugin;
use Rolegate\Modules\Admin_Ui\Engine;
use Rolegate\Modules\Admin_Ui\Rules;

defined( 'ABSPATH' ) || exit;

/**
 * Plans a migration from Adminimize: the top-level menu items, dashboard widgets and toolbar
 * items it hides per role are hidden here for the same roles. Everything else it keeps is
 * listed as not carried over. Adminimize's own settings are never touched.
 */
final class Adminimize_Migration {
	const PLUGIN = 'adminimize/adminimize.php';
	const OPTION = 'mw_adminimize';
	const PREFIX = 'mw_adminimize_disabled_';

	private static function is_sitewide(): bool {
		return is_multisite() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ self::PLUGIN ] );
	}

	private static function is_active(): bool {
		return in_array( self::PLUGIN, (array) get_option( 'active_plugins', array() ), true ) || self::is_sitewide();
	}

	/** @return array|null */
	public static function settings(): ?array {
		$value = self::is_sitewide() ? get_site_option( self::OPTION, null ) : get_option( self::OPTION, null );
		return is_array( $value ) ? $value : null;
	}

	/** @return string[] */
	private static function items( array $settings, string $key ): array {
		$list = isset( $settings[ $key ] ) && is_array( $settings[ $key ] ) ? $settings[ $key ] : array();
		$out  = array();
		foreach ( $list as $item ) {
			if ( is_string( $item ) && '' !== trim( $item ) ) {
				$out[] = trim( $item );
			}
		}
		return array_values( array_unique( $out ) );
	}

	public static function plan( int $actor, array $opts = array() ): array {
		$plan     = array(
			'source'   => 'adminimize',
			'label'    => 'Adminimize',
			'detected' => false,
			'rows'     => array(),
			'ops'      => Migrator::empty_ops(),
		);
		$settings = self::settings();

		$plan['detected'] = null !== $settings || self::is_active();
		if ( ! $plan['detected'] ) {
			$plan['rows'][] = Migrator::row( __( 'Source', 'role-gatekeeper' ), 'Adminimize', 'info', __( 'No Adminimize data found on this site.', 'role-gatekeeper' ) );
			return $plan;
		}
		$settings = (array) $settings;
		$rows     = array();
		$ops      = Migrator::empty_ops();
		$used     = array();
		$all      = Rules::all();
		$multi    = ! empty( $settings['mw_adminimize_multiple_roles'] );
		$noblock  = ! empty( $settings['mw_adminimize_prevent_page_access'] );

		foreach ( wp_roles()->roles as $slug => $def ) {
			$slug  = (string) $slug;
			$keys  = array(
				'menu'      => self::PREFIX . 'menu_' . $slug . '_items',
				'dashboard' => self::PREFIX . 'dashboard_option_' . $slug . '_items',
				'bar'       => self::PREFIX . 'admin_bar_' . $slug . '_items',
				'bar_front' => self::PREFIX . 'admin_bar_frontend_' . $slug . '_items',
			);
			$used  = array_merge( $used, array_values( $keys ) );
			$menu  = self::items( $settings, $keys['menu'] );
			$dash  = self::items( $settings, $keys['dashboard'] );
			$bar   = self::items( $settings, $keys['bar'] );
			$front = self::items( $settings, $keys['bar_front'] );
			if ( ! $menu && ! $dash && ! $bar && ! $front ) {
				continue;
			}
			$area_role = __( 'Roles', 'role-gatekeeper' );
			if ( 'administrator' === $slug ) {
				$rows[] = Migrator::row( $area_role, $slug, 'skip', __( 'Role Gatekeeper never restricts administrators, so what Adminimize hides for them is not carried over.', 'role-gatekeeper' ) );
				continue;
			}
			if ( Rules::is_manager_role( (array) ( $def['capabilities'] ?? array() ) ) ) {
				$rows[] = Migrator::row( $area_role, $slug, 'blocked', __( 'Roles that can manage Role Gatekeeper cannot be restricted.', 'role-gatekeeper' ) );
				continue;
			}

			$current = Rules::get( 'role', $slug );
			$target  = $current;
			$mine    = array();

			if ( $menu ) {
				$area = __( 'Hidden menu items', 'role-gatekeeper' );
				if ( $multi ) {
					$mine[] = Migrator::row( $area, $slug, 'skip', __( 'Adminimize hides an item for a user with several roles only when every role hides it; here one role is enough, which would hide more.', 'role-gatekeeper' ) );
				} elseif ( $noblock ) {
					$mine[] = Migrator::row( $area, $slug, 'skip', __( 'Adminimize only hides these items on this site; here the pages are also closed to the role, which would block more.', 'role-gatekeeper' ) );
				} elseif ( 'deny' !== $target['menu']['model'] ) {
					$mine[] = Migrator::row( $area, $slug, 'conflict', __( 'The role has an allow list for the menu here; it stays.', 'role-gatekeeper' ) );
				} else {
					$ok = Rules::sanitize(
						array(
							'menu' => array(
								'model' => 'deny',
								'items' => $menu,
							),
						)
					)['menu']['items'];
					$ok = array_values(
						array_filter(
							$ok,
							function ( $key ) {
								return ! Engine::is_exempt_key( $key, false );
							}
						)
					);
					self::report( $mine, $area, $slug, $menu, $ok, $target['menu']['items'] );
					$target['menu']['items'] = array_values( array_unique( array_merge( $target['menu']['items'], $ok ) ) );
				}
			}

			if ( $dash ) {
				$area = __( 'Dashboard widgets', 'role-gatekeeper' );
				if ( $multi ) {
					$mine[] = Migrator::row( $area, $slug, 'skip', __( 'Adminimize hides a widget for a user with several roles only when every role hides it; here one role is enough, which would hide more.', 'role-gatekeeper' ) );
				} else {
					$ok  = Rules::sanitize( array( 'metaboxes' => array( 'dashboard' => $dash ) ) )['metaboxes']['dashboard'] ?? array();
					$had = $target['metaboxes']['dashboard'] ?? array();
					self::report( $mine, $area, $slug, $dash, $ok, $had );
					if ( $ok ) {
						$target['metaboxes']['dashboard'] = array_values( array_unique( array_merge( $had, $ok ) ) );
					}
				}
			}

			if ( $bar || $front ) {
				$area = __( 'Toolbar items', 'role-gatekeeper' );
				if ( $multi ) {
					$mine[] = Migrator::row( $area, $slug, 'skip', __( 'Adminimize hides an item for a user with several roles only when every role hides it; here one role is enough, which would hide more.', 'role-gatekeeper' ) );
				} else {
					$both = array_values( array_intersect( $bar, $front ) );
					$one  = array_values( array_diff( array_merge( $bar, $front ), $both ) );
					if ( $one ) {
						/* translators: %s: comma-separated toolbar item ids */
						$mine[] = Migrator::row( $area, $slug, 'skip', sprintf( __( 'Hidden by Adminimize only in the dashboard or only on the site, while here toolbar items are hidden in both: %s.', 'role-gatekeeper' ), implode( ', ', $one ) ) );
					}
					$ok  = Rules::sanitize( array( 'admin_bar' => $both ) )['admin_bar'];
					$ok  = array_values( array_diff( $ok, Engine::protected_bar_nodes() ) );
					$had = $target['admin_bar'];
					self::report( $mine, $area, $slug, $both, $ok, $had );
					$target['admin_bar'] = array_values( array_unique( array_merge( $had, $ok ) ) );
				}
			}

			if ( $target !== $current ) {
				$target                  = Rules::sanitize( $target );
				$check                   = Rules::validate( $target );
				$after                   = $all;
				$after['roles'][ $slug ] = $target;
				if ( is_wp_error( $check ) ) {
					$mine[] = Migrator::row( $area_role, $slug, 'blocked', $check->get_error_message() );
				} elseif ( ! Migrator::is_shell( $actor ) && Rules::lockout_reasons( $actor, $after ) ) {
					$mine[] = Migrator::row( $area_role, $slug, 'blocked', __( 'This would leave you without access to Role Gatekeeper or your profile.', 'role-gatekeeper' ) );
				} else {
					$ops['access'][ $slug ] = $target;
				}
				if ( ! isset( $ops['access'][ $slug ] ) ) {
					$mine = array_values(
						array_filter(
							$mine,
							function ( $row ) {
								return 'add' !== $row['action'];
							}
						)
					);
				}
			}
			$rows = array_merge( $rows, $mine );
		}

		if ( $ops['access'] && isset( Plugin::modules()['admin-ui'] ) ) {
			$title = Plugin::modules()['admin-ui']->title();
			if ( Plugin::is_enabled( 'admin-ui' ) ) {
				$rows[] = Migrator::row( __( 'Modules', 'role-gatekeeper' ), $title, 'unchanged', __( 'Already on.', 'role-gatekeeper' ) );
			} else {
				$ops['modules'][] = 'admin-ui';
				$rows[]           = Migrator::row( __( 'Modules', 'role-gatekeeper' ), $title, 'add', __( 'Switch on, so the hidden items stay hidden.', 'role-gatekeeper' ) );
			}
		}

		self::not_migrated( $settings, $used, $rows );

		$plan['rows'] = $rows;
		$plan['ops']  = $ops;
		return $plan;
	}

	/**
	 * @param string[] $wanted  what Adminimize hides
	 * @param string[] $ok      what can be carried over
	 * @param string[] $present what the role already hides here
	 */
	private static function report( array &$rows, string $area, string $role, array $wanted, array $ok, array $present ): void {
		$left = array_values( array_diff( $wanted, $ok ) );
		$new  = array_values( array_diff( $ok, $present ) );
		if ( $left ) {
			/* translators: %s: comma-separated item names */
			$rows[] = Migrator::row( $area, $role, 'skip', sprintf( __( 'Can\'t be hidden here: %s.', 'role-gatekeeper' ), implode( ', ', $left ) ) );
		}
		if ( $new ) {
			$rows[] = Migrator::row( $area, $role, 'add', implode( ', ', $new ) );
		} elseif ( $ok ) {
			$rows[] = Migrator::row( $area, $role, 'unchanged', implode( ', ', $ok ) );
		}
	}

	private static function not_migrated( array $settings, array $used, array &$rows ): void {
		$area   = __( 'Not carried over', 'role-gatekeeper' );
		$groups = array(
			'submenu_'            => __( 'Hidden submenu items (Adminimize stores their position, not the page)', 'role-gatekeeper' ),
			'global_option_'      => __( 'Hidden global options', 'role-gatekeeper' ),
			'metaboxes_'          => __( 'Hidden fields on the post, page and custom post type screens (hidden with CSS selectors)', 'role-gatekeeper' ),
			'link_option_'        => __( 'Hidden link screen fields', 'role-gatekeeper' ),
			'nav_menu_option_'    => __( 'Hidden menu screen fields', 'role-gatekeeper' ),
			'widget_option_'      => __( 'Hidden widget screen fields', 'role-gatekeeper' ),
			'admin_bar_frontend_' => __( 'Toolbar items of roles that no longer exist', 'role-gatekeeper' ),
			'admin_bar_'          => __( 'Toolbar items of roles that no longer exist', 'role-gatekeeper' ),
			'dashboard_option_'   => __( 'Dashboard widgets of roles that no longer exist', 'role-gatekeeper' ),
			'menu_'               => __( 'Menu items of roles that no longer exist', 'role-gatekeeper' ),
		);
		$found  = array();
		$other  = array();
		$cached = false;
		foreach ( $settings as $key => $value ) {
			$key = (string) $key;
			if ( in_array( $key, $used, true ) ) {
				continue;
			}
			if ( 0 === strpos( $key, self::PREFIX ) ) {
				$items = is_array( $value ) ? array_filter( $value, 'is_scalar' ) : array();
				if ( ! $items ) {
					continue;
				}
				$rest = substr( $key, strlen( self::PREFIX ) );
				foreach ( $groups as $prefix => $label ) {
					if ( 0 === strpos( $rest, $prefix ) ) {
						$role              = preg_replace( '/_items$/', '', substr( $rest, strlen( $prefix ) ) );
						$found[ $label ][] = sanitize_key( (string) $role );
						continue 2;
					}
				}
				$other[] = sanitize_key( $key );
			} elseif ( in_array( $key, array( 'mw_adminimize_dashboard_widgets', 'mw_adminimize_admin_bar_nodes', 'mw_adminimize_admin_bar_frontend_nodes' ), true ) || 0 === strpos( $key, 'mw_adminimize_meta_boxes_' ) ) {
				$cached = true;
			} elseif ( in_array( $key, array( 'mw_adminimize_multiple_roles', 'mw_adminimize_prevent_page_access' ), true ) ) {
				continue;
			} elseif ( ! empty( $value ) ) {
				$other[] = sanitize_key( $key );
			}
		}
		foreach ( $found as $label => $roles ) {
			/* translators: %s: comma-separated role slugs */
			$rows[] = Migrator::row( $area, $label, 'skip', sprintf( __( 'Roles: %s.', 'role-gatekeeper' ), implode( ', ', array_unique( $roles ) ) ) );
		}
		if ( $other ) {
			$rows[] = Migrator::row(
				$area,
				__( 'Other Adminimize settings', 'role-gatekeeper' ),
				'skip',
				/* translators: %s: comma-separated setting names */
				sprintf( __( 'Left as they are and not read here: %s.', 'role-gatekeeper' ), implode( ', ', array_slice( $other, 0, 30 ) ) )
			);
		}
		if ( $cached ) {
			$rows[] = Migrator::row( $area, __( 'Saved lists of available items', 'role-gatekeeper' ), 'info', __( 'Adminimize keeps these for its own settings screen; nothing to carry over.', 'role-gatekeeper' ) );
		}
	}
}
