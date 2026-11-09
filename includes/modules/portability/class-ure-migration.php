<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Plugin;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Plans a migration from User Role Editor. Roles, capabilities and per-user capabilities
 * live in WordPress itself; what URE keeps of its own is its settings array, of which the
 * extra default roles carry over. Read only.
 */
final class Ure_Migration {
	const PLUGIN     = 'user-role-editor/user-role-editor.php';
	const PRO_PLUGIN = 'user-role-editor-pro/user-role-editor-pro.php';
	const OPTION     = 'user_role_editor';
	const EXTRAS_KEY = 'other_default_roles';
	const ADDITIONAL = 'ure_role_additional_options_values';

	private static function is_active( string $file ): bool {
		if ( in_array( $file, (array) get_option( 'active_plugins', array() ), true ) ) {
			return true;
		}
		return is_multisite() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ $file ] );
	}

	/**
	 * URE network-activated on multisite keeps its settings on the main site.
	 *
	 * @return array|null
	 */
	public static function settings(): ?array {
		$switch = is_multisite() && ! is_main_site() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ self::PLUGIN ] );
		if ( $switch ) {
			switch_to_blog( get_main_site_id() );
		}
		$value = get_option( self::OPTION, null );
		if ( $switch ) {
			restore_current_blog();
		}
		return is_array( $value ) ? $value : null;
	}

	/** @return string[] names of options that look like URE's but aren't the free plugin's. */
	private static function other_options(): array {
		global $wpdb;
		$known = array( self::OPTION, self::ADDITIONAL, 'ure_tasks_queue' );
		$names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( 'ure_' ) . '%', $wpdb->esc_like( 'user_role_editor_' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return array_values( array_diff( array_map( 'strval', (array) $names ), $known ) );
	}

	public static function plan( int $actor, array $opts = array() ): array {
		global $wpdb;
		$plan     = array(
			'source'   => 'ure',
			'label'    => 'User Role Editor',
			'detected' => false,
			'rows'     => array(),
			'ops'      => Migrator::empty_ops(),
		);
		$settings = self::settings();
		$pro      = self::is_active( self::PRO_PLUGIN );
		$others   = self::other_options();
		$backup   = get_option( $wpdb->get_blog_prefix() . 'backup_user_roles', null );

		$plan['detected'] = null !== $settings || self::is_active( self::PLUGIN ) || $pro || is_array( $backup );
		if ( ! $plan['detected'] ) {
			$plan['rows'][] = Migrator::row( __( 'Source', 'role-gatekeeper' ), 'User Role Editor', 'info', __( 'No User Role Editor data found on this site.', 'role-gatekeeper' ) );
			return $plan;
		}
		$settings = (array) $settings;
		$rows     = array();
		$ops      = Migrator::empty_ops();

		$rows[] = Migrator::row( __( 'Roles', 'role-gatekeeper' ), __( 'Roles, capabilities and per-user capabilities', 'role-gatekeeper' ), 'info', __( 'User Role Editor stores these in WordPress itself; they are used here as they are.', 'role-gatekeeper' ) );
		if ( is_array( $backup ) ) {
			$rows[] = Migrator::row( __( 'Roles', 'role-gatekeeper' ), __( 'Saved copy of the original roles', 'role-gatekeeper' ), 'info', __( 'Available as an import source in the Import section of this page.', 'role-gatekeeper' ) );
		}

		$area    = __( 'Default roles', 'role-gatekeeper' );
		$wanted  = isset( $settings[ self::EXTRAS_KEY ] ) && is_array( $settings[ self::EXTRAS_KEY ] ) ? array_values( array_unique( array_filter( $settings[ self::EXTRAS_KEY ], 'is_string' ) ) ) : array();
		$default = (string) get_option( 'default_role' );
		$current = Role_Service::extra_default_roles();
		$valid   = array();
		foreach ( $wanted as $role ) {
			if ( $role === $default ) {
				continue;
			}
			if ( ! get_role( $role ) ) {
				/* translators: %s: role slug */
				$rows[] = Migrator::row( $area, $role, 'skip', __( 'This role no longer exists.', 'role-gatekeeper' ) );
				continue;
			}
			if ( Guard::critical_subset( (array) get_role( $role )->capabilities ) ) {
				$rows[] = Migrator::row( $area, $role, 'blocked', __( 'The role holds capabilities that can take over the site, so new registrations can\'t get it.', 'role-gatekeeper' ) );
				continue;
			}
			$valid[] = $role;
		}
		if ( ! $wanted ) {
			$rows[] = Migrator::row( $area, __( 'Extra roles for new users', 'role-gatekeeper' ), 'info', __( 'None set in User Role Editor.', 'role-gatekeeper' ) );
		} elseif ( $valid ) {
			$target = array_values( array_unique( array_merge( $current, $valid ) ) );
			if ( ! array_diff( $target, $current ) ) {
				$rows[] = Migrator::row( $area, __( 'Extra roles for new users', 'role-gatekeeper' ), 'unchanged', implode( ', ', $valid ) );
			} else {
				$ops['extras'] = $target;
				$rows[]        = Migrator::row( $area, __( 'Extra roles for new users', 'role-gatekeeper' ), 'add', implode( ', ', array_diff( $target, $current ) ) );
				if ( isset( Plugin::modules()['roles'] ) && ! Plugin::is_enabled( 'roles' ) ) {
					$ops['modules'][] = 'roles';
					$rows[]           = Migrator::row( __( 'Modules', 'role-gatekeeper' ), Plugin::modules()['roles']->title(), 'add', __( 'Switch on, so new users get the extra roles.', 'role-gatekeeper' ) );
				}
			}
		}

		$area   = __( 'User Role Editor settings', 'role-gatekeeper' );
		$notes  = array(
			'ure_caps_readable'                     => array( __( 'Readable capability names', 'role-gatekeeper' ), 'info', __( 'The capability editor here shows readable labels without a setting.', 'role-gatekeeper' ) ),
			'ure_show_deprecated_caps'              => array( __( 'Deprecated capabilities', 'role-gatekeeper' ), 'info', __( 'The capability editor here marks deprecated capabilities.', 'role-gatekeeper' ) ),
			'ure_confirm_role_update'               => array( __( 'Confirm role updates', 'role-gatekeeper' ), 'info', __( 'Risky role changes here ask for confirmation without a setting.', 'role-gatekeeper' ) ),
			'edit_user_caps'                        => array( __( 'Per-user capabilities', 'role-gatekeeper' ), 'info', __( 'Edited on the user screens here; existing ones are kept.', 'role-gatekeeper' ) ),
			'show_admin_role'                       => array( __( 'Show the Administrator role', 'role-gatekeeper' ), 'skip', __( 'Display preference with no counterpart; the Administrator role is always listed and protected here.', 'role-gatekeeper' ) ),
			'caps_columns_quant'                    => array( __( 'Capability columns', 'role-gatekeeper' ), 'skip', __( 'Display preference with no counterpart.', 'role-gatekeeper' ) ),
			'count_users_without_role'              => array( __( 'Count users without a role', 'role-gatekeeper' ), 'skip', __( 'No counterpart.', 'role-gatekeeper' ) ),
			'count_users_without_role_thoroughly'   => array( __( 'Count users without a role thoroughly', 'role-gatekeeper' ), 'skip', __( 'No counterpart.', 'role-gatekeeper' ) ),
			'allow_edit_users_to_not_super_admin'   => array( __( 'Site admins editing users on multisite', 'role-gatekeeper' ), 'skip', __( 'Set with the rolegate_multisite_site_admin_access filter here.', 'role-gatekeeper' ) ),
			'enable_simple_admin_for_multisite'     => array( __( 'Single-site administrator on multisite', 'role-gatekeeper' ), 'skip', __( 'Set with the rolegate_multisite_site_admin_access filter here.', 'role-gatekeeper' ) ),
			'caps_access_restrict_for_simple_admin' => array( __( 'Capability limits for single-site administrators', 'role-gatekeeper' ), 'skip', __( 'Site administrators here can only grant capabilities they hold.', 'role-gatekeeper' ) ),
			'caps_allowed_for_single_admin'         => array( __( 'Capabilities allowed for single-site administrators', 'role-gatekeeper' ), 'skip', __( 'Site administrators here can only grant capabilities they hold.', 'role-gatekeeper' ) ),
		);
		$ignore = array( self::EXTRAS_KEY, 'ure_version', 'ure_hide_pro_banner' );
		$extra  = array();
		foreach ( array_keys( $settings ) as $key ) {
			$key = (string) $key;
			if ( isset( $notes[ $key ] ) ) {
				$rows[] = Migrator::row( $area, $notes[ $key ][0], $notes[ $key ][1], $notes[ $key ][2] );
			} elseif ( ! in_array( $key, $ignore, true ) ) {
				$extra[] = sanitize_key( $key );
			}
		}

		$additional = get_option( self::ADDITIONAL, array() );
		$hide_bar   = array();
		foreach ( is_array( $additional ) ? $additional : array() as $role => $items ) {
			if ( is_array( $items ) && ! empty( $items['hide_admin_bar'] ) ) {
				$hide_bar[] = sanitize_key( (string) $role );
			}
		}
		if ( $hide_bar ) {
			/* translators: %s: comma-separated role slugs */
			$rows[] = Migrator::row( $area, __( 'Hide the toolbar for roles', 'role-gatekeeper' ), 'skip', sprintf( __( 'Available in Site access as toolbar hiding by role (%s); switch it on there.', 'role-gatekeeper' ), implode( ', ', $hide_bar ) ) );
		}

		if ( $pro || $extra || $others ) {
			$names  = array_merge( $extra, $others );
			$rows[] = Migrator::row(
				__( 'User Role Editor Pro', 'role-gatekeeper' ),
				__( 'Pro or add-on data', 'role-gatekeeper' ),
				'skip',
				$names
					/* translators: %s: comma-separated setting or option names */
					? sprintf( __( 'Left as it is and not read here: %s.', 'role-gatekeeper' ), implode( ', ', array_slice( $names, 0, 20 ) ) )
					: __( 'Left as it is and not read here.', 'role-gatekeeper' )
			);
		}

		$plan['rows'] = $rows;
		$plan['ops']  = $ops;
		return $plan;
	}
}
