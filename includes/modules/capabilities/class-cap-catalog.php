<?php
namespace Rolegate\Modules\Capabilities;

use Rolegate\Modules\Roles\Role_Store;

defined( 'ABSPATH' ) || exit;

/**
 * Knows which group a capability belongs to and how to label it.
 */
final class Cap_Catalog {
	const OPTION_CUSTOM = 'rolegate_custom_caps';

	/** @return array<string,string> group id => label, in display order */
	public static function group_labels(): array {
		return array(
			'general'    => __( 'General', 'role-gatekeeper' ),
			'posts'      => __( 'Posts', 'role-gatekeeper' ),
			'pages'      => __( 'Pages', 'role-gatekeeper' ),
			'media'      => __( 'Media', 'role-gatekeeper' ),
			'users'      => __( 'Users', 'role-gatekeeper' ),
			'plugins'    => __( 'Plugins', 'role-gatekeeper' ),
			'themes'     => __( 'Themes', 'role-gatekeeper' ),
			'appearance' => __( 'Appearance', 'role-gatekeeper' ),
			'tools'      => __( 'Tools', 'role-gatekeeper' ),
			'settings'   => __( 'Settings', 'role-gatekeeper' ),
		);
	}

	/** @return array<string,string[]> */
	public static function core_map(): array {
		$post_caps = function ( $p ) {
			return array( "edit_{$p}", "edit_others_{$p}", "edit_published_{$p}", "edit_private_{$p}", "publish_{$p}", "delete_{$p}", "delete_others_{$p}", "delete_published_{$p}", "delete_private_{$p}", "read_private_{$p}" );
		};
		return array(
			'general'    => array( 'read', 'edit_dashboard', 'moderate_comments', 'manage_categories', 'unfiltered_html', 'update_core', 'manage_links' ),
			'posts'      => $post_caps( 'posts' ),
			'pages'      => $post_caps( 'pages' ),
			'media'      => array( 'upload_files', 'unfiltered_upload' ),
			'users'      => array( 'list_users', 'create_users', 'add_users', 'edit_users', 'delete_users', 'promote_users', 'remove_users' ),
			'plugins'    => array( 'install_plugins', 'activate_plugins', 'edit_plugins', 'update_plugins', 'delete_plugins' ),
			'themes'     => array( 'install_themes', 'switch_themes', 'edit_themes', 'update_themes', 'delete_themes' ),
			'appearance' => array( 'edit_theme_options', 'customize' ),
			'tools'      => array( 'import', 'export', 'export_others_personal_data', 'erase_others_personal_data' ),
			'settings'   => array( 'manage_options', 'manage_privacy_options', 'edit_files' ),
		);
	}

	/** @return array<string,string> plugin id => label */
	public static function plugin_labels(): array {
		return array(
			'woocommerce' => 'WooCommerce',
			'bbpress'     => 'bbPress',
			'acf'         => 'Advanced Custom Fields',
			'edd'         => 'Easy Digital Downloads',
			'give'        => 'GiveWP',
			'metabox'     => 'Meta Box',
		);
	}

	/** @return array<string,string> plugin id => regex matched against a cap name */
	public static function plugin_patterns(): array {
		return array(
			'woocommerce' => '/^(manage_woocommerce|view_woocommerce_reports|woocommerce_\w+|\w+_(shop_orders?|shop_coupons?|products?|product_terms|shop_webhooks?)|assign_product_terms|read_shop_order\w*)$/',
			'bbpress'     => '/^(keep_gate|moderate|participate|spectate|throttle|view_trash|\w+_(forums?|topics?|replies|reply))$/',
			'acf'         => '/^acf_\w+$/',
			'edd'         => '/^(\w+_shop_(payments?|discounts?|reports|settings|sensitive_data)|view_shop_\w+|export_shop_reports|manage_shop_\w+|edd_\w+|\w+_(products?|download_terms|download_tags))$/',
			'give'        => '/^(\w+_give_\w+|give_\w+|view_give_\w+|manage_give_\w+|export_give_reports)$/',
			'metabox'     => '/^(mb_\w+|metabox_\w+|\w+_meta_box\w*)$/',
		);
	}

	/** @return string[] */
	public static function plugin_known_caps( string $id ): array {
		$known = array(
			'woocommerce' => array( 'manage_woocommerce', 'view_woocommerce_reports' ),
			'bbpress'     => array( 'keep_gate', 'moderate', 'participate', 'spectate', 'throttle', 'view_trash' ),
			'edd'         => array( 'view_shop_reports', 'view_shop_sensitive_data', 'export_shop_reports', 'manage_shop_settings', 'manage_shop_discounts' ),
			'give'        => array( 'view_give_reports', 'view_give_sensitive_data', 'export_give_reports', 'manage_give_settings' ),
		);
		return isset( $known[ $id ] ) ? $known[ $id ] : array();
	}

	/** @return string[] plugin ids whose plugin looks active */
	public static function detected_plugins(): array {
		$found = array();
		$tests = array(
			'woocommerce' => class_exists( 'WooCommerce' ),
			'bbpress'     => function_exists( 'bbpress' ) || class_exists( 'bbPress' ),
			'acf'         => class_exists( 'ACF' ) || function_exists( 'acf' ),
			'edd'         => class_exists( 'Easy_Digital_Downloads' ),
			'give'        => class_exists( 'Give' ),
			'metabox'     => class_exists( 'RWMB_Loader' ) || function_exists( 'rwmb_meta' ),
		);
		foreach ( $tests as $id => $on ) {
			if ( $on ) {
				$found[] = $id;
			}
		}
		return $found;
	}

	/** @return string[] */
	public static function custom_caps(): array {
		$stored = get_option( self::OPTION_CUSTOM, array() );
		return is_array( $stored ) ? array_values( array_filter( array_map( 'strval', $stored ) ) ) : array();
	}

	public static function is_deprecated( string $cap ): bool {
		return (bool) preg_match( '/^level_(\d|10)$/', $cap ) || in_array( $cap, array( 'edit_files', 'manage_links' ), true );
	}

	/** @return string[] every capability name Role Gatekeeper knows or finds on a role */
	public static function universe( array $extra = array() ): array {
		$caps = array();
		foreach ( self::core_map() as $list ) {
			$caps = array_merge( $caps, $list );
		}
		foreach ( Role_Store::all() as $data ) {
			$caps = array_merge( $caps, array_keys( $data['caps'] ) );
		}
		foreach ( self::post_type_caps() as $cap => $unused ) {
			$caps[] = $cap;
		}
		for ( $i = 0; $i <= 10; $i++ ) {
			$caps[] = 'level_' . $i;
		}
		foreach ( self::detected_plugins() as $id ) {
			$caps = array_merge( $caps, self::plugin_known_caps( $id ) );
		}
		$caps = array_merge( $caps, self::custom_caps(), $extra );
		$caps = array_values( array_unique( array_filter( $caps, 'is_string' ) ) );
		sort( $caps );
		return $caps;
	}

	/** @return array<string,string> cap => post type slug, for post types with their own capability names */
	public static function post_type_caps(): array {
		$out = array();
		foreach ( get_post_types( array(), 'objects' ) as $slug => $type ) {
			if ( $type->_builtin || ! isset( $type->cap ) ) {
				continue;
			}
			foreach ( get_object_vars( $type->cap ) as $key => $cap ) {
				if ( in_array( $key, array( 'edit_post', 'read_post', 'delete_post' ), true ) ) {
					continue;
				}
				if ( is_string( $cap ) && '' !== $cap && ! in_array( $cap, array( 'edit_posts', 'edit_others_posts', 'publish_posts', 'read_private_posts', 'delete_posts', 'delete_private_posts', 'delete_published_posts', 'delete_others_posts', 'edit_private_posts', 'edit_published_posts', 'read' ), true ) ) {
					$out[ $cap ] = $slug;
				}
			}
		}
		return $out;
	}

	public static function group_of( string $cap, array $cpt_caps = array() ): string {
		if ( self::is_deprecated( $cap ) ) {
			return 'deprecated';
		}
		foreach ( self::core_map() as $group => $list ) {
			if ( in_array( $cap, $list, true ) ) {
				return $group;
			}
		}
		$cpt_plugin = array(
			'product'      => 'woocommerce',
			'shop_order'   => 'woocommerce',
			'shop_coupon'  => 'woocommerce',
			'forum'        => 'bbpress',
			'topic'        => 'bbpress',
			'reply'        => 'bbpress',
			'download'     => 'edd',
			'give_forms'   => 'give',
			'give_payment' => 'give',
		);
		if ( isset( $cpt_caps[ $cap ] ) ) {
			$type = $cpt_caps[ $cap ];
			if ( isset( $cpt_plugin[ $type ] ) ) {
				return 'plugin:' . $cpt_plugin[ $type ];
			}
			if ( 0 === strpos( $type, 'acf-' ) ) {
				return 'plugin:acf';
			}
		}
		foreach ( self::plugin_patterns() as $id => $regex ) {
			if ( preg_match( $regex, $cap ) ) {
				return 'plugin:' . $id;
			}
		}
		if ( isset( $cpt_caps[ $cap ] ) ) {
			return 'cpt:' . $cpt_caps[ $cap ];
		}
		return 'custom';
	}

	/**
	 * @param string[] $caps
	 * @return array<string,array{label:string,caps:string[]}> ordered group id => group
	 */
	public static function grouped( array $caps ): array {
		$cpt    = self::post_type_caps();
		$bucket = array();
		foreach ( $caps as $cap ) {
			$bucket[ self::group_of( $cap, $cpt ) ][] = $cap;
		}
		$out = array();
		foreach ( self::group_labels() as $id => $label ) {
			if ( ! empty( $bucket[ $id ] ) ) {
				$out[ $id ] = array(
					'label' => $label,
					'caps'  => self::order_within_core( $id, $bucket[ $id ] ),
				);
			}
		}
		$plugins = self::plugin_labels();
		foreach ( $plugins as $id => $label ) {
			if ( ! empty( $bucket[ 'plugin:' . $id ] ) ) {
				$out[ 'plugin:' . $id ] = array(
					'label' => $label,
					'caps'  => $bucket[ 'plugin:' . $id ],
				);
			}
		}
		foreach ( $bucket as $id => $list ) {
			if ( 0 === strpos( $id, 'cpt:' ) ) {
				$type       = get_post_type_object( substr( $id, 4 ) );
				$out[ $id ] = array(
					/* translators: %s: post type label */
					'label' => sprintf( __( '%s (post type)', 'role-gatekeeper' ), $type ? $type->labels->name : substr( $id, 4 ) ),
					'caps'  => $list,
				);
			}
		}
		if ( ! empty( $bucket['custom'] ) ) {
			$out['custom'] = array(
				'label' => __( 'Custom', 'role-gatekeeper' ),
				'caps'  => $bucket['custom'],
			);
		}
		if ( ! empty( $bucket['deprecated'] ) ) {
			$out['deprecated'] = array(
				'label' => __( 'Deprecated', 'role-gatekeeper' ),
				'caps'  => $bucket['deprecated'],
			);
		}
		return $out;
	}

	public static function label( string $cap ): string {
		$overrides = array(
			'read'                        => __( 'Read (log in and view the dashboard)', 'role-gatekeeper' ),
			'edit_dashboard'              => __( 'Edit dashboard', 'role-gatekeeper' ),
			'unfiltered_html'             => __( 'Post unfiltered HTML', 'role-gatekeeper' ),
			'unfiltered_upload'           => __( 'Upload unfiltered files', 'role-gatekeeper' ),
			'manage_options'              => __( 'Manage settings', 'role-gatekeeper' ),
			'edit_theme_options'          => __( 'Edit theme options (menus, widgets)', 'role-gatekeeper' ),
			'customize'                   => __( 'Use the Customizer', 'role-gatekeeper' ),
			'update_core'                 => __( 'Update WordPress', 'role-gatekeeper' ),
			'export_others_personal_data' => __( 'Export other users\' personal data', 'role-gatekeeper' ),
			'erase_others_personal_data'  => __( 'Erase other users\' personal data', 'role-gatekeeper' ),
		);
		if ( isset( $overrides[ $cap ] ) ) {
			return $overrides[ $cap ];
		}
		if ( preg_match( '/^level_(\d+)$/', $cap, $m ) ) {
			/* translators: %s: level number */
			return sprintf( __( 'User level %s', 'role-gatekeeper' ), $m[1] );
		}
		return ucfirst( trim( str_replace( array( '_', '-', ':' ), ' ', $cap ) ) );
	}

	/** @param string[] $caps @return string[] */
	private static function order_within_core( string $group, array $caps ): array {
		$map = self::core_map();
		if ( ! isset( $map[ $group ] ) ) {
			return $caps;
		}
		$known = array_values( array_intersect( $map[ $group ], $caps ) );
		$rest  = array_values( array_diff( $caps, $known ) );
		sort( $rest );
		return array_merge( $known, $rest );
	}
}
