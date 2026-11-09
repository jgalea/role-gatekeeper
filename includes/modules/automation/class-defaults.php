<?php
namespace Rolewright\Modules\Automation;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress's own default capabilities for the five core roles, read by running core's
 * populate_roles() against an in-memory role set so the stored roles are never touched.
 */
final class Defaults {
	const ROLES = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );

	/** @var array<string,array<string,bool>>|null */
	private static $cache = null;

	/** @return array<string,array<string,bool>> */
	public static function core_roles(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}
		global $wp_roles, $wp_user_roles;
		require_once ABSPATH . 'wp-admin/includes/schema.php';

		// phpcs:disable WordPress.WP.GlobalVariablesOverride.Prohibited -- swaps the role globals for a scratch copy to read core defaults, and restores them in finally.
		$saved_roles   = $wp_roles;
		$saved_static  = $wp_user_roles;
		$wp_user_roles = array(
			'rolewright_scratch' => array(
				'name'         => 'Scratch',
				'capabilities' => array(),
			),
		);
		$out           = array();
		try {
			$wp_roles = new \WP_Roles();
			populate_roles();
			foreach ( self::ROLES as $slug ) {
				$role = $wp_roles->get_role( $slug );
				if ( $role ) {
					$out[ $slug ] = array();
					foreach ( (array) $role->capabilities as $cap => $grant ) {
						$out[ $slug ][ (string) $cap ] = (bool) $grant;
					}
				}
			}
		} finally {
			$wp_roles      = $saved_roles;
			$wp_user_roles = $saved_static;
		}
		// phpcs:enable WordPress.WP.GlobalVariablesOverride.Prohibited
		self::$cache = $out;
		return $out;
	}

	/** @return array<string,bool>|null */
	public static function for_role( string $slug ): ?array {
		$all = self::core_roles();
		return $all[ $slug ] ?? null;
	}
}
