<?php
namespace Rolegate\Modules\Login_Redirects;

use Rolegate\Modules\Site_Access\Redirects;

defined( 'ABSPATH' ) || exit;

final class Resolver {
	const FIRST_LOGIN_META = 'rolegate_first_login_pending';

	/**
	 * Roles in priority order: the configured order first, then any other role the user holds.
	 *
	 * @param string[] $user_roles
	 * @param string[] $priority
	 * @return string[]
	 */
	public static function ordered_roles( array $user_roles, array $priority ): array {
		$first = array_values( array_intersect( $priority, $user_roles ) );
		return array_values( array_merge( $first, array_diff( $user_roles, $first ) ) );
	}

	/**
	 * First usable URL for $field among the user's roles, or '' when no role has one. A stored
	 * URL is checked again here, so a value written straight into the option can't redirect off-site.
	 */
	public static function url_for( array $user_roles, string $field, array $settings ): string {
		foreach ( self::ordered_roles( $user_roles, (array) $settings['priority'] ) as $role ) {
			if ( empty( $settings['rules'][ $role ][ $field ] ) ) {
				continue;
			}
			$url = Redirects::sanitize_target( (string) $settings['rules'][ $role ][ $field ], 'logout' !== $field );
			if ( false !== $url ) {
				return $url;
			}
		}
		return '';
	}

	/** True when the visitor asked for a specific same-site destination. */
	public static function requested_is_usable( string $requested ): bool {
		return '' !== $requested && false !== Redirects::sanitize_target( $requested, true );
	}

	/**
	 * @param string                   $redirect_to
	 * @param string                   $requested
	 * @param \WP_User|\WP_Error|mixed $user
	 * @return string
	 */
	public static function filter_login( $redirect_to, $requested, $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $redirect_to;
		}
		$settings  = Login_Redirects_Settings::get();
		$requested = (string) $requested;
		$usable    = self::requested_is_usable( $requested );
		$first     = (bool) get_user_meta( $user->ID, self::FIRST_LOGIN_META, true );
		if ( $first ) {
			delete_user_meta( $user->ID, self::FIRST_LOGIN_META );
		}
		if ( $usable && empty( $settings['override'] ) ) {
			return $redirect_to;
		}
		$roles = (array) $user->roles;
		$url   = $first ? self::url_for( $roles, 'first_login', $settings ) : '';
		if ( '' === $url ) {
			$url = self::url_for( $roles, 'login', $settings );
		}
		if ( '' === $url ) {
			$url = self::url_for( $roles, 'landing', $settings );
		}
		if ( '' !== $url ) {
			return $url;
		}
		if ( '' !== $requested && ! $usable ) {
			return admin_url();
		}
		return $redirect_to;
	}

	/**
	 * @param string                   $redirect_to
	 * @param string                   $requested
	 * @param \WP_User|\WP_Error|mixed $user
	 * @return string
	 */
	public static function filter_logout( $redirect_to, $requested, $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $redirect_to;
		}
		$requested = (string) $requested;
		if ( '' !== $requested ) {
			return false !== Redirects::sanitize_target( $requested, true ) ? $redirect_to : add_query_arg( 'loggedout', 'true', wp_login_url() );
		}
		$url = self::url_for( (array) $user->roles, 'logout', Login_Redirects_Settings::get() );
		return '' !== $url ? $url : $redirect_to;
	}

	/**
	 * @param string $redirect_to
	 * @param mixed  $user_id The new user's ID.
	 * @return string
	 */
	public static function filter_registration( $redirect_to, $user_id ) {
		$user = is_numeric( $user_id ) ? get_userdata( (int) $user_id ) : false;
		if ( ! $user ) {
			return $redirect_to;
		}
		$url = self::url_for( (array) $user->roles, 'registration', Login_Redirects_Settings::get() );
		return '' !== $url ? $url : $redirect_to;
	}

	public static function mark_first_login( $user_id ): void {
		update_user_meta( (int) $user_id, self::FIRST_LOGIN_META, 1 );
	}
}
