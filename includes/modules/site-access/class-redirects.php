<?php
namespace Rolewright\Modules\Site_Access;

defined( 'ABSPATH' ) || exit;

final class Redirects {
	/**
	 * Returns a same-site absolute URL, or false when the target is off-site, malformed or would
	 * send the visitor into wp-admin (unless allowed) or the login page, which can loop.
	 *
	 * @return string|false
	 */
	public static function sanitize_target( string $url, bool $allow_admin = false ) {
		$url = trim( $url );
		if ( '' === $url || preg_match( '/[\x00-\x1f\x7f\\\\]/', $url ) ) {
			return false;
		}
		if ( '/' === $url[0] && 0 !== strpos( $url, '//' ) ) {
			$url = home_url( $url );
		}
		$fallback = '__rw_invalid__';
		$valid    = wp_validate_redirect( $url, $fallback );
		if ( $fallback === $valid || ! self::is_on_this_site( $valid ) ) {
			return false;
		}
		$path = (string) wp_parse_url( $valid, PHP_URL_PATH );
		if ( preg_match( '#/wp-login\.php$#', $path ) ) {
			return false;
		}
		if ( ! $allow_admin && false !== strpos( $path . '/', '/wp-admin/' ) ) {
			return false;
		}
		return esc_url_raw( $valid );
	}

	public static function is_on_this_site( string $url ): bool {
		$host = wp_parse_url( $url, PHP_URL_HOST );
		$home = wp_parse_url( home_url(), PHP_URL_HOST );
		return is_string( $host ) && is_string( $home ) && 0 === strcasecmp( $host, $home );
	}
}
