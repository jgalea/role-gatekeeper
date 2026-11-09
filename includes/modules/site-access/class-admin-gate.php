<?php
namespace Rolewright\Modules\Site_Access;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Rescue;

defined( 'ABSPATH' ) || exit;

final class Admin_Gate {
	const EXEMPT_PAGES = array( 'admin-ajax.php', 'admin-post.php', 'async-upload.php' );

	public function register(): void {
		add_action( 'admin_init', array( $this, 'on_admin_init' ), 1 );
		add_filter( 'show_admin_bar', array( $this, 'filter_toolbar' ), 99 );
	}

	/**
	 * Administrators, super admins and anyone holding the plugin's manage cap are never gated, so
	 * a wrong setting can't shut the people who would fix it out of wp-admin.
	 */
	public static function is_exempt( \WP_User $user ): bool {
		if ( is_super_admin( $user->ID ) || Rescue::is_eligible( $user ) || user_can( $user, Caps::MANAGE ) ) {
			return true;
		}
		return (bool) apply_filters( 'rolewright_site_access_admin_exempt', false, $user );
	}

	public static function is_gated( \WP_User $user, array $settings ): bool {
		return ! empty( $settings['admin_gate'] )
			&& $user->exists()
			&& ! self::is_exempt( $user )
			&& ! user_can( $user, (string) $settings['admin_gate_cap'] );
	}

	/** Where a gated user is sent. Never wp-admin or wp-login.php, so it can't loop. */
	public static function target( array $settings ): string {
		$url = '' !== (string) $settings['admin_redirect'] ? Redirects::sanitize_target( (string) $settings['admin_redirect'] ) : false;
		return false === $url ? home_url( '/' ) : $url;
	}

	public function on_admin_init(): void {
		global $pagenow;
		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || in_array( $pagenow, self::EXEMPT_PAGES, true ) ) {
			return;
		}
		$settings = Site_Access_Settings::get();
		$user     = wp_get_current_user();
		if ( ! self::is_gated( $user, $settings ) ) {
			return;
		}
		wp_safe_redirect( self::target( $settings ), 302, 'Rolewright' );
		exit;
	}

	/**
	 * @param bool $show
	 * @return bool
	 */
	public function filter_toolbar( $show ) {
		if ( ! $show ) {
			return $show;
		}
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return $show;
		}
		$settings = Site_Access_Settings::get();
		if ( array_intersect( (array) $user->roles, (array) $settings['toolbar_hide_roles'] ) ) {
			return false;
		}
		if ( ! empty( $settings['toolbar_hide_gated'] ) && self::is_gated( $user, $settings ) ) {
			return false;
		}
		return $show;
	}
}
