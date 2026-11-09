<?php
namespace Rolewright\Modules\Site_Access;

use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Site_Access_Settings {
	const OPTION = 'rolewright_site_access';

	public static function defaults(): array {
		return array(
			'private_enabled'    => false,
			'private_feed'       => true,
			'private_rest'       => true,
			'allow_paths'        => array(),
			'admin_gate'         => false,
			'admin_gate_cap'     => 'edit_posts',
			'admin_redirect'     => '',
			'toolbar_hide_roles' => array(),
			'toolbar_hide_gated' => true,
		);
	}

	public static function get(): array {
		$stored = get_option( self::OPTION, array() );
		return array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Turns posted values into a clean settings array, or a WP_Error to show the admin.
	 *
	 * @param array $raw     Unslashed form values.
	 * @param array $current Settings stored now.
	 * @return array|\WP_Error
	 */
	public static function sanitize( array $raw, array $current, int $actor_id ) {
		$out                       = self::defaults();
		$out['private_enabled']    = ! empty( $raw['private_enabled'] );
		$out['private_feed']       = ! empty( $raw['private_feed'] );
		$out['private_rest']       = ! empty( $raw['private_rest'] );
		$out['admin_gate']         = ! empty( $raw['admin_gate'] );
		$out['toolbar_hide_gated'] = ! empty( $raw['toolbar_hide_gated'] );

		if ( $out['private_enabled'] && empty( $current['private_enabled'] ) && empty( $raw['confirm_private'] ) ) {
			return new \WP_Error( 'rolewright_confirm', __( 'Tick the confirmation box to turn private-site mode on.', 'rolewright' ) );
		}

		$paths = isset( $raw['allow_paths'] ) ? $raw['allow_paths'] : '';
		if ( is_string( $paths ) ) {
			$paths = preg_split( '/\r\n|\r|\n/', $paths );
		}
		foreach ( (array) $paths as $line ) {
			$clean = self::clean_path( (string) $line );
			if ( '' !== $clean ) {
				$out['allow_paths'][] = $clean;
			}
		}
		$out['allow_paths'] = array_values( array_unique( $out['allow_paths'] ) );

		$cap = isset( $raw['admin_gate_cap'] ) ? Guard::sanitize_cap_name( (string) $raw['admin_gate_cap'] ) : false;
		if ( $out['admin_gate'] ) {
			if ( false === $cap ) {
				return new \WP_Error( 'rolewright_bad_cap', __( 'Choose a valid capability for wp-admin access.', 'rolewright' ) );
			}
			if ( $actor_id && ! user_can( $actor_id, $cap ) ) {
				return new \WP_Error( 'rolewright_self_lockout', __( 'You do not hold that capability yourself, so choosing it could lock you out of wp-admin.', 'rolewright' ) );
			}
		}
		$out['admin_gate_cap'] = false === $cap ? 'edit_posts' : $cap;

		$url = isset( $raw['admin_redirect'] ) ? trim( (string) $raw['admin_redirect'] ) : '';
		if ( '' !== $url ) {
			$checked = Redirects::sanitize_target( $url );
			if ( false === $checked ) {
				return new \WP_Error( 'rolewright_bad_redirect', __( 'The redirect URL must be a page on this site and cannot point into wp-admin or the login page.', 'rolewright' ) );
			}
			$url = $checked;
		}
		$out['admin_redirect'] = $url;

		$roles = array();
		foreach ( (array) ( isset( $raw['toolbar_hide_roles'] ) ? $raw['toolbar_hide_roles'] : array() ) as $role ) {
			$role = sanitize_key( (string) $role );
			if ( $role && get_role( $role ) ) {
				$roles[] = $role;
			}
		}
		$out['toolbar_hide_roles'] = array_values( array_unique( $roles ) );

		return $out;
	}

	/** Reduces a line to "/path" or "/path*"; empty when it is not a usable site path. */
	public static function clean_path( string $line ): string {
		$line = trim( $line );
		if ( '' === $line || preg_match( '#^[a-z][a-z0-9+.-]*:#i', $line ) || 0 === strpos( $line, '//' ) ) {
			return '';
		}
		$line = preg_replace( '/[?#].*$/', '', $line );
		if ( ! is_string( $line ) || '' === $line ) {
			return '';
		}
		if ( '/' !== $line[0] ) {
			$line = '/' . $line;
		}
		$wild = '*' === substr( $line, -1 );
		$base = Gate::normalize_path( rtrim( $line, '*' ) );
		if ( null === $base ) {
			return '';
		}
		if ( $wild ) {
			return '/' === $base ? '' : $base . '/*';
		}
		return $base;
	}

	public static function save( array $new, int $actor_id ): void {
		$before = self::get();
		update_option( self::OPTION, $new, false );
		do_action(
			'rolewright_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => 'site-access',
				'before' => $before,
				'after'  => $new,
			)
		);
	}
}
