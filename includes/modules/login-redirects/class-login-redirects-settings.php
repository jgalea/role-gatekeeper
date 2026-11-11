<?php
namespace Rolegate\Modules\Login_Redirects;

use Rolegate\Modules\Site_Access\Redirects;

defined( 'ABSPATH' ) || exit;

final class Login_Redirects_Settings {
	const OPTION = 'rolegate_login_redirects';
	const FIELDS = array( 'login', 'logout', 'landing', 'registration', 'first_login' );

	public static function defaults(): array {
		return array(
			'rules'    => array(),
			'priority' => array(),
			'override' => false,
		);
	}

	public static function get(): array {
		$stored          = get_option( self::OPTION, array() );
		$out             = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		$out['rules']    = is_array( $out['rules'] ) ? $out['rules'] : array();
		$out['priority'] = is_array( $out['priority'] ) ? array_values( $out['priority'] ) : array();
		return $out;
	}

	/**
	 * @param array $raw Unslashed form values: rules[role][login|logout|landing|registration|first_login], priority[role], override.
	 * @return array|\WP_Error
	 */
	public static function sanitize( array $raw ) {
		$out             = self::defaults();
		$out['override'] = ! empty( $raw['override'] );
		$rules           = isset( $raw['rules'] ) && is_array( $raw['rules'] ) ? $raw['rules'] : array();
		foreach ( $rules as $role => $fields ) {
			$role = sanitize_key( (string) $role );
			if ( ! $role || ! get_role( $role ) || ! is_array( $fields ) ) {
				continue;
			}
			foreach ( self::FIELDS as $field ) {
				$url = isset( $fields[ $field ] ) ? trim( (string) $fields[ $field ] ) : '';
				if ( '' === $url ) {
					continue;
				}
				$ok = Redirects::sanitize_target( $url, 'logout' !== $field );
				if ( false === $ok ) {
					return new \WP_Error(
						'rolegate_bad_redirect',
						sprintf(
							/* translators: 1: role slug, 2: field name */
							__( 'The %2$s URL for %1$s must be a page on this site, and cannot be the login page (or wp-admin for logout).', 'role-gatekeeper' ),
							$role,
							$field
						)
					);
				}
				$out['rules'][ $role ][ $field ] = $ok;
			}
		}
		$order = isset( $raw['priority'] ) && is_array( $raw['priority'] ) ? $raw['priority'] : array();
		$clean = array();
		foreach ( $order as $role => $weight ) {
			$role = sanitize_key( (string) $role );
			if ( $role && get_role( $role ) ) {
				$clean[ $role ] = (int) $weight;
			}
		}
		asort( $clean, SORT_NUMERIC );
		$out['priority'] = array_keys( $clean );
		return $out;
	}

	public static function save( array $new, int $actor_id ): void {
		$before = self::get();
		update_option( self::OPTION, $new, false );
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => 'login-redirects',
				'before' => $before,
				'after'  => $new,
			)
		);
	}
}
