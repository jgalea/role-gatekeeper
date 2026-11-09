<?php
namespace Rolewright\Modules\Audit;

use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Who holds a capability right now, and where it comes from.
 */
final class Permissions {
	const USER_LIMIT = 200;

	/** @return string[] Every capability named by any role, sorted. */
	public static function known_caps(): array {
		$caps = array();
		foreach ( wp_roles()->roles as $data ) {
			foreach ( array_keys( (array) $data['capabilities'] ) as $cap ) {
				$caps[ (string) $cap ] = true;
			}
		}
		$caps = array_keys( $caps );
		sort( $caps );
		return $caps;
	}

	/**
	 * @return array{
	 *   roles: array<int,array{slug:string,name:string,state:string}>,
	 *   users: array<int,array{id:int,login:string,name:string,sources:string[],effective:bool}>,
	 *   truncated: bool
	 * }
	 */
	public static function holders( string $cap ): array {
		global $wpdb;
		$out = array(
			'roles'     => array(),
			'users'     => array(),
			'truncated' => false,
		);
		if ( '' === $cap ) {
			return $out;
		}

		$holding_roles = array();
		foreach ( wp_roles()->roles as $slug => $data ) {
			$caps = (array) $data['capabilities'];
			if ( ! array_key_exists( $cap, $caps ) ) {
				continue;
			}
			$out['roles'][] = array(
				'slug'  => (string) $slug,
				'name'  => translate_user_role( (string) $data['name'] ),
				'state' => $caps[ $cap ] ? 'granted' : 'denied',
			);
			if ( $caps[ $cap ] ) {
				$holding_roles[] = (string) $slug;
			}
		}

		$ids = array();
		if ( $holding_roles ) {
			$ids = array_merge(
				$ids,
				get_users(
					array(
						'role__in' => $holding_roles,
						'fields'   => 'ID',
						'number'   => self::USER_LIMIT + 1,
					)
				)
			);
		}
		$ids = array_merge(
			$ids,
			get_users(
				array(
					'fields'     => 'ID',
					'number'     => self::USER_LIMIT + 1,
					'meta_query' => array( // phpcs:ignore WordPress.DB.SlowDBQuery
						array(
							'key'     => $wpdb->get_blog_prefix() . 'capabilities',
							'value'   => '"' . $cap . '";b:1',
							'compare' => 'LIKE',
						),
					),
				)
			)
		);
		$ids = array_values( array_unique( array_map( 'intval', $ids ) ) );
		if ( count( $ids ) > self::USER_LIMIT ) {
			$out['truncated'] = true;
			$ids              = array_slice( $ids, 0, self::USER_LIMIT );
		}

		foreach ( $ids as $id ) {
			$user = get_userdata( $id );
			if ( ! $user ) {
				continue;
			}
			$sources = array();
			foreach ( (array) $user->roles as $role ) {
				if ( in_array( $role, $holding_roles, true ) ) {
					$sources[] = 'role:' . $role;
				}
			}
			if ( ! empty( $user->caps[ $cap ] ) ) {
				$sources[] = 'user';
			}
			if ( ! $sources ) {
				continue;
			}
			$held             = Guard::user_caps( $id );
			$out['users'][] = array(
				'id'        => $id,
				'login'     => (string) $user->user_login,
				'name'      => (string) $user->display_name,
				'sources'   => $sources,
				'effective' => ! empty( $held[ $cap ] ) || Guard::is_super( $id ),
			);
		}
		return $out;
	}
}
