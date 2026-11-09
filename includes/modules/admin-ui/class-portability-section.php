<?php
namespace Rolegate\Modules\Admin_Ui;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Admin screen restrictions in a role file. Per-user rules travel by login, so a file from
 * another site only touches users with the same login there. Import goes through Rules::save
 * for every role and user, with all of its checks.
 */
final class Portability_Section {
	public static function register( $sections ) {
		$sections             = is_array( $sections ) ? $sections : array();
		$sections['admin-ui'] = array(
			'label'   => __( 'Admin screen restrictions', 'role-gatekeeper' ),
			'cap'     => Caps::MANAGE_ACCESS,
			'export'  => array( __CLASS__, 'export' ),
			'preview' => array( __CLASS__, 'preview' ),
			'import'  => array( __CLASS__, 'import' ),
		);
		return $sections;
	}

	public static function export(): array {
		$all   = Rules::all();
		$users = array();
		foreach ( $all['users'] as $uid => $rule ) {
			$user = get_userdata( (int) $uid );
			if ( $user ) {
				$users[ $user->user_login ] = $rule;
			}
		}
		return array(
			'roles' => $all['roles'],
			'users' => $users,
		);
	}

	/**
	 * @param mixed $data
	 * @return array<int,array{scope:string,target:string,label:string,rule:mixed}>|\WP_Error
	 */
	private static function entries( $data ) {
		if ( ! is_array( $data ) || ( isset( $data['roles'] ) && ! is_array( $data['roles'] ) ) || ( isset( $data['users'] ) && ! is_array( $data['users'] ) ) ) {
			return new \WP_Error( 'rolegate_bad_section', __( 'The admin restrictions section is not in the expected format.', 'role-gatekeeper' ) );
		}
		$out = array();
		foreach ( (array) ( $data['roles'] ?? array() ) as $role => $rule ) {
			$out[] = array(
				'scope'  => 'role',
				'target' => sanitize_key( (string) $role ),
				'label'  => sanitize_key( (string) $role ),
				'rule'   => $rule,
			);
		}
		foreach ( (array) ( $data['users'] ?? array() ) as $login => $rule ) {
			$user  = get_user_by( 'login', (string) $login );
			$out[] = array(
				'scope'  => 'user',
				'target' => $user ? (string) $user->ID : '',
				'label'  => sanitize_user( (string) $login, true ),
				'rule'   => $rule,
			);
		}
		return $out;
	}

	/** @return string[]|\WP_Error */
	public static function preview( $data ) {
		$entries = self::entries( $data );
		if ( is_wp_error( $entries ) ) {
			return $entries;
		}
		$lines = array();
		foreach ( $entries as $entry ) {
			if ( '' === $entry['target'] ) {
				/* translators: %s: user login */
				$lines[] = sprintf( __( 'User %s: no user with that login here, skipped.', 'role-gatekeeper' ), $entry['label'] );
				continue;
			}
			$ok = Rules::validate( Rules::sanitize( $entry['rule'] ) );
			if ( is_wp_error( $ok ) ) {
				return $ok;
			}
			$lines[] = 'role' === $entry['scope']
				/* translators: %s: role slug */
				? sprintf( __( 'Restrictions for role %s', 'role-gatekeeper' ), $entry['label'] )
				/* translators: %s: user login */
				: sprintf( __( 'Restrictions for user %s', 'role-gatekeeper' ), $entry['label'] );
		}
		return $lines;
	}

	/** @return array|\WP_Error the previous rules */
	public static function import( $data, int $actor ) {
		$entries = self::entries( $data );
		if ( is_wp_error( $entries ) ) {
			return $entries;
		}
		$before = Rules::all();
		foreach ( $entries as $entry ) {
			if ( '' === $entry['target'] ) {
				continue;
			}
			$ok = Rules::save( $actor, $entry['scope'], $entry['target'], $entry['rule'] );
			if ( is_wp_error( $ok ) ) {
				update_option( Rules::OPTION, $before, true );
				Rules::flush_cache();
				return $ok;
			}
		}
		return $before;
	}
}
