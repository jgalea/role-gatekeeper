<?php
namespace Rolewright\Modules\Admin_Ui;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;
use WP_Error;

defined( 'ABSPATH' ) || exit;

final class Rules {
	const OPTION = 'rolewright_admin_ui_rules';

	/** @var array<string,?array> */
	private static $cache = array();

	public static function all(): array {
		$all = get_option( self::OPTION, array() );
		$all = is_array( $all ) ? $all : array();
		return array(
			'roles' => isset( $all['roles'] ) && is_array( $all['roles'] ) ? $all['roles'] : array(),
			'users' => isset( $all['users'] ) && is_array( $all['users'] ) ? $all['users'] : array(),
		);
	}

	public static function get( string $scope, string $target ): array {
		$all = self::all();
		$key = 'user' === $scope ? 'users' : 'roles';
		return isset( $all[ $key ][ $target ] ) && is_array( $all[ $key ][ $target ] ) ? array_replace_recursive( Engine::empty_rule(), $all[ $key ][ $target ] ) : Engine::empty_rule();
	}

	public static function flush_cache(): void {
		self::$cache = array();
	}

	/** Merged restrictions for a user, or null when none apply (no rules, administrators, super admins). */
	public static function effective_for_user( int $user_id ): ?array {
		$user = $user_id ? get_userdata( $user_id ) : false;
		if ( ! $user || is_super_admin( $user_id ) || in_array( 'administrator', (array) $user->roles, true ) ) {
			return null;
		}
		$ck = $user_id . ':' . implode( ',', (array) $user->roles );
		if ( ! array_key_exists( $ck, self::$cache ) ) {
			self::$cache[ $ck ] = self::effective_from( self::all(), $user );
		}
		return self::$cache[ $ck ];
	}

	public static function effective_from( array $all, \WP_User $user ): ?array {
		$rules = array();
		foreach ( (array) $user->roles as $role ) {
			if ( isset( $all['roles'][ $role ] ) && is_array( $all['roles'][ $role ] ) ) {
				$rules[] = $all['roles'][ $role ];
			}
		}
		if ( isset( $all['users'][ $user->ID ] ) && is_array( $all['users'][ $user->ID ] ) ) {
			$rules[] = $all['users'][ $user->ID ];
		}
		return $rules ? Engine::merge( $rules ) : null;
	}

	private static function slug_list( $raw, string $pattern ): array {
		$out = array();
		foreach ( (array) $raw as $item ) {
			if ( ! is_scalar( $item ) ) {
				continue;
			}
			$item = trim( (string) $item );
			if ( '' !== $item && strlen( $item ) <= 200 && preg_match( $pattern, $item ) ) {
				$out[] = $item;
			}
		}
		return array_values( array_unique( $out ) );
	}

	private static function plugin_list( $raw, string $own ): array {
		$list = self::slug_list( $raw, '/^[A-Za-z0-9_\-\.\/]+\.php$/' );
		$list = array_filter(
			$list,
			function ( $p ) use ( $own ) {
				return $p !== $own && false === strpos( $p, '..' );
			}
		);
		return array_values( $list );
	}

	public static function sanitize( $raw ): array {
		$raw  = is_array( $raw ) ? $raw : array();
		$rule = Engine::empty_rule();

		$menu                  = isset( $raw['menu'] ) && is_array( $raw['menu'] ) ? $raw['menu'] : array();
		$rule['menu']['model'] = isset( $menu['model'] ) && 'allow' === $menu['model'] ? 'allow' : 'deny';
		$rule['menu']['items'] = self::slug_list( $menu['items'] ?? array(), '/^[A-Za-z0-9_\-\.\/\?=&%|:]+$/' );

		$rule['blocks'] = array_values( array_intersect( array_keys( Engine::block_defs() ), array_map( 'strval', (array) ( $raw['blocks'] ?? array() ) ) ) );

		foreach ( (array) ( $raw['metaboxes'] ?? array() ) as $type => $ids ) {
			$type = sanitize_key( (string) $type );
			$ids  = self::slug_list( $ids, '/^[A-Za-z0-9_\-]+$/' );
			if ( '' !== $type && $ids ) {
				$rule['metaboxes'][ $type ] = $ids;
			}
		}
		ksort( $rule['metaboxes'] );

		$plugins                   = isset( $raw['plugins'] ) && is_array( $raw['plugins'] ) ? $raw['plugins'] : array();
		$own                       = plugin_basename( ROLEWRIGHT_FILE );
		$rule['plugins']['model']  = isset( $plugins['model'] ) && 'allow' === $plugins['model'] ? 'allow' : 'deny';
		$rule['plugins']['locked'] = self::plugin_list( $plugins['locked'] ?? array(), $own );
		$rule['plugins']['hidden'] = self::plugin_list( $plugins['hidden'] ?? array(), $own );

		$rule['themes_locked'] = ! empty( $raw['themes_locked'] );
		$rule['admin_bar']     = self::slug_list( $raw['admin_bar'] ?? array(), '/^[A-Za-z0-9_\-]+$/' );
		return $rule;
	}

	/** Items no rule may block. Returns a WP_Error naming them. */
	public static function validate( array $rule ) {
		$bad = array();
		if ( 'deny' === $rule['menu']['model'] ) {
			foreach ( $rule['menu']['items'] as $key ) {
				if ( Engine::is_exempt_key( $key, false ) ) {
					$bad[] = $key;
				}
			}
		}
		foreach ( $rule['admin_bar'] as $node ) {
			if ( in_array( $node, Engine::protected_bar_nodes(), true ) ) {
				$bad[] = $node;
			}
		}
		if ( $bad ) {
			return new WP_Error( 'rolewright_exempt_item', sprintf( /* translators: %s: item names */ __( 'These items can never be blocked: %s. Everyone keeps their profile page.', 'rolewright' ), implode( ', ', $bad ) ) );
		}
		return true;
	}

	/**
	 * Check that the proposed rule set leaves the actor able to reach Rolewright and their profile.
	 *
	 * @return string[] Reason codes; empty when safe.
	 */
	public static function lockout_reasons( int $actor_id, array $all_after ): array {
		$actor = get_userdata( $actor_id );
		if ( ! $actor || is_super_admin( $actor_id ) || in_array( 'administrator', (array) $actor->roles, true ) ) {
			return array();
		}
		$eff = self::effective_from( $all_after, $actor );
		if ( null === $eff ) {
			return array();
		}
		$can_manage = user_can( $actor_id, Caps::MANAGE );
		$reasons    = array();
		$must       = array(
			array( 'rolewright', null ),
			array( 'rolewright|rolewright-admin-ui', 'rolewright' ),
			array( 'profile.php', null ),
		);
		foreach ( $must as $pair ) {
			if ( Engine::key_blocked( $pair[0], $pair[1], $eff, $can_manage ) ) {
				$reasons[] = 'blocks_' . str_replace( array( '|', '.' ), '_', $pair[0] );
			}
		}
		if ( null !== $eff['menu_allow'] ) {
			$real = array_filter(
				$eff['menu_allow'],
				function ( $k ) use ( $can_manage ) {
					return ! Engine::is_exempt_key( $k, $can_manage );
				}
			);
			if ( ! $real ) {
				$reasons[] = 'empty_allow_list';
			}
		}
		if ( in_array( 'profile.php', Engine::blocked_pages( $eff ), true ) ) {
			$reasons[] = 'blocks_profile_php';
		}
		return array_values( array_unique( $reasons ) );
	}

	/**
	 * Store the rule for a role or user.
	 *
	 * @param string $scope  'role' or 'user'.
	 * @param string $target Role slug or user id.
	 * @param mixed  $raw    Unsanitized rule.
	 */
	public static function save( int $actor_id, string $scope, string $target, $raw ) {
		if ( ! user_can( $actor_id, Caps::MANAGE_ACCESS ) ) {
			return new WP_Error( 'rolewright_forbidden', __( 'You do not have permission to change access rules.', 'rolewright' ) );
		}
		if ( 'role' === $scope ) {
			$target = sanitize_key( $target );
			if ( 'administrator' === $target ) {
				return new WP_Error( 'rolewright_protected_role', __( 'The Administrator role cannot be restricted.', 'rolewright' ) );
			}
			if ( ! get_role( $target ) ) {
				return new WP_Error( 'rolewright_no_role', __( 'That role does not exist.', 'rolewright' ) );
			}
		} elseif ( 'user' === $scope ) {
			$uid  = absint( $target );
			$user = $uid ? get_userdata( $uid ) : false;
			if ( ! $user ) {
				return new WP_Error( 'rolewright_no_user', __( 'That user does not exist.', 'rolewright' ) );
			}
			if ( is_super_admin( $uid ) || in_array( 'administrator', (array) $user->roles, true ) ) {
				return new WP_Error( 'rolewright_protected_user', __( 'Administrators cannot be restricted.', 'rolewright' ) );
			}
			if ( $uid !== $actor_id && ! Guard::can_act_on_user( $actor_id, $uid ) ) {
				return new WP_Error( 'rolewright_user_above_actor', __( 'You cannot change a user who holds capabilities you lack.', 'rolewright' ) );
			}
			$target = (string) $uid;
		} else {
			return new WP_Error( 'rolewright_bad_scope', __( 'Unknown target type.', 'rolewright' ) );
		}

		$rule = self::sanitize( $raw );
		$ok   = self::validate( $rule );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}

		$all    = self::all();
		$bucket = 'role' === $scope ? 'roles' : 'users';
		$before = isset( $all[ $bucket ][ $target ] ) ? array_replace_recursive( Engine::empty_rule(), (array) $all[ $bucket ][ $target ] ) : array();
		$after  = $all;
		if ( Engine::is_empty( $rule ) ) {
			unset( $after[ $bucket ][ $target ] );
			$rule_after = array();
		} else {
			$after[ $bucket ][ $target ] = $rule;
			$rule_after                  = $rule;
		}

		$reasons = self::lockout_reasons( $actor_id, $after );
		if ( $reasons ) {
			return new WP_Error(
				'rolewright_lockout',
				__( 'This change would leave you without access to Rolewright or your profile, so it was not saved.', 'rolewright' ),
				array( 'reasons' => $reasons )
			);
		}

		if ( $before === $rule_after ) {
			return true;
		}
		update_option( self::OPTION, $after, true );
		self::flush_cache();
		do_action(
			'rolewright_changed',
			'access.updated',
			array(
				'actor'  => $actor_id,
				'target' => 'role' === $scope ? $target : (int) $target,
				'scope'  => $scope,
				'module' => 'admin-ui',
				'before' => $before,
				'after'  => $rule_after,
			)
		);
		return true;
	}
}
