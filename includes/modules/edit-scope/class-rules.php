<?php
namespace Rolegate\Modules\Edit_Scope;

use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Storage and validation of edit-scope rules.
 *
 * A rule: id, subject_type (role|user), subject (role slug or user id as string),
 * mode (allow|block), by (post|author|term|assign|gf_form), ids (int[]),
 * children (bool, term and assign only), taxonomy (assign only).
 */
final class Rules {
	const OPTION   = 'rolegate_edit_scope_rules';
	const SETTINGS = 'rolegate_edit_scope_settings';
	const MAX_IDS  = 500;

	/** @var array<int,array> */
	private static $user_cache = array();

	public static function flush(): void {
		self::$user_cache = array();
		Evaluator::reset();
	}

	/** @return array<string,array> */
	public static function all(): array {
		$rules = get_option( self::OPTION, array() );
		return is_array( $rules ) ? $rules : array();
	}

	public static function get( string $id ): ?array {
		$all = self::all();
		return isset( $all[ $id ] ) ? $all[ $id ] : null;
	}

	/** @return array<int,array> */
	public static function for_user( int $user_id ): array {
		if ( isset( self::$user_cache[ $user_id ] ) ) {
			return self::$user_cache[ $user_id ];
		}
		$user  = $user_id > 0 ? get_userdata( $user_id ) : false;
		$roles = $user ? (array) $user->roles : array();
		$out   = array();
		foreach ( self::all() as $rule ) {
			if ( 'user' === $rule['subject_type'] && (int) $rule['subject'] === $user_id ) {
				$out[] = $rule;
			} elseif ( 'role' === $rule['subject_type'] && in_array( $rule['subject'], $roles, true ) ) {
				$out[] = $rule;
			}
		}
		self::$user_cache[ $user_id ] = $out;
		return $out;
	}

	public static function hide_in_lists(): bool {
		$s = get_option( self::SETTINGS, array() );
		return ! is_array( $s ) || ! array_key_exists( 'hide_in_lists', $s ) || ! empty( $s['hide_in_lists'] );
	}

	/** @return true|\WP_Error */
	public static function save_settings( int $actor, bool $hide ) {
		if ( ! user_can( $actor, Caps::MANAGE_ACCESS ) ) {
			return new \WP_Error( 'rolegate_forbidden', __( 'You do not have permission to change access rules.', 'role-gatekeeper' ) );
		}
		$before = array( 'hide_in_lists' => self::hide_in_lists() );
		update_option( self::SETTINGS, array( 'hide_in_lists' => $hide ), false );
		self::fire( $actor, 'edit-scope:settings', $before, array( 'hide_in_lists' => $hide ) );
		return true;
	}

	/** @return array|\WP_Error */
	public static function add( int $actor, array $raw ) {
		$rule = self::validate( $actor, $raw );
		if ( is_wp_error( $rule ) ) {
			return $rule;
		}
		$all = self::all();
		do {
			$id = strtolower( wp_generate_password( 8, false, false ) );
		} while ( isset( $all[ $id ] ) );
		$rule['id'] = $id;
		$all[ $id ] = $rule;
		update_option( self::OPTION, $all, false );
		self::flush();
		self::fire( $actor, $id, array(), $rule );
		return $rule;
	}

	/** @return array|\WP_Error */
	public static function update( int $actor, string $id, array $raw ) {
		$old = self::get( $id );
		if ( ! $old ) {
			return new \WP_Error( 'rolegate_no_rule', __( 'That rule does not exist.', 'role-gatekeeper' ) );
		}
		$check = self::can_touch( $actor, $old );
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$rule = self::validate( $actor, $raw );
		if ( is_wp_error( $rule ) ) {
			return $rule;
		}
		$rule['id'] = $id;
		$all        = self::all();
		$all[ $id ] = $rule;
		update_option( self::OPTION, $all, false );
		self::flush();
		self::fire( $actor, $id, $old, $rule );
		return $rule;
	}

	/** @return true|\WP_Error */
	public static function delete( int $actor, string $id ) {
		if ( ! user_can( $actor, Caps::MANAGE_ACCESS ) ) {
			return new \WP_Error( 'rolegate_forbidden', __( 'You do not have permission to change access rules.', 'role-gatekeeper' ) );
		}
		$old = self::get( $id );
		if ( ! $old ) {
			return new \WP_Error( 'rolegate_no_rule', __( 'That rule does not exist.', 'role-gatekeeper' ) );
		}
		$check = self::can_touch( $actor, $old );
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$all = self::all();
		unset( $all[ $id ] );
		update_option( self::OPTION, $all, false );
		self::flush();
		self::fire( $actor, $id, $old, array() );
		return true;
	}

	/**
	 * The stored rule's subject must be within the actor's reach, so a rule on someone
	 * above the actor can't be loosened or removed by them.
	 *
	 * @return true|\WP_Error
	 */
	private static function can_touch( int $actor, array $rule ) {
		$subject = isset( $rule['subject'] ) ? (string) $rule['subject'] : '';
		if ( isset( $rule['subject_type'] ) && 'user' === $rule['subject_type'] ) {
			if ( ! Guard::can_act_on_user( $actor, (int) $subject ) ) {
				return new \WP_Error( 'rolegate_user_above_actor', __( 'You cannot change rules for a user with more access than you.', 'role-gatekeeper' ) );
			}
		} elseif ( ! self::role_within_reach( $actor, $subject ) ) {
			return new \WP_Error( 'rolegate_role_above_actor', __( 'You cannot change rules for a role with more access than you.', 'role-gatekeeper' ) );
		}
		return true;
	}

	/** A deleted role is within reach; one holding a critical cap the actor lacks is not. */
	private static function role_within_reach( int $actor, string $role ): bool {
		if ( Guard::is_super( $actor ) ) {
			return true;
		}
		$obj = get_role( $role );
		if ( ! $obj ) {
			return true;
		}
		return ! Guard::missing( Guard::critical_subset( (array) $obj->capabilities ), Guard::user_caps( $actor ) );
	}

	/** @return string[] */
	public static function allowed_kinds(): array {
		$kinds = array( 'post', 'author', 'term', 'assign' );
		if ( Gravity_Forms::available() ) {
			$kinds[] = 'gf_form';
		}
		return $kinds;
	}

	/** @return array|\WP_Error */
	private static function validate( int $actor, array $raw ) {
		if ( ! user_can( $actor, Caps::MANAGE_ACCESS ) ) {
			return new \WP_Error( 'rolegate_forbidden', __( 'You do not have permission to change access rules.', 'role-gatekeeper' ) );
		}
		$type = isset( $raw['subject_type'] ) ? (string) $raw['subject_type'] : '';
		$mode = isset( $raw['mode'] ) ? (string) $raw['mode'] : '';
		$by   = isset( $raw['by'] ) ? (string) $raw['by'] : '';
		if ( ! in_array( $type, array( 'role', 'user' ), true ) ) {
			return new \WP_Error( 'rolegate_bad_subject', __( 'Choose a role or a user.', 'role-gatekeeper' ) );
		}
		if ( ! in_array( $mode, array( 'allow', 'block' ), true ) ) {
			return new \WP_Error( 'rolegate_bad_mode', __( 'Choose allow or block.', 'role-gatekeeper' ) );
		}
		if ( ! in_array( $by, self::allowed_kinds(), true ) ) {
			return new \WP_Error( 'rolegate_bad_kind', __( 'Unknown rule type.', 'role-gatekeeper' ) );
		}

		if ( 'role' === $type ) {
			$subject = sanitize_key( isset( $raw['subject'] ) ? (string) $raw['subject'] : '' );
			$role    = get_role( $subject );
			if ( ! $role ) {
				return new \WP_Error( 'rolegate_bad_subject', __( 'That role does not exist.', 'role-gatekeeper' ) );
			}
			if ( $role->has_cap( Caps::MANAGE_ACCESS ) ) {
				return new \WP_Error( 'rolegate_edit_scope_exempt', __( 'Roles that can manage access rules are exempt from edit scope.', 'role-gatekeeper' ) );
			}
			if ( ! self::role_within_reach( $actor, $subject ) ) {
				return new \WP_Error( 'rolegate_role_above_actor', __( 'You cannot change rules for a role with more access than you.', 'role-gatekeeper' ) );
			}
		} else {
			$uid  = isset( $raw['subject'] ) ? absint( $raw['subject'] ) : 0;
			$user = $uid ? get_userdata( $uid ) : false;
			if ( ! $user ) {
				return new \WP_Error( 'rolegate_bad_subject', __( 'That user does not exist.', 'role-gatekeeper' ) );
			}
			if ( $uid === $actor ) {
				return new \WP_Error( 'rolegate_edit_scope_self', __( 'You cannot restrict your own account.', 'role-gatekeeper' ) );
			}
			if ( is_super_admin( $uid ) || user_can( $uid, Caps::MANAGE_ACCESS ) ) {
				return new \WP_Error( 'rolegate_edit_scope_exempt', __( 'Users who can manage access rules are exempt from edit scope.', 'role-gatekeeper' ) );
			}
			if ( ! Guard::can_act_on_user( $actor, $uid ) ) {
				return new \WP_Error( 'rolegate_user_above_actor', __( 'You cannot change rules for a user with more access than you.', 'role-gatekeeper' ) );
			}
			$subject = (string) $uid;
		}

		$ids = array();
		foreach ( (array) ( isset( $raw['ids'] ) ? $raw['ids'] : array() ) as $v ) {
			$n = ( is_int( $v ) || ( is_string( $v ) && ctype_digit( $v ) ) ) ? (int) $v : 0;
			if ( $n > 0 ) {
				$ids[ $n ] = $n;
			}
		}
		$ids = array_values( $ids );
		if ( ! $ids ) {
			return new \WP_Error( 'rolegate_no_ids', __( 'Enter at least one ID.', 'role-gatekeeper' ) );
		}
		if ( count( $ids ) > self::MAX_IDS ) {
			return new \WP_Error( 'rolegate_too_many_ids', __( 'Too many IDs in one rule.', 'role-gatekeeper' ) );
		}

		$taxonomy = '';
		if ( 'assign' === $by ) {
			$taxonomy = sanitize_key( isset( $raw['taxonomy'] ) ? (string) $raw['taxonomy'] : '' );
			if ( ! $taxonomy || ! taxonomy_exists( $taxonomy ) ) {
				return new \WP_Error( 'rolegate_bad_taxonomy', __( 'Choose a taxonomy.', 'role-gatekeeper' ) );
			}
		}

		return array(
			'id'           => '',
			'subject_type' => $type,
			'subject'      => $subject,
			'mode'         => $mode,
			'by'           => $by,
			'ids'          => $ids,
			'children'     => in_array( $by, array( 'term', 'assign' ), true ) && ! empty( $raw['children'] ),
			'taxonomy'     => $taxonomy,
		);
	}

	private static function fire( int $actor, string $target, array $before, array $after ): void {
		do_action(
			'rolegate_changed',
			'access.updated',
			array(
				'actor'  => $actor,
				'target' => $target,
				'before' => $before,
				'after'  => $after,
			)
		);
	}
}
