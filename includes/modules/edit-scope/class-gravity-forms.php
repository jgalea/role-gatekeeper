<?php
namespace Rolewright\Modules\Edit_Scope;

defined( 'ABSPATH' ) || exit;

/**
 * Form access rules (by = gf_form). Loaded only when Gravity Forms is active.
 */
final class Gravity_Forms {
	public static function available(): bool {
		return class_exists( 'GFForms' );
	}

	public function register(): void {
		add_action( 'admin_init', array( $this, 'gate_admin_page' ) );
		add_filter( 'rest_request_before_callbacks', array( $this, 'gate_rest' ), 10, 3 );
	}

	public static function form_allowed( int $user_id, int $form_id ): bool {
		if ( $form_id <= 0 || Evaluator::exempt( $user_id ) ) {
			return true;
		}
		$has_allow = false;
		$hit_allow = false;
		foreach ( Evaluator::rules_of( $user_id, array( 'gf_form' ) ) as $rule ) {
			$hit = in_array( $form_id, $rule['ids'], true );
			if ( 'block' === $rule['mode'] ) {
				if ( $hit ) {
					return false;
				}
			} else {
				$has_allow = true;
				$hit_allow = $hit_allow || $hit;
			}
		}
		return ! $has_allow || $hit_allow;
	}

	public function gate_admin_page(): void {
		// phpcs:disable WordPress.Security.NonceVerification
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( ! in_array( $page, array( 'gf_edit_forms', 'gf_entries' ), true ) ) {
			return;
		}
		$form_id = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : 0;
		// phpcs:enable
		if ( ! self::form_allowed( get_current_user_id(), $form_id ) ) {
			wp_die( esc_html( Scope_Enforcer::blocked_message() ), esc_html__( 'Not allowed', 'rolewright' ), array( 'response' => 403, 'back_link' => true ) );
		}
	}

	public function gate_rest( $response, $handler, $request ) {
		if ( is_wp_error( $response ) || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}
		$verdict = self::rest_verdict( get_current_user_id(), $request->get_route(), $request->get_params() );
		if ( false === $verdict['allowed'] ) {
			return new \WP_Error( 'rolewright_edit_scope_blocked', Scope_Enforcer::blocked_message(), array( 'status' => 403 ) );
		}
		foreach ( $verdict['set'] as $key => $value ) {
			$request->set_param( $key, $value );
		}
		return $response;
	}

	/**
	 * WordPress matches routes case-insensitively, so compare a lowercased route with
	 * repeated slashes collapsed and no trailing slash.
	 */
	public static function normalize_route( string $route ): string {
		$route = strtolower( trim( rawurldecode( $route ) ) );
		$route = (string) preg_replace( '#/+#', '/', $route );
		$route = '/' . trim( $route, '/' );
		return $route;
	}

	public static function has_rules( int $user_id ): bool {
		return ! Evaluator::exempt( $user_id ) && (bool) Evaluator::rules_of( $user_id, array( 'gf_form' ) );
	}

	/**
	 * Form IDs the user's allow rules name, minus blocked ones. Null when the user has
	 * only block rules, so no finite list describes what they may see.
	 *
	 * @return int[]|null
	 */
	public static function allowed_form_ids( int $user_id ): ?array {
		$allow = null;
		$block = array();
		foreach ( Evaluator::rules_of( $user_id, array( 'gf_form' ) ) as $rule ) {
			if ( 'block' === $rule['mode'] ) {
				$block = array_merge( $block, $rule['ids'] );
			} else {
				$allow = array_merge( (array) $allow, $rule['ids'] );
			}
		}
		if ( null === $allow ) {
			return null;
		}
		return array_values( array_diff( array_unique( array_map( 'intval', $allow ) ), array_map( 'intval', $block ) ) );
	}

	/** @return int|null Form ID of an entry, null when it can't be resolved. */
	public static function entry_form_id( int $entry_id ): ?int {
		if ( $entry_id <= 0 || ! class_exists( 'GFAPI' ) || ! is_callable( array( 'GFAPI', 'get_entry' ) ) ) {
			return null;
		}
		$entry = \GFAPI::get_entry( $entry_id );
		if ( ! is_array( $entry ) || empty( $entry['form_id'] ) ) {
			return null;
		}
		return (int) $entry['form_id'];
	}

	/**
	 * Decides a Gravity Forms REST request for the user. 'set' holds params to narrow a
	 * list request to the forms the user may see.
	 *
	 * @return array{allowed:bool,set:array<string,int[]>}
	 */
	public static function rest_verdict( int $user_id, string $route, array $params ): array {
		$ok    = array(
			'allowed' => true,
			'set'     => array(),
		);
		$deny  = array(
			'allowed' => false,
			'set'     => array(),
		);
		$route = self::normalize_route( $route );
		if ( ! preg_match( '#^/gf(?:/|$)#i', $route ) || ! self::has_rules( $user_id ) ) {
			return $ok;
		}
		$check = function ( array $ids ) use ( $user_id ) {
			foreach ( $ids as $id ) {
				if ( (int) $id <= 0 || ! self::form_allowed( $user_id, (int) $id ) ) {
					return false;
				}
			}
			return true;
		};

		if ( preg_match( '#^/gf/v2/forms/([0-9;,]+)(?:/|$)#i', $route, $m ) ) {
			$ids = array_filter( array_map( 'intval', preg_split( '#[;,]#', $m[1] ) ) );
			return $ids && $check( $ids ) ? $ok : $deny;
		}
		if ( preg_match( '#^/gf/v2/entries/(\d+)(?:/|$)#i', $route, $m ) ) {
			$form = self::entry_form_id( (int) $m[1] );
			return null !== $form && $check( array( $form ) ) ? $ok : $deny;
		}
		$list_param = null;
		if ( preg_match( '#^/gf/v2/forms$#i', $route ) ) {
			$list_param = 'include';
		} elseif ( preg_match( '#^/gf/v2/entries$#i', $route ) ) {
			$list_param = 'form_ids';
		}
		if ( null === $list_param ) {
			return $deny;
		}
		$given = isset( $params[ $list_param ] ) ? wp_parse_id_list( $params[ $list_param ] ) : array();
		if ( $given ) {
			return $check( $given ) ? $ok : $deny;
		}
		$allowed = self::allowed_form_ids( $user_id );
		if ( ! $allowed ) {
			return $deny;
		}
		$ok['set'][ $list_param ] = $allowed;
		return $ok;
	}
}
