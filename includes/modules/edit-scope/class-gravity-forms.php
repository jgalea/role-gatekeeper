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
		$route = $request instanceof \WP_REST_Request ? $request->get_route() : '';
		if ( 0 !== strpos( $route, '/gf/v2/' ) ) {
			return $response;
		}
		$ids = array();
		if ( preg_match( '#^/gf/v2/forms/(\d+)#', $route, $m ) ) {
			$ids[] = (int) $m[1];
		}
		if ( preg_match( '#^/gf/v2/forms/\d+/entries#', $route ) === 0 && $request->get_param( 'form_ids' ) ) {
			$ids = array_merge( $ids, array_map( 'absint', (array) $request->get_param( 'form_ids' ) ) );
		}
		foreach ( $ids as $id ) {
			if ( ! self::form_allowed( get_current_user_id(), $id ) ) {
				return new \WP_Error( 'rolewright_edit_scope_blocked', Scope_Enforcer::blocked_message(), array( 'status' => 403 ) );
			}
		}
		return $response;
	}
}
