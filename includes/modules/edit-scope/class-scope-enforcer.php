<?php
namespace Rolewright\Modules\Edit_Scope;

defined( 'ABSPATH' ) || exit;

final class Scope_Enforcer {
	/** @var bool */
	private $reverting = false;

	public function register(): void {
		add_filter( 'map_meta_cap', array( $this, 'map_meta_cap' ), 20, 4 );
		add_action( 'pre_get_posts', array( $this, 'pre_get_posts' ) );
		add_action( 'rest_api_init', array( $this, 'rest_api_init' ) );
		add_action( 'load-post.php', array( $this, 'gate_edit_screen' ) );
		add_action( 'admin_notices', array( $this, 'list_notice' ) );
		add_action( 'admin_bar_menu', array( $this, 'admin_bar' ), 999 );
		add_filter( 'get_terms_args', array( $this, 'filter_term_lists' ), 10, 2 );
		add_action( 'set_object_terms', array( $this, 'enforce_assignment' ), 10, 6 );
	}

	public static function blocked_message(): string {
		return (string) apply_filters(
			'rolewright_edit_scope_message',
			__( 'Your account is not allowed to edit this item. Ask a site administrator if you need access.', 'rolewright' )
		);
	}

	public function map_meta_cap( $caps, $cap, $user_id, $args ) {
		if ( in_array( $cap, array( 'edit_post', 'delete_post', 'publish_post', 'edit_page', 'delete_page' ), true ) ) {
			$post_id = 0;
			if ( isset( $args[0] ) ) {
				$post_id = $args[0] instanceof \WP_Post ? (int) $args[0]->ID : (int) $args[0];
			}
			if ( $post_id > 0 && ! Evaluator::post_allowed( (int) $user_id, $post_id ) ) {
				return array( 'do_not_allow' );
			}
		} elseif ( 'assign_term' === $cap && isset( $args[0] ) ) {
			$term = get_term( (int) $args[0] );
			if ( $term && ! is_wp_error( $term ) && ! Evaluator::term_allowed( (int) $user_id, (int) $term->term_id, $term->taxonomy ) ) {
				return array( 'do_not_allow' );
			}
		}
		return $caps;
	}

	/**
	 * @param array $args WP_Query style arguments.
	 * @return array
	 */
	public static function constrain( array $args, int $user_id ): array {
		$c = Evaluator::list_constraints( $user_id );
		if ( isset( $c['post__in'] ) ) {
			$existing         = array_map( 'intval', (array) ( isset( $args['post__in'] ) ? $args['post__in'] : array() ) );
			$merged           = $existing ? array_values( array_intersect( $existing, $c['post__in'] ) ) : $c['post__in'];
			$args['post__in'] = $merged ? $merged : array( 0 );
		}
		if ( ! empty( $c['post__not_in'] ) ) {
			$existing             = array_map( 'intval', (array) ( isset( $args['post__not_in'] ) ? $args['post__not_in'] : array() ) );
			$args['post__not_in'] = array_values( array_unique( array_merge( $existing, $c['post__not_in'] ) ) );
		}
		return $args;
	}

	public function pre_get_posts( $query ): void {
		global $pagenow;
		if ( ! is_admin() || ! $query->is_main_query() || 'edit.php' !== $pagenow || $query->get( 'rolewright_scope_skip' ) || ! Rules::hide_in_lists() ) {
			return;
		}
		$uid = get_current_user_id();
		if ( ! $uid ) {
			return;
		}
		$vars = self::constrain( $query->query_vars, $uid );
		foreach ( array( 'post__in', 'post__not_in' ) as $key ) {
			if ( isset( $vars[ $key ] ) ) {
				$query->set( $key, $vars[ $key ] );
			}
		}
	}

	public function rest_api_init(): void {
		foreach ( get_post_types( array( 'show_in_rest' => true ) ) as $type ) {
			add_filter( "rest_{$type}_query", array( $this, 'rest_query' ) );
		}
	}

	public function rest_query( $args ) {
		$uid = get_current_user_id();
		if ( ! $uid || ! Rules::hide_in_lists() ) {
			return $args;
		}
		return self::constrain( (array) $args, $uid );
	}

	public function gate_edit_screen(): void {
		// phpcs:disable WordPress.Security.NonceVerification
		$id = 0;
		if ( isset( $_POST['post_ID'] ) ) {
			$id = absint( $_POST['post_ID'] );
		} elseif ( isset( $_GET['post'] ) ) {
			$id = absint( $_GET['post'] );
		}
		// phpcs:enable
		if ( $id && ! Evaluator::post_allowed( get_current_user_id(), $id ) ) {
			wp_die( esc_html( self::blocked_message() ), esc_html__( 'Not allowed', 'rolewright' ), array( 'response' => 403, 'back_link' => true ) );
		}
	}

	public function list_notice(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'edit' !== $screen->base ) {
			return;
		}
		$uid = get_current_user_id();
		if ( Evaluator::exempt( $uid ) || ! Evaluator::rules_of( $uid, array( 'post', 'author', 'term' ) ) ) {
			return;
		}
		$text = Rules::hide_in_lists()
			? __( 'Some items are hidden because your account can only edit part of this site.', 'rolewright' )
			: __( 'Some items are read-only because your account can only edit part of this site.', 'rolewright' );
		echo '<div class="notice notice-info"><p>' . esc_html( $text ) . '</p></div>';
	}

	public function admin_bar( $bar ): void {
		if ( is_admin() || ! is_singular() ) {
			return;
		}
		$post = get_queried_object();
		if ( $post instanceof \WP_Post && ! current_user_can( 'edit_post', $post->ID ) ) {
			$bar->remove_node( 'edit' );
		}
	}

	public function filter_term_lists( $args, $taxonomies ) {
		global $pagenow;
		$uid = get_current_user_id();
		if ( ! $uid || ! empty( $args['rolewright_scope_skip'] ) ) {
			return $args;
		}
		$in_editor = is_admin() && in_array( $pagenow, array( 'post.php', 'post-new.php', 'admin-ajax.php' ), true );
		if ( ! $in_editor && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $args;
		}
		$exclude = array();
		foreach ( (array) $taxonomies as $tax ) {
			$exclude = array_merge( $exclude, Evaluator::unassignable_terms( $uid, (string) $tax ) );
		}
		if ( $exclude ) {
			$args['exclude'] = array_values( array_unique( array_merge( array_map( 'intval', (array) ( isset( $args['exclude'] ) ? $args['exclude'] : array() ) ), $exclude ) ) );
		}
		return $args;
	}

	/**
	 * Undoes any change to a restricted taxonomy that the user isn't allowed to make:
	 * disallowed terms that were added are dropped, locked terms that were removed come back.
	 */
	public function enforce_assignment( $object_id, $terms, $tt_ids, $taxonomy, $append, $old_tt_ids ): void {
		$uid = get_current_user_id();
		if ( $this->reverting || ! $uid || ! Evaluator::has_assign_rules( $uid, (string) $taxonomy ) ) {
			return;
		}
		$old = array();
		if ( $old_tt_ids ) {
			$old = get_terms(
				array(
					'taxonomy'              => $taxonomy,
					'term_taxonomy_id'      => array_map( 'intval', (array) $old_tt_ids ),
					'hide_empty'            => false,
					'fields'                => 'ids',
					'rolewright_scope_skip' => true,
				)
			);
			$old = is_wp_error( $old ) ? array() : array_map( 'intval', $old );
		}
		$now = wp_get_object_terms( $object_id, $taxonomy, array( 'fields' => 'ids' ) );
		$now = is_wp_error( $now ) ? array() : array_map( 'intval', $now );

		$final = $now;
		foreach ( array_diff( $now, $old ) as $added ) {
			if ( ! Evaluator::term_allowed( $uid, $added, (string) $taxonomy ) ) {
				$final = array_diff( $final, array( $added ) );
			}
		}
		foreach ( array_diff( $old, $now ) as $removed ) {
			if ( ! Evaluator::term_allowed( $uid, $removed, (string) $taxonomy ) ) {
				$final[] = $removed;
			}
		}
		$final = array_values( array_unique( $final ) );
		if ( array_diff( $final, $now ) || array_diff( $now, $final ) ) {
			$this->reverting = true;
			wp_set_object_terms( (int) $object_id, $final, $taxonomy, false );
			$this->reverting = false;
		}
	}
}
