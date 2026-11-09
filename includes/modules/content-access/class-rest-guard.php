<?php
namespace Rolewright\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

final class Rest_Guard {
	public function register(): void {
		add_filter( 'rest_request_before_callbacks', array( $this, 'guard_request' ), 10, 3 );
		add_filter( 'rest_comment_query', array( $this, 'exclude_comments' ) );
		add_action( 'rest_api_init', array( $this, 'hook_prepare' ), 20 );
	}

	public function hook_prepare(): void {
		foreach ( get_post_types( array( 'show_in_rest' => true ), 'names' ) as $type ) {
			add_filter( "rest_prepare_{$type}", array( $this, 'mask_response' ), 10, 2 );
		}
	}

	/**
	 * Single reads, revisions and autosaves of a protected post answer 404, so the
	 * response gives no hint that the post exists.
	 *
	 * @param mixed            $response
	 * @param array            $handler
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function guard_request( $response, $handler, $request ) {
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$route = $request->get_route();
		if ( preg_match( '#^/wp/v2/comments/(\d+)$#', $route, $m ) ) {
			$comment = get_comment( (int) $m[1] );
			if ( $comment && Access::is_denied( (int) $comment->comment_post_ID ) && Access::is_restricted( (int) $comment->comment_post_ID ) ) {
				return new \WP_Error( 'rest_comment_invalid_id', __( 'Invalid comment ID.', 'rolewright' ), array( 'status' => 404 ) );
			}
			return $response;
		}
		if ( ! preg_match( '#^/wp/v2/([^/]+)/(\d+)(?:/|$)#', $route, $m ) ) {
			return $response;
		}
		$post_id = (int) $m[2];
		foreach ( get_post_types( array( 'show_in_rest' => true ), 'objects' ) as $type ) {
			$base = $type->rest_base ? $type->rest_base : $type->name;
			if ( $base !== $m[1] ) {
				continue;
			}
			$post = get_post( $post_id );
			if ( $post && $post->post_type === $type->name && Access::is_restricted( $post_id ) && Access::is_denied( $post_id ) ) {
				return new \WP_Error( 'rest_post_invalid_id', __( 'Invalid post ID.', 'rolewright' ), array( 'status' => 404 ) );
			}
			break;
		}
		return $response;
	}

	public function exclude_comments( array $args ): array {
		$hidden = Access::hidden_ids();
		if ( $hidden ) {
			$args['post__not_in'] = array_values( array_unique( array_merge( array_map( 'intval', (array) ( $args['post__not_in'] ?? array() ) ), $hidden ) ) );
		}
		return $args;
	}

	/**
	 * Safety net for responses built outside the routes above, such as embedded links.
	 *
	 * @param \WP_REST_Response $response
	 * @param \WP_Post          $post
	 */
	public function mask_response( $response, $post ) {
		if ( ! $post instanceof \WP_Post || ! Access::is_restricted( (int) $post->ID ) || ! Access::is_denied( (int) $post->ID ) ) {
			return $response;
		}
		$data = $response->get_data();
		foreach ( array( 'title', 'content', 'excerpt' ) as $field ) {
			if ( isset( $data[ $field ] ) ) {
				$data[ $field ] = array(
					'rendered'  => '',
					'protected' => true,
				);
			}
		}
		$response->set_data( $data );
		return $response;
	}
}
