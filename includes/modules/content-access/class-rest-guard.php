<?php
namespace Rolewright\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

final class Rest_Guard {
	public function register(): void {
		add_filter( 'rest_request_before_callbacks', array( $this, 'guard_request' ), 10, 3 );
		add_filter( 'rest_comment_query', array( $this, 'exclude_comments' ) );
		add_filter( 'rest_post_search_query', array( $this, 'exclude_search' ) );
		add_action( 'rest_api_init', array( $this, 'hook_prepare' ), 20 );
	}

	public function hook_prepare(): void {
		foreach ( get_post_types( array( 'show_in_rest' => true ), 'names' ) as $type ) {
			add_filter( "rest_prepare_{$type}", array( $this, 'mask_response' ), 10, 2 );
		}
		add_filter( 'rest_prepare_revision', array( $this, 'mask_response' ), 10, 2 );
		add_filter( 'rest_prepare_autosave', array( $this, 'mask_response' ), 10, 2 );
	}

	private static function denied( int $post_id ): bool {
		return $post_id > 0 && Access::is_restricted( $post_id ) && Access::is_denied( $post_id );
	}

	/** Revisions and autosaves answer to their parent's rule. */
	private static function subject_id( \WP_Post $post ): int {
		if ( 'revision' === $post->post_type && $post->post_parent ) {
			return (int) $post->post_parent;
		}
		return (int) $post->ID;
	}

	/**
	 * The post a request reads or renders, taken from the matched handler and its params
	 * rather than the route text, so route case and namespace don't matter.
	 *
	 * @param array            $handler
	 * @param \WP_REST_Request $request
	 * @return int[] post ids, comment hits as negative ids
	 */
	public static function targets( $handler, $request ): array {
		$controller = isset( $handler['callback'] ) && is_array( $handler['callback'] ) && isset( $handler['callback'][0] ) && is_object( $handler['callback'][0] ) ? $handler['callback'][0] : null;
		$out        = array();
		$id         = (int) $request->get_param( 'id' );
		if ( $controller instanceof \WP_REST_Revisions_Controller || $controller instanceof \WP_REST_Autosaves_Controller ) {
			$out[] = (int) $request->get_param( 'parent' );
			if ( $id ) {
				$rev   = get_post( $id );
				$out[] = $rev instanceof \WP_Post ? self::subject_id( $rev ) : 0;
			}
		} elseif ( $controller instanceof \WP_REST_Posts_Controller ) {
			$out[] = $id;
		} elseif ( $controller instanceof \WP_REST_Comments_Controller ) {
			$comment = $id ? get_comment( $id ) : null;
			if ( $comment ) {
				$out[] = (int) $comment->comment_post_ID;
			}
			$out[] = (int) $request->get_param( 'post' );
		} elseif ( $controller instanceof \WP_REST_Block_Renderer_Controller ) {
			$out[] = (int) $request->get_param( 'post_id' );
		} elseif ( $controller instanceof \WP_oEmbed_Controller ) {
			$url = (string) $request->get_param( 'url' );
			if ( '' !== $url ) {
				$out[] = (int) url_to_postid( $url );
			}
		} else {
			$route = strtolower( (string) preg_replace( '#/+#', '/', $request->get_route() ) );
			if ( preg_match( '#^/wp/v2/([^/]+)/(\d+)(?:/|$)#', $route, $m ) ) {
				$out[] = (int) $m[2];
			}
		}
		return array_values( array_filter( array_unique( $out ) ) );
	}

	/**
	 * Reads, revisions, autosaves, renders and embeds of a protected post answer 404, so
	 * the response gives no hint that the post exists.
	 *
	 * @param mixed            $response
	 * @param array            $handler
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function guard_request( $response, $handler, $request ) {
		if ( is_wp_error( $response ) || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}
		foreach ( self::targets( $handler, $request ) as $post_id ) {
			if ( self::denied( $post_id ) ) {
				return new \WP_Error( 'rest_post_invalid_id', __( 'Invalid post ID.', 'rolewright' ), array( 'status' => 404 ) );
			}
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

	public function exclude_search( $args ) {
		$hidden = Access::hidden_ids();
		if ( $hidden && is_array( $args ) ) {
			$args['post__not_in'] = array_values( array_unique( array_merge( array_map( 'intval', (array) ( $args['post__not_in'] ?? array() ) ), $hidden ) ) );
			if ( ! empty( $args['post__in'] ) ) {
				$args['post__in'] = Query_Guard::without_hidden( (array) $args['post__in'], $hidden );
			}
		}
		return $args;
	}

	/**
	 * Safety net for responses built outside the routes above, such as embedded links:
	 * a denied post keeps only its id, with no fields and no links.
	 *
	 * @param \WP_REST_Response $response
	 * @param \WP_Post          $post
	 */
	public function mask_response( $response, $post ) {
		if ( ! $post instanceof \WP_Post || ! $response instanceof \WP_REST_Response || ! self::denied( self::subject_id( $post ) ) ) {
			return $response;
		}
		foreach ( array_keys( $response->get_links() ) as $rel ) {
			$response->remove_link( $rel );
		}
		$response->set_data( array( 'id' => (int) $post->ID ) );
		return $response;
	}
}
