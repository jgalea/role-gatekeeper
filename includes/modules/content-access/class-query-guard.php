<?php
namespace Rolewright\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

final class Query_Guard {
	public function register(): void {
		add_action( 'pre_get_posts', array( $this, 'exclude_hidden' ), 99 );
		add_action( 'pre_get_comments', array( $this, 'exclude_hidden_comments' ), 99 );
		add_filter( 'the_posts', array( $this, 'mask_singular' ), 10, 2 );
		add_action( 'template_redirect', array( $this, 'enforce_single' ), 0 );
		add_filter( 'the_content', array( $this, 'guard_content' ), 1 );
		add_filter( 'get_the_excerpt', array( $this, 'guard_excerpt' ), 999, 2 );
		add_filter( 'single_post_title', array( $this, 'guard_title' ), 10, 2 );
		add_filter( 'post_thumbnail_id', array( $this, 'guard_thumbnail' ), 10, 2 );
		add_filter( 'comments_array', array( $this, 'guard_comments' ), 10, 2 );
		add_filter( 'comments_open', array( $this, 'guard_comments_open' ), 10, 2 );
		add_filter( 'get_comments_number', array( $this, 'guard_comments_number' ), 10, 2 );
		add_filter( 'get_previous_post_where', array( $this, 'adjacent_where' ) );
		add_filter( 'get_next_post_where', array( $this, 'adjacent_where' ) );
		add_filter( 'wp_sitemaps_posts_query_args', array( $this, 'sitemap_args' ) );
		add_filter( 'get_pages', array( $this, 'filter_pages' ) );
	}

	private function applies_to_query(): bool {
		return ! is_admin() || wp_doing_ajax();
	}

	public function exclude_hidden( \WP_Query $query ): void {
		if ( ! $this->applies_to_query() ) {
			return;
		}
		if ( $query->is_main_query() && $query->is_singular() ) {
			return;
		}
		if ( ! apply_filters( 'rolewright_exclude_hidden_posts', true, $query ) ) {
			return;
		}
		$hidden = Access::hidden_ids();
		if ( $hidden ) {
			$query->set( 'post__not_in', array_values( array_unique( array_merge( array_map( 'intval', (array) $query->get( 'post__not_in' ) ), $hidden ) ) ) );
		}
	}

	public function exclude_hidden_comments( \WP_Comment_Query $query ): void {
		if ( ! $this->applies_to_query() ) {
			return;
		}
		$hidden = Access::hidden_ids();
		if ( $hidden ) {
			$existing                              = (array) ( $query->query_vars['post__not_in'] ?? array() );
			$query->query_vars['post__not_in'] = array_values( array_unique( array_merge( array_map( 'intval', $existing ), $hidden ) ) );
		}
	}

	/**
	 * Swaps a denied post for a clone that carries only the notice, so nothing downstream
	 * (templates, SEO and schema output) can read the real title, content or excerpt.
	 *
	 * @param \WP_Post[] $posts
	 * @return \WP_Post[]
	 */
	public function mask_singular( $posts, \WP_Query $query ) {
		if ( is_admin() || ! $query->is_main_query() || ! $query->is_singular() || empty( $posts ) ) {
			return $posts;
		}
		foreach ( $posts as $i => $post ) {
			if ( ! $post instanceof \WP_Post || ! Access::is_denied( (int) $post->ID ) ) {
				continue;
			}
			$mask                 = clone $post;
			$mask->post_title     = __( 'Restricted content', 'rolewright' );
			$mask->post_content   = Access::notice_html( (int) $post->ID );
			$mask->post_excerpt   = '';
			$mask->comment_status = 'closed';
			$mask->comment_count  = 0;
			if ( 'attachment' === $mask->post_type ) {
				$mask->post_type = 'page';
			}
			$posts[ $i ] = $mask;
		}
		return $posts;
	}

	public function enforce_single(): void {
		if ( ! is_singular() ) {
			return;
		}
		$post = get_queried_object();
		if ( ! $post instanceof \WP_Post || ! Access::is_restricted( (int) $post->ID ) ) {
			return;
		}
		Access::mark_uncacheable();
		if ( ! Access::is_denied( (int) $post->ID ) ) {
			return;
		}
		if ( is_feed() || is_embed() || is_attachment() ) {
			global $wp_query;
			$wp_query->set_404();
			status_header( 404 );
			return;
		}
		status_header( 403 );
	}

	public function guard_content( $content ) {
		$id = (int) get_the_ID();
		if ( $id && Access::is_restricted( $id ) && Access::is_denied( $id ) ) {
			return Access::notice_html( $id );
		}
		return $content;
	}

	public function guard_excerpt( $excerpt, $post = null ) {
		$post = get_post( $post );
		if ( $post && Access::is_restricted( (int) $post->ID ) && Access::is_denied( (int) $post->ID ) ) {
			return '';
		}
		return $excerpt;
	}

	public function guard_title( $title, $post = null ) {
		if ( $post instanceof \WP_Post && Access::is_restricted( (int) $post->ID ) && Access::is_denied( (int) $post->ID ) ) {
			return __( 'Restricted content', 'rolewright' );
		}
		return $title;
	}

	public function guard_thumbnail( $thumbnail_id, $post = null ) {
		$post = get_post( $post );
		if ( $post && Access::is_restricted( (int) $post->ID ) && Access::is_denied( (int) $post->ID ) ) {
			return false;
		}
		return $thumbnail_id;
	}

	public function guard_comments( $comments, $post_id ) {
		return Access::is_restricted( (int) $post_id ) && Access::is_denied( (int) $post_id ) ? array() : $comments;
	}

	public function guard_comments_open( $open, $post_id ) {
		return Access::is_restricted( (int) $post_id ) && Access::is_denied( (int) $post_id ) ? false : $open;
	}

	public function guard_comments_number( $count, $post_id ) {
		return Access::is_restricted( (int) $post_id ) && Access::is_denied( (int) $post_id ) ? 0 : $count;
	}

	public function adjacent_where( string $where ): string {
		$hidden = Access::hidden_ids();
		if ( $hidden ) {
			$where .= ' AND p.ID NOT IN (' . implode( ',', array_map( 'intval', $hidden ) ) . ')';
		}
		return $where;
	}

	public function sitemap_args( array $args ): array {
		$hidden = Access::hidden_ids();
		if ( $hidden ) {
			$args['post__not_in'] = array_values( array_unique( array_merge( array_map( 'intval', (array) ( $args['post__not_in'] ?? array() ) ), $hidden ) ) );
		}
		return $args;
	}

	/** @param \WP_Post[] $pages */
	public function filter_pages( $pages ) {
		if ( is_admin() || ! is_array( $pages ) ) {
			return $pages;
		}
		$hidden = array_flip( Access::hidden_ids() );
		if ( ! $hidden ) {
			return $pages;
		}
		return array_values(
			array_filter(
				$pages,
				function ( $page ) use ( $hidden ) {
					return ! ( $page instanceof \WP_Post ) || ! isset( $hidden[ (int) $page->ID ] );
				}
			)
		);
	}
}
