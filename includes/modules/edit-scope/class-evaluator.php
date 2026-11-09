<?php
namespace Rolegate\Modules\Edit_Scope;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Answers "may this user edit this post / assign this term" from the stored rules.
 *
 * Per user: any matching block rule denies. If the user has allow rules of the same
 * family, the target must match at least one. Users who can manage access rules and
 * super admins are never restricted.
 */
final class Evaluator {
	/** @var array<string,array<string,int[]>> */
	private static $expanded = array();

	public static function reset(): void {
		self::$expanded = array();
	}

	public static function exempt( int $user_id ): bool {
		return $user_id <= 0 || is_super_admin( $user_id ) || user_can( $user_id, Caps::MANAGE_ACCESS );
	}

	/** @return array<int,array> */
	public static function rules_of( int $user_id, array $kinds ): array {
		return array_values(
			array_filter(
				Rules::for_user( $user_id ),
				function ( $r ) use ( $kinds ) {
					return in_array( $r['by'], $kinds, true );
				}
			)
		);
	}

	/**
	 * Term IDs of a rule grouped by taxonomy, with descendants when the rule includes children.
	 *
	 * @return array<string,int[]>
	 */
	public static function expand( array $rule ): array {
		$key = $rule['id'] . ':' . md5( wp_json_encode( array( $rule['ids'], $rule['children'], $rule['taxonomy'] ) ) );
		if ( isset( self::$expanded[ $key ] ) ) {
			return self::$expanded[ $key ];
		}
		$map = array();
		foreach ( $rule['ids'] as $id ) {
			$term = get_term( (int) $id );
			if ( ! $term || is_wp_error( $term ) ) {
				continue;
			}
			if ( $rule['taxonomy'] && $rule['taxonomy'] !== $term->taxonomy ) {
				continue;
			}
			$map[ $term->taxonomy ][] = (int) $term->term_id;
			if ( $rule['children'] && is_taxonomy_hierarchical( $term->taxonomy ) ) {
				$kids = get_term_children( (int) $term->term_id, $term->taxonomy );
				if ( ! is_wp_error( $kids ) ) {
					foreach ( $kids as $kid ) {
						$map[ $term->taxonomy ][] = (int) $kid;
					}
				}
			}
		}
		foreach ( $map as $tax => $list ) {
			$map[ $tax ] = array_values( array_unique( $list ) );
		}
		self::$expanded[ $key ] = $map;
		return $map;
	}

	private static function is_own( int $user_id, \WP_Post $post, array $rule ): bool {
		return (int) $post->post_author === $user_id
			&& (bool) apply_filters( 'rolegate_edit_scope_own_posts', true, $user_id, $post, $rule );
	}

	private static function matches_post( array $rule, \WP_Post $post, int $user_id ): bool {
		switch ( $rule['by'] ) {
			case 'post':
				return in_array( (int) $post->ID, $rule['ids'], true );
			case 'author':
				if ( self::is_own( $user_id, $post, $rule ) ) {
					return 'allow' === $rule['mode'];
				}
				return in_array( (int) $post->post_author, $rule['ids'], true );
			case 'term':
				$map = self::expand( $rule );
				if ( ! $map ) {
					return false;
				}
				$have = wp_get_object_terms( $post->ID, array_keys( $map ), array( 'fields' => 'ids' ) );
				$have = is_wp_error( $have ) ? array() : array_map( 'intval', $have );
				foreach ( $map as $ids ) {
					if ( array_intersect( $have, $ids ) ) {
						return true;
					}
				}
				if ( 'allow' === $rule['mode'] && self::is_own( $user_id, $post, $rule ) ) {
					return self::only_default_terms( $post->ID, array_keys( $map ) );
				}
				return false;
		}
		return false;
	}

	/** An own post with no term yet (or only the default one) stays editable so it can be categorised. */
	private static function only_default_terms( int $post_id, array $taxonomies ): bool {
		foreach ( $taxonomies as $tax ) {
			$have = wp_get_object_terms( $post_id, $tax, array( 'fields' => 'ids' ) );
			$have = is_wp_error( $have ) ? array() : array_map( 'intval', $have );
			$def  = (int) get_option( 'default_' . $tax, 0 );
			if ( array_diff( $have, array( $def ) ) ) {
				return false;
			}
		}
		return true;
	}

	/** @param int|\WP_Post $post */
	public static function post_allowed( int $user_id, $post ): bool {
		$post = get_post( $post );
		if ( ! $post || 'auto-draft' === $post->post_status || self::exempt( $user_id ) ) {
			return true;
		}
		if ( 'revision' === $post->post_type && $post->post_parent ) {
			return self::post_allowed( $user_id, (int) $post->post_parent );
		}
		$rules = self::rules_of( $user_id, array( 'post', 'author', 'term' ) );
		if ( ! $rules ) {
			return true;
		}
		$allowed   = true;
		$has_allow = false;
		$hit_allow = false;
		foreach ( $rules as $rule ) {
			$hit = self::matches_post( $rule, $post, $user_id );
			if ( 'block' === $rule['mode'] ) {
				if ( $hit ) {
					$allowed = false;
					break;
				}
			} else {
				$has_allow = true;
				$hit_allow = $hit_allow || $hit;
			}
		}
		if ( $allowed && $has_allow && ! $hit_allow ) {
			$allowed = false;
		}
		return (bool) apply_filters( 'rolegate_edit_scope_post_allowed', $allowed, $user_id, $post, $rules );
	}

	/** @return int[] */
	private static function ids_for( array $args ): array {
		$q = new \WP_Query(
			array_merge(
				array(
					'post_type'              => array_values( get_post_types( array( 'show_ui' => true ) ) ),
					'post_status'            => array_values( get_post_stati() ),
					'posts_per_page'         => -1,
					'fields'                 => 'ids',
					'no_found_rows'          => true,
					'orderby'                => 'none',
					'suppress_filters'       => true, // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.SuppressFilters_suppress_filters -- these ids become the scope's exclusion list, so other plugins' query filters (language, access) must not shrink the set.
					'ignore_sticky_posts'    => true,
					'rolegate_scope_skip'    => true,
					'update_post_meta_cache' => false,
				),
				$args
			)
		);
		return array_map( 'intval', $q->posts );
	}

	/** @return int[] */
	private static function rule_post_ids( array $rule, int $user_id ): array {
		switch ( $rule['by'] ) {
			case 'post':
				return $rule['ids'];
			case 'author':
				$authors = 'block' === $rule['mode'] ? array_values( array_diff( $rule['ids'], array( $user_id ) ) ) : $rule['ids'];
				return $authors ? self::ids_for( array( 'author__in' => $authors ) ) : array();
			case 'term':
				$tax_query = array( 'relation' => 'OR' );
				foreach ( self::expand( $rule ) as $tax => $ids ) {
					$tax_query[] = array(
						'taxonomy'         => $tax,
						'field'            => 'term_id',
						'terms'            => $ids,
						'include_children' => false,
					);
				}
				return count( $tax_query ) > 1 ? self::ids_for( array( 'tax_query' => $tax_query ) ) : array();
		}
		return array();
	}

	/**
	 * Query constraints that hide what the user can't edit.
	 *
	 * @return array{post__in?:int[],post__not_in?:int[]}
	 */
	public static function list_constraints( int $user_id ): array {
		if ( self::exempt( $user_id ) ) {
			return array();
		}
		$rules = self::rules_of( $user_id, array( 'post', 'author', 'term' ) );
		if ( ! $rules ) {
			return array();
		}
		$blocked = array();
		$allowed = null;
		foreach ( $rules as $rule ) {
			$ids = self::rule_post_ids( $rule, $user_id );
			if ( 'block' === $rule['mode'] ) {
				$blocked = array_merge( $blocked, $ids );
			} else {
				$allowed = array_merge( (array) $allowed, $ids );
			}
		}
		$out = array();
		if ( null !== $allowed ) {
			foreach ( self::ids_for( array( 'author' => $user_id ) ) as $own ) {
				if ( self::post_allowed( $user_id, $own ) ) {
					$allowed[] = $own;
				}
			}
			$allowed         = array_values( array_diff( array_unique( $allowed ), $blocked ) );
			$out['post__in'] = $allowed ? $allowed : array( 0 );
		}
		if ( $blocked ) {
			$out['post__not_in'] = array_values( array_unique( $blocked ) );
		}
		return $out;
	}

	public static function term_allowed( int $user_id, int $term_id, string $taxonomy ): bool {
		if ( self::exempt( $user_id ) ) {
			return true;
		}
		$rules = array_values(
			array_filter(
				self::rules_of( $user_id, array( 'assign' ) ),
				function ( $r ) use ( $taxonomy ) {
					return $r['taxonomy'] === $taxonomy;
				}
			)
		);
		if ( ! $rules ) {
			return true;
		}
		$has_allow = false;
		$hit_allow = false;
		foreach ( $rules as $rule ) {
			$map = self::expand( $rule );
			$hit = isset( $map[ $taxonomy ] ) && in_array( $term_id, $map[ $taxonomy ], true );
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

	public static function has_assign_rules( int $user_id, string $taxonomy ): bool {
		if ( self::exempt( $user_id ) ) {
			return false;
		}
		foreach ( self::rules_of( $user_id, array( 'assign' ) ) as $rule ) {
			if ( $rule['taxonomy'] === $taxonomy ) {
				return true;
			}
		}
		return false;
	}

	/** @return int[] */
	public static function unassignable_terms( int $user_id, string $taxonomy ): array {
		if ( ! self::has_assign_rules( $user_id, $taxonomy ) ) {
			return array();
		}
		$all = get_terms(
			array(
				'taxonomy'            => $taxonomy,
				'hide_empty'          => false,
				'fields'              => 'ids',
				'rolegate_scope_skip' => true,
			)
		);
		if ( is_wp_error( $all ) ) {
			return array();
		}
		$out = array();
		foreach ( $all as $id ) {
			if ( ! self::term_allowed( $user_id, (int) $id, $taxonomy ) ) {
				$out[] = (int) $id;
			}
		}
		return $out;
	}
}
