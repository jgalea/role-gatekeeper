<?php
namespace Rolegate\Modules\Capabilities;

defined( 'ABSPATH' ) || exit;

/**
 * Optional capability sets and per-post-type capabilities. The settings only change what
 * WordPress asks for; granting the new capabilities to roles is done by Cap_Service.
 */
final class Cap_Sets {
	const OPTION_SETS = 'rolegate_extra_cap_sets';
	const OPTION_CPT  = 'rolegate_cpt_own_caps';
	const SET_IDS     = array( 'create', 'terms', 'privacy' );

	/**
	 * Labels for the admin screen. Filters that run before init use SET_IDS instead, so no
	 * translation loads early.
	 *
	 * @return array<string,array{label:string,description:string}>
	 */
	public static function definitions(): array {
		return array(
			'create'  => array(
				'label'       => __( 'Separate create capabilities', 'role-gatekeeper' ),
				'description' => __( 'Adds create_posts and create_pages so adding new content can be allowed apart from editing it.', 'role-gatekeeper' ),
			),
			'terms'   => array(
				'label'       => __( 'Category and tag capabilities', 'role-gatekeeper' ),
				'description' => __( 'Adds edit, delete and assign capabilities for categories and tags, and manage, edit, delete and assign capabilities for tags.', 'role-gatekeeper' ),
			),
			'privacy' => array(
				'label'       => __( 'Privacy capabilities', 'role-gatekeeper' ),
				'description' => __( 'Adds export_others_personal_data, erase_others_personal_data and manage_privacy_options as their own capabilities (single sites only).', 'role-gatekeeper' ),
			),
		);
	}

	/** @return string[] enabled set ids */
	public static function enabled(): array {
		$stored = get_option( self::OPTION_SETS, array() );
		return is_array( $stored ) ? array_values( array_intersect( self::SET_IDS, array_map( 'strval', $stored ) ) ) : array();
	}

	/** @return string[] post type slugs that use their own capabilities */
	public static function cpt_own(): array {
		$stored = get_option( self::OPTION_CPT, array() );
		return is_array( $stored ) ? array_values( array_filter( array_map( 'sanitize_key', $stored ) ) ) : array();
	}

	/** @return array<string,string> slug => label of post types that could get their own capabilities */
	public static function eligible_post_types(): array {
		$out = array();
		foreach ( get_post_types( array( '_builtin' => false ), 'objects' ) as $slug => $type ) {
			$own = in_array( $slug, self::cpt_own(), true );
			if ( $own || ( $type->show_ui && 'post' === $type->capability_type && ! self::has_custom_caps( $type ) ) ) {
				$out[ $slug ] = $type->labels->name;
			}
		}
		return $out;
	}

	public static function is_enabled( string $set ): bool {
		return in_array( $set, self::enabled(), true );
	}

	/** @return array{0:string,1:string} single and plural used in capability names */
	public static function cpt_words( string $slug ): array {
		$plural = '' !== $slug && 's' === substr( $slug, -1 ) ? $slug . 'es' : $slug . 's';
		return array( $slug, $plural );
	}

	/**
	 * @return array<string,string> core post capability => this post type's capability
	 */
	public static function cpt_cap_map( string $slug ): array {
		list( $single, $plural ) = self::cpt_words( $slug );
		unset( $single );
		$map = array();
		foreach ( array( 'edit', 'edit_others', 'publish', 'read_private', 'delete', 'delete_private', 'delete_published', 'delete_others', 'edit_private', 'edit_published' ) as $verb ) {
			$map[ $verb . '_posts' ] = $verb . '_' . $plural;
		}
		return $map;
	}

	public function register(): void {
		add_filter( 'register_post_type_args', array( $this, 'post_type_args' ), 10, 2 );
		add_filter( 'register_taxonomy_args', array( $this, 'taxonomy_args' ), 10, 2 );
		add_filter( 'map_meta_cap', array( $this, 'privacy_caps' ), 20, 2 );
	}

	/**
	 * @param array  $args
	 * @param string $post_type
	 * @return array
	 */
	public function post_type_args( $args, $post_type ) {
		if ( self::is_enabled( 'create' ) && in_array( $post_type, array( 'post', 'page' ), true ) ) {
			$args['capabilities'] = array_merge( isset( $args['capabilities'] ) ? (array) $args['capabilities'] : array(), array( 'create_posts' => 'create_' . $post_type . 's' ) );
		}
		if ( in_array( $post_type, self::cpt_own(), true ) && empty( $args['capabilities'] ) && ( empty( $args['capability_type'] ) || 'post' === $args['capability_type'] ) ) {
			$args['capability_type'] = self::cpt_words( $post_type );
			$args['map_meta_cap']    = true;
		}
		return $args;
	}

	/**
	 * @param array  $args
	 * @param string $taxonomy
	 * @return array
	 */
	public function taxonomy_args( $args, $taxonomy ) {
		if ( ! self::is_enabled( 'terms' ) ) {
			return $args;
		}
		$maps = array(
			'category' => array(
				'edit_terms'   => 'edit_categories',
				'delete_terms' => 'delete_categories',
				'assign_terms' => 'assign_categories',
			),
			'post_tag' => array(
				'manage_terms' => 'manage_post_tags',
				'edit_terms'   => 'edit_post_tags',
				'delete_terms' => 'delete_post_tags',
				'assign_terms' => 'assign_post_tags',
			),
		);
		if ( isset( $maps[ $taxonomy ] ) ) {
			$args['capabilities'] = array_merge( isset( $args['capabilities'] ) ? (array) $args['capabilities'] : array(), $maps[ $taxonomy ] );
		}
		return $args;
	}

	/**
	 * @param string[] $caps
	 * @param string   $cap
	 * @return string[]
	 */
	public function privacy_caps( $caps, $cap ) {
		if ( ! is_multisite() && self::is_enabled( 'privacy' ) && in_array( $cap, self::privacy_cap_names(), true ) ) {
			return array( $cap );
		}
		return $caps;
	}

	/** @return string[] */
	public static function privacy_cap_names(): array {
		return array( 'export_others_personal_data', 'erase_others_personal_data', 'manage_privacy_options' );
	}

	/**
	 * Which new capabilities each role should receive, based on what it holds today.
	 *
	 * @param string[]                                    $sets
	 * @param string[]                                    $cpts
	 * @param array<string,array<string,bool>> $roles role => caps
	 * @return array<string,string[]> role => caps to add
	 */
	public static function grants_for( array $sets, array $cpts, array $roles ): array {
		$out = array();
		foreach ( $roles as $role => $caps ) {
			$has = function ( $c ) use ( $caps ) {
				return ! empty( $caps[ $c ] );
			};
			$add = array();
			if ( in_array( 'create', $sets, true ) ) {
				if ( $has( 'edit_posts' ) ) {
					$add[] = 'create_posts';
				}
				if ( $has( 'edit_pages' ) ) {
					$add[] = 'create_pages';
				}
			}
			if ( in_array( 'terms', $sets, true ) ) {
				if ( $has( 'manage_categories' ) ) {
					array_push( $add, 'edit_categories', 'delete_categories', 'manage_post_tags', 'edit_post_tags', 'delete_post_tags' );
				}
				if ( $has( 'edit_posts' ) ) {
					array_push( $add, 'assign_categories', 'assign_post_tags' );
				}
			}
			if ( in_array( 'privacy', $sets, true ) && ! is_multisite() && $has( 'manage_options' ) ) {
				$add = array_merge( $add, self::privacy_cap_names() );
			}
			foreach ( $cpts as $slug ) {
				foreach ( self::cpt_cap_map( $slug ) as $core => $own ) {
					if ( $has( $core ) ) {
						$add[] = $own;
					}
				}
			}
			$add = array_values(
				array_filter(
					array_unique( $add ),
					function ( $c ) use ( $caps ) {
						return empty( $caps[ $c ] );
					}
				)
			);
			if ( $add ) {
				$out[ $role ] = $add;
			}
		}
		return $out;
	}

	private static function has_custom_caps( \WP_Post_Type $type ): bool {
		return ! empty( $type->capabilities );
	}
}
