<?php
namespace Rolewright\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

use Rolewright\Modules\Safety\Caps;

final class Visibility {
	const ATTRS = array( 'rolewrightMode', 'rolewrightRoles' );

	/**
	 * Set while the block renderer previews a block for a user who may edit the post:
	 * the block name and the visibility attributes the editor sent.
	 *
	 * @var array{name:string,attrs:array}|null
	 */
	private static $editor_preview = null;

	public function register(): void {
		add_filter( 'register_block_type_args', array( $this, 'block_attributes' ) );
		add_filter( 'render_block', array( $this, 'render_block' ), 10, 2 );
		add_filter( 'rest_pre_dispatch', array( $this, 'reset_preview' ), 0 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'detect_block_renderer' ), 20, 3 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'reset_preview' ), 0 );
		add_filter( 'rest_post_dispatch', array( $this, 'reset_preview' ), 0 );
		add_filter( 'wp_insert_post_data', array( $this, 'guard_saved_attributes' ), 20, 2 );
		add_shortcode( 'rolewright_if', array( $this, 'sc_if' ) );
		add_shortcode( 'rolewright_logged_in', array( $this, 'sc_logged_in' ) );
		add_shortcode( 'rolewright_logged_out', array( $this, 'sc_logged_out' ) );
		add_shortcode( 'rolewright_login_form', array( $this, 'sc_login_form' ) );
	}

	public function block_attributes( array $args ): array {
		$attrs                    = isset( $args['attributes'] ) && is_array( $args['attributes'] ) ? $args['attributes'] : array();
		$attrs['rolewrightMode']  = array( 'type' => 'string' );
		$attrs['rolewrightRoles'] = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);
		$args['attributes']       = $attrs;
		return $args;
	}

	/** @param mixed $result */
	public function reset_preview( $result ) {
		self::$editor_preview = null;
		return $result;
	}

	public static function preview_active(): bool {
		return null !== self::$editor_preview;
	}

	/**
	 * Lets the editor preview show a block its author hid from their own role. Only the
	 * block the request names, only for someone who can edit the post it renders for
	 * (or manage access when no post is given), and only until the request ends.
	 *
	 * @param mixed            $response
	 * @param array            $handler
	 * @param \WP_REST_Request $request
	 */
	public function detect_block_renderer( $response, $handler, $request ) {
		self::$editor_preview = null;
		$controller           = isset( $handler['callback'] ) && is_array( $handler['callback'] ) && isset( $handler['callback'][0] ) ? $handler['callback'][0] : null;
		if ( is_wp_error( $response ) || ! $controller instanceof \WP_REST_Block_Renderer_Controller || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}
		$post_id = (int) $request->get_param( 'post_id' );
		$allowed = $post_id > 0 ? current_user_can( 'edit_post', $post_id ) : current_user_can( Caps::MANAGE_ACCESS );
		if ( ! $allowed ) {
			return $response;
		}
		$attrs                = $request->get_param( 'attributes' );
		self::$editor_preview = array(
			'name'  => strtolower( (string) $request->get_param( 'name' ) ),
			'attrs' => self::visibility_attrs( is_array( $attrs ) ? $attrs : array() ),
		);
		return $response;
	}

	private static function visibility_attrs( array $attrs ): array {
		$out = array();
		foreach ( self::ATTRS as $key ) {
			if ( isset( $attrs[ $key ] ) ) {
				$out[ $key ] = $attrs[ $key ];
			}
		}
		return $out;
	}

	public function render_block( $content, array $block ) {
		if ( empty( $block['attrs']['rolewrightMode'] ) ) {
			return $content;
		}
		if ( self::$editor_preview && isset( $block['blockName'] ) && strtolower( (string) $block['blockName'] ) === self::$editor_preview['name'] && self::visibility_attrs( $block['attrs'] ) == self::$editor_preview['attrs'] ) { // phpcs:ignore Universal.Operators.StrictComparisonOperators
			return $content;
		}
		$roles = isset( $block['attrs']['rolewrightRoles'] ) && is_array( $block['attrs']['rolewrightRoles'] ) ? $block['attrs']['rolewrightRoles'] : array();
		return Access::matches( Access::sanitize_mode( $block['attrs']['rolewrightMode'] ), $roles ) ? $content : '';
	}

	/**
	 * Block visibility is an access rule, so only users who manage access may set or
	 * change it. For anyone else a block keeps visibility attributes only when the stored
	 * post already had a block of the same type with the same attributes.
	 *
	 * @param array $data Slashed post data.
	 * @param array $postarr
	 */
	public function guard_saved_attributes( $data, $postarr = array() ) {
		$uid = get_current_user_id();
		if ( ! $uid || ! is_array( $data ) || empty( $data['post_content'] ) || user_can( $uid, Caps::MANAGE_ACCESS ) ) {
			return $data;
		}
		if ( isset( $data['post_type'] ) && 'revision' === $data['post_type'] ) {
			return $data;
		}
		$content = wp_unslash( (string) $data['post_content'] );
		if ( false === stripos( $content, 'rolewright' ) ) {
			return $data;
		}
		$old = '';
		if ( ! empty( $postarr['ID'] ) ) {
			$post = get_post( (int) $postarr['ID'] );
			$old  = $post instanceof \WP_Post ? (string) $post->post_content : '';
		}
		$clean = self::strip_new_attributes( $content, $old );
		if ( $clean !== $content ) {
			$data['post_content'] = wp_slash( $clean );
		}
		return $data;
	}

	/** Drops visibility attributes from blocks in $content that $old doesn't carry. */
	public static function strip_new_attributes( string $content, string $old ): string {
		$allowance = array();
		$collect   = function ( array $blocks ) use ( &$collect, &$allowance ) {
			foreach ( $blocks as $block ) {
				$attrs = self::visibility_attrs( isset( $block['attrs'] ) && is_array( $block['attrs'] ) ? $block['attrs'] : array() );
				if ( $attrs ) {
					$key               = (string) $block['blockName'] . '|' . wp_json_encode( $attrs );
					$allowance[ $key ] = ( isset( $allowance[ $key ] ) ? $allowance[ $key ] : 0 ) + 1;
				}
				if ( ! empty( $block['innerBlocks'] ) ) {
					$collect( $block['innerBlocks'] );
				}
			}
		};
		if ( '' !== $old ) {
			$collect( parse_blocks( $old ) );
		}
		$changed = false;
		$walk    = function ( array $blocks ) use ( &$walk, &$allowance, &$changed ) {
			foreach ( $blocks as $i => $block ) {
				$attrs = self::visibility_attrs( isset( $block['attrs'] ) && is_array( $block['attrs'] ) ? $block['attrs'] : array() );
				if ( $attrs ) {
					$key = (string) $block['blockName'] . '|' . wp_json_encode( $attrs );
					if ( ! empty( $allowance[ $key ] ) ) {
						--$allowance[ $key ];
					} else {
						foreach ( self::ATTRS as $name ) {
							unset( $blocks[ $i ]['attrs'][ $name ] );
						}
						$changed = true;
					}
				}
				if ( ! empty( $block['innerBlocks'] ) ) {
					$blocks[ $i ]['innerBlocks'] = $walk( $block['innerBlocks'] );
				}
			}
			return $blocks;
		};
		$blocks = $walk( parse_blocks( $content ) );
		return $changed ? serialize_blocks( $blocks ) : $content;
	}

	public function sc_if( $atts, $content = '' ): string {
		$atts  = shortcode_atts( array( 'roles' => '' ), (array) $atts, 'rolewright_if' );
		$roles = Access::sanitize_roles( $atts['roles'] );
		if ( ! $roles || ! Access::matches( 'roles', $roles ) ) {
			return '';
		}
		return do_shortcode( (string) $content );
	}

	public function sc_logged_in( $atts, $content = '' ): string {
		return Access::matches( 'logged_in', array() ) ? do_shortcode( (string) $content ) : '';
	}

	public function sc_logged_out( $atts, $content = '' ): string {
		return Access::matches( 'logged_out', array() ) ? do_shortcode( (string) $content ) : '';
	}

	/** Posts to wp-login.php, so 2FA and other login-screen plugins run as usual. */
	public function sc_login_form( $atts ): string {
		if ( is_user_logged_in() ) {
			Access::mark_uncacheable();
			return '';
		}
		$atts     = shortcode_atts( array( 'redirect' => '' ), (array) $atts, 'rolewright_login_form' );
		$redirect = '' !== $atts['redirect'] ? wp_validate_redirect( esc_url_raw( $atts['redirect'] ), '' ) : '';
		if ( '' === $redirect ) {
			$post     = get_post();
			$redirect = $post ? (string) get_permalink( $post ) : home_url( '/' );
		}
		return (string) wp_login_form(
			array(
				'echo'     => false,
				'redirect' => $redirect,
				'form_id'  => 'rolewright-login-form',
			)
		);
	}
}
