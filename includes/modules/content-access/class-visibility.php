<?php
namespace Rolewright\Modules\Content_Access;

defined( 'ABSPATH' ) || exit;

final class Visibility {
	/** @var bool */
	private static $editor_preview = false;

	public function register(): void {
		add_filter( 'register_block_type_args', array( $this, 'block_attributes' ) );
		add_filter( 'render_block', array( $this, 'render_block' ), 10, 2 );
		add_filter( 'rest_pre_dispatch', array( $this, 'detect_block_renderer' ), 10, 3 );
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
	public function detect_block_renderer( $result, $server, $request ) {
		self::$editor_preview = 0 === strpos( $request->get_route(), '/wp/v2/block-renderer/' );
		return $result;
	}

	public function render_block( $content, array $block ) {
		if ( self::$editor_preview || empty( $block['attrs']['rolewrightMode'] ) ) {
			return $content;
		}
		$roles = isset( $block['attrs']['rolewrightRoles'] ) && is_array( $block['attrs']['rolewrightRoles'] ) ? $block['attrs']['rolewrightRoles'] : array();
		return Access::matches( Access::sanitize_mode( $block['attrs']['rolewrightMode'] ), $roles ) ? $content : '';
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
