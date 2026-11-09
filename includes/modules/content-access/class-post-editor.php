<?php
namespace Rolewright\Modules\Content_Access;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Post_Editor {
	const NONCE = 'rolewright_post_access';

	public function register(): void {
		add_action( 'init', array( $this, 'register_meta' ), 100 );
		add_action( 'add_meta_boxes', array( $this, 'add_meta_box' ) );
		add_action( 'save_post', array( $this, 'save_meta_box' ), 10, 2 );
		add_action( 'enqueue_block_editor_assets', array( $this, 'enqueue' ) );
		add_action( 'rest_api_init', array( $this, 'hook_rest_events' ) );
	}

	/** @return string[] */
	private function post_types(): array {
		$types = get_post_types( array( 'show_ui' => true ), 'names' );
		unset( $types['attachment'], $types['wp_block'], $types['wp_template'], $types['wp_template_part'], $types['wp_navigation'], $types['wp_global_styles'] );
		return array_values( (array) apply_filters( 'rolewright_access_post_types', $types ) );
	}

	public function register_meta(): void {
		foreach ( $this->post_types() as $type ) {
			if ( ! post_type_supports( $type, 'custom-fields' ) ) {
				add_post_type_support( $type, 'custom-fields' );
			}
			register_post_meta(
				$type,
				Access::META_ROLES,
				array(
					'single'            => true,
					'type'              => 'array',
					'default'           => array(),
					'show_in_rest'      => array(
						'schema' => array(
							'type'  => 'array',
							'items' => array( 'type' => 'string' ),
						),
					),
					'sanitize_callback' => array( Access::class, 'sanitize_roles' ),
					'auth_callback'     => array( $this, 'can_edit_rules' ),
				)
			);
			register_post_meta(
				$type,
				Access::META_MESSAGE,
				array(
					'single'            => true,
					'type'              => 'string',
					'default'           => '',
					'show_in_rest'      => true,
					'sanitize_callback' => array( Access::class, 'sanitize_message' ),
					'auth_callback'     => array( $this, 'can_edit_rules' ),
				)
			);
		}
	}

	/** @param mixed $allowed */
	public function can_edit_rules( $allowed, $meta_key, $post_id ): bool {
		return current_user_can( Caps::MANAGE_ACCESS ) && current_user_can( 'edit_post', (int) $post_id );
	}

	public function hook_rest_events(): void {
		foreach ( $this->post_types() as $type ) {
			add_action( "rest_after_insert_{$type}", array( $this, 'after_rest_save' ) );
			add_filter( "rest_prepare_{$type}", array( $this, 'hide_rule_meta' ), 10, 2 );
		}
	}

	/**
	 * The access rule is shown over REST only to users who may edit the post, which is
	 * what the block editor needs. Everyone else gets the post without the rule.
	 *
	 * @param \WP_REST_Response $response
	 * @param \WP_Post          $post
	 * @return \WP_REST_Response
	 */
	public function hide_rule_meta( $response, $post ) {
		if ( ! $response instanceof \WP_REST_Response || ! $post instanceof \WP_Post || current_user_can( 'edit_post', (int) $post->ID ) ) {
			return $response;
		}
		$data = $response->get_data();
		if ( is_array( $data ) && isset( $data['meta'] ) && is_array( $data['meta'] ) ) {
			unset( $data['meta'][ Access::META_ROLES ], $data['meta'][ Access::META_MESSAGE ] );
			$response->set_data( $data );
		}
		return $response;
	}

	/** @param \WP_Post $post */
	public function after_rest_save( $post ): void {
		Access::fire_if_changed( (int) $post->ID );
	}

	public function add_meta_box( string $post_type ): void {
		if ( ! in_array( $post_type, $this->post_types(), true ) || ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			return;
		}
		add_meta_box(
			'rolewright-access',
			__( 'Access', 'rolewright' ),
			array( $this, 'render_meta_box' ),
			$post_type,
			'side',
			'default',
			array( '__back_compat_meta_box' => true )
		);
	}

	public function render_meta_box( \WP_Post $post ): void {
		$rules = Access::rules( (int) $post->ID );
		wp_nonce_field( self::NONCE, '_rolewright_access_nonce' );
		echo '<p>' . esc_html__( 'Only these roles can view this content. Leave all unchecked for everyone.', 'rolewright' ) . '</p>';
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="rolewright_roles[]" value="%1$s" %2$s /> %3$s</label>',
				esc_attr( $slug ),
				checked( in_array( $slug, $rules['roles'], true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '<p><label for="rolewright-message">' . esc_html__( 'Message for people without access', 'rolewright' ) . '</label>';
		printf(
			'<textarea id="rolewright-message" name="rolewright_message" rows="3" class="widefat">%s</textarea></p>',
			esc_textarea( $rules['message'] )
		);
	}

	public function save_meta_box( int $post_id, \WP_Post $post ): void {
		if ( ! isset( $_POST['_rolewright_access_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_rolewright_access_nonce'] ) ), self::NONCE ) ) {
			return;
		}
		if ( ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) || wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_post', $post_id ) || ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			return;
		}
		$roles   = isset( $_POST['rolewright_roles'] ) ? (array) wp_unslash( $_POST['rolewright_roles'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$message = isset( $_POST['rolewright_message'] ) ? (string) wp_unslash( $_POST['rolewright_message'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		Access::save_rules( $post_id, $roles, $message );
	}

	public function enqueue(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			return;
		}
		$roles = array();
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			$roles[] = array(
				'value' => $slug,
				'label' => translate_user_role( $name ),
			);
		}
		wp_enqueue_script(
			'rolewright-content-access',
			ROLEWRIGHT_URL . 'assets/content-access/editor.js',
			array( 'wp-plugins', 'wp-element', 'wp-components', 'wp-data', 'wp-block-editor', 'wp-compose', 'wp-hooks', 'wp-i18n', 'wp-edit-post' ),
			ROLEWRIGHT_VERSION,
			true
		);
		wp_add_inline_script( 'rolewright-content-access', 'window.rolewrightAccess = ' . wp_json_encode( array( 'roles' => $roles ) ) . ';', 'before' );
	}
}
