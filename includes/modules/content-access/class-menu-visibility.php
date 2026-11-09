<?php
namespace Rolewright\Modules\Content_Access;

use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Menu_Visibility {
	const META_MODE  = '_rolewright_menu_mode';
	const META_ROLES = '_rolewright_menu_roles';
	const NONCE      = 'rolewright_menu_item';

	public function register(): void {
		add_action( 'wp_nav_menu_item_custom_fields', array( $this, 'fields' ), 10, 2 );
		add_action( 'wp_update_nav_menu_item', array( $this, 'save' ), 10, 2 );
		add_filter( 'wp_get_nav_menu_items', array( $this, 'filter_items' ), 10, 3 );
	}

	public function fields( $item_id, $item ): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			return;
		}
		$item_id = (int) $item_id;
		$mode    = Access::sanitize_mode( get_post_meta( $item_id, self::META_MODE, true ) );
		$roles   = get_post_meta( $item_id, self::META_ROLES, true );
		$roles   = is_array( $roles ) ? $roles : array();
		$name    = 'rolewright_menu[' . $item_id . ']';
		$modes   = array(
			'all'        => __( 'Everyone', 'rolewright' ),
			'logged_in'  => __( 'Logged-in users', 'rolewright' ),
			'logged_out' => __( 'Logged-out visitors', 'rolewright' ),
			'roles'      => __( 'Selected roles', 'rolewright' ),
		);
		echo '<fieldset class="field-rolewright description-wide"><legend>' . esc_html__( 'Show to', 'rolewright' ) . '</legend>';
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[nonce]" value="' . esc_attr( wp_create_nonce( self::NONCE ) ) . '" />';
		echo '<select name="' . esc_attr( $name ) . '[mode]">';
		foreach ( $modes as $value => $label ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $value ), selected( $mode, $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		foreach ( wp_roles()->get_names() as $slug => $role_name ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="%1$s[roles][]" value="%2$s" %3$s /> %4$s</label>',
				esc_attr( $name ),
				esc_attr( $slug ),
				checked( in_array( $slug, $roles, true ), true, false ),
				esc_html( translate_user_role( $role_name ) )
			);
		}
		echo '</fieldset>';
	}

	public function save( $menu_id, $item_id ): void {
		$item_id = (int) $item_id;
		$posted  = isset( $_POST['rolewright_menu'][ $item_id ] ) ? wp_unslash( $_POST['rolewright_menu'][ $item_id ] ) : null; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_array( $posted ) || ! isset( $posted['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( $posted['nonce'] ), self::NONCE ) ) {
			return;
		}
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) || ! current_user_can( 'edit_theme_options' ) ) {
			return;
		}
		$before = $this->state( $item_id );
		$mode   = Access::sanitize_mode( $posted['mode'] ?? '' );
		$roles  = 'roles' === $mode ? Access::sanitize_roles( $posted['roles'] ?? array() ) : array();
		if ( 'all' === $mode ) {
			delete_post_meta( $item_id, self::META_MODE );
			delete_post_meta( $item_id, self::META_ROLES );
		} else {
			update_post_meta( $item_id, self::META_MODE, $mode );
			update_post_meta( $item_id, self::META_ROLES, $roles );
		}
		Access::fire_scoped( 'menu_item', (string) $item_id, $before, $this->state( $item_id ) );
	}

	private function state( int $item_id ): array {
		$roles = get_post_meta( $item_id, self::META_ROLES, true );
		return array(
			'mode'  => Access::sanitize_mode( get_post_meta( $item_id, self::META_MODE, true ) ),
			'roles' => is_array( $roles ) ? Access::sanitize_roles( $roles ) : array(),
		);
	}

	/**
	 * Items the visitor may not see are dropped, along with their children and any item that
	 * points at a post the visitor may not view.
	 *
	 * @param array $items
	 * @return array
	 */
	public function filter_items( $items, $menu = null, $args = array() ) {
		if ( is_admin() || ! is_array( $items ) ) {
			return $items;
		}
		$hide = array();
		foreach ( $items as $item ) {
			$id    = (int) $item->ID;
			$state = $this->state( $id );
			if ( 'all' !== $state['mode'] && ! Access::matches( $state['mode'], $state['roles'] ) ) {
				$hide[ $id ] = true;
			} elseif ( 'post_type' === $item->type && (int) $item->object_id && Access::is_restricted( (int) $item->object_id ) && Access::is_denied( (int) $item->object_id ) ) {
				$hide[ $id ] = true;
			}
		}
		if ( ! $hide ) {
			return $items;
		}
		$parents = array();
		foreach ( $items as $item ) {
			$parents[ (int) $item->ID ] = (int) $item->menu_item_parent;
		}
		$kept = array();
		foreach ( $items as $item ) {
			$id    = (int) $item->ID;
			$walk  = $id;
			$gone  = false;
			$guard = 0;
			while ( $walk && $guard++ < 50 ) {
				if ( isset( $hide[ $walk ] ) ) {
					$gone = true;
					break;
				}
				$walk = $parents[ $walk ] ?? 0;
			}
			if ( ! $gone ) {
				$kept[] = $item;
			}
		}
		return $kept;
	}
}
