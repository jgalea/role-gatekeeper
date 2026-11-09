<?php
namespace Rolegate\Modules\Content_Access;

use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Classic widgets, and widget-screen blocks through the legacy widget block, run through
 * widget_display_callback. Native blocks use the block visibility attributes instead.
 */
final class Widget_Visibility {
	const MODE  = 'rolegate_mode';
	const ROLES = 'rolegate_roles';

	public function register(): void {
		add_action( 'in_widget_form', array( $this, 'form' ), 10, 3 );
		add_filter( 'widget_update_callback', array( $this, 'update' ), 10, 4 );
		add_filter( 'widget_display_callback', array( $this, 'display' ), 10, 2 );
	}

	/** @param \WP_Widget $widget */
	public function form( $widget, $return, $instance ): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			return;
		}
		$instance = (array) $instance;
		$mode     = Access::sanitize_mode( $instance[ self::MODE ] ?? '' );
		$roles    = Access::sanitize_roles( $instance[ self::ROLES ] ?? array() );
		$modes    = array(
			'all'        => __( 'Everyone', 'role-gatekeeper' ),
			'logged_in'  => __( 'Logged-in users', 'role-gatekeeper' ),
			'logged_out' => __( 'Logged-out visitors', 'role-gatekeeper' ),
			'roles'      => __( 'Selected roles', 'role-gatekeeper' ),
		);
		echo '<p><label for="' . esc_attr( $widget->get_field_id( self::MODE ) ) . '">' . esc_html__( 'Show to', 'role-gatekeeper' ) . '</label>';
		echo '<select class="widefat" id="' . esc_attr( $widget->get_field_id( self::MODE ) ) . '" name="' . esc_attr( $widget->get_field_name( self::MODE ) ) . '">';
		foreach ( $modes as $value => $label ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $value ), selected( $mode, $value, false ), esc_html( $label ) );
		}
		echo '</select></p><p>';
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s /> %4$s</label>',
				esc_attr( $widget->get_field_name( self::ROLES ) ),
				esc_attr( $slug ),
				checked( in_array( $slug, $roles, true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '</p>';
	}

	/** @param \WP_Widget $widget */
	public function update( $instance, $new_instance, $old_instance, $widget ) {
		$instance = (array) $instance;
		$old      = (array) $old_instance;
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			foreach ( array( self::MODE, self::ROLES ) as $key ) {
				if ( isset( $old[ $key ] ) ) {
					$instance[ $key ] = $old[ $key ];
				} else {
					unset( $instance[ $key ] );
				}
			}
			return $instance;
		}
		$new  = (array) $new_instance;
		$mode = Access::sanitize_mode( $new[ self::MODE ] ?? '' );
		if ( 'all' === $mode ) {
			unset( $instance[ self::MODE ], $instance[ self::ROLES ] );
		} else {
			$instance[ self::MODE ]  = $mode;
			$instance[ self::ROLES ] = 'roles' === $mode ? Access::sanitize_roles( $new[ self::ROLES ] ?? array() ) : array();
		}
		Access::fire_scoped(
			'widget',
			(string) ( $widget->id ? $widget->id : $widget->id_base ),
			array(
				'mode'  => Access::sanitize_mode( $old[ self::MODE ] ?? '' ),
				'roles' => Access::sanitize_roles( $old[ self::ROLES ] ?? array() ),
			),
			array(
				'mode'  => Access::sanitize_mode( $instance[ self::MODE ] ?? '' ),
				'roles' => Access::sanitize_roles( $instance[ self::ROLES ] ?? array() ),
			)
		);
		return $instance;
	}

	/** @param mixed $instance */
	public function display( $instance, $widget ) {
		if ( ! is_array( $instance ) || empty( $instance[ self::MODE ] ) ) {
			return $instance;
		}
		$roles = isset( $instance[ self::ROLES ] ) && is_array( $instance[ self::ROLES ] ) ? $instance[ self::ROLES ] : array();
		return Access::matches( Access::sanitize_mode( $instance[ self::MODE ] ), $roles ) ? $instance : false;
	}
}
