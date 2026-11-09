<?php
namespace Rolewright\Modules\Deny_Hierarchy;

use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Admin_Page {
	const SLUG = 'rolewright-deny-hierarchy';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolewright_save_denials', array( $this, 'save_denials' ) );
		add_action( 'admin_post_rolewright_save_positions', array( $this, 'save_positions' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Deny and hierarchy', 'rolewright' ),
			__( 'Deny and hierarchy', 'rolewright' ),
			Caps::MANAGE_ACCESS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	private static function url( string $tab, array $args = array() ): string {
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					'tab'  => $tab,
				),
				$args
			),
			admin_url( 'admin.php' )
		);
	}

	private static function role_name( string $role ): string {
		$names = wp_roles()->get_names();
		return isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role;
	}

	/** @return string[] every cap any role lists, sorted */
	private static function all_caps(): array {
		$caps = array();
		foreach ( wp_roles()->roles as $data ) {
			foreach ( array_keys( (array) $data['capabilities'] ) as $cap ) {
				$caps[ (string) $cap ] = true;
			}
		}
		foreach ( Denials::map() as $list ) {
			foreach ( $list as $cap ) {
				$caps[ $cap ] = true;
			}
		}
		$caps = array_keys( $caps );
		sort( $caps );
		return $caps;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only navigation.
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'denials';
		$tab  = in_array( $tab, array( 'denials', 'hierarchy', 'effective' ), true ) ? $tab : 'denials';
		$tabs = array(
			'denials'   => __( 'Denied capabilities', 'rolewright' ),
			'hierarchy' => __( 'Role hierarchy', 'rolewright' ),
			'effective' => __( 'Effective capabilities', 'rolewright' ),
		);

		echo '<div class="wrap"><h1>' . esc_html__( 'Deny and hierarchy', 'rolewright' ) . '</h1>';
		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $id => $label ) {
			printf( '<a href="%1$s" class="nav-tab%2$s">%3$s</a>', esc_url( self::url( $id ) ), $tab === $id ? ' nav-tab-active' : '', esc_html( $label ) );
		}
		echo '</nav>';

		if ( isset( $_GET['rw_error'] ) ) {
			$msg = get_transient( 'rolewright_dh_error_' . get_current_user_id() );
			delete_transient( 'rolewright_dh_error_' . get_current_user_id() );
			if ( $msg ) {
				echo '<div class="notice notice-error"><p>' . esc_html( (string) $msg ) . '</p></div>';
			}
		} elseif ( isset( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'rolewright' ) . '</p></div>';
		}
		// phpcs:enable

		if ( 'hierarchy' === $tab ) {
			$this->render_hierarchy();
		} elseif ( 'effective' === $tab ) {
			$this->render_effective();
		} else {
			$this->render_denials();
		}
		echo '</div>';
	}

	private function render_denials(): void {
		$actor = get_current_user_id();
		$roles = array();
		foreach ( Hierarchy::positions() as $role => $pos ) {
			if ( Hierarchy::can_manage_role( $actor, $role ) ) {
				$roles[] = $role;
			}
		}

		echo '<p>' . esc_html__( 'A denied capability is removed from every user who has the role, even when another of their roles or a per-user grant gives it. Administrators always keep read, their critical capabilities and Rolewright\'s own capabilities.', 'rolewright' ) . '</p>';

		$map = Denials::map();
		if ( $map ) {
			echo '<h2>' . esc_html__( 'Current denials', 'rolewright' ) . '</h2>';
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Role', 'rolewright' ) . '</th><th>' . esc_html__( 'Denied capabilities', 'rolewright' ) . '</th></tr></thead><tbody>';
			foreach ( $map as $role => $caps ) {
				printf(
					'<tr><td><a href="%1$s">%2$s</a></td><td><code>%3$s</code></td></tr>',
					esc_url( self::url( 'denials', array( 'role' => $role ) ) ),
					esc_html( self::role_name( $role ) ),
					esc_html( implode( ', ', $caps ) )
				);
			}
			echo '</tbody></table>';
		}

		if ( ! $roles ) {
			echo '<p>' . esc_html__( 'There are no roles below your position that you can edit.', 'rolewright' ) . '</p>';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only selection.
		$role = isset( $_GET['role'] ) ? sanitize_key( wp_unslash( $_GET['role'] ) ) : $roles[0];
		$role = in_array( $role, $roles, true ) ? $role : $roles[0];

		echo '<h2>' . esc_html__( 'Edit denials', 'rolewright' ) . '</h2>';
		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" /><input type="hidden" name="tab" value="denials" />';
		echo '<label for="rw-dh-role">' . esc_html__( 'Role', 'rolewright' ) . '</label> <select id="rw-dh-role" name="role">';
		foreach ( $roles as $r ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $r ), selected( $r, $role, false ), esc_html( self::role_name( $r ) ) );
		}
		echo '</select> ';
		submit_button( __( 'Select', 'rolewright' ), 'secondary', '', false );
		echo '</form>';

		$role_caps = Guard::normalize_caps( (array) get_role( $role )->capabilities );
		$denied    = array_flip( Denials::for_role( $role ) );
		$user      = wp_get_current_user();
		$own       = in_array( $role, (array) $user->roles, true );

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolewright_save_denials" />';
		echo '<input type="hidden" name="role" value="' . esc_attr( $role ) . '" />';
		wp_nonce_field( 'rolewright_save_denials_' . $role );
		echo '<table class="widefat striped" style="max-width:48rem"><thead><tr><th>' . esc_html__( 'Capability', 'rolewright' ) . '</th><th>' . esc_html__( 'This role grants it', 'rolewright' ) . '</th><th>' . esc_html__( 'Deny', 'rolewright' ) . '</th></tr></thead><tbody>';
		foreach ( self::all_caps() as $cap ) {
			$locked = Denials::is_protected( $role, $cap ) || ( $own && 'read' === $cap );
			$id     = 'rw-dh-cap-' . md5( $cap );
			printf(
				'<tr><td><label for="%1$s"><code>%2$s</code></label></td><td>%3$s</td><td><input type="checkbox" id="%1$s" name="denied[]" value="%4$s"%5$s%6$s />%7$s</td></tr>',
				esc_attr( $id ),
				esc_html( $cap ),
				! empty( $role_caps[ $cap ] ) ? esc_html__( 'Yes', 'rolewright' ) : '&mdash;',
				esc_attr( $cap ),
				checked( isset( $denied[ $cap ] ), true, false ),
				disabled( $locked, true, false ),
				$locked ? ' <span class="description">' . esc_html__( 'protected', 'rolewright' ) . '</span>' : ''
			);
		}
		echo '</tbody></table>';
		submit_button( __( 'Save denials', 'rolewright' ) );
		echo '</form>';
	}

	private function render_hierarchy(): void {
		$actor  = get_current_user_id();
		$mine   = Hierarchy::user_position( $actor );
		$top    = Hierarchy::is_top( $actor );
		$stored = Hierarchy::stored();

		echo '<p>' . esc_html__( 'Higher numbers rank higher. Below the top, users can only edit, delete or assign roles below their own position, can only edit users below it, and don\'t see users of higher roles. Administrator is fixed at the top.', 'rolewright' ) . '</p>';
		/* translators: %d: position number */
		echo '<p>' . esc_html( sprintf( __( 'Your position: %d.', 'rolewright' ), $mine ) ) . '</p>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolewright_save_positions" />';
		wp_nonce_field( 'rolewright_save_positions' );
		echo '<table class="widefat striped" style="max-width:40rem"><thead><tr><th>' . esc_html__( 'Role', 'rolewright' ) . '</th><th>' . esc_html__( 'Position', 'rolewright' ) . '</th><th>' . esc_html__( 'Source', 'rolewright' ) . '</th></tr></thead><tbody>';
		foreach ( Hierarchy::positions() as $role => $pos ) {
			$editable = 'administrator' !== $role && ( $top || $pos < $mine );
			$max      = $top ? Hierarchy::MAX_EDITABLE : max( 0, $mine - 1 );
			$input    = $editable
				? sprintf( '<input type="number" class="small-text" name="positions[%1$s]" value="%2$d" min="0" max="%3$d" aria-label="%4$s" />', esc_attr( $role ), (int) $pos, (int) $max, esc_attr( self::role_name( $role ) ) )
				: '<strong>' . (int) $pos . '</strong>';
			if ( 'administrator' === $role ) {
				$source = __( 'fixed', 'rolewright' );
			} else {
				$source = isset( $stored[ $role ] ) ? __( 'set', 'rolewright' ) : __( 'default from user level', 'rolewright' );
			}
			printf( '<tr><td>%1$s <code>%2$s</code></td><td>%3$s</td><td>%4$s</td></tr>', esc_html( self::role_name( $role ) ), esc_html( $role ), $input, esc_html( $source ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $input is built from escaped parts above.
		}
		echo '</tbody></table>';
		submit_button( __( 'Save positions', 'rolewright' ) );
		echo '</form>';
	}

	private function render_effective(): void {
		$actor = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only lookup.
		$query = isset( $_GET['user'] ) ? sanitize_text_field( wp_unslash( $_GET['user'] ) ) : '';

		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::SLUG ) . '" /><input type="hidden" name="tab" value="effective" />';
		echo '<label for="rw-dh-user">' . esc_html__( 'User ID, login or email', 'rolewright' ) . '</label> ';
		echo '<input type="text" id="rw-dh-user" name="user" value="' . esc_attr( $query ) . '" /> ';
		submit_button( __( 'Show', 'rolewright' ), 'secondary', '', false );
		echo '</form>';

		if ( '' === $query ) {
			return;
		}
		$user = ctype_digit( $query ) ? get_userdata( (int) $query ) : false;
		if ( ! $user ) {
			$user = get_user_by( is_email( $query ) ? 'email' : 'login', $query );
		}
		if ( ! $user || ( $user->ID !== $actor && ( ! Hierarchy::can_act_on_user( $actor, $user->ID ) || ! Guard::can_act_on_user( $actor, $user->ID ) ) ) ) {
			echo '<p>' . esc_html__( 'No user you can view matches that.', 'rolewright' ) . '</p>';
			return;
		}

		$view = Effective::for_user( $user );
		printf(
			'<h2>%1$s</h2><p>%2$s</p>',
			esc_html( $user->display_name . ' (' . $user->user_login . ')' ),
			/* translators: 1: role list, 2: position */
			esc_html( sprintf( __( 'Roles: %1$s. Position: %2$d.', 'rolewright' ), $view['roles'] ? implode( ', ', array_map( array( __CLASS__, 'role_name' ), $view['roles'] ) ) : __( 'none', 'rolewright' ), $view['position'] ) )
		);
		if ( $view['super'] ) {
			echo '<p>' . esc_html__( 'This user is a super admin and passes every capability check except do_not_allow.', 'rolewright' ) . '</p>';
		}
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Capability', 'rolewright' ) . '</th><th>' . esc_html__( 'Granted by', 'rolewright' ) . '</th><th>' . esc_html__( 'Denied by', 'rolewright' ) . '</th><th>' . esc_html__( 'Effective', 'rolewright' ) . '</th></tr></thead><tbody>';
		foreach ( $view['caps'] as $cap => $row ) {
			$granted = array_map( array( __CLASS__, 'role_name' ), $row['granted_by'] );
			if ( $row['user_grant'] ) {
				$granted[] = __( 'per-user grant', 'rolewright' );
			}
			$denied = array_map( array( __CLASS__, 'role_name' ), $row['denied_by'] );
			if ( $row['denial_ignored'] ) {
				$denied[] = __( 'ignored for administrators', 'rolewright' );
			}
			printf(
				'<tr><td><code>%1$s</code></td><td>%2$s</td><td>%3$s</td><td>%4$s</td></tr>',
				esc_html( $cap ),
				esc_html( $granted ? implode( ', ', $granted ) : '—' ),
				esc_html( $denied ? implode( ', ', $denied ) : '—' ),
				$row['effective'] ? '<span style="color:#008a20">' . esc_html__( 'Yes', 'rolewright' ) . '</span>' : '<span style="color:#b32d2e">' . esc_html__( 'No', 'rolewright' ) . '</span>'
			);
		}
		echo '</tbody></table>';
	}

	private static function back( string $tab, $result, array $args = array() ): void {
		if ( is_wp_error( $result ) ) {
			set_transient( 'rolewright_dh_error_' . get_current_user_id(), $result->get_error_message(), 60 );
			$args['rw_error'] = 1;
		} else {
			$args['updated'] = 1;
		}
		wp_safe_redirect( self::url( $tab, $args ) );
		exit;
	}

	public function save_denials(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		$role = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
		check_admin_referer( 'rolewright_save_denials_' . $role );
		$denied = isset( $_POST['denied'] ) && is_array( $_POST['denied'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['denied'] ) ) : array();
		self::back( 'denials', Denials::save( get_current_user_id(), $role, $denied ), array( 'role' => $role ) );
	}

	public function save_positions(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'rolewright_save_positions' );
		$posted  = isset( $_POST['positions'] ) && is_array( $_POST['positions'] ) ? wp_unslash( $_POST['positions'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- keys and values are validated below.
		$changes = array();
		foreach ( $posted as $role => $pos ) {
			$changes[ sanitize_key( (string) $role ) ] = is_scalar( $pos ) ? trim( (string) $pos ) : '';
		}
		self::back( 'hierarchy', Hierarchy::save_positions( get_current_user_id(), $changes ) );
	}
}
