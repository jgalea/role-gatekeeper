<?php
namespace Rolewright\Modules\Roles;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Role_List {
	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ROLES ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		$actor   = get_current_user_id();
		$roles   = Role_Store::all();
		$counts  = Role_Store::user_counts();
		$default = (string) get_option( 'default_role' );
		$extras  = Role_Service::extra_default_roles();
		$notices = get_transient( 'rolewright_roles_notice_' . $actor );
		delete_transient( 'rolewright_roles_notice_' . $actor );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only view selector.
		$do = isset( $_GET['do'] ) ? sanitize_key( wp_unslash( $_GET['do'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$target = isset( $_GET['role'] ) ? sanitize_key( wp_unslash( $_GET['role'] ) ) : '';

		echo '<div class="wrap"><h1>' . esc_html__( 'Roles', 'rolewright' ) . '</h1>';
		foreach ( is_array( $notices ) ? $notices : array() as $n ) {
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $n[0] ), esc_html( $n[1] ) );
		}

		if ( in_array( $do, array( 'rename', 'clone' ), true ) && isset( $roles[ $target ] ) ) {
			$this->render_name_form( $do, $target, $roles[ $target ]['name'] );
		}

		$this->render_add_form();
		$this->render_table( $actor, $roles, $counts, $default, $extras );
		$this->render_defaults( $roles, $default, $extras );
		$this->render_reset();
		echo '</div>';
	}

	private function form_open( string $op, string $extra_attr = '' ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" ' . $extra_attr . '>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<input type="hidden" name="action" value="' . esc_attr( Roles_Module::ACTION ) . '" />';
		echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '" />';
		wp_nonce_field( Roles_Module::ACTION );
	}

	private function render_name_form( string $do, string $role, string $current ): void {
		$title = 'rename' === $do
			/* translators: %s: role name */
			? sprintf( __( 'Rename "%s"', 'rolewright' ), $current )
			/* translators: %s: role name */
			: sprintf( __( 'Clone "%s"', 'rolewright' ), $current );
		echo '<h2>' . esc_html( $title ) . '</h2>';
		$this->form_open( $do );
		echo '<input type="hidden" name="role" value="' . esc_attr( $role ) . '" />';
		echo '<p><label for="rw-name">' . esc_html__( 'Name', 'rolewright' ) . '</label> ';
		echo '<input type="text" id="rw-name" name="name" class="regular-text" required value="' . esc_attr( 'rename' === $do ? $current : '' ) . '" /> ';
		submit_button( 'rename' === $do ? __( 'Rename role', 'rolewright' ) : __( 'Clone role', 'rolewright' ), 'primary', '', false );
		echo ' <a href="' . esc_url( Roles_Module::page_url() ) . '" class="button">' . esc_html__( 'Cancel', 'rolewright' ) . '</a></p></form>';
	}

	private function render_add_form(): void {
		echo '<h2>' . esc_html__( 'Add role', 'rolewright' ) . '</h2>';
		$this->form_open( 'create' );
		echo '<p><label for="rw-new-role">' . esc_html__( 'Name', 'rolewright' ) . '</label> ';
		echo '<input type="text" id="rw-new-role" name="name" class="regular-text" required /> ';
		submit_button( __( 'Add role', 'rolewright' ), 'secondary', '', false );
		echo '</p><p class="description">' . esc_html__( 'New roles start with the read capability. Edit the rest under Capabilities.', 'rolewright' ) . '</p></form>';
	}

	private function render_table( int $actor, array $roles, array $counts, string $default, array $extras ): void {
		echo '<h2>' . esc_html__( 'All roles', 'rolewright' ) . '</h2>';
		$this->form_open( 'bulk_delete', 'id="rw-bulk"' );
		echo '<p><button type="submit" class="button action" onclick="return confirm(\'' . esc_js( __( 'Delete the selected roles?', 'rolewright' ) ) . '\');">' . esc_html__( 'Delete selected', 'rolewright' ) . '</button> ';
		echo '<span class="description">' . esc_html__( 'Only roles without users can be deleted.', 'rolewright' ) . '</span></p>';
		echo '<table class="wp-list-table widefat fixed striped"><thead><tr>';
		echo '<td class="manage-column check-column"></td>';
		echo '<th>' . esc_html__( 'Role', 'rolewright' ) . '</th><th>' . esc_html__( 'Slug', 'rolewright' ) . '</th>';
		echo '<th>' . esc_html__( 'Users', 'rolewright' ) . '</th><th>' . esc_html__( 'Capabilities', 'rolewright' ) . '</th><th>' . esc_html__( 'Actions', 'rolewright' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $roles as $slug => $data ) {
			$users     = isset( $counts[ $slug ] ) ? $counts[ $slug ] : 0;
			$protected = Guard::is_protected_role( $slug );
			$deletable = ! $protected && 0 === $users;
			echo '<tr><th scope="row" class="check-column">';
			if ( $deletable ) {
				echo '<input type="checkbox" name="roles[]" value="' . esc_attr( $slug ) . '" aria-label="' . esc_attr( $data['name'] ) . '" />';
			}
			echo '</th><td><strong>' . esc_html( $data['name'] ) . '</strong>';
			if ( $slug === $default ) {
				echo ' <span class="description">' . esc_html__( '(default)', 'rolewright' ) . '</span>';
			} elseif ( in_array( $slug, $extras, true ) ) {
				echo ' <span class="description">' . esc_html__( '(also assigned at registration)', 'rolewright' ) . '</span>';
			}
			if ( $protected ) {
				echo ' <span class="description">' . esc_html__( '(protected)', 'rolewright' ) . '</span>';
			}
			echo '</td><td><code>' . esc_html( $slug ) . '</code></td>';
			echo '<td>' . esc_html( number_format_i18n( $users ) ) . '</td>';
			echo '<td>' . esc_html( number_format_i18n( Role_Store::granted_count( $data['caps'] ) ) ) . '</td><td>';

			$links = array();
			if ( current_user_can( Caps::MANAGE_CAPS ) ) {
				$links[] = '<a href="' . esc_url( admin_url( 'admin.php?page=rolewright-capabilities&role=' . rawurlencode( $slug ) ) ) . '">' . esc_html__( 'Capabilities', 'rolewright' ) . '</a>';
			}
			if ( 'administrator' !== $slug ) {
				$links[] = '<a href="' . esc_url(
					Roles_Module::page_url(
						array(
							'do'   => 'rename',
							'role' => $slug,
						)
					)
				) . '">' . esc_html__( 'Rename', 'rolewright' ) . '</a>';
			}
			$links[] = '<a href="' . esc_url(
				Roles_Module::page_url(
					array(
						'do'   => 'clone',
						'role' => $slug,
					)
				)
			) . '">' . esc_html__( 'Clone', 'rolewright' ) . '</a>';
			echo implode( ' | ', $links ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts.
			if ( $deletable ) {
				echo ' | <button type="submit" form="rw-del-' . esc_attr( $slug ) . '" class="button-link button-link-delete" onclick="return confirm(\'' . esc_js( __( 'Delete this role?', 'rolewright' ) ) . '\');">' . esc_html__( 'Delete', 'rolewright' ) . '</button>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></form>';

		foreach ( $roles as $slug => $data ) {
			if ( ! Guard::is_protected_role( $slug ) && empty( $counts[ $slug ] ) ) {
				$this->form_open( 'delete', 'id="rw-del-' . esc_attr( $slug ) . '"' );
				echo '<input type="hidden" name="role" value="' . esc_attr( $slug ) . '" /></form>';
			}
		}
	}

	private function render_defaults( array $roles, string $default, array $extras ): void {
		echo '<h2>' . esc_html__( 'Default registration roles', 'rolewright' ) . '</h2>';
		$this->form_open( 'default' );
		echo '<p><label for="rw-default">' . esc_html__( 'New users get the role', 'rolewright' ) . '</label> <select id="rw-default" name="role">';
		foreach ( $roles as $slug => $data ) {
			if ( ! Guard::critical_subset( $data['caps'] ) ) {
				printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $slug ), selected( $slug, $default, false ), esc_html( $data['name'] ) );
			}
		}
		echo '</select></p><fieldset><legend>' . esc_html__( 'and also these roles', 'rolewright' ) . '</legend>';
		foreach ( $roles as $slug => $data ) {
			if ( ! Guard::critical_subset( $data['caps'] ) ) {
				printf(
					'<label style="display:block"><input type="checkbox" name="extras[]" value="%1$s"%2$s /> %3$s</label>',
					esc_attr( $slug ),
					checked( in_array( $slug, $extras, true ), true, false ),
					esc_html( $data['name'] )
				);
			}
		}
		echo '</fieldset><p class="description">' . esc_html__( 'Roles with powerful capabilities are not offered here.', 'rolewright' ) . '</p>';
		submit_button( __( 'Save default roles', 'rolewright' ), 'secondary' );
		echo '</form>';
	}

	private function render_reset(): void {
		echo '<h2>' . esc_html__( 'Reset roles', 'rolewright' ) . '</h2>';
		$this->form_open( 'reset' );
		echo '<p>' . esc_html__( 'Puts Administrator, Editor, Author, Contributor and Subscriber back to the WordPress defaults. Capabilities that plugins added to these roles are removed. Custom roles are left alone. The current roles are saved as a backup first.', 'rolewright' ) . '</p>';
		echo '<p><label><input type="checkbox" name="confirm_reset" value="1" /> ' . esc_html__( 'I understand that plugin-added capabilities on the core roles will be removed.', 'rolewright' ) . '</label></p>';
		submit_button( __( 'Reset roles', 'rolewright' ), 'delete' );
		echo '</form>';
		$backups = Role_Service::backups();
		if ( $backups ) {
			/* translators: %s: date and time of the latest backup */
			echo '<p class="description">' . esc_html( sprintf( __( 'Latest backup: %s.', 'rolewright' ), wp_date( 'Y-m-d H:i', (int) $backups[0]['time'] ) ) ) . '</p>';
		}
	}
}
