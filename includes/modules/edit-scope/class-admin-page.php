<?php
namespace Rolewright\Modules\Edit_Scope;

use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Admin_Page {
	const SLUG = 'rolewright-edit-scope';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolewright_edit_scope_add', array( $this, 'handle_add' ) );
		add_action( 'admin_post_rolewright_edit_scope_delete', array( $this, 'handle_delete' ) );
		add_action( 'admin_post_rolewright_edit_scope_settings', array( $this, 'handle_settings' ) );
	}

	public function menu(): void {
		add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Edit scope', 'rolewright' ),
			__( 'Edit scope', 'rolewright' ),
			Caps::MANAGE_ACCESS,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	private function back( string $notice = '' ): void {
		if ( $notice ) {
			set_transient( 'rolewright_es_notice_' . get_current_user_id(), $notice, 60 );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SLUG ) );
		exit;
	}

	private function guard( string $nonce_action ): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'rolewright' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	public function handle_add(): void {
		$this->guard( 'rolewright_edit_scope_add' );
		// phpcs:ignore WordPress.Security.NonceVerification -- checked in guard().
		$in      = wp_unslash( $_POST );
		$by      = isset( $in['by'] ) ? sanitize_key( $in['by'] ) : '';
		$type    = isset( $in['subject_type'] ) ? sanitize_key( $in['subject_type'] ) : '';
		$subject = '';
		if ( 'role' === $type ) {
			$subject = isset( $in['role'] ) ? sanitize_key( $in['role'] ) : '';
		} elseif ( isset( $in['user'] ) ) {
			$login   = sanitize_text_field( $in['user'] );
			$user    = is_numeric( $login ) ? get_userdata( (int) $login ) : get_user_by( 'login', $login );
			$subject = $user ? (string) $user->ID : '';
		}
		$ids = preg_split( '/[\s,]+/', isset( $in['ids'] ) ? sanitize_text_field( $in['ids'] ) : '', -1, PREG_SPLIT_NO_EMPTY );
		$res = Rules::add(
			get_current_user_id(),
			array(
				'subject_type' => $type,
				'subject'      => $subject,
				'mode'         => isset( $in['mode'] ) ? sanitize_key( $in['mode'] ) : '',
				'by'           => $by,
				'ids'          => $ids ? $ids : array(),
				'children'     => ! empty( $in['children'] ),
				'taxonomy'     => isset( $in['taxonomy'] ) ? sanitize_key( $in['taxonomy'] ) : '',
			)
		);
		$this->back( is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'ok:' . __( 'Rule added.', 'rolewright' ) );
	}

	public function handle_delete(): void {
		$this->guard( 'rolewright_edit_scope_delete' );
		// phpcs:ignore WordPress.Security.NonceVerification -- checked in guard().
		$id  = isset( $_POST['rule'] ) ? sanitize_key( wp_unslash( $_POST['rule'] ) ) : '';
		$res = Rules::delete( get_current_user_id(), $id );
		$this->back( is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'ok:' . __( 'Rule deleted.', 'rolewright' ) );
	}

	public function handle_settings(): void {
		$this->guard( 'rolewright_edit_scope_settings' );
		// phpcs:ignore WordPress.Security.NonceVerification -- checked in guard().
		$res = Rules::save_settings( get_current_user_id(), ! empty( $_POST['hide_in_lists'] ) );
		$this->back( is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'ok:' . __( 'Settings saved.', 'rolewright' ) );
	}

	private function subject_label( array $rule ): string {
		if ( 'role' === $rule['subject_type'] ) {
			$roles = wp_roles()->get_names();
			return isset( $roles[ $rule['subject'] ] ) ? translate_user_role( $roles[ $rule['subject'] ] ) : $rule['subject'];
		}
		$user = get_userdata( (int) $rule['subject'] );
		return $user ? $user->user_login : '#' . $rule['subject'];
	}

	private function kind_label( string $by ): string {
		$labels = array(
			'post'    => __( 'Post IDs', 'rolewright' ),
			'author'  => __( 'Author IDs', 'rolewright' ),
			'term'    => __( 'Term IDs', 'rolewright' ),
			'assign'  => __( 'Assignable terms', 'rolewright' ),
			'gf_form' => __( 'Gravity Forms form IDs', 'rolewright' ),
		);
		return isset( $labels[ $by ] ) ? $labels[ $by ] : $by;
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_ACCESS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'rolewright' ) );
		}
		$key    = 'rolewright_es_notice_' . get_current_user_id();
		$notice = get_transient( $key );
		delete_transient( $key );

		echo '<div class="wrap"><h1>' . esc_html__( 'Edit scope', 'rolewright' ) . '</h1>';
		if ( is_string( $notice ) && false !== strpos( $notice, ':' ) ) {
			list( $kind, $msg ) = explode( ':', $notice, 2 );
			printf( '<div class="notice notice-%s"><p>%s</p></div>', 'error' === $kind ? 'error' : 'success', esc_html( $msg ) );
		}
		echo '<p>' . esc_html__( 'An allow rule limits a role or user to the listed items. A block rule removes them. Users who can manage access rules are never restricted.', 'rolewright' ) . '</p>';

		$this->render_rules();
		$this->render_add_form();
		$this->render_settings();
		echo '</div>';
	}

	private function render_rules(): void {
		$rules = Rules::all();
		echo '<h2>' . esc_html__( 'Rules', 'rolewright' ) . '</h2>';
		if ( ! $rules ) {
			echo '<p>' . esc_html__( 'No rules yet.', 'rolewright' ) . '</p>';
			return;
		}
		echo '<div class="rw-scroll" style="overflow-x:auto"><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Applies to', 'rolewright' ) . '</th><th>' . esc_html__( 'Mode', 'rolewright' ) . '</th><th>' . esc_html__( 'Type', 'rolewright' ) . '</th><th>' . esc_html__( 'IDs', 'rolewright' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $rules as $rule ) {
			$type = 'role' === $rule['subject_type'] ? __( 'Role', 'rolewright' ) : __( 'User', 'rolewright' );
			$kind = $this->kind_label( $rule['by'] );
			if ( $rule['taxonomy'] ) {
				$kind .= ' (' . $rule['taxonomy'] . ')';
			}
			if ( $rule['children'] ) {
				$kind .= ', ' . __( 'with children', 'rolewright' );
			}
			echo '<tr><td>' . esc_html( $type . ': ' . $this->subject_label( $rule ) ) . '</td>';
			echo '<td>' . esc_html( 'allow' === $rule['mode'] ? __( 'Allow only', 'rolewright' ) : __( 'Block', 'rolewright' ) ) . '</td>';
			echo '<td>' . esc_html( $kind ) . '</td><td>' . esc_html( implode( ', ', $rule['ids'] ) ) . '</td><td>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="rolewright_edit_scope_delete" /><input type="hidden" name="rule" value="' . esc_attr( $rule['id'] ) . '" />';
			wp_nonce_field( 'rolewright_edit_scope_delete' );
			submit_button( __( 'Delete', 'rolewright' ), 'small', '', false );
			echo '</form></td></tr>';
		}
		echo '</tbody></table></div>';
	}

	private function render_add_form(): void {
		echo '<h2>' . esc_html__( 'Add a rule', 'rolewright' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="rolewright_edit_scope_add" />';
		wp_nonce_field( 'rolewright_edit_scope_add' );
		echo '<table class="form-table" role="presentation"><tbody>';

		echo '<tr><th scope="row"><label for="rw-es-type">' . esc_html__( 'Applies to', 'rolewright' ) . '</label></th><td>';
		echo '<select name="subject_type" id="rw-es-type"><option value="role">' . esc_html__( 'Role', 'rolewright' ) . '</option><option value="user">' . esc_html__( 'User', 'rolewright' ) . '</option></select> ';
		echo '<select name="role" aria-label="' . esc_attr__( 'Role', 'rolewright' ) . '">';
		foreach ( wp_roles()->roles as $slug => $role ) {
			if ( ! empty( $role['capabilities'][ Caps::MANAGE_ACCESS ] ) ) {
				continue;
			}
			echo '<option value="' . esc_attr( $slug ) . '">' . esc_html( translate_user_role( $role['name'] ) ) . '</option>';
		}
		echo '</select> <input type="text" name="user" aria-label="' . esc_attr__( 'User', 'rolewright' ) . '" placeholder="' . esc_attr__( 'Username or user ID', 'rolewright' ) . '" />';
		echo '<p class="description">' . esc_html__( 'Use the role field for a role, the user field for a single user.', 'rolewright' ) . '</p></td></tr>';

		echo '<tr><th scope="row"><label for="rw-es-mode">' . esc_html__( 'Mode', 'rolewright' ) . '</label></th><td><select name="mode" id="rw-es-mode"><option value="allow">' . esc_html__( 'Allow only these', 'rolewright' ) . '</option><option value="block">' . esc_html__( 'Block these', 'rolewright' ) . '</option></select></td></tr>';

		echo '<tr><th scope="row"><label for="rw-es-by">' . esc_html__( 'Match by', 'rolewright' ) . '</label></th><td><select name="by" id="rw-es-by">';
		foreach ( Rules::allowed_kinds() as $kind ) {
			echo '<option value="' . esc_attr( $kind ) . '">' . esc_html( $this->kind_label( $kind ) ) . '</option>';
		}
		echo '</select> <select name="taxonomy" aria-label="' . esc_attr__( 'Taxonomy', 'rolewright' ) . '"><option value="">' . esc_html__( 'Taxonomy (assignable terms only)', 'rolewright' ) . '</option>';
		foreach ( get_taxonomies( array( 'show_ui' => true ), 'objects' ) as $tax ) {
			echo '<option value="' . esc_attr( $tax->name ) . '">' . esc_html( $tax->label ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr><th scope="row"><label for="rw-es-ids">' . esc_html__( 'IDs', 'rolewright' ) . '</label></th><td><input type="text" class="regular-text" name="ids" id="rw-es-ids" placeholder="12, 40, 77" />';
		echo '<p><label><input type="checkbox" name="children" value="1" /> ' . esc_html__( 'Include child terms (term rules)', 'rolewright' ) . '</label></p></td></tr>';
		echo '</tbody></table>';
		submit_button( __( 'Add rule', 'rolewright' ) );
		echo '</form>';
	}

	private function render_settings(): void {
		echo '<h2>' . esc_html__( 'Lists', 'rolewright' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="rolewright_edit_scope_settings" />';
		wp_nonce_field( 'rolewright_edit_scope_settings' );
		echo '<p><label><input type="checkbox" name="hide_in_lists" value="1" ' . checked( Rules::hide_in_lists(), true, false ) . ' /> ' . esc_html__( 'Hide items a user cannot edit from lists and REST queries (otherwise they stay visible and read-only).', 'rolewright' ) . '</label></p>';
		submit_button( __( 'Save', 'rolewright' ) );
		echo '</form>';
	}
}
