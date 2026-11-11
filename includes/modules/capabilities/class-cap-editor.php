<?php
namespace Rolegate\Modules\Capabilities;

use Rolegate\Modules\Roles\Role_Store;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Cap_Editor {
	/** @var array{errors:string[],posted:?string[],removed:string[]} */
	private $state = array(
		'errors'  => array(),
		'posted'  => null,
		'removed' => array(),
	);

	public function handle_post(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the nonce is checked below.
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) || ! isset( $_POST['rw_op'] ) ) {
			return;
		}
		if ( ! current_user_can( Caps::MANAGE_CAPS ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( Capabilities_Module::NONCE );

		$actor = get_current_user_id();
		$op    = sanitize_key( wp_unslash( $_POST['rw_op'] ) );
		$role  = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
		$msg   = '';
		$err   = null;

		if ( 'options' === $op ) {
			$sets                      = isset( $_POST['sets'] ) && is_array( $_POST['sets'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['sets'] ) ) : array();
			$cpts                      = isset( $_POST['cpts'] ) && is_array( $_POST['cpts'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['cpts'] ) ) : array();
			$res                       = Cap_Service::save_options( $actor, $sets, $cpts );
			is_wp_error( $res ) ? $err = $res : $msg = __( 'Capability options saved. New capabilities were given to roles that hold the matching core capability.', 'role-gatekeeper' );
		} elseif ( isset( $_POST['delete_cap'] ) ) {
			$cap                       = sanitize_text_field( wp_unslash( $_POST['delete_cap'] ) );
			$res                       = Cap_Service::delete_custom_cap( $actor, $cap );
			is_wp_error( $res ) ? $err = $res : $msg = __( 'Custom capability deleted.', 'role-gatekeeper' );
		} else {
			$granted = isset( $_POST['caps'] ) && is_array( $_POST['caps'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['caps'] ) ) : array();
			$new     = isset( $_POST['new_caps'] ) ? preg_split( '/[\s,]+/', sanitize_text_field( wp_unslash( $_POST['new_caps'] ) ), -1, PREG_SPLIT_NO_EMPTY ) : array();
			$level   = null;
			if ( isset( $_POST['level'] ) && '' !== $_POST['level'] ) {
				$raw   = sanitize_text_field( wp_unslash( $_POST['level'] ) );
				$level = 'none' === $raw ? -1 : max( 0, min( 10, (int) $raw ) );
			}
			$res = Cap_Service::update_role( $actor, $role, $granted, $level, (array) $new, ! empty( $_POST['confirm_self'] ) );
			if ( is_wp_error( $res ) ) {
				$err = $res;
				if ( 'rolegate_confirm' === $res->get_error_code() ) {
					$data                   = $res->get_error_data();
					$this->state['removed'] = isset( $data['removed'] ) ? (array) $data['removed'] : array();
				}
				$this->state['posted'] = $granted;
			} else {
				$msg = __( 'Capabilities saved.', 'role-gatekeeper' );
			}
		}

		if ( null === $this->state['posted'] ) {
			$notices = array();
			if ( '' !== $msg ) {
				$notices[] = array( 'success', $msg );
			}
			if ( $err ) {
				$notices[] = array( 'error', $err->get_error_message() );
			}
			set_transient( 'rolegate_caps_notice_' . $actor, $notices, 60 );
			wp_safe_redirect( Capabilities_Module::page_url( $role ? array( 'role' => $role ) : array() ) );
			exit;
		}
		$this->state['errors'][] = $err->get_error_message();
	}

	public function render(): void {
		if ( ! current_user_can( Caps::MANAGE_CAPS ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'role-gatekeeper' ) );
		}
		$actor = get_current_user_id();
		$roles = Role_Store::all();
		// phpcs:ignore WordPress.Security.NonceVerification
		$role = isset( $_REQUEST['role'] ) ? sanitize_key( wp_unslash( $_REQUEST['role'] ) ) : '';
		if ( ! isset( $roles[ $role ] ) ) {
			$role = isset( $roles['editor'] ) ? 'editor' : (string) key( $roles );
		}

		echo '<div class="wrap rw-caps"><h1>' . esc_html__( 'Capabilities', 'role-gatekeeper' ) . '</h1>';
		echo '<p class="description">' . wp_kses( __( 'Capabilities that can run code or take over the site need extra care to hand out. Add capabilities from other plugins to that list with the <code>rolegate_critical_caps</code> filter.', 'role-gatekeeper' ), array( 'code' => array() ) ) . '</p>';
		$notices = get_transient( 'rolegate_caps_notice_' . $actor );
		delete_transient( 'rolegate_caps_notice_' . $actor );
		foreach ( is_array( $notices ) ? $notices : array() as $n ) {
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $n[0] ), esc_html( $n[1] ) );
		}
		foreach ( $this->state['errors'] as $e ) {
			printf( '<div class="notice notice-error"><p>%s</p></div>', esc_html( $e ) );
		}

		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '"><input type="hidden" name="page" value="' . esc_attr( Capabilities_Module::SLUG ) . '" />';
		echo '<label for="rw-role">' . esc_html__( 'Role', 'role-gatekeeper' ) . '</label> <select id="rw-role" name="role" onchange="this.form.submit()">';
		foreach ( $roles as $slug => $data ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $slug ), selected( $slug, $role, false ), esc_html( $data['name'] ) );
		}
		echo '</select> <noscript><button class="button">' . esc_html__( 'Edit', 'role-gatekeeper' ) . '</button></noscript></form>';

		$this->render_editor( $actor, $role, $roles[ $role ] );
		$this->render_options();
		echo '</div>';
	}

	private function render_editor( int $actor, string $role, array $data ): void {
		$current = $data['caps'];
		$posted  = $this->state['posted'];
		$user    = get_userdata( $actor );
		$own     = $user && in_array( $role, (array) $user->roles, true );
		$groups  = Cap_Catalog::grouped( array_diff( Cap_Catalog::universe(), Cap_Service::level_caps() ) );
		$level   = Cap_Service::level_of( $current );

		echo '<form method="post" id="rw-caps-form" data-own="' . ( $own ? '1' : '0' ) . '" action="' . esc_url( Capabilities_Module::page_url( array( 'role' => $role ) ) ) . '">';
		wp_nonce_field( Capabilities_Module::NONCE );
		echo '<input type="hidden" name="rw_op" value="save" /><input type="hidden" name="role" value="' . esc_attr( $role ) . '" />';

		echo '<div class="rw-toolbar"><p><label for="rw-search" class="screen-reader-text">' . esc_html__( 'Filter capabilities', 'role-gatekeeper' ) . '</label>';
		echo '<input type="search" id="rw-search" placeholder="' . esc_attr__( 'Filter capabilities', 'role-gatekeeper' ) . '" /> ';
		echo '<label><input type="checkbox" id="rw-show-deprecated" /> ' . esc_html__( 'Show deprecated capabilities', 'role-gatekeeper' ) . '</label> ';
		echo '<label for="rw-level">' . esc_html__( 'Role level', 'role-gatekeeper' ) . '</label> <select id="rw-level" name="level"><option value="">' . esc_html__( 'Leave as is', 'role-gatekeeper' ) . '</option>';
		echo '<option value="none">' . esc_html__( 'No level', 'role-gatekeeper' ) . '</option>';
		for ( $i = 0; $i <= 10; $i++ ) {
			printf( '<option value="%1$d">%1$d</option>', (int) $i );
		}
		echo '</select> <span class="description">' . esc_html( -1 === $level ? __( 'Current: none', 'role-gatekeeper' ) : sprintf( /* translators: %d: level */ __( 'Current: %d', 'role-gatekeeper' ), $level ) ) . '</span></p></div>';

		if ( $this->state['removed'] ) {
			echo '<div class="notice notice-warning inline"><p><label><input type="checkbox" name="confirm_self" value="1" /> ';
			/* translators: %s: list of capability names */
			echo esc_html( sprintf( __( 'I confirm removing these capabilities from my own role: %s', 'role-gatekeeper' ), implode( ', ', $this->state['removed'] ) ) );
			echo '</label></p></div>';
		}

		foreach ( $groups as $id => $group ) {
			$deprecated = 'deprecated' === $id;
			printf( '<fieldset class="rw-group%s" data-group="%s"%s>', $deprecated ? ' rw-deprecated' : '', esc_attr( $id ), $deprecated ? ' hidden' : '' );
			echo '<legend>' . esc_html( $group['label'] ) . '</legend>';
			echo '<label class="rw-select-all"><input type="checkbox" class="rw-all" /> ' . esc_html__( 'Select all', 'role-gatekeeper' ) . '</label>';
			echo '<div class="rw-caps-grid">';
			foreach ( $group['caps'] as $cap ) {
				$on    = null === $posted ? ! empty( $current[ $cap ] ) : in_array( $cap, $posted, true );
				$label = Cap_Catalog::label( $cap );
				printf(
					'<label class="rw-cap" data-search="%1$s"><input type="checkbox" name="caps[]" value="%2$s"%3$s /> %4$s <code>%2$s</code></label>',
					esc_attr( strtolower( $label . ' ' . $cap ) ),
					esc_attr( $cap ),
					checked( $on, true, false ),
					esc_html( $label )
				);
			}
			echo '</div>';
			if ( 'custom' === $id ) {
				foreach ( $group['caps'] as $cap ) {
					printf(
						'<button type="submit" name="delete_cap" value="%1$s" class="button-link button-link-delete rw-del" formnovalidate>%2$s</button> ',
						esc_attr( $cap ),
						/* translators: %s: capability name */
						esc_html( sprintf( __( 'Delete %s', 'role-gatekeeper' ), $cap ) )
					);
				}
			}
			echo '</fieldset>';
		}

		echo '<h2>' . esc_html__( 'Add custom capabilities', 'role-gatekeeper' ) . '</h2><p>';
		echo '<label for="rw-new-caps" class="screen-reader-text">' . esc_html__( 'New capabilities', 'role-gatekeeper' ) . '</label>';
		echo '<input type="text" id="rw-new-caps" name="new_caps" class="regular-text" placeholder="manage_reports, view_invoices" /> ';
		echo '<span class="description">' . esc_html__( 'Separate names with commas. They are added to this role.', 'role-gatekeeper' ) . '</span></p>';

		submit_button( __( 'Save capabilities', 'role-gatekeeper' ) );
		echo '</form>';
	}

	private function render_options(): void {
		echo '<h2>' . esc_html__( 'Extra capability options', 'role-gatekeeper' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( Capabilities_Module::page_url() ) . '">';
		wp_nonce_field( Capabilities_Module::NONCE );
		echo '<input type="hidden" name="rw_op" value="options" />';
		$enabled = Cap_Sets::enabled();
		foreach ( Cap_Sets::definitions() as $id => $def ) {
			printf(
				'<p><label><input type="checkbox" name="sets[]" value="%1$s"%2$s /> %3$s</label><br /><span class="description">%4$s</span></p>',
				esc_attr( $id ),
				checked( in_array( $id, $enabled, true ), true, false ),
				esc_html( $def['label'] ),
				esc_html( $def['description'] )
			);
		}
		echo '<h3>' . esc_html__( 'Own capabilities per custom post type', 'role-gatekeeper' ) . '</h3>';
		$types = Cap_Sets::eligible_post_types();
		if ( $types ) {
			echo '<p class="description">' . esc_html__( 'Selected post types get their own capability names, for example edit_books instead of edit_posts. Roles that hold the matching post capability receive the new ones.', 'role-gatekeeper' ) . '</p>';
			foreach ( $types as $slug => $label ) {
				printf(
					'<label style="display:block"><input type="checkbox" name="cpts[]" value="%1$s"%2$s /> %3$s <code>%1$s</code></label>',
					esc_attr( $slug ),
					checked( in_array( $slug, Cap_Sets::cpt_own(), true ), true, false ),
					esc_html( $label )
				);
			}
		} else {
			echo '<p class="description">' . esc_html__( 'No custom post types are using the default post capabilities.', 'role-gatekeeper' ) . '</p>';
		}
		submit_button( __( 'Save options', 'role-gatekeeper' ), 'secondary' );
		echo '</form>';
	}
}
