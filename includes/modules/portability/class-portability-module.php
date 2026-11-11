<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Module;
use Rolegate\Core\Settings;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

final class Portability_Module extends Module {
	const SLUG        = 'role-gatekeeper-portability';
	const PENDING_TTL = HOUR_IN_SECONDS;
	const PENDING_KEY = 'rolegate_import_pending_';
	const NOTICE_KEY  = 'rolegate_portability_notice_';

	public function id(): string {
		return 'portability';
	}

	public function title(): string {
		return __( 'Import and export', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Export roles to a JSON file and import them on another site, with a preview and confirmation before anything changes.', 'role-gatekeeper' );
	}

	public function init(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolegate_portability_export', array( $this, 'handle_export' ) );
		add_action( 'admin_post_rolegate_portability_preview', array( $this, 'handle_preview' ) );
		add_action( 'admin_post_rolegate_portability_apply', array( $this, 'handle_apply' ) );
		add_action( 'admin_post_rolegate_migrate_apply', array( $this, 'handle_migrate' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'rolegate migrate', Cli_Migrate::class );
		}
	}

	public function menu(): void {
		add_submenu_page( Settings::MENU_SLUG, __( 'Import and export', 'role-gatekeeper' ), __( 'Import and export', 'role-gatekeeper' ), Caps::IMPORT, self::SLUG, array( $this, 'render' ) );
	}

	private function page_url( array $args = array() ): string {
		return add_query_arg( $args, admin_url( 'admin.php?page=' . self::SLUG ) );
	}

	private function deny(): void {
		wp_die( esc_html__( 'You do not have permission to do that.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
	}

	private function notice( string $type, string $message ): void {
		set_transient( self::NOTICE_KEY . get_current_user_id(), array( $type, $message ), 5 * MINUTE_IN_SECONDS );
	}

	private function pending_key( string $token ): string {
		return self::PENDING_KEY . get_current_user_id() . '_' . $token;
	}

	public function handle_export(): void {
		if ( ! current_user_can( Caps::IMPORT ) ) {
			$this->deny();
		}
		check_admin_referer( 'rolegate_portability_export' );
		$roles    = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['roles'] ) ) : array();
		$sections = isset( $_POST['sections'] ) && is_array( $_POST['sections'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) ) : array();
		if ( ! $roles && ! $sections ) {
			$this->notice( 'error', __( 'Pick at least one role or section to export.', 'role-gatekeeper' ) );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		$json = Exporter::to_json( Exporter::build( $roles, $sections, get_current_user_id() ) );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="role-gatekeeper-roles-' . gmdate( 'Y-m-d' ) . '.json"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download, not HTML.
		exit;
	}

	public function handle_preview(): void {
		if ( ! current_user_can( Caps::IMPORT ) ) {
			$this->deny();
		}
		check_admin_referer( 'rolegate_portability_preview' );
		$source = isset( $_POST['source'] ) ? sanitize_key( wp_unslash( $_POST['source'] ) ) : 'file';
		$mode   = isset( $_POST['mode'] ) && 'merge' === $_POST['mode'] ? 'merge' : 'replace';

		if ( 'file' === $source ) {
			$json = '';
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- uploaded file checked below.
			$file = isset( $_FILES['rolegate_file'] ) && is_array( $_FILES['rolegate_file'] ) ? $_FILES['rolegate_file'] : null;
			if ( $file && isset( $file['tmp_name'], $file['size'], $file['error'] ) && UPLOAD_ERR_OK === (int) $file['error'] && is_uploaded_file( $file['tmp_name'] ) ) {
				if ( (int) $file['size'] > Importer::max_bytes() ) {
					$this->notice( 'error', __( 'The file is larger than the import size limit.', 'role-gatekeeper' ) );
					wp_safe_redirect( $this->page_url() );
					exit;
				}
				$json = (string) file_get_contents( $file['tmp_name'], false, null, 0, Importer::max_bytes() + 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local upload.
			} elseif ( isset( $_POST['rolegate_json'] ) ) {
				// JSON is validated field by field in Importer::parse; sanitize_text_field would corrupt it.
				$json = (string) wp_unslash( $_POST['rolegate_json'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			}
			$payload = Importer::parse( $json );
		} else {
			$payload = Sources::load( $source );
		}

		if ( is_wp_error( $payload ) ) {
			$this->notice( 'error', $payload->get_error_message() );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		$token = wp_generate_password( 20, false, false );
		set_transient(
			$this->pending_key( $token ),
			array(
				'payload' => $payload,
				'mode'    => $mode,
			),
			self::PENDING_TTL
		);
		wp_safe_redirect( $this->page_url( array( 'preview' => $token ) ) );
		exit;
	}

	public function handle_apply(): void {
		if ( ! current_user_can( Caps::IMPORT ) ) {
			$this->deny();
		}
		$token = isset( $_POST['token'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', (string) wp_unslash( $_POST['token'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- reduced to letters and digits by preg_replace.
		check_admin_referer( 'rolegate_portability_apply_' . $token );
		$pending = '' === $token ? false : get_transient( $this->pending_key( $token ) );
		if ( ! is_array( $pending ) || ! isset( $pending['payload'] ) ) {
			$this->notice( 'error', __( 'That import preview has expired. Upload the file again.', 'role-gatekeeper' ) );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		if ( empty( $_POST['reviewed'] ) ) {
			$this->notice( 'error', __( 'Tick the box to confirm you reviewed the changes.', 'role-gatekeeper' ) );
			wp_safe_redirect( $this->page_url( array( 'preview' => $token ) ) );
			exit;
		}
		$args   = array(
			'mode'             => $pending['mode'],
			'roles'            => isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['roles'] ) ) : array(),
			'confirm_critical' => isset( $_POST['confirm_critical'] ) && is_array( $_POST['confirm_critical'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['confirm_critical'] ) ) : array(),
			'sections'         => isset( $_POST['sections'] ) && is_array( $_POST['sections'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) ) : array(),
		);
		$result = Importer::apply( $pending['payload'], get_current_user_id(), $args );
		if ( is_wp_error( $result ) ) {
			$this->notice( 'error', $result->get_error_message() );
			wp_safe_redirect( $this->page_url( array( 'preview' => $token ) ) );
			exit;
		}
		delete_transient( $this->pending_key( $token ) );
		$message = sprintf(
			/* translators: 1: number of roles, 2: backup id */
			__( 'Imported %1$d role(s). The previous roles were saved as backup %2$s.', 'role-gatekeeper' ),
			count( $result['roles'] ),
			$result['backup_id']
		);
		if ( $result['errors'] ) {
			$message .= ' ' . implode( ' ', $result['errors'] );
		}
		$this->notice( $result['errors'] ? 'warning' : 'success', $message );
		wp_safe_redirect( $this->page_url() );
		exit;
	}

	private function can_migrate(): bool {
		return current_user_can( Caps::IMPORT ) && Guard::is_site_authority( get_current_user_id() );
	}

	public function handle_migrate(): void {
		if ( ! $this->can_migrate() ) {
			$this->deny();
		}
		$source = isset( $_POST['source'] ) ? sanitize_key( wp_unslash( $_POST['source'] ) ) : '';
		if ( ! isset( Migrator::sources()[ $source ] ) ) {
			$this->deny();
		}
		check_admin_referer( 'rolegate_migrate_apply_' . $source );
		$back = $this->page_url( array( 'migrate' => $source ) );
		if ( empty( $_POST['reviewed'] ) ) {
			$this->notice( 'error', __( 'Tick the box to confirm you reviewed the changes.', 'role-gatekeeper' ) );
			wp_safe_redirect( $back );
			exit;
		}
		$result = Migrator::apply( $source, get_current_user_id(), array( 'confirm_private' => ! empty( $_POST['confirm_private'] ) ) );
		if ( is_wp_error( $result ) ) {
			$this->notice( 'error', $result->get_error_message() );
			wp_safe_redirect( $back );
			exit;
		}
		if ( 'unchanged' === $result['status'] ) {
			$this->notice( 'success', __( 'Nothing to change: everything is already carried over.', 'role-gatekeeper' ) );
		} else {
			$message = sprintf(
				/* translators: 1: migration id, 2: backup id */
				__( 'Migration %1$s applied. The roles were backed up as %2$s, and the audit log can revert it.', 'role-gatekeeper' ),
				$result['migration_id'],
				$result['backup_id']
			);
			if ( $result['errors'] ) {
				$message .= ' ' . implode( ' ', $result['errors'] );
			}
			$this->notice( $result['errors'] ? 'warning' : 'success', $message );
		}
		wp_safe_redirect( $back );
		exit;
	}

	private function render_migrate(): void {
		if ( ! $this->can_migrate() ) {
			return;
		}
		$found = array();
		foreach ( Migrator::sources() as $id => $class ) {
			$plan = Migrator::plan( $id, get_current_user_id() );
			if ( ! is_wp_error( $plan ) && $plan['detected'] ) {
				$found[ $id ] = $plan['label'];
			}
		}
		echo '<h2>' . esc_html__( 'Migrate from another plugin', 'role-gatekeeper' ) . '</h2>';
		if ( ! $found ) {
			echo '<p>' . esc_html__( 'No data from Members, User Role Editor, Disable Users or Adminimize was found on this site.', 'role-gatekeeper' ) . '</p>';
			return;
		}
		echo '<p>' . esc_html__( 'Carries their settings and rules over. Their own data stays as it is, and nothing changes until you confirm on the next screen.', 'role-gatekeeper' ) . '</p><p>';
		foreach ( $found as $id => $label ) {
			/* translators: %s: plugin name */
			echo '<a class="button" href="' . esc_url( $this->page_url( array( 'migrate' => $id ) ) ) . '">' . esc_html( sprintf( __( 'Preview migration from %s', 'role-gatekeeper' ), $label ) ) . '</a> ';
		}
		echo '</p>';
	}

	private function render_migration_preview( string $source ): void {
		$plan = Migrator::plan( $source, get_current_user_id(), array( 'confirm_private' => true ) );
		if ( is_wp_error( $plan ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $plan->get_error_message() ) . '</p></div>';
			return;
		}
		$labels = Migrator::action_labels();
		/* translators: %s: plugin name */
		echo '<h2>' . esc_html( sprintf( __( 'Migrate from %s', 'role-gatekeeper' ), $plan['label'] ) ) . '</h2>';
		echo '<div class="rw-scroll" style="overflow-x:auto"><table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Area', 'role-gatekeeper' ), __( 'Item', 'role-gatekeeper' ), __( 'Change', 'role-gatekeeper' ), __( 'Details', 'role-gatekeeper' ) ) as $head ) {
			echo '<th scope="col">' . esc_html( $head ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		$private = false;
		foreach ( $plan['rows'] as $row ) {
			$color = in_array( $row['action'], array( 'blocked' ), true ) ? ' style="color:#b32d2e"' : '';
			echo '<tr><td>' . esc_html( $row['area'] ) . '</td><td>' . esc_html( $row['item'] ) . '</td><td' . $color . '>' . esc_html( $labels[ $row['action'] ] ?? $row['action'] ) . '</td><td>' . esc_html( $row['detail'] ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $color is a fixed string.
		}
		echo '</tbody></table></div>';
		if ( null !== $plan['ops']['site_access'] ) {
			$private = true;
		}
		if ( ! $plan['detected'] || ! Migrator::has_changes( $plan['ops'] ) ) {
			echo '<p>' . esc_html__( 'Nothing to change: everything is already carried over.', 'role-gatekeeper' ) . '</p>';
			echo '<p><a class="button" href="' . esc_url( $this->page_url() ) . '">' . esc_html__( 'Back', 'role-gatekeeper' ) . '</a></p>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_migrate_apply" />';
		echo '<input type="hidden" name="source" value="' . esc_attr( $source ) . '" />';
		wp_nonce_field( 'rolegate_migrate_apply_' . $source );
		if ( $private ) {
			echo '<p><label><input type="checkbox" name="confirm_private" value="1" /> ' . esc_html__( 'Also switch on private-site mode: only logged-in users can see the site.', 'role-gatekeeper' ) . '</label></p>';
		}
		echo '<p><label><input type="checkbox" name="reviewed" value="1" /> ' . esc_html__( 'I reviewed these changes. The current roles are backed up first.', 'role-gatekeeper' ) . '</label></p>';
		echo '<p>';
		submit_button( __( 'Apply migration', 'role-gatekeeper' ), 'primary', 'rolegate-migrate', false );
		echo ' <a class="button" href="' . esc_url( $this->page_url() ) . '">' . esc_html__( 'Cancel', 'role-gatekeeper' ) . '</a></p>';
		echo '</form>';
	}

	public function render(): void {
		if ( ! current_user_can( Caps::IMPORT ) ) {
			$this->deny();
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'Import and export', 'role-gatekeeper' ) . '</h1>';
		$notice = get_transient( self::NOTICE_KEY . get_current_user_id() );
		if ( is_array( $notice ) ) {
			delete_transient( self::NOTICE_KEY . get_current_user_id() );
			printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only view; applying checks a nonce. Reduced to letters and digits by preg_replace.
		$token = isset( $_GET['preview'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', (string) wp_unslash( $_GET['preview'] ) ) : '';
		if ( $token ) {
			$pending = get_transient( $this->pending_key( $token ) );
			if ( is_array( $pending ) && isset( $pending['payload'] ) ) {
				$this->render_preview( $token, $pending );
				echo '</div>';
				return;
			}
			echo '<div class="notice notice-error"><p>' . esc_html__( 'That import preview has expired. Upload the file again.', 'role-gatekeeper' ) . '</p></div>';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only preview; applying checks a nonce.
		$migrate = isset( $_GET['migrate'] ) ? sanitize_key( wp_unslash( $_GET['migrate'] ) ) : '';
		if ( '' !== $migrate && isset( Migrator::sources()[ $migrate ] ) && $this->can_migrate() ) {
			$this->render_migration_preview( $migrate );
			echo '</div>';
			return;
		}
		$this->render_export();
		$this->render_import();
		$this->render_migrate();
		echo '</div>';
	}

	private function render_export(): void {
		echo '<h2>' . esc_html__( 'Export', 'role-gatekeeper' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_portability_export" />';
		wp_nonce_field( 'rolegate_portability_export' );
		echo '<fieldset><legend class="screen-reader-text">' . esc_html__( 'Roles to export', 'role-gatekeeper' ) . '</legend>';
		foreach ( Role_Store::all() as $slug => $def ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="roles[]" value="%1$s" checked="checked" /> %2$s <code>%1$s</code></label>',
				esc_attr( $slug ),
				esc_html( translate_user_role( $def['name'] ) )
			);
		}
		echo '</fieldset>';
		$sections = Sections::all();
		foreach ( $sections as $id => $section ) {
			if ( current_user_can( $section['cap'] ) ) {
				printf(
					'<label style="display:block"><input type="checkbox" name="sections[]" value="%1$s" /> %2$s</label>',
					esc_attr( $id ),
					esc_html( $section['label'] )
				);
			}
		}
		submit_button( __( 'Download JSON file', 'role-gatekeeper' ), 'secondary', 'rolegate-export' );
		echo '</form>';
	}

	private function render_import(): void {
		echo '<h2>' . esc_html__( 'Import', 'role-gatekeeper' ) . '</h2>';
		echo '<p>' . esc_html__( 'Nothing changes until you confirm on the next screen. Protected roles and your own role are never overwritten.', 'role-gatekeeper' ) . '</p>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_portability_preview" />';
		wp_nonce_field( 'rolegate_portability_preview' );
		echo '<table class="form-table" role="presentation"><tbody>';
		echo '<tr><th scope="row">' . esc_html__( 'Source', 'role-gatekeeper' ) . '</th><td>';
		echo '<label style="display:block"><input type="radio" name="source" value="file" checked="checked" /> ' . esc_html__( 'A Role Gatekeeper JSON file', 'role-gatekeeper' ) . '</label>';
		foreach ( Sources::available() as $id => $label ) {
			printf( '<label style="display:block"><input type="radio" name="source" value="%1$s" /> %2$s</label>', esc_attr( $id ), esc_html( $label ) );
		}
		echo '</td></tr>';
		echo '<tr><th scope="row"><label for="rolegate-file">' . esc_html__( 'File', 'role-gatekeeper' ) . '</label></th><td>';
		echo '<input type="file" id="rolegate-file" style="width:100%;max-width:30em;min-height:32px;box-sizing:border-box" name="rolegate_file" accept=".json,application/json" />';
		/* translators: %s: size limit */
		echo '<p class="description">' . esc_html( sprintf( __( 'Up to %s.', 'role-gatekeeper' ), size_format( Importer::max_bytes() ) ) ) . '</p>';
		echo '<p><label for="rolegate-json">' . esc_html__( 'Or paste the JSON:', 'role-gatekeeper' ) . '</label><br /><textarea id="rolegate-json" name="rolegate_json" rows="6" class="large-text code"></textarea></p>';
		echo '</td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Existing roles', 'role-gatekeeper' ) . '</th><td>';
		echo '<label style="display:block"><input type="radio" name="mode" value="replace" checked="checked" /> ' . esc_html__( 'Replace their capabilities with the ones in the file', 'role-gatekeeper' ) . '</label>';
		echo '<label style="display:block"><input type="radio" name="mode" value="merge" /> ' . esc_html__( 'Only add capabilities, keep the rest', 'role-gatekeeper' ) . '</label>';
		echo '</td></tr></tbody></table>';
		submit_button( __( 'Preview import', 'role-gatekeeper' ), 'primary', 'rolegate-preview' );
		echo '</form>';
	}

	private function cap_list( array $caps ): string {
		if ( ! $caps ) {
			return '&mdash;';
		}
		return implode(
			', ',
			array_map(
				function ( $cap ) {
					return '<code>' . esc_html( $cap ) . '</code>';
				},
				$caps
			)
		);
	}

	private function render_preview( string $token, array $pending ): void {
		$plan    = Importer::plan( $pending['payload'], get_current_user_id(), $pending['mode'] );
		$actions = array(
			'create'    => __( 'Create', 'role-gatekeeper' ),
			'overwrite' => __( 'Overwrite', 'role-gatekeeper' ),
			'unchanged' => __( 'No change', 'role-gatekeeper' ),
		);
		echo '<h2>' . esc_html__( 'Review the import', 'role-gatekeeper' ) . '</h2>';
		echo '<p>' . esc_html( 'merge' === $pending['mode'] ? __( 'Mode: only add capabilities to existing roles.', 'role-gatekeeper' ) : __( 'Mode: replace the capabilities of existing roles.', 'role-gatekeeper' ) ) . '</p>';

		if ( $plan['rejected'] ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'These entries were skipped:', 'role-gatekeeper' ) . '</p><ul>';
			foreach ( $plan['rejected'] as $line ) {
				echo '<li>' . esc_html( $line ) . '</li>';
			}
			echo '</ul></div>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_portability_apply" />';
		echo '<input type="hidden" name="token" value="' . esc_attr( $token ) . '" />';
		wp_nonce_field( 'rolegate_portability_apply_' . $token );

		echo '<div class="rw-scroll" style="overflow-x:auto"><table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Import', 'role-gatekeeper' ), __( 'Role', 'role-gatekeeper' ), __( 'Action', 'role-gatekeeper' ), __( 'Added', 'role-gatekeeper' ), __( 'Removed', 'role-gatekeeper' ), __( 'New custom capabilities', 'role-gatekeeper' ), __( 'Critical capabilities', 'role-gatekeeper' ) ) as $head ) {
			echo '<th scope="col">' . esc_html( $head ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( ! $plan['roles'] ) {
			echo '<tr><td colspan="7">' . esc_html__( 'The file holds no valid roles.', 'role-gatekeeper' ) . '</td></tr>';
		}
		foreach ( $plan['roles'] as $slug => $row ) {
			$can = ! $row['blocked'] && 'unchanged' !== $row['action'];
			echo '<tr><td>';
			if ( $can ) {
				printf( '<input type="checkbox" name="roles[]" value="%1$s" checked="checked" aria-label="%2$s" />', esc_attr( $slug ), esc_attr( $row['name'] ) );
			}
			echo '</td><td><strong>' . esc_html( $row['name'] ) . '</strong> <code>' . esc_html( $slug ) . '</code></td><td>';
			echo esc_html( $actions[ $row['action'] ] );
			if ( $row['blocked'] ) {
				echo '<br /><span style="color:#b32d2e">' . esc_html( $row['blocked'] ) . '</span>';
			}
			echo '</td><td>' . $this->cap_list( $row['added'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in cap_list.
			echo '<td>' . $this->cap_list( $row['removed'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td>' . $this->cap_list( $row['new_custom'] ) . '</td><td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			if ( $row['critical'] ) {
				echo $this->cap_list( $row['critical'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				if ( $can ) {
					printf(
						'<br /><label><input type="checkbox" name="confirm_critical[]" value="%1$s" /> %2$s</label>',
						esc_attr( $slug ),
						esc_html__( 'Grant these too. Unticked, they are left out.', 'role-gatekeeper' )
					);
				}
			} else {
				echo '&mdash;';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';

		foreach ( $plan['sections'] as $id => $section ) {
			echo '<h3>' . esc_html( $section['label'] ) . '</h3>';
			if ( $section['blocked'] ) {
				echo '<p style="color:#b32d2e">' . esc_html( $section['blocked'] ) . '</p>';
				continue;
			}
			echo '<ul>';
			foreach ( $section['summary'] as $line ) {
				echo '<li>' . esc_html( $line ) . '</li>';
			}
			echo '</ul>';
			printf( '<label><input type="checkbox" name="sections[]" value="%1$s" /> %2$s</label>', esc_attr( $id ), esc_html__( 'Import this section', 'role-gatekeeper' ) );
		}

		echo '<p><label><input type="checkbox" name="reviewed" value="1" /> ' . esc_html__( 'I reviewed these changes. The current roles are backed up first.', 'role-gatekeeper' ) . '</label></p>';
		echo '<p>';
		submit_button( __( 'Apply import', 'role-gatekeeper' ), 'primary', 'rolegate-apply', false );
		echo ' <a class="button" href="' . esc_url( $this->page_url() ) . '">' . esc_html__( 'Cancel', 'role-gatekeeper' ) . '</a></p>';
		echo '</form>';
	}
}
