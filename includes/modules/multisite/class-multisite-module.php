<?php
namespace Rolegate\Modules\Multisite;

use Rolegate\Core\Module;
use Rolegate\Modules\Portability\Role_Store;
use Rolegate\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

/**
 * Network tools: copy a role to every site, push all roles and users, and decide whether
 * site administrators may use Role Gatekeeper. Registers nothing on a single-site install.
 */
final class Multisite_Module extends Module {
	const SLUG              = 'role-gatekeeper-multisite';
	const OPTION_SITE_ADMIN = 'rolegate_network_site_admin_access';
	const OPTION_BATCH      = 'rolegate_network_batch_size';
	const NOTICE_KEY        = 'rolegate_ms_notice_';

	public function id(): string {
		return 'multisite';
	}

	public function title(): string {
		return __( 'Multisite', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'On a network: copy roles to every site, push users to subsites, and choose whether site administrators may use Role Gatekeeper.', 'role-gatekeeper' );
	}

	public function init(): void {
		if ( ! is_multisite() ) {
			return;
		}
		add_filter( 'rolegate_multisite_site_admin_access', array( __CLASS__, 'site_admins_allowed' ), 10, 1 );
		add_filter( 'map_meta_cap', array( __CLASS__, 'restrict_site_admins' ), 10, 4 );
		add_action( 'network_admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_rolegate_ms_settings', array( $this, 'handle_settings' ) );
		add_action( 'admin_post_rolegate_ms_start', array( $this, 'handle_start' ) );
		add_action( 'admin_post_rolegate_ms_batch', array( $this, 'handle_batch' ) );
	}

	public static function site_admins_allowed( $allowed = false ): bool {
		return (bool) $allowed || (bool) get_site_option( self::OPTION_SITE_ADMIN, false );
	}

	/**
	 * With the network setting off and no `rolegate_multisite_site_admin_access` grant,
	 * no Role Gatekeeper cap (pages included) is usable by anyone but a super admin.
	 *
	 * @param string[] $caps
	 * @param string   $cap
	 * @param int      $user_id
	 * @param array    $args
	 * @return string[]
	 */
	public static function restrict_site_admins( $caps, $cap, $user_id, $args ) {
		if ( in_array( $cap, Caps::all(), true ) && ! is_super_admin( (int) $user_id ) && ! apply_filters( 'rolegate_multisite_site_admin_access', false, get_userdata( (int) $user_id ) ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	private function can(): bool {
		return is_super_admin() && current_user_can( 'manage_network_options' );
	}

	private function deny(): void {
		wp_die( esc_html__( 'Only super admins can use the Role Gatekeeper network tools.', 'role-gatekeeper' ), '', array( 'response' => 403 ) );
	}

	private function page_url( array $args = array() ): string {
		return add_query_arg( $args, network_admin_url( 'admin.php?page=' . self::SLUG ) );
	}

	private function notice( string $type, string $message ): void {
		set_site_transient( self::NOTICE_KEY . get_current_user_id(), array( $type, $message ), 5 * MINUTE_IN_SECONDS );
	}

	public function menu(): void {
		add_menu_page( __( 'Role Gatekeeper network', 'role-gatekeeper' ), __( 'Role Gatekeeper', 'role-gatekeeper' ), 'manage_network_options', self::SLUG, array( $this, 'render' ), 'dashicons-admin-network', 71 );
	}

	public function handle_settings(): void {
		if ( ! $this->can() ) {
			$this->deny();
		}
		check_admin_referer( 'rolegate_ms_settings' );
		update_site_option( self::OPTION_SITE_ADMIN, ! empty( $_POST['site_admins'] ) );
		$batch = isset( $_POST['batch'] ) ? absint( $_POST['batch'] ) : Network_Sync::DEFAULT_BATCH;
		update_site_option( self::OPTION_BATCH, max( 1, min( 200, $batch ) ) );
		$this->notice( 'success', __( 'Network settings saved.', 'role-gatekeeper' ) );
		wp_safe_redirect( $this->page_url() );
		exit;
	}

	public function handle_start(): void {
		if ( ! $this->can() ) {
			$this->deny();
		}
		check_admin_referer( 'rolegate_ms_start' );
		$kind   = isset( $_POST['kind'] ) && 'push' === $_POST['kind'] ? 'push' : 'role';
		$source = isset( $_POST['source'] ) ? absint( $_POST['source'] ) : get_main_site_id();
		if ( 'push' === $kind ) {
			$roles = array();
			$mode  = 'replace';
			$users = ! empty( $_POST['users'] );
		} else {
			$role  = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
			$roles = '' === $role ? array( '__none__' ) : array( $role );
			$mode  = isset( $_POST['mode'] ) && 'merge' === $_POST['mode'] ? 'merge' : 'replace';
			$users = false;
		}
		if ( empty( $_POST['confirm'] ) ) {
			$this->notice( 'error', __( 'Tick the confirmation box: this changes every site on the network.', 'role-gatekeeper' ) );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		$job = Network_Sync::start( get_current_user_id(), $source, $roles, $mode, $users );
		if ( is_wp_error( $job ) ) {
			$this->notice( 'error', $job->get_error_message() );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		wp_safe_redirect( $this->page_url( array( 'job' => $job['id'] ) ) );
		exit;
	}

	public function handle_batch(): void {
		if ( ! $this->can() ) {
			$this->deny();
		}
		$id = isset( $_POST['job'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', (string) wp_unslash( $_POST['job'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- reduced to letters and digits by preg_replace.
		check_admin_referer( 'rolegate_ms_batch_' . $id );
		$job = Network_Sync::get( get_current_user_id(), $id );
		if ( ! $job ) {
			$this->notice( 'error', __( 'That job has expired or belongs to someone else.', 'role-gatekeeper' ) );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		$job = Network_Sync::run_batch( $job, get_current_user_id() );
		if ( is_wp_error( $job ) ) {
			$this->notice( 'error', $job->get_error_message() );
			wp_safe_redirect( $this->page_url() );
			exit;
		}
		wp_safe_redirect( $this->page_url( array( 'job' => $job['id'] ) ) );
		exit;
	}

	public function render(): void {
		if ( ! $this->can() ) {
			$this->deny();
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'Role Gatekeeper network tools', 'role-gatekeeper' ) . '</h1>';
		$notice = get_site_transient( self::NOTICE_KEY . get_current_user_id() );
		if ( is_array( $notice ) ) {
			delete_site_transient( self::NOTICE_KEY . get_current_user_id() );
			printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only view; each batch checks a nonce. Reduced to letters and digits by preg_replace.
		$job_id = isset( $_GET['job'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', (string) wp_unslash( $_GET['job'] ) ) : '';
		$job    = $job_id ? Network_Sync::get( get_current_user_id(), $job_id ) : null;
		if ( $job ) {
			$this->render_job( $job );
		}
		$this->render_tools();
		$this->render_settings();
		echo '</div>';
	}

	private function render_job( array $job ): void {
		echo '<div class="card" style="max-width:none"><h2>' . esc_html( $job['finished'] ? __( 'Job finished', 'role-gatekeeper' ) : __( 'Job in progress', 'role-gatekeeper' ) ) . '</h2>';
		printf(
			'<p>%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: sites processed, 2: total sites, 3: role changes, 4: users added */
					__( 'Sites processed: %1$d of %2$d. Role changes: %3$d. Users added: %4$d.', 'role-gatekeeper' ),
					min( $job['offset'], $job['total'] ),
					$job['total'],
					$job['roles_done'],
					$job['users_done']
				)
			)
		);
		if ( $job['errors'] ) {
			echo '<ul>';
			foreach ( $job['errors'] as $error ) {
				echo '<li>' . esc_html( $error ) . '</li>';
			}
			echo '</ul>';
		}
		if ( ! $job['finished'] ) {
			echo '<form id="rolegate-ms-batch" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="rolegate_ms_batch" />';
			echo '<input type="hidden" name="job" value="' . esc_attr( $job['id'] ) . '" />';
			wp_nonce_field( 'rolegate_ms_batch_' . $job['id'] );
			submit_button( __( 'Run next batch', 'role-gatekeeper' ), 'primary', 'rolegate-ms-next', false );
			echo '</form>';
			echo '<script>setTimeout(function(){document.getElementById("rolegate-ms-batch").submit();},300);</script>';
		}
		echo '</div>';
	}

	private function render_tools(): void {
		$main = get_main_site_id();
		switch_to_blog( $main );
		$roles = Role_Store::all();
		restore_current_blog();
		$post = esc_url( admin_url( 'admin-post.php' ) );

		echo '<h2>' . esc_html__( 'Apply a role to all sites', 'role-gatekeeper' ) . '</h2>';
		echo '<form method="post" action="' . $post . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
		echo '<input type="hidden" name="action" value="rolegate_ms_start" /><input type="hidden" name="kind" value="role" />';
		echo '<input type="hidden" name="source" value="' . esc_attr( (string) $main ) . '" />';
		wp_nonce_field( 'rolegate_ms_start' );
		echo '<p><label for="rolegate-ms-role">' . esc_html__( 'Role on the main site', 'role-gatekeeper' ) . '</label> <select id="rolegate-ms-role" name="role">';
		foreach ( $roles as $slug => $def ) {
			printf( '<option value="%1$s">%2$s (%1$s)</option>', esc_attr( $slug ), esc_html( translate_user_role( $def['name'] ) ) );
		}
		echo '</select></p>';
		echo '<p><label style="display:block"><input type="radio" name="mode" value="replace" checked="checked" /> ' . esc_html__( 'Sync: copy the role exactly, creating it where missing', 'role-gatekeeper' ) . '</label>';
		echo '<label style="display:block"><input type="radio" name="mode" value="merge" /> ' . esc_html__( 'Add its capabilities only, keep what each site has', 'role-gatekeeper' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="confirm" value="1" /> ' . esc_html__( 'I understand this changes every site on the network.', 'role-gatekeeper' ) . '</label></p>';
		submit_button( __( 'Apply to all sites', 'role-gatekeeper' ), 'secondary', 'rolegate-ms-apply' );
		echo '</form>';

		echo '<h2>' . esc_html__( 'Push all roles and users', 'role-gatekeeper' ) . '</h2>';
		echo '<p>' . esc_html__( 'Copies every role from the main site to all other sites. Optionally adds the main site\'s users to sites they don\'t belong to yet, with the same roles. Users who are already members keep their roles.', 'role-gatekeeper' ) . '</p>';
		echo '<form method="post" action="' . $post . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
		echo '<input type="hidden" name="action" value="rolegate_ms_start" /><input type="hidden" name="kind" value="push" />';
		echo '<input type="hidden" name="source" value="' . esc_attr( (string) $main ) . '" />';
		wp_nonce_field( 'rolegate_ms_start' );
		echo '<p><label><input type="checkbox" name="users" value="1" /> ' . esc_html__( 'Also add users to every site', 'role-gatekeeper' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="confirm" value="1" /> ' . esc_html__( 'I understand this changes every site on the network.', 'role-gatekeeper' ) . '</label></p>';
		submit_button( __( 'Push to all sites', 'role-gatekeeper' ), 'secondary', 'rolegate-ms-push' );
		echo '</form>';
	}

	private function render_settings(): void {
		echo '<h2>' . esc_html__( 'Settings', 'role-gatekeeper' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="rolegate_ms_settings" />';
		wp_nonce_field( 'rolegate_ms_settings' );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="site_admins" value="1" %2$s /> %3$s</label></td></tr>',
			esc_html__( 'Site administrators', 'role-gatekeeper' ),
			checked( self::site_admins_allowed(), true, false ),
			esc_html__( 'Let site administrators use Role Gatekeeper on their own sites', 'role-gatekeeper' )
		);
		printf(
			'<tr><th scope="row"><label for="rolegate-ms-batch-size">%1$s</label></th><td><input type="number" id="rolegate-ms-batch-size" name="batch" min="1" max="200" value="%2$d" /> <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Sites per batch', 'role-gatekeeper' ),
			(int) Network_Sync::batch_size(),
			esc_html__( 'Lower this if a batch times out.', 'role-gatekeeper' )
		);
		echo '</tbody></table>';
		submit_button( __( 'Save settings', 'role-gatekeeper' ), 'primary', 'rolegate-ms-save' );
		echo '</form>';
	}
}
