<?php
namespace Rolewright\Modules\User_Roles;

use Rolewright\Modules\Safety\Caps;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Extra roles and per-user capabilities on the profile and new-user screens.
 *
 * WordPress saves the primary role with set_role(), which drops every other role, so
 * the extras are validated in user_profile_update_errors and written back afterwards.
 */
final class Profile {
	/** @var array<int,string[]> */
	private static $before = array();

	/** @var array<string,array> */
	private static $plan = array();

	public function register(): void {
		add_action( 'edit_user_profile', array( $this, 'render_profile' ) );
		add_action( 'user_new_form', array( $this, 'render_new_user' ) );
		add_action( 'edit_user_profile_update', array( $this, 'remember' ), 1 );
		add_action( 'personal_options_update', array( $this, 'remember' ), 1 );
		add_action( 'user_profile_update_errors', array( $this, 'validate' ), 20, 3 );
		add_action( 'profile_update', array( $this, 'apply_update' ), 20 );
		add_action( 'user_register', array( $this, 'apply_new' ), 20 );
	}

	private static function posted_nonce_ok( int $target ): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput -- verified on the next line.
		$nonce = isset( $_POST['rolewright_user_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rolewright_user_nonce'] ) ) : '';
		return (bool) wp_verify_nonce( $nonce, 'rolewright_user_' . $target );
	}

	/**
	 * @return string[]
	 */
	private static function posted_list( string $key ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- callers verify the nonce first; each slug goes through Users::clean_slugs.
		$raw = isset( $_POST[ $key ] ) && is_array( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : array();
		return Users::clean_slugs( array_filter( $raw, 'is_string' ) );
	}

	public function render_profile( $user ): void {
		$actor = get_current_user_id();
		if ( ! $user instanceof \WP_User || ! $actor || $user->ID === $actor ) {
			return;
		}
		$member    = true === Users::check_site_member( $actor, $user->ID );
		$can_roles = $member && user_can( $actor, 'promote_user', $user->ID ) && Guard::can_act_on_user( $actor, $user->ID );
		$can_caps  = $member && user_can( $actor, Caps::MANAGE_USERS ) && user_can( $actor, 'edit_user', $user->ID ) && Guard::can_act_on_user( $actor, $user->ID );
		if ( ! $can_roles && ! $can_caps ) {
			return;
		}
		wp_nonce_field( 'rolewright_user_' . $user->ID, 'rolewright_user_nonce' );

		if ( $can_roles ) {
			$held       = Users::raw_roles( $user->ID );
			$primary    = $held ? $held[0] : '';
			$assignable = Users::assignable_roles( $actor, $user->ID );
			$names      = wp_roles()->role_names;
			$locked     = array_diff( $held, $assignable );
			echo '<h2>' . esc_html__( 'Additional roles', 'rolewright' ) . '</h2>';
			echo '<input type="hidden" name="rolewright_user_roles_present" value="1" />';
			echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Roles', 'rolewright' ) . '</th><td>';
			foreach ( $assignable as $role ) {
				if ( $role === $primary ) {
					continue;
				}
				printf(
					'<label style="display:block;margin:2px 0"><input type="checkbox" name="rolewright_user_roles[]" value="%1$s" %2$s /> %3$s</label>',
					esc_attr( $role ),
					checked( in_array( $role, $held, true ), true, false ),
					esc_html( translate_user_role( $names[ $role ] ?? $role ) )
				);
			}
			if ( $locked ) {
				echo '<p class="description">' . esc_html(
					sprintf(
						/* translators: %s: role names */
						__( 'Also holds, and you can\'t change: %s', 'rolewright' ),
						implode(
							', ',
							array_map(
								function ( $r ) use ( $names ) {
									return translate_user_role( $names[ $r ] ?? $r );
								},
								$locked
							)
						)
					)
				) . '</p>';
			}
			echo '<p class="description">' . esc_html__( 'The role chosen under Role above stays the primary role. Tick the roles this user should hold as well.', 'rolewright' ) . '</p>';
			echo '</td></tr></table>';
		}

		if ( $can_caps ) {
			$this->render_caps( $user, $actor );
		}
	}

	private function render_caps( \WP_User $user, int $actor ): void {
		$roles_caps = array();
		$all        = array();
		foreach ( wp_roles()->roles as $name => $data ) {
			$roles_caps[ $name ] = (array) $data['capabilities'];
			foreach ( $roles_caps[ $name ] as $cap => $grant ) {
				if ( ! isset( wp_roles()->role_names[ $cap ] ) ) {
					$all[ (string) $cap ] = true;
				}
			}
		}
		$direct     = Users::direct_caps( $user->ID );
		$all       += $direct;
		$from_roles = Guard::caps_from_roles( Users::raw_roles( $user->ID ), $roles_caps );
		ksort( $all );

		echo '<h2>' . esc_html__( 'Capabilities granted to this user', 'rolewright' ) . '</h2>';
		echo '<input type="hidden" name="rolewright_user_caps_present" value="1" />';
		echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Capabilities', 'rolewright' ) . '</th><td>';
		echo '<div style="max-height:280px;overflow:auto;border:1px solid #c3c4c7;padding:8px;columns:3 220px">';
		foreach ( array_keys( $all ) as $cap ) {
			$is_direct = isset( $direct[ $cap ] );
			$grantable = $is_direct || Guard::can_grant_cap( $actor, $cap );
			printf(
				'<label style="display:block;break-inside:avoid;margin:1px 0"><input type="checkbox" name="rolewright_user_caps[]" value="%1$s" %2$s %3$s /> %4$s%5$s</label>',
				esc_attr( $cap ),
				checked( $is_direct, true, false ),
				disabled( ! $grantable || ( $is_direct && ! Guard::can_grant_cap( $actor, $cap ) ), true, false ),
				esc_html( $cap ),
				! empty( $from_roles[ $cap ] ) ? ' <span class="description">' . esc_html__( '(from role)', 'rolewright' ) . '</span>' : ''
			);
		}
		echo '</div>';
		echo '<p><label for="rolewright_user_cap_new">' . esc_html__( 'Add capabilities not listed', 'rolewright' ) . '</label><br />';
		echo '<input type="text" class="regular-text" id="rolewright_user_cap_new" name="rolewright_user_cap_new" value="" /></p>';
		echo '<p class="description">' . esc_html__( 'Separate names with spaces or commas. You can only grant capabilities you hold yourself, unless you can manage capabilities.', 'rolewright' ) . '</p>';
		echo '</td></tr></table>';
	}

	public function render_new_user( $type ): void {
		if ( 'add-new-user' !== $type || ! current_user_can( 'promote_users' ) ) {
			return;
		}
		$actor      = get_current_user_id();
		$assignable = Users::assignable_roles( $actor, 0 );
		if ( ! $assignable ) {
			return;
		}
		$names = wp_roles()->role_names;
		wp_nonce_field( 'rolewright_user_0', 'rolewright_user_nonce' );
		echo '<input type="hidden" name="rolewright_user_roles_present" value="1" />';
		echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Additional roles', 'rolewright' ) . '</th><td>';
		foreach ( $assignable as $role ) {
			printf(
				'<label style="display:block;margin:2px 0"><input type="checkbox" name="rolewright_user_roles[]" value="%1$s" /> %2$s</label>',
				esc_attr( $role ),
				esc_html( translate_user_role( $names[ $role ] ?? $role ) )
			);
		}
		echo '</td></tr></table>';
	}

	public function remember( $user_id ): void {
		self::$before[ (int) $user_id ] = Users::raw_roles( (int) $user_id );
	}

	/**
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param \stdClass $user
	 */
	public function validate( $errors, $update, $user ): void {
		$actor = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence marker only; the nonce is verified below.
		if ( ! $actor || ( empty( $_POST['rolewright_user_roles_present'] ) && empty( $_POST['rolewright_user_caps_present'] ) ) ) {
			return;
		}
		$target = $update ? (int) $user->ID : 0;
		if ( $update && $target === $actor ) {
			return;
		}
		if ( ! self::posted_nonce_ok( $target ) ) {
			$errors->add( 'rolewright_nonce', __( 'The roles section of this form has expired. Reload the page and try again.', 'rolewright' ) );
			return;
		}
		$key  = $update ? (string) $target : 'new';
		$plan = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['rolewright_user_roles_present'] ) && isset( $user->role ) ) {
			$extras = array_values( array_diff( self::posted_list( 'rolewright_user_roles' ), array( (string) $user->role ) ) );
			$ok     = Users::check_roles_change( $actor, $target, $extras, array() );
			if ( is_wp_error( $ok ) ) {
				$errors->add( $ok->get_error_code(), $ok->get_error_message() );
			} elseif ( array_diff( $extras, Users::assignable_roles( $actor, $target ) ) ) {
				$errors->add( 'rolewright_role_not_allowed', __( 'You can\'t give one of the chosen roles.', 'rolewright' ) );
			} else {
				$plan['extras'] = $extras;
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( $update && ! empty( $_POST['rolewright_user_caps_present'] ) && user_can( $actor, Caps::MANAGE_USERS ) ) {
			$posted = self::posted_list( 'rolewright_user_caps' );
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$typed = isset( $_POST['rolewright_user_cap_new'] ) ? preg_split( '/[\s,]+/', sanitize_text_field( wp_unslash( $_POST['rolewright_user_cap_new'] ) ), -1, PREG_SPLIT_NO_EMPTY ) : array();
			$want  = array_values( array_unique( array_merge( $posted, $typed ) ) );
			$have  = array_keys( Users::direct_caps( $target ) );
			$check = Users::check_caps_change( $actor, $target, array_diff( $want, $have ), array_diff( $have, $want ) );
			if ( is_wp_error( $check ) ) {
				$errors->add( $check->get_error_code(), $check->get_error_message() );
			} else {
				$plan['caps'] = $check;
			}
		}

		if ( $plan && ! $errors->get_error_codes() ) {
			self::$plan[ $key ] = $plan;
		}
	}

	public function apply_update( $user_id ): void {
		$user_id = (int) $user_id;
		if ( ! isset( self::$before[ $user_id ] ) ) {
			return;
		}
		$actor  = get_current_user_id();
		$before = self::$before[ $user_id ];
		$plan   = self::$plan[ (string) $user_id ] ?? array();
		unset( self::$before[ $user_id ], self::$plan[ (string) $user_id ] );
		if ( ! $actor || $actor === $user_id ) {
			return;
		}

		if ( isset( $plan['extras'] ) ) {
			$user = get_userdata( $user_id );
			$keep = array_diff( $before, Users::assignable_roles( $actor, $user_id ) );
			foreach ( array_merge( $keep, $plan['extras'] ) as $role ) {
				if ( get_role( $role ) ) {
					$user->add_role( $role );
				}
			}
			clean_user_cache( $user_id );
		}
		Users::announce_roles( $actor, $user_id, $before, Users::raw_roles( $user_id ) );

		if ( isset( $plan['caps'] ) ) {
			Users::apply_caps( $actor, $user_id, $plan['caps'][0], $plan['caps'][1] );
		}
	}

	public function apply_new( $user_id ): void {
		$user_id = (int) $user_id;
		$actor   = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! $actor || ! is_admin() || ! isset( $_POST['action'] ) || 'createuser' !== $_POST['action'] ) {
			return;
		}
		$plan = self::$plan['new'] ?? array();
		unset( self::$plan['new'] );
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		foreach ( $plan['extras'] ?? array() as $role ) {
			if ( get_role( $role ) && Guard::can_assign_role( $actor, $role, $user_id ) ) {
				$user->add_role( $role );
			}
		}
		clean_user_cache( $user_id );
		Users::announce_roles( $actor, $user_id, array(), Users::raw_roles( $user_id ) );
	}
}
