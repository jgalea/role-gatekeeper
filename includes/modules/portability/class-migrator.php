<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Plugin;
use Rolegate\Core\Settings;
use Rolegate\Modules\Capabilities\Cap_Catalog;
use Rolegate\Modules\Admin_Ui\Rules;
use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Content_Access\Content_Settings;
use Rolegate\Modules\Deny_Hierarchy\Denials;
use Rolegate\Modules\Disabled_Users\Accounts;
use Rolegate\Modules\Roles\Role_Service;
use Rolegate\Modules\Safety\Caps;
use Rolegate\Modules\Safety\Guard;
use Rolegate\Modules\Site_Access\Site_Access_Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Carries another role plugin's data over: a source class plans the change (read only),
 * this class applies the plan through the owning modules' save paths, keeps a record of
 * what it added so the audit log can revert it, and builds capability snapshots to prove
 * the result grants exactly what it did before.
 *
 * A plan is { source, label, detected, rows: [{area,item,action,detail}], ops }. ops keys:
 * denials (role => full new list), posts (id => {roles?, message?} to add), blocks
 * (id => {before, after} content), content_message, site_access (new settings), extras
 * (extra default roles), modules (ids to switch on), users (ids of accounts to disable),
 * access (role => full new admin-ui rule).
 */
final class Migrator {
	const RECORDS     = 'rolegate_migrations';
	const KEEP        = 20;
	const SNAP_FORMAT = 'rolegate-capsnap';

	/** @return array<string,string> source id => class */
	public static function sources(): array {
		return array(
			'members'            => Members_Migration::class,
			'ure'                => Ure_Migration::class,
			'disable-users'      => Disable_Users_Migration::class,
			'disable-user-login' => Disable_User_Login_Migration::class,
			'adminimize'         => Adminimize_Migration::class,
		);
	}

	public static function is_shell( int $actor ): bool {
		return $actor <= 0 && defined( 'WP_CLI' ) && WP_CLI;
	}

	/**
	 * Same authority as switching modules: a migration changes several modules' settings.
	 *
	 * @return true|\WP_Error
	 */
	public static function authorize( int $actor ) {
		if ( self::is_shell( $actor ) ) {
			return true;
		}
		if ( $actor > 0 && user_can( $actor, Caps::IMPORT ) && Guard::is_site_authority( $actor ) ) {
			return true;
		}
		return new \WP_Error( 'rolegate_not_authority', __( 'Only an administrator who holds every administrator capability can run a migration.', 'role-gatekeeper' ) );
	}

	public static function row( string $area, string $item, string $action, string $detail = '' ): array {
		return array(
			'area'   => $area,
			'item'   => $item,
			'action' => $action,
			'detail' => $detail,
		);
	}

	/** @return array<string,string> */
	public static function action_labels(): array {
		return array(
			'add'       => __( 'Carry over', 'role-gatekeeper' ),
			'unchanged' => __( 'Already carried over', 'role-gatekeeper' ),
			'conflict'  => __( 'Kept as is', 'role-gatekeeper' ),
			'blocked'   => __( 'Refused', 'role-gatekeeper' ),
			'skip'      => __( 'Not carried over', 'role-gatekeeper' ),
			'info'      => __( 'Note', 'role-gatekeeper' ),
		);
	}

	public static function empty_ops(): array {
		return array(
			'denials'         => array(),
			'posts'           => array(),
			'blocks'          => array(),
			'content_message' => null,
			'site_access'     => null,
			'extras'          => null,
			'modules'         => array(),
			'users'           => array(),
			'access'          => array(),
		);
	}

	public static function has_changes( array $ops ): bool {
		return $ops['denials'] || $ops['posts'] || $ops['blocks'] || null !== $ops['content_message'] || null !== $ops['site_access'] || null !== $ops['extras'] || $ops['modules'] || ! empty( $ops['users'] ) || ! empty( $ops['access'] );
	}

	/**
	 * @param array $opts confirm_private (bool)
	 * @return array|\WP_Error
	 */
	public static function plan( string $source, int $actor, array $opts = array() ) {
		$sources = self::sources();
		if ( ! isset( $sources[ $source ] ) ) {
			return new \WP_Error( 'rolegate_migrate_source', __( 'Unknown migration source.', 'role-gatekeeper' ) );
		}
		$ok = self::authorize( $actor );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		return call_user_func( array( $sources[ $source ], 'plan' ), $actor, $opts );
	}

	/**
	 * Plans again from live data and applies it. Returns status unchanged when there is
	 * nothing left to carry over.
	 *
	 * @return array|\WP_Error {status, plan, migration_id, backup_id, errors}
	 */
	public static function apply( string $source, int $actor, array $opts = array() ) {
		$plan = self::plan( $source, $actor, $opts );
		if ( is_wp_error( $plan ) ) {
			return $plan;
		}
		$result = array(
			'status'       => 'unchanged',
			'plan'         => $plan,
			'migration_id' => '',
			'backup_id'    => '',
			'errors'       => array(),
		);
		$ops    = $plan['ops'];
		if ( ! $plan['detected'] || ! self::has_changes( $ops ) ) {
			return $result;
		}

		$backup_id = Backups::store( max( 0, $actor ), Role_Store::all(), 'migrate-' . $source );
		$record    = array(
			'id'              => gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false, false ),
			'time'            => time(),
			'actor'           => max( 0, $actor ),
			'source'          => $source,
			'backup_id'       => $backup_id,
			'denials'         => array(),
			'posts'           => array(),
			'blocks'          => array(),
			'content_message' => null,
			'site_access'     => null,
			'extras'          => null,
			'modules'         => null,
			'users'           => array(),
			'user_state'      => array(),
			'access'          => array(),
			'post_ids'        => array(),
			'reverted'        => false,
		);
		$errors    = array();

		foreach ( $ops['denials'] as $role => $list ) {
			$before = Denials::for_role( (string) $role );
			$ok     = Denials::save( $actor, (string) $role, $list );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $role . ': ' . $ok->get_error_message();
				continue;
			}
			$record['denials'][ $role ] = array(
				'before' => $before,
				'after'  => Denials::for_role( (string) $role ),
			);
		}

		foreach ( (array) ( $ops['access'] ?? array() ) as $role => $rule ) {
			$before = Rules::get( 'role', (string) $role );
			$ok     = Rules::save( $actor, 'role', (string) $role, $rule );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $role . ': ' . $ok->get_error_message();
				continue;
			}
			$record['access'][ $role ] = array(
				'before' => $before,
				'after'  => Rules::get( 'role', (string) $role ),
			);
		}

		foreach ( $ops['posts'] as $post_id => $add ) {
			$post_id = (int) $post_id;
			$now     = self::post_rules( $post_id );
			$roles   = isset( $add['roles'] ) ? (array) $add['roles'] : $now['roles'];
			$message = isset( $add['message'] ) ? (string) $add['message'] : $now['message'];
			Access::save_rules( $post_id, $roles, $message );
			$after = self::post_rules( $post_id );
			$added = array();
			if ( isset( $add['roles'] ) ) {
				$added['roles'] = $after['roles'];
			}
			if ( isset( $add['message'] ) ) {
				$added['message'] = $after['message'];
			}
			$record['posts'][ $post_id ] = $added;
			$record['post_ids'][]        = $post_id;
		}

		foreach ( $ops['blocks'] as $post_id => $change ) {
			$post_id = (int) $post_id;
			$post    = get_post( $post_id );
			if ( ! $post || (string) $post->post_content !== (string) $change['before'] ) {
				/* translators: %d: post id */
				$errors[] = sprintf( __( 'Post #%d changed since the preview; its blocks were left as they are.', 'role-gatekeeper' ), $post_id );
				continue;
			}
			$ok = self::update_content( $post_id, (string) $change['after'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = '#' . $post_id . ': ' . $ok->get_error_message();
				continue;
			}
			$record['blocks'][ $post_id ] = array(
				'before'     => (string) $change['before'],
				'after_hash' => hash( 'sha256', (string) get_post( $post_id )->post_content ),
			);
			$record['post_ids'][]         = $post_id;
		}

		if ( null !== $ops['content_message'] ) {
			$before = Content_Settings::get();
			Content_Settings::save( max( 0, $actor ), array( 'default_message' => (string) $ops['content_message'] ) );
			$record['content_message'] = array(
				'before' => $before['default_message'],
				'after'  => Content_Settings::default_message(),
			);
		}

		if ( null !== $ops['site_access'] ) {
			$before = Site_Access_Settings::get();
			Site_Access_Settings::save( (array) $ops['site_access'], max( 0, $actor ) );
			$record['site_access'] = array(
				'before' => $before,
				'after'  => Site_Access_Settings::get(),
			);
		}

		if ( null !== $ops['extras'] ) {
			$before = array(
				'default' => (string) get_option( 'default_role' ),
				'extras'  => Role_Service::extra_default_roles(),
			);
			$ok     = Role_Service::set_default( $actor, $before['default'], (array) $ops['extras'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $ok->get_error_message();
			} else {
				$record['extras'] = array(
					'before' => $before,
					'after'  => array(
						'default' => (string) get_option( 'default_role' ),
						'extras'  => Role_Service::extra_default_roles(),
					),
				);
			}
		}

		if ( $ops['modules'] ) {
			$before = self::enabled_modules();
			$ok     = Settings::apply_modules( $actor, array_values( array_unique( array_merge( $before, $ops['modules'] ) ) ) );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $ok->get_error_message();
			} else {
				$record['modules'] = array(
					'before' => $before,
					'after'  => self::enabled_modules(),
				);
			}
		}

		foreach ( (array) ( $ops['users'] ?? array() ) as $user_id ) {
			$user_id = (int) $user_id;
			$allowed = self::is_shell( $actor ) ? true : Accounts::check_actor( $actor, $user_id );
			if ( is_wp_error( $allowed ) ) {
				$errors[] = '#' . $user_id . ': ' . $allowed->get_error_message();
				continue;
			}
			Accounts::write( $user_id, true );
			$record['users'][]                = $user_id;
			$record['user_state'][ $user_id ] = Accounts::meta_id( $user_id );
		}

		$record['post_ids'] = array_values( array_unique( array_map( 'intval', $record['post_ids'] ) ) );
		self::store_record( $record );

		do_action(
			'rolegate_changed',
			'migration.applied',
			array(
				'actor'        => max( 0, $actor ),
				'target'       => $source,
				'before'       => array(
					'denials'  => wp_list_pluck( $record['denials'], 'before' ),
					'access'   => wp_list_pluck( $record['access'], 'before' ),
					'post_ids' => $record['post_ids'],
					'settings' => array(
						'content_message' => $record['content_message'] ? $record['content_message']['before'] : null,
						'site_access'     => $record['site_access'] ? $record['site_access']['before'] : null,
						'extras'          => $record['extras'] ? $record['extras']['before'] : null,
						'modules'         => $record['modules'] ? $record['modules']['before'] : null,
					),
					'users'    => array(),
				),
				'after'        => array(
					'denials'  => wp_list_pluck( $record['denials'], 'after' ),
					'access'   => wp_list_pluck( $record['access'], 'after' ),
					'post_ids' => $record['post_ids'],
					'settings' => array(
						'content_message' => $record['content_message'] ? $record['content_message']['after'] : null,
						'site_access'     => $record['site_access'] ? $record['site_access']['after'] : null,
						'extras'          => $record['extras'] ? $record['extras']['after'] : null,
						'modules'         => $record['modules'] ? $record['modules']['after'] : null,
					),
					'users'    => $record['users'],
				),
				'migration_id' => $record['id'],
				'backup_id'    => $backup_id,
				'summary'      => self::summary( $record ),
			)
		);

		$result['status']       = 'applied';
		$result['migration_id'] = $record['id'];
		$result['backup_id']    = $backup_id;
		$result['errors']       = $errors;
		return $result;
	}

	public static function summary( array $record ): string {
		$parts = array();
		if ( $record['denials'] ) {
			/* translators: %d: number of roles */
			$parts[] = sprintf( _n( 'denials on %d role', 'denials on %d roles', count( $record['denials'] ), 'role-gatekeeper' ), count( $record['denials'] ) );
		}
		if ( ! empty( $record['access'] ) ) {
			/* translators: %d: number of roles */
			$parts[] = sprintf( _n( 'hidden items on %d role', 'hidden items on %d roles', count( $record['access'] ), 'role-gatekeeper' ), count( $record['access'] ) );
		}
		if ( $record['post_ids'] ) {
			/* translators: %d: number of posts */
			$parts[] = sprintf( _n( '%d post', '%d posts', count( $record['post_ids'] ), 'role-gatekeeper' ), count( $record['post_ids'] ) );
		}
		if ( ! empty( $record['users'] ) ) {
			/* translators: %d: number of accounts */
			$parts[] = sprintf( _n( '%d disabled account', '%d disabled accounts', count( $record['users'] ), 'role-gatekeeper' ), count( $record['users'] ) );
		}
		foreach ( array(
			'content_message' => __( 'default message', 'role-gatekeeper' ),
			'site_access'     => __( 'private site', 'role-gatekeeper' ),
			'extras'          => __( 'extra default roles', 'role-gatekeeper' ),
			'modules'         => __( 'modules', 'role-gatekeeper' ),
		) as $key => $label ) {
			if ( $record[ $key ] ) {
				$parts[] = $label;
			}
		}
		return $record['source'] . ': ' . implode( ', ', $parts );
	}

	/** @return string[] ids of the modules switched on now */
	public static function enabled_modules(): array {
		$out = array();
		foreach ( Plugin::modules() as $module ) {
			if ( Plugin::is_enabled( $module->id() ) ) {
				$out[] = $module->id();
			}
		}
		return $out;
	}

	/** @return array{roles:string[],message:string} the post's own rule, without the attachment fallback */
	public static function post_rules( int $post_id ): array {
		$roles   = get_post_meta( $post_id, Access::META_ROLES, true );
		$message = get_post_meta( $post_id, Access::META_MESSAGE, true );
		return array(
			'roles'   => is_array( $roles ) ? array_values( array_map( 'strval', $roles ) ) : array(),
			'message' => is_string( $message ) ? $message : '',
		);
	}

	/**
	 * Writes post content changed only in block comment attributes. Content kses is
	 * switched off for the write because the rest of the content was already stored as is,
	 * and filtering it again would strip markup its author was allowed to use.
	 *
	 * @return true|\WP_Error
	 */
	public static function update_content( int $post_id, string $content ) {
		$kses = false !== has_filter( 'content_save_pre', 'wp_filter_post_kses' );
		if ( $kses ) {
			kses_remove_filters();
		}
		try {
			$ok = wp_update_post(
				array(
					'ID'           => $post_id,
					'post_content' => wp_slash( $content ),
				),
				true
			);
		} finally {
			if ( $kses ) {
				kses_init_filters();
			}
		}
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		clean_post_cache( $post_id );
		$post = get_post( $post_id );
		if ( ! $post || (string) $post->post_content !== $content ) {
			return new \WP_Error( 'rolegate_write_refused', __( 'The post content could not be saved as planned.', 'role-gatekeeper' ) );
		}
		return true;
	}

	/** @return array[] */
	public static function records(): array {
		$list = get_option( self::RECORDS, array() );
		return is_array( $list ) ? array_values( array_filter( $list, 'is_array' ) ) : array();
	}

	public static function record( string $id ): ?array {
		foreach ( self::records() as $record ) {
			if ( isset( $record['id'] ) && $record['id'] === $id ) {
				return $record;
			}
		}
		return null;
	}

	private static function store_record( array $record ): void {
		$list = array_values(
			array_filter(
				self::records(),
				function ( $r ) use ( $record ) {
					return ( $r['id'] ?? '' ) !== $record['id'];
				}
			)
		);
		array_unshift( $list, $record );
		update_option( self::RECORDS, array_slice( $list, 0, self::KEEP ), false );
	}

	/**
	 * Puts back what a migration changed. Every item is checked first; if any was changed
	 * again since, nothing is reverted.
	 *
	 * @return true|\WP_Error
	 */
	public static function revert( string $id, int $actor ) {
		$ok = self::authorize( $actor );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}
		$record = self::record( $id );
		if ( ! $record ) {
			return new \WP_Error( 'rolegate_audit_missing', __( 'The record of that migration is no longer kept.', 'role-gatekeeper' ) );
		}
		if ( ! empty( $record['reverted'] ) ) {
			return new \WP_Error( 'rolegate_audit_already_reverted', __( 'This migration was already reverted.', 'role-gatekeeper' ) );
		}

		$changed = array();
		foreach ( $record['denials'] as $role => $d ) {
			if ( Denials::for_role( (string) $role ) !== $d['after'] ) {
				/* translators: %s: role slug */
				$changed[] = sprintf( __( 'denials on %s', 'role-gatekeeper' ), $role );
			}
		}
		foreach ( (array) ( $record['access'] ?? array() ) as $role => $a ) {
			if ( Rules::get( 'role', (string) $role ) !== $a['after'] ) {
				/* translators: %s: role slug */
				$changed[] = sprintf( __( 'hidden items on %s', 'role-gatekeeper' ), $role );
			}
		}
		foreach ( $record['posts'] as $post_id => $added ) {
			$now = self::post_rules( (int) $post_id );
			if ( ( isset( $added['roles'] ) && $now['roles'] !== $added['roles'] ) || ( isset( $added['message'] ) && $now['message'] !== $added['message'] ) ) {
				/* translators: %d: post id */
				$changed[] = sprintf( __( 'access rule on post #%d', 'role-gatekeeper' ), (int) $post_id );
			}
		}
		foreach ( $record['blocks'] as $post_id => $b ) {
			$post = get_post( (int) $post_id );
			if ( ! $post || hash( 'sha256', (string) $post->post_content ) !== $b['after_hash'] ) {
				/* translators: %d: post id */
				$changed[] = sprintf( __( 'content of post #%d', 'role-gatekeeper' ), (int) $post_id );
			}
		}
		if ( $record['content_message'] && Content_Settings::default_message() !== $record['content_message']['after'] ) {
			$changed[] = __( 'default message', 'role-gatekeeper' );
		}
		if ( $record['site_access'] && Site_Access_Settings::get() !== $record['site_access']['after'] ) {
			$changed[] = __( 'site access settings', 'role-gatekeeper' );
		}
		if ( $record['extras'] && ( Role_Service::extra_default_roles() !== $record['extras']['after']['extras'] || (string) get_option( 'default_role' ) !== $record['extras']['after']['default'] ) ) {
			$changed[] = __( 'default roles', 'role-gatekeeper' );
		}
		foreach ( (array) ( $record['users'] ?? array() ) as $user_id ) {
			$user_id = (int) $user_id;
			if ( ! Accounts::is_disabled( $user_id ) || Accounts::meta_id( $user_id ) !== (int) ( $record['user_state'][ $user_id ] ?? 0 ) ) {
				$user      = get_userdata( $user_id );
				/* translators: %s: user login */
				$changed[] = sprintf( __( 'account status of %s', 'role-gatekeeper' ), $user ? $user->user_login : '#' . $user_id );
			}
		}
		if ( $changed ) {
			return new \WP_Error(
				'rolegate_migration_changed',
				/* translators: %s: comma-separated list of items */
				sprintf( __( 'Nothing was reverted: these were changed again after the migration: %s.', 'role-gatekeeper' ), implode( ', ', $changed ) )
			);
		}

		$errors = array();
		foreach ( $record['denials'] as $role => $d ) {
			$ok = Denials::save( $actor, (string) $role, (array) $d['before'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $role . ': ' . $ok->get_error_message();
			}
		}
		foreach ( (array) ( $record['access'] ?? array() ) as $role => $a ) {
			$ok = Rules::save( $actor, 'role', (string) $role, $a['before'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $role . ': ' . $ok->get_error_message();
			}
		}
		foreach ( $record['posts'] as $post_id => $added ) {
			$now = self::post_rules( (int) $post_id );
			Access::save_rules( (int) $post_id, isset( $added['roles'] ) ? array() : $now['roles'], isset( $added['message'] ) ? '' : $now['message'] );
		}
		foreach ( $record['blocks'] as $post_id => $b ) {
			$ok = self::update_content( (int) $post_id, (string) $b['before'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = '#' . (int) $post_id . ': ' . $ok->get_error_message();
			}
		}
		if ( $record['content_message'] ) {
			Content_Settings::save( max( 0, $actor ), array( 'default_message' => (string) $record['content_message']['before'] ) );
		}
		if ( $record['site_access'] ) {
			Site_Access_Settings::save( (array) $record['site_access']['before'], max( 0, $actor ) );
		}
		if ( $record['extras'] ) {
			$ok = Role_Service::set_default( $actor, (string) $record['extras']['before']['default'], (array) $record['extras']['before']['extras'] );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $ok->get_error_message();
			}
		}
		foreach ( (array) ( $record['users'] ?? array() ) as $user_id ) {
			if ( self::is_shell( $actor ) ) {
				Accounts::write( (int) $user_id, false );
				continue;
			}
			$ok = Accounts::change( $actor, (int) $user_id, false );
			if ( is_wp_error( $ok ) ) {
				$errors[] = '#' . (int) $user_id . ': ' . $ok->get_error_message();
			}
		}
		if ( $record['modules'] ) {
			$switched_on = array_diff( (array) $record['modules']['after'], (array) $record['modules']['before'] );
			$ok          = Settings::apply_modules( $actor, array_values( array_diff( self::enabled_modules(), $switched_on ) ) );
			if ( is_wp_error( $ok ) ) {
				$errors[] = $ok->get_error_message();
			}
		}

		$record['reverted'] = true;
		self::store_record( $record );
		if ( $errors ) {
			return new \WP_Error( 'rolegate_migration_partial', __( 'Some parts could not be reverted:', 'role-gatekeeper' ) . ' ' . implode( ' ', $errors ) );
		}
		return true;
	}

	/**
	 * Every user's stored caps on this site, in one query.
	 *
	 * @return array<int,array<string,bool>>
	 */
	public static function user_cap_rows(): array {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", $wpdb->get_blog_prefix() . 'capabilities' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$caps = maybe_unserialize( $row->meta_value );
			if ( is_array( $caps ) ) {
				$out[ (int) $row->user_id ] = array_map( 'boolval', $caps );
			}
		}
		return $out;
	}

	/**
	 * Caps whose meaning depends on an object (edit_post, delete_user...). Checked without
	 * one they say nothing, so snapshots leave them out.
	 *
	 * @return string[]
	 */
	private static function meta_caps(): array {
		$caps = array( 'edit_post', 'read_post', 'delete_post', 'publish_post', 'edit_page', 'read_page', 'delete_page', 'edit_user', 'delete_user', 'remove_user', 'promote_user', 'edit_comment', 'approve_comment', 'edit_term', 'delete_term', 'assign_term', 'edit_post_meta', 'delete_post_meta', 'add_post_meta', 'edit_comment_meta', 'delete_comment_meta', 'add_comment_meta', 'edit_term_meta', 'delete_term_meta', 'add_term_meta', 'edit_user_meta', 'delete_user_meta', 'add_user_meta', 'delete_site', 'edit_app_password', 'read_app_password', 'delete_app_password', 'create_app_password', 'list_app_passwords', 'delete_app_passwords', 'edit_block_binding', 'manage_post_tags', 'edit_categories' );
		foreach ( get_post_types( array(), 'objects' ) as $type ) {
			foreach ( array( 'edit_post', 'read_post', 'delete_post' ) as $key ) {
				if ( isset( $type->cap->$key ) ) {
					$caps[] = (string) $type->cap->$key;
				}
			}
		}
		return array_values( array_unique( $caps ) );
	}

	/** @return string[] */
	private static function universe( array $user_rows ): array {
		$extra = Caps::all();
		foreach ( wp_roles()->roles as $slug => $data ) {
			$extra[] = (string) $slug;
			$extra   = array_merge( $extra, array_map( 'strval', array_keys( (array) $data['capabilities'] ) ) );
		}
		foreach ( $user_rows as $caps ) {
			$extra = array_merge( $extra, array_map( 'strval', array_keys( $caps ) ) );
		}
		$all = array_values( array_diff( Cap_Catalog::universe( $extra ), self::meta_caps() ) );
		sort( $all );
		return $all;
	}

	/**
	 * True caps of a user holding exactly $roles, through the full user_has_cap filter chain.
	 *
	 * @param string[] $roles
	 * @param string[] $universe
	 * @return string[]
	 */
	private static function role_set_caps( array $roles, array $universe ): array {
		static $fake = 2147480000;
		$user        = new \WP_User();
		$user->ID    = ++$fake;
		$user->caps  = array_fill_keys( $roles, true );
		$user->get_role_caps();
		return self::true_caps( $user, $universe );
	}

	/** @return string[] */
	private static function true_caps( \WP_User $user, array $universe ): array {
		$out = array();
		foreach ( $universe as $cap ) {
			if ( $user->has_cap( $cap ) ) {
				$out[] = $cap;
			}
		}
		sort( $out );
		return $out;
	}

	/** @return array{count:int,sha256:string,caps:string[]} */
	private static function entry( array $caps ): array {
		return array(
			'count'  => count( $caps ),
			'sha256' => hash( 'sha256', implode( "\n", $caps ) ),
			'caps'   => $caps,
		);
	}

	/**
	 * Effective caps for every role on its own, every role combination users hold, and every
	 * user with capabilities granted or denied on their own account.
	 *
	 * @param string[]|null $universe the cap list to test; the site's full list when null.
	 * @return array{format:string,version:int,universe:string[],entries:array<string,array>}
	 */
	public static function snapshot( ?array $universe = null ): array {
		$rows     = self::user_cap_rows();
		$universe = null === $universe ? self::universe( $rows ) : $universe;
		$labels   = self::snapshot_labels( $rows );
		$entries  = array();
		foreach ( $labels as $label => $spec ) {
			$entries[ $label ] = self::entry( self::caps_for_label( $spec, $universe ) );
		}
		ksort( $entries );
		return array(
			'format'   => self::SNAP_FORMAT,
			'version'  => 1,
			'universe' => $universe,
			'entries'  => $entries,
		);
	}

	/** @return array<string,array{type:string,roles?:string[],user?:int}> */
	private static function snapshot_labels( array $rows ): array {
		$out = array();
		foreach ( array_keys( wp_roles()->roles ) as $slug ) {
			$out[ 'role:' . $slug ] = array(
				'type'  => 'roles',
				'roles' => array( (string) $slug ),
			);
		}
		foreach ( $rows as $user_id => $caps ) {
			$roles = array();
			$own   = false;
			foreach ( $caps as $cap => $grant ) {
				if ( wp_roles()->is_role( (string) $cap ) ) {
					if ( $grant ) {
						$roles[] = (string) $cap;
					}
				} else {
					$own = true;
				}
			}
			sort( $roles );
			if ( $roles ) {
				$out[ 'set:' . implode( '+', $roles ) ] = array(
					'type'  => 'roles',
					'roles' => $roles,
				);
			}
			if ( $own ) {
				$out[ 'user:' . $user_id ] = array(
					'type' => 'user',
					'user' => (int) $user_id,
				);
			}
		}
		return $out;
	}

	/** @return string[] */
	private static function caps_for_label( array $spec, array $universe ): array {
		if ( 'user' === $spec['type'] ) {
			$user = get_userdata( (int) $spec['user'] );
			return $user ? self::true_caps( $user, $universe ) : array();
		}
		return self::role_set_caps( $spec['roles'], $universe );
	}

	/** @return array{roles?:string[],user?:int,type:string}|null */
	private static function spec_from_label( string $label ): ?array {
		if ( 0 === strpos( $label, 'role:' ) ) {
			return array(
				'type'  => 'roles',
				'roles' => array( substr( $label, 5 ) ),
			);
		}
		if ( 0 === strpos( $label, 'set:' ) ) {
			return array(
				'type'  => 'roles',
				'roles' => explode( '+', substr( $label, 4 ) ),
			);
		}
		if ( 0 === strpos( $label, 'user:' ) ) {
			return array(
				'type' => 'user',
				'user' => (int) substr( $label, 5 ),
			);
		}
		return null;
	}

	/**
	 * Recomputes every entry of a snapshot with its own cap list and lists the differences.
	 *
	 * @return array{entries:int,differences:array[]}|\WP_Error
	 */
	public static function compare( array $snap ) {
		if ( ( $snap['format'] ?? '' ) !== self::SNAP_FORMAT || empty( $snap['entries'] ) || ! is_array( $snap['entries'] ) || empty( $snap['universe'] ) || ! is_array( $snap['universe'] ) ) {
			return new \WP_Error( 'rolegate_snapshot_invalid', __( 'That file is not a capability snapshot, or it holds no entries.', 'role-gatekeeper' ) );
		}
		$universe = array_values( array_filter( $snap['universe'], 'is_string' ) );
		$now      = self::snapshot( $universe );
		$diffs    = array();
		foreach ( $snap['entries'] as $label => $old ) {
			$spec = self::spec_from_label( (string) $label );
			if ( ! $spec ) {
				continue;
			}
			$caps = isset( $now['entries'][ $label ] ) ? $now['entries'][ $label ]['caps'] : self::caps_for_label( $spec, $universe );
			$fresh   = self::entry( $caps );
			$old_sha = isset( $old['sha256'] ) ? (string) $old['sha256'] : '';
			if ( $fresh['sha256'] !== $old_sha ) {
				$before  = isset( $old['caps'] ) && is_array( $old['caps'] ) ? $old['caps'] : array();
				$diffs[] = array(
					'label'   => (string) $label,
					'lost'    => array_values( array_diff( $before, $caps ) ),
					'gained'  => array_values( array_diff( $caps, $before ) ),
					'note'    => '',
					'missing' => false,
				);
			}
		}
		foreach ( array_diff( array_keys( $now['entries'] ), array_keys( $snap['entries'] ) ) as $label ) {
			if ( 0 === strpos( (string) $label, 'role:' ) ) {
				continue;
			}
			$diffs[] = array(
				'label'   => (string) $label,
				'lost'    => array(),
				'gained'  => array(),
				'note'    => __( 'not in the snapshot: a user holds this combination now', 'role-gatekeeper' ),
				'missing' => true,
			);
		}
		return array(
			'entries'     => count( $snap['entries'] ),
			'differences' => $diffs,
		);
	}
}
