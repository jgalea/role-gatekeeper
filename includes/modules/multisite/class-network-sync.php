<?php
namespace Rolewright\Modules\Multisite;

use Rolewright\Modules\Portability\Role_Store;
use Rolewright\Modules\Safety\Guard;

defined( 'ABSPATH' ) || exit;

/**
 * Copies roles (and optionally user memberships) from a source site to every other site
 * on the network, a batch of sites per call. Jobs live in a site transient owned by the
 * super admin who started them.
 */
final class Network_Sync {
	const JOB_KEY       = 'rolewright_ms_job_';
	const JOB_TTL       = DAY_IN_SECONDS;
	const DEFAULT_BATCH = 25;
	const MAX_ERRORS    = 50;

	public static function batch_size(): int {
		$size = (int) get_site_option( Multisite_Module::OPTION_BATCH, self::DEFAULT_BATCH );
		return max( 1, min( 200, $size ) );
	}

	/**
	 * Starts a job.
	 *
	 * @param string   $mode  replace (copy the role exactly) or merge (add its caps only).
	 * @param string[] $roles Role slugs on the source site; empty means all roles.
	 * @return array|\WP_Error The job.
	 */
	public static function start( int $actor, int $source_site, array $roles, string $mode, bool $users ) {
		if ( ! Guard::is_super( $actor ) ) {
			return new \WP_Error( 'rolewright_forbidden', __( 'Only super admins can change roles on every site.', 'rolewright' ) );
		}
		if ( ! get_site( $source_site ) ) {
			return new \WP_Error( 'rolewright_no_site', __( 'That source site does not exist.', 'rolewright' ) );
		}
		switch_to_blog( $source_site );
		$all = Role_Store::all();
		restore_current_blog();

		$picked = array();
		foreach ( $roles ? $roles : array_keys( $all ) as $slug ) {
			if ( isset( $all[ $slug ] ) ) {
				$picked[ $slug ] = $all[ $slug ];
			}
		}
		if ( ! $picked ) {
			return new \WP_Error( 'rolewright_no_role', __( 'The source site has none of the chosen roles.', 'rolewright' ) );
		}
		$job = array(
			'id'         => wp_generate_password( 16, false, false ),
			'actor'      => $actor,
			'source'     => $source_site,
			'network'    => get_current_network_id(),
			'roles'      => $picked,
			'mode'       => 'merge' === $mode ? 'merge' : 'replace',
			'users'      => $users,
			'offset'     => 0,
			'total'      => (int) get_sites(
				array(
					'count'      => true,
					'network_id' => get_current_network_id(),
					'number'     => 0,
				)
			),
			'sites_done' => 0,
			'roles_done' => 0,
			'users_done' => 0,
			'errors'     => array(),
			'finished'   => false,
		);
		self::save( $job );
		return $job;
	}

	public static function get( int $actor, string $id ): ?array {
		$job = get_site_transient( self::JOB_KEY . $actor . '_' . preg_replace( '/[^A-Za-z0-9]/', '', $id ) );
		return is_array( $job ) && (int) $job['actor'] === $actor ? $job : null;
	}

	private static function save( array $job ): void {
		set_site_transient( self::JOB_KEY . $job['actor'] . '_' . $job['id'], $job, self::JOB_TTL );
	}

	/**
	 * Processes the next batch of sites. Paged with offset and number so networks of any
	 * size are covered, not only get_sites()'s default first 100.
	 *
	 * @return array|\WP_Error The updated job.
	 */
	public static function run_batch( array $job, int $actor ) {
		if ( (int) $job['actor'] !== $actor || ! Guard::is_super( $actor ) ) {
			return new \WP_Error( 'rolewright_forbidden', __( 'Only the super admin who started this job can continue it.', 'rolewright' ) );
		}
		if ( $job['finished'] ) {
			return $job;
		}
		$size  = self::batch_size();
		$sites = get_sites(
			array(
				'fields'     => 'ids',
				'network_id' => (int) $job['network'],
				'number'     => $size,
				'offset'     => (int) $job['offset'],
				'orderby'    => 'id',
				'order'      => 'ASC',
			)
		);
		$users = $job['users'] ? self::source_users( (int) $job['source'] ) : array();

		foreach ( $sites as $site_id ) {
			$site_id = (int) $site_id;
			if ( $site_id === (int) $job['source'] ) {
				continue;
			}
			$result             = self::apply_to_site( $site_id, $job['roles'], $job['mode'], $actor );
			$job['roles_done'] += $result['roles'];
			foreach ( $result['errors'] as $error ) {
				$job['errors'][] = $error;
			}
			if ( $users ) {
				$pushed             = self::push_users_to_site( $site_id, $users, $actor );
				$job['users_done'] += $pushed['users'];
				foreach ( $pushed['errors'] as $error ) {
					$job['errors'][] = $error;
				}
			}
			++$job['sites_done'];
		}
		$job['errors']   = array_slice( $job['errors'], 0, self::MAX_ERRORS );
		$job['offset']  += count( $sites );
		$job['finished'] = count( $sites ) < $size;
		self::save( $job );
		return $job;
	}

	/**
	 * Applies role definitions to one site. Every role goes through the same Guard
	 * assertion a single-site edit would, inside that site's context.
	 *
	 * @param array<string,array{name:string,capabilities:array}> $roles
	 * @return array{roles:int,errors:string[]}
	 */
	public static function apply_to_site( int $site_id, array $roles, string $mode, int $actor ): array {
		$out = array(
			'roles'  => 0,
			'errors' => array(),
		);
		switch_to_blog( $site_id );
		try {
			$current = Role_Store::all();
			$changes = array();
			$events  = array();
			foreach ( $roles as $slug => $def ) {
				$before = isset( $current[ $slug ] ) ? $current[ $slug ] : null;
				$caps   = 'merge' === $mode && $before ? array_merge( $before['capabilities'], $def['capabilities'] ) : $def['capabilities'];
				$name   = 'merge' === $mode && $before ? $before['name'] : $def['name'];
				if ( $before && Role_Store::same_caps( $before['capabilities'], $caps ) && $before['name'] === $name ) {
					continue;
				}
				$check = $before ? true : Guard::valid_new_role_slug( (string) $slug );
				if ( true === $check ) {
					$check = Guard::assert_can_modify_role( $actor, (string) $slug, $caps );
				}
				if ( is_wp_error( $check ) ) {
					/* translators: 1: site id, 2: role slug, 3: reason */
					$out['errors'][] = sprintf( __( 'Site %1$d, role %2$s: %3$s', 'rolewright' ), $site_id, $slug, $check->get_error_message() );
					continue;
				}
				$changes[ $slug ] = array(
					'name'         => $name,
					'capabilities' => $caps,
				);
				$events[ $slug ]  = $before;
			}
			if ( $changes ) {
				$written = Role_Store::write( $changes );
				if ( is_wp_error( $written ) ) {
					/* translators: 1: site id, 2: reason */
					$out['errors'][] = sprintf( __( 'Site %1$d: %2$s', 'rolewright' ), $site_id, $written->get_error_message() );
				} else {
					foreach ( $changes as $slug => $def ) {
						++$out['roles'];
						do_action(
							'rolewright_changed',
							null === $events[ $slug ] ? 'role.created' : 'caps.updated',
							array(
								'actor'   => $actor,
								'target'  => $slug,
								'site_id' => $site_id,
								'before'  => null === $events[ $slug ] ? array() : $events[ $slug ],
								'after'   => $def,
							)
						);
					}
				}
			}
		} finally {
			restore_current_blog();
		}
		return $out;
	}

	/**
	 * @return array<int,string[]> user id => role slugs on the source site.
	 */
	public static function source_users( int $source_site ): array {
		$out = array();
		switch_to_blog( $source_site );
		try {
			$ids = get_users(
				array(
					'blog_id' => $source_site,
					'fields'  => 'ID',
					'number'  => -1,
				)
			);
			foreach ( $ids as $id ) {
				$user  = new \WP_User( (int) $id, '', $source_site );
				$roles = array_values( array_filter( (array) $user->roles, 'is_string' ) );
				if ( $roles ) {
					$out[ (int) $id ] = $roles;
				}
			}
		} finally {
			restore_current_blog();
		}
		return $out;
	}

	/**
	 * Adds source-site users that aren't members of the target site, with their source
	 * roles. Existing members keep their roles. Each role must pass can_assign_role on
	 * the target site.
	 *
	 * @param array<int,string[]> $users
	 * @return array{users:int,errors:string[]}
	 */
	public static function push_users_to_site( int $site_id, array $users, int $actor ): array {
		$out = array(
			'users'  => 0,
			'errors' => array(),
		);
		switch_to_blog( $site_id );
		try {
			foreach ( $users as $uid => $roles ) {
				if ( is_user_member_of_blog( $uid, $site_id ) ) {
					continue;
				}
				$ok = array();
				foreach ( $roles as $role ) {
					if ( get_role( $role ) && Guard::can_assign_role( $actor, $role, $uid ) ) {
						$ok[] = $role;
					}
				}
				if ( ! $ok ) {
					/* translators: 1: user id, 2: site id */
					$out['errors'][] = sprintf( __( 'User %1$d was not added to site %2$d: none of their roles exist there or may be assigned.', 'rolewright' ), $uid, $site_id );
					continue;
				}
				$added = add_user_to_blog( $site_id, $uid, $ok[0] );
				if ( is_wp_error( $added ) ) {
					/* translators: 1: user id, 2: site id, 3: reason */
					$out['errors'][] = sprintf( __( 'User %1$d was not added to site %2$d: %3$s', 'rolewright' ), $uid, $site_id, $added->get_error_message() );
					continue;
				}
				$user = new \WP_User( $uid, '', $site_id );
				foreach ( array_slice( $ok, 1 ) as $role ) {
					$user->add_role( $role );
				}
				++$out['users'];
				do_action(
					'rolewright_changed',
					'user.roles',
					array(
						'actor'   => $actor,
						'target'  => $uid,
						'site_id' => $site_id,
						'before'  => array( 'roles' => array() ),
						'after'   => array( 'roles' => $ok ),
					)
				);
			}
		} finally {
			restore_current_blog();
		}
		return $out;
	}
}
