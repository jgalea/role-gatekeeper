<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Plugin;
use Rolegate\Modules\Disabled_Users\Accounts;

defined( 'ABSPATH' ) || exit;

/**
 * Plans a migration from Disable Users: every account it flagged with ja_disable_user is
 * flagged here too. The Disable Users flag is never touched, so either plugin can go.
 */
final class Disable_Users_Migration {
	const PLUGIN = 'disable-users/init.php';
	const META   = 'ja_disable_user';
	const MODULE = 'disabled-users';

	private static function is_active( string $plugin = self::PLUGIN ): bool {
		if ( in_array( $plugin, (array) get_option( 'active_plugins', array() ), true ) ) {
			return true;
		}
		return is_multisite() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ $plugin ] );
	}

	/** @return int[] ids of existing users Disable Users has flagged */
	public static function flagged( string $meta = self::META ): array {
		global $wpdb;
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT m.user_id FROM {$wpdb->usermeta} m INNER JOIN {$wpdb->users} u ON u.ID = m.user_id WHERE m.meta_key = %s AND m.meta_value = %s ORDER BY m.user_id", $meta, '1' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ids = array_values( array_unique( array_map( 'intval', (array) $ids ) ) );
		if ( is_multisite() ) {
			$ids = array_values( array_filter( $ids, 'is_user_member_of_blog' ) );
		}
		return $ids;
	}

	public static function plan( int $actor, array $opts = array() ): array {
		return self::build( $actor, 'disable-users', 'Disable Users', self::PLUGIN, self::META );
	}

	/** Shared by every migrator whose source plugin flags accounts with a user meta value of 1. */
	public static function build( int $actor, string $source, string $name, string $plugin, string $meta ): array {
		$area    = __( 'Disabled accounts', 'role-gatekeeper' );
		$plan    = array(
			'source'   => $source,
			'label'    => $name,
			'detected' => false,
			'rows'     => array(),
			'ops'      => Migrator::empty_ops(),
		);
		$flagged = self::flagged( $meta );

		$plan['detected'] = $flagged || self::is_active( $plugin );
		if ( ! $plan['detected'] ) {
			$plan['rows'][] = Migrator::row( __( 'Source', 'role-gatekeeper' ), $name, 'info', sprintf( /* translators: %s: plugin name */ __( 'No %s data found on this site.', 'role-gatekeeper' ), $name ) );
			return $plan;
		}

		update_meta_cache( 'user', $flagged );
		$rows    = array();
		$ops     = Migrator::empty_ops();
		$already = array();
		$todo    = array();
		foreach ( $flagged as $id ) {
			if ( Accounts::is_disabled( $id ) ) {
				$already[] = $id;
			} else {
				$todo[] = $id;
			}
		}

		if ( $actor > 0 && in_array( $actor, $todo, true ) ) {
			$todo   = array_values( array_diff( $todo, array( $actor ) ) );
			$rows[] = Migrator::row( $area, self::login( $actor ), 'blocked', __( 'This is your own account, which you can\'t disable.', 'role-gatekeeper' ) );
		}
		if ( ! Migrator::is_shell( $actor ) ) {
			$denied = array();
			foreach ( $todo as $id ) {
				if ( true !== Accounts::check_actor( $actor, $id ) ) {
					$denied[] = $id;
				}
			}
			if ( $denied ) {
				$todo   = array_values( array_diff( $todo, $denied ) );
				$rows[] = Migrator::row( $area, implode( ', ', array_map( array( __CLASS__, 'login' ), array_slice( $denied, 0, 10 ) ) ), 'blocked', __( 'You can\'t change the accounts of these users.', 'role-gatekeeper' ) );
			}
		}
		$managers = Accounts::active_managers();
		if ( $managers && ! array_diff( $managers, $todo ) ) {
			$keep   = (int) current( array_intersect( $managers, $todo ) );
			$todo   = array_values( array_diff( $todo, array( $keep ) ) );
			$rows[] = Migrator::row( $area, self::login( $keep ), 'blocked', __( 'This is the last active user who can manage Role Gatekeeper, so the account stays enabled.', 'role-gatekeeper' ) );
		}

		if ( $todo ) {
			$names = array_map( array( __CLASS__, 'login' ), array_slice( $todo, 0, 10 ) );
			$more  = count( $todo ) - count( $names );
			$list  = implode( ', ', $names ) . ( $more > 0 ? ', ' . sprintf( /* translators: %d: number of further accounts */ __( '+%d more', 'role-gatekeeper' ), $more ) : '' );
			/* translators: %d: number of accounts */
			$rows[]       = Migrator::row( $area, sprintf( _n( '%d account', '%d accounts', count( $todo ), 'role-gatekeeper' ), count( $todo ) ), 'add', $list );
			$ops['users'] = $todo;
		}
		if ( $already ) {
			/* translators: %d: number of accounts */
			$rows[] = Migrator::row( $area, sprintf( _n( '%d account', '%d accounts', count( $already ), 'role-gatekeeper' ), count( $already ) ), 'unchanged', __( 'Already disabled here.', 'role-gatekeeper' ) );
		}
		if ( ! $flagged ) {
			$rows[] = Migrator::row( $area, __( 'Disabled accounts', 'role-gatekeeper' ), 'info', sprintf( /* translators: %s: plugin name */ __( '%s has no disabled accounts on this site.', 'role-gatekeeper' ), $name ) );
		}
		if ( ( $todo || $already ) && isset( Plugin::modules()[ self::MODULE ] ) && ! Plugin::is_enabled( self::MODULE ) ) {
			$ops['modules'][] = self::MODULE;
			$rows[]           = Migrator::row( __( 'Modules', 'role-gatekeeper' ), Plugin::modules()[ self::MODULE ]->title(), 'add', __( 'Switch on, so the disabled accounts are blocked.', 'role-gatekeeper' ) );
		}
		$rows[] = Migrator::row( $name, __( 'Its own settings', 'role-gatekeeper' ), 'info', __( 'Left as they are, so you can deactivate either plugin.', 'role-gatekeeper' ) );

		$plan['rows'] = $rows;
		$plan['ops']  = $ops;
		return $plan;
	}

	private static function login( int $user_id ): string {
		$user = get_userdata( $user_id );
		return $user ? $user->user_login : '#' . $user_id;
	}
}
