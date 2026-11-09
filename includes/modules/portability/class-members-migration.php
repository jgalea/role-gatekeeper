<?php
namespace Rolegate\Modules\Portability;

use Rolegate\Core\Plugin;
use Rolegate\Modules\Content_Access\Access;
use Rolegate\Modules\Content_Access\Content_Settings;
use Rolegate\Modules\Deny_Hierarchy\Denials;
use Rolegate\Modules\Site_Access\Admin_Gate;
use Rolegate\Modules\Site_Access\Site_Access_Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Plans a migration from the Members plugin's stored data: denied caps in roles, per-post
 * content permissions, block permissions and its settings. Read only.
 */
final class Members_Migration {
	const PLUGIN       = 'members/members.php';
	const BLOCK_ADDON  = 'members-block-permissions';
	const META_ROLE    = '_members_access_role';
	const META_LEGACY  = '_role';
	const META_MESSAGE = '_members_access_error';

	/** Members' own defaults for settings it never saved. */
	private static function defaults(): array {
		return array(
			'role_manager'              => 1,
			'content_permissions'       => 1,
			'private_blog'              => 0,
			'private_feed'              => 0,
			'content_permissions_error' => 'Sorry, but you do not have permission to view this content.',
			'explicit_denied_caps'      => true,
			'multi_roles'               => true,
			'show_human_caps'           => true,
			'private_rest_api'          => false,
			'hide_posts_rest_api'       => true,
		);
	}

	public static function settings(): array {
		$stored = get_option( 'members_settings', array() );
		return array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	public static function is_active(): bool {
		$active = (array) get_option( 'active_plugins', array() );
		if ( in_array( self::PLUGIN, $active, true ) ) {
			return true;
		}
		return is_multisite() && isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ self::PLUGIN ] );
	}

	/** @return array<int,array{roles:string[],legacy:string[],message:string}> */
	private static function post_meta(): array {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT post_id, meta_key, meta_value FROM {$wpdb->postmeta} WHERE meta_key IN ( %s, %s, %s ) ORDER BY meta_id", self::META_ROLE, self::META_LEGACY, self::META_MESSAGE ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$id = (int) $row->post_id;
			if ( ! isset( $out[ $id ] ) ) {
				$out[ $id ] = array(
					'roles'   => array(),
					'legacy'  => array(),
					'message' => '',
				);
			}
			$value = maybe_unserialize( $row->meta_value );
			if ( self::META_MESSAGE === $row->meta_key ) {
				$out[ $id ]['message'] = is_string( $value ) ? $value : '';
			} elseif ( is_string( $value ) && '' !== $value ) {
				$out[ $id ][ self::META_ROLE === $row->meta_key ? 'roles' : 'legacy' ][] = $value;
			}
		}
		ksort( $out );
		return $out;
	}

	private static function post_label( \WP_Post $post ): string {
		$title = '' !== trim( $post->post_title ) ? wp_strip_all_tags( $post->post_title ) : __( '(no title)', 'role-gatekeeper' );
		return sprintf( '#%d %s (%s)', $post->ID, mb_substr( $title, 0, 60 ), $post->post_type );
	}

	/**
	 * @param array $opts confirm_private (bool)
	 */
	public static function plan( int $actor, array $opts = array() ): array {
		$plan             = array(
			'source'   => 'members',
			'label'    => 'Members',
			'detected' => false,
			'rows'     => array(),
			'ops'      => Migrator::empty_ops(),
		);
		$meta             = self::post_meta();
		$plan['detected'] = self::is_active() || false !== get_option( 'members_settings', false ) || (bool) $meta;
		if ( ! $plan['detected'] ) {
			$plan['rows'][] = Migrator::row( __( 'Source', 'role-gatekeeper' ), 'Members', 'info', __( 'No Members data found on this site.', 'role-gatekeeper' ) );
			return $plan;
		}
		$settings = self::settings();
		$rows     = array();
		$ops      = Migrator::empty_ops();
		$shell    = Migrator::is_shell( $actor );

		$rows[] = Migrator::row( __( 'Roles', 'role-gatekeeper' ), __( 'Roles and their capabilities', 'role-gatekeeper' ), 'info', __( 'Stored in WordPress\'s own roles list and used here as they are.', 'role-gatekeeper' ) );
		$rows[] = Migrator::row( __( 'Users', 'role-gatekeeper' ), __( 'Several roles per user', 'role-gatekeeper' ), 'info', __( 'Stored on each user by WordPress and used here as they are.', 'role-gatekeeper' ) );

		$denying = self::plan_denials( $actor, $settings, $rows, $ops );
		self::plan_posts( $actor, $shell, $meta, ! empty( $settings['content_permissions'] ), $rows, $ops );
		self::plan_blocks( $actor, $shell, $rows, $ops );

		if ( ! empty( $settings['content_permissions'] ) ) {
			$message = trim( Access::sanitize_message( (string) $settings['content_permissions_error'] ) );
			$ours    = Content_Settings::default_message();
			$area    = __( 'Settings', 'role-gatekeeper' );
			$item    = __( 'Default message on restricted content', 'role-gatekeeper' );
			if ( '' === $message ) {
				$rows[] = Migrator::row( $area, $item, 'info', __( 'Members has no default message set.', 'role-gatekeeper' ) );
			} elseif ( $ours === $message ) {
				$rows[] = Migrator::row( $area, $item, 'unchanged', $message );
			} elseif ( '' !== $ours ) {
				$rows[] = Migrator::row( $area, $item, 'conflict', __( 'A default message is already set here; it stays.', 'role-gatekeeper' ) );
			} else {
				$ops['content_message'] = $message;
				$rows[]                 = Migrator::row( $area, $item, 'add', $message );
			}
		}

		$private = self::plan_private( $actor, $settings, $opts, $rows, $ops );

		$needed = array();
		if ( ! empty( $settings['role_manager'] ) ) {
			$needed = array_merge( $needed, array( 'roles', 'capabilities', 'user-roles' ) );
		}
		if ( ! empty( $settings['content_permissions'] ) ) {
			$needed[] = 'content-access';
		}
		if ( $denying ) {
			$needed[] = 'deny-hierarchy';
		}
		if ( $private ) {
			$needed[] = 'site-access';
		}
		foreach ( array_unique( $needed ) as $id ) {
			if ( ! isset( Plugin::modules()[ $id ] ) ) {
				continue;
			}
			$title = Plugin::modules()[ $id ]->title();
			if ( Plugin::is_enabled( $id ) ) {
				$rows[] = Migrator::row( __( 'Modules', 'role-gatekeeper' ), $title, 'unchanged', __( 'Already on.', 'role-gatekeeper' ) );
			} else {
				$ops['modules'][] = $id;
				$rows[]           = Migrator::row( __( 'Modules', 'role-gatekeeper' ), $title, 'add', __( 'Switch on.', 'role-gatekeeper' ) );
			}
		}

		self::plan_notes( $settings, $rows );

		$plan['rows'] = $rows;
		$plan['ops']  = $ops;
		return $plan;
	}

	/** @return bool whether any role carries a deny Members enforces */
	private static function plan_denials( int $actor, array $settings, array &$rows, array &$ops ): bool {
		$area    = __( 'Denied capabilities', 'role-gatekeeper' );
		$denying = false;
		$false   = array();
		foreach ( Role_Store::all() as $slug => $def ) {
			$list = array_keys(
				array_filter(
					$def['capabilities'],
					function ( $grant ) {
						return false === $grant;
					}
				)
			);
			if ( $list ) {
				sort( $list );
				$false[ $slug ] = $list;
			}
		}
		if ( ! $false ) {
			return false;
		}
		if ( empty( $settings['explicit_denied_caps'] ) ) {
			foreach ( $false as $slug => $list ) {
				$rows[] = Migrator::row( $area, $slug, 'skip', __( 'Members\' "deny wins" setting is off on this site, so these denials only apply to users with this role alone, which WordPress already does.', 'role-gatekeeper' ) );
			}
			return false;
		}
		foreach ( $false as $slug => $list ) {
			$denying = true;
			$current = Denials::for_role( $slug );
			$target  = array_values( array_unique( array_merge( $current, $list ) ) );
			sort( $target );
			$sorted = $current;
			sort( $sorted );
			if ( $target === $sorted ) {
				$rows[] = Migrator::row( $area, $slug, 'unchanged', implode( ', ', $list ) );
				continue;
			}
			$check = Denials::validate( $actor, $slug, $target );
			if ( is_wp_error( $check ) ) {
				$rows[] = Migrator::row( $area, $slug, 'blocked', $check->get_error_message() );
				continue;
			}
			$ops['denials'][ $slug ] = $check;
			$rows[]                  = Migrator::row( $area, $slug, 'add', implode( ', ', array_diff( $list, $current ) ) );
		}

		$own = array();
		foreach ( Migrator::user_cap_rows() as $caps ) {
			$roles = array_keys( array_filter( $caps ) );
			$roles = array_values( array_filter( $roles, array( wp_roles(), 'is_role' ) ) );
			if ( 1 !== count( $roles ) || empty( $false[ $roles[0] ] ) ) {
				continue;
			}
			foreach ( $false[ $roles[0] ] as $cap ) {
				if ( ! empty( $caps[ $cap ] ) ) {
					$own[ $cap ] = true;
				}
			}
		}
		if ( $own ) {
			$rows[] = Migrator::row(
				$area,
				__( 'Users with one role and their own grant', 'role-gatekeeper' ),
				'info',
				/* translators: %s: comma-separated capability names */
				sprintf( __( 'Some users have one role that denies a capability and hold it again on their own account (%s). Members lets that grant through; here the role\'s denial applies. Check those users before or after applying.', 'role-gatekeeper' ), implode( ', ', array_keys( $own ) ) )
			);
		}
		return $denying;
	}

	private static function plan_posts( int $actor, bool $shell, array $meta, bool $enabled, array &$rows, array &$ops ): void {
		$area = __( 'Content permissions', 'role-gatekeeper' );
		if ( ! $meta ) {
			$rows[] = Migrator::row( $area, __( 'Posts', 'role-gatekeeper' ), 'info', __( 'No post carries a Members access rule or message.', 'role-gatekeeper' ) );
			return;
		}
		if ( ! $enabled ) {
			$rows[] = Migrator::row( $area, __( 'Posts', 'role-gatekeeper' ), 'skip', __( 'Content permissions are off in Members, so its post rules don\'t apply now.', 'role-gatekeeper' ) );
			return;
		}
		$unchanged = 0;
		foreach ( $meta as $post_id => $m ) {
			$post = get_post( $post_id );
			if ( ! $post || 'revision' === $post->post_type ) {
				continue;
			}
			$item    = self::post_label( $post );
			$members = $m['roles'] ? $m['roles'] : $m['legacy'];
			$known   = Access::sanitize_roles( $members );
			$unknown = array_values( array_diff( array_unique( $members ), $known ) );
			$raw_msg = trim( $m['message'] );
			$message = trim( Access::sanitize_message( $raw_msg ) );
			$ours    = Migrator::post_rules( $post_id );
			$add     = array();
			$notes   = array();

			if ( $members && ! $known ) {
				/* translators: %s: comma-separated role slugs */
				$rows[] = Migrator::row( $area, $item, 'skip', sprintf( __( 'Its roles no longer exist: %s.', 'role-gatekeeper' ), implode( ', ', $unknown ) ) );
				continue;
			}
			if ( $unknown ) {
				/* translators: %s: comma-separated role slugs */
				$notes[] = sprintf( __( 'Roles that no longer exist are left out: %s.', 'role-gatekeeper' ), implode( ', ', $unknown ) );
			}
			if ( $known ) {
				$a = $known;
				$b = $ours['roles'];
				sort( $a );
				sort( $b );
				if ( ! $ours['roles'] ) {
					$add['roles'] = $known;
				} elseif ( $a !== $b ) {
					$rows[] = Migrator::row( $area, $item, 'conflict', __( 'The post already has its own access rule here; it stays.', 'role-gatekeeper' ) );
					continue;
				}
			}
			if ( '' !== $message ) {
				if ( '' === trim( $ours['message'] ) ) {
					$add['message'] = $message;
					if ( $message !== $raw_msg ) {
						$notes[] = __( 'Markup outside links, paragraphs, line breaks, bold and italic is removed from the message.', 'role-gatekeeper' );
					}
					if ( ! $known && ! $ours['roles'] ) {
						$notes[] = __( 'The post has no role restriction, so the message shows only once it gets one.', 'role-gatekeeper' );
					}
				} elseif ( $ours['message'] !== $message ) {
					$notes[] = __( 'The post already has its own message here; it stays.', 'role-gatekeeper' );
				}
			}
			if ( ! $add ) {
				++$unchanged;
				continue;
			}
			if ( ! $shell && ! user_can( $actor, 'edit_post', $post_id ) ) {
				$rows[] = Migrator::row( $area, $item, 'blocked', __( 'You can\'t edit this post.', 'role-gatekeeper' ) );
				continue;
			}
			$ops['posts'][ $post_id ] = $add;
			$parts                    = array();
			if ( isset( $add['roles'] ) ) {
				/* translators: %s: comma-separated role slugs */
				$parts[] = sprintf( __( 'Only these roles: %s.', 'role-gatekeeper' ), implode( ', ', $add['roles'] ) );
			}
			if ( isset( $add['message'] ) ) {
				/* translators: %s: message text */
				$parts[] = sprintf( __( 'Message: %s', 'role-gatekeeper' ), wp_strip_all_tags( $add['message'] ) );
			}
			$rows[] = Migrator::row( $area, $item, 'add', implode( ' ', array_merge( $parts, $notes ) ) );
		}
		if ( $unchanged ) {
			/* translators: %d: number of posts */
			$rows[] = Migrator::row( $area, __( 'Posts', 'role-gatekeeper' ), 'unchanged', sprintf( _n( '%d post already carried over or with nothing to carry.', '%d posts already carried over or with nothing to carry.', $unchanged, 'role-gatekeeper' ), $unchanged ) );
		}
	}

	/**
	 * Members block permissions to our block attributes, through parse_blocks and
	 * serialize_blocks. A post whose content doesn't survive that round trip unchanged is
	 * skipped, so nothing but the attributes can change.
	 */
	private static function plan_blocks( int $actor, bool $shell, array &$rows, array &$ops ): void {
		global $wpdb;
		$area = __( 'Block permissions', 'role-gatekeeper' );
		$ids  = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type <> 'revision' AND post_content LIKE %s ORDER BY ID", '%' . $wpdb->esc_like( 'blockPermissions' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( ! $ids ) {
			return;
		}
		$active = in_array( self::BLOCK_ADDON, array_filter( (array) get_option( 'members_active_addons', array() ), 'is_string' ), true );
		if ( ! $active ) {
			/* translators: %d: number of posts */
			$rows[] = Migrator::row( $area, __( 'Posts', 'role-gatekeeper' ), 'skip', sprintf( __( 'Members\' block permissions add-on is off, so the block rules in %d post(s) don\'t apply now.', 'role-gatekeeper' ), count( $ids ) ) );
			return;
		}
		foreach ( $ids as $post_id ) {
			$post = get_post( (int) $post_id );
			if ( ! $post ) {
				continue;
			}
			$item    = self::post_label( $post );
			$content = (string) $post->post_content;
			$blocks  = parse_blocks( $content );
			if ( serialize_blocks( $blocks ) !== $content ) {
				$rows[] = Migrator::row( $area, $item, 'skip', __( 'The content doesn\'t pass through the block parser unchanged, so its blocks are left as they are.', 'role-gatekeeper' ) );
				continue;
			}
			$notes   = array();
			$changed = 0;
			$same    = 0;
			$blocks  = self::map_blocks( $blocks, $notes, $changed, $same );
			if ( ! $changed ) {
				$rows[] = Migrator::row( $area, $item, $same && ! $notes ? 'unchanged' : 'skip', $notes ? implode( ' ', array_unique( $notes ) ) : __( 'Already carried over.', 'role-gatekeeper' ) );
				continue;
			}
			if ( ! $shell && ! user_can( $actor, 'edit_post', (int) $post_id ) ) {
				$rows[] = Migrator::row( $area, $item, 'blocked', __( 'You can\'t edit this post.', 'role-gatekeeper' ) );
				continue;
			}
			$ops['blocks'][ (int) $post_id ] = array(
				'before' => $content,
				'after'  => serialize_blocks( $blocks ),
			);
			/* translators: %d: number of blocks */
			$rows[] = Migrator::row( $area, $item, 'add', trim( sprintf( _n( '%d block.', '%d blocks.', $changed, 'role-gatekeeper' ), $changed ) . ' ' . implode( ' ', array_unique( $notes ) ) ) );
		}
	}

	private static function map_blocks( array $blocks, array &$notes, int &$changed, int &$same ): array {
		foreach ( $blocks as $i => $block ) {
			$attrs = isset( $block['attrs'] ) && is_array( $block['attrs'] ) ? $block['attrs'] : array();
			$rule  = self::map_attrs( $attrs, $notes );
			if ( $rule ) {
				$has = isset( $attrs['rolegateMode'] ) ? array(
					'rolegateMode'  => $attrs['rolegateMode'],
					'rolegateRoles' => isset( $attrs['rolegateRoles'] ) ? $attrs['rolegateRoles'] : array(),
				) : null;
				if ( null === $has ) {
					foreach ( $rule as $key => $value ) {
						$blocks[ $i ]['attrs'][ $key ] = $value;
					}
					++$changed;
				} elseif ( $has['rolegateMode'] === $rule['rolegateMode'] && array_values( (array) $has['rolegateRoles'] ) === array_values( (array) ( $rule['rolegateRoles'] ?? array() ) ) ) {
					++$same;
				} else {
					$notes[] = __( 'A block already has its own visibility rule here; it stays.', 'role-gatekeeper' );
				}
			}
			if ( ! empty( $block['innerBlocks'] ) ) {
				$blocks[ $i ]['innerBlocks'] = self::map_blocks( $block['innerBlocks'], $notes, $changed, $same );
			}
		}
		return $blocks;
	}

	/** @return array|null our attributes, or null when there is nothing to carry over. */
	private static function map_attrs( array $attrs, array &$notes ): ?array {
		$condition = isset( $attrs['blockPermissionsCondition'] ) && is_string( $attrs['blockPermissionsCondition'] ) ? $attrs['blockPermissionsCondition'] : '';
		$type      = isset( $attrs['blockPermissionsType'] ) && is_string( $attrs['blockPermissionsType'] ) ? $attrs['blockPermissionsType'] : '';
		if ( '' === $condition || '' === $type ) {
			return null;
		}
		if ( ! in_array( $condition, array( '=', '!=' ), true ) ) {
			$notes[] = __( 'A block rule has a condition that can\'t be read; that block is left as it is.', 'role-gatekeeper' );
			return null;
		}
		$rule = null;
		if ( 'user-status' === $type ) {
			$status = isset( $attrs['blockPermissionsUserStatus'] ) ? (string) $attrs['blockPermissionsUserStatus'] : '';
			if ( ! in_array( $status, array( 'logged-in', 'logged-out' ), true ) ) {
				return null;
			}
			$in   = ( 'logged-in' === $status ) === ( '=' === $condition );
			$rule = array( 'rolegateMode' => $in ? 'logged_in' : 'logged_out' );
		} elseif ( 'role' === $type ) {
			$roles = isset( $attrs['blockPermissionsRoles'] ) && is_array( $attrs['blockPermissionsRoles'] ) ? $attrs['blockPermissionsRoles'] : array();
			if ( ! $roles ) {
				return null;
			}
			if ( '!=' === $condition ) {
				$notes[] = __( 'A block hidden from chosen roles has no counterpart here (blocks can be shown to chosen roles); that block is left as it is.', 'role-gatekeeper' );
				return null;
			}
			$known = Access::sanitize_roles( $roles );
			if ( ! $known ) {
				$notes[] = __( 'A block is limited to roles that no longer exist; that block is left as it is.', 'role-gatekeeper' );
				return null;
			}
			$rule = array(
				'rolegateMode'  => 'roles',
				'rolegateRoles' => $known,
			);
		} elseif ( 'cap' === $type ) {
			$notes[] = __( 'A block rule based on a capability has no counterpart here (blocks can be shown to chosen roles); that block is left as it is.', 'role-gatekeeper' );
			return null;
		} else {
			return null;
		}
		if ( isset( $attrs['blockPermissionsMessage'] ) && is_string( $attrs['blockPermissionsMessage'] ) && '' !== trim( $attrs['blockPermissionsMessage'] ) ) {
			$notes[] = __( 'Hidden blocks show nothing here, so a block\'s replacement message isn\'t used.', 'role-gatekeeper' );
		}
		return $rule;
	}

	/** @return bool whether private-site mode is part of the migration */
	private static function plan_private( int $actor, array $settings, array $opts, array &$rows, array &$ops ): bool {
		$area = __( 'Settings', 'role-gatekeeper' );
		$item = __( 'Private site', 'role-gatekeeper' );
		if ( empty( $settings['private_blog'] ) ) {
			if ( ! empty( $settings['private_feed'] ) || ! empty( $settings['private_rest_api'] ) ) {
				$rows[] = Migrator::row( $area, __( 'Private feed and REST API', 'role-gatekeeper' ), 'skip', __( 'Here these apply together with private-site mode, which is off in Members.', 'role-gatekeeper' ) );
			}
			return false;
		}
		$current = Site_Access_Settings::get();
		$want    = array(
			'private_enabled' => true,
			'private_feed'    => ! empty( $settings['private_feed'] ),
			'private_rest'    => ! empty( $settings['private_rest_api'] ),
		);
		if ( ! empty( $current['private_enabled'] ) && (bool) $current['private_feed'] === $want['private_feed'] && (bool) $current['private_rest'] === $want['private_rest'] ) {
			$rows[] = Migrator::row( $area, $item, 'unchanged', __( 'Already on.', 'role-gatekeeper' ) );
			return true;
		}
		if ( empty( $opts['confirm_private'] ) ) {
			$rows[] = Migrator::row( $area, $item, 'skip', __( 'Members keeps the site private to logged-in users. Confirm private-site mode to carry this over (WP-CLI: --confirm-private).', 'role-gatekeeper' ) );
			return false;
		}
		$raw                    = array_merge( $current, $want );
		$raw['confirm_private'] = 1;
		$new                    = Site_Access_Settings::sanitize( $raw, $current, max( 0, $actor ) );
		if ( is_wp_error( $new ) ) {
			$rows[] = Migrator::row( $area, $item, 'blocked', $new->get_error_message() );
			return false;
		}
		$user = $actor > 0 ? get_userdata( $actor ) : false;
		if ( $user && Admin_Gate::is_gated( $user, $new ) ) {
			$rows[] = Migrator::row( $area, $item, 'blocked', __( 'These settings would lock you out of wp-admin.', 'role-gatekeeper' ) );
			return false;
		}
		$ops['site_access'] = $new;
		$detail             = array( __( 'Private-site mode on.', 'role-gatekeeper' ) );
		$detail[]           = $want['private_feed'] ? __( 'Feeds private.', 'role-gatekeeper' ) : __( 'Feeds public.', 'role-gatekeeper' );
		$detail[]           = $want['private_rest'] ? __( 'REST API private.', 'role-gatekeeper' ) : __( 'REST API public.', 'role-gatekeeper' );
		$rows[]             = Migrator::row( $area, $item, 'add', implode( ' ', $detail ) );
		return true;
	}

	private static function plan_notes( array $settings, array &$rows ): void {
		$area   = __( 'Other features', 'role-gatekeeper' );
		$rows[] = Migrator::row( $area, __( 'Who can view a restricted post', 'role-gatekeeper' ), 'info', __( 'Members also lets the post author and holders of restrict_content in; here anyone who can edit the post can view it, as can the chosen roles.', 'role-gatekeeper' ) );
		if ( ! empty( $settings['show_human_caps'] ) ) {
			$rows[] = Migrator::row( $area, __( 'Readable capability names', 'role-gatekeeper' ), 'info', __( 'The capability editor here shows readable labels without a setting.', 'role-gatekeeper' ) );
		}
		if ( ! empty( $settings['hide_posts_rest_api'] ) ) {
			$rows[] = Migrator::row( $area, __( 'Restricted posts in the REST API', 'role-gatekeeper' ), 'info', __( 'Hidden from people who can\'t view them, here as well.', 'role-gatekeeper' ) );
		}
		if ( ! empty( $settings['login_form_widget'] ) ) {
			$rows[] = Migrator::row( $area, __( 'Login form widget', 'role-gatekeeper' ), 'skip', __( 'No widget here; the [rolegate_login_form] shortcode shows a login form.', 'role-gatekeeper' ) );
		}
		if ( ! empty( $settings['users_widget'] ) ) {
			$rows[] = Migrator::row( $area, __( 'Users widget', 'role-gatekeeper' ), 'skip', __( 'No counterpart here.', 'role-gatekeeper' ) );
		}
		foreach ( array_filter( (array) get_option( 'members_active_addons', array() ), 'is_string' ) as $addon ) {
			if ( self::BLOCK_ADDON === $addon ) {
				continue;
			}
			$rows[] = Migrator::row( $area, sanitize_key( $addon ), 'skip', __( 'Members add-on: its data is left as it is and not read here.', 'role-gatekeeper' ) );
		}
	}
}
