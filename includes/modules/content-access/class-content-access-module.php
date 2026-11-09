<?php
namespace Rolewright\Modules\Content_Access;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Content_Access_Module extends Module {
	public function id(): string {
		return 'content-access';
	}

	public function title(): string {
		return __( 'Content access', 'rolewright' );
	}

	public function description(): string {
		return __( 'Restrict posts, blocks, widgets, menu items and shortcode content to selected roles.', 'rolewright' );
	}

	public function init(): void {
		add_filter( 'rolewright_module_restricts_user', array( __CLASS__, 'restricts_user' ), 10, 3 );
		Access::register();
		( new Post_Editor() )->register();
		( new Query_Guard() )->register();
		( new Rest_Guard() )->register();
		( new Visibility() )->register();
		( new Widget_Visibility() )->register();
		( new Menu_Visibility() )->register();
	}

	/**
	 * True when some restricted post is hidden from the user.
	 *
	 * @param bool   $restricts
	 * @param string $module
	 * @param int    $user_id
	 */
	public static function restricts_user( $restricts, $module, $user_id ): bool {
		if ( $restricts || 'content-access' !== $module ) {
			return (bool) $restricts;
		}
		foreach ( array_keys( Access::protected_map() ) as $post_id ) {
			if ( user_can( (int) $user_id, 'edit_post', (int) $post_id ) ) {
				continue;
			}
			$allowed = false;
			foreach ( Access::rules( (int) $post_id )['roles'] as $role ) {
				if ( user_can( (int) $user_id, (string) $role ) ) {
					$allowed = true;
					break;
				}
			}
			if ( ! $allowed ) {
				return true;
			}
		}
		return false;
	}
}
