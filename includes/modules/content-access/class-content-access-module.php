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
		Access::register();
		( new Post_Editor() )->register();
		( new Query_Guard() )->register();
		( new Rest_Guard() )->register();
		( new Visibility() )->register();
		( new Widget_Visibility() )->register();
		( new Menu_Visibility() )->register();
	}
}
