<?php
namespace Rolewright\Modules\Capabilities;

use Rolewright\Core\Module;
use Rolewright\Core\Settings;
use Rolewright\Modules\Safety\Caps;

defined( 'ABSPATH' ) || exit;

final class Capabilities_Module extends Module {
	const SLUG  = 'rolewright-capabilities';
	const NONCE = 'rolewright_caps';

	/** @var Cap_Editor */
	private $editor;

	public function id(): string {
		return 'capabilities';
	}

	public function title(): string {
		return __( 'Capability editor', 'rolewright' );
	}

	public function description(): string {
		return __( 'Edit the capabilities of each role, add custom capabilities, and turn on extra capability sets.', 'rolewright' );
	}

	public function init(): void {
		( new Cap_Sets() )->register();
		if ( is_admin() ) {
			$this->editor = new Cap_Editor();
			add_action( 'admin_menu', array( $this, 'menu' ) );
			add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		}
	}

	public function menu(): void {
		$hook = add_submenu_page(
			Settings::MENU_SLUG,
			__( 'Capabilities', 'rolewright' ),
			__( 'Capabilities', 'rolewright' ),
			Caps::MANAGE_CAPS,
			self::SLUG,
			array( $this->editor, 'render' )
		);
		if ( $hook ) {
			add_action( 'load-' . $hook, array( $this->editor, 'handle_post' ) );
		}
	}

	/** @param string $hook_suffix */
	public function assets( $hook_suffix ): void {
		if ( false === strpos( (string) $hook_suffix, self::SLUG ) ) {
			return;
		}
		wp_enqueue_style( 'rolewright-capabilities', ROLEWRIGHT_URL . 'assets/capabilities/capabilities.css', array(), ROLEWRIGHT_VERSION );
		wp_enqueue_script( 'rolewright-capabilities', ROLEWRIGHT_URL . 'assets/capabilities/capabilities.js', array(), ROLEWRIGHT_VERSION, true );
		wp_localize_script(
			'rolewright-capabilities',
			'rolewrightCaps',
			array(
				'confirmSelf' => __( 'You are removing capabilities from a role you hold yourself. Continue?', 'rolewright' ),
				'confirmDel'  => __( 'Delete this custom capability from every role?', 'rolewright' ),
			)
		);
	}

	public static function page_url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'admin.php' ) );
	}
}
