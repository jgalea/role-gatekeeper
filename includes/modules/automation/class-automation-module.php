<?php
namespace Rolewright\Modules\Automation;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

class Automation_Module extends Module {
	const OPTION_SETTINGS = 'rolewright_automation';

	public function id(): string {
		return 'automation';
	}

	public function title(): string {
		return __( 'WP-CLI, REST and Abilities', 'rolewright' );
	}

	public function description(): string {
		return __( 'Manage roles from the command line, a REST API and the WordPress Abilities API. Read-only unless you switch writes on.', 'rolewright' );
	}

	public function default_enabled(): bool {
		return false;
	}

	public function init(): void {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'rolewright role', Cli_Role::class );
			\WP_CLI::add_command( 'rolewright cap', Cli_Cap::class );
			\WP_CLI::add_command( 'rolewright user', Cli_User::class );
			\WP_CLI::add_command( 'rolewright export', array( Cli_Transfer::class, 'export' ) );
			\WP_CLI::add_command( 'rolewright import', array( Cli_Transfer::class, 'import' ) );
		}
		add_action( 'rest_api_init', array( new Rest_Routes(), 'register' ) );
		$abilities = new Abilities();
		add_action( 'wp_abilities_api_categories_init', array( $abilities, 'register_category' ) );
		add_action( 'wp_abilities_api_init', array( $abilities, 'register' ) );
		if ( is_admin() ) {
			( new Automation_Page() )->register();
		}
	}

	/** @return array{rest_writes:bool,abilities_writes:bool} */
	public static function settings(): array {
		$saved = get_option( self::OPTION_SETTINGS, array() );
		$saved = is_array( $saved ) ? $saved : array();
		return array(
			'rest_writes'      => ! empty( $saved['rest_writes'] ),
			'abilities_writes' => ! empty( $saved['abilities_writes'] ),
		);
	}
}
