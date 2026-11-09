<?php
namespace Rolewright\Modules\Audit;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

class Audit_Module extends Module {
	const OPTION_SETTINGS = 'rolewright_audit_settings';

	public function id(): string {
		return 'audit';
	}

	public function title(): string {
		return __( 'Audit log and permissions viewer', 'rolewright' );
	}

	public function description(): string {
		return __( 'Records role, capability and user changes with a revert button, and shows who holds a capability right now.', 'rolewright' );
	}

	public function init(): void {
		add_action( 'rolewright_activate', array( Store::class, 'install' ) );
		add_action( 'init', array( Store::class, 'maybe_upgrade' ), 2 );
		add_action( 'init', array( Store::class, 'schedule' ), 3 );
		add_action( Store::CRON_HOOK, array( Store::class, 'prune' ) );

		$recorder = new Recorder();
		add_action( 'rolewright_changed', array( $recorder, 'on_changed' ), 10, 2 );
		add_action( 'rolewright_escalation_blocked', array( $recorder, 'on_blocked' ), 10, 4 );
		add_action( 'rolewright_rescue_used', array( $recorder, 'on_rescue' ), 10, 1 );

		if ( is_admin() ) {
			( new Audit_Page() )->register();
		}
	}

	/** @return array{retention_days:int,delete_on_uninstall:bool} */
	public static function settings(): array {
		$saved = get_option( self::OPTION_SETTINGS, array() );
		$saved = is_array( $saved ) ? $saved : array();
		$days  = isset( $saved['retention_days'] ) ? (int) $saved['retention_days'] : 180;
		return array(
			'retention_days'      => max( 1, min( 3650, $days ) ),
			'delete_on_uninstall' => ! empty( $saved['delete_on_uninstall'] ),
		);
	}
}
