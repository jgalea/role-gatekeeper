<?php
namespace Rolewright\Modules\Site_Access;

use Rolewright\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Site_Access_Module extends Module {
	public function id(): string {
		return 'site-access';
	}

	public function title(): string {
		return __( 'Site access', 'rolewright' );
	}

	public function description(): string {
		return __( 'Private-site mode, wp-admin access by role and toolbar hiding. Off until you switch it on.', 'rolewright' );
	}

	public function default_enabled(): bool {
		return false;
	}

	public function init(): void {
		if ( defined( 'ROLEWRIGHT_DISABLE_SITE_ACCESS' ) && ROLEWRIGHT_DISABLE_SITE_ACCESS ) {
			return;
		}
		( new Gate() )->register();
		( new Admin_Gate() )->register();
		if ( is_admin() ) {
			( new Site_Access_Page() )->register();
		}
	}
}
