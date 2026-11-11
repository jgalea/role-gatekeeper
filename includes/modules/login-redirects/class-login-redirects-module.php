<?php
namespace Rolegate\Modules\Login_Redirects;

use Rolegate\Core\Module;

defined( 'ABSPATH' ) || exit;

final class Login_Redirects_Module extends Module {
	public function id(): string {
		return 'login-redirects';
	}

	public function title(): string {
		return __( 'Login redirects', 'role-gatekeeper' );
	}

	public function description(): string {
		return __( 'Send each role to its own page after registration, after its first login, after login and after logout.', 'role-gatekeeper' );
	}

	public function default_enabled(): bool {
		return true;
	}

	public function init(): void {
		add_filter( 'login_redirect', array( Resolver::class, 'filter_login' ), 20, 3 );
		add_filter( 'logout_redirect', array( Resolver::class, 'filter_logout' ), 20, 3 );
		add_filter( 'registration_redirect', array( Resolver::class, 'filter_registration' ), 20, 2 );
		add_action( 'user_register', array( Resolver::class, 'mark_first_login' ) );
		if ( is_admin() ) {
			( new Login_Redirects_Page() )->register();
		}
	}
}
