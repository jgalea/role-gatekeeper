<?php
namespace Rolegate\Modules\Portability;

defined( 'ABSPATH' ) || exit;

/**
 * Plans a migration from Disable User Login: every account it flagged with _is_disabled is
 * flagged here too. Its flag and settings are never touched, so either plugin can go.
 */
final class Disable_User_Login_Migration {
	const PLUGIN = 'disable-user-login/disable-user-login.php';
	const META   = '_is_disabled';

	public static function plan( int $actor, array $opts = array() ): array {
		return Disable_Users_Migration::build( $actor, 'disable-user-login', 'Disable User Login', self::PLUGIN, self::META );
	}
}
