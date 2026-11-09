<?php
namespace Rolegate\Modules\Automation;

defined( 'ABSPATH' ) || exit;

abstract class Cli_Base {
	/**
	 * The acting user: whoever --user named, or 0 (shell access, no user). A named user needs
	 * every capability in $caps.
	 *
	 * @param string[] $caps
	 */
	protected static function actor( array $caps ): int {
		$actor = get_current_user_id();
		if ( $actor > 0 ) {
			foreach ( $caps as $cap ) {
				if ( ! user_can( $actor, $cap ) ) {
					\WP_CLI::error( sprintf( 'User %d lacks the %s capability.', $actor, $cap ) );
				}
			}
		}
		return $actor;
	}

	/** @param mixed $result */
	protected static function check( $result ) {
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		return $result;
	}

	/** @return string[] */
	protected static function csv( $value ): array {
		return array_values( array_filter( array_map( 'trim', explode( ',', (string) $value ) ), 'strlen' ) );
	}

	protected static function user_id( string $ident ): int {
		$user = is_numeric( $ident ) ? get_userdata( (int) $ident ) : ( false !== strpos( $ident, '@' ) ? get_user_by( 'email', $ident ) : get_user_by( 'login', $ident ) );
		if ( ! $user ) {
			\WP_CLI::error( 'No such user: ' . $ident );
		}
		return (int) $user->ID;
	}
}
