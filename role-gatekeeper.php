<?php
/**
 * Plugin Name: Role Gatekeeper: Access Control, Roles and Capabilities
 * Description: Roles, capabilities, content access and admin restrictions in one free plugin.
 * Version: 1.0.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Jean Galea
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: role-gatekeeper
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ROLEGATE_VERSION', '1.0.0' );
define( 'ROLEGATE_FILE', __FILE__ );
define( 'ROLEGATE_DIR', plugin_dir_path( __FILE__ ) );
define( 'ROLEGATE_URL', plugin_dir_url( __FILE__ ) );

spl_autoload_register(
	function ( $class ) {
		if ( 0 !== strpos( $class, 'Rolegate\\' ) ) {
			return;
		}
		$rel  = strtolower( str_replace( array( 'Rolegate\\', '\\', '_' ), array( '', '/', '-' ), $class ) );
		$base = ROLEGATE_DIR . 'includes/';
		$dir  = dirname( $rel );
		$file = 'class-' . basename( $rel ) . '.php';
		$path = $base . ( '.' === $dir ? '' : $dir . '/' ) . $file;
		$real = realpath( $path );
		if ( $real && 0 === strpos( $real, realpath( $base ) ) ) {
			require_once $real;
		}
	}
);

register_activation_hook( __FILE__, array( 'Rolegate\\Core\\Plugin', 'activate' ) );
add_action( 'plugins_loaded', array( 'Rolegate\\Core\\Plugin', 'boot' ) );
