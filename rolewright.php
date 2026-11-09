<?php
/**
 * Plugin Name: Rolewright
 * Description: Roles, capabilities, content access and admin restrictions in one free plugin.
 * Version: 0.1.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Jean Galea
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: rolewright
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ROLEWRIGHT_VERSION', '0.1.0' );
define( 'ROLEWRIGHT_FILE', __FILE__ );
define( 'ROLEWRIGHT_DIR', plugin_dir_path( __FILE__ ) );
define( 'ROLEWRIGHT_URL', plugin_dir_url( __FILE__ ) );

spl_autoload_register(
	function ( $class ) {
		if ( 0 !== strpos( $class, 'Rolewright\\' ) ) {
			return;
		}
		$rel  = strtolower( str_replace( array( 'Rolewright\\', '\\', '_' ), array( '', '/', '-' ), $class ) );
		$base = ROLEWRIGHT_DIR . 'includes/';
		$dir  = dirname( $rel );
		$file = 'class-' . basename( $rel ) . '.php';
		$path = $base . ( '.' === $dir ? '' : $dir . '/' ) . $file;
		$real = realpath( $path );
		if ( $real && 0 === strpos( $real, realpath( $base ) ) ) {
			require_once $real;
		}
	}
);

register_activation_hook( __FILE__, array( 'Rolewright\\Core\\Plugin', 'activate' ) );
add_action( 'plugins_loaded', array( 'Rolewright\\Core\\Plugin', 'boot' ) );
