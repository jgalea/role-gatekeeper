<?php
namespace Rolewright\Core;

defined( 'ABSPATH' ) || exit;

final class Plugin {
	const OPTION_MODULES = 'rolewright_modules';

	/** @var Module[] */
	private static $modules = array();

	public static function boot(): void {
		load_plugin_textdomain( 'rolewright', false, dirname( plugin_basename( ROLEWRIGHT_FILE ) ) . '/languages' );
		$enabled = self::enabled_map();

		foreach ( self::discover() as $module ) {
			self::$modules[ $module->id() ] = $module;
			$on = array_key_exists( $module->id(), $enabled ) ? (bool) $enabled[ $module->id() ] : $module->default_enabled();
			if ( 'safety' === $module->id() || $on ) {
				$module->init();
			}
		}

		if ( is_admin() ) {
			( new Settings() )->init();
		}
	}

	public static function activate(): void {
		\Rolewright\Modules\Safety\Caps::grant_to_administrator();
		do_action( 'rolewright_activate' );
	}

	/** @return Module[] */
	public static function modules(): array {
		return self::$modules;
	}

	/** @return array<string,bool> */
	public static function enabled_map(): array {
		$map = get_option( self::OPTION_MODULES, array() );
		return is_array( $map ) ? $map : array();
	}

	public static function is_enabled( string $id ): bool {
		$map = self::enabled_map();
		if ( array_key_exists( $id, $map ) ) {
			return (bool) $map[ $id ];
		}
		return isset( self::$modules[ $id ] ) ? self::$modules[ $id ]->default_enabled() : false;
	}

	/**
	 * A module lives in includes/modules/<name>/class-<name>-module.php and defines
	 * Rolewright\Modules\<Name>\<Name>_Module (hyphens in <name> become underscores, words capitalised).
	 */
	private static function discover(): array {
		$found = array();
		foreach ( (array) glob( ROLEWRIGHT_DIR . 'includes/modules/*', GLOB_ONLYDIR ) as $dir ) {
			$name  = basename( $dir );
			$camel = str_replace( ' ', '_', ucwords( str_replace( '-', ' ', $name ) ) );
			$class = 'Rolewright\\Modules\\' . $camel . '\\' . $camel . '_Module';
			if ( file_exists( $dir . '/class-' . $name . '-module.php' ) && class_exists( $class ) ) {
				$found[] = new $class();
			}
		}
		usort(
			$found,
			function ( $a, $b ) {
				return strcmp( $a->id(), $b->id() );
			}
		);
		return $found;
	}
}
