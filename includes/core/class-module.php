<?php
namespace Rolegate\Core;

defined( 'ABSPATH' ) || exit;

abstract class Module {
	/** Unique lowercase id, used as the settings key and the menu slug suffix. */
	abstract public function id(): string;

	abstract public function title(): string;

	abstract public function description(): string;

	/** Whether the module runs when the admin has not set it either way. */
	public function default_enabled(): bool {
		return true;
	}

	/** Called on plugins_loaded when the module is enabled. Add hooks here. */
	abstract public function init(): void;
}
