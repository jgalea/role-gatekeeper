<?php
namespace Rolewright\Modules\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Turns plugin events into audit rows: ids, slugs, a diff of capability names, a timestamp
 * and a salted hash of the IP. Never stores values from the event beyond that.
 */
final class Recorder {
	const CAP_DIFF_TYPES = array( 'role.created', 'role.deleted', 'caps.updated', 'user.caps' );

	/**
	 * @param mixed $type
	 * @param mixed $data
	 */
	public function on_changed( $type, $data = array() ): void {
		$type = $this->clean_type( $type );
		if ( '' === $type || ! is_array( $data ) ) {
			return;
		}
		$before = $data['before'] ?? array();
		$after  = $data['after'] ?? array();
		$diff   = array();
		$detail = array();

		if ( in_array( $type, self::CAP_DIFF_TYPES, true ) ) {
			$caps = Diff::caps( Diff::caps_map( $before ), Diff::caps_map( $after ) );
			if ( ! Diff::is_empty( $caps ) ) {
				$diff['caps'] = $caps;
			}
		} elseif ( 'user.roles' === $type ) {
			$roles = Diff::roles( Diff::role_list( $before ), Diff::role_list( $after ) );
			if ( ! Diff::is_empty( $roles ) ) {
				$diff['roles'] = $roles;
			}
		}

		if ( in_array( $type, array( 'modules.updated', 'automation.updated' ), true ) ) {
			$b = is_array( $before ) ? $before : array();
			$a = is_array( $after ) ? $after : array();
			foreach ( array_unique( array_merge( array_keys( $b ), array_keys( $a ) ) ) as $key ) {
				$was = ! empty( $b[ $key ] );
				$now = ! empty( $a[ $key ] );
				if ( $was !== $now ) {
					$diff['settings'][ $now ? 'enabled' : 'disabled' ][] = $this->clean_target( $key );
				}
			}
			$detail['before'] = array_values( array_map( array( $this, 'clean_target' ), array_keys( array_filter( $b ) ) ) );
			$detail['after']  = array_values( array_map( array( $this, 'clean_target' ), array_keys( array_filter( $a ) ) ) );
		}

		if ( 'roles.reset' === $type ) {
			$b = is_array( $before ) && isset( $before['roles'] ) && is_array( $before['roles'] ) ? $before['roles'] : array();
			$a = is_array( $after ) && isset( $after['roles'] ) && is_array( $after['roles'] ) ? $after['roles'] : array();
			foreach ( array_unique( array_merge( array_keys( $b ), array_keys( $a ) ) ) as $slug ) {
				$caps = Diff::caps( Diff::caps_map( $b[ $slug ] ?? array() ), Diff::caps_map( $a[ $slug ] ?? array() ) );
				if ( ! Diff::is_empty( $caps ) ) {
					$diff['role_caps'][ $this->clean_target( $slug ) ] = $caps;
				}
				if ( isset( $b[ $slug ]['name'] ) && ! isset( $a[ $slug ] ) ) {
					$detail['labels'][ $this->clean_target( $slug ) ] = $this->label( $b[ $slug ]['name'] );
				}
			}
		} elseif ( 'role.default_set' === $type ) {
			foreach ( array(
				'before' => $before,
				'after'  => $after,
			) as $side => $state ) {
				$state                        = is_array( $state ) ? $state : array();
				$detail[ 'default_' . $side ] = $this->clean_target( $state['default'] ?? '' );
				$detail[ 'extras_' . $side ]  = array_values( array_map( array( $this, 'clean_target' ), (array) ( $state['extras'] ?? array() ) ) );
			}
		}

		if ( 'role.created' === $type && is_array( $after ) && isset( $after['name'] ) ) {
			$detail['label'] = $this->label( $after['name'] );
		} elseif ( 'role.deleted' === $type && is_array( $before ) && isset( $before['name'] ) ) {
			$detail['label'] = $this->label( $before['name'] );
		} elseif ( 'role.renamed' === $type ) {
			$detail['old_label'] = $this->label( is_array( $before ) ? ( $before['name'] ?? '' ) : $before );
			$detail['new_label'] = $this->label( is_array( $after ) ? ( $after['name'] ?? '' ) : $after );
		}

		$revert_of = isset( $data['revert_of'] ) ? absint( $data['revert_of'] ) : 0;
		$id        = Store::insert(
			array(
				'type'        => $type,
				'actor_id'    => isset( $data['actor'] ) ? absint( $data['actor'] ) : 0,
				'target'      => $this->clean_target( $data['target'] ?? '' ),
				'diff'        => $diff,
				'detail'      => $detail,
				'ip_hash'     => $this->ip_hash(),
				'reverted_of' => $revert_of,
			)
		);
		if ( $id && $revert_of ) {
			Store::mark_reverted( $revert_of, $id );
		}
	}

	/**
	 * @param mixed $kind
	 * @param mixed $actor_id
	 * @param mixed $target
	 * @param mixed $detail
	 */
	public function on_blocked( $kind, $actor_id = 0, $target = '', $detail = array() ): void {
		$caps = array();
		foreach ( (array) $detail as $cap ) {
			if ( is_string( $cap ) && '' !== $cap ) {
				$caps[] = $this->clean_target( $cap );
			}
		}
		Store::insert(
			array(
				'type'        => 'escalation.blocked',
				'actor_id'    => absint( $actor_id ),
				'target'      => $this->clean_target( $target ),
				'diff'        => $caps ? array( 'caps' => array( 'added' => array_values( array_unique( $caps ) ) ) ) : array(),
				'detail'      => array( 'kind' => $this->clean_target( $kind ) ),
				'ip_hash'     => $this->ip_hash(),
				'reverted_of' => 0,
			)
		);
	}

	/** @param mixed $uid */
	public function on_rescue( $uid = 0 ): void {
		Store::insert(
			array(
				'type'        => 'rescue.used',
				'actor_id'    => absint( $uid ),
				'target'      => (string) absint( $uid ),
				'diff'        => array(),
				'detail'      => array(),
				'ip_hash'     => $this->ip_hash(),
				'reverted_of' => 0,
			)
		);
	}

	/** @param mixed $type */
	private function clean_type( $type ): string {
		$type = is_string( $type ) ? strtolower( $type ) : '';
		return preg_match( '/^[a-z0-9_.]{1,40}$/', $type ) ? $type : '';
	}

	/** @param mixed $target */
	private function clean_target( $target ): string {
		if ( ! is_scalar( $target ) ) {
			return '';
		}
		return substr( preg_replace( '/[^A-Za-z0-9_:.,\-]/', '', (string) $target ), 0, 191 );
	}

	/** @param mixed $label */
	private function label( $label ): string {
		return is_string( $label ) ? substr( sanitize_text_field( $label ), 0, 191 ) : '';
	}

	private function ip_hash(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- hashed immediately.
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$ip = (string) apply_filters( 'rolewright_rescue_client_ip', $ip );
		return '' === $ip ? '' : hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
	}
}
