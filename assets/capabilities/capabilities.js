( function () {
	'use strict';
	var form = document.getElementById( 'rw-caps-form' );
	if ( ! form ) {
		return;
	}
	var strings = window.rolewrightCaps || {};
	var search = document.getElementById( 'rw-search' );
	var showDep = document.getElementById( 'rw-show-deprecated' );
	var boxes = form.querySelectorAll( 'input[name="caps[]"]' );
	var initial = {};
	Array.prototype.forEach.call( boxes, function ( b ) {
		initial[ b.value ] = b.checked;
	} );

	function syncAll() {
		Array.prototype.forEach.call( form.querySelectorAll( '.rw-group' ), function ( g ) {
			var all = g.querySelector( '.rw-all' );
			var items = g.querySelectorAll( 'input[name="caps[]"]' );
			var on = g.querySelectorAll( 'input[name="caps[]"]:checked' );
			all.checked = items.length > 0 && items.length === on.length;
		} );
	}

	function filter() {
		var q = search.value.trim().toLowerCase();
		Array.prototype.forEach.call( form.querySelectorAll( '.rw-group' ), function ( g ) {
			var shown = 0;
			Array.prototype.forEach.call( g.querySelectorAll( '.rw-cap' ), function ( l ) {
				var match = '' === q || l.getAttribute( 'data-search' ).indexOf( q ) !== -1;
				l.hidden = ! match;
				if ( match ) {
					shown++;
				}
			} );
			var dep = g.classList.contains( 'rw-deprecated' );
			g.hidden = 0 === shown || ( dep && ! showDep.checked );
		} );
	}

	form.addEventListener( 'change', function ( e ) {
		if ( e.target.classList.contains( 'rw-all' ) ) {
			Array.prototype.forEach.call( e.target.closest( '.rw-group' ).querySelectorAll( '.rw-cap:not([hidden]) input' ), function ( b ) {
				b.checked = e.target.checked;
			} );
		}
		syncAll();
	} );
	search.addEventListener( 'input', filter );
	showDep.addEventListener( 'change', filter );

	form.addEventListener( 'submit', function ( e ) {
		var submitter = e.submitter;
		if ( submitter && 'delete_cap' === submitter.name ) {
			if ( ! window.confirm( strings.confirmDel ) ) {
				e.preventDefault();
			}
			return;
		}
		if ( '1' !== form.getAttribute( 'data-own' ) || form.querySelector( 'input[name="confirm_self"]' ) ) {
			return;
		}
		var removing = Array.prototype.some.call( boxes, function ( b ) {
			return initial[ b.value ] && ! b.checked;
		} );
		if ( removing ) {
			if ( ! window.confirm( strings.confirmSelf ) ) {
				e.preventDefault();
				return;
			}
			var h = document.createElement( 'input' );
			h.type = 'hidden';
			h.name = 'confirm_self';
			h.value = '1';
			form.appendChild( h );
		}
	} );

	filter();
	syncAll();
}() );
