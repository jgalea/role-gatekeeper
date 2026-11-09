( function () {
	document.addEventListener( 'change', function ( e ) {
		var el = e.target;
		if ( ! el.classList || ! el.classList.contains( 'rw-parent' ) ) {
			return;
		}
		document.querySelectorAll( '.rw-child[data-group="' + el.dataset.group.replace( /"/g, '\\"' ) + '"]' ).forEach( function ( c ) {
			c.checked = el.checked;
		} );
	} );
} )();
