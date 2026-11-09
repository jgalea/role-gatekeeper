( function ( wp ) {
	var el = wp.element.createElement;
	var Fragment = wp.element.Fragment;
	var __ = wp.i18n.__;
	var c = wp.components;
	var cfg = window.rolegateAccess || { roles: [] };
	var META_ROLES = '_rolegate_roles';
	var META_MESSAGE = '_rolegate_message';

	function toggle( list, value, on ) {
		var next = ( list || [] ).filter( function ( v ) {
			return v !== value;
		} );
		if ( on ) {
			next.push( value );
		}
		return next;
	}

	function roleBoxes( selected, onChange ) {
		return cfg.roles.map( function ( role ) {
			return el( c.CheckboxControl, {
				key: role.value,
				label: role.label,
				checked: ( selected || [] ).indexOf( role.value ) !== -1,
				onChange: function ( on ) {
					onChange( toggle( selected, role.value, on ) );
				},
			} );
		} );
	}

	wp.hooks.addFilter( 'blocks.registerBlockType', 'rolegate/attributes', function ( settings ) {
		settings.attributes = Object.assign( {}, settings.attributes, {
			rolegateMode: { type: 'string' },
			rolegateRoles: { type: 'array', items: { type: 'string' } },
		} );
		return settings;
	} );

	var withControls = wp.compose.createHigherOrderComponent( function ( BlockEdit ) {
		return function ( props ) {
			var mode = props.attributes.rolegateMode || 'all';
			var roles = props.attributes.rolegateRoles || [];
			var panel = el(
				wp.blockEditor.InspectorControls,
				null,
				el(
					c.PanelBody,
					{ title: __( 'Visibility by role', 'role-gatekeeper' ), initialOpen: mode !== 'all' },
					el( c.SelectControl, {
						label: __( 'Show this block to', 'role-gatekeeper' ),
						value: mode,
						options: [
							{ value: 'all', label: __( 'Everyone', 'role-gatekeeper' ) },
							{ value: 'logged_in', label: __( 'Logged-in users', 'role-gatekeeper' ) },
							{ value: 'logged_out', label: __( 'Logged-out visitors', 'role-gatekeeper' ) },
							{ value: 'roles', label: __( 'Selected roles', 'role-gatekeeper' ) },
						],
						onChange: function ( value ) {
							props.setAttributes( { rolegateMode: 'all' === value ? undefined : value } );
						},
					} ),
					mode === 'roles'
						? roleBoxes( roles, function ( next ) {
								props.setAttributes( { rolegateRoles: next.length ? next : undefined } );
						  } )
						: null
				)
			);
			return el( Fragment, null, el( BlockEdit, props ), props.isSelected ? panel : null );
		};
	}, 'withRolegateControls' );
	wp.hooks.addFilter( 'editor.BlockEdit', 'rolegate/controls', withControls );

	var Panel = ( wp.editor && wp.editor.PluginDocumentSettingPanel ) || ( wp.editPost && wp.editPost.PluginDocumentSettingPanel );
	if ( ! Panel ) {
		return;
	}

	function AccessPanel() {
		var meta = wp.data.useSelect( function ( select ) {
			return select( 'core/editor' ).getEditedPostAttribute( 'meta' ) || {};
		}, [] );
		var editPost = wp.data.useDispatch( 'core/editor' ).editPost;
		var roles = meta[ META_ROLES ] || [];
		var message = meta[ META_MESSAGE ] || '';
		function set( key, value ) {
			var patch = {};
			patch[ key ] = value;
			editPost( { meta: patch } );
		}
		return el(
			Panel,
			{ name: 'rolegate-access', title: __( 'Access', 'role-gatekeeper' ) },
			el( 'p', null, __( 'Only these roles can view this content. Leave all unchecked for everyone.', 'role-gatekeeper' ) ),
			el(
				'div',
				{ style: { display: 'grid', gap: '12px', marginBottom: '16px' } },
				roleBoxes( roles, function ( next ) {
					set( META_ROLES, next );
				} )
			),
			el( c.TextareaControl, {
				label: __( 'Message for people without access', 'role-gatekeeper' ),
				value: message,
				onChange: function ( value ) {
					set( META_MESSAGE, value );
				},
			} )
		);
	}

	wp.plugins.registerPlugin( 'rolegate-access', { render: AccessPanel } );
} )( window.wp );
