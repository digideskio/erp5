<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts90205368.23</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery-ui.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>436715</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*! jQuery UI - v1.10.4 - 2014-01-19\n
* http://jqueryui.com\n
* Includes: jquery.ui.core.js, jquery.ui.widget.js, jquery.ui.mouse.js, jquery.ui.position.js, jquery.ui.draggable.js, jquery.ui.droppable.js, jquery.ui.resizable.js, jquery.ui.selectable.js, jquery.ui.sortable.js, jquery.ui.accordion.js, jquery.ui.autocomplete.js, jquery.ui.button.js, jquery.ui.datepicker.js, jquery.ui.dialog.js, jquery.ui.menu.js, jquery.ui.progressbar.js, jquery.ui.slider.js, jquery.ui.spinner.js, jquery.ui.tabs.js, jquery.ui.tooltip.js, jquery.ui.effect.js, jquery.ui.effect-blind.js, jquery.ui.effect-bounce.js, jquery.ui.effect-clip.js, jquery.ui.effect-drop.js, jquery.ui.effect-explode.js, jquery.ui.effect-fade.js, jquery.ui.effect-fold.js, jquery.ui.effect-highlight.js, jquery.ui.effect-pulsate.js, jquery.ui.effect-scale.js, jquery.ui.effect-shake.js, jquery.ui.effect-slide.js, jquery.ui.effect-transfer.js\n
* Copyright 2014 jQuery Foundation and other contributors; Licensed MIT */\n
\n
(function( $, undefined ) {\n
\n
var uuid = 0,\n
\truniqueId = /^ui-id-\\d+$/;\n
\n
// $.ui might exist from components with no dependencies, e.g., $.ui.position\n
$.ui = $.ui || {};\n
\n
$.extend( $.ui, {\n
\tversion: "1.10.4",\n
\n
\tkeyCode: {\n
\t\tBACKSPACE: 8,\n
\t\tCOMMA: 188,\n
\t\tDELETE: 46,\n
\t\tDOWN: 40,\n
\t\tEND: 35,\n
\t\tENTER: 13,\n
\t\tESCAPE: 27,\n
\t\tHOME: 36,\n
\t\tLEFT: 37,\n
\t\tNUMPAD_ADD: 107,\n
\t\tNUMPAD_DECIMAL: 110,\n
\t\tNUMPAD_DIVIDE: 111,\n
\t\tNUMPAD_ENTER: 108,\n
\t\tNUMPAD_MULTIPLY: 106,\n
\t\tNUMPAD_SUBTRACT: 109,\n
\t\tPAGE_DOWN: 34,\n
\t\tPAGE_UP: 33,\n
\t\tPERIOD: 190,\n
\t\tRIGHT: 39,\n
\t\tSPACE: 32,\n
\t\tTAB: 9,\n
\t\tUP: 38\n
\t}\n
});\n
\n
// plugins\n
$.fn.extend({\n
\tfocus: (function( orig ) {\n
\t\treturn function( delay, fn ) {\n
\t\t\treturn typeof delay === "number" ?\n
\t\t\t\tthis.each(function() {\n
\t\t\t\t\tvar elem = this;\n
\t\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t\t$( elem ).focus();\n
\t\t\t\t\t\tif ( fn ) {\n
\t\t\t\t\t\t\tfn.call( elem );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}, delay );\n
\t\t\t\t}) :\n
\t\t\t\torig.apply( this, arguments );\n
\t\t};\n
\t})( $.fn.focus ),\n
\n
\tscrollParent: function() {\n
\t\tvar scrollParent;\n
\t\tif (($.ui.ie && (/(static|relative)/).test(this.css("position"))) || (/absolute/).test(this.css("position"))) {\n
\t\t\tscrollParent = this.parents().filter(function() {\n
\t\t\t\treturn (/(relative|absolute|fixed)/).test($.css(this,"position")) && (/(auto|scroll)/).test($.css(this,"overflow")+$.css(this,"overflow-y")+$.css(this,"overflow-x"));\n
\t\t\t}).eq(0);\n
\t\t} else {\n
\t\t\tscrollParent = this.parents().filter(function() {\n
\t\t\t\treturn (/(auto|scroll)/).test($.css(this,"overflow")+$.css(this,"overflow-y")+$.css(this,"overflow-x"));\n
\t\t\t}).eq(0);\n
\t\t}\n
\n
\t\treturn (/fixed/).test(this.css("position")) || !scrollParent.length ? $(document) : scrollParent;\n
\t},\n
\n
\tzIndex: function( zIndex ) {\n
\t\tif ( zIndex !== undefined ) {\n
\t\t\treturn this.css( "zIndex", zIndex );\n
\t\t}\n
\n
\t\tif ( this.length ) {\n
\t\t\tvar elem = $( this[ 0 ] ), position, value;\n
\t\t\twhile ( elem.length && elem[ 0 ] !== document ) {\n
\t\t\t\t// Ignore z-index if position is set to a value where z-index is ignored by the browser\n
\t\t\t\t// This makes behavior of this function consistent across browsers\n
\t\t\t\t// WebKit always returns auto if the element is positioned\n
\t\t\t\tposition = elem.css( "position" );\n
\t\t\t\tif ( position === "absolute" || position === "relative" || position === "fixed" ) {\n
\t\t\t\t\t// IE returns 0 when zIndex is not specified\n
\t\t\t\t\t// other browsers return a string\n
\t\t\t\t\t// we ignore the case of nested elements with an explicit value of 0\n
\t\t\t\t\t// <div style="z-index: -10;"><div style="z-index: 0;"></div></div>\n
\t\t\t\t\tvalue = parseInt( elem.css( "zIndex" ), 10 );\n
\t\t\t\t\tif ( !isNaN( value ) && value !== 0 ) {\n
\t\t\t\t\t\treturn value;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\telem = elem.parent();\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn 0;\n
\t},\n
\n
\tuniqueId: function() {\n
\t\treturn this.each(function() {\n
\t\t\tif ( !this.id ) {\n
\t\t\t\tthis.id = "ui-id-" + (++uuid);\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tremoveUniqueId: function() {\n
\t\treturn this.each(function() {\n
\t\t\tif ( runiqueId.test( this.id ) ) {\n
\t\t\t\t$( this ).removeAttr( "id" );\n
\t\t\t}\n
\t\t});\n
\t}\n
});\n
\n
// selectors\n
function focusable( element, isTabIndexNotNaN ) {\n
\tvar map, mapName, img,\n
\t\tnodeName = element.nodeName.toLowerCase();\n
\tif ( "area" === nodeName ) {\n
\t\tmap = element.parentNode;\n
\t\tmapName = map.name;\n
\t\tif ( !element.href || !mapName || map.nodeName.toLowerCase() !== "map" ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\timg = $( "img[usemap=#" + mapName + "]" )[0];\n
\t\treturn !!img && visible( img );\n
\t}\n
\treturn ( /input|select|textarea|button|object/.test( nodeName ) ?\n
\t\t!element.disabled :\n
\t\t"a" === nodeName ?\n
\t\t\telement.href || isTabIndexNotNaN :\n
\t\t\tisTabIndexNotNaN) &&\n
\t\t// the element and all of its ancestors must be visible\n
\t\tvisible( element );\n
}\n
\n
function visible( element ) {\n
\treturn $.expr.filters.visible( element ) &&\n
\t\t!$( element ).parents().addBack().filter(function() {\n
\t\t\treturn $.css( this, "visibility" ) === "hidden";\n
\t\t}).length;\n
}\n
\n
$.extend( $.expr[ ":" ], {\n
\tdata: $.expr.createPseudo ?\n
\t\t$.expr.createPseudo(function( dataName ) {\n
\t\t\treturn function( elem ) {\n
\t\t\t\treturn !!$.data( elem, dataName );\n
\t\t\t};\n
\t\t}) :\n
\t\t// support: jQuery <1.8\n
\t\tfunction( elem, i, match ) {\n
\t\t\treturn !!$.data( elem, match[ 3 ] );\n
\t\t},\n
\n
\tfocusable: function( element ) {\n
\t\treturn focusable( element, !isNaN( $.attr( element, "tabindex" ) ) );\n
\t},\n
\n
\ttabbable: function( element ) {\n
\t\tvar tabIndex = $.attr( element, "tabindex" ),\n
\t\t\tisTabIndexNaN = isNaN( tabIndex );\n
\t\treturn ( isTabIndexNaN || tabIndex >= 0 ) && focusable( element, !isTabIndexNaN );\n
\t}\n
});\n
\n
// support: jQuery <1.8\n
if ( !$( "<a>" ).outerWidth( 1 ).jquery ) {\n
\t$.each( [ "Width", "Height" ], function( i, name ) {\n
\t\tvar side = name === "Width" ? [ "Left", "Right" ] : [ "Top", "Bottom" ],\n
\t\t\ttype = name.toLowerCase(),\n
\t\t\torig = {\n
\t\t\t\tinnerWidth: $.fn.innerWidth,\n
\t\t\t\tinnerHeight: $.fn.innerHeight,\n
\t\t\t\touterWidth: $.fn.outerWidth,\n
\t\t\t\touterHeight: $.fn.outerHeight\n
\t\t\t};\n
\n
\t\tfunction reduce( elem, size, border, margin ) {\n
\t\t\t$.each( side, function() {\n
\t\t\t\tsize -= parseFloat( $.css( elem, "padding" + this ) ) || 0;\n
\t\t\t\tif ( border ) {\n
\t\t\t\t\tsize -= parseFloat( $.css( elem, "border" + this + "Width" ) ) || 0;\n
\t\t\t\t}\n
\t\t\t\tif ( margin ) {\n
\t\t\t\t\tsize -= parseFloat( $.css( elem, "margin" + this ) ) || 0;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\treturn size;\n
\t\t}\n
\n
\t\t$.fn[ "inner" + name ] = function( size ) {\n
\t\t\tif ( size === undefined ) {\n
\t\t\t\treturn orig[ "inner" + name ].call( this );\n
\t\t\t}\n
\n
\t\t\treturn this.each(function() {\n
\t\t\t\t$( this ).css( type, reduce( this, size ) + "px" );\n
\t\t\t});\n
\t\t};\n
\n
\t\t$.fn[ "outer" + name] = function( size, margin ) {\n
\t\t\tif ( typeof size !== "number" ) {\n
\t\t\t\treturn orig[ "outer" + name ].call( this, size );\n
\t\t\t}\n
\n
\t\t\treturn this.each(function() {\n
\t\t\t\t$( this).css( type, reduce( this, size, true, margin ) + "px" );\n
\t\t\t});\n
\t\t};\n
\t});\n
}\n
\n
// support: jQuery <1.8\n
if ( !$.fn.addBack ) {\n
\t$.fn.addBack = function( selector ) {\n
\t\treturn this.add( selector == null ?\n
\t\t\tthis.prevObject : this.prevObject.filter( selector )\n
\t\t);\n
\t};\n
}\n
\n
// support: jQuery 1.6.1, 1.6.2 (http://bugs.jquery.com/ticket/9413)\n
if ( $( "<a>" ).data( "a-b", "a" ).removeData( "a-b" ).data( "a-b" ) ) {\n
\t$.fn.removeData = (function( removeData ) {\n
\t\treturn function( key ) {\n
\t\t\tif ( arguments.length ) {\n
\t\t\t\treturn removeData.call( this, $.camelCase( key ) );\n
\t\t\t} else {\n
\t\t\t\treturn removeData.call( this );\n
\t\t\t}\n
\t\t};\n
\t})( $.fn.removeData );\n
}\n
\n
\n
\n
\n
\n
// deprecated\n
$.ui.ie = !!/msie [\\w.]+/.exec( navigator.userAgent.toLowerCase() );\n
\n
$.support.selectstart = "onselectstart" in document.createElement( "div" );\n
$.fn.extend({\n
\tdisableSelection: function() {\n
\t\treturn this.bind( ( $.support.selectstart ? "selectstart" : "mousedown" ) +\n
\t\t\t".ui-disableSelection", function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t});\n
\t},\n
\n
\tenableSelection: function() {\n
\t\treturn this.unbind( ".ui-disableSelection" );\n
\t}\n
});\n
\n
$.extend( $.ui, {\n
\t// $.ui.plugin is deprecated. Use $.widget() extensions instead.\n
\tplugin: {\n
\t\tadd: function( module, option, set ) {\n
\t\t\tvar i,\n
\t\t\t\tproto = $.ui[ module ].prototype;\n
\t\t\tfor ( i in set ) {\n
\t\t\t\tproto.plugins[ i ] = proto.plugins[ i ] || [];\n
\t\t\t\tproto.plugins[ i ].push( [ option, set[ i ] ] );\n
\t\t\t}\n
\t\t},\n
\t\tcall: function( instance, name, args ) {\n
\t\t\tvar i,\n
\t\t\t\tset = instance.plugins[ name ];\n
\t\t\tif ( !set || !instance.element[ 0 ].parentNode || instance.element[ 0 ].parentNode.nodeType === 11 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tfor ( i = 0; i < set.length; i++ ) {\n
\t\t\t\tif ( instance.options[ set[ i ][ 0 ] ] ) {\n
\t\t\t\t\tset[ i ][ 1 ].apply( instance.element, args );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// only used by resizable\n
\thasScroll: function( el, a ) {\n
\n
\t\t//If overflow is hidden, the element might have extra content, but the user wants to hide it\n
\t\tif ( $( el ).css( "overflow" ) === "hidden") {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tvar scroll = ( a && a === "left" ) ? "scrollLeft" : "scrollTop",\n
\t\t\thas = false;\n
\n
\t\tif ( el[ scroll ] > 0 ) {\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\t// TODO: determine which cases actually cause this to happen\n
\t\t// if the element doesn\'t have the scroll set, see if it\'s possible to\n
\t\t// set the scroll\n
\t\tel[ scroll ] = 1;\n
\t\thas = ( el[ scroll ] > 0 );\n
\t\tel[ scroll ] = 0;\n
\t\treturn has;\n
\t}\n
});\n
\n
})( jQuery );\n
(function( $, undefined ) {\n
\n
var uuid = 0,\n
\tslice = Array.prototype.slice,\n
\t_cleanData = $.cleanData;\n
$.cleanData = function( elems ) {\n
\tfor ( var i = 0, elem; (elem = elems[i]) != null; i++ ) {\n
\t\ttry {\n
\t\t\t$( elem ).triggerHandler( "remove" );\n
\t\t// http://bugs.jquery.com/ticket/8235\n
\t\t} catch( e ) {}\n
\t}\n
\t_cleanData( elems );\n
};\n
\n
$.widget = function( name, base, prototype ) {\n
\tvar fullName, existingConstructor, constructor, basePrototype,\n
\t\t// proxiedPrototype allows the provided prototype to remain unmodified\n
\t\t// so that it can be used as a mixin for multiple widgets (#8876)\n
\t\tproxiedPrototype = {},\n
\t\tnamespace = name.split( "." )[ 0 ];\n
\n
\tname = name.split( "." )[ 1 ];\n
\tfullName = namespace + "-" + name;\n
\n
\tif ( !prototype ) {\n
\t\tprototype = base;\n
\t\tbase = $.Widget;\n
\t}\n
\n
\t// create selector for plugin\n
\t$.expr[ ":" ][ fullName.toLowerCase() ] = function( elem ) {\n
\t\treturn !!$.data( elem, fullName );\n
\t};\n
\n
\t$[ namespace ] = $[ namespace ] || {};\n
\texistingConstructor = $[ namespace ][ name ];\n
\tconstructor = $[ namespace ][ name ] = function( options, element ) {\n
\t\t// allow instantiation without "new" keyword\n
\t\tif ( !this._createWidget ) {\n
\t\t\treturn new constructor( options, element );\n
\t\t}\n
\n
\t\t// allow instantiation without initializing for simple inheritance\n
\t\t// must use "new" keyword (the code above always passes args)\n
\t\tif ( arguments.length ) {\n
\t\t\tthis._createWidget( options, element );\n
\t\t}\n
\t};\n
\t// extend with the existing constructor to carry over any static properties\n
\t$.extend( constructor, existingConstructor, {\n
\t\tversion: prototype.version,\n
\t\t// copy the object used to create the prototype in case we need to\n
\t\t// redefine the widget later\n
\t\t_proto: $.extend( {}, prototype ),\n
\t\t// track widgets that inherit from this widget in case this widget is\n
\t\t// redefined after a widget inherits from it\n
\t\t_childConstructors: []\n
\t});\n
\n
\tbasePrototype = new base();\n
\t// we need to make the options hash a property directly on the new instance\n
\t// otherwise we\'ll modify the options hash on the prototype that we\'re\n
\t// inheriting from\n
\tbasePrototype.options = $.widget.extend( {}, basePrototype.options );\n
\t$.each( prototype, function( prop, value ) {\n
\t\tif ( !$.isFunction( value ) ) {\n
\t\t\tproxiedPrototype[ prop ] = value;\n
\t\t\treturn;\n
\t\t}\n
\t\tproxiedPrototype[ prop ] = (function() {\n
\t\t\tvar _super = function() {\n
\t\t\t\t\treturn base.prototype[ prop ].apply( this, arguments );\n
\t\t\t\t},\n
\t\t\t\t_superApply = function( args ) {\n
\t\t\t\t\treturn base.prototype[ prop ].apply( this, args );\n
\t\t\t\t};\n
\t\t\treturn function() {\n
\t\t\t\tvar __super = this._super,\n
\t\t\t\t\t__superApply = this._superApply,\n
\t\t\t\t\treturnValue;\n
\n
\t\t\t\tthis._super = _super;\n
\t\t\t\tthis._superApply = _superApply;\n
\n
\t\t\t\treturnValue = value.apply( this, arguments );\n
\n
\t\t\t\tthis._super = __super;\n
\t\t\t\tthis._superApply = __superApply;\n
\n
\t\t\t\treturn returnValue;\n
\t\t\t};\n
\t\t})();\n
\t});\n
\tconstructor.prototype = $.widget.extend( basePrototype, {\n
\t\t// TODO: remove support for widgetEventPrefix\n
\t\t// always use the name + a colon as the prefix, e.g., draggable:start\n
\t\t// don\'t prefix for widgets that aren\'t DOM-based\n
\t\twidgetEventPrefix: existingConstructor ? (basePrototype.widgetEventPrefix || name) : name\n
\t}, proxiedPrototype, {\n
\t\tconstructor: constructor,\n
\t\tnamespace: namespace,\n
\t\twidgetName: name,\n
\t\twidgetFullName: fullName\n
\t});\n
\n
\t// If this widget is being redefined then we need to find all widgets that\n
\t// are inheriting from it and redefine all of them so that they inherit from\n
\t// the new version of this widget. We\'re essentially trying to replace one\n
\t// level in the prototype chain.\n
\tif ( existingConstructor ) {\n
\t\t$.each( existingConstructor._childConstructors, function( i, child ) {\n
\t\t\tvar childPrototype = child.prototype;\n
\n
\t\t\t// redefine the child widget using the same prototype that was\n
\t\t\t// originally used, but inherit from the new version of the base\n
\t\t\t$.widget( childPrototype.namespace + "." + childPrototype.widgetName, constructor, child._proto );\n
\t\t});\n
\t\t// remove the list of existing child constructors from the old constructor\n
\t\t// so the old child constructors can be garbage collected\n
\t\tdelete existingConstructor._childConstructors;\n
\t} else {\n
\t\tbase._childConstructors.push( constructor );\n
\t}\n
\n
\t$.widget.bridge( name, constructor );\n
};\n
\n
$.widget.extend = function( target ) {\n
\tvar input = slice.call( arguments, 1 ),\n
\t\tinputIndex = 0,\n
\t\tinputLength = input.length,\n
\t\tkey,\n
\t\tvalue;\n
\tfor ( ; inputIndex < inputLength; inputIndex++ ) {\n
\t\tfor ( key in input[ inputIndex ] ) {\n
\t\t\tvalue = input[ inputIndex ][ key ];\n
\t\t\tif ( input[ inputIndex ].hasOwnProperty( key ) && value !== undefined ) {\n
\t\t\t\t// Clone objects\n
\t\t\t\tif ( $.isPlainObject( value ) ) {\n
\t\t\t\t\ttarget[ key ] = $.isPlainObject( target[ key ] ) ?\n
\t\t\t\t\t\t$.widget.extend( {}, target[ key ], value ) :\n
\t\t\t\t\t\t// Don\'t extend strings, arrays, etc. with objects\n
\t\t\t\t\t\t$.widget.extend( {}, value );\n
\t\t\t\t// Copy everything else by reference\n
\t\t\t\t} else {\n
\t\t\t\t\ttarget[ key ] = value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\treturn target;\n
};\n
\n
$.widget.bridge = function( name, object ) {\n
\tvar fullName = object.prototype.widgetFullName || name;\n
\t$.fn[ name ] = function( options ) {\n
\t\tvar isMethodCall = typeof options === "string",\n
\t\t\targs = slice.call( arguments, 1 ),\n
\t\t\treturnValue = this;\n
\n
\t\t// allow multiple hashes to be passed on init\n
\t\toptions = !isMethodCall && args.length ?\n
\t\t\t$.widget.extend.apply( null, [ options ].concat(args) ) :\n
\t\t\toptions;\n
\n
\t\tif ( isMethodCall ) {\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar methodValue,\n
\t\t\t\t\tinstance = $.data( this, fullName );\n
\t\t\t\tif ( !instance ) {\n
\t\t\t\t\treturn $.error( "cannot call methods on " + name + " prior to initialization; " +\n
\t\t\t\t\t\t"attempted to call method \'" + options + "\'" );\n
\t\t\t\t}\n
\t\t\t\tif ( !$.isFunction( instance[options] ) || options.charAt( 0 ) === "_" ) {\n
\t\t\t\t\treturn $.error( "no such method \'" + options + "\' for " + name + " widget instance" );\n
\t\t\t\t}\n
\t\t\t\tmethodValue = instance[ options ].apply( instance, args );\n
\t\t\t\tif ( methodValue !== instance && methodValue !== undefined ) {\n
\t\t\t\t\treturnValue = methodValue && methodValue.jquery ?\n
\t\t\t\t\t\treturnValue.pushStack( methodValue.get() ) :\n
\t\t\t\t\t\tmethodValue;\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar instance = $.data( this, fullName );\n
\t\t\t\tif ( instance ) {\n
\t\t\t\t\tinstance.option( options || {} )._init();\n
\t\t\t\t} else {\n
\t\t\t\t\t$.data( this, fullName, new object( options, this ) );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn returnValue;\n
\t};\n
};\n
\n
$.Widget = function( /* options, element */ ) {};\n
$.Widget._childConstructors = [];\n
\n
$.Widget.prototype = {\n
\twidgetName: "widget",\n
\twidgetEventPrefix: "",\n
\tdefaultElement: "<div>",\n
\toptions: {\n
\t\tdisabled: false,\n
\n
\t\t// callbacks\n
\t\tcreate: null\n
\t},\n
\t_createWidget: function( options, element ) {\n
\t\telement = $( element || this.defaultElement || this )[ 0 ];\n
\t\tthis.element = $( element );\n
\t\tthis.uuid = uuid++;\n
\t\tthis.eventNamespace = "." + this.widgetName + this.uuid;\n
\t\tthis.options = $.widget.extend( {},\n
\t\t\tthis.options,\n
\t\t\tthis._getCreateOptions(),\n
\t\t\toptions );\n
\n
\t\tthis.bindings = $();\n
\t\tthis.hoverable = $();\n
\t\tthis.focusable = $();\n
\n
\t\tif ( element !== this ) {\n
\t\t\t$.data( element, this.widgetFullName, this );\n
\t\t\tthis._on( true, this.element, {\n
\t\t\t\tremove: function( event ) {\n
\t\t\t\t\tif ( event.target === element ) {\n
\t\t\t\t\t\tthis.destroy();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\tthis.document = $( element.style ?\n
\t\t\t\t// element within the document\n
\t\t\t\telement.ownerDocument :\n
\t\t\t\t// element is window or document\n
\t\t\t\telement.document || element );\n
\t\t\tthis.window = $( this.document[0].defaultView || this.document[0].parentWindow );\n
\t\t}\n
\n
\t\tthis._create();\n
\t\tthis._trigger( "create", null, this._getCreateEventData() );\n
\t\tthis._init();\n
\t},\n
\t_getCreateOptions: $.noop,\n
\t_getCreateEventData: $.noop,\n
\t_create: $.noop,\n
\t_init: $.noop,\n
\n
\tdestroy: function() {\n
\t\tthis._destroy();\n
\t\t// we can probably remove the unbind calls in 2.0\n
\t\t// all event bindings should go through this._on()\n
\t\tthis.element\n
\t\t\t.unbind( this.eventNamespace )\n
\t\t\t// 1.9 BC for #7810\n
\t\t\t// TODO remove dual storage\n
\t\t\t.removeData( this.widgetName )\n
\t\t\t.removeData( this.widgetFullName )\n
\t\t\t// support: jquery <1.6.3\n
\t\t\t// http://bugs.jquery.com/ticket/9413\n
\t\t\t.removeData( $.camelCase( this.widgetFullName ) );\n
\t\tthis.widget()\n
\t\t\t.unbind( this.eventNamespace )\n
\t\t\t.removeAttr( "aria-disabled" )\n
\t\t\t.removeClass(\n
\t\t\t\tthis.widgetFullName + "-disabled " +\n
\t\t\t\t"ui-state-disabled" );\n
\n
\t\t// clean up events and states\n
\t\tthis.bindings.unbind( this.eventNamespace );\n
\t\tthis.hoverable.removeClass( "ui-state-hover" );\n
\t\tthis.focusable.removeClass( "ui-state-focus" );\n
\t},\n
\t_destroy: $.noop,\n
\n
\twidget: function() {\n
\t\treturn this.element;\n
\t},\n
\n
\toption: function( key, value ) {\n
\t\tvar options = key,\n
\t\t\tparts,\n
\t\t\tcurOption,\n
\t\t\ti;\n
\n
\t\tif ( arguments.length === 0 ) {\n
\t\t\t// don\'t return a reference to the internal hash\n
\t\t\treturn $.widget.extend( {}, this.options );\n
\t\t}\n
\n
\t\tif ( typeof key === "string" ) {\n
\t\t\t// handle nested keys, e.g., "foo.bar" => { foo: { bar: ___ } }\n
\t\t\toptions = {};\n
\t\t\tparts = key.split( "." );\n
\t\t\tkey = parts.shift();\n
\t\t\tif ( parts.length ) {\n
\t\t\t\tcurOption = options[ key ] = $.widget.extend( {}, this.options[ key ] );\n
\t\t\t\tfor ( i = 0; i < parts.length - 1; i++ ) {\n
\t\t\t\t\tcurOption[ parts[ i ] ] = curOption[ parts[ i ] ] || {};\n
\t\t\t\t\tcurOption = curOption[ parts[ i ] ];\n
\t\t\t\t}\n
\t\t\t\tkey = parts.pop();\n
\t\t\t\tif ( arguments.length === 1 ) {\n
\t\t\t\t\treturn curOption[ key ] === undefined ? null : curOption[ key ];\n
\t\t\t\t}\n
\t\t\t\tcurOption[ key ] = value;\n
\t\t\t} else {\n
\t\t\t\tif ( arguments.length === 1 ) {\n
\t\t\t\t\treturn this.options[ key ] === undefined ? null : this.options[ key ];\n
\t\t\t\t}\n
\t\t\t\toptions[ key ] = value;\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis._setOptions( options );\n
\n
\t\treturn this;\n
\t},\n
\t_setOptions: function( options ) {\n
\t\tvar key;\n
\n
\t\tfor ( key in options ) {\n
\t\t\tthis._setOption( key, options[ key ] );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\t_setOption: function( key, value ) {\n
\t\tthis.options[ key ] = value;\n
\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.widget()\n
\t\t\t\t.toggleClass( this.widgetFullName + "-disabled ui-state-disabled", !!value )\n
\t\t\t\t.attr( "aria-disabled", value );\n
\t\t\tthis.hoverable.removeClass( "ui-state-hover" );\n
\t\t\tthis.focusable.removeClass( "ui-state-focus" );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tenable: function() {\n
\t\treturn this._setOption( "disabled", false );\n
\t},\n
\tdisable: function() {\n
\t\treturn this._setOption( "disabled", true );\n
\t},\n
\n
\t_on: function( suppressDisabledCheck, element, handlers ) {\n
\t\tvar delegateElement,\n
\t\t\tinstance = this;\n
\n
\t\t// no suppressDisabledCheck flag, shuffle arguments\n
\t\tif ( typeof suppressDisabledCheck !== "boolean" ) {\n
\t\t\thandlers = element;\n
\t\t\telement = suppressDisabledCheck;\n
\t\t\tsuppressDisabledCheck = false;\n
\t\t}\n
\n
\t\t// no element argument, shuffle and use this.element\n
\t\tif ( !handlers ) {\n
\t\t\thandlers = element;\n
\t\t\telement = this.element;\n
\t\t\tdelegateElement = this.widget();\n
\t\t} else {\n
\t\t\t// accept selectors, DOM elements\n
\t\t\telement = delegateElement = $( element );\n
\t\t\tthis.bindings = this.bindings.add( element );\n
\t\t}\n
\n
\t\t$.each( handlers, function( event, handler ) {\n
\t\t\tfunction handlerProxy() {\n
\t\t\t\t// allow widgets to customize the disabled handling\n
\t\t\t\t// - disabled as an array instead of boolean\n
\t\t\t\t// - disabled class as method for disabling individual parts\n
\t\t\t\tif ( !suppressDisabledCheck &&\n
\t\t\t\t\t\t( instance.options.disabled === true ||\n
\t\t\t\t\t\t\t$( this ).hasClass( "ui-state-disabled" ) ) ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\treturn ( typeof handler === "string" ? instance[ handler ] : handler )\n
\t\t\t\t\t.apply( instance, arguments );\n
\t\t\t}\n
\n
\t\t\t// copy the guid so direct unbinding works\n
\t\t\tif ( typeof handler !== "string" ) {\n
\t\t\t\thandlerProxy.guid = handler.guid =\n
\t\t\t\t\thandler.guid || handlerProxy.guid || $.guid++;\n
\t\t\t}\n
\n
\t\t\tvar match = event.match( /^(\\w+)\\s*(.*)$/ ),\n
\t\t\t\teventName = match[1] + instance.eventNamespace,\n
\t\t\t\tselector = match[2];\n
\t\t\tif ( selector ) {\n
\t\t\t\tdelegateElement.delegate( selector, eventName, handlerProxy );\n
\t\t\t} else {\n
\t\t\t\telement.bind( eventName, handlerProxy );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_off: function( element, eventName ) {\n
\t\teventName = (eventName || "").split( " " ).join( this.eventNamespace + " " ) + this.eventNamespace;\n
\t\telement.unbind( eventName ).undelegate( eventName );\n
\t},\n
\n
\t_delay: function( handler, delay ) {\n
\t\tfunction handlerProxy() {\n
\t\t\treturn ( typeof handler === "string" ? instance[ handler ] : handler )\n
\t\t\t\t.apply( instance, arguments );\n
\t\t}\n
\t\tvar instance = this;\n
\t\treturn setTimeout( handlerProxy, delay || 0 );\n
\t},\n
\n
\t_hoverable: function( element ) {\n
\t\tthis.hoverable = this.hoverable.add( element );\n
\t\tthis._on( element, {\n
\t\t\tmouseenter: function( event ) {\n
\t\t\t\t$( event.currentTarget ).addClass( "ui-state-hover" );\n
\t\t\t},\n
\t\t\tmouseleave: function( event ) {\n
\t\t\t\t$( event.currentTarget ).removeClass( "ui-state-hover" );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_focusable: function( element ) {\n
\t\tthis.focusable = this.focusable.add( element );\n
\t\tthis._on( element, {\n
\t\t\tfocusin: function( event ) {\n
\t\t\t\t$( event.currentTarget ).addClass( "ui-state-focus" );\n
\t\t\t},\n
\t\t\tfocusout: function( event ) {\n
\t\t\t\t$( event.currentTarget ).removeClass( "ui-state-focus" );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_trigger: function( type, event, data ) {\n
\t\tvar prop, orig,\n
\t\t\tcallback = this.options[ type ];\n
\n
\t\tdata = data || {};\n
\t\tevent = $.Event( event );\n
\t\tevent.type = ( type === this.widgetEventPrefix ?\n
\t\t\ttype :\n
\t\t\tthis.widgetEventPrefix + type ).toLowerCase();\n
\t\t// the original event may come from any element\n
\t\t// so we need to reset the target on the new event\n
\t\tevent.target = this.element[ 0 ];\n
\n
\t\t// copy original event properties over to the new event\n
\t\torig = event.originalEvent;\n
\t\tif ( orig ) {\n
\t\t\tfor ( prop in orig ) {\n
\t\t\t\tif ( !( prop in event ) ) {\n
\t\t\t\t\tevent[ prop ] = orig[ prop ];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.element.trigger( event, data );\n
\t\treturn !( $.isFunction( callback ) &&\n
\t\t\tcallback.apply( this.element[0], [ event ].concat( data ) ) === false ||\n
\t\t\tevent.isDefaultPrevented() );\n
\t}\n
};\n
\n
$.each( { show: "fadeIn", hide: "fadeOut" }, function( method, defaultEffect ) {\n
\t$.Widget.prototype[ "_" + method ] = function( element, options, callback ) {\n
\t\tif ( typeof options === "string" ) {\n
\t\t\toptions = { effect: options };\n
\t\t}\n
\t\tvar hasOptions,\n
\t\t\teffectName = !options ?\n
\t\t\t\tmethod :\n
\t\t\t\toptions === true || typeof options === "number" ?\n
\t\t\t\t\tdefaultEffect :\n
\t\t\t\t\toptions.effect || defaultEffect;\n
\t\toptions = options || {};\n
\t\tif ( typeof options === "number" ) {\n
\t\t\toptions = { duration: options };\n
\t\t}\n
\t\thasOptions = !$.isEmptyObject( options );\n
\t\toptions.complete = callback;\n
\t\tif ( options.delay ) {\n
\t\t\telement.delay( options.delay );\n
\t\t}\n
\t\tif ( hasOptions && $.effects && $.effects.effect[ effectName ] ) {\n
\t\t\telement[ method ]( options );\n
\t\t} else if ( effectName !== method && element[ effectName ] ) {\n
\t\t\telement[ effectName ]( options.duration, options.easing, callback );\n
\t\t} else {\n
\t\t\telement.queue(function( next ) {\n
\t\t\t\t$( this )[ method ]();\n
\t\t\t\tif ( callback ) {\n
\t\t\t\t\tcallback.call( element[ 0 ] );\n
\t\t\t\t}\n
\t\t\t\tnext();\n
\t\t\t});\n
\t\t}\n
\t};\n
});\n
\n
})( jQuery );\n
(function( $, undefined ) {\n
\n
var mouseHandled = false;\n
$( document ).mouseup( function() {\n
\tmouseHandled = false;\n
});\n
\n
$.widget("ui.mouse", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tcancel: "input,textarea,button,select,option",\n
\t\tdistance: 1,\n
\t\tdelay: 0\n
\t},\n
\t_mouseInit: function() {\n
\t\tvar that = this;\n
\n
\t\tthis.element\n
\t\t\t.bind("mousedown."+this.widgetName, function(event) {\n
\t\t\t\treturn that._mouseDown(event);\n
\t\t\t})\n
\t\t\t.bind("click."+this.widgetName, function(event) {\n
\t\t\t\tif (true === $.data(event.target, that.widgetName + ".preventClickEvent")) {\n
\t\t\t\t\t$.removeData(event.target, that.widgetName + ".preventClickEvent");\n
\t\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\tthis.started = false;\n
\t},\n
\n
\t// TODO: make sure destroying one instance of mouse doesn\'t mess with\n
\t// other instances of mouse\n
\t_mouseDestroy: function() {\n
\t\tthis.element.unbind("."+this.widgetName);\n
\t\tif ( this._mouseMoveDelegate ) {\n
\t\t\t$(document)\n
\t\t\t\t.unbind("mousemove."+this.widgetName, this._mouseMoveDelegate)\n
\t\t\t\t.unbind("mouseup."+this.widgetName, this._mouseUpDelegate);\n
\t\t}\n
\t},\n
\n
\t_mouseDown: function(event) {\n
\t\t// don\'t let more than one widget handle mouseStart\n
\t\tif( mouseHandled ) { return; }\n
\n
\t\t// we may have missed mouseup (out of window)\n
\t\t(this._mouseStarted && this._mouseUp(event));\n
\n
\t\tthis._mouseDownEvent = event;\n
\n
\t\tvar that = this,\n
\t\t\tbtnIsLeft = (event.which === 1),\n
\t\t\t// event.target.nodeName works around a bug in IE 8 with\n
\t\t\t// disabled inputs (#7620)\n
\t\t\telIsCancel = (typeof this.options.cancel === "string" && event.target.nodeName ? $(event.target).closest(this.options.cancel).length : false);\n
\t\tif (!btnIsLeft || elIsCancel || !this._mouseCapture(event)) {\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\tthis.mouseDelayMet = !this.options.delay;\n
\t\tif (!this.mouseDelayMet) {\n
\t\t\tthis._mouseDelayTimer = setTimeout(function() {\n
\t\t\t\tthat.mouseDelayMet = true;\n
\t\t\t}, this.options.delay);\n
\t\t}\n
\n
\t\tif (this._mouseDistanceMet(event) && this._mouseDelayMet(event)) {\n
\t\t\tthis._mouseStarted = (this._mouseStart(event) !== false);\n
\t\t\tif (!this._mouseStarted) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Click event may never have fired (Gecko & Opera)\n
\t\tif (true === $.data(event.target, this.widgetName + ".preventClickEvent")) {\n
\t\t\t$.removeData(event.target, this.widgetName + ".preventClickEvent");\n
\t\t}\n
\n
\t\t// these delegates are required to keep context\n
\t\tthis._mouseMoveDelegate = function(event) {\n
\t\t\treturn that._mouseMove(event);\n
\t\t};\n
\t\tthis._mouseUpDelegate = function(event) {\n
\t\t\treturn that._mouseUp(event);\n
\t\t};\n
\t\t$(document)\n
\t\t\t.bind("mousemove."+this.widgetName, this._mouseMoveDelegate)\n
\t\t\t.bind("mouseup."+this.widgetName, this._mouseUpDelegate);\n
\n
\t\tevent.preventDefault();\n
\n
\t\tmouseHandled = true;\n
\t\treturn true;\n
\t},\n
\n
\t_mouseMove: function(event) {\n
\t\t// IE mouseup check - mouseup happened when mouse was out of window\n
\t\tif ($.ui.ie && ( !document.documentMode || document.documentMode < 9 ) && !event.button) {\n
\t\t\treturn this._mouseUp(event);\n
\t\t}\n
\n
\t\tif (this._mouseStarted) {\n
\t\t\tthis._mouseDrag(event);\n
\t\t\treturn event.preventDefault();\n
\t\t}\n
\n
\t\tif (this._mouseDistanceMet(event) && this._mouseDelayMet(event)) {\n
\t\t\tthis._mouseStarted =\n
\t\t\t\t(this._mouseStart(this._mouseDownEvent, event) !== false);\n
\t\t\t(this._mouseStarted ? this._mouseDrag(event) : this._mouseUp(event));\n
\t\t}\n
\n
\t\treturn !this._mouseStarted;\n
\t},\n
\n
\t_mouseUp: function(event) {\n
\t\t$(document)\n
\t\t\t.unbind("mousemove."+this.widgetName, this._mouseMoveDelegate)\n
\t\t\t.unbind("mouseup."+this.widgetName, this._mouseUpDelegate);\n
\n
\t\tif (this._mouseStarted) {\n
\t\t\tthis._mouseStarted = false;\n
\n
\t\t\tif (event.target === this._mouseDownEvent.target) {\n
\t\t\t\t$.data(event.target, this.widgetName + ".preventClickEvent", true);\n
\t\t\t}\n
\n
\t\t\tthis._mouseStop(event);\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseDistanceMet: function(event) {\n
\t\treturn (Math.max(\n
\t\t\t\tMath.abs(this._mouseDownEvent.pageX - event.pageX),\n
\t\t\t\tMath.abs(this._mouseDownEvent.pageY - event.pageY)\n
\t\t\t) >= this.options.distance\n
\t\t);\n
\t},\n
\n
\t_mouseDelayMet: function(/* event */) {\n
\t\treturn this.mouseDelayMet;\n
\t},\n
\n
\t// These are placeholder methods, to be overriden by extending plugin\n
\t_mouseStart: function(/* event */) {},\n
\t_mouseDrag: function(/* event */) {},\n
\t_mouseStop: function(/* event */) {},\n
\t_mouseCapture: function(/* event */) { return true; }\n
});\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.ui = $.ui || {};\n
\n
var cachedScrollbarWidth,\n
\tmax = Math.max,\n
\tabs = Math.abs,\n
\tround = Math.round,\n
\trhorizontal = /left|center|right/,\n
\trvertical = /top|center|bottom/,\n
\troffset = /[\\+\\-]\\d+(\\.[\\d]+)?%?/,\n
\trposition = /^\\w+/,\n
\trpercent = /%$/,\n
\t_position = $.fn.position;\n
\n
function getOffsets( offsets, width, height ) {\n
\treturn [\n
\t\tparseFloat( offsets[ 0 ] ) * ( rpercent.test( offsets[ 0 ] ) ? width / 100 : 1 ),\n
\t\tparseFloat( offsets[ 1 ] ) * ( rpercent.test( offsets[ 1 ] ) ? height / 100 : 1 )\n
\t];\n
}\n
\n
function parseCss( element, property ) {\n
\treturn parseInt( $.css( element, property ), 10 ) || 0;\n
}\n
\n
function getDimensions( elem ) {\n
\tvar raw = elem[0];\n
\tif ( raw.nodeType === 9 ) {\n
\t\treturn {\n
\t\t\twidth: elem.width(),\n
\t\t\theight: elem.height(),\n
\t\t\toffset: { top: 0, left: 0 }\n
\t\t};\n
\t}\n
\tif ( $.isWindow( raw ) ) {\n
\t\treturn {\n
\t\t\twidth: elem.width(),\n
\t\t\theight: elem.height(),\n
\t\t\toffset: { top: elem.scrollTop(), left: elem.scrollLeft() }\n
\t\t};\n
\t}\n
\tif ( raw.preventDefault ) {\n
\t\treturn {\n
\t\t\twidth: 0,\n
\t\t\theight: 0,\n
\t\t\toffset: { top: raw.pageY, left: raw.pageX }\n
\t\t};\n
\t}\n
\treturn {\n
\t\twidth: elem.outerWidth(),\n
\t\theight: elem.outerHeight(),\n
\t\toffset: elem.offset()\n
\t};\n
}\n
\n
$.position = {\n
\tscrollbarWidth: function() {\n
\t\tif ( cachedScrollbarWidth !== undefined ) {\n
\t\t\treturn cachedScrollbarWidth;\n
\t\t}\n
\t\tvar w1, w2,\n
\t\t\tdiv = $( "<div style=\'display:block;position:absolute;width:50px;height:50px;overflow:hidden;\'><div style=\'height:100px;width:auto;\'></div></div>" ),\n
\t\t\tinnerDiv = div.children()[0];\n
\n
\t\t$( "body" ).append( div );\n
\t\tw1 = innerDiv.offsetWidth;\n
\t\tdiv.css( "overflow", "scroll" );\n
\n
\t\tw2 = innerDiv.offsetWidth;\n
\n
\t\tif ( w1 === w2 ) {\n
\t\t\tw2 = div[0].clientWidth;\n
\t\t}\n
\n
\t\tdiv.remove();\n
\n
\t\treturn (cachedScrollbarWidth = w1 - w2);\n
\t},\n
\tgetScrollInfo: function( within ) {\n
\t\tvar overflowX = within.isWindow || within.isDocument ? "" :\n
\t\t\t\twithin.element.css( "overflow-x" ),\n
\t\t\toverflowY = within.isWindow || within.isDocument ? "" :\n
\t\t\t\twithin.element.css( "overflow-y" ),\n
\t\t\thasOverflowX = overflowX === "scroll" ||\n
\t\t\t\t( overflowX === "auto" && within.width < within.element[0].scrollWidth ),\n
\t\t\thasOverflowY = overflowY === "scroll" ||\n
\t\t\t\t( overflowY === "auto" && within.height < within.element[0].scrollHeight );\n
\t\treturn {\n
\t\t\twidth: hasOverflowY ? $.position.scrollbarWidth() : 0,\n
\t\t\theight: hasOverflowX ? $.position.scrollbarWidth() : 0\n
\t\t};\n
\t},\n
\tgetWithinInfo: function( element ) {\n
\t\tvar withinElement = $( element || window ),\n
\t\t\tisWindow = $.isWindow( withinElement[0] ),\n
\t\t\tisDocument = !!withinElement[ 0 ] && withinElement[ 0 ].nodeType === 9;\n
\t\treturn {\n
\t\t\telement: withinElement,\n
\t\t\tisWindow: isWindow,\n
\t\t\tisDocument: isDocument,\n
\t\t\toffset: withinElement.offset() || { left: 0, top: 0 },\n
\t\t\tscrollLeft: withinElement.scrollLeft(),\n
\t\t\tscrollTop: withinElement.scrollTop(),\n
\t\t\twidth: isWindow ? withinElement.width() : withinElement.outerWidth(),\n
\t\t\theight: isWindow ? withinElement.height() : withinElement.outerHeight()\n
\t\t};\n
\t}\n
};\n
\n
$.fn.position = function( options ) {\n
\tif ( !options || !options.of ) {\n
\t\treturn _position.apply( this, arguments );\n
\t}\n
\n
\t// make a copy, we don\'t want to modify arguments\n
\toptions = $.extend( {}, options );\n
\n
\tvar atOffset, targetWidth, targetHeight, targetOffset, basePosition, dimensions,\n
\t\ttarget = $( options.of ),\n
\t\twithin = $.position.getWithinInfo( options.within ),\n
\t\tscrollInfo = $.position.getScrollInfo( within ),\n
\t\tcollision = ( options.collision || "flip" ).split( " " ),\n
\t\toffsets = {};\n
\n
\tdimensions = getDimensions( target );\n
\tif ( target[0].preventDefault ) {\n
\t\t// force left top to allow flipping\n
\t\toptions.at = "left top";\n
\t}\n
\ttargetWidth = dimensions.width;\n
\ttargetHeight = dimensions.height;\n
\ttargetOffset = dimensions.offset;\n
\t// clone to reuse original targetOffset later\n
\tbasePosition = $.extend( {}, targetOffset );\n
\n
\t// force my and at to have valid horizontal and vertical positions\n
\t// if a value is missing or invalid, it will be converted to center\n
\t$.each( [ "my", "at" ], function() {\n
\t\tvar pos = ( options[ this ] || "" ).split( " " ),\n
\t\t\thorizontalOffset,\n
\t\t\tverticalOffset;\n
\n
\t\tif ( pos.length === 1) {\n
\t\t\tpos = rhorizontal.test( pos[ 0 ] ) ?\n
\t\t\t\tpos.concat( [ "center" ] ) :\n
\t\t\t\trvertical.test( pos[ 0 ] ) ?\n
\t\t\t\t\t[ "center" ].concat( pos ) :\n
\t\t\t\t\t[ "center", "center" ];\n
\t\t}\n
\t\tpos[ 0 ] = rhorizontal.test( pos[ 0 ] ) ? pos[ 0 ] : "center";\n
\t\tpos[ 1 ] = rvertical.test( pos[ 1 ] ) ? pos[ 1 ] : "center";\n
\n
\t\t// calculate offsets\n
\t\thorizontalOffset = roffset.exec( pos[ 0 ] );\n
\t\tverticalOffset = roffset.exec( pos[ 1 ] );\n
\t\toffsets[ this ] = [\n
\t\t\thorizontalOffset ? horizontalOffset[ 0 ] : 0,\n
\t\t\tverticalOffset ? verticalOffset[ 0 ] : 0\n
\t\t];\n
\n
\t\t// reduce to just the positions without the offsets\n
\t\toptions[ this ] = [\n
\t\t\trposition.exec( pos[ 0 ] )[ 0 ],\n
\t\t\trposition.exec( pos[ 1 ] )[ 0 ]\n
\t\t];\n
\t});\n
\n
\t// normalize collision option\n
\tif ( collision.length === 1 ) {\n
\t\tcollision[ 1 ] = collision[ 0 ];\n
\t}\n
\n
\tif ( options.at[ 0 ] === "right" ) {\n
\t\tbasePosition.left += targetWidth;\n
\t} else if ( options.at[ 0 ] === "center" ) {\n
\t\tbasePosition.left += targetWidth / 2;\n
\t}\n
\n
\tif ( options.at[ 1 ] === "bottom" ) {\n
\t\tbasePosition.top += targetHeight;\n
\t} else if ( options.at[ 1 ] === "center" ) {\n
\t\tbasePosition.top += targetHeight / 2;\n
\t}\n
\n
\tatOffset = getOffsets( offsets.at, targetWidth, targetHeight );\n
\tbasePosition.left += atOffset[ 0 ];\n
\tbasePosition.top += atOffset[ 1 ];\n
\n
\treturn this.each(function() {\n
\t\tvar collisionPosition, using,\n
\t\t\telem = $( this ),\n
\t\t\telemWidth = elem.outerWidth(),\n
\t\t\telemHeight = elem.outerHeight(),\n
\t\t\tmarginLeft = parseCss( this, "marginLeft" ),\n
\t\t\tmarginTop = parseCss( this, "marginTop" ),\n
\t\t\tcollisionWidth = elemWidth + marginLeft + parseCss( this, "marginRight" ) + scrollInfo.width,\n
\t\t\tcollisionHeight = elemHeight + marginTop + parseCss( this, "marginBottom" ) + scrollInfo.height,\n
\t\t\tposition = $.extend( {}, basePosition ),\n
\t\t\tmyOffset = getOffsets( offsets.my, elem.outerWidth(), elem.outerHeight() );\n
\n
\t\tif ( options.my[ 0 ] === "right" ) {\n
\t\t\tposition.left -= elemWidth;\n
\t\t} else if ( options.my[ 0 ] === "center" ) {\n
\t\t\tposition.left -= elemWidth / 2;\n
\t\t}\n
\n
\t\tif ( options.my[ 1 ] === "bottom" ) {\n
\t\t\tposition.top -= elemHeight;\n
\t\t} else if ( options.my[ 1 ] === "center" ) {\n
\t\t\tposition.top -= elemHeight / 2;\n
\t\t}\n
\n
\t\tposition.left += myOffset[ 0 ];\n
\t\tposition.top += myOffset[ 1 ];\n
\n
\t\t// if the browser doesn\'t support fractions, then round for consistent results\n
\t\tif ( !$.support.offsetFractions ) {\n
\t\t\tposition.left = round( position.left );\n
\t\t\tposition.top = round( position.top );\n
\t\t}\n
\n
\t\tcollisionPosition = {\n
\t\t\tmarginLeft: marginLeft,\n
\t\t\tmarginTop: marginTop\n
\t\t};\n
\n
\t\t$.each( [ "left", "top" ], function( i, dir ) {\n
\t\t\tif ( $.ui.position[ collision[ i ] ] ) {\n
\t\t\t\t$.ui.position[ collision[ i ] ][ dir ]( position, {\n
\t\t\t\t\ttargetWidth: targetWidth,\n
\t\t\t\t\ttargetHeight: targetHeight,\n
\t\t\t\t\telemWidth: elemWidth,\n
\t\t\t\t\telemHeight: elemHeight,\n
\t\t\t\t\tcollisionPosition: collisionPosition,\n
\t\t\t\t\tcollisionWidth: collisionWidth,\n
\t\t\t\t\tcollisionHeight: collisionHeight,\n
\t\t\t\t\toffset: [ atOffset[ 0 ] + myOffset[ 0 ], atOffset [ 1 ] + myOffset[ 1 ] ],\n
\t\t\t\t\tmy: options.my,\n
\t\t\t\t\tat: options.at,\n
\t\t\t\t\twithin: within,\n
\t\t\t\t\telem : elem\n
\t\t\t\t});\n
\t\t\t}\n
\t\t});\n
\n
\t\tif ( options.using ) {\n
\t\t\t// adds feedback as second argument to using callback, if present\n
\t\t\tusing = function( props ) {\n
\t\t\t\tvar left = targetOffset.left - position.left,\n
\t\t\t\t\tright = left + targetWidth - elemWidth,\n
\t\t\t\t\ttop = targetOffset.top - position.top,\n
\t\t\t\t\tbottom = top + targetHeight - elemHeight,\n
\t\t\t\t\tfeedback = {\n
\t\t\t\t\t\ttarget: {\n
\t\t\t\t\t\t\telement: target,\n
\t\t\t\t\t\t\tleft: targetOffset.left,\n
\t\t\t\t\t\t\ttop: targetOffset.top,\n
\t\t\t\t\t\t\twidth: targetWidth,\n
\t\t\t\t\t\t\theight: targetHeight\n
\t\t\t\t\t\t},\n
\t\t\t\t\t\telement: {\n
\t\t\t\t\t\t\telement: elem,\n
\t\t\t\t\t\t\tleft: position.left,\n
\t\t\t\t\t\t\ttop: position.top,\n
\t\t\t\t\t\t\twidth: elemWidth,\n
\t\t\t\t\t\t\theight: elemHeight\n
\t\t\t\t\t\t},\n
\t\t\t\t\t\thorizontal: right < 0 ? "left" : left > 0 ? "right" : "center",\n
\t\t\t\t\t\tvertical: bottom < 0 ? "top" : top > 0 ? "bottom" : "middle"\n
\t\t\t\t\t};\n
\t\t\t\tif ( targetWidth < elemWidth && abs( left + right ) < targetWidth ) {\n
\t\t\t\t\tfeedback.horizontal = "center";\n
\t\t\t\t}\n
\t\t\t\tif ( targetHeight < elemHeight && abs( top + bottom ) < targetHeight ) {\n
\t\t\t\t\tfeedback.vertical = "middle";\n
\t\t\t\t}\n
\t\t\t\tif ( max( abs( left ), abs( right ) ) > max( abs( top ), abs( bottom ) ) ) {\n
\t\t\t\t\tfeedback.important = "horizontal";\n
\t\t\t\t} else {\n
\t\t\t\t\tfeedback.important = "vertical";\n
\t\t\t\t}\n
\t\t\t\toptions.using.call( this, props, feedback );\n
\t\t\t};\n
\t\t}\n
\n
\t\telem.offset( $.extend( position, { using: using } ) );\n
\t});\n
};\n
\n
$.ui.position = {\n
\tfit: {\n
\t\tleft: function( position, data ) {\n
\t\t\tvar within = data.within,\n
\t\t\t\twithinOffset = within.isWindow ? within.scrollLeft : within.offset.left,\n
\t\t\t\touterWidth = within.width,\n
\t\t\t\tcollisionPosLeft = position.left - data.collisionPosition.marginLeft,\n
\t\t\t\toverLeft = withinOffset - collisionPosLeft,\n
\t\t\t\toverRight = collisionPosLeft + data.collisionWidth - outerWidth - withinOffset,\n
\t\t\t\tnewOverRight;\n
\n
\t\t\t// element is wider than within\n
\t\t\tif ( data.collisionWidth > outerWidth ) {\n
\t\t\t\t// element is initially over the left side of within\n
\t\t\t\tif ( overLeft > 0 && overRight <= 0 ) {\n
\t\t\t\t\tnewOverRight = position.left + overLeft + data.collisionWidth - outerWidth - withinOffset;\n
\t\t\t\t\tposition.left += overLeft - newOverRight;\n
\t\t\t\t// element is initially over right side of within\n
\t\t\t\t} else if ( overRight > 0 && overLeft <= 0 ) {\n
\t\t\t\t\tposition.left = withinOffset;\n
\t\t\t\t// element is initially over both left and right sides of within\n
\t\t\t\t} else {\n
\t\t\t\t\tif ( overLeft > overRight ) {\n
\t\t\t\t\t\tposition.left = withinOffset + outerWidth - data.collisionWidth;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tposition.left = withinOffset;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t// too far left -> align with left edge\n
\t\t\t} else if ( overLeft > 0 ) {\n
\t\t\t\tposition.left += overLeft;\n
\t\t\t// too far right -> align with right edge\n
\t\t\t} else if ( overRight > 0 ) {\n
\t\t\t\tposition.left -= overRight;\n
\t\t\t// adjust based on position and margin\n
\t\t\t} else {\n
\t\t\t\tposition.left = max( position.left - collisionPosLeft, position.left );\n
\t\t\t}\n
\t\t},\n
\t\ttop: function( position, data ) {\n
\t\t\tvar within = data.within,\n
\t\t\t\twithinOffset = within.isWindow ? within.scrollTop : within.offset.top,\n
\t\t\t\touterHeight = data.within.height,\n
\t\t\t\tcollisionPosTop = position.top - data.collisionPosition.marginTop,\n
\t\t\t\toverTop = withinOffset - collisionPosTop,\n
\t\t\t\toverBottom = collisionPosTop + data.collisionHeight - outerHeight - withinOffset,\n
\t\t\t\tnewOverBottom;\n
\n
\t\t\t// element is taller than within\n
\t\t\tif ( data.collisionHeight > outerHeight ) {\n
\t\t\t\t// element is initially over the top of within\n
\t\t\t\tif ( overTop > 0 && overBottom <= 0 ) {\n
\t\t\t\t\tnewOverBottom = position.top + overTop + data.collisionHeight - outerHeight - withinOffset;\n
\t\t\t\t\tposition.top += overTop - newOverBottom;\n
\t\t\t\t// element is initially over bottom of within\n
\t\t\t\t} else if ( overBottom > 0 && overTop <= 0 ) {\n
\t\t\t\t\tposition.top = withinOffset;\n
\t\t\t\t// element is initially over both top and bottom of within\n
\t\t\t\t} else {\n
\t\t\t\t\tif ( overTop > overBottom ) {\n
\t\t\t\t\t\tposition.top = withinOffset + outerHeight - data.collisionHeight;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tposition.top = withinOffset;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t// too far up -> align with top\n
\t\t\t} else if ( overTop > 0 ) {\n
\t\t\t\tposition.top += overTop;\n
\t\t\t// too far down -> align with bottom edge\n
\t\t\t} else if ( overBottom > 0 ) {\n
\t\t\t\tposition.top -= overBottom;\n
\t\t\t// adjust based on position and margin\n
\t\t\t} else {\n
\t\t\t\tposition.top = max( position.top - collisionPosTop, position.top );\n
\t\t\t}\n
\t\t}\n
\t},\n
\tflip: {\n
\t\tleft: function( position, data ) {\n
\t\t\tvar within = data.within,\n
\t\t\t\twithinOffset = within.offset.left + within.scrollLeft,\n
\t\t\t\touterWidth = within.width,\n
\t\t\t\toffsetLeft = within.isWindow ? within.scrollLeft : within.offset.left,\n
\t\t\t\tcollisionPosLeft = position.left - data.collisionPosition.marginLeft,\n
\t\t\t\toverLeft = collisionPosLeft - offsetLeft,\n
\t\t\t\toverRight = collisionPosLeft + data.collisionWidth - outerWidth - offsetLeft,\n
\t\t\t\tmyOffset = data.my[ 0 ] === "left" ?\n
\t\t\t\t\t-data.elemWidth :\n
\t\t\t\t\tdata.my[ 0 ] === "right" ?\n
\t\t\t\t\t\tdata.elemWidth :\n
\t\t\t\t\t\t0,\n
\t\t\t\tatOffset = data.at[ 0 ] === "left" ?\n
\t\t\t\t\tdata.targetWidth :\n
\t\t\t\t\tdata.at[ 0 ] === "right" ?\n
\t\t\t\t\t\t-data.targetWidth :\n
\t\t\t\t\t\t0,\n
\t\t\t\toffset = -2 * data.offset[ 0 ],\n
\t\t\t\tnewOverRight,\n
\t\t\t\tnewOverLeft;\n
\n
\t\t\tif ( overLeft < 0 ) {\n
\t\t\t\tnewOverRight = position.left + myOffset + atOffset + offset + data.collisionWidth - outerWidth - withinOffset;\n
\t\t\t\tif ( newOverRight < 0 || newOverRight < abs( overLeft ) ) {\n
\t\t\t\t\tposition.left += myOffset + atOffset + offset;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\telse if ( overRight > 0 ) {\n
\t\t\t\tnewOverLeft = position.left - data.collisionPosition.marginLeft + myOffset + atOffset + offset - offsetLeft;\n
\t\t\t\tif ( newOverLeft > 0 || abs( newOverLeft ) < overRight ) {\n
\t\t\t\t\tposition.left += myOffset + atOffset + offset;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\ttop: function( position, data ) {\n
\t\t\tvar within = data.within,\n
\t\t\t\twithinOffset = within.offset.top + within.scrollTop,\n
\t\t\t\touterHeight = within.height,\n
\t\t\t\toffsetTop = within.isWindow ? within.scrollTop : within.offset.top,\n
\t\t\t\tcollisionPosTop = position.top - data.collisionPosition.marginTop,\n
\t\t\t\toverTop = collisionPosTop - offsetTop,\n
\t\t\t\toverBottom = collisionPosTop + data.collisionHeight - outerHeight - offsetTop,\n
\t\t\t\ttop = data.my[ 1 ] === "top",\n
\t\t\t\tmyOffset = top ?\n
\t\t\t\t\t-data.elemHeight :\n
\t\t\t\t\tdata.my[ 1 ] === "bottom" ?\n
\t\t\t\t\t\tdata.elemHeight :\n
\t\t\t\t\t\t0,\n
\t\t\t\tatOffset = data.at[ 1 ] === "top" ?\n
\t\t\t\t\tdata.targetHeight :\n
\t\t\t\t\tdata.at[ 1 ] === "bottom" ?\n
\t\t\t\t\t\t-data.targetHeight :\n
\t\t\t\t\t\t0,\n
\t\t\t\toffset = -2 * data.offset[ 1 ],\n
\t\t\t\tnewOverTop,\n
\t\t\t\tnewOverBottom;\n
\t\t\tif ( overTop < 0 ) {\n
\t\t\t\tnewOverBottom = position.top + myOffset + atOffset + offset + data.collisionHeight - outerHeight - withinOffset;\n
\t\t\t\tif ( ( position.top + myOffset + atOffset + offset) > overTop && ( newOverBottom < 0 || newOverBottom < abs( overTop ) ) ) {\n
\t\t\t\t\tposition.top += myOffset + atOffset + offset;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\telse if ( overBottom > 0 ) {\n
\t\t\t\tnewOverTop = position.top - data.collisionPosition.marginTop + myOffset + atOffset + offset - offsetTop;\n
\t\t\t\tif ( ( position.top + myOffset + atOffset + offset) > overBottom && ( newOverTop > 0 || abs( newOverTop ) < overBottom ) ) {\n
\t\t\t\t\tposition.top += myOffset + atOffset + offset;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\tflipfit: {\n
\t\tleft: function() {\n
\t\t\t$.ui.position.flip.left.apply( this, arguments );\n
\t\t\t$.ui.position.fit.left.apply( this, arguments );\n
\t\t},\n
\t\ttop: function() {\n
\t\t\t$.ui.position.flip.top.apply( this, arguments );\n
\t\t\t$.ui.position.fit.top.apply( this, arguments );\n
\t\t}\n
\t}\n
};\n
\n
// fraction support test\n
(function () {\n
\tvar testElement, testElementParent, testElementStyle, offsetLeft, i,\n
\t\tbody = document.getElementsByTagName( "body" )[ 0 ],\n
\t\tdiv = document.createElement( "div" );\n
\n
\t//Create a "fake body" for testing based on method used in jQuery.support\n
\ttestElement = document.createElement( body ? "div" : "body" );\n
\ttestElementStyle = {\n
\t\tvisibility: "hidden",\n
\t\twidth: 0,\n
\t\theight: 0,\n
\t\tborder: 0,\n
\t\tmargin: 0,\n
\t\tbackground: "none"\n
\t};\n
\tif ( body ) {\n
\t\t$.extend( testElementStyle, {\n
\t\t\tposition: "absolute",\n
\t\t\tleft: "-1000px",\n
\t\t\ttop: "-1000px"\n
\t\t});\n
\t}\n
\tfor ( i in testElementStyle ) {\n
\t\ttestElement.style[ i ] = testElementStyle[ i ];\n
\t}\n
\ttestElement.appendChild( div );\n
\ttestElementParent = body || document.documentElement;\n
\ttestElementParent.insertBefore( testElement, testElementParent.firstChild );\n
\n
\tdiv.style.cssText = "position: absolute; left: 10.7432222px;";\n
\n
\toffsetLeft = $( div ).offset().left;\n
\t$.support.offsetFractions = offsetLeft > 10 && offsetLeft < 11;\n
\n
\ttestElement.innerHTML = "";\n
\ttestElementParent.removeChild( testElement );\n
})();\n
\n
}( jQuery ) );\n
(function( $, undefined ) {\n
\n
$.widget("ui.draggable", $.ui.mouse, {\n
\tversion: "1.10.4",\n
\twidgetEventPrefix: "drag",\n
\toptions: {\n
\t\taddClasses: true,\n
\t\tappendTo: "parent",\n
\t\taxis: false,\n
\t\tconnectToSortable: false,\n
\t\tcontainment: false,\n
\t\tcursor: "auto",\n
\t\tcursorAt: false,\n
\t\tgrid: false,\n
\t\thandle: false,\n
\t\thelper: "original",\n
\t\tiframeFix: false,\n
\t\topacity: false,\n
\t\trefreshPositions: false,\n
\t\trevert: false,\n
\t\trevertDuration: 500,\n
\t\tscope: "default",\n
\t\tscroll: true,\n
\t\tscrollSensitivity: 20,\n
\t\tscrollSpeed: 20,\n
\t\tsnap: false,\n
\t\tsnapMode: "both",\n
\t\tsnapTolerance: 20,\n
\t\tstack: false,\n
\t\tzIndex: false,\n
\n
\t\t// callbacks\n
\t\tdrag: null,\n
\t\tstart: null,\n
\t\tstop: null\n
\t},\n
\t_create: function() {\n
\n
\t\tif (this.options.helper === "original" && !(/^(?:r|a|f)/).test(this.element.css("position"))) {\n
\t\t\tthis.element[0].style.position = "relative";\n
\t\t}\n
\t\tif (this.options.addClasses){\n
\t\t\tthis.element.addClass("ui-draggable");\n
\t\t}\n
\t\tif (this.options.disabled){\n
\t\t\tthis.element.addClass("ui-draggable-disabled");\n
\t\t}\n
\n
\t\tthis._mouseInit();\n
\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element.removeClass( "ui-draggable ui-draggable-dragging ui-draggable-disabled" );\n
\t\tthis._mouseDestroy();\n
\t},\n
\n
\t_mouseCapture: function(event) {\n
\n
\t\tvar o = this.options;\n
\n
\t\t// among others, prevent a drag on a resizable-handle\n
\t\tif (this.helper || o.disabled || $(event.target).closest(".ui-resizable-handle").length > 0) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t//Quit if we\'re not on a valid handle\n
\t\tthis.handle = this._getHandle(event);\n
\t\tif (!this.handle) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t$(o.iframeFix === true ? "iframe" : o.iframeFix).each(function() {\n
\t\t\t$("<div class=\'ui-draggable-iframeFix\' style=\'background: #fff;\'></div>")\n
\t\t\t.css({\n
\t\t\t\twidth: this.offsetWidth+"px", height: this.offsetHeight+"px",\n
\t\t\t\tposition: "absolute", opacity: "0.001", zIndex: 1000\n
\t\t\t})\n
\t\t\t.css($(this).offset())\n
\t\t\t.appendTo("body");\n
\t\t});\n
\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\n
\t\tvar o = this.options;\n
\n
\t\t//Create and append the visible helper\n
\t\tthis.helper = this._createHelper(event);\n
\n
\t\tthis.helper.addClass("ui-draggable-dragging");\n
\n
\t\t//Cache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t//If ddmanager is used for droppables, set the global draggable\n
\t\tif($.ui.ddmanager) {\n
\t\t\t$.ui.ddmanager.current = this;\n
\t\t}\n
\n
\t\t/*\n
\t\t * - Position generation -\n
\t\t * This block generates everything position related - it\'s the core of draggables.\n
\t\t */\n
\n
\t\t//Cache the margins of the original element\n
\t\tthis._cacheMargins();\n
\n
\t\t//Store the helper\'s css position\n
\t\tthis.cssPosition = this.helper.css( "position" );\n
\t\tthis.scrollParent = this.helper.scrollParent();\n
\t\tthis.offsetParent = this.helper.offsetParent();\n
\t\tthis.offsetParentCssPosition = this.offsetParent.css( "position" );\n
\n
\t\t//The element\'s absolute position on the page minus margins\n
\t\tthis.offset = this.positionAbs = this.element.offset();\n
\t\tthis.offset = {\n
\t\t\ttop: this.offset.top - this.margins.top,\n
\t\t\tleft: this.offset.left - this.margins.left\n
\t\t};\n
\n
\t\t//Reset scroll cache\n
\t\tthis.offset.scroll = false;\n
\n
\t\t$.extend(this.offset, {\n
\t\t\tclick: { //Where the click happened, relative to the element\n
\t\t\t\tleft: event.pageX - this.offset.left,\n
\t\t\t\ttop: event.pageY - this.offset.top\n
\t\t\t},\n
\t\t\tparent: this._getParentOffset(),\n
\t\t\trelative: this._getRelativeOffset() //This is a relative to absolute position minus the actual position calculation - only used for relative positioned helper\n
\t\t});\n
\n
\t\t//Generate the original position\n
\t\tthis.originalPosition = this.position = this._generatePosition(event);\n
\t\tthis.originalPageX = event.pageX;\n
\t\tthis.originalPageY = event.pageY;\n
\n
\t\t//Adjust the mouse offset relative to the helper if "cursorAt" is supplied\n
\t\t(o.cursorAt && this._adjustOffsetFromHelper(o.cursorAt));\n
\n
\t\t//Set a containment if given in the options\n
\t\tthis._setContainment();\n
\n
\t\t//Trigger event + callbacks\n
\t\tif(this._trigger("start", event) === false) {\n
\t\t\tthis._clear();\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t//Recache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t//Prepare the droppable offsets\n
\t\tif ($.ui.ddmanager && !o.dropBehaviour) {\n
\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\t\t}\n
\n
\n
\t\tthis._mouseDrag(event, true); //Execute the drag once - this causes the helper not to be visible before getting its correct position\n
\n
\t\t//If the ddmanager is used for droppables, inform the manager that dragging has started (see #5003)\n
\t\tif ( $.ui.ddmanager ) {\n
\t\t\t$.ui.ddmanager.dragStart(this, event);\n
\t\t}\n
\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function(event, noPropagation) {\n
\t\t// reset any necessary cached properties (see #5009)\n
\t\tif ( this.offsetParentCssPosition === "fixed" ) {\n
\t\t\tthis.offset.parent = this._getParentOffset();\n
\t\t}\n
\n
\t\t//Compute the helpers position\n
\t\tthis.position = this._generatePosition(event);\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\t//Call plugins and callbacks and use the resulting position if something is returned\n
\t\tif (!noPropagation) {\n
\t\t\tvar ui = this._uiHash();\n
\t\t\tif(this._trigger("drag", event, ui) === false) {\n
\t\t\t\tthis._mouseUp({});\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tthis.position = ui.position;\n
\t\t}\n
\n
\t\tif(!this.options.axis || this.options.axis !== "y") {\n
\t\t\tthis.helper[0].style.left = this.position.left+"px";\n
\t\t}\n
\t\tif(!this.options.axis || this.options.axis !== "x") {\n
\t\t\tthis.helper[0].style.top = this.position.top+"px";\n
\t\t}\n
\t\tif($.ui.ddmanager) {\n
\t\t\t$.ui.ddmanager.drag(this, event);\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\n
\t\t//If we are using droppables, inform the manager about the drop\n
\t\tvar that = this,\n
\t\t\tdropped = false;\n
\t\tif ($.ui.ddmanager && !this.options.dropBehaviour) {\n
\t\t\tdropped = $.ui.ddmanager.drop(this, event);\n
\t\t}\n
\n
\t\t//if a drop comes from outside (a sortable)\n
\t\tif(this.dropped) {\n
\t\t\tdropped = this.dropped;\n
\t\t\tthis.dropped = false;\n
\t\t}\n
\n
\t\t//if the original element is no longer in the DOM don\'t bother to continue (see #8269)\n
\t\tif ( this.options.helper === "original" && !$.contains( this.element[ 0 ].ownerDocument, this.element[ 0 ] ) ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif((this.options.revert === "invalid" && !dropped) || (this.options.revert === "valid" && dropped) || this.options.revert === true || ($.isFunction(this.options.revert) && this.options.revert.call(this.element, dropped))) {\n
\t\t\t$(this.helper).animate(this.originalPosition, parseInt(this.options.revertDuration, 10), function() {\n
\t\t\t\tif(that._trigger("stop", event) !== false) {\n
\t\t\t\t\tthat._clear();\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\tif(this._trigger("stop", event) !== false) {\n
\t\t\t\tthis._clear();\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseUp: function(event) {\n
\t\t//Remove frame helpers\n
\t\t$("div.ui-draggable-iframeFix").each(function() {\n
\t\t\tthis.parentNode.removeChild(this);\n
\t\t});\n
\n
\t\t//If the ddmanager is used for droppables, inform the manager that dragging has stopped (see #5003)\n
\t\tif( $.ui.ddmanager ) {\n
\t\t\t$.ui.ddmanager.dragStop(this, event);\n
\t\t}\n
\n
\t\treturn $.ui.mouse.prototype._mouseUp.call(this, event);\n
\t},\n
\n
\tcancel: function() {\n
\n
\t\tif(this.helper.is(".ui-draggable-dragging")) {\n
\t\t\tthis._mouseUp({});\n
\t\t} else {\n
\t\t\tthis._clear();\n
\t\t}\n
\n
\t\treturn this;\n
\n
\t},\n
\n
\t_getHandle: function(event) {\n
\t\treturn this.options.handle ?\n
\t\t\t!!$( event.target ).closest( this.element.find( this.options.handle ) ).length :\n
\t\t\ttrue;\n
\t},\n
\n
\t_createHelper: function(event) {\n
\n
\t\tvar o = this.options,\n
\t\t\thelper = $.isFunction(o.helper) ? $(o.helper.apply(this.element[0], [event])) : (o.helper === "clone" ? this.element.clone().removeAttr("id") : this.element);\n
\n
\t\tif(!helper.parents("body").length) {\n
\t\t\thelper.appendTo((o.appendTo === "parent" ? this.element[0].parentNode : o.appendTo));\n
\t\t}\n
\n
\t\tif(helper[0] !== this.element[0] && !(/(fixed|absolute)/).test(helper.css("position"))) {\n
\t\t\thelper.css("position", "absolute");\n
\t\t}\n
\n
\t\treturn helper;\n
\n
\t},\n
\n
\t_adjustOffsetFromHelper: function(obj) {\n
\t\tif (typeof obj === "string") {\n
\t\t\tobj = obj.split(" ");\n
\t\t}\n
\t\tif ($.isArray(obj)) {\n
\t\t\tobj = {left: +obj[0], top: +obj[1] || 0};\n
\t\t}\n
\t\tif ("left" in obj) {\n
\t\t\tthis.offset.click.left = obj.left + this.margins.left;\n
\t\t}\n
\t\tif ("right" in obj) {\n
\t\t\tthis.offset.click.left = this.helperProportions.width - obj.right + this.margins.left;\n
\t\t}\n
\t\tif ("top" in obj) {\n
\t\t\tthis.offset.click.top = obj.top + this.margins.top;\n
\t\t}\n
\t\tif ("bottom" in obj) {\n
\t\t\tthis.offset.click.top = this.helperProportions.height - obj.bottom + this.margins.top;\n
\t\t}\n
\t},\n
\n
\t_getParentOffset: function() {\n
\n
\t\t//Get the offsetParent and cache its position\n
\t\tvar po = this.offsetParent.offset();\n
\n
\t\t// This is a special case where we need to modify a offset calculated on start, since the following happened:\n
\t\t// 1. The position of the helper is absolute, so it\'s position is calculated based on the next positioned parent\n
\t\t// 2. The actual offset parent is a child of the scroll parent, and the scroll parent isn\'t the document, which means that\n
\t\t//    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag\n
\t\tif(this.cssPosition === "absolute" && this.scrollParent[0] !== document && $.contains(this.scrollParent[0], this.offsetParent[0])) {\n
\t\t\tpo.left += this.scrollParent.scrollLeft();\n
\t\t\tpo.top += this.scrollParent.scrollTop();\n
\t\t}\n
\n
\t\t//This needs to be actually done for all browsers, since pageX/pageY includes this information\n
\t\t//Ugly IE fix\n
\t\tif((this.offsetParent[0] === document.body) ||\n
\t\t\t(this.offsetParent[0].tagName && this.offsetParent[0].tagName.toLowerCase() === "html" && $.ui.ie)) {\n
\t\t\tpo = { top: 0, left: 0 };\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: po.top + (parseInt(this.offsetParent.css("borderTopWidth"),10) || 0),\n
\t\t\tleft: po.left + (parseInt(this.offsetParent.css("borderLeftWidth"),10) || 0)\n
\t\t};\n
\n
\t},\n
\n
\t_getRelativeOffset: function() {\n
\n
\t\tif(this.cssPosition === "relative") {\n
\t\t\tvar p = this.element.position();\n
\t\t\treturn {\n
\t\t\t\ttop: p.top - (parseInt(this.helper.css("top"),10) || 0) + this.scrollParent.scrollTop(),\n
\t\t\t\tleft: p.left - (parseInt(this.helper.css("left"),10) || 0) + this.scrollParent.scrollLeft()\n
\t\t\t};\n
\t\t} else {\n
\t\t\treturn { top: 0, left: 0 };\n
\t\t}\n
\n
\t},\n
\n
\t_cacheMargins: function() {\n
\t\tthis.margins = {\n
\t\t\tleft: (parseInt(this.element.css("marginLeft"),10) || 0),\n
\t\t\ttop: (parseInt(this.element.css("marginTop"),10) || 0),\n
\t\t\tright: (parseInt(this.element.css("marginRight"),10) || 0),\n
\t\t\tbottom: (parseInt(this.element.css("marginBottom"),10) || 0)\n
\t\t};\n
\t},\n
\n
\t_cacheHelperProportions: function() {\n
\t\tthis.helperProportions = {\n
\t\t\twidth: this.helper.outerWidth(),\n
\t\t\theight: this.helper.outerHeight()\n
\t\t};\n
\t},\n
\n
\t_setContainment: function() {\n
\n
\t\tvar over, c, ce,\n
\t\t\to = this.options;\n
\n
\t\tif ( !o.containment ) {\n
\t\t\tthis.containment = null;\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( o.containment === "window" ) {\n
\t\t\tthis.containment = [\n
\t\t\t\t$( window ).scrollLeft() - this.offset.relative.left - this.offset.parent.left,\n
\t\t\t\t$( window ).scrollTop() - this.offset.relative.top - this.offset.parent.top,\n
\t\t\t\t$( window ).scrollLeft() + $( window ).width() - this.helperProportions.width - this.margins.left,\n
\t\t\t\t$( window ).scrollTop() + ( $( window ).height() || document.body.parentNode.scrollHeight ) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( o.containment === "document") {\n
\t\t\tthis.containment = [\n
\t\t\t\t0,\n
\t\t\t\t0,\n
\t\t\t\t$( document ).width() - this.helperProportions.width - this.margins.left,\n
\t\t\t\t( $( document ).height() || document.body.parentNode.scrollHeight ) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( o.containment.constructor === Array ) {\n
\t\t\tthis.containment = o.containment;\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( o.containment === "parent" ) {\n
\t\t\to.containment = this.helper[ 0 ].parentNode;\n
\t\t}\n
\n
\t\tc = $( o.containment );\n
\t\tce = c[ 0 ];\n
\n
\t\tif( !ce ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tover = c.css( "overflow" ) !== "hidden";\n
\n
\t\tthis.containment = [\n
\t\t\t( parseInt( c.css( "borderLeftWidth" ), 10 ) || 0 ) + ( parseInt( c.css( "paddingLeft" ), 10 ) || 0 ),\n
\t\t\t( parseInt( c.css( "borderTopWidth" ), 10 ) || 0 ) + ( parseInt( c.css( "paddingTop" ), 10 ) || 0 ) ,\n
\t\t\t( over ? Math.max( ce.scrollWidth, ce.offsetWidth ) : ce.offsetWidth ) - ( parseInt( c.css( "borderRightWidth" ), 10 ) || 0 ) - ( parseInt( c.css( "paddingRight" ), 10 ) || 0 ) - this.helperProportions.width - this.margins.left - this.margins.right,\n
\t\t\t( over ? Math.max( ce.scrollHeight, ce.offsetHeight ) : ce.offsetHeight ) - ( parseInt( c.css( "borderBottomWidth" ), 10 ) || 0 ) - ( parseInt( c.css( "paddingBottom" ), 10 ) || 0 ) - this.helperProportions.height - this.margins.top  - this.margins.bottom\n
\t\t];\n
\t\tthis.relative_container = c;\n
\t},\n
\n
\t_convertPositionTo: function(d, pos) {\n
\n
\t\tif(!pos) {\n
\t\t\tpos = this.position;\n
\t\t}\n
\n
\t\tvar mod = d === "absolute" ? 1 : -1,\n
\t\t\tscroll = this.cssPosition === "absolute" && !( this.scrollParent[ 0 ] !== document && $.contains( this.scrollParent[ 0 ], this.offsetParent[ 0 ] ) ) ? this.offsetParent : this.scrollParent;\n
\n
\t\t//Cache the scroll\n
\t\tif (!this.offset.scroll) {\n
\t\t\tthis.offset.scroll = {top : scroll.scrollTop(), left : scroll.scrollLeft()};\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpos.top\t+\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.relative.top * mod +\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.top * mod -\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollTop() : this.offset.scroll.top ) * mod )\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpos.left +\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.relative.left * mod +\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.left * mod\t-\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollLeft() : this.offset.scroll.left ) * mod )\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_generatePosition: function(event) {\n
\n
\t\tvar containment, co, top, left,\n
\t\t\to = this.options,\n
\t\t\tscroll = this.cssPosition === "absolute" && !( this.scrollParent[ 0 ] !== document && $.contains( this.scrollParent[ 0 ], this.offsetParent[ 0 ] ) ) ? this.offsetParent : this.scrollParent,\n
\t\t\tpageX = event.pageX,\n
\t\t\tpageY = event.pageY;\n
\n
\t\t//Cache the scroll\n
\t\tif (!this.offset.scroll) {\n
\t\t\tthis.offset.scroll = {top : scroll.scrollTop(), left : scroll.scrollLeft()};\n
\t\t}\n
\n
\t\t/*\n
\t\t * - Position constraining -\n
\t\t * Constrain the position to a mix of grid, containment.\n
\t\t */\n
\n
\t\t// If we are not dragging yet, we won\'t check for options\n
\t\tif ( this.originalPosition ) {\n
\t\t\tif ( this.containment ) {\n
\t\t\t\tif ( this.relative_container ){\n
\t\t\t\t\tco = this.relative_container.offset();\n
\t\t\t\t\tcontainment = [\n
\t\t\t\t\t\tthis.containment[ 0 ] + co.left,\n
\t\t\t\t\t\tthis.containment[ 1 ] + co.top,\n
\t\t\t\t\t\tthis.containment[ 2 ] + co.left,\n
\t\t\t\t\t\tthis.containment[ 3 ] + co.top\n
\t\t\t\t\t];\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tcontainment = this.containment;\n
\t\t\t\t}\n
\n
\t\t\t\tif(event.pageX - this.offset.click.left < containment[0]) {\n
\t\t\t\t\tpageX = containment[0] + this.offset.click.left;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageY - this.offset.click.top < containment[1]) {\n
\t\t\t\t\tpageY = containment[1] + this.offset.click.top;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageX - this.offset.click.left > containment[2]) {\n
\t\t\t\t\tpageX = containment[2] + this.offset.click.left;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageY - this.offset.click.top > containment[3]) {\n
\t\t\t\t\tpageY = containment[3] + this.offset.click.top;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(o.grid) {\n
\t\t\t\t//Check for grid elements set to 0 to prevent divide by 0 error causing invalid argument errors in IE (see ticket #6950)\n
\t\t\t\ttop = o.grid[1] ? this.originalPageY + Math.round((pageY - this.originalPageY) / o.grid[1]) * o.grid[1] : this.originalPageY;\n
\t\t\t\tpageY = containment ? ((top - this.offset.click.top >= containment[1] || top - this.offset.click.top > containment[3]) ? top : ((top - this.offset.click.top >= containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;\n
\n
\t\t\t\tleft = o.grid[0] ? this.originalPageX + Math.round((pageX - this.originalPageX) / o.grid[0]) * o.grid[0] : this.originalPageX;\n
\t\t\t\tpageX = containment ? ((left - this.offset.click.left >= containment[0] || left - this.offset.click.left > containment[2]) ? left : ((left - this.offset.click.left >= containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpageY -\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.click.top\t-\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\tthis.offset.relative.top -\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.top +\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( this.cssPosition === "fixed" ? -this.scrollParent.scrollTop() : this.offset.scroll.top )\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpageX -\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.click.left -\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\tthis.offset.relative.left -\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.left +\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( this.cssPosition === "fixed" ? -this.scrollParent.scrollLeft() : this.offset.scroll.left )\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_clear: function() {\n
\t\tthis.helper.removeClass("ui-draggable-dragging");\n
\t\tif(this.helper[0] !== this.element[0] && !this.cancelHelperRemoval) {\n
\t\t\tthis.helper.remove();\n
\t\t}\n
\t\tthis.helper = null;\n
\t\tthis.cancelHelperRemoval = false;\n
\t},\n
\n
\t// From now on bulk stuff - mainly helpers\n
\n
\t_trigger: function(type, event, ui) {\n
\t\tui = ui || this._uiHash();\n
\t\t$.ui.plugin.call(this, type, [event, ui]);\n
\t\t//The absolute position has to be recalculated after plugins\n
\t\tif(type === "drag") {\n
\t\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\t\t}\n
\t\treturn $.Widget.prototype._trigger.call(this, type, event, ui);\n
\t},\n
\n
\tplugins: {},\n
\n
\t_uiHash: function() {\n
\t\treturn {\n
\t\t\thelper: this.helper,\n
\t\t\tposition: this.position,\n
\t\t\toriginalPosition: this.originalPosition,\n
\t\t\toffset: this.positionAbs\n
\t\t};\n
\t}\n
\n
});\n
\n
$.ui.plugin.add("draggable", "connectToSortable", {\n
\tstart: function(event, ui) {\n
\n
\t\tvar inst = $(this).data("ui-draggable"), o = inst.options,\n
\t\t\tuiSortable = $.extend({}, ui, { item: inst.element });\n
\t\tinst.sortables = [];\n
\t\t$(o.connectToSortable).each(function() {\n
\t\t\tvar sortable = $.data(this, "ui-sortable");\n
\t\t\tif (sortable && !sortable.options.disabled) {\n
\t\t\t\tinst.sortables.push({\n
\t\t\t\t\tinstance: sortable,\n
\t\t\t\t\tshouldRevert: sortable.options.revert\n
\t\t\t\t});\n
\t\t\t\tsortable.refreshPositions();\t// Call the sortable\'s refreshPositions at drag start to refresh the containerCache since the sortable container cache is used in drag and needs to be up to date (this will ensure it\'s initialised as well as being kept in step with any changes that might have happened on the page).\n
\t\t\t\tsortable._trigger("activate", event, uiSortable);\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\tstop: function(event, ui) {\n
\n
\t\t//If we are still over the sortable, we fake the stop event of the sortable, but also remove helper\n
\t\tvar inst = $(this).data("ui-draggable"),\n
\t\t\tuiSortable = $.extend({}, ui, { item: inst.element });\n
\n
\t\t$.each(inst.sortables, function() {\n
\t\t\tif(this.instance.isOver) {\n
\n
\t\t\t\tthis.instance.isOver = 0;\n
\n
\t\t\t\tinst.cancelHelperRemoval = true; //Don\'t remove the helper in the draggable instance\n
\t\t\t\tthis.instance.cancelHelperRemoval = false; //Remove it in the sortable instance (so sortable plugins like revert still work)\n
\n
\t\t\t\t//The sortable revert is supported, and we have to set a temporary dropped variable on the draggable to support revert: "valid/invalid"\n
\t\t\t\tif(this.shouldRevert) {\n
\t\t\t\t\tthis.instance.options.revert = this.shouldRevert;\n
\t\t\t\t}\n
\n
\t\t\t\t//Trigger the stop of the sortable\n
\t\t\t\tthis.instance._mouseStop(event);\n
\n
\t\t\t\tthis.instance.options.helper = this.instance.options._helper;\n
\n
\t\t\t\t//If the helper has been the original item, restore properties in the sortable\n
\t\t\t\tif(inst.options.helper === "original") {\n
\t\t\t\t\tthis.instance.currentItem.css({ top: "auto", left: "auto" });\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\t\t\t\tthis.instance.cancelHelperRemoval = false; //Remove the helper in the sortable instance\n
\t\t\t\tthis.instance._trigger("deactivate", event, uiSortable);\n
\t\t\t}\n
\n
\t\t});\n
\n
\t},\n
\tdrag: function(event, ui) {\n
\n
\t\tvar inst = $(this).data("ui-draggable"), that = this;\n
\n
\t\t$.each(inst.sortables, function() {\n
\n
\t\t\tvar innermostIntersecting = false,\n
\t\t\t\tthisSortable = this;\n
\n
\t\t\t//Copy over some variables to allow calling the sortable\'s native _intersectsWith\n
\t\t\tthis.instance.positionAbs = inst.positionAbs;\n
\t\t\tthis.instance.helperProportions = inst.helperProportions;\n
\t\t\tthis.instance.offset.click = inst.offset.click;\n
\n
\t\t\tif(this.instance._intersectsWith(this.instance.containerCache)) {\n
\t\t\t\tinnermostIntersecting = true;\n
\t\t\t\t$.each(inst.sortables, function () {\n
\t\t\t\t\tthis.instance.positionAbs = inst.positionAbs;\n
\t\t\t\t\tthis.instance.helperProportions = inst.helperProportions;\n
\t\t\t\t\tthis.instance.offset.click = inst.offset.click;\n
\t\t\t\t\tif (this !== thisSortable &&\n
\t\t\t\t\t\tthis.instance._intersectsWith(this.instance.containerCache) &&\n
\t\t\t\t\t\t$.contains(thisSortable.instance.element[0], this.instance.element[0])\n
\t\t\t\t\t) {\n
\t\t\t\t\t\tinnermostIntersecting = false;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn innermostIntersecting;\n
\t\t\t\t});\n
\t\t\t}\n
\n
\n
\t\t\tif(innermostIntersecting) {\n
\t\t\t\t//If it intersects, we use a little isOver variable and set it once, so our move-in stuff gets fired only once\n
\t\t\t\tif(!this.instance.isOver) {\n
\n
\t\t\t\t\tthis.instance.isOver = 1;\n
\t\t\t\t\t//Now we fake the start of dragging for the sortable instance,\n
\t\t\t\t\t//by cloning the list group item, appending it to the sortable and using it as inst.currentItem\n
\t\t\t\t\t//We can then fire the start event of the sortable with our passed browser event, and our own helper (so it doesn\'t create a new one)\n
\t\t\t\t\tthis.instance.currentItem = $(that).clone().removeAttr("id").appendTo(this.instance.element).data("ui-sortable-item", true);\n
\t\t\t\t\tthis.instance.options._helper = this.instance.options.helper; //Store helper option to later restore it\n
\t\t\t\t\tthis.instance.options.helper = function() { return ui.helper[0]; };\n
\n
\t\t\t\t\tevent.target = this.instance.currentItem[0];\n
\t\t\t\t\tthis.instance._mouseCapture(event, true);\n
\t\t\t\t\tthis.instance._mouseStart(event, true, true);\n
\n
\t\t\t\t\t//Because the browser event is way off the new appended portlet, we modify a couple of variables to reflect the changes\n
\t\t\t\t\tthis.instance.offset.click.top = inst.offset.click.top;\n
\t\t\t\t\tthis.instance.offset.click.left = inst.offset.click.left;\n
\t\t\t\t\tthis.instance.offset.parent.left -= inst.offset.parent.left - this.instance.offset.parent.left;\n
\t\t\t\t\tthis.instance.offset.parent.top -= inst.offset.parent.top - this.instance.offset.parent.top;\n
\n
\t\t\t\t\tinst._trigger("toSortable", event);\n
\t\t\t\t\tinst.dropped = this.instance.element; //draggable revert needs that\n
\t\t\t\t\t//hack so receive/update callbacks work (mostly)\n
\t\t\t\t\tinst.currentItem = inst.element;\n
\t\t\t\t\tthis.instance.fromOutside = inst;\n
\n
\t\t\t\t}\n
\n
\t\t\t\t//Provided we did all the previous steps, we can fire the drag event of the sortable on every draggable drag, when it intersects with the sortable\n
\t\t\t\tif(this.instance.currentItem) {\n
\t\t\t\t\tthis.instance._mouseDrag(event);\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\n
\t\t\t\t//If it doesn\'t intersect with the sortable, and it intersected before,\n
\t\t\t\t//we fake the drag stop of the sortable, but make sure it doesn\'t remove the helper by using cancelHelperRemoval\n
\t\t\t\tif(this.instance.isOver) {\n
\n
\t\t\t\t\tthis.instance.isOver = 0;\n
\t\t\t\t\tthis.instance.cancelHelperRemoval = true;\n
\n
\t\t\t\t\t//Prevent reverting on this forced stop\n
\t\t\t\t\tthis.instance.options.revert = false;\n
\n
\t\t\t\t\t// The out event needs to be triggered independently\n
\t\t\t\t\tthis.instance._trigger("out", event, this.instance._uiHash(this.instance));\n
\n
\t\t\t\t\tthis.instance._mouseStop(event, true);\n
\t\t\t\t\tthis.instance.options.helper = this.instance.options._helper;\n
\n
\t\t\t\t\t//Now we remove our currentItem, the list group clone again, and the placeholder, and animate the helper back to it\'s original size\n
\t\t\t\t\tthis.instance.currentItem.remove();\n
\t\t\t\t\tif(this.instance.placeholder) {\n
\t\t\t\t\t\tthis.instance.placeholder.remove();\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tinst._trigger("fromSortable", event);\n
\t\t\t\t\tinst.dropped = false; //draggable revert needs that\n
\t\t\t\t}\n
\n
\t\t\t}\n
\n
\t\t});\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "cursor", {\n
\tstart: function() {\n
\t\tvar t = $("body"), o = $(this).data("ui-draggable").options;\n
\t\tif (t.css("cursor")) {\n
\t\t\to._cursor = t.css("cursor");\n
\t\t}\n
\t\tt.css("cursor", o.cursor);\n
\t},\n
\tstop: function() {\n
\t\tvar o = $(this).data("ui-draggable").options;\n
\t\tif (o._cursor) {\n
\t\t\t$("body").css("cursor", o._cursor);\n
\t\t}\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "opacity", {\n
\tstart: function(event, ui) {\n
\t\tvar t = $(ui.helper), o = $(this).data("ui-draggable").options;\n
\t\tif(t.css("opacity")) {\n
\t\t\to._opacity = t.css("opacity");\n
\t\t}\n
\t\tt.css("opacity", o.opacity);\n
\t},\n
\tstop: function(event, ui) {\n
\t\tvar o = $(this).data("ui-draggable").options;\n
\t\tif(o._opacity) {\n
\t\t\t$(ui.helper).css("opacity", o._opacity);\n
\t\t}\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "scroll", {\n
\tstart: function() {\n
\t\tvar i = $(this).data("ui-draggable");\n
\t\tif(i.scrollParent[0] !== document && i.scrollParent[0].tagName !== "HTML") {\n
\t\t\ti.overflowOffset = i.scrollParent.offset();\n
\t\t}\n
\t},\n
\tdrag: function( event ) {\n
\n
\t\tvar i = $(this).data("ui-draggable"), o = i.options, scrolled = false;\n
\n
\t\tif(i.scrollParent[0] !== document && i.scrollParent[0].tagName !== "HTML") {\n
\n
\t\t\tif(!o.axis || o.axis !== "x") {\n
\t\t\t\tif((i.overflowOffset.top + i.scrollParent[0].offsetHeight) - event.pageY < o.scrollSensitivity) {\n
\t\t\t\t\ti.scrollParent[0].scrollTop = scrolled = i.scrollParent[0].scrollTop + o.scrollSpeed;\n
\t\t\t\t} else if(event.pageY - i.overflowOffset.top < o.scrollSensitivity) {\n
\t\t\t\t\ti.scrollParent[0].scrollTop = scrolled = i.scrollParent[0].scrollTop - o.scrollSpeed;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(!o.axis || o.axis !== "y") {\n
\t\t\t\tif((i.overflowOffset.left + i.scrollParent[0].offsetWidth) - event.pageX < o.scrollSensitivity) {\n
\t\t\t\t\ti.scrollParent[0].scrollLeft = scrolled = i.scrollParent[0].scrollLeft + o.scrollSpeed;\n
\t\t\t\t} else if(event.pageX - i.overflowOffset.left < o.scrollSensitivity) {\n
\t\t\t\t\ti.scrollParent[0].scrollLeft = scrolled = i.scrollParent[0].scrollLeft - o.scrollSpeed;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t} else {\n
\n
\t\t\tif(!o.axis || o.axis !== "x") {\n
\t\t\t\tif(event.pageY - $(document).scrollTop() < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() - o.scrollSpeed);\n
\t\t\t\t} else if($(window).height() - (event.pageY - $(document).scrollTop()) < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() + o.scrollSpeed);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(!o.axis || o.axis !== "y") {\n
\t\t\t\tif(event.pageX - $(document).scrollLeft() < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() - o.scrollSpeed);\n
\t\t\t\t} else if($(window).width() - (event.pageX - $(document).scrollLeft()) < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() + o.scrollSpeed);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\tif(scrolled !== false && $.ui.ddmanager && !o.dropBehaviour) {\n
\t\t\t$.ui.ddmanager.prepareOffsets(i, event);\n
\t\t}\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "snap", {\n
\tstart: function() {\n
\n
\t\tvar i = $(this).data("ui-draggable"),\n
\t\t\to = i.options;\n
\n
\t\ti.snapElements = [];\n
\n
\t\t$(o.snap.constructor !== String ? ( o.snap.items || ":data(ui-draggable)" ) : o.snap).each(function() {\n
\t\t\tvar $t = $(this),\n
\t\t\t\t$o = $t.offset();\n
\t\t\tif(this !== i.element[0]) {\n
\t\t\t\ti.snapElements.push({\n
\t\t\t\t\titem: this,\n
\t\t\t\t\twidth: $t.outerWidth(), height: $t.outerHeight(),\n
\t\t\t\t\ttop: $o.top, left: $o.left\n
\t\t\t\t});\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\tdrag: function(event, ui) {\n
\n
\t\tvar ts, bs, ls, rs, l, r, t, b, i, first,\n
\t\t\tinst = $(this).data("ui-draggable"),\n
\t\t\to = inst.options,\n
\t\t\td = o.snapTolerance,\n
\t\t\tx1 = ui.offset.left, x2 = x1 + inst.helperProportions.width,\n
\t\t\ty1 = ui.offset.top, y2 = y1 + inst.helperProportions.height;\n
\n
\t\tfor (i = inst.snapElements.length - 1; i >= 0; i--){\n
\n
\t\t\tl = inst.snapElements[i].left;\n
\t\t\tr = l + inst.snapElements[i].width;\n
\t\t\tt = inst.snapElements[i].top;\n
\t\t\tb = t + inst.snapElements[i].height;\n
\n
\t\t\tif ( x2 < l - d || x1 > r + d || y2 < t - d || y1 > b + d || !$.contains( inst.snapElements[ i ].item.ownerDocument, inst.snapElements[ i ].item ) ) {\n
\t\t\t\tif(inst.snapElements[i].snapping) {\n
\t\t\t\t\t(inst.options.snap.release && inst.options.snap.release.call(inst.element, event, $.extend(inst._uiHash(), { snapItem: inst.snapElements[i].item })));\n
\t\t\t\t}\n
\t\t\t\tinst.snapElements[i].snapping = false;\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif(o.snapMode !== "inner") {\n
\t\t\t\tts = Math.abs(t - y2) <= d;\n
\t\t\t\tbs = Math.abs(b - y1) <= d;\n
\t\t\t\tls = Math.abs(l - x2) <= d;\n
\t\t\t\trs = Math.abs(r - x1) <= d;\n
\t\t\t\tif(ts) {\n
\t\t\t\t\tui.position.top = inst._convertPositionTo("relative", { top: t - inst.helperProportions.height, left: 0 }).top - inst.margins.top;\n
\t\t\t\t}\n
\t\t\t\tif(bs) {\n
\t\t\t\t\tui.position.top = inst._convertPositionTo("relative", { top: b, left: 0 }).top - inst.margins.top;\n
\t\t\t\t}\n
\t\t\t\tif(ls) {\n
\t\t\t\t\tui.position.left = inst._convertPositionTo("relative", { top: 0, left: l - inst.helperProportions.width }).left - inst.margins.left;\n
\t\t\t\t}\n
\t\t\t\tif(rs) {\n
\t\t\t\t\tui.position.left = inst._convertPositionTo("relative", { top: 0, left: r }).left - inst.margins.left;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tfirst = (ts || bs || ls || rs);\n
\n
\t\t\tif(o.snapMode !== "outer") {\n
\t\t\t\tts = Math.abs(t - y1) <= d;\n
\t\t\t\tbs = Math.abs(b - y2) <= d;\n
\t\t\t\tls = Math.abs(l - x1) <= d;\n
\t\t\t\trs = Math.abs(r - x2) <= d;\n
\t\t\t\tif(ts) {\n
\t\t\t\t\tui.position.top = inst._convertPositionTo("relative", { top: t, left: 0 }).top - inst.margins.top;\n
\t\t\t\t}\n
\t\t\t\tif(bs) {\n
\t\t\t\t\tui.position.top = inst._convertPositionTo("relative", { top: b - inst.helperProportions.height, left: 0 }).top - inst.margins.top;\n
\t\t\t\t}\n
\t\t\t\tif(ls) {\n
\t\t\t\t\tui.position.left = inst._convertPositionTo("relative", { top: 0, left: l }).left - inst.margins.left;\n
\t\t\t\t}\n
\t\t\t\tif(rs) {\n
\t\t\t\t\tui.position.left = inst._convertPositionTo("relative", { top: 0, left: r - inst.helperProportions.width }).left - inst.margins.left;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(!inst.snapElements[i].snapping && (ts || bs || ls || rs || first)) {\n
\t\t\t\t(inst.options.snap.snap && inst.options.snap.snap.call(inst.element, event, $.extend(inst._uiHash(), { snapItem: inst.snapElements[i].item })));\n
\t\t\t}\n
\t\t\tinst.snapElements[i].snapping = (ts || bs || ls || rs || first);\n
\n
\t\t}\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "stack", {\n
\tstart: function() {\n
\t\tvar min,\n
\t\t\to = this.data("ui-draggable").options,\n
\t\t\tgroup = $.makeArray($(o.stack)).sort(function(a,b) {\n
\t\t\t\treturn (parseInt($(a).css("zIndex"),10) || 0) - (parseInt($(b).css("zIndex"),10) || 0);\n
\t\t\t});\n
\n
\t\tif (!group.length) { return; }\n
\n
\t\tmin = parseInt($(group[0]).css("zIndex"), 10) || 0;\n
\t\t$(group).each(function(i) {\n
\t\t\t$(this).css("zIndex", min + i);\n
\t\t});\n
\t\tthis.css("zIndex", (min + group.length));\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "zIndex", {\n
\tstart: function(event, ui) {\n
\t\tvar t = $(ui.helper), o = $(this).data("ui-draggable").options;\n
\t\tif(t.css("zIndex")) {\n
\t\t\to._zIndex = t.css("zIndex");\n
\t\t}\n
\t\tt.css("zIndex", o.zIndex);\n
\t},\n
\tstop: function(event, ui) {\n
\t\tvar o = $(this).data("ui-draggable").options;\n
\t\tif(o._zIndex) {\n
\t\t\t$(ui.helper).css("zIndex", o._zIndex);\n
\t\t}\n
\t}\n
});\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
function isOverAxis( x, reference, size ) {\n
\treturn ( x > reference ) && ( x < ( reference + size ) );\n
}\n
\n
$.widget("ui.droppable", {\n
\tversion: "1.10.4",\n
\twidgetEventPrefix: "drop",\n
\toptions: {\n
\t\taccept: "*",\n
\t\tactiveClass: false,\n
\t\taddClasses: true,\n
\t\tgreedy: false,\n
\t\thoverClass: false,\n
\t\tscope: "default",\n
\t\ttolerance: "intersect",\n
\n
\t\t// callbacks\n
\t\tactivate: null,\n
\t\tdeactivate: null,\n
\t\tdrop: null,\n
\t\tout: null,\n
\t\tover: null\n
\t},\n
\t_create: function() {\n
\n
\t\tvar proportions,\n
\t\t\to = this.options,\n
\t\t\taccept = o.accept;\n
\n
\t\tthis.isover = false;\n
\t\tthis.isout = true;\n
\n
\t\tthis.accept = $.isFunction(accept) ? accept : function(d) {\n
\t\t\treturn d.is(accept);\n
\t\t};\n
\n
\t\tthis.proportions = function( /* valueToWrite */ ) {\n
\t\t\tif ( arguments.length ) {\n
\t\t\t\t// Store the droppable\'s proportions\n
\t\t\t\tproportions = arguments[ 0 ];\n
\t\t\t} else {\n
\t\t\t\t// Retrieve or derive the droppable\'s proportions\n
\t\t\t\treturn proportions ?\n
\t\t\t\t\tproportions :\n
\t\t\t\t\tproportions = {\n
\t\t\t\t\t\twidth: this.element[ 0 ].offsetWidth,\n
\t\t\t\t\t\theight: this.element[ 0 ].offsetHeight\n
\t\t\t\t\t};\n
\t\t\t}\n
\t\t};\n
\n
\t\t// Add the reference and positions to the manager\n
\t\t$.ui.ddmanager.droppables[o.scope] = $.ui.ddmanager.droppables[o.scope] || [];\n
\t\t$.ui.ddmanager.droppables[o.scope].push(this);\n
\n
\t\t(o.addClasses && this.element.addClass("ui-droppable"));\n
\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar i = 0,\n
\t\t\tdrop = $.ui.ddmanager.droppables[this.options.scope];\n
\n
\t\tfor ( ; i < drop.length; i++ ) {\n
\t\t\tif ( drop[i] === this ) {\n
\t\t\t\tdrop.splice(i, 1);\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.element.removeClass("ui-droppable ui-droppable-disabled");\n
\t},\n
\n
\t_setOption: function(key, value) {\n
\n
\t\tif(key === "accept") {\n
\t\t\tthis.accept = $.isFunction(value) ? value : function(d) {\n
\t\t\t\treturn d.is(value);\n
\t\t\t};\n
\t\t}\n
\t\t$.Widget.prototype._setOption.apply(this, arguments);\n
\t},\n
\n
\t_activate: function(event) {\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif(this.options.activeClass) {\n
\t\t\tthis.element.addClass(this.options.activeClass);\n
\t\t}\n
\t\tif(draggable){\n
\t\t\tthis._trigger("activate", event, this.ui(draggable));\n
\t\t}\n
\t},\n
\n
\t_deactivate: function(event) {\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif(this.options.activeClass) {\n
\t\t\tthis.element.removeClass(this.options.activeClass);\n
\t\t}\n
\t\tif(draggable){\n
\t\t\tthis._trigger("deactivate", event, this.ui(draggable));\n
\t\t}\n
\t},\n
\n
\t_over: function(event) {\n
\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\n
\t\t// Bail if draggable and droppable are same element\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] === this.element[0]) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (this.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.hoverClass) {\n
\t\t\t\tthis.element.addClass(this.options.hoverClass);\n
\t\t\t}\n
\t\t\tthis._trigger("over", event, this.ui(draggable));\n
\t\t}\n
\n
\t},\n
\n
\t_out: function(event) {\n
\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\n
\t\t// Bail if draggable and droppable are same element\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] === this.element[0]) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (this.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.hoverClass) {\n
\t\t\t\tthis.element.removeClass(this.options.hoverClass);\n
\t\t\t}\n
\t\t\tthis._trigger("out", event, this.ui(draggable));\n
\t\t}\n
\n
\t},\n
\n
\t_drop: function(event,custom) {\n
\n
\t\tvar draggable = custom || $.ui.ddmanager.current,\n
\t\t\tchildrenIntersection = false;\n
\n
\t\t// Bail if draggable and droppable are same element\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] === this.element[0]) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tthis.element.find(":data(ui-droppable)").not(".ui-draggable-dragging").each(function() {\n
\t\t\tvar inst = $.data(this, "ui-droppable");\n
\t\t\tif(\n
\t\t\t\tinst.options.greedy &&\n
\t\t\t\t!inst.options.disabled &&\n
\t\t\t\tinst.options.scope === draggable.options.scope &&\n
\t\t\t\tinst.accept.call(inst.element[0], (draggable.currentItem || draggable.element)) &&\n
\t\t\t\t$.ui.intersect(draggable, $.extend(inst, { offset: inst.element.offset() }), inst.options.tolerance)\n
\t\t\t) { childrenIntersection = true; return false; }\n
\t\t});\n
\t\tif(childrenIntersection) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif(this.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.activeClass) {\n
\t\t\t\tthis.element.removeClass(this.options.activeClass);\n
\t\t\t}\n
\t\t\tif(this.options.hoverClass) {\n
\t\t\t\tthis.element.removeClass(this.options.hoverClass);\n
\t\t\t}\n
\t\t\tthis._trigger("drop", event, this.ui(draggable));\n
\t\t\treturn this.element;\n
\t\t}\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\tui: function(c) {\n
\t\treturn {\n
\t\t\tdraggable: (c.currentItem || c.element),\n
\t\t\thelper: c.helper,\n
\t\t\tposition: c.position,\n
\t\t\toffset: c.positionAbs\n
\t\t};\n
\t}\n
\n
});\n
\n
$.ui.intersect = function(draggable, droppable, toleranceMode) {\n
\n
\tif (!droppable.offset) {\n
\t\treturn false;\n
\t}\n
\n
\tvar draggableLeft, draggableTop,\n
\t\tx1 = (draggable.positionAbs || draggable.position.absolute).left,\n
\t\ty1 = (draggable.positionAbs || draggable.position.absolute).top,\n
\t\tx2 = x1 + draggable.helperProportions.width,\n
\t\ty2 = y1 + draggable.helperProportions.height,\n
\t\tl = droppable.offset.left,\n
\t\tt = droppable.offset.top,\n
\t\tr = l + droppable.proportions().width,\n
\t\tb = t + droppable.proportions().height;\n
\n
\tswitch (toleranceMode) {\n
\t\tcase "fit":\n
\t\t\treturn (l <= x1 && x2 <= r && t <= y1 && y2 <= b);\n
\t\tcase "intersect":\n
\t\t\treturn (l < x1 + (draggable.helperProportions.width / 2) && // Right Half\n
\t\t\t\tx2 - (draggable.helperProportions.width / 2) < r && // Left Half\n
\t\t\t\tt < y1 + (draggable.helperProportions.height / 2) && // Bottom Half\n
\t\t\t\ty2 - (draggable.helperProportions.height / 2) < b ); // Top Half\n
\t\tcase "pointer":\n
\t\t\tdraggableLeft = ((draggable.positionAbs || draggable.position.absolute).left + (draggable.clickOffset || draggable.offset.click).left);\n
\t\t\tdraggableTop = ((draggable.positionAbs || draggable.position.absolute).top + (draggable.clickOffset || draggable.offset.click).top);\n
\t\t\treturn isOverAxis( draggableTop, t, droppable.proportions().height ) && isOverAxis( draggableLeft, l, droppable.proportions().width );\n
\t\tcase "touch":\n
\t\t\treturn (\n
\t\t\t\t(y1 >= t && y1 <= b) ||\t// Top edge touching\n
\t\t\t\t(y2 >= t && y2 <= b) ||\t// Bottom edge touching\n
\t\t\t\t(y1 < t && y2 > b)\t\t// Surrounded vertically\n
\t\t\t) && (\n
\t\t\t\t(x1 >= l && x1 <= r) ||\t// Left edge touching\n
\t\t\t\t(x2 >= l && x2 <= r) ||\t// Right edge touching\n
\t\t\t\t(x1 < l && x2 > r)\t\t// Surrounded horizontally\n
\t\t\t);\n
\t\tdefault:\n
\t\t\treturn false;\n
\t\t}\n
\n
};\n
\n
/*\n
\tThis manager tracks offsets of draggables and droppables\n
*/\n
$.ui.ddmanager = {\n
\tcurrent: null,\n
\tdroppables: { "default": [] },\n
\tprepareOffsets: function(t, event) {\n
\n
\t\tvar i, j,\n
\t\t\tm = $.ui.ddmanager.droppables[t.options.scope] || [],\n
\t\t\ttype = event ? event.type : null, // workaround for #2317\n
\t\t\tlist = (t.currentItem || t.element).find(":data(ui-droppable)").addBack();\n
\n
\t\tdroppablesLoop: for (i = 0; i < m.length; i++) {\n
\n
\t\t\t//No disabled and non-accepted\n
\t\t\tif(m[i].options.disabled || (t && !m[i].accept.call(m[i].element[0],(t.currentItem || t.element)))) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t// Filter out elements in the current dragged item\n
\t\t\tfor (j=0; j < list.length; j++) {\n
\t\t\t\tif(list[j] === m[i].element[0]) {\n
\t\t\t\t\tm[i].proportions().height = 0;\n
\t\t\t\t\tcontinue droppablesLoop;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tm[i].visible = m[i].element.css("display") !== "none";\n
\t\t\tif(!m[i].visible) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t//Activate the droppable if used directly from draggables\n
\t\t\tif(type === "mousedown") {\n
\t\t\t\tm[i]._activate.call(m[i], event);\n
\t\t\t}\n
\n
\t\t\tm[ i ].offset = m[ i ].element.offset();\n
\t\t\tm[ i ].proportions({ width: m[ i ].element[ 0 ].offsetWidth, height: m[ i ].element[ 0 ].offsetHeight });\n
\n
\t\t}\n
\n
\t},\n
\tdrop: function(draggable, event) {\n
\n
\t\tvar dropped = false;\n
\t\t// Create a copy of the droppables in case the list changes during the drop (#9116)\n
\t\t$.each(($.ui.ddmanager.droppables[draggable.options.scope] || []).slice(), function() {\n
\n
\t\t\tif(!this.options) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif (!this.options.disabled && this.visible && $.ui.intersect(draggable, this, this.options.tolerance)) {\n
\t\t\t\tdropped = this._drop.call(this, event) || dropped;\n
\t\t\t}\n
\n
\t\t\tif (!this.options.disabled && this.visible && this.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\t\tthis.isout = true;\n
\t\t\t\tthis.isover = false;\n
\t\t\t\tthis._deactivate.call(this, event);\n
\t\t\t}\n
\n
\t\t});\n
\t\treturn dropped;\n
\n
\t},\n
\tdragStart: function( draggable, event ) {\n
\t\t//Listen for scrolling so that if the dragging causes scrolling the position of the droppables can be recalculated (see #5003)\n
\t\tdraggable.element.parentsUntil( "body" ).bind( "scroll.droppable", function() {\n
\t\t\tif( !draggable.options.refreshPositions ) {\n
\t\t\t\t$.ui.ddmanager.prepareOffsets( draggable, event );\n
\t\t\t}\n
\t\t});\n
\t},\n
\tdrag: function(draggable, event) {\n
\n
\t\t//If you have a highly dynamic page, you might try this option. It renders positions every time you move the mouse.\n
\t\tif(draggable.options.refreshPositions) {\n
\t\t\t$.ui.ddmanager.prepareOffsets(draggable, event);\n
\t\t}\n
\n
\t\t//Run through all droppables and check their positions based on specific tolerance options\n
\t\t$.each($.ui.ddmanager.droppables[draggable.options.scope] || [], function() {\n
\n
\t\t\tif(this.options.disabled || this.greedyChild || !this.visible) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tvar parentInstance, scope, parent,\n
\t\t\t\tintersects = $.ui.intersect(draggable, this, this.options.tolerance),\n
\t\t\t\tc = !intersects && this.isover ? "isout" : (intersects && !this.isover ? "isover" : null);\n
\t\t\tif(!c) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif (this.options.greedy) {\n
\t\t\t\t// find droppable parents with same scope\n
\t\t\t\tscope = this.options.scope;\n
\t\t\t\tparent = this.element.parents(":data(ui-droppable)").filter(function () {\n
\t\t\t\t\treturn $.data(this, "ui-droppable").options.scope === scope;\n
\t\t\t\t});\n
\n
\t\t\t\tif (parent.length) {\n
\t\t\t\t\tparentInstance = $.data(parent[0], "ui-droppable");\n
\t\t\t\t\tparentInstance.greedyChild = (c === "isover");\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// we just moved into a greedy child\n
\t\t\tif (parentInstance && c === "isover") {\n
\t\t\t\tparentInstance.isover = false;\n
\t\t\t\tparentInstance.isout = true;\n
\t\t\t\tparentInstance._out.call(parentInstance, event);\n
\t\t\t}\n
\n
\t\t\tthis[c] = true;\n
\t\t\tthis[c === "isout" ? "isover" : "isout"] = false;\n
\t\t\tthis[c === "isover" ? "_over" : "_out"].call(this, event);\n
\n
\t\t\t// we just moved out of a greedy child\n
\t\t\tif (parentInstance && c === "isout") {\n
\t\t\t\tparentInstance.isout = false;\n
\t\t\t\tparentInstance.isover = true;\n
\t\t\t\tparentInstance._over.call(parentInstance, event);\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\tdragStop: function( draggable, event ) {\n
\t\tdraggable.element.parentsUntil( "body" ).unbind( "scroll.droppable" );\n
\t\t//Call prepareOffsets one final time since IE does not fire return scroll events when overflow was caused by drag (see #5003)\n
\t\tif( !draggable.options.refreshPositions ) {\n
\t\t\t$.ui.ddmanager.prepareOffsets( draggable, event );\n
\t\t}\n
\t}\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
function num(v) {\n
\treturn parseInt(v, 10) || 0;\n
}\n
\n
function isNumber(value) {\n
\treturn !isNaN(parseInt(value, 10));\n
}\n
\n
$.widget("ui.resizable", $.ui.mouse, {\n
\tversion: "1.10.4",\n
\twidgetEventPrefix: "resize",\n
\toptions: {\n
\t\talsoResize: false,\n
\t\tanimate: false,\n
\t\tanimateDuration: "slow",\n
\t\tanimateEasing: "swing",\n
\t\taspectRatio: false,\n
\t\tautoHide: false,\n
\t\tcontainment: false,\n
\t\tghost: false,\n
\t\tgrid: false,\n
\t\thandles: "e,s,se",\n
\t\thelper: false,\n
\t\tmaxHeight: null,\n
\t\tmaxWidth: null,\n
\t\tminHeight: 10,\n
\t\tminWidth: 10,\n
\t\t// See #7960\n
\t\tzIndex: 90,\n
\n
\t\t// callbacks\n
\t\tresize: null,\n
\t\tstart: null,\n
\t\tstop: null\n
\t},\n
\t_create: function() {\n
\n
\t\tvar n, i, handle, axis, hname,\n
\t\t\tthat = this,\n
\t\t\to = this.options;\n
\t\tthis.element.addClass("ui-resizable");\n
\n
\t\t$.extend(this, {\n
\t\t\t_aspectRatio: !!(o.aspectRatio),\n
\t\t\taspectRatio: o.aspectRatio,\n
\t\t\toriginalElement: this.element,\n
\t\t\t_proportionallyResizeElements: [],\n
\t\t\t_helper: o.helper || o.ghost || o.animate ? o.helper || "ui-resizable-helper" : null\n
\t\t});\n
\n
\t\t//Wrap the element if it cannot hold child nodes\n
\t\tif(this.element[0].nodeName.match(/canvas|textarea|input|select|button|img/i)) {\n
\n
\t\t\t//Create a wrapper element and set the wrapper to the new current internal element\n
\t\t\tthis.element.wrap(\n
\t\t\t\t$("<div class=\'ui-wrapper\' style=\'overflow: hidden;\'></div>").css({\n
\t\t\t\t\tposition: this.element.css("position"),\n
\t\t\t\t\twidth: this.element.outerWidth(),\n
\t\t\t\t\theight: this.element.outerHeight(),\n
\t\t\t\t\ttop: this.element.css("top"),\n
\t\t\t\t\tleft: this.element.css("left")\n
\t\t\t\t})\n
\t\t\t);\n
\n
\t\t\t//Overwrite the original this.element\n
\t\t\tthis.element = this.element.parent().data(\n
\t\t\t\t"ui-resizable", this.element.data("ui-resizable")\n
\t\t\t);\n
\n
\t\t\tthis.elementIsWrapper = true;\n
\n
\t\t\t//Move margins to the wrapper\n
\t\t\tthis.element.css({ marginLeft: this.originalElement.css("marginLeft"), marginTop: this.originalElement.css("marginTop"), marginRight: this.originalElement.css("marginRight"), marginBottom: this.originalElement.css("marginBottom") });\n
\t\t\tthis.originalElement.css({ marginLeft: 0, marginTop: 0, marginRight: 0, marginBottom: 0});\n
\n
\t\t\t//Prevent Safari textarea resize\n
\t\t\tthis.originalResizeStyle = this.originalElement.css("resize");\n
\t\t\tthis.originalElement.css("resize", "none");\n
\n
\t\t\t//Push the actual element to our proportionallyResize internal array\n
\t\t\tthis._proportionallyResizeElements.push(this.originalElement.css({ position: "static", zoom: 1, display: "block" }));\n
\n
\t\t\t// avoid IE jump (hard set the margin)\n
\t\t\tthis.originalElement.css({ margin: this.originalElement.css("margin") });\n
\n
\t\t\t// fix handlers offset\n
\t\t\tthis._proportionallyResize();\n
\n
\t\t}\n
\n
\t\tthis.handles = o.handles || (!$(".ui-resizable-handle", this.element).length ? "e,s,se" : { n: ".ui-resizable-n", e: ".ui-resizable-e", s: ".ui-resizable-s", w: ".ui-resizable-w", se: ".ui-resizable-se", sw: ".ui-resizable-sw", ne: ".ui-resizable-ne", nw: ".ui-resizable-nw" });\n
\t\tif(this.handles.constructor === String) {\n
\n
\t\t\tif ( this.handles === "all") {\n
\t\t\t\tthis.handles = "n,e,s,w,se,sw,ne,nw";\n
\t\t\t}\n
\n
\t\t\tn = this.handles.split(",");\n
\t\t\tthis.handles = {};\n
\n
\t\t\tfor(i = 0; i < n.length; i++) {\n
\n
\t\t\t\thandle = $.trim(n[i]);\n
\t\t\t\thname = "ui-resizable-"+handle;\n
\t\t\t\taxis = $("<div class=\'ui-resizable-handle " + hname + "\'></div>");\n
\n
\t\t\t\t// Apply zIndex to all handles - see #7960\n
\t\t\t\taxis.css({ zIndex: o.zIndex });\n
\n
\t\t\t\t//TODO : What\'s going on here?\n
\t\t\t\tif ("se" === handle) {\n
\t\t\t\t\taxis.addClass("ui-icon ui-icon-gripsmall-diagonal-se");\n
\t\t\t\t}\n
\n
\t\t\t\t//Insert into internal handles object and append to element\n
\t\t\t\tthis.handles[handle] = ".ui-resizable-"+handle;\n
\t\t\t\tthis.element.append(axis);\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\tthis._renderAxis = function(target) {\n
\n
\t\t\tvar i, axis, padPos, padWrapper;\n
\n
\t\t\ttarget = target || this.element;\n
\n
\t\t\tfor(i in this.handles) {\n
\n
\t\t\t\tif(this.handles[i].constructor === String) {\n
\t\t\t\t\tthis.handles[i] = $(this.handles[i], this.element).show();\n
\t\t\t\t}\n
\n
\t\t\t\t//Apply pad to wrapper element, needed to fix axis position (textarea, inputs, scrolls)\n
\t\t\t\tif (this.elementIsWrapper && this.originalElement[0].nodeName.match(/textarea|input|select|button/i)) {\n
\n
\t\t\t\t\taxis = $(this.handles[i], this.element);\n
\n
\t\t\t\t\t//Checking the correct pad and border\n
\t\t\t\t\tpadWrapper = /sw|ne|nw|se|n|s/.test(i) ? axis.outerHeight() : axis.outerWidth();\n
\n
\t\t\t\t\t//The padding type i have to apply...\n
\t\t\t\t\tpadPos = [ "padding",\n
\t\t\t\t\t\t/ne|nw|n/.test(i) ? "Top" :\n
\t\t\t\t\t\t/se|sw|s/.test(i) ? "Bottom" :\n
\t\t\t\t\t\t/^e$/.test(i) ? "Right" : "Left" ].join("");\n
\n
\t\t\t\t\ttarget.css(padPos, padWrapper);\n
\n
\t\t\t\t\tthis._proportionallyResize();\n
\n
\t\t\t\t}\n
\n
\t\t\t\t//TODO: What\'s that good for? There\'s not anything to be executed left\n
\t\t\t\tif(!$(this.handles[i]).length) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\n
\t\t//TODO: make renderAxis a prototype function\n
\t\tthis._renderAxis(this.element);\n
\n
\t\tthis._handles = $(".ui-resizable-handle", this.element)\n
\t\t\t.disableSelection();\n
\n
\t\t//Matching axis name\n
\t\tthis._handles.mouseover(function() {\n
\t\t\tif (!that.resizing) {\n
\t\t\t\tif (this.className) {\n
\t\t\t\t\taxis = this.className.match(/ui-resizable-(se|sw|ne|nw|n|e|s|w)/i);\n
\t\t\t\t}\n
\t\t\t\t//Axis, default = se\n
\t\t\t\tthat.axis = axis && axis[1] ? axis[1] : "se";\n
\t\t\t}\n
\t\t});\n
\n
\t\t//If we want to auto hide the elements\n
\t\tif (o.autoHide) {\n
\t\t\tthis._handles.hide();\n
\t\t\t$(this.element)\n
\t\t\t\t.addClass("ui-resizable-autohide")\n
\t\t\t\t.mouseenter(function() {\n
\t\t\t\t\tif (o.disabled) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\t$(this).removeClass("ui-resizable-autohide");\n
\t\t\t\t\tthat._handles.show();\n
\t\t\t\t})\n
\t\t\t\t.mouseleave(function(){\n
\t\t\t\t\tif (o.disabled) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (!that.resizing) {\n
\t\t\t\t\t\t$(this).addClass("ui-resizable-autohide");\n
\t\t\t\t\t\tthat._handles.hide();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t}\n
\n
\t\t//Initialize the mouse interaction\n
\t\tthis._mouseInit();\n
\n
\t},\n
\n
\t_destroy: function() {\n
\n
\t\tthis._mouseDestroy();\n
\n
\t\tvar wrapper,\n
\t\t\t_destroy = function(exp) {\n
\t\t\t\t$(exp).removeClass("ui-resizable ui-resizable-disabled ui-resizable-resizing")\n
\t\t\t\t\t.removeData("resizable").removeData("ui-resizable").unbind(".resizable").find(".ui-resizable-handle").remove();\n
\t\t\t};\n
\n
\t\t//TODO: Unwrap at same DOM position\n
\t\tif (this.elementIsWrapper) {\n
\t\t\t_destroy(this.element);\n
\t\t\twrapper = this.element;\n
\t\t\tthis.originalElement.css({\n
\t\t\t\tposition: wrapper.css("position"),\n
\t\t\t\twidth: wrapper.outerWidth(),\n
\t\t\t\theight: wrapper.outerHeight(),\n
\t\t\t\ttop: wrapper.css("top"),\n
\t\t\t\tleft: wrapper.css("left")\n
\t\t\t}).insertAfter( wrapper );\n
\t\t\twrapper.remove();\n
\t\t}\n
\n
\t\tthis.originalElement.css("resize", this.originalResizeStyle);\n
\t\t_destroy(this.originalElement);\n
\n
\t\treturn this;\n
\t},\n
\n
\t_mouseCapture: function(event) {\n
\t\tvar i, handle,\n
\t\t\tcapture = false;\n
\n
\t\tfor (i in this.handles) {\n
\t\t\thandle = $(this.handles[i])[0];\n
\t\t\tif (handle === event.target || $.contains(handle, event.target)) {\n
\t\t\t\tcapture = true;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn !this.options.disabled && capture;\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\n
\t\tvar curleft, curtop, cursor,\n
\t\t\to = this.options,\n
\t\t\tiniPos = this.element.position(),\n
\t\t\tel = this.element;\n
\n
\t\tthis.resizing = true;\n
\n
\t\t// bugfix for http://dev.jquery.com/ticket/1749\n
\t\tif ( (/absolute/).test( el.css("position") ) ) {\n
\t\t\tel.css({ position: "absolute", top: el.css("top"), left: el.css("left") });\n
\t\t} else if (el.is(".ui-draggable")) {\n
\t\t\tel.css({ position: "absolute", top: iniPos.top, left: iniPos.left });\n
\t\t}\n
\n
\t\tthis._renderProxy();\n
\n
\t\tcurleft = num(this.helper.css("left"));\n
\t\tcurtop = num(this.helper.css("top"));\n
\n
\t\tif (o.containment) {\n
\t\t\tcurleft += $(o.containment).scrollLeft() || 0;\n
\t\t\tcurtop += $(o.containment).scrollTop() || 0;\n
\t\t}\n
\n
\t\t//Store needed variables\n
\t\tthis.offset = this.helper.offset();\n
\t\tthis.position = { left: curleft, top: curtop };\n
\t\tthis.size = this._helper ? { width: this.helper.width(), height: this.helper.height() } : { width: el.width(), height: el.height() };\n
\t\tthis.originalSize = this._helper ? { width: el.outerWidth(), height: el.outerHeight() } : { width: el.width(), height: el.height() };\n
\t\tthis.originalPosition = { left: curleft, top: curtop };\n
\t\tthis.sizeDiff = { width: el.outerWidth() - el.width(), height: el.outerHeight() - el.height() };\n
\t\tthis.originalMousePosition = { left: event.pageX, top: event.pageY };\n
\n
\t\t//Aspect Ratio\n
\t\tthis.aspectRatio = (typeof o.aspectRatio === "number") ? o.aspectRatio : ((this.originalSize.width / this.originalSize.height) || 1);\n
\n
\t\tcursor = $(".ui-resizable-" + this.axis).css("cursor");\n
\t\t$("body").css("cursor", cursor === "auto" ? this.axis + "-resize" : cursor);\n
\n
\t\tel.addClass("ui-resizable-resizing");\n
\t\tthis._propagate("start", event);\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\n
\t\t//Increase performance, avoid regex\n
\t\tvar data,\n
\t\t\tel = this.helper, props = {},\n
\t\t\tsmp = this.originalMousePosition,\n
\t\t\ta = this.axis,\n
\t\t\tprevTop = this.position.top,\n
\t\t\tprevLeft = this.position.left,\n
\t\t\tprevWidth = this.size.width,\n
\t\t\tprevHeight = this.size.height,\n
\t\t\tdx = (event.pageX-smp.left)||0,\n
\t\t\tdy = (event.pageY-smp.top)||0,\n
\t\t\ttrigger = this._change[a];\n
\n
\t\tif (!trigger) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t// Calculate the attrs that will be change\n
\t\tdata = trigger.apply(this, [event, dx, dy]);\n
\n
\t\t// Put this in the mouseDrag handler since the user can start pressing shift while resizing\n
\t\tthis._updateVirtualBoundaries(event.shiftKey);\n
\t\tif (this._aspectRatio || event.shiftKey) {\n
\t\t\tdata = this._updateRatio(data, event);\n
\t\t}\n
\n
\t\tdata = this._respectSize(data, event);\n
\n
\t\tthis._updateCache(data);\n
\n
\t\t// plugins callbacks need to be called first\n
\t\tthis._propagate("resize", event);\n
\n
\t\tif (this.position.top !== prevTop) {\n
\t\t\tprops.top = this.position.top + "px";\n
\t\t}\n
\t\tif (this.position.left !== prevLeft) {\n
\t\t\tprops.left = this.position.left + "px";\n
\t\t}\n
\t\tif (this.size.width !== prevWidth) {\n
\t\t\tprops.width = this.size.width + "px";\n
\t\t}\n
\t\tif (this.size.height !== prevHeight) {\n
\t\t\tprops.height = this.size.height + "px";\n
\t\t}\n
\t\tel.css(props);\n
\n
\t\tif (!this._helper && this._proportionallyResizeElements.length) {\n
\t\t\tthis._proportionallyResize();\n
\t\t}\n
\n
\t\t// Call the user callback if the element was resized\n
\t\tif ( ! $.isEmptyObject(props) ) {\n
\t\t\tthis._trigger("resize", event, this.ui());\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\n
\t\tthis.resizing = false;\n
\t\tvar pr, ista, soffseth, soffsetw, s, left, top,\n
\t\t\to = this.options, that = this;\n
\n
\t\tif(this._helper) {\n
\n
\t\t\tpr = this._proportionallyResizeElements;\n
\t\t\tista = pr.length && (/textarea/i).test(pr[0].nodeName);\n
\t\t\tsoffseth = ista && $.ui.hasScroll(pr[0], "left") /* TODO - jump height */ ? 0 : that.sizeDiff.height;\n
\t\t\tsoffsetw = ista ? 0 : that.sizeDiff.width;\n
\n
\t\t\ts = { width: (that.helper.width()  - soffsetw), height: (that.helper.height() - soffseth) };\n
\t\t\tleft = (parseInt(that.element.css("left"), 10) + (that.position.left - that.originalPosition.left)) || null;\n
\t\t\ttop = (parseInt(that.element.css("top"), 10) + (that.position.top - that.originalPosition.top)) || null;\n
\n
\t\t\tif (!o.animate) {\n
\t\t\t\tthis.element.css($.extend(s, { top: top, left: left }));\n
\t\t\t}\n
\n
\t\t\tthat.helper.height(that.size.height);\n
\t\t\tthat.helper.width(that.size.width);\n
\n
\t\t\tif (this._helper && !o.animate) {\n
\t\t\t\tthis._proportionallyResize();\n
\t\t\t}\n
\t\t}\n
\n
\t\t$("body").css("cursor", "auto");\n
\n
\t\tthis.element.removeClass("ui-resizable-resizing");\n
\n
\t\tthis._propagate("stop", event);\n
\n
\t\tif (this._helper) {\n
\t\t\tthis.helper.remove();\n
\t\t}\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\t_updateVirtualBoundaries: function(forceAspectRatio) {\n
\t\tvar pMinWidth, pMaxWidth, pMinHeight, pMaxHeight, b,\n
\t\t\to = this.options;\n
\n
\t\tb = {\n
\t\t\tminWidth: isNumber(o.minWidth) ? o.minWidth : 0,\n
\t\t\tmaxWidth: isNumber(o.maxWidth) ? o.maxWidth : Infinity,\n
\t\t\tminHeight: isNumber(o.minHeight) ? o.minHeight : 0,\n
\t\t\tmaxHeight: isNumber(o.maxHeight) ? o.maxHeight : Infinity\n
\t\t};\n
\n
\t\tif(this._aspectRatio || forceAspectRatio) {\n
\t\t\t// We want to create an enclosing box whose aspect ration is the requested one\n
\t\t\t// First, compute the "projected" size for each dimension based on the aspect ratio and other dimension\n
\t\t\tpMinWidth = b.minHeight * this.aspectRatio;\n
\t\t\tpMinHeight = b.minWidth / this.aspectRatio;\n
\t\t\tpMaxWidth = b.maxHeight * this.aspectRatio;\n
\t\t\tpMaxHeight = b.maxWidth / this.aspectRatio;\n
\n
\t\t\tif(pMinWidth > b.minWidth) {\n
\t\t\t\tb.minWidth = pMinWidth;\n
\t\t\t}\n
\t\t\tif(pMinHeight > b.minHeight) {\n
\t\t\t\tb.minHeight = pMinHeight;\n
\t\t\t}\n
\t\t\tif(pMaxWidth < b.maxWidth) {\n
\t\t\t\tb.maxWidth = pMaxWidth;\n
\t\t\t}\n
\t\t\tif(pMaxHeight < b.maxHeight) {\n
\t\t\t\tb.maxHeight = pMaxHeight;\n
\t\t\t}\n
\t\t}\n
\t\tthis._vBoundaries = b;\n
\t},\n
\n
\t_updateCache: function(data) {\n
\t\tthis.offset = this.helper.offset();\n
\t\tif (isNumber(data.left)) {\n
\t\t\tthis.position.left = data.left;\n
\t\t}\n
\t\tif (isNumber(data.top)) {\n
\t\t\tthis.position.top = data.top;\n
\t\t}\n
\t\tif (isNumber(data.height)) {\n
\t\t\tthis.size.height = data.height;\n
\t\t}\n
\t\tif (isNumber(data.width)) {\n
\t\t\tthis.size.width = data.width;\n
\t\t}\n
\t},\n
\n
\t_updateRatio: function( data ) {\n
\n
\t\tvar cpos = this.position,\n
\t\t\tcsize = this.size,\n
\t\t\ta = this.axis;\n
\n
\t\tif (isNumber(data.height)) {\n
\t\t\tdata.width = (data.height * this.aspectRatio);\n
\t\t} else if (isNumber(data.width)) {\n
\t\t\tdata.height = (data.width / this.aspectRatio);\n
\t\t}\n
\n
\t\tif (a === "sw") {\n
\t\t\tdata.left = cpos.left + (csize.width - data.width);\n
\t\t\tdata.top = null;\n
\t\t}\n
\t\tif (a === "nw") {\n
\t\t\tdata.top = cpos.top + (csize.height - data.height);\n
\t\t\tdata.left = cpos.left + (csize.width - data.width);\n
\t\t}\n
\n
\t\treturn data;\n
\t},\n
\n
\t_respectSize: function( data ) {\n
\n
\t\tvar o = this._vBoundaries,\n
\t\t\ta = this.axis,\n
\t\t\tismaxw = isNumber(data.width) && o.maxWidth && (o.maxWidth < data.width), ismaxh = isNumber(data.height) && o.maxHeight && (o.maxHeight < data.height),\n
\t\t\tisminw = isNumber(data.width) && o.minWidth && (o.minWidth > data.width), isminh = isNumber(data.height) && o.minHeight && (o.minHeight > data.height),\n
\t\t\tdw = this.originalPosition.left + this.originalSize.width,\n
\t\t\tdh = this.position.top + this.size.height,\n
\t\t\tcw = /sw|nw|w/.test(a), ch = /nw|ne|n/.test(a);\n
\t\tif (isminw) {\n
\t\t\tdata.width = o.minWidth;\n
\t\t}\n
\t\tif (isminh) {\n
\t\t\tdata.height = o.minHeight;\n
\t\t}\n
\t\tif (ismaxw) {\n
\t\t\tdata.width = o.maxWidth;\n
\t\t}\n
\t\tif (ismaxh) {\n
\t\t\tdata.height = o.maxHeight;\n
\t\t}\n
\n
\t\tif (isminw && cw) {\n
\t\t\tdata.left = dw - o.minWidth;\n
\t\t}\n
\t\tif (ismaxw && cw) {\n
\t\t\tdata.left = dw - o.maxWidth;\n
\t\t}\n
\t\tif (isminh && ch) {\n
\t\t\tdata.top = dh - o.minHeight;\n
\t\t}\n
\t\tif (ismaxh && ch) {\n
\t\t\tdata.top = dh - o.maxHeight;\n
\t\t}\n
\n
\t\t// fixing jump error on top/left - bug #2330\n
\t\tif (!data.width && !data.height && !data.left && data.top) {\n
\t\t\tdata.top = null;\n
\t\t} else if (!data.width && !data.height && !data.top && data.left) {\n
\t\t\tdata.left = null;\n
\t\t}\n
\n
\t\treturn data;\n
\t},\n
\n
\t_proportionallyResize: function() {\n
\n
\t\tif (!this._proportionallyResizeElements.length) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar i, j, borders, paddings, prel,\n
\t\t\telement = this.helper || this.element;\n
\n
\t\tfor ( i=0; i < this._proportionallyResizeElements.length; i++) {\n
\n
\t\t\tprel = this._proportionallyResizeElements[i];\n
\n
\t\t\tif (!this.borderDif) {\n
\t\t\t\tthis.borderDif = [];\n
\t\t\t\tborders = [prel.css("borderTopWidth"), prel.css("borderRightWidth"), prel.css("borderBottomWidth"), prel.css("borderLeftWidth")];\n
\t\t\t\tpaddings = [prel.css("paddingTop"), prel.css("paddingRight"), prel.css("paddingBottom"), prel.css("paddingLeft")];\n
\n
\t\t\t\tfor ( j = 0; j < borders.length; j++ ) {\n
\t\t\t\t\tthis.borderDif[ j ] = ( parseInt( borders[ j ], 10 ) || 0 ) + ( parseInt( paddings[ j ], 10 ) || 0 );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tprel.css({\n
\t\t\t\theight: (element.height() - this.borderDif[0] - this.borderDif[2]) || 0,\n
\t\t\t\twidth: (element.width() - this.borderDif[1] - this.borderDif[3]) || 0\n
\t\t\t});\n
\n
\t\t}\n
\n
\t},\n
\n
\t_renderProxy: function() {\n
\n
\t\tvar el = this.element, o = this.options;\n
\t\tthis.elementOffset = el.offset();\n
\n
\t\tif(this._helper) {\n
\n
\t\t\tthis.helper = this.helper || $("<div style=\'overflow:hidden;\'></div>");\n
\n
\t\t\tthis.helper.addClass(this._helper).css({\n
\t\t\t\twidth: this.element.outerWidth() - 1,\n
\t\t\t\theight: this.element.outerHeight() - 1,\n
\t\t\t\tposition: "absolute",\n
\t\t\t\tleft: this.elementOffset.left +"px",\n
\t\t\t\ttop: this.elementOffset.top +"px",\n
\t\t\t\tzIndex: ++o.zIndex //TODO: Don\'t modify option\n
\t\t\t});\n
\n
\t\t\tthis.helper\n
\t\t\t\t.appendTo("body")\n
\t\t\t\t.disableSelection();\n
\n
\t\t} else {\n
\t\t\tthis.helper = this.element;\n
\t\t}\n
\n
\t},\n
\n
\t_change: {\n
\t\te: function(event, dx) {\n
\t\t\treturn { width: this.originalSize.width + dx };\n
\t\t},\n
\t\tw: function(event, dx) {\n
\t\t\tvar cs = this.originalSize, sp = this.originalPosition;\n
\t\t\treturn { left: sp.left + dx, width: cs.width - dx };\n
\t\t},\n
\t\tn: function(event, dx, dy) {\n
\t\t\tvar cs = this.originalSize, sp = this.originalPosition;\n
\t\t\treturn { top: sp.top + dy, height: cs.height - dy };\n
\t\t},\n
\t\ts: function(event, dx, dy) {\n
\t\t\treturn { height: this.originalSize.height + dy };\n
\t\t},\n
\t\tse: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.s.apply(this, arguments), this._change.e.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tsw: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.s.apply(this, arguments), this._change.w.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tne: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.n.apply(this, arguments), this._change.e.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tnw: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.n.apply(this, arguments), this._change.w.apply(this, [event, dx, dy]));\n
\t\t}\n
\t},\n
\n
\t_propagate: function(n, event) {\n
\t\t$.ui.plugin.call(this, n, [event, this.ui()]);\n
\t\t(n !== "resize" && this._trigger(n, event, this.ui()));\n
\t},\n
\n
\tplugins: {},\n
\n
\tui: function() {\n
\t\treturn {\n
\t\t\toriginalElement: this.originalElement,\n
\t\t\telement: this.element,\n
\t\t\thelper: this.helper,\n
\t\t\tposition: this.position,\n
\t\t\tsize: this.size,\n
\t\t\toriginalSize: this.originalSize,\n
\t\t\toriginalPosition: this.originalPosition\n
\t\t};\n
\t}\n
\n
});\n
\n
/*\n
 * Resizable Extensions\n
 */\n
\n
$.ui.plugin.add("resizable", "animate", {\n
\n
\tstop: function( event ) {\n
\t\tvar that = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tpr = that._proportionallyResizeElements,\n
\t\t\tista = pr.length && (/textarea/i).test(pr[0].nodeName),\n
\t\t\tsoffseth = ista && $.ui.hasScroll(pr[0], "left") /* TODO - jump height */ ? 0 : that.sizeDiff.height,\n
\t\t\tsoffsetw = ista ? 0 : that.sizeDiff.width,\n
\t\t\tstyle = { width: (that.size.width - soffsetw), height: (that.size.height - soffseth) },\n
\t\t\tleft = (parseInt(that.element.css("left"), 10) + (that.position.left - that.originalPosition.left)) || null,\n
\t\t\ttop = (parseInt(that.element.css("top"), 10) + (that.position.top - that.originalPosition.top)) || null;\n
\n
\t\tthat.element.animate(\n
\t\t\t$.extend(style, top && left ? { top: top, left: left } : {}), {\n
\t\t\t\tduration: o.animateDuration,\n
\t\t\t\teasing: o.animateEasing,\n
\t\t\t\tstep: function() {\n
\n
\t\t\t\t\tvar data = {\n
\t\t\t\t\t\twidth: parseInt(that.element.css("width"), 10),\n
\t\t\t\t\t\theight: parseInt(that.element.css("height"), 10),\n
\t\t\t\t\t\ttop: parseInt(that.element.css("top"), 10),\n
\t\t\t\t\t\tleft: parseInt(that.element.css("left"), 10)\n
\t\t\t\t\t};\n
\n
\t\t\t\t\tif (pr && pr.length) {\n
\t\t\t\t\t\t$(pr[0]).css({ width: data.width, height: data.height });\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// propagating resize, and updating values for each animation step\n
\t\t\t\t\tthat._updateCache(data);\n
\t\t\t\t\tthat._propagate("resize", event);\n
\n
\t\t\t\t}\n
\t\t\t}\n
\t\t);\n
\t}\n
\n
});\n
\n
$.ui.plugin.add("resizable", "containment", {\n
\n
\tstart: function() {\n
\t\tvar element, p, co, ch, cw, width, height,\n
\t\t\tthat = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tel = that.element,\n
\t\t\toc = o.containment,\n
\t\t\tce = (oc instanceof $) ? oc.get(0) : (/parent/.test(oc)) ? el.parent().get(0) : oc;\n
\n
\t\tif (!ce) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthat.containerElement = $(ce);\n
\n
\t\tif (/document/.test(oc) || oc === document) {\n
\t\t\tthat.containerOffset = { left: 0, top: 0 };\n
\t\t\tthat.containerPosition = { left: 0, top: 0 };\n
\n
\t\t\tthat.parentData = {\n
\t\t\t\telement: $(document), left: 0, top: 0,\n
\t\t\t\twidth: $(document).width(), height: $(document).height() || document.body.parentNode.scrollHeight\n
\t\t\t};\n
\t\t}\n
\n
\t\t// i\'m a node, so compute top, left, right, bottom\n
\t\telse {\n
\t\t\telement = $(ce);\n
\t\t\tp = [];\n
\t\t\t$([ "Top", "Right", "Left", "Bottom" ]).each(function(i, name) { p[i] = num(element.css("padding" + name)); });\n
\n
\t\t\tthat.containerOffset = element.offset();\n
\t\t\tthat.containerPosition = element.position();\n
\t\t\tthat.containerSize = { height: (element.innerHeight() - p[3]), width: (element.innerWidth() - p[1]) };\n
\n
\t\t\tco = that.containerOffset;\n
\t\t\tch = that.containerSize.height;\n
\t\t\tcw = that.containerSize.width;\n
\t\t\twidth = ($.ui.hasScroll(ce, "left") ? ce.scrollWidth : cw );\n
\t\t\theight = ($.ui.hasScroll(ce) ? ce.scrollHeight : ch);\n
\n
\t\t\tthat.parentData = {\n
\t\t\t\telement: ce, left: co.left, top: co.top, width: width, height: height\n
\t\t\t};\n
\t\t}\n
\t},\n
\n
\tresize: function( event ) {\n
\t\tvar woset, hoset, isParent, isOffsetRelative,\n
\t\t\tthat = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tco = that.containerOffset, cp = that.position,\n
\t\t\tpRatio = that._aspectRatio || event.shiftKey,\n
\t\t\tcop = { top:0, left:0 }, ce = that.containerElement;\n
\n
\t\tif (ce[0] !== document && (/static/).test(ce.css("position"))) {\n
\t\t\tcop = co;\n
\t\t}\n
\n
\t\tif (cp.left < (that._helper ? co.left : 0)) {\n
\t\t\tthat.size.width = that.size.width + (that._helper ? (that.position.left - co.left) : (that.position.left - cop.left));\n
\t\t\tif (pRatio) {\n
\t\t\t\tthat.size.height = that.size.width / that.aspectRatio;\n
\t\t\t}\n
\t\t\tthat.position.left = o.helper ? co.left : 0;\n
\t\t}\n
\n
\t\tif (cp.top < (that._helper ? co.top : 0)) {\n
\t\t\tthat.size.height = that.size.height + (that._helper ? (that.position.top - co.top) : that.position.top);\n
\t\t\tif (pRatio) {\n
\t\t\t\tthat.size.width = that.size.height * that.aspectRatio;\n
\t\t\t}\n
\t\t\tthat.position.top = that._helper ? co.top : 0;\n
\t\t}\n
\n
\t\tthat.offset.left = that.parentData.left+that.position.left;\n
\t\tthat.offset.top = that.parentData.top+that.position.top;\n
\n
\t\twoset = Math.abs( (that._helper ? that.offset.left - cop.left : (that.offset.left - cop.left)) + that.sizeDiff.width );\n
\t\thoset = Math.abs( (that._helper ? that.offset.top - cop.top : (that.offset.top - co.top)) + that.sizeDiff.height );\n
\n
\t\tisParent = that.containerElement.get(0) === that.element.parent().get(0);\n
\t\tisOffsetRelative = /relative|absolute/.test(that.containerElement.css("position"));\n
\n
\t\tif ( isParent && isOffsetRelative ) {\n
\t\t\twoset -= Math.abs( that.parentData.left );\n
\t\t}\n
\n
\t\tif (woset + that.size.width >= that.parentData.width) {\n
\t\t\tthat.size.width = that.parentData.width - woset;\n
\t\t\tif (pRatio) {\n
\t\t\t\tthat.size.height = that.size.width / that.aspectRatio;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (hoset + that.size.height >= that.parentData.height) {\n
\t\t\tthat.size.height = that.parentData.height - hoset;\n
\t\t\tif (pRatio) {\n
\t\t\t\tthat.size.width = that.size.height * that.aspectRatio;\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tstop: function(){\n
\t\tvar that = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tco = that.containerOffset,\n
\t\t\tcop = that.containerPosition,\n
\t\t\tce = that.containerElement,\n
\t\t\thelper = $(that.helper),\n
\t\t\tho = helper.offset(),\n
\t\t\tw = helper.outerWidth() - that.sizeDiff.width,\n
\t\t\th = helper.outerHeight() - that.sizeDiff.height;\n
\n
\t\tif (that._helper && !o.animate && (/relative/).test(ce.css("position"))) {\n
\t\t\t$(this).css({ left: ho.left - cop.left - co.left, width: w, height: h });\n
\t\t}\n
\n
\t\tif (that._helper && !o.animate && (/static/).test(ce.css("position"))) {\n
\t\t\t$(this).css({ left: ho.left - cop.left - co.left, width: w, height: h });\n
\t\t}\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("resizable", "alsoResize", {\n
\n
\tstart: function () {\n
\t\tvar that = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\t_store = function (exp) {\n
\t\t\t\t$(exp).each(function() {\n
\t\t\t\t\tvar el = $(this);\n
\t\t\t\t\tel.data("ui-resizable-alsoresize", {\n
\t\t\t\t\t\twidth: parseInt(el.width(), 10), height: parseInt(el.height(), 10),\n
\t\t\t\t\t\tleft: parseInt(el.css("left"), 10), top: parseInt(el.css("top"), 10)\n
\t\t\t\t\t});\n
\t\t\t\t});\n
\t\t\t};\n
\n
\t\tif (typeof(o.alsoResize) === "object" && !o.alsoResize.parentNode) {\n
\t\t\tif (o.alsoResize.length) { o.alsoResize = o.alsoResize[0]; _store(o.alsoResize); }\n
\t\t\telse { $.each(o.alsoResize, function (exp) { _store(exp); }); }\n
\t\t}else{\n
\t\t\t_store(o.alsoResize);\n
\t\t}\n
\t},\n
\n
\tresize: function (event, ui) {\n
\t\tvar that = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tos = that.originalSize,\n
\t\t\top = that.originalPosition,\n
\t\t\tdelta = {\n
\t\t\t\theight: (that.size.height - os.height) || 0, width: (that.size.width - os.width) || 0,\n
\t\t\t\ttop: (that.position.top - op.top) || 0, left: (that.position.left - op.left) || 0\n
\t\t\t},\n
\n
\t\t\t_alsoResize = function (exp, c) {\n
\t\t\t\t$(exp).each(function() {\n
\t\t\t\t\tvar el = $(this), start = $(this).data("ui-resizable-alsoresize"), style = {},\n
\t\t\t\t\t\tcss = c && c.length ? c : el.parents(ui.originalElement[0]).length ? ["width", "height"] : ["width", "height", "top", "left"];\n
\n
\t\t\t\t\t$.each(css, function (i, prop) {\n
\t\t\t\t\t\tvar sum = (start[prop]||0) + (delta[prop]||0);\n
\t\t\t\t\t\tif (sum && sum >= 0) {\n
\t\t\t\t\t\t\tstyle[prop] = sum || null;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\n
\t\t\t\t\tel.css(style);\n
\t\t\t\t});\n
\t\t\t};\n
\n
\t\tif (typeof(o.alsoResize) === "object" && !o.alsoResize.nodeType) {\n
\t\t\t$.each(o.alsoResize, function (exp, c) { _alsoResize(exp, c); });\n
\t\t}else{\n
\t\t\t_alsoResize(o.alsoResize);\n
\t\t}\n
\t},\n
\n
\tstop: function () {\n
\t\t$(this).removeData("resizable-alsoresize");\n
\t}\n
});\n
\n
$.ui.plugin.add("resizable", "ghost", {\n
\n
\tstart: function() {\n
\n
\t\tvar that = $(this).data("ui-resizable"), o = that.options, cs = that.size;\n
\n
\t\tthat.ghost = that.originalElement.clone();\n
\t\tthat.ghost\n
\t\t\t.css({ opacity: 0.25, display: "block", position: "relative", height: cs.height, width: cs.width, margin: 0, left: 0, top: 0 })\n
\t\t\t.addClass("ui-resizable-ghost")\n
\t\t\t.addClass(typeof o.ghost === "string" ? o.ghost : "");\n
\n
\t\tthat.ghost.appendTo(that.helper);\n
\n
\t},\n
\n
\tresize: function(){\n
\t\tvar that = $(this).data("ui-resizable");\n
\t\tif (that.ghost) {\n
\t\t\tthat.ghost.css({ position: "relative", height: that.size.height, width: that.size.width });\n
\t\t}\n
\t},\n
\n
\tstop: function() {\n
\t\tvar that = $(this).data("ui-resizable");\n
\t\tif (that.ghost && that.helper) {\n
\t\t\tthat.helper.get(0).removeChild(that.ghost.get(0));\n
\t\t}\n
\t}\n
\n
});\n
\n
$.ui.plugin.add("resizable", "grid", {\n
\n
\tresize: function() {\n
\t\tvar that = $(this).data("ui-resizable"),\n
\t\t\to = that.options,\n
\t\t\tcs = that.size,\n
\t\t\tos = that.originalSize,\n
\t\t\top = that.originalPosition,\n
\t\t\ta = that.axis,\n
\t\t\tgrid = typeof o.grid === "number" ? [o.grid, o.grid] : o.grid,\n
\t\t\tgridX = (grid[0]||1),\n
\t\t\tgridY = (grid[1]||1),\n
\t\t\tox = Math.round((cs.width - os.width) / gridX) * gridX,\n
\t\t\toy = Math.round((cs.height - os.height) / gridY) * gridY,\n
\t\t\tnewWidth = os.width + ox,\n
\t\t\tnewHeight = os.height + oy,\n
\t\t\tisMaxWidth = o.maxWidth && (o.maxWidth < newWidth),\n
\t\t\tisMaxHeight = o.maxHeight && (o.maxHeight < newHeight),\n
\t\t\tisMinWidth = o.minWidth && (o.minWidth > newWidth),\n
\t\t\tisMinHeight = o.minHeight && (o.minHeight > newHeight);\n
\n
\t\to.grid = grid;\n
\n
\t\tif (isMinWidth) {\n
\t\t\tnewWidth = newWidth + gridX;\n
\t\t}\n
\t\tif (isMinHeight) {\n
\t\t\tnewHeight = newHeight + gridY;\n
\t\t}\n
\t\tif (isMaxWidth) {\n
\t\t\tnewWidth = newWidth - gridX;\n
\t\t}\n
\t\tif (isMaxHeight) {\n
\t\t\tnewHeight = newHeight - gridY;\n
\t\t}\n
\n
\t\tif (/^(se|s|e)$/.test(a)) {\n
\t\t\tthat.size.width = newWidth;\n
\t\t\tthat.size.height = newHeight;\n
\t\t} else if (/^(ne)$/.test(a)) {\n
\t\t\tthat.size.width = newWidth;\n
\t\t\tthat.size.height = newHeight;\n
\t\t\tthat.position.top = op.top - oy;\n
\t\t} else if (/^(sw)$/.test(a)) {\n
\t\t\tthat.size.width = newWidth;\n
\t\t\tthat.size.height = newHeight;\n
\t\t\tthat.position.left = op.left - ox;\n
\t\t} else {\n
\t\t\tif ( newHeight - gridY > 0 ) {\n
\t\t\t\tthat.size.height = newHeight;\n
\t\t\t\tthat.position.top = op.top - oy;\n
\t\t\t} else {\n
\t\t\t\tthat.size.height = gridY;\n
\t\t\t\tthat.position.top = op.top + os.height - gridY;\n
\t\t\t}\n
\t\t\tif ( newWidth - gridX > 0 ) {\n
\t\t\t\tthat.size.width = newWidth;\n
\t\t\t\tthat.position.left = op.left - ox;\n
\t\t\t} else {\n
\t\t\t\tthat.size.width = gridX;\n
\t\t\t\tthat.position.left = op.left + os.width - gridX;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
});\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.widget("ui.selectable", $.ui.mouse, {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tappendTo: "body",\n
\t\tautoRefresh: true,\n
\t\tdistance: 0,\n
\t\tfilter: "*",\n
\t\ttolerance: "touch",\n
\n
\t\t// callbacks\n
\t\tselected: null,\n
\t\tselecting: null,\n
\t\tstart: null,\n
\t\tstop: null,\n
\t\tunselected: null,\n
\t\tunselecting: null\n
\t},\n
\t_create: function() {\n
\t\tvar selectees,\n
\t\t\tthat = this;\n
\n
\t\tthis.element.addClass("ui-selectable");\n
\n
\t\tthis.dragged = false;\n
\n
\t\t// cache selectee children based on filter\n
\t\tthis.refresh = function() {\n
\t\t\tselectees = $(that.options.filter, that.element[0]);\n
\t\t\tselectees.addClass("ui-selectee");\n
\t\t\tselectees.each(function() {\n
\t\t\t\tvar $this = $(this),\n
\t\t\t\t\tpos = $this.offset();\n
\t\t\t\t$.data(this, "selectable-item", {\n
\t\t\t\t\telement: this,\n
\t\t\t\t\t$element: $this,\n
\t\t\t\t\tleft: pos.left,\n
\t\t\t\t\ttop: pos.top,\n
\t\t\t\t\tright: pos.left + $this.outerWidth(),\n
\t\t\t\t\tbottom: pos.top + $this.outerHeight(),\n
\t\t\t\t\tstartselected: false,\n
\t\t\t\t\tselected: $this.hasClass("ui-selected"),\n
\t\t\t\t\tselecting: $this.hasClass("ui-selecting"),\n
\t\t\t\t\tunselecting: $this.hasClass("ui-unselecting")\n
\t\t\t\t});\n
\t\t\t});\n
\t\t};\n
\t\tthis.refresh();\n
\n
\t\tthis.selectees = selectees.addClass("ui-selectee");\n
\n
\t\tthis._mouseInit();\n
\n
\t\tthis.helper = $("<div class=\'ui-selectable-helper\'></div>");\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.selectees\n
\t\t\t.removeClass("ui-selectee")\n
\t\t\t.removeData("selectable-item");\n
\t\tthis.element\n
\t\t\t.removeClass("ui-selectable ui-selectable-disabled");\n
\t\tthis._mouseDestroy();\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\t\tvar that = this,\n
\t\t\toptions = this.options;\n
\n
\t\tthis.opos = [event.pageX, event.pageY];\n
\n
\t\tif (this.options.disabled) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.selectees = $(options.filter, this.element[0]);\n
\n
\t\tthis._trigger("start", event);\n
\n
\t\t$(options.appendTo).append(this.helper);\n
\t\t// position helper (lasso)\n
\t\tthis.helper.css({\n
\t\t\t"left": event.pageX,\n
\t\t\t"top": event.pageY,\n
\t\t\t"width": 0,\n
\t\t\t"height": 0\n
\t\t});\n
\n
\t\tif (options.autoRefresh) {\n
\t\t\tthis.refresh();\n
\t\t}\n
\n
\t\tthis.selectees.filter(".ui-selected").each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.startselected = true;\n
\t\t\tif (!event.metaKey && !event.ctrlKey) {\n
\t\t\t\tselectee.$element.removeClass("ui-selected");\n
\t\t\t\tselectee.selected = false;\n
\t\t\t\tselectee.$element.addClass("ui-unselecting");\n
\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\tthat._trigger("unselecting", event, {\n
\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t});\n
\t\t\t}\n
\t\t});\n
\n
\t\t$(event.target).parents().addBack().each(function() {\n
\t\t\tvar doSelect,\n
\t\t\t\tselectee = $.data(this, "selectable-item");\n
\t\t\tif (selectee) {\n
\t\t\t\tdoSelect = (!event.metaKey && !event.ctrlKey) || !selectee.$element.hasClass("ui-selected");\n
\t\t\t\tselectee.$element\n
\t\t\t\t\t.removeClass(doSelect ? "ui-unselecting" : "ui-selected")\n
\t\t\t\t\t.addClass(doSelect ? "ui-selecting" : "ui-unselecting");\n
\t\t\t\tselectee.unselecting = !doSelect;\n
\t\t\t\tselectee.selecting = doSelect;\n
\t\t\t\tselectee.selected = doSelect;\n
\t\t\t\t// selectable (UN)SELECTING callback\n
\t\t\t\tif (doSelect) {\n
\t\t\t\t\tthat._trigger("selecting", event, {\n
\t\t\t\t\t\tselecting: selectee.element\n
\t\t\t\t\t});\n
\t\t\t\t} else {\n
\t\t\t\t\tthat._trigger("unselecting", event, {\n
\t\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\n
\t\tthis.dragged = true;\n
\n
\t\tif (this.options.disabled) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar tmp,\n
\t\t\tthat = this,\n
\t\t\toptions = this.options,\n
\t\t\tx1 = this.opos[0],\n
\t\t\ty1 = this.opos[1],\n
\t\t\tx2 = event.pageX,\n
\t\t\ty2 = event.pageY;\n
\n
\t\tif (x1 > x2) { tmp = x2; x2 = x1; x1 = tmp; }\n
\t\tif (y1 > y2) { tmp = y2; y2 = y1; y1 = tmp; }\n
\t\tthis.helper.css({left: x1, top: y1, width: x2-x1, height: y2-y1});\n
\n
\t\tthis.selectees.each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item"),\n
\t\t\t\thit = false;\n
\n
\t\t\t//prevent helper from being selected if appendTo: selectable\n
\t\t\tif (!selectee || selectee.element === that.element[0]) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif (options.tolerance === "touch") {\n
\t\t\t\thit = ( !(selectee.left > x2 || selectee.right < x1 || selectee.top > y2 || selectee.bottom < y1) );\n
\t\t\t} else if (options.tolerance === "fit") {\n
\t\t\t\thit = (selectee.left > x1 && selectee.right < x2 && selectee.top > y1 && selectee.bottom < y2);\n
\t\t\t}\n
\n
\t\t\tif (hit) {\n
\t\t\t\t// SELECT\n
\t\t\t\tif (selectee.selected) {\n
\t\t\t\t\tselectee.$element.removeClass("ui-selected");\n
\t\t\t\t\tselectee.selected = false;\n
\t\t\t\t}\n
\t\t\t\tif (selectee.unselecting) {\n
\t\t\t\t\tselectee.$element.removeClass("ui-unselecting");\n
\t\t\t\t\tselectee.unselecting = false;\n
\t\t\t\t}\n
\t\t\t\tif (!selectee.selecting) {\n
\t\t\t\t\tselectee.$element.addClass("ui-selecting");\n
\t\t\t\t\tselectee.selecting = true;\n
\t\t\t\t\t// selectable SELECTING callback\n
\t\t\t\t\tthat._trigger("selecting", event, {\n
\t\t\t\t\t\tselecting: selectee.element\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\t// UNSELECT\n
\t\t\t\tif (selectee.selecting) {\n
\t\t\t\t\tif ((event.metaKey || event.ctrlKey) && selectee.startselected) {\n
\t\t\t\t\t\tselectee.$element.removeClass("ui-selecting");\n
\t\t\t\t\t\tselectee.selecting = false;\n
\t\t\t\t\t\tselectee.$element.addClass("ui-selected");\n
\t\t\t\t\t\tselectee.selected = true;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tselectee.$element.removeClass("ui-selecting");\n
\t\t\t\t\t\tselectee.selecting = false;\n
\t\t\t\t\t\tif (selectee.startselected) {\n
\t\t\t\t\t\t\tselectee.$element.addClass("ui-unselecting");\n
\t\t\t\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\t\t\tthat._trigger("unselecting", event, {\n
\t\t\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tif (selectee.selected) {\n
\t\t\t\t\tif (!event.metaKey && !event.ctrlKey && !selectee.startselected) {\n
\t\t\t\t\t\tselectee.$element.removeClass("ui-selected");\n
\t\t\t\t\t\tselectee.selected = false;\n
\n
\t\t\t\t\t\tselectee.$element.addClass("ui-unselecting");\n
\t\t\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\t\t\tthat._trigger("unselecting", event, {\n
\t\t\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\t\tvar that = this;\n
\n
\t\tthis.dragged = false;\n
\n
\t\t$(".ui-unselecting", this.element[0]).each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.$element.removeClass("ui-unselecting");\n
\t\t\tselectee.unselecting = false;\n
\t\t\tselectee.startselected = false;\n
\t\t\tthat._trigger("unselected", event, {\n
\t\t\t\tunselected: selectee.element\n
\t\t\t});\n
\t\t});\n
\t\t$(".ui-selecting", this.element[0]).each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.$element.removeClass("ui-selecting").addClass("ui-selected");\n
\t\t\tselectee.selecting = false;\n
\t\t\tselectee.selected = true;\n
\t\t\tselectee.startselected = true;\n
\t\t\tthat._trigger("selected", event, {\n
\t\t\t\tselected: selectee.element\n
\t\t\t});\n
\t\t});\n
\t\tthis._trigger("stop", event);\n
\n
\t\tthis.helper.remove();\n
\n
\t\treturn false;\n
\t}\n
\n
});\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
function isOverAxis( x, reference, size ) {\n
\treturn ( x > reference ) && ( x < ( reference + size ) );\n
}\n
\n
function isFloating(item) {\n
\treturn (/left|right/).test(item.css("float")) || (/inline|table-cell/).test(item.css("display"));\n
}\n
\n
$.widget("ui.sortable", $.ui.mouse, {\n
\tversion: "1.10.4",\n
\twidgetEventPrefix: "sort",\n
\tready: false,\n
\toptions: {\n
\t\tappendTo: "parent",\n
\t\taxis: false,\n
\t\tconnectWith: false,\n
\t\tcontainment: false,\n
\t\tcursor: "auto",\n
\t\tcursorAt: false,\n
\t\tdropOnEmpty: true,\n
\t\tforcePlaceholderSize: false,\n
\t\tforceHelperSize: false,\n
\t\tgrid: false,\n
\t\thandle: false,\n
\t\thelper: "original",\n
\t\titems: "> *",\n
\t\topacity: false,\n
\t\tplaceholder: false,\n
\t\trevert: false,\n
\t\tscroll: true,\n
\t\tscrollSensitivity: 20,\n
\t\tscrollSpeed: 20,\n
\t\tscope: "default",\n
\t\ttolerance: "intersect",\n
\t\tzIndex: 1000,\n
\n
\t\t// callbacks\n
\t\tactivate: null,\n
\t\tbeforeStop: null,\n
\t\tchange: null,\n
\t\tdeactivate: null,\n
\t\tout: null,\n
\t\tover: null,\n
\t\treceive: null,\n
\t\tremove: null,\n
\t\tsort: null,\n
\t\tstart: null,\n
\t\tstop: null,\n
\t\tupdate: null\n
\t},\n
\t_create: function() {\n
\n
\t\tvar o = this.options;\n
\t\tthis.containerCache = {};\n
\t\tthis.element.addClass("ui-sortable");\n
\n
\t\t//Get the items\n
\t\tthis.refresh();\n
\n
\t\t//Let\'s determine if the items are being displayed horizontally\n
\t\tthis.floating = this.items.length ? o.axis === "x" || isFloating(this.items[0].item) : false;\n
\n
\t\t//Let\'s determine the parent\'s offset\n
\t\tthis.offset = this.element.offset();\n
\n
\t\t//Initialize mouse events for interaction\n
\t\tthis._mouseInit();\n
\n
\t\t//We\'re ready to go\n
\t\tthis.ready = true;\n
\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass("ui-sortable ui-sortable-disabled");\n
\t\tthis._mouseDestroy();\n
\n
\t\tfor ( var i = this.items.length - 1; i >= 0; i-- ) {\n
\t\t\tthis.items[i].item.removeData(this.widgetName + "-item");\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\t_setOption: function(key, value){\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.options[ key ] = value;\n
\n
\t\t\tthis.widget().toggleClass( "ui-sortable-disabled", !!value );\n
\t\t} else {\n
\t\t\t// Don\'t call widget base _setOption for disable as it adds ui-state-disabled class\n
\t\t\t$.Widget.prototype._setOption.apply(this, arguments);\n
\t\t}\n
\t},\n
\n
\t_mouseCapture: function(event, overrideHandle) {\n
\t\tvar currentItem = null,\n
\t\t\tvalidHandle = false,\n
\t\t\tthat = this;\n
\n
\t\tif (this.reverting) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif(this.options.disabled || this.options.type === "static") {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t//We have to refresh the items data once first\n
\t\tthis._refreshItems(event);\n
\n
\t\t//Find out if the clicked node (or one of its parents) is a actual item in this.items\n
\t\t$(event.target).parents().each(function() {\n
\t\t\tif($.data(this, that.widgetName + "-item") === that) {\n
\t\t\t\tcurrentItem = $(this);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t});\n
\t\tif($.data(event.target, that.widgetName + "-item") === that) {\n
\t\t\tcurrentItem = $(event.target);\n
\t\t}\n
\n
\t\tif(!currentItem) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tif(this.options.handle && !overrideHandle) {\n
\t\t\t$(this.options.handle, currentItem).find("*").addBack().each(function() {\n
\t\t\t\tif(this === event.target) {\n
\t\t\t\t\tvalidHandle = true;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\tif(!validHandle) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.currentItem = currentItem;\n
\t\tthis._removeCurrentsFromItems();\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseStart: function(event, overrideHandle, noActivation) {\n
\n
\t\tvar i, body,\n
\t\t\to = this.options;\n
\n
\t\tthis.currentContainer = this;\n
\n
\t\t//We only need to call refreshPositions, because the refreshItems call has been moved to mouseCapture\n
\t\tthis.refreshPositions();\n
\n
\t\t//Create and append the visible helper\n
\t\tthis.helper = this._createHelper(event);\n
\n
\t\t//Cache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t/*\n
\t\t * - Position generation -\n
\t\t * This block generates everything position related - it\'s the core of draggables.\n
\t\t */\n
\n
\t\t//Cache the margins of the original element\n
\t\tthis._cacheMargins();\n
\n
\t\t//Get the next scrolling parent\n
\t\tthis.scrollParent = this.helper.scrollParent();\n
\n
\t\t//The element\'s absolute position on the page minus margins\n
\t\tthis.offset = this.currentItem.offset();\n
\t\tthis.offset = {\n
\t\t\ttop: this.offset.top - this.margins.top,\n
\t\t\tleft: this.offset.left - this.margins.left\n
\t\t};\n
\n
\t\t$.extend(this.offset, {\n
\t\t\tclick: { //Where the click happened, relative to the element\n
\t\t\t\tleft: event.pageX - this.offset.left,\n
\t\t\t\ttop: event.pageY - this.offset.top\n
\t\t\t},\n
\t\t\tparent: this._getParentOffset(),\n
\t\t\trelative: this._getRelativeOffset() //This is a relative to absolute position minus the actual position calculation - only used for relative positioned helper\n
\t\t});\n
\n
\t\t// Only after we got the offset, we can change the helper\'s position to absolute\n
\t\t// TODO: Still need to figure out a way to make relative sorting possible\n
\t\tthis.helper.css("position", "absolute");\n
\t\tthis.cssPosition = this.helper.css("position");\n
\n
\t\t//Generate the original position\n
\t\tthis.originalPosition = this._generatePosition(event);\n
\t\tthis.originalPageX = event.pageX;\n
\t\tthis.originalPageY = event.pageY;\n
\n
\t\t//Adjust the mouse offset relative to the helper if "cursorAt" is supplied\n
\t\t(o.cursorAt && this._adjustOffsetFromHelper(o.cursorAt));\n
\n
\t\t//Cache the former DOM position\n
\t\tthis.domPosition = { prev: this.currentItem.prev()[0], parent: this.currentItem.parent()[0] };\n
\n
\t\t//If the helper is not the original, hide the original so it\'s not playing any role during the drag, won\'t cause anything bad this way\n
\t\tif(this.helper[0] !== this.currentItem[0]) {\n
\t\t\tthis.currentItem.hide();\n
\t\t}\n
\n
\t\t//Create the placeholder\n
\t\tthis._createPlaceholder();\n
\n
\t\t//Set a containment if given in the options\n
\t\tif(o.containment) {\n
\t\t\tthis._setContainment();\n
\t\t}\n
\n
\t\tif( o.cursor && o.cursor !== "auto" ) { // cursor option\n
\t\t\tbody = this.document.find( "body" );\n
\n
\t\t\t// support: IE\n
\t\t\tthis.storedCursor = body.css( "cursor" );\n
\t\t\tbody.css( "cursor", o.cursor );\n
\n
\t\t\tthis.storedStylesheet = $( "<style>*{ cursor: "+o.cursor+" !important; }</style>" ).appendTo( body );\n
\t\t}\n
\n
\t\tif(o.opacity) { // opacity option\n
\t\t\tif (this.helper.css("opacity")) {\n
\t\t\t\tthis._storedOpacity = this.helper.css("opacity");\n
\t\t\t}\n
\t\t\tthis.helper.css("opacity", o.opacity);\n
\t\t}\n
\n
\t\tif(o.zIndex) { // zIndex option\n
\t\t\tif (this.helper.css("zIndex")) {\n
\t\t\t\tthis._storedZIndex = this.helper.css("zIndex");\n
\t\t\t}\n
\t\t\tthis.helper.css("zIndex", o.zIndex);\n
\t\t}\n
\n
\t\t//Prepare scrolling\n
\t\tif(this.scrollParent[0] !== document && this.scrollParent[0].tagName !== "HTML") {\n
\t\t\tthis.overflowOffset = this.scrollParent.offset();\n
\t\t}\n
\n
\t\t//Call callbacks\n
\t\tthis._trigger("start", event, this._uiHash());\n
\n
\t\t//Recache the helper size\n
\t\tif(!this._preserveHelperProportions) {\n
\t\t\tthis._cacheHelperProportions();\n
\t\t}\n
\n
\n
\t\t//Post "activate" events to possible containers\n
\t\tif( !noActivation ) {\n
\t\t\tfor ( i = this.containers.length - 1; i >= 0; i-- ) {\n
\t\t\t\tthis.containers[ i ]._trigger( "activate", event, this._uiHash( this ) );\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Prepare possible droppables\n
\t\tif($.ui.ddmanager) {\n
\t\t\t$.ui.ddmanager.current = this;\n
\t\t}\n
\n
\t\tif ($.ui.ddmanager && !o.dropBehaviour) {\n
\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\t\t}\n
\n
\t\tthis.dragging = true;\n
\n
\t\tthis.helper.addClass("ui-sortable-helper");\n
\t\tthis._mouseDrag(event); //Execute the drag once - this causes the helper not to be visible before getting its correct position\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\t\tvar i, item, itemElement, intersection,\n
\t\t\to = this.options,\n
\t\t\tscrolled = false;\n
\n
\t\t//Compute the helpers position\n
\t\tthis.position = this._generatePosition(event);\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\tif (!this.lastPositionAbs) {\n
\t\t\tthis.lastPositionAbs = this.positionAbs;\n
\t\t}\n
\n
\t\t//Do scrolling\n
\t\tif(this.options.scroll) {\n
\t\t\tif(this.scrollParent[0] !== document && this.scrollParent[0].tagName !== "HTML") {\n
\n
\t\t\t\tif((this.overflowOffset.top + this.scrollParent[0].offsetHeight) - event.pageY < o.scrollSensitivity) {\n
\t\t\t\t\tthis.scrollParent[0].scrollTop = scrolled = this.scrollParent[0].scrollTop + o.scrollSpeed;\n
\t\t\t\t} else if(event.pageY - this.overflowOffset.top < o.scrollSensitivity) {\n
\t\t\t\t\tthis.scrollParent[0].scrollTop = scrolled = this.scrollParent[0].scrollTop - o.scrollSpeed;\n
\t\t\t\t}\n
\n
\t\t\t\tif((this.overflowOffset.left + this.scrollParent[0].offsetWidth) - event.pageX < o.scrollSensitivity) {\n
\t\t\t\t\tthis.scrollParent[0].scrollLeft = scrolled = this.scrollParent[0].scrollLeft + o.scrollSpeed;\n
\t\t\t\t} else if(event.pageX - this.overflowOffset.left < o.scrollSensitivity) {\n
\t\t\t\t\tthis.scrollParent[0].scrollLeft = scrolled = this.scrollParent[0].scrollLeft - o.scrollSpeed;\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\n
\t\t\t\tif(event.pageY - $(document).scrollTop() < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() - o.scrollSpeed);\n
\t\t\t\t} else if($(window).height() - (event.pageY - $(document).scrollTop()) < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() + o.scrollSpeed);\n
\t\t\t\t}\n
\n
\t\t\t\tif(event.pageX - $(document).scrollLeft() < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() - o.scrollSpeed);\n
\t\t\t\t} else if($(window).width() - (event.pageX - $(document).scrollLeft()) < o.scrollSensitivity) {\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() + o.scrollSpeed);\n
\t\t\t\t}\n
\n
\t\t\t}\n
\n
\t\t\tif(scrolled !== false && $.ui.ddmanager && !o.dropBehaviour) {\n
\t\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Regenerate the absolute position used for position checks\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\t//Set the helper position\n
\t\tif(!this.options.axis || this.options.axis !== "y") {\n
\t\t\tthis.helper[0].style.left = this.position.left+"px";\n
\t\t}\n
\t\tif(!this.options.axis || this.options.axis !== "x") {\n
\t\t\tthis.helper[0].style.top = this.position.top+"px";\n
\t\t}\n
\n
\t\t//Rearrange\n
\t\tfor (i = this.items.length - 1; i >= 0; i--) {\n
\n
\t\t\t//Cache variables and intersection, continue if no intersection\n
\t\t\titem = this.items[i];\n
\t\t\titemElement = item.item[0];\n
\t\t\tintersection = this._intersectsWithPointer(item);\n
\t\t\tif (!intersection) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t// Only put the placeholder inside the current Container, skip all\n
\t\t\t// items from other containers. This works because when moving\n
\t\t\t// an item from one container to another the\n
\t\t\t// currentContainer is switched before the placeholder is moved.\n
\t\t\t//\n
\t\t\t// Without this, moving items in "sub-sortables" can cause\n
\t\t\t// the placeholder to jitter beetween the outer and inner container.\n
\t\t\tif (item.instance !== this.currentContainer) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t// cannot intersect with itself\n
\t\t\t// no useless actions that have been done before\n
\t\t\t// no action if the item moved is the parent of the item checked\n
\t\t\tif (itemElement !== this.currentItem[0] &&\n
\t\t\t\tthis.placeholder[intersection === 1 ? "next" : "prev"]()[0] !== itemElement &&\n
\t\t\t\t!$.contains(this.placeholder[0], itemElement) &&\n
\t\t\t\t(this.options.type === "semi-dynamic" ? !$.contains(this.element[0], itemElement) : true)\n
\t\t\t) {\n
\n
\t\t\t\tthis.direction = intersection === 1 ? "down" : "up";\n
\n
\t\t\t\tif (this.options.tolerance === "pointer" || this._intersectsWithSides(item)) {\n
\t\t\t\t\tthis._rearrange(event, item);\n
\t\t\t\t} else {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tthis._trigger("change", event, this._uiHash());\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Post events to containers\n
\t\tthis._contactContainers(event);\n
\n
\t\t//Interconnect with droppables\n
\t\tif($.ui.ddmanager) {\n
\t\t\t$.ui.ddmanager.drag(this, event);\n
\t\t}\n
\n
\t\t//Call callbacks\n
\t\tthis._trigger("sort", event, this._uiHash());\n
\n
\t\tthis.lastPositionAbs = this.positionAbs;\n
\t\treturn false;\n
\n
\t},\n
\n
\t_mouseStop: function(event, noPropagation) {\n
\n
\t\tif(!event) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t//If we are using droppables, inform the manager about the drop\n
\t\tif ($.ui.ddmanager && !this.options.dropBehaviour) {\n
\t\t\t$.ui.ddmanager.drop(this, event);\n
\t\t}\n
\n
\t\tif(this.options.revert) {\n
\t\t\tvar that = this,\n
\t\t\t\tcur = this.placeholder.offset(),\n
\t\t\t\taxis = this.options.axis,\n
\t\t\t\tanimation = {};\n
\n
\t\t\tif ( !axis || axis === "x" ) {\n
\t\t\t\tanimation.left = cur.left - this.offset.parent.left - this.margins.left + (this.offsetParent[0] === document.body ? 0 : this.offsetParent[0].scrollLeft);\n
\t\t\t}\n
\t\t\tif ( !axis || axis === "y" ) {\n
\t\t\t\tanimation.top = cur.top - this.offset.parent.top - this.margins.top + (this.offsetParent[0] === document.body ? 0 : this.offsetParent[0].scrollTop);\n
\t\t\t}\n
\t\t\tthis.reverting = true;\n
\t\t\t$(this.helper).animate( animation, parseInt(this.options.revert, 10) || 500, function() {\n
\t\t\t\tthat._clear(event);\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis._clear(event, noPropagation);\n
\t\t}\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\tcancel: function() {\n
\n
\t\tif(this.dragging) {\n
\n
\t\t\tthis._mouseUp({ target: null });\n
\n
\t\t\tif(this.options.helper === "original") {\n
\t\t\t\tthis.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");\n
\t\t\t} else {\n
\t\t\t\tthis.currentItem.show();\n
\t\t\t}\n
\n
\t\t\t//Post deactivating events to containers\n
\t\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\t\t\t\tthis.containers[i]._trigger("deactivate", null, this._uiHash(this));\n
\t\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\t\tthis.containers[i]._trigger("out", null, this._uiHash(this));\n
\t\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\tif (this.placeholder) {\n
\t\t\t//$(this.placeholder[0]).remove(); would have been the jQuery way - unfortunately, it unbinds ALL events from the original node!\n
\t\t\tif(this.placeholder[0].parentNode) {\n
\t\t\t\tthis.placeholder[0].parentNode.removeChild(this.placeholder[0]);\n
\t\t\t}\n
\t\t\tif(this.options.helper !== "original" && this.helper && this.helper[0].parentNode) {\n
\t\t\t\tthis.helper.remove();\n
\t\t\t}\n
\n
\t\t\t$.extend(this, {\n
\t\t\t\thelper: null,\n
\t\t\t\tdragging: false,\n
\t\t\t\treverting: false,\n
\t\t\t\t_noFinalSort: null\n
\t\t\t});\n
\n
\t\t\tif(this.domPosition.prev) {\n
\t\t\t\t$(this.domPosition.prev).after(this.currentItem);\n
\t\t\t} else {\n
\t\t\t\t$(this.domPosition.parent).prepend(this.currentItem);\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\n
\t},\n
\n
\tserialize: function(o) {\n
\n
\t\tvar items = this._getItemsAsjQuery(o && o.connected),\n
\t\t\tstr = [];\n
\t\to = o || {};\n
\n
\t\t$(items).each(function() {\n
\t\t\tvar res = ($(o.item || this).attr(o.attribute || "id") || "").match(o.expression || (/(.+)[\\-=_](.+)/));\n
\t\t\tif (res) {\n
\t\t\t\tstr.push((o.key || res[1]+"[]")+"="+(o.key && o.expression ? res[1] : res[2]));\n
\t\t\t}\n
\t\t});\n
\n
\t\tif(!str.length && o.key) {\n
\t\t\tstr.push(o.key + "=");\n
\t\t}\n
\n
\t\treturn str.join("&");\n
\n
\t},\n
\n
\ttoArray: function(o) {\n
\n
\t\tvar items = this._getItemsAsjQuery(o && o.connected),\n
\t\t\tret = [];\n
\n
\t\to = o || {};\n
\n
\t\titems.each(function() { ret.push($(o.item || this).attr(o.attribute || "id") || ""); });\n
\t\treturn ret;\n
\n
\t},\n
\n
\t/* Be careful with the following core functions */\n
\t_intersectsWith: function(item) {\n
\n
\t\tvar x1 = this.positionAbs.left,\n
\t\t\tx2 = x1 + this.helperProportions.width,\n
\t\t\ty1 = this.positionAbs.top,\n
\t\t\ty2 = y1 + this.helperProportions.height,\n
\t\t\tl = item.left,\n
\t\t\tr = l + item.width,\n
\t\t\tt = item.top,\n
\t\t\tb = t + item.height,\n
\t\t\tdyClick = this.offset.click.top,\n
\t\t\tdxClick = this.offset.click.left,\n
\t\t\tisOverElementHeight = ( this.options.axis === "x" ) || ( ( y1 + dyClick ) > t && ( y1 + dyClick ) < b ),\n
\t\t\tisOverElementWidth = ( this.options.axis === "y" ) || ( ( x1 + dxClick ) > l && ( x1 + dxClick ) < r ),\n
\t\t\tisOverElement = isOverElementHeight && isOverElementWidth;\n
\n
\t\tif ( this.options.tolerance === "pointer" ||\n
\t\t\tthis.options.forcePointerForContainers ||\n
\t\t\t(this.options.tolerance !== "pointer" && this.helperProportions[this.floating ? "width" : "height"] > item[this.floating ? "width" : "height"])\n
\t\t) {\n
\t\t\treturn isOverElement;\n
\t\t} else {\n
\n
\t\t\treturn (l < x1 + (this.helperProportions.width / 2) && // Right Half\n
\t\t\t\tx2 - (this.helperProportions.width / 2) < r && // Left Half\n
\t\t\t\tt < y1 + (this.helperProportions.height / 2) && // Bottom Half\n
\t\t\t\ty2 - (this.helperProportions.height / 2) < b ); // Top Half\n
\n
\t\t}\n
\t},\n
\n
\t_intersectsWithPointer: function(item) {\n
\n
\t\tvar isOverElementHeight = (this.options.axis === "x") || isOverAxis(this.positionAbs.top + this.offset.click.top, item.top, item.height),\n
\t\t\tisOverElementWidth = (this.options.axis === "y") || isOverAxis(this.positionAbs.left + this.offset.click.left, item.left, item.width),\n
\t\t\tisOverElement = isOverElementHeight && isOverElementWidth,\n
\t\t\tverticalDirection = this._getDragVerticalDirection(),\n
\t\t\thorizontalDirection = this._getDragHorizontalDirection();\n
\n
\t\tif (!isOverElement) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\treturn this.floating ?\n
\t\t\t( ((horizontalDirection && horizontalDirection === "right") || verticalDirection === "down") ? 2 : 1 )\n
\t\t\t: ( verticalDirection && (verticalDirection === "down" ? 2 : 1) );\n
\n
\t},\n
\n
\t_intersectsWithSides: function(item) {\n
\n
\t\tvar isOverBottomHalf = isOverAxis(this.positionAbs.top + this.offset.click.top, item.top + (item.height/2), item.height),\n
\t\t\tisOverRightHalf = isOverAxis(this.positionAbs.left + this.offset.click.left, item.left + (item.width/2), item.width),\n
\t\t\tverticalDirection = this._getDragVerticalDirection(),\n
\t\t\thorizontalDirection = this._getDragHorizontalDirection();\n
\n
\t\tif (this.floating && horizontalDirection) {\n
\t\t\treturn ((horizontalDirection === "right" && isOverRightHalf) || (horizontalDirection === "left" && !isOverRightHalf));\n
\t\t} else {\n
\t\t\treturn verticalDirection && ((verticalDirection === "down" && isOverBottomHalf) || (verticalDirection === "up" && !isOverBottomHalf));\n
\t\t}\n
\n
\t},\n
\n
\t_getDragVerticalDirection: function() {\n
\t\tvar delta = this.positionAbs.top - this.lastPositionAbs.top;\n
\t\treturn delta !== 0 && (delta > 0 ? "down" : "up");\n
\t},\n
\n
\t_getDragHorizontalDirection: function() {\n
\t\tvar delta = this.positionAbs.left - this.lastPositionAbs.left;\n
\t\treturn delta !== 0 && (delta > 0 ? "right" : "left");\n
\t},\n
\n
\trefresh: function(event) {\n
\t\tthis._refreshItems(event);\n
\t\tthis.refreshPositions();\n
\t\treturn this;\n
\t},\n
\n
\t_connectWith: function() {\n
\t\tvar options = this.options;\n
\t\treturn options.connectWith.constructor === String ? [options.connectWith] : options.connectWith;\n
\t},\n
\n
\t_getItemsAsjQuery: function(connected) {\n
\n
\t\tvar i, j, cur, inst,\n
\t\t\titems = [],\n
\t\t\tqueries = [],\n
\t\t\tconnectWith = this._connectWith();\n
\n
\t\tif(connectWith && connected) {\n
\t\t\tfor (i = connectWith.length - 1; i >= 0; i--){\n
\t\t\t\tcur = $(connectWith[i]);\n
\t\t\t\tfor ( j = cur.length - 1; j >= 0; j--){\n
\t\t\t\t\tinst = $.data(cur[j], this.widgetFullName);\n
\t\t\t\t\tif(inst && inst !== this && !inst.options.disabled) {\n
\t\t\t\t\t\tqueries.push([$.isFunction(inst.options.items) ? inst.options.items.call(inst.element) : $(inst.options.items, inst.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"), inst]);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tqueries.push([$.isFunction(this.options.items) ? this.options.items.call(this.element, null, { options: this.options, item: this.currentItem }) : $(this.options.items, this.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"), this]);\n
\n
\t\tfunction addItems() {\n
\t\t\titems.push( this );\n
\t\t}\n
\t\tfor (i = queries.length - 1; i >= 0; i--){\n
\t\t\tqueries[i][0].each( addItems );\n
\t\t}\n
\n
\t\treturn $(items);\n
\n
\t},\n
\n
\t_removeCurrentsFromItems: function() {\n
\n
\t\tvar list = this.currentItem.find(":data(" + this.widgetName + "-item)");\n
\n
\t\tthis.items = $.grep(this.items, function (item) {\n
\t\t\tfor (var j=0; j < list.length; j++) {\n
\t\t\t\tif(list[j] === item.item[0]) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn true;\n
\t\t});\n
\n
\t},\n
\n
\t_refreshItems: function(event) {\n
\n
\t\tthis.items = [];\n
\t\tthis.containers = [this];\n
\n
\t\tvar i, j, cur, inst, targetData, _queries, item, queriesLength,\n
\t\t\titems = this.items,\n
\t\t\tqueries = [[$.isFunction(this.options.items) ? this.options.items.call(this.element[0], event, { item: this.currentItem }) : $(this.options.items, this.element), this]],\n
\t\t\tconnectWith = this._connectWith();\n
\n
\t\tif(connectWith && this.ready) { //Shouldn\'t be run the first time through due to massive slow-down\n
\t\t\tfor (i = connectWith.length - 1; i >= 0; i--){\n
\t\t\t\tcur = $(connectWith[i]);\n
\t\t\t\tfor (j = cur.length - 1; j >= 0; j--){\n
\t\t\t\t\tinst = $.data(cur[j], this.widgetFullName);\n
\t\t\t\t\tif(inst && inst !== this && !inst.options.disabled) {\n
\t\t\t\t\t\tqueries.push([$.isFunction(inst.options.items) ? inst.options.items.call(inst.element[0], event, { item: this.currentItem }) : $(inst.options.items, inst.element), inst]);\n
\t\t\t\t\t\tthis.containers.push(inst);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tfor (i = queries.length - 1; i >= 0; i--) {\n
\t\t\ttargetData = queries[i][1];\n
\t\t\t_queries = queries[i][0];\n
\n
\t\t\tfor (j=0, queriesLength = _queries.length; j < queriesLength; j++) {\n
\t\t\t\titem = $(_queries[j]);\n
\n
\t\t\t\titem.data(this.widgetName + "-item", targetData); // Data for target checking (mouse manager)\n
\n
\t\t\t\titems.push({\n
\t\t\t\t\titem: item,\n
\t\t\t\t\tinstance: targetData,\n
\t\t\t\t\twidth: 0, height: 0,\n
\t\t\t\t\tleft: 0, top: 0\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t},\n
\n
\trefreshPositions: function(fast) {\n
\n
\t\t//This has to be redone because due to the item being moved out/into the offsetParent, the offsetParent\'s position will change\n
\t\tif(this.offsetParent && this.helper) {\n
\t\t\tthis.offset.parent = this._getParentOffset();\n
\t\t}\n
\n
\t\tvar i, item, t, p;\n
\n
\t\tfor (i = this.items.length - 1; i >= 0; i--){\n
\t\t\titem = this.items[i];\n
\n
\t\t\t//We ignore calculating positions of all connected containers when we\'re not over them\n
\t\t\tif(item.instance !== this.currentContainer && this.currentContainer && item.item[0] !== this.currentItem[0]) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tt = this.options.toleranceElement ? $(this.options.toleranceElement, item.item) : item.item;\n
\n
\t\t\tif (!fast) {\n
\t\t\t\titem.width = t.outerWidth();\n
\t\t\t\titem.height = t.outerHeight();\n
\t\t\t}\n
\n
\t\t\tp = t.offset();\n
\t\t\titem.left = p.left;\n
\t\t\titem.top = p.top;\n
\t\t}\n
\n
\t\tif(this.options.custom && this.options.custom.refreshContainers) {\n
\t\t\tthis.options.custom.refreshContainers.call(this);\n
\t\t} else {\n
\t\t\tfor (i = this.containers.length - 1; i >= 0; i--){\n
\t\t\t\tp = this.containers[i].element.offset();\n
\t\t\t\tthis.containers[i].containerCache.left = p.left;\n
\t\t\t\tthis.containers[i].containerCache.top = p.top;\n
\t\t\t\tthis.containers[i].containerCache.width\t= this.containers[i].element.outerWidth();\n
\t\t\t\tthis.containers[i].containerCache.height = this.containers[i].element.outerHeight();\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\t_createPlaceholder: function(that) {\n
\t\tthat = that || this;\n
\t\tvar className,\n
\t\t\to = that.options;\n
\n
\t\tif(!o.placeholder || o.placeholder.constructor === String) {\n
\t\t\tclassName = o.placeholder;\n
\t\t\to.placeholder = {\n
\t\t\t\telement: function() {\n
\n
\t\t\t\t\tvar nodeName = that.currentItem[0].nodeName.toLowerCase(),\n
\t\t\t\t\t\telement = $( "<" + nodeName + ">", that.document[0] )\n
\t\t\t\t\t\t\t.addClass(className || that.currentItem[0].className+" ui-sortable-placeholder")\n
\t\t\t\t\t\t\t.removeClass("ui-sortable-helper");\n
\n
\t\t\t\t\tif ( nodeName === "tr" ) {\n
\t\t\t\t\t\tthat.currentItem.children().each(function() {\n
\t\t\t\t\t\t\t$( "<td>&#160;</td>", that.document[0] )\n
\t\t\t\t\t\t\t\t.attr( "colspan", $( this ).attr( "colspan" ) || 1 )\n
\t\t\t\t\t\t\t\t.appendTo( element );\n
\t\t\t\t\t\t});\n
\t\t\t\t\t} else if ( nodeName === "img" ) {\n
\t\t\t\t\t\telement.attr( "src", that.currentItem.attr( "src" ) );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( !className ) {\n
\t\t\t\t\t\telement.css( "visibility", "hidden" );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn element;\n
\t\t\t\t},\n
\t\t\t\tupdate: function(container, p) {\n
\n
\t\t\t\t\t// 1. If a className is set as \'placeholder option, we don\'t force sizes - the class is responsible for that\n
\t\t\t\t\t// 2. The option \'forcePlaceholderSize can be enabled to force it even if a class name is specified\n
\t\t\t\t\tif(className && !o.forcePlaceholderSize) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t//If the element doesn\'t have a actual height by itself (without styles coming from a stylesheet), it receives the inline height from the dragged item\n
\t\t\t\t\tif(!p.height()) { p.height(that.currentItem.innerHeight() - parseInt(that.currentItem.css("paddingTop")||0, 10) - parseInt(that.currentItem.css("paddingBottom")||0, 10)); }\n
\t\t\t\t\tif(!p.width()) { p.width(that.currentItem.innerWidth() - parseInt(that.currentItem.css("paddingLeft")||0, 10) - parseInt(that.currentItem.css("paddingRight")||0, 10)); }\n
\t\t\t\t}\n
\t\t\t};\n
\t\t}\n
\n
\t\t//Create the placeholder\n
\t\tthat.placeholder = $(o.placeholder.element.call(that.element, that.currentItem));\n
\n
\t\t//Append it after the actual current item\n
\t\tthat.currentItem.after(that.placeholder);\n
\n
\t\t//Update the size of the placeholder (TODO: Logic to fuzzy, see line 316/317)\n
\t\to.placeholder.update(that, that.placeholder);\n
\n
\t},\n
\n
\t_contactContainers: function(event) {\n
\t\tvar i, j, dist, itemWithLeastDistance, posProperty, sizeProperty, base, cur, nearBottom, floating,\n
\t\t\tinnermostContainer = null,\n
\t\t\tinnermostIndex = null;\n
\n
\t\t// get innermost container that intersects with item\n
\t\tfor (i = this.containers.length - 1; i >= 0; i--) {\n
\n
\t\t\t// never consider a container that\'s located within the item itself\n
\t\t\tif($.contains(this.currentItem[0], this.containers[i].element[0])) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif(this._intersectsWith(this.containers[i].containerCache)) {\n
\n
\t\t\t\t// if we\'ve already found a container and it\'s more "inner" than this, then continue\n
\t\t\t\tif(innermostContainer && $.contains(this.containers[i].element[0], innermostContainer.element[0])) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\tinnermostContainer = this.containers[i];\n
\t\t\t\tinnermostIndex = i;\n
\n
\t\t\t} else {\n
\t\t\t\t// container doesn\'t intersect. trigger "out" event if necessary\n
\t\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\t\tthis.containers[i]._trigger("out", event, this._uiHash(this));\n
\t\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\t// if no intersecting containers found, return\n
\t\tif(!innermostContainer) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// move the item into the container if it\'s not there already\n
\t\tif(this.containers.length === 1) {\n
\t\t\tif (!this.containers[innermostIndex].containerCache.over) {\n
\t\t\t\tthis.containers[innermostIndex]._trigger("over", event, this._uiHash(this));\n
\t\t\t\tthis.containers[innermostIndex].containerCache.over = 1;\n
\t\t\t}\n
\t\t} else {\n
\n
\t\t\t//When entering a new container, we will find the item with the least distance and append our item near it\n
\t\t\tdist = 10000;\n
\t\t\titemWithLeastDistance = null;\n
\t\t\tfloating = innermostContainer.floating || isFloating(this.currentItem);\n
\t\t\tposProperty = floating ? "left" : "top";\n
\t\t\tsizeProperty = floating ? "width" : "height";\n
\t\t\tbase = this.positionAbs[posProperty] + this.offset.click[posProperty];\n
\t\t\tfor (j = this.items.length - 1; j >= 0; j--) {\n
\t\t\t\tif(!$.contains(this.containers[innermostIndex].element[0], this.items[j].item[0])) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t\tif(this.items[j].item[0] === this.currentItem[0]) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t\tif (floating && !isOverAxis(this.positionAbs.top + this.offset.click.top, this.items[j].top, this.items[j].height)) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t\tcur = this.items[j].item.offset()[posProperty];\n
\t\t\t\tnearBottom = false;\n
\t\t\t\tif(Math.abs(cur - base) > Math.abs(cur + this.items[j][sizeProperty] - base)){\n
\t\t\t\t\tnearBottom = true;\n
\t\t\t\t\tcur += this.items[j][sizeProperty];\n
\t\t\t\t}\n
\n
\t\t\t\tif(Math.abs(cur - base) < dist) {\n
\t\t\t\t\tdist = Math.abs(cur - base); itemWithLeastDistance = this.items[j];\n
\t\t\t\t\tthis.direction = nearBottom ? "up": "down";\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t//Check if dropOnEmpty is enabled\n
\t\t\tif(!itemWithLeastDistance && !this.options.dropOnEmpty) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif(this.currentContainer === this.containers[innermostIndex]) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\titemWithLeastDistance ? this._rearrange(event, itemWithLeastDistance, null, true) : this._rearrange(event, null, this.containers[innermostIndex].element, true);\n
\t\t\tthis._trigger("change", event, this._uiHash());\n
\t\t\tthis.containers[innermostIndex]._trigger("change", event, this._uiHash(this));\n
\t\t\tthis.currentContainer = this.containers[innermostIndex];\n
\n
\t\t\t//Update the placeholder\n
\t\t\tthis.options.placeholder.update(this.currentContainer, this.placeholder);\n
\n
\t\t\tthis.containers[innermostIndex]._trigger("over", event, this._uiHash(this));\n
\t\t\tthis.containers[innermostIndex].containerCache.over = 1;\n
\t\t}\n
\n
\n
\t},\n
\n
\t_createHelper: function(event) {\n
\n
\t\tvar o = this.options,\n
\t\t\thelper = $.isFunction(o.helper) ? $(o.helper.apply(this.element[0], [event, this.currentItem])) : (o.helper === "clone" ? this.currentItem.clone() : this.currentItem);\n
\n
\t\t//Add the helper to the DOM if that didn\'t happen already\n
\t\tif(!helper.parents("body").length) {\n
\t\t\t$(o.appendTo !== "parent" ? o.appendTo : this.currentItem[0].parentNode)[0].appendChild(helper[0]);\n
\t\t}\n
\n
\t\tif(helper[0] === this.currentItem[0]) {\n
\t\t\tthis._storedCSS = { width: this.currentItem[0].style.width, height: this.currentItem[0].style.height, position: this.currentItem.css("position"), top: this.currentItem.css("top"), left: this.currentItem.css("left") };\n
\t\t}\n
\n
\t\tif(!helper[0].style.width || o.forceHelperSize) {\n
\t\t\thelper.width(this.currentItem.width());\n
\t\t}\n
\t\tif(!helper[0].style.height || o.forceHelperSize) {\n
\t\t\thelper.height(this.currentItem.height());\n
\t\t}\n
\n
\t\treturn helper;\n
\n
\t},\n
\n
\t_adjustOffsetFromHelper: function(obj) {\n
\t\tif (typeof obj === "string") {\n
\t\t\tobj = obj.split(" ");\n
\t\t}\n
\t\tif ($.isArray(obj)) {\n
\t\t\tobj = {left: +obj[0], top: +obj[1] || 0};\n
\t\t}\n
\t\tif ("left" in obj) {\n
\t\t\tthis.offset.click.left = obj.left + this.margins.left;\n
\t\t}\n
\t\tif ("right" in obj) {\n
\t\t\tthis.offset.click.left = this.helperProportions.width - obj.right + this.margins.left;\n
\t\t}\n
\t\tif ("top" in obj) {\n
\t\t\tthis.offset.click.top = obj.top + this.margins.top;\n
\t\t}\n
\t\tif ("bottom" in obj) {\n
\t\t\tthis.offset.click.top = this.helperProportions.height - obj.bottom + this.margins.top;\n
\t\t}\n
\t},\n
\n
\t_getParentOffset: function() {\n
\n
\n
\t\t//Get the offsetParent and cache its position\n
\t\tthis.offsetParent = this.helper.offsetParent();\n
\t\tvar po = this.offsetParent.offset();\n
\n
\t\t// This is a special case where we need to modify a offset calculated on start, since the following happened:\n
\t\t// 1. The position of the helper is absolute, so it\'s position is calculated based on the next positioned parent\n
\t\t// 2. The actual offset parent is a child of the scroll parent, and the scroll parent isn\'t the document, which means that\n
\t\t//    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag\n
\t\tif(this.cssPosition === "absolute" && this.scrollParent[0] !== document && $.contains(this.scrollParent[0], this.offsetParent[0])) {\n
\t\t\tpo.left += this.scrollParent.scrollLeft();\n
\t\t\tpo.top += this.scrollParent.scrollTop();\n
\t\t}\n
\n
\t\t// This needs to be actually done for all browsers, since pageX/pageY includes this information\n
\t\t// with an ugly IE fix\n
\t\tif( this.offsetParent[0] === document.body || (this.offsetParent[0].tagName && this.offsetParent[0].tagName.toLowerCase() === "html" && $.ui.ie)) {\n
\t\t\tpo = { top: 0, left: 0 };\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: po.top + (parseInt(this.offsetParent.css("borderTopWidth"),10) || 0),\n
\t\t\tleft: po.left + (parseInt(this.offsetParent.css("borderLeftWidth"),10) || 0)\n
\t\t};\n
\n
\t},\n
\n
\t_getRelativeOffset: function() {\n
\n
\t\tif(this.cssPosition === "relative") {\n
\t\t\tvar p = this.currentItem.position();\n
\t\t\treturn {\n
\t\t\t\ttop: p.top - (parseInt(this.helper.css("top"),10) || 0) + this.scrollParent.scrollTop(),\n
\t\t\t\tleft: p.left - (parseInt(this.helper.css("left"),10) || 0) + this.scrollParent.scrollLeft()\n
\t\t\t};\n
\t\t} else {\n
\t\t\treturn { top: 0, left: 0 };\n
\t\t}\n
\n
\t},\n
\n
\t_cacheMargins: function() {\n
\t\tthis.margins = {\n
\t\t\tleft: (parseInt(this.currentItem.css("marginLeft"),10) || 0),\n
\t\t\ttop: (parseInt(this.currentItem.css("marginTop"),10) || 0)\n
\t\t};\n
\t},\n
\n
\t_cacheHelperProportions: function() {\n
\t\tthis.helperProportions = {\n
\t\t\twidth: this.helper.outerWidth(),\n
\t\t\theight: this.helper.outerHeight()\n
\t\t};\n
\t},\n
\n
\t_setContainment: function() {\n
\n
\t\tvar ce, co, over,\n
\t\t\to = this.options;\n
\t\tif(o.containment === "parent") {\n
\t\t\to.containment = this.helper[0].parentNode;\n
\t\t}\n
\t\tif(o.containment === "document" || o.containment === "window") {\n
\t\t\tthis.containment = [\n
\t\t\t\t0 - this.offset.relative.left - this.offset.parent.left,\n
\t\t\t\t0 - this.offset.relative.top - this.offset.parent.top,\n
\t\t\t\t$(o.containment === "document" ? document : window).width() - this.helperProportions.width - this.margins.left,\n
\t\t\t\t($(o.containment === "document" ? document : window).height() || document.body.parentNode.scrollHeight) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t}\n
\n
\t\tif(!(/^(document|window|parent)$/).test(o.containment)) {\n
\t\t\tce = $(o.containment)[0];\n
\t\t\tco = $(o.containment).offset();\n
\t\t\tover = ($(ce).css("overflow") !== "hidden");\n
\n
\t\t\tthis.containment = [\n
\t\t\t\tco.left + (parseInt($(ce).css("borderLeftWidth"),10) || 0) + (parseInt($(ce).css("paddingLeft"),10) || 0) - this.margins.left,\n
\t\t\t\tco.top + (parseInt($(ce).css("borderTopWidth"),10) || 0) + (parseInt($(ce).css("paddingTop"),10) || 0) - this.margins.top,\n
\t\t\t\tco.left+(over ? Math.max(ce.scrollWidth,ce.offsetWidth) : ce.offsetWidth) - (parseInt($(ce).css("borderLeftWidth"),10) || 0) - (parseInt($(ce).css("paddingRight"),10) || 0) - this.helperProportions.width - this.margins.left,\n
\t\t\t\tco.top+(over ? Math.max(ce.scrollHeight,ce.offsetHeight) : ce.offsetHeight) - (parseInt($(ce).css("borderTopWidth"),10) || 0) - (parseInt($(ce).css("paddingBottom"),10) || 0) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t}\n
\n
\t},\n
\n
\t_convertPositionTo: function(d, pos) {\n
\n
\t\tif(!pos) {\n
\t\t\tpos = this.position;\n
\t\t}\n
\t\tvar mod = d === "absolute" ? 1 : -1,\n
\t\t\tscroll = this.cssPosition === "absolute" && !(this.scrollParent[0] !== document && $.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent,\n
\t\t\tscrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpos.top\t+\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.relative.top * mod +\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.top * mod -\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ) * mod)\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpos.left +\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.relative.left * mod +\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.left * mod\t-\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ) * mod)\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_generatePosition: function(event) {\n
\n
\t\tvar top, left,\n
\t\t\to = this.options,\n
\t\t\tpageX = event.pageX,\n
\t\t\tpageY = event.pageY,\n
\t\t\tscroll = this.cssPosition === "absolute" && !(this.scrollParent[0] !== document && $.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent, scrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\t// This is another very weird special case that only happens for relative elements:\n
\t\t// 1. If the css position is relative\n
\t\t// 2. and the scroll parent is the document or similar to the offset parent\n
\t\t// we have to refresh the relative offset during the scroll so there are no jumps\n
\t\tif(this.cssPosition === "relative" && !(this.scrollParent[0] !== document && this.scrollParent[0] !== this.offsetParent[0])) {\n
\t\t\tthis.offset.relative = this._getRelativeOffset();\n
\t\t}\n
\n
\t\t/*\n
\t\t * - Position constraining -\n
\t\t * Constrain the position to a mix of grid, containment.\n
\t\t */\n
\n
\t\tif(this.originalPosition) { //If we are not dragging yet, we won\'t check for options\n
\n
\t\t\tif(this.containment) {\n
\t\t\t\tif(event.pageX - this.offset.click.left < this.containment[0]) {\n
\t\t\t\t\tpageX = this.containment[0] + this.offset.click.left;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageY - this.offset.click.top < this.containment[1]) {\n
\t\t\t\t\tpageY = this.containment[1] + this.offset.click.top;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageX - this.offset.click.left > this.containment[2]) {\n
\t\t\t\t\tpageX = this.containment[2] + this.offset.click.left;\n
\t\t\t\t}\n
\t\t\t\tif(event.pageY - this.offset.click.top > this.containment[3]) {\n
\t\t\t\t\tpageY = this.containment[3] + this.offset.click.top;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(o.grid) {\n
\t\t\t\ttop = this.originalPageY + Math.round((pageY - this.originalPageY) / o.grid[1]) * o.grid[1];\n
\t\t\t\tpageY = this.containment ? ( (top - this.offset.click.top >= this.containment[1] && top - this.offset.click.top <= this.containment[3]) ? top : ((top - this.offset.click.top >= this.containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;\n
\n
\t\t\t\tleft = this.originalPageX + Math.round((pageX - this.originalPageX) / o.grid[0]) * o.grid[0];\n
\t\t\t\tpageX = this.containment ? ( (left - this.offset.click.left >= this.containment[0] && left - this.offset.click.left <= this.containment[2]) ? left : ((left - this.offset.click.left >= this.containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpageY -\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.click.top -\t\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\tthis.offset.relative.top\t-\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.top +\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ))\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpageX -\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\tthis.offset.click.left -\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\tthis.offset.relative.left\t-\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\tthis.offset.parent.left +\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t( ( this.cssPosition === "fixed" ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ))\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_rearrange: function(event, i, a, hardRefresh) {\n
\n
\t\ta ? a[0].appendChild(this.placeholder[0]) : i.item[0].parentNode.insertBefore(this.placeholder[0], (this.direction === "down" ? i.item[0] : i.item[0].nextSibling));\n
\n
\t\t//Various things done here to improve the performance:\n
\t\t// 1. we create a setTimeout, that calls refreshPositions\n
\t\t// 2. on the instance, we have a counter variable, that get\'s higher after every append\n
\t\t// 3. on the local scope, we copy the counter variable, and check in the timeout, if it\'s still the same\n
\t\t// 4. this lets only the last addition to the timeout stack through\n
\t\tthis.counter = this.counter ? ++this.counter : 1;\n
\t\tvar counter = this.counter;\n
\n
\t\tthis._delay(function() {\n
\t\t\tif(counter === this.counter) {\n
\t\t\t\tthis.refreshPositions(!hardRefresh); //Precompute after each DOM insertion, NOT on mousemove\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\n
\t_clear: function(event, noPropagation) {\n
\n
\t\tthis.reverting = false;\n
\t\t// We delay all events that have to be triggered to after the point where the placeholder has been removed and\n
\t\t// everything else normalized again\n
\t\tvar i,\n
\t\t\tdelayedTriggers = [];\n
\n
\t\t// We first have to update the dom position of the actual currentItem\n
\t\t// Note: don\'t do it if the current item is already removed (by a user), or it gets reappended (see #4088)\n
\t\tif(!this._noFinalSort && this.currentItem.parent().length) {\n
\t\t\tthis.placeholder.before(this.currentItem);\n
\t\t}\n
\t\tthis._noFinalSort = null;\n
\n
\t\tif(this.helper[0] === this.currentItem[0]) {\n
\t\t\tfor(i in this._storedCSS) {\n
\t\t\t\tif(this._storedCSS[i] === "auto" || this._storedCSS[i] === "static") {\n
\t\t\t\t\tthis._storedCSS[i] = "";\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");\n
\t\t} else {\n
\t\t\tthis.currentItem.show();\n
\t\t}\n
\n
\t\tif(this.fromOutside && !noPropagation) {\n
\t\t\tdelayedTriggers.push(function(event) { this._trigger("receive", event, this._uiHash(this.fromOutside)); });\n
\t\t}\n
\t\tif((this.fromOutside || this.domPosition.prev !== this.currentItem.prev().not(".ui-sortable-helper")[0] || this.domPosition.parent !== this.currentItem.parent()[0]) && !noPropagation) {\n
\t\t\tdelayedTriggers.push(function(event) { this._trigger("update", event, this._uiHash()); }); //Trigger update callback if the DOM position has changed\n
\t\t}\n
\n
\t\t// Check if the items Container has Changed and trigger appropriate\n
\t\t// events.\n
\t\tif (this !== this.currentContainer) {\n
\t\t\tif(!noPropagation) {\n
\t\t\t\tdelayedTriggers.push(function(event) { this._trigger("remove", event, this._uiHash()); });\n
\t\t\t\tdelayedTriggers.push((function(c) { return function(event) { c._trigger("receive", event, this._uiHash(this)); };  }).call(this, this.currentContainer));\n
\t\t\t\tdelayedTriggers.push((function(c) { return function(event) { c._trigger("update", event, this._uiHash(this));  }; }).call(this, this.currentContainer));\n
\t\t\t}\n
\t\t}\n
\n
\n
\t\t//Post events to containers\n
\t\tfunction delayEvent( type, instance, container ) {\n
\t\t\treturn function( event ) {\n
\t\t\t\tcontainer._trigger( type, event, instance._uiHash( instance ) );\n
\t\t\t};\n
\t\t}\n
\t\tfor (i = this.containers.length - 1; i >= 0; i--){\n
\t\t\tif (!noPropagation) {\n
\t\t\t\tdelayedTriggers.push( delayEvent( "deactivate", this, this.containers[ i ] ) );\n
\t\t\t}\n
\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\tdelayedTriggers.push( delayEvent( "out", this, this.containers[ i ] ) );\n
\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Do what was originally in plugins\n
\t\tif ( this.storedCursor ) {\n
\t\t\tthis.document.find( "body" ).css( "cursor", this.storedCursor );\n
\t\t\tthis.storedStylesheet.remove();\n
\t\t}\n
\t\tif(this._storedOpacity) {\n
\t\t\tthis.helper.css("opacity", this._storedOpacity);\n
\t\t}\n
\t\tif(this._storedZIndex) {\n
\t\t\tthis.helper.css("zIndex", this._storedZIndex === "auto" ? "" : this._storedZIndex);\n
\t\t}\n
\n
\t\tthis.dragging = false;\n
\t\tif(this.cancelHelperRemoval) {\n
\t\t\tif(!noPropagation) {\n
\t\t\t\tthis._trigger("beforeStop", event, this._uiHash());\n
\t\t\t\tfor (i=0; i < delayedTriggers.length; i++) {\n
\t\t\t\t\tdelayedTriggers[i].call(this, event);\n
\t\t\t\t} //Trigger all delayed events\n
\t\t\t\tthis._trigger("stop", event, this._uiHash());\n
\t\t\t}\n
\n
\t\t\tthis.fromOutside = false;\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif(!noPropagation) {\n
\t\t\tthis._trigger("beforeStop", event, this._uiHash());\n
\t\t}\n
\n
\t\t//$(this.placeholder[0]).remove(); would have been the jQuery way - unfortunately, it unbinds ALL events from the original node!\n
\t\tthis.placeholder[0].parentNode.removeChild(this.placeholder[0]);\n
\n
\t\tif(this.helper[0] !== this.currentItem[0]) {\n
\t\t\tthis.helper.remove();\n
\t\t}\n
\t\tthis.helper = null;\n
\n
\t\tif(!noPropagation) {\n
\t\t\tfor (i=0; i < delayedTriggers.length; i++) {\n
\t\t\t\tdelayedTriggers[i].call(this, event);\n
\t\t\t} //Trigger all delayed events\n
\t\t\tthis._trigger("stop", event, this._uiHash());\n
\t\t}\n
\n
\t\tthis.fromOutside = false;\n
\t\treturn true;\n
\n
\t},\n
\n
\t_trigger: function() {\n
\t\tif ($.Widget.prototype._trigger.apply(this, arguments) === false) {\n
\t\t\tthis.cancel();\n
\t\t}\n
\t},\n
\n
\t_uiHash: function(_inst) {\n
\t\tvar inst = _inst || this;\n
\t\treturn {\n
\t\t\thelper: inst.helper,\n
\t\t\tplaceholder: inst.placeholder || $([]),\n
\t\t\tposition: inst.position,\n
\t\t\toriginalPosition: inst.originalPosition,\n
\t\t\toffset: inst.positionAbs,\n
\t\t\titem: inst.currentItem,\n
\t\t\tsender: _inst ? _inst.element : null\n
\t\t};\n
\t}\n
\n
});\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
var uid = 0,\n
\thideProps = {},\n
\tshowProps = {};\n
\n
hideProps.height = hideProps.paddingTop = hideProps.paddingBottom =\n
\thideProps.borderTopWidth = hideProps.borderBottomWidth = "hide";\n
showProps.height = showProps.paddingTop = showProps.paddingBottom =\n
\tshowProps.borderTopWidth = showProps.borderBottomWidth = "show";\n
\n
$.widget( "ui.accordion", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tactive: 0,\n
\t\tanimate: {},\n
\t\tcollapsible: false,\n
\t\tevent: "click",\n
\t\theader: "> li > :first-child,> :not(li):even",\n
\t\theightStyle: "auto",\n
\t\ticons: {\n
\t\t\tactiveHeader: "ui-icon-triangle-1-s",\n
\t\t\theader: "ui-icon-triangle-1-e"\n
\t\t},\n
\n
\t\t// callbacks\n
\t\tactivate: null,\n
\t\tbeforeActivate: null\n
\t},\n
\n
\t_create: function() {\n
\t\tvar options = this.options;\n
\t\tthis.prevShow = this.prevHide = $();\n
\t\tthis.element.addClass( "ui-accordion ui-widget ui-helper-reset" )\n
\t\t\t// ARIA\n
\t\t\t.attr( "role", "tablist" );\n
\n
\t\t// don\'t allow collapsible: false and active: false / null\n
\t\tif ( !options.collapsible && (options.active === false || options.active == null) ) {\n
\t\t\toptions.active = 0;\n
\t\t}\n
\n
\t\tthis._processPanels();\n
\t\t// handle negative values\n
\t\tif ( options.active < 0 ) {\n
\t\t\toptions.active += this.headers.length;\n
\t\t}\n
\t\tthis._refresh();\n
\t},\n
\n
\t_getCreateEventData: function() {\n
\t\treturn {\n
\t\t\theader: this.active,\n
\t\t\tpanel: !this.active.length ? $() : this.active.next(),\n
\t\t\tcontent: !this.active.length ? $() : this.active.next()\n
\t\t};\n
\t},\n
\n
\t_createIcons: function() {\n
\t\tvar icons = this.options.icons;\n
\t\tif ( icons ) {\n
\t\t\t$( "<span>" )\n
\t\t\t\t.addClass( "ui-accordion-header-icon ui-icon " + icons.header )\n
\t\t\t\t.prependTo( this.headers );\n
\t\t\tthis.active.children( ".ui-accordion-header-icon" )\n
\t\t\t\t.removeClass( icons.header )\n
\t\t\t\t.addClass( icons.activeHeader );\n
\t\t\tthis.headers.addClass( "ui-accordion-icons" );\n
\t\t}\n
\t},\n
\n
\t_destroyIcons: function() {\n
\t\tthis.headers\n
\t\t\t.removeClass( "ui-accordion-icons" )\n
\t\t\t.children( ".ui-accordion-header-icon" )\n
\t\t\t\t.remove();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar contents;\n
\n
\t\t// clean up main element\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-accordion ui-widget ui-helper-reset" )\n
\t\t\t.removeAttr( "role" );\n
\n
\t\t// clean up headers\n
\t\tthis.headers\n
\t\t\t.removeClass( "ui-accordion-header ui-accordion-header-active ui-helper-reset ui-state-default ui-corner-all ui-state-active ui-state-disabled ui-corner-top" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-expanded" )\n
\t\t\t.removeAttr( "aria-selected" )\n
\t\t\t.removeAttr( "aria-controls" )\n
\t\t\t.removeAttr( "tabIndex" )\n
\t\t\t.each(function() {\n
\t\t\t\tif ( /^ui-accordion/.test( this.id ) ) {\n
\t\t\t\t\tthis.removeAttribute( "id" );\n
\t\t\t\t}\n
\t\t\t});\n
\t\tthis._destroyIcons();\n
\n
\t\t// clean up content panels\n
\t\tcontents = this.headers.next()\n
\t\t\t.css( "display", "" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-hidden" )\n
\t\t\t.removeAttr( "aria-labelledby" )\n
\t\t\t.removeClass( "ui-helper-reset ui-widget-content ui-corner-bottom ui-accordion-content ui-accordion-content-active ui-state-disabled" )\n
\t\t\t.each(function() {\n
\t\t\t\tif ( /^ui-accordion/.test( this.id ) ) {\n
\t\t\t\t\tthis.removeAttribute( "id" );\n
\t\t\t\t}\n
\t\t\t});\n
\t\tif ( this.options.heightStyle !== "content" ) {\n
\t\t\tcontents.css( "height", "" );\n
\t\t}\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "active" ) {\n
\t\t\t// _activate() will handle invalid values and update this.options\n
\t\t\tthis._activate( value );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( key === "event" ) {\n
\t\t\tif ( this.options.event ) {\n
\t\t\t\tthis._off( this.headers, this.options.event );\n
\t\t\t}\n
\t\t\tthis._setupEvents( value );\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\n
\t\t// setting collapsible: false while collapsed; open first panel\n
\t\tif ( key === "collapsible" && !value && this.options.active === false ) {\n
\t\t\tthis._activate( 0 );\n
\t\t}\n
\n
\t\tif ( key === "icons" ) {\n
\t\t\tthis._destroyIcons();\n
\t\t\tif ( value ) {\n
\t\t\t\tthis._createIcons();\n
\t\t\t}\n
\t\t}\n
\n
\t\t// #5332 - opacity doesn\'t cascade to positioned elements in IE\n
\t\t// so we need to add the disabled class to the headers and panels\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.headers.add( this.headers.next() )\n
\t\t\t\t.toggleClass( "ui-state-disabled", !!value );\n
\t\t}\n
\t},\n
\n
\t_keydown: function( event ) {\n
\t\tif ( event.altKey || event.ctrlKey ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar keyCode = $.ui.keyCode,\n
\t\t\tlength = this.headers.length,\n
\t\t\tcurrentIndex = this.headers.index( event.target ),\n
\t\t\ttoFocus = false;\n
\n
\t\tswitch ( event.keyCode ) {\n
\t\t\tcase keyCode.RIGHT:\n
\t\t\tcase keyCode.DOWN:\n
\t\t\t\ttoFocus = this.headers[ ( currentIndex + 1 ) % length ];\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.LEFT:\n
\t\t\tcase keyCode.UP:\n
\t\t\t\ttoFocus = this.headers[ ( currentIndex - 1 + length ) % length ];\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.SPACE:\n
\t\t\tcase keyCode.ENTER:\n
\t\t\t\tthis._eventHandler( event );\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.HOME:\n
\t\t\t\ttoFocus = this.headers[ 0 ];\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.END:\n
\t\t\t\ttoFocus = this.headers[ length - 1 ];\n
\t\t\t\tbreak;\n
\t\t}\n
\n
\t\tif ( toFocus ) {\n
\t\t\t$( event.target ).attr( "tabIndex", -1 );\n
\t\t\t$( toFocus ).attr( "tabIndex", 0 );\n
\t\t\ttoFocus.focus();\n
\t\t\tevent.preventDefault();\n
\t\t}\n
\t},\n
\n
\t_panelKeyDown : function( event ) {\n
\t\tif ( event.keyCode === $.ui.keyCode.UP && event.ctrlKey ) {\n
\t\t\t$( event.currentTarget ).prev().focus();\n
\t\t}\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar options = this.options;\n
\t\tthis._processPanels();\n
\n
\t\t// was collapsed or no panel\n
\t\tif ( ( options.active === false && options.collapsible === true ) || !this.headers.length ) {\n
\t\t\toptions.active = false;\n
\t\t\tthis.active = $();\n
\t\t// active false only when collapsible is true\n
\t\t} else if ( options.active === false ) {\n
\t\t\tthis._activate( 0 );\n
\t\t// was active, but active panel is gone\n
\t\t} else if ( this.active.length && !$.contains( this.element[ 0 ], this.active[ 0 ] ) ) {\n
\t\t\t// all remaining panel are disabled\n
\t\t\tif ( this.headers.length === this.headers.find(".ui-state-disabled").length ) {\n
\t\t\t\toptions.active = false;\n
\t\t\t\tthis.active = $();\n
\t\t\t// activate previous panel\n
\t\t\t} else {\n
\t\t\t\tthis._activate( Math.max( 0, options.active - 1 ) );\n
\t\t\t}\n
\t\t// was active, active panel still exists\n
\t\t} else {\n
\t\t\t// make sure active index is correct\n
\t\t\toptions.active = this.headers.index( this.active );\n
\t\t}\n
\n
\t\tthis._destroyIcons();\n
\n
\t\tthis._refresh();\n
\t},\n
\n
\t_processPanels: function() {\n
\t\tthis.headers = this.element.find( this.options.header )\n
\t\t\t.addClass( "ui-accordion-header ui-helper-reset ui-state-default ui-corner-all" );\n
\n
\t\tthis.headers.next()\n
\t\t\t.addClass( "ui-accordion-content ui-helper-reset ui-widget-content ui-corner-bottom" )\n
\t\t\t.filter(":not(.ui-accordion-content-active)")\n
\t\t\t.hide();\n
\t},\n
\n
\t_refresh: function() {\n
\t\tvar maxHeight,\n
\t\t\toptions = this.options,\n
\t\t\theightStyle = options.heightStyle,\n
\t\t\tparent = this.element.parent(),\n
\t\t\taccordionId = this.accordionId = "ui-accordion-" +\n
\t\t\t\t(this.element.attr( "id" ) || ++uid);\n
\n
\t\tthis.active = this._findActive( options.active )\n
\t\t\t.addClass( "ui-accordion-header-active ui-state-active ui-corner-top" )\n
\t\t\t.removeClass( "ui-corner-all" );\n
\t\tthis.active.next()\n
\t\t\t.addClass( "ui-accordion-content-active" )\n
\t\t\t.show();\n
\n
\t\tthis.headers\n
\t\t\t.attr( "role", "tab" )\n
\t\t\t.each(function( i ) {\n
\t\t\t\tvar header = $( this ),\n
\t\t\t\t\theaderId = header.attr( "id" ),\n
\t\t\t\t\tpanel = header.next(),\n
\t\t\t\t\tpanelId = panel.attr( "id" );\n
\t\t\t\tif ( !headerId ) {\n
\t\t\t\t\theaderId = accordionId + "-header-" + i;\n
\t\t\t\t\theader.attr( "id", headerId );\n
\t\t\t\t}\n
\t\t\t\tif ( !panelId ) {\n
\t\t\t\t\tpanelId = accordionId + "-panel-" + i;\n
\t\t\t\t\tpanel.attr( "id", panelId );\n
\t\t\t\t}\n
\t\t\t\theader.attr( "aria-controls", panelId );\n
\t\t\t\tpanel.attr( "aria-labelledby", headerId );\n
\t\t\t})\n
\t\t\t.next()\n
\t\t\t\t.attr( "role", "tabpanel" );\n
\n
\t\tthis.headers\n
\t\t\t.not( this.active )\n
\t\t\t.attr({\n
\t\t\t\t"aria-selected": "false",\n
\t\t\t\t"aria-expanded": "false",\n
\t\t\t\ttabIndex: -1\n
\t\t\t})\n
\t\t\t.next()\n
\t\t\t\t.attr({\n
\t\t\t\t\t"aria-hidden": "true"\n
\t\t\t\t})\n
\t\t\t\t.hide();\n
\n
\t\t// make sure at least one header is in the tab order\n
\t\tif ( !this.active.length ) {\n
\t\t\tthis.headers.eq( 0 ).attr( "tabIndex", 0 );\n
\t\t} else {\n
\t\t\tthis.active.attr({\n
\t\t\t\t"aria-selected": "true",\n
\t\t\t\t"aria-expanded": "true",\n
\t\t\t\ttabIndex: 0\n
\t\t\t})\n
\t\t\t.next()\n
\t\t\t\t.attr({\n
\t\t\t\t\t"aria-hidden": "false"\n
\t\t\t\t});\n
\t\t}\n
\n
\t\tthis._createIcons();\n
\n
\t\tthis._setupEvents( options.event );\n
\n
\t\tif ( heightStyle === "fill" ) {\n
\t\t\tmaxHeight = parent.height();\n
\t\t\tthis.element.siblings( ":visible" ).each(function() {\n
\t\t\t\tvar elem = $( this ),\n
\t\t\t\t\tposition = elem.css( "position" );\n
\n
\t\t\t\tif ( position === "absolute" || position === "fixed" ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tmaxHeight -= elem.outerHeight( true );\n
\t\t\t});\n
\n
\t\t\tthis.headers.each(function() {\n
\t\t\t\tmaxHeight -= $( this ).outerHeight( true );\n
\t\t\t});\n
\n
\t\t\tthis.headers.next()\n
\t\t\t\t.each(function() {\n
\t\t\t\t\t$( this ).height( Math.max( 0, maxHeight -\n
\t\t\t\t\t\t$( this ).innerHeight() + $( this ).height() ) );\n
\t\t\t\t})\n
\t\t\t\t.css( "overflow", "auto" );\n
\t\t} else if ( heightStyle === "auto" ) {\n
\t\t\tmaxHeight = 0;\n
\t\t\tthis.headers.next()\n
\t\t\t\t.each(function() {\n
\t\t\t\t\tmaxHeight = Math.max( maxHeight, $( this ).css( "height", "" ).height() );\n
\t\t\t\t})\n
\t\t\t\t.height( maxHeight );\n
\t\t}\n
\t},\n
\n
\t_activate: function( index ) {\n
\t\tvar active = this._findActive( index )[ 0 ];\n
\n
\t\t// trying to activate the already active panel\n
\t\tif ( active === this.active[ 0 ] ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// trying to collapse, simulate a click on the currently active header\n
\t\tactive = active || this.active[ 0 ];\n
\n
\t\tthis._eventHandler({\n
\t\t\ttarget: active,\n
\t\t\tcurrentTarget: active,\n
\t\t\tpreventDefault: $.noop\n
\t\t});\n
\t},\n
\n
\t_findActive: function( selector ) {\n
\t\treturn typeof selector === "number" ? this.headers.eq( selector ) : $();\n
\t},\n
\n
\t_setupEvents: function( event ) {\n
\t\tvar events = {\n
\t\t\tkeydown: "_keydown"\n
\t\t};\n
\t\tif ( event ) {\n
\t\t\t$.each( event.split(" "), function( index, eventName ) {\n
\t\t\t\tevents[ eventName ] = "_eventHandler";\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._off( this.headers.add( this.headers.next() ) );\n
\t\tthis._on( this.headers, events );\n
\t\tthis._on( this.headers.next(), { keydown: "_panelKeyDown" });\n
\t\tthis._hoverable( this.headers );\n
\t\tthis._focusable( this.headers );\n
\t},\n
\n
\t_eventHandler: function( event ) {\n
\t\tvar options = this.options,\n
\t\t\tactive = this.active,\n
\t\t\tclicked = $( event.currentTarget ),\n
\t\t\tclickedIsActive = clicked[ 0 ] === active[ 0 ],\n
\t\t\tcollapsing = clickedIsActive && options.collapsible,\n
\t\t\ttoShow = collapsing ? $() : clicked.next(),\n
\t\t\ttoHide = active.next(),\n
\t\t\teventData = {\n
\t\t\t\toldHeader: active,\n
\t\t\t\toldPanel: toHide,\n
\t\t\t\tnewHeader: collapsing ? $() : clicked,\n
\t\t\t\tnewPanel: toShow\n
\t\t\t};\n
\n
\t\tevent.preventDefault();\n
\n
\t\tif (\n
\t\t\t\t// click on active header, but not collapsible\n
\t\t\t\t( clickedIsActive && !options.collapsible ) ||\n
\t\t\t\t// allow canceling activation\n
\t\t\t\t( this._trigger( "beforeActivate", event, eventData ) === false ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\toptions.active = collapsing ? false : this.headers.index( clicked );\n
\n
\t\t// when the call to ._toggle() comes after the class changes\n
\t\t// it causes a very odd bug in IE 8 (see #6720)\n
\t\tthis.active = clickedIsActive ? $() : clicked;\n
\t\tthis._toggle( eventData );\n
\n
\t\t// switch classes\n
\t\t// corner classes on the previously active header stay after the animation\n
\t\tactive.removeClass( "ui-accordion-header-active ui-state-active" );\n
\t\tif ( options.icons ) {\n
\t\t\tactive.children( ".ui-accordion-header-icon" )\n
\t\t\t\t.removeClass( options.icons.activeHeader )\n
\t\t\t\t.addClass( options.icons.header );\n
\t\t}\n
\n
\t\tif ( !clickedIsActive ) {\n
\t\t\tclicked\n
\t\t\t\t.removeClass( "ui-corner-all" )\n
\t\t\t\t.addClass( "ui-accordion-header-active ui-state-active ui-corner-top" );\n
\t\t\tif ( options.icons ) {\n
\t\t\t\tclicked.children( ".ui-accordion-header-icon" )\n
\t\t\t\t\t.removeClass( options.icons.header )\n
\t\t\t\t\t.addClass( options.icons.activeHeader );\n
\t\t\t}\n
\n
\t\t\tclicked\n
\t\t\t\t.next()\n
\t\t\t\t.addClass( "ui-accordion-content-active" );\n
\t\t}\n
\t},\n
\n
\t_toggle: function( data ) {\n
\t\tvar toShow = data.newPanel,\n
\t\t\ttoHide = this.prevShow.length ? this.prevShow : data.oldPanel;\n
\n
\t\t// handle activating a panel during the animation for another activation\n
\t\tthis.prevShow.add( this.prevHide ).stop( true, true );\n
\t\tthis.prevShow = toShow;\n
\t\tthis.prevHide = toHide;\n
\n
\t\tif ( this.options.animate ) {\n
\t\t\tthis._animate( toShow, toHide, data );\n
\t\t} else {\n
\t\t\ttoHide.hide();\n
\t\t\ttoShow.show();\n
\t\t\tthis._toggleComplete( data );\n
\t\t}\n
\n
\t\ttoHide.attr({\n
\t\t\t"aria-hidden": "true"\n
\t\t});\n
\t\ttoHide.prev().attr( "aria-selected", "false" );\n
\t\t// if we\'re switching panels, remove the old header from the tab order\n
\t\t// if we\'re opening from collapsed state, remove the previous header from the tab order\n
\t\t// if we\'re collapsing, then keep the collapsing header in the tab order\n
\t\tif ( toShow.length && toHide.length ) {\n
\t\t\ttoHide.prev().attr({\n
\t\t\t\t"tabIndex": -1,\n
\t\t\t\t"aria-expanded": "false"\n
\t\t\t});\n
\t\t} else if ( toShow.length ) {\n
\t\t\tthis.headers.filter(function() {\n
\t\t\t\treturn $( this ).attr( "tabIndex" ) === 0;\n
\t\t\t})\n
\t\t\t.attr( "tabIndex", -1 );\n
\t\t}\n
\n
\t\ttoShow\n
\t\t\t.attr( "aria-hidden", "false" )\n
\t\t\t.prev()\n
\t\t\t\t.attr({\n
\t\t\t\t\t"aria-selected": "true",\n
\t\t\t\t\ttabIndex: 0,\n
\t\t\t\t\t"aria-expanded": "true"\n
\t\t\t\t});\n
\t},\n
\n
\t_animate: function( toShow, toHide, data ) {\n
\t\tvar total, easing, duration,\n
\t\t\tthat = this,\n
\t\t\tadjust = 0,\n
\t\t\tdown = toShow.length &&\n
\t\t\t\t( !toHide.length || ( toShow.index() < toHide.index() ) ),\n
\t\t\tanimate = this.options.animate || {},\n
\t\t\toptions = down && animate.down || animate,\n
\t\t\tcomplete = function() {\n
\t\t\t\tthat._toggleComplete( data );\n
\t\t\t};\n
\n
\t\tif ( typeof options === "number" ) {\n
\t\t\tduration = options;\n
\t\t}\n
\t\tif ( typeof options === "string" ) {\n
\t\t\teasing = options;\n
\t\t}\n
\t\t// fall back from options to animation in case of partial down settings\n
\t\teasing = easing || options.easing || animate.easing;\n
\t\tduration = duration || options.duration || animate.duration;\n
\n
\t\tif ( !toHide.length ) {\n
\t\t\treturn toShow.animate( showProps, duration, easing, complete );\n
\t\t}\n
\t\tif ( !toShow.length ) {\n
\t\t\treturn toHide.animate( hideProps, duration, easing, complete );\n
\t\t}\n
\n
\t\ttotal = toShow.show().outerHeight();\n
\t\ttoHide.animate( hideProps, {\n
\t\t\tduration: duration,\n
\t\t\teasing: easing,\n
\t\t\tstep: function( now, fx ) {\n
\t\t\t\tfx.now = Math.round( now );\n
\t\t\t}\n
\t\t});\n
\t\ttoShow\n
\t\t\t.hide()\n
\t\t\t.animate( showProps, {\n
\t\t\t\tduration: duration,\n
\t\t\t\teasing: easing,\n
\t\t\t\tcomplete: complete,\n
\t\t\t\tstep: function( now, fx ) {\n
\t\t\t\t\tfx.now = Math.round( now );\n
\t\t\t\t\tif ( fx.prop !== "height" ) {\n
\t\t\t\t\t\tadjust += fx.now;\n
\t\t\t\t\t} else if ( that.options.heightStyle !== "content" ) {\n
\t\t\t\t\t\tfx.now = Math.round( total - toHide.outerHeight() - adjust );\n
\t\t\t\t\t\tadjust = 0;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t},\n
\n
\t_toggleComplete: function( data ) {\n
\t\tvar toHide = data.oldPanel;\n
\n
\t\ttoHide\n
\t\t\t.removeClass( "ui-accordion-content-active" )\n
\t\t\t.prev()\n
\t\t\t\t.removeClass( "ui-corner-top" )\n
\t\t\t\t.addClass( "ui-corner-all" );\n
\n
\t\t// Work around for rendering bug in IE (#5421)\n
\t\tif ( toHide.length ) {\n
\t\t\ttoHide.parent()[0].className = toHide.parent()[0].className;\n
\t\t}\n
\t\tthis._trigger( "activate", null, data );\n
\t}\n
});\n
\n
})( jQuery );\n
(function( $, undefined ) {\n
\n
$.widget( "ui.autocomplete", {\n
\tversion: "1.10.4",\n
\tdefaultElement: "<input>",\n
\toptions: {\n
\t\tappendTo: null,\n
\t\tautoFocus: false,\n
\t\tdelay: 300,\n
\t\tminLength: 1,\n
\t\tposition: {\n
\t\t\tmy: "left top",\n
\t\t\tat: "left bottom",\n
\t\t\tcollision: "none"\n
\t\t},\n
\t\tsource: null,\n
\n
\t\t// callbacks\n
\t\tchange: null,\n
\t\tclose: null,\n
\t\tfocus: null,\n
\t\topen: null,\n
\t\tresponse: null,\n
\t\tsearch: null,\n
\t\tselect: null\n
\t},\n
\n
\trequestIndex: 0,\n
\tpending: 0,\n
\n
\t_create: function() {\n
\t\t// Some browsers only repeat keydown events, not keypress events,\n
\t\t// so we use the suppressKeyPress flag to determine if we\'ve already\n
\t\t// handled the keydown event. #7269\n
\t\t// Unfortunately the code for & in keypress is the same as the up arrow,\n
\t\t// so we use the suppressKeyPressRepeat flag to avoid handling keypress\n
\t\t// events when we know the keydown event was used to modify the\n
\t\t// search term. #7799\n
\t\tvar suppressKeyPress, suppressKeyPressRepeat, suppressInput,\n
\t\t\tnodeName = this.element[0].nodeName.toLowerCase(),\n
\t\t\tisTextarea = nodeName === "textarea",\n
\t\t\tisInput = nodeName === "input";\n
\n
\t\tthis.isMultiLine =\n
\t\t\t// Textareas are always multi-line\n
\t\t\tisTextarea ? true :\n
\t\t\t// Inputs are always single-line, even if inside a contentEditable element\n
\t\t\t// IE also treats inputs as contentEditable\n
\t\t\tisInput ? false :\n
\t\t\t// All other element types are determined by whether or not they\'re contentEditable\n
\t\t\tthis.element.prop( "isContentEditable" );\n
\n
\t\tthis.valueMethod = this.element[ isTextarea || isInput ? "val" : "text" ];\n
\t\tthis.isNewMenu = true;\n
\n
\t\tthis.element\n
\t\t\t.addClass( "ui-autocomplete-input" )\n
\t\t\t.attr( "autocomplete", "off" );\n
\n
\t\tthis._on( this.element, {\n
\t\t\tkeydown: function( event ) {\n
\t\t\t\tif ( this.element.prop( "readOnly" ) ) {\n
\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\tsuppressInput = true;\n
\t\t\t\t\tsuppressKeyPressRepeat = true;\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tsuppressKeyPress = false;\n
\t\t\t\tsuppressInput = false;\n
\t\t\t\tsuppressKeyPressRepeat = false;\n
\t\t\t\tvar keyCode = $.ui.keyCode;\n
\t\t\t\tswitch( event.keyCode ) {\n
\t\t\t\tcase keyCode.PAGE_UP:\n
\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\tthis._move( "previousPage", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.PAGE_DOWN:\n
\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\tthis._move( "nextPage", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.UP:\n
\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\tthis._keyEvent( "previous", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.DOWN:\n
\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\tthis._keyEvent( "next", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.ENTER:\n
\t\t\t\tcase keyCode.NUMPAD_ENTER:\n
\t\t\t\t\t// when menu is open and has focus\n
\t\t\t\t\tif ( this.menu.active ) {\n
\t\t\t\t\t\t// #6055 - Opera still allows the keypress to occur\n
\t\t\t\t\t\t// which causes forms to submit\n
\t\t\t\t\t\tsuppressKeyPress = true;\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\tthis.menu.select( event );\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.TAB:\n
\t\t\t\t\tif ( this.menu.active ) {\n
\t\t\t\t\t\tthis.menu.select( event );\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.ESCAPE:\n
\t\t\t\t\tif ( this.menu.element.is( ":visible" ) ) {\n
\t\t\t\t\t\tthis._value( this.term );\n
\t\t\t\t\t\tthis.close( event );\n
\t\t\t\t\t\t// Different browsers have different default behavior for escape\n
\t\t\t\t\t\t// Single press can mean undo or clear\n
\t\t\t\t\t\t// Double press in IE means clear the whole form\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tsuppressKeyPressRepeat = true;\n
\t\t\t\t\t// search timeout should be triggered before the input value is changed\n
\t\t\t\t\tthis._searchTimeout( event );\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tkeypress: function( event ) {\n
\t\t\t\tif ( suppressKeyPress ) {\n
\t\t\t\t\tsuppressKeyPress = false;\n
\t\t\t\t\tif ( !this.isMultiLine || this.menu.element.is( ":visible" ) ) {\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tif ( suppressKeyPressRepeat ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\t// replicate some key handlers to allow them to repeat in Firefox and Opera\n
\t\t\t\tvar keyCode = $.ui.keyCode;\n
\t\t\t\tswitch( event.keyCode ) {\n
\t\t\t\tcase keyCode.PAGE_UP:\n
\t\t\t\t\tthis._move( "previousPage", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.PAGE_DOWN:\n
\t\t\t\t\tthis._move( "nextPage", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.UP:\n
\t\t\t\t\tthis._keyEvent( "previous", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase keyCode.DOWN:\n
\t\t\t\t\tthis._keyEvent( "next", event );\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tinput: function( event ) {\n
\t\t\t\tif ( suppressInput ) {\n
\t\t\t\t\tsuppressInput = false;\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tthis._searchTimeout( event );\n
\t\t\t},\n
\t\t\tfocus: function() {\n
\t\t\t\tthis.selectedItem = null;\n
\t\t\t\tthis.previous = this._value();\n
\t\t\t},\n
\t\t\tblur: function( event ) {\n
\t\t\t\tif ( this.cancelBlur ) {\n
\t\t\t\t\tdelete this.cancelBlur;\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tclearTimeout( this.searching );\n
\t\t\t\tthis.close( event );\n
\t\t\t\tthis._change( event );\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis._initSource();\n
\t\tthis.menu = $( "<ul>" )\n
\t\t\t.addClass( "ui-autocomplete ui-front" )\n
\t\t\t.appendTo( this._appendTo() )\n
\t\t\t.menu({\n
\t\t\t\t// disable ARIA support, the live region takes care of that\n
\t\t\t\trole: null\n
\t\t\t})\n
\t\t\t.hide()\n
\t\t\t.data( "ui-menu" );\n
\n
\t\tthis._on( this.menu.element, {\n
\t\t\tmousedown: function( event ) {\n
\t\t\t\t// prevent moving focus out of the text field\n
\t\t\t\tevent.preventDefault();\n
\n
\t\t\t\t// IE doesn\'t prevent moving focus even with event.preventDefault()\n
\t\t\t\t// so we set a flag to know when we should ignore the blur event\n
\t\t\t\tthis.cancelBlur = true;\n
\t\t\t\tthis._delay(function() {\n
\t\t\t\t\tdelete this.cancelBlur;\n
\t\t\t\t});\n
\n
\t\t\t\t// clicking on the scrollbar causes focus to shift to the body\n
\t\t\t\t// but we can\'t detect a mouseup or a click immediately afterward\n
\t\t\t\t// so we have to track the next mousedown and close the menu if\n
\t\t\t\t// the user clicks somewhere outside of the autocomplete\n
\t\t\t\tvar menuElement = this.menu.element[ 0 ];\n
\t\t\t\tif ( !$( event.target ).closest( ".ui-menu-item" ).length ) {\n
\t\t\t\t\tthis._delay(function() {\n
\t\t\t\t\t\tvar that = this;\n
\t\t\t\t\t\tthis.document.one( "mousedown", function( event ) {\n
\t\t\t\t\t\t\tif ( event.target !== that.element[ 0 ] &&\n
\t\t\t\t\t\t\t\t\tevent.target !== menuElement &&\n
\t\t\t\t\t\t\t\t\t!$.contains( menuElement, event.target ) ) {\n
\t\t\t\t\t\t\t\tthat.close();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tmenufocus: function( event, ui ) {\n
\t\t\t\t// support: Firefox\n
\t\t\t\t// Prevent accidental activation of menu items in Firefox (#7024 #9118)\n
\t\t\t\tif ( this.isNewMenu ) {\n
\t\t\t\t\tthis.isNewMenu = false;\n
\t\t\t\t\tif ( event.originalEvent && /^mouse/.test( event.originalEvent.type ) ) {\n
\t\t\t\t\t\tthis.menu.blur();\n
\n
\t\t\t\t\t\tthis.document.one( "mousemove", function() {\n
\t\t\t\t\t\t\t$( event.target ).trigger( event.originalEvent );\n
\t\t\t\t\t\t});\n
\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tvar item = ui.item.data( "ui-autocomplete-item" );\n
\t\t\t\tif ( false !== this._trigger( "focus", event, { item: item } ) ) {\n
\t\t\t\t\t// use value to match what will end up in the input, if it was a key event\n
\t\t\t\t\tif ( event.originalEvent && /^key/.test( event.originalEvent.type ) ) {\n
\t\t\t\t\t\tthis._value( item.value );\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\t// Normally the input is populated with the item\'s value as the\n
\t\t\t\t\t// menu is navigated, causing screen readers to notice a change and\n
\t\t\t\t\t// announce the item. Since the focus event was canceled, this doesn\'t\n
\t\t\t\t\t// happen, so we update the live region so that screen readers can\n
\t\t\t\t\t// still notice the change and announce it.\n
\t\t\t\t\tthis.liveRegion.text( item.value );\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tmenuselect: function( event, ui ) {\n
\t\t\t\tvar item = ui.item.data( "ui-autocomplete-item" ),\n
\t\t\t\t\tprevious = this.previous;\n
\n
\t\t\t\t// only trigger when focus was lost (click on menu)\n
\t\t\t\tif ( this.element[0] !== this.document[0].activeElement ) {\n
\t\t\t\t\tthis.element.focus();\n
\t\t\t\t\tthis.previous = previous;\n
\t\t\t\t\t// #6109 - IE triggers two focus events and the second\n
\t\t\t\t\t// is asynchronous, so we need to reset the previous\n
\t\t\t\t\t// term synchronously and asynchronously :-(\n
\t\t\t\t\tthis._delay(function() {\n
\t\t\t\t\t\tthis.previous = previous;\n
\t\t\t\t\t\tthis.selectedItem = item;\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\n
\t\t\t\tif ( false !== this._trigger( "select", event, { item: item } ) ) {\n
\t\t\t\t\tthis._value( item.value );\n
\t\t\t\t}\n
\t\t\t\t// reset the term after the select event\n
\t\t\t\t// this allows custom select handling to work properly\n
\t\t\t\tthis.term = this._value();\n
\n
\t\t\t\tthis.close( event );\n
\t\t\t\tthis.selectedItem = item;\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis.liveRegion = $( "<span>", {\n
\t\t\t\trole: "status",\n
\t\t\t\t"aria-live": "polite"\n
\t\t\t})\n
\t\t\t.addClass( "ui-helper-hidden-accessible" )\n
\t\t\t.insertBefore( this.element );\n
\n
\t\t// turning off autocomplete prevents the browser from remembering the\n
\t\t// value when navigating through history, so we re-enable autocomplete\n
\t\t// if the page is unloaded before the widget is destroyed. #7790\n
\t\tthis._on( this.window, {\n
\t\t\tbeforeunload: function() {\n
\t\t\t\tthis.element.removeAttr( "autocomplete" );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_destroy: function() {\n
\t\tclearTimeout( this.searching );\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-autocomplete-input" )\n
\t\t\t.removeAttr( "autocomplete" );\n
\t\tthis.menu.element.remove();\n
\t\tthis.liveRegion.remove();\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tthis._super( key, value );\n
\t\tif ( key === "source" ) {\n
\t\t\tthis._initSource();\n
\t\t}\n
\t\tif ( key === "appendTo" ) {\n
\t\t\tthis.menu.element.appendTo( this._appendTo() );\n
\t\t}\n
\t\tif ( key === "disabled" && value && this.xhr ) {\n
\t\t\tthis.xhr.abort();\n
\t\t}\n
\t},\n
\n
\t_appendTo: function() {\n
\t\tvar element = this.options.appendTo;\n
\n
\t\tif ( element ) {\n
\t\t\telement = element.jquery || element.nodeType ?\n
\t\t\t\t$( element ) :\n
\t\t\t\tthis.document.find( element ).eq( 0 );\n
\t\t}\n
\n
\t\tif ( !element ) {\n
\t\t\telement = this.element.closest( ".ui-front" );\n
\t\t}\n
\n
\t\tif ( !element.length ) {\n
\t\t\telement = this.document[0].body;\n
\t\t}\n
\n
\t\treturn element;\n
\t},\n
\n
\t_initSource: function() {\n
\t\tvar array, url,\n
\t\t\tthat = this;\n
\t\tif ( $.isArray(this.options.source) ) {\n
\t\t\tarray = this.options.source;\n
\t\t\tthis.source = function( request, response ) {\n
\t\t\t\tresponse( $.ui.autocomplete.filter( array, request.term ) );\n
\t\t\t};\n
\t\t} else if ( typeof this.options.source === "string" ) {\n
\t\t\turl = this.options.source;\n
\t\t\tthis.source = function( request, response ) {\n
\t\t\t\tif ( that.xhr ) {\n
\t\t\t\t\tthat.xhr.abort();\n
\t\t\t\t}\n
\t\t\t\tthat.xhr = $.ajax({\n
\t\t\t\t\turl: url,\n
\t\t\t\t\tdata: request,\n
\t\t\t\t\tdataType: "json",\n
\t\t\t\t\tsuccess: function( data ) {\n
\t\t\t\t\t\tresponse( data );\n
\t\t\t\t\t},\n
\t\t\t\t\terror: function() {\n
\t\t\t\t\t\tresponse( [] );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t};\n
\t\t} else {\n
\t\t\tthis.source = this.options.source;\n
\t\t}\n
\t},\n
\n
\t_searchTimeout: function( event ) {\n
\t\tclearTimeout( this.searching );\n
\t\tthis.searching = this._delay(function() {\n
\t\t\t// only search if the value has changed\n
\t\t\tif ( this.term !== this._value() ) {\n
\t\t\t\tthis.selectedItem = null;\n
\t\t\t\tthis.search( null, event );\n
\t\t\t}\n
\t\t}, this.options.delay );\n
\t},\n
\n
\tsearch: function( value, event ) {\n
\t\tvalue = value != null ? value : this._value();\n
\n
\t\t// always save the actual value, not the one passed as an argument\n
\t\tthis.term = this._value();\n
\n
\t\tif ( value.length < this.options.minLength ) {\n
\t\t\treturn this.close( event );\n
\t\t}\n
\n
\t\tif ( this._trigger( "search", event ) === false ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\treturn this._search( value );\n
\t},\n
\n
\t_search: function( value ) {\n
\t\tthis.pending++;\n
\t\tthis.element.addClass( "ui-autocomplete-loading" );\n
\t\tthis.cancelSearch = false;\n
\n
\t\tthis.source( { term: value }, this._response() );\n
\t},\n
\n
\t_response: function() {\n
\t\tvar index = ++this.requestIndex;\n
\n
\t\treturn $.proxy(function( content ) {\n
\t\t\tif ( index === this.requestIndex ) {\n
\t\t\t\tthis.__response( content );\n
\t\t\t}\n
\n
\t\t\tthis.pending--;\n
\t\t\tif ( !this.pending ) {\n
\t\t\t\tthis.element.removeClass( "ui-autocomplete-loading" );\n
\t\t\t}\n
\t\t}, this );\n
\t},\n
\n
\t__response: function( content ) {\n
\t\tif ( content ) {\n
\t\t\tcontent = this._normalize( content );\n
\t\t}\n
\t\tthis._trigger( "response", null, { content: content } );\n
\t\tif ( !this.options.disabled && content && content.length && !this.cancelSearch ) {\n
\t\t\tthis._suggest( content );\n
\t\t\tthis._trigger( "open" );\n
\t\t} else {\n
\t\t\t// use ._close() instead of .close() so we don\'t cancel future searches\n
\t\t\tthis._close();\n
\t\t}\n
\t},\n
\n
\tclose: function( event ) {\n
\t\tthis.cancelSearch = true;\n
\t\tthis._close( event );\n
\t},\n
\n
\t_close: function( event ) {\n
\t\tif ( this.menu.element.is( ":visible" ) ) {\n
\t\t\tthis.menu.element.hide();\n
\t\t\tthis.menu.blur();\n
\t\t\tthis.isNewMenu = true;\n
\t\t\tthis._trigger( "close", event );\n
\t\t}\n
\t},\n
\n
\t_change: function( event ) {\n
\t\tif ( this.previous !== this._value() ) {\n
\t\t\tthis._trigger( "change", event, { item: this.selectedItem } );\n
\t\t}\n
\t},\n
\n
\t_normalize: function( items ) {\n
\t\t// assume all items have the right format when the first item is complete\n
\t\tif ( items.length && items[0].label && items[0].value ) {\n
\t\t\treturn items;\n
\t\t}\n
\t\treturn $.map( items, function( item ) {\n
\t\t\tif ( typeof item === "string" ) {\n
\t\t\t\treturn {\n
\t\t\t\t\tlabel: item,\n
\t\t\t\t\tvalue: item\n
\t\t\t\t};\n
\t\t\t}\n
\t\t\treturn $.extend({\n
\t\t\t\tlabel: item.label || item.value,\n
\t\t\t\tvalue: item.value || item.label\n
\t\t\t}, item );\n
\t\t});\n
\t},\n
\n
\t_suggest: function( items ) {\n
\t\tvar ul = this.menu.element.empty();\n
\t\tthis._renderMenu( ul, items );\n
\t\tthis.isNewMenu = true;\n
\t\tthis.menu.refresh();\n
\n
\t\t// size and position menu\n
\t\tul.show();\n
\t\tthis._resizeMenu();\n
\t\tul.position( $.extend({\n
\t\t\tof: this.element\n
\t\t}, this.options.position ));\n
\n
\t\tif ( this.options.autoFocus ) {\n
\t\t\tthis.menu.next();\n
\t\t}\n
\t},\n
\n
\t_resizeMenu: function() {\n
\t\tvar ul = this.menu.element;\n
\t\tul.outerWidth( Math.max(\n
\t\t\t// Firefox wraps long text (possibly a rounding bug)\n
\t\t\t// so we add 1px to avoid the wrapping (#7513)\n
\t\t\tul.width( "" ).outerWidth() + 1,\n
\t\t\tthis.element.outerWidth()\n
\t\t) );\n
\t},\n
\n
\t_renderMenu: function( ul, items ) {\n
\t\tvar that = this;\n
\t\t$.each( items, function( index, item ) {\n
\t\t\tthat._renderItemData( ul, item );\n
\t\t});\n
\t},\n
\n
\t_renderItemData: function( ul, item ) {\n
\t\treturn this._renderItem( ul, item ).data( "ui-autocomplete-item", item );\n
\t},\n
\n
\t_renderItem: function( ul, item ) {\n
\t\treturn $( "<li>" )\n
\t\t\t.append( $( "<a>" ).text( item.label ) )\n
\t\t\t.appendTo( ul );\n
\t},\n
\n
\t_move: function( direction, event ) {\n
\t\tif ( !this.menu.element.is( ":visible" ) ) {\n
\t\t\tthis.search( null, event );\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this.menu.isFirstItem() && /^previous/.test( direction ) ||\n
\t\t\t\tthis.menu.isLastItem() && /^next/.test( direction ) ) {\n
\t\t\tthis._value( this.term );\n
\t\t\tthis.menu.blur();\n
\t\t\treturn;\n
\t\t}\n
\t\tthis.menu[ direction ]( event );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.menu.element;\n
\t},\n
\n
\t_value: function() {\n
\t\treturn this.valueMethod.apply( this.element, arguments );\n
\t},\n
\n
\t_keyEvent: function( keyEvent, event ) {\n
\t\tif ( !this.isMultiLine || this.menu.element.is( ":visible" ) ) {\n
\t\t\tthis._move( keyEvent, event );\n
\n
\t\t\t// prevents moving cursor to beginning/end of the text field in some browsers\n
\t\t\tevent.preventDefault();\n
\t\t}\n
\t}\n
});\n
\n
$.extend( $.ui.autocomplete, {\n
\tescapeRegex: function( value ) {\n
\t\treturn value.replace(/[\\-\\[\\]{}()*+?.,\\\\\\^$|#\\s]/g, "\\\\$&");\n
\t},\n
\tfilter: function(array, term) {\n
\t\tvar matcher = new RegExp( $.ui.autocomplete.escapeRegex(term), "i" );\n
\t\treturn $.grep( array, function(value) {\n
\t\t\treturn matcher.test( value.label || value.value || value );\n
\t\t});\n
\t}\n
});\n
\n
\n
// live region extension, adding a `messages` option\n
// NOTE: This is an experimental API. We are still investigating\n
// a full solution for string manipulation and internationalization.\n
$.widget( "ui.autocomplete", $.ui.autocomplete, {\n
\toptions: {\n
\t\tmessages: {\n
\t\t\tnoResults: "No search results.",\n
\t\t\tresults: function( amount ) {\n
\t\t\t\treturn amount + ( amount > 1 ? " results are" : " result is" ) +\n
\t\t\t\t\t" available, use up and down arrow keys to navigate.";\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t__response: function( content ) {\n
\t\tvar message;\n
\t\tthis._superApply( arguments );\n
\t\tif ( this.options.disabled || this.cancelSearch ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( content && content.length ) {\n
\t\t\tmessage = this.options.messages.results( content.length );\n
\t\t} else {\n
\t\t\tmessage = this.options.messages.noResults;\n
\t\t}\n
\t\tthis.liveRegion.text( message );\n
\t}\n
});\n
\n
}( jQuery ));\n
(function( $, undefined ) {\n
\n
var lastActive,\n
\tbaseClasses = "ui-button ui-widget ui-state-default ui-corner-all",\n
\ttypeClasses = "ui-button-icons-only ui-button-icon-only ui-button-text-icons ui-button-text-icon-primary ui-button-text-icon-secondary ui-button-text-only",\n
\tformResetHandler = function() {\n
\t\tvar form = $( this );\n
\t\tsetTimeout(function() {\n
\t\t\tform.find( ":ui-button" ).button( "refresh" );\n
\t\t}, 1 );\n
\t},\n
\tradioGroup = function( radio ) {\n
\t\tvar name = radio.name,\n
\t\t\tform = radio.form,\n
\t\t\tradios = $( [] );\n
\t\tif ( name ) {\n
\t\t\tname = name.replace( /\'/g, "\\\\\'" );\n
\t\t\tif ( form ) {\n
\t\t\t\tradios = $( form ).find( "[name=\'" + name + "\']" );\n
\t\t\t} else {\n
\t\t\t\tradios = $( "[name=\'" + name + "\']", radio.ownerDocument )\n
\t\t\t\t\t.filter(function() {\n
\t\t\t\t\t\treturn !this.form;\n
\t\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\t\treturn radios;\n
\t};\n
\n
$.widget( "ui.button", {\n
\tversion: "1.10.4",\n
\tdefaultElement: "<button>",\n
\toptions: {\n
\t\tdisabled: null,\n
\t\ttext: true,\n
\t\tlabel: null,\n
\t\ticons: {\n
\t\t\tprimary: null,\n
\t\t\tsecondary: null\n
\t\t}\n
\t},\n
\t_create: function() {\n
\t\tthis.element.closest( "form" )\n
\t\t\t.unbind( "reset" + this.eventNamespace )\n
\t\t\t.bind( "reset" + this.eventNamespace, formResetHandler );\n
\n
\t\tif ( typeof this.options.disabled !== "boolean" ) {\n
\t\t\tthis.options.disabled = !!this.element.prop( "disabled" );\n
\t\t} else {\n
\t\t\tthis.element.prop( "disabled", this.options.disabled );\n
\t\t}\n
\n
\t\tthis._determineButtonType();\n
\t\tthis.hasTitle = !!this.buttonElement.attr( "title" );\n
\n
\t\tvar that = this,\n
\t\t\toptions = this.options,\n
\t\t\ttoggleButton = this.type === "checkbox" || this.type === "radio",\n
\t\t\tactiveClass = !toggleButton ? "ui-state-active" : "";\n
\n
\t\tif ( options.label === null ) {\n
\t\t\toptions.label = (this.type === "input" ? this.buttonElement.val() : this.buttonElement.html());\n
\t\t}\n
\n
\t\tthis._hoverable( this.buttonElement );\n
\n
\t\tthis.buttonElement\n
\t\t\t.addClass( baseClasses )\n
\t\t\t.attr( "role", "button" )\n
\t\t\t.bind( "mouseenter" + this.eventNamespace, function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tif ( this === lastActive ) {\n
\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t.bind( "mouseleave" + this.eventNamespace, function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t$( this ).removeClass( activeClass );\n
\t\t\t})\n
\t\t\t.bind( "click" + this.eventNamespace, function( event ) {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t// Can\'t use _focusable() because the element that receives focus\n
\t\t// and the element that gets the ui-state-focus class are different\n
\t\tthis._on({\n
\t\t\tfocus: function() {\n
\t\t\t\tthis.buttonElement.addClass( "ui-state-focus" );\n
\t\t\t},\n
\t\t\tblur: function() {\n
\t\t\t\tthis.buttonElement.removeClass( "ui-state-focus" );\n
\t\t\t}\n
\t\t});\n
\n
\t\tif ( toggleButton ) {\n
\t\t\tthis.element.bind( "change" + this.eventNamespace, function() {\n
\t\t\t\tthat.refresh();\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this.type === "checkbox" ) {\n
\t\t\tthis.buttonElement.bind( "click" + this.eventNamespace, function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else if ( this.type === "radio" ) {\n
\t\t\tthis.buttonElement.bind( "click" + this.eventNamespace, function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\tthat.buttonElement.attr( "aria-pressed", "true" );\n
\n
\t\t\t\tvar radio = that.element[ 0 ];\n
\t\t\t\tradioGroup( radio )\n
\t\t\t\t\t.not( radio )\n
\t\t\t\t\t.map(function() {\n
\t\t\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t\t\t})\n
\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", "false" );\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis.buttonElement\n
\t\t\t\t.bind( "mousedown" + this.eventNamespace, function() {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t\tlastActive = this;\n
\t\t\t\t\tthat.document.one( "mouseup", function() {\n
\t\t\t\t\t\tlastActive = null;\n
\t\t\t\t\t});\n
\t\t\t\t})\n
\t\t\t\t.bind( "mouseup" + this.eventNamespace, function() {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\t$( this ).removeClass( "ui-state-active" );\n
\t\t\t\t})\n
\t\t\t\t.bind( "keydown" + this.eventNamespace, function(event) {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( event.keyCode === $.ui.keyCode.SPACE || event.keyCode === $.ui.keyCode.ENTER ) {\n
\t\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t\t}\n
\t\t\t\t})\n
\t\t\t\t// see #8559, we bind to blur here in case the button element loses\n
\t\t\t\t// focus between keydown and keyup, it would be left in an "active" state\n
\t\t\t\t.bind( "keyup" + this.eventNamespace + " blur" + this.eventNamespace, function() {\n
\t\t\t\t\t$( this ).removeClass( "ui-state-active" );\n
\t\t\t\t});\n
\n
\t\t\tif ( this.buttonElement.is("a") ) {\n
\t\t\t\tthis.buttonElement.keyup(function(event) {\n
\t\t\t\t\tif ( event.keyCode === $.ui.keyCode.SPACE ) {\n
\t\t\t\t\t\t// TODO pass through original event correctly (just as 2nd argument doesn\'t work)\n
\t\t\t\t\t\t$( this ).click();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t\t// TODO: pull out $.Widget\'s handling for the disabled option into\n
\t\t// $.Widget.prototype._setOptionDisabled so it\'s easy to proxy and can\n
\t\t// be overridden by individual plugins\n
\t\tthis._setOption( "disabled", options.disabled );\n
\t\tthis._resetButton();\n
\t},\n
\n
\t_determineButtonType: function() {\n
\t\tvar ancestor, labelSelector, checked;\n
\n
\t\tif ( this.element.is("[type=checkbox]") ) {\n
\t\t\tthis.type = "checkbox";\n
\t\t} else if ( this.element.is("[type=radio]") ) {\n
\t\t\tthis.type = "radio";\n
\t\t} else if ( this.element.is("input") ) {\n
\t\t\tthis.type = "input";\n
\t\t} else {\n
\t\t\tthis.type = "button";\n
\t\t}\n
\n
\t\tif ( this.type === "checkbox" || this.type === "radio" ) {\n
\t\t\t// we don\'t search against the document in case the element\n
\t\t\t// is disconnected from the DOM\n
\t\t\tancestor = this.element.parents().last();\n
\t\t\tlabelSelector = "label[for=\'" + this.element.attr("id") + "\']";\n
\t\t\tthis.buttonElement = ancestor.find( labelSelector );\n
\t\t\tif ( !this.buttonElement.length ) {\n
\t\t\t\tancestor = ancestor.length ? ancestor.siblings() : this.element.siblings();\n
\t\t\t\tthis.buttonElement = ancestor.filter( labelSelector );\n
\t\t\t\tif ( !this.buttonElement.length ) {\n
\t\t\t\t\tthis.buttonElement = ancestor.find( labelSelector );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis.element.addClass( "ui-helper-hidden-accessible" );\n
\n
\t\t\tchecked = this.element.is( ":checked" );\n
\t\t\tif ( checked ) {\n
\t\t\t\tthis.buttonElement.addClass( "ui-state-active" );\n
\t\t\t}\n
\t\t\tthis.buttonElement.prop( "aria-pressed", checked );\n
\t\t} else {\n
\t\t\tthis.buttonElement = this.element;\n
\t\t}\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.buttonElement;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-helper-hidden-accessible" );\n
\t\tthis.buttonElement\n
\t\t\t.removeClass( baseClasses + " ui-state-active " + typeClasses )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-pressed" )\n
\t\t\t.html( this.buttonElement.find(".ui-button-text").html() );\n
\n
\t\tif ( !this.hasTitle ) {\n
\t\t\tthis.buttonElement.removeAttr( "title" );\n
\t\t}\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tthis._super( key, value );\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.element.prop( "disabled", !!value );\n
\t\t\tif ( value ) {\n
\t\t\t\tthis.buttonElement.removeClass( "ui-state-focus" );\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\t\tthis._resetButton();\n
\t},\n
\n
\trefresh: function() {\n
\t\t//See #8237 & #8828\n
\t\tvar isDisabled = this.element.is( "input, button" ) ? this.element.is( ":disabled" ) : this.element.hasClass( "ui-button-disabled" );\n
\n
\t\tif ( isDisabled !== this.options.disabled ) {\n
\t\t\tthis._setOption( "disabled", isDisabled );\n
\t\t}\n
\t\tif ( this.type === "radio" ) {\n
\t\t\tradioGroup( this.element[0] ).each(function() {\n
\t\t\t\tif ( $( this ).is( ":checked" ) ) {\n
\t\t\t\t\t$( this ).button( "widget" )\n
\t\t\t\t\t\t.addClass( "ui-state-active" )\n
\t\t\t\t\t\t.attr( "aria-pressed", "true" );\n
\t\t\t\t} else {\n
\t\t\t\t\t$( this ).button( "widget" )\n
\t\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t\t.attr( "aria-pressed", "false" );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else if ( this.type === "checkbox" ) {\n
\t\t\tif ( this.element.is( ":checked" ) ) {\n
\t\t\t\tthis.buttonElement\n
\t\t\t\t\t.addClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", "true" );\n
\t\t\t} else {\n
\t\t\t\tthis.buttonElement\n
\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", "false" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_resetButton: function() {\n
\t\tif ( this.type === "input" ) {\n
\t\t\tif ( this.options.label ) {\n
\t\t\t\tthis.element.val( this.options.label );\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\t\tvar buttonElement = this.buttonElement.removeClass( typeClasses ),\n
\t\t\tbuttonText = $( "<span></span>", this.document[0] )\n
\t\t\t\t.addClass( "ui-button-text" )\n
\t\t\t\t.html( this.options.label )\n
\t\t\t\t.appendTo( buttonElement.empty() )\n
\t\t\t\t.text(),\n
\t\t\ticons = this.options.icons,\n
\t\t\tmultipleIcons = icons.primary && icons.secondary,\n
\t\t\tbuttonClasses = [];\n
\n
\t\tif ( icons.primary || icons.secondary ) {\n
\t\t\tif ( this.options.text ) {\n
\t\t\t\tbuttonClasses.push( "ui-button-text-icon" + ( multipleIcons ? "s" : ( icons.primary ? "-primary" : "-secondary" ) ) );\n
\t\t\t}\n
\n
\t\t\tif ( icons.primary ) {\n
\t\t\t\tbuttonElement.prepend( "<span class=\'ui-button-icon-primary ui-icon " + icons.primary + "\'></span>" );\n
\t\t\t}\n
\n
\t\t\tif ( icons.secondary ) {\n
\t\t\t\tbuttonElement.append( "<span class=\'ui-button-icon-secondary ui-icon " + icons.secondary + "\'></span>" );\n
\t\t\t}\n
\n
\t\t\tif ( !this.options.text ) {\n
\t\t\t\tbuttonClasses.push( multipleIcons ? "ui-button-icons-only" : "ui-button-icon-only" );\n
\n
\t\t\t\tif ( !this.hasTitle ) {\n
\t\t\t\t\tbuttonElement.attr( "title", $.trim( buttonText ) );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tbuttonClasses.push( "ui-button-text-only" );\n
\t\t}\n
\t\tbuttonElement.addClass( buttonClasses.join( " " ) );\n
\t}\n
});\n
\n
$.widget( "ui.buttonset", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\titems: "button, input[type=button], input[type=submit], input[type=reset], input[type=checkbox], input[type=radio], a, :data(ui-button)"\n
\t},\n
\n
\t_create: function() {\n
\t\tthis.element.addClass( "ui-buttonset" );\n
\t},\n
\n
\t_init: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.buttons.button( "option", key, value );\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar rtl = this.element.css( "direction" ) === "rtl";\n
\n
\t\tthis.buttons = this.element.find( this.options.items )\n
\t\t\t.filter( ":ui-button" )\n
\t\t\t\t.button( "refresh" )\n
\t\t\t.end()\n
\t\t\t.not( ":ui-button" )\n
\t\t\t\t.button()\n
\t\t\t.end()\n
\t\t\t.map(function() {\n
\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t})\n
\t\t\t\t.removeClass( "ui-corner-all ui-corner-left ui-corner-right" )\n
\t\t\t\t.filter( ":first" )\n
\t\t\t\t\t.addClass( rtl ? "ui-corner-right" : "ui-corner-left" )\n
\t\t\t\t.end()\n
\t\t\t\t.filter( ":last" )\n
\t\t\t\t\t.addClass( rtl ? "ui-corner-left" : "ui-corner-right" )\n
\t\t\t\t.end()\n
\t\t\t.end();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element.removeClass( "ui-buttonset" );\n
\t\tthis.buttons\n
\t\t\t.map(function() {\n
\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t})\n
\t\t\t\t.removeClass( "ui-corner-left ui-corner-right" )\n
\t\t\t.end()\n
\t\t\t.button( "destroy" );\n
\t}\n
});\n
\n
}( jQuery ) );\n
(function( $, undefined ) {\n
\n
$.extend($.ui, { datepicker: { version: "1.10.4" } });\n
\n
var PROP_NAME = "datepicker",\n
\tinstActive;\n
\n
/* Date picker manager.\n
   Use the singleton instance of this class, $.datepicker, to interact with the date picker.\n
   Settings for (groups of) date pickers are maintained in an instance object,\n
   allowing multiple different settings on the same page. */\n
\n
function Datepicker() {\n
\tthis._curInst = null; // The current instance in use\n
\tthis._keyEvent = false; // If the last event was a key event\n
\tthis._disabledInputs = []; // List of date picker inputs that have been disabled\n
\tthis._datepickerShowing = false; // True if the popup picker is showing , false if not\n
\tthis._inDialog = false; // True if showing within a "dialog", false if not\n
\tthis._mainDivId = "ui-datepicker-div"; // The ID of the main datepicker division\n
\tthis._inlineClass = "ui-datepicker-inline"; // The name of the inline marker class\n
\tthis._appendClass = "ui-datepicker-append"; // The name of the append marker class\n
\tthis._triggerClass = "ui-datepicker-trigger"; // The name of the trigger marker class\n
\tthis._dialogClass = "ui-datepicker-dialog"; // The name of the dialog marker class\n
\tthis._disableClass = "ui-datepicker-disabled"; // The name of the disabled covering marker class\n
\tthis._unselectableClass = "ui-datepicker-unselectable"; // The name of the unselectable cell marker class\n
\tthis._currentClass = "ui-datepicker-current-day"; // The name of the current day marker class\n
\tthis._dayOverClass = "ui-datepicker-days-cell-over"; // The name of the day hover marker class\n
\tthis.regional = []; // Available regional settings, indexed by language code\n
\tthis.regional[""] = { // Default regional settings\n
\t\tcloseText: "Done", // Display text for close link\n
\t\tprevText: "Prev", // Display text for previous month link\n
\t\tnextText: "Next", // Display text for next month link\n
\t\tcurrentText: "Today", // Display text for current month link\n
\t\tmonthNames: ["January","February","March","April","May","June",\n
\t\t\t"July","August","September","October","November","December"], // Names of months for drop-down and formatting\n
\t\tmonthNamesShort: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], // For formatting\n
\t\tdayNames: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"], // For formatting\n
\t\tdayNamesShort: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], // For formatting\n
\t\tdayNamesMin: ["Su","Mo","Tu","We","Th","Fr","Sa"], // Column headings for days starting at Sunday\n
\t\tweekHeader: "Wk", // Column header for week of the year\n
\t\tdateFormat: "mm/dd/yy", // See format options on parseDate\n
\t\tfirstDay: 0, // The first day of the week, Sun = 0, Mon = 1, ...\n
\t\tisRTL: false, // True if right-to-left language, false if left-to-right\n
\t\tshowMonthAfterYear: false, // True if the year select precedes month, false for month then year\n
\t\tyearSuffix: "" // Additional text to append to the year in the month headers\n
\t};\n
\tthis._defaults = { // Global defaults for all the date picker instances\n
\t\tshowOn: "focus", // "focus" for popup on focus,\n
\t\t\t// "button" for trigger button, or "both" for either\n
\t\tshowAnim: "fadeIn", // Name of jQuery animation for popup\n
\t\tshowOptions: {}, // Options for enhanced animations\n
\t\tdefaultDate: null, // Used when field is blank: actual date,\n
\t\t\t// +/-number for offset from today, null for today\n
\t\tappendText: "", // Display text following the input box, e.g. showing the format\n
\t\tbuttonText: "...", // Text for trigger button\n
\t\tbuttonImage: "", // URL for trigger button image\n
\t\tbuttonImageOnly: false, // True if the image appears alone, false if it appears on a button\n
\t\thideIfNoPrevNext: false, // True to hide next/previous month links\n
\t\t\t// if not applicable, false to just disable them\n
\t\tnavigationAsDateFormat: false, // True if date formatting applied to prev/today/next links\n
\t\tgotoCurrent: false, // True if today link goes back to current selection instead\n
\t\tchangeMonth: false, // True if month can be selected directly, false if only prev/next\n
\t\tchangeYear: false, // True if year can be selected directly, false if only prev/next\n
\t\tyearRange: "c-10:c+10", // Range of years to display in drop-down,\n
\t\t\t// either relative to today\'s year (-nn:+nn), relative to currently displayed year\n
\t\t\t// (c-nn:c+nn), absolute (nnnn:nnnn), or a combination of the above (nnnn:-n)\n
\t\tshowOtherMonths: false, // True to show dates in other months, false to leave blank\n
\t\tselectOtherMonths: false, // True to allow selection of dates in other months, false for unselectable\n
\t\tshowWeek: false, // True to show week of the year, false to not show it\n
\t\tcalculateWeek: this.iso8601Week, // How to calculate the week of the year,\n
\t\t\t// takes a Date and returns the number of the week for it\n
\t\tshortYearCutoff: "+10", // Short year values < this are in the current century,\n
\t\t\t// > this are in the previous century,\n
\t\t\t// string value starting with "+" for current year + value\n
\t\tminDate: null, // The earliest selectable date, or null for no limit\n
\t\tmaxDate: null, // The latest selectable date, or null for no limit\n
\t\tduration: "fast", // Duration of display/closure\n
\t\tbeforeShowDay: null, // Function that takes a date and returns an array with\n
\t\t\t// [0] = true if selectable, false if not, [1] = custom CSS class name(s) or "",\n
\t\t\t// [2] = cell title (optional), e.g. $.datepicker.noWeekends\n
\t\tbeforeShow: null, // Function that takes an input field and\n
\t\t\t// returns a set of custom settings for the date picker\n
\t\tonSelect: null, // Define a callback function when a date is selected\n
\t\tonChangeMonthYear: null, // Define a callback function when the month or year is changed\n
\t\tonClose: null, // Define a callback function when the datepicker is closed\n
\t\tnumberOfMonths: 1, // Number of months to show at a time\n
\t\tshowCurrentAtPos: 0, // The position in multipe months at which to show the current month (starting at 0)\n
\t\tstepMonths: 1, // Number of months to step back/forward\n
\t\tstepBigMonths: 12, // Number of months to step back/forward for the big links\n
\t\taltField: "", // Selector for an alternate field to store selected dates into\n
\t\taltFormat: "", // The date format to use for the alternate field\n
\t\tconstrainInput: true, // The input is constrained by the current date format\n
\t\tshowButtonPanel: false, // True to show button panel, false to not show it\n
\t\tautoSize: false, // True to size the input for the date format, false to leave as is\n
\t\tdisabled: false // The initial disabled state\n
\t};\n
\t$.extend(this._defaults, this.regional[""]);\n
\tthis.dpDiv = bindHover($("<div id=\'" + this._mainDivId + "\' class=\'ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all\'></div>"));\n
}\n
\n
$.extend(Datepicker.prototype, {\n
\t/* Class name added to elements to indicate already configured with a date picker. */\n
\tmarkerClassName: "hasDatepicker",\n
\n
\t//Keep track of the maximum number of rows displayed (see #7043)\n
\tmaxRows: 4,\n
\n
\t// TODO rename to "widget" when switching to widget factory\n
\t_widgetDatepicker: function() {\n
\t\treturn this.dpDiv;\n
\t},\n
\n
\t/* Override the default settings for all instances of the date picker.\n
\t * @param  settings  object - the new settings to use as defaults (anonymous object)\n
\t * @return the manager object\n
\t */\n
\tsetDefaults: function(settings) {\n
\t\textendRemove(this._defaults, settings || {});\n
\t\treturn this;\n
\t},\n
\n
\t/* Attach the date picker to a jQuery selection.\n
\t * @param  target\telement - the target input field or division or span\n
\t * @param  settings  object - the new settings to use for this date picker instance (anonymous)\n
\t */\n
\t_attachDatepicker: function(target, settings) {\n
\t\tvar nodeName, inline, inst;\n
\t\tnodeName = target.nodeName.toLowerCase();\n
\t\tinline = (nodeName === "div" || nodeName === "span");\n
\t\tif (!target.id) {\n
\t\t\tthis.uuid += 1;\n
\t\t\ttarget.id = "dp" + this.uuid;\n
\t\t}\n
\t\tinst = this._newInst($(target), inline);\n
\t\tinst.settings = $.extend({}, settings || {});\n
\t\tif (nodeName === "input") {\n
\t\t\tthis._connectDatepicker(target, inst);\n
\t\t} else if (inline) {\n
\t\t\tthis._inlineDatepicker(target, inst);\n
\t\t}\n
\t},\n
\n
\t/* Create a new instance object. */\n
\t_newInst: function(target, inline) {\n
\t\tvar id = target[0].id.replace(/([^A-Za-z0-9_\\-])/g, "\\\\\\\\$1"); // escape jQuery meta chars\n
\t\treturn {id: id, input: target, // associated target\n
\t\t\tselectedDay: 0, selectedMonth: 0, selectedYear: 0, // current selection\n
\t\t\tdrawMonth: 0, drawYear: 0, // month being drawn\n
\t\t\tinline: inline, // is datepicker inline or not\n
\t\t\tdpDiv: (!inline ? this.dpDiv : // presentation div\n
\t\t\tbindHover($("<div class=\'" + this._inlineClass + " ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all\'></div>")))};\n
\t},\n
\n
\t/* Attach the date picker to an input field. */\n
\t_connectDatepicker: function(target, inst) {\n
\t\tvar input = $(target);\n
\t\tinst.append = $([]);\n
\t\tinst.trigger = $([]);\n
\t\tif (input.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\t\tthis._attachments(input, inst);\n
\t\tinput.addClass(this.markerClassName).keydown(this._doKeyDown).\n
\t\t\tkeypress(this._doKeyPress).keyup(this._doKeyUp);\n
\t\tthis._autoSize(inst);\n
\t\t$.data(target, PROP_NAME, inst);\n
\t\t//If disabled option is true, disable the datepicker once it has been attached to the input (see ticket #5665)\n
\t\tif( inst.settings.disabled ) {\n
\t\t\tthis._disableDatepicker( target );\n
\t\t}\n
\t},\n
\n
\t/* Make attachments based on settings. */\n
\t_attachments: function(input, inst) {\n
\t\tvar showOn, buttonText, buttonImage,\n
\t\t\tappendText = this._get(inst, "appendText"),\n
\t\t\tisRTL = this._get(inst, "isRTL");\n
\n
\t\tif (inst.append) {\n
\t\t\tinst.append.remove();\n
\t\t}\n
\t\tif (appendText) {\n
\t\t\tinst.append = $("<span class=\'" + this._appendClass + "\'>" + appendText + "</span>");\n
\t\t\tinput[isRTL ? "before" : "after"](inst.append);\n
\t\t}\n
\n
\t\tinput.unbind("focus", this._showDatepicker);\n
\n
\t\tif (inst.trigger) {\n
\t\t\tinst.trigger.remove();\n
\t\t}\n
\n
\t\tshowOn = this._get(inst, "showOn");\n
\t\tif (showOn === "focus" || showOn === "both") { // pop-up date picker when in the marked field\n
\t\t\tinput.focus(this._showDatepicker);\n
\t\t}\n
\t\tif (showOn === "button" || showOn === "both") { // pop-up date picker when button clicked\n
\t\t\tbuttonText = this._get(inst, "buttonText");\n
\t\t\tbuttonImage = this._get(inst, "buttonImage");\n
\t\t\tinst.trigger = $(this._get(inst, "buttonImageOnly") ?\n
\t\t\t\t$("<img/>").addClass(this._triggerClass).\n
\t\t\t\t\tattr({ src: buttonImage, alt: buttonText, title: buttonText }) :\n
\t\t\t\t$("<button type=\'button\'></button>").addClass(this._triggerClass).\n
\t\t\t\t\thtml(!buttonImage ? buttonText : $("<img/>").attr(\n
\t\t\t\t\t{ src:buttonImage, alt:buttonText, title:buttonText })));\n
\t\t\tinput[isRTL ? "before" : "after"](inst.trigger);\n
\t\t\tinst.trigger.click(function() {\n
\t\t\t\tif ($.datepicker._datepickerShowing && $.datepicker._lastInput === input[0]) {\n
\t\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t\t\t} else if ($.datepicker._datepickerShowing && $.datepicker._lastInput !== input[0]) {\n
\t\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t\t\t\t$.datepicker._showDatepicker(input[0]);\n
\t\t\t\t} else {\n
\t\t\t\t\t$.datepicker._showDatepicker(input[0]);\n
\t\t\t\t}\n
\t\t\t\treturn false;\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\t/* Apply the maximum length for the date format. */\n
\t_autoSize: function(inst) {\n
\t\tif (this._get(inst, "autoSize") && !inst.inline) {\n
\t\t\tvar findMax, max, maxI, i,\n
\t\t\t\tdate = new Date(2009, 12 - 1, 20), // Ensure double digits\n
\t\t\t\tdateFormat = this._get(inst, "dateFormat");\n
\n
\t\t\tif (dateFormat.match(/[DM]/)) {\n
\t\t\t\tfindMax = function(names) {\n
\t\t\t\t\tmax = 0;\n
\t\t\t\t\tmaxI = 0;\n
\t\t\t\t\tfor (i = 0; i < names.length; i++) {\n
\t\t\t\t\t\tif (names[i].length > max) {\n
\t\t\t\t\t\t\tmax = names[i].length;\n
\t\t\t\t\t\t\tmaxI = i;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn maxI;\n
\t\t\t\t};\n
\t\t\t\tdate.setMonth(findMax(this._get(inst, (dateFormat.match(/MM/) ?\n
\t\t\t\t\t"monthNames" : "monthNamesShort"))));\n
\t\t\t\tdate.setDate(findMax(this._get(inst, (dateFormat.match(/DD/) ?\n
\t\t\t\t\t"dayNames" : "dayNamesShort"))) + 20 - date.getDay());\n
\t\t\t}\n
\t\t\tinst.input.attr("size", this._formatDate(inst, date).length);\n
\t\t}\n
\t},\n
\n
\t/* Attach an inline date picker to a div. */\n
\t_inlineDatepicker: function(target, inst) {\n
\t\tvar divSpan = $(target);\n
\t\tif (divSpan.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\t\tdivSpan.addClass(this.markerClassName).append(inst.dpDiv);\n
\t\t$.data(target, PROP_NAME, inst);\n
\t\tthis._setDate(inst, this._getDefaultDate(inst), true);\n
\t\tthis._updateDatepicker(inst);\n
\t\tthis._updateAlternate(inst);\n
\t\t//If disabled option is true, disable the datepicker before showing it (see ticket #5665)\n
\t\tif( inst.settings.disabled ) {\n
\t\t\tthis._disableDatepicker( target );\n
\t\t}\n
\t\t// Set display:block in place of inst.dpDiv.show() which won\'t work on disconnected elements\n
\t\t// http://bugs.jqueryui.com/ticket/7552 - A Datepicker created on a detached div has zero height\n
\t\tinst.dpDiv.css( "display", "block" );\n
\t},\n
\n
\t/* Pop-up the date picker in a "dialog" box.\n
\t * @param  input element - ignored\n
\t * @param  date\tstring or Date - the initial date to display\n
\t * @param  onSelect  function - the function to call when a date is selected\n
\t * @param  settings  object - update the dialog date picker instance\'s settings (anonymous object)\n
\t * @param  pos int[2] - coordinates for the dialog\'s position within the screen or\n
\t *\t\t\t\t\tevent - with x/y coordinates or\n
\t *\t\t\t\t\tleave empty for default (screen centre)\n
\t * @return the manager object\n
\t */\n
\t_dialogDatepicker: function(input, date, onSelect, settings, pos) {\n
\t\tvar id, browserWidth, browserHeight, scrollX, scrollY,\n
\t\t\tinst = this._dialogInst; // internal instance\n
\n
\t\tif (!inst) {\n
\t\t\tthis.uuid += 1;\n
\t\t\tid = "dp" + this.uuid;\n
\t\t\tthis._dialogInput = $("<input type=\'text\' id=\'" + id +\n
\t\t\t\t"\' style=\'position: absolute; top: -100px; width: 0px;\'/>");\n
\t\t\tthis._dialogInput.keydown(this._doKeyDown);\n
\t\t\t$("body").append(this._dialogInput);\n
\t\t\tinst = this._dialogInst = this._newInst(this._dialogInput, false);\n
\t\t\tinst.settings = {};\n
\t\t\t$.data(this._dialogInput[0], PROP_NAME, inst);\n
\t\t}\n
\t\textendRemove(inst.settings, settings || {});\n
\t\tdate = (date && date.constructor === Date ? this._formatDate(inst, date) : date);\n
\t\tthis._dialogInput.val(date);\n
\n
\t\tthis._pos = (pos ? (pos.length ? pos : [pos.pageX, pos.pageY]) : null);\n
\t\tif (!this._pos) {\n
\t\t\tbrowserWidth = document.documentElement.clientWidth;\n
\t\t\tbrowserHeight = document.documentElement.clientHeight;\n
\t\t\tscrollX = document.documentElement.scrollLeft || document.body.scrollLeft;\n
\t\t\tscrollY = document.documentElement.scrollTop || document.body.scrollTop;\n
\t\t\tthis._pos = // should use actual width/height below\n
\t\t\t\t[(browserWidth / 2) - 100 + scrollX, (browserHeight / 2) - 150 + scrollY];\n
\t\t}\n
\n
\t\t// move input on screen for focus, but hidden behind dialog\n
\t\tthis._dialogInput.css("left", (this._pos[0] + 20) + "px").css("top", this._pos[1] + "px");\n
\t\tinst.settings.onSelect = onSelect;\n
\t\tthis._inDialog = true;\n
\t\tthis.dpDiv.addClass(this._dialogClass);\n
\t\tthis._showDatepicker(this._dialogInput[0]);\n
\t\tif ($.blockUI) {\n
\t\t\t$.blockUI(this.dpDiv);\n
\t\t}\n
\t\t$.data(this._dialogInput[0], PROP_NAME, inst);\n
\t\treturn this;\n
\t},\n
\n
\t/* Detach a datepicker from its control.\n
\t * @param  target\telement - the target input field or division or span\n
\t */\n
\t_destroyDatepicker: function(target) {\n
\t\tvar nodeName,\n
\t\t\t$target = $(target),\n
\t\t\tinst = $.data(target, PROP_NAME);\n
\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tnodeName = target.nodeName.toLowerCase();\n
\t\t$.removeData(target, PROP_NAME);\n
\t\tif (nodeName === "input") {\n
\t\t\tinst.append.remove();\n
\t\t\tinst.trigger.remove();\n
\t\t\t$target.removeClass(this.markerClassName).\n
\t\t\t\tunbind("focus", this._showDatepicker).\n
\t\t\t\tunbind("keydown", this._doKeyDown).\n
\t\t\t\tunbind("keypress", this._doKeyPress).\n
\t\t\t\tunbind("keyup", this._doKeyUp);\n
\t\t} else if (nodeName === "div" || nodeName === "span") {\n
\t\t\t$target.removeClass(this.markerClassName).empty();\n
\t\t}\n
\t},\n
\n
\t/* Enable the date picker to a jQuery selection.\n
\t * @param  target\telement - the target input field or division or span\n
\t */\n
\t_enableDatepicker: function(target) {\n
\t\tvar nodeName, inline,\n
\t\t\t$target = $(target),\n
\t\t\tinst = $.data(target, PROP_NAME);\n
\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tnodeName = target.nodeName.toLowerCase();\n
\t\tif (nodeName === "input") {\n
\t\t\ttarget.disabled = false;\n
\t\t\tinst.trigger.filter("button").\n
\t\t\t\teach(function() { this.disabled = false; }).end().\n
\t\t\t\tfilter("img").css({opacity: "1.0", cursor: ""});\n
\t\t} else if (nodeName === "div" || nodeName === "span") {\n
\t\t\tinline = $target.children("." + this._inlineClass);\n
\t\t\tinline.children().removeClass("ui-state-disabled");\n
\t\t\tinline.find("select.ui-datepicker-month, select.ui-datepicker-year").\n
\t\t\t\tprop("disabled", false);\n
\t\t}\n
\t\tthis._disabledInputs = $.map(this._disabledInputs,\n
\t\t\tfunction(value) { return (value === target ? null : value); }); // delete entry\n
\t},\n
\n
\t/* Disable the date picker to a jQuery selection.\n
\t * @param  target\telement - the target input field or division or span\n
\t */\n
\t_disableDatepicker: function(target) {\n
\t\tvar nodeName, inline,\n
\t\t\t$target = $(target),\n
\t\t\tinst = $.data(target, PROP_NAME);\n
\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tnodeName = target.nodeName.toLowerCase();\n
\t\tif (nodeName === "input") {\n
\t\t\ttarget.disabled = true;\n
\t\t\tinst.trigger.filter("button").\n
\t\t\t\teach(function() { this.disabled = true; }).end().\n
\t\t\t\tfilter("img").css({opacity: "0.5", cursor: "default"});\n
\t\t} else if (nodeName === "div" || nodeName === "span") {\n
\t\t\tinline = $target.children("." + this._inlineClass);\n
\t\t\tinline.children().addClass("ui-state-disabled");\n
\t\t\tinline.find("select.ui-datepicker-month, select.ui-datepicker-year").\n
\t\t\t\tprop("disabled", true);\n
\t\t}\n
\t\tthis._disabledInputs = $.map(this._disabledInputs,\n
\t\t\tfunction(value) { return (value === target ? null : value); }); // delete entry\n
\t\tthis._disabledInputs[this._disabledInputs.length] = target;\n
\t},\n
\n
\t/* Is the first field in a jQuery collection disabled as a datepicker?\n
\t * @param  target\telement - the target input field or division or span\n
\t * @return boolean - true if disabled, false if enabled\n
\t */\n
\t_isDisabledDatepicker: function(target) {\n
\t\tif (!target) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tfor (var i = 0; i < this._disabledInputs.length; i++) {\n
\t\t\tif (this._disabledInputs[i] === target) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\t\treturn false;\n
\t},\n
\n
\t/* Retrieve the instance data for the target control.\n
\t * @param  target  element - the target input field or division or span\n
\t * @return  object - the associated instance data\n
\t * @throws  error if a jQuery problem getting data\n
\t */\n
\t_getInst: function(target) {\n
\t\ttry {\n
\t\t\treturn $.data(target, PROP_NAME);\n
\t\t}\n
\t\tcatch (err) {\n
\t\t\tthrow "Missing instance data for this datepicker";\n
\t\t}\n
\t},\n
\n
\t/* Update or retrieve the settings for a date picker attached to an input field or division.\n
\t * @param  target  element - the target input field or division or span\n
\t * @param  name\tobject - the new settings to update or\n
\t *\t\t\t\tstring - the name of the setting to change or retrieve,\n
\t *\t\t\t\twhen retrieving also "all" for all instance settings or\n
\t *\t\t\t\t"defaults" for all global defaults\n
\t * @param  value   any - the new value for the setting\n
\t *\t\t\t\t(omit if above is an object or to retrieve a value)\n
\t */\n
\t_optionDatepicker: function(target, name, value) {\n
\t\tvar settings, date, minDate, maxDate,\n
\t\t\tinst = this._getInst(target);\n
\n
\t\tif (arguments.length === 2 && typeof name === "string") {\n
\t\t\treturn (name === "defaults" ? $.extend({}, $.datepicker._defaults) :\n
\t\t\t\t(inst ? (name === "all" ? $.extend({}, inst.settings) :\n
\t\t\t\tthis._get(inst, name)) : null));\n
\t\t}\n
\n
\t\tsettings = name || {};\n
\t\tif (typeof name === "string") {\n
\t\t\tsettings = {};\n
\t\t\tsettings[name] = value;\n
\t\t}\n
\n
\t\tif (inst) {\n
\t\t\tif (this._curInst === inst) {\n
\t\t\t\tthis._hideDatepicker();\n
\t\t\t}\n
\n
\t\t\tdate = this._getDateDatepicker(target, true);\n
\t\t\tminDate = this._getMinMaxDate(inst, "min");\n
\t\t\tmaxDate = this._getMinMaxDate(inst, "max");\n
\t\t\textendRemove(inst.settings, settings);\n
\t\t\t// reformat the old minDate/maxDate values if dateFormat changes and a new minDate/maxDate isn\'t provided\n
\t\t\tif (minDate !== null && settings.dateFormat !== undefined && settings.minDate === undefined) {\n
\t\t\t\tinst.settings.minDate = this._formatDate(inst, minDate);\n
\t\t\t}\n
\t\t\tif (maxDate !== null && settings.dateFormat !== undefined && settings.maxDate === undefined) {\n
\t\t\t\tinst.settings.maxDate = this._formatDate(inst, maxDate);\n
\t\t\t}\n
\t\t\tif ( "disabled" in settings ) {\n
\t\t\t\tif ( settings.disabled ) {\n
\t\t\t\t\tthis._disableDatepicker(target);\n
\t\t\t\t} else {\n
\t\t\t\t\tthis._enableDatepicker(target);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._attachments($(target), inst);\n
\t\t\tthis._autoSize(inst);\n
\t\t\tthis._setDate(inst, date);\n
\t\t\tthis._updateAlternate(inst);\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t}\n
\t},\n
\n
\t// change method deprecated\n
\t_changeDatepicker: function(target, name, value) {\n
\t\tthis._optionDatepicker(target, name, value);\n
\t},\n
\n
\t/* Redraw the date picker attached to an input field or division.\n
\t * @param  target  element - the target input field or division or span\n
\t */\n
\t_refreshDatepicker: function(target) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst) {\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t}\n
\t},\n
\n
\t/* Set the dates for a jQuery selection.\n
\t * @param  target element - the target input field or division or span\n
\t * @param  date\tDate - the new date\n
\t */\n
\t_setDateDatepicker: function(target, date) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst) {\n
\t\t\tthis._setDate(inst, date);\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t\tthis._updateAlternate(inst);\n
\t\t}\n
\t},\n
\n
\t/* Get the date(s) for the first entry in a jQuery selection.\n
\t * @param  target element - the target input field or division or span\n
\t * @param  noDefault boolean - true if no default date is to be used\n
\t * @return Date - the current date\n
\t */\n
\t_getDateDatepicker: function(target, noDefault) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst && !inst.inline) {\n
\t\t\tthis._setDateFromField(inst, noDefault);\n
\t\t}\n
\t\treturn (inst ? this._getDate(inst) : null);\n
\t},\n
\n
\t/* Handle keystrokes. */\n
\t_doKeyDown: function(event) {\n
\t\tvar onSelect, dateStr, sel,\n
\t\t\tinst = $.datepicker._getInst(event.target),\n
\t\t\thandled = true,\n
\t\t\tisRTL = inst.dpDiv.is(".ui-datepicker-rtl");\n
\n
\t\tinst._keyEvent = true;\n
\t\tif ($.datepicker._datepickerShowing) {\n
\t\t\tswitch (event.keyCode) {\n
\t\t\t\tcase 9: $.datepicker._hideDatepicker();\n
\t\t\t\t\t\thandled = false;\n
\t\t\t\t\t\tbreak; // hide on tab out\n
\t\t\t\tcase 13: sel = $("td." + $.datepicker._dayOverClass + ":not(." +\n
\t\t\t\t\t\t\t\t\t$.datepicker._currentClass + ")", inst.dpDiv);\n
\t\t\t\t\t\tif (sel[0]) {\n
\t\t\t\t\t\t\t$.datepicker._selectDay(event.target, inst.selectedMonth, inst.selectedYear, sel[0]);\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tonSelect = $.datepicker._get(inst, "onSelect");\n
\t\t\t\t\t\tif (onSelect) {\n
\t\t\t\t\t\t\tdateStr = $.datepicker._formatDate(inst);\n
\n
\t\t\t\t\t\t\t// trigger custom callback\n
\t\t\t\t\t\t\tonSelect.apply((inst.input ? inst.input[0] : null), [dateStr, inst]);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\treturn false; // don\'t submit the form\n
\t\t\t\tcase 27: $.datepicker._hideDatepicker();\n
\t\t\t\t\t\tbreak; // hide on escape\n
\t\t\t\tcase 33: $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t-$.datepicker._get(inst, "stepBigMonths") :\n
\t\t\t\t\t\t\t-$.datepicker._get(inst, "stepMonths")), "M");\n
\t\t\t\t\t\tbreak; // previous month/year on page up/+ ctrl\n
\t\t\t\tcase 34: $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t+$.datepicker._get(inst, "stepBigMonths") :\n
\t\t\t\t\t\t\t+$.datepicker._get(inst, "stepMonths")), "M");\n
\t\t\t\t\t\tbreak; // next month/year on page down/+ ctrl\n
\t\t\t\tcase 35: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._clearDate(event.target);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // clear on ctrl or command +end\n
\t\t\t\tcase 36: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._gotoToday(event.target);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // current on ctrl or command +home\n
\t\t\t\tcase 37: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, (isRTL ? +1 : -1), "D");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\t// -1 day on ctrl or command +left\n
\t\t\t\t\t\tif (event.originalEvent.altKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t\t-$.datepicker._get(inst, "stepBigMonths") :\n
\t\t\t\t\t\t\t\t-$.datepicker._get(inst, "stepMonths")), "M");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// next month/year on alt +left on Mac\n
\t\t\t\t\t\tbreak;\n
\t\t\t\tcase 38: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, -7, "D");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // -1 week on ctrl or command +up\n
\t\t\t\tcase 39: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, (isRTL ? -1 : +1), "D");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\t// +1 day on ctrl or command +right\n
\t\t\t\t\t\tif (event.originalEvent.altKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t\t+$.datepicker._get(inst, "stepBigMonths") :\n
\t\t\t\t\t\t\t\t+$.datepicker._get(inst, "stepMonths")), "M");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// next month/year on alt +right\n
\t\t\t\t\t\tbreak;\n
\t\t\t\tcase 40: if (event.ctrlKey || event.metaKey) {\n
\t\t\t\t\t\t\t$.datepicker._adjustDate(event.target, +7, "D");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // +1 week on ctrl or command +down\n
\t\t\t\tdefault: handled = false;\n
\t\t\t}\n
\t\t} else if (event.keyCode === 36 && event.ctrlKey) { // display the date picker on ctrl+home\n
\t\t\t$.datepicker._showDatepicker(this);\n
\t\t} else {\n
\t\t\thandled = false;\n
\t\t}\n
\n
\t\tif (handled) {\n
\t\t\tevent.preventDefault();\n
\t\t\tevent.stopPropagation();\n
\t\t}\n
\t},\n
\n
\t/* Filter entered characters - based on date format. */\n
\t_doKeyPress: function(event) {\n
\t\tvar chars, chr,\n
\t\t\tinst = $.datepicker._getInst(event.target);\n
\n
\t\tif ($.datepicker._get(inst, "constrainInput")) {\n
\t\t\tchars = $.datepicker._possibleChars($.datepicker._get(inst, "dateFormat"));\n
\t\t\tchr = String.fromCharCode(event.charCode == null ? event.keyCode : event.charCode);\n
\t\t\treturn event.ctrlKey || event.metaKey || (chr < " " || !chars || chars.indexOf(chr) > -1);\n
\t\t}\n
\t},\n
\n
\t/* Synchronise manual entry and field/alternate field. */\n
\t_doKeyUp: function(event) {\n
\t\tvar date,\n
\t\t\tinst = $.datepicker._getInst(event.target);\n
\n
\t\tif (inst.input.val() !== inst.lastVal) {\n
\t\t\ttry {\n
\t\t\t\tdate = $.datepicker.parseDate($.datepicker._get(inst, "dateFormat"),\n
\t\t\t\t\t(inst.input ? inst.input.val() : null),\n
\t\t\t\t\t$.datepicker._getFormatConfig(inst));\n
\n
\t\t\t\tif (date) { // only if valid\n
\t\t\t\t\t$.datepicker._setDateFromField(inst);\n
\t\t\t\t\t$.datepicker._updateAlternate(inst);\n
\t\t\t\t\t$.datepicker._updateDatepicker(inst);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tcatch (err) {\n
\t\t\t}\n
\t\t}\n
\t\treturn true;\n
\t},\n
\n
\t/* Pop-up the date picker for a given input field.\n
\t * If false returned from beforeShow event handler do not show.\n
\t * @param  input  element - the input field attached to the date picker or\n
\t *\t\t\t\t\tevent - if triggered by focus\n
\t */\n
\t_showDatepicker: function(input) {\n
\t\tinput = input.target || input;\n
\t\tif (input.nodeName.toLowerCase() !== "input") { // find from button/image trigger\n
\t\t\tinput = $("input", input.parentNode)[0];\n
\t\t}\n
\n
\t\tif ($.datepicker._isDisabledDatepicker(input) || $.datepicker._lastInput === input) { // already here\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar inst, beforeShow, beforeShowSettings, isFixed,\n
\t\t\toffset, showAnim, duration;\n
\n
\t\tinst = $.datepicker._getInst(input);\n
\t\tif ($.datepicker._curInst && $.datepicker._curInst !== inst) {\n
\t\t\t$.datepicker._curInst.dpDiv.stop(true, true);\n
\t\t\tif ( inst && $.datepicker._datepickerShowing ) {\n
\t\t\t\t$.datepicker._hideDatepicker( $.datepicker._curInst.input[0] );\n
\t\t\t}\n
\t\t}\n
\n
\t\tbeforeShow = $.datepicker._get(inst, "beforeShow");\n
\t\tbeforeShowSettings = beforeShow ? beforeShow.apply(input, [input, inst]) : {};\n
\t\tif(beforeShowSettings === false){\n
\t\t\treturn;\n
\t\t}\n
\t\textendRemove(inst.settings, beforeShowSettings);\n
\n
\t\tinst.lastVal = null;\n
\t\t$.datepicker._lastInput = input;\n
\t\t$.datepicker._setDateFromField(inst);\n
\n
\t\tif ($.datepicker._inDialog) { // hide cursor\n
\t\t\tinput.value = "";\n
\t\t}\n
\t\tif (!$.datepicker._pos) { // position below input\n
\t\t\t$.datepicker._pos = $.datepicker._findPos(input);\n
\t\t\t$.datepicker._pos[1] += input.offsetHeight; // add the height\n
\t\t}\n
\n
\t\tisFixed = false;\n
\t\t$(input).parents().each(function() {\n
\t\t\tisFixed |= $(this).css("position") === "fixed";\n
\t\t\treturn !isFixed;\n
\t\t});\n
\n
\t\toffset = {left: $.datepicker._pos[0], top: $.datepicker._pos[1]};\n
\t\t$.datepicker._pos = null;\n
\t\t//to avoid flashes on Firefox\n
\t\tinst.dpDiv.empty();\n
\t\t// determine sizing offscreen\n
\t\tinst.dpDiv.css({position: "absolute", display: "block", top: "-1000px"});\n
\t\t$.datepicker._updateDatepicker(inst);\n
\t\t// fix width for dynamic number of date pickers\n
\t\t// and adjust position before showing\n
\t\toffset = $.datepicker._checkOffset(inst, offset, isFixed);\n
\t\tinst.dpDiv.css({position: ($.datepicker._inDialog && $.blockUI ?\n
\t\t\t"static" : (isFixed ? "fixed" : "absolute")), display: "none",\n
\t\t\tleft: offset.left + "px", top: offset.top + "px"});\n
\n
\t\tif (!inst.inline) {\n
\t\t\tshowAnim = $.datepicker._get(inst, "showAnim");\n
\t\t\tduration = $.datepicker._get(inst, "duration");\n
\t\t\tinst.dpDiv.zIndex($(input).zIndex()+1);\n
\t\t\t$.datepicker._datepickerShowing = true;\n
\n
\t\t\tif ( $.effects && $.effects.effect[ showAnim ] ) {\n
\t\t\t\tinst.dpDiv.show(showAnim, $.datepicker._get(inst, "showOptions"), duration);\n
\t\t\t} else {\n
\t\t\t\tinst.dpDiv[showAnim || "show"](showAnim ? duration : null);\n
\t\t\t}\n
\n
\t\t\tif ( $.datepicker._shouldFocusInput( inst ) ) {\n
\t\t\t\tinst.input.focus();\n
\t\t\t}\n
\n
\t\t\t$.datepicker._curInst = inst;\n
\t\t}\n
\t},\n
\n
\t/* Generate the date picker content. */\n
\t_updateDatepicker: function(inst) {\n
\t\tthis.maxRows = 4; //Reset the max number of rows being displayed (see #7043)\n
\t\tinstActive = inst; // for delegate hover events\n
\t\tinst.dpDiv.empty().append(this._generateHTML(inst));\n
\t\tthis._attachHandlers(inst);\n
\t\tinst.dpDiv.find("." + this._dayOverClass + " a").mouseover();\n
\n
\t\tvar origyearshtml,\n
\t\t\tnumMonths = this._getNumberOfMonths(inst),\n
\t\t\tcols = numMonths[1],\n
\t\t\twidth = 17;\n
\n
\t\tinst.dpDiv.removeClass("ui-datepicker-multi-2 ui-datepicker-multi-3 ui-datepicker-multi-4").width("");\n
\t\tif (cols > 1) {\n
\t\t\tinst.dpDiv.addClass("ui-datepicker-multi-" + cols).css("width", (width * cols) + "em");\n
\t\t}\n
\t\tinst.dpDiv[(numMonths[0] !== 1 || numMonths[1] !== 1 ? "add" : "remove") +\n
\t\t\t"Class"]("ui-datepicker-multi");\n
\t\tinst.dpDiv[(this._get(inst, "isRTL") ? "add" : "remove") +\n
\t\t\t"Class"]("ui-datepicker-rtl");\n
\n
\t\tif (inst === $.datepicker._curInst && $.datepicker._datepickerShowing && $.datepicker._shouldFocusInput( inst ) ) {\n
\t\t\tinst.input.focus();\n
\t\t}\n
\n
\t\t// deffered render of the years select (to avoid flashes on Firefox)\n
\t\tif( inst.yearshtml ){\n
\t\t\torigyearshtml = inst.yearshtml;\n
\t\t\tsetTimeout(function(){\n
\t\t\t\t//assure that inst.yearshtml didn\'t change.\n
\t\t\t\tif( origyearshtml === inst.yearshtml && inst.yearshtml ){\n
\t\t\t\t\tinst.dpDiv.find("select.ui-datepicker-year:first").replaceWith(inst.yearshtml);\n
\t\t\t\t}\n
\t\t\t\torigyearshtml = inst.yearshtml = null;\n
\t\t\t}, 0);\n
\t\t}\n
\t},\n
\n
\t// #6694 - don\'t focus the input if it\'s already focused\n
\t// this breaks the change event in IE\n
\t// Support: IE and jQuery <1.9\n
\t_shouldFocusInput: function( inst ) {\n
\t\treturn inst.input && inst.input.is( ":visible" ) && !inst.input.is( ":disabled" ) && !inst.input.is( ":focus" );\n
\t},\n
\n
\t/* Check positioning to remain on screen. */\n
\t_checkOffset: function(inst, offset, isFixed) {\n
\t\tvar dpWidth = inst.dpDiv.outerWidth(),\n
\t\t\tdpHeight = inst.dpDiv.outerHeight(),\n
\t\t\tinputWidth = inst.input ? inst.input.outerWidth() : 0,\n
\t\t\tinputHeight = inst.input ? inst.input.outerHeight() : 0,\n
\t\t\tviewWidth = document.documentElement.clientWidth + (isFixed ? 0 : $(document).scrollLeft()),\n
\t\t\tviewHeight = document.documentElement.clientHeight + (isFixed ? 0 : $(document).scrollTop());\n
\n
\t\toffset.left -= (this._get(inst, "isRTL") ? (dpWidth - inputWidth) : 0);\n
\t\toffset.left -= (isFixed && offset.left === inst.input.offset().left) ? $(document).scrollLeft() : 0;\n
\t\toffset.top -= (isFixed && offset.top === (inst.input.offset().top + inputHeight)) ? $(document).scrollTop() : 0;\n
\n
\t\t// now check if datepicker is showing outside window viewport - move to a better place if so.\n
\t\toffset.left -= Math.min(offset.left, (offset.left + dpWidth > viewWidth && viewWidth > dpWidth) ?\n
\t\t\tMath.abs(offset.left + dpWidth - viewWidth) : 0);\n
\t\toffset.top -= Math.min(offset.top, (offset.top + dpHeight > viewHeight && viewHeight > dpHeight) ?\n
\t\t\tMath.abs(dpHeight + inputHeight) : 0);\n
\n
\t\treturn offset;\n
\t},\n
\n
\t/* Find an object\'s position on the screen. */\n
\t_findPos: function(obj) {\n
\t\tvar position,\n
\t\t\tinst = this._getInst(obj),\n
\t\t\tisRTL = this._get(inst, "isRTL");\n
\n
\t\twhile (obj && (obj.type === "hidden" || obj.nodeType !== 1 || $.expr.filters.hidden(obj))) {\n
\t\t\tobj = obj[isRTL ? "previousSibling" : "nextSibling"];\n
\t\t}\n
\n
\t\tposition = $(obj).offset();\n
\t\treturn [position.left, position.top];\n
\t},\n
\n
\t/* Hide the date picker from view.\n
\t * @param  input  element - the input field attached to the date picker\n
\t */\n
\t_hideDatepicker: function(input) {\n
\t\tvar showAnim, duration, postProcess, onClose,\n
\t\t\tinst = this._curInst;\n
\n
\t\tif (!inst || (input && inst !== $.data(input, PROP_NAME))) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (this._datepickerShowing) {\n
\t\t\tshowAnim = this._get(inst, "showAnim");\n
\t\t\tduration = this._get(inst, "duration");\n
\t\t\tpostProcess = function() {\n
\t\t\t\t$.datepicker._tidyDialog(inst);\n
\t\t\t};\n
\n
\t\t\t// DEPRECATED: after BC for 1.8.x $.effects[ showAnim ] is not needed\n
\t\t\tif ( $.effects && ( $.effects.effect[ showAnim ] || $.effects[ showAnim ] ) ) {\n
\t\t\t\tinst.dpDiv.hide(showAnim, $.datepicker._get(inst, "showOptions"), duration, postProcess);\n
\t\t\t} else {\n
\t\t\t\tinst.dpDiv[(showAnim === "slideDown" ? "slideUp" :\n
\t\t\t\t\t(showAnim === "fadeIn" ? "fadeOut" : "hide"))]((showAnim ? duration : null), postProcess);\n
\t\t\t}\n
\n
\t\t\tif (!showAnim) {\n
\t\t\t\tpostProcess();\n
\t\t\t}\n
\t\t\tthis._datepickerShowing = false;\n
\n
\t\t\tonClose = this._get(inst, "onClose");\n
\t\t\tif (onClose) {\n
\t\t\t\tonClose.apply((inst.input ? inst.input[0] : null), [(inst.input ? inst.input.val() : ""), inst]);\n
\t\t\t}\n
\n
\t\t\tthis._lastInput = null;\n
\t\t\tif (this._inDialog) {\n
\t\t\t\tthis._dialogInput.css({ position: "absolute", left: "0", top: "-100px" });\n
\t\t\t\tif ($.blockUI) {\n
\t\t\t\t\t$.unblockUI();\n
\t\t\t\t\t$("body").append(this.dpDiv);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._inDialog = false;\n
\t\t}\n
\t},\n
\n
\t/* Tidy up after a dialog display. */\n
\t_tidyDialog: function(inst) {\n
\t\tinst.dpDiv.removeClass(this._dialogClass).unbind(".ui-datepicker-calendar");\n
\t},\n
\n
\t/* Close date picker if clicked elsewhere. */\n
\t_checkExternalClick: function(event) {\n
\t\tif (!$.datepicker._curInst) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar $target = $(event.target),\n
\t\t\tinst = $.datepicker._getInst($target[0]);\n
\n
\t\tif ( ( ( $target[0].id !== $.datepicker._mainDivId &&\n
\t\t\t\t$target.parents("#" + $.datepicker._mainDivId).length === 0 &&\n
\t\t\t\t!$target.hasClass($.datepicker.markerClassName) &&\n
\t\t\t\t!$target.closest("." + $.datepicker._triggerClass).length &&\n
\t\t\t\t$.datepicker._datepickerShowing && !($.datepicker._inDialog && $.blockUI) ) ) ||\n
\t\t\t( $target.hasClass($.datepicker.markerClassName) && $.datepicker._curInst !== inst ) ) {\n
\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t}\n
\t},\n
\n
\t/* Adjust one of the date sub-fields. */\n
\t_adjustDate: function(id, offset, period) {\n
\t\tvar target = $(id),\n
\t\t\tinst = this._getInst(target[0]);\n
\n
\t\tif (this._isDisabledDatepicker(target[0])) {\n
\t\t\treturn;\n
\t\t}\n
\t\tthis._adjustInstDate(inst, offset +\n
\t\t\t(period === "M" ? this._get(inst, "showCurrentAtPos") : 0), // undo positioning\n
\t\t\tperiod);\n
\t\tthis._updateDatepicker(inst);\n
\t},\n
\n
\t/* Action for current link. */\n
\t_gotoToday: function(id) {\n
\t\tvar date,\n
\t\t\ttarget = $(id),\n
\t\t\tinst = this._getInst(target[0]);\n
\n
\t\tif (this._get(inst, "gotoCurrent") && inst.currentDay) {\n
\t\t\tinst.selectedDay = inst.currentDay;\n
\t\t\tinst.drawMonth = inst.selectedMonth = inst.currentMonth;\n
\t\t\tinst.drawYear = inst.selectedYear = inst.currentYear;\n
\t\t} else {\n
\t\t\tdate = new Date();\n
\t\t\tinst.selectedDay = date.getDate();\n
\t\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\t}\n
\t\tthis._notifyChange(inst);\n
\t\tthis._adjustDate(target);\n
\t},\n
\n
\t/* Action for selecting a new month/year. */\n
\t_selectMonthYear: function(id, select, period) {\n
\t\tvar target = $(id),\n
\t\t\tinst = this._getInst(target[0]);\n
\n
\t\tinst["selected" + (period === "M" ? "Month" : "Year")] =\n
\t\tinst["draw" + (period === "M" ? "Month" : "Year")] =\n
\t\t\tparseInt(select.options[select.selectedIndex].value,10);\n
\n
\t\tthis._notifyChange(inst);\n
\t\tthis._adjustDate(target);\n
\t},\n
\n
\t/* Action for selecting a day. */\n
\t_selectDay: function(id, month, year, td) {\n
\t\tvar inst,\n
\t\t\ttarget = $(id);\n
\n
\t\tif ($(td).hasClass(this._unselectableClass) || this._isDisabledDatepicker(target[0])) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tinst = this._getInst(target[0]);\n
\t\tinst.selectedDay = inst.currentDay = $("a", td).html();\n
\t\tinst.selectedMonth = inst.currentMonth = month;\n
\t\tinst.selectedYear = inst.currentYear = year;\n
\t\tthis._selectDate(id, this._formatDate(inst,\n
\t\t\tinst.currentDay, inst.currentMonth, inst.currentYear));\n
\t},\n
\n
\t/* Erase the input field and hide the date picker. */\n
\t_clearDate: function(id) {\n
\t\tvar target = $(id);\n
\t\tthis._selectDate(target, "");\n
\t},\n
\n
\t/* Update the input field with the selected date. */\n
\t_selectDate: function(id, dateStr) {\n
\t\tvar onSelect,\n
\t\t\ttarget = $(id),\n
\t\t\tinst = this._getInst(target[0]);\n
\n
\t\tdateStr = (dateStr != null ? dateStr : this._formatDate(inst));\n
\t\tif (inst.input) {\n
\t\t\tinst.input.val(dateStr);\n
\t\t}\n
\t\tthis._updateAlternate(inst);\n
\n
\t\tonSelect = this._get(inst, "onSelect");\n
\t\tif (onSelect) {\n
\t\t\tonSelect.apply((inst.input ? inst.input[0] : null), [dateStr, inst]);  // trigger custom callback\n
\t\t} else if (inst.input) {\n
\t\t\tinst.input.trigger("change"); // fire the change event\n
\t\t}\n
\n
\t\tif (inst.inline){\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t} else {\n
\t\t\tthis._hideDatepicker();\n
\t\t\tthis._lastInput = inst.input[0];\n
\t\t\tif (typeof(inst.input[0]) !== "object") {\n
\t\t\t\tinst.input.focus(); // restore focus\n
\t\t\t}\n
\t\t\tthis._lastInput = null;\n
\t\t}\n
\t},\n
\n
\t/* Update any alternate field to synchronise with the main field. */\n
\t_updateAlternate: function(inst) {\n
\t\tvar altFormat, date, dateStr,\n
\t\t\taltField = this._get(inst, "altField");\n
\n
\t\tif (altField) { // update alternate field too\n
\t\t\taltFormat = this._get(inst, "altFormat") || this._get(inst, "dateFormat");\n
\t\t\tdate = this._getDate(inst);\n
\t\t\tdateStr = this.formatDate(altFormat, date, this._getFormatConfig(inst));\n
\t\t\t$(altField).each(function() { $(this).val(dateStr); });\n
\t\t}\n
\t},\n
\n
\t/* Set as beforeShowDay function to prevent selection of weekends.\n
\t * @param  date  Date - the date to customise\n
\t * @return [boolean, string] - is this date selectable?, what is its CSS class?\n
\t */\n
\tnoWeekends: function(date) {\n
\t\tvar day = date.getDay();\n
\t\treturn [(day > 0 && day < 6), ""];\n
\t},\n
\n
\t/* Set as calculateWeek to determine the week of the year based on the ISO 8601 definition.\n
\t * @param  date  Date - the date to get the week for\n
\t * @return  number - the number of the week within the year that contains this date\n
\t */\n
\tiso8601Week: function(date) {\n
\t\tvar time,\n
\t\t\tcheckDate = new Date(date.getTime());\n
\n
\t\t// Find Thursday of this week starting on Monday\n
\t\tcheckDate.setDate(checkDate.getDate() + 4 - (checkDate.getDay() || 7));\n
\n
\t\ttime = checkDate.getTime();\n
\t\tcheckDate.setMonth(0); // Compare with Jan 1\n
\t\tcheckDate.setDate(1);\n
\t\treturn Math.floor(Math.round((time - checkDate) / 86400000) / 7) + 1;\n
\t},\n
\n
\t/* Parse a string value into a date object.\n
\t * See formatDate below for the possible formats.\n
\t *\n
\t * @param  format string - the expected format of the date\n
\t * @param  value string - the date in the above format\n
\t * @param  settings Object - attributes include:\n
\t *\t\t\t\t\tshortYearCutoff  number - the cutoff year for determining the century (optional)\n
\t *\t\t\t\t\tdayNamesShort\tstring[7] - abbreviated names of the days from Sunday (optional)\n
\t *\t\t\t\t\tdayNames\t\tstring[7] - names of the days from Sunday (optional)\n
\t *\t\t\t\t\tmonthNamesShort string[12] - abbreviated names of the months (optional)\n
\t *\t\t\t\t\tmonthNames\t\tstring[12] - names of the months (optional)\n
\t * @return  Date - the extracted date value or null if value is blank\n
\t */\n
\tparseDate: function (format, value, settings) {\n
\t\tif (format == null || value == null) {\n
\t\t\tthrow "Invalid arguments";\n
\t\t}\n
\n
\t\tvalue = (typeof value === "object" ? value.toString() : value + "");\n
\t\tif (value === "") {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tvar iFormat, dim, extra,\n
\t\t\tiValue = 0,\n
\t\t\tshortYearCutoffTemp = (settings ? settings.shortYearCutoff : null) || this._defaults.shortYearCutoff,\n
\t\t\tshortYearCutoff = (typeof shortYearCutoffTemp !== "string" ? shortYearCutoffTemp :\n
\t\t\t\tnew Date().getFullYear() % 100 + parseInt(shortYearCutoffTemp, 10)),\n
\t\t\tdayNamesShort = (settings ? settings.dayNamesShort : null) || this._defaults.dayNamesShort,\n
\t\t\tdayNames = (settings ? settings.dayNames : null) || this._defaults.dayNames,\n
\t\t\tmonthNamesShort = (settings ? settings.monthNamesShort : null) || this._defaults.monthNamesShort,\n
\t\t\tmonthNames = (settings ? settings.monthNames : null) || this._defaults.monthNames,\n
\t\t\tyear = -1,\n
\t\t\tmonth = -1,\n
\t\t\tday = -1,\n
\t\t\tdoy = -1,\n
\t\t\tliteral = false,\n
\t\t\tdate,\n
\t\t\t// Check whether a format character is doubled\n
\t\t\tlookAhead = function(match) {\n
\t\t\t\tvar matches = (iFormat + 1 < format.length && format.charAt(iFormat + 1) === match);\n
\t\t\t\tif (matches) {\n
\t\t\t\t\tiFormat++;\n
\t\t\t\t}\n
\t\t\t\treturn matches;\n
\t\t\t},\n
\t\t\t// Extract a number from the string value\n
\t\t\tgetNumber = function(match) {\n
\t\t\t\tvar isDoubled = lookAhead(match),\n
\t\t\t\t\tsize = (match === "@" ? 14 : (match === "!" ? 20 :\n
\t\t\t\t\t(match === "y" && isDoubled ? 4 : (match === "o" ? 3 : 2)))),\n
\t\t\t\t\tdigits = new RegExp("^\\\\d{1," + size + "}"),\n
\t\t\t\t\tnum = value.substring(iValue).match(digits);\n
\t\t\t\tif (!num) {\n
\t\t\t\t\tthrow "Missing number at position " + iValue;\n
\t\t\t\t}\n
\t\t\t\tiValue += num[0].length;\n
\t\t\t\treturn parseInt(num[0], 10);\n
\t\t\t},\n
\t\t\t// Extract a name from the string value and convert to an index\n
\t\t\tgetName = function(match, shortNames, longNames) {\n
\t\t\t\tvar index = -1,\n
\t\t\t\t\tnames = $.map(lookAhead(match) ? longNames : shortNames, function (v, k) {\n
\t\t\t\t\t\treturn [ [k, v] ];\n
\t\t\t\t\t}).sort(function (a, b) {\n
\t\t\t\t\t\treturn -(a[1].length - b[1].length);\n
\t\t\t\t\t});\n
\n
\t\t\t\t$.each(names, function (i, pair) {\n
\t\t\t\t\tvar name = pair[1];\n
\t\t\t\t\tif (value.substr(iValue, name.length).toLowerCase() === name.toLowerCase()) {\n
\t\t\t\t\t\tindex = pair[0];\n
\t\t\t\t\t\tiValue += name.length;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\tif (index !== -1) {\n
\t\t\t\t\treturn index + 1;\n
\t\t\t\t} else {\n
\t\t\t\t\tthrow "Unknown name at position " + iValue;\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\t// Confirm that a literal character matches the string value\n
\t\t\tcheckLiteral = function() {\n
\t\t\t\tif (value.charAt(iValue) !== format.charAt(iFormat)) {\n
\t\t\t\t\tthrow "Unexpected literal at position " + iValue;\n
\t\t\t\t}\n
\t\t\t\tiValue++;\n
\t\t\t};\n
\n
\t\tfor (iFormat = 0; iFormat < format.length; iFormat++) {\n
\t\t\tif (literal) {\n
\t\t\t\tif (format.charAt(iFormat) === "\'" && !lookAhead("\'")) {\n
\t\t\t\t\tliteral = false;\n
\t\t\t\t} else {\n
\t\t\t\t\tcheckLiteral();\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\tcase "d":\n
\t\t\t\t\t\tday = getNumber("d");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "D":\n
\t\t\t\t\t\tgetName("D", dayNamesShort, dayNames);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "o":\n
\t\t\t\t\t\tdoy = getNumber("o");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "m":\n
\t\t\t\t\t\tmonth = getNumber("m");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "M":\n
\t\t\t\t\t\tmonth = getName("M", monthNamesShort, monthNames);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "y":\n
\t\t\t\t\t\tyear = getNumber("y");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "@":\n
\t\t\t\t\t\tdate = new Date(getNumber("@"));\n
\t\t\t\t\t\tyear = date.getFullYear();\n
\t\t\t\t\t\tmonth = date.getMonth() + 1;\n
\t\t\t\t\t\tday = date.getDate();\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "!":\n
\t\t\t\t\t\tdate = new Date((getNumber("!") - this._ticksTo1970) / 10000);\n
\t\t\t\t\t\tyear = date.getFullYear();\n
\t\t\t\t\t\tmonth = date.getMonth() + 1;\n
\t\t\t\t\t\tday = date.getDate();\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\tif (lookAhead("\'")){\n
\t\t\t\t\t\t\tcheckLiteral();\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\tcheckLiteral();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (iValue < value.length){\n
\t\t\textra = value.substr(iValue);\n
\t\t\tif (!/^\\s+/.test(extra)) {\n
\t\t\t\tthrow "Extra/unparsed characters found in date: " + extra;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (year === -1) {\n
\t\t\tyear = new Date().getFullYear();\n
\t\t} else if (year < 100) {\n
\t\t\tyear += new Date().getFullYear() - new Date().getFullYear() % 100 +\n
\t\t\t\t(year <= shortYearCutoff ? 0 : -100);\n
\t\t}\n
\n
\t\tif (doy > -1) {\n
\t\t\tmonth = 1;\n
\t\t\tday = doy;\n
\t\t\tdo {\n
\t\t\t\tdim = this._getDaysInMonth(year, month - 1);\n
\t\t\t\tif (day <= dim) {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tmonth++;\n
\t\t\t\tday -= dim;\n
\t\t\t} while (true);\n
\t\t}\n
\n
\t\tdate = this._daylightSavingAdjust(new Date(year, month - 1, day));\n
\t\tif (date.getFullYear() !== year || date.getMonth() + 1 !== month || date.getDate() !== day) {\n
\t\t\tthrow "Invalid date"; // E.g. 31/02/00\n
\t\t}\n
\t\treturn date;\n
\t},\n
\n
\t/* Standard date formats. */\n
\tATOM: "yy-mm-dd", // RFC 3339 (ISO 8601)\n
\tCOOKIE: "D, dd M yy",\n
\tISO_8601: "yy-mm-dd",\n
\tRFC_822: "D, d M y",\n
\tRFC_850: "DD, dd-M-y",\n
\tRFC_1036: "D, d M y",\n
\tRFC_1123: "D, d M yy",\n
\tRFC_2822: "D, d M yy",\n
\tRSS: "D, d M y", // RFC 822\n
\tTICKS: "!",\n
\tTIMESTAMP: "@",\n
\tW3C: "yy-mm-dd", // ISO 8601\n
\n
\t_ticksTo1970: (((1970 - 1) * 365 + Math.floor(1970 / 4) - Math.floor(1970 / 100) +\n
\t\tMath.floor(1970 / 400)) * 24 * 60 * 60 * 10000000),\n
\n
\t/* Format a date object into a string value.\n
\t * The format can be combinations of the following:\n
\t * d  - day of month (no leading zero)\n
\t * dd - day of month (two digit)\n
\t * o  - day of year (no leading zeros)\n
\t * oo - day of year (three digit)\n
\t * D  - day name short\n
\t * DD - day name long\n
\t * m  - month of year (no leading zero)\n
\t * mm - month of year (two digit)\n
\t * M  - month name short\n
\t * MM - month name long\n
\t * y  - year (two digit)\n
\t * yy - year (four digit)\n
\t * @ - Unix timestamp (ms since 01/01/1970)\n
\t * ! - Windows ticks (100ns since 01/01/0001)\n
\t * "..." - literal text\n
\t * \'\' - single quote\n
\t *\n
\t * @param  format string - the desired format of the date\n
\t * @param  date Date - the date value to format\n
\t * @param  settings Object - attributes include:\n
\t *\t\t\t\t\tdayNamesShort\tstring[7] - abbreviated names of the days from Sunday (optional)\n
\t *\t\t\t\t\tdayNames\t\tstring[7] - names of the days from Sunday (optional)\n
\t *\t\t\t\t\tmonthNamesShort string[12] - abbreviated names of the months (optional)\n
\t *\t\t\t\t\tmonthNames\t\tstring[12] - names of the months (optional)\n
\t * @return  string - the date in the above format\n
\t */\n
\tformatDate: function (format, date, settings) {\n
\t\tif (!date) {\n
\t\t\treturn "";\n
\t\t}\n
\n
\t\tvar iFormat,\n
\t\t\tdayNamesShort = (settings ? settings.dayNamesShort : null) || this._defaults.dayNamesShort,\n
\t\t\tdayNames = (settings ? settings.dayNames : null) || this._defaults.dayNames,\n
\t\t\tmonthNamesShort = (settings ? settings.monthNamesShort : null) || this._defaults.monthNamesShort,\n
\t\t\tmonthNames = (settings ? settings.monthNames : null) || this._defaults.monthNames,\n
\t\t\t// Check whether a format character is doubled\n
\t\t\tlookAhead = function(match) {\n
\t\t\t\tvar matches = (iFormat + 1 < format.length && format.charAt(iFormat + 1) === match);\n
\t\t\t\tif (matches) {\n
\t\t\t\t\tiFormat++;\n
\t\t\t\t}\n
\t\t\t\treturn matches;\n
\t\t\t},\n
\t\t\t// Format a number, with leading zero if necessary\n
\t\t\tformatNumber = function(match, value, len) {\n
\t\t\t\tvar num = "" + value;\n
\t\t\t\tif (lookAhead(match)) {\n
\t\t\t\t\twhile (num.length < len) {\n
\t\t\t\t\t\tnum = "0" + num;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn num;\n
\t\t\t},\n
\t\t\t// Format a name, short or long as requested\n
\t\t\tformatName = function(match, value, shortNames, longNames) {\n
\t\t\t\treturn (lookAhead(match) ? longNames[value] : shortNames[value]);\n
\t\t\t},\n
\t\t\toutput = "",\n
\t\t\tliteral = false;\n
\n
\t\tif (date) {\n
\t\t\tfor (iFormat = 0; iFormat < format.length; iFormat++) {\n
\t\t\t\tif (literal) {\n
\t\t\t\t\tif (format.charAt(iFormat) === "\'" && !lookAhead("\'")) {\n
\t\t\t\t\t\tliteral = false;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\toutput += format.charAt(iFormat);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\t\tcase "d":\n
\t\t\t\t\t\t\toutput += formatNumber("d", date.getDate(), 2);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "D":\n
\t\t\t\t\t\t\toutput += formatName("D", date.getDay(), dayNamesShort, dayNames);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "o":\n
\t\t\t\t\t\t\toutput += formatNumber("o",\n
\t\t\t\t\t\t\t\tMath.round((new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime() - new Date(date.getFullYear(), 0, 0).getTime()) / 86400000), 3);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "m":\n
\t\t\t\t\t\t\toutput += formatNumber("m", date.getMonth() + 1, 2);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "M":\n
\t\t\t\t\t\t\toutput += formatName("M", date.getMonth(), monthNamesShort, monthNames);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "y":\n
\t\t\t\t\t\t\toutput += (lookAhead("y") ? date.getFullYear() :\n
\t\t\t\t\t\t\t\t(date.getYear() % 100 < 10 ? "0" : "") + date.getYear() % 100);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "@":\n
\t\t\t\t\t\t\toutput += date.getTime();\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "!":\n
\t\t\t\t\t\t\toutput += date.getTime() * 10000 + this._ticksTo1970;\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\t\tif (lookAhead("\'")) {\n
\t\t\t\t\t\t\t\toutput += "\'";\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tdefault:\n
\t\t\t\t\t\t\toutput += format.charAt(iFormat);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\treturn output;\n
\t},\n
\n
\t/* Extract all possible characters from the date format. */\n
\t_possibleChars: function (format) {\n
\t\tvar iFormat,\n
\t\t\tchars = "",\n
\t\t\tliteral = false,\n
\t\t\t// Check whether a format character is doubled\n
\t\t\tlookAhead = function(match) {\n
\t\t\t\tvar matches = (iFormat + 1 < format.length && format.charAt(iFormat + 1) === match);\n
\t\t\t\tif (matches) {\n
\t\t\t\t\tiFormat++;\n
\t\t\t\t}\n
\t\t\t\treturn matches;\n
\t\t\t};\n
\n
\t\tfor (iFormat = 0; iFormat < format.length; iFormat++) {\n
\t\t\tif (literal) {\n
\t\t\t\tif (format.charAt(iFormat) === "\'" && !lookAhead("\'")) {\n
\t\t\t\t\tliteral = false;\n
\t\t\t\t} else {\n
\t\t\t\t\tchars += format.charAt(iFormat);\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\tcase "d": case "m": case "y": case "@":\n
\t\t\t\t\t\tchars += "0123456789";\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "D": case "M":\n
\t\t\t\t\t\treturn null; // Accept anything\n
\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\tif (lookAhead("\'")) {\n
\t\t\t\t\t\t\tchars += "\'";\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\tchars += format.charAt(iFormat);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\treturn chars;\n
\t},\n
\n
\t/* Get a setting value, defaulting if necessary. */\n
\t_get: function(inst, name) {\n
\t\treturn inst.settings[name] !== undefined ?\n
\t\t\tinst.settings[name] : this._defaults[name];\n
\t},\n
\n
\t/* Parse existing date and initialise date picker. */\n
\t_setDateFromField: function(inst, noDefault) {\n
\t\tif (inst.input.val() === inst.lastVal) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar dateFormat = this._get(inst, "dateFormat"),\n
\t\t\tdates = inst.lastVal = inst.input ? inst.input.val() : null,\n
\t\t\tdefaultDate = this._getDefaultDate(inst),\n
\t\t\tdate = defaultDate,\n
\t\t\tsettings = this._getFormatConfig(inst);\n
\n
\t\ttry {\n
\t\t\tdate = this.parseDate(dateFormat, dates, settings) || defaultDate;\n
\t\t} catch (event) {\n
\t\t\tdates = (noDefault ? "" : dates);\n
\t\t}\n
\t\tinst.selectedDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\tinst.currentDay = (dates ? date.getDate() : 0);\n
\t\tinst.currentMonth = (dates ? date.getMonth() : 0);\n
\t\tinst.currentYear = (dates ? date.getFullYear() : 0);\n
\t\tthis._adjustInstDate(inst);\n
\t},\n
\n
\t/* Retrieve the default date shown on opening. */\n
\t_getDefaultDate: function(inst) {\n
\t\treturn this._restrictMinMax(inst,\n
\t\t\tthis._determineDate(inst, this._get(inst, "defaultDate"), new Date()));\n
\t},\n
\n
\t/* A date may be specified as an exact value or a relative one. */\n
\t_determineDate: function(inst, date, defaultDate) {\n
\t\tvar offsetNumeric = function(offset) {\n
\t\t\t\tvar date = new Date();\n
\t\t\t\tdate.setDate(date.getDate() + offset);\n
\t\t\t\treturn date;\n
\t\t\t},\n
\t\t\toffsetString = function(offset) {\n
\t\t\t\ttry {\n
\t\t\t\t\treturn $.datepicker.parseDate($.datepicker._get(inst, "dateFormat"),\n
\t\t\t\t\t\toffset, $.datepicker._getFormatConfig(inst));\n
\t\t\t\t}\n
\t\t\t\tcatch (e) {\n
\t\t\t\t\t// Ignore\n
\t\t\t\t}\n
\n
\t\t\t\tvar date = (offset.toLowerCase().match(/^c/) ?\n
\t\t\t\t\t$.datepicker._getDate(inst) : null) || new Date(),\n
\t\t\t\t\tyear = date.getFullYear(),\n
\t\t\t\t\tmonth = date.getMonth(),\n
\t\t\t\t\tday = date.getDate(),\n
\t\t\t\t\tpattern = /([+\\-]?[0-9]+)\\s*(d|D|w|W|m|M|y|Y)?/g,\n
\t\t\t\t\tmatches = pattern.exec(offset);\n
\n
\t\t\t\twhile (matches) {\n
\t\t\t\t\tswitch (matches[2] || "d") {\n
\t\t\t\t\t\tcase "d" : case "D" :\n
\t\t\t\t\t\t\tday += parseInt(matches[1],10); break;\n
\t\t\t\t\t\tcase "w" : case "W" :\n
\t\t\t\t\t\t\tday += parseInt(matches[1],10) * 7; break;\n
\t\t\t\t\t\tcase "m" : case "M" :\n
\t\t\t\t\t\t\tmonth += parseInt(matches[1],10);\n
\t\t\t\t\t\t\tday = Math.min(day, $.datepicker._getDaysInMonth(year, month));\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "y": case "Y" :\n
\t\t\t\t\t\t\tyear += parseInt(matches[1],10);\n
\t\t\t\t\t\t\tday = Math.min(day, $.datepicker._getDaysInMonth(year, month));\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tmatches = pattern.exec(offset);\n
\t\t\t\t}\n
\t\t\t\treturn new Date(year, month, day);\n
\t\t\t},\n
\t\t\tnewDate = (date == null || date === "" ? defaultDate : (typeof date === "string" ? offsetString(date) :\n
\t\t\t\t(typeof date === "number" ? (isNaN(date) ? defaultDate : offsetNumeric(date)) : new Date(date.getTime()))));\n
\n
\t\tnewDate = (newDate && newDate.toString() === "Invalid Date" ? defaultDate : newDate);\n
\t\tif (newDate) {\n
\t\t\tnewDate.setHours(0);\n
\t\t\tnewDate.setMinutes(0);\n
\t\t\tnewDate.setSeconds(0);\n
\t\t\tnewDate.setMilliseconds(0);\n
\t\t}\n
\t\treturn this._daylightSavingAdjust(newDate);\n
\t},\n
\n
\t/* Handle switch to/from daylight saving.\n
\t * Hours may be non-zero on daylight saving cut-over:\n
\t * > 12 when midnight changeover, but then cannot generate\n
\t * midnight datetime, so jump to 1AM, otherwise reset.\n
\t * @param  date  (Date) the date to check\n
\t * @return  (Date) the corrected date\n
\t */\n
\t_daylightSavingAdjust: function(date) {\n
\t\tif (!date) {\n
\t\t\treturn null;\n
\t\t}\n
\t\tdate.setHours(date.getHours() > 12 ? date.getHours() + 2 : 0);\n
\t\treturn date;\n
\t},\n
\n
\t/* Set the date(s) directly. */\n
\t_setDate: function(inst, date, noChange) {\n
\t\tvar clear = !date,\n
\t\t\torigMonth = inst.selectedMonth,\n
\t\t\torigYear = inst.selectedYear,\n
\t\t\tnewDate = this._restrictMinMax(inst, this._determineDate(inst, date, new Date()));\n
\n
\t\tinst.selectedDay = inst.currentDay = newDate.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = inst.currentMonth = newDate.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = inst.currentYear = newDate.getFullYear();\n
\t\tif ((origMonth !== inst.selectedMonth || origYear !== inst.selectedYear) && !noChange) {\n
\t\t\tthis._notifyChange(inst);\n
\t\t}\n
\t\tthis._adjustInstDate(inst);\n
\t\tif (inst.input) {\n
\t\t\tinst.input.val(clear ? "" : this._formatDate(inst));\n
\t\t}\n
\t},\n
\n
\t/* Retrieve the date(s) directly. */\n
\t_getDate: function(inst) {\n
\t\tvar startDate = (!inst.currentYear || (inst.input && inst.input.val() === "") ? null :\n
\t\t\tthis._daylightSavingAdjust(new Date(\n
\t\t\tinst.currentYear, inst.currentMonth, inst.currentDay)));\n
\t\t\treturn startDate;\n
\t},\n
\n
\t/* Attach the onxxx handlers.  These are declared statically so\n
\t * they work with static code transformers like Caja.\n
\t */\n
\t_attachHandlers: function(inst) {\n
\t\tvar stepMonths = this._get(inst, "stepMonths"),\n
\t\t\tid = "#" + inst.id.replace( /\\\\\\\\/g, "\\\\" );\n
\t\tinst.dpDiv.find("[data-handler]").map(function () {\n
\t\t\tvar handler = {\n
\t\t\t\tprev: function () {\n
\t\t\t\t\t$.datepicker._adjustDate(id, -stepMonths, "M");\n
\t\t\t\t},\n
\t\t\t\tnext: function () {\n
\t\t\t\t\t$.datepicker._adjustDate(id, +stepMonths, "M");\n
\t\t\t\t},\n
\t\t\t\thide: function () {\n
\t\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t\t\t},\n
\t\t\t\ttoday: function () {\n
\t\t\t\t\t$.datepicker._gotoToday(id);\n
\t\t\t\t},\n
\t\t\t\tselectDay: function () {\n
\t\t\t\t\t$.datepicker._selectDay(id, +this.getAttribute("data-month"), +this.getAttribute("data-year"), this);\n
\t\t\t\t\treturn false;\n
\t\t\t\t},\n
\t\t\t\tselectMonth: function () {\n
\t\t\t\t\t$.datepicker._selectMonthYear(id, this, "M");\n
\t\t\t\t\treturn false;\n
\t\t\t\t},\n
\t\t\t\tselectYear: function () {\n
\t\t\t\t\t$.datepicker._selectMonthYear(id, this, "Y");\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t$(this).bind(this.getAttribute("data-event"), handler[this.getAttribute("data-handler")]);\n
\t\t});\n
\t},\n
\n
\t/* Generate the HTML for the current state of the date picker. */\n
\t_generateHTML: function(inst) {\n
\t\tvar maxDraw, prevText, prev, nextText, next, currentText, gotoDate,\n
\t\t\tcontrols, buttonPanel, firstDay, showWeek, dayNames, dayNamesMin,\n
\t\t\tmonthNames, monthNamesShort, beforeShowDay, showOtherMonths,\n
\t\t\tselectOtherMonths, defaultDate, html, dow, row, group, col, selectedDate,\n
\t\t\tcornerClass, calender, thead, day, daysInMonth, leadDays, curRows, numRows,\n
\t\t\tprintDate, dRow, tbody, daySettings, otherMonth, unselectable,\n
\t\t\ttempDate = new Date(),\n
\t\t\ttoday = this._daylightSavingAdjust(\n
\t\t\t\tnew Date(tempDate.getFullYear(), tempDate.getMonth(), tempDate.getDate())), // clear time\n
\t\t\tisRTL = this._get(inst, "isRTL"),\n
\t\t\tshowButtonPanel = this._get(inst, "showButtonPanel"),\n
\t\t\thideIfNoPrevNext = this._get(inst, "hideIfNoPrevNext"),\n
\t\t\tnavigationAsDateFormat = this._get(inst, "navigationAsDateFormat"),\n
\t\t\tnumMonths = this._getNumberOfMonths(inst),\n
\t\t\tshowCurrentAtPos = this._get(inst, "showCurrentAtPos"),\n
\t\t\tstepMonths = this._get(inst, "stepMonths"),\n
\t\t\tisMultiMonth = (numMonths[0] !== 1 || numMonths[1] !== 1),\n
\t\t\tcurrentDate = this._daylightSavingAdjust((!inst.currentDay ? new Date(9999, 9, 9) :\n
\t\t\t\tnew Date(inst.currentYear, inst.currentMonth, inst.currentDay))),\n
\t\t\tminDate = this._getMinMaxDate(inst, "min"),\n
\t\t\tmaxDate = this._getMinMaxDate(inst, "max"),\n
\t\t\tdrawMonth = inst.drawMonth - showCurrentAtPos,\n
\t\t\tdrawYear = inst.drawYear;\n
\n
\t\tif (drawMonth < 0) {\n
\t\t\tdrawMonth += 12;\n
\t\t\tdrawYear--;\n
\t\t}\n
\t\tif (maxDate) {\n
\t\t\tmaxDraw = this._daylightSavingAdjust(new Date(maxDate.getFullYear(),\n
\t\t\t\tmaxDate.getMonth() - (numMonths[0] * numMonths[1]) + 1, maxDate.getDate()));\n
\t\t\tmaxDraw = (minDate && maxDraw < minDate ? minDate : maxDraw);\n
\t\t\twhile (this._daylightSavingAdjust(new Date(drawYear, drawMonth, 1)) > maxDraw) {\n
\t\t\t\tdrawMonth--;\n
\t\t\t\tif (drawMonth < 0) {\n
\t\t\t\t\tdrawMonth = 11;\n
\t\t\t\t\tdrawYear--;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tinst.drawMonth = drawMonth;\n
\t\tinst.drawYear = drawYear;\n
\n
\t\tprevText = this._get(inst, "prevText");\n
\t\tprevText = (!navigationAsDateFormat ? prevText : this.formatDate(prevText,\n
\t\t\tthis._daylightSavingAdjust(new Date(drawYear, drawMonth - stepMonths, 1)),\n
\t\t\tthis._getFormatConfig(inst)));\n
\n
\t\tprev = (this._canAdjustMonth(inst, -1, drawYear, drawMonth) ?\n
\t\t\t"<a class=\'ui-datepicker-prev ui-corner-all\' data-handler=\'prev\' data-event=\'click\'" +\n
\t\t\t" title=\'" + prevText + "\'><span class=\'ui-icon ui-icon-circle-triangle-" + ( isRTL ? "e" : "w") + "\'>" + prevText + "</span></a>" :\n
\t\t\t(hideIfNoPrevNext ? "" : "<a class=\'ui-datepicker-prev ui-corner-all ui-state-disabled\' title=\'"+ prevText +"\'><span class=\'ui-icon ui-icon-circle-triangle-" + ( isRTL ? "e" : "w") + "\'>" + prevText + "</span></a>"));\n
\n
\t\tnextText = this._get(inst, "nextText");\n
\t\tnextText = (!navigationAsDateFormat ? nextText : this.formatDate(nextText,\n
\t\t\tthis._daylightSavingAdjust(new Date(drawYear, drawMonth + stepMonths, 1)),\n
\t\t\tthis._getFormatConfig(inst)));\n
\n
\t\tnext = (this._canAdjustMonth(inst, +1, drawYear, drawMonth) ?\n
\t\t\t"<a class=\'ui-datepicker-next ui-corner-all\' data-handler=\'next\' data-event=\'click\'" +\n
\t\t\t" title=\'" + nextText + "\'><span class=\'ui-icon ui-icon-circle-triangle-" + ( isRTL ? "w" : "e") + "\'>" + nextText + "</span></a>" :\n
\t\t\t(hideIfNoPrevNext ? "" : "<a class=\'ui-datepicker-next ui-corner-all ui-state-disabled\' title=\'"+ nextText + "\'><span class=\'ui-icon ui-icon-circle-triangle-" + ( isRTL ? "w" : "e") + "\'>" + nextText + "</span></a>"));\n
\n
\t\tcurrentText = this._get(inst, "currentText");\n
\t\tgotoDate = (this._get(inst, "gotoCurrent") && inst.currentDay ? currentDate : today);\n
\t\tcurrentText = (!navigationAsDateFormat ? currentText :\n
\t\t\tthis.formatDate(currentText, gotoDate, this._getFormatConfig(inst)));\n
\n
\t\tcontrols = (!inst.inline ? "<button type=\'button\' class=\'ui-datepicker-close ui-state-default ui-priority-primary ui-corner-all\' data-handler=\'hide\' data-event=\'click\'>" +\n
\t\t\tthis._get(inst, "closeText") + "</button>" : "");\n
\n
\t\tbuttonPanel = (showButtonPanel) ? "<div class=\'ui-datepicker-buttonpane ui-widget-content\'>" + (isRTL ? controls : "") +\n
\t\t\t(this._isInRange(inst, gotoDate) ? "<button type=\'button\' class=\'ui-datepicker-current ui-state-default ui-priority-secondary ui-corner-all\' data-handler=\'today\' data-event=\'click\'" +\n
\t\t\t">" + currentText + "</button>" : "") + (isRTL ? "" : controls) + "</div>" : "";\n
\n
\t\tfirstDay = parseInt(this._get(inst, "firstDay"),10);\n
\t\tfirstDay = (isNaN(firstDay) ? 0 : firstDay);\n
\n
\t\tshowWeek = this._get(inst, "showWeek");\n
\t\tdayNames = this._get(inst, "dayNames");\n
\t\tdayNamesMin = this._get(inst, "dayNamesMin");\n
\t\tmonthNames = this._get(inst, "monthNames");\n
\t\tmonthNamesShort = this._get(inst, "monthNamesShort");\n
\t\tbeforeShowDay = this._get(inst, "beforeShowDay");\n
\t\tshowOtherMonths = this._get(inst, "showOtherMonths");\n
\t\tselectOtherMonths = this._get(inst, "selectOtherMonths");\n
\t\tdefaultDate = this._getDefaultDate(inst);\n
\t\thtml = "";\n
\t\tdow;\n
\t\tfor (row = 0; row < numMonths[0]; row++) {\n
\t\t\tgroup = "";\n
\t\t\tthis.maxRows = 4;\n
\t\t\tfor (col = 0; col < numMonths[1]; col++) {\n
\t\t\t\tselectedDate = this._daylightSavingAdjust(new Date(drawYear, drawMonth, inst.selectedDay));\n
\t\t\t\tcornerClass = " ui-corner-all";\n
\t\t\t\tcalender = "";\n
\t\t\t\tif (isMultiMonth) {\n
\t\t\t\t\tcalender += "<div class=\'ui-datepicker-group";\n
\t\t\t\t\tif (numMonths[1] > 1) {\n
\t\t\t\t\t\tswitch (col) {\n
\t\t\t\t\t\t\tcase 0: calender += " ui-datepicker-group-first";\n
\t\t\t\t\t\t\t\tcornerClass = " ui-corner-" + (isRTL ? "right" : "left"); break;\n
\t\t\t\t\t\t\tcase numMonths[1]-1: calender += " ui-datepicker-group-last";\n
\t\t\t\t\t\t\t\tcornerClass = " ui-corner-" + (isRTL ? "left" : "right"); break;\n
\t\t\t\t\t\t\tdefault: calender += " ui-datepicker-group-middle"; cornerClass = ""; break;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tcalender += "\'>";\n
\t\t\t\t}\n
\t\t\t\tcalender += "<div class=\'ui-datepicker-header ui-widget-header ui-helper-clearfix" + cornerClass + "\'>" +\n
\t\t\t\t\t(/all|left/.test(cornerClass) && row === 0 ? (isRTL ? next : prev) : "") +\n
\t\t\t\t\t(/all|right/.test(cornerClass) && row === 0 ? (isRTL ? prev : next) : "") +\n
\t\t\t\t\tthis._generateMonthYearHeader(inst, drawMonth, drawYear, minDate, maxDate,\n
\t\t\t\t\trow > 0 || col > 0, monthNames, monthNamesShort) + // draw month headers\n
\t\t\t\t\t"</div><table class=\'ui-datepicker-calendar\'><thead>" +\n
\t\t\t\t\t"<tr>";\n
\t\t\t\tthead = (showWeek ? "<th class=\'ui-datepicker-week-col\'>" + this._get(inst, "weekHeader") + "</th>" : "");\n
\t\t\t\tfor (dow = 0; dow < 7; dow++) { // days of the week\n
\t\t\t\t\tday = (dow + firstDay) % 7;\n
\t\t\t\t\tthead += "<th" + ((dow + firstDay + 6) % 7 >= 5 ? " class=\'ui-datepicker-week-end\'" : "") + ">" +\n
\t\t\t\t\t\t"<span title=\'" + dayNames[day] + "\'>" + dayNamesMin[day] + "</span></th>";\n
\t\t\t\t}\n
\t\t\t\tcalender += thead + "</tr></thead><tbody>";\n
\t\t\t\tdaysInMonth = this._getDaysInMonth(drawYear, drawMonth);\n
\t\t\t\tif (drawYear === inst.selectedYear && drawMonth === inst.selectedMonth) {\n
\t\t\t\t\tinst.selectedDay = Math.min(inst.selectedDay, daysInMonth);\n
\t\t\t\t}\n
\t\t\t\tleadDays = (this._getFirstDayOfMonth(drawYear, drawMonth) - firstDay + 7) % 7;\n
\t\t\t\tcurRows = Math.ceil((leadDays + daysInMonth) / 7); // calculate the number of rows to generate\n
\t\t\t\tnumRows = (isMultiMonth ? this.maxRows > curRows ? this.maxRows : curRows : curRows); //If multiple months, use the higher number of rows (see #7043)\n
\t\t\t\tthis.maxRows = numRows;\n
\t\t\t\tprintDate = this._daylightSavingAdjust(new Date(drawYear, drawMonth, 1 - leadDays));\n
\t\t\t\tfor (dRow = 0; dRow < numRows; dRow++) { // create date picker rows\n
\t\t\t\t\tcalender += "<tr>";\n
\t\t\t\t\ttbody = (!showWeek ? "" : "<td class=\'ui-datepicker-week-col\'>" +\n
\t\t\t\t\t\tthis._get(inst, "calculateWeek")(printDate) + "</td>");\n
\t\t\t\t\tfor (dow = 0; dow < 7; dow++) { // create date picker days\n
\t\t\t\t\t\tdaySettings = (beforeShowDay ?\n
\t\t\t\t\t\t\tbeforeShowDay.apply((inst.input ? inst.input[0] : null), [printDate]) : [true, ""]);\n
\t\t\t\t\t\totherMonth = (printDate.getMonth() !== drawMonth);\n
\t\t\t\t\t\tunselectable = (otherMonth && !selectOtherMonths) || !daySettings[0] ||\n
\t\t\t\t\t\t\t(minDate && printDate < minDate) || (maxDate && printDate > maxDate);\n
\t\t\t\t\t\ttbody += "<td class=\'" +\n
\t\t\t\t\t\t\t((dow + firstDay + 6) % 7 >= 5 ? " ui-datepicker-week-end" : "") + // highlight weekends\n
\t\t\t\t\t\t\t(otherMonth ? " ui-datepicker-other-month" : "") + // highlight days from other months\n
\t\t\t\t\t\t\t((printDate.getTime() === selectedDate.getTime() && drawMonth === inst.selectedMonth && inst._keyEvent) || // user pressed key\n
\t\t\t\t\t\t\t(defaultDate.getTime() === printDate.getTime() && defaultDate.getTime() === selectedDate.getTime()) ?\n
\t\t\t\t\t\t\t// or defaultDate is current printedDate and defaultDate is selectedDate\n
\t\t\t\t\t\t\t" " + this._dayOverClass : "") + // highlight selected day\n
\t\t\t\t\t\t\t(unselectable ? " " + this._unselectableClass + " ui-state-disabled": "") +  // highlight unselectable days\n
\t\t\t\t\t\t\t(otherMonth && !showOtherMonths ? "" : " " + daySettings[1] + // highlight custom dates\n
\t\t\t\t\t\t\t(printDate.getTime() === currentDate.getTime() ? " " + this._currentClass : "") + // highlight selected day\n
\t\t\t\t\t\t\t(printDate.getTime() === today.getTime() ? " ui-datepicker-today" : "")) + "\'" + // highlight today (if different)\n
\t\t\t\t\t\t\t((!otherMonth || showOtherMonths) && daySettings[2] ? " title=\'" + daySettings[2].replace(/\'/g, "&#39;") + "\'" : "") + // cell title\n
\t\t\t\t\t\t\t(unselectable ? "" : " data-handler=\'selectDay\' data-event=\'click\' data-month=\'" + printDate.getMonth() + "\' data-year=\'" + printDate.getFullYear() + "\'") + ">" + // actions\n
\t\t\t\t\t\t\t(otherMonth && !showOtherMonths ? "&#xa0;" : // display for other months\n
\t\t\t\t\t\t\t(unselectable ? "<span class=\'ui-state-default\'>" + printDate.getDate() + "</span>" : "<a class=\'ui-state-default" +\n
\t\t\t\t\t\t\t(printDate.getTime() === today.getTime() ? " ui-state-highlight" : "") +\n
\t\t\t\t\t\t\t(printDate.getTime() === currentDate.getTime() ? " ui-state-active" : "") + // highlight selected day\n
\t\t\t\t\t\t\t(otherMonth ? " ui-priority-secondary" : "") + // distinguish dates from other months\n
\t\t\t\t\t\t\t"\' href=\'#\'>" + printDate.getDate() + "</a>")) + "</td>"; // display selectable date\n
\t\t\t\t\t\tprintDate.setDate(printDate.getDate() + 1);\n
\t\t\t\t\t\tprintDate = this._daylightSavingAdjust(printDate);\n
\t\t\t\t\t}\n
\t\t\t\t\tcalender += tbody + "</tr>";\n
\t\t\t\t}\n
\t\t\t\tdrawMonth++;\n
\t\t\t\tif (drawMonth > 11) {\n
\t\t\t\t\tdrawMonth = 0;\n
\t\t\t\t\tdrawYear++;\n
\t\t\t\t}\n
\t\t\t\tcalender += "</tbody></table>" + (isMultiMonth ? "</div>" +\n
\t\t\t\t\t\t\t((numMonths[0] > 0 && col === numMonths[1]-1) ? "<div class=\'ui-datepicker-row-break\'></div>" : "") : "");\n
\t\t\t\tgroup += calender;\n
\t\t\t}\n
\t\t\thtml += group;\n
\t\t}\n
\t\thtml += buttonPanel;\n
\t\tinst._keyEvent = false;\n
\t\treturn html;\n
\t},\n
\n
\t/* Generate the month and year header. */\n
\t_generateMonthYearHeader: function(inst, drawMonth, drawYear, minDate, maxDate,\n
\t\t\tsecondary, monthNames, monthNamesShort) {\n
\n
\t\tvar inMinYear, inMaxYear, month, years, thisYear, determineYear, year, endYear,\n
\t\t\tchangeMonth = this._get(inst, "changeMonth"),\n
\t\t\tchangeYear = this._get(inst, "changeYear"),\n
\t\t\tshowMonthAfterYear = this._get(inst, "showMonthAfterYear"),\n
\t\t\thtml = "<div class=\'ui-datepicker-title\'>",\n
\t\t\tmonthHtml = "";\n
\n
\t\t// month selection\n
\t\tif (secondary || !changeMonth) {\n
\t\t\tmonthHtml += "<span class=\'ui-datepicker-month\'>" + monthNames[drawMonth] + "</span>";\n
\t\t} else {\n
\t\t\tinMinYear = (minDate && minDate.getFullYear() === drawYear);\n
\t\t\tinMaxYear = (maxDate && maxDate.getFullYear() === drawYear);\n
\t\t\tmonthHtml += "<select class=\'ui-datepicker-month\' data-handler=\'selectMonth\' data-event=\'change\'>";\n
\t\t\tfor ( month = 0; month < 12; month++) {\n
\t\t\t\tif ((!inMinYear || month >= minDate.getMonth()) && (!inMaxYear || month <= maxDate.getMonth())) {\n
\t\t\t\t\tmonthHtml += "<option value=\'" + month + "\'" +\n
\t\t\t\t\t\t(month === drawMonth ? " selected=\'selected\'" : "") +\n
\t\t\t\t\t\t">" + monthNamesShort[month] + "</option>";\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tmonthHtml += "</select>";\n
\t\t}\n
\n
\t\tif (!showMonthAfterYear) {\n
\t\t\thtml += monthHtml + (secondary || !(changeMonth && changeYear) ? "&#xa0;" : "");\n
\t\t}\n
\n
\t\t// year selection\n
\t\tif ( !inst.yearshtml ) {\n
\t\t\tinst.yearshtml = "";\n
\t\t\tif (secondary || !changeYear) {\n
\t\t\t\thtml += "<span class=\'ui-datepicker-year\'>" + drawYear + "</span>";\n
\t\t\t} else {\n
\t\t\t\t// determine range of years to display\n
\t\t\t\tyears = this._get(inst, "yearRange").split(":");\n
\t\t\t\tthisYear = new Date().getFullYear();\n
\t\t\t\tdetermineYear = function(value) {\n
\t\t\t\t\tvar year = (value.match(/c[+\\-].*/) ? drawYear + parseInt(value.substring(1), 10) :\n
\t\t\t\t\t\t(value.match(/[+\\-].*/) ? thisYear + parseInt(value, 10) :\n
\t\t\t\t\t\tparseInt(value, 10)));\n
\t\t\t\t\treturn (isNaN(year) ? thisYear : year);\n
\t\t\t\t};\n
\t\t\t\tyear = determineYear(years[0]);\n
\t\t\t\tendYear = Math.max(year, determineYear(years[1] || ""));\n
\t\t\t\tyear = (minDate ? Math.max(year, minDate.getFullYear()) : year);\n
\t\t\t\tendYear = (maxDate ? Math.min(endYear, maxDate.getFullYear()) : endYear);\n
\t\t\t\tinst.yearshtml += "<select class=\'ui-datepicker-year\' data-handler=\'selectYear\' data-event=\'change\'>";\n
\t\t\t\tfor (; year <= endYear; year++) {\n
\t\t\t\t\tinst.yearshtml += "<option value=\'" + year + "\'" +\n
\t\t\t\t\t\t(year === drawYear ? " selected=\'selected\'" : "") +\n
\t\t\t\t\t\t">" + year + "</option>";\n
\t\t\t\t}\n
\t\t\t\tinst.yearshtml += "</select>";\n
\n
\t\t\t\thtml += inst.yearshtml;\n
\t\t\t\tinst.yearshtml = null;\n
\t\t\t}\n
\t\t}\n
\n
\t\thtml += this._get(inst, "yearSuffix");\n
\t\tif (showMonthAfterYear) {\n
\t\t\thtml += (secondary || !(changeMonth && changeYear) ? "&#xa0;" : "") + monthHtml;\n
\t\t}\n
\t\thtml += "</div>"; // Close datepicker_header\n
\t\treturn html;\n
\t},\n
\n
\t/* Adjust one of the date sub-fields. */\n
\t_adjustInstDate: function(inst, offset, period) {\n
\t\tvar year = inst.drawYear + (period === "Y" ? offset : 0),\n
\t\t\tmonth = inst.drawMonth + (period === "M" ? offset : 0),\n
\t\t\tday = Math.min(inst.selectedDay, this._getDaysInMonth(year, month)) + (period === "D" ? offset : 0),\n
\t\t\tdate = this._restrictMinMax(inst, this._daylightSavingAdjust(new Date(year, month, day)));\n
\n
\t\tinst.selectedDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\tif (period === "M" || period === "Y") {\n
\t\t\tthis._notifyChange(inst);\n
\t\t}\n
\t},\n
\n
\t/* Ensure a date is within any min/max bounds. */\n
\t_restrictMinMax: function(inst, date) {\n
\t\tvar minDate = this._getMinMaxDate(inst, "min"),\n
\t\t\tmaxDate = this._getMinMaxDate(inst, "max"),\n
\t\t\tnewDate = (minDate && date < minDate ? minDate : date);\n
\t\treturn (maxDate && newDate > maxDate ? maxDate : newDate);\n
\t},\n
\n
\t/* Notify change of month/year. */\n
\t_notifyChange: function(inst) {\n
\t\tvar onChange = this._get(inst, "onChangeMonthYear");\n
\t\tif (onChange) {\n
\t\t\tonChange.apply((inst.input ? inst.input[0] : null),\n
\t\t\t\t[inst.selectedYear, inst.selectedMonth + 1, inst]);\n
\t\t}\n
\t},\n
\n
\t/* Determine the number of months to show. */\n
\t_getNumberOfMonths: function(inst) {\n
\t\tvar numMonths = this._get(inst, "numberOfMonths");\n
\t\treturn (numMonths == null ? [1, 1] : (typeof numMonths === "number" ? [1, numMonths] : numMonths));\n
\t},\n
\n
\t/* Determine the current maximum date - ensure no time components are set. */\n
\t_getMinMaxDate: function(inst, minMax) {\n
\t\treturn this._determineDate(inst, this._get(inst, minMax + "Date"), null);\n
\t},\n
\n
\t/* Find the number of days in a given month. */\n
\t_getDaysInMonth: function(year, month) {\n
\t\treturn 32 - this._daylightSavingAdjust(new Date(year, month, 32)).getDate();\n
\t},\n
\n
\t/* Find the day of the week of the first of a month. */\n
\t_getFirstDayOfMonth: function(year, month) {\n
\t\treturn new Date(year, month, 1).getDay();\n
\t},\n
\n
\t/* Determines if we should allow a "next/prev" month display change. */\n
\t_canAdjustMonth: function(inst, offset, curYear, curMonth) {\n
\t\tvar numMonths = this._getNumberOfMonths(inst),\n
\t\t\tdate = this._daylightSavingAdjust(new Date(curYear,\n
\t\t\tcurMonth + (offset < 0 ? offset : numMonths[0] * numMonths[1]), 1));\n
\n
\t\tif (offset < 0) {\n
\t\t\tdate.setDate(this._getDaysInMonth(date.getFullYear(), date.getMonth()));\n
\t\t}\n
\t\treturn this._isInRange(inst, date);\n
\t},\n
\n
\t/* Is the given date in the accepted range? */\n
\t_isInRange: function(inst, date) {\n
\t\tvar yearSplit, currentYear,\n
\t\t\tminDate = this._getMinMaxDate(inst, "min"),\n
\t\t\tmaxDate = this._getMinMaxDate(inst, "max"),\n
\t\t\tminYear = null,\n
\t\t\tmaxYear = null,\n
\t\t\tyears = this._get(inst, "yearRange");\n
\t\t\tif (years){\n
\t\t\t\tyearSplit = years.split(":");\n
\t\t\t\tcurrentYear = new Date().getFullYear();\n
\t\t\t\tminYear = parseInt(yearSplit[0], 10);\n
\t\t\t\tmaxYear = parseInt(yearSplit[1], 10);\n
\t\t\t\tif ( yearSplit[0].match(/[+\\-].*/) ) {\n
\t\t\t\t\tminYear += currentYear;\n
\t\t\t\t}\n
\t\t\t\tif ( yearSplit[1].match(/[+\\-].*/) ) {\n
\t\t\t\t\tmaxYear += currentYear;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\treturn ((!minDate || date.getTime() >= minDate.getTime()) &&\n
\t\t\t(!maxDate || date.getTime() <= maxDate.getTime()) &&\n
\t\t\t(!minYear || date.getFullYear() >= minYear) &&\n
\t\t\t(!maxYear || date.getFullYear() <= maxYear));\n
\t},\n
\n
\t/* Provide the configuration settings for formatting/parsing. */\n
\t_getFormatConfig: function(inst) {\n
\t\tvar shortYearCutoff = this._get(inst, "shortYearCutoff");\n
\t\tshortYearCutoff = (typeof shortYearCutoff !== "string" ? shortYearCutoff :\n
\t\t\tnew Date().getFullYear() % 100 + parseInt(shortYearCutoff, 10));\n
\t\treturn {shortYearCutoff: shortYearCutoff,\n
\t\t\tdayNamesShort: this._get(inst, "dayNamesShort"), dayNames: this._get(inst, "dayNames"),\n
\t\t\tmonthNamesShort: this._get(inst, "monthNamesShort"), monthNames: this._get(inst, "monthNames")};\n
\t},\n
\n
\t/* Format the given date for display. */\n
\t_formatDate: function(inst, day, month, year) {\n
\t\tif (!day) {\n
\t\t\tinst.currentDay = inst.selectedDay;\n
\t\t\tinst.currentMonth = inst.selectedMonth;\n
\t\t\tinst.currentYear = inst.selectedYear;\n
\t\t}\n
\t\tvar date = (day ? (typeof day === "object" ? day :\n
\t\t\tthis._daylightSavingAdjust(new Date(year, month, day))) :\n
\t\t\tthis._daylightSavingAdjust(new Date(inst.currentYear, inst.currentMonth, inst.currentDay)));\n
\t\treturn this.formatDate(this._get(inst, "dateFormat"), date, this._getFormatConfig(inst));\n
\t}\n
});\n
\n
/*\n
 * Bind hover events for datepicker elements.\n
 * Done via delegate so the binding only occurs once in the lifetime of the parent div.\n
 * Global instActive, set by _updateDatepicker allows the handlers to find their way back to the active picker.\n
 */\n
function bindHover(dpDiv) {\n
\tvar selector = "button, .ui-datepicker-prev, .ui-datepicker-next, .ui-datepicker-calendar td a";\n
\treturn dpDiv.delegate(selector, "mouseout", function() {\n
\t\t\t$(this).removeClass("ui-state-hover");\n
\t\t\tif (this.className.indexOf("ui-datepicker-prev") !== -1) {\n
\t\t\t\t$(this).removeClass("ui-datepicker-prev-hover");\n
\t\t\t}\n
\t\t\tif (this.className.indexOf("ui-datepicker-next") !== -1) {\n
\t\t\t\t$(this).removeClass("ui-datepicker-next-hover");\n
\t\t\t}\n
\t\t})\n
\t\t.delegate(selector, "mouseover", function(){\n
\t\t\tif (!$.datepicker._isDisabledDatepicker( instActive.inline ? dpDiv.parent()[0] : instActive.input[0])) {\n
\t\t\t\t$(this).parents(".ui-datepicker-calendar").find("a").removeClass("ui-state-hover");\n
\t\t\t\t$(this).addClass("ui-state-hover");\n
\t\t\t\tif (this.className.indexOf("ui-datepicker-prev") !== -1) {\n
\t\t\t\t\t$(this).addClass("ui-datepicker-prev-hover");\n
\t\t\t\t}\n
\t\t\t\tif (this.className.indexOf("ui-datepicker-next") !== -1) {\n
\t\t\t\t\t$(this).addClass("ui-datepicker-next-hover");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
}\n
\n
/* jQuery extend now ignores nulls! */\n
function extendRemove(target, props) {\n
\t$.extend(target, props);\n
\tfor (var name in props) {\n
\t\tif (props[name] == null) {\n
\t\t\ttarget[name] = props[name];\n
\t\t}\n
\t}\n
\treturn target;\n
}\n
\n
/* Invoke the datepicker functionality.\n
   @param  options  string - a command, optionally followed by additional parameters or\n
\t\t\t\t\tObject - settings for attaching new datepicker functionality\n
   @return  jQuery object */\n
$.fn.datepicker = function(options){\n
\n
\t/* Verify an empty collection wasn\'t passed - Fixes #6976 */\n
\tif ( !this.length ) {\n
\t\treturn this;\n
\t}\n
\n
\t/* Initialise the date picker. */\n
\tif (!$.datepicker.initialized) {\n
\t\t$(document).mousedown($.datepicker._checkExternalClick);\n
\t\t$.datepicker.initialized = true;\n
\t}\n
\n
\t/* Append datepicker main container to body if not exist. */\n
\tif ($("#"+$.datepicker._mainDivId).length === 0) {\n
\t\t$("body").append($.datepicker.dpDiv);\n
\t}\n
\n
\tvar otherArgs = Array.prototype.slice.call(arguments, 1);\n
\tif (typeof options === "string" && (options === "isDisabled" || options === "getDate" || options === "widget")) {\n
\t\treturn $.datepicker["_" + options + "Datepicker"].\n
\t\t\tapply($.datepicker, [this[0]].concat(otherArgs));\n
\t}\n
\tif (options === "option" && arguments.length === 2 && typeof arguments[1] === "string") {\n
\t\treturn $.datepicker["_" + options + "Datepicker"].\n
\t\t\tapply($.datepicker, [this[0]].concat(otherArgs));\n
\t}\n
\treturn this.each(function() {\n
\t\ttypeof options === "string" ?\n
\t\t\t$.datepicker["_" + options + "Datepicker"].\n
\t\t\t\tapply($.datepicker, [this].concat(otherArgs)) :\n
\t\t\t$.datepicker._attachDatepicker(this, options);\n
\t});\n
};\n
\n
$.datepicker = new Datepicker(); // singleton instance\n
$.datepicker.initialized = false;\n
$.datepicker.uuid = new Date().getTime();\n
$.datepicker.version = "1.10.4";\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
var sizeRelatedOptions = {\n
\t\tbuttons: true,\n
\t\theight: true,\n
\t\tmaxHeight: true,\n
\t\tmaxWidth: true,\n
\t\tminHeight: true,\n
\t\tminWidth: true,\n
\t\twidth: true\n
\t},\n
\tresizableRelatedOptions = {\n
\t\tmaxHeight: true,\n
\t\tmaxWidth: true,\n
\t\tminHeight: true,\n
\t\tminWidth: true\n
\t};\n
\n
$.widget( "ui.dialog", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tappendTo: "body",\n
\t\tautoOpen: true,\n
\t\tbuttons: [],\n
\t\tcloseOnEscape: true,\n
\t\tcloseText: "close",\n
\t\tdialogClass: "",\n
\t\tdraggable: true,\n
\t\thide: null,\n
\t\theight: "auto",\n
\t\tmaxHeight: null,\n
\t\tmaxWidth: null,\n
\t\tminHeight: 150,\n
\t\tminWidth: 150,\n
\t\tmodal: false,\n
\t\tposition: {\n
\t\t\tmy: "center",\n
\t\t\tat: "center",\n
\t\t\tof: window,\n
\t\t\tcollision: "fit",\n
\t\t\t// Ensure the titlebar is always visible\n
\t\t\tusing: function( pos ) {\n
\t\t\t\tvar topOffset = $( this ).css( pos ).offset().top;\n
\t\t\t\tif ( topOffset < 0 ) {\n
\t\t\t\t\t$( this ).css( "top", pos.top - topOffset );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\tresizable: true,\n
\t\tshow: null,\n
\t\ttitle: null,\n
\t\twidth: 300,\n
\n
\t\t// callbacks\n
\t\tbeforeClose: null,\n
\t\tclose: null,\n
\t\tdrag: null,\n
\t\tdragStart: null,\n
\t\tdragStop: null,\n
\t\tfocus: null,\n
\t\topen: null,\n
\t\tresize: null,\n
\t\tresizeStart: null,\n
\t\tresizeStop: null\n
\t},\n
\n
\t_create: function() {\n
\t\tthis.originalCss = {\n
\t\t\tdisplay: this.element[0].style.display,\n
\t\t\twidth: this.element[0].style.width,\n
\t\t\tminHeight: this.element[0].style.minHeight,\n
\t\t\tmaxHeight: this.element[0].style.maxHeight,\n
\t\t\theight: this.element[0].style.height\n
\t\t};\n
\t\tthis.originalPosition = {\n
\t\t\tparent: this.element.parent(),\n
\t\t\tindex: this.element.parent().children().index( this.element )\n
\t\t};\n
\t\tthis.originalTitle = this.element.attr("title");\n
\t\tthis.options.title = this.options.title || this.originalTitle;\n
\n
\t\tthis._createWrapper();\n
\n
\t\tthis.element\n
\t\t\t.show()\n
\t\t\t.removeAttr("title")\n
\t\t\t.addClass("ui-dialog-content ui-widget-content")\n
\t\t\t.appendTo( this.uiDialog );\n
\n
\t\tthis._createTitlebar();\n
\t\tthis._createButtonPane();\n
\n
\t\tif ( this.options.draggable && $.fn.draggable ) {\n
\t\t\tthis._makeDraggable();\n
\t\t}\n
\t\tif ( this.options.resizable && $.fn.resizable ) {\n
\t\t\tthis._makeResizable();\n
\t\t}\n
\n
\t\tthis._isOpen = false;\n
\t},\n
\n
\t_init: function() {\n
\t\tif ( this.options.autoOpen ) {\n
\t\t\tthis.open();\n
\t\t}\n
\t},\n
\n
\t_appendTo: function() {\n
\t\tvar element = this.options.appendTo;\n
\t\tif ( element && (element.jquery || element.nodeType) ) {\n
\t\t\treturn $( element );\n
\t\t}\n
\t\treturn this.document.find( element || "body" ).eq( 0 );\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar next,\n
\t\t\toriginalPosition = this.originalPosition;\n
\n
\t\tthis._destroyOverlay();\n
\n
\t\tthis.element\n
\t\t\t.removeUniqueId()\n
\t\t\t.removeClass("ui-dialog-content ui-widget-content")\n
\t\t\t.css( this.originalCss )\n
\t\t\t// Without detaching first, the following becomes really slow\n
\t\t\t.detach();\n
\n
\t\tthis.uiDialog.stop( true, true ).remove();\n
\n
\t\tif ( this.originalTitle ) {\n
\t\t\tthis.element.attr( "title", this.originalTitle );\n
\t\t}\n
\n
\t\tnext = originalPosition.parent.children().eq( originalPosition.index );\n
\t\t// Don\'t try to place the dialog next to itself (#8613)\n
\t\tif ( next.length && next[0] !== this.element[0] ) {\n
\t\t\tnext.before( this.element );\n
\t\t} else {\n
\t\t\toriginalPosition.parent.append( this.element );\n
\t\t}\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.uiDialog;\n
\t},\n
\n
\tdisable: $.noop,\n
\tenable: $.noop,\n
\n
\tclose: function( event ) {\n
\t\tvar activeElement,\n
\t\t\tthat = this;\n
\n
\t\tif ( !this._isOpen || this._trigger( "beforeClose", event ) === false ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._isOpen = false;\n
\t\tthis._destroyOverlay();\n
\n
\t\tif ( !this.opener.filter(":focusable").focus().length ) {\n
\n
\t\t\t// support: IE9\n
\t\t\t// IE9 throws an "Unspecified error" accessing document.activeElement from an <iframe>\n
\t\t\ttry {\n
\t\t\t\tactiveElement = this.document[ 0 ].activeElement;\n
\n
\t\t\t\t// Support: IE9, IE10\n
\t\t\t\t// If the <body> is blurred, IE will switch windows, see #4520\n
\t\t\t\tif ( activeElement && activeElement.nodeName.toLowerCase() !== "body" ) {\n
\n
\t\t\t\t\t// Hiding a focused element doesn\'t trigger blur in WebKit\n
\t\t\t\t\t// so in case we have nothing to focus on, explicitly blur the active element\n
\t\t\t\t\t// https://bugs.webkit.org/show_bug.cgi?id=47182\n
\t\t\t\t\t$( activeElement ).blur();\n
\t\t\t\t}\n
\t\t\t} catch ( error ) {}\n
\t\t}\n
\n
\t\tthis._hide( this.uiDialog, this.options.hide, function() {\n
\t\t\tthat._trigger( "close", event );\n
\t\t});\n
\t},\n
\n
\tisOpen: function() {\n
\t\treturn this._isOpen;\n
\t},\n
\n
\tmoveToTop: function() {\n
\t\tthis._moveToTop();\n
\t},\n
\n
\t_moveToTop: function( event, silent ) {\n
\t\tvar moved = !!this.uiDialog.nextAll(":visible").insertBefore( this.uiDialog ).length;\n
\t\tif ( moved && !silent ) {\n
\t\t\tthis._trigger( "focus", event );\n
\t\t}\n
\t\treturn moved;\n
\t},\n
\n
\topen: function() {\n
\t\tvar that = this;\n
\t\tif ( this._isOpen ) {\n
\t\t\tif ( this._moveToTop() ) {\n
\t\t\t\tthis._focusTabbable();\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._isOpen = true;\n
\t\tthis.opener = $( this.document[0].activeElement );\n
\n
\t\tthis._size();\n
\t\tthis._position();\n
\t\tthis._createOverlay();\n
\t\tthis._moveToTop( null, true );\n
\t\tthis._show( this.uiDialog, this.options.show, function() {\n
\t\t\tthat._focusTabbable();\n
\t\t\tthat._trigger("focus");\n
\t\t});\n
\n
\t\tthis._trigger("open");\n
\t},\n
\n
\t_focusTabbable: function() {\n
\t\t// Set focus to the first match:\n
\t\t// 1. First element inside the dialog matching [autofocus]\n
\t\t// 2. Tabbable element inside the content element\n
\t\t// 3. Tabbable element inside the buttonpane\n
\t\t// 4. The close button\n
\t\t// 5. The dialog itself\n
\t\tvar hasFocus = this.element.find("[autofocus]");\n
\t\tif ( !hasFocus.length ) {\n
\t\t\thasFocus = this.element.find(":tabbable");\n
\t\t}\n
\t\tif ( !hasFocus.length ) {\n
\t\t\thasFocus = this.uiDialogButtonPane.find(":tabbable");\n
\t\t}\n
\t\tif ( !hasFocus.length ) {\n
\t\t\thasFocus = this.uiDialogTitlebarClose.filter(":tabbable");\n
\t\t}\n
\t\tif ( !hasFocus.length ) {\n
\t\t\thasFocus = this.uiDialog;\n
\t\t}\n
\t\thasFocus.eq( 0 ).focus();\n
\t},\n
\n
\t_keepFocus: function( event ) {\n
\t\tfunction checkFocus() {\n
\t\t\tvar activeElement = this.document[0].activeElement,\n
\t\t\t\tisActive = this.uiDialog[0] === activeElement ||\n
\t\t\t\t\t$.contains( this.uiDialog[0], activeElement );\n
\t\t\tif ( !isActive ) {\n
\t\t\t\tthis._focusTabbable();\n
\t\t\t}\n
\t\t}\n
\t\tevent.preventDefault();\n
\t\tcheckFocus.call( this );\n
\t\t// support: IE\n
\t\t// IE <= 8 doesn\'t prevent moving focus even with event.preventDefault()\n
\t\t// so we check again later\n
\t\tthis._delay( checkFocus );\n
\t},\n
\n
\t_createWrapper: function() {\n
\t\tthis.uiDialog = $("<div>")\n
\t\t\t.addClass( "ui-dialog ui-widget ui-widget-content ui-corner-all ui-front " +\n
\t\t\t\tthis.options.dialogClass )\n
\t\t\t.hide()\n
\t\t\t.attr({\n
\t\t\t\t// Setting tabIndex makes the div focusable\n
\t\t\t\ttabIndex: -1,\n
\t\t\t\trole: "dialog"\n
\t\t\t})\n
\t\t\t.appendTo( this._appendTo() );\n
\n
\t\tthis._on( this.uiDialog, {\n
\t\t\tkeydown: function( event ) {\n
\t\t\t\tif ( this.options.closeOnEscape && !event.isDefaultPrevented() && event.keyCode &&\n
\t\t\t\t\t\tevent.keyCode === $.ui.keyCode.ESCAPE ) {\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\tthis.close( event );\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\t// prevent tabbing out of dialogs\n
\t\t\t\tif ( event.keyCode !== $.ui.keyCode.TAB ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tvar tabbables = this.uiDialog.find(":tabbable"),\n
\t\t\t\t\tfirst = tabbables.filter(":first"),\n
\t\t\t\t\tlast  = tabbables.filter(":last");\n
\n
\t\t\t\tif ( ( event.target === last[0] || event.target === this.uiDialog[0] ) && !event.shiftKey ) {\n
\t\t\t\t\tfirst.focus( 1 );\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t} else if ( ( event.target === first[0] || event.target === this.uiDialog[0] ) && event.shiftKey ) {\n
\t\t\t\t\tlast.focus( 1 );\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tmousedown: function( event ) {\n
\t\t\t\tif ( this._moveToTop( event ) ) {\n
\t\t\t\t\tthis._focusTabbable();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\t// We assume that any existing aria-describedby attribute means\n
\t\t// that the dialog content is marked up properly\n
\t\t// otherwise we brute force the content as the description\n
\t\tif ( !this.element.find("[aria-describedby]").length ) {\n
\t\t\tthis.uiDialog.attr({\n
\t\t\t\t"aria-describedby": this.element.uniqueId().attr("id")\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\t_createTitlebar: function() {\n
\t\tvar uiDialogTitle;\n
\n
\t\tthis.uiDialogTitlebar = $("<div>")\n
\t\t\t.addClass("ui-dialog-titlebar ui-widget-header ui-corner-all ui-helper-clearfix")\n
\t\t\t.prependTo( this.uiDialog );\n
\t\tthis._on( this.uiDialogTitlebar, {\n
\t\t\tmousedown: function( event ) {\n
\t\t\t\t// Don\'t prevent click on close button (#8838)\n
\t\t\t\t// Focusing a dialog that is partially scrolled out of view\n
\t\t\t\t// causes the browser to scroll it into view, preventing the click event\n
\t\t\t\tif ( !$( event.target ).closest(".ui-dialog-titlebar-close") ) {\n
\t\t\t\t\t// Dialog isn\'t getting focus when dragging (#8063)\n
\t\t\t\t\tthis.uiDialog.focus();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\t// support: IE\n
\t\t// Use type="button" to prevent enter keypresses in textboxes from closing the\n
\t\t// dialog in IE (#9312)\n
\t\tthis.uiDialogTitlebarClose = $( "<button type=\'button\'></button>" )\n
\t\t\t.button({\n
\t\t\t\tlabel: this.options.closeText,\n
\t\t\t\ticons: {\n
\t\t\t\t\tprimary: "ui-icon-closethick"\n
\t\t\t\t},\n
\t\t\t\ttext: false\n
\t\t\t})\n
\t\t\t.addClass("ui-dialog-titlebar-close")\n
\t\t\t.appendTo( this.uiDialogTitlebar );\n
\t\tthis._on( this.uiDialogTitlebarClose, {\n
\t\t\tclick: function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\tthis.close( event );\n
\t\t\t}\n
\t\t});\n
\n
\t\tuiDialogTitle = $("<span>")\n
\t\t\t.uniqueId()\n
\t\t\t.addClass("ui-dialog-title")\n
\t\t\t.prependTo( this.uiDialogTitlebar );\n
\t\tthis._title( uiDialogTitle );\n
\n
\t\tthis.uiDialog.attr({\n
\t\t\t"aria-labelledby": uiDialogTitle.attr("id")\n
\t\t});\n
\t},\n
\n
\t_title: function( title ) {\n
\t\tif ( !this.options.title ) {\n
\t\t\ttitle.html("&#160;");\n
\t\t}\n
\t\ttitle.text( this.options.title );\n
\t},\n
\n
\t_createButtonPane: function() {\n
\t\tthis.uiDialogButtonPane = $("<div>")\n
\t\t\t.addClass("ui-dialog-buttonpane ui-widget-content ui-helper-clearfix");\n
\n
\t\tthis.uiButtonSet = $("<div>")\n
\t\t\t.addClass("ui-dialog-buttonset")\n
\t\t\t.appendTo( this.uiDialogButtonPane );\n
\n
\t\tthis._createButtons();\n
\t},\n
\n
\t_createButtons: function() {\n
\t\tvar that = this,\n
\t\t\tbuttons = this.options.buttons;\n
\n
\t\t// if we already have a button pane, remove it\n
\t\tthis.uiDialogButtonPane.remove();\n
\t\tthis.uiButtonSet.empty();\n
\n
\t\tif ( $.isEmptyObject( buttons ) || ($.isArray( buttons ) && !buttons.length) ) {\n
\t\t\tthis.uiDialog.removeClass("ui-dialog-buttons");\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t$.each( buttons, function( name, props ) {\n
\t\t\tvar click, buttonOptions;\n
\t\t\tprops = $.isFunction( props ) ?\n
\t\t\t\t{ click: props, text: name } :\n
\t\t\t\tprops;\n
\t\t\t// Default to a non-submitting button\n
\t\t\tprops = $.extend( { type: "button" }, props );\n
\t\t\t// Change the context for the click callback to be the main element\n
\t\t\tclick = props.click;\n
\t\t\tprops.click = function() {\n
\t\t\t\tclick.apply( that.element[0], arguments );\n
\t\t\t};\n
\t\t\tbuttonOptions = {\n
\t\t\t\ticons: props.icons,\n
\t\t\t\ttext: props.showText\n
\t\t\t};\n
\t\t\tdelete props.icons;\n
\t\t\tdelete props.showText;\n
\t\t\t$( "<button></button>", props )\n
\t\t\t\t.button( buttonOptions )\n
\t\t\t\t.appendTo( that.uiButtonSet );\n
\t\t});\n
\t\tthis.uiDialog.addClass("ui-dialog-buttons");\n
\t\tthis.uiDialogButtonPane.appendTo( this.uiDialog );\n
\t},\n
\n
\t_makeDraggable: function() {\n
\t\tvar that = this,\n
\t\t\toptions = this.options;\n
\n
\t\tfunction filteredUi( ui ) {\n
\t\t\treturn {\n
\t\t\t\tposition: ui.position,\n
\t\t\t\toffset: ui.offset\n
\t\t\t};\n
\t\t}\n
\n
\t\tthis.uiDialog.draggable({\n
\t\t\tcancel: ".ui-dialog-content, .ui-dialog-titlebar-close",\n
\t\t\thandle: ".ui-dialog-titlebar",\n
\t\t\tcontainment: "document",\n
\t\t\tstart: function( event, ui ) {\n
\t\t\t\t$( this ).addClass("ui-dialog-dragging");\n
\t\t\t\tthat._blockFrames();\n
\t\t\t\tthat._trigger( "dragStart", event, filteredUi( ui ) );\n
\t\t\t},\n
\t\t\tdrag: function( event, ui ) {\n
\t\t\t\tthat._trigger( "drag", event, filteredUi( ui ) );\n
\t\t\t},\n
\t\t\tstop: function( event, ui ) {\n
\t\t\t\toptions.position = [\n
\t\t\t\t\tui.position.left - that.document.scrollLeft(),\n
\t\t\t\t\tui.position.top - that.document.scrollTop()\n
\t\t\t\t];\n
\t\t\t\t$( this ).removeClass("ui-dialog-dragging");\n
\t\t\t\tthat._unblockFrames();\n
\t\t\t\tthat._trigger( "dragStop", event, filteredUi( ui ) );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_makeResizable: function() {\n
\t\tvar that = this,\n
\t\t\toptions = this.options,\n
\t\t\thandles = options.resizable,\n
\t\t\t// .ui-resizable has position: relative defined in the stylesheet\n
\t\t\t// but dialogs have to use absolute or fixed positioning\n
\t\t\tposition = this.uiDialog.css("position"),\n
\t\t\tresizeHandles = typeof handles === "string" ?\n
\t\t\t\thandles\t:\n
\t\t\t\t"n,e,s,w,se,sw,ne,nw";\n
\n
\t\tfunction filteredUi( ui ) {\n
\t\t\treturn {\n
\t\t\t\toriginalPosition: ui.originalPosition,\n
\t\t\t\toriginalSize: ui.originalSize,\n
\t\t\t\tposition: ui.position,\n
\t\t\t\tsize: ui.size\n
\t\t\t};\n
\t\t}\n
\n
\t\tthis.uiDialog.resizable({\n
\t\t\tcancel: ".ui-dialog-content",\n
\t\t\tcontainment: "document",\n
\t\t\talsoResize: this.element,\n
\t\t\tmaxWidth: options.maxWidth,\n
\t\t\tmaxHeight: options.maxHeight,\n
\t\t\tminWidth: options.minWidth,\n
\t\t\tminHeight: this._minHeight(),\n
\t\t\thandles: resizeHandles,\n
\t\t\tstart: function( event, ui ) {\n
\t\t\t\t$( this ).addClass("ui-dialog-resizing");\n
\t\t\t\tthat._blockFrames();\n
\t\t\t\tthat._trigger( "resizeStart", event, filteredUi( ui ) );\n
\t\t\t},\n
\t\t\tresize: function( event, ui ) {\n
\t\t\t\tthat._trigger( "resize", event, filteredUi( ui ) );\n
\t\t\t},\n
\t\t\tstop: function( event, ui ) {\n
\t\t\t\toptions.height = $( this ).height();\n
\t\t\t\toptions.width = $( this ).width();\n
\t\t\t\t$( this ).removeClass("ui-dialog-resizing");\n
\t\t\t\tthat._unblockFrames();\n
\t\t\t\tthat._trigger( "resizeStop", event, filteredUi( ui ) );\n
\t\t\t}\n
\t\t})\n
\t\t.css( "position", position );\n
\t},\n
\n
\t_minHeight: function() {\n
\t\tvar options = this.options;\n
\n
\t\treturn options.height === "auto" ?\n
\t\t\toptions.minHeight :\n
\t\t\tMath.min( options.minHeight, options.height );\n
\t},\n
\n
\t_position: function() {\n
\t\t// Need to show the dialog to get the actual offset in the position plugin\n
\t\tvar isVisible = this.uiDialog.is(":visible");\n
\t\tif ( !isVisible ) {\n
\t\t\tthis.uiDialog.show();\n
\t\t}\n
\t\tthis.uiDialog.position( this.options.position );\n
\t\tif ( !isVisible ) {\n
\t\t\tthis.uiDialog.hide();\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar that = this,\n
\t\t\tresize = false,\n
\t\t\tresizableOptions = {};\n
\n
\t\t$.each( options, function( key, value ) {\n
\t\t\tthat._setOption( key, value );\n
\n
\t\t\tif ( key in sizeRelatedOptions ) {\n
\t\t\t\tresize = true;\n
\t\t\t}\n
\t\t\tif ( key in resizableRelatedOptions ) {\n
\t\t\t\tresizableOptions[ key ] = value;\n
\t\t\t}\n
\t\t});\n
\n
\t\tif ( resize ) {\n
\t\t\tthis._size();\n
\t\t\tthis._position();\n
\t\t}\n
\t\tif ( this.uiDialog.is(":data(ui-resizable)") ) {\n
\t\t\tthis.uiDialog.resizable( "option", resizableOptions );\n
\t\t}\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tvar isDraggable, isResizable,\n
\t\t\tuiDialog = this.uiDialog;\n
\n
\t\tif ( key === "dialogClass" ) {\n
\t\t\tuiDialog\n
\t\t\t\t.removeClass( this.options.dialogClass )\n
\t\t\t\t.addClass( value );\n
\t\t}\n
\n
\t\tif ( key === "disabled" ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\n
\t\tif ( key === "appendTo" ) {\n
\t\t\tthis.uiDialog.appendTo( this._appendTo() );\n
\t\t}\n
\n
\t\tif ( key === "buttons" ) {\n
\t\t\tthis._createButtons();\n
\t\t}\n
\n
\t\tif ( key === "closeText" ) {\n
\t\t\tthis.uiDialogTitlebarClose.button({\n
\t\t\t\t// Ensure that we always pass a string\n
\t\t\t\tlabel: "" + value\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( key === "draggable" ) {\n
\t\t\tisDraggable = uiDialog.is(":data(ui-draggable)");\n
\t\t\tif ( isDraggable && !value ) {\n
\t\t\t\tuiDialog.draggable("destroy");\n
\t\t\t}\n
\n
\t\t\tif ( !isDraggable && value ) {\n
\t\t\t\tthis._makeDraggable();\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( key === "position" ) {\n
\t\t\tthis._position();\n
\t\t}\n
\n
\t\tif ( key === "resizable" ) {\n
\t\t\t// currently resizable, becoming non-resizable\n
\t\t\tisResizable = uiDialog.is(":data(ui-resizable)");\n
\t\t\tif ( isResizable && !value ) {\n
\t\t\t\tuiDialog.resizable("destroy");\n
\t\t\t}\n
\n
\t\t\t// currently resizable, changing handles\n
\t\t\tif ( isResizable && typeof value === "string" ) {\n
\t\t\t\tuiDialog.resizable( "option", "handles", value );\n
\t\t\t}\n
\n
\t\t\t// currently non-resizable, becoming resizable\n
\t\t\tif ( !isResizable && value !== false ) {\n
\t\t\t\tthis._makeResizable();\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( key === "title" ) {\n
\t\t\tthis._title( this.uiDialogTitlebar.find(".ui-dialog-title") );\n
\t\t}\n
\t},\n
\n
\t_size: function() {\n
\t\t// If the user has resized the dialog, the .ui-dialog and .ui-dialog-content\n
\t\t// divs will both have width and height set, so we need to reset them\n
\t\tvar nonContentHeight, minContentHeight, maxContentHeight,\n
\t\t\toptions = this.options;\n
\n
\t\t// Reset content sizing\n
\t\tthis.element.show().css({\n
\t\t\twidth: "auto",\n
\t\t\tminHeight: 0,\n
\t\t\tmaxHeight: "none",\n
\t\t\theight: 0\n
\t\t});\n
\n
\t\tif ( options.minWidth > options.width ) {\n
\t\t\toptions.width = options.minWidth;\n
\t\t}\n
\n
\t\t// reset wrapper sizing\n
\t\t// determine the height of all the non-content elements\n
\t\tnonContentHeight = this.uiDialog.css({\n
\t\t\t\theight: "auto",\n
\t\t\t\twidth: options.width\n
\t\t\t})\n
\t\t\t.outerHeight();\n
\t\tminContentHeight = Math.max( 0, options.minHeight - nonContentHeight );\n
\t\tmaxContentHeight = typeof options.maxHeight === "number" ?\n
\t\t\tMath.max( 0, options.maxHeight - nonContentHeight ) :\n
\t\t\t"none";\n
\n
\t\tif ( options.height === "auto" ) {\n
\t\t\tthis.element.css({\n
\t\t\t\tminHeight: minContentHeight,\n
\t\t\t\tmaxHeight: maxContentHeight,\n
\t\t\t\theight: "auto"\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis.element.height( Math.max( 0, options.height - nonContentHeight ) );\n
\t\t}\n
\n
\t\tif (this.uiDialog.is(":data(ui-resizable)") ) {\n
\t\t\tthis.uiDialog.resizable( "option", "minHeight", this._minHeight() );\n
\t\t}\n
\t},\n
\n
\t_blockFrames: function() {\n
\t\tthis.iframeBlocks = this.document.find( "iframe" ).map(function() {\n
\t\t\tvar iframe = $( this );\n
\n
\t\t\treturn $( "<div>" )\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: "absolute",\n
\t\t\t\t\twidth: iframe.outerWidth(),\n
\t\t\t\t\theight: iframe.outerHeight()\n
\t\t\t\t})\n
\t\t\t\t.appendTo( iframe.parent() )\n
\t\t\t\t.offset( iframe.offset() )[0];\n
\t\t});\n
\t},\n
\n
\t_unblockFrames: function() {\n
\t\tif ( this.iframeBlocks ) {\n
\t\t\tthis.iframeBlocks.remove();\n
\t\t\tdelete this.iframeBlocks;\n
\t\t}\n
\t},\n
\n
\t_allowInteraction: function( event ) {\n
\t\tif ( $( event.target ).closest(".ui-dialog").length ) {\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\t// TODO: Remove hack when datepicker implements\n
\t\t// the .ui-front logic (#8989)\n
\t\treturn !!$( event.target ).closest(".ui-datepicker").length;\n
\t},\n
\n
\t_createOverlay: function() {\n
\t\tif ( !this.options.modal ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar that = this,\n
\t\t\twidgetFullName = this.widgetFullName;\n
\t\tif ( !$.ui.dialog.overlayInstances ) {\n
\t\t\t// Prevent use of anchors and inputs.\n
\t\t\t// We use a delay in case the overlay is created from an\n
\t\t\t// event that we\'re going to be cancelling. (#2804)\n
\t\t\tthis._delay(function() {\n
\t\t\t\t// Handle .dialog().dialog("close") (#4065)\n
\t\t\t\tif ( $.ui.dialog.overlayInstances ) {\n
\t\t\t\t\tthis.document.bind( "focusin.dialog", function( event ) {\n
\t\t\t\t\t\tif ( !that._allowInteraction( event ) ) {\n
\t\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\t\t$(".ui-dialog:visible:last .ui-dialog-content")\n
\t\t\t\t\t\t\t\t.data( widgetFullName )._focusTabbable();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis.overlay = $("<div>")\n
\t\t\t.addClass("ui-widget-overlay ui-front")\n
\t\t\t.appendTo( this._appendTo() );\n
\t\tthis._on( this.overlay, {\n
\t\t\tmousedown: "_keepFocus"\n
\t\t});\n
\t\t$.ui.dialog.overlayInstances++;\n
\t},\n
\n
\t_destroyOverlay: function() {\n
\t\tif ( !this.options.modal ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( this.overlay ) {\n
\t\t\t$.ui.dialog.overlayInstances--;\n
\n
\t\t\tif ( !$.ui.dialog.overlayInstances ) {\n
\t\t\t\tthis.document.unbind( "focusin.dialog" );\n
\t\t\t}\n
\t\t\tthis.overlay.remove();\n
\t\t\tthis.overlay = null;\n
\t\t}\n
\t}\n
});\n
\n
$.ui.dialog.overlayInstances = 0;\n
\n
// DEPRECATED\n
if ( $.uiBackCompat !== false ) {\n
\t// position option with array notation\n
\t// just override with old implementation\n
\t$.widget( "ui.dialog", $.ui.dialog, {\n
\t\t_position: function() {\n
\t\t\tvar position = this.options.position,\n
\t\t\t\tmyAt = [],\n
\t\t\t\toffset = [ 0, 0 ],\n
\t\t\t\tisVisible;\n
\n
\t\t\tif ( position ) {\n
\t\t\t\tif ( typeof position === "string" || (typeof position === "object" && "0" in position ) ) {\n
\t\t\t\t\tmyAt = position.split ? position.split(" ") : [ position[0], position[1] ];\n
\t\t\t\t\tif ( myAt.length === 1 ) {\n
\t\t\t\t\t\tmyAt[1] = myAt[0];\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t$.each( [ "left", "top" ], function( i, offsetPosition ) {\n
\t\t\t\t\t\tif ( +myAt[ i ] === myAt[ i ] ) {\n
\t\t\t\t\t\t\toffset[ i ] = myAt[ i ];\n
\t\t\t\t\t\t\tmyAt[ i ] = offsetPosition;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\n
\t\t\t\t\tposition = {\n
\t\t\t\t\t\tmy: myAt[0] + (offset[0] < 0 ? offset[0] : "+" + offset[0]) + " " +\n
\t\t\t\t\t\t\tmyAt[1] + (offset[1] < 0 ? offset[1] : "+" + offset[1]),\n
\t\t\t\t\t\tat: myAt.join(" ")\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\n
\t\t\t\tposition = $.extend( {}, $.ui.dialog.prototype.options.position, position );\n
\t\t\t} else {\n
\t\t\t\tposition = $.ui.dialog.prototype.options.position;\n
\t\t\t}\n
\n
\t\t\t// need to show the dialog to get the actual offset in the position plugin\n
\t\t\tisVisible = this.uiDialog.is(":visible");\n
\t\t\tif ( !isVisible ) {\n
\t\t\t\tthis.uiDialog.show();\n
\t\t\t}\n
\t\t\tthis.uiDialog.position( position );\n
\t\t\tif ( !isVisible ) {\n
\t\t\t\tthis.uiDialog.hide();\n
\t\t\t}\n
\t\t}\n
\t});\n
}\n
\n
}( jQuery ) );\n
(function( $, undefined ) {\n
\n
$.widget( "ui.menu", {\n
\tversion: "1.10.4",\n
\tdefaultElement: "<ul>",\n
\tdelay: 300,\n
\toptions: {\n
\t\ticons: {\n
\t\t\tsubmenu: "ui-icon-carat-1-e"\n
\t\t},\n
\t\tmenus: "ul",\n
\t\tposition: {\n
\t\t\tmy: "left top",\n
\t\t\tat: "right top"\n
\t\t},\n
\t\trole: "menu",\n
\n
\t\t// callbacks\n
\t\tblur: null,\n
\t\tfocus: null,\n
\t\tselect: null\n
\t},\n
\n
\t_create: function() {\n
\t\tthis.activeMenu = this.element;\n
\t\t// flag used to prevent firing of the click handler\n
\t\t// as the event bubbles up through nested menus\n
\t\tthis.mouseHandled = false;\n
\t\tthis.element\n
\t\t\t.uniqueId()\n
\t\t\t.addClass( "ui-menu ui-widget ui-widget-content ui-corner-all" )\n
\t\t\t.toggleClass( "ui-menu-icons", !!this.element.find( ".ui-icon" ).length )\n
\t\t\t.attr({\n
\t\t\t\trole: this.options.role,\n
\t\t\t\ttabIndex: 0\n
\t\t\t})\n
\t\t\t// need to catch all clicks on disabled menu\n
\t\t\t// not possible through _on\n
\t\t\t.bind( "click" + this.eventNamespace, $.proxy(function( event ) {\n
\t\t\t\tif ( this.options.disabled ) {\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t}\n
\t\t\t}, this ));\n
\n
\t\tif ( this.options.disabled ) {\n
\t\t\tthis.element\n
\t\t\t\t.addClass( "ui-state-disabled" )\n
\t\t\t\t.attr( "aria-disabled", "true" );\n
\t\t}\n
\n
\t\tthis._on({\n
\t\t\t// Prevent focus from sticking to links inside menu after clicking\n
\t\t\t// them (focus should always stay on UL during navigation).\n
\t\t\t"mousedown .ui-menu-item > a": function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t},\n
\t\t\t"click .ui-state-disabled > a": function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t},\n
\t\t\t"click .ui-menu-item:has(a)": function( event ) {\n
\t\t\t\tvar target = $( event.target ).closest( ".ui-menu-item" );\n
\t\t\t\tif ( !this.mouseHandled && target.not( ".ui-state-disabled" ).length ) {\n
\t\t\t\t\tthis.select( event );\n
\n
\t\t\t\t\t// Only set the mouseHandled flag if the event will bubble, see #9469.\n
\t\t\t\t\tif ( !event.isPropagationStopped() ) {\n
\t\t\t\t\t\tthis.mouseHandled = true;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Open submenu on click\n
\t\t\t\t\tif ( target.has( ".ui-menu" ).length ) {\n
\t\t\t\t\t\tthis.expand( event );\n
\t\t\t\t\t} else if ( !this.element.is( ":focus" ) && $( this.document[ 0 ].activeElement ).closest( ".ui-menu" ).length ) {\n
\n
\t\t\t\t\t\t// Redirect focus to the menu\n
\t\t\t\t\t\tthis.element.trigger( "focus", [ true ] );\n
\n
\t\t\t\t\t\t// If the active item is on the top level, let it stay active.\n
\t\t\t\t\t\t// Otherwise, blur the active item since it is no longer visible.\n
\t\t\t\t\t\tif ( this.active && this.active.parents( ".ui-menu" ).length === 1 ) {\n
\t\t\t\t\t\t\tclearTimeout( this.timer );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\t"mouseenter .ui-menu-item": function( event ) {\n
\t\t\t\tvar target = $( event.currentTarget );\n
\t\t\t\t// Remove ui-state-active class from siblings of the newly focused menu item\n
\t\t\t\t// to avoid a jump caused by adjacent elements both having a class with a border\n
\t\t\t\ttarget.siblings().children( ".ui-state-active" ).removeClass( "ui-state-active" );\n
\t\t\t\tthis.focus( event, target );\n
\t\t\t},\n
\t\t\tmouseleave: "collapseAll",\n
\t\t\t"mouseleave .ui-menu": "collapseAll",\n
\t\t\tfocus: function( event, keepActiveItem ) {\n
\t\t\t\t// If there\'s already an active item, keep it active\n
\t\t\t\t// If not, activate the first item\n
\t\t\t\tvar item = this.active || this.element.children( ".ui-menu-item" ).eq( 0 );\n
\n
\t\t\t\tif ( !keepActiveItem ) {\n
\t\t\t\t\tthis.focus( event, item );\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tblur: function( event ) {\n
\t\t\t\tthis._delay(function() {\n
\t\t\t\t\tif ( !$.contains( this.element[0], this.document[0].activeElement ) ) {\n
\t\t\t\t\t\tthis.collapseAll( event );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t},\n
\t\t\tkeydown: "_keydown"\n
\t\t});\n
\n
\t\tthis.refresh();\n
\n
\t\t// Clicks outside of a menu collapse any open menus\n
\t\tthis._on( this.document, {\n
\t\t\tclick: function( event ) {\n
\t\t\t\tif ( !$( event.target ).closest( ".ui-menu" ).length ) {\n
\t\t\t\t\tthis.collapseAll( event );\n
\t\t\t\t}\n
\n
\t\t\t\t// Reset the mouseHandled flag\n
\t\t\t\tthis.mouseHandled = false;\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_destroy: function() {\n
\t\t// Destroy (sub)menus\n
\t\tthis.element\n
\t\t\t.removeAttr( "aria-activedescendant" )\n
\t\t\t.find( ".ui-menu" ).addBack()\n
\t\t\t\t.removeClass( "ui-menu ui-widget ui-widget-content ui-corner-all ui-menu-icons" )\n
\t\t\t\t.removeAttr( "role" )\n
\t\t\t\t.removeAttr( "tabIndex" )\n
\t\t\t\t.removeAttr( "aria-labelledby" )\n
\t\t\t\t.removeAttr( "aria-expanded" )\n
\t\t\t\t.removeAttr( "aria-hidden" )\n
\t\t\t\t.removeAttr( "aria-disabled" )\n
\t\t\t\t.removeUniqueId()\n
\t\t\t\t.show();\n
\n
\t\t// Destroy menu items\n
\t\tthis.element.find( ".ui-menu-item" )\n
\t\t\t.removeClass( "ui-menu-item" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-disabled" )\n
\t\t\t.children( "a" )\n
\t\t\t\t.removeUniqueId()\n
\t\t\t\t.removeClass( "ui-corner-all ui-state-hover" )\n
\t\t\t\t.removeAttr( "tabIndex" )\n
\t\t\t\t.removeAttr( "role" )\n
\t\t\t\t.removeAttr( "aria-haspopup" )\n
\t\t\t\t.children().each( function() {\n
\t\t\t\t\tvar elem = $( this );\n
\t\t\t\t\tif ( elem.data( "ui-menu-submenu-carat" ) ) {\n
\t\t\t\t\t\telem.remove();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\n
\t\t// Destroy menu dividers\n
\t\tthis.element.find( ".ui-menu-divider" ).removeClass( "ui-menu-divider ui-widget-content" );\n
\t},\n
\n
\t_keydown: function( event ) {\n
\t\tvar match, prev, character, skip, regex,\n
\t\t\tpreventDefault = true;\n
\n
\t\tfunction escape( value ) {\n
\t\t\treturn value.replace( /[\\-\\[\\]{}()*+?.,\\\\\\^$|#\\s]/g, "\\\\$&" );\n
\t\t}\n
\n
\t\tswitch ( event.keyCode ) {\n
\t\tcase $.ui.keyCode.PAGE_UP:\n
\t\t\tthis.previousPage( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.PAGE_DOWN:\n
\t\t\tthis.nextPage( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.HOME:\n
\t\t\tthis._move( "first", "first", event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.END:\n
\t\t\tthis._move( "last", "last", event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.UP:\n
\t\t\tthis.previous( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.DOWN:\n
\t\t\tthis.next( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.LEFT:\n
\t\t\tthis.collapse( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\tif ( this.active && !this.active.is( ".ui-state-disabled" ) ) {\n
\t\t\t\tthis.expand( event );\n
\t\t\t}\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.ENTER:\n
\t\tcase $.ui.keyCode.SPACE:\n
\t\t\tthis._activate( event );\n
\t\t\tbreak;\n
\t\tcase $.ui.keyCode.ESCAPE:\n
\t\t\tthis.collapse( event );\n
\t\t\tbreak;\n
\t\tdefault:\n
\t\t\tpreventDefault = false;\n
\t\t\tprev = this.previousFilter || "";\n
\t\t\tcharacter = String.fromCharCode( event.keyCode );\n
\t\t\tskip = false;\n
\n
\t\t\tclearTimeout( this.filterTimer );\n
\n
\t\t\tif ( character === prev ) {\n
\t\t\t\tskip = true;\n
\t\t\t} else {\n
\t\t\t\tcharacter = prev + character;\n
\t\t\t}\n
\n
\t\t\tregex = new RegExp( "^" + escape( character ), "i" );\n
\t\t\tmatch = this.activeMenu.children( ".ui-menu-item" ).filter(function() {\n
\t\t\t\treturn regex.test( $( this ).children( "a" ).text() );\n
\t\t\t});\n
\t\t\tmatch = skip && match.index( this.active.next() ) !== -1 ?\n
\t\t\t\tthis.active.nextAll( ".ui-menu-item" ) :\n
\t\t\t\tmatch;\n
\n
\t\t\t// If no matches on the current filter, reset to the last character pressed\n
\t\t\t// to move down the menu to the first item that starts with that character\n
\t\t\tif ( !match.length ) {\n
\t\t\t\tcharacter = String.fromCharCode( event.keyCode );\n
\t\t\t\tregex = new RegExp( "^" + escape( character ), "i" );\n
\t\t\t\tmatch = this.activeMenu.children( ".ui-menu-item" ).filter(function() {\n
\t\t\t\t\treturn regex.test( $( this ).children( "a" ).text() );\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif ( match.length ) {\n
\t\t\t\tthis.focus( event, match );\n
\t\t\t\tif ( match.length > 1 ) {\n
\t\t\t\t\tthis.previousFilter = character;\n
\t\t\t\t\tthis.filterTimer = this._delay(function() {\n
\t\t\t\t\t\tdelete this.previousFilter;\n
\t\t\t\t\t}, 1000 );\n
\t\t\t\t} else {\n
\t\t\t\t\tdelete this.previousFilter;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tdelete this.previousFilter;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( preventDefault ) {\n
\t\t\tevent.preventDefault();\n
\t\t}\n
\t},\n
\n
\t_activate: function( event ) {\n
\t\tif ( !this.active.is( ".ui-state-disabled" ) ) {\n
\t\t\tif ( this.active.children( "a[aria-haspopup=\'true\']" ).length ) {\n
\t\t\t\tthis.expand( event );\n
\t\t\t} else {\n
\t\t\t\tthis.select( event );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar menus,\n
\t\t\ticon = this.options.icons.submenu,\n
\t\t\tsubmenus = this.element.find( this.options.menus );\n
\n
\t\tthis.element.toggleClass( "ui-menu-icons", !!this.element.find( ".ui-icon" ).length );\n
\n
\t\t// Initialize nested menus\n
\t\tsubmenus.filter( ":not(.ui-menu)" )\n
\t\t\t.addClass( "ui-menu ui-widget ui-widget-content ui-corner-all" )\n
\t\t\t.hide()\n
\t\t\t.attr({\n
\t\t\t\trole: this.options.role,\n
\t\t\t\t"aria-hidden": "true",\n
\t\t\t\t"aria-expanded": "false"\n
\t\t\t})\n
\t\t\t.each(function() {\n
\t\t\t\tvar menu = $( this ),\n
\t\t\t\t\titem = menu.prev( "a" ),\n
\t\t\t\t\tsubmenuCarat = $( "<span>" )\n
\t\t\t\t\t\t.addClass( "ui-menu-icon ui-icon " + icon )\n
\t\t\t\t\t\t.data( "ui-menu-submenu-carat", true );\n
\n
\t\t\t\titem\n
\t\t\t\t\t.attr( "aria-haspopup", "true" )\n
\t\t\t\t\t.prepend( submenuCarat );\n
\t\t\t\tmenu.attr( "aria-labelledby", item.attr( "id" ) );\n
\t\t\t});\n
\n
\t\tmenus = submenus.add( this.element );\n
\n
\t\t// Don\'t refresh list items that are already adapted\n
\t\tmenus.children( ":not(.ui-menu-item):has(a)" )\n
\t\t\t.addClass( "ui-menu-item" )\n
\t\t\t.attr( "role", "presentation" )\n
\t\t\t.children( "a" )\n
\t\t\t\t.uniqueId()\n
\t\t\t\t.addClass( "ui-corner-all" )\n
\t\t\t\t.attr({\n
\t\t\t\t\ttabIndex: -1,\n
\t\t\t\t\trole: this._itemRole()\n
\t\t\t\t});\n
\n
\t\t// Initialize unlinked menu-items containing spaces and/or dashes only as dividers\n
\t\tmenus.children( ":not(.ui-menu-item)" ).each(function() {\n
\t\t\tvar item = $( this );\n
\t\t\t// hyphen, em dash, en dash\n
\t\t\tif ( !/[^\\-\\u2014\\u2013\\s]/.test( item.text() ) ) {\n
\t\t\t\titem.addClass( "ui-widget-content ui-menu-divider" );\n
\t\t\t}\n
\t\t});\n
\n
\t\t// Add aria-disabled attribute to any disabled menu item\n
\t\tmenus.children( ".ui-state-disabled" ).attr( "aria-disabled", "true" );\n
\n
\t\t// If the active item has been removed, blur the menu\n
\t\tif ( this.active && !$.contains( this.element[ 0 ], this.active[ 0 ] ) ) {\n
\t\t\tthis.blur();\n
\t\t}\n
\t},\n
\n
\t_itemRole: function() {\n
\t\treturn {\n
\t\t\tmenu: "menuitem",\n
\t\t\tlistbox: "option"\n
\t\t}[ this.options.role ];\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "icons" ) {\n
\t\t\tthis.element.find( ".ui-menu-icon" )\n
\t\t\t\t.removeClass( this.options.icons.submenu )\n
\t\t\t\t.addClass( value.submenu );\n
\t\t}\n
\t\tthis._super( key, value );\n
\t},\n
\n
\tfocus: function( event, item ) {\n
\t\tvar nested, focused;\n
\t\tthis.blur( event, event && event.type === "focus" );\n
\n
\t\tthis._scrollIntoView( item );\n
\n
\t\tthis.active = item.first();\n
\t\tfocused = this.active.children( "a" ).addClass( "ui-state-focus" );\n
\t\t// Only update aria-activedescendant if there\'s a role\n
\t\t// otherwise we assume focus is managed elsewhere\n
\t\tif ( this.options.role ) {\n
\t\t\tthis.element.attr( "aria-activedescendant", focused.attr( "id" ) );\n
\t\t}\n
\n
\t\t// Highlight active parent menu item, if any\n
\t\tthis.active\n
\t\t\t.parent()\n
\t\t\t.closest( ".ui-menu-item" )\n
\t\t\t.children( "a:first" )\n
\t\t\t.addClass( "ui-state-active" );\n
\n
\t\tif ( event && event.type === "keydown" ) {\n
\t\t\tthis._close();\n
\t\t} else {\n
\t\t\tthis.timer = this._delay(function() {\n
\t\t\t\tthis._close();\n
\t\t\t}, this.delay );\n
\t\t}\n
\n
\t\tnested = item.children( ".ui-menu" );\n
\t\tif ( nested.length && event && ( /^mouse/.test( event.type ) ) ) {\n
\t\t\tthis._startOpening(nested);\n
\t\t}\n
\t\tthis.activeMenu = item.parent();\n
\n
\t\tthis._trigger( "focus", event, { item: item } );\n
\t},\n
\n
\t_scrollIntoView: function( item ) {\n
\t\tvar borderTop, paddingTop, offset, scroll, elementHeight, itemHeight;\n
\t\tif ( this._hasScroll() ) {\n
\t\t\tborderTop = parseFloat( $.css( this.activeMenu[0], "borderTopWidth" ) ) || 0;\n
\t\t\tpaddingTop = parseFloat( $.css( this.activeMenu[0], "paddingTop" ) ) || 0;\n
\t\t\toffset = item.offset().top - this.activeMenu.offset().top - borderTop - paddingTop;\n
\t\t\tscroll = this.activeMenu.scrollTop();\n
\t\t\telementHeight = this.activeMenu.height();\n
\t\t\titemHeight = item.height();\n
\n
\t\t\tif ( offset < 0 ) {\n
\t\t\t\tthis.activeMenu.scrollTop( scroll + offset );\n
\t\t\t} else if ( offset + itemHeight > elementHeight ) {\n
\t\t\t\tthis.activeMenu.scrollTop( scroll + offset - elementHeight + itemHeight );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tblur: function( event, fromFocus ) {\n
\t\tif ( !fromFocus ) {\n
\t\t\tclearTimeout( this.timer );\n
\t\t}\n
\n
\t\tif ( !this.active ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.active.children( "a" ).removeClass( "ui-state-focus" );\n
\t\tthis.active = null;\n
\n
\t\tthis._trigger( "blur", event, { item: this.active } );\n
\t},\n
\n
\t_startOpening: function( submenu ) {\n
\t\tclearTimeout( this.timer );\n
\n
\t\t// Don\'t open if already open fixes a Firefox bug that caused a .5 pixel\n
\t\t// shift in the submenu position when mousing over the carat icon\n
\t\tif ( submenu.attr( "aria-hidden" ) !== "true" ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.timer = this._delay(function() {\n
\t\t\tthis._close();\n
\t\t\tthis._open( submenu );\n
\t\t}, this.delay );\n
\t},\n
\n
\t_open: function( submenu ) {\n
\t\tvar position = $.extend({\n
\t\t\tof: this.active\n
\t\t}, this.options.position );\n
\n
\t\tclearTimeout( this.timer );\n
\t\tthis.element.find( ".ui-menu" ).not( submenu.parents( ".ui-menu" ) )\n
\t\t\t.hide()\n
\t\t\t.attr( "aria-hidden", "true" );\n
\n
\t\tsubmenu\n
\t\t\t.show()\n
\t\t\t.removeAttr( "aria-hidden" )\n
\t\t\t.attr( "aria-expanded", "true" )\n
\t\t\t.position( position );\n
\t},\n
\n
\tcollapseAll: function( event, all ) {\n
\t\tclearTimeout( this.timer );\n
\t\tthis.timer = this._delay(function() {\n
\t\t\t// If we were passed an event, look for the submenu that contains the event\n
\t\t\tvar currentMenu = all ? this.element :\n
\t\t\t\t$( event && event.target ).closest( this.element.find( ".ui-menu" ) );\n
\n
\t\t\t// If we found no valid submenu ancestor, use the main menu to close all sub menus anyway\n
\t\t\tif ( !currentMenu.length ) {\n
\t\t\t\tcurrentMenu = this.element;\n
\t\t\t}\n
\n
\t\t\tthis._close( currentMenu );\n
\n
\t\t\tthis.blur( event );\n
\t\t\tthis.activeMenu = currentMenu;\n
\t\t}, this.delay );\n
\t},\n
\n
\t// With no arguments, closes the currently active menu - if nothing is active\n
\t// it closes all menus.  If passed an argument, it will search for menus BELOW\n
\t_close: function( startMenu ) {\n
\t\tif ( !startMenu ) {\n
\t\t\tstartMenu = this.active ? this.active.parent() : this.element;\n
\t\t}\n
\n
\t\tstartMenu\n
\t\t\t.find( ".ui-menu" )\n
\t\t\t\t.hide()\n
\t\t\t\t.attr( "aria-hidden", "true" )\n
\t\t\t\t.attr( "aria-expanded", "false" )\n
\t\t\t.end()\n
\t\t\t.find( "a.ui-state-active" )\n
\t\t\t\t.removeClass( "ui-state-active" );\n
\t},\n
\n
\tcollapse: function( event ) {\n
\t\tvar newItem = this.active &&\n
\t\t\tthis.active.parent().closest( ".ui-menu-item", this.element );\n
\t\tif ( newItem && newItem.length ) {\n
\t\t\tthis._close();\n
\t\t\tthis.focus( event, newItem );\n
\t\t}\n
\t},\n
\n
\texpand: function( event ) {\n
\t\tvar newItem = this.active &&\n
\t\t\tthis.active\n
\t\t\t\t.children( ".ui-menu " )\n
\t\t\t\t.children( ".ui-menu-item" )\n
\t\t\t\t.first();\n
\n
\t\tif ( newItem && newItem.length ) {\n
\t\t\tthis._open( newItem.parent() );\n
\n
\t\t\t// Delay so Firefox will not hide activedescendant change in expanding submenu from AT\n
\t\t\tthis._delay(function() {\n
\t\t\t\tthis.focus( event, newItem );\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\tnext: function( event ) {\n
\t\tthis._move( "next", "first", event );\n
\t},\n
\n
\tprevious: function( event ) {\n
\t\tthis._move( "prev", "last", event );\n
\t},\n
\n
\tisFirstItem: function() {\n
\t\treturn this.active && !this.active.prevAll( ".ui-menu-item" ).length;\n
\t},\n
\n
\tisLastItem: function() {\n
\t\treturn this.active && !this.active.nextAll( ".ui-menu-item" ).length;\n
\t},\n
\n
\t_move: function( direction, filter, event ) {\n
\t\tvar next;\n
\t\tif ( this.active ) {\n
\t\t\tif ( direction === "first" || direction === "last" ) {\n
\t\t\t\tnext = this.active\n
\t\t\t\t\t[ direction === "first" ? "prevAll" : "nextAll" ]( ".ui-menu-item" )\n
\t\t\t\t\t.eq( -1 );\n
\t\t\t} else {\n
\t\t\t\tnext = this.active\n
\t\t\t\t\t[ direction + "All" ]( ".ui-menu-item" )\n
\t\t\t\t\t.eq( 0 );\n
\t\t\t}\n
\t\t}\n
\t\tif ( !next || !next.length || !this.active ) {\n
\t\t\tnext = this.activeMenu.children( ".ui-menu-item" )[ filter ]();\n
\t\t}\n
\n
\t\tthis.focus( event, next );\n
\t},\n
\n
\tnextPage: function( event ) {\n
\t\tvar item, base, height;\n
\n
\t\tif ( !this.active ) {\n
\t\t\tthis.next( event );\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this.isLastItem() ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this._hasScroll() ) {\n
\t\t\tbase = this.active.offset().top;\n
\t\t\theight = this.element.height();\n
\t\t\tthis.active.nextAll( ".ui-menu-item" ).each(function() {\n
\t\t\t\titem = $( this );\n
\t\t\t\treturn item.offset().top - base - height < 0;\n
\t\t\t});\n
\n
\t\t\tthis.focus( event, item );\n
\t\t} else {\n
\t\t\tthis.focus( event, this.activeMenu.children( ".ui-menu-item" )\n
\t\t\t\t[ !this.active ? "first" : "last" ]() );\n
\t\t}\n
\t},\n
\n
\tpreviousPage: function( event ) {\n
\t\tvar item, base, height;\n
\t\tif ( !this.active ) {\n
\t\t\tthis.next( event );\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this.isFirstItem() ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this._hasScroll() ) {\n
\t\t\tbase = this.active.offset().top;\n
\t\t\theight = this.element.height();\n
\t\t\tthis.active.prevAll( ".ui-menu-item" ).each(function() {\n
\t\t\t\titem = $( this );\n
\t\t\t\treturn item.offset().top - base + height > 0;\n
\t\t\t});\n
\n
\t\t\tthis.focus( event, item );\n
\t\t} else {\n
\t\t\tthis.focus( event, this.activeMenu.children( ".ui-menu-item" ).first() );\n
\t\t}\n
\t},\n
\n
\t_hasScroll: function() {\n
\t\treturn this.element.outerHeight() < this.element.prop( "scrollHeight" );\n
\t},\n
\n
\tselect: function( event ) {\n
\t\t// TODO: It should never be possible to not have an active item at this\n
\t\t// point, but the tests don\'t trigger mouseenter before click.\n
\t\tthis.active = this.active || $( event.target ).closest( ".ui-menu-item" );\n
\t\tvar ui = { item: this.active };\n
\t\tif ( !this.active.has( ".ui-menu" ).length ) {\n
\t\t\tthis.collapseAll( event, true );\n
\t\t}\n
\t\tthis._trigger( "select", event, ui );\n
\t}\n
});\n
\n
}( jQuery ));\n
(function( $, undefined ) {\n
\n
$.widget( "ui.progressbar", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tmax: 100,\n
\t\tvalue: 0,\n
\n
\t\tchange: null,\n
\t\tcomplete: null\n
\t},\n
\n
\tmin: 0,\n
\n
\t_create: function() {\n
\t\t// Constrain initial value\n
\t\tthis.oldValue = this.options.value = this._constrainedValue();\n
\n
\t\tthis.element\n
\t\t\t.addClass( "ui-progressbar ui-widget ui-widget-content ui-corner-all" )\n
\t\t\t.attr({\n
\t\t\t\t// Only set static values, aria-valuenow and aria-valuemax are\n
\t\t\t\t// set inside _refreshValue()\n
\t\t\t\trole: "progressbar",\n
\t\t\t\t"aria-valuemin": this.min\n
\t\t\t});\n
\n
\t\tthis.valueDiv = $( "<div class=\'ui-progressbar-value ui-widget-header ui-corner-left\'></div>" )\n
\t\t\t.appendTo( this.element );\n
\n
\t\tthis._refreshValue();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-progressbar ui-widget ui-widget-content ui-corner-all" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-valuemin" )\n
\t\t\t.removeAttr( "aria-valuemax" )\n
\t\t\t.removeAttr( "aria-valuenow" );\n
\n
\t\tthis.valueDiv.remove();\n
\t},\n
\n
\tvalue: function( newValue ) {\n
\t\tif ( newValue === undefined ) {\n
\t\t\treturn this.options.value;\n
\t\t}\n
\n
\t\tthis.options.value = this._constrainedValue( newValue );\n
\t\tthis._refreshValue();\n
\t},\n
\n
\t_constrainedValue: function( newValue ) {\n
\t\tif ( newValue === undefined ) {\n
\t\t\tnewValue = this.options.value;\n
\t\t}\n
\n
\t\tthis.indeterminate = newValue === false;\n
\n
\t\t// sanitize value\n
\t\tif ( typeof newValue !== "number" ) {\n
\t\t\tnewValue = 0;\n
\t\t}\n
\n
\t\treturn this.indeterminate ? false :\n
\t\t\tMath.min( this.options.max, Math.max( this.min, newValue ) );\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\t// Ensure "value" option is set after other values (like max)\n
\t\tvar value = options.value;\n
\t\tdelete options.value;\n
\n
\t\tthis._super( options );\n
\n
\t\tthis.options.value = this._constrainedValue( value );\n
\t\tthis._refreshValue();\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "max" ) {\n
\t\t\t// Don\'t allow a max less than min\n
\t\t\tvalue = Math.max( this.min, value );\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\t},\n
\n
\t_percentage: function() {\n
\t\treturn this.indeterminate ? 100 : 100 * ( this.options.value - this.min ) / ( this.options.max - this.min );\n
\t},\n
\n
\t_refreshValue: function() {\n
\t\tvar value = this.options.value,\n
\t\t\tpercentage = this._percentage();\n
\n
\t\tthis.valueDiv\n
\t\t\t.toggle( this.indeterminate || value > this.min )\n
\t\t\t.toggleClass( "ui-corner-right", value === this.options.max )\n
\t\t\t.width( percentage.toFixed(0) + "%" );\n
\n
\t\tthis.element.toggleClass( "ui-progressbar-indeterminate", this.indeterminate );\n
\n
\t\tif ( this.indeterminate ) {\n
\t\t\tthis.element.removeAttr( "aria-valuenow" );\n
\t\t\tif ( !this.overlayDiv ) {\n
\t\t\t\tthis.overlayDiv = $( "<div class=\'ui-progressbar-overlay\'></div>" ).appendTo( this.valueDiv );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tthis.element.attr({\n
\t\t\t\t"aria-valuemax": this.options.max,\n
\t\t\t\t"aria-valuenow": value\n
\t\t\t});\n
\t\t\tif ( this.overlayDiv ) {\n
\t\t\t\tthis.overlayDiv.remove();\n
\t\t\t\tthis.overlayDiv = null;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( this.oldValue !== value ) {\n
\t\t\tthis.oldValue = value;\n
\t\t\tthis._trigger( "change" );\n
\t\t}\n
\t\tif ( value === this.options.max ) {\n
\t\t\tthis._trigger( "complete" );\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
(function( $, undefined ) {\n
\n
// number of pages in a slider\n
// (how many times can you page up/down to go through the whole range)\n
var numPages = 5;\n
\n
$.widget( "ui.slider", $.ui.mouse, {\n
\tversion: "1.10.4",\n
\twidgetEventPrefix: "slide",\n
\n
\toptions: {\n
\t\tanimate: false,\n
\t\tdistance: 0,\n
\t\tmax: 100,\n
\t\tmin: 0,\n
\t\torientation: "horizontal",\n
\t\trange: false,\n
\t\tstep: 1,\n
\t\tvalue: 0,\n
\t\tvalues: null,\n
\n
\t\t// callbacks\n
\t\tchange: null,\n
\t\tslide: null,\n
\t\tstart: null,\n
\t\tstop: null\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._keySliding = false;\n
\t\tthis._mouseSliding = false;\n
\t\tthis._animateOff = true;\n
\t\tthis._handleIndex = null;\n
\t\tthis._detectOrientation();\n
\t\tthis._mouseInit();\n
\n
\t\tthis.element\n
\t\t\t.addClass( "ui-slider" +\n
\t\t\t\t" ui-slider-" + this.orientation +\n
\t\t\t\t" ui-widget" +\n
\t\t\t\t" ui-widget-content" +\n
\t\t\t\t" ui-corner-all");\n
\n
\t\tthis._refresh();\n
\t\tthis._setOption( "disabled", this.options.disabled );\n
\n
\t\tthis._animateOff = false;\n
\t},\n
\n
\t_refresh: function() {\n
\t\tthis._createRange();\n
\t\tthis._createHandles();\n
\t\tthis._setupEvents();\n
\t\tthis._refreshValue();\n
\t},\n
\n
\t_createHandles: function() {\n
\t\tvar i, handleCount,\n
\t\t\toptions = this.options,\n
\t\t\texistingHandles = this.element.find( ".ui-slider-handle" ).addClass( "ui-state-default ui-corner-all" ),\n
\t\t\thandle = "<a class=\'ui-slider-handle ui-state-default ui-corner-all\' href=\'#\'></a>",\n
\t\t\thandles = [];\n
\n
\t\thandleCount = ( options.values && options.values.length ) || 1;\n
\n
\t\tif ( existingHandles.length > handleCount ) {\n
\t\t\texistingHandles.slice( handleCount ).remove();\n
\t\t\texistingHandles = existingHandles.slice( 0, handleCount );\n
\t\t}\n
\n
\t\tfor ( i = existingHandles.length; i < handleCount; i++ ) {\n
\t\t\thandles.push( handle );\n
\t\t}\n
\n
\t\tthis.handles = existingHandles.add( $( handles.join( "" ) ).appendTo( this.element ) );\n
\n
\t\tthis.handle = this.handles.eq( 0 );\n
\n
\t\tthis.handles.each(function( i ) {\n
\t\t\t$( this ).data( "ui-slider-handle-index", i );\n
\t\t});\n
\t},\n
\n
\t_createRange: function() {\n
\t\tvar options = this.options,\n
\t\t\tclasses = "";\n
\n
\t\tif ( options.range ) {\n
\t\t\tif ( options.range === true ) {\n
\t\t\t\tif ( !options.values ) {\n
\t\t\t\t\toptions.values = [ this._valueMin(), this._valueMin() ];\n
\t\t\t\t} else if ( options.values.length && options.values.length !== 2 ) {\n
\t\t\t\t\toptions.values = [ options.values[0], options.values[0] ];\n
\t\t\t\t} else if ( $.isArray( options.values ) ) {\n
\t\t\t\t\toptions.values = options.values.slice(0);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( !this.range || !this.range.length ) {\n
\t\t\t\tthis.range = $( "<div></div>" )\n
\t\t\t\t\t.appendTo( this.element );\n
\n
\t\t\t\tclasses = "ui-slider-range" +\n
\t\t\t\t// note: this isn\'t the most fittingly semantic framework class for this element,\n
\t\t\t\t// but worked best visually with a variety of themes\n
\t\t\t\t" ui-widget-header ui-corner-all";\n
\t\t\t} else {\n
\t\t\t\tthis.range.removeClass( "ui-slider-range-min ui-slider-range-max" )\n
\t\t\t\t\t// Handle range switching from true to min/max\n
\t\t\t\t\t.css({\n
\t\t\t\t\t\t"left": "",\n
\t\t\t\t\t\t"bottom": ""\n
\t\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tthis.range.addClass( classes +\n
\t\t\t\t( ( options.range === "min" || options.range === "max" ) ? " ui-slider-range-" + options.range : "" ) );\n
\t\t} else {\n
\t\t\tif ( this.range ) {\n
\t\t\t\tthis.range.remove();\n
\t\t\t}\n
\t\t\tthis.range = null;\n
\t\t}\n
\t},\n
\n
\t_setupEvents: function() {\n
\t\tvar elements = this.handles.add( this.range ).filter( "a" );\n
\t\tthis._off( elements );\n
\t\tthis._on( elements, this._handleEvents );\n
\t\tthis._hoverable( elements );\n
\t\tthis._focusable( elements );\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.handles.remove();\n
\t\tif ( this.range ) {\n
\t\t\tthis.range.remove();\n
\t\t}\n
\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-slider" +\n
\t\t\t\t" ui-slider-horizontal" +\n
\t\t\t\t" ui-slider-vertical" +\n
\t\t\t\t" ui-widget" +\n
\t\t\t\t" ui-widget-content" +\n
\t\t\t\t" ui-corner-all" );\n
\n
\t\tthis._mouseDestroy();\n
\t},\n
\n
\t_mouseCapture: function( event ) {\n
\t\tvar position, normValue, distance, closestHandle, index, allowed, offset, mouseOverHandle,\n
\t\t\tthat = this,\n
\t\t\to = this.options;\n
\n
\t\tif ( o.disabled ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tthis.elementSize = {\n
\t\t\twidth: this.element.outerWidth(),\n
\t\t\theight: this.element.outerHeight()\n
\t\t};\n
\t\tthis.elementOffset = this.element.offset();\n
\n
\t\tposition = { x: event.pageX, y: event.pageY };\n
\t\tnormValue = this._normValueFromMouse( position );\n
\t\tdistance = this._valueMax() - this._valueMin() + 1;\n
\t\tthis.handles.each(function( i ) {\n
\t\t\tvar thisDistance = Math.abs( normValue - that.values(i) );\n
\t\t\tif (( distance > thisDistance ) ||\n
\t\t\t\t( distance === thisDistance &&\n
\t\t\t\t\t(i === that._lastChangedValue || that.values(i) === o.min ))) {\n
\t\t\t\tdistance = thisDistance;\n
\t\t\t\tclosestHandle = $( this );\n
\t\t\t\tindex = i;\n
\t\t\t}\n
\t\t});\n
\n
\t\tallowed = this._start( event, index );\n
\t\tif ( allowed === false ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tthis._mouseSliding = true;\n
\n
\t\tthis._handleIndex = index;\n
\n
\t\tclosestHandle\n
\t\t\t.addClass( "ui-state-active" )\n
\t\t\t.focus();\n
\n
\t\toffset = closestHandle.offset();\n
\t\tmouseOverHandle = !$( event.target ).parents().addBack().is( ".ui-slider-handle" );\n
\t\tthis._clickOffset = mouseOverHandle ? { left: 0, top: 0 } : {\n
\t\t\tleft: event.pageX - offset.left - ( closestHandle.width() / 2 ),\n
\t\t\ttop: event.pageY - offset.top -\n
\t\t\t\t( closestHandle.height() / 2 ) -\n
\t\t\t\t( parseInt( closestHandle.css("borderTopWidth"), 10 ) || 0 ) -\n
\t\t\t\t( parseInt( closestHandle.css("borderBottomWidth"), 10 ) || 0) +\n
\t\t\t\t( parseInt( closestHandle.css("marginTop"), 10 ) || 0)\n
\t\t};\n
\n
\t\tif ( !this.handles.hasClass( "ui-state-hover" ) ) {\n
\t\t\tthis._slide( event, index, normValue );\n
\t\t}\n
\t\tthis._animateOff = true;\n
\t\treturn true;\n
\t},\n
\n
\t_mouseStart: function() {\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function( event ) {\n
\t\tvar position = { x: event.pageX, y: event.pageY },\n
\t\t\tnormValue = this._normValueFromMouse( position );\n
\n
\t\tthis._slide( event, this._handleIndex, normValue );\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function( event ) {\n
\t\tthis.handles.removeClass( "ui-state-active" );\n
\t\tthis._mouseSliding = false;\n
\n
\t\tthis._stop( event, this._handleIndex );\n
\t\tthis._change( event, this._handleIndex );\n
\n
\t\tthis._handleIndex = null;\n
\t\tthis._clickOffset = null;\n
\t\tthis._animateOff = false;\n
\n
\t\treturn false;\n
\t},\n
\n
\t_detectOrientation: function() {\n
\t\tthis.orientation = ( this.options.orientation === "vertical" ) ? "vertical" : "horizontal";\n
\t},\n
\n
\t_normValueFromMouse: function( position ) {\n
\t\tvar pixelTotal,\n
\t\t\tpixelMouse,\n
\t\t\tpercentMouse,\n
\t\t\tvalueTotal,\n
\t\t\tvalueMouse;\n
\n
\t\tif ( this.orientation === "horizontal" ) {\n
\t\t\tpixelTotal = this.elementSize.width;\n
\t\t\tpixelMouse = position.x - this.elementOffset.left - ( this._clickOffset ? this._clickOffset.left : 0 );\n
\t\t} else {\n
\t\t\tpixelTotal = this.elementSize.height;\n
\t\t\tpixelMouse = position.y - this.elementOffset.top - ( this._clickOffset ? this._clickOffset.top : 0 );\n
\t\t}\n
\n
\t\tpercentMouse = ( pixelMouse / pixelTotal );\n
\t\tif ( percentMouse > 1 ) {\n
\t\t\tpercentMouse = 1;\n
\t\t}\n
\t\tif ( percentMouse < 0 ) {\n
\t\t\tpercentMouse = 0;\n
\t\t}\n
\t\tif ( this.orientation === "vertical" ) {\n
\t\t\tpercentMouse = 1 - percentMouse;\n
\t\t}\n
\n
\t\tvalueTotal = this._valueMax() - this._valueMin();\n
\t\tvalueMouse = this._valueMin() + percentMouse * valueTotal;\n
\n
\t\treturn this._trimAlignValue( valueMouse );\n
\t},\n
\n
\t_start: function( event, index ) {\n
\t\tvar uiHash = {\n
\t\t\thandle: this.handles[ index ],\n
\t\t\tvalue: this.value()\n
\t\t};\n
\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\tuiHash.value = this.values( index );\n
\t\t\tuiHash.values = this.values();\n
\t\t}\n
\t\treturn this._trigger( "start", event, uiHash );\n
\t},\n
\n
\t_slide: function( event, index, newVal ) {\n
\t\tvar otherVal,\n
\t\t\tnewValues,\n
\t\t\tallowed;\n
\n
\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\totherVal = this.values( index ? 0 : 1 );\n
\n
\t\t\tif ( ( this.options.values.length === 2 && this.options.range === true ) &&\n
\t\t\t\t\t( ( index === 0 && newVal > otherVal) || ( index === 1 && newVal < otherVal ) )\n
\t\t\t\t) {\n
\t\t\t\tnewVal = otherVal;\n
\t\t\t}\n
\n
\t\t\tif ( newVal !== this.values( index ) ) {\n
\t\t\t\tnewValues = this.values();\n
\t\t\t\tnewValues[ index ] = newVal;\n
\t\t\t\t// A slide can be canceled by returning false from the slide callback\n
\t\t\t\tallowed = this._trigger( "slide", event, {\n
\t\t\t\t\thandle: this.handles[ index ],\n
\t\t\t\t\tvalue: newVal,\n
\t\t\t\t\tvalues: newValues\n
\t\t\t\t} );\n
\t\t\t\totherVal = this.values( index ? 0 : 1 );\n
\t\t\t\tif ( allowed !== false ) {\n
\t\t\t\t\tthis.values( index, newVal );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tif ( newVal !== this.value() ) {\n
\t\t\t\t// A slide can be canceled by returning false from the slide callback\n
\t\t\t\tallowed = this._trigger( "slide", event, {\n
\t\t\t\t\thandle: this.handles[ index ],\n
\t\t\t\t\tvalue: newVal\n
\t\t\t\t} );\n
\t\t\t\tif ( allowed !== false ) {\n
\t\t\t\t\tthis.value( newVal );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_stop: function( event, index ) {\n
\t\tvar uiHash = {\n
\t\t\thandle: this.handles[ index ],\n
\t\t\tvalue: this.value()\n
\t\t};\n
\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\tuiHash.value = this.values( index );\n
\t\t\tuiHash.values = this.values();\n
\t\t}\n
\n
\t\tthis._trigger( "stop", event, uiHash );\n
\t},\n
\n
\t_change: function( event, index ) {\n
\t\tif ( !this._keySliding && !this._mouseSliding ) {\n
\t\t\tvar uiHash = {\n
\t\t\t\thandle: this.handles[ index ],\n
\t\t\t\tvalue: this.value()\n
\t\t\t};\n
\t\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\t\tuiHash.value = this.values( index );\n
\t\t\t\tuiHash.values = this.values();\n
\t\t\t}\n
\n
\t\t\t//store the last changed value index for reference when handles overlap\n
\t\t\tthis._lastChangedValue = index;\n
\n
\t\t\tthis._trigger( "change", event, uiHash );\n
\t\t}\n
\t},\n
\n
\tvalue: function( newValue ) {\n
\t\tif ( arguments.length ) {\n
\t\t\tthis.options.value = this._trimAlignValue( newValue );\n
\t\t\tthis._refreshValue();\n
\t\t\tthis._change( null, 0 );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\treturn this._value();\n
\t},\n
\n
\tvalues: function( index, newValue ) {\n
\t\tvar vals,\n
\t\t\tnewValues,\n
\t\t\ti;\n
\n
\t\tif ( arguments.length > 1 ) {\n
\t\t\tthis.options.values[ index ] = this._trimAlignValue( newValue );\n
\t\t\tthis._refreshValue();\n
\t\t\tthis._change( null, index );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( arguments.length ) {\n
\t\t\tif ( $.isArray( arguments[ 0 ] ) ) {\n
\t\t\t\tvals = this.options.values;\n
\t\t\t\tnewValues = arguments[ 0 ];\n
\t\t\t\tfor ( i = 0; i < vals.length; i += 1 ) {\n
\t\t\t\t\tvals[ i ] = this._trimAlignValue( newValues[ i ] );\n
\t\t\t\t\tthis._change( null, i );\n
\t\t\t\t}\n
\t\t\t\tthis._refreshValue();\n
\t\t\t} else {\n
\t\t\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\t\t\treturn this._values( index );\n
\t\t\t\t} else {\n
\t\t\t\t\treturn this.value();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\treturn this._values();\n
\t\t}\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tvar i,\n
\t\t\tvalsLength = 0;\n
\n
\t\tif ( key === "range" && this.options.range === true ) {\n
\t\t\tif ( value === "min" ) {\n
\t\t\t\tthis.options.value = this._values( 0 );\n
\t\t\t\tthis.options.values = null;\n
\t\t\t} else if ( value === "max" ) {\n
\t\t\t\tthis.options.value = this._values( this.options.values.length-1 );\n
\t\t\t\tthis.options.values = null;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( $.isArray( this.options.values ) ) {\n
\t\t\tvalsLength = this.options.values.length;\n
\t\t}\n
\n
\t\t$.Widget.prototype._setOption.apply( this, arguments );\n
\n
\t\tswitch ( key ) {\n
\t\t\tcase "orientation":\n
\t\t\t\tthis._detectOrientation();\n
\t\t\t\tthis.element\n
\t\t\t\t\t.removeClass( "ui-slider-horizontal ui-slider-vertical" )\n
\t\t\t\t\t.addClass( "ui-slider-" + this.orientation );\n
\t\t\t\tthis._refreshValue();\n
\t\t\t\tbreak;\n
\t\t\tcase "value":\n
\t\t\t\tthis._animateOff = true;\n
\t\t\t\tthis._refreshValue();\n
\t\t\t\tthis._change( null, 0 );\n
\t\t\t\tthis._animateOff = false;\n
\t\t\t\tbreak;\n
\t\t\tcase "values":\n
\t\t\t\tthis._animateOff = true;\n
\t\t\t\tthis._refreshValue();\n
\t\t\t\tfor ( i = 0; i < valsLength; i += 1 ) {\n
\t\t\t\t\tthis._change( null, i );\n
\t\t\t\t}\n
\t\t\t\tthis._animateOff = false;\n
\t\t\t\tbreak;\n
\t\t\tcase "min":\n
\t\t\tcase "max":\n
\t\t\t\tthis._animateOff = true;\n
\t\t\t\tthis._refreshValue();\n
\t\t\t\tthis._animateOff = false;\n
\t\t\t\tbreak;\n
\t\t\tcase "range":\n
\t\t\t\tthis._animateOff = true;\n
\t\t\t\tthis._refresh();\n
\t\t\t\tthis._animateOff = false;\n
\t\t\t\tbreak;\n
\t\t}\n
\t},\n
\n
\t//internal value getter\n
\t// _value() returns value trimmed by min and max, aligned by step\n
\t_value: function() {\n
\t\tvar val = this.options.value;\n
\t\tval = this._trimAlignValue( val );\n
\n
\t\treturn val;\n
\t},\n
\n
\t//internal values getter\n
\t// _values() returns array of values trimmed by min and max, aligned by step\n
\t// _values( index ) returns single value trimmed by min and max, aligned by step\n
\t_values: function( index ) {\n
\t\tvar val,\n
\t\t\tvals,\n
\t\t\ti;\n
\n
\t\tif ( arguments.length ) {\n
\t\t\tval = this.options.values[ index ];\n
\t\t\tval = this._trimAlignValue( val );\n
\n
\t\t\treturn val;\n
\t\t} else if ( this.options.values && this.options.values.length ) {\n
\t\t\t// .slice() creates a copy of the array\n
\t\t\t// this copy gets trimmed by min and max and then returned\n
\t\t\tvals = this.options.values.slice();\n
\t\t\tfor ( i = 0; i < vals.length; i+= 1) {\n
\t\t\t\tvals[ i ] = this._trimAlignValue( vals[ i ] );\n
\t\t\t}\n
\n
\t\t\treturn vals;\n
\t\t} else {\n
\t\t\treturn [];\n
\t\t}\n
\t},\n
\n
\t// returns the step-aligned value that val is closest to, between (inclusive) min and max\n
\t_trimAlignValue: function( val ) {\n
\t\tif ( val <= this._valueMin() ) {\n
\t\t\treturn this._valueMin();\n
\t\t}\n
\t\tif ( val >= this._valueMax() ) {\n
\t\t\treturn this._valueMax();\n
\t\t}\n
\t\tvar step = ( this.options.step > 0 ) ? this.options.step : 1,\n
\t\t\tvalModStep = (val - this._valueMin()) % step,\n
\t\t\talignValue = val - valModStep;\n
\n
\t\tif ( Math.abs(valModStep) * 2 >= step ) {\n
\t\t\talignValue += ( valModStep > 0 ) ? step : ( -step );\n
\t\t}\n
\n
\t\t// Since JavaScript has problems with large floats, round\n
\t\t// the final value to 5 digits after the decimal point (see #4124)\n
\t\treturn parseFloat( alignValue.toFixed(5) );\n
\t},\n
\n
\t_valueMin: function() {\n
\t\treturn this.options.min;\n
\t},\n
\n
\t_valueMax: function() {\n
\t\treturn this.options.max;\n
\t},\n
\n
\t_refreshValue: function() {\n
\t\tvar lastValPercent, valPercent, value, valueMin, valueMax,\n
\t\t\toRange = this.options.range,\n
\t\t\to = this.options,\n
\t\t\tthat = this,\n
\t\t\tanimate = ( !this._animateOff ) ? o.animate : false,\n
\t\t\t_set = {};\n
\n
\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\tthis.handles.each(function( i ) {\n
\t\t\t\tvalPercent = ( that.values(i) - that._valueMin() ) / ( that._valueMax() - that._valueMin() ) * 100;\n
\t\t\t\t_set[ that.orientation === "horizontal" ? "left" : "bottom" ] = valPercent + "%";\n
\t\t\t\t$( this ).stop( 1, 1 )[ animate ? "animate" : "css" ]( _set, o.animate );\n
\t\t\t\tif ( that.options.range === true ) {\n
\t\t\t\t\tif ( that.orientation === "horizontal" ) {\n
\t\t\t\t\t\tif ( i === 0 ) {\n
\t\t\t\t\t\t\tthat.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { left: valPercent + "%" }, o.animate );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif ( i === 1 ) {\n
\t\t\t\t\t\t\tthat.range[ animate ? "animate" : "css" ]( { width: ( valPercent - lastValPercent ) + "%" }, { queue: false, duration: o.animate } );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif ( i === 0 ) {\n
\t\t\t\t\t\t\tthat.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { bottom: ( valPercent ) + "%" }, o.animate );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif ( i === 1 ) {\n
\t\t\t\t\t\t\tthat.range[ animate ? "animate" : "css" ]( { height: ( valPercent - lastValPercent ) + "%" }, { queue: false, duration: o.animate } );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tlastValPercent = valPercent;\n
\t\t\t});\n
\t\t} else {\n
\t\t\tvalue = this.value();\n
\t\t\tvalueMin = this._valueMin();\n
\t\t\tvalueMax = this._valueMax();\n
\t\t\tvalPercent = ( valueMax !== valueMin ) ?\n
\t\t\t\t\t( value - valueMin ) / ( valueMax - valueMin ) * 100 :\n
\t\t\t\t\t0;\n
\t\t\t_set[ this.orientation === "horizontal" ? "left" : "bottom" ] = valPercent + "%";\n
\t\t\tthis.handle.stop( 1, 1 )[ animate ? "animate" : "css" ]( _set, o.animate );\n
\n
\t\t\tif ( oRange === "min" && this.orientation === "horizontal" ) {\n
\t\t\t\tthis.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { width: valPercent + "%" }, o.animate );\n
\t\t\t}\n
\t\t\tif ( oRange === "max" && this.orientation === "horizontal" ) {\n
\t\t\t\tthis.range[ animate ? "animate" : "css" ]( { width: ( 100 - valPercent ) + "%" }, { queue: false, duration: o.animate } );\n
\t\t\t}\n
\t\t\tif ( oRange === "min" && this.orientation === "vertical" ) {\n
\t\t\t\tthis.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { height: valPercent + "%" }, o.animate );\n
\t\t\t}\n
\t\t\tif ( oRange === "max" && this.orientation === "vertical" ) {\n
\t\t\t\tthis.range[ animate ? "animate" : "css" ]( { height: ( 100 - valPercent ) + "%" }, { queue: false, duration: o.animate } );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_handleEvents: {\n
\t\tkeydown: function( event ) {\n
\t\t\tvar allowed, curVal, newVal, step,\n
\t\t\t\tindex = $( event.target ).data( "ui-slider-handle-index" );\n
\n
\t\t\tswitch ( event.keyCode ) {\n
\t\t\t\tcase $.ui.keyCode.HOME:\n
\t\t\t\tcase $.ui.keyCode.END:\n
\t\t\t\tcase $.ui.keyCode.PAGE_UP:\n
\t\t\t\tcase $.ui.keyCode.PAGE_DOWN:\n
\t\t\t\tcase $.ui.keyCode.UP:\n
\t\t\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\t\tcase $.ui.keyCode.DOWN:\n
\t\t\t\tcase $.ui.keyCode.LEFT:\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\tif ( !this._keySliding ) {\n
\t\t\t\t\t\tthis._keySliding = true;\n
\t\t\t\t\t\t$( event.target ).addClass( "ui-state-active" );\n
\t\t\t\t\t\tallowed = this._start( event, index );\n
\t\t\t\t\t\tif ( allowed === false ) {\n
\t\t\t\t\t\t\treturn;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tstep = this.options.step;\n
\t\t\tif ( this.options.values && this.options.values.length ) {\n
\t\t\t\tcurVal = newVal = this.values( index );\n
\t\t\t} else {\n
\t\t\t\tcurVal = newVal = this.value();\n
\t\t\t}\n
\n
\t\t\tswitch ( event.keyCode ) {\n
\t\t\t\tcase $.ui.keyCode.HOME:\n
\t\t\t\t\tnewVal = this._valueMin();\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.END:\n
\t\t\t\t\tnewVal = this._valueMax();\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.PAGE_UP:\n
\t\t\t\t\tnewVal = this._trimAlignValue( curVal + ( (this._valueMax() - this._valueMin()) / numPages ) );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.PAGE_DOWN:\n
\t\t\t\t\tnewVal = this._trimAlignValue( curVal - ( (this._valueMax() - this._valueMin()) / numPages ) );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.UP:\n
\t\t\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\t\t\tif ( curVal === this._valueMax() ) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\tnewVal = this._trimAlignValue( curVal + step );\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.DOWN:\n
\t\t\t\tcase $.ui.keyCode.LEFT:\n
\t\t\t\t\tif ( curVal === this._valueMin() ) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\tnewVal = this._trimAlignValue( curVal - step );\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tthis._slide( event, index, newVal );\n
\t\t},\n
\t\tclick: function( event ) {\n
\t\t\tevent.preventDefault();\n
\t\t},\n
\t\tkeyup: function( event ) {\n
\t\t\tvar index = $( event.target ).data( "ui-slider-handle-index" );\n
\n
\t\t\tif ( this._keySliding ) {\n
\t\t\t\tthis._keySliding = false;\n
\t\t\t\tthis._stop( event, index );\n
\t\t\t\tthis._change( event, index );\n
\t\t\t\t$( event.target ).removeClass( "ui-state-active" );\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
});\n
\n
}(jQuery));\n
(function( $ ) {\n
\n
function modifier( fn ) {\n
\treturn function() {\n
\t\tvar previous = this.element.val();\n
\t\tfn.apply( this, arguments );\n
\t\tthis._refresh();\n
\t\tif ( previous !== this.element.val() ) {\n
\t\t\tthis._trigger( "change" );\n
\t\t}\n
\t};\n
}\n
\n
$.widget( "ui.spinner", {\n
\tversion: "1.10.4",\n
\tdefaultElement: "<input>",\n
\twidgetEventPrefix: "spin",\n
\toptions: {\n
\t\tculture: null,\n
\t\ticons: {\n
\t\t\tdown: "ui-icon-triangle-1-s",\n
\t\t\tup: "ui-icon-triangle-1-n"\n
\t\t},\n
\t\tincremental: true,\n
\t\tmax: null,\n
\t\tmin: null,\n
\t\tnumberFormat: null,\n
\t\tpage: 10,\n
\t\tstep: 1,\n
\n
\t\tchange: null,\n
\t\tspin: null,\n
\t\tstart: null,\n
\t\tstop: null\n
\t},\n
\n
\t_create: function() {\n
\t\t// handle string values that need to be parsed\n
\t\tthis._setOption( "max", this.options.max );\n
\t\tthis._setOption( "min", this.options.min );\n
\t\tthis._setOption( "step", this.options.step );\n
\n
\t\t// Only format if there is a value, prevents the field from being marked\n
\t\t// as invalid in Firefox, see #9573.\n
\t\tif ( this.value() !== "" ) {\n
\t\t\t// Format the value, but don\'t constrain.\n
\t\t\tthis._value( this.element.val(), true );\n
\t\t}\n
\n
\t\tthis._draw();\n
\t\tthis._on( this._events );\n
\t\tthis._refresh();\n
\n
\t\t// turning off autocomplete prevents the browser from remembering the\n
\t\t// value when navigating through history, so we re-enable autocomplete\n
\t\t// if the page is unloaded before the widget is destroyed. #7790\n
\t\tthis._on( this.window, {\n
\t\t\tbeforeunload: function() {\n
\t\t\t\tthis.element.removeAttr( "autocomplete" );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_getCreateOptions: function() {\n
\t\tvar options = {},\n
\t\t\telement = this.element;\n
\n
\t\t$.each( [ "min", "max", "step" ], function( i, option ) {\n
\t\t\tvar value = element.attr( option );\n
\t\t\tif ( value !== undefined && value.length ) {\n
\t\t\t\toptions[ option ] = value;\n
\t\t\t}\n
\t\t});\n
\n
\t\treturn options;\n
\t},\n
\n
\t_events: {\n
\t\tkeydown: function( event ) {\n
\t\t\tif ( this._start( event ) && this._keydown( event ) ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t}\n
\t\t},\n
\t\tkeyup: "_stop",\n
\t\tfocus: function() {\n
\t\t\tthis.previous = this.element.val();\n
\t\t},\n
\t\tblur: function( event ) {\n
\t\t\tif ( this.cancelBlur ) {\n
\t\t\t\tdelete this.cancelBlur;\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tthis._stop();\n
\t\t\tthis._refresh();\n
\t\t\tif ( this.previous !== this.element.val() ) {\n
\t\t\t\tthis._trigger( "change", event );\n
\t\t\t}\n
\t\t},\n
\t\tmousewheel: function( event, delta ) {\n
\t\t\tif ( !delta ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( !this.spinning && !this._start( event ) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\tthis._spin( (delta > 0 ? 1 : -1) * this.options.step, event );\n
\t\t\tclearTimeout( this.mousewheelTimer );\n
\t\t\tthis.mousewheelTimer = this._delay(function() {\n
\t\t\t\tif ( this.spinning ) {\n
\t\t\t\t\tthis._stop( event );\n
\t\t\t\t}\n
\t\t\t}, 100 );\n
\t\t\tevent.preventDefault();\n
\t\t},\n
\t\t"mousedown .ui-spinner-button": function( event ) {\n
\t\t\tvar previous;\n
\n
\t\t\t// We never want the buttons to have focus; whenever the user is\n
\t\t\t// interacting with the spinner, the focus should be on the input.\n
\t\t\t// If the input is focused then this.previous is properly set from\n
\t\t\t// when the input first received focus. If the input is not focused\n
\t\t\t// then we need to set this.previous based on the value before spinning.\n
\t\t\tprevious = this.element[0] === this.document[0].activeElement ?\n
\t\t\t\tthis.previous : this.element.val();\n
\t\t\tfunction checkFocus() {\n
\t\t\t\tvar isActive = this.element[0] === this.document[0].activeElement;\n
\t\t\t\tif ( !isActive ) {\n
\t\t\t\t\tthis.element.focus();\n
\t\t\t\t\tthis.previous = previous;\n
\t\t\t\t\t// support: IE\n
\t\t\t\t\t// IE sets focus asynchronously, so we need to check if focus\n
\t\t\t\t\t// moved off of the input because the user clicked on the button.\n
\t\t\t\t\tthis._delay(function() {\n
\t\t\t\t\t\tthis.previous = previous;\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// ensure focus is on (or stays on) the text field\n
\t\t\tevent.preventDefault();\n
\t\t\tcheckFocus.call( this );\n
\n
\t\t\t// support: IE\n
\t\t\t// IE doesn\'t prevent moving focus even with event.preventDefault()\n
\t\t\t// so we set a flag to know when we should ignore the blur event\n
\t\t\t// and check (again) if focus moved off of the input.\n
\t\t\tthis.cancelBlur = true;\n
\t\t\tthis._delay(function() {\n
\t\t\t\tdelete this.cancelBlur;\n
\t\t\t\tcheckFocus.call( this );\n
\t\t\t});\n
\n
\t\t\tif ( this._start( event ) === false ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tthis._repeat( null, $( event.currentTarget ).hasClass( "ui-spinner-up" ) ? 1 : -1, event );\n
\t\t},\n
\t\t"mouseup .ui-spinner-button": "_stop",\n
\t\t"mouseenter .ui-spinner-button": function( event ) {\n
\t\t\t// button will add ui-state-active if mouse was down while mouseleave and kept down\n
\t\t\tif ( !$( event.currentTarget ).hasClass( "ui-state-active" ) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif ( this._start( event ) === false ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tthis._repeat( null, $( event.currentTarget ).hasClass( "ui-spinner-up" ) ? 1 : -1, event );\n
\t\t},\n
\t\t// TODO: do we really want to consider this a stop?\n
\t\t// shouldn\'t we just stop the repeater and wait until mouseup before\n
\t\t// we trigger the stop event?\n
\t\t"mouseleave .ui-spinner-button": "_stop"\n
\t},\n
\n
\t_draw: function() {\n
\t\tvar uiSpinner = this.uiSpinner = this.element\n
\t\t\t.addClass( "ui-spinner-input" )\n
\t\t\t.attr( "autocomplete", "off" )\n
\t\t\t.wrap( this._uiSpinnerHtml() )\n
\t\t\t.parent()\n
\t\t\t\t// add buttons\n
\t\t\t\t.append( this._buttonHtml() );\n
\n
\t\tthis.element.attr( "role", "spinbutton" );\n
\n
\t\t// button bindings\n
\t\tthis.buttons = uiSpinner.find( ".ui-spinner-button" )\n
\t\t\t.attr( "tabIndex", -1 )\n
\t\t\t.button()\n
\t\t\t.removeClass( "ui-corner-all" );\n
\n
\t\t// IE 6 doesn\'t understand height: 50% for the buttons\n
\t\t// unless the wrapper has an explicit height\n
\t\tif ( this.buttons.height() > Math.ceil( uiSpinner.height() * 0.5 ) &&\n
\t\t\t\tuiSpinner.height() > 0 ) {\n
\t\t\tuiSpinner.height( uiSpinner.height() );\n
\t\t}\n
\n
\t\t// disable spinner if element was already disabled\n
\t\tif ( this.options.disabled ) {\n
\t\t\tthis.disable();\n
\t\t}\n
\t},\n
\n
\t_keydown: function( event ) {\n
\t\tvar options = this.options,\n
\t\t\tkeyCode = $.ui.keyCode;\n
\n
\t\tswitch ( event.keyCode ) {\n
\t\tcase keyCode.UP:\n
\t\t\tthis._repeat( null, 1, event );\n
\t\t\treturn true;\n
\t\tcase keyCode.DOWN:\n
\t\t\tthis._repeat( null, -1, event );\n
\t\t\treturn true;\n
\t\tcase keyCode.PAGE_UP:\n
\t\t\tthis._repeat( null, options.page, event );\n
\t\t\treturn true;\n
\t\tcase keyCode.PAGE_DOWN:\n
\t\t\tthis._repeat( null, -options.page, event );\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_uiSpinnerHtml: function() {\n
\t\treturn "<span class=\'ui-spinner ui-widget ui-widget-content ui-corner-all\'></span>";\n
\t},\n
\n
\t_buttonHtml: function() {\n
\t\treturn "" +\n
\t\t\t"<a class=\'ui-spinner-button ui-spinner-up ui-corner-tr\'>" +\n
\t\t\t\t"<span class=\'ui-icon " + this.options.icons.up + "\'>&#9650;</span>" +\n
\t\t\t"</a>" +\n
\t\t\t"<a class=\'ui-spinner-button ui-spinner-down ui-corner-br\'>" +\n
\t\t\t\t"<span class=\'ui-icon " + this.options.icons.down + "\'>&#9660;</span>" +\n
\t\t\t"</a>";\n
\t},\n
\n
\t_start: function( event ) {\n
\t\tif ( !this.spinning && this._trigger( "start", event ) === false ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif ( !this.counter ) {\n
\t\t\tthis.counter = 1;\n
\t\t}\n
\t\tthis.spinning = true;\n
\t\treturn true;\n
\t},\n
\n
\t_repeat: function( i, steps, event ) {\n
\t\ti = i || 500;\n
\n
\t\tclearTimeout( this.timer );\n
\t\tthis.timer = this._delay(function() {\n
\t\t\tthis._repeat( 40, steps, event );\n
\t\t}, i );\n
\n
\t\tthis._spin( steps * this.options.step, event );\n
\t},\n
\n
\t_spin: function( step, event ) {\n
\t\tvar value = this.value() || 0;\n
\n
\t\tif ( !this.counter ) {\n
\t\t\tthis.counter = 1;\n
\t\t}\n
\n
\t\tvalue = this._adjustValue( value + step * this._increment( this.counter ) );\n
\n
\t\tif ( !this.spinning || this._trigger( "spin", event, { value: value } ) !== false) {\n
\t\t\tthis._value( value );\n
\t\t\tthis.counter++;\n
\t\t}\n
\t},\n
\n
\t_increment: function( i ) {\n
\t\tvar incremental = this.options.incremental;\n
\n
\t\tif ( incremental ) {\n
\t\t\treturn $.isFunction( incremental ) ?\n
\t\t\t\tincremental( i ) :\n
\t\t\t\tMath.floor( i*i*i/50000 - i*i/500 + 17*i/200 + 1 );\n
\t\t}\n
\n
\t\treturn 1;\n
\t},\n
\n
\t_precision: function() {\n
\t\tvar precision = this._precisionOf( this.options.step );\n
\t\tif ( this.options.min !== null ) {\n
\t\t\tprecision = Math.max( precision, this._precisionOf( this.options.min ) );\n
\t\t}\n
\t\treturn precision;\n
\t},\n
\n
\t_precisionOf: function( num ) {\n
\t\tvar str = num.toString(),\n
\t\t\tdecimal = str.indexOf( "." );\n
\t\treturn decimal === -1 ? 0 : str.length - decimal - 1;\n
\t},\n
\n
\t_adjustValue: function( value ) {\n
\t\tvar base, aboveMin,\n
\t\t\toptions = this.options;\n
\n
\t\t// make sure we\'re at a valid step\n
\t\t// - find out where we are relative to the base (min or 0)\n
\t\tbase = options.min !== null ? options.min : 0;\n
\t\taboveMin = value - base;\n
\t\t// - round to the nearest step\n
\t\taboveMin = Math.round(aboveMin / options.step) * options.step;\n
\t\t// - rounding is based on 0, so adjust back to our base\n
\t\tvalue = base + aboveMin;\n
\n
\t\t// fix precision from bad JS floating point math\n
\t\tvalue = parseFloat( value.toFixed( this._precision() ) );\n
\n
\t\t// clamp the value\n
\t\tif ( options.max !== null && value > options.max) {\n
\t\t\treturn options.max;\n
\t\t}\n
\t\tif ( options.min !== null && value < options.min ) {\n
\t\t\treturn options.min;\n
\t\t}\n
\n
\t\treturn value;\n
\t},\n
\n
\t_stop: function( event ) {\n
\t\tif ( !this.spinning ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tclearTimeout( this.timer );\n
\t\tclearTimeout( this.mousewheelTimer );\n
\t\tthis.counter = 0;\n
\t\tthis.spinning = false;\n
\t\tthis._trigger( "stop", event );\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "culture" || key === "numberFormat" ) {\n
\t\t\tvar prevValue = this._parse( this.element.val() );\n
\t\t\tthis.options[ key ] = value;\n
\t\t\tthis.element.val( this._format( prevValue ) );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( key === "max" || key === "min" || key === "step" ) {\n
\t\t\tif ( typeof value === "string" ) {\n
\t\t\t\tvalue = this._parse( value );\n
\t\t\t}\n
\t\t}\n
\t\tif ( key === "icons" ) {\n
\t\t\tthis.buttons.first().find( ".ui-icon" )\n
\t\t\t\t.removeClass( this.options.icons.up )\n
\t\t\t\t.addClass( value.up );\n
\t\t\tthis.buttons.last().find( ".ui-icon" )\n
\t\t\t\t.removeClass( this.options.icons.down )\n
\t\t\t\t.addClass( value.down );\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\n
\t\tif ( key === "disabled" ) {\n
\t\t\tif ( value ) {\n
\t\t\t\tthis.element.prop( "disabled", true );\n
\t\t\t\tthis.buttons.button( "disable" );\n
\t\t\t} else {\n
\t\t\t\tthis.element.prop( "disabled", false );\n
\t\t\t\tthis.buttons.button( "enable" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_setOptions: modifier(function( options ) {\n
\t\tthis._super( options );\n
\t\tthis._value( this.element.val() );\n
\t}),\n
\n
\t_parse: function( val ) {\n
\t\tif ( typeof val === "string" && val !== "" ) {\n
\t\t\tval = window.Globalize && this.options.numberFormat ?\n
\t\t\t\tGlobalize.parseFloat( val, 10, this.options.culture ) : +val;\n
\t\t}\n
\t\treturn val === "" || isNaN( val ) ? null : val;\n
\t},\n
\n
\t_format: function( value ) {\n
\t\tif ( value === "" ) {\n
\t\t\treturn "";\n
\t\t}\n
\t\treturn window.Globalize && this.options.numberFormat ?\n
\t\t\tGlobalize.format( value, this.options.numberFormat, this.options.culture ) :\n
\t\t\tvalue;\n
\t},\n
\n
\t_refresh: function() {\n
\t\tthis.element.attr({\n
\t\t\t"aria-valuemin": this.options.min,\n
\t\t\t"aria-valuemax": this.options.max,\n
\t\t\t// TODO: what should we do with values that can\'t be parsed?\n
\t\t\t"aria-valuenow": this._parse( this.element.val() )\n
\t\t});\n
\t},\n
\n
\t// update the value without triggering change\n
\t_value: function( value, allowAny ) {\n
\t\tvar parsed;\n
\t\tif ( value !== "" ) {\n
\t\t\tparsed = this._parse( value );\n
\t\t\tif ( parsed !== null ) {\n
\t\t\t\tif ( !allowAny ) {\n
\t\t\t\t\tparsed = this._adjustValue( parsed );\n
\t\t\t\t}\n
\t\t\t\tvalue = this._format( parsed );\n
\t\t\t}\n
\t\t}\n
\t\tthis.element.val( value );\n
\t\tthis._refresh();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-spinner-input" )\n
\t\t\t.prop( "disabled", false )\n
\t\t\t.removeAttr( "autocomplete" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-valuemin" )\n
\t\t\t.removeAttr( "aria-valuemax" )\n
\t\t\t.removeAttr( "aria-valuenow" );\n
\t\tthis.uiSpinner.replaceWith( this.element );\n
\t},\n
\n
\tstepUp: modifier(function( steps ) {\n
\t\tthis._stepUp( steps );\n
\t}),\n
\t_stepUp: function( steps ) {\n
\t\tif ( this._start() ) {\n
\t\t\tthis._spin( (steps || 1) * this.options.step );\n
\t\t\tthis._stop();\n
\t\t}\n
\t},\n
\n
\tstepDown: modifier(function( steps ) {\n
\t\tthis._stepDown( steps );\n
\t}),\n
\t_stepDown: function( steps ) {\n
\t\tif ( this._start() ) {\n
\t\t\tthis._spin( (steps || 1) * -this.options.step );\n
\t\t\tthis._stop();\n
\t\t}\n
\t},\n
\n
\tpageUp: modifier(function( pages ) {\n
\t\tthis._stepUp( (pages || 1) * this.options.page );\n
\t}),\n
\n
\tpageDown: modifier(function( pages ) {\n
\t\tthis._stepDown( (pages || 1) * this.options.page );\n
\t}),\n
\n
\tvalue: function( newVal ) {\n
\t\tif ( !arguments.length ) {\n
\t\t\treturn this._parse( this.element.val() );\n
\t\t}\n
\t\tmodifier( this._value ).call( this, newVal );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.uiSpinner;\n
\t}\n
});\n
\n
}( jQuery ) );\n
(function( $, undefined ) {\n
\n
var tabId = 0,\n
\trhash = /#.*$/;\n
\n
function getNextTabId() {\n
\treturn ++tabId;\n
}\n
\n
function isLocal( anchor ) {\n
\t// support: IE7\n
\t// IE7 doesn\'t normalize the href property when set via script (#9317)\n
\tanchor = anchor.cloneNode( false );\n
\n
\treturn anchor.hash.length > 1 &&\n
\t\tdecodeURIComponent( anchor.href.replace( rhash, "" ) ) ===\n
\t\t\tdecodeURIComponent( location.href.replace( rhash, "" ) );\n
}\n
\n
$.widget( "ui.tabs", {\n
\tversion: "1.10.4",\n
\tdelay: 300,\n
\toptions: {\n
\t\tactive: null,\n
\t\tcollapsible: false,\n
\t\tevent: "click",\n
\t\theightStyle: "content",\n
\t\thide: null,\n
\t\tshow: null,\n
\n
\t\t// callbacks\n
\t\tactivate: null,\n
\t\tbeforeActivate: null,\n
\t\tbeforeLoad: null,\n
\t\tload: null\n
\t},\n
\n
\t_create: function() {\n
\t\tvar that = this,\n
\t\t\toptions = this.options;\n
\n
\t\tthis.running = false;\n
\n
\t\tthis.element\n
\t\t\t.addClass( "ui-tabs ui-widget ui-widget-content ui-corner-all" )\n
\t\t\t.toggleClass( "ui-tabs-collapsible", options.collapsible )\n
\t\t\t// Prevent users from focusing disabled tabs via click\n
\t\t\t.delegate( ".ui-tabs-nav > li", "mousedown" + this.eventNamespace, function( event ) {\n
\t\t\t\tif ( $( this ).is( ".ui-state-disabled" ) ) {\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t// support: IE <9\n
\t\t\t// Preventing the default action in mousedown doesn\'t prevent IE\n
\t\t\t// from focusing the element, so if the anchor gets focused, blur.\n
\t\t\t// We don\'t have to worry about focusing the previously focused\n
\t\t\t// element since clicking on a non-focusable element should focus\n
\t\t\t// the body anyway.\n
\t\t\t.delegate( ".ui-tabs-anchor", "focus" + this.eventNamespace, function() {\n
\t\t\t\tif ( $( this ).closest( "li" ).is( ".ui-state-disabled" ) ) {\n
\t\t\t\t\tthis.blur();\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\tthis._processTabs();\n
\t\toptions.active = this._initialActive();\n
\n
\t\t// Take disabling tabs via class attribute from HTML\n
\t\t// into account and update option properly.\n
\t\tif ( $.isArray( options.disabled ) ) {\n
\t\t\toptions.disabled = $.unique( options.disabled.concat(\n
\t\t\t\t$.map( this.tabs.filter( ".ui-state-disabled" ), function( li ) {\n
\t\t\t\t\treturn that.tabs.index( li );\n
\t\t\t\t})\n
\t\t\t) ).sort();\n
\t\t}\n
\n
\t\t// check for length avoids error when initializing empty list\n
\t\tif ( this.options.active !== false && this.anchors.length ) {\n
\t\t\tthis.active = this._findActive( options.active );\n
\t\t} else {\n
\t\t\tthis.active = $();\n
\t\t}\n
\n
\t\tthis._refresh();\n
\n
\t\tif ( this.active.length ) {\n
\t\t\tthis.load( options.active );\n
\t\t}\n
\t},\n
\n
\t_initialActive: function() {\n
\t\tvar active = this.options.active,\n
\t\t\tcollapsible = this.options.collapsible,\n
\t\t\tlocationHash = location.hash.substring( 1 );\n
\n
\t\tif ( active === null ) {\n
\t\t\t// check the fragment identifier in the URL\n
\t\t\tif ( locationHash ) {\n
\t\t\t\tthis.tabs.each(function( i, tab ) {\n
\t\t\t\t\tif ( $( tab ).attr( "aria-controls" ) === locationHash ) {\n
\t\t\t\t\t\tactive = i;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\t// check for a tab marked active via a class\n
\t\t\tif ( active === null ) {\n
\t\t\t\tactive = this.tabs.index( this.tabs.filter( ".ui-tabs-active" ) );\n
\t\t\t}\n
\n
\t\t\t// no active tab, set to false\n
\t\t\tif ( active === null || active === -1 ) {\n
\t\t\t\tactive = this.tabs.length ? 0 : false;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// handle numbers: negative, out of range\n
\t\tif ( active !== false ) {\n
\t\t\tactive = this.tabs.index( this.tabs.eq( active ) );\n
\t\t\tif ( active === -1 ) {\n
\t\t\t\tactive = collapsible ? false : 0;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// don\'t allow collapsible: false and active: false\n
\t\tif ( !collapsible && active === false && this.anchors.length ) {\n
\t\t\tactive = 0;\n
\t\t}\n
\n
\t\treturn active;\n
\t},\n
\n
\t_getCreateEventData: function() {\n
\t\treturn {\n
\t\t\ttab: this.active,\n
\t\t\tpanel: !this.active.length ? $() : this._getPanelForTab( this.active )\n
\t\t};\n
\t},\n
\n
\t_tabKeydown: function( event ) {\n
\t\tvar focusedTab = $( this.document[0].activeElement ).closest( "li" ),\n
\t\t\tselectedIndex = this.tabs.index( focusedTab ),\n
\t\t\tgoingForward = true;\n
\n
\t\tif ( this._handlePageNav( event ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tswitch ( event.keyCode ) {\n
\t\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\tcase $.ui.keyCode.DOWN:\n
\t\t\t\tselectedIndex++;\n
\t\t\t\tbreak;\n
\t\t\tcase $.ui.keyCode.UP:\n
\t\t\tcase $.ui.keyCode.LEFT:\n
\t\t\t\tgoingForward = false;\n
\t\t\t\tselectedIndex--;\n
\t\t\t\tbreak;\n
\t\t\tcase $.ui.keyCode.END:\n
\t\t\t\tselectedIndex = this.anchors.length - 1;\n
\t\t\t\tbreak;\n
\t\t\tcase $.ui.keyCode.HOME:\n
\t\t\t\tselectedIndex = 0;\n
\t\t\t\tbreak;\n
\t\t\tcase $.ui.keyCode.SPACE:\n
\t\t\t\t// Activate only, no collapsing\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\tclearTimeout( this.activating );\n
\t\t\t\tthis._activate( selectedIndex );\n
\t\t\t\treturn;\n
\t\t\tcase $.ui.keyCode.ENTER:\n
\t\t\t\t// Toggle (cancel delayed activation, allow collapsing)\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\tclearTimeout( this.activating );\n
\t\t\t\t// Determine if we should collapse or activate\n
\t\t\t\tthis._activate( selectedIndex === this.options.active ? false : selectedIndex );\n
\t\t\t\treturn;\n
\t\t\tdefault:\n
\t\t\t\treturn;\n
\t\t}\n
\n
\t\t// Focus the appropriate tab, based on which key was pressed\n
\t\tevent.preventDefault();\n
\t\tclearTimeout( this.activating );\n
\t\tselectedIndex = this._focusNextTab( selectedIndex, goingForward );\n
\n
\t\t// Navigating with control key will prevent automatic activation\n
\t\tif ( !event.ctrlKey ) {\n
\t\t\t// Update aria-selected immediately so that AT think the tab is already selected.\n
\t\t\t// Otherwise AT may confuse the user by stating that they need to activate the tab,\n
\t\t\t// but the tab will already be activated by the time the announcement finishes.\n
\t\t\tfocusedTab.attr( "aria-selected", "false" );\n
\t\t\tthis.tabs.eq( selectedIndex ).attr( "aria-selected", "true" );\n
\n
\t\t\tthis.activating = this._delay(function() {\n
\t\t\t\tthis.option( "active", selectedIndex );\n
\t\t\t}, this.delay );\n
\t\t}\n
\t},\n
\n
\t_panelKeydown: function( event ) {\n
\t\tif ( this._handlePageNav( event ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Ctrl+up moves focus to the current tab\n
\t\tif ( event.ctrlKey && event.keyCode === $.ui.keyCode.UP ) {\n
\t\t\tevent.preventDefault();\n
\t\t\tthis.active.focus();\n
\t\t}\n
\t},\n
\n
\t// Alt+page up/down moves focus to the previous/next tab (and activates)\n
\t_handlePageNav: function( event ) {\n
\t\tif ( event.altKey && event.keyCode === $.ui.keyCode.PAGE_UP ) {\n
\t\t\tthis._activate( this._focusNextTab( this.options.active - 1, false ) );\n
\t\t\treturn true;\n
\t\t}\n
\t\tif ( event.altKey && event.keyCode === $.ui.keyCode.PAGE_DOWN ) {\n
\t\t\tthis._activate( this._focusNextTab( this.options.active + 1, true ) );\n
\t\t\treturn true;\n
\t\t}\n
\t},\n
\n
\t_findNextTab: function( index, goingForward ) {\n
\t\tvar lastTabIndex = this.tabs.length - 1;\n
\n
\t\tfunction constrain() {\n
\t\t\tif ( index > lastTabIndex ) {\n
\t\t\t\tindex = 0;\n
\t\t\t}\n
\t\t\tif ( index < 0 ) {\n
\t\t\t\tindex = lastTabIndex;\n
\t\t\t}\n
\t\t\treturn index;\n
\t\t}\n
\n
\t\twhile ( $.inArray( constrain(), this.options.disabled ) !== -1 ) {\n
\t\t\tindex = goingForward ? index + 1 : index - 1;\n
\t\t}\n
\n
\t\treturn index;\n
\t},\n
\n
\t_focusNextTab: function( index, goingForward ) {\n
\t\tindex = this._findNextTab( index, goingForward );\n
\t\tthis.tabs.eq( index ).focus();\n
\t\treturn index;\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "active" ) {\n
\t\t\t// _activate() will handle invalid values and update this.options\n
\t\t\tthis._activate( value );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( key === "disabled" ) {\n
\t\t\t// don\'t use the widget factory\'s disabled handling\n
\t\t\tthis._setupDisabled( value );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._super( key, value);\n
\n
\t\tif ( key === "collapsible" ) {\n
\t\t\tthis.element.toggleClass( "ui-tabs-collapsible", value );\n
\t\t\t// Setting collapsible: false while collapsed; open first panel\n
\t\t\tif ( !value && this.options.active === false ) {\n
\t\t\t\tthis._activate( 0 );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( key === "event" ) {\n
\t\t\tthis._setupEvents( value );\n
\t\t}\n
\n
\t\tif ( key === "heightStyle" ) {\n
\t\t\tthis._setupHeightStyle( value );\n
\t\t}\n
\t},\n
\n
\t_tabId: function( tab ) {\n
\t\treturn tab.attr( "aria-controls" ) || "ui-tabs-" + getNextTabId();\n
\t},\n
\n
\t_sanitizeSelector: function( hash ) {\n
\t\treturn hash ? hash.replace( /[!"$%&\'()*+,.\\/:;<=>?@\\[\\]\\^`{|}~]/g, "\\\\$&" ) : "";\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar options = this.options,\n
\t\t\tlis = this.tablist.children( ":has(a[href])" );\n
\n
\t\t// get disabled tabs from class attribute from HTML\n
\t\t// this will get converted to a boolean if needed in _refresh()\n
\t\toptions.disabled = $.map( lis.filter( ".ui-state-disabled" ), function( tab ) {\n
\t\t\treturn lis.index( tab );\n
\t\t});\n
\n
\t\tthis._processTabs();\n
\n
\t\t// was collapsed or no tabs\n
\t\tif ( options.active === false || !this.anchors.length ) {\n
\t\t\toptions.active = false;\n
\t\t\tthis.active = $();\n
\t\t// was active, but active tab is gone\n
\t\t} else if ( this.active.length && !$.contains( this.tablist[ 0 ], this.active[ 0 ] ) ) {\n
\t\t\t// all remaining tabs are disabled\n
\t\t\tif ( this.tabs.length === options.disabled.length ) {\n
\t\t\t\toptions.active = false;\n
\t\t\t\tthis.active = $();\n
\t\t\t// activate previous tab\n
\t\t\t} else {\n
\t\t\t\tthis._activate( this._findNextTab( Math.max( 0, options.active - 1 ), false ) );\n
\t\t\t}\n
\t\t// was active, active tab still exists\n
\t\t} else {\n
\t\t\t// make sure active index is correct\n
\t\t\toptions.active = this.tabs.index( this.active );\n
\t\t}\n
\n
\t\tthis._refresh();\n
\t},\n
\n
\t_refresh: function() {\n
\t\tthis._setupDisabled( this.options.disabled );\n
\t\tthis._setupEvents( this.options.event );\n
\t\tthis._setupHeightStyle( this.options.heightStyle );\n
\n
\t\tthis.tabs.not( this.active ).attr({\n
\t\t\t"aria-selected": "false",\n
\t\t\ttabIndex: -1\n
\t\t});\n
\t\tthis.panels.not( this._getPanelForTab( this.active ) )\n
\t\t\t.hide()\n
\t\t\t.attr({\n
\t\t\t\t"aria-expanded": "false",\n
\t\t\t\t"aria-hidden": "true"\n
\t\t\t});\n
\n
\t\t// Make sure one tab is in the tab order\n
\t\tif ( !this.active.length ) {\n
\t\t\tthis.tabs.eq( 0 ).attr( "tabIndex", 0 );\n
\t\t} else {\n
\t\t\tthis.active\n
\t\t\t\t.addClass( "ui-tabs-active ui-state-active" )\n
\t\t\t\t.attr({\n
\t\t\t\t\t"aria-selected": "true",\n
\t\t\t\t\ttabIndex: 0\n
\t\t\t\t});\n
\t\t\tthis._getPanelForTab( this.active )\n
\t\t\t\t.show()\n
\t\t\t\t.attr({\n
\t\t\t\t\t"aria-expanded": "true",\n
\t\t\t\t\t"aria-hidden": "false"\n
\t\t\t\t});\n
\t\t}\n
\t},\n
\n
\t_processTabs: function() {\n
\t\tvar that = this;\n
\n
\t\tthis.tablist = this._getList()\n
\t\t\t.addClass( "ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all" )\n
\t\t\t.attr( "role", "tablist" );\n
\n
\t\tthis.tabs = this.tablist.find( "> li:has(a[href])" )\n
\t\t\t.addClass( "ui-state-default ui-corner-top" )\n
\t\t\t.attr({\n
\t\t\t\trole: "tab",\n
\t\t\t\ttabIndex: -1\n
\t\t\t});\n
\n
\t\tthis.anchors = this.tabs.map(function() {\n
\t\t\t\treturn $( "a", this )[ 0 ];\n
\t\t\t})\n
\t\t\t.addClass( "ui-tabs-anchor" )\n
\t\t\t.attr({\n
\t\t\t\trole: "presentation",\n
\t\t\t\ttabIndex: -1\n
\t\t\t});\n
\n
\t\tthis.panels = $();\n
\n
\t\tthis.anchors.each(function( i, anchor ) {\n
\t\t\tvar selector, panel, panelId,\n
\t\t\t\tanchorId = $( anchor ).uniqueId().attr( "id" ),\n
\t\t\t\ttab = $( anchor ).closest( "li" ),\n
\t\t\t\toriginalAriaControls = tab.attr( "aria-controls" );\n
\n
\t\t\t// inline tab\n
\t\t\tif ( isLocal( anchor ) ) {\n
\t\t\t\tselector = anchor.hash;\n
\t\t\t\tpanel = that.element.find( that._sanitizeSelector( selector ) );\n
\t\t\t// remote tab\n
\t\t\t} else {\n
\t\t\t\tpanelId = that._tabId( tab );\n
\t\t\t\tselector = "#" + panelId;\n
\t\t\t\tpanel = that.element.find( selector );\n
\t\t\t\tif ( !panel.length ) {\n
\t\t\t\t\tpanel = that._createPanel( panelId );\n
\t\t\t\t\tpanel.insertAfter( that.panels[ i - 1 ] || that.tablist );\n
\t\t\t\t}\n
\t\t\t\tpanel.attr( "aria-live", "polite" );\n
\t\t\t}\n
\n
\t\t\tif ( panel.length) {\n
\t\t\t\tthat.panels = that.panels.add( panel );\n
\t\t\t}\n
\t\t\tif ( originalAriaControls ) {\n
\t\t\t\ttab.data( "ui-tabs-aria-controls", originalAriaControls );\n
\t\t\t}\n
\t\t\ttab.attr({\n
\t\t\t\t"aria-controls": selector.substring( 1 ),\n
\t\t\t\t"aria-labelledby": anchorId\n
\t\t\t});\n
\t\t\tpanel.attr( "aria-labelledby", anchorId );\n
\t\t});\n
\n
\t\tthis.panels\n
\t\t\t.addClass( "ui-tabs-panel ui-widget-content ui-corner-bottom" )\n
\t\t\t.attr( "role", "tabpanel" );\n
\t},\n
\n
\t// allow overriding how to find the list for rare usage scenarios (#7715)\n
\t_getList: function() {\n
\t\treturn this.tablist || this.element.find( "ol,ul" ).eq( 0 );\n
\t},\n
\n
\t_createPanel: function( id ) {\n
\t\treturn $( "<div>" )\n
\t\t\t.attr( "id", id )\n
\t\t\t.addClass( "ui-tabs-panel ui-widget-content ui-corner-bottom" )\n
\t\t\t.data( "ui-tabs-destroy", true );\n
\t},\n
\n
\t_setupDisabled: function( disabled ) {\n
\t\tif ( $.isArray( disabled ) ) {\n
\t\t\tif ( !disabled.length ) {\n
\t\t\t\tdisabled = false;\n
\t\t\t} else if ( disabled.length === this.anchors.length ) {\n
\t\t\t\tdisabled = true;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// disable tabs\n
\t\tfor ( var i = 0, li; ( li = this.tabs[ i ] ); i++ ) {\n
\t\t\tif ( disabled === true || $.inArray( i, disabled ) !== -1 ) {\n
\t\t\t\t$( li )\n
\t\t\t\t\t.addClass( "ui-state-disabled" )\n
\t\t\t\t\t.attr( "aria-disabled", "true" );\n
\t\t\t} else {\n
\t\t\t\t$( li )\n
\t\t\t\t\t.removeClass( "ui-state-disabled" )\n
\t\t\t\t\t.removeAttr( "aria-disabled" );\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.options.disabled = disabled;\n
\t},\n
\n
\t_setupEvents: function( event ) {\n
\t\tvar events = {\n
\t\t\tclick: function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t}\n
\t\t};\n
\t\tif ( event ) {\n
\t\t\t$.each( event.split(" "), function( index, eventName ) {\n
\t\t\t\tevents[ eventName ] = "_eventHandler";\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._off( this.anchors.add( this.tabs ).add( this.panels ) );\n
\t\tthis._on( this.anchors, events );\n
\t\tthis._on( this.tabs, { keydown: "_tabKeydown" } );\n
\t\tthis._on( this.panels, { keydown: "_panelKeydown" } );\n
\n
\t\tthis._focusable( this.tabs );\n
\t\tthis._hoverable( this.tabs );\n
\t},\n
\n
\t_setupHeightStyle: function( heightStyle ) {\n
\t\tvar maxHeight,\n
\t\t\tparent = this.element.parent();\n
\n
\t\tif ( heightStyle === "fill" ) {\n
\t\t\tmaxHeight = parent.height();\n
\t\t\tmaxHeight -= this.element.outerHeight() - this.element.height();\n
\n
\t\t\tthis.element.siblings( ":visible" ).each(function() {\n
\t\t\t\tvar elem = $( this ),\n
\t\t\t\t\tposition = elem.css( "position" );\n
\n
\t\t\t\tif ( position === "absolute" || position === "fixed" ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tmaxHeight -= elem.outerHeight( true );\n
\t\t\t});\n
\n
\t\t\tthis.element.children().not( this.panels ).each(function() {\n
\t\t\t\tmaxHeight -= $( this ).outerHeight( true );\n
\t\t\t});\n
\n
\t\t\tthis.panels.each(function() {\n
\t\t\t\t$( this ).height( Math.max( 0, maxHeight -\n
\t\t\t\t\t$( this ).innerHeight() + $( this ).height() ) );\n
\t\t\t})\n
\t\t\t.css( "overflow", "auto" );\n
\t\t} else if ( heightStyle === "auto" ) {\n
\t\t\tmaxHeight = 0;\n
\t\t\tthis.panels.each(function() {\n
\t\t\t\tmaxHeight = Math.max( maxHeight, $( this ).height( "" ).height() );\n
\t\t\t}).height( maxHeight );\n
\t\t}\n
\t},\n
\n
\t_eventHandler: function( event ) {\n
\t\tvar options = this.options,\n
\t\t\tactive = this.active,\n
\t\t\tanchor = $( event.currentTarget ),\n
\t\t\ttab = anchor.closest( "li" ),\n
\t\t\tclickedIsActive = tab[ 0 ] === active[ 0 ],\n
\t\t\tcollapsing = clickedIsActive && options.collapsible,\n
\t\t\ttoShow = collapsing ? $() : this._getPanelForTab( tab ),\n
\t\t\ttoHide = !active.length ? $() : this._getPanelForTab( active ),\n
\t\t\teventData = {\n
\t\t\t\toldTab: active,\n
\t\t\t\toldPanel: toHide,\n
\t\t\t\tnewTab: collapsing ? $() : tab,\n
\t\t\t\tnewPanel: toShow\n
\t\t\t};\n
\n
\t\tevent.preventDefault();\n
\n
\t\tif ( tab.hasClass( "ui-state-disabled" ) ||\n
\t\t\t\t// tab is already loading\n
\t\t\t\ttab.hasClass( "ui-tabs-loading" ) ||\n
\t\t\t\t// can\'t switch durning an animation\n
\t\t\t\tthis.running ||\n
\t\t\t\t// click on active header, but not collapsible\n
\t\t\t\t( clickedIsActive && !options.collapsible ) ||\n
\t\t\t\t// allow canceling activation\n
\t\t\t\t( this._trigger( "beforeActivate", event, eventData ) === false ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\toptions.active = collapsing ? false : this.tabs.index( tab );\n
\n
\t\tthis.active = clickedIsActive ? $() : tab;\n
\t\tif ( this.xhr ) {\n
\t\t\tthis.xhr.abort();\n
\t\t}\n
\n
\t\tif ( !toHide.length && !toShow.length ) {\n
\t\t\t$.error( "jQuery UI Tabs: Mismatching fragment identifier." );\n
\t\t}\n
\n
\t\tif ( toShow.length ) {\n
\t\t\tthis.load( this.tabs.index( tab ), event );\n
\t\t}\n
\t\tthis._toggle( event, eventData );\n
\t},\n
\n
\t// handles show/hide for selecting tabs\n
\t_toggle: function( event, eventData ) {\n
\t\tvar that = this,\n
\t\t\ttoShow = eventData.newPanel,\n
\t\t\ttoHide = eventData.oldPanel;\n
\n
\t\tthis.running = true;\n
\n
\t\tfunction complete() {\n
\t\t\tthat.running = false;\n
\t\t\tthat._trigger( "activate", event, eventData );\n
\t\t}\n
\n
\t\tfunction show() {\n
\t\t\teventData.newTab.closest( "li" ).addClass( "ui-tabs-active ui-state-active" );\n
\n
\t\t\tif ( toShow.length && that.options.show ) {\n
\t\t\t\tthat._show( toShow, that.options.show, complete );\n
\t\t\t} else {\n
\t\t\t\ttoShow.show();\n
\t\t\t\tcomplete();\n
\t\t\t}\n
\t\t}\n
\n
\t\t// start out by hiding, then showing, then completing\n
\t\tif ( toHide.length && this.options.hide ) {\n
\t\t\tthis._hide( toHide, this.options.hide, function() {\n
\t\t\t\teventData.oldTab.closest( "li" ).removeClass( "ui-tabs-active ui-state-active" );\n
\t\t\t\tshow();\n
\t\t\t});\n
\t\t} else {\n
\t\t\teventData.oldTab.closest( "li" ).removeClass( "ui-tabs-active ui-state-active" );\n
\t\t\ttoHide.hide();\n
\t\t\tshow();\n
\t\t}\n
\n
\t\ttoHide.attr({\n
\t\t\t"aria-expanded": "false",\n
\t\t\t"aria-hidden": "true"\n
\t\t});\n
\t\teventData.oldTab.attr( "aria-selected", "false" );\n
\t\t// If we\'re switching tabs, remove the old tab from the tab order.\n
\t\t// If we\'re opening from collapsed state, remove the previous tab from the tab order.\n
\t\t// If we\'re collapsing, then keep the collapsing tab in the tab order.\n
\t\tif ( toShow.length && toHide.length ) {\n
\t\t\teventData.oldTab.attr( "tabIndex", -1 );\n
\t\t} else if ( toShow.length ) {\n
\t\t\tthis.tabs.filter(function() {\n
\t\t\t\treturn $( this ).attr( "tabIndex" ) === 0;\n
\t\t\t})\n
\t\t\t.attr( "tabIndex", -1 );\n
\t\t}\n
\n
\t\ttoShow.attr({\n
\t\t\t"aria-expanded": "true",\n
\t\t\t"aria-hidden": "false"\n
\t\t});\n
\t\teventData.newTab.attr({\n
\t\t\t"aria-selected": "true",\n
\t\t\ttabIndex: 0\n
\t\t});\n
\t},\n
\n
\t_activate: function( index ) {\n
\t\tvar anchor,\n
\t\t\tactive = this._findActive( index );\n
\n
\t\t// trying to activate the already active panel\n
\t\tif ( active[ 0 ] === this.active[ 0 ] ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// trying to collapse, simulate a click on the current active header\n
\t\tif ( !active.length ) {\n
\t\t\tactive = this.active;\n
\t\t}\n
\n
\t\tanchor = active.find( ".ui-tabs-anchor" )[ 0 ];\n
\t\tthis._eventHandler({\n
\t\t\ttarget: anchor,\n
\t\t\tcurrentTarget: anchor,\n
\t\t\tpreventDefault: $.noop\n
\t\t});\n
\t},\n
\n
\t_findActive: function( index ) {\n
\t\treturn index === false ? $() : this.tabs.eq( index );\n
\t},\n
\n
\t_getIndex: function( index ) {\n
\t\t// meta-function to give users option to provide a href string instead of a numerical index.\n
\t\tif ( typeof index === "string" ) {\n
\t\t\tindex = this.anchors.index( this.anchors.filter( "[href$=\'" + index + "\']" ) );\n
\t\t}\n
\n
\t\treturn index;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tif ( this.xhr ) {\n
\t\t\tthis.xhr.abort();\n
\t\t}\n
\n
\t\tthis.element.removeClass( "ui-tabs ui-widget ui-widget-content ui-corner-all ui-tabs-collapsible" );\n
\n
\t\tthis.tablist\n
\t\t\t.removeClass( "ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all" )\n
\t\t\t.removeAttr( "role" );\n
\n
\t\tthis.anchors\n
\t\t\t.removeClass( "ui-tabs-anchor" )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "tabIndex" )\n
\t\t\t.removeUniqueId();\n
\n
\t\tthis.tabs.add( this.panels ).each(function() {\n
\t\t\tif ( $.data( this, "ui-tabs-destroy" ) ) {\n
\t\t\t\t$( this ).remove();\n
\t\t\t} else {\n
\t\t\t\t$( this )\n
\t\t\t\t\t.removeClass( "ui-state-default ui-state-active ui-state-disabled " +\n
\t\t\t\t\t\t"ui-corner-top ui-corner-bottom ui-widget-content ui-tabs-active ui-tabs-panel" )\n
\t\t\t\t\t.removeAttr( "tabIndex" )\n
\t\t\t\t\t.removeAttr( "aria-live" )\n
\t\t\t\t\t.removeAttr( "aria-busy" )\n
\t\t\t\t\t.removeAttr( "aria-selected" )\n
\t\t\t\t\t.removeAttr( "aria-labelledby" )\n
\t\t\t\t\t.removeAttr( "aria-hidden" )\n
\t\t\t\t\t.removeAttr( "aria-expanded" )\n
\t\t\t\t\t.removeAttr( "role" );\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis.tabs.each(function() {\n
\t\t\tvar li = $( this ),\n
\t\t\t\tprev = li.data( "ui-tabs-aria-controls" );\n
\t\t\tif ( prev ) {\n
\t\t\t\tli\n
\t\t\t\t\t.attr( "aria-controls", prev )\n
\t\t\t\t\t.removeData( "ui-tabs-aria-controls" );\n
\t\t\t} else {\n
\t\t\t\tli.removeAttr( "aria-controls" );\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis.panels.show();\n
\n
\t\tif ( this.options.heightStyle !== "content" ) {\n
\t\t\tthis.panels.css( "height", "" );\n
\t\t}\n
\t},\n
\n
\tenable: function( index ) {\n
\t\tvar disabled = this.options.disabled;\n
\t\tif ( disabled === false ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( index === undefined ) {\n
\t\t\tdisabled = false;\n
\t\t} else {\n
\t\t\tindex = this._getIndex( index );\n
\t\t\tif ( $.isArray( disabled ) ) {\n
\t\t\t\tdisabled = $.map( disabled, function( num ) {\n
\t\t\t\t\treturn num !== index ? num : null;\n
\t\t\t\t});\n
\t\t\t} else {\n
\t\t\t\tdisabled = $.map( this.tabs, function( li, num ) {\n
\t\t\t\t\treturn num !== index ? num : null;\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\t\tthis._setupDisabled( disabled );\n
\t},\n
\n
\tdisable: function( index ) {\n
\t\tvar disabled = this.options.disabled;\n
\t\tif ( disabled === true ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( index === undefined ) {\n
\t\t\tdisabled = true;\n
\t\t} else {\n
\t\t\tindex = this._getIndex( index );\n
\t\t\tif ( $.inArray( index, disabled ) !== -1 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( $.isArray( disabled ) ) {\n
\t\t\t\tdisabled = $.merge( [ index ], disabled ).sort();\n
\t\t\t} else {\n
\t\t\t\tdisabled = [ index ];\n
\t\t\t}\n
\t\t}\n
\t\tthis._setupDisabled( disabled );\n
\t},\n
\n
\tload: function( index, event ) {\n
\t\tindex = this._getIndex( index );\n
\t\tvar that = this,\n
\t\t\ttab = this.tabs.eq( index ),\n
\t\t\tanchor = tab.find( ".ui-tabs-anchor" ),\n
\t\t\tpanel = this._getPanelForTab( tab ),\n
\t\t\teventData = {\n
\t\t\t\ttab: tab,\n
\t\t\t\tpanel: panel\n
\t\t\t};\n
\n
\t\t// not remote\n
\t\tif ( isLocal( anchor[ 0 ] ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.xhr = $.ajax( this._ajaxSettings( anchor, event, eventData ) );\n
\n
\t\t// support: jQuery <1.8\n
\t\t// jQuery <1.8 returns false if the request is canceled in beforeSend,\n
\t\t// but as of 1.8, $.ajax() always returns a jqXHR object.\n
\t\tif ( this.xhr && this.xhr.statusText !== "canceled" ) {\n
\t\t\ttab.addClass( "ui-tabs-loading" );\n
\t\t\tpanel.attr( "aria-busy", "true" );\n
\n
\t\t\tthis.xhr\n
\t\t\t\t.success(function( response ) {\n
\t\t\t\t\t// support: jQuery <1.8\n
\t\t\t\t\t// http://bugs.jquery.com/ticket/11778\n
\t\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t\tpanel.html( response );\n
\t\t\t\t\t\tthat._trigger( "load", event, eventData );\n
\t\t\t\t\t}, 1 );\n
\t\t\t\t})\n
\t\t\t\t.complete(function( jqXHR, status ) {\n
\t\t\t\t\t// support: jQuery <1.8\n
\t\t\t\t\t// http://bugs.jquery.com/ticket/11778\n
\t\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t\tif ( status === "abort" ) {\n
\t\t\t\t\t\t\tthat.panels.stop( false, true );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\ttab.removeClass( "ui-tabs-loading" );\n
\t\t\t\t\t\tpanel.removeAttr( "aria-busy" );\n
\n
\t\t\t\t\t\tif ( jqXHR === that.xhr ) {\n
\t\t\t\t\t\t\tdelete that.xhr;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}, 1 );\n
\t\t\t\t});\n
\t\t}\n
\t},\n
\n
\t_ajaxSettings: function( anchor, event, eventData ) {\n
\t\tvar that = this;\n
\t\treturn {\n
\t\t\turl: anchor.attr( "href" ),\n
\t\t\tbeforeSend: function( jqXHR, settings ) {\n
\t\t\t\treturn that._trigger( "beforeLoad", event,\n
\t\t\t\t\t$.extend( { jqXHR : jqXHR, ajaxSettings: settings }, eventData ) );\n
\t\t\t}\n
\t\t};\n
\t},\n
\n
\t_getPanelForTab: function( tab ) {\n
\t\tvar id = $( tab ).attr( "aria-controls" );\n
\t\treturn this.element.find( this._sanitizeSelector( "#" + id ) );\n
\t}\n
});\n
\n
})( jQuery );\n
(function( $ ) {\n
\n
var increments = 0;\n
\n
function addDescribedBy( elem, id ) {\n
\tvar describedby = (elem.attr( "aria-describedby" ) || "").split( /\\s+/ );\n
\tdescribedby.push( id );\n
\telem\n
\t\t.data( "ui-tooltip-id", id )\n
\t\t.attr( "aria-describedby", $.trim( describedby.join( " " ) ) );\n
}\n
\n
function removeDescribedBy( elem ) {\n
\tvar id = elem.data( "ui-tooltip-id" ),\n
\t\tdescribedby = (elem.attr( "aria-describedby" ) || "").split( /\\s+/ ),\n
\t\tindex = $.inArray( id, describedby );\n
\tif ( index !== -1 ) {\n
\t\tdescribedby.splice( index, 1 );\n
\t}\n
\n
\telem.removeData( "ui-tooltip-id" );\n
\tdescribedby = $.trim( describedby.join( " " ) );\n
\tif ( describedby ) {\n
\t\telem.attr( "aria-describedby", describedby );\n
\t} else {\n
\t\telem.removeAttr( "aria-describedby" );\n
\t}\n
}\n
\n
$.widget( "ui.tooltip", {\n
\tversion: "1.10.4",\n
\toptions: {\n
\t\tcontent: function() {\n
\t\t\t// support: IE<9, Opera in jQuery <1.7\n
\t\t\t// .text() can\'t accept undefined, so coerce to a string\n
\t\t\tvar title = $( this ).attr( "title" ) || "";\n
\t\t\t// Escape title, since we\'re going from an attribute to raw HTML\n
\t\t\treturn $( "<a>" ).text( title ).html();\n
\t\t},\n
\t\thide: true,\n
\t\t// Disabled elements have inconsistent behavior across browsers (#8661)\n
\t\titems: "[title]:not([disabled])",\n
\t\tposition: {\n
\t\t\tmy: "left top+15",\n
\t\t\tat: "left bottom",\n
\t\t\tcollision: "flipfit flip"\n
\t\t},\n
\t\tshow: true,\n
\t\ttooltipClass: null,\n
\t\ttrack: false,\n
\n
\t\t// callbacks\n
\t\tclose: null,\n
\t\topen: null\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._on({\n
\t\t\tmouseover: "open",\n
\t\t\tfocusin: "open"\n
\t\t});\n
\n
\t\t// IDs of generated tooltips, needed for destroy\n
\t\tthis.tooltips = {};\n
\t\t// IDs of parent tooltips where we removed the title attribute\n
\t\tthis.parents = {};\n
\n
\t\tif ( this.options.disabled ) {\n
\t\t\tthis._disable();\n
\t\t}\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tvar that = this;\n
\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis[ value ? "_disable" : "_enable" ]();\n
\t\t\tthis.options[ key ] = value;\n
\t\t\t// disable element style changes\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._super( key, value );\n
\n
\t\tif ( key === "content" ) {\n
\t\t\t$.each( this.tooltips, function( id, element ) {\n
\t\t\t\tthat._updateContent( element );\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\t_disable: function() {\n
\t\tvar that = this;\n
\n
\t\t// close open tooltips\n
\t\t$.each( this.tooltips, function( id, element ) {\n
\t\t\tvar event = $.Event( "blur" );\n
\t\t\tevent.target = event.currentTarget = element[0];\n
\t\t\tthat.close( event, true );\n
\t\t});\n
\n
\t\t// remove title attributes to prevent native tooltips\n
\t\tthis.element.find( this.options.items ).addBack().each(function() {\n
\t\t\tvar element = $( this );\n
\t\t\tif ( element.is( "[title]" ) ) {\n
\t\t\t\telement\n
\t\t\t\t\t.data( "ui-tooltip-title", element.attr( "title" ) )\n
\t\t\t\t\t.attr( "title", "" );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_enable: function() {\n
\t\t// restore title attributes\n
\t\tthis.element.find( this.options.items ).addBack().each(function() {\n
\t\t\tvar element = $( this );\n
\t\t\tif ( element.data( "ui-tooltip-title" ) ) {\n
\t\t\t\telement.attr( "title", element.data( "ui-tooltip-title" ) );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\topen: function( event ) {\n
\t\tvar that = this,\n
\t\t\ttarget = $( event ? event.target : this.element )\n
\t\t\t\t// we need closest here due to mouseover bubbling,\n
\t\t\t\t// but always pointing at the same event target\n
\t\t\t\t.closest( this.options.items );\n
\n
\t\t// No element to show a tooltip for or the tooltip is already open\n
\t\tif ( !target.length || target.data( "ui-tooltip-id" ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( target.attr( "title" ) ) {\n
\t\t\ttarget.data( "ui-tooltip-title", target.attr( "title" ) );\n
\t\t}\n
\n
\t\ttarget.data( "ui-tooltip-open", true );\n
\n
\t\t// kill parent tooltips, custom or native, for hover\n
\t\tif ( event && event.type === "mouseover" ) {\n
\t\t\ttarget.parents().each(function() {\n
\t\t\t\tvar parent = $( this ),\n
\t\t\t\t\tblurEvent;\n
\t\t\t\tif ( parent.data( "ui-tooltip-open" ) ) {\n
\t\t\t\t\tblurEvent = $.Event( "blur" );\n
\t\t\t\t\tblurEvent.target = blurEvent.currentTarget = this;\n
\t\t\t\t\tthat.close( blurEvent, true );\n
\t\t\t\t}\n
\t\t\t\tif ( parent.attr( "title" ) ) {\n
\t\t\t\t\tparent.uniqueId();\n
\t\t\t\t\tthat.parents[ this.id ] = {\n
\t\t\t\t\t\telement: this,\n
\t\t\t\t\t\ttitle: parent.attr( "title" )\n
\t\t\t\t\t};\n
\t\t\t\t\tparent.attr( "title", "" );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._updateContent( target, event );\n
\t},\n
\n
\t_updateContent: function( target, event ) {\n
\t\tvar content,\n
\t\t\tcontentOption = this.options.content,\n
\t\t\tthat = this,\n
\t\t\teventType = event ? event.type : null;\n
\n
\t\tif ( typeof contentOption === "string" ) {\n
\t\t\treturn this._open( event, target, contentOption );\n
\t\t}\n
\n
\t\tcontent = contentOption.call( target[0], function( response ) {\n
\t\t\t// ignore async response if tooltip was closed already\n
\t\t\tif ( !target.data( "ui-tooltip-open" ) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\t// IE may instantly serve a cached response for ajax requests\n
\t\t\t// delay this call to _open so the other call to _open runs first\n
\t\t\tthat._delay(function() {\n
\t\t\t\t// jQuery creates a special event for focusin when it doesn\'t\n
\t\t\t\t// exist natively. To improve performance, the native event\n
\t\t\t\t// object is reused and the type is changed. Therefore, we can\'t\n
\t\t\t\t// rely on the type being correct after the event finished\n
\t\t\t\t// bubbling, so we set it back to the previous value. (#8740)\n
\t\t\t\tif ( event ) {\n
\t\t\t\t\tevent.type = eventType;\n
\t\t\t\t}\n
\t\t\t\tthis._open( event, target, response );\n
\t\t\t});\n
\t\t});\n
\t\tif ( content ) {\n
\t\t\tthis._open( event, target, content );\n
\t\t}\n
\t},\n
\n
\t_open: function( event, target, content ) {\n
\t\tvar tooltip, events, delayedShow,\n
\t\t\tpositionOption = $.extend( {}, this.options.position );\n
\n
\t\tif ( !content ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Content can be updated multiple times. If the tooltip already\n
\t\t// exists, then just update the content and bail.\n
\t\ttooltip = this._find( target );\n
\t\tif ( tooltip.length ) {\n
\t\t\ttooltip.find( ".ui-tooltip-content" ).html( content );\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// if we have a title, clear it to prevent the native tooltip\n
\t\t// we have to check first to avoid defining a title if none exists\n
\t\t// (we don\'t want to cause an element to start matching [title])\n
\t\t//\n
\t\t// We use removeAttr only for key events, to allow IE to export the correct\n
\t\t// accessible attributes. For mouse events, set to empty string to avoid\n
\t\t// native tooltip showing up (happens only when removing inside mouseover).\n
\t\tif ( target.is( "[title]" ) ) {\n
\t\t\tif ( event && event.type === "mouseover" ) {\n
\t\t\t\ttarget.attr( "title", "" );\n
\t\t\t} else {\n
\t\t\t\ttarget.removeAttr( "title" );\n
\t\t\t}\n
\t\t}\n
\n
\t\ttooltip = this._tooltip( target );\n
\t\taddDescribedBy( target, tooltip.attr( "id" ) );\n
\t\ttooltip.find( ".ui-tooltip-content" ).html( content );\n
\n
\t\tfunction position( event ) {\n
\t\t\tpositionOption.of = event;\n
\t\t\tif ( tooltip.is( ":hidden" ) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\ttooltip.position( positionOption );\n
\t\t}\n
\t\tif ( this.options.track && event && /^mouse/.test( event.type ) ) {\n
\t\t\tthis._on( this.document, {\n
\t\t\t\tmousemove: position\n
\t\t\t});\n
\t\t\t// trigger once to override element-relative positioning\n
\t\t\tposition( event );\n
\t\t} else {\n
\t\t\ttooltip.position( $.extend({\n
\t\t\t\tof: target\n
\t\t\t}, this.options.position ) );\n
\t\t}\n
\n
\t\ttooltip.hide();\n
\n
\t\tthis._show( tooltip, this.options.show );\n
\t\t// Handle tracking tooltips that are shown with a delay (#8644). As soon\n
\t\t// as the tooltip is visible, position the tooltip using the most recent\n
\t\t// event.\n
\t\tif ( this.options.show && this.options.show.delay ) {\n
\t\t\tdelayedShow = this.delayedShow = setInterval(function() {\n
\t\t\t\tif ( tooltip.is( ":visible" ) ) {\n
\t\t\t\t\tposition( positionOption.of );\n
\t\t\t\t\tclearInterval( delayedShow );\n
\t\t\t\t}\n
\t\t\t}, $.fx.interval );\n
\t\t}\n
\n
\t\tthis._trigger( "open", event, { tooltip: tooltip } );\n
\n
\t\tevents = {\n
\t\t\tkeyup: function( event ) {\n
\t\t\t\tif ( event.keyCode === $.ui.keyCode.ESCAPE ) {\n
\t\t\t\t\tvar fakeEvent = $.Event(event);\n
\t\t\t\t\tfakeEvent.currentTarget = target[0];\n
\t\t\t\t\tthis.close( fakeEvent, true );\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tremove: function() {\n
\t\t\t\tthis._removeTooltip( tooltip );\n
\t\t\t}\n
\t\t};\n
\t\tif ( !event || event.type === "mouseover" ) {\n
\t\t\tevents.mouseleave = "close";\n
\t\t}\n
\t\tif ( !event || event.type === "focusin" ) {\n
\t\t\tevents.focusout = "close";\n
\t\t}\n
\t\tthis._on( true, target, events );\n
\t},\n
\n
\tclose: function( event ) {\n
\t\tvar that = this,\n
\t\t\ttarget = $( event ? event.currentTarget : this.element ),\n
\t\t\ttooltip = this._find( target );\n
\n
\t\t// disabling closes the tooltip, so we need to track when we\'re closing\n
\t\t// to avoid an infinite loop in case the tooltip becomes disabled on close\n
\t\tif ( this.closing ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Clear the interval for delayed tracking tooltips\n
\t\tclearInterval( this.delayedShow );\n
\n
\t\t// only set title if we had one before (see comment in _open())\n
\t\tif ( target.data( "ui-tooltip-title" ) ) {\n
\t\t\ttarget.attr( "title", target.data( "ui-tooltip-title" ) );\n
\t\t}\n
\n
\t\tremoveDescribedBy( target );\n
\n
\t\ttooltip.stop( true );\n
\t\tthis._hide( tooltip, this.options.hide, function() {\n
\t\t\tthat._removeTooltip( $( this ) );\n
\t\t});\n
\n
\t\ttarget.removeData( "ui-tooltip-open" );\n
\t\tthis._off( target, "mouseleave focusout keyup" );\n
\t\t// Remove \'remove\' binding only on delegated targets\n
\t\tif ( target[0] !== this.element[0] ) {\n
\t\t\tthis._off( target, "remove" );\n
\t\t}\n
\t\tthis._off( this.document, "mousemove" );\n
\n
\t\tif ( event && event.type === "mouseleave" ) {\n
\t\t\t$.each( this.parents, function( id, parent ) {\n
\t\t\t\t$( parent.element ).attr( "title", parent.title );\n
\t\t\t\tdelete that.parents[ id ];\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis.closing = true;\n
\t\tthis._trigger( "close", event, { tooltip: tooltip } );\n
\t\tthis.closing = false;\n
\t},\n
\n
\t_tooltip: function( element ) {\n
\t\tvar id = "ui-tooltip-" + increments++,\n
\t\t\ttooltip = $( "<div>" )\n
\t\t\t\t.attr({\n
\t\t\t\t\tid: id,\n
\t\t\t\t\trole: "tooltip"\n
\t\t\t\t})\n
\t\t\t\t.addClass( "ui-tooltip ui-widget ui-corner-all ui-widget-content " +\n
\t\t\t\t\t( this.options.tooltipClass || "" ) );\n
\t\t$( "<div>" )\n
\t\t\t.addClass( "ui-tooltip-content" )\n
\t\t\t.appendTo( tooltip );\n
\t\ttooltip.appendTo( this.document[0].body );\n
\t\tthis.tooltips[ id ] = element;\n
\t\treturn tooltip;\n
\t},\n
\n
\t_find: function( target ) {\n
\t\tvar id = target.data( "ui-tooltip-id" );\n
\t\treturn id ? $( "#" + id ) : $();\n
\t},\n
\n
\t_removeTooltip: function( tooltip ) {\n
\t\ttooltip.remove();\n
\t\tdelete this.tooltips[ tooltip.attr( "id" ) ];\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar that = this;\n
\n
\t\t// close open tooltips\n
\t\t$.each( this.tooltips, function( id, element ) {\n
\t\t\t// Delegate to close method to handle common cleanup\n
\t\t\tvar event = $.Event( "blur" );\n
\t\t\tevent.target = event.currentTarget = element[0];\n
\t\t\tthat.close( event, true );\n
\n
\t\t\t// Remove immediately; destroying an open tooltip doesn\'t use the\n
\t\t\t// hide animation\n
\t\t\t$( "#" + id ).remove();\n
\n
\t\t\t// Restore the title\n
\t\t\tif ( element.data( "ui-tooltip-title" ) ) {\n
\t\t\t\telement.attr( "title", element.data( "ui-tooltip-title" ) );\n
\t\t\t\telement.removeData( "ui-tooltip-title" );\n
\t\t\t}\n
\t\t});\n
\t}\n
});\n
\n
}( jQuery ) );\n
(function($, undefined) {\n
\n
var dataSpace = "ui-effects-";\n
\n
$.effects = {\n
\teffect: {}\n
};\n
\n
/*!\n
 * jQuery Color Animations v2.1.2\n
 * https://github.com/jquery/jquery-color\n
 *\n
 * Copyright 2013 jQuery Foundation and other contributors\n
 * Released under the MIT license.\n
 * http://jquery.org/license\n
 *\n
 * Date: Wed Jan 16 08:47:09 2013 -0600\n
 */\n
(function( jQuery, undefined ) {\n
\n
\tvar stepHooks = "backgroundColor borderBottomColor borderLeftColor borderRightColor borderTopColor color columnRuleColor outlineColor textDecorationColor textEmphasisColor",\n
\n
\t// plusequals test for += 100 -= 100\n
\trplusequals = /^([\\-+])=\\s*(\\d+\\.?\\d*)/,\n
\t// a set of RE\'s that can match strings and generate color tuples.\n
\tstringParsers = [{\n
\t\t\tre: /rgba?\\(\\s*(\\d{1,3})\\s*,\\s*(\\d{1,3})\\s*,\\s*(\\d{1,3})\\s*(?:,\\s*(\\d?(?:\\.\\d+)?)\\s*)?\\)/,\n
\t\t\tparse: function( execResult ) {\n
\t\t\t\treturn [\n
\t\t\t\t\texecResult[ 1 ],\n
\t\t\t\t\texecResult[ 2 ],\n
\t\t\t\t\texecResult[ 3 ],\n
\t\t\t\t\texecResult[ 4 ]\n
\t\t\t\t];\n
\t\t\t}\n
\t\t}, {\n
\t\t\tre: /rgba?\\(\\s*(\\d+(?:\\.\\d+)?)\\%\\s*,\\s*(\\d+(?:\\.\\d+)?)\\%\\s*,\\s*(\\d+(?:\\.\\d+)?)\\%\\s*(?:,\\s*(\\d?(?:\\.\\d+)?)\\s*)?\\)/,\n
\t\t\tparse: function( execResult ) {\n
\t\t\t\treturn [\n
\t\t\t\t\texecResult[ 1 ] * 2.55,\n
\t\t\t\t\texecResult[ 2 ] * 2.55,\n
\t\t\t\t\texecResult[ 3 ] * 2.55,\n
\t\t\t\t\texecResult[ 4 ]\n
\t\t\t\t];\n
\t\t\t}\n
\t\t}, {\n
\t\t\t// this regex ignores A-F because it\'s compared against an already lowercased string\n
\t\t\tre: /#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})/,\n
\t\t\tparse: function( execResult ) {\n
\t\t\t\treturn [\n
\t\t\t\t\tparseInt( execResult[ 1 ], 16 ),\n
\t\t\t\t\tparseInt( execResult[ 2 ], 16 ),\n
\t\t\t\t\tparseInt( execResult[ 3 ], 16 )\n
\t\t\t\t];\n
\t\t\t}\n
\t\t}, {\n
\t\t\t// this regex ignores A-F because it\'s compared against an already lowercased string\n
\t\t\tre: /#([a-f0-9])([a-f0-9])([a-f0-9])/,\n
\t\t\tparse: function( execResult ) {\n
\t\t\t\treturn [\n
\t\t\t\t\tparseInt( execResult[ 1 ] + execResult[ 1 ], 16 ),\n
\t\t\t\t\tparseInt( execResult[ 2 ] + execResult[ 2 ], 16 ),\n
\t\t\t\t\tparseInt( execResult[ 3 ] + execResult[ 3 ], 16 )\n
\t\t\t\t];\n
\t\t\t}\n
\t\t}, {\n
\t\t\tre: /hsla?\\(\\s*(\\d+(?:\\.\\d+)?)\\s*,\\s*(\\d+(?:\\.\\d+)?)\\%\\s*,\\s*(\\d+(?:\\.\\d+)?)\\%\\s*(?:,\\s*(\\d?(?:\\.\\d+)?)\\s*)?\\)/,\n
\t\t\tspace: "hsla",\n
\t\t\tparse: function( execResult ) {\n
\t\t\t\treturn [\n
\t\t\t\t\texecResult[ 1 ],\n
\t\t\t\t\texecResult[ 2 ] / 100,\n
\t\t\t\t\texecResult[ 3 ] / 100,\n
\t\t\t\t\texecResult[ 4 ]\n
\t\t\t\t];\n
\t\t\t}\n
\t\t}],\n
\n
\t// jQuery.Color( )\n
\tcolor = jQuery.Color = function( color, green, blue, alpha ) {\n
\t\treturn new jQuery.Color.fn.parse( color, green, blue, alpha );\n
\t},\n
\tspaces = {\n
\t\trgba: {\n
\t\t\tprops: {\n
\t\t\t\tred: {\n
\t\t\t\t\tidx: 0,\n
\t\t\t\t\ttype: "byte"\n
\t\t\t\t},\n
\t\t\t\tgreen: {\n
\t\t\t\t\tidx: 1,\n
\t\t\t\t\ttype: "byte"\n
\t\t\t\t},\n
\t\t\t\tblue: {\n
\t\t\t\t\tidx: 2,\n
\t\t\t\t\ttype: "byte"\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\thsla: {\n
\t\t\tprops: {\n
\t\t\t\thue: {\n
\t\t\t\t\tidx: 0,\n
\t\t\t\t\ttype: "degrees"\n
\t\t\t\t},\n
\t\t\t\tsaturation: {\n
\t\t\t\t\tidx: 1,\n
\t\t\t\t\ttype: "percent"\n
\t\t\t\t},\n
\t\t\t\tlightness: {\n
\t\t\t\t\tidx: 2,\n
\t\t\t\t\ttype: "percent"\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\tpropTypes = {\n
\t\t"byte": {\n
\t\t\tfloor: true,\n
\t\t\tmax: 255\n
\t\t},\n
\t\t"percent": {\n
\t\t\tmax: 1\n
\t\t},\n
\t\t"degrees": {\n
\t\t\tmod: 360,\n
\t\t\tfloor: true\n
\t\t}\n
\t},\n
\tsupport = color.support = {},\n
\n
\t// element for support tests\n
\tsupportElem = jQuery( "<p>" )[ 0 ],\n
\n
\t// colors = jQuery.Color.names\n
\tcolors,\n
\n
\t// local aliases of functions called often\n
\teach = jQuery.each;\n
\n
// determine rgba support immediately\n
supportElem.style.cssText = "background-color:rgba(1,1,1,.5)";\n
support.rgba = supportElem.style.backgroundColor.indexOf( "rgba" ) > -1;\n
\n
// define cache name and alpha properties\n
// for rgba and hsla spaces\n
each( spaces, function( spaceName, space ) {\n
\tspace.cache = "_" + spaceName;\n
\tspace.props.alpha = {\n
\t\tidx: 3,\n
\t\ttype: "percent",\n
\t\tdef: 1\n
\t};\n
});\n
\n
function clamp( value, prop, allowEmpty ) {\n
\tvar type = propTypes[ prop.type ] || {};\n
\n
\tif ( value == null ) {\n
\t\treturn (allowEmpty || !prop.def) ? null : prop.def;\n
\t}\n
\n
\t// ~~ is an short way of doing floor for positive numbers\n
\tvalue = type.floor ? ~~value : parseFloat( value );\n
\n
\t// IE will pass in empty strings as value for alpha,\n
\t// which will hit this case\n
\tif ( isNaN( value ) ) {\n
\t\treturn prop.def;\n
\t}\n
\n
\tif ( type.mod ) {\n
\t\t// we add mod before modding to make sure that negatives values\n
\t\t// get converted properly: -10 -> 350\n
\t\treturn (value + type.mod) % type.mod;\n
\t}\n
\n
\t// for now all property types without mod have min and max\n
\treturn 0 > value ? 0 : type.max < value ? type.max : value;\n
}\n
\n
function stringParse( string ) {\n
\tvar inst = color(),\n
\t\trgba = inst._rgba = [];\n
\n
\tstring = string.toLowerCase();\n
\n
\teach( stringParsers, function( i, parser ) {\n
\t\tvar parsed,\n
\t\t\tmatch = parser.re.exec( string ),\n
\t\t\tvalues = match && parser.parse( match ),\n
\t\t\tspaceName = parser.space || "rgba";\n
\n
\t\tif ( values ) {\n
\t\t\tparsed = inst[ spaceName ]( values );\n
\n
\t\t\t// if this was an rgba parse the assignment might happen twice\n
\t\t\t// oh well....\n
\t\t\tinst[ spaces[ spaceName ].cache ] = parsed[ spaces[ spaceName ].cache ];\n
\t\t\trgba = inst._rgba = parsed._rgba;\n
\n
\t\t\t// exit each( stringParsers ) here because we matched\n
\t\t\treturn false;\n
\t\t}\n
\t});\n
\n
\t// Found a stringParser that handled it\n
\tif ( rgba.length ) {\n
\n
\t\t// if this came from a parsed string, force "transparent" when alpha is 0\n
\t\t// chrome, (and maybe others) return "transparent" as rgba(0,0,0,0)\n
\t\tif ( rgba.join() === "0,0,0,0" ) {\n
\t\t\tjQuery.extend( rgba, colors.transparent );\n
\t\t}\n
\t\treturn inst;\n
\t}\n
\n
\t// named colors\n
\treturn colors[ string ];\n
}\n
\n
color.fn = jQuery.extend( color.prototype, {\n
\tparse: function( red, green, blue, alpha ) {\n
\t\tif ( red === undefined ) {\n
\t\t\tthis._rgba = [ null, null, null, null ];\n
\t\t\treturn this;\n
\t\t}\n
\t\tif ( red.jquery || red.nodeType ) {\n
\t\t\tred = jQuery( red ).css( green );\n
\t\t\tgreen = undefined;\n
\t\t}\n
\n
\t\tvar inst = this,\n
\t\t\ttype = jQuery.type( red ),\n
\t\t\trgba = this._rgba = [];\n
\n
\t\t// more than 1 argument specified - assume ( red, green, blue, alpha )\n
\t\tif ( green !== undefined ) {\n
\t\t\tred = [ red, green, blue, alpha ];\n
\t\t\ttype = "array";\n
\t\t}\n
\n
\t\tif ( type === "string" ) {\n
\t\t\treturn this.parse( stringParse( red ) || colors._default );\n
\t\t}\n
\n
\t\tif ( type === "array" ) {\n
\t\t\teach( spaces.rgba.props, function( key, prop ) {\n
\t\t\t\trgba[ prop.idx ] = clamp( red[ prop.idx ], prop );\n
\t\t\t});\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tif ( type === "object" ) {\n
\t\t\tif ( red instanceof color ) {\n
\t\t\t\teach( spaces, function( spaceName, space ) {\n
\t\t\t\t\tif ( red[ space.cache ] ) {\n
\t\t\t\t\t\tinst[ space.cache ] = red[ space.cache ].slice();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t} else {\n
\t\t\t\teach( spaces, function( spaceName, space ) {\n
\t\t\t\t\tvar cache = space.cache;\n
\t\t\t\t\teach( space.props, function( key, prop ) {\n
\n
\t\t\t\t\t\t// if the cache doesn\'t exist, and we know how to convert\n
\t\t\t\t\t\tif ( !inst[ cache ] && space.to ) {\n
\n
\t\t\t\t\t\t\t// if the value was null, we don\'t need to copy it\n
\t\t\t\t\t\t\t// if the key was alpha, we don\'t need to copy it either\n
\t\t\t\t\t\t\tif ( key === "alpha" || red[ key ] == null ) {\n
\t\t\t\t\t\t\t\treturn;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tinst[ cache ] = space.to( inst._rgba );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// this is the only case where we allow nulls for ALL properties.\n
\t\t\t\t\t\t// call clamp with alwaysAllowEmpty\n
\t\t\t\t\t\tinst[ cache ][ prop.idx ] = clamp( red[ key ], prop, true );\n
\t\t\t\t\t});\n
\n
\t\t\t\t\t// everything defined but alpha?\n
\t\t\t\t\tif ( inst[ cache ] && jQuery.inArray( null, inst[ cache ].slice( 0, 3 ) ) < 0 ) {\n
\t\t\t\t\t\t// use the default of 1\n
\t\t\t\t\t\tinst[ cache ][ 3 ] = 1;\n
\t\t\t\t\t\tif ( space.from ) {\n
\t\t\t\t\t\t\tinst._rgba = space.from( inst[ cache ] );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t}\n
\t},\n
\tis: function( compare ) {\n
\t\tvar is = color( compare ),\n
\t\t\tsame = true,\n
\t\t\tinst = this;\n
\n
\t\teach( spaces, function( _, space ) {\n
\t\t\tvar localCache,\n
\t\t\t\tisCache = is[ space.cache ];\n
\t\t\tif (isCache) {\n
\t\t\t\tlocalCache = inst[ space.cache ] || space.to && space.to( inst._rgba ) || [];\n
\t\t\t\teach( space.props, function( _, prop ) {\n
\t\t\t\t\tif ( isCache[ prop.idx ] != null ) {\n
\t\t\t\t\t\tsame = ( isCache[ prop.idx ] === localCache[ prop.idx ] );\n
\t\t\t\t\t\treturn same;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\treturn same;\n
\t\t});\n
\t\treturn same;\n
\t},\n
\t_space: function() {\n
\t\tvar used = [],\n
\t\t\tinst = this;\n
\t\teach( spaces, function( spaceName, space ) {\n
\t\t\tif ( inst[ space.cache ] ) {\n
\t\t\t\tused.push( spaceName );\n
\t\t\t}\n
\t\t});\n
\t\treturn used.pop();\n
\t},\n
\ttransition: function( other, distance ) {\n
\t\tvar end = color( other ),\n
\t\t\tspaceName = end._space(),\n
\t\t\tspace = spaces[ spaceName ],\n
\t\t\tstartColor = this.alpha() === 0 ? color( "transparent" ) : this,\n
\t\t\tstart = startColor[ space.cache ] || space.to( startColor._rgba ),\n
\t\t\tresult = start.slice();\n
\n
\t\tend = end[ space.cache ];\n
\t\teach( space.props, function( key, prop ) {\n
\t\t\tvar index = prop.idx,\n
\t\t\t\tstartValue = start[ index ],\n
\t\t\t\tendValue = end[ index ],\n
\t\t\t\ttype = propTypes[ prop.type ] || {};\n
\n
\t\t\t// if null, don\'t override start value\n
\t\t\tif ( endValue === null ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\t// if null - use end\n
\t\t\tif ( startValue === null ) {\n
\t\t\t\tresult[ index ] = endValue;\n
\t\t\t} else {\n
\t\t\t\tif ( type.mod ) {\n
\t\t\t\t\tif ( endValue - startValue > type.mod / 2 ) {\n
\t\t\t\t\t\tstartValue += type.mod;\n
\t\t\t\t\t} else if ( startValue - endValue > type.mod / 2 ) {\n
\t\t\t\t\t\tstartValue -= type.mod;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tresult[ index ] = clamp( ( endValue - startValue ) * distance + startValue, prop );\n
\t\t\t}\n
\t\t});\n
\t\treturn this[ spaceName ]( result );\n
\t},\n
\tblend: function( opaque ) {\n
\t\t// if we are already opaque - return ourself\n
\t\tif ( this._rgba[ 3 ] === 1 ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tvar rgb = this._rgba.slice(),\n
\t\t\ta = rgb.pop(),\n
\t\t\tblend = color( opaque )._rgba;\n
\n
\t\treturn color( jQuery.map( rgb, function( v, i ) {\n
\t\t\treturn ( 1 - a ) * blend[ i ] + a * v;\n
\t\t}));\n
\t},\n
\ttoRgbaString: function() {\n
\t\tvar prefix = "rgba(",\n
\t\t\trgba = jQuery.map( this._rgba, function( v, i ) {\n
\t\t\t\treturn v == null ? ( i > 2 ? 1 : 0 ) : v;\n
\t\t\t});\n
\n
\t\tif ( rgba[ 3 ] === 1 ) {\n
\t\t\trgba.pop();\n
\t\t\tprefix = "rgb(";\n
\t\t}\n
\n
\t\treturn prefix + rgba.join() + ")";\n
\t},\n
\ttoHslaString: function() {\n
\t\tvar prefix = "hsla(",\n
\t\t\thsla = jQuery.map( this.hsla(), function( v, i ) {\n
\t\t\t\tif ( v == null ) {\n
\t\t\t\t\tv = i > 2 ? 1 : 0;\n
\t\t\t\t}\n
\n
\t\t\t\t// catch 1 and 2\n
\t\t\t\tif ( i && i < 3 ) {\n
\t\t\t\t\tv = Math.round( v * 100 ) + "%";\n
\t\t\t\t}\n
\t\t\t\treturn v;\n
\t\t\t});\n
\n
\t\tif ( hsla[ 3 ] === 1 ) {\n
\t\t\thsla.pop();\n
\t\t\tprefix = "hsl(";\n
\t\t}\n
\t\treturn prefix + hsla.join() + ")";\n
\t},\n
\ttoHexString: function( includeAlpha ) {\n
\t\tvar rgba = this._rgba.slice(),\n
\t\t\talpha = rgba.pop();\n
\n
\t\tif ( includeAlpha ) {\n
\t\t\trgba.push( ~~( alpha * 255 ) );\n
\t\t}\n
\n
\t\treturn "#" + jQuery.map( rgba, function( v ) {\n
\n
\t\t\t// default to 0 when nulls exist\n
\t\t\tv = ( v || 0 ).toString( 16 );\n
\t\t\treturn v.length === 1 ? "0" + v : v;\n
\t\t}).join("");\n
\t},\n
\ttoString: function() {\n
\t\treturn this._rgba[ 3 ] === 0 ? "transparent" : this.toRgbaString();\n
\t}\n
});\n
color.fn.parse.prototype = color.fn;\n
\n
// hsla conversions adapted from:\n
// https://code.google.com/p/maashaack/source/browse/packages/graphics/trunk/src/graphics/colors/HUE2RGB.as?r=5021\n
\n
function hue2rgb( p, q, h ) {\n
\th = ( h + 1 ) % 1;\n
\tif ( h * 6 < 1 ) {\n
\t\treturn p + (q - p) * h * 6;\n
\t}\n
\tif ( h * 2 < 1) {\n
\t\treturn q;\n
\t}\n
\tif ( h * 3 < 2 ) {\n
\t\treturn p + (q - p) * ((2/3) - h) * 6;\n
\t}\n
\treturn p;\n
}\n
\n
spaces.hsla.to = function ( rgba ) {\n
\tif ( rgba[ 0 ] == null || rgba[ 1 ] == null || rgba[ 2 ] == null ) {\n
\t\treturn [ null, null, null, rgba[ 3 ] ];\n
\t}\n
\tvar r = rgba[ 0 ] / 255,\n
\t\tg = rgba[ 1 ] / 255,\n
\t\tb = rgba[ 2 ] / 255,\n
\t\ta = rgba[ 3 ],\n
\t\tmax = Math.max( r, g, b ),\n
\t\tmin = Math.min( r, g, b ),\n
\t\tdiff = max - min,\n
\t\tadd = max + min,\n
\t\tl = add * 0.5,\n
\t\th, s;\n
\n
\tif ( min === max ) {\n
\t\th = 0;\n
\t} else if ( r === max ) {\n
\t\th = ( 60 * ( g - b ) / diff ) + 360;\n
\t} else if ( g === max ) {\n
\t\th = ( 60 * ( b - r ) / diff ) + 120;\n
\t} else {\n
\t\th = ( 60 * ( r - g ) / diff ) + 240;\n
\t}\n
\n
\t// chroma (diff) == 0 means greyscale which, by definition, saturation = 0%\n
\t// otherwise, saturation is based on the ratio of chroma (diff) to lightness (add)\n
\tif ( diff === 0 ) {\n
\t\ts = 0;\n
\t} else if ( l <= 0.5 ) {\n
\t\ts = diff / add;\n
\t} else {\n
\t\ts = diff / ( 2 - add );\n
\t}\n
\treturn [ Math.round(h) % 360, s, l, a == null ? 1 : a ];\n
};\n
\n
spaces.hsla.from = function ( hsla ) {\n
\tif ( hsla[ 0 ] == null || hsla[ 1 ] == null || hsla[ 2 ] == null ) {\n
\t\treturn [ null, null, null, hsla[ 3 ] ];\n
\t}\n
\tvar h = hsla[ 0 ] / 360,\n
\t\ts = hsla[ 1 ],\n
\t\tl = hsla[ 2 ],\n
\t\ta = hsla[ 3 ],\n
\t\tq = l <= 0.5 ? l * ( 1 + s ) : l + s - l * s,\n
\t\tp = 2 * l - q;\n
\n
\treturn [\n
\t\tMath.round( hue2rgb( p, q, h + ( 1 / 3 ) ) * 255 ),\n
\t\tMath.round( hue2rgb( p, q, h ) * 255 ),\n
\t\tMath.round( hue2rgb( p, q, h - ( 1 / 3 ) ) * 255 ),\n
\t\ta\n
\t];\n
};\n
\n
\n
each( spaces, function( spaceName, space ) {\n
\tvar props = space.props,\n
\t\tcache = space.cache,\n
\t\tto = space.to,\n
\t\tfrom = space.from;\n
\n
\t// makes rgba() and hsla()\n
\tcolor.fn[ spaceName ] = function( value ) {\n
\n
\t\t// generate a cache for this space if it doesn\'t exist\n
\t\tif ( to && !this[ cache ] ) {\n
\t\t\tthis[ cache ] = to( this._rgba );\n
\t\t}\n
\t\tif ( value === undefined ) {\n
\t\t\treturn this[ cache ].slice();\n
\t\t}\n
\n
\t\tvar ret,\n
\t\t\ttype = jQuery.type( value ),\n
\t\t\tarr = ( type === "array" || type === "object" ) ? value : arguments,\n
\t\t\tlocal = this[ cache ].slice();\n
\n
\t\teach( props, function( key, prop ) {\n
\t\t\tvar val = arr[ type === "object" ? key : prop.idx ];\n
\t\t\tif ( val == null ) {\n
\t\t\t\tval = local[ prop.idx ];\n
\t\t\t}\n
\t\t\tlocal[ prop.idx ] = clamp( val, prop );\n
\t\t});\n
\n
\t\tif ( from ) {\n
\t\t\tret = color( from( local ) );\n
\t\t\tret[ cache ] = local;\n
\t\t\treturn ret;\n
\t\t} else {\n
\t\t\treturn color( local );\n
\t\t}\n
\t};\n
\n
\t// makes red() green() blue() alpha() hue() saturation() lightness()\n
\teach( props, function( key, prop ) {\n
\t\t// alpha is included in more than one space\n
\t\tif ( color.fn[ key ] ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tcolor.fn[ key ] = function( value ) {\n
\t\t\tvar vtype = jQuery.type( value ),\n
\t\t\t\tfn = ( key === "alpha" ? ( this._hsla ? "hsla" : "rgba" ) : spaceName ),\n
\t\t\t\tlocal = this[ fn ](),\n
\t\t\t\tcur = local[ prop.idx ],\n
\t\t\t\tmatch;\n
\n
\t\t\tif ( vtype === "undefined" ) {\n
\t\t\t\treturn cur;\n
\t\t\t}\n
\n
\t\t\tif ( vtype === "function" ) {\n
\t\t\t\tvalue = value.call( this, cur );\n
\t\t\t\tvtype = jQuery.type( value );\n
\t\t\t}\n
\t\t\tif ( value == null && prop.empty ) {\n
\t\t\t\treturn this;\n
\t\t\t}\n
\t\t\tif ( vtype === "string" ) {\n
\t\t\t\tmatch = rplusequals.exec( value );\n
\t\t\t\tif ( match ) {\n
\t\t\t\t\tvalue = cur + parseFloat( match[ 2 ] ) * ( match[ 1 ] === "+" ? 1 : -1 );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tlocal[ prop.idx ] = value;\n
\t\t\treturn this[ fn ]( local );\n
\t\t};\n
\t});\n
});\n
\n
// add cssHook and .fx.step function for each named hook.\n
// accept a space separated string of properties\n
color.hook = function( hook ) {\n
\tvar hooks = hook.split( " " );\n
\teach( hooks, function( i, hook ) {\n
\t\tjQuery.cssHooks[ hook ] = {\n
\t\t\tset: function( elem, value ) {\n
\t\t\t\tvar parsed, curElem,\n
\t\t\t\t\tbackgroundColor = "";\n
\n
\t\t\t\tif ( value !== "transparent" && ( jQuery.type( value ) !== "string" || ( parsed = stringParse( value ) ) ) ) {\n
\t\t\t\t\tvalue = color( parsed || value );\n
\t\t\t\t\tif ( !support.rgba && value._rgba[ 3 ] !== 1 ) {\n
\t\t\t\t\t\tcurElem = hook === "backgroundColor" ? elem.parentNode : elem;\n
\t\t\t\t\t\twhile (\n
\t\t\t\t\t\t\t(backgroundColor === "" || backgroundColor === "transparent") &&\n
\t\t\t\t\t\t\tcurElem && curElem.style\n
\t\t\t\t\t\t) {\n
\t\t\t\t\t\t\ttry {\n
\t\t\t\t\t\t\t\tbackgroundColor = jQuery.css( curElem, "backgroundColor" );\n
\t\t\t\t\t\t\t\tcurElem = curElem.parentNode;\n
\t\t\t\t\t\t\t} catch ( e ) {\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tvalue = value.blend( backgroundColor && backgroundColor !== "transparent" ?\n
\t\t\t\t\t\t\tbackgroundColor :\n
\t\t\t\t\t\t\t"_default" );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tvalue = value.toRgbaString();\n
\t\t\t\t}\n
\t\t\t\ttry {\n
\t\t\t\t\telem.style[ hook ] = value;\n
\t\t\t\t} catch( e ) {\n
\t\t\t\t\t// wrapped to prevent IE from throwing errors on "invalid" values like \'auto\' or \'inherit\'\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\t\tjQuery.fx.step[ hook ] = function( fx ) {\n
\t\t\tif ( !fx.colorInit ) {\n
\t\t\t\tfx.start = color( fx.elem, hook );\n
\t\t\t\tfx.end = color( fx.end );\n
\t\t\t\tfx.colorInit = true;\n
\t\t\t}\n
\t\t\tjQuery.cssHooks[ hook ].set( fx.elem, fx.start.transition( fx.end, fx.pos ) );\n
\t\t};\n
\t});\n
\n
};\n
\n
color.hook( stepHooks );\n
\n
jQuery.cssHooks.borderColor = {\n
\texpand: function( value ) {\n
\t\tvar expanded = {};\n
\n
\t\teach( [ "Top", "Right", "Bottom", "Left" ], function( i, part ) {\n
\t\t\texpanded[ "border" + part + "Color" ] = value;\n
\t\t});\n
\t\treturn expanded;\n
\t}\n
};\n
\n
// Basic color names only.\n
// Usage of any of the other color names requires adding yourself or including\n
// jquery.color.svg-names.js.\n
colors = jQuery.Color.names = {\n
\t// 4.1. Basic color keywords\n
\taqua: "#00ffff",\n
\tblack: "#000000",\n
\tblue: "#0000ff",\n
\tfuchsia: "#ff00ff",\n
\tgray: "#808080",\n
\tgreen: "#008000",\n
\tlime: "#00ff00",\n
\tmaroon: "#800000",\n
\tnavy: "#000080",\n
\tolive: "#808000",\n
\tpurple: "#800080",\n
\tred: "#ff0000",\n
\tsilver: "#c0c0c0",\n
\tteal: "#008080",\n
\twhite: "#ffffff",\n
\tyellow: "#ffff00",\n
\n
\t// 4.2.3. "transparent" color keyword\n
\ttransparent: [ null, null, null, 0 ],\n
\n
\t_default: "#ffffff"\n
};\n
\n
})( jQuery );\n
\n
\n
/******************************************************************************/\n
/****************************** CLASS ANIMATIONS ******************************/\n
/******************************************************************************/\n
(function() {\n
\n
var classAnimationActions = [ "add", "remove", "toggle" ],\n
\tshorthandStyles = {\n
\t\tborder: 1,\n
\t\tborderBottom: 1,\n
\t\tborderColor: 1,\n
\t\tborderLeft: 1,\n
\t\tborderRight: 1,\n
\t\tborderTop: 1,\n
\t\tborderWidth: 1,\n
\t\tmargin: 1,\n
\t\tpadding: 1\n
\t};\n
\n
$.each([ "borderLeftStyle", "borderRightStyle", "borderBottomStyle", "borderTopStyle" ], function( _, prop ) {\n
\t$.fx.step[ prop ] = function( fx ) {\n
\t\tif ( fx.end !== "none" && !fx.setAttr || fx.pos === 1 && !fx.setAttr ) {\n
\t\t\tjQuery.style( fx.elem, prop, fx.end );\n
\t\t\tfx.setAttr = true;\n
\t\t}\n
\t};\n
});\n
\n
function getElementStyles( elem ) {\n
\tvar key, len,\n
\t\tstyle = elem.ownerDocument.defaultView ?\n
\t\t\telem.ownerDocument.defaultView.getComputedStyle( elem, null ) :\n
\t\t\telem.currentStyle,\n
\t\tstyles = {};\n
\n
\tif ( style && style.length && style[ 0 ] && style[ style[ 0 ] ] ) {\n
\t\tlen = style.length;\n
\t\twhile ( len-- ) {\n
\t\t\tkey = style[ len ];\n
\t\t\tif ( typeof style[ key ] === "string" ) {\n
\t\t\t\tstyles[ $.camelCase( key ) ] = style[ key ];\n
\t\t\t}\n
\t\t}\n
\t// support: Opera, IE <9\n
\t} else {\n
\t\tfor ( key in style ) {\n
\t\t\tif ( typeof style[ key ] === "string" ) {\n
\t\t\t\tstyles[ key ] = style[ key ];\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn styles;\n
}\n
\n
\n
function styleDifference( oldStyle, newStyle ) {\n
\tvar diff = {},\n
\t\tname, value;\n
\n
\tfor ( name in newStyle ) {\n
\t\tvalue = newStyle[ name ];\n
\t\tif ( oldStyle[ name ] !== value ) {\n
\t\t\tif ( !shorthandStyles[ name ] ) {\n
\t\t\t\tif ( $.fx.step[ name ] || !isNaN( parseFloat( value ) ) ) {\n
\t\t\t\t\tdiff[ name ] = value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn diff;\n
}\n
\n
// support: jQuery <1.8\n
if ( !$.fn.addBack ) {\n
\t$.fn.addBack = function( selector ) {\n
\t\treturn this.add( selector == null ?\n
\t\t\tthis.prevObject : this.prevObject.filter( selector )\n
\t\t);\n
\t};\n
}\n
\n
$.effects.animateClass = function( value, duration, easing, callback ) {\n
\tvar o = $.speed( duration, easing, callback );\n
\n
\treturn this.queue( function() {\n
\t\tvar animated = $( this ),\n
\t\t\tbaseClass = animated.attr( "class" ) || "",\n
\t\t\tapplyClassChange,\n
\t\t\tallAnimations = o.children ? animated.find( "*" ).addBack() : animated;\n
\n
\t\t// map the animated objects to store the original styles.\n
\t\tallAnimations = allAnimations.map(function() {\n
\t\t\tvar el = $( this );\n
\t\t\treturn {\n
\t\t\t\tel: el,\n
\t\t\t\tstart: getElementStyles( this )\n
\t\t\t};\n
\t\t});\n
\n
\t\t// apply class change\n
\t\tapplyClassChange = function() {\n
\t\t\t$.each( classAnimationActions, function(i, action) {\n
\t\t\t\tif ( value[ action ] ) {\n
\t\t\t\t\tanimated[ action + "Class" ]( value[ action ] );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t};\n
\t\tapplyClassChange();\n
\n
\t\t// map all animated objects again - calculate new styles and diff\n
\t\tallAnimations = allAnimations.map(function() {\n
\t\t\tthis.end = getElementStyles( this.el[ 0 ] );\n
\t\t\tthis.diff = styleDifference( this.start, this.end );\n
\t\t\treturn this;\n
\t\t});\n
\n
\t\t// apply original class\n
\t\tanimated.attr( "class", baseClass );\n
\n
\t\t// map all animated objects again - this time collecting a promise\n
\t\tallAnimations = allAnimations.map(function() {\n
\t\t\tvar styleInfo = this,\n
\t\t\t\tdfd = $.Deferred(),\n
\t\t\t\topts = $.extend({}, o, {\n
\t\t\t\t\tqueue: false,\n
\t\t\t\t\tcomplete: function() {\n
\t\t\t\t\t\tdfd.resolve( styleInfo );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\n
\t\t\tthis.el.animate( this.diff, opts );\n
\t\t\treturn dfd.promise();\n
\t\t});\n
\n
\t\t// once all animations have completed:\n
\t\t$.when.apply( $, allAnimations.get() ).done(function() {\n
\n
\t\t\t// set the final class\n
\t\t\tapplyClassChange();\n
\n
\t\t\t// for each animated element,\n
\t\t\t// clear all css properties that were animated\n
\t\t\t$.each( arguments, function() {\n
\t\t\t\tvar el = this.el;\n
\t\t\t\t$.each( this.diff, function(key) {\n
\t\t\t\t\tel.css( key, "" );\n
\t\t\t\t});\n
\t\t\t});\n
\n
\t\t\t// this is guarnteed to be there if you use jQuery.speed()\n
\t\t\t// it also handles dequeuing the next anim...\n
\t\t\to.complete.call( animated[ 0 ] );\n
\t\t});\n
\t});\n
};\n
\n
$.fn.extend({\n
\taddClass: (function( orig ) {\n
\t\treturn function( classNames, speed, easing, callback ) {\n
\t\t\treturn speed ?\n
\t\t\t\t$.effects.animateClass.call( this,\n
\t\t\t\t\t{ add: classNames }, speed, easing, callback ) :\n
\t\t\t\torig.apply( this, arguments );\n
\t\t};\n
\t})( $.fn.addClass ),\n
\n
\tremoveClass: (function( orig ) {\n
\t\treturn function( classNames, speed, easing, callback ) {\n
\t\t\treturn arguments.length > 1 ?\n
\t\t\t\t$.effects.animateClass.call( this,\n
\t\t\t\t\t{ remove: classNames }, speed, easing, callback ) :\n
\t\t\t\torig.apply( this, arguments );\n
\t\t};\n
\t})( $.fn.removeClass ),\n
\n
\ttoggleClass: (function( orig ) {\n
\t\treturn function( classNames, force, speed, easing, callback ) {\n
\t\t\tif ( typeof force === "boolean" || force === undefined ) {\n
\t\t\t\tif ( !speed ) {\n
\t\t\t\t\t// without speed parameter\n
\t\t\t\t\treturn orig.apply( this, arguments );\n
\t\t\t\t} else {\n
\t\t\t\t\treturn $.effects.animateClass.call( this,\n
\t\t\t\t\t\t(force ? { add: classNames } : { remove: classNames }),\n
\t\t\t\t\t\tspeed, easing, callback );\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\t// without force parameter\n
\t\t\t\treturn $.effects.animateClass.call( this,\n
\t\t\t\t\t{ toggle: classNames }, force, speed, easing );\n
\t\t\t}\n
\t\t};\n
\t})( $.fn.toggleClass ),\n
\n
\tswitchClass: function( remove, add, speed, easing, callback) {\n
\t\treturn $.effects.animateClass.call( this, {\n
\t\t\tadd: add,\n
\t\t\tremove: remove\n
\t\t}, speed, easing, callback );\n
\t}\n
});\n
\n
})();\n
\n
/******************************************************************************/\n
/*********************************** EFFECTS **********************************/\n
/******************************************************************************/\n
\n
(function() {\n
\n
$.extend( $.effects, {\n
\tversion: "1.10.4",\n
\n
\t// Saves a set of properties in a data storage\n
\tsave: function( element, set ) {\n
\t\tfor( var i=0; i < set.length; i++ ) {\n
\t\t\tif ( set[ i ] !== null ) {\n
\t\t\t\telement.data( dataSpace + set[ i ], element[ 0 ].style[ set[ i ] ] );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// Restores a set of previously saved properties from a data storage\n
\trestore: function( element, set ) {\n
\t\tvar val, i;\n
\t\tfor( i=0; i < set.length; i++ ) {\n
\t\t\tif ( set[ i ] !== null ) {\n
\t\t\t\tval = element.data( dataSpace + set[ i ] );\n
\t\t\t\t// support: jQuery 1.6.2\n
\t\t\t\t// http://bugs.jquery.com/ticket/9917\n
\t\t\t\t// jQuery 1.6.2 incorrectly returns undefined for any falsy value.\n
\t\t\t\t// We can\'t differentiate between "" and 0 here, so we just assume\n
\t\t\t\t// empty string since it\'s likely to be a more common value...\n
\t\t\t\tif ( val === undefined ) {\n
\t\t\t\t\tval = "";\n
\t\t\t\t}\n
\t\t\t\telement.css( set[ i ], val );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tsetMode: function( el, mode ) {\n
\t\tif (mode === "toggle") {\n
\t\t\tmode = el.is( ":hidden" ) ? "show" : "hide";\n
\t\t}\n
\t\treturn mode;\n
\t},\n
\n
\t// Translates a [top,left] array into a baseline value\n
\t// this should be a little more flexible in the future to handle a string & hash\n
\tgetBaseline: function( origin, original ) {\n
\t\tvar y, x;\n
\t\tswitch ( origin[ 0 ] ) {\n
\t\t\tcase "top": y = 0; break;\n
\t\t\tcase "middle": y = 0.5; break;\n
\t\t\tcase "bottom": y = 1; break;\n
\t\t\tdefault: y = origin[ 0 ] / original.height;\n
\t\t}\n
\t\tswitch ( origin[ 1 ] ) {\n
\t\t\tcase "left": x = 0; break;\n
\t\t\tcase "center": x = 0.5; break;\n
\t\t\tcase "right": x = 1; break;\n
\t\t\tdefault: x = origin[ 1 ] / original.width;\n
\t\t}\n
\t\treturn {\n
\t\t\tx: x,\n
\t\t\ty: y\n
\t\t};\n
\t},\n
\n
\t// Wraps the element around a wrapper that copies position properties\n
\tcreateWrapper: function( element ) {\n
\n
\t\t// if the element is already wrapped, return it\n
\t\tif ( element.parent().is( ".ui-effects-wrapper" )) {\n
\t\t\treturn element.parent();\n
\t\t}\n
\n
\t\t// wrap the element\n
\t\tvar props = {\n
\t\t\t\twidth: element.outerWidth(true),\n
\t\t\t\theight: element.outerHeight(true),\n
\t\t\t\t"float": element.css( "float" )\n
\t\t\t},\n
\t\t\twrapper = $( "<div></div>" )\n
\t\t\t\t.addClass( "ui-effects-wrapper" )\n
\t\t\t\t.css({\n
\t\t\t\t\tfontSize: "100%",\n
\t\t\t\t\tbackground: "transparent",\n
\t\t\t\t\tborder: "none",\n
\t\t\t\t\tmargin: 0,\n
\t\t\t\t\tpadding: 0\n
\t\t\t\t}),\n
\t\t\t// Store the size in case width/height are defined in % - Fixes #5245\n
\t\t\tsize = {\n
\t\t\t\twidth: element.width(),\n
\t\t\t\theight: element.height()\n
\t\t\t},\n
\t\t\tactive = document.activeElement;\n
\n
\t\t// support: Firefox\n
\t\t// Firefox incorrectly exposes anonymous content\n
\t\t// https://bugzilla.mozilla.org/show_bug.cgi?id=561664\n
\t\ttry {\n
\t\t\tactive.id;\n
\t\t} catch( e ) {\n
\t\t\tactive = document.body;\n
\t\t}\n
\n
\t\telement.wrap( wrapper );\n
\n
\t\t// Fixes #7595 - Elements lose focus when wrapped.\n
\t\tif ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {\n
\t\t\t$( active ).focus();\n
\t\t}\n
\n
\t\twrapper = element.parent(); //Hotfix for jQuery 1.4 since some change in wrap() seems to actually lose the reference to the wrapped element\n
\n
\t\t// transfer positioning properties to the wrapper\n
\t\tif ( element.css( "position" ) === "static" ) {\n
\t\t\twrapper.css({ position: "relative" });\n
\t\t\telement.css({ position: "relative" });\n
\t\t} else {\n
\t\t\t$.extend( props, {\n
\t\t\t\tposition: element.css( "position" ),\n
\t\t\t\tzIndex: element.css( "z-index" )\n
\t\t\t});\n
\t\t\t$.each([ "top", "left", "bottom", "right" ], function(i, pos) {\n
\t\t\t\tprops[ pos ] = element.css( pos );\n
\t\t\t\tif ( isNaN( parseInt( props[ pos ], 10 ) ) ) {\n
\t\t\t\t\tprops[ pos ] = "auto";\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\telement.css({\n
\t\t\t\tposition: "relative",\n
\t\t\t\ttop: 0,\n
\t\t\t\tleft: 0,\n
\t\t\t\tright: "auto",\n
\t\t\t\tbottom: "auto"\n
\t\t\t});\n
\t\t}\n
\t\telement.css(size);\n
\n
\t\treturn wrapper.css( props ).show();\n
\t},\n
\n
\tremoveWrapper: function( element ) {\n
\t\tvar active = document.activeElement;\n
\n
\t\tif ( element.parent().is( ".ui-effects-wrapper" ) ) {\n
\t\t\telement.parent().replaceWith( element );\n
\n
\t\t\t// Fixes #7595 - Elements lose focus when wrapped.\n
\t\t\tif ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {\n
\t\t\t\t$( active ).focus();\n
\t\t\t}\n
\t\t}\n
\n
\n
\t\treturn element;\n
\t},\n
\n
\tsetTransition: function( element, list, factor, value ) {\n
\t\tvalue = value || {};\n
\t\t$.each( list, function( i, x ) {\n
\t\t\tvar unit = element.cssUnit( x );\n
\t\t\tif ( unit[ 0 ] > 0 ) {\n
\t\t\t\tvalue[ x ] = unit[ 0 ] * factor + unit[ 1 ];\n
\t\t\t}\n
\t\t});\n
\t\treturn value;\n
\t}\n
});\n
\n
// return an effect options object for the given parameters:\n
function _normalizeArguments( effect, options, speed, callback ) {\n
\n
\t// allow passing all options as the first parameter\n
\tif ( $.isPlainObject( effect ) ) {\n
\t\toptions = effect;\n
\t\teffect = effect.effect;\n
\t}\n
\n
\t// convert to an object\n
\teffect = { effect: effect };\n
\n
\t// catch (effect, null, ...)\n
\tif ( options == null ) {\n
\t\toptions = {};\n
\t}\n
\n
\t// catch (effect, callback)\n
\tif ( $.isFunction( options ) ) {\n
\t\tcallback = options;\n
\t\tspeed = null;\n
\t\toptions = {};\n
\t}\n
\n
\t// catch (effect, speed, ?)\n
\tif ( typeof options === "number" || $.fx.speeds[ options ] ) {\n
\t\tcallback = speed;\n
\t\tspeed = options;\n
\t\toptions = {};\n
\t}\n
\n
\t// catch (effect, options, callback)\n
\tif ( $.isFunction( speed ) ) {\n
\t\tcallback = speed;\n
\t\tspeed = null;\n
\t}\n
\n
\t// add options to effect\n
\tif ( options ) {\n
\t\t$.extend( effect, options );\n
\t}\n
\n
\tspeed = speed || options.duration;\n
\teffect.duration = $.fx.off ? 0 :\n
\t\ttypeof speed === "number" ? speed :\n
\t\tspeed in $.fx.speeds ? $.fx.speeds[ speed ] :\n
\t\t$.fx.speeds._default;\n
\n
\teffect.complete = callback || options.complete;\n
\n
\treturn effect;\n
}\n
\n
function standardAnimationOption( option ) {\n
\t// Valid standard speeds (nothing, number, named speed)\n
\tif ( !option || typeof option === "number" || $.fx.speeds[ option ] ) {\n
\t\treturn true;\n
\t}\n
\n
\t// Invalid strings - treat as "normal" speed\n
\tif ( typeof option === "string" && !$.effects.effect[ option ] ) {\n
\t\treturn true;\n
\t}\n
\n
\t// Complete callback\n
\tif ( $.isFunction( option ) ) {\n
\t\treturn true;\n
\t}\n
\n
\t// Options hash (but not naming an effect)\n
\tif ( typeof option === "object" && !option.effect ) {\n
\t\treturn true;\n
\t}\n
\n
\t// Didn\'t match any standard API\n
\treturn false;\n
}\n
\n
$.fn.extend({\n
\teffect: function( /* effect, options, speed, callback */ ) {\n
\t\tvar args = _normalizeArguments.apply( this, arguments ),\n
\t\t\tmode = args.mode,\n
\t\t\tqueue = args.queue,\n
\t\t\teffectMethod = $.effects.effect[ args.effect ];\n
\n
\t\tif ( $.fx.off || !effectMethod ) {\n
\t\t\t// delegate to the original method (e.g., .show()) if possible\n
\t\t\tif ( mode ) {\n
\t\t\t\treturn this[ mode ]( args.duration, args.complete );\n
\t\t\t} else {\n
\t\t\t\treturn this.each( function() {\n
\t\t\t\t\tif ( args.complete ) {\n
\t\t\t\t\t\targs.complete.call( this );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t\tfunction run( next ) {\n
\t\t\tvar elem = $( this ),\n
\t\t\t\tcomplete = args.complete,\n
\t\t\t\tmode = args.mode;\n
\n
\t\t\tfunction done() {\n
\t\t\t\tif ( $.isFunction( complete ) ) {\n
\t\t\t\t\tcomplete.call( elem[0] );\n
\t\t\t\t}\n
\t\t\t\tif ( $.isFunction( next ) ) {\n
\t\t\t\t\tnext();\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// If the element already has the correct final state, delegate to\n
\t\t\t// the core methods so the internal tracking of "olddisplay" works.\n
\t\t\tif ( elem.is( ":hidden" ) ? mode === "hide" : mode === "show" ) {\n
\t\t\t\telem[ mode ]();\n
\t\t\t\tdone();\n
\t\t\t} else {\n
\t\t\t\teffectMethod.call( elem[0], args, done );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn queue === false ? this.each( run ) : this.queue( queue || "fx", run );\n
\t},\n
\n
\tshow: (function( orig ) {\n
\t\treturn function( option ) {\n
\t\t\tif ( standardAnimationOption( option ) ) {\n
\t\t\t\treturn orig.apply( this, arguments );\n
\t\t\t} else {\n
\t\t\t\tvar args = _normalizeArguments.apply( this, arguments );\n
\t\t\t\targs.mode = "show";\n
\t\t\t\treturn this.effect.call( this, args );\n
\t\t\t}\n
\t\t};\n
\t})( $.fn.show ),\n
\n
\thide: (function( orig ) {\n
\t\treturn function( option ) {\n
\t\t\tif ( standardAnimationOption( option ) ) {\n
\t\t\t\treturn orig.apply( this, arguments );\n
\t\t\t} else {\n
\t\t\t\tvar args = _normalizeArguments.apply( this, arguments );\n
\t\t\t\targs.mode = "hide";\n
\t\t\t\treturn this.effect.call( this, args );\n
\t\t\t}\n
\t\t};\n
\t})( $.fn.hide ),\n
\n
\ttoggle: (function( orig ) {\n
\t\treturn function( option ) {\n
\t\t\tif ( standardAnimationOption( option ) || typeof option === "boolean" ) {\n
\t\t\t\treturn orig.apply( this, arguments );\n
\t\t\t} else {\n
\t\t\t\tvar args = _normalizeArguments.apply( this, arguments );\n
\t\t\t\targs.mode = "toggle";\n
\t\t\t\treturn this.effect.call( this, args );\n
\t\t\t}\n
\t\t};\n
\t})( $.fn.toggle ),\n
\n
\t// helper functions\n
\tcssUnit: function(key) {\n
\t\tvar style = this.css( key ),\n
\t\t\tval = [];\n
\n
\t\t$.each( [ "em", "px", "%", "pt" ], function( i, unit ) {\n
\t\t\tif ( style.indexOf( unit ) > 0 ) {\n
\t\t\t\tval = [ parseFloat( style ), unit ];\n
\t\t\t}\n
\t\t});\n
\t\treturn val;\n
\t}\n
});\n
\n
})();\n
\n
/******************************************************************************/\n
/*********************************** EASING ***********************************/\n
/******************************************************************************/\n
\n
(function() {\n
\n
// based on easing equations from Robert Penner (http://www.robertpenner.com/easing)\n
\n
var baseEasings = {};\n
\n
$.each( [ "Quad", "Cubic", "Quart", "Quint", "Expo" ], function( i, name ) {\n
\tbaseEasings[ name ] = function( p ) {\n
\t\treturn Math.pow( p, i + 2 );\n
\t};\n
});\n
\n
$.extend( baseEasings, {\n
\tSine: function ( p ) {\n
\t\treturn 1 - Math.cos( p * Math.PI / 2 );\n
\t},\n
\tCirc: function ( p ) {\n
\t\treturn 1 - Math.sqrt( 1 - p * p );\n
\t},\n
\tElastic: function( p ) {\n
\t\treturn p === 0 || p === 1 ? p :\n
\t\t\t-Math.pow( 2, 8 * (p - 1) ) * Math.sin( ( (p - 1) * 80 - 7.5 ) * Math.PI / 15 );\n
\t},\n
\tBack: function( p ) {\n
\t\treturn p * p * ( 3 * p - 2 );\n
\t},\n
\tBounce: function ( p ) {\n
\t\tvar pow2,\n
\t\t\tbounce = 4;\n
\n
\t\twhile ( p < ( ( pow2 = Math.pow( 2, --bounce ) ) - 1 ) / 11 ) {}\n
\t\treturn 1 / Math.pow( 4, 3 - bounce ) - 7.5625 * Math.pow( ( pow2 * 3 - 2 ) / 22 - p, 2 );\n
\t}\n
});\n
\n
$.each( baseEasings, function( name, easeIn ) {\n
\t$.easing[ "easeIn" + name ] = easeIn;\n
\t$.easing[ "easeOut" + name ] = function( p ) {\n
\t\treturn 1 - easeIn( 1 - p );\n
\t};\n
\t$.easing[ "easeInOut" + name ] = function( p ) {\n
\t\treturn p < 0.5 ?\n
\t\t\teaseIn( p * 2 ) / 2 :\n
\t\t\t1 - easeIn( p * -2 + 2 ) / 2;\n
\t};\n
});\n
\n
})();\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
var rvertical = /up|down|vertical/,\n
\trpositivemotion = /up|left|vertical|horizontal/;\n
\n
$.effects.effect.blind = function( o, done ) {\n
\t// Create element\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "height", "width" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "hide" ),\n
\t\tdirection = o.direction || "up",\n
\t\tvertical = rvertical.test( direction ),\n
\t\tref = vertical ? "height" : "width",\n
\t\tref2 = vertical ? "top" : "left",\n
\t\tmotion = rpositivemotion.test( direction ),\n
\t\tanimation = {},\n
\t\tshow = mode === "show",\n
\t\twrapper, distance, margin;\n
\n
\t// if already wrapped, the wrapper\'s properties are my property. #6245\n
\tif ( el.parent().is( ".ui-effects-wrapper" ) ) {\n
\t\t$.effects.save( el.parent(), props );\n
\t} else {\n
\t\t$.effects.save( el, props );\n
\t}\n
\tel.show();\n
\twrapper = $.effects.createWrapper( el ).css({\n
\t\toverflow: "hidden"\n
\t});\n
\n
\tdistance = wrapper[ ref ]();\n
\tmargin = parseFloat( wrapper.css( ref2 ) ) || 0;\n
\n
\tanimation[ ref ] = show ? distance : 0;\n
\tif ( !motion ) {\n
\t\tel\n
\t\t\t.css( vertical ? "bottom" : "right", 0 )\n
\t\t\t.css( vertical ? "top" : "left", "auto" )\n
\t\t\t.css({ position: "absolute" });\n
\n
\t\tanimation[ ref2 ] = show ? margin : distance + margin;\n
\t}\n
\n
\t// start at 0 if we are showing\n
\tif ( show ) {\n
\t\twrapper.css( ref, 0 );\n
\t\tif ( ! motion ) {\n
\t\t\twrapper.css( ref2, margin + distance );\n
\t\t}\n
\t}\n
\n
\t// Animate\n
\twrapper.animate( animation, {\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tqueue: false,\n
\t\tcomplete: function() {\n
\t\t\tif ( mode === "hide" ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t}\n
\t});\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.bounce = function( o, done ) {\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "height", "width" ],\n
\n
\t\t// defaults:\n
\t\tmode = $.effects.setMode( el, o.mode || "effect" ),\n
\t\thide = mode === "hide",\n
\t\tshow = mode === "show",\n
\t\tdirection = o.direction || "up",\n
\t\tdistance = o.distance,\n
\t\ttimes = o.times || 5,\n
\n
\t\t// number of internal animations\n
\t\tanims = times * 2 + ( show || hide ? 1 : 0 ),\n
\t\tspeed = o.duration / anims,\n
\t\teasing = o.easing,\n
\n
\t\t// utility:\n
\t\tref = ( direction === "up" || direction === "down" ) ? "top" : "left",\n
\t\tmotion = ( direction === "up" || direction === "left" ),\n
\t\ti,\n
\t\tupAnim,\n
\t\tdownAnim,\n
\n
\t\t// we will need to re-assemble the queue to stack our animations in place\n
\t\tqueue = el.queue(),\n
\t\tqueuelen = queue.length;\n
\n
\t// Avoid touching opacity to prevent clearType and PNG issues in IE\n
\tif ( show || hide ) {\n
\t\tprops.push( "opacity" );\n
\t}\n
\n
\t$.effects.save( el, props );\n
\tel.show();\n
\t$.effects.createWrapper( el ); // Create Wrapper\n
\n
\t// default distance for the BIGGEST bounce is the outer Distance / 3\n
\tif ( !distance ) {\n
\t\tdistance = el[ ref === "top" ? "outerHeight" : "outerWidth" ]() / 3;\n
\t}\n
\n
\tif ( show ) {\n
\t\tdownAnim = { opacity: 1 };\n
\t\tdownAnim[ ref ] = 0;\n
\n
\t\t// if we are showing, force opacity 0 and set the initial position\n
\t\t// then do the "first" animation\n
\t\tel.css( "opacity", 0 )\n
\t\t\t.css( ref, motion ? -distance * 2 : distance * 2 )\n
\t\t\t.animate( downAnim, speed, easing );\n
\t}\n
\n
\t// start at the smallest distance if we are hiding\n
\tif ( hide ) {\n
\t\tdistance = distance / Math.pow( 2, times - 1 );\n
\t}\n
\n
\tdownAnim = {};\n
\tdownAnim[ ref ] = 0;\n
\t// Bounces up/down/left/right then back to 0 -- times * 2 animations happen here\n
\tfor ( i = 0; i < times; i++ ) {\n
\t\tupAnim = {};\n
\t\tupAnim[ ref ] = ( motion ? "-=" : "+=" ) + distance;\n
\n
\t\tel.animate( upAnim, speed, easing )\n
\t\t\t.animate( downAnim, speed, easing );\n
\n
\t\tdistance = hide ? distance * 2 : distance / 2;\n
\t}\n
\n
\t// Last Bounce when Hiding\n
\tif ( hide ) {\n
\t\tupAnim = { opacity: 0 };\n
\t\tupAnim[ ref ] = ( motion ? "-=" : "+=" ) + distance;\n
\n
\t\tel.animate( upAnim, speed, easing );\n
\t}\n
\n
\tel.queue(function() {\n
\t\tif ( hide ) {\n
\t\t\tel.hide();\n
\t\t}\n
\t\t$.effects.restore( el, props );\n
\t\t$.effects.removeWrapper( el );\n
\t\tdone();\n
\t});\n
\n
\t// inject all the animations we just queued to be first in line (after "inprogress")\n
\tif ( queuelen > 1) {\n
\t\tqueue.splice.apply( queue,\n
\t\t\t[ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );\n
\t}\n
\tel.dequeue();\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.clip = function( o, done ) {\n
\t// Create element\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "height", "width" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "hide" ),\n
\t\tshow = mode === "show",\n
\t\tdirection = o.direction || "vertical",\n
\t\tvert = direction === "vertical",\n
\t\tsize = vert ? "height" : "width",\n
\t\tposition = vert ? "top" : "left",\n
\t\tanimation = {},\n
\t\twrapper, animate, distance;\n
\n
\t// Save & Show\n
\t$.effects.save( el, props );\n
\tel.show();\n
\n
\t// Create Wrapper\n
\twrapper = $.effects.createWrapper( el ).css({\n
\t\toverflow: "hidden"\n
\t});\n
\tanimate = ( el[0].tagName === "IMG" ) ? wrapper : el;\n
\tdistance = animate[ size ]();\n
\n
\t// Shift\n
\tif ( show ) {\n
\t\tanimate.css( size, 0 );\n
\t\tanimate.css( position, distance / 2 );\n
\t}\n
\n
\t// Create Animation Object:\n
\tanimation[ size ] = show ? distance : 0;\n
\tanimation[ position ] = show ? 0 : distance / 2;\n
\n
\t// Animate\n
\tanimate.animate( animation, {\n
\t\tqueue: false,\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tcomplete: function() {\n
\t\t\tif ( !show ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t}\n
\t});\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.drop = function( o, done ) {\n
\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "opacity", "height", "width" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "hide" ),\n
\t\tshow = mode === "show",\n
\t\tdirection = o.direction || "left",\n
\t\tref = ( direction === "up" || direction === "down" ) ? "top" : "left",\n
\t\tmotion = ( direction === "up" || direction === "left" ) ? "pos" : "neg",\n
\t\tanimation = {\n
\t\t\topacity: show ? 1 : 0\n
\t\t},\n
\t\tdistance;\n
\n
\t// Adjust\n
\t$.effects.save( el, props );\n
\tel.show();\n
\t$.effects.createWrapper( el );\n
\n
\tdistance = o.distance || el[ ref === "top" ? "outerHeight": "outerWidth" ]( true ) / 2;\n
\n
\tif ( show ) {\n
\t\tel\n
\t\t\t.css( "opacity", 0 )\n
\t\t\t.css( ref, motion === "pos" ? -distance : distance );\n
\t}\n
\n
\t// Animation\n
\tanimation[ ref ] = ( show ?\n
\t\t( motion === "pos" ? "+=" : "-=" ) :\n
\t\t( motion === "pos" ? "-=" : "+=" ) ) +\n
\t\tdistance;\n
\n
\t// Animate\n
\tel.animate( animation, {\n
\t\tqueue: false,\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tcomplete: function() {\n
\t\t\tif ( mode === "hide" ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t}\n
\t});\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.explode = function( o, done ) {\n
\n
\tvar rows = o.pieces ? Math.round( Math.sqrt( o.pieces ) ) : 3,\n
\t\tcells = rows,\n
\t\tel = $( this ),\n
\t\tmode = $.effects.setMode( el, o.mode || "hide" ),\n
\t\tshow = mode === "show",\n
\n
\t\t// show and then visibility:hidden the element before calculating offset\n
\t\toffset = el.show().css( "visibility", "hidden" ).offset(),\n
\n
\t\t// width and height of a piece\n
\t\twidth = Math.ceil( el.outerWidth() / cells ),\n
\t\theight = Math.ceil( el.outerHeight() / rows ),\n
\t\tpieces = [],\n
\n
\t\t// loop\n
\t\ti, j, left, top, mx, my;\n
\n
\t// children animate complete:\n
\tfunction childComplete() {\n
\t\tpieces.push( this );\n
\t\tif ( pieces.length === rows * cells ) {\n
\t\t\tanimComplete();\n
\t\t}\n
\t}\n
\n
\t// clone the element for each row and cell.\n
\tfor( i = 0; i < rows ; i++ ) { // ===>\n
\t\ttop = offset.top + i * height;\n
\t\tmy = i - ( rows - 1 ) / 2 ;\n
\n
\t\tfor( j = 0; j < cells ; j++ ) { // |||\n
\t\t\tleft = offset.left + j * width;\n
\t\t\tmx = j - ( cells - 1 ) / 2 ;\n
\n
\t\t\t// Create a clone of the now hidden main element that will be absolute positioned\n
\t\t\t// within a wrapper div off the -left and -top equal to size of our pieces\n
\t\t\tel\n
\t\t\t\t.clone()\n
\t\t\t\t.appendTo( "body" )\n
\t\t\t\t.wrap( "<div></div>" )\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: "absolute",\n
\t\t\t\t\tvisibility: "visible",\n
\t\t\t\t\tleft: -j * width,\n
\t\t\t\t\ttop: -i * height\n
\t\t\t\t})\n
\n
\t\t\t// select the wrapper - make it overflow: hidden and absolute positioned based on\n
\t\t\t// where the original was located +left and +top equal to the size of pieces\n
\t\t\t\t.parent()\n
\t\t\t\t.addClass( "ui-effects-explode" )\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: "absolute",\n
\t\t\t\t\toverflow: "hidden",\n
\t\t\t\t\twidth: width,\n
\t\t\t\t\theight: height,\n
\t\t\t\t\tleft: left + ( show ? mx * width : 0 ),\n
\t\t\t\t\ttop: top + ( show ? my * height : 0 ),\n
\t\t\t\t\topacity: show ? 0 : 1\n
\t\t\t\t}).animate({\n
\t\t\t\t\tleft: left + ( show ? 0 : mx * width ),\n
\t\t\t\t\ttop: top + ( show ? 0 : my * height ),\n
\t\t\t\t\topacity: show ? 1 : 0\n
\t\t\t\t}, o.duration || 500, o.easing, childComplete );\n
\t\t}\n
\t}\n
\n
\tfunction animComplete() {\n
\t\tel.css({\n
\t\t\tvisibility: "visible"\n
\t\t});\n
\t\t$( pieces ).remove();\n
\t\tif ( !show ) {\n
\t\t\tel.hide();\n
\t\t}\n
\t\tdone();\n
\t}\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.fade = function( o, done ) {\n
\tvar el = $( this ),\n
\t\tmode = $.effects.setMode( el, o.mode || "toggle" );\n
\n
\tel.animate({\n
\t\topacity: mode\n
\t}, {\n
\t\tqueue: false,\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tcomplete: done\n
\t});\n
};\n
\n
})( jQuery );\n
(function( $, undefined ) {\n
\n
$.effects.effect.fold = function( o, done ) {\n
\n
\t// Create element\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "height", "width" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "hide" ),\n
\t\tshow = mode === "show",\n
\t\thide = mode === "hide",\n
\t\tsize = o.size || 15,\n
\t\tpercent = /([0-9]+)%/.exec( size ),\n
\t\thorizFirst = !!o.horizFirst,\n
\t\twidthFirst = show !== horizFirst,\n
\t\tref = widthFirst ? [ "width", "height" ] : [ "height", "width" ],\n
\t\tduration = o.duration / 2,\n
\t\twrapper, distance,\n
\t\tanimation1 = {},\n
\t\tanimation2 = {};\n
\n
\t$.effects.save( el, props );\n
\tel.show();\n
\n
\t// Create Wrapper\n
\twrapper = $.effects.createWrapper( el ).css({\n
\t\toverflow: "hidden"\n
\t});\n
\tdistance = widthFirst ?\n
\t\t[ wrapper.width(), wrapper.height() ] :\n
\t\t[ wrapper.height(), wrapper.width() ];\n
\n
\tif ( percent ) {\n
\t\tsize = parseInt( percent[ 1 ], 10 ) / 100 * distance[ hide ? 0 : 1 ];\n
\t}\n
\tif ( show ) {\n
\t\twrapper.css( horizFirst ? {\n
\t\t\theight: 0,\n
\t\t\twidth: size\n
\t\t} : {\n
\t\t\theight: size,\n
\t\t\twidth: 0\n
\t\t});\n
\t}\n
\n
\t// Animation\n
\tanimation1[ ref[ 0 ] ] = show ? distance[ 0 ] : size;\n
\tanimation2[ ref[ 1 ] ] = show ? distance[ 1 ] : 0;\n
\n
\t// Animate\n
\twrapper\n
\t\t.animate( animation1, duration, o.easing )\n
\t\t.animate( animation2, duration, o.easing, function() {\n
\t\t\tif ( hide ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t});\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.highlight = function( o, done ) {\n
\tvar elem = $( this ),\n
\t\tprops = [ "backgroundImage", "backgroundColor", "opacity" ],\n
\t\tmode = $.effects.setMode( elem, o.mode || "show" ),\n
\t\tanimation = {\n
\t\t\tbackgroundColor: elem.css( "backgroundColor" )\n
\t\t};\n
\n
\tif (mode === "hide") {\n
\t\tanimation.opacity = 0;\n
\t}\n
\n
\t$.effects.save( elem, props );\n
\n
\telem\n
\t\t.show()\n
\t\t.css({\n
\t\t\tbackgroundImage: "none",\n
\t\t\tbackgroundColor: o.color || "#ffff99"\n
\t\t})\n
\t\t.animate( animation, {\n
\t\t\tqueue: false,\n
\t\t\tduration: o.duration,\n
\t\t\teasing: o.easing,\n
\t\t\tcomplete: function() {\n
\t\t\t\tif ( mode === "hide" ) {\n
\t\t\t\t\telem.hide();\n
\t\t\t\t}\n
\t\t\t\t$.effects.restore( elem, props );\n
\t\t\t\tdone();\n
\t\t\t}\n
\t\t});\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.pulsate = function( o, done ) {\n
\tvar elem = $( this ),\n
\t\tmode = $.effects.setMode( elem, o.mode || "show" ),\n
\t\tshow = mode === "show",\n
\t\thide = mode === "hide",\n
\t\tshowhide = ( show || mode === "hide" ),\n
\n
\t\t// showing or hiding leaves of the "last" animation\n
\t\tanims = ( ( o.times || 5 ) * 2 ) + ( showhide ? 1 : 0 ),\n
\t\tduration = o.duration / anims,\n
\t\tanimateTo = 0,\n
\t\tqueue = elem.queue(),\n
\t\tqueuelen = queue.length,\n
\t\ti;\n
\n
\tif ( show || !elem.is(":visible")) {\n
\t\telem.css( "opacity", 0 ).show();\n
\t\tanimateTo = 1;\n
\t}\n
\n
\t// anims - 1 opacity "toggles"\n
\tfor ( i = 1; i < anims; i++ ) {\n
\t\telem.animate({\n
\t\t\topacity: animateTo\n
\t\t}, duration, o.easing );\n
\t\tanimateTo = 1 - animateTo;\n
\t}\n
\n
\telem.animate({\n
\t\topacity: animateTo\n
\t}, duration, o.easing);\n
\n
\telem.queue(function() {\n
\t\tif ( hide ) {\n
\t\t\telem.hide();\n
\t\t}\n
\t\tdone();\n
\t});\n
\n
\t// We just queued up "anims" animations, we need to put them next in the queue\n
\tif ( queuelen > 1 ) {\n
\t\tqueue.splice.apply( queue,\n
\t\t\t[ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );\n
\t}\n
\telem.dequeue();\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.puff = function( o, done ) {\n
\tvar elem = $( this ),\n
\t\tmode = $.effects.setMode( elem, o.mode || "hide" ),\n
\t\thide = mode === "hide",\n
\t\tpercent = parseInt( o.percent, 10 ) || 150,\n
\t\tfactor = percent / 100,\n
\t\toriginal = {\n
\t\t\theight: elem.height(),\n
\t\t\twidth: elem.width(),\n
\t\t\touterHeight: elem.outerHeight(),\n
\t\t\touterWidth: elem.outerWidth()\n
\t\t};\n
\n
\t$.extend( o, {\n
\t\teffect: "scale",\n
\t\tqueue: false,\n
\t\tfade: true,\n
\t\tmode: mode,\n
\t\tcomplete: done,\n
\t\tpercent: hide ? percent : 100,\n
\t\tfrom: hide ?\n
\t\t\toriginal :\n
\t\t\t{\n
\t\t\t\theight: original.height * factor,\n
\t\t\t\twidth: original.width * factor,\n
\t\t\t\touterHeight: original.outerHeight * factor,\n
\t\t\t\touterWidth: original.outerWidth * factor\n
\t\t\t}\n
\t});\n
\n
\telem.effect( o );\n
};\n
\n
$.effects.effect.scale = function( o, done ) {\n
\n
\t// Create element\n
\tvar el = $( this ),\n
\t\toptions = $.extend( true, {}, o ),\n
\t\tmode = $.effects.setMode( el, o.mode || "effect" ),\n
\t\tpercent = parseInt( o.percent, 10 ) ||\n
\t\t\t( parseInt( o.percent, 10 ) === 0 ? 0 : ( mode === "hide" ? 0 : 100 ) ),\n
\t\tdirection = o.direction || "both",\n
\t\torigin = o.origin,\n
\t\toriginal = {\n
\t\t\theight: el.height(),\n
\t\t\twidth: el.width(),\n
\t\t\touterHeight: el.outerHeight(),\n
\t\t\touterWidth: el.outerWidth()\n
\t\t},\n
\t\tfactor = {\n
\t\t\ty: direction !== "horizontal" ? (percent / 100) : 1,\n
\t\t\tx: direction !== "vertical" ? (percent / 100) : 1\n
\t\t};\n
\n
\t// We are going to pass this effect to the size effect:\n
\toptions.effect = "size";\n
\toptions.queue = false;\n
\toptions.complete = done;\n
\n
\t// Set default origin and restore for show/hide\n
\tif ( mode !== "effect" ) {\n
\t\toptions.origin = origin || ["middle","center"];\n
\t\toptions.restore = true;\n
\t}\n
\n
\toptions.from = o.from || ( mode === "show" ? {\n
\t\theight: 0,\n
\t\twidth: 0,\n
\t\touterHeight: 0,\n
\t\touterWidth: 0\n
\t} : original );\n
\toptions.to = {\n
\t\theight: original.height * factor.y,\n
\t\twidth: original.width * factor.x,\n
\t\touterHeight: original.outerHeight * factor.y,\n
\t\touterWidth: original.outerWidth * factor.x\n
\t};\n
\n
\t// Fade option to support puff\n
\tif ( options.fade ) {\n
\t\tif ( mode === "show" ) {\n
\t\t\toptions.from.opacity = 0;\n
\t\t\toptions.to.opacity = 1;\n
\t\t}\n
\t\tif ( mode === "hide" ) {\n
\t\t\toptions.from.opacity = 1;\n
\t\t\toptions.to.opacity = 0;\n
\t\t}\n
\t}\n
\n
\t// Animate\n
\tel.effect( options );\n
\n
};\n
\n
$.effects.effect.size = function( o, done ) {\n
\n
\t// Create element\n
\tvar original, baseline, factor,\n
\t\tel = $( this ),\n
\t\tprops0 = [ "position", "top", "bottom", "left", "right", "width", "height", "overflow", "opacity" ],\n
\n
\t\t// Always restore\n
\t\tprops1 = [ "position", "top", "bottom", "left", "right", "overflow", "opacity" ],\n
\n
\t\t// Copy for children\n
\t\tprops2 = [ "width", "height", "overflow" ],\n
\t\tcProps = [ "fontSize" ],\n
\t\tvProps = [ "borderTopWidth", "borderBottomWidth", "paddingTop", "paddingBottom" ],\n
\t\thProps = [ "borderLeftWidth", "borderRightWidth", "paddingLeft", "paddingRight" ],\n
\n
\t\t// Set options\n
\t\tmode = $.effects.setMode( el, o.mode || "effect" ),\n
\t\trestore = o.restore || mode !== "effect",\n
\t\tscale = o.scale || "both",\n
\t\torigin = o.origin || [ "middle", "center" ],\n
\t\tposition = el.css( "position" ),\n
\t\tprops = restore ? props0 : props1,\n
\t\tzero = {\n
\t\t\theight: 0,\n
\t\t\twidth: 0,\n
\t\t\touterHeight: 0,\n
\t\t\touterWidth: 0\n
\t\t};\n
\n
\tif ( mode === "show" ) {\n
\t\tel.show();\n
\t}\n
\toriginal = {\n
\t\theight: el.height(),\n
\t\twidth: el.width(),\n
\t\touterHeight: el.outerHeight(),\n
\t\touterWidth: el.outerWidth()\n
\t};\n
\n
\tif ( o.mode === "toggle" && mode === "show" ) {\n
\t\tel.from = o.to || zero;\n
\t\tel.to = o.from || original;\n
\t} else {\n
\t\tel.from = o.from || ( mode === "show" ? zero : original );\n
\t\tel.to = o.to || ( mode === "hide" ? zero : original );\n
\t}\n
\n
\t// Set scaling factor\n
\tfactor = {\n
\t\tfrom: {\n
\t\t\ty: el.from.height / original.height,\n
\t\t\tx: el.from.width / original.width\n
\t\t},\n
\t\tto: {\n
\t\t\ty: el.to.height / original.height,\n
\t\t\tx: el.to.width / original.width\n
\t\t}\n
\t};\n
\n
\t// Scale the css box\n
\tif ( scale === "box" || scale === "both" ) {\n
\n
\t\t// Vertical props scaling\n
\t\tif ( factor.from.y !== factor.to.y ) {\n
\t\t\tprops = props.concat( vProps );\n
\t\t\tel.from = $.effects.setTransition( el, vProps, factor.from.y, el.from );\n
\t\t\tel.to = $.effects.setTransition( el, vProps, factor.to.y, el.to );\n
\t\t}\n
\n
\t\t// Horizontal props scaling\n
\t\tif ( factor.from.x !== factor.to.x ) {\n
\t\t\tprops = props.concat( hProps );\n
\t\t\tel.from = $.effects.setTransition( el, hProps, factor.from.x, el.from );\n
\t\t\tel.to = $.effects.setTransition( el, hProps, factor.to.x, el.to );\n
\t\t}\n
\t}\n
\n
\t// Scale the content\n
\tif ( scale === "content" || scale === "both" ) {\n
\n
\t\t// Vertical props scaling\n
\t\tif ( factor.from.y !== factor.to.y ) {\n
\t\t\tprops = props.concat( cProps ).concat( props2 );\n
\t\t\tel.from = $.effects.setTransition( el, cProps, factor.from.y, el.from );\n
\t\t\tel.to = $.effects.setTransition( el, cProps, factor.to.y, el.to );\n
\t\t}\n
\t}\n
\n
\t$.effects.save( el, props );\n
\tel.show();\n
\t$.effects.createWrapper( el );\n
\tel.css( "overflow", "hidden" ).css( el.from );\n
\n
\t// Adjust\n
\tif (origin) { // Calculate baseline shifts\n
\t\tbaseline = $.effects.getBaseline( origin, original );\n
\t\tel.from.top = ( original.outerHeight - el.outerHeight() ) * baseline.y;\n
\t\tel.from.left = ( original.outerWidth - el.outerWidth() ) * baseline.x;\n
\t\tel.to.top = ( original.outerHeight - el.to.outerHeight ) * baseline.y;\n
\t\tel.to.left = ( original.outerWidth - el.to.outerWidth ) * baseline.x;\n
\t}\n
\tel.css( el.from ); // set top & left\n
\n
\t// Animate\n
\tif ( scale === "content" || scale === "both" ) { // Scale the children\n
\n
\t\t// Add margins/font-size\n
\t\tvProps = vProps.concat([ "marginTop", "marginBottom" ]).concat(cProps);\n
\t\thProps = hProps.concat([ "marginLeft", "marginRight" ]);\n
\t\tprops2 = props0.concat(vProps).concat(hProps);\n
\n
\t\tel.find( "*[width]" ).each( function(){\n
\t\t\tvar child = $( this ),\n
\t\t\t\tc_original = {\n
\t\t\t\t\theight: child.height(),\n
\t\t\t\t\twidth: child.width(),\n
\t\t\t\t\touterHeight: child.outerHeight(),\n
\t\t\t\t\touterWidth: child.outerWidth()\n
\t\t\t\t};\n
\t\t\tif (restore) {\n
\t\t\t\t$.effects.save(child, props2);\n
\t\t\t}\n
\n
\t\t\tchild.from = {\n
\t\t\t\theight: c_original.height * factor.from.y,\n
\t\t\t\twidth: c_original.width * factor.from.x,\n
\t\t\t\touterHeight: c_original.outerHeight * factor.from.y,\n
\t\t\t\touterWidth: c_original.outerWidth * factor.from.x\n
\t\t\t};\n
\t\t\tchild.to = {\n
\t\t\t\theight: c_original.height * factor.to.y,\n
\t\t\t\twidth: c_original.width * factor.to.x,\n
\t\t\t\touterHeight: c_original.height * factor.to.y,\n
\t\t\t\touterWidth: c_original.width * factor.to.x\n
\t\t\t};\n
\n
\t\t\t// Vertical props scaling\n
\t\t\tif ( factor.from.y !== factor.to.y ) {\n
\t\t\t\tchild.from = $.effects.setTransition( child, vProps, factor.from.y, child.from );\n
\t\t\t\tchild.to = $.effects.setTransition( child, vProps, factor.to.y, child.to );\n
\t\t\t}\n
\n
\t\t\t// Horizontal props scaling\n
\t\t\tif ( factor.from.x !== factor.to.x ) {\n
\t\t\t\tchild.from = $.effects.setTransition( child, hProps, factor.from.x, child.from );\n
\t\t\t\tchild.to = $.effects.setTransition( child, hProps, factor.to.x, child.to );\n
\t\t\t}\n
\n
\t\t\t// Animate children\n
\t\t\tchild.css( child.from );\n
\t\t\tchild.animate( child.to, o.duration, o.easing, function() {\n
\n
\t\t\t\t// Restore children\n
\t\t\t\tif ( restore ) {\n
\t\t\t\t\t$.effects.restore( child, props2 );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t});\n
\t}\n
\n
\t// Animate\n
\tel.animate( el.to, {\n
\t\tqueue: false,\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tcomplete: function() {\n
\t\t\tif ( el.to.opacity === 0 ) {\n
\t\t\t\tel.css( "opacity", el.from.opacity );\n
\t\t\t}\n
\t\t\tif( mode === "hide" ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\tif ( !restore ) {\n
\n
\t\t\t\t// we need to calculate our new positioning based on the scaling\n
\t\t\t\tif ( position === "static" ) {\n
\t\t\t\t\tel.css({\n
\t\t\t\t\t\tposition: "relative",\n
\t\t\t\t\t\ttop: el.to.top,\n
\t\t\t\t\t\tleft: el.to.left\n
\t\t\t\t\t});\n
\t\t\t\t} else {\n
\t\t\t\t\t$.each([ "top", "left" ], function( idx, pos ) {\n
\t\t\t\t\t\tel.css( pos, function( _, str ) {\n
\t\t\t\t\t\t\tvar val = parseInt( str, 10 ),\n
\t\t\t\t\t\t\t\ttoRef = idx ? el.to.left : el.to.top;\n
\n
\t\t\t\t\t\t\t// if original was "auto", recalculate the new value from wrapper\n
\t\t\t\t\t\t\tif ( str === "auto" ) {\n
\t\t\t\t\t\t\t\treturn toRef + "px";\n
\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\treturn val + toRef + "px";\n
\t\t\t\t\t\t});\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t}\n
\t});\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.shake = function( o, done ) {\n
\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "height", "width" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "effect" ),\n
\t\tdirection = o.direction || "left",\n
\t\tdistance = o.distance || 20,\n
\t\ttimes = o.times || 3,\n
\t\tanims = times * 2 + 1,\n
\t\tspeed = Math.round(o.duration/anims),\n
\t\tref = (direction === "up" || direction === "down") ? "top" : "left",\n
\t\tpositiveMotion = (direction === "up" || direction === "left"),\n
\t\tanimation = {},\n
\t\tanimation1 = {},\n
\t\tanimation2 = {},\n
\t\ti,\n
\n
\t\t// we will need to re-assemble the queue to stack our animations in place\n
\t\tqueue = el.queue(),\n
\t\tqueuelen = queue.length;\n
\n
\t$.effects.save( el, props );\n
\tel.show();\n
\t$.effects.createWrapper( el );\n
\n
\t// Animation\n
\tanimation[ ref ] = ( positiveMotion ? "-=" : "+=" ) + distance;\n
\tanimation1[ ref ] = ( positiveMotion ? "+=" : "-=" ) + distance * 2;\n
\tanimation2[ ref ] = ( positiveMotion ? "-=" : "+=" ) + distance * 2;\n
\n
\t// Animate\n
\tel.animate( animation, speed, o.easing );\n
\n
\t// Shakes\n
\tfor ( i = 1; i < times; i++ ) {\n
\t\tel.animate( animation1, speed, o.easing ).animate( animation2, speed, o.easing );\n
\t}\n
\tel\n
\t\t.animate( animation1, speed, o.easing )\n
\t\t.animate( animation, speed / 2, o.easing )\n
\t\t.queue(function() {\n
\t\t\tif ( mode === "hide" ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t});\n
\n
\t// inject all the animations we just queued to be first in line (after "inprogress")\n
\tif ( queuelen > 1) {\n
\t\tqueue.splice.apply( queue,\n
\t\t\t[ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );\n
\t}\n
\tel.dequeue();\n
\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.slide = function( o, done ) {\n
\n
\t// Create element\n
\tvar el = $( this ),\n
\t\tprops = [ "position", "top", "bottom", "left", "right", "width", "height" ],\n
\t\tmode = $.effects.setMode( el, o.mode || "show" ),\n
\t\tshow = mode === "show",\n
\t\tdirection = o.direction || "left",\n
\t\tref = (direction === "up" || direction === "down") ? "top" : "left",\n
\t\tpositiveMotion = (direction === "up" || direction === "left"),\n
\t\tdistance,\n
\t\tanimation = {};\n
\n
\t// Adjust\n
\t$.effects.save( el, props );\n
\tel.show();\n
\tdistance = o.distance || el[ ref === "top" ? "outerHeight" : "outerWidth" ]( true );\n
\n
\t$.effects.createWrapper( el ).css({\n
\t\toverflow: "hidden"\n
\t});\n
\n
\tif ( show ) {\n
\t\tel.css( ref, positiveMotion ? (isNaN(distance) ? "-" + distance : -distance) : distance );\n
\t}\n
\n
\t// Animation\n
\tanimation[ ref ] = ( show ?\n
\t\t( positiveMotion ? "+=" : "-=") :\n
\t\t( positiveMotion ? "-=" : "+=")) +\n
\t\tdistance;\n
\n
\t// Animate\n
\tel.animate( animation, {\n
\t\tqueue: false,\n
\t\tduration: o.duration,\n
\t\teasing: o.easing,\n
\t\tcomplete: function() {\n
\t\t\tif ( mode === "hide" ) {\n
\t\t\t\tel.hide();\n
\t\t\t}\n
\t\t\t$.effects.restore( el, props );\n
\t\t\t$.effects.removeWrapper( el );\n
\t\t\tdone();\n
\t\t}\n
\t});\n
};\n
\n
})(jQuery);\n
(function( $, undefined ) {\n
\n
$.effects.effect.transfer = function( o, done ) {\n
\tvar elem = $( this ),\n
\t\ttarget = $( o.to ),\n
\t\ttargetFixed = target.css( "position" ) === "fixed",\n
\t\tbody = $("body"),\n
\t\tfixTop = targetFixed ? body.scrollTop() : 0,\n
\t\tfixLeft = targetFixed ? body.scrollLeft() : 0,\n
\t\tendPosition = target.offset(),\n
\t\tanimation = {\n
\t\t\ttop: endPosition.top - fixTop ,\n
\t\t\tleft: endPosition.left - fixLeft ,\n
\t\t\theight: target.innerHeight(),\n
\t\t\twidth: target.innerWidth()\n
\t\t},\n
\t\tstartPosition = elem.offset(),\n
\t\ttransfer = $( "<div class=\'ui-effects-transfer\'></div>" )\n
\t\t\t.appendTo( document.body )\n
\t\t\t.addClass( o.className )\n
\t\t\t.css({\n
\t\t\t\ttop: startPosition.top - fixTop ,\n
\t\t\t\tleft: startPosition.left - fixLeft ,\n
\t\t\t\theight: elem.innerHeight(),\n
\t\t\t\twidth: elem.innerWidth(),\n
\t\t\t\tposition: targetFixed ? "fixed" : "absolute"\n
\t\t\t})\n
\t\t\t.animate( animation, o.duration, o.easing, function() {\n
\t\t\t\ttransfer.remove();\n
\t\t\t\tdone();\n
\t\t\t});\n
};\n
\n
})(jQuery);\n


]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
