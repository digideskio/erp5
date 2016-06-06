<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="Web Script" module="erp5.portal_type"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Access_contents_information_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Add_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Change_local_roles_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Modify_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>content_md5</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>default_reference</string> </key>
            <value> <string>jquerymobile.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>rjs_jquerymobile_js</string> </value>
        </item>
        <item>
            <key> <string>language</string> </key>
            <value> <string>en</string> </value>
        </item>
        <item>
            <key> <string>portal_type</string> </key>
            <value> <string>Web Script</string> </value>
        </item>
        <item>
            <key> <string>short_title</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>text_content</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// CUSTOM HACKS:\n
// added wrapper class property on select to enable readonly (wontfix)\n
\n
/*!\n
* jQuery Mobile 1.5.0-pre\n
* Git HEAD hash: 39cb20fe26969941329347e2f41a222f94c63138 <> Date: Tue Aug 26 2014 13:31:05 UTC\n
* http://jquerymobile.com\n
*\n
* Copyright 2010, 2014 jQuery Foundation, Inc. and othercontributors\n
* Released under the MIT license.\n
* http://jquery.org/license\n
*\n
*/\n
\n
\n
(function ( root, doc, factory ) {\n
\tif ( typeof define === "function" && define.amd ) {\n
\t\t// AMD. Register as an anonymous module.\n
\t\tdefine( [ "jquery" ], function ( $ ) {\n
\t\t\tfactory( $, root, doc );\n
\t\t\treturn $.mobile;\n
\t\t});\n
\t} else {\n
\t\t// Browser globals\n
\t\tfactory( root.jQuery, root, doc );\n
\t}\n
}( this, document, function ( jQuery, window, document, undefined ) {\n
(function( $ ) {\n
\t$.mobile = {};\n
}( jQuery ));\n
\n
(function( $, window, undefined ) {\n
\t$.extend( $.mobile, {\n
\n
\t\t// Version of the jQuery Mobile Framework\n
\t\tversion: "1.5.0-pre",\n
\n
\t\t// Deprecated and no longer used in 1.4 remove in 1.5\n
\t\t// Define the url parameter used for referencing widget-generated sub-pages.\n
\t\t// Translates to example.html&ui-page=subpageIdentifier\n
\t\t// hash segment before &ui-page= is used to make Ajax request\n
\t\tsubPageUrlKey: "ui-page",\n
\n
\t\thideUrlBar: true,\n
\n
\t\t// Keepnative Selector\n
\t\tkeepNative: ":jqmData(role=\'none\'), :jqmData(role=\'nojs\')",\n
\n
\t\t// Deprecated in 1.4 remove in 1.5\n
\t\t// Class assigned to page currently in view, and during transitions\n
\t\tactivePageClass: "ui-page-active",\n
\n
\t\t// Deprecated in 1.4 remove in 1.5\n
\t\t// Class used for "active" button state, from CSS framework\n
\t\tactiveBtnClass: "ui-btn-active",\n
\n
\t\t// Deprecated in 1.4 remove in 1.5\n
\t\t// Class used for "focus" form element state, from CSS framework\n
\t\tfocusClass: "ui-focus",\n
\n
\t\t// Automatically handle clicks and form submissions through Ajax, when same-domain\n
\t\tajaxEnabled: true,\n
\n
\t\t// Automatically load and show pages based on location.hash\n
\t\thashListeningEnabled: true,\n
\n
\t\t// disable to prevent jquery from bothering with links\n
\t\tlinkBindingEnabled: true,\n
\n
\t\t// Set default page transition - \'none\' for no transitions\n
\t\tdefaultPageTransition: "fade",\n
\n
\t\t// Set maximum window width for transitions to apply - \'false\' for no limit\n
\t\tmaxTransitionWidth: false,\n
\n
\t\t// Minimum scroll distance that will be remembered when returning to a page\n
\t\t// Deprecated remove in 1.5\n
\t\tminScrollBack: 0,\n
\n
\t\t// Set default dialog transition - \'none\' for no transitions\n
\t\tdefaultDialogTransition: "pop",\n
\n
\t\t// Error response message - appears when an Ajax page request fails\n
\t\tpageLoadErrorMessage: "Error Loading Page",\n
\n
\t\t// For error messages, which theme does the box use?\n
\t\tpageLoadErrorMessageTheme: "a",\n
\n
\t\t// replace calls to window.history.back with phonegaps navigation helper\n
\t\t// where it is provided on the window object\n
\t\tphonegapNavigationEnabled: false,\n
\n
\t\t//automatically initialize the DOM when it\'s ready\n
\t\tautoInitializePage: true,\n
\n
\t\tpushStateEnabled: true,\n
\n
\t\t// allows users to opt in to ignoring content by marking a parent element as\n
\t\t// data-ignored\n
\t\tignoreContentEnabled: false,\n
\n
\t\tbuttonMarkup: {\n
\t\t\thoverDelay: 200\n
\t\t},\n
\n
\t\t// disable the alteration of the dynamic base tag or links in the case\n
\t\t// that a dynamic base tag isn\'t supported\n
\t\tdynamicBaseEnabled: true,\n
\n
\t\t// default the property to remove dependency on assignment in init module\n
\t\tpageContainer: $(),\n
\n
\t\t//enable cross-domain page support\n
\t\tallowCrossDomainPages: false,\n
\n
\t\tdialogHashKey: "&ui-state=dialog"\n
\t});\n
})( jQuery, this );\n
\n
(function( $, window, undefined ) {\n
\tvar nsNormalizeDict = {},\n
\t\toldFind = $.find,\n
\t\trbrace = /(?:\\{[\\s\\S]*\\}|\\[[\\s\\S]*\\])$/,\n
\t\tjqmDataRE = /:jqmData\\(([^)]*)\\)/g;\n
\n
\t$.extend( $.mobile, {\n
\n
\t\t// Namespace used framework-wide for data-attrs. Default is no namespace\n
\n
\t\tns: "",\n
\n
\t\t// Retrieve an attribute from an element and perform some massaging of the value\n
\n
\t\tgetAttribute: function( element, key ) {\n
\t\t\tvar data;\n
\n
\t\t\telement = element.jquery ? element[0] : element;\n
\n
\t\t\tif ( element && element.getAttribute ) {\n
\t\t\t\tdata = element.getAttribute( "data-" + $.mobile.ns + key );\n
\t\t\t}\n
\n
\t\t\t// Copied from core\'s src/data.js:dataAttr()\n
\t\t\t// Convert from a string to a proper data type\n
\t\t\ttry {\n
\t\t\t\tdata = data === "true" ? true :\n
\t\t\t\t\tdata === "false" ? false :\n
\t\t\t\t\tdata === "null" ? null :\n
\t\t\t\t\t// Only convert to a number if it doesn\'t change the string\n
\t\t\t\t\t+data + "" === data ? +data :\n
\t\t\t\t\trbrace.test( data ) ? JSON.parse( data ) :\n
\t\t\t\t\tdata;\n
\t\t\t} catch( err ) {}\n
\n
\t\t\treturn data;\n
\t\t},\n
\n
\t\t// Expose our cache for testing purposes.\n
\t\tnsNormalizeDict: nsNormalizeDict,\n
\n
\t\t// Take a data attribute property, prepend the namespace\n
\t\t// and then camel case the attribute string. Add the result\n
\t\t// to our nsNormalizeDict so we don\'t have to do this again.\n
\t\tnsNormalize: function( prop ) {\n
\t\t\treturn nsNormalizeDict[ prop ] ||\n
\t\t\t\t( nsNormalizeDict[ prop ] = $.camelCase( $.mobile.ns + prop ) );\n
\t\t},\n
\n
\t\t// Find the closest javascript page element to gather settings data jsperf test\n
\t\t// http://jsperf.com/single-complex-selector-vs-many-complex-selectors/edit\n
\t\t// possibly naive, but it shows that the parsing overhead for *just* the page selector vs\n
\t\t// the page and dialog selector is negligable. This could probably be speed up by\n
\t\t// doing a similar parent node traversal to the one found in the inherited theme code above\n
\t\tclosestPageData: function( $target ) {\n
\t\t\treturn $target\n
\t\t\t\t.closest( ":jqmData(role=\'page\'), :jqmData(role=\'dialog\')" )\n
\t\t\t\t.data( "mobile-page" );\n
\t\t}\n
\n
\t});\n
\n
\t// Mobile version of data and removeData and hasData methods\n
\t// ensures all data is set and retrieved using jQuery Mobile\'s data namespace\n
\t$.fn.jqmData = function( prop, value ) {\n
\t\tvar result;\n
\t\tif ( typeof prop !== "undefined" ) {\n
\t\t\tif ( prop ) {\n
\t\t\t\tprop = $.mobile.nsNormalize( prop );\n
\t\t\t}\n
\n
\t\t\t// undefined is permitted as an explicit input for the second param\n
\t\t\t// in this case it returns the value and does not set it to undefined\n
\t\t\tif ( arguments.length < 2 || value === undefined ) {\n
\t\t\t\tresult = this.data( prop );\n
\t\t\t} else {\n
\t\t\t\tresult = this.data( prop, value );\n
\t\t\t}\n
\t\t}\n
\t\treturn result;\n
\t};\n
\n
\t$.jqmData = function( elem, prop, value ) {\n
\t\tvar result;\n
\t\tif ( typeof prop !== "undefined" ) {\n
\t\t\tresult = $.data( elem, prop ? $.mobile.nsNormalize( prop ) : prop, value );\n
\t\t}\n
\t\treturn result;\n
\t};\n
\n
\t$.fn.jqmRemoveData = function( prop ) {\n
\t\treturn this.removeData( $.mobile.nsNormalize( prop ) );\n
\t};\n
\n
\t$.jqmRemoveData = function( elem, prop ) {\n
\t\treturn $.removeData( elem, $.mobile.nsNormalize( prop ) );\n
\t};\n
\n
\t$.find = function( selector, context, ret, extra ) {\n
\t\tif ( selector.indexOf( ":jqmData" ) > -1 ) {\n
\t\t\tselector = selector.replace( jqmDataRE, "[data-" + ( $.mobile.ns || "" ) + "$1]" );\n
\t\t}\n
\n
\t\treturn oldFind.call( this, selector, context, ret, extra );\n
\t};\n
\n
\t$.extend( $.find, oldFind );\n
\n
})( jQuery, this );\n
\n
/*!\n
 * jQuery UI Core c0ab71056b936627e8a7821f03c044aec6280a40\n
 * http://jqueryui.com\n
 *\n
 * Copyright 2013 jQuery Foundation and other contributors\n
 * Released under the MIT license.\n
 * http://jquery.org/license\n
 *\n
 * http://api.jqueryui.com/category/ui-core/\n
 */\n
(function( $, undefined ) {\n
\n
var uuid = 0,\n
\truniqueId = /^ui-id-\\d+$/;\n
\n
// $.ui might exist from components with no dependencies, e.g., $.ui.position\n
$.ui = $.ui || {};\n
\n
$.extend( $.ui, {\n
\tversion: "c0ab71056b936627e8a7821f03c044aec6280a40",\n
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
\t\treturn ( /fixed/ ).test( this.css( "position") ) || !scrollParent.length ? $( this[ 0 ].ownerDocument || document ) : scrollParent;\n
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
\t}\n
});\n
\n
// $.ui.plugin is deprecated. Use $.widget() extensions instead.\n
$.ui.plugin = {\n
\tadd: function( module, option, set ) {\n
\t\tvar i,\n
\t\t\tproto = $.ui[ module ].prototype;\n
\t\tfor ( i in set ) {\n
\t\t\tproto.plugins[ i ] = proto.plugins[ i ] || [];\n
\t\t\tproto.plugins[ i ].push( [ option, set[ i ] ] );\n
\t\t}\n
\t},\n
\tcall: function( instance, name, args, allowDisconnected ) {\n
\t\tvar i,\n
\t\t\tset = instance.plugins[ name ];\n
\n
\t\tif ( !set ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( !allowDisconnected && ( !instance.element[ 0 ].parentNode || instance.element[ 0 ].parentNode.nodeType === 11 ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tfor ( i = 0; i < set.length; i++ ) {\n
\t\t\tif ( instance.options[ set[ i ][ 0 ] ] ) {\n
\t\t\t\tset[ i ][ 1 ].apply( instance.element, args );\n
\t\t\t}\n
\t\t}\n
\t}\n
};\n
\n
})( jQuery );\n
\n
(function( $, window, undefined ) {\n
\n
\t// Subtract the height of external toolbars from the page height, if the page does not have\n
\t// internal toolbars of the same type\n
\tvar compensateToolbars = function( page, desiredHeight ) {\n
\t\tvar pageParent = page.parent(),\n
\t\t\ttoolbarsAffectingHeight = [],\n
\t\t\texternalHeaders = pageParent.children( ":jqmData(role=\'header\')" ),\n
\t\t\tinternalHeaders = page.children( ":jqmData(role=\'header\')" ),\n
\t\t\texternalFooters = pageParent.children( ":jqmData(role=\'footer\')" ),\n
\t\t\tinternalFooters = page.children( ":jqmData(role=\'footer\')" );\n
\n
\t\t// If we have no internal headers, but we do have external headers, then their height\n
\t\t// reduces the page height\n
\t\tif ( internalHeaders.length === 0 && externalHeaders.length > 0 ) {\n
\t\t\ttoolbarsAffectingHeight = toolbarsAffectingHeight.concat( externalHeaders.toArray() );\n
\t\t}\n
\n
\t\t// If we have no internal footers, but we do have external footers, then their height\n
\t\t// reduces the page height\n
\t\tif ( internalFooters.length === 0 && externalFooters.length > 0 ) {\n
\t\t\ttoolbarsAffectingHeight = toolbarsAffectingHeight.concat( externalFooters.toArray() );\n
\t\t}\n
\n
\t\t$.each( toolbarsAffectingHeight, function( index, value ) {\n
\t\t\tdesiredHeight -= $( value ).outerHeight();\n
\t\t});\n
\n
\t\t// Height must be at least zero\n
\t\treturn Math.max( 0, desiredHeight );\n
\t};\n
\n
\t$.extend( $.mobile, {\n
\t\t// define the window and the document objects\n
\t\twindow: $( window ),\n
\t\tdocument: $( document ),\n
\n
\t\t// TODO: Remove and use $.ui.keyCode directly\n
\t\tkeyCode: $.ui.keyCode,\n
\n
\t\t// Place to store various widget extensions\n
\t\tbehaviors: {},\n
\n
\t\t// Scroll page vertically: scroll to 0 to hide iOS address bar, or pass a Y value\n
\t\tsilentScroll: function( ypos ) {\n
\t\t\tif ( $.type( ypos ) !== "number" ) {\n
\t\t\t\typos = $.mobile.defaultHomeScroll;\n
\t\t\t}\n
\n
\t\t\t// prevent scrollstart and scrollstop events\n
\t\t\t$.event.special.scrollstart.enabled = false;\n
\n
\t\t\tsetTimeout(function() {\n
\t\t\t\twindow.scrollTo( 0, ypos );\n
\t\t\t\t$.mobile.document.trigger( "silentscroll", { x: 0, y: ypos });\n
\t\t\t}, 20 );\n
\n
\t\t\tsetTimeout(function() {\n
\t\t\t\t$.event.special.scrollstart.enabled = true;\n
\t\t\t}, 150 );\n
\t\t},\n
\n
\t\tgetClosestBaseUrl: function( ele )\t{\n
\t\t\t// Find the closest page and extract out its url.\n
\t\t\tvar url = $( ele ).closest( ".ui-page" ).jqmData( "url" ),\n
\t\t\t\tbase = $.mobile.path.documentBase.hrefNoHash;\n
\n
\t\t\tif ( !$.mobile.dynamicBaseEnabled || !url || !$.mobile.path.isPath( url ) ) {\n
\t\t\t\turl = base;\n
\t\t\t}\n
\n
\t\t\treturn $.mobile.path.makeUrlAbsolute( url, base );\n
\t\t},\n
\t\tremoveActiveLinkClass: function( forceRemoval ) {\n
\t\t\tif ( !!$.mobile.activeClickedLink &&\n
\t\t\t\t( !$.mobile.activeClickedLink.closest( "." + $.mobile.activePageClass ).length ||\n
\t\t\t\t\tforceRemoval ) ) {\n
\n
\t\t\t\t$.mobile.activeClickedLink.removeClass( $.mobile.activeBtnClass );\n
\t\t\t}\n
\t\t\t$.mobile.activeClickedLink = null;\n
\t\t},\n
\n
\t\t// DEPRECATED in 1.4\n
\t\t// Find the closest parent with a theme class on it. Note that\n
\t\t// we are not using $.fn.closest() on purpose here because this\n
\t\t// method gets called quite a bit and we need it to be as fast\n
\t\t// as possible.\n
\t\tgetInheritedTheme: function( el, defaultTheme ) {\n
\t\t\tvar e = el[ 0 ],\n
\t\t\t\tltr = "",\n
\t\t\t\tre = /ui-(bar|body|overlay)-([a-z])\\b/,\n
\t\t\t\tc, m;\n
\t\t\twhile ( e ) {\n
\t\t\t\tc = e.className || "";\n
\t\t\t\tif ( c && ( m = re.exec( c ) ) && ( ltr = m[ 2 ] ) ) {\n
\t\t\t\t\t// We found a parent with a theme class\n
\t\t\t\t\t// on it so bail from this loop.\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\te = e.parentNode;\n
\t\t\t}\n
\t\t\t// Return the theme letter we found, if none, return the\n
\t\t\t// specified default.\n
\t\t\treturn ltr || defaultTheme || "a";\n
\t\t},\n
\n
\t\tenhanceable: function( elements ) {\n
\t\t\treturn this.haveParents( elements, "enhance" );\n
\t\t},\n
\n
\t\thijackable: function( elements ) {\n
\t\t\treturn this.haveParents( elements, "ajax" );\n
\t\t},\n
\n
\t\thaveParents: function( elements, attr ) {\n
\t\t\tif ( !$.mobile.ignoreContentEnabled ) {\n
\t\t\t\treturn elements;\n
\t\t\t}\n
\n
\t\t\tvar count = elements.length,\n
\t\t\t\t$newSet = $(),\n
\t\t\t\te, $element, excluded,\n
\t\t\t\ti, c;\n
\n
\t\t\tfor ( i = 0; i < count; i++ ) {\n
\t\t\t\t$element = elements.eq( i );\n
\t\t\t\texcluded = false;\n
\t\t\t\te = elements[ i ];\n
\n
\t\t\t\twhile ( e ) {\n
\t\t\t\t\tc = e.getAttribute ? e.getAttribute( "data-" + $.mobile.ns + attr ) : "";\n
\n
\t\t\t\t\tif ( c === "false" ) {\n
\t\t\t\t\t\texcluded = true;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\te = e.parentNode;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( !excluded ) {\n
\t\t\t\t\t$newSet = $newSet.add( $element );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn $newSet;\n
\t\t},\n
\n
\t\tgetScreenHeight: function() {\n
\t\t\t// Native innerHeight returns more accurate value for this across platforms,\n
\t\t\t// jQuery version is here as a normalized fallback for platforms like Symbian\n
\t\t\treturn window.innerHeight || $.mobile.window.height();\n
\t\t},\n
\n
\t\t//simply set the active page\'s minimum height to screen height, depending on orientation\n
\t\tresetActivePageHeight: function( height ) {\n
\t\t\tvar page = $( "." + $.mobile.activePageClass ),\n
\t\t\t\tpageHeight = page.height(),\n
\t\t\t\tpageOuterHeight = page.outerHeight( true );\n
\n
\t\t\theight = compensateToolbars( page,\n
\t\t\t\t( typeof height === "number" ) ? height : $.mobile.getScreenHeight() );\n
\n
\t\t\t// Remove any previous min-height setting\n
\t\t\tpage.css( "min-height", "" );\n
\n
\t\t\t// Set the minimum height only if the height as determined by CSS is insufficient\n
\t\t\tif ( page.height() < height ) {\n
\t\t\t\tpage.css( "min-height", height - ( pageOuterHeight - pageHeight ) );\n
\t\t\t}\n
\t\t},\n
\n
\t\tloading: function() {\n
\t\t\t// If this is the first call to this function, instantiate a loader widget\n
\t\t\tvar loader = this.loading._widget || $( $.mobile.loader.prototype.defaultHtml ).loader(),\n
\n
\t\t\t\t// Call the appropriate method on the loader\n
\t\t\t\treturnValue = loader.loader.apply( loader, arguments );\n
\n
\t\t\t// Make sure the loader is retained for future calls to this function.\n
\t\t\tthis.loading._widget = loader;\n
\n
\t\t\treturn returnValue;\n
\t\t}\n
\t});\n
\n
\t$.addDependents = function( elem, newDependents ) {\n
\t\tvar $elem = $( elem ),\n
\t\t\tdependents = $elem.jqmData( "dependents" ) || $();\n
\n
\t\t$elem.jqmData( "dependents", $( dependents ).add( newDependents ) );\n
\t};\n
\n
\t// plugins\n
\t$.fn.extend({\n
\t\tremoveWithDependents: function() {\n
\t\t\t$.removeWithDependents( this );\n
\t\t},\n
\n
\t\t// Enhance child elements\n
\t\tenhanceWithin: function() {\n
\t\t\tvar index,\n
\t\t\t\twidgetElements = {},\n
\t\t\t\tkeepNative = $.mobile.page.prototype.keepNativeSelector(),\n
\t\t\t\tthat = this;\n
\n
\t\t\t// Add no js class to elements\n
\t\t\tif ( $.mobile.nojs ) {\n
\t\t\t\t$.mobile.nojs( this );\n
\t\t\t}\n
\n
\t\t\t// Bind links for ajax nav\n
\t\t\tif ( $.mobile.links ) {\n
\t\t\t\t$.mobile.links( this );\n
\t\t\t}\n
\n
\t\t\t// Degrade inputs for styleing\n
\t\t\tif ( $.mobile.degradeInputsWithin ) {\n
\t\t\t\t$.mobile.degradeInputsWithin( this );\n
\t\t\t}\n
\n
\t\t\t// Run buttonmarkup\n
\t\t\tif ( $.fn.buttonMarkup ) {\n
\t\t\t\tthis.find( $.fn.buttonMarkup.initSelector ).not( keepNative )\n
\t\t\t\t.jqmEnhanceable().buttonMarkup();\n
\t\t\t}\n
\n
\t\t\t// Add classes for fieldContain\n
\t\t\tif ( $.fn.fieldcontain ) {\n
\t\t\t\tthis.find( ":jqmData(role=\'fieldcontain\')" ).not( keepNative )\n
\t\t\t\t.jqmEnhanceable().fieldcontain();\n
\t\t\t}\n
\n
\t\t\t// Enhance widgets\n
\t\t\t$.each( $.mobile.widgets, function( name, constructor ) {\n
\n
\t\t\t\t// If initSelector not false find elements\n
\t\t\t\tif ( constructor.initSelector ) {\n
\n
\t\t\t\t\t// Filter elements that should not be enhanced based on parents\n
\t\t\t\t\tvar elements = $.mobile.enhanceable( that.find( constructor.initSelector ) );\n
\n
\t\t\t\t\t// If any matching elements remain filter ones with keepNativeSelector\n
\t\t\t\t\tif ( elements.length > 0 ) {\n
\n
\t\t\t\t\t\t// $.mobile.page.prototype.keepNativeSelector is deprecated this is just for backcompat\n
\t\t\t\t\t\t// Switch to $.mobile.keepNative in 1.5 which is just a value not a function\n
\t\t\t\t\t\telements = elements.not( keepNative );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Enhance whatever is left\n
\t\t\t\t\tif ( elements.length > 0 ) {\n
\t\t\t\t\t\twidgetElements[ constructor.prototype.widgetName ] = elements;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\tfor ( index in widgetElements ) {\n
\t\t\t\twidgetElements[ index ][ index ]();\n
\t\t\t}\n
\n
\t\t\treturn this;\n
\t\t},\n
\n
\t\taddDependents: function( newDependents ) {\n
\t\t\t$.addDependents( this, newDependents );\n
\t\t},\n
\n
\t\t// note that this helper doesn\'t attempt to handle the callback\n
\t\t// or setting of an html element\'s text, its only purpose is\n
\t\t// to return the html encoded version of the text in all cases. (thus the name)\n
\t\tgetEncodedText: function() {\n
\t\t\treturn $( "<a>" ).text( this.text() ).html();\n
\t\t},\n
\n
\t\t// fluent helper function for the mobile namespaced equivalent\n
\t\tjqmEnhanceable: function() {\n
\t\t\treturn $.mobile.enhanceable( this );\n
\t\t},\n
\n
\t\tjqmHijackable: function() {\n
\t\t\treturn $.mobile.hijackable( this );\n
\t\t}\n
\t});\n
\n
\t$.removeWithDependents = function( nativeElement ) {\n
\t\tvar element = $( nativeElement );\n
\n
\t\t( element.jqmData( "dependents" ) || $() ).remove();\n
\t\telement.remove();\n
\t};\n
\t$.addDependents = function( nativeElement, newDependents ) {\n
\t\tvar element = $( nativeElement ),\n
\t\t\tdependents = element.jqmData( "dependents" ) || $();\n
\n
\t\telement.jqmData( "dependents", $( dependents ).add( newDependents ) );\n
\t};\n
\n
\t$.find.matches = function( expr, set ) {\n
\t\treturn $.find( expr, null, null, set );\n
\t};\n
\n
\t$.find.matchesSelector = function( node, expr ) {\n
\t\treturn $.find( expr, null, null, [ node ] ).length > 0;\n
\t};\n
\n
})( jQuery, this );\n
\n
\n
/*!\n
 * jQuery UI Widget c0ab71056b936627e8a7821f03c044aec6280a40\n
 * http://jqueryui.com\n
 *\n
 * Copyright 2013 jQuery Foundation and other contributors\n
 * Released under the MIT license.\n
 * http://jquery.org/license\n
 *\n
 * http://api.jqueryui.com/jQuery.widget/\n
 */\n
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
\n
\treturn constructor;\n
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
\t\t\t\tif ( options === "instance" ) {\n
\t\t\t\t\treturnValue = instance;\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
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
\t\t\t\tif ( value === undefined ) {\n
\t\t\t\t\treturn curOption[ key ] === undefined ? null : curOption[ key ];\n
\t\t\t\t}\n
\t\t\t\tcurOption[ key ] = value;\n
\t\t\t} else {\n
\t\t\t\tif ( value === undefined ) {\n
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
\t\t\t\t.toggleClass( this.widgetFullName + "-disabled", !!value );\n
\t\t\tthis.hoverable.removeClass( "ui-state-hover" );\n
\t\t\tthis.focusable.removeClass( "ui-state-focus" );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tenable: function() {\n
\t\treturn this._setOptions({ disabled: false });\n
\t},\n
\tdisable: function() {\n
\t\treturn this._setOptions({ disabled: true });\n
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
\n
(function( $, undefined ) {\n
\n
var rcapitals = /[A-Z]/g,\n
\treplaceFunction = function( c ) {\n
\t\treturn "-" + c.toLowerCase();\n
\t};\n
\n
$.extend( $.Widget.prototype, {\n
\t_getCreateOptions: function() {\n
\t\tvar option, value,\n
\t\t\telem = this.element[ 0 ],\n
\t\t\toptions = {};\n
\n
\t\t//\n
\t\tif ( !$.mobile.getAttribute( elem, "defaults" ) ) {\n
\t\t\tfor ( option in this.options ) {\n
\t\t\t\tvalue = $.mobile.getAttribute( elem, option.replace( rcapitals, replaceFunction ) );\n
\n
\t\t\t\tif ( value != null ) {\n
\t\t\t\t\toptions[ option ] = value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn options;\n
\t}\n
});\n
\n
//TODO: Remove in 1.5 for backcompat only\n
$.mobile.widget = $.Widget;\n
\n
})( jQuery );\n
\n
\n
(function( $ ) {\n
\t// TODO move loader class down into the widget settings\n
\tvar loaderClass = "ui-loader", $html = $( "html" );\n
\n
\t$.widget( "mobile.loader", {\n
\t\t// NOTE if the global config settings are defined they will override these\n
\t\t//      options\n
\t\toptions: {\n
\t\t\t// the theme for the loading message\n
\t\t\ttheme: "a",\n
\n
\t\t\t// whether the text in the loading message is shown\n
\t\t\ttextVisible: false,\n
\n
\t\t\t// custom html for the inner content of the loading message\n
\t\t\thtml: "",\n
\n
\t\t\t// the text to be displayed when the popup is shown\n
\t\t\ttext: "loading"\n
\t\t},\n
\n
\t\tdefaultHtml: "<div class=\'" + loaderClass + "\'>" +\n
\t\t\t"<span class=\'ui-icon-loading\'></span>" +\n
\t\t\t"<h1></h1>" +\n
\t\t\t"</div>",\n
\n
\t\t// For non-fixed supportin browsers. Position at y center (if scrollTop supported), above the activeBtn (if defined), or just 100px from top\n
\t\tfakeFixLoader: function() {\n
\t\t\tvar activeBtn = $( "." + $.mobile.activeBtnClass ).first();\n
\n
\t\t\tthis.element\n
\t\t\t\t.css({\n
\t\t\t\t\ttop: $.support.scrollTop && this.window.scrollTop() + this.window.height() / 2 ||\n
\t\t\t\t\t\tactiveBtn.length && activeBtn.offset().top || 100\n
\t\t\t\t});\n
\t\t},\n
\n
\t\t// check position of loader to see if it appears to be "fixed" to center\n
\t\t// if not, use abs positioning\n
\t\tcheckLoaderPosition: function() {\n
\t\t\tvar offset = this.element.offset(),\n
\t\t\t\tscrollTop = this.window.scrollTop(),\n
\t\t\t\tscreenHeight = $.mobile.getScreenHeight();\n
\n
\t\t\tif ( offset.top < scrollTop || ( offset.top - scrollTop ) > screenHeight ) {\n
\t\t\t\tthis.element.addClass( "ui-loader-fakefix" );\n
\t\t\t\tthis.fakeFixLoader();\n
\t\t\t\tthis.window\n
\t\t\t\t\t.unbind( "scroll", this.checkLoaderPosition )\n
\t\t\t\t\t.bind( "scroll", $.proxy( this.fakeFixLoader, this ) );\n
\t\t\t}\n
\t\t},\n
\n
\t\tresetHtml: function() {\n
\t\t\tthis.element.html( $( this.defaultHtml ).html() );\n
\t\t},\n
\n
\t\t// Turn on/off page loading message. Theme doubles as an object argument\n
\t\t// with the following shape: { theme: \'\', text: \'\', html: \'\', textVisible: \'\' }\n
\t\t// NOTE that the $.mobile.loading* settings and params past the first are deprecated\n
\t\t// TODO sweet jesus we need to break some of this out\n
\t\tshow: function( theme, msgText, textonly ) {\n
\t\t\tvar textVisible, message, loadSettings;\n
\n
\t\t\tthis.resetHtml();\n
\n
\t\t\t// use the prototype options so that people can set them globally at\n
\t\t\t// mobile init. Consistency, it\'s what\'s for dinner\n
\t\t\tif ( $.type( theme ) === "object" ) {\n
\t\t\t\tloadSettings = $.extend( {}, this.options, theme );\n
\n
\t\t\t\ttheme = loadSettings.theme;\n
\t\t\t} else {\n
\t\t\t\tloadSettings = this.options;\n
\n
\t\t\t\t// here we prefer the theme value passed as a string argument, then\n
\t\t\t\t// we prefer the global option because we can\'t use undefined default\n
\t\t\t\t// prototype options, then the prototype option\n
\t\t\t\ttheme = theme || loadSettings.theme;\n
\t\t\t}\n
\n
\t\t\t// set the message text, prefer the param, then the settings object\n
\t\t\t// then loading message\n
\t\t\tmessage = msgText || ( loadSettings.text === false ? "" : loadSettings.text );\n
\n
\t\t\t// prepare the dom\n
\t\t\t$html.addClass( "ui-loading" );\n
\n
\t\t\ttextVisible = loadSettings.textVisible;\n
\n
\t\t\t// add the proper css given the options (theme, text, etc)\n
\t\t\t// Force text visibility if the second argument was supplied, or\n
\t\t\t// if the text was explicitly set in the object args\n
\t\t\tthis.element.attr("class", loaderClass +\n
\t\t\t\t" ui-corner-all ui-body-" + theme +\n
\t\t\t\t" ui-loader-" + ( textVisible || msgText || theme.text ? "verbose" : "default" ) +\n
\t\t\t\t( loadSettings.textonly || textonly ? " ui-loader-textonly" : "" ) );\n
\n
\t\t\t// TODO verify that jquery.fn.html is ok to use in both cases here\n
\t\t\t//      this might be overly defensive in preventing unknowing xss\n
\t\t\t// if the html attribute is defined on the loading settings, use that\n
\t\t\t// otherwise use the fallbacks from above\n
\t\t\tif ( loadSettings.html ) {\n
\t\t\t\tthis.element.html( loadSettings.html );\n
\t\t\t} else {\n
\t\t\t\tthis.element.find( "h1" ).text( message );\n
\t\t\t}\n
\n
\t\t\t// attach the loader to the DOM\n
\t\t\tthis.element.appendTo( $.mobile.pageContainer );\n
\n
\t\t\t// check that the loader is visible\n
\t\t\tthis.checkLoaderPosition();\n
\n
\t\t\t// on scroll check the loader position\n
\t\t\tthis.window.bind( "scroll", $.proxy( this.checkLoaderPosition, this ) );\n
\t\t},\n
\n
\t\thide: function() {\n
\t\t\t$html.removeClass( "ui-loading" );\n
\n
\t\t\tif ( this.options.text ) {\n
\t\t\t\tthis.element.removeClass( "ui-loader-fakefix" );\n
\t\t\t}\n
\n
\t\t\t$.mobile.window.unbind( "scroll", this.fakeFixLoader );\n
\t\t\t$.mobile.window.unbind( "scroll", this.checkLoaderPosition );\n
\t\t}\n
\t});\n
\n
})(jQuery, this);\n
\n
\n
(function( $, undefined ) {\n
\n
\t/*! matchMedia() polyfill - Test a CSS media type/query in JS. Authors & copyright (c) 2012: Scott Jehl, Paul Irish, Nicholas Zakas. Dual MIT/BSD license */\n
\twindow.matchMedia = window.matchMedia || (function( doc, undefined ) {\n
\n
\t\tvar bool,\n
\t\t\tdocElem = doc.documentElement,\n
\t\t\trefNode = docElem.firstElementChild || docElem.firstChild,\n
\t\t\t// fakeBody required for <FF4 when executed in <head>\n
\t\t\tfakeBody = doc.createElement( "body" ),\n
\t\t\tdiv = doc.createElement( "div" );\n
\n
\t\tdiv.id = "mq-test-1";\n
\t\tdiv.style.cssText = "position:absolute;top:-100em";\n
\t\tfakeBody.style.background = "none";\n
\t\tfakeBody.appendChild(div);\n
\n
\t\treturn function(q){\n
\n
\t\t\tdiv.innerHTML = "&shy;<style media=\\"" + q + "\\"> #mq-test-1 { width: 42px; }</style>";\n
\n
\t\t\tdocElem.insertBefore( fakeBody, refNode );\n
\t\t\tbool = div.offsetWidth === 42;\n
\t\t\tdocElem.removeChild( fakeBody );\n
\n
\t\t\treturn {\n
\t\t\t\tmatches: bool,\n
\t\t\t\tmedia: q\n
\t\t\t};\n
\n
\t\t};\n
\n
\t}( document ));\n
\n
\t// $.mobile.media uses matchMedia to return a boolean.\n
\t$.mobile.media = function( q ) {\n
\t\treturn window.matchMedia( q ).matches;\n
\t};\n
\n
})(jQuery);\n
\n
\t(function( $, undefined ) {\n
\t\tvar support = {\n
\t\t\ttouch: "ontouchend" in document\n
\t\t};\n
\n
\t\t$.mobile.support = $.mobile.support || {};\n
\t\t$.extend( $.support, support );\n
\t\t$.extend( $.mobile.support, support );\n
\t}( jQuery ));\n
\n
\t(function( $, undefined ) {\n
\t\t$.extend( $.support, {\n
\t\t\torientation: "orientation" in window && "onorientationchange" in window\n
\t\t});\n
\t}( jQuery ));\n
\n
(function( $, undefined ) {\n
\n
// thx Modernizr\n
function propExists( prop ) {\n
\tvar uc_prop = prop.charAt( 0 ).toUpperCase() + prop.substr( 1 ),\n
\t\tprops = ( prop + " " + vendors.join( uc_prop + " " ) + uc_prop ).split( " " ),\n
\t\tv;\n
\n
\tfor ( v in props ) {\n
\t\tif ( fbCSS[ props[ v ] ] !== undefined ) {\n
\t\t\treturn true;\n
\t\t}\n
\t}\n
}\n
\n
var fakeBody = $( "<body>" ).prependTo( "html" ),\n
\tfbCSS = fakeBody[ 0 ].style,\n
\tvendors = [ "Webkit", "Moz", "O" ],\n
\twebos = "palmGetResource" in window, //only used to rule out scrollTop\n
\toperamini = window.operamini && ({}).toString.call( window.operamini ) === "[object OperaMini]",\n
\tbb = window.blackberry && !propExists( "-webkit-transform" ), //only used to rule out box shadow, as it\'s filled opaque on BB 5 and lower\n
\tnokiaLTE7_3;\n
\n
// inline SVG support test\n
function inlineSVG() {\n
\t// Thanks Modernizr & Erik Dahlstrom\n
\tvar w = window,\n
\t\tsvg = !!w.document.createElementNS && !!w.document.createElementNS( "http://www.w3.org/2000/svg", "svg" ).createSVGRect && !( w.opera && navigator.userAgent.indexOf( "Chrome" ) === -1 ),\n
\t\tsupport = function( data ) {\n
\t\t\tif ( !( data && svg ) ) {\n
\t\t\t\t$( "html" ).addClass( "ui-nosvg" );\n
\t\t\t}\n
\t\t},\n
\t\timg = new w.Image();\n
\n
\timg.onerror = function() {\n
\t\tsupport( false );\n
\t};\n
\timg.onload = function() {\n
\t\tsupport( img.width === 1 && img.height === 1 );\n
\t};\n
\timg.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";\n
}\n
\n
function transform3dTest() {\n
\tvar mqProp = "transform-3d",\n
\t\t// Because the `translate3d` test below throws false positives in Android:\n
\t\tret = $.mobile.media( "(-" + vendors.join( "-" + mqProp + "),(-" ) + "-" + mqProp + "),(" + mqProp + ")" ),\n
\t\tel, transforms, t;\n
\n
\tif ( ret ) {\n
\t\treturn !!ret;\n
\t}\n
\n
\tel = document.createElement( "div" );\n
\ttransforms = {\n
\t\t// Weâ€™re omitting Opera for the time being; MS uses unprefixed.\n
\t\t"MozTransform": "-moz-transform",\n
\t\t"transform": "transform"\n
\t};\n
\n
\tfakeBody.append( el );\n
\n
\tfor ( t in transforms ) {\n
\t\tif ( el.style[ t ] !== undefined ) {\n
\t\t\tel.style[ t ] = "translate3d( 100px, 1px, 1px )";\n
\t\t\tret = window.getComputedStyle( el ).getPropertyValue( transforms[ t ] );\n
\t\t}\n
\t}\n
\treturn ( !!ret && ret !== "none" );\n
}\n
\n
// Test for dynamic-updating base tag support ( allows us to avoid href,src attr rewriting )\n
function baseTagTest() {\n
\tvar fauxBase = location.protocol + "//" + location.host + location.pathname + "ui-dir/",\n
\t\tbase = $( "head base" ),\n
\t\tfauxEle = null,\n
\t\thref = "",\n
\t\tlink, rebase;\n
\n
\tif ( !base.length ) {\n
\t\tbase = fauxEle = $( "<base>", { "href": fauxBase }).appendTo( "head" );\n
\t} else {\n
\t\thref = base.attr( "href" );\n
\t}\n
\n
\tlink = $( "<a href=\'testurl\' />" ).prependTo( fakeBody );\n
\trebase = link[ 0 ].href;\n
\tbase[ 0 ].href = href || location.pathname;\n
\n
\tif ( fauxEle ) {\n
\t\tfauxEle.remove();\n
\t}\n
\treturn rebase.indexOf( fauxBase ) === 0;\n
}\n
\n
// Thanks Modernizr\n
function cssPointerEventsTest() {\n
\tvar element = document.createElement( "x" ),\n
\t\tdocumentElement = document.documentElement,\n
\t\tgetComputedStyle = window.getComputedStyle,\n
\t\tsupports;\n
\n
\tif ( !( "pointerEvents" in element.style ) ) {\n
\t\treturn false;\n
\t}\n
\n
\telement.style.pointerEvents = "auto";\n
\telement.style.pointerEvents = "x";\n
\tdocumentElement.appendChild( element );\n
\tsupports = getComputedStyle &&\n
\tgetComputedStyle( element, "" ).pointerEvents === "auto";\n
\tdocumentElement.removeChild( element );\n
\treturn !!supports;\n
}\n
\n
function boundingRect() {\n
\tvar div = document.createElement( "div" );\n
\treturn typeof div.getBoundingClientRect !== "undefined";\n
}\n
\n
// non-UA-based IE version check by James Padolsey, modified by jdalton - from http://gist.github.com/527683\n
// allows for inclusion of IE 6+, including Windows Mobile 7\n
$.extend( $.mobile, { browser: {} } );\n
$.mobile.browser.oldIE = (function() {\n
\tvar v = 3,\n
\t\tdiv = document.createElement( "div" ),\n
\t\ta = div.all || [];\n
\n
\tdo {\n
\t\tdiv.innerHTML = "<!--[if gt IE " + ( ++v ) + "]><br><![endif]-->";\n
\t} while( a[0] );\n
\n
\treturn v > 4 ? v : !v;\n
})();\n
\n
function fixedPosition() {\n
\tvar w = window,\n
\t\tua = navigator.userAgent,\n
\t\tplatform = navigator.platform,\n
\t\t// Rendering engine is Webkit, and capture major version\n
\t\twkmatch = ua.match( /AppleWebKit\\/([0-9]+)/ ),\n
\t\twkversion = !!wkmatch && wkmatch[ 1 ],\n
\t\tffmatch = ua.match( /Fennec\\/([0-9]+)/ ),\n
\t\tffversion = !!ffmatch && ffmatch[ 1 ],\n
\t\toperammobilematch = ua.match( /Opera Mobi\\/([0-9]+)/ ),\n
\t\tomversion = !!operammobilematch && operammobilematch[ 1 ];\n
\n
\tif (\n
\t\t// iOS 4.3 and older : Platform is iPhone/Pad/Touch and Webkit version is less than 534 (ios5)\n
\t\t( ( platform.indexOf( "iPhone" ) > -1 || platform.indexOf( "iPad" ) > -1  || platform.indexOf( "iPod" ) > -1 ) && wkversion && wkversion < 534 ) ||\n
\t\t// Opera Mini\n
\t\t( w.operamini && ({}).toString.call( w.operamini ) === "[object OperaMini]" ) ||\n
\t\t( operammobilematch && omversion < 7458 )\t||\n
\t\t//Android lte 2.1: Platform is Android and Webkit version is less than 533 (Android 2.2)\n
\t\t( ua.indexOf( "Android" ) > -1 && wkversion && wkversion < 533 ) ||\n
\t\t// Firefox Mobile before 6.0 -\n
\t\t( ffversion && ffversion < 6 ) ||\n
\t\t// WebOS less than 3\n
\t\t( "palmGetResource" in window && wkversion && wkversion < 534 )\t||\n
\t\t// MeeGo\n
\t\t( ua.indexOf( "MeeGo" ) > -1 && ua.indexOf( "NokiaBrowser/8.5.0" ) > -1 ) ) {\n
\t\treturn false;\n
\t}\n
\n
\treturn true;\n
}\n
\n
$.extend( $.support, {\n
\t// Note, Chrome for iOS has an extremely quirky implementation of popstate.\n
\t// We\'ve chosen to take the shortest path to a bug fix here for issue #5426\n
\t// See the following link for information about the regex chosen\n
\t// https://developers.google.com/chrome/mobile/docs/user-agent#chrome_for_ios_user-agent\n
\tpushState: "pushState" in history &&\n
\t\t"replaceState" in history &&\n
\t\t// When running inside a FF iframe, calling replaceState causes an error\n
\t\t!( window.navigator.userAgent.indexOf( "Firefox" ) >= 0 && window.top !== window ) &&\n
\t\t( window.navigator.userAgent.search(/CriOS/) === -1 ),\n
\n
\tmediaquery: $.mobile.media( "only all" ),\n
\tcssPseudoElement: !!propExists( "content" ),\n
\ttouchOverflow: !!propExists( "overflowScrolling" ),\n
\tcssTransform3d: transform3dTest(),\n
\tboxShadow: !!propExists( "boxShadow" ) && !bb,\n
\tfixedPosition: fixedPosition(),\n
\tscrollTop: ("pageXOffset" in window ||\n
\t\t"scrollTop" in document.documentElement ||\n
\t\t"scrollTop" in fakeBody[ 0 ]) && !webos && !operamini,\n
\n
\tdynamicBaseTag: baseTagTest(),\n
\tcssPointerEvents: cssPointerEventsTest(),\n
\tboundingRect: boundingRect(),\n
\tinlineSVG: inlineSVG\n
});\n
\n
fakeBody.remove();\n
\n
// $.mobile.ajaxBlacklist is used to override ajaxEnabled on platforms that have known conflicts with hash history updates (BB5, Symbian)\n
// or that generally work better browsing in regular http for full page refreshes (Opera Mini)\n
// Note: This detection below is used as a last resort.\n
// We recommend only using these detection methods when all other more reliable/forward-looking approaches are not possible\n
nokiaLTE7_3 = (function() {\n
\n
\tvar ua = window.navigator.userAgent;\n
\n
\t//The following is an attempt to match Nokia browsers that are running Symbian/s60, with webkit, version 7.3 or older\n
\treturn ua.indexOf( "Nokia" ) > -1 &&\n
\t\t\t( ua.indexOf( "Symbian/3" ) > -1 || ua.indexOf( "Series60/5" ) > -1 ) &&\n
\t\t\tua.indexOf( "AppleWebKit" ) > -1 &&\n
\t\t\tua.match( /(BrowserNG|NokiaBrowser)\\/7\\.[0-3]/ );\n
})();\n
\n
// Support conditions that must be met in order to proceed\n
// default enhanced qualifications are media query support OR IE 7+\n
\n
$.mobile.gradeA = function() {\n
\treturn ( ( $.support.mediaquery && $.support.cssPseudoElement ) || $.mobile.browser.oldIE && $.mobile.browser.oldIE >= 8 ) && ( $.support.boundingRect || $.fn.jquery.match(/1\\.[0-7+]\\.[0-9+]?/) !== null );\n
};\n
\n
$.mobile.ajaxBlacklist =\n
\t\t\t// BlackBerry browsers, pre-webkit\n
\t\t\twindow.blackberry && !window.WebKitPoint ||\n
\t\t\t// Opera Mini\n
\t\t\toperamini ||\n
\t\t\t// Symbian webkits pre 7.3\n
\t\t\tnokiaLTE7_3;\n
\n
// Lastly, this workaround is the only way we\'ve found so far to get pre 7.3 Symbian webkit devices\n
// to render the stylesheets when they\'re referenced before this script, as we\'d recommend doing.\n
// This simply reappends the CSS in place, which for some reason makes it apply\n
if ( nokiaLTE7_3 ) {\n
\t$(function() {\n
\t\t$( "head link[rel=\'stylesheet\']" ).attr( "rel", "alternate stylesheet" ).attr( "rel", "stylesheet" );\n
\t});\n
}\n
\n
// For ruling out shadows via css\n
if ( !$.support.boxShadow ) {\n
\t$( "html" ).addClass( "ui-noboxshadow" );\n
}\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\tvar $win = $.mobile.window, self,\n
\t\tdummyFnToInitNavigate = function() {\n
\t\t};\n
\n
\t$.event.special.beforenavigate = {\n
\t\tsetup: function() {\n
\t\t\t$win.on( "navigate", dummyFnToInitNavigate );\n
\t\t},\n
\n
\t\tteardown: function() {\n
\t\t\t$win.off( "navigate", dummyFnToInitNavigate );\n
\t\t}\n
\t};\n
\n
\t$.event.special.navigate = self = {\n
\t\tbound: false,\n
\n
\t\tpushStateEnabled: true,\n
\n
\t\toriginalEventName: undefined,\n
\n
\t\t// If pushstate support is present and push state support is defined to\n
\t\t// be true on the mobile namespace.\n
\t\tisPushStateEnabled: function() {\n
\t\t\treturn $.support.pushState &&\n
\t\t\t\t$.mobile.pushStateEnabled === true &&\n
\t\t\t\tthis.isHashChangeEnabled();\n
\t\t},\n
\n
\t\t// !! assumes mobile namespace is present\n
\t\tisHashChangeEnabled: function() {\n
\t\t\treturn $.mobile.hashListeningEnabled === true;\n
\t\t},\n
\n
\t\t// TODO a lot of duplication between popstate and hashchange\n
\t\tpopstate: function( event ) {\n
\t\t\tvar newEvent = new $.Event( "navigate" ),\n
\t\t\t\tbeforeNavigate = new $.Event( "beforenavigate" ),\n
\t\t\t\tstate = event.originalEvent.state || {};\n
\n
\t\t\tbeforeNavigate.originalEvent = event;\n
\t\t\t$win.trigger( beforeNavigate );\n
\n
\t\t\tif ( beforeNavigate.isDefaultPrevented() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif ( event.historyState ) {\n
\t\t\t\t$.extend(state, event.historyState);\n
\t\t\t}\n
\n
\t\t\t// Make sure the original event is tracked for the end\n
\t\t\t// user to inspect incase they want to do something special\n
\t\t\tnewEvent.originalEvent = event;\n
\n
\t\t\t// NOTE we let the current stack unwind because any assignment to\n
\t\t\t//      location.hash will stop the world and run this event handler. By\n
\t\t\t//      doing this we create a similar behavior to hashchange on hash\n
\t\t\t//      assignment\n
\t\t\tsetTimeout(function() {\n
\t\t\t\t$win.trigger( newEvent, {\n
\t\t\t\t\tstate: state\n
\t\t\t\t});\n
\t\t\t}, 0);\n
\t\t},\n
\n
\t\thashchange: function( event /*, data */ ) {\n
\t\t\tvar newEvent = new $.Event( "navigate" ),\n
\t\t\t\tbeforeNavigate = new $.Event( "beforenavigate" );\n
\n
\t\t\tbeforeNavigate.originalEvent = event;\n
\t\t\t$win.trigger( beforeNavigate );\n
\n
\t\t\tif ( beforeNavigate.isDefaultPrevented() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// Make sure the original event is tracked for the end\n
\t\t\t// user to inspect incase they want to do something special\n
\t\t\tnewEvent.originalEvent = event;\n
\n
\t\t\t// Trigger the hashchange with state provided by the user\n
\t\t\t// that altered the hash\n
\t\t\t$win.trigger( newEvent, {\n
\t\t\t\t// Users that want to fully normalize the two events\n
\t\t\t\t// will need to do history management down the stack and\n
\t\t\t\t// add the state to the event before this binding is fired\n
\t\t\t\t// TODO consider allowing for the explicit addition of callbacks\n
\t\t\t\t//      to be fired before this value is set to avoid event timing issues\n
\t\t\t\tstate: event.hashchangeState || {}\n
\t\t\t});\n
\t\t},\n
\n
\t\t// TODO We really only want to set this up once\n
\t\t//      but I\'m not clear if there\'s a beter way to achieve\n
\t\t//      this with the jQuery special event structure\n
\t\tsetup: function( /* data, namespaces */ ) {\n
\t\t\tif ( self.bound ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tself.bound = true;\n
\n
\t\t\tif ( self.isPushStateEnabled() ) {\n
\t\t\t\tself.originalEventName = "popstate";\n
\t\t\t\t$win.bind( "popstate.navigate", self.popstate );\n
\t\t\t} else if ( self.isHashChangeEnabled() ) {\n
\t\t\t\tself.originalEventName = "hashchange";\n
\t\t\t\t$win.bind( "hashchange.navigate", self.hashchange );\n
\t\t\t}\n
\t\t}\n
\t};\n
})( jQuery );\n
\n
\n
\n
(function( $, undefined ) {\n
\t\tvar path, $base, dialogHashKey = "&ui-state=dialog";\n
\n
\t\t$.mobile.path = path = {\n
\t\t\tuiStateKey: "&ui-state",\n
\n
\t\t\t// This scary looking regular expression parses an absolute URL or its relative\n
\t\t\t// variants (protocol, site, document, query, and hash), into the various\n
\t\t\t// components (protocol, host, path, query, fragment, etc that make up the\n
\t\t\t// URL as well as some other commonly used sub-parts. When used with RegExp.exec()\n
\t\t\t// or String.match, it parses the URL into a results array that looks like this:\n
\t\t\t//\n
\t\t\t//     [0]: http://jblas:password@mycompany.com:8080/mail/inbox?msg=1234&type=unread#msg-content\n
\t\t\t//     [1]: http://jblas:password@mycompany.com:8080/mail/inbox?msg=1234&type=unread\n
\t\t\t//     [2]: http://jblas:password@mycompany.com:8080/mail/inbox\n
\t\t\t//     [3]: http://jblas:password@mycompany.com:8080\n
\t\t\t//     [4]: http:\n
\t\t\t//     [5]: //\n
\t\t\t//     [6]: jblas:password@mycompany.com:8080\n
\t\t\t//     [7]: jblas:password\n
\t\t\t//     [8]: jblas\n
\t\t\t//     [9]: password\n
\t\t\t//    [10]: mycompany.com:8080\n
\t\t\t//    [11]: mycompany.com\n
\t\t\t//    [12]: 8080\n
\t\t\t//    [13]: /mail/inbox\n
\t\t\t//    [14]: /mail/\n
\t\t\t//    [15]: inbox\n
\t\t\t//    [16]: ?msg=1234&type=unread\n
\t\t\t//    [17]: #msg-content\n
\t\t\t//\n
\t\t\turlParseRE: /^\\s*(((([^:\\/#\\?]+:)?(?:(\\/\\/)((?:(([^:@\\/#\\?]+)(?:\\:([^:@\\/#\\?]+))?)@)?(([^:\\/#\\?\\]\\[]+|\\[[^\\/\\]@#?]+\\])(?:\\:([0-9]+))?))?)?)?((\\/?(?:[^\\/\\?#]+\\/+)*)([^\\?#]*)))?(\\?[^#]+)?)(#.*)?/,\n
\n
\t\t\t// Abstraction to address xss (Issue #4787) by removing the authority in\n
\t\t\t// browsers that auto-decode it. All references to location.href should be\n
\t\t\t// replaced with a call to this method so that it can be dealt with properly here\n
\t\t\tgetLocation: function( url ) {\n
\t\t\t\tvar parsedUrl = this.parseUrl( url || location.href ),\n
\t\t\t\t\turi = url ? parsedUrl : location,\n
\n
\t\t\t\t\t// Make sure to parse the url or the location object for the hash because using\n
\t\t\t\t\t// location.hash is autodecoded in firefox, the rest of the url should be from\n
\t\t\t\t\t// the object (location unless we\'re testing) to avoid the inclusion of the\n
\t\t\t\t\t// authority\n
\t\t\t\t\thash = parsedUrl.hash;\n
\n
\t\t\t\t// mimic the browser with an empty string when the hash is empty\n
\t\t\t\thash = hash === "#" ? "" : hash;\n
\n
\t\t\t\treturn uri.protocol +\n
\t\t\t\t\tparsedUrl.doubleSlash +\n
\t\t\t\t\turi.host +\n
\n
\t\t\t\t\t// The pathname must start with a slash if there\'s a protocol, because you\n
\t\t\t\t\t// can\'t have a protocol followed by a relative path. Also, it\'s impossible to\n
\t\t\t\t\t// calculate absolute URLs from relative ones if the absolute one doesn\'t have\n
\t\t\t\t\t// a leading "/".\n
\t\t\t\t\t( ( uri.protocol !== "" && uri.pathname.substring( 0, 1 ) !== "/" ) ?\n
\t\t\t\t\t\t"/" : "" ) +\n
\t\t\t\t\turi.pathname +\n
\t\t\t\t\turi.search +\n
\t\t\t\t\thash;\n
\t\t\t},\n
\n
\t\t\t//return the original document url\n
\t\t\tgetDocumentUrl: function( asParsedObject ) {\n
\t\t\t\treturn asParsedObject ? $.extend( {}, path.documentUrl ) : path.documentUrl.href;\n
\t\t\t},\n
\n
\t\t\tparseLocation: function() {\n
\t\t\t\treturn this.parseUrl( this.getLocation() );\n
\t\t\t},\n
\n
\t\t\t//Parse a URL into a structure that allows easy access to\n
\t\t\t//all of the URL components by name.\n
\t\t\tparseUrl: function( url ) {\n
\t\t\t\t// If we\'re passed an object, we\'ll assume that it is\n
\t\t\t\t// a parsed url object and just return it back to the caller.\n
\t\t\t\tif ( $.type( url ) === "object" ) {\n
\t\t\t\t\treturn url;\n
\t\t\t\t}\n
\n
\t\t\t\tvar matches = path.urlParseRE.exec( url || "" ) || [];\n
\n
\t\t\t\t\t// Create an object that allows the caller to access the sub-matches\n
\t\t\t\t\t// by name. Note that IE returns an empty string instead of undefined,\n
\t\t\t\t\t// like all other browsers do, so we normalize everything so its consistent\n
\t\t\t\t\t// no matter what browser we\'re running on.\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\thref:         matches[  0 ] || "",\n
\t\t\t\t\t\threfNoHash:   matches[  1 ] || "",\n
\t\t\t\t\t\threfNoSearch: matches[  2 ] || "",\n
\t\t\t\t\t\tdomain:       matches[  3 ] || "",\n
\t\t\t\t\t\tprotocol:     matches[  4 ] || "",\n
\t\t\t\t\t\tdoubleSlash:  matches[  5 ] || "",\n
\t\t\t\t\t\tauthority:    matches[  6 ] || "",\n
\t\t\t\t\t\tusername:     matches[  8 ] || "",\n
\t\t\t\t\t\tpassword:     matches[  9 ] || "",\n
\t\t\t\t\t\thost:         matches[ 10 ] || "",\n
\t\t\t\t\t\thostname:     matches[ 11 ] || "",\n
\t\t\t\t\t\tport:         matches[ 12 ] || "",\n
\t\t\t\t\t\tpathname:     matches[ 13 ] || "",\n
\t\t\t\t\t\tdirectory:    matches[ 14 ] || "",\n
\t\t\t\t\t\tfilename:     matches[ 15 ] || "",\n
\t\t\t\t\t\tsearch:       matches[ 16 ] || "",\n
\t\t\t\t\t\thash:         matches[ 17 ] || ""\n
\t\t\t\t\t};\n
\t\t\t},\n
\n
\t\t\t//Turn relPath into an asbolute path. absPath is\n
\t\t\t//an optional absolute path which describes what\n
\t\t\t//relPath is relative to.\n
\t\t\tmakePathAbsolute: function( relPath, absPath ) {\n
\t\t\t\tvar absStack,\n
\t\t\t\t\trelStack,\n
\t\t\t\t\ti, d;\n
\n
\t\t\t\tif ( relPath && relPath.charAt( 0 ) === "/" ) {\n
\t\t\t\t\treturn relPath;\n
\t\t\t\t}\n
\n
\t\t\t\trelPath = relPath || "";\n
\t\t\t\tabsPath = absPath ? absPath.replace( /^\\/|(\\/[^\\/]*|[^\\/]+)$/g, "" ) : "";\n
\n
\t\t\t\tabsStack = absPath ? absPath.split( "/" ) : [];\n
\t\t\t\trelStack = relPath.split( "/" );\n
\n
\t\t\t\tfor ( i = 0; i < relStack.length; i++ ) {\n
\t\t\t\t\td = relStack[ i ];\n
\t\t\t\t\tswitch ( d ) {\n
\t\t\t\t\t\tcase ".":\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "..":\n
\t\t\t\t\t\t\tif ( absStack.length ) {\n
\t\t\t\t\t\t\t\tabsStack.pop();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tdefault:\n
\t\t\t\t\t\t\tabsStack.push( d );\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn "/" + absStack.join( "/" );\n
\t\t\t},\n
\n
\t\t\t//Returns true if both urls have the same domain.\n
\t\t\tisSameDomain: function( absUrl1, absUrl2 ) {\n
\t\t\t\treturn path.parseUrl( absUrl1 ).domain.toLowerCase() ===\n
\t\t\t\t\tpath.parseUrl( absUrl2 ).domain.toLowerCase();\n
\t\t\t},\n
\n
\t\t\t//Returns true for any relative variant.\n
\t\t\tisRelativeUrl: function( url ) {\n
\t\t\t\t// All relative Url variants have one thing in common, no protocol.\n
\t\t\t\treturn path.parseUrl( url ).protocol === "";\n
\t\t\t},\n
\n
\t\t\t//Returns true for an absolute url.\n
\t\t\tisAbsoluteUrl: function( url ) {\n
\t\t\t\treturn path.parseUrl( url ).protocol !== "";\n
\t\t\t},\n
\n
\t\t\t//Turn the specified realtive URL into an absolute one. This function\n
\t\t\t//can handle all relative variants (protocol, site, document, query, fragment).\n
\t\t\tmakeUrlAbsolute: function( relUrl, absUrl ) {\n
\t\t\t\tif ( !path.isRelativeUrl( relUrl ) ) {\n
\t\t\t\t\treturn relUrl;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( absUrl === undefined ) {\n
\t\t\t\t\tabsUrl = this.documentBase;\n
\t\t\t\t}\n
\n
\t\t\t\tvar relObj = path.parseUrl( relUrl ),\n
\t\t\t\t\tabsObj = path.parseUrl( absUrl ),\n
\t\t\t\t\tprotocol = relObj.protocol || absObj.protocol,\n
\t\t\t\t\tdoubleSlash = relObj.protocol ? relObj.doubleSlash : ( relObj.doubleSlash || absObj.doubleSlash ),\n
\t\t\t\t\tauthority = relObj.authority || absObj.authority,\n
\t\t\t\t\thasPath = relObj.pathname !== "",\n
\t\t\t\t\tpathname = path.makePathAbsolute( relObj.pathname || absObj.filename, absObj.pathname ),\n
\t\t\t\t\tsearch = relObj.search || ( !hasPath && absObj.search ) || "",\n
\t\t\t\t\thash = relObj.hash;\n
\n
\t\t\t\treturn protocol + doubleSlash + authority + pathname + search + hash;\n
\t\t\t},\n
\n
\t\t\t//Add search (aka query) params to the specified url.\n
\t\t\taddSearchParams: function( url, params ) {\n
\t\t\t\tvar u = path.parseUrl( url ),\n
\t\t\t\t\tp = ( typeof params === "object" ) ? $.param( params ) : params,\n
\t\t\t\t\ts = u.search || "?";\n
\t\t\t\treturn u.hrefNoSearch + s + ( s.charAt( s.length - 1 ) !== "?" ? "&" : "" ) + p + ( u.hash || "" );\n
\t\t\t},\n
\n
\t\t\tconvertUrlToDataUrl: function( absUrl ) {\n
\t\t\t\tvar u = path.parseUrl( absUrl );\n
\t\t\t\tif ( path.isEmbeddedPage( u ) ) {\n
\t\t\t\t\t// For embedded pages, remove the dialog hash key as in getFilePath(),\n
\t\t\t\t\t// and remove otherwise the Data Url won\'t match the id of the embedded Page.\n
\t\t\t\t\treturn u.hash\n
\t\t\t\t\t\t.split( dialogHashKey )[0]\n
\t\t\t\t\t\t.replace( /^#/, "" )\n
\t\t\t\t\t\t.replace( /\\?.*$/, "" );\n
\t\t\t\t} else if ( path.isSameDomain( u, this.documentBase ) ) {\n
\t\t\t\t\treturn u.hrefNoHash.replace( this.documentBase.domain, "" ).split( dialogHashKey )[0];\n
\t\t\t\t}\n
\n
\t\t\t\treturn window.decodeURIComponent(absUrl);\n
\t\t\t},\n
\n
\t\t\t//get path from current hash, or from a file path\n
\t\t\tget: function( newPath ) {\n
\t\t\t\tif ( newPath === undefined ) {\n
\t\t\t\t\tnewPath = path.parseLocation().hash;\n
\t\t\t\t}\n
\t\t\t\treturn path.stripHash( newPath ).replace( /[^\\/]*\\.[^\\/*]+$/, "" );\n
\t\t\t},\n
\n
\t\t\t//set location hash to path\n
\t\t\tset: function( path ) {\n
\t\t\t\tlocation.hash = path;\n
\t\t\t},\n
\n
\t\t\t//test if a given url (string) is a path\n
\t\t\t//NOTE might be exceptionally naive\n
\t\t\tisPath: function( url ) {\n
\t\t\t\treturn ( /\\// ).test( url );\n
\t\t\t},\n
\n
\t\t\t//return a url path with the window\'s location protocol/hostname/pathname removed\n
\t\t\tclean: function( url ) {\n
\t\t\t\treturn url.replace( this.documentBase.domain, "" );\n
\t\t\t},\n
\n
\t\t\t//just return the url without an initial #\n
\t\t\tstripHash: function( url ) {\n
\t\t\t\treturn url.replace( /^#/, "" );\n
\t\t\t},\n
\n
\t\t\tstripQueryParams: function( url ) {\n
\t\t\t\treturn url.replace( /\\?.*$/, "" );\n
\t\t\t},\n
\n
\t\t\t//remove the preceding hash, any query params, and dialog notations\n
\t\t\tcleanHash: function( hash ) {\n
\t\t\t\treturn path.stripHash( hash.replace( /\\?.*$/, "" ).replace( dialogHashKey, "" ) );\n
\t\t\t},\n
\n
\t\t\tisHashValid: function( hash ) {\n
\t\t\t\treturn ( /^#[^#]+$/ ).test( hash );\n
\t\t\t},\n
\n
\t\t\t//check whether a url is referencing the same domain, or an external domain or different protocol\n
\t\t\t//could be mailto, etc\n
\t\t\tisExternal: function( url ) {\n
\t\t\t\tvar u = path.parseUrl( url );\n
\n
\t\t\t\treturn !!( u.protocol &&\n
\t\t\t\t\t( u.domain.toLowerCase() !== this.documentUrl.domain.toLowerCase() ) );\n
\t\t\t},\n
\n
\t\t\thasProtocol: function( url ) {\n
\t\t\t\treturn ( /^(:?\\w+:)/ ).test( url );\n
\t\t\t},\n
\n
\t\t\tisEmbeddedPage: function( url ) {\n
\t\t\t\tvar u = path.parseUrl( url );\n
\n
\t\t\t\t//if the path is absolute, then we need to compare the url against\n
\t\t\t\t//both the this.documentUrl and the documentBase. The main reason for this\n
\t\t\t\t//is that links embedded within external documents will refer to the\n
\t\t\t\t//application document, whereas links embedded within the application\n
\t\t\t\t//document will be resolved against the document base.\n
\t\t\t\tif ( u.protocol !== "" ) {\n
\t\t\t\t\treturn ( !this.isPath(u.hash) && u.hash && ( u.hrefNoHash === this.documentUrl.hrefNoHash || ( this.documentBaseDiffers && u.hrefNoHash === this.documentBase.hrefNoHash ) ) );\n
\t\t\t\t}\n
\t\t\t\treturn ( /^#/ ).test( u.href );\n
\t\t\t},\n
\n
\t\t\tsquash: function( url, resolutionUrl ) {\n
\t\t\t\tvar href, cleanedUrl, search, stateIndex, docUrl,\n
\t\t\t\t\tisPath = this.isPath( url ),\n
\t\t\t\t\turi = this.parseUrl( url ),\n
\t\t\t\t\tpreservedHash = uri.hash,\n
\t\t\t\t\tuiState = "";\n
\n
\t\t\t\t// produce a url against which we can resolve the provided path\n
\t\t\t\tif ( !resolutionUrl ) {\n
\t\t\t\t\tif ( isPath ) {\n
\t\t\t\t\t\tresolutionUrl = path.getLocation();\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tdocUrl = path.getDocumentUrl( true );\n
\t\t\t\t\t\tif ( path.isPath( docUrl.hash ) ) {\n
\t\t\t\t\t\t\tresolutionUrl = path.squash( docUrl.href );\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tresolutionUrl = docUrl.href;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// If the url is anything but a simple string, remove any preceding hash\n
\t\t\t\t// eg #foo/bar -> foo/bar\n
\t\t\t\t//    #foo -> #foo\n
\t\t\t\tcleanedUrl = isPath ? path.stripHash( url ) : url;\n
\n
\t\t\t\t// If the url is a full url with a hash check if the parsed hash is a path\n
\t\t\t\t// if it is, strip the #, and use it otherwise continue without change\n
\t\t\t\tcleanedUrl = path.isPath( uri.hash ) ? path.stripHash( uri.hash ) : cleanedUrl;\n
\n
\t\t\t\t// Split the UI State keys off the href\n
\t\t\t\tstateIndex = cleanedUrl.indexOf( this.uiStateKey );\n
\n
\t\t\t\t// store the ui state keys for use\n
\t\t\t\tif ( stateIndex > -1 ) {\n
\t\t\t\t\tuiState = cleanedUrl.slice( stateIndex );\n
\t\t\t\t\tcleanedUrl = cleanedUrl.slice( 0, stateIndex );\n
\t\t\t\t}\n
\n
\t\t\t\t// make the cleanedUrl absolute relative to the resolution url\n
\t\t\t\thref = path.makeUrlAbsolute( cleanedUrl, resolutionUrl );\n
\n
\t\t\t\t// grab the search from the resolved url since parsing from\n
\t\t\t\t// the passed url may not yield the correct result\n
\t\t\t\tsearch = this.parseUrl( href ).search;\n
\n
\t\t\t\t// TODO all this crap is terrible, clean it up\n
\t\t\t\tif ( isPath ) {\n
\t\t\t\t\t// reject the hash if it\'s a path or it\'s just a dialog key\n
\t\t\t\t\tif ( path.isPath( preservedHash ) || preservedHash.replace("#", "").indexOf( this.uiStateKey ) === 0) {\n
\t\t\t\t\t\tpreservedHash = "";\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Append the UI State keys where it exists and it\'s been removed\n
\t\t\t\t\t// from the url\n
\t\t\t\t\tif ( uiState && preservedHash.indexOf( this.uiStateKey ) === -1) {\n
\t\t\t\t\t\tpreservedHash += uiState;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// make sure that pound is on the front of the hash\n
\t\t\t\t\tif ( preservedHash.indexOf( "#" ) === -1 && preservedHash !== "" ) {\n
\t\t\t\t\t\tpreservedHash = "#" + preservedHash;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// reconstruct each of the pieces with the new search string and hash\n
\t\t\t\t\thref = path.parseUrl( href );\n
\t\t\t\t\thref = href.protocol + href.doubleSlash + href.host + href.pathname + search +\n
\t\t\t\t\t\tpreservedHash;\n
\t\t\t\t} else {\n
\t\t\t\t\thref += href.indexOf( "#" ) > -1 ? uiState : "#" + uiState;\n
\t\t\t\t}\n
\n
\t\t\t\treturn href;\n
\t\t\t},\n
\n
\t\t\tisPreservableHash: function( hash ) {\n
\t\t\t\treturn hash.replace( "#", "" ).indexOf( this.uiStateKey ) === 0;\n
\t\t\t},\n
\n
\t\t\t// Escape weird characters in the hash if it is to be used as a selector\n
\t\t\thashToSelector: function( hash ) {\n
\t\t\t\tvar hasHash = ( hash.substring( 0, 1 ) === "#" );\n
\t\t\t\tif ( hasHash ) {\n
\t\t\t\t\thash = hash.substring( 1 );\n
\t\t\t\t}\n
\t\t\t\treturn ( hasHash ? "#" : "" ) + hash.replace( /([!"#$%&\'()*+,./:;<=>?@[\\]^`{|}~])/g, "\\\\$1" );\n
\t\t\t},\n
\n
\t\t\t// return the substring of a filepath before the sub-page key, for making\n
\t\t\t// a server request\n
\t\t\tgetFilePath: function( path ) {\n
\t\t\t\tvar splitkey = "&" + $.mobile.subPageUrlKey;\n
\t\t\t\treturn path && path.split( splitkey )[0].split( dialogHashKey )[0];\n
\t\t\t},\n
\n
\t\t\t// check if the specified url refers to the first page in the main\n
\t\t\t// application document.\n
\t\t\tisFirstPageUrl: function( url ) {\n
\t\t\t\t// We only deal with absolute paths.\n
\t\t\t\tvar u = path.parseUrl( path.makeUrlAbsolute( url, this.documentBase ) ),\n
\n
\t\t\t\t\t// Does the url have the same path as the document?\n
\t\t\t\t\tsamePath = u.hrefNoHash === this.documentUrl.hrefNoHash ||\n
\t\t\t\t\t\t( this.documentBaseDiffers &&\n
\t\t\t\t\t\t\tu.hrefNoHash === this.documentBase.hrefNoHash ),\n
\n
\t\t\t\t\t// Get the first page element.\n
\t\t\t\t\tfp = $.mobile.firstPage,\n
\n
\t\t\t\t\t// Get the id of the first page element if it has one.\n
\t\t\t\t\tfpId = fp && fp[0] ? fp[0].id : undefined;\n
\n
\t\t\t\t// The url refers to the first page if the path matches the document and\n
\t\t\t\t// it either has no hash value, or the hash is exactly equal to the id\n
\t\t\t\t// of the first page element.\n
\t\t\t\treturn samePath &&\n
\t\t\t\t\t( !u.hash ||\n
\t\t\t\t\t\tu.hash === "#" ||\n
\t\t\t\t\t\t( fpId && u.hash.replace( /^#/, "" ) === fpId ) );\n
\t\t\t},\n
\n
\t\t\t// Some embedded browsers, like the web view in Phone Gap, allow\n
\t\t\t// cross-domain XHR requests if the document doing the request was loaded\n
\t\t\t// via the file:// protocol. This is usually to allow the application to\n
\t\t\t// "phone home" and fetch app specific data. We normally let the browser\n
\t\t\t// handle external/cross-domain urls, but if the allowCrossDomainPages\n
\t\t\t// option is true, we will allow cross-domain http/https requests to go\n
\t\t\t// through our page loading logic.\n
\t\t\tisPermittedCrossDomainRequest: function( docUrl, reqUrl ) {\n
\t\t\t\treturn $.mobile.allowCrossDomainPages &&\n
\t\t\t\t\t(docUrl.protocol === "file:" || docUrl.protocol === "content:") &&\n
\t\t\t\t\treqUrl.search( /^https?:/ ) !== -1;\n
\t\t\t}\n
\t\t};\n
\n
\t\tpath.documentUrl = path.parseLocation();\n
\n
\t\t$base = $( "head" ).find( "base" );\n
\n
\t\tpath.documentBase = $base.length ?\n
\t\t\tpath.parseUrl( path.makeUrlAbsolute( $base.attr( "href" ), path.documentUrl.href ) ) :\n
\t\t\tpath.documentUrl;\n
\n
\t\tpath.documentBaseDiffers = (path.documentUrl.hrefNoHash !== path.documentBase.hrefNoHash);\n
\n
\t\t//return the original document base url\n
\t\tpath.getDocumentBase = function( asParsedObject ) {\n
\t\t\treturn asParsedObject ? $.extend( {}, path.documentBase ) : path.documentBase.href;\n
\t\t};\n
\n
\t\t// DEPRECATED as of 1.4.0 - remove in 1.5.0\n
\t\t$.extend( $.mobile, {\n
\n
\t\t\t//return the original document url\n
\t\t\tgetDocumentUrl: path.getDocumentUrl,\n
\n
\t\t\t//return the original document base url\n
\t\t\tgetDocumentBase: path.getDocumentBase\n
\t\t});\n
})( jQuery );\n
\n
\n
\n
(function( $, undefined ) {\n
\t$.mobile.History = function( stack, index ) {\n
\t\tthis.stack = stack || [];\n
\t\tthis.activeIndex = index || 0;\n
\t};\n
\n
\t$.extend($.mobile.History.prototype, {\n
\t\tgetActive: function() {\n
\t\t\treturn this.stack[ this.activeIndex ];\n
\t\t},\n
\n
\t\tgetLast: function() {\n
\t\t\treturn this.stack[ this.previousIndex ];\n
\t\t},\n
\n
\t\tgetNext: function() {\n
\t\t\treturn this.stack[ this.activeIndex + 1 ];\n
\t\t},\n
\n
\t\tgetPrev: function() {\n
\t\t\treturn this.stack[ this.activeIndex - 1 ];\n
\t\t},\n
\n
\t\t// addNew is used whenever a new page is added\n
\t\tadd: function( url, data ) {\n
\t\t\tdata = data || {};\n
\n
\t\t\t//if there\'s forward history, wipe it\n
\t\t\tif ( this.getNext() ) {\n
\t\t\t\tthis.clearForward();\n
\t\t\t}\n
\n
\t\t\t// if the hash is included in the data make sure the shape\n
\t\t\t// is consistent for comparison\n
\t\t\tif ( data.hash && data.hash.indexOf( "#" ) === -1) {\n
\t\t\t\tdata.hash = "#" + data.hash;\n
\t\t\t}\n
\n
\t\t\tdata.url = url;\n
\t\t\tthis.stack.push( data );\n
\t\t\tthis.activeIndex = this.stack.length - 1;\n
\t\t},\n
\n
\t\t//wipe urls ahead of active index\n
\t\tclearForward: function() {\n
\t\t\tthis.stack = this.stack.slice( 0, this.activeIndex + 1 );\n
\t\t},\n
\n
\t\tfind: function( url, stack, earlyReturn ) {\n
\t\t\tstack = stack || this.stack;\n
\n
\t\t\tvar entry, i, length = stack.length, index;\n
\n
\t\t\tfor ( i = 0; i < length; i++ ) {\n
\t\t\t\tentry = stack[i];\n
\n
\t\t\t\tif ( decodeURIComponent(url) === decodeURIComponent(entry.url) ||\n
\t\t\t\t\tdecodeURIComponent(url) === decodeURIComponent(entry.hash) ) {\n
\t\t\t\t\tindex = i;\n
\n
\t\t\t\t\tif ( earlyReturn ) {\n
\t\t\t\t\t\treturn index;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn index;\n
\t\t},\n
\n
\t\t_findById: function( id ) {\n
\t\t\tvar stackIndex,\n
\t\t\t\tstackLength = this.stack.length;\n
\n
\t\t\tfor ( stackIndex = 0 ; stackIndex < stackLength ; stackIndex++ ) {\n
\t\t\t\tif ( this.stack[ stackIndex ].id === id ) {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn ( stackIndex < stackLength ? stackIndex : undefined );\n
\t\t},\n
\n
\t\tclosest: function( url, id ) {\n
\t\t\tvar closest = ( id === undefined ? undefined : this._findById( id ) ),\n
\t\t\t\ta = this.activeIndex;\n
\n
\t\t\t// First, we check whether we\'ve found an entry by id. If so, we\'re done.\n
\t\t\tif ( closest !== undefined ) {\n
\t\t\t\treturn closest;\n
\t\t\t}\n
\n
\t\t\t// Failing that take the slice of the history stack before the current index and search\n
\t\t\t// for a url match. If one is found, we\'ll avoid avoid looking through forward history\n
\t\t\t// NOTE the preference for backward history movement is driven by the fact that\n
\t\t\t//      most mobile browsers only have a dedicated back button, and users rarely use\n
\t\t\t//      the forward button in desktop browser anyhow\n
\t\t\tclosest = this.find( url, this.stack.slice(0, a) );\n
\n
\t\t\t// If nothing was found in backward history check forward. The `true`\n
\t\t\t// value passed as the third parameter causes the find method to break\n
\t\t\t// on the first match in the forward history slice. The starting index\n
\t\t\t// of the slice must then be added to the result to get the element index\n
\t\t\t// in the original history stack :( :(\n
\t\t\t//\n
\t\t\t// TODO this is hyper confusing and should be cleaned up (ugh so bad)\n
\t\t\tif ( closest === undefined ) {\n
\t\t\t\tclosest = this.find( url, this.stack.slice(a), true );\n
\t\t\t\tclosest = closest === undefined ? closest : closest + a;\n
\t\t\t}\n
\n
\t\t\treturn closest;\n
\t\t},\n
\n
\t\tdirect: function( opts ) {\n
\t\t\tvar newActiveIndex = this.closest( opts.url, opts.id ), a = this.activeIndex;\n
\n
\t\t\t// save new page index, null check to prevent falsey 0 result\n
\t\t\t// record the previous index for reference\n
\t\t\tif ( newActiveIndex !== undefined ) {\n
\t\t\t\tthis.activeIndex = newActiveIndex;\n
\t\t\t\tthis.previousIndex = a;\n
\t\t\t}\n
\n
\t\t\t// invoke callbacks where appropriate\n
\t\t\t//\n
\t\t\t// TODO this is also convoluted and confusing\n
\t\t\tif ( newActiveIndex < a ) {\n
\t\t\t\t( opts.present || opts.back || $.noop )( this.getActive(), "back" );\n
\t\t\t} else if ( newActiveIndex > a ) {\n
\t\t\t\t( opts.present || opts.forward || $.noop )( this.getActive(), "forward" );\n
\t\t\t} else if ( newActiveIndex === undefined && opts.missing ) {\n
\t\t\t\topts.missing( this.getActive() );\n
\t\t\t}\n
\t\t}\n
\t});\n
})( jQuery );\n
\n
\n
\n
(function( $, undefined ) {\n
\tvar path = $.mobile.path,\n
\t\tinitialHref = location.href;\n
\n
\t$.mobile.Navigator = function( history ) {\n
\t\tthis.history = history;\n
\t\tthis.ignoreInitialHashChange = true;\n
\n
\t\t$.mobile.window.bind({\n
\t\t\t"popstate.history": $.proxy( this.popstate, this ),\n
\t\t\t"hashchange.history": $.proxy( this.hashchange, this )\n
\t\t});\n
\t};\n
\n
\t$.extend($.mobile.Navigator.prototype, {\n
\t\thistoryEntryId: 0,\n
\t\tsquash: function( url, data ) {\n
\t\t\tvar state, href, hash = path.isPath(url) ? path.stripHash(url) : url;\n
\n
\t\t\thref = path.squash( url );\n
\n
\t\t\t// make sure to provide this information when it isn\'t explicitly set in the\n
\t\t\t// data object that was passed to the squash method\n
\t\t\tstate = $.extend({\n
\t\t\t\tid: ++this.historyEntryId,\n
\t\t\t\thash: hash,\n
\t\t\t\turl: href\n
\t\t\t}, data);\n
\n
\t\t\t// replace the current url with the new href and store the state\n
\t\t\t// Note that in some cases we might be replacing an url with the\n
\t\t\t// same url. We do this anyways because we need to make sure that\n
\t\t\t// all of our history entries have a state object associated with\n
\t\t\t// them. This allows us to work around the case where $.mobile.back()\n
\t\t\t// is called to transition from an external page to an embedded page.\n
\t\t\t// In that particular case, a hashchange event is *NOT* generated by the browser.\n
\t\t\t// Ensuring each history entry has a state object means that onPopState()\n
\t\t\t// will always trigger our hashchange callback even when a hashchange event\n
\t\t\t// is not fired.\n
\t\t\twindow.history.replaceState( state, state.title || document.title, href );\n
\n
\t\t\treturn state;\n
\t\t},\n
\n
\t\thash: function( url, href ) {\n
\t\t\tvar parsed, loc, hash, resolved;\n
\n
\t\t\t// Grab the hash for recording. If the passed url is a path\n
\t\t\t// we used the parsed version of the squashed url to reconstruct,\n
\t\t\t// otherwise we assume it\'s a hash and store it directly\n
\t\t\tparsed = path.parseUrl( url );\n
\t\t\tloc = path.parseLocation();\n
\n
\t\t\tif ( loc.pathname + loc.search === parsed.pathname + parsed.search ) {\n
\t\t\t\t// If the pathname and search of the passed url is identical to the current loc\n
\t\t\t\t// then we must use the hash. Otherwise there will be no event\n
\t\t\t\t// eg, url = "/foo/bar?baz#bang", location.href = "http://example.com/foo/bar?baz"\n
\t\t\t\thash = parsed.hash ? parsed.hash : parsed.pathname + parsed.search;\n
\t\t\t} else if ( path.isPath(url) ) {\n
\t\t\t\tresolved = path.parseUrl( href );\n
\t\t\t\t// If the passed url is a path, make it domain relative and remove any trailing hash\n
\t\t\t\thash = resolved.pathname + resolved.search + (path.isPreservableHash( resolved.hash )? resolved.hash.replace( "#", "" ) : "");\n
\t\t\t} else {\n
\t\t\t\thash = url;\n
\t\t\t}\n
\n
\t\t\treturn hash;\n
\t\t},\n
\n
\t\t// TODO reconsider name\n
\t\tgo: function( url, data, noEvents ) {\n
\t\t\tvar state, href, hash, popstateEvent,\n
\t\t\t\tisPopStateEvent = $.event.special.navigate.isPushStateEnabled();\n
\n
\t\t\t// Get the url as it would look squashed on to the current resolution url\n
\t\t\thref = path.squash( url );\n
\n
\t\t\t// sort out what the hash sould be from the url\n
\t\t\thash = this.hash( url, href );\n
\n
\t\t\t// Here we prevent the next hash change or popstate event from doing any\n
\t\t\t// history management. In the case of hashchange we don\'t swallow it\n
\t\t\t// if there will be no hashchange fired (since that won\'t reset the value)\n
\t\t\t// and will swallow the following hashchange\n
\t\t\tif ( noEvents && hash !== path.stripHash(path.parseLocation().hash) ) {\n
\t\t\t\tthis.preventNextHashChange = noEvents;\n
\t\t\t}\n
\n
\t\t\t// IMPORTANT in the case where popstate is supported the event will be triggered\n
\t\t\t//      directly, stopping further execution - ie, interupting the flow of this\n
\t\t\t//      method call to fire bindings at this expression. Below the navigate method\n
\t\t\t//      there is a binding to catch this event and stop its propagation.\n
\t\t\t//\n
\t\t\t//      We then trigger a new popstate event on the window with a null state\n
\t\t\t//      so that the navigate events can conclude their work properly\n
\t\t\t//\n
\t\t\t// if the url is a path we want to preserve the query params that are available on\n
\t\t\t// the current url.\n
\t\t\tthis.preventHashAssignPopState = true;\n
\t\t\twindow.location.hash = hash;\n
\n
\t\t\t// If popstate is enabled and the browser triggers `popstate` events when the hash\n
\t\t\t// is set (this often happens immediately in browsers like Chrome), then the\n
\t\t\t// this flag will be set to false already. If it\'s a browser that does not trigger\n
\t\t\t// a `popstate` on hash assignement or `replaceState` then we need avoid the branch\n
\t\t\t// that swallows the event created by the popstate generated by the hash assignment\n
\t\t\t// At the time of this writing this happens with Opera 12 and some version of IE\n
\t\t\tthis.preventHashAssignPopState = false;\n
\n
\t\t\tstate = $.extend({\n
\t\t\t\turl: href,\n
\t\t\t\thash: hash,\n
\t\t\t\ttitle: document.title\n
\t\t\t}, data);\n
\n
\t\t\tif ( isPopStateEvent ) {\n
\t\t\t\tpopstateEvent = new $.Event( "popstate" );\n
\t\t\t\tpopstateEvent.originalEvent = {\n
\t\t\t\t\ttype: "popstate",\n
\t\t\t\t\tstate: null\n
\t\t\t\t};\n
\n
\t\t\t\tstate.id = ( this.squash( url, state ) || {} ).id;\n
\n
\t\t\t\t// Trigger a new faux popstate event to replace the one that we\n
\t\t\t\t// caught that was triggered by the hash setting above.\n
\t\t\t\tif ( !noEvents ) {\n
\t\t\t\t\tthis.ignorePopState = true;\n
\t\t\t\t\t$.mobile.window.trigger( popstateEvent );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// record the history entry so that the information can be included\n
\t\t\t// in hashchange event driven navigate events in a similar fashion to\n
\t\t\t// the state that\'s provided by popstate\n
\t\t\tthis.history.add( state.url, state );\n
\t\t},\n
\n
\t\t// This binding is intended to catch the popstate events that are fired\n
\t\t// when execution of the `$.navigate` method stops at window.location.hash = url;\n
\t\t// and completely prevent them from propagating. The popstate event will then be\n
\t\t// retriggered after execution resumes\n
\t\t//\n
\t\t// TODO grab the original event here and use it for the synthetic event in the\n
\t\t//      second half of the navigate execution that will follow this binding\n
\t\tpopstate: function( event ) {\n
\t\t\tvar hash, state;\n
\n
\t\t\t// Partly to support our test suite which manually alters the support\n
\t\t\t// value to test hashchange. Partly to prevent all around weirdness\n
\t\t\tif ( !$.event.special.navigate.isPushStateEnabled() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// If this is the popstate triggered by the actual alteration of the hash\n
\t\t\t// prevent it completely. History is tracked manually\n
\t\t\tif ( this.preventHashAssignPopState ) {\n
\t\t\t\tthis.preventHashAssignPopState = false;\n
\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// if this is the popstate triggered after the `replaceState` call in the go\n
\t\t\t// method, then simply ignore it. The history entry has already been captured\n
\t\t\tif ( this.ignorePopState ) {\n
\t\t\t\tthis.ignorePopState = false;\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// If there is no state, and the history stack length is one were\n
\t\t\t// probably getting the page load popstate fired by browsers like chrome\n
\t\t\t// avoid it and set the one time flag to false.\n
\t\t\t// TODO: Do we really need all these conditions? Comparing location hrefs\n
\t\t\t// should be sufficient.\n
\t\t\tif ( !event.originalEvent.state &&\n
\t\t\t\tthis.history.stack.length === 1 &&\n
\t\t\t\tthis.ignoreInitialHashChange ) {\n
\t\t\t\tthis.ignoreInitialHashChange = false;\n
\n
\t\t\t\tif ( location.href === initialHref ) {\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// account for direct manipulation of the hash. That is, we will receive a popstate\n
\t\t\t// when the hash is changed by assignment, and it won\'t have a state associated. We\n
\t\t\t// then need to squash the hash. See below for handling of hash assignment that\n
\t\t\t// matches an existing history entry\n
\t\t\t// TODO it might be better to only add to the history stack\n
\t\t\t//      when the hash is adjacent to the active history entry\n
\t\t\thash = path.parseLocation().hash;\n
\t\t\tif ( !event.originalEvent.state && hash ) {\n
\t\t\t\t// squash the hash that\'s been assigned on the URL with replaceState\n
\t\t\t\t// also grab the resulting state object for storage\n
\t\t\t\tstate = this.squash( hash );\n
\n
\t\t\t\t// record the new hash as an additional history entry\n
\t\t\t\t// to match the browser\'s treatment of hash assignment\n
\t\t\t\tthis.history.add( state.url, state );\n
\n
\t\t\t\t// pass the newly created state information\n
\t\t\t\t// along with the event\n
\t\t\t\tevent.historyState = state;\n
\n
\t\t\t\t// do not alter history, we\'ve added a new history entry\n
\t\t\t\t// so we know where we are\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// If all else fails this is a popstate that comes from the back or forward buttons\n
\t\t\t// make sure to set the state of our history stack properly, and record the directionality\n
\t\t\tthis.history.direct({\n
\t\t\t\tid: ( event.originalEvent.state || {} ).id,\n
\t\t\t\turl: (event.originalEvent.state || {}).url || hash,\n
\n
\t\t\t\t// When the url is either forward or backward in history include the entry\n
\t\t\t\t// as data on the event object for merging as data in the navigate event\n
\t\t\t\tpresent: function( historyEntry, direction ) {\n
\t\t\t\t\t// make sure to create a new object to pass down as the navigate event data\n
\t\t\t\t\tevent.historyState = $.extend({}, historyEntry);\n
\t\t\t\t\tevent.historyState.direction = direction;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t},\n
\n
\t\t// NOTE must bind before `navigate` special event hashchange binding otherwise the\n
\t\t//      navigation data won\'t be attached to the hashchange event in time for those\n
\t\t//      bindings to attach it to the `navigate` special event\n
\t\t// TODO add a check here that `hashchange.navigate` is bound already otherwise it\'s\n
\t\t//      broken (exception?)\n
\t\thashchange: function( event ) {\n
\t\t\tvar history, hash;\n
\n
\t\t\t// If hashchange listening is explicitly disabled or pushstate is supported\n
\t\t\t// avoid making use of the hashchange handler.\n
\t\t\tif (!$.event.special.navigate.isHashChangeEnabled() ||\n
\t\t\t\t$.event.special.navigate.isPushStateEnabled() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// On occasion explicitly want to prevent the next hash from propogating because we only\n
\t\t\t// with to alter the url to represent the new state do so here\n
\t\t\tif ( this.preventNextHashChange ) {\n
\t\t\t\tthis.preventNextHashChange = false;\n
\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\thistory = this.history;\n
\t\t\thash = path.parseLocation().hash;\n
\n
\t\t\t// If this is a hashchange caused by the back or forward button\n
\t\t\t// make sure to set the state of our history stack properly\n
\t\t\tthis.history.direct({\n
\t\t\t\turl: hash,\n
\n
\t\t\t\t// When the url is either forward or backward in history include the entry\n
\t\t\t\t// as data on the event object for merging as data in the navigate event\n
\t\t\t\tpresent: function( historyEntry, direction ) {\n
\t\t\t\t\t// make sure to create a new object to pass down as the navigate event data\n
\t\t\t\t\tevent.hashchangeState = $.extend({}, historyEntry);\n
\t\t\t\t\tevent.hashchangeState.direction = direction;\n
\t\t\t\t},\n
\n
\t\t\t\t// When we don\'t find a hash in our history clearly we\'re aiming to go there\n
\t\t\t\t// record the entry as new for future traversal\n
\t\t\t\t//\n
\t\t\t\t// NOTE it\'s not entirely clear that this is the right thing to do given that we\n
\t\t\t\t//      can\'t know the users intention. It might be better to explicitly _not_\n
\t\t\t\t//      support location.hash assignment in preference to $.navigate calls\n
\t\t\t\t// TODO first arg to add should be the href, but it causes issues in identifying\n
\t\t\t\t//      embeded pages\n
\t\t\t\tmissing: function() {\n
\t\t\t\t\thistory.add( hash, {\n
\t\t\t\t\t\thash: hash,\n
\t\t\t\t\t\ttitle: document.title\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t});\n
})( jQuery );\n
\n
\n
\n
(function( $, undefined ) {\n
\t// TODO consider queueing navigation activity until previous activities have completed\n
\t//      so that end users don\'t have to think about it. Punting for now\n
\t// TODO !! move the event bindings into callbacks on the navigate event\n
\t$.mobile.navigate = function( url, data, noEvents ) {\n
\t\t$.mobile.navigate.navigator.go( url, data, noEvents );\n
\t};\n
\n
\t// expose the history on the navigate method in anticipation of full integration with\n
\t// existing navigation functionalty that is tightly coupled to the history information\n
\t$.mobile.navigate.history = new $.mobile.History();\n
\n
\t// instantiate an instance of the navigator for use within the $.navigate method\n
\t$.mobile.navigate.navigator = new $.mobile.Navigator( $.mobile.navigate.history );\n
\n
\tvar loc = $.mobile.path.parseLocation();\n
\t$.mobile.navigate.history.add( loc.href, {hash: loc.hash} );\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\tvar props = {\n
\t\t\t"animation": {},\n
\t\t\t"transition": {}\n
\t\t},\n
\t\ttestElement = document.createElement( "a" ),\n
\t\tvendorPrefixes = [ "", "webkit-", "moz-", "o-" ];\n
\n
\t$.each( [ "animation", "transition" ], function( i, test ) {\n
\n
\t\t// Get correct name for test\n
\t\tvar testName = ( i === 0 ) ? test + "-" + "name" : test;\n
\n
\t\t$.each( vendorPrefixes, function( j, prefix ) {\n
\t\t\tif ( testElement.style[ $.camelCase( prefix + testName ) ] !== undefined ) {\n
\t\t\t\t props[ test ][ "prefix" ] = prefix;\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t});\n
\n
\t\t// Set event and duration names for later use\n
\t\tprops[ test ][ "duration" ] =\n
\t\t\t$.camelCase( props[ test ][ "prefix" ] + test + "-" + "duration" );\n
\t\tprops[ test ][ "event" ] =\n
\t\t\t$.camelCase( props[ test ][ "prefix" ] + test + "-" + "end" );\n
\n
\t\t// All lower case if not a vendor prop\n
\t\tif ( props[ test ][ "prefix" ] === "" ) {\n
\t\t\tprops[ test ][ "event" ] = props[ test ][ "event" ].toLowerCase();\n
\t\t}\n
\t});\n
\n
\t// If a valid prefix was found then the it is supported by the browser\n
\t$.support.cssTransitions = ( props[ "transition" ][ "prefix" ] !== undefined );\n
\t$.support.cssAnimations = ( props[ "animation" ][ "prefix" ] !== undefined );\n
\n
\t// Remove the testElement\n
\t$( testElement ).remove();\n
\n
\t// Animation complete callback\n
\t$.fn.animationComplete = function( callback, type, fallbackTime ) {\n
\t\tvar timer, duration,\n
\t\t\tthat = this,\n
\t\t\teventBinding = function() {\n
\n
\t\t\t\t// Clear the timer so we don\'t call callback twice\n
\t\t\t\tclearTimeout( timer );\n
\t\t\t\tcallback.apply( this, arguments );\n
\t\t\t},\n
\t\t\tanimationType = ( !type || type === "animation" ) ? "animation" : "transition";\n
\n
\t\t// Make sure selected type is supported by browser\n
\t\tif ( ( $.support.cssTransitions && animationType === "transition" ) ||\n
\t\t\t( $.support.cssAnimations && animationType === "animation" ) ) {\n
\n
\t\t\t// If a fallback time was not passed set one\n
\t\t\tif ( fallbackTime === undefined ) {\n
\n
\t\t\t\t// Make sure the was not bound to document before checking .css\n
\t\t\t\tif ( $( this ).context !== document ) {\n
\n
\t\t\t\t\t// Parse the durration since its in second multiple by 1000 for milliseconds\n
\t\t\t\t\t// Multiply by 3 to make sure we give the animation plenty of time.\n
\t\t\t\t\tduration = parseFloat(\n
\t\t\t\t\t\t$( this ).css( props[ animationType ].duration )\n
\t\t\t\t\t) * 3000;\n
\t\t\t\t}\n
\n
\t\t\t\t// If we could not read a duration use the default\n
\t\t\t\tif ( duration === 0 || duration === undefined || isNaN( duration ) ) {\n
\t\t\t\t\tduration = $.fn.animationComplete.defaultDuration;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Sets up the fallback if event never comes\n
\t\t\ttimer = setTimeout( function() {\n
\t\t\t\t$( that ).off( props[ animationType ].event, eventBinding );\n
\t\t\t\tcallback.apply( that );\n
\t\t\t}, duration );\n
\n
\t\t\t// Bind the event\n
\t\t\treturn $( this ).one( props[ animationType ].event, eventBinding );\n
\t\t} else {\n
\n
\t\t\t// CSS animation / transitions not supported\n
\t\t\t// Defer execution for consistency between webkit/non webkit\n
\t\t\tsetTimeout( $.proxy( callback, this ), 0 );\n
\t\t\treturn $( this );\n
\t\t}\n
\t};\n
\n
\t// Allow default callback to be configured on mobileInit\n
\t$.fn.animationComplete.defaultDuration = 1000;\n
})( jQuery );\n
\n
// This plugin is an experiment for abstracting away the touch and mouse\n
// events so that developers don\'t have to worry about which method of input\n
// the device their document is loaded on supports.\n
//\n
// The idea here is to allow the developer to register listeners for the\n
// basic mouse events, such as mousedown, mousemove, mouseup, and click,\n
// and the plugin will take care of registering the correct listeners\n
// behind the scenes to invoke the listener at the fastest possible time\n
// for that device, while still retaining the order of event firing in\n
// the traditional mouse environment, should multiple handlers be registered\n
// on the same element for different events.\n
//\n
// The current version exposes the following virtual events to jQuery bind methods:\n
// "vmouseover vmousedown vmousemove vmouseup vclick vmouseout vmousecancel"\n
\n
(function( $, window, document, undefined ) {\n
\n
var dataPropertyName = "virtualMouseBindings",\n
\ttouchTargetPropertyName = "virtualTouchID",\n
\tvirtualEventNames = "vmouseover vmousedown vmousemove vmouseup vclick vmouseout vmousecancel".split( " " ),\n
\ttouchEventProps = "clientX clientY pageX pageY screenX screenY".split( " " ),\n
\tmouseHookProps = $.event.mouseHooks ? $.event.mouseHooks.props : [],\n
\tmouseEventProps = $.event.props.concat( mouseHookProps ),\n
\tactiveDocHandlers = {},\n
\tresetTimerID = 0,\n
\tstartX = 0,\n
\tstartY = 0,\n
\tdidScroll = false,\n
\tclickBlockList = [],\n
\tblockMouseTriggers = false,\n
\tblockTouchTriggers = false,\n
\teventCaptureSupported = "addEventListener" in document,\n
\t$document = $( document ),\n
\tnextTouchID = 1,\n
\tlastTouchID = 0, threshold,\n
\ti;\n
\n
$.vmouse = {\n
\tmoveDistanceThreshold: 10,\n
\tclickDistanceThreshold: 10,\n
\tresetTimerDuration: 1500\n
};\n
\n
function getNativeEvent( event ) {\n
\n
\twhile ( event && typeof event.originalEvent !== "undefined" ) {\n
\t\tevent = event.originalEvent;\n
\t}\n
\treturn event;\n
}\n
\n
function createVirtualEvent( event, eventType ) {\n
\n
\tvar t = event.type,\n
\t\toe, props, ne, prop, ct, touch, i, j, len;\n
\n
\tevent = $.Event( event );\n
\tevent.type = eventType;\n
\n
\toe = event.originalEvent;\n
\tprops = $.event.props;\n
\n
\t// addresses separation of $.event.props in to $.event.mouseHook.props and Issue 3280\n
\t// https://github.com/jquery/jquery-mobile/issues/3280\n
\tif ( t.search( /^(mouse|click)/ ) > -1 ) {\n
\t\tprops = mouseEventProps;\n
\t}\n
\n
\t// copy original event properties over to the new event\n
\t// this would happen if we could call $.event.fix instead of $.Event\n
\t// but we don\'t have a way to force an event to be fixed multiple times\n
\tif ( oe ) {\n
\t\tfor ( i = props.length, prop; i; ) {\n
\t\t\tprop = props[ --i ];\n
\t\t\tevent[ prop ] = oe[ prop ];\n
\t\t}\n
\t}\n
\n
\t// make sure that if the mouse and click virtual events are generated\n
\t// without a .which one is defined\n
\tif ( t.search(/mouse(down|up)|click/) > -1 && !event.which ) {\n
\t\tevent.which = 1;\n
\t}\n
\n
\tif ( t.search(/^touch/) !== -1 ) {\n
\t\tne = getNativeEvent( oe );\n
\t\tt = ne.touches;\n
\t\tct = ne.changedTouches;\n
\t\ttouch = ( t && t.length ) ? t[0] : ( ( ct && ct.length ) ? ct[ 0 ] : undefined );\n
\n
\t\tif ( touch ) {\n
\t\t\tfor ( j = 0, len = touchEventProps.length; j < len; j++) {\n
\t\t\t\tprop = touchEventProps[ j ];\n
\t\t\t\tevent[ prop ] = touch[ prop ];\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn event;\n
}\n
\n
function getVirtualBindingFlags( element ) {\n
\n
\tvar flags = {},\n
\t\tb, k;\n
\n
\twhile ( element ) {\n
\n
\t\tb = $.data( element, dataPropertyName );\n
\n
\t\tfor (  k in b ) {\n
\t\t\tif ( b[ k ] ) {\n
\t\t\t\tflags[ k ] = flags.hasVirtualBinding = true;\n
\t\t\t}\n
\t\t}\n
\t\telement = element.parentNode;\n
\t}\n
\treturn flags;\n
}\n
\n
function getClosestElementWithVirtualBinding( element, eventType ) {\n
\tvar b;\n
\twhile ( element ) {\n
\n
\t\tb = $.data( element, dataPropertyName );\n
\n
\t\tif ( b && ( !eventType || b[ eventType ] ) ) {\n
\t\t\treturn element;\n
\t\t}\n
\t\telement = element.parentNode;\n
\t}\n
\treturn null;\n
}\n
\n
function enableTouchBindings() {\n
\tblockTouchTriggers = false;\n
}\n
\n
function disableTouchBindings() {\n
\tblockTouchTriggers = true;\n
}\n
\n
function enableMouseBindings() {\n
\tlastTouchID = 0;\n
\tclickBlockList.length = 0;\n
\tblockMouseTriggers = false;\n
\n
\t// When mouse bindings are enabled, our\n
\t// touch bindings are disabled.\n
\tdisableTouchBindings();\n
}\n
\n
function disableMouseBindings() {\n
\t// When mouse bindings are disabled, our\n
\t// touch bindings are enabled.\n
\tenableTouchBindings();\n
}\n
\n
function startResetTimer() {\n
\tclearResetTimer();\n
\tresetTimerID = setTimeout( function() {\n
\t\tresetTimerID = 0;\n
\t\tenableMouseBindings();\n
\t}, $.vmouse.resetTimerDuration );\n
}\n
\n
function clearResetTimer() {\n
\tif ( resetTimerID ) {\n
\t\tclearTimeout( resetTimerID );\n
\t\tresetTimerID = 0;\n
\t}\n
}\n
\n
function triggerVirtualEvent( eventType, event, flags ) {\n
\tvar ve;\n
\n
\tif ( ( flags && flags[ eventType ] ) ||\n
\t\t\t\t( !flags && getClosestElementWithVirtualBinding( event.target, eventType ) ) ) {\n
\n
\t\tve = createVirtualEvent( event, eventType );\n
\n
\t\t$( event.target).trigger( ve );\n
\t}\n
\n
\treturn ve;\n
}\n
\n
function mouseEventCallback( event ) {\n
\tvar touchID = $.data( event.target, touchTargetPropertyName ),\n
\t\tve;\n
\n
\tif ( !blockMouseTriggers && ( !lastTouchID || lastTouchID !== touchID ) ) {\n
\t\tve = triggerVirtualEvent( "v" + event.type, event );\n
\t\tif ( ve ) {\n
\t\t\tif ( ve.isDefaultPrevented() ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t}\n
\t\t\tif ( ve.isPropagationStopped() ) {\n
\t\t\t\tevent.stopPropagation();\n
\t\t\t}\n
\t\t\tif ( ve.isImmediatePropagationStopped() ) {\n
\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t}\n
\t\t}\n
\t}\n
}\n
\n
function handleTouchStart( event ) {\n
\n
\tvar touches = getNativeEvent( event ).touches,\n
\t\ttarget, flags, t;\n
\n
\tif ( touches && touches.length === 1 ) {\n
\n
\t\ttarget = event.target;\n
\t\tflags = getVirtualBindingFlags( target );\n
\n
\t\tif ( flags.hasVirtualBinding ) {\n
\n
\t\t\tlastTouchID = nextTouchID++;\n
\t\t\t$.data( target, touchTargetPropertyName, lastTouchID );\n
\n
\t\t\tclearResetTimer();\n
\n
\t\t\tdisableMouseBindings();\n
\t\t\tdidScroll = false;\n
\n
\t\t\tt = getNativeEvent( event ).touches[ 0 ];\n
\t\t\tstartX = t.pageX;\n
\t\t\tstartY = t.pageY;\n
\n
\t\t\ttriggerVirtualEvent( "vmouseover", event, flags );\n
\t\t\ttriggerVirtualEvent( "vmousedown", event, flags );\n
\t\t}\n
\t}\n
}\n
\n
function handleScroll( event ) {\n
\tif ( blockTouchTriggers ) {\n
\t\treturn;\n
\t}\n
\n
\tif ( !didScroll ) {\n
\t\ttriggerVirtualEvent( "vmousecancel", event, getVirtualBindingFlags( event.target ) );\n
\t}\n
\n
\tdidScroll = true;\n
\tstartResetTimer();\n
}\n
\n
function handleTouchMove( event ) {\n
\tif ( blockTouchTriggers ) {\n
\t\treturn;\n
\t}\n
\n
\tvar t = getNativeEvent( event ).touches[ 0 ],\n
\t\tdidCancel = didScroll,\n
\t\tmoveThreshold = $.vmouse.moveDistanceThreshold,\n
\t\tflags = getVirtualBindingFlags( event.target );\n
\n
\t\tdidScroll = didScroll ||\n
\t\t\t( Math.abs( t.pageX - startX ) > moveThreshold ||\n
\t\t\t\tMath.abs( t.pageY - startY ) > moveThreshold );\n
\n
\tif ( didScroll && !didCancel ) {\n
\t\ttriggerVirtualEvent( "vmousecancel", event, flags );\n
\t}\n
\n
\ttriggerVirtualEvent( "vmousemove", event, flags );\n
\tstartResetTimer();\n
}\n
\n
function handleTouchEnd( event ) {\n
\tif ( blockTouchTriggers ) {\n
\t\treturn;\n
\t}\n
\n
\tdisableTouchBindings();\n
\n
\tvar flags = getVirtualBindingFlags( event.target ),\n
\t\tve, t;\n
\ttriggerVirtualEvent( "vmouseup", event, flags );\n
\n
\tif ( !didScroll ) {\n
\t\tve = triggerVirtualEvent( "vclick", event, flags );\n
\t\tif ( ve && ve.isDefaultPrevented() ) {\n
\t\t\t// The target of the mouse events that follow the touchend\n
\t\t\t// event don\'t necessarily match the target used during the\n
\t\t\t// touch. This means we need to rely on coordinates for blocking\n
\t\t\t// any click that is generated.\n
\t\t\tt = getNativeEvent( event ).changedTouches[ 0 ];\n
\t\t\tclickBlockList.push({\n
\t\t\t\ttouchID: lastTouchID,\n
\t\t\t\tx: t.clientX,\n
\t\t\t\ty: t.clientY\n
\t\t\t});\n
\n
\t\t\t// Prevent any mouse events that follow from triggering\n
\t\t\t// virtual event notifications.\n
\t\t\tblockMouseTriggers = true;\n
\t\t}\n
\t}\n
\ttriggerVirtualEvent( "vmouseout", event, flags);\n
\tdidScroll = false;\n
\n
\tstartResetTimer();\n
}\n
\n
function hasVirtualBindings( ele ) {\n
\tvar bindings = $.data( ele, dataPropertyName ),\n
\t\tk;\n
\n
\tif ( bindings ) {\n
\t\tfor ( k in bindings ) {\n
\t\t\tif ( bindings[ k ] ) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\t}\n
\treturn false;\n
}\n
\n
function dummyMouseHandler() {}\n
\n
function getSpecialEventObject( eventType ) {\n
\tvar realType = eventType.substr( 1 );\n
\n
\treturn {\n
\t\tsetup: function(/* data, namespace */) {\n
\t\t\t// If this is the first virtual mouse binding for this element,\n
\t\t\t// add a bindings object to its data.\n
\n
\t\t\tif ( !hasVirtualBindings( this ) ) {\n
\t\t\t\t$.data( this, dataPropertyName, {} );\n
\t\t\t}\n
\n
\t\t\t// If setup is called, we know it is the first binding for this\n
\t\t\t// eventType, so initialize the count for the eventType to zero.\n
\t\t\tvar bindings = $.data( this, dataPropertyName );\n
\t\t\tbindings[ eventType ] = true;\n
\n
\t\t\t// If this is the first virtual mouse event for this type,\n
\t\t\t// register a global handler on the document.\n
\n
\t\t\tactiveDocHandlers[ eventType ] = ( activeDocHandlers[ eventType ] || 0 ) + 1;\n
\n
\t\t\tif ( activeDocHandlers[ eventType ] === 1 ) {\n
\t\t\t\t$document.bind( realType, mouseEventCallback );\n
\t\t\t}\n
\n
\t\t\t// Some browsers, like Opera Mini, won\'t dispatch mouse/click events\n
\t\t\t// for elements unless they actually have handlers registered on them.\n
\t\t\t// To get around this, we register dummy handlers on the elements.\n
\n
\t\t\t$( this ).bind( realType, dummyMouseHandler );\n
\n
\t\t\t// For now, if event capture is not supported, we rely on mouse handlers.\n
\t\t\tif ( eventCaptureSupported ) {\n
\t\t\t\t// If this is the first virtual mouse binding for the document,\n
\t\t\t\t// register our touchstart handler on the document.\n
\n
\t\t\t\tactiveDocHandlers[ "touchstart" ] = ( activeDocHandlers[ "touchstart" ] || 0) + 1;\n
\n
\t\t\t\tif ( activeDocHandlers[ "touchstart" ] === 1 ) {\n
\t\t\t\t\t$document.bind( "touchstart", handleTouchStart )\n
\t\t\t\t\t\t.bind( "touchend", handleTouchEnd )\n
\n
\t\t\t\t\t\t// On touch platforms, touching the screen and then dragging your finger\n
\t\t\t\t\t\t// causes the window content to scroll after some distance threshold is\n
\t\t\t\t\t\t// exceeded. On these platforms, a scroll prevents a click event from being\n
\t\t\t\t\t\t// dispatched, and on some platforms, even the touchend is suppressed. To\n
\t\t\t\t\t\t// mimic the suppression of the click event, we need to watch for a scroll\n
\t\t\t\t\t\t// event. Unfortunately, some platforms like iOS don\'t dispatch scroll\n
\t\t\t\t\t\t// events until *AFTER* the user lifts their finger (touchend). This means\n
\t\t\t\t\t\t// we need to watch both scroll and touchmove events to figure out whether\n
\t\t\t\t\t\t// or not a scroll happenens before the touchend event is fired.\n
\n
\t\t\t\t\t\t.bind( "touchmove", handleTouchMove )\n
\t\t\t\t\t\t.bind( "scroll", handleScroll );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\tteardown: function(/* data, namespace */) {\n
\t\t\t// If this is the last virtual binding for this eventType,\n
\t\t\t// remove its global handler from the document.\n
\n
\t\t\t--activeDocHandlers[ eventType ];\n
\n
\t\t\tif ( !activeDocHandlers[ eventType ] ) {\n
\t\t\t\t$document.unbind( realType, mouseEventCallback );\n
\t\t\t}\n
\n
\t\t\tif ( eventCaptureSupported ) {\n
\t\t\t\t// If this is the last virtual mouse binding in existence,\n
\t\t\t\t// remove our document touchstart listener.\n
\n
\t\t\t\t--activeDocHandlers[ "touchstart" ];\n
\n
\t\t\t\tif ( !activeDocHandlers[ "touchstart" ] ) {\n
\t\t\t\t\t$document.unbind( "touchstart", handleTouchStart )\n
\t\t\t\t\t\t.unbind( "touchmove", handleTouchMove )\n
\t\t\t\t\t\t.unbind( "touchend", handleTouchEnd )\n
\t\t\t\t\t\t.unbind( "scroll", handleScroll );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tvar $this = $( this ),\n
\t\t\t\tbindings = $.data( this, dataPropertyName );\n
\n
\t\t\t// teardown may be called when an element was\n
\t\t\t// removed from the DOM. If this is the case,\n
\t\t\t// jQuery core may have already stripped the element\n
\t\t\t// of any data bindings so we need to check it before\n
\t\t\t// using it.\n
\t\t\tif ( bindings ) {\n
\t\t\t\tbindings[ eventType ] = false;\n
\t\t\t}\n
\n
\t\t\t// Unregister the dummy event handler.\n
\n
\t\t\t$this.unbind( realType, dummyMouseHandler );\n
\n
\t\t\t// If this is the last virtual mouse binding on the\n
\t\t\t// element, remove the binding data from the element.\n
\n
\t\t\tif ( !hasVirtualBindings( this ) ) {\n
\t\t\t\t$this.removeData( dataPropertyName );\n
\t\t\t}\n
\t\t}\n
\t};\n
}\n
\n
// Expose our custom events to the jQuery bind/unbind mechanism.\n
\n
for ( i = 0; i < virtualEventNames.length; i++ ) {\n
\t$.event.special[ virtualEventNames[ i ] ] = getSpecialEventObject( virtualEventNames[ i ] );\n
}\n
\n
// Add a capture click handler to block clicks.\n
// Note that we require event capture support for this so if the device\n
// doesn\'t support it, we punt for now and rely solely on mouse events.\n
if ( eventCaptureSupported ) {\n
\tdocument.addEventListener( "click", function( e ) {\n
\t\tvar cnt = clickBlockList.length,\n
\t\t\ttarget = e.target,\n
\t\t\tx, y, ele, i, o, touchID;\n
\n
\t\tif ( cnt ) {\n
\t\t\tx = e.clientX;\n
\t\t\ty = e.clientY;\n
\t\t\tthreshold = $.vmouse.clickDistanceThreshold;\n
\n
\t\t\t// The idea here is to run through the clickBlockList to see if\n
\t\t\t// the current click event is in the proximity of one of our\n
\t\t\t// vclick events that had preventDefault() called on it. If we find\n
\t\t\t// one, then we block the click.\n
\t\t\t//\n
\t\t\t// Why do we have to rely on proximity?\n
\t\t\t//\n
\t\t\t// Because the target of the touch event that triggered the vclick\n
\t\t\t// can be different from the target of the click event synthesized\n
\t\t\t// by the browser. The target of a mouse/click event that is synthesized\n
\t\t\t// from a touch event seems to be implementation specific. For example,\n
\t\t\t// some browsers will fire mouse/click events for a link that is near\n
\t\t\t// a touch event, even though the target of the touchstart/touchend event\n
\t\t\t// says the user touched outside the link. Also, it seems that with most\n
\t\t\t// browsers, the target of the mouse/click event is not calculated until the\n
\t\t\t// time it is dispatched, so if you replace an element that you touched\n
\t\t\t// with another element, the target of the mouse/click will be the new\n
\t\t\t// element underneath that point.\n
\t\t\t//\n
\t\t\t// Aside from proximity, we also check to see if the target and any\n
\t\t\t// of its ancestors were the ones that blocked a click. This is necessary\n
\t\t\t// because of the strange mouse/click target calculation done in the\n
\t\t\t// Android 2.1 browser, where if you click on an element, and there is a\n
\t\t\t// mouse/click handler on one of its ancestors, the target will be the\n
\t\t\t// innermost child of the touched element, even if that child is no where\n
\t\t\t// near the point of touch.\n
\n
\t\t\tele = target;\n
\n
\t\t\twhile ( ele ) {\n
\t\t\t\tfor ( i = 0; i < cnt; i++ ) {\n
\t\t\t\t\to = clickBlockList[ i ];\n
\t\t\t\t\ttouchID = 0;\n
\n
\t\t\t\t\tif ( ( ele === target && Math.abs( o.x - x ) < threshold && Math.abs( o.y - y ) < threshold ) ||\n
\t\t\t\t\t\t\t\t$.data( ele, touchTargetPropertyName ) === o.touchID ) {\n
\t\t\t\t\t\t// XXX: We may want to consider removing matches from the block list\n
\t\t\t\t\t\t//      instead of waiting for the reset timer to fire.\n
\t\t\t\t\t\te.preventDefault();\n
\t\t\t\t\t\te.stopPropagation();\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tele = ele.parentNode;\n
\t\t\t}\n
\t\t}\n
\t}, true);\n
}\n
})( jQuery, window, document );\n
\n
\n
(function( $, window, undefined ) {\n
\tvar $document = $( document ),\n
\t\tsupportTouch = $.mobile.support.touch,\n
\t\tscrollEvent = "touchmove scroll",\n
\t\ttouchStartEvent = supportTouch ? "touchstart" : "mousedown",\n
\t\ttouchStopEvent = supportTouch ? "touchend" : "mouseup",\n
\t\ttouchMoveEvent = supportTouch ? "touchmove" : "mousemove";\n
\n
\t// setup new event shortcuts\n
\t$.each( ( "touchstart touchmove touchend " +\n
\t\t"tap taphold " +\n
\t\t"swipe swipeleft swiperight " +\n
\t\t"scrollstart scrollstop" ).split( " " ), function( i, name ) {\n
\n
\t\t$.fn[ name ] = function( fn ) {\n
\t\t\treturn fn ? this.bind( name, fn ) : this.trigger( name );\n
\t\t};\n
\n
\t\t// jQuery < 1.8\n
\t\tif ( $.attrFn ) {\n
\t\t\t$.attrFn[ name ] = true;\n
\t\t}\n
\t});\n
\n
\tfunction triggerCustomEvent( obj, eventType, event, bubble ) {\n
\t\tvar originalType = event.type;\n
\t\tevent.type = eventType;\n
\t\tif ( bubble ) {\n
\t\t\t$.event.trigger( event, undefined, obj );\n
\t\t} else {\n
\t\t\t$.event.dispatch.call( obj, event );\n
\t\t}\n
\t\tevent.type = originalType;\n
\t}\n
\n
\t// also handles scrollstop\n
\t$.event.special.scrollstart = {\n
\n
\t\tenabled: true,\n
\t\tsetup: function() {\n
\n
\t\t\tvar thisObject = this,\n
\t\t\t\t$this = $( thisObject ),\n
\t\t\t\tscrolling,\n
\t\t\t\ttimer;\n
\n
\t\t\tfunction trigger( event, state ) {\n
\t\t\t\tscrolling = state;\n
\t\t\t\ttriggerCustomEvent( thisObject, scrolling ? "scrollstart" : "scrollstop", event );\n
\t\t\t}\n
\n
\t\t\t// iPhone triggers scroll after a small delay; use touchmove instead\n
\t\t\t$this.bind( scrollEvent, function( event ) {\n
\n
\t\t\t\tif ( !$.event.special.scrollstart.enabled ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( !scrolling ) {\n
\t\t\t\t\ttrigger( event, true );\n
\t\t\t\t}\n
\n
\t\t\t\tclearTimeout( timer );\n
\t\t\t\ttimer = setTimeout( function() {\n
\t\t\t\t\ttrigger( event, false );\n
\t\t\t\t}, 50 );\n
\t\t\t});\n
\t\t},\n
\t\tteardown: function() {\n
\t\t\t$( this ).unbind( scrollEvent );\n
\t\t}\n
\t};\n
\n
\t// also handles taphold\n
\t$.event.special.tap = {\n
\t\ttapholdThreshold: 750,\n
\t\temitTapOnTaphold: true,\n
\t\tsetup: function() {\n
\t\t\tvar thisObject = this,\n
\t\t\t\t$this = $( thisObject ),\n
\t\t\t\tisTaphold = false;\n
\n
\t\t\t$this.bind( "vmousedown", function( event ) {\n
\t\t\t\tisTaphold = false;\n
\t\t\t\tif ( event.which && event.which !== 1 ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\n
\t\t\t\tvar origTarget = event.target,\n
\t\t\t\t\ttimer;\n
\n
\t\t\t\tfunction clearTapTimer() {\n
\t\t\t\t\tclearTimeout( timer );\n
\t\t\t\t}\n
\n
\t\t\t\tfunction clearTapHandlers() {\n
\t\t\t\t\tclearTapTimer();\n
\n
\t\t\t\t\t$this.unbind( "vclick", clickHandler )\n
\t\t\t\t\t\t.unbind( "vmouseup", clearTapTimer );\n
\t\t\t\t\t$document.unbind( "vmousecancel", clearTapHandlers );\n
\t\t\t\t}\n
\n
\t\t\t\tfunction clickHandler( event ) {\n
\t\t\t\t\tclearTapHandlers();\n
\n
\t\t\t\t\t// ONLY trigger a \'tap\' event if the start target is\n
\t\t\t\t\t// the same as the stop target.\n
\t\t\t\t\tif ( !isTaphold && origTarget === event.target ) {\n
\t\t\t\t\t\ttriggerCustomEvent( thisObject, "tap", event );\n
\t\t\t\t\t} else if ( isTaphold ) {\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t$this.bind( "vmouseup", clearTapTimer )\n
\t\t\t\t\t.bind( "vclick", clickHandler );\n
\t\t\t\t$document.bind( "vmousecancel", clearTapHandlers );\n
\n
\t\t\t\ttimer = setTimeout( function() {\n
\t\t\t\t\tif ( !$.event.special.tap.emitTapOnTaphold ) {\n
\t\t\t\t\t\tisTaphold = true;\n
\t\t\t\t\t}\n
\t\t\t\t\ttriggerCustomEvent( thisObject, "taphold", $.Event( "taphold", { target: origTarget } ) );\n
\t\t\t\t}, $.event.special.tap.tapholdThreshold );\n
\t\t\t});\n
\t\t},\n
\t\tteardown: function() {\n
\t\t\t$( this ).unbind( "vmousedown" ).unbind( "vclick" ).unbind( "vmouseup" );\n
\t\t\t$document.unbind( "vmousecancel" );\n
\t\t}\n
\t};\n
\n
\t// Also handles swipeleft, swiperight\n
\t$.event.special.swipe = {\n
\n
\t\t// More than this horizontal displacement, and we will suppress scrolling.\n
\t\tscrollSupressionThreshold: 30,\n
\n
\t\t// More time than this, and it isn\'t a swipe.\n
\t\tdurationThreshold: 1000,\n
\n
\t\t// Swipe horizontal displacement must be more than this.\n
\t\thorizontalDistanceThreshold: 30,\n
\n
\t\t// Swipe vertical displacement must be less than this.\n
\t\tverticalDistanceThreshold: 30,\n
\n
\t\tgetLocation: function ( event ) {\n
\t\t\tvar winPageX = window.pageXOffset,\n
\t\t\t\twinPageY = window.pageYOffset,\n
\t\t\t\tx = event.clientX,\n
\t\t\t\ty = event.clientY;\n
\n
\t\t\tif ( event.pageY === 0 && Math.floor( y ) > Math.floor( event.pageY ) ||\n
\t\t\t\tevent.pageX === 0 && Math.floor( x ) > Math.floor( event.pageX ) ) {\n
\n
\t\t\t\t// iOS4 clientX/clientY have the value that should have been\n
\t\t\t\t// in pageX/pageY. While pageX/page/ have the value 0\n
\t\t\t\tx = x - winPageX;\n
\t\t\t\ty = y - winPageY;\n
\t\t\t} else if ( y < ( event.pageY - winPageY) || x < ( event.pageX - winPageX ) ) {\n
\n
\t\t\t\t// Some Android browsers have totally bogus values for clientX/Y\n
\t\t\t\t// when scrolling/zooming a page. Detectable since clientX/clientY\n
\t\t\t\t// should never be smaller than pageX/pageY minus page scroll\n
\t\t\t\tx = event.pageX - winPageX;\n
\t\t\t\ty = event.pageY - winPageY;\n
\t\t\t}\n
\n
\t\t\treturn {\n
\t\t\t\tx: x,\n
\t\t\t\ty: y\n
\t\t\t};\n
\t\t},\n
\n
\t\tstart: function( event ) {\n
\t\t\tvar data = event.originalEvent.touches ?\n
\t\t\t\t\tevent.originalEvent.touches[ 0 ] : event,\n
\t\t\t\tlocation = $.event.special.swipe.getLocation( data );\n
\t\t\treturn {\n
\t\t\t\t\t\ttime: ( new Date() ).getTime(),\n
\t\t\t\t\t\tcoords: [ location.x, location.y ],\n
\t\t\t\t\t\torigin: $( event.target )\n
\t\t\t\t\t};\n
\t\t},\n
\n
\t\tstop: function( event ) {\n
\t\t\tvar data = event.originalEvent.touches ?\n
\t\t\t\t\tevent.originalEvent.touches[ 0 ] : event,\n
\t\t\t\tlocation = $.event.special.swipe.getLocation( data );\n
\t\t\treturn {\n
\t\t\t\t\t\ttime: ( new Date() ).getTime(),\n
\t\t\t\t\t\tcoords: [ location.x, location.y ]\n
\t\t\t\t\t};\n
\t\t},\n
\n
\t\thandleSwipe: function( start, stop, thisObject, origTarget ) {\n
\t\t\tif ( stop.time - start.time < $.event.special.swipe.durationThreshold &&\n
\t\t\t\tMath.abs( start.coords[ 0 ] - stop.coords[ 0 ] ) > $.event.special.swipe.horizontalDistanceThreshold &&\n
\t\t\t\tMath.abs( start.coords[ 1 ] - stop.coords[ 1 ] ) < $.event.special.swipe.verticalDistanceThreshold ) {\n
\t\t\t\tvar direction = start.coords[0] > stop.coords[ 0 ] ? "swipeleft" : "swiperight";\n
\n
\t\t\t\ttriggerCustomEvent( thisObject, "swipe", $.Event( "swipe", { target: origTarget, swipestart: start, swipestop: stop }), true );\n
\t\t\t\ttriggerCustomEvent( thisObject, direction,$.Event( direction, { target: origTarget, swipestart: start, swipestop: stop } ), true );\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t\treturn false;\n
\n
\t\t},\n
\n
\t\t// This serves as a flag to ensure that at most one swipe event event is\n
\t\t// in work at any given time\n
\t\teventInProgress: false,\n
\n
\t\tsetup: function() {\n
\t\t\tvar events,\n
\t\t\t\tthisObject = this,\n
\t\t\t\t$this = $( thisObject ),\n
\t\t\t\tcontext = {};\n
\n
\t\t\t// Retrieve the events data for this element and add the swipe context\n
\t\t\tevents = $.data( this, "mobile-events" );\n
\t\t\tif ( !events ) {\n
\t\t\t\tevents = { length: 0 };\n
\t\t\t\t$.data( this, "mobile-events", events );\n
\t\t\t}\n
\t\t\tevents.length++;\n
\t\t\tevents.swipe = context;\n
\n
\t\t\tcontext.start = function( event ) {\n
\n
\t\t\t\t// Bail if we\'re already working on a swipe event\n
\t\t\t\tif ( $.event.special.swipe.eventInProgress ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t$.event.special.swipe.eventInProgress = true;\n
\n
\t\t\t\tvar stop,\n
\t\t\t\t\tstart = $.event.special.swipe.start( event ),\n
\t\t\t\t\torigTarget = event.target,\n
\t\t\t\t\temitted = false;\n
\n
\t\t\t\tcontext.move = function( event ) {\n
\t\t\t\t\tif ( !start || event.isDefaultPrevented() ) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tstop = $.event.special.swipe.stop( event );\n
\t\t\t\t\tif ( !emitted ) {\n
\t\t\t\t\t\temitted = $.event.special.swipe.handleSwipe( start, stop, thisObject, origTarget );\n
\t\t\t\t\t\tif ( emitted ) {\n
\n
\t\t\t\t\t\t\t// Reset the context to make way for the next swipe event\n
\t\t\t\t\t\t\t$.event.special.swipe.eventInProgress = false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\t// prevent scrolling\n
\t\t\t\t\tif ( Math.abs( start.coords[ 0 ] - stop.coords[ 0 ] ) > $.event.special.swipe.scrollSupressionThreshold ) {\n
\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\n
\t\t\t\tcontext.stop = function() {\n
\t\t\t\t\t\temitted = true;\n
\n
\t\t\t\t\t\t// Reset the context to make way for the next swipe event\n
\t\t\t\t\t\t$.event.special.swipe.eventInProgress = false;\n
\t\t\t\t\t\t$document.off( touchMoveEvent, context.move );\n
\t\t\t\t\t\tcontext.move = null;\n
\t\t\t\t};\n
\n
\t\t\t\t$document.on( touchMoveEvent, context.move )\n
\t\t\t\t\t.one( touchStopEvent, context.stop );\n
\t\t\t};\n
\t\t\t$this.on( touchStartEvent, context.start );\n
\t\t},\n
\n
\t\tteardown: function() {\n
\t\t\tvar events, context;\n
\n
\t\t\tevents = $.data( this, "mobile-events" );\n
\t\t\tif ( events ) {\n
\t\t\t\tcontext = events.swipe;\n
\t\t\t\tdelete events.swipe;\n
\t\t\t\tevents.length--;\n
\t\t\t\tif ( events.length === 0 ) {\n
\t\t\t\t\t$.removeData( this, "mobile-events" );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( context ) {\n
\t\t\t\tif ( context.start ) {\n
\t\t\t\t\t$( this ).off( touchStartEvent, context.start );\n
\t\t\t\t}\n
\t\t\t\tif ( context.move ) {\n
\t\t\t\t\t$document.off( touchMoveEvent, context.move );\n
\t\t\t\t}\n
\t\t\t\tif ( context.stop ) {\n
\t\t\t\t\t$document.off( touchStopEvent, context.stop );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t};\n
\t$.each({\n
\t\tscrollstop: "scrollstart",\n
\t\ttaphold: "tap",\n
\t\tswipeleft: "swipe.left",\n
\t\tswiperight: "swipe.right"\n
\t}, function( event, sourceEvent ) {\n
\n
\t\t$.event.special[ event ] = {\n
\t\t\tsetup: function() {\n
\t\t\t\t$( this ).bind( sourceEvent, $.noop );\n
\t\t\t},\n
\t\t\tteardown: function() {\n
\t\t\t\t$( this ).unbind( sourceEvent );\n
\t\t\t}\n
\t\t};\n
\t});\n
\n
})( jQuery, this );\n
\n
\n
\t// throttled resize event\n
\t(function( $ ) {\n
\t\t$.event.special.throttledresize = {\n
\t\t\tsetup: function() {\n
\t\t\t\t$( this ).bind( "resize", handler );\n
\t\t\t},\n
\t\t\tteardown: function() {\n
\t\t\t\t$( this ).unbind( "resize", handler );\n
\t\t\t}\n
\t\t};\n
\n
\t\tvar throttle = 250,\n
\t\t\thandler = function() {\n
\t\t\t\tcurr = ( new Date() ).getTime();\n
\t\t\t\tdiff = curr - lastCall;\n
\n
\t\t\t\tif ( diff >= throttle ) {\n
\n
\t\t\t\t\tlastCall = curr;\n
\t\t\t\t\t$( this ).trigger( "throttledresize" );\n
\n
\t\t\t\t} else {\n
\n
\t\t\t\t\tif ( heldCall ) {\n
\t\t\t\t\t\tclearTimeout( heldCall );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Promise a held call will still execute\n
\t\t\t\t\theldCall = setTimeout( handler, throttle - diff );\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tlastCall = 0,\n
\t\t\theldCall,\n
\t\t\tcurr,\n
\t\t\tdiff;\n
\t})( jQuery );\n
\n
\n
(function( $, window ) {\n
\tvar win = $( window ),\n
\t\tevent_name = "orientationchange",\n
\t\tget_orientation,\n
\t\tlast_orientation,\n
\t\tinitial_orientation_is_landscape,\n
\t\tinitial_orientation_is_default,\n
\t\tportrait_map = { "0": true, "180": true },\n
\t\tww, wh, landscape_threshold;\n
\n
\t// It seems that some device/browser vendors use window.orientation values 0 and 180 to\n
\t// denote the "default" orientation. For iOS devices, and most other smart-phones tested,\n
\t// the default orientation is always "portrait", but in some Android and RIM based tablets,\n
\t// the default orientation is "landscape". The following code attempts to use the window\n
\t// dimensions to figure out what the current orientation is, and then makes adjustments\n
\t// to the to the portrait_map if necessary, so that we can properly decode the\n
\t// window.orientation value whenever get_orientation() is called.\n
\t//\n
\t// Note that we used to use a media query to figure out what the orientation the browser\n
\t// thinks it is in:\n
\t//\n
\t//     initial_orientation_is_landscape = $.mobile.media("all and (orientation: landscape)");\n
\t//\n
\t// but there was an iPhone/iPod Touch bug beginning with iOS 4.2, up through iOS 5.1,\n
\t// where the browser *ALWAYS* applied the landscape media query. This bug does not\n
\t// happen on iPad.\n
\n
\tif ( $.support.orientation ) {\n
\n
\t\t// Check the window width and height to figure out what the current orientation\n
\t\t// of the device is at this moment. Note that we\'ve initialized the portrait map\n
\t\t// values to 0 and 180, *AND* we purposely check for landscape so that if we guess\n
\t\t// wrong, , we default to the assumption that portrait is the default orientation.\n
\t\t// We use a threshold check below because on some platforms like iOS, the iPhone\n
\t\t// form-factor can report a larger width than height if the user turns on the\n
\t\t// developer console. The actual threshold value is somewhat arbitrary, we just\n
\t\t// need to make sure it is large enough to exclude the developer console case.\n
\n
\t\tww = window.innerWidth || win.width();\n
\t\twh = window.innerHeight || win.height();\n
\t\tlandscape_threshold = 50;\n
\n
\t\tinitial_orientation_is_landscape = ww > wh && ( ww - wh ) > landscape_threshold;\n
\n
\t\t// Now check to see if the current window.orientation is 0 or 180.\n
\t\tinitial_orientation_is_default = portrait_map[ window.orientation ];\n
\n
\t\t// If the initial orientation is landscape, but window.orientation reports 0 or 180, *OR*\n
\t\t// if the initial orientation is portrait, but window.orientation reports 90 or -90, we\n
\t\t// need to flip our portrait_map values because landscape is the default orientation for\n
\t\t// this device/browser.\n
\t\tif ( ( initial_orientation_is_landscape && initial_orientation_is_default ) || ( !initial_orientation_is_landscape && !initial_orientation_is_default ) ) {\n
\t\t\tportrait_map = { "-90": true, "90": true };\n
\t\t}\n
\t}\n
\n
\t$.event.special.orientationchange = $.extend( {}, $.event.special.orientationchange, {\n
\t\tsetup: function() {\n
\t\t\t// If the event is supported natively, return false so that jQuery\n
\t\t\t// will bind to the event using DOM methods.\n
\t\t\tif ( $.support.orientation && !$.event.special.orientationchange.disabled ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\t// Get the current orientation to avoid initial double-triggering.\n
\t\t\tlast_orientation = get_orientation();\n
\n
\t\t\t// Because the orientationchange event doesn\'t exist, simulate the\n
\t\t\t// event by testing window dimensions on resize.\n
\t\t\twin.bind( "throttledresize", handler );\n
\t\t},\n
\t\tteardown: function() {\n
\t\t\t// If the event is not supported natively, return false so that\n
\t\t\t// jQuery will unbind the event using DOM methods.\n
\t\t\tif ( $.support.orientation && !$.event.special.orientationchange.disabled ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\t// Because the orientationchange event doesn\'t exist, unbind the\n
\t\t\t// resize event handler.\n
\t\t\twin.unbind( "throttledresize", handler );\n
\t\t},\n
\t\tadd: function( handleObj ) {\n
\t\t\t// Save a reference to the bound event handler.\n
\t\t\tvar old_handler = handleObj.handler;\n
\n
\t\t\thandleObj.handler = function( event ) {\n
\t\t\t\t// Modify event object, adding the .orientation property.\n
\t\t\t\tevent.orientation = get_orientation();\n
\n
\t\t\t\t// Call the originally-bound event handler and return its result.\n
\t\t\t\treturn old_handler.apply( this, arguments );\n
\t\t\t};\n
\t\t}\n
\t});\n
\n
\t// If the event is not supported natively, this handler will be bound to\n
\t// the window resize event to simulate the orientationchange event.\n
\tfunction handler() {\n
\t\t// Get the current orientation.\n
\t\tvar orientation = get_orientation();\n
\n
\t\tif ( orientation !== last_orientation ) {\n
\t\t\t// The orientation has changed, so trigger the orientationchange event.\n
\t\t\tlast_orientation = orientation;\n
\t\t\twin.trigger( event_name );\n
\t\t}\n
\t}\n
\n
\t// Get the current page orientation. This method is exposed publicly, should it\n
\t// be needed, as jQuery.event.special.orientationchange.orientation()\n
\t$.event.special.orientationchange.orientation = get_orientation = function() {\n
\t\tvar isPortrait = true, elem = document.documentElement;\n
\n
\t\t// prefer window orientation to the calculation based on screensize as\n
\t\t// the actual screen resize takes place before or after the orientation change event\n
\t\t// has been fired depending on implementation (eg android 2.3 is before, iphone after).\n
\t\t// More testing is required to determine if a more reliable method of determining the new screensize\n
\t\t// is possible when orientationchange is fired. (eg, use media queries + element + opacity)\n
\t\tif ( $.support.orientation ) {\n
\t\t\t// if the window orientation registers as 0 or 180 degrees report\n
\t\t\t// portrait, otherwise landscape\n
\t\t\tisPortrait = portrait_map[ window.orientation ];\n
\t\t} else {\n
\t\t\tisPortrait = elem && elem.clientWidth / elem.clientHeight < 1.1;\n
\t\t}\n
\n
\t\treturn isPortrait ? "portrait" : "landscape";\n
\t};\n
\n
\t$.fn[ event_name ] = function( fn ) {\n
\t\treturn fn ? this.bind( event_name, fn ) : this.trigger( event_name );\n
\t};\n
\n
\t// jQuery < 1.8\n
\tif ( $.attrFn ) {\n
\t\t$.attrFn[ event_name ] = true;\n
\t}\n
\n
}( jQuery, this ));\n
\n
\n
\n
\n
(function( $, undefined ) {\n
\n
\t// existing base tag?\n
\tvar baseElement = $( "head" ).children( "base" ),\n
\n
\t// base element management, defined depending on dynamic base tag support\n
\t// TODO move to external widget\n
\tbase = {\n
\n
\t\t// define base element, for use in routing asset urls that are referenced\n
\t\t// in Ajax-requested markup\n
\t\telement: ( baseElement.length ? baseElement :\n
\t\t\t$( "<base>", { href: $.mobile.path.documentBase.hrefNoHash } ).prependTo( $( "head" ) ) ),\n
\n
\t\tlinkSelector: "[src], link[href], a[rel=\'external\'], :jqmData(ajax=\'false\'), a[target]",\n
\n
\t\t// set the generated BASE element\'s href to a new page\'s base path\n
\t\tset: function( href ) {\n
\n
\t\t\t// we should do nothing if the user wants to manage their url base\n
\t\t\t// manually\n
\t\t\tif ( !$.mobile.dynamicBaseEnabled ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// we should use the base tag if we can manipulate it dynamically\n
\t\t\tif ( $.support.dynamicBaseTag ) {\n
\t\t\t\tbase.element.attr( "href",\n
\t\t\t\t\t$.mobile.path.makeUrlAbsolute( href, $.mobile.path.documentBase ) );\n
\t\t\t}\n
\t\t},\n
\n
\t\trewrite: function( href, page ) {\n
\t\t\tvar newPath = $.mobile.path.get( href );\n
\n
\t\t\tpage.find( base.linkSelector ).each(function( i, link ) {\n
\t\t\t\tvar thisAttr = $( link ).is( "[href]" ) ? "href" :\n
\t\t\t\t\t$( link ).is( "[src]" ) ? "src" : "action",\n
\t\t\t\ttheLocation = $.mobile.path.parseLocation(),\n
\t\t\t\tthisUrl = $( link ).attr( thisAttr );\n
\n
\t\t\t\t// XXX_jblas: We need to fix this so that it removes the document\n
\t\t\t\t//            base URL, and then prepends with the new page URL.\n
\t\t\t\t// if full path exists and is same, chop it - helps IE out\n
\t\t\t\tthisUrl = thisUrl.replace( theLocation.protocol + theLocation.doubleSlash +\n
\t\t\t\t\ttheLocation.host + theLocation.pathname, "" );\n
\n
\t\t\t\tif ( !/^(\\w+:|#|\\/)/.test( thisUrl ) ) {\n
\t\t\t\t\t$( link ).attr( thisAttr, newPath + thisUrl );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t},\n
\n
\t\t// set the generated BASE element\'s href to a new page\'s base path\n
\t\treset: function(/* href */) {\n
\t\t\tbase.element.attr( "href", $.mobile.path.documentBase.hrefNoSearch );\n
\t\t}\n
\t};\n
\n
\t$.mobile.base = base;\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
$.mobile.widgets = {};\n
\n
var originalWidget = $.widget,\n
\n
\t// Record the original, non-mobileinit-modified version of $.mobile.keepNative\n
\t// so we can later determine whether someone has modified $.mobile.keepNative\n
\tkeepNativeFactoryDefault = $.mobile.keepNative;\n
\n
$.widget = (function( orig ) {\n
\treturn function() {\n
\t\tvar constructor = orig.apply( this, arguments ),\n
\t\t\tname = constructor.prototype.widgetName;\n
\n
\t\tconstructor.initSelector = ( ( constructor.prototype.initSelector !== undefined ) ?\n
\t\t\tconstructor.prototype.initSelector : ":jqmData(role=\'" + name + "\')" );\n
\n
\t\t$.mobile.widgets[ name ] = constructor;\n
\n
\t\treturn constructor;\n
\t};\n
})( $.widget );\n
\n
// Make sure $.widget still has bridge and extend methods\n
$.extend( $.widget, originalWidget );\n
\n
// For backcompat remove in 1.5\n
$.mobile.document.on( "create", function( event ) {\n
\t$( event.target ).enhanceWithin();\n
});\n
\n
$.widget( "mobile.page", {\n
\toptions: {\n
\t\ttheme: "a",\n
\t\tdomCache: false,\n
\n
\t\t// Deprecated in 1.4 remove in 1.5\n
\t\tkeepNativeDefault: $.mobile.keepNative,\n
\n
\t\t// Deprecated in 1.4 remove in 1.5\n
\t\tcontentTheme: null,\n
\t\tenhanced: false\n
\t},\n
\n
\t// DEPRECATED for > 1.4\n
\t// TODO remove at 1.5\n
\t_createWidget: function() {\n
\t\t$.Widget.prototype._createWidget.apply( this, arguments );\n
\t\tthis._trigger( "init" );\n
\t},\n
\n
\t_create: function() {\n
\t\t// If false is returned by the callbacks do not create the page\n
\t\tif ( this._trigger( "beforecreate" ) === false ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif ( !this.options.enhanced ) {\n
\t\t\tthis._enhance();\n
\t\t}\n
\n
\t\tthis._on( this.element, {\n
\t\t\tpagebeforehide: "removeContainerBackground",\n
\t\t\tpagebeforeshow: "_handlePageBeforeShow"\n
\t\t});\n
\n
\t\tthis.element.enhanceWithin();\n
\t\t// Dialog widget is deprecated in 1.4 remove this in 1.5\n
\t\tif ( $.mobile.getAttribute( this.element[0], "role" ) === "dialog" && $.mobile.dialog ) {\n
\t\t\tthis.element.dialog();\n
\t\t}\n
\t},\n
\n
\t_enhance: function () {\n
\t\tvar attrPrefix = "data-" + $.mobile.ns,\n
\t\t\tself = this;\n
\n
\t\tif ( this.options.role ) {\n
\t\t\tthis.element.attr( "data-" + $.mobile.ns + "role", this.options.role );\n
\t\t}\n
\n
\t\tthis.element\n
\t\t\t.attr( "tabindex", "0" )\n
\t\t\t.addClass( "ui-page ui-page-theme-" + this.options.theme );\n
\n
\t\t// Manipulation of content os Deprecated as of 1.4 remove in 1.5\n
\t\tthis.element.find( "[" + attrPrefix + "role=\'content\']" ).each( function() {\n
\t\t\tvar $this = $( this ),\n
\t\t\t\ttheme = this.getAttribute( attrPrefix + "theme" ) || undefined;\n
\t\t\t\tself.options.contentTheme = theme || self.options.contentTheme || ( self.options.dialog && self.options.theme ) || ( self.element.jqmData("role") === "dialog" &&  self.options.theme );\n
\t\t\t\t$this.addClass( "ui-content" );\n
\t\t\t\tif ( self.options.contentTheme ) {\n
\t\t\t\t\t$this.addClass( "ui-body-" + ( self.options.contentTheme ) );\n
\t\t\t\t}\n
\t\t\t\t// Add ARIA role\n
\t\t\t\t$this.attr( "role", "main" ).addClass( "ui-content" );\n
\t\t});\n
\t},\n
\n
\tbindRemove: function( callback ) {\n
\t\tvar page = this.element;\n
\n
\t\t// when dom caching is not enabled or the page is embedded bind to remove the page on hide\n
\t\tif ( !page.data( "mobile-page" ).options.domCache &&\n
\t\t\tpage.is( ":jqmData(external-page=\'true\')" ) ) {\n
\n
\t\t\t// TODO use _on - that is, sort out why it doesn\'t work in this case\n
\t\t\tpage.bind( "pagehide.remove", callback || function( e, data ) {\n
\n
\t\t\t\t//check if this is a same page transition and if so don\'t remove the page\n
\t\t\t\tif( !data.samePage ){\n
\t\t\t\t\tvar $this = $( this ),\n
\t\t\t\t\t\tprEvent = new $.Event( "pageremove" );\n
\n
\t\t\t\t\t$this.trigger( prEvent );\n
\n
\t\t\t\t\tif ( !prEvent.isDefaultPrevented() ) {\n
\t\t\t\t\t\t$this.removeWithDependents();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( o ) {\n
\t\tif ( o.theme !== undefined ) {\n
\t\t\tthis.element.removeClass( "ui-page-theme-" + this.options.theme ).addClass( "ui-page-theme-" + o.theme );\n
\t\t}\n
\n
\t\tif ( o.contentTheme !== undefined ) {\n
\t\t\tthis.element.find( "[data-" + $.mobile.ns + "=\'content\']" ).removeClass( "ui-body-" + this.options.contentTheme )\n
\t\t\t\t.addClass( "ui-body-" + o.contentTheme );\n
\t\t}\n
\t},\n
\n
\t_handlePageBeforeShow: function(/* e */) {\n
\t\tthis.setContainerBackground();\n
\t},\n
\t// Deprecated in 1.4 remove in 1.5\n
\tremoveContainerBackground: function() {\n
\t\tthis.element.closest( ":mobile-pagecontainer" ).pagecontainer({ "theme": "none" });\n
\t},\n
\t// Deprecated in 1.4 remove in 1.5\n
\t// set the page container background to the page theme\n
\tsetContainerBackground: function( theme ) {\n
\t\tthis.element.parent().pagecontainer( { "theme": theme || this.options.theme } );\n
\t},\n
\t// Deprecated in 1.4 remove in 1.5\n
\tkeepNativeSelector: function() {\n
\t\tvar options = this.options,\n
\t\t\tkeepNative = $.trim( options.keepNative || "" ),\n
\t\t\tglobalValue = $.trim( $.mobile.keepNative ),\n
\t\t\toptionValue = $.trim( options.keepNativeDefault ),\n
\n
\t\t\t// Check if $.mobile.keepNative has changed from the factory default\n
\t\t\tnewDefault = ( keepNativeFactoryDefault === globalValue ?\n
\t\t\t\t"" : globalValue ),\n
\n
\t\t\t// If $.mobile.keepNative has not changed, use options.keepNativeDefault\n
\t\t\toldDefault = ( newDefault === "" ? optionValue : "" );\n
\n
\t\t// Concatenate keepNative selectors from all sources where the value has\n
\t\t// changed or, if nothing has changed, return the default\n
\t\treturn ( ( keepNative ? [ keepNative ] : [] )\n
\t\t\t.concat( newDefault ? [ newDefault ] : [] )\n
\t\t\t.concat( oldDefault ? [ oldDefault ] : [] )\n
\t\t\t.join( ", " ) );\n
\t}\n
});\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
\t$.widget( "mobile.pagecontainer", {\n
\t\toptions: {\n
\t\t\ttheme: "a"\n
\t\t},\n
\n
\t\tinitSelector: false,\n
\n
\t\t_create: function() {\n
\t\t\tthis._trigger( "beforecreate" );\n
\t\t\tthis.setLastScrollEnabled = true;\n
\n
\t\t\tthis._on( this.window, {\n
\t\t\t\t// disable an scroll setting when a hashchange has been fired,\n
\t\t\t\t// this only works because the recording of the scroll position\n
\t\t\t\t// is delayed for 100ms after the browser might have changed the\n
\t\t\t\t// position because of the hashchange\n
\t\t\t\tnavigate: "_disableRecordScroll",\n
\n
\t\t\t\t// bind to scrollstop for the first page, "pagechange" won\'t be\n
\t\t\t\t// fired in that case\n
\t\t\t\tscrollstop: "_delayedRecordScroll"\n
\t\t\t});\n
\n
\t\t\t// TODO consider moving the navigation handler OUT of widget into\n
\t\t\t//      some other object as glue between the navigate event and the\n
\t\t\t//      content widget load and change methods\n
\t\t\tthis._on( this.window, { navigate: "_filterNavigateEvents" });\n
\n
\t\t\t// TODO move from page* events to content* events\n
\t\t\tthis._on({ pagechange: "_afterContentChange" });\n
\n
\t\t\t// handle initial hashchange from chrome :(\n
\t\t\tthis.window.one( "navigate", $.proxy(function() {\n
\t\t\t\tthis.setLastScrollEnabled = true;\n
\t\t\t}, this));\n
\t\t},\n
\n
\t\t_setOptions: function( options ) {\n
\t\t\tif ( options.theme !== undefined && options.theme !== "none" ) {\n
\t\t\t\tthis.element.removeClass( "ui-overlay-" + this.options.theme )\n
\t\t\t\t\t.addClass( "ui-overlay-" + options.theme );\n
\t\t\t} else if ( options.theme !== undefined ) {\n
\t\t\t\tthis.element.removeClass( "ui-overlay-" + this.options.theme );\n
\t\t\t}\n
\n
\t\t\tthis._super( options );\n
\t\t},\n
\n
\t\t_disableRecordScroll: function() {\n
\t\t\tthis.setLastScrollEnabled = false;\n
\t\t},\n
\n
\t\t_enableRecordScroll: function() {\n
\t\t\tthis.setLastScrollEnabled = true;\n
\t\t},\n
\n
\t\t// TODO consider the name here, since it\'s purpose specific\n
\t\t_afterContentChange: function() {\n
\t\t\t// once the page has changed, re-enable the scroll recording\n
\t\t\tthis.setLastScrollEnabled = true;\n
\n
\t\t\t// remove any binding that previously existed on the get scroll\n
\t\t\t// which may or may not be different than the scroll element\n
\t\t\t// determined for this page previously\n
\t\t\tthis._off( this.window, "scrollstop" );\n
\n
\t\t\t// determine and bind to the current scoll element which may be the\n
\t\t\t// window or in the case of touch overflow the element touch overflow\n
\t\t\tthis._on( this.window, { scrollstop: "_delayedRecordScroll" });\n
\t\t},\n
\n
\t\t_recordScroll: function() {\n
\t\t\t// this barrier prevents setting the scroll value based on\n
\t\t\t// the browser scrolling the window based on a hashchange\n
\t\t\tif ( !this.setLastScrollEnabled ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tvar active = this._getActiveHistory(),\n
\t\t\t\tcurrentScroll, minScroll, defaultScroll;\n
\n
\t\t\tif ( active ) {\n
\t\t\t\tcurrentScroll = this._getScroll();\n
\t\t\t\tminScroll = this._getMinScroll();\n
\t\t\t\tdefaultScroll = this._getDefaultScroll();\n
\n
\t\t\t\t// Set active page\'s lastScroll prop. If the location we\'re\n
\t\t\t\t// scrolling to is less than minScrollBack, let it go.\n
\t\t\t\tactive.lastScroll = currentScroll < minScroll ? defaultScroll : currentScroll;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_delayedRecordScroll: function() {\n
\t\t\tsetTimeout( $.proxy(this, "_recordScroll"), 100 );\n
\t\t},\n
\n
\t\t_getScroll: function() {\n
\t\t\treturn this.window.scrollTop();\n
\t\t},\n
\n
\t\t_getMinScroll: function() {\n
\t\t\treturn $.mobile.minScrollBack;\n
\t\t},\n
\n
\t\t_getDefaultScroll: function() {\n
\t\t\treturn $.mobile.defaultHomeScroll;\n
\t\t},\n
\n
\t\t_filterNavigateEvents: function( e, data ) {\n
\t\t\tvar url;\n
\n
\t\t\tif ( e.originalEvent && e.originalEvent.isDefaultPrevented() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\turl = e.originalEvent.type.indexOf( "hashchange" ) > -1 ? data.state.hash : data.state.url;\n
\n
\t\t\tif ( !url ) {\n
\t\t\t\turl = this._getHash();\n
\t\t\t}\n
\n
\t\t\tif ( !url || url === "#" || url.indexOf( "#" + $.mobile.path.uiStateKey ) === 0 ) {\n
\t\t\t\turl = location.href;\n
\t\t\t}\n
\n
\t\t\tthis._handleNavigate( url, data.state );\n
\t\t},\n
\n
\t\t_getHash: function() {\n
\t\t\treturn $.mobile.path.parseLocation().hash;\n
\t\t},\n
\n
\t\t// TODO active page should be managed by the container (ie, it should be a property)\n
\t\tgetActivePage: function() {\n
\t\t\treturn this.activePage;\n
\t\t},\n
\n
\t\t// TODO the first page should be a property set during _create using the logic\n
\t\t//      that currently resides in init\n
\t\t_getInitialContent: function() {\n
\t\t\treturn $.mobile.firstPage;\n
\t\t},\n
\n
\t\t// TODO each content container should have a history object\n
\t\t_getHistory: function() {\n
\t\t\treturn $.mobile.navigate.history;\n
\t\t},\n
\n
\t\t_getActiveHistory: function() {\n
\t\t\treturn this._getHistory().getActive();\n
\t\t},\n
\n
\t\t// TODO the document base should be determined at creation\n
\t\t_getDocumentBase: function() {\n
\t\t\treturn $.mobile.path.documentBase;\n
\t\t},\n
\n
\t\tback: function() {\n
\t\t\tthis.go( -1 );\n
\t\t},\n
\n
\t\tforward: function() {\n
\t\t\tthis.go( 1 );\n
\t\t},\n
\n
\t\tgo: function( steps ) {\n
\n
\t\t\t//if hashlistening is enabled use native history method\n
\t\t\tif ( $.mobile.hashListeningEnabled ) {\n
\t\t\t\twindow.history.go( steps );\n
\t\t\t} else {\n
\n
\t\t\t\t//we are not listening to the hash so handle history internally\n
\t\t\t\tvar activeIndex = $.mobile.navigate.history.activeIndex,\n
\t\t\t\t\tindex = activeIndex + parseInt( steps, 10 ),\n
\t\t\t\t\turl = $.mobile.navigate.history.stack[ index ].url,\n
\t\t\t\t\tdirection = ( steps >= 1 )? "forward" : "back";\n
\n
\t\t\t\t//update the history object\n
\t\t\t\t$.mobile.navigate.history.activeIndex = index;\n
\t\t\t\t$.mobile.navigate.history.previousIndex = activeIndex;\n
\n
\t\t\t\t//change to the new page\n
\t\t\t\tthis.change( url, { direction: direction, changeHash: false, fromHashChange: true } );\n
\t\t\t}\n
\t\t},\n
\n
\t\t// TODO rename _handleDestination\n
\t\t_handleDestination: function( to ) {\n
\t\t\tvar history;\n
\n
\t\t\t// clean the hash for comparison if it\'s a url\n
\t\t\tif ( $.type(to) === "string" ) {\n
\t\t\t\tto = $.mobile.path.stripHash( to );\n
\t\t\t}\n
\n
\t\t\tif ( to ) {\n
\t\t\t\thistory = this._getHistory();\n
\n
\t\t\t\t// At this point, \'to\' can be one of 3 things, a cached page\n
\t\t\t\t// element from a history stack entry, an id, or site-relative /\n
\t\t\t\t// absolute URL. If \'to\' is an id, we need to resolve it against\n
\t\t\t\t// the documentBase, not the location.href, since the hashchange\n
\t\t\t\t// could\'ve been the result of a forward/backward navigation\n
\t\t\t\t// that crosses from an external page/dialog to an internal\n
\t\t\t\t// page/dialog.\n
\t\t\t\t//\n
\t\t\t\t// TODO move check to history object or path object?\n
\t\t\t\tto = !$.mobile.path.isPath( to ) ? ( $.mobile.path.makeUrlAbsolute( "#" + to, this._getDocumentBase() ) ) : to;\n
\t\t\t}\n
\t\t\treturn to || this._getInitialContent();\n
\t\t},\n
\n
\t\t// The options by which a given page was reached are stored in the history entry for that\n
\t\t// page. When this function is called, history is already at the new entry. So, when moving\n
\t\t// back, this means we need to consult the old entry and reverse the meaning of the\n
\t\t// options. Otherwise, if we\'re moving forward, we need to consult the options for the\n
\t\t// current entry.\n
\t\t_optionFromHistory: function( direction, optionName, fallbackValue ) {\n
\t\t\tvar history = this._getHistory(),\n
\t\t\t\tentry = ( direction === "back" ? history.getLast() : history.getActive() );\n
\n
\t\t\treturn ( ( entry && entry[ optionName ] ) || fallbackValue );\n
\t\t},\n
\n
\t\t_handleDialog: function( changePageOptions, data ) {\n
\t\t\tvar to, active, activeContent = this.getActivePage();\n
\n
\t\t\t// If current active page is not a dialog skip the dialog and continue\n
\t\t\t// in the same direction\n
\t\t\t// Note: The dialog widget is deprecated as of 1.4.0 and will be removed in 1.5.0.\n
\t\t\t// Thus, as of 1.5.0 activeContent.data( "mobile-dialog" ) will always evaluate to\n
\t\t\t// falsy, so the second condition in the if-statement below can be removed altogether.\n
\t\t\tif ( activeContent && !activeContent.data( "mobile-dialog" ) ) {\n
\t\t\t\t// determine if we\'re heading forward or backward and continue\n
\t\t\t\t// accordingly past the current dialog\n
\t\t\t\tif ( data.direction === "back" ) {\n
\t\t\t\t\tthis.back();\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.forward();\n
\t\t\t\t}\n
\n
\t\t\t\t// prevent changePage call\n
\t\t\t\treturn false;\n
\t\t\t} else {\n
\t\t\t\t// if the current active page is a dialog and we\'re navigating\n
\t\t\t\t// to a dialog use the dialog objected saved in the stack\n
\t\t\t\tto = data.pageUrl;\n
\t\t\t\tactive = this._getActiveHistory();\n
\n
\t\t\t\t// make sure to set the role, transition and reversal\n
\t\t\t\t// as most of this is lost by the domCache cleaning\n
\t\t\t\t$.extend( changePageOptions, {\n
\t\t\t\t\trole: active.role,\n
\t\t\t\t\ttransition: this._optionFromHistory( data.direction, "transition",\n
\t\t\t\t\t\tchangePageOptions.transition ),\n
\t\t\t\t\treverse: data.direction === "back"\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\treturn to;\n
\t\t},\n
\n
\t\t_handleNavigate: function( url, data ) {\n
\t\t\t//find first page via hash\n
\t\t\t// TODO stripping the hash twice with handleUrl\n
\t\t\tvar to = $.mobile.path.stripHash( url ), history = this._getHistory(),\n
\n
\t\t\t\t// transition is false if it\'s the first page, undefined\n
\t\t\t\t// otherwise (and may be overridden by default)\n
\t\t\t\ttransition = history.stack.length === 0 ? "none" :\n
\t\t\t\t\tthis._optionFromHistory( data.direction, "transition" ),\n
\n
\t\t\t\t// default options for the changPage calls made after examining\n
\t\t\t\t// the current state of the page and the hash, NOTE that the\n
\t\t\t\t// transition is derived from the previous history entry\n
\t\t\t\tchangePageOptions = {\n
\t\t\t\t\tchangeHash: false,\n
\t\t\t\t\tfromHashChange: true,\n
\t\t\t\t\treverse: data.direction === "back"\n
\t\t\t\t};\n
\n
\t\t\t$.extend( changePageOptions, data, {\n
\t\t\t\ttransition: transition,\n
\t\t\t\tallowSamePageTransition: this._optionFromHistory( data.direction,\n
\t\t\t\t\t"allowSamePageTransition" )\n
\t\t\t});\n
\n
\t\t\t// TODO move to _handleDestination ?\n
\t\t\t// If this isn\'t the first page, if the current url is a dialog hash\n
\t\t\t// key, and the initial destination isn\'t equal to the current target\n
\t\t\t// page, use the special dialog handling\n
\t\t\tif ( history.activeIndex > 0 &&\n
\t\t\t\tto.indexOf( $.mobile.dialogHashKey ) > -1 ) {\n
\n
\t\t\t\tto = this._handleDialog( changePageOptions, data );\n
\n
\t\t\t\tif ( to === false ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tthis._changeContent( this._handleDestination( to ), changePageOptions );\n
\t\t},\n
\n
\t\t_changeContent: function( to, opts ) {\n
\t\t\t$.mobile.changePage( to, opts );\n
\t\t},\n
\n
\t\t_getBase: function() {\n
\t\t\treturn $.mobile.base;\n
\t\t},\n
\n
\t\t_getNs: function() {\n
\t\t\treturn $.mobile.ns;\n
\t\t},\n
\n
\t\t_enhance: function( content, role ) {\n
\t\t\t// TODO consider supporting a custom callback, and passing in\n
\t\t\t// the settings which includes the role\n
\t\t\treturn content.page({ role: role });\n
\t\t},\n
\n
\t\t_include: function( page, settings ) {\n
\t\t\t// append to page and enhance\n
\t\t\tpage.appendTo( this.element );\n
\n
\t\t\t// use the page widget to enhance\n
\t\t\tthis._enhance( page, settings.role );\n
\n
\t\t\t// remove page on hide\n
\t\t\tpage.page( "bindRemove" );\n
\t\t},\n
\n
\t\t_find: function( absUrl ) {\n
\t\t\t// TODO consider supporting a custom callback\n
\t\t\tvar fileUrl = this._createFileUrl( absUrl ),\n
\t\t\t\tdataUrl = this._createDataUrl( absUrl ),\n
\t\t\t\tpage, initialContent = this._getInitialContent();\n
\n
\t\t\t// Check to see if the page already exists in the DOM.\n
\t\t\t// NOTE do _not_ use the :jqmData pseudo selector because parenthesis\n
\t\t\t//      are a valid url char and it breaks on the first occurence\n
\t\t\tpage = this.element\n
\t\t\t\t.children( "[data-" + this._getNs() +"url=\'" + dataUrl + "\']" );\n
\n
\t\t\t// If we failed to find the page, check to see if the url is a\n
\t\t\t// reference to an embedded page. If so, it may have been dynamically\n
\t\t\t// injected by a developer, in which case it would be lacking a\n
\t\t\t// data-url attribute and in need of enhancement.\n
\t\t\tif ( page.length === 0 && dataUrl && !$.mobile.path.isPath( dataUrl ) ) {\n
\t\t\t\tpage = this.element.children( $.mobile.path.hashToSelector("#" + dataUrl) )\n
\t\t\t\t\t.attr( "data-" + this._getNs() + "url", dataUrl )\n
\t\t\t\t\t.jqmData( "url", dataUrl );\n
\t\t\t}\n
\n
\t\t\t// If we failed to find a page in the DOM, check the URL to see if it\n
\t\t\t// refers to the first page in the application. Also check to make sure\n
\t\t\t// our cached-first-page is actually in the DOM. Some user deployed\n
\t\t\t// apps are pruning the first page from the DOM for various reasons.\n
\t\t\t// We check for this case here because we don\'t want a first-page with\n
\t\t\t// an id falling through to the non-existent embedded page error case.\n
\t\t\tif ( page.length === 0 &&\n
\t\t\t\t$.mobile.path.isFirstPageUrl( fileUrl ) &&\n
\t\t\t\tinitialContent &&\n
\t\t\t\tinitialContent.parent().length ) {\n
\t\t\t\tpage = $( initialContent );\n
\t\t\t}\n
\n
\t\t\treturn page;\n
\t\t},\n
\n
\t\t_getLoader: function() {\n
\t\t\treturn $.mobile.loading();\n
\t\t},\n
\n
\t\t_showLoading: function( delay, theme, msg, textonly ) {\n
\t\t\t// This configurable timeout allows cached pages a brief\n
\t\t\t// delay to load without showing a message\n
\t\t\tif ( this._loadMsg ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tthis._loadMsg = setTimeout($.proxy(function() {\n
\t\t\t\tthis._getLoader().loader( "show", theme, msg, textonly );\n
\t\t\t\tthis._loadMsg = 0;\n
\t\t\t}, this), delay );\n
\t\t},\n
\n
\t\t_hideLoading: function() {\n
\t\t\t// Stop message show timer\n
\t\t\tclearTimeout( this._loadMsg );\n
\t\t\tthis._loadMsg = 0;\n
\n
\t\t\t// Hide loading message\n
\t\t\tthis._getLoader().loader( "hide" );\n
\t\t},\n
\n
\t\t_showError: function() {\n
\t\t\t// make sure to remove the current loading message\n
\t\t\tthis._hideLoading();\n
\n
\t\t\t// show the error message\n
\t\t\tthis._showLoading( 0, $.mobile.pageLoadErrorMessageTheme, $.mobile.pageLoadErrorMessage, true );\n
\n
\t\t\t// hide the error message after a delay\n
\t\t\t// TODO configuration\n
\t\t\tsetTimeout( $.proxy(this, "_hideLoading"), 1500 );\n
\t\t},\n
\n
\t\t_parse: function( html, fileUrl ) {\n
\t\t\t// TODO consider allowing customization of this method. It\'s very JQM specific\n
\t\t\tvar page, all = $( "<div></div>" );\n
\n
\t\t\t//workaround to allow scripts to execute when included in page divs\n
\t\t\tall.get( 0 ).innerHTML = html;\n
\n
\t\t\tpage = all.find( ":jqmData(role=\'page\'), :jqmData(role=\'dialog\')" ).first();\n
\n
\t\t\t//if page elem couldn\'t be found, create one and insert the body element\'s contents\n
\t\t\tif ( !page.length ) {\n
\t\t\t\tpage = $( "<div data-" + this._getNs() + "role=\'page\'>" +\n
\t\t\t\t\t( html.split( /<\\/?body[^>]*>/gmi )[1] || "" ) +\n
\t\t\t\t\t"</div>" );\n
\t\t\t}\n
\n
\t\t\t// TODO tagging a page with external to make sure that embedded pages aren\'t\n
\t\t\t// removed by the various page handling code is bad. Having page handling code\n
\t\t\t// in many places is bad. Solutions post 1.0\n
\t\t\tpage.attr( "data-" + this._getNs() + "url", $.mobile.path.convertUrlToDataUrl(fileUrl) )\n
\t\t\t\t.attr( "data-" + this._getNs() + "external-page", true );\n
\n
\t\t\treturn page;\n
\t\t},\n
\n
\t\t_setLoadedTitle: function( page, html ) {\n
\t\t\t//page title regexp\n
\t\t\tvar newPageTitle = html.match( /<title[^>]*>([^<]*)/ ) && RegExp.$1;\n
\n
\t\t\tif ( newPageTitle && !page.jqmData("title") ) {\n
\t\t\t\tnewPageTitle = $( "<div>" + newPageTitle + "</div>" ).text();\n
\t\t\t\tpage.jqmData( "title", newPageTitle );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_isRewritableBaseTag: function() {\n
\t\t\treturn $.mobile.dynamicBaseEnabled && !$.support.dynamicBaseTag;\n
\t\t},\n
\n
\t\t_createDataUrl: function( absoluteUrl ) {\n
\t\t\treturn $.mobile.path.convertUrlToDataUrl( absoluteUrl );\n
\t\t},\n
\n
\t\t_createFileUrl: function( absoluteUrl ) {\n
\t\t\treturn $.mobile.path.getFilePath( absoluteUrl );\n
\t\t},\n
\n
\t\t_triggerWithDeprecated: function( name, data, page ) {\n
\t\t\tvar deprecatedEvent = $.Event( "page" + name ),\n
\t\t\t\tnewEvent = $.Event( this.widgetName + name );\n
\n
\t\t\t// DEPRECATED\n
\t\t\t// trigger the old deprecated event on the page if it\'s provided\n
\t\t\t( page || this.element ).trigger( deprecatedEvent, data );\n
\n
\t\t\t// use the widget trigger method for the new content* event\n
\t\t\tthis._trigger( name, newEvent, data );\n
\n
\t\t\treturn {\n
\t\t\t\tdeprecatedEvent: deprecatedEvent,\n
\t\t\t\tevent: newEvent\n
\t\t\t};\n
\t\t},\n
\n
\t\t// TODO it would be nice to split this up more but everything appears to be "one off"\n
\t\t//      or require ordering such that other bits are sprinkled in between parts that\n
\t\t//      could be abstracted out as a group\n
\t\t_loadSuccess: function( absUrl, triggerData, settings, deferred ) {\n
\t\t\tvar fileUrl = this._createFileUrl( absUrl ),\n
\t\t\t\tdataUrl = this._createDataUrl( absUrl );\n
\n
\t\t\treturn $.proxy(function( html, textStatus, xhr ) {\n
\t\t\t\t//pre-parse html to check for a data-url,\n
\t\t\t\t//use it as the new fileUrl, base path, etc\n
\t\t\t\tvar content,\n
\n
\t\t\t\t\t// TODO handle dialogs again\n
\t\t\t\t\tpageElemRegex = new RegExp( "(<[^>]+\\\\bdata-" + this._getNs() + "role=[\\"\']?page[\\"\']?[^>]*>)" ),\n
\n
\t\t\t\t\tdataUrlRegex = new RegExp( "\\\\bdata-" + this._getNs() + "url=[\\"\']?([^\\"\'>]*)[\\"\']?" );\n
\n
\t\t\t\t// data-url must be provided for the base tag so resource requests\n
\t\t\t\t// can be directed to the correct url. loading into a temprorary\n
\t\t\t\t// element makes these requests immediately\n
\t\t\t\tif ( pageElemRegex.test( html ) &&\n
\t\t\t\t\tRegExp.$1 &&\n
\t\t\t\t\tdataUrlRegex.test( RegExp.$1 ) &&\n
\t\t\t\t\tRegExp.$1 ) {\n
\t\t\t\t\tfileUrl = $.mobile.path.getFilePath( $("<div>" + RegExp.$1 + "</div>").text() );\n
\t\t\t\t}\n
\n
\t\t\t\t//dont update the base tag if we are prefetching\n
\t\t\t\tif ( settings.prefetch === undefined ) {\n
\t\t\t\t\tthis._getBase().set( fileUrl );\n
\t\t\t\t}\n
\n
\t\t\t\tcontent = this._parse( html, fileUrl );\n
\n
\t\t\t\tthis._setLoadedTitle( content, html );\n
\n
\t\t\t\t// Add the content reference and xhr to our triggerData.\n
\t\t\t\ttriggerData.xhr = xhr;\n
\t\t\t\ttriggerData.textStatus = textStatus;\n
\n
\t\t\t\t// DEPRECATED\n
\t\t\t\ttriggerData.page = content;\n
\n
\t\t\t\ttriggerData.content = content;\n
\n
\t\t\t\ttriggerData.toPage = content;\n
\n
\t\t\t\t// If the default behavior is prevented, stop here!\n
\t\t\t\t// Note that it is the responsibility of the listener/handler\n
\t\t\t\t// that called preventDefault(), to resolve/reject the\n
\t\t\t\t// deferred object within the triggerData.\n
\t\t\t\tif ( this._triggerWithDeprecated( "load", triggerData ).event.isDefaultPrevented() ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\t// rewrite src and href attrs to use a base url if the base tag won\'t work\n
\t\t\t\tif ( this._isRewritableBaseTag() && content ) {\n
\t\t\t\t\tthis._getBase().rewrite( fileUrl, content );\n
\t\t\t\t}\n
\n
\t\t\t\tthis._include( content, settings );\n
\n
\t\t\t\t// Enhancing the content may result in new dialogs/sub content being inserted\n
\t\t\t\t// into the DOM. If the original absUrl refers to a sub-content, that is the\n
\t\t\t\t// real content we are interested in.\n
\t\t\t\tif ( absUrl.indexOf( "&" + $.mobile.subPageUrlKey ) > -1 ) {\n
\t\t\t\t\tcontent = this.element.children( "[data-" + this._getNs() +"url=\'" + dataUrl + "\']" );\n
\t\t\t\t}\n
\n
\t\t\t\t// Remove loading message.\n
\t\t\t\tif ( settings.showLoadMsg ) {\n
\t\t\t\t\tthis._hideLoading();\n
\t\t\t\t}\n
\n
\t\t\t\tdeferred.resolve( absUrl, settings, content );\n
\t\t\t}, this);\n
\t\t},\n
\n
\t\t_loadDefaults: {\n
\t\t\ttype: "get",\n
\t\t\tdata: undefined,\n
\n
\t\t\t// DEPRECATED\n
\t\t\treloadPage: false,\n
\n
\t\t\treload: false,\n
\n
\t\t\t// By default we rely on the role defined by the @data-role attribute.\n
\t\t\trole: undefined,\n
\n
\t\t\tshowLoadMsg: false,\n
\n
\t\t\t// This delay allows loads that pull from browser cache to\n
\t\t\t// occur without showing the loading message.\n
\t\t\tloadMsgDelay: 50\n
\t\t},\n
\n
\t\tload: function( url, options ) {\n
\t\t\t// This function uses deferred notifications to let callers\n
\t\t\t// know when the content is done loading, or if an error has occurred.\n
\t\t\tvar deferred = ( options && options.deferred ) || $.Deferred(),\n
\n
\t\t\t\t// The default load options with overrides specified by the caller.\n
\t\t\t\tsettings = $.extend( {}, this._loadDefaults, options ),\n
\n
\t\t\t\t// The DOM element for the content after it has been loaded.\n
\t\t\t\tcontent = null,\n
\n
\t\t\t\t// The absolute version of the URL passed into the function. This\n
\t\t\t\t// version of the URL may contain dialog/subcontent params in it.\n
\t\t\t\tabsUrl = $.mobile.path.makeUrlAbsolute( url, this._findBaseWithDefault() ),\n
\t\t\t\tfileUrl, dataUrl, pblEvent, triggerData;\n
\n
\t\t\t// DEPRECATED reloadPage\n
\t\t\tsettings.reload = settings.reloadPage;\n
\n
\t\t\t// If the caller provided data, and we\'re using "get" request,\n
\t\t\t// append the data to the URL.\n
\t\t\tif ( settings.data && settings.type === "get" ) {\n
\t\t\t\tabsUrl = $.mobile.path.addSearchParams( absUrl, settings.data );\n
\t\t\t\tsettings.data = undefined;\n
\t\t\t}\n
\n
\t\t\t// If the caller is using a "post" request, reload must be true\n
\t\t\tif ( settings.data && settings.type === "post" ) {\n
\t\t\t\tsettings.reload = true;\n
\t\t\t}\n
\n
\t\t\t// The absolute version of the URL minus any dialog/subcontent params.\n
\t\t\t// In otherwords the real URL of the content to be loaded.\n
\t\t\tfileUrl = this._createFileUrl( absUrl );\n
\n
\t\t\t// The version of the Url actually stored in the data-url attribute of\n
\t\t\t// the content. For embedded content, it is just the id of the page. For\n
\t\t\t// content within the same domain as the document base, it is the site\n
\t\t\t// relative path. For cross-domain content (Phone Gap only) the entire\n
\t\t\t// absolute Url is used to load the content.\n
\t\t\tdataUrl = this._createDataUrl( absUrl );\n
\n
\t\t\tcontent = this._find( absUrl );\n
\n
\t\t\t// If it isn\'t a reference to the first content and refers to missing\n
\t\t\t// embedded content reject the deferred and return\n
\t\t\tif ( content.length === 0 &&\n
\t\t\t\t$.mobile.path.isEmbeddedPage(fileUrl) &&\n
\t\t\t\t!$.mobile.path.isFirstPageUrl(fileUrl) ) {\n
\t\t\t\tdeferred.reject( absUrl, settings );\n
\t\t\t\treturn deferred.promise();\n
\t\t\t}\n
\n
\t\t\t// Reset base to the default document base\n
\t\t\t// TODO figure out why we doe this\n
\t\t\tthis._getBase().reset();\n
\n
\t\t\t// If the content we are interested in is already in the DOM,\n
\t\t\t// and the caller did not indicate that we should force a\n
\t\t\t// reload of the file, we are done. Resolve the deferrred so that\n
\t\t\t// users can bind to .done on the promise\n
\t\t\tif ( content.length && !settings.reload ) {\n
\t\t\t\tthis._enhance( content, settings.role );\n
\t\t\t\tdeferred.resolve( absUrl, settings, content );\n
\n
\t\t\t\t//if we are reloading the content make sure we update\n
\t\t\t\t// the base if its not a prefetch\n
\t\t\t\tif ( !settings.prefetch ) {\n
\t\t\t\t\tthis._getBase().set(url);\n
\t\t\t\t}\n
\n
\t\t\t\treturn deferred.promise();\n
\t\t\t}\n
\n
\t\t\ttriggerData = {\n
\t\t\t\turl: url,\n
\t\t\t\tabsUrl: absUrl,\n
\t\t\t\ttoPage: url,\n
\t\t\t\tprevPage: options ? options.fromPage : undefined,\n
\t\t\t\tdataUrl: dataUrl,\n
\t\t\t\tdeferred: deferred,\n
\t\t\t\toptions: settings\n
\t\t\t};\n
\n
\t\t\t// Let listeners know we\'re about to load content.\n
\t\t\tpblEvent = this._triggerWithDeprecated( "beforeload", triggerData );\n
\n
\t\t\t// If the default behavior is prevented, stop here!\n
\t\t\tif ( pblEvent.deprecatedEvent.isDefaultPrevented() ||\n
\t\t\t\tpblEvent.event.isDefaultPrevented() ) {\n
\t\t\t\treturn deferred.promise();\n
\t\t\t}\n
\n
\t\t\tif ( settings.showLoadMsg ) {\n
\t\t\t\tthis._showLoading( settings.loadMsgDelay );\n
\t\t\t}\n
\n
\t\t\t// Reset base to the default document base.\n
\t\t\t// only reset if we are not prefetching\n
\t\t\tif ( settings.prefetch === undefined ) {\n
\t\t\t\tthis._getBase().reset();\n
\t\t\t}\n
\n
\t\t\tif ( !( $.mobile.allowCrossDomainPages ||\n
\t\t\t\t$.mobile.path.isSameDomain($.mobile.path.documentUrl, absUrl ) ) ) {\n
\t\t\t\tdeferred.reject( absUrl, settings );\n
\t\t\t\treturn deferred.promise();\n
\t\t\t}\n
\n
\t\t\t// Load the new content.\n
\t\t\t$.ajax({\n
\t\t\t\turl: fileUrl,\n
\t\t\t\ttype: settings.type,\n
\t\t\t\tdata: settings.data,\n
\t\t\t\tcontentType: settings.contentType,\n
\t\t\t\tdataType: "html",\n
\t\t\t\tsuccess: this._loadSuccess( absUrl, triggerData, settings, deferred ),\n
\t\t\t\terror: this._loadError( absUrl, triggerData, settings, deferred )\n
\t\t\t});\n
\n
\t\t\treturn deferred.promise();\n
\t\t},\n
\n
\t\t_loadError: function( absUrl, triggerData, settings, deferred ) {\n
\t\t\treturn $.proxy(function( xhr, textStatus, errorThrown ) {\n
\t\t\t\t//set base back to current path\n
\t\t\t\tthis._getBase().set( $.mobile.path.get() );\n
\n
\t\t\t\t// Add error info to our triggerData.\n
\t\t\t\ttriggerData.xhr = xhr;\n
\t\t\t\ttriggerData.textStatus = textStatus;\n
\t\t\t\ttriggerData.errorThrown = errorThrown;\n
\n
\t\t\t\t// Let listeners know the page load failed.\n
\t\t\t\tvar plfEvent = this._triggerWithDeprecated( "loadfailed", triggerData );\n
\n
\t\t\t\t// If the default behavior is prevented, stop here!\n
\t\t\t\t// Note that it is the responsibility of the listener/handler\n
\t\t\t\t// that called preventDefault(), to resolve/reject the\n
\t\t\t\t// deferred object within the triggerData.\n
\t\t\t\tif ( plfEvent.deprecatedEvent.isDefaultPrevented() ||\n
\t\t\t\t\tplfEvent.event.isDefaultPrevented() ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\t// Remove loading message.\n
\t\t\t\tif ( settings.showLoadMsg ) {\n
\t\t\t\t\tthis._showError();\n
\t\t\t\t}\n
\n
\t\t\t\tdeferred.reject( absUrl, settings );\n
\t\t\t}, this);\n
\t\t},\n
\n
\t\t_getTransitionHandler: function( transition ) {\n
\t\t\ttransition = $.mobile._maybeDegradeTransition( transition );\n
\n
\t\t\t//find the transition handler for the specified transition. If there\n
\t\t\t//isn\'t one in our transitionHandlers dictionary, use the default one.\n
\t\t\t//call the handler immediately to kick-off the transition.\n
\t\t\treturn $.mobile.transitionHandlers[ transition ] || $.mobile.defaultTransitionHandler;\n
\t\t},\n
\n
\t\t// TODO move into transition handlers?\n
\t\t_triggerCssTransitionEvents: function( to, from, prefix ) {\n
\t\t\tvar samePage = false;\n
\n
\t\t\tprefix = prefix || "";\n
\n
\t\t\t// TODO decide if these events should in fact be triggered on the container\n
\t\t\tif ( from ) {\n
\n
\t\t\t\t//Check if this is a same page transition and tell the handler in page\n
\t\t\t\tif( to[0] === from[0] ){\n
\t\t\t\t\tsamePage = true;\n
\t\t\t\t}\n
\n
\t\t\t\t//trigger before show/hide events\n
\t\t\t\t// TODO deprecate nextPage in favor of next\n
\t\t\t\tthis._triggerWithDeprecated( prefix + "hide", {\n
\n
\t\t\t\t\t// Deprecated in 1.4 remove in 1.5\n
\t\t\t\t\tnextPage: to,\n
\t\t\t\t\ttoPage: to,\n
\t\t\t\t\tprevPage: from,\n
\t\t\t\t\tsamePage: samePage\n
\t\t\t\t}, from );\n
\t\t\t}\n
\n
\t\t\t// TODO deprecate prevPage in favor of previous\n
\t\t\tthis._triggerWithDeprecated( prefix + "show", {\n
\t\t\t\tprevPage: from || $( "" ),\n
\t\t\t\ttoPage: to\n
\t\t\t}, to );\n
\t\t},\n
\n
\t\t// TODO make private once change has been defined in the widget\n
\t\t_cssTransition: function( to, from, options ) {\n
\t\t\tvar transition = options.transition,\n
\t\t\t\treverse = options.reverse,\n
\t\t\t\tdeferred = options.deferred,\n
\t\t\t\tTransitionHandler,\n
\t\t\t\tpromise;\n
\n
\t\t\tthis._triggerCssTransitionEvents( to, from, "before" );\n
\n
\t\t\t// TODO put this in a binding to events *outside* the widget\n
\t\t\tthis._hideLoading();\n
\n
\t\t\tTransitionHandler = this._getTransitionHandler( transition );\n
\n
\t\t\tpromise = ( new TransitionHandler( transition, reverse, to, from ) ).transition();\n
\n
\t\t\tpromise.done( $.proxy( function() {\n
\t\t\t\tthis._triggerCssTransitionEvents( to, from );\n
\t\t\t}, this ));\n
\n
\t\t\t// TODO temporary accomodation of argument deferred\n
\t\t\tpromise.done(function() {\n
\t\t\t\tdeferred.resolve.apply( deferred, arguments );\n
\t\t\t});\n
\t\t},\n
\n
\t\t_releaseTransitionLock: function() {\n
\t\t\t//release transition lock so navigation is free again\n
\t\t\tisPageTransitioning = false;\n
\t\t\tif ( pageTransitionQueue.length > 0 ) {\n
\t\t\t\t$.mobile.changePage.apply( null, pageTransitionQueue.pop() );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_removeActiveLinkClass: function( force ) {\n
\t\t\t//clear out the active button state\n
\t\t\t$.mobile.removeActiveLinkClass( force );\n
\t\t},\n
\n
\t\t_loadUrl: function( to, triggerData, settings ) {\n
\t\t\t// preserve the original target as the dataUrl value will be\n
\t\t\t// simplified eg, removing ui-state, and removing query params\n
\t\t\t// from the hash this is so that users who want to use query\n
\t\t\t// params have access to them in the event bindings for the page\n
\t\t\t// life cycle See issue #5085\n
\t\t\tsettings.target = to;\n
\t\t\tsettings.deferred = $.Deferred();\n
\n
\t\t\tthis.load( to, settings );\n
\n
\t\t\tsettings.deferred.done($.proxy(function( url, options, content ) {\n
\t\t\t\tisPageTransitioning = false;\n
\n
\t\t\t\t// store the original absolute url so that it can be provided\n
\t\t\t\t// to events in the triggerData of the subsequent changePage call\n
\t\t\t\toptions.absUrl = triggerData.absUrl;\n
\n
\t\t\t\tthis.transition( content, triggerData, options );\n
\t\t\t}, this));\n
\n
\t\t\tsettings.deferred.fail($.proxy(function(/* url, options */) {\n
\t\t\t\tthis._removeActiveLinkClass( true );\n
\t\t\t\tthis._releaseTransitionLock();\n
\t\t\t\tthis._triggerWithDeprecated( "changefailed", triggerData );\n
\t\t\t}, this));\n
\t\t},\n
\n
\t\t_triggerPageBeforeChange: function( to, triggerData, settings ) {\n
\t\t\tvar returnEvents;\n
\n
\t\t\ttriggerData.prevPage = this.activePage;\n
\t\t\t$.extend( triggerData, {\n
\t\t\t\ttoPage: to,\n
\t\t\t\toptions: settings\n
\t\t\t});\n
\n
\t\t\t// NOTE: preserve the original target as the dataUrl value will be\n
\t\t\t// simplified eg, removing ui-state, and removing query params from\n
\t\t\t// the hash this is so that users who want to use query params have\n
\t\t\t// access to them in the event bindings for the page life cycle\n
\t\t\t// See issue #5085\n
\t\t\tif ( $.type(to) === "string" ) {\n
\t\t\t\t// if the toPage is a string simply convert it\n
\t\t\t\ttriggerData.absUrl = $.mobile.path.makeUrlAbsolute( to, this._findBaseWithDefault() );\n
\t\t\t} else {\n
\t\t\t\t// if the toPage is a jQuery object grab the absolute url stored\n
\t\t\t\t// in the loadPage callback where it exists\n
\t\t\t\ttriggerData.absUrl = settings.absUrl;\n
\t\t\t}\n
\n
\t\t\t// Let listeners know we\'re about to change the current page.\n
\t\t\treturnEvents = this._triggerWithDeprecated( "beforechange", triggerData );\n
\n
\t\t\t// If the default behavior is prevented, stop here!\n
\t\t\tif ( returnEvents.event.isDefaultPrevented() ||\n
\t\t\t\treturnEvents.deprecatedEvent.isDefaultPrevented() ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\treturn true;\n
\t\t},\n
\n
\t\tchange: function( to, options ) {\n
\t\t\t// If we are in the midst of a transition, queue the current request.\n
\t\t\t// We\'ll call changePage() once we\'re done with the current transition\n
\t\t\t// to service the request.\n
\t\t\tif ( isPageTransitioning ) {\n
\t\t\t\tpageTransitionQueue.unshift( arguments );\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tvar settings = $.extend( {}, $.mobile.changePage.defaults, options ),\n
\t\t\t\ttriggerData = {};\n
\n
\t\t\t// Make sure we have a fromPage.\n
\t\t\tsettings.fromPage = settings.fromPage || this.activePage;\n
\n
\t\t\t// if the page beforechange default is prevented return early\n
\t\t\tif ( !this._triggerPageBeforeChange(to, triggerData, settings) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// We allow "pagebeforechange" observers to modify the to in\n
\t\t\t// the trigger data to allow for redirects. Make sure our to is\n
\t\t\t// updated. We also need to re-evaluate whether it is a string,\n
\t\t\t// because an object can also be replaced by a string\n
\t\t\tto = triggerData.toPage;\n
\n
\t\t\t// If the caller passed us a url, call loadPage()\n
\t\t\t// to make sure it is loaded into the DOM. We\'ll listen\n
\t\t\t// to the promise object it returns so we know when\n
\t\t\t// it is done loading or if an error ocurred.\n
\t\t\tif ( $.type(to) === "string" ) {\n
\t\t\t\t// Set the isPageTransitioning flag to prevent any requests from\n
\t\t\t\t// entering this method while we are in the midst of loading a page\n
\t\t\t\t// or transitioning.\n
\t\t\t\tisPageTransitioning = true;\n
\n
\t\t\t\tthis._loadUrl( to, triggerData, settings );\n
\t\t\t} else {\n
\t\t\t\tthis.transition( to, triggerData, settings );\n
\t\t\t}\n
\t\t},\n
\n
\t\ttransition: function( toPage, triggerData, settings ) {\n
\t\t\tvar fromPage, url, pageUrl, fileUrl,\n
\t\t\t\tactive, activeIsInitialPage,\n
\t\t\t\thistoryDir, pageTitle, isDialog,\n
\t\t\t\talreadyThere, newPageTitle,\n
\t\t\t\tparams,\tcssTransitionDeferred,\n
\t\t\t\tbeforeTransition;\n
\n
\t\t\t// If we are in the midst of a transition, queue the current request.\n
\t\t\t// We\'ll call changePage() once we\'re done with the current transition\n
\t\t\t// to service the request.\n
\t\t\tif ( isPageTransitioning ) {\n
\t\t\t\t// make sure to only queue the to and settings values so the arguments\n
\t\t\t\t// work with a call to the change method\n
\t\t\t\tpageTransitionQueue.unshift( [toPage, settings] );\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// DEPRECATED - this call only, in favor of the before transition\n
\t\t\t// if the page beforechange default is prevented return early\n
\t\t\tif ( !this._triggerPageBeforeChange(toPage, triggerData, settings) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\ttriggerData.prevPage = settings.fromPage;\n
\t\t\t// if the (content|page)beforetransition default is prevented return early\n
\t\t\t// Note, we have to check for both the deprecated and new events\n
\t\t\tbeforeTransition = this._triggerWithDeprecated( "beforetransition", triggerData );\n
\t\t\tif (beforeTransition.deprecatedEvent.isDefaultPrevented() ||\n
\t\t\t\tbeforeTransition.event.isDefaultPrevented() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// Set the isPageTransitioning flag to prevent any requests from\n
\t\t\t// entering this method while we are in the midst of loading a page\n
\t\t\t// or transitioning.\n
\t\t\tisPageTransitioning = true;\n
\n
\t\t\t// If we are going to the first-page of the application, we need to make\n
\t\t\t// sure settings.dataUrl is set to the application document url. This allows\n
\t\t\t// us to avoid generating a document url with an id hash in the case where the\n
\t\t\t// first-page of the document has an id attribute specified.\n
\t\t\tif ( toPage[ 0 ] === $.mobile.firstPage[ 0 ] && !settings.dataUrl ) {\n
\t\t\t\tsettings.dataUrl = $.mobile.path.documentUrl.hrefNoHash;\n
\t\t\t}\n
\n
\t\t\t// The caller passed us a real page DOM element. Update our\n
\t\t\t// internal state and then trigger a transition to the page.\n
\t\t\tfromPage = settings.fromPage;\n
\t\t\turl = ( settings.dataUrl && $.mobile.path.convertUrlToDataUrl(settings.dataUrl) ) ||\n
\t\t\t\ttoPage.jqmData( "url" );\n
\n
\t\t\t// The pageUrl var is usually the same as url, except when url is obscured\n
\t\t\t// as a dialog url. pageUrl always contains the file path\n
\t\t\tpageUrl = url;\n
\t\t\tfileUrl = $.mobile.path.getFilePath( url );\n
\t\t\tactive = $.mobile.navigate.history.getActive();\n
\t\t\tactiveIsInitialPage = $.mobile.navigate.history.activeIndex === 0;\n
\t\t\thistoryDir = 0;\n
\t\t\tpageTitle = document.title;\n
\t\t\tisDialog = ( settings.role === "dialog" ||\n
\t\t\t\ttoPage.jqmData( "role" ) === "dialog" ) &&\n
\t\t\t\ttoPage.jqmData( "dialog" ) !== true;\n
\n
\t\t\t// By default, we prevent changePage requests when the fromPage and toPage\n
\t\t\t// are the same element, but folks that generate content\n
\t\t\t// manually/dynamically and reuse pages want to be able to transition to\n
\t\t\t// the same page. To allow this, they will need to change the default\n
\t\t\t// value of allowSamePageTransition to true, *OR*, pass it in as an\n
\t\t\t// option when they manually call changePage(). It should be noted that\n
\t\t\t// our default transition animations assume that the formPage and toPage\n
\t\t\t// are different elements, so they may behave unexpectedly. It is up to\n
\t\t\t// the developer that turns on the allowSamePageTransitiona option to\n
\t\t\t// either turn off transition animations, or make sure that an appropriate\n
\t\t\t// animation transition is used.\n
\t\t\tif ( fromPage && fromPage[0] === toPage[0] &&\n
\t\t\t\t!settings.allowSamePageTransition ) {\n
\n
\t\t\t\tisPageTransitioning = false;\n
\t\t\t\tthis._triggerWithDeprecated( "transition", triggerData );\n
\t\t\t\tthis._triggerWithDeprecated( "change", triggerData );\n
\n
\t\t\t\t// Even if there is no page change to be done, we should keep the\n
\t\t\t\t// urlHistory in sync with the hash changes\n
\t\t\t\tif ( settings.fromHashChange ) {\n
\t\t\t\t\t$.mobile.navigate.history.direct({ url: url });\n
\t\t\t\t}\n
\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// We need to make sure the page we are given has already been enhanced.\n
\t\t\ttoPage.page({ role: settings.role });\n
\n
\t\t\t// If the changePage request was sent from a hashChange event, check to\n
\t\t\t// see if the page is already within the urlHistory stack. If so, we\'ll\n
\t\t\t// assume the user hit the forward/back button and will try to match the\n
\t\t\t// transition accordingly.\n
\t\t\tif ( settings.fromHashChange ) {\n
\t\t\t\thistoryDir = settings.direction === "back" ? -1 : 1;\n
\t\t\t}\n
\n
\t\t\t// Kill the keyboard.\n
\t\t\t// XXX_jblas: We need to stop crawling the entire document to kill focus.\n
\t\t\t//            Instead, we should be tracking focus with a delegate()\n
\t\t\t//            handler so we already have the element in hand at this\n
\t\t\t//            point.\n
\t\t\t// Wrap this in a try/catch block since IE9 throw "Unspecified error" if\n
\t\t\t// document.activeElement is undefined when we are in an IFrame.\n
\t\t\ttry {\n
\t\t\t\tif ( document.activeElement &&\n
\t\t\t\t\tdocument.activeElement.nodeName.toLowerCase() !== "body" ) {\n
\n
\t\t\t\t\t$( document.activeElement ).blur();\n
\t\t\t\t} else {\n
\t\t\t\t\t$( "input:focus, textarea:focus, select:focus" ).blur();\n
\t\t\t\t}\n
\t\t\t} catch( e ) {}\n
\n
\t\t\t// Record whether we are at a place in history where a dialog used to be -\n
\t\t\t// if so, do not add a new history entry and do not change the hash either\n
\t\t\talreadyThere = false;\n
\n
\t\t\t// If we\'re displaying the page as a dialog, we don\'t want the url\n
\t\t\t// for the dialog content to be used in the hash. Instead, we want\n
\t\t\t// to append the dialogHashKey to the url of the current page.\n
\t\t\tif ( isDialog && active ) {\n
\t\t\t\t// on the initial page load active.url is undefined and in that case\n
\t\t\t\t// should be an empty string. Moving the undefined -> empty string back\n
\t\t\t\t// into urlHistory.addNew seemed imprudent given undefined better\n
\t\t\t\t// represents the url state\n
\n
\t\t\t\t// If we are at a place in history that once belonged to a dialog, reuse\n
\t\t\t\t// this state without adding to urlHistory and without modifying the\n
\t\t\t\t// hash. However, if a dialog is already displayed at this point, and\n
\t\t\t\t// we\'re about to display another dialog, then we must add another hash\n
\t\t\t\t// and history entry on top so that one may navigate back to the\n
\t\t\t\t// original dialog\n
\t\t\t\tif ( active.url &&\n
\t\t\t\t\tactive.url.indexOf( $.mobile.dialogHashKey ) > -1 &&\n
\t\t\t\t\tthis.activePage &&\n
\t\t\t\t\t!this.activePage.hasClass( "ui-dialog" ) &&\n
\t\t\t\t\t$.mobile.navigate.history.activeIndex > 0 ) {\n
\n
\t\t\t\t\tsettings.changeHash = false;\n
\t\t\t\t\talreadyThere = true;\n
\t\t\t\t}\n
\n
\t\t\t\t// Normally, we tack on a dialog hash key, but if this is the location\n
\t\t\t\t// of a stale dialog, we reuse the URL from the entry\n
\t\t\t\turl = ( active.url || "" );\n
\n
\t\t\t\t// account for absolute urls instead of just relative urls use as hashes\n
\t\t\t\tif ( !alreadyThere && url.indexOf("#") > -1 ) {\n
\t\t\t\t\turl += $.mobile.dialogHashKey;\n
\t\t\t\t} else {\n
\t\t\t\t\turl += "#" + $.mobile.dialogHashKey;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// if title element wasn\'t found, try the page div data attr too\n
\t\t\t// If this is a deep-link or a reload ( active === undefined ) then just\n
\t\t\t// use pageTitle\n
\t\t\tnewPageTitle = ( !active ) ? pageTitle : toPage.jqmData( "title" ) ||\n
\t\t\t\ttoPage.children( ":jqmData(role=\'header\')" ).find( ".ui-title" ).text();\n
\t\t\tif ( !!newPageTitle && pageTitle === document.title ) {\n
\t\t\t\tpageTitle = newPageTitle;\n
\t\t\t}\n
\t\t\tif ( !toPage.jqmData( "title" ) ) {\n
\t\t\t\ttoPage.jqmData( "title", pageTitle );\n
\t\t\t}\n
\n
\t\t\t// Make sure we have a transition defined.\n
\t\t\tsettings.transition = settings.transition ||\n
\t\t\t\t( ( historyDir && !activeIsInitialPage ) ? active.transition : undefined ) ||\n
\t\t\t\t( isDialog ? $.mobile.defaultDialogTransition : $.mobile.defaultPageTransition );\n
\n
\t\t\t//add page to history stack if it\'s not back or forward\n
\t\t\tif ( !historyDir && alreadyThere ) {\n
\t\t\t\t$.mobile.navigate.history.getActive().pageUrl = pageUrl;\n
\t\t\t}\n
\n
\t\t\t// Set the location hash.\n
\t\t\tif ( url && !settings.fromHashChange ) {\n
\n
\t\t\t\t// rebuilding the hash here since we loose it earlier on\n
\t\t\t\t// TODO preserve the originally passed in path\n
\t\t\t\tif ( !$.mobile.path.isPath( url ) && url.indexOf( "#" ) < 0 ) {\n
\t\t\t\t\turl = "#" + url;\n
\t\t\t\t}\n
\n
\t\t\t\t// TODO the property names here are just silly\n
\t\t\t\tparams = {\n
\t\t\t\t\tallowSamePageTransition: settings.allowSamePageTransition,\n
\t\t\t\t\ttransition: settings.transition,\n
\t\t\t\t\ttitle: pageTitle,\n
\t\t\t\t\tpageUrl: pageUrl,\n
\t\t\t\t\trole: settings.role\n
\t\t\t\t};\n
\n
\t\t\t\tif ( settings.changeHash !== false && $.mobile.hashListeningEnabled ) {\n
\t\t\t\t\t$.mobile.navigate( url, params, true);\n
\t\t\t\t} else if ( toPage[ 0 ] !== $.mobile.firstPage[ 0 ] ) {\n
\t\t\t\t\t$.mobile.navigate.history.add( url, params );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t//set page title\n
\t\t\tdocument.title = pageTitle;\n
\n
\t\t\t//set "toPage" as activePage deprecated in 1.4 remove in 1.5\n
\t\t\t$.mobile.activePage = toPage;\n
\n
\t\t\t//new way to handle activePage\n
\t\t\tthis.activePage = toPage;\n
\n
\t\t\t// If we\'re navigating back in the URL history, set reverse accordingly.\n
\t\t\tsettings.reverse = settings.reverse || historyDir < 0;\n
\n
\t\t\tcssTransitionDeferred = $.Deferred();\n
\n
\t\t\tthis._cssTransition(toPage, fromPage, {\n
\t\t\t\ttransition: settings.transition,\n
\t\t\t\treverse: settings.reverse,\n
\t\t\t\tdeferred: cssTransitionDeferred\n
\t\t\t});\n
\n
\t\t\tcssTransitionDeferred.done($.proxy(function( name, reverse, $to, $from, alreadyFocused ) {\n
\t\t\t\t$.mobile.removeActiveLinkClass();\n
\n
\t\t\t\t//if there\'s a duplicateCachedPage, remove it from the DOM now that it\'s hidden\n
\t\t\t\tif ( settings.duplicateCachedPage ) {\n
\t\t\t\t\tsettings.duplicateCachedPage.remove();\n
\t\t\t\t}\n
\n
\t\t\t\t// despite visibility: hidden addresses issue #2965\n
\t\t\t\t// https://github.com/jquery/jquery-mobile/issues/2965\n
\t\t\t\tif ( !alreadyFocused ) {\n
\t\t\t\t\t$.mobile.focusPage( toPage );\n
\t\t\t\t}\n
\n
\t\t\t\tthis._releaseTransitionLock();\n
\t\t\t\tthis._triggerWithDeprecated( "transition", triggerData );\n
\t\t\t\tthis._triggerWithDeprecated( "change", triggerData );\n
\t\t\t}, this));\n
\t\t},\n
\n
\t\t// determine the current base url\n
\t\t_findBaseWithDefault: function() {\n
\t\t\tvar closestBase = ( this.activePage &&\n
\t\t\t$.mobile.getClosestBaseUrl( this.activePage ) );\n
\t\treturn closestBase || $.mobile.path.documentBase.hrefNoHash;\n
\t\t}\n
\t});\n
\n
\t// The following handlers should be bound after mobileinit has been triggered\n
\t// the following deferred is resolved in the init file\n
\t$.mobile.navreadyDeferred = $.Deferred();\n
\n
\t//these variables make all page containers use the same queue and only navigate one at a time\n
\t// queue to hold simultanious page transitions\n
\tvar pageTransitionQueue = [],\n
\n
\t\t// indicates whether or not page is in process of transitioning\n
\t\tisPageTransitioning = false;\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
\t\t// resolved on domready\n
\tvar domreadyDeferred = $.Deferred(),\n
\n
\t\t// resolved and nulled on window.load()\n
\t\tloadDeferred = $.Deferred(),\n
\n
\t\t// function that resolves the above deferred\n
\t\tpageIsFullyLoaded = function() {\n
\n
\t\t\t// Resolve and null the deferred\n
\t\t\tloadDeferred.resolve();\n
\t\t\tloadDeferred = null;\n
\t\t},\n
\n
\t\tdocumentUrl = $.mobile.path.documentUrl,\n
\n
\t\t// used to track last vclicked element to make sure its value is added to form data\n
\t\t$lastVClicked = null;\n
\n
\t/* Event Bindings - hashchange, submit, and click */\n
\tfunction findClosestLink( ele )\t{\n
\t\twhile ( ele ) {\n
\t\t\t// Look for the closest element with a nodeName of "a".\n
\t\t\t// Note that we are checking if we have a valid nodeName\n
\t\t\t// before attempting to access it. This is because the\n
\t\t\t// node we get called with could have originated from within\n
\t\t\t// an embedded SVG document where some symbol instance elements\n
\t\t\t// don\'t have nodeName defined on them, or strings are of type\n
\t\t\t// SVGAnimatedString.\n
\t\t\tif ( ( typeof ele.nodeName === "string" ) && ele.nodeName.toLowerCase() === "a" ) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tele = ele.parentNode;\n
\t\t}\n
\t\treturn ele;\n
\t}\n
\n
\t$.mobile.loadPage = function( url, opts ) {\n
\t\tvar container;\n
\n
\t\topts = opts || {};\n
\t\tcontainer = ( opts.pageContainer || $.mobile.pageContainer );\n
\n
\t\t// create the deferred that will be supplied to loadPage callers\n
\t\t// and resolved by the content widget\'s load method\n
\t\topts.deferred = $.Deferred();\n
\n
\t\t// Preferring to allow exceptions for uninitialized opts.pageContainer\n
\t\t// widgets so we know if we need to force init here for users\n
\t\tcontainer.pagecontainer( "load", url, opts );\n
\n
\t\t// provide the deferred\n
\t\treturn opts.deferred.promise();\n
\t};\n
\n
\t//define vars for interal use\n
\n
\t/* internal utility functions */\n
\n
\t// NOTE Issue #4950 Android phonegap doesn\'t navigate back properly\n
\t//      when a full page refresh has taken place. It appears that hashchange\n
\t//      and replacestate history alterations work fine but we need to support\n
\t//      both forms of history traversal in our code that uses backward history\n
\t//      movement\n
\t$.mobile.back = function() {\n
\t\tvar nav = window.navigator;\n
\n
\t\t// if the setting is on and the navigator object is\n
\t\t// available use the phonegap navigation capability\n
\t\tif ( this.phonegapNavigationEnabled &&\n
\t\t\tnav &&\n
\t\t\tnav.app &&\n
\t\t\tnav.app.backHistory ) {\n
\t\t\tnav.app.backHistory();\n
\t\t} else {\n
\t\t\t$.mobile.pageContainer.pagecontainer( "back" );\n
\t\t}\n
\t};\n
\n
\t// Direct focus to the page title, or otherwise first focusable element\n
\t$.mobile.focusPage = function ( page ) {\n
\t\tvar autofocus = page.find( "[autofocus]" ),\n
\t\t\tpageTitle = page.find( ".ui-title:eq(0)" );\n
\n
\t\tif ( autofocus.length ) {\n
\t\t\tautofocus.focus();\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( pageTitle.length ) {\n
\t\t\tpageTitle.focus();\n
\t\t} else{\n
\t\t\tpage.focus();\n
\t\t}\n
\t};\n
\n
\t// No-op implementation of transition degradation\n
\t$.mobile._maybeDegradeTransition = $.mobile._maybeDegradeTransition || function( transition ) {\n
\t\treturn transition;\n
\t};\n
\n
\t// Exposed $.mobile methods\n
\n
\t$.mobile.changePage = function( to, options ) {\n
\t\t$.mobile.pageContainer.pagecontainer( "change", to, options );\n
\t};\n
\n
\t$.mobile.changePage.defaults = {\n
\t\ttransition: undefined,\n
\t\treverse: false,\n
\t\tchangeHash: true,\n
\t\tfromHashChange: false,\n
\t\trole: undefined, // By default we rely on the role defined by the @data-role attribute.\n
\t\tduplicateCachedPage: undefined,\n
\t\tpageContainer: undefined,\n
\t\tshowLoadMsg: true, //loading message shows by default when pages are being fetched during changePage\n
\t\tdataUrl: undefined,\n
\t\tfromPage: undefined,\n
\t\tallowSamePageTransition: false\n
\t};\n
\n
\t$.mobile._registerInternalEvents = function() {\n
\t\tvar getAjaxFormData = function( $form, calculateOnly ) {\n
\t\t\tvar url, ret = true, formData, vclickedName, method;\n
\t\t\tif ( !$.mobile.ajaxEnabled ||\n
\t\t\t\t\t// test that the form is, itself, ajax false\n
\t\t\t\t\t$form.is( ":jqmData(ajax=\'false\')" ) ||\n
\t\t\t\t\t// test that $.mobile.ignoreContentEnabled is set and\n
\t\t\t\t\t// the form or one of it\'s parents is ajax=false\n
\t\t\t\t\t!$form.jqmHijackable().length ||\n
\t\t\t\t\t$form.attr( "target" ) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\turl = ( $lastVClicked && $lastVClicked.attr( "formaction" ) ) ||\n
\t\t\t\t$form.attr( "action" );\n
\t\t\tmethod = ( $form.attr( "method" ) || "get" ).toLowerCase();\n
\n
\t\t\t// If no action is specified, browsers default to using the\n
\t\t\t// URL of the document containing the form. Since we dynamically\n
\t\t\t// pull in pages from external documents, the form should submit\n
\t\t\t// to the URL for the source document of the page containing\n
\t\t\t// the form.\n
\t\t\tif ( !url ) {\n
\t\t\t\t// Get the @data-url for the page containing the form.\n
\t\t\t\turl = $.mobile.getClosestBaseUrl( $form );\n
\n
\t\t\t\t// NOTE: If the method is "get", we need to strip off the query string\n
\t\t\t\t// because it will get replaced with the new form data. See issue #5710.\n
\t\t\t\tif ( method === "get" ) {\n
\t\t\t\t\turl = $.mobile.path.parseUrl( url ).hrefNoSearch;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( url === $.mobile.path.documentBase.hrefNoHash ) {\n
\t\t\t\t\t// The url we got back matches the document base,\n
\t\t\t\t\t// which means the page must be an internal/embedded page,\n
\t\t\t\t\t// so default to using the actual document url as a browser\n
\t\t\t\t\t// would.\n
\t\t\t\t\turl = documentUrl.hrefNoSearch;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\turl = $.mobile.path.makeUrlAbsolute(  url, $.mobile.getClosestBaseUrl( $form ) );\n
\n
\t\t\tif ( ( $.mobile.path.isExternal( url ) && !$.mobile.path.isPermittedCrossDomainRequest( documentUrl, url ) ) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\tif ( !calculateOnly ) {\n
\t\t\t\tformData = $form.serializeArray();\n
\n
\t\t\t\tif ( $lastVClicked && $lastVClicked[ 0 ].form === $form[ 0 ] ) {\n
\t\t\t\t\tvclickedName = $lastVClicked.attr( "name" );\n
\t\t\t\t\tif ( vclickedName ) {\n
\t\t\t\t\t\t// Make sure the last clicked element is included in the form\n
\t\t\t\t\t\t$.each( formData, function( key, value ) {\n
\t\t\t\t\t\t\tif ( value.name === vclickedName ) {\n
\t\t\t\t\t\t\t\t// Unset vclickedName - we\'ve found it in the serialized data already\n
\t\t\t\t\t\t\t\tvclickedName = "";\n
\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tif ( vclickedName ) {\n
\t\t\t\t\t\t\tformData.push( { name: vclickedName, value: $lastVClicked.attr( "value" ) } );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tret = {\n
\t\t\t\t\turl: url,\n
\t\t\t\t\toptions: {\n
\t\t\t\t\t\ttype:\t\tmethod,\n
\t\t\t\t\t\tdata:\t\t$.param( formData ),\n
\t\t\t\t\t\ttransition:\t$form.jqmData( "transition" ),\n
\t\t\t\t\t\treverse:\t$form.jqmData( "direction" ) === "reverse",\n
\t\t\t\t\t\treloadPage:\ttrue\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\treturn ret;\n
\t\t};\n
\n
\t\t//bind to form submit events, handle with Ajax\n
\t\t$.mobile.document.delegate( "form", "submit", function( event ) {\n
\t\t\tvar formData;\n
\n
\t\t\tif ( !event.isDefaultPrevented() ) {\n
\t\t\t\tformData = getAjaxFormData( $( this ) );\n
\t\t\t\tif ( formData ) {\n
\t\t\t\t\t$.mobile.changePage( formData.url, formData.options );\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\t//add active state on vclick\n
\t\t$.mobile.document.bind( "vclick", function( event ) {\n
\t\t\tvar $btn, btnEls, target = event.target, needClosest = false;\n
\t\t\t// if this isn\'t a left click we don\'t care. Its important to note\n
\t\t\t// that when the virtual event is generated it will create the which attr\n
\t\t\tif ( event.which > 1 || !$.mobile.linkBindingEnabled ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// Record that this element was clicked, in case we need it for correct\n
\t\t\t// form submission during the "submit" handler above\n
\t\t\t$lastVClicked = $( target );\n
\n
\t\t\t// Try to find a target element to which the active class will be applied\n
\t\t\tif ( $.data( target, "mobile-button" ) ) {\n
\t\t\t\t// If the form will not be submitted via AJAX, do not add active class\n
\t\t\t\tif ( !getAjaxFormData( $( target ).closest( "form" ), true ) ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t// We will apply the active state to this button widget - the parent\n
\t\t\t\t// of the input that was clicked will have the associated data\n
\t\t\t\tif ( target.parentNode ) {\n
\t\t\t\t\ttarget = target.parentNode;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\ttarget = findClosestLink( target );\n
\t\t\t\tif ( !( target && $.mobile.path.parseUrl( target.getAttribute( "href" ) || "#" ).hash !== "#" ) ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\t// TODO teach $.mobile.hijackable to operate on raw dom elements so the\n
\t\t\t\t// link wrapping can be avoided\n
\t\t\t\tif ( !$( target ).jqmHijackable().length ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Avoid calling .closest by using the data set during .buttonMarkup()\n
\t\t\t// List items have the button data in the parent of the element clicked\n
\t\t\tif ( !!~target.className.indexOf( "ui-link-inherit" ) ) {\n
\t\t\t\tif ( target.parentNode ) {\n
\t\t\t\t\tbtnEls = $.data( target.parentNode, "buttonElements" );\n
\t\t\t\t}\n
\t\t\t// Otherwise, look for the data on the target itself\n
\t\t\t} else {\n
\t\t\t\tbtnEls = $.data( target, "buttonElements" );\n
\t\t\t}\n
\t\t\t// If found, grab the button\'s outer element\n
\t\t\tif ( btnEls ) {\n
\t\t\t\ttarget = btnEls.outer;\n
\t\t\t} else {\n
\t\t\t\tneedClosest = true;\n
\t\t\t}\n
\n
\t\t\t$btn = $( target );\n
\t\t\t// If the outer element wasn\'t found by the our heuristics, use .closest()\n
\t\t\tif ( needClosest ) {\n
\t\t\t\t$btn = $btn.closest( ".ui-btn" );\n
\t\t\t}\n
\n
\t\t\tif ( $btn.length > 0 &&\n
\t\t\t\t!( $btn.hasClass( "ui-state-disabled" ||\n
\n
\t\t\t\t\t// DEPRECATED as of 1.4.0 - remove after 1.4.0 release\n
\t\t\t\t\t// only ui-state-disabled should be present thereafter\n
\t\t\t\t\t$btn.hasClass( "ui-disabled" ) ) ) ) {\n
\t\t\t\t$.mobile.removeActiveLinkClass( true );\n
\t\t\t\t$.mobile.activeClickedLink = $btn;\n
\t\t\t\t$.mobile.activeClickedLink.addClass( $.mobile.activeBtnClass );\n
\t\t\t}\n
\t\t});\n
\n
\t\t// click routing - direct to HTTP or Ajax, accordingly\n
\t\t$.mobile.document.bind( "click", function( event ) {\n
\t\t\tif ( !$.mobile.linkBindingEnabled || event.isDefaultPrevented() ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tvar link = findClosestLink( event.target ),\n
\t\t\t\t$link = $( link ),\n
\n
\t\t\t\t//remove active link class if external (then it won\'t be there if you come back)\n
\t\t\t\thttpCleanup = function() {\n
\t\t\t\t\twindow.setTimeout(function() { $.mobile.removeActiveLinkClass( true ); }, 200 );\n
\t\t\t\t},\n
\t\t\t\tbaseUrl, href,\n
\t\t\t\tuseDefaultUrlHandling, isExternal,\n
\t\t\t\ttransition, reverse, role;\n
\n
\t\t\t// If a button was clicked, clean up the active class added by vclick above\n
\t\t\tif ( $.mobile.activeClickedLink &&\n
\t\t\t\t$.mobile.activeClickedLink[ 0 ] === event.target.parentNode ) {\n
\t\t\t\thttpCleanup();\n
\t\t\t}\n
\n
\t\t\t// If there is no link associated with the click or its not a left\n
\t\t\t// click we want to ignore the click\n
\t\t\t// TODO teach $.mobile.hijackable to operate on raw dom elements so the link wrapping\n
\t\t\t// can be avoided\n
\t\t\tif ( !link || event.which > 1 || !$link.jqmHijackable().length ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t//if there\'s a data-rel=back attr, go back in history\n
\t\t\tif ( $link.is( ":jqmData(rel=\'back\')" ) ) {\n
\t\t\t\t$.mobile.back();\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\tbaseUrl = $.mobile.getClosestBaseUrl( $link );\n
\n
\t\t\t//get href, if defined, otherwise default to empty hash\n
\t\t\thref = $.mobile.path.makeUrlAbsolute( $link.attr( "href" ) || "#", baseUrl );\n
\n
\t\t\t//if ajax is disabled, exit early\n
\t\t\tif ( !$.mobile.ajaxEnabled && !$.mobile.path.isEmbeddedPage( href ) ) {\n
\t\t\t\thttpCleanup();\n
\t\t\t\t//use default click handling\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// XXX_jblas: Ideally links to application pages should be specified as\n
\t\t\t//            an url to the application document with a hash that is either\n
\t\t\t//            the site relative path or id to the page. But some of the\n
\t\t\t//            internal code that dynamically generates sub-pages for nested\n
\t\t\t//            lists and select dialogs, just write a hash in the link they\n
\t\t\t//            create. This means the actual URL path is based on whatever\n
\t\t\t//            the current value of the base tag is at the time this code\n
\t\t\t//            is called.\n
\t\t\tif ( href.search( "#" ) !== -1 &&\n
\t\t\t\t!( $.mobile.path.isExternal( href ) && $.mobile.path.isAbsoluteUrl( href ) ) ) {\n
\n
\t\t\t\thref = href.replace( /[^#]*#/, "" );\n
\t\t\t\tif ( !href ) {\n
\t\t\t\t\t//link was an empty hash meant purely\n
\t\t\t\t\t//for interaction, so we ignore it.\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\treturn;\n
\t\t\t\t} else if ( $.mobile.path.isPath( href ) ) {\n
\t\t\t\t\t//we have apath so make it the href we want to load.\n
\t\t\t\t\thref = $.mobile.path.makeUrlAbsolute( href, baseUrl );\n
\t\t\t\t} else {\n
\t\t\t\t\t//we have a simple id so use the documentUrl as its base.\n
\t\t\t\t\thref = $.mobile.path.makeUrlAbsolute( "#" + href, documentUrl.hrefNoHash );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Should we handle this link, or let the browser deal with it?\n
\t\t\tuseDefaultUrlHandling = $link.is( "[rel=\'external\']" ) || $link.is( ":jqmData(ajax=\'false\')" ) || $link.is( "[target]" );\n
\n
\t\t\t// Some embedded browsers, like the web view in Phone Gap, allow cross-domain XHR\n
\t\t\t// requests if the document doing the request was loaded via the file:// protocol.\n
\t\t\t// This is usually to allow the application to "phone home" and fetch app specific\n
\t\t\t// data. We normally let the browser handle external/cross-domain urls, but if the\n
\t\t\t// allowCrossDomainPages option is true, we will allow cross-domain http/https\n
\t\t\t// requests to go through our page loading logic.\n
\n
\t\t\t//check for protocol or rel and its not an embedded page\n
\t\t\t//TODO overlap in logic from isExternal, rel=external check should be\n
\t\t\t//     moved into more comprehensive isExternalLink\n
\t\t\tisExternal = useDefaultUrlHandling || ( $.mobile.path.isExternal( href ) && !$.mobile.path.isPermittedCrossDomainRequest( documentUrl, href ) );\n
\n
\t\t\tif ( isExternal ) {\n
\t\t\t\thttpCleanup();\n
\t\t\t\t//use default click handling\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t//use ajax\n
\t\t\ttransition = $link.jqmData( "transition" );\n
\t\t\treverse = $link.jqmData( "direction" ) === "reverse" ||\n
\t\t\t\t\t\t// deprecated - remove by 1.0\n
\t\t\t\t\t\t$link.jqmData( "back" );\n
\n
\t\t\t//this may need to be more specific as we use data-rel more\n
\t\t\trole = $link.attr( "data-" + $.mobile.ns + "rel" ) || undefined;\n
\n
\t\t\t$.mobile.changePage( href, { transition: transition, reverse: reverse, role: role, link: $link } );\n
\t\t\tevent.preventDefault();\n
\t\t});\n
\n
\t\t//prefetch pages when anchors with data-prefetch are encountered\n
\t\t$.mobile.document.delegate( ".ui-page", "pageshow.prefetch", function() {\n
\t\t\tvar urls = [];\n
\t\t\t$( this ).find( "a:jqmData(prefetch)" ).each(function() {\n
\t\t\t\tvar $link = $( this ),\n
\t\t\t\t\turl = $link.attr( "href" );\n
\n
\t\t\t\tif ( url && $.inArray( url, urls ) === -1 ) {\n
\t\t\t\t\turls.push( url );\n
\n
\t\t\t\t\t$.mobile.loadPage( url, { role: $link.attr( "data-" + $.mobile.ns + "rel" ),prefetch: true } );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t});\n
\n
\t\t// TODO ensure that the navigate binding in the content widget happens at the right time\n
\t\t$.mobile.pageContainer.pagecontainer();\n
\n
\t\t//set page min-heights to be device specific\n
\t\t$.mobile.document.bind( "pageshow", function() {\n
\n
\t\t\t// We need to wait for window.load to make sure that styles have already been rendered,\n
\t\t\t// otherwise heights of external toolbars will have the wrong value\n
\t\t\tif ( loadDeferred ) {\n
\t\t\t\tloadDeferred.done( $.mobile.resetActivePageHeight );\n
\t\t\t} else {\n
\t\t\t\t$.mobile.resetActivePageHeight();\n
\t\t\t}\n
\t\t});\n
\t\t$.mobile.window.bind( "throttledresize", $.mobile.resetActivePageHeight );\n
\n
\t};//navreadyDeferred done callback\n
\n
\t$( function() { domreadyDeferred.resolve(); } );\n
\n
\t// Account for the possibility that the load event has already fired\n
\tif ( document.readyState === "complete" ) {\n
\t\tpageIsFullyLoaded();\n
\t} else {\n
\t\t$.mobile.window.load( pageIsFullyLoaded );\n
\t}\n
\n
\t$.when( domreadyDeferred, $.mobile.navreadyDeferred ).done( function() { $.mobile._registerInternalEvents(); } );\n
})( jQuery );\n
\n
\n
(function( $, window, undefined ) {\n
\n
\t// TODO remove direct references to $.mobile and properties, we should\n
\t//      favor injection with params to the constructor\n
\t$.mobile.Transition = function() {\n
\t\tthis.init.apply( this, arguments );\n
\t};\n
\n
\t$.extend($.mobile.Transition.prototype, {\n
\t\ttoPreClass: " ui-page-pre-in",\n
\n
\t\tinit: function( name, reverse, $to, $from ) {\n
\t\t\t$.extend(this, {\n
\t\t\t\tname: name,\n
\t\t\t\treverse: reverse,\n
\t\t\t\t$to: $to,\n
\t\t\t\t$from: $from,\n
\t\t\t\tdeferred: new $.Deferred()\n
\t\t\t});\n
\t\t},\n
\n
\t\tcleanFrom: function() {\n
\t\t\tthis.$from\n
\t\t\t\t.removeClass( $.mobile.activePageClass + " out in reverse " + this.name )\n
\t\t\t\t.height( "" );\n
\t\t},\n
\n
\t\t// NOTE overridden by child object prototypes, noop\'d here as defaults\n
\t\tbeforeDoneIn: function() {},\n
\t\tbeforeDoneOut: function() {},\n
\t\tbeforeStartOut: function() {},\n
\n
\t\tdoneIn: function() {\n
\t\t\tthis.beforeDoneIn();\n
\n
\t\t\tthis.$to.removeClass( "out in reverse " + this.name ).height( "" );\n
\n
\t\t\tthis.toggleViewportClass();\n
\n
\t\t\t// In some browsers (iOS5), 3D transitions block the ability to scroll to the desired location during transition\n
\t\t\t// This ensures we jump to that spot after the fact, if we aren\'t there already.\n
\t\t\tif ( $.mobile.window.scrollTop() !== this.toScroll ) {\n
\t\t\t\tthis.scrollPage();\n
\t\t\t}\n
\t\t\tif ( !this.sequential ) {\n
\t\t\t\tthis.$to.addClass( $.mobile.activePageClass );\n
\t\t\t}\n
\t\t\tthis.deferred.resolve( this.name, this.reverse, this.$to, this.$from, true );\n
\t\t},\n
\n
\t\tdoneOut: function( screenHeight, reverseClass, none, preventFocus ) {\n
\t\t\tthis.beforeDoneOut();\n
\t\t\tthis.startIn( screenHeight, reverseClass, none, preventFocus );\n
\t\t},\n
\n
\t\thideIn: function( callback ) {\n
\t\t\t// Prevent flickering in phonegap container: see comments at #4024 regarding iOS\n
\t\t\tthis.$to.css( "z-index", -10 );\n
\t\t\tcallback.call( this );\n
\t\t\tthis.$to.css( "z-index", "" );\n
\t\t},\n
\n
\t\tscrollPage: function() {\n
\t\t\t// By using scrollTo instead of silentScroll, we can keep things better in order\n
\t\t\t// Just to be precautios, disable scrollstart listening like silentScroll would\n
\t\t\t$.event.special.scrollstart.enabled = false;\n
\t\t\t//if we are hiding the url bar or the page was previously scrolled scroll to hide or return to position\n
\t\t\tif ( $.mobile.hideUrlBar || this.toScroll !== $.mobile.defaultHomeScroll ) {\n
\t\t\t\twindow.scrollTo( 0, this.toScroll );\n
\t\t\t}\n
\n
\t\t\t// reenable scrollstart listening like silentScroll would\n
\t\t\tsetTimeout( function() {\n
\t\t\t\t$.event.special.scrollstart.enabled = true;\n
\t\t\t}, 150 );\n
\t\t},\n
\n
\t\tstartIn: function( screenHeight, reverseClass, none, preventFocus ) {\n
\t\t\tthis.hideIn(function() {\n
\t\t\t\tthis.$to.addClass( $.mobile.activePageClass + this.toPreClass );\n
\n
\t\t\t\t// Send focus to page as it is now display: block\n
\t\t\t\tif ( !preventFocus ) {\n
\t\t\t\t\t$.mobile.focusPage( this.$to );\n
\t\t\t\t}\n
\n
\t\t\t\t// Set to page height\n
\t\t\t\tthis.$to.height( screenHeight + this.toScroll );\n
\n
                if ( !none ) {\n
                    this.scrollPage();\n
                }\n
\t\t\t});\n
\n
\t\t\tthis.$to\n
\t\t\t\t.removeClass( this.toPreClass )\n
\t\t\t\t.addClass( this.name + " in " + reverseClass );\n
\n
\t\t\tif ( !none ) {\n
\t\t\t\tthis.$to.animationComplete( $.proxy(function() {\n
\t\t\t\t\tthis.doneIn();\n
\t\t\t\t}, this ));\n
\t\t\t} else {\n
\t\t\t\tthis.doneIn();\n
\t\t\t}\n
\n
\t\t},\n
\n
\t\tstartOut: function( screenHeight, reverseClass, none ) {\n
\t\t\tthis.beforeStartOut( screenHeight, reverseClass, none );\n
\n
\t\t\t// Set the from page\'s height and start it transitioning out\n
\t\t\t// Note: setting an explicit height helps eliminate tiling in the transitions\n
\t\t\tthis.$from\n
\t\t\t\t.height( screenHeight + $.mobile.window.scrollTop() )\n
\t\t\t\t.addClass( this.name + " out" + reverseClass );\n
\t\t},\n
\n
\t\ttoggleViewportClass: function() {\n
\t\t\t$.mobile.pageContainer.toggleClass( "ui-mobile-viewport-transitioning viewport-" + this.name );\n
\t\t},\n
\n
\t\ttransition: function() {\n
\t\t\t// NOTE many of these could be calculated/recorded in the constructor, it\'s my\n
\t\t\t//      opinion that binding them as late as possible has value with regards to\n
\t\t\t//      better transitions with fewer bugs. Ie, it\'s not guaranteed that the\n
\t\t\t//      object will be created and transition will be run immediately after as\n
\t\t\t//      it is today. So we wait until transition is invoked to gather the following\n
\t\t\tvar none,\n
\t\t\t\treverseClass = this.reverse ? " reverse" : "",\n
\t\t\t\tscreenHeight = $.mobile.getScreenHeight(),\n
\t\t\t\tmaxTransitionOverride = $.mobile.maxTransitionWidth !== false &&\n
\t\t\t\t\t$.mobile.window.width() > $.mobile.maxTransitionWidth;\n
\n
\t\t\tthis.toScroll = $.mobile.navigate.history.getActive().lastScroll || $.mobile.defaultHomeScroll;\n
\n
\t\t\tnone = !$.support.cssTransitions || !$.support.cssAnimations ||\n
\t\t\t\tmaxTransitionOverride || !this.name || this.name === "none" ||\n
\t\t\t\tMath.max( $.mobile.window.scrollTop(), this.toScroll ) >\n
\t\t\t\t\t$.mobile.getMaxScrollForTransition();\n
\n
\t\t\tthis.toggleViewportClass();\n
\n
\t\t\tif ( this.$from && !none ) {\n
\t\t\t\tthis.startOut( screenHeight, reverseClass, none );\n
\t\t\t} else {\n
\t\t\t\tthis.doneOut( screenHeight, reverseClass, none, true );\n
\t\t\t}\n
\n
\t\t\treturn this.deferred.promise();\n
\t\t}\n
\t});\n
})( jQuery, this );\n
\n
\n
(function( $ ) {\n
\n
\t$.mobile.SerialTransition = function() {\n
\t\tthis.init.apply(this, arguments);\n
\t};\n
\n
\t$.extend($.mobile.SerialTransition.prototype, $.mobile.Transition.prototype, {\n
\t\tsequential: true,\n
\n
\t\tbeforeDoneOut: function() {\n
\t\t\tif ( this.$from ) {\n
\t\t\t\tthis.cleanFrom();\n
\t\t\t}\n
\t\t},\n
\n
\t\tbeforeStartOut: function( screenHeight, reverseClass, none ) {\n
\t\t\tthis.$from.animationComplete($.proxy(function() {\n
\t\t\t\tthis.doneOut( screenHeight, reverseClass, none );\n
\t\t\t}, this ));\n
\t\t}\n
\t});\n
\n
})( jQuery );\n
\n
\n
(function( $ ) {\n
\n
\t$.mobile.ConcurrentTransition = function() {\n
\t\tthis.init.apply(this, arguments);\n
\t};\n
\n
\t$.extend($.mobile.ConcurrentTransition.prototype, $.mobile.Transition.prototype, {\n
\t\tsequential: false,\n
\n
\t\tbeforeDoneIn: function() {\n
\t\t\tif ( this.$from ) {\n
\t\t\t\tthis.cleanFrom();\n
\t\t\t}\n
\t\t},\n
\n
\t\tbeforeStartOut: function( screenHeight, reverseClass, none ) {\n
\t\t\tthis.doneOut( screenHeight, reverseClass, none );\n
\t\t}\n
\t});\n
\n
})( jQuery );\n
\n
\n
(function( $ ) {\n
\n
\t// generate the handlers from the above\n
\tvar defaultGetMaxScrollForTransition = function() {\n
\t\treturn $.mobile.getScreenHeight() * 3;\n
\t};\n
\n
\t//transition handler dictionary for 3rd party transitions\n
\t$.mobile.transitionHandlers = {\n
\t\t"sequential": $.mobile.SerialTransition,\n
\t\t"simultaneous": $.mobile.ConcurrentTransition\n
\t};\n
\n
\t// Make our transition handler the public default.\n
\t$.mobile.defaultTransitionHandler = $.mobile.transitionHandlers.sequential;\n
\n
\t$.mobile.transitionFallbacks = {};\n
\n
\t// If transition is defined, check if css 3D transforms are supported, and if not, if a fallback is specified\n
\t$.mobile._maybeDegradeTransition = function( transition ) {\n
\t\tif ( transition && !$.support.cssTransform3d && $.mobile.transitionFallbacks[ transition ] ) {\n
\t\t\ttransition = $.mobile.transitionFallbacks[ transition ];\n
\t\t}\n
\n
\t\treturn transition;\n
\t};\n
\n
\t// Set the getMaxScrollForTransition to default if no implementation was set by user\n
\t$.mobile.getMaxScrollForTransition = $.mobile.getMaxScrollForTransition || defaultGetMaxScrollForTransition;\n
\n
})( jQuery );\n
\n
/*\n
* fallback transition for flip in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.flip = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for flow in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.flow = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for pop in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.pop = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for slide in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
// Use the simultaneous transitions handler for slide transitions\n
$.mobile.transitionHandlers.slide = $.mobile.transitionHandlers.simultaneous;\n
\n
// Set the slide transitions\'s fallback to "fade"\n
$.mobile.transitionFallbacks.slide = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for slidedown in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.slidedown = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for slidefade in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
// Set the slide transitions\'s fallback to "fade"\n
$.mobile.transitionFallbacks.slidefade = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for slideup in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.slideup = "fade";\n
\n
})( jQuery, this );\n
\n
/*\n
* fallback transition for turn in non-3D supporting browsers (which tend to handle complex transitions poorly in general\n
*/\n
\n
(function( $, window, undefined ) {\n
\n
$.mobile.transitionFallbacks.turn = "fade";\n
\n
})( jQuery, this );\n
\n
\n
(function( $, undefined ) {\n
\n
$.mobile.degradeInputs = {\n
\tcolor: false,\n
\tdate: false,\n
\tdatetime: false,\n
\t"datetime-local": false,\n
\temail: false,\n
\tmonth: false,\n
\tnumber: false,\n
\trange: "number",\n
\tsearch: "text",\n
\ttel: false,\n
\ttime: false,\n
\turl: false,\n
\tweek: false\n
};\n
// Backcompat remove in 1.5\n
$.mobile.page.prototype.options.degradeInputs = $.mobile.degradeInputs;\n
\n
// Auto self-init widgets\n
$.mobile.degradeInputsWithin = function( target ) {\n
\n
\ttarget = $( target );\n
\n
\t// Degrade inputs to avoid poorly implemented native functionality\n
\ttarget.find( "input" ).not( $.mobile.page.prototype.keepNativeSelector() ).each(function() {\n
\t\tvar element = $( this ),\n
\t\t\ttype = this.getAttribute( "type" ),\n
\t\t\toptType = $.mobile.degradeInputs[ type ] || "text",\n
\t\t\thtml, hasType, findstr, repstr;\n
\n
\t\tif ( $.mobile.degradeInputs[ type ] ) {\n
\t\t\thtml = $( "<div>" ).html( element.clone() ).html();\n
\t\t\t// In IE browsers, the type sometimes doesn\'t exist in the cloned markup, so we replace the closing tag instead\n
\t\t\thasType = html.indexOf( " type=" ) > -1;\n
\t\t\tfindstr = hasType ? /\\s+type=["\']?\\w+[\'"]?/ : /\\/?>/;\n
\t\t\trepstr = " type=\\"" + optType + "\\" data-" + $.mobile.ns + "type=\\"" + type + "\\"" + ( hasType ? "" : ">" );\n
\n
\t\t\telement.replaceWith( html.replace( findstr, repstr ) );\n
\t\t}\n
\t});\n
\n
};\n
\n
})( jQuery );\n
\n
(function( $, window, undefined ) {\n
\n
$.widget( "mobile.page", $.mobile.page, {\n
\toptions: {\n
\n
\t\t// Accepts left, right and none\n
\t\tcloseBtn: "left",\n
\t\tcloseBtnText: "Close",\n
\t\toverlayTheme: "a",\n
\t\tcorners: true,\n
\t\tdialog: false\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._super();\n
\t\tif ( this.options.dialog ) {\n
\n
\t\t\t$.extend( this, {\n
\t\t\t\t_inner: this.element.children(),\n
\t\t\t\t_headerCloseButton: null\n
\t\t\t});\n
\n
\t\t\tif ( !this.options.enhanced ) {\n
\t\t\t\tthis._setCloseBtn( this.options.closeBtn );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_enhance: function() {\n
\t\tthis._super();\n
\n
\t\t// Class the markup for dialog styling and wrap interior\n
\t\tif ( this.options.dialog ) {\n
\t\t\tthis.element.addClass( "ui-dialog" )\n
\t\t\t\t.wrapInner( $( "<div/>", {\n
\n
\t\t\t\t\t// ARIA role\n
\t\t\t\t\t"role" : "dialog",\n
\t\t\t\t\t"class" : "ui-dialog-contain ui-overlay-shadow" +\n
\t\t\t\t\t\t( this.options.corners ? " ui-corner-all" : "" )\n
\t\t\t\t}));\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar closeButtonLocation, closeButtonText,\n
\t\t\tcurrentOpts = this.options;\n
\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\tthis._inner.toggleClass( "ui-corner-all", !!options.corners );\n
\t\t}\n
\n
\t\tif ( options.overlayTheme !== undefined ) {\n
\t\t\tif ( $.mobile.activePage[ 0 ] === this.element[ 0 ] ) {\n
\t\t\t\tcurrentOpts.overlayTheme = options.overlayTheme;\n
\t\t\t\tthis._handlePageBeforeShow();\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( options.closeBtnText !== undefined ) {\n
\t\t\tcloseButtonLocation = currentOpts.closeBtn;\n
\t\t\tcloseButtonText = options.closeBtnText;\n
\t\t}\n
\n
\t\tif ( options.closeBtn !== undefined ) {\n
\t\t\tcloseButtonLocation = options.closeBtn;\n
\t\t}\n
\n
\t\tif ( closeButtonLocation ) {\n
\t\t\tthis._setCloseBtn( closeButtonLocation, closeButtonText );\n
\t\t}\n
\n
\t\tthis._super( options );\n
\t},\n
\n
\t_handlePageBeforeShow: function () {\n
\t\tif ( this.options.overlayTheme && this.options.dialog ) {\n
\t\t\tthis.removeContainerBackground();\n
\t\t\tthis.setContainerBackground( this.options.overlayTheme );\n
\t\t} else {\n
\t\t\tthis._super();\n
\t\t}\n
\t},\n
\n
\t_setCloseBtn: function( location, text ) {\n
\t\tvar dst,\n
\t\t\tbtn = this._headerCloseButton;\n
\n
\t\t// Sanitize value\n
\t\tlocation = "left" === location ? "left" : "right" === location ? "right" : "none";\n
\n
\t\tif ( "none" === location ) {\n
\t\t\tif ( btn ) {\n
\t\t\t\tbtn.remove();\n
\t\t\t\tbtn = null;\n
\t\t\t}\n
\t\t} else if ( btn ) {\n
\t\t\tbtn.removeClass( "ui-btn-left ui-btn-right" ).addClass( "ui-btn-" + location );\n
\t\t\tif ( text ) {\n
\t\t\t\tbtn.text( text );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tdst = this._inner.find( ":jqmData(role=\'header\')" ).first();\n
\t\t\tbtn = $( "<a></a>", {\n
\t\t\t\t\t"href": "#",\n
\t\t\t\t\t"class": "ui-btn ui-corner-all ui-icon-delete ui-btn-icon-notext ui-btn-" + location\n
\t\t\t\t})\n
\t\t\t\t.attr( "data-" + $.mobile.ns + "rel", "back" )\n
\t\t\t\t.text( text || this.options.closeBtnText || "" )\n
\t\t\t\t.prependTo( dst );\n
\t\t}\n
\n
\t\tthis._headerCloseButton = btn;\n
\t}\n
});\n
\n
})( jQuery, this );\n
\n
(function( $, window, undefined ) {\n
\n
$.widget( "mobile.dialog", {\n
\toptions: {\n
\n
\t\t// Accepts left, right and none\n
\t\tcloseBtn: "left",\n
\t\tcloseBtnText: "Close",\n
\t\toverlayTheme: "a",\n
\t\tcorners: true\n
\t},\n
\n
\t// Override the theme set by the page plugin on pageshow\n
\t_handlePageBeforeShow: function() {\n
\t\tthis._isCloseable = true;\n
\t\tif ( this.options.overlayTheme ) {\n
\t\t\tthis.element\n
\t\t\t\t.page( "removeContainerBackground" )\n
\t\t\t\t.page( "setContainerBackground", this.options.overlayTheme );\n
\t\t}\n
\t},\n
\n
\t_handlePageBeforeHide: function() {\n
\t\tthis._isCloseable = false;\n
\t},\n
\n
\t// click and submit events:\n
\t// - clicks and submits should use the closing transition that the dialog\n
\t//   opened with unless a data-transition is specified on the link/form\n
\t// - if the click was on the close button, or the link has a data-rel="back"\n
\t//   it\'ll go back in history naturally\n
\t_handleVClickSubmit: function( event ) {\n
\t\tvar attrs,\n
\t\t\t$target = $( event.target ).closest( event.type === "vclick" ? "a" : "form" );\n
\n
\t\tif ( $target.length && !$target.jqmData( "transition" ) ) {\n
\t\t\tattrs = {};\n
\t\t\tattrs[ "data-" + $.mobile.ns + "transition" ] =\n
\t\t\t\t( $.mobile.navigate.history.getActive() || {} )[ "transition" ] ||\n
\t\t\t\t$.mobile.defaultDialogTransition;\n
\t\t\tattrs[ "data-" + $.mobile.ns + "direction" ] = "reverse";\n
\t\t\t$target.attr( attrs );\n
\t\t}\n
\t},\n
\n
\t_create: function() {\n
\t\tvar elem = this.element,\n
\t\t\topts = this.options;\n
\n
\t\t// Class the markup for dialog styling and wrap interior\n
\t\telem.addClass( "ui-dialog" )\n
\t\t\t.wrapInner( $( "<div/>", {\n
\n
\t\t\t\t// ARIA role\n
\t\t\t\t"role" : "dialog",\n
\t\t\t\t"class" : "ui-dialog-contain ui-overlay-shadow" +\n
\t\t\t\t\t( !!opts.corners ? " ui-corner-all" : "" )\n
\t\t\t}));\n
\n
\t\t$.extend( this, {\n
\t\t\t_isCloseable: false,\n
\t\t\t_inner: elem.children(),\n
\t\t\t_headerCloseButton: null\n
\t\t});\n
\n
\t\tthis._on( elem, {\n
\t\t\tvclick: "_handleVClickSubmit",\n
\t\t\tsubmit: "_handleVClickSubmit",\n
\t\t\tpagebeforeshow: "_handlePageBeforeShow",\n
\t\t\tpagebeforehide: "_handlePageBeforeHide"\n
\t\t});\n
\n
\t\tthis._setCloseBtn( opts.closeBtn );\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar closeButtonLocation, closeButtonText,\n
\t\t\tcurrentOpts = this.options;\n
\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\tthis._inner.toggleClass( "ui-corner-all", !!options.corners );\n
\t\t}\n
\n
\t\tif ( options.overlayTheme !== undefined ) {\n
\t\t\tif ( $.mobile.activePage[ 0 ] === this.element[ 0 ] ) {\n
\t\t\t\tcurrentOpts.overlayTheme = options.overlayTheme;\n
\t\t\t\tthis._handlePageBeforeShow();\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( options.closeBtnText !== undefined ) {\n
\t\t\tcloseButtonLocation = currentOpts.closeBtn;\n
\t\t\tcloseButtonText = options.closeBtnText;\n
\t\t}\n
\n
\t\tif ( options.closeBtn !== undefined ) {\n
\t\t\tcloseButtonLocation = options.closeBtn;\n
\t\t}\n
\n
\t\tif ( closeButtonLocation ) {\n
\t\t\tthis._setCloseBtn( closeButtonLocation, closeButtonText );\n
\t\t}\n
\n
\t\tthis._super( options );\n
\t},\n
\n
\t_setCloseBtn: function( location, text ) {\n
\t\tvar dst,\n
\t\t\tbtn = this._headerCloseButton;\n
\n
\t\t// Sanitize value\n
\t\tlocation = "left" === location ? "left" : "right" === location ? "right" : "none";\n
\n
\t\tif ( "none" === location ) {\n
\t\t\tif ( btn ) {\n
\t\t\t\tbtn.remove();\n
\t\t\t\tbtn = null;\n
\t\t\t}\n
\t\t} else if ( btn ) {\n
\t\t\tbtn.removeClass( "ui-btn-left ui-btn-right" ).addClass( "ui-btn-" + location );\n
\t\t\tif ( text ) {\n
\t\t\t\tbtn.text( text );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tdst = this._inner.find( ":jqmData(role=\'header\')" ).first();\n
\t\t\tbtn = $( "<a></a>", {\n
\t\t\t\t\t"role": "button",\n
\t\t\t\t\t"href": "#",\n
\t\t\t\t\t"class": "ui-btn ui-corner-all ui-icon-delete ui-btn-icon-notext ui-btn-" + location\n
\t\t\t\t})\n
\t\t\t\t.text( text || this.options.closeBtnText || "" )\n
\t\t\t\t.prependTo( dst );\n
\t\t\tthis._on( btn, { click: "close" } );\n
\t\t}\n
\n
\t\tthis._headerCloseButton = btn;\n
\t},\n
\n
\t// Close method goes back in history\n
\tclose: function() {\n
\t\tvar hist = $.mobile.navigate.history;\n
\n
\t\tif ( this._isCloseable ) {\n
\t\t\tthis._isCloseable = false;\n
\t\t\t// If the hash listening is enabled and there is at least one preceding history\n
\t\t\t// entry it\'s ok to go back. Initial pages with the dialog hash state are an example\n
\t\t\t// where the stack check is necessary\n
\t\t\tif ( $.mobile.hashListeningEnabled && hist.activeIndex > 0 ) {\n
\t\t\t\t$.mobile.back();\n
\t\t\t} else {\n
\t\t\t\t$.mobile.pageContainer.pagecontainer( "back" );\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery, this );\n
\n
(function( $, undefined ) {\n
\n
var rInitialLetter = /([A-Z])/g,\n
\n
\t// Construct iconpos class from iconpos value\n
\ticonposClass = function( iconpos ) {\n
\t\treturn ( "ui-btn-icon-" + ( iconpos === null ? "left" : iconpos ) );\n
\t};\n
\n
$.widget( "mobile.collapsible", {\n
\toptions: {\n
\t\tenhanced: false,\n
\t\texpandCueText: null,\n
\t\tcollapseCueText: null,\n
\t\tcollapsed: true,\n
\t\theading: "h1,h2,h3,h4,h5,h6,legend",\n
\t\tcollapsedIcon: null,\n
\t\texpandedIcon: null,\n
\t\ticonpos: null,\n
\t\ttheme: null,\n
\t\tcontentTheme: null,\n
\t\tinset: null,\n
\t\tcorners: null,\n
\t\tmini: null\n
\t},\n
\n
\t_create: function() {\n
\t\tvar elem = this.element,\n
\t\t\tui = {\n
\t\t\t\taccordion: elem\n
\t\t\t\t\t.closest( ":jqmData(role=\'collapsible-set\')," +\n
\t\t\t\t\t\t":jqmData(role=\'collapsibleset\')" +\n
\t\t\t\t\t\t( $.mobile.collapsibleset ? ", :mobile-collapsibleset" :\n
\t\t\t\t\t\t\t"" ) )\n
\t\t\t\t\t.addClass( "ui-collapsible-set" )\n
\t\t\t};\n
\n
\t\tthis._ui = ui;\n
\t\tthis._renderedOptions = this._getOptions( this.options );\n
\n
\t\tif ( this.options.enhanced ) {\n
\t\t\tui.heading = this.element.children( ".ui-collapsible-heading" );\n
\t\t\tui.content = ui.heading.next();\n
\t\t\tui.anchor = ui.heading.children();\n
\t\t\tui.status = ui.anchor.children( ".ui-collapsible-heading-status" );\n
\t\t} else {\n
\t\t\tthis._enhance( elem, ui );\n
\t\t}\n
\n
\t\tthis._on( ui.heading, {\n
\t\t\t"tap": function() {\n
\t\t\t\tui.heading.find( "a" ).first().addClass( $.mobile.activeBtnClass );\n
\t\t\t},\n
\n
\t\t\t"click": function( event ) {\n
\t\t\t\tthis._handleExpandCollapse( !ui.heading.hasClass( "ui-collapsible-heading-collapsed" ) );\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\tevent.stopPropagation();\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t// Adjust the keys inside options for inherited values\n
\t_getOptions: function( options ) {\n
\t\tvar key,\n
\t\t\taccordion = this._ui.accordion,\n
\t\t\taccordionWidget = this._ui.accordionWidget;\n
\n
\t\t// Copy options\n
\t\toptions = $.extend( {}, options );\n
\n
\t\tif ( accordion.length && !accordionWidget ) {\n
\t\t\tthis._ui.accordionWidget =\n
\t\t\taccordionWidget = accordion.data( "mobile-collapsibleset" );\n
\t\t}\n
\n
\t\tfor ( key in options ) {\n
\n
\t\t\t// Retrieve the option value first from the options object passed in and, if\n
\t\t\t// null, from the parent accordion or, if that\'s null too, or if there\'s no\n
\t\t\t// parent accordion, then from the defaults.\n
\t\t\toptions[ key ] =\n
\t\t\t\t( options[ key ] != null ) ? options[ key ] :\n
\t\t\t\t( accordionWidget ) ? accordionWidget.options[ key ] :\n
\t\t\t\taccordion.length ? $.mobile.getAttribute( accordion[ 0 ],\n
\t\t\t\t\tkey.replace( rInitialLetter, "-$1" ).toLowerCase() ):\n
\t\t\t\tnull;\n
\n
\t\t\tif ( null == options[ key ] ) {\n
\t\t\t\toptions[ key ] = $.mobile.collapsible.defaults[ key ];\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn options;\n
\t},\n
\n
\t_themeClassFromOption: function( prefix, value ) {\n
\t\treturn ( value ? ( value === "none" ? "" : prefix + value ) : "" );\n
\t},\n
\n
\t_enhance: function( elem, ui ) {\n
\t\tvar iconclass,\n
\t\t\topts = this._renderedOptions,\n
\t\t\tcontentThemeClass = this._themeClassFromOption( "ui-body-", opts.contentTheme );\n
\n
\t\telem.addClass( "ui-collapsible " +\n
\t\t\t( opts.inset ? "ui-collapsible-inset " : "" ) +\n
\t\t\t( opts.inset && opts.corners ? "ui-corner-all " : "" ) +\n
\t\t\t( contentThemeClass ? "ui-collapsible-themed-content " : "" ) );\n
\t\tui.originalHeading = elem.children( this.options.heading ).first(),\n
\t\tui.content = elem\n
\t\t\t.wrapInner( "<div " +\n
\t\t\t\t"class=\'ui-collapsible-content " +\n
\t\t\t\tcontentThemeClass + "\'></div>" )\n
\t\t\t.children( ".ui-collapsible-content" ),\n
\t\tui.heading = ui.originalHeading;\n
\n
\t\t// Replace collapsibleHeading if it\'s a legend\n
\t\tif ( ui.heading.is( "legend" ) ) {\n
\t\t\tui.heading = $( "<div role=\'heading\'>"+ ui.heading.html() +"</div>" );\n
\t\t\tui.placeholder = $( "<div><!-- placeholder for legend --></div>" ).insertBefore( ui.originalHeading );\n
\t\t\tui.originalHeading.remove();\n
\t\t}\n
\n
\t\ticonclass = ( opts.collapsed ? ( opts.collapsedIcon ? "ui-icon-" + opts.collapsedIcon : "" ):\n
\t\t\t( opts.expandedIcon ? "ui-icon-" + opts.expandedIcon : "" ) );\n
\n
\t\tui.status = $( "<span class=\'ui-collapsible-heading-status\'></span>" );\n
\t\tui.anchor = ui.heading\n
\t\t\t.detach()\n
\t\t\t//modify markup & attributes\n
\t\t\t.addClass( "ui-collapsible-heading" )\n
\t\t\t.append( ui.status )\n
\t\t\t.wrapInner( "<a href=\'#\' class=\'ui-collapsible-heading-toggle\'></a>" )\n
\t\t\t.find( "a" )\n
\t\t\t\t.first()\n
\t\t\t\t.addClass( "ui-btn " +\n
\t\t\t\t\t( iconclass ? iconclass + " " : "" ) +\n
\t\t\t\t\t( iconclass ? iconposClass( opts.iconpos ) +\n
\t\t\t\t\t\t" " : "" ) +\n
\t\t\t\t\tthis._themeClassFromOption( "ui-btn-", opts.theme ) + " " +\n
\t\t\t\t\t( opts.mini ? "ui-mini " : "" ) );\n
\n
\t\t//drop heading in before content\n
\t\tui.heading.insertBefore( ui.content );\n
\n
\t\tthis._handleExpandCollapse( this.options.collapsed );\n
\n
\t\treturn ui;\n
\t},\n
\n
\trefresh: function() {\n
\t\tthis._applyOptions( this.options );\n
\t\tthis._renderedOptions = this._getOptions( this.options );\n
\t},\n
\n
\t_applyOptions: function( options ) {\n
\t\tvar isCollapsed, newTheme, oldTheme, hasCorners, hasIcon,\n
\t\t\telem = this.element,\n
\t\t\tcurrentOpts = this._renderedOptions,\n
\t\t\tui = this._ui,\n
\t\t\tanchor = ui.anchor,\n
\t\t\tstatus = ui.status,\n
\t\t\topts = this._getOptions( options );\n
\n
\t\t// First and foremost we need to make sure the collapsible is in the proper\n
\t\t// state, in case somebody decided to change the collapsed option at the\n
\t\t// same time as another option\n
\t\tif ( options.collapsed !== undefined ) {\n
\t\t\tthis._handleExpandCollapse( options.collapsed );\n
\t\t}\n
\n
\t\tisCollapsed = elem.hasClass( "ui-collapsible-collapsed" );\n
\n
\t\t// We only need to apply the cue text for the current state right away.\n
\t\t// The cue text for the alternate state will be stored in the options\n
\t\t// and applied the next time the collapsible\'s state is toggled\n
\t\tif ( isCollapsed ) {\n
\t\t\tif ( opts.expandCueText !== undefined ) {\n
\t\t\t\tstatus.text( opts.expandCueText );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tif ( opts.collapseCueText !== undefined ) {\n
\t\t\t\tstatus.text( opts.collapseCueText );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Update icon\n
\n
\t\t// Is it supposed to have an icon?\n
\t\thasIcon =\n
\n
\t\t\t// If the collapsedIcon is being set, consult that\n
\t\t\t( opts.collapsedIcon !== undefined ? opts.collapsedIcon !== false :\n
\n
\t\t\t\t// Otherwise consult the existing option value\n
\t\t\t\tcurrentOpts.collapsedIcon !== false );\n
\n
\n
\t\t// If any icon-related options have changed, make sure the new icon\n
\t\t// state is reflected by first removing all icon-related classes\n
\t\t// reflecting the current state and then adding all icon-related\n
\t\t// classes for the new state\n
\t\tif ( !( opts.iconpos === undefined &&\n
\t\t\topts.collapsedIcon === undefined &&\n
\t\t\topts.expandedIcon === undefined ) ) {\n
\n
\t\t\t// Remove all current icon-related classes\n
\t\t\tanchor.removeClass( [ iconposClass( currentOpts.iconpos ) ]\n
\t\t\t\t.concat( ( currentOpts.expandedIcon ?\n
\t\t\t\t\t[ "ui-icon-" + currentOpts.expandedIcon ] : [] ) )\n
\t\t\t\t.concat( ( currentOpts.collapsedIcon ?\n
\t\t\t\t\t[ "ui-icon-" + currentOpts.collapsedIcon ] : [] ) )\n
\t\t\t\t.join( " " ) );\n
\n
\t\t\t// Add new classes if an icon is supposed to be present\n
\t\t\tif ( hasIcon ) {\n
\t\t\t\tanchor.addClass(\n
\t\t\t\t\t[ iconposClass( opts.iconpos !== undefined ?\n
\t\t\t\t\t\topts.iconpos : currentOpts.iconpos ) ]\n
\t\t\t\t\t\t.concat( isCollapsed ?\n
\t\t\t\t\t\t\t[ "ui-icon-" + ( opts.collapsedIcon !== undefined ?\n
\t\t\t\t\t\t\t\topts.collapsedIcon :\n
\t\t\t\t\t\t\t\tcurrentOpts.collapsedIcon ) ] :\n
\t\t\t\t\t\t\t[ "ui-icon-" + ( opts.expandedIcon !== undefined ?\n
\t\t\t\t\t\t\t\topts.expandedIcon :\n
\t\t\t\t\t\t\t\tcurrentOpts.expandedIcon ) ] )\n
\t\t\t\t\t\t.join( " " ) );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( opts.theme !== undefined ) {\n
\t\t\toldTheme = this._themeClassFromOption( "ui-btn-", currentOpts.theme );\n
\t\t\tnewTheme = this._themeClassFromOption( "ui-btn-", opts.theme );\n
\t\t\tanchor.removeClass( oldTheme ).addClass( newTheme );\n
\t\t}\n
\n
\t\tif ( opts.contentTheme !== undefined ) {\n
\t\t\toldTheme = this._themeClassFromOption( "ui-body-",\n
\t\t\t\tcurrentOpts.contentTheme );\n
\t\t\tnewTheme = this._themeClassFromOption( "ui-body-",\n
\t\t\t\topts.contentTheme );\n
\t\t\tui.content.removeClass( oldTheme ).addClass( newTheme );\n
\t\t}\n
\n
\t\tif ( opts.inset !== undefined ) {\n
\t\t\telem.toggleClass( "ui-collapsible-inset", opts.inset );\n
\t\t\thasCorners = !!( opts.inset && ( opts.corners || currentOpts.corners ) );\n
\t\t}\n
\n
\t\tif ( opts.corners !== undefined ) {\n
\t\t\thasCorners = !!( opts.corners && ( opts.inset || currentOpts.inset ) );\n
\t\t}\n
\n
\t\tif ( hasCorners !== undefined ) {\n
\t\t\telem.toggleClass( "ui-corner-all", hasCorners );\n
\t\t}\n
\n
\t\tif ( opts.mini !== undefined ) {\n
\t\t\tanchor.toggleClass( "ui-mini", opts.mini );\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tthis._applyOptions( options );\n
\t\tthis._super( options );\n
\t\tthis._renderedOptions = this._getOptions( this.options );\n
\t},\n
\n
\t_handleExpandCollapse: function( isCollapse ) {\n
\t\tvar opts = this._renderedOptions,\n
\t\t\tui = this._ui;\n
\n
\t\tui.status.text( isCollapse ? opts.expandCueText : opts.collapseCueText );\n
\t\tui.heading\n
\t\t\t.toggleClass( "ui-collapsible-heading-collapsed", isCollapse )\n
\t\t\t.find( "a" ).first()\n
\t\t\t.toggleClass( "ui-icon-" + opts.expandedIcon, !isCollapse )\n
\n
\t\t\t// logic or cause same icon for expanded/collapsed state would remove the ui-icon-class\n
\t\t\t.toggleClass( "ui-icon-" + opts.collapsedIcon, ( isCollapse || opts.expandedIcon === opts.collapsedIcon ) )\n
\t\t\t.removeClass( $.mobile.activeBtnClass );\n
\n
\t\tthis.element.toggleClass( "ui-collapsible-collapsed", isCollapse );\n
\t\tui.content\n
\t\t\t.toggleClass( "ui-collapsible-content-collapsed", isCollapse )\n
\t\t\t.attr( "aria-hidden", isCollapse )\n
\t\t\t.trigger( "updatelayout" );\n
\t\tthis.options.collapsed = isCollapse;\n
\t\tthis._trigger( isCollapse ? "collapse" : "expand" );\n
\t},\n
\n
\texpand: function() {\n
\t\tthis._handleExpandCollapse( false );\n
\t},\n
\n
\tcollapse: function() {\n
\t\tthis._handleExpandCollapse( true );\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar ui = this._ui,\n
\t\t\topts = this.options;\n
\n
\t\tif ( opts.enhanced ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( ui.placeholder ) {\n
\t\t\tui.originalHeading.insertBefore( ui.placeholder );\n
\t\t\tui.placeholder.remove();\n
\t\t\tui.heading.remove();\n
\t\t} else {\n
\t\t\tui.status.remove();\n
\t\t\tui.heading\n
\t\t\t\t.removeClass( "ui-collapsible-heading ui-collapsible-heading-collapsed" )\n
\t\t\t\t.children()\n
\t\t\t\t\t.contents()\n
\t\t\t\t\t\t.unwrap();\n
\t\t}\n
\n
\t\tui.anchor.contents().unwrap();\n
\t\tui.content.contents().unwrap();\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-collapsible ui-collapsible-collapsed " +\n
\t\t\t\t"ui-collapsible-themed-content ui-collapsible-inset ui-corner-all" );\n
\t}\n
});\n
\n
// Defaults to be used by all instances of collapsible if per-instance values\n
// are unset or if nothing is specified by way of inheritance from an accordion.\n
// Note that this hash does not contain options "collapsed" or "heading",\n
// because those are not inheritable.\n
$.mobile.collapsible.defaults = {\n
\texpandCueText: " click to expand contents",\n
\tcollapseCueText: " click to collapse contents",\n
\tcollapsedIcon: "plus",\n
\tcontentTheme: "inherit",\n
\texpandedIcon: "minus",\n
\ticonpos: "left",\n
\tinset: true,\n
\tcorners: true,\n
\ttheme: "inherit",\n
\tmini: false\n
};\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
var uiScreenHiddenRegex = /\\bui-screen-hidden\\b/;\n
function noHiddenClass( elements ) {\n
\tvar index,\n
\t\tlength = elements.length,\n
\t\tresult = [];\n
\n
\tfor ( index = 0; index < length; index++ ) {\n
\t\tif ( !elements[ index ].className.match( uiScreenHiddenRegex ) ) {\n
\t\t\tresult.push( elements[ index ] );\n
\t\t}\n
\t}\n
\n
\treturn $( result );\n
}\n
\n
$.mobile.behaviors.addFirstLastClasses = {\n
\t_getVisibles: function( $els, create ) {\n
\t\tvar visibles;\n
\n
\t\tif ( create ) {\n
\t\t\tvisibles = noHiddenClass( $els );\n
\t\t} else {\n
\t\t\tvisibles = $els.filter( ":visible" );\n
\t\t\tif ( visibles.length === 0 ) {\n
\t\t\t\tvisibles = noHiddenClass( $els );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn visibles;\n
\t},\n
\n
\t_addFirstLastClasses: function( $els, $visibles, create ) {\n
\t\t$els.removeClass( "ui-first-child ui-last-child" );\n
\t\t$visibles.eq( 0 ).addClass( "ui-first-child" ).end().last().addClass( "ui-last-child" );\n
\t\tif ( !create ) {\n
\t\t\tthis.element.trigger( "updatelayout" );\n
\t\t}\n
\t},\n
\n
\t_removeFirstLastClasses: function( $els ) {\n
\t\t$els.removeClass( "ui-first-child ui-last-child" );\n
\t}\n
};\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
var childCollapsiblesSelector = ":mobile-collapsible, " + $.mobile.collapsible.initSelector;\n
\n
$.widget( "mobile.collapsibleset", $.extend( {\n
\n
\t// The initSelector is deprecated as of 1.4.0. In 1.5.0 we will use\n
\t// :jqmData(role=\'collapsibleset\') which will allow us to get rid of the line\n
\t// below altogether, because the autoinit will generate such an initSelector\n
\tinitSelector: ":jqmData(role=\'collapsible-set\'),:jqmData(role=\'collapsibleset\')",\n
\n
\toptions: $.extend( {\n
\t\tenhanced: false\n
\t}, $.mobile.collapsible.defaults ),\n
\n
\t_handleCollapsibleExpand: function( event ) {\n
\t\tvar closestCollapsible = $( event.target ).closest( ".ui-collapsible" );\n
\n
\t\tif ( closestCollapsible.parent().is( ":mobile-collapsibleset, :jqmData(role=\'collapsible-set\')" ) ) {\n
\t\t\tclosestCollapsible\n
\t\t\t\t.siblings( ".ui-collapsible:not(.ui-collapsible-collapsed)" )\n
\t\t\t\t.collapsible( "collapse" );\n
\t\t}\n
\t},\n
\n
\t_create: function() {\n
\t\tvar elem = this.element,\n
\t\t\topts = this.options;\n
\n
\t\t$.extend( this, {\n
\t\t\t_classes: ""\n
\t\t});\n
\n
\t\tif ( !opts.enhanced ) {\n
\t\t\telem.addClass( "ui-collapsible-set " +\n
\t\t\t\tthis._themeClassFromOption( "ui-group-theme-", opts.theme ) + " " +\n
\t\t\t\t( opts.corners && opts.inset ? "ui-corner-all " : "" ) );\n
\t\t\tthis.element.find( $.mobile.collapsible.initSelector ).collapsible();\n
\t\t}\n
\n
\t\tthis._on( elem, { collapsibleexpand: "_handleCollapsibleExpand" } );\n
\t},\n
\n
\t_themeClassFromOption: function( prefix, value ) {\n
\t\treturn ( value ? ( value === "none" ? "" : prefix + value ) : "" );\n
\t},\n
\n
\t_init: function() {\n
\t\tthis._refresh( true );\n
\n
\t\t// Because the corners are handled by the collapsible itself and the default state is collapsed\n
\t\t// That was causing https://github.com/jquery/jquery-mobile/issues/4116\n
\t\tthis.element\n
\t\t\t.children( childCollapsiblesSelector )\n
\t\t\t.filter( ":jqmData(collapsed=\'false\')" )\n
\t\t\t.collapsible( "expand" );\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar ret, hasCorners,\n
\t\t\telem = this.element,\n
\t\t\tthemeClass = this._themeClassFromOption( "ui-group-theme-", options.theme );\n
\n
\t\tif ( themeClass ) {\n
\t\t\telem\n
\t\t\t\t.removeClass( this._themeClassFromOption( "ui-group-theme-", this.options.theme ) )\n
\t\t\t\t.addClass( themeClass );\n
\t\t}\n
\n
\t\tif ( options.inset !== undefined ) {\n
\t\t\thasCorners = !!( options.inset && ( options.corners || this.options.corners ) );\n
\t\t}\n
\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\thasCorners = !!( options.corners && ( options.inset || this.options.inset ) );\n
\t\t}\n
\n
\t\tif ( hasCorners !== undefined ) {\n
\t\t\telem.toggleClass( "ui-corner-all", hasCorners );\n
\t\t}\n
\n
\t\tret = this._super( options );\n
\t\tthis.element.children( ":mobile-collapsible" ).collapsible( "refresh" );\n
\t\treturn ret;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar el = this.element;\n
\n
\t\tthis._removeFirstLastClasses( el.children( childCollapsiblesSelector ) );\n
\t\tel\n
\t\t\t.removeClass( "ui-collapsible-set ui-corner-all " +\n
\t\t\t\tthis._themeClassFromOption( "ui-group-theme-", this.options.theme ) )\n
\t\t\t.children( ":mobile-collapsible" )\n
\t\t\t.collapsible( "destroy" );\n
\t},\n
\n
\t_refresh: function( create ) {\n
\t\tvar collapsiblesInSet = this.element.children( childCollapsiblesSelector );\n
\n
\t\tthis.element.find( $.mobile.collapsible.initSelector ).not( ".ui-collapsible" ).collapsible();\n
\n
\t\tthis._addFirstLastClasses( collapsiblesInSet, this._getVisibles( collapsiblesInSet, create ), create );\n
\t},\n
\n
\trefresh: function() {\n
\t\tthis._refresh( false );\n
\t}\n
}, $.mobile.behaviors.addFirstLastClasses ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
// Deprecated in 1.4\n
$.fn.fieldcontain = function(/* options */) {\n
\treturn this.addClass( "ui-field-contain" );\n
};\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.fn.grid = function( options ) {\n
\treturn this.each(function() {\n
\n
\t\tvar $this = $( this ),\n
\t\t\to = $.extend({\n
\t\t\t\tgrid: null\n
\t\t\t}, options ),\n
\t\t\t$kids = $this.children(),\n
\t\t\tgridCols = { solo:1, a:2, b:3, c:4, d:5 },\n
\t\t\tgrid = o.grid,\n
\t\t\titerator,\n
\t\t\tletter;\n
\n
\t\t\tif ( !grid ) {\n
\t\t\t\tif ( $kids.length <= 5 ) {\n
\t\t\t\t\tfor ( letter in gridCols ) {\n
\t\t\t\t\t\tif ( gridCols[ letter ] === $kids.length ) {\n
\t\t\t\t\t\t\tgrid = letter;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tgrid = "a";\n
\t\t\t\t\t$this.addClass( "ui-grid-duo" );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\titerator = gridCols[grid];\n
\n
\t\t$this.addClass( "ui-grid-" + grid );\n
\n
\t\t$kids.filter( ":nth-child(" + iterator + "n+1)" ).addClass( "ui-block-a" );\n
\n
\t\tif ( iterator > 1 ) {\n
\t\t\t$kids.filter( ":nth-child(" + iterator + "n+2)" ).addClass( "ui-block-b" );\n
\t\t}\n
\t\tif ( iterator > 2 ) {\n
\t\t\t$kids.filter( ":nth-child(" + iterator + "n+3)" ).addClass( "ui-block-c" );\n
\t\t}\n
\t\tif ( iterator > 3 ) {\n
\t\t\t$kids.filter( ":nth-child(" + iterator + "n+4)" ).addClass( "ui-block-d" );\n
\t\t}\n
\t\tif ( iterator > 4 ) {\n
\t\t\t$kids.filter( ":nth-child(" + iterator + "n+5)" ).addClass( "ui-block-e" );\n
\t\t}\n
\t});\n
};\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.navbar", {\n
\toptions: {\n
\t\ticonpos: "top",\n
\t\tgrid: null\n
\t},\n
\n
\t_create: function() {\n
\n
\t\tvar $navbar = this.element,\n
\t\t\t$navbtns = $navbar.find( "a, button" ),\n
\t\t\ticonpos = $navbtns.filter( ":jqmData(icon)" ).length ? this.options.iconpos : undefined;\n
\n
\t\t$navbar.addClass( "ui-navbar" )\n
\t\t\t.attr( "role", "navigation" )\n
\t\t\t.find( "ul" )\n
\t\t\t.jqmEnhanceable()\n
\t\t\t.grid({ grid: this.options.grid });\n
\n
\t\t$navbtns\n
\t\t\t.each( function() {\n
\t\t\t\tvar icon = $.mobile.getAttribute( this, "icon" ),\n
\t\t\t\t\ttheme = $.mobile.getAttribute( this, "theme" ),\n
\t\t\t\t\tclasses = "ui-btn";\n
\n
\t\t\t\tif ( theme ) {\n
\t\t\t\t\tclasses += " ui-btn-" + theme;\n
\t\t\t\t}\n
\t\t\t\tif ( icon ) {\n
\t\t\t\t\tclasses += " ui-icon-" + icon + " ui-btn-icon-" + iconpos;\n
\t\t\t\t}\n
\t\t\t\t$( this ).addClass( classes );\n
\t\t\t});\n
\n
\t\t$navbar.delegate( "a", "vclick", function( /* event */ ) {\n
\t\t\tvar activeBtn = $( this );\n
\n
\t\t\tif ( !( activeBtn.hasClass( "ui-state-disabled" ) ||\n
\n
\t\t\t\t// DEPRECATED as of 1.4.0 - remove after 1.4.0 release\n
\t\t\t\t// only ui-state-disabled should be present thereafter\n
\t\t\t\tactiveBtn.hasClass( "ui-disabled" ) ||\n
\t\t\t\tactiveBtn.hasClass( $.mobile.activeBtnClass ) ) ) {\n
\n
\t\t\t\t$navbtns.removeClass( $.mobile.activeBtnClass );\n
\t\t\t\tactiveBtn.addClass( $.mobile.activeBtnClass );\n
\n
\t\t\t\t// The code below is a workaround to fix #1181\n
\t\t\t\t$( document ).one( "pagehide", function() {\n
\t\t\t\t\tactiveBtn.removeClass( $.mobile.activeBtnClass );\n
\t\t\t\t});\n
\t\t\t}\n
\t\t});\n
\n
\t\t// Buttons in the navbar with ui-state-persist class should regain their active state before page show\n
\t\t$navbar.closest( ".ui-page" ).bind( "pagebeforeshow", function() {\n
\t\t\t$navbtns.filter( ".ui-state-persist" ).addClass( $.mobile.activeBtnClass );\n
\t\t});\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
var getAttr = $.mobile.getAttribute;\n
\n
$.widget( "mobile.listview", $.extend( {\n
\n
\toptions: {\n
\t\ttheme: null,\n
\t\tcountTheme: null, /* Deprecated in 1.4 */\n
\t\tdividerTheme: null,\n
\t\ticon: "carat-r",\n
\t\tsplitIcon: "carat-r",\n
\t\tsplitTheme: null,\n
\t\tcorners: true,\n
\t\tshadow: true,\n
\t\tinset: false\n
\t},\n
\n
\t_create: function() {\n
\t\tvar t = this,\n
\t\t\tlistviewClasses = "";\n
\n
\t\tlistviewClasses += t.options.inset ? " ui-listview-inset" : "";\n
\n
\t\tif ( !!t.options.inset ) {\n
\t\t\tlistviewClasses += t.options.corners ? " ui-corner-all" : "";\n
\t\t\tlistviewClasses += t.options.shadow ? " ui-shadow" : "";\n
\t\t}\n
\n
\t\t// create listview markup\n
\t\tt.element.addClass( " ui-listview" + listviewClasses );\n
\n
\t\tt.refresh( true );\n
\t},\n
\n
\t// TODO: Remove in 1.5\n
\t_findFirstElementByTagName: function( ele, nextProp, lcName, ucName ) {\n
\t\tvar dict = {};\n
\t\tdict[ lcName ] = dict[ ucName ] = true;\n
\t\twhile ( ele ) {\n
\t\t\tif ( dict[ ele.nodeName ] ) {\n
\t\t\t\treturn ele;\n
\t\t\t}\n
\t\t\tele = ele[ nextProp ];\n
\t\t}\n
\t\treturn null;\n
\t},\n
\t// TODO: Remove in 1.5\n
\t_addThumbClasses: function( containers ) {\n
\t\tvar i, img, len = containers.length;\n
\t\tfor ( i = 0; i < len; i++ ) {\n
\t\t\timg = $( this._findFirstElementByTagName( containers[ i ].firstChild, "nextSibling", "img", "IMG" ) );\n
\t\t\tif ( img.length ) {\n
\t\t\t\t$( this._findFirstElementByTagName( img[ 0 ].parentNode, "parentNode", "li", "LI" ) ).addClass( img.hasClass( "ui-li-icon" ) ? "ui-li-has-icon" : "ui-li-has-thumb" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_getChildrenByTagName: function( ele, lcName, ucName ) {\n
\t\tvar results = [],\n
\t\t\tdict = {};\n
\t\tdict[ lcName ] = dict[ ucName ] = true;\n
\t\tele = ele.firstChild;\n
\t\twhile ( ele ) {\n
\t\t\tif ( dict[ ele.nodeName ] ) {\n
\t\t\t\tresults.push( ele );\n
\t\t\t}\n
\t\t\tele = ele.nextSibling;\n
\t\t}\n
\t\treturn $( results );\n
\t},\n
\n
\t_beforeListviewRefresh: $.noop,\n
\t_afterListviewRefresh: $.noop,\n
\n
\trefresh: function( create ) {\n
\t\tvar buttonClass, pos, numli, item, itemClass, itemTheme, itemIcon, icon, a,\n
\t\t\tisDivider, startCount, newStartCount, value, last, splittheme, splitThemeClass, spliticon,\n
\t\t\taltButtonClass, dividerTheme, li,\n
\t\t\to = this.options,\n
\t\t\t$list = this.element,\n
\t\t\tol = !!$.nodeName( $list[ 0 ], "ol" ),\n
\t\t\tstart = $list.attr( "start" ),\n
\t\t\titemClassDict = {},\n
\t\t\tcountBubbles = $list.find( ".ui-li-count" ),\n
\t\t\tcountTheme = getAttr( $list[ 0 ], "counttheme" ) || this.options.countTheme,\n
\t\t\tcountThemeClass = countTheme ? "ui-body-" + countTheme : "ui-body-inherit";\n
\n
\t\tif ( o.theme ) {\n
\t\t\t$list.addClass( "ui-group-theme-" + o.theme );\n
\t\t}\n
\n
\t\t// Check if a start attribute has been set while taking a value of 0 into account\n
\t\tif ( ol && ( start || start === 0 ) ) {\n
\t\t\tstartCount = parseInt( start, 10 ) - 1;\n
\t\t\t$list.css( "counter-reset", "listnumbering " + startCount );\n
\t\t}\n
\n
\t\tthis._beforeListviewRefresh();\n
\n
\t\tli = this._getChildrenByTagName( $list[ 0 ], "li", "LI" );\n
\n
\t\tfor ( pos = 0, numli = li.length; pos < numli; pos++ ) {\n
\t\t\titem = li.eq( pos );\n
\t\t\titemClass = "";\n
\n
\t\t\tif ( create || item[ 0 ].className.search( /\\bui-li-static\\b|\\bui-li-divider\\b/ ) < 0 ) {\n
\t\t\t\ta = this._getChildrenByTagName( item[ 0 ], "a", "A" );\n
\t\t\t\tisDivider = ( getAttr( item[ 0 ], "role" ) === "list-divider" );\n
\t\t\t\tvalue = item.attr( "value" );\n
\t\t\t\titemTheme = getAttr( item[ 0 ], "theme" );\n
\n
\t\t\t\tif ( a.length && a[ 0 ].className.search( /\\bui-btn\\b/ ) < 0 && !isDivider ) {\n
\t\t\t\t\titemIcon = getAttr( item[ 0 ], "icon" );\n
\t\t\t\t\ticon = ( itemIcon === false ) ? false : ( itemIcon || o.icon );\n
\n
\t\t\t\t\t// TODO: Remove in 1.5 together with links.js (links.js / .ui-link deprecated in 1.4)\n
\t\t\t\t\ta.removeClass( "ui-link" );\n
\n
\t\t\t\t\tbuttonClass = "ui-btn";\n
\n
\t\t\t\t\tif ( itemTheme ) {\n
\t\t\t\t\t\tbuttonClass += " ui-btn-" + itemTheme;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( a.length > 1 ) {\n
\t\t\t\t\t\titemClass = "ui-li-has-alt";\n
\n
\t\t\t\t\t\tlast = a.last();\n
\t\t\t\t\t\tsplittheme = getAttr( last[ 0 ], "theme" ) || o.splitTheme || getAttr( item[ 0 ], "theme", true );\n
\t\t\t\t\t\tsplitThemeClass = splittheme ? " ui-btn-" + splittheme : "";\n
\t\t\t\t\t\tspliticon = getAttr( last[ 0 ], "icon" ) || getAttr( item[ 0 ], "icon" ) || o.splitIcon;\n
\t\t\t\t\t\taltButtonClass = "ui-btn ui-btn-icon-notext ui-icon-" + spliticon + splitThemeClass;\n
\n
\t\t\t\t\t\tlast\n
\t\t\t\t\t\t\t.attr( "title", $.trim( last.getEncodedText() ) )\n
\t\t\t\t\t\t\t.addClass( altButtonClass )\n
\t\t\t\t\t\t\t.empty();\n
\n
\t\t\t\t\t\t// Reduce to the first anchor, because only the first gets the buttonClass\n
\t\t\t\t\t\ta = a.first();\n
\t\t\t\t\t} else if ( icon ) {\n
\t\t\t\t\t\tbuttonClass += " ui-btn-icon-right ui-icon-" + icon;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Apply buttonClass to the (first) anchor\n
\t\t\t\t\ta.addClass( buttonClass );\n
\t\t\t\t} else if ( isDivider ) {\n
\t\t\t\t\tdividerTheme = ( getAttr( item[ 0 ], "theme" ) || o.dividerTheme || o.theme );\n
\n
\t\t\t\t\titemClass = "ui-li-divider ui-bar-" + ( dividerTheme ? dividerTheme : "inherit" );\n
\n
\t\t\t\t\titem.attr( "role", "heading" );\n
\t\t\t\t} else if ( a.length <= 0 ) {\n
\t\t\t\t\titemClass = "ui-li-static ui-body-" + ( itemTheme ? itemTheme : "inherit" );\n
\t\t\t\t}\n
\t\t\t\tif ( ol && value ) {\n
\t\t\t\t\tnewStartCount = parseInt( value , 10 ) - 1;\n
\n
\t\t\t\t\titem.css( "counter-reset", "listnumbering " + newStartCount );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Instead of setting item class directly on the list item\n
\t\t\t// at this point in time, push the item into a dictionary\n
\t\t\t// that tells us what class to set on it so we can do this after this\n
\t\t\t// processing loop is finished.\n
\n
\t\t\tif ( !itemClassDict[ itemClass ] ) {\n
\t\t\t\titemClassDict[ itemClass ] = [];\n
\t\t\t}\n
\n
\t\t\titemClassDict[ itemClass ].push( item[ 0 ] );\n
\t\t}\n
\n
\t\t// Set the appropriate listview item classes on each list item.\n
\t\t// The main reason we didn\'t do this\n
\t\t// in the for-loop above is because we can eliminate per-item function overhead\n
\t\t// by calling addClass() and children() once or twice afterwards. This\n
\t\t// can give us a significant boost on platforms like WP7.5.\n
\n
\t\tfor ( itemClass in itemClassDict ) {\n
\t\t\t$( itemClassDict[ itemClass ] ).addClass( itemClass );\n
\t\t}\n
\n
\t\tcountBubbles.each( function() {\n
\t\t\t$( this ).closest( "li" ).addClass( "ui-li-has-count" );\n
\t\t});\n
\t\tif ( countThemeClass ) {\n
\t\t\tcountBubbles.not( "[class*=\'ui-body-\']" ).addClass( countThemeClass );\n
\t\t}\n
\n
\t\t// Deprecated in 1.4. From 1.5 you have to add class ui-li-has-thumb or ui-li-has-icon to the LI.\n
\t\tthis._addThumbClasses( li );\n
\t\tthis._addThumbClasses( li.find( ".ui-btn" ) );\n
\n
\t\tthis._afterListviewRefresh();\n
\n
\t\tthis._addFirstLastClasses( li, this._getVisibles( li, create ), create );\n
\t}\n
}, $.mobile.behaviors.addFirstLastClasses ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
function defaultAutodividersSelector( elt ) {\n
\t// look for the text in the given element\n
\tvar text = $.trim( elt.text() ) || null;\n
\n
\tif ( !text ) {\n
\t\treturn null;\n
\t}\n
\n
\t// create the text for the divider (first uppercased letter)\n
\ttext = text.slice( 0, 1 ).toUpperCase();\n
\n
\treturn text;\n
}\n
\n
$.widget( "mobile.listview", $.mobile.listview, {\n
\toptions: {\n
\t\tautodividers: false,\n
\t\tautodividersSelector: defaultAutodividersSelector\n
\t},\n
\n
\t_beforeListviewRefresh: function() {\n
\t\tif ( this.options.autodividers ) {\n
\t\t\tthis._replaceDividers();\n
\t\t\tthis._superApply( arguments );\n
\t\t}\n
\t},\n
\n
\t_replaceDividers: function() {\n
\t\tvar i, lis, li, dividerText,\n
\t\t\tlastDividerText = null,\n
\t\t\tlist = this.element,\n
\t\t\tdivider;\n
\n
\t\tlist.children( "li:jqmData(role=\'list-divider\')" ).remove();\n
\n
\t\tlis = list.children( "li" );\n
\n
\t\tfor ( i = 0; i < lis.length ; i++ ) {\n
\t\t\tli = lis[ i ];\n
\t\t\tdividerText = this.options.autodividersSelector( $( li ) );\n
\n
\t\t\tif ( dividerText && lastDividerText !== dividerText ) {\n
\t\t\t\tdivider = document.createElement( "li" );\n
\t\t\t\tdivider.appendChild( document.createTextNode( dividerText ) );\n
\t\t\t\tdivider.setAttribute( "data-" + $.mobile.ns + "role", "list-divider" );\n
\t\t\t\tli.parentNode.insertBefore( divider, li );\n
\t\t\t}\n
\n
\t\t\tlastDividerText = dividerText;\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
var rdivider = /(^|\\s)ui-li-divider($|\\s)/,\n
\trhidden = /(^|\\s)ui-screen-hidden($|\\s)/;\n
\n
$.widget( "mobile.listview", $.mobile.listview, {\n
\toptions: {\n
\t\thideDividers: false\n
\t},\n
\n
\t_afterListviewRefresh: function() {\n
\t\tvar items, idx, item, hideDivider = true;\n
\n
\t\tthis._superApply( arguments );\n
\n
\t\tif ( this.options.hideDividers ) {\n
\t\t\titems = this._getChildrenByTagName( this.element[ 0 ], "li", "LI" );\n
\t\t\tfor ( idx = items.length - 1 ; idx > -1 ; idx-- ) {\n
\t\t\t\titem = items[ idx ];\n
\t\t\t\tif ( item.className.match( rdivider ) ) {\n
\t\t\t\t\tif ( hideDivider ) {\n
\t\t\t\t\t\titem.className = item.className + " ui-screen-hidden";\n
\t\t\t\t\t}\n
\t\t\t\t\thideDivider = true;\n
\t\t\t\t} else {\n
\t\t\t\t\tif ( !item.className.match( rhidden ) ) {\n
\t\t\t\t\t\thideDivider = false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.mobile.nojs = function( target ) {\n
\t$( ":jqmData(role=\'nojs\')", target ).addClass( "ui-nojs" );\n
};\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.mobile.behaviors.formReset = {\n
\t_handleFormReset: function() {\n
\t\tthis._on( this.element.closest( "form" ), {\n
\t\t\treset: function() {\n
\t\t\t\tthis._delay( "_reset" );\n
\t\t\t}\n
\t\t});\n
\t}\n
};\n
\n
})( jQuery );\n
\n
/*\n
* "checkboxradio" plugin\n
*/\n
\n
(function( $, undefined ) {\n
\n
var escapeId = $.mobile.path.hashToSelector;\n
\n
$.widget( "mobile.checkboxradio", $.extend( {\n
\n
\tinitSelector: "input:not( :jqmData(role=\'flipswitch\' ) )[type=\'checkbox\'],input[type=\'radio\']:not( :jqmData(role=\'flipswitch\' ))",\n
\n
\toptions: {\n
\t\ttheme: "inherit",\n
\n
\t\t// Deprecated as of 1.5.0\n
\t\tmini: false,\n
\t\twrapperClass: null,\n
\t\tenhanced: false,\n
\t\ticonpos: "left"\n
\n
\t},\n
\t_create: function() {\n
\t\tvar input = this.element,\n
\t\t\to = this.options,\n
\t\t\tinheritAttr = function( input, dataAttr ) {\n
\t\t\t\treturn input.jqmData( dataAttr ) ||\n
\t\t\t\t\tinput.closest( "form, fieldset" ).jqmData( dataAttr );\n
\t\t\t},\n
\t\t\tlabel = this.options.enhanced ?\n
\t\t\t\t{\n
\t\t\t\t\telement: this.element.siblings( "label" ),\n
\t\t\t\t\tisParent: false\n
\t\t\t\t} :\n
\t\t\t\tthis._findLabel(),\n
\t\t\tinputtype = input[0].type,\n
\t\t\tcheckedClass = "ui-" + inputtype + "-on",\n
\t\t\tuncheckedClass = "ui-" + inputtype + "-off";\n
\n
\t\tif ( inputtype !== "checkbox" && inputtype !== "radio" ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( this.element[0].disabled ) {\n
\t\t\tthis.options.disabled = true;\n
\t\t}\n
\n
\t\to.iconpos = inheritAttr( input, "iconpos" ) ||\n
\t\t\tlabel.element.attr( "data-" + $.mobile.ns + "iconpos" ) || o.iconpos,\n
\n
\t\t// Deprecated as of 1.5.0\n
\t\t// Establish options\n
\t\to.mini = inheritAttr( input, "mini" ) || o.mini;\n
\n
\t\t// Expose for other methods\n
\t\t$.extend( this, {\n
\t\t\tinput: input,\n
\t\t\tlabel: label.element,\n
\t\t\tlabelIsParent: label.isParent,\n
\t\t\tinputtype: inputtype,\n
\t\t\tcheckedClass: checkedClass,\n
\t\t\tuncheckedClass: uncheckedClass\n
\t\t});\n
\n
\t\tif ( !this.options.enhanced ) {\n
\t\t\tthis._enhance();\n
\t\t}\n
\n
\t\tthis._on( label.element, {\n
\t\t\tvmouseover: "_handleLabelVMouseOver",\n
\t\t\tvclick: "_handleLabelVClick"\n
\t\t});\n
\n
\t\tthis._on( input, {\n
\t\t\tvmousedown: "_cacheVals",\n
\t\t\tvclick: "_handleInputVClick",\n
\t\t\tfocus: "_handleInputFocus",\n
\t\t\tblur: "_handleInputBlur"\n
\t\t});\n
\n
\t\tthis._handleFormReset();\n
\t\tthis.refresh();\n
\t},\n
\n
\t_findLabel: function() {\n
\t\tvar parentLabel, label, isParent,\n
\t\t\tinput = this.element,\n
\t\t\tlabelsList = input[ 0 ].labels;\n
\n
\t\tif( labelsList && labelsList.length > 0 ) {\n
\t\t\tlabel = $( labelsList[ 0 ] );\n
\t\t\tisParent = $.contains( label[ 0 ], input[ 0 ] );\n
\t\t} else {\n
\t\t\tparentLabel = input.closest( "label" );\n
\t\t\tisParent = ( parentLabel.length > 0 );\n
\n
\t\t\t// NOTE: Windows Phone could not find the label through a selector\n
\t\t\t// filter works though.\n
\t\t\tlabel = isParent ? parentLabel :\n
\t\t\t\t$( this.document[ 0 ].getElementsByTagName( "label" ) )\n
\t\t\t\t\t.filter( "[for=\'" + escapeId( input[ 0 ].id ) + "\']" )\n
\t\t\t\t\t.first();\n
\t\t}\n
\n
\t\treturn {\n
\t\t\telement: label,\n
\t\t\tisParent: isParent\n
\t\t};\n
\t},\n
\n
\t_enhance: function() {\n
\t\tthis.label.addClass( "ui-btn ui-corner-all");\n
\n
\t\tif ( this.labelIsParent ) {\n
\t\t\tthis.input.add( this.label ).wrapAll( this._wrapper() );\n
\t\t} else {\n
\t\t\t//this.element.replaceWith( this.input.add( this.label ).wrapAll( this._wrapper() ) );\n
\t\t\tthis.element.wrap( this._wrapper() );\n
\t\t\tthis.element.parent().prepend( this.label );\n
\t\t}\n
\n
\t\t// Wrap the input + label in a div\n
\n
\t\tthis._setOptions({\n
\t\t\t"theme": this.options.theme,\n
\t\t\t"iconpos": this.options.iconpos,\n
\t\t\t"wrapperClass": this.options.wrapperClass,\n
\n
\t\t\t// Deprecated as of 1.5.0\n
\t\t\t"mini": this.options.mini\n
\t\t});\n
\n
\t},\n
\n
\t_wrapper: function() {\n
\t\treturn $( "<div class=\'ui-" + this.inputtype +\n
\t\t\t( this.options.disabled ? " ui-state-disabled" : "" ) + "\' ></div>" );\n
\t},\n
\n
\t_handleInputFocus: function() {\n
\t\tthis.label.addClass( $.mobile.focusClass );\n
\t},\n
\n
\t_handleInputBlur: function() {\n
\t\tthis.label.removeClass( $.mobile.focusClass );\n
\t},\n
\n
\t_handleInputVClick: function() {\n
\t\t// Adds checked attribute to checked input when keyboard is used\n
\t\tthis.element.prop( "checked", this.element.is( ":checked" ) );\n
\t\tthis._getInputSet().not( this.element ).prop( "checked", false );\n
\t\tthis._updateAll( true );\n
\t},\n
\n
\t_handleLabelVMouseOver: function( event ) {\n
\t\tif ( this.label.parent().hasClass( "ui-state-disabled" ) ) {\n
\t\t\tevent.stopPropagation();\n
\t\t}\n
\t},\n
\n
\t_handleLabelVClick: function( event ) {\n
\t\tvar input = this.element;\n
\n
\t\tif ( input.is( ":disabled" ) ) {\n
\t\t\tevent.preventDefault();\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis._cacheVals();\n
\n
\t\tinput.prop( "checked", this.inputtype === "radio" && true || !input.prop( "checked" ) );\n
\n
\t\t// trigger click handler\'s bound directly to the input as a substitute for\n
\t\t// how label clicks behave normally in the browsers\n
\t\t// TODO: it would be nice to let the browser\'s handle the clicks and pass them\n
\t\t//       through to the associate input. we can swallow that click at the parent\n
\t\t//       wrapper element level\n
\t\tinput.triggerHandler( "click" );\n
\n
\t\t// Input set for common radio buttons will contain all the radio\n
\t\t// buttons, but will not for checkboxes. clearing the checked status\n
\t\t// of other radios ensures the active button state is applied properly\n
\t\tthis._getInputSet().not( input ).prop( "checked", false );\n
\n
\t\tthis._updateAll();\n
\t\treturn false;\n
\t},\n
\n
\t_cacheVals: function() {\n
\t\tthis._getInputSet().each( function() {\n
\t\t\t$( this ).attr("data-" + $.mobile.ns + "cacheVal", this.checked );\n
\t\t});\n
\t},\n
\n
\t// Returns those radio buttons that are supposed to be in the same group as\n
\t// this radio button. In the case of a checkbox or a radio lacking a name\n
\t// attribute, it returns this.element.\n
\t_getInputSet: function() {\n
\t\tvar selector, formId,\n
\t\t\tradio = this.element[ 0 ],\n
\t\t\tname = radio.name,\n
\t\t\tform = radio.form,\n
\t\t\tdoc = this.element.parents().last().get( 0 ),\n
\n
\t\t\t// A radio is always a member of its own group\n
\t\t\tradios = this.element;\n
\n
\t\t// Only start running selectors if this is an attached radio button with a name\n
\t\tif ( name && this.inputtype === "radio" && doc ) {\n
\t\t\tselector = "input[type=\'radio\'][name=\'" + escapeId( name ) + "\']";\n
\n
\t\t\t// If we\'re inside a form\n
\t\t\tif ( form ) {\n
\t\t\t\tformId = form.getAttribute( "id" );\n
\n
\t\t\t\t// If the form has an ID, collect radios scattered throught the document which\n
\t\t\t\t// nevertheless are part of the form by way of the value of their form attribute\n
\t\t\t\tif ( formId ) {\n
\t\t\t\t\tradios = $( selector + "[form=\'" + escapeId( formId ) + "\']", doc );\n
\t\t\t\t}\n
\n
\t\t\t\t// Also add to those the radios in the form itself\n
\t\t\t\tradios = $( form ).find( selector ).filter( function() {\n
\n
\t\t\t\t\t// Some radios inside the form may belong to some other form by virtue of\n
\t\t\t\t\t// having a form attribute defined on them, so we must filter them out here\n
\t\t\t\t\treturn ( this.form === form );\n
\t\t\t\t}).add( radios );\n
\n
\t\t\t// If we\'re outside a form\n
\t\t\t} else {\n
\n
\t\t\t\t// Collect all those radios which are also outside of a form and match our name\n
\t\t\t\tradios = $( selector, doc ).filter( function() {\n
\t\t\t\t\treturn !this.form;\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\t\treturn radios;\n
\t},\n
\n
\t_updateAll: function( changeTriggered ) {\n
\t\tvar self = this;\n
\n
\t\tthis._getInputSet().each( function() {\n
\t\t\tvar $this = $( this );\n
\n
\t\t\tif ( ( this.checked || self.inputtype === "checkbox" ) && !changeTriggered ) {\n
\t\t\t\t$this.trigger( "change" );\n
\t\t\t}\n
\t\t})\n
\t\t.checkboxradio( "refresh" );\n
\t},\n
\n
\t_reset: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\t// Is the widget supposed to display an icon?\n
\t_hasIcon: function() {\n
\t\tvar controlgroup, controlgroupWidget,\n
\t\t\tcontrolgroupConstructor = $.mobile.controlgroup;\n
\n
\t\t// If the controlgroup widget is defined ...\n
\t\tif ( controlgroupConstructor ) {\n
\t\t\tcontrolgroup = this.element.closest(\n
\t\t\t\t":mobile-controlgroup," +\n
\t\t\t\tcontrolgroupConstructor.prototype.initSelector );\n
\n
\t\t\t// ... and the checkbox is in a controlgroup ...\n
\t\t\tif ( controlgroup.length > 0 ) {\n
\n
\t\t\t\t// ... look for a controlgroup widget instance, and ...\n
\t\t\t\tcontrolgroupWidget = $.data( controlgroup[ 0 ], "mobile-controlgroup" );\n
\n
\t\t\t\t// ... if found, decide based on the option value, ...\n
\t\t\t\treturn ( ( controlgroupWidget ? controlgroupWidget.options.type :\n
\n
\t\t\t\t\t// ... otherwise decide based on the "type" data attribute.\n
\t\t\t\t\tcontrolgroup.attr( "data-" + $.mobile.ns + "type" ) ) !== "horizontal" );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Normally, the widget displays an icon.\n
\t\treturn true;\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar isChecked = this.element[ 0 ].checked,\n
\t\t\tactive = $.mobile.activeBtnClass,\n
\t\t\ticonposClass = "ui-btn-icon-" + this.options.iconpos,\n
\t\t\taddClasses = [],\n
\t\t\tremoveClasses = [];\n
\n
\t\tif ( this._hasIcon() ) {\n
\t\t\tremoveClasses.push( active );\n
\t\t\taddClasses.push( iconposClass );\n
\t\t} else {\n
\t\t\tremoveClasses.push( iconposClass );\n
\t\t\t( isChecked ? addClasses : removeClasses ).push( active );\n
\t\t}\n
\n
\t\tif ( isChecked ) {\n
\t\t\taddClasses.push( this.checkedClass );\n
\t\t\tremoveClasses.push( this.uncheckedClass );\n
\t\t} else {\n
\t\t\taddClasses.push( this.uncheckedClass );\n
\t\t\tremoveClasses.push( this.checkedClass );\n
\t\t}\n
\n
\t\tthis.widget().toggleClass( "ui-state-disabled", this.element.prop( "disabled" ) );\n
\n
\t\tthis.label\n
\t\t\t.addClass( addClasses.join( " " ) )\n
\t\t\t.removeClass( removeClasses.join( " " ) );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.label.parent();\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar label = this.label,\n
\t\t\tcurrentOptions = this.options,\n
\t\t\touter = this.widget(),\n
\t\t\thasIcon = this._hasIcon();\n
\n
\t\tif ( options.disabled !== undefined ) {\n
\t\t\tthis.input.prop( "disabled", !!options.disabled );\n
\t\t\touter.toggleClass( "ui-state-disabled", !!options.disabled );\n
\t\t}\n
\n
\t\t// Deprecated as of 1.5.0\n
\t\tif ( options.mini !== undefined ) {\n
\t\t\touter.toggleClass( "ui-mini", !!options.mini );\n
\t\t}\n
\t\tif ( options.theme !== undefined ) {\n
\t\t\tlabel\n
\t\t\t\t.removeClass( "ui-btn-" + currentOptions.theme )\n
\t\t\t\t.addClass( "ui-btn-" + options.theme );\n
\t\t}\n
\t\tif ( options.wrapperClass !== undefined ) {\n
\t\t\touter\n
\t\t\t\t.removeClass( currentOptions.wrapperClass )\n
\t\t\t\t.addClass( options.wrapperClass );\n
\t\t}\n
\t\tif ( options.iconpos !== undefined && hasIcon ) {\n
\t\t\tlabel.removeClass( "ui-btn-icon-" + currentOptions.iconpos ).addClass( "ui-btn-icon-" + options.iconpos );\n
\t\t} else if ( !hasIcon ) {\n
\t\t\tlabel.removeClass( "ui-btn-icon-" + currentOptions.iconpos );\n
\t\t}\n
\t\tthis._super( options );\n
\t}\n
\n
}, $.mobile.behaviors.formReset ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.button", {\n
\n
\tinitSelector: "input[type=\'button\'], input[type=\'submit\'], input[type=\'reset\']",\n
\n
\toptions: {\n
\t\ttheme: null,\n
\t\ticon: null,\n
\t\ticonpos: "left",\n
\t\ticonshadow: false, /* TODO: Deprecated in 1.4, remove in 1.5. */\n
\t\tcorners: true,\n
\t\tshadow: true,\n
\t\tinline: null,\n
\t\tmini: null,\n
\t\twrapperClass: null,\n
\t\tenhanced: false\n
\t},\n
\n
\t_create: function() {\n
\n
\t\tif ( this.element.is( ":disabled" ) ) {\n
\t\t\tthis.options.disabled = true;\n
\t\t}\n
\n
\t\tif ( !this.options.enhanced ) {\n
\t\t\tthis._enhance();\n
\t\t}\n
\n
\t\t$.extend( this, {\n
\t\t\twrapper: this.element.parent()\n
\t\t});\n
\n
\t\tthis._on( {\n
\t\t\tfocus: function() {\n
\t\t\t\tthis.widget().addClass( $.mobile.focusClass );\n
\t\t\t},\n
\n
\t\t\tblur: function() {\n
\t\t\t\tthis.widget().removeClass( $.mobile.focusClass );\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis.refresh( true );\n
\t},\n
\n
\t_enhance: function() {\n
\t\tthis.element.wrap( this._button() );\n
\t},\n
\n
\t_button: function() {\n
\t\tvar options = this.options,\n
\t\t\ticonClasses = this._getIconClasses( this.options );\n
\n
\t\treturn $("<div class=\'ui-btn ui-input-btn" +\n
\t\t\t( options.wrapperClass ? " " + options.wrapperClass : "" ) +\n
\t\t\t( options.theme ? " ui-btn-" + options.theme : "" ) +\n
\t\t\t( options.corners ? " ui-corner-all" : "" ) +\n
\t\t\t( options.shadow ? " ui-shadow" : "" ) +\n
\t\t\t( options.inline ? " ui-btn-inline" : "" ) +\n
\t\t\t( options.mini ? " ui-mini" : "" ) +\n
\t\t\t( options.disabled ? " ui-state-disabled" : "" ) +\n
\t\t\t( iconClasses ? ( " " + iconClasses ) : "" ) +\n
\t\t\t"\' >" + this.element.val() + "</div>" );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.wrapper;\n
\t},\n
\n
\t_destroy: function() {\n
\t\t\tthis.element.insertBefore( this.wrapper );\n
\t\t\tthis.wrapper.remove();\n
\t},\n
\n
\t_getIconClasses: function( options ) {\n
\t\treturn ( options.icon ? ( "ui-icon-" + options.icon +\n
\t\t\t( options.iconshadow ? " ui-shadow-icon" : "" ) + /* TODO: Deprecated in 1.4, remove in 1.5. */\n
\t\t\t" ui-btn-icon-" + options.iconpos ) : "" );\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar outer = this.widget();\n
\n
\t\tif ( options.theme !== undefined ) {\n
\t\t\touter\n
\t\t\t\t.removeClass( this.options.theme )\n
\t\t\t\t.addClass( "ui-btn-" + options.theme );\n
\t\t}\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\touter.toggleClass( "ui-corner-all", options.corners );\n
\t\t}\n
\t\tif ( options.shadow !== undefined ) {\n
\t\t\touter.toggleClass( "ui-shadow", options.shadow );\n
\t\t}\n
\t\tif ( options.inline !== undefined ) {\n
\t\t\touter.toggleClass( "ui-btn-inline", options.inline );\n
\t\t}\n
\t\tif ( options.mini !== undefined ) {\n
\t\t\touter.toggleClass( "ui-mini", options.mini );\n
\t\t}\n
\t\tif ( options.disabled !== undefined ) {\n
\t\t\tthis.element.prop( "disabled", options.disabled );\n
\t\t\touter.toggleClass( "ui-state-disabled", options.disabled );\n
\t\t}\n
\n
\t\tif ( options.icon !== undefined ||\n
\t\t\t\toptions.iconshadow !== undefined || /* TODO: Deprecated in 1.4, remove in 1.5. */\n
\t\t\t\toptions.iconpos !== undefined ) {\n
\t\t\touter\n
\t\t\t\t.removeClass( this._getIconClasses( this.options ) )\n
\t\t\t\t.addClass( this._getIconClasses(\n
\t\t\t\t\t$.extend( {}, this.options, options ) ) );\n
\t\t}\n
\n
\t\tthis._super( options );\n
\t},\n
\n
\trefresh: function( create ) {\n
\t\tvar originalElement,\n
\t\t\tisDisabled = this.element.prop( "disabled" );\n
\n
\t\tif ( this.options.icon && this.options.iconpos === "notext" && this.element.attr( "title" ) ) {\n
\t\t\tthis.element.attr( "title", this.element.val() );\n
\t\t}\n
\t\tif ( !create ) {\n
\t\t\toriginalElement = this.element.detach();\n
\t\t\t$( this.wrapper ).text( this.element.val() ).append( originalElement );\n
\t\t}\n
\t\tif ( this.options.disabled !== isDisabled ) {\n
\t\t\tthis._setOptions({ disabled: isDisabled });\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $ ) {\n
\tvar\tmeta = $( "meta[name=viewport]" ),\n
\t\tinitialContent = meta.attr( "content" ),\n
\t\tdisabledZoom = initialContent + ",maximum-scale=1, user-scalable=no",\n
\t\tenabledZoom = initialContent + ",maximum-scale=10, user-scalable=yes",\n
\t\tdisabledInitially = /(user-scalable[\\s]*=[\\s]*no)|(maximum-scale[\\s]*=[\\s]*1)[$,\\s]/.test( initialContent );\n
\n
\t$.mobile.zoom = $.extend( {}, {\n
\t\tenabled: !disabledInitially,\n
\t\tlocked: false,\n
\t\tdisable: function( lock ) {\n
\t\t\tif ( !disabledInitially && !$.mobile.zoom.locked ) {\n
\t\t\t\tmeta.attr( "content", disabledZoom );\n
\t\t\t\t$.mobile.zoom.enabled = false;\n
\t\t\t\t$.mobile.zoom.locked = lock || false;\n
\t\t\t}\n
\t\t},\n
\t\tenable: function( unlock ) {\n
\t\t\tif ( !disabledInitially && ( !$.mobile.zoom.locked || unlock === true ) ) {\n
\t\t\t\tmeta.attr( "content", enabledZoom );\n
\t\t\t\t$.mobile.zoom.enabled = true;\n
\t\t\t\t$.mobile.zoom.locked = false;\n
\t\t\t}\n
\t\t},\n
\t\trestore: function() {\n
\t\t\tif ( !disabledInitially ) {\n
\t\t\t\tmeta.attr( "content", initialContent );\n
\t\t\t\t$.mobile.zoom.enabled = true;\n
\t\t\t}\n
\t\t}\n
\t});\n
\n
}( jQuery ));\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.textinput", {\n
\tinitSelector: "input[type=\'text\']," +\n
\t\t"input[type=\'search\']," +\n
\t\t":jqmData(type=\'search\')," +\n
\t\t"input[type=\'number\']," +\n
\t\t":jqmData(type=\'number\')," +\n
\t\t"input[type=\'password\']," +\n
\t\t"input[type=\'email\']," +\n
\t\t"input[type=\'url\']," +\n
\t\t"input[type=\'tel\']," +\n
\t\t"textarea," +\n
\t\t"input[type=\'time\']," +\n
\t\t"input[type=\'date\']," +\n
\t\t"input[type=\'month\']," +\n
\t\t"input[type=\'week\']," +\n
\t\t"input[type=\'datetime\']," +\n
\t\t"input[type=\'datetime-local\']," +\n
\t\t"input[type=\'color\']," +\n
\t\t"input:not([type])," +\n
\t\t"input[type=\'file\']",\n
\n
\toptions: {\n
\t\ttheme: null,\n
\t\tcorners: true,\n
\t\tmini: false,\n
\t\t// This option defaults to true on iOS devices.\n
\t\tpreventFocusZoom: /iPhone|iPad|iPod/.test( navigator.platform ) && navigator.userAgent.indexOf( "AppleWebKit" ) > -1,\n
\t\twrapperClass: "",\n
\t\tenhanced: false\n
\t},\n
\n
\t_create: function() {\n
\n
\t\tvar options = this.options,\n
\t\t\tisSearch = this.element.is( "[type=\'search\'], :jqmData(type=\'search\')" ),\n
\t\t\tisTextarea = this.element[ 0 ].tagName === "TEXTAREA",\n
\t\t\tisRange = this.element.is( "[data-" + ( $.mobile.ns || "" ) + "type=\'range\']" ),\n
\t\t\tinputNeedsWrap = ( (this.element.is( "input" ) ||\n
\t\t\t\tthis.element.is( "[data-" + ( $.mobile.ns || "" ) + "type=\'search\']" ) ) &&\n
\t\t\t\t\t!isRange );\n
\n
\t\tif ( this.element.prop( "disabled" ) ) {\n
\t\t\toptions.disabled = true;\n
\t\t}\n
\n
\t\t$.extend( this, {\n
\t\t\tclasses: this._classesFromOptions(),\n
\t\t\tisSearch: isSearch,\n
\t\t\tisTextarea: isTextarea,\n
\t\t\tisRange: isRange,\n
\t\t\tinputNeedsWrap: inputNeedsWrap\n
\t\t});\n
\n
\t\tthis._autoCorrect();\n
\n
\t\tif ( !options.enhanced ) {\n
\t\t\tthis._enhance();\n
\t\t}\n
\n
\t\tthis._on( {\n
\t\t\t"focus": "_handleFocus",\n
\t\t\t"blur": "_handleBlur"\n
\t\t});\n
\n
\t},\n
\n
\trefresh: function() {\n
\t\tthis.setOptions({\n
\t\t\t"disabled" : this.element.is( ":disabled" )\n
\t\t});\n
\t},\n
\n
\t_enhance: function() {\n
\t\tvar elementClasses = [];\n
\n
\t\tif ( this.isTextarea ) {\n
\t\t\telementClasses.push( "ui-input-text" );\n
\t\t}\n
\n
\t\tif ( this.isTextarea || this.isRange ) {\n
\t\t\telementClasses.push( "ui-shadow-inset" );\n
\t\t}\n
\n
\t\t//"search" and "text" input widgets\n
\t\tif ( this.inputNeedsWrap ) {\n
\t\t\tthis.element.wrap( this._wrap() );\n
\t\t} else {\n
\t\t\telementClasses = elementClasses.concat( this.classes );\n
\t\t}\n
\n
\t\tthis.element.addClass( elementClasses.join( " " ) );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn ( this.inputNeedsWrap ) ? this.element.parent() : this.element;\n
\t},\n
\n
\t_classesFromOptions: function() {\n
\t\tvar options = this.options,\n
\t\t\tclasses = [];\n
\n
\t\tclasses.push( "ui-body-" + ( ( options.theme === null ) ? "inherit" : options.theme ) );\n
\t\tif ( options.corners ) {\n
\t\t\tclasses.push( "ui-corner-all" );\n
\t\t}\n
\t\tif ( options.mini ) {\n
\t\t\tclasses.push( "ui-mini" );\n
\t\t}\n
\t\tif ( options.disabled ) {\n
\t\t\tclasses.push( "ui-state-disabled" );\n
\t\t}\n
\t\tif ( options.wrapperClass ) {\n
\t\t\tclasses.push( options.wrapperClass );\n
\t\t}\n
\n
\t\treturn classes;\n
\t},\n
\n
\t_wrap: function() {\n
\t\treturn $( "<div class=\'" +\n
\t\t\t( this.isSearch ? "ui-input-search " : "ui-input-text " ) +\n
\t\t\tthis.classes.join( " " ) + " " +\n
\t\t\t"ui-shadow-inset\'></div>" );\n
\t},\n
\n
\t_autoCorrect: function() {\n
\t\t// XXX: Temporary workaround for issue 785 (Apple bug 8910589).\n
\t\t//      Turn off autocorrect and autocomplete on non-iOS 5 devices\n
\t\t//      since the popup they use can\'t be dismissed by the user. Note\n
\t\t//      that we test for the presence of the feature by looking for\n
\t\t//      the autocorrect property on the input element. We currently\n
\t\t//      have no test for iOS 5 or newer so we\'re temporarily using\n
\t\t//      the touchOverflow support flag for jQM 1.0. Yes, I feel dirty.\n
\t\t//      - jblas\n
\t\tif ( typeof this.element[0].autocorrect !== "undefined" &&\n
\t\t\t!$.support.touchOverflow ) {\n
\n
\t\t\t// Set the attribute instead of the property just in case there\n
\t\t\t// is code that attempts to make modifications via HTML.\n
\t\t\tthis.element[0].setAttribute( "autocorrect", "off" );\n
\t\t\tthis.element[0].setAttribute( "autocomplete", "off" );\n
\t\t}\n
\t},\n
\n
\t_handleBlur: function() {\n
\t\tthis.widget().removeClass( $.mobile.focusClass );\n
\t\tif ( this.options.preventFocusZoom ) {\n
\t\t\t$.mobile.zoom.enable( true );\n
\t\t}\n
\t},\n
\n
\t_handleFocus: function() {\n
\t\t// In many situations, iOS will zoom into the input upon tap, this\n
\t\t// prevents that from happening\n
\t\tif ( this.options.preventFocusZoom ) {\n
\t\t\t$.mobile.zoom.disable( true );\n
\t\t}\n
\t\tthis.widget().addClass( $.mobile.focusClass );\n
\t},\n
\n
\t_setOptions: function ( options ) {\n
\t\tvar outer = this.widget();\n
\n
\t\tthis._super( options );\n
\n
\t\tif ( !( options.disabled === undefined &&\n
\t\t\toptions.mini === undefined &&\n
\t\t\toptions.corners === undefined &&\n
\t\t\toptions.theme === undefined &&\n
\t\t\toptions.wrapperClass === undefined ) ) {\n
\n
\t\t\touter.removeClass( this.classes.join( " " ) );\n
\t\t\tthis.classes = this._classesFromOptions();\n
\t\t\touter.addClass( this.classes.join( " " ) );\n
\t\t}\n
\n
\t\tif ( options.disabled !== undefined ) {\n
\t\t\tthis.element.prop( "disabled", !!options.disabled );\n
\t\t}\n
\t},\n
\n
\t_destroy: function() {\n
\t\tif ( this.options.enhanced ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this.inputNeedsWrap ) {\n
\t\t\tthis.element.unwrap();\n
\t\t}\n
\t\tthis.element.removeClass( "ui-input-text " + this.classes.join( " " ) );\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.slider", $.extend( {\n
\tinitSelector: "input[type=\'range\'], :jqmData(type=\'range\'), :jqmData(role=\'slider\')",\n
\n
\twidgetEventPrefix: "slide",\n
\n
\toptions: {\n
\t\ttheme: null,\n
\t\ttrackTheme: null,\n
\t\tcorners: true,\n
\t\tmini: false,\n
\t\thighlight: false\n
\t},\n
\n
\t_create: function() {\n
\n
\t\t// TODO: Each of these should have comments explain what they\'re for\n
\t\tvar self = this,\n
\t\t\tcontrol = this.element,\n
\t\t\ttrackTheme = this.options.trackTheme || $.mobile.getAttribute( control[ 0 ], "theme" ),\n
\t\t\ttrackThemeClass = trackTheme ? " ui-bar-" + trackTheme : " ui-bar-inherit",\n
\t\t\tcornerClass = ( this.options.corners || control.jqmData( "corners" ) ) ? " ui-corner-all" : "",\n
\t\t\tminiClass = ( this.options.mini || control.jqmData( "mini" ) ) ? " ui-mini" : "",\n
\t\t\tcType = control[ 0 ].nodeName.toLowerCase(),\n
\t\t\tisToggleSwitch = ( cType === "select" ),\n
\t\t\tisRangeslider = control.parent().is( ":jqmData(role=\'rangeslider\')" ),\n
\t\t\tselectClass = ( isToggleSwitch ) ? "ui-slider-switch" : "",\n
\t\t\tcontrolID = control.attr( "id" ),\n
\t\t\t$label = $( "[for=\'" + controlID + "\']" ),\n
\t\t\tlabelID = $label.attr( "id" ) || controlID + "-label",\n
\t\t\tmin = !isToggleSwitch ? parseFloat( control.attr( "min" ) ) : 0,\n
\t\t\tmax =  !isToggleSwitch ? parseFloat( control.attr( "max" ) ) : control.find( "option" ).length-1,\n
\t\t\tstep = window.parseFloat( control.attr( "step" ) || 1 ),\n
\t\t\tdomHandle = document.createElement( "a" ),\n
\t\t\thandle = $( domHandle ),\n
\t\t\tdomSlider = document.createElement( "div" ),\n
\t\t\tslider = $( domSlider ),\n
\t\t\tvaluebg = this.options.highlight && !isToggleSwitch ? (function() {\n
\t\t\t\tvar bg = document.createElement( "div" );\n
\t\t\t\tbg.className = "ui-slider-bg " + $.mobile.activeBtnClass;\n
\t\t\t\treturn $( bg ).prependTo( slider );\n
\t\t\t})() : false,\n
\t\t\toptions,\n
\t\t\twrapper,\n
\t\t\tj, length,\n
\t\t\ti, optionsCount, origTabIndex,\n
\t\t\tside, activeClass, sliderImg;\n
\n
\t\t$label.attr( "id", labelID );\n
\t\tthis.isToggleSwitch = isToggleSwitch;\n
\n
\t\tdomHandle.setAttribute( "href", "#" );\n
\t\tdomSlider.setAttribute( "role", "application" );\n
\t\tdomSlider.className = [ this.isToggleSwitch ? "ui-slider ui-slider-track ui-shadow-inset " : "ui-slider-track ui-shadow-inset ", selectClass, trackThemeClass, cornerClass, miniClass ].join( "" );\n
\t\tdomHandle.className = "ui-slider-handle";\n
\t\tdomSlider.appendChild( domHandle );\n
\n
\t\thandle.attr({\n
\t\t\t"role": "slider",\n
\t\t\t"aria-valuemin": min,\n
\t\t\t"aria-valuemax": max,\n
\t\t\t"aria-valuenow": this._value(),\n
\t\t\t"aria-valuetext": this._value(),\n
\t\t\t"title": this._value(),\n
\t\t\t"aria-labelledby": labelID\n
\t\t});\n
\n
\t\t$.extend( this, {\n
\t\t\tslider: slider,\n
\t\t\thandle: handle,\n
\t\t\tcontrol: control,\n
\t\t\ttype: cType,\n
\t\t\tstep: step,\n
\t\t\tmax: max,\n
\t\t\tmin: min,\n
\t\t\tvaluebg: valuebg,\n
\t\t\tisRangeslider: isRangeslider,\n
\t\t\tdragging: false,\n
\t\t\tbeforeStart: null,\n
\t\t\tuserModified: false,\n
\t\t\tmouseMoved: false\n
\t\t});\n
\n
\t\tif ( isToggleSwitch ) {\n
\t\t\t// TODO: restore original tabindex (if any) in a destroy method\n
\t\t\torigTabIndex = control.attr( "tabindex" );\n
\t\t\tif ( origTabIndex ) {\n
\t\t\t\thandle.attr( "tabindex", origTabIndex );\n
\t\t\t}\n
\t\t\tcontrol.attr( "tabindex", "-1" ).focus(function() {\n
\t\t\t\t$( this ).blur();\n
\t\t\t\thandle.focus();\n
\t\t\t});\n
\n
\t\t\twrapper = document.createElement( "div" );\n
\t\t\twrapper.className = "ui-slider-inneroffset";\n
\n
\t\t\tfor ( j = 0, length = domSlider.childNodes.length; j < length; j++ ) {\n
\t\t\t\twrapper.appendChild( domSlider.childNodes[j] );\n
\t\t\t}\n
\n
\t\t\tdomSlider.appendChild( wrapper );\n
\n
\t\t\t// slider.wrapInner( "<div class=\'ui-slider-inneroffset\'></div>" );\n
\n
\t\t\t// make the handle move with a smooth transition\n
\t\t\thandle.addClass( "ui-slider-handle-snapping" );\n
\n
\t\t\toptions = control.find( "option" );\n
\n
\t\t\tfor ( i = 0, optionsCount = options.length; i < optionsCount; i++ ) {\n
\t\t\t\tside = !i ? "b" : "a";\n
\t\t\t\tactiveClass = !i ? "" : " " + $.mobile.activeBtnClass;\n
\t\t\t\tsliderImg = document.createElement( "span" );\n
\n
\t\t\t\tsliderImg.className = [ "ui-slider-label ui-slider-label-", side, activeClass ].join( "" );\n
\t\t\t\tsliderImg.setAttribute( "role", "img" );\n
\t\t\t\tsliderImg.appendChild( document.createTextNode( options[i].innerHTML ) );\n
\t\t\t\t$( sliderImg ).prependTo( slider );\n
\t\t\t}\n
\n
\t\t\tself._labels = $( ".ui-slider-label", slider );\n
\n
\t\t}\n
\n
\t\t// monitor the input for updated values\n
\t\tcontrol.addClass( isToggleSwitch ? "ui-slider-switch" : "ui-slider-input" );\n
\n
\t\tthis._on( control, {\n
\t\t\t"change": "_controlChange",\n
\t\t\t"keyup": "_controlKeyup",\n
\t\t\t"blur": "_controlBlur",\n
\t\t\t"vmouseup": "_controlVMouseUp"\n
\t\t});\n
\n
\t\tslider.bind( "vmousedown", $.proxy( this._sliderVMouseDown, this ) )\n
\t\t\t.bind( "vclick", false );\n
\n
\t\t// We have to instantiate a new function object for the unbind to work properly\n
\t\t// since the method itself is defined in the prototype (causing it to unbind everything)\n
\t\tthis._on( document, { "vmousemove": "_preventDocumentDrag" });\n
\t\tthis._on( slider.add( document ), { "vmouseup": "_sliderVMouseUp" });\n
\n
\t\tslider.insertAfter( control );\n
\n
\t\t// wrap in a div for styling purposes\n
\t\tif ( !isToggleSwitch && !isRangeslider ) {\n
\t\t\twrapper = this.options.mini ? "<div class=\'ui-slider ui-mini\'>" : "<div class=\'ui-slider\'>";\n
\n
\t\t\tcontrol.add( slider ).wrapAll( wrapper );\n
\t\t}\n
\n
\t\t// bind the handle event callbacks and set the context to the widget instance\n
\t\tthis._on( this.handle, {\n
\t\t\t"vmousedown": "_handleVMouseDown",\n
\t\t\t"keydown": "_handleKeydown",\n
\t\t\t"keyup": "_handleKeyup"\n
\t\t});\n
\n
\t\tthis.handle.bind( "vclick", false );\n
\n
\t\tthis._handleFormReset();\n
\n
\t\tthis.refresh( undefined, undefined, true );\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tif ( options.theme !== undefined ) {\n
\t\t\tthis._setTheme( options.theme );\n
\t\t}\n
\n
\t\tif ( options.trackTheme !== undefined ) {\n
\t\t\tthis._setTrackTheme( options.trackTheme );\n
\t\t}\n
\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\tthis._setCorners( options.corners );\n
\t\t}\n
\n
\t\tif ( options.mini !== undefined ) {\n
\t\t\tthis._setMini( options.mini );\n
\t\t}\n
\n
\t\tif ( options.highlight !== undefined ) {\n
\t\t\tthis._setHighlight( options.highlight );\n
\t\t}\n
\n
\t\tif ( options.disabled !== undefined ) {\n
\t\t\tthis._setDisabled( options.disabled );\n
\t\t}\n
\t\tthis._super( options );\n
\t},\n
\n
\t_controlChange: function( event ) {\n
\t\t// if the user dragged the handle, the "change" event was triggered from inside refresh(); don\'t call refresh() again\n
\t\tif ( this._trigger( "controlchange", event ) === false ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tif ( !this.mouseMoved ) {\n
\t\t\tthis.refresh( this._value(), true );\n
\t\t}\n
\t},\n
\n
\t_controlKeyup: function(/* event */) { // necessary?\n
\t\tthis.refresh( this._value(), true, true );\n
\t},\n
\n
\t_controlBlur: function(/* event */) {\n
\t\tthis.refresh( this._value(), true );\n
\t},\n
\n
\t// it appears the clicking the up and down buttons in chrome on\n
\t// range/number inputs doesn\'t trigger a change until the field is\n
\t// blurred. Here we check thif the value has changed and refresh\n
\t_controlVMouseUp: function(/* event */) {\n
\t\tthis._checkedRefresh();\n
\t},\n
\n
\t// NOTE force focus on handle\n
\t_handleVMouseDown: function(/* event */) {\n
\t\tthis.handle.focus();\n
\t},\n
\n
\t_handleKeydown: function( event ) {\n
\t\tvar index = this._value();\n
\t\tif ( this.options.disabled ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// In all cases prevent the default and mark the handle as active\n
\t\tswitch ( event.keyCode ) {\n
\t\t\tcase $.mobile.keyCode.HOME:\n
\t\t\tcase $.mobile.keyCode.END:\n
\t\t\tcase $.mobile.keyCode.PAGE_UP:\n
\t\t\tcase $.mobile.keyCode.PAGE_DOWN:\n
\t\t\tcase $.mobile.keyCode.UP:\n
\t\t\tcase $.mobile.keyCode.RIGHT:\n
\t\t\tcase $.mobile.keyCode.DOWN:\n
\t\t\tcase $.mobile.keyCode.LEFT:\n
\t\t\t\tevent.preventDefault();\n
\n
\t\t\t\tif ( !this._keySliding ) {\n
\t\t\t\t\tthis._keySliding = true;\n
\t\t\t\t\tthis.handle.addClass( "ui-state-active" ); /* TODO: We don\'t use this class for styling. Do we need to add it? */\n
\t\t\t\t}\n
\n
\t\t\t\tbreak;\n
\t\t}\n
\n
\t\t// move the slider according to the keypress\n
\t\tswitch ( event.keyCode ) {\n
\t\t\tcase $.mobile.keyCode.HOME:\n
\t\t\t\tthis.refresh( this.min );\n
\t\t\t\tbreak;\n
\t\t\tcase $.mobile.keyCode.END:\n
\t\t\t\tthis.refresh( this.max );\n
\t\t\t\tbreak;\n
\t\t\tcase $.mobile.keyCode.PAGE_UP:\n
\t\t\tcase $.mobile.keyCode.UP:\n
\t\t\tcase $.mobile.keyCode.RIGHT:\n
\t\t\t\tthis.refresh( index + this.step );\n
\t\t\t\tbreak;\n
\t\t\tcase $.mobile.keyCode.PAGE_DOWN:\n
\t\t\tcase $.mobile.keyCode.DOWN:\n
\t\t\tcase $.mobile.keyCode.LEFT:\n
\t\t\t\tthis.refresh( index - this.step );\n
\t\t\t\tbreak;\n
\t\t}\n
\t}, // remove active mark\n
\n
\t_handleKeyup: function(/* event */) {\n
\t\tif ( this._keySliding ) {\n
\t\t\tthis._keySliding = false;\n
\t\t\tthis.handle.removeClass( "ui-state-active" ); /* See comment above. */\n
\t\t}\n
\t},\n
\n
\t_sliderVMouseDown: function( event ) {\n
\t\t// NOTE: we don\'t do this in refresh because we still want to\n
\t\t//       support programmatic alteration of disabled inputs\n
\t\tif ( this.options.disabled || !( event.which === 1 || event.which === 0 || event.which === undefined ) ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tif ( this._trigger( "beforestart", event ) === false ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tthis.dragging = true;\n
\t\tthis.userModified = false;\n
\t\tthis.mouseMoved = false;\n
\n
\t\tif ( this.isToggleSwitch ) {\n
\t\t\tthis.beforeStart = this.element[0].selectedIndex;\n
\t\t}\n
\n
\t\tthis.refresh( event );\n
\t\tthis._trigger( "start" );\n
\t\treturn false;\n
\t},\n
\n
\t_sliderVMouseUp: function() {\n
\t\tif ( this.dragging ) {\n
\t\t\tthis.dragging = false;\n
\n
\t\t\tif ( this.isToggleSwitch ) {\n
\t\t\t\t// make the handle move with a smooth transition\n
\t\t\t\tthis.handle.addClass( "ui-slider-handle-snapping" );\n
\n
\t\t\t\tif ( this.mouseMoved ) {\n
\t\t\t\t\t// this is a drag, change the value only if user dragged enough\n
\t\t\t\t\tif ( this.userModified ) {\n
\t\t\t\t\t\tthis.refresh( this.beforeStart === 0 ? 1 : 0 );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tthis.refresh( this.beforeStart );\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\t// this is just a click, change the value\n
\t\t\t\t\tthis.refresh( this.beforeStart === 0 ? 1 : 0 );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tthis.mouseMoved = false;\n
\t\t\tthis._trigger( "stop" );\n
\t\t\treturn false;\n
\t\t}\n
\t},\n
\n
\t_preventDocumentDrag: function( event ) {\n
\t\t\t// NOTE: we don\'t do this in refresh because we still want to\n
\t\t\t//       support programmatic alteration of disabled inputs\n
\t\t\tif ( this._trigger( "drag", event ) === false) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tif ( this.dragging && !this.options.disabled ) {\n
\n
\t\t\t\t// this.mouseMoved must be updated before refresh() because it will be used in the control "change" event\n
\t\t\t\tthis.mouseMoved = true;\n
\n
\t\t\t\tif ( this.isToggleSwitch ) {\n
\t\t\t\t\t// make the handle move in sync with the mouse\n
\t\t\t\t\tthis.handle.removeClass( "ui-slider-handle-snapping" );\n
\t\t\t\t}\n
\n
\t\t\t\tthis.refresh( event );\n
\n
\t\t\t\t// only after refresh() you can calculate this.userModified\n
\t\t\t\tthis.userModified = this.beforeStart !== this.element[0].selectedIndex;\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t},\n
\n
\t_checkedRefresh: function() {\n
\t\tif ( this.value !== this._value() ) {\n
\t\t\tthis.refresh( this._value() );\n
\t\t}\n
\t},\n
\n
\t_value: function() {\n
\t\treturn  this.isToggleSwitch ? this.element[0].selectedIndex : parseFloat( this.element.val() ) ;\n
\t},\n
\n
\t_reset: function() {\n
\t\tthis.refresh( undefined, false, true );\n
\t},\n
\n
\trefresh: function( val, isfromControl, preventInputUpdate ) {\n
\t\t// NOTE: we don\'t return here because we want to support programmatic\n
\t\t//       alteration of the input value, which should still update the slider\n
\n
\t\tvar self = this,\n
\t\t\tparentTheme = $.mobile.getAttribute( this.element[ 0 ], "theme" ),\n
\t\t\ttheme = this.options.theme || parentTheme,\n
\t\t\tthemeClass =  theme ? " ui-btn-" + theme : "",\n
\t\t\ttrackTheme = this.options.trackTheme || parentTheme,\n
\t\t\ttrackThemeClass = trackTheme ? " ui-bar-" + trackTheme : " ui-bar-inherit",\n
\t\t\tcornerClass = this.options.corners ? " ui-corner-all" : "",\n
\t\t\tminiClass = this.options.mini ? " ui-mini" : "",\n
\t\t\tleft, width, data, tol,\n
\t\t\tpxStep, percent,\n
\t\t\tcontrol, isInput, optionElements, min, max, step,\n
\t\t\tnewval, valModStep, alignValue, percentPerStep,\n
\t\t\thandlePercent, aPercent, bPercent,\n
\t\t\tvalueChanged;\n
\n
\t\tself.slider[0].className = [ this.isToggleSwitch ? "ui-slider ui-slider-switch ui-slider-track ui-shadow-inset" : "ui-slider-track ui-shadow-inset", trackThemeClass, cornerClass, miniClass ].join( "" );\n
\t\tif ( this.options.disabled || this.element.prop( "disabled" ) ) {\n
\t\t\tthis.disable();\n
\t\t}\n
\n
\t\t// set the stored value for comparison later\n
\t\tthis.value = this._value();\n
\t\tif ( this.options.highlight && !this.isToggleSwitch && this.slider.find( ".ui-slider-bg" ).length === 0 ) {\n
\t\t\tthis.valuebg = (function() {\n
\t\t\t\tvar bg = document.createElement( "div" );\n
\t\t\t\tbg.className = "ui-slider-bg " + $.mobile.activeBtnClass;\n
\t\t\t\treturn $( bg ).prependTo( self.slider );\n
\t\t\t})();\n
\t\t}\n
\t\tthis.handle.addClass( "ui-btn" + themeClass + " ui-shadow" );\n
\n
\t\tcontrol = this.element;\n
\t\tisInput = !this.isToggleSwitch;\n
\t\toptionElements = isInput ? [] : control.find( "option" );\n
\t\tmin =  isInput ? parseFloat( control.attr( "min" ) ) : 0;\n
\t\tmax = isInput ? parseFloat( control.attr( "max" ) ) : optionElements.length - 1;\n
\t\tstep = ( isInput && parseFloat( control.attr( "step" ) ) > 0 ) ? parseFloat( control.attr( "step" ) ) : 1;\n
\n
\t\tif ( typeof val === "object" ) {\n
\t\t\tdata = val;\n
\t\t\t// a slight tolerance helped get to the ends of the slider\n
\t\t\ttol = 8;\n
\n
\t\t\tleft = this.slider.offset().left;\n
\t\t\twidth = this.slider.width();\n
\t\t\tpxStep = width/((max-min)/step);\n
\t\t\tif ( !this.dragging ||\n
\t\t\t\t\tdata.pageX < left - tol ||\n
\t\t\t\t\tdata.pageX > left + width + tol ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( pxStep > 1 ) {\n
\t\t\t\tpercent = ( ( data.pageX - left ) / width ) * 100;\n
\t\t\t} else {\n
\t\t\t\tpercent = Math.round( ( ( data.pageX - left ) / width ) * 100 );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tif ( val == null ) {\n
\t\t\t\tval = isInput ? parseFloat( control.val() || 0 ) : control[0].selectedIndex;\n
\t\t\t}\n
\t\t\tpercent = ( parseFloat( val ) - min ) / ( max - min ) * 100;\n
\t\t}\n
\n
\t\tif ( isNaN( percent ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tnewval = ( percent / 100 ) * ( max - min ) + min;\n
\n
\t\t//from jQuery UI slider, the following source will round to the nearest step\n
\t\tvalModStep = ( newval - min ) % step;\n
\t\talignValue = newval - valModStep;\n
\n
\t\tif ( Math.abs( valModStep ) * 2 >= step ) {\n
\t\t\talignValue += ( valModStep > 0 ) ? step : ( -step );\n
\t\t}\n
\n
\t\tpercentPerStep = 100/((max-min)/step);\n
\t\t// Since JavaScript has problems with large floats, round\n
\t\t// the final value to 5 digits after the decimal point (see jQueryUI: #4124)\n
\t\tnewval = parseFloat( alignValue.toFixed(5) );\n
\n
\t\tif ( typeof pxStep === "undefined" ) {\n
\t\t\tpxStep = width / ( (max-min) / step );\n
\t\t}\n
\t\tif ( pxStep > 1 && isInput ) {\n
\t\t\tpercent = ( newval - min ) * percentPerStep * ( 1 / step );\n
\t\t}\n
\t\tif ( percent < 0 ) {\n
\t\t\tpercent = 0;\n
\t\t}\n
\n
\t\tif ( percent > 100 ) {\n
\t\t\tpercent = 100;\n
\t\t}\n
\n
\t\tif ( newval < min ) {\n
\t\t\tnewval = min;\n
\t\t}\n
\n
\t\tif ( newval > max ) {\n
\t\t\tnewval = max;\n
\t\t}\n
\n
\t\tthis.handle.css( "left", percent + "%" );\n
\n
\t\tthis.handle[0].setAttribute( "aria-valuenow", isInput ? newval : optionElements.eq( newval ).attr( "value" ) );\n
\n
\t\tthis.handle[0].setAttribute( "aria-valuetext", isInput ? newval : optionElements.eq( newval ).getEncodedText() );\n
\n
\t\tthis.handle[0].setAttribute( "title", isInput ? newval : optionElements.eq( newval ).getEncodedText() );\n
\n
\t\tif ( this.valuebg ) {\n
\t\t\tthis.valuebg.css( "width", percent + "%" );\n
\t\t}\n
\n
\t\t// drag the label widths\n
\t\tif ( this._labels ) {\n
\t\t\thandlePercent = this.handle.width() / this.slider.width() * 100;\n
\t\t\taPercent = percent && handlePercent + ( 100 - handlePercent ) * percent / 100;\n
\t\t\tbPercent = percent === 100 ? 0 : Math.min( handlePercent + 100 - aPercent, 100 );\n
\n
\t\t\tthis._labels.each(function() {\n
\t\t\t\tvar ab = $( this ).hasClass( "ui-slider-label-a" );\n
\t\t\t\t$( this ).width( ( ab ? aPercent : bPercent  ) + "%" );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( !preventInputUpdate ) {\n
\t\t\tvalueChanged = false;\n
\n
\t\t\t// update control"s value\n
\t\t\tif ( isInput ) {\n
\t\t\t\tvalueChanged = control.val() !== newval;\n
\t\t\t\tcontrol.val( newval );\n
\t\t\t} else {\n
\t\t\t\tvalueChanged = control[ 0 ].selectedIndex !== newval;\n
\t\t\t\tcontrol[ 0 ].selectedIndex = newval;\n
\t\t\t}\n
\t\t\tif ( this._trigger( "beforechange", val ) === false) {\n
\t\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tif ( !isfromControl && valueChanged ) {\n
\t\t\t\tcontrol.trigger( "change" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_setHighlight: function( value ) {\n
\t\tvalue = !!value;\n
\t\tif ( value ) {\n
\t\t\tthis.options.highlight = !!value;\n
\t\t\tthis.refresh();\n
\t\t} else if ( this.valuebg ) {\n
\t\t\tthis.valuebg.remove();\n
\t\t\tthis.valuebg = false;\n
\t\t}\n
\t},\n
\n
\t_setTheme: function( value ) {\n
\t\tthis.handle\n
\t\t\t.removeClass( "ui-btn-" + this.options.theme )\n
\t\t\t.addClass( "ui-btn-" + value );\n
\n
\t\tvar currentTheme = this.options.theme ? this.options.theme : "inherit",\n
\t\t\tnewTheme = value ? value : "inherit";\n
\n
\t\tthis.control\n
\t\t\t.removeClass( "ui-body-" + currentTheme )\n
\t\t\t.addClass( "ui-body-" + newTheme );\n
\t},\n
\n
\t_setTrackTheme: function( value ) {\n
\t\tvar currentTrackTheme = this.options.trackTheme ? this.options.trackTheme : "inherit",\n
\t\t\tnewTrackTheme = value ? value : "inherit";\n
\n
\t\tthis.slider\n
\t\t\t.removeClass( "ui-body-" + currentTrackTheme )\n
\t\t\t.addClass( "ui-body-" + newTrackTheme );\n
\t},\n
\n
\t_setMini: function( value ) {\n
\t\tvalue = !!value;\n
\t\tif ( !this.isToggleSwitch && !this.isRangeslider ) {\n
\t\t\tthis.slider.parent().toggleClass( "ui-mini", value );\n
\t\t\tthis.element.toggleClass( "ui-mini", value );\n
\t\t}\n
\t\tthis.slider.toggleClass( "ui-mini", value );\n
\t},\n
\n
\t_setCorners: function( value ) {\n
\t\tthis.slider.toggleClass( "ui-corner-all", value );\n
\n
\t\tif ( !this.isToggleSwitch ) {\n
\t\t\tthis.control.toggleClass( "ui-corner-all", value );\n
\t\t}\n
\t},\n
\n
\t_setDisabled: function( value ) {\n
\t\tvalue = !!value;\n
\t\tthis.element.prop( "disabled", value );\n
\t\tthis.slider\n
\t\t\t.toggleClass( "ui-state-disabled", value )\n
\t\t\t.attr( "aria-disabled", value );\n
\n
\t\tthis.element.toggleClass( "ui-state-disabled", value );\n
\t}\n
\n
}, $.mobile.behaviors.formReset ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
var popup;\n
\n
function getPopup() {\n
\tif ( !popup ) {\n
\t\tpopup = $( "<div></div>", {\n
\t\t\t"class": "ui-slider-popup ui-shadow ui-corner-all"\n
\t\t});\n
\t}\n
\treturn popup.clone();\n
}\n
\n
$.widget( "mobile.slider", $.mobile.slider, {\n
\toptions: {\n
\t\tpopupEnabled: false,\n
\t\tshowValue: false\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._super();\n
\n
\t\t$.extend( this, {\n
\t\t\t_currentValue: null,\n
\t\t\t_popup: null,\n
\t\t\t_popupVisible: false\n
\t\t});\n
\n
\t\tthis._setOption( "popupEnabled", this.options.popupEnabled );\n
\n
\t\tthis._on( this.handle, { "vmousedown" : "_showPopup" } );\n
\t\tthis._on( this.slider.add( this.document ), { "vmouseup" : "_hidePopup" } );\n
\t\tthis._refresh();\n
\t},\n
\n
\t// position the popup centered 5px above the handle\n
\t_positionPopup: function() {\n
\t\tvar dstOffset = this.handle.offset();\n
\n
\t\tthis._popup.offset( {\n
\t\t\tleft: dstOffset.left + ( this.handle.width() - this._popup.width() ) / 2,\n
\t\t\ttop: dstOffset.top - this._popup.outerHeight() - 5\n
\t\t});\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tthis._super( key, value );\n
\n
\t\tif ( key === "showValue" ) {\n
\t\t\tthis.handle.html( value && !this.options.mini ? this._value() : "" );\n
\t\t} else if ( key === "popupEnabled" ) {\n
\t\t\tif ( value && !this._popup ) {\n
\t\t\t\tthis._popup = getPopup()\n
\t\t\t\t\t.addClass( "ui-body-" + ( this.options.theme || "a" ) )\n
\t\t\t\t\t.hide()\n
\t\t\t\t\t.insertBefore( this.element );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// show value on the handle and in popup\n
\trefresh: function() {\n
\t\tthis._super.apply( this, arguments );\n
\t\tthis._refresh();\n
\t},\n
\n
\t_refresh: function() {\n
\t\tvar o = this.options, newValue;\n
\n
\t\tif ( o.popupEnabled ) {\n
\t\t\t// remove the title attribute from the handle (which is\n
\t\t\t// responsible for the annoying tooltip); NB we have\n
\t\t\t// to do it here as the jqm slider sets it every time\n
\t\t\t// the slider\'s value changes :(\n
\t\t\tthis.handle.removeAttr( "title" );\n
\t\t}\n
\n
\t\tnewValue = this._value();\n
\t\tif ( newValue === this._currentValue ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tthis._currentValue = newValue;\n
\n
\t\tif ( o.popupEnabled && this._popup ) {\n
\t\t\tthis._positionPopup();\n
\t\t\tthis._popup.html( newValue );\n
\t\t}\n
\n
\t\tif ( o.showValue && !this.options.mini ) {\n
\t\t\tthis.handle.html( newValue );\n
\t\t}\n
\t},\n
\n
\t_showPopup: function() {\n
\t\tif ( this.options.popupEnabled && !this._popupVisible ) {\n
\t\t\tthis.handle.html( "" );\n
\t\t\tthis._popup.show();\n
\t\t\tthis._positionPopup();\n
\t\t\tthis._popupVisible = true;\n
\t\t}\n
\t},\n
\n
\t_hidePopup: function() {\n
\t\tvar o = this.options;\n
\n
\t\tif ( o.popupEnabled && this._popupVisible ) {\n
\t\t\tif ( o.showValue && !o.mini ) {\n
\t\t\t\tthis.handle.html( this._value() );\n
\t\t\t}\n
\t\t\tthis._popup.hide();\n
\t\t\tthis._popupVisible = false;\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.flipswitch", $.extend({\n
\n
\toptions: {\n
\t\tonText: "On",\n
\t\toffText: "Off",\n
\t\ttheme: null,\n
\t\tenhanced: false,\n
\t\twrapperClass: null,\n
\t\tcorners: true,\n
\t\tmini: false\n
\t},\n
\n
\t_create: function() {\n
\t\t\tif ( !this.options.enhanced ) {\n
\t\t\t\tthis._enhance();\n
\t\t\t} else {\n
\t\t\t\t$.extend( this, {\n
\t\t\t\t\tflipswitch: this.element.parent(),\n
\t\t\t\t\ton: this.element.find( ".ui-flipswitch-on" ).eq( 0 ),\n
\t\t\t\t\toff: this.element.find( ".ui-flipswitch-off" ).eq(0),\n
\t\t\t\t\ttype: this.element.get( 0 ).tagName\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tthis._handleFormReset();\n
\n
\t\t\t// Transfer tabindex to "on" element and make input unfocusable\n
\t\t\tthis._originalTabIndex = this.element.attr( "tabindex" );\n
\t\t\tif ( this._originalTabIndex != null ) {\n
\t\t\t\tthis.on.attr( "tabindex", this._originalTabIndex );\n
\t\t\t}\n
\t\t\tthis.element.attr( "tabindex", "-1" );\n
\t\t\tthis._on({\n
\t\t\t\t"focus" : "_handleInputFocus"\n
\t\t\t});\n
\n
\t\t\tif ( this.element.is( ":disabled" ) ) {\n
\t\t\t\tthis._setOptions({\n
\t\t\t\t\t"disabled": true\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tthis._on( this.flipswitch, {\n
\t\t\t\t"click": "_toggle",\n
\t\t\t\t"swipeleft": "_left",\n
\t\t\t\t"swiperight": "_right"\n
\t\t\t});\n
\n
\t\t\tthis._on( this.on, {\n
\t\t\t\t"keydown": "_keydown"\n
\t\t\t});\n
\n
\t\t\tthis._on( {\n
\t\t\t\t"change": "refresh"\n
\t\t\t});\n
\t},\n
\n
\t_handleInputFocus: function() {\n
\t\tthis.on.focus();\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.flipswitch;\n
\t},\n
\n
\t_left: function() {\n
\t\tthis.flipswitch.removeClass( "ui-flipswitch-active" );\n
\t\tif ( this.type === "SELECT" ) {\n
\t\t\tthis.element.get( 0 ).selectedIndex = 0;\n
\t\t} else {\n
\t\t\tthis.element.prop( "checked", false );\n
\t\t}\n
\t\tthis.element.trigger( "change" );\n
\t},\n
\n
\t_right: function() {\n
\t\tthis.flipswitch.addClass( "ui-flipswitch-active" );\n
\t\tif ( this.type === "SELECT" ) {\n
\t\t\tthis.element.get( 0 ).selectedIndex = 1;\n
\t\t} else {\n
\t\t\tthis.element.prop( "checked", true );\n
\t\t}\n
\t\tthis.element.trigger( "change" );\n
\t},\n
\n
\t_enhance: function() {\n
\t\tvar flipswitch = $( "<div>" ),\n
\t\t\toptions = this.options,\n
\t\t\telement = this.element,\n
\t\t\ttheme = options.theme ? options.theme : "inherit",\n
\n
\t\t\t// The "on" button is an anchor so it\'s focusable\n
\t\t\ton = $( "<a></a>", {\n
\t\t\t\t"href": "#"\n
\t\t\t}),\n
\t\t\toff = $( "<span></span>" ),\n
\t\t\ttype = element.get( 0 ).tagName,\n
\t\t\tonText = ( type === "INPUT" ) ?\n
\t\t\t\toptions.onText : element.find( "option" ).eq( 1 ).text(),\n
\t\t\toffText = ( type === "INPUT" ) ?\n
\t\t\t\toptions.offText : element.find( "option" ).eq( 0 ).text();\n
\n
\t\t\ton\n
\t\t\t\t.addClass( "ui-flipswitch-on ui-btn ui-shadow ui-btn-inherit" )\n
\t\t\t\t.text( onText );\n
\t\t\toff\n
\t\t\t\t.addClass( "ui-flipswitch-off" )\n
\t\t\t\t.text( offText );\n
\n
\t\t\tflipswitch\n
\t\t\t\t.addClass( "ui-flipswitch ui-shadow-inset " +\n
\t\t\t\t\t"ui-bar-" + theme + " " +\n
\t\t\t\t\t( options.wrapperClass ? options.wrapperClass : "" ) + " " +\n
\t\t\t\t\t( ( element.is( ":checked" ) ||\n
\t\t\t\t\t\telement\n
\t\t\t\t\t\t\t.find( "option" )\n
\t\t\t\t\t\t\t.eq( 1 )\n
\t\t\t\t\t\t\t.is( ":selected" ) ) ? "ui-flipswitch-active" : "" ) +\n
\t\t\t\t\t( element.is(":disabled") ? " ui-state-disabled": "") +\n
\t\t\t\t\t( options.corners ? " ui-corner-all": "" ) +\n
\t\t\t\t\t( options.mini ? " ui-mini": "" ) )\n
\t\t\t\t.append( on, off );\n
\n
\t\t\telement\n
\t\t\t\t.addClass( "ui-flipswitch-input" )\n
\t\t\t\t.after( flipswitch )\n
\t\t\t\t.appendTo( flipswitch );\n
\n
\t\t$.extend( this, {\n
\t\t\tflipswitch: flipswitch,\n
\t\t\ton: on,\n
\t\t\toff: off,\n
\t\t\ttype: type\n
\t\t});\n
\t},\n
\n
\t_reset: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar direction,\n
\t\t\texistingDirection = this.flipswitch.hasClass( "ui-flipswitch-active" ) ? "_right" : "_left";\n
\n
\t\tif ( this.type === "SELECT" ) {\n
\t\t\tdirection = ( this.element.get( 0 ).selectedIndex > 0 ) ? "_right": "_left";\n
\t\t} else {\n
\t\t\tdirection = this.element.prop( "checked" ) ? "_right": "_left";\n
\t\t}\n
\n
\t\tif ( direction !== existingDirection ) {\n
\t\t\tthis[ direction ]();\n
\t\t}\n
\t},\n
\n
\t_toggle: function() {\n
\t\tvar direction = this.flipswitch.hasClass( "ui-flipswitch-active" ) ? "_left" : "_right";\n
\n
\t\tthis[ direction ]();\n
\t},\n
\n
\t_keydown: function( e ) {\n
\t\tif ( e.which === $.mobile.keyCode.LEFT ) {\n
\t\t\tthis._left();\n
\t\t} else if ( e.which === $.mobile.keyCode.RIGHT ) {\n
\t\t\tthis._right();\n
\t\t} else if ( e.which === $.mobile.keyCode.SPACE ) {\n
\t\t\tthis._toggle();\n
\t\t\te.preventDefault();\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tif ( options.theme !== undefined ) {\n
\t\t\tvar currentTheme = options.theme ? options.theme : "inherit",\n
\t\t\t\tnewTheme = options.theme ? options.theme : "inherit";\n
\n
\t\t\tthis.widget()\n
\t\t\t\t.removeClass( "ui-bar-" + currentTheme )\n
\t\t\t\t.addClass( "ui-bar-" + newTheme );\n
\t\t}\n
\t\tif ( options.onText !== undefined ) {\n
\t\t\tthis.on.text( options.onText );\n
\t\t}\n
\t\tif ( options.offText !== undefined ) {\n
\t\t\tthis.off.text( options.offText );\n
\t\t}\n
\t\tif ( options.disabled !== undefined ) {\n
\t\t\tthis.widget().toggleClass( "ui-state-disabled", options.disabled );\n
\t\t}\n
\t\tif ( options.mini !== undefined ) {\n
\t\t\tthis.widget().toggleClass( "ui-mini", options.mini );\n
\t\t}\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\tthis.widget().toggleClass( "ui-corner-all", options.corners );\n
\t\t}\n
\n
\t\tthis._super( options );\n
\t},\n
\n
\t_destroy: function() {\n
\t\tif ( this.options.enhanced ) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif ( this._originalTabIndex != null ) {\n
\t\t\tthis.element.attr( "tabindex", this._originalTabIndex );\n
\t\t} else {\n
\t\t\tthis.element.removeAttr( "tabindex" );\n
\t\t}\n
\t\tthis.on.remove();\n
\t\tthis.off.remove();\n
\t\tthis.element.unwrap();\n
\t\tthis.flipswitch.remove();\n
\t\tthis.removeClass( "ui-flipswitch-input" );\n
\t}\n
\n
}, $.mobile.behaviors.formReset ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\t$.widget( "mobile.rangeslider", $.extend( {\n
\n
\t\toptions: {\n
\t\t\ttheme: null,\n
\t\t\ttrackTheme: null,\n
\t\t\tcorners: true,\n
\t\t\tmini: false,\n
\t\t\thighlight: true\n
\t\t},\n
\n
\t\t_create: function() {\n
\t\t\tvar $el = this.element,\n
\t\t\telClass = this.options.mini ? "ui-rangeslider ui-mini" : "ui-rangeslider",\n
\t\t\t_inputFirst = $el.find( "input" ).first(),\n
\t\t\t_inputLast = $el.find( "input" ).last(),\n
\t\t\t_label = $el.find( "label" ).first(),\n
\t\t\t_sliderWidgetFirst = $.data( _inputFirst.get( 0 ), "mobile-slider" ) ||\n
\t\t\t\t$.data( _inputFirst.slider().get( 0 ), "mobile-slider" ),\n
\t\t\t_sliderWidgetLast = $.data( _inputLast.get(0), "mobile-slider" ) ||\n
\t\t\t\t$.data( _inputLast.slider().get( 0 ), "mobile-slider" ),\n
\t\t\t_sliderFirst = _sliderWidgetFirst.slider,\n
\t\t\t_sliderLast = _sliderWidgetLast.slider,\n
\t\t\tfirstHandle = _sliderWidgetFirst.handle,\n
\t\t\t_sliders = $( "<div class=\'ui-rangeslider-sliders\' />" ).appendTo( $el );\n
\n
\t\t\t_inputFirst.addClass( "ui-rangeslider-first" );\n
\t\t\t_inputLast.addClass( "ui-rangeslider-last" );\n
\t\t\t$el.addClass( elClass );\n
\n
\t\t\t_sliderFirst.appendTo( _sliders );\n
\t\t\t_sliderLast.appendTo( _sliders );\n
\t\t\t_label.insertBefore( $el );\n
\t\t\tfirstHandle.prependTo( _sliderLast );\n
\n
\t\t\t$.extend( this, {\n
\t\t\t\t_inputFirst: _inputFirst,\n
\t\t\t\t_inputLast: _inputLast,\n
\t\t\t\t_sliderFirst: _sliderFirst,\n
\t\t\t\t_sliderLast: _sliderLast,\n
\t\t\t\t_label: _label,\n
\t\t\t\t_targetVal: null,\n
\t\t\t\t_sliderTarget: false,\n
\t\t\t\t_sliders: _sliders,\n
\t\t\t\t_proxy: false\n
\t\t\t});\n
\n
\t\t\tthis.refresh();\n
\t\t\tthis._on( this.element.find( "input.ui-slider-input" ), {\n
\t\t\t\t"slidebeforestart": "_slidebeforestart",\n
\t\t\t\t"slidestop": "_slidestop",\n
\t\t\t\t"slidedrag": "_slidedrag",\n
\t\t\t\t"slidebeforechange": "_change",\n
\t\t\t\t"blur": "_change",\n
\t\t\t\t"keyup": "_change"\n
\t\t\t});\n
\t\t\tthis._on({\n
\t\t\t\t"mousedown":"_change"\n
\t\t\t});\n
\t\t\tthis._on( this.element.closest( "form" ), {\n
\t\t\t\t"reset":"_handleReset"\n
\t\t\t});\n
\t\t\tthis._on( firstHandle, {\n
\t\t\t\t"vmousedown": "_dragFirstHandle"\n
\t\t\t});\n
\t\t},\n
\t\t_handleReset: function() {\n
\t\t\tvar self = this;\n
\t\t\t//we must wait for the stack to unwind before updateing other wise sliders will not have updated yet\n
\t\t\tsetTimeout( function() {\n
\t\t\t\tself._updateHighlight();\n
\t\t\t},0);\n
\t\t},\n
\n
\t\t_dragFirstHandle: function( event ) {\n
\t\t\t//if the first handle is dragged send the event to the first slider\n
\t\t\t$.data( this._inputFirst.get(0), "mobile-slider" ).dragging = true;\n
\t\t\t$.data( this._inputFirst.get(0), "mobile-slider" ).refresh( event );\n
\t\t\t$.data( this._inputFirst.get(0), "mobile-slider" )._trigger( "start" );\n
\t\t\treturn false;\n
\t\t},\n
\n
\t\t_slidedrag: function( event ) {\n
\t\t\tvar first = $( event.target ).is( this._inputFirst ),\n
\t\t\t\totherSlider = ( first ) ? this._inputLast : this._inputFirst;\n
\n
\t\t\tthis._sliderTarget = false;\n
\t\t\t//if the drag was initiated on an extreme and the other handle is focused send the events to\n
\t\t\t//the closest handle\n
\t\t\tif ( ( this._proxy === "first" && first ) || ( this._proxy === "last" && !first ) ) {\n
\t\t\t\t$.data( otherSlider.get(0), "mobile-slider" ).dragging = true;\n
\t\t\t\t$.data( otherSlider.get(0), "mobile-slider" ).refresh( event );\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_slidestop: function( event ) {\n
\t\t\tvar first = $( event.target ).is( this._inputFirst );\n
\n
\t\t\tthis._proxy = false;\n
\t\t\t//this stops dragging of the handle and brings the active track to the front\n
\t\t\t//this makes clicks on the track go the the last handle used\n
\t\t\tthis.element.find( "input" ).trigger( "vmouseup" );\n
\t\t\tthis._sliderFirst.css( "z-index", first ? 1 : "" );\n
\t\t},\n
\n
\t\t_slidebeforestart: function( event ) {\n
\t\t\tthis._sliderTarget = false;\n
\t\t\t//if the track is the target remember this and the original value\n
\t\t\tif ( $( event.originalEvent.target ).hasClass( "ui-slider-track" ) ) {\n
\t\t\t\tthis._sliderTarget = true;\n
\t\t\t\tthis._targetVal = $( event.target ).val();\n
\t\t\t}\n
\t\t},\n
\n
\t\t_setOptions: function( options ) {\n
\t\t\tif ( options.theme !== undefined ) {\n
\t\t\t\tthis._setTheme( options.theme );\n
\t\t\t}\n
\n
\t\t\tif ( options.trackTheme !== undefined ) {\n
\t\t\t\tthis._setTrackTheme( options.trackTheme );\n
\t\t\t}\n
\n
\t\t\tif ( options.mini !== undefined ) {\n
\t\t\t\tthis._setMini( options.mini );\n
\t\t\t}\n
\n
\t\t\tif ( options.highlight !== undefined ) {\n
\t\t\t\tthis._setHighlight( options.highlight );\n
\t\t\t}\n
\n
\t\t\tif ( options.disabled !== undefined ) {\n
\t\t\t\tthis._setDisabled( options.disabled );\n
\t\t\t}\n
\n
\t\t\tthis._super( options );\n
\t\t\tthis.refresh();\n
\t\t},\n
\n
\t\trefresh: function() {\n
\t\t\tvar $el = this.element,\n
\t\t\t\to = this.options;\n
\n
\t\t\tif ( this._inputFirst.is( ":disabled" ) || this._inputLast.is( ":disabled" ) ) {\n
\t\t\t\tthis.options.disabled = true;\n
\t\t\t}\n
\n
\t\t\t$el.find( "input" ).slider({\n
\t\t\t\ttheme: o.theme,\n
\t\t\t\ttrackTheme: o.trackTheme,\n
\t\t\t\tdisabled: o.disabled,\n
\t\t\t\tcorners: o.corners,\n
\t\t\t\tmini: o.mini,\n
\t\t\t\thighlight: o.highlight\n
\t\t\t}).slider( "refresh" );\n
\t\t\tthis._updateHighlight();\n
\t\t},\n
\n
\t\t_change: function( event ) {\n
\t\t\tif ( event.type === "keyup" ) {\n
\t\t\t\tthis._updateHighlight();\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\tvar self = this,\n
\t\t\t\tmin = parseFloat( this._inputFirst.val(), 10 ),\n
\t\t\t\tmax = parseFloat( this._inputLast.val(), 10 ),\n
\t\t\t\tfirst = $( event.target ).hasClass( "ui-rangeslider-first" ),\n
\t\t\t\tthisSlider = first ? this._inputFirst : this._inputLast,\n
\t\t\t\totherSlider = first ? this._inputLast : this._inputFirst;\n
\n
\t\t\tif ( ( this._inputFirst.val() > this._inputLast.val() && event.type === "mousedown" && !$(event.target).hasClass("ui-slider-handle")) ) {\n
\t\t\t\tthisSlider.blur();\n
\t\t\t} else if ( event.type === "mousedown" ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( min > max && !this._sliderTarget ) {\n
\t\t\t\t//this prevents min from being greater then max\n
\t\t\t\tthisSlider.val( first ? max: min ).slider( "refresh" );\n
\t\t\t\tthis._trigger( "normalize" );\n
\t\t\t} else if ( min > max ) {\n
\t\t\t\t//this makes it so clicks on the target on either extreme go to the closest handle\n
\t\t\t\tthisSlider.val( this._targetVal ).slider( "refresh" );\n
\n
\t\t\t\t//You must wait for the stack to unwind so first slider is updated before updating second\n
\t\t\t\tsetTimeout( function() {\n
\t\t\t\t\totherSlider.val( first ? min: max ).slider( "refresh" );\n
\t\t\t\t\t$.data( otherSlider.get(0), "mobile-slider" ).handle.focus();\n
\t\t\t\t\tself._sliderFirst.css( "z-index", first ? "" : 1 );\n
\t\t\t\t\tself._trigger( "normalize" );\n
\t\t\t\t}, 0 );\n
\t\t\t\tthis._proxy = ( first ) ? "first" : "last";\n
\t\t\t}\n
\t\t\t//fixes issue where when both _sliders are at min they cannot be adjusted\n
\t\t\tif ( min === max ) {\n
\t\t\t\t$.data( thisSlider.get(0), "mobile-slider" ).handle.css( "z-index", 1 );\n
\t\t\t\t$.data( otherSlider.get(0), "mobile-slider" ).handle.css( "z-index", 0 );\n
\t\t\t} else {\n
\t\t\t\t$.data( otherSlider.get(0), "mobile-slider" ).handle.css( "z-index", "" );\n
\t\t\t\t$.data( thisSlider.get(0), "mobile-slider" ).handle.css( "z-index", "" );\n
\t\t\t}\n
\n
\t\t\tthis._updateHighlight();\n
\n
\t\t\tif ( min >= max ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_updateHighlight: function() {\n
\t\t\tvar min = parseInt( $.data( this._inputFirst.get(0), "mobile-slider" ).handle.get(0).style.left, 10 ),\n
\t\t\t\tmax = parseInt( $.data( this._inputLast.get(0), "mobile-slider" ).handle.get(0).style.left, 10 ),\n
\t\t\t\twidth = (max - min);\n
\n
\t\t\tthis.element.find( ".ui-slider-bg" ).css({\n
\t\t\t\t"margin-left": min + "%",\n
\t\t\t\t"width": width + "%"\n
\t\t\t});\n
\t\t},\n
\n
\t\t_setTheme: function( value ) {\n
\t\t\tthis._inputFirst.slider( "option", "theme", value );\n
\t\t\tthis._inputLast.slider( "option", "theme", value );\n
\t\t},\n
\n
\t\t_setTrackTheme: function( value ) {\n
\t\t\tthis._inputFirst.slider( "option", "trackTheme", value );\n
\t\t\tthis._inputLast.slider( "option", "trackTheme", value );\n
\t\t},\n
\n
\t\t_setMini: function( value ) {\n
\t\t\tthis._inputFirst.slider( "option", "mini", value );\n
\t\t\tthis._inputLast.slider( "option", "mini", value );\n
\t\t\tthis.element.toggleClass( "ui-mini", !!value );\n
\t\t},\n
\n
\t\t_setHighlight: function( value ) {\n
\t\t\tthis._inputFirst.slider( "option", "highlight", value );\n
\t\t\tthis._inputLast.slider( "option", "highlight", value );\n
\t\t},\n
\n
\t\t_setDisabled: function( value ) {\n
\t\t\tthis._inputFirst.prop( "disabled", value );\n
\t\t\tthis._inputLast.prop( "disabled", value );\n
\t\t},\n
\n
\t\t_destroy: function() {\n
\t\t\tthis._label.prependTo( this.element );\n
\t\t\tthis.element.removeClass( "ui-rangeslider ui-mini" );\n
\t\t\tthis._inputFirst.after( this._sliderFirst );\n
\t\t\tthis._inputLast.after( this._sliderLast );\n
\t\t\tthis._sliders.remove();\n
\t\t\tthis.element.find( "input" ).removeClass( "ui-rangeslider-first ui-rangeslider-last" ).slider( "destroy" );\n
\t\t}\n
\n
\t}, $.mobile.behaviors.formReset ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
\t$.widget( "mobile.textinput", $.mobile.textinput, {\n
\t\toptions: {\n
\t\t\tclearBtn: false,\n
\t\t\tclearBtnText: "Clear text"\n
\t\t},\n
\n
\t\t_create: function() {\n
\t\t\tthis._super();\n
\n
\t\t\tif ( this.isSearch ) {\n
\t\t\t\tthis.options.clearBtn = true;\n
\t\t\t}\n
\n
\t\t\tif ( !!this.options.clearBtn && this.inputNeedsWrap ) {\n
\t\t\t\tthis._addClearBtn();\n
\t\t\t}\n
\t\t},\n
\n
\t\tclearButton: function() {\n
\t\t\treturn $( "<a href=\'#\' " +\n
\t\t\t\t"class=\'ui-input-clear ui-btn ui-icon-delete ui-btn-icon-notext ui-corner-all\'>" +\n
\t\t\t\t"</a>" )\n
\t\t\t\t\t.attr( "title", this.options.clearBtnText )\n
\t\t\t\t\t.text( this.options.clearBtnText );\n
\t\t},\n
\n
\t\t_clearBtnClick: function( event ) {\n
\t\t\tthis.element.val( "" )\n
\t\t\t\t\t.focus()\n
\t\t\t\t\t.trigger( "change" );\n
\n
\t\t\tthis._clearBtn.addClass( "ui-input-clear-hidden" );\n
\t\t\tevent.preventDefault();\n
\t\t},\n
\n
\t\t_addClearBtn: function() {\n
\n
\t\t\tif ( !this.options.enhanced ) {\n
\t\t\t\tthis._enhanceClear();\n
\t\t\t}\n
\n
\t\t\t$.extend( this, {\n
\t\t\t\t_clearBtn: this.widget().find("a.ui-input-clear")\n
\t\t\t});\n
\n
\t\t\tthis._bindClearEvents();\n
\n
\t\t\tthis._toggleClear();\n
\n
\t\t},\n
\n
\t\t_enhanceClear: function() {\n
\n
\t\t\tthis.clearButton().appendTo( this.widget() );\n
\t\t\tthis.widget().addClass( "ui-input-has-clear" );\n
\n
\t\t},\n
\n
\t\t_bindClearEvents: function() {\n
\n
\t\t\tthis._on( this._clearBtn, {\n
\t\t\t\t"click": "_clearBtnClick"\n
\t\t\t});\n
\n
\t\t\tthis._on({\n
\t\t\t\t"keyup": "_toggleClear",\n
\t\t\t\t"change": "_toggleClear",\n
\t\t\t\t"input": "_toggleClear",\n
\t\t\t\t"focus": "_toggleClear",\n
\t\t\t\t"blur": "_toggleClear",\n
\t\t\t\t"cut": "_toggleClear",\n
\t\t\t\t"paste": "_toggleClear"\n
\n
\t\t\t});\n
\n
\t\t},\n
\n
\t\t_unbindClear: function() {\n
\t\t\tthis._off( this._clearBtn, "click");\n
\t\t\tthis._off( this.element, "keyup change input focus blur cut paste" );\n
\t\t},\n
\n
\t\t_setOptions: function( options ) {\n
\t\t\tthis._super( options );\n
\n
\t\t\tif ( options.clearBtn !== undefined &&\n
\t\t\t\t!this.element.is( "textarea, :jqmData(type=\'range\')" ) ) {\n
\t\t\t\tif ( options.clearBtn ) {\n
\t\t\t\t\tthis._addClearBtn();\n
\t\t\t\t} else {\n
\t\t\t\t\tthis._destroyClear();\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( options.clearBtnText !== undefined && this._clearBtn !== undefined ) {\n
\t\t\t\tthis._clearBtn.text( options.clearBtnText )\n
\t\t\t\t\t.attr("title", options.clearBtnText);\n
\t\t\t}\n
\t\t},\n
\n
\t\t_toggleClear: function() {\n
\t\t\tthis._delay( "_toggleClearClass", 0 );\n
\t\t},\n
\n
\t\t_toggleClearClass: function() {\n
\t\t\tthis._clearBtn.toggleClass( "ui-input-clear-hidden", !this.element.val() );\n
\t\t},\n
\n
\t\t_destroyClear: function() {\n
\t\t\tthis.widget().removeClass( "ui-input-has-clear" );\n
\t\t\tthis._unbindClear();\n
\t\t\tthis._clearBtn.remove();\n
\t\t},\n
\n
\t\t_destroy: function() {\n
\t\t\tthis._super();\n
\t\t\tthis._destroyClear();\n
\t\t}\n
\n
\t});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
\t$.widget( "mobile.textinput", $.mobile.textinput, {\n
\t\toptions: {\n
\t\t\tautogrow:true,\n
\t\t\tkeyupTimeoutBuffer: 100\n
\t\t},\n
\n
\t\t_create: function() {\n
\t\t\tthis._super();\n
\n
\t\t\tif ( this.options.autogrow && this.isTextarea ) {\n
\t\t\t\tthis._autogrow();\n
\t\t\t}\n
\t\t},\n
\n
\t\t_autogrow: function() {\n
\t\t\tthis.element.addClass( "ui-textinput-autogrow" );\n
\n
\t\t\tthis._on({\n
\t\t\t\t"keyup": "_timeout",\n
\t\t\t\t"change": "_timeout",\n
\t\t\t\t"input": "_timeout",\n
\t\t\t\t"paste": "_timeout"\n
\t\t\t});\n
\n
\t\t\t// Attach to the various you-have-become-visible notifications that the\n
\t\t\t// various framework elements emit.\n
\t\t\t// TODO: Remove all but the updatelayout handler once #6426 is fixed.\n
\t\t\tthis._on( true, this.document, {\n
\n
\t\t\t\t// TODO: Move to non-deprecated event\n
\t\t\t\t"pageshow": "_handleShow",\n
\t\t\t\t"popupbeforeposition": "_handleShow",\n
\t\t\t\t"updatelayout": "_handleShow",\n
\t\t\t\t"panelopen": "_handleShow"\n
\t\t\t});\n
\t\t},\n
\n
\t\t// Synchronously fix the widget height if this widget\'s parents are such\n
\t\t// that they show/hide content at runtime. We still need to check whether\n
\t\t// the widget is actually visible in case it is contained inside multiple\n
\t\t// such containers. For example: panel contains collapsible contains\n
\t\t// autogrow textinput. The panel may emit "panelopen" indicating that its\n
\t\t// content has become visible, but the collapsible is still collapsed, so\n
\t\t// the autogrow textarea is still not visible.\n
\t\t_handleShow: function( event ) {\n
\t\t\tif ( $.contains( event.target, this.element[ 0 ] ) &&\n
\t\t\t\tthis.element.is( ":visible" ) ) {\n
\n
\t\t\t\tif ( event.type !== "popupbeforeposition" ) {\n
\t\t\t\t\tthis.element\n
\t\t\t\t\t\t.addClass( "ui-textinput-autogrow-resize" )\n
\t\t\t\t\t\t.animationComplete(\n
\t\t\t\t\t\t\t$.proxy( function() {\n
\t\t\t\t\t\t\t\tthis.element.removeClass( "ui-textinput-autogrow-resize" );\n
\t\t\t\t\t\t\t}, this ),\n
\t\t\t\t\t\t"transition" );\n
\t\t\t\t}\n
\t\t\t\tthis._prepareHeightUpdate();\n
\t\t\t}\n
\t\t},\n
\n
\t\t_unbindAutogrow: function() {\n
\t\t\tthis.element.removeClass( "ui-textinput-autogrow" );\n
\t\t\tthis._off( this.element, "keyup change input paste" );\n
\t\t\tthis._off( this.document,\n
\t\t\t\t"pageshow popupbeforeposition updatelayout panelopen" );\n
\t\t},\n
\n
\t\tkeyupTimeout: null,\n
\n
\t\t_prepareHeightUpdate: function( delay ) {\n
\t\t\tif ( this.keyupTimeout ) {\n
\t\t\t\tclearTimeout( this.keyupTimeout );\n
\t\t\t}\n
\t\t\tif ( delay === undefined ) {\n
\t\t\t\tthis._updateHeight();\n
\t\t\t} else {\n
\t\t\t\tthis.keyupTimeout = this._delay( "_updateHeight", delay );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_timeout: function() {\n
\t\t\tthis._prepareHeightUpdate( this.options.keyupTimeoutBuffer );\n
\t\t},\n
\n
\t\t_updateHeight: function() {\n
\t\t\tvar paddingTop, paddingBottom, paddingHeight, scrollHeight, clientHeight,\n
\t\t\t\tborderTop, borderBottom, borderHeight, height,\n
\t\t\t\tscrollTop = this.window.scrollTop();\n
\t\t\tthis.keyupTimeout = 0;\n
\n
\t\t\t// IE8 textareas have the onpage property - others do not\n
\t\t\tif ( !( "onpage" in this.element[ 0 ] ) ) {\n
\t\t\t\tthis.element.css({\n
\t\t\t\t\t"height": 0,\n
\t\t\t\t\t"min-height": 0,\n
\t\t\t\t\t"max-height": 0\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tscrollHeight = this.element[ 0 ].scrollHeight;\n
\t\t\tclientHeight = this.element[ 0 ].clientHeight;\n
\t\t\tborderTop = parseFloat( this.element.css( "border-top-width" ) );\n
\t\t\tborderBottom = parseFloat( this.element.css( "border-bottom-width" ) );\n
\t\t\tborderHeight = borderTop + borderBottom;\n
\t\t\theight = scrollHeight + borderHeight + 15;\n
\n
\t\t\t// Issue 6179: Padding is not included in scrollHeight and\n
\t\t\t// clientHeight by Firefox if no scrollbar is visible. Because\n
\t\t\t// textareas use the border-box box-sizing model, padding should be\n
\t\t\t// included in the new (assigned) height. Because the height is set\n
\t\t\t// to 0, clientHeight == 0 in Firefox. Therefore, we can use this to\n
\t\t\t// check if padding must be added.\n
\t\t\tif ( clientHeight === 0 ) {\n
\t\t\t\tpaddingTop = parseFloat( this.element.css( "padding-top" ) );\n
\t\t\t\tpaddingBottom = parseFloat( this.element.css( "padding-bottom" ) );\n
\t\t\t\tpaddingHeight = paddingTop + paddingBottom;\n
\n
\t\t\t\theight += paddingHeight;\n
\t\t\t}\n
\n
\t\t\tthis.element.css({\n
\t\t\t\t"height": height,\n
\t\t\t\t"min-height": "",\n
\t\t\t\t"max-height": ""\n
\t\t\t});\n
\n
\t\t\tthis.window.scrollTop( scrollTop );\n
\t\t},\n
\n
\t\trefresh: function() {\n
\t\t\tif ( this.options.autogrow && this.isTextarea ) {\n
\t\t\t\tthis._updateHeight();\n
\t\t\t}\n
\t\t},\n
\n
\t\t_setOptions: function( options ) {\n
\n
\t\t\tthis._super( options );\n
\n
\t\t\tif ( options.autogrow !== undefined && this.isTextarea ) {\n
\t\t\t\tif ( options.autogrow ) {\n
\t\t\t\t\tthis._autogrow();\n
\t\t\t\t} else {\n
\t\t\t\t\tthis._unbindAutogrow();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t});\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.selectmenu", $.extend( {\n
\tinitSelector: "select:not( :jqmData(role=\'slider\')):not( :jqmData(role=\'flipswitch\') )",\n
\n
\toptions: {\n
\t\ttheme: null,\n
\t\ticon: "carat-d",\n
\t\ticonpos: "right",\n
\t\tinline: false,\n
\t\tcorners: true,\n
\t\tshadow: true,\n
\t\ticonshadow: false, /* TODO: Deprecated in 1.4, remove in 1.5. */\n
\t\toverlayTheme: null,\n
\t\tdividerTheme: null,\n
\t\thidePlaceholderMenuItems: true,\n
\t\tcloseText: "Close",\n
\t\tnativeMenu: true,\n
\t\t// XXX Sven added wrapper class\n
\t\twrapperClass: null,\n
\t\t// This option defaults to true on iOS devices.\n
\t\tpreventFocusZoom: /iPhone|iPad|iPod/.test( navigator.platform ) && navigator.userAgent.indexOf( "AppleWebKit" ) > -1,\n
\t\tmini: false\n
\t},\n
\n
\t_button: function() {\n
\t\treturn $( "<div/>" );\n
\t},\n
\n
\t_setDisabled: function( value ) {\n
\t\tthis.element.attr( "disabled", value );\n
\t\tthis.button.attr( "aria-disabled", value );\n
\t\treturn this._setOption( "disabled", value );\n
\t},\n
\n
\t_focusButton : function() {\n
\t\tvar self = this;\n
\n
\t\tsetTimeout( function() {\n
\t\t\tself.button.focus();\n
\t\t}, 40);\n
\t},\n
\n
\t_selectOptions: function() {\n
\t\treturn this.select.find( "option" );\n
\t},\n
\n
\t// setup items that are generally necessary for select menu extension\n
\t_preExtension: function() {\n
\t\tvar inline = this.options.inline || this.element.jqmData( "inline" ),\n
\t\t\tmini = this.options.mini || this.element.jqmData( "mini" ),\n
\t\t\tclasses = "";\n
\t\t// TODO: Post 1.1--once we have time to test thoroughly--any classes manually applied to the original element should be carried over to the enhanced element, with an `-enhanced` suffix. See https://github.com/jquery/jquery-mobile/issues/3577\n
\t\t/* if ( $el[0].className.length ) {\n
\t\t\tclasses = $el[0].className;\n
\t\t} */\n
\t\tif ( !!~this.element[0].className.indexOf( "ui-btn-left" ) ) {\n
\t\t\tclasses = " ui-btn-left";\n
\t\t}\n
\n
\t\tif (  !!~this.element[0].className.indexOf( "ui-btn-right" ) ) {\n
\t\t\tclasses = " ui-btn-right";\n
\t\t}\n
\n
\t\tif ( inline ) {\n
\t\t\tclasses += " ui-btn-inline";\n
\t\t}\n
\t\tif ( mini ) {\n
\t\t\tclasses += " ui-mini";\n
\t\t}\n
\n
\t\tthis.select = this.element.removeClass( "ui-btn-left ui-btn-right" ).wrap( "<div class=\'ui-select" + classes + "\'>" );\n
\t\tthis.selectId  = this.select.attr( "id" ) || ( "select-" + this.uuid );\n
\t\tthis.buttonId = this.selectId + "-button";\n
\t\tthis.label = $( "label[for=\'"+ this.selectId +"\']" );\n
\t\tthis.isMultiple = this.select[ 0 ].multiple;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar wrapper = this.element.parents( ".ui-select" );\n
\t\tif ( wrapper.length > 0 ) {\n
\t\t\tif ( wrapper.is( ".ui-btn-left, .ui-btn-right" ) ) {\n
\t\t\t\tthis.element.addClass( wrapper.hasClass( "ui-btn-left" ) ? "ui-btn-left" : "ui-btn-right" );\n
\t\t\t}\n
\t\t\tthis.element.insertAfter( wrapper );\n
\t\t\twrapper.remove();\n
\t\t}\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._preExtension();\n
\n
\t\tthis.button = this._button();\n
\n
\t\tvar self = this,\n
\n
\t\t\toptions = this.options,\n
\n
\t\t\ticonpos = options.icon ? ( options.iconpos || this.select.jqmData( "iconpos" ) ) : false,\n
\n
\t\t\tbutton = this.button\n
\t\t\t\t.insertBefore( this.select )\n
\t\t\t\t.attr( "id", this.buttonId )\n
\t\t\t\t.addClass( "ui-btn" +\n
\t\t\t\t\t( options.icon ? ( " ui-icon-" + options.icon + " ui-btn-icon-" + iconpos +\n
\t\t\t\t\t( options.iconshadow ? " ui-shadow-icon" : "" ) ) :\t"" ) + /* TODO: Remove in 1.5. */\n
\t\t\t\t\t( options.theme ? " ui-btn-" + options.theme : "" ) +\n
\t\t\t\t\t( options.corners ? " ui-corner-all" : "" ) +\n
\t\t\t\t\t// XXX Sven wrapper class\n
\t\t\t\t\t( options.shadow ? " ui-shadow " : "" ) +\n
\t\t\t\t\t( options.wrapperClass || "" ) );\n
\n
\t\tthis.setButtonText();\n
\n
\t\t// Opera does not properly support opacity on select elements\n
\t\t// In Mini, it hides the element, but not its text\n
\t\t// On the desktop,it seems to do the opposite\n
\t\t// for these reasons, using the nativeMenu option results in a full native select in Opera\n
\t\tif ( options.nativeMenu && window.opera && window.opera.version ) {\n
\t\t\tbutton.addClass( "ui-select-nativeonly" );\n
\t\t}\n
\n
\t\t// Add counter for multi selects\n
\t\tif ( this.isMultiple ) {\n
\t\t\tthis.buttonCount = $( "<span>" )\n
\t\t\t\t.addClass( "ui-li-count ui-body-inherit" )\n
\t\t\t\t.hide()\n
\t\t\t\t.appendTo( button.addClass( "ui-li-has-count" ) );\n
\t\t}\n
\n
\t\t// Disable if specified\n
\t\tif ( options.disabled || this.element.attr( "disabled" )) {\n
\t\t\tthis.disable();\n
\t\t}\n
\n
\t\t// Events on native select\n
\t\tthis.select.change(function() {\n
\t\t\tself.refresh();\n
\n
\t\t\tif ( !!options.nativeMenu ) {\n
\t\t\t\tthis.blur();\n
\t\t\t}\n
\t\t});\n
\n
\t\tthis._handleFormReset();\n
\n
\t\tthis._on( this.button, {\n
\t\t\tkeydown: "_handleKeydown"\n
\t\t});\n
\n
\t\tthis.build();\n
\t},\n
\n
\tbuild: function() {\n
\t\tvar self = this;\n
\n
\t\tthis.select\n
\t\t\t.appendTo( self.button )\n
\t\t\t.bind( "vmousedown", function() {\n
\t\t\t\t// Add active class to button\n
\t\t\t\tself.button.addClass( $.mobile.activeBtnClass );\n
\t\t\t})\n
\t\t\t.bind( "focus", function() {\n
\t\t\t\tself.button.addClass( $.mobile.focusClass );\n
\t\t\t})\n
\t\t\t.bind( "blur", function() {\n
\t\t\t\tself.button.removeClass( $.mobile.focusClass );\n
\t\t\t})\n
\t\t\t.bind( "focus vmouseover", function() {\n
\t\t\t\tself.button.trigger( "vmouseover" );\n
\t\t\t})\n
\t\t\t.bind( "vmousemove", function() {\n
\t\t\t\t// Remove active class on scroll/touchmove\n
\t\t\t\tself.button.removeClass( $.mobile.activeBtnClass );\n
\t\t\t})\n
\t\t\t.bind( "change blur vmouseout", function() {\n
\t\t\t\tself.button.trigger( "vmouseout" )\n
\t\t\t\t\t.removeClass( $.mobile.activeBtnClass );\n
\t\t\t});\n
\n
\t\t// In many situations, iOS will zoom into the select upon tap, this prevents that from happening\n
\t\tself.button.bind( "vmousedown", function() {\n
\t\t\tif ( self.options.preventFocusZoom ) {\n
\t\t\t\t\t$.mobile.zoom.disable( true );\n
\t\t\t}\n
\t\t});\n
\t\tself.label.bind( "click focus", function() {\n
\t\t\tif ( self.options.preventFocusZoom ) {\n
\t\t\t\t\t$.mobile.zoom.disable( true );\n
\t\t\t}\n
\t\t});\n
\t\tself.select.bind( "focus", function() {\n
\t\t\tif ( self.options.preventFocusZoom ) {\n
\t\t\t\t\t$.mobile.zoom.disable( true );\n
\t\t\t}\n
\t\t});\n
\t\tself.button.bind( "mouseup", function() {\n
\t\t\tif ( self.options.preventFocusZoom ) {\n
\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t$.mobile.zoom.enable( true );\n
\t\t\t\t}, 0 );\n
\t\t\t}\n
\t\t});\n
\t\tself.select.bind( "blur", function() {\n
\t\t\tif ( self.options.preventFocusZoom ) {\n
\t\t\t\t$.mobile.zoom.enable( true );\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\n
\tselected: function() {\n
\t\treturn this._selectOptions().filter( ":selected" );\n
\t},\n
\n
\tselectedIndices: function() {\n
\t\tvar self = this;\n
\n
\t\treturn this.selected().map(function() {\n
\t\t\treturn self._selectOptions().index( this );\n
\t\t}).get();\n
\t},\n
\n
\tsetButtonText: function() {\n
\t\tvar self = this,\n
\t\t\tselected = this.selected(),\n
\t\t\ttext = this.placeholder,\n
\t\t\tspan = $( document.createElement( "span" ) );\n
\n
\t\tthis.button.children( "span" ).not( ".ui-li-count" ).remove().end().end().prepend( (function() {\n
\t\t\tif ( selected.length ) {\n
\t\t\t\ttext = selected.map(function() {\n
\t\t\t\t\treturn $( this ).text();\n
\t\t\t\t}).get().join( ", " );\n
\t\t\t} else {\n
\t\t\t\ttext = self.placeholder;\n
\t\t\t}\n
\n
\t\t\tif ( text ) {\n
\t\t\t\tspan.text( text );\n
\t\t\t} else {\n
\n
\t\t\t\t// Set the contents to &nbsp; which we write as &#160; to be XHTML compliant - see gh-6699\n
\t\t\t\tspan.html( "&#160;" );\n
\t\t\t}\n
\n
\t\t\t// TODO possibly aggregate multiple select option classes\n
\t\t\treturn span\n
\t\t\t\t.addClass( self.select.attr( "class" ) )\n
\t\t\t\t.addClass( selected.attr( "class" ) )\n
\t\t\t\t.removeClass( "ui-screen-hidden" );\n
\t\t})());\n
\t},\n
\n
\tsetButtonCount: function() {\n
\t\tvar selected = this.selected();\n
\n
\t\t// multiple count inside button\n
\t\tif ( this.isMultiple ) {\n
\t\t\tthis.buttonCount[ selected.length > 1 ? "show" : "hide" ]().text( selected.length );\n
\t\t}\n
\t},\n
\n
\t_handleKeydown: function( /* event */ ) {\n
\t\tthis._delay( "_refreshButton" );\n
\t},\n
\n
\t_reset: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\t_refreshButton: function() {\n
\t\tthis.setButtonText();\n
\t\tthis.setButtonCount();\n
\t},\n
\n
\trefresh: function() {\n
\t\tthis._refreshButton();\n
\t},\n
\n
\t// open and close preserved in native selects\n
\t// to simplify users code when looping over selects\n
\topen: $.noop,\n
\tclose: $.noop,\n
\n
\tdisable: function() {\n
\t\tthis._setDisabled( true );\n
\t\tthis.button.addClass( "ui-state-disabled" );\n
\t},\n
\n
\tenable: function() {\n
\t\tthis._setDisabled( false );\n
\t\tthis.button.removeClass( "ui-state-disabled" );\n
\t}\n
}, $.mobile.behaviors.formReset ) );\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.mobile.links = function( target ) {\n
\n
\t//links within content areas, tests included with page\n
\t$( target )\n
\t\t.find( "a" )\n
\t\t.jqmEnhanceable()\n
\t\t.filter( ":jqmData(rel=\'popup\')[href][href!=\'\']" )\n
\t\t.each( function() {\n
\t\t\t// Accessibility info for popups\n
\t\t\tvar element = this,\n
\t\t\t\tidref = element.getAttribute( "href" ).substring( 1 );\n
\n
\t\t\tif ( idref ) {\n
\t\t\t\telement.setAttribute( "aria-haspopup", true );\n
\t\t\t\telement.setAttribute( "aria-owns", idref );\n
\t\t\t\telement.setAttribute( "aria-expanded", false );\n
\t\t\t}\n
\t\t})\n
\t\t.end()\n
\t\t.not( ".ui-btn, :jqmData(role=\'none\'), :jqmData(role=\'nojs\')" )\n
\t\t.addClass( "ui-link" );\n
\n
};\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\n
function fitSegmentInsideSegment( windowSize, segmentSize, offset, desired ) {\n
\tvar returnValue = desired;\n
\n
\tif ( windowSize < segmentSize ) {\n
\t\t// Center segment if it\'s bigger than the window\n
\t\treturnValue = offset + ( windowSize - segmentSize ) / 2;\n
\t} else {\n
\t\t// Otherwise center it at the desired coordinate while keeping it completely inside the window\n
\t\treturnValue = Math.min( Math.max( offset, desired - segmentSize / 2 ), offset + windowSize - segmentSize );\n
\t}\n
\n
\treturn returnValue;\n
}\n
\n
function getWindowCoordinates( theWindow ) {\n
\treturn {\n
\t\tx: theWindow.scrollLeft(),\n
\t\ty: theWindow.scrollTop(),\n
\t\tcx: ( theWindow[ 0 ].innerWidth || theWindow.width() ),\n
\t\tcy: ( theWindow[ 0 ].innerHeight || theWindow.height() )\n
\t};\n
}\n
\n
$.widget( "mobile.popup", {\n
\toptions: {\n
\t\twrapperClass: null,\n
\t\ttheme: null,\n
\t\toverlayTheme: null,\n
\t\tshadow: true,\n
\t\tcorners: true,\n
\t\ttransition: "none",\n
\t\tpositionTo: "origin",\n
\t\ttolerance: null,\n
\t\tcloseLinkSelector: "a:jqmData(rel=\'back\')",\n
\t\tcloseLinkEvents: "click.popup",\n
\t\tnavigateEvents: "navigate.popup",\n
\t\tcloseEvents: "navigate.popup pagebeforechange.popup",\n
\t\tdismissible: true,\n
\t\tenhanced: false,\n
\n
\t\t// NOTE Windows Phone 7 has a scroll position caching issue that\n
\t\t//      requires us to disable popup history management by default\n
\t\t//      https://github.com/jquery/jquery-mobile/issues/4784\n
\t\t//\n
\t\t// NOTE this option is modified in _create!\n
\t\thistory: !$.mobile.browser.oldIE\n
\t},\n
\n
\t// When the user depresses the mouse/finger on an element inside the popup while the popup is\n
\t// open, we ignore resize events for a short while. This prevents #6961.\n
\t_handleDocumentVmousedown: function( theEvent ) {\n
\t\tif ( this._isOpen && $.contains( this._ui.container[ 0 ], theEvent.target ) ) {\n
\t\t\tthis._ignoreResizeEvents();\n
\t\t}\n
\t},\n
\n
\t_create: function() {\n
\t\tvar theElement = this.element,\n
\t\t\tmyId = theElement.attr( "id" ),\n
\t\t\tcurrentOptions = this.options;\n
\n
\t\t// We need to adjust the history option to be false if there\'s no AJAX nav.\n
\t\t// We can\'t do it in the option declarations because those are run before\n
\t\t// it is determined whether there shall be AJAX nav.\n
\t\tcurrentOptions.history = currentOptions.history && $.mobile.ajaxEnabled && $.mobile.hashListeningEnabled;\n
\n
\t\tthis._on( this.document, {\n
\t\t\t"vmousedown": "_handleDocumentVmousedown"\n
\t\t});\n
\n
\t\t// Define instance variables\n
\t\t$.extend( this, {\n
\t\t\t_scrollTop: 0,\n
\t\t\t_page: theElement.closest( ".ui-page" ),\n
\t\t\t_ui: null,\n
\t\t\t_fallbackTransition: "",\n
\t\t\t_currentTransition: false,\n
\t\t\t_prerequisites: null,\n
\t\t\t_isOpen: false,\n
\t\t\t_tolerance: null,\n
\t\t\t_resizeData: null,\n
\t\t\t_ignoreResizeTo: 0,\n
\t\t\t_orientationchangeInProgress: false\n
\t\t});\n
\n
\t\tif ( this._page.length === 0 ) {\n
\t\t\tthis._page = $( "body" );\n
\t\t}\n
\n
\t\tif ( currentOptions.enhanced ) {\n
\t\t\tthis._ui = {\n
\t\t\t\tcontainer: theElement.parent(),\n
\t\t\t\tscreen: theElement.parent().prev(),\n
\t\t\t\tplaceholder: $( this.document[ 0 ].getElementById( myId + "-placeholder" ) )\n
\t\t\t};\n
\t\t} else {\n
\t\t\tthis._ui = this._enhance( theElement, myId );\n
\t\t\tthis._applyTransition( currentOptions.transition );\n
\t\t}\n
\t\tthis\n
\t\t\t._setTolerance( currentOptions.tolerance )\n
\t\t\t._ui.focusElement = this._ui.container;\n
\n
\t\t// Event handlers\n
\t\tthis._on( this._ui.screen, { "vclick": "_eatEventAndClose" } );\n
\t\tthis._on( this.window, {\n
\t\t\torientationchange: $.proxy( this, "_handleWindowOrientationchange" ),\n
\t\t\tresize: $.proxy( this, "_handleWindowResize" ),\n
\t\t\tkeyup: $.proxy( this, "_handleWindowKeyUp" )\n
\t\t});\n
\t\tthis._on( this.document, { "focusin": "_handleDocumentFocusIn" } );\n
\t},\n
\n
\t_enhance: function( theElement, myId ) {\n
\t\tvar currentOptions = this.options,\n
\t\t\twrapperClass = currentOptions.wrapperClass,\n
\t\t\tui = {\n
\t\t\t\tscreen: $( "<div class=\'ui-screen-hidden ui-popup-screen " +\n
\t\t\t\tthis._themeClassFromOption( "ui-overlay-", currentOptions.overlayTheme ) + "\'></div>" ),\n
\t\t\t\tplaceholder: $( "<div style=\'display: none;\'><!-- placeholder --></div>" ),\n
\t\t\t\tcontainer: $( "<div class=\'ui-popup-container ui-popup-hidden ui-popup-truncate" +\n
\t\t\t\t\t( wrapperClass ? ( " " + wrapperClass ) : "" ) + "\'></div>" )\n
\t\t\t},\n
\t\t\tfragment = this.document[ 0 ].createDocumentFragment();\n
\n
\t\tfragment.appendChild( ui.screen[ 0 ] );\n
\t\tfragment.appendChild( ui.container[ 0 ] );\n
\n
\t\tif ( myId ) {\n
\t\t\tui.screen.attr( "id", myId + "-screen" );\n
\t\t\tui.container.attr( "id", myId + "-popup" );\n
\t\t\tui.placeholder\n
\t\t\t\t.attr( "id", myId + "-placeholder" )\n
\t\t\t\t.html( "<!-- placeholder for " + myId + " -->" );\n
\t\t}\n
\n
\t\t// Apply the proto\n
\t\tthis._page[ 0 ].appendChild( fragment );\n
\t\t// Leave a placeholder where the element used to be\n
\t\tui.placeholder.insertAfter( theElement );\n
\t\ttheElement\n
\t\t\t.detach()\n
\t\t\t.addClass( "ui-popup " +\n
\t\t\t\tthis._themeClassFromOption( "ui-body-", currentOptions.theme ) + " " +\n
\t\t\t\t( currentOptions.shadow ? "ui-overlay-shadow " : "" ) +\n
\t\t\t\t( currentOptions.corners ? "ui-corner-all " : "" ) )\n
\t\t\t.appendTo( ui.container );\n
\n
\t\treturn ui;\n
\t},\n
\n
\t_eatEventAndClose: function( theEvent ) {\n
\t\ttheEvent.preventDefault();\n
\t\ttheEvent.stopImmediatePropagation();\n
\t\tif ( this.options.dismissible ) {\n
\t\t\tthis.close();\n
\t\t}\n
\t\treturn false;\n
\t},\n
\n
\t// Make sure the screen covers the entire document - CSS is sometimes not\n
\t// enough to accomplish this.\n
\t_resizeScreen: function() {\n
\t\tvar screen = this._ui.screen,\n
\t\t\tpopupHeight = this._ui.container.outerHeight( true ),\n
\t\t\tscreenHeight = screen.removeAttr( "style" ).height(),\n
\n
\t\t\t// Subtracting 1 here is necessary for an obscure Andrdoid 4.0 bug where\n
\t\t\t// the browser hangs if the screen covers the entire document :/\n
\t\t\tdocumentHeight = this.document.height() - 1;\n
\n
\t\tif ( screenHeight < documentHeight ) {\n
\t\t\tscreen.height( documentHeight );\n
\t\t} else if ( popupHeight > screenHeight ) {\n
\t\t\tscreen.height( popupHeight );\n
\t\t}\n
\t},\n
\n
\t_handleWindowKeyUp: function( theEvent ) {\n
\t\tif ( this._isOpen && theEvent.keyCode === $.mobile.keyCode.ESCAPE ) {\n
\t\t\treturn this._eatEventAndClose( theEvent );\n
\t\t}\n
\t},\n
\n
\t_expectResizeEvent: function() {\n
\t\tvar windowCoordinates = getWindowCoordinates( this.window );\n
\n
\t\tif ( this._resizeData ) {\n
\t\t\tif ( windowCoordinates.x === this._resizeData.windowCoordinates.x &&\n
\t\t\t\twindowCoordinates.y === this._resizeData.windowCoordinates.y &&\n
\t\t\t\twindowCoordinates.cx === this._resizeData.windowCoordinates.cx &&\n
\t\t\t\twindowCoordinates.cy === this._resizeData.windowCoordinates.cy ) {\n
\t\t\t\t// timeout not refreshed\n
\t\t\t\treturn false;\n
\t\t\t} else {\n
\t\t\t\t// clear existing timeout - it will be refreshed below\n
\t\t\t\tclearTimeout( this._resizeData.timeoutId );\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis._resizeData = {\n
\t\t\ttimeoutId: this._delay( "_resizeTimeout", 200 ),\n
\t\t\twindowCoordinates: windowCoordinates\n
\t\t};\n
\n
\t\treturn true;\n
\t},\n
\n
\t_resizeTimeout: function() {\n
\t\tif ( this._isOpen ) {\n
\t\t\tif ( !this._expectResizeEvent() ) {\n
\t\t\t\tif ( this._ui.container.hasClass( "ui-popup-hidden" ) ) {\n
\t\t\t\t\t// effectively rapid-open the popup while leaving the screen intact\n
\t\t\t\t\tthis._ui.container.removeClass( "ui-popup-hidden ui-popup-truncate" );\n
\t\t\t\t\tthis.reposition( { positionTo: "window" } );\n
\t\t\t\t\tthis._ignoreResizeEvents();\n
\t\t\t\t}\n
\n
\t\t\t\tthis._resizeScreen();\n
\t\t\t\tthis._resizeData = null;\n
\t\t\t\tthis._orientationchangeInProgress = false;\n
\t\t\t}\n
\t\t} else {\n
\t\t\tthis._resizeData = null;\n
\t\t\tthis._orientationchangeInProgress = false;\n
\t\t}\n
\t},\n
\n
\t_stopIgnoringResizeEvents: function() {\n
\t\tthis._ignoreResizeTo = 0;\n
\t},\n
\n
\t_ignoreResizeEvents: function() {\n
\t\tif ( this._ignoreResizeTo ) {\n
\t\t\tclearTimeout( this._ignoreResizeTo );\n
\t\t}\n
\t\tthis._ignoreResizeTo = this._delay( "_stopIgnoringResizeEvents", 1000 );\n
\t},\n
\n
\t_handleWindowResize: function(/* theEvent */) {\n
\t\tif ( this._isOpen && this._ignoreResizeTo === 0 ) {\n
\t\t\tif ( ( this._expectResizeEvent() || this._orientationchangeInProgress ) &&\n
\t\t\t\t!this._ui.container.hasClass( "ui-popup-hidden" ) ) {\n
\t\t\t\t// effectively rapid-close the popup while leaving the screen intact\n
\t\t\t\tthis._ui.container\n
\t\t\t\t\t.addClass( "ui-popup-hidden ui-popup-truncate" )\n
\t\t\t\t\t.removeAttr( "style" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_handleWindowOrientationchange: function(/* theEvent */) {\n
\t\tif ( !this._orientationchangeInProgress && this._isOpen && this._ignoreResizeTo === 0 ) {\n
\t\t\tthis._expectResizeEvent();\n
\t\t\tthis._orientationchangeInProgress = true;\n
\t\t}\n
\t},\n
\n
\t// When the popup is open, attempting to focus on an element that is not a\n
\t// child of the popup will redirect focus to the popup\n
\t_handleDocumentFocusIn: function( theEvent ) {\n
\t\tvar target,\n
\t\t\ttargetElement = theEvent.target,\n
\t\t\tui = this._ui;\n
\n
\t\tif ( !this._isOpen ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( targetElement !== ui.container[ 0 ] ) {\n
\t\t\ttarget = $( targetElement );\n
\t\t\tif ( 0 === target.parents().filter( ui.container[ 0 ] ).length ) {\n
\t\t\t\t$( this.document[ 0 ].activeElement ).one( "focus", function(/* theEvent */) {\n
\t\t\t\t\tif ( targetElement.nodeName.toLowerCase() !== "body" ) {\n
\t\t\t\t            target.blur();\n
\t\t\t\t        }\n
\t\t\t\t});\n
\t\t\t\tui.focusElement.focus();\n
\t\t\t\ttheEvent.preventDefault();\n
\t\t\t\ttheEvent.stopImmediatePropagation();\n
\t\t\t\treturn false;\n
\t\t\t} else if ( ui.focusElement[ 0 ] === ui.container[ 0 ] ) {\n
\t\t\t\tui.focusElement = target;\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis._ignoreResizeEvents();\n
\t},\n
\n
\t_themeClassFromOption: function( prefix, value ) {\n
\t\treturn ( value ? ( value === "none" ? "" : ( prefix + value ) ) : ( prefix + "inherit" ) );\n
\t},\n
\n
\t_applyTransition: function( value ) {\n
\t\tif ( value ) {\n
\t\t\tthis._ui.container.removeClass( this._fallbackTransition );\n
\t\t\tif ( value !== "none" ) {\n
\t\t\t\tthis._fallbackTransition = $.mobile._maybeDegradeTransition( value );\n
\t\t\t\tif ( this._fallbackTransition === "none" ) {\n
\t\t\t\t\tthis._fallbackTransition = "";\n
\t\t\t\t}\n
\t\t\t\tthis._ui.container.addClass( this._fallbackTransition );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\t_setOptions: function( newOptions ) {\n
\t\tvar currentOptions = this.options,\n
\t\t\ttheElement = this.element,\n
\t\t\tscreen = this._ui.screen;\n
\n
\t\tif ( newOptions.wrapperClass !== undefined ) {\n
\t\t\tthis._ui.container\n
\t\t\t\t.removeClass( currentOptions.wrapperClass )\n
\t\t\t\t.addClass( newOptions.wrapperClass );\n
\t\t}\n
\n
\t\tif ( newOptions.theme !== undefined ) {\n
\t\t\ttheElement\n
\t\t\t\t.removeClass( this._themeClassFromOption( "ui-body-", currentOptions.theme ) )\n
\t\t\t\t.addClass( this._themeClassFromOption( "ui-body-", newOptions.theme ) );\n
\t\t}\n
\n
\t\tif ( newOptions.overlayTheme !== undefined ) {\n
\t\t\tscreen\n
\t\t\t\t.removeClass( this._themeClassFromOption( "ui-overlay-", currentOptions.overlayTheme ) )\n
\t\t\t\t.addClass( this._themeClassFromOption( "ui-overlay-", newOptions.overlayTheme ) );\n
\n
\t\t\tif ( this._isOpen ) {\n
\t\t\t\tscreen.addClass( "in" );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( newOptions.shadow !== undefined ) {\n
\t\t\ttheElement.toggleClass( "ui-overlay-shadow", newOptions.shadow );\n
\t\t}\n
\n
\t\tif ( newOptions.corners !== undefined ) {\n
\t\t\ttheElement.toggleClass( "ui-corner-all", newOptions.corners );\n
\t\t}\n
\n
\t\tif ( newOptions.transition !== undefined ) {\n
\t\t\tif ( !this._currentTransition ) {\n
\t\t\t\tthis._applyTransition( newOptions.transition );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( newOptions.tolerance !== undefined ) {\n
\t\t\tthis._setTolerance( newOptions.tolerance );\n
\t\t}\n
\n
\t\tif ( newOptions.disabled !== undefined ) {\n
\t\t\tif ( newOptions.disabled ) {\n
\t\t\t\tthis.close();\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this._super( newOptions );\n
\t},\n
\n
\t_setTolerance: function( value ) {\n
\t\tvar tol = { t: 30, r: 15, b: 30, l: 15 },\n
\t\t\tar;\n
\n
\t\tif ( value !== undefined ) {\n
\t\t\tar = String( value ).split( "," );\n
\n
\t\t\t$.each( ar, function( idx, val ) { ar[ idx ] = parseInt( val, 10 ); } );\n
\n
\t\t\tswitch( ar.length ) {\n
\t\t\t\t// All values are to be the same\n
\t\t\t\tcase 1:\n
\t\t\t\t\tif ( !isNaN( ar[ 0 ] ) ) {\n
\t\t\t\t\t\ttol.t = tol.r = tol.b = tol.l = ar[ 0 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\n
\t\t\t\t// The first value denotes top/bottom tolerance, and the second value denotes left/right tolerance\n
\t\t\t\tcase 2:\n
\t\t\t\t\tif ( !isNaN( ar[ 0 ] ) ) {\n
\t\t\t\t\t\ttol.t = tol.b = ar[ 0 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( !isNaN( ar[ 1 ] ) ) {\n
\t\t\t\t\t\ttol.l = tol.r = ar[ 1 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\n
\t\t\t\t// The array contains values in the order top, right, bottom, left\n
\t\t\t\tcase 4:\n
\t\t\t\t\tif ( !isNaN( ar[ 0 ] ) ) {\n
\t\t\t\t\t\ttol.t = ar[ 0 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( !isNaN( ar[ 1 ] ) ) {\n
\t\t\t\t\t\ttol.r = ar[ 1 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( !isNaN( ar[ 2 ] ) ) {\n
\t\t\t\t\t\ttol.b = ar[ 2 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( !isNaN( ar[ 3 ] ) ) {\n
\t\t\t\t\t\ttol.l = ar[ 3 ];\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\n
\t\t\t\tdefault:\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis._tolerance = tol;\n
\t\treturn this;\n
\t},\n
\n
\t_clampPopupWidth: function( infoOnly ) {\n
\t\tvar menuSize,\n
\t\t\twindowCoordinates = getWindowCoordinates( this.window ),\n
\t\t\t// rectangle within which the popup must fit\n
\t\t\trectangle = {\n
\t\t\t\tx: this._tolerance.l,\n
\t\t\t\ty: windowCoordinates.y + this._tolerance.t,\n
\t\t\t\tcx: windowCoordinates.cx - this._tolerance.l - this._tolerance.r,\n
\t\t\t\tcy: windowCoordinates.cy - this._tolerance.t - this._tolerance.b\n
\t\t\t};\n
\n
\t\tif ( !infoOnly ) {\n
\t\t\t// Clamp the width of the menu before grabbing its size\n
\t\t\tthis._ui.container.css( "max-width", rectangle.cx );\n
\t\t}\n
\n
\t\tmenuSize = {\n
\t\t\tcx: this._ui.container.outerWidth( true ),\n
\t\t\tcy: this._ui.container.outerHeight( true )\n
\t\t};\n
\n
\t\treturn { rc: rectangle, menuSize: menuSize };\n
\t},\n
\n
\t_calculateFinalLocation: function( desired, clampInfo ) {\n
\t\tvar returnValue,\n
\t\t\trectangle = clampInfo.rc,\n
\t\t\tmenuSize = clampInfo.menuSize;\n
\n
\t\t// Center the menu over the desired coordinates, while not going outside\n
\t\t// the window tolerances. This will center wrt. the window if the popup is\n
\t\t// too large.\n
\t\treturnValue = {\n
\t\t\tleft: fitSegmentInsideSegment( rectangle.cx, menuSize.cx, rectangle.x, desired.x ),\n
\t\t\ttop: fitSegmentInsideSegment( rectangle.cy, menuSize.cy, rectangle.y, desired.y )\n
\t\t};\n
\n
\t\t// Make sure the top of the menu is visible\n
\t\treturnValue.top = Math.max( 0, returnValue.top );\n
\n
\t\t// If the height of the menu is smaller than the height of the document\n
\t\t// align the bottom with the bottom of the document\n
\n
\t\treturnValue.top -= Math.min( returnValue.top,\n
\t\t\tMath.max( 0, returnValue.top + menuSize.cy - this.document.height() ) );\n
\n
\t\treturn returnValue;\n
\t},\n
\n
\t// Try and center the overlay over the given coordinates\n
\t_placementCoords: function( desired ) {\n
\t\treturn this._calculateFinalLocation( desired, this._clampPopupWidth() );\n
\t},\n
\n
\t_createPrerequisites: function( screenPrerequisite, containerPrerequisite, whenDone ) {\n
\t\tvar prerequisites,\n
\t\t\tself = this;\n
\n
\t\t// It is important to maintain both the local variable prerequisites and\n
\t\t// self._prerequisites. The local variable remains in the closure of the\n
\t\t// functions which call the callbacks passed in. The comparison between the\n
\t\t// local variable and self._prerequisites is necessary, because once a\n
\t\t// function has been passed to .animationComplete() it will be called next\n
\t\t// time an animation completes, even if that\'s not the animation whose end\n
\t\t// the function was supposed to catch (for example, if an abort happens\n
\t\t// during the opening animation, the .animationComplete handler is not\n
\t\t// called for that animation anymore, but the handler remains attached, so\n
\t\t// it is called the next time the popup is opened - making it stale.\n
\t\t// Comparing the local variable prerequisites to the widget-level variable\n
\t\t// self._prerequisites ensures that callbacks triggered by a stale\n
\t\t// .animationComplete will be ignored.\n
\n
\t\tprerequisites = {\n
\t\t\tscreen: $.Deferred(),\n
\t\t\tcontainer: $.Deferred()\n
\t\t};\n
\n
\t\tprerequisites.screen.then( function() {\n
\t\t\tif ( prerequisites === self._prerequisites ) {\n
\t\t\t\tscreenPrerequisite();\n
\t\t\t}\n
\t\t});\n
\n
\t\tprerequisites.container.then( function() {\n
\t\t\tif ( prerequisites === self._prerequisites ) {\n
\t\t\t\tcontainerPrerequisite();\n
\t\t\t}\n
\t\t});\n
\n
\t\t$.when( prerequisites.screen, prerequisites.container ).done( function() {\n
\t\t\tif ( prerequisites === self._prerequisites ) {\n
\t\t\t\tself._prerequisites = null;\n
\t\t\t\twhenDone();\n
\t\t\t}\n
\t\t});\n
\n
\t\tself._prerequisites = prerequisites;\n
\t},\n
\n
\t_animate: function( args ) {\n
\t\t// NOTE before removing the default animation of the screen\n
\t\t//      this had an animate callback that would resolve the deferred\n
\t\t//      now the deferred is resolved immediately\n
\t\t// TODO remove the dependency on the screen deferred\n
\t\tthis._ui.screen\n
\t\t\t.removeClass( args.classToRemove )\n
\t\t\t.addClass( args.screenClassToAdd );\n
\n
\t\targs.prerequisites.screen.resolve();\n
\n
\t\tif ( args.transition && args.transition !== "none" ) {\n
\t\t\tif ( args.applyTransition ) {\n
\t\t\t\tthis._applyTransition( args.transition );\n
\t\t\t}\n
\t\t\tif ( this._fallbackTransition ) {\n
\t\t\t\tthis._ui.container\n
\t\t\t\t\t.addClass( args.containerClassToAdd )\n
\t\t\t\t\t.removeClass( args.classToRemove )\n
\t\t\t\t\t.animationComplete( $.proxy( args.prerequisites.container, "resolve" ) );\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t}\n
\t\tthis._ui.container.removeClass( args.classToRemove );\n
\t\targs.prerequisites.container.resolve();\n
\t},\n
\n
\t// The desired coordinates passed in will be returned untouched if no reference element can be identified via\n
\t// desiredPosition.positionTo. Nevertheless, this function ensures that its return value always contains valid\n
\t// x and y coordinates by specifying the center middle of the window if the coordinates are absent.\n
\t// options: { x: coordinate, y: coordinate, positionTo: string: "origin", "window", or jQuery selector\n
\t_desiredCoords: function( openOptions ) {\n
\t\tvar offset,\n
\t\t\tdst = null,\n
\t\t\twindowCoordinates = getWindowCoordinates( this.window ),\n
\t\t\tx = openOptions.x,\n
\t\t\ty = openOptions.y,\n
\t\t\tpTo = openOptions.positionTo;\n
\n
\t\t// Establish which element will serve as the reference\n
\t\tif ( pTo && pTo !== "origin" ) {\n
\t\t\tif ( pTo === "window" ) {\n
\t\t\t\tx = windowCoordinates.cx / 2 + windowCoordinates.x;\n
\t\t\t\ty = windowCoordinates.cy / 2 + windowCoordinates.y;\n
\t\t\t} else {\n
\t\t\t\ttry {\n
\t\t\t\t\tdst = $( pTo );\n
\t\t\t\t} catch( err ) {\n
\t\t\t\t\tdst = null;\n
\t\t\t\t}\n
\t\t\t\tif ( dst ) {\n
\t\t\t\t\tdst.filter( ":visible" );\n
\t\t\t\t\tif ( dst.length === 0 ) {\n
\t\t\t\t\t\tdst = null;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// If an element was found, center over it\n
\t\tif ( dst ) {\n
\t\t\toffset = dst.offset();\n
\t\t\tx = offset.left + dst.outerWidth() / 2;\n
\t\t\ty = offset.top + dst.outerHeight() / 2;\n
\t\t}\n
\n
\t\t// Make sure x and y are valid numbers - center over the window\n
\t\tif ( $.type( x ) !== "number" || isNaN( x ) ) {\n
\t\t\tx = windowCoordinates.cx / 2 + windowCoordinates.x;\n
\t\t}\n
\t\tif ( $.type( y ) !== "number" || isNaN( y ) ) {\n
\t\t\ty = windowCoordinates.cy / 2 + windowCoordinates.y;\n
\t\t}\n
\n
\t\treturn { x: x, y: y };\n
\t},\n
\n
\t_reposition: function( openOptions ) {\n
\t\t// We only care about position-related parameters for repositioning\n
\t\topenOptions = {\n
\t\t\tx: openOptions.x,\n
\t\t\ty: openOptions.y,\n
\t\t\tpositionTo: openOptions.positionTo\n
\t\t};\n
\t\tthis._trigger( "beforeposition", undefined, openOptions );\n
\t\tthis._ui.container.offset( this._placementCoords( this._desiredCoords( openOptions ) ) );\n
\t},\n
\n
\treposition: function( openOptions ) {\n
\t\tif ( this._isOpen ) {\n
\t\t\tthis._reposition( openOptions );\n
\t\t}\n
\t},\n
\n
\t_openPrerequisitesComplete: function() {\n
\t\tvar id = this.element.attr( "id" );\n
\n
\t\tthis._ui.container.addClass( "ui-popup-active" );\n
\t\tthis._isOpen = true;\n
\t\tthis._resizeScreen();\n
\t\tthis._ui.container.attr( "tabindex", "0" ).focus();\n
\t\tthis._ignoreResizeEvents();\n
\t\tif ( id ) {\n
\t\t\tthis.document.find( "[aria-haspopup=\'true\'][aria-owns=\'" +  id + "\']" ).attr( "aria-expanded", true );\n
\t\t}\n
\t\tthis._trigger( "afteropen" );\n
\t},\n
\n
\t_open: function( options ) {\n
\t\tvar openOptions = $.extend( {}, this.options, options ),\n
\t\t\t// TODO move blacklist to private method\n
\t\t\tandroidBlacklist = ( function() {\n
\t\t\t\tvar ua = navigator.userAgent,\n
\t\t\t\t\t// Rendering engine is Webkit, and capture major version\n
\t\t\t\t\twkmatch = ua.match( /AppleWebKit\\/([0-9\\.]+)/ ),\n
\t\t\t\t\twkversion = !!wkmatch && wkmatch[ 1 ],\n
\t\t\t\t\tandroidmatch = ua.match( /Android (\\d+(?:\\.\\d+))/ ),\n
\t\t\t\t\tandversion = !!androidmatch && androidmatch[ 1 ],\n
\t\t\t\t\tchromematch = ua.indexOf( "Chrome" ) > -1;\n
\n
\t\t\t\t// Platform is Android, WebKit version is greater than 534.13 ( Android 3.2.1 ) and not Chrome.\n
\t\t\t\tif ( androidmatch !== null && andversion === "4.0" && wkversion && wkversion > 534.13 && !chromematch ) {\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\t\t\t\treturn false;\n
\t\t\t}());\n
\n
\t\t// Count down to triggering "popupafteropen" - we have two prerequisites:\n
\t\t// 1. The popup window animation completes (container())\n
\t\t// 2. The screen opacity animation completes (screen())\n
\t\tthis._createPrerequisites(\n
\t\t\t$.noop,\n
\t\t\t$.noop,\n
\t\t\t$.proxy( this, "_openPrerequisitesComplete" ) );\n
\n
\t\tthis._currentTransition = openOptions.transition;\n
\t\tthis._applyTransition( openOptions.transition );\n
\n
\t\tthis._ui.screen.removeClass( "ui-screen-hidden" );\n
\t\tthis._ui.container.removeClass( "ui-popup-truncate" );\n
\n
\t\t// Give applications a chance to modify the contents of the container before it appears\n
\t\tthis._reposition( openOptions );\n
\n
\t\tthis._ui.container.removeClass( "ui-popup-hidden" );\n
\n
\t\tif ( this.options.overlayTheme && androidBlacklist ) {\n
\t\t\t/* TODO: The native browser on Android 4.0.X ("Ice Cream Sandwich") suffers from an issue where the popup overlay appears to be z-indexed above the popup itself when certain other styles exist on the same page -- namely, any element set to `position: fixed` and certain types of input. These issues are reminiscent of previously uncovered bugs in older versions of Android\'s native browser: https://github.com/scottjehl/Device-Bugs/issues/3\n
\t\t\tThis fix closes the following bugs ( I use "closes" with reluctance, and stress that this issue should be revisited as soon as possible ):\n
\t\t\thttps://github.com/jquery/jquery-mobile/issues/4816\n
\t\t\thttps://github.com/jquery/jquery-mobile/issues/4844\n
\t\t\thttps://github.com/jquery/jquery-mobile/issues/4874\n
\t\t\t*/\n
\n
\t\t\t// TODO sort out why this._page isn\'t working\n
\t\t\tthis.element.closest( ".ui-page" ).addClass( "ui-popup-open" );\n
\t\t}\n
\t\tthis._animate({\n
\t\t\tadditionalCondition: true,\n
\t\t\ttransition: openOptions.transition,\n
\t\t\tclassToRemove: "",\n
\t\t\tscreenClassToAdd: "in",\n
\t\t\tcontainerClassToAdd: "in",\n
\t\t\tapplyTransition: false,\n
\t\t\tprerequisites: this._prerequisites\n
\t\t});\n
\t},\n
\n
\t_closePrerequisiteScreen: function() {\n
\t\tthis._ui.screen\n
\t\t\t.removeClass( "out" )\n
\t\t\t.addClass( "ui-screen-hidden" );\n
\t},\n
\n
\t_closePrerequisiteContainer: function() {\n
\t\tthis._ui.container\n
\t\t\t.removeClass( "reverse out" )\n
\t\t\t.addClass( "ui-popup-hidden ui-popup-truncate" )\n
\t\t\t.removeAttr( "style" );\n
\t},\n
\n
\t_closePrerequisitesDone: function() {\n
\t\tvar container = this._ui.container,\n
\t\t\tid = this.element.attr( "id" );\n
\n
\t\tcontainer.removeAttr( "tabindex" );\n
\n
\t\t// remove the global mutex for popups\n
\t\t$.mobile.popup.active = undefined;\n
\n
\t\t// Blur elements inside the container, including the container\n
\t\t$( ":focus", container[ 0 ] ).add( container[ 0 ] ).blur();\n
\n
\t\tif ( id ) {\n
\t\t\tthis.document.find( "[aria-haspopup=\'true\'][aria-owns=\'" +  id + "\']" ).attr( "aria-expanded", false );\n
\t\t}\n
\n
\t\t// alert users that the popup is closed\n
\t\tthis._trigger( "afterclose" );\n
\t},\n
\n
\t_close: function( immediate ) {\n
\t\tthis._ui.container.removeClass( "ui-popup-active" );\n
\t\tthis._page.removeClass( "ui-popup-open" );\n
\n
\t\tthis._isOpen = false;\n
\n
\t\t// Count down to triggering "popupafterclose" - we have two prerequisites:\n
\t\t// 1. The popup window reverse animation completes (container())\n
\t\t// 2. The screen opacity animation completes (screen())\n
\t\tthis._createPrerequisites(\n
\t\t\t$.proxy( this, "_closePrerequisiteScreen" ),\n
\t\t\t$.proxy( this, "_closePrerequisiteContainer" ),\n
\t\t\t$.proxy( this, "_closePrerequisitesDone" ) );\n
\n
\t\tthis._animate( {\n
\t\t\tadditionalCondition: this._ui.screen.hasClass( "in" ),\n
\t\t\ttransition: ( immediate ? "none" : ( this._currentTransition ) ),\n
\t\t\tclassToRemove: "in",\n
\t\t\tscreenClassToAdd: "out",\n
\t\t\tcontainerClassToAdd: "reverse out",\n
\t\t\tapplyTransition: true,\n
\t\t\tprerequisites: this._prerequisites\n
\t\t});\n
\t},\n
\n
\t_unenhance: function() {\n
\t\tif ( this.options.enhanced ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Put the element back to where the placeholder was and remove the "ui-popup" class\n
\t\tthis._setOptions( { theme: $.mobile.popup.prototype.options.theme } );\n
\t\tthis.element\n
\t\t\t// Cannot directly insertAfter() - we need to detach() first, because\n
\t\t\t// insertAfter() will do nothing if the payload div was not attached\n
\t\t\t// to the DOM at the time the widget was created, and so the payload\n
\t\t\t// will remain inside the container even after we call insertAfter().\n
\t\t\t// If that happens and we remove the container a few lines below, we\n
\t\t\t// will cause an infinite recursion - #5244\n
\t\t\t.detach()\n
\t\t\t.insertAfter( this._ui.placeholder )\n
\t\t\t.removeClass( "ui-popup ui-overlay-shadow ui-corner-all ui-body-inherit" );\n
\t\tthis._ui.screen.remove();\n
\t\tthis._ui.container.remove();\n
\t\tthis._ui.placeholder.remove();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tif ( $.mobile.popup.active === this ) {\n
\t\t\tthis.element.one( "popupafterclose", $.proxy( this, "_unenhance" ) );\n
\t\t\tthis.close();\n
\t\t} else {\n
\t\t\tthis._unenhance();\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\t_closePopup: function( theEvent, data ) {\n
\t\tvar parsedDst, toUrl,\n
\t\t\tcurrentOptions = this.options,\n
\t\t\timmediate = false;\n
\n
\t\tif ( ( theEvent && theEvent.isDefaultPrevented() ) || $.mobile.popup.active !== this ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// restore location on screen\n
\t\twindow.scrollTo( 0, this._scrollTop );\n
\n
\t\tif ( theEvent && theEvent.type === "pagebeforechange" && data ) {\n
\t\t\t// Determine whether we need to rapid-close the popup, or whether we can\n
\t\t\t// take the time to run the closing transition\n
\t\t\tif ( typeof data.toPage === "string" ) {\n
\t\t\t\tparsedDst = data.toPage;\n
\t\t\t} else {\n
\t\t\t\tparsedDst = data.toPage.jqmData( "url" );\n
\t\t\t}\n
\t\t\tparsedDst = $.mobile.path.parseUrl( parsedDst );\n
\t\t\ttoUrl = parsedDst.pathname + parsedDst.search + parsedDst.hash;\n
\n
\t\t\tif ( this._myUrl !== $.mobile.path.makeUrlAbsolute( toUrl ) ) {\n
\t\t\t\t// Going to a different page - close immediately\n
\t\t\t\timmediate = true;\n
\t\t\t} else {\n
\t\t\t\ttheEvent.preventDefault();\n
\t\t\t}\n
\t\t}\n
\n
\t\t// remove nav bindings\n
\t\tthis.window.off( currentOptions.closeEvents );\n
\t\t// unbind click handlers added when history is disabled\n
\t\tthis.element.undelegate( currentOptions.closeLinkSelector, currentOptions.closeLinkEvents );\n
\n
\t\tthis._close( immediate );\n
\t},\n
\n
\t// any navigation event after a popup is opened should close the popup\n
\t// NOTE the pagebeforechange is bound to catch navigation events that don\'t\n
\t//      alter the url (eg, dialogs from popups)\n
\t_bindContainerClose: function() {\n
\t\tthis.window\n
\t\t\t.on( this.options.closeEvents, $.proxy( this, "_closePopup" ) );\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this._ui.container;\n
\t},\n
\n
\t// TODO no clear deliniation of what should be here and\n
\t// what should be in _open. Seems to be "visual" vs "history" for now\n
\topen: function( options ) {\n
\t\tvar url, hashkey, activePage, currentIsDialog, hasHash, urlHistory,\n
\t\t\tself = this,\n
\t\t\tcurrentOptions = this.options;\n
\n
\t\t// make sure open is idempotent\n
\t\tif ( $.mobile.popup.active || currentOptions.disabled ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// set the global popup mutex\n
\t\t$.mobile.popup.active = this;\n
\t\tthis._scrollTop = this.window.scrollTop();\n
\n
\t\t// if history alteration is disabled close on navigate events\n
\t\t// and leave the url as is\n
\t\tif ( !( currentOptions.history ) ) {\n
\t\t\tself._open( options );\n
\t\t\tself._bindContainerClose();\n
\n
\t\t\t// When histoy is disabled we have to grab the data-rel\n
\t\t\t// back link clicks so we can close the popup instead of\n
\t\t\t// relying on history to do it for us\n
\t\t\tself.element\n
\t\t\t\t.delegate( currentOptions.closeLinkSelector, currentOptions.closeLinkEvents, function( theEvent ) {\n
\t\t\t\t\tself.close();\n
\t\t\t\t\ttheEvent.preventDefault();\n
\t\t\t\t});\n
\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// cache some values for min/readability\n
\t\turlHistory = $.mobile.navigate.history;\n
\t\thashkey = $.mobile.dialogHashKey;\n
\t\tactivePage = $.mobile.activePage;\n
\t\tcurrentIsDialog = ( activePage ? activePage.hasClass( "ui-dialog" ) : false );\n
\t\tthis._myUrl = url = urlHistory.getActive().url;\n
\t\thasHash = ( url.indexOf( hashkey ) > -1 ) && !currentIsDialog && ( urlHistory.activeIndex > 0 );\n
\n
\t\tif ( hasHash ) {\n
\t\t\tself._open( options );\n
\t\t\tself._bindContainerClose();\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// if the current url has no dialog hash key proceed as normal\n
\t\t// otherwise, if the page is a dialog simply tack on the hash key\n
\t\tif ( url.indexOf( hashkey ) === -1 && !currentIsDialog ) {\n
\t\t\turl = url + (url.indexOf( "#" ) > -1 ? hashkey : "#" + hashkey);\n
\t\t} else {\n
\t\t\turl = $.mobile.path.parseLocation().hash + hashkey;\n
\t\t}\n
\n
\t\t// swallow the the initial navigation event, and bind for the next\n
\t\tthis.window.one( "beforenavigate", function( theEvent ) {\n
\t\t\ttheEvent.preventDefault();\n
\t\t\tself._open( options );\n
\t\t\tself._bindContainerClose();\n
\t\t});\n
\n
\t\tthis.urlAltered = true;\n
\t\t$.mobile.navigate( url, { role: "dialog" } );\n
\n
\t\treturn this;\n
\t},\n
\n
\tclose: function() {\n
\t\t// make sure close is idempotent\n
\t\tif ( $.mobile.popup.active !== this ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tthis._scrollTop = this.window.scrollTop();\n
\n
\t\tif ( this.options.history && this.urlAltered ) {\n
\t\t\t$.mobile.back();\n
\t\t\tthis.urlAltered = false;\n
\t\t} else {\n
\t\t\t// simulate the nav bindings having fired\n
\t\t\tthis._closePopup();\n
\t\t}\n
\n
\t\treturn this;\n
\t}\n
});\n
\n
// TODO this can be moved inside the widget\n
$.mobile.popup.handleLink = function( $link ) {\n
\tvar offset,\n
\t\tpath = $.mobile.path,\n
\n
\t\t// NOTE make sure to get only the hash from the href because ie7 (wp7)\n
\t\t//      returns the absolute href in this case ruining the element selection\n
\t\tpopup = $( path.hashToSelector( path.parseUrl( $link.attr( "href" ) ).hash ) ).first();\n
\n
\tif ( popup.length > 0 && popup.data( "mobile-popup" ) ) {\n
\t\toffset = $link.offset();\n
\t\tpopup.popup( "open", {\n
\t\t\tx: offset.left + $link.outerWidth() / 2,\n
\t\t\ty: offset.top + $link.outerHeight() / 2,\n
\t\t\ttransition: $link.jqmData( "transition" ),\n
\t\t\tpositionTo: $link.jqmData( "position-to" )\n
\t\t});\n
\t}\n
\n
\t//remove after delay\n
\tsetTimeout( function() {\n
\t\t$link.removeClass( $.mobile.activeBtnClass );\n
\t}, 300 );\n
};\n
\n
// TODO move inside _create\n
$.mobile.document.on( "pagebeforechange", function( theEvent, data ) {\n
\tif ( data.options.role === "popup" ) {\n
\t\t$.mobile.popup.handleLink( data.options.link );\n
\t\ttheEvent.preventDefault();\n
\t}\n
});\n
\n
})( jQuery );\n
\n
/*\n
* custom "selectmenu" plugin\n
*/\n
\n
(function( $, undefined ) {\n
\n
var unfocusableItemSelector = ".ui-disabled,.ui-state-disabled,.ui-li-divider,.ui-screen-hidden,:jqmData(role=\'placeholder\')",\n
\tgoToAdjacentItem = function( item, target, direction ) {\n
\t\tvar adjacent = item[ direction + "All" ]()\n
\t\t\t.not( unfocusableItemSelector )\n
\t\t\t.first();\n
\n
\t\t// if there\'s a previous option, focus it\n
\t\tif ( adjacent.length ) {\n
\t\t\ttarget\n
\t\t\t\t.blur()\n
\t\t\t\t.attr( "tabindex", "-1" );\n
\n
\t\t\tadjacent.find( "a" ).first().focus();\n
\t\t}\n
\t};\n
\n
$.widget( "mobile.selectmenu", $.mobile.selectmenu, {\n
\t_create: function() {\n
\t\tvar o = this.options;\n
\n
\t\t// Custom selects cannot exist inside popups, so revert the "nativeMenu"\n
\t\t// option to true if a parent is a popup\n
\t\to.nativeMenu = o.nativeMenu || ( this.element.parents( ":jqmData(role=\'popup\'),:mobile-popup" ).length > 0 );\n
\n
\t\treturn this._super();\n
\t},\n
\n
\t_handleSelectFocus: function() {\n
\t\tthis.element.blur();\n
\t\tthis.button.focus();\n
\t},\n
\n
\t_handleKeydown: function( event ) {\n
\t\tthis._super( event );\n
\t\tthis._handleButtonVclickKeydown( event );\n
\t},\n
\n
\t_handleButtonVclickKeydown: function( event ) {\n
\t\tif ( this.options.disabled || this.isOpen || this.options.nativeMenu ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (event.type === "vclick" ||\n
\t\t\t\tevent.keyCode && (event.keyCode === $.mobile.keyCode.ENTER || event.keyCode === $.mobile.keyCode.SPACE)) {\n
\n
\t\t\tthis._decideFormat();\n
\t\t\tif ( this.menuType === "overlay" ) {\n
\t\t\t\tthis.button.attr( "href", "#" + this.popupId ).attr( "data-" + ( $.mobile.ns || "" ) + "rel", "popup" );\n
\t\t\t} else {\n
\t\t\t\tthis.button.attr( "href", "#" + this.dialogId ).attr( "data-" + ( $.mobile.ns || "" ) + "rel", "dialog" );\n
\t\t\t}\n
\t\t\tthis.isOpen = true;\n
\t\t\t// Do not prevent default, so the navigation may have a chance to actually open the chosen format\n
\t\t}\n
\t},\n
\n
\t_handleListFocus: function( e ) {\n
\t\tvar params = ( e.type === "focusin" ) ?\n
\t\t\t{ tabindex: "0", event: "vmouseover" }:\n
\t\t\t{ tabindex: "-1", event: "vmouseout" };\n
\n
\t\t$( e.target )\n
\t\t\t.attr( "tabindex", params.tabindex )\n
\t\t\t.trigger( params.event );\n
\t},\n
\n
\t_handleListKeydown: function( event ) {\n
\t\tvar target = $( event.target ),\n
\t\t\tli = target.closest( "li" );\n
\n
\t\t// switch logic based on which key was pressed\n
\t\tswitch ( event.keyCode ) {\n
\t\t\t// up or left arrow keys\n
\t\tcase 38:\n
\t\t\tgoToAdjacentItem( li, target, "prev" );\n
\t\t\treturn false;\n
\t\t\t// down or right arrow keys\n
\t\tcase 40:\n
\t\t\tgoToAdjacentItem( li, target, "next" );\n
\t\t\treturn false;\n
\t\t\t// If enter or space is pressed, trigger click\n
\t\tcase 13:\n
\t\tcase 32:\n
\t\t\ttarget.trigger( "click" );\n
\t\t\treturn false;\n
\t\t}\n
\t},\n
\n
\t_handleMenuPageHide: function() {\n
\n
\t\t// After the dialog\'s done, we may want to trigger change if the value has actually changed\n
\t\tthis._delayedTrigger();\n
\n
\t\t// TODO centralize page removal binding / handling in the page plugin.\n
\t\t// Suggestion from @jblas to do refcounting\n
\t\t//\n
\t\t// TODO extremely confusing dependency on the open method where the pagehide.remove\n
\t\t// bindings are stripped to prevent the parent page from disappearing. The way\n
\t\t// we\'re keeping pages in the DOM right now sucks\n
\t\t//\n
\t\t// rebind the page remove that was unbound in the open function\n
\t\t// to allow for the parent page removal from actions other than the use\n
\t\t// of a dialog sized custom select\n
\t\t//\n
\t\t// doing this here provides for the back button on the custom select dialog\n
\t\tthis.thisPage.page( "bindRemove" );\n
\t},\n
\n
\t_handleHeaderCloseClick: function() {\n
\t\tif ( this.menuType === "overlay" ) {\n
\t\t\tthis.close();\n
\t\t\treturn false;\n
\t\t}\n
\t},\n
\n
\t_handleListItemClick: function( event ) {\n
\t\tvar listItem = $( event.target ).closest( "li" ),\n
\n
\t\t\t// Index of option tag to be selected\n
\t\t\toldIndex = this.select[ 0 ].selectedIndex,\n
\t\t\tnewIndex = $.mobile.getAttribute( listItem, "option-index" ),\n
\t\t\toption = this._selectOptions().eq( newIndex )[ 0 ];\n
\n
\t\t// Toggle selected status on the tag for multi selects\n
\t\toption.selected = this.isMultiple ? !option.selected : true;\n
\n
\t\t// Toggle checkbox class for multiple selects\n
\t\tif ( this.isMultiple ) {\n
\t\t\tlistItem.find( "a" )\n
\t\t\t\t.toggleClass( "ui-checkbox-on", option.selected )\n
\t\t\t\t.toggleClass( "ui-checkbox-off", !option.selected );\n
\t\t}\n
\n
\t\t// If it\'s not a multiple select, trigger change after it has finished closing\n
\t\tif ( !this.isMultiple && oldIndex !== newIndex ) {\n
\t\t\tthis._triggerChange = true;\n
\t\t}\n
\n
\t\t// Trigger change if it\'s a multiple select\n
\t\t// Hide custom select for single selects only - otherwise focus clicked item\n
\t\t// We need to grab the clicked item the hard way, because the list may have been rebuilt\n
\t\tif ( this.isMultiple ) {\n
\t\t\tthis.select.trigger( "change" );\n
\t\t\tthis.list.find( "li:not(.ui-li-divider)" ).eq( newIndex )\n
\t\t\t\t.find( "a" ).first().focus();\n
\t\t}\n
\t\telse {\n
\t\t\tthis.close();\n
\t\t}\n
\n
\t\tevent.preventDefault();\n
\t},\n
\n
\tbuild: function() {\n
\t\tvar selectId, popupId, dialogId, label, thisPage, isMultiple, menuId,\n
\t\t\tthemeAttr, overlayTheme, overlayThemeAttr, dividerThemeAttr,\n
\t\t\tmenuPage, listbox, list, header, headerTitle, menuPageContent,\n
\t\t\tmenuPageClose, headerClose,\n
\t\t\to = this.options;\n
\n
\t\tif ( o.nativeMenu ) {\n
\t\t\treturn this._super();\n
\t\t}\n
\n
\t\tselectId = this.selectId;\n
\t\tpopupId = selectId + "-listbox";\n
\t\tdialogId = selectId + "-dialog";\n
\t\tlabel = this.label;\n
\t\tthisPage = this.element.closest( ".ui-page" );\n
\t\tisMultiple = this.element[ 0 ].multiple;\n
\t\tmenuId = selectId + "-menu";\n
\t\tthemeAttr = o.theme ? ( " data-" + $.mobile.ns + "theme=\'" + o.theme + "\'" ) : "";\n
\t\toverlayTheme = o.overlayTheme || o.theme || null;\n
\t\toverlayThemeAttr = overlayTheme ? ( " data-" + $.mobile.ns +\n
\t\t\t"overlay-theme=\'" + overlayTheme + "\'" ) : "";\n
\t\tdividerThemeAttr = ( o.dividerTheme && isMultiple ) ? ( " data-" + $.mobile.ns + "divider-theme=\'" + o.dividerTheme + "\'" ) : "";\n
\t\tmenuPage = $( "<div data-" + $.mobile.ns + "role=\'dialog\' class=\'ui-selectmenu\' id=\'" + dialogId + "\'" + themeAttr + overlayThemeAttr + ">" +\n
\t\t\t"<div data-" + $.mobile.ns + "role=\'header\'>" +\n
\t\t\t"<div class=\'ui-title\'></div>"+\n
\t\t\t"</div>"+\n
\t\t\t"<div data-" + $.mobile.ns + "role=\'content\'></div>"+\n
\t\t\t"</div>" );\n
\t\tlistbox = $( "<div" + themeAttr + overlayThemeAttr + " id=\'" + popupId +\n
\t\t\t\t"\' class=\'ui-selectmenu\'></div>" )\n
\t\t\t.insertAfter( this.select )\n
\t\t\t.popup();\n
\t\tlist = $( "<ul class=\'ui-selectmenu-list\' id=\'" + menuId + "\' role=\'listbox\' aria-labelledby=\'" + this.buttonId + "\'" + themeAttr + dividerThemeAttr + "></ul>" ).appendTo( listbox );\n
\t\theader = $( "<div class=\'ui-header ui-bar-" + ( o.theme ? o.theme : "inherit" ) + "\'></div>" ).prependTo( listbox );\n
\t\theaderTitle = $( "<h1 class=\'ui-title\'></h1>" ).appendTo( header );\n
\n
\t\tif ( this.isMultiple ) {\n
\t\t\theaderClose = $( "<a>", {\n
\t\t\t\t"role": "button",\n
\t\t\t\t"text": o.closeText,\n
\t\t\t\t"href": "#",\n
\t\t\t\t"class": "ui-btn ui-corner-all ui-btn-left ui-btn-icon-notext ui-icon-delete"\n
\t\t\t}).appendTo( header );\n
\t\t}\n
\n
\t\t$.extend( this, {\n
\t\t\tselectId: selectId,\n
\t\t\tmenuId: menuId,\n
\t\t\tpopupId: popupId,\n
\t\t\tdialogId: dialogId,\n
\t\t\tthisPage: thisPage,\n
\t\t\tmenuPage: menuPage,\n
\t\t\tlabel: label,\n
\t\t\tisMultiple: isMultiple,\n
\t\t\ttheme: o.theme,\n
\t\t\tlistbox: listbox,\n
\t\t\tlist: list,\n
\t\t\theader: header,\n
\t\t\theaderTitle: headerTitle,\n
\t\t\theaderClose: headerClose,\n
\t\t\tmenuPageContent: menuPageContent,\n
\t\t\tmenuPageClose: menuPageClose,\n
\t\t\tplaceholder: ""\n
\t\t});\n
\n
\t\t// Create list from select, update state\n
\t\tthis.refresh();\n
\n
\t\tif ( this._origTabIndex === undefined ) {\n
\t\t\t// Map undefined to false, because this._origTabIndex === undefined\n
\t\t\t// indicates that we have not yet checked whether the select has\n
\t\t\t// originally had a tabindex attribute, whereas false indicates that\n
\t\t\t// we have checked the select for such an attribute, and have found\n
\t\t\t// none present.\n
\t\t\tthis._origTabIndex = ( this.select[ 0 ].getAttribute( "tabindex" ) === null ) ? false : this.select.attr( "tabindex" );\n
\t\t}\n
\t\tthis.select.attr( "tabindex", "-1" );\n
\t\tthis._on( this.select, { focus : "_handleSelectFocus" } );\n
\n
\t\t// Button events\n
\t\tthis._on( this.button, {\n
\t\t\tvclick: "_handleButtonVclickKeydown"\n
\t\t});\n
\n
\t\t// Events for list items\n
\t\tthis.list.attr( "role", "listbox" );\n
\t\tthis._on( this.list, {\n
\t\t\t"focusin": "_handleListFocus",\n
\t\t\t"focusout": "_handleListFocus",\n
\t\t\t"keydown": "_handleListKeydown",\n
\t\t\t"click li:not(.ui-disabled,.ui-state-disabled,.ui-li-divider)": "_handleListItemClick"\n
\t\t});\n
\n
\t\t// button refocus ensures proper height calculation\n
\t\t// by removing the inline style and ensuring page inclusion\n
\t\tthis._on( this.menuPage, { pagehide: "_handleMenuPageHide" } );\n
\n
\t\t// Events on the popup\n
\t\tthis._on( this.listbox, { popupafterclose: "_popupClosed" } );\n
\n
\t\t// Close button on small overlays\n
\t\tif ( this.isMultiple ) {\n
\t\t\tthis._on( this.headerClose, { click: "_handleHeaderCloseClick" } );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\t_popupClosed: function() {\n
\t\tthis.close();\n
\t\tthis._delayedTrigger();\n
\t},\n
\n
\t_delayedTrigger: function() {\n
\t\tif ( this._triggerChange ) {\n
\t\t\tthis.element.trigger( "change" );\n
\t\t}\n
\t\tthis._triggerChange = false;\n
\t},\n
\n
\t_isRebuildRequired: function() {\n
\t\tvar list = this.list.find( "li" ),\n
\t\t\toptions = this._selectOptions().not( ".ui-screen-hidden" );\n
\n
\t\t// TODO exceedingly naive method to determine difference\n
\t\t// ignores value changes etc in favor of a forcedRebuild\n
\t\t// from the user in the refresh method\n
\t\treturn options.text() !== list.text();\n
\t},\n
\n
\tselected: function() {\n
\t\treturn this._selectOptions().filter( ":selected:not( :jqmData(placeholder=\'true\') )" );\n
\t},\n
\n
\trefresh: function( force ) {\n
\t\tvar self, indices;\n
\n
\t\tif ( this.options.nativeMenu ) {\n
\t\t\treturn this._super( force );\n
\t\t}\n
\n
\t\tself = this;\n
\t\tif ( force || this._isRebuildRequired() ) {\n
\t\t\tself._buildList();\n
\t\t}\n
\n
\t\tindices = this.selectedIndices();\n
\n
\t\tself.setButtonText();\n
\t\tself.setButtonCount();\n
\n
\t\tself.list.find( "li:not(.ui-li-divider)" )\n
\t\t\t.find( "a" ).removeClass( $.mobile.activeBtnClass ).end()\n
\t\t\t.attr( "aria-selected", false )\n
\t\t\t.each(function( i ) {\n
\n
\t\t\t\tif ( $.inArray( i, indices ) > -1 ) {\n
\t\t\t\t\tvar item = $( this );\n
\n
\t\t\t\t\t// Aria selected attr\n
\t\t\t\t\titem.attr( "aria-selected", true );\n
\n
\t\t\t\t\t// Multiple selects: add the "on" checkbox state to the icon\n
\t\t\t\t\tif ( self.isMultiple ) {\n
\t\t\t\t\t\titem.find( "a" ).removeClass( "ui-checkbox-off" ).addClass( "ui-checkbox-on" );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif ( item.hasClass( "ui-screen-hidden" ) ) {\n
\t\t\t\t\t\t\titem.next().find( "a" ).addClass( $.mobile.activeBtnClass );\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\titem.find( "a" ).addClass( $.mobile.activeBtnClass );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t},\n
\n
\tclose: function() {\n
\t\tif ( this.options.disabled || !this.isOpen ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar self = this;\n
\n
\t\tif ( self.menuType === "page" ) {\n
\t\t\tself.menuPage.dialog( "close" );\n
\t\t\tself.list.appendTo( self.listbox );\n
\t\t} else {\n
\t\t\tself.listbox.popup( "close" );\n
\t\t}\n
\n
\t\tself._focusButton();\n
\t\t// allow the dialog to be closed again\n
\t\tself.isOpen = false;\n
\t},\n
\n
\topen: function() {\n
\t\tthis.button.click();\n
\t},\n
\n
\t_focusMenuItem: function() {\n
\t\tvar selector = this.list.find( "a." + $.mobile.activeBtnClass );\n
\t\tif ( selector.length === 0 ) {\n
\t\t\tselector = this.list.find( "li:not(" + unfocusableItemSelector + ") a.ui-btn" );\n
\t\t}\n
\t\tselector.first().focus();\n
\t},\n
\n
\t_decideFormat: function() {\n
\t\tvar self = this,\n
\t\t\t$window = this.window,\n
\t\t\tselfListParent = self.list.parent(),\n
\t\t\tmenuHeight = selfListParent.outerHeight(),\n
\t\t\tscrollTop = $window.scrollTop(),\n
\t\t\tbtnOffset = self.button.offset().top,\n
\t\t\tscreenHeight = $window.height();\n
\n
\t\tif ( menuHeight > screenHeight - 80 || !$.support.scrollTop ) {\n
\n
\t\t\tself.menuPage.appendTo( $.mobile.pageContainer ).page();\n
\t\t\tself.menuPageContent = self.menuPage.find( ".ui-content" );\n
\t\t\tself.menuPageClose = self.menuPage.find( ".ui-header a" );\n
\n
\t\t\t// prevent the parent page from being removed from the DOM,\n
\t\t\t// otherwise the results of selecting a list item in the dialog\n
\t\t\t// fall into a black hole\n
\t\t\tself.thisPage.unbind( "pagehide.remove" );\n
\n
\t\t\t//for WebOS/Opera Mini (set lastscroll using button offset)\n
\t\t\tif ( scrollTop === 0 && btnOffset > screenHeight ) {\n
\t\t\t\tself.thisPage.one( "pagehide", function() {\n
\t\t\t\t\t$( this ).jqmData( "lastScroll", btnOffset );\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tself.menuPage.one( {\n
\t\t\t\tpageshow: $.proxy( this, "_focusMenuItem" ),\n
\t\t\t\tpagehide: $.proxy( this, "close" )\n
\t\t\t});\n
\n
\t\t\tself.menuType = "page";\n
\t\t\tself.menuPageContent.append( self.list );\n
\t\t\tself.menuPage\n
\t\t\t\t.find( "div .ui-title" )\n
\t\t\t\t\t.text( self.label.getEncodedText() || self.placeholder );\n
\t\t} else {\n
\t\t\tself.menuType = "overlay";\n
\n
\t\t\tself.listbox.one( { popupafteropen: $.proxy( this, "_focusMenuItem" ) } );\n
\t\t}\n
\t},\n
\n
\t_buildList: function() {\n
\t\tvar self = this,\n
\t\t\to = this.options,\n
\t\t\tplaceholder = this.placeholder,\n
\t\t\tneedPlaceholder = true,\n
\t\t\tdataIcon = "false",\n
\t\t\t$options, numOptions, select,\n
\t\t\tdataPrefix = "data-" + $.mobile.ns,\n
\t\t\tdataIndexAttr = dataPrefix + "option-index",\n
\t\t\tdataIconAttr = dataPrefix + "icon",\n
\t\t\tdataRoleAttr = dataPrefix + "role",\n
\t\t\tdataPlaceholderAttr = dataPrefix + "placeholder",\n
\t\t\tfragment = document.createDocumentFragment(),\n
\t\t\tisPlaceholderItem = false,\n
\t\t\toptGroup,\n
\t\t\ti,\n
\t\t\toption, $option, parent, text, anchor, classes,\n
\t\t\toptLabel, divider, item;\n
\n
\t\tself.list.empty().filter( ".ui-listview" ).listview( "destroy" );\n
\t\t$options = this._selectOptions();\n
\t\tnumOptions = $options.length;\n
\t\tselect = this.select[ 0 ];\n
\n
\t\tfor ( i = 0; i < numOptions;i++, isPlaceholderItem = false) {\n
\t\t\toption = $options[i];\n
\t\t\t$option = $( option );\n
\n
\t\t\t// Do not create options based on ui-screen-hidden select options\n
\t\t\tif ( $option.hasClass( "ui-screen-hidden" ) ) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tparent = option.parentNode;\n
\t\t\tclasses = [];\n
\n
\t\t\t// Although using .text() here raises the risk that, when we later paste this into the\n
\t\t\t// list item we end up pasting possibly malicious things like <script> tags, that risk\n
\t\t\t// only arises if we do something like $( "<li><a href=\'#\'>" + text + "</a></li>" ). We\n
\t\t\t// don\'t do that. We do document.createTextNode( text ) instead, which guarantees that\n
\t\t\t// whatever we paste in will end up as text, with characters like <, > and & escaped.\n
\t\t\ttext = $option.text();\n
\t\t\tanchor = document.createElement( "a" );\n
\t\t\tanchor.setAttribute( "href", "#" );\n
\t\t\tanchor.appendChild( document.createTextNode( text ) );\n
\n
\t\t\t// Are we inside an optgroup?\n
\t\t\tif ( parent !== select && parent.nodeName.toLowerCase() === "optgroup" ) {\n
\t\t\t\toptLabel = parent.getAttribute( "label" );\n
\t\t\t\tif ( optLabel !== optGroup ) {\n
\t\t\t\t\tdivider = document.createElement( "li" );\n
\t\t\t\t\tdivider.setAttribute( dataRoleAttr, "list-divider" );\n
\t\t\t\t\tdivider.setAttribute( "role", "option" );\n
\t\t\t\t\tdivider.setAttribute( "tabindex", "-1" );\n
\t\t\t\t\tdivider.appendChild( document.createTextNode( optLabel ) );\n
\t\t\t\t\tfragment.appendChild( divider );\n
\t\t\t\t\toptGroup = optLabel;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( needPlaceholder && ( !option.getAttribute( "value" ) || text.length === 0 || $option.jqmData( "placeholder" ) ) ) {\n
\t\t\t\tneedPlaceholder = false;\n
\t\t\t\tisPlaceholderItem = true;\n
\n
\t\t\t\t// If we have identified a placeholder, record the fact that it was\n
\t\t\t\t// us who have added the placeholder to the option and mark it\n
\t\t\t\t// retroactively in the select as well\n
\t\t\t\tif ( null === option.getAttribute( dataPlaceholderAttr ) ) {\n
\t\t\t\t\tthis._removePlaceholderAttr = true;\n
\t\t\t\t}\n
\t\t\t\toption.setAttribute( dataPlaceholderAttr, true );\n
\t\t\t\tif ( o.hidePlaceholderMenuItems ) {\n
\t\t\t\t\tclasses.push( "ui-screen-hidden" );\n
\t\t\t\t}\n
\t\t\t\tif ( placeholder !== text ) {\n
\t\t\t\t\tplaceholder = self.placeholder = text;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\titem = document.createElement( "li" );\n
\t\t\tif ( option.disabled ) {\n
\t\t\t\tclasses.push( "ui-state-disabled" );\n
\t\t\t\titem.setAttribute( "aria-disabled", true );\n
\t\t\t}\n
\t\t\titem.setAttribute( dataIndexAttr, i );\n
\t\t\titem.setAttribute( dataIconAttr, dataIcon );\n
\t\t\tif ( isPlaceholderItem ) {\n
\t\t\t\titem.setAttribute( dataPlaceholderAttr, true );\n
\t\t\t}\n
\t\t\titem.className = classes.join( " " );\n
\t\t\titem.setAttribute( "role", "option" );\n
\t\t\tanchor.setAttribute( "tabindex", "-1" );\n
\t\t\tif ( this.isMultiple ) {\n
\t\t\t\t$( anchor ).addClass( "ui-btn ui-checkbox-off ui-btn-icon-right" );\n
\t\t\t}\n
\n
\t\t\titem.appendChild( anchor );\n
\t\t\tfragment.appendChild( item );\n
\t\t}\n
\n
\t\tself.list[0].appendChild( fragment );\n
\n
\t\t// Hide header if it\'s not a multiselect and there\'s no placeholder\n
\t\tif ( !this.isMultiple && !placeholder.length ) {\n
\t\t\tthis.header.addClass( "ui-screen-hidden" );\n
\t\t} else {\n
\t\t\tthis.headerTitle.text( this.placeholder );\n
\t\t}\n
\n
\t\t// Now populated, create listview\n
\t\tself.list.listview();\n
\t},\n
\n
\t_button: function() {\n
\t\treturn this.options.nativeMenu ?\n
\t\t\tthis._super() :\n
\t\t\t$( "<a>", {\n
\t\t\t\t"href": "#",\n
\t\t\t\t"role": "button",\n
\t\t\t\t// TODO value is undefined at creation\n
\t\t\t\t"id": this.buttonId,\n
\t\t\t\t"aria-haspopup": "true",\n
\n
\t\t\t\t// TODO value is undefined at creation\n
\t\t\t\t"aria-owns": this.menuId\n
\t\t\t});\n
\t},\n
\n
\t_destroy: function() {\n
\n
\t\tif ( !this.options.nativeMenu ) {\n
\t\t\tthis.close();\n
\n
\t\t\t// Restore the tabindex attribute to its original value\n
\t\t\tif ( this._origTabIndex !== undefined ) {\n
\t\t\t\tif ( this._origTabIndex !== false ) {\n
\t\t\t\t\tthis.select.attr( "tabindex", this._origTabIndex );\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.select.removeAttr( "tabindex" );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Remove the placeholder attribute if we were the ones to add it\n
\t\t\tif ( this._removePlaceholderAttr ) {\n
\t\t\t\tthis._selectOptions().removeAttr( "data-" + $.mobile.ns + "placeholder" );\n
\t\t\t}\n
\n
\t\t\t// Remove the popup\n
\t\t\tthis.listbox.remove();\n
\n
\t\t\t// Remove the dialog\n
\t\t\tthis.menuPage.remove();\n
\t\t}\n
\n
\t\t// Chain up\n
\t\tthis._super();\n
\t}\n
});\n
\n
})( jQuery );\n
\n
\n
// buttonMarkup is deprecated as of 1.4.0 and will be removed in 1.5.0.\n
\n
(function( $, undefined ) {\n
\n
// General policy: Do not access data-* attributes except during enhancement.\n
// In all other cases we determine the state of the button exclusively from its\n
// className. That\'s why optionsToClasses expects a full complement of options,\n
// and the jQuery plugin completes the set of options from the default values.\n
\n
// Map classes to buttonMarkup boolean options - used in classNameToOptions()\n
var reverseBoolOptionMap = {\n
\t\t"ui-shadow" : "shadow",\n
\t\t"ui-corner-all" : "corners",\n
\t\t"ui-btn-inline" : "inline",\n
\t\t"ui-shadow-icon" : "iconshadow", /* TODO: Remove in 1.5 */\n
\t\t"ui-mini" : "mini"\n
\t},\n
\tgetAttrFixed = function() {\n
\t\tvar ret = $.mobile.getAttribute.apply( this, arguments );\n
\n
\t\treturn ( ret == null ? undefined : ret );\n
\t},\n
\tcapitalLettersRE = /[A-Z]/g;\n
\n
// optionsToClasses:\n
// @options: A complete set of options to convert to class names.\n
// @existingClasses: extra classes to add to the result\n
//\n
// Converts @options to buttonMarkup classes and returns the result as an array\n
// that can be converted to an element\'s className with .join( " " ). All\n
// possible options must be set inside @options. Use $.fn.buttonMarkup.defaults\n
// to get a complete set and use $.extend to override your choice of options\n
// from that set.\n
function optionsToClasses( options, existingClasses ) {\n
\tvar classes = existingClasses ? existingClasses : [];\n
\n
\t// Add classes to the array - first ui-btn\n
\tclasses.push( "ui-btn" );\n
\n
\t// If there is a theme\n
\tif ( options.theme ) {\n
\t\tclasses.push( "ui-btn-" + options.theme );\n
\t}\n
\n
\t// If there\'s an icon, add the icon-related classes\n
\tif ( options.icon ) {\n
\t\tclasses = classes.concat([\n
\t\t\t"ui-icon-" + options.icon,\n
\t\t\t"ui-btn-icon-" + options.iconpos\n
\t\t]);\n
\t\tif ( options.iconshadow ) {\n
\t\t\tclasses.push( "ui-shadow-icon" ); /* TODO: Remove in 1.5 */\n
\t\t}\n
\t}\n
\n
\t// Add the appropriate class for each boolean option\n
\tif ( options.inline ) {\n
\t\tclasses.push( "ui-btn-inline" );\n
\t}\n
\tif ( options.shadow ) {\n
\t\tclasses.push( "ui-shadow" );\n
\t}\n
\tif ( options.corners ) {\n
\t\tclasses.push( "ui-corner-all" );\n
\t}\n
\tif ( options.mini ) {\n
\t\tclasses.push( "ui-mini" );\n
\t}\n
\n
\t// Create a string from the array and return it\n
\treturn classes;\n
}\n
\n
// classNameToOptions:\n
// @classes: A string containing a .className-style space-separated class list\n
//\n
// Loops over @classes and calculates an options object based on the\n
// buttonMarkup-related classes it finds. It records unrecognized classes in an\n
// array.\n
//\n
// Returns: An object containing the following items:\n
//\n
// "options": buttonMarkup options found to be present because of the\n
// presence/absence of corresponding classes\n
//\n
// "unknownClasses": a string containing all the non-buttonMarkup-related\n
// classes found in @classes\n
//\n
// "alreadyEnhanced": A boolean indicating whether the ui-btn class was among\n
// those found to be present\n
function classNameToOptions( classes ) {\n
\tvar idx, map, unknownClass,\n
\t\talreadyEnhanced = false,\n
\t\tnoIcon = true,\n
\t\to = {\n
\t\t\ticon: "",\n
\t\t\tinline: false,\n
\t\t\tshadow: false,\n
\t\t\tcorners: false,\n
\t\t\ticonshadow: false,\n
\t\t\tmini: false\n
\t\t},\n
\t\tunknownClasses = [];\n
\n
\tclasses = classes.split( " " );\n
\n
\t// Loop over the classes\n
\tfor ( idx = 0 ; idx < classes.length ; idx++ ) {\n
\n
\t\t// Assume it\'s an unrecognized class\n
\t\tunknownClass = true;\n
\n
\t\t// Recognize boolean options from the presence of classes\n
\t\tmap = reverseBoolOptionMap[ classes[ idx ] ];\n
\t\tif ( map !== undefined ) {\n
\t\t\tunknownClass = false;\n
\t\t\to[ map ] = true;\n
\n
\t\t// Recognize the presence of an icon and establish the icon position\n
\t\t} else if ( classes[ idx ].indexOf( "ui-btn-icon-" ) === 0 ) {\n
\t\t\tunknownClass = false;\n
\t\t\tnoIcon = false;\n
\t\t\to.iconpos = classes[ idx ].substring( 12 );\n
\n
\t\t// Establish which icon is present\n
\t\t} else if ( classes[ idx ].indexOf( "ui-icon-" ) === 0 ) {\n
\t\t\tunknownClass = false;\n
\t\t\to.icon = classes[ idx ].substring( 8 );\n
\n
\t\t// Establish the theme - this recognizes one-letter theme swatch names\n
\t\t} else if ( classes[ idx ].indexOf( "ui-btn-" ) === 0 && classes[ idx ].length === 8 ) {\n
\t\t\tunknownClass = false;\n
\t\t\to.theme = classes[ idx ].substring( 7 );\n
\n
\t\t// Recognize that this element has already been buttonMarkup-enhanced\n
\t\t} else if ( classes[ idx ] === "ui-btn" ) {\n
\t\t\tunknownClass = false;\n
\t\t\talreadyEnhanced = true;\n
\t\t}\n
\n
\t\t// If this class has not been recognized, add it to the list\n
\t\tif ( unknownClass ) {\n
\t\t\tunknownClasses.push( classes[ idx ] );\n
\t\t}\n
\t}\n
\n
\t// If a "ui-btn-icon-*" icon position class is absent there cannot be an icon\n
\tif ( noIcon ) {\n
\t\to.icon = "";\n
\t}\n
\n
\treturn {\n
\t\toptions: o,\n
\t\tunknownClasses: unknownClasses,\n
\t\talreadyEnhanced: alreadyEnhanced\n
\t};\n
}\n
\n
function camelCase2Hyphenated( c ) {\n
\treturn "-" + c.toLowerCase();\n
}\n
\n
// $.fn.buttonMarkup:\n
// DOM: gets/sets .className\n
//\n
// @options: options to apply to the elements in the jQuery object\n
// @overwriteClasses: boolean indicating whether to honour existing classes\n
//\n
// Calculates the classes to apply to the elements in the jQuery object based on\n
// the options passed in. If @overwriteClasses is true, it sets the className\n
// property of each element in the jQuery object to the buttonMarkup classes\n
// it calculates based on the options passed in.\n
//\n
// If you wish to preserve any classes that are already present on the elements\n
// inside the jQuery object, including buttonMarkup-related classes that were\n
// added by a previous call to $.fn.buttonMarkup() or during page enhancement\n
// then you should omit @overwriteClasses or set it to false.\n
$.fn.buttonMarkup = function( options, overwriteClasses ) {\n
\tvar idx, data, el, retrievedOptions, optionKey,\n
\t\tdefaults = $.fn.buttonMarkup.defaults;\n
\n
\tfor ( idx = 0 ; idx < this.length ; idx++ ) {\n
\t\tel = this[ idx ];\n
\t\tdata = overwriteClasses ?\n
\n
\t\t\t// Assume this element is not enhanced and ignore its classes\n
\t\t\t{ alreadyEnhanced: false, unknownClasses: [] } :\n
\n
\t\t\t// Otherwise analyze existing classes to establish existing options and\n
\t\t\t// classes\n
\t\t\tclassNameToOptions( el.className );\n
\n
\t\tretrievedOptions = $.extend( {},\n
\n
\t\t\t// If the element already has the class ui-btn, then we assume that\n
\t\t\t// it has passed through buttonMarkup before - otherwise, the options\n
\t\t\t// returned by classNameToOptions do not correctly reflect the state of\n
\t\t\t// the element\n
\t\t\t( data.alreadyEnhanced ? data.options : {} ),\n
\n
\t\t\t// Finally, apply the options passed in\n
\t\t\toptions );\n
\n
\t\t// If this is the first call on this element, retrieve remaining options\n
\t\t// from the data-attributes\n
\t\tif ( !data.alreadyEnhanced ) {\n
\t\t\tfor ( optionKey in defaults ) {\n
\t\t\t\tif ( retrievedOptions[ optionKey ] === undefined ) {\n
\t\t\t\t\tretrievedOptions[ optionKey ] = getAttrFixed( el,\n
\t\t\t\t\t\toptionKey.replace( capitalLettersRE, camelCase2Hyphenated )\n
\t\t\t\t\t);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tel.className = optionsToClasses(\n
\n
\t\t\t// Merge all the options and apply them as classes\n
\t\t\t$.extend( {},\n
\n
\t\t\t\t// The defaults form the basis\n
\t\t\t\tdefaults,\n
\n
\t\t\t\t// Add the computed options\n
\t\t\t\tretrievedOptions\n
\t\t\t),\n
\n
\t\t\t// ... and re-apply any unrecognized classes that were found\n
\t\t\tdata.unknownClasses ).join( " " );\n
\t\tif ( el.tagName.toLowerCase() !== "button" ) {\n
\t\t\tel.setAttribute( "role", "button" );\n
\t\t}\n
\t}\n
\n
\treturn this;\n
};\n
\n
// buttonMarkup defaults. This must be a complete set, i.e., a value must be\n
// given here for all recognized options\n
$.fn.buttonMarkup.defaults = {\n
\ticon: "",\n
\ticonpos: "left",\n
\ttheme: null,\n
\tinline: false,\n
\tshadow: true,\n
\tcorners: true,\n
\ticonshadow: false, /* TODO: Remove in 1.5. Option deprecated in 1.4. */\n
\tmini: false\n
};\n
\n
$.extend( $.fn.buttonMarkup, {\n
\tinitSelector: "a:jqmData(role=\'button\'), .ui-bar > a, .ui-bar > :jqmData(role=\'controlgroup\') > a, button:not(:jqmData(role=\'navbar\') button)"\n
});\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.controlgroup", $.extend( {\n
\toptions: {\n
\t\tenhanced: false,\n
\t\ttheme: null,\n
\t\tshadow: false,\n
\t\tcorners: true,\n
\t\texcludeInvisible: true,\n
\t\ttype: "vertical",\n
\t\tmini: false\n
\t},\n
\n
\t_create: function() {\n
\t\tvar elem = this.element,\n
\t\t\topts = this.options;\n
\n
\t\t// Run buttonmarkup\n
\t\tif ( $.fn.buttonMarkup ) {\n
\t\t\tthis.element.find( $.fn.buttonMarkup.initSelector ).buttonMarkup();\n
\t\t}\n
\t\t// Enhance child widgets\n
\t\t$.each( this._childWidgets, $.proxy( function( number, widgetName ) {\n
\t\t\tif ( $.mobile[ widgetName ] ) {\n
\t\t\t\tthis.element.find( $.mobile[ widgetName ].initSelector ).not( $.mobile.page.prototype.keepNativeSelector() )[ widgetName ]();\n
\t\t\t}\n
\t\t}, this ));\n
\n
\t\t$.extend( this, {\n
\t\t\t_ui: null,\n
\t\t\t_initialRefresh: true\n
\t\t});\n
\n
\t\tif ( opts.enhanced ) {\n
\t\t\tthis._ui = {\n
\t\t\t\tgroupLegend: elem.children( ".ui-controlgroup-label" ).children(),\n
\t\t\t\tchildWrapper: elem.children( ".ui-controlgroup-controls" )\n
\t\t\t};\n
\t\t} else {\n
\t\t\tthis._ui = this._enhance();\n
\t\t}\n
\n
\t},\n
\n
\t_childWidgets: [ "checkboxradio", "selectmenu", "button" ],\n
\n
\t_themeClassFromOption: function( value ) {\n
\t\treturn ( value ? ( value === "none" ? "" : "ui-group-theme-" + value ) : "" );\n
\t},\n
\n
\t_enhance: function() {\n
\t\tvar elem = this.element,\n
\t\t\topts = this.options,\n
\t\t\tui = {\n
\t\t\t\tgroupLegend: elem.children( "legend" ),\n
\t\t\t\tchildWrapper: elem\n
\t\t\t\t\t.addClass( "ui-controlgroup " +\n
\t\t\t\t\t\t"ui-controlgroup-" +\n
\t\t\t\t\t\t\t( opts.type === "horizontal" ? "horizontal" : "vertical" ) + " " +\n
\t\t\t\t\t\tthis._themeClassFromOption( opts.theme ) + " " +\n
\t\t\t\t\t\t( opts.corners ? "ui-corner-all " : "" ) +\n
\t\t\t\t\t\t( opts.mini ? "ui-mini " : "" ) )\n
\t\t\t\t\t.wrapInner( "<div " +\n
\t\t\t\t\t\t"class=\'ui-controlgroup-controls " +\n
\t\t\t\t\t\t\t( opts.shadow === true ? "ui-shadow" : "" ) + "\'></div>" )\n
\t\t\t\t\t.children()\n
\t\t\t};\n
\n
\t\tif ( ui.groupLegend.length > 0 ) {\n
\t\t\t$( "<div role=\'heading\' class=\'ui-controlgroup-label\'></div>" )\n
\t\t\t\t.append( ui.groupLegend )\n
\t\t\t\t.prependTo( elem );\n
\t\t}\n
\n
\t\treturn ui;\n
\t},\n
\n
\t_init: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar callRefresh, returnValue,\n
\t\t\telem = this.element;\n
\n
\t\t// Must have one of horizontal or vertical\n
\t\tif ( options.type !== undefined ) {\n
\t\t\telem\n
\t\t\t\t.removeClass( "ui-controlgroup-horizontal ui-controlgroup-vertical" )\n
\t\t\t\t.addClass( "ui-controlgroup-" + ( options.type === "horizontal" ? "horizontal" : "vertical" ) );\n
\t\t\tcallRefresh = true;\n
\t\t}\n
\n
\t\tif ( options.theme !== undefined ) {\n
\t\t\telem\n
\t\t\t\t.removeClass( this._themeClassFromOption( this.options.theme ) )\n
\t\t\t\t.addClass( this._themeClassFromOption( options.theme ) );\n
\t\t}\n
\n
\t\tif ( options.corners !== undefined ) {\n
\t\t\telem.toggleClass( "ui-corner-all", options.corners );\n
\t\t}\n
\n
\t\tif ( options.mini !== undefined ) {\n
\t\t\telem.toggleClass( "ui-mini", options.mini );\n
\t\t}\n
\n
\t\tif ( options.shadow !== undefined ) {\n
\t\t\tthis._ui.childWrapper.toggleClass( "ui-shadow", options.shadow );\n
\t\t}\n
\n
\t\tif ( options.excludeInvisible !== undefined ) {\n
\t\t\tthis.options.excludeInvisible = options.excludeInvisible;\n
\t\t\tcallRefresh = true;\n
\t\t}\n
\n
\t\treturnValue = this._super( options );\n
\n
\t\tif ( callRefresh ) {\n
\t\t\tthis.refresh();\n
\t\t}\n
\n
\t\treturn returnValue;\n
\t},\n
\n
\tcontainer: function() {\n
\t\treturn this._ui.childWrapper;\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar $el = this.container(),\n
\t\t\tels = $el.find( ".ui-btn" ).not( ".ui-slider-handle" ),\n
\t\t\tcreate = this._initialRefresh;\n
\t\tif ( $.mobile.checkboxradio ) {\n
\t\t\t$el.find( ":mobile-checkboxradio" ).checkboxradio( "refresh" );\n
\t\t}\n
\t\tthis._addFirstLastClasses( els,\n
\t\t\tthis.options.excludeInvisible ? this._getVisibles( els, create ) : els,\n
\t\t\tcreate );\n
\t\tthis._initialRefresh = false;\n
\t},\n
\n
\t// Caveat: If the legend is not the first child of the controlgroup at enhance\n
\t// time, it will be after _destroy().\n
\t_destroy: function() {\n
\t\tvar ui, buttons,\n
\t\t\topts = this.options;\n
\n
\t\tif ( opts.enhanced ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tui = this._ui;\n
\t\tbuttons = this.element\n
\t\t\t.removeClass( "ui-controlgroup " +\n
\t\t\t\t"ui-controlgroup-horizontal ui-controlgroup-vertical ui-corner-all ui-mini " +\n
\t\t\t\tthis._themeClassFromOption( opts.theme ) )\n
\t\t\t.find( ".ui-btn" )\n
\t\t\t.not( ".ui-slider-handle" );\n
\n
\t\tthis._removeFirstLastClasses( buttons );\n
\n
\t\tui.groupLegend.unwrap();\n
\t\tui.childWrapper.children().unwrap();\n
\t}\n
}, $.mobile.behaviors.addFirstLastClasses ) );\n
\n
})(jQuery);\n
\n
(function( $, undefined ) {\n
\n
\t$.widget( "mobile.toolbar", {\n
\t\tinitSelector: ":jqmData(role=\'footer\'), :jqmData(role=\'header\')",\n
\n
\t\toptions: {\n
\t\t\ttheme: null,\n
\t\t\taddBackBtn: false,\n
\t\t\tbackBtnTheme: null,\n
\t\t\tbackBtnText: "Back"\n
\t\t},\n
\n
\t\t_create: function() {\n
\t\t\tvar leftbtn, rightbtn,\n
\t\t\t\trole =  this.element.is( ":jqmData(role=\'header\')" ) ? "header" : "footer",\n
\t\t\t\tpage = this.element.closest( ".ui-page" );\n
\t\t\tif ( page.length === 0 ) {\n
\t\t\t\tpage = false;\n
\t\t\t\tthis._on( this.document, {\n
\t\t\t\t\t"pageshow": "refresh"\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t$.extend( this, {\n
\t\t\t\trole: role,\n
\t\t\t\tpage: page,\n
\t\t\t\tleftbtn: leftbtn,\n
\t\t\t\trightbtn: rightbtn\n
\t\t\t});\n
\t\t\tthis.element.attr( "role", role === "header" ? "banner" : "contentinfo" ).addClass( "ui-" + role );\n
\t\t\tthis.refresh();\n
\t\t\tthis._setOptions( this.options );\n
\t\t},\n
\t\t_setOptions: function( o ) {\n
\t\t\tif ( o.addBackBtn !== undefined ) {\n
\t\t\t\tthis._updateBackButton();\n
\t\t\t}\n
\t\t\tif ( o.backBtnTheme != null ) {\n
\t\t\t\tthis.element\n
\t\t\t\t\t.find( ".ui-toolbar-back-btn" )\n
\t\t\t\t\t.addClass( "ui-btn ui-btn-" + o.backBtnTheme );\n
\t\t\t}\n
\t\t\tif ( o.backBtnText !== undefined ) {\n
\t\t\t\tthis.element.find( ".ui-toolbar-back-btn .ui-btn-text" ).text( o.backBtnText );\n
\t\t\t}\n
\t\t\tif ( o.theme !== undefined ) {\n
\t\t\t\tvar currentTheme = this.options.theme ? this.options.theme : "inherit",\n
\t\t\t\t\tnewTheme = o.theme ? o.theme : "inherit";\n
\n
\t\t\t\tthis.element.removeClass( "ui-bar-" + currentTheme ).addClass( "ui-bar-" + newTheme );\n
\t\t\t}\n
\n
\t\t\tthis._super( o );\n
\t\t},\n
\t\trefresh: function() {\n
\t\t\tif ( this.role === "header" ) {\n
\t\t\t\tthis._addHeaderButtonClasses();\n
\t\t\t}\n
\t\t\tif ( !this.page ) {\n
\t\t\t\tthis._setRelative();\n
\t\t\t\tif ( this.role === "footer" ) {\n
\t\t\t\t\tthis.element.appendTo( "body" );\n
\t\t\t\t} else if ( this.role === "header" ) {\n
\t\t\t\t\tthis._updateBackButton();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._addHeadingClasses();\n
\t\t\tthis._btnMarkup();\n
\t\t},\n
\n
\t\t//we only want this to run on non fixed toolbars so make it easy to override\n
\t\t_setRelative: function() {\n
\t\t\t$( "[data-"+ $.mobile.ns + "role=\'page\']" ).css({ "position": "relative" });\n
\t\t},\n
\n
\t\t// Deprecated in 1.4. As from 1.5 button classes have to be present in the markup.\n
\t\t_btnMarkup: function() {\n
\t\t\tthis.element\n
\t\t\t\t.children( "a" )\n
\t\t\t\t.filter( ":not([data-" + $.mobile.ns + "role=\'none\'])" )\n
\t\t\t\t.attr( "data-" + $.mobile.ns + "role", "button" );\n
\t\t\tthis.element.trigger( "create" );\n
\t\t},\n
\t\t// Deprecated in 1.4. As from 1.5 ui-btn-left/right classes have to be present in the markup.\n
\t\t_addHeaderButtonClasses: function() {\n
\t\t\tvar headerAnchors = this.element.children( "a, button" );\n
\n
\t\t\t// Do not mistake a back button for a left toolbar button\n
\t\t\tthis.leftbtn = headerAnchors.hasClass( "ui-btn-left" ) &&\n
\t\t\t\t!headerAnchors.hasClass( "ui-toolbar-back-btn" );\n
\n
\t\t\tthis.rightbtn = headerAnchors.hasClass( "ui-btn-right" );\n
\n
\t\t\t// Filter out right buttons and back buttons\n
\t\t\tthis.leftbtn = this.leftbtn ||\n
\t\t\t\theaderAnchors.eq( 0 )\n
\t\t\t\t\t.not( ".ui-btn-right,.ui-toolbar-back-btn" )\n
\t\t\t\t\t.addClass( "ui-btn-left" )\n
\t\t\t\t\t.length;\n
\n
\t\t\tthis.rightbtn = this.rightbtn || headerAnchors.eq( 1 ).addClass( "ui-btn-right" ).length;\n
\t\t},\n
\t\t_updateBackButton: function() {\n
\t\t\tvar backButton,\n
\t\t\t\toptions = this.options,\n
\t\t\t\ttheme = options.backBtnTheme || options.theme;\n
\n
\t\t\t// Retrieve the back button or create a new, empty one\n
\t\t\tbackButton = this._backButton = ( this._backButton || {} );\n
\n
\t\t\t// We add a back button only if the option to do so is on\n
\t\t\tif ( this.options.addBackBtn &&\n
\n
\t\t\t\t\t// This must also be a header toolbar\n
\t\t\t\t\tthis.role === "header" &&\n
\n
\t\t\t\t\t// There must be multiple pages in the DOM\n
\t\t\t\t\t$( ".ui-page" ).length > 1 &&\n
\t\t\t\t\t( this.page ?\n
\n
\t\t\t\t\t\t// If the toolbar is internal the page\'s URL must differ from the hash\n
\t\t\t\t\t\t( this.page[ 0 ].getAttribute( "data-" + $.mobile.ns + "url" ) !==\n
\t\t\t\t\t\t\t$.mobile.path.stripHash( location.hash ) ) :\n
\n
\t\t\t\t\t\t// Otherwise, if the toolbar is external there must be at least one\n
\t\t\t\t\t\t// history item to which one can go back\n
\t\t\t\t\t\t( $.mobile.navigate && $.mobile.navigate.history &&\n
\t\t\t\t\t\t\t$.mobile.navigate.history.activeIndex > 0 ) ) &&\n
\n
\t\t\t\t\t// The toolbar does not have a left button\n
\t\t\t\t\t!this.leftbtn ) {\n
\n
\t\t\t\t// Skip back button creation if one is already present\n
\t\t\t\tif ( !backButton.attached ) {\n
\t\t\t\t\tbackButton.element = ( backButton.element ||\n
\t\t\t\t\t\t$( "<a role=\'button\' href=\'javascript:void(0);\' " +\n
\t\t\t\t\t\t\t"class=\'ui-btn ui-corner-all ui-shadow ui-btn-left " +\n
\t\t\t\t\t\t\t\t( theme ? "ui-btn-" + theme + " " : "" ) +\n
\t\t\t\t\t\t\t\t"ui-toolbar-back-btn ui-icon-carat-l ui-btn-icon-left\' " +\n
\t\t\t\t\t\t\t"data-" + $.mobile.ns + "rel=\'back\'>" + options.backBtnText +\n
\t\t\t\t\t\t\t"</a>" ) )\n
\t\t\t\t\t\t\t.prependTo( this.element );\n
\t\t\t\t\tbackButton.attached = true;\n
\t\t\t\t}\n
\n
\t\t\t// If we are not adding a back button, then remove the one present, if any\n
\t\t\t} else if ( backButton.element ) {\n
\t\t\t\tbackButton.element.detach();\n
\t\t\t\tbackButton.attached = false;\n
\t\t\t}\n
\t\t},\n
\t\t_addHeadingClasses: function() {\n
\t\t\tthis.element.children( "h1, h2, h3, h4, h5, h6" )\n
\t\t\t\t.addClass( "ui-title" )\n
\t\t\t\t// Regardless of h element number in src, it becomes h1 for the enhanced page\n
\t\t\t\t.attr({\n
\t\t\t\t\t"role": "heading",\n
\t\t\t\t\t"aria-level": "1"\n
\t\t\t\t});\n
\t\t}\n
\t});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
\t$.widget( "mobile.toolbar", $.mobile.toolbar, {\n
\t\toptions: {\n
\t\t\tposition:null,\n
\t\t\tvisibleOnPageShow: true,\n
\t\t\tdisablePageZoom: true,\n
\t\t\ttransition: "slide", //can be none, fade, slide (slide maps to slideup or slidedown)\n
\t\t\tfullscreen: false,\n
\t\t\ttapToggle: true,\n
\t\t\ttapToggleBlacklist: "a, button, input, select, textarea, .ui-header-fixed, .ui-footer-fixed, .ui-flipswitch, .ui-popup, .ui-panel, .ui-panel-dismiss-open",\n
\t\t\thideDuringFocus: "input, textarea, select",\n
\t\t\tupdatePagePadding: true,\n
\t\t\ttrackPersistentToolbars: true,\n
\n
\t\t\t// Browser detection! Weeee, here we go...\n
\t\t\t// Unfortunately, position:fixed is costly, not to mention probably impossible, to feature-detect accurately.\n
\t\t\t// Some tests exist, but they currently return false results in critical devices and browsers, which could lead to a broken experience.\n
\t\t\t// Testing fixed positioning is also pretty obtrusive to page load, requiring injected elements and scrolling the window\n
\t\t\t// The following function serves to rule out some popular browsers with known fixed-positioning issues\n
\t\t\t// This is a plugin option like any other, so feel free to improve or overwrite it\n
\t\t\tsupportBlacklist: function() {\n
\t\t\t\treturn !$.support.fixedPosition;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_create: function() {\n
\t\t\tthis._super();\n
\t\t\tif ( this.options.position === "fixed" && !this.options.supportBlacklist() ) {\n
\t\t\t\tthis._makeFixed();\n
\t\t\t}\n
\t\t},\n
\n
\t\t_makeFixed: function() {\n
\t\t\tthis.element.addClass( "ui-"+ this.role +"-fixed" );\n
\t\t\tthis.updatePagePadding();\n
\t\t\tthis._addTransitionClass();\n
\t\t\tthis._bindPageEvents();\n
\t\t\tthis._bindToggleHandlers();\n
\t\t},\n
\n
\t\t_setOptions: function( o ) {\n
\t\t\tif ( o.position === "fixed" && this.options.position !== "fixed" ) {\n
\t\t\t\tthis._makeFixed();\n
\t\t\t}\n
\t\t\tif ( this.options.position === "fixed" && !this.options.supportBlacklist() ) {\n
\t\t\t\tvar $page = ( !!this.page )? this.page: ( $(".ui-page-active").length > 0 )? $(".ui-page-active"): $(".ui-page").eq(0);\n
\n
\t\t\t\tif ( o.fullscreen !== undefined) {\n
\t\t\t\t\tif ( o.fullscreen ) {\n
\t\t\t\t\t\tthis.element.addClass( "ui-"+ this.role +"-fullscreen" );\n
\t\t\t\t\t\t$page.addClass( "ui-page-" + this.role + "-fullscreen" );\n
\t\t\t\t\t}\n
\t\t\t\t\t// If not fullscreen, add class to page to set top or bottom padding\n
\t\t\t\t\telse {\n
\t\t\t\t\t\tthis.element.removeClass( "ui-"+ this.role +"-fullscreen" );\n
\t\t\t\t\t\t$page.removeClass( "ui-page-" + this.role + "-fullscreen" ).addClass( "ui-page-" + this.role+ "-fixed" );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._super(o);\n
\t\t},\n
\n
\t\t_addTransitionClass: function() {\n
\t\t\tvar tclass = this.options.transition;\n
\n
\t\t\tif ( tclass && tclass !== "none" ) {\n
\t\t\t\t// use appropriate slide for header or footer\n
\t\t\t\tif ( tclass === "slide" ) {\n
\t\t\t\t\ttclass = this.element.hasClass( "ui-header" ) ? "slidedown" : "slideup";\n
\t\t\t\t}\n
\n
\t\t\t\tthis.element.addClass( tclass );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_bindPageEvents: function() {\n
\t\t\tvar page = ( !!this.page )? this.element.closest( ".ui-page" ): this.document;\n
\t\t\t//page event bindings\n
\t\t\t// Fixed toolbars require page zoom to be disabled, otherwise usability issues crop up\n
\t\t\t// This method is meant to disable zoom while a fixed-positioned toolbar page is visible\n
\t\t\tthis._on( page , {\n
\t\t\t\t"pagebeforeshow": "_handlePageBeforeShow",\n
\t\t\t\t"webkitAnimationStart":"_handleAnimationStart",\n
\t\t\t\t"animationstart":"_handleAnimationStart",\n
\t\t\t\t"updatelayout": "_handleAnimationStart",\n
\t\t\t\t"pageshow": "_handlePageShow",\n
\t\t\t\t"pagebeforehide": "_handlePageBeforeHide"\n
\t\t\t});\n
\t\t},\n
\n
\t\t_handlePageBeforeShow: function( ) {\n
\t\t\tvar o = this.options;\n
\t\t\tif ( o.disablePageZoom ) {\n
\t\t\t\t$.mobile.zoom.disable( true );\n
\t\t\t}\n
\t\t\tif ( !o.visibleOnPageShow ) {\n
\t\t\t\tthis.hide( true );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_handleAnimationStart: function() {\n
\t\t\tif ( this.options.updatePagePadding ) {\n
\t\t\t\tthis.updatePagePadding( ( !!this.page )? this.page: ".ui-page-active" );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_handlePageShow: function() {\n
\t\t\tthis.updatePagePadding( ( !!this.page )? this.page: ".ui-page-active" );\n
\t\t\tif ( this.options.updatePagePadding ) {\n
\t\t\t\tthis._on( this.window, { "throttledresize": "updatePagePadding" } );\n
\t\t\t}\n
\t\t},\n
\n
\t\t_handlePageBeforeHide: function( e, ui ) {\n
\t\t\tvar o = this.options,\n
\t\t\t\tthisFooter, thisHeader, nextFooter, nextHeader;\n
\n
\t\t\tif ( o.disablePageZoom ) {\n
\t\t\t\t$.mobile.zoom.enable( true );\n
\t\t\t}\n
\t\t\tif ( o.updatePagePadding ) {\n
\t\t\t\tthis._off( this.window, "throttledresize" );\n
\t\t\t}\n
\n
\t\t\tif ( o.trackPersistentToolbars ) {\n
\t\t\t\tthisFooter = $( ".ui-footer-fixed:jqmData(id)", this.page );\n
\t\t\t\tthisHeader = $( ".ui-header-fixed:jqmData(id)", this.page );\n
\t\t\t\tnextFooter = thisFooter.length && ui.nextPage && $( ".ui-footer-fixed:jqmData(id=\'" + thisFooter.jqmData( "id" ) + "\')", ui.nextPage ) || $();\n
\t\t\t\tnextHeader = thisHeader.length && ui.nextPage && $( ".ui-header-fixed:jqmData(id=\'" + thisHeader.jqmData( "id" ) + "\')", ui.nextPage ) || $();\n
\n
\t\t\t\tif ( nextFooter.length || nextHeader.length ) {\n
\n
\t\t\t\t\tnextFooter.add( nextHeader ).appendTo( $.mobile.pageContainer );\n
\n
\t\t\t\t\tui.nextPage.one( "pageshow", function() {\n
\t\t\t\t\t\tnextHeader.prependTo( this );\n
\t\t\t\t\t\tnextFooter.appendTo( this );\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\t_visible: true,\n
\n
\t\t// This will set the content element\'s top or bottom padding equal to the toolbar\'s height\n
\t\tupdatePagePadding: function( tbPage ) {\n
\t\t\tvar $el = this.element,\n
\t\t\t\theader = ( this.role ==="header" ),\n
\t\t\t\tpos = parseFloat( $el.css( header ? "top" : "bottom" ) );\n
\n
\t\t\t// This behavior only applies to "fixed", not "fullscreen"\n
\t\t\tif ( this.options.fullscreen ) { return; }\n
\t\t\t// tbPage argument can be a Page object or an event, if coming from throttled resize.\n
\t\t\ttbPage = ( tbPage && tbPage.type === undefined && tbPage ) || this.page || $el.closest( ".ui-page" );\n
\t\t\ttbPage = ( !!this.page )? this.page: ".ui-page-active";\n
\t\t\t$( tbPage ).css( "padding-" + ( header ? "top" : "bottom" ), $el.outerHeight() + pos );\n
\t\t},\n
\n
\t\t_useTransition: function( notransition ) {\n
\t\t\tvar $win = this.window,\n
\t\t\t\t$el = this.element,\n
\t\t\t\tscroll = $win.scrollTop(),\n
\t\t\t\telHeight = $el.height(),\n
\t\t\t\tpHeight = ( !!this.page )? $el.closest( ".ui-page" ).height():$(".ui-page-active").height(),\n
\t\t\t\tviewportHeight = $.mobile.getScreenHeight();\n
\n
\t\t\treturn !notransition &&\n
\t\t\t\t( this.options.transition && this.options.transition !== "none" &&\n
\t\t\t\t(\n
\t\t\t\t\t( this.role === "header" && !this.options.fullscreen && scroll > elHeight ) ||\n
\t\t\t\t\t( this.role === "footer" && !this.options.fullscreen && scroll + viewportHeight < pHeight - elHeight )\n
\t\t\t\t) || this.options.fullscreen\n
\t\t\t\t);\n
\t\t},\n
\n
\t\tshow: function( notransition ) {\n
\t\t\tvar hideClass = "ui-fixed-hidden",\n
\t\t\t\t$el = this.element;\n
\n
\t\t\tif ( this._useTransition( notransition ) ) {\n
\t\t\t\t$el\n
\t\t\t\t\t.removeClass( "out " + hideClass )\n
\t\t\t\t\t.addClass( "in" )\n
\t\t\t\t\t.animationComplete(function () {\n
\t\t\t\t\t\t$el.removeClass( "in" );\n
\t\t\t\t\t});\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\t$el.removeClass( hideClass );\n
\t\t\t}\n
\t\t\tthis._visible = true;\n
\t\t},\n
\n
\t\thide: function( notransition ) {\n
\t\t\tvar hideClass = "ui-fixed-hidden",\n
\t\t\t\t$el = this.element,\n
\t\t\t\t// if it\'s a slide transition, our new transitions need the reverse class as well to slide outward\n
\t\t\t\toutclass = "out" + ( this.options.transition === "slide" ? " reverse" : "" );\n
\n
\t\t\tif ( this._useTransition( notransition ) ) {\n
\t\t\t\t$el\n
\t\t\t\t\t.addClass( outclass )\n
\t\t\t\t\t.removeClass( "in" )\n
\t\t\t\t\t.animationComplete(function() {\n
\t\t\t\t\t\t$el.addClass( hideClass ).removeClass( outclass );\n
\t\t\t\t\t});\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\t$el.addClass( hideClass ).removeClass( outclass );\n
\t\t\t}\n
\t\t\tthis._visible = false;\n
\t\t},\n
\n
\t\ttoggle: function() {\n
\t\t\tthis[ this._visible ? "hide" : "show" ]();\n
\t\t},\n
\n
\t\t_bindToggleHandlers: function() {\n
\t\t\tvar self = this,\n
\t\t\t\to = self.options,\n
\t\t\t\tdelayShow, delayHide,\n
\t\t\t\tisVisible = true,\n
\t\t\t\tpage = ( !!this.page )? this.page: $(".ui-page");\n
\n
\t\t\t// tap toggle\n
\t\t\tpage\n
\t\t\t\t.bind( "vclick", function( e ) {\n
\t\t\t\t\tif ( o.tapToggle && !$( e.target ).closest( o.tapToggleBlacklist ).length ) {\n
\t\t\t\t\t\tself.toggle();\n
\t\t\t\t\t}\n
\t\t\t\t})\n
\t\t\t\t.bind( "focusin focusout", function( e ) {\n
\t\t\t\t\t//this hides the toolbars on a keyboard pop to give more screen room and prevent ios bug which\n
\t\t\t\t\t//positions fixed toolbars in the middle of the screen on pop if the input is near the top or\n
\t\t\t\t\t//bottom of the screen addresses issues #4410 Footer navbar moves up when clicking on a textbox in an Android environment\n
\t\t\t\t\t//and issue #4113 Header and footer change their position after keyboard popup - iOS\n
\t\t\t\t\t//and issue #4410 Footer navbar moves up when clicking on a textbox in an Android environment\n
\t\t\t\t\tif ( screen.width < 1025 && $( e.target ).is( o.hideDuringFocus ) && !$( e.target ).closest( ".ui-header-fixed, .ui-footer-fixed" ).length ) {\n
\t\t\t\t\t\t//Fix for issue #4724 Moving through form in Mobile Safari with "Next" and "Previous" system\n
\t\t\t\t\t\t//controls causes fixed position, tap-toggle false Header to reveal itself\n
\t\t\t\t\t\t// isVisible instead of self._visible because the focusin and focusout events fire twice at the same time\n
\t\t\t\t\t\t// Also use a delay for hiding the toolbars because on Android native browser focusin is direclty followed\n
\t\t\t\t\t\t// by a focusout when a native selects opens and the other way around when it closes.\n
\t\t\t\t\t\tif ( e.type === "focusout" && !isVisible ) {\n
\t\t\t\t\t\t\tisVisible = true;\n
\t\t\t\t\t\t\t//wait for the stack to unwind and see if we have jumped to another input\n
\t\t\t\t\t\t\tclearTimeout( delayHide );\n
\t\t\t\t\t\t\tdelayShow = setTimeout( function() {\n
\t\t\t\t\t\t\t\tself.show();\n
\t\t\t\t\t\t\t}, 0 );\n
\t\t\t\t\t\t} else if ( e.type === "focusin" && !!isVisible ) {\n
\t\t\t\t\t\t\t//if we have jumped to another input clear the time out to cancel the show.\n
\t\t\t\t\t\t\tclearTimeout( delayShow );\n
\t\t\t\t\t\t\tisVisible = false;\n
\t\t\t\t\t\t\tdelayHide = setTimeout( function() {\n
\t\t\t\t\t\t\t\tself.hide();\n
\t\t\t\t\t\t\t}, 0 );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t},\n
\n
\t\t_setRelative: function() {\n
\t\t\tif( this.options.position !== "fixed" ){\n
\t\t\t\t$( "[data-"+ $.mobile.ns + "role=\'page\']" ).css({ "position": "relative" });\n
\t\t\t}\n
\t\t},\n
\n
\t\t_destroy: function() {\n
\t\t\tvar $el = this.element,\n
\t\t\t\theader = $el.hasClass( "ui-header" );\n
\n
\t\t\t$el.closest( ".ui-page" ).css( "padding-" + ( header ? "top" : "bottom" ), "" );\n
\t\t\t$el.removeClass( "ui-header-fixed ui-footer-fixed ui-header-fullscreen ui-footer-fullscreen in out fade slidedown slideup ui-fixed-hidden" );\n
\t\t\t$el.closest( ".ui-page" ).removeClass( "ui-page-header-fixed ui-page-footer-fixed ui-page-header-fullscreen ui-page-footer-fullscreen" );\n
\t\t}\n
\n
\t});\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\t$.widget( "mobile.toolbar", $.mobile.toolbar, {\n
\n
\t\t_makeFixed: function() {\n
\t\t\tthis._super();\n
\t\t\tthis._workarounds();\n
\t\t},\n
\n
\t\t//check the browser and version and run needed workarounds\n
\t\t_workarounds: function() {\n
\t\t\tvar ua = navigator.userAgent,\n
\t\t\tplatform = navigator.platform,\n
\t\t\t// Rendering engine is Webkit, and capture major version\n
\t\t\twkmatch = ua.match( /AppleWebKit\\/([0-9]+)/ ),\n
\t\t\twkversion = !!wkmatch && wkmatch[ 1 ],\n
\t\t\tos = null,\n
\t\t\tself = this;\n
\t\t\t//set the os we are working in if it dosent match one with workarounds return\n
\t\t\tif ( platform.indexOf( "iPhone" ) > -1 || platform.indexOf( "iPad" ) > -1  || platform.indexOf( "iPod" ) > -1 ) {\n
\t\t\t\tos = "ios";\n
\t\t\t} else if ( ua.indexOf( "Android" ) > -1 ) {\n
\t\t\t\tos = "android";\n
\t\t\t} else {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\t//check os version if it dosent match one with workarounds return\n
\t\t\tif ( os === "ios" ) {\n
\t\t\t\t//iOS  workarounds\n
\t\t\t\tself._bindScrollWorkaround();\n
\t\t\t} else if ( os === "android" && wkversion && wkversion < 534 ) {\n
\t\t\t\t//Android 2.3 run all Android 2.3 workaround\n
\t\t\t\tself._bindScrollWorkaround();\n
\t\t\t\tself._bindListThumbWorkaround();\n
\t\t\t} else {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t},\n
\n
\t\t//Utility class for checking header and footer positions relative to viewport\n
\t\t_viewportOffset: function() {\n
\t\t\tvar $el = this.element,\n
\t\t\t\theader = $el.hasClass( "ui-header" ),\n
\t\t\t\toffset = Math.abs( $el.offset().top - this.window.scrollTop() );\n
\t\t\tif ( !header ) {\n
\t\t\t\toffset = Math.round( offset - this.window.height() + $el.outerHeight() ) - 60;\n
\t\t\t}\n
\t\t\treturn offset;\n
\t\t},\n
\n
\t\t//bind events for _triggerRedraw() function\n
\t\t_bindScrollWorkaround: function() {\n
\t\t\tvar self = this;\n
\t\t\t//bind to scrollstop and check if the toolbars are correctly positioned\n
\t\t\tthis._on( this.window, { scrollstop: function() {\n
\t\t\t\tvar viewportOffset = self._viewportOffset();\n
\t\t\t\t//check if the header is visible and if its in the right place\n
\t\t\t\tif ( viewportOffset > 2 && self._visible ) {\n
\t\t\t\t\tself._triggerRedraw();\n
\t\t\t\t}\n
\t\t\t}});\n
\t\t},\n
\n
\t\t//this addresses issue #4250 Persistent footer instability in v1.1 with long select lists in Android 2.3.3\n
\t\t//and issue #3748 Android 2.x: Page transitions broken when fixed toolbars used\n
\t\t//the absolutely positioned thumbnail in a list view causes problems with fixed position buttons above in a nav bar\n
\t\t//setting the li\'s to -webkit-transform:translate3d(0,0,0); solves this problem to avoide potential issues in other\n
\t\t//platforms we scope this with the class ui-android-2x-fix\n
\t\t_bindListThumbWorkaround: function() {\n
\t\t\tthis.element.closest( ".ui-page" ).addClass( "ui-android-2x-fixed" );\n
\t\t},\n
\t\t//this addresses issues #4337 Fixed header problem after scrolling content on iOS and Android\n
\t\t//and device bugs project issue #1 Form elements can lose click hit area in position: fixed containers.\n
\t\t//this also addresses not on fixed toolbars page in docs\n
\t\t//adding 1px of padding to the bottom then removing it causes a "redraw"\n
\t\t//which positions the toolbars correctly (they will always be visually correct)\n
\t\t_triggerRedraw: function() {\n
\t\t\tvar paddingBottom = parseFloat( $( ".ui-page-active" ).css( "padding-bottom" ) );\n
\t\t\t//trigger page redraw to fix incorrectly positioned fixed elements\n
\t\t\t$( ".ui-page-active" ).css( "padding-bottom", ( paddingBottom + 1 ) + "px" );\n
\t\t\t//if the padding is reset with out a timeout the reposition will not occure.\n
\t\t\t//this is independant of JQM the browser seems to need the time to react.\n
\t\t\tsetTimeout( function() {\n
\t\t\t\t$( ".ui-page-active" ).css( "padding-bottom", paddingBottom + "px" );\n
\t\t\t}, 0 );\n
\t\t},\n
\n
\t\tdestroy: function() {\n
\t\t\tthis._super();\n
\t\t\t//Remove the class we added to the page previously in android 2.x\n
\t\t\tthis.element.closest( ".ui-page-active" ).removeClass( "ui-android-2x-fix" );\n
\t\t}\n
\t});\n
\n
})( jQuery );\n
\n
\n
( function( $, undefined ) {\n
\n
var ieHack = ( $.mobile.browser.oldIE && $.mobile.browser.oldIE <= 8 ),\n
\tuiTemplate = $(\n
\t\t"<div class=\'ui-popup-arrow-guide\'></div>" +\n
\t\t"<div class=\'ui-popup-arrow-container" + ( ieHack ? " ie" : "" ) + "\'>" +\n
\t\t\t"<div class=\'ui-popup-arrow\'></div>" +\n
\t\t"</div>"\n
\t);\n
\n
function getArrow() {\n
\tvar clone = uiTemplate.clone(),\n
\t\tgd = clone.eq( 0 ),\n
\t\tct = clone.eq( 1 ),\n
\t\tar = ct.children();\n
\n
\treturn { arEls: ct.add( gd ), gd: gd, ct: ct, ar: ar };\n
}\n
\n
$.widget( "mobile.popup", $.mobile.popup, {\n
\toptions: {\n
\n
\t\tarrow: ""\n
\t},\n
\n
\t_create: function() {\n
\t\tvar ar,\n
\t\t\tret = this._super();\n
\n
\t\tif ( this.options.arrow ) {\n
\t\t\tthis._ui.arrow = ar = this._addArrow();\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t_addArrow: function() {\n
\t\tvar theme,\n
\t\t\topts = this.options,\n
\t\t\tar = getArrow();\n
\n
\t\ttheme = this._themeClassFromOption( "ui-body-", opts.theme );\n
\t\tar.ar.addClass( theme + ( opts.shadow ? " ui-overlay-shadow" : "" ) );\n
\t\tar.arEls.hide().appendTo( this.element );\n
\n
\t\treturn ar;\n
\t},\n
\n
\t_unenhance: function() {\n
\t\tvar ar = this._ui.arrow;\n
\n
\t\tif ( ar ) {\n
\t\t\tar.arEls.remove();\n
\t\t}\n
\n
\t\treturn this._super();\n
\t},\n
\n
\t// Pretend to show an arrow described by @p and @dir and calculate the\n
\t// distance from the desired point. If a best-distance is passed in, return\n
\t// the minimum of the one passed in and the one calculated.\n
\t_tryAnArrow: function( p, dir, desired, s, best ) {\n
\t\tvar result, r, diff, desiredForArrow = {}, tip = {};\n
\n
\t\t// If the arrow has no wiggle room along the edge of the popup, it cannot\n
\t\t// be displayed along the requested edge without it sticking out.\n
\t\tif ( s.arFull[ p.dimKey ] > s.guideDims[ p.dimKey ] ) {\n
\t\t\treturn best;\n
\t\t}\n
\n
\t\tdesiredForArrow[ p.fst ] = desired[ p.fst ] +\n
\t\t\t( s.arHalf[ p.oDimKey ] + s.menuHalf[ p.oDimKey ] ) * p.offsetFactor -\n
\t\t\ts.contentBox[ p.fst ] + ( s.clampInfo.menuSize[ p.oDimKey ] - s.contentBox[ p.oDimKey ] ) * p.arrowOffsetFactor;\n
\t\tdesiredForArrow[ p.snd ] = desired[ p.snd ];\n
\n
\t\tresult = s.result || this._calculateFinalLocation( desiredForArrow, s.clampInfo );\n
\t\tr = { x: result.left, y: result.top };\n
\n
\t\ttip[ p.fst ] = r[ p.fst ] + s.contentBox[ p.fst ] + p.tipOffset;\n
\t\ttip[ p.snd ] = Math.max( result[ p.prop ] + s.guideOffset[ p.prop ] + s.arHalf[ p.dimKey ],\n
\t\t\tMath.min( result[ p.prop ] + s.guideOffset[ p.prop ] + s.guideDims[ p.dimKey ] - s.arHalf[ p.dimKey ],\n
\t\t\t\tdesired[ p.snd ] ) );\n
\n
\t\tdiff = Math.abs( desired.x - tip.x ) + Math.abs( desired.y - tip.y );\n
\t\tif ( !best || diff < best.diff ) {\n
\t\t\t// Convert tip offset to coordinates inside the popup\n
\t\t\ttip[ p.snd ] -= s.arHalf[ p.dimKey ] + result[ p.prop ] + s.contentBox[ p.snd ];\n
\t\t\tbest = { dir: dir, diff: diff, result: result, posProp: p.prop, posVal: tip[ p.snd ] };\n
\t\t}\n
\n
\t\treturn best;\n
\t},\n
\n
\t_getPlacementState: function( clamp ) {\n
\t\tvar offset, gdOffset,\n
\t\t\tar = this._ui.arrow,\n
\t\t\tstate = {\n
\t\t\t\tclampInfo: this._clampPopupWidth( !clamp ),\n
\t\t\t\tarFull: { cx: ar.ct.width(), cy: ar.ct.height() },\n
\t\t\t\tguideDims: { cx: ar.gd.width(), cy: ar.gd.height() },\n
\t\t\t\tguideOffset: ar.gd.offset()\n
\t\t\t};\n
\n
\t\toffset = this.element.offset();\n
\n
\t\tar.gd.css( { left: 0, top: 0, right: 0, bottom: 0 } );\n
\t\tgdOffset = ar.gd.offset();\n
\t\tstate.contentBox = {\n
\t\t\tx: gdOffset.left - offset.left,\n
\t\t\ty: gdOffset.top - offset.top,\n
\t\t\tcx: ar.gd.width(),\n
\t\t\tcy: ar.gd.height()\n
\t\t};\n
\t\tar.gd.removeAttr( "style" );\n
\n
\t\t// The arrow box moves between guideOffset and guideOffset + guideDims - arFull\n
\t\tstate.guideOffset = { left: state.guideOffset.left - offset.left, top: state.guideOffset.top - offset.top };\n
\t\tstate.arHalf = { cx: state.arFull.cx / 2, cy: state.arFull.cy / 2 };\n
\t\tstate.menuHalf = { cx: state.clampInfo.menuSize.cx / 2, cy: state.clampInfo.menuSize.cy / 2 };\n
\n
\t\treturn state;\n
\t},\n
\n
\t_placementCoords: function( desired ) {\n
\t\tvar state, best, params, elOffset, bgRef,\n
\t\t\toptionValue = this.options.arrow,\n
\t\t\tar = this._ui.arrow;\n
\n
\t\tif ( !ar ) {\n
\t\t\treturn this._super( desired );\n
\t\t}\n
\n
\t\tar.arEls.show();\n
\n
\t\tbgRef = {};\n
\t\tstate = this._getPlacementState( true );\n
\t\tparams = {\n
\t\t\t"l": { fst: "x", snd: "y", prop: "top", dimKey: "cy", oDimKey: "cx", offsetFactor: 1, tipOffset:  -state.arHalf.cx, arrowOffsetFactor: 0 },\n
\t\t\t"r": { fst: "x", snd: "y", prop: "top", dimKey: "cy", oDimKey: "cx", offsetFactor: -1, tipOffset: state.arHalf.cx + state.contentBox.cx, arrowOffsetFactor: 1 },\n
\t\t\t"b": { fst: "y", snd: "x", prop: "left", dimKey: "cx", oDimKey: "cy", offsetFactor: -1, tipOffset: state.arHalf.cy + state.contentBox.cy, arrowOffsetFactor: 1 },\n
\t\t\t"t": { fst: "y", snd: "x", prop: "left", dimKey: "cx", oDimKey: "cy", offsetFactor: 1, tipOffset: -state.arHalf.cy, arrowOffsetFactor: 0 }\n
\t\t};\n
\n
\t\t// Try each side specified in the options to see on which one the arrow\n
\t\t// should be placed such that the distance between the tip of the arrow and\n
\t\t// the desired coordinates is the shortest.\n
\t\t$.each( ( optionValue === true ? "l,t,r,b" : optionValue ).split( "," ),\n
\t\t\t$.proxy( function( key, value ) {\n
\t\t\t\tbest = this._tryAnArrow( params[ value ], value, desired, state, best );\n
\t\t\t}, this ) );\n
\n
\t\t// Could not place the arrow along any of the edges - behave as if showing\n
\t\t// the arrow was turned off.\n
\t\tif ( !best ) {\n
\t\t\tar.arEls.hide();\n
\t\t\treturn this._super( desired );\n
\t\t}\n
\n
\t\t// Move the arrow into place\n
\t\tar.ct\n
\t\t\t.removeClass( "ui-popup-arrow-l ui-popup-arrow-t ui-popup-arrow-r ui-popup-arrow-b" )\n
\t\t\t.addClass( "ui-popup-arrow-" + best.dir )\n
\t\t\t.removeAttr( "style" ).css( best.posProp, best.posVal )\n
\t\t\t.show();\n
\n
\t\t// Do not move/size the background div on IE, because we use the arrow div for background as well.\n
\t\tif ( !ieHack ) {\n
\t\t\telOffset = this.element.offset();\n
\t\t\tbgRef[ params[ best.dir ].fst ] = ar.ct.offset();\n
\t\t\tbgRef[ params[ best.dir ].snd ] = {\n
\t\t\t\tleft: elOffset.left + state.contentBox.x,\n
\t\t\t\ttop: elOffset.top + state.contentBox.y\n
\t\t\t};\n
\t\t}\n
\n
\t\treturn best.result;\n
\t},\n
\n
\t_setOptions: function( opts ) {\n
\t\tvar newTheme,\n
\t\t\toldTheme = this.options.theme,\n
\t\t\tar = this._ui.arrow,\n
\t\t\tret = this._super( opts );\n
\n
\t\tif ( opts.arrow !== undefined ) {\n
\t\t\tif ( !ar && opts.arrow ) {\n
\t\t\t\tthis._ui.arrow = this._addArrow();\n
\n
\t\t\t\t// Important to return here so we don\'t set the same options all over\n
\t\t\t\t// again below.\n
\t\t\t\treturn;\n
\t\t\t} else if ( ar && !opts.arrow ) {\n
\t\t\t\tar.arEls.remove();\n
\t\t\t\tthis._ui.arrow = null;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Reassign with potentially new arrow\n
\t\tar = this._ui.arrow;\n
\n
\t\tif ( ar ) {\n
\t\t\tif ( opts.theme !== undefined ) {\n
\t\t\t\toldTheme = this._themeClassFromOption( "ui-body-", oldTheme );\n
\t\t\t\tnewTheme = this._themeClassFromOption( "ui-body-", opts.theme );\n
\t\t\t\tar.ar.removeClass( oldTheme ).addClass( newTheme );\n
\t\t\t}\n
\n
\t\t\tif ( opts.shadow !== undefined ) {\n
\t\t\t\tar.ar.toggleClass( "ui-overlay-shadow", opts.shadow );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar ar = this._ui.arrow;\n
\n
\t\tif ( ar ) {\n
\t\t\tar.arEls.remove();\n
\t\t}\n
\n
\t\treturn this._super();\n
\t}\n
});\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.panel", {\n
\toptions: {\n
\t\tclasses: {\n
\t\t\tpanel: "ui-panel",\n
\t\t\tpanelOpen: "ui-panel-open",\n
\t\t\tpanelClosed: "ui-panel-closed",\n
\t\t\tpanelFixed: "ui-panel-fixed",\n
\t\t\tpanelInner: "ui-panel-inner",\n
\t\t\tmodal: "ui-panel-dismiss",\n
\t\t\tmodalOpen: "ui-panel-dismiss-open",\n
\t\t\tpageContainer: "ui-panel-page-container",\n
\t\t\tpageWrapper: "ui-panel-wrapper",\n
\t\t\tpageFixedToolbar: "ui-panel-fixed-toolbar",\n
\t\t\tpageContentPrefix: "ui-panel-page-content", /* Used for wrapper and fixed toolbars position, display and open classes. */\n
\t\t\tanimate: "ui-panel-animate"\n
\t\t},\n
\t\tanimate: true,\n
\t\ttheme: null,\n
\t\tposition: "left",\n
\t\tdismissible: true,\n
\t\tdisplay: "reveal", //accepts reveal, push, overlay\n
\t\tswipeClose: true,\n
\t\tpositionFixed: false\n
\t},\n
\n
\t_closeLink: null,\n
\t_parentPage: null,\n
\t_page: null,\n
\t_modal: null,\n
\t_panelInner: null,\n
\t_wrapper: null,\n
\t_fixedToolbars: null,\n
\n
\t_create: function() {\n
\t\tvar el = this.element,\n
\t\t\tparentPage = el.closest( ".ui-page, :jqmData(role=\'page\')" );\n
\n
\t\t// expose some private props to other methods\n
\t\t$.extend( this, {\n
\t\t\t_closeLink: el.find( ":jqmData(rel=\'close\')" ),\n
\t\t\t_parentPage: ( parentPage.length > 0 ) ? parentPage : false,\n
\t\t\t_openedPage: null,\n
\t\t\t_page: this._getPage,\n
\t\t\t_panelInner: this._getPanelInner(),\n
\t\t\t_fixedToolbars: this._getFixedToolbars\n
\t\t});\n
\t\tif ( this.options.display !== "overlay" ){\n
\t\t\tthis._getWrapper();\n
\t\t}\n
\t\tthis._addPanelClasses();\n
\n
\t\t// if animating, add the class to do so\n
\t\tif ( $.support.cssTransform3d && !!this.options.animate ) {\n
\t\t\tthis.element.addClass( this.options.classes.animate );\n
\t\t}\n
\n
\t\tthis._bindUpdateLayout();\n
\t\tthis._bindCloseEvents();\n
\t\tthis._bindLinkListeners();\n
\t\tthis._bindPageEvents();\n
\n
\t\tif ( !!this.options.dismissible ) {\n
\t\t\tthis._createModal();\n
\t\t}\n
\n
\t\tthis._bindSwipeEvents();\n
\t},\n
\n
\t_getPanelInner: function() {\n
\t\tvar panelInner = this.element.find( "." + this.options.classes.panelInner );\n
\n
\t\tif ( panelInner.length === 0 ) {\n
\t\t\tpanelInner = this.element.children().wrapAll( "<div class=\'" + this.options.classes.panelInner + "\' />" ).parent();\n
\t\t}\n
\n
\t\treturn panelInner;\n
\t},\n
\n
\t_createModal: function() {\n
\t\tvar self = this,\n
\t\t\ttarget = self._parentPage ? self._parentPage.parent() : self.element.parent();\n
\n
\t\tself._modal = $( "<div class=\'" + self.options.classes.modal + "\'></div>" )\n
\t\t\t.on( "mousedown", function() {\n
\t\t\t\tself.close();\n
\t\t\t})\n
\t\t\t.appendTo( target );\n
\t},\n
\n
\t_getPage: function() {\n
\t\tvar page = this._openedPage || this._parentPage || $( "." + $.mobile.activePageClass );\n
\n
\t\treturn page;\n
\t},\n
\n
\t_getWrapper: function() {\n
\t\tvar wrapper = this._page().find( "." + this.options.classes.pageWrapper );\n
\t\tif ( wrapper.length === 0 ) {\n
\t\t\twrapper = this._page().children( ".ui-header:not(.ui-header-fixed), .ui-content:not(.ui-popup), .ui-footer:not(.ui-footer-fixed)" )\n
\t\t\t\t.wrapAll( "<div class=\'" + this.options.classes.pageWrapper + "\'></div>" )\n
\t\t\t\t.parent();\n
\t\t}\n
\n
\t\tthis._wrapper = wrapper;\n
\t},\n
\n
\t_getFixedToolbars: function() {\n
\t\tvar extFixedToolbars = $( "body" ).children( ".ui-header-fixed, .ui-footer-fixed" ),\n
\t\t\tintFixedToolbars = this._page().find( ".ui-header-fixed, .ui-footer-fixed" ),\n
\t\t\tfixedToolbars = extFixedToolbars.add( intFixedToolbars ).addClass( this.options.classes.pageFixedToolbar );\n
\n
\t\treturn fixedToolbars;\n
\t},\n
\n
\t_getPosDisplayClasses: function( prefix ) {\n
\t\treturn prefix + "-position-" + this.options.position + " " + prefix + "-display-" + this.options.display;\n
\t},\n
\n
\t_getPanelClasses: function() {\n
\t\tvar panelClasses = this.options.classes.panel +\n
\t\t\t" " + this._getPosDisplayClasses( this.options.classes.panel ) +\n
\t\t\t" " + this.options.classes.panelClosed +\n
\t\t\t" " + "ui-body-" + ( this.options.theme ? this.options.theme : "inherit" );\n
\n
\t\tif ( !!this.options.positionFixed ) {\n
\t\t\tpanelClasses += " " + this.options.classes.panelFixed;\n
\t\t}\n
\n
\t\treturn panelClasses;\n
\t},\n
\n
\t_addPanelClasses: function() {\n
\t\tthis.element.addClass( this._getPanelClasses() );\n
\t},\n
\n
\t_handleCloseClick: function( event ) {\n
\t\tif ( !event.isDefaultPrevented() ) {\n
\t\t\tthis.close();\n
\t\t}\n
\t},\n
\n
\t_bindCloseEvents: function() {\n
\t\tthis._on( this._closeLink, {\n
\t\t\t"click": "_handleCloseClick"\n
\t\t});\n
\n
\t\tthis._on({\n
\t\t\t"click a:jqmData(ajax=\'false\')": "_handleCloseClick"\n
\t\t});\n
\t},\n
\n
\t_positionPanel: function( scrollToTop ) {\n
\t\tvar self = this,\n
\t\t\tpanelInnerHeight = self._panelInner.outerHeight(),\n
\t\t\texpand = panelInnerHeight > $.mobile.getScreenHeight();\n
\n
\t\tif ( expand || !self.options.positionFixed ) {\n
\t\t\tif ( expand ) {\n
\t\t\t\tself._unfixPanel();\n
\t\t\t\t$.mobile.resetActivePageHeight( panelInnerHeight );\n
\t\t\t}\n
\t\t\tif ( scrollToTop ) {\n
\t\t\t\tthis.window[ 0 ].scrollTo( 0, $.mobile.defaultHomeScroll );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tself._fixPanel();\n
\t\t}\n
\t},\n
\n
\t_bindFixListener: function() {\n
\t\tthis._on( $( window ), { "throttledresize": "_positionPanel" });\n
\t},\n
\n
\t_unbindFixListener: function() {\n
\t\tthis._off( $( window ), "throttledresize" );\n
\t},\n
\n
\t_unfixPanel: function() {\n
\t\tif ( !!this.options.positionFixed && $.support.fixedPosition ) {\n
\t\t\tthis.element.removeClass( this.options.classes.panelFixed );\n
\t\t}\n
\t},\n
\n
\t_fixPanel: function() {\n
\t\tif ( !!this.options.positionFixed && $.support.fixedPosition ) {\n
\t\t\tthis.element.addClass( this.options.classes.panelFixed );\n
\t\t}\n
\t},\n
\n
\t_bindUpdateLayout: function() {\n
\t\tvar self = this;\n
\n
\t\tself.element.on( "updatelayout", function(/* e */) {\n
\t\t\tif ( self._open ) {\n
\t\t\t\tself._positionPanel();\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_bindLinkListeners: function() {\n
\t\tthis._on( "body", {\n
\t\t\t"click a": "_handleClick"\n
\t\t});\n
\n
\t},\n
\n
\t_handleClick: function( e ) {\n
\t\tvar link,\n
\t\t\tpanelId = this.element.attr( "id" );\n
\n
\t\tif ( e.currentTarget.href.split( "#" )[ 1 ] === panelId && panelId !== undefined ) {\n
\n
\t\t\te.preventDefault();\n
\t\t\tlink = $( e.target );\n
\t\t\tif ( link.hasClass( "ui-btn" ) ) {\n
\t\t\t\tlink.addClass( $.mobile.activeBtnClass );\n
\t\t\t\tthis.element.one( "panelopen panelclose", function() {\n
\t\t\t\t\tlink.removeClass( $.mobile.activeBtnClass );\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\tthis.toggle();\n
\t\t}\n
\t},\n
\n
\t_bindSwipeEvents: function() {\n
\t\tvar self = this,\n
\t\t\tarea = self._modal ? self.element.add( self._modal ) : self.element;\n
\n
\t\t// on swipe, close the panel\n
\t\tif ( !!self.options.swipeClose ) {\n
\t\t\tif ( self.options.position === "left" ) {\n
\t\t\t\tarea.on( "swipeleft.panel", function(/* e */) {\n
\t\t\t\t\tself.close();\n
\t\t\t\t});\n
\t\t\t} else {\n
\t\t\t\tarea.on( "swiperight.panel", function(/* e */) {\n
\t\t\t\t\tself.close();\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_bindPageEvents: function() {\n
\t\tvar self = this;\n
\n
\t\tthis.document\n
\t\t\t// Close the panel if another panel on the page opens\n
\t\t\t.on( "panelbeforeopen", function( e ) {\n
\t\t\t\tif ( self._open && e.target !== self.element[ 0 ] ) {\n
\t\t\t\t\tself.close();\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t// On escape, close? might need to have a target check too...\n
\t\t\t.on( "keyup.panel", function( e ) {\n
\t\t\t\tif ( e.keyCode === 27 && self._open ) {\n
\t\t\t\t\tself.close();\n
\t\t\t\t}\n
\t\t\t});\n
\t\tif ( !this._parentPage && this.options.display !== "overlay" ) {\n
\t\t\tthis._on( this.document, {\n
\t\t\t\t"pageshow": "_getWrapper"\n
\t\t\t});\n
\t\t}\n
\t\t// Clean up open panels after page hide\n
\t\tif ( self._parentPage ) {\n
\t\t\tthis.document.on( "pagehide", ":jqmData(role=\'page\')", function() {\n
\t\t\t\tif ( self._open ) {\n
\t\t\t\t\tself.close( true );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis.document.on( "pagebeforehide", function() {\n
\t\t\t\tif ( self._open ) {\n
\t\t\t\t\tself.close( true );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\t// state storage of open or closed\n
\t_open: false,\n
\t_pageContentOpenClasses: null,\n
\t_modalOpenClasses: null,\n
\n
\topen: function( immediate ) {\n
\t\tif ( !this._open ) {\n
\t\t\tvar self = this,\n
\t\t\t\to = self.options,\n
\n
\t\t\t\t_openPanel = function() {\n
\t\t\t\t\tself._off( self.document , "panelclose" );\n
\t\t\t\t\tself._page().jqmData( "panel", "open" );\n
\n
\t\t\t\t\tif ( $.support.cssTransform3d && !!o.animate && o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._wrapper.addClass( o.classes.animate );\n
\t\t\t\t\t\tself._fixedToolbars().addClass( o.classes.animate );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( !immediate && $.support.cssTransform3d && !!o.animate ) {\n
\t\t\t\t\t\t( self._wrapper || self.element )\n
\t\t\t\t\t\t\t.animationComplete( complete, "transition" );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tsetTimeout( complete, 0 );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( o.theme && o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._page().parent()\n
\t\t\t\t\t\t\t.addClass( o.classes.pageContainer + "-themed " + o.classes.pageContainer + "-" + o.theme );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself.element\n
\t\t\t\t\t\t.removeClass( o.classes.panelClosed )\n
\t\t\t\t\t\t.addClass( o.classes.panelOpen );\n
\n
\t\t\t\t\tself._positionPanel( true );\n
\n
\t\t\t\t\tself._pageContentOpenClasses = self._getPosDisplayClasses( o.classes.pageContentPrefix );\n
\n
\t\t\t\t\tif ( o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._page().parent().addClass( o.classes.pageContainer );\n
\t\t\t\t\t\tself._wrapper.addClass( self._pageContentOpenClasses );\n
\t\t\t\t\t\tself._fixedToolbars().addClass( self._pageContentOpenClasses );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself._modalOpenClasses = self._getPosDisplayClasses( o.classes.modal ) + " " + o.classes.modalOpen;\n
\t\t\t\t\tif ( self._modal ) {\n
\t\t\t\t\t\tself._modal\n
\t\t\t\t\t\t\t.addClass( self._modalOpenClasses )\n
\t\t\t\t\t\t\t.height( Math.max( self._modal.height(), self.document.height() ) );\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\t\t\t\tcomplete = function() {\n
\n
\t\t\t\t\t// Bail if the panel was closed before the opening animation has completed\n
\t\t\t\t\tif ( !self._open ) {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._wrapper.addClass( o.classes.pageContentPrefix + "-open" );\n
\t\t\t\t\t\tself._fixedToolbars().addClass( o.classes.pageContentPrefix + "-open" );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself._bindFixListener();\n
\n
\t\t\t\t\tself._trigger( "open" );\n
\n
\t\t\t\t\tself._openedPage = self._page();\n
\t\t\t\t};\n
\n
\t\t\tself._trigger( "beforeopen" );\n
\n
\t\t\tif ( self._page().jqmData( "panel" ) === "open" ) {\n
\t\t\t\tself._on( self.document, {\n
\t\t\t\t\t"panelclose": _openPanel\n
\t\t\t\t});\n
\t\t\t} else {\n
\t\t\t\t_openPanel();\n
\t\t\t}\n
\n
\t\t\tself._open = true;\n
\t\t}\n
\t},\n
\n
\tclose: function( immediate ) {\n
\t\tif ( this._open ) {\n
\t\t\tvar self = this,\n
\t\t\t\to = this.options,\n
\n
\t\t\t\t_closePanel = function() {\n
\n
\t\t\t\t\tself.element.removeClass( o.classes.panelOpen );\n
\n
\t\t\t\t\tif ( o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._wrapper.removeClass( self._pageContentOpenClasses );\n
\t\t\t\t\t\tself._fixedToolbars().removeClass( self._pageContentOpenClasses );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( !immediate && $.support.cssTransform3d && !!o.animate ) {\n
\t\t\t\t\t\t( self._wrapper || self.element )\n
\t\t\t\t\t\t\t.animationComplete( complete, "transition" );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tsetTimeout( complete, 0 );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( self._modal ) {\n
\t\t\t\t\t\tself._modal\n
\t\t\t\t\t\t\t.removeClass( self._modalOpenClasses )\n
\t\t\t\t\t\t\t.height( "" );\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\t\t\t\tcomplete = function() {\n
\t\t\t\t\tif ( o.theme && o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._page().parent().removeClass( o.classes.pageContainer + "-themed " + o.classes.pageContainer + "-" + o.theme );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself.element.addClass( o.classes.panelClosed );\n
\n
\t\t\t\t\tif ( o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._page().parent().removeClass( o.classes.pageContainer );\n
\t\t\t\t\t\tself._wrapper.removeClass( o.classes.pageContentPrefix + "-open" );\n
\t\t\t\t\t\tself._fixedToolbars().removeClass( o.classes.pageContentPrefix + "-open" );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( $.support.cssTransform3d && !!o.animate && o.display !== "overlay" ) {\n
\t\t\t\t\t\tself._wrapper.removeClass( o.classes.animate );\n
\t\t\t\t\t\tself._fixedToolbars().removeClass( o.classes.animate );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself._fixPanel();\n
\t\t\t\t\tself._unbindFixListener();\n
\t\t\t\t\t$.mobile.resetActivePageHeight();\n
\n
\t\t\t\t\tself._page().jqmRemoveData( "panel" );\n
\n
\t\t\t\t\tself._trigger( "close" );\n
\n
\t\t\t\t\tself._openedPage = null;\n
\t\t\t\t};\n
\n
\t\t\tself._trigger( "beforeclose" );\n
\n
\t\t\t_closePanel();\n
\n
\t\t\tself._open = false;\n
\t\t}\n
\t},\n
\n
\ttoggle: function() {\n
\t\tthis[ this._open ? "close" : "open" ]();\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar otherPanels,\n
\t\to = this.options,\n
\t\tmultiplePanels = ( $( "body > :mobile-panel" ).length + $.mobile.activePage.find( ":mobile-panel" ).length ) > 1;\n
\n
\t\tif ( o.display !== "overlay" ) {\n
\n
\t\t\t//  remove the wrapper if not in use by another panel\n
\t\t\totherPanels = $( "body > :mobile-panel" ).add( $.mobile.activePage.find( ":mobile-panel" ) );\n
\t\t\tif ( otherPanels.not( ".ui-panel-display-overlay" ).not( this.element ).length === 0 ) {\n
\t\t\t\tthis._wrapper.children().unwrap();\n
\t\t\t}\n
\n
\t\t\tif ( this._open ) {\n
\n
\t\t\t\tthis._fixedToolbars().removeClass( o.classes.pageContentPrefix + "-open" );\n
\n
\t\t\t\tif ( $.support.cssTransform3d && !!o.animate ) {\n
\t\t\t\t\tthis._fixedToolbars().removeClass( o.classes.animate );\n
\t\t\t\t}\n
\n
\t\t\t\tthis._page().parent().removeClass( o.classes.pageContainer );\n
\n
\t\t\t\tif ( o.theme ) {\n
\t\t\t\t\tthis._page().parent().removeClass( o.classes.pageContainer + "-themed " + o.classes.pageContainer + "-" + o.theme );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !multiplePanels ) {\n
\n
\t\t\tthis.document.off( "panelopen panelclose" );\n
\n
\t\t}\n
\n
\t\tif ( this._open ) {\n
\t\t\tthis._page().jqmRemoveData( "panel" );\n
\t\t}\n
\n
\t\tthis._panelInner.children().unwrap();\n
\n
\t\tthis.element\n
\t\t\t.removeClass( [ this._getPanelClasses(), o.classes.panelOpen, o.classes.animate ].join( " " ) )\n
\t\t\t.off( "swipeleft.panel swiperight.panel" )\n
\t\t\t.off( "panelbeforeopen" )\n
\t\t\t.off( "panelhide" )\n
\t\t\t.off( "keyup.panel" )\n
\t\t\t.off( "updatelayout" );\n
\n
\t\tif ( this._modal ) {\n
\t\t\tthis._modal.remove();\n
\t\t}\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.table", {\n
\toptions: {\n
\t\tclasses: {\n
\t\t\ttable: "ui-table"\n
\t\t},\n
\t\tenhanced: false\n
\t},\n
\n
\t_create: function() {\n
\t\tif ( !this.options.enhanced ) {\n
\t\t\tthis.element.addClass( this.options.classes.table );\n
\t\t}\n
\n
\t\t// extend here, assign on refresh > _setHeaders\n
\t\t$.extend( this, {\n
\n
\t\t\t// Expose headers and allHeaders properties on the widget\n
\t\t\t// headers references the THs within the first TR in the table\n
\t\t\theaders: undefined,\n
\n
\t\t\t// allHeaders references headers, plus all THs in the thead, which may\n
\t\t\t// include several rows, or not\n
\t\t\tallHeaders: undefined\n
\t\t});\n
\n
\t\tthis._refresh( true );\n
\t},\n
\n
\t_setHeaders: function() {\n
\t\tvar trs = this.element.find( "thead tr" );\n
\n
\t\tthis.headers = this.element.find( "tr:eq(0)" ).children();\n
\t\tthis.allHeaders = this.headers.add( trs.children() );\n
\t},\n
\n
\trefresh: function() {\n
\t\tthis._refresh();\n
\t},\n
\n
\trebuild: $.noop,\n
\n
\t_refresh: function( /* create */ ) {\n
\t\tvar table = this.element,\n
\t\t\ttrs = table.find( "thead tr" );\n
\n
\t\t// updating headers on refresh (fixes #5880)\n
\t\tthis._setHeaders();\n
\n
\t\t// Iterate over the trs\n
\t\ttrs.each( function() {\n
\t\t\tvar columnCount = 0;\n
\n
\t\t\t// Iterate over the children of the tr\n
\t\t\t$( this ).children().each( function() {\n
\t\t\t\tvar span = parseInt( this.getAttribute( "colspan" ), 10 ),\n
\t\t\t\t\tselector = ":nth-child(" + ( columnCount + 1 ) + ")",\n
\t\t\t\t\tj;\n
\n
\t\t\t\tthis.setAttribute( "data-" + $.mobile.ns + "colstart", columnCount + 1 );\n
\n
\t\t\t\tif ( span ) {\n
\t\t\t\t\tfor( j = 0; j < span - 1; j++ ) {\n
\t\t\t\t\t\tcolumnCount++;\n
\t\t\t\t\t\tselector += ", :nth-child(" + ( columnCount + 1 ) + ")";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Store "cells" data on header as a reference to all cells in the\n
\t\t\t\t// same column as this TH\n
\t\t\t\t$( this ).jqmData( "cells", table.find( "tr" ).not( trs.eq( 0 ) ).not( this ).children( selector ) );\n
\n
\t\t\t\tcolumnCount++;\n
\t\t\t});\n
\t\t});\n
\t}\n
});\n
\n
})( jQuery );\n
\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.table", $.mobile.table, {\n
\toptions: {\n
\t\tmode: "columntoggle",\n
\t\tcolumnBtnTheme: null,\n
\t\tcolumnPopupTheme: null,\n
\t\tcolumnBtnText: "Columns...",\n
\t\tclasses: $.extend( $.mobile.table.prototype.options.classes, {\n
\t\t\tpopup: "ui-table-columntoggle-popup",\n
\t\t\tcolumnBtn: "ui-table-columntoggle-btn",\n
\t\t\tpriorityPrefix: "ui-table-priority-",\n
\t\t\tcolumnToggleTable: "ui-table-columntoggle"\n
\t\t})\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._super();\n
\n
\t\tif ( this.options.mode !== "columntoggle" ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t$.extend( this, {\n
\t\t\t_menu: null\n
\t\t});\n
\n
\t\tif ( this.options.enhanced ) {\n
\t\t\tthis._menu = $( this.document[ 0 ].getElementById( this._id() + "-popup" ) ).children().first();\n
\t\t\tthis._addToggles( this._menu, true );\n
\t\t} else {\n
\t\t\tthis._menu = this._enhanceColToggle();\n
\t\t\tthis.element.addClass( this.options.classes.columnToggleTable );\n
\t\t}\n
\n
\t\tthis._setupEvents();\n
\n
\t\tthis._setToggleState();\n
\t},\n
\n
\t_id: function() {\n
\t\treturn ( this.element.attr( "id" ) || ( this.widgetName + this.uuid ) );\n
\t},\n
\n
\t_setupEvents: function() {\n
\t\t//NOTE: inputs are bound in bindToggles,\n
\t\t// so it can be called on refresh, too\n
\n
\t\t// update column toggles on resize\n
\t\tthis._on( this.window, {\n
\t\t\tthrottledresize: "_setToggleState"\n
\t\t});\n
\t\tthis._on( this._menu, {\n
\t\t\t"change input": "_menuInputChange"\n
\t\t});\n
\t},\n
\n
\t_addToggles: function( menu, keep ) {\n
\t\tvar inputs,\n
\t\t\tcheckboxIndex = 0,\n
\t\t\topts = this.options,\n
\t\t\tcontainer = menu.controlgroup( "container" );\n
\n
\t\t// allow update of menu on refresh (fixes #5880)\n
\t\tif ( keep ) {\n
\t\t\tinputs = menu.find( "input" );\n
\t\t} else {\n
\t\t\tcontainer.empty();\n
\t\t}\n
\n
\t\t// create the hide/show toggles\n
\t\tthis.headers.not( "td" ).each( function() {\n
\t\t\tvar input, cells,\n
\t\t\t\theader = $( this ),\n
\t\t\t\tpriority = $.mobile.getAttribute( this, "priority" );\n
\n
\t\t\tif ( priority ) {\n
\t\t\t\tcells = header.add( header.jqmData( "cells" ) );\n
\t\t\t\tcells.addClass( opts.classes.priorityPrefix + priority );\n
\n
\t\t\t\t// Make sure the (new?) checkbox is associated with its header via .jqmData() and\n
\t\t\t\t// that, vice versa, the header is also associated with the checkbox\n
\t\t\t\tinput = ( keep ? inputs.eq( checkboxIndex++ ) :\n
\t\t\t\t\t$("<label><input type=\'checkbox\' checked />" +\n
\t\t\t\t\t\t( header.children( "abbr" ).first().attr( "title" ) ||\n
\t\t\t\t\t\t\theader.text() ) +\n
\t\t\t\t\t\t"</label>" )\n
\t\t\t\t\t\t.appendTo( container )\n
\t\t\t\t\t\t.children( 0 )\n
\t\t\t\t\t\t.checkboxradio( {\n
\t\t\t\t\t\t\ttheme: opts.columnPopupTheme\n
\t\t\t\t\t\t}) )\n
\n
\t\t\t\t\t\t// Associate the header with the checkbox\n
\t\t\t\t\t\t.jqmData( "header", header )\n
\t\t\t\t\t\t.jqmData( "cells", cells );\n
\n
\t\t\t\t// Associate the checkbox with the header\n
\t\t\t\theader.jqmData( "input", input );\n
\t\t\t}\n
\t\t});\n
\n
\t\t// set bindings here\n
\t\tif ( !keep ) {\n
\t\t\tmenu.controlgroup( "refresh" );\n
\t\t}\n
\t},\n
\n
\t_menuInputChange: function( evt ) {\n
\t\tvar input = $( evt.target ),\n
\t\t\tchecked = input[ 0 ].checked;\n
\n
\t\tinput.jqmData( "cells" )\n
\t\t\t.toggleClass( "ui-table-cell-hidden", !checked )\n
\t\t\t.toggleClass( "ui-table-cell-visible", checked );\n
\t},\n
\n
\t_unlockCells: function( cells ) {\n
\t\t// allow hide/show via CSS only = remove all toggle-locks\n
\t\tcells.removeClass( "ui-table-cell-hidden ui-table-cell-visible");\n
\t},\n
\n
\t_enhanceColToggle: function() {\n
\t\tvar id , menuButton, popup, menu,\n
\t\t\ttable = this.element,\n
\t\t\topts = this.options,\n
\t\t\tns = $.mobile.ns,\n
\t\t\tfragment = this.document[ 0 ].createDocumentFragment();\n
\n
\t\tid = this._id() + "-popup";\n
\t\tmenuButton = $( "<a href=\'#" + id + "\' " +\n
\t\t\t"class=\'" + opts.classes.columnBtn + " ui-btn " +\n
\t\t\t"ui-btn-" + ( opts.columnBtnTheme || "a" ) +\n
\t\t\t" ui-corner-all ui-shadow ui-mini\' " +\n
\t\t\t"data-" + ns + "rel=\'popup\'>" + opts.columnBtnText + "</a>" );\n
\t\tpopup = $( "<div class=\'" + opts.classes.popup + "\' id=\'" + id + "\'></div>" );\n
\t\tmenu = $( "<fieldset></fieldset>" ).controlgroup();\n
\n
\t\t// set extension here, send "false" to trigger build/rebuild\n
\t\tthis._addToggles( menu, false );\n
\n
\t\tmenu.appendTo( popup );\n
\n
\t\tfragment.appendChild( popup[ 0 ] );\n
\t\tfragment.appendChild( menuButton[ 0 ] );\n
\t\ttable.before( fragment );\n
\n
\t\tpopup.popup();\n
\n
\t\treturn menu;\n
\t},\n
\n
\trebuild: function() {\n
\t\tthis._super();\n
\n
\t\tif ( this.options.mode === "columntoggle" ) {\n
\t\t\t// NOTE: rebuild passes "false", while refresh passes "undefined"\n
\t\t\t// both refresh the table, but inside addToggles, !false will be true,\n
\t\t\t// so a rebuild call can be indentified\n
\t\t\tthis._refresh( false );\n
\t\t}\n
\t},\n
\n
\t_refresh: function( create ) {\n
\t\tvar headers, hiddenColumns, index;\n
\n
\t\t// Calling _super() here updates this.headers\n
\t\tthis._super( create );\n
\n
\t\tif ( !create && this.options.mode === "columntoggle" ) {\n
\t\t\theaders = this.headers;\n
\t\t\thiddenColumns = [];\n
\n
\t\t\t// Find the index of the column header associated with each old checkbox among the\n
\t\t\t// post-refresh headers and, if the header is still there, make sure the corresponding\n
\t\t\t// column will be hidden if the pre-refresh checkbox indicates that the column is\n
\t\t\t// hidden by recording its index in the array of hidden columns.\n
\t\t\tthis._menu.find( "input" ).each( function() {\n
\t\t\t\tvar input = $( this ),\n
\t\t\t\t\theader = input.jqmData( "header" ),\n
\t\t\t\t\tindex = headers.index( header[ 0 ] );\n
\n
\t\t\t\tif ( index > -1 && !input.prop( "checked" ) ) {\n
\n
\t\t\t\t\t// The column header associated with /this/ checkbox is still present in the\n
\t\t\t\t\t// post-refresh table and the checkbox is not checked, so the column associated\n
\t\t\t\t\t// with this column header is currently hidden. Let\'s record that.\n
\t\t\t\t\thiddenColumns.push( index );\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\t// columns not being replaced must be cleared from input toggle-locks\n
\t\t\tthis._unlockCells( this.element.find( ".ui-table-cell-hidden, " +\n
\t\t\t\t".ui-table-cell-visible" ) );\n
\n
\t\t\t// update columntoggles and cells\n
\t\t\tthis._addToggles( this._menu, create );\n
\n
\t\t\t// At this point all columns are visible, so uncheck the checkboxes that correspond to\n
\t\t\t// those columns we\'ve found to be hidden\n
\t\t\tfor ( index = hiddenColumns.length - 1 ; index > -1 ; index-- ) {\n
\t\t\t\theaders.eq( hiddenColumns[ index ] ).jqmData( "input" )\n
\t\t\t\t\t.prop( "checked", false )\n
\t\t\t\t\t.checkboxradio( "refresh" )\n
\t\t\t\t\t.trigger( "change" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_setToggleState: function() {\n
\t\tthis._menu.find( "input" ).each( function() {\n
\t\t\tvar checkbox = $( this );\n
\n
\t\t\tthis.checked = checkbox.jqmData( "cells" ).eq( 0 ).css( "display" ) === "table-cell";\n
\t\t\tcheckbox.checkboxradio( "refresh" );\n
\t\t});\n
\t},\n
\n
\t_destroy: function() {\n
\t\tthis._super();\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
$.widget( "mobile.table", $.mobile.table, {\n
\toptions: {\n
\t\tmode: "reflow",\n
\t\tclasses: $.extend( $.mobile.table.prototype.options.classes, {\n
\t\t\treflowTable: "ui-table-reflow",\n
\t\t\tcellLabels: "ui-table-cell-label"\n
\t\t})\n
\t},\n
\n
\t_create: function() {\n
\t\tthis._super();\n
\n
\t\t// If it\'s not reflow mode, return here.\n
\t\tif ( this.options.mode !== "reflow" ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( !this.options.enhanced ) {\n
\t\t\tthis.element.addClass( this.options.classes.reflowTable );\n
\n
\t\t\tthis._updateReflow();\n
\t\t}\n
\t},\n
\n
\trebuild: function() {\n
\t\tthis._super();\n
\n
\t\tif ( this.options.mode === "reflow" ) {\n
\t\t\tthis._refresh( false );\n
\t\t}\n
\t},\n
\n
\t_refresh: function( create ) {\n
\t\tthis._super( create );\n
\t\tif ( !create && this.options.mode === "reflow" ) {\n
\t\t\tthis._updateReflow( );\n
\t\t}\n
\t},\n
\n
\t_updateReflow: function() {\n
\t\tvar table = this,\n
\t\t\topts = this.options;\n
\n
\t\t// get headers in reverse order so that top-level headers are appended last\n
\t\t$( table.allHeaders.get().reverse() ).each( function() {\n
\t\t\tvar cells = $( this ).jqmData( "cells" ),\n
\t\t\t\tcolstart = $.mobile.getAttribute( this, "colstart" ),\n
\t\t\t\thierarchyClass = cells.not( this ).filter( "thead th" ).length && " ui-table-cell-label-top",\n
\t\t\t\tcontents = $( this ).clone().contents(),\n
\t\t\t\titeration, filter;\n
\n
\t\t\t\tif ( contents.length > 0  ) {\n
\n
\t\t\t\t\tif ( hierarchyClass ) {\n
\t\t\t\t\t\titeration = parseInt( this.getAttribute( "colspan" ), 10 );\n
\t\t\t\t\t\tfilter = "";\n
\n
\t\t\t\t\t\tif ( iteration ) {\n
\t\t\t\t\t\t\tfilter = "td:nth-child("+ iteration +"n + " + ( colstart ) +")";\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\ttable._addLabels( cells.filter( filter ),\n
\t\t\t\t\t\t\topts.classes.cellLabels + hierarchyClass, contents );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\ttable._addLabels( cells, opts.classes.cellLabels, contents );\n
\t\t\t\t\t}\n
\n
\t\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_addLabels: function( cells, label, contents ) {\n
\t\tif ( contents.length === 1 && contents[ 0 ].nodeName.toLowerCase() === "abbr" ) {\n
\t\t\tcontents = contents.eq( 0 ).attr( "title" );\n
\t\t}\n
\t\t// .not fixes #6006\n
\t\tcells\n
\t\t\t.not( ":has(b." + label + ")" )\n
\t\t\t\t.prepend( $( "<b class=\'" + label + "\'></b>" ).append( contents ) );\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
// TODO rename filterCallback/deprecate and default to the item itself as the first argument\n
var defaultFilterCallback = function( index, searchValue ) {\n
\treturn ( ( "" + ( $.mobile.getAttribute( this, "filtertext" ) || $( this ).text() ) )\n
\t\t.toLowerCase().indexOf( searchValue ) === -1 );\n
};\n
\n
$.widget( "mobile.filterable", {\n
\n
\tinitSelector: ":jqmData(filter=\'true\')",\n
\n
\toptions: {\n
\t\tfilterReveal: false,\n
\t\tfilterCallback: defaultFilterCallback,\n
\t\tenhanced: false,\n
\t\tinput: null,\n
\t\tchildren: "> li, > option, > optgroup option, > tbody tr, > .ui-controlgroup-controls > .ui-btn, > .ui-controlgroup-controls > .ui-checkbox, > .ui-controlgroup-controls > .ui-radio"\n
\t},\n
\n
\t_create: function() {\n
\t\tvar opts = this.options;\n
\n
\t\t$.extend( this, {\n
\t\t\t_search: null,\n
\t\t\t_timer: 0\n
\t\t});\n
\n
\t\tthis._setInput( opts.input );\n
\t\tif ( !opts.enhanced ) {\n
\t\t\tthis._filterItems( ( ( this._search && this._search.val() ) || "" ).toLowerCase() );\n
\t\t}\n
\t},\n
\n
\t_onKeyUp: function() {\n
\t\tvar val, lastval,\n
\t\t\tsearch = this._search;\n
\n
\t\tif ( search ) {\n
\t\t\tval = search.val().toLowerCase(),\n
\t\t\tlastval = $.mobile.getAttribute( search[ 0 ], "lastval" ) + "";\n
\n
\t\t\tif ( lastval && lastval === val ) {\n
\t\t\t\t// Execute the handler only once per value change\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif ( this._timer ) {\n
\t\t\t\twindow.clearTimeout( this._timer );\n
\t\t\t\tthis._timer = 0;\n
\t\t\t}\n
\n
\t\t\tthis._timer = this._delay( function() {\n
\t\t\t\tif ( this._trigger( "beforefilter", null, { input: search } ) === false ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\n
\t\t\t\t// Change val as lastval for next execution\n
\t\t\t\tsearch[ 0 ].setAttribute( "data-" + $.mobile.ns + "lastval", val );\n
\n
\t\t\t\tthis._filterItems( val );\n
\t\t\t\tthis._timer = 0;\n
\t\t\t}, 250 );\n
\t\t}\n
\t},\n
\n
\t_getFilterableItems: function() {\n
\t\tvar elem = this.element,\n
\t\t\tchildren = this.options.children,\n
\t\t\titems = !children ? { length: 0 }:\n
\t\t\t\t$.isFunction( children ) ? children():\n
\t\t\t\tchildren.nodeName ? $( children ):\n
\t\t\t\tchildren.jquery ? children:\n
\t\t\t\tthis.element.find( children );\n
\n
\t\tif ( items.length === 0 ) {\n
\t\t\titems = elem.children();\n
\t\t}\n
\n
\t\treturn items;\n
\t},\n
\n
\t_filterItems: function( val ) {\n
\t\tvar idx, callback, length, dst,\n
\t\t\tshow = [],\n
\t\t\thide = [],\n
\t\t\topts = this.options,\n
\t\t\tfilterItems = this._getFilterableItems();\n
\n
\t\tif ( val != null ) {\n
\t\t\tcallback = opts.filterCallback || defaultFilterCallback;\n
\t\t\tlength = filterItems.length;\n
\n
\t\t\t// Partition the items into those to be hidden and those to be shown\n
\t\t\tfor ( idx = 0 ; idx < length ; idx++ ) {\n
\t\t\t\tdst = ( callback.call( filterItems[ idx ], idx, val ) ) ? hide : show;\n
\t\t\t\tdst.push( filterItems[ idx ] );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// If nothing is hidden, then the decision whether to hide or show the items\n
\t\t// is based on the "filterReveal" option.\n
\t\tif ( hide.length === 0 ) {\n
\t\t\tfilterItems[ ( opts.filterReveal && val.length === 0 ) ?\n
\t\t\t\t"addClass" : "removeClass" ]( "ui-screen-hidden" );\n
\t\t} else {\n
\t\t\t$( hide ).addClass( "ui-screen-hidden" );\n
\t\t\t$( show ).removeClass( "ui-screen-hidden" );\n
\t\t}\n
\n
\t\tthis._refreshChildWidget();\n
\n
\t\tthis._trigger( "filter", null, {\n
\t\t\titems: filterItems\n
\t\t});\n
\t},\n
\n
\t// The Default implementation of _refreshChildWidget attempts to call\n
\t// refresh on collapsibleset, controlgroup, selectmenu, or listview\n
\t_refreshChildWidget: function() {\n
\t\tvar widget, idx,\n
\t\t\trecognizedWidgets = [ "collapsibleset", "selectmenu", "controlgroup", "listview" ];\n
\n
\t\tfor ( idx = recognizedWidgets.length - 1 ; idx > -1 ; idx-- ) {\n
\t\t\twidget = recognizedWidgets[ idx ];\n
\t\t\tif ( $.mobile[ widget ] ) {\n
\t\t\t\twidget = this.element.data( "mobile-" + widget );\n
\t\t\t\tif ( widget && $.isFunction( widget.refresh ) ) {\n
\t\t\t\t\twidget.refresh();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// TODO: When the input is not internal, do not even store it in this._search\n
\t_setInput: function ( selector ) {\n
\t\tvar search = this._search;\n
\n
\t\t// Stop a pending filter operation\n
\t\tif ( this._timer ) {\n
\t\t\twindow.clearTimeout( this._timer );\n
\t\t\tthis._timer = 0;\n
\t\t}\n
\n
\t\tif ( search ) {\n
\t\t\tthis._off( search, "keyup change input" );\n
\t\t\tsearch = null;\n
\t\t}\n
\n
\t\tif ( selector ) {\n
\t\t\tsearch = selector.jquery ? selector:\n
\t\t\t\tselector.nodeName ? $( selector ):\n
\t\t\t\tthis.document.find( selector );\n
\n
\t\t\tthis._on( search, {\n
\t\t\t\tkeydown: "_onKeyDown",\n
\t\t\t\tkeypress: "_onKeyPress",\n
\t\t\t\tkeyup: "_onKeyUp",\n
\t\t\t\tchange: "_onKeyUp",\n
\t\t\t\tinput: "_onKeyUp"\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._search = search;\n
\t},\n
\n
\t// Prevent form submission\n
\t_onKeyDown: function( event ) {\n
\t\tif ( event.keyCode === $.ui.keyCode.ENTER ) {\n
\t\t\tevent.preventDefault();\n
\t\t\tthis._preventKeyPress = true;\n
\t\t}\n
\t},\n
\n
\t_onKeyPress: function( event ) {\n
\t\tif ( this._preventKeyPress ) {\n
\t\t\tevent.preventDefault();\n
\t\t\tthis._preventKeyPress = false;\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar refilter = !( ( options.filterReveal === undefined ) &&\n
\t\t\t\t( options.filterCallback === undefined ) &&\n
\t\t\t\t( options.children === undefined ) );\n
\n
\t\tthis._super( options );\n
\n
\t\tif ( options.input !== undefined ) {\n
\t\t\tthis._setInput( options.input );\n
\t\t\trefilter = true;\n
\t\t}\n
\n
\t\tif ( refilter ) {\n
\t\t\tthis.refresh();\n
\t\t}\n
\t},\n
\n
\t_destroy: function() {\n
\t\tvar opts = this.options,\n
\t\t\titems = this._getFilterableItems();\n
\n
\t\tif ( opts.enhanced ) {\n
\t\t\titems.toggleClass( "ui-screen-hidden", opts.filterReveal );\n
\t\t} else {\n
\t\t\titems.removeClass( "ui-screen-hidden" );\n
\t\t}\n
\t},\n
\n
\trefresh: function() {\n
\t\tif ( this._timer ) {\n
\t\t\twindow.clearTimeout( this._timer );\n
\t\t\tthis._timer = 0;\n
\t\t}\n
\t\tthis._filterItems( ( ( this._search && this._search.val() ) || "" ).toLowerCase() );\n
\t}\n
});\n
\n
})( jQuery );\n
\n
(function( $, undefined ) {\n
\n
// Create a function that will replace the _setOptions function of a widget,\n
// and will pass the options on to the input of the filterable.\n
var replaceSetOptions = function( self, orig ) {\n
\t\treturn function( options ) {\n
\t\t\torig.call( this, options );\n
\t\t\tself._syncTextInputOptions( options );\n
\t\t};\n
\t},\n
\trDividerListItem = /(^|\\s)ui-li-divider(\\s|$)/,\n
\torigDefaultFilterCallback = $.mobile.filterable.prototype.options.filterCallback;\n
\n
// Override the default filter callback with one that does not hide list dividers\n
$.mobile.filterable.prototype.options.filterCallback = function( index, searchValue ) {\n
\treturn !this.className.match( rDividerListItem ) &&\n
\t\torigDefaultFilterCallback.call( this, index, searchValue );\n
};\n
\n
$.widget( "mobile.filterable", $.mobile.filterable, {\n
\toptions: {\n
\t\tfilterPlaceholder: "Filter items...",\n
\t\tfilterTheme: null\n
\t},\n
\n
\t_create: function() {\n
\t\tvar idx, widgetName,\n
\t\t\telem = this.element,\n
\t\t\trecognizedWidgets = [ "collapsibleset", "selectmenu", "controlgroup", "listview" ],\n
\t\t\tcreateHandlers = {};\n
\n
\t\tthis._super();\n
\n
\t\t$.extend( this, {\n
\t\t\t_widget: null\n
\t\t});\n
\n
\t\tfor ( idx = recognizedWidgets.length - 1 ; idx > -1 ; idx-- ) {\n
\t\t\twidgetName = recognizedWidgets[ idx ];\n
\t\t\tif ( $.mobile[ widgetName ] ) {\n
\t\t\t\tif ( this._setWidget( elem.data( "mobile-" + widgetName ) ) ) {\n
\t\t\t\t\tbreak;\n
\t\t\t\t} else {\n
\t\t\t\t\tcreateHandlers[ widgetName + "create" ] = "_handleCreate";\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !this._widget ) {\n
\t\t\tthis._on( elem, createHandlers );\n
\t\t}\n
\t},\n
\n
\t_handleCreate: function( evt ) {\n
\t\tthis._setWidget( this.element.data( "mobile-" + evt.type.substring( 0, evt.type.length - 6 ) ) );\n
\t},\n
\n
\t_trigger: function( type, event, data ) {\n
\t\tif ( this._widget && this._widget.widgetFullName === "mobile-listview" &&\n
\t\t\ttype === "beforefilter" ) {\n
\n
\t\t\t// Also trigger listviewbeforefilter if this widget is also a listview\n
\t\t\tthis._widget._trigger( "beforefilter", event, data );\n
\t\t}\n
\n
\t\t// Passing back the response enables calling preventDefault()\n
\t\treturn this._super( type, event, data );\n
\t},\n
\n
\t_setWidget: function( widget ) {\n
\t\tif ( !this._widget && widget ) {\n
\t\t\tthis._widget = widget;\n
\t\t\tthis._widget._setOptions = replaceSetOptions( this, this._widget._setOptions );\n
\t\t}\n
\n
\t\tif ( !!this._widget ) {\n
\t\t\tthis._syncTextInputOptions( this._widget.options );\n
\t\t\tif ( this._widget.widgetName === "listview" ) {\n
\t\t\t\tthis._widget.options.hideDividers = true;\n
\t\t\t\tthis._widget.element.listview( "refresh" );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn !!this._widget;\n
\t},\n
\n
\t_isSearchInternal: function() {\n
\t\treturn ( this._search && this._search.jqmData( "ui-filterable-" + this.uuid + "-internal" ) );\n
\t},\n
\n
\t_setInput: function( selector ) {\n
\t\tvar opts = this.options,\n
\t\t\tupdatePlaceholder = true,\n
\t\t\ttextinputOpts = {};\n
\n
\t\tif ( !selector ) {\n
\t\t\tif ( this._isSearchInternal() ) {\n
\n
\t\t\t\t// Ignore the call to set a new input if the selector goes to falsy and\n
\t\t\t\t// the current textinput is already of the internally generated variety.\n
\t\t\t\treturn;\n
\t\t\t} else {\n
\n
\t\t\t\t// Generating a new textinput widget. No need to set the placeholder\n
\t\t\t\t// further down the function.\n
\t\t\t\tupdatePlaceholder = false;\n
\t\t\t\tselector = $( "<input " +\n
\t\t\t\t\t"data-" + $.mobile.ns + "type=\'search\' " +\n
\t\t\t\t\t"placeholder=\'" + opts.filterPlaceholder + "\'></input>" )\n
\t\t\t\t\t.jqmData( "ui-filterable-" + this.uuid + "-internal", true );\n
\t\t\t\t$( "<form class=\'ui-filterable\'></form>" )\n
\t\t\t\t\t.append( selector )\n
\t\t\t\t\t.submit( function( evt ) {\n
\t\t\t\t\t\tevt.preventDefault();\n
\t\t\t\t\t\tselector.blur();\n
\t\t\t\t\t})\n
\t\t\t\t\t.insertBefore( this.element );\n
\t\t\t\tif ( $.mobile.textinput ) {\n
\t\t\t\t\tif ( this.options.filterTheme != null ) {\n
\t\t\t\t\t\ttextinputOpts[ "theme" ] = opts.filterTheme;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tselector.textinput( textinputOpts );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis._super( selector );\n
\n
\t\tif ( this._isSearchInternal() && updatePlaceholder ) {\n
\t\t\tthis._search.attr( "placeholder", this.options.filterPlaceholder );\n
\t\t}\n
\t},\n
\n
\t_setOptions: function( options ) {\n
\t\tvar ret = this._super( options );\n
\n
\t\t// Need to set the filterPlaceholder after having established the search input\n
\t\tif ( options.filterPlaceholder !== undefined ) {\n
\t\t\tif ( this._isSearchInternal() ) {\n
\t\t\t\tthis._search.attr( "placeholder", options.filterPlaceholder );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( options.filterTheme !== undefined && this._search && $.mobile.textinput ) {\n
\t\t\tthis._search.textinput( "option", "theme", options.filterTheme );\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t_destroy: function() {\n
\t\tif ( this._isSearchInternal() ) {\n
\t\t\tthis._search.remove();\n
\t\t}\n
\t\tthis._super();\n
\t},\n
\n
\t_syncTextInputOptions: function( options ) {\n
\t\tvar idx,\n
\t\t\ttextinputOptions = {};\n
\n
\t\t// We only sync options if the filterable\'s textinput is of the internally\n
\t\t// generated variety, rather than one specified by the user.\n
\t\tif ( this._isSearchInternal() && $.mobile.textinput ) {\n
\n
\t\t\t// Apply only the options understood by textinput\n
\t\t\tfor ( idx in $.mobile.textinput.prototype.options ) {\n
\t\t\t\tif ( options[ idx ] !== undefined ) {\n
\t\t\t\t\tif ( idx === "theme" && this.options.filterTheme != null ) {\n
\t\t\t\t\t\ttextinputOptions[ idx ] = this.options.filterTheme;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\ttextinputOptions[ idx ] = options[ idx ];\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._search.textinput( "option", textinputOptions );\n
\t\t}\n
\t}\n
});\n
\n
// Instantiate a filterable on a listview that has the data-filter="true" attribute\n
// This is not necessary for static content, because the auto-enhance takes care of instantiating\n
// the filterable upon encountering data-filter="true". However, because of 1.3.x it is expected\n
// that a listview with data-filter="true" will be filterable even if you just instantiate a\n
// listview on it. The extension below ensures that this continues to happen in 1.4.x.\n
$.widget( "mobile.listview", $.mobile.listview, {\n
\toptions: {\n
\t\tfilter: false\n
\t},\n
\t_create: function() {\n
\t\tif ( this.options.filter === true &&\n
\t\t\t\t!this.element.data( "mobile-filterable" ) ) {\n
\t\t\tthis.element.filterable();\n
\t\t}\n
\t\treturn this._super();\n
\t}\n
});\n
\n
})( jQuery );\n
\n
/*!\n
 * jQuery UI Tabs c0ab71056b936627e8a7821f03c044aec6280a40\n
 * http://jqueryui.com\n
 *\n
 * Copyright 2013 jQuery Foundation and other contributors\n
 * Released under the MIT license.\n
 * http://jquery.org/license\n
 *\n
 * http://api.jqueryui.com/tabs/\n
 *\n
 * Depends:\n
 *\tjquery.ui.core.js\n
 *\tjquery.ui.widget.js\n
 */\n
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
\tversion: "c0ab71056b936627e8a7821f03c044aec6280a40",\n
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
\t\treturn this.element.find( "ol,ul" ).eq( 0 );\n
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
\t\tvar events = {};\n
\t\tif ( event ) {\n
\t\t\t$.each( event.split(" "), function( index, eventName ) {\n
\t\t\t\tevents[ eventName ] = "_eventHandler";\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._off( this.anchors.add( this.tabs ).add( this.panels ) );\n
\t\t// Always prevent the default action, even when disabled\n
\t\tthis._on( true, this.anchors, {\n
\t\t\tclick: function( event ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t}\n
\t\t});\n
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
\n
(function( $, undefined ) {\n
\n
})( jQuery );\n
\n
(function( $, window ) {\n
\n
\t$.mobile.iosorientationfixEnabled = true;\n
\n
\t// This fix addresses an iOS bug, so return early if the UA claims it\'s something else.\n
\tvar ua = navigator.userAgent,\n
\t\tzoom,\n
\t\tevt, x, y, z, aig;\n
\tif ( !( /iPhone|iPad|iPod/.test( navigator.platform ) && /OS [1-5]_[0-9_]* like Mac OS X/i.test( ua ) && ua.indexOf( "AppleWebKit" ) > -1 ) ) {\n
\t\t$.mobile.iosorientationfixEnabled = false;\n
\t\treturn;\n
\t}\n
\n
\tzoom = $.mobile.zoom;\n
\n
\tfunction checkTilt( e ) {\n
\t\tevt = e.originalEvent;\n
\t\taig = evt.accelerationIncludingGravity;\n
\n
\t\tx = Math.abs( aig.x );\n
\t\ty = Math.abs( aig.y );\n
\t\tz = Math.abs( aig.z );\n
\n
\t\t// If portrait orientation and in one of the danger zones\n
\t\tif ( !window.orientation && ( x > 7 || ( ( z > 6 && y < 8 || z < 8 && y > 6 ) && x > 5 ) ) ) {\n
\t\t\t\tif ( zoom.enabled ) {\n
\t\t\t\t\tzoom.disable();\n
\t\t\t\t}\n
\t\t}\telse if ( !zoom.enabled ) {\n
\t\t\t\tzoom.enable();\n
\t\t}\n
\t}\n
\n
\t$.mobile.document.on( "mobileinit", function() {\n
\t\tif ( $.mobile.iosorientationfixEnabled ) {\n
\t\t\t$.mobile.window\n
\t\t\t\t.bind( "orientationchange.iosorientationfix", zoom.enable )\n
\t\t\t\t.bind( "devicemotion.iosorientationfix", checkTilt );\n
\t\t}\n
\t});\n
\n
}( jQuery, this ));\n
\n
(function( $, window, undefined ) {\n
\tvar\t$html = $( "html" ),\n
\t\t$window = $.mobile.window;\n
\n
\t//remove initial build class (only present on first pageshow)\n
\tfunction hideRenderingClass() {\n
\t\t$html.removeClass( "ui-mobile-rendering" );\n
\t}\n
\n
\t// trigger mobileinit event - useful hook for configuring $.mobile settings before they\'re used\n
\t$( window.document ).trigger( "mobileinit" );\n
\n
\t// support conditions\n
\t// if device support condition(s) aren\'t met, leave things as they are -> a basic, usable experience,\n
\t// otherwise, proceed with the enhancements\n
\tif ( !$.mobile.gradeA() ) {\n
\t\treturn;\n
\t}\n
\n
\t// override ajaxEnabled on platforms that have known conflicts with hash history updates\n
\t// or generally work better browsing in regular http for full page refreshes (BB5, Opera Mini)\n
\tif ( $.mobile.ajaxBlacklist ) {\n
\t\t$.mobile.ajaxEnabled = false;\n
\t}\n
\n
\t// Add mobile, initial load "rendering" classes to docEl\n
\t$html.addClass( "ui-mobile ui-mobile-rendering" );\n
\n
\t// This is a fallback. If anything goes wrong (JS errors, etc), or events don\'t fire,\n
\t// this ensures the rendering class is removed after 5 seconds, so content is visible and accessible\n
\tsetTimeout( hideRenderingClass, 5000 );\n
\n
\t$.extend( $.mobile, {\n
\t\t// find and enhance the pages in the dom and transition to the first page.\n
\t\tinitializePage: function() {\n
\t\t\t// find present pages\n
\t\t\tvar path = $.mobile.path,\n
\t\t\t\t$pages = $( ":jqmData(role=\'page\'), :jqmData(role=\'dialog\')" ),\n
\t\t\t\thash = path.stripHash( path.stripQueryParams(path.parseLocation().hash) ),\n
\t\t\t\ttheLocation = $.mobile.path.parseLocation(),\n
\t\t\t\thashPage = hash ? document.getElementById( hash ) : undefined;\n
\n
\t\t\t// if no pages are found, create one with body\'s inner html\n
\t\t\tif ( !$pages.length ) {\n
\t\t\t\t$pages = $( "body" ).wrapInner( "<div data-" + $.mobile.ns + "role=\'page\'></div>" ).children( 0 );\n
\t\t\t}\n
\n
\t\t\t// add dialogs, set data-url attrs\n
\t\t\t$pages.each(function() {\n
\t\t\t\tvar $this = $( this );\n
\n
\t\t\t\t// unless the data url is already set set it to the pathname\n
\t\t\t\tif ( !$this[ 0 ].getAttribute( "data-" + $.mobile.ns + "url" ) ) {\n
\t\t\t\t\t$this.attr( "data-" + $.mobile.ns + "url", $this.attr( "id" ) ||\n
\t\t\t\t\t\ttheLocation.pathname + theLocation.search );\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\t// define first page in dom case one backs out to the directory root (not always the first page visited, but defined as fallback)\n
\t\t\t$.mobile.firstPage = $pages.first();\n
\n
\t\t\t// define page container\n
\t\t\t$.mobile.pageContainer = $.mobile.firstPage\n
\t\t\t\t.parent()\n
\t\t\t\t.addClass( "ui-mobile-viewport" )\n
\t\t\t\t.pagecontainer();\n
\n
\t\t\t// initialize navigation events now, after mobileinit has occurred and the page container\n
\t\t\t// has been created but before the rest of the library is alerted to that fact\n
\t\t\t$.mobile.navreadyDeferred.resolve();\n
\n
\t\t\t// alert listeners that the pagecontainer has been determined for binding\n
\t\t\t// to events triggered on it\n
\t\t\t$window.trigger( "pagecontainercreate" );\n
\n
\t\t\t// cue page loading message\n
\t\t\t$.mobile.loading( "show" );\n
\n
\t\t\t//remove initial build class (only present on first pageshow)\n
\t\t\thideRenderingClass();\n
\n
\t\t\t// if hashchange listening is disabled, there\'s no hash deeplink,\n
\t\t\t// the hash is not valid (contains more than one # or does not start with #)\n
\t\t\t// or there is no page with that hash, change to the first page in the DOM\n
\t\t\t// Remember, however, that the hash can also be a path!\n
\t\t\tif ( ! ( $.mobile.hashListeningEnabled &&\n
\t\t\t\t$.mobile.path.isHashValid( location.hash ) &&\n
\t\t\t\t( $( hashPage ).is( ":jqmData(role=\'page\')" ) ||\n
\t\t\t\t\t$.mobile.path.isPath( hash ) ||\n
\t\t\t\t\thash === $.mobile.dialogHashKey ) ) ) {\n
\n
\t\t\t\t// make sure to set initial popstate state if it exists\n
\t\t\t\t// so that navigation back to the initial page works properly\n
\t\t\t\tif ( $.event.special.navigate.isPushStateEnabled() ) {\n
\t\t\t\t\t$.mobile.navigate.navigator.squash( path.parseLocation().href );\n
\t\t\t\t}\n
\n
\t\t\t\t$.mobile.changePage( $.mobile.firstPage, {\n
\t\t\t\t\ttransition: "none",\n
\t\t\t\t\treverse: true,\n
\t\t\t\t\tchangeHash: false,\n
\t\t\t\t\tfromHashChange: true\n
\t\t\t\t});\n
\t\t\t} else {\n
\t\t\t\t// trigger hashchange or navigate to squash and record the correct\n
\t\t\t\t// history entry for an initial hash path\n
\t\t\t\tif ( !$.event.special.navigate.isPushStateEnabled() ) {\n
\t\t\t\t\t$window.trigger( "hashchange", [true] );\n
\t\t\t\t} else {\n
\t\t\t\t\t// TODO figure out how to simplify this interaction with the initial history entry\n
\t\t\t\t\t// at the bottom js/navigate/navigate.js\n
\t\t\t\t\t$.mobile.navigate.history.stack = [];\n
\t\t\t\t\t$.mobile.navigate( $.mobile.path.isPath( location.hash ) ? location.hash : location.href );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t});\n
\n
\t$(function() {\n
\t\t//Run inlineSVG support test\n
\t\t$.support.inlineSVG();\n
\n
\t\t// check which scrollTop value should be used by scrolling to 1 immediately at domready\n
\t\t// then check what the scroll top is. Android will report 0... others 1\n
\t\t// note that this initial scroll won\'t hide the address bar. It\'s just for the check.\n
\n
\t\t// hide iOS browser chrome on load if hideUrlBar is true this is to try and do it as soon as possible\n
\t\tif ( $.mobile.hideUrlBar ) {\n
\t\t\twindow.scrollTo( 0, 1 );\n
\t\t}\n
\n
\t\t// if defaultHomeScroll hasn\'t been set yet, see if scrollTop is 1\n
\t\t// it should be 1 in most browsers, but android treats 1 as 0 (for hiding addr bar)\n
\t\t// so if it\'s 1, use 0 from now on\n
\t\t$.mobile.defaultHomeScroll = ( !$.support.scrollTop || $.mobile.window.scrollTop() === 1 ) ? 0 : 1;\n
\n
\t\t//dom-ready inits\n
\t\tif ( $.mobile.autoInitializePage ) {\n
\t\t\t$.mobile.initializePage();\n
\t\t}\n
\n
\t\t// window load event\n
\t\t// hide iOS browser chrome on load if hideUrlBar is true this is as fall back incase we were too early before\n
\t\tif ( $.mobile.hideUrlBar ) {\n
\t\t\t$window.load( $.mobile.silentScroll );\n
\t\t}\n
\n
\t\tif ( !$.support.cssPointerEvents ) {\n
\t\t\t// IE and Opera don\'t support CSS pointer-events: none that we use to disable link-based buttons\n
\t\t\t// by adding the \'ui-disabled\' class to them. Using a JavaScript workaround for those browser.\n
\t\t\t// https://github.com/jquery/jquery-mobile/issues/3558\n
\n
\t\t\t// DEPRECATED as of 1.4.0 - remove ui-disabled after 1.4.0 release\n
\t\t\t// only ui-state-disabled should be present thereafter\n
\t\t\t$.mobile.document.delegate( ".ui-state-disabled,.ui-disabled", "vclick",\n
\t\t\t\tfunction( e ) {\n
\t\t\t\t\te.preventDefault();\n
\t\t\t\t\te.stopImmediatePropagation();\n
\t\t\t\t}\n
\t\t\t);\n
\t\t}\n
\t});\n
}( jQuery, this ));\n
\n
\n
}));\n


]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>jQuery Mobile JS</string> </value>
        </item>
        <item>
            <key> <string>version</string> </key>
            <value> <string>1.4.0-alpha.2</string> </value>
        </item>
        <item>
            <key> <string>workflow_history</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="PersistentMapping" module="Persistence.mapping"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value>
              <dictionary>
                <item>
                    <key> <string>document_publication_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>edit_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>processing_status_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAU=</string> </persistent>
                    </value>
                </item>
              </dictionary>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>publish_alive</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1406898405.74</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
            <item>
                <key> <string>validation_state</string> </key>
                <value> <string>published_alive</string> </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>edit</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>sven</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value>
                  <none/>
                </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>938.18960.34745.36676</string> </value>
            </item>
            <item>
                <key> <string>state</string> </key>
                <value> <string>current</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1413468526.28</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="5" aka="AAAAAAAAAAU=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>detect_converted_file</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>external_processing_state</string> </key>
                <value> <string>converted</string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>0.0.0.0</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1404998932.44</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
</ZopeData>
