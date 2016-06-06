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
            <value> <string>ts58329290.51</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery-1.7.js</string> </value>
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
            <value> <int>252881</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>jquery-1.7.2.js</string> </value>
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

/*!\n
 * jQuery JavaScript Library v1.7.2\n
 * http://jquery.com/\n
 *\n
 * Copyright 2011, John Resig\n
 * Dual licensed under the MIT or GPL Version 2 licenses.\n
 * http://jquery.org/license\n
 *\n
 * Includes Sizzle.js\n
 * http://sizzlejs.com/\n
 * Copyright 2011, The Dojo Foundation\n
 * Released under the MIT, BSD, and GPL Licenses.\n
 *\n
 * Date: Wed Mar 21 12:46:34 2012 -0700\n
 */\n
(function( window, undefined ) {\n
\n
// Use the correct document accordingly with window argument (sandbox)\n
var document = window.document,\n
\tnavigator = window.navigator,\n
\tlocation = window.location;\n
var jQuery = (function() {\n
\n
// Define a local copy of jQuery\n
var jQuery = function( selector, context ) {\n
\t\t// The jQuery object is actually just the init constructor \'enhanced\'\n
\t\treturn new jQuery.fn.init( selector, context, rootjQuery );\n
\t},\n
\n
\t// Map over jQuery in case of overwrite\n
\t_jQuery = window.jQuery,\n
\n
\t// Map over the $ in case of overwrite\n
\t_$ = window.$,\n
\n
\t// A central reference to the root jQuery(document)\n
\trootjQuery,\n
\n
\t// A simple way to check for HTML strings or ID strings\n
\t// Prioritize #id over <tag> to avoid XSS via location.hash (#9521)\n
\tquickExpr = /^(?:[^#<]*(<[\\w\\W]+>)[^>]*$|#([\\w\\-]*)$)/,\n
\n
\t// Check if a string has a non-whitespace character in it\n
\trnotwhite = /\\S/,\n
\n
\t// Used for trimming whitespace\n
\ttrimLeft = /^\\s+/,\n
\ttrimRight = /\\s+$/,\n
\n
\t// Match a standalone tag\n
\trsingleTag = /^<(\\w+)\\s*\\/?>(?:<\\/\\1>)?$/,\n
\n
\t// JSON RegExp\n
\trvalidchars = /^[\\],:{}\\s]*$/,\n
\trvalidescape = /\\\\(?:["\\\\\\/bfnrt]|u[0-9a-fA-F]{4})/g,\n
\trvalidtokens = /"[^"\\\\\\n\\r]*"|true|false|null|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?/g,\n
\trvalidbraces = /(?:^|:|,)(?:\\s*\\[)+/g,\n
\n
\t// Useragent RegExp\n
\trwebkit = /(webkit)[ \\/]([\\w.]+)/,\n
\tropera = /(opera)(?:.*version)?[ \\/]([\\w.]+)/,\n
\trmsie = /(msie) ([\\w.]+)/,\n
\trmozilla = /(mozilla)(?:.*? rv:([\\w.]+))?/,\n
\n
\t// Matches dashed string for camelizing\n
\trdashAlpha = /-([a-z]|[0-9])/ig,\n
\trmsPrefix = /^-ms-/,\n
\n
\t// Used by jQuery.camelCase as callback to replace()\n
\tfcamelCase = function( all, letter ) {\n
\t\treturn ( letter + "" ).toUpperCase();\n
\t},\n
\n
\t// Keep a UserAgent string for use with jQuery.browser\n
\tuserAgent = navigator.userAgent,\n
\n
\t// For matching the engine and version of the browser\n
\tbrowserMatch,\n
\n
\t// The deferred used on DOM ready\n
\treadyList,\n
\n
\t// The ready event handler\n
\tDOMContentLoaded,\n
\n
\t// Save a reference to some core methods\n
\ttoString = Object.prototype.toString,\n
\thasOwn = Object.prototype.hasOwnProperty,\n
\tpush = Array.prototype.push,\n
\tslice = Array.prototype.slice,\n
\ttrim = String.prototype.trim,\n
\tindexOf = Array.prototype.indexOf,\n
\n
\t// [[Class]] -> type pairs\n
\tclass2type = {};\n
\n
jQuery.fn = jQuery.prototype = {\n
\tconstructor: jQuery,\n
\tinit: function( selector, context, rootjQuery ) {\n
\t\tvar match, elem, ret, doc;\n
\n
\t\t// Handle $(""), $(null), or $(undefined)\n
\t\tif ( !selector ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// Handle $(DOMElement)\n
\t\tif ( selector.nodeType ) {\n
\t\t\tthis.context = this[0] = selector;\n
\t\t\tthis.length = 1;\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// The body element only exists once, optimize finding it\n
\t\tif ( selector === "body" && !context && document.body ) {\n
\t\t\tthis.context = document;\n
\t\t\tthis[0] = document.body;\n
\t\t\tthis.selector = selector;\n
\t\t\tthis.length = 1;\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// Handle HTML strings\n
\t\tif ( typeof selector === "string" ) {\n
\t\t\t// Are we dealing with HTML string or an ID?\n
\t\t\tif ( selector.charAt(0) === "<" && selector.charAt( selector.length - 1 ) === ">" && selector.length >= 3 ) {\n
\t\t\t\t// Assume that strings that start and end with <> are HTML and skip the regex check\n
\t\t\t\tmatch = [ null, selector, null ];\n
\n
\t\t\t} else {\n
\t\t\t\tmatch = quickExpr.exec( selector );\n
\t\t\t}\n
\n
\t\t\t// Verify a match, and that no context was specified for #id\n
\t\t\tif ( match && (match[1] || !context) ) {\n
\n
\t\t\t\t// HANDLE: $(html) -> $(array)\n
\t\t\t\tif ( match[1] ) {\n
\t\t\t\t\tcontext = context instanceof jQuery ? context[0] : context;\n
\t\t\t\t\tdoc = ( context ? context.ownerDocument || context : document );\n
\n
\t\t\t\t\t// If a single string is passed in and it\'s a single tag\n
\t\t\t\t\t// just do a createElement and skip the rest\n
\t\t\t\t\tret = rsingleTag.exec( selector );\n
\n
\t\t\t\t\tif ( ret ) {\n
\t\t\t\t\t\tif ( jQuery.isPlainObject( context ) ) {\n
\t\t\t\t\t\t\tselector = [ document.createElement( ret[1] ) ];\n
\t\t\t\t\t\t\tjQuery.fn.attr.call( selector, context, true );\n
\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tselector = [ doc.createElement( ret[1] ) ];\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tret = jQuery.buildFragment( [ match[1] ], [ doc ] );\n
\t\t\t\t\t\tselector = ( ret.cacheable ? jQuery.clone(ret.fragment) : ret.fragment ).childNodes;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn jQuery.merge( this, selector );\n
\n
\t\t\t\t// HANDLE: $("#id")\n
\t\t\t\t} else {\n
\t\t\t\t\telem = document.getElementById( match[2] );\n
\n
\t\t\t\t\t// Check parentNode to catch when Blackberry 4.6 returns\n
\t\t\t\t\t// nodes that are no longer in the document #6963\n
\t\t\t\t\tif ( elem && elem.parentNode ) {\n
\t\t\t\t\t\t// Handle the case where IE and Opera return items\n
\t\t\t\t\t\t// by name instead of ID\n
\t\t\t\t\t\tif ( elem.id !== match[2] ) {\n
\t\t\t\t\t\t\treturn rootjQuery.find( selector );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// Otherwise, we inject the element directly into the jQuery object\n
\t\t\t\t\t\tthis.length = 1;\n
\t\t\t\t\t\tthis[0] = elem;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tthis.context = document;\n
\t\t\t\t\tthis.selector = selector;\n
\t\t\t\t\treturn this;\n
\t\t\t\t}\n
\n
\t\t\t// HANDLE: $(expr, $(...))\n
\t\t\t} else if ( !context || context.jquery ) {\n
\t\t\t\treturn ( context || rootjQuery ).find( selector );\n
\n
\t\t\t// HANDLE: $(expr, context)\n
\t\t\t// (which is just equivalent to: $(context).find(expr)\n
\t\t\t} else {\n
\t\t\t\treturn this.constructor( context ).find( selector );\n
\t\t\t}\n
\n
\t\t// HANDLE: $(function)\n
\t\t// Shortcut for document ready\n
\t\t} else if ( jQuery.isFunction( selector ) ) {\n
\t\t\treturn rootjQuery.ready( selector );\n
\t\t}\n
\n
\t\tif ( selector.selector !== undefined ) {\n
\t\t\tthis.selector = selector.selector;\n
\t\t\tthis.context = selector.context;\n
\t\t}\n
\n
\t\treturn jQuery.makeArray( selector, this );\n
\t},\n
\n
\t// Start with an empty selector\n
\tselector: "",\n
\n
\t// The current version of jQuery being used\n
\tjquery: "1.7.2",\n
\n
\t// The default length of a jQuery object is 0\n
\tlength: 0,\n
\n
\t// The number of elements contained in the matched element set\n
\tsize: function() {\n
\t\treturn this.length;\n
\t},\n
\n
\ttoArray: function() {\n
\t\treturn slice.call( this, 0 );\n
\t},\n
\n
\t// Get the Nth element in the matched element set OR\n
\t// Get the whole matched element set as a clean array\n
\tget: function( num ) {\n
\t\treturn num == null ?\n
\n
\t\t\t// Return a \'clean\' array\n
\t\t\tthis.toArray() :\n
\n
\t\t\t// Return just the object\n
\t\t\t( num < 0 ? this[ this.length + num ] : this[ num ] );\n
\t},\n
\n
\t// Take an array of elements and push it onto the stack\n
\t// (returning the new matched element set)\n
\tpushStack: function( elems, name, selector ) {\n
\t\t// Build a new jQuery matched element set\n
\t\tvar ret = this.constructor();\n
\n
\t\tif ( jQuery.isArray( elems ) ) {\n
\t\t\tpush.apply( ret, elems );\n
\n
\t\t} else {\n
\t\t\tjQuery.merge( ret, elems );\n
\t\t}\n
\n
\t\t// Add the old object onto the stack (as a reference)\n
\t\tret.prevObject = this;\n
\n
\t\tret.context = this.context;\n
\n
\t\tif ( name === "find" ) {\n
\t\t\tret.selector = this.selector + ( this.selector ? " " : "" ) + selector;\n
\t\t} else if ( name ) {\n
\t\t\tret.selector = this.selector + "." + name + "(" + selector + ")";\n
\t\t}\n
\n
\t\t// Return the newly-formed element set\n
\t\treturn ret;\n
\t},\n
\n
\t// Execute a callback for every element in the matched set.\n
\t// (You can seed the arguments with an array of args, but this is\n
\t// only used internally.)\n
\teach: function( callback, args ) {\n
\t\treturn jQuery.each( this, callback, args );\n
\t},\n
\n
\tready: function( fn ) {\n
\t\t// Attach the listeners\n
\t\tjQuery.bindReady();\n
\n
\t\t// Add the callback\n
\t\treadyList.add( fn );\n
\n
\t\treturn this;\n
\t},\n
\n
\teq: function( i ) {\n
\t\ti = +i;\n
\t\treturn i === -1 ?\n
\t\t\tthis.slice( i ) :\n
\t\t\tthis.slice( i, i + 1 );\n
\t},\n
\n
\tfirst: function() {\n
\t\treturn this.eq( 0 );\n
\t},\n
\n
\tlast: function() {\n
\t\treturn this.eq( -1 );\n
\t},\n
\n
\tslice: function() {\n
\t\treturn this.pushStack( slice.apply( this, arguments ),\n
\t\t\t"slice", slice.call(arguments).join(",") );\n
\t},\n
\n
\tmap: function( callback ) {\n
\t\treturn this.pushStack( jQuery.map(this, function( elem, i ) {\n
\t\t\treturn callback.call( elem, i, elem );\n
\t\t}));\n
\t},\n
\n
\tend: function() {\n
\t\treturn this.prevObject || this.constructor(null);\n
\t},\n
\n
\t// For internal use only.\n
\t// Behaves like an Array\'s method, not like a jQuery method.\n
\tpush: push,\n
\tsort: [].sort,\n
\tsplice: [].splice\n
};\n
\n
// Give the init function the jQuery prototype for later instantiation\n
jQuery.fn.init.prototype = jQuery.fn;\n
\n
jQuery.extend = jQuery.fn.extend = function() {\n
\tvar options, name, src, copy, copyIsArray, clone,\n
\t\ttarget = arguments[0] || {},\n
\t\ti = 1,\n
\t\tlength = arguments.length,\n
\t\tdeep = false;\n
\n
\t// Handle a deep copy situation\n
\tif ( typeof target === "boolean" ) {\n
\t\tdeep = target;\n
\t\ttarget = arguments[1] || {};\n
\t\t// skip the boolean and the target\n
\t\ti = 2;\n
\t}\n
\n
\t// Handle case when target is a string or something (possible in deep copy)\n
\tif ( typeof target !== "object" && !jQuery.isFunction(target) ) {\n
\t\ttarget = {};\n
\t}\n
\n
\t// extend jQuery itself if only one argument is passed\n
\tif ( length === i ) {\n
\t\ttarget = this;\n
\t\t--i;\n
\t}\n
\n
\tfor ( ; i < length; i++ ) {\n
\t\t// Only deal with non-null/undefined values\n
\t\tif ( (options = arguments[ i ]) != null ) {\n
\t\t\t// Extend the base object\n
\t\t\tfor ( name in options ) {\n
\t\t\t\tsrc = target[ name ];\n
\t\t\t\tcopy = options[ name ];\n
\n
\t\t\t\t// Prevent never-ending loop\n
\t\t\t\tif ( target === copy ) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\t// Recurse if we\'re merging plain objects or arrays\n
\t\t\t\tif ( deep && copy && ( jQuery.isPlainObject(copy) || (copyIsArray = jQuery.isArray(copy)) ) ) {\n
\t\t\t\t\tif ( copyIsArray ) {\n
\t\t\t\t\t\tcopyIsArray = false;\n
\t\t\t\t\t\tclone = src && jQuery.isArray(src) ? src : [];\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tclone = src && jQuery.isPlainObject(src) ? src : {};\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Never move original objects, clone them\n
\t\t\t\t\ttarget[ name ] = jQuery.extend( deep, clone, copy );\n
\n
\t\t\t\t// Don\'t bring in undefined values\n
\t\t\t\t} else if ( copy !== undefined ) {\n
\t\t\t\t\ttarget[ name ] = copy;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\t// Return the modified object\n
\treturn target;\n
};\n
\n
jQuery.extend({\n
\tnoConflict: function( deep ) {\n
\t\tif ( window.$ === jQuery ) {\n
\t\t\twindow.$ = _$;\n
\t\t}\n
\n
\t\tif ( deep && window.jQuery === jQuery ) {\n
\t\t\twindow.jQuery = _jQuery;\n
\t\t}\n
\n
\t\treturn jQuery;\n
\t},\n
\n
\t// Is the DOM ready to be used? Set to true once it occurs.\n
\tisReady: false,\n
\n
\t// A counter to track how many items to wait for before\n
\t// the ready event fires. See #6781\n
\treadyWait: 1,\n
\n
\t// Hold (or release) the ready event\n
\tholdReady: function( hold ) {\n
\t\tif ( hold ) {\n
\t\t\tjQuery.readyWait++;\n
\t\t} else {\n
\t\t\tjQuery.ready( true );\n
\t\t}\n
\t},\n
\n
\t// Handle when the DOM is ready\n
\tready: function( wait ) {\n
\t\t// Either a released hold or an DOMready/load event and not yet ready\n
\t\tif ( (wait === true && !--jQuery.readyWait) || (wait !== true && !jQuery.isReady) ) {\n
\t\t\t// Make sure body exists, at least, in case IE gets a little overzealous (ticket #5443).\n
\t\t\tif ( !document.body ) {\n
\t\t\t\treturn setTimeout( jQuery.ready, 1 );\n
\t\t\t}\n
\n
\t\t\t// Remember that the DOM is ready\n
\t\t\tjQuery.isReady = true;\n
\n
\t\t\t// If a normal DOM Ready event fired, decrement, and wait if need be\n
\t\t\tif ( wait !== true && --jQuery.readyWait > 0 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// If there are functions bound, to execute\n
\t\t\treadyList.fireWith( document, [ jQuery ] );\n
\n
\t\t\t// Trigger any bound ready events\n
\t\t\tif ( jQuery.fn.trigger ) {\n
\t\t\t\tjQuery( document ).trigger( "ready" ).off( "ready" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tbindReady: function() {\n
\t\tif ( readyList ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\treadyList = jQuery.Callbacks( "once memory" );\n
\n
\t\t// Catch cases where $(document).ready() is called after the\n
\t\t// browser event has already occurred.\n
\t\tif ( document.readyState === "complete" ) {\n
\t\t\t// Handle it asynchronously to allow scripts the opportunity to delay ready\n
\t\t\treturn setTimeout( jQuery.ready, 1 );\n
\t\t}\n
\n
\t\t// Mozilla, Opera and webkit nightlies currently support this event\n
\t\tif ( document.addEventListener ) {\n
\t\t\t// Use the handy event callback\n
\t\t\tdocument.addEventListener( "DOMContentLoaded", DOMContentLoaded, false );\n
\n
\t\t\t// A fallback to window.onload, that will always work\n
\t\t\twindow.addEventListener( "load", jQuery.ready, false );\n
\n
\t\t// If IE event model is used\n
\t\t} else if ( document.attachEvent ) {\n
\t\t\t// ensure firing before onload,\n
\t\t\t// maybe late but safe also for iframes\n
\t\t\tdocument.attachEvent( "onreadystatechange", DOMContentLoaded );\n
\n
\t\t\t// A fallback to window.onload, that will always work\n
\t\t\twindow.attachEvent( "onload", jQuery.ready );\n
\n
\t\t\t// If IE and not a frame\n
\t\t\t// continually check to see if the document is ready\n
\t\t\tvar toplevel = false;\n
\n
\t\t\ttry {\n
\t\t\t\ttoplevel = window.frameElement == null;\n
\t\t\t} catch(e) {}\n
\n
\t\t\tif ( document.documentElement.doScroll && toplevel ) {\n
\t\t\t\tdoScrollCheck();\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// See test/unit/core.js for details concerning isFunction.\n
\t// Since version 1.3, DOM methods and functions like alert\n
\t// aren\'t supported. They return false on IE (#2968).\n
\tisFunction: function( obj ) {\n
\t\treturn jQuery.type(obj) === "function";\n
\t},\n
\n
\tisArray: Array.isArray || function( obj ) {\n
\t\treturn jQuery.type(obj) === "array";\n
\t},\n
\n
\tisWindow: function( obj ) {\n
\t\treturn obj != null && obj == obj.window;\n
\t},\n
\n
\tisNumeric: function( obj ) {\n
\t\treturn !isNaN( parseFloat(obj) ) && isFinite( obj );\n
\t},\n
\n
\ttype: function( obj ) {\n
\t\treturn obj == null ?\n
\t\t\tString( obj ) :\n
\t\t\tclass2type[ toString.call(obj) ] || "object";\n
\t},\n
\n
\tisPlainObject: function( obj ) {\n
\t\t// Must be an Object.\n
\t\t// Because of IE, we also have to check the presence of the constructor property.\n
\t\t// Make sure that DOM nodes and window objects don\'t pass through, as well\n
\t\tif ( !obj || jQuery.type(obj) !== "object" || obj.nodeType || jQuery.isWindow( obj ) ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\ttry {\n
\t\t\t// Not own constructor property must be Object\n
\t\t\tif ( obj.constructor &&\n
\t\t\t\t!hasOwn.call(obj, "constructor") &&\n
\t\t\t\t!hasOwn.call(obj.constructor.prototype, "isPrototypeOf") ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t} catch ( e ) {\n
\t\t\t// IE8,9 Will throw exceptions on certain host objects #9897\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t// Own properties are enumerated firstly, so to speed up,\n
\t\t// if last one is own, then all properties are own.\n
\n
\t\tvar key;\n
\t\tfor ( key in obj ) {}\n
\n
\t\treturn key === undefined || hasOwn.call( obj, key );\n
\t},\n
\n
\tisEmptyObject: function( obj ) {\n
\t\tfor ( var name in obj ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\treturn true;\n
\t},\n
\n
\terror: function( msg ) {\n
\t\tthrow new Error( msg );\n
\t},\n
\n
\tparseJSON: function( data ) {\n
\t\tif ( typeof data !== "string" || !data ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\t// Make sure leading/trailing whitespace is removed (IE can\'t handle it)\n
\t\tdata = jQuery.trim( data );\n
\n
\t\t// Attempt to parse using the native JSON parser first\n
\t\tif ( window.JSON && window.JSON.parse ) {\n
\t\t\treturn window.JSON.parse( data );\n
\t\t}\n
\n
\t\t// Make sure the incoming data is actual JSON\n
\t\t// Logic borrowed from http://json.org/json2.js\n
\t\tif ( rvalidchars.test( data.replace( rvalidescape, "@" )\n
\t\t\t.replace( rvalidtokens, "]" )\n
\t\t\t.replace( rvalidbraces, "")) ) {\n
\n
\t\t\treturn ( new Function( "return " + data ) )();\n
\n
\t\t}\n
\t\tjQuery.error( "Invalid JSON: " + data );\n
\t},\n
\n
\t// Cross-browser xml parsing\n
\tparseXML: function( data ) {\n
\t\tif ( typeof data !== "string" || !data ) {\n
\t\t\treturn null;\n
\t\t}\n
\t\tvar xml, tmp;\n
\t\ttry {\n
\t\t\tif ( window.DOMParser ) { // Standard\n
\t\t\t\ttmp = new DOMParser();\n
\t\t\t\txml = tmp.parseFromString( data , "text/xml" );\n
\t\t\t} else { // IE\n
\t\t\t\txml = new ActiveXObject( "Microsoft.XMLDOM" );\n
\t\t\t\txml.async = "false";\n
\t\t\t\txml.loadXML( data );\n
\t\t\t}\n
\t\t} catch( e ) {\n
\t\t\txml = undefined;\n
\t\t}\n
\t\tif ( !xml || !xml.documentElement || xml.getElementsByTagName( "parsererror" ).length ) {\n
\t\t\tjQuery.error( "Invalid XML: " + data );\n
\t\t}\n
\t\treturn xml;\n
\t},\n
\n
\tnoop: function() {},\n
\n
\t// Evaluates a script in a global context\n
\t// Workarounds based on findings by Jim Driscoll\n
\t// http://weblogs.java.net/blog/driscoll/archive/2009/09/08/eval-javascript-global-context\n
\tglobalEval: function( data ) {\n
\t\tif ( data && rnotwhite.test( data ) ) {\n
\t\t\t// We use execScript on Internet Explorer\n
\t\t\t// We use an anonymous function so that context is window\n
\t\t\t// rather than jQuery in Firefox\n
\t\t\t( window.execScript || function( data ) {\n
\t\t\t\twindow[ "eval" ].call( window, data );\n
\t\t\t} )( data );\n
\t\t}\n
\t},\n
\n
\t// Convert dashed to camelCase; used by the css and data modules\n
\t// Microsoft forgot to hump their vendor prefix (#9572)\n
\tcamelCase: function( string ) {\n
\t\treturn string.replace( rmsPrefix, "ms-" ).replace( rdashAlpha, fcamelCase );\n
\t},\n
\n
\tnodeName: function( elem, name ) {\n
\t\treturn elem.nodeName && elem.nodeName.toUpperCase() === name.toUpperCase();\n
\t},\n
\n
\t// args is for internal usage only\n
\teach: function( object, callback, args ) {\n
\t\tvar name, i = 0,\n
\t\t\tlength = object.length,\n
\t\t\tisObj = length === undefined || jQuery.isFunction( object );\n
\n
\t\tif ( args ) {\n
\t\t\tif ( isObj ) {\n
\t\t\t\tfor ( name in object ) {\n
\t\t\t\t\tif ( callback.apply( object[ name ], args ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( ; i < length; ) {\n
\t\t\t\t\tif ( callback.apply( object[ i++ ], args ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t// A special, fast, case for the most common use of each\n
\t\t} else {\n
\t\t\tif ( isObj ) {\n
\t\t\t\tfor ( name in object ) {\n
\t\t\t\t\tif ( callback.call( object[ name ], name, object[ name ] ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( ; i < length; ) {\n
\t\t\t\t\tif ( callback.call( object[ i ], i, object[ i++ ] ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn object;\n
\t},\n
\n
\t// Use native String.trim function wherever possible\n
\ttrim: trim ?\n
\t\tfunction( text ) {\n
\t\t\treturn text == null ?\n
\t\t\t\t"" :\n
\t\t\t\ttrim.call( text );\n
\t\t} :\n
\n
\t\t// Otherwise use our own trimming functionality\n
\t\tfunction( text ) {\n
\t\t\treturn text == null ?\n
\t\t\t\t"" :\n
\t\t\t\ttext.toString().replace( trimLeft, "" ).replace( trimRight, "" );\n
\t\t},\n
\n
\t// results is for internal usage only\n
\tmakeArray: function( array, results ) {\n
\t\tvar ret = results || [];\n
\n
\t\tif ( array != null ) {\n
\t\t\t// The window, strings (and functions) also have \'length\'\n
\t\t\t// Tweaked logic slightly to handle Blackberry 4.7 RegExp issues #6930\n
\t\t\tvar type = jQuery.type( array );\n
\n
\t\t\tif ( array.length == null || type === "string" || type === "function" || type === "regexp" || jQuery.isWindow( array ) ) {\n
\t\t\t\tpush.call( ret, array );\n
\t\t\t} else {\n
\t\t\t\tjQuery.merge( ret, array );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\tinArray: function( elem, array, i ) {\n
\t\tvar len;\n
\n
\t\tif ( array ) {\n
\t\t\tif ( indexOf ) {\n
\t\t\t\treturn indexOf.call( array, elem, i );\n
\t\t\t}\n
\n
\t\t\tlen = array.length;\n
\t\t\ti = i ? i < 0 ? Math.max( 0, len + i ) : i : 0;\n
\n
\t\t\tfor ( ; i < len; i++ ) {\n
\t\t\t\t// Skip accessing in sparse arrays\n
\t\t\t\tif ( i in array && array[ i ] === elem ) {\n
\t\t\t\t\treturn i;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn -1;\n
\t},\n
\n
\tmerge: function( first, second ) {\n
\t\tvar i = first.length,\n
\t\t\tj = 0;\n
\n
\t\tif ( typeof second.length === "number" ) {\n
\t\t\tfor ( var l = second.length; j < l; j++ ) {\n
\t\t\t\tfirst[ i++ ] = second[ j ];\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\twhile ( second[j] !== undefined ) {\n
\t\t\t\tfirst[ i++ ] = second[ j++ ];\n
\t\t\t}\n
\t\t}\n
\n
\t\tfirst.length = i;\n
\n
\t\treturn first;\n
\t},\n
\n
\tgrep: function( elems, callback, inv ) {\n
\t\tvar ret = [], retVal;\n
\t\tinv = !!inv;\n
\n
\t\t// Go through the array, only saving the items\n
\t\t// that pass the validator function\n
\t\tfor ( var i = 0, length = elems.length; i < length; i++ ) {\n
\t\t\tretVal = !!callback( elems[ i ], i );\n
\t\t\tif ( inv !== retVal ) {\n
\t\t\t\tret.push( elems[ i ] );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t// arg is for internal usage only\n
\tmap: function( elems, callback, arg ) {\n
\t\tvar value, key, ret = [],\n
\t\t\ti = 0,\n
\t\t\tlength = elems.length,\n
\t\t\t// jquery objects are treated as arrays\n
\t\t\tisArray = elems instanceof jQuery || length !== undefined && typeof length === "number" && ( ( length > 0 && elems[ 0 ] && elems[ length -1 ] ) || length === 0 || jQuery.isArray( elems ) ) ;\n
\n
\t\t// Go through the array, translating each of the items to their\n
\t\tif ( isArray ) {\n
\t\t\tfor ( ; i < length; i++ ) {\n
\t\t\t\tvalue = callback( elems[ i ], i, arg );\n
\n
\t\t\t\tif ( value != null ) {\n
\t\t\t\t\tret[ ret.length ] = value;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t// Go through every key on the object,\n
\t\t} else {\n
\t\t\tfor ( key in elems ) {\n
\t\t\t\tvalue = callback( elems[ key ], key, arg );\n
\n
\t\t\t\tif ( value != null ) {\n
\t\t\t\t\tret[ ret.length ] = value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Flatten any nested arrays\n
\t\treturn ret.concat.apply( [], ret );\n
\t},\n
\n
\t// A global GUID counter for objects\n
\tguid: 1,\n
\n
\t// Bind a function to a context, optionally partially applying any\n
\t// arguments.\n
\tproxy: function( fn, context ) {\n
\t\tif ( typeof context === "string" ) {\n
\t\t\tvar tmp = fn[ context ];\n
\t\t\tcontext = fn;\n
\t\t\tfn = tmp;\n
\t\t}\n
\n
\t\t// Quick check to determine if target is callable, in the spec\n
\t\t// this throws a TypeError, but we will just return undefined.\n
\t\tif ( !jQuery.isFunction( fn ) ) {\n
\t\t\treturn undefined;\n
\t\t}\n
\n
\t\t// Simulated bind\n
\t\tvar args = slice.call( arguments, 2 ),\n
\t\t\tproxy = function() {\n
\t\t\t\treturn fn.apply( context, args.concat( slice.call( arguments ) ) );\n
\t\t\t};\n
\n
\t\t// Set the guid of unique handler to the same of original handler, so it can be removed\n
\t\tproxy.guid = fn.guid = fn.guid || proxy.guid || jQuery.guid++;\n
\n
\t\treturn proxy;\n
\t},\n
\n
\t// Mutifunctional method to get and set values to a collection\n
\t// The value/s can optionally be executed if it\'s a function\n
\taccess: function( elems, fn, key, value, chainable, emptyGet, pass ) {\n
\t\tvar exec,\n
\t\t\tbulk = key == null,\n
\t\t\ti = 0,\n
\t\t\tlength = elems.length;\n
\n
\t\t// Sets many values\n
\t\tif ( key && typeof key === "object" ) {\n
\t\t\tfor ( i in key ) {\n
\t\t\t\tjQuery.access( elems, fn, i, key[i], 1, emptyGet, value );\n
\t\t\t}\n
\t\t\tchainable = 1;\n
\n
\t\t// Sets one value\n
\t\t} else if ( value !== undefined ) {\n
\t\t\t// Optionally, function values get executed if exec is true\n
\t\t\texec = pass === undefined && jQuery.isFunction( value );\n
\n
\t\t\tif ( bulk ) {\n
\t\t\t\t// Bulk operations only iterate when executing function values\n
\t\t\t\tif ( exec ) {\n
\t\t\t\t\texec = fn;\n
\t\t\t\t\tfn = function( elem, key, value ) {\n
\t\t\t\t\t\treturn exec.call( jQuery( elem ), value );\n
\t\t\t\t\t};\n
\n
\t\t\t\t// Otherwise they run against the entire set\n
\t\t\t\t} else {\n
\t\t\t\t\tfn.call( elems, value );\n
\t\t\t\t\tfn = null;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( fn ) {\n
\t\t\t\tfor (; i < length; i++ ) {\n
\t\t\t\t\tfn( elems[i], key, exec ? value.call( elems[i], i, fn( elems[i], key ) ) : value, pass );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tchainable = 1;\n
\t\t}\n
\n
\t\treturn chainable ?\n
\t\t\telems :\n
\n
\t\t\t// Gets\n
\t\t\tbulk ?\n
\t\t\t\tfn.call( elems ) :\n
\t\t\t\tlength ? fn( elems[0], key ) : emptyGet;\n
\t},\n
\n
\tnow: function() {\n
\t\treturn ( new Date() ).getTime();\n
\t},\n
\n
\t// Use of jQuery.browser is frowned upon.\n
\t// More details: http://docs.jquery.com/Utilities/jQuery.browser\n
\tuaMatch: function( ua ) {\n
\t\tua = ua.toLowerCase();\n
\n
\t\tvar match = rwebkit.exec( ua ) ||\n
\t\t\tropera.exec( ua ) ||\n
\t\t\trmsie.exec( ua ) ||\n
\t\t\tua.indexOf("compatible") < 0 && rmozilla.exec( ua ) ||\n
\t\t\t[];\n
\n
\t\treturn { browser: match[1] || "", version: match[2] || "0" };\n
\t},\n
\n
\tsub: function() {\n
\t\tfunction jQuerySub( selector, context ) {\n
\t\t\treturn new jQuerySub.fn.init( selector, context );\n
\t\t}\n
\t\tjQuery.extend( true, jQuerySub, this );\n
\t\tjQuerySub.superclass = this;\n
\t\tjQuerySub.fn = jQuerySub.prototype = this();\n
\t\tjQuerySub.fn.constructor = jQuerySub;\n
\t\tjQuerySub.sub = this.sub;\n
\t\tjQuerySub.fn.init = function init( selector, context ) {\n
\t\t\tif ( context && context instanceof jQuery && !(context instanceof jQuerySub) ) {\n
\t\t\t\tcontext = jQuerySub( context );\n
\t\t\t}\n
\n
\t\t\treturn jQuery.fn.init.call( this, selector, context, rootjQuerySub );\n
\t\t};\n
\t\tjQuerySub.fn.init.prototype = jQuerySub.fn;\n
\t\tvar rootjQuerySub = jQuerySub(document);\n
\t\treturn jQuerySub;\n
\t},\n
\n
\tbrowser: {}\n
});\n
\n
// Populate the class2type map\n
jQuery.each("Boolean Number String Function Array Date RegExp Object".split(" "), function(i, name) {\n
\tclass2type[ "[object " + name + "]" ] = name.toLowerCase();\n
});\n
\n
browserMatch = jQuery.uaMatch( userAgent );\n
if ( browserMatch.browser ) {\n
\tjQuery.browser[ browserMatch.browser ] = true;\n
\tjQuery.browser.version = browserMatch.version;\n
}\n
\n
// Deprecated, use jQuery.browser.webkit instead\n
if ( jQuery.browser.webkit ) {\n
\tjQuery.browser.safari = true;\n
}\n
\n
// IE doesn\'t match non-breaking spaces with \\s\n
if ( rnotwhite.test( "\\xA0" ) ) {\n
\ttrimLeft = /^[\\s\\xA0]+/;\n
\ttrimRight = /[\\s\\xA0]+$/;\n
}\n
\n
// All jQuery objects should point back to these\n
rootjQuery = jQuery(document);\n
\n
// Cleanup functions for the document ready method\n
if ( document.addEventListener ) {\n
\tDOMContentLoaded = function() {\n
\t\tdocument.removeEventListener( "DOMContentLoaded", DOMContentLoaded, false );\n
\t\tjQuery.ready();\n
\t};\n
\n
} else if ( document.attachEvent ) {\n
\tDOMContentLoaded = function() {\n
\t\t// Make sure body exists, at least, in case IE gets a little overzealous (ticket #5443).\n
\t\tif ( document.readyState === "complete" ) {\n
\t\t\tdocument.detachEvent( "onreadystatechange", DOMContentLoaded );\n
\t\t\tjQuery.ready();\n
\t\t}\n
\t};\n
}\n
\n
// The DOM ready check for Internet Explorer\n
function doScrollCheck() {\n
\tif ( jQuery.isReady ) {\n
\t\treturn;\n
\t}\n
\n
\ttry {\n
\t\t// If IE is used, use the trick by Diego Perini\n
\t\t// http://javascript.nwbox.com/IEContentLoaded/\n
\t\tdocument.documentElement.doScroll("left");\n
\t} catch(e) {\n
\t\tsetTimeout( doScrollCheck, 1 );\n
\t\treturn;\n
\t}\n
\n
\t// and execute any waiting functions\n
\tjQuery.ready();\n
}\n
\n
return jQuery;\n
\n
})();\n
\n
\n
// String to Object flags format cache\n
var flagsCache = {};\n
\n
// Convert String-formatted flags into Object-formatted ones and store in cache\n
function createFlags( flags ) {\n
\tvar object = flagsCache[ flags ] = {},\n
\t\ti, length;\n
\tflags = flags.split( /\\s+/ );\n
\tfor ( i = 0, length = flags.length; i < length; i++ ) {\n
\t\tobject[ flags[i] ] = true;\n
\t}\n
\treturn object;\n
}\n
\n
/*\n
 * Create a callback list using the following parameters:\n
 *\n
 *\tflags:\tan optional list of space-separated flags that will change how\n
 *\t\t\tthe callback list behaves\n
 *\n
 * By default a callback list will act like an event callback list and can be\n
 * "fired" multiple times.\n
 *\n
 * Possible flags:\n
 *\n
 *\tonce:\t\t\twill ensure the callback list can only be fired once (like a Deferred)\n
 *\n
 *\tmemory:\t\t\twill keep track of previous values and will call any callback added\n
 *\t\t\t\t\tafter the list has been fired right away with the latest "memorized"\n
 *\t\t\t\t\tvalues (like a Deferred)\n
 *\n
 *\tunique:\t\t\twill ensure a callback can only be added once (no duplicate in the list)\n
 *\n
 *\tstopOnFalse:\tinterrupt callings when a callback returns false\n
 *\n
 */\n
jQuery.Callbacks = function( flags ) {\n
\n
\t// Convert flags from String-formatted to Object-formatted\n
\t// (we check in cache first)\n
\tflags = flags ? ( flagsCache[ flags ] || createFlags( flags ) ) : {};\n
\n
\tvar // Actual callback list\n
\t\tlist = [],\n
\t\t// Stack of fire calls for repeatable lists\n
\t\tstack = [],\n
\t\t// Last fire value (for non-forgettable lists)\n
\t\tmemory,\n
\t\t// Flag to know if list was already fired\n
\t\tfired,\n
\t\t// Flag to know if list is currently firing\n
\t\tfiring,\n
\t\t// First callback to fire (used internally by add and fireWith)\n
\t\tfiringStart,\n
\t\t// End of the loop when firing\n
\t\tfiringLength,\n
\t\t// Index of currently firing callback (modified by remove if needed)\n
\t\tfiringIndex,\n
\t\t// Add one or several callbacks to the list\n
\t\tadd = function( args ) {\n
\t\t\tvar i,\n
\t\t\t\tlength,\n
\t\t\t\telem,\n
\t\t\t\ttype,\n
\t\t\t\tactual;\n
\t\t\tfor ( i = 0, length = args.length; i < length; i++ ) {\n
\t\t\t\telem = args[ i ];\n
\t\t\t\ttype = jQuery.type( elem );\n
\t\t\t\tif ( type === "array" ) {\n
\t\t\t\t\t// Inspect recursively\n
\t\t\t\t\tadd( elem );\n
\t\t\t\t} else if ( type === "function" ) {\n
\t\t\t\t\t// Add if not in unique mode and callback is not in\n
\t\t\t\t\tif ( !flags.unique || !self.has( elem ) ) {\n
\t\t\t\t\t\tlist.push( elem );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\t// Fire callbacks\n
\t\tfire = function( context, args ) {\n
\t\t\targs = args || [];\n
\t\t\tmemory = !flags.memory || [ context, args ];\n
\t\t\tfired = true;\n
\t\t\tfiring = true;\n
\t\t\tfiringIndex = firingStart || 0;\n
\t\t\tfiringStart = 0;\n
\t\t\tfiringLength = list.length;\n
\t\t\tfor ( ; list && firingIndex < firingLength; firingIndex++ ) {\n
\t\t\t\tif ( list[ firingIndex ].apply( context, args ) === false && flags.stopOnFalse ) {\n
\t\t\t\t\tmemory = true; // Mark as halted\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tfiring = false;\n
\t\t\tif ( list ) {\n
\t\t\t\tif ( !flags.once ) {\n
\t\t\t\t\tif ( stack && stack.length ) {\n
\t\t\t\t\t\tmemory = stack.shift();\n
\t\t\t\t\t\tself.fireWith( memory[ 0 ], memory[ 1 ] );\n
\t\t\t\t\t}\n
\t\t\t\t} else if ( memory === true ) {\n
\t\t\t\t\tself.disable();\n
\t\t\t\t} else {\n
\t\t\t\t\tlist = [];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\t// Actual Callbacks object\n
\t\tself = {\n
\t\t\t// Add a callback or a collection of callbacks to the list\n
\t\t\tadd: function() {\n
\t\t\t\tif ( list ) {\n
\t\t\t\t\tvar length = list.length;\n
\t\t\t\t\tadd( arguments );\n
\t\t\t\t\t// Do we need to add the callbacks to the\n
\t\t\t\t\t// current firing batch?\n
\t\t\t\t\tif ( firing ) {\n
\t\t\t\t\t\tfiringLength = list.length;\n
\t\t\t\t\t// With memory, if we\'re not firing then\n
\t\t\t\t\t// we should call right away, unless previous\n
\t\t\t\t\t// firing was halted (stopOnFalse)\n
\t\t\t\t\t} else if ( memory && memory !== true ) {\n
\t\t\t\t\t\tfiringStart = length;\n
\t\t\t\t\t\tfire( memory[ 0 ], memory[ 1 ] );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Remove a callback from the list\n
\t\t\tremove: function() {\n
\t\t\t\tif ( list ) {\n
\t\t\t\t\tvar args = arguments,\n
\t\t\t\t\t\targIndex = 0,\n
\t\t\t\t\t\targLength = args.length;\n
\t\t\t\t\tfor ( ; argIndex < argLength ; argIndex++ ) {\n
\t\t\t\t\t\tfor ( var i = 0; i < list.length; i++ ) {\n
\t\t\t\t\t\t\tif ( args[ argIndex ] === list[ i ] ) {\n
\t\t\t\t\t\t\t\t// Handle firingIndex and firingLength\n
\t\t\t\t\t\t\t\tif ( firing ) {\n
\t\t\t\t\t\t\t\t\tif ( i <= firingLength ) {\n
\t\t\t\t\t\t\t\t\t\tfiringLength--;\n
\t\t\t\t\t\t\t\t\t\tif ( i <= firingIndex ) {\n
\t\t\t\t\t\t\t\t\t\t\tfiringIndex--;\n
\t\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t// Remove the element\n
\t\t\t\t\t\t\t\tlist.splice( i--, 1 );\n
\t\t\t\t\t\t\t\t// If we have some unicity property then\n
\t\t\t\t\t\t\t\t// we only need to do this once\n
\t\t\t\t\t\t\t\tif ( flags.unique ) {\n
\t\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Control if a given callback is in the list\n
\t\t\thas: function( fn ) {\n
\t\t\t\tif ( list ) {\n
\t\t\t\t\tvar i = 0,\n
\t\t\t\t\t\tlength = list.length;\n
\t\t\t\t\tfor ( ; i < length; i++ ) {\n
\t\t\t\t\t\tif ( fn === list[ i ] ) {\n
\t\t\t\t\t\t\treturn true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn false;\n
\t\t\t},\n
\t\t\t// Remove all callbacks from the list\n
\t\t\tempty: function() {\n
\t\t\t\tlist = [];\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Have the list do nothing anymore\n
\t\t\tdisable: function() {\n
\t\t\t\tlist = stack = memory = undefined;\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Is it disabled?\n
\t\t\tdisabled: function() {\n
\t\t\t\treturn !list;\n
\t\t\t},\n
\t\t\t// Lock the list in its current state\n
\t\t\tlock: function() {\n
\t\t\t\tstack = undefined;\n
\t\t\t\tif ( !memory || memory === true ) {\n
\t\t\t\t\tself.disable();\n
\t\t\t\t}\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Is it locked?\n
\t\t\tlocked: function() {\n
\t\t\t\treturn !stack;\n
\t\t\t},\n
\t\t\t// Call all callbacks with the given context and arguments\n
\t\t\tfireWith: function( context, args ) {\n
\t\t\t\tif ( stack ) {\n
\t\t\t\t\tif ( firing ) {\n
\t\t\t\t\t\tif ( !flags.once ) {\n
\t\t\t\t\t\t\tstack.push( [ context, args ] );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if ( !( flags.once && memory ) ) {\n
\t\t\t\t\t\tfire( context, args );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// Call all the callbacks with the given arguments\n
\t\t\tfire: function() {\n
\t\t\t\tself.fireWith( this, arguments );\n
\t\t\t\treturn this;\n
\t\t\t},\n
\t\t\t// To know if the callbacks have already been called at least once\n
\t\t\tfired: function() {\n
\t\t\t\treturn !!fired;\n
\t\t\t}\n
\t\t};\n
\n
\treturn self;\n
};\n
\n
\n
\n
\n
var // Static reference to slice\n
\tsliceDeferred = [].slice;\n
\n
jQuery.extend({\n
\n
\tDeferred: function( func ) {\n
\t\tvar doneList = jQuery.Callbacks( "once memory" ),\n
\t\t\tfailList = jQuery.Callbacks( "once memory" ),\n
\t\t\tprogressList = jQuery.Callbacks( "memory" ),\n
\t\t\tstate = "pending",\n
\t\t\tlists = {\n
\t\t\t\tresolve: doneList,\n
\t\t\t\treject: failList,\n
\t\t\t\tnotify: progressList\n
\t\t\t},\n
\t\t\tpromise = {\n
\t\t\t\tdone: doneList.add,\n
\t\t\t\tfail: failList.add,\n
\t\t\t\tprogress: progressList.add,\n
\n
\t\t\t\tstate: function() {\n
\t\t\t\t\treturn state;\n
\t\t\t\t},\n
\n
\t\t\t\t// Deprecated\n
\t\t\t\tisResolved: doneList.fired,\n
\t\t\t\tisRejected: failList.fired,\n
\n
\t\t\t\tthen: function( doneCallbacks, failCallbacks, progressCallbacks ) {\n
\t\t\t\t\tdeferred.done( doneCallbacks ).fail( failCallbacks ).progress( progressCallbacks );\n
\t\t\t\t\treturn this;\n
\t\t\t\t},\n
\t\t\t\talways: function() {\n
\t\t\t\t\tdeferred.done.apply( deferred, arguments ).fail.apply( deferred, arguments );\n
\t\t\t\t\treturn this;\n
\t\t\t\t},\n
\t\t\t\tpipe: function( fnDone, fnFail, fnProgress ) {\n
\t\t\t\t\treturn jQuery.Deferred(function( newDefer ) {\n
\t\t\t\t\t\tjQuery.each( {\n
\t\t\t\t\t\t\tdone: [ fnDone, "resolve" ],\n
\t\t\t\t\t\t\tfail: [ fnFail, "reject" ],\n
\t\t\t\t\t\t\tprogress: [ fnProgress, "notify" ]\n
\t\t\t\t\t\t}, function( handler, data ) {\n
\t\t\t\t\t\t\tvar fn = data[ 0 ],\n
\t\t\t\t\t\t\t\taction = data[ 1 ],\n
\t\t\t\t\t\t\t\treturned;\n
\t\t\t\t\t\t\tif ( jQuery.isFunction( fn ) ) {\n
\t\t\t\t\t\t\t\tdeferred[ handler ](function() {\n
\t\t\t\t\t\t\t\t\treturned = fn.apply( this, arguments );\n
\t\t\t\t\t\t\t\t\tif ( returned && jQuery.isFunction( returned.promise ) ) {\n
\t\t\t\t\t\t\t\t\t\treturned.promise().then( newDefer.resolve, newDefer.reject, newDefer.notify );\n
\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\tnewDefer[ action + "With" ]( this === deferred ? newDefer : this, [ returned ] );\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tdeferred[ handler ]( newDefer[ action ] );\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}).promise();\n
\t\t\t\t},\n
\t\t\t\t// Get a promise for this deferred\n
\t\t\t\t// If obj is provided, the promise aspect is added to the object\n
\t\t\t\tpromise: function( obj ) {\n
\t\t\t\t\tif ( obj == null ) {\n
\t\t\t\t\t\tobj = promise;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tfor ( var key in promise ) {\n
\t\t\t\t\t\t\tobj[ key ] = promise[ key ];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn obj;\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tdeferred = promise.promise({}),\n
\t\t\tkey;\n
\n
\t\tfor ( key in lists ) {\n
\t\t\tdeferred[ key ] = lists[ key ].fire;\n
\t\t\tdeferred[ key + "With" ] = lists[ key ].fireWith;\n
\t\t}\n
\n
\t\t// Handle state\n
\t\tdeferred.done( function() {\n
\t\t\tstate = "resolved";\n
\t\t}, failList.disable, progressList.lock ).fail( function() {\n
\t\t\tstate = "rejected";\n
\t\t}, doneList.disable, progressList.lock );\n
\n
\t\t// Call given func if any\n
\t\tif ( func ) {\n
\t\t\tfunc.call( deferred, deferred );\n
\t\t}\n
\n
\t\t// All done!\n
\t\treturn deferred;\n
\t},\n
\n
\t// Deferred helper\n
\twhen: function( firstParam ) {\n
\t\tvar args = sliceDeferred.call( arguments, 0 ),\n
\t\t\ti = 0,\n
\t\t\tlength = args.length,\n
\t\t\tpValues = new Array( length ),\n
\t\t\tcount = length,\n
\t\t\tpCount = length,\n
\t\t\tdeferred = length <= 1 && firstParam && jQuery.isFunction( firstParam.promise ) ?\n
\t\t\t\tfirstParam :\n
\t\t\t\tjQuery.Deferred(),\n
\t\t\tpromise = deferred.promise();\n
\t\tfunction resolveFunc( i ) {\n
\t\t\treturn function( value ) {\n
\t\t\t\targs[ i ] = arguments.length > 1 ? sliceDeferred.call( arguments, 0 ) : value;\n
\t\t\t\tif ( !( --count ) ) {\n
\t\t\t\t\tdeferred.resolveWith( deferred, args );\n
\t\t\t\t}\n
\t\t\t};\n
\t\t}\n
\t\tfunction progressFunc( i ) {\n
\t\t\treturn function( value ) {\n
\t\t\t\tpValues[ i ] = arguments.length > 1 ? sliceDeferred.call( arguments, 0 ) : value;\n
\t\t\t\tdeferred.notifyWith( promise, pValues );\n
\t\t\t};\n
\t\t}\n
\t\tif ( length > 1 ) {\n
\t\t\tfor ( ; i < length; i++ ) {\n
\t\t\t\tif ( args[ i ] && args[ i ].promise && jQuery.isFunction( args[ i ].promise ) ) {\n
\t\t\t\t\targs[ i ].promise().then( resolveFunc(i), deferred.reject, progressFunc(i) );\n
\t\t\t\t} else {\n
\t\t\t\t\t--count;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif ( !count ) {\n
\t\t\t\tdeferred.resolveWith( deferred, args );\n
\t\t\t}\n
\t\t} else if ( deferred !== firstParam ) {\n
\t\t\tdeferred.resolveWith( deferred, length ? [ firstParam ] : [] );\n
\t\t}\n
\t\treturn promise;\n
\t}\n
});\n
\n
\n
\n
\n
jQuery.support = (function() {\n
\n
\tvar support,\n
\t\tall,\n
\t\ta,\n
\t\tselect,\n
\t\topt,\n
\t\tinput,\n
\t\tfragment,\n
\t\ttds,\n
\t\tevents,\n
\t\teventName,\n
\t\ti,\n
\t\tisSupported,\n
\t\tdiv = document.createElement( "div" ),\n
\t\tdocumentElement = document.documentElement;\n
\n
\t// Preliminary tests\n
\tdiv.setAttribute("className", "t");\n
\tdiv.innerHTML = "   <link/><table></table><a href=\'/a\' style=\'top:1px;float:left;opacity:.55;\'>a</a><input type=\'checkbox\'/>";\n
\n
\tall = div.getElementsByTagName( "*" );\n
\ta = div.getElementsByTagName( "a" )[ 0 ];\n
\n
\t// Can\'t get basic test support\n
\tif ( !all || !all.length || !a ) {\n
\t\treturn {};\n
\t}\n
\n
\t// First batch of supports tests\n
\tselect = document.createElement( "select" );\n
\topt = select.appendChild( document.createElement("option") );\n
\tinput = div.getElementsByTagName( "input" )[ 0 ];\n
\n
\tsupport = {\n
\t\t// IE strips leading whitespace when .innerHTML is used\n
\t\tleadingWhitespace: ( div.firstChild.nodeType === 3 ),\n
\n
\t\t// Make sure that tbody elements aren\'t automatically inserted\n
\t\t// IE will insert them into empty tables\n
\t\ttbody: !div.getElementsByTagName("tbody").length,\n
\n
\t\t// Make sure that link elements get serialized correctly by innerHTML\n
\t\t// This requires a wrapper element in IE\n
\t\thtmlSerialize: !!div.getElementsByTagName("link").length,\n
\n
\t\t// Get the style information from getAttribute\n
\t\t// (IE uses .cssText instead)\n
\t\tstyle: /top/.test( a.getAttribute("style") ),\n
\n
\t\t// Make sure that URLs aren\'t manipulated\n
\t\t// (IE normalizes it by default)\n
\t\threfNormalized: ( a.getAttribute("href") === "/a" ),\n
\n
\t\t// Make sure that element opacity exists\n
\t\t// (IE uses filter instead)\n
\t\t// Use a regex to work around a WebKit issue. See #5145\n
\t\topacity: /^0.55/.test( a.style.opacity ),\n
\n
\t\t// Verify style float existence\n
\t\t// (IE uses styleFloat instead of cssFloat)\n
\t\tcssFloat: !!a.style.cssFloat,\n
\n
\t\t// Make sure that if no value is specified for a checkbox\n
\t\t// that it defaults to "on".\n
\t\t// (WebKit defaults to "" instead)\n
\t\tcheckOn: ( input.value === "on" ),\n
\n
\t\t// Make sure that a selected-by-default option has a working selected property.\n
\t\t// (WebKit defaults to false instead of true, IE too, if it\'s in an optgroup)\n
\t\toptSelected: opt.selected,\n
\n
\t\t// Test setAttribute on camelCase class. If it works, we need attrFixes when doing get/setAttribute (ie6/7)\n
\t\tgetSetAttribute: div.className !== "t",\n
\n
\t\t// Tests for enctype support on a form(#6743)\n
\t\tenctype: !!document.createElement("form").enctype,\n
\n
\t\t// Makes sure cloning an html5 element does not cause problems\n
\t\t// Where outerHTML is undefined, this still works\n
\t\thtml5Clone: document.createElement("nav").cloneNode( true ).outerHTML !== "<:nav></:nav>",\n
\n
\t\t// Will be defined later\n
\t\tsubmitBubbles: true,\n
\t\tchangeBubbles: true,\n
\t\tfocusinBubbles: false,\n
\t\tdeleteExpando: true,\n
\t\tnoCloneEvent: true,\n
\t\tinlineBlockNeedsLayout: false,\n
\t\tshrinkWrapBlocks: false,\n
\t\treliableMarginRight: true,\n
\t\tpixelMargin: true\n
\t};\n
\n
\t// jQuery.boxModel DEPRECATED in 1.3, use jQuery.support.boxModel instead\n
\tjQuery.boxModel = support.boxModel = (document.compatMode === "CSS1Compat");\n
\n
\t// Make sure checked status is properly cloned\n
\tinput.checked = true;\n
\tsupport.noCloneChecked = input.cloneNode( true ).checked;\n
\n
\t// Make sure that the options inside disabled selects aren\'t marked as disabled\n
\t// (WebKit marks them as disabled)\n
\tselect.disabled = true;\n
\tsupport.optDisabled = !opt.disabled;\n
\n
\t// Test to see if it\'s possible to delete an expando from an element\n
\t// Fails in Internet Explorer\n
\ttry {\n
\t\tdelete div.test;\n
\t} catch( e ) {\n
\t\tsupport.deleteExpando = false;\n
\t}\n
\n
\tif ( !div.addEventListener && div.attachEvent && div.fireEvent ) {\n
\t\tdiv.attachEvent( "onclick", function() {\n
\t\t\t// Cloning a node shouldn\'t copy over any\n
\t\t\t// bound event handlers (IE does this)\n
\t\t\tsupport.noCloneEvent = false;\n
\t\t});\n
\t\tdiv.cloneNode( true ).fireEvent( "onclick" );\n
\t}\n
\n
\t// Check if a radio maintains its value\n
\t// after being appended to the DOM\n
\tinput = document.createElement("input");\n
\tinput.value = "t";\n
\tinput.setAttribute("type", "radio");\n
\tsupport.radioValue = input.value === "t";\n
\n
\tinput.setAttribute("checked", "checked");\n
\n
\t// #11217 - WebKit loses check when the name is after the checked attribute\n
\tinput.setAttribute( "name", "t" );\n
\n
\tdiv.appendChild( input );\n
\tfragment = document.createDocumentFragment();\n
\tfragment.appendChild( div.lastChild );\n
\n
\t// WebKit doesn\'t clone checked state correctly in fragments\n
\tsupport.checkClone = fragment.cloneNode( true ).cloneNode( true ).lastChild.checked;\n
\n
\t// Check if a disconnected checkbox will retain its checked\n
\t// value of true after appended to the DOM (IE6/7)\n
\tsupport.appendChecked = input.checked;\n
\n
\tfragment.removeChild( input );\n
\tfragment.appendChild( div );\n
\n
\t// Technique from Juriy Zaytsev\n
\t// http://perfectionkills.com/detecting-event-support-without-browser-sniffing/\n
\t// We only care about the case where non-standard event systems\n
\t// are used, namely in IE. Short-circuiting here helps us to\n
\t// avoid an eval call (in setAttribute) which can cause CSP\n
\t// to go haywire. See: https://developer.mozilla.org/en/Security/CSP\n
\tif ( div.attachEvent ) {\n
\t\tfor ( i in {\n
\t\t\tsubmit: 1,\n
\t\t\tchange: 1,\n
\t\t\tfocusin: 1\n
\t\t}) {\n
\t\t\teventName = "on" + i;\n
\t\t\tisSupported = ( eventName in div );\n
\t\t\tif ( !isSupported ) {\n
\t\t\t\tdiv.setAttribute( eventName, "return;" );\n
\t\t\t\tisSupported = ( typeof div[ eventName ] === "function" );\n
\t\t\t}\n
\t\t\tsupport[ i + "Bubbles" ] = isSupported;\n
\t\t}\n
\t}\n
\n
\tfragment.removeChild( div );\n
\n
\t// Null elements to avoid leaks in IE\n
\tfragment = select = opt = div = input = null;\n
\n
\t// Run tests that need a body at doc ready\n
\tjQuery(function() {\n
\t\tvar container, outer, inner, table, td, offsetSupport,\n
\t\t\tmarginDiv, conMarginTop, style, html, positionTopLeftWidthHeight,\n
\t\t\tpaddingMarginBorderVisibility, paddingMarginBorder,\n
\t\t\tbody = document.getElementsByTagName("body")[0];\n
\n
\t\tif ( !body ) {\n
\t\t\t// Return for frameset docs that don\'t have a body\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tconMarginTop = 1;\n
\t\tpaddingMarginBorder = "padding:0;margin:0;border:";\n
\t\tpositionTopLeftWidthHeight = "position:absolute;top:0;left:0;width:1px;height:1px;";\n
\t\tpaddingMarginBorderVisibility = paddingMarginBorder + "0;visibility:hidden;";\n
\t\tstyle = "style=\'" + positionTopLeftWidthHeight + paddingMarginBorder + "5px solid #000;";\n
\t\thtml = "<div " + style + "display:block;\'><div style=\'" + paddingMarginBorder + "0;display:block;overflow:hidden;\'></div></div>" +\n
\t\t\t"<table " + style + "\' cellpadding=\'0\' cellspacing=\'0\'>" +\n
\t\t\t"<tr><td></td></tr></table>";\n
\n
\t\tcontainer = document.createElement("div");\n
\t\tcontainer.style.cssText = paddingMarginBorderVisibility + "width:0;height:0;position:static;top:0;margin-top:" + conMarginTop + "px";\n
\t\tbody.insertBefore( container, body.firstChild );\n
\n
\t\t// Construct the test element\n
\t\tdiv = document.createElement("div");\n
\t\tcontainer.appendChild( div );\n
\n
\t\t// Check if table cells still have offsetWidth/Height when they are set\n
\t\t// to display:none and there are still other visible table cells in a\n
\t\t// table row; if so, offsetWidth/Height are not reliable for use when\n
\t\t// determining if an element has been hidden directly using\n
\t\t// display:none (it is still safe to use offsets if a parent element is\n
\t\t// hidden; don safety goggles and see bug #4512 for more information).\n
\t\t// (only IE 8 fails this test)\n
\t\tdiv.innerHTML = "<table><tr><td style=\'" + paddingMarginBorder + "0;display:none\'></td><td>t</td></tr></table>";\n
\t\ttds = div.getElementsByTagName( "td" );\n
\t\tisSupported = ( tds[ 0 ].offsetHeight === 0 );\n
\n
\t\ttds[ 0 ].style.display = "";\n
\t\ttds[ 1 ].style.display = "none";\n
\n
\t\t// Check if empty table cells still have offsetWidth/Height\n
\t\t// (IE <= 8 fail this test)\n
\t\tsupport.reliableHiddenOffsets = isSupported && ( tds[ 0 ].offsetHeight === 0 );\n
\n
\t\t// Check if div with explicit width and no margin-right incorrectly\n
\t\t// gets computed margin-right based on width of container. For more\n
\t\t// info see bug #3333\n
\t\t// Fails in WebKit before Feb 2011 nightlies\n
\t\t// WebKit Bug 13343 - getComputedStyle returns wrong value for margin-right\n
\t\tif ( window.getComputedStyle ) {\n
\t\t\tdiv.innerHTML = "";\n
\t\t\tmarginDiv = document.createElement( "div" );\n
\t\t\tmarginDiv.style.width = "0";\n
\t\t\tmarginDiv.style.marginRight = "0";\n
\t\t\tdiv.style.width = "2px";\n
\t\t\tdiv.appendChild( marginDiv );\n
\t\t\tsupport.reliableMarginRight =\n
\t\t\t\t( parseInt( ( window.getComputedStyle( marginDiv, null ) || { marginRight: 0 } ).marginRight, 10 ) || 0 ) === 0;\n
\t\t}\n
\n
\t\tif ( typeof div.style.zoom !== "undefined" ) {\n
\t\t\t// Check if natively block-level elements act like inline-block\n
\t\t\t// elements when setting their display to \'inline\' and giving\n
\t\t\t// them layout\n
\t\t\t// (IE < 8 does this)\n
\t\t\tdiv.innerHTML = "";\n
\t\t\tdiv.style.width = div.style.padding = "1px";\n
\t\t\tdiv.style.border = 0;\n
\t\t\tdiv.style.overflow = "hidden";\n
\t\t\tdiv.style.display = "inline";\n
\t\t\tdiv.style.zoom = 1;\n
\t\t\tsupport.inlineBlockNeedsLayout = ( div.offsetWidth === 3 );\n
\n
\t\t\t// Check if elements with layout shrink-wrap their children\n
\t\t\t// (IE 6 does this)\n
\t\t\tdiv.style.display = "block";\n
\t\t\tdiv.style.overflow = "visible";\n
\t\t\tdiv.innerHTML = "<div style=\'width:5px;\'></div>";\n
\t\t\tsupport.shrinkWrapBlocks = ( div.offsetWidth !== 3 );\n
\t\t}\n
\n
\t\tdiv.style.cssText = positionTopLeftWidthHeight + paddingMarginBorderVisibility;\n
\t\tdiv.innerHTML = html;\n
\n
\t\touter = div.firstChild;\n
\t\tinner = outer.firstChild;\n
\t\ttd = outer.nextSibling.firstChild.firstChild;\n
\n
\t\toffsetSupport = {\n
\t\t\tdoesNotAddBorder: ( inner.offsetTop !== 5 ),\n
\t\t\tdoesAddBorderForTableAndCells: ( td.offsetTop === 5 )\n
\t\t};\n
\n
\t\tinner.style.position = "fixed";\n
\t\tinner.style.top = "20px";\n
\n
\t\t// safari subtracts parent border width here which is 5px\n
\t\toffsetSupport.fixedPosition = ( inner.offsetTop === 20 || inner.offsetTop === 15 );\n
\t\tinner.style.position = inner.style.top = "";\n
\n
\t\touter.style.overflow = "hidden";\n
\t\touter.style.position = "relative";\n
\n
\t\toffsetSupport.subtractsBorderForOverflowNotVisible = ( inner.offsetTop === -5 );\n
\t\toffsetSupport.doesNotIncludeMarginInBodyOffset = ( body.offsetTop !== conMarginTop );\n
\n
\t\tif ( window.getComputedStyle ) {\n
\t\t\tdiv.style.marginTop = "1%";\n
\t\t\tsupport.pixelMargin = ( window.getComputedStyle( div, null ) || { marginTop: 0 } ).marginTop !== "1%";\n
\t\t}\n
\n
\t\tif ( typeof container.style.zoom !== "undefined" ) {\n
\t\t\tcontainer.style.zoom = 1;\n
\t\t}\n
\n
\t\tbody.removeChild( container );\n
\t\tmarginDiv = div = container = null;\n
\n
\t\tjQuery.extend( support, offsetSupport );\n
\t});\n
\n
\treturn support;\n
})();\n
\n
\n
\n
\n
var rbrace = /^(?:\\{.*\\}|\\[.*\\])$/,\n
\trmultiDash = /([A-Z])/g;\n
\n
jQuery.extend({\n
\tcache: {},\n
\n
\t// Please use with caution\n
\tuuid: 0,\n
\n
\t// Unique for each copy of jQuery on the page\n
\t// Non-digits removed to match rinlinejQuery\n
\texpando: "jQuery" + ( jQuery.fn.jquery + Math.random() ).replace( /\\D/g, "" ),\n
\n
\t// The following elements throw uncatchable exceptions if you\n
\t// attempt to add expando properties to them.\n
\tnoData: {\n
\t\t"embed": true,\n
\t\t// Ban all objects except for Flash (which handle expandos)\n
\t\t"object": "clsid:D27CDB6E-AE6D-11cf-96B8-444553540000",\n
\t\t"applet": true\n
\t},\n
\n
\thasData: function( elem ) {\n
\t\telem = elem.nodeType ? jQuery.cache[ elem[jQuery.expando] ] : elem[ jQuery.expando ];\n
\t\treturn !!elem && !isEmptyDataObject( elem );\n
\t},\n
\n
\tdata: function( elem, name, data, pvt /* Internal Use Only */ ) {\n
\t\tif ( !jQuery.acceptData( elem ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar privateCache, thisCache, ret,\n
\t\t\tinternalKey = jQuery.expando,\n
\t\t\tgetByName = typeof name === "string",\n
\n
\t\t\t// We have to handle DOM nodes and JS objects differently because IE6-7\n
\t\t\t// can\'t GC object references properly across the DOM-JS boundary\n
\t\t\tisNode = elem.nodeType,\n
\n
\t\t\t// Only DOM nodes need the global jQuery cache; JS object data is\n
\t\t\t// attached directly to the object so GC can occur automatically\n
\t\t\tcache = isNode ? jQuery.cache : elem,\n
\n
\t\t\t// Only defining an ID for JS objects if its cache already exists allows\n
\t\t\t// the code to shortcut on the same path as a DOM node with no cache\n
\t\t\tid = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey,\n
\t\t\tisEvents = name === "events";\n
\n
\t\t// Avoid doing any more work than we need to when trying to get data on an\n
\t\t// object that has no data at all\n
\t\tif ( (!id || !cache[id] || (!isEvents && !pvt && !cache[id].data)) && getByName && data === undefined ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( !id ) {\n
\t\t\t// Only DOM nodes need a new unique ID for each element since their data\n
\t\t\t// ends up in the global cache\n
\t\t\tif ( isNode ) {\n
\t\t\t\telem[ internalKey ] = id = ++jQuery.uuid;\n
\t\t\t} else {\n
\t\t\t\tid = internalKey;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !cache[ id ] ) {\n
\t\t\tcache[ id ] = {};\n
\n
\t\t\t// Avoids exposing jQuery metadata on plain JS objects when the object\n
\t\t\t// is serialized using JSON.stringify\n
\t\t\tif ( !isNode ) {\n
\t\t\t\tcache[ id ].toJSON = jQuery.noop;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// An object can be passed to jQuery.data instead of a key/value pair; this gets\n
\t\t// shallow copied over onto the existing cache\n
\t\tif ( typeof name === "object" || typeof name === "function" ) {\n
\t\t\tif ( pvt ) {\n
\t\t\t\tcache[ id ] = jQuery.extend( cache[ id ], name );\n
\t\t\t} else {\n
\t\t\t\tcache[ id ].data = jQuery.extend( cache[ id ].data, name );\n
\t\t\t}\n
\t\t}\n
\n
\t\tprivateCache = thisCache = cache[ id ];\n
\n
\t\t// jQuery data() is stored in a separate object inside the object\'s internal data\n
\t\t// cache in order to avoid key collisions between internal data and user-defined\n
\t\t// data.\n
\t\tif ( !pvt ) {\n
\t\t\tif ( !thisCache.data ) {\n
\t\t\t\tthisCache.data = {};\n
\t\t\t}\n
\n
\t\t\tthisCache = thisCache.data;\n
\t\t}\n
\n
\t\tif ( data !== undefined ) {\n
\t\t\tthisCache[ jQuery.camelCase( name ) ] = data;\n
\t\t}\n
\n
\t\t// Users should not attempt to inspect the internal events object using jQuery.data,\n
\t\t// it is undocumented and subject to change. But does anyone listen? No.\n
\t\tif ( isEvents && !thisCache[ name ] ) {\n
\t\t\treturn privateCache.events;\n
\t\t}\n
\n
\t\t// Check for both converted-to-camel and non-converted data property names\n
\t\t// If a data property was specified\n
\t\tif ( getByName ) {\n
\n
\t\t\t// First Try to find as-is property data\n
\t\t\tret = thisCache[ name ];\n
\n
\t\t\t// Test for null|undefined property data\n
\t\t\tif ( ret == null ) {\n
\n
\t\t\t\t// Try to find the camelCased property\n
\t\t\t\tret = thisCache[ jQuery.camelCase( name ) ];\n
\t\t\t}\n
\t\t} else {\n
\t\t\tret = thisCache;\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\tremoveData: function( elem, name, pvt /* Internal Use Only */ ) {\n
\t\tif ( !jQuery.acceptData( elem ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar thisCache, i, l,\n
\n
\t\t\t// Reference to internal data cache key\n
\t\t\tinternalKey = jQuery.expando,\n
\n
\t\t\tisNode = elem.nodeType,\n
\n
\t\t\t// See jQuery.data for more information\n
\t\t\tcache = isNode ? jQuery.cache : elem,\n
\n
\t\t\t// See jQuery.data for more information\n
\t\t\tid = isNode ? elem[ internalKey ] : internalKey;\n
\n
\t\t// If there is already no cache entry for this object, there is no\n
\t\t// purpose in continuing\n
\t\tif ( !cache[ id ] ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( name ) {\n
\n
\t\t\tthisCache = pvt ? cache[ id ] : cache[ id ].data;\n
\n
\t\t\tif ( thisCache ) {\n
\n
\t\t\t\t// Support array or space separated string names for data keys\n
\t\t\t\tif ( !jQuery.isArray( name ) ) {\n
\n
\t\t\t\t\t// try the string as a key before any manipulation\n
\t\t\t\t\tif ( name in thisCache ) {\n
\t\t\t\t\t\tname = [ name ];\n
\t\t\t\t\t} else {\n
\n
\t\t\t\t\t\t// split the camel cased version by spaces unless a key with the spaces exists\n
\t\t\t\t\t\tname = jQuery.camelCase( name );\n
\t\t\t\t\t\tif ( name in thisCache ) {\n
\t\t\t\t\t\t\tname = [ name ];\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tname = name.split( " " );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tfor ( i = 0, l = name.length; i < l; i++ ) {\n
\t\t\t\t\tdelete thisCache[ name[i] ];\n
\t\t\t\t}\n
\n
\t\t\t\t// If there is no data left in the cache, we want to continue\n
\t\t\t\t// and let the cache object itself get destroyed\n
\t\t\t\tif ( !( pvt ? isEmptyDataObject : jQuery.isEmptyObject )( thisCache ) ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// See jQuery.data for more information\n
\t\tif ( !pvt ) {\n
\t\t\tdelete cache[ id ].data;\n
\n
\t\t\t// Don\'t destroy the parent cache unless the internal data object\n
\t\t\t// had been the only thing left in it\n
\t\t\tif ( !isEmptyDataObject(cache[ id ]) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Browsers that fail expando deletion also refuse to delete expandos on\n
\t\t// the window, but it will allow it on all other JS objects; other browsers\n
\t\t// don\'t care\n
\t\t// Ensure that `cache` is not a window object #10080\n
\t\tif ( jQuery.support.deleteExpando || !cache.setInterval ) {\n
\t\t\tdelete cache[ id ];\n
\t\t} else {\n
\t\t\tcache[ id ] = null;\n
\t\t}\n
\n
\t\t// We destroyed the cache and need to eliminate the expando on the node to avoid\n
\t\t// false lookups in the cache for entries that no longer exist\n
\t\tif ( isNode ) {\n
\t\t\t// IE does not allow us to delete expando properties from nodes,\n
\t\t\t// nor does it have a removeAttribute function on Document nodes;\n
\t\t\t// we must handle all of these cases\n
\t\t\tif ( jQuery.support.deleteExpando ) {\n
\t\t\t\tdelete elem[ internalKey ];\n
\t\t\t} else if ( elem.removeAttribute ) {\n
\t\t\t\telem.removeAttribute( internalKey );\n
\t\t\t} else {\n
\t\t\t\telem[ internalKey ] = null;\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// For internal use only.\n
\t_data: function( elem, name, data ) {\n
\t\treturn jQuery.data( elem, name, data, true );\n
\t},\n
\n
\t// A method for determining if a DOM node can handle the data expando\n
\tacceptData: function( elem ) {\n
\t\tif ( elem.nodeName ) {\n
\t\t\tvar match = jQuery.noData[ elem.nodeName.toLowerCase() ];\n
\n
\t\t\tif ( match ) {\n
\t\t\t\treturn !(match === true || elem.getAttribute("classid") !== match);\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn true;\n
\t}\n
});\n
\n
jQuery.fn.extend({\n
\tdata: function( key, value ) {\n
\t\tvar parts, part, attr, name, l,\n
\t\t\telem = this[0],\n
\t\t\ti = 0,\n
\t\t\tdata = null;\n
\n
\t\t// Gets all values\n
\t\tif ( key === undefined ) {\n
\t\t\tif ( this.length ) {\n
\t\t\t\tdata = jQuery.data( elem );\n
\n
\t\t\t\tif ( elem.nodeType === 1 && !jQuery._data( elem, "parsedAttrs" ) ) {\n
\t\t\t\t\tattr = elem.attributes;\n
\t\t\t\t\tfor ( l = attr.length; i < l; i++ ) {\n
\t\t\t\t\t\tname = attr[i].name;\n
\n
\t\t\t\t\t\tif ( name.indexOf( "data-" ) === 0 ) {\n
\t\t\t\t\t\t\tname = jQuery.camelCase( name.substring(5) );\n
\n
\t\t\t\t\t\t\tdataAttr( elem, name, data[ name ] );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tjQuery._data( elem, "parsedAttrs", true );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn data;\n
\t\t}\n
\n
\t\t// Sets multiple values\n
\t\tif ( typeof key === "object" ) {\n
\t\t\treturn this.each(function() {\n
\t\t\t\tjQuery.data( this, key );\n
\t\t\t});\n
\t\t}\n
\n
\t\tparts = key.split( ".", 2 );\n
\t\tparts[1] = parts[1] ? "." + parts[1] : "";\n
\t\tpart = parts[1] + "!";\n
\n
\t\treturn jQuery.access( this, function( value ) {\n
\n
\t\t\tif ( value === undefined ) {\n
\t\t\t\tdata = this.triggerHandler( "getData" + part, [ parts[0] ] );\n
\n
\t\t\t\t// Try to fetch any internally stored data first\n
\t\t\t\tif ( data === undefined && elem ) {\n
\t\t\t\t\tdata = jQuery.data( elem, key );\n
\t\t\t\t\tdata = dataAttr( elem, key, data );\n
\t\t\t\t}\n
\n
\t\t\t\treturn data === undefined && parts[1] ?\n
\t\t\t\t\tthis.data( parts[0] ) :\n
\t\t\t\t\tdata;\n
\t\t\t}\n
\n
\t\t\tparts[1] = value;\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar self = jQuery( this );\n
\n
\t\t\t\tself.triggerHandler( "setData" + part, parts );\n
\t\t\t\tjQuery.data( this, key, value );\n
\t\t\t\tself.triggerHandler( "changeData" + part, parts );\n
\t\t\t});\n
\t\t}, null, value, arguments.length > 1, null, false );\n
\t},\n
\n
\tremoveData: function( key ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.removeData( this, key );\n
\t\t});\n
\t}\n
});\n
\n
function dataAttr( elem, key, data ) {\n
\t// If nothing was found internally, try to fetch any\n
\t// data from the HTML5 data-* attribute\n
\tif ( data === undefined && elem.nodeType === 1 ) {\n
\n
\t\tvar name = "data-" + key.replace( rmultiDash, "-$1" ).toLowerCase();\n
\n
\t\tdata = elem.getAttribute( name );\n
\n
\t\tif ( typeof data === "string" ) {\n
\t\t\ttry {\n
\t\t\t\tdata = data === "true" ? true :\n
\t\t\t\tdata === "false" ? false :\n
\t\t\t\tdata === "null" ? null :\n
\t\t\t\tjQuery.isNumeric( data ) ? +data :\n
\t\t\t\t\trbrace.test( data ) ? jQuery.parseJSON( data ) :\n
\t\t\t\t\tdata;\n
\t\t\t} catch( e ) {}\n
\n
\t\t\t// Make sure we set the data so it isn\'t changed later\n
\t\t\tjQuery.data( elem, key, data );\n
\n
\t\t} else {\n
\t\t\tdata = undefined;\n
\t\t}\n
\t}\n
\n
\treturn data;\n
}\n
\n
// checks a cache object for emptiness\n
function isEmptyDataObject( obj ) {\n
\tfor ( var name in obj ) {\n
\n
\t\t// if the public data object is empty, the private is still empty\n
\t\tif ( name === "data" && jQuery.isEmptyObject( obj[name] ) ) {\n
\t\t\tcontinue;\n
\t\t}\n
\t\tif ( name !== "toJSON" ) {\n
\t\t\treturn false;\n
\t\t}\n
\t}\n
\n
\treturn true;\n
}\n
\n
\n
\n
\n
function handleQueueMarkDefer( elem, type, src ) {\n
\tvar deferDataKey = type + "defer",\n
\t\tqueueDataKey = type + "queue",\n
\t\tmarkDataKey = type + "mark",\n
\t\tdefer = jQuery._data( elem, deferDataKey );\n
\tif ( defer &&\n
\t\t( src === "queue" || !jQuery._data(elem, queueDataKey) ) &&\n
\t\t( src === "mark" || !jQuery._data(elem, markDataKey) ) ) {\n
\t\t// Give room for hard-coded callbacks to fire first\n
\t\t// and eventually mark/queue something else on the element\n
\t\tsetTimeout( function() {\n
\t\t\tif ( !jQuery._data( elem, queueDataKey ) &&\n
\t\t\t\t!jQuery._data( elem, markDataKey ) ) {\n
\t\t\t\tjQuery.removeData( elem, deferDataKey, true );\n
\t\t\t\tdefer.fire();\n
\t\t\t}\n
\t\t}, 0 );\n
\t}\n
}\n
\n
jQuery.extend({\n
\n
\t_mark: function( elem, type ) {\n
\t\tif ( elem ) {\n
\t\t\ttype = ( type || "fx" ) + "mark";\n
\t\t\tjQuery._data( elem, type, (jQuery._data( elem, type ) || 0) + 1 );\n
\t\t}\n
\t},\n
\n
\t_unmark: function( force, elem, type ) {\n
\t\tif ( force !== true ) {\n
\t\t\ttype = elem;\n
\t\t\telem = force;\n
\t\t\tforce = false;\n
\t\t}\n
\t\tif ( elem ) {\n
\t\t\ttype = type || "fx";\n
\t\t\tvar key = type + "mark",\n
\t\t\t\tcount = force ? 0 : ( (jQuery._data( elem, key ) || 1) - 1 );\n
\t\t\tif ( count ) {\n
\t\t\t\tjQuery._data( elem, key, count );\n
\t\t\t} else {\n
\t\t\t\tjQuery.removeData( elem, key, true );\n
\t\t\t\thandleQueueMarkDefer( elem, type, "mark" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tqueue: function( elem, type, data ) {\n
\t\tvar q;\n
\t\tif ( elem ) {\n
\t\t\ttype = ( type || "fx" ) + "queue";\n
\t\t\tq = jQuery._data( elem, type );\n
\n
\t\t\t// Speed up dequeue by getting out quickly if this is just a lookup\n
\t\t\tif ( data ) {\n
\t\t\t\tif ( !q || jQuery.isArray(data) ) {\n
\t\t\t\t\tq = jQuery._data( elem, type, jQuery.makeArray(data) );\n
\t\t\t\t} else {\n
\t\t\t\t\tq.push( data );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn q || [];\n
\t\t}\n
\t},\n
\n
\tdequeue: function( elem, type ) {\n
\t\ttype = type || "fx";\n
\n
\t\tvar queue = jQuery.queue( elem, type ),\n
\t\t\tfn = queue.shift(),\n
\t\t\thooks = {};\n
\n
\t\t// If the fx queue is dequeued, always remove the progress sentinel\n
\t\tif ( fn === "inprogress" ) {\n
\t\t\tfn = queue.shift();\n
\t\t}\n
\n
\t\tif ( fn ) {\n
\t\t\t// Add a progress sentinel to prevent the fx queue from being\n
\t\t\t// automatically dequeued\n
\t\t\tif ( type === "fx" ) {\n
\t\t\t\tqueue.unshift( "inprogress" );\n
\t\t\t}\n
\n
\t\t\tjQuery._data( elem, type + ".run", hooks );\n
\t\t\tfn.call( elem, function() {\n
\t\t\t\tjQuery.dequeue( elem, type );\n
\t\t\t}, hooks );\n
\t\t}\n
\n
\t\tif ( !queue.length ) {\n
\t\t\tjQuery.removeData( elem, type + "queue " + type + ".run", true );\n
\t\t\thandleQueueMarkDefer( elem, type, "queue" );\n
\t\t}\n
\t}\n
});\n
\n
jQuery.fn.extend({\n
\tqueue: function( type, data ) {\n
\t\tvar setter = 2;\n
\n
\t\tif ( typeof type !== "string" ) {\n
\t\t\tdata = type;\n
\t\t\ttype = "fx";\n
\t\t\tsetter--;\n
\t\t}\n
\n
\t\tif ( arguments.length < setter ) {\n
\t\t\treturn jQuery.queue( this[0], type );\n
\t\t}\n
\n
\t\treturn data === undefined ?\n
\t\t\tthis :\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar queue = jQuery.queue( this, type, data );\n
\n
\t\t\t\tif ( type === "fx" && queue[0] !== "inprogress" ) {\n
\t\t\t\t\tjQuery.dequeue( this, type );\n
\t\t\t\t}\n
\t\t\t});\n
\t},\n
\tdequeue: function( type ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.dequeue( this, type );\n
\t\t});\n
\t},\n
\t// Based off of the plugin by Clint Helfers, with permission.\n
\t// http://blindsignals.com/index.php/2009/07/jquery-delay/\n
\tdelay: function( time, type ) {\n
\t\ttime = jQuery.fx ? jQuery.fx.speeds[ time ] || time : time;\n
\t\ttype = type || "fx";\n
\n
\t\treturn this.queue( type, function( next, hooks ) {\n
\t\t\tvar timeout = setTimeout( next, time );\n
\t\t\thooks.stop = function() {\n
\t\t\t\tclearTimeout( timeout );\n
\t\t\t};\n
\t\t});\n
\t},\n
\tclearQueue: function( type ) {\n
\t\treturn this.queue( type || "fx", [] );\n
\t},\n
\t// Get a promise resolved when queues of a certain type\n
\t// are emptied (fx is the type by default)\n
\tpromise: function( type, object ) {\n
\t\tif ( typeof type !== "string" ) {\n
\t\t\tobject = type;\n
\t\t\ttype = undefined;\n
\t\t}\n
\t\ttype = type || "fx";\n
\t\tvar defer = jQuery.Deferred(),\n
\t\t\telements = this,\n
\t\t\ti = elements.length,\n
\t\t\tcount = 1,\n
\t\t\tdeferDataKey = type + "defer",\n
\t\t\tqueueDataKey = type + "queue",\n
\t\t\tmarkDataKey = type + "mark",\n
\t\t\ttmp;\n
\t\tfunction resolve() {\n
\t\t\tif ( !( --count ) ) {\n
\t\t\t\tdefer.resolveWith( elements, [ elements ] );\n
\t\t\t}\n
\t\t}\n
\t\twhile( i-- ) {\n
\t\t\tif (( tmp = jQuery.data( elements[ i ], deferDataKey, undefined, true ) ||\n
\t\t\t\t\t( jQuery.data( elements[ i ], queueDataKey, undefined, true ) ||\n
\t\t\t\t\t\tjQuery.data( elements[ i ], markDataKey, undefined, true ) ) &&\n
\t\t\t\t\tjQuery.data( elements[ i ], deferDataKey, jQuery.Callbacks( "once memory" ), true ) )) {\n
\t\t\t\tcount++;\n
\t\t\t\ttmp.add( resolve );\n
\t\t\t}\n
\t\t}\n
\t\tresolve();\n
\t\treturn defer.promise( object );\n
\t}\n
});\n
\n
\n
\n
\n
var rclass = /[\\n\\t\\r]/g,\n
\trspace = /\\s+/,\n
\trreturn = /\\r/g,\n
\trtype = /^(?:button|input)$/i,\n
\trfocusable = /^(?:button|input|object|select|textarea)$/i,\n
\trclickable = /^a(?:rea)?$/i,\n
\trboolean = /^(?:autofocus|autoplay|async|checked|controls|defer|disabled|hidden|loop|multiple|open|readonly|required|scoped|selected)$/i,\n
\tgetSetAttribute = jQuery.support.getSetAttribute,\n
\tnodeHook, boolHook, fixSpecified;\n
\n
jQuery.fn.extend({\n
\tattr: function( name, value ) {\n
\t\treturn jQuery.access( this, jQuery.attr, name, value, arguments.length > 1 );\n
\t},\n
\n
\tremoveAttr: function( name ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.removeAttr( this, name );\n
\t\t});\n
\t},\n
\n
\tprop: function( name, value ) {\n
\t\treturn jQuery.access( this, jQuery.prop, name, value, arguments.length > 1 );\n
\t},\n
\n
\tremoveProp: function( name ) {\n
\t\tname = jQuery.propFix[ name ] || name;\n
\t\treturn this.each(function() {\n
\t\t\t// try/catch handles cases where IE balks (such as removing a property on window)\n
\t\t\ttry {\n
\t\t\t\tthis[ name ] = undefined;\n
\t\t\t\tdelete this[ name ];\n
\t\t\t} catch( e ) {}\n
\t\t});\n
\t},\n
\n
\taddClass: function( value ) {\n
\t\tvar classNames, i, l, elem,\n
\t\t\tsetClass, c, cl;\n
\n
\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\treturn this.each(function( j ) {\n
\t\t\t\tjQuery( this ).addClass( value.call(this, j, this.className) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( value && typeof value === "string" ) {\n
\t\t\tclassNames = value.split( rspace );\n
\n
\t\t\tfor ( i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\telem = this[ i ];\n
\n
\t\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\t\tif ( !elem.className && classNames.length === 1 ) {\n
\t\t\t\t\t\telem.className = value;\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tsetClass = " " + elem.className + " ";\n
\n
\t\t\t\t\t\tfor ( c = 0, cl = classNames.length; c < cl; c++ ) {\n
\t\t\t\t\t\t\tif ( !~setClass.indexOf( " " + classNames[ c ] + " " ) ) {\n
\t\t\t\t\t\t\t\tsetClass += classNames[ c ] + " ";\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telem.className = jQuery.trim( setClass );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tremoveClass: function( value ) {\n
\t\tvar classNames, i, l, elem, className, c, cl;\n
\n
\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\treturn this.each(function( j ) {\n
\t\t\t\tjQuery( this ).removeClass( value.call(this, j, this.className) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( (value && typeof value === "string") || value === undefined ) {\n
\t\t\tclassNames = ( value || "" ).split( rspace );\n
\n
\t\t\tfor ( i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\telem = this[ i ];\n
\n
\t\t\t\tif ( elem.nodeType === 1 && elem.className ) {\n
\t\t\t\t\tif ( value ) {\n
\t\t\t\t\t\tclassName = (" " + elem.className + " ").replace( rclass, " " );\n
\t\t\t\t\t\tfor ( c = 0, cl = classNames.length; c < cl; c++ ) {\n
\t\t\t\t\t\t\tclassName = className.replace(" " + classNames[ c ] + " ", " ");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telem.className = jQuery.trim( className );\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\telem.className = "";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\ttoggleClass: function( value, stateVal ) {\n
\t\tvar type = typeof value,\n
\t\t\tisBool = typeof stateVal === "boolean";\n
\n
\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\treturn this.each(function( i ) {\n
\t\t\t\tjQuery( this ).toggleClass( value.call(this, i, this.className, stateVal), stateVal );\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn this.each(function() {\n
\t\t\tif ( type === "string" ) {\n
\t\t\t\t// toggle individual class names\n
\t\t\t\tvar className,\n
\t\t\t\t\ti = 0,\n
\t\t\t\t\tself = jQuery( this ),\n
\t\t\t\t\tstate = stateVal,\n
\t\t\t\t\tclassNames = value.split( rspace );\n
\n
\t\t\t\twhile ( (className = classNames[ i++ ]) ) {\n
\t\t\t\t\t// check each className given, space seperated list\n
\t\t\t\t\tstate = isBool ? state : !self.hasClass( className );\n
\t\t\t\t\tself[ state ? "addClass" : "removeClass" ]( className );\n
\t\t\t\t}\n
\n
\t\t\t} else if ( type === "undefined" || type === "boolean" ) {\n
\t\t\t\tif ( this.className ) {\n
\t\t\t\t\t// store className if set\n
\t\t\t\t\tjQuery._data( this, "__className__", this.className );\n
\t\t\t\t}\n
\n
\t\t\t\t// toggle whole className\n
\t\t\t\tthis.className = this.className || value === false ? "" : jQuery._data( this, "__className__" ) || "";\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\thasClass: function( selector ) {\n
\t\tvar className = " " + selector + " ",\n
\t\t\ti = 0,\n
\t\t\tl = this.length;\n
\t\tfor ( ; i < l; i++ ) {\n
\t\t\tif ( this[i].nodeType === 1 && (" " + this[i].className + " ").replace(rclass, " ").indexOf( className ) > -1 ) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\tval: function( value ) {\n
\t\tvar hooks, ret, isFunction,\n
\t\t\telem = this[0];\n
\n
\t\tif ( !arguments.length ) {\n
\t\t\tif ( elem ) {\n
\t\t\t\thooks = jQuery.valHooks[ elem.type ] || jQuery.valHooks[ elem.nodeName.toLowerCase() ];\n
\n
\t\t\t\tif ( hooks && "get" in hooks && (ret = hooks.get( elem, "value" )) !== undefined ) {\n
\t\t\t\t\treturn ret;\n
\t\t\t\t}\n
\n
\t\t\t\tret = elem.value;\n
\n
\t\t\t\treturn typeof ret === "string" ?\n
\t\t\t\t\t// handle most common string cases\n
\t\t\t\t\tret.replace(rreturn, "") :\n
\t\t\t\t\t// handle cases where value is null/undef or number\n
\t\t\t\t\tret == null ? "" : ret;\n
\t\t\t}\n
\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tisFunction = jQuery.isFunction( value );\n
\n
\t\treturn this.each(function( i ) {\n
\t\t\tvar self = jQuery(this), val;\n
\n
\t\t\tif ( this.nodeType !== 1 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif ( isFunction ) {\n
\t\t\t\tval = value.call( this, i, self.val() );\n
\t\t\t} else {\n
\t\t\t\tval = value;\n
\t\t\t}\n
\n
\t\t\t// Treat null/undefined as ""; convert numbers to string\n
\t\t\tif ( val == null ) {\n
\t\t\t\tval = "";\n
\t\t\t} else if ( typeof val === "number" ) {\n
\t\t\t\tval += "";\n
\t\t\t} else if ( jQuery.isArray( val ) ) {\n
\t\t\t\tval = jQuery.map(val, function ( value ) {\n
\t\t\t\t\treturn value == null ? "" : value + "";\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\thooks = jQuery.valHooks[ this.type ] || jQuery.valHooks[ this.nodeName.toLowerCase() ];\n
\n
\t\t\t// If set returns undefined, fall back to normal setting\n
\t\t\tif ( !hooks || !("set" in hooks) || hooks.set( this, val, "value" ) === undefined ) {\n
\t\t\t\tthis.value = val;\n
\t\t\t}\n
\t\t});\n
\t}\n
});\n
\n
jQuery.extend({\n
\tvalHooks: {\n
\t\toption: {\n
\t\t\tget: function( elem ) {\n
\t\t\t\t// attributes.value is undefined in Blackberry 4.7 but\n
\t\t\t\t// uses .value. See #6932\n
\t\t\t\tvar val = elem.attributes.value;\n
\t\t\t\treturn !val || val.specified ? elem.value : elem.text;\n
\t\t\t}\n
\t\t},\n
\t\tselect: {\n
\t\t\tget: function( elem ) {\n
\t\t\t\tvar value, i, max, option,\n
\t\t\t\t\tindex = elem.selectedIndex,\n
\t\t\t\t\tvalues = [],\n
\t\t\t\t\toptions = elem.options,\n
\t\t\t\t\tone = elem.type === "select-one";\n
\n
\t\t\t\t// Nothing was selected\n
\t\t\t\tif ( index < 0 ) {\n
\t\t\t\t\treturn null;\n
\t\t\t\t}\n
\n
\t\t\t\t// Loop through all the selected options\n
\t\t\t\ti = one ? index : 0;\n
\t\t\t\tmax = one ? index + 1 : options.length;\n
\t\t\t\tfor ( ; i < max; i++ ) {\n
\t\t\t\t\toption = options[ i ];\n
\n
\t\t\t\t\t// Don\'t return options that are disabled or in a disabled optgroup\n
\t\t\t\t\tif ( option.selected && (jQuery.support.optDisabled ? !option.disabled : option.getAttribute("disabled") === null) &&\n
\t\t\t\t\t\t\t(!option.parentNode.disabled || !jQuery.nodeName( option.parentNode, "optgroup" )) ) {\n
\n
\t\t\t\t\t\t// Get the specific value for the option\n
\t\t\t\t\t\tvalue = jQuery( option ).val();\n
\n
\t\t\t\t\t\t// We don\'t need an array for one selects\n
\t\t\t\t\t\tif ( one ) {\n
\t\t\t\t\t\t\treturn value;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// Multi-Selects return an array\n
\t\t\t\t\t\tvalues.push( value );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Fixes Bug #2551 -- select.val() broken in IE after form.reset()\n
\t\t\t\tif ( one && !values.length && options.length ) {\n
\t\t\t\t\treturn jQuery( options[ index ] ).val();\n
\t\t\t\t}\n
\n
\t\t\t\treturn values;\n
\t\t\t},\n
\n
\t\t\tset: function( elem, value ) {\n
\t\t\t\tvar values = jQuery.makeArray( value );\n
\n
\t\t\t\tjQuery(elem).find("option").each(function() {\n
\t\t\t\t\tthis.selected = jQuery.inArray( jQuery(this).val(), values ) >= 0;\n
\t\t\t\t});\n
\n
\t\t\t\tif ( !values.length ) {\n
\t\t\t\t\telem.selectedIndex = -1;\n
\t\t\t\t}\n
\t\t\t\treturn values;\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tattrFn: {\n
\t\tval: true,\n
\t\tcss: true,\n
\t\thtml: true,\n
\t\ttext: true,\n
\t\tdata: true,\n
\t\twidth: true,\n
\t\theight: true,\n
\t\toffset: true\n
\t},\n
\n
\tattr: function( elem, name, value, pass ) {\n
\t\tvar ret, hooks, notxml,\n
\t\t\tnType = elem.nodeType;\n
\n
\t\t// don\'t get/set attributes on text, comment and attribute nodes\n
\t\tif ( !elem || nType === 3 || nType === 8 || nType === 2 ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( pass && name in jQuery.attrFn ) {\n
\t\t\treturn jQuery( elem )[ name ]( value );\n
\t\t}\n
\n
\t\t// Fallback to prop when attributes are not supported\n
\t\tif ( typeof elem.getAttribute === "undefined" ) {\n
\t\t\treturn jQuery.prop( elem, name, value );\n
\t\t}\n
\n
\t\tnotxml = nType !== 1 || !jQuery.isXMLDoc( elem );\n
\n
\t\t// All attributes are lowercase\n
\t\t// Grab necessary hook if one is defined\n
\t\tif ( notxml ) {\n
\t\t\tname = name.toLowerCase();\n
\t\t\thooks = jQuery.attrHooks[ name ] || ( rboolean.test( name ) ? boolHook : nodeHook );\n
\t\t}\n
\n
\t\tif ( value !== undefined ) {\n
\n
\t\t\tif ( value === null ) {\n
\t\t\t\tjQuery.removeAttr( elem, name );\n
\t\t\t\treturn;\n
\n
\t\t\t} else if ( hooks && "set" in hooks && notxml && (ret = hooks.set( elem, value, name )) !== undefined ) {\n
\t\t\t\treturn ret;\n
\n
\t\t\t} else {\n
\t\t\t\telem.setAttribute( name, "" + value );\n
\t\t\t\treturn value;\n
\t\t\t}\n
\n
\t\t} else if ( hooks && "get" in hooks && notxml && (ret = hooks.get( elem, name )) !== null ) {\n
\t\t\treturn ret;\n
\n
\t\t} else {\n
\n
\t\t\tret = elem.getAttribute( name );\n
\n
\t\t\t// Non-existent attributes return null, we normalize to undefined\n
\t\t\treturn ret === null ?\n
\t\t\t\tundefined :\n
\t\t\t\tret;\n
\t\t}\n
\t},\n
\n
\tremoveAttr: function( elem, value ) {\n
\t\tvar propName, attrNames, name, l, isBool,\n
\t\t\ti = 0;\n
\n
\t\tif ( value && elem.nodeType === 1 ) {\n
\t\t\tattrNames = value.toLowerCase().split( rspace );\n
\t\t\tl = attrNames.length;\n
\n
\t\t\tfor ( ; i < l; i++ ) {\n
\t\t\t\tname = attrNames[ i ];\n
\n
\t\t\t\tif ( name ) {\n
\t\t\t\t\tpropName = jQuery.propFix[ name ] || name;\n
\t\t\t\t\tisBool = rboolean.test( name );\n
\n
\t\t\t\t\t// See #9699 for explanation of this approach (setting first, then removal)\n
\t\t\t\t\t// Do not do this for boolean attributes (see #10870)\n
\t\t\t\t\tif ( !isBool ) {\n
\t\t\t\t\t\tjQuery.attr( elem, name, "" );\n
\t\t\t\t\t}\n
\t\t\t\t\telem.removeAttribute( getSetAttribute ? name : propName );\n
\n
\t\t\t\t\t// Set corresponding property to false for boolean attributes\n
\t\t\t\t\tif ( isBool && propName in elem ) {\n
\t\t\t\t\t\telem[ propName ] = false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tattrHooks: {\n
\t\ttype: {\n
\t\t\tset: function( elem, value ) {\n
\t\t\t\t// We can\'t allow the type property to be changed (since it causes problems in IE)\n
\t\t\t\tif ( rtype.test( elem.nodeName ) && elem.parentNode ) {\n
\t\t\t\t\tjQuery.error( "type property can\'t be changed" );\n
\t\t\t\t} else if ( !jQuery.support.radioValue && value === "radio" && jQuery.nodeName(elem, "input") ) {\n
\t\t\t\t\t// Setting the type on a radio button after the value resets the value in IE6-9\n
\t\t\t\t\t// Reset value to it\'s default in case type is set after value\n
\t\t\t\t\t// This is for element creation\n
\t\t\t\t\tvar val = elem.value;\n
\t\t\t\t\telem.setAttribute( "type", value );\n
\t\t\t\t\tif ( val ) {\n
\t\t\t\t\t\telem.value = val;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\t// Use the value property for back compat\n
\t\t// Use the nodeHook for button elements in IE6/7 (#1954)\n
\t\tvalue: {\n
\t\t\tget: function( elem, name ) {\n
\t\t\t\tif ( nodeHook && jQuery.nodeName( elem, "button" ) ) {\n
\t\t\t\t\treturn nodeHook.get( elem, name );\n
\t\t\t\t}\n
\t\t\t\treturn name in elem ?\n
\t\t\t\t\telem.value :\n
\t\t\t\t\tnull;\n
\t\t\t},\n
\t\t\tset: function( elem, value, name ) {\n
\t\t\t\tif ( nodeHook && jQuery.nodeName( elem, "button" ) ) {\n
\t\t\t\t\treturn nodeHook.set( elem, value, name );\n
\t\t\t\t}\n
\t\t\t\t// Does not return so that setAttribute is also used\n
\t\t\t\telem.value = value;\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tpropFix: {\n
\t\ttabindex: "tabIndex",\n
\t\treadonly: "readOnly",\n
\t\t"for": "htmlFor",\n
\t\t"class": "className",\n
\t\tmaxlength: "maxLength",\n
\t\tcellspacing: "cellSpacing",\n
\t\tcellpadding: "cellPadding",\n
\t\trowspan: "rowSpan",\n
\t\tcolspan: "colSpan",\n
\t\tusemap: "useMap",\n
\t\tframeborder: "frameBorder",\n
\t\tcontenteditable: "contentEditable"\n
\t},\n
\n
\tprop: function( elem, name, value ) {\n
\t\tvar ret, hooks, notxml,\n
\t\t\tnType = elem.nodeType;\n
\n
\t\t// don\'t get/set properties on text, comment and attribute nodes\n
\t\tif ( !elem || nType === 3 || nType === 8 || nType === 2 ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tnotxml = nType !== 1 || !jQuery.isXMLDoc( elem );\n
\n
\t\tif ( notxml ) {\n
\t\t\t// Fix name and attach hooks\n
\t\t\tname = jQuery.propFix[ name ] || name;\n
\t\t\thooks = jQuery.propHooks[ name ];\n
\t\t}\n
\n
\t\tif ( value !== undefined ) {\n
\t\t\tif ( hooks && "set" in hooks && (ret = hooks.set( elem, value, name )) !== undefined ) {\n
\t\t\t\treturn ret;\n
\n
\t\t\t} else {\n
\t\t\t\treturn ( elem[ name ] = value );\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\tif ( hooks && "get" in hooks && (ret = hooks.get( elem, name )) !== null ) {\n
\t\t\t\treturn ret;\n
\n
\t\t\t} else {\n
\t\t\t\treturn elem[ name ];\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tpropHooks: {\n
\t\ttabIndex: {\n
\t\t\tget: function( elem ) {\n
\t\t\t\t// elem.tabIndex doesn\'t always return the correct value when it hasn\'t been explicitly set\n
\t\t\t\t// http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-values-with-javascript/\n
\t\t\t\tvar attributeNode = elem.getAttributeNode("tabindex");\n
\n
\t\t\t\treturn attributeNode && attributeNode.specified ?\n
\t\t\t\t\tparseInt( attributeNode.value, 10 ) :\n
\t\t\t\t\trfocusable.test( elem.nodeName ) || rclickable.test( elem.nodeName ) && elem.href ?\n
\t\t\t\t\t\t0 :\n
\t\t\t\t\t\tundefined;\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
// Add the tabIndex propHook to attrHooks for back-compat (different case is intentional)\n
jQuery.attrHooks.tabindex = jQuery.propHooks.tabIndex;\n
\n
// Hook for boolean attributes\n
boolHook = {\n
\tget: function( elem, name ) {\n
\t\t// Align boolean attributes with corresponding properties\n
\t\t// Fall back to attribute presence where some booleans are not supported\n
\t\tvar attrNode,\n
\t\t\tproperty = jQuery.prop( elem, name );\n
\t\treturn property === true || typeof property !== "boolean" && ( attrNode = elem.getAttributeNode(name) ) && attrNode.nodeValue !== false ?\n
\t\t\tname.toLowerCase() :\n
\t\t\tundefined;\n
\t},\n
\tset: function( elem, value, name ) {\n
\t\tvar propName;\n
\t\tif ( value === false ) {\n
\t\t\t// Remove boolean attributes when set to false\n
\t\t\tjQuery.removeAttr( elem, name );\n
\t\t} else {\n
\t\t\t// value is true since we know at this point it\'s type boolean and not false\n
\t\t\t// Set boolean attributes to the same name and set the DOM property\n
\t\t\tpropName = jQuery.propFix[ name ] || name;\n
\t\t\tif ( propName in elem ) {\n
\t\t\t\t// Only set the IDL specifically if it already exists on the element\n
\t\t\t\telem[ propName ] = true;\n
\t\t\t}\n
\n
\t\t\telem.setAttribute( name, name.toLowerCase() );\n
\t\t}\n
\t\treturn name;\n
\t}\n
};\n
\n
// IE6/7 do not support getting/setting some attributes with get/setAttribute\n
if ( !getSetAttribute ) {\n
\n
\tfixSpecified = {\n
\t\tname: true,\n
\t\tid: true,\n
\t\tcoords: true\n
\t};\n
\n
\t// Use this for any attribute in IE6/7\n
\t// This fixes almost every IE6/7 issue\n
\tnodeHook = jQuery.valHooks.button = {\n
\t\tget: function( elem, name ) {\n
\t\t\tvar ret;\n
\t\t\tret = elem.getAttributeNode( name );\n
\t\t\treturn ret && ( fixSpecified[ name ] ? ret.nodeValue !== "" : ret.specified ) ?\n
\t\t\t\tret.nodeValue :\n
\t\t\t\tundefined;\n
\t\t},\n
\t\tset: function( elem, value, name ) {\n
\t\t\t// Set the existing or create a new attribute node\n
\t\t\tvar ret = elem.getAttributeNode( name );\n
\t\t\tif ( !ret ) {\n
\t\t\t\tret = document.createAttribute( name );\n
\t\t\t\telem.setAttributeNode( ret );\n
\t\t\t}\n
\t\t\treturn ( ret.nodeValue = value + "" );\n
\t\t}\n
\t};\n
\n
\t// Apply the nodeHook to tabindex\n
\tjQuery.attrHooks.tabindex.set = nodeHook.set;\n
\n
\t// Set width and height to auto instead of 0 on empty string( Bug #8150 )\n
\t// This is for removals\n
\tjQuery.each([ "width", "height" ], function( i, name ) {\n
\t\tjQuery.attrHooks[ name ] = jQuery.extend( jQuery.attrHooks[ name ], {\n
\t\t\tset: function( elem, value ) {\n
\t\t\t\tif ( value === "" ) {\n
\t\t\t\t\telem.setAttribute( name, "auto" );\n
\t\t\t\t\treturn value;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\t});\n
\n
\t// Set contenteditable to false on removals(#10429)\n
\t// Setting to empty string throws an error as an invalid value\n
\tjQuery.attrHooks.contenteditable = {\n
\t\tget: nodeHook.get,\n
\t\tset: function( elem, value, name ) {\n
\t\t\tif ( value === "" ) {\n
\t\t\t\tvalue = "false";\n
\t\t\t}\n
\t\t\tnodeHook.set( elem, value, name );\n
\t\t}\n
\t};\n
}\n
\n
\n
// Some attributes require a special call on IE\n
if ( !jQuery.support.hrefNormalized ) {\n
\tjQuery.each([ "href", "src", "width", "height" ], function( i, name ) {\n
\t\tjQuery.attrHooks[ name ] = jQuery.extend( jQuery.attrHooks[ name ], {\n
\t\t\tget: function( elem ) {\n
\t\t\t\tvar ret = elem.getAttribute( name, 2 );\n
\t\t\t\treturn ret === null ? undefined : ret;\n
\t\t\t}\n
\t\t});\n
\t});\n
}\n
\n
if ( !jQuery.support.style ) {\n
\tjQuery.attrHooks.style = {\n
\t\tget: function( elem ) {\n
\t\t\t// Return undefined in the case of empty string\n
\t\t\t// Normalize to lowercase since IE uppercases css property names\n
\t\t\treturn elem.style.cssText.toLowerCase() || undefined;\n
\t\t},\n
\t\tset: function( elem, value ) {\n
\t\t\treturn ( elem.style.cssText = "" + value );\n
\t\t}\n
\t};\n
}\n
\n
// Safari mis-reports the default selected property of an option\n
// Accessing the parent\'s selectedIndex property fixes it\n
if ( !jQuery.support.optSelected ) {\n
\tjQuery.propHooks.selected = jQuery.extend( jQuery.propHooks.selected, {\n
\t\tget: function( elem ) {\n
\t\t\tvar parent = elem.parentNode;\n
\n
\t\t\tif ( parent ) {\n
\t\t\t\tparent.selectedIndex;\n
\n
\t\t\t\t// Make sure that it also works with optgroups, see #5701\n
\t\t\t\tif ( parent.parentNode ) {\n
\t\t\t\t\tparent.parentNode.selectedIndex;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn null;\n
\t\t}\n
\t});\n
}\n
\n
// IE6/7 call enctype encoding\n
if ( !jQuery.support.enctype ) {\n
\tjQuery.propFix.enctype = "encoding";\n
}\n
\n
// Radios and checkboxes getter/setter\n
if ( !jQuery.support.checkOn ) {\n
\tjQuery.each([ "radio", "checkbox" ], function() {\n
\t\tjQuery.valHooks[ this ] = {\n
\t\t\tget: function( elem ) {\n
\t\t\t\t// Handle the case where in Webkit "" is returned instead of "on" if a value isn\'t specified\n
\t\t\t\treturn elem.getAttribute("value") === null ? "on" : elem.value;\n
\t\t\t}\n
\t\t};\n
\t});\n
}\n
jQuery.each([ "radio", "checkbox" ], function() {\n
\tjQuery.valHooks[ this ] = jQuery.extend( jQuery.valHooks[ this ], {\n
\t\tset: function( elem, value ) {\n
\t\t\tif ( jQuery.isArray( value ) ) {\n
\t\t\t\treturn ( elem.checked = jQuery.inArray( jQuery(elem).val(), value ) >= 0 );\n
\t\t\t}\n
\t\t}\n
\t});\n
});\n
\n
\n
\n
\n
var rformElems = /^(?:textarea|input|select)$/i,\n
\trtypenamespace = /^([^\\.]*)?(?:\\.(.+))?$/,\n
\trhoverHack = /(?:^|\\s)hover(\\.\\S+)?\\b/,\n
\trkeyEvent = /^key/,\n
\trmouseEvent = /^(?:mouse|contextmenu)|click/,\n
\trfocusMorph = /^(?:focusinfocus|focusoutblur)$/,\n
\trquickIs = /^(\\w*)(?:#([\\w\\-]+))?(?:\\.([\\w\\-]+))?$/,\n
\tquickParse = function( selector ) {\n
\t\tvar quick = rquickIs.exec( selector );\n
\t\tif ( quick ) {\n
\t\t\t//   0  1    2   3\n
\t\t\t// [ _, tag, id, class ]\n
\t\t\tquick[1] = ( quick[1] || "" ).toLowerCase();\n
\t\t\tquick[3] = quick[3] && new RegExp( "(?:^|\\\\s)" + quick[3] + "(?:\\\\s|$)" );\n
\t\t}\n
\t\treturn quick;\n
\t},\n
\tquickIs = function( elem, m ) {\n
\t\tvar attrs = elem.attributes || {};\n
\t\treturn (\n
\t\t\t(!m[1] || elem.nodeName.toLowerCase() === m[1]) &&\n
\t\t\t(!m[2] || (attrs.id || {}).value === m[2]) &&\n
\t\t\t(!m[3] || m[3].test( (attrs[ "class" ] || {}).value ))\n
\t\t);\n
\t},\n
\thoverHack = function( events ) {\n
\t\treturn jQuery.event.special.hover ? events : events.replace( rhoverHack, "mouseenter$1 mouseleave$1" );\n
\t};\n
\n
/*\n
 * Helper functions for managing events -- not part of the public interface.\n
 * Props to Dean Edwards\' addEvent library for many of the ideas.\n
 */\n
jQuery.event = {\n
\n
\tadd: function( elem, types, handler, data, selector ) {\n
\n
\t\tvar elemData, eventHandle, events,\n
\t\t\tt, tns, type, namespaces, handleObj,\n
\t\t\thandleObjIn, quick, handlers, special;\n
\n
\t\t// Don\'t attach events to noData or text/comment nodes (allow plain objects tho)\n
\t\tif ( elem.nodeType === 3 || elem.nodeType === 8 || !types || !handler || !(elemData = jQuery._data( elem )) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Caller can pass in an object of custom data in lieu of the handler\n
\t\tif ( handler.handler ) {\n
\t\t\thandleObjIn = handler;\n
\t\t\thandler = handleObjIn.handler;\n
\t\t\tselector = handleObjIn.selector;\n
\t\t}\n
\n
\t\t// Make sure that the handler has a unique ID, used to find/remove it later\n
\t\tif ( !handler.guid ) {\n
\t\t\thandler.guid = jQuery.guid++;\n
\t\t}\n
\n
\t\t// Init the element\'s event structure and main handler, if this is the first\n
\t\tevents = elemData.events;\n
\t\tif ( !events ) {\n
\t\t\telemData.events = events = {};\n
\t\t}\n
\t\teventHandle = elemData.handle;\n
\t\tif ( !eventHandle ) {\n
\t\t\telemData.handle = eventHandle = function( e ) {\n
\t\t\t\t// Discard the second event of a jQuery.event.trigger() and\n
\t\t\t\t// when an event is called after a page has unloaded\n
\t\t\t\treturn typeof jQuery !== "undefined" && (!e || jQuery.event.triggered !== e.type) ?\n
\t\t\t\t\tjQuery.event.dispatch.apply( eventHandle.elem, arguments ) :\n
\t\t\t\t\tundefined;\n
\t\t\t};\n
\t\t\t// Add elem as a property of the handle fn to prevent a memory leak with IE non-native events\n
\t\t\teventHandle.elem = elem;\n
\t\t}\n
\n
\t\t// Handle multiple events separated by a space\n
\t\t// jQuery(...).bind("mouseover mouseout", fn);\n
\t\ttypes = jQuery.trim( hoverHack(types) ).split( " " );\n
\t\tfor ( t = 0; t < types.length; t++ ) {\n
\n
\t\t\ttns = rtypenamespace.exec( types[t] ) || [];\n
\t\t\ttype = tns[1];\n
\t\t\tnamespaces = ( tns[2] || "" ).split( "." ).sort();\n
\n
\t\t\t// If event changes its type, use the special event handlers for the changed type\n
\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\n
\t\t\t// If selector defined, determine special event api type, otherwise given type\n
\t\t\ttype = ( selector ? special.delegateType : special.bindType ) || type;\n
\n
\t\t\t// Update special based on newly reset type\n
\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\n
\t\t\t// handleObj is passed to all event handlers\n
\t\t\thandleObj = jQuery.extend({\n
\t\t\t\ttype: type,\n
\t\t\t\torigType: tns[1],\n
\t\t\t\tdata: data,\n
\t\t\t\thandler: handler,\n
\t\t\t\tguid: handler.guid,\n
\t\t\t\tselector: selector,\n
\t\t\t\tquick: selector && quickParse( selector ),\n
\t\t\t\tnamespace: namespaces.join(".")\n
\t\t\t}, handleObjIn );\n
\n
\t\t\t// Init the event handler queue if we\'re the first\n
\t\t\thandlers = events[ type ];\n
\t\t\tif ( !handlers ) {\n
\t\t\t\thandlers = events[ type ] = [];\n
\t\t\t\thandlers.delegateCount = 0;\n
\n
\t\t\t\t// Only use addEventListener/attachEvent if the special events handler returns false\n
\t\t\t\tif ( !special.setup || special.setup.call( elem, data, namespaces, eventHandle ) === false ) {\n
\t\t\t\t\t// Bind the global event handler to the element\n
\t\t\t\t\tif ( elem.addEventListener ) {\n
\t\t\t\t\t\telem.addEventListener( type, eventHandle, false );\n
\n
\t\t\t\t\t} else if ( elem.attachEvent ) {\n
\t\t\t\t\t\telem.attachEvent( "on" + type, eventHandle );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( special.add ) {\n
\t\t\t\tspecial.add.call( elem, handleObj );\n
\n
\t\t\t\tif ( !handleObj.handler.guid ) {\n
\t\t\t\t\thandleObj.handler.guid = handler.guid;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Add to the element\'s handler list, delegates in front\n
\t\t\tif ( selector ) {\n
\t\t\t\thandlers.splice( handlers.delegateCount++, 0, handleObj );\n
\t\t\t} else {\n
\t\t\t\thandlers.push( handleObj );\n
\t\t\t}\n
\n
\t\t\t// Keep track of which events have ever been used, for event optimization\n
\t\t\tjQuery.event.global[ type ] = true;\n
\t\t}\n
\n
\t\t// Nullify elem to prevent memory leaks in IE\n
\t\telem = null;\n
\t},\n
\n
\tglobal: {},\n
\n
\t// Detach an event or set of events from an element\n
\tremove: function( elem, types, handler, selector, mappedTypes ) {\n
\n
\t\tvar elemData = jQuery.hasData( elem ) && jQuery._data( elem ),\n
\t\t\tt, tns, type, origType, namespaces, origCount,\n
\t\t\tj, events, special, handle, eventType, handleObj;\n
\n
\t\tif ( !elemData || !(events = elemData.events) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Once for each type.namespace in types; type may be omitted\n
\t\ttypes = jQuery.trim( hoverHack( types || "" ) ).split(" ");\n
\t\tfor ( t = 0; t < types.length; t++ ) {\n
\t\t\ttns = rtypenamespace.exec( types[t] ) || [];\n
\t\t\ttype = origType = tns[1];\n
\t\t\tnamespaces = tns[2];\n
\n
\t\t\t// Unbind all events (on this namespace, if provided) for the element\n
\t\t\tif ( !type ) {\n
\t\t\t\tfor ( type in events ) {\n
\t\t\t\t\tjQuery.event.remove( elem, type + types[ t ], handler, selector, true );\n
\t\t\t\t}\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\t\t\ttype = ( selector? special.delegateType : special.bindType ) || type;\n
\t\t\teventType = events[ type ] || [];\n
\t\t\torigCount = eventType.length;\n
\t\t\tnamespaces = namespaces ? new RegExp("(^|\\\\.)" + namespaces.split(".").sort().join("\\\\.(?:.*\\\\.)?") + "(\\\\.|$)") : null;\n
\n
\t\t\t// Remove matching events\n
\t\t\tfor ( j = 0; j < eventType.length; j++ ) {\n
\t\t\t\thandleObj = eventType[ j ];\n
\n
\t\t\t\tif ( ( mappedTypes || origType === handleObj.origType ) &&\n
\t\t\t\t\t ( !handler || handler.guid === handleObj.guid ) &&\n
\t\t\t\t\t ( !namespaces || namespaces.test( handleObj.namespace ) ) &&\n
\t\t\t\t\t ( !selector || selector === handleObj.selector || selector === "**" && handleObj.selector ) ) {\n
\t\t\t\t\teventType.splice( j--, 1 );\n
\n
\t\t\t\t\tif ( handleObj.selector ) {\n
\t\t\t\t\t\teventType.delegateCount--;\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( special.remove ) {\n
\t\t\t\t\t\tspecial.remove.call( elem, handleObj );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Remove generic event handler if we removed something and no more handlers exist\n
\t\t\t// (avoids potential for endless recursion during removal of special event handlers)\n
\t\t\tif ( eventType.length === 0 && origCount !== eventType.length ) {\n
\t\t\t\tif ( !special.teardown || special.teardown.call( elem, namespaces ) === false ) {\n
\t\t\t\t\tjQuery.removeEvent( elem, type, elemData.handle );\n
\t\t\t\t}\n
\n
\t\t\t\tdelete events[ type ];\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Remove the expando if it\'s no longer used\n
\t\tif ( jQuery.isEmptyObject( events ) ) {\n
\t\t\thandle = elemData.handle;\n
\t\t\tif ( handle ) {\n
\t\t\t\thandle.elem = null;\n
\t\t\t}\n
\n
\t\t\t// removeData also checks for emptiness and clears the expando if empty\n
\t\t\t// so use it instead of delete\n
\t\t\tjQuery.removeData( elem, [ "events", "handle" ], true );\n
\t\t}\n
\t},\n
\n
\t// Events that are safe to short-circuit if no handlers are attached.\n
\t// Native DOM events should not be added, they may have inline handlers.\n
\tcustomEvent: {\n
\t\t"getData": true,\n
\t\t"setData": true,\n
\t\t"changeData": true\n
\t},\n
\n
\ttrigger: function( event, data, elem, onlyHandlers ) {\n
\t\t// Don\'t do events on text and comment nodes\n
\t\tif ( elem && (elem.nodeType === 3 || elem.nodeType === 8) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Event object or event type\n
\t\tvar type = event.type || event,\n
\t\t\tnamespaces = [],\n
\t\t\tcache, exclusive, i, cur, old, ontype, special, handle, eventPath, bubbleType;\n
\n
\t\t// focus/blur morphs to focusin/out; ensure we\'re not firing them right now\n
\t\tif ( rfocusMorph.test( type + jQuery.event.triggered ) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( type.indexOf( "!" ) >= 0 ) {\n
\t\t\t// Exclusive events trigger only for the exact event (no namespaces)\n
\t\t\ttype = type.slice(0, -1);\n
\t\t\texclusive = true;\n
\t\t}\n
\n
\t\tif ( type.indexOf( "." ) >= 0 ) {\n
\t\t\t// Namespaced trigger; create a regexp to match event type in handle()\n
\t\t\tnamespaces = type.split(".");\n
\t\t\ttype = namespaces.shift();\n
\t\t\tnamespaces.sort();\n
\t\t}\n
\n
\t\tif ( (!elem || jQuery.event.customEvent[ type ]) && !jQuery.event.global[ type ] ) {\n
\t\t\t// No jQuery handlers for this event type, and it can\'t have inline handlers\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Caller can pass in an Event, Object, or just an event type string\n
\t\tevent = typeof event === "object" ?\n
\t\t\t// jQuery.Event object\n
\t\t\tevent[ jQuery.expando ] ? event :\n
\t\t\t// Object literal\n
\t\t\tnew jQuery.Event( type, event ) :\n
\t\t\t// Just the event type (string)\n
\t\t\tnew jQuery.Event( type );\n
\n
\t\tevent.type = type;\n
\t\tevent.isTrigger = true;\n
\t\tevent.exclusive = exclusive;\n
\t\tevent.namespace = namespaces.join( "." );\n
\t\tevent.namespace_re = event.namespace? new RegExp("(^|\\\\.)" + namespaces.join("\\\\.(?:.*\\\\.)?") + "(\\\\.|$)") : null;\n
\t\tontype = type.indexOf( ":" ) < 0 ? "on" + type : "";\n
\n
\t\t// Handle a global trigger\n
\t\tif ( !elem ) {\n
\n
\t\t\t// TODO: Stop taunting the data cache; remove global events and always attach to document\n
\t\t\tcache = jQuery.cache;\n
\t\t\tfor ( i in cache ) {\n
\t\t\t\tif ( cache[ i ].events && cache[ i ].events[ type ] ) {\n
\t\t\t\t\tjQuery.event.trigger( event, data, cache[ i ].handle.elem, true );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Clean up the event in case it is being reused\n
\t\tevent.result = undefined;\n
\t\tif ( !event.target ) {\n
\t\t\tevent.target = elem;\n
\t\t}\n
\n
\t\t// Clone any incoming data and prepend the event, creating the handler arg list\n
\t\tdata = data != null ? jQuery.makeArray( data ) : [];\n
\t\tdata.unshift( event );\n
\n
\t\t// Allow special events to draw outside the lines\n
\t\tspecial = jQuery.event.special[ type ] || {};\n
\t\tif ( special.trigger && special.trigger.apply( elem, data ) === false ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Determine event propagation path in advance, per W3C events spec (#9951)\n
\t\t// Bubble up to document, then to window; watch for a global ownerDocument var (#9724)\n
\t\teventPath = [[ elem, special.bindType || type ]];\n
\t\tif ( !onlyHandlers && !special.noBubble && !jQuery.isWindow( elem ) ) {\n
\n
\t\t\tbubbleType = special.delegateType || type;\n
\t\t\tcur = rfocusMorph.test( bubbleType + type ) ? elem : elem.parentNode;\n
\t\t\told = null;\n
\t\t\tfor ( ; cur; cur = cur.parentNode ) {\n
\t\t\t\teventPath.push([ cur, bubbleType ]);\n
\t\t\t\told = cur;\n
\t\t\t}\n
\n
\t\t\t// Only add window if we got to document (e.g., not plain obj or detached DOM)\n
\t\t\tif ( old && old === elem.ownerDocument ) {\n
\t\t\t\teventPath.push([ old.defaultView || old.parentWindow || window, bubbleType ]);\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Fire handlers on the event path\n
\t\tfor ( i = 0; i < eventPath.length && !event.isPropagationStopped(); i++ ) {\n
\n
\t\t\tcur = eventPath[i][0];\n
\t\t\tevent.type = eventPath[i][1];\n
\n
\t\t\thandle = ( jQuery._data( cur, "events" ) || {} )[ event.type ] && jQuery._data( cur, "handle" );\n
\t\t\tif ( handle ) {\n
\t\t\t\thandle.apply( cur, data );\n
\t\t\t}\n
\t\t\t// Note that this is a bare JS function and not a jQuery handler\n
\t\t\thandle = ontype && cur[ ontype ];\n
\t\t\tif ( handle && jQuery.acceptData( cur ) && handle.apply( cur, data ) === false ) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t}\n
\t\t}\n
\t\tevent.type = type;\n
\n
\t\t// If nobody prevented the default action, do it now\n
\t\tif ( !onlyHandlers && !event.isDefaultPrevented() ) {\n
\n
\t\t\tif ( (!special._default || special._default.apply( elem.ownerDocument, data ) === false) &&\n
\t\t\t\t!(type === "click" && jQuery.nodeName( elem, "a" )) && jQuery.acceptData( elem ) ) {\n
\n
\t\t\t\t// Call a native DOM method on the target with the same name name as the event.\n
\t\t\t\t// Can\'t use an .isFunction() check here because IE6/7 fails that test.\n
\t\t\t\t// Don\'t do default actions on window, that\'s where global variables be (#6170)\n
\t\t\t\t// IE<9 dies on focus/blur to hidden element (#1486)\n
\t\t\t\tif ( ontype && elem[ type ] && ((type !== "focus" && type !== "blur") || event.target.offsetWidth !== 0) && !jQuery.isWindow( elem ) ) {\n
\n
\t\t\t\t\t// Don\'t re-trigger an onFOO event when we call its FOO() method\n
\t\t\t\t\told = elem[ ontype ];\n
\n
\t\t\t\t\tif ( old ) {\n
\t\t\t\t\t\telem[ ontype ] = null;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Prevent re-triggering of the same event, since we already bubbled it above\n
\t\t\t\t\tjQuery.event.triggered = type;\n
\t\t\t\t\telem[ type ]();\n
\t\t\t\t\tjQuery.event.triggered = undefined;\n
\n
\t\t\t\t\tif ( old ) {\n
\t\t\t\t\t\telem[ ontype ] = old;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn event.result;\n
\t},\n
\n
\tdispatch: function( event ) {\n
\n
\t\t// Make a writable jQuery.Event from the native event object\n
\t\tevent = jQuery.event.fix( event || window.event );\n
\n
\t\tvar handlers = ( (jQuery._data( this, "events" ) || {} )[ event.type ] || []),\n
\t\t\tdelegateCount = handlers.delegateCount,\n
\t\t\targs = [].slice.call( arguments, 0 ),\n
\t\t\trun_all = !event.exclusive && !event.namespace,\n
\t\t\tspecial = jQuery.event.special[ event.type ] || {},\n
\t\t\thandlerQueue = [],\n
\t\t\ti, j, cur, jqcur, ret, selMatch, matched, matches, handleObj, sel, related;\n
\n
\t\t// Use the fix-ed jQuery.Event rather than the (read-only) native event\n
\t\targs[0] = event;\n
\t\tevent.delegateTarget = this;\n
\n
\t\t// Call the preDispatch hook for the mapped type, and let it bail if desired\n
\t\tif ( special.preDispatch && special.preDispatch.call( this, event ) === false ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Determine handlers that should run if there are delegated events\n
\t\t// Avoid non-left-click bubbling in Firefox (#3861)\n
\t\tif ( delegateCount && !(event.button && event.type === "click") ) {\n
\n
\t\t\t// Pregenerate a single jQuery object for reuse with .is()\n
\t\t\tjqcur = jQuery(this);\n
\t\t\tjqcur.context = this.ownerDocument || this;\n
\n
\t\t\tfor ( cur = event.target; cur != this; cur = cur.parentNode || this ) {\n
\n
\t\t\t\t// Don\'t process events on disabled elements (#6911, #8165)\n
\t\t\t\tif ( cur.disabled !== true ) {\n
\t\t\t\t\tselMatch = {};\n
\t\t\t\t\tmatches = [];\n
\t\t\t\t\tjqcur[0] = cur;\n
\t\t\t\t\tfor ( i = 0; i < delegateCount; i++ ) {\n
\t\t\t\t\t\thandleObj = handlers[ i ];\n
\t\t\t\t\t\tsel = handleObj.selector;\n
\n
\t\t\t\t\t\tif ( selMatch[ sel ] === undefined ) {\n
\t\t\t\t\t\t\tselMatch[ sel ] = (\n
\t\t\t\t\t\t\t\thandleObj.quick ? quickIs( cur, handleObj.quick ) : jqcur.is( sel )\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif ( selMatch[ sel ] ) {\n
\t\t\t\t\t\t\tmatches.push( handleObj );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( matches.length ) {\n
\t\t\t\t\t\thandlerQueue.push({ elem: cur, matches: matches });\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Add the remaining (directly-bound) handlers\n
\t\tif ( handlers.length > delegateCount ) {\n
\t\t\thandlerQueue.push({ elem: this, matches: handlers.slice( delegateCount ) });\n
\t\t}\n
\n
\t\t// Run delegates first; they may want to stop propagation beneath us\n
\t\tfor ( i = 0; i < handlerQueue.length && !event.isPropagationStopped(); i++ ) {\n
\t\t\tmatched = handlerQueue[ i ];\n
\t\t\tevent.currentTarget = matched.elem;\n
\n
\t\t\tfor ( j = 0; j < matched.matches.length && !event.isImmediatePropagationStopped(); j++ ) {\n
\t\t\t\thandleObj = matched.matches[ j ];\n
\n
\t\t\t\t// Triggered event must either 1) be non-exclusive and have no namespace, or\n
\t\t\t\t// 2) have namespace(s) a subset or equal to those in the bound event (both can have no namespace).\n
\t\t\t\tif ( run_all || (!event.namespace && !handleObj.namespace) || event.namespace_re && event.namespace_re.test( handleObj.namespace ) ) {\n
\n
\t\t\t\t\tevent.data = handleObj.data;\n
\t\t\t\t\tevent.handleObj = handleObj;\n
\n
\t\t\t\t\tret = ( (jQuery.event.special[ handleObj.origType ] || {}).handle || handleObj.handler )\n
\t\t\t\t\t\t\t.apply( matched.elem, args );\n
\n
\t\t\t\t\tif ( ret !== undefined ) {\n
\t\t\t\t\t\tevent.result = ret;\n
\t\t\t\t\t\tif ( ret === false ) {\n
\t\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\t\tevent.stopPropagation();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Call the postDispatch hook for the mapped type\n
\t\tif ( special.postDispatch ) {\n
\t\t\tspecial.postDispatch.call( this, event );\n
\t\t}\n
\n
\t\treturn event.result;\n
\t},\n
\n
\t// Includes some event props shared by KeyEvent and MouseEvent\n
\t// *** attrChange attrName relatedNode srcElement  are not normalized, non-W3C, deprecated, will be removed in 1.8 ***\n
\tprops: "attrChange attrName relatedNode srcElement altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),\n
\n
\tfixHooks: {},\n
\n
\tkeyHooks: {\n
\t\tprops: "char charCode key keyCode".split(" "),\n
\t\tfilter: function( event, original ) {\n
\n
\t\t\t// Add which for key events\n
\t\t\tif ( event.which == null ) {\n
\t\t\t\tevent.which = original.charCode != null ? original.charCode : original.keyCode;\n
\t\t\t}\n
\n
\t\t\treturn event;\n
\t\t}\n
\t},\n
\n
\tmouseHooks: {\n
\t\tprops: "button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(" "),\n
\t\tfilter: function( event, original ) {\n
\t\t\tvar eventDoc, doc, body,\n
\t\t\t\tbutton = original.button,\n
\t\t\t\tfromElement = original.fromElement;\n
\n
\t\t\t// Calculate pageX/Y if missing and clientX/Y available\n
\t\t\tif ( event.pageX == null && original.clientX != null ) {\n
\t\t\t\teventDoc = event.target.ownerDocument || document;\n
\t\t\t\tdoc = eventDoc.documentElement;\n
\t\t\t\tbody = eventDoc.body;\n
\n
\t\t\t\tevent.pageX = original.clientX + ( doc && doc.scrollLeft || body && body.scrollLeft || 0 ) - ( doc && doc.clientLeft || body && body.clientLeft || 0 );\n
\t\t\t\tevent.pageY = original.clientY + ( doc && doc.scrollTop  || body && body.scrollTop  || 0 ) - ( doc && doc.clientTop  || body && body.clientTop  || 0 );\n
\t\t\t}\n
\n
\t\t\t// Add relatedTarget, if necessary\n
\t\t\tif ( !event.relatedTarget && fromElement ) {\n
\t\t\t\tevent.relatedTarget = fromElement === event.target ? original.toElement : fromElement;\n
\t\t\t}\n
\n
\t\t\t// Add which for click: 1 === left; 2 === middle; 3 === right\n
\t\t\t// Note: button is not normalized, so don\'t use it\n
\t\t\tif ( !event.which && button !== undefined ) {\n
\t\t\t\tevent.which = ( button & 1 ? 1 : ( button & 2 ? 3 : ( button & 4 ? 2 : 0 ) ) );\n
\t\t\t}\n
\n
\t\t\treturn event;\n
\t\t}\n
\t},\n
\n
\tfix: function( event ) {\n
\t\tif ( event[ jQuery.expando ] ) {\n
\t\t\treturn event;\n
\t\t}\n
\n
\t\t// Create a writable copy of the event object and normalize some properties\n
\t\tvar i, prop,\n
\t\t\toriginalEvent = event,\n
\t\t\tfixHook = jQuery.event.fixHooks[ event.type ] || {},\n
\t\t\tcopy = fixHook.props ? this.props.concat( fixHook.props ) : this.props;\n
\n
\t\tevent = jQuery.Event( originalEvent );\n
\n
\t\tfor ( i = copy.length; i; ) {\n
\t\t\tprop = copy[ --i ];\n
\t\t\tevent[ prop ] = originalEvent[ prop ];\n
\t\t}\n
\n
\t\t// Fix target property, if necessary (#1925, IE 6/7/8 & Safari2)\n
\t\tif ( !event.target ) {\n
\t\t\tevent.target = originalEvent.srcElement || document;\n
\t\t}\n
\n
\t\t// Target should not be a text node (#504, Safari)\n
\t\tif ( event.target.nodeType === 3 ) {\n
\t\t\tevent.target = event.target.parentNode;\n
\t\t}\n
\n
\t\t// For mouse/key events; add metaKey if it\'s not there (#3368, IE6/7/8)\n
\t\tif ( event.metaKey === undefined ) {\n
\t\t\tevent.metaKey = event.ctrlKey;\n
\t\t}\n
\n
\t\treturn fixHook.filter? fixHook.filter( event, originalEvent ) : event;\n
\t},\n
\n
\tspecial: {\n
\t\tready: {\n
\t\t\t// Make sure the ready event is setup\n
\t\t\tsetup: jQuery.bindReady\n
\t\t},\n
\n
\t\tload: {\n
\t\t\t// Prevent triggered image.load events from bubbling to window.load\n
\t\t\tnoBubble: true\n
\t\t},\n
\n
\t\tfocus: {\n
\t\t\tdelegateType: "focusin"\n
\t\t},\n
\t\tblur: {\n
\t\t\tdelegateType: "focusout"\n
\t\t},\n
\n
\t\tbeforeunload: {\n
\t\t\tsetup: function( data, namespaces, eventHandle ) {\n
\t\t\t\t// We only want to do this special case on windows\n
\t\t\t\tif ( jQuery.isWindow( this ) ) {\n
\t\t\t\t\tthis.onbeforeunload = eventHandle;\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\tteardown: function( namespaces, eventHandle ) {\n
\t\t\t\tif ( this.onbeforeunload === eventHandle ) {\n
\t\t\t\t\tthis.onbeforeunload = null;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tsimulate: function( type, elem, event, bubble ) {\n
\t\t// Piggyback on a donor event to simulate a different one.\n
\t\t// Fake originalEvent to avoid donor\'s stopPropagation, but if the\n
\t\t// simulated event prevents default then we do the same on the donor.\n
\t\tvar e = jQuery.extend(\n
\t\t\tnew jQuery.Event(),\n
\t\t\tevent,\n
\t\t\t{ type: type,\n
\t\t\t\tisSimulated: true,\n
\t\t\t\toriginalEvent: {}\n
\t\t\t}\n
\t\t);\n
\t\tif ( bubble ) {\n
\t\t\tjQuery.event.trigger( e, null, elem );\n
\t\t} else {\n
\t\t\tjQuery.event.dispatch.call( elem, e );\n
\t\t}\n
\t\tif ( e.isDefaultPrevented() ) {\n
\t\t\tevent.preventDefault();\n
\t\t}\n
\t}\n
};\n
\n
// Some plugins are using, but it\'s undocumented/deprecated and will be removed.\n
// The 1.7 special event interface should provide all the hooks needed now.\n
jQuery.event.handle = jQuery.event.dispatch;\n
\n
jQuery.removeEvent = document.removeEventListener ?\n
\tfunction( elem, type, handle ) {\n
\t\tif ( elem.removeEventListener ) {\n
\t\t\telem.removeEventListener( type, handle, false );\n
\t\t}\n
\t} :\n
\tfunction( elem, type, handle ) {\n
\t\tif ( elem.detachEvent ) {\n
\t\t\telem.detachEvent( "on" + type, handle );\n
\t\t}\n
\t};\n
\n
jQuery.Event = function( src, props ) {\n
\t// Allow instantiation without the \'new\' keyword\n
\tif ( !(this instanceof jQuery.Event) ) {\n
\t\treturn new jQuery.Event( src, props );\n
\t}\n
\n
\t// Event object\n
\tif ( src && src.type ) {\n
\t\tthis.originalEvent = src;\n
\t\tthis.type = src.type;\n
\n
\t\t// Events bubbling up the document may have been marked as prevented\n
\t\t// by a handler lower down the tree; reflect the correct value.\n
\t\tthis.isDefaultPrevented = ( src.defaultPrevented || src.returnValue === false ||\n
\t\t\tsrc.getPreventDefault && src.getPreventDefault() ) ? returnTrue : returnFalse;\n
\n
\t// Event type\n
\t} else {\n
\t\tthis.type = src;\n
\t}\n
\n
\t// Put explicitly provided properties onto the event object\n
\tif ( props ) {\n
\t\tjQuery.extend( this, props );\n
\t}\n
\n
\t// Create a timestamp if incoming event doesn\'t have one\n
\tthis.timeStamp = src && src.timeStamp || jQuery.now();\n
\n
\t// Mark it as fixed\n
\tthis[ jQuery.expando ] = true;\n
};\n
\n
function returnFalse() {\n
\treturn false;\n
}\n
function returnTrue() {\n
\treturn true;\n
}\n
\n
// jQuery.Event is based on DOM3 Events as specified by the ECMAScript Language Binding\n
// http://www.w3.org/TR/2003/WD-DOM-Level-3-Events-20030331/ecma-script-binding.html\n
jQuery.Event.prototype = {\n
\tpreventDefault: function() {\n
\t\tthis.isDefaultPrevented = returnTrue;\n
\n
\t\tvar e = this.originalEvent;\n
\t\tif ( !e ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// if preventDefault exists run it on the original event\n
\t\tif ( e.preventDefault ) {\n
\t\t\te.preventDefault();\n
\n
\t\t// otherwise set the returnValue property of the original event to false (IE)\n
\t\t} else {\n
\t\t\te.returnValue = false;\n
\t\t}\n
\t},\n
\tstopPropagation: function() {\n
\t\tthis.isPropagationStopped = returnTrue;\n
\n
\t\tvar e = this.originalEvent;\n
\t\tif ( !e ) {\n
\t\t\treturn;\n
\t\t}\n
\t\t// if stopPropagation exists run it on the original event\n
\t\tif ( e.stopPropagation ) {\n
\t\t\te.stopPropagation();\n
\t\t}\n
\t\t// otherwise set the cancelBubble property of the original event to true (IE)\n
\t\te.cancelBubble = true;\n
\t},\n
\tstopImmediatePropagation: function() {\n
\t\tthis.isImmediatePropagationStopped = returnTrue;\n
\t\tthis.stopPropagation();\n
\t},\n
\tisDefaultPrevented: returnFalse,\n
\tisPropagationStopped: returnFalse,\n
\tisImmediatePropagationStopped: returnFalse\n
};\n
\n
// Create mouseenter/leave events using mouseover/out and event-time checks\n
jQuery.each({\n
\tmouseenter: "mouseover",\n
\tmouseleave: "mouseout"\n
}, function( orig, fix ) {\n
\tjQuery.event.special[ orig ] = {\n
\t\tdelegateType: fix,\n
\t\tbindType: fix,\n
\n
\t\thandle: function( event ) {\n
\t\t\tvar target = this,\n
\t\t\t\trelated = event.relatedTarget,\n
\t\t\t\thandleObj = event.handleObj,\n
\t\t\t\tselector = handleObj.selector,\n
\t\t\t\tret;\n
\n
\t\t\t// For mousenter/leave call the handler if related is outside the target.\n
\t\t\t// NB: No relatedTarget if the mouse left/entered the browser window\n
\t\t\tif ( !related || (related !== target && !jQuery.contains( target, related )) ) {\n
\t\t\t\tevent.type = handleObj.origType;\n
\t\t\t\tret = handleObj.handler.apply( this, arguments );\n
\t\t\t\tevent.type = fix;\n
\t\t\t}\n
\t\t\treturn ret;\n
\t\t}\n
\t};\n
});\n
\n
// IE submit delegation\n
if ( !jQuery.support.submitBubbles ) {\n
\n
\tjQuery.event.special.submit = {\n
\t\tsetup: function() {\n
\t\t\t// Only need this for delegated form submit events\n
\t\t\tif ( jQuery.nodeName( this, "form" ) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\t// Lazy-add a submit handler when a descendant form may potentially be submitted\n
\t\t\tjQuery.event.add( this, "click._submit keypress._submit", function( e ) {\n
\t\t\t\t// Node name check avoids a VML-related crash in IE (#9807)\n
\t\t\t\tvar elem = e.target,\n
\t\t\t\t\tform = jQuery.nodeName( elem, "input" ) || jQuery.nodeName( elem, "button" ) ? elem.form : undefined;\n
\t\t\t\tif ( form && !form._submit_attached ) {\n
\t\t\t\t\tjQuery.event.add( form, "submit._submit", function( event ) {\n
\t\t\t\t\t\tevent._submit_bubble = true;\n
\t\t\t\t\t});\n
\t\t\t\t\tform._submit_attached = true;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t// return undefined since we don\'t need an event listener\n
\t\t},\n
\t\t\n
\t\tpostDispatch: function( event ) {\n
\t\t\t// If form was submitted by the user, bubble the event up the tree\n
\t\t\tif ( event._submit_bubble ) {\n
\t\t\t\tdelete event._submit_bubble;\n
\t\t\t\tif ( this.parentNode && !event.isTrigger ) {\n
\t\t\t\t\tjQuery.event.simulate( "submit", this.parentNode, event, true );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\tteardown: function() {\n
\t\t\t// Only need this for delegated form submit events\n
\t\t\tif ( jQuery.nodeName( this, "form" ) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\t// Remove delegated handlers; cleanData eventually reaps submit handlers attached above\n
\t\t\tjQuery.event.remove( this, "._submit" );\n
\t\t}\n
\t};\n
}\n
\n
// IE change delegation and checkbox/radio fix\n
if ( !jQuery.support.changeBubbles ) {\n
\n
\tjQuery.event.special.change = {\n
\n
\t\tsetup: function() {\n
\n
\t\t\tif ( rformElems.test( this.nodeName ) ) {\n
\t\t\t\t// IE doesn\'t fire change on a check/radio until blur; trigger it on click\n
\t\t\t\t// after a propertychange. Eat the blur-change in special.change.handle.\n
\t\t\t\t// This still fires onchange a second time for check/radio after blur.\n
\t\t\t\tif ( this.type === "checkbox" || this.type === "radio" ) {\n
\t\t\t\t\tjQuery.event.add( this, "propertychange._change", function( event ) {\n
\t\t\t\t\t\tif ( event.originalEvent.propertyName === "checked" ) {\n
\t\t\t\t\t\t\tthis._just_changed = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tjQuery.event.add( this, "click._change", function( event ) {\n
\t\t\t\t\t\tif ( this._just_changed && !event.isTrigger ) {\n
\t\t\t\t\t\t\tthis._just_changed = false;\n
\t\t\t\t\t\t\tjQuery.event.simulate( "change", this, event, true );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\t// Delegated event; lazy-add a change handler on descendant inputs\n
\t\t\tjQuery.event.add( this, "beforeactivate._change", function( e ) {\n
\t\t\t\tvar elem = e.target;\n
\n
\t\t\t\tif ( rformElems.test( elem.nodeName ) && !elem._change_attached ) {\n
\t\t\t\t\tjQuery.event.add( elem, "change._change", function( event ) {\n
\t\t\t\t\t\tif ( this.parentNode && !event.isSimulated && !event.isTrigger ) {\n
\t\t\t\t\t\t\tjQuery.event.simulate( "change", this.parentNode, event, true );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\telem._change_attached = true;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t},\n
\n
\t\thandle: function( event ) {\n
\t\t\tvar elem = event.target;\n
\n
\t\t\t// Swallow native change events from checkbox/radio, we already triggered them above\n
\t\t\tif ( this !== elem || event.isSimulated || event.isTrigger || (elem.type !== "radio" && elem.type !== "checkbox") ) {\n
\t\t\t\treturn event.handleObj.handler.apply( this, arguments );\n
\t\t\t}\n
\t\t},\n
\n
\t\tteardown: function() {\n
\t\t\tjQuery.event.remove( this, "._change" );\n
\n
\t\t\treturn rformElems.test( this.nodeName );\n
\t\t}\n
\t};\n
}\n
\n
// Create "bubbling" focus and blur events\n
if ( !jQuery.support.focusinBubbles ) {\n
\tjQuery.each({ focus: "focusin", blur: "focusout" }, function( orig, fix ) {\n
\n
\t\t// Attach a single capturing handler while someone wants focusin/focusout\n
\t\tvar attaches = 0,\n
\t\t\thandler = function( event ) {\n
\t\t\t\tjQuery.event.simulate( fix, event.target, jQuery.event.fix( event ), true );\n
\t\t\t};\n
\n
\t\tjQuery.event.special[ fix ] = {\n
\t\t\tsetup: function() {\n
\t\t\t\tif ( attaches++ === 0 ) {\n
\t\t\t\t\tdocument.addEventListener( orig, handler, true );\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tteardown: function() {\n
\t\t\t\tif ( --attaches === 0 ) {\n
\t\t\t\t\tdocument.removeEventListener( orig, handler, true );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\t});\n
}\n
\n
jQuery.fn.extend({\n
\n
\ton: function( types, selector, data, fn, /*INTERNAL*/ one ) {\n
\t\tvar origFn, type;\n
\n
\t\t// Types can be a map of types/handlers\n
\t\tif ( typeof types === "object" ) {\n
\t\t\t// ( types-Object, selector, data )\n
\t\t\tif ( typeof selector !== "string" ) { // && selector != null\n
\t\t\t\t// ( types-Object, data )\n
\t\t\t\tdata = data || selector;\n
\t\t\t\tselector = undefined;\n
\t\t\t}\n
\t\t\tfor ( type in types ) {\n
\t\t\t\tthis.on( type, selector, data, types[ type ], one );\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tif ( data == null && fn == null ) {\n
\t\t\t// ( types, fn )\n
\t\t\tfn = selector;\n
\t\t\tdata = selector = undefined;\n
\t\t} else if ( fn == null ) {\n
\t\t\tif ( typeof selector === "string" ) {\n
\t\t\t\t// ( types, selector, fn )\n
\t\t\t\tfn = data;\n
\t\t\t\tdata = undefined;\n
\t\t\t} else {\n
\t\t\t\t// ( types, data, fn )\n
\t\t\t\tfn = data;\n
\t\t\t\tdata = selector;\n
\t\t\t\tselector = undefined;\n
\t\t\t}\n
\t\t}\n
\t\tif ( fn === false ) {\n
\t\t\tfn = returnFalse;\n
\t\t} else if ( !fn ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tif ( one === 1 ) {\n
\t\t\torigFn = fn;\n
\t\t\tfn = function( event ) {\n
\t\t\t\t// Can use an empty set, since event contains the info\n
\t\t\t\tjQuery().off( event );\n
\t\t\t\treturn origFn.apply( this, arguments );\n
\t\t\t};\n
\t\t\t// Use same guid so caller can remove using origFn\n
\t\t\tfn.guid = origFn.guid || ( origFn.guid = jQuery.guid++ );\n
\t\t}\n
\t\treturn this.each( function() {\n
\t\t\tjQuery.event.add( this, types, fn, data, selector );\n
\t\t});\n
\t},\n
\tone: function( types, selector, data, fn ) {\n
\t\treturn this.on( types, selector, data, fn, 1 );\n
\t},\n
\toff: function( types, selector, fn ) {\n
\t\tif ( types && types.preventDefault && types.handleObj ) {\n
\t\t\t// ( event )  dispatched jQuery.Event\n
\t\t\tvar handleObj = types.handleObj;\n
\t\t\tjQuery( types.delegateTarget ).off(\n
\t\t\t\thandleObj.namespace ? handleObj.origType + "." + handleObj.namespace : handleObj.origType,\n
\t\t\t\thandleObj.selector,\n
\t\t\t\thandleObj.handler\n
\t\t\t);\n
\t\t\treturn this;\n
\t\t}\n
\t\tif ( typeof types === "object" ) {\n
\t\t\t// ( types-object [, selector] )\n
\t\t\tfor ( var type in types ) {\n
\t\t\t\tthis.off( type, selector, types[ type ] );\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t}\n
\t\tif ( selector === false || typeof selector === "function" ) {\n
\t\t\t// ( types [, fn] )\n
\t\t\tfn = selector;\n
\t\t\tselector = undefined;\n
\t\t}\n
\t\tif ( fn === false ) {\n
\t\t\tfn = returnFalse;\n
\t\t}\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.event.remove( this, types, fn, selector );\n
\t\t});\n
\t},\n
\n
\tbind: function( types, data, fn ) {\n
\t\treturn this.on( types, null, data, fn );\n
\t},\n
\tunbind: function( types, fn ) {\n
\t\treturn this.off( types, null, fn );\n
\t},\n
\n
\tlive: function( types, data, fn ) {\n
\t\tjQuery( this.context ).on( types, this.selector, data, fn );\n
\t\treturn this;\n
\t},\n
\tdie: function( types, fn ) {\n
\t\tjQuery( this.context ).off( types, this.selector || "**", fn );\n
\t\treturn this;\n
\t},\n
\n
\tdelegate: function( selector, types, data, fn ) {\n
\t\treturn this.on( types, selector, data, fn );\n
\t},\n
\tundelegate: function( selector, types, fn ) {\n
\t\t// ( namespace ) or ( selector, types [, fn] )\n
\t\treturn arguments.length == 1? this.off( selector, "**" ) : this.off( types, selector, fn );\n
\t},\n
\n
\ttrigger: function( type, data ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.event.trigger( type, data, this );\n
\t\t});\n
\t},\n
\ttriggerHandler: function( type, data ) {\n
\t\tif ( this[0] ) {\n
\t\t\treturn jQuery.event.trigger( type, data, this[0], true );\n
\t\t}\n
\t},\n
\n
\ttoggle: function( fn ) {\n
\t\t// Save reference to arguments for access in closure\n
\t\tvar args = arguments,\n
\t\t\tguid = fn.guid || jQuery.guid++,\n
\t\t\ti = 0,\n
\t\t\ttoggler = function( event ) {\n
\t\t\t\t// Figure out which function to execute\n
\t\t\t\tvar lastToggle = ( jQuery._data( this, "lastToggle" + fn.guid ) || 0 ) % i;\n
\t\t\t\tjQuery._data( this, "lastToggle" + fn.guid, lastToggle + 1 );\n
\n
\t\t\t\t// Make sure that clicks stop\n
\t\t\t\tevent.preventDefault();\n
\n
\t\t\t\t// and execute the function\n
\t\t\t\treturn args[ lastToggle ].apply( this, arguments ) || false;\n
\t\t\t};\n
\n
\t\t// link all the functions, so any of them can unbind this click handler\n
\t\ttoggler.guid = guid;\n
\t\twhile ( i < args.length ) {\n
\t\t\targs[ i++ ].guid = guid;\n
\t\t}\n
\n
\t\treturn this.click( toggler );\n
\t},\n
\n
\thover: function( fnOver, fnOut ) {\n
\t\treturn this.mouseenter( fnOver ).mouseleave( fnOut || fnOver );\n
\t}\n
});\n
\n
jQuery.each( ("blur focus focusin focusout load resize scroll unload click dblclick " +\n
\t"mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave " +\n
\t"change select submit keydown keypress keyup error contextmenu").split(" "), function( i, name ) {\n
\n
\t// Handle event binding\n
\tjQuery.fn[ name ] = function( data, fn ) {\n
\t\tif ( fn == null ) {\n
\t\t\tfn = data;\n
\t\t\tdata = null;\n
\t\t}\n
\n
\t\treturn arguments.length > 0 ?\n
\t\t\tthis.on( name, null, data, fn ) :\n
\t\t\tthis.trigger( name );\n
\t};\n
\n
\tif ( jQuery.attrFn ) {\n
\t\tjQuery.attrFn[ name ] = true;\n
\t}\n
\n
\tif ( rkeyEvent.test( name ) ) {\n
\t\tjQuery.event.fixHooks[ name ] = jQuery.event.keyHooks;\n
\t}\n
\n
\tif ( rmouseEvent.test( name ) ) {\n
\t\tjQuery.event.fixHooks[ name ] = jQuery.event.mouseHooks;\n
\t}\n
});\n
\n
\n
\n
/*!\n
 * Sizzle CSS Selector Engine\n
 *  Copyright 2011, The Dojo Foundation\n
 *  Released under the MIT, BSD, and GPL Licenses.\n
 *  More information: http://sizzlejs.com/\n
 */\n
(function(){\n
\n
var chunker = /((?:\\((?:\\([^()]+\\)|[^()]+)+\\)|\\[(?:\\[[^\\[\\]]*\\]|[\'"][^\'"]*[\'"]|[^\\[\\]\'"]+)+\\]|\\\\.|[^ >+~,(\\[\\\\]+)+|[>+~])(\\s*,\\s*)?((?:.|\\r|\\n)*)/g,\n
\texpando = "sizcache" + (Math.random() + \'\').replace(\'.\', \'\'),\n
\tdone = 0,\n
\ttoString = Object.prototype.toString,\n
\thasDuplicate = false,\n
\tbaseHasDuplicate = true,\n
\trBackslash = /\\\\/g,\n
\trReturn = /\\r\\n/g,\n
\trNonWord = /\\W/;\n
\n
// Here we check if the JavaScript engine is using some sort of\n
// optimization where it does not always call our comparision\n
// function. If that is the case, discard the hasDuplicate value.\n
//   Thus far that includes Google Chrome.\n
[0, 0].sort(function() {\n
\tbaseHasDuplicate = false;\n
\treturn 0;\n
});\n
\n
var Sizzle = function( selector, context, results, seed ) {\n
\tresults = results || [];\n
\tcontext = context || document;\n
\n
\tvar origContext = context;\n
\n
\tif ( context.nodeType !== 1 && context.nodeType !== 9 ) {\n
\t\treturn [];\n
\t}\n
\n
\tif ( !selector || typeof selector !== "string" ) {\n
\t\treturn results;\n
\t}\n
\n
\tvar m, set, checkSet, extra, ret, cur, pop, i,\n
\t\tprune = true,\n
\t\tcontextXML = Sizzle.isXML( context ),\n
\t\tparts = [],\n
\t\tsoFar = selector;\n
\n
\t// Reset the position of the chunker regexp (start from head)\n
\tdo {\n
\t\tchunker.exec( "" );\n
\t\tm = chunker.exec( soFar );\n
\n
\t\tif ( m ) {\n
\t\t\tsoFar = m[3];\n
\n
\t\t\tparts.push( m[1] );\n
\n
\t\t\tif ( m[2] ) {\n
\t\t\t\textra = m[3];\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t} while ( m );\n
\n
\tif ( parts.length > 1 && origPOS.exec( selector ) ) {\n
\n
\t\tif ( parts.length === 2 && Expr.relative[ parts[0] ] ) {\n
\t\t\tset = posProcess( parts[0] + parts[1], context, seed );\n
\n
\t\t} else {\n
\t\t\tset = Expr.relative[ parts[0] ] ?\n
\t\t\t\t[ context ] :\n
\t\t\t\tSizzle( parts.shift(), context );\n
\n
\t\t\twhile ( parts.length ) {\n
\t\t\t\tselector = parts.shift();\n
\n
\t\t\t\tif ( Expr.relative[ selector ] ) {\n
\t\t\t\t\tselector += parts.shift();\n
\t\t\t\t}\n
\n
\t\t\t\tset = posProcess( selector, set, seed );\n
\t\t\t}\n
\t\t}\n
\n
\t} else {\n
\t\t// Take a shortcut and set the context if the root selector is an ID\n
\t\t// (but not if it\'ll be faster if the inner selector is an ID)\n
\t\tif ( !seed && parts.length > 1 && context.nodeType === 9 && !contextXML &&\n
\t\t\t\tExpr.match.ID.test(parts[0]) && !Expr.match.ID.test(parts[parts.length - 1]) ) {\n
\n
\t\t\tret = Sizzle.find( parts.shift(), context, contextXML );\n
\t\t\tcontext = ret.expr ?\n
\t\t\t\tSizzle.filter( ret.expr, ret.set )[0] :\n
\t\t\t\tret.set[0];\n
\t\t}\n
\n
\t\tif ( context ) {\n
\t\t\tret = seed ?\n
\t\t\t\t{ expr: parts.pop(), set: makeArray(seed) } :\n
\t\t\t\tSizzle.find( parts.pop(), parts.length === 1 && (parts[0] === "~" || parts[0] === "+") && context.parentNode ? context.parentNode : context, contextXML );\n
\n
\t\t\tset = ret.expr ?\n
\t\t\t\tSizzle.filter( ret.expr, ret.set ) :\n
\t\t\t\tret.set;\n
\n
\t\t\tif ( parts.length > 0 ) {\n
\t\t\t\tcheckSet = makeArray( set );\n
\n
\t\t\t} else {\n
\t\t\t\tprune = false;\n
\t\t\t}\n
\n
\t\t\twhile ( parts.length ) {\n
\t\t\t\tcur = parts.pop();\n
\t\t\t\tpop = cur;\n
\n
\t\t\t\tif ( !Expr.relative[ cur ] ) {\n
\t\t\t\t\tcur = "";\n
\t\t\t\t} else {\n
\t\t\t\t\tpop = parts.pop();\n
\t\t\t\t}\n
\n
\t\t\t\tif ( pop == null ) {\n
\t\t\t\t\tpop = context;\n
\t\t\t\t}\n
\n
\t\t\t\tExpr.relative[ cur ]( checkSet, pop, contextXML );\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\tcheckSet = parts = [];\n
\t\t}\n
\t}\n
\n
\tif ( !checkSet ) {\n
\t\tcheckSet = set;\n
\t}\n
\n
\tif ( !checkSet ) {\n
\t\tSizzle.error( cur || selector );\n
\t}\n
\n
\tif ( toString.call(checkSet) === "[object Array]" ) {\n
\t\tif ( !prune ) {\n
\t\t\tresults.push.apply( results, checkSet );\n
\n
\t\t} else if ( context && context.nodeType === 1 ) {\n
\t\t\tfor ( i = 0; checkSet[i] != null; i++ ) {\n
\t\t\t\tif ( checkSet[i] && (checkSet[i] === true || checkSet[i].nodeType === 1 && Sizzle.contains(context, checkSet[i])) ) {\n
\t\t\t\t\tresults.push( set[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\tfor ( i = 0; checkSet[i] != null; i++ ) {\n
\t\t\t\tif ( checkSet[i] && checkSet[i].nodeType === 1 ) {\n
\t\t\t\t\tresults.push( set[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t} else {\n
\t\tmakeArray( checkSet, results );\n
\t}\n
\n
\tif ( extra ) {\n
\t\tSizzle( extra, origContext, results, seed );\n
\t\tSizzle.uniqueSort( results );\n
\t}\n
\n
\treturn results;\n
};\n
\n
Sizzle.uniqueSort = function( results ) {\n
\tif ( sortOrder ) {\n
\t\thasDuplicate = baseHasDuplicate;\n
\t\tresults.sort( sortOrder );\n
\n
\t\tif ( hasDuplicate ) {\n
\t\t\tfor ( var i = 1; i < results.length; i++ ) {\n
\t\t\t\tif ( results[i] === results[ i - 1 ] ) {\n
\t\t\t\t\tresults.splice( i--, 1 );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn results;\n
};\n
\n
Sizzle.matches = function( expr, set ) {\n
\treturn Sizzle( expr, null, null, set );\n
};\n
\n
Sizzle.matchesSelector = function( node, expr ) {\n
\treturn Sizzle( expr, null, null, [node] ).length > 0;\n
};\n
\n
Sizzle.find = function( expr, context, isXML ) {\n
\tvar set, i, len, match, type, left;\n
\n
\tif ( !expr ) {\n
\t\treturn [];\n
\t}\n
\n
\tfor ( i = 0, len = Expr.order.length; i < len; i++ ) {\n
\t\ttype = Expr.order[i];\n
\n
\t\tif ( (match = Expr.leftMatch[ type ].exec( expr )) ) {\n
\t\t\tleft = match[1];\n
\t\t\tmatch.splice( 1, 1 );\n
\n
\t\t\tif ( left.substr( left.length - 1 ) !== "\\\\" ) {\n
\t\t\t\tmatch[1] = (match[1] || "").replace( rBackslash, "" );\n
\t\t\t\tset = Expr.find[ type ]( match, context, isXML );\n
\n
\t\t\t\tif ( set != null ) {\n
\t\t\t\t\texpr = expr.replace( Expr.match[ type ], "" );\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tif ( !set ) {\n
\t\tset = typeof context.getElementsByTagName !== "undefined" ?\n
\t\t\tcontext.getElementsByTagName( "*" ) :\n
\t\t\t[];\n
\t}\n
\n
\treturn { set: set, expr: expr };\n
};\n
\n
Sizzle.filter = function( expr, set, inplace, not ) {\n
\tvar match, anyFound,\n
\t\ttype, found, item, filter, left,\n
\t\ti, pass,\n
\t\told = expr,\n
\t\tresult = [],\n
\t\tcurLoop = set,\n
\t\tisXMLFilter = set && set[0] && Sizzle.isXML( set[0] );\n
\n
\twhile ( expr && set.length ) {\n
\t\tfor ( type in Expr.filter ) {\n
\t\t\tif ( (match = Expr.leftMatch[ type ].exec( expr )) != null && match[2] ) {\n
\t\t\t\tfilter = Expr.filter[ type ];\n
\t\t\t\tleft = match[1];\n
\n
\t\t\t\tanyFound = false;\n
\n
\t\t\t\tmatch.splice(1,1);\n
\n
\t\t\t\tif ( left.substr( left.length - 1 ) === "\\\\" ) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( curLoop === result ) {\n
\t\t\t\t\tresult = [];\n
\t\t\t\t}\n
\n
\t\t\t\tif ( Expr.preFilter[ type ] ) {\n
\t\t\t\t\tmatch = Expr.preFilter[ type ]( match, curLoop, inplace, result, not, isXMLFilter );\n
\n
\t\t\t\t\tif ( !match ) {\n
\t\t\t\t\t\tanyFound = found = true;\n
\n
\t\t\t\t\t} else if ( match === true ) {\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( match ) {\n
\t\t\t\t\tfor ( i = 0; (item = curLoop[i]) != null; i++ ) {\n
\t\t\t\t\t\tif ( item ) {\n
\t\t\t\t\t\t\tfound = filter( item, match, i, curLoop );\n
\t\t\t\t\t\t\tpass = not ^ found;\n
\n
\t\t\t\t\t\t\tif ( inplace && found != null ) {\n
\t\t\t\t\t\t\t\tif ( pass ) {\n
\t\t\t\t\t\t\t\t\tanyFound = true;\n
\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tcurLoop[i] = false;\n
\t\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t} else if ( pass ) {\n
\t\t\t\t\t\t\t\tresult.push( item );\n
\t\t\t\t\t\t\t\tanyFound = true;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( found !== undefined ) {\n
\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\tcurLoop = result;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\texpr = expr.replace( Expr.match[ type ], "" );\n
\n
\t\t\t\t\tif ( !anyFound ) {\n
\t\t\t\t\t\treturn [];\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Improper expression\n
\t\tif ( expr === old ) {\n
\t\t\tif ( anyFound == null ) {\n
\t\t\t\tSizzle.error( expr );\n
\n
\t\t\t} else {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\told = expr;\n
\t}\n
\n
\treturn curLoop;\n
};\n
\n
Sizzle.error = function( msg ) {\n
\tthrow new Error( "Syntax error, unrecognized expression: " + msg );\n
};\n
\n
/**\n
 * Utility function for retreiving the text value of an array of DOM nodes\n
 * @param {Array|Element} elem\n
 */\n
var getText = Sizzle.getText = function( elem ) {\n
    var i, node,\n
\t\tnodeType = elem.nodeType,\n
\t\tret = "";\n
\n
\tif ( nodeType ) {\n
\t\tif ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) {\n
\t\t\t// Use textContent || innerText for elements\n
\t\t\tif ( typeof elem.textContent === \'string\' ) {\n
\t\t\t\treturn elem.textContent;\n
\t\t\t} else if ( typeof elem.innerText === \'string\' ) {\n
\t\t\t\t// Replace IE\'s carriage returns\n
\t\t\t\treturn elem.innerText.replace( rReturn, \'\' );\n
\t\t\t} else {\n
\t\t\t\t// Traverse it\'s children\n
\t\t\t\tfor ( elem = elem.firstChild; elem; elem = elem.nextSibling) {\n
\t\t\t\t\tret += getText( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else if ( nodeType === 3 || nodeType === 4 ) {\n
\t\t\treturn elem.nodeValue;\n
\t\t}\n
\t} else {\n
\n
\t\t// If no nodeType, this is expected to be an array\n
\t\tfor ( i = 0; (node = elem[i]); i++ ) {\n
\t\t\t// Do not traverse comment nodes\n
\t\t\tif ( node.nodeType !== 8 ) {\n
\t\t\t\tret += getText( node );\n
\t\t\t}\n
\t\t}\n
\t}\n
\treturn ret;\n
};\n
\n
var Expr = Sizzle.selectors = {\n
\torder: [ "ID", "NAME", "TAG" ],\n
\n
\tmatch: {\n
\t\tID: /#((?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)+)/,\n
\t\tCLASS: /\\.((?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)+)/,\n
\t\tNAME: /\\[name=[\'"]*((?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)+)[\'"]*\\]/,\n
\t\tATTR: /\\[\\s*((?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)+)\\s*(?:(\\S?=)\\s*(?:([\'"])(.*?)\\3|(#?(?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)*)|)|)\\s*\\]/,\n
\t\tTAG: /^((?:[\\w\\u00c0-\\uFFFF\\*\\-]|\\\\.)+)/,\n
\t\tCHILD: /:(only|nth|last|first)-child(?:\\(\\s*(even|odd|(?:[+\\-]?\\d+|(?:[+\\-]?\\d*)?n\\s*(?:[+\\-]\\s*\\d+)?))\\s*\\))?/,\n
\t\tPOS: /:(nth|eq|gt|lt|first|last|even|odd)(?:\\((\\d*)\\))?(?=[^\\-]|$)/,\n
\t\tPSEUDO: /:((?:[\\w\\u00c0-\\uFFFF\\-]|\\\\.)+)(?:\\(([\'"]?)((?:\\([^\\)]+\\)|[^\\(\\)]*)+)\\2\\))?/\n
\t},\n
\n
\tleftMatch: {},\n
\n
\tattrMap: {\n
\t\t"class": "className",\n
\t\t"for": "htmlFor"\n
\t},\n
\n
\tattrHandle: {\n
\t\thref: function( elem ) {\n
\t\t\treturn elem.getAttribute( "href" );\n
\t\t},\n
\t\ttype: function( elem ) {\n
\t\t\treturn elem.getAttribute( "type" );\n
\t\t}\n
\t},\n
\n
\trelative: {\n
\t\t"+": function(checkSet, part){\n
\t\t\tvar isPartStr = typeof part === "string",\n
\t\t\t\tisTag = isPartStr && !rNonWord.test( part ),\n
\t\t\t\tisPartStrNotTag = isPartStr && !isTag;\n
\n
\t\t\tif ( isTag ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\t\t\t}\n
\n
\t\t\tfor ( var i = 0, l = checkSet.length, elem; i < l; i++ ) {\n
\t\t\t\tif ( (elem = checkSet[i]) ) {\n
\t\t\t\t\twhile ( (elem = elem.previousSibling) && elem.nodeType !== 1 ) {}\n
\n
\t\t\t\t\tcheckSet[i] = isPartStrNotTag || elem && elem.nodeName.toLowerCase() === part ?\n
\t\t\t\t\t\telem || false :\n
\t\t\t\t\t\telem === part;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( isPartStrNotTag ) {\n
\t\t\t\tSizzle.filter( part, checkSet, true );\n
\t\t\t}\n
\t\t},\n
\n
\t\t">": function( checkSet, part ) {\n
\t\t\tvar elem,\n
\t\t\t\tisPartStr = typeof part === "string",\n
\t\t\t\ti = 0,\n
\t\t\t\tl = checkSet.length;\n
\n
\t\t\tif ( isPartStr && !rNonWord.test( part ) ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\n
\t\t\t\tfor ( ; i < l; i++ ) {\n
\t\t\t\t\telem = checkSet[i];\n
\n
\t\t\t\t\tif ( elem ) {\n
\t\t\t\t\t\tvar parent = elem.parentNode;\n
\t\t\t\t\t\tcheckSet[i] = parent.nodeName.toLowerCase() === part ? parent : false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\t\t\t\tfor ( ; i < l; i++ ) {\n
\t\t\t\t\telem = checkSet[i];\n
\n
\t\t\t\t\tif ( elem ) {\n
\t\t\t\t\t\tcheckSet[i] = isPartStr ?\n
\t\t\t\t\t\t\telem.parentNode :\n
\t\t\t\t\t\t\telem.parentNode === part;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( isPartStr ) {\n
\t\t\t\t\tSizzle.filter( part, checkSet, true );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\t"": function(checkSet, part, isXML){\n
\t\t\tvar nodeCheck,\n
\t\t\t\tdoneName = done++,\n
\t\t\t\tcheckFn = dirCheck;\n
\n
\t\t\tif ( typeof part === "string" && !rNonWord.test( part ) ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\t\t\t\tnodeCheck = part;\n
\t\t\t\tcheckFn = dirNodeCheck;\n
\t\t\t}\n
\n
\t\t\tcheckFn( "parentNode", part, doneName, checkSet, nodeCheck, isXML );\n
\t\t},\n
\n
\t\t"~": function( checkSet, part, isXML ) {\n
\t\t\tvar nodeCheck,\n
\t\t\t\tdoneName = done++,\n
\t\t\t\tcheckFn = dirCheck;\n
\n
\t\t\tif ( typeof part === "string" && !rNonWord.test( part ) ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\t\t\t\tnodeCheck = part;\n
\t\t\t\tcheckFn = dirNodeCheck;\n
\t\t\t}\n
\n
\t\t\tcheckFn( "previousSibling", part, doneName, checkSet, nodeCheck, isXML );\n
\t\t}\n
\t},\n
\n
\tfind: {\n
\t\tID: function( match, context, isXML ) {\n
\t\t\tif ( typeof context.getElementById !== "undefined" && !isXML ) {\n
\t\t\t\tvar m = context.getElementById(match[1]);\n
\t\t\t\t// Check parentNode to catch when Blackberry 4.6 returns\n
\t\t\t\t// nodes that are no longer in the document #6963\n
\t\t\t\treturn m && m.parentNode ? [m] : [];\n
\t\t\t}\n
\t\t},\n
\n
\t\tNAME: function( match, context ) {\n
\t\t\tif ( typeof context.getElementsByName !== "undefined" ) {\n
\t\t\t\tvar ret = [],\n
\t\t\t\t\tresults = context.getElementsByName( match[1] );\n
\n
\t\t\t\tfor ( var i = 0, l = results.length; i < l; i++ ) {\n
\t\t\t\t\tif ( results[i].getAttribute("name") === match[1] ) {\n
\t\t\t\t\t\tret.push( results[i] );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\treturn ret.length === 0 ? null : ret;\n
\t\t\t}\n
\t\t},\n
\n
\t\tTAG: function( match, context ) {\n
\t\t\tif ( typeof context.getElementsByTagName !== "undefined" ) {\n
\t\t\t\treturn context.getElementsByTagName( match[1] );\n
\t\t\t}\n
\t\t}\n
\t},\n
\tpreFilter: {\n
\t\tCLASS: function( match, curLoop, inplace, result, not, isXML ) {\n
\t\t\tmatch = " " + match[1].replace( rBackslash, "" ) + " ";\n
\n
\t\t\tif ( isXML ) {\n
\t\t\t\treturn match;\n
\t\t\t}\n
\n
\t\t\tfor ( var i = 0, elem; (elem = curLoop[i]) != null; i++ ) {\n
\t\t\t\tif ( elem ) {\n
\t\t\t\t\tif ( not ^ (elem.className && (" " + elem.className + " ").replace(/[\\t\\n\\r]/g, " ").indexOf(match) >= 0) ) {\n
\t\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\t\tresult.push( elem );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else if ( inplace ) {\n
\t\t\t\t\t\tcurLoop[i] = false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn false;\n
\t\t},\n
\n
\t\tID: function( match ) {\n
\t\t\treturn match[1].replace( rBackslash, "" );\n
\t\t},\n
\n
\t\tTAG: function( match, curLoop ) {\n
\t\t\treturn match[1].replace( rBackslash, "" ).toLowerCase();\n
\t\t},\n
\n
\t\tCHILD: function( match ) {\n
\t\t\tif ( match[1] === "nth" ) {\n
\t\t\t\tif ( !match[2] ) {\n
\t\t\t\t\tSizzle.error( match[0] );\n
\t\t\t\t}\n
\n
\t\t\t\tmatch[2] = match[2].replace(/^\\+|\\s*/g, \'\');\n
\n
\t\t\t\t// parse equations like \'even\', \'odd\', \'5\', \'2n\', \'3n+2\', \'4n-1\', \'-n+6\'\n
\t\t\t\tvar test = /(-?)(\\d*)(?:n([+\\-]?\\d*))?/.exec(\n
\t\t\t\t\tmatch[2] === "even" && "2n" || match[2] === "odd" && "2n+1" ||\n
\t\t\t\t\t!/\\D/.test( match[2] ) && "0n+" + match[2] || match[2]);\n
\n
\t\t\t\t// calculate the numbers (first)n+(last) including if they are negative\n
\t\t\t\tmatch[2] = (test[1] + (test[2] || 1)) - 0;\n
\t\t\t\tmatch[3] = test[3] - 0;\n
\t\t\t}\n
\t\t\t

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

else if ( match[2] ) {\n
\t\t\t\tSizzle.error( match[0] );\n
\t\t\t}\n
\n
\t\t\t// TODO: Move to normal caching system\n
\t\t\tmatch[0] = done++;\n
\n
\t\t\treturn match;\n
\t\t},\n
\n
\t\tATTR: function( match, curLoop, inplace, result, not, isXML ) {\n
\t\t\tvar name = match[1] = match[1].replace( rBackslash, "" );\n
\n
\t\t\tif ( !isXML && Expr.attrMap[name] ) {\n
\t\t\t\tmatch[1] = Expr.attrMap[name];\n
\t\t\t}\n
\n
\t\t\t// Handle if an un-quoted value was used\n
\t\t\tmatch[4] = ( match[4] || match[5] || "" ).replace( rBackslash, "" );\n
\n
\t\t\tif ( match[2] === "~=" ) {\n
\t\t\t\tmatch[4] = " " + match[4] + " ";\n
\t\t\t}\n
\n
\t\t\treturn match;\n
\t\t},\n
\n
\t\tPSEUDO: function( match, curLoop, inplace, result, not ) {\n
\t\t\tif ( match[1] === "not" ) {\n
\t\t\t\t// If we\'re dealing with a complex expression, or a simple one\n
\t\t\t\tif ( ( chunker.exec(match[3]) || "" ).length > 1 || /^\\w/.test(match[3]) ) {\n
\t\t\t\t\tmatch[3] = Sizzle(match[3], null, null, curLoop);\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tvar ret = Sizzle.filter(match[3], curLoop, inplace, true ^ not);\n
\n
\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\tresult.push.apply( result, ret );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\n
\t\t\t} else if ( Expr.match.POS.test( match[0] ) || Expr.match.CHILD.test( match[0] ) ) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\n
\t\t\treturn match;\n
\t\t},\n
\n
\t\tPOS: function( match ) {\n
\t\t\tmatch.unshift( true );\n
\n
\t\t\treturn match;\n
\t\t}\n
\t},\n
\n
\tfilters: {\n
\t\tenabled: function( elem ) {\n
\t\t\treturn elem.disabled === false && elem.type !== "hidden";\n
\t\t},\n
\n
\t\tdisabled: function( elem ) {\n
\t\t\treturn elem.disabled === true;\n
\t\t},\n
\n
\t\tchecked: function( elem ) {\n
\t\t\treturn elem.checked === true;\n
\t\t},\n
\n
\t\tselected: function( elem ) {\n
\t\t\t// Accessing this property makes selected-by-default\n
\t\t\t// options in Safari work properly\n
\t\t\tif ( elem.parentNode ) {\n
\t\t\t\telem.parentNode.selectedIndex;\n
\t\t\t}\n
\n
\t\t\treturn elem.selected === true;\n
\t\t},\n
\n
\t\tparent: function( elem ) {\n
\t\t\treturn !!elem.firstChild;\n
\t\t},\n
\n
\t\tempty: function( elem ) {\n
\t\t\treturn !elem.firstChild;\n
\t\t},\n
\n
\t\thas: function( elem, i, match ) {\n
\t\t\treturn !!Sizzle( match[3], elem ).length;\n
\t\t},\n
\n
\t\theader: function( elem ) {\n
\t\t\treturn (/h\\d/i).test( elem.nodeName );\n
\t\t},\n
\n
\t\ttext: function( elem ) {\n
\t\t\tvar attr = elem.getAttribute( "type" ), type = elem.type;\n
\t\t\t// IE6 and 7 will map elem.type to \'text\' for new HTML5 types (search, etc)\n
\t\t\t// use getAttribute instead to test this case\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "text" === type && ( attr === type || attr === null );\n
\t\t},\n
\n
\t\tradio: function( elem ) {\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "radio" === elem.type;\n
\t\t},\n
\n
\t\tcheckbox: function( elem ) {\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "checkbox" === elem.type;\n
\t\t},\n
\n
\t\tfile: function( elem ) {\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "file" === elem.type;\n
\t\t},\n
\n
\t\tpassword: function( elem ) {\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "password" === elem.type;\n
\t\t},\n
\n
\t\tsubmit: function( elem ) {\n
\t\t\tvar name = elem.nodeName.toLowerCase();\n
\t\t\treturn (name === "input" || name === "button") && "submit" === elem.type;\n
\t\t},\n
\n
\t\timage: function( elem ) {\n
\t\t\treturn elem.nodeName.toLowerCase() === "input" && "image" === elem.type;\n
\t\t},\n
\n
\t\treset: function( elem ) {\n
\t\t\tvar name = elem.nodeName.toLowerCase();\n
\t\t\treturn (name === "input" || name === "button") && "reset" === elem.type;\n
\t\t},\n
\n
\t\tbutton: function( elem ) {\n
\t\t\tvar name = elem.nodeName.toLowerCase();\n
\t\t\treturn name === "input" && "button" === elem.type || name === "button";\n
\t\t},\n
\n
\t\tinput: function( elem ) {\n
\t\t\treturn (/input|select|textarea|button/i).test( elem.nodeName );\n
\t\t},\n
\n
\t\tfocus: function( elem ) {\n
\t\t\treturn elem === elem.ownerDocument.activeElement;\n
\t\t}\n
\t},\n
\tsetFilters: {\n
\t\tfirst: function( elem, i ) {\n
\t\t\treturn i === 0;\n
\t\t},\n
\n
\t\tlast: function( elem, i, match, array ) {\n
\t\t\treturn i === array.length - 1;\n
\t\t},\n
\n
\t\teven: function( elem, i ) {\n
\t\t\treturn i % 2 === 0;\n
\t\t},\n
\n
\t\todd: function( elem, i ) {\n
\t\t\treturn i % 2 === 1;\n
\t\t},\n
\n
\t\tlt: function( elem, i, match ) {\n
\t\t\treturn i < match[3] - 0;\n
\t\t},\n
\n
\t\tgt: function( elem, i, match ) {\n
\t\t\treturn i > match[3] - 0;\n
\t\t},\n
\n
\t\tnth: function( elem, i, match ) {\n
\t\t\treturn match[3] - 0 === i;\n
\t\t},\n
\n
\t\teq: function( elem, i, match ) {\n
\t\t\treturn match[3] - 0 === i;\n
\t\t}\n
\t},\n
\tfilter: {\n
\t\tPSEUDO: function( elem, match, i, array ) {\n
\t\t\tvar name = match[1],\n
\t\t\t\tfilter = Expr.filters[ name ];\n
\n
\t\t\tif ( filter ) {\n
\t\t\t\treturn filter( elem, i, match, array );\n
\n
\t\t\t} else if ( name === "contains" ) {\n
\t\t\t\treturn (elem.textContent || elem.innerText || getText([ elem ]) || "").indexOf(match[3]) >= 0;\n
\n
\t\t\t} else if ( name === "not" ) {\n
\t\t\t\tvar not = match[3];\n
\n
\t\t\t\tfor ( var j = 0, l = not.length; j < l; j++ ) {\n
\t\t\t\t\tif ( not[j] === elem ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\treturn true;\n
\n
\t\t\t} else {\n
\t\t\t\tSizzle.error( name );\n
\t\t\t}\n
\t\t},\n
\n
\t\tCHILD: function( elem, match ) {\n
\t\t\tvar first, last,\n
\t\t\t\tdoneName, parent, cache,\n
\t\t\t\tcount, diff,\n
\t\t\t\ttype = match[1],\n
\t\t\t\tnode = elem;\n
\n
\t\t\tswitch ( type ) {\n
\t\t\t\tcase "only":\n
\t\t\t\tcase "first":\n
\t\t\t\t\twhile ( (node = node.previousSibling) ) {\n
\t\t\t\t\t\tif ( node.nodeType === 1 ) {\n
\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( type === "first" ) {\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tnode = elem;\n
\n
\t\t\t\t\t/* falls through */\n
\t\t\t\tcase "last":\n
\t\t\t\t\twhile ( (node = node.nextSibling) ) {\n
\t\t\t\t\t\tif ( node.nodeType === 1 ) {\n
\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn true;\n
\n
\t\t\t\tcase "nth":\n
\t\t\t\t\tfirst = match[2];\n
\t\t\t\t\tlast = match[3];\n
\n
\t\t\t\t\tif ( first === 1 && last === 0 ) {\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tdoneName = match[0];\n
\t\t\t\t\tparent = elem.parentNode;\n
\n
\t\t\t\t\tif ( parent && (parent[ expando ] !== doneName || !elem.nodeIndex) ) {\n
\t\t\t\t\t\tcount = 0;\n
\n
\t\t\t\t\t\tfor ( node = parent.firstChild; node; node = node.nextSibling ) {\n
\t\t\t\t\t\t\tif ( node.nodeType === 1 ) {\n
\t\t\t\t\t\t\t\tnode.nodeIndex = ++count;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tparent[ expando ] = doneName;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tdiff = elem.nodeIndex - last;\n
\n
\t\t\t\t\tif ( first === 0 ) {\n
\t\t\t\t\t\treturn diff === 0;\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn ( diff % first === 0 && diff / first >= 0 );\n
\t\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\tID: function( elem, match ) {\n
\t\t\treturn elem.nodeType === 1 && elem.getAttribute("id") === match;\n
\t\t},\n
\n
\t\tTAG: function( elem, match ) {\n
\t\t\treturn (match === "*" && elem.nodeType === 1) || !!elem.nodeName && elem.nodeName.toLowerCase() === match;\n
\t\t},\n
\n
\t\tCLASS: function( elem, match ) {\n
\t\t\treturn (" " + (elem.className || elem.getAttribute("class")) + " ")\n
\t\t\t\t.indexOf( match ) > -1;\n
\t\t},\n
\n
\t\tATTR: function( elem, match ) {\n
\t\t\tvar name = match[1],\n
\t\t\t\tresult = Sizzle.attr ?\n
\t\t\t\t\tSizzle.attr( elem, name ) :\n
\t\t\t\t\tExpr.attrHandle[ name ] ?\n
\t\t\t\t\tExpr.attrHandle[ name ]( elem ) :\n
\t\t\t\t\telem[ name ] != null ?\n
\t\t\t\t\t\telem[ name ] :\n
\t\t\t\t\t\telem.getAttribute( name ),\n
\t\t\t\tvalue = result + "",\n
\t\t\t\ttype = match[2],\n
\t\t\t\tcheck = match[4];\n
\n
\t\t\treturn result == null ?\n
\t\t\t\ttype === "!=" :\n
\t\t\t\t!type && Sizzle.attr ?\n
\t\t\t\tresult != null :\n
\t\t\t\ttype === "=" ?\n
\t\t\t\tvalue === check :\n
\t\t\t\ttype === "*=" ?\n
\t\t\t\tvalue.indexOf(check) >= 0 :\n
\t\t\t\ttype === "~=" ?\n
\t\t\t\t(" " + value + " ").indexOf(check) >= 0 :\n
\t\t\t\t!check ?\n
\t\t\t\tvalue && result !== false :\n
\t\t\t\ttype === "!=" ?\n
\t\t\t\tvalue !== check :\n
\t\t\t\ttype === "^=" ?\n
\t\t\t\tvalue.indexOf(check) === 0 :\n
\t\t\t\ttype === "$=" ?\n
\t\t\t\tvalue.substr(value.length - check.length) === check :\n
\t\t\t\ttype === "|=" ?\n
\t\t\t\tvalue === check || value.substr(0, check.length + 1) === check + "-" :\n
\t\t\t\tfalse;\n
\t\t},\n
\n
\t\tPOS: function( elem, match, i, array ) {\n
\t\t\tvar name = match[2],\n
\t\t\t\tfilter = Expr.setFilters[ name ];\n
\n
\t\t\tif ( filter ) {\n
\t\t\t\treturn filter( elem, i, match, array );\n
\t\t\t}\n
\t\t}\n
\t}\n
};\n
\n
var origPOS = Expr.match.POS,\n
\tfescape = function(all, num){\n
\t\treturn "\\\\" + (num - 0 + 1);\n
\t};\n
\n
for ( var type in Expr.match ) {\n
\tExpr.match[ type ] = new RegExp( Expr.match[ type ].source + (/(?![^\\[]*\\])(?![^\\(]*\\))/.source) );\n
\tExpr.leftMatch[ type ] = new RegExp( /(^(?:.|\\r|\\n)*?)/.source + Expr.match[ type ].source.replace(/\\\\(\\d+)/g, fescape) );\n
}\n
// Expose origPOS\n
// "global" as in regardless of relation to brackets/parens\n
Expr.match.globalPOS = origPOS;\n
\n
var makeArray = function( array, results ) {\n
\tarray = Array.prototype.slice.call( array, 0 );\n
\n
\tif ( results ) {\n
\t\tresults.push.apply( results, array );\n
\t\treturn results;\n
\t}\n
\n
\treturn array;\n
};\n
\n
// Perform a simple check to determine if the browser is capable of\n
// converting a NodeList to an array using builtin methods.\n
// Also verifies that the returned array holds DOM nodes\n
// (which is not the case in the Blackberry browser)\n
try {\n
\tArray.prototype.slice.call( document.documentElement.childNodes, 0 )[0].nodeType;\n
\n
// Provide a fallback method if it does not work\n
} catch( e ) {\n
\tmakeArray = function( array, results ) {\n
\t\tvar i = 0,\n
\t\t\tret = results || [];\n
\n
\t\tif ( toString.call(array) === "[object Array]" ) {\n
\t\t\tArray.prototype.push.apply( ret, array );\n
\n
\t\t} else {\n
\t\t\tif ( typeof array.length === "number" ) {\n
\t\t\t\tfor ( var l = array.length; i < l; i++ ) {\n
\t\t\t\t\tret.push( array[i] );\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\t\t\t\tfor ( ; array[i]; i++ ) {\n
\t\t\t\t\tret.push( array[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t};\n
}\n
\n
var sortOrder, siblingCheck;\n
\n
if ( document.documentElement.compareDocumentPosition ) {\n
\tsortOrder = function( a, b ) {\n
\t\tif ( a === b ) {\n
\t\t\thasDuplicate = true;\n
\t\t\treturn 0;\n
\t\t}\n
\n
\t\tif ( !a.compareDocumentPosition || !b.compareDocumentPosition ) {\n
\t\t\treturn a.compareDocumentPosition ? -1 : 1;\n
\t\t}\n
\n
\t\treturn a.compareDocumentPosition(b) & 4 ? -1 : 1;\n
\t};\n
\n
} else {\n
\tsortOrder = function( a, b ) {\n
\t\t// The nodes are identical, we can exit early\n
\t\tif ( a === b ) {\n
\t\t\thasDuplicate = true;\n
\t\t\treturn 0;\n
\n
\t\t// Fallback to using sourceIndex (in IE) if it\'s available on both nodes\n
\t\t} else if ( a.sourceIndex && b.sourceIndex ) {\n
\t\t\treturn a.sourceIndex - b.sourceIndex;\n
\t\t}\n
\n
\t\tvar al, bl,\n
\t\t\tap = [],\n
\t\t\tbp = [],\n
\t\t\taup = a.parentNode,\n
\t\t\tbup = b.parentNode,\n
\t\t\tcur = aup;\n
\n
\t\t// If the nodes are siblings (or identical) we can do a quick check\n
\t\tif ( aup === bup ) {\n
\t\t\treturn siblingCheck( a, b );\n
\n
\t\t// If no parents were found then the nodes are disconnected\n
\t\t} else if ( !aup ) {\n
\t\t\treturn -1;\n
\n
\t\t} else if ( !bup ) {\n
\t\t\treturn 1;\n
\t\t}\n
\n
\t\t// Otherwise they\'re somewhere else in the tree so we need\n
\t\t// to build up a full list of the parentNodes for comparison\n
\t\twhile ( cur ) {\n
\t\t\tap.unshift( cur );\n
\t\t\tcur = cur.parentNode;\n
\t\t}\n
\n
\t\tcur = bup;\n
\n
\t\twhile ( cur ) {\n
\t\t\tbp.unshift( cur );\n
\t\t\tcur = cur.parentNode;\n
\t\t}\n
\n
\t\tal = ap.length;\n
\t\tbl = bp.length;\n
\n
\t\t// Start walking down the tree looking for a discrepancy\n
\t\tfor ( var i = 0; i < al && i < bl; i++ ) {\n
\t\t\tif ( ap[i] !== bp[i] ) {\n
\t\t\t\treturn siblingCheck( ap[i], bp[i] );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// We ended someplace up the tree so do a sibling check\n
\t\treturn i === al ?\n
\t\t\tsiblingCheck( a, bp[i], -1 ) :\n
\t\t\tsiblingCheck( ap[i], b, 1 );\n
\t};\n
\n
\tsiblingCheck = function( a, b, ret ) {\n
\t\tif ( a === b ) {\n
\t\t\treturn ret;\n
\t\t}\n
\n
\t\tvar cur = a.nextSibling;\n
\n
\t\twhile ( cur ) {\n
\t\t\tif ( cur === b ) {\n
\t\t\t\treturn -1;\n
\t\t\t}\n
\n
\t\t\tcur = cur.nextSibling;\n
\t\t}\n
\n
\t\treturn 1;\n
\t};\n
}\n
\n
// Check to see if the browser returns elements by name when\n
// querying by getElementById (and provide a workaround)\n
(function(){\n
\t// We\'re going to inject a fake input element with a specified name\n
\tvar form = document.createElement("div"),\n
\t\tid = "script" + (new Date()).getTime(),\n
\t\troot = document.documentElement;\n
\n
\tform.innerHTML = "<a name=\'" + id + "\'/>";\n
\n
\t// Inject it into the root element, check its status, and remove it quickly\n
\troot.insertBefore( form, root.firstChild );\n
\n
\t// The workaround has to do additional checks after a getElementById\n
\t// Which slows things down for other browsers (hence the branching)\n
\tif ( document.getElementById( id ) ) {\n
\t\tExpr.find.ID = function( match, context, isXML ) {\n
\t\t\tif ( typeof context.getElementById !== "undefined" && !isXML ) {\n
\t\t\t\tvar m = context.getElementById(match[1]);\n
\n
\t\t\t\treturn m ?\n
\t\t\t\t\tm.id === match[1] || typeof m.getAttributeNode !== "undefined" && m.getAttributeNode("id").nodeValue === match[1] ?\n
\t\t\t\t\t\t[m] :\n
\t\t\t\t\t\tundefined :\n
\t\t\t\t\t[];\n
\t\t\t}\n
\t\t};\n
\n
\t\tExpr.filter.ID = function( elem, match ) {\n
\t\t\tvar node = typeof elem.getAttributeNode !== "undefined" && elem.getAttributeNode("id");\n
\n
\t\t\treturn elem.nodeType === 1 && node && node.nodeValue === match;\n
\t\t};\n
\t}\n
\n
\troot.removeChild( form );\n
\n
\t// release memory in IE\n
\troot = form = null;\n
})();\n
\n
(function(){\n
\t// Check to see if the browser returns only elements\n
\t// when doing getElementsByTagName("*")\n
\n
\t// Create a fake element\n
\tvar div = document.createElement("div");\n
\tdiv.appendChild( document.createComment("") );\n
\n
\t// Make sure no comments are found\n
\tif ( div.getElementsByTagName("*").length > 0 ) {\n
\t\tExpr.find.TAG = function( match, context ) {\n
\t\t\tvar results = context.getElementsByTagName( match[1] );\n
\n
\t\t\t// Filter out possible comments\n
\t\t\tif ( match[1] === "*" ) {\n
\t\t\t\tvar tmp = [];\n
\n
\t\t\t\tfor ( var i = 0; results[i]; i++ ) {\n
\t\t\t\t\tif ( results[i].nodeType === 1 ) {\n
\t\t\t\t\t\ttmp.push( results[i] );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tresults = tmp;\n
\t\t\t}\n
\n
\t\t\treturn results;\n
\t\t};\n
\t}\n
\n
\t// Check to see if an attribute returns normalized href attributes\n
\tdiv.innerHTML = "<a href=\'#\'></a>";\n
\n
\tif ( div.firstChild && typeof div.firstChild.getAttribute !== "undefined" &&\n
\t\t\tdiv.firstChild.getAttribute("href") !== "#" ) {\n
\n
\t\tExpr.attrHandle.href = function( elem ) {\n
\t\t\treturn elem.getAttribute( "href", 2 );\n
\t\t};\n
\t}\n
\n
\t// release memory in IE\n
\tdiv = null;\n
})();\n
\n
if ( document.querySelectorAll ) {\n
\t(function(){\n
\t\tvar oldSizzle = Sizzle,\n
\t\t\tdiv = document.createElement("div"),\n
\t\t\tid = "__sizzle__";\n
\n
\t\tdiv.innerHTML = "<p class=\'TEST\'></p>";\n
\n
\t\t// Safari can\'t handle uppercase or unicode characters when\n
\t\t// in quirks mode.\n
\t\tif ( div.querySelectorAll && div.querySelectorAll(".TEST").length === 0 ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tSizzle = function( query, context, extra, seed ) {\n
\t\t\tcontext = context || document;\n
\n
\t\t\t// Only use querySelectorAll on non-XML documents\n
\t\t\t// (ID selectors don\'t work in non-HTML documents)\n
\t\t\tif ( !seed && !Sizzle.isXML(context) ) {\n
\t\t\t\t// See if we find a selector to speed up\n
\t\t\t\tvar match = /^(\\w+$)|^\\.([\\w\\-]+$)|^#([\\w\\-]+$)/.exec( query );\n
\n
\t\t\t\tif ( match && (context.nodeType === 1 || context.nodeType === 9) ) {\n
\t\t\t\t\t// Speed-up: Sizzle("TAG")\n
\t\t\t\t\tif ( match[1] ) {\n
\t\t\t\t\t\treturn makeArray( context.getElementsByTagName( query ), extra );\n
\n
\t\t\t\t\t// Speed-up: Sizzle(".CLASS")\n
\t\t\t\t\t} else if ( match[2] && Expr.find.CLASS && context.getElementsByClassName ) {\n
\t\t\t\t\t\treturn makeArray( context.getElementsByClassName( match[2] ), extra );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( context.nodeType === 9 ) {\n
\t\t\t\t\t// Speed-up: Sizzle("body")\n
\t\t\t\t\t// The body element only exists once, optimize finding it\n
\t\t\t\t\tif ( query === "body" && context.body ) {\n
\t\t\t\t\t\treturn makeArray( [ context.body ], extra );\n
\n
\t\t\t\t\t// Speed-up: Sizzle("#ID")\n
\t\t\t\t\t} else if ( match && match[3] ) {\n
\t\t\t\t\t\tvar elem = context.getElementById( match[3] );\n
\n
\t\t\t\t\t\t// Check parentNode to catch when Blackberry 4.6 returns\n
\t\t\t\t\t\t// nodes that are no longer in the document #6963\n
\t\t\t\t\t\tif ( elem && elem.parentNode ) {\n
\t\t\t\t\t\t\t// Handle the case where IE and Opera return items\n
\t\t\t\t\t\t\t// by name instead of ID\n
\t\t\t\t\t\t\tif ( elem.id === match[3] ) {\n
\t\t\t\t\t\t\t\treturn makeArray( [ elem ], extra );\n
\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\treturn makeArray( [], extra );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\treturn makeArray( context.querySelectorAll(query), extra );\n
\t\t\t\t\t} catch(qsaError) {}\n
\n
\t\t\t\t// qSA works strangely on Element-rooted queries\n
\t\t\t\t// We can work around this by specifying an extra ID on the root\n
\t\t\t\t// and working up from there (Thanks to Andrew Dupont for the technique)\n
\t\t\t\t// IE 8 doesn\'t work on object elements\n
\t\t\t\t} else if ( context.nodeType === 1 && context.nodeName.toLowerCase() !== "object" ) {\n
\t\t\t\t\tvar oldContext = context,\n
\t\t\t\t\t\told = context.getAttribute( "id" ),\n
\t\t\t\t\t\tnid = old || id,\n
\t\t\t\t\t\thasParent = context.parentNode,\n
\t\t\t\t\t\trelativeHierarchySelector = /^\\s*[+~]/.test( query );\n
\n
\t\t\t\t\tif ( !old ) {\n
\t\t\t\t\t\tcontext.setAttribute( "id", nid );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tnid = nid.replace( /\'/g, "\\\\$&" );\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( relativeHierarchySelector && hasParent ) {\n
\t\t\t\t\t\tcontext = context.parentNode;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\tif ( !relativeHierarchySelector || hasParent ) {\n
\t\t\t\t\t\t\treturn makeArray( context.querySelectorAll( "[id=\'" + nid + "\'] " + query ), extra );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} catch(pseudoError) {\n
\t\t\t\t\t} finally {\n
\t\t\t\t\t\tif ( !old ) {\n
\t\t\t\t\t\t\toldContext.removeAttribute( "id" );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn oldSizzle(query, context, extra, seed);\n
\t\t};\n
\n
\t\tfor ( var prop in oldSizzle ) {\n
\t\t\tSizzle[ prop ] = oldSizzle[ prop ];\n
\t\t}\n
\n
\t\t// release memory in IE\n
\t\tdiv = null;\n
\t})();\n
}\n
\n
(function(){\n
\tvar html = document.documentElement,\n
\t\tmatches = html.matchesSelector || html.mozMatchesSelector || html.webkitMatchesSelector || html.msMatchesSelector;\n
\n
\tif ( matches ) {\n
\t\t// Check to see if it\'s possible to do matchesSelector\n
\t\t// on a disconnected node (IE 9 fails this)\n
\t\tvar disconnectedMatch = !matches.call( document.createElement( "div" ), "div" ),\n
\t\t\tpseudoWorks = false;\n
\n
\t\ttry {\n
\t\t\t// This should fail with an exception\n
\t\t\t// Gecko does not error, returns false instead\n
\t\t\tmatches.call( document.documentElement, "[test!=\'\']:sizzle" );\n
\n
\t\t} catch( pseudoError ) {\n
\t\t\tpseudoWorks = true;\n
\t\t}\n
\n
\t\tSizzle.matchesSelector = function( node, expr ) {\n
\t\t\t// Make sure that attribute selectors are quoted\n
\t\t\texpr = expr.replace(/\\=\\s*([^\'"\\]]*)\\s*\\]/g, "=\'$1\']");\n
\n
\t\t\tif ( !Sizzle.isXML( node ) ) {\n
\t\t\t\ttry {\n
\t\t\t\t\tif ( pseudoWorks || !Expr.match.PSEUDO.test( expr ) && !/!=/.test( expr ) ) {\n
\t\t\t\t\t\tvar ret = matches.call( node, expr );\n
\n
\t\t\t\t\t\t// IE 9\'s matchesSelector returns false on disconnected nodes\n
\t\t\t\t\t\tif ( ret || !disconnectedMatch ||\n
\t\t\t\t\t\t\t\t// As well, disconnected nodes are said to be in a document\n
\t\t\t\t\t\t\t\t// fragment in IE 9, so check for that\n
\t\t\t\t\t\t\t\tnode.document && node.document.nodeType !== 11 ) {\n
\t\t\t\t\t\t\treturn ret;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t} catch(e) {}\n
\t\t\t}\n
\n
\t\t\treturn Sizzle(expr, null, null, [node]).length > 0;\n
\t\t};\n
\t}\n
})();\n
\n
(function(){\n
\tvar div = document.createElement("div");\n
\n
\tdiv.innerHTML = "<div class=\'test e\'></div><div class=\'test\'></div>";\n
\n
\t// Opera can\'t find a second classname (in 9.6)\n
\t// Also, make sure that getElementsByClassName actually exists\n
\tif ( !div.getElementsByClassName || div.getElementsByClassName("e").length === 0 ) {\n
\t\treturn;\n
\t}\n
\n
\t// Safari caches class attributes, doesn\'t catch changes (in 3.2)\n
\tdiv.lastChild.className = "e";\n
\n
\tif ( div.getElementsByClassName("e").length === 1 ) {\n
\t\treturn;\n
\t}\n
\n
\tExpr.order.splice(1, 0, "CLASS");\n
\tExpr.find.CLASS = function( match, context, isXML ) {\n
\t\tif ( typeof context.getElementsByClassName !== "undefined" && !isXML ) {\n
\t\t\treturn context.getElementsByClassName(match[1]);\n
\t\t}\n
\t};\n
\n
\t// release memory in IE\n
\tdiv = null;\n
})();\n
\n
function dirNodeCheck( dir, cur, doneName, checkSet, nodeCheck, isXML ) {\n
\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\tvar elem = checkSet[i];\n
\n
\t\tif ( elem ) {\n
\t\t\tvar match = false;\n
\n
\t\t\telem = elem[dir];\n
\n
\t\t\twhile ( elem ) {\n
\t\t\t\tif ( elem[ expando ] === doneName ) {\n
\t\t\t\t\tmatch = checkSet[elem.sizset];\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeType === 1 && !isXML ){\n
\t\t\t\t\telem[ expando ] = doneName;\n
\t\t\t\t\telem.sizset = i;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeName.toLowerCase() === cur ) {\n
\t\t\t\t\tmatch = elem;\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\telem = elem[dir];\n
\t\t\t}\n
\n
\t\t\tcheckSet[i] = match;\n
\t\t}\n
\t}\n
}\n
\n
function dirCheck( dir, cur, doneName, checkSet, nodeCheck, isXML ) {\n
\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\tvar elem = checkSet[i];\n
\n
\t\tif ( elem ) {\n
\t\t\tvar match = false;\n
\n
\t\t\telem = elem[dir];\n
\n
\t\t\twhile ( elem ) {\n
\t\t\t\tif ( elem[ expando ] === doneName ) {\n
\t\t\t\t\tmatch = checkSet[elem.sizset];\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\t\tif ( !isXML ) {\n
\t\t\t\t\t\telem[ expando ] = doneName;\n
\t\t\t\t\t\telem.sizset = i;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( typeof cur !== "string" ) {\n
\t\t\t\t\t\tif ( elem === cur ) {\n
\t\t\t\t\t\t\tmatch = true;\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else if ( Sizzle.filter( cur, [elem] ).length > 0 ) {\n
\t\t\t\t\t\tmatch = elem;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\telem = elem[dir];\n
\t\t\t}\n
\n
\t\t\tcheckSet[i] = match;\n
\t\t}\n
\t}\n
}\n
\n
if ( document.documentElement.contains ) {\n
\tSizzle.contains = function( a, b ) {\n
\t\treturn a !== b && (a.contains ? a.contains(b) : true);\n
\t};\n
\n
} else if ( document.documentElement.compareDocumentPosition ) {\n
\tSizzle.contains = function( a, b ) {\n
\t\treturn !!(a.compareDocumentPosition(b) & 16);\n
\t};\n
\n
} else {\n
\tSizzle.contains = function() {\n
\t\treturn false;\n
\t};\n
}\n
\n
Sizzle.isXML = function( elem ) {\n
\t// documentElement is verified for cases where it doesn\'t yet exist\n
\t// (such as loading iframes in IE - #4833)\n
\tvar documentElement = (elem ? elem.ownerDocument || elem : 0).documentElement;\n
\n
\treturn documentElement ? documentElement.nodeName !== "HTML" : false;\n
};\n
\n
var posProcess = function( selector, context, seed ) {\n
\tvar match,\n
\t\ttmpSet = [],\n
\t\tlater = "",\n
\t\troot = context.nodeType ? [context] : context;\n
\n
\t// Position selectors must be done after the filter\n
\t// And so must :not(positional) so we move all PSEUDOs to the end\n
\twhile ( (match = Expr.match.PSEUDO.exec( selector )) ) {\n
\t\tlater += match[0];\n
\t\tselector = selector.replace( Expr.match.PSEUDO, "" );\n
\t}\n
\n
\tselector = Expr.relative[selector] ? selector + "*" : selector;\n
\n
\tfor ( var i = 0, l = root.length; i < l; i++ ) {\n
\t\tSizzle( selector, root[i], tmpSet, seed );\n
\t}\n
\n
\treturn Sizzle.filter( later, tmpSet );\n
};\n
\n
// EXPOSE\n
// Override sizzle attribute retrieval\n
Sizzle.attr = jQuery.attr;\n
Sizzle.selectors.attrMap = {};\n
jQuery.find = Sizzle;\n
jQuery.expr = Sizzle.selectors;\n
jQuery.expr[":"] = jQuery.expr.filters;\n
jQuery.unique = Sizzle.uniqueSort;\n
jQuery.text = Sizzle.getText;\n
jQuery.isXMLDoc = Sizzle.isXML;\n
jQuery.contains = Sizzle.contains;\n
\n
\n
})();\n
\n
\n
var runtil = /Until$/,\n
\trparentsprev = /^(?:parents|prevUntil|prevAll)/,\n
\t// Note: This RegExp should be improved, or likely pulled from Sizzle\n
\trmultiselector = /,/,\n
\tisSimple = /^.[^:#\\[\\.,]*$/,\n
\tslice = Array.prototype.slice,\n
\tPOS = jQuery.expr.match.globalPOS,\n
\t// methods guaranteed to produce a unique set when starting from a unique set\n
\tguaranteedUnique = {\n
\t\tchildren: true,\n
\t\tcontents: true,\n
\t\tnext: true,\n
\t\tprev: true\n
\t};\n
\n
jQuery.fn.extend({\n
\tfind: function( selector ) {\n
\t\tvar self = this,\n
\t\t\ti, l;\n
\n
\t\tif ( typeof selector !== "string" ) {\n
\t\t\treturn jQuery( selector ).filter(function() {\n
\t\t\t\tfor ( i = 0, l = self.length; i < l; i++ ) {\n
\t\t\t\t\tif ( jQuery.contains( self[ i ], this ) ) {\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\tvar ret = this.pushStack( "", "find", selector ),\n
\t\t\tlength, n, r;\n
\n
\t\tfor ( i = 0, l = this.length; i < l; i++ ) {\n
\t\t\tlength = ret.length;\n
\t\t\tjQuery.find( selector, this[i], ret );\n
\n
\t\t\tif ( i > 0 ) {\n
\t\t\t\t// Make sure that the results are unique\n
\t\t\t\tfor ( n = length; n < ret.length; n++ ) {\n
\t\t\t\t\tfor ( r = 0; r < length; r++ ) {\n
\t\t\t\t\t\tif ( ret[r] === ret[n] ) {\n
\t\t\t\t\t\t\tret.splice(n--, 1);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\thas: function( target ) {\n
\t\tvar targets = jQuery( target );\n
\t\treturn this.filter(function() {\n
\t\t\tfor ( var i = 0, l = targets.length; i < l; i++ ) {\n
\t\t\t\tif ( jQuery.contains( this, targets[i] ) ) {\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tnot: function( selector ) {\n
\t\treturn this.pushStack( winnow(this, selector, false), "not", selector);\n
\t},\n
\n
\tfilter: function( selector ) {\n
\t\treturn this.pushStack( winnow(this, selector, true), "filter", selector );\n
\t},\n
\n
\tis: function( selector ) {\n
\t\treturn !!selector && (\n
\t\t\ttypeof selector === "string" ?\n
\t\t\t\t// If this is a positional selector, check membership in the returned set\n
\t\t\t\t// so $("p:first").is("p:last") won\'t return true for a doc with two "p".\n
\t\t\t\tPOS.test( selector ) ?\n
\t\t\t\t\tjQuery( selector, this.context ).index( this[0] ) >= 0 :\n
\t\t\t\t\tjQuery.filter( selector, this ).length > 0 :\n
\t\t\t\tthis.filter( selector ).length > 0 );\n
\t},\n
\n
\tclosest: function( selectors, context ) {\n
\t\tvar ret = [], i, l, cur = this[0];\n
\n
\t\t// Array (deprecated as of jQuery 1.7)\n
\t\tif ( jQuery.isArray( selectors ) ) {\n
\t\t\tvar level = 1;\n
\n
\t\t\twhile ( cur && cur.ownerDocument && cur !== context ) {\n
\t\t\t\tfor ( i = 0; i < selectors.length; i++ ) {\n
\n
\t\t\t\t\tif ( jQuery( cur ).is( selectors[ i ] ) ) {\n
\t\t\t\t\t\tret.push({ selector: selectors[ i ], elem: cur, level: level });\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tcur = cur.parentNode;\n
\t\t\t\tlevel++;\n
\t\t\t}\n
\n
\t\t\treturn ret;\n
\t\t}\n
\n
\t\t// String\n
\t\tvar pos = POS.test( selectors ) || typeof selectors !== "string" ?\n
\t\t\t\tjQuery( selectors, context || this.context ) :\n
\t\t\t\t0;\n
\n
\t\tfor ( i = 0, l = this.length; i < l; i++ ) {\n
\t\t\tcur = this[i];\n
\n
\t\t\twhile ( cur ) {\n
\t\t\t\tif ( pos ? pos.index(cur) > -1 : jQuery.find.matchesSelector(cur, selectors) ) {\n
\t\t\t\t\tret.push( cur );\n
\t\t\t\t\tbreak;\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tcur = cur.parentNode;\n
\t\t\t\t\tif ( !cur || !cur.ownerDocument || cur === context || cur.nodeType === 11 ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tret = ret.length > 1 ? jQuery.unique( ret ) : ret;\n
\n
\t\treturn this.pushStack( ret, "closest", selectors );\n
\t},\n
\n
\t// Determine the position of an element within\n
\t// the matched set of elements\n
\tindex: function( elem ) {\n
\n
\t\t// No argument, return index in parent\n
\t\tif ( !elem ) {\n
\t\t\treturn ( this[0] && this[0].parentNode ) ? this.prevAll().length : -1;\n
\t\t}\n
\n
\t\t// index in selector\n
\t\tif ( typeof elem === "string" ) {\n
\t\t\treturn jQuery.inArray( this[0], jQuery( elem ) );\n
\t\t}\n
\n
\t\t// Locate the position of the desired element\n
\t\treturn jQuery.inArray(\n
\t\t\t// If it receives a jQuery object, the first element is used\n
\t\t\telem.jquery ? elem[0] : elem, this );\n
\t},\n
\n
\tadd: function( selector, context ) {\n
\t\tvar set = typeof selector === "string" ?\n
\t\t\t\tjQuery( selector, context ) :\n
\t\t\t\tjQuery.makeArray( selector && selector.nodeType ? [ selector ] : selector ),\n
\t\t\tall = jQuery.merge( this.get(), set );\n
\n
\t\treturn this.pushStack( isDisconnected( set[0] ) || isDisconnected( all[0] ) ?\n
\t\t\tall :\n
\t\t\tjQuery.unique( all ) );\n
\t},\n
\n
\tandSelf: function() {\n
\t\treturn this.add( this.prevObject );\n
\t}\n
});\n
\n
// A painfully simple check to see if an element is disconnected\n
// from a document (should be improved, where feasible).\n
function isDisconnected( node ) {\n
\treturn !node || !node.parentNode || node.parentNode.nodeType === 11;\n
}\n
\n
jQuery.each({\n
\tparent: function( elem ) {\n
\t\tvar parent = elem.parentNode;\n
\t\treturn parent && parent.nodeType !== 11 ? parent : null;\n
\t},\n
\tparents: function( elem ) {\n
\t\treturn jQuery.dir( elem, "parentNode" );\n
\t},\n
\tparentsUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "parentNode", until );\n
\t},\n
\tnext: function( elem ) {\n
\t\treturn jQuery.nth( elem, 2, "nextSibling" );\n
\t},\n
\tprev: function( elem ) {\n
\t\treturn jQuery.nth( elem, 2, "previousSibling" );\n
\t},\n
\tnextAll: function( elem ) {\n
\t\treturn jQuery.dir( elem, "nextSibling" );\n
\t},\n
\tprevAll: function( elem ) {\n
\t\treturn jQuery.dir( elem, "previousSibling" );\n
\t},\n
\tnextUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "nextSibling", until );\n
\t},\n
\tprevUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "previousSibling", until );\n
\t},\n
\tsiblings: function( elem ) {\n
\t\treturn jQuery.sibling( ( elem.parentNode || {} ).firstChild, elem );\n
\t},\n
\tchildren: function( elem ) {\n
\t\treturn jQuery.sibling( elem.firstChild );\n
\t},\n
\tcontents: function( elem ) {\n
\t\treturn jQuery.nodeName( elem, "iframe" ) ?\n
\t\t\telem.contentDocument || elem.contentWindow.document :\n
\t\t\tjQuery.makeArray( elem.childNodes );\n
\t}\n
}, function( name, fn ) {\n
\tjQuery.fn[ name ] = function( until, selector ) {\n
\t\tvar ret = jQuery.map( this, fn, until );\n
\n
\t\tif ( !runtil.test( name ) ) {\n
\t\t\tselector = until;\n
\t\t}\n
\n
\t\tif ( selector && typeof selector === "string" ) {\n
\t\t\tret = jQuery.filter( selector, ret );\n
\t\t}\n
\n
\t\tret = this.length > 1 && !guaranteedUnique[ name ] ? jQuery.unique( ret ) : ret;\n
\n
\t\tif ( (this.length > 1 || rmultiselector.test( selector )) && rparentsprev.test( name ) ) {\n
\t\t\tret = ret.reverse();\n
\t\t}\n
\n
\t\treturn this.pushStack( ret, name, slice.call( arguments ).join(",") );\n
\t};\n
});\n
\n
jQuery.extend({\n
\tfilter: function( expr, elems, not ) {\n
\t\tif ( not ) {\n
\t\t\texpr = ":not(" + expr + ")";\n
\t\t}\n
\n
\t\treturn elems.length === 1 ?\n
\t\t\tjQuery.find.matchesSelector(elems[0], expr) ? [ elems[0] ] : [] :\n
\t\t\tjQuery.find.matches(expr, elems);\n
\t},\n
\n
\tdir: function( elem, dir, until ) {\n
\t\tvar matched = [],\n
\t\t\tcur = elem[ dir ];\n
\n
\t\twhile ( cur && cur.nodeType !== 9 && (until === undefined || cur.nodeType !== 1 || !jQuery( cur ).is( until )) ) {\n
\t\t\tif ( cur.nodeType === 1 ) {\n
\t\t\t\tmatched.push( cur );\n
\t\t\t}\n
\t\t\tcur = cur[dir];\n
\t\t}\n
\t\treturn matched;\n
\t},\n
\n
\tnth: function( cur, result, dir, elem ) {\n
\t\tresult = result || 1;\n
\t\tvar num = 0;\n
\n
\t\tfor ( ; cur; cur = cur[dir] ) {\n
\t\t\tif ( cur.nodeType === 1 && ++num === result ) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn cur;\n
\t},\n
\n
\tsibling: function( n, elem ) {\n
\t\tvar r = [];\n
\n
\t\tfor ( ; n; n = n.nextSibling ) {\n
\t\t\tif ( n.nodeType === 1 && n !== elem ) {\n
\t\t\t\tr.push( n );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn r;\n
\t}\n
});\n
\n
// Implement the identical functionality for filter and not\n
function winnow( elements, qualifier, keep ) {\n
\n
\t// Can\'t pass null or undefined to indexOf in Firefox 4\n
\t// Set to 0 to skip string check\n
\tqualifier = qualifier || 0;\n
\n
\tif ( jQuery.isFunction( qualifier ) ) {\n
\t\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\t\tvar retVal = !!qualifier.call( elem, i, elem );\n
\t\t\treturn retVal === keep;\n
\t\t});\n
\n
\t} else if ( qualifier.nodeType ) {\n
\t\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\t\treturn ( elem === qualifier ) === keep;\n
\t\t});\n
\n
\t} else if ( typeof qualifier === "string" ) {\n
\t\tvar filtered = jQuery.grep(elements, function( elem ) {\n
\t\t\treturn elem.nodeType === 1;\n
\t\t});\n
\n
\t\tif ( isSimple.test( qualifier ) ) {\n
\t\t\treturn jQuery.filter(qualifier, filtered, !keep);\n
\t\t} else {\n
\t\t\tqualifier = jQuery.filter( qualifier, filtered );\n
\t\t}\n
\t}\n
\n
\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\treturn ( jQuery.inArray( elem, qualifier ) >= 0 ) === keep;\n
\t});\n
}\n
\n
\n
\n
\n
function createSafeFragment( document ) {\n
\tvar list = nodeNames.split( "|" ),\n
\tsafeFrag = document.createDocumentFragment();\n
\n
\tif ( safeFrag.createElement ) {\n
\t\twhile ( list.length ) {\n
\t\t\tsafeFrag.createElement(\n
\t\t\t\tlist.pop()\n
\t\t\t);\n
\t\t}\n
\t}\n
\treturn safeFrag;\n
}\n
\n
var nodeNames = "abbr|article|aside|audio|bdi|canvas|data|datalist|details|figcaption|figure|footer|" +\n
\t\t"header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",\n
\trinlinejQuery = / jQuery\\d+="(?:\\d+|null)"/g,\n
\trleadingWhitespace = /^\\s+/,\n
\trxhtmlTag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\\w:]+)[^>]*)\\/>/ig,\n
\trtagName = /<([\\w:]+)/,\n
\trtbody = /<tbody/i,\n
\trhtml = /<|&#?\\w+;/,\n
\trnoInnerhtml = /<(?:script|style)/i,\n
\trnocache = /<(?:script|object|embed|option|style)/i,\n
\trnoshimcache = new RegExp("<(?:" + nodeNames + ")[\\\\s/>]", "i"),\n
\t// checked="checked" or checked\n
\trchecked = /checked\\s*(?:[^=]|=\\s*.checked.)/i,\n
\trscriptType = /\\/(java|ecma)script/i,\n
\trcleanScript = /^\\s*<!(?:\\[CDATA\\[|\\-\\-)/,\n
\twrapMap = {\n
\t\toption: [ 1, "<select multiple=\'multiple\'>", "</select>" ],\n
\t\tlegend: [ 1, "<fieldset>", "</fieldset>" ],\n
\t\tthead: [ 1, "<table>", "</table>" ],\n
\t\ttr: [ 2, "<table><tbody>", "</tbody></table>" ],\n
\t\ttd: [ 3, "<table><tbody><tr>", "</tr></tbody></table>" ],\n
\t\tcol: [ 2, "<table><tbody></tbody><colgroup>", "</colgroup></table>" ],\n
\t\tarea: [ 1, "<map>", "</map>" ],\n
\t\t_default: [ 0, "", "" ]\n
\t},\n
\tsafeFragment = createSafeFragment( document );\n
\n
wrapMap.optgroup = wrapMap.option;\n
wrapMap.tbody = wrapMap.tfoot = wrapMap.colgroup = wrapMap.caption = wrapMap.thead;\n
wrapMap.th = wrapMap.td;\n
\n
// IE can\'t serialize <link> and <script> tags normally\n
if ( !jQuery.support.htmlSerialize ) {\n
\twrapMap._default = [ 1, "div<div>", "</div>" ];\n
}\n
\n
jQuery.fn.extend({\n
\ttext: function( value ) {\n
\t\treturn jQuery.access( this, function( value ) {\n
\t\t\treturn value === undefined ?\n
\t\t\t\tjQuery.text( this ) :\n
\t\t\t\tthis.empty().append( ( this[0] && this[0].ownerDocument || document ).createTextNode( value ) );\n
\t\t}, null, value, arguments.length );\n
\t},\n
\n
\twrapAll: function( html ) {\n
\t\tif ( jQuery.isFunction( html ) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tjQuery(this).wrapAll( html.call(this, i) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this[0] ) {\n
\t\t\t// The elements to wrap the target around\n
\t\t\tvar wrap = jQuery( html, this[0].ownerDocument ).eq(0).clone(true);\n
\n
\t\t\tif ( this[0].parentNode ) {\n
\t\t\t\twrap.insertBefore( this[0] );\n
\t\t\t}\n
\n
\t\t\twrap.map(function() {\n
\t\t\t\tvar elem = this;\n
\n
\t\t\t\twhile ( elem.firstChild && elem.firstChild.nodeType === 1 ) {\n
\t\t\t\t\telem = elem.firstChild;\n
\t\t\t\t}\n
\n
\t\t\t\treturn elem;\n
\t\t\t}).append( this );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\twrapInner: function( html ) {\n
\t\tif ( jQuery.isFunction( html ) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tjQuery(this).wrapInner( html.call(this, i) );\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn this.each(function() {\n
\t\t\tvar self = jQuery( this ),\n
\t\t\t\tcontents = self.contents();\n
\n
\t\t\tif ( contents.length ) {\n
\t\t\t\tcontents.wrapAll( html );\n
\n
\t\t\t} else {\n
\t\t\t\tself.append( html );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\twrap: function( html ) {\n
\t\tvar isFunction = jQuery.isFunction( html );\n
\n
\t\treturn this.each(function(i) {\n
\t\t\tjQuery( this ).wrapAll( isFunction ? html.call(this, i) : html );\n
\t\t});\n
\t},\n
\n
\tunwrap: function() {\n
\t\treturn this.parent().each(function() {\n
\t\t\tif ( !jQuery.nodeName( this, "body" ) ) {\n
\t\t\t\tjQuery( this ).replaceWith( this.childNodes );\n
\t\t\t}\n
\t\t}).end();\n
\t},\n
\n
\tappend: function() {\n
\t\treturn this.domManip(arguments, true, function( elem ) {\n
\t\t\tif ( this.nodeType === 1 ) {\n
\t\t\t\tthis.appendChild( elem );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tprepend: function() {\n
\t\treturn this.domManip(arguments, true, function( elem ) {\n
\t\t\tif ( this.nodeType === 1 ) {\n
\t\t\t\tthis.insertBefore( elem, this.firstChild );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tbefore: function() {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\treturn this.domManip(arguments, false, function( elem ) {\n
\t\t\t\tthis.parentNode.insertBefore( elem, this );\n
\t\t\t});\n
\t\t} else if ( arguments.length ) {\n
\t\t\tvar set = jQuery.clean( arguments );\n
\t\t\tset.push.apply( set, this.toArray() );\n
\t\t\treturn this.pushStack( set, "before", arguments );\n
\t\t}\n
\t},\n
\n
\tafter: function() {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\treturn this.domManip(arguments, false, function( elem ) {\n
\t\t\t\tthis.parentNode.insertBefore( elem, this.nextSibling );\n
\t\t\t});\n
\t\t} else if ( arguments.length ) {\n
\t\t\tvar set = this.pushStack( this, "after", arguments );\n
\t\t\tset.push.apply( set, jQuery.clean(arguments) );\n
\t\t\treturn set;\n
\t\t}\n
\t},\n
\n
\t// keepData is for internal use only--do not document\n
\tremove: function( selector, keepData ) {\n
\t\tfor ( var i = 0, elem; (elem = this[i]) != null; i++ ) {\n
\t\t\tif ( !selector || jQuery.filter( selector, [ elem ] ).length ) {\n
\t\t\t\tif ( !keepData && elem.nodeType === 1 ) {\n
\t\t\t\t\tjQuery.cleanData( elem.getElementsByTagName("*") );\n
\t\t\t\t\tjQuery.cleanData( [ elem ] );\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.parentNode ) {\n
\t\t\t\t\telem.parentNode.removeChild( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tempty: function() {\n
\t\tfor ( var i = 0, elem; (elem = this[i]) != null; i++ ) {\n
\t\t\t// Remove element nodes and prevent memory leaks\n
\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\tjQuery.cleanData( elem.getElementsByTagName("*") );\n
\t\t\t}\n
\n
\t\t\t// Remove any remaining nodes\n
\t\t\twhile ( elem.firstChild ) {\n
\t\t\t\telem.removeChild( elem.firstChild );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tclone: function( dataAndEvents, deepDataAndEvents ) {\n
\t\tdataAndEvents = dataAndEvents == null ? false : dataAndEvents;\n
\t\tdeepDataAndEvents = deepDataAndEvents == null ? dataAndEvents : deepDataAndEvents;\n
\n
\t\treturn this.map( function () {\n
\t\t\treturn jQuery.clone( this, dataAndEvents, deepDataAndEvents );\n
\t\t});\n
\t},\n
\n
\thtml: function( value ) {\n
\t\treturn jQuery.access( this, function( value ) {\n
\t\t\tvar elem = this[0] || {},\n
\t\t\t\ti = 0,\n
\t\t\t\tl = this.length;\n
\n
\t\t\tif ( value === undefined ) {\n
\t\t\t\treturn elem.nodeType === 1 ?\n
\t\t\t\t\telem.innerHTML.replace( rinlinejQuery, "" ) :\n
\t\t\t\t\tnull;\n
\t\t\t}\n
\n
\n
\t\t\tif ( typeof value === "string" && !rnoInnerhtml.test( value ) &&\n
\t\t\t\t( jQuery.support.leadingWhitespace || !rleadingWhitespace.test( value ) ) &&\n
\t\t\t\t!wrapMap[ ( rtagName.exec( value ) || ["", ""] )[1].toLowerCase() ] ) {\n
\n
\t\t\t\tvalue = value.replace( rxhtmlTag, "<$1></$2>" );\n
\n
\t\t\t\ttry {\n
\t\t\t\t\tfor (; i < l; i++ ) {\n
\t\t\t\t\t\t// Remove element nodes and prevent memory leaks\n
\t\t\t\t\t\telem = this[i] || {};\n
\t\t\t\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\t\t\t\tjQuery.cleanData( elem.getElementsByTagName( "*" ) );\n
\t\t\t\t\t\t\telem.innerHTML = value;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\telem = 0;\n
\n
\t\t\t\t// If using innerHTML throws an exception, use the fallback method\n
\t\t\t\t} catch(e) {}\n
\t\t\t}\n
\n
\t\t\tif ( elem ) {\n
\t\t\t\tthis.empty().append( value );\n
\t\t\t}\n
\t\t}, null, value, arguments.length );\n
\t},\n
\n
\treplaceWith: function( value ) {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\t// Make sure that the elements are removed from the DOM before they are inserted\n
\t\t\t// this can help fix replacing a parent with child elements\n
\t\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\t\treturn this.each(function(i) {\n
\t\t\t\t\tvar self = jQuery(this), old = self.html();\n
\t\t\t\t\tself.replaceWith( value.call( this, i, old ) );\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif ( typeof value !== "string" ) {\n
\t\t\t\tvalue = jQuery( value ).detach();\n
\t\t\t}\n
\n
\t\t\treturn this.each(function() {\n
\t\t\t\tvar next = this.nextSibling,\n
\t\t\t\t\tparent = this.parentNode;\n
\n
\t\t\t\tjQuery( this ).remove();\n
\n
\t\t\t\tif ( next ) {\n
\t\t\t\t\tjQuery(next).before( value );\n
\t\t\t\t} else {\n
\t\t\t\t\tjQuery(parent).append( value );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\treturn this.length ?\n
\t\t\t\tthis.pushStack( jQuery(jQuery.isFunction(value) ? value() : value), "replaceWith", value ) :\n
\t\t\t\tthis;\n
\t\t}\n
\t},\n
\n
\tdetach: function( selector ) {\n
\t\treturn this.remove( selector, true );\n
\t},\n
\n
\tdomManip: function( args, table, callback ) {\n
\t\tvar results, first, fragment, parent,\n
\t\t\tvalue = args[0],\n
\t\t\tscripts = [];\n
\n
\t\t// We can\'t cloneNode fragments that contain checked, in WebKit\n
\t\tif ( !jQuery.support.checkClone && arguments.length === 3 && typeof value === "string" && rchecked.test( value ) ) {\n
\t\t\treturn this.each(function() {\n
\t\t\t\tjQuery(this).domManip( args, table, callback, true );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( jQuery.isFunction(value) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\targs[0] = value.call(this, i, table ? self.html() : undefined);\n
\t\t\t\tself.domManip( args, table, callback );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this[0] ) {\n
\t\t\tparent = value && value.parentNode;\n
\n
\t\t\t// If we\'re in a fragment, just use that instead of building a new one\n
\t\t\tif ( jQuery.support.parentNode && parent && parent.nodeType === 11 && parent.childNodes.length === this.length ) {\n
\t\t\t\tresults = { fragment: parent };\n
\n
\t\t\t} else {\n
\t\t\t\tresults = jQuery.buildFragment( args, this, scripts );\n
\t\t\t}\n
\n
\t\t\tfragment = results.fragment;\n
\n
\t\t\tif ( fragment.childNodes.length === 1 ) {\n
\t\t\t\tfirst = fragment = fragment.firstChild;\n
\t\t\t} else {\n
\t\t\t\tfirst = fragment.firstChild;\n
\t\t\t}\n
\n
\t\t\tif ( first ) {\n
\t\t\t\ttable = table && jQuery.nodeName( first, "tr" );\n
\n
\t\t\t\tfor ( var i = 0, l = this.length, lastIndex = l - 1; i < l; i++ ) {\n
\t\t\t\t\tcallback.call(\n
\t\t\t\t\t\ttable ?\n
\t\t\t\t\t\t\troot(this[i], first) :\n
\t\t\t\t\t\t\tthis[i],\n
\t\t\t\t\t\t// Make sure that we do not leak memory by inadvertently discarding\n
\t\t\t\t\t\t// the original fragment (which might have attached data) instead of\n
\t\t\t\t\t\t// using it; in addition, use the original fragment object for the last\n
\t\t\t\t\t\t// item instead of first because it can end up being emptied incorrectly\n
\t\t\t\t\t\t// in certain situations (Bug #8070).\n
\t\t\t\t\t\t// Fragments from the fragment cache must always be cloned and never used\n
\t\t\t\t\t\t// in place.\n
\t\t\t\t\t\tresults.cacheable || ( l > 1 && i < lastIndex ) ?\n
\t\t\t\t\t\t\tjQuery.clone( fragment, true, true ) :\n
\t\t\t\t\t\t\tfragment\n
\t\t\t\t\t);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( scripts.length ) {\n
\t\t\t\tjQuery.each( scripts, function( i, elem ) {\n
\t\t\t\t\tif ( elem.src ) {\n
\t\t\t\t\t\tjQuery.ajax({\n
\t\t\t\t\t\t\ttype: "GET",\n
\t\t\t\t\t\t\tglobal: false,\n
\t\t\t\t\t\t\turl: elem.src,\n
\t\t\t\t\t\t\tasync: false,\n
\t\t\t\t\t\t\tdataType: "script"\n
\t\t\t\t\t\t});\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tjQuery.globalEval( ( elem.text || elem.textContent || elem.innerHTML || "" ).replace( rcleanScript, "/*$0*/" ) );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( elem.parentNode ) {\n
\t\t\t\t\t\telem.parentNode.removeChild( elem );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t}\n
});\n
\n
function root( elem, cur ) {\n
\treturn jQuery.nodeName(elem, "table") ?\n
\t\t(elem.getElementsByTagName("tbody")[0] ||\n
\t\telem.appendChild(elem.ownerDocument.createElement("tbody"))) :\n
\t\telem;\n
}\n
\n
function cloneCopyEvent( src, dest ) {\n
\n
\tif ( dest.nodeType !== 1 || !jQuery.hasData( src ) ) {\n
\t\treturn;\n
\t}\n
\n
\tvar type, i, l,\n
\t\toldData = jQuery._data( src ),\n
\t\tcurData = jQuery._data( dest, oldData ),\n
\t\tevents = oldData.events;\n
\n
\tif ( events ) {\n
\t\tdelete curData.handle;\n
\t\tcurData.events = {};\n
\n
\t\tfor ( type in events ) {\n
\t\t\tfor ( i = 0, l = events[ type ].length; i < l; i++ ) {\n
\t\t\t\tjQuery.event.add( dest, type, events[ type ][ i ] );\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\t// make the cloned public data object a copy from the original\n
\tif ( curData.data ) {\n
\t\tcurData.data = jQuery.extend( {}, curData.data );\n
\t}\n
}\n
\n
function cloneFixAttributes( src, dest ) {\n
\tvar nodeName;\n
\n
\t// We do not need to do anything for non-Elements\n
\tif ( dest.nodeType !== 1 ) {\n
\t\treturn;\n
\t}\n
\n
\t// clearAttributes removes the attributes, which we don\'t want,\n
\t// but also removes the attachEvent events, which we *do* want\n
\tif ( dest.clearAttributes ) {\n
\t\tdest.clearAttributes();\n
\t}\n
\n
\t// mergeAttributes, in contrast, only merges back on the\n
\t// original attributes, not the events\n
\tif ( dest.mergeAttributes ) {\n
\t\tdest.mergeAttributes( src );\n
\t}\n
\n
\tnodeName = dest.nodeName.toLowerCase();\n
\n
\t// IE6-8 fail to clone children inside object elements that use\n
\t// the proprietary classid attribute value (rather than the type\n
\t// attribute) to identify the type of content to display\n
\tif ( nodeName === "object" ) {\n
\t\tdest.outerHTML = src.outerHTML;\n
\n
\t} else if ( nodeName === "input" && (src.type === "checkbox" || src.type === "radio") ) {\n
\t\t// IE6-8 fails to persist the checked state of a cloned checkbox\n
\t\t// or radio button. Worse, IE6-7 fail to give the cloned element\n
\t\t// a checked appearance if the defaultChecked value isn\'t also set\n
\t\tif ( src.checked ) {\n
\t\t\tdest.defaultChecked = dest.checked = src.checked;\n
\t\t}\n
\n
\t\t// IE6-7 get confused and end up setting the value of a cloned\n
\t\t// checkbox/radio button to an empty string instead of "on"\n
\t\tif ( dest.value !== src.value ) {\n
\t\t\tdest.value = src.value;\n
\t\t}\n
\n
\t// IE6-8 fails to return the selected option to the default selected\n
\t// state when cloning options\n
\t} else if ( nodeName === "option" ) {\n
\t\tdest.selected = src.defaultSelected;\n
\n
\t// IE6-8 fails to set the defaultValue to the correct value when\n
\t// cloning other types of input fields\n
\t} else if ( nodeName === "input" || nodeName === "textarea" ) {\n
\t\tdest.defaultValue = src.defaultValue;\n
\n
\t// IE blanks contents when cloning scripts\n
\t} else if ( nodeName === "script" && dest.text !== src.text ) {\n
\t\tdest.text = src.text;\n
\t}\n
\n
\t// Event data gets referenced instead of copied if the expando\n
\t// gets copied too\n
\tdest.removeAttribute( jQuery.expando );\n
\n
\t// Clear flags for bubbling special change/submit events, they must\n
\t// be reattached when the newly cloned events are first activated\n
\tdest.removeAttribute( "_submit_attached" );\n
\tdest.removeAttribute( "_change_attached" );\n
}\n
\n
jQuery.buildFragment = function( args, nodes, scripts ) {\n
\tvar fragment, cacheable, cacheresults, doc,\n
\tfirst = args[ 0 ];\n
\n
\t// nodes may contain either an explicit document object,\n
\t// a jQuery collection or context object.\n
\t// If nodes[0] contains a valid object to assign to doc\n
\tif ( nodes && nodes[0] ) {\n
\t\tdoc = nodes[0].ownerDocument || nodes[0];\n
\t}\n
\n
\t// Ensure that an attr object doesn\'t incorrectly stand in as a document object\n
\t// Chrome and Firefox seem to allow this to occur and will throw exception\n
\t// Fixes #8950\n
\tif ( !doc.createDocumentFragment ) {\n
\t\tdoc = document;\n
\t}\n
\n
\t// Only cache "small" (1/2 KB) HTML strings that are associated with the main document\n
\t// Cloning options loses the selected state, so don\'t cache them\n
\t// IE 6 doesn\'t like it when you put <object> or <embed> elements in a fragment\n
\t// Also, WebKit does not clone \'checked\' attributes on cloneNode, so don\'t cache\n
\t// Lastly, IE6,7,8 will not correctly reuse cached fragments that were created from unknown elems #10501\n
\tif ( args.length === 1 && typeof first === "string" && first.length < 512 && doc === document &&\n
\t\tfirst.charAt(0) === "<" && !rnocache.test( first ) &&\n
\t\t(jQuery.support.checkClone || !rchecked.test( first )) &&\n
\t\t(jQuery.support.html5Clone || !rnoshimcache.test( first )) ) {\n
\n
\t\tcacheable = true;\n
\n
\t\tcacheresults = jQuery.fragments[ first ];\n
\t\tif ( cacheresults && cacheresults !== 1 ) {\n
\t\t\tfragment = cacheresults;\n
\t\t}\n
\t}\n
\n
\tif ( !fragment ) {\n
\t\tfragment = doc.createDocumentFragment();\n
\t\tjQuery.clean( args, doc, fragment, scripts );\n
\t}\n
\n
\tif ( cacheable ) {\n
\t\tjQuery.fragments[ first ] = cacheresults ? fragment : 1;\n
\t}\n
\n
\treturn { fragment: fragment, cacheable: cacheable };\n
};\n
\n
jQuery.fragments = {};\n
\n
jQuery.each({\n
\tappendTo: "append",\n
\tprependTo: "prepend",\n
\tinsertBefore: "before",\n
\tinsertAfter: "after",\n
\treplaceAll: "replaceWith"\n
}, function( name, original ) {\n
\tjQuery.fn[ name ] = function( selector ) {\n
\t\tvar ret = [],\n
\t\t\tinsert = jQuery( selector ),\n
\t\t\tparent = this.length === 1 && this[0].parentNode;\n
\n
\t\tif ( parent && parent.nodeType === 11 && parent.childNodes.length === 1 && insert.length === 1 ) {\n
\t\t\tinsert[ original ]( this[0] );\n
\t\t\treturn this;\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = insert.length; i < l; i++ ) {\n
\t\t\t\tvar elems = ( i > 0 ? this.clone(true) : this ).get();\n
\t\t\t\tjQuery( insert[i] )[ original ]( elems );\n
\t\t\t\tret = ret.concat( elems );\n
\t\t\t}\n
\n
\t\t\treturn this.pushStack( ret, name, insert.selector );\n
\t\t}\n
\t};\n
});\n
\n
function getAll( elem ) {\n
\tif ( typeof elem.getElementsByTagName !== "undefined" ) {\n
\t\treturn elem.getElementsByTagName( "*" );\n
\n
\t} else if ( typeof elem.querySelectorAll !== "undefined" ) {\n
\t\treturn elem.querySelectorAll( "*" );\n
\n
\t} else {\n
\t\treturn [];\n
\t}\n
}\n
\n
// Used in clean, fixes the defaultChecked property\n
function fixDefaultChecked( elem ) {\n
\tif ( elem.type === "checkbox" || elem.type === "radio" ) {\n
\t\telem.defaultChecked = elem.checked;\n
\t}\n
}\n
// Finds all inputs and passes them to fixDefaultChecked\n
function findInputs( elem ) {\n
\tvar nodeName = ( elem.nodeName || "" ).toLowerCase();\n
\tif ( nodeName === "input" ) {\n
\t\tfixDefaultChecked( elem );\n
\t// Skip scripts, get other children\n
\t} else if ( nodeName !== "script" && typeof elem.getElementsByTagName !== "undefined" ) {\n
\t\tjQuery.grep( elem.getElementsByTagName("input"), fixDefaultChecked );\n
\t}\n
}\n
\n
// Derived From: http://www.iecss.com/shimprove/javascript/shimprove.1-0-1.js\n
function shimCloneNode( elem ) {\n
\tvar div = document.createElement( "div" );\n
\tsafeFragment.appendChild( div );\n
\n
\tdiv.innerHTML = elem.outerHTML;\n
\treturn div.firstChild;\n
}\n
\n
jQuery.extend({\n
\tclone: function( elem, dataAndEvents, deepDataAndEvents ) {\n
\t\tvar srcElements,\n
\t\t\tdestElements,\n
\t\t\ti,\n
\t\t\t// IE<=8 does not properly clone detached, unknown element nodes\n
\t\t\tclone = jQuery.support.html5Clone || jQuery.isXMLDoc(elem) || !rnoshimcache.test( "<" + elem.nodeName + ">" ) ?\n
\t\t\t\telem.cloneNode( true ) :\n
\t\t\t\tshimCloneNode( elem );\n
\n
\t\tif ( (!jQuery.support.noCloneEvent || !jQuery.support.noCloneChecked) &&\n
\t\t\t\t(elem.nodeType === 1 || elem.nodeType === 11) && !jQuery.isXMLDoc(elem) ) {\n
\t\t\t// IE copies events bound via attachEvent when using cloneNode.\n
\t\t\t// Calling detachEvent on the clone will also remove the events\n
\t\t\t// from the original. In order to get around this, we use some\n
\t\t\t// proprietary methods to clear the events. Thanks to MooTools\n
\t\t\t// guys for this hotness.\n
\n
\t\t\tcloneFixAttributes( elem, clone );\n
\n
\t\t\t// Using Sizzle here is crazy slow, so we use getElementsByTagName instead\n
\t\t\tsrcElements = getAll( elem );\n
\t\t\tdestElements = getAll( clone );\n
\n
\t\t\t// Weird iteration because IE will replace the length property\n
\t\t\t// with an element if you are cloning the body and one of the\n
\t\t\t// elements on the page has a name or id of "length"\n
\t\t\tfor ( i = 0; srcElements[i]; ++i ) {\n
\t\t\t\t// Ensure that the destination node is not null; Fixes #9587\n
\t\t\t\tif ( destElements[i] ) {\n
\t\t\t\t\tcloneFixAttributes( srcElements[i], destElements[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Copy the events from the original to the clone\n
\t\tif ( dataAndEvents ) {\n
\t\t\tcloneCopyEvent( elem, clone );\n
\n
\t\t\tif ( deepDataAndEvents ) {\n
\t\t\t\tsrcElements = getAll( elem );\n
\t\t\t\tdestElements = getAll( clone );\n
\n
\t\t\t\tfor ( i = 0; srcElements[i]; ++i ) {\n
\t\t\t\t\tcloneCopyEvent( srcElements[i], destElements[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tsrcElements = destElements = null;\n
\n
\t\t// Return the cloned set\n
\t\treturn clone;\n
\t},\n
\n
\tclean: function( elems, context, fragment, scripts ) {\n
\t\tvar checkScriptType, script, j,\n
\t\t\t\tret = [];\n
\n
\t\tcontext = context || document;\n
\n
\t\t// !context.createElement fails in IE with an error but returns typeof \'object\'\n
\t\tif ( typeof context.createElement === "undefined" ) {\n
\t\t\tcontext = context.ownerDocument || context[0] && context[0].ownerDocument || document;\n
\t\t}\n
\n
\t\tfor ( var i = 0, elem; (elem = elems[i]) != null; i++ ) {\n
\t\t\tif ( typeof elem === "number" ) {\n
\t\t\t\telem += "";\n
\t\t\t}\n
\n
\t\t\tif ( !elem ) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t// Convert html string into DOM nodes\n
\t\t\tif ( typeof elem === "string" ) {\n
\t\t\t\tif ( !rhtml.test( elem ) ) {\n
\t\t\t\t\telem = context.createTextNode( elem );\n
\t\t\t\t} else {\n
\t\t\t\t\t// Fix "XHTML"-style tags in all browsers\n
\t\t\t\t\telem = elem.replace(rxhtmlTag, "<$1></$2>");\n
\n
\t\t\t\t\t// Trim whitespace, otherwise indexOf won\'t work as expected\n
\t\t\t\t\tvar tag = ( rtagName.exec( elem ) || ["", ""] )[1].toLowerCase(),\n
\t\t\t\t\t\twrap = wrapMap[ tag ] || wrapMap._default,\n
\t\t\t\t\t\tdepth = wrap[0],\n
\t\t\t\t\t\tdiv = context.createElement("div"),\n
\t\t\t\t\t\tsafeChildNodes = safeFragment.childNodes,\n
\t\t\t\t\t\tremove;\n
\n
\t\t\t\t\t// Append wrapper element to unknown element safe doc fragment\n
\t\t\t\t\tif ( context === document ) {\n
\t\t\t\t\t\t// Use the fragment we\'ve already created for this document\n
\t\t\t\t\t\tsafeFragment.appendChild( div );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t// Use a fragment created with the owner document\n
\t\t\t\t\t\tcreateSafeFragment( context ).appendChild( div );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Go to html and back, then peel off extra wrappers\n
\t\t\t\t\tdiv.innerHTML = wrap[1] + elem + wrap[2];\n
\n
\t\t\t\t\t// Move to the right depth\n
\t\t\t\t\twhile ( depth-- ) {\n
\t\t\t\t\t\tdiv = div.lastChild;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Remove IE\'s autoinserted <tbody> from table fragments\n
\t\t\t\t\tif ( !jQuery.support.tbody ) {\n
\n
\t\t\t\t\t\t// String was a <table>, *may* have spurious <tbody>\n
\t\t\t\t\t\tvar hasBody = rtbody.test(elem),\n
\t\t\t\t\t\t\ttbody = tag === "table" && !hasBody ?\n
\t\t\t\t\t\t\t\tdiv.firstChild && div.firstChild.childNodes :\n
\n
\t\t\t\t\t\t\t\t// String was a bare <thead> or <tfoot>\n
\t\t\t\t\t\t\t\twrap[1] === "<table>" && !hasBody ?\n
\t\t\t\t\t\t\t\t\tdiv.childNodes :\n
\t\t\t\t\t\t\t\t\t[];\n
\n
\t\t\t\t\t\tfor ( j = tbody.length - 1; j >= 0 ; --j ) {\n
\t\t\t\t\t\t\tif ( jQuery.nodeName( tbody[ j ], "tbody" ) && !tbody[ j ].childNodes.length ) {\n
\t\t\t\t\t\t\t\ttbody[ j ].parentNode.removeChild( tbody[ j ] );\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// IE completely kills leading whitespace when innerHTML is used\n
\t\t\t\t\tif ( !jQuery.support.leadingWhitespace && rleadingWhitespace.test( elem ) ) {\n
\t\t\t\t\t\tdiv.insertBefore( context.createTextNode( rleadingWhitespace.exec(elem)[0] ), div.firstChild );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\telem = div.childNodes;\n
\n
\t\t\t\t\t// Clear elements from DocumentFragment (safeFragment or otherwise)\n
\t\t\t\t\t// to avoid hoarding elements. Fixes #11356\n
\t\t\t\t\tif ( div ) {\n
\t\t\t\t\t\tdiv.parentNode.removeChild( div );\n
\n
\t\t\t\t\t\t// Guard against -1 index exceptions in FF3.6\n
\t\t\t\t\t\tif ( safeChildNodes.length > 0 ) {\n
\t\t\t\t\t\t\tremove = safeChildNodes[ safeChildNodes.length - 1 ];\n
\n
\t\t\t\t\t\t\tif ( remove && remove.parentNode ) {\n
\t\t\t\t\t\t\t\tremove.parentNode.removeChild( remove );\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Resets defaultChecked for any radios and checkboxes\n
\t\t\t// about to be appended to the DOM in IE 6/7 (#8060)\n
\t\t\tvar len;\n
\t\t\tif ( !jQuery.support.appendChecked ) {\n
\t\t\t\tif ( elem[0] && typeof (len = elem.length) === "number" ) {\n
\t\t\t\t\tfor ( j = 0; j < len; j++ ) {\n
\t\t\t\t\t\tfindInputs( elem[j] );\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tfindInputs( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( elem.nodeType ) {\n
\t\t\t\tret.push( elem );\n
\t\t\t} else {\n
\t\t\t\tret = jQuery.merge( ret, elem );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( fragment ) {\n
\t\t\tcheckScriptType = function( elem ) {\n
\t\t\t\treturn !elem.type || rscriptType.test( elem.type );\n
\t\t\t};\n
\t\t\tfor ( i = 0; ret[i]; i++ ) {\n
\t\t\t\tscript = ret[i];\n
\t\t\t\tif ( scripts && jQuery.nodeName( script, "script" ) && (!script.type || rscriptType.test( script.type )) ) {\n
\t\t\t\t\tscripts.push( script.parentNode ? script.parentNode.removeChild( script ) : script );\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tif ( script.nodeType === 1 ) {\n
\t\t\t\t\t\tvar jsTags = jQuery.grep( script.getElementsByTagName( "script" ), checkScriptType );\n
\n
\t\t\t\t\t\tret.splice.apply( ret, [i + 1, 0].concat( jsTags ) );\n
\t\t\t\t\t}\n
\t\t\t\t\tfragment.appendChild( script );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\tcleanData: function( elems ) {\n
\t\tvar data, id,\n
\t\t\tcache = jQuery.cache,\n
\t\t\tspecial = jQuery.event.special,\n
\t\t\tdeleteExpando = jQuery.support.deleteExpando;\n
\n
\t\tfor ( var i = 0, elem; (elem = elems[i]) != null; i++ ) {\n
\t\t\tif ( elem.nodeName && jQuery.noData[elem.nodeName.toLowerCase()] ) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tid = elem[ jQuery.expando ];\n
\n
\t\t\tif ( id ) {\n
\t\t\t\tdata = cache[ id ];\n
\n
\t\t\t\tif ( data && data.events ) {\n
\t\t\t\t\tfor ( var type in data.events ) {\n
\t\t\t\t\t\tif ( special[ type ] ) {\n
\t\t\t\t\t\t\tjQuery.event.remove( elem, type );\n
\n
\t\t\t\t\t\t// This is a shortcut to avoid jQuery.event.remove\'s overhead\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tjQuery.removeEvent( elem, type, data.handle );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Null the DOM reference to avoid IE6/7/8 leak (#7054)\n
\t\t\t\t\tif ( data.handle ) {\n
\t\t\t\t\t\tdata.handle.elem = null;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( deleteExpando ) {\n
\t\t\t\t\tdelete elem[ jQuery.expando ];\n
\n
\t\t\t\t} else if ( elem.removeAttribute ) {\n
\t\t\t\t\telem.removeAttribute( jQuery.expando );\n
\t\t\t\t}\n
\n
\t\t\t\tdelete cache[ id ];\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
\n
\n
\n
var ralpha = /alpha\\([^)]*\\)/i,\n
\tropacity = /opacity=([^)]*)/,\n
\t// fixed for IE9, see #8346\n
\trupper = /([A-Z]|^ms)/g,\n
\trnum = /^[\\-+]?(?:\\d*\\.)?\\d+$/i,\n
\trnumnonpx = /^-?(?:\\d*\\.)?\\d+(?!px)[^\\d\\s]+$/i,\n
\trrelNum = /^([\\-+])=([\\-+.\\de]+)/,\n
\trmargin = /^margin/,\n
\n
\tcssShow = { position: "absolute", visibility: "hidden", display: "block" },\n
\n
\t// order is important!\n
\tcssExpand = [ "Top", "Right", "Bottom", "Left" ],\n
\n
\tcurCSS,\n
\n
\tgetComputedStyle,\n
\tcurrentStyle;\n
\n
jQuery.fn.css = function( name, value ) {\n
\treturn jQuery.access( this, function( elem, name, value ) {\n
\t\treturn value !== undefined ?\n
\t\t\tjQuery.style( elem, name, value ) :\n
\t\t\tjQuery.css( elem, name );\n
\t}, name, value, arguments.length > 1 );\n
};\n
\n
jQuery.extend({\n
\t// Add in style property hooks for overriding the default\n
\t// behavior of getting and setting a style property\n
\tcssHooks: {\n
\t\topacity: {\n
\t\t\tget: function( elem, computed ) {\n
\t\t\t\tif ( computed ) {\n
\t\t\t\t\t// We should always get a number back from opacity\n
\t\t\t\t\tvar ret = curCSS( elem, "opacity" );\n
\t\t\t\t\treturn ret === "" ? "1" : ret;\n
\n
\t\t\t\t} else {\n
\t\t\t\t\treturn elem.style.opacity;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// Exclude the following css properties to add px\n
\tcssNumber: {\n
\t\t"fillOpacity": true,\n
\t\t"fontWeight": true,\n
\t\t"lineHeight": true,\n
\t\t"opacity": true,\n
\t\t"orphans": true,\n
\t\t"widows": true,\n
\t\t"zIndex": true,\n
\t\t"zoom": true\n
\t},\n
\n
\t// Add in properties whose names you wish to fix before\n
\t// setting or getting the value\n
\tcssProps: {\n
\t\t// normalize float css property\n
\t\t"float": jQuery.support.cssFloat ? "cssFloat" : "styleFloat"\n
\t},\n
\n
\t// Get and set the style property on a DOM Node\n
\tstyle: function( elem, name, value, extra ) {\n
\t\t// Don\'t set styles on text and comment nodes\n
\t\tif ( !elem || elem.nodeType === 3 || elem.nodeType === 8 || !elem.style ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Make sure that we\'re working with the right name\n
\t\tvar ret, type, origName = jQuery.camelCase( name ),\n
\t\t\tstyle = elem.style, hooks = jQuery.cssHooks[ origName ];\n
\n
\t\tname = jQuery.cssProps[ origName ] || origName;\n
\n
\t\t// Check if we\'re setting a value\n
\t\tif ( value !== undefined ) {\n
\t\t\ttype = typeof value;\n
\n
\t\t\t// convert relative number strings (+= or -=) to relative numbers. #7345\n
\t\t\tif ( type === "string" && (ret = rrelNum.exec( value )) ) {\n
\t\t\t\tvalue = ( +( ret[1] + 1) * +ret[2] ) + parseFloat( jQuery.css( elem, name ) );\n
\t\t\t\t// Fixes bug #9237\n
\t\t\t\ttype = "number";\n
\t\t\t}\n
\n
\t\t\t// Make sure that NaN and null values aren\'t set. See: #7116\n
\t\t\tif ( value == null || type === "number" && isNaN( value ) ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// If a number was passed in, add \'px\' to the (except for certain CSS properties)\n
\t\t\tif ( type === "number" && !jQuery.cssNumber[ origName ] ) {\n
\t\t\t\tvalue += "px";\n
\t\t\t}\n
\n
\t\t\t// If a hook was provided, use that value, otherwise just set the specified value\n
\t\t\tif ( !hooks || !("set" in hooks) || (value = hooks.set( elem, value )) !== undefined ) {\n
\t\t\t\t// Wrapped to prevent IE from throwing errors when \'invalid\' values are provided\n
\t\t\t\t// Fixes bug #5509\n
\t\t\t\ttry {\n
\t\t\t\t\tstyle[ name ] = value;\n
\t\t\t\t} catch(e) {}\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\t// If a hook was provided get the non-computed value from there\n
\t\t\tif ( hooks && "get" in hooks && (ret = hooks.get( elem, false, extra )) !== undefined ) {\n
\t\t\t\treturn ret;\n
\t\t\t}\n
\n
\t\t\t// Otherwise just get the value from the style object\n
\t\t\treturn style[ name ];\n
\t\t}\n
\t},\n
\n
\tcss: function( elem, name, extra ) {\n
\t\tvar ret, hooks;\n
\n
\t\t// Make sure that we\'re working with the right name\n
\t\tname = jQuery.camelCase( name );\n
\t\thooks = jQuery.cssHooks[ name ];\n
\t\tname = jQuery.cssProps[ name ] || name;\n
\n
\t\t// cssFloat needs a special treatment\n
\t\tif ( name === "cssFloat" ) {\n
\t\t\tname = "float";\n
\t\t}\n
\n
\t\t// If a hook was provided get the computed value from there\n
\t\tif ( hooks && "get" in hooks && (ret = hooks.get( elem, true, extra )) !== undefined ) {\n
\t\t\treturn ret;\n
\n
\t\t// Otherwise, if a way to get the computed value exists, use that\n
\t\t} else if ( curCSS ) {\n
\t\t\treturn curCSS( elem, name );\n
\t\t}\n
\t},\n
\n
\t// A method for quickly swapping in/out CSS properties to get correct calculations\n
\tswap: function( elem, options, callback ) {\n
\t\tvar old = {},\n
\t\t\tret, name;\n
\n
\t\t// Remember the old values, and insert the new ones\n
\t\tfor ( name in options ) {\n
\t\t\told[ name ] = elem.style[ name ];\n
\t\t\telem.style[ name ] = options[ name ];\n
\t\t}\n
\n
\t\tret = callback.call( elem );\n
\n
\t\t// Revert the old values\n
\t\tfor ( name in options ) {\n
\t\t\telem.style[ name ] = old[ name ];\n
\t\t}\n
\n
\t\treturn ret;\n
\t}\n
});\n
\n
// DEPRECATED in 1.3, Use jQuery.css() instead\n
jQuery.curCSS = jQuery.css;\n
\n
if ( document.defaultView && document.defaultView.getComputedStyle ) {\n
\tgetComputedStyle = function( elem, name ) {\n
\t\tvar ret, defaultView, computedStyle, width,\n
\t\t\tstyle = elem.style;\n
\n
\t\tname = name.replace( rupper, "-$1" ).toLowerCase();\n
\n
\t\tif ( (defaultView = elem.ownerDocument.defaultView) &&\n
\t\t\t\t(computedStyle = defaultView.getComputedStyle( elem, null )) ) {\n
\n
\t\t\tret = computedStyle.getPropertyValue( name );\n
\t\t\tif ( ret === "" && !jQuery.contains( elem.ownerDocument.documentElement, elem ) ) {\n
\t\t\t\tret = jQuery.style( elem, name );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// A tribute to the "awesome hack by Dean Edwards"\n
\t\t// WebKit uses "computed value (percentage if specified)" instead of "used value" for margins\n
\t\t// which is against the CSSOM draft spec: http://dev.w3.org/csswg/cssom/#resolved-values\n
\t\tif ( !jQuery.support.pixelMargin && computedStyle && rmargin.test( name ) && rnumnonpx.test( ret ) ) {\n
\t\t\twidth = style.width;\n
\t\t\tstyle.width = ret;\n
\t\t\tret = computedStyle.width;\n
\t\t\tstyle.width = width;\n
\t\t}\n
\n
\t\treturn ret;\n
\t};\n
}\n
\n
if ( document.documentElement.currentStyle ) {\n
\tcurrentStyle = function( elem, name ) {\n
\t\tvar left, rsLeft, uncomputed,\n
\t\t\tret = elem.currentStyle && elem.currentStyle[ name ],\n
\t\t\tstyle = elem.style;\n
\n
\t\t// Avoid setting ret to empty string here\n
\t\t// so we don\'t default to auto\n
\t\tif ( ret == null && style && (uncomputed = style[ name ]) ) {\n
\t\t\tret = uncomputed;\n
\t\t}\n
\n
\t\t// From the awesome hack by Dean Edwards\n
\t\t// http://erik.eae.net/archives/2007/07/27/18.54.15/#comment-102291\n
\n
\t\t// If we\'re not dealing with a regular pixel number\n
\t\t// but a number that has a weird ending, we need to convert it to pixels\n
\t\tif ( rnumnonpx.test( ret ) ) {\n
\n
\t\t\t// Remember the original values\n
\t\t\tleft = style.left;\n
\t\t\trsLeft = elem.runtimeStyle && elem.runtimeStyle.left;\n
\n
\t\t\t// Put in the new values to get a computed value out\n
\t\t\tif ( rsLeft ) {\n
\t\t\t\telem.runtimeStyle.left = elem.currentStyle.left;\n
\t\t\t}\n
\t\t\tstyle.left = name === "fontSize" ? "1em" : ret;\n
\t\t\tret = style.pixelLeft + "px";\n
\n
\t\t\t// Revert the changed values\n
\t\t\tstyle.left = left;\n
\t\t\tif ( rsLeft ) {\n
\t\t\t\telem.runtimeStyle.left = rsLeft;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret === "" ? "auto" : ret;\n
\t};\n
}\n
\n
curCSS = getComputedStyle || currentStyle;\n
\n
function getWidthOrHeight( elem, name, extra ) {\n
\n
\t// Start with offset property\n
\tvar val = name === "width" ? elem.offsetWidth : elem.offsetHeight,\n
\t\ti = name === "width" ? 1 : 0,\n
\t\tlen = 4;\n
\n
\tif ( val > 0 ) {\n
\t\tif ( extra !== "border" ) {\n
\t\t\tfor ( ; i < len; i += 2 ) {\n
\t\t\t\tif ( !extra ) {\n
\t\t\t\t\tval -= parseFloat( jQuery.css( elem, "padding" + cssExpand[ i ] ) ) || 0;\n
\t\t\t\t}\n
\t\t\t\tif ( extra === "margin" ) {\n
\t\t\t\t\tval += parseFloat( jQuery.css( elem, extra + cssExpand[ i ] ) ) || 0;\n
\t\t\t\t} else {\n
\t\t\t\t\tval -= parseFloat( jQuery.css( elem, "border" + cssExpand[ i ] + "Width" ) ) || 0;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn val + "px";\n
\t}\n
\n
\t// Fall back to computed then uncomputed css if necessary\n
\tval = curCSS( elem, name );\n
\tif ( val < 0 || val == null ) {\n
\t\tval = elem.style[ name ];\n
\t}\n
\n
\t// Computed unit is not pixels. Stop here and return.\n
\tif ( rnumnonpx.test(val) ) {\n
\t\treturn val;\n
\t}\n
\n
\t// Normalize "", auto, and prepare for extra\n
\tval = parseFloat( val ) || 0;\n
\n
\t// Add padding, border, margin\n
\tif ( extra ) {\n
\t\tfor ( ; i < len; i += 2 ) {\n
\t\t\tval += parseFloat( jQuery.css( elem, "padding" + cssExpand[ i ] ) ) || 0;\n
\t\t\tif ( extra !== "padding" ) {\n
\t\t\t\tval += parseFloat( jQuery.css( elem, "border" + cssExpand[ i ] + "Width" ) ) || 0;\n
\t\t\t}\n
\t\t\tif ( extra === "margin" ) {\n
\t\t\t\tval += parseFloat( jQuery.css( elem, extra + cssExpand[ i ]) ) || 0;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn val + "px";\n
}\n
\n
jQuery.each([ "height", "width" ], function( i, name ) {\n
\tjQuery.cssHooks[ name ] = {\n
\t\tget: function( elem, computed, extra ) {\n
\t\t\tif ( computed ) {\n
\t\t\t\tif ( elem.offsetWidth !== 0 ) {\n
\t\t\t\t\treturn getWidthOrHeight( elem, name, extra );\n
\t\t\t\t} else {\n
\t\t\t\t\treturn jQuery.swap( elem, cssShow, function() {\n
\t\t\t\t\t\treturn getWidthOrHeight( elem, name, extra );\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\tset: function( elem, value ) {\n
\t\t\treturn rnum.test( value ) ?\n
\t\t\t\tvalue + "px" :\n
\t\t\t\tvalue;\n
\t\t}\n
\t};\n
});\n
\n
if ( !jQuery.support.opacity ) {\n
\tjQuery.cssHooks.opacity = {\n
\t\tget: function( elem, computed ) {\n
\t\t\t// IE uses filters for opacity\n
\t\t\treturn ropacity.test( (computed && elem.currentStyle ? elem.currentStyle.filter : elem.style.filter) || "" ) ?\n
\t\t\t\t( parseFloat( RegExp.$1 ) / 100 ) + "" :\n
\t\t\t\tcomputed ? "1" : "";\n
\t\t},\n
\n
\t\tset: function( elem, value ) {\n
\t\t\tvar style = elem.style,\n
\t\t\t\tcurrentStyle = elem.currentStyle,\n
\t\t\t\topacity = jQuery.isNumeric( value ) ? "alpha(opacity=" + value * 100 + ")" : "",\n
\t\t\t\tfilter = currentStyle && currentStyle.filter || style.filter || "";\n
\n
\t\t\t// IE has trouble with opacity if it does not have layout\n
\t\t\t// Force it by setting the zoom level\n
\t\t\tstyle.zoom = 1;\n
\n
\t\t\t// if setting opacity to 1, and no other filters exist - attempt to remove filter attribute #6652\n
\t\t\tif ( value >= 1 && jQuery.trim( filter.replace( ralpha, "" ) ) === "" ) {\n
\n
\t\t\t\t// Setting style.filter to null, "" & " " still leave "filter:" in the cssText\n
\t\t\t\t// if "filter:" is present at all, clearType is disabled, we want to avoid this\n
\t\t\t\t// style.removeAttribute is IE Only, but so apparently is this code path...\n
\t\t\t\tstyle.removeAttribute( "filter" );\n
\n
\t\t\t\t// if there there is no filter style applied in a css rule, we are done\n
\t\t\t\tif ( currentStyle && !currentStyle.filter ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// otherwise, set new filter values\n
\t\t\tstyle.filter = ralpha.test( filter ) ?\n
\t\t\t\tfilter.replace( ralpha, opacity ) :\n
\t\t\t\tfilter + " " + opacity;\n
\t\t}\n
\t};\n
}\n
\n
jQuery(function() {\n
\t// This hook cannot be added until DOM ready because the support test\n
\t// for it is not run until after DOM ready\n
\tif ( !jQuery.support.reliableMarginRight ) {\n
\t\tjQuery.cssHooks.marginRight = {\n
\t\t\tget: function( elem, computed ) {\n
\t\t\t\t// WebKit Bug 13343 - getComputedStyle returns wrong value for margin-right\n
\t\t\t\t// Work around by temporarily setting element display to inline-block\n
\t\t\t\treturn jQuery.swap( elem, { "display": "inline-block" }, function() {\n
\t\t\t\t\tif ( computed ) {\n
\t\t\t\t\t\treturn curCSS( elem, "margin-right" );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn elem.style.marginRight;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t};\n
\t}\n
});\n
\n
if ( jQuery.expr && jQuery.expr.filters ) {\n
\tjQuery.expr.filters.hidden = function( elem ) {\n
\t\tvar width = elem.offsetWidth,\n
\t\t\theight = elem.offsetHeight;\n
\n
\t\treturn ( width === 0 && height === 0 ) || (!jQuery.support.reliableHiddenOffsets && ((elem.style && elem.style.display) || jQuery.css( elem, "display" )) === "none");\n
\t};\n
\n
\tjQuery.expr.filters.visible = function( elem ) {\n
\t\treturn !jQuery.expr.filters.hidden( elem );\n
\t};\n
}\n
\n
// These hooks are used by animate to expand properties\n
jQuery.each({\n
\tmargin: "",\n
\tpadding: "",\n
\tborder: "Width"\n
}, function( prefix, suffix ) {\n
\n
\tjQuery.cssHooks[ prefix + suffix ] = {\n
\t\texpand: function( value ) {\n
\t\t\tvar i,\n
\n
\t\t\t\t// assumes a single number if not a string\n
\t\t\t\tparts = typeof value === "string" ? value.split(" ") : [ value ],\n
\t\t\t\texpanded = {};\n
\n
\t\t\tfor ( i = 0; i < 4; i++ ) {\n
\t\t\t\texpanded[ prefix + cssExpand[ i ] + suffix ] =\n
\t\t\t\t\tparts[ i ] || parts[ i - 2 ] || parts[ 0 ];\n
\t\t\t}\n
\n
\t\t\treturn expanded;\n
\t\t}\n
\t};\n
});\n
\n
\n
\n
\n
var r20 = /%20/g,\n
\trbracket = /\\[\\]$/,\n
\trCRLF = /\\r?\\n/g,\n
\trhash = /#.*$/,\n
\trheaders = /^(.*?):[ \\t]*([^\\r\\n]*)\\r?$/mg, // IE leaves an \\r character at EOL\n
\trinput = /^(?:color|date|datetime|datetime-local|email|hidden|month|number|password|range|search|tel|text|time|url|week)$/i,\n
\t// #7653, #8125, #8152: local protocol detection\n
\trlocalProtocol = /^(?:about|app|app\\-storage|.+\\-extension|file|res|widget):$/,\n
\trnoContent = /^(?:GET|HEAD)$/,\n
\trprotocol = /^\\/\\//,\n
\trquery = /\\?/,\n
\trscript = /<script\\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi,\n
\trselectTextarea = /^(?:select|textarea)/i,\n
\trspacesAjax = /\\s+/,\n
\trts = /([?&])_=[^&]*/,\n
\trurl = /^([\\w\\+\\.\\-]+:)(?:\\/\\/([^\\/?#:]*)(?

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

::(\\d+))?)?/,\n
\n
\t// Keep a copy of the old load method\n
\t_load = jQuery.fn.load,\n
\n
\t/* Prefilters\n
\t * 1) They are useful to introduce custom dataTypes (see ajax/jsonp.js for an example)\n
\t * 2) These are called:\n
\t *    - BEFORE asking for a transport\n
\t *    - AFTER param serialization (s.data is a string if s.processData is true)\n
\t * 3) key is the dataType\n
\t * 4) the catchall symbol "*" can be used\n
\t * 5) execution will start with transport dataType and THEN continue down to "*" if needed\n
\t */\n
\tprefilters = {},\n
\n
\t/* Transports bindings\n
\t * 1) key is the dataType\n
\t * 2) the catchall symbol "*" can be used\n
\t * 3) selection will start with transport dataType and THEN go to "*" if needed\n
\t */\n
\ttransports = {},\n
\n
\t// Document location\n
\tajaxLocation,\n
\n
\t// Document location segments\n
\tajaxLocParts,\n
\n
\t// Avoid comment-prolog char sequence (#10098); must appease lint and evade compression\n
\tallTypes = ["*/"] + ["*"];\n
\n
// #8138, IE may throw an exception when accessing\n
// a field from window.location if document.domain has been set\n
try {\n
\tajaxLocation = location.href;\n
} catch( e ) {\n
\t// Use the href attribute of an A element\n
\t// since IE will modify it given document.location\n
\tajaxLocation = document.createElement( "a" );\n
\tajaxLocation.href = "";\n
\tajaxLocation = ajaxLocation.href;\n
}\n
\n
// Segment location into parts\n
ajaxLocParts = rurl.exec( ajaxLocation.toLowerCase() ) || [];\n
\n
// Base "constructor" for jQuery.ajaxPrefilter and jQuery.ajaxTransport\n
function addToPrefiltersOrTransports( structure ) {\n
\n
\t// dataTypeExpression is optional and defaults to "*"\n
\treturn function( dataTypeExpression, func ) {\n
\n
\t\tif ( typeof dataTypeExpression !== "string" ) {\n
\t\t\tfunc = dataTypeExpression;\n
\t\t\tdataTypeExpression = "*";\n
\t\t}\n
\n
\t\tif ( jQuery.isFunction( func ) ) {\n
\t\t\tvar dataTypes = dataTypeExpression.toLowerCase().split( rspacesAjax ),\n
\t\t\t\ti = 0,\n
\t\t\t\tlength = dataTypes.length,\n
\t\t\t\tdataType,\n
\t\t\t\tlist,\n
\t\t\t\tplaceBefore;\n
\n
\t\t\t// For each dataType in the dataTypeExpression\n
\t\t\tfor ( ; i < length; i++ ) {\n
\t\t\t\tdataType = dataTypes[ i ];\n
\t\t\t\t// We control if we\'re asked to add before\n
\t\t\t\t// any existing element\n
\t\t\t\tplaceBefore = /^\\+/.test( dataType );\n
\t\t\t\tif ( placeBefore ) {\n
\t\t\t\t\tdataType = dataType.substr( 1 ) || "*";\n
\t\t\t\t}\n
\t\t\t\tlist = structure[ dataType ] = structure[ dataType ] || [];\n
\t\t\t\t// then we add to the structure accordingly\n
\t\t\t\tlist[ placeBefore ? "unshift" : "push" ]( func );\n
\t\t\t}\n
\t\t}\n
\t};\n
}\n
\n
// Base inspection function for prefilters and transports\n
function inspectPrefiltersOrTransports( structure, options, originalOptions, jqXHR,\n
\t\tdataType /* internal */, inspected /* internal */ ) {\n
\n
\tdataType = dataType || options.dataTypes[ 0 ];\n
\tinspected = inspected || {};\n
\n
\tinspected[ dataType ] = true;\n
\n
\tvar list = structure[ dataType ],\n
\t\ti = 0,\n
\t\tlength = list ? list.length : 0,\n
\t\texecuteOnly = ( structure === prefilters ),\n
\t\tselection;\n
\n
\tfor ( ; i < length && ( executeOnly || !selection ); i++ ) {\n
\t\tselection = list[ i ]( options, originalOptions, jqXHR );\n
\t\t// If we got redirected to another dataType\n
\t\t// we try there if executing only and not done already\n
\t\tif ( typeof selection === "string" ) {\n
\t\t\tif ( !executeOnly || inspected[ selection ] ) {\n
\t\t\t\tselection = undefined;\n
\t\t\t} else {\n
\t\t\t\toptions.dataTypes.unshift( selection );\n
\t\t\t\tselection = inspectPrefiltersOrTransports(\n
\t\t\t\t\t\tstructure, options, originalOptions, jqXHR, selection, inspected );\n
\t\t\t}\n
\t\t}\n
\t}\n
\t// If we\'re only executing or nothing was selected\n
\t// we try the catchall dataType if not done already\n
\tif ( ( executeOnly || !selection ) && !inspected[ "*" ] ) {\n
\t\tselection = inspectPrefiltersOrTransports(\n
\t\t\t\tstructure, options, originalOptions, jqXHR, "*", inspected );\n
\t}\n
\t// unnecessary when only executing (prefilters)\n
\t// but it\'ll be ignored by the caller in that case\n
\treturn selection;\n
}\n
\n
// A special extend for ajax options\n
// that takes "flat" options (not to be deep extended)\n
// Fixes #9887\n
function ajaxExtend( target, src ) {\n
\tvar key, deep,\n
\t\tflatOptions = jQuery.ajaxSettings.flatOptions || {};\n
\tfor ( key in src ) {\n
\t\tif ( src[ key ] !== undefined ) {\n
\t\t\t( flatOptions[ key ] ? target : ( deep || ( deep = {} ) ) )[ key ] = src[ key ];\n
\t\t}\n
\t}\n
\tif ( deep ) {\n
\t\tjQuery.extend( true, target, deep );\n
\t}\n
}\n
\n
jQuery.fn.extend({\n
\tload: function( url, params, callback ) {\n
\t\tif ( typeof url !== "string" && _load ) {\n
\t\t\treturn _load.apply( this, arguments );\n
\n
\t\t// Don\'t do a request if no elements are being requested\n
\t\t} else if ( !this.length ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tvar off = url.indexOf( " " );\n
\t\tif ( off >= 0 ) {\n
\t\t\tvar selector = url.slice( off, url.length );\n
\t\t\turl = url.slice( 0, off );\n
\t\t}\n
\n
\t\t// Default to a GET request\n
\t\tvar type = "GET";\n
\n
\t\t// If the second parameter was provided\n
\t\tif ( params ) {\n
\t\t\t// If it\'s a function\n
\t\t\tif ( jQuery.isFunction( params ) ) {\n
\t\t\t\t// We assume that it\'s the callback\n
\t\t\t\tcallback = params;\n
\t\t\t\tparams = undefined;\n
\n
\t\t\t// Otherwise, build a param string\n
\t\t\t} else if ( typeof params === "object" ) {\n
\t\t\t\tparams = jQuery.param( params, jQuery.ajaxSettings.traditional );\n
\t\t\t\ttype = "POST";\n
\t\t\t}\n
\t\t}\n
\n
\t\tvar self = this;\n
\n
\t\t// Request the remote document\n
\t\tjQuery.ajax({\n
\t\t\turl: url,\n
\t\t\ttype: type,\n
\t\t\tdataType: "html",\n
\t\t\tdata: params,\n
\t\t\t// Complete callback (responseText is used internally)\n
\t\t\tcomplete: function( jqXHR, status, responseText ) {\n
\t\t\t\t// Store the response as specified by the jqXHR object\n
\t\t\t\tresponseText = jqXHR.responseText;\n
\t\t\t\t// If successful, inject the HTML into all the matched elements\n
\t\t\t\tif ( jqXHR.isResolved() ) {\n
\t\t\t\t\t// #4825: Get the actual response in case\n
\t\t\t\t\t// a dataFilter is present in ajaxSettings\n
\t\t\t\t\tjqXHR.done(function( r ) {\n
\t\t\t\t\t\tresponseText = r;\n
\t\t\t\t\t});\n
\t\t\t\t\t// See if a selector was specified\n
\t\t\t\t\tself.html( selector ?\n
\t\t\t\t\t\t// Create a dummy div to hold the results\n
\t\t\t\t\t\tjQuery("<div>")\n
\t\t\t\t\t\t\t// inject the contents of the document in, removing the scripts\n
\t\t\t\t\t\t\t// to avoid any \'Permission Denied\' errors in IE\n
\t\t\t\t\t\t\t.append(responseText.replace(rscript, ""))\n
\n
\t\t\t\t\t\t\t// Locate the specified elements\n
\t\t\t\t\t\t\t.find(selector) :\n
\n
\t\t\t\t\t\t// If not, just inject the full result\n
\t\t\t\t\t\tresponseText );\n
\t\t\t\t}\n
\n
\t\t\t\tif ( callback ) {\n
\t\t\t\t\tself.each( callback, [ responseText, status, jqXHR ] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\treturn this;\n
\t},\n
\n
\tserialize: function() {\n
\t\treturn jQuery.param( this.serializeArray() );\n
\t},\n
\n
\tserializeArray: function() {\n
\t\treturn this.map(function(){\n
\t\t\treturn this.elements ? jQuery.makeArray( this.elements ) : this;\n
\t\t})\n
\t\t.filter(function(){\n
\t\t\treturn this.name && !this.disabled &&\n
\t\t\t\t( this.checked || rselectTextarea.test( this.nodeName ) ||\n
\t\t\t\t\trinput.test( this.type ) );\n
\t\t})\n
\t\t.map(function( i, elem ){\n
\t\t\tvar val = jQuery( this ).val();\n
\n
\t\t\treturn val == null ?\n
\t\t\t\tnull :\n
\t\t\t\tjQuery.isArray( val ) ?\n
\t\t\t\t\tjQuery.map( val, function( val, i ){\n
\t\t\t\t\t\treturn { name: elem.name, value: val.replace( rCRLF, "\\r\\n" ) };\n
\t\t\t\t\t}) :\n
\t\t\t\t\t{ name: elem.name, value: val.replace( rCRLF, "\\r\\n" ) };\n
\t\t}).get();\n
\t}\n
});\n
\n
// Attach a bunch of functions for handling common AJAX events\n
jQuery.each( "ajaxStart ajaxStop ajaxComplete ajaxError ajaxSuccess ajaxSend".split( " " ), function( i, o ){\n
\tjQuery.fn[ o ] = function( f ){\n
\t\treturn this.on( o, f );\n
\t};\n
});\n
\n
jQuery.each( [ "get", "post" ], function( i, method ) {\n
\tjQuery[ method ] = function( url, data, callback, type ) {\n
\t\t// shift arguments if data argument was omitted\n
\t\tif ( jQuery.isFunction( data ) ) {\n
\t\t\ttype = type || callback;\n
\t\t\tcallback = data;\n
\t\t\tdata = undefined;\n
\t\t}\n
\n
\t\treturn jQuery.ajax({\n
\t\t\ttype: method,\n
\t\t\turl: url,\n
\t\t\tdata: data,\n
\t\t\tsuccess: callback,\n
\t\t\tdataType: type\n
\t\t});\n
\t};\n
});\n
\n
jQuery.extend({\n
\n
\tgetScript: function( url, callback ) {\n
\t\treturn jQuery.get( url, undefined, callback, "script" );\n
\t},\n
\n
\tgetJSON: function( url, data, callback ) {\n
\t\treturn jQuery.get( url, data, callback, "json" );\n
\t},\n
\n
\t// Creates a full fledged settings object into target\n
\t// with both ajaxSettings and settings fields.\n
\t// If target is omitted, writes into ajaxSettings.\n
\tajaxSetup: function( target, settings ) {\n
\t\tif ( settings ) {\n
\t\t\t// Building a settings object\n
\t\t\tajaxExtend( target, jQuery.ajaxSettings );\n
\t\t} else {\n
\t\t\t// Extending ajaxSettings\n
\t\t\tsettings = target;\n
\t\t\ttarget = jQuery.ajaxSettings;\n
\t\t}\n
\t\tajaxExtend( target, settings );\n
\t\treturn target;\n
\t},\n
\n
\tajaxSettings: {\n
\t\turl: ajaxLocation,\n
\t\tisLocal: rlocalProtocol.test( ajaxLocParts[ 1 ] ),\n
\t\tglobal: true,\n
\t\ttype: "GET",\n
\t\tcontentType: "application/x-www-form-urlencoded; charset=UTF-8",\n
\t\tprocessData: true,\n
\t\tasync: true,\n
\t\t/*\n
\t\ttimeout: 0,\n
\t\tdata: null,\n
\t\tdataType: null,\n
\t\tusername: null,\n
\t\tpassword: null,\n
\t\tcache: null,\n
\t\ttraditional: false,\n
\t\theaders: {},\n
\t\t*/\n
\n
\t\taccepts: {\n
\t\t\txml: "application/xml, text/xml",\n
\t\t\thtml: "text/html",\n
\t\t\ttext: "text/plain",\n
\t\t\tjson: "application/json, text/javascript",\n
\t\t\t"*": allTypes\n
\t\t},\n
\n
\t\tcontents: {\n
\t\t\txml: /xml/,\n
\t\t\thtml: /html/,\n
\t\t\tjson: /json/\n
\t\t},\n
\n
\t\tresponseFields: {\n
\t\t\txml: "responseXML",\n
\t\t\ttext: "responseText"\n
\t\t},\n
\n
\t\t// List of data converters\n
\t\t// 1) key format is "source_type destination_type" (a single space in-between)\n
\t\t// 2) the catchall symbol "*" can be used for source_type\n
\t\tconverters: {\n
\n
\t\t\t// Convert anything to text\n
\t\t\t"* text": window.String,\n
\n
\t\t\t// Text to html (true = no transformation)\n
\t\t\t"text html": true,\n
\n
\t\t\t// Evaluate text as a json expression\n
\t\t\t"text json": jQuery.parseJSON,\n
\n
\t\t\t// Parse text as xml\n
\t\t\t"text xml": jQuery.parseXML\n
\t\t},\n
\n
\t\t// For options that shouldn\'t be deep extended:\n
\t\t// you can add your own custom options here if\n
\t\t// and when you create one that shouldn\'t be\n
\t\t// deep extended (see ajaxExtend)\n
\t\tflatOptions: {\n
\t\t\tcontext: true,\n
\t\t\turl: true\n
\t\t}\n
\t},\n
\n
\tajaxPrefilter: addToPrefiltersOrTransports( prefilters ),\n
\tajaxTransport: addToPrefiltersOrTransports( transports ),\n
\n
\t// Main method\n
\tajax: function( url, options ) {\n
\n
\t\t// If url is an object, simulate pre-1.5 signature\n
\t\tif ( typeof url === "object" ) {\n
\t\t\toptions = url;\n
\t\t\turl = undefined;\n
\t\t}\n
\n
\t\t// Force options to be an object\n
\t\toptions = options || {};\n
\n
\t\tvar // Create the final options object\n
\t\t\ts = jQuery.ajaxSetup( {}, options ),\n
\t\t\t// Callbacks context\n
\t\t\tcallbackContext = s.context || s,\n
\t\t\t// Context for global events\n
\t\t\t// It\'s the callbackContext if one was provided in the options\n
\t\t\t// and if it\'s a DOM node or a jQuery collection\n
\t\t\tglobalEventContext = callbackContext !== s &&\n
\t\t\t\t( callbackContext.nodeType || callbackContext instanceof jQuery ) ?\n
\t\t\t\t\t\tjQuery( callbackContext ) : jQuery.event,\n
\t\t\t// Deferreds\n
\t\t\tdeferred = jQuery.Deferred(),\n
\t\t\tcompleteDeferred = jQuery.Callbacks( "once memory" ),\n
\t\t\t// Status-dependent callbacks\n
\t\t\tstatusCode = s.statusCode || {},\n
\t\t\t// ifModified key\n
\t\t\tifModifiedKey,\n
\t\t\t// Headers (they are sent all at once)\n
\t\t\trequestHeaders = {},\n
\t\t\trequestHeadersNames = {},\n
\t\t\t// Response headers\n
\t\t\tresponseHeadersString,\n
\t\t\tresponseHeaders,\n
\t\t\t// transport\n
\t\t\ttransport,\n
\t\t\t// timeout handle\n
\t\t\ttimeoutTimer,\n
\t\t\t// Cross-domain detection vars\n
\t\t\tparts,\n
\t\t\t// The jqXHR state\n
\t\t\tstate = 0,\n
\t\t\t// To know if global events are to be dispatched\n
\t\t\tfireGlobals,\n
\t\t\t// Loop variable\n
\t\t\ti,\n
\t\t\t// Fake xhr\n
\t\t\tjqXHR = {\n
\n
\t\t\t\treadyState: 0,\n
\n
\t\t\t\t// Caches the header\n
\t\t\t\tsetRequestHeader: function( name, value ) {\n
\t\t\t\t\tif ( !state ) {\n
\t\t\t\t\t\tvar lname = name.toLowerCase();\n
\t\t\t\t\t\tname = requestHeadersNames[ lname ] = requestHeadersNames[ lname ] || name;\n
\t\t\t\t\t\trequestHeaders[ name ] = value;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn this;\n
\t\t\t\t},\n
\n
\t\t\t\t// Raw string\n
\t\t\t\tgetAllResponseHeaders: function() {\n
\t\t\t\t\treturn state === 2 ? responseHeadersString : null;\n
\t\t\t\t},\n
\n
\t\t\t\t// Builds headers hashtable if needed\n
\t\t\t\tgetResponseHeader: function( key ) {\n
\t\t\t\t\tvar match;\n
\t\t\t\t\tif ( state === 2 ) {\n
\t\t\t\t\t\tif ( !responseHeaders ) {\n
\t\t\t\t\t\t\tresponseHeaders = {};\n
\t\t\t\t\t\t\twhile( ( match = rheaders.exec( responseHeadersString ) ) ) {\n
\t\t\t\t\t\t\t\tresponseHeaders[ match[1].toLowerCase() ] = match[ 2 ];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tmatch = responseHeaders[ key.toLowerCase() ];\n
\t\t\t\t\t}\n
\t\t\t\t\treturn match === undefined ? null : match;\n
\t\t\t\t},\n
\n
\t\t\t\t// Overrides response content-type header\n
\t\t\t\toverrideMimeType: function( type ) {\n
\t\t\t\t\tif ( !state ) {\n
\t\t\t\t\t\ts.mimeType = type;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn this;\n
\t\t\t\t},\n
\n
\t\t\t\t// Cancel the request\n
\t\t\t\tabort: function( statusText ) {\n
\t\t\t\t\tstatusText = statusText || "abort";\n
\t\t\t\t\tif ( transport ) {\n
\t\t\t\t\t\ttransport.abort( statusText );\n
\t\t\t\t\t}\n
\t\t\t\t\tdone( 0, statusText );\n
\t\t\t\t\treturn this;\n
\t\t\t\t}\n
\t\t\t};\n
\n
\t\t// Callback for when everything is done\n
\t\t// It is defined here because jslint complains if it is declared\n
\t\t// at the end of the function (which would be more logical and readable)\n
\t\tfunction done( status, nativeStatusText, responses, headers ) {\n
\n
\t\t\t// Called once\n
\t\t\tif ( state === 2 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\t// State is "done" now\n
\t\t\tstate = 2;\n
\n
\t\t\t// Clear timeout if it exists\n
\t\t\tif ( timeoutTimer ) {\n
\t\t\t\tclearTimeout( timeoutTimer );\n
\t\t\t}\n
\n
\t\t\t// Dereference transport for early garbage collection\n
\t\t\t// (no matter how long the jqXHR object will be used)\n
\t\t\ttransport = undefined;\n
\n
\t\t\t// Cache response headers\n
\t\t\tresponseHeadersString = headers || "";\n
\n
\t\t\t// Set readyState\n
\t\t\tjqXHR.readyState = status > 0 ? 4 : 0;\n
\n
\t\t\tvar isSuccess,\n
\t\t\t\tsuccess,\n
\t\t\t\terror,\n
\t\t\t\tstatusText = nativeStatusText,\n
\t\t\t\tresponse = responses ? ajaxHandleResponses( s, jqXHR, responses ) : undefined,\n
\t\t\t\tlastModified,\n
\t\t\t\tetag;\n
\n
\t\t\t// If successful, handle type chaining\n
\t\t\tif ( status >= 200 && status < 300 || status === 304 ) {\n
\n
\t\t\t\t// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.\n
\t\t\t\tif ( s.ifModified ) {\n
\n
\t\t\t\t\tif ( ( lastModified = jqXHR.getResponseHeader( "Last-Modified" ) ) ) {\n
\t\t\t\t\t\tjQuery.lastModified[ ifModifiedKey ] = lastModified;\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( ( etag = jqXHR.getResponseHeader( "Etag" ) ) ) {\n
\t\t\t\t\t\tjQuery.etag[ ifModifiedKey ] = etag;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// If not modified\n
\t\t\t\tif ( status === 304 ) {\n
\n
\t\t\t\t\tstatusText = "notmodified";\n
\t\t\t\t\tisSuccess = true;\n
\n
\t\t\t\t// If we have data\n
\t\t\t\t} else {\n
\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\tsuccess = ajaxConvert( s, response );\n
\t\t\t\t\t\tstatusText = "success";\n
\t\t\t\t\t\tisSuccess = true;\n
\t\t\t\t\t} catch(e) {\n
\t\t\t\t\t\t// We have a parsererror\n
\t\t\t\t\t\tstatusText = "parsererror";\n
\t\t\t\t\t\terror = e;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\t// We extract error from statusText\n
\t\t\t\t// then normalize statusText and status for non-aborts\n
\t\t\t\terror = statusText;\n
\t\t\t\tif ( !statusText || status ) {\n
\t\t\t\t\tstatusText = "error";\n
\t\t\t\t\tif ( status < 0 ) {\n
\t\t\t\t\t\tstatus = 0;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set data for the fake xhr object\n
\t\t\tjqXHR.status = status;\n
\t\t\tjqXHR.statusText = "" + ( nativeStatusText || statusText );\n
\n
\t\t\t// Success/Error\n
\t\t\tif ( isSuccess ) {\n
\t\t\t\tdeferred.resolveWith( callbackContext, [ success, statusText, jqXHR ] );\n
\t\t\t} else {\n
\t\t\t\tdeferred.rejectWith( callbackContext, [ jqXHR, statusText, error ] );\n
\t\t\t}\n
\n
\t\t\t// Status-dependent callbacks\n
\t\t\tjqXHR.statusCode( statusCode );\n
\t\t\tstatusCode = undefined;\n
\n
\t\t\tif ( fireGlobals ) {\n
\t\t\t\tglobalEventContext.trigger( "ajax" + ( isSuccess ? "Success" : "Error" ),\n
\t\t\t\t\t\t[ jqXHR, s, isSuccess ? success : error ] );\n
\t\t\t}\n
\n
\t\t\t// Complete\n
\t\t\tcompleteDeferred.fireWith( callbackContext, [ jqXHR, statusText ] );\n
\n
\t\t\tif ( fireGlobals ) {\n
\t\t\t\tglobalEventContext.trigger( "ajaxComplete", [ jqXHR, s ] );\n
\t\t\t\t// Handle the global AJAX counter\n
\t\t\t\tif ( !( --jQuery.active ) ) {\n
\t\t\t\t\tjQuery.event.trigger( "ajaxStop" );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Attach deferreds\n
\t\tdeferred.promise( jqXHR );\n
\t\tjqXHR.success = jqXHR.done;\n
\t\tjqXHR.error = jqXHR.fail;\n
\t\tjqXHR.complete = completeDeferred.add;\n
\n
\t\t// Status-dependent callbacks\n
\t\tjqXHR.statusCode = function( map ) {\n
\t\t\tif ( map ) {\n
\t\t\t\tvar tmp;\n
\t\t\t\tif ( state < 2 ) {\n
\t\t\t\t\tfor ( tmp in map ) {\n
\t\t\t\t\t\tstatusCode[ tmp ] = [ statusCode[tmp], map[tmp] ];\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\ttmp = map[ jqXHR.status ];\n
\t\t\t\t\tjqXHR.then( tmp, tmp );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t};\n
\n
\t\t// Remove hash character (#7531: and string promotion)\n
\t\t// Add protocol if not provided (#5866: IE7 issue with protocol-less urls)\n
\t\t// We also use the url parameter if available\n
\t\ts.url = ( ( url || s.url ) + "" ).replace( rhash, "" ).replace( rprotocol, ajaxLocParts[ 1 ] + "//" );\n
\n
\t\t// Extract dataTypes list\n
\t\ts.dataTypes = jQuery.trim( s.dataType || "*" ).toLowerCase().split( rspacesAjax );\n
\n
\t\t// Determine if a cross-domain request is in order\n
\t\tif ( s.crossDomain == null ) {\n
\t\t\tparts = rurl.exec( s.url.toLowerCase() );\n
\t\t\ts.crossDomain = !!( parts &&\n
\t\t\t\t( parts[ 1 ] != ajaxLocParts[ 1 ] || parts[ 2 ] != ajaxLocParts[ 2 ] ||\n
\t\t\t\t\t( parts[ 3 ] || ( parts[ 1 ] === "http:" ? 80 : 443 ) ) !=\n
\t\t\t\t\t\t( ajaxLocParts[ 3 ] || ( ajaxLocParts[ 1 ] === "http:" ? 80 : 443 ) ) )\n
\t\t\t);\n
\t\t}\n
\n
\t\t// Convert data if not already a string\n
\t\tif ( s.data && s.processData && typeof s.data !== "string" ) {\n
\t\t\ts.data = jQuery.param( s.data, s.traditional );\n
\t\t}\n
\n
\t\t// Apply prefilters\n
\t\tinspectPrefiltersOrTransports( prefilters, s, options, jqXHR );\n
\n
\t\t// If request was aborted inside a prefilter, stop there\n
\t\tif ( state === 2 ) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t// We can fire global events as of now if asked to\n
\t\tfireGlobals = s.global;\n
\n
\t\t// Uppercase the type\n
\t\ts.type = s.type.toUpperCase();\n
\n
\t\t// Determine if request has content\n
\t\ts.hasContent = !rnoContent.test( s.type );\n
\n
\t\t// Watch for a new set of requests\n
\t\tif ( fireGlobals && jQuery.active++ === 0 ) {\n
\t\t\tjQuery.event.trigger( "ajaxStart" );\n
\t\t}\n
\n
\t\t// More options handling for requests with no content\n
\t\tif ( !s.hasContent ) {\n
\n
\t\t\t// If data is available, append data to url\n
\t\t\tif ( s.data ) {\n
\t\t\t\ts.url += ( rquery.test( s.url ) ? "&" : "?" ) + s.data;\n
\t\t\t\t// #9682: remove data so that it\'s not used in an eventual retry\n
\t\t\t\tdelete s.data;\n
\t\t\t}\n
\n
\t\t\t// Get ifModifiedKey before adding the anti-cache parameter\n
\t\t\tifModifiedKey = s.url;\n
\n
\t\t\t// Add anti-cache in url if needed\n
\t\t\tif ( s.cache === false ) {\n
\n
\t\t\t\tvar ts = jQuery.now(),\n
\t\t\t\t\t// try replacing _= if it is there\n
\t\t\t\t\tret = s.url.replace( rts, "$1_=" + ts );\n
\n
\t\t\t\t// if nothing was replaced, add timestamp to the end\n
\t\t\t\ts.url = ret + ( ( ret === s.url ) ? ( rquery.test( s.url ) ? "&" : "?" ) + "_=" + ts : "" );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Set the correct header, if data is being sent\n
\t\tif ( s.data && s.hasContent && s.contentType !== false || options.contentType ) {\n
\t\t\tjqXHR.setRequestHeader( "Content-Type", s.contentType );\n
\t\t}\n
\n
\t\t// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.\n
\t\tif ( s.ifModified ) {\n
\t\t\tifModifiedKey = ifModifiedKey || s.url;\n
\t\t\tif ( jQuery.lastModified[ ifModifiedKey ] ) {\n
\t\t\t\tjqXHR.setRequestHeader( "If-Modified-Since", jQuery.lastModified[ ifModifiedKey ] );\n
\t\t\t}\n
\t\t\tif ( jQuery.etag[ ifModifiedKey ] ) {\n
\t\t\t\tjqXHR.setRequestHeader( "If-None-Match", jQuery.etag[ ifModifiedKey ] );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Set the Accepts header for the server, depending on the dataType\n
\t\tjqXHR.setRequestHeader(\n
\t\t\t"Accept",\n
\t\t\ts.dataTypes[ 0 ] && s.accepts[ s.dataTypes[0] ] ?\n
\t\t\t\ts.accepts[ s.dataTypes[0] ] + ( s.dataTypes[ 0 ] !== "*" ? ", " + allTypes + "; q=0.01" : "" ) :\n
\t\t\t\ts.accepts[ "*" ]\n
\t\t);\n
\n
\t\t// Check for headers option\n
\t\tfor ( i in s.headers ) {\n
\t\t\tjqXHR.setRequestHeader( i, s.headers[ i ] );\n
\t\t}\n
\n
\t\t// Allow custom headers/mimetypes and early abort\n
\t\tif ( s.beforeSend && ( s.beforeSend.call( callbackContext, jqXHR, s ) === false || state === 2 ) ) {\n
\t\t\t\t// Abort if not done already\n
\t\t\t\tjqXHR.abort();\n
\t\t\t\treturn false;\n
\n
\t\t}\n
\n
\t\t// Install callbacks on deferreds\n
\t\tfor ( i in { success: 1, error: 1, complete: 1 } ) {\n
\t\t\tjqXHR[ i ]( s[ i ] );\n
\t\t}\n
\n
\t\t// Get transport\n
\t\ttransport = inspectPrefiltersOrTransports( transports, s, options, jqXHR );\n
\n
\t\t// If no transport, we auto-abort\n
\t\tif ( !transport ) {\n
\t\t\tdone( -1, "No Transport" );\n
\t\t} else {\n
\t\t\tjqXHR.readyState = 1;\n
\t\t\t// Send global event\n
\t\t\tif ( fireGlobals ) {\n
\t\t\t\tglobalEventContext.trigger( "ajaxSend", [ jqXHR, s ] );\n
\t\t\t}\n
\t\t\t// Timeout\n
\t\t\tif ( s.async && s.timeout > 0 ) {\n
\t\t\t\ttimeoutTimer = setTimeout( function(){\n
\t\t\t\t\tjqXHR.abort( "timeout" );\n
\t\t\t\t}, s.timeout );\n
\t\t\t}\n
\n
\t\t\ttry {\n
\t\t\t\tstate = 1;\n
\t\t\t\ttransport.send( requestHeaders, done );\n
\t\t\t} catch (e) {\n
\t\t\t\t// Propagate exception as error if not done\n
\t\t\t\tif ( state < 2 ) {\n
\t\t\t\t\tdone( -1, e );\n
\t\t\t\t// Simply rethrow otherwise\n
\t\t\t\t} else {\n
\t\t\t\t\tthrow e;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn jqXHR;\n
\t},\n
\n
\t// Serialize an array of form elements or a set of\n
\t// key/values into a query string\n
\tparam: function( a, traditional ) {\n
\t\tvar s = [],\n
\t\t\tadd = function( key, value ) {\n
\t\t\t\t// If value is a function, invoke it and return its value\n
\t\t\t\tvalue = jQuery.isFunction( value ) ? value() : value;\n
\t\t\t\ts[ s.length ] = encodeURIComponent( key ) + "=" + encodeURIComponent( value );\n
\t\t\t};\n
\n
\t\t// Set traditional to true for jQuery <= 1.3.2 behavior.\n
\t\tif ( traditional === undefined ) {\n
\t\t\ttraditional = jQuery.ajaxSettings.traditional;\n
\t\t}\n
\n
\t\t// If an array was passed in, assume that it is an array of form elements.\n
\t\tif ( jQuery.isArray( a ) || ( a.jquery && !jQuery.isPlainObject( a ) ) ) {\n
\t\t\t// Serialize the form elements\n
\t\t\tjQuery.each( a, function() {\n
\t\t\t\tadd( this.name, this.value );\n
\t\t\t});\n
\n
\t\t} else {\n
\t\t\t// If traditional, encode the "old" way (the way 1.3.2 or older\n
\t\t\t// did it), otherwise encode params recursively.\n
\t\t\tfor ( var prefix in a ) {\n
\t\t\t\tbuildParams( prefix, a[ prefix ], traditional, add );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Return the resulting serialization\n
\t\treturn s.join( "&" ).replace( r20, "+" );\n
\t}\n
});\n
\n
function buildParams( prefix, obj, traditional, add ) {\n
\tif ( jQuery.isArray( obj ) ) {\n
\t\t// Serialize array item.\n
\t\tjQuery.each( obj, function( i, v ) {\n
\t\t\tif ( traditional || rbracket.test( prefix ) ) {\n
\t\t\t\t// Treat each array item as a scalar.\n
\t\t\t\tadd( prefix, v );\n
\n
\t\t\t} else {\n
\t\t\t\t// If array item is non-scalar (array or object), encode its\n
\t\t\t\t// numeric index to resolve deserialization ambiguity issues.\n
\t\t\t\t// Note that rack (as of 1.0.0) can\'t currently deserialize\n
\t\t\t\t// nested arrays properly, and attempting to do so may cause\n
\t\t\t\t// a server error. Possible fixes are to modify rack\'s\n
\t\t\t\t// deserialization algorithm or to provide an option or flag\n
\t\t\t\t// to force array serialization to be shallow.\n
\t\t\t\tbuildParams( prefix + "[" + ( typeof v === "object" ? i : "" ) + "]", v, traditional, add );\n
\t\t\t}\n
\t\t});\n
\n
\t} else if ( !traditional && jQuery.type( obj ) === "object" ) {\n
\t\t// Serialize object item.\n
\t\tfor ( var name in obj ) {\n
\t\t\tbuildParams( prefix + "[" + name + "]", obj[ name ], traditional, add );\n
\t\t}\n
\n
\t} else {\n
\t\t// Serialize scalar item.\n
\t\tadd( prefix, obj );\n
\t}\n
}\n
\n
// This is still on the jQuery object... for now\n
// Want to move this to jQuery.ajax some day\n
jQuery.extend({\n
\n
\t// Counter for holding the number of active queries\n
\tactive: 0,\n
\n
\t// Last-Modified header cache for next request\n
\tlastModified: {},\n
\tetag: {}\n
\n
});\n
\n
/* Handles responses to an ajax request:\n
 * - sets all responseXXX fields accordingly\n
 * - finds the right dataType (mediates between content-type and expected dataType)\n
 * - returns the corresponding response\n
 */\n
function ajaxHandleResponses( s, jqXHR, responses ) {\n
\n
\tvar contents = s.contents,\n
\t\tdataTypes = s.dataTypes,\n
\t\tresponseFields = s.responseFields,\n
\t\tct,\n
\t\ttype,\n
\t\tfinalDataType,\n
\t\tfirstDataType;\n
\n
\t// Fill responseXXX fields\n
\tfor ( type in responseFields ) {\n
\t\tif ( type in responses ) {\n
\t\t\tjqXHR[ responseFields[type] ] = responses[ type ];\n
\t\t}\n
\t}\n
\n
\t// Remove auto dataType and get content-type in the process\n
\twhile( dataTypes[ 0 ] === "*" ) {\n
\t\tdataTypes.shift();\n
\t\tif ( ct === undefined ) {\n
\t\t\tct = s.mimeType || jqXHR.getResponseHeader( "content-type" );\n
\t\t}\n
\t}\n
\n
\t// Check if we\'re dealing with a known content-type\n
\tif ( ct ) {\n
\t\tfor ( type in contents ) {\n
\t\t\tif ( contents[ type ] && contents[ type ].test( ct ) ) {\n
\t\t\t\tdataTypes.unshift( type );\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\t// Check to see if we have a response for the expected dataType\n
\tif ( dataTypes[ 0 ] in responses ) {\n
\t\tfinalDataType = dataTypes[ 0 ];\n
\t} else {\n
\t\t// Try convertible dataTypes\n
\t\tfor ( type in responses ) {\n
\t\t\tif ( !dataTypes[ 0 ] || s.converters[ type + " " + dataTypes[0] ] ) {\n
\t\t\t\tfinalDataType = type;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tif ( !firstDataType ) {\n
\t\t\t\tfirstDataType = type;\n
\t\t\t}\n
\t\t}\n
\t\t// Or just use first one\n
\t\tfinalDataType = finalDataType || firstDataType;\n
\t}\n
\n
\t// If we found a dataType\n
\t// We add the dataType to the list if needed\n
\t// and return the corresponding response\n
\tif ( finalDataType ) {\n
\t\tif ( finalDataType !== dataTypes[ 0 ] ) {\n
\t\t\tdataTypes.unshift( finalDataType );\n
\t\t}\n
\t\treturn responses[ finalDataType ];\n
\t}\n
}\n
\n
// Chain conversions given the request and the original response\n
function ajaxConvert( s, response ) {\n
\n
\t// Apply the dataFilter if provided\n
\tif ( s.dataFilter ) {\n
\t\tresponse = s.dataFilter( response, s.dataType );\n
\t}\n
\n
\tvar dataTypes = s.dataTypes,\n
\t\tconverters = {},\n
\t\ti,\n
\t\tkey,\n
\t\tlength = dataTypes.length,\n
\t\ttmp,\n
\t\t// Current and previous dataTypes\n
\t\tcurrent = dataTypes[ 0 ],\n
\t\tprev,\n
\t\t// Conversion expression\n
\t\tconversion,\n
\t\t// Conversion function\n
\t\tconv,\n
\t\t// Conversion functions (transitive conversion)\n
\t\tconv1,\n
\t\tconv2;\n
\n
\t// For each dataType in the chain\n
\tfor ( i = 1; i < length; i++ ) {\n
\n
\t\t// Create converters map\n
\t\t// with lowercased keys\n
\t\tif ( i === 1 ) {\n
\t\t\tfor ( key in s.converters ) {\n
\t\t\t\tif ( typeof key === "string" ) {\n
\t\t\t\t\tconverters[ key.toLowerCase() ] = s.converters[ key ];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Get the dataTypes\n
\t\tprev = current;\n
\t\tcurrent = dataTypes[ i ];\n
\n
\t\t// If current is auto dataType, update it to prev\n
\t\tif ( current === "*" ) {\n
\t\t\tcurrent = prev;\n
\t\t// If no auto and dataTypes are actually different\n
\t\t} else if ( prev !== "*" && prev !== current ) {\n
\n
\t\t\t// Get the converter\n
\t\t\tconversion = prev + " " + current;\n
\t\t\tconv = converters[ conversion ] || converters[ "* " + current ];\n
\n
\t\t\t// If there is no direct converter, search transitively\n
\t\t\tif ( !conv ) {\n
\t\t\t\tconv2 = undefined;\n
\t\t\t\tfor ( conv1 in converters ) {\n
\t\t\t\t\ttmp = conv1.split( " " );\n
\t\t\t\t\tif ( tmp[ 0 ] === prev || tmp[ 0 ] === "*" ) {\n
\t\t\t\t\t\tconv2 = converters[ tmp[1] + " " + current ];\n
\t\t\t\t\t\tif ( conv2 ) {\n
\t\t\t\t\t\t\tconv1 = converters[ conv1 ];\n
\t\t\t\t\t\t\tif ( conv1 === true ) {\n
\t\t\t\t\t\t\t\tconv = conv2;\n
\t\t\t\t\t\t\t} else if ( conv2 === true ) {\n
\t\t\t\t\t\t\t\tconv = conv1;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// If we found no converter, dispatch an error\n
\t\t\tif ( !( conv || conv2 ) ) {\n
\t\t\t\tjQuery.error( "No conversion from " + conversion.replace(" "," to ") );\n
\t\t\t}\n
\t\t\t// If found converter is not an equivalence\n
\t\t\tif ( conv !== true ) {\n
\t\t\t\t// Convert with 1 or 2 converters accordingly\n
\t\t\t\tresponse = conv ? conv( response ) : conv2( conv1(response) );\n
\t\t\t}\n
\t\t}\n
\t}\n
\treturn response;\n
}\n
\n
\n
\n
\n
var jsc = jQuery.now(),\n
\tjsre = /(\\=)\\?(&|$)|\\?\\?/i;\n
\n
// Default jsonp settings\n
jQuery.ajaxSetup({\n
\tjsonp: "callback",\n
\tjsonpCallback: function() {\n
\t\treturn jQuery.expando + "_" + ( jsc++ );\n
\t}\n
});\n
\n
// Detect, normalize options and install callbacks for jsonp requests\n
jQuery.ajaxPrefilter( "json jsonp", function( s, originalSettings, jqXHR ) {\n
\n
\tvar inspectData = ( typeof s.data === "string" ) && /^application\\/x\\-www\\-form\\-urlencoded/.test( s.contentType );\n
\n
\tif ( s.dataTypes[ 0 ] === "jsonp" ||\n
\t\ts.jsonp !== false && ( jsre.test( s.url ) ||\n
\t\t\t\tinspectData && jsre.test( s.data ) ) ) {\n
\n
\t\tvar responseContainer,\n
\t\t\tjsonpCallback = s.jsonpCallback =\n
\t\t\t\tjQuery.isFunction( s.jsonpCallback ) ? s.jsonpCallback() : s.jsonpCallback,\n
\t\t\tprevious = window[ jsonpCallback ],\n
\t\t\turl = s.url,\n
\t\t\tdata = s.data,\n
\t\t\treplace = "$1" + jsonpCallback + "$2";\n
\n
\t\tif ( s.jsonp !== false ) {\n
\t\t\turl = url.replace( jsre, replace );\n
\t\t\tif ( s.url === url ) {\n
\t\t\t\tif ( inspectData ) {\n
\t\t\t\t\tdata = data.replace( jsre, replace );\n
\t\t\t\t}\n
\t\t\t\tif ( s.data === data ) {\n
\t\t\t\t\t// Add callback manually\n
\t\t\t\t\turl += (/\\?/.test( url ) ? "&" : "?") + s.jsonp + "=" + jsonpCallback;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\ts.url = url;\n
\t\ts.data = data;\n
\n
\t\t// Install callback\n
\t\twindow[ jsonpCallback ] = function( response ) {\n
\t\t\tresponseContainer = [ response ];\n
\t\t};\n
\n
\t\t// Clean-up function\n
\t\tjqXHR.always(function() {\n
\t\t\t// Set callback back to previous value\n
\t\t\twindow[ jsonpCallback ] = previous;\n
\t\t\t// Call if it was a function and we have a response\n
\t\t\tif ( responseContainer && jQuery.isFunction( previous ) ) {\n
\t\t\t\twindow[ jsonpCallback ]( responseContainer[ 0 ] );\n
\t\t\t}\n
\t\t});\n
\n
\t\t// Use data converter to retrieve json after script execution\n
\t\ts.converters["script json"] = function() {\n
\t\t\tif ( !responseContainer ) {\n
\t\t\t\tjQuery.error( jsonpCallback + " was not called" );\n
\t\t\t}\n
\t\t\treturn responseContainer[ 0 ];\n
\t\t};\n
\n
\t\t// force json dataType\n
\t\ts.dataTypes[ 0 ] = "json";\n
\n
\t\t// Delegate to script\n
\t\treturn "script";\n
\t}\n
});\n
\n
\n
\n
\n
// Install script dataType\n
jQuery.ajaxSetup({\n
\taccepts: {\n
\t\tscript: "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"\n
\t},\n
\tcontents: {\n
\t\tscript: /javascript|ecmascript/\n
\t},\n
\tconverters: {\n
\t\t"text script": function( text ) {\n
\t\t\tjQuery.globalEval( text );\n
\t\t\treturn text;\n
\t\t}\n
\t}\n
});\n
\n
// Handle cache\'s special case and global\n
jQuery.ajaxPrefilter( "script", function( s ) {\n
\tif ( s.cache === undefined ) {\n
\t\ts.cache = false;\n
\t}\n
\tif ( s.crossDomain ) {\n
\t\ts.type = "GET";\n
\t\ts.global = false;\n
\t}\n
});\n
\n
// Bind script tag hack transport\n
jQuery.ajaxTransport( "script", function(s) {\n
\n
\t// This transport only deals with cross domain requests\n
\tif ( s.crossDomain ) {\n
\n
\t\tvar script,\n
\t\t\thead = document.head || document.getElementsByTagName( "head" )[0] || document.documentElement;\n
\n
\t\treturn {\n
\n
\t\t\tsend: function( _, callback ) {\n
\n
\t\t\t\tscript = document.createElement( "script" );\n
\n
\t\t\t\tscript.async = "async";\n
\n
\t\t\t\tif ( s.scriptCharset ) {\n
\t\t\t\t\tscript.charset = s.scriptCharset;\n
\t\t\t\t}\n
\n
\t\t\t\tscript.src = s.url;\n
\n
\t\t\t\t// Attach handlers for all browsers\n
\t\t\t\tscript.onload = script.onreadystatechange = function( _, isAbort ) {\n
\n
\t\t\t\t\tif ( isAbort || !script.readyState || /loaded|complete/.test( script.readyState ) ) {\n
\n
\t\t\t\t\t\t// Handle memory leak in IE\n
\t\t\t\t\t\tscript.onload = script.onreadystatechange = null;\n
\n
\t\t\t\t\t\t// Remove the script\n
\t\t\t\t\t\tif ( head && script.parentNode ) {\n
\t\t\t\t\t\t\thead.removeChild( script );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// Dereference the script\n
\t\t\t\t\t\tscript = undefined;\n
\n
\t\t\t\t\t\t// Callback if not abort\n
\t\t\t\t\t\tif ( !isAbort ) {\n
\t\t\t\t\t\t\tcallback( 200, "success" );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t\t// Use insertBefore instead of appendChild  to circumvent an IE6 bug.\n
\t\t\t\t// This arises when a base node is used (#2709 and #4378).\n
\t\t\t\thead.insertBefore( script, head.firstChild );\n
\t\t\t},\n
\n
\t\t\tabort: function() {\n
\t\t\t\tif ( script ) {\n
\t\t\t\t\tscript.onload( 0, 1 );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\t}\n
});\n
\n
\n
\n
\n
var // #5280: Internet Explorer will keep connections alive if we don\'t abort on unload\n
\txhrOnUnloadAbort = window.ActiveXObject ? function() {\n
\t\t// Abort all pending requests\n
\t\tfor ( var key in xhrCallbacks ) {\n
\t\t\txhrCallbacks[ key ]( 0, 1 );\n
\t\t}\n
\t} : false,\n
\txhrId = 0,\n
\txhrCallbacks;\n
\n
// Functions to create xhrs\n
function createStandardXHR() {\n
\ttry {\n
\t\treturn new window.XMLHttpRequest();\n
\t} catch( e ) {}\n
}\n
\n
function createActiveXHR() {\n
\ttry {\n
\t\treturn new window.ActiveXObject( "Microsoft.XMLHTTP" );\n
\t} catch( e ) {}\n
}\n
\n
// Create the request object\n
// (This is still attached to ajaxSettings for backward compatibility)\n
jQuery.ajaxSettings.xhr = window.ActiveXObject ?\n
\t/* Microsoft failed to properly\n
\t * implement the XMLHttpRequest in IE7 (can\'t request local files),\n
\t * so we use the ActiveXObject when it is available\n
\t * Additionally XMLHttpRequest can be disabled in IE7/IE8 so\n
\t * we need a fallback.\n
\t */\n
\tfunction() {\n
\t\treturn !this.isLocal && createStandardXHR() || createActiveXHR();\n
\t} :\n
\t// For all other browsers, use the standard XMLHttpRequest object\n
\tcreateStandardXHR;\n
\n
// Determine support properties\n
(function( xhr ) {\n
\tjQuery.extend( jQuery.support, {\n
\t\tajax: !!xhr,\n
\t\tcors: !!xhr && ( "withCredentials" in xhr )\n
\t});\n
})( jQuery.ajaxSettings.xhr() );\n
\n
// Create transport if the browser can provide an xhr\n
if ( jQuery.support.ajax ) {\n
\n
\tjQuery.ajaxTransport(function( s ) {\n
\t\t// Cross domain only allowed if supported through XMLHttpRequest\n
\t\tif ( !s.crossDomain || jQuery.support.cors ) {\n
\n
\t\t\tvar callback;\n
\n
\t\t\treturn {\n
\t\t\t\tsend: function( headers, complete ) {\n
\n
\t\t\t\t\t// Get a new xhr\n
\t\t\t\t\tvar xhr = s.xhr(),\n
\t\t\t\t\t\thandle,\n
\t\t\t\t\t\ti;\n
\n
\t\t\t\t\t// Open the socket\n
\t\t\t\t\t// Passing null username, generates a login popup on Opera (#2865)\n
\t\t\t\t\tif ( s.username ) {\n
\t\t\t\t\t\txhr.open( s.type, s.url, s.async, s.username, s.password );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\txhr.open( s.type, s.url, s.async );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Apply custom fields if provided\n
\t\t\t\t\tif ( s.xhrFields ) {\n
\t\t\t\t\t\tfor ( i in s.xhrFields ) {\n
\t\t\t\t\t\t\txhr[ i ] = s.xhrFields[ i ];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Override mime type if needed\n
\t\t\t\t\tif ( s.mimeType && xhr.overrideMimeType ) {\n
\t\t\t\t\t\txhr.overrideMimeType( s.mimeType );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// X-Requested-With header\n
\t\t\t\t\t// For cross-domain requests, seeing as conditions for a preflight are\n
\t\t\t\t\t// akin to a jigsaw puzzle, we simply never set it to be sure.\n
\t\t\t\t\t// (it can always be set on a per-request basis or even using ajaxSetup)\n
\t\t\t\t\t// For same-domain requests, won\'t change header if already provided.\n
\t\t\t\t\tif ( !s.crossDomain && !headers["X-Requested-With"] ) {\n
\t\t\t\t\t\theaders[ "X-Requested-With" ] = "XMLHttpRequest";\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Need an extra try/catch for cross domain requests in Firefox 3\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\tfor ( i in headers ) {\n
\t\t\t\t\t\t\txhr.setRequestHeader( i, headers[ i ] );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} catch( _ ) {}\n
\n
\t\t\t\t\t// Do send the request\n
\t\t\t\t\t// This may raise an exception which is actually\n
\t\t\t\t\t// handled in jQuery.ajax (so no try/catch here)\n
\t\t\t\t\txhr.send( ( s.hasContent && s.data ) || null );\n
\n
\t\t\t\t\t// Listener\n
\t\t\t\t\tcallback = function( _, isAbort ) {\n
\n
\t\t\t\t\t\tvar status,\n
\t\t\t\t\t\t\tstatusText,\n
\t\t\t\t\t\t\tresponseHeaders,\n
\t\t\t\t\t\t\tresponses,\n
\t\t\t\t\t\t\txml;\n
\n
\t\t\t\t\t\t// Firefox throws exceptions when accessing properties\n
\t\t\t\t\t\t// of an xhr when a network error occured\n
\t\t\t\t\t\t// http://helpful.knobs-dials.com/index.php/Component_returned_failure_code:_0x80040111_(NS_ERROR_NOT_AVAILABLE)\n
\t\t\t\t\t\ttry {\n
\n
\t\t\t\t\t\t\t// Was never called and is aborted or complete\n
\t\t\t\t\t\t\tif ( callback && ( isAbort || xhr.readyState === 4 ) ) {\n
\n
\t\t\t\t\t\t\t\t// Only called once\n
\t\t\t\t\t\t\t\tcallback = undefined;\n
\n
\t\t\t\t\t\t\t\t// Do not keep as active anymore\n
\t\t\t\t\t\t\t\tif ( handle ) {\n
\t\t\t\t\t\t\t\t\txhr.onreadystatechange = jQuery.noop;\n
\t\t\t\t\t\t\t\t\tif ( xhrOnUnloadAbort ) {\n
\t\t\t\t\t\t\t\t\t\tdelete xhrCallbacks[ handle ];\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t\t// If it\'s an abort\n
\t\t\t\t\t\t\t\tif ( isAbort ) {\n
\t\t\t\t\t\t\t\t\t// Abort it manually if needed\n
\t\t\t\t\t\t\t\t\tif ( xhr.readyState !== 4 ) {\n
\t\t\t\t\t\t\t\t\t\txhr.abort();\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tstatus = xhr.status;\n
\t\t\t\t\t\t\t\t\tresponseHeaders = xhr.getAllResponseHeaders();\n
\t\t\t\t\t\t\t\t\tresponses = {};\n
\t\t\t\t\t\t\t\t\txml = xhr.responseXML;\n
\n
\t\t\t\t\t\t\t\t\t// Construct response list\n
\t\t\t\t\t\t\t\t\tif ( xml && xml.documentElement /* #4958 */ ) {\n
\t\t\t\t\t\t\t\t\t\tresponses.xml = xml;\n
\t\t\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t\t\t// When requesting binary data, IE6-9 will throw an exception\n
\t\t\t\t\t\t\t\t\t// on any attempt to access responseText (#11426)\n
\t\t\t\t\t\t\t\t\ttry {\n
\t\t\t\t\t\t\t\t\t\tresponses.text = xhr.responseText;\n
\t\t\t\t\t\t\t\t\t} catch( _ ) {\n
\t\t\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t\t\t// Firefox throws an exception when accessing\n
\t\t\t\t\t\t\t\t\t// statusText for faulty cross-domain requests\n
\t\t\t\t\t\t\t\t\ttry {\n
\t\t\t\t\t\t\t\t\t\tstatusText = xhr.statusText;\n
\t\t\t\t\t\t\t\t\t} catch( e ) {\n
\t\t\t\t\t\t\t\t\t\t// We normalize with Webkit giving an empty statusText\n
\t\t\t\t\t\t\t\t\t\tstatusText = "";\n
\t\t\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t\t\t// Filter status for non standard behaviors\n
\n
\t\t\t\t\t\t\t\t\t// If the request is local and we have data: assume a success\n
\t\t\t\t\t\t\t\t\t// (success with no data won\'t get notified, that\'s the best we\n
\t\t\t\t\t\t\t\t\t// can do given current implementations)\n
\t\t\t\t\t\t\t\t\tif ( !status && s.isLocal && !s.crossDomain ) {\n
\t\t\t\t\t\t\t\t\t\tstatus = responses.text ? 200 : 404;\n
\t\t\t\t\t\t\t\t\t// IE - #1450: sometimes returns 1223 when it should be 204\n
\t\t\t\t\t\t\t\t\t} else if ( status === 1223 ) {\n
\t\t\t\t\t\t\t\t\t\tstatus = 204;\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} catch( firefoxAccessException ) {\n
\t\t\t\t\t\t\tif ( !isAbort ) {\n
\t\t\t\t\t\t\t\tcomplete( -1, firefoxAccessException );\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// Call complete if needed\n
\t\t\t\t\t\tif ( responses ) {\n
\t\t\t\t\t\t\tcomplete( status, statusText, responses, responseHeaders );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t};\n
\n
\t\t\t\t\t// if we\'re in sync mode or it\'s in cache\n
\t\t\t\t\t// and has been retrieved directly (IE6 & IE7)\n
\t\t\t\t\t// we need to manually fire the callback\n
\t\t\t\t\tif ( !s.async || xhr.readyState === 4 ) {\n
\t\t\t\t\t\tcallback();\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\thandle = ++xhrId;\n
\t\t\t\t\t\tif ( xhrOnUnloadAbort ) {\n
\t\t\t\t\t\t\t// Create the active xhrs callbacks list if needed\n
\t\t\t\t\t\t\t// and attach the unload handler\n
\t\t\t\t\t\t\tif ( !xhrCallbacks ) {\n
\t\t\t\t\t\t\t\txhrCallbacks = {};\n
\t\t\t\t\t\t\t\tjQuery( window ).unload( xhrOnUnloadAbort );\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t// Add to list of active xhrs callbacks\n
\t\t\t\t\t\t\txhrCallbacks[ handle ] = callback;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\txhr.onreadystatechange = callback;\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\n
\t\t\t\tabort: function() {\n
\t\t\t\t\tif ( callback ) {\n
\t\t\t\t\t\tcallback(0,1);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t};\n
\t\t}\n
\t});\n
}\n
\n
\n
\n
\n
var elemdisplay = {},\n
\tiframe, iframeDoc,\n
\trfxtypes = /^(?:toggle|show|hide)$/,\n
\trfxnum = /^([+\\-]=)?([\\d+.\\-]+)([a-z%]*)$/i,\n
\ttimerId,\n
\tfxAttrs = [\n
\t\t// height animations\n
\t\t[ "height", "marginTop", "marginBottom", "paddingTop", "paddingBottom" ],\n
\t\t// width animations\n
\t\t[ "width", "marginLeft", "marginRight", "paddingLeft", "paddingRight" ],\n
\t\t// opacity animations\n
\t\t[ "opacity" ]\n
\t],\n
\tfxNow;\n
\n
jQuery.fn.extend({\n
\tshow: function( speed, easing, callback ) {\n
\t\tvar elem, display;\n
\n
\t\tif ( speed || speed === 0 ) {\n
\t\t\treturn this.animate( genFx("show", 3), speed, easing, callback );\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, j = this.length; i < j; i++ ) {\n
\t\t\t\telem = this[ i ];\n
\n
\t\t\t\tif ( elem.style ) {\n
\t\t\t\t\tdisplay = elem.style.display;\n
\n
\t\t\t\t\t// Reset the inline display of this element to learn if it is\n
\t\t\t\t\t// being hidden by cascaded rules or not\n
\t\t\t\t\tif ( !jQuery._data(elem, "olddisplay") && display === "none" ) {\n
\t\t\t\t\t\tdisplay = elem.style.display = "";\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Set elements which have been overridden with display: none\n
\t\t\t\t\t// in a stylesheet to whatever the default browser style is\n
\t\t\t\t\t// for such an element\n
\t\t\t\t\tif ( (display === "" && jQuery.css(elem, "display") === "none") ||\n
\t\t\t\t\t\t!jQuery.contains( elem.ownerDocument.documentElement, elem ) ) {\n
\t\t\t\t\t\tjQuery._data( elem, "olddisplay", defaultDisplay(elem.nodeName) );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set the display of most of the elements in a second loop\n
\t\t\t// to avoid the constant reflow\n
\t\t\tfor ( i = 0; i < j; i++ ) {\n
\t\t\t\telem = this[ i ];\n
\n
\t\t\t\tif ( elem.style ) {\n
\t\t\t\t\tdisplay = elem.style.display;\n
\n
\t\t\t\t\tif ( display === "" || display === "none" ) {\n
\t\t\t\t\t\telem.style.display = jQuery._data( elem, "olddisplay" ) || "";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn this;\n
\t\t}\n
\t},\n
\n
\thide: function( speed, easing, callback ) {\n
\t\tif ( speed || speed === 0 ) {\n
\t\t\treturn this.animate( genFx("hide", 3), speed, easing, callback);\n
\n
\t\t} else {\n
\t\t\tvar elem, display,\n
\t\t\t\ti = 0,\n
\t\t\t\tj = this.length;\n
\n
\t\t\tfor ( ; i < j; i++ ) {\n
\t\t\t\telem = this[i];\n
\t\t\t\tif ( elem.style ) {\n
\t\t\t\t\tdisplay = jQuery.css( elem, "display" );\n
\n
\t\t\t\t\tif ( display !== "none" && !jQuery._data( elem, "olddisplay" ) ) {\n
\t\t\t\t\t\tjQuery._data( elem, "olddisplay", display );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set the display of the elements in a second loop\n
\t\t\t// to avoid the constant reflow\n
\t\t\tfor ( i = 0; i < j; i++ ) {\n
\t\t\t\tif ( this[i].style ) {\n
\t\t\t\t\tthis[i].style.display = "none";\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn this;\n
\t\t}\n
\t},\n
\n
\t// Save the old toggle function\n
\t_toggle: jQuery.fn.toggle,\n
\n
\ttoggle: function( fn, fn2, callback ) {\n
\t\tvar bool = typeof fn === "boolean";\n
\n
\t\tif ( jQuery.isFunction(fn) && jQuery.isFunction(fn2) ) {\n
\t\t\tthis._toggle.apply( this, arguments );\n
\n
\t\t} else if ( fn == null || bool ) {\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar state = bool ? fn : jQuery(this).is(":hidden");\n
\t\t\t\tjQuery(this)[ state ? "show" : "hide" ]();\n
\t\t\t});\n
\n
\t\t} else {\n
\t\t\tthis.animate(genFx("toggle", 3), fn, fn2, callback);\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tfadeTo: function( speed, to, easing, callback ) {\n
\t\treturn this.filter(":hidden").css("opacity", 0).show().end()\n
\t\t\t\t\t.animate({opacity: to}, speed, easing, callback);\n
\t},\n
\n
\tanimate: function( prop, speed, easing, callback ) {\n
\t\tvar optall = jQuery.speed( speed, easing, callback );\n
\n
\t\tif ( jQuery.isEmptyObject( prop ) ) {\n
\t\t\treturn this.each( optall.complete, [ false ] );\n
\t\t}\n
\n
\t\t// Do not change referenced properties as per-property easing will be lost\n
\t\tprop = jQuery.extend( {}, prop );\n
\n
\t\tfunction doAnimation() {\n
\t\t\t// XXX \'this\' does not always have a nodeName when running the\n
\t\t\t// test suite\n
\n
\t\t\tif ( optall.queue === false ) {\n
\t\t\t\tjQuery._mark( this );\n
\t\t\t}\n
\n
\t\t\tvar opt = jQuery.extend( {}, optall ),\n
\t\t\t\tisElement = this.nodeType === 1,\n
\t\t\t\thidden = isElement && jQuery(this).is(":hidden"),\n
\t\t\t\tname, val, p, e, hooks, replace,\n
\t\t\t\tparts, start, end, unit,\n
\t\t\t\tmethod;\n
\n
\t\t\t// will store per property easing and be used to determine when an animation is complete\n
\t\t\topt.animatedProperties = {};\n
\n
\t\t\t// first pass over propertys to expand / normalize\n
\t\t\tfor ( p in prop ) {\n
\t\t\t\tname = jQuery.camelCase( p );\n
\t\t\t\tif ( p !== name ) {\n
\t\t\t\t\tprop[ name ] = prop[ p ];\n
\t\t\t\t\tdelete prop[ p ];\n
\t\t\t\t}\n
\n
\t\t\t\tif ( ( hooks = jQuery.cssHooks[ name ] ) && "expand" in hooks ) {\n
\t\t\t\t\treplace = hooks.expand( prop[ name ] );\n
\t\t\t\t\tdelete prop[ name ];\n
\n
\t\t\t\t\t// not quite $.extend, this wont overwrite keys already present.\n
\t\t\t\t\t// also - reusing \'p\' from above because we have the correct "name"\n
\t\t\t\t\tfor ( p in replace ) {\n
\t\t\t\t\t\tif ( ! ( p in prop ) ) {\n
\t\t\t\t\t\t\tprop[ p ] = replace[ p ];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tfor ( name in prop ) {\n
\t\t\t\tval = prop[ name ];\n
\t\t\t\t// easing resolution: per property > opt.specialEasing > opt.easing > \'swing\' (default)\n
\t\t\t\tif ( jQuery.isArray( val ) ) {\n
\t\t\t\t\topt.animatedProperties[ name ] = val[ 1 ];\n
\t\t\t\t\tval = prop[ name ] = val[ 0 ];\n
\t\t\t\t} else {\n
\t\t\t\t\topt.animatedProperties[ name ] = opt.specialEasing && opt.specialEasing[ name ] || opt.easing || \'swing\';\n
\t\t\t\t}\n
\n
\t\t\t\tif ( val === "hide" && hidden || val === "show" && !hidden ) {\n
\t\t\t\t\treturn opt.complete.call( this );\n
\t\t\t\t}\n
\n
\t\t\t\tif ( isElement && ( name === "height" || name === "width" ) ) {\n
\t\t\t\t\t// Make sure that nothing sneaks out\n
\t\t\t\t\t// Record all 3 overflow attributes because IE does not\n
\t\t\t\t\t// change the overflow attribute when overflowX and\n
\t\t\t\t\t// overflowY are set to the same value\n
\t\t\t\t\topt.overflow = [ this.style.overflow, this.style.overflowX, this.style.overflowY ];\n
\n
\t\t\t\t\t// Set display property to inline-block for height/width\n
\t\t\t\t\t// animations on inline elements that are having width/height animated\n
\t\t\t\t\tif ( jQuery.css( this, "display" ) === "inline" &&\n
\t\t\t\t\t\t\tjQuery.css( this, "float" ) === "none" ) {\n
\n
\t\t\t\t\t\t// inline-level elements accept inline-block;\n
\t\t\t\t\t\t// block-level elements need to be inline with layout\n
\t\t\t\t\t\tif ( !jQuery.support.inlineBlockNeedsLayout || defaultDisplay( this.nodeName ) === "inline" ) {\n
\t\t\t\t\t\t\tthis.style.display = "inline-block";\n
\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tthis.style.zoom = 1;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( opt.overflow != null ) {\n
\t\t\t\tthis.style.overflow = "hidden";\n
\t\t\t}\n
\n
\t\t\tfor ( p in prop ) {\n
\t\t\t\te = new jQuery.fx( this, opt, p );\n
\t\t\t\tval = prop[ p ];\n
\n
\t\t\t\tif ( rfxtypes.test( val ) ) {\n
\n
\t\t\t\t\t// Tracks whether to show or hide based on private\n
\t\t\t\t\t// data attached to the element\n
\t\t\t\t\tmethod = jQuery._data( this, "toggle" + p ) || ( val === "toggle" ? hidden ? "show" : "hide" : 0 );\n
\t\t\t\t\tif ( method ) {\n
\t\t\t\t\t\tjQuery._data( this, "toggle" + p, method === "show" ? "hide" : "show" );\n
\t\t\t\t\t\te[ method ]();\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\te[ val ]();\n
\t\t\t\t\t}\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tparts = rfxnum.exec( val );\n
\t\t\t\t\tstart = e.cur();\n
\n
\t\t\t\t\tif ( parts ) {\n
\t\t\t\t\t\tend = parseFloat( parts[2] );\n
\t\t\t\t\t\tunit = parts[3] || ( jQuery.cssNumber[ p ] ? "" : "px" );\n
\n
\t\t\t\t\t\t// We need to compute starting value\n
\t\t\t\t\t\tif ( unit !== "px" ) {\n
\t\t\t\t\t\t\tjQuery.style( this, p, (end || 1) + unit);\n
\t\t\t\t\t\t\tstart = ( (end || 1) / e.cur() ) * start;\n
\t\t\t\t\t\t\tjQuery.style( this, p, start + unit);\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// If a +=/-= token was provided, we\'re doing a relative animation\n
\t\t\t\t\t\tif ( parts[1] ) {\n
\t\t\t\t\t\t\tend = ( (parts[ 1 ] === "-=" ? -1 : 1) * end ) + start;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\te.custom( start, end, unit );\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\te.custom( start, val, "" );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// For JS strict compliance\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\treturn optall.queue === false ?\n
\t\t\tthis.each( doAnimation ) :\n
\t\t\tthis.queue( optall.queue, doAnimation );\n
\t},\n
\n
\tstop: function( type, clearQueue, gotoEnd ) {\n
\t\tif ( typeof type !== "string" ) {\n
\t\t\tgotoEnd = clearQueue;\n
\t\t\tclearQueue = type;\n
\t\t\ttype = undefined;\n
\t\t}\n
\t\tif ( clearQueue && type !== false ) {\n
\t\t\tthis.queue( type || "fx", [] );\n
\t\t}\n
\n
\t\treturn this.each(function() {\n
\t\t\tvar index,\n
\t\t\t\thadTimers = false,\n
\t\t\t\ttimers = jQuery.timers,\n
\t\t\t\tdata = jQuery._data( this );\n
\n
\t\t\t// clear marker counters if we know they won\'t be\n
\t\t\tif ( !gotoEnd ) {\n
\t\t\t\tjQuery._unmark( true, this );\n
\t\t\t}\n
\n
\t\t\tfunction stopQueue( elem, data, index ) {\n
\t\t\t\tvar hooks = data[ index ];\n
\t\t\t\tjQuery.removeData( elem, index, true );\n
\t\t\t\thooks.stop( gotoEnd );\n
\t\t\t}\n
\n
\t\t\tif ( type == null ) {\n
\t\t\t\tfor ( index in data ) {\n
\t\t\t\t\tif ( data[ index ] && data[ index ].stop && index.indexOf(".run") === index.length - 4 ) {\n
\t\t\t\t\t\tstopQueue( this, data, index );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else if ( data[ index = type + ".run" ] && data[ index ].stop ){\n
\t\t\t\tstopQueue( this, data, index );\n
\t\t\t}\n
\n
\t\t\tfor ( index = timers.length; index--; ) {\n
\t\t\t\tif ( timers[ index ].elem === this && (type == null || timers[ index ].queue === type) ) {\n
\t\t\t\t\tif ( gotoEnd ) {\n
\n
\t\t\t\t\t\t// force the next step to be the last\n
\t\t\t\t\t\ttimers[ index ]( true );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\ttimers[ index ].saveState();\n
\t\t\t\t\t}\n
\t\t\t\t\thadTimers = true;\n
\t\t\t\t\ttimers.splice( index, 1 );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// start the next in the queue if the last step wasn\'t forced\n
\t\t\t// timers currently will call their complete callbacks, which will dequeue\n
\t\t\t// but only if they were gotoEnd\n
\t\t\tif ( !( gotoEnd && hadTimers ) ) {\n
\t\t\t\tjQuery.dequeue( this, type );\n
\t\t\t}\n
\t\t});\n
\t}\n
\n
});\n
\n
// Animations created synchronously will run synchronously\n
function createFxNow() {\n
\tsetTimeout( clearFxNow, 0 );\n
\treturn ( fxNow = jQuery.now() );\n
}\n
\n
function clearFxNow() {\n
\tfxNow = undefined;\n
}\n
\n
// Generate parameters to create a standard animation\n
function genFx( type, num ) {\n
\tvar obj = {};\n
\n
\tjQuery.each( fxAttrs.concat.apply([], fxAttrs.slice( 0, num )), function() {\n
\t\tobj[ this ] = type;\n
\t});\n
\n
\treturn obj;\n
}\n
\n
// Generate shortcuts for custom animations\n
jQuery.each({\n
\tslideDown: genFx( "show", 1 ),\n
\tslideUp: genFx( "hide", 1 ),\n
\tslideToggle: genFx( "toggle", 1 ),\n
\tfadeIn: { opacity: "show" },\n
\tfadeOut: { opacity: "hide" },\n
\tfadeToggle: { opacity: "toggle" }\n
}, function( name, props ) {\n
\tjQuery.fn[ name ] = function( speed, easing, callback ) {\n
\t\treturn this.animate( props, speed, easing, callback );\n
\t};\n
});\n
\n
jQuery.extend({\n
\tspeed: function( speed, easing, fn ) {\n
\t\tvar opt = speed && typeof speed === "object" ? jQuery.extend( {}, speed ) : {\n
\t\t\tcomplete: fn || !fn && easing ||\n
\t\t\t\tjQuery.isFunction( speed ) && speed,\n
\t\t\tduration: speed,\n
\t\t\teasing: fn && easing || easing && !jQuery.isFunction( easing ) && easing\n
\t\t};\n
\n
\t\topt.duration = jQuery.fx.off ? 0 : typeof opt.duration === "number" ? opt.duration :\n
\t\t\topt.duration in jQuery.fx.speeds ? jQuery.fx.speeds[ opt.duration ] : jQuery.fx.speeds._default;\n
\n
\t\t// normalize opt.queue - true/undefined/null -> "fx"\n
\t\tif ( opt.queue == null || opt.queue === true ) {\n
\t\t\topt.queue = "fx";\n
\t\t}\n
\n
\t\t// Queueing\n
\t\topt.old = opt.complete;\n
\n
\t\topt.complete = function( noUnmark ) {\n
\t\t\tif ( jQuery.isFunction( opt.old ) ) {\n
\t\t\t\topt.old.call( this );\n
\t\t\t}\n
\n
\t\t\tif ( opt.queue ) {\n
\t\t\t\tjQuery.dequeue( this, opt.queue );\n
\t\t\t} else if ( noUnmark !== false ) {\n
\t\t\t\tjQuery._unmark( this );\n
\t\t\t}\n
\t\t};\n
\n
\t\treturn opt;\n
\t},\n
\n
\teasing: {\n
\t\tlinear: function( p ) {\n
\t\t\treturn p;\n
\t\t},\n
\t\tswing: function( p ) {\n
\t\t\treturn ( -Math.cos( p*Math.PI ) / 2 ) + 0.5;\n
\t\t}\n
\t},\n
\n
\ttimers: [],\n
\n
\tfx: function( elem, options, prop ) {\n
\t\tthis.options = options;\n
\t\tthis.elem = elem;\n
\t\tthis.prop = prop;\n
\n
\t\toptions.orig = options.orig || {};\n
\t}\n
\n
});\n
\n
jQuery.fx.prototype = {\n
\t// Simple function for setting a style value\n
\tupdate: function() {\n
\t\tif ( this.options.step ) {\n
\t\t\tthis.options.step.call( this.elem, this.now, this );\n
\t\t}\n
\n
\t\t( jQuery.fx.step[ this.prop ] || jQuery.fx.step._default )( this );\n
\t},\n
\n
\t// Get the current size\n
\tcur: function() {\n
\t\tif ( this.elem[ this.prop ] != null && (!this.elem.style || this.elem.style[ this.prop ] == null) ) {\n
\t\t\treturn this.elem[ this.prop ];\n
\t\t}\n
\n
\t\tvar parsed,\n
\t\t\tr = jQuery.css( this.elem, this.prop );\n
\t\t// Empty strings, null, undefined and "auto" are converted to 0,\n
\t\t// complex values such as "rotate(1rad)" are returned as is,\n
\t\t// simple values such as "10px" are parsed to Float.\n
\t\treturn isNaN( parsed = parseFloat( r ) ) ? !r || r === "auto" ? 0 : r : parsed;\n
\t},\n
\n
\t// Start an animation from one number to another\n
\tcustom: function( from, to, unit ) {\n
\t\tvar self = this,\n
\t\t\tfx = jQuery.fx;\n
\n
\t\tthis.startTime = fxNow || createFxNow();\n
\t\tthis.end = to;\n
\t\tthis.now = this.start = from;\n
\t\tthis.pos = this.state = 0;\n
\t\tthis.unit = unit || this.unit || ( jQuery.cssNumber[ this.prop ] ? "" : "px" );\n
\n
\t\tfunction t( gotoEnd ) {\n
\t\t\treturn self.step( gotoEnd );\n
\t\t}\n
\n
\t\tt.queue = this.options.queue;\n
\t\tt.elem = this.elem;\n
\t\tt.saveState = function() {\n
\t\t\tif ( jQuery._data( self.elem, "fxshow" + self.prop ) === undefined ) {\n
\t\t\t\tif ( self.options.hide ) {\n
\t\t\t\t\tjQuery._data( self.elem, "fxshow" + self.prop, self.start );\n
\t\t\t\t} else if ( self.options.show ) {\n
\t\t\t\t\tjQuery._data( self.elem, "fxshow" + self.prop, self.end );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\n
\t\tif ( t() && jQuery.timers.push(t) && !timerId ) {\n
\t\t\ttimerId = setInterval( fx.tick, fx.interval );\n
\t\t}\n
\t},\n
\n
\t// Simple \'show\' function\n
\tshow: function() {\n
\t\tvar dataShow = jQuery._data( this.elem, "fxshow" + this.prop );\n
\n
\t\t// Remember where we started, so that we can go back to it later\n
\t\tthis.options.orig[ this.prop ] = dataShow || jQuery.style( this.elem, this.prop );\n
\t\tthis.options.show = true;\n
\n
\t\t// Begin the animation\n
\t\t// Make sure that we start at a small width/height to avoid any flash of content\n
\t\tif ( dataShow !== undefined ) {\n
\t\t\t// This show is picking up where a previous hide or show left off\n
\t\t\tthis.custom( this.cur(), dataShow );\n
\t\t} else {\n
\t\t\tthis.custom( this.prop === "width" || this.prop === "height" ? 1 : 0, this.cur() );\n
\t\t}\n
\n
\t\t// Start by showing the element\n
\t\tjQuery( this.elem ).show();\n
\t},\n
\n
\t// Simple \'hide\' function\n
\thide: function() {\n
\t\t// Remember where we started, so that we can go back to it later\n
\t\tthis.options.orig[ this.prop ] = jQuery._data( this.elem, "fxshow" + this.prop ) || jQuery.style( this.elem, this.prop );\n
\t\tthis.options.hide = true;\n
\n
\t\t// Begin the animation\n
\t\tthis.custom( this.cur(), 0 );\n
\t},\n
\n
\t// Each step of an animation\n
\tstep: function( gotoEnd ) {\n
\t\tvar p, n, complete,\n
\t\t\tt = fxNow || createFxNow(),\n
\t\t\tdone = true,\n
\t\t\telem = this.elem,\n
\t\t\toptions = this.options;\n
\n
\t\tif ( gotoEnd || t >= options.duration + this.startTime ) {\n
\t\t\tthis.now = this.end;\n
\t\t\tthis.pos = this.state = 1;\n
\t\t\tthis.update();\n
\n
\t\t\toptions.animatedProperties[ this.prop ] = true;\n
\n
\t\t\tfor ( p in options.animatedProperties ) {\n
\t\t\t\tif ( options.animatedProperties[ p ] !== true ) {\n
\t\t\t\t\tdone = false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( done ) {\n
\t\t\t\t// Reset the overflow\n
\t\t\t\tif ( options.overflow != null && !jQuery.support.shrinkWrapBlocks ) {\n
\n
\t\t\t\t\tjQuery.each( [ "", "X", "Y" ], function( index, value ) {\n
\t\t\t\t\t\telem.style[ "overflow" + value ] = options.overflow[ index ];\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\n
\t\t\t\t// Hide the element if the "hide" operation was done\n
\t\t\t\tif ( options.hide ) {\n
\t\t\t\t\tjQuery( elem ).hide();\n
\t\t\t\t}\n
\n
\t\t\t\t// Reset the properties, if the item has been hidden or shown\n
\t\t\t\tif ( options.hide || options.show ) {\n
\t\t\t\t\tfor ( p in options.animatedProperties ) {\n
\t\t\t\t\t\tjQuery.style( elem, p, options.orig[ p ] );\n
\t\t\t\t\t\tjQuery.removeData( elem, "fxshow" + p, true );\n
\t\t\t\t\t\t// Toggle data is no longer needed\n
\t\t\t\t\t\tjQuery.removeData( elem, "toggle" + p, true );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Execute the complete function\n
\t\t\t\t// in the event that the complete function throws an exception\n
\t\t\t\t// we must ensure it won\'t be called twice. #5684\n
\n
\t\t\t\tcomplete = options.complete;\n
\t\t\t\tif ( complete ) {\n
\n
\t\t\t\t\toptions.complete = false;\n
\t\t\t\t\tcomplete.call( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn false;\n
\n
\t\t} else {\n
\t\t\t// classical easing cannot be used with an Infinity duration\n
\t\t\tif ( options.duration == Infinity ) {\n
\t\t\t\tthis.now = t;\n
\t\t\t} else {\n
\t\t\t\tn = t - this.startTime;\n
\t\t\t\tthis.state = n / options.duration;\n
\n
\t\t\t\t// Perform the easing function, defaults to swing\n
\t\t\t\tthis.pos = jQuery.easing[ options.animatedProperties[this.prop] ]( this.state, n, 0, 1, options.duration );\n
\t\t\t\tthis.now = this.start + ( (this.end - this.start) * this.pos );\n
\t\t\t}\n
\t\t\t// Perform the next step of the animation\n
\t\t\tthis.update();\n
\t\t}\n
\n
\t\treturn true;\n
\t}\n
};\n
\n
jQuery.extend( jQuery.fx, {\n
\ttick: function() {\n
\t\tvar timer,\n
\t\t\ttimers = jQuery.timers,\n
\t\t\ti = 0;\n
\n
\t\tfor ( ; i < timers.length; i++ ) {\n
\t\t\ttimer = timers[ i ];\n
\t\t\t// Checks the timer has not already been removed\n
\t\t\tif ( !timer() && timers[ i ] === timer ) {\n
\t\t\t\ttimers.splice( i--, 1 );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !timers.length ) {\n
\t\t\tjQuery.fx.stop();\n
\t\t}\n
\t},\n
\n
\tinterval: 13,\n
\n
\tstop: function() {\n
\t\tclearInterval( timerId );\n
\t\ttimerId = null;\n
\t},\n
\n
\tspeeds: {\n
\t\tslow: 600,\n
\t\tfast: 200,\n
\t\t// Default speed\n
\t\t_default: 400\n
\t},\n
\n
\tstep: {\n
\t\topacity: function( fx ) {\n
\t\t\tjQuery.style( fx.elem, "opacity", fx.now );\n
\t\t},\n
\n
\t\t_default: function( fx ) {\n
\t\t\tif ( fx.elem.style && fx.elem.style[ fx.prop ] != null ) {\n
\t\t\t\tfx.elem.style[ fx.prop ] = fx.now + fx.unit;\n
\t\t\t} else {\n
\t\t\t\tfx.elem[ fx.prop ] = fx.now;\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
// Ensure props that can\'t be negative don\'t go there on undershoot easing\n
jQuery.each( fxAttrs.concat.apply( [], fxAttrs ), function( i, prop ) {\n
\t// exclude marginTop, marginLeft, marginBottom and marginRight from this list\n
\tif ( prop.indexOf( "margin" ) ) {\n
\t\tjQuery.fx.step[ prop ] = function( fx ) {\n
\t\t\tjQuery.style( fx.elem, prop, Math.max(0, fx.now) + fx.unit );\n
\t\t};\n
\t}\n
});\n
\n
if ( jQuery.expr && jQuery.expr.filters ) {\n
\tjQuery.expr.filters.animated = function( elem ) {\n
\t\treturn jQuery.grep(jQuery.timers, function( fn ) {\n
\t\t\treturn elem === fn.elem;\n
\t\t}).length;\n
\t};\n
}\n
\n
// Try to restore the default display value of an element\n
function defaultDisplay( nodeName ) {\n
\n
\tif ( !elemdisplay[ nodeName ] ) {\n
\n
\t\tvar body = document.body,\n
\t\t\telem = jQuery( "<" + nodeName + ">" ).appendTo( body ),\n
\t\t\tdisplay = elem.css( "display" );\n
\t\telem.remove();\n
\n
\t\t// If the simple way fails,\n
\t\t// get element\'s real default display by attaching it to a temp iframe\n
\t\tif ( display === "none" || display === "" ) {\n
\t\t\t// No iframe to use yet, so create it\n
\t\t\tif ( !iframe ) {\n
\t\t\t\tiframe = document.createElement( "iframe" );\n
\t\t\t\tiframe.frameBorder = iframe.width = iframe.height = 0;\n
\t\t\t}\n
\n
\t\t\tbody.appendChild( iframe );\n
\n
\t\t\t// Create a cacheable copy of the iframe document on first call.\n
\t\t\t// IE and Opera will allow us to reuse the iframeDoc without re-writing the fake HTML\n
\t\t\t// document to it; WebKit & Firefox won\'t allow reusing the iframe document.\n
\t\t\tif ( !iframeDoc || !iframe.createElement ) {\n
\t\t\t\tiframeDoc = ( iframe.contentWindow || iframe.contentDocument ).document;\n
\t\t\t\tiframeDoc.write( ( jQuery.support.boxModel ? "<!doctype html>" : "" ) + "<html><body>" );\n
\t\t\t\tiframeDoc.close();\n
\t\t\t}\n
\n
\t\t\telem = iframeDoc.createElement( nodeName );\n
\n
\t\t\tiframeDoc.body.appendChild( elem );\n
\n
\t\t\tdisplay = jQuery.css( elem, "display" );\n
\t\t\tbody.removeChild( iframe );\n
\t\t}\n
\n
\t\t// Store the correct default display\n
\t\telemdisplay[ nodeName ] = display;\n
\t}\n
\n
\treturn elemdisplay[ nodeName ];\n
}\n
\n
\n
\n
\n
var getOffset,\n
\trtable = /^t(?:able|d|h)$/i,\n
\trroot = /^(?:body|html)$/i;\n
\n
if ( "getBoundingClientRect" in document.documentElement ) {\n
\tgetOffset = function( elem, doc, docElem, box ) {\n
\t\ttry {\n
\t\t\tbox = elem.getBoundingClientRect();\n
\t\t} catch(e) {}\n
\n
\t\t// Make sure we\'re not dealing with a disconnected DOM node\n
\t\tif ( !box || !jQuery.contains( docElem, elem ) ) {\n
\t\t\treturn box ? { top: box.top, left: box.left } : { top: 0, left: 0 };\n
\t\t}\n
\n
\t\tvar body = doc.body,\n
\t\t\twin = getWindow( doc ),\n
\t\t\tclientTop  = docElem.clientTop  || body.clientTop  || 0,\n
\t\t\tclientLeft = docElem.clientLeft || body.clientLeft || 0,\n
\t\t\tscrollTop  = win.pageYOffset || jQuery.support.boxModel && docElem.scrollTop  || body.scrollTop,\n
\t\t\tscrollLeft = win.pageXOffset || jQuery.support.boxModel && docElem.scrollLeft || body.scrollLeft,\n
\t\t\ttop  = box.top  + scrollTop  - clientTop,\n
\t\t\tleft = box.left + scrollLeft - clientLeft;\n
\n
\t\treturn { top: top, left: left };\n
\t};\n
\n
} else {\n
\tgetOffset = function( elem, doc, docElem ) {\n
\t\tvar computedStyle,\n
\t\t\toffsetParent = elem.offsetParent,\n
\t\t\tprevOffsetParent = elem,\n
\t\t\tbody = doc.body,\n
\t\t\tdefaultView = doc.defaultView,\n
\t\t\tprevComputedStyle = defaultView ? defaultView.getComputedStyle( elem, null ) : elem.currentStyle,\n
\t\t\ttop = elem.offsetTop,\n
\t\t\tleft = elem.offsetLeft;\n
\n
\t\twhile ( (elem = elem.parentNode) && elem !== body && elem !== docElem ) {\n
\t\t\tif ( jQuery.support.fixedPosition && prevComputedStyle.position === "fixed" ) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tcomputedStyle = defaultView ? defaultView.getComputedStyle(elem, null) : elem.currentStyle;\n
\t\t\ttop  -= elem.scrollTop;\n
\t\t\tleft -= elem.scrollLeft;\n
\n
\t\t\tif ( elem === offsetParent ) {\n
\t\t\t\ttop  += elem.offsetTop;\n
\t\t\t\tleft += elem.offsetLeft;\n
\n
\t\t\t\tif ( jQuery.support.doesNotAddBorder && !(jQuery.support.doesAddBorderForTableAndCells && rtable.test(elem.nodeName)) ) {\n
\t\t\t\t\ttop  += parseFloat( computedStyle.borderTopWidth  ) || 0;\n
\t\t\t\t\tleft += parseFloat( computedStyle.borderLeftWidth ) || 0;\n
\t\t\t\t}\n
\n
\t\t\t\tprevOffsetParent = offsetParent;\n
\t\t\t\toffsetParent = elem.offsetParent;\n
\t\t\t}\n
\n
\t\t\tif ( jQuery.support.subtractsBorderForOverflowNotVisible && computedStyle.overflow !== "visible" ) {\n
\t\t\t\ttop  += parseFloat( computedStyle.borderTopWidth  ) || 0;\n
\t\t\t\tleft += parseFloat( computedStyle.borderLeftWidth ) || 0;\n
\t\t\t}\n
\n
\t\t\tprevComputedStyle = computedStyle;\n
\t\t}\n
\n
\t\tif ( prevComputedStyle.position === "relative" || prevComputedStyle.position === "static" ) {\n
\t\t\ttop  += body.offsetTop;\n
\t\t\tleft += body.offsetLeft;\n
\t\t}\n
\n
\t\tif ( jQuery.support.fixedPosition && prevComputedStyle.position === "fixed" ) {\n
\t\t\ttop  += Math.max( docElem.scrollTop, body.scrollTop );\n
\t\t\tleft += Math.max( docElem.scrollLeft, body.scrollLeft );\n
\t\t}\n
\n
\t\treturn { top: top, left: left };\n
\t};\n
}\n
\n
jQuery.fn.offset = function( options ) {\n
\tif ( arguments.length ) {\n
\t\treturn options === undefined ?\n
\t\t\tthis :\n
\t\t\tthis.each(function( i ) {\n
\t\t\t\tjQuery.offset.setOffset( this, options, i );\n
\t\t\t});\n
\t}\n
\n
\tvar elem = this[0],\n
\t\tdoc = elem && elem.ownerDocument;\n
\n
\tif ( !doc ) {\n
\t\treturn null;\n
\t}\n
\n
\tif ( elem === doc.body ) {\n
\t\treturn jQuery.offset.bodyOffset( elem );\n
\t}\n
\n
\treturn getOffset( elem, doc, doc.documentElement );\n
};\n
\n
jQuery.offset = {\n
\n
\tbodyOffset: function( body ) {\n
\t\tvar top = body.offsetTop,\n
\t\t\tleft = body.offsetLeft;\n
\n
\t\tif ( jQuery.support.doesNotIncludeMarginInBodyOffset ) {\n
\t\t\ttop  += parseFloat( jQuery.css(body, "marginTop") ) || 0;\n
\t\t\tleft += parseFloat( jQuery.css(body, "marginLeft") ) || 0;\n
\t\t}\n
\n
\t\treturn { top: top, left: left };\n
\t},\n
\n
\tsetOffset: function( elem, options, i ) {\n
\t\tvar position = jQuery.css( elem, "position" );\n
\n
\t\t// set position first, in-case top/left are set even on static elem\n
\t\tif ( position === "static" ) {\n
\t\t\telem.style.position = "relative";\n
\t\t}\n
\n
\t\tvar curElem = jQuery( elem ),\n
\t\t\tcurOffset = curElem.offset(),\n
\t\t\tcurCSSTop = jQuery.css( elem, "top" ),\n
\t\t\tcurCSSLeft = jQuery.css( elem, "left" ),\n
\t\t\tcalculatePosition = ( position === "absolute" || position === "fixed" ) && jQuery.inArray("auto", [curCSSTop, curCSSLeft]) > -1,\n
\t\t\tprops = {}, curPosition = {}, curTop, curLeft;\n
\n
\t\t// need to be able to calculate position if either top or left is auto and position is either absolute or fixed\n
\t\tif ( calculatePosition ) {\n
\t\t\tcurPosition = curElem.position();\n
\t\t\tcurTop = curPosition.top;\n
\t\t\tcurLeft = curPosition.left;\n
\t\t} else {\n
\t\t\tcurTop = parseFloat( curCSSTop ) || 0;\n
\t\t\tcurLeft = parseFloat( curCSSLeft ) || 0;\n
\t\t}\n
\n
\t\tif ( jQuery.isFunction( options ) ) {\n
\t\t\toptions = options.call( elem, i, curOffset );\n
\t\t}\n
\n
\t\tif ( options.top != null ) {\n
\t\t\tprops.top = ( options.top - curOffset.top ) + curTop;\n
\t\t}\n
\t\tif ( options.left != null ) {\n
\t\t\tprops.left = ( options.left - curOffset.left ) + curLeft;\n
\t\t}\n
\n
\t\tif ( "using" in options ) {\n
\t\t\toptions.using.call( elem, props );\n
\t\t} else {\n
\t\t\tcurElem.css( props );\n
\t\t}\n
\t}\n
};\n
\n
\n
jQuery.fn.extend({\n
\n
\tposition: function() {\n
\t\tif ( !this[0] ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tvar elem = this[0],\n
\n
\t\t// Get *real* offsetParent\n
\t\toffsetParent = this.offsetParent(),\n
\n
\t\t// Get correct offsets\n
\t\toffset       = this.offset(),\n
\t\tparentOffset = rroot.test(offsetParent[0].nodeName) ? { top: 0, left: 0 } : offsetParent.offset();\n
\n
\t\t// Subtract element margins\n
\t\t// note: when an element has margin: auto the offsetLeft and marginLeft\n
\t\t// are the same in Safari causing offset.left to incorrectly be 0\n
\t\toffset.top  -= parseFloat( jQuery.css(elem, "marginTop") ) || 0;\n
\t\toffset.left -= parseFloat( jQuery.css(elem, "marginLeft") ) || 0;\n
\n
\t\t// Add offsetParent borders\n
\t\tparentOffset.top  += parseFloat( jQuery.css(offsetParent[0], "borderTopWidth") ) || 0;\n
\t\tparentOffset.left += parseFloat( jQuery.css(offsetParent[0], "borderLeftWidth") ) || 0;\n
\n
\t\t// Subtract the two offsets\n
\t\treturn {\n
\t\t\ttop:  offset.top  - parentOffset.top,\n
\t\t\tleft: offset.left - parentOffset.left\n
\t\t};\n
\t},\n
\n
\toffsetParent: function() {\n
\t\treturn this.map(function() {\n
\t\t\tvar offsetParent = this.offsetParent || document.body;\n
\t\t\twhile ( offsetParent && (!rroot.test(offsetParent.nodeName) && jQuery.css(offsetParent, "position") === "static") ) {\n
\t\t\t\toffsetParent = offsetParent.offsetParent;\n
\t\t\t}\n
\t\t\treturn offsetParent;\n
\t\t});\n
\t}\n
});\n
\n
\n
// Create scrollLeft and scrollTop methods\n
jQuery.each( {scrollLeft: "pageXOffset", scrollTop: "pageYOffset"}, function( method, prop ) {\n
\tvar top = /Y/.test( prop );\n
\n
\tjQuery.fn[ method ] = function( val ) {\n
\t\treturn jQuery.access( this, function( elem, method, val ) {\n
\t\t\tvar win = getWindow( elem );\n
\n
\t\t\tif ( val === undefined ) {\n
\t\t\t\treturn win ? (prop in win) ? win[ prop ] :\n
\t\t\t\t\tjQuery.support.boxModel && win.document.documentElement[ method ] ||\n
\t\t\t\t\t\twin.document.body[ method ] :\n
\t\t\t\t\telem[ method ];\n
\t\t\t}\n
\n
\t\t\tif ( win ) {\n
\t\t\t\twin.scrollTo(\n
\t\t\t\t\t!top ? val : jQuery( win ).scrollLeft(),\n
\t\t\t\t\t top ? val : jQuery( win ).scrollTop()\n
\t\t\t\t);\n
\n
\t\t\t} else {\n
\t\t\t\telem[ method ] = val;\n
\t\t\t}\n
\t\t}, method, val, arguments.length, null );\n
\t};\n
});\n
\n
function getWindow( elem ) {\n
\treturn jQuery.isWindow( elem ) ?\n
\t\telem :\n
\t\telem.nodeType === 9 ?\n
\t\t\telem.defaultView || elem.parentWindow :\n
\t\t\tfalse;\n
}\n
\n
\n
\n
\n
// Create width, height, innerHeight, innerWidth, outerHeight and outerWidth methods\n
jQuery.each( { Height: "height", Width: "width" }, function( name, type ) {\n
\tvar clientProp = "client" + name,\n
\t\tscrollProp = "scroll" + name,\n
\t\toffsetProp = "offset" + name;\n
\n
\t// innerHeight and innerWidth\n
\tjQuery.fn[ "inner" + name ] = function() {\n
\t\tvar elem = this[0];\n
\t\treturn elem ?\n
\t\t\telem.style ?\n
\t\t\tparseFloat( jQuery.css( elem, type, "padding" ) ) :\n
\t\t\tthis[ type ]() :\n
\t\t\tnull;\n
\t};\n
\n
\t// outerHeight and outerWidth\n
\tjQuery.fn[ "outer" + name ] = function( margin ) {\n
\t\tvar elem = this[0];\n
\t\treturn elem ?\n
\t\t\telem.style ?\n
\t\t\tparseFloat( jQuery.css( elem, type, margin ? "margin" : "border" ) ) :\n
\t\t\tthis[ type ]() :\n
\t\t\tnull;\n
\t};\n
\n
\tjQuery.fn[ type ] = function( value ) {\n
\t\treturn jQuery.access( this, function( elem, type, value ) {\n
\t\t\tvar doc, docElemProp, orig, ret;\n
\n
\t\t\tif ( jQuery.isWindow( elem ) ) {\n
\t\t\t\t// 3rd condition allows Nokia support, as it supports the docElem prop but not CSS1Compat\n
\t\t\t\tdoc = elem.document;\n
\t\t\t\tdocElemProp = doc.documentElement[ clientProp ];\n
\t\t\t\treturn jQuery.support.boxModel && docElemProp ||\n
\t\t\t\t\tdoc.body && doc.body[ clientProp ] || docElemProp;\n
\t\t\t}\n
\n
\t\t\t// Get document width or height\n
\t\t\tif ( elem.nodeType === 9 ) {\n
\t\t\t\t// Either scroll[Width/Height] or offset[Width/Height], whichever is greater\n
\t\t\t\tdoc = elem.documentElement;\n
\n
\t\t\t\t// when a window > document, IE6 reports a offset[Width/Height] > client[Width/Height]\n
\t\t\t\t// so we can\'t use max, as it\'ll choose the incorrect offset[Width/Height]\n
\t\t\t\t// instead we use the correct client[Width/Height]\n
\t\t\t\t// support:IE6\n
\t\t\t\tif ( doc[ clientProp ] >= doc[ scrollProp ] ) {\n
\t\t\t\t\treturn doc[ clientProp ];\n
\t\t\t\t}\n
\n
\t\t\t\treturn Math.max(\n
\t\t\t\t\telem.body[ scrollProp ], doc[ scrollProp ],\n
\t\t\t\t\telem.body[ offsetProp ], doc[ offsetProp ]\n
\t\t\t\t);\n
\t\t\t}\n
\n
\t\t\t// Get width or height on the element\n
\t\t\tif ( value === undefined ) {\n
\t\t\t\torig = jQuery.css( elem, type );\n
\t\t\t\tret = parseFloat( orig );\n
\t\t\t\treturn jQuery.isNumeric( ret ) ? ret : orig;\n
\t\t\t}\n
\n
\t\t\t// Set the width or height on the element\n
\t\t\tjQuery( elem ).css( type, value );\n
\t\t}, type, value, arguments.length, null );\n
\t};\n
});\n
\n
\n
\n
\n
// Expose jQuery to the global object\n
window.jQuery = window.$ = jQuery;\n
\n
// Expose jQuery as an AMD module, but only for AMD loaders that\n
// understand the issues with loading multiple versions of jQuery\n
// in a page that all might call define(). The loader will indicate\n
// they have special allowances for multiple jQuery versions by\n
// specifying define.amd.jQuery = true. Register as a named module,\n
// since jQuery can be concatenated with other files that may use define,\n
// but not use a proper concatenation script that understands anonymous\n
// AMD modules. A named AMD is safest and most robust way to register.\n
// Lowercase jquery is used because AMD module names are derived from\n
// file names, and jQuery is normally delivered in a lowercase file name.\n
// Do this after creating the global so that if an AMD module wants to call\n
// noConflict to hide this version of jQuery, it will work.\n
if ( typeof define === "function" && define.amd && define.amd.jQuery ) {\n
\tdefine( "jquery", [], function () { return jQuery; } );\n
}\n
\n
\n
\n
})( window );\n


]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <none/>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
