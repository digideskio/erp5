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
            <value> <string>ts31508727.41</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>bbq.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*!\n
 * jQuery BBQ: Back Button & Query Library - v1.2.1 - 2/17/2010\n
 * http://benalman.com/projects/jquery-bbq-plugin/\n
 * \n
 * Copyright (c) 2010 "Cowboy" Ben Alman\n
 * Dual licensed under the MIT and GPL licenses.\n
 * http://benalman.com/about/license/\n
 */\n
\n
// Script: jQuery BBQ: Back Button & Query Library\n
//\n
// *Version: 1.2.1, Last updated: 2/17/2010*\n
// \n
// Project Home - http://benalman.com/projects/jquery-bbq-plugin/\n
// GitHub       - http://github.com/cowboy/jquery-bbq/\n
// Source       - http://github.com/cowboy/jquery-bbq/raw/master/jquery.ba-bbq.js\n
// (Minified)   - http://github.com/cowboy/jquery-bbq/raw/master/jquery.ba-bbq.min.js (4.0kb)\n
// \n
// About: License\n
// \n
// Copyright (c) 2010 "Cowboy" Ben Alman,\n
// Dual licensed under the MIT and GPL licenses.\n
// http://benalman.com/about/license/\n
// \n
// About: Examples\n
// \n
// These working examples, complete with fully commented code, illustrate a few\n
// ways in which this plugin can be used.\n
// \n
// Basic AJAX     - http://benalman.com/code/projects/jquery-bbq/examples/fragment-basic/\n
// Advanced AJAX  - http://benalman.com/code/projects/jquery-bbq/examples/fragment-advanced/\n
// jQuery UI Tabs - http://benalman.com/code/projects/jquery-bbq/examples/fragment-jquery-ui-tabs/\n
// Deparam        - http://benalman.com/code/projects/jquery-bbq/examples/deparam/\n
// \n
// About: Support and Testing\n
// \n
// Information about what version or versions of jQuery this plugin has been\n
// tested with, what browsers it has been tested in, and where the unit tests\n
// reside (so you can test it yourself).\n
// \n
// jQuery Versions - 1.3.2, 1.4.1, 1.4.2\n
// Browsers Tested - Internet Explorer 6-8, Firefox 2-3.7, Safari 3-4,\n
//                   Chrome 4-5, Opera 9.6-10.1.\n
// Unit Tests      - http://benalman.com/code/projects/jquery-bbq/unit/\n
// \n
// About: Release History\n
// \n
// 1.2.1 - (2/17/2010) Actually fixed the stale window.location Safari bug from\n
//         <jQuery hashchange event> in BBQ, which was the main reason for the\n
//         previous release!\n
// 1.2   - (2/16/2010) Integrated <jQuery hashchange event> v1.2, which fixes a\n
//         Safari bug, the event can now be bound before DOM ready, and IE6/7\n
//         page should no longer scroll when the event is first bound. Also\n
//         added the <jQuery.param.fragment.noEscape> method, and reworked the\n
//         <hashchange event (BBQ)> internal "add" method to be compatible with\n
//         changes made to the jQuery 1.4.2 special events API.\n
// 1.1.1 - (1/22/2010) Integrated <jQuery hashchange event> v1.1, which fixes an\n
//         obscure IE8 EmulateIE7 meta tag compatibility mode bug.\n
// 1.1   - (1/9/2010) Broke out the jQuery BBQ event.special <hashchange event>\n
//         functionality into a separate plugin for users who want just the\n
//         basic event & back button support, without all the extra awesomeness\n
//         that BBQ provides. This plugin will be included as part of jQuery BBQ,\n
//         but also be available separately. See <jQuery hashchange event>\n
//         plugin for more information. Also added the <jQuery.bbq.removeState>\n
//         method and added additional <jQuery.deparam> examples.\n
// 1.0.3 - (12/2/2009) Fixed an issue in IE 6 where location.search and\n
//         location.hash would report incorrectly if the hash contained the ?\n
//         character. Also <jQuery.param.querystring> and <jQuery.param.fragment>\n
//         will no longer parse params out of a URL that doesn\'t contain ? or #,\n
//         respectively.\n
// 1.0.2 - (10/10/2009) Fixed an issue in IE 6/7 where the hidden IFRAME caused\n
//         a "This page contains both secure and nonsecure items." warning when\n
//         used on an https:// page.\n
// 1.0.1 - (10/7/2009) Fixed an issue in IE 8. Since both "IE7" and "IE8\n
//         Compatibility View" modes erroneously report that the browser\n
//         supports the native window.onhashchange event, a slightly more\n
//         robust test needed to be added.\n
// 1.0   - (10/2/2009) Initial release\n
\n
(function($,window){\n
  \'$:nomunge\'; // Used by YUI compressor.\n
  \n
  // Some convenient shortcuts.\n
  var undefined,\n
    aps = Array.prototype.slice,\n
    decode = decodeURIComponent,\n
    \n
    // Method / object references.\n
    jq_param = $.param,\n
    jq_param_fragment,\n
    jq_deparam,\n
    jq_deparam_fragment,\n
    jq_bbq = $.bbq = $.bbq || {},\n
    jq_bbq_pushState,\n
    jq_bbq_getState,\n
    jq_elemUrlAttr,\n
    jq_event_special = $.event.special,\n
    \n
    // Reused strings.\n
    str_hashchange = \'hashchange\',\n
    str_querystring = \'querystring\',\n
    str_fragment = \'fragment\',\n
    str_elemUrlAttr = \'elemUrlAttr\',\n
    str_location = \'location\',\n
    str_href = \'href\',\n
    str_src = \'src\',\n
    \n
    // Reused RegExp.\n
    re_trim_querystring = /^.*\\?|#.*$/g,\n
    re_trim_fragment = /^.*\\#/,\n
    re_no_escape,\n
    \n
    // Used by jQuery.elemUrlAttr.\n
    elemUrlAttr_cache = {};\n
  \n
  // A few commonly used bits, broken out to help reduce minified file size.\n
  \n
  function is_string( arg ) {\n
    return typeof arg === \'string\';\n
  };\n
  \n
  // Why write the same function twice? Let\'s curry! Mmmm, curry..\n
  \n
  function curry( func ) {\n
    var args = aps.call( arguments, 1 );\n
    \n
    return function() {\n
      return func.apply( this, args.concat( aps.call( arguments ) ) );\n
    };\n
  };\n
  \n
  // Get location.hash (or what you\'d expect location.hash to be) sans any\n
  // leading #. Thanks for making this necessary, Firefox!\n
  function get_fragment( url ) {\n
    return url.replace( /^[^#]*#?(.*)$/, \'$1\' );\n
  };\n
  \n
  // Get location.search (or what you\'d expect location.search to be) sans any\n
  // leading #. Thanks for making this necessary, IE6!\n
  function get_querystring( url ) {\n
    return url.replace( /(?:^[^?#]*\\?([^#]*).*$)?.*/, \'$1\' );\n
  };\n
  \n
  // Section: Param (to string)\n
  // \n
  // Method: jQuery.param.querystring\n
  // \n
  // Retrieve the query string from a URL or if no arguments are passed, the\n
  // current window.location.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.param.querystring( [ url ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) A URL containing query string params to be parsed. If url\n
  //    is not passed, the current window.location is used.\n
  // \n
  // Returns:\n
  // \n
  //  (String) The parsed query string, with any leading "?" removed.\n
  //\n
  \n
  // Method: jQuery.param.querystring (build url)\n
  // \n
  // Merge a URL, with or without pre-existing query string params, plus any\n
  // object, params string or URL containing query string params into a new URL.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.param.querystring( url, params [, merge_mode ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) A valid URL for params to be merged into. This URL may\n
  //    contain a query string and/or fragment (hash).\n
  //  params - (String) A params string or URL containing query string params to\n
  //    be merged into url.\n
  //  params - (Object) A params object to be merged into url.\n
  //  merge_mode - (Number) Merge behavior defaults to 0 if merge_mode is not\n
  //    specified, and is as-follows:\n
  // \n
  //    * 0: params in the params argument will override any query string\n
  //         params in url.\n
  //    * 1: any query string params in url will override params in the params\n
  //         argument.\n
  //    * 2: params argument will completely replace any query string in url.\n
  // \n
  // Returns:\n
  // \n
  //  (String) Either a params string with urlencoded data or a URL with a\n
  //    urlencoded query string in the format \'a=b&c=d&e=f\'.\n
  \n
  // Method: jQuery.param.fragment\n
  // \n
  // Retrieve the fragment (hash) from a URL or if no arguments are passed, the\n
  // current window.location.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.param.fragment( [ url ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) A URL containing fragment (hash) params to be parsed. If\n
  //    url is not passed, the current window.location is used.\n
  // \n
  // Returns:\n
  // \n
  //  (String) The parsed fragment (hash) string, with any leading "#" removed.\n
  \n
  // Method: jQuery.param.fragment (build url)\n
  // \n
  // Merge a URL, with or without pre-existing fragment (hash) params, plus any\n
  // object, params string or URL containing fragment (hash) params into a new\n
  // URL.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.param.fragment( url, params [, merge_mode ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) A valid URL for params to be merged into. This URL may\n
  //    contain a query string and/or fragment (hash).\n
  //  params - (String) A params string or URL containing fragment (hash) params\n
  //    to be merged into url.\n
  //  params - (Object) A params object to be merged into url.\n
  //  merge_mode - (Number) Merge behavior defaults to 0 if merge_mode is not\n
  //    specified, and is as-follows:\n
  // \n
  //    * 0: params in the params argument will override any fragment (hash)\n
  //         params in url.\n
  //    * 1: any fragment (hash) params in url will override params in the\n
  //         params argument.\n
  //    * 2: params argument will completely replace any query string in url.\n
  // \n
  // Returns:\n
  // \n
  //  (String) Either a params string with urlencoded data or a URL with a\n
  //    urlencoded fragment (hash) in the format \'a=b&c=d&e=f\'.\n
  \n
  function jq_param_sub( is_fragment, get_func, url, params, merge_mode ) {\n
    var result,\n
      qs,\n
      matches,\n
      url_params,\n
      hash;\n
    \n
    if ( params !== undefined ) {\n
      // Build URL by merging params into url string.\n
      \n
      // matches[1] = url part that precedes params, not including trailing ?/#\n
      // matches[2] = params, not including leading ?/#\n
      // matches[3] = if in \'querystring\' mode, hash including leading #, otherwise \'\'\n
      matches = url.match( is_fragment ? /^([^#]*)\\#?(.*)$/ : /^([^#?]*)\\??([^#]*)(#?.*)/ );\n
      \n
      // Get the hash if in \'querystring\' mode, and it exists.\n
      hash = matches[3] || \'\';\n
      \n
      if ( merge_mode === 2 && is_string( params ) ) {\n
        // If merge_mode is 2 and params is a string, merge the fragment / query\n
        // string into the URL wholesale, without converting it into an object.\n
        qs = params.replace( is_fragment ? re_trim_fragment : re_trim_querystring, \'\' );\n
        \n
      } else {\n
        // Convert relevant params in url to object.\n
        url_params = jq_deparam( matches[2] );\n
        \n
        params = is_string( params )\n
          \n
          // Convert passed params string into object.\n
          ? jq_deparam[ is_fragment ? str_fragment : str_querystring ]( params )\n
          \n
          // Passed params object.\n
          : params;\n
        \n
        qs = merge_mode === 2 ? params                              // passed params replace url params\n
          : merge_mode === 1  ? $.extend( {}, params, url_params )  // url params override passed params\n
          : $.extend( {}, url_params, params );                     // passed params override url params\n
        \n
        // Convert params object to a string.\n
        qs = jq_param( qs );\n
        \n
        // Unescape characters specified via $.param.noEscape. Since only hash-\n
        // history users have requested this feature, it\'s only enabled for\n
        // fragment-related params strings.\n
        if ( is_fragment ) {\n
          qs = qs.replace( re_no_escape, decode );\n
        }\n
      }\n
      \n
      // Build URL from the base url, querystring and hash. In \'querystring\'\n
      // mode, ? is only added if a query string exists. In \'fragment\' mode, #\n
      // is always added.\n
      result = matches[1] + ( is_fragment ? \'#\' : qs || !matches[1] ? \'?\' : \'\' ) + qs + hash;\n
      \n
    } else {\n
      // If URL was passed in, parse params from URL string, otherwise parse\n
      // params from window.location.\n
      result = get_func( url !== undefined ? url : window[ str_location ][ str_href ] );\n
    }\n
    \n
    return result;\n
  };\n
  \n
  jq_param[ str_querystring ]                  = curry( jq_param_sub, 0, get_querystring );\n
  jq_param[ str_fragment ] = jq_param_fragment = curry( jq_param_sub, 1, get_fragment );\n
  \n
  // Method: jQuery.param.fragment.noEscape\n
  // \n
  // Specify characters that will be left unescaped when fragments are created\n
  // or merged using <jQuery.param.fragment>, or when the fragment is modified\n
  // using <jQuery.bbq.pushState>. This option only applies to serialized data\n
  // object fragments, and not set-as-string fragments. Does not affect the\n
  // query string. Defaults to ",/" (comma, forward slash).\n
  // \n
  // Note that this is considered a purely aesthetic option, and will help to\n
  // create URLs that "look pretty" in the address bar or bookmarks, without\n
  // affecting functionality in any way. That being said, be careful to not\n
  // unescape characters that are used as delimiters or serve a special\n
  // purpose, such as the "#?&=+" (octothorpe, question mark, ampersand,\n
  // equals, plus) characters.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.param.fragment.noEscape( [ chars ] );\n
  // \n
  // Arguments:\n
  // \n
  //  chars - (String) The characters to not escape in the fragment. If\n
  //    unspecified, defaults to empty string (escape all characters).\n
  // \n
  // Returns:\n
  // \n
  //  Nothing.\n
  \n
  jq_param_fragment.noEscape = function( chars ) {\n
    chars = chars || \'\';\n
    var arr = $.map( chars.split(\'\'), encodeURIComponent );\n
    re_no_escape = new RegExp( arr.join(\'|\'), \'g\' );\n
  };\n
  \n
  // A sensible default. These are the characters people seem to complain about\n
  // "uglifying up the URL" the most.\n
  jq_param_fragment.noEscape( \',/\' );\n
  \n
  // Section: Deparam (from string)\n
  // \n
  // Method: jQuery.deparam\n
  // \n
  // Deserialize a params string into an object, optionally coercing numbers,\n
  // booleans, null and undefined values; this method is the counterpart to the\n
  // internal jQuery.param method.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.deparam( params [, coerce ] );\n
  // \n
  // Arguments:\n
  // \n
  //  params - (String) A params string to be parsed.\n
  //  coerce - (Boolean) If true, coerces any numbers or true, false, null, and\n
  //    undefined to their actual value. Defaults to false if omitted.\n
  // \n
  // Returns:\n
  // \n
  //  (Object) An object representing the deserialized params string.\n
  \n
  $.deparam = jq_deparam = function( params, coerce ) {\n
    var obj = {},\n
      coerce_types = { \'true\': !0, \'false\': !1, \'null\': null };\n
    \n
    // Iterate over all name=value pairs.\n
    $.each( params.replace( /\\+/g, \' \' ).split( \'&\' ), function(j,v){\n
      var param = v.split( \'=\' ),\n
        key = decode( param[0] ),\n
        val,\n
        cur = obj,\n
        i = 0,\n
        \n
        // If key is more complex than \'foo\', like \'a[]\' or \'a[b][c]\', split it\n
        // into its component parts.\n
        keys = key.split( \'][\' ),\n
        keys_last = keys.length - 1;\n
      \n
      // If the first keys part contains [ and the last ends with ], then []\n
      // are correctly balanced.\n
      if ( /\\[/.test( keys[0] ) && /\\]$/.test( keys[ keys_last ] ) ) {\n
        // Remove the trailing ] from the last keys part.\n
        keys[ keys_last ] = keys[ keys_last ].replace( /\\]$/, \'\' );\n
        \n
        // Split first keys part into two parts on the [ and add them back onto\n
        // the beginning of the keys array.\n
        keys = keys.shift().split(\'[\').concat( keys );\n
        \n
        keys_last = keys.length - 1;\n
      } else {\n
        // Basic \'foo\' style key.\n
        keys_last = 0;\n
      }\n
      \n
      // Are we dealing with a name=value pair, or just a name?\n
      if ( param.length === 2 ) {\n
        val = decode( param[1] );\n
        \n
        // Coerce values.\n
        if ( coerce ) {\n
          val = val && !isNaN(val)            ? +val              // number\n
            : val === \'undefined\'             ? undefined         // undefined\n
            : coerce_types[val] !== undefined ? coerce_types[val] // true, false, null\n
            : val;                                                // string\n
        }\n
        \n
        if ( keys_last ) {\n
          // Complex key, build deep object structure based on a few rules:\n
          // * The \'cur\' pointer starts at the object top-level.\n
          // * [] = array push (n is set to array length), [n] = array if n is \n
          //   numeric, otherwise object.\n
          // * If at the last keys part, set the value.\n
          // * For each keys part, if the current level is undefined create an\n
          //   object or array based on the type of the next keys part.\n
          // * Move the \'cur\' pointer to the next level.\n
          // * Rinse & repeat.\n
          for ( ; i <= keys_last; i++ ) {\n
            key = keys[i] === \'\' ? cur.length : keys[i];\n
            cur = cur[key] = i < keys_last\n
              ? cur[key] || ( keys[i+1] && isNaN( keys[i+1] ) ? {} : [] )\n
              : val;\n
          }\n
          \n
        } else {\n
          // Simple key, even simpler rules, since only scalars and shallow\n
          // arrays are allowed.\n
          \n
          if ( $.isArray( obj[key] ) ) {\n
            // val is already an array, so push on the next value.\n
            obj[key].push( val );\n
            \n
          } else if ( obj[key] !== undefined ) {\n
            // val isn\'t an array, but since a second value has been specified,\n
            // convert val into an array.\n
            obj[key] = [ obj[key], val ];\n
            \n
          } else {\n
            // val is a scalar.\n
            obj[key] = val;\n
          }\n
        }\n
        \n
      } else if ( key ) {\n
        // No value was defined, so set something meaningful.\n
        obj[key] = coerce\n
          ? undefined\n
          : \'\';\n
      }\n
    });\n
    \n
    return obj;\n
  };\n
  \n
  // Method: jQuery.deparam.querystring\n
  // \n
  // Parse the query string from a URL or the current window.location,\n
  // deserializing it into an object, optionally coercing numbers, booleans,\n
  // null and undefined values.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.deparam.querystring( [ url ] [, coerce ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) An optional params string or URL containing query string\n
  //    params to be parsed. If url is omitted, the current window.location\n
  //    is used.\n
  //  coerce - (Boolean) If true, coerces any numbers or true, false, null, and\n
  //    undefined to their actual value. Defaults to false if omitted.\n
  // \n
  // Returns:\n
  // \n
  //  (Object) An object representing the deserialized params string.\n
  \n
  // Method: jQuery.deparam.fragment\n
  // \n
  // Parse the fragment (hash) from a URL or the current window.location,\n
  // deserializing it into an object, optionally coercing numbers, booleans,\n
  // null and undefined values.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.deparam.fragment( [ url ] [, coerce ] );\n
  // \n
  // Arguments:\n
  // \n
  //  url - (String) An optional params string or URL containing fragment (hash)\n
  //    params to be parsed. If url is omitted, the current window.location\n
  //    is used.\n
  //  coerce - (Boolean) If true, coerces any numbers or true, false, null, and\n
  //    undefined to their actual value. Defaults to false if omitted.\n
  // \n
  // Returns:\n
  // \n
  //  (Object) An object representing the deserialized params string.\n
  \n
  function jq_deparam_sub( is_fragment, url_or_params, coerce ) {\n
    if ( url_or_params === undefined || typeof url_or_params === \'boolean\' ) {\n
      // url_or_params not specified.\n
      coerce = url_or_params;\n
      url_or_params = jq_param[ is_fragment ? str_fragment : str_querystring ]();\n
    } else {\n
      url_or_params = is_string( url_or_params )\n
        ? url_or_params.replace( is_fragment ? re_trim_fragment : re_trim_querystring, \'\' )\n
        : url_or_params;\n
    }\n
    \n
    return jq_deparam( url_or_params, coerce );\n
  };\n
  \n
  jq_deparam[ str_querystring ]                    = curry( jq_deparam_sub, 0 );\n
  jq_deparam[ str_fragment ] = jq_deparam_fragment = curry( jq_deparam_sub, 1 );\n
  \n
  // Section: Element manipulation\n
  // \n
  // Method: jQuery.elemUrlAttr\n
  // \n
  // Get the internal "Default URL attribute per tag" list, or augment the list\n
  // with additional tag-attribute pairs, in case the defaults are insufficient.\n
  // \n
  // In the <jQuery.fn.querystring> and <jQuery.fn.fragment> methods, this list\n
  // is used to determine which attribute contains the URL to be modified, if\n
  // an "attr" param is not specified.\n
  // \n
  // Default Tag-Attribute List:\n
  // \n
  //  a      - href\n
  //  base   - href\n
  //  iframe - src\n
  //  img    - src\n
  //  input  - src\n
  //  form   - action\n
  //  link   - href\n
  //  script - src\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.elemUrlAttr( [ tag_attr ] );\n
  // \n
  // Arguments:\n
  // \n
  //  tag_attr - (Object) An object containing a list of tag names and their\n
  //    associated default attribute names in the format { tag: \'attr\', ... } to\n
  //    be merged into the internal tag-attribute list.\n
  // \n
  // Returns:\n
  // \n
  //  (Object) An object containing all stored tag-attribute values.\n
  \n
  // Only define function and set defaults if function doesn\'t already exist, as\n
  // the urlInternal plugin will provide this method as well.\n
  $[ str_elemUrlAttr ] || ($[ str_elemUrlAttr ] = function( obj ) {\n
    return $.extend( elemUrlAttr_cache, obj );\n
  })({\n
    a: str_href,\n
    base: str_href,\n
    iframe: str_src,\n
    img: str_src,\n
    input: str_src,\n
    form: \'action\',\n
    link: str_href,\n
    script: str_src\n
  });\n
  \n
  jq_elemUrlAttr = $[ str_elemUrlAttr ];\n
  \n
  // Method: jQuery.fn.querystring\n
  // \n
  // Update URL attribute in one or more elements, merging the current URL (with\n
  // or without pre-existing query string params) plus any params object or\n
  // string into a new URL, which is then set into that attribute. Like\n
  // <jQuery.param.querystring (build url)>, but for all elements in a jQuery\n
  // collection.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery(\'selector\').querystring( [ attr, ] params [, merge_mode ] );\n
  // \n
  // Arguments:\n
  // \n
  //  attr - (String) Optional name of an attribute that will contain a URL to\n
  //    merge params or url into. See <jQuery.elemUrlAttr> for a list of default\n
  //    attributes.\n
  //  params - (Object) A params object to be merged into the URL attribute.\n
  //  params - (String) A URL containing query string params, or params string\n
  //    to be merged into the URL attribute.\n
  //  merge_mode - (Number) Merge behavior defaults to 0 if merge_mode is not\n
  //    specified, and is as-follows:\n
  //    \n
  //    * 0: params in the params argument will override any params in attr URL.\n
  //    * 1: any params in attr URL will override params in the params argument.\n
  //    * 2: params argument will completely replace any query string in attr\n
  //         URL.\n
  // \n
  // Returns:\n
  // \n
  //  (jQuery) The initial jQuery collection of elements, but with modified URL\n
  //  attribute values.\n
  \n
  // Method: jQuery.fn.fragment\n
  // \n
  // Update URL attribute in one or more elements, merging the current URL (with\n
  // or without pre-existing fragment/hash params) plus any params object or\n
  // string into a new URL, which is then set into that attribute. Like\n
  // <jQuery.param.fragment (build url)>, but for all elements in a jQuery\n
  // collection.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery(\'selector\').fragment( [ attr, ] params [, merge_mode ] );\n
  // \n
  // Arguments:\n
  // \n
  //  attr - (String) Optional name of an attribute that will contain a URL to\n
  //    merge params into. See <jQuery.elemUrlAttr> for a list of default\n
  //    attributes.\n
  //  params - (Object) A params object to be merged into the URL attribute.\n
  //  params - (String) A URL containing fragment (hash) params, or params\n
  //    string to be merged into the URL attribute.\n
  //  merge_mode - (Number) Merge behavior defaults to 0 if merge_mode is not\n
  //    specified, and is as-follows:\n
  //    \n
  //    * 0: params in the params argument will override any params in attr URL.\n
  //    * 1: any params in attr URL will override params in the params argument.\n
  //    * 2: params argument will completely replace any fragment (hash) in attr\n
  //         URL.\n
  // \n
  // Returns:\n
  // \n
  //  (jQuery) The initial jQuery collection of elements, but with modified URL\n
  //  attribute values.\n
  \n
  function jq_fn_sub( mode, force_attr, params, merge_mode ) {\n
    if ( !is_string( params ) && typeof params !== \'object\' ) {\n
      // force_attr not specified.\n
      merge_mode = params;\n
      params = force_attr;\n
      force_attr = undefined;\n
    }\n
    \n
    return this.each(function(){\n
      var that = $(this),\n
        \n
        // Get attribute specified, or default specified via $.elemUrlAttr.\n
        attr = force_attr || jq_elemUrlAttr()[ ( this.nodeName || \'\' ).toLowerCase() ] || \'\',\n
        \n
        // Get URL value.\n
        url = attr && that.attr( attr ) || \'\';\n
      \n
      // Update attribute with new URL.\n
      that.attr( attr, jq_param[ mode ]( url, params, merge_mode ) );\n
    });\n
    \n
  };\n
  \n
  $.fn[ str_querystring ] = curry( jq_fn_sub, str_querystring );\n
  $.fn[ str_fragment ]    = curry( jq_fn_sub, str_fragment );\n
  \n
  // Section: History, hashchange event\n
  // \n
  // Method: jQuery.bbq.pushState\n
  // \n
  // Adds a \'state\' into the browser history at the current position, setting\n
  // location.hash and triggering any bound <hashchange event> callbacks\n
  // (provided the new state is different than the previous state).\n
  // \n
  // If no arguments are passed, an empty state is created, which is just a\n
  // shortcut for jQuery.bbq.pushState( {}, 2 ).\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.bbq.pushState( [ params [, merge_mode ] ] );\n
  // \n
  // Arguments:\n
  // \n
  //  params - (String) A serialized params string or a hash string beginning\n
  //    with # to merge into location.hash.\n
  //  params - (Object) A params object to merge into location.hash.\n
  //  merge_mode - (Number) Merge behavior defaults to 0 if merge_mode is not\n
  //    specified (unless a hash string beginning with # is specified, in which\n
  //    case merge behavior defaults to 2), and is as-follows:\n
  // \n
  //    * 0: params in the params argument will override any params in the\n
  //         current state.\n
  //    * 1: any params in the current state will override params in the params\n
  //         argument.\n
  //    * 2: params argument will completely replace current state.\n
  // \n
  // Returns:\n
  // \n
  //  Nothing.\n
  // \n
  // Additional Notes:\n
  // \n
  //  * Setting an empty state may cause the browser to scroll.\n
  //  * Unlike the fragment and querystring methods, if a hash string beginning\n
  //    with # is specified as the params agrument, merge_mode defaults to 2.\n
  \n
  jq_bbq.pushState = jq_bbq_pushState = function( params, merge_mode ) {\n
    if ( is_string( params ) && /^#/.test( params ) && merge_mode === undefined ) {\n
      // Params string begins with # and merge_mode not specified, so completely\n
      // overwrite window.location.hash.\n
      merge_mode = 2;\n
    }\n
    \n
    var has_args = params !== undefined,\n
      // Merge params into window.location using $.param.fragment.\n
      url = jq_param_fragment( window[ str_location ][ str_href ],\n
        has_args ? params : {}, has_args ? merge_mode : 2 );\n
    \n
    // Set new window.location.href. If hash is empty, use just # to prevent\n
    // browser from reloading the page. Note that Safari 3 & Chrome barf on\n
    // location.hash = \'#\'.\n
    window[ str_location ][ str_href ] = url + ( /#/.test( url ) ? \'\' : \'#\' );\n
  };\n
  \n
  // Method: jQuery.bbq.getState\n
  // \n
  // Retrieves the current \'state\' from the browser history, parsing\n
  // location.hash for a specific key or returning an object containing the\n
  // entire state, optionally coercing numbers, booleans, null and undefined\n
  // values.\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.bbq.getState( [ key ] [, coerce ] );\n
  // \n
  // Arguments:\n
  // \n
  //  key - (String) An optional state key for which to return a value.\n
  //  coerce - (Boolean) If true, coerces any numbers or true, false, null, and\n
  //    undefined to their actual value. Defaults to false.\n
  // \n
  // Returns:\n
  // \n
  //  (Anything) If key is passed, returns the value corresponding with that key\n
  //    in the location.hash \'state\', or undefined. If not, an object\n
  //    representing the entire \'state\' is returned.\n
  \n
  jq_bbq.getState = jq_bbq_getState = function( key, coerce ) {\n
    return key === undefined || typeof key === \'boolean\'\n
      ? jq_deparam_fragment( key ) // \'key\' really means \'coerce\' here\n
      : jq_deparam_fragment( coerce )[ key ];\n
  };\n
  \n
  // Method: jQuery.bbq.removeState\n
  // \n
  // Remove one or more keys from the current browser history \'state\', creating\n
  // a new state, setting location.hash and triggering any bound\n
  // <hashchange event> callbacks (provided the new state is different than\n
  // the previous state).\n
  // \n
  // If no arguments are passed, an empty state is created, which is just a\n
  // shortcut for jQuery.bbq.pushState( {}, 2 ).\n
  // \n
  // Usage:\n
  // \n
  // > jQuery.bbq.removeState( [ key [, key ... ] ] );\n
  // \n
  // Arguments:\n
  // \n
  //  key - (String) One or more key values to remove from the current state,\n
  //    passed as individual arguments.\n
  //  key - (Array) A single array argument that contains a list of key values\n
  //    to remove from the current state.\n
  // \n
  // Returns:\n
  // \n
  //  Nothing.\n
  // \n
  // Additional Notes:\n
  // \n
  //  * Setting an empty state may cause the browser to scroll.\n
  \n
  jq_bbq.removeState = function( arr ) {\n
    var state = {};\n
    \n
    // If one or more arguments is passed..\n
    if ( arr !== undefined ) {\n
      \n
      // Get the current state.\n
      state = jq_bbq_getState();\n
      \n
      // For each passed key, delete the corresponding property from the current\n
      // state.\n
      $.each( $.isArray( arr ) ? arr : arguments, function(i,v){\n
        delete state[ v ];\n
      });\n
    }\n
    \n
    // Set the state, completely overriding any existing state.\n
    jq_bbq_pushState( state, 2 );\n
  };\n
  \n
  // Event: hashchange event (BBQ)\n
  // \n
  // Usage in jQuery 1.4 and newer:\n
  // \n
  // In jQuery 1.4 and newer, the event object passed into any hashchange event\n
  // callback is augmented with a copy of the location.hash fragment at the time\n
  // the event was triggered as its event.fragment property. In addition, the\n
  // event.getState method operates on this property (instead of location.hash)\n
  // which allows this fragment-as-a-state to be referenced later, even after\n
  // window.location may have changed.\n
  // \n
  // Note that event.fragment and event.getState are not defined according to\n
  // W3C (or any other) specification, but will still be available whether or\n
  // not the hashchange event exists natively in the browser, because of the\n
  // utility they provide.\n
  // \n
  // The event.fragment property contains the output of <jQuery.param.fragment>\n
  // and the event.getState method is equivalent to the <jQuery.bbq.getState>\n
  // method.\n
  // \n
  // > $(window).bind( \'hashchange\', function( event ) {\n
  // >   var hash_str = event.fragment,\n
  // >     param_obj = event.getState(),\n
  // >     param_val = event.getState( \'param_name\' ),\n
  // >     param_val_coerced = event.getState( \'param_name\', true );\n
  // >   ...\n
  // > });\n
  // \n
  // Usage in jQuery 1.3.2:\n
  // \n
  // In jQuery 1.3.2, the event object cannot to be augmented as in jQuery 1.4+,\n
  // so the fragment state isn\'t bound to the event object and must instead be\n
  // parsed using the <jQuery.param.fragment> and <jQuery.bbq.getState> methods.\n
  // \n
  // > $(window).bind( \'hashchange\', function( event ) {\n
  // >   var hash_str = $.param.fragment(),\n
  // >     param_obj = $.bbq.getState(),\n
  // >     param_val = $.bbq.getState( \'param_name\' ),\n
  // >     param_val_coerced = $.bbq.getState( \'param_name\', true );\n
  // >   ...\n
  // > });\n
  // \n
  // Additional Notes:\n
  // \n
  // * Due to changes in the special events API, jQuery BBQ v1.2 or newer is\n
  //   required to enable the augmented event object in jQuery 1.4.2 and newer.\n
  // * See <jQuery hashchange event> for more detailed information.\n
  \n
  jq_event_special[ str_hashchange ] = $.extend( jq_event_special[ str_hashchange ], {\n
    \n
    // Augmenting the event object with the .fragment property and .getState\n
    // method requires jQuery 1.4 or newer. Note: with 1.3.2, everything will\n
    // work, but the event won\'t be augmented)\n
    add: function( handleObj ) {\n
      var old_handler;\n
      \n
      function new_handler(e) {\n
        // e.fragment is set to the value of location.hash (with any leading #\n
        // removed) at the time the event is triggered.\n
        var hash = e[ str_fragment ] = jq_param_fragment();\n
        \n
        // e.getState() works just like $.bbq.getState(), but uses the\n
        // e.fragment property stored on the event object.\n
        e.getState = function( key, coerce ) {\n
          return key === undefined || typeof key === \'boolean\'\n
            ? jq_deparam( hash, key ) // \'key\' really means \'coerce\' here\n
            : jq_deparam( hash, coerce )[ key ];\n
        };\n
        \n
        old_handler.apply( this, arguments );\n
      };\n
      \n
      // This may seem a little complicated, but it normalizes the special event\n
      // .add method between jQuery 1.4/1.4.1 and 1.4.2+\n
      if ( $.isFunction( handleObj ) ) {\n
        // 1.4, 1.4.1\n
        old_handler = handleObj;\n
        return new_handler;\n
      } else {\n
        // 1.4.2+\n
        old_handler = handleObj.handler;\n
        handleObj.handler = new_handler;\n
      }\n
    }\n
    \n
  });\n
  \n
})(jQuery,this);\n
\n
/*!\n
 * jQuery hashchange event - v1.2 - 2/11/2010\n
 * http://benalman.com/projects/jquery-hashchange-plugin/\n
 * \n
 * Copyright (c) 2010 "Cowboy" Ben Alman\n
 * Dual licensed under the MIT and GPL licenses.\n
 * http://benalman.com/about/license/\n
 */\n
\n
// Script: jQuery hashchange event\n
//\n
// *Version: 1.2, Last updated: 2/11/2010*\n
// \n
// Project Home - http://benalman.com/projects/jquery-hashchange-plugin/\n
// GitHub       - http://github.com/cowboy/jquery-hashchange/\n
// Source       - http://github.com/cowboy/jquery-hashchange/raw/master/jquery.ba-hashchange.js\n
// (Minified)   - http://github.com/cowboy/jquery-hashchange/raw/master/jquery.ba-hashchange.min.js (1.1kb)\n
// \n
// About: License\n
// \n
// Copyright (c) 2010 "Cowboy" Ben Alman,\n
// Dual licensed under the MIT and GPL licenses.\n
// http://benalman.com/about/license/\n
// \n
// About: Examples\n
// \n
// This working example, complete with fully commented code, illustrate one way\n
// in which this plugin can be used.\n
// \n
// hashchange event - http://benalman.com/code/projects/jquery-hashchange/examples/hashchange/\n
// \n
// About: Support and Testing\n
// \n
// Information about what version or versions of jQuery this plugin has been\n
// tested with, what browsers it has been tested in, and where the unit tests\n
// reside (so you can test it yourself).\n
// \n
// jQuery Versions - 1.3.2, 1.4.1, 1.4.2\n
// Browsers Tested - Internet Explorer 6-8, Firefox 2-3.7, Safari 3-4, Chrome, Opera 9.6-10.1.\n
// Unit Tests      - http://benalman.com/code/projects/jquery-hashchange/unit/\n
// \n
// About: Known issues\n
// \n
// While this jQuery hashchange event implementation is quite stable and robust,\n
// there are a few unfortunate browser bugs surrounding expected hashchange\n
// event-based behaviors, independent of any JavaScript window.onhashchange\n
// abstraction. See the following examples for more information:\n
// \n
// Chrome: Back Button - http://benalman.com/code/projects/jquery-hashchange/examples/bug-chrome-back-button/\n
// Firefox: Remote XMLHttpRequest - http://benalman.com/code/projects/jquery-hashchange/examples/bug-firefox-remote-xhr/\n
// WebKit: Back Button in an Iframe - http://benalman.com/code/projects/jquery-hashchange/examples/bug-webkit-hash-iframe/\n
// Safari: Back Button from a different domain - http://benalman.com/code/projects/jquery-hashchange/examples/bug-safari-back-from-diff-domain/\n
// \n
// About: Release History\n
// \n
// 1.2   - (2/11/2010) Fixed a bug where coming back to a page using this plugin\n
//         from a page on another domain would cause an error in Safari 4. Also,\n
//         IE6/7 Iframe is now inserted after the body (this actually works),\n
//         which prevents the page from scrolling when the event is first bound.\n
//         Event can also now be bound before DOM ready, but it won\'t be usable\n
//         before then in IE6/7.\n
// 1.1   - (1/21/2010) Incorporated document.documentMode test to fix IE8 bug\n
//         where browser version is incorrectly reported as 8.0, despite\n
//         inclusion of the X-UA-Compatible IE=EmulateIE7 meta tag.\n
// 1.0   - (1/9/2010) Initial Release. Broke out the jQuery BBQ event.special\n
//         window.onhashchange functionality into a separate plugin for users\n
//         who want just the basic event & back button support, without all the\n
//         extra awesomeness that BBQ provides. This plugin will be included as\n
//         part of jQuery BBQ, but also be available separately.\n
\n
(function($,window,undefined){\n
  \'$:nomunge\'; // Used by YUI compressor.\n
  \n
  // Method / object references.\n
  var fake_onhashchange,\n
    jq_event_special = $.event.special,\n
    \n
    // Reused strings.\n
    str_location = \'location\',\n
    str_hashchange = \'hashchange\',\n
    str_href = \'href\',\n
    \n
    // IE6/7 specifically need some special love when it comes to back-button\n
    // support, so let\'s do a little browser sniffing..\n
    mode = document.documentMode,\n
    is_old_ie = (navigator.userAgent.match(/MSIE/i) !== null) && ( mode === undefined || mode < 8 ),\n
    \n
    // Does the browser support window.onhashchange? Test for IE version, since\n
    // IE8 incorrectly reports this when in "IE7" or "IE8 Compatibility View"!\n
    supports_onhashchange = \'on\' + str_hashchange in window && !is_old_ie;\n
  \n
  // Get location.hash (or what you\'d expect location.hash to be) sans any\n
  // leading #. Thanks for making this necessary, Firefox!\n
  function get_fragment( url ) {\n
    url = url || window[ str_location ][ str_href ];\n
    return url.replace( /^[^#]*#?(.*)$/, \'$1\' );\n
  };\n
  \n
  // Property: jQuery.hashchangeDelay\n
  // \n
  // The numeric interval (in milliseconds) at which the <hashchange event>\n
  // polling loop executes. Defaults to 100.\n
  \n
  $[ str_hashchange + \'Delay\' ] = 100;\n
  \n
  // Event: hashchange event\n
  // \n
  // Fired when location.hash changes. In browsers that support it, the native\n
  // window.onhashchange event is used (IE8, FF3.6), otherwise a polling loop is\n
  // initialized, running every <jQuery.hashchangeDelay> milliseconds to see if\n
  // the hash has changed. In IE 6 and 7, a hidden Iframe is created to allow\n
  // the back button and hash-based history to work.\n
  // \n
  // Usage:\n
  // \n
  // > $(window).bind( \'hashchange\', function(e) {\n
  // >   var hash = location.hash;\n
  // >   ...\n
  // > });\n
  // \n
  // Additional Notes:\n
  // \n
  // * The polling loop and Iframe are not created until at least one callback\n
  //   is actually bound to \'hashchange\'.\n
  // * If you need the bound callback(s) to execute immediately, in cases where\n
  //   the page \'state\' exists on page load (via bookmark or page refresh, for\n
  //   example) use $(window).trigger( \'hashchange\' );\n
  // * The event can be bound before DOM ready, but since it won\'t be usable\n
  //   before then in IE6/7 (due to the necessary Iframe), recommended usage is\n
  //   to bind it inside a $(document).ready() callback.\n
  \n
  jq_event_special[ str_hashchange ] = $.extend( jq_event_special[ str_hashchange ], {\n
    \n
    // Called only when the first \'hashchange\' event is bound to window.\n
    setup: function() {\n
      // If window.onhashchange is supported natively, there\'s nothing to do..\n
      if ( supports_onhashchange ) { return false; }\n
      \n
      // Otherwise, we need to create our own. And we don\'t want to call this\n
      // until the user binds to the event, just in case they never do, since it\n
      // will create a polling loop and possibly even a hidden Iframe.\n
      $( fake_onhashchange.start );\n
    },\n
    \n
    // Called only when the last \'hashchange\' event is unbound from window.\n
    teardown: function() {\n
      // If window.onhashchange is supported natively, there\'s nothing to do..\n
      if ( supports_onhashchange ) { return false; }\n
      \n
      // Otherwise, we need to stop ours (if possible).\n
      $( fake_onhashchange.stop );\n
    }\n
    \n
  });\n
  \n
  // fake_onhashchange does all the work of triggering the window.onhashchange\n
  // event for browsers that don\'t natively support it, including creating a\n
  // polling loop to watch for hash changes and in IE 6/7 creating a hidden\n
  // Iframe to enable back and forward.\n
  fake_onhashchange = (function(){\n
    var self = {},\n
      timeout_id,\n
      iframe,\n
      set_history,\n
      get_history;\n
    \n
    // Initialize. In IE 6/7, creates a hidden Iframe for history handling.\n
    function init(){\n
      // Most browsers don\'t need special methods here..\n
      set_history = get_history = function(val){ return val; };\n
      \n
      // But IE6/7 do!\n
      if ( is_old_ie ) {\n
        \n
        // Create hidden Iframe after the end of the body to prevent initial\n
        // page load from scrolling unnecessarily.\n
        iframe = $(\'<iframe src="javascript:0"/>\').hide().insertAfter( \'body\' )[0].contentWindow;\n
        \n
        // Get history by looking at the hidden Iframe\'s location.hash.\n
        get_history = function() {\n
          return get_fragment( iframe.document[ str_location ][ str_href ] );\n
        };\n
        \n
        // Set a new history item by opening and then closing the Iframe\n
        // document, *then* setting its location.hash.\n
        set_history = function( hash, history_hash ) {\n
          if ( hash !== history_hash ) {\n
            var doc = iframe.document;\n
            doc.open().close();\n
            doc[ str_location ].hash = \'#\' + hash;\n
          }\n
        };\n
        \n
        // Set initial history.\n
        set_history( get_fragment() );\n
      }\n
    };\n
    \n
    // Start the polling loop.\n
    self.start = function() {\n
      // Polling loop is already running!\n
      if ( timeout_id ) { return; }\n
      \n
      // Remember the initial hash so it doesn\'t get triggered immediately.\n
      var last_hash = get_fragment();\n
      \n
      // Initialize if not yet initialized.\n
      set_history || init();\n
      \n
      // This polling loop checks every $.hashchangeDelay milliseconds to see if\n
      // location.hash has changed, and triggers the \'hashchange\' event on\n
      // window when necessary.\n
      (function loopy(){\n
        var hash = get_fragment(),\n
          history_hash = get_history( last_hash );\n
        \n
        if ( hash !== last_hash ) {\n
          set_history( last_hash = hash, history_hash );\n
          \n
          $(window).trigger( str_hashchange );\n
          \n
        } else if ( history_hash !== last_hash ) {\n
          window[ str_location ][ str_href ] = window[ str_location ][ str_href ].replace( /#.*/, \'\' ) + \'#\' + history_hash;\n
        }\n
        \n
        timeout_id = setTimeout( loopy, $[ str_hashchange + \'Delay\' ] );\n
      })();\n
    };\n
    \n
    // Stop the polling loop, but only if an IE6/7 Iframe wasn\'t created. In\n
    // that case, even if there are no longer any bound event handlers, the\n
    // polling loop is still necessary for back/next to work at all!\n
    self.stop = function() {\n
      if ( !iframe ) {\n
        timeout_id && clearTimeout( timeout_id );\n
        timeout_id = 0;\n
      }\n
    };\n
    \n
    return self;\n
  })();\n
  \n
})(jQuery,this);\n
\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>43257</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>bbq.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
