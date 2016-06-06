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
            <value> <string>ts94102736.51</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.cookie.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*!\n
 * jQuery Cookie Plugin v1.4.0\n
 * https://github.com/carhartl/jquery-cookie\n
 *\n
 * Copyright 2013 Klaus Hartl\n
 * Released under the MIT license\n
 */\n
(function (factory) {\n
\tif (typeof define === \'function\' && define.amd) {\n
\t\t// AMD. Register as anonymous module.\n
\t\tdefine([\'jquery\'], factory);\n
\t} else {\n
\t\t// Browser globals.\n
\t\tfactory(jQuery);\n
\t}\n
}(function ($) {\n
\n
\tvar pluses = /\\+/g;\n
\n
\tfunction encode(s) {\n
\t\treturn config.raw ? s : encodeURIComponent(s);\n
\t}\n
\n
\tfunction decode(s) {\n
\t\treturn config.raw ? s : decodeURIComponent(s);\n
\t}\n
\n
\tfunction stringifyCookieValue(value) {\n
\t\treturn encode(config.json ? JSON.stringify(value) : String(value));\n
\t}\n
\n
\tfunction parseCookieValue(s) {\n
\t\tif (s.indexOf(\'"\') === 0) {\n
\t\t\t// This is a quoted cookie as according to RFC2068, unescape...\n
\t\t\ts = s.slice(1, -1).replace(/\\\\"/g, \'"\').replace(/\\\\\\\\/g, \'\\\\\');\n
\t\t}\n
\n
\t\ttry {\n
\t\t\t// Replace server-side written pluses with spaces.\n
\t\t\t// If we can\'t decode the cookie, ignore it, it\'s unusable.\n
\t\t\ts = decodeURIComponent(s.replace(pluses, \' \'));\n
\t\t} catch(e) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\ttry {\n
\t\t\t// If we can\'t parse the cookie, ignore it, it\'s unusable.\n
\t\t\treturn config.json ? JSON.parse(s) : s;\n
\t\t} catch(e) {}\n
\t}\n
\n
\tfunction read(s, converter) {\n
\t\tvar value = config.raw ? s : parseCookieValue(s);\n
\t\treturn $.isFunction(converter) ? converter(value) : value;\n
\t}\n
\n
\tvar config = $.cookie = function (key, value, options) {\n
\n
\t\t// Write\n
\t\tif (value !== undefined && !$.isFunction(value)) {\n
\t\t\toptions = $.extend({}, config.defaults, options);\n
\n
\t\t\tif (typeof options.expires === \'number\') {\n
\t\t\t\tvar days = options.expires, t = options.expires = new Date();\n
\t\t\t\tt.setDate(t.getDate() + days);\n
\t\t\t}\n
\n
\t\t\treturn (document.cookie = [\n
\t\t\t\tencode(key), \'=\', stringifyCookieValue(value),\n
\t\t\t\toptions.expires ? \'; expires=\' + options.expires.toUTCString() : \'\', // use expires attribute, max-age is not supported by IE\n
\t\t\t\toptions.path    ? \'; path=\' + options.path : \'\',\n
\t\t\t\toptions.domain  ? \'; domain=\' + options.domain : \'\',\n
\t\t\t\toptions.secure  ? \'; secure\' : \'\'\n
\t\t\t].join(\'\'));\n
\t\t}\n
\n
\t\t// Read\n
\n
\t\tvar result = key ? undefined : {};\n
\n
\t\t// To prevent the for loop in the first place assign an empty array\n
\t\t// in case there are no cookies at all. Also prevents odd result when\n
\t\t// calling $.cookie().\n
\t\tvar cookies = document.cookie ? document.cookie.split(\'; \') : [];\n
\n
\t\tfor (var i = 0, l = cookies.length; i < l; i++) {\n
\t\t\tvar parts = cookies[i].split(\'=\');\n
\t\t\tvar name = decode(parts.shift());\n
\t\t\tvar cookie = parts.join(\'=\');\n
\n
\t\t\tif (key && key === name) {\n
\t\t\t\t// If second argument (value) is a function it\'s a converter...\n
\t\t\t\tresult = read(cookie, value);\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\t// Prevent storing a cookie that we couldn\'t decode.\n
\t\t\tif (!key && (cookie = read(cookie)) !== undefined) {\n
\t\t\t\tresult[name] = cookie;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn result;\n
\t};\n
\n
\tconfig.defaults = {};\n
\n
\t$.removeCookie = function (key, options) {\n
\t\tif ($.cookie(key) !== undefined) {\n
\t\t\t// Must not alter options, thus extending a fresh object...\n
\t\t\t$.cookie(key, \'\', $.extend({}, options, { expires: -1 }));\n
\t\t\treturn true;\n
\t\t}\n
\t\treturn false;\n
\t};\n
\n
}));\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3095</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
