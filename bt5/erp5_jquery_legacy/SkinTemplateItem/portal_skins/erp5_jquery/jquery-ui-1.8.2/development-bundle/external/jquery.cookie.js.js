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
            <value> <string>ts77895651.69</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.cookie.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*jslint browser: true */ /*global jQuery: true */\n
\n
/**\n
 * jQuery Cookie plugin\n
 *\n
 * Copyright (c) 2010 Klaus Hartl (stilbuero.de)\n
 * Dual licensed under the MIT and GPL licenses:\n
 * http://www.opensource.org/licenses/mit-license.php\n
 * http://www.gnu.org/licenses/gpl.html\n
 *\n
 */\n
\n
// TODO JsDoc\n
\n
/**\n
 * Create a cookie with the given key and value and other optional parameters.\n
 *\n
 * @example $.cookie(\'the_cookie\', \'the_value\');\n
 * @desc Set the value of a cookie.\n
 * @example $.cookie(\'the_cookie\', \'the_value\', { expires: 7, path: \'/\', domain: \'jquery.com\', secure: true });\n
 * @desc Create a cookie with all available options.\n
 * @example $.cookie(\'the_cookie\', \'the_value\');\n
 * @desc Create a session cookie.\n
 * @example $.cookie(\'the_cookie\', null);\n
 * @desc Delete a cookie by passing null as value. Keep in mind that you have to use the same path and domain\n
 *       used when the cookie was set.\n
 *\n
 * @param String key The key of the cookie.\n
 * @param String value The value of the cookie.\n
 * @param Object options An object literal containing key/value pairs to provide optional cookie attributes.\n
 * @option Number|Date expires Either an integer specifying the expiration date from now on in days or a Date object.\n
 *                             If a negative value is specified (e.g. a date in the past), the cookie will be deleted.\n
 *                             If set to null or omitted, the cookie will be a session cookie and will not be retained\n
 *                             when the the browser exits.\n
 * @option String path The value of the path atribute of the cookie (default: path of page that created the cookie).\n
 * @option String domain The value of the domain attribute of the cookie (default: domain of page that created the cookie).\n
 * @option Boolean secure If true, the secure attribute of the cookie will be set and the cookie transmission will\n
 *                        require a secure protocol (like HTTPS).\n
 * @type undefined\n
 *\n
 * @name $.cookie\n
 * @cat Plugins/Cookie\n
 * @author Klaus Hartl/klaus.hartl@stilbuero.de\n
 */\n
\n
/**\n
 * Get the value of a cookie with the given key.\n
 *\n
 * @example $.cookie(\'the_cookie\');\n
 * @desc Get the value of a cookie.\n
 *\n
 * @param String key The key of the cookie.\n
 * @return The value of the cookie.\n
 * @type String\n
 *\n
 * @name $.cookie\n
 * @cat Plugins/Cookie\n
 * @author Klaus Hartl/klaus.hartl@stilbuero.de\n
 */\n
jQuery.cookie = function (key, value, options) {\n
\n
    // key and value given, set cookie...\n
    if (arguments.length > 1 && (value === null || typeof value !== "object")) {\n
        options = jQuery.extend({}, options);\n
\n
        if (value === null) {\n
            options.expires = -1;\n
        }\n
\n
        if (typeof options.expires === \'number\') {\n
            var days = options.expires, t = options.expires = new Date();\n
            t.setDate(t.getDate() + days);\n
        }\n
\n
        return (document.cookie = [\n
            encodeURIComponent(key), \'=\',\n
            options.raw ? String(value) : encodeURIComponent(String(value)),\n
            options.expires ? \'; expires=\' + options.expires.toUTCString() : \'\', // use expires attribute, max-age is not supported by IE\n
            options.path ? \'; path=\' + options.path : \'\',\n
            options.domain ? \'; domain=\' + options.domain : \'\',\n
            options.secure ? \'; secure\' : \'\'\n
].join(\'\'));\n
    }\n
\n
    // key and possibly options given, get cookie...\n
    options = value || {};\n
    var result, decode = options.raw ? function (s) { return s; } : decodeURIComponent;\n
    return (result = new RegExp(\'(?:^|; )\' + encodeURIComponent(key) + \'=([^;]*)\').exec(document.cookie)) ? decode(result[1]) : null;\n
};\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3655</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
