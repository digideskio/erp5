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
            <value> <string>ts65545387.07</string> </value>
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

/**\n
 * Cookie plugin\n
 *\n
 * Copyright (c) 2006 Klaus Hartl (stilbuero.de)\n
 * Dual licensed under the MIT and GPL licenses:\n
 * http://www.opensource.org/licenses/mit-license.php\n
 * http://www.gnu.org/licenses/gpl.html\n
 *\n
 */\n
\n
/**\n
 * Create a cookie with the given name and value and other optional parameters.\n
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
 * @param String name The name of the cookie.\n
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
 * Get the value of a cookie with the given name.\n
 *\n
 * @example $.cookie(\'the_cookie\');\n
 * @desc Get the value of a cookie.\n
 *\n
 * @param String name The name of the cookie.\n
 * @return The value of the cookie.\n
 * @type String\n
 *\n
 * @name $.cookie\n
 * @cat Plugins/Cookie\n
 * @author Klaus Hartl/klaus.hartl@stilbuero.de\n
 */\n
jQuery.cookie = function(name, value, options) {\n
    if (typeof value != \'undefined\') { // name and value given, set cookie\n
        options = options || {};\n
        if (value === null) {\n
            value = \'\';\n
            options = $.extend({}, options); // clone object since it\'s unexpected behavior if the expired property were changed\n
            options.expires = -1;\n
        }\n
        var expires = \'\';\n
        if (options.expires && (typeof options.expires == \'number\' || options.expires.toUTCString)) {\n
            var date;\n
            if (typeof options.expires == \'number\') {\n
                date = new Date();\n
                date.setTime(date.getTime() + (options.expires * 24 * 60 * 60 * 1000));\n
            } else {\n
                date = options.expires;\n
            }\n
            expires = \'; expires=\' + date.toUTCString(); // use expires attribute, max-age is not supported by IE\n
        }\n
        // NOTE Needed to parenthesize options.path and options.domain\n
        // in the following expressions, otherwise they evaluate to undefined\n
        // in the packed version for some reason...\n
        var path = options.path ? \'; path=\' + (options.path) : \'\';\n
        var domain = options.domain ? \'; domain=\' + (options.domain) : \'\';\n
        var secure = options.secure ? \'; secure\' : \'\';\n
        document.cookie = [name, \'=\', encodeURIComponent(value), expires, path, domain, secure].join(\'\');\n
    } else { // only name given, get cookie\n
        var cookieValue = null;\n
        if (document.cookie && document.cookie != \'\') {\n
            var cookies = document.cookie.split(\';\');\n
            for (var i = 0; i < cookies.length; i++) {\n
                var cookie = jQuery.trim(cookies[i]);\n
                // Does this cookie string begin with the name we want?\n
                if (cookie.substring(0, name.length + 1) == (name + \'=\')) {\n
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));\n
                    break;\n
                }\n
            }\n
        }\n
        return cookieValue;\n
    }\n
};

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <long>4371</long> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
