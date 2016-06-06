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
            <value> <string>ts83646622.57</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-themelist.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>/* ***** BEGIN LICENSE BLOCK *****\n
 * Distributed under the BSD license:\n
 *\n
 * Copyright (c) 2013 Matthew Christopher Kastor-Inare III, Atropa Inc. Intl\n
 * All rights reserved.\n
 *\n
 * Contributed to Ajax.org under the BSD license.\n
 *\n
 * Redistribution and use in source and binary forms, with or without\n
 * modification, are permitted provided that the following conditions are met:\n
 *     * Redistributions of source code must retain the above copyright\n
 *       notice, this list of conditions and the following disclaimer.\n
 *     * Redistributions in binary form must reproduce the above copyright\n
 *       notice, this list of conditions and the following disclaimer in the\n
 *       documentation and/or other materials provided with the distribution.\n
 *     * Neither the name of Ajax.org B.V. nor the\n
 *       names of its contributors may be used to endorse or promote products\n
 *       derived from this software without specific prior written permission.\n
 *\n
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND\n
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED\n
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n
 * DISCLAIMED. IN NO EVENT SHALL AJAX.ORG B.V. BE LIABLE FOR ANY\n
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND\n
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\n
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/ext/themelist\', [\'require\', \'exports\', \'module\' , \'ace/ext/themelist_utils/themes\'], function(require, exports, module) {\n
module.exports.themes = require(\'ace/ext/themelist_utils/themes\').themes;\n
module.exports.ThemeDescription = function(name) {\n
    this.name = name;\n
    this.desc = name.split(\'_\'\n
        ).map(\n
            function(namePart) {\n
                return namePart[0].toUpperCase() + namePart.slice(1);\n
            }\n
        ).join(\' \');\n
    this.theme = "ace/theme/" + name;\n
};\n
\n
module.exports.themesByName = {};\n
\n
module.exports.themes = module.exports.themes.map(function(name) {\n
    module.exports.themesByName[name] = new module.exports.ThemeDescription(name);\n
    return module.exports.themesByName[name];\n
});\n
\n
});\n
\n
define(\'ace/ext/themelist_utils/themes\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
module.exports.themes = [\n
    "ambiance",\n
    "chaos",\n
    "chrome",\n
    "clouds",\n
    "clouds_midnight",\n
    "cobalt",\n
    "crimson_editor",\n
    "dawn",\n
    "dreamweaver",\n
    "eclipse",\n
    "github",\n
    "idle_fingers",\n
    "kr_theme",\n
    "merbivore",\n
    "merbivore_soft",\n
    "mono_industrial",\n
    "monokai",\n
    "pastel_on_dark",\n
    "solarized_dark",\n
    "solarized_light",\n
    "terminal",\n
    "textmate",\n
    "tomorrow",\n
    "tomorrow_night",\n
    "tomorrow_night_blue",\n
    "tomorrow_night_bright",\n
    "tomorrow_night_eighties",\n
    "twilight",\n
    "vibrant_ink",\n
    "xcode"\n
];\n
\n
});</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3224</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
