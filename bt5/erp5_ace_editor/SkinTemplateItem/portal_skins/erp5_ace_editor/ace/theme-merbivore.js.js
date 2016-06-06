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
            <value> <string>ts83646620.73</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>theme-merbivore.js</string> </value>
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
 * Copyright (c) 2010, Ajax.org B.V.\n
 * All rights reserved.\n
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
 * \n
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
define(\'ace/theme/merbivore\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
exports.isDark = true;\n
exports.cssClass = "ace-merbivore";\n
exports.cssText = ".ace-merbivore .ace_gutter {\\\n
background: #202020;\\\n
color: #E6E1DC\\\n
}\\\n
.ace-merbivore .ace_print-margin {\\\n
width: 1px;\\\n
background: #555651\\\n
}\\\n
.ace-merbivore {\\\n
background-color: #161616;\\\n
color: #E6E1DC\\\n
}\\\n
.ace-merbivore .ace_cursor {\\\n
color: #FFFFFF\\\n
}\\\n
.ace-merbivore .ace_marker-layer .ace_selection {\\\n
background: #454545\\\n
}\\\n
.ace-merbivore.ace_multiselect .ace_selection.ace_start {\\\n
box-shadow: 0 0 3px 0px #161616;\\\n
border-radius: 2px\\\n
}\\\n
.ace-merbivore .ace_marker-layer .ace_step {\\\n
background: rgb(102, 82, 0)\\\n
}\\\n
.ace-merbivore .ace_marker-layer .ace_bracket {\\\n
margin: -1px 0 0 -1px;\\\n
border: 1px solid #404040\\\n
}\\\n
.ace-merbivore .ace_marker-layer .ace_active-line {\\\n
background: #333435\\\n
}\\\n
.ace-merbivore .ace_gutter-active-line {\\\n
background-color: #333435\\\n
}\\\n
.ace-merbivore .ace_marker-layer .ace_selected-word {\\\n
border: 1px solid #454545\\\n
}\\\n
.ace-merbivore .ace_invisible {\\\n
color: #404040\\\n
}\\\n
.ace-merbivore .ace_entity.ace_name.ace_tag,\\\n
.ace-merbivore .ace_keyword,\\\n
.ace-merbivore .ace_meta,\\\n
.ace-merbivore .ace_meta.ace_tag,\\\n
.ace-merbivore .ace_storage,\\\n
.ace-merbivore .ace_support.ace_function {\\\n
color: #FC6F09\\\n
}\\\n
.ace-merbivore .ace_constant,\\\n
.ace-merbivore .ace_constant.ace_character,\\\n
.ace-merbivore .ace_constant.ace_character.ace_escape,\\\n
.ace-merbivore .ace_constant.ace_other,\\\n
.ace-merbivore .ace_support.ace_type {\\\n
color: #1EDAFB\\\n
}\\\n
.ace-merbivore .ace_constant.ace_character.ace_escape {\\\n
color: #519F50\\\n
}\\\n
.ace-merbivore .ace_constant.ace_language {\\\n
color: #FDC251\\\n
}\\\n
.ace-merbivore .ace_constant.ace_library,\\\n
.ace-merbivore .ace_string,\\\n
.ace-merbivore .ace_support.ace_constant {\\\n
color: #8DFF0A\\\n
}\\\n
.ace-merbivore .ace_constant.ace_numeric {\\\n
color: #58C554\\\n
}\\\n
.ace-merbivore .ace_invalid {\\\n
color: #FFFFFF;\\\n
background-color: #990000\\\n
}\\\n
.ace-merbivore .ace_fold {\\\n
background-color: #FC6F09;\\\n
border-color: #E6E1DC\\\n
}\\\n
.ace-merbivore .ace_comment {\\\n
font-style: italic;\\\n
color: #AD2EA4\\\n
}\\\n
.ace-merbivore .ace_entity.ace_other.ace_attribute-name {\\\n
color: #FFFF89\\\n
}\\\n
.ace-merbivore .ace_indent-guide {\\\n
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWMQFxf3ZXB1df0PAAdsAmERTkEHAAAAAElFTkSuQmCC) right repeat-y;\\\n
}";\n
\n
var dom = require("../lib/dom");\n
dom.importCssString(exports.cssText, exports.cssClass);\n
});\n
</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4190</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
