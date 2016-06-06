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
            <value> <string>ts83646620.59</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>theme-vibrant_ink.js</string> </value>
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
define(\'ace/theme/vibrant_ink\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
exports.isDark = true;\n
exports.cssClass = "ace-vibrant-ink";\n
exports.cssText = ".ace-vibrant-ink .ace_gutter {\\\n
background: #1a1a1a;\\\n
color: #BEBEBE\\\n
}\\\n
.ace-vibrant-ink .ace_print-margin {\\\n
width: 1px;\\\n
background: #1a1a1a\\\n
}\\\n
.ace-vibrant-ink {\\\n
background-color: #0F0F0F;\\\n
color: #FFFFFF\\\n
}\\\n
.ace-vibrant-ink .ace_cursor {\\\n
color: #FFFFFF\\\n
}\\\n
.ace-vibrant-ink .ace_marker-layer .ace_selection {\\\n
background: #6699CC\\\n
}\\\n
.ace-vibrant-ink.ace_multiselect .ace_selection.ace_start {\\\n
box-shadow: 0 0 3px 0px #0F0F0F;\\\n
border-radius: 2px\\\n
}\\\n
.ace-vibrant-ink .ace_marker-layer .ace_step {\\\n
background: rgb(102, 82, 0)\\\n
}\\\n
.ace-vibrant-ink .ace_marker-layer .ace_bracket {\\\n
margin: -1px 0 0 -1px;\\\n
border: 1px solid #404040\\\n
}\\\n
.ace-vibrant-ink .ace_marker-layer .ace_active-line {\\\n
background: #333333\\\n
}\\\n
.ace-vibrant-ink .ace_gutter-active-line {\\\n
background-color: #333333\\\n
}\\\n
.ace-vibrant-ink .ace_marker-layer .ace_selected-word {\\\n
border: 1px solid #6699CC\\\n
}\\\n
.ace-vibrant-ink .ace_invisible {\\\n
color: #404040\\\n
}\\\n
.ace-vibrant-ink .ace_keyword,\\\n
.ace-vibrant-ink .ace_meta {\\\n
color: #FF6600\\\n
}\\\n
.ace-vibrant-ink .ace_constant,\\\n
.ace-vibrant-ink .ace_constant.ace_character,\\\n
.ace-vibrant-ink .ace_constant.ace_character.ace_escape,\\\n
.ace-vibrant-ink .ace_constant.ace_other {\\\n
color: #339999\\\n
}\\\n
.ace-vibrant-ink .ace_constant.ace_numeric {\\\n
color: #99CC99\\\n
}\\\n
.ace-vibrant-ink .ace_invalid,\\\n
.ace-vibrant-ink .ace_invalid.ace_deprecated {\\\n
color: #CCFF33;\\\n
background-color: #000000\\\n
}\\\n
.ace-vibrant-ink .ace_fold {\\\n
background-color: #FFCC00;\\\n
border-color: #FFFFFF\\\n
}\\\n
.ace-vibrant-ink .ace_entity.ace_name.ace_function,\\\n
.ace-vibrant-ink .ace_support.ace_function,\\\n
.ace-vibrant-ink .ace_variable {\\\n
color: #FFCC00\\\n
}\\\n
.ace-vibrant-ink .ace_variable.ace_parameter {\\\n
font-style: italic\\\n
}\\\n
.ace-vibrant-ink .ace_string {\\\n
color: #66FF00\\\n
}\\\n
.ace-vibrant-ink .ace_string.ace_regexp {\\\n
color: #44B4CC\\\n
}\\\n
.ace-vibrant-ink .ace_comment {\\\n
color: #9933CC\\\n
}\\\n
.ace-vibrant-ink .ace_entity.ace_other.ace_attribute-name {\\\n
font-style: italic;\\\n
color: #99CC99\\\n
}\\\n
.ace-vibrant-ink .ace_indent-guide {\\\n
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWNgYGBgYNDTc/oPAALPAZ7hxlbYAAAAAElFTkSuQmCC) right repeat-y;\\\n
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
            <value> <int>4156</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
