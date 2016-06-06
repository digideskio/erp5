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
            <value> <string>ts83646620.86</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>theme-clouds_midnight.js</string> </value>
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
define(\'ace/theme/clouds_midnight\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
exports.isDark = true;\n
exports.cssClass = "ace-clouds-midnight";\n
exports.cssText = ".ace-clouds-midnight .ace_gutter {\\\n
background: #232323;\\\n
color: #929292\\\n
}\\\n
.ace-clouds-midnight .ace_print-margin {\\\n
width: 1px;\\\n
background: #232323\\\n
}\\\n
.ace-clouds-midnight{\\\n
background-color: #191919;\\\n
color: #929292\\\n
}\\\n
.ace-clouds-midnight .ace_cursor {\\\n
color: #7DA5DC\\\n
}\\\n
.ace-clouds-midnight .ace_marker-layer .ace_selection {\\\n
background: #000000\\\n
}\\\n
.ace-clouds-midnight.ace_multiselect .ace_selection.ace_start {\\\n
box-shadow: 0 0 3px 0px #191919;\\\n
border-radius: 2px\\\n
}\\\n
.ace-clouds-midnight .ace_marker-layer .ace_step {\\\n
background: rgb(102, 82, 0)\\\n
}\\\n
.ace-clouds-midnight .ace_marker-layer .ace_bracket {\\\n
margin: -1px 0 0 -1px;\\\n
border: 1px solid #BFBFBF\\\n
}\\\n
.ace-clouds-midnight .ace_marker-layer .ace_active-line {\\\n
background: rgba(215, 215, 215, 0.031)\\\n
}\\\n
.ace-clouds-midnight .ace_gutter-active-line {\\\n
background-color: rgba(215, 215, 215, 0.031)\\\n
}\\\n
.ace-clouds-midnight .ace_marker-layer .ace_selected-word {\\\n
border: 1px solid #000000\\\n
}\\\n
.ace-clouds-midnight .ace_invisible {\\\n
color: #BFBFBF\\\n
}\\\n
.ace-clouds-midnight .ace_keyword,\\\n
.ace-clouds-midnight .ace_meta,\\\n
.ace-clouds-midnight .ace_support.ace_constant.ace_property-value {\\\n
color: #927C5D\\\n
}\\\n
.ace-clouds-midnight .ace_keyword.ace_operator {\\\n
color: #4B4B4B\\\n
}\\\n
.ace-clouds-midnight .ace_keyword.ace_other.ace_unit {\\\n
color: #366F1A\\\n
}\\\n
.ace-clouds-midnight .ace_constant.ace_language {\\\n
color: #39946A\\\n
}\\\n
.ace-clouds-midnight .ace_constant.ace_numeric {\\\n
color: #46A609\\\n
}\\\n
.ace-clouds-midnight .ace_constant.ace_character.ace_entity {\\\n
color: #A165AC\\\n
}\\\n
.ace-clouds-midnight .ace_invalid {\\\n
color: #FFFFFF;\\\n
background-color: #E92E2E\\\n
}\\\n
.ace-clouds-midnight .ace_fold {\\\n
background-color: #927C5D;\\\n
border-color: #929292\\\n
}\\\n
.ace-clouds-midnight .ace_storage,\\\n
.ace-clouds-midnight .ace_support.ace_class,\\\n
.ace-clouds-midnight .ace_support.ace_function,\\\n
.ace-clouds-midnight .ace_support.ace_other,\\\n
.ace-clouds-midnight .ace_support.ace_type {\\\n
color: #E92E2E\\\n
}\\\n
.ace-clouds-midnight .ace_string {\\\n
color: #5D90CD\\\n
}\\\n
.ace-clouds-midnight .ace_comment {\\\n
color: #3C403B\\\n
}\\\n
.ace-clouds-midnight .ace_entity.ace_name.ace_tag,\\\n
.ace-clouds-midnight .ace_entity.ace_other.ace_attribute-name {\\\n
color: #606060\\\n
}\\\n
.ace-clouds-midnight .ace_indent-guide {\\\n
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWNgYGBgYHB3d/8PAAOIAdULw8qMAAAAAElFTkSuQmCC) right repeat-y;\\\n
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
            <value> <int>4390</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
