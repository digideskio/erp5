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
            <value> <string>ts83646620.69</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>theme-monokai.js</string> </value>
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
define(\'ace/theme/monokai\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
exports.isDark = true;\n
exports.cssClass = "ace-monokai";\n
exports.cssText = ".ace-monokai .ace_gutter {\\\n
background: #2F3129;\\\n
color: #8F908A\\\n
}\\\n
.ace-monokai .ace_print-margin {\\\n
width: 1px;\\\n
background: #555651\\\n
}\\\n
.ace-monokai {\\\n
background-color: #272822;\\\n
color: #F8F8F2\\\n
}\\\n
.ace-monokai .ace_cursor {\\\n
color: #F8F8F0\\\n
}\\\n
.ace-monokai .ace_marker-layer .ace_selection {\\\n
background: #49483E\\\n
}\\\n
.ace-monokai.ace_multiselect .ace_selection.ace_start {\\\n
box-shadow: 0 0 3px 0px #272822;\\\n
border-radius: 2px\\\n
}\\\n
.ace-monokai .ace_marker-layer .ace_step {\\\n
background: rgb(102, 82, 0)\\\n
}\\\n
.ace-monokai .ace_marker-layer .ace_bracket {\\\n
margin: -1px 0 0 -1px;\\\n
border: 1px solid #49483E\\\n
}\\\n
.ace-monokai .ace_marker-layer .ace_active-line {\\\n
background: #202020\\\n
}\\\n
.ace-monokai .ace_gutter-active-line {\\\n
background-color: #272727\\\n
}\\\n
.ace-monokai .ace_marker-layer .ace_selected-word {\\\n
border: 1px solid #49483E\\\n
}\\\n
.ace-monokai .ace_invisible {\\\n
color: #52524d\\\n
}\\\n
.ace-monokai .ace_entity.ace_name.ace_tag,\\\n
.ace-monokai .ace_keyword,\\\n
.ace-monokai .ace_meta.ace_tag,\\\n
.ace-monokai .ace_storage {\\\n
color: #F92672\\\n
}\\\n
.ace-monokai .ace_punctuation,\\\n
.ace-monokai .ace_punctuation.ace_tag {\\\n
color: #fff\\\n
}\\\n
.ace-monokai .ace_constant.ace_character,\\\n
.ace-monokai .ace_constant.ace_language,\\\n
.ace-monokai .ace_constant.ace_numeric,\\\n
.ace-monokai .ace_constant.ace_other {\\\n
color: #AE81FF\\\n
}\\\n
.ace-monokai .ace_invalid {\\\n
color: #F8F8F0;\\\n
background-color: #F92672\\\n
}\\\n
.ace-monokai .ace_invalid.ace_deprecated {\\\n
color: #F8F8F0;\\\n
background-color: #AE81FF\\\n
}\\\n
.ace-monokai .ace_support.ace_constant,\\\n
.ace-monokai .ace_support.ace_function {\\\n
color: #66D9EF\\\n
}\\\n
.ace-monokai .ace_fold {\\\n
background-color: #A6E22E;\\\n
border-color: #F8F8F2\\\n
}\\\n
.ace-monokai .ace_storage.ace_type,\\\n
.ace-monokai .ace_support.ace_class,\\\n
.ace-monokai .ace_support.ace_type {\\\n
font-style: italic;\\\n
color: #66D9EF\\\n
}\\\n
.ace-monokai .ace_entity.ace_name.ace_function,\\\n
.ace-monokai .ace_entity.ace_other,\\\n
.ace-monokai .ace_entity.ace_other.ace_attribute-name,\\\n
.ace-monokai .ace_variable {\\\n
color: #A6E22E\\\n
}\\\n
.ace-monokai .ace_variable.ace_parameter {\\\n
font-style: italic;\\\n
color: #FD971F\\\n
}\\\n
.ace-monokai .ace_string {\\\n
color: #E6DB74\\\n
}\\\n
.ace-monokai .ace_comment {\\\n
color: #75715E\\\n
}\\\n
.ace-monokai .ace_indent-guide {\\\n
background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWPQ0FD0ZXBzd/wPAAjVAoxeSgNeAAAAAElFTkSuQmCC) right repeat-y;\\\n
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
            <value> <int>4349</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
