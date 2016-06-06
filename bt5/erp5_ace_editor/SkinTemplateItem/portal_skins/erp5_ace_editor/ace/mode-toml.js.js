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
            <value> <string>ts83646621.82</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-toml.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* ***** BEGIN LICENSE BLOCK *****\n
 * Distributed under the BSD license:\n
 *\n
 * Copyright (c) 2013, Ajax.org B.V.\n
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
 *\n
 * Contributor(s):\n
 *\n
 * Garen J. Torikian\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/toml\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/toml_highlight_rules\', \'ace/mode/folding/ini\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var TomlHighlightRules = require("./toml_highlight_rules").TomlHighlightRules;\n
var FoldMode = require("./folding/ini").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = TomlHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "#";\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/toml_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var TomlHighlightRules = function() {\n
    var keywordMapper = this.createKeywordMapper({\n
        "constant.language.boolean": "true|false"\n
    }, "identifier");\n
\n
    var identifierRe = "[a-zA-Z\\\\$_\\u00a1-\\uffff][a-zA-Z\\\\d\\\\$_\\u00a1-\\uffff]*\\\\b";\n
\n
    this.$rules = {\n
    "start": [\n
        {\n
            token: "comment.toml",\n
            regex: /#.*$/\n
        },\n
        {\n
            token : "string",\n
            regex : \'"(?=.)\',\n
            next  : "qqstring"\n
        },\n
        {\n
            token: ["variable.keygroup.toml"],\n
            regex: "(?:^\\\\s*)(\\\\[([^\\\\]]+)\\\\])"\n
        },\n
        {\n
            token : keywordMapper,\n
            regex : identifierRe\n
        },\n
        {\n
           token : "support.date.toml",\n
           regex: "\\\\d{4}-\\\\d{2}-\\\\d{2}(T)\\\\d{2}:\\\\d{2}:\\\\d{2}(Z)"\n
        },\n
        {\n
           token: "constant.numeric.toml",\n
           regex: "-?\\\\d+(\\\\.?\\\\d+)?"\n
        }\n
    ],\n
    "qqstring" : [\n
        {\n
            token : "string",\n
            regex : "\\\\\\\\$",\n
            next  : "qqstring"\n
        },\n
        {\n
            token : "constant.language.escape",\n
            regex : \'\\\\\\\\[0tnr"\\\\\\\\]\'\n
        },\n
        {\n
            token : "string",\n
            regex : \'"|$\',\n
            next  : "start"\n
        },\n
        {\n
            defaultToken: "string"\n
        }\n
    ]\n
    }\n
\n
};\n
\n
oop.inherits(TomlHighlightRules, TextHighlightRules);\n
\n
exports.TomlHighlightRules = TomlHighlightRules;\n
});\n
\n
define(\'ace/mode/folding/ini\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/range\', \'ace/mode/folding/fold_mode\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Range = require("../../range").Range;\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
\n
var FoldMode = exports.FoldMode = function() {\n
};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
\n
    this.foldingStartMarker = /^\\s*\\[([^\\])]*)]\\s*(?:$|[;#])/;\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var re = this.foldingStartMarker;\n
        var line = session.getLine(row);\n
        \n
        var m = line.match(re);\n
        \n
        if (!m) return;\n
        \n
        var startName = m[1] + ".";\n
        \n
        var startColumn = line.length;\n
        var maxRow = session.getLength();\n
        var startRow = row;\n
        var endRow = row;\n
\n
        while (++row < maxRow) {\n
            line = session.getLine(row);\n
            if (/^\\s*$/.test(line))\n
                continue;\n
            m = line.match(re);\n
            if (m && m[1].lastIndexOf(startName, 0) !== 0)\n
                break;\n
\n
            endRow = row;\n
        }\n
\n
        if (endRow > startRow) {\n
            var endColumn = session.getLine(endRow).length;\n
            return new Range(startRow, startColumn, endRow, endColumn);\n
        }\n
    };\n
\n
}).call(FoldMode.prototype);\n
\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>5521</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
