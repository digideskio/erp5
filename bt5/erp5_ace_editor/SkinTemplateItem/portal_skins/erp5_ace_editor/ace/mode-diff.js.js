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
            <value> <string>ts83646622.26</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-diff.js</string> </value>
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
 * Copyright (c) 2010, Ajax.org B.V.\n
 * All rights reserved.\n
 * \n
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
 * ***** END LICENSE BLOCK ***** */\r\n
\r\n
define(\'ace/mode/diff\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/diff_highlight_rules\', \'ace/mode/folding/diff\'], function(require, exports, module) {\r\n
\r\n
\r\n
var oop = require("../lib/oop");\r\n
var TextMode = require("./text").Mode;\r\n
var Tokenizer = require("../tokenizer").Tokenizer;\r\n
var HighlightRules = require("./diff_highlight_rules").DiffHighlightRules;\r\n
var FoldMode = require("./folding/diff").FoldMode;\r\n
\r\n
var Mode = function() {\r\n
    this.HighlightRules = HighlightRules;\r\n
    this.foldingRules = new FoldMode(["diff", "index", "\\\\+{3}", "@@|\\\\*{5}"], "i");\n
};\r\n
oop.inherits(Mode, TextMode);\r\n
\r\n
(function() {\r\n
\r\n
}).call(Mode.prototype);\r\n
\r\n
exports.Mode = Mode;\r\n
\r\n
});\r\n
\r\n
define(\'ace/mode/diff_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\r\n
\r\n
\r\n
var oop = require("../lib/oop");\r\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\r\n
\r\n
var DiffHighlightRules = function() {\r\r\r\n
\r\n
    this.$rules = {\r\n
        "start" : [{\r\n
                regex: "^(?:\\\\*{15}|={67}|-{3}|\\\\+{3})$",\r\n
                token: "punctuation.definition.separator.diff",\r\n
                "name": "keyword"\r\n
            }, { //diff.range.unified\r\n
                regex: "^(@@)(\\\\s*.+?\\\\s*)(@@)(.*)$",\r\n
                token: [\r\n
                    "constant",\r\n
                    "constant.numeric",\r\n
                    "constant",\r\n
                    "comment.doc.tag"\r\n
                ]\r\n
            }, { //diff.range.normal\r\n
                regex: "^(\\\\d+)([,\\\\d]+)(a|d|c)(\\\\d+)([,\\\\d]+)(.*)$",\r\n
                token: [\r\n
                    "constant.numeric",\r\n
                    "punctuation.definition.range.diff",\r\n
                    "constant.function",\r\n
                    "constant.numeric",\r\n
                    "punctuation.definition.range.diff",\r\n
                    "invalid"\r\n
                ],\r\n
                "name": "meta."\r\n
            }, {\r\n
                regex: "^(\\\\-{3}|\\\\+{3}|\\\\*{3})( .+)$",\n
                token: [\n
                    "constant.numeric",\r\n
                    "meta.tag"\r\n
                ]\r\n
            }, { // added\r\n
                regex: "^([!+>])(.*?)(\\\\s*)$",\r\n
                token: [\r\n
                    "support.constant",\r\n
                    "text",\r\n
                    "invalid"\r\n
                ]\r\n
            }, { // removed\r\n
                regex: "^([<\\\\-])(.*?)(\\\\s*)$",\r\n
                token: [\r\n
                    "support.function",\r\n
                    "string",\r\n
                    "invalid"\r\n
                ]\r\n
            }, {\r\n
                regex: "^(diff)(\\\\s+--\\\\w+)?(.+?)( .+)?$",\r\n
                token: ["variable", "variable", "keyword", "variable"]\r\n
            }, {\r\n
                regex: "^Index.+$",\r\n
                token: "variable"\r\n
            }, {\r\n
                regex: "^\\\\s+$",\n
                token: "text"\n
            }, {\r\n
                regex: "\\\\s*$",\n
                token: "invalid"\n
            }, {\n
                defaultToken: "invisible",\n
                caseInsensitive: true\n
            }\r\n
        ]\r\n
    };\r\n
};\r\n
\r\n
oop.inherits(DiffHighlightRules, TextHighlightRules);\r\n
\r\n
exports.DiffHighlightRules = DiffHighlightRules;\r\n
});\n
\n
define(\'ace/mode/folding/diff\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/folding/fold_mode\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
var Range = require("../../range").Range;\n
\n
var FoldMode = exports.FoldMode = function(levels, flag) {\n
\tthis.regExpList = levels;\n
\tthis.flag = flag;\n
\tthis.foldingStartMarker = RegExp("^(" + levels.join("|") + ")", this.flag);\n
};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        var start = {row: row, column: line.length};\n
\n
        var regList = this.regExpList;\n
        for (var i = 1; i <= regList.length; i++) {\n
            var re = RegExp("^(" + regList.slice(0, i).join("|") + ")", this.flag);\n
            if (re.test(line))\n
                break;\n
        }\n
\n
        for (var l = session.getLength(); ++row < l; ) {\n
            line = session.getLine(row);\n
            if (re.test(line))\n
                break;\n
        }\n
        if (row == start.row + 1)\n
            return;\n
        return  Range.fromPoints(start, {row: row - 1, column: line.length});\n
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
            <value> <int>6242</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
