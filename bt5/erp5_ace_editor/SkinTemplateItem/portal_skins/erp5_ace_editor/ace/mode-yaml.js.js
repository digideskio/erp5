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
            <value> <string>ts83646620.94</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-yaml.js</string> </value>
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
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/yaml\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/yaml_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/mode/folding/coffee\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var YamlHighlightRules = require("./yaml_highlight_rules").YamlHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var FoldMode = require("./folding/coffee").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = YamlHighlightRules;\n
    this.$outdent = new MatchingBraceOutdent();\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "#";\n
    \n
    this.getNextLineIndent = function(state, line, tab) {\n
        var indent = this.$getIndent(line);\n
\n
        if (state == "start") {\n
            var match = line.match(/^.*[\\{\\(\\[]\\s*$/);\n
            if (match) {\n
                indent += tab;\n
            }\n
        }\n
\n
        return indent;\n
    };\n
\n
    this.checkOutdent = function(state, line, input) {\n
        return this.$outdent.checkOutdent(line, input);\n
    };\n
\n
    this.autoOutdent = function(state, doc, row) {\n
        this.$outdent.autoOutdent(doc, row);\n
    };\n
\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
\n
});\n
\n
define(\'ace/mode/yaml_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var YamlHighlightRules = function() {\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment",\n
                regex : "#.*$"\n
            }, {\n
                token : "list.markup",\n
                regex : /^(?:-{3}|\\.{3})\\s*(?=#|$)/     \n
            },  {\n
                token : "list.markup",\n
                regex : /^\\s*[\\-?](?:$|\\s)/     \n
            }, {\n
                token: "constant",\n
                regex: "!![\\\\w//]+"\n
            }, {\n
                token: "constant.language",\n
                regex: "[&\\\\*][a-zA-Z0-9-_]+"\n
            }, {\n
                token: ["meta.tag", "keyword"],\n
                regex: /^(\\s*\\w.*?)(\\:(?:\\s+|$))/\n
            },{\n
                token: ["meta.tag", "keyword"],\n
                regex: /(\\w+?)(\\s*\\:(?:\\s+|$))/\n
            }, {\n
                token : "keyword.operator",\n
                regex : "<<\\\\w*:\\\\w*"\n
            }, {\n
                token : "keyword.operator",\n
                regex : "-\\\\s*(?=[{])"\n
            }, {\n
                token : "string", // single line\n
                regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
            }, {\n
                token : "string", // multi line string start\n
                regex : \'[|>][-+\\\\d\\\\s]*$\',\n
                next : "qqstring"\n
            }, {\n
                token : "string", // single quoted string\n
                regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
            }, {\n
                token : "constant.numeric", // float\n
                regex : /[+\\-]?[\\d_]+(?:(?:\\.[\\d_]*)?(?:[eE][+\\-]?[\\d_]+)?)?\\b/\n
            }, {\n
                token : "constant.numeric", // other number\n
                regex : /[+\\-]?\\.inf\\b|NaN\\b|0x[\\dA-Fa-f_]+|0b[10_]+/\n
            }, {\n
                token : "constant.language.boolean",\n
                regex : "(?:true|false|TRUE|FALSE|True|False|yes|no)\\\\b"\n
            }, {\n
                token : "invalid.illegal", // comments are not allowed\n
                regex : "\\\\/\\\\/.*$"\n
            }, {\n
                token : "paren.lparen",\n
                regex : "[[({]"\n
            }, {\n
                token : "paren.rparen",\n
                regex : "[\\\\])}]"\n
            }\n
        ],\n
        "qqstring" : [\n
            {\n
                token : "string",\n
                regex : \'(?=(?:(?:\\\\\\\\.)|(?:[^:]))*?:)\',\n
                next : "start"\n
            }, {\n
                token : "string",\n
                regex : \'.+\'\n
            }\n
        ]};\n
\n
};\n
\n
oop.inherits(YamlHighlightRules, TextHighlightRules);\n
\n
exports.YamlHighlightRules = YamlHighlightRules;\n
});\n
\n
define(\'ace/mode/matching_brace_outdent\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
\n
var MatchingBraceOutdent = function() {};\n
\n
(function() {\n
\n
    this.checkOutdent = function(line, input) {\n
        if (! /^\\s+$/.test(line))\n
            return false;\n
\n
        return /^\\s*\\}/.test(input);\n
    };\n
\n
    this.autoOutdent = function(doc, row) {\n
        var line = doc.getLine(row);\n
        var match = line.match(/^(\\s*\\})/);\n
\n
        if (!match) return 0;\n
\n
        var column = match[1].length;\n
        var openBracePos = doc.findMatchingBracket({row: row, column: column});\n
\n
        if (!openBracePos || openBracePos.row == row) return 0;\n
\n
        var indent = this.$getIndent(doc.getLine(openBracePos.row));\n
        doc.replace(new Range(row, 0, row, column-1), indent);\n
    };\n
\n
    this.$getIndent = function(line) {\n
        return line.match(/^\\s*/)[0];\n
    };\n
\n
}).call(MatchingBraceOutdent.prototype);\n
\n
exports.MatchingBraceOutdent = MatchingBraceOutdent;\n
});\n
\n
define(\'ace/mode/folding/coffee\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/folding/fold_mode\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
var Range = require("../../range").Range;\n
\n
var FoldMode = exports.FoldMode = function() {};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var range = this.indentationBlock(session, row);\n
        if (range)\n
            return range;\n
\n
        var re = /\\S/;\n
        var line = session.getLine(row);\n
        var startLevel = line.search(re);\n
        if (startLevel == -1 || line[startLevel] != "#")\n
            return;\n
\n
        var startColumn = line.length;\n
        var maxRow = session.getLength();\n
        var startRow = row;\n
        var endRow = row;\n
\n
        while (++row < maxRow) {\n
            line = session.getLine(row);\n
            var level = line.search(re);\n
\n
            if (level == -1)\n
                continue;\n
\n
            if (line[level] != "#")\n
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
    this.getFoldWidget = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        var indent = line.search(/\\S/);\n
        var next = session.getLine(row + 1);\n
        var prev = session.getLine(row - 1);\n
        var prevIndent = prev.search(/\\S/);\n
        var nextIndent = next.search(/\\S/);\n
\n
        if (indent == -1) {\n
            session.foldWidgets[row - 1] = prevIndent!= -1 && prevIndent < nextIndent ? "start" : "";\n
            return "";\n
        }\n
        if (prevIndent == -1) {\n
            if (indent == nextIndent && line[indent] == "#" && next[indent] == "#") {\n
                session.foldWidgets[row - 1] = "";\n
                session.foldWidgets[row + 1] = "";\n
                return "start";\n
            }\n
        } else if (prevIndent == indent && line[indent] == "#" && prev[indent] == "#") {\n
            if (session.getLine(row - 2).search(/\\S/) == -1) {\n
                session.foldWidgets[row - 1] = "start";\n
                session.foldWidgets[row + 1] = "";\n
                return "";\n
            }\n
        }\n
\n
        if (prevIndent!= -1 && prevIndent < indent)\n
            session.foldWidgets[row - 1] = "start";\n
        else\n
            session.foldWidgets[row - 1] = "";\n
\n
        if (indent < nextIndent)\n
            return "start";\n
        else\n
            return "";\n
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
            <value> <int>9677</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
