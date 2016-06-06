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
            <value> <string>ts83646621.68</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-makefile.js</string> </value>
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
 * Copyright (c) 2012, Ajax.org B.V.\n
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
 *\n
 * Contributor(s):\n
 * \n
 *\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/makefile\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/makefile_highlight_rules\', \'ace/mode/folding/coffee\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var MakefileHighlightRules = require("./makefile_highlight_rules").MakefileHighlightRules;\n
var FoldMode = require("./folding/coffee").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = MakefileHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
       \n
    this.lineCommentStart = "#";    \n
    this.$indentWithTabs = true;\n
    \n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});define(\'ace/mode/makefile_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\', \'ace/mode/sh_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var ShHighlightFile = require("./sh_highlight_rules");\n
\n
var MakefileHighlightRules = function() {\n
\n
    var keywordMapper = this.createKeywordMapper({\n
        "keyword": ShHighlightFile.reservedKeywords,\n
        "support.function.builtin": ShHighlightFile.languageConstructs,\n
        "invalid.deprecated": "debugger"\n
    }, "string");\n
\n
    this.$rules = \n
        {\n
    "start": [\n
        {\n
            token: "string.interpolated.backtick.makefile",\n
            regex: "`",\n
            next: "shell-start"\n
        },\n
        {\n
            token: "punctuation.definition.comment.makefile",\n
            regex: /#(?=.)/,\n
            next: "comment"\n
        },\n
        {\n
            token: [ "keyword.control.makefile"],\n
            regex: "^(?:\\\\s*\\\\b)(\\\\-??include|ifeq|ifneq|ifdef|ifndef|else|endif|vpath|export|unexport|define|endef|override)(?:\\\\b)"\n
        },\n
        {// ^([^\\t ]+(\\s[^\\t ]+)*:(?!\\=))\\s*.*\n
            token: ["entity.name.function.makefile", "text"],\n
            regex: "^([^\\\\t ]+(?:\\\\s[^\\\\t ]+)*:)(\\\\s*.*)"\n
        }\n
    ],\n
    "comment": [\n
        {\n
            token : "punctuation.definition.comment.makefile",\n
            regex : /.+\\\\/\n
        },\n
        {\n
            token : "punctuation.definition.comment.makefile",\n
            regex : ".+",\n
            next  : "start"\n
        }\n
    ],\n
    "shell-start": [\n
        {\n
            token: keywordMapper,\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        }, \n
        {\n
            token: "string",\n
            regex : "\\\\w+"\n
        }, \n
        {\n
            token : "string.interpolated.backtick.makefile",\n
            regex : "`",\n
            next  : "start"\n
        }\n
    ]\n
}\n
\n
};\n
\n
oop.inherits(MakefileHighlightRules, TextHighlightRules);\n
\n
exports.MakefileHighlightRules = MakefileHighlightRules;\n
});\n
\n
define(\'ace/mode/sh_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var reservedKeywords = exports.reservedKeywords = (\n
        \'!|{|}|case|do|done|elif|else|\'+\n
        \'esac|fi|for|if|in|then|until|while|\'+\n
        \'&|;|export|local|read|typeset|unset|\'+\n
        \'elif|select|set\'\n
    );\n
\n
var languageConstructs = exports.languageConstructs = (\n
    \'[|]|alias|bg|bind|break|builtin|\'+\n
     \'cd|command|compgen|complete|continue|\'+\n
     \'dirs|disown|echo|enable|eval|exec|\'+\n
     \'exit|fc|fg|getopts|hash|help|history|\'+\n
     \'jobs|kill|let|logout|popd|printf|pushd|\'+\n
     \'pwd|return|set|shift|shopt|source|\'+\n
     \'suspend|test|times|trap|type|ulimit|\'+\n
     \'umask|unalias|wait\'\n
);\n
\n
var ShHighlightRules = function() {\n
    var keywordMapper = this.createKeywordMapper({\n
        "keyword": reservedKeywords,\n
        "support.function.builtin": languageConstructs,\n
        "invalid.deprecated": "debugger"\n
    }, "identifier");\n
\n
    var integer = "(?:(?:[1-9]\\\\d*)|(?:0))";\n
\n
    var fraction = "(?:\\\\.\\\\d+)";\n
    var intPart = "(?:\\\\d+)";\n
    var pointFloat = "(?:(?:" + intPart + "?" + fraction + ")|(?:" + intPart + "\\\\.))";\n
    var exponentFloat = "(?:(?:" + pointFloat + "|" +  intPart + ")" + ")";\n
    var floatNumber = "(?:" + exponentFloat + "|" + pointFloat + ")";\n
    var fileDescriptor = "(?:&" + intPart + ")";\n
\n
    var variableName = "[a-zA-Z][a-zA-Z0-9_]*";\n
    var variable = "(?:(?:\\\\$" + variableName + ")|(?:" + variableName + "=))";\n
\n
    var builtinVariable = "(?:\\\\$(?:SHLVL|\\\\$|\\\\!|\\\\?))";\n
\n
    var func = "(?:" + variableName + "\\\\s*\\\\(\\\\))";\n
\n
    this.$rules = {\n
        "start" : [{\n
            token : "constant",\n
            regex : /\\\\./\n
        }, {\n
            token : ["text", "comment"],\n
            regex : /(^|\\s)(#.*)$/\n
        }, {\n
            token : "string",\n
            regex : \'"\',\n
            push : [{\n
                token : "constant.language.escape",\n
                regex : /\\\\(?:[$abeEfnrtv\\\\\'"]|x[a-fA-F\\d]{1,2}|u[a-fA-F\\d]{4}([a-fA-F\\d]{4})?|c.|\\d{1,3})/\n
            }, {\n
                token : "constant",\n
                regex : /\\$\\w+/\n
            }, {\n
                token : "string",\n
                regex : \'"\',\n
                next: "pop"\n
            }, {\n
                defaultToken: "string"\n
            }]\n
        }, {\n
            token : "variable.language",\n
            regex : builtinVariable\n
        }, {\n
            token : "variable",\n
            regex : variable\n
        }, {\n
            token : "support.function",\n
            regex : func\n
        }, {\n
            token : "support.function",\n
            regex : fileDescriptor\n
        }, {\n
            token : "string",           // \' string\n
            start : "\'", end : "\'"\n
        }, {\n
            token : "constant.numeric", // float\n
            regex : floatNumber\n
        }, {\n
            token : "constant.numeric", // integer\n
            regex : integer + "\\\\b"\n
        }, {\n
            token : keywordMapper,\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        }, {\n
            token : "keyword.operator",\n
            regex : "\\\\+|\\\\-|\\\\*|\\\\*\\\\*|\\\\/|\\\\/\\\\/|~|<|>|<=|=>|=|!="\n
        }, {\n
            token : "paren.lparen",\n
            regex : "[\\\\[\\\\(\\\\{]"\n
        }, {\n
            token : "paren.rparen",\n
            regex : "[\\\\]\\\\)\\\\}]"\n
        } ]\n
    };\n
    \n
    this.normalizeRules();\n
};\n
\n
oop.inherits(ShHighlightRules, TextHighlightRules);\n
\n
exports.ShHighlightRules = ShHighlightRules;\n
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
            <value> <int>10935</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
