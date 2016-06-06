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
            <value> <string>ts83646622.37</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-coffee.js</string> </value>
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
define(\'ace/mode/coffee\', [\'require\', \'exports\', \'module\' , \'ace/tokenizer\', \'ace/mode/coffee_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/mode/folding/coffee\', \'ace/range\', \'ace/mode/text\', \'ace/worker/worker_client\', \'ace/lib/oop\'], function(require, exports, module) {\n
\n
\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var Rules = require("./coffee_highlight_rules").CoffeeHighlightRules;\n
var Outdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var FoldMode = require("./folding/coffee").FoldMode;\n
var Range = require("../range").Range;\n
var TextMode = require("./text").Mode;\n
var WorkerClient = require("../worker/worker_client").WorkerClient;\n
var oop = require("../lib/oop");\n
\n
function Mode() {\n
    this.HighlightRules = Rules;\n
    this.$outdent = new Outdent();\n
    this.foldingRules = new FoldMode();\n
}\n
\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    \n
    var indenter = /(?:[({[=:]|[-=]>|\\b(?:else|switch|try|catch(?:\\s*[$A-Za-z_\\x7f-\\uffff][$\\w\\x7f-\\uffff]*)?|finally))\\s*$/;\n
    var commentLine = /^(\\s*)#/;\n
    var hereComment = /^\\s*###(?!#)/;\n
    var indentation = /^\\s*/;\n
    \n
    this.getNextLineIndent = function(state, line, tab) {\n
        var indent = this.$getIndent(line);\n
        var tokens = this.getTokenizer().getLineTokens(line, state).tokens;\n
    \n
        if (!(tokens.length && tokens[tokens.length - 1].type === \'comment\') &&\n
            state === \'start\' && indenter.test(line))\n
            indent += tab;\n
        return indent;\n
    };\n
    \n
    this.toggleCommentLines = function(state, doc, startRow, endRow){\n
        console.log("toggle");\n
        var range = new Range(0, 0, 0, 0);\n
        for (var i = startRow; i <= endRow; ++i) {\n
            var line = doc.getLine(i);\n
            if (hereComment.test(line))\n
                continue;\n
                \n
            if (commentLine.test(line))\n
                line = line.replace(commentLine, \'$1\');\n
            else\n
                line = line.replace(indentation, \'$&#\');\n
    \n
            range.end.row = range.start.row = i;\n
            range.end.column = line.length + 1;\n
            doc.replace(range, line);\n
        }\n
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
    this.createWorker = function(session) {\n
        var worker = new WorkerClient(["ace"], "ace/mode/coffee_worker", "Worker");\n
        worker.attachToDocument(session.getDocument());\n
        \n
        worker.on("error", function(e) {\n
            session.setAnnotations([e.data]);\n
        });\n
        \n
        worker.on("ok", function(e) {\n
            session.clearAnnotations();\n
        });\n
        \n
        return worker;\n
    };\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
\n
});\n
\n
define(\'ace/mode/coffee_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
    var oop = require("../lib/oop");\n
    var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
    oop.inherits(CoffeeHighlightRules, TextHighlightRules);\n
\n
    function CoffeeHighlightRules() {\n
        var identifier = "[$A-Za-z_\\\\x7f-\\\\uffff][$\\\\w\\\\x7f-\\\\uffff]*";\n
\n
        var keywords = (\n
            "this|throw|then|try|typeof|super|switch|return|break|by|continue|" +\n
            "catch|class|in|instanceof|is|isnt|if|else|extends|for|forown|" +\n
            "finally|function|while|when|new|no|not|delete|debugger|do|loop|of|off|" +\n
            "or|on|unless|until|and|yes"\n
        );\n
\n
        var langConstant = (\n
            "true|false|null|undefined|NaN|Infinity"\n
        );\n
\n
        var illegal = (\n
            "case|const|default|function|var|void|with|enum|export|implements|" +\n
            "interface|let|package|private|protected|public|static|yield|" +\n
            "__hasProp|slice|bind|indexOf"\n
        );\n
\n
        var supportClass = (\n
            "Array|Boolean|Date|Function|Number|Object|RegExp|ReferenceError|String|" +\n
            "Error|EvalError|InternalError|RangeError|ReferenceError|StopIteration|" +\n
            "SyntaxError|TypeError|URIError|"  +\n
            "ArrayBuffer|Float32Array|Float64Array|Int16Array|Int32Array|Int8Array|" +\n
            "Uint16Array|Uint32Array|Uint8Array|Uint8ClampedArray"\n
        );\n
\n
        var supportFunction = (\n
            "Math|JSON|isNaN|isFinite|parseInt|parseFloat|encodeURI|" +\n
            "encodeURIComponent|decodeURI|decodeURIComponent|String|"\n
        );\n
\n
        var variableLanguage = (\n
            "window|arguments|prototype|document"\n
        );\n
\n
        var keywordMapper = this.createKeywordMapper({\n
            "keyword": keywords,\n
            "constant.language": langConstant,\n
            "invalid.illegal": illegal,\n
            "language.support.class": supportClass,\n
            "language.support.function": supportFunction,\n
            "variable.language": variableLanguage\n
        }, "identifier");\n
\n
        var functionRule = {\n
            token: ["paren.lparen", "variable.parameter", "paren.rparen", "text", "storage.type"],\n
            regex: /(?:(\\()((?:"[^")]*?"|\'[^\')]*?\'|\\/[^\\/)]*?\\/|[^()\\"\'\\/])*?)(\\))(\\s*))?([\\-=]>)/.source\n
        };\n
\n
        var stringEscape = /\\\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-2][0-7]{0,2}|3[0-6][0-7]?|37[0-7]?|[4-7][0-7]?|.)/;\n
\n
        this.$rules = {\n
            start : [\n
                {\n
                    token : "constant.numeric",\n
                    regex : "(?:0x[\\\\da-fA-F]+|(?:\\\\d+(?:\\\\.\\\\d+)?|\\\\.\\\\d+)(?:[eE][+-]?\\\\d+)?)"\n
                }, {\n
                    stateName: "qdoc",\n
                    token : "string", regex : "\'\'\'", next : [\n
                        {token : "string", regex : "\'\'\'", next : "start"},\n
                        {token : "constant.language.escape", regex : stringEscape},\n
                        {defaultToken: "string"}\n
                    ]\n
                }, {\n
                    stateName: "qqdoc",\n
                    token : "string",\n
                    regex : \'"""\',\n
                    next : [\n
                        {token : "string", regex : \'"""\', next : "start"},\n
                        {token : "paren.string", regex : \'#{\', push : "start"},\n
                        {token : "constant.language.escape", regex : stringEscape},\n
                        {defaultToken: "string"}\n
                    ]\n
                }, {\n
                    stateName: "qstring",\n
                    token : "string", regex : "\'", next : [\n
                        {token : "string", regex : "\'", next : "start"},\n
                        {token : "constant.language.escape", regex : stringEscape},\n
                        {defaultToken: "string"}\n
                    ]\n
                }, {\n
                    stateName: "qqstring",\n
                    token : "string.start", regex : \'"\', next : [\n
                        {token : "string.end", regex : \'"\', next : "start"},\n
                        {token : "paren.string", regex : \'#{\', push : "start"},\n
                        {token : "constant.language.escape", regex : stringEscape},\n
                        {defaultToken: "string"}\n
                    ]\n
                }, {\n
                    stateName: "js",\n
                    token : "string", regex : "`", next : [\n
                        {token : "string", regex : "`", next : "start"},\n
                        {token : "constant.language.escape", regex : stringEscape},\n
                        {defaultToken: "string"}\n
                    ]\n
                }, {\n
                    regex: "[{}]", onMatch: function(val, state, stack) {\n
                        this.next = "";\n
                        if (val == "{" && stack.length) {\n
                            stack.unshift("start", state);\n
                            return "paren";\n
                        }\n
                        if (val == "}" && stack.length) {\n
                            stack.shift();\n
                            this.next = stack.shift();\n
                            if (this.next.indexOf("string") != -1)\n
                                return "paren.string";\n
                        }\n
                        return "paren";\n
                    }\n
                }, {\n
                    token : "string.regex",\n
                    regex : "///",\n
                    next : "heregex"\n
                }, {\n
                    token : "string.regex",\n
                    regex : /(?:\\/(?![\\s=])[^[\\/\\n\\\\]*(?:(?:\\\\[\\s\\S]|\\[[^\\]\\n\\\\]*(?:\\\\[\\s\\S][^\\]\\n\\\\]*)*])[^[\\/\\n\\\\]*)*\\/)(?:[imgy]{0,4})(?!\\w)/\n
                }, {\n
                    token : "comment",\n
                    regex : "###(?!#)",\n
                    next : "comment"\n
                }, {\n
                    token : "comment",\n
                    regex : "#.*"\n
                }, {\n
                    token : ["punctuation.operator", "text", "identifier"],\n
                    regex : "(\\\\.)(\\\\s*)(" + illegal + ")"\n
                }, {\n
                    token : "punctuation.operator",\n
                    regex : "\\\\."\n
                }, {\n
                    token : ["keyword", "text", "language.support.class",\n
                     "text", "keyword", "text", "language.support.class"],\n
                    regex : "(class)(\\\\s+)(" + identifier + ")(?:(\\\\s+)(extends)(\\\\s+)(" + identifier + "))?"\n
                }, {\n
                    token : ["entity.name.function", "text", "keyword.operator", "text"].concat(functionRule.token),\n
                    regex : "(" + identifier + ")(\\\\s*)([=:])(\\\\s*)" + functionRule.regex\n
                }, \n
                functionRule, \n
                {\n
                    token : "variable",\n
                    regex : "@(?:" + identifier + ")?"\n
                }, {\n
                    token: keywordMapper,\n
                    regex : identifier\n
                }, {\n
                    token : "punctuation.operator",\n
                    regex : "\\\\,|\\\\."\n
                }, {\n
                    token : "storage.type",\n
                    regex : "[\\\\-=]>"\n
                }, {\n
                    token : "keyword.operator",\n
                    regex : "(?:[-+*/%<>&|^!?=]=|>>>=?|\\\\-\\\\-|\\\\+\\\\+|::|&&=|\\\\|\\\\|=|<<=|>>=|\\\\?\\\\.|\\\\.{2,3}|[!*+-=><])"\n
                }, {\n
                    token : "paren.lparen",\n
                    regex : "[({[]"\n
                }, {\n
                    token : "paren.rparen",\n
                    regex : "[\\\\]})]"\n
                }, {\n
                    token : "text",\n
                    regex : "\\\\s+"\n
                }],\n
\n
\n
            heregex : [{\n
                token : "string.regex",\n
                regex : \'.*?///[imgy]{0,4}\',\n
                next : "start"\n
            }, {\n
                token : "comment.regex",\n
                regex : "\\\\s+(?:#.*)?"\n
            }, {\n
                token : "string.regex",\n
                regex : "\\\\S+"\n
            }],\n
\n
            comment : [{\n
                token : "comment",\n
                regex : \'###\',\n
                next : "start"\n
            }, {\n
                defaultToken : "comment"\n
            }]\n
        };\n
        this.normalizeRules();\n
    }\n
\n
    exports.CoffeeHighlightRules = CoffeeHighlightRules;\n
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
            <value> <int>16685</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
