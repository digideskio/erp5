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
            <value> <string>ts83646621.1</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-tmsnippet.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

define(\'ace/mode/tmsnippet\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/text_highlight_rules\', \'ace/mode/folding/coffee\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var SnippetHighlightRules = function() {\n
\n
    var builtins = "SELECTION|CURRENT_WORD|SELECTED_TEXT|CURRENT_LINE|LINE_INDEX|" +\n
        "LINE_NUMBER|SOFT_TABS|TAB_SIZE|FILENAME|FILEPATH|FULLNAME";\n
\n
    this.$rules = {\n
        "start" : [\n
            {token:"constant.language.escape", regex: /\\\\[\\$}`\\\\]/},\n
            {token:"keyword", regex: "\\\\$(?:TM_)?(?:" + builtins + ")\\\\b"},\n
            {token:"variable", regex: "\\\\$\\\\w+"},\n
            {onMatch: function(value, state, stack) {\n
                if (stack[1])\n
                    stack[1]++;\n
                else\n
                    stack.unshift(state, 1);\n
                return this.tokenName;\n
            }, tokenName: "markup.list", regex: "\\\\${", next: "varDecl"},\n
            {onMatch: function(value, state, stack) {\n
                if (!stack[1])\n
                    return "text";\n
                stack[1]--;\n
                if (!stack[1])\n
                    stack.splice(0,2);\n
                return this.tokenName;\n
            }, tokenName: "markup.list", regex: "}"},\n
            {token: "doc.comment", regex:/^\\${2}-{5,}$/}\n
        ],\n
        "varDecl" : [\n
            {regex: /\\d+\\b/, token: "constant.numeric"},\n
            {token:"keyword", regex: "(?:TM_)?(?:" + builtins + ")\\\\b"},\n
            {token:"variable", regex: "\\\\w+"},\n
            {regex: /:/, token: "punctuation.operator", next: "start"},\n
            {regex: /\\//, token: "string.regex", next: "regexp"},\n
            {regex: "", next: "start"}\n
        ],\n
        "regexp" : [\n
            {regex: /\\\\./, token: "escape"},\n
            {regex: /\\[/, token: "regex.start", next: "charClass"},\n
            {regex: "/", token: "string.regex", next: "format"},\n
            {"token": "string.regex", regex:"."}\n
        ],\n
        charClass : [\n
            {regex: "\\\\.", token: "escape"},\n
            {regex: "\\\\]", token: "regex.end", next: "regexp"},\n
            {"token": "string.regex", regex:"."}\n
        ],\n
        "format" : [\n
            {regex: /\\\\[ulULE]/, token: "keyword"},\n
            {regex: /\\$\\d+/, token: "variable"},\n
            {regex: "/[gim]*:?", token: "string.regex", next: "start"},\n
            {"token": "string", regex:"."}\n
        ]\n
    };\n
};\n
oop.inherits(SnippetHighlightRules, TextHighlightRules);\n
\n
exports.SnippetHighlightRules = SnippetHighlightRules;\n
\n
var SnippetGroupHighlightRules = function() {\n
    this.$rules = {\n
        "start" : [\n
\t\t\t{token: "text", regex: "^\\\\t", next: "sn-start"},\n
\t\t\t{token:"invalid", regex: /^ \\s*/},\n
            {token:"comment", regex: /^#.*/},\n
            {token:"constant.language.escape", regex: "^regex ", next: "regex"},\n
            {token:"constant.language.escape", regex: "^(trigger|endTrigger|name|snippet|guard|endGuard|tabTrigger|key)\\\\b"}\n
        ],\n
\t\t"regex" : [\n
\t\t\t{token:"text", regex: "\\\\."},\n
\t\t\t{token:"keyword", regex: "/"},\n
\t\t\t{token:"empty", regex: "$", next: "start"}\n
\t\t]\n
    };\n
\tthis.embedRules(SnippetHighlightRules, "sn-", [\n
\t\t{token: "text", regex: "^\\\\t", next: "sn-start"},\n
\t\t{onMatch: function(value, state, stack) {\n
\t\t\tstack.splice(stack.length);\n
\t\t\treturn this.tokenName;\n
\t\t}, tokenName: "text", regex: "^(?!\\t)", next: "start"},\n
\t])\n
\t\n
};\n
\n
oop.inherits(SnippetGroupHighlightRules, TextHighlightRules);\n
\n
exports.SnippetGroupHighlightRules = SnippetGroupHighlightRules;\n
\n
var FoldMode = require("./folding/coffee").FoldMode;\n
\n
var Mode = function() {\n
    var highlighter = new SnippetGroupHighlightRules();\n
    this.foldingRules = new FoldMode();\n
    this.$tokenizer = new Tokenizer(highlighter.getRules());\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.getNextLineIndent = function(state, line, tab) {\n
        return this.$getIndent(line);\n
    };\n
}).call(Mode.prototype);\n
exports.Mode = Mode;\n
\n
\n
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
            <value> <int>6850</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
