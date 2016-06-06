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
            <value> <string>ts83646621.32</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-sass.js</string> </value>
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
define(\'ace/mode/sass\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/sass_highlight_rules\', \'ace/mode/folding/coffee\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var SassHighlightRules = require("./sass_highlight_rules").SassHighlightRules;\n
var FoldMode = require("./folding/coffee").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = SassHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {   \n
    this.lineCommentStart = "//";\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
\n
});\n
\n
define(\'ace/mode/sass_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/scss_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var ScssHighlightRules = require("./scss_highlight_rules").ScssHighlightRules;\n
\n
var SassHighlightRules = function() {\n
    ScssHighlightRules.call(this);\n
    var start = this.$rules.start;\n
    if (start[1].token == "comment") {\n
        start.splice(1, 1, {\n
            onMatch: function(value, currentState, stack) {\n
                stack.unshift(this.next, -1, value.length - 2, currentState);\n
                return "comment";\n
            },\n
            regex: /^\\s*\\/\\*/,\n
            next: "comment"\n
        }, {\n
            token: "error.invalid",\n
            regex: "/\\\\*|[{;}]"\n
        }, {\n
            token: "support.type",\n
            regex: /^\\s*:[\\w\\-]+\\s/\n
        });\n
        \n
        this.$rules.comment = [\n
            {regex: /^\\s*/, onMatch: function(value, currentState, stack) {\n
                if (stack[1] === -1)\n
                    stack[1] = Math.max(stack[2], value.length - 1);\n
                if (value.length <= stack[1]) {stack.shift();stack.shift();stack.shift();\n
                    this.next = stack.shift();\n
                    return "text";\n
                } else {\n
                    this.next = "";\n
                    return "comment";\n
                }\n
            }, next: "start"},\n
            {defaultToken: "comment"}\n
        ]\n
    }\n
};\n
\n
oop.inherits(SassHighlightRules, ScssHighlightRules);\n
\n
exports.SassHighlightRules = SassHighlightRules;\n
\n
});\n
\n
define(\'ace/mode/scss_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var ScssHighlightRules = function() {\n
    \n
    var properties = lang.arrayToMap( (function () {\n
\n
        var browserPrefix = ("-webkit-|-moz-|-o-|-ms-|-svg-|-pie-|-khtml-").split("|");\n
        \n
        var prefixProperties = ("appearance|background-clip|background-inline-policy|background-origin|" + \n
             "background-size|binding|border-bottom-colors|border-left-colors|" + \n
             "border-right-colors|border-top-colors|border-end|border-end-color|" + \n
             "border-end-style|border-end-width|border-image|border-start|" + \n
             "border-start-color|border-start-style|border-start-width|box-align|" + \n
             "box-direction|box-flex|box-flexgroup|box-ordinal-group|box-orient|" + \n
             "box-pack|box-sizing|column-count|column-gap|column-width|column-rule|" + \n
             "column-rule-width|column-rule-style|column-rule-color|float-edge|" + \n
             "font-feature-settings|font-language-override|force-broken-image-icon|" + \n
             "image-region|margin-end|margin-start|opacity|outline|outline-color|" + \n
             "outline-offset|outline-radius|outline-radius-bottomleft|" + \n
             "outline-radius-bottomright|outline-radius-topleft|outline-radius-topright|" + \n
             "outline-style|outline-width|padding-end|padding-start|stack-sizing|" + \n
             "tab-size|text-blink|text-decoration-color|text-decoration-line|" + \n
             "text-decoration-style|transform|transform-origin|transition|" + \n
             "transition-delay|transition-duration|transition-property|" + \n
             "transition-timing-function|user-focus|user-input|user-modify|user-select|" +\n
             "window-shadow|border-radius").split("|");\n
        \n
        var properties = ("azimuth|background-attachment|background-color|background-image|" +\n
            "background-position|background-repeat|background|border-bottom-color|" +\n
            "border-bottom-style|border-bottom-width|border-bottom|border-collapse|" +\n
            "border-color|border-left-color|border-left-style|border-left-width|" +\n
            "border-left|border-right-color|border-right-style|border-right-width|" +\n
            "border-right|border-spacing|border-style|border-top-color|" +\n
            "border-top-style|border-top-width|border-top|border-width|border|bottom|" +\n
            "box-shadow|box-sizing|caption-side|clear|clip|color|content|counter-increment|" +\n
            "counter-reset|cue-after|cue-before|cue|cursor|direction|display|" +\n
            "elevation|empty-cells|float|font-family|font-size-adjust|font-size|" +\n
            "font-stretch|font-style|font-variant|font-weight|font|height|left|" +\n
            "letter-spacing|line-height|list-style-image|list-style-position|" +\n
            "list-style-type|list-style|margin-bottom|margin-left|margin-right|" +\n
            "margin-top|marker-offset|margin|marks|max-height|max-width|min-height|" +\n
            "min-width|opacity|orphans|outline-color|" +\n
            "outline-style|outline-width|outline|overflow|overflow-x|overflow-y|padding-bottom|" +\n
            "padding-left|padding-right|padding-top|padding|page-break-after|" +\n
            "page-break-before|page-break-inside|page|pause-after|pause-before|" +\n
            "pause|pitch-range|pitch|play-during|position|quotes|richness|right|" +\n
            "size|speak-header|speak-numeral|speak-punctuation|speech-rate|speak|" +\n
            "stress|table-layout|text-align|text-decoration|text-indent|" +\n
            "text-shadow|text-transform|top|unicode-bidi|vertical-align|" +\n
            "visibility|voice-family|volume|white-space|widows|width|word-spacing|" +\n
            "z-index").split("|");\n
        var ret = [];\n
        for (var i=0, ln=browserPrefix.length; i<ln; i++) {\n
            Array.prototype.push.apply(\n
                ret,\n
                (( browserPrefix[i] + prefixProperties.join("|" + browserPrefix[i]) ).split("|"))\n
            );\n
        }\n
        Array.prototype.push.apply(ret, prefixProperties);\n
        Array.prototype.push.apply(ret, properties);\n
        \n
        return ret;\n
        \n
    })() );\n
    \n
\n
\n
    var functions = lang.arrayToMap(\n
        ("hsl|hsla|rgb|rgba|url|attr|counter|counters|abs|adjust_color|adjust_hue|" +\n
         "alpha|join|blue|ceil|change_color|comparable|complement|darken|desaturate|" + \n
         "floor|grayscale|green|hue|if|invert|join|length|lighten|lightness|mix|" + \n
         "nth|opacify|opacity|percentage|quote|red|round|saturate|saturation|" +\n
         "scale_color|transparentize|type_of|unit|unitless|unqoute").split("|")\n
    );\n
\n
    var constants = lang.arrayToMap(\n
        ("absolute|all-scroll|always|armenian|auto|baseline|below|bidi-override|" +\n
        "block|bold|bolder|border-box|both|bottom|break-all|break-word|capitalize|center|" +\n
        "char|circle|cjk-ideographic|col-resize|collapse|content-box|crosshair|dashed|" +\n
        "decimal-leading-zero|decimal|default|disabled|disc|" +\n
        "distribute-all-lines|distribute-letter|distribute-space|" +\n
        "distribute|dotted|double|e-resize|ellipsis|fixed|georgian|groove|" +\n
        "hand|hebrew|help|hidden|hiragana-iroha|hiragana|horizontal|" +\n
        "ideograph-alpha|ideograph-numeric|ideograph-parenthesis|" +\n
        "ideograph-space|inactive|inherit|inline-block|inline|inset|inside|" +\n
        "inter-ideograph|inter-word|italic|justify|katakana-iroha|katakana|" +\n
        "keep-all|left|lighter|line-edge|line-through|line|list-item|loose|" +\n
        "lower-alpha|lower-greek|lower-latin|lower-roman|lowercase|lr-tb|ltr|" +\n
        "medium|middle|move|n-resize|ne-resize|newspaper|no-drop|no-repeat|" +\n
        "nw-resize|none|normal|not-allowed|nowrap|oblique|outset|outside|" +\n
        "overline|pointer|progress|relative|repeat-x|repeat-y|repeat|right|" +\n
        "ridge|row-resize|rtl|s-resize|scroll|se-resize|separate|small-caps|" +\n
        "solid|square|static|strict|super|sw-resize|table-footer-group|" +\n
        "table-header-group|tb-rl|text-bottom|text-top|text|thick|thin|top|" +\n
        "transparent|underline|upper-alpha|upper-latin|upper-roman|uppercase|" +\n
        "vertical-ideographic|vertical-text|visible|w-resize|wait|whitespace|" +\n
        "zero").split("|")\n
    );\n
\n
    var colors = lang.arrayToMap(\n
        ("aqua|black|blue|fuchsia|gray|green|lime|maroon|navy|olive|orange|" +\n
        "purple|red|silver|teal|white|yellow").split("|")\n
    );\n
    \n
    var keywords = lang.arrayToMap(\n
        ("@mixin|@extend|@include|@import|@media|@debug|@warn|@if|@for|@each|@while|@else|@font-face|@-webkit-keyframes|if|and|!default|module|def|end|declare").split("|")\n
    )\n
    \n
    var tags = lang.arrayToMap(\n
        ("a|abbr|acronym|address|applet|area|article|aside|audio|b|base|basefont|bdo|" + \n
         "big|blockquote|body|br|button|canvas|caption|center|cite|code|col|colgroup|" + \n
         "command|datalist|dd|del|details|dfn|dir|div|dl|dt|em|embed|fieldset|" + \n
         "figcaption|figure|font|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|" + \n
         "header|hgroup|hr|html|i|iframe|img|input|ins|keygen|kbd|label|legend|li|" + \n
         "link|map|mark|menu|meta|meter|nav|noframes|noscript|object|ol|optgroup|" + \n
         "option|output|p|param|pre|progress|q|rp|rt|ruby|s|samp|script|section|select|" + \n
         "small|source|span|strike|strong|style|sub|summary|sup|table|tbody|td|" + \n
         "textarea|tfoot|th|thead|time|title|tr|tt|u|ul|var|video|wbr|xmp").split("|")\n
    );\n
\n
    var numRe = "\\\\-?(?:(?:[0-9]+)|(?:[0-9]*\\\\.[0-9]+))";\n
\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment",\n
                regex : "\\\\/\\\\/.*$"\n
            },\n
            {\n
                token : "comment", // multi line comment\n
                regex : "\\\\/\\\\*",\n
                next : "comment"\n
            }, {\n
                token : "string", // single line\n
                regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
            }, {\n
                token : "string", // multi line string start\n
                regex : \'["].*\\\\\\\\$\',\n
                next : "qqstring"\n
            }, {\n
                token : "string", // single line\n
                regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
            }, {\n
                token : "string", // multi line string start\n
                regex : "[\'].*\\\\\\\\$",\n
                next : "qstring"\n
            }, {\n
                token : "constant.numeric",\n
                regex : numRe + "(?:em|ex|px|cm|mm|in|pt|pc|deg|rad|grad|ms|s|hz|khz|%)"\n
            }, {\n
                token : "constant.numeric", // hex6 color\n
                regex : "#[a-f0-9]{6}"\n
            }, {\n
                token : "constant.numeric", // hex3 color\n
                regex : "#[a-f0-9]{3}"\n
            }, {\n
                token : "constant.numeric",\n
                regex : numRe\n
            }, {\n
                token : ["support.function", "string", "support.function"],\n
                regex : "(url\\\\()(.*)(\\\\))"\n
            }, {\n
                token : function(value) {\n
                    if (properties.hasOwnProperty(value.toLowerCase()))\n
                        return "support.type";\n
                    if (keywords.hasOwnProperty(value))\n
                        return "keyword";\n
                    else if (constants.hasOwnProperty(value))\n
                        return "constant.language";\n
                    else if (functions.hasOwnProperty(value))\n
                        return "support.function";\n
                    else if (colors.hasOwnProperty(value.toLowerCase()))\n
                        return "support.constant.color";\n
                    else if (tags.hasOwnProperty(value.toLowerCase()))\n
                        return "variable.language";\n
                    else\n
                        return "text";\n
                },\n
                regex : "\\\\-?[@a-z_][@a-z0-9_\\\\-]*"\n
            }, {\n
                token : "variable",\n
                regex : "[a-z_\\\\-$][a-z0-9_\\\\-$]*\\\\b"\n
            }, {\n
                token: "variable.language",\n
                regex: "#[a-z0-9-_]+"\n
            }, {\n
                token: "variable.language",\n
                regex: "\\\\.[a-z0-9-_]+"\n
            }, {\n
                token: "variable.language",\n
                regex: ":[a-z0-9-_]+"\n
            }, {\n
                token: "constant",\n
                regex: "[a-z0-9-_]+"\n
            }, {\n
                token : "keyword.operator",\n
                regex : "<|>|<=|>=|==|!=|-|%|#|\\\\+|\\\\$|\\\\+|\\\\*"\n
            }, {\n
                token : "paren.lparen",\n
                regex : "[[({]"\n
            }, {\n
                token : "paren.rparen",\n
                regex : "[\\\\])}]"\n
            }, {\n
                token : "text",\n
                regex : "\\\\s+"\n
            }, {\n
                caseInsensitive: true\n
            }\n
        ],\n
        "comment" : [\n
            {\n
                token : "comment", // closing comment\n
                regex : ".*?\\\\*\\\\/",\n
                next : "start"\n
            }, {\n
                token : "comment", // comment spanning whole line\n
                regex : ".+"\n
            }\n
        ],\n
        "qqstring" : [\n
            {\n
                token : "string",\n
                regex : \'(?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?"\',\n
                next : "start"\n
            }, {\n
                token : "string",\n
                regex : \'.+\'\n
            }\n
        ],\n
        "qstring" : [\n
            {\n
                token : "string",\n
                regex : "(?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?\'",\n
                next : "start"\n
            }, {\n
                token : "string",\n
                regex : \'.+\'\n
            }\n
        ]\n
    };\n
};\n
\n
oop.inherits(ScssHighlightRules, TextHighlightRules);\n
\n
exports.ScssHighlightRules = ScssHighlightRules;\n
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
            <value> <int>18786</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
