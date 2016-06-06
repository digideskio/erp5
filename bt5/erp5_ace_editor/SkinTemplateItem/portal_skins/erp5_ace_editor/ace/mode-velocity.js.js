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
            <value> <string>ts83646621.03</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-velocity.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>68951</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* ***** BEGIN LICENSE BLOCK *****\n
 * Distributed under the BSD license:\n
 *\n
 * Copyright (c) 2012, Ajax.org B.V.\n
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
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/velocity\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/velocity_highlight_rules\', \'ace/mode/folding/velocity\', \'ace/mode/behaviour/html\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var VelocityHighlightRules = require("./velocity_highlight_rules").VelocityHighlightRules;\n
var FoldMode = require("./folding/velocity").FoldMode;\n
var HtmlBehaviour = require("./behaviour/html").HtmlBehaviour;\n
\n
var Mode = function() {\n
    this.HighlightRules = VelocityHighlightRules;\n
    this.foldingRules = new FoldMode();\n
    this.$behaviour = new HtmlBehaviour();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "##";\n
    this.blockComment = {start: "#*", end: "*#"};\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});define(\'ace/mode/velocity_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/text_highlight_rules\', \'ace/mode/html_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var HtmlHighlightRules = require("./html_highlight_rules").HtmlHighlightRules;\n
\n
var VelocityHighlightRules = function() {\n
    HtmlHighlightRules.call(this);\n
\n
    var builtinConstants = lang.arrayToMap(\n
        (\'true|false|null\').split(\'|\')\n
    );\n
\n
    var builtinFunctions = lang.arrayToMap(\n
        ("_DateTool|_DisplayTool|_EscapeTool|_FieldTool|_MathTool|_NumberTool|_SerializerTool|_SortTool|_StringTool|_XPathTool").split(\'|\')\n
    );\n
\n
    var builtinVariables = lang.arrayToMap(\n
        (\'$contentRoot|$foreach\').split(\'|\')\n
    );\n
\n
    var keywords = lang.arrayToMap(\n
        ("#set|#macro|#include|#parse|" +\n
        "#if|#elseif|#else|#foreach|" +\n
        "#break|#end|#stop"\n
        ).split(\'|\')\n
    );\n
\n
    this.$rules.start.push(\n
        {\n
            token : "comment",\n
            regex : "##.*$"\n
        },{\n
            token : "comment.block", // multi line comment\n
            regex : "#\\\\*",\n
            next : "vm_comment"\n
        }, {\n
            token : "string.regexp",\n
            regex : "[/](?:(?:\\\\[(?:\\\\\\\\]|[^\\\\]])+\\\\])|(?:\\\\\\\\/|[^\\\\]/]))*[/]\\\\w*\\\\s*(?=[).,;]|$)"\n
        }, {\n
            token : "string", // single line\n
            regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
        }, {\n
            token : "string", // single line\n
            regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
        }, {\n
            token : "constant.numeric", // hex\n
            regex : "0[xX][0-9a-fA-F]+\\\\b"\n
        }, {\n
            token : "constant.numeric", // float\n
            regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
        }, {\n
            token : "constant.language.boolean",\n
            regex : "(?:true|false)\\\\b"\n
        }, {\n
            token : function(value) {\n
                if (keywords.hasOwnProperty(value))\n
                    return "keyword";\n
                else if (builtinConstants.hasOwnProperty(value))\n
                    return "constant.language";\n
                else if (builtinVariables.hasOwnProperty(value))\n
                    return "variable.language";\n
                else if (builtinFunctions.hasOwnProperty(value) || builtinFunctions.hasOwnProperty(value.substring(1)))\n
                    return "support.function";\n
                else if (value == "debugger")\n
                    return "invalid.deprecated";\n
                else\n
                    if(value.match(/^(\\$[a-zA-Z_][a-zA-Z0-9_]*)$/))\n
                        return "variable";\n
                    return "identifier";\n
            },\n
            regex : "[a-zA-Z$#][a-zA-Z0-9_]*\\\\b"\n
        }, {\n
            token : "keyword.operator",\n
            regex : "!|&|\\\\*|\\\\-|\\\\+|=|!=|<=|>=|<|>|&&|\\\\|\\\\|"\n
        }, {\n
            token : "lparen",\n
            regex : "[[({]"\n
        }, {\n
            token : "rparen",\n
            regex : "[\\\\])}]"\n
        }, {\n
            token : "text",\n
            regex : "\\\\s+"\n
        }\n
    );\n
\n
    this.$rules["vm_comment"] = [\n
        {\n
            token : "comment", // closing comment\n
            regex : "\\\\*#|-->",\n
            next : "start"\n
        }, {\n
            defaultToken: "comment"\n
        }\n
    ];\n
\n
    this.$rules["vm_start"] = [\n
        {\n
            token: "variable",\n
            regex: "}",\n
            next: "pop"\n
        }, {\n
            token : "string.regexp",\n
            regex : "[/](?:(?:\\\\[(?:\\\\\\\\]|[^\\\\]])+\\\\])|(?:\\\\\\\\/|[^\\\\]/]))*[/]\\\\w*\\\\s*(?=[).,;]|$)"\n
        }, {\n
            token : "string", // single line\n
            regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
        }, {\n
            token : "string", // single line\n
            regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
        }, {\n
            token : "constant.numeric", // hex\n
            regex : "0[xX][0-9a-fA-F]+\\\\b"\n
        }, {\n
            token : "constant.numeric", // float\n
            regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
        }, {\n
            token : "constant.language.boolean",\n
            regex : "(?:true|false)\\\\b"\n
        }, {\n
            token : function(value) {\n
                if (keywords.hasOwnProperty(value))\n
                    return "keyword";\n
                else if (builtinConstants.hasOwnProperty(value))\n
                    return "constant.language";\n
                else if (builtinVariables.hasOwnProperty(value))\n
                    return "variable.language";\n
                else if (builtinFunctions.hasOwnProperty(value) || builtinFunctions.hasOwnProperty(value.substring(1)))\n
                    return "support.function";\n
                else if (value == "debugger")\n
                    return "invalid.deprecated";\n
                else\n
                    if(value.match(/^(\\$[a-zA-Z_$][a-zA-Z0-9_]*)$/))\n
                        return "variable";\n
                    return "identifier";\n
            },\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        }, {\n
            token : "keyword.operator",\n
            regex : "!|&|\\\\*|\\\\-|\\\\+|=|!=|<=|>=|<|>|&&|\\\\|\\\\|"\n
        }, {\n
            token : "lparen",\n
            regex : "[[({]"\n
        }, {\n
            token : "rparen",\n
            regex : "[\\\\])}]"\n
        }, {\n
            token : "text",\n
            regex : "\\\\s+"\n
        }\n
    ];\n
\n
    for (var i in this.$rules) {\n
        this.$rules[i].unshift({\n
            token: "variable",\n
            regex: "\\\\${",\n
            push: "vm_start"\n
        });\n
    }\n
\n
    this.normalizeRules();\n
};\n
\n
oop.inherits(VelocityHighlightRules, TextHighlightRules);\n
\n
exports.VelocityHighlightRules = VelocityHighlightRules;\n
});\n
\n
define(\'ace/mode/html_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/css_highlight_rules\', \'ace/mode/javascript_highlight_rules\', \'ace/mode/xml_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var CssHighlightRules = require("./css_highlight_rules").CssHighlightRules;\n
var JavaScriptHighlightRules = require("./javascript_highlight_rules").JavaScriptHighlightRules;\n
var XmlHighlightRules = require("./xml_highlight_rules").XmlHighlightRules;\n
\n
var tagMap = lang.createMap({\n
    a           : \'anchor\',\n
    button \t    : \'form\',\n
    form        : \'form\',\n
    img         : \'image\',\n
    input       : \'form\',\n
    label       : \'form\',\n
    option      : \'form\',\n
    script      : \'script\',\n
    select      : \'form\',\n
    textarea    : \'form\',\n
    style       : \'style\',\n
    table       : \'table\',\n
    tbody       : \'table\',\n
    td          : \'table\',\n
    tfoot       : \'table\',\n
    th          : \'table\',\n
    tr          : \'table\'\n
});\n
\n
var HtmlHighlightRules = function() {\n
    XmlHighlightRules.call(this);\n
\n
    this.addRules({\n
        attributes: [{\n
            include : "space"\n
        }, {\n
            token : "entity.other.attribute-name",\n
            regex : "[-_a-zA-Z0-9:]+"\n
        }, {\n
            token : "keyword.operator.separator",\n
            regex : "=",\n
            push : [{\n
                include: "space"\n
            }, {\n
                token : "string",\n
                regex : "[^<>=\'\\"`\\\\s]+",\n
                next : "pop"\n
            }, {\n
                token : "empty",\n
                regex : "",\n
                next : "pop"\n
            }]\n
        }, {\n
            include : "string"\n
        }],\n
        tag: [{\n
            token : function(start, tag) {\n
                var group = tagMap[tag];\n
                return ["meta.tag.punctuation.begin",\n
                    "meta.tag.name" + (group ? "." + group : "")];\n
            },\n
            regex : "(<)([-_a-zA-Z0-9:]+)",\n
            next: "start_tag_stuff"\n
        }, {\n
            token : function(start, tag) {\n
                var group = tagMap[tag];\n
                return ["meta.tag.punctuation.begin",\n
                    "meta.tag.name" + (group ? "." + group : "")];\n
            },\n
            regex : "(</)([-_a-zA-Z0-9:]+)",\n
            next: "end_tag_stuff"\n
        }],\n
        start_tag_stuff: [\n
            {include : "attributes"},\n
            {token : "meta.tag.punctuation.end", regex : "/?>", next : "start"}\n
        ],\n
        end_tag_stuff: [\n
            {include : "space"},\n
            {token : "meta.tag.punctuation.end", regex : ">", next : "start"}\n
        ]\n
    });\n
\n
    this.embedTagRules(CssHighlightRules, "css-", "style");\n
    this.embedTagRules(JavaScriptHighlightRules, "js-", "script");\n
\n
    if (this.constructor === HtmlHighlightRules)\n
        this.normalizeRules();\n
};\n
\n
oop.inherits(HtmlHighlightRules, XmlHighlightRules);\n
\n
exports.HtmlHighlightRules = HtmlHighlightRules;\n
});\n
\n
define(\'ace/mode/css_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var supportType = exports.supportType = "animation-fill-mode|alignment-adjust|alignment-baseline|animation-delay|animation-direction|animation-duration|animation-iteration-count|animation-name|animation-play-state|animation-timing-function|animation|appearance|azimuth|backface-visibility|background-attachment|background-break|background-clip|background-color|background-image|background-origin|background-position|background-repeat|background-size|background|baseline-shift|binding|bleed|bookmark-label|bookmark-level|bookmark-state|bookmark-target|border-bottom|border-bottom-color|border-bottom-left-radius|border-bottom-right-radius|border-bottom-style|border-bottom-width|border-collapse|border-color|border-image|border-image-outset|border-image-repeat|border-image-slice|border-image-source|border-image-width|border-left|border-left-color|border-left-style|border-left-width|border-radius|border-right|border-right-color|border-right-style|border-right-width|border-spacing|border-style|border-top|border-top-color|border-top-left-radius|border-top-right-radius|border-top-style|border-top-width|border-width|border|bottom|box-align|box-decoration-break|box-direction|box-flex-group|box-flex|box-lines|box-ordinal-group|box-orient|box-pack|box-shadow|box-sizing|break-after|break-before|break-inside|caption-side|clear|clip|color-profile|color|column-count|column-fill|column-gap|column-rule|column-rule-color|column-rule-style|column-rule-width|column-span|column-width|columns|content|counter-increment|counter-reset|crop|cue-after|cue-before|cue|cursor|direction|display|dominant-baseline|drop-initial-after-adjust|drop-initial-after-align|drop-initial-before-adjust|drop-initial-before-align|drop-initial-size|drop-initial-value|elevation|empty-cells|fit|fit-position|float-offset|float|font-family|font-size|font-size-adjust|font-stretch|font-style|font-variant|font-weight|font|grid-columns|grid-rows|hanging-punctuation|height|hyphenate-after|hyphenate-before|hyphenate-character|hyphenate-lines|hyphenate-resource|hyphens|icon|image-orientation|image-rendering|image-resolution|inline-box-align|left|letter-spacing|line-height|line-stacking-ruby|line-stacking-shift|line-stacking-strategy|line-stacking|list-style-image|list-style-position|list-style-type|list-style|margin-bottom|margin-left|margin-right|margin-top|margin|mark-after|mark-before|mark|marks|marquee-direction|marquee-play-count|marquee-speed|marquee-style|max-height|max-width|min-height|min-width|move-to|nav-down|nav-index|nav-left|nav-right|nav-up|opacity|orphans|outline-color|outline-offset|outline-style|outline-width|outline|overflow-style|overflow-x|overflow-y|overflow|padding-bottom|padding-left|padding-right|padding-top|padding|page-break-after|page-break-before|page-break-inside|page-policy|page|pause-after|pause-before|pause|perspective-origin|perspective|phonemes|pitch-range|pitch|play-during|position|presentation-level|punctuation-trim|quotes|rendering-intent|resize|rest-after|rest-before|rest|richness|right|rotation-point|rotation|ruby-align|ruby-overhang|ruby-position|ruby-span|size|speak-header|speak-numeral|speak-punctuation|speak|speech-rate|stress|string-set|table-layout|target-name|target-new|target-position|target|text-align-last|text-align|text-decoration|text-emphasis|text-height|text-indent|text-justify|text-outline|text-shadow|text-transform|text-wrap|top|transform-origin|transform-style|transform|transition-delay|transition-duration|transition-property|transition-timing-function|transition|unicode-bidi|vertical-align|visibility|voice-balance|voice-duration|voice-family|voice-pitch-range|voice-pitch|voice-rate|voice-stress|voice-volume|volume|white-space-collapse|white-space|widows|width|word-break|word-spacing|word-wrap|z-index";\n
var supportFunction = exports.supportFunction = "rgb|rgba|url|attr|counter|counters";\n
var supportConstant = exports.supportConstant = "absolute|after-edge|after|all-scroll|all|alphabetic|always|antialiased|armenian|auto|avoid-column|avoid-page|avoid|balance|baseline|before-edge|before|below|bidi-override|block-line-height|block|bold|bolder|border-box|both|bottom|box|break-all|break-word|capitalize|caps-height|caption|center|central|char|circle|cjk-ideographic|clone|close-quote|col-resize|collapse|column|consider-shifts|contain|content-box|cover|crosshair|cubic-bezier|dashed|decimal-leading-zero|decimal|default|disabled|disc|disregard-shifts|distribute-all-lines|distribute-letter|distribute-space|distribute|dotted|double|e-resize|ease-in|ease-in-out|ease-out|ease|ellipsis|end|exclude-ruby|fill|fixed|georgian|glyphs|grid-height|groove|hand|hanging|hebrew|help|hidden|hiragana-iroha|hiragana|horizontal|icon|ideograph-alpha|ideograph-numeric|ideograph-parenthesis|ideograph-space|ideographic|inactive|include-ruby|inherit|initial|inline-block|inline-box|inline-line-height|inline-table|inline|inset|inside|inter-ideograph|inter-word|invert|italic|justify|katakana-iroha|katakana|keep-all|last|left|lighter|line-edge|line-through|line|linear|list-item|local|loose|lower-alpha|lower-greek|lower-latin|lower-roman|lowercase|lr-tb|ltr|mathematical|max-height|max-size|medium|menu|message-box|middle|move|n-resize|ne-resize|newspaper|no-change|no-close-quote|no-drop|no-open-quote|no-repeat|none|normal|not-allowed|nowrap|nw-resize|oblique|open-quote|outset|outside|overline|padding-box|page|pointer|pre-line|pre-wrap|pre|preserve-3d|progress|relative|repeat-x|repeat-y|repeat|replaced|reset-size|ridge|right|round|row-resize|rtl|s-resize|scroll|se-resize|separate|slice|small-caps|small-caption|solid|space|square|start|static|status-bar|step-end|step-start|steps|stretch|strict|sub|super|sw-resize|table-caption|table-cell|table-column-group|table-column|table-footer-group|table-header-group|table-row-group|table-row|table|tb-rl|text-after-edge|text-before-edge|text-bottom|text-size|text-top|text|thick|thin|transparent|underline|upper-alpha|upper-latin|upper-roman|uppercase|use-script|vertical-ideographic|vertical-text|visible|w-resize|wait|whitespace|z-index|zero";\n
var supportConstantColor = exports.supportConstantColor = "aqua|black|blue|fuchsia|gray|green|lime|maroon|navy|olive|orange|purple|red|silver|teal|white|yellow";\n
var supportConstantFonts = exports.supportConstantFonts = "arial|century|comic|courier|garamond|georgia|helvetica|impact|lucida|symbol|system|tahoma|times|trebuchet|utopia|verdana|webdings|sans-serif|serif|monospace";\n
\n
var numRe = exports.numRe = "\\\\-?(?:(?:[0-9]+)|(?:[0-9]*\\\\.[0-9]+))";\n
var pseudoElements = exports.pseudoElements = "(\\\\:+)\\\\b(after|before|first-letter|first-line|moz-selection|selection)\\\\b";\n
var pseudoClasses  = exports.pseudoClasses =  "(:)\\\\b(active|checked|disabled|empty|enabled|first-child|first-of-type|focus|hover|indeterminate|invalid|last-child|last-of-type|link|not|nth-child|nth-last-child|nth-last-of-type|nth-of-type|only-child|only-of-type|required|root|target|valid|visited)\\\\b";\n
\n
var CssHighlightRules = function() {\n
\n
    var keywordMapper = this.createKeywordMapper({\n
        "support.function": supportFunction,\n
        "support.constant": supportConstant,\n
        "support.type": supportType,\n
        "support.constant.color": supportConstantColor,\n
        "support.constant.fonts": supportConstantFonts\n
    }, "text", true);\n
\n
    this.$rules = {\n
        "start" : [{\n
            token : "comment", // multi line comment\n
            regex : "\\\\/\\\\*",\n
            push : "comment"\n
        }, {\n
            token: "paren.lparen",\n
            regex: "\\\\{",\n
            push:  "ruleset"\n
        }, {\n
            token: "string",\n
            regex: "@.*?{",\n
            push:  "media"\n
        }, {\n
            token: "keyword",\n
            regex: "#[a-z0-9-_]+"\n
        }, {\n
            token: "variable",\n
            regex: "\\\\.[a-z0-9-_]+"\n
        }, {\n
            token: "string",\n
            regex: ":[a-z0-9-_]+"\n
        }, {\n
            token: "constant",\n
            regex: "[a-z0-9-_]+"\n
        }, {\n
            caseInsensitive: true\n
        }],\n
\n
        "media" : [{\n
            token : "comment", // multi line comment\n
            regex : "\\\\/\\\\*",\n
            push : "comment"\n
        }, {\n
            token: "paren.lparen",\n
            regex: "\\\\{",\n
            push:  "ruleset"\n
        }, {\n
            token: "string",\n
            regex: "\\\\}",\n
            next:  "pop"\n
        }, {\n
            token: "keyword",\n
            regex: "#[a-z0-9-_]+"\n
        }, {\n
            token: "variable",\n
            regex: "\\\\.[a-z0-9-_]+"\n
        }, {\n
            token: "string",\n
            regex: ":[a-z0-9-_]+"\n
        }, {\n
            token: "constant",\n
            regex: "[a-z0-9-_]+"\n
        }, {\n
            caseInsensitive: true\n
        }],\n
\n
        "comment" : [{\n
            token : "comment",\n
            regex : "\\\\*\\\\/",\n
            next : "pop"\n
        }, {\n
            defaultToken : "comment"\n
        }],\n
\n
        "ruleset" : [\n
        {\n
            token : "paren.rparen",\n
            regex : "\\\\}",\n
            next:   "pop"\n
        }, {\n
            token : "comment", // multi line comment\n
            regex : "\\\\/\\\\*",\n
            push : "comment"\n
        }, {\n
            token : "string", // single line\n
            regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
        }, {\n
            token : "string", // single line\n
            regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
        }, {\n
            token : ["constant.numeric", "keyword"],\n
            regex : "(" + numRe + ")(ch|cm|deg|em|ex|fr|gd|grad|Hz|in|kHz|mm|ms|pc|pt|px|rad|rem|s|turn|vh|vm|vw|%)"\n
        }, {\n
            token : "constant.numeric",\n
            regex : numRe\n
        }, {\n
            token : "constant.numeric",  // hex6 color\n
            regex : "#[a-f0-9]{6}"\n
        }, {\n
            token : "constant.numeric", // hex3 color\n
            regex : "#[a-f0-9]{3}"\n
        }, {\n
            token : ["punctuation", "entity.other.attribute-name.pseudo-element.css"],\n
            regex : pseudoElements\n
        }, {\n
            token : ["punctuation", "entity.other.attribute-name.pseudo-class.css"],\n
            regex : pseudoClasses\n
        }, {\n
            token : ["support.function", "string", "support.function"],\n
            regex : "(url\\\\()(.*)(\\\\))"\n
        }, {\n
            token : keywordMapper,\n
            regex : "\\\\-?[a-zA-Z_][a-zA-Z0-9_\\\\-]*"\n
        }, {\n
            caseInsensitive: true\n
        }]\n
    };\n
\n
    this.normalizeRules();\n
};\n
\n
oop.inherits(CssHighlightRules, TextHighlightRules);\n
\n
exports.CssHighlightRules = CssHighlightRules;\n
\n
});\n
\n
define(\'ace/mode/javascript_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/doc_comment_highlight_rules\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var DocCommentHighlightRules = require("./doc_comment_highlight_rules").DocCommentHighlightRules;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var JavaScriptHighlightRules = function() {\n
    var keywordMapper = this.createKeywordMapper({\n
        "variable.language":\n
            "Array|Boolean|Date|Function|Iterator|Number|Object|RegExp|String|Proxy|"  + // Constructors\n
            "Namespace|QName|XML|XMLList|"                                             + // E4X\n
            "ArrayBuffer|Float32Array|Float64Array|Int16Array|Int32Array|Int8Array|"   +\n
            "Uint16Array|Uint32Array|Uint8Array|Uint8ClampedArray|"                    +\n
            "Error|EvalError|InternalError|RangeError|ReferenceError|StopIteration|"   + // Errors\n
            "SyntaxError|TypeError|URIError|"                                          +\n
            "decodeURI|decodeURIComponent|encodeURI|encodeURIComponent|eval|isFinite|" + // Non-constructor functions\n
            "isNaN|parseFloat|parseInt|"                                               +\n
            "JSON|Math|"                                                               + // Other\n
            "this|arguments|prototype|window|document"                                 , // Pseudo\n
        "keyword":\n
            "const|yield|import|get|set|" +\n
            "break|case|catch|continue|default|delete|do|else|finally|for|function|" +\n
            "if|in|instanceof|new|return|switch|throw|try|typeof|let|var|while|with|debugger|" +\n
            "__parent__|__count__|escape|unescape|with|__proto__|" +\n
            "class|enum|extends|super|export|implements|private|public|interface|package|protected|static",\n
        "storage.type":\n
            "const|let|var|function",\n
        "constant.language":\n
            "null|Infinity|NaN|undefined",\n
        "support.function":\n
            "alert",\n
        "constant.language.boolean": "true|false"\n
    }, "identifier");\n
    var kwBeforeRe = "case|do|else|finally|in|instanceof|return|throw|try|typeof|yield|void";\n
    var identifierRe = "[a-zA-Z\\\\$_\\u00a1-\\uffff][a-zA-Z\\\\d\\\\$_\\u00a1-\\uffff]*\\\\b";\n
\n
    var escapedRe = "\\\\\\\\(?:x[0-9a-fA-F]{2}|" + // hex\n
        "u[0-9a-fA-F]{4}|" + // unicode\n
        "[0-2][0-7]{0,2}|" + // oct\n
        "3[0-6][0-7]?|" + // oct\n
        "37[0-7]?|" + // oct\n
        "[4-7][0-7]?|" + //oct\n
        ".)";\n
\n
    this.$rules = {\n
        "no_regex" : [\n
            {\n
                token : "comment",\n
                regex : "\\\\/\\\\/",\n
                next : "line_comment"\n
            },\n
            DocCommentHighlightRules.getStartRule("doc-start"),\n
            {\n
                token : "comment", // multi line comment\n
                regex : /\\/\\*/,\n
                next : "comment"\n
            }, {\n
                token : "string",\n
                regex : "\'(?=.)",\n
                next  : "qstring"\n
            }, {\n
                token : "string",\n
                regex : \'"(?=.)\',\n
                next  : "qqstring"\n
            }, {\n
                token : "constant.numeric", // hex\n
                regex : /0[xX][0-9a-fA-F]+\\b/\n
            }, {\n
                token : "constant.numeric", // float\n
                regex : /[+-]?\\d+(?:(?:\\.\\d*)?(?:[eE][+-]?\\d+)?)?\\b/\n
            }, {\n
                token : [\n
                    "storage.type", "punctuation.operator", "support.function",\n
                    "punctuation.operator", "entity.name.function", "text","keyword.operator"\n
                ],\n
                regex : "(" + identifierRe + ")(\\\\.)(prototype)(\\\\.)(" + identifierRe +")(\\\\s*)(=)",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "storage.type", "punctuation.operator", "entity.name.function", "text",\n
                    "keyword.operator", "text", "storage.type", "text", "paren.lparen"\n
                ],\n
                regex : "(" + identifierRe + ")(\\\\.)(" + identifierRe +")(\\\\s*)(=)(\\\\s*)(function)(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "entity.name.function", "text", "keyword.operator", "text", "storage.type",\n
                    "text", "paren.lparen"\n
                ],\n
                regex : "(" + identifierRe +")(\\\\s*)(=)(\\\\s*)(function)(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "storage.type", "punctuation.operator", "entity.name.function", "text",\n
                    "keyword.operator", "text",\n
                    "storage.type", "text", "entity.name.function", "text", "paren.lparen"\n
                ],\n
                regex : "(" + identifierRe + ")(\\\\.)(" + identifierRe +")(\\\\s*)(=)(\\\\s*)(function)(\\\\s+)(\\\\w+)(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "storage.type", "text", "entity.name.function", "text", "paren.lparen"\n
                ],\n
                regex : "(function)(\\\\s+)(" + identifierRe + ")(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "entity.name.function", "text", "punctuation.operator",\n
                    "text", "storage.type", "text", "paren.lparen"\n
                ],\n
                regex : "(" + identifierRe + ")(\\\\s*)(:)(\\\\s*)(function)(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : [\n
                    "text", "text", "storage.type", "text", "paren.lparen"\n
                ],\n
                regex : "(:)(\\\\s*)(function)(\\\\s*)(\\\\()",\n
                next: "function_arguments"\n
            }, {\n
                token : "keyword",\n
                regex : "(?:" + kwBeforeRe + ")\\\\b",\n
                next : "start"\n
            }, {\n
                token : ["punctuation.operator", "support.function"],\n
                regex : /(\\.)(s(?:h(?:ift|ow(?:Mod(?:elessDialog|alDialog)|Help))|croll(?:X|By(?:Pages|Lines)?|Y|To)?|t(?:op|rike)|i(?:n|zeToContent|debar|gnText)|ort|u(?:p|b(?:str(?:ing)?)?)|pli(?:ce|t)|e(?:nd|t(?:Re(?:sizable|questHeader)|M(?:i(?:nutes|lliseconds)|onth)|Seconds|Ho(?:tKeys|urs)|Year|Cursor|Time(?:out)?|Interval|ZOptions|Date|UTC(?:M(?:i(?:nutes|lliseconds)|onth)|Seconds|Hours|Date|FullYear)|FullYear|Active)|arch)|qrt|lice|avePreferences|mall)|h(?:ome|andleEvent)|navigate|c(?:har(?:CodeAt|At)|o(?:s|n(?:cat|textual|firm)|mpile)|eil|lear(?:Timeout|Interval)?|a(?:ptureEvents|ll)|reate(?:StyleSheet|Popup|EventObject))|t(?:o(?:GMTString|S(?:tring|ource)|U(?:TCString|pperCase)|Lo(?:caleString|werCase))|est|a(?:n|int(?:Enabled)?))|i(?:s(?:NaN|Finite)|ndexOf|talics)|d(?:isableExternalCapture|ump|etachEvent)|u(?:n(?:shift|taint|escape|watch)|pdateCommands)|j(?:oin|avaEnabled)|p(?:o(?:p|w)|ush|lugins.refresh|a(?:ddings|rse(?:Int|Float)?)|r(?:int|ompt|eference))|e(?:scape|nableExternalCapture|val|lementFromPoint|x(?:p|ec(?:Script|Command)?))|valueOf|UTC|queryCommand(?:State|Indeterm|Enabled|Value)|f(?:i(?:nd|le(?:ModifiedDate|Size|CreatedDate|UpdatedDate)|xed)|o(?:nt(?:size|color)|rward)|loor|romCharCode)|watch|l(?:ink|o(?:ad|g)|astIndexOf)|a(?:sin|nchor|cos|t(?:tachEvent|ob|an(?:2)?)|pply|lert|b(?:s|ort))|r(?:ou(?:nd|teEvents)|e(?:size(?:By|To)|calc|turnValue|place|verse|l(?:oad|ease(?:Capture|Events)))|andom)|g(?:o|et(?:ResponseHeader|M(?:i(?:nutes|lliseconds)|onth)|Se(?:conds|lection)|Hours|Year|Time(?:zoneOffset)?|Da(?:y|te)|UTC(?:M(?:i(?:nutes|lliseconds)|onth)|Seconds|Hours|Da(?:y|te)|FullYear)|FullYear|A(?:ttention|llResponseHeaders)))|m(?:in|ove(?:B(?:y|elow)|To(?:Absolute)?|Above)|ergeAttributes|a(?:tch|rgins|x))|b(?:toa|ig|o(?:ld|rderWidths)|link|ack))\\b(?=\\()/\n
            }, {\n
                token : ["punctuation.operator", "support.function.dom"],\n
                regex : /(\\.)(s(?:ub(?:stringData|mit)|plitText|e(?:t(?:NamedItem|Attribute(?:Node)?)|lect))|has(?:ChildNodes|Feature)|namedItem|c(?:l(?:ick|o(?:se|neNode))|reate(?:C(?:omment|DATASection|aption)|T(?:Head|extNode|Foot)|DocumentFragment|ProcessingInstruction|E(?:ntityReference|lement)|Attribute))|tabIndex|i(?:nsert(?:Row|Before|Cell|Data)|tem)|open|delete(?:Row|C(?:ell|aption)|T(?:Head|Foot)|Data)|focus|write(?:ln)?|a(?:dd|ppend(?:Child|Data))|re(?:set|place(?:Child|Data)|move(?:NamedItem|Child|Attribute(?:Node)?)?)|get(?:NamedItem|Element(?:sBy(?:Name|TagName)|ById)|Attribute(?:Node)?)|blur)\\b(?=\\()/\n
            }, {\n
                token : ["punctuation.operator", "support.constant"],\n
                regex : /(\\.)(s(?:ystemLanguage|cr(?:ipts|ollbars|een(?:X|Y|Top|Left))|t(?:yle(?:Sheets)?|atus(?:Text|bar)?)|ibling(?:Below|Above)|ource|uffixes|e(?:curity(?:Policy)?|l(?:ection|f)))|h(?:istory|ost(?:name)?|as(?:h|Focus))|y|X(?:MLDocument|SLDocument)|n(?:ext|ame(?:space(?:s|URI)|Prop))|M(?:IN_VALUE|AX_VALUE)|c(?:haracterSet|o(?:n(?:structor|trollers)|okieEnabled|lorDepth|mp(?:onents|lete))|urrent|puClass|l(?:i(?:p(?:boardData)?|entInformation)|osed|asses)|alle(?:e|r)|rypto)|t(?:o(?:olbar|p)|ext(?:Transform|Indent|Decoration|Align)|ags)|SQRT(?:1_2|2)|i(?:n(?:ner(?:Height|Width)|put)|ds|gnoreCase)|zIndex|o(?:scpu|n(?:readystatechange|Line)|uter(?:Height|Width)|p(?:sProfile|ener)|ffscreenBuffering)|NEGATIVE_INFINITY|d(?:i(?:splay|alog(?:Height|Top|Width|Left|Arguments)|rectories)|e(?:scription|fault(?:Status|Ch(?:ecked|arset)|View)))|u(?:ser(?:Profile|Language|Agent)|n(?:iqueID|defined)|pdateInterval)|_content|p(?:ixelDepth|ort|ersonalbar|kcs11|l(?:ugins|atform)|a(?:thname|dding(?:Right|Bottom|Top|Left)|rent(?:Window|Layer)?|ge(?:X(?:Offset)?|Y(?:Offset)?))|r(?:o(?:to(?:col|type)|duct(?:Sub)?|mpter)|e(?:vious|fix)))|e(?:n(?:coding|abledPlugin)|x(?:ternal|pando)|mbeds)|v(?:isibility|endor(?:Sub)?|Linkcolor)|URLUnencoded|P(?:I|OSITIVE_INFINITY)|f(?:ilename|o(?:nt(?:Size|Family|Weight)|rmName)|rame(?:s|Element)|gColor)|E|whiteSpace|l(?:i(?:stStyleType|n(?:eHeight|kColor))|o(?:ca(?:tion(?:bar)?|lName)|wsrc)|e(?:ngth|ft(?:Context)?)|a(?:st(?:M(?:odified|atch)|Index|Paren)|yer(?:s|X)|nguage))|a(?:pp(?:MinorVersion|Name|Co(?:deName|re)|Version)|vail(?:Height|Top|Width|Left)|ll|r(?:ity|guments)|Linkcolor|bove)|r(?:ight(?:Context)?|e(?:sponse(?:XML|Text)|adyState))|global|x|m(?:imeTypes|ultiline|enubar|argin(?:Right|Bottom|Top|Left))|L(?:N(?:10|2)|OG(?:10E|2E))|b(?:o(?:ttom|rder(?:Width|RightWidth|BottomWidth|Style|Color|TopWidth|LeftWidth))|ufferDepth|elow|ackground(?:Color|Image)))\\b/\n
            }, {\n
                token : ["storage.type", "punctuation.operator", "support.function.firebug"],\n
                regex : /(console)(\\.)(warn|info|log|error|time|timeEnd|assert)\\b/\n
            }, {\n
                token : keywordMapper,\n
                regex : identifierRe\n
            }, {\n
                token : "keyword.operator",\n
                regex : /--|\\+\\+|[!$%&*+\\-~]|===|==|=|!=|!==|<=|>=|<<=|>>=|>>>=|<>|<|>|!|&&|\\|\\||\\?\\:|\\*=|%=|\\+=|\\-=|&=|\\^=/,\n
                next  : "start"\n
            }, {\n
                token : "punctuation.operator",\n
                regex : /\\?|\\:|\\,|\\;|\\./,\n
                next  : "start"\n
            }, {\n
                token : "paren.lparen",\n
                regex : /[\\[({]/,\n
                next  : "start"\n
            }, {\n
                token : "paren.rparen",\n
                regex : /[\\])}]/\n
            }, {\n
                token : "keyword.operator",\n
                regex : /\\/=?/,\n
                next  : "start"\n
            }, {\n
                token: "comment",\n
                regex: /^#!.*$/\n
            }\n
        ],\n
        "start": [\n
            DocCommentHighlightRules.getStartRule("doc-start"),\n
            {\n
                token : "comment", // multi line comment\n
                regex : "\\\\/\\\\*",\n
                next : "comment_regex_allowed"\n
            }, {\n
                token : "comment",\n
                regex : "\\\\/\\\\/",\n
                next : "line_comment_regex_allowed"\n
            }, {\n
                token: "string.regexp",\n
                regex: "\\\\/",\n
                next: "regex"\n
            }, {\n
                token : "text",\n
                regex : "\\\\s+|^$",\n
                next : "start"\n
            }, {\n
                token: "empty",\n
                regex: "",\n
                next: "no_regex"\n
            }\n
        ],\n
        "regex": [\n
            {\n
                token: "regexp.keyword.operator",\n
                regex: "\\\\\\\\(?:u[\\\\da-fA-F]{4}|x[\\\\da-fA-F]{2}|.)"\n
            }, {\n
                token: "string.regexp",\n
                regex: "/\\\\w*",\n
                next: "no_regex"\n
            }, {\n
                token : "invalid",\n
                regex: /\\{\\d+\\b,?\\d*\\}[+*]|[+*$^?][+*]|[$^][?]|\\?{3,}/\n
            }, {\n
                token : "constant.language.escape",\n
                regex: /\\(\\?[:=!]|\\)|\\{\\d+\\b,?\\d*\\}|[+*]\\?|[()$^+*?]/\n
            }, {\n
                token : "constant.language.delimiter",\n
                regex: /\\|/\n
            }, {\n
                token: "constant.language.escape",\n
                regex: /\\[\\^?/,\n
                next: "regex_character_class"\n
            }, {\n
                token: "empty",\n
                regex: "$",\n
                next: "no_regex"\n
            }, {\n
                defaultToken: "string.regexp"\n
            }\n
        ],\n
        "regex_character_class": [\n
            {\n
                token: "regexp.keyword.operator",\n
                regex: "\\\\\\\\(?:u[\\\\da-fA-F]{4}|x[\\\\da-fA-F]{2}|.)"\n
            }, {\n
                token: "constant.language.escape",\n
                regex: "]",\n
                next: "regex"\n
            }, {\n
                token: "constant.language.escape",\n
                regex: "-"\n
            }, {\n
                token: "empty",\n
                regex: "$",\n
                next: "no_regex"\n
            }, {\n
                defaultToken: "string.regexp.charachterclass"\n
            }\n
        ],\n
        "function_arguments": [\n
            {\n
                token: "variable.parameter",\n
                regex: identifierRe\n
            }, {\n
                token: "punctuation.operator",\n
                regex: "[, ]+"\n
            }, {\n
                token: "punctuation.operator",\n
                regex: "$"\n
            }, {\n
                token: "empty",\n
                regex: "",\n
                next: "no_regex"\n
            }\n
        ],\n
        "comment_regex_allowed" : [\n
            {token : "comment", regex : "\\\\*\\\\/", next : "start"},\n
            {defaultToken : "comment"}\n
        ],\n
        "comment" : [\n
            {token : "comment", regex : "\\\\*\\\\/", next : "no_regex"},\n
            {defaultToken : "comment"}\n
        ],\n
        "line_comment_regex_allowed" : [\n
            {token : "comment", regex : "$|^", next : "start"},\n
            {defaultToken : "comment"}\n
        ],\n
        "line_comment" : [\n
            {token : "comment", regex : "$|^", next : "no_regex"},\n
            {defaultToken : "comment"}\n
        ],\n
        "qqstring" : [\n
            {\n
                token : "constant.language.escape",\n
                regex : escapedRe\n
            }, {\n
                token : "string",\n
                regex : "\\\\\\\\$",\n
                next  : "qqstring"\n
            }, {\n
                token : "string",\n
                regex : \'"|$\',\n
                next  : "no_regex"\n
            }, {\n
                defaultToken: "string"\n
            }\n
        ],\n
        "qstring" : [\n
            {\n
                token : "constant.language.escape",\n
                regex : escapedRe\n
            }, {\n
                token : "string",\n
                regex : "\\\\\\\\$",\n
                next  : "qstring"\n
            }, {\n
                token : "string",\n
                regex : "\'|$",\n
                next  : "no_regex"\n
            }, {\n
                defaultToken: "string"\n
            }\n
        ]\n
    };\n
\n
    this.embedRules(DocCommentHighlightRules, "doc-",\n
        [ DocCommentHighlightRules.getEndRule("no_regex") ]);\n
};\n
\n
oop.inherits(JavaScriptHighlightRules, TextHighlightRules);\n
\n
exports.JavaScriptHighlightRules = JavaScriptHighlightRules;\n
});\n
\n
define(\'ace/mode/doc_comment_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var DocCommentHighlightRules = function() {\n
\n
    this.$rules = {\n
        "start" : [ {\n
            token : "comment.doc.tag",\n
            regex : "@[\\\\w\\\\d_]+" // TODO: fix email addresses\n
        }, {\n
            token : "comment.doc.tag",\n
            regex : "\\\\bTODO\\\\b"\n
        }, {\n
            defaultToken : "comment.doc"\n
        }]\n
    };\n
};\n
\n
oop.inherits(DocCommentHighlightRules, TextHighlightRules);\n
\n
DocCommentHighlightRules.getStartRule = function(start) {\n
    return {\n
        token : "comment.doc", // doc comment\n
        regex : "\\\\/\\\\*(?=\\\\*)",\n
        next  : start\n
    };\n
};\n
\n
DocCommentHighlightRules.getEndRule = function (start) {\n
    return {\n
        token : "comment.doc", // closing comment\n
        regex : "\\\\*\\\\/",\n
        next  : start\n
    };\n
};\n
\n
\n
exports.DocCommentHighlightRules = DocCommentHighlightRules;\n
\n
});\n
\n
define(\'ace/mode/xml_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/xml_util\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var xmlUtil = require("./xml_util");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var XmlHighlightRules = function(normalize) {\n
    this.$rules = {\n
        start : [\n
            {token : "punctuation.string.begin", regex : "<\\\\!\\\\[CDATA\\\\[", next : "cdata"},\n
            {\n
                token : ["punctuation.instruction.begin", "keyword.instruction"],\n
                regex : "(<\\\\?)(xml)(?=[\\\\s])", next : "xml_declaration"\n
            },\n
            {\n
                token : ["punctuation.instruction.begin", "keyword.instruction"],\n
                regex : "(<\\\\?)([-_a-zA-Z0-9]+)", next : "instruction"\n
            },\n
            {token : "comment", regex : "<\\\\!--", next : "comment"},\n
            {\n
                token : ["punctuation.doctype.begin", "meta.tag.doctype"],\n
                regex : "(<\\\\!)(DOCTYPE)(?=[\\\\s])", next : "doctype"\n
            },\n
            {include : "tag"},\n
            {include : "reference"}\n
        ],\n
\n
        xml_declaration : [\n
            {include : "attributes"},\n
            {include : "instruction"}\n
        ],\n
\n
        instruction : [\n
            {token : "punctuation.instruction.end", regex : "\\\\?>", next : "start"}\n
        ],\n
\n
        doctype : [\n
            {include : "space"},\n
            {include : "string"},\n
            {token : "punctuation.doctype.end", regex : ">", next : "start"},\n
            {token : "xml-pe", regex : "[-_a-zA-Z0-9:]+"},\n
            {token : "punctuation.begin", regex : "\\\\[", push : "declarations"}\n
        ],\n
\n
        declarations : [{\n
            token : "text",\n
            regex : "\\\\s+"\n
        }, {\n
            token: "punctuation.end",\n
            regex: "]",\n
            next: "pop"\n
        }, {\n
            token : ["punctuation.begin", "keyword"],\n
            regex : "(<\\\\!)([-_a-zA-Z0-9]+)",\n
            push : [{\n
                token : "text",\n
                regex : "\\\\s+"\n
            },\n
            {\n
                token : "punctuation.end",\n
                regex : ">",\n
                next : "pop"\n
            },\n
            {include : "string"}]\n
        }],\n
\n
        cdata : [\n
            {token : "string.end", regex : "\\\\]\\\\]>", next : "start"},\n
            {token : "text", regex : "\\\\s+"},\n
            {token : "text", regex : "(?:[^\\\\]]|\\\\](?!\\\\]>))+"}\n
        ],\n
\n
        comment : [\n
            {token : "comment", regex : "-->", next : "start"},\n
            {defaultToken : "comment"}\n
        ],\n
\n
        tag : [{\n
            token : ["meta.tag.punctuation.begin", "meta.tag.name"],\n
            regex : "(<)((?:[-_a-zA-Z0-9]+:)?[-_a-zA-Z0-9]+)",\n
            next: [\n
                {include : "attributes"},\n
                {token : "meta.tag.punctuation.end", regex : "/?>", next : "start"}\n
            ]\n
        }, {\n
            token : ["meta.tag.punctuation.begin", "meta.tag.name"],\n
            regex : "(</)((?:[-_a-zA-Z0-9]+:)?[-_a-zA-Z0-9]+)",\n
            next: [\n
                {include : "space"},\n
                {token : "meta.tag.punctuation.end", regex : ">", next : "start"}\n
            ]\n
        }],\n
\n
        space : [\n
            {token : "text", regex : "\\\\s+"}\n
        ],\n
\n
        reference : [{\n
            token : "constant.language.escape",\n
            regex : "(?:&#[0-9]+;)|(?:&#x[0-9a-fA-F]+;)|(?:&[a-zA-Z0-9_:\\\\.-]+;)"\n
        }, {\n
            token : "invalid.illegal", regex : "&"\n
        }],\n
\n
        string: [{\n
            token : "string",\n
            regex : "\'",\n
            push : "qstring_inner"\n
        }, {\n
            token : "string",\n
            regex : \'"\',\n
            push : "qqstring_inner"\n
        }],\n
\n
        qstring_inner: [\n
            {token : "string", regex: "\'", next: "pop"},\n
            {include : "reference"},\n
            {defaultToken : "string"}\n
        ],\n
\n
        qqstring_inner: [\n
            {token : "string", regex: \'"\', next: "pop"},\n
            {include : "reference"},\n
            {defaultToken : "string"}\n
        ],\n
\n
        attributes: [{\n
            token : "entity.other.attribute-name",\n
            regex : "(?:[-_a-zA-Z0-9]+:)?[-_a-zA-Z0-9]+"\n
        }, {\n
            token : "keyword.operator.separator",\n
            regex : "="\n
        }, {\n
            include : "space"\n
        }, {\n
            include : "string"\n
        }]\n
    };\n
\n
    if (this.constructor === XmlHighlightRules)\n
        this.normalizeRules();\n
};\n
\n
\n
(function() {\n
\n
    this.embedTagRules = function(HighlightRules, prefix, tag){\n
        this.$rules.tag.unshift({\n
            token : ["meta.tag.punctuation.begin", "meta.tag.name." + tag],\n
            regex : "(<)(" + tag + ")",\n
            next: [\n
                {include : "space"},\n
                {include : "attributes"},\n
                {token : "meta.tag.punctuation.end", regex : "/?>", next : prefix + "start"}\n
            ]\n
        });\n
\n
        this.$rules[tag + "-end"] = [\n
            {include : "space"},\n
            {token : "meta.tag.punctuation.end", regex : ">",  next: "start",\n
                onMatch : function(value, currentState, stack) {\n
                    stack.splice(0);\n
                    return this.token;\n
            }}\n
        ]\n
\n
        this.embedRules(HighlightRules, prefix, [{\n
            token: ["meta.tag.punctuation.begin", "meta.tag.name." + tag],\n
            regex : "(</)(" + tag + ")",\n
            next: tag + "-end"\n
        }, {\n
            token: "string.begin",\n
            regex : "<\\\\!\\\\[CDATA\\\\["\n
        }, {\n
            token: "string.end",\n
            regex : "\\\\]\\\\]>"\n
        }]);\n
    };\n
\n
}).call(TextHighlightRules.prototype);\n
\n
oop.inherits(XmlHighlightRules, TextHighlightRules);\n
\n
exports.XmlHighlightRules = XmlHighlightRules;\n
});\n
\n
define(\'ace/mode/xml_util\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
function string(state) {\n
    return [{\n
        token : "string",\n
        regex : \'"\',\n
        next : state + "_qqstring"\n
    }, {\n
        token : "string",\n
        regex : "\'",\n
        next : state + "_qstring"\n
    }];\n
}\n
\n
function multiLineString(quote, state) {\n
    return [\n
        {token : "string", regex : quote, next : state},\n
        {\n
            token : "constant.language.escape",\n
            regex : "(?:&#[0-9]+;)|(?:&#x[0-9a-fA-F]+;)|(?:&[a-zA-Z0-9_:\\\\.-]+;)" \n
        },\n
        {defaultToken : "string"}\n
    ];\n
}\n
\n
exports.tag = function(states, name, nextState, tagMap) {\n
    states[name] = [{\n
        token : "text",\n
        regex : "\\\\s+"\n
    }, {\n
        \n
    token : !tagMap ? "meta.tag.tag-name" : function(value) {\n
            if (tagMap[value])\n
                return "meta.tag.tag-name." + tagMap[value];\n
            else\n
                return "meta.tag.tag-name";\n
        },\n
        regex : "[-_a-zA-Z0-9:]+",\n
        next : name + "_embed_attribute_list" \n
    }, {\n
        token: "empty",\n
        regex: "",\n
        next : name + "_embed_attribute_list"\n
    }];\n
\n
    states[name + "_qstring"] = multiLineString("\'", name + "_embed_attribute_list");\n
    states[name + "_qqstring"] = multiLineString("\\"", name + "_embed_attribute_list");\n
    \n
    states[name + "_embed_attribute_list"] = [{\n
        token : "meta.tag.r",\n
        regex : "/?>",\n
        next : nextState\n
    }, {\n
        token : "keyword.operator",\n
        regex : "="\n
    }, {\n
        token : "entity.other.attribute-name",\n
        regex : "[-_a-zA-Z0-9:]+"\n
    }, {\n
        token : "constant.numeric", // float\n
        regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
    }, {\n
        token : "text",\n
        regex : "\\\\s+"\n
    }].concat(string(name));\n
};\n
\n
});\n
\n
define(\'ace/mode/folding/velocity\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/folding/fold_mode\', \'ace/range\'], function(require, exports, module) {\n
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
        if (startLevel == -1 || line[startLevel] != "##")\n
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
            if (line[level] != "##")\n
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
            if (indent == nextIndent && line[indent] == "##" && next[indent] == "##") {\n
                session.foldWidgets[row - 1] = "";\n
                session.foldWidgets[row + 1] = "";\n
                return "start";\n
            }\n
        } else if (prevIndent == indent && line[indent] == "##" && prev[indent] == "##") {\n
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
\n
define(\'ace/mode/behaviour/html\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/behaviour/xml\', \'ace/mode/behaviour/cstyle\', \'ace/token_iterator\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var XmlBehaviour = require("../behaviour/xml").XmlBehaviour;\n
var CstyleBehaviour = require("./cstyle").CstyleBehaviour;\n
var TokenIterator = require("../../token_iterator").TokenIterator;\n
var voidElements = [\'area\', \'base\', \'br\', \'col\', \'command\', \'embed\', \'hr\', \'img\', \'input\', \'keygen\', \'link\', \'meta\', \'param\', \'source\', \'track\', \'wbr\'];\n
\n
function hasType(token, type) {\n
    var tokenTypes = token.type.split(\'.\');\n
    return type.split(\'.\').every(function(type){\n
        return (tokenTypes.indexOf(type) !== -1);\n
    });\n
    return hasType;\n
}\n
\n
var HtmlBehaviour = function () {\n
\n
    this.inherit(XmlBehaviour); // Get xml behaviour\n
    \n
    this.add("autoclosing", "insertion", function (state, action, editor, session, text) {\n
        if (text == \'>\') {\n
            var position = editor.getCursorPosition();\n
            var iterator = new TokenIterator(session, position.row, position.column);\n
            var token = iterator.getCurrentToken();\n
\n
            if (token && hasType(token, \'string\') && iterator.getCurrentTokenColumn() + token.value.length > position.column)\n
                return;\n
            var atCursor = false;\n
            if (!token || !hasType(token, \'meta.tag\') && !(hasType(token, \'text\') && token.value.match(\'/\'))){\n
                do {\n
                    token = iterator.stepBackward();\n
                } while (token && (hasType(token, \'string\') || hasType(token, \'keyword.operator\') || hasType(token, \'entity.attribute-name\') || hasType(token, \'text\')));\n
            } else {\n
                atCursor = true;\n
            }\n
            if (!token || !hasType(token, \'meta.tag.name\') || iterator.stepBackward().value.match(\'/\')) {\n
                return;\n
            }\n
            var element = token.value;\n
            if (atCursor){\n
                var element = element.substring(0, position.column - token.start);\n
            }\n
            if (voidElements.indexOf(element) !== -1){\n
                return;\n
            }\n
            return {\n
               text: \'>\' + \'</\' + element + \'>\',\n
               selection: [1, 1]\n
            }\n
        }\n
    });\n
}\n
oop.inherits(HtmlBehaviour, XmlBehaviour);\n
\n
exports.HtmlBehaviour = HtmlBehaviour;\n
});\n
\n
define(\'ace/mode/behaviour/xml\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/behaviour\', \'ace/mode/behaviour/cstyle\', \'ace/token_iterator\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Behaviour = require("../behaviour").Behaviour;\n
var CstyleBehaviour = require("./cstyle").CstyleBehaviour;\n
var TokenIterator = require("../../token_iterator").TokenIterator;\n
\n
function hasType(token, type) {\n
    var tokenTypes = token.type.split(\'.\');\n
    return type.split(\'.\').every(function(type){\n
        return (tokenTypes.indexOf(type) !== -1);\n
    });\n
    return hasType;\n
}\n
\n
var XmlBehaviour = function () {\n
    \n
    this.inherit(CstyleBehaviour, ["string_dquotes"]); // Get string behaviour\n
    \n
    this.add("autoclosing", "insertion", function (state, action, editor, session, text) {\n
        if (text == \'>\') {\n
            var position = editor.getCursorPosition();\n
            var iterator = new TokenIterator(session, position.row, position.column);\n
            var token = iterator.getCurrentToken();\n
\n
            if (token && hasType(token, \'string\') && iterator.getCurrentTokenColumn() + token.value.length > position.column)\n
                return;\n
            var atCursor = false;\n
            if (!token || !hasType(token, \'meta.tag\') && !(hasType(token, \'text\') && token.value.match(\'/\'))){\n
                do {\n
                    token = iterator.stepBackward();\n
                } while (token && (hasType(token, \'string\') || hasType(token, \'keyword.operator\') || hasType(token, \'entity.attribute-name\') || hasType(token, \'text\')));\n
            } else {\n
                atCursor = true;\n
            }\n
            if (!token || !hasType(token, \'meta.tag.name\') || iterator.stepBackward().value.match(\'/\')) {\n
                return;\n
            }\n
            var tag = token.value;\n
            if (atCursor){\n
                var tag = tag.substring(0, position.column - token.start);\n
            }\n
\n
            return {\n
               text: \'>\' + \'</\' + tag + \'>\',\n
               selection: [1, 1]\n
            }\n
        }\n
    });\n
\n
    this.add(\'autoindent\', \'insertion\', function (state, action, editor, session, text) {\n
        if (text == "\\n") {\n
            var cursor = editor.getCursorPosition();\n
            var line = session.getLine(cursor.row);\n
            var rightChars = line.substring(cursor.column, cursor.column + 2);\n
            if (rightChars == \'</\') {\n
                var next_indent = this.$getIndent(line);\n
                var indent = next_indent + session.getTabString();\n
\n
                return {\n
                    text: \'\\n\' + indent + \'\\n\' + next_indent,\n
                    selection: [1, indent.length, 1, indent.length]\n
                }\n
            }\n
        }\n
    });\n
    \n
}\n
oop.inherits(XmlBehaviour, Behaviour);\n
\n
exports.XmlBehaviour = XmlBehaviour;\n
});\n
\n
define(\'ace/mode/behaviour/cstyle\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/behaviour\', \'ace/token_iterator\', \'ace/lib/lang\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Behaviour = require("../behaviour").Behaviour;\n
var TokenIterator = require("../../token_iterator").TokenIterator;\n
var lang = require("../../lib/lang");\n
\n
var SAFE_INSERT_IN_TOKENS =\n
    ["text", "paren.rparen", "punctuation.operator"];\n
var SAFE_INSERT_BEFORE_TOKENS =\n
    ["text", "paren.rparen", "punctuation.operator", "comment"];\n
\n
\n
var autoInsertedBrackets = 0;\n
var autoInsertedRow = -1;\n
var autoInsertedLineEnd = "";\n
var maybeInsertedBrackets = 0;\n
var maybeInsertedRow = -1;\n
var maybeInsertedLineStart = "";\n
var maybeInsertedLineEnd = "";\n
\n
var CstyleBehaviour = function () {\n
    \n
    CstyleBehaviour.isSaneInsertion = function(editor, session) {\n
        var cursor = editor.getCursorPosition();\n
        var iterator = new TokenIterator(session, cursor.row, cursor.column);\n
        if (!this.$matchTokenType(iterator.getCurrentToken() || "text", SAFE_INSERT_IN_TOKENS)) {\n
            var iterator2 = new TokenIterator(session, cursor.row, cursor.column + 1);\n
            if (!this.$matchTokenType(iterator2.getCurrentToken() || "text", SAFE_INSERT_IN_TOKENS))\n
                return false;\n
        }\n
        iterator.stepForward();\n
        return iterator.getCurrentTokenRow() !== cursor.row ||\n
            this.$matchTokenType(iterator.getCurrentToken() || "text", SAFE_INSERT_BEFORE_TOKENS);\n
    };\n
    \n
    CstyleBehaviour.$matchTokenType = function(token, types) {\n
        return types.indexOf(token.type || token) > -1;\n
    };\n
    \n
    CstyleBehaviour.recordAutoInsert = function(editor, session, bracket) {\n
        var cursor = editor.getCursorPosition();\n
        var line = session.doc.getLine(cursor.row);\n
        if (!this.isAutoInsertedClosing(cursor, line, autoInsertedLineEnd[0]))\n
            autoInsertedBrackets = 0;\n
        autoInsertedRow = cursor.row;\n
        autoInsertedLineEnd = bracket + line.substr(cursor.column);\n
        autoInsertedBrackets++;\n
    };\n
    \n
    CstyleBehaviour.recordMaybeInsert = function(editor, session, bracket) {\n
        var cursor = editor.getCursorPosition();\n
        var line = session.doc.getLine(cursor.row);\n
        if (!this.isMaybeInsertedClosing(cursor, line))\n
            maybeInsertedBrackets = 0;\n
        maybeInsertedRow = cursor.row;\n
        maybeInsertedLineStart = line.substr(0, cursor.column) + bracket;\n
        maybeInsertedLineEnd = line.substr(cursor.column);\n
        maybeInsertedBrackets++;\n
    };\n
    \n
    CstyleBehaviour.isAutoInsertedClosing = function(cursor, line, bracket) {\n
        return autoInsertedBrackets > 0 &&\n
            cursor.row === autoInsertedRow &&\n
            bracket === autoInsertedLineEnd[0] &&\n
            line.substr(cursor.column) === autoInsertedLineEnd;\n
    };\n
    \n
    CstyleBehaviour.isMaybeInsertedClosing = function(cursor, line) {\n
        return maybeInsertedBrackets > 0 &&\n
            cursor.row === maybeInsertedRow &&\n
            line.substr(cursor.column) === maybeInsertedLineEnd &&\n
            line.substr(0, cursor.column) == maybeInsertedLineStart;\n
    };\n
    \n
    CstyleBehaviour.popAutoInsertedClosing = function() {\n
        autoInsertedLineEnd = autoInsertedLineEnd.substr(1);\n
        autoInsertedBrackets--;\n
    };\n
    \n
    CstyleBehaviour.clearMaybeInsertedClosing = function() {\n
        maybeInsertedBrackets = 0;\n
        maybeInsertedRow = -1;\n
    };\n
\n
    this.add("braces", "insertion", function (state, action, editor, session, text) {\n
        var cursor = editor.getCursorPosition();\n
        var line = session.doc.getLine(cursor.row);\n
        if (text == \'{\') {\n
            var selection = editor.getSelectionRange();\n
            var selected = session.doc.getTextRange(selection);\n
            if (selected !== "" && selected !== "{" && editor.getWrapBehavioursEnabled()) {\n
                return {\n
                    text: \'{\' + selected + \'}\',\n
                    selection: false\n
                };\n
            } else if (CstyleBehaviour.isSaneInsertion(editor, session)) {\n
                if (/[\\]\\}\\)]/.test(line[cursor.column])) {\n
                    CstyleBehaviour.recordAutoInsert(editor, session, "}");\n
                    return {\n
                        text: \'{}\',\n
                        selection: [1, 1]\n
                    };\n
                } else {\n
                    CstyleBehaviour.recordMaybeInsert(editor, session, "{");\n
                    return {\n
                        text: \'{\',\n
                        selection: [1, 1]\n
                    };\n
                }\n
            }\n
        } else if (text == \'}\') {\n
            var rightChar = line.substring(cursor.column, cursor.column + 1);\n
            if (rightChar == \'}\') {\n
                var matching = session.$findOpeningBracket(\'}\', {column: cursor.column + 1, row: cursor.row});\n
                if (matching !== null && CstyleBehaviour.isAutoInsertedClosing(cursor, line, text)) {\n
                    CstyleBehaviour.popAutoInsertedClosing();\n
                    return {\n
                        text: \'\',\n
                        selection: [1, 1]\n
                    };\n
                }\n
            }\n
        } else if (text == "\\n" || text == "\\r\\n") {\n
            var closing = "";\n
            if (CstyleBehaviour.isMaybeInsertedClosing(cursor, line)) {\n
                closing = lang.stringRepeat("}", maybeInsertedBrackets);\n
                CstyleBehaviour.clearMaybeInsertedClosing();\n
            }\n
            var rightChar = line.substring(cursor.column, cursor.column + 1);\n
            if (rightChar == \'}\' || closing !== "") {\n
                var openBracePos = session.findMatchingBracket({row: cursor.row, column: cursor.column}, \'}\');\n
                if (!openBracePos)\n
                     return null;\n
\n
                var indent = this.getNextLineIndent(state, line.substring(0, cursor.column), session.getTabString());\n
                var next_indent = this.$getIndent(line);\n
\n
                return {\n
                    text: \'\\n\' + indent + \'\\n\' + next_indent + closing,\n
                    selection: [1, indent.length, 1, indent.length]\n
                };\n
            }\n
        }\n
    });\n
\n
    this.add("braces", "deletion", function (state, action, editor, session, range) {\n
        var selected = session.doc.getTextRange(range);\n
        if (!range.isMultiLine() && selected == \'{\') {\n
            var line = session.doc.getLine(range.start.row);\n
            var rightChar = line.substring(range.end.column, range.end.column + 1);\n
            if (rightChar == \'}\') {\n
                range.end.column++;\n
                return range;\n
            } else {\n
                maybeInsertedBrackets--;\n
            }\n
        }\n
    });\n
\n
    this.add("parens", "insertion", function (state, action, editor, session, text) {\n
        if (text == \'(\') {\n
            var selection = editor.getSelectionRange();\n
            var selected = session.doc.getTextRange(selection);\n
            if (selected !== "" && editor.getWrapBehavioursEnabled()) {\n
                return {\n
                    text: \'(\' + selected + \')\',\n
                    selection: false\n
                };\n
            } else if (CstyleBehaviour.isSaneInsertion(editor, session)) {\n
                CstyleBehaviour.recordAutoInsert(editor, session, ")");\n
                return {\n
                    text: \'()\',\n
                    selection: [1, 1]\n
                };\n
            }\n
        } else if (text == \')\') {\n
            var cursor = editor.getCursorPosition();\n
            var line = session.doc.getLine(cursor.row);\n
            var rightChar = line.substring(cursor.column, cursor.column + 1);\n
            if (rightChar == \')\') {\n
                var matching = session.$findOpeningBracket(\')\', {column: cursor.column + 1, row: cursor.row});\n
                if (matching !== null && CstyleBehaviour.isAutoInsertedClosing(cursor, line, text)) {\n
                    CstyleBehaviour.popAutoInsertedClosing();\n
                    return {\n
                        text: \'\',\n
                        selection: [1, 1]\n
                    };\n
                }\n
            }\n
        }\n
    });\n
\n
    this.add("parens", "deletion", function (state, action, editor, session, range) {\n
        var selected = session.doc.getTextRange(range);\n
        if (!range.isMultiLine() && selected == \'(\') {\n
            var line = session.doc.getLine(range.start.row);\n
            var rightChar = line.substring(range.start.column + 1, range.start.column + 2);\n
            if (rightChar == \')\') {\n
                range.end.column++;\n
                return range;\n
            }\n
        }\n
    });\n
\n
    this.add("brackets", "insertion", function (state, action, editor, session, text) {\n
        if (text == \'[\') {\n
            var selection = editor.getSelectionRange();\n
            var selected = session.doc.getTextRange(selection);\n
            if (selected !== "" && editor.getWrapBehavioursEnabled()) {\n
                return {\n
                    text: \'[\' + selected + \']\',\n
                    selection: false\n
                };\n
            } else if (CstyleBehaviour.isSaneInsertion(editor, session)) {\n
                CstyleBehaviour.recordAutoInsert(editor, session, "]");\n
                return {\n
                    text: \'[]\',\n
                    selection: [1, 1]\n
                };\n
            }\n
        } else if (text == \']\') {\n
            var cursor = editor.getCursorPosition();\n
            var line = session.doc.getLine(cursor.row);\n
            var rightChar = line.substring(cursor.column, cursor.column + 1);\n
            if (rightChar == \']\') {\n
                var matching = session.$findOpeningBracket(\']\', {column: cursor.column + 1, row: cursor.row});\n
                if (matching !== null && CstyleBehaviour.isAutoInsertedClosing(cursor, line, text)) {\n
                    CstyleBehaviour.popAutoInsertedClosing();\n
                    return {\n
                        text: \'\',\n
                        selection: [1, 1]\n
                    };\n
                }\n
            }\n
        }\n
    });\n
\n
    this.add("brackets", "deletion", function (state, action, editor, session, range) {\n
        var selected = session.doc.getTextRange(range);\n
        if (!range.isMultiLine() && selected == \'[\') {\n
            var line = session.doc.getLine(range.start.row);\n
            var rightChar = line.substring(range.start.column + 1, range.start.column + 2);\n
            if (rightChar == \']\') {\n
                range.end.column++;\n
                return range;\n
            }\n
        }\n
    });\n
\n
    this.add("string_dquotes", "insertion", function (state, action, editor, session, text) {\n
        if (text == \'"\' || text == "\'") {\n
            var quote = text;\n
            var selection = editor.getSelectionRange();\n
            var selected = session.doc.getTextRange(selection);\n
            if (selected !== "" && selected !== "\'" && selected != \'"\' && editor.getWrapBehavioursEnabled()) {\n
                return {\n
                    text: quote + selected + quote,\n
                    selection: false\n
                };\n
            } else {\n
                var cursor = editor.getCursorPosition();\n
                var line = session.doc.getLine(cursor.row);\n
                var leftChar = line.substring(cursor.column-1, cursor.column);\n
                if (leftChar == \'\\\\\') {\n
                    return null;\n
                }\n
                var tokens = session.getTokens(selection.start.row);\n
                var col = 0, token;\n
                var quotepos = -1; // Track whether we\'re inside an open quote.\n
\n
                for (var x = 0; x < tokens.length; x++) {\n
                    token = tokens[x];\n
                    if (token.type == "string") {\n
                      quotepos = -1;\n
                    } else if (quotepos < 0) {\n
                      quotepos = token.value.indexOf(quote);\n
                    }\n
                    if ((token.value.length + col) > selection.start.column) {\n
                        break;\n
                    }\n
                    col += tokens[x].value.length;\n
                }\n
                if (!token || (quotepos < 0 && token.type !== "comment" && (token.type !== "string" || ((selection.start.column !== token.value.length+col-1) && token.value.lastIndexOf(quote) === token.value.length-1)))) {\n
                    if (!CstyleBehaviour.isSaneInsertion(editor, session))\n
                        return;\n
                    return {\n
                        text: quote + quote,\n
                        selection: [1,1]\n
                    };\n
                } else if (token && token.type === "string") {\n
                    var rightChar = line.substring(cursor.column, cursor.column + 1);\n
                    if (rightChar == quote) {\n
                        return {\n
                            text: \'\',\n
                            selection: [1, 1]\n
                        };\n
                    }\n
                }\n
            }\n
        }\n
    });\n
\n
    this.add("string_dquotes", "deletion", function (state, action, editor, session, range) {\n
        var selected = session.doc.getTextRange(range);\n
        if (!range.isMultiLine() && (selected == \'"\' || selected == "\'")) {\n
            var line = session.doc.getLine(range.start.row);\n
            var rightChar = line.substring(range.start.column + 1, range.start.column + 2);\n
            if (rightChar == selected) {\n
                range.end.column++;\n
                return range;\n
            }\n
        }\n
    });\n
\n
};\n
\n
oop.inherits(CstyleBehaviour, Behaviour);\n
\n
exports.CstyleBehaviour = CstyleBehaviour;\n
});\n


]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
