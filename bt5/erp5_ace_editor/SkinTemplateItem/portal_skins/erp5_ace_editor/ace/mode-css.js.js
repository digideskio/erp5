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
            <value> <string>ts83646622.32</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-css.js</string> </value>
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
define(\'ace/mode/css\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/css_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/worker/worker_client\', \'ace/mode/behaviour/css\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var CssHighlightRules = require("./css_highlight_rules").CssHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var WorkerClient = require("../worker/worker_client").WorkerClient;\n
var CssBehaviour = require("./behaviour/css").CssBehaviour;\n
var CStyleFoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = CssHighlightRules;\n
    this.$outdent = new MatchingBraceOutdent();\n
    this.$behaviour = new CssBehaviour();\n
    this.foldingRules = new CStyleFoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.foldingRules = "cStyle";\n
    this.blockComment = {start: "/*", end: "*/"};\n
\n
    this.getNextLineIndent = function(state, line, tab) {\n
        var indent = this.$getIndent(line);\n
        var tokens = this.getTokenizer().getLineTokens(line, state).tokens;\n
        if (tokens.length && tokens[tokens.length-1].type == "comment") {\n
            return indent;\n
        }\n
\n
        var match = line.match(/^.*\\{\\s*$/);\n
        if (match) {\n
            indent += tab;\n
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
    this.createWorker = function(session) {\n
        var worker = new WorkerClient(["ace"], "ace/mode/css_worker", "Worker");\n
        worker.attachToDocument(session.getDocument());\n
\n
        worker.on("csslint", function(e) {\n
            session.setAnnotations(e.data);\n
        });\n
\n
        worker.on("terminate", function() {\n
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
define(\'ace/mode/behaviour/css\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/behaviour\', \'ace/mode/behaviour/cstyle\', \'ace/token_iterator\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Behaviour = require("../behaviour").Behaviour;\n
var CstyleBehaviour = require("./cstyle").CstyleBehaviour;\n
var TokenIterator = require("../../token_iterator").TokenIterator;\n
\n
var CssBehaviour = function () {\n
\n
    this.inherit(CstyleBehaviour);\n
\n
    this.add("colon", "insertion", function (state, action, editor, session, text) {\n
        if (text === \':\') {\n
            var cursor = editor.getCursorPosition();\n
            var iterator = new TokenIterator(session, cursor.row, cursor.column);\n
            var token = iterator.getCurrentToken();\n
            if (token && token.value.match(/\\s+/)) {\n
                token = iterator.stepBackward();\n
            }\n
            if (token && token.type === \'support.type\') {\n
                var line = session.doc.getLine(cursor.row);\n
                var rightChar = line.substring(cursor.column, cursor.column + 1);\n
                if (rightChar === \':\') {\n
                    return {\n
                       text: \'\',\n
                       selection: [1, 1]\n
                    }\n
                }\n
                if (!line.substring(cursor.column).match(/^\\s*;/)) {\n
                    return {\n
                       text: \':;\',\n
                       selection: [1, 1]\n
                    }\n
                }\n
            }\n
        }\n
    });\n
\n
    this.add("colon", "deletion", function (state, action, editor, session, range) {\n
        var selected = session.doc.getTextRange(range);\n
        if (!range.isMultiLine() && selected === \':\') {\n
            var cursor = editor.getCursorPosition();\n
            var iterator = new TokenIterator(session, cursor.row, cursor.column);\n
            var token = iterator.getCurrentToken();\n
            if (token && token.value.match(/\\s+/)) {\n
                token = iterator.stepBackward();\n
            }\n
            if (token && token.type === \'support.type\') {\n
                var line = session.doc.getLine(range.start.row);\n
                var rightChar = line.substring(range.end.column, range.end.column + 1);\n
                if (rightChar === \';\') {\n
                    range.end.column ++;\n
                    return range;\n
                }\n
            }\n
        }\n
    });\n
\n
    this.add("semicolon", "insertion", function (state, action, editor, session, text) {\n
        if (text === \';\') {\n
            var cursor = editor.getCursorPosition();\n
            var line = session.doc.getLine(cursor.row);\n
            var rightChar = line.substring(cursor.column, cursor.column + 1);\n
            if (rightChar === \';\') {\n
                return {\n
                   text: \'\',\n
                   selection: [1, 1]\n
                }\n
            }\n
        }\n
    });\n
\n
}\n
oop.inherits(CssBehaviour, CstyleBehaviour);\n
\n
exports.CssBehaviour = CssBehaviour;\n
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
\n
define(\'ace/mode/folding/cstyle\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/range\', \'ace/mode/folding/fold_mode\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var Range = require("../../range").Range;\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
\n
var FoldMode = exports.FoldMode = function(commentRegex) {\n
    if (commentRegex) {\n
        this.foldingStartMarker = new RegExp(\n
            this.foldingStartMarker.source.replace(/\\|[^|]*?$/, "|" + commentRegex.start)\n
        );\n
        this.foldingStopMarker = new RegExp(\n
            this.foldingStopMarker.source.replace(/\\|[^|]*?$/, "|" + commentRegex.end)\n
        );\n
    }\n
};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
\n
    this.foldingStartMarker = /(\\{|\\[)[^\\}\\]]*$|^\\s*(\\/\\*)/;\n
    this.foldingStopMarker = /^[^\\[\\{]*(\\}|\\])|^[\\s\\*]*(\\*\\/)/;\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        var match = line.match(this.foldingStartMarker);\n
        if (match) {\n
            var i = match.index;\n
\n
            if (match[1])\n
                return this.openingBracketBlock(session, match[1], row, i);\n
\n
            return session.getCommentFoldRange(row, i + match[0].length, 1);\n
        }\n
\n
        if (foldStyle !== "markbeginend")\n
            return;\n
\n
        var match = line.match(this.foldingStopMarker);\n
        if (match) {\n
            var i = match.index + match[0].length;\n
\n
            if (match[1])\n
                return this.closingBracketBlock(session, match[1], row, i);\n
\n
            return session.getCommentFoldRange(row, i, -1);\n
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
            <value> <int>34059</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>mode-css.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
