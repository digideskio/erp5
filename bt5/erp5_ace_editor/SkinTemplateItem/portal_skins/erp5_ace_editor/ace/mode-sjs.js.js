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
            <value> <string>ts83646620.24</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-sjs.js</string> </value>
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
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/sjs\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/javascript\', \'ace/tokenizer\', \'ace/mode/sjs_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/mode/behaviour/cstyle\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
var oop = require("../lib/oop");\n
var JSMode = require("./javascript").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var SJSHighlightRules = require("./sjs_highlight_rules").SJSHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var CstyleBehaviour = require("./behaviour/cstyle").CstyleBehaviour;\n
var CStyleFoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    var highlighter = new SJSHighlightRules();\n
\n
    this.$tokenizer = new Tokenizer(highlighter.getRules());\n
    this.$outdent = new MatchingBraceOutdent();\n
    this.$behaviour = new CstyleBehaviour();\n
    this.$keywordList = highlighter.$keywordList;\n
    this.foldingRules = new CStyleFoldMode();\n
};\n
oop.inherits(Mode, JSMode);\n
(function() {\n
    this.createWorker = function(session) {\n
        return null;\n
    }\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/javascript\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/javascript_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/range\', \'ace/worker/worker_client\', \'ace/mode/behaviour/cstyle\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var JavaScriptHighlightRules = require("./javascript_highlight_rules").JavaScriptHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var Range = require("../range").Range;\n
var WorkerClient = require("../worker/worker_client").WorkerClient;\n
var CstyleBehaviour = require("./behaviour/cstyle").CstyleBehaviour;\n
var CStyleFoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = JavaScriptHighlightRules;\n
    \n
    this.$outdent = new MatchingBraceOutdent();\n
    this.$behaviour = new CstyleBehaviour();\n
    this.foldingRules = new CStyleFoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "//";\n
    this.blockComment = {start: "/*", end: "*/"};\n
\n
    this.getNextLineIndent = function(state, line, tab) {\n
        var indent = this.$getIndent(line);\n
\n
        var tokenizedLine = this.getTokenizer().getLineTokens(line, state);\n
        var tokens = tokenizedLine.tokens;\n
        var endState = tokenizedLine.state;\n
\n
        if (tokens.length && tokens[tokens.length-1].type == "comment") {\n
            return indent;\n
        }\n
\n
        if (state == "start" || state == "no_regex") {\n
            var match = line.match(/^.*(?:\\bcase\\b.*\\:|[\\{\\(\\[])\\s*$/);\n
            if (match) {\n
                indent += tab;\n
            }\n
        } else if (state == "doc-start") {\n
            if (endState == "start" || endState == "no_regex") {\n
                return "";\n
            }\n
            var match = line.match(/^\\s*(\\/?)\\*/);\n
            if (match) {\n
                if (match[1]) {\n
                    indent += " ";\n
                }\n
                indent += "* ";\n
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
    this.createWorker = function(session) {\n
        var worker = new WorkerClient(["ace"], "ace/mode/javascript_worker", "JavaScriptWorker");\n
        worker.attachToDocument(session.getDocument());\n
\n
        worker.on("jslint", function(results) {\n
            session.setAnnotations(results.data);\n
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
\n
define(\'ace/mode/sjs_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/javascript_highlight_rules\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var JavaScriptHighlightRules = require("./javascript_highlight_rules").JavaScriptHighlightRules;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var SJSHighlightRules = function() {\n
    var parent = new JavaScriptHighlightRules();\n
    var escapedRe = "\\\\\\\\(?:x[0-9a-fA-F]{2}|" + // hex\n
        "u[0-9a-fA-F]{4}|" + // unicode\n
        "[0-2][0-7]{0,2}|" + // oct\n
        "3[0-6][0-7]?|" + // oct\n
        "37[0-7]?|" + // oct\n
        "[4-7][0-7]?|" + //oct\n
        ".)";\n
\n
    var contextAware = function(f) {\n
        f.isContextAware = true;\n
        return f;\n
    };\n
\n
    var ctxBegin = function(opts) {\n
        return {\n
            token: opts.token,\n
            regex: opts.regex,\n
            next: contextAware(function(currentState, stack) {\n
                if (stack.length === 0)\n
                    stack.unshift(currentState);\n
                stack.unshift(opts.next);\n
                return opts.next;\n
            }),\n
        };\n
    };\n
\n
    var ctxEnd = function(opts) {\n
        return {\n
            token: opts.token,\n
            regex: opts.regex,\n
            next: contextAware(function(currentState, stack) {\n
                stack.shift();\n
                return stack[0] || "start";\n
            }),\n
        };\n
    };\n
\n
    this.$rules = parent.$rules;\n
    this.$rules.no_regex = [\n
        {\n
            token: "keyword",\n
            regex: "(waitfor|or|and|collapse|spawn|retract)\\\\b"\n
        },\n
        {\n
            token: "keyword.operator",\n
            regex: "(->|=>|\\\\.\\\\.)"\n
        },\n
        {\n
            token: "variable.language",\n
            regex: "(hold|default)\\\\b"\n
        },\n
        ctxBegin({\n
            token: "string",\n
            regex: "`",\n
            next: "bstring"\n
        }),\n
        ctxBegin({\n
            token: "string",\n
            regex: \'"\',\n
            next: "qqstring"\n
        }),\n
        ctxBegin({\n
            token: "string",\n
            regex: \'"\',\n
            next: "qqstring"\n
        }),\n
        {\n
            token: ["paren.lparen", "text", "paren.rparen"],\n
            regex: "(\\\\{)(\\\\s*)(\\\\|)",\n
            next: "block_arguments",\n
        }\n
\n
    ].concat(this.$rules.no_regex);\n
\n
    this.$rules.block_arguments = [\n
        {\n
            token: "paren.rparen",\n
            regex: "\\\\|",\n
            next: "no_regex",\n
        }\n
    ].concat(this.$rules.function_arguments);\n
\n
    this.$rules.bstring = [\n
        {\n
            token : "constant.language.escape",\n
            regex : escapedRe\n
        },\n
        {\n
            token : "string",\n
            regex : "\\\\\\\\$",\n
            next: "bstring"\n
        },\n
        ctxBegin({\n
            token : "paren.lparen",\n
            regex : "\\\\$\\\\{",\n
            next: "string_interp"\n
        }),\n
        ctxBegin({\n
            token : "paren.lparen",\n
            regex : "\\\\$",\n
            next: "bstring_interp_single"\n
        }),\n
        ctxEnd({\n
            token : "string",\n
            regex : "`",\n
        }),\n
        {\n
            defaultToken: "string"\n
        }\n
    ];\n
    \n
    this.$rules.qqstring = [\n
        {\n
            token : "constant.language.escape",\n
            regex : escapedRe\n
        },\n
        {\n
            token : "string",\n
            regex : "\\\\\\\\$",\n
            next: "qqstring",\n
        },\n
        ctxBegin({\n
            token : "paren.lparen",\n
            regex : "#\\\\{",\n
            next: "string_interp"\n
        }),\n
        ctxEnd({\n
            token : "string",\n
            regex : \'"\',\n
        }),\n
        {\n
            defaultToken: "string"\n
        }\n
    ];\n
    var embeddableRules = [];\n
    for (var i=0; i<this.$rules.no_regex.length; i++) {\n
        var rule = this.$rules.no_regex[i];\n
        var token = String(rule.token);\n
        if(token.indexOf(\'paren\') == -1 && (!rule.next || rule.next.isContextAware)) {\n
            embeddableRules.push(rule);\n
        }\n
    };\n
\n
    this.$rules.string_interp = [\n
        ctxEnd({\n
            token: "paren.rparen",\n
            regex: "\\\\}"\n
        }),\n
        ctxBegin({\n
            token: "paren.lparen",\n
            regex: \'{\',\n
            next: "string_interp"\n
        }),\n
    ].concat(embeddableRules);\n
    this.$rules.bstring_interp_single = [\n
        {\n
            token: ["identifier", "paren.lparen"],\n
            regex: \'(\\\\w+)(\\\\()\',\n
            next: \'bstring_interp_single_call\'\n
        },\n
        ctxEnd({\n
            token : "identifier",\n
            regex : "\\\\w*",\n
        })\n
    ];\n
    this.$rules.bstring_interp_single_call = [\n
        ctxBegin({\n
            token: "paren.lparen",\n
            regex: "\\\\(",\n
            next: "bstring_interp_single_call"\n
        }),\n
        ctxEnd({\n
            token: "paren.rparen",\n
            regex: "\\\\)"\n
        })\n
    ].concat(embeddableRules);\n
}\n
oop.inherits(SJSHighlightRules, TextHighlightRules);\n
\n
exports.SJSHighlightRules = SJSHighlightRules;\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>44535</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
