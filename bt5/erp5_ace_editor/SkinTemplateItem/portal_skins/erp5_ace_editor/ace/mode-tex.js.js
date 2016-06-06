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
            <value> <string>ts83646621.15</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-tex.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * tex.js\n
 *\n
 * Copyright (C) 2009-11 by RStudio, Inc.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Ajax.org B.V.\n
 * Portions created by the Initial Developer are Copyright (C) 2010\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n
 *\n
 */\n
define(\'ace/mode/tex\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/text_highlight_rules\', \'ace/mode/tex_highlight_rules\', \'ace/mode/matching_brace_outdent\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var TexHighlightRules = require("./tex_highlight_rules").TexHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
\n
var Mode = function(suppressHighlighting) {\n
\tif (suppressHighlighting)\n
    \tthis.HighlightRules = TextHighlightRules;\n
\telse\n
    \tthis.HighlightRules = TexHighlightRules;\n
    this.$outdent = new MatchingBraceOutdent();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
   this.getNextLineIndent = function(state, line, tab) {\n
      return this.$getIndent(line);\n
   };\n
\n
   this.allowAutoInsert = function() {\n
      return false;\n
   };\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
define(\'ace/mode/tex_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var TexHighlightRules = function(textClass) {\n
\n
    if (!textClass)\n
        textClass = "text";\n
\n
    this.$rules = {\n
        "start" : [\n
\t        {\n
\t            token : "comment",\n
\t            regex : "%.*$"\n
\t        }, {\n
\t            token : textClass, // non-command\n
\t            regex : "\\\\\\\\[$&%#\\\\{\\\\}]"\n
\t        }, {\n
\t            token : "keyword", // command\n
\t            regex : "\\\\\\\\(?:documentclass|usepackage|newcounter|setcounter|addtocounter|value|arabic|stepcounter|newenvironment|renewenvironment|ref|vref|eqref|pageref|label|cite[a-zA-Z]*|tag|begin|end|bibitem)\\\\b",\n
               next : "nospell"\n
\t        }, {\n
\t            token : "keyword", // command\n
\t            regex : "\\\\\\\\(?:[a-zA-z0-9]+|[^a-zA-z0-9])"\n
\t        }, {\n
               token : "paren.keyword.operator",\n
\t            regex : "[[({]"\n
\t        }, {\n
               token : "paren.keyword.operator",\n
\t            regex : "[\\\\])}]"\n
\t        }, {\n
\t            token : textClass,\n
\t            regex : "\\\\s+"\n
\t        }\n
        ],\n
        "nospell" : [\n
           {\n
               token : "comment",\n
               regex : "%.*$",\n
               next : "start"\n
           }, {\n
               token : "nospell." + textClass, // non-command\n
               regex : "\\\\\\\\[$&%#\\\\{\\\\}]"\n
           }, {\n
               token : "keyword", // command\n
               regex : "\\\\\\\\(?:documentclass|usepackage|newcounter|setcounter|addtocounter|value|arabic|stepcounter|newenvironment|renewenvironment|ref|vref|eqref|pageref|label|cite[a-zA-Z]*|tag|begin|end|bibitem)\\\\b"\n
           }, {\n
               token : "keyword", // command\n
               regex : "\\\\\\\\(?:[a-zA-z0-9]+|[^a-zA-z0-9])",\n
               next : "start"\n
           }, {\n
               token : "paren.keyword.operator",\n
               regex : "[[({]"\n
           }, {\n
               token : "paren.keyword.operator",\n
               regex : "[\\\\])]"\n
           }, {\n
               token : "paren.keyword.operator",\n
               regex : "}",\n
               next : "start"\n
           }, {\n
               token : "nospell." + textClass,\n
               regex : "\\\\s+"\n
           }, {\n
               token : "nospell." + textClass,\n
               regex : "\\\\w+"\n
           }\n
        ]\n
    };\n
};\n
\n
oop.inherits(TexHighlightRules, TextHighlightRules);\n
\n
exports.TexHighlightRules = TexHighlightRules;\n
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


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>6579</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
