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
            <value> <string>ts83646621.01</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-verilog.js</string> </value>
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
define(\'ace/mode/verilog\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/verilog_highlight_rules\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var VerilogHighlightRules = require("./verilog_highlight_rules").VerilogHighlightRules;\n
var Range = require("../range").Range;\n
\n
var Mode = function() {\n
    this.HighlightRules = VerilogHighlightRules;\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "//";\n
    this.blockComment = {start: "/*", end: "*/"};\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
\n
});\n
\n
\n
define(\'ace/mode/verilog_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var VerilogHighlightRules = function() {\n
var keywords = "always|and|assign|automatic|begin|buf|bufif0|bufif1|case|casex|casez|cell|cmos|config|" +\n
    "deassign|default|defparam|design|disable|edge|else|end|endcase|endconfig|endfunction|endgenerate|endmodule|" +\n
    "endprimitive|endspecify|endtable|endtask|event|for|force|forever|fork|function|generate|genvar|highz0|" +\n
    "highz1|if|ifnone|incdir|include|initial|inout|input|instance|integer|join|large|liblist|library|localparam|" +\n
    "macromodule|medium|module|nand|negedge|nmos|nor|noshowcancelled|not|notif0|notif1|or|output|parameter|pmos|" +\n
    "posedge|primitive|pull0|pull1|pulldown|pullup|pulsestyle_onevent|pulsestyle_ondetect|rcmos|real|realtime|" +\n
    "reg|release|repeat|rnmos|rpmos|rtran|rtranif0|rtranif1|scalared|showcancelled|signed|small|specify|specparam|" +\n
    "strong0|strong1|supply0|supply1|table|task|time|tran|tranif0|tranif1|tri|tri0|tri1|triand|trior|trireg|" +\n
    "unsigned|use|vectored|wait|wand|weak0|weak1|while|wire|wor|xnor|xor" +\n
    "begin|bufif0|bufif1|case|casex|casez|config|else|end|endcase|endconfig|endfunction|" +\n
    "endgenerate|endmodule|endprimitive|endspecify|endtable|endtask|for|forever|function|generate|if|ifnone|" +\n
    "macromodule|module|primitive|repeat|specify|table|task|while";\n
\n
    var builtinConstants = (\n
        "true|false|null"\n
    );\n
\n
    var builtinFunctions = (\n
        "count|min|max|avg|sum|rank|now|coalesce|main"\n
    );\n
\n
    var keywordMapper = this.createKeywordMapper({\n
        "support.function": builtinFunctions,\n
        "keyword": keywords,\n
        "constant.language": builtinConstants\n
    }, "identifier", true);\n
\n
    this.$rules = {\n
        "start" : [ {\n
            token : "comment",\n
            regex : "//.*$"\n
        }, {\n
            token : "string",           // " string\n
            regex : \'".*?"\'\n
        }, {\n
            token : "string",           // \' string\n
            regex : "\'.*?\'"\n
        }, {\n
            token : "constant.numeric", // float\n
            regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
        }, {\n
            token : keywordMapper,\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        }, {\n
            token : "keyword.operator",\n
            regex : "\\\\+|\\\\-|\\\\/|\\\\/\\\\/|%|<@>|@>|<@|&|\\\\^|~|<|>|<=|=>|==|!=|<>|="\n
        }, {\n
            token : "paren.lparen",\n
            regex : "[\\\\(]"\n
        }, {\n
            token : "paren.rparen",\n
            regex : "[\\\\)]"\n
        }, {\n
            token : "text",\n
            regex : "\\\\s+"\n
        } ]\n
    };\n
};\n
\n
oop.inherits(VerilogHighlightRules, TextHighlightRules);\n
\n
exports.VerilogHighlightRules = VerilogHighlightRules;\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>5336</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
