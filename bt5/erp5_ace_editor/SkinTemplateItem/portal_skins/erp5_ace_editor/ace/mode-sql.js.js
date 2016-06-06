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
            <value> <string>ts83646621.21</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-sql.js</string> </value>
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
define(\'ace/mode/sql\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/sql_highlight_rules\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var SqlHighlightRules = require("./sql_highlight_rules").SqlHighlightRules;\n
var Range = require("../range").Range;\n
\n
var Mode = function() {\n
    this.HighlightRules = SqlHighlightRules;\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "--";\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
\n
});\n
\n
define(\'ace/mode/sql_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var SqlHighlightRules = function() {\n
\n
    var keywords = (\n
        "select|insert|update|delete|from|where|and|or|group|by|order|limit|offset|having|as|case|" +\n
        "when|else|end|type|left|right|join|on|outer|desc|asc"\n
    );\n
\n
    var builtinConstants = (\n
        "true|false|null"\n
    );\n
\n
    var builtinFunctions = (\n
        "count|min|max|avg|sum|rank|now|coalesce"\n
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
            regex : "--.*$"\n
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
oop.inherits(SqlHighlightRules, TextHighlightRules);\n
\n
exports.SqlHighlightRules = SqlHighlightRules;\n
});\n
\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4174</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>mode-sql.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
