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
            <value> <string>ts83646621.7</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-lucene.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>define(\'ace/mode/lucene\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/lucene_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var LuceneHighlightRules = require("./lucene_highlight_rules").LuceneHighlightRules;\n
\n
var Mode = function() {\n
    this.$tokenizer =  new Tokenizer(new LuceneHighlightRules().getRules());\n
};\n
\n
oop.inherits(Mode, TextMode);\n
\n
exports.Mode = Mode;\n
});define(\'ace/mode/lucene_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var LuceneHighlightRules = function() {\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "constant.character.negation",\n
                regex : "[\\\\-]"\n
            }, {\n
                token : "constant.character.interro",\n
                regex : "[\\\\?]"\n
            }, {\n
                token : "constant.character.asterisk",\n
                regex : "[\\\\*]"\n
            }, {\n
                token: \'constant.character.proximity\',\n
                regex: \'~[0-9]+\\\\b\'\n
            }, {\n
                token : \'keyword.operator\',\n
                regex: \'(?:AND|OR|NOT)\\\\b\'\n
            }, {\n
                token : "paren.lparen",\n
                regex : "[\\\\(]"\n
            }, {\n
                token : "paren.rparen",\n
                regex : "[\\\\)]"\n
            }, {\n
                token : "keyword",\n
                regex : "[\\\\S]+:"\n
            }, {\n
                token : "string",           // " string\n
                regex : \'".*?"\'\n
            }, {\n
                token : "text",\n
                regex : "\\\\s+"\n
            }\n
        ]\n
    };\n
};\n
\n
oop.inherits(LuceneHighlightRules, TextHighlightRules);\n
\n
exports.LuceneHighlightRules = LuceneHighlightRules;\n
});\n
</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>2079</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
