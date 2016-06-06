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
            <value> <string>ts83646621.64</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-mushcode.js</string> </value>
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
define(\'ace/mode/mushcode\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/mushcode_high_rules\', \'ace/mode/folding/pythonic\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var MushCodeRules = require("./mushcode_high_rules").MushCodeRules;\n
var PythonFoldMode = require("./folding/pythonic").FoldMode;\n
var Range = require("../range").Range;\n
\n
var Mode = function() {\n
    this.HighlightRules = MushCodeRules;\n
    this.foldingRules = new PythonFoldMode("\\\\:");\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "#";\n
\n
    this.getNextLineIndent = function(state, line, tab) {\n
        var indent = this.$getIndent(line);\n
\n
        var tokenizedLine = this.getTokenizer().getLineTokens(line, state);\n
        var tokens = tokenizedLine.tokens;\n
\n
        if (tokens.length && tokens[tokens.length-1].type == "comment") {\n
            return indent;\n
        }\n
\n
        if (state == "start") {\n
            var match = line.match(/^.*[\\{\\(\\[\\:]\\s*$/);\n
            if (match) {\n
                indent += tab;\n
            }\n
        }\n
\n
        return indent;\n
    };\n
\n
   var outdents = {\n
        "pass": 1,\n
        "return": 1,\n
        "raise": 1,\n
        "break": 1,\n
        "continue": 1\n
    };\n
\n
    this.checkOutdent = function(state, line, input) {\n
        if (input !== "\\r\\n" && input !== "\\r" && input !== "\\n")\n
            return false;\n
\n
        var tokens = this.getTokenizer().getLineTokens(line.trim(), state).tokens;\n
\n
        if (!tokens)\n
            return false;\n
        do {\n
            var last = tokens.pop();\n
        } while (last && (last.type == "comment" || (last.type == "text" && last.value.match(/^\\s+$/))));\n
\n
        if (!last)\n
            return false;\n
\n
        return (last.type == "keyword" && outdents[last.value]);\n
    };\n
\n
    this.autoOutdent = function(state, doc, row) {\n
\n
        row += 1;\n
        var indent = this.$getIndent(doc.getLine(row));\n
        var tab = doc.getTabString();\n
        if (indent.slice(-tab.length) == tab)\n
            doc.remove(new Range(row, indent.length-tab.length, row, indent.length));\n
    };\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/mushcode_high_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var MushCodeRules = function() {\n
\n
\n
    var keywords = (\n
 "@if|"+\n
 "@ifelse|"+\n
 "@switch|"+\n
 "@halt|"+\n
 "@dolist|"+\n
 "@create|"+\n
 "@scent|"+\n
 "@sound|"+\n
 "@touch|"+\n
 "@ataste|"+\n
 "@osound|"+\n
 "@ahear|"+\n
 "@aahear|"+\n
 "@amhear|"+\n
 "@otouch|"+\n
 "@otaste|"+\n
 "@drop|"+\n
 "@odrop|"+\n
 "@adrop|"+\n
 "@dropfail|"+\n
 "@odropfail|"+\n
 "@smell|"+\n
 "@oemit|"+\n
 "@emit|"+\n
 "@pemit|"+\n
 "@parent|"+\n
 "@clone|"+\n
 "@taste|"+\n
 "whisper|"+\n
 "page|"+\n
 "say|"+\n
 "pose|"+\n
 "semipose|"+\n
 "teach|"+\n
 "touch|"+\n
 "taste|"+\n
 "smell|"+\n
 "listen|"+\n
 "look|"+\n
 "move|"+\n
 "go|"+\n
 "home|"+\n
 "follow|"+\n
 "unfollow|"+\n
 "desert|"+\n
 "dismiss|"+\n
 "@tel"\n
    );\n
\n
    var builtinConstants = (\n
        "=#0"\n
    );\n
\n
    var builtinFunctions = (\n
 "default|"+\n
 "edefault|"+\n
 "eval|"+\n
 "get_eval|"+\n
 "get|"+\n
 "grep|"+\n
 "grepi|"+\n
 "hasattr|"+\n
 "hasattrp|"+\n
 "hasattrval|"+\n
 "hasattrpval|"+\n
 "lattr|"+\n
 "nattr|"+\n
 "poss|"+\n
 "udefault|"+\n
 "ufun|"+\n
 "u|"+\n
 "v|"+\n
 "uldefault|"+\n
 "xget|"+\n
 "zfun|"+\n
 "band|"+\n
 "bnand|"+\n
 "bnot|"+\n
 "bor|"+\n
 "bxor|"+\n
 "shl|"+\n
 "shr|"+\n
 "and|"+\n
 "cand|"+\n
 "cor|"+\n
 "eq|"+\n
 "gt|"+\n
 "gte|"+\n
 "lt|"+\n
 "lte|"+\n
 "nand|"+\n
 "neq|"+\n
 "nor|"+\n
 "not|"+\n
 "or|"+\n
 "t|"+\n
 "xor|"+\n
 "con|"+\n
 "entrances|"+\n
 "exit|"+\n
 "followers|"+\n
 "home|"+\n
 "lcon|"+\n
 "lexits|"+\n
 "loc|"+\n
 "locate|"+\n
 "lparent|"+\n
 "lsearch|"+\n
 "next|"+\n
 "num|"+\n
 "owner|"+\n
 "parent|"+\n
 "pmatch|"+\n
 "rloc|"+\n
 "rnum|"+\n
 "room|"+\n
 "where|"+\n
 "zone|"+\n
 "worn|"+\n
 "held|"+\n
 "carried|"+\n
 "acos|"+\n
 "asin|"+\n
 "atan|"+\n
 "ceil|"+\n
 "cos|"+\n
 "e|"+\n
 "exp|"+\n
 "fdiv|"+\n
 "fmod|"+\n
 "floor|"+\n
 "log|"+\n
 "ln|"+\n
 "pi|"+\n
 "power|"+\n
 "round|"+\n
 "sin|"+\n
 "sqrt|"+\n
 "tan|"+\n
 "aposs|"+\n
 "andflags|"+\n
 "conn|"+\n
 "commandssent|"+\n
 "controls|"+\n
 "doing|"+\n
 "elock|"+\n
 "findable|"+\n
 "flags|"+\n
 "fullname|"+\n
 "hasflag|"+\n
 "haspower|"+\n
 "hastype|"+\n
 "hidden|"+\n
 "idle|"+\n
 "isbaker|"+\n
 "lock|"+\n
 "lstats|"+\n
 "money|"+\n
 "who|"+\n
 "name|"+\n
 "nearby|"+\n
 "obj|"+\n
 "objflags|"+\n
 "photo|"+\n
 "poll|"+\n
 "powers|"+\n
 "pendingtext|"+\n
 "receivedtext|"+\n
 "restarts|"+\n
 "restarttime|"+\n
 "subj|"+\n
 "shortestpath|"+\n
 "tmoney|"+\n
 "type|"+\n
 "visible|"+\n
 "cat|"+\n
 "element|"+\n
 "elements|"+\n
 "extract|"+\n
 "filter|"+\n
 "filterbool|"+\n
 "first|"+\n
 "foreach|"+\n
 "fold|"+\n
 "grab|"+\n
 "graball|"+\n
 "index|"+\n
 "insert|"+\n
 "itemize|"+\n
 "items|"+\n
 "iter|"+\n
 "last|"+\n
 "ldelete|"+\n
 "map|"+\n
 "match|"+\n
 "matchall|"+\n
 "member|"+\n
 "mix|"+\n
 "munge|"+\n
 "pick|"+\n
 "remove|"+\n
 "replace|"+\n
 "rest|"+\n
 "revwords|"+\n
 "setdiff|"+\n
 "setinter|"+\n
 "setunion|"+\n
 "shuffle|"+\n
 "sort|"+\n
 "sortby|"+\n
 "splice|"+\n
 "step|"+\n
 "wordpos|"+\n
 "words|"+\n
 "add|"+\n
 "lmath|"+\n
 "max|"+\n
 "mean|"+\n
 "median|"+\n
 "min|"+\n
 "mul|"+\n
 "percent|"+\n
 "sign|"+\n
 "stddev|"+\n
 "sub|"+\n
 "val|"+\n
 "bound|"+\n
 "abs|"+\n
 "inc|"+\n
 "dec|"+\n
 "dist2d|"+\n
 "dist3d|"+\n
 "div|"+\n
 "floordiv|"+\n
 "mod|"+\n
 "modulo|"+\n
 "remainder|"+\n
 "vadd|"+\n
 "vdim|"+\n
 "vdot|"+\n
 "vmag|"+\n
 "vmax|"+\n
 "vmin|"+\n
 "vmul|"+\n
 "vsub|"+\n
 "vunit|"+\n
 "regedit|"+\n
 "regeditall|"+\n
 "regeditalli|"+\n
 "regediti|"+\n
 "regmatch|"+\n
 "regmatchi|"+\n
 "regrab|"+\n
 "regraball|"+\n
 "regraballi|"+\n
 "regrabi|"+\n
 "regrep|"+\n
 "regrepi|"+\n
 "after|"+\n
 "alphamin|"+\n
 "alphamax|"+\n
 "art|"+\n
 "before|"+\n
 "brackets|"+\n
 "capstr|"+\n
 "case|"+\n
 "caseall|"+\n
 "center|"+\n
 "containsfansi|"+\n
 "comp|"+\n
 "decompose|"+\n
 "decrypt|"+\n
 "delete|"+\n
 "edit|"+\n
 "encrypt|"+\n
 "escape|"+\n
 "if|"+\n
 "ifelse|"+\n
 "lcstr|"+\n
 "left|"+\n
 "lit|"+\n
 "ljust|"+\n
 "merge|"+\n
 "mid|"+\n
 "ostrlen|"+\n
 "pos|"+\n
 "repeat|"+\n
 "reverse|"+\n
 "right|"+\n
 "rjust|"+\n
 "scramble|"+\n
 "secure|"+\n
 "space|"+\n
 "spellnum|"+\n
 "squish|"+\n
 "strcat|"+\n
 "strmatch|"+\n
 "strinsert|"+\n
 "stripansi|"+\n
 "stripfansi|"+\n
 "strlen|"+\n
 "switch|"+\n
 "switchall|"+\n
 "table|"+\n
 "tr|"+\n
 "trim|"+\n
 "ucstr|"+\n
 "unsafe|"+\n
 "wrap|"+\n
 "ctitle|"+\n
 "cwho|"+\n
 "channels|"+\n
 "clock|"+\n
 "cflags|"+\n
 "ilev|"+\n
 "itext|"+\n
 "inum|"+\n
 "convsecs|"+\n
 "convutcsecs|"+\n
 "convtime|"+\n
 "ctime|"+\n
 "etimefmt|"+\n
 "isdaylight|"+\n
 "mtime|"+\n
 "secs|"+\n
 "msecs|"+\n
 "starttime|"+\n
 "time|"+\n
 "timefmt|"+\n
 "timestring|"+\n
 "utctime|"+\n
 "atrlock|"+\n
 "clone|"+\n
 "create|"+\n
 "cook|"+\n
 "dig|"+\n
 "emit|"+\n
 "lemit|"+\n
 "link|"+\n
 "oemit|"+\n
 "open|"+\n
 "pemit|"+\n
 "remit|"+\n
 "set|"+\n
 "tel|"+\n
 "wipe|"+\n
 "zemit|"+\n
 "fbcreate|"+\n
 "fbdestroy|"+\n
 "fbwrite|"+\n
 "fbclear|"+\n
 "fbcopy|"+\n
 "fbcopyto|"+\n
 "fbclip|"+\n
 "fbdump|"+\n
 "fbflush|"+\n
 "fbhset|"+\n
 "fblist|"+\n
 "fbstats|"+\n
 "qentries|"+\n
 "qentry|"+\n
 "play|"+\n
 "ansi|"+\n
 "break|"+\n
 "c|"+\n
 "asc|"+\n
 "die|"+\n
 "isdbref|"+\n
 "isint|"+\n
 "isnum|"+\n
 "isletters|"+\n
 "linecoords|"+\n
 "localize|"+\n
 "lnum|"+\n
 "nameshort|"+\n
 "null|"+\n
 "objeval|"+\n
 "r|"+\n
 "rand|"+\n
 "s|"+\n
 "setq|"+\n
 "setr|"+\n
 "soundex|"+\n
 "soundslike|"+\n
 "valid|"+\n
 "vchart|"+\n
 "vchart2|"+\n
 "vlabel|"+\n
 "@@|"+\n
 "bakerdays|"+\n
 "bodybuild|"+\n
 "box|"+\n
 "capall|"+\n
 "catalog|"+\n
 "children|"+\n
 "ctrailer|"+\n
 "darttime|"+\n
 "debt|"+\n
 "detailbar|"+\n
 "exploredroom|"+\n
 "fansitoansi|"+\n
 "fansitoxansi|"+\n
 "fullbar|"+\n
 "halfbar|"+\n
 "isdarted|"+\n
 "isnewbie|"+\n
 "isword|"+\n
 "lambda|"+\n
 "lobjects|"+\n
 "lplayers|"+\n
 "lthings|"+\n
 "lvexits|"+\n
 "lvobjects|"+\n
 "lvplayers|"+\n
 "lvthings|"+\n
 "newswrap|"+\n
 "numsuffix|"+\n
 "playerson|"+\n
 "playersthisweek|"+\n
 "randomad|"+\n
 "randword|"+\n
 "realrandword|"+\n
 "replacechr|"+\n
 "second|"+\n
 "splitamount|"+\n
 "strlenall|"+\n
 "text|"+\n
 "third|"+\n
 "tofansi|"+\n
 "totalac|"+\n
 "unique|"+\n
 "getaddressroom|"+\n
 "listpropertycomm|"+\n
 "listpropertyres|"+\n
 "lotowner|"+\n
 "lotrating|"+\n
 "lotratingcount|"+\n
 "lotvalue|"+\n
 "boughtproduct|"+\n
 "companyabb|"+\n
 "companyicon|"+\n
 "companylist|"+\n
 "companyname|"+\n
 "companyowners|"+\n
 "companyvalue|"+\n
 "employees|"+\n
 "invested|"+\n
 "productlist|"+\n
 "productname|"+\n
 "productowners|"+\n
 "productrating|"+\n
 "productratingcount|"+\n
 "productsoldat|"+\n
 "producttype|"+\n
 "ratedproduct|"+\n
 "soldproduct|"+\n
 "topproducts|"+\n
 "totalspentonproduct|"+\n
 "totalstock|"+\n
 "transfermoney|"+\n
 "uniquebuyercount|"+\n
 "uniqueproductsbought|"+\n
 "validcompany|"+\n
 "deletepicture|"+\n
 "fbsave|"+\n
 "getpicturesecurity|"+\n
 "haspicture|"+\n
 "listpictures|"+\n
 "picturesize|"+\n
 "replacecolor|"+\n
 "rgbtocolor|"+\n
 "savepicture|"+\n
 "setpicturesecurity|"+\n
 "showpicture|"+\n
 "piechart|"+\n
 "piechartlabel|"+\n
 "createmaze|"+\n
 "drawmaze|"+\n
 "drawwireframe"\n
    );\n
    var keywordMapper = this.createKeywordMapper({\n
        "invalid.deprecated": "debugger",\n
        "support.function": builtinFunctions,\n
        "constant.language": builtinConstants,\n
        "keyword": keywords\n
    }, "identifier");\n
\n
    var strPre = "(?:r|u|ur|R|U|UR|Ur|uR)?";\n
\n
    var decimalInteger = "(?:(?:[1-9]\\\\d*)|(?:0))";\n
    var octInteger = "(?:0[oO]?[0-7]+)";\n
    var hexInteger = "(?:0[xX][\\\\dA-Fa-f]+)";\n
    var binInteger = "(?:0[bB][01]+)";\n
    var integer = "(?:" + decimalInteger + "|" + octInteger + "|" + hexInteger + "|" + binInteger + ")";\n
\n
    var exponent = "(?:[eE][+-]?\\\\d+)";\n
    var fraction = "(?:\\\\.\\\\d+)";\n
    var intPart = "(?:\\\\d+)";\n
    var pointFloat = "(?:(?:" + intPart + "?" + fraction + ")|(?:" + intPart + "\\\\.))";\n
    var exponentFloat = "(?:(?:" + pointFloat + "|" +  intPart + ")" + exponent + ")";\n
    var floatNumber = "(?:" + exponentFloat + "|" + pointFloat + ")";\n
\n
    this.$rules = {\n
        "start" : [\n
         {\n
                token : "variable", // mush substitution register\n
                regex : "%[0-9]{1}"\n
         },\n
         {\n
                token : "variable", // mush substitution register\n
                regex : "%q[0-9A-Za-z]{1}"\n
         },\n
         {\n
                token : "variable", // mush special character register\n
                regex : "%[a-zA-Z]{1}"\n
         },\n
         {\n
                token: "variable.language",\n
                regex: "%[a-z0-9-_]+"\n
         },\n
        {\n
            token : "constant.numeric", // imaginary\n
            regex : "(?:" + floatNumber + "|\\\\d+)[jJ]\\\\b"\n
        }, {\n
            token : "constant.numeric", // float\n
            regex : floatNumber\n
        }, {\n
            token : "constant.numeric", // long integer\n
            regex : integer + "[lL]\\\\b"\n
        }, {\n
            token : "constant.numeric", // integer\n
            regex : integer + "\\\\b"\n
        }, {\n
            token : keywordMapper,\n
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
        }, {\n
            token : "keyword.operator",\n
            regex : "\\\\+|\\\\-|\\\\*|\\\\*\\\\*|\\\\/|\\\\/\\\\/|#|%|<<|>>|\\\\||\\\\^|~|<|>|<=|=>|==|!=|<>|="\n
        }, {\n
            token : "paren.lparen",\n
            regex : "[\\\\[\\\\(\\\\{]"\n
        }, {\n
            token : "paren.rparen",\n
            regex : "[\\\\]\\\\)\\\\}]"\n
        }, {\n
            token : "text",\n
            regex : "\\\\s+"\n
        } ]\n
    };\n
};\n
\n
oop.inherits(MushCodeRules, TextHighlightRules);\n
\n
exports.MushCodeRules = MushCodeRules;\n
});\n
\n
define(\'ace/mode/folding/pythonic\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/folding/fold_mode\'], function(require, exports, module) {\n
\n
\n
var oop = require("../../lib/oop");\n
var BaseFoldMode = require("./fold_mode").FoldMode;\n
\n
var FoldMode = exports.FoldMode = function(markers) {\n
    this.foldingStartMarker = new RegExp("([\\\\[{])(?:\\\\s*)$|(" + markers + ")(?:\\\\s*)(?:#.*)?$");\n
};\n
oop.inherits(FoldMode, BaseFoldMode);\n
\n
(function() {\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        var match = line.match(this.foldingStartMarker);\n
        if (match) {\n
            if (match[1])\n
                return this.openingBracketBlock(session, match[1], row, match.index);\n
            if (match[2])\n
                return this.indentationBlock(session, row, match.index + match[2].length);\n
            return this.indentationBlock(session, row);\n
        }\n
    }\n
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
            <value> <int>13699</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
