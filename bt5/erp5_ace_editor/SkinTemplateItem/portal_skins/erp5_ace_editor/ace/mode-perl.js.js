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
            <value> <string>ts83646621.55</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-perl.js</string> </value>
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
define(\'ace/mode/perl\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/perl_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/range\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var PerlHighlightRules = require("./perl_highlight_rules").PerlHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var Range = require("../range").Range;\n
var CStyleFoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = PerlHighlightRules;\n
    \n
    this.$outdent = new MatchingBraceOutdent();\n
    this.foldingRules = new CStyleFoldMode({start: "^=(begin|item)\\\\b", end: "^=(cut)\\\\b"});\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = "#";\n
    this.blockComment = [\n
        {start: "=begin", end: "=cut"},\n
        {start: "=item", end: "=cut"}\n
    ];\n
\n
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
    this.checkOutdent = function(state, line, input) {\n
        return this.$outdent.checkOutdent(line, input);\n
    };\n
\n
    this.autoOutdent = function(state, doc, row) {\n
        this.$outdent.autoOutdent(doc, row);\n
    };\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/perl_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var PerlHighlightRules = function() {\n
\n
    var keywords = (\n
        "base|constant|continue|else|elsif|for|foreach|format|goto|if|last|local|my|next|" +\n
         "no|package|parent|redo|require|scalar|sub|unless|until|while|use|vars"\n
    );\n
\n
    var buildinConstants = ("ARGV|ENV|INC|SIG");\n
\n
    var builtinFunctions = (\n
        "getprotobynumber|getprotobyname|getservbyname|gethostbyaddr|" +\n
         "gethostbyname|getservbyport|getnetbyaddr|getnetbyname|getsockname|" +\n
         "getpeername|setpriority|getprotoent|setprotoent|getpriority|" +\n
         "endprotoent|getservent|setservent|endservent|sethostent|socketpair|" +\n
         "getsockopt|gethostent|endhostent|setsockopt|setnetent|quotemeta|" +\n
         "localtime|prototype|getnetent|endnetent|rewinddir|wantarray|getpwuid|" +\n
         "closedir|getlogin|readlink|endgrent|getgrgid|getgrnam|shmwrite|" +\n
         "shutdown|readline|endpwent|setgrent|readpipe|formline|truncate|" +\n
         "dbmclose|syswrite|setpwent|getpwnam|getgrent|getpwent|ucfirst|sysread|" +\n
         "setpgrp|shmread|sysseek|sysopen|telldir|defined|opendir|connect|" +\n
         "lcfirst|getppid|binmode|syscall|sprintf|getpgrp|readdir|seekdir|" +\n
         "waitpid|reverse|unshift|symlink|dbmopen|semget|msgrcv|rename|listen|" +\n
         "chroot|msgsnd|shmctl|accept|unpack|exists|fileno|shmget|system|" +\n
         "unlink|printf|gmtime|msgctl|semctl|values|rindex|substr|splice|" +\n
         "length|msgget|select|socket|return|caller|delete|alarm|ioctl|index|" +\n
         "undef|lstat|times|srand|chown|fcntl|close|write|umask|rmdir|study|" +\n
         "sleep|chomp|untie|print|utime|mkdir|atan2|split|crypt|flock|chmod|" +\n
         "BEGIN|bless|chdir|semop|shift|reset|link|stat|chop|grep|fork|dump|" +\n
         "join|open|tell|pipe|exit|glob|warn|each|bind|sort|pack|eval|push|" +\n
         "keys|getc|kill|seek|sqrt|send|wait|rand|tied|read|time|exec|recv|" +\n
         "eof|chr|int|ord|exp|pos|pop|sin|log|abs|oct|hex|tie|cos|vec|END|ref|" +\n
         "map|die|uc|lc|do"\n
    );\n
\n
    var keywordMapper = this.createKeywordMapper({\n
        "keyword": keywords,\n
        "constant.language": buildinConstants,\n
        "support.function": builtinFunctions\n
    }, "identifier");\n
\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment.doc",\n
                regex : "^=(?:begin|item)\\\\b",\n
                next : "block_comment"\n
            }, {\n
                token : "string.regexp",\n
                regex : "[/](?:(?:\\\\[(?:\\\\\\\\]|[^\\\\]])+\\\\])|(?:\\\\\\\\/|[^\\\\]/]))*[/]\\\\w*\\\\s*(?=[).,;]|$)"\n
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
                token : "constant.numeric", // hex\n
                regex : "0x[0-9a-fA-F]+\\\\b"\n
            }, {\n
                token : "constant.numeric", // float\n
                regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
            }, {\n
                token : keywordMapper,\n
                regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
            }, {\n
                token : "keyword.operator",\n
                regex : "%#|\\\\$#|\\\\.\\\\.\\\\.|\\\\|\\\\|=|>>=|<<=|<=>|&&=|=>|!~|\\\\^=|&=|\\\\|=|\\\\.=|x=|%=|\\\\/=|\\\\*=|\\\\-=|\\\\+=|=~|\\\\*\\\\*|\\\\-\\\\-|\\\\.\\\\.|\\\\|\\\\||&&|\\\\+\\\\+|\\\\->|!=|==|>=|<=|>>|<<|,|=|\\\\?\\\\:|\\\\^|\\\\||x|%|\\\\/|\\\\*|<|&|\\\\\\\\|~|!|>|\\\\.|\\\\-|\\\\+|\\\\-C|\\\\-b|\\\\-S|\\\\-u|\\\\-t|\\\\-p|\\\\-l|\\\\-d|\\\\-f|\\\\-g|\\\\-s|\\\\-z|\\\\-k|\\\\-e|\\\\-O|\\\\-T|\\\\-B|\\\\-M|\\\\-A|\\\\-X|\\\\-W|\\\\-c|\\\\-R|\\\\-o|\\\\-x|\\\\-w|\\\\-r|\\\\b(?:and|cmp|eq|ge|gt|le|lt|ne|not|or|xor)"\n
            }, {\n
                token : "comment",\n
                regex : "#.*$"\n
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
        ],\n
        "block_comment": [\n
            {\n
                token: "comment.doc", \n
                regex: "^=cut\\\\b",\n
                next: "start"\n
            },\n
            {\n
                defaultToken: "comment.doc"\n
            }\n
        ]\n
    };\n
};\n
\n
oop.inherits(PerlHighlightRules, TextHighlightRules);\n
\n
exports.PerlHighlightRules = PerlHighlightRules;\n
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
            <value> <int>11735</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
