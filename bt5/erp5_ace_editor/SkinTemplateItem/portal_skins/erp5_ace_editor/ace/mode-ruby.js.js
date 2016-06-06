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
            <value> <string>ts83646621.35</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-ruby.js</string> </value>
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
define(\'ace/mode/ruby\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/ruby_highlight_rules\', \'ace/mode/matching_brace_outdent\', \'ace/range\', \'ace/mode/folding/coffee\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var RubyHighlightRules = require("./ruby_highlight_rules").RubyHighlightRules;\n
var MatchingBraceOutdent = require("./matching_brace_outdent").MatchingBraceOutdent;\n
var Range = require("../range").Range;\n
var FoldMode = require("./folding/coffee").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = RubyHighlightRules;\n
    this.$outdent = new MatchingBraceOutdent();\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
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
            var match = line.match(/^.*[\\{\\(\\[]\\s*$/);\n
            var startingClassOrMethod = line.match(/^\\s*(class|def)\\s.*$/);\n
            var startingDoBlock = line.match(/.*do(\\s*|\\s+\\|.*\\|\\s*)$/);\n
            var startingConditional = line.match(/^\\s*(if|else)\\s*/)\n
            if (match || startingClassOrMethod || startingDoBlock || startingConditional) {\n
                indent += tab;\n
            }\n
        }\n
\n
        return indent;\n
    };\n
\n
    this.checkOutdent = function(state, line, input) {\n
        return /^\\s+end$/.test(line + input) || /^\\s+}$/.test(line + input) || /^\\s+else$/.test(line + input);\n
    };\n
\n
    this.autoOutdent = function(state, doc, row) {\n
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
define(\'ace/mode/ruby_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var constantOtherSymbol = exports.constantOtherSymbol = {\n
    token : "constant.other.symbol.ruby", // symbol\n
    regex : "[:](?:[A-Za-z_]|[@$](?=[a-zA-Z0-9_]))[a-zA-Z0-9_]*[!=?]?"\n
};\n
\n
var qString = exports.qString = {\n
    token : "string", // single line\n
    regex : "[\'](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[\']"\n
};\n
\n
var qqString = exports.qqString = {\n
    token : "string", // single line\n
    regex : \'["](?:(?:\\\\\\\\.)|(?:[^"\\\\\\\\]))*?["]\'\n
};\n
\n
var tString = exports.tString = {\n
    token : "string", // backtick string\n
    regex : "[`](?:(?:\\\\\\\\.)|(?:[^\'\\\\\\\\]))*?[`]"\n
};\n
\n
var constantNumericHex = exports.constantNumericHex = {\n
    token : "constant.numeric", // hex\n
    regex : "0[xX][0-9a-fA-F](?:[0-9a-fA-F]|_(?=[0-9a-fA-F]))*\\\\b"\n
};\n
\n
var constantNumericFloat = exports.constantNumericFloat = {\n
    token : "constant.numeric", // float\n
    regex : "[+-]?\\\\d(?:\\\\d|_(?=\\\\d))*(?:(?:\\\\.\\\\d(?:\\\\d|_(?=\\\\d))*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
};\n
\n
var RubyHighlightRules = function() {\n
\n
    var builtinFunctions = (\n
        "abort|Array|assert|assert_equal|assert_not_equal|assert_same|assert_not_same|" +\n
        "assert_nil|assert_not_nil|assert_match|assert_no_match|assert_in_delta|assert_throws|" +\n
        "assert_raise|assert_nothing_raised|assert_instance_of|assert_kind_of|assert_respond_to|" +\n
        "assert_operator|assert_send|assert_difference|assert_no_difference|assert_recognizes|" +\n
        "assert_generates|assert_response|assert_redirected_to|assert_template|assert_select|" +\n
        "assert_select_email|assert_select_rjs|assert_select_encoded|css_select|at_exit|" +\n
        "attr|attr_writer|attr_reader|attr_accessor|attr_accessible|autoload|binding|block_given?|callcc|" +\n
        "caller|catch|chomp|chomp!|chop|chop!|defined?|delete_via_redirect|eval|exec|exit|" +\n
        "exit!|fail|Float|flunk|follow_redirect!|fork|form_for|form_tag|format|gets|global_variables|gsub|" +\n
        "gsub!|get_via_redirect|host!|https?|https!|include|Integer|lambda|link_to|" +\n
        "link_to_unless_current|link_to_function|link_to_remote|load|local_variables|loop|open|open_session|" +\n
        "p|print|printf|proc|putc|puts|post_via_redirect|put_via_redirect|raise|rand|" +\n
        "raw|readline|readlines|redirect?|request_via_redirect|require|scan|select|" +\n
        "set_trace_func|sleep|split|sprintf|srand|String|stylesheet_link_tag|syscall|system|sub|sub!|test|" +\n
        "throw|trace_var|trap|untrace_var|atan2|cos|exp|frexp|ldexp|log|log10|sin|sqrt|tan|" +\n
        "render|javascript_include_tag|csrf_meta_tag|label_tag|text_field_tag|submit_tag|check_box_tag|" +\n
        "content_tag|radio_button_tag|text_area_tag|password_field_tag|hidden_field_tag|" +\n
        "fields_for|select_tag|options_for_select|options_from_collection_for_select|collection_select|" +\n
        "time_zone_select|select_date|select_time|select_datetime|date_select|time_select|datetime_select|" +\n
        "select_year|select_month|select_day|select_hour|select_minute|select_second|file_field_tag|" +\n
        "file_field|respond_to|skip_before_filter|around_filter|after_filter|verify|" +\n
        "protect_from_forgery|rescue_from|helper_method|redirect_to|before_filter|" +\n
        "send_data|send_file|validates_presence_of|validates_uniqueness_of|validates_length_of|" +\n
        "validates_format_of|validates_acceptance_of|validates_associated|validates_exclusion_of|" +\n
        "validates_inclusion_of|validates_numericality_of|validates_with|validates_each|" +\n
        "authenticate_or_request_with_http_basic|authenticate_or_request_with_http_digest|" +\n
        "filter_parameter_logging|match|get|post|resources|redirect|scope|assert_routing|" +\n
        "translate|localize|extract_locale_from_tld|caches_page|expire_page|caches_action|expire_action|" +\n
        "cache|expire_fragment|expire_cache_for|observe|cache_sweeper|" +\n
        "has_many|has_one|belongs_to|has_and_belongs_to_many"\n
    );\n
\n
    var keywords = (\n
        "alias|and|BEGIN|begin|break|case|class|def|defined|do|else|elsif|END|end|ensure|" +\n
        "__FILE__|finally|for|gem|if|in|__LINE__|module|next|not|or|private|protected|public|" +\n
        "redo|rescue|retry|return|super|then|undef|unless|until|when|while|yield"\n
    );\n
\n
    var buildinConstants = (\n
        "true|TRUE|false|FALSE|nil|NIL|ARGF|ARGV|DATA|ENV|RUBY_PLATFORM|RUBY_RELEASE_DATE|" +\n
        "RUBY_VERSION|STDERR|STDIN|STDOUT|TOPLEVEL_BINDING"\n
    );\n
\n
    var builtinVariables = (\n
        "\\$DEBUG|\\$defout|\\$FILENAME|\\$LOAD_PATH|\\$SAFE|\\$stdin|\\$stdout|\\$stderr|\\$VERBOSE|" +\n
        "$!|root_url|flash|session|cookies|params|request|response|logger|self"\n
    );\n
\n
    var keywordMapper = this.$keywords = this.createKeywordMapper({\n
        "keyword": keywords,\n
        "constant.language": buildinConstants,\n
        "variable.language": builtinVariables,\n
        "support.function": builtinFunctions,\n
        "invalid.deprecated": "debugger" // TODO is this a remnant from js mode?\n
    }, "identifier");\n
\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment",\n
                regex : "#.*$"\n
            }, {\n
                token : "comment", // multi line comment\n
                regex : "^=begin(?:$|\\\\s.*$)",\n
                next : "comment"\n
            }, {\n
                token : "string.regexp",\n
                regex : "[/](?:(?:\\\\[(?:\\\\\\\\]|[^\\\\]])+\\\\])|(?:\\\\\\\\/|[^\\\\]/]))*[/]\\\\w*\\\\s*(?=[).,;]|$)"\n
            },\n
\n
            qString,\n
            qqString,\n
            tString,\n
\n
            {\n
                token : "text", // namespaces aren\'t symbols\n
                regex : "::"\n
            }, {\n
                token : "variable.instance", // instance variable\n
                regex : "@{1,2}[a-zA-Z_\\\\d]+"\n
            }, {\n
                token : "support.class", // class name\n
                regex : "[A-Z][a-zA-Z_\\\\d]+"\n
            },\n
\n
            constantOtherSymbol,\n
            constantNumericHex,\n
            constantNumericFloat,\n
\n
            {\n
                token : "constant.language.boolean",\n
                regex : "(?:true|false)\\\\b"\n
            }, {\n
                token : keywordMapper,\n
                regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\\\b"\n
            }, {\n
                token : "punctuation.separator.key-value",\n
                regex : "=>"\n
            }, {\n
                stateName: "heredoc",\n
                onMatch : function(value, currentState, stack) {\n
                    var next = value[2] == \'-\' ? "indentedHeredoc" : "heredoc";\n
                    var tokens = value.split(this.splitRegex);\n
                    stack.push(next, tokens[3]);\n
                    return [\n
                        {type:"constant", value: tokens[1]},\n
                        {type:"string", value: tokens[2]},\n
                        {type:"support.class", value: tokens[3]},\n
                        {type:"string", value: tokens[4]}\n
                    ];\n
                },\n
                regex : "(<<-?)([\'\\"`]?)([\\\\w]+)([\'\\"`]?)",\n
                rules: {\n
                    heredoc: [{\n
                        onMatch:  function(value, currentState, stack) {\n
                            if (value == stack[1]) {\n
                                stack.shift();\n
                                stack.shift();\n
                                return "support.class";\n
                            }\n
                            return "string";\n
                        },\n
                        regex: ".*$",\n
                        next: "start"\n
                    }],\n
                    indentedHeredoc: [{\n
                        token: "string",\n
                        regex: "^ +"\n
                    }, {\n
                        onMatch:  function(value, currentState, stack) {\n
                            if (value == stack[1]) {\n
                                stack.shift();\n
                                stack.shift();\n
                                return "support.class";\n
                            }\n
                            return "string";\n
                        },\n
                        regex: ".*$",\n
                        next: "start"\n
                    }]\n
                }\n
            }, {\n
                token : "keyword.operator",\n
                regex : "!|\\\\$|%|&|\\\\*|\\\\-\\\\-|\\\\-|\\\\+\\\\+|\\\\+|~|===|==|=|!=|!==|<=|>=|<<=|>>=|>>>=|<>|<|>|!|&&|\\\\|\\\\||\\\\?\\\\:|\\\\*=|%=|\\\\+=|\\\\-=|&=|\\\\^=|\\\\b(?:in|instanceof|new|delete|typeof|void)"\n
            }, {\n
                token : "paren.lparen",\n
                regex : "[[({]"\n
            }, {\n
                token : "paren.rparen",\n
                regex : "[\\\\])}]"\n
            }, {\n
                token : "text",\n
                regex : "\\\\s+"\n
            }\n
        ],\n
        "comment" : [\n
            {\n
                token : "comment", // closing comment\n
                regex : "^=end(?:$|\\\\s.*$)",\n
                next : "start"\n
            }, {\n
                token : "comment", // comment spanning whole line\n
                regex : ".+"\n
            }\n
        ]\n
    };\n
\n
    this.normalizeRules();\n
};\n
\n
oop.inherits(RubyHighlightRules, TextHighlightRules);\n
\n
exports.RubyHighlightRules = RubyHighlightRules;\n
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
            <value> <int>17003</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
