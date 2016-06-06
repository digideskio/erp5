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
            <value> <string>ts83646622.4</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-clojure.js</string> </value>
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
define(\'ace/mode/clojure\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/clojure_highlight_rules\', \'ace/mode/matching_parens_outdent\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var ClojureHighlightRules = require("./clojure_highlight_rules").ClojureHighlightRules;\n
var MatchingParensOutdent = require("./matching_parens_outdent").MatchingParensOutdent;\n
var Range = require("../range").Range;\n
\n
var Mode = function() {\n
    this.HighlightRules = ClojureHighlightRules;\n
    this.$outdent = new MatchingParensOutdent();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
\n
    this.lineCommentStart = ";";\n
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
            var match = line.match(/[\\(\\[]/);\n
            if (match) {\n
                indent += "  ";\n
            }\n
            match = line.match(/[\\)]/);\n
            if (match) {\n
              indent = "";\n
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
define(\'ace/mode/clojure_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
\n
\n
var ClojureHighlightRules = function() {\n
\n
    var builtinFunctions = (\n
        \'* *1 *2 *3 *agent* *allow-unresolved-vars* *assert* *clojure-version* \' +\n
        \'*command-line-args* *compile-files* *compile-path* *e *err* *file* \' +\n
        \'*flush-on-newline* *in* *macro-meta* *math-context* *ns* *out* \' +\n
        \'*print-dup* *print-length* *print-level* *print-meta* *print-readably* \' +\n
        \'*read-eval* *source-path* *use-context-classloader* \' +\n
        \'*warn-on-reflection* + - -> ->> .. / < <= = \' +\n
        \'== > &gt; >= &gt;= accessor aclone \' +\n
        \'add-classpath add-watch agent agent-errors aget alength alias all-ns \' +\n
        \'alter alter-meta! alter-var-root amap ancestors and apply areduce \' +\n
        \'array-map aset aset-boolean aset-byte aset-char aset-double aset-float \' +\n
        \'aset-int aset-long aset-short assert assoc assoc! assoc-in associative? \' +\n
        \'atom await await-for await1 bases bean bigdec bigint binding bit-and \' +\n
        \'bit-and-not bit-clear bit-flip bit-not bit-or bit-set bit-shift-left \' +\n
        \'bit-shift-right bit-test bit-xor boolean boolean-array booleans \' +\n
        \'bound-fn bound-fn* butlast byte byte-array bytes cast char char-array \' +\n
        \'char-escape-string char-name-string char? chars chunk chunk-append \' +\n
        \'chunk-buffer chunk-cons chunk-first chunk-next chunk-rest chunked-seq? \' +\n
        \'class class? clear-agent-errors clojure-version coll? comment commute \' +\n
        \'comp comparator compare compare-and-set! compile complement concat cond \' +\n
        \'condp conj conj! cons constantly construct-proxy contains? count \' +\n
        \'counted? create-ns create-struct cycle dec decimal? declare definline \' +\n
        \'defmacro defmethod defmulti defn defn- defonce defstruct delay delay? \' +\n
        \'deliver deref derive descendants destructure disj disj! dissoc dissoc! \' +\n
        \'distinct distinct? doall doc dorun doseq dosync dotimes doto double \' +\n
        \'double-array doubles drop drop-last drop-while empty empty? ensure \' +\n
        \'enumeration-seq eval even? every? false? ffirst file-seq filter find \' +\n
        \'find-doc find-ns find-var first float float-array float? floats flush \' +\n
        \'fn fn? fnext for force format future future-call future-cancel \' +\n
        \'future-cancelled? future-done? future? gen-class gen-interface gensym \' +\n
        \'get get-in get-method get-proxy-class get-thread-bindings get-validator \' +\n
        \'hash hash-map hash-set identical? identity if-let if-not ifn? import \' +\n
        \'in-ns inc init-proxy instance? int int-array integer? interleave intern \' +\n
        \'interpose into into-array ints io! isa? iterate iterator-seq juxt key \' +\n
        \'keys keyword keyword? last lazy-cat lazy-seq let letfn line-seq list \' +\n
        \'list* list? load load-file load-reader load-string loaded-libs locking \' +\n
        \'long long-array longs loop macroexpand macroexpand-1 make-array \' +\n
        \'make-hierarchy map map? mapcat max max-key memfn memoize merge \' +\n
        \'merge-with meta method-sig methods min min-key mod name namespace neg? \' +\n
        \'newline next nfirst nil? nnext not not-any? not-empty not-every? not= \' +\n
        \'ns ns-aliases ns-imports ns-interns ns-map ns-name ns-publics \' +\n
        \'ns-refers ns-resolve ns-unalias ns-unmap nth nthnext num number? odd? \' +\n
        \'or parents partial partition pcalls peek persistent! pmap pop pop! \' +\n
        \'pop-thread-bindings pos? pr pr-str prefer-method prefers \' +\n
        \'primitives-classnames print print-ctor print-doc print-dup print-method \' +\n
        \'print-namespace-doc print-simple print-special-doc print-str printf \' +\n
        \'println println-str prn prn-str promise proxy proxy-call-with-super \' +\n
        \'proxy-mappings proxy-name proxy-super push-thread-bindings pvalues quot \' +\n
        \'rand rand-int range ratio? rational? rationalize re-find re-groups \' +\n
        \'re-matcher re-matches re-pattern re-seq read read-line read-string \' +\n
        \'reduce ref ref-history-count ref-max-history ref-min-history ref-set \' +\n
        \'refer refer-clojure release-pending-sends rem remove remove-method \' +\n
        \'remove-ns remove-watch repeat repeatedly replace replicate require \' +\n
        \'reset! reset-meta! resolve rest resultset-seq reverse reversible? rseq \' +\n
        \'rsubseq second select-keys send send-off seq seq? seque sequence \' +\n
        \'sequential? set set-validator! set? short short-array shorts \' +\n
        \'shutdown-agents slurp some sort sort-by sorted-map sorted-map-by \' +\n
        \'sorted-set sorted-set-by sorted? special-form-anchor special-symbol? \' +\n
        \'split-at split-with str stream? string? struct struct-map subs subseq \' +\n
        \'subvec supers swap! symbol symbol? sync syntax-symbol-anchor take \' +\n
        \'take-last take-nth take-while test the-ns time to-array to-array-2d \' +\n
        \'trampoline transient tree-seq true? type unchecked-add unchecked-dec \' +\n
        \'unchecked-divide unchecked-inc unchecked-multiply unchecked-negate \' +\n
        \'unchecked-remainder unchecked-subtract underive unquote \' +\n
        \'unquote-splicing update-in update-proxy use val vals var-get var-set \' +\n
        \'var? vary-meta vec vector vector? when when-first when-let when-not \' +\n
        \'while with-bindings with-bindings* with-in-str with-loading-context \' +\n
        \'with-local-vars with-meta with-open with-out-str with-precision xml-seq \' +\n
        \'zero? zipmap\'\n
    );\n
\n
    var keywords = (\'throw try var \' +\n
        \'def do fn if let loop monitor-enter monitor-exit new quote recur set!\'\n
    );\n
\n
    var buildinConstants = ("true false nil");\n
\n
    var keywordMapper = this.createKeywordMapper({\n
        "keyword": keywords,\n
        "constant.language": buildinConstants,\n
        "support.function": builtinFunctions\n
    }, "identifier", false, " ");\n
\n
    this.$rules = {\n
        "start" : [\n
            {\n
                token : "comment",\n
                regex : ";.*$"\n
            }, {\n
                token : "keyword", //parens\n
                regex : "[\\\\(|\\\\)]"\n
            }, {\n
                token : "keyword", //lists\n
                regex : "[\\\\\'\\\\(]"\n
            }, {\n
                token : "keyword", //vectors\n
                regex : "[\\\\[|\\\\]]"\n
            }, {\n
                token : "keyword", //sets and maps\n
                regex : "[\\\\{|\\\\}|\\\\#\\\\{|\\\\#\\\\}]"\n
            }, {\n
                    token : "keyword", // ampersands\n
                    regex : \'[\\\\&]\'\n
            }, {\n
                    token : "keyword", // metadata\n
                    regex : \'[\\\\#\\\\^\\\\{]\'\n
            }, {\n
                    token : "keyword", // anonymous fn syntactic sugar\n
                    regex : \'[\\\\%]\'\n
            }, {\n
                    token : "keyword", // deref reader macro\n
                    regex : \'[@]\'\n
            }, {\n
                token : "constant.numeric", // hex\n
                regex : "0[xX][0-9a-fA-F]+\\\\b"\n
            }, {\n
                token : "constant.numeric", // float\n
                regex : "[+-]?\\\\d+(?:(?:\\\\.\\\\d*)?(?:[eE][+-]?\\\\d+)?)?\\\\b"\n
            }, {\n
                token : "constant.language",\n
                regex : \'[!|\\\\$|%|&|\\\\*|\\\\-\\\\-|\\\\-|\\\\+\\\\+|\\\\+||=|!=|<=|>=|<>|<|>|!|&&]\'\n
            }, {\n
                token : keywordMapper,\n
                regex : "[a-zA-Z_$][a-zA-Z0-9_$\\\\-]*\\\\b"\n
            }, {\n
                token : "string", // single line\n
                regex : \'"\',\n
                next: "string"\n
            }, {\n
                token : "constant", // symbol\n
                regex : /:[^()\\[\\]{}\'"\\^%`,;\\s]+/\n
            }, {\n
                token : "string.regexp", //Regular Expressions\n
                regex : \'/#"(?:\\\\.|(?:\\\\\\")|[^\\""\\n])*"/g\'\n
            }\n
\n
        ],\n
        "string" : [\n
            {\n
                token : "constant.language.escape",                \n
                regex : "\\\\\\\\.|\\\\\\\\$"\n
            }, {\n
                token : "string",                \n
                regex : \'[^"\\\\\\\\]+\'\n
            }, {\n
                token : "string",\n
                regex : \'"\',\n
                next : "start"\n
            }\n
        ]\n
    };\n
};\n
\n
oop.inherits(ClojureHighlightRules, TextHighlightRules);\n
\n
exports.ClojureHighlightRules = ClojureHighlightRules;\n
});\n
\n
define(\'ace/mode/matching_parens_outdent\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
\n
var MatchingParensOutdent = function() {};\n
\n
(function() {\n
\n
    this.checkOutdent = function(line, input) {\n
        if (! /^\\s+$/.test(line))\n
            return false;\n
\n
        return /^\\s*\\)/.test(input);\n
    };\n
\n
    this.autoOutdent = function(doc, row) {\n
        var line = doc.getLine(row);\n
        var match = line.match(/^(\\s*\\))/);\n
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
        var match = line.match(/^(\\s+)/);\n
        if (match) {\n
            return match[1];\n
        }\n
\n
        return "";\n
    };\n
\n
}).call(MatchingParensOutdent.prototype);\n
\n
exports.MatchingParensOutdent = MatchingParensOutdent;\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>13039</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
