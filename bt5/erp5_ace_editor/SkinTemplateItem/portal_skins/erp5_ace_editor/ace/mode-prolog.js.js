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
            <value> <string>ts83646621.44</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-prolog.js</string> </value>
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
 * Copyright (c) 2012, Ajax.org B.V.\n
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
 *\n
 * Contributor(s):\n
 *\n
 *\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/prolog\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/prolog_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var PrologHighlightRules = require("./prolog_highlight_rules").PrologHighlightRules;\n
var FoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = PrologHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "/\\\\*";\n
    this.blockComment = {start: "/*", end: "*/"};\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/prolog_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var PrologHighlightRules = function() {\n
\n
    this.$rules = { start: \n
       [ { include: \'#comment\' },\n
         { include: \'#basic_fact\' },\n
         { include: \'#rule\' },\n
         { include: \'#directive\' },\n
         { include: \'#fact\' } ],\n
      \'#atom\': \n
       [ { token: \'constant.other.atom.prolog\',\n
           regex: \'\\\\b[a-z][a-zA-Z0-9_]*\\\\b\' },\n
         { token: \'constant.numeric.prolog\',\n
           regex: \'-?\\\\d+(?:\\\\.\\\\d+)?\' },\n
         { include: \'#string\' } ],\n
      \'#basic_elem\': \n
       [ { include: \'#comment\' },\n
         { include: \'#statement\' },\n
         { include: \'#constants\' },\n
         { include: \'#operators\' },\n
         { include: \'#builtins\' },\n
         { include: \'#list\' },\n
         { include: \'#atom\' },\n
         { include: \'#variable\' } ],\n
      \'#basic_fact\': \n
       [ { token: \n
            [ \'entity.name.function.fact.basic.prolog\',\n
              \'punctuation.end.fact.basic.prolog\' ],\n
           regex: \'([a-z]\\\\w*)(\\\\.)\' } ],\n
      \'#builtins\': \n
       [ { token: \'support.function.builtin.prolog\',\n
           regex: \'\\\\b(?:\\n\\t\\t\\t\\t\\t\\tabolish|abort|ancestors|arg|ascii|assert[az]|\\n\\t\\t\\t\\t\\t\\tatom(?:ic)?|body|char|close|conc|concat|consult|\\n\\t\\t\\t\\t\\t\\tdefine|definition|dynamic|dump|fail|file|free|\\n\\t\\t\\t\\t\\t\\tfree_proc|functor|getc|goal|halt|head|head|integer|\\n\\t\\t\\t\\t\\t\\tlength|listing|match_args|member|next_clause|nl|\\n\\t\\t\\t\\t\\t\\tnonvar|nth|number|cvars|nvars|offset|op|\\n\\t\\t\\t\\t\\t\\tprint?|prompt|putc|quoted|ratom|read|redefine|\\n\\t\\t\\t\\t\\t\\trename|retract(?:all)?|see|seeing|seen|skip|spy|\\n\\t\\t\\t\\t\\t\\tstatistics|system|tab|tell|telling|term|\\n\\t\\t\\t\\t\\t\\ttime|told|univ|unlink_clause|unspy_predicate|\\n\\t\\t\\t\\t\\t\\tvar|write\\n\\t\\t\\t\\t\\t)\\\\b\' } ],\n
      \'#comment\': \n
       [ { token: \n
            [ \'punctuation.definition.comment.prolog\',\n
              \'comment.line.percentage.prolog\' ],\n
           regex: \'(%)(.*$)\' },\n
         { token: \'punctuation.definition.comment.prolog\',\n
           regex: \'/\\\\*\',\n
           push: \n
            [ { token: \'punctuation.definition.comment.prolog\',\n
                regex: \'\\\\*/\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.block.prolog\' } ] } ],\n
      \'#constants\': \n
       [ { token: \'constant.language.prolog\',\n
           regex: \'\\\\b(?:true|false|yes|no)\\\\b\' } ],\n
      \'#directive\': \n
       [ { token: \'keyword.operator.directive.prolog\',\n
           regex: \':-\',\n
           push: \n
            [ { token: \'meta.directive.prolog\', regex: \'\\\\.\', next: \'pop\' },\n
              { include: \'#comment\' },\n
              { include: \'#statement\' },\n
              { defaultToken: \'meta.directive.prolog\' } ] } ],\n
      \'#expr\': \n
       [ { include: \'#comments\' },\n
         { token: \'meta.expression.prolog\',\n
           regex: \'\\\\(\',\n
           push: \n
            [ { token: \'meta.expression.prolog\', regex: \'\\\\)\', next: \'pop\' },\n
              { include: \'#expr\' },\n
              { defaultToken: \'meta.expression.prolog\' } ] },\n
         { token: \'keyword.control.cutoff.prolog\', regex: \'!\' },\n
         { token: \'punctuation.control.and.prolog\', regex: \',\' },\n
         { token: \'punctuation.control.or.prolog\', regex: \';\' },\n
         { include: \'#basic_elem\' } ],\n
      \'#fact\': \n
       [ { token: \n
            [ \'entity.name.function.fact.prolog\',\n
              \'punctuation.begin.fact.parameters.prolog\' ],\n
           regex: \'([a-z]\\\\w*)(\\\\()(?!.*:-)\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.end.fact.parameters.prolog\',\n
                   \'punctuation.end.fact.prolog\' ],\n
                regex: \'(\\\\))(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#parameter\' },\n
              { defaultToken: \'meta.fact.prolog\' } ] } ],\n
      \'#list\': \n
       [ { token: \'punctuation.begin.list.prolog\',\n
           regex: \'\\\\[(?=.*\\\\])\',\n
           push: \n
            [ { token: \'punctuation.end.list.prolog\',\n
                regex: \'\\\\]\',\n
                next: \'pop\' },\n
              { include: \'#comment\' },\n
              { token: \'punctuation.separator.list.prolog\', regex: \',\' },\n
              { token: \'punctuation.concat.list.prolog\',\n
                regex: \'\\\\|\',\n
                push: \n
                 [ { token: \'meta.list.concat.prolog\',\n
                     regex: \'(?=\\\\s*\\\\])\',\n
                     next: \'pop\' },\n
                   { include: \'#basic_elem\' },\n
                   { defaultToken: \'meta.list.concat.prolog\' } ] },\n
              { include: \'#basic_elem\' },\n
              { defaultToken: \'meta.list.prolog\' } ] } ],\n
      \'#operators\': \n
       [ { token: \'keyword.operator.prolog\',\n
           regex: \'\\\\\\\\\\\\+|\\\\bnot\\\\b|\\\\bis\\\\b|->|[><]|[><\\\\\\\\:=]?=|(?:=\\\\\\\\|\\\\\\\\=)=\' } ],\n
      \'#parameter\': \n
       [ { token: \'variable.language.anonymous.prolog\',\n
           regex: \'\\\\b_\\\\b\' },\n
         { token: \'variable.parameter.prolog\',\n
           regex: \'\\\\b[A-Z_]\\\\w*\\\\b\' },\n
         { token: \'punctuation.separator.parameters.prolog\', regex: \',\' },\n
         { include: \'#basic_elem\' },\n
         { token: \'invalid.illegal.invalidchar.prolog\', regex: \'[^\\\\s]\' } ],\n
      \'#rule\': \n
       [ { token: \'meta.rule.prolog\',\n
           regex: \'(?=[a-z]\\\\w*.*:-)\',\n
           push: \n
            [ { token: \'punctuation.rule.end.prolog\',\n
                regex: \'\\\\.\',\n
                next: \'pop\' },\n
              { token: \'meta.rule.signature.prolog\',\n
                regex: \'(?=[a-z]\\\\w*.*:-)\',\n
                push: \n
                 [ { token: \'meta.rule.signature.prolog\',\n
                     regex: \'(?=:-)\',\n
                     next: \'pop\' },\n
                   { token: \'entity.name.function.rule.prolog\',\n
                     regex: \'[a-z]\\\\w*(?=\\\\(|\\\\s*:-)\' },\n
                   { token: \'punctuation.rule.parameters.begin.prolog\',\n
                     regex: \'\\\\(\',\n
                     push: \n
                      [ { token: \'punctuation.rule.parameters.end.prolog\',\n
                          regex: \'\\\\)\',\n
                          next: \'pop\' },\n
                        { include: \'#parameter\' },\n
                        { defaultToken: \'meta.rule.parameters.prolog\' } ] },\n
                   { defaultToken: \'meta.rule.signature.prolog\' } ] },\n
              { token: \'keyword.operator.definition.prolog\',\n
                regex: \':-\',\n
                push: \n
                 [ { token: \'meta.rule.definition.prolog\',\n
                     regex: \'(?=\\\\.)\',\n
                     next: \'pop\' },\n
                   { include: \'#comment\' },\n
                   { include: \'#expr\' },\n
                   { defaultToken: \'meta.rule.definition.prolog\' } ] },\n
              { defaultToken: \'meta.rule.prolog\' } ] } ],\n
      \'#statement\': \n
       [ { token: \'meta.statement.prolog\',\n
           regex: \'(?=[a-z]\\\\w*\\\\()\',\n
           push: \n
            [ { token: \'punctuation.end.statement.parameters.prolog\',\n
                regex: \'\\\\)\',\n
                next: \'pop\' },\n
              { include: \'#builtins\' },\n
              { include: \'#atom\' },\n
              { token: \'punctuation.begin.statement.parameters.prolog\',\n
                regex: \'\\\\(\',\n
                push: \n
                 [ { token: \'meta.statement.parameters.prolog\',\n
                     regex: \'(?=\\\\))\',\n
                     next: \'pop\' },\n
                   { token: \'punctuation.separator.statement.prolog\', regex: \',\' },\n
                   { include: \'#basic_elem\' },\n
                   { defaultToken: \'meta.statement.parameters.prolog\' } ] },\n
              { defaultToken: \'meta.statement.prolog\' } ] } ],\n
      \'#string\': \n
       [ { token: \'punctuation.definition.string.begin.prolog\',\n
           regex: \'\\\'\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.prolog\',\n
                regex: \'\\\'\',\n
                next: \'pop\' },\n
              { token: \'constant.character.escape.prolog\', regex: \'\\\\\\\\.\' },\n
              { token: \'constant.character.escape.quote.prolog\',\n
                regex: \'\\\'\\\'\' },\n
              { defaultToken: \'string.quoted.single.prolog\' } ] } ],\n
      \'#variable\': \n
       [ { token: \'variable.language.anonymous.prolog\',\n
           regex: \'\\\\b_\\\\b\' },\n
         { token: \'variable.other.prolog\',\n
           regex: \'\\\\b[A-Z_][a-zA-Z0-9_]*\\\\b\' } ] }\n
    \n
    this.normalizeRules();\n
};\n
\n
PrologHighlightRules.metaData = { fileTypes: [ \'plg\', \'prolog\' ],\n
      foldingStartMarker: \'(%\\\\s*region \\\\w*)|([a-z]\\\\w*.*:- ?)\',\n
      foldingStopMarker: \'(%\\\\s*end(\\\\s*region)?)|(?=\\\\.)\',\n
      keyEquivalent: \'^~P\',\n
      name: \'Prolog\',\n
      scopeName: \'source.prolog\' }\n
\n
\n
oop.inherits(PrologHighlightRules, TextHighlightRules);\n
\n
exports.PrologHighlightRules = PrologHighlightRules;\n
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
            <value> <int>13008</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
