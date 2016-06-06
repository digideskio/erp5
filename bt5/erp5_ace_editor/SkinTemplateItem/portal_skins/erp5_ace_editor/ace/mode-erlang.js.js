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
            <value> <string>ts83646622.19</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-erlang.js</string> </value>
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
 * ***** END LICENSE BLOCK ***** */\n
\n
define(\'ace/mode/erlang\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/erlang_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var ErlangHighlightRules = require("./erlang_highlight_rules").ErlangHighlightRules;\n
var FoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = ErlangHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "%";\n
    this.blockComment = {start: "/*", end: "*/"};\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/erlang_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var ErlangHighlightRules = function() {\n
\n
    this.$rules = { start: \n
       [ { include: \'#module-directive\' },\n
         { include: \'#import-export-directive\' },\n
         { include: \'#behaviour-directive\' },\n
         { include: \'#record-directive\' },\n
         { include: \'#define-directive\' },\n
         { include: \'#macro-directive\' },\n
         { include: \'#directive\' },\n
         { include: \'#function\' },\n
         { include: \'#everything-else\' } ],\n
      \'#atom\': \n
       [ { token: \'punctuation.definition.symbol.begin.erlang\',\n
           regex: \'\\\'\',\n
           push: \n
            [ { token: \'punctuation.definition.symbol.end.erlang\',\n
                regex: \'\\\'\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'punctuation.definition.escape.erlang\',\n
                   \'constant.other.symbol.escape.erlang\',\n
                   \'punctuation.definition.escape.erlang\',\n
                   \'constant.other.symbol.escape.erlang\',\n
                   \'constant.other.symbol.escape.erlang\' ],\n
                regex: \'(\\\\\\\\)(?:([bdefnrstv\\\\\\\\\\\'"])|(\\\\^)([@-_])|([0-7]{1,3}))\' },\n
              { token: \'invalid.illegal.atom.erlang\', regex: \'\\\\\\\\\\\\^?.?\' },\n
              { defaultToken: \'constant.other.symbol.quoted.single.erlang\' } ] },\n
         { token: \'constant.other.symbol.unquoted.erlang\',\n
           regex: \'[a-z][a-zA-Z\\\\d@_]*\' } ],\n
      \'#behaviour-directive\': \n
       [ { token: \n
            [ \'meta.directive.behaviour.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.behaviour.erlang\',\n
              \'keyword.control.directive.behaviour.erlang\',\n
              \'meta.directive.behaviour.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.behaviour.erlang\',\n
              \'entity.name.type.class.behaviour.definition.erlang\',\n
              \'meta.directive.behaviour.erlang\',\n
              \'punctuation.definition.parameters.end.erlang\',\n
              \'meta.directive.behaviour.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(behaviour)(\\\\s*)(\\\\()(\\\\s*)([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\' } ],\n
      \'#binary\': \n
       [ { token: \'punctuation.definition.binary.begin.erlang\',\n
           regex: \'<<\',\n
           push: \n
            [ { token: \'punctuation.definition.binary.end.erlang\',\n
                regex: \'>>\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'punctuation.separator.binary.erlang\',\n
                   \'punctuation.separator.value-size.erlang\' ],\n
                regex: \'(,)|(:)\' },\n
              { include: \'#internal-type-specifiers\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.structure.binary.erlang\' } ] } ],\n
      \'#character\': \n
       [ { token: \n
            [ \'punctuation.definition.character.erlang\',\n
              \'punctuation.definition.escape.erlang\',\n
              \'constant.character.escape.erlang\',\n
              \'punctuation.definition.escape.erlang\',\n
              \'constant.character.escape.erlang\',\n
              \'constant.character.escape.erlang\' ],\n
           regex: \'(\\\\$)(\\\\\\\\)(?:([bdefnrstv\\\\\\\\\\\'"])|(\\\\^)([@-_])|([0-7]{1,3}))\' },\n
         { token: \'invalid.illegal.character.erlang\',\n
           regex: \'\\\\$\\\\\\\\\\\\^?.?\' },\n
         { token: \n
            [ \'punctuation.definition.character.erlang\',\n
              \'constant.character.erlang\' ],\n
           regex: \'(\\\\$)(\\\\S)\' },\n
         { token: \'invalid.illegal.character.erlang\', regex: \'\\\\$.?\' } ],\n
      \'#comment\': \n
       [ { token: \'punctuation.definition.comment.erlang\',\n
           regex: \'%.*$\',\n
           push_: \n
            [ { token: \'comment.line.percentage.erlang\',\n
                regex: \'$\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.line.percentage.erlang\' } ] } ],\n
      \'#define-directive\': \n
       [ { token: \n
            [ \'meta.directive.define.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.define.erlang\',\n
              \'keyword.control.directive.define.erlang\',\n
              \'meta.directive.define.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.define.erlang\',\n
              \'entity.name.function.macro.definition.erlang\',\n
              \'meta.directive.define.erlang\',\n
              \'punctuation.separator.parameters.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(define)(\\\\s*)(\\\\()(\\\\s*)([a-zA-Z\\\\d@_]+)(\\\\s*)(,)\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.define.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\))(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.directive.define.erlang\' } ] },\n
         { token: \'meta.directive.define.erlang\',\n
           regex: \'(?=^\\\\s*-\\\\s*define\\\\s*\\\\(\\\\s*[a-zA-Z\\\\d@_]+\\\\s*\\\\()\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.define.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\))(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'text\',\n
                   \'punctuation.section.directive.begin.erlang\',\n
                   \'text\',\n
                   \'keyword.control.directive.define.erlang\',\n
                   \'text\',\n
                   \'punctuation.definition.parameters.begin.erlang\',\n
                   \'text\',\n
                   \'entity.name.function.macro.definition.erlang\',\n
                   \'text\',\n
                   \'punctuation.definition.parameters.begin.erlang\' ],\n
                regex: \'^(\\\\s*)(-)(\\\\s*)(define)(\\\\s*)(\\\\()(\\\\s*)([a-zA-Z\\\\d@_]+)(\\\\s*)(\\\\()\',\n
                push: \n
                 [ { token: \n
                      [ \'punctuation.definition.parameters.end.erlang\',\n
                        \'text\',\n
                        \'punctuation.separator.parameters.erlang\' ],\n
                     regex: \'(\\\\))(\\\\s*)(,)\',\n
                     next: \'pop\' },\n
                   { token: \'punctuation.separator.parameters.erlang\', regex: \',\' },\n
                   { include: \'#everything-else\' } ] },\n
              { token: \'punctuation.separator.define.erlang\',\n
                regex: \'\\\\|\\\\||\\\\||:|;|,|\\\\.|->\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.directive.define.erlang\' } ] } ],\n
      \'#directive\': \n
       [ { token: \n
            [ \'meta.directive.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.erlang\',\n
              \'keyword.control.directive.erlang\',\n
              \'meta.directive.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(\\\\(?)\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\)?)(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.directive.erlang\' } ] },\n
         { token: \n
            [ \'meta.directive.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.erlang\',\n
              \'keyword.control.directive.erlang\',\n
              \'meta.directive.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(\\\\.)\' } ],\n
      \'#everything-else\': \n
       [ { include: \'#comment\' },\n
         { include: \'#record-usage\' },\n
         { include: \'#macro-usage\' },\n
         { include: \'#expression\' },\n
         { include: \'#keyword\' },\n
         { include: \'#textual-operator\' },\n
         { include: \'#function-call\' },\n
         { include: \'#tuple\' },\n
         { include: \'#list\' },\n
         { include: \'#binary\' },\n
         { include: \'#parenthesized-expression\' },\n
         { include: \'#character\' },\n
         { include: \'#number\' },\n
         { include: \'#atom\' },\n
         { include: \'#string\' },\n
         { include: \'#symbolic-operator\' },\n
         { include: \'#variable\' } ],\n
      \'#expression\': \n
       [ { token: \'keyword.control.if.erlang\',\n
           regex: \'\\\\bif\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#internal-expression-punctuation\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.if.erlang\' } ] },\n
         { token: \'keyword.control.case.erlang\',\n
           regex: \'\\\\bcase\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#internal-expression-punctuation\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.case.erlang\' } ] },\n
         { token: \'keyword.control.receive.erlang\',\n
           regex: \'\\\\breceive\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#internal-expression-punctuation\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.receive.erlang\' } ] },\n
         { token: \n
            [ \'keyword.control.fun.erlang\',\n
              \'text\',\n
              \'entity.name.type.class.module.erlang\',\n
              \'text\',\n
              \'punctuation.separator.module-function.erlang\',\n
              \'text\',\n
              \'entity.name.function.erlang\',\n
              \'text\',\n
              \'punctuation.separator.function-arity.erlang\' ],\n
           regex: \'\\\\b(fun)(\\\\s*)(?:([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(:)(\\\\s*))?([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(/)\' },\n
         { token: \'keyword.control.fun.erlang\',\n
           regex: \'\\\\bfun\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { token: \'text\',\n
                regex: \'(?=\\\\()\',\n
                push: \n
                 [ { token: \'punctuation.separator.clauses.erlang\',\n
                     regex: \';|(?=\\\\bend\\\\b)\',\n
                     next: \'pop\' },\n
                   { include: \'#internal-function-parts\' } ] },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.fun.erlang\' } ] },\n
         { token: \'keyword.control.try.erlang\',\n
           regex: \'\\\\btry\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#internal-expression-punctuation\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.try.erlang\' } ] },\n
         { token: \'keyword.control.begin.erlang\',\n
           regex: \'\\\\bbegin\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#internal-expression-punctuation\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.begin.erlang\' } ] },\n
         { token: \'keyword.control.query.erlang\',\n
           regex: \'\\\\bquery\\\\b\',\n
           push: \n
            [ { token: \'keyword.control.end.erlang\',\n
                regex: \'\\\\bend\\\\b\',\n
                next: \'pop\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.query.erlang\' } ] } ],\n
      \'#function\': \n
       [ { token: \n
            [ \'meta.function.erlang\',\n
              \'entity.name.function.definition.erlang\',\n
              \'meta.function.erlang\' ],\n
           regex: \'^(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(?=\\\\()\',\n
           push: \n
            [ { token: \'punctuation.terminator.function.erlang\',\n
                regex: \'\\\\.\',\n
                next: \'pop\' },\n
              { token: [ \'text\', \'entity.name.function.erlang\', \'text\' ],\n
                regex: \'^(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(?=\\\\()\' },\n
              { token: \'text\',\n
                regex: \'(?=\\\\()\',\n
                push: \n
                 [ { token: \'punctuation.separator.clauses.erlang\',\n
                     regex: \';|(?=\\\\.)\',\n
                     next: \'pop\' },\n
                   { include: \'#parenthesized-expression\' },\n
                   { include: \'#internal-function-parts\' } ] },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.function.erlang\' } ] } ],\n
      \'#function-call\': \n
       [ { token: \'meta.function-call.erlang\',\n
           regex: \'(?=(?:[a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')\\\\s*(?:\\\\(|:\\\\s*(?:[a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')\\\\s*\\\\())\',\n
           push: \n
            [ { token: \'punctuation.definition.parameters.end.erlang\',\n
                regex: \'\\\\)\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'entity.name.type.class.module.erlang\',\n
                   \'text\',\n
                   \'punctuation.separator.module-function.erlang\',\n
                   \'text\',\n
                   \'entity.name.function.guard.erlang\',\n
                   \'text\',\n
                   \'punctuation.definition.parameters.begin.erlang\' ],\n
                regex: \'(?:(erlang)(\\\\s*)(:)(\\\\s*))?(is_atom|is_binary|is_constant|is_float|is_function|is_integer|is_list|is_number|is_pid|is_port|is_reference|is_tuple|is_record|abs|element|hd|length|node|round|self|size|tl|trunc)(\\\\s*)(\\\\()\',\n
                push: \n
                 [ { token: \'text\', regex: \'(?=\\\\))\', next: \'pop\' },\n
                   { token: \'punctuation.separator.parameters.erlang\', regex: \',\' },\n
                   { include: \'#everything-else\' } ] },\n
              { token: \n
                 [ \'entity.name.type.class.module.erlang\',\n
                   \'text\',\n
                   \'punctuation.separator.module-function.erlang\',\n
                   \'text\',\n
                   \'entity.name.function.erlang\',\n
                   \'text\',\n
                   \'punctuation.definition.parameters.begin.erlang\' ],\n
                regex: \'(?:([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(:)(\\\\s*))?([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(\\\\()\',\n
                push: \n
                 [ { token: \'text\', regex: \'(?=\\\\))\', next: \'pop\' },\n
                   { token: \'punctuation.separator.parameters.erlang\', regex: \',\' },\n
                   { include: \'#everything-else\' } ] },\n
              { defaultToken: \'meta.function-call.erlang\' } ] } ],\n
      \'#import-export-directive\': \n
       [ { token: \n
            [ \'meta.directive.import.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.import.erlang\',\n
              \'keyword.control.directive.import.erlang\',\n
              \'meta.directive.import.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.import.erlang\',\n
              \'entity.name.type.class.module.erlang\',\n
              \'meta.directive.import.erlang\',\n
              \'punctuation.separator.parameters.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(import)(\\\\s*)(\\\\()(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(,)\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.import.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\))(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#internal-function-list\' },\n
              { defaultToken: \'meta.directive.import.erlang\' } ] },\n
         { token: \n
            [ \'meta.directive.export.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.export.erlang\',\n
              \'keyword.control.directive.export.erlang\',\n
              \'meta.directive.export.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(export)(\\\\s*)(\\\\()\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.export.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\))(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#internal-function-list\' },\n
              { defaultToken: \'meta.directive.export.erlang\' } ] } ],\n
      \'#internal-expression-punctuation\': \n
       [ { token: \n
            [ \'punctuation.separator.clause-head-body.erlang\',\n
              \'punctuation.separator.clauses.erlang\',\n
              \'punctuation.separator.expressions.erlang\' ],\n
           regex: \'(->)|(;)|(,)\' } ],\n
      \'#internal-function-list\': \n
       [ { token: \'punctuation.definition.list.begin.erlang\',\n
           regex: \'\\\\[\',\n
           push: \n
            [ { token: \'punctuation.definition.list.end.erlang\',\n
                regex: \'\\\\]\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'entity.name.function.erlang\',\n
                   \'text\',\n
                   \'punctuation.separator.function-arity.erlang\' ],\n
                regex: \'([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(/)\',\n
                push: \n
                 [ { token: \'punctuation.separator.list.erlang\',\n
                     regex: \',|(?=\\\\])\',\n
                     next: \'pop\' },\n
                   { include: \'#everything-else\' } ] },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.structure.list.function.erlang\' } ] } ],\n
      \'#internal-function-parts\': \n
       [ { token: \'text\',\n
           regex: \'(?=\\\\()\',\n
           push: \n
            [ { token: \'punctuation.separator.clause-head-body.erlang\',\n
                regex: \'->\',\n
                next: \'pop\' },\n
              { token: \'punctuation.definition.parameters.begin.erlang\',\n
                regex: \'\\\\(\',\n
                push: \n
                 [ { token: \'punctuation.definition.parameters.end.erlang\',\n
                     regex: \'\\\\)\',\n
                     next: \'pop\' },\n
                   { token: \'punctuation.separator.parameters.erlang\', regex: \',\' },\n
                   { include: \'#everything-else\' } ] },\n
              { token: \'punctuation.separator.guards.erlang\', regex: \',|;\' },\n
              { include: \'#everything-else\' } ] },\n
         { token: \'punctuation.separator.expressions.erlang\',\n
           regex: \',\' },\n
         { include: \'#everything-else\' } ],\n
      \'#internal-record-body\': \n
       [ { token: \'punctuation.definition.class.record.begin.erlang\',\n
           regex: \'\\\\{\',\n
           push: \n
            [ { token: \'meta.structure.record.erlang\',\n
                regex: \'(?=\\\\})\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'variable.other.field.erlang\',\n
                   \'variable.language.omitted.field.erlang\',\n
                   \'text\',\n
                   \'keyword.operator.assignment.erlang\' ],\n
                regex: \'(?:([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')|(_))(\\\\s*)(=|::)\',\n
                push: \n
                 [ { token: \'punctuation.separator.class.record.erlang\',\n
                     regex: \',|(?=\\\\})\',\n
                     next: \'pop\' },\n
                   { include: \'#everything-else\' } ] },\n
              { token: \n
                 [ \'variable.other.field.erlang\',\n
                   \'text\',\n
                   \'punctuation.separator.class.record.erlang\' ],\n
                regex: \'([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)((?:,)?)\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.structure.record.erlang\' } ] } ],\n
      \'#internal-type-specifiers\': \n
       [ { token: \'punctuation.separator.value-type.erlang\',\n
           regex: \'/\',\n
           push: \n
            [ { token: \'text\', regex: \'(?=,|:|>>)\', next: \'pop\' },\n
              { token: \n
                 [ \'storage.type.erlang\',\n
                   \'storage.modifier.signedness.erlang\',\n
                   \'storage.modifier.endianness.erlang\',\n
                   \'storage.modifier.unit.erlang\',\n
                   \'punctuation.separator.type-specifiers.erlang\' ],\n
                regex: \'(integer|float|binary|bytes|bitstring|bits)|(signed|unsigned)|(big|little|native)|(unit)|(-)\' } ] } ],\n
      \'#keyword\': \n
       [ { token: \'keyword.control.erlang\',\n
           regex: \'\\\\b(?:after|begin|case|catch|cond|end|fun|if|let|of|query|try|receive|when)\\\\b\' } ],\n
      \'#list\': \n
       [ { token: \'punctuation.definition.list.begin.erlang\',\n
           regex: \'\\\\[\',\n
           push: \n
            [ { token: \'punctuation.definition.list.end.erlang\',\n
                regex: \'\\\\]\',\n
                next: \'pop\' },\n
              { token: \'punctuation.separator.list.erlang\',\n
                regex: \'\\\\||\\\\|\\\\||,\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.structure.list.erlang\' } ] } ],\n
      \'#macro-directive\': \n
       [ { token: \n
            [ \'meta.directive.ifdef.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.ifdef.erlang\',\n
              \'keyword.control.directive.ifdef.erlang\',\n
              \'meta.directive.ifdef.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.ifdef.erlang\',\n
              \'entity.name.function.macro.erlang\',\n
              \'meta.directive.ifdef.erlang\',\n
              \'punctuation.definition.parameters.end.erlang\',\n
              \'meta.directive.ifdef.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(ifdef)(\\\\s*)(\\\\()(\\\\s*)([a-zA-z\\\\d@_]+)(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\' },\n
         { token: \n
            [ \'meta.directive.ifndef.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.ifndef.erlang\',\n
              \'keyword.control.directive.ifndef.erlang\',\n
              \'meta.directive.ifndef.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.ifndef.erlang\',\n
              \'entity.name.function.macro.erlang\',\n
              \'meta.directive.ifndef.erlang\',\n
              \'punctuation.definition.parameters.end.erlang\',\n
              \'meta.directive.ifndef.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(ifndef)(\\\\s*)(\\\\()(\\\\s*)([a-zA-z\\\\d@_]+)(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\' },\n
         { token: \n
            [ \'meta.directive.undef.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.undef.erlang\',\n
              \'keyword.control.directive.undef.erlang\',\n
              \'meta.directive.undef.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.undef.erlang\',\n
              \'entity.name.function.macro.erlang\',\n
              \'meta.directive.undef.erlang\',\n
              \'punctuation.definition.parameters.end.erlang\',\n
              \'meta.directive.undef.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(undef)(\\\\s*)(\\\\()(\\\\s*)([a-zA-z\\\\d@_]+)(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\' } ],\n
      \'#macro-usage\': \n
       [ { token: \n
            [ \'keyword.operator.macro.erlang\',\n
              \'meta.macro-usage.erlang\',\n
              \'entity.name.function.macro.erlang\' ],\n
           regex: \'(\\\\?\\\\??)(\\\\s*)([a-zA-Z\\\\d@_]+)\' } ],\n
      \'#module-directive\': \n
       [ { token: \n
            [ \'meta.directive.module.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.module.erlang\',\n
              \'keyword.control.directive.module.erlang\',\n
              \'meta.directive.module.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.module.erlang\',\n
              \'entity.name.type.class.module.definition.erlang\',\n
              \'meta.directive.module.erlang\',\n
              \'punctuation.definition.parameters.end.erlang\',\n
              \'meta.directive.module.erlang\',\n
              \'punctuation.section.directive.end.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(module)(\\\\s*)(\\\\()(\\\\s*)([a-z][a-zA-Z\\\\d@_]*)(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\' } ],\n
      \'#number\': \n
       [ { token: \'text\',\n
           regex: \'(?=\\\\d)\',\n
           push: \n
            [ { token: \'text\', regex: \'(?!\\\\d)\', next: \'pop\' },\n
              { token: \n
                 [ \'constant.numeric.float.erlang\',\n
                   \'punctuation.separator.integer-float.erlang\',\n
                   \'constant.numeric.float.erlang\',\n
                   \'punctuation.separator.float-exponent.erlang\' ],\n
                regex: \'(\\\\d+)(\\\\.)(\\\\d+)((?:[eE][\\\\+\\\\-]?\\\\d+)?)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.binary.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.binary.erlang\' ],\n
                regex: \'(2)(#)([0-1]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-3.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-3.erlang\' ],\n
                regex: \'(3)(#)([0-2]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-4.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-4.erlang\' ],\n
                regex: \'(4)(#)([0-3]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-5.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-5.erlang\' ],\n
                regex: \'(5)(#)([0-4]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-6.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-6.erlang\' ],\n
                regex: \'(6)(#)([0-5]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-7.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-7.erlang\' ],\n
                regex: \'(7)(#)([0-6]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.octal.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.octal.erlang\' ],\n
                regex: \'(8)(#)([0-7]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-9.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-9.erlang\' ],\n
                regex: \'(9)(#)([0-8]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.decimal.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.decimal.erlang\' ],\n
                regex: \'(10)(#)(\\\\d+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-11.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-11.erlang\' ],\n
                regex: \'(11)(#)([\\\\daA]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-12.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-12.erlang\' ],\n
                regex: \'(12)(#)([\\\\da-bA-B]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-13.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-13.erlang\' ],\n
                regex: \'(13)(#)([\\\\da-cA-C]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-14.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-14.erlang\' ],\n
                regex: \'(14)(#)([\\\\da-dA-D]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-15.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-15.erlang\' ],\n
                regex: \'(15)(#)([\\\\da-eA-E]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.hexadecimal.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.hexadecimal.erlang\' ],\n
                regex: \'(16)(#)([\\\\da-fA-F]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-17.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-17.erlang\' ],\n
                regex: \'(17)(#)([\\\\da-gA-G]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-18.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-18.erlang\' ],\n
                regex: \'(18)(#)([\\\\da-hA-H]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-19.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-19.erlang\' ],\n
                regex: \'(19)(#)([\\\\da-iA-I]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-20.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-20.erlang\' ],\n
                regex: \'(20)(#)([\\\\da-jA-J]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-21.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-21.erlang\' ],\n
                regex: \'(21)(#)([\\\\da-kA-K]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-22.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-22.erlang\' ],\n
                regex: \'(22)(#)([\\\\da-lA-L]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-23.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-23.erlang\' ],\n
                regex: \'(23)(#)([\\\\da-mA-M]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-24.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-24.erlang\' ],\n
                regex: \'(24)(#)([\\\\da-nA-N]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-25.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-25.erlang\' ],\n
                regex: \'(25)(#)([\\\\da-oA-O]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-26.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-26.erlang\' ],\n
                regex: \'(26)(#)([\\\\da-pA-P]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-27.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-27.erlang\' ],\n
                regex: \'(27)(#)([\\\\da-qA-Q]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-28.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-28.erlang\' ],\n
                regex: \'(28)(#)([\\\\da-rA-R]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-29.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-29.erlang\' ],\n
                regex: \'(29)(#)([\\\\da-sA-S]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-30.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-30.erlang\' ],\n
                regex: \'(30)(#)([\\\\da-tA-T]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-31.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-31.erlang\' ],\n
                regex: \'(31)(#)([\\\\da-uA-U]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-32.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-32.erlang\' ],\n
                regex: \'(32)(#)([\\\\da-vA-V]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-33.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-33.erlang\' ],\n
                regex: \'(33)(#)([\\\\da-wA-W]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-34.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-34.erlang\' ],\n
                regex: \'(34)(#)([\\\\da-xA-X]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-35.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-35.erlang\' ],\n
                regex: \'(35)(#)([\\\\da-yA-Y]+)\' },\n
              { token: \n
                 [ \'constant.numeric.integer.base-36.erlang\',\n
                   \'punctuation.separator.base-integer.erlang\',\n
                   \'constant.numeric.integer.base-36.erlang\' ],\n
                regex: \'(36)(#)([\\\\da-zA-Z]+)\' },\n
              { token: \'invalid.illegal.integer.erlang\',\n
                regex: \'\\\\d+#[\\\\da-zA-Z]+\' },\n
              { token: \'constant.numeric.integer.decimal.erlang\',\n
                regex: \'\\\\d+\' } ] } ],\n
      \'#parenthesized-expression\': \n
       [ { token: \'punctuation.section.expression.begin.erlang\',\n
           regex: \'\\\\(\',\n
           push: \n
            [ { token: \'punctuation.section.expression.end.erlang\',\n
                regex: \'\\\\)\',\n
                next: \'pop\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.expression.parenthesized\' } ] } ],\n
      \'#record-directive\': \n
       [ { token: \n
            [ \'meta.directive.record.erlang\',\n
              \'punctuation.section.directive.begin.erlang\',\n
              \'meta.directive.record.erlang\',\n
              \'keyword.control.directive.import.erlang\',\n
              \'meta.directive.record.erlang\',\n
              \'punctuation.definition.parameters.begin.erlang\',\n
              \'meta.directive.record.erlang\',\n
              \'entity.name.type.class.record.definition.erlang\',\n
              \'meta.directive.record.erlang\',\n
              \'punctuation.separator.parameters.erlang\' ],\n
           regex: \'^(\\\\s*)(-)(\\\\s*)(record)(\\\\s*)(\\\\()(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(,)\',\n
           push: \n
            [ { token: \n
                 [ \'punctuation.definition.class.record.end.erlang\',\n
                   \'meta.directive.record.erlang\',\n
                   \'punctuation.definition.parameters.end.erlang\',\n
                   \'meta.directive.record.erlang\',\n
                   \'punctuation.section.directive.end.erlang\' ],\n
                regex: \'(\\\\})(\\\\s*)(\\\\))(\\\\s*)(\\\\.)\',\n
                next: \'pop\' },\n
              { include: \'#internal-record-body\' },\n
              { defaultToken: \'meta.directive.record.erlang\' } ] } ],\n
      \'#record-usage\': \n
       [ { token: \n
            [ \'keyword.operator.record.erlang\',\n
              \'meta.record-usage.erlang\',\n
              \'entity.name.type.class.record.erlang\',\n
              \'meta.record-usage.erlang\',\n
              \'punctuation.separator.record-field.erlang\',\n
              \'meta.record-usage.erlang\',\n
              \'variable.other.field.erlang\' ],\n
           regex: \'(#)(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')(\\\\s*)(\\\\.)(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')\' },\n
         { token: \n
            [ \'keyword.operator.record.erlang\',\n
              \'meta.record-usage.erlang\',\n
              \'entity.name.type.class.record.erlang\' ],\n
           regex: \'(#)(\\\\s*)([a-z][a-zA-Z\\\\d@_]*|\\\'[^\\\']*\\\')\',\n
           push: \n
            [ { token: \'punctuation.definition.class.record.end.erlang\',\n
                regex: \'\\\\}\',\n
                next: \'pop\' },\n
              { include: \'#internal-record-body\' },\n
              { defaultToken: \'meta.record-usage.erlang\' } ] } ],\n
      \'#string\': \n
       [ { token: \'punctuation.definition.string.begin.erlang\',\n
           regex: \'"\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.erlang\',\n
                regex: \'"\',\n
                next: \'pop\' },\n
              { token: \n
                 [ \'punctuation.definition.escape.erlang\',\n
                   \'constant.character.escape.erlang\',\n
                   \'punctuation.definition.escape.erlang\',\n
                   \'constant.character.escape.erlang\',\n
                   \'constant.character.escape.erlang\' ],\n
                regex: \'(\\\\\\\\)(?:([bdefnrstv\\\\\\\\\\\'"])|(\\\\^)([@-_])|([0-7]{1,3}))\' },\n
              { token: \'invalid.illegal.string.erlang\', regex: \'\\\\\\\\\\\\^?.?\' },\n
              { token: \n
                 [ \'punctuation.definition.placeholder.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'constant.other.placeholder.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'constant.other.placeholder.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'constant.other.placeholder.erlang\',\n
                   \'constant.other.placeholder.erlang\' ],\n
                regex: \'(~)(?:((?:\\\\-)?)(\\\\d+)|(\\\\*))?(?:(\\\\.)(?:(\\\\d+)|(\\\\*)))?(?:(\\\\.)(?:(\\\\*)|(.)))?([~cfegswpWPBX#bx\\\\+ni])\' },\n
              { token: \n
                 [ \'punctuation.definition.placeholder.erlang\',\n
                   \'punctuation.separator.placeholder-parts.erlang\',\n
                   \'constant.other.placeholder.erlang\',\n
                   \'constant.other.placeholder.erlang\' ],\n
                regex: \'(~)((?:\\\\*)?)((?:\\\\d+)?)([~du\\\\-#fsacl])\' },\n
              { token: \'invalid.illegal.string.erlang\', regex: \'~.?\' },\n
              { defaultToken: \'string.quoted.double.erlang\' } ] } ],\n
      \'#symbolic-operator\': \n
       [ { token: \'keyword.operator.symbolic.erlang\',\n
           regex: \'\\\\+\\\\+|\\\\+|--|-|\\\\*|/=|/|=/=|=:=|==|=<|=|<-|<|>=|>|!|::\' } ],\n
      \'#textual-operator\': \n
       [ { token: \'keyword.operator.textual.erlang\',\n
           regex: \'\\\\b(?:andalso|band|and|bxor|xor|bor|orelse|or|bnot|not|bsl|bsr|div|rem)\\\\b\' } ],\n
      \'#tuple\': \n
       [ { token: \'punctuation.definition.tuple.begin.erlang\',\n
           regex: \'\\\\{\',\n
           push: \n
            [ { token: \'punctuation.definition.tuple.end.erlang\',\n
                regex: \'\\\\}\',\n
                next: \'pop\' },\n
              { token: \'punctuation.separator.tuple.erlang\', regex: \',\' },\n
              { include: \'#everything-else\' },\n
              { defaultToken: \'meta.structure.tuple.erlang\' } ] } ],\n
      \'#variable\': \n
       [ { token: [ \'variable.other.erlang\', \'variable.language.omitted.erlang\' ],\n
           regex: \'(_[a-zA-Z\\\\d@_]+|[A-Z][a-zA-Z\\\\d@_]*)|(_)\' } ] }\n
    \n
    this.normalizeRules();\n
};\n
\n
ErlangHighlightRules.metaData = { comment: \'The recognition of function definitions and compiler directives (such as module, record and macro definitions) requires that each of the aforementioned constructs must be the first string inside a line (except for whitespace).  Also, the function/module/record/macro names must be given unquoted.  -- desp\',\n
      fileTypes: [ \'erl\', \'hrl\' ],\n
      keyEquivalent: \'^~E\',\n
      name: \'Erlang\',\n
      scopeName: \'source.erlang\' }\n
\n
\n
oop.inherits(ErlangHighlightRules, TextHighlightRules);\n
\n
exports.ErlangHighlightRules = ErlangHighlightRules;\n
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
            <value> <int>45111</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
