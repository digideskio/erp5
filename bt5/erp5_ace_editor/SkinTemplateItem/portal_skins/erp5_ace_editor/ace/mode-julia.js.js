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
            <value> <string>ts83646621.89</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-julia.js</string> </value>
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
define(\'ace/mode/julia\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/julia_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var JuliaHighlightRules = require("./julia_highlight_rules").JuliaHighlightRules;\n
var FoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = JuliaHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "#";\n
    this.blockComment = "";\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/julia_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var JuliaHighlightRules = function() {\n
\n
    this.$rules = { start: \n
       [ { include: \'#function_decl\' },\n
         { include: \'#function_call\' },\n
         { include: \'#type_decl\' },\n
         { include: \'#keyword\' },\n
         { include: \'#operator\' },\n
         { include: \'#number\' },\n
         { include: \'#string\' },\n
         { include: \'#comment\' } ],\n
      \'#bracket\': \n
       [ { token: \'keyword.bracket.julia\',\n
           regex: \'\\\\(|\\\\)|\\\\[|\\\\]|\\\\{|\\\\}|,\' } ],\n
      \'#comment\': \n
       [ { token: \n
            [ \'punctuation.definition.comment.julia\',\n
              \'comment.line.number-sign.julia\' ],\n
           regex: \'(#)(?!\\\\{)(.*$)\'} ],\n
      \'#function_call\': \n
       [ { token: [ \'support.function.julia\', \'text\' ],\n
           regex: \'([a-zA-Z0-9_]+!?)(\\\\w*\\\\()\'} ],\n
      \'#function_decl\': \n
       [ { token: [ \'keyword.other.julia\', \'meta.function.julia\',\n
               \'entity.name.function.julia\', \'meta.function.julia\',\'text\' ],\n
           regex: \'(function|macro)(\\\\s*)([a-zA-Z0-9_\\\\{]+!?)(\\\\w*)([(\\\\\\\\{])\'} ],\n
      \'#keyword\':\n
       [ { token: \'keyword.other.julia\',\n
           regex: \'\\\\b(?:function|type|immutable|macro|quote|abstract|bitstype|typealias|module|baremodule|new)\\\\b\' },\n
         { token: \'keyword.control.julia\',\n
           regex: \'\\\\b(?:if|else|elseif|while|for|in|begin|let|end|do|try|catch|finally|return|break|continue)\\\\b\' },\n
         { token: \'storage.modifier.variable.julia\',\n
           regex: \'\\\\b(?:global|local|const|export|import|importall|using)\\\\b\' },\n
         { token: \'variable.macro.julia\', regex: \'@\\\\w+\\\\b\' } ],\n
      \'#number\': \n
       [ { token: \'constant.numeric.julia\',\n
           regex: \'\\\\b0(?:x|X)[0-9a-fA-F]*|(?:\\\\b[0-9]+\\\\.?[0-9]*|\\\\.[0-9]+)(?:(?:e|E)(?:\\\\+|-)?[0-9]*)?(?:im)?|\\\\bInf(?:32)?\\\\b|\\\\bNaN(?:32)?\\\\b|\\\\btrue\\\\b|\\\\bfalse\\\\b\' } ],\n
      \'#operator\': \n
       [ { token: \'keyword.operator.update.julia\',\n
           regex: \'=|:=|\\\\+=|-=|\\\\*=|/=|//=|\\\\.//=|\\\\.\\\\*=|\\\\\\\\=|\\\\.\\\\\\\\=|^=|\\\\.^=|%=|\\\\|=|&=|\\\\$=|<<=|>>=\' },\n
         { token: \'keyword.operator.ternary.julia\', regex: \'\\\\?|:\' },\n
         { token: \'keyword.operator.boolean.julia\',\n
           regex: \'\\\\|\\\\||&&|!\' },\n
         { token: \'keyword.operator.arrow.julia\', regex: \'->|<-|-->\' },\n
         { token: \'keyword.operator.relation.julia\',\n
           regex: \'>|<|>=|<=|==|!=|\\\\.>|\\\\.<|\\\\.>=|\\\\.>=|\\\\.==|\\\\.!=|\\\\.=|\\\\.!|<:|:>\' },\n
         { token: \'keyword.operator.range.julia\', regex: \':\' },\n
         { token: \'keyword.operator.shift.julia\', regex: \'<<|>>\' },\n
         { token: \'keyword.operator.bitwise.julia\', regex: \'\\\\||\\\\&|~\' },\n
         { token: \'keyword.operator.arithmetic.julia\',\n
           regex: \'\\\\+|-|\\\\*|\\\\.\\\\*|/|\\\\./|//|\\\\.//|%|\\\\.%|\\\\\\\\|\\\\.\\\\\\\\|\\\\^|\\\\.\\\\^\' },\n
         { token: \'keyword.operator.isa.julia\', regex: \'::\' },\n
         { token: \'keyword.operator.dots.julia\',\n
           regex: \'\\\\.(?=[a-zA-Z])|\\\\.\\\\.+\' },\n
         { token: \'keyword.operator.interpolation.julia\',\n
           regex: \'\\\\$#?(?=.)\' },\n
         { token: [ \'variable\', \'keyword.operator.transposed-variable.julia\' ],\n
           regex: \'(\\\\w+)((?:\\\'|\\\\.\\\')*\\\\.?\\\')\' },\n
         { token: \'text\',\n
           regex: \'\\\\[|\\\\(\'},\n
         { token: [ \'text\', \'keyword.operator.transposed-matrix.julia\' ],\n
            regex: "([\\\\]\\\\)])((?:\'|\\\\.\')*\\\\.?\')"} ],\n
      \'#string\': \n
       [ { token: \'punctuation.definition.string.begin.julia\',\n
           regex: \'\\\'\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.julia\',\n
                regex: \'\\\'\',\n
                next: \'pop\' },\n
              { include: \'#string_escaped_char\' },\n
              { defaultToken: \'string.quoted.single.julia\' } ] },\n
         { token: \'punctuation.definition.string.begin.julia\',\n
           regex: \'"\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.julia\',\n
                regex: \'"\',\n
                next: \'pop\' },\n
              { include: \'#string_escaped_char\' },\n
              { defaultToken: \'string.quoted.double.julia\' } ] },\n
         { token: \'punctuation.definition.string.begin.julia\',\n
           regex: \'\\\\b\\\\w+"\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.julia\',\n
                regex: \'"\\\\w*\',\n
                next: \'pop\' },\n
              { include: \'#string_custom_escaped_char\' },\n
              { defaultToken: \'string.quoted.custom-double.julia\' } ] },\n
         { token: \'punctuation.definition.string.begin.julia\',\n
           regex: \'`\',\n
           push: \n
            [ { token: \'punctuation.definition.string.end.julia\',\n
                regex: \'`\',\n
                next: \'pop\' },\n
              { include: \'#string_escaped_char\' },\n
              { defaultToken: \'string.quoted.backtick.julia\' } ] } ],\n
      \'#string_custom_escaped_char\': [ { token: \'constant.character.escape.julia\', regex: \'\\\\\\\\"\' } ],\n
      \'#string_escaped_char\': \n
       [ { token: \'constant.character.escape.julia\',\n
           regex: \'\\\\\\\\(?:\\\\\\\\|[0-3]\\\\d{,2}|[4-7]\\\\d?|x[a-fA-F0-9]{,2}|u[a-fA-F0-9]{,4}|U[a-fA-F0-9]{,8}|.)\' } ],\n
      \'#type_decl\': \n
       [ { token: \n
            [ \'keyword.control.type.julia\',\n
              \'meta.type.julia\',\n
              \'entity.name.type.julia\',\n
              \'entity.other.inherited-class.julia\',\n
              \'punctuation.separator.inheritance.julia\',\n
              \'entity.other.inherited-class.julia\' ],\n
           regex: \'(type|immutable)(\\\\s+)([a-zA-Z0-9_]+)(?:(\\\\s*)(<:)(\\\\s*[.a-zA-Z0-9_:]+))?\' },\n
         { token: [ \'other.typed-variable.julia\', \'support.type.julia\' ],\n
           regex: \'([a-zA-Z0-9_]+)(::[a-zA-Z0-9_{}]+)\' } ] }\n
    \n
    this.normalizeRules();\n
};\n
\n
JuliaHighlightRules.metaData = { fileTypes: [ \'jl\' ],\n
      firstLineMatch: \'^#!.*\\\\bjulia\\\\s*$\',\n
      foldingStartMarker: \'^\\\\s*(?:if|while|for|begin|function|macro|module|baremodule|type|immutable|let)\\\\b(?!.*\\\\bend\\\\b).*$\',\n
      foldingStopMarker: \'^\\\\s*(?:end)\\\\b.*$\',\n
      name: \'Julia\',\n
      scopeName: \'source.julia\' }\n
\n
\n
oop.inherits(JuliaHighlightRules, TextHighlightRules);\n
\n
exports.JuliaHighlightRules = JuliaHighlightRules;\n
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
            <value> <int>10441</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
