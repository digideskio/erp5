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
            <value> <string>ts83646622.18</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-forth.js</string> </value>
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
define(\'ace/mode/forth\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/forth_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var ForthHighlightRules = require("./forth_highlight_rules").ForthHighlightRules;\n
var FoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = ForthHighlightRules;\n
    this.foldingRules = new FoldMode();\n
};\n
oop.inherits(Mode, TextMode);\n
\n
(function() {\n
    this.lineCommentStart = "(?<=^|\\\\s)\\\\.?\\\\( [^)]*\\\\)";\n
    this.blockComment = {start: "/*", end: "*/"};\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/mode/forth_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var ForthHighlightRules = function() {\n
\n
    this.$rules = { start: [ { include: \'#forth\' } ],\n
      \'#comment\': \n
       [ { token: \'comment.line.double-dash.forth\',\n
           regex: \'(?:^|\\\\s)--\\\\s.*$\',\n
           comment: \'line comments for iForth\' },\n
         { token: \'comment.line.backslash.forth\',\n
           regex: \'(?:^|\\\\s)\\\\\\\\[\\\\s\\\\S]*$\',\n
           comment: \'ANSI line comment\' },\n
         { token: \'comment.line.backslash-g.forth\',\n
           regex: \'(?:^|\\\\s)\\\\\\\\[Gg] .*$\',\n
           comment: \'gForth line comment\' },\n
         { token: \'comment.block.forth\',\n
           regex: \'(?:^|\\\\s)\\\\(\\\\*(?=\\\\s|$)\',\n
           push: \n
            [ { token: \'comment.block.forth\',\n
                regex: \'(?:^|\\\\s)\\\\*\\\\)(?=\\\\s|$)\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.block.forth\' } ],\n
           comment: \'multiline comments for iForth\' },\n
         { token: \'comment.block.documentation.forth\',\n
           regex: \'\\\\bDOC\\\\b\',\n
           caseInsensitive: true,\n
           push: \n
            [ { token: \'comment.block.documentation.forth\',\n
                regex: \'\\\\bENDDOC\\\\b\',\n
                caseInsensitive: true,\n
                next: \'pop\' },\n
              { defaultToken: \'comment.block.documentation.forth\' } ],\n
           comment: \'documentation comments for iForth\' },\n
         { token: \'comment.line.parentheses.forth\',\n
           regex: \'(?:^|\\\\s)\\\\.?\\\\( [^)]*\\\\)\',\n
           comment: \'ANSI line comment\' } ],\n
      \'#constant\': \n
       [ { token: \'constant.language.forth\',\n
           regex: \'(?:^|\\\\s)(?:TRUE|FALSE|BL|PI|CELL|C/L|R/O|W/O|R/W)(?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'constant.numeric.forth\',\n
           regex: \'(?:^|\\\\s)[$#%]?[-+]?[0-9]+(?:\\\\.[0-9]*e-?[0-9]+|\\\\.?[0-9a-fA-F]*)(?=\\\\s|$)\'},\n
         { token: \'constant.character.forth\',\n
           regex: \'(?:^|\\\\s)(?:[&^]\\\\S|(?:"|\\\')\\\\S(?:"|\\\'))(?=\\\\s|$)\'}],\n
      \'#forth\': \n
       [ { include: \'#constant\' },\n
         { include: \'#comment\' },\n
         { include: \'#string\' },\n
         { include: \'#word\' },\n
         { include: \'#variable\' },\n
         { include: \'#storage\' },\n
         { include: \'#word-def\' } ],\n
      \'#storage\': \n
       [ { token: \'storage.type.forth\',\n
           regex: \'(?:^|\\\\s)(?:2CONSTANT|2VARIABLE|ALIAS|CONSTANT|CREATE-INTERPRET/COMPILE[:]?|CREATE|DEFER|FCONSTANT|FIELD|FVARIABLE|USER|VALUE|VARIABLE|VOCABULARY)(?=\\\\s|$)\',\n
           caseInsensitive: true}],\n
      \'#string\': \n
       [ { token: \'string.quoted.double.forth\',\n
           regex: \'(ABORT" |BREAK" |\\\\." |C" |0"|S\\\\\\\\?" )([^"]+")\',\n
           caseInsensitive: true},\n
         { token: \'string.unquoted.forth\',\n
           regex: \'(?:INCLUDE|NEEDS|REQUIRE|USE)[ ]\\\\S+(?=\\\\s|$)\',\n
           caseInsensitive: true}],\n
      \'#variable\': \n
       [ { token: \'variable.language.forth\',\n
           regex: \'\\\\b(?:I|J)\\\\b\',\n
           caseInsensitive: true } ],\n
      \'#word\': \n
       [ { token: \'keyword.control.immediate.forth\',\n
           regex: \'(?:^|\\\\s)\\\\[(?:\\\\?DO|\\\\+LOOP|AGAIN|BEGIN|DEFINED|DO|ELSE|ENDIF|FOR|IF|IFDEF|IFUNDEF|LOOP|NEXT|REPEAT|THEN|UNTIL|WHILE)\\\\](?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'keyword.other.immediate.forth\',\n
           regex: \'(?:^|\\\\s)(?:COMPILE-ONLY|IMMEDIATE|IS|RESTRICT|TO|WHAT\\\'S|])(?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'keyword.control.compile-only.forth\',\n
           regex: \'(?:^|\\\\s)(?:-DO|\\\\-LOOP|\\\\?DO|\\\\?LEAVE|\\\\+DO|\\\\+LOOP|ABORT\\\\"|AGAIN|AHEAD|BEGIN|CASE|DO|ELSE|ENDCASE|ENDIF|ENDOF|ENDTRY\\\\-IFERROR|ENDTRY|FOR|IF|IFERROR|LEAVE|LOOP|NEXT|RECOVER|REPEAT|RESTORE|THEN|TRY|U\\\\-DO|U\\\\+DO|UNTIL|WHILE)(?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'keyword.other.compile-only.forth\',\n
           regex: \'(?:^|\\\\s)(?:\\\\?DUP-0=-IF|\\\\?DUP-IF|\\\\)|\\\\[|\\\\[\\\'\\\\]|\\\\[CHAR\\\\]|\\\\[COMPILE\\\\]|\\\\[IS\\\\]|\\\\[TO\\\\]|<COMPILATION|<INTERPRETATION|ASSERT\\\\(|ASSERT0\\\\(|ASSERT1\\\\(|ASSERT2\\\\(|ASSERT3\\\\(|COMPILATION>|DEFERS|DOES>|INTERPRETATION>|OF|POSTPONE)(?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'keyword.other.non-immediate.forth\',\n
           regex: \'(?:^|\\\\s)(?:\\\'|<IS>|<TO>|CHAR|END-STRUCT|INCLUDE[D]?|LOAD|NEEDS|REQUIRE[D]?|REVISION|SEE|STRUCT|THRU|USE)(?=\\\\s|$)\',\n
           caseInsensitive: true},\n
         { token: \'keyword.other.warning.forth\',\n
           regex: \'(?:^|\\\\s)(?:~~|BREAK:|BREAK"|DBG)(?=\\\\s|$)\',\n
           caseInsensitive: true}],\n
      \'#word-def\': \n
       [ { token: \n
            [ \'keyword.other.compile-only.forth\',\n
              \'keyword.other.compile-only.forth\',\n
              \'meta.block.forth\',\n
              \'entity.name.function.forth\' ],\n
           regex: \'(:NONAME)|(^:|\\\\s:)(\\\\s)(\\\\S+)(?=\\\\s|$)\',\n
           caseInsensitive: true,\n
           push: \n
            [ { token: \'keyword.other.compile-only.forth\',\n
                regex: \';(?:CODE)?\',\n
                caseInsensitive: true,\n
                next: \'pop\' },\n
              { include: \'#constant\' },\n
              { include: \'#comment\' },\n
              { include: \'#string\' },\n
              { include: \'#word\' },\n
              { include: \'#variable\' },\n
              { include: \'#storage\' },\n
              { defaultToken: \'meta.block.forth\' } ] } ] }\n
    \n
    this.normalizeRules();\n
};\n
\n
ForthHighlightRules.metaData = { fileTypes: [ \'frt\', \'fs\', \'ldr\' ],\n
      foldingStartMarker: \'/\\\\*\\\\*|\\\\{\\\\s*$\',\n
      foldingStopMarker: \'\\\\*\\\\*/|^\\\\s*\\\\}\',\n
      keyEquivalent: \'^~F\',\n
      name: \'Forth\',\n
      scopeName: \'source.forth\' }\n
\n
\n
oop.inherits(ForthHighlightRules, TextHighlightRules);\n
\n
exports.ForthHighlightRules = ForthHighlightRules;\n
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
            <value> <int>10016</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
