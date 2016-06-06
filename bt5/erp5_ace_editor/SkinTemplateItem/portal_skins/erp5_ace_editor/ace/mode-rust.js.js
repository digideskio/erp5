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
            <value> <string>ts83646621.33</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mode-rust.js</string> </value>
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
define(\'ace/mode/rust\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text\', \'ace/tokenizer\', \'ace/mode/rust_highlight_rules\', \'ace/mode/folding/cstyle\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextMode = require("./text").Mode;\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var RustHighlightRules = require("./rust_highlight_rules").RustHighlightRules;\n
var FoldMode = require("./folding/cstyle").FoldMode;\n
\n
var Mode = function() {\n
    this.HighlightRules = RustHighlightRules;\n
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
define(\'ace/mode/rust_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/mode/text_highlight_rules\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
\n
var RustHighlightRules = function() {\n
\n
    this.$rules = { start: \n
       [ { token: \'variable.other.source.rust\',\n
           regex: \'\\\'[a-zA-Z_][a-zA-Z0-9_]*[^\\\\\\\']\' },\n
         { token: \'string.quoted.single.source.rust\',\n
           regex: \'\\\'\',\n
           push: \n
            [ { token: \'string.quoted.single.source.rust\',\n
                regex: \'\\\'\',\n
                next: \'pop\' },\n
              { include: \'#rust_escaped_character\' },\n
              { defaultToken: \'string.quoted.single.source.rust\' } ] },\n
         { token: \'string.quoted.double.source.rust\',\n
           regex: \'"\',\n
           push: \n
            [ { token: \'string.quoted.double.source.rust\',\n
                regex: \'"\',\n
                next: \'pop\' },\n
              { include: \'#rust_escaped_character\' },\n
              { defaultToken: \'string.quoted.double.source.rust\' } ] },\n
         { token: [ \'keyword.source.rust\', \'meta.function.source.rust\',\n
              \'entity.name.function.source.rust\', \'meta.function.source.rust\' ],\n
           regex: \'\\\\b(fn)(\\\\s+)([a-zA-Z_][a-zA-Z0-9_][\\\\w\\\\:,+ \\\\\\\'<>]*)(\\\\s*\\\\()\' },\n
         { token: \'support.constant\', regex: \'\\\\b[a-zA-Z_][\\\\w\\\\d]*::\' },\n
         { token: \'keyword.source.rust\',\n
           regex: \'\\\\b(?:as|assert|break|claim|const|copy|Copy|do|drop|else|extern|fail|for|if|impl|in|let|log|loop|match|mod|module|move|mut|Owned|priv|pub|pure|ref|return|unchecked|unsafe|use|while|mod|Send|static|trait|class|struct|enum|type)\\\\b\' },\n
         { token: \'storage.type.source.rust\',\n
           regex: \'\\\\b(?:Self|m32|m64|m128|f80|f16|f128|int|uint|float|char|bool|u8|u16|u32|u64|f32|f64|i8|i16|i32|i64|str|option|either|c_float|c_double|c_void|FILE|fpos_t|DIR|dirent|c_char|c_schar|c_uchar|c_short|c_ushort|c_int|c_uint|c_long|c_ulong|size_t|ptrdiff_t|clock_t|time_t|c_longlong|c_ulonglong|intptr_t|uintptr_t|off_t|dev_t|ino_t|pid_t|mode_t|ssize_t)\\\\b\' },\n
         { token: \'variable.language.source.rust\', regex: \'\\\\bself\\\\b\' },\n
         { token: \'keyword.operator\',\n
            regex: \'!|\\\\$|\\\\*|\\\\-\\\\-|\\\\-|\\\\+\\\\+|\\\\+|-->|===|==|=|!=|!==|<=|>=|<<=|>>=|>>>=|<>|<|>|!|&&|\\\\|\\\\||\\\\?\\\\:|\\\\*=|/=|%=|\\\\+=|\\\\-=|&=|\\\\^=|,|;\' },\n
         { token: \'constant.language.source.rust\',\n
           regex: \'\\\\b(?:true|false|Some|None|Left|Right|Ok|Err)\\\\b\' },\n
         { token: \'support.constant.source.rust\',\n
           regex: \'\\\\b(?:EXIT_FAILURE|EXIT_SUCCESS|RAND_MAX|EOF|SEEK_SET|SEEK_CUR|SEEK_END|_IOFBF|_IONBF|_IOLBF|BUFSIZ|FOPEN_MAX|FILENAME_MAX|L_tmpnam|TMP_MAX|O_RDONLY|O_WRONLY|O_RDWR|O_APPEND|O_CREAT|O_EXCL|O_TRUNC|S_IFIFO|S_IFCHR|S_IFBLK|S_IFDIR|S_IFREG|S_IFMT|S_IEXEC|S_IWRITE|S_IREAD|S_IRWXU|S_IXUSR|S_IWUSR|S_IRUSR|F_OK|R_OK|W_OK|X_OK|STDIN_FILENO|STDOUT_FILENO|STDERR_FILENO)\\\\b\' },\n
         { token: \'meta.preprocessor.source.rust\',\n
           regex: \'\\\\b\\\\w\\\\(\\\\w\\\\)*!|#\\\\[[\\\\w=\\\\(\\\\)_]+\\\\]\\\\b\' },\n
         { token: \'constant.numeric.integer.source.rust\',\n
           regex: \'\\\\b(?:[0-9][0-9_]*|[0-9][0-9_]*(?:u|u8|u16|u32|u64)|[0-9][0-9_]*(?:i|i8|i16|i32|i64))\\\\b\' },\n
         { token: \'constant.numeric.hex.source.rust\',\n
           regex: \'\\\\b(?:0x[a-fA-F0-9_]+|0x[a-fA-F0-9_]+(?:u|u8|u16|u32|u64)|0x[a-fA-F0-9_]+(?:i|i8|i16|i32|i64))\\\\b\' },\n
         { token: \'constant.numeric.binary.source.rust\',\n
           regex: \'\\\\b(?:0b[01_]+|0b[01_]+(?:u|u8|u16|u32|u64)|0b[01_]+(?:i|i8|i16|i32|i64))\\\\b\' },\n
         { token: \'constant.numeric.float.source.rust\',\n
           regex: \'[0-9][0-9_]*(?:f32|f64|f)|[0-9][0-9_]*[eE][+-]=[0-9_]+|[0-9][0-9_]*[eE][+-]=[0-9_]+(?:f32|f64|f)|[0-9][0-9_]*\\\\.[0-9_]+|[0-9][0-9_]*\\\\.[0-9_]+(?:f32|f64|f)|[0-9][0-9_]*\\\\.[0-9_]+%[eE][+-]=[0-9_]+|[0-9][0-9_]*\\\\.[0-9_]+%[eE][+-]=[0-9_]+(?:f32|f64|f)\' },\n
         { token: \'comment.line.documentation.source.rust\',\n
           regex: \'//!.*$\',\n
           push_: \n
            [ { token: \'comment.line.documentation.source.rust\',\n
                regex: \'$\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.line.documentation.source.rust\' } ] },\n
         { token: \'comment.line.double-dash.source.rust\',\n
           regex: \'//.*$\',\n
           push_: \n
            [ { token: \'comment.line.double-dash.source.rust\',\n
                regex: \'$\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.line.double-dash.source.rust\' } ] },\n
         { token: \'comment.block.source.rust\',\n
           regex: \'/\\\\*\',\n
           push: \n
            [ { token: \'comment.block.source.rust\',\n
                regex: \'\\\\*/\',\n
                next: \'pop\' },\n
              { defaultToken: \'comment.block.source.rust\' } ] } ],\n
      \'#rust_escaped_character\': \n
       [ { token: \'constant.character.escape.source.rust\',\n
           regex: \'\\\\\\\\(?:x[\\\\da-fA-F]{2}|[0-2][0-7]{,2}|3[0-6][0-7]?|37[0-7]?|[4-7][0-7]?|.)\' } ] }\n
    \n
    this.normalizeRules();\n
};\n
\n
RustHighlightRules.metaData = { fileTypes: [ \'rs\', \'rc\' ],\n
      foldingStartMarker: \'^.*\\\\bfn\\\\s*(\\\\w+\\\\s*)?\\\\([^\\\\)]*\\\\)(\\\\s*\\\\{[^\\\\}]*)?\\\\s*$\',\n
      foldingStopMarker: \'^\\\\s*\\\\}\',\n
      name: \'Rust\',\n
      scopeName: \'source.rust\' }\n
\n
\n
oop.inherits(RustHighlightRules, TextHighlightRules);\n
\n
exports.RustHighlightRules = RustHighlightRules;\n
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
            <value> <int>9530</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
