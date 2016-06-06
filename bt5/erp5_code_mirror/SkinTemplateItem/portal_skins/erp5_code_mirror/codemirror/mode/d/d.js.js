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
            <value> <string>ts21897138.44</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>d.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// CodeMirror, copyright (c) by Marijn Haverbeke and others\n
// Distributed under an MIT license: http://codemirror.net/LICENSE\n
\n
(function(mod) {\n
  if (typeof exports == "object" && typeof module == "object") // CommonJS\n
    mod(require("../../lib/codemirror"));\n
  else if (typeof define == "function" && define.amd) // AMD\n
    define(["../../lib/codemirror"], mod);\n
  else // Plain browser env\n
    mod(CodeMirror);\n
})(function(CodeMirror) {\n
"use strict";\n
\n
CodeMirror.defineMode("d", function(config, parserConfig) {\n
  var indentUnit = config.indentUnit,\n
      statementIndentUnit = parserConfig.statementIndentUnit || indentUnit,\n
      keywords = parserConfig.keywords || {},\n
      builtin = parserConfig.builtin || {},\n
      blockKeywords = parserConfig.blockKeywords || {},\n
      atoms = parserConfig.atoms || {},\n
      hooks = parserConfig.hooks || {},\n
      multiLineStrings = parserConfig.multiLineStrings;\n
  var isOperatorChar = /[+\\-*&%=<>!?|\\/]/;\n
\n
  var curPunc;\n
\n
  function tokenBase(stream, state) {\n
    var ch = stream.next();\n
    if (hooks[ch]) {\n
      var result = hooks[ch](stream, state);\n
      if (result !== false) return result;\n
    }\n
    if (ch == \'"\' || ch == "\'" || ch == "`") {\n
      state.tokenize = tokenString(ch);\n
      return state.tokenize(stream, state);\n
    }\n
    if (/[\\[\\]{}\\(\\),;\\:\\.]/.test(ch)) {\n
      curPunc = ch;\n
      return null;\n
    }\n
    if (/\\d/.test(ch)) {\n
      stream.eatWhile(/[\\w\\.]/);\n
      return "number";\n
    }\n
    if (ch == "/") {\n
      if (stream.eat("+")) {\n
        state.tokenize = tokenComment;\n
        return tokenNestedComment(stream, state);\n
      }\n
      if (stream.eat("*")) {\n
        state.tokenize = tokenComment;\n
        return tokenComment(stream, state);\n
      }\n
      if (stream.eat("/")) {\n
        stream.skipToEnd();\n
        return "comment";\n
      }\n
    }\n
    if (isOperatorChar.test(ch)) {\n
      stream.eatWhile(isOperatorChar);\n
      return "operator";\n
    }\n
    stream.eatWhile(/[\\w\\$_\\xa1-\\uffff]/);\n
    var cur = stream.current();\n
    if (keywords.propertyIsEnumerable(cur)) {\n
      if (blockKeywords.propertyIsEnumerable(cur)) curPunc = "newstatement";\n
      return "keyword";\n
    }\n
    if (builtin.propertyIsEnumerable(cur)) {\n
      if (blockKeywords.propertyIsEnumerable(cur)) curPunc = "newstatement";\n
      return "builtin";\n
    }\n
    if (atoms.propertyIsEnumerable(cur)) return "atom";\n
    return "variable";\n
  }\n
\n
  function tokenString(quote) {\n
    return function(stream, state) {\n
      var escaped = false, next, end = false;\n
      while ((next = stream.next()) != null) {\n
        if (next == quote && !escaped) {end = true; break;}\n
        escaped = !escaped && next == "\\\\";\n
      }\n
      if (end || !(escaped || multiLineStrings))\n
        state.tokenize = null;\n
      return "string";\n
    };\n
  }\n
\n
  function tokenComment(stream, state) {\n
    var maybeEnd = false, ch;\n
    while (ch = stream.next()) {\n
      if (ch == "/" && maybeEnd) {\n
        state.tokenize = null;\n
        break;\n
      }\n
      maybeEnd = (ch == "*");\n
    }\n
    return "comment";\n
  }\n
\n
  function tokenNestedComment(stream, state) {\n
    var maybeEnd = false, ch;\n
    while (ch = stream.next()) {\n
      if (ch == "/" && maybeEnd) {\n
        state.tokenize = null;\n
        break;\n
      }\n
      maybeEnd = (ch == "+");\n
    }\n
    return "comment";\n
  }\n
\n
  function Context(indented, column, type, align, prev) {\n
    this.indented = indented;\n
    this.column = column;\n
    this.type = type;\n
    this.align = align;\n
    this.prev = prev;\n
  }\n
  function pushContext(state, col, type) {\n
    var indent = state.indented;\n
    if (state.context && state.context.type == "statement")\n
      indent = state.context.indented;\n
    return state.context = new Context(indent, col, type, null, state.context);\n
  }\n
  function popContext(state) {\n
    var t = state.context.type;\n
    if (t == ")" || t == "]" || t == "}")\n
      state.indented = state.context.indented;\n
    return state.context = state.context.prev;\n
  }\n
\n
  // Interface\n
\n
  return {\n
    startState: function(basecolumn) {\n
      return {\n
        tokenize: null,\n
        context: new Context((basecolumn || 0) - indentUnit, 0, "top", false),\n
        indented: 0,\n
        startOfLine: true\n
      };\n
    },\n
\n
    token: function(stream, state) {\n
      var ctx = state.context;\n
      if (stream.sol()) {\n
        if (ctx.align == null) ctx.align = false;\n
        state.indented = stream.indentation();\n
        state.startOfLine = true;\n
      }\n
      if (stream.eatSpace()) return null;\n
      curPunc = null;\n
      var style = (state.tokenize || tokenBase)(stream, state);\n
      if (style == "comment" || style == "meta") return style;\n
      if (ctx.align == null) ctx.align = true;\n
\n
      if ((curPunc == ";" || curPunc == ":" || curPunc == ",") && ctx.type == "statement") popContext(state);\n
      else if (curPunc == "{") pushContext(state, stream.column(), "}");\n
      else if (curPunc == "[") pushContext(state, stream.column(), "]");\n
      else if (curPunc == "(") pushContext(state, stream.column(), ")");\n
      else if (curPunc == "}") {\n
        while (ctx.type == "statement") ctx = popContext(state);\n
        if (ctx.type == "}") ctx = popContext(state);\n
        while (ctx.type == "statement") ctx = popContext(state);\n
      }\n
      else if (curPunc == ctx.type) popContext(state);\n
      else if (((ctx.type == "}" || ctx.type == "top") && curPunc != \';\') || (ctx.type == "statement" && curPunc == "newstatement"))\n
        pushContext(state, stream.column(), "statement");\n
      state.startOfLine = false;\n
      return style;\n
    },\n
\n
    indent: function(state, textAfter) {\n
      if (state.tokenize != tokenBase && state.tokenize != null) return CodeMirror.Pass;\n
      var ctx = state.context, firstChar = textAfter && textAfter.charAt(0);\n
      if (ctx.type == "statement" && firstChar == "}") ctx = ctx.prev;\n
      var closing = firstChar == ctx.type;\n
      if (ctx.type == "statement") return ctx.indented + (firstChar == "{" ? 0 : statementIndentUnit);\n
      else if (ctx.align) return ctx.column + (closing ? 0 : 1);\n
      else return ctx.indented + (closing ? 0 : indentUnit);\n
    },\n
\n
    electricChars: "{}"\n
  };\n
});\n
\n
  function words(str) {\n
    var obj = {}, words = str.split(" ");\n
    for (var i = 0; i < words.length; ++i) obj[words[i]] = true;\n
    return obj;\n
  }\n
\n
  var blockKeywords = "body catch class do else enum for foreach foreach_reverse if in interface mixin " +\n
                      "out scope struct switch try union unittest version while with";\n
\n
  CodeMirror.defineMIME("text/x-d", {\n
    name: "d",\n
    keywords: words("abstract alias align asm assert auto break case cast cdouble cent cfloat const continue " +\n
                    "debug default delegate delete deprecated export extern final finally function goto immutable " +\n
                    "import inout invariant is lazy macro module new nothrow override package pragma private " +\n
                    "protected public pure ref return shared short static super synchronized template this " +\n
                    "throw typedef typeid typeof volatile __FILE__ __LINE__ __gshared __traits __vector __parameters " +\n
                    blockKeywords),\n
    blockKeywords: words(blockKeywords),\n
    builtin: words("bool byte char creal dchar double float idouble ifloat int ireal long real short ubyte " +\n
                   "ucent uint ulong ushort wchar wstring void size_t sizediff_t"),\n
    atoms: words("exit failure success true false null"),\n
    hooks: {\n
      "@": function(stream, _state) {\n
        stream.eatWhile(/[\\w\\$_]/);\n
        return "meta";\n
      }\n
    }\n
  });\n
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
            <value> <int>7566</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
