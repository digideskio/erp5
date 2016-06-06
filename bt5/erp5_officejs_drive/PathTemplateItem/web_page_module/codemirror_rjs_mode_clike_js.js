<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="Web Script" module="erp5.portal_type"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Access_contents_information_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Add_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Change_local_roles_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Modify_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>content_md5</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>default_reference</string> </key>
            <value> <string>codemirror_mode_clike.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>codemirror_rjs_mode_clike_js</string> </value>
        </item>
        <item>
            <key> <string>language</string> </key>
            <value> <string>en</string> </value>
        </item>
        <item>
            <key> <string>portal_type</string> </key>
            <value> <string>Web Script</string> </value>
        </item>
        <item>
            <key> <string>short_title</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>text_content</string> </key>
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
CodeMirror.defineMode("clike", function(config, parserConfig) {\n
  var indentUnit = config.indentUnit,\n
      statementIndentUnit = parserConfig.statementIndentUnit || indentUnit,\n
      dontAlignCalls = parserConfig.dontAlignCalls,\n
      keywords = parserConfig.keywords || {},\n
      types = parserConfig.types || {},\n
      builtin = parserConfig.builtin || {},\n
      blockKeywords = parserConfig.blockKeywords || {},\n
      defKeywords = parserConfig.defKeywords || {},\n
      atoms = parserConfig.atoms || {},\n
      hooks = parserConfig.hooks || {},\n
      multiLineStrings = parserConfig.multiLineStrings,\n
      indentStatements = parserConfig.indentStatements !== false,\n
      indentSwitch = parserConfig.indentSwitch !== false,\n
      namespaceSeparator = parserConfig.namespaceSeparator,\n
      isPunctuationChar = parserConfig.isPunctuationChar || /[\\[\\]{}\\(\\),;\\:\\.]/,\n
      numberStart = parserConfig.numberStart || /[\\d\\.]/,\n
      number = parserConfig.number || /^(?:0x[a-f\\d]+|0b[01]+|(?:\\d+\\.?\\d*|\\.\\d+)(?:e[-+]?\\d+)?)(u|ll?|l|f)?/i,\n
      isOperatorChar = parserConfig.isOperatorChar || /[+\\-*&%=<>!?|\\/]/,\n
      endStatement = parserConfig.endStatement || /^[;:,]$/;\n
\n
  var curPunc, isDefKeyword;\n
\n
  function tokenBase(stream, state) {\n
    var ch = stream.next();\n
    if (hooks[ch]) {\n
      var result = hooks[ch](stream, state);\n
      if (result !== false) return result;\n
    }\n
    if (ch == \'"\' || ch == "\'") {\n
      state.tokenize = tokenString(ch);\n
      return state.tokenize(stream, state);\n
    }\n
    if (isPunctuationChar.test(ch)) {\n
      curPunc = ch;\n
      return null;\n
    }\n
    if (numberStart.test(ch)) {\n
      stream.backUp(1)\n
      if (stream.match(number)) return "number"\n
      stream.next()\n
    }\n
    if (ch == "/") {\n
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
    if (namespaceSeparator) while (stream.match(namespaceSeparator))\n
      stream.eatWhile(/[\\w\\$_\\xa1-\\uffff]/);\n
\n
    var cur = stream.current();\n
    if (contains(keywords, cur)) {\n
      if (contains(blockKeywords, cur)) curPunc = "newstatement";\n
      if (contains(defKeywords, cur)) isDefKeyword = true;\n
      return "keyword";\n
    }\n
    if (contains(types, cur)) return "variable-3";\n
    if (contains(builtin, cur)) {\n
      if (contains(blockKeywords, cur)) curPunc = "newstatement";\n
      return "builtin";\n
    }\n
    if (contains(atoms, cur)) return "atom";\n
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
  function Context(indented, column, type, align, prev) {\n
    this.indented = indented;\n
    this.column = column;\n
    this.type = type;\n
    this.align = align;\n
    this.prev = prev;\n
  }\n
  function isStatement(type) {\n
    return type == "statement" || type == "switchstatement" || type == "namespace";\n
  }\n
  function pushContext(state, col, type) {\n
    var indent = state.indented;\n
    if (state.context && isStatement(state.context.type) && !isStatement(type))\n
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
  function typeBefore(stream, state) {\n
    if (state.prevToken == "variable" || state.prevToken == "variable-3") return true;\n
    if (/\\S(?:[^- ]>|[*\\]])\\s*$|\\*$/.test(stream.string.slice(0, stream.start))) return true;\n
  }\n
\n
  function isTopScope(context) {\n
    for (;;) {\n
      if (!context || context.type == "top") return true;\n
      if (context.type == "}" && context.prev.type != "namespace") return false;\n
      context = context.prev;\n
    }\n
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
        startOfLine: true,\n
        prevToken: null\n
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
      curPunc = isDefKeyword = null;\n
      var style = (state.tokenize || tokenBase)(stream, state);\n
      if (style == "comment" || style == "meta") return style;\n
      if (ctx.align == null) ctx.align = true;\n
\n
      if (endStatement.test(curPunc)) while (isStatement(state.context.type)) popContext(state);\n
      else if (curPunc == "{") pushContext(state, stream.column(), "}");\n
      else if (curPunc == "[") pushContext(state, stream.column(), "]");\n
      else if (curPunc == "(") pushContext(state, stream.column(), ")");\n
      else if (curPunc == "}") {\n
        while (isStatement(ctx.type)) ctx = popContext(state);\n
        if (ctx.type == "}") ctx = popContext(state);\n
        while (isStatement(ctx.type)) ctx = popContext(state);\n
      }\n
      else if (curPunc == ctx.type) popContext(state);\n
      else if (indentStatements &&\n
               (((ctx.type == "}" || ctx.type == "top") && curPunc != ";") ||\n
                (isStatement(ctx.type) && curPunc == "newstatement"))) {\n
        var type = "statement";\n
        if (curPunc == "newstatement" && indentSwitch && stream.current() == "switch")\n
          type = "switchstatement";\n
        else if (style == "keyword" && stream.current() == "namespace")\n
          type = "namespace";\n
        pushContext(state, stream.column(), type);\n
      }\n
\n
      if (style == "variable" &&\n
          ((state.prevToken == "def" ||\n
            (parserConfig.typeFirstDefinitions && typeBefore(stream, state) &&\n
             isTopScope(state.context) && stream.match(/^\\s*\\(/, false)))))\n
        style = "def";\n
\n
      if (hooks.token) {\n
        var result = hooks.token(stream, state, style);\n
        if (result !== undefined) style = result;\n
      }\n
\n
      if (style == "def" && parserConfig.styleDefs === false) style = "variable";\n
\n
      state.startOfLine = false;\n
      state.prevToken = isDefKeyword ? "def" : style || curPunc;\n
      return style;\n
    },\n
\n
    indent: function(state, textAfter) {\n
      if (state.tokenize != tokenBase && state.tokenize != null) return CodeMirror.Pass;\n
      var ctx = state.context, firstChar = textAfter && textAfter.charAt(0);\n
      if (isStatement(ctx.type) && firstChar == "}") ctx = ctx.prev;\n
      if (hooks.indent) {\n
        var hook = hooks.indent(state, ctx, textAfter);\n
        if (typeof hook == "number") return hook\n
      }\n
      var closing = firstChar == ctx.type;\n
      var switchBlock = ctx.prev && ctx.prev.type == "switchstatement";\n
      if (parserConfig.allmanIndentation && /[{(]/.test(firstChar)) {\n
        while (ctx.type != "top" && ctx.type != "}") ctx = ctx.prev\n
        return ctx.indented\n
      }\n
      if (isStatement(ctx.type))\n
        return ctx.indented + (firstChar == "{" ? 0 : statementIndentUnit);\n
      if (ctx.align && (!dontAlignCalls || ctx.type != ")"))\n
        return ctx.column + (closing ? 0 : 1);\n
      if (ctx.type == ")" && !closing)\n
        return ctx.indented + statementIndentUnit;\n
\n
      return ctx.indented + (closing ? 0 : indentUnit) +\n
        (!closing && switchBlock && !/^(?:case|default)\\b/.test(textAfter) ? indentUnit : 0);\n
    },\n
\n
    electricInput: indentSwitch ? /^\\s*(?:case .*?:|default:|\\{\\}?|\\})$/ : /^\\s*[{}]$/,\n
    blockCommentStart: "/*",\n
    blockCommentEnd: "*/",\n
    lineComment: "//",\n
    fold: "brace"\n
  };\n
});\n
\n
  function words(str) {\n
    var obj = {}, words = str.split(" ");\n
    for (var i = 0; i < words.length; ++i) obj[words[i]] = true;\n
    return obj;\n
  }\n
  function contains(words, word) {\n
    if (typeof words === "function") {\n
      return words(word);\n
    } else {\n
      return words.propertyIsEnumerable(word);\n
    }\n
  }\n
  var cKeywords = "auto if break case register continue return default do sizeof " +\n
    "static else struct switch extern typedef union for goto while enum const volatile";\n
  var cTypes = "int long char short double float unsigned signed void size_t ptrdiff_t";\n
\n
  function cppHook(stream, state) {\n
    if (!state.startOfLine) return false\n
    for (var ch, next = null; ch = stream.peek();) {\n
      if (!ch) {\n
        break\n
      } else if (ch == "\\\\" && stream.match(/^.$/)) {\n
        next = cppHook\n
        break\n
      } else if (ch == "/" && stream.match(/^\\/[\\/\\*]/, false)) {\n
        break\n
      }\n
      stream.next()\n
    }\n
    state.tokenize = next\n
    return "meta"\n
  }\n
\n
  function pointerHook(_stream, state) {\n
    if (state.prevToken == "variable-3") return "variable-3";\n
    return false;\n
  }\n
\n
  function cpp14Literal(stream) {\n
    stream.eatWhile(/[\\w\\.\']/);\n
    return "number";\n
  }\n
\n
  function cpp11StringHook(stream, state) {\n
    stream.backUp(1);\n
    // Raw strings.\n
    if (stream.match(/(R|u8R|uR|UR|LR)/)) {\n
      var match = stream.match(/"([^\\s\\\\()]{0,16})\\(/);\n
      if (!match) {\n
        return false;\n
      }\n
      state.cpp11RawStringDelim = match[1];\n
      state.tokenize = tokenRawString;\n
      return tokenRawString(stream, state);\n
    }\n
    // Unicode strings/chars.\n
    if (stream.match(/(u8|u|U|L)/)) {\n
      if (stream.match(/["\']/, /* eat */ false)) {\n
        return "string";\n
      }\n
      return false;\n
    }\n
    // Ignore this hook.\n
    stream.next();\n
    return false;\n
  }\n
\n
  function cppLooksLikeConstructor(word) {\n
    var lastTwo = /(\\w+)::(\\w+)$/.exec(word);\n
    return lastTwo && lastTwo[1] == lastTwo[2];\n
  }\n
\n
  // C#-style strings where "" escapes a quote.\n
  function tokenAtString(stream, state) {\n
    var next;\n
    while ((next = stream.next()) != null) {\n
      if (next == \'"\' && !stream.eat(\'"\')) {\n
        state.tokenize = null;\n
        break;\n
      }\n
    }\n
    return "string";\n
  }\n
\n
  // C++11 raw string literal is <prefix>"<delim>( anything )<delim>", where\n
  // <delim> can be a string up to 16 characters long.\n
  function tokenRawString(stream, state) {\n
    // Escape characters that have special regex meanings.\n
    var delim = state.cpp11RawStringDelim.replace(/[^\\w\\s]/g, \'\\\\$&\');\n
    var match = stream.match(new RegExp(".*?\\\\)" + delim + \'"\'));\n
    if (match)\n
      state.tokenize = null;\n
    else\n
      stream.skipToEnd();\n
    return "string";\n
  }\n
\n
  function def(mimes, mode) {\n
    if (typeof mimes == "string") mimes = [mimes];\n
    var words = [];\n
    function add(obj) {\n
      if (obj) for (var prop in obj) if (obj.hasOwnProperty(prop))\n
        words.push(prop);\n
    }\n
    add(mode.keywords);\n
    add(mode.types);\n
    add(mode.builtin);\n
    add(mode.atoms);\n
    if (words.length) {\n
      mode.helperType = mimes[0];\n
      CodeMirror.registerHelper("hintWords", mimes[0], words);\n
    }\n
\n
    for (var i = 0; i < mimes.length; ++i)\n
      CodeMirror.defineMIME(mimes[i], mode);\n
  }\n
\n
  def(["text/x-csrc", "text/x-c", "text/x-chdr"], {\n
    name: "clike",\n
    keywords: words(cKeywords),\n
    types: words(cTypes + " bool _Complex _Bool float_t double_t intptr_t intmax_t " +\n
                 "int8_t int16_t int32_t int64_t uintptr_t uintmax_t uint8_t uint16_t " +\n
                 "uint32_t uint64_t"),\n
    blockKeywords: words("case do else for if switch while struct"),\n
    defKeywords: words("struct"),\n
    typeFirstDefinitions: true,\n
    atoms: words("null true false"),\n
    hooks: {"#": cppHook, "*": pointerHook},\n
    modeProps: {fold: ["brace", "include"]}\n
  });\n
\n
  def(["text/x-c++src", "text/x-c++hdr"], {\n
    name: "clike",\n
    keywords: words(cKeywords + " asm dynamic_cast namespace reinterpret_cast try explicit new " +\n
                    "static_cast typeid catch operator template typename class friend private " +\n
                    "this using const_cast inline public throw virtual delete mutable protected " +\n
                    "alignas alignof constexpr decltype nullptr noexcept thread_local final " +\n
                    "static_assert override"),\n
    types: words(cTypes + " bool wchar_t"),\n
    blockKeywords: words("catch class do else finally for if struct switch try while"),\n
    defKeywords: words("class namespace struct enum union"),\n
    typeFirstDefinitions: true,\n
    atoms: words("true false null"),\n
    hooks: {\n
      "#": cppHook,\n
      "*": pointerHook,\n
      "u": cpp11StringHook,\n
      "U": cpp11StringHook,\n
      "L": cpp11StringHook,\n
      "R": cpp11StringHook,\n
      "0": cpp14Literal,\n
      "1": cpp14Literal,\n
      "2": cpp14Literal,\n
      "3": cpp14Literal,\n
      "4": cpp14Literal,\n
      "5": cpp14Literal,\n
      "6": cpp14Literal,\n
      "7": cpp14Literal,\n
      "8": cpp14Literal,\n
      "9": cpp14Literal,\n
      token: function(stream, state, style) {\n
        if (style == "variable" && stream.peek() == "(" &&\n
            (state.prevToken == ";" || state.prevToken == null ||\n
             state.prevToken == "}") &&\n
            cppLooksLikeConstructor(stream.current()))\n
          return "def";\n
      }\n
    },\n
    namespaceSeparator: "::",\n
    modeProps: {fold: ["brace", "include"]}\n
  });\n
\n
  def("text/x-java", {\n
    name: "clike",\n
    keywords: words("abstract assert break case catch class const continue default " +\n
                    "do else enum extends final finally float for goto if implements import " +\n
                    "instanceof interface native new package private protected public " +\n
                    "return static strictfp super switch synchronized this throw throws transient " +\n
                    "try volatile while"),\n
    types: words("byte short int long float double boolean char void Boolean Byte Character Double Float " +\n
                 "Integer Long Number Object Short String StringBuffer StringBuilder Void"),\n
    blockKeywords: words("catch class do else finally for if switch try while"),\n
    defKeywords: words("class interface package enum"),\n
    typeFirstDefinitions: true,\n
    atoms: words("true false null"),\n
    endStatement: /^[;:]$/,\n
    hooks: {\n
      "@": function(stream) {\n
        stream.eatWhile(/[\\w\\$_]/);\n
        return "meta";\n
      }\n
    },\n
    modeProps: {fold: ["brace", "import"]}\n
  });\n
\n
  def("text/x-csharp", {\n
    name: "clike",\n
    keywords: words("abstract as async await base break case catch checked class const continue" +\n
                    " default delegate do else enum event explicit extern finally fixed for" +\n
                    " foreach goto if implicit in interface internal is lock namespace new" +\n
                    " operator out override params private protected public readonly ref return sealed" +\n
                    " sizeof stackalloc static struct switch this throw try typeof unchecked" +\n
                    " unsafe using virtual void volatile while add alias ascending descending dynamic from get" +\n
                    " global group into join let orderby partial remove select set value var yield"),\n
    types: words("Action Boolean Byte Char DateTime DateTimeOffset Decimal Double Func" +\n
                 " Guid Int16 Int32 Int64 Object SByte Single String Task TimeSpan UInt16 UInt32" +\n
                 " UInt64 bool byte char decimal double short int long object"  +\n
                 " sbyte float string ushort uint ulong"),\n
    blockKeywords: words("catch class do else finally for foreach if struct switch try while"),\n
    defKeywords: words("class interface namespace struct var"),\n
    typeFirstDefinitions: true,\n
    atoms: words("true false null"),\n
    hooks: {\n
      "@": function(stream, state) {\n
        if (stream.eat(\'"\')) {\n
          state.tokenize = tokenAtString;\n
          return tokenAtString(stream, state);\n
        }\n
        stream.eatWhile(/[\\w\\$_]/);\n
        return "meta";\n
      }\n
    }\n
  });\n
\n
  function tokenTripleString(stream, state) {\n
    var escaped = false;\n
    while (!stream.eol()) {\n
      if (!escaped && stream.match(\'"""\')) {\n
        state.tokenize = null;\n
        break;\n
      }\n
      escaped = stream.next() == "\\\\" && !escaped;\n
    }\n
    return "string";\n
  }\n
\n
  def("text/x-scala", {\n
    name: "clike",\n
    keywords: words(\n
\n
      /* scala */\n
      "abstract case catch class def do else extends final finally for forSome if " +\n
      "implicit import lazy match new null object override package private protected return " +\n
      "sealed super this throw trait try type val var while with yield _ : = => <- <: " +\n
      "<% >: # @ " +\n
\n
      /* package scala */\n
      "assert assume require print println printf readLine readBoolean readByte readShort " +\n
      "readChar readInt readLong readFloat readDouble " +\n
\n
      ":: #:: "\n
    ),\n
    types: words(\n
      "AnyVal App Application Array BufferedIterator BigDecimal BigInt Char Console Either " +\n
      "Enumeration Equiv Error Exception Fractional Function IndexedSeq Integral Iterable " +\n
      "Iterator List Map Numeric Nil NotNull Option Ordered Ordering PartialFunction PartialOrdering " +\n
      "Product Proxy Range Responder Seq Serializable Set Specializable Stream StringBuilder " +\n
      "StringContext Symbol Throwable Traversable TraversableOnce Tuple Unit Vector " +\n
\n
      /* package java.lang */\n
      "Boolean Byte Character CharSequence Class ClassLoader Cloneable Comparable " +\n
      "Compiler Double Exception Float Integer Long Math Number Object Package Pair Process " +\n
      "Runtime Runnable SecurityManager Short StackTraceElement StrictMath String " +\n
      "StringBuffer System Thread ThreadGroup ThreadLocal Throwable Triple Void"\n
    ),\n
    multiLineStrings: true,\n
    blockKeywords: words("catch class do else finally for forSome if match switch try while"),\n
    defKeywords: words("class def object package trait type val var"),\n
    atoms: words("true false null"),\n
    indentStatements: false,\n
    indentSwitch: false,\n
    hooks: {\n
      "@": function(stream) {\n
        stream.eatWhile(/[\\w\\$_]/);\n
        return "meta";\n
      },\n
      \'"\': function(stream, state) {\n
        if (!stream.match(\'""\')) return false;\n
        state.tokenize = tokenTripleString;\n
        return state.tokenize(stream, state);\n
      },\n
      "\'": function(stream) {\n
        stream.eatWhile(/[\\w\\$_\\xa1-\\uffff]/);\n
        return "atom";\n
      }\n
    },\n
    modeProps: {closeBrackets: {triples: \'"\'}}\n
  });\n
\n
  function tokenKotlinString(tripleString){\n
    return function (stream, state) {\n
      var escaped = false, next, end = false;\n
      while (!stream.eol()) {\n
        if (!tripleString && !escaped && stream.match(\'"\') ) {end = true; break;}\n
        if (tripleString && stream.match(\'"""\')) {end = true; break;}\n
        next = stream.next();\n
        if(!escaped && next == "$" && stream.match(\'{\'))\n
          stream.skipTo("}");\n
        escaped = !escaped && next == "\\\\" && !tripleString;\n
      }\n
      if (end || !tripleString)\n
        state.tokenize = null;\n
      return "string";\n
    }\n
  }\n
\n
  def("text/x-kotlin", {\n
    name: "clike",\n
    keywords: words(\n
      /*keywords*/\n
      "package as typealias class interface this super val " +\n
      "var fun for is in This throw return " +\n
      "break continue object if else while do try when !in !is as? " +\n
\n
      /*soft keywords*/\n
      "file import where by get set abstract enum open inner override private public internal " +\n
      "protected catch finally out final vararg reified dynamic companion constructor init " +\n
      "sealed field property receiver param sparam lateinit data inline noinline tailrec " +\n
      "external annotation crossinline const operator infix"\n
    ),\n
    types: words(\n
      /* package java.lang */\n
      "Boolean Byte Character CharSequence Class ClassLoader Cloneable Comparable " +\n
      "Compiler Double Exception Float Integer Long Math Number Object Package Pair Process " +\n
      "Runtime Runnable SecurityManager Short StackTraceElement StrictMath String " +\n
      "StringBuffer System Thread ThreadGroup ThreadLocal Throwable Triple Void"\n
    ),\n
    intendSwitch: false,\n
    indentStatements: false,\n
    multiLineStrings: true,\n
    blockKeywords: words("catch class do else finally for if where try while enum"),\n
    defKeywords: words("class val var object package interface fun"),\n
    atoms: words("true false null this"),\n
    hooks: {\n
      \'"\': function(stream, state) {\n
        state.tokenize = tokenKotlinString(stream.match(\'""\'));\n
        return state.tokenize(stream, state);\n
      }\n
    },\n
    modeProps: {closeBrackets: {triples: \'"\'}}\n
  });\n
\n
  def(["x-shader/x-vertex", "x-shader/x-fragment"], {\n
    name: "clike",\n
    keywords: words("sampler1D sampler2D sampler3D samplerCube " +\n
                    "sampler1DShadow sampler2DShadow " +\n
                    "const attribute uniform varying " +\n
                    "break continue discard return " +\n
                    "for while do if else struct " +\n
                    "in out inout"),\n
    types: words("float int bool void " +\n
                 "vec2 vec3 vec4 ivec2 ivec3 ivec4 bvec2 bvec3 bvec4 " +\n
                 "mat2 mat3 mat4"),\n
    blockKeywords: words("for while do if else struct"),\n
    builtin: words("radians degrees sin cos tan asin acos atan " +\n
                    "pow exp log exp2 sqrt inversesqrt " +\n
                    "abs sign floor ceil fract mod min max clamp mix step smoothstep " +\n
                    "length distance dot cross normalize ftransform faceforward " +\n
                    "reflect refract matrixCompMult " +\n
                    "lessThan lessThanEqual greaterThan greaterThanEqual " +\n
                    "equal notEqual any all not " +\n
                    "texture1D texture1DProj texture1DLod texture1DProjLod " +\n
                    "texture2D texture2DProj texture2DLod texture2DProjLod " +\n
                    "texture3D texture3DProj texture3DLod texture3DProjLod " +\n
                    "textureCube textureCubeLod " +\n
                    "shadow1D shadow2D shadow1DProj shadow2DProj " +\n
                    "shadow1DLod shadow2DLod shadow1DProjLod shadow2DProjLod " +\n
                    "dFdx dFdy fwidth " +\n
                    "noise1 noise2 noise3 noise4"),\n
    atoms: words("true false " +\n
                "gl_FragColor gl_SecondaryColor gl_Normal gl_Vertex " +\n
                "gl_MultiTexCoord0 gl_MultiTexCoord1 gl_MultiTexCoord2 gl_MultiTexCoord3 " +\n
                "gl_MultiTexCoord4 gl_MultiTexCoord5 gl_MultiTexCoord6 gl_MultiTexCoord7 " +\n
                "gl_FogCoord gl_PointCoord " +\n
                "gl_Position gl_PointSize gl_ClipVertex " +\n
                "gl_FrontColor gl_BackColor gl_FrontSecondaryColor gl_BackSecondaryColor " +\n
                "gl_TexCoord gl_FogFragCoord " +\n
                "gl_FragCoord gl_FrontFacing " +\n
                "gl_FragData gl_FragDepth " +\n
                "gl_ModelViewMatrix gl_ProjectionMatrix gl_ModelViewProjectionMatrix " +\n
                "gl_TextureMatrix gl_NormalMatrix gl_ModelViewMatrixInverse " +\n
                "gl_ProjectionMatrixInverse gl_ModelViewProjectionMatrixInverse " +\n
                "gl_TexureMatrixTranspose gl_ModelViewMatrixInverseTranspose " +\n
                "gl_ProjectionMatrixInverseTranspose " +\n
                "gl_ModelViewProjectionMatrixInverseTranspose " +\n
                "gl_TextureMatrixInverseTranspose " +\n
                "gl_NormalScale gl_DepthRange gl_ClipPlane " +\n
                "gl_Point gl_FrontMaterial gl_BackMaterial gl_LightSource gl_LightModel " +\n
                "gl_FrontLightModelProduct gl_BackLightModelProduct " +\n
                "gl_TextureColor gl_EyePlaneS gl_EyePlaneT gl_EyePlaneR gl_EyePlaneQ " +\n
                "gl_FogParameters " +\n
                "gl_MaxLights gl_MaxClipPlanes gl_MaxTextureUnits gl_MaxTextureCoords " +\n
                "gl_MaxVertexAttribs gl_MaxVertexUniformComponents gl_MaxVaryingFloats " +\n
                "gl_MaxVertexTextureImageUnits gl_MaxTextureImageUnits " +\n
                "gl_MaxFragmentUniformComponents gl_MaxCombineTextureImageUnits " +\n
                "gl_MaxDrawBuffers"),\n
    indentSwitch: false,\n
    hooks: {"#": cppHook},\n
    modeProps: {fold: ["brace", "include"]}\n
  });\n
\n
  def("text/x-nesc", {\n
    name: "clike",\n
    keywords: words(cKeywords + "as atomic async call command component components configuration event generic " +\n
                    "implementation includes interface module new norace nx_struct nx_union post provides " +\n
                    "signal task uses abstract extends"),\n
    types: words(cTypes),\n
    blockKeywords: words("case do else for if switch while struct"),\n
    atoms: words("null true false"),\n
    hooks: {"#": cppHook},\n
    modeProps: {fold: ["brace", "include"]}\n
  });\n
\n
  def("text/x-objectivec", {\n
    name: "clike",\n
    keywords: words(cKeywords + "inline restrict _Bool _Complex _Imaginery BOOL Class bycopy byref id IMP in " +\n
                    "inout nil oneway out Protocol SEL self super atomic nonatomic retain copy readwrite readonly"),\n
    types: words(cTypes),\n
    atoms: words("YES NO NULL NILL ON OFF true false"),\n
    hooks: {\n
      "@": function(stream) {\n
        stream.eatWhile(/[\\w\\$]/);\n
        return "keyword";\n
      },\n
      "#": cppHook,\n
      indent: function(_state, ctx, textAfter) {\n
        if (ctx.type == "statement" && /^@\\w/.test(textAfter)) return ctx.indented\n
      }\n
    },\n
    modeProps: {fold: "brace"}\n
  });\n
\n
  def("text/x-squirrel", {\n
    name: "clike",\n
    keywords: words("base break clone continue const default delete enum extends function in class" +\n
                    " foreach local resume return this throw typeof yield constructor instanceof static"),\n
    types: words(cTypes),\n
    blockKeywords: words("case catch class else for foreach if switch try while"),\n
    defKeywords: words("function local class"),\n
    typeFirstDefinitions: true,\n
    atoms: words("true false null"),\n
    hooks: {"#": cppHook},\n
    modeProps: {fold: ["brace", "include"]}\n
  });\n
\n
  // Ceylon Strings need to deal with interpolation\n
  var stringTokenizer = null;\n
  function tokenCeylonString(type) {\n
    return function(stream, state) {\n
      var escaped = false, next, end = false;\n
      while (!stream.eol()) {\n
        if (!escaped && stream.match(\'"\') &&\n
              (type == "single" || stream.match(\'""\'))) {\n
          end = true;\n
          break;\n
        }\n
        if (!escaped && stream.match(\'``\')) {\n
          stringTokenizer = tokenCeylonString(type);\n
          end = true;\n
          break;\n
        }\n
        next = stream.next();\n
        escaped = type == "single" && !escaped && next == "\\\\";\n
      }\n
      if (end)\n
          state.tokenize = null;\n
      return "string";\n
    }\n
  }\n
\n
  def("text/x-ceylon", {\n
    name: "clike",\n
    keywords: words("abstracts alias assembly assert assign break case catch class continue dynamic else" +\n
                    " exists extends finally for function given if import in interface is let module new" +\n
                    " nonempty object of out outer package return satisfies super switch then this throw" +\n
                    " try value void while"),\n
    types: function(word) {\n
        // In Ceylon all identifiers that start with an uppercase are types\n
        var first = word.charAt(0);\n
        return (first === first.toUpperCase() && first !== first.toLowerCase());\n
    },\n
    blockKeywords: words("case catch class dynamic else finally for function if interface module new object switch try while"),\n
    defKeywords: words("class dynamic function interface module object package value"),\n
    builtin: words("abstract actual aliased annotation by default deprecated doc final formal late license" +\n
                   " native optional sealed see serializable shared suppressWarnings tagged throws variable"),\n
    isPunctuationChar: /[\\[\\]{}\\(\\),;\\:\\.`]/,\n
    isOperatorChar: /[+\\-*&%=<>!?|^~:\\/]/,\n
    numberStart: /[\\d#$]/,\n
    number: /^(?:#[\\da-fA-F_]+|\\$[01_]+|[\\d_]+[kMGTPmunpf]?|[\\d_]+\\.[\\d_]+(?:[eE][-+]?\\d+|[kMGTPmunpf]|)|)/i,\n
    multiLineStrings: true,\n
    typeFirstDefinitions: true,\n
    atoms: words("true false null larger smaller equal empty finished"),\n
    indentSwitch: false,\n
    styleDefs: false,\n
    hooks: {\n
      "@": function(stream) {\n
        stream.eatWhile(/[\\w\\$_]/);\n
        return "meta";\n
      },\n
      \'"\': function(stream, state) {\n
          state.tokenize = tokenCeylonString(stream.match(\'""\') ? "triple" : "single");\n
          return state.tokenize(stream, state);\n
        },\n
      \'`\': function(stream, state) {\n
          if (!stringTokenizer || !stream.match(\'`\')) return false;\n
          state.tokenize = stringTokenizer;\n
          stringTokenizer = null;\n
          return state.tokenize(stream, state);\n
        },\n
      "\'": function(stream) {\n
        stream.eatWhile(/[\\w\\$_\\xa1-\\uffff]/);\n
        return "atom";\n
      },\n
      token: function(_stream, state, style) {\n
          if ((style == "variable" || style == "variable-3") &&\n
              state.prevToken == ".") {\n
            return "variable-2";\n
          }\n
        }\n
    },\n
    modeProps: {\n
        fold: ["brace", "import"],\n
        closeBrackets: {triples: \'"\'}\n
    }\n
  });\n
\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>CodeMirror Mode CLike</string> </value>
        </item>
        <item>
            <key> <string>version</string> </key>
            <value> <string>4.3.0</string> </value>
        </item>
        <item>
            <key> <string>workflow_history</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="PersistentMapping" module="Persistence.mapping"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value>
              <dictionary>
                <item>
                    <key> <string>document_publication_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>edit_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>processing_status_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAU=</string> </persistent>
                    </value>
                </item>
              </dictionary>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>publish_alive</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1406898405.73</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
            <item>
                <key> <string>validation_state</string> </key>
                <value> <string>published_alive</string> </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>edit</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>zope</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value>
                  <none/>
                </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>948.28969.17299.54579</string> </value>
            </item>
            <item>
                <key> <string>state</string> </key>
                <value> <string>current</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1453133683.21</float>
                        <string>UTC</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="5" aka="AAAAAAAAAAU=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>detect_converted_file</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>external_processing_state</string> </key>
                <value> <string>converted</string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>0.0.0.0</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1405068613.53</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
</ZopeData>
