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
            <value> <string>codemirror_mode_javascript.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>codemirror_rjs_mode_javascript_js</string> </value>
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
// TODO actually recognize syntax of TypeScript constructs\n
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
CodeMirror.defineMode("javascript", function(config, parserConfig) {\n
  var indentUnit = config.indentUnit;\n
  var statementIndent = parserConfig.statementIndent;\n
  var jsonldMode = parserConfig.jsonld;\n
  var jsonMode = parserConfig.json || jsonldMode;\n
  var isTS = parserConfig.typescript;\n
  var wordRE = parserConfig.wordCharacters || /[\\w$\\xa1-\\uffff]/;\n
\n
  // Tokenizer\n
\n
  var keywords = function(){\n
    function kw(type) {return {type: type, style: "keyword"};}\n
    var A = kw("keyword a"), B = kw("keyword b"), C = kw("keyword c");\n
    var operator = kw("operator"), atom = {type: "atom", style: "atom"};\n
\n
    var jsKeywords = {\n
      "if": kw("if"), "while": A, "with": A, "else": B, "do": B, "try": B, "finally": B,\n
      "return": C, "break": C, "continue": C, "new": kw("new"), "delete": C, "throw": C, "debugger": C,\n
      "var": kw("var"), "const": kw("var"), "let": kw("var"),\n
      "function": kw("function"), "catch": kw("catch"),\n
      "for": kw("for"), "switch": kw("switch"), "case": kw("case"), "default": kw("default"),\n
      "in": operator, "typeof": operator, "instanceof": operator,\n
      "true": atom, "false": atom, "null": atom, "undefined": atom, "NaN": atom, "Infinity": atom,\n
      "this": kw("this"), "class": kw("class"), "super": kw("atom"),\n
      "yield": C, "export": kw("export"), "import": kw("import"), "extends": C\n
    };\n
\n
    // Extend the \'normal\' keywords with the TypeScript language extensions\n
    if (isTS) {\n
      var type = {type: "variable", style: "variable-3"};\n
      var tsKeywords = {\n
        // object-like things\n
        "interface": kw("class"),\n
        "implements": C,\n
        "namespace": C,\n
        "module": kw("module"),\n
        "enum": kw("module"),\n
\n
        // scope modifiers\n
        "public": kw("modifier"),\n
        "private": kw("modifier"),\n
        "protected": kw("modifier"),\n
        "abstract": kw("modifier"),\n
\n
        // operators\n
        "as": operator,\n
\n
        // types\n
        "string": type, "number": type, "boolean": type, "any": type\n
      };\n
\n
      for (var attr in tsKeywords) {\n
        jsKeywords[attr] = tsKeywords[attr];\n
      }\n
    }\n
\n
    return jsKeywords;\n
  }();\n
\n
  var isOperatorChar = /[+\\-*&%=<>!?|~^]/;\n
  var isJsonldKeyword = /^@(context|id|value|language|type|container|list|set|reverse|index|base|vocab|graph)"/;\n
\n
  function readRegexp(stream) {\n
    var escaped = false, next, inSet = false;\n
    while ((next = stream.next()) != null) {\n
      if (!escaped) {\n
        if (next == "/" && !inSet) return;\n
        if (next == "[") inSet = true;\n
        else if (inSet && next == "]") inSet = false;\n
      }\n
      escaped = !escaped && next == "\\\\";\n
    }\n
  }\n
\n
  // Used as scratch variables to communicate multiple values without\n
  // consing up tons of objects.\n
  var type, content;\n
  function ret(tp, style, cont) {\n
    type = tp; content = cont;\n
    return style;\n
  }\n
  function tokenBase(stream, state) {\n
    var ch = stream.next();\n
    if (ch == \'"\' || ch == "\'") {\n
      state.tokenize = tokenString(ch);\n
      return state.tokenize(stream, state);\n
    } else if (ch == "." && stream.match(/^\\d+(?:[eE][+\\-]?\\d+)?/)) {\n
      return ret("number", "number");\n
    } else if (ch == "." && stream.match("..")) {\n
      return ret("spread", "meta");\n
    } else if (/[\\[\\]{}\\(\\),;\\:\\.]/.test(ch)) {\n
      return ret(ch);\n
    } else if (ch == "=" && stream.eat(">")) {\n
      return ret("=>", "operator");\n
    } else if (ch == "0" && stream.eat(/x/i)) {\n
      stream.eatWhile(/[\\da-f]/i);\n
      return ret("number", "number");\n
    } else if (ch == "0" && stream.eat(/o/i)) {\n
      stream.eatWhile(/[0-7]/i);\n
      return ret("number", "number");\n
    } else if (ch == "0" && stream.eat(/b/i)) {\n
      stream.eatWhile(/[01]/i);\n
      return ret("number", "number");\n
    } else if (/\\d/.test(ch)) {\n
      stream.match(/^\\d*(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?/);\n
      return ret("number", "number");\n
    } else if (ch == "/") {\n
      if (stream.eat("*")) {\n
        state.tokenize = tokenComment;\n
        return tokenComment(stream, state);\n
      } else if (stream.eat("/")) {\n
        stream.skipToEnd();\n
        return ret("comment", "comment");\n
      } else if (/^(?:operator|sof|keyword c|case|new|[\\[{}\\(,;:])$/.test(state.lastType) ||\n
                 (state.lastType == "quasi" && /\\{\\s*$/.test(stream.string.slice(0, stream.pos - 1)))) {\n
        readRegexp(stream);\n
        stream.match(/^\\b(([gimyu])(?![gimyu]*\\2))+\\b/);\n
        return ret("regexp", "string-2");\n
      } else {\n
        stream.eatWhile(isOperatorChar);\n
        return ret("operator", "operator", stream.current());\n
      }\n
    } else if (ch == "`") {\n
      state.tokenize = tokenQuasi;\n
      return tokenQuasi(stream, state);\n
    } else if (ch == "#") {\n
      stream.skipToEnd();\n
      return ret("error", "error");\n
    } else if (isOperatorChar.test(ch)) {\n
      stream.eatWhile(isOperatorChar);\n
      return ret("operator", "operator", stream.current());\n
    } else if (wordRE.test(ch)) {\n
      stream.eatWhile(wordRE);\n
      var word = stream.current(), known = keywords.propertyIsEnumerable(word) && keywords[word];\n
      return (known && state.lastType != ".") ? ret(known.type, known.style, word) :\n
                     ret("variable", "variable", word);\n
    }\n
  }\n
\n
  function tokenString(quote) {\n
    return function(stream, state) {\n
      var escaped = false, next;\n
      if (jsonldMode && stream.peek() == "@" && stream.match(isJsonldKeyword)){\n
        state.tokenize = tokenBase;\n
        return ret("jsonld-keyword", "meta");\n
      }\n
      while ((next = stream.next()) != null) {\n
        if (next == quote && !escaped) break;\n
        escaped = !escaped && next == "\\\\";\n
      }\n
      if (!escaped) state.tokenize = tokenBase;\n
      return ret("string", "string");\n
    };\n
  }\n
\n
  function tokenComment(stream, state) {\n
    var maybeEnd = false, ch;\n
    while (ch = stream.next()) {\n
      if (ch == "/" && maybeEnd) {\n
        state.tokenize = tokenBase;\n
        break;\n
      }\n
      maybeEnd = (ch == "*");\n
    }\n
    return ret("comment", "comment");\n
  }\n
\n
  function tokenQuasi(stream, state) {\n
    var escaped = false, next;\n
    while ((next = stream.next()) != null) {\n
      if (!escaped && (next == "`" || next == "$" && stream.eat("{"))) {\n
        state.tokenize = tokenBase;\n
        break;\n
      }\n
      escaped = !escaped && next == "\\\\";\n
    }\n
    return ret("quasi", "string-2", stream.current());\n
  }\n
\n
  var brackets = "([{}])";\n
  // This is a crude lookahead trick to try and notice that we\'re\n
  // parsing the argument patterns for a fat-arrow function before we\n
  // actually hit the arrow token. It only works if the arrow is on\n
  // the same line as the arguments and there\'s no strange noise\n
  // (comments) in between. Fallback is to only notice when we hit the\n
  // arrow, and not declare the arguments as locals for the arrow\n
  // body.\n
  function findFatArrow(stream, state) {\n
    if (state.fatArrowAt) state.fatArrowAt = null;\n
    var arrow = stream.string.indexOf("=>", stream.start);\n
    if (arrow < 0) return;\n
\n
    var depth = 0, sawSomething = false;\n
    for (var pos = arrow - 1; pos >= 0; --pos) {\n
      var ch = stream.string.charAt(pos);\n
      var bracket = brackets.indexOf(ch);\n
      if (bracket >= 0 && bracket < 3) {\n
        if (!depth) { ++pos; break; }\n
        if (--depth == 0) break;\n
      } else if (bracket >= 3 && bracket < 6) {\n
        ++depth;\n
      } else if (wordRE.test(ch)) {\n
        sawSomething = true;\n
      } else if (/["\'\\/]/.test(ch)) {\n
        return;\n
      } else if (sawSomething && !depth) {\n
        ++pos;\n
        break;\n
      }\n
    }\n
    if (sawSomething && !depth) state.fatArrowAt = pos;\n
  }\n
\n
  // Parser\n
\n
  var atomicTypes = {"atom": true, "number": true, "variable": true, "string": true, "regexp": true, "this": true, "jsonld-keyword": true};\n
\n
  function JSLexical(indented, column, type, align, prev, info) {\n
    this.indented = indented;\n
    this.column = column;\n
    this.type = type;\n
    this.prev = prev;\n
    this.info = info;\n
    if (align != null) this.align = align;\n
  }\n
\n
  function inScope(state, varname) {\n
    for (var v = state.localVars; v; v = v.next)\n
      if (v.name == varname) return true;\n
    for (var cx = state.context; cx; cx = cx.prev) {\n
      for (var v = cx.vars; v; v = v.next)\n
        if (v.name == varname) return true;\n
    }\n
  }\n
\n
  function parseJS(state, style, type, content, stream) {\n
    var cc = state.cc;\n
    // Communicate our context to the combinators.\n
    // (Less wasteful than consing up a hundred closures on every call.)\n
    cx.state = state; cx.stream = stream; cx.marked = null, cx.cc = cc; cx.style = style;\n
\n
    if (!state.lexical.hasOwnProperty("align"))\n
      state.lexical.align = true;\n
\n
    while(true) {\n
      var combinator = cc.length ? cc.pop() : jsonMode ? expression : statement;\n
      if (combinator(type, content)) {\n
        while(cc.length && cc[cc.length - 1].lex)\n
          cc.pop()();\n
        if (cx.marked) return cx.marked;\n
        if (type == "variable" && inScope(state, content)) return "variable-2";\n
        return style;\n
      }\n
    }\n
  }\n
\n
  // Combinator utils\n
\n
  var cx = {state: null, column: null, marked: null, cc: null};\n
  function pass() {\n
    for (var i = arguments.length - 1; i >= 0; i--) cx.cc.push(arguments[i]);\n
  }\n
  function cont() {\n
    pass.apply(null, arguments);\n
    return true;\n
  }\n
  function register(varname) {\n
    function inList(list) {\n
      for (var v = list; v; v = v.next)\n
        if (v.name == varname) return true;\n
      return false;\n
    }\n
    var state = cx.state;\n
    cx.marked = "def";\n
    if (state.context) {\n
      if (inList(state.localVars)) return;\n
      state.localVars = {name: varname, next: state.localVars};\n
    } else {\n
      if (inList(state.globalVars)) return;\n
      if (parserConfig.globalVars)\n
        state.globalVars = {name: varname, next: state.globalVars};\n
    }\n
  }\n
\n
  // Combinators\n
\n
  var defaultVars = {name: "this", next: {name: "arguments"}};\n
  function pushcontext() {\n
    cx.state.context = {prev: cx.state.context, vars: cx.state.localVars};\n
    cx.state.localVars = defaultVars;\n
  }\n
  function popcontext() {\n
    cx.state.localVars = cx.state.context.vars;\n
    cx.state.context = cx.state.context.prev;\n
  }\n
  function pushlex(type, info) {\n
    var result = function() {\n
      var state = cx.state, indent = state.indented;\n
      if (state.lexical.type == "stat") indent = state.lexical.indented;\n
      else for (var outer = state.lexical; outer && outer.type == ")" && outer.align; outer = outer.prev)\n
        indent = outer.indented;\n
      state.lexical = new JSLexical(indent, cx.stream.column(), type, null, state.lexical, info);\n
    };\n
    result.lex = true;\n
    return result;\n
  }\n
  function poplex() {\n
    var state = cx.state;\n
    if (state.lexical.prev) {\n
      if (state.lexical.type == ")")\n
        state.indented = state.lexical.indented;\n
      state.lexical = state.lexical.prev;\n
    }\n
  }\n
  poplex.lex = true;\n
\n
  function expect(wanted) {\n
    function exp(type) {\n
      if (type == wanted) return cont();\n
      else if (wanted == ";") return pass();\n
      else return cont(exp);\n
    };\n
    return exp;\n
  }\n
\n
  function statement(type, value) {\n
    if (type == "var") return cont(pushlex("vardef", value.length), vardef, expect(";"), poplex);\n
    if (type == "keyword a") return cont(pushlex("form"), expression, statement, poplex);\n
    if (type == "keyword b") return cont(pushlex("form"), statement, poplex);\n
    if (type == "{") return cont(pushlex("}"), block, poplex);\n
    if (type == ";") return cont();\n
    if (type == "if") {\n
      if (cx.state.lexical.info == "else" && cx.state.cc[cx.state.cc.length - 1] == poplex)\n
        cx.state.cc.pop()();\n
      return cont(pushlex("form"), expression, statement, poplex, maybeelse);\n
    }\n
    if (type == "function") return cont(functiondef);\n
    if (type == "for") return cont(pushlex("form"), forspec, statement, poplex);\n
    if (type == "variable") return cont(pushlex("stat"), maybelabel);\n
    if (type == "switch") return cont(pushlex("form"), expression, pushlex("}", "switch"), expect("{"),\n
                                      block, poplex, poplex);\n
    if (type == "case") return cont(expression, expect(":"));\n
    if (type == "default") return cont(expect(":"));\n
    if (type == "catch") return cont(pushlex("form"), pushcontext, expect("("), funarg, expect(")"),\n
                                     statement, poplex, popcontext);\n
    if (type == "class") return cont(pushlex("form"), className, poplex);\n
    if (type == "export") return cont(pushlex("stat"), afterExport, poplex);\n
    if (type == "import") return cont(pushlex("stat"), afterImport, poplex);\n
    if (type == "module") return cont(pushlex("form"), pattern, pushlex("}"), expect("{"), block, poplex, poplex)\n
    return pass(pushlex("stat"), expression, expect(";"), poplex);\n
  }\n
  function expression(type) {\n
    return expressionInner(type, false);\n
  }\n
  function expressionNoComma(type) {\n
    return expressionInner(type, true);\n
  }\n
  function expressionInner(type, noComma) {\n
    if (cx.state.fatArrowAt == cx.stream.start) {\n
      var body = noComma ? arrowBodyNoComma : arrowBody;\n
      if (type == "(") return cont(pushcontext, pushlex(")"), commasep(pattern, ")"), poplex, expect("=>"), body, popcontext);\n
      else if (type == "variable") return pass(pushcontext, pattern, expect("=>"), body, popcontext);\n
    }\n
\n
    var maybeop = noComma ? maybeoperatorNoComma : maybeoperatorComma;\n
    if (atomicTypes.hasOwnProperty(type)) return cont(maybeop);\n
    if (type == "function") return cont(functiondef, maybeop);\n
    if (type == "keyword c") return cont(noComma ? maybeexpressionNoComma : maybeexpression);\n
    if (type == "(") return cont(pushlex(")"), maybeexpression, comprehension, expect(")"), poplex, maybeop);\n
    if (type == "operator" || type == "spread") return cont(noComma ? expressionNoComma : expression);\n
    if (type == "[") return cont(pushlex("]"), arrayLiteral, poplex, maybeop);\n
    if (type == "{") return contCommasep(objprop, "}", null, maybeop);\n
    if (type == "quasi") return pass(quasi, maybeop);\n
    if (type == "new") return cont(maybeTarget(noComma));\n
    return cont();\n
  }\n
  function maybeexpression(type) {\n
    if (type.match(/[;\\}\\)\\],]/)) return pass();\n
    return pass(expression);\n
  }\n
  function maybeexpressionNoComma(type) {\n
    if (type.match(/[;\\}\\)\\],]/)) return pass();\n
    return pass(expressionNoComma);\n
  }\n
\n
  function maybeoperatorComma(type, value) {\n
    if (type == ",") return cont(expression);\n
    return maybeoperatorNoComma(type, value, false);\n
  }\n
  function maybeoperatorNoComma(type, value, noComma) {\n
    var me = noComma == false ? maybeoperatorComma : maybeoperatorNoComma;\n
    var expr = noComma == false ? expression : expressionNoComma;\n
    if (type == "=>") return cont(pushcontext, noComma ? arrowBodyNoComma : arrowBody, popcontext);\n
    if (type == "operator") {\n
      if (/\\+\\+|--/.test(value)) return cont(me);\n
      if (value == "?") return cont(expression, expect(":"), expr);\n
      return cont(expr);\n
    }\n
    if (type == "quasi") { return pass(quasi, me); }\n
    if (type == ";") return;\n
    if (type == "(") return contCommasep(expressionNoComma, ")", "call", me);\n
    if (type == ".") return cont(property, me);\n
    if (type == "[") return cont(pushlex("]"), maybeexpression, expect("]"), poplex, me);\n
  }\n
  function quasi(type, value) {\n
    if (type != "quasi") return pass();\n
    if (value.slice(value.length - 2) != "${") return cont(quasi);\n
    return cont(expression, continueQuasi);\n
  }\n
  function continueQuasi(type) {\n
    if (type == "}") {\n
      cx.marked = "string-2";\n
      cx.state.tokenize = tokenQuasi;\n
      return cont(quasi);\n
    }\n
  }\n
  function arrowBody(type) {\n
    findFatArrow(cx.stream, cx.state);\n
    return pass(type == "{" ? statement : expression);\n
  }\n
  function arrowBodyNoComma(type) {\n
    findFatArrow(cx.stream, cx.state);\n
    return pass(type == "{" ? statement : expressionNoComma);\n
  }\n
  function maybeTarget(noComma) {\n
    return function(type) {\n
      if (type == ".") return cont(noComma ? targetNoComma : target);\n
      else return pass(noComma ? expressionNoComma : expression);\n
    };\n
  }\n
  function target(_, value) {\n
    if (value == "target") { cx.marked = "keyword"; return cont(maybeoperatorComma); }\n
  }\n
  function targetNoComma(_, value) {\n
    if (value == "target") { cx.marked = "keyword"; return cont(maybeoperatorNoComma); }\n
  }\n
  function maybelabel(type) {\n
    if (type == ":") return cont(poplex, statement);\n
    return pass(maybeoperatorComma, expect(";"), poplex);\n
  }\n
  function property(type) {\n
    if (type == "variable") {cx.marked = "property"; return cont();}\n
  }\n
  function objprop(type, value) {\n
    if (type == "variable" || cx.style == "keyword") {\n
      cx.marked = "property";\n
      if (value == "get" || value == "set") return cont(getterSetter);\n
      return cont(afterprop);\n
    } else if (type == "number" || type == "string") {\n
      cx.marked = jsonldMode ? "property" : (cx.style + " property");\n
      return cont(afterprop);\n
    } else if (type == "jsonld-keyword") {\n
      return cont(afterprop);\n
    } else if (type == "modifier") {\n
      return cont(objprop)\n
    } else if (type == "[") {\n
      return cont(expression, expect("]"), afterprop);\n
    } else if (type == "spread") {\n
      return cont(expression);\n
    }\n
  }\n
  function getterSetter(type) {\n
    if (type != "variable") return pass(afterprop);\n
    cx.marked = "property";\n
    return cont(functiondef);\n
  }\n
  function afterprop(type) {\n
    if (type == ":") return cont(expressionNoComma);\n
    if (type == "(") return pass(functiondef);\n
  }\n
  function commasep(what, end) {\n
    function proceed(type) {\n
      if (type == ",") {\n
        var lex = cx.state.lexical;\n
        if (lex.info == "call") lex.pos = (lex.pos || 0) + 1;\n
        return cont(what, proceed);\n
      }\n
      if (type == end) return cont();\n
      return cont(expect(end));\n
    }\n
    return function(type) {\n
      if (type == end) return cont();\n
      return pass(what, proceed);\n
    };\n
  }\n
  function contCommasep(what, end, info) {\n
    for (var i = 3; i < arguments.length; i++)\n
      cx.cc.push(arguments[i]);\n
    return cont(pushlex(end, info), commasep(what, end), poplex);\n
  }\n
  function block(type) {\n
    if (type == "}") return cont();\n
    return pass(statement, block);\n
  }\n
  function maybetype(type) {\n
    if (isTS && type == ":") return cont(typedef);\n
  }\n
  function maybedefault(_, value) {\n
    if (value == "=") return cont(expressionNoComma);\n
  }\n
  function typedef(type) {\n
    if (type == "variable") {cx.marked = "variable-3"; return cont();}\n
  }\n
  function vardef() {\n
    return pass(pattern, maybetype, maybeAssign, vardefCont);\n
  }\n
  function pattern(type, value) {\n
    if (type == "modifier") return cont(pattern)\n
    if (type == "variable") { register(value); return cont(); }\n
    if (type == "spread") return cont(pattern);\n
    if (type == "[") return contCommasep(pattern, "]");\n
    if (type == "{") return contCommasep(proppattern, "}");\n
  }\n
  function proppattern(type, value) {\n
    if (type == "variable" && !cx.stream.match(/^\\s*:/, false)) {\n
      register(value);\n
      return cont(maybeAssign);\n
    }\n
    if (type == "variable") cx.marked = "property";\n
    if (type == "spread") return cont(pattern);\n
    return cont(expect(":"), pattern, maybeAssign);\n
  }\n
  function maybeAssign(_type, value) {\n
    if (value == "=") return cont(expressionNoComma);\n
  }\n
  function vardefCont(type) {\n
    if (type == ",") return cont(vardef);\n
  }\n
  function maybeelse(type, value) {\n
    if (type == "keyword b" && value == "else") return cont(pushlex("form", "else"), statement, poplex);\n
  }\n
  function forspec(type) {\n
    if (type == "(") return cont(pushlex(")"), forspec1, expect(")"), poplex);\n
  }\n
  function forspec1(type) {\n
    if (type == "var") return cont(vardef, expect(";"), forspec2);\n
    if (type == ";") return cont(forspec2);\n
    if (type == "variable") return cont(formaybeinof);\n
    return pass(expression, expect(";"), forspec2);\n
  }\n
  function formaybeinof(_type, value) {\n
    if (value == "in" || value == "of") { cx.marked = "keyword"; return cont(expression); }\n
    return cont(maybeoperatorComma, forspec2);\n
  }\n
  function forspec2(type, value) {\n
    if (type == ";") return cont(forspec3);\n
    if (value == "in" || value == "of") { cx.marked = "keyword"; return cont(expression); }\n
    return pass(expression, expect(";"), forspec3);\n
  }\n
  function forspec3(type) {\n
    if (type != ")") cont(expression);\n
  }\n
  function functiondef(type, value) {\n
    if (value == "*") {cx.marked = "keyword"; return cont(functiondef);}\n
    if (type == "variable") {register(value); return cont(functiondef);}\n
    if (type == "(") return cont(pushcontext, pushlex(")"), commasep(funarg, ")"), poplex, statement, popcontext);\n
  }\n
  function funarg(type) {\n
    if (type == "spread") return cont(funarg);\n
    return pass(pattern, maybetype, maybedefault);\n
  }\n
  function className(type, value) {\n
    if (type == "variable") {register(value); return cont(classNameAfter);}\n
  }\n
  function classNameAfter(type, value) {\n
    if (value == "extends") return cont(expression, classNameAfter);\n
    if (type == "{") return cont(pushlex("}"), classBody, poplex);\n
  }\n
  function classBody(type, value) {\n
    if (type == "variable" || cx.style == "keyword") {\n
      if (value == "static") {\n
        cx.marked = "keyword";\n
        return cont(classBody);\n
      }\n
      cx.marked = "property";\n
      if (value == "get" || value == "set") return cont(classGetterSetter, functiondef, classBody);\n
      return cont(functiondef, classBody);\n
    }\n
    if (value == "*") {\n
      cx.marked = "keyword";\n
      return cont(classBody);\n
    }\n
    if (type == ";") return cont(classBody);\n
    if (type == "}") return cont();\n
  }\n
  function classGetterSetter(type) {\n
    if (type != "variable") return pass();\n
    cx.marked = "property";\n
    return cont();\n
  }\n
  function afterExport(_type, value) {\n
    if (value == "*") { cx.marked = "keyword"; return cont(maybeFrom, expect(";")); }\n
    if (value == "default") { cx.marked = "keyword"; return cont(expression, expect(";")); }\n
    return pass(statement);\n
  }\n
  function afterImport(type) {\n
    if (type == "string") return cont();\n
    return pass(importSpec, maybeFrom);\n
  }\n
  function importSpec(type, value) {\n
    if (type == "{") return contCommasep(importSpec, "}");\n
    if (type == "variable") register(value);\n
    if (value == "*") cx.marked = "keyword";\n
    return cont(maybeAs);\n
  }\n
  function maybeAs(_type, value) {\n
    if (value == "as") { cx.marked = "keyword"; return cont(importSpec); }\n
  }\n
  function maybeFrom(_type, value) {\n
    if (value == "from") { cx.marked = "keyword"; return cont(expression); }\n
  }\n
  function arrayLiteral(type) {\n
    if (type == "]") return cont();\n
    return pass(expressionNoComma, maybeArrayComprehension);\n
  }\n
  function maybeArrayComprehension(type) {\n
    if (type == "for") return pass(comprehension, expect("]"));\n
    if (type == ",") return cont(commasep(maybeexpressionNoComma, "]"));\n
    return pass(commasep(expressionNoComma, "]"));\n
  }\n
  function comprehension(type) {\n
    if (type == "for") return cont(forspec, comprehension);\n
    if (type == "if") return cont(expression, comprehension);\n
  }\n
\n
  function isContinuedStatement(state, textAfter) {\n
    return state.lastType == "operator" || state.lastType == "," ||\n
      isOperatorChar.test(textAfter.charAt(0)) ||\n
      /[,.]/.test(textAfter.charAt(0));\n
  }\n
\n
  // Interface\n
\n
  return {\n
    startState: function(basecolumn) {\n
      var state = {\n
        tokenize: tokenBase,\n
        lastType: "sof",\n
        cc: [],\n
        lexical: new JSLexical((basecolumn || 0) - indentUnit, 0, "block", false),\n
        localVars: parserConfig.localVars,\n
        context: parserConfig.localVars && {vars: parserConfig.localVars},\n
        indented: 0\n
      };\n
      if (parserConfig.globalVars && typeof parserConfig.globalVars == "object")\n
        state.globalVars = parserConfig.globalVars;\n
      return state;\n
    },\n
\n
    token: function(stream, state) {\n
      if (stream.sol()) {\n
        if (!state.lexical.hasOwnProperty("align"))\n
          state.lexical.align = false;\n
        state.indented = stream.indentation();\n
        findFatArrow(stream, state);\n
      }\n
      if (state.tokenize != tokenComment && stream.eatSpace()) return null;\n
      var style = state.tokenize(stream, state);\n
      if (type == "comment") return style;\n
      state.lastType = type == "operator" && (content == "++" || content == "--") ? "incdec" : type;\n
      return parseJS(state, style, type, content, stream);\n
    },\n
\n
    indent: function(state, textAfter) {\n
      if (state.tokenize == tokenComment) return CodeMirror.Pass;\n
      if (state.tokenize != tokenBase) return 0;\n
      var firstChar = textAfter && textAfter.charAt(0), lexical = state.lexical;\n
      // Kludge to prevent \'maybelse\' from blocking lexical scope pops\n
      if (!/^\\s*else\\b/.test(textAfter)) for (var i = state.cc.length - 1; i >= 0; --i) {\n
        var c = state.cc[i];\n
        if (c == poplex) lexical = lexical.prev;\n
        else if (c != maybeelse) break;\n
      }\n
      if (lexical.type == "stat" && firstChar == "}") lexical = lexical.prev;\n
      if (statementIndent && lexical.type == ")" && lexical.prev.type == "stat")\n
        lexical = lexical.prev;\n
      var type = lexical.type, closing = firstChar == type;\n
\n
      if (type == "vardef") return lexical.indented + (state.lastType == "operator" || state.lastType == "," ? lexical.info + 1 : 0);\n
      else if (type == "form" && firstChar == "{") return lexical.indented;\n
      else if (type == "form") return lexical.indented + indentUnit;\n
      else if (type == "stat")\n
        return lexical.indented + (isContinuedStatement(state, textAfter) ? statementIndent || indentUnit : 0);\n
      else if (lexical.info == "switch" && !closing && parserConfig.doubleIndentSwitch != false)\n
        return lexical.indented + (/^(?:case|default)\\b/.test(textAfter) ? indentUnit : 2 * indentUnit);\n
      else if (lexical.align) return lexical.column + (closing ? 0 : 1);\n
      else return lexical.indented + (closing ? 0 : indentUnit);\n
    },\n
\n
    electricInput: /^\\s*(?:case .*?:|default:|\\{|\\})$/,\n
    blockCommentStart: jsonMode ? null : "/*",\n
    blockCommentEnd: jsonMode ? null : "*/",\n
    lineComment: jsonMode ? null : "//",\n
    fold: "brace",\n
    closeBrackets: "()[]{}\'\'\\"\\"``",\n
\n
    helperType: jsonMode ? "json" : "javascript",\n
    jsonldMode: jsonldMode,\n
    jsonMode: jsonMode\n
  };\n
});\n
\n
CodeMirror.registerHelper("wordChars", "javascript", /[\\w$]/);\n
\n
CodeMirror.defineMIME("text/javascript", "javascript");\n
CodeMirror.defineMIME("text/ecmascript", "javascript");\n
CodeMirror.defineMIME("application/javascript", "javascript");\n
CodeMirror.defineMIME("application/x-javascript", "javascript");\n
CodeMirror.defineMIME("application/ecmascript", "javascript");\n
CodeMirror.defineMIME("application/json", {name: "javascript", json: true});\n
CodeMirror.defineMIME("application/x-json", {name: "javascript", json: true});\n
CodeMirror.defineMIME("application/ld+json", {name: "javascript", jsonld: true});\n
CodeMirror.defineMIME("text/typescript", { name: "javascript", typescript: true });\n
CodeMirror.defineMIME("application/typescript", { name: "javascript", typescript: true });\n
\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>CodeMirror Mode Javascript</string> </value>
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
                        <float>1406898405.79</float>
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
                <value> <string>948.28968.29478.7014</string> </value>
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
                        <float>1453133668.22</float>
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
                        <float>1405589294.22</float>
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
