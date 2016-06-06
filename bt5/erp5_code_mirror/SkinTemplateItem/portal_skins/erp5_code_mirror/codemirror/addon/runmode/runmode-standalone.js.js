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
            <value> <string>ts21897122.07</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>runmode-standalone.js</string> </value>
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
window.CodeMirror = {};\n
\n
(function() {\n
"use strict";\n
\n
function splitLines(string){ return string.split(/\\r?\\n|\\r/); };\n
\n
function StringStream(string) {\n
  this.pos = this.start = 0;\n
  this.string = string;\n
  this.lineStart = 0;\n
}\n
StringStream.prototype = {\n
  eol: function() {return this.pos >= this.string.length;},\n
  sol: function() {return this.pos == 0;},\n
  peek: function() {return this.string.charAt(this.pos) || null;},\n
  next: function() {\n
    if (this.pos < this.string.length)\n
      return this.string.charAt(this.pos++);\n
  },\n
  eat: function(match) {\n
    var ch = this.string.charAt(this.pos);\n
    if (typeof match == "string") var ok = ch == match;\n
    else var ok = ch && (match.test ? match.test(ch) : match(ch));\n
    if (ok) {++this.pos; return ch;}\n
  },\n
  eatWhile: function(match) {\n
    var start = this.pos;\n
    while (this.eat(match)){}\n
    return this.pos > start;\n
  },\n
  eatSpace: function() {\n
    var start = this.pos;\n
    while (/[\\s\\u00a0]/.test(this.string.charAt(this.pos))) ++this.pos;\n
    return this.pos > start;\n
  },\n
  skipToEnd: function() {this.pos = this.string.length;},\n
  skipTo: function(ch) {\n
    var found = this.string.indexOf(ch, this.pos);\n
    if (found > -1) {this.pos = found; return true;}\n
  },\n
  backUp: function(n) {this.pos -= n;},\n
  column: function() {return this.start - this.lineStart;},\n
  indentation: function() {return 0;},\n
  match: function(pattern, consume, caseInsensitive) {\n
    if (typeof pattern == "string") {\n
      var cased = function(str) {return caseInsensitive ? str.toLowerCase() : str;};\n
      var substr = this.string.substr(this.pos, pattern.length);\n
      if (cased(substr) == cased(pattern)) {\n
        if (consume !== false) this.pos += pattern.length;\n
        return true;\n
      }\n
    } else {\n
      var match = this.string.slice(this.pos).match(pattern);\n
      if (match && match.index > 0) return null;\n
      if (match && consume !== false) this.pos += match[0].length;\n
      return match;\n
    }\n
  },\n
  current: function(){return this.string.slice(this.start, this.pos);},\n
  hideFirstChars: function(n, inner) {\n
    this.lineStart += n;\n
    try { return inner(); }\n
    finally { this.lineStart -= n; }\n
  }\n
};\n
CodeMirror.StringStream = StringStream;\n
\n
CodeMirror.startState = function (mode, a1, a2) {\n
  return mode.startState ? mode.startState(a1, a2) : true;\n
};\n
\n
var modes = CodeMirror.modes = {}, mimeModes = CodeMirror.mimeModes = {};\n
CodeMirror.defineMode = function (name, mode) {\n
  if (arguments.length > 2)\n
    mode.dependencies = Array.prototype.slice.call(arguments, 2);\n
  modes[name] = mode;\n
};\n
CodeMirror.defineMIME = function (mime, spec) { mimeModes[mime] = spec; };\n
CodeMirror.resolveMode = function(spec) {\n
  if (typeof spec == "string" && mimeModes.hasOwnProperty(spec)) {\n
    spec = mimeModes[spec];\n
  } else if (spec && typeof spec.name == "string" && mimeModes.hasOwnProperty(spec.name)) {\n
    spec = mimeModes[spec.name];\n
  }\n
  if (typeof spec == "string") return {name: spec};\n
  else return spec || {name: "null"};\n
};\n
CodeMirror.getMode = function (options, spec) {\n
  spec = CodeMirror.resolveMode(spec);\n
  var mfactory = modes[spec.name];\n
  if (!mfactory) throw new Error("Unknown mode: " + spec);\n
  return mfactory(options, spec);\n
};\n
CodeMirror.registerHelper = CodeMirror.registerGlobalHelper = Math.min;\n
CodeMirror.defineMode("null", function() {\n
  return {token: function(stream) {stream.skipToEnd();}};\n
});\n
CodeMirror.defineMIME("text/plain", "null");\n
\n
CodeMirror.runMode = function (string, modespec, callback, options) {\n
  var mode = CodeMirror.getMode({ indentUnit: 2 }, modespec);\n
\n
  if (callback.nodeType == 1) {\n
    var tabSize = (options && options.tabSize) || 4;\n
    var node = callback, col = 0;\n
    node.innerHTML = "";\n
    callback = function (text, style) {\n
      if (text == "\\n") {\n
        node.appendChild(document.createElement("br"));\n
        col = 0;\n
        return;\n
      }\n
      var content = "";\n
      // replace tabs\n
      for (var pos = 0; ;) {\n
        var idx = text.indexOf("\\t", pos);\n
        if (idx == -1) {\n
          content += text.slice(pos);\n
          col += text.length - pos;\n
          break;\n
        } else {\n
          col += idx - pos;\n
          content += text.slice(pos, idx);\n
          var size = tabSize - col % tabSize;\n
          col += size;\n
          for (var i = 0; i < size; ++i) content += " ";\n
          pos = idx + 1;\n
        }\n
      }\n
\n
      if (style) {\n
        var sp = node.appendChild(document.createElement("span"));\n
        sp.className = "cm-" + style.replace(/ +/g, " cm-");\n
        sp.appendChild(document.createTextNode(content));\n
      } else {\n
        node.appendChild(document.createTextNode(content));\n
      }\n
    };\n
  }\n
\n
  var lines = splitLines(string), state = (options && options.state) || CodeMirror.startState(mode);\n
  for (var i = 0, e = lines.length; i < e; ++i) {\n
    if (i) callback("\\n");\n
    var stream = new CodeMirror.StringStream(lines[i]);\n
    if (!stream.string && mode.blankLine) mode.blankLine(state);\n
    while (!stream.eol()) {\n
      var style = mode.token(stream, state);\n
      callback(stream.current(), style, i, stream.start, state);\n
      stream.start = stream.pos;\n
    }\n
  }\n
};\n
})();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>5302</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
