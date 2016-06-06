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
            <value> <string>ts83646620.4</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-language_tools.js</string> </value>
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
define(\'ace/ext/language_tools\', [\'require\', \'exports\', \'module\' , \'ace/snippets\', \'ace/autocomplete\', \'ace/config\', \'ace/autocomplete/text_completer\', \'ace/editor\'], function(require, exports, module) {\n
\n
\n
var snippetManager = require("../snippets").snippetManager;\n
var Autocomplete = require("../autocomplete").Autocomplete;\n
var config = require("../config");\n
\n
var textCompleter = require("../autocomplete/text_completer");\n
var keyWordCompleter = {\n
    getCompletions: function(editor, session, pos, prefix, callback) {\n
        var state = editor.session.getState(pos.row);\n
        var completions = session.$mode.getCompletions(state, session, pos, prefix);\n
        callback(null, completions);\n
    }\n
};\n
\n
var snippetCompleter = {\n
    getCompletions: function(editor, session, pos, prefix, callback) {\n
        var scope = snippetManager.$getScope(editor);\n
        var snippetMap = snippetManager.snippetMap;\n
        var completions = [];\n
        [scope, "_"].forEach(function(scope) {\n
            var snippets = snippetMap[scope] || [];\n
            for (var i = snippets.length; i--;) {\n
                var s = snippets[i];\n
                var caption = s.name || s.tabTrigger;\n
                if (!caption)\n
                    continue;\n
                completions.push({\n
                    caption: caption,\n
                    snippet: s.content,\n
                    meta: s.tabTrigger && !s.name ? s.tabTrigger + "\\u21E5 " : "snippet"\n
                });\n
            }\n
        }, this);\n
        callback(null, completions);\n
    }\n
};\n
\n
var completers = [snippetCompleter, textCompleter, keyWordCompleter];\n
exports.addCompleter = function(completer) {\n
    completers.push(completer);\n
};\n
\n
var expandSnippet = {\n
    name: "expandSnippet",\n
    exec: function(editor) {\n
        var success = snippetManager.expandWithTab(editor);\n
        if (!success)\n
            editor.execCommand("indent");\n
    },\n
    bindKey: "tab"\n
}\n
\n
var onChangeMode = function(e, editor) {\n
    var mode = editor.session.$mode;\n
    var id = mode.$id\n
    if (!snippetManager.files) snippetManager.files = {};\n
    if (id && !snippetManager.files[id]) {\n
        var snippetFilePath = id.replace("mode", "snippets");\n
        config.loadModule(snippetFilePath, function(m) {\n
            if (m) {\n
                snippetManager.files[id] = m;\n
                m.snippets = snippetManager.parseSnippetFile(m.snippetText);\n
                snippetManager.register(m.snippets, m.scope);\n
            }\n
        });\n
    }\n
};\n
\n
var Editor = require("../editor").Editor;\n
require("../config").defineOptions(Editor.prototype, "editor", {\n
    enableBasicAutocompletion: {\n
        set: function(val) {\n
            if (val) {\n
                this.completers = completers\n
                this.commands.addCommand(Autocomplete.startCommand);\n
            } else {\n
                this.commands.removeCommand(Autocomplete.startCommand);\n
            }\n
        },\n
        value: false\n
    },\n
    enableSnippets: {\n
        set: function(val) {\n
            if (val) {\n
                this.commands.addCommand(expandSnippet);\n
                this.on("changeMode", onChangeMode);\n
                onChangeMode(null, this)\n
            } else {\n
                this.commands.removeCommand(expandSnippet);\n
                this.off("changeMode", onChangeMode);\n
            }\n
        },\n
        value: false\n
    }\n
});\n
\n
});\n
\n
define(\'ace/snippets\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/range\', \'ace/keyboard/hash_handler\', \'ace/tokenizer\', \'ace/lib/dom\'], function(require, exports, module) {\n
\n
var lang = require("./lib/lang")\n
var Range = require("./range").Range\n
var HashHandler = require("./keyboard/hash_handler").HashHandler;\n
var Tokenizer = require("./tokenizer").Tokenizer;\n
var comparePoints = Range.comparePoints;\n
\n
var SnippetManager = function() {\n
    this.snippetMap = {};\n
    this.snippetNameMap = {};\n
};\n
\n
(function() {\n
    this.getTokenizer = function() {\n
        function TabstopToken(str, _, stack) {\n
            str = str.substr(1);\n
            if (/^\\d+$/.test(str) && !stack.inFormatString)\n
                return [{tabstopId: parseInt(str, 10)}];\n
            return [{text: str}]\n
        }\n
        function escape(ch) {\n
            return "(?:[^\\\\\\\\" + ch + "]|\\\\\\\\.)";\n
        }\n
        SnippetManager.$tokenizer = new Tokenizer({\n
            start: [\n
                {regex: /:/, onMatch: function(val, state, stack) {\n
                    if (stack.length && stack[0].expectIf) {\n
                        stack[0].expectIf = false;\n
                        stack[0].elseBranch = stack[0];\n
                        return [stack[0]];\n
                    }\n
                    return ":";\n
                }},\n
                {regex: /\\\\./, onMatch: function(val, state, stack) {\n
                    var ch = val[1];\n
                    if (ch == "}" && stack.length) {\n
                        val = ch;\n
                    }else if ("`$\\\\".indexOf(ch) != -1) {\n
                        val = ch;\n
                    } else if (stack.inFormatString) {\n
                        if (ch == "n")\n
                            val = "\\n";\n
                        else if (ch == "t")\n
                            val = "\\n";\n
                        else if ("ulULE".indexOf(ch) != -1) {\n
                            val = {changeCase: ch, local: ch > "a"};\n
                        }\n
                    }\n
\n
                    return [val];\n
                }},\n
                {regex: /}/, onMatch: function(val, state, stack) {\n
                    return [stack.length ? stack.shift() : val];\n
                }},\n
                {regex: /\\$(?:\\d+|\\w+)/, onMatch: TabstopToken},\n
                {regex: /\\$\\{[\\dA-Z_a-z]+/, onMatch: function(str, state, stack) {\n
                    var t = TabstopToken(str.substr(1), state, stack);\n
                    stack.unshift(t[0]);\n
                    return t;\n
                }, next: "snippetVar"},\n
                {regex: /\\n/, token: "newline", merge: false}\n
            ],\n
            snippetVar: [\n
                {regex: "\\\\|" + escape("\\\\|") + "*\\\\|", onMatch: function(val, state, stack) {\n
                    stack[0].choices = val.slice(1, -1).split(",");\n
                }, next: "start"},\n
                {regex: "/(" + escape("/") + "+)/(?:(" + escape("/") + "*)/)(\\\\w*):?",\n
                 onMatch: function(val, state, stack) {\n
                    var ts = stack[0];\n
                    ts.fmtString = val;\n
\n
                    val = this.splitRegex.exec(val);\n
                    ts.guard = val[1];\n
                    ts.fmt = val[2];\n
                    ts.flag = val[3];\n
                    return "";\n
                }, next: "start"},\n
                {regex: "`" + escape("`") + "*`", onMatch: function(val, state, stack) {\n
                    stack[0].code = val.splice(1, -1);\n
                    return "";\n
                }, next: "start"},\n
                {regex: "\\\\?", onMatch: function(val, state, stack) {\n
                    if (stack[0])\n
                        stack[0].expectIf = true;\n
                }, next: "start"},\n
                {regex: "([^:}\\\\\\\\]|\\\\\\\\.)*:?", token: "", next: "start"}\n
            ],\n
            formatString: [\n
                {regex: "/(" + escape("/") + "+)/", token: "regex"},\n
                {regex: "", onMatch: function(val, state, stack) {\n
                    stack.inFormatString = true;\n
                }, next: "start"}\n
            ]\n
        });\n
        SnippetManager.prototype.getTokenizer = function() {\n
            return SnippetManager.$tokenizer;\n
        }\n
        return SnippetManager.$tokenizer;\n
    };\n
\n
    this.tokenizeTmSnippet = function(str, startState) {\n
        return this.getTokenizer().getLineTokens(str, startState).tokens.map(function(x) {\n
            return x.value || x;\n
        });\n
    };\n
\n
    this.$getDefaultValue = function(editor, name) {\n
        if (/^[A-Z]\\d+$/.test(name)) {\n
            var i = name.substr(1);\n
            return (this.variables[name[0] + "__"] || {})[i];\n
        }\n
        if (/^\\d+$/.test(name)) {\n
            return (this.variables.__ || {})[name];\n
        }\n
        name = name.replace(/^TM_/, "");\n
\n
        if (!editor)\n
            return;\n
        var s = editor.session;\n
        switch(name) {\n
            case "CURRENT_WORD":\n
                var r = s.getWordRange();\n
            case "SELECTION":\n
            case "SELECTED_TEXT":\n
                return s.getTextRange(r);\n
            case "CURRENT_LINE":\n
                return s.getLine(editor.getCursorPosition().row);\n
            case "PREV_LINE": // not possible in textmate\n
                return s.getLine(editor.getCursorPosition().row - 1);\n
            case "LINE_INDEX":\n
                return editor.getCursorPosition().column;\n
            case "LINE_NUMBER":\n
                return editor.getCursorPosition().row + 1;\n
            case "SOFT_TABS":\n
                return s.getUseSoftTabs() ? "YES" : "NO";\n
            case "TAB_SIZE":\n
                return s.getTabSize();\n
            case "FILENAME":\n
            case "FILEPATH":\n
                return "ace.ajax.org";\n
            case "FULLNAME":\n
                return "Ace";\n
        }\n
    };\n
    this.variables = {};\n
    this.getVariableValue = function(editor, varName) {\n
        if (this.variables.hasOwnProperty(varName))\n
            return this.variables[varName](editor, varName) || "";\n
        return this.$getDefaultValue(editor, varName) || "";\n
    };\n
    this.tmStrFormat = function(str, ch, editor) {\n
        var flag = ch.flag || "";\n
        var re = ch.guard;\n
        re = new RegExp(re, flag.replace(/[^gi]/, ""));\n
        var fmtTokens = this.tokenizeTmSnippet(ch.fmt, "formatString");\n
        var _self = this;\n
        var formatted = str.replace(re, function() {\n
            _self.variables.__ = arguments;\n
            var fmtParts = _self.resolveVariables(fmtTokens, editor);\n
            var gChangeCase = "E";\n
            for (var i  = 0; i < fmtParts.length; i++) {\n
                var ch = fmtParts[i];\n
                if (typeof ch == "object") {\n
                    fmtParts[i] = "";\n
                    if (ch.changeCase && ch.local) {\n
                        var next = fmtParts[i + 1];\n
                        if (next && typeof next == "string") {\n
                            if (ch.changeCase == "u")\n
                                fmtParts[i] = next[0].toUpperCase();\n
                            else\n
                                fmtParts[i] = next[0].toLowerCase();\n
                            fmtParts[i + 1] = next.substr(1);\n
                        }\n
                    } else if (ch.changeCase) {\n
                        gChangeCase = ch.changeCase;\n
                    }\n
                } else if (gChangeCase == "U") {\n
                    fmtParts[i] = ch.toUpperCase();\n
                } else if (gChangeCase == "L") {\n
                    fmtParts[i] = ch.toLowerCase();\n
                }\n
            }\n
            return fmtParts.join("");\n
        });\n
        this.variables.__ = null;\n
        return formatted;\n
    };\n
\n
    this.resolveVariables = function(snippet, editor) {\n
        var result = [];\n
        for (var i = 0; i < snippet.length; i++) {\n
            var ch = snippet[i];\n
            if (typeof ch == "string") {\n
                result.push(ch);\n
            } else if (typeof ch != "object") {\n
                continue;\n
            } else if (ch.skip) {\n
                gotoNext(ch);\n
            } else if (ch.processed < i) {\n
                continue;\n
            } else if (ch.text) {\n
                var value = this.getVariableValue(editor, ch.text);\n
                if (value && ch.fmtString)\n
                    value = this.tmStrFormat(value, ch);\n
                ch.processed = i;\n
                if (ch.expectIf == null) {\n
                    if (value) {\n
                        result.push(value);\n
                        gotoNext(ch);\n
                    }\n
                } else {\n
                    if (value) {\n
                        ch.skip = ch.elseBranch;\n
                    } else\n
                        gotoNext(ch);\n
                }\n
            } else if (ch.tabstopId != null) {\n
                result.push(ch);\n
            } else if (ch.changeCase != null) {\n
                result.push(ch);\n
            }\n
        }\n
        function gotoNext(ch) {\n
            var i1 = snippet.indexOf(ch, i + 1);\n
            if (i1 != -1)\n
                i = i1;\n
        }\n
        return result;\n
    };\n
\n
    this.insertSnippet = function(editor, snippetText) {\n
        var cursor = editor.getCursorPosition();\n
        var line = editor.session.getLine(cursor.row);\n
        var indentString = line.match(/^\\s*/)[0];\n
        var tabString = editor.session.getTabString();\n
\n
        var tokens = this.tokenizeTmSnippet(snippetText);\n
        tokens = this.resolveVariables(tokens, editor);\n
        tokens = tokens.map(function(x) {\n
            if (x == "\\n")\n
                return x + indentString;\n
            if (typeof x == "string")\n
                return x.replace(/\\t/g, tabString);\n
            return x;\n
        });\n
        var tabstops = [];\n
        tokens.forEach(function(p, i) {\n
            if (typeof p != "object")\n
                return;\n
            var id = p.tabstopId;\n
            var ts = tabstops[id];\n
            if (!ts) {\n
                ts = tabstops[id] = [];\n
                ts.index = id;\n
                ts.value = "";\n
            }\n
            if (ts.indexOf(p) !== -1)\n
                return;\n
            ts.push(p);\n
            var i1 = tokens.indexOf(p, i + 1);\n
            if (i1 === -1)\n
                return;\n
\n
            var value = tokens.slice(i + 1, i1);\n
            var isNested = value.some(function(t) {return typeof t === "object"});          \n
            if (isNested && !ts.value) {\n
                ts.value = value;\n
            } else if (value.length && (!ts.value || typeof ts.value !== "string")) {\n
                ts.value = value.join("");\n
            }\n
        });\n
        tabstops.forEach(function(ts) {ts.length = 0});\n
        var expanding = {};\n
        function copyValue(val) {\n
            var copy = []\n
            for (var i = 0; i < val.length; i++) {\n
                var p = val[i];\n
                if (typeof p == "object") {\n
                    if (expanding[p.tabstopId])\n
                        continue;\n
                    var j = val.lastIndexOf(p, i - 1);\n
                    p = copy[j] || {tabstopId: p.tabstopId};\n
                }\n
                copy[i] = p;\n
            }\n
            return copy;\n
        }\n
        for (var i = 0; i < tokens.length; i++) {\n
            var p = tokens[i];\n
            if (typeof p != "object")\n
                continue;\n
            var id = p.tabstopId;\n
            var i1 = tokens.indexOf(p, i + 1);\n
            if (expanding[id] == p) { \n
                expanding[id] = null;\n
                continue;\n
            }\n
            \n
            var ts = tabstops[id];\n
            var arg = typeof ts.value == "string" ? [ts.value] : copyValue(ts.value);\n
            arg.unshift(i + 1, Math.max(0, i1 - i));\n
            arg.push(p);\n
            expanding[id] = p;\n
            tokens.splice.apply(tokens, arg);\n
\n
            if (ts.indexOf(p) === -1)\n
                ts.push(p);\n
        };\n
        var row = 0, column = 0;\n
        var text = "";\n
        tokens.forEach(function(t) {\n
            if (typeof t === "string") {\n
                if (t[0] === "\\n"){\n
                    column = t.length - 1;\n
                    row ++;\n
                } else\n
                    column += t.length;\n
                text += t;\n
            } else {\n
                if (!t.start)\n
                    t.start = {row: row, column: column};\n
                else\n
                    t.end = {row: row, column: column};\n
            }\n
        });\n
        var range = editor.getSelectionRange();\n
        var end = editor.session.replace(range, text);\n
\n
        var tabstopManager = new TabstopManager(editor);\n
        tabstopManager.addTabstops(tabstops, range.start, end);\n
        tabstopManager.tabNext();\n
    };\n
\n
    this.$getScope = function(editor) {\n
        var scope = editor.session.$mode.$id || "";\n
        scope = scope.split("/").pop();\n
        if (scope === "html" || scope === "php") {\n
            if (scope === "php") \n
                scope = "html";\n
            var c = editor.getCursorPosition()\n
            var state = editor.session.getState(c.row);\n
            if (typeof state === "object") {\n
                state = state[0];\n
            }\n
            if (state.substring) {\n
                if (state.substring(0, 3) == "js-")\n
                    scope = "javascript";\n
                else if (state.substring(0, 4) == "css-")\n
                    scope = "css";\n
                else if (state.substring(0, 4) == "php-")\n
                    scope = "php";\n
            }\n
        }\n
        \n
        return scope;\n
    };\n
\n
    this.expandWithTab = function(editor) {\n
        var cursor = editor.getCursorPosition();\n
        var line = editor.session.getLine(cursor.row);\n
        var before = line.substring(0, cursor.column);\n
        var after = line.substr(cursor.column);\n
\n
        var scope = this.$getScope(editor);\n
        var snippetMap = this.snippetMap;\n
        var snippet;\n
        [scope, "_"].some(function(scope) {\n
            var snippets = snippetMap[scope];\n
            if (snippets)\n
                snippet = this.findMatchingSnippet(snippets, before, after);\n
            return !!snippet;\n
        }, this);\n
        if (!snippet)\n
            return false;\n
\n
        editor.session.doc.removeInLine(cursor.row,\n
            cursor.column - snippet.replaceBefore.length,\n
            cursor.column + snippet.replaceAfter.length\n
        );\n
\n
        this.variables.M__ = snippet.matchBefore;\n
        this.variables.T__ = snippet.matchAfter;\n
        this.insertSnippet(editor, snippet.content);\n
\n
        this.variables.M__ = this.variables.T__ = null;\n
        return true;\n
    };\n
\n
    this.findMatchingSnippet = function(snippetList, before, after) {\n
        for (var i = snippetList.length; i--;) {\n
            var s = snippetList[i];\n
            if (s.startRe && !s.startRe.test(before))\n
                continue;\n
            if (s.endRe && !s.endRe.test(after))\n
                continue;\n
            if (!s.startRe && !s.endRe)\n
                continue;\n
\n
            s.matchBefore = s.startRe ? s.startRe.exec(before) : [""];\n
            s.matchAfter = s.endRe ? s.endRe.exec(after) : [""];\n
            s.replaceBefore = s.triggerRe ? s.triggerRe.exec(before)[0] : "";\n
            s.replaceAfter = s.endTriggerRe ? s.endTriggerRe.exec(after)[0] : "";\n
            return s;\n
        }\n
    };\n
\n
    this.snippetMap = {};\n
    this.snippetNameMap = {};\n
    this.register = function(snippets, scope) {\n
        var snippetMap = this.snippetMap;\n
        var snippetNameMap = this.snippetNameMap;\n
        var self = this;\n
        function wrapRegexp(src) {\n
            if (src && !/^\\^?\\(.*\\)\\$?$|^\\\\b$/.test(src))\n
                src = "(?:" + src + ")"\n
\n
            return src || "";\n
        }\n
        function guardedRegexp(re, guard, opening) {\n
            re = wrapRegexp(re);\n
            guard = wrapRegexp(guard);\n
            if (opening) {\n
                re = guard + re;\n
                if (re && re[re.length - 1] != "$")\n
                    re = re + "$";\n
            } else {\n
                re = re + guard;\n
                if (re && re[0] != "^")\n
                    re = "^" + re;\n
            }\n
            return new RegExp(re);\n
        }\n
\n
        function addSnippet(s) {\n
            if (!s.scope)\n
                s.scope = scope || "_";\n
            scope = s.scope\n
            if (!snippetMap[scope]) {\n
                snippetMap[scope] = [];\n
                snippetNameMap[scope] = {};\n
            }\n
\n
            var map = snippetNameMap[scope];\n
            if (s.name) {\n
                var old = map[s.name];\n
                if (old)\n
                    self.unregister(old);\n
                map[s.name] = s;\n
            }\n
            snippetMap[scope].push(s);\n
\n
            if (s.tabTrigger && !s.trigger) {\n
                if (!s.guard && /^\\w/.test(s.tabTrigger))\n
                    s.guard = "\\\\b";\n
                s.trigger = lang.escapeRegExp(s.tabTrigger);\n
            }\n
\n
            s.startRe = guardedRegexp(s.trigger, s.guard, true);\n
            s.triggerRe = new RegExp(s.trigger, "", true);\n
\n
            s.endRe = guardedRegexp(s.endTrigger, s.endGuard, true);\n
            s.endTriggerRe = new RegExp(s.endTrigger, "", true);\n
        };\n
\n
        if (snippets.content)\n
            addSnippet(snippets);\n
        else if (Array.isArray(snippets))\n
            snippets.forEach(addSnippet);\n
    };\n
    this.unregister = function(snippets, scope) {\n
        var snippetMap = this.snippetMap;\n
        var snippetNameMap = this.snippetNameMap;\n
\n
        function removeSnippet(s) {\n
            var nameMap = snippetNameMap[s.scope||scope];\n
            if (nameMap && nameMap[s.name]) {\n
                delete nameMap[s.name];\n
                var map = snippetMap[s.scope||scope];\n
                var i = map && map.indexOf(s);\n
                if (i >= 0)\n
                    map.splice(i, 1);\n
            }\n
        }\n
        if (snippets.content)\n
            removeSnippet(snippets);\n
        else if (Array.isArray(snippets))\n
            snippets.forEach(removeSnippet);\n
    };\n
    this.parseSnippetFile = function(str) {\n
        str = str.replace(/\\r/g, "");\n
        var list = [], snippet = {};\n
        var re = /^#.*|^({[\\s\\S]*})\\s*$|^(\\S+) (.*)$|^((?:\\n*\\t.*)+)/gm;\n
        var m;\n
        while (m = re.exec(str)) {\n
            if (m[1]) {\n
                try {\n
                    snippet = JSON.parse(m[1])\n
                    list.push(snippet);\n
                } catch (e) {}\n
            } if (m[4]) {\n
                snippet.content = m[4].replace(/^\\t/gm, "");\n
                list.push(snippet);\n
                snippet = {};\n
            } else {\n
                var key = m[2], val = m[3];\n
                if (key == "regex") {\n
                    var guardRe = /\\/((?:[^\\/\\\\]|\\\\.)*)|$/g;\n
                    snippet.guard = guardRe.exec(val)[1];\n
                    snippet.trigger = guardRe.exec(val)[1];\n
                    snippet.endTrigger = guardRe.exec(val)[1];\n
                    snippet.endGuard = guardRe.exec(val)[1];\n
                } else if (key == "snippet") {\n
                    snippet.tabTrigger = val.match(/^\\S*/)[0];\n
                    if (!snippet.name)\n
                        snippet.name = val;\n
                } else {\n
                    snippet[key] = val;\n
                }\n
            }\n
        }\n
        return list;\n
    };\n
    this.getSnippetByName = function(name, editor) {\n
        var scope = editor && this.$getScope(editor);\n
        var snippetMap = this.snippetNameMap;\n
        var snippet;\n
        [scope, "_"].some(function(scope) {\n
            var snippets = snippetMap[scope];\n
            if (snippets)\n
                snippet = snippets[name];\n
            return !!snippet;\n
        }, this);\n
        return snippet;\n
    };\n
\n
}).call(SnippetManager.prototype);\n
\n
\n
var TabstopManager = function(editor) {\n
    if (editor.tabstopManager)\n
        return editor.tabstopManager;\n
    editor.tabstopManager = this;\n
    this.$onChange = this.onChange.bind(this);\n
    this.$onChangeSelection = lang.delayedCall(this.onChangeSelection.bind(this)).schedule;\n
    this.$onChangeSession = this.onChangeSession.bind(this);\n
    this.$onAfterExec = this.onAfterExec.bind(this);\n
    this.attach(editor);\n
};\n
(function() {\n
    this.attach = function(editor) {\n
        this.index = -1;\n
        this.ranges = [];\n
        this.tabstops = [];\n
        this.selectedTabstop = null;\n
\n
        this.editor = editor;\n
        this.editor.on("change", this.$onChange);\n
        this.editor.on("changeSelection", this.$onChangeSelection);\n
        this.editor.on("changeSession", this.$onChangeSession);\n
        this.editor.commands.on("afterExec", this.$onAfterExec);\n
        this.editor.keyBinding.addKeyboardHandler(this.keyboardHandler);\n
    };\n
    this.detach = function() {\n
        this.tabstops.forEach(this.removeTabstopMarkers, this);\n
        this.ranges = null;\n
        this.tabstops = null;\n
        this.selectedTabstop = null;\n
        this.editor.removeListener("change", this.$onChange);\n
        this.editor.removeListener("changeSelection", this.$onChangeSelection);\n
        this.editor.removeListener("changeSession", this.$onChangeSession);\n
        this.editor.commands.removeListener("afterExec", this.$onAfterExec);\n
        this.editor.keyBinding.removeKeyboardHandler(this.keyboardHandler);\n
        this.editor.tabstopManager = null;\n
        this.editor = null;\n
    };\n
\n
    this.onChange = function(e) {\n
        var changeRange = e.data.range;\n
        var isRemove = e.data.action[0] == "r";\n
        var start = changeRange.start;\n
        var end = changeRange.end;\n
        var startRow = start.row;\n
        var endRow = end.row;\n
        var lineDif = endRow - startRow;\n
        var colDiff = end.column - start.column;\n
\n
        if (isRemove) {\n
            lineDif = -lineDif;\n
            colDiff = -colDiff;\n
        }\n
        if (!this.$inChange && isRemove) {\n
            var ts = this.selectedTabstop;\n
            var changedOutside = !ts.some(function(r) {\n
                return comparePoints(r.start, start) <= 0 && comparePoints(r.end, end) >= 0;\n
            });\n
            if (changedOutside)\n
                return this.detach();\n
        }\n
        var ranges = this.ranges;\n
        for (var i = 0; i < ranges.length; i++) {\n
            var r = ranges[i];\n
            if (r.end.row < start.row)\n
                continue;\n
\n
            if (comparePoints(start, r.start) < 0 && comparePoints(end, r.end) > 0) {\n
                this.removeRange(r);\n
                i--;\n
                continue;\n
            }\n
\n
            if (r.start.row == startRow && r.start.column > start.column)\n
                r.start.column += colDiff;\n
            if (r.end.row == startRow && r.end.column >= start.column)\n
                r.end.column += colDiff;\n
            if (r.start.row >= startRow)\n
                r.start.row += lineDif;\n
            if (r.end.row >= startRow)\n
                r.end.row += lineDif;\n
\n
            if (comparePoints(r.start, r.end) > 0)\n
                this.removeRange(r);\n
        }\n
        if (!ranges.length)\n
            this.detach();\n
    };\n
    this.updateLinkedFields = function() {\n
        var ts = this.selectedTabstop;\n
        if (!ts.hasLinkedRanges)\n
            return;\n
        this.$inChange = true;\n
        var session = this.editor.session;\n
        var text = session.getTextRange(ts.firstNonLinked);\n
        for (var i = ts.length; i--;) {\n
            var range = ts[i];\n
            if (!range.linked)\n
                continue;\n
            var fmt = exports.snippetManager.tmStrFormat(text, range.original)\n
            session.replace(range, fmt);\n
        }\n
        this.$inChange = false;\n
    };\n
    this.onAfterExec = function(e) {\n
        if (e.command && !e.command.readOnly)\n
            this.updateLinkedFields();\n
    };\n
    this.onChangeSelection = function() {\n
        if (!this.editor)\n
            return\n
        var lead = this.editor.selection.lead;\n
        var anchor = this.editor.selection.anchor;\n
        var isEmpty = this.editor.selection.isEmpty();\n
        for (var i = this.ranges.length; i--;) {\n
            if (this.ranges[i].linked)\n
                continue;\n
            var containsLead = this.ranges[i].contains(lead.row, lead.column);\n
            var containsAnchor = isEmpty || this.ranges[i].contains(anchor.row, anchor.column);\n
            if (containsLead && containsAnchor)\n
                return;\n
        }\n
        this.detach();\n
    };\n
    this.onChangeSession = function() {\n
        this.detach();\n
    };\n
    this.tabNext = function(dir) {\n
        var max = this.tabstops.length - 1;\n
        var index = this.index + (dir || 1);\n
        index = Math.min(Math.max(index, 0), max);\n
        this.selectTabstop(index);\n
        if (index == max)\n
            this.detach();\n
    };\n
    this.selectTabstop = function(index) {\n
        var ts = this.tabstops[this.index];\n
        if (ts)\n
            this.addTabstopMarkers(ts);\n
        this.index = index;\n
        ts = this.tabstops[this.index];\n
        if (!ts || !ts.length)\n
            return;\n
        \n
        this.selectedTabstop = ts;\n
        if (!this.editor.inVirtualSelectionMode) {        \n
            var sel = this.editor.multiSelect;\n
            sel.toSingleRange(ts.firstNonLinked.clone());\n
            for (var i = ts.length; i--;) {\n
                if (ts.hasLinkedRanges && ts[i].linked)\n
                    continue;\n
                sel.addRange(ts[i].clone(), true);\n
            }\n
        } else {\n
            this.editor.selection.setRange(ts.firstNonLinked);\n
        }\n
        \n
        this.editor.keyBinding.addKeyboardHandler(this.keyboardHandler);\n
    };\n
    this.addTabstops = function(tabstops, start, end) {\n
        if (!tabstops[0]) {\n
            var p = Range.fromPoints(end, end);\n
            moveRelative(p.start, start);\n
            moveRelative(p.end, start);\n
            tabstops[0] = [p];\n
            tabstops[0].index = 0;\n
        }\n
\n
        var i = this.index;\n
        var arg = [i, 0];\n
        var ranges = this.ranges;\n
        var editor = this.editor;\n
        tabstops.forEach(function(ts) {\n
            for (var i = ts.length; i--;) {\n
                var p = ts[i];\n
                var range = Range.fromPoints(p.start, p.end || p.start);\n
                movePoint(range.start, start);\n
                movePoint(range.end, start);\n
                range.original = p;\n
                range.tabstop = ts;\n
                ranges.push(range);\n
                ts[i] = range;\n
                if (p.fmtString) {\n
                    range.linked = true;\n
                    ts.hasLinkedRanges = true;\n
                } else if (!ts.firstNonLinked)\n
                    ts.firstNonLinked = range;\n
            }\n
            if (!ts.firstNonLinked)\n
                ts.hasLinkedRanges = false;\n
            arg.push(ts);\n
            this.addTabstopMarkers(ts);\n
        }, this);\n
        arg.push(arg.splice(2, 1)[0]);\n
        this.tabstops.splice.apply(this.tabstops, arg);\n
    };\n
\n
    this.addTabstopMarkers = function(ts) {\n
        var session = this.editor.session;\n
        ts.forEach(function(range) {\n
            if  (!range.markerId)\n
                range.markerId = session.addMarker(range, "ace_snippet-marker", "text");\n
        });\n
    };\n
    this.removeTabstopMarkers = function(ts) {\n
        var session = this.editor.session;\n
        ts.forEach(function(range) {\n
            session.removeMarker(range.markerId);\n
            range.markerId = null;\n
        });\n
    };\n
    this.removeRange = function(range) {\n
        var i = range.tabstop.indexOf(range);\n
        range.tabstop.splice(i, 1);\n
        i = this.ranges.indexOf(range);\n
        this.ranges.splice(i, 1);\n
        this.editor.session.removeMarker(range.markerId);\n
    };\n
\n
    this.keyboardHandler = new HashHandler();\n
    this.keyboardHandler.bindKeys({\n
        "Tab": function(ed) {\n
            ed.tabstopManager.tabNext(1);\n
        },\n
        "Shift-Tab": function(ed) {\n
            ed.tabstopManager.tabNext(-1);\n
        },\n
        "Esc": function(ed) {\n
            ed.tabstopManager.detach();\n
        },\n
        "Return": function(ed) {\n
            return false;\n
        }\n
    });\n
}).call(TabstopManager.prototype);\n
\n
\n
var movePoint = function(point, diff) {\n
    if (point.row == 0)\n
        point.column += diff.column;\n
    point.row += diff.row;\n
};\n
\n
var moveRelative = function(point, start) {\n
    if (point.row == start.row)\n
        point.column -= start.column;\n
    point.row -= start.row;\n
};\n
\n
\n
require("./lib/dom").importCssString("\\\n
.ace_snippet-marker {\\\n
    -moz-box-sizing: border-box;\\\n
    box-sizing: border-box;\\\n
    background: rgba(194, 193, 208, 0.09);\\\n
    border: 1px dotted rgba(211, 208, 235, 0.62);\\\n
    position: absolute;\\\n
}");\n
\n
exports.snippetManager = new SnippetManager();\n
\n
\n
});\n
\n
define(\'ace/autocomplete\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/hash_handler\', \'ace/autocomplete/popup\', \'ace/autocomplete/util\', \'ace/lib/event\', \'ace/lib/lang\', \'ace/snippets\'], function(require, exports, module) {\n
\n
\n
var HashHandler = require("./keyboard/hash_handler").HashHandler;\n
var AcePopup = require("./autocomplete/popup").AcePopup;\n
var util = require("./autocomplete/util");\n
var event = require("./lib/event");\n
var lang = require("./lib/lang");\n
var snippetManager = require("./snippets").snippetManager;\n
\n
var Autocomplete = function() {\n
    this.keyboardHandler = new HashHandler();\n
    this.keyboardHandler.bindKeys(this.commands);\n
\n
    this.blurListener = this.blurListener.bind(this);\n
    this.changeListener = this.changeListener.bind(this);\n
    this.mousedownListener = this.mousedownListener.bind(this);\n
    this.mousewheelListener = this.mousewheelListener.bind(this);\n
    \n
    this.changeTimer = lang.delayedCall(function() {\n
        this.updateCompletions(true);\n
    }.bind(this))\n
};\n
\n
(function() {\n
    this.$init = function() {\n
        this.popup = new AcePopup(document.body || document.documentElement);\n
        this.popup.on("click", function(e) {\n
            this.insertMatch();\n
            e.stop();\n
        }.bind(this));\n
    };\n
\n
    this.openPopup = function(editor, prefix, keepPopupPosition) {\n
        if (!this.popup)\n
            this.$init();\n
\n
        this.popup.setData(this.completions.filtered);\n
\n
        var renderer = editor.renderer;\n
        if (!keepPopupPosition) {\n
            this.popup.setFontSize(editor.getFontSize());\n
\n
            var lineHeight = renderer.layerConfig.lineHeight;\n
            \n
            var pos = renderer.$cursorLayer.getPixelPosition(this.base, true);            \n
            pos.left -= this.popup.getTextLeftOffset();\n
            \n
            var rect = editor.container.getBoundingClientRect();\n
            pos.top += rect.top - renderer.layerConfig.offset;\n
            pos.left += rect.left;\n
            pos.left += renderer.$gutterLayer.gutterWidth;\n
\n
            this.popup.show(pos, lineHeight);\n
        }\n
    };\n
\n
    this.detach = function() {\n
        this.editor.keyBinding.removeKeyboardHandler(this.keyboardHandler);\n
        this.editor.off("changeSelection", this.changeListener);\n
        this.editor.off("blur", this.changeListener);\n
        this.editor.off("mousedown", this.mousedownListener);\n
        this.editor.off("mousewheel", this.mousewheelListener);\n
        this.changeTimer.cancel();\n
        \n
        if (this.popup)\n
            this.popup.hide();\n
\n
        this.activated = false;\n
        this.completions = this.base = null;\n
    };\n
\n
    this.changeListener = function(e) {\n
        var cursor = this.editor.selection.lead;\n
        if (cursor.row != this.base.row || cursor.column < this.base.column) {\n
            this.detach();\n
        }\n
        if (this.activated)\n
            this.changeTimer.schedule();\n
        else\n
            this.detach();\n
    };\n
\n
    this.blurListener = function() {\n
        if (document.activeElement != this.editor.textInput.getElement())\n
            this.detach();\n
    };\n
\n
    this.mousedownListener = function(e) {\n
        this.detach();\n
    };\n
\n
    this.mousewheelListener = function(e) {\n
        this.detach();\n
    };\n
\n
    this.goTo = function(where) {\n
        var row = this.popup.getRow();\n
        var max = this.popup.session.getLength() - 1;\n
\n
        switch(where) {\n
            case "up": row = row < 0 ? max : row - 1; break;\n
            case "down": row = row >= max ? -1 : row + 1; break;\n
            case "start": row = 0; break;\n
            case "end": row = max; break;\n
        }\n
\n
        this.popup.setRow(row);\n
    };\n
\n
    this.insertMatch = function(data) {\n
        if (!data)\n
            data = this.popup.getData(this.popup.getRow());\n
        if (!data)\n
            return false;\n
        if (data.completer && data.completer.insertMatch) {\n
            data.completer.insertMatch(this.editor);\n
        } else {\n
            if (this.completions.filterText) {\n
                var ranges = this.editor.selection.getAllRanges();\n
                for (var i = 0, range; range = ranges[i]; i++) {\n
                    range.start.column -= this.completions.filterText.length;\n
                    this.editor.session.remove(range);\n
                }\n
            }\n
            if (data.snippet)\n
                snippetManager.insertSnippet(this.editor, data.snippet);\n
            else\n
                this.editor.execCommand("insertstring", data.value || data);\n
        }\n
        this.detach();\n
    };\n
\n
    this.commands = {\n
        "Up": function(editor) { editor.completer.goTo("up"); },\n
        "Down": function(editor) { editor.completer.goTo("down"); },\n
        "Ctrl-Up|Ctrl-Home": function(editor) { editor.completer.goTo("start"); },\n
        "Ctrl-Down|Ctrl-End": function(editor) { editor.completer.goTo("end"); },\n
\n
        "Esc": function(editor) { editor.completer.detach(); },\n
        "Space": function(editor) { editor.completer.detach(); editor.insert(" ");},\n
        "Return": function(editor) { editor.completer.insertMatch(); },\n
        "Shift-Return": function(editor) { editor.completer.insertMatch(true); },\n
        "Tab": function(editor) { editor.completer.insertMatch(); },\n
\n
        "PageUp": function(editor) { editor.completer.popup.gotoPageUp(); },\n
        "PageDown": function(editor) { editor.completer.popup.gotoPageDown(); }\n
    };\n
\n
    this.gatherCompletions = function(editor, callback) {\n
        var session = editor.getSession();\n
        var pos = editor.getCursorPosition();\n
        \n
        var line = session.getLine(pos.row);\n
        var prefix = util.retrievePrecedingIdentifier(line, pos.column);\n
        \n
        this.base = editor.getCursorPosition();\n
        this.base.column -= prefix.length;\n
\n
        var matches = [];\n
        util.parForEach(editor.completers, function(completer, next) {\n
            completer.getCompletions(editor, session, pos, prefix, function(err, results) {\n
                if (!err)\n
                    matches = matches.concat(results);\n
                next();\n
            });\n
        }, function() {\n
            callback(null, {\n
                prefix: prefix,\n
                matches: matches\n
            });\n
        });\n
        return true;\n
    };\n
\n
    this.showPopup = function(editor) {\n
        if (this.editor)\n
            this.detach();\n
        \n
        this.activated = true;\n
\n
        this.editor = editor;\n
        if (editor.completer != this) {\n
            if (editor.completer)\n
                editor.completer.detach();\n
            editor.completer = this;\n
        }\n
\n
        editor.keyBinding.addKeyboardHandler(this.keyboardHandler);\n
        editor.on("changeSelection", this.changeListener);\n
        editor.on("blur", this.blurListener);\n
        editor.on("mousedown", this.mousedownListener);\n
        editor.on("mousewheel", this.mousewheelListener);\n
        \n
        this.updateCompletions();\n
    };\n
    \n
    this.updateCompletions = function(keepPopupPosition) {\n
        if (keepPopupPosition && this.base && this.completions) {\n
            var pos = this.editor.getCursorPosition();\n
            var prefix = this.editor.session.getTextRange({start: this.base, end: pos});\n
            if (prefix == this.completions.filterText)\n
                return;\n
            this.completions.setFilter(prefix);\n
            if (!this.completions.filtered.length)\n
                return this.detach();\n
            this.openPopup(this.editor, prefix, keepPopupPosition);\n
            return;\n
        }\n
        this.gatherCompletions(this.editor, function(err, results) {\n
            var matches = results && results.matches;\n
            if (!matches || !matches.length)\n
                return this.detach();\n
\n
            this.completions = new FilteredList(matches);\n
            this.completions.setFilter(results.prefix);\n
            if (!this.completions.filtered.length)\n
                return this.detach();\n
            this.openPopup(this.editor, results.prefix, keepPopupPosition);\n
        }.bind(this));\n
    };\n
\n
    this.cancelContextMenu = function() {\n
        var stop = function(e) {\n
            this.editor.off("nativecontextmenu", stop);\n
            if (e && e.domEvent)\n
                event.stopEvent(e.domEvent);\n
        }.bind(this);\n
        setTimeout(stop, 10);\n
        this.editor.on("nativecontextmenu", stop);\n
    };\n
\n
}).call(Autocomplete.prototype);\n
\n
Autocomplete.startCommand = {\n
    name: "startAutocomplete",\n
    exec: function(editor) {\n
        if (!editor.completer)\n
            editor.completer = new Autocomplete();\n
        editor.completer.showPopup(editor);\n
        editor.completer.cancelContextMenu();\n
    },\n
    bindKey: "Ctrl-Space|Ctrl-Shift-Space|Alt-Space"\n
};\n
\n
var FilteredList = function(array, filterText, mutateData) {\n
    this.all = array;\n
    this.filtered = array;\n
    this.filterText = filterText || "";\n
};\n
(function(){\n
    this.setFilter = function(str) {\n
        if (str.length > this.filterText && str.lastIndexOf(this.filterText, 0) === 0)\n
            var matches = this.filtered;\n
        else\n
            var matches = this.all;\n
\n
        this.filterText = str;\n
        matches = this.filterCompletions(matches, this.filterText);\n
        matches = matches.sort(function(a, b) {\n
            return b.exactMatch - a.exactMatch || b.score - a.score;\n
        });\n
        var prev = null;\n
        matches = matches.filter(function(item){\n
            var caption = item.value || item.caption || item.snippet; \n
            if (caption === prev) return false;\n
            prev = caption;\n
            return true;\n
        });\n
        \n
        this.filtered = matches;\n
    };\n
    this.filterCompletions = function(items, needle) {\n
        var results = [];\n
        var upper = needle.toUpperCase();\n
        var lower = needle.toLowerCase();\n
        loop: for (var i = 0, item; item = items[i]; i++) {\n
            var caption = item.value || item.caption || item.snippet;\n
            if (!caption) continue;\n
            var lastIndex = -1;\n
            var matchMask = 0;\n
            var penalty = 0;\n
            var index, distance;\n
            for (var j = 0; j < needle.length; j++) {\n
                var i1 = caption.indexOf(lower[j], lastIndex + 1);\n
                var i2 = caption.indexOf(upper[j], lastIndex + 1);\n
                index = (i1 >= 0) ? ((i2 < 0 || i1 < i2) ? i1 : i2) : i2;\n
                if (index < 0)\n
                    continue loop;\n
                distance = index - lastIndex - 1;\n
                if (distance > 0) {\n
                    if (lastIndex === -1)\n
                        penalty += 10;\n
                    penalty += distance;\n
                }\n
                matchMask = matchMask | (1 << index);\n
                lastIndex = index;\n
            }\n
            item.matchMask = matchMask;\n
            item.exactMatch = penalty ? 0 : 1;\n
            item.score = (item.score || 0) - penalty;\n
            results.push(item);\n
        }\n
        return results;\n
    };\n
}).call(FilteredList.prototype);\n
\n
exports.Autocomplete = Autocomplete;\n
exports.FilteredList = FilteredList;\n
\n
});\n
\n
define(\'ace/autocomplete/popup\', [\'require\', \'exports\', \'module\' , \'ace/edit_session\', \'ace/virtual_renderer\', \'ace/editor\', \'ace/range\', \'ace/lib/event\', \'ace/lib/lang\', \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
var EditSession = require("../edit_session").EditSession;\n
var Renderer = require("../virtual_renderer").VirtualRenderer;\n
var Editor = require("../editor").Editor;\n
var Range = require("../range").Range;\n
var event = require("../lib/event");\n
var lang = require("../lib/lang");\n
var dom = require("../lib/dom");\n
\n
var $singleLineEditor = function(el) {\n
    var renderer = new Renderer(el);\n
\n
    renderer.$maxLines = 4;\n
    \n
    var editor = new Editor(renderer);\n
\n
    editor.setHighlightActiveLine(false);\n
    editor.setShowPrintMargin(false);\n
    editor.renderer.setShowGutter(false);\n
    editor.renderer.setHighlightGutterLine(false);\n
\n
    editor.$mouseHandler.$focusWaitTimout = 0;\n
\n
    return editor;\n
};\n
\n
var AcePopup = function(parentNode) {\n
    var el = dom.createElement("div");\n
    var popup = new $singleLineEditor(el);\n
    \n
    if (parentNode)\n
        parentNode.appendChild(el);\n
    el.style.display = "none";\n
    popup.renderer.content.style.cursor = "default";\n
    popup.renderer.setStyle("ace_autocomplete");\n
    \n
    popup.setOption("displayIndentGuides", false);\n
\n
    var noop = function(){};\n
\n
    popup.focus = noop;\n
    popup.$isFocused = true;\n
\n
    popup.renderer.$cursorLayer.restartTimer = noop;\n
    popup.renderer.$cursorLayer.element.style.opacity = 0;\n
\n
    popup.renderer.$maxLines = 8;\n
    popup.renderer.$keepTextAreaAtCursor = false;\n
\n
    popup.setHighlightActiveLine(false);\n
    popup.session.highlight("");\n
    popup.session.$searchHighlight.clazz = "ace_highlight-marker";\n
\n
    popup.on("mousedown", function(e) {\n
        var pos = e.getDocumentPosition();\n
        popup.moveCursorToPosition(pos);\n
        popup.selection.clearSelection();\n
        selectionMarker.start.row = selectionMarker.end.row = pos.row;\n
        e.stop();\n
    });\n
\n
    var lastMouseEvent;\n
    var hoverMarker = new Range(-1,0,-1,Infinity);\n
    var selectionMarker = new Range(-1,0,-1,Infinity);\n
    selectionMarker.id = popup.session.addMarker(selectionMarker, "ace_active-line", "fullLine");\n
    popup.setSelectOnHover = function(val) {\n
        if (!val) {\n
            hoverMarker.id = popup.session.addMarker(hoverMarker, "ace_line-hover", "fullLine");\n
        } else if (hoverMarker.id) {\n
            popup.session.removeMarker(hoverMarker.id);\n
            hoverMarker.id = null;\n
        }\n
    }\n
    popup.setSelectOnHover(false);\n
    popup.on("mousemove", function(e) {\n
        if (!lastMouseEvent) {\n
            lastMouseEvent = e;\n
            return;\n
        }\n
        if (lastMouseEvent.x == e.x && lastMouseEvent.y == e.y) {\n
            return;\n
        }\n
        lastMouseEvent = e;\n
        lastMouseEvent.scrollTop = popup.renderer.scrollTop;\n
        var row = lastMouseEvent.getDocumentPosition().row;\n
        if (hoverMarker.start.row != row) {\n
            if (!hoverMarker.id)\n
                popup.setRow(row);\n
            setHoverMarker(row);\n
        }\n
    });\n
    popup.renderer.on("beforeRender", function() {\n
        if (lastMouseEvent && hoverMarker.start.row != -1) {\n
            lastMouseEvent.$pos = null;\n
            var row = lastMouseEvent.getDocumentPosition().row;\n
            if (!hoverMarker.id)\n
                popup.setRow(row);\n
            setHoverMarker(row, true);\n
        }\n
    });\n
    popup.renderer.on("afterRender", function() {\n
        var row = popup.getRow();\n
        var t = popup.renderer.$textLayer;\n
        var selected = t.element.childNodes[row - t.config.firstRow];\n
        if (selected == t.selectedNode)\n
            return;\n
        if (t.selectedNode)\n
            dom.removeCssClass(t.selectedNode, "ace_selected");\n
        t.selectedNode = selected;\n
        if (selected)\n
            dom.addCssClass(selected, "ace_selected");\n
    });\n
    var hideHoverMarker = function() { setHoverMarker(-1) };\n
    var setHoverMarker = function(row, suppressRedraw) {\n
        if (row !== hoverMarker.start.row) {\n
            hoverMarker.start.row = hoverMarker.end.row = row;\n
            if (!suppressRedraw)\n
                popup.session._emit("changeBackMarker");\n
            popup._emit("changeHoverMarker");\n
        }\n
    };\n
    popup.getHoveredRow = function() {\n
        return hoverMarker.start.row;\n
    };\n
    \n
    event.addListener(popup.container, "mouseout", hideHoverMarker);\n
    popup.on("hide", hideHoverMarker);\n
    popup.on("changeSelection", hideHoverMarker);\n
    \n
    popup.session.doc.getLength = function() {\n
        return popup.data.length;\n
    };\n
    popup.session.doc.getLine = function(i) {\n
        var data = popup.data[i];\n
        if (typeof data == "string")\n
            return data;\n
        return (data && data.value) || "";\n
    };\n
\n
    var bgTokenizer = popup.session.bgTokenizer;\n
    bgTokenizer.$tokenizeRow = function(i) {\n
        var data = popup.data[i];\n
        var tokens = [];\n
        if (!data)\n
            return tokens;\n
        if (typeof data == "string")\n
            data = {value: data};\n
        if (!data.caption)\n
            data.caption = data.value;\n
\n
        var last = -1;\n
        var flag, c;\n
        for (var i = 0; i < data.caption.length; i++) {\n
            c = data.caption[i];\n
            flag = data.matchMask & (1 << i) ? 1 : 0;\n
            if (last !== flag) {\n
                tokens.push({type: data.className || "" + ( flag ? "completion-highlight" : ""), value: c});\n
                last = flag;\n
            } else {\n
                tokens[tokens.length - 1].value += c;\n
            }\n
        }\n
\n
        if (data.meta) {\n
            var maxW = popup.renderer.$size.scrollerWidth / popup.renderer.layerConfig.characterWidth;\n
            if (data.meta.length + data.caption.length < maxW - 2)\n
                tokens.push({type: "rightAlignedText", value: data.meta});\n
        }\n
        return tokens;\n
    };\n
    bgTokenizer.$updateOnChange = noop;\n
    bgTokenizer.start = noop;\n
    \n
    popup.session.$computeWidth = function() {\n
        return this.screenWidth = 0;\n
    }\n
    popup.data = [];\n
    popup.setData = function(list) {\n
        popup.data = list || [];\n
        popup.setValue(lang.stringRepeat("\\n", list.length), -1);\n
        popup.setRow(0);\n
    };\n
    popup.getData = function(row) {\n
        return popup.data[row];\n
    };\n
\n
    popup.getRow = function() {\n
        return selectionMarker.start.row;\n
    };\n
    popup.setRow = function(line) {\n
        line = Math.max(-1, Math.min(this.data.length, line));\n
        if (selectionMarker.start.row != line) {\n
            popup.selection.clearSelection();\n
            selectionMarker.start.row = selectionMarker.end.row = line || 0;\n
            popup.session._emit("changeBackMarker");\n
            popup.moveCursorTo(line || 0, 0);\n
            if (popup.isOpen)\n
                popup._signal("select");\n
        }\n
    };\n
\n
    popup.hide = function() {\n
        this.container.style.display = "none";\n
        this._signal("hide");\n
        popup.isOpen = false;\n
    };\n
    popup.show = function(pos, lineHeight) {\n
        var el = this.container;\n
        var screenHeight = window.innerHeight;\n
        var renderer = this.renderer;\n
        var maxH = renderer.$maxLines * lineHeight * 1.4;\n
        var top = pos.top + this.$borderSize;\n
        if (top + maxH > screenHeight - lineHeight) {\n
            el.style.top = "";\n
            el.style.bottom = screenHeight - top + "px";\n
        } else {\n
            top += lineHeight;\n
            el.style.top = top + "px";\n
            el.style.bottom = "";\n
        }\n
\n
        el.style.left = pos.left + "px";\n
        el.style.display = "";\n
        this.renderer.$textLayer.checkForSizeChanges();\n
\n
        this._signal("show");\n
        lastMouseEvent = null;\n
        popup.isOpen = true;\n
    };\n
    \n
    popup.getTextLeftOffset = function() {\n
        return this.$borderSize + this.renderer.$padding + this.$imageSize;\n
    };\n
    \n
    popup.$imageSize = 0;\n
    popup.$borderSize = 1;\n
\n
    return popup;\n
};\n
\n
dom.importCssString("\\\n
.ace_autocomplete.ace-tm .ace_marker-layer .ace_active-line {\\\n
    background-color: #CAD6FA;\\\n
    z-index: 1;\\\n
}\\\n
.ace_autocomplete.ace-tm .ace_line-hover {\\\n
    border: 1px solid #abbffe;\\\n
    margin-top: -1px;\\\n
    background: rgba(233,233,253,0.4);\\\n
}\\\n
.ace_autocomplete .ace_line-hover {\\\n
    position: absolute;\\\n
    z-index: 2;\\\n
}\\\n
.ace_rightAlignedText {\\\n
    color: gray;\\\n
    display: inline-block;\\\n
    position: absolute;\\\n
    right: 4px;\\\n
    text-align: right;\\\n
    z-index: -1;\\\n
}\\\n
.ace_autocomplete .ace_completion-highlight{\\\n
    color: #000;\\\n
    text-shadow: 0 0 0.01em;\\\n
}\\\n
.ace_autocomplete {\\\n
    width: 280px;\\\n
    z-index: 200000;\\\n
    background: #fbfbfb;\\\n
    color: #444;\\\n
    border: 1px lightgray solid;\\\n
    position: fixed;\\\n
    box-shadow: 2px 3px 5px rgba(0,0,0,.2);\\\n
    line-height: 1.4;\\\n
}");\n
\n
exports.AcePopup = AcePopup;\n
\n
});\n
\n
define(\'ace/autocomplete/util\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
exports.parForEach = function(array, fn, callback) {\n
    var completed = 0;\n
    var arLength = array.length;\n
    if (arLength === 0)\n
        callback();\n
    for (var i = 0; i < arLength; i++) {\n
        fn(array[i], function(result, err) {\n
            completed++;\n
            if (completed === arLength)\n
                callback(result, err);\n
        });\n
    }\n
}\n
\n
var ID_REGEX = /[a-zA-Z_0-9\\$-]/;\n
\n
exports.retrievePrecedingIdentifier = function(text, pos, regex) {\n
    regex = regex || ID_REGEX;\n
    var buf = [];\n
    for (var i = pos-1; i >= 0; i--) {\n
        if (regex.test(text[i]))\n
            buf.push(text[i]);\n
        else\n
            break;\n
    }\n
    return buf.reverse().join("");\n
}\n
\n
exports.retrieveFollowingIdentifier = function(text, pos, regex) {\n
    regex = regex || ID_REGEX;\n
    var buf = [];\n
    for (var i = pos; i < text.length; i++) {\n
        if (regex.test(text[i]))\n
            buf.push(text[i]);\n
        else\n
            break;\n
    }\n
    return buf;\n
}\n
\n
});\n
\n
define(\'ace/autocomplete/text_completer\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
    var Range = require("ace/range").Range;\n
    \n
    var splitRegex = /[^a-zA-Z_0-9\\$\\-]+/;\n
\n
    function getWordIndex(doc, pos) {\n
        var textBefore = doc.getTextRange(Range.fromPoints({row: 0, column:0}, pos));\n
        return textBefore.split(splitRegex).length - 1;\n
    }\n
    function wordDistance(doc, pos) {\n
        var prefixPos = getWordIndex(doc, pos);\n
        var words = doc.getValue().split(splitRegex);\n
        var wordScores = Object.create(null);\n
        \n
        var currentWord = words[prefixPos];\n
\n
        words.forEach(function(word, idx) {\n
            if (!word || word === currentWord) return;\n
\n
            var distance = Math.abs(prefixPos - idx);\n
            var score = words.length - distance;\n
            if (wordScores[word]) {\n
                wordScores[word] = Math.max(score, wordScores[word]);\n
            } else {\n
                wordScores[word] = score;\n
            }\n
        });\n
        return wordScores;\n
    }\n
\n
    exports.getCompletions = function(editor, session, pos, prefix, callback) {\n
        var wordScore = wordDistance(session, pos, prefix);\n
        var wordList = Object.keys(wordScore);\n
        callback(null, wordList.map(function(word) {\n
            return {\n
                name: word,\n
                value: word,\n
                score: wordScore[word],\n
                meta: "local"\n
            };\n
        }));\n
    };\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>56218</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
