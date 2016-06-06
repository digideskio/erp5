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
            <value> <string>ts83646622.54</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>keybinding-emacs.js</string> </value>
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
 * Copyright (c) 2010, Ajax.org B.V.\n
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
define(\'ace/keyboard/emacs\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/incremental_search\', \'ace/commands/incremental_search_commands\', \'ace/keyboard/hash_handler\', \'ace/lib/keys\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
require("../incremental_search");\n
var iSearchCommandModule = require("../commands/incremental_search_commands");\n
\n
\n
var screenToTextBlockCoordinates = function(x, y) {\n
    var canvasPos = this.scroller.getBoundingClientRect();\n
\n
    var col = Math.floor(\n
        (x + this.scrollLeft - canvasPos.left - this.$padding) / this.characterWidth\n
    );\n
    var row = Math.floor(\n
        (y + this.scrollTop - canvasPos.top) / this.lineHeight\n
    );\n
\n
    return this.session.screenToDocumentPosition(row, col);\n
};\n
\n
var HashHandler = require("./hash_handler").HashHandler;\n
exports.handler = new HashHandler();\n
\n
exports.handler.isEmacs = true;\n
exports.handler.$id = "ace/keyboard/emacs";\n
\n
var initialized = false;\n
var $formerLongWords;\n
var $formerLineStart;\n
\n
exports.handler.attach = function(editor) {\n
    if (!initialized) {\n
        initialized = true;\n
        dom.importCssString(\'\\\n
            .emacs-mode .ace_cursor{\\\n
                border: 2px rgba(50,250,50,0.8) solid!important;\\\n
                -moz-box-sizing: border-box!important;\\\n
                -webkit-box-sizing: border-box!important;\\\n
                box-sizing: border-box!important;\\\n
                background-color: rgba(0,250,0,0.9);\\\n
                opacity: 0.5;\\\n
            }\\\n
            .emacs-mode .ace_hidden-cursors .ace_cursor{\\\n
                opacity: 1;\\\n
                background-color: transparent;\\\n
            }\\\n
            .emacs-mode .ace_overwrite-cursors .ace_cursor {\\\n
                opacity: 1;\\\n
                background-color: transparent;\\\n
                border-width: 0 0 2px 2px !important;\\\n
            }\\\n
            .emacs-mode .ace_text-layer {\\\n
                z-index: 4\\\n
            }\\\n
            .emacs-mode .ace_cursor-layer {\\\n
                z-index: 2\\\n
            }\', \'emacsMode\'\n
        );\n
    }\n
    $formerLongWords = editor.session.$selectLongWords;\n
    editor.session.$selectLongWords = true;\n
    $formerLineStart = editor.session.$useEmacsStyleLineStart;\n
    editor.session.$useEmacsStyleLineStart = true;\n
\n
    editor.session.$emacsMark = null; // the active mark\n
    editor.session.$emacsMarkRing = editor.session.$emacsMarkRing || [];\n
\n
    editor.emacsMark = function() {\n
        return this.session.$emacsMark;\n
    }\n
\n
    editor.setEmacsMark = function(p) {\n
        this.session.$emacsMark = p;\n
    }\n
\n
    editor.pushEmacsMark = function(p, activate) {\n
        var prevMark = this.session.$emacsMark;\n
        if (prevMark)\n
            this.session.$emacsMarkRing.push(prevMark);\n
        if (!p || activate) this.setEmacsMark(p)\n
        else this.session.$emacsMarkRing.push(p);\n
    }\n
\n
    editor.popEmacsMark = function() {\n
        var mark = this.emacsMark();\n
        if (mark) { this.setEmacsMark(null); return mark; }\n
        return this.session.$emacsMarkRing.pop();\n
    }\n
\n
    editor.getLastEmacsMark = function(p) {\n
        return this.session.$emacsMark || this.session.$emacsMarkRing.slice(-1)[0];\n
    }\n
\n
    editor.on("click", $resetMarkMode);\n
    editor.on("changeSession", $kbSessionChange);\n
    editor.renderer.screenToTextCoordinates = screenToTextBlockCoordinates;\n
    editor.setStyle("emacs-mode");\n
    editor.commands.addCommands(commands);\n
    exports.handler.platform = editor.commands.platform;\n
    editor.$emacsModeHandler = this;\n
    editor.addEventListener(\'copy\', this.onCopy);\n
    editor.addEventListener(\'paste\', this.onPaste);\n
};\n
\n
exports.handler.detach = function(editor) {\n
    delete editor.renderer.screenToTextCoordinates;\n
    editor.session.$selectLongWords = $formerLongWords;\n
    editor.session.$useEmacsStyleLineStart = $formerLineStart;\n
    editor.removeEventListener("click", $resetMarkMode);\n
    editor.removeEventListener("changeSession", $kbSessionChange);\n
    editor.unsetStyle("emacs-mode");\n
    editor.commands.removeCommands(commands);\n
    editor.removeEventListener(\'copy\', this.onCopy);\n
    editor.removeEventListener(\'paste\', this.onPaste);\n
};\n
\n
var $kbSessionChange = function(e) {\n
    if (e.oldSession) {\n
        e.oldSession.$selectLongWords = $formerLongWords;\n
        e.oldSession.$useEmacsStyleLineStart = $formerLineStart;\n
    }\n
\n
    $formerLongWords = e.session.$selectLongWords;\n
    e.session.$selectLongWords = true;\n
    $formerLineStart = e.session.$useEmacsStyleLineStart;\n
    e.session.$useEmacsStyleLineStart = true;\n
\n
    if (!e.session.hasOwnProperty(\'$emacsMark\'))\n
        e.session.$emacsMark = null;\n
    if (!e.session.hasOwnProperty(\'$emacsMarkRing\'))\n
        e.session.$emacsMarkRing = [];\n
}\n
\n
var $resetMarkMode = function(e) {\n
    e.editor.session.$emacsMark = null;\n
}\n
\n
var keys = require("../lib/keys").KEY_MODS,\n
    eMods = {C: "ctrl", S: "shift", M: "alt", CMD: "command"},\n
    combinations = ["C-S-M-CMD",\n
                    "S-M-CMD", "C-M-CMD", "C-S-CMD", "C-S-M",\n
                    "M-CMD", "S-CMD", "S-M", "C-CMD", "C-M", "C-S",\n
                    "CMD", "M", "S", "C"];\n
combinations.forEach(function(c) {\n
    var hashId = 0;\n
    c.split("-").forEach(function(c) {\n
        hashId = hashId | keys[eMods[c]];\n
    });\n
    eMods[hashId] = c.toLowerCase() + "-";\n
});\n
\n
exports.handler.onCopy = function(e, editor) {\n
    if (editor.$handlesEmacsOnCopy) return;\n
    editor.$handlesEmacsOnCopy = true;\n
    exports.handler.commands.killRingSave.exec(editor);\n
    delete editor.$handlesEmacsOnCopy;\n
}\n
\n
exports.handler.onPaste = function(e, editor) {\n
    editor.pushEmacsMark(editor.getCursorPosition());\n
}\n
\n
exports.handler.bindKey = function(key, command) {\n
    if (!key)\n
        return;\n
\n
    var ckb = this.commandKeyBinding;\n
    key.split("|").forEach(function(keyPart) {\n
        keyPart = keyPart.toLowerCase();\n
        ckb[keyPart] = command;\n
        var keyParts = keyPart.split(" ").slice(0,-1);\n
        keyParts.reduce(function(keyMapKeys, keyPart, i) {\n
            var prefix = keyMapKeys[i-1] ? keyMapKeys[i-1] + \' \' : \'\';\n
            return keyMapKeys.concat([prefix + keyPart]);\n
        }, []).forEach(function(keyPart) {\n
            if (!ckb[keyPart]) ckb[keyPart] = "null";\n
        });\n
    }, this);\n
}\n
\n
exports.handler.handleKeyboard = function(data, hashId, key, keyCode) {\n
    var editor = data.editor;\n
    if (hashId == -1) {\n
        editor.pushEmacsMark();\n
        if (data.count) {\n
            var str = Array(data.count + 1).join(key);\n
            data.count = null;\n
            return {command: "insertstring", args: str};\n
        }\n
    }\n
\n
    if (key == "\\x00") return undefined;\n
\n
    var modifier = eMods[hashId];\n
    if (modifier == "c-" || data.universalArgument) {\n
        var prevCount = String(data.count || 0);\n
        var count = parseInt(key[key.length - 1]);\n
        if (typeof count === \'number\' && !isNaN(count)) {\n
            data.count = parseInt(prevCount + count);\n
            return {command: "null"};\n
        } else if (data.universalArgument) {\n
            data.count = 4;\n
        }\n
    }\n
    data.universalArgument = false;\n
    if (modifier) key = modifier + key;\n
    if (data.keyChain) key = data.keyChain += " " + key;\n
    var command = this.commandKeyBinding[key];\n
    data.keyChain = command == "null" ? key : "";\n
    if (!command) return undefined;\n
    if (command === "null") return {command: "null"};\n
\n
    if (command === "universalArgument") {\n
        data.universalArgument = true;\n
        return {command: "null"};\n
    }\n
    var args;\n
    if (typeof command !== "string") {\n
        args = command.args;\n
        if (command.command) command = command.command;\n
        if (command === "goorselect") {\n
            command = editor.emacsMark() ? args[1] : args[0];\n
            args = null;\n
        }\n
    }\n
\n
    if (typeof command === "string") {\n
        if (command === "insertstring" ||\n
            command === "splitline" ||\n
            command === "togglecomment") {\n
            editor.pushEmacsMark();\n
        }\n
        command = this.commands[command] || editor.commands.commands[command];\n
        if (!command) return undefined;\n
    }\n
\n
    if (!command.readonly && !command.isYank)\n
        data.lastCommand = null;\n
\n
    if (data.count) {\n
        var count = data.count;\n
        data.count = 0;\n
        if (!command || !command.handlesCount) {\n
            return {\n
                args: args,\n
                command: {\n
                    exec: function(editor, args) {\n
                        for (var i = 0; i < count; i++)\n
                            command.exec(editor, args);\n
                    }\n
                }\n
            };\n
        } else {\n
            if (!args) args = {}\n
            if (typeof args === \'object\') args.count = count;\n
        }\n
    }\n
\n
    return {command: command, args: args};\n
};\n
\n
exports.emacsKeys = {\n
    "Up|C-p"      : {command: "goorselect", args: ["golineup","selectup"]},\n
    "Down|C-n"    : {command: "goorselect", args: ["golinedown","selectdown"]},\n
    "Left|C-b"    : {command: "goorselect", args: ["gotoleft","selectleft"]},\n
    "Right|C-f"   : {command: "goorselect", args: ["gotoright","selectright"]},\n
    "C-Left|M-b"  : {command: "goorselect", args: ["gotowordleft","selectwordleft"]},\n
    "C-Right|M-f" : {command: "goorselect", args: ["gotowordright","selectwordright"]},\n
    "Home|C-a"    : {command: "goorselect", args: ["gotolinestart","selecttolinestart"]},\n
    "End|C-e"     : {command: "goorselect", args: ["gotolineend","selecttolineend"]},\n
    "C-Home|S-M-,": {command: "goorselect", args: ["gotostart","selecttostart"]},\n
    "C-End|S-M-." : {command: "goorselect", args: ["gotoend","selecttoend"]},\n
    "S-Up|S-C-p"      : "selectup",\n
    "S-Down|S-C-n"    : "selectdown",\n
    "S-Left|S-C-b"    : "selectleft",\n
    "S-Right|S-C-f"   : "selectright",\n
    "S-C-Left|S-M-b"  : "selectwordleft",\n
    "S-C-Right|S-M-f" : "selectwordright",\n
    "S-Home|S-C-a"    : "selecttolinestart",\n
    "S-End|S-C-e"     : "selecttolineend",\n
    "S-C-Home"        : "selecttostart",\n
    "S-C-End"         : "selecttoend",\n
\n
    "C-l" : "recenterTopBottom",\n
    "M-s" : "centerselection",\n
    "M-g": "gotoline",\n
    "C-x C-p": "selectall",\n
    "C-Down": {command: "goorselect", args: ["gotopagedown","selectpagedown"]},\n
    "C-Up": {command: "goorselect", args: ["gotopageup","selectpageup"]},\n
    "PageDown|C-v": {command: "goorselect", args: ["gotopagedown","selectpagedown"]},\n
    "PageUp|M-v": {command: "goorselect", args: ["gotopageup","selectpageup"]},\n
    "S-C-Down": "selectpagedown",\n
    "S-C-Up": "selectpageup",\n
\n
    "C-s": "iSearch",\n
    "C-r": "iSearchBackwards",\n
\n
    "M-C-s": "findnext",\n
    "M-C-r": "findprevious",\n
    "S-M-5": "replace",\n
    "Backspace": "backspace",\n
    "Delete|C-d": "del",\n
    "Return|C-m": {command: "insertstring", args: "\\n"}, // "newline"\n
    "C-o": "splitline",\n
\n
    "M-d|C-Delete": {command: "killWord", args: "right"},\n
    "C-Backspace|M-Backspace|M-Delete": {command: "killWord", args: "left"},\n
    "C-k": "killLine",\n
\n
    "C-y|S-Delete": "yank",\n
    "M-y": "yankRotate",\n
    "C-g": "keyboardQuit",\n
\n
    "C-w": "killRegion",\n
    "M-w": "killRingSave",\n
    "C-Space": "setMark",\n
    "C-x C-x": "exchangePointAndMark",\n
\n
    "C-t": "transposeletters",\n
    "M-u": "touppercase",    // Doesn\'t work\n
    "M-l": "tolowercase",\n
    "M-/": "autocomplete",   // Doesn\'t work\n
    "C-u": "universalArgument",\n
\n
    "M-;": "togglecomment",\n
\n
    "C-/|C-x u|S-C--|C-z": "undo",\n
    "S-C-/|S-C-x u|C--|S-C-z": "redo", //infinite undo?\n
    "C-x r":  "selectRectangularRegion",\n
    "M-x": {command: "focusCommandLine", args: "M-x "}\n
};\n
\n
\n
exports.handler.bindKeys(exports.emacsKeys);\n
\n
exports.handler.addCommands({\n
    recenterTopBottom: function(editor) {\n
        var renderer = editor.renderer;\n
        var pos = renderer.$cursorLayer.getPixelPosition();\n
        var h = renderer.$size.scrollerHeight - renderer.lineHeight;\n
        var scrollTop = renderer.scrollTop;\n
        if (Math.abs(pos.top - scrollTop) < 2) {\n
            scrollTop = pos.top - h;\n
        } else if (Math.abs(pos.top - scrollTop - h * 0.5) < 2) {\n
            scrollTop = pos.top;\n
        } else {\n
            scrollTop = pos.top - h * 0.5;\n
        }\n
        editor.session.setScrollTop(scrollTop);\n
    },\n
    selectRectangularRegion:  function(editor) {\n
        editor.multiSelect.toggleBlockSelection();\n
    },\n
    setMark:  {\n
        exec: function(editor, args) {\n
            if (args && args.count) {\n
                var mark = editor.popEmacsMark();\n
                mark && editor.selection.moveCursorToPosition(mark);\n
                return;\n
            }\n
\n
            var mark = editor.emacsMark(),\n
                transientMarkModeActive = true;\n
            if (transientMarkModeActive && (mark || !editor.selection.isEmpty())) {\n
                editor.pushEmacsMark();\n
                editor.clearSelection();\n
                return;\n
            }\n
\n
            if (mark) {\n
                var cp = editor.getCursorPosition();\n
                if (editor.selection.isEmpty() &&\n
                    mark.row == cp.row && mark.column == cp.column) {\n
                    editor.pushEmacsMark();\n
                    return;\n
                }\n
            }\n
            mark = editor.getCursorPosition();\n
            editor.setEmacsMark(mark);\n
            editor.selection.setSelectionAnchor(mark.row, mark.column);\n
        },\n
        readonly: true,\n
        handlesCount: true,\n
        multiSelectAction: "forEach"\n
    },\n
    exchangePointAndMark: {\n
        exec: function(editor, args) {\n
            var sel = editor.selection;\n
            if (args.count) {\n
                var pos = editor.getCursorPosition();\n
                sel.clearSelection();\n
                sel.moveCursorToPosition(editor.popEmacsMark());\n
                editor.pushEmacsMark(pos);\n
                return;\n
            }\n
            var lastMark = editor.getLastEmacsMark();\n
            var range = sel.getRange();\n
            if (range.isEmpty()) {\n
                sel.selectToPosition(lastMark);\n
                return;\n
            }\n
            sel.setSelectionRange(range, !sel.isBackwards());\n
        },\n
        readonly: true,\n
        handlesCount: true,\n
        multiSelectAction: "forEach"\n
    },\n
    killWord: {\n
        exec: function(editor, dir) {\n
            editor.clearSelection();\n
            if (dir == "left")\n
                editor.selection.selectWordLeft();\n
            else\n
                editor.selection.selectWordRight();\n
\n
            var range = editor.getSelectionRange();\n
            var text = editor.session.getTextRange(range);\n
            exports.killRing.add(text);\n
\n
            editor.session.remove(range);\n
            editor.clearSelection();\n
        },\n
        multiSelectAction: "forEach"\n
    },\n
    killLine: function(editor) {\n
        editor.pushEmacsMark(null);\n
        var pos = editor.getCursorPosition();\n
        if (pos.column == 0 &&\n
            editor.session.doc.getLine(pos.row).length == 0) {\n
            editor.selection.selectLine();\n
        } else {\n
            editor.clearSelection();\n
            editor.selection.selectLineEnd();\n
        }\n
        var range = editor.getSelectionRange();\n
        var text = editor.session.getTextRange(range);\n
        exports.killRing.add(text);\n
\n
        editor.session.remove(range);\n
        editor.clearSelection();\n
    },\n
    yank: function(editor) {\n
        editor.onPaste(exports.killRing.get() || \'\');\n
        editor.keyBinding.$data.lastCommand = "yank";\n
    },\n
    yankRotate: function(editor) {\n
        if (editor.keyBinding.$data.lastCommand != "yank")\n
            return;\n
        editor.undo();\n
        editor.onPaste(exports.killRing.rotate());\n
        editor.keyBinding.$data.lastCommand = "yank";\n
    },\n
    killRegion: {\n
        exec: function(editor) {\n
            exports.killRing.add(editor.getCopyText());\n
            editor.commands.byName.cut.exec(editor);\n
        },\n
        readonly: true,\n
        multiSelectAction: "forEach"\n
    },\n
    killRingSave: {\n
        exec: function(editor) {\n
            exports.killRing.add(editor.getCopyText());\n
            setTimeout(function() {\n
                var sel = editor.selection,\n
                    range = sel.getRange();\n
                editor.pushEmacsMark(sel.isBackwards() ? range.end : range.start);\n
                sel.clearSelection();\n
            }, 0);\n
        },\n
        readonly: true\n
    },\n
    keyboardQuit: function(editor) {\n
        editor.selection.clearSelection();\n
        editor.setEmacsMark(null);\n
    },\n
    focusCommandLine: function(editor, arg) {\n
        if (editor.showCommandLine)\n
            editor.showCommandLine(arg);\n
    }\n
});\n
\n
exports.handler.addCommands(iSearchCommandModule.iSearchStartCommands);\n
\n
var commands = exports.handler.commands;\n
commands.yank.isYank = true;\n
commands.yankRotate.isYank = true;\n
\n
exports.killRing = {\n
    $data: [],\n
    add: function(str) {\n
        str && this.$data.push(str);\n
        if (this.$data.length > 30)\n
            this.$data.shift();\n
    },\n
    get: function(n) {\n
        n = n || 1;\n
        return this.$data.slice(this.$data.length-n, this.$data.length).reverse().join(\'\\n\');\n
    },\n
    pop: function() {\n
        if (this.$data.length > 1)\n
            this.$data.pop();\n
        return this.get();\n
    },\n
    rotate: function() {\n
        this.$data.unshift(this.$data.pop());\n
        return this.get();\n
    }\n
};\n
\n
});\n
\n
define(\'ace/incremental_search\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/range\', \'ace/search\', \'ace/search_highlight\', \'ace/commands/incremental_search_commands\', \'ace/lib/dom\', \'ace/commands/command_manager\', \'ace/editor\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var Range = require("./range").Range;\n
var Search = require("./search").Search;\n
var SearchHighlight = require("./search_highlight").SearchHighlight;\n
var iSearchCommandModule = require("./commands/incremental_search_commands");\n
var ISearchKbd = iSearchCommandModule.IncrementalSearchKeyboardHandler;\n
function IncrementalSearch() {\n
    this.$options = {wrap: false, skipCurrent: false};\n
    this.$keyboardHandler = new ISearchKbd(this);\n
}\n
\n
oop.inherits(IncrementalSearch, Search);\n
\n
;(function() {\n
\n
    this.activate = function(ed, backwards) {\n
        this.$editor = ed;\n
        this.$startPos = this.$currentPos = ed.getCursorPosition();\n
        this.$options.needle = \'\';\n
        this.$options.backwards = backwards;\n
        ed.keyBinding.addKeyboardHandler(this.$keyboardHandler);\n
        this.$mousedownHandler = ed.addEventListener(\'mousedown\', this.onMouseDown.bind(this));\n
        this.selectionFix(ed);\n
        this.statusMessage(true);\n
    }\n
\n
    this.deactivate = function(reset) {\n
        this.cancelSearch(reset);\n
        this.$editor.keyBinding.removeKeyboardHandler(this.$keyboardHandler);\n
        if (this.$mousedownHandler) {\n
            this.$editor.removeEventListener(\'mousedown\', this.$mousedownHandler);\n
            delete this.$mousedownHandler;\n
        }\n
        this.message(\'\');\n
    }\n
\n
    this.selectionFix = function(editor) {\n
        if (editor.selection.isEmpty() && !editor.session.$emacsMark) {\n
            editor.clearSelection();\n
        }\n
    }\n
\n
    this.highlight = function(regexp) {\n
        var sess = this.$editor.session,\n
            hl = sess.$isearchHighlight = sess.$isearchHighlight || sess.addDynamicMarker(\n
                new SearchHighlight(null, "ace_isearch-result", "text"));\n
        hl.setRegexp(regexp);\n
        sess._emit("changeBackMarker"); // force highlight layer redraw\n
    }\n
\n
    this.cancelSearch = function(reset) {\n
        var e = this.$editor;\n
        this.$prevNeedle = this.$options.needle;\n
        this.$options.needle = \'\';\n
        if (reset) {\n
            e.moveCursorToPosition(this.$startPos);\n
            this.$currentPos = this.$startPos;\n
        } else {\n
            e.pushEmacsMark && e.pushEmacsMark(this.$startPos, false);\n
        }\n
        this.highlight(null);\n
        return Range.fromPoints(this.$currentPos, this.$currentPos);\n
    }\n
\n
    this.highlightAndFindWithNeedle = function(moveToNext, needleUpdateFunc) {\n
        if (!this.$editor) return null;\n
        var options = this.$options;\n
        if (needleUpdateFunc) {\n
            options.needle = needleUpdateFunc.call(this, options.needle || \'\') || \'\';\n
        }\n
        if (options.needle.length === 0) {\n
            this.statusMessage(true);\n
            return this.cancelSearch(true);\n
        };\n
        options.start = this.$currentPos;\n
        var session = this.$editor.session,\n
            found = this.find(session);\n
        if (found) {\n
            if (options.backwards) found = Range.fromPoints(found.end, found.start);\n
            this.$editor.moveCursorToPosition(found.end);\n
            if (moveToNext) this.$currentPos = found.end;\n
            this.highlight(options.re)\n
        }\n
\n
        this.statusMessage(found);\n
\n
        return found;\n
    }\n
\n
    this.addChar = function(c) {\n
        return this.highlightAndFindWithNeedle(false, function(needle) {\n
            return needle + c;\n
        });\n
    }\n
\n
    this.removeChar = function(c) {\n
        return this.highlightAndFindWithNeedle(false, function(needle) {\n
            return needle.length > 0 ? needle.substring(0, needle.length-1) : needle;\n
        });\n
    }\n
\n
    this.next = function(options) {\n
        options = options || {};\n
        this.$options.backwards = !!options.backwards;\n
        this.$currentPos = this.$editor.getCursorPosition();\n
        return this.highlightAndFindWithNeedle(true, function(needle) {\n
            return options.useCurrentOrPrevSearch && needle.length === 0 ?\n
                this.$prevNeedle || \'\' : needle;\n
        });\n
    }\n
\n
    this.onMouseDown = function(evt) {\n
        this.deactivate();\n
        return true;\n
    }\n
\n
    this.statusMessage = function(found) {\n
        var options = this.$options, msg = \'\';\n
        msg += options.backwards ? \'reverse-\' : \'\';\n
        msg += \'isearch: \' + options.needle;\n
        msg += found ? \'\' : \' (not found)\';\n
        this.message(msg);\n
    }\n
\n
    this.message = function(msg) {\n
        if (this.$editor.showCommandLine) {\n
            this.$editor.showCommandLine(msg);\n
            this.$editor.focus();\n
        } else {\n
            console.log(msg);\n
        }\n
    }\n
\n
}).call(IncrementalSearch.prototype);\n
\n
\n
exports.IncrementalSearch = IncrementalSearch;\n
\n
var dom = require(\'./lib/dom\');\n
dom.importCssString && dom.importCssString("\\\n
.ace_marker-layer .ace_isearch-result {\\\n
  position: absolute;\\\n
  z-index: 6;\\\n
  -moz-box-sizing: border-box;\\\n
  -webkit-box-sizing: border-box;\\\n
  box-sizing: border-box;\\\n
}\\\n
div.ace_isearch-result {\\\n
  border-radius: 4px;\\\n
  background-color: rgba(255, 200, 0, 0.5);\\\n
  box-shadow: 0 0 4px rgb(255, 200, 0);\\\n
}\\\n
.ace_dark div.ace_isearch-result {\\\n
  background-color: rgb(100, 110, 160);\\\n
  box-shadow: 0 0 4px rgb(80, 90, 140);\\\n
}", "incremental-search-highlighting");\n
var commands = require("./commands/command_manager");\n
(function() {\n
    this.setupIncrementalSearch = function(editor, val) {\n
        if (this.usesIncrementalSearch == val) return;\n
        this.usesIncrementalSearch = val;\n
        var iSearchCommands = iSearchCommandModule.iSearchStartCommands;\n
        var method = val ? \'addCommands\' : \'removeCommands\';\n
        this[method](iSearchCommands);\n
    };\n
}).call(commands.CommandManager.prototype);\n
var Editor = require("./editor").Editor;\n
require("./config").defineOptions(Editor.prototype, "editor", {\n
    useIncrementalSearch: {\n
        set: function(val) {\n
            this.keyBinding.$handlers.forEach(function(handler) {\n
                if (handler.setupIncrementalSearch) {\n
                    handler.setupIncrementalSearch(this, val);\n
                }\n
            });\n
            this._emit(\'incrementalSearchSettingChanged\', {isEnabled: val});\n
        }\n
    }\n
});\n
\n
});\n
\n
define(\'ace/commands/incremental_search_commands\', [\'require\', \'exports\', \'module\' , \'ace/config\', \'ace/lib/oop\', \'ace/keyboard/hash_handler\', \'ace/commands/occur_commands\'], function(require, exports, module) {\n
\n
var config = require("../config");\n
var oop = require("../lib/oop");\n
var HashHandler = require("../keyboard/hash_handler").HashHandler;\n
var occurStartCommand = require("./occur_commands").occurStartCommand;\n
exports.iSearchStartCommands = [{\n
    name: "iSearch",\n
    bindKey: {win: "Ctrl-F", mac: "Command-F"},\n
    exec: function(editor, options) {\n
        config.loadModule(["core", "ace/incremental_search"], function(e) {\n
            var iSearch = e.iSearch = e.iSearch || new e.IncrementalSearch();\n
            iSearch.activate(editor, options.backwards);\n
            if (options.jumpToFirstMatch) iSearch.next(options);\n
        });\n
    },\n
    readOnly: true\n
}, {\n
    name: "iSearchBackwards",\n
    exec: function(editor, jumpToNext) { editor.execCommand(\'iSearch\', {backwards: true}); },\n
    readOnly: true\n
}, {\n
    name: "iSearchAndGo",\n
    bindKey: {win: "Ctrl-K", mac: "Command-G"},\n
    exec: function(editor, jumpToNext) { editor.execCommand(\'iSearch\', {jumpToFirstMatch: true, useCurrentOrPrevSearch: true}); },\n
    readOnly: true\n
}, {\n
    name: "iSearchBackwardsAndGo",\n
    bindKey: {win: "Ctrl-Shift-K", mac: "Command-Shift-G"},\n
    exec: function(editor) { editor.execCommand(\'iSearch\', {jumpToFirstMatch: true, backwards: true, useCurrentOrPrevSearch: true}); },\n
    readOnly: true\n
}];\n
exports.iSearchCommands = [{\n
    name: "restartSearch",\n
    bindKey: {win: "Ctrl-F", mac: "Command-F"},\n
    exec: function(iSearch) {\n
        iSearch.cancelSearch(true);\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: "searchForward",\n
    bindKey: {win: "Ctrl-S|Ctrl-K", mac: "Ctrl-S|Command-G"},\n
    exec: function(iSearch, options) {\n
        options.useCurrentOrPrevSearch = true;\n
        iSearch.next(options);\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: "searchBackward",\n
    bindKey: {win: "Ctrl-R|Ctrl-Shift-K", mac: "Ctrl-R|Command-Shift-G"},\n
    exec: function(iSearch, options) {\n
        options.useCurrentOrPrevSearch = true;\n
        options.backwards = true;\n
        iSearch.next(options);\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: "extendSearchTerm",\n
    exec: function(iSearch, string) {\n
        iSearch.addChar(string);\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: "extendSearchTermSpace",\n
    bindKey: "space",\n
    exec: function(iSearch) { iSearch.addChar(\' \'); },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: "shrinkSearchTerm",\n
    bindKey: "backspace",\n
    exec: function(iSearch) {\n
        iSearch.removeChar();\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: \'confirmSearch\',\n
    bindKey: \'return\',\n
    exec: function(iSearch) { iSearch.deactivate(); },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: \'cancelSearch\',\n
    bindKey: \'esc|Ctrl-G\',\n
    exec: function(iSearch) { iSearch.deactivate(true); },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}, {\n
    name: \'occurisearch\',\n
    bindKey: \'Ctrl-O\',\n
    exec: function(iSearch) {\n
        var options = oop.mixin({}, iSearch.$options);\n
        iSearch.deactivate();\n
        occurStartCommand.exec(iSearch.$editor, options);\n
    },\n
    readOnly: true,\n
    isIncrementalSearchCommand: true\n
}];\n
\n
function IncrementalSearchKeyboardHandler(iSearch) {\n
    this.$iSearch = iSearch;\n
}\n
\n
oop.inherits(IncrementalSearchKeyboardHandler, HashHandler);\n
\n
;(function() {\n
\n
    this.attach = function(editor) {\n
        var iSearch = this.$iSearch;\n
        HashHandler.call(this, exports.iSearchCommands, editor.commands.platform);\n
        this.$commandExecHandler = editor.commands.addEventListener(\'exec\', function(e) {\n
            if (!e.command.isIncrementalSearchCommand) return undefined;\n
            e.stopPropagation();\n
            e.preventDefault();\n
            return e.command.exec(iSearch, e.args || {});\n
        });\n
    }\n
\n
    this.detach = function(editor) {\n
        if (!this.$commandExecHandler) return;\n
        editor.commands.removeEventListener(\'exec\', this.$commandExecHandler);\n
        delete this.$commandExecHandler;\n
    }\n
\n
    var handleKeyboard$super = this.handleKeyboard;\n
    this.handleKeyboard = function(data, hashId, key, keyCode) {\n
        var cmd = handleKeyboard$super.call(this, data, hashId, key, keyCode);\n
        if (cmd.command) { return cmd; }\n
        if (hashId == -1) {\n
            var extendCmd = this.commands.extendSearchTerm;\n
            if (extendCmd) { return {command: extendCmd, args: key}; }\n
        }\n
        return {command: "null", passEvent: hashId == 0 || hashId == 4};\n
    }\n
\n
}).call(IncrementalSearchKeyboardHandler.prototype);\n
\n
\n
exports.IncrementalSearchKeyboardHandler = IncrementalSearchKeyboardHandler;\n
\n
});\n
\n
define(\'ace/commands/occur_commands\', [\'require\', \'exports\', \'module\' , \'ace/config\', \'ace/occur\', \'ace/keyboard/hash_handler\', \'ace/lib/oop\'], function(require, exports, module) {\n
\n
var config = require("../config"),\n
    Occur = require("../occur").Occur;\n
var occurStartCommand = {\n
    name: "occur",\n
    exec: function(editor, options) {\n
        var alreadyInOccur = !!editor.session.$occur;\n
        var occurSessionActive = new Occur().enter(editor, options);\n
        if (occurSessionActive && !alreadyInOccur)\n
            OccurKeyboardHandler.installIn(editor);\n
    },\n
    readOnly: true\n
};\n
\n
var occurCommands = [{\n
    name: "occurexit",\n
    bindKey: \'esc|Ctrl-G\',\n
    exec: function(editor) {\n
        var occur = editor.session.$occur;\n
        if (!occur) return;\n
        occur.exit(editor, {});\n
        if (!editor.session.$occur) OccurKeyboardHandler.uninstallFrom(editor);\n
    },\n
    readOnly: true\n
}, {\n
    name: "occuraccept",\n
    bindKey: \'enter\',\n
    exec: function(editor) {\n
        var occur = editor.session.$occur;\n
        if (!occur) return;\n
        occur.exit(editor, {translatePosition: true});\n
        if (!editor.session.$occur) OccurKeyboardHandler.uninstallFrom(editor);\n
    },\n
    readOnly: true\n
}];\n
\n
var HashHandler = require("../keyboard/hash_handler").HashHandler;\n
var oop = require("../lib/oop");\n
\n
\n
function OccurKeyboardHandler() {}\n
\n
oop.inherits(OccurKeyboardHandler, HashHandler);\n
\n
;(function() {\n
\n
    this.isOccurHandler = true;\n
\n
    this.attach = function(editor) {\n
        HashHandler.call(this, occurCommands, editor.commands.platform);\n
        this.$editor = editor;\n
    }\n
\n
    var handleKeyboard$super = this.handleKeyboard;\n
    this.handleKeyboard = function(data, hashId, key, keyCode) {\n
        var cmd = handleKeyboard$super.call(this, data, hashId, key, keyCode);\n
        return (cmd && cmd.command) ? cmd : undefined;\n
    }\n
\n
}).call(OccurKeyboardHandler.prototype);\n
\n
OccurKeyboardHandler.installIn = function(editor) {\n
    var handler = new this();\n
    editor.keyBinding.addKeyboardHandler(handler);\n
    editor.commands.addCommands(occurCommands);\n
}\n
\n
OccurKeyboardHandler.uninstallFrom = function(editor) {\n
    editor.commands.removeCommands(occurCommands);\n
    var handler = editor.getKeyboardHandler();\n
    if (handler.isOccurHandler)\n
        editor.keyBinding.removeKeyboardHandler(handler);\n
}\n
\n
exports.occurStartCommand = occurStartCommand;\n
\n
});\n
\n
define(\'ace/occur\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/range\', \'ace/search\', \'ace/edit_session\', \'ace/search_highlight\', \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var Range = require("./range").Range;\n
var Search = require("./search").Search;\n
var EditSession = require("./edit_session").EditSession;\n
var SearchHighlight = require("./search_highlight").SearchHighlight;\n
function Occur() {}\n
\n
oop.inherits(Occur, Search);\n
\n
(function() {\n
    this.enter = function(editor, options) {\n
        if (!options.needle) return false;\n
        var pos = editor.getCursorPosition();\n
        this.displayOccurContent(editor, options);\n
        var translatedPos = this.originalToOccurPosition(editor.session, pos);\n
        editor.moveCursorToPosition(translatedPos);\n
        return true;\n
    }\n
    this.exit = function(editor, options) {\n
        var pos = options.translatePosition && editor.getCursorPosition();\n
        var translatedPos = pos && this.occurToOriginalPosition(editor.session, pos);\n
        this.displayOriginalContent(editor);\n
        if (translatedPos)\n
            editor.moveCursorToPosition(translatedPos);\n
        return true;\n
    }\n
\n
    this.highlight = function(sess, regexp) {\n
        var hl = sess.$occurHighlight = sess.$occurHighlight || sess.addDynamicMarker(\n
                new SearchHighlight(null, "ace_occur-highlight", "text"));\n
        hl.setRegexp(regexp);\n
        sess._emit("changeBackMarker"); // force highlight layer redraw\n
    }\n
\n
    this.displayOccurContent = function(editor, options) {\n
        this.$originalSession = editor.session;\n
        var found = this.matchingLines(editor.session, options);\n
        var lines = found.map(function(foundLine) { return foundLine.content; });\n
        var occurSession = new EditSession(lines.join(\'\\n\'));\n
        occurSession.$occur = this;\n
        occurSession.$occurMatchingLines = found;\n
        editor.setSession(occurSession);\n
        this.highlight(occurSession, options.re);\n
        occurSession._emit(\'changeBackMarker\');\n
    }\n
\n
    this.displayOriginalContent = function(editor) {\n
        editor.setSession(this.$originalSession);\n
    }\n
    this.originalToOccurPosition = function(session, pos) {\n
        var lines = session.$occurMatchingLines;\n
        var nullPos = {row: 0, column: 0};\n
        if (!lines) return nullPos;\n
        for (var i = 0; i < lines.length; i++) {\n
            if (lines[i].row === pos.row)\n
                return {row: i, column: pos.column};\n
        }\n
        return nullPos;\n
    }\n
    this.occurToOriginalPosition = function(session, pos) {\n
        var lines = session.$occurMatchingLines;\n
        if (!lines || !lines[pos.row])\n
            return pos;\n
        return {row: lines[pos.row].row, column: pos.column};\n
    }\n
\n
    this.matchingLines = function(session, options) {\n
        options = oop.mixin({}, options);\n
        if (!session || !options.needle) return [];\n
        var search = new Search();\n
        search.set(options);\n
        return search.findAll(session).reduce(function(lines, range) {\n
            var row = range.start.row;\n
            var last = lines[lines.length-1];\n
            return last && last.row === row ?\n
                lines :\n
                lines.concat({row: row, content: session.getLine(row)});\n
        }, []);\n
    }\n
\n
}).call(Occur.prototype);\n
\n
var dom = require(\'./lib/dom\');\n
dom.importCssString(".ace_occur-highlight {\\n\\\n
    border-radius: 4px;\\n\\\n
    background-color: rgba(87, 255, 8, 0.25);\\n\\\n
    position: absolute;\\n\\\n
    z-index: 4;\\n\\\n
    -moz-box-sizing: border-box;\\n\\\n
    -webkit-box-sizing: border-box;\\n\\\n
    box-sizing: border-box;\\n\\\n
    box-shadow: 0 0 4px rgb(91, 255, 50);\\n\\\n
}\\n\\\n
.ace_dark .ace_occur-highlight {\\n\\\n
    background-color: rgb(80, 140, 85);\\n\\\n
    box-shadow: 0 0 4px rgb(60, 120, 70);\\n\\\n
}\\n", "incremental-occur-highlighting");\n
\n
exports.Occur = Occur;\n
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
            <value> <int>36745</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>keybinding-emacs.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
