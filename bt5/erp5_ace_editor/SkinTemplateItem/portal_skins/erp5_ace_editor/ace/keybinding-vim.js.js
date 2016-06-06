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
            <value> <string>ts83646622.53</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>keybinding-vim.js</string> </value>
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
 * \n
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
 * \n
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
define(\'ace/keyboard/vim\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/vim/commands\', \'ace/keyboard/vim/maps/util\', \'ace/lib/useragent\'], function(require, exports, module) {\n
\n
\n
var cmds = require("./vim/commands");\n
var coreCommands = cmds.coreCommands;\n
var util = require("./vim/maps/util");\n
var useragent = require("../lib/useragent");\n
\n
var startCommands = {\n
    "i": {\n
        command: coreCommands.start\n
    },\n
    "I": {\n
        command: coreCommands.startBeginning\n
    },\n
    "a": {\n
        command: coreCommands.append\n
    },\n
    "A": {\n
        command: coreCommands.appendEnd\n
    },\n
    "ctrl-f": {\n
        command: "gotopagedown"\n
    },\n
    "ctrl-b": {\n
        command: "gotopageup"\n
    }\n
};\n
\n
exports.handler = {\n
\t$id: "ace/keyboard/vim",\n
    handleMacRepeat: function(data, hashId, key) {\n
        if (hashId == -1) {\n
            data.inputChar = key;\n
            data.lastEvent = "input";\n
        } else if (data.inputChar && data.$lastHash == hashId && data.$lastKey == key) {\n
            if (data.lastEvent == "input") {\n
                data.lastEvent = "input1";\n
            } else if (data.lastEvent == "input1") {\n
                return true;\n
            }\n
        } else {\n
            data.$lastHash = hashId;\n
            data.$lastKey = key;\n
            data.lastEvent = "keypress";\n
        }\n
    },\n
    updateMacCompositionHandlers: function(editor, enable) {\n
        var onCompositionUpdateOverride = function(text) {\n
            if (util.currentMode !== "insert") {\n
                var el = this.textInput.getElement();\n
                el.blur();\n
                el.focus();\n
                el.value = text;\n
            } else {\n
                this.onCompositionUpdateOrig(text);\n
            }\n
        };\n
        var onCompositionStartOverride = function(text) {\n
            if (util.currentMode === "insert") {            \n
                this.onCompositionStartOrig(text);\n
            }\n
        }\n
        if (enable) {\n
            if (!editor.onCompositionUpdateOrig) {\n
                editor.onCompositionUpdateOrig = editor.onCompositionUpdate;\n
                editor.onCompositionUpdate = onCompositionUpdateOverride;\n
                editor.onCompositionStartOrig = editor.onCompositionStart;\n
                editor.onCompositionStart = onCompositionStartOverride;\n
            }\n
        } else {\n
            if (editor.onCompositionUpdateOrig) {\n
                editor.onCompositionUpdate = editor.onCompositionUpdateOrig;\n
                editor.onCompositionUpdateOrig = null;\n
                editor.onCompositionStart = editor.onCompositionStartOrig;\n
                editor.onCompositionStartOrig = null;\n
            }\n
        }\n
    },\n
\n
    handleKeyboard: function(data, hashId, key, keyCode, e) {\n
        if (hashId != 0 && (key == "" || key == "\\x00"))\n
            return null;\n
        \n
        var editor = data.editor;\n
        \n
        if (hashId == 1)\n
            key = "ctrl-" + key;\n
        if (key == "ctrl-c") {\n
            if (!useragent.isMac && editor.getCopyText()) {\n
                editor.once("copy", function() {\n
                    if (data.state == "start")\n
                        coreCommands.stop.exec(editor);\n
                    else\n
                        editor.selection.clearSelection();\n
                });\n
                return {command: "null", passEvent: true};\n
            }\n
            return {command: coreCommands.stop};            \n
        } else if ((key == "esc" && hashId == 0) || key == "ctrl-[") {\n
            return {command: coreCommands.stop};\n
        } else if (data.state == "start") {\n
            if (useragent.isMac && this.handleMacRepeat(data, hashId, key)) {\n
                hashId = -1;\n
                key = data.inputChar;\n
            }\n
            \n
            if (hashId == -1 || hashId == 1 || hashId == 0 && key.length > 1) {\n
                if (cmds.inputBuffer.idle && startCommands[key])\n
                    return startCommands[key];\n
                cmds.inputBuffer.push(editor, key);\n
                return {command: "null", passEvent: false}; \n
            } // if no modifier || shift: wait for input.\n
            else if (key.length == 1 && (hashId == 0 || hashId == 4)) {\n
                return {command: "null", passEvent: true};\n
            } else if (key == "esc" && hashId == 0) {\n
                return {command: coreCommands.stop};\n
            }\n
        } else {\n
            if (key == "ctrl-w") {\n
                return {command: "removewordleft"};\n
            }\n
        }\n
    },\n
\n
    attach: function(editor) {\n
        editor.on("click", exports.onCursorMove);\n
        if (util.currentMode !== "insert")\n
            cmds.coreCommands.stop.exec(editor);\n
        editor.$vimModeHandler = this;\n
        \n
        this.updateMacCompositionHandlers(editor, true);\n
    },\n
\n
    detach: function(editor) {\n
        editor.removeListener("click", exports.onCursorMove);\n
        util.noMode(editor);\n
        util.currentMode = "normal";\n
        this.updateMacCompositionHandlers(editor, false);\n
    },\n
\n
    actions: cmds.actions,\n
    getStatusText: function() {\n
        if (util.currentMode == "insert")\n
            return "INSERT";\n
        if (util.onVisualMode)\n
            return (util.onVisualLineMode ? "VISUAL LINE " : "VISUAL ") + cmds.inputBuffer.status;\n
        return cmds.inputBuffer.status;\n
    }\n
};\n
\n
\n
exports.onCursorMove = function(e) {\n
    cmds.onCursorMove(e.editor, e);\n
    exports.onCursorMove.scheduled = false;\n
};\n
\n
});\n
 \n
define(\'ace/keyboard/vim/commands\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/keyboard/vim/maps/util\', \'ace/keyboard/vim/maps/motions\', \'ace/keyboard/vim/maps/operators\', \'ace/keyboard/vim/maps/aliases\', \'ace/keyboard/vim/registers\'], function(require, exports, module) {\n
\n
"never use strict";\n
\n
var lang = require("../../lib/lang");\n
var util = require("./maps/util");\n
var motions = require("./maps/motions");\n
var operators = require("./maps/operators");\n
var alias = require("./maps/aliases");\n
var registers = require("./registers");\n
\n
var NUMBER = 1;\n
var OPERATOR = 2;\n
var MOTION = 3;\n
var ACTION = 4;\n
var HMARGIN = 8; // Minimum amount of line separation between margins;\n
\n
var repeat = function repeat(fn, count, args) {\n
    while (0 < count--)\n
        fn.apply(this, args);\n
};\n
\n
var ensureScrollMargin = function(editor) {\n
    var renderer = editor.renderer;\n
    var pos = renderer.$cursorLayer.getPixelPosition();\n
\n
    var top = pos.top;\n
\n
    var margin = HMARGIN * renderer.layerConfig.lineHeight;\n
    if (2 * margin > renderer.$size.scrollerHeight)\n
        margin = renderer.$size.scrollerHeight / 2;\n
\n
    if (renderer.scrollTop > top - margin) {\n
        renderer.session.setScrollTop(top - margin);\n
    }\n
\n
    if (renderer.scrollTop + renderer.$size.scrollerHeight < top + margin + renderer.lineHeight) {\n
        renderer.session.setScrollTop(top + margin + renderer.lineHeight - renderer.$size.scrollerHeight);\n
    }\n
};\n
\n
var actions = exports.actions = {\n
    "z": {\n
        param: true,\n
        fn: function(editor, range, count, param) {\n
            switch (param) {\n
                case "z":\n
                    editor.renderer.alignCursor(null, 0.5);\n
                    break;\n
                case "t":\n
                    editor.renderer.alignCursor(null, 0);\n
                    break;\n
                case "b":\n
                    editor.renderer.alignCursor(null, 1);\n
                    break;\n
                case "c":\n
                    editor.session.onFoldWidgetClick(range.start.row, {domEvent:{target :{}}});\n
                    break;\n
                case "o":\n
                    editor.session.onFoldWidgetClick(range.start.row, {domEvent:{target :{}}});\n
                    break;\n
                case "C":\n
                    editor.session.foldAll();\n
                    break;\n
                case "O":\n
                    editor.session.unfold();\n
                    break;\n
            }\n
        }\n
    },\n
    "r": {\n
        param: true,\n
        fn: function(editor, range, count, param) {\n
            if (param && param.length) {\n
                if (param.length > 1)\n
                    param = param == "return" ? "\\n" : param == "tab" ? "\\t" : param;\n
                repeat(function() { editor.insert(param); }, count || 1);\n
                editor.navigateLeft();\n
            }\n
        }\n
    },\n
    "R": {\n
        fn: function(editor, range, count, param) {\n
            util.insertMode(editor);\n
            editor.setOverwrite(true);\n
        }\n
    },\n
    "~": {\n
        fn: function(editor, range, count) {\n
            repeat(function() {\n
                var range = editor.selection.getRange();\n
                if (range.isEmpty())\n
                    range.end.column++;\n
                var text = editor.session.getTextRange(range);\n
                var toggled = text.toUpperCase();\n
                if (toggled == text)\n
                    editor.navigateRight();\n
                else\n
                    editor.session.replace(range, toggled);\n
            }, count || 1);\n
        }\n
    },\n
    "*": {\n
        fn: function(editor, range, count, param) {\n
            editor.selection.selectWord();\n
            editor.findNext();\n
            ensureScrollMargin(editor);\n
            var r = editor.selection.getRange();\n
            editor.selection.setSelectionRange(r, true);\n
        }\n
    },\n
    "#": {\n
        fn: function(editor, range, count, param) {\n
            editor.selection.selectWord();\n
            editor.findPrevious();\n
            ensureScrollMargin(editor);\n
            var r = editor.selection.getRange();\n
            editor.selection.setSelectionRange(r, true);\n
        }\n
    },\n
    "m": {\n
        param: true,\n
        fn: function(editor, range, count, param) {\n
            var s =  editor.session;\n
            var markers = s.vimMarkers || (s.vimMarkers = {});\n
            var c = editor.getCursorPosition();\n
            if (!markers[param]) {\n
                markers[param] = editor.session.doc.createAnchor(c);\n
            }\n
            markers[param].setPosition(c.row, c.column, true);\n
        }\n
    },\n
    "n": {\n
        fn: function(editor, range, count, param) {\n
            var options = editor.getLastSearchOptions();\n
            options.backwards = false;\n
\n
            editor.selection.moveCursorRight();\n
            editor.selection.clearSelection();\n
            editor.findNext(options);\n
\n
            ensureScrollMargin(editor);\n
            var r = editor.selection.getRange();\n
            r.end.row = r.start.row;\n
            r.end.column = r.start.column;\n
            editor.selection.setSelectionRange(r, true);\n
        }\n
    },\n
    "N": {\n
        fn: function(editor, range, count, param) {\n
            var options = editor.getLastSearchOptions();\n
            options.backwards = true;\n
\n
            editor.findPrevious(options);\n
            ensureScrollMargin(editor);\n
            var r = editor.selection.getRange();\n
            r.end.row = r.start.row;\n
            r.end.column = r.start.column;\n
            editor.selection.setSelectionRange(r, true);\n
        }\n
    },\n
    "v": {\n
        fn: function(editor, range, count, param) {\n
            editor.selection.selectRight();\n
            util.visualMode(editor, false);\n
        },\n
        acceptsMotion: true\n
    },\n
    "V": {\n
        fn: function(editor, range, count, param) {\n
            var row = editor.getCursorPosition().row;\n
            editor.selection.clearSelection();\n
            editor.selection.moveCursorTo(row, 0);\n
            editor.selection.selectLineEnd();\n
            editor.selection.visualLineStart = row;\n
\n
            util.visualMode(editor, true);\n
        },\n
        acceptsMotion: true\n
    },\n
    "Y": {\n
        fn: function(editor, range, count, param) {\n
            util.copyLine(editor);\n
        }\n
    },\n
    "p": {\n
        fn: function(editor, range, count, param) {\n
            var defaultReg = registers._default;\n
\n
            editor.setOverwrite(false);\n
            if (defaultReg.isLine) {\n
                var pos = editor.getCursorPosition();\n
                pos.column = editor.session.getLine(pos.row).length;\n
                var text = lang.stringRepeat("\\n" + defaultReg.text, count || 1);\n
                editor.session.insert(pos, text);\n
                editor.moveCursorTo(pos.row + 1, 0);\n
            }\n
            else {\n
                editor.navigateRight();\n
                editor.insert(lang.stringRepeat(defaultReg.text, count || 1));\n
                editor.navigateLeft();\n
            }\n
            editor.setOverwrite(true);\n
            editor.selection.clearSelection();\n
        }\n
    },\n
    "P": {\n
        fn: function(editor, range, count, param) {\n
            var defaultReg = registers._default;\n
            editor.setOverwrite(false);\n
\n
            if (defaultReg.isLine) {\n
                var pos = editor.getCursorPosition();\n
                pos.column = 0;\n
                var text = lang.stringRepeat(defaultReg.text + "\\n", count || 1);\n
                editor.session.insert(pos, text);\n
                editor.moveCursorToPosition(pos);\n
            }\n
            else {\n
                editor.insert(lang.stringRepeat(defaultReg.text, count || 1));\n
            }\n
            editor.setOverwrite(true);\n
            editor.selection.clearSelection();\n
        }\n
    },\n
    "J": {\n
        fn: function(editor, range, count, param) {\n
            var session = editor.session;\n
            range = editor.getSelectionRange();\n
            var pos = {row: range.start.row, column: range.start.column};\n
            count = count || range.end.row - range.start.row;\n
            var maxRow = Math.min(pos.row + (count || 1), session.getLength() - 1);\n
\n
            range.start.column = session.getLine(pos.row).length;\n
            range.end.column = session.getLine(maxRow).length;\n
            range.end.row = maxRow;\n
\n
            var text = "";\n
            for (var i = pos.row; i < maxRow; i++) {\n
                var nextLine = session.getLine(i + 1);\n
                text += " " + /^\\s*(.*)$/.exec(nextLine)[1] || "";\n
            }\n
\n
            session.replace(range, text);\n
            editor.moveCursorTo(pos.row, pos.column);\n
        }\n
    },\n
    "u": {\n
        fn: function(editor, range, count, param) {\n
            count = parseInt(count || 1, 10);\n
            for (var i = 0; i < count; i++) {\n
                editor.undo();\n
            }\n
            editor.selection.clearSelection();\n
        }\n
    },\n
    "ctrl-r": {\n
        fn: function(editor, range, count, param) {\n
            count = parseInt(count || 1, 10);\n
            for (var i = 0; i < count; i++) {\n
                editor.redo();\n
            }\n
            editor.selection.clearSelection();\n
        }\n
    },\n
    ":": {\n
        fn: function(editor, range, count, param) {\n
            var val = ":";\n
            if (count > 1)\n
                val = ".,.+" + count + val;\n
            if (editor.showCommandLine)\n
                editor.showCommandLine(val);\n
        }\n
    },\n
    "/": {\n
        fn: function(editor, range, count, param) {\n
            if (editor.showCommandLine)\n
                editor.showCommandLine("/");\n
        }\n
    },\n
    "?": {\n
        fn: function(editor, range, count, param) {\n
            if (editor.showCommandLine)\n
                editor.showCommandLine("?");\n
        }\n
    },\n
    ".": {\n
        fn: function(editor, range, count, param) {\n
            util.onInsertReplaySequence = inputBuffer.lastInsertCommands;\n
            var previous = inputBuffer.previous;\n
            if (previous) // If there is a previous action\n
                inputBuffer.exec(editor, previous.action, previous.param);\n
        }\n
    },\n
    "ctrl-x": {\n
        fn: function(editor, range, count, param) {\n
            editor.modifyNumber(-(count || 1));\n
        }\n
    },\n
    "ctrl-a": {\n
        fn: function(editor, range, count, param) {\n
            editor.modifyNumber(count || 1);\n
        }\n
    }\n
};\n
\n
var inputBuffer = exports.inputBuffer = {\n
    accepting: [NUMBER, OPERATOR, MOTION, ACTION],\n
    currentCmd: null,\n
    currentCount: "",\n
    status: "",\n
    operator: null,\n
    motion: null,\n
\n
    lastInsertCommands: [],\n
\n
    push: function(editor, ch, keyId) {\n
        var status = this.status;\n
        var isKeyHandled = true;\n
        this.idle = false;\n
        var wObj = this.waitingForParam;\n
        if (/^numpad\\d+$/i.test(ch))\n
            ch = ch.substr(6);\n
            \n
        if (wObj) {\n
            this.exec(editor, wObj, ch);\n
        }\n
        else if (!(ch === "0" && !this.currentCount.length) &&\n
            (/^\\d+$/.test(ch) && this.isAccepting(NUMBER))) {\n
            this.currentCount += ch;\n
            this.currentCmd = NUMBER;\n
            this.accepting = [NUMBER, OPERATOR, MOTION, ACTION];\n
        }\n
        else if (!this.operator && this.isAccepting(OPERATOR) && operators[ch]) {\n
            this.operator = {\n
                ch: ch,\n
                count: this.getCount()\n
            };\n
            this.currentCmd = OPERATOR;\n
            this.accepting = [NUMBER, MOTION, ACTION];\n
            this.exec(editor, { operator: this.operator });\n
        }\n
        else if (motions[ch] && this.isAccepting(MOTION)) {\n
            this.currentCmd = MOTION;\n
\n
            var ctx = {\n
                operator: this.operator,\n
                motion: {\n
                    ch: ch,\n
                    count: this.getCount()\n
                }\n
            };\n
\n
            if (motions[ch].param)\n
                this.waitForParam(ctx);\n
            else\n
                this.exec(editor, ctx);\n
        }\n
        else if (alias[ch] && this.isAccepting(MOTION)) {\n
            alias[ch].operator.count = this.getCount();\n
            this.exec(editor, alias[ch]);\n
        }\n
        else if (actions[ch] && this.isAccepting(ACTION)) {\n
            var actionObj = {\n
                action: {\n
                    fn: actions[ch].fn,\n
                    count: this.getCount()\n
                }\n
            };\n
\n
            if (actions[ch].param) {\n
                this.waitForParam(actionObj);\n
            }\n
            else {\n
                this.exec(editor, actionObj);\n
            }\n
\n
            if (actions[ch].acceptsMotion)\n
                this.idle = false;\n
        }\n
        else if (this.operator) {\n
            this.operator.count = this.getCount();\n
            this.exec(editor, { operator: this.operator }, ch);\n
        }\n
        else {\n
            isKeyHandled = ch.length == 1;\n
            this.reset();\n
        }\n
        \n
        if (this.waitingForParam || this.motion || this.operator) {\n
            this.status += ch;\n
        } else if (this.currentCount) {\n
            this.status = this.currentCount;\n
        } else if (this.status) {\n
            this.status = "";\n
        }\n
        if (this.status != status)\n
            editor._emit("changeStatus");\n
        return isKeyHandled;\n
    },\n
\n
    waitForParam: function(cmd) {\n
        this.waitingForParam = cmd;\n
    },\n
\n
    getCount: function() {\n
        var count = this.currentCount;\n
        this.currentCount = "";\n
        return count && parseInt(count, 10);\n
    },\n
\n
    exec: function(editor, action, param) {\n
        var m = action.motion;\n
        var o = action.operator;\n
        var a = action.action;\n
\n
        if (!param)\n
            param = action.param;\n
\n
        if (o) {\n
            this.previous = {\n
                action: action,\n
                param: param\n
            };\n
        }\n
\n
        if (o && !editor.selection.isEmpty()) {\n
            if (operators[o.ch].selFn) {\n
                operators[o.ch].selFn(editor, editor.getSelectionRange(), o.count, param);\n
                this.reset();\n
            }\n
            return;\n
        }\n
        else if (!m && !a && o && param) {\n
            operators[o.ch].fn(editor, null, o.count, param);\n
            this.reset();\n
        }\n
        else if (m) {\n
            var run = function(fn) {\n
                if (fn && typeof fn === "function") { // There should always be a motion\n
                    if (m.count && !motionObj.handlesCount)\n
                        repeat(fn, m.count, [editor, null, m.count, param]);\n
                    else\n
                        fn(editor, null, m.count, param);\n
                }\n
            };\n
\n
            var motionObj = motions[m.ch];\n
            var selectable = motionObj.sel;\n
\n
            if (!o) {\n
                if ((util.onVisualMode || util.onVisualLineMode) && selectable)\n
                    run(motionObj.sel);\n
                else\n
                    run(motionObj.nav);\n
            }\n
            else if (selectable) {\n
                repeat(function() {\n
                    run(motionObj.sel);\n
                    operators[o.ch].fn(editor, editor.getSelectionRange(), o.count, param);\n
                }, o.count || 1);\n
            }\n
            this.reset();\n
        }\n
        else if (a) {\n
            a.fn(editor, editor.getSelectionRange(), a.count, param);\n
            this.reset();\n
        }\n
        handleCursorMove(editor);\n
    },\n
\n
    isAccepting: function(type) {\n
        return this.accepting.indexOf(type) !== -1;\n
    },\n
\n
    reset: function() {\n
        this.operator = null;\n
        this.motion = null;\n
        this.currentCount = "";\n
        this.status = "";\n
        this.accepting = [NUMBER, OPERATOR, MOTION, ACTION];\n
        this.idle = true;\n
        this.waitingForParam = null;\n
    }\n
};\n
\n
function setPreviousCommand(fn) {\n
    inputBuffer.previous = { action: { action: { fn: fn } } };\n
}\n
\n
exports.coreCommands = {\n
    start: {\n
        exec: function start(editor) {\n
            util.insertMode(editor);\n
            setPreviousCommand(start);\n
        }\n
    },\n
    startBeginning: {\n
        exec: function startBeginning(editor) {\n
            editor.navigateLineStart();\n
            util.insertMode(editor);\n
            setPreviousCommand(startBeginning);\n
        }\n
    },\n
    stop: {\n
        exec: function stop(editor) {\n
            inputBuffer.reset();\n
            util.onVisualMode = false;\n
            util.onVisualLineMode = false;\n
            inputBuffer.lastInsertCommands = util.normalMode(editor);\n
        }\n
    },\n
    append: {\n
        exec: function append(editor) {\n
            var pos = editor.getCursorPosition();\n
            var lineLen = editor.session.getLine(pos.row).length;\n
            if (lineLen)\n
                editor.navigateRight();\n
            util.insertMode(editor);\n
            setPreviousCommand(append);\n
        }\n
    },\n
    appendEnd: {\n
        exec: function appendEnd(editor) {\n
            editor.navigateLineEnd();\n
            util.insertMode(editor);\n
            setPreviousCommand(appendEnd);\n
        }\n
    }\n
};\n
\n
var handleCursorMove = exports.onCursorMove = function(editor, e) {\n
    if (util.currentMode === \'insert\' || handleCursorMove.running)\n
        return;\n
    else if(!editor.selection.isEmpty()) {\n
        handleCursorMove.running = true;\n
        if (util.onVisualLineMode) {\n
            var originRow = editor.selection.visualLineStart;\n
            var cursorRow = editor.getCursorPosition().row;\n
            if(originRow <= cursorRow) {\n
                var endLine = editor.session.getLine(cursorRow);\n
                editor.selection.clearSelection();\n
                editor.selection.moveCursorTo(originRow, 0);\n
                editor.selection.selectTo(cursorRow, endLine.length);\n
            } else {\n
                var endLine = editor.session.getLine(originRow);\n
                editor.selection.clearSelection();\n
                editor.selection.moveCursorTo(originRow, endLine.length);\n
                editor.selection.selectTo(cursorRow, 0);\n
            }\n
        }\n
        handleCursorMove.running = false;\n
        return;\n
    }\n
    else {\n
        if (e && (util.onVisualLineMode || util.onVisualMode)) {\n
            editor.selection.clearSelection();\n
            util.normalMode(editor);\n
        }\n
\n
        handleCursorMove.running = true;\n
        var pos = editor.getCursorPosition();\n
        var lineLen = editor.session.getLine(pos.row).length;\n
\n
        if (lineLen && pos.column === lineLen)\n
            editor.navigateLeft();\n
        handleCursorMove.running = false;\n
    }\n
};\n
});\n
define(\'ace/keyboard/vim/maps/util\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/vim/registers\', \'ace/lib/dom\'], function(require, exports, module) {\n
var registers = require("../registers");\n
\n
var dom = require("../../../lib/dom");\n
dom.importCssString(\'.insert-mode .ace_cursor{\\\n
    border-left: 2px solid #333333;\\\n
}\\\n
.ace_dark.insert-mode .ace_cursor{\\\n
    border-left: 2px solid #eeeeee;\\\n
}\\\n
.normal-mode .ace_cursor{\\\n
    border: 0!important;\\\n
    background-color: red;\\\n
    opacity: 0.5;\\\n
}\', \'vimMode\');\n
\n
module.exports = {\n
    onVisualMode: false,\n
    onVisualLineMode: false,\n
    currentMode: \'normal\',\n
    noMode: function(editor) {\n
        editor.unsetStyle(\'insert-mode\');\n
        editor.unsetStyle(\'normal-mode\');\n
        if (editor.commands.recording)\n
            editor.commands.toggleRecording(editor);\n
        editor.setOverwrite(false);\n
    },\n
    insertMode: function(editor) {\n
        this.currentMode = \'insert\';\n
        editor.setStyle(\'insert-mode\');\n
        editor.unsetStyle(\'normal-mode\');\n
\n
        editor.setOverwrite(false);\n
        editor.keyBinding.$data.buffer = "";\n
        editor.keyBinding.$data.state = "insertMode";\n
        this.onVisualMode = false;\n
        this.onVisualLineMode = false;\n
        if(this.onInsertReplaySequence) {\n
            editor.commands.macro = this.onInsertReplaySequence;\n
            editor.commands.replay(editor);\n
            this.onInsertReplaySequence = null;\n
            this.normalMode(editor);\n
        } else {\n
            editor._emit("changeStatus");\n
            if(!editor.commands.recording)\n
                editor.commands.toggleRecording(editor);\n
        }\n
    },\n
    normalMode: function(editor) {\n
        this.currentMode = \'normal\';\n
\n
        editor.unsetStyle(\'insert-mode\');\n
        editor.setStyle(\'normal-mode\');\n
        editor.clearSelection();\n
\n
        var pos;\n
        if (!editor.getOverwrite()) {\n
            pos = editor.getCursorPosition();\n
            if (pos.column > 0)\n
                editor.navigateLeft();\n
        }\n
\n
        editor.setOverwrite(true);\n
        editor.keyBinding.$data.buffer = "";\n
        editor.keyBinding.$data.state = "start";\n
        this.onVisualMode = false;\n
        this.onVisualLineMode = false;\n
        editor._emit("changeStatus");\n
        if (editor.commands.recording) {\n
            editor.commands.toggleRecording(editor);\n
            return editor.commands.macro;\n
        }\n
        else {\n
            return [];\n
        }\n
    },\n
    visualMode: function(editor, lineMode) {\n
        if (\n
            (this.onVisualLineMode && lineMode)\n
            || (this.onVisualMode && !lineMode)\n
        ) {\n
            this.normalMode(editor);\n
            return;\n
        }\n
\n
        editor.setStyle(\'insert-mode\');\n
        editor.unsetStyle(\'normal-mode\');\n
\n
        editor._emit("changeStatus");\n
        if (lineMode) {\n
            this.onVisualLineMode = true;\n
        } else {\n
            this.onVisualMode = true;\n
            this.onVisualLineMode = false;\n
        }\n
    },\n
    getRightNthChar: function(editor, cursor, ch, n) {\n
        var line = editor.getSession().getLine(cursor.row);\n
        var matches = line.substr(cursor.column + 1).split(ch);\n
\n
        return n < matches.length ? matches.slice(0, n).join(ch).length : null;\n
    },\n
    getLeftNthChar: function(editor, cursor, ch, n) {\n
        var line = editor.getSession().getLine(cursor.row);\n
        var matches = line.substr(0, cursor.column).split(ch);\n
\n
        return n < matches.length ? matches.slice(-1 * n).join(ch).length : null;\n
    },\n
    toRealChar: function(ch) {\n
        if (ch.length === 1)\n
            return ch;\n
\n
        if (/^shift-./.test(ch))\n
            return ch[ch.length - 1].toUpperCase();\n
        else\n
            return "";\n
    },\n
    copyLine: function(editor) {\n
        var pos = editor.getCursorPosition();\n
        editor.selection.clearSelection();\n
        editor.moveCursorTo(pos.row, pos.column);\n
        editor.selection.selectLine();\n
        registers._default.isLine = true;\n
        registers._default.text = editor.getCopyText().replace(/\\n$/, "");\n
        editor.selection.clearSelection();\n
        editor.moveCursorTo(pos.row, pos.column);\n
    }\n
};\n
});\n
\n
define(\'ace/keyboard/vim/registers\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
"never use strict";\n
\n
module.exports = {\n
    _default: {\n
        text: "",\n
        isLine: false\n
    }\n
};\n
\n
});\n
\n
\n
define(\'ace/keyboard/vim/maps/motions\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/vim/maps/util\', \'ace/search\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var util = require("./util");\n
\n
var keepScrollPosition = function(editor, fn) {\n
    var scrollTopRow = editor.renderer.getScrollTopRow();\n
    var initialRow = editor.getCursorPosition().row;\n
    var diff = initialRow - scrollTopRow;\n
    fn && fn.call(editor);\n
    editor.renderer.scrollToRow(editor.getCursorPosition().row - diff);\n
};\n
\n
function Motion(m) {\n
    if (typeof m == "function") {\n
        var getPos = m;\n
        m = this;\n
    } else {\n
        var getPos = m.getPos;\n
    }\n
    m.nav = function(editor, range, count, param) {\n
        var a = getPos(editor, range, count, param, false);\n
        if (!a)\n
            return;\n
        editor.clearSelection();\n
        editor.moveCursorTo(a.row, a.column);\n
    };\n
    m.sel = function(editor, range, count, param) {\n
        var a = getPos(editor, range, count, param, true);\n
        if (!a)\n
            return;\n
        editor.selection.selectTo(a.row, a.column);\n
    };\n
    return m;\n
}\n
\n
var nonWordRe = /[\\s.\\/\\\\()\\"\'-:,.;<>~!@#$%^&*|+=\\[\\]{}`~?]/;\n
var wordSeparatorRe = /[.\\/\\\\()\\"\'-:,.;<>~!@#$%^&*|+=\\[\\]{}`~?]/;\n
var whiteRe = /\\s/;\n
var StringStream = function(editor, cursor) {\n
    var sel = editor.selection;\n
    this.range = sel.getRange();\n
    cursor = cursor || sel.selectionLead;\n
    this.row = cursor.row;\n
    this.col = cursor.column;\n
    var line = editor.session.getLine(this.row);\n
    var maxRow = editor.session.getLength();\n
    this.ch = line[this.col] || \'\\n\';\n
    this.skippedLines = 0;\n
\n
    this.next = function() {\n
        this.ch = line[++this.col] || this.handleNewLine(1);\n
        return this.ch;\n
    };\n
    this.prev = function() {\n
        this.ch = line[--this.col] || this.handleNewLine(-1);\n
        return this.ch;\n
    };\n
    this.peek = function(dir) {\n
        var ch = line[this.col + dir];\n
        if (ch)\n
            return ch;\n
        if (dir == -1)\n
            return \'\\n\';\n
        if (this.col == line.length - 1)\n
            return \'\\n\';\n
        return editor.session.getLine(this.row + 1)[0] || \'\\n\';\n
    };\n
\n
    this.handleNewLine = function(dir) {\n
        if (dir == 1){\n
            if (this.col == line.length)\n
                return \'\\n\';\n
            if (this.row == maxRow - 1)\n
                return \'\';\n
            this.col = 0;\n
            this.row ++;\n
            line = editor.session.getLine(this.row);\n
            this.skippedLines++;\n
            return line[0] || \'\\n\';\n
        }\n
        if (dir == -1) {\n
            if (this.row === 0)\n
                return \'\';\n
            this.row --;\n
            line = editor.session.getLine(this.row);\n
            this.col = line.length;\n
            this.skippedLines--;\n
            return \'\\n\';\n
        }\n
    };\n
    this.debug = function() {\n
        console.log(line.substring(0, this.col)+\'|\'+this.ch+\'\\\'\'+this.col+\'\\\'\'+line.substr(this.col+1));\n
    };\n
};\n
\n
var Search = require("../../../search").Search;\n
var search = new Search();\n
\n
function find(editor, needle, dir) {\n
    search.$options.needle = needle;\n
    search.$options.backwards = dir == -1;\n
    return search.find(editor.session);\n
}\n
\n
var Range = require("../../../range").Range;\n
\n
var LAST_SEARCH_MOTION = {};\n
\n
module.exports = {\n
    "w": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
\n
        if (str.ch && wordSeparatorRe.test(str.ch)) {\n
            while (str.ch && wordSeparatorRe.test(str.ch))\n
                str.next();\n
        } else {\n
            while (str.ch && !nonWordRe.test(str.ch))\n
                str.next();\n
        }\n
        while (str.ch && whiteRe.test(str.ch) && str.skippedLines < 2)\n
            str.next();\n
\n
        str.skippedLines == 2 && str.prev();\n
        return {column: str.col, row: str.row};\n
    }),\n
    "W": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
        while(str.ch && !(whiteRe.test(str.ch) && !whiteRe.test(str.peek(1))) && str.skippedLines < 2)\n
            str.next();\n
        if (str.skippedLines == 2)\n
            str.prev();\n
        else\n
            str.next();\n
\n
        return {column: str.col, row: str.row};\n
    }),\n
    "b": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
\n
        str.prev();\n
        while (str.ch && whiteRe.test(str.ch) && str.skippedLines > -2)\n
            str.prev();\n
\n
        if (str.ch && wordSeparatorRe.test(str.ch)) {\n
            while (str.ch && wordSeparatorRe.test(str.ch))\n
                str.prev();\n
        } else {\n
            while (str.ch && !nonWordRe.test(str.ch))\n
                str.prev();\n
        }\n
        str.ch && str.next();\n
        return {column: str.col, row: str.row};\n
    }),\n
    "B": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
        str.prev();\n
        while(str.ch && !(!whiteRe.test(str.ch) && whiteRe.test(str.peek(-1))) && str.skippedLines > -2)\n
            str.prev();\n
\n
        if (str.skippedLines == -2)\n
            str.next();\n
\n
        return {column: str.col, row: str.row};\n
    }),\n
    "e": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
\n
        str.next();\n
        while (str.ch && whiteRe.test(str.ch))\n
            str.next();\n
\n
        if (str.ch && wordSeparatorRe.test(str.ch)) {\n
            while (str.ch && wordSeparatorRe.test(str.ch))\n
                str.next();\n
        } else {\n
            while (str.ch && !nonWordRe.test(str.ch))\n
                str.next();\n
        }\n
        str.ch && str.prev();\n
        return {column: str.col, row: str.row};\n
    }),\n
    "E": new Motion(function(editor) {\n
        var str = new StringStream(editor);\n
        str.next();\n
        while(str.ch && !(!whiteRe.test(str.ch) && whiteRe.test(str.peek(1))))\n
            str.next();\n
\n
        return {column: str.col, row: str.row};\n
    }),\n
\n
    "l": {\n
        nav: function(editor) {\n
            var pos = editor.getCursorPosition();\n
            var col = pos.column;\n
            var lineLen = editor.session.getLine(pos.row).length;\n
            if (lineLen && col !== lineLen)\n
                editor.navigateRight();\n
        },\n
        sel: function(editor) {\n
            var pos = editor.getCursorPosition();\n
            var col = pos.column;\n
            var lineLen = editor.session.getLine(pos.row).length;\n
            if (lineLen && col !== lineLen) //In selection mode you can select the newline\n
                editor.selection.selectRight();\n
        }\n
    },\n
    "h": {\n
        nav: function(editor) {\n
            var pos = editor.getCursorPosition();\n
            if (pos.column > 0)\n
                editor.navigateLeft();\n
        },\n
        sel: function(editor) {\n
            var pos = editor.getCursorPosition();\n
            if (pos.column > 0)\n
                editor.selection.selectLeft();\n
        }\n
    },\n
    "H": {\n
        nav: function(editor) {\n
            var row = editor.renderer.getScrollTopRow();\n
            editor.moveCursorTo(row);\n
        },\n
        sel: function(editor) {\n
            var row = editor.renderer.getScrollTopRow();\n
            editor.selection.selectTo(row);\n
        }\n
    },\n
    "M": {\n
        nav: function(editor) {\n
            var topRow = editor.renderer.getScrollTopRow();\n
            var bottomRow = editor.renderer.getScrollBottomRow();\n
            var row = topRow + ((bottomRow - topRow) / 2);\n
            editor.moveCursorTo(row);\n
        },\n
        sel: function(editor) {\n
            var topRow = editor.renderer.getScrollTopRow();\n
            var bottomRow = editor.renderer.getScrollBottomRow();\n
            var row = topRow + ((bottomRow - topRow) / 2);\n
            editor.selection.selectTo(row);\n
        }\n
    },\n
    "L": {\n
        nav: function(editor) {\n
            var row = editor.renderer.getScrollBottomRow();\n
            editor.moveCursorTo(row);\n
        },\n
        sel: function(editor) {\n
            var row = editor.renderer.getScrollBottomRow();\n
            editor.selection.selectTo(row);\n
        }\n
    },\n
    "k": {\n
        nav: function(editor) {\n
            editor.navigateUp();\n
        },\n
        sel: function(editor) {\n
            editor.selection.selectUp();\n
        }\n
    },\n
    "j": {\n
        nav: function(editor) {\n
            editor.navigateDown();\n
        },\n
        sel: function(editor) {\n
            editor.selection.selectDown();\n
        }\n
    },\n
\n
    "i": {\n
        param: true,\n
        sel: function(editor, range, count, param) {\n
            switch (param) {\n
                case "w":\n
                    editor.selection.selectWord();\n
                    break;\n
                case "W":\n
                    editor.selection.selectAWord();\n
                    break;\n
                case "(":\n
                case "{":\n
                case "[":\n
                    var cursor = editor.getCursorPosition();\n
                    var end = editor.session.$findClosingBracket(param, cursor, /paren/);\n
                    if (!end)\n
                        return;\n
                    var start = editor.session.$findOpeningBracket(editor.session.$brackets[param], cursor, /paren/);\n
                    if (!start)\n
                        return;\n
                    start.column ++;\n
                    editor.selection.setSelectionRange(Range.fromPoints(start, end));\n
                    break;\n
                case "\'":\n
                case \'"\':\n
                case "/":\n
                    var end = find(editor, param, 1);\n
                    if (!end)\n
                        return;\n
                    var start = find(editor, param, -1);\n
                    if (!start)\n
                        return;\n
                    editor.selection.setSelectionRange(Range.fromPoints(start.end, end.start));\n
                    break;\n
            }\n
        }\n
    },\n
    "a": {\n
        param: true,\n
        sel: function(editor, range, count, param) {\n
            switch (param) {\n
                case "w":\n
                    editor.selection.selectAWord();\n
                    break;\n
                case "W":\n
                    editor.selection.selectAWord();\n
                    break;\n
                case "(":\n
                case "{":\n
                case "[":\n
                    var cursor = editor.getCursorPosition();\n
                    var end = editor.session.$findClosingBracket(param, cursor, /paren/);\n
                    if (!end)\n
                        return;\n
                    var start = editor.session.$findOpeningBracket(editor.session.$brackets[param], cursor, /paren/);\n
                    if (!start)\n
                        return;\n
                    end.column ++;\n
                    editor.selection.setSelectionRange(Range.fromPoints(start, end));\n
                    break;\n
                case "\'":\n
                case "\\"":\n
                case "/":\n
                    var end = find(editor, param, 1);\n
                    if (!end)\n
                        return;\n
                    var start = find(editor, param, -1);\n
                    if (!start)\n
                        return;\n
                    end.column ++;\n
                    editor.selection.setSelectionRange(Range.fromPoints(start.start, end.end));\n
                    break;\n
            }\n
        }\n
    },\n
\n
    "f": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel, isRepeat) {\n
            if (!isRepeat)\n
                LAST_SEARCH_MOTION = {ch: "f", param: param};\n
            var cursor = editor.getCursorPosition();\n
            var column = util.getRightNthChar(editor, cursor, param, count || 1);\n
\n
            if (typeof column === "number") {\n
                cursor.column += column + (isSel ? 2 : 1);\n
                return cursor;\n
            }\n
        }\n
    }),\n
    "F": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel, isRepeat) {\n
            if (!isRepeat)\n
                LAST_SEARCH_MOTION = {ch: "F", param: param};\n
            var cursor = editor.getCursorPosition();\n
            var column = util.getLeftNthChar(editor, cursor, param, count || 1);\n
\n
            if (typeof column === "number") {\n
                cursor.column -= column + 1;\n
                return cursor;\n
            }\n
        }\n
    }),\n
    "t": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel, isRepeat) {\n
            if (!isRepeat)\n
                LAST_SEARCH_MOTION = {ch: "t", param: param};\n
            var cursor = editor.getCursorPosition();\n
            var column = util.getRightNthChar(editor, cursor, param, count || 1);\n
\n
            if (isRepeat && column == 0 && !(count > 1))\n
                var column = util.getRightNthChar(editor, cursor, param, 2);\n
                \n
            if (typeof column === "number") {\n
                cursor.column += column + (isSel ? 1 : 0);\n
                return cursor;\n
            }\n
        }\n
    }),\n
    "T": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel, isRepeat) {\n
            if (!isRepeat)\n
                LAST_SEARCH_MOTION = {ch: "T", param: param};\n
            var cursor = editor.getCursorPosition();\n
            var column = util.getLeftNthChar(editor, cursor, param, count || 1);\n
\n
            if (isRepeat && column == 0 && !(count > 1))\n
                var column = util.getLeftNthChar(editor, cursor, param, 2);\n
            \n
            if (typeof column === "number") {\n
                cursor.column -= column;\n
                return cursor;\n
            }\n
        }\n
    }),\n
    ";": new Motion({\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel) {\n
            var ch = LAST_SEARCH_MOTION.ch;\n
            if (!ch)\n
                return;\n
            return module.exports[ch].getPos(\n
                editor, range, count, LAST_SEARCH_MOTION.param, isSel, true\n
            );\n
        }\n
    }),\n
    ",": new Motion({\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel) {\n
            var ch = LAST_SEARCH_MOTION.ch;\n
            if (!ch)\n
                return;\n
            var up = ch.toUpperCase();\n
            ch = ch === up ? ch.toLowerCase() : up;\n
            \n
            return module.exports[ch].getPos(\n
                editor, range, count, LAST_SEARCH_MOTION.param, isSel, true\n
            );\n
        }\n
    }),\n
\n
    "^": {\n
        nav: function(editor) {\n
            editor.navigateLineStart();\n
        },\n
        sel: function(editor) {\n
            editor.selection.selectLineStart();\n
        }\n
    },\n
    "$": {\n
        nav: function(editor) {\n
            editor.navigateLineEnd();\n
        },\n
        sel: function(editor) {\n
            editor.selection.selectLineEnd();\n
        }\n
    },\n
    "0": new Motion(function(ed) {\n
        return {row: ed.selection.lead.row, column: 0};\n
    }),\n
    "G": {\n
        nav: function(editor, range, count, param) {\n
            if (!count && count !== 0) { // Stupid JS\n
                count = editor.session.getLength();\n
            }\n
            editor.gotoLine(count);\n
        },\n
        sel: function(editor, range, count, param) {\n
            if (!count && count !== 0) { // Stupid JS\n
                count = editor.session.getLength();\n
            }\n
            editor.selection.selectTo(count, 0);\n
        }\n
    },\n
    "g": {\n
        param: true,\n
        nav: function(editor, range, count, param) {\n
            switch(param) {\n
                case "m":\n
                    console.log("Middle line");\n
                    break;\n
                case "e":\n
                    console.log("End of prev word");\n
                    break;\n
                case "g":\n
                    editor.gotoLine(count || 0);\n
                case "u":\n
                    editor.gotoLine(count || 0);\n
                case "U":\n
                    editor.gotoLine(count || 0);\n
            }\n
        },\n
        sel: function(editor, range, count, param) {\n
            switch(param) {\n
                case "m":\n
                    console.log("Middle line");\n
                    break;\n
                case "e":\n
                    console.log("End of prev word");\n
                    break;\n
                case "g":\n
                    editor.selection.selectTo(count || 0, 0);\n
            }\n
        }\n
    },\n
    "o": {\n
        nav: function(editor, range, count, param) {\n
            count = count || 1;\n
            var content = "";\n
            while (0 < count--)\n
                content += "\\n";\n
\n
            if (content.length) {\n
                editor.navigateLineEnd()\n
                editor.insert(content);\n
                util.insertMode(editor);\n
            }\n
        }\n
    },\n
    "O": {\n
        nav: function(editor, range, count, param) {\n
            var row = editor.getCursorPosition().row;\n
            count = count || 1;\n
            var content = "";\n
            while (0 < count--)\n
                content += "\\n";\n
\n
            if (content.length) {\n
                if(row > 0) {\n
                    editor.navigateUp();\n
                    editor.navigateLineEnd()\n
                    editor.insert(content);\n
                } else {\n
                    editor.session.insert({row: 0, column: 0}, content);\n
                    editor.navigateUp();\n
                }\n
                util.insertMode(editor);\n
            }\n
        }\n
    },\n
    "%": new Motion(function(editor){\n
        var brRe = /[\\[\\]{}()]/g;\n
        var cursor = editor.getCursorPosition();\n
        var ch = editor.session.getLine(cursor.row)[cursor.column];\n
        if (!brRe.test(ch)) {\n
            var range = find(editor, brRe);\n
            if (!range)\n
                return;\n
            cursor = range.start;\n
        }\n
        var match = editor.session.findMatchingBracket({\n
            row: cursor.row,\n
            column: cursor.column + 1\n
        });\n
\n
        return match;\n
    }),\n
    "{": new Motion(function(ed) {\n
        var session = ed.session;\n
        var row = session.selection.lead.row;\n
        while(row > 0 && !/\\S/.test(session.getLine(row)))\n
            row--;\n
        while(/\\S/.test(session.getLine(row)))\n
            row--;\n
        return {column: 0, row: row};\n
    }),\n
    "}": new Motion(function(ed) {\n
        var session = ed.session;\n
        var l = session.getLength();\n
        var row = session.selection.lead.row;\n
        while(row < l && !/\\S/.test(session.getLine(row)))\n
            row++;\n
        while(/\\S/.test(session.getLine(row)))\n
            row++;\n
        return {column: 0, row: row};\n
    }),\n
    "ctrl-d": {\n
        nav: function(editor, range, count, param) {\n
            editor.selection.clearSelection();\n
            keepScrollPosition(editor, editor.gotoPageDown);\n
        },\n
        sel: function(editor, range, count, param) {\n
            keepScrollPosition(editor, editor.selectPageDown);\n
        }\n
    },\n
    "ctrl-u": {\n
        nav: function(editor, range, count, param) {\n
            editor.selection.clearSelection();\n
            keepScrollPosition(editor, editor.gotoPageUp);\n
        },\n
        sel: function(editor, range, count, param) {\n
            keepScrollPosition(editor, editor.selectPageUp);\n
        }\n
    },\n
    "`": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel) {\n
            var s = editor.session;\n
            var marker = s.vimMarkers && s.vimMarkers[param];\n
            if (marker) {\n
                return marker.getPosition();\n
            }\n
        }\n
    }),\n
    "\'": new Motion({\n
        param: true,\n
        handlesCount: true,\n
        getPos: function(editor, range, count, param, isSel) {\n
            var s = editor.session;\n
            var marker = s.vimMarkers && s.vimMarkers[param];\n
            if (marker) {\n
                var pos = marker.getPosition();\n
                var line = editor.session.getLine(pos.row);                \n
                pos.column = line.search(/\\S/);\n
                if (pos.column == -1)\n
                    pos.column = line.length;\n
                return pos;\n
            }\n
        }\n
    })\n
};\n
\n
module.exports.backspace = module.exports.left = module.exports.h;\n
module.exports.space = module.exports[\'return\'] = module.exports.right = module.exports.l;\n
module.exports.up = module.exports.k;\n
module.exports.down = module.exports.j;\n
module.exports.pagedown = module.exports["ctrl-d"];\n
module.exports.pageup = module.exports["ctrl-u"];\n
\n
});\n
 \n
define(\'ace/keyboard/vim/maps/operators\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/vim/maps/util\', \'ace/keyboard/vim/registers\'], function(require, exports, module) {\n
\n
\n
\n
var util = require("./util");\n
var registers = require("../registers");\n
\n
module.exports = {\n
    "d": {\n
        selFn: function(editor, range, count, param) {\n
            registers._default.text = editor.getCopyText();\n
            registers._default.isLine = util.onVisualLineMode;\n
            if(util.onVisualLineMode)\n
                editor.removeLines();\n
            else\n
                editor.session.remove(range);\n
            util.normalMode(editor);\n
        },\n
        fn: function(editor, range, count, param) {\n
            count = count || 1;\n
            switch (param) {\n
                case "d":\n
                    registers._default.text = "";\n
                    registers._default.isLine = true;\n
                    for (var i = 0; i < count; i++) {\n
                        editor.selection.selectLine();\n
                        registers._default.text += editor.getCopyText();\n
                        var selRange = editor.getSelectionRange();\n
                        if (!selRange.isMultiLine()) {\n
                            var row = selRange.start.row - 1;\n
                            var col = editor.session.getLine(row).length\n
                            selRange.setStart(row, col);\n
                            editor.session.remove(selRange);\n
                            editor.selection.clearSelection();\n
                            break;\n
                        }\n
                        editor.session.remove(selRange);\n
                        editor.selection.clearSelection();\n
                    }\n
                    registers._default.text = registers._default.text.replace(/\\n$/, "");\n
                    break;\n
                default:\n
                    if (range) {\n
                        editor.selection.setSelectionRange(range);\n
                        registers._default.text = editor.getCopyText();\n
                        registers._default.isLine = false;\n
                        editor.session.remove(range);\n
                        editor.selection.clearSelection();\n
                    }\n
            }\n
        }\n
    },\n
    "c": {\n
        selFn: function(editor, range, count, param) {\n
            editor.session.remove(range);\n
            util.insertMode(editor);\n
        },\n
        fn: function(editor, range, count, param) {\n
            count = count || 1;\n
            switch (param) {\n
                case "c":\n
                    for (var i = 0; i < count; i++) {\n
                        editor.removeLines();\n
                        util.insertMode(editor);\n
                    }\n
\n
                    break;\n
                default:\n
                    if (range) {\n
                        editor.session.remove(range);\n
                        util.insertMode(editor);\n
                    }\n
            }\n
        }\n
    },\n
    "y": {\n
        selFn: function(editor, range, count, param) {\n
            registers._default.text = editor.getCopyText();\n
            registers._default.isLine = util.onVisualLineMode;\n
            editor.selection.clearSelection();\n
            util.normalMode(editor);\n
        },\n
        fn: function(editor, range, count, param) {\n
            count = count || 1;\n
            switch (param) {\n
                case "y":\n
                    var pos = editor.getCursorPosition();\n
                    editor.selection.selectLine();\n
                    for (var i = 0; i < count - 1; i++) {\n
                        editor.selection.moveCursorDown();\n
                    }\n
                    registers._default.text = editor.getCopyText().replace(/\\n$/, "");\n
                    editor.selection.clearSelection();\n
                    registers._default.isLine = true;\n
                    editor.moveCursorToPosition(pos);\n
                    break;\n
                default:\n
                    if (range) {\n
                        var pos = editor.getCursorPosition();\n
                        editor.selection.setSelectionRange(range);\n
                        registers._default.text = editor.getCopyText();\n
                        registers._default.isLine = false;\n
                        editor.selection.clearSelection();\n
                        editor.moveCursorTo(pos.row, pos.column);\n
                    }\n
            }\n
        }\n
    },\n
    ">": {\n
        selFn: function(editor, range, count, param) {\n
            count = count || 1;\n
            for (var i = 0; i < count; i++) {\n
                editor.indent();\n
            }\n
            util.normalMode(editor);\n
        },\n
        fn: function(editor, range, count, param) {\n
            count = parseInt(count || 1, 10);\n
            switch (param) {\n
                case ">":\n
                    var pos = editor.getCursorPosition();\n
                    editor.selection.selectLine();\n
                    for (var i = 0; i < count - 1; i++) {\n
                        editor.selection.moveCursorDown();\n
                    }\n
                    editor.indent();\n
                    editor.selection.clearSelection();\n
                    editor.moveCursorToPosition(pos);\n
                    editor.navigateLineEnd();\n
                    editor.navigateLineStart();\n
                    break;\n
            }\n
        }\n
    },\n
    "<": {\n
        selFn: function(editor, range, count, param) {\n
            count = count || 1;\n
            for (var i = 0; i < count; i++) {\n
                editor.blockOutdent();\n
            }\n
            util.normalMode(editor);\n
        },\n
        fn: function(editor, range, count, param) {\n
            count = count || 1;\n
            switch (param) {\n
                case "<":\n
                    var pos = editor.getCursorPosition();\n
                    editor.selection.selectLine();\n
                    for (var i = 0; i < count - 1; i++) {\n
                        editor.selection.moveCursorDown();\n
                    }\n
                    editor.blockOutdent();\n
                    editor.selection.clearSelection();\n
                    editor.moveCursorToPosition(pos);\n
                    editor.navigateLineEnd();\n
                    editor.navigateLineStart();\n
                    break;\n
            }\n
        }\n
    }\n
};\n
});\n
 \n
"use strict"\n
\n
define(\'ace/keyboard/vim/maps/aliases\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
module.exports = {\n
    "x": {\n
        operator: {\n
            ch: "d",\n
            count: 1\n
        },\n
        motion: {\n
            ch: "l",\n
            count: 1\n
        }\n
    },\n
    "X": {\n
        operator: {\n
            ch: "d",\n
            count: 1\n
        },\n
        motion: {\n
            ch: "h",\n
            count: 1\n
        }\n
    },\n
    "D": {\n
        operator: {\n
            ch: "d",\n
            count: 1\n
        },\n
        motion: {\n
            ch: "$",\n
            count: 1\n
        }\n
    },\n
    "C": {\n
        operator: {\n
            ch: "c",\n
            count: 1\n
        },\n
        motion: {\n
            ch: "$",\n
            count: 1\n
        }\n
    },\n
    "s": {\n
        operator: {\n
            ch: "c",\n
            count: 1\n
        },\n
        motion: {\n
            ch: "l",\n
            count: 1\n
        }\n
    },\n
    "S": {\n
        operator: {\n
            ch: "c",\n
            count: 1\n
        },\n
        param: "c"\n
    }\n
};\n
});\n
\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>57858</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>keybinding-vim.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
