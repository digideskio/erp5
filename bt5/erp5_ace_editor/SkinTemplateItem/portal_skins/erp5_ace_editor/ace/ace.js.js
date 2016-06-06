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
            <value> <string>ts83646622.73</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ace.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>580350</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>ace.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
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
(function() {\n
\n
var ACE_NAMESPACE = "";\n
\n
var global = (function() {\n
    return this;\n
})();\n
\n
\n
if (!ACE_NAMESPACE && typeof requirejs !== "undefined")\n
    return;\n
\n
\n
var _define = function(module, deps, payload) {\n
    if (typeof module !== \'string\') {\n
        if (_define.original)\n
            _define.original.apply(window, arguments);\n
        else {\n
            console.error(\'dropping module because define wasn\\\'t a string.\');\n
            console.trace();\n
        }\n
        return;\n
    }\n
\n
    if (arguments.length == 2)\n
        payload = deps;\n
\n
    if (!_define.modules) {\n
        _define.modules = {};\n
        _define.payloads = {};\n
    }\n
    \n
    _define.payloads[module] = payload;\n
    _define.modules[module] = null;\n
};\n
var _require = function(parentId, module, callback) {\n
    if (Object.prototype.toString.call(module) === "[object Array]") {\n
        var params = [];\n
        for (var i = 0, l = module.length; i < l; ++i) {\n
            var dep = lookup(parentId, module[i]);\n
            if (!dep && _require.original)\n
                return _require.original.apply(window, arguments);\n
            params.push(dep);\n
        }\n
        if (callback) {\n
            callback.apply(null, params);\n
        }\n
    }\n
    else if (typeof module === \'string\') {\n
        var payload = lookup(parentId, module);\n
        if (!payload && _require.original)\n
            return _require.original.apply(window, arguments);\n
\n
        if (callback) {\n
            callback();\n
        }\n
\n
        return payload;\n
    }\n
    else {\n
        if (_require.original)\n
            return _require.original.apply(window, arguments);\n
    }\n
};\n
\n
var normalizeModule = function(parentId, moduleName) {\n
    if (moduleName.indexOf("!") !== -1) {\n
        var chunks = moduleName.split("!");\n
        return normalizeModule(parentId, chunks[0]) + "!" + normalizeModule(parentId, chunks[1]);\n
    }\n
    if (moduleName.charAt(0) == ".") {\n
        var base = parentId.split("/").slice(0, -1).join("/");\n
        moduleName = base + "/" + moduleName;\n
\n
        while(moduleName.indexOf(".") !== -1 && previous != moduleName) {\n
            var previous = moduleName;\n
            moduleName = moduleName.replace(/\\/\\.\\//, "/").replace(/[^\\/]+\\/\\.\\.\\//, "");\n
        }\n
    }\n
\n
    return moduleName;\n
};\n
var lookup = function(parentId, moduleName) {\n
\n
    moduleName = normalizeModule(parentId, moduleName);\n
\n
    var module = _define.modules[moduleName];\n
    if (!module) {\n
        module = _define.payloads[moduleName];\n
        if (typeof module === \'function\') {\n
            var exports = {};\n
            var mod = {\n
                id: moduleName,\n
                uri: \'\',\n
                exports: exports,\n
                packaged: true\n
            };\n
\n
            var req = function(module, callback) {\n
                return _require(moduleName, module, callback);\n
            };\n
\n
            var returnValue = module(req, exports, mod);\n
            exports = returnValue || mod.exports;\n
            _define.modules[moduleName] = exports;\n
            delete _define.payloads[moduleName];\n
        }\n
        module = _define.modules[moduleName] = exports || module;\n
    }\n
    return module;\n
};\n
\n
function exportAce(ns) {\n
    var require = function(module, callback) {\n
        return _require("", module, callback);\n
    };    \n
\n
    var root = global;\n
    if (ns) {\n
        if (!global[ns])\n
            global[ns] = {};\n
        root = global[ns];\n
    }\n
\n
    if (!root.define || !root.define.packaged) {\n
        _define.original = root.define;\n
        root.define = _define;\n
        root.define.packaged = true;\n
    }\n
\n
    if (!root.require || !root.require.packaged) {\n
        _require.original = root.require;\n
        root.require = require;\n
        root.require.packaged = true;\n
    }\n
}\n
\n
exportAce(ACE_NAMESPACE);\n
\n
})();\n
\n
define(\'ace/ace\', [\'require\', \'exports\', \'module\' , \'ace/lib/fixoldbrowsers\', \'ace/lib/dom\', \'ace/lib/event\', \'ace/editor\', \'ace/edit_session\', \'ace/undomanager\', \'ace/virtual_renderer\', \'ace/multi_select\', \'ace/worker/worker_client\', \'ace/keyboard/hash_handler\', \'ace/placeholder\', \'ace/mode/folding/fold_mode\', \'ace/theme/textmate\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
require("./lib/fixoldbrowsers");\n
\n
var dom = require("./lib/dom");\n
var event = require("./lib/event");\n
\n
var Editor = require("./editor").Editor;\n
var EditSession = require("./edit_session").EditSession;\n
var UndoManager = require("./undomanager").UndoManager;\n
var Renderer = require("./virtual_renderer").VirtualRenderer;\n
var MultiSelect = require("./multi_select").MultiSelect;\n
require("./worker/worker_client");\n
require("./keyboard/hash_handler");\n
require("./placeholder");\n
require("./mode/folding/fold_mode");\n
require("./theme/textmate");\n
\n
exports.config = require("./config");\n
exports.require = require;\n
exports.edit = function(el) {\n
    if (typeof(el) == "string") {\n
        var _id = el;\n
        var el = document.getElementById(_id);\n
        if (!el)\n
            throw new Error("ace.edit can\'t find div #" + _id);\n
    }\n
\n
    if (el.env && el.env.editor instanceof Editor)\n
        return el.env.editor;\n
\n
    var doc = exports.createEditSession(dom.getInnerText(el));\n
    el.innerHTML = \'\';\n
\n
    var editor = new Editor(new Renderer(el));\n
    new MultiSelect(editor);\n
    editor.setSession(doc);\n
\n
    var env = {\n
        document: doc,\n
        editor: editor,\n
        onResize: editor.resize.bind(editor, null)\n
    };\n
    event.addListener(window, "resize", env.onResize);\n
    editor.on("destroy", function() {\n
        event.removeListener(window, "resize", env.onResize);\n
    });\n
    el.env = editor.env = env;\n
    return editor;\n
};\n
exports.createEditSession = function(text, mode) {\n
    var doc = new EditSession(text, mode);\n
    doc.setUndoManager(new UndoManager());\n
    return doc;\n
}\n
exports.EditSession = EditSession;\n
exports.UndoManager = UndoManager;\n
});\n
\n
define(\'ace/lib/fixoldbrowsers\', [\'require\', \'exports\', \'module\' , \'ace/lib/regexp\', \'ace/lib/es5-shim\'], function(require, exports, module) {\n
\n
\n
require("./regexp");\n
require("./es5-shim");\n
\n
});\n
 \n
define(\'ace/lib/regexp\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
    var real = {\n
            exec: RegExp.prototype.exec,\n
            test: RegExp.prototype.test,\n
            match: String.prototype.match,\n
            replace: String.prototype.replace,\n
            split: String.prototype.split\n
        },\n
        compliantExecNpcg = real.exec.call(/()??/, "")[1] === undefined, // check `exec` handling of nonparticipating capturing groups\n
        compliantLastIndexIncrement = function () {\n
            var x = /^/g;\n
            real.test.call(x, "");\n
            return !x.lastIndex;\n
        }();\n
\n
    if (compliantLastIndexIncrement && compliantExecNpcg)\n
        return;\n
    RegExp.prototype.exec = function (str) {\n
        var match = real.exec.apply(this, arguments),\n
            name, r2;\n
        if ( typeof(str) == \'string\' && match) {\n
            if (!compliantExecNpcg && match.length > 1 && indexOf(match, "") > -1) {\n
                r2 = RegExp(this.source, real.replace.call(getNativeFlags(this), "g", ""));\n
                real.replace.call(str.slice(match.index), r2, function () {\n
                    for (var i = 1; i < arguments.length - 2; i++) {\n
                        if (arguments[i] === undefined)\n
                            match[i] = undefined;\n
                    }\n
                });\n
            }\n
            if (this._xregexp && this._xregexp.captureNames) {\n
                for (var i = 1; i < match.length; i++) {\n
                    name = this._xregexp.captureNames[i - 1];\n
                    if (name)\n
                       match[name] = match[i];\n
                }\n
            }\n
            if (!compliantLastIndexIncrement && this.global && !match[0].length && (this.lastIndex > match.index))\n
                this.lastIndex--;\n
        }\n
        return match;\n
    };\n
    if (!compliantLastIndexIncrement) {\n
        RegExp.prototype.test = function (str) {\n
            var match = real.exec.call(this, str);\n
            if (match && this.global && !match[0].length && (this.lastIndex > match.index))\n
                this.lastIndex--;\n
            return !!match;\n
        };\n
    }\n
\n
    function getNativeFlags (regex) {\n
        return (regex.global     ? "g" : "") +\n
               (regex.ignoreCase ? "i" : "") +\n
               (regex.multiline  ? "m" : "") +\n
               (regex.extended   ? "x" : "") + // Proposed for ES4; included in AS3\n
               (regex.sticky     ? "y" : "");\n
    }\n
\n
    function indexOf (array, item, from) {\n
        if (Array.prototype.indexOf) // Use the native array method if available\n
            return array.indexOf(item, from);\n
        for (var i = from || 0; i < array.length; i++) {\n
            if (array[i] === item)\n
                return i;\n
        }\n
        return -1;\n
    }\n
\n
});\n
\n
define(\'ace/lib/es5-shim\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
function Empty() {}\n
\n
if (!Function.prototype.bind) {\n
    Function.prototype.bind = function bind(that) { // .length is 1\n
        var target = this;\n
        if (typeof target != "function") {\n
            throw new TypeError("Function.prototype.bind called on incompatible " + target);\n
        }\n
        var args = slice.call(arguments, 1); // for normal call\n
        var bound = function () {\n
\n
            if (this instanceof bound) {\n
\n
                var result = target.apply(\n
                    this,\n
                    args.concat(slice.call(arguments))\n
                );\n
                if (Object(result) === result) {\n
                    return result;\n
                }\n
                return this;\n
\n
            } else {\n
                return target.apply(\n
                    that,\n
                    args.concat(slice.call(arguments))\n
                );\n
\n
            }\n
\n
        };\n
        if(target.prototype) {\n
            Empty.prototype = target.prototype;\n
            bound.prototype = new Empty();\n
            Empty.prototype = null;\n
        }\n
        return bound;\n
    };\n
}\n
var call = Function.prototype.call;\n
var prototypeOfArray = Array.prototype;\n
var prototypeOfObject = Object.prototype;\n
var slice = prototypeOfArray.slice;\n
var _toString = call.bind(prototypeOfObject.toString);\n
var owns = call.bind(prototypeOfObject.hasOwnProperty);\n
var defineGetter;\n
var defineSetter;\n
var lookupGetter;\n
var lookupSetter;\n
var supportsAccessors;\n
if ((supportsAccessors = owns(prototypeOfObject, "__defineGetter__"))) {\n
    defineGetter = call.bind(prototypeOfObject.__defineGetter__);\n
    defineSetter = call.bind(prototypeOfObject.__defineSetter__);\n
    lookupGetter = call.bind(prototypeOfObject.__lookupGetter__);\n
    lookupSetter = call.bind(prototypeOfObject.__lookupSetter__);\n
}\n
if ([1,2].splice(0).length != 2) {\n
    if(function() { // test IE < 9 to splice bug - see issue #138\n
        function makeArray(l) {\n
            var a = new Array(l+2);\n
            a[0] = a[1] = 0;\n
            return a;\n
        }\n
        var array = [], lengthBefore;\n
        \n
        array.splice.apply(array, makeArray(20));\n
        array.splice.apply(array, makeArray(26));\n
\n
        lengthBefore = array.length; //46\n
        array.splice(5, 0, "XXX"); // add one element\n
\n
        lengthBefore + 1 == array.length\n
\n
        if (lengthBefore + 1 == array.length) {\n
            return true;// has right splice implementation without bugs\n
        }\n
    }()) {//IE 6/7\n
        var array_splice = Array.prototype.splice;\n
        Array.prototype.splice = function(start, deleteCount) {\n
            if (!arguments.length) {\n
                return [];\n
            } else {\n
                return array_splice.apply(this, [\n
                    start === void 0 ? 0 : start,\n
                    deleteCount === void 0 ? (this.length - start) : deleteCount\n
                ].concat(slice.call(arguments, 2)))\n
            }\n
        };\n
    } else {//IE8\n
        Array.prototype.splice = function(pos, removeCount){\n
            var length = this.length;\n
            if (pos > 0) {\n
                if (pos > length)\n
                    pos = length;\n
            } else if (pos == void 0) {\n
                pos = 0;\n
            } else if (pos < 0) {\n
                pos = Math.max(length + pos, 0);\n
            }\n
\n
            if (!(pos+removeCount < length))\n
                removeCount = length - pos;\n
\n
            var removed = this.slice(pos, pos+removeCount);\n
            var insert = slice.call(arguments, 2);\n
            var add = insert.length;            \n
            if (pos === length) {\n
                if (add) {\n
                    this.push.apply(this, insert);\n
                }\n
            } else {\n
                var remove = Math.min(removeCount, length - pos);\n
                var tailOldPos = pos + remove;\n
                var tailNewPos = tailOldPos + add - remove;\n
                var tailCount = length - tailOldPos;\n
                var lengthAfterRemove = length - remove;\n
\n
                if (tailNewPos < tailOldPos) { // case A\n
                    for (var i = 0; i < tailCount; ++i) {\n
                        this[tailNewPos+i] = this[tailOldPos+i];\n
                    }\n
                } else if (tailNewPos > tailOldPos) { // case B\n
                    for (i = tailCount; i--; ) {\n
                        this[tailNewPos+i] = this[tailOldPos+i];\n
                    }\n
                } // else, add == remove (nothing to do)\n
\n
                if (add && pos === lengthAfterRemove) {\n
                    this.length = lengthAfterRemove; // truncate array\n
                    this.push.apply(this, insert);\n
                } else {\n
                    this.length = lengthAfterRemove + add; // reserves space\n
                    for (i = 0; i < add; ++i) {\n
                        this[pos+i] = insert[i];\n
                    }\n
                }\n
            }\n
            return removed;\n
        };\n
    }\n
}\n
if (!Array.isArray) {\n
    Array.isArray = function isArray(obj) {\n
        return _toString(obj) == "[object Array]";\n
    };\n
}\n
var boxedString = Object("a"),\n
    splitString = boxedString[0] != "a" || !(0 in boxedString);\n
\n
if (!Array.prototype.forEach) {\n
    Array.prototype.forEach = function forEach(fun /*, thisp*/) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            thisp = arguments[1],\n
            i = -1,\n
            length = self.length >>> 0;\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(); // TODO message\n
        }\n
\n
        while (++i < length) {\n
            if (i in self) {\n
                fun.call(thisp, self[i], i, object);\n
            }\n
        }\n
    };\n
}\n
if (!Array.prototype.map) {\n
    Array.prototype.map = function map(fun /*, thisp*/) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            length = self.length >>> 0,\n
            result = Array(length),\n
            thisp = arguments[1];\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
\n
        for (var i = 0; i < length; i++) {\n
            if (i in self)\n
                result[i] = fun.call(thisp, self[i], i, object);\n
        }\n
        return result;\n
    };\n
}\n
if (!Array.prototype.filter) {\n
    Array.prototype.filter = function filter(fun /*, thisp */) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                    object,\n
            length = self.length >>> 0,\n
            result = [],\n
            value,\n
            thisp = arguments[1];\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
\n
        for (var i = 0; i < length; i++) {\n
            if (i in self) {\n
                value = self[i];\n
                if (fun.call(thisp, value, i, object)) {\n
                    result.push(value);\n
                }\n
            }\n
        }\n
        return result;\n
    };\n
}\n
if (!Array.prototype.every) {\n
    Array.prototype.every = function every(fun /*, thisp */) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            length = self.length >>> 0,\n
            thisp = arguments[1];\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
\n
        for (var i = 0; i < length; i++) {\n
            if (i in self && !fun.call(thisp, self[i], i, object)) {\n
                return false;\n
            }\n
        }\n
        return true;\n
    };\n
}\n
if (!Array.prototype.some) {\n
    Array.prototype.some = function some(fun /*, thisp */) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            length = self.length >>> 0,\n
            thisp = arguments[1];\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
\n
        for (var i = 0; i < length; i++) {\n
            if (i in self && fun.call(thisp, self[i], i, object)) {\n
                return true;\n
            }\n
        }\n
        return false;\n
    };\n
}\n
if (!Array.prototype.reduce) {\n
    Array.prototype.reduce = function reduce(fun /*, initial*/) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            length = self.length >>> 0;\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
        if (!length && arguments.length == 1) {\n
            throw new TypeError("reduce of empty array with no initial value");\n
        }\n
\n
        var i = 0;\n
        var result;\n
        if (arguments.length >= 2) {\n
            result = arguments[1];\n
        } else {\n
            do {\n
                if (i in self) {\n
                    result = self[i++];\n
                    break;\n
                }\n
                if (++i >= length) {\n
                    throw new TypeError("reduce of empty array with no initial value");\n
                }\n
            } while (true);\n
        }\n
\n
        for (; i < length; i++) {\n
            if (i in self) {\n
                result = fun.call(void 0, result, self[i], i, object);\n
            }\n
        }\n
\n
        return result;\n
    };\n
}\n
if (!Array.prototype.reduceRight) {\n
    Array.prototype.reduceRight = function reduceRight(fun /*, initial*/) {\n
        var object = toObject(this),\n
            self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                object,\n
            length = self.length >>> 0;\n
        if (_toString(fun) != "[object Function]") {\n
            throw new TypeError(fun + " is not a function");\n
        }\n
        if (!length && arguments.length == 1) {\n
            throw new TypeError("reduceRight of empty array with no initial value");\n
        }\n
\n
        var result, i = length - 1;\n
        if (arguments.length >= 2) {\n
            result = arguments[1];\n
        } else {\n
            do {\n
                if (i in self) {\n
                    result = self[i--];\n
                    break;\n
                }\n
                if (--i < 0) {\n
                    throw new TypeError("reduceRight of empty array with no initial value");\n
                }\n
            } while (true);\n
        }\n
\n
        do {\n
            if (i in this) {\n
                result = fun.call(void 0, result, self[i], i, object);\n
            }\n
        } while (i--);\n
\n
        return result;\n
    };\n
}\n
if (!Array.prototype.indexOf || ([0, 1].indexOf(1, 2) != -1)) {\n
    Array.prototype.indexOf = function indexOf(sought /*, fromIndex */ ) {\n
        var self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                toObject(this),\n
            length = self.length >>> 0;\n
\n
        if (!length) {\n
            return -1;\n
        }\n
\n
        var i = 0;\n
        if (arguments.length > 1) {\n
            i = toInteger(arguments[1]);\n
        }\n
        i = i >= 0 ? i : Math.max(0, length + i);\n
        for (; i < length; i++) {\n
            if (i in self && self[i] === sought) {\n
                return i;\n
            }\n
        }\n
        return -1;\n
    };\n
}\n
if (!Array.prototype.lastIndexOf || ([0, 1].lastIndexOf(0, -3) != -1)) {\n
    Array.prototype.lastIndexOf = function lastIndexOf(sought /*, fromIndex */) {\n
        var self = splitString && _toString(this) == "[object String]" ?\n
                this.split("") :\n
                toObject(this),\n
            length = self.length >>> 0;\n
\n
        if (!length) {\n
            return -1;\n
        }\n
        var i = length - 1;\n
        if (arguments.length > 1) {\n
            i = Math.min(i, toInteger(arguments[1]));\n
        }\n
        i = i >= 0 ? i : length - Math.abs(i);\n
        for (; i >= 0; i--) {\n
            if (i in self && sought === self[i]) {\n
                return i;\n
            }\n
        }\n
        return -1;\n
    };\n
}\n
if (!Object.getPrototypeOf) {\n
    Object.getPrototypeOf = function getPrototypeOf(object) {\n
        return object.__proto__ || (\n
            object.constructor ?\n
            object.constructor.prototype :\n
            prototypeOfObject\n
        );\n
    };\n
}\n
if (!Object.getOwnPropertyDescriptor) {\n
    var ERR_NON_OBJECT = "Object.getOwnPropertyDescriptor called on a " +\n
                         "non-object: ";\n
    Object.getOwnPropertyDescriptor = function getOwnPropertyDescriptor(object, property) {\n
        if ((typeof object != "object" && typeof object != "function") || object === null)\n
            throw new TypeError(ERR_NON_OBJECT + object);\n
        if (!owns(object, property))\n
            return;\n
\n
        var descriptor, getter, setter;\n
        descriptor =  { enumerable: true, configurable: true };\n
        if (supportsAccessors) {\n
            var prototype = object.__proto__;\n
            object.__proto__ = prototypeOfObject;\n
\n
            var getter = lookupGetter(object, property);\n
            var setter = lookupSetter(object, property);\n
            object.__proto__ = prototype;\n
\n
            if (getter || setter) {\n
                if (getter) descriptor.get = getter;\n
                if (setter) descriptor.set = setter;\n
                return descriptor;\n
            }\n
        }\n
        descriptor.value = object[property];\n
        return descriptor;\n
    };\n
}\n
if (!Object.getOwnPropertyNames) {\n
    Object.getOwnPropertyNames = function getOwnPropertyNames(object) {\n
        return Object.keys(object);\n
    };\n
}\n
if (!Object.create) {\n
    var createEmpty;\n
    if (Object.prototype.__proto__ === null) {\n
        createEmpty = function () {\n
            return { "__proto__": null };\n
        };\n
    } else {\n
        createEmpty = function () {\n
            var empty = {};\n
            for (var i in empty)\n
                empty[i] = null;\n
            empty.constructor =\n
            empty.hasOwnProperty =\n
            empty.propertyIsEnumerable =\n
            empty.isPrototypeOf =\n
            empty.toLocaleString =\n
            empty.toString =\n
            empty.valueOf =\n
            empty.__proto__ = null;\n
            return empty;\n
        }\n
    }\n
\n
    Object.create = function create(prototype, properties) {\n
        var object;\n
        if (prototype === null) {\n
            object = createEmpty();\n
        } else {\n
            if (typeof prototype != "object")\n
                throw new TypeError("typeof prototype["+(typeof prototype)+"] != \'object\'");\n
            var Type = function () {};\n
            Type.prototype = prototype;\n
            object = new Type();\n
            object.__proto__ = prototype;\n
        }\n
        if (properties !== void 0)\n
            Object.defineProperties(object, properties);\n
        return object;\n
    };\n
}\n
\n
function doesDefinePropertyWork(object) {\n
    try {\n
        Object.defineProperty(object, "sentinel", {});\n
        return "sentinel" in object;\n
    } catch (exception) {\n
    }\n
}\n
if (Object.defineProperty) {\n
    var definePropertyWorksOnObject = doesDefinePropertyWork({});\n
    var definePropertyWorksOnDom = typeof document == "undefined" ||\n
        doesDefinePropertyWork(document.createElement("div"));\n
    if (!definePropertyWorksOnObject || !definePropertyWorksOnDom) {\n
        var definePropertyFallback = Object.defineProperty;\n
    }\n
}\n
\n
if (!Object.defineProperty || definePropertyFallback) {\n
    var ERR_NON_OBJECT_DESCRIPTOR = "Property description must be an object: ";\n
    var ERR_NON_OBJECT_TARGET = "Object.defineProperty called on non-object: "\n
    var ERR_ACCESSORS_NOT_SUPPORTED = "getters & setters can not be defined " +\n
                                      "on this javascript engine";\n
\n
    Object.defineProperty = function defineProperty(object, property, descriptor) {\n
        if ((typeof object != "object" && typeof object != "function") || object === null)\n
            throw new TypeError(ERR_NON_OBJECT_TARGET + object);\n
        if ((typeof descriptor != "object" && typeof descriptor != "function") || descriptor === null)\n
            throw new TypeError(ERR_NON_OBJECT_DESCRIPTOR + descriptor);\n
        if (definePropertyFallback) {\n
            try {\n
                return definePropertyFallback.call(Object, object, property, descriptor);\n
            } catch (exception) {\n
            }\n
        }\n
        if (owns(descriptor, "value")) {\n
\n
            if (supportsAccessors && (lookupGetter(object, property) ||\n
                                      lookupSetter(object, property)))\n
            {\n
                var prototype = object.__proto__;\n
                object.__proto__ = prototypeOfObject;\n
                delete object[property];\n
                object[property] = descriptor.value;\n
                object.__proto__ = prototype;\n
            } else {\n
                object[property] = descriptor.value;\n
            }\n
        } else {\n
            if (!supportsAccessors)\n
                throw new TypeError(ERR_ACCESSORS_NOT_SUPPORTED);\n
            if (owns(descriptor, "get"))\n
                defineGetter(object, property, descriptor.get);\n
            if (owns(descriptor, "set"))\n
                defineSetter(object, property, descriptor.set);\n
        }\n
\n
        return object;\n
    };\n
}\n
if (!Object.defineProperties) {\n
    Object.defineProperties = function defineProperties(object, properties) {\n
        for (var property in properties) {\n
            if (owns(properties, property))\n
                Object.defineProperty(object, property, properties[property]);\n
        }\n
        return object;\n
    };\n
}\n
if (!Object.seal) {\n
    Object.seal = function seal(object) {\n
        return object;\n
    };\n
}\n
if (!Object.freeze) {\n
    Object.freeze = function freeze(object) {\n
        return object;\n
    };\n
}\n
try {\n
    Object.freeze(function () {});\n
} catch (exception) {\n
    Object.freeze = (function freeze(freezeObject) {\n
        return function freeze(object) {\n
            if (typeof object == "function") {\n
                return object;\n
            } else {\n
                return freezeObject(object);\n
            }\n
        };\n
    })(Object.freeze);\n
}\n
if (!Object.preventExtensions) {\n
    Object.preventExtensions = function preventExtensions(object) {\n
        return object;\n
    };\n
}\n
if (!Object.isSealed) {\n
    Object.isSealed = function isSealed(object) {\n
        return false;\n
    };\n
}\n
if (!Object.isFrozen) {\n
    Object.isFrozen = function isFrozen(object) {\n
        return false;\n
    };\n
}\n
if (!Object.isExtensible) {\n
    Object.isExtensible = function isExtensible(object) {\n
        if (Object(object) === object) {\n
            throw new TypeError(); // TODO message\n
        }\n
        var name = \'\';\n
        while (owns(object, name)) {\n
            name += \'?\';\n
        }\n
        object[name] = true;\n
        var returnValue = owns(object, name);\n
        delete object[name];\n
        return returnValue;\n
    };\n
}\n
if (!Object.keys) {\n
    var hasDontEnumBug = true,\n
        dontEnums = [\n
            "toString",\n
            "toLocaleString",\n
            "valueOf",\n
            "hasOwnProperty",\n
            "isPrototypeOf",\n
            "propertyIsEnumerable",\n
            "constructor"\n
        ],\n
        dontEnumsLength = dontEnums.length;\n
\n
    for (var key in {"toString": null}) {\n
        hasDontEnumBug = false;\n
    }\n
\n
    Object.keys = function keys(object) {\n
\n
        if (\n
            (typeof object != "object" && typeof object != "function") ||\n
            object === null\n
        ) {\n
            throw new TypeError("Object.keys called on a non-object");\n
        }\n
\n
        var keys = [];\n
        for (var name in object) {\n
            if (owns(object, name)) {\n
                keys.push(name);\n
            }\n
        }\n
\n
        if (hasDontEnumBug) {\n
            for (var i = 0, ii = dontEnumsLength; i < ii; i++) {\n
                var dontEnum = dontEnums[i];\n
                if (owns(object, dontEnum)) {\n
                    keys.push(dontEnum);\n
                }\n
            }\n
        }\n
        return keys;\n
    };\n
\n
}\n
if (!Date.now) {\n
    Date.now = function now() {\n
        return new Date().getTime();\n
    };\n
}\n
var ws = "\\x09\\x0A\\x0B\\x0C\\x0D\\x20\\xA0\\u1680\\u180E\\u2000\\u2001\\u2002\\u2003" +\n
    "\\u2004\\u2005\\u2006\\u2007\\u2008\\u2009\\u200A\\u202F\\u205F\\u3000\\u2028" +\n
    "\\u2029\\uFEFF";\n
if (!String.prototype.trim || ws.trim()) {\n
    ws = "[" + ws + "]";\n
    var trimBeginRegexp = new RegExp("^" + ws + ws + "*"),\n
        trimEndRegexp = new RegExp(ws + ws + "*$");\n
    String.prototype.trim = function trim() {\n
        return String(this).replace(trimBeginRegexp, "").replace(trimEndRegexp, "");\n
    };\n
}\n
\n
function toInteger(n) {\n
    n = +n;\n
    if (n !== n) { // isNaN\n
        n = 0;\n
    } else if (n !== 0 && n !== (1/0) && n !== -(1/0)) {\n
        n = (n > 0 || -1) * Math.floor(Math.abs(n));\n
    }\n
    return n;\n
}\n
\n
function isPrimitive(input) {\n
    var type = typeof input;\n
    return (\n
        input === null ||\n
        type === "undefined" ||\n
        type === "boolean" ||\n
        type === "number" ||\n
        type === "string"\n
    );\n
}\n
\n
function toPrimitive(input) {\n
    var val, valueOf, toString;\n
    if (isPrimitive(input)) {\n
        return input;\n
    }\n
    valueOf = input.valueOf;\n
    if (typeof valueOf === "function") {\n
        val = valueOf.call(input);\n
        if (isPrimitive(val)) {\n
            return val;\n
        }\n
    }\n
    toString = input.toString;\n
    if (typeof toString === "function") {\n
        val = toString.call(input);\n
        if (isPrimitive(val)) {\n
            return val;\n
        }\n
    }\n
    throw new TypeError();\n
}\n
var toObject = function (o) {\n
    if (o == null) { // this matches both null and undefined\n
        throw new TypeError("can\'t convert "+o+" to object");\n
    }\n
    return Object(o);\n
};\n
\n
});\n
\n
define(\'ace/lib/dom\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
if (typeof document == "undefined")\n
    return;\n
\n
var XHTML_NS = "http://www.w3.org/1999/xhtml";\n
\n
exports.getDocumentHead = function(doc) {\n
    if (!doc)\n
        doc = document;\n
    return doc.head || doc.getElementsByTagName("head")[0] || doc.documentElement;\n
}\n
\n
exports.createElement = function(tag, ns) {\n
    return document.createElementNS ?\n
           document.createElementNS(ns || XHTML_NS, tag) :\n
           document.createElement(tag);\n
};\n
\n
exports.hasCssClass = function(el, name) {\n
    var classes = el.className.split(/\\s+/g);\n
    return classes.indexOf(name) !== -1;\n
};\n
exports.addCssClass = function(el, name) {\n
    if (!exports.hasCssClass(el, name)) {\n
        el.className += " " + name;\n
    }\n
};\n
exports.removeCssClass = function(el, name) {\n
    var classes = el.className.split(/\\s+/g);\n
    while (true) {\n
        var index = classes.indexOf(name);\n
        if (index == -1) {\n
            break;\n
        }\n
        classes.splice(index, 1);\n
    }\n
    el.className = classes.join(" ");\n
};\n
\n
exports.toggleCssClass = function(el, name) {\n
    var classes = el.className.split(/\\s+/g), add = true;\n
    while (true) {\n
        var index = classes.indexOf(name);\n
        if (index == -1) {\n
            break;\n
        }\n
        add = false;\n
        classes.splice(index, 1);\n
    }\n
    if(add)\n
        classes.push(name);\n
\n
    el.className = classes.join(" ");\n
    return add;\n
};\n
exports.setCssClass = function(node, className, include) {\n
    if (include) {\n
        exports.addCssClass(node, className);\n
    } else {\n
        exports.removeCssClass(node, className);\n
    }\n
};\n
\n
exports.hasCssString = function(id, doc) {\n
    var index = 0, sheets;\n
    doc = doc || document;\n
\n
    if (doc.createStyleSheet && (sheets = doc.styleSheets)) {\n
        while (index < sheets.length)\n
            if (sheets[index++].owningElement.id === id) return true;\n
    } else if ((sheets = doc.getElementsByTagName("style"))) {\n
        while (index < sheets.length)\n
            if (sheets[index++].id === id) return true;\n
    }\n
\n
    return false;\n
};\n
\n
exports.importCssString = function importCssString(cssText, id, doc) {\n
    doc = doc || document;\n
    if (id && exports.hasCssString(id, doc))\n
        return null;\n
    \n
    var style;\n
    \n
    if (doc.createStyleSheet) {\n
        style = doc.createStyleSheet();\n
        style.cssText = cssText;\n
        if (id)\n
            style.owningElement.id = id;\n
    } else {\n
        style = doc.createElementNS\n
            ? doc.createElementNS(XHTML_NS, "style")\n
            : doc.createElement("style");\n
\n
        style.appendChild(doc.createTextNode(cssText));\n
        if (id)\n
            style.id = id;\n
\n
        exports.getDocumentHead(doc).appendChild(style);\n
    }\n
};\n
\n
exports.importCssStylsheet = function(uri, doc) {\n
    if (doc.createStyleSheet) {\n
        doc.createStyleSheet(uri);\n
    } else {\n
        var link = exports.createElement(\'link\');\n
        link.rel = \'stylesheet\';\n
        link.href = uri;\n
\n
        exports.getDocumentHead(doc).appendChild(link);\n
    }\n
};\n
\n
exports.getInnerWidth = function(element) {\n
    return (\n
        parseInt(exports.computedStyle(element, "paddingLeft"), 10) +\n
        parseInt(exports.computedStyle(element, "paddingRight"), 10) + \n
        element.clientWidth\n
    );\n
};\n
\n
exports.getInnerHeight = function(element) {\n
    return (\n
        parseInt(exports.computedStyle(element, "paddingTop"), 10) +\n
        parseInt(exports.computedStyle(element, "paddingBottom"), 10) +\n
        element.clientHeight\n
    );\n
};\n
\n
if (window.pageYOffset !== undefined) {\n
    exports.getPageScrollTop = function() {\n
        return window.pageYOffset;\n
    };\n
\n
    exports.getPageScrollLeft = function() {\n
        return window.pageXOffset;\n
    };\n
}\n
else {\n
    exports.getPageScrollTop = function() {\n
        return document.body.scrollTop;\n
    };\n
\n
    exports.getPageScrollLeft = function() {\n
        return document.body.scrollLeft;\n
    };\n
}\n
\n
if (window.getComputedStyle)\n
    exports.computedStyle = function(element, style) {\n
        if (style)\n
            return (window.getComputedStyle(element, "") || {})[style] || "";\n
        return window.getComputedStyle(element, "") || {};\n
    };\n
else\n
    exports.computedStyle = function(element, style) {\n
        if (style)\n
            return element.currentStyle[style];\n
        return element.currentStyle;\n
    };\n
\n
exports.scrollbarWidth = function(document) {\n
    var inner = exports.createElement("ace_inner");\n
    inner.style.width = "100%";\n
    inner.style.minWidth = "0px";\n
    inner.style.height = "200px";\n
    inner.style.display = "block";\n
\n
    var outer = exports.createElement("ace_outer");\n
    var style = outer.style;\n
\n
    style.position = "absolute";\n
    style.left = "-10000px";\n
    style.overflow = "hidden";\n
    style.width = "200px";\n
    style.minWidth = "0px";\n
    style.height = "150px";\n
    style.display = "block";\n
\n
    outer.appendChild(inner);\n
\n
    var body = document.documentElement;\n
    body.appendChild(outer);\n
\n
    var noScrollbar = inner.offsetWidth;\n
\n
    style.overflow = "scroll";\n
    var withScrollbar = inner.offsetWidth;\n
\n
    if (noScrollbar == withScrollbar) {\n
        withScrollbar = outer.clientWidth;\n
    }\n
\n
    body.removeChild(outer);\n
\n
    return noScrollbar-withScrollbar;\n
};\n
exports.setInnerHtml = function(el, innerHtml) {\n
    var element = el.cloneNode(false);//document.createElement("div");\n
    element.innerHTML = innerHtml;\n
    el.parentNode.replaceChild(element, el);\n
    return element;\n
};\n
\n
if ("textContent" in document.documentElement) {\n
    exports.setInnerText = function(el, innerText) {\n
        el.textContent = innerText;\n
    };\n
\n
    exports.getInnerText = function(el) {\n
        return el.textContent;\n
    };\n
}\n
else {\n
    exports.setInnerText = function(el, innerText) {\n
        el.innerText = innerText;\n
    };\n
\n
    exports.getInnerText = function(el) {\n
        return el.innerText;\n
    };\n
}\n
\n
exports.getParentWindow = function(document) {\n
    return document.defaultView || document.parentWindow;\n
};\n
\n
});\n
\n
define(\'ace/lib/event\', [\'require\', \'exports\', \'module\' , \'ace/lib/keys\', \'ace/lib/useragent\', \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
var keys = require("./keys");\n
var useragent = require("./useragent");\n
var dom = require("./dom");\n
\n
exports.addListener = function(elem, type, callback) {\n
    if (elem.addEventListener) {\n
        return elem.addEventListener(type, callback, false);\n
    }\n
    if (elem.attachEvent) {\n
        var wrapper = function() {\n
            callback.call(elem, window.event);\n
        };\n
        callback._wrapper = wrapper;\n
        elem.attachEvent("on" + type, wrapper);\n
    }\n
};\n
\n
exports.removeListener = function(elem, type, callback) {\n
    if (elem.removeEventListener) {\n
        return elem.removeEventListener(type, callback, false);\n
    }\n
    if (elem.detachEvent) {\n
        elem.detachEvent("on" + type, callback._wrapper || callback);\n
    }\n
};\n
exports.stopEvent = function(e) {\n
    exports.stopPropagation(e);\n
    exports.preventDefault(e);\n
    return false;\n
};\n
\n
exports.stopPropagation = function(e) {\n
    if (e.stopPropagation)\n
        e.stopPropagation();\n
    else\n
        e.cancelBubble = true;\n
};\n
\n
exports.preventDefault = function(e) {\n
    if (e.preventDefault)\n
        e.preventDefault();\n
    else\n
        e.returnValue = false;\n
};\n
exports.getButton = function(e) {\n
    if (e.type == "dblclick")\n
        return 0;\n
    if (e.type == "contextmenu" || (e.ctrlKey && useragent.isMac))\n
        return 2;\n
    if (e.preventDefault) {\n
        return e.button;\n
    }\n
    else {\n
        return {1:0, 2:2, 4:1}[e.button];\n
    }\n
};\n
\n
exports.capture = function(el, eventHandler, releaseCaptureHandler) {\n
    function onMouseUp(e) {\n
        eventHandler && eventHandler(e);\n
        releaseCaptureHandler && releaseCaptureHandler(e);\n
\n
        exports.removeListener(document, "mousemove", eventHandler, true);\n
        exports.removeListener(document, "mouseup", onMouseUp, true);\n
        exports.removeListener(document, "dragstart", onMouseUp, true);\n
    }\n
\n
    exports.addListener(document, "mousemove", eventHandler, true);\n
    exports.addListener(document, "mouseup", onMouseUp, true);\n
    exports.addListener(document, "dragstart", onMouseUp, true);\n
};\n
\n
exports.addMouseWheelListener = function(el, callback) {\n
    if ("onmousewheel" in el) {\n
        var factor = 8;\n
        exports.addListener(el, "mousewheel", function(e) {\n
            if (e.wheelDeltaX !== undefined) {\n
                e.wheelX = -e.wheelDeltaX / factor;\n
                e.wheelY = -e.wheelDeltaY / factor;\n
            } else {\n
                e.wheelX = 0;\n
                e.wheelY = -e.wheelDelta / factor;\n
            }\n
            callback(e);\n
        });\n
    } else if ("onwheel" in el) {\n
        exports.addListener(el, "wheel",  function(e) {\n
            e.wheelX = (e.deltaX || 0) * 5;\n
            e.wheelY = (e.deltaY || 0) * 5;\n
            callback(e);\n
        });\n
    } else {\n
        exports.addListener(el, "DOMMouseScroll", function(e) {\n
            if (e.axis && e.axis == e.HORIZONTAL_AXIS) {\n
                e.wheelX = (e.detail || 0) * 5;\n
                e.wheelY = 0;\n
            } else {\n
                e.wheelX = 0;\n
                e.wheelY = (e.detail || 0) * 5;\n
            }\n
            callback(e);\n
        });\n
    }\n
};\n
\n
exports.addMultiMouseDownListener = function(el, timeouts, eventHandler, callbackName) {\n
    var clicks = 0;\n
    var startX, startY, timer;\n
    var eventNames = {\n
        2: "dblclick",\n
        3: "tripleclick",\n
        4: "quadclick"\n
    };\n
\n
    exports.addListener(el, "mousedown", function(e) {\n
        if (exports.getButton(e) != 0) {\n
            clicks = 0;\n
        } else if (e.detail > 1) {\n
            clicks++;\n
            if (clicks > 4)\n
                clicks = 1;\n
        } else {\n
            clicks = 1;\n
        }\n
        if (useragent.isIE) {\n
            var isNewClick = Math.abs(e.clientX - startX) > 5 || Math.abs(e.clientY - startY) > 5;\n
            if (isNewClick) {\n
                clicks = 1;\n
            }\n
            if (clicks == 1) {\n
                startX = e.clientX;\n
                startY = e.clientY;\n
            }\n
        }\n
\n
        eventHandler[callbackName]("mousedown", e);\n
\n
        if (clicks > 4)\n
            clicks = 0;\n
        else if (clicks > 1)\n
            return eventHandler[callbackName](eventNames[clicks], e);\n
    });\n
\n
    if (useragent.isOldIE) {\n
        exports.addListener(el, "dblclick", function(e) {\n
            clicks = 2;\n
            if (timer)\n
                clearTimeout(timer);\n
            timer = setTimeout(function() {timer = null}, timeouts[clicks - 1] || 600);\n
            eventHandler[callbackName]("mousedown", e);\n
            eventHandler[callbackName](eventNames[clicks], e);\n
        });\n
    }\n
};\n
\n
function normalizeCommandKeys(callback, e, keyCode) {\n
    var hashId = 0;\n
    if ((useragent.isOpera && !("KeyboardEvent" in window)) && useragent.isMac) {\n
        hashId = 0 | (e.metaKey ? 1 : 0) | (e.altKey ? 2 : 0)\n
            | (e.shiftKey ? 4 : 0) | (e.ctrlKey ? 8 : 0);\n
    } else {\n
        hashId = 0 | (e.ctrlKey ? 1 : 0) | (e.altKey ? 2 : 0)\n
            | (e.shiftKey ? 4 : 0) | (e.metaKey ? 8 : 0);\n
    }\n
\n
    if (!useragent.isMac && pressedKeys) {\n
        if (pressedKeys[91] || pressedKeys[92])\n
            hashId |= 8;\n
        if (pressedKeys.altGr) {\n
            if ((3 & hashId) != 3)\n
                pressedKeys.altGr = 0\n
            else\n
                return;\n
        }\n
        if (keyCode === 18 || keyCode === 17) {\n
            var location = e.location || e.keyLocation;\n
            if (keyCode === 17 && location === 1) {\n
                ts = e.timeStamp;\n
            } else if (keyCode === 18 && hashId === 3 && location === 2) {\n
                var dt = -ts;\n
                ts = e.timeStamp;\n
                dt += ts;\n
                if (dt < 3)\n
                    pressedKeys.altGr = true;\n
            }\n
        }\n
    }\n
    \n
    if (keyCode in keys.MODIFIER_KEYS) {\n
        switch (keys.MODIFIER_KEYS[keyCode]) {\n
            case "Alt":\n
                hashId = 2;\n
                break;\n
            case "Shift":\n
                hashId = 4;\n
                break;\n
            case "Ctrl":\n
                hashId = 1;\n
                break;\n
            default:\n
                hashId = 8;\n
                break;\n
        }\n
        keyCode = 0;\n
    }\n
\n
    if (hashId & 8 && (keyCode === 91 || keyCode === 93)) {\n
        keyCode = 0;\n
    }\n
    \n
    if (!hashId && keyCode === 13) {\n
        if (e.location || e.keyLocation === 3) {\n
            callback(e, hashId, -keyCode)\n
            if (e.defaultPrevented)\n
                return;\n
        }\n
    }\n
    if (!hashId && !(keyCode in keys.FUNCTION_KEYS) && !(keyCode in keys.PRINTABLE_KEYS)) {\n
        return false;\n
    }\n
    \n
    \n
    \n
    return callback(e, hashId, keyCode);\n
}\n
\n
var pressedKeys = null;\n
var ts = 0;\n
exports.addCommandKeyListener = function(el, callback) {\n
    var addListener = exports.addListener;\n
    if (useragent.isOldGecko || (useragent.isOpera && !("KeyboardEvent" in window))) {\n
        var lastKeyDownKeyCode = null;\n
        addListener(el, "keydown", function(e) {\n
            lastKeyDownKeyCode = e.keyCode;\n
        });\n
        addListener(el, "keypress", function(e) {\n
            return normalizeCommandKeys(callback, e, lastKeyDownKeyCode);\n
        });\n
    } else {\n
        var lastDefaultPrevented = null;\n
\n
        addListener(el, "keydown", function(e) {\n
            pressedKeys[e.keyCode] = true;\n
            var result = normalizeCommandKeys(callback, e, e.keyCode);\n
            lastDefaultPrevented = e.defaultPrevented;\n
            return result;\n
        });\n
\n
        addListener(el, "keypress", function(e) {\n
            if (lastDefaultPrevented && (e.ctrlKey || e.altKey || e.shiftKey || e.metaKey)) {\n
                exports.stopEvent(e);\n
                lastDefaultPrevented = null;\n
            }\n
        });\n
\n
        addListener(el, "keyup", function(e) {\n
            pressedKeys[e.keyCode] = null;\n
        });\n
\n
        if (!pressedKeys) {\n
            pressedKeys = Object.create(null);\n
            addListener(window, "focus", function(e) {\n
                pressedKeys = Object.create(null);\n
            });\n
        }\n
    }\n
};\n
\n
if (window.postMessage && !useragent.isOldIE) {\n
    var postMessageId = 1;\n
    exports.nextTick = function(callback, win) {\n
        win = win || window;\n
        var messageName = "zero-timeout-message-" + postMessageId;\n
        exports.addListener(win, "message", function listener(e) {\n
            if (e.data == messageName) {\n
                exports.stopPropagation(e);\n
                exports.removeListener(win, "message", listener);\n
                callback();\n
            }\n
        });\n
        win.postMessage(messageName, "*");\n
    };\n
}\n
\n
\n
exports.nextFrame = window.requestAnimationFrame ||\n
    window.mozRequestAnimationFrame ||\n
    window.webkitRequestAnimationFrame ||\n
    window.msRequestAnimationFrame ||\n
    window.oRequestAnimationFrame;\n
\n
if (exports.nextFrame)\n
    exports.nextFrame = exports.nextFrame.bind(window);\n
else\n
    exports.nextFrame = function(callback) {\n
        setTimeout(callback, 17);\n
    };\n
});\n
\n
define(\'ace/lib/keys\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\'], function(require, exports, module) {\n
\n
\n
var oop = require("./oop");\n
var Keys = (function() {\n
    var ret = {\n
        MODIFIER_KEYS: {\n
            16: \'Shift\', 17: \'Ctrl\', 18: \'Alt\', 224: \'Meta\'\n
        },\n
\n
        KEY_MODS: {\n
            "ctrl": 1, "alt": 2, "option" : 2,\n
            "shift": 4, "meta": 8, "command": 8, "cmd": 8\n
        },\n
\n
        FUNCTION_KEYS : {\n
            8  : "Backspace",\n
            9  : "Tab",\n
            13 : "Return",\n
            19 : "Pause",\n
            27 : "Esc",\n
            32 : "Space",\n
            33 : "PageUp",\n
            34 : "PageDown",\n
            35 : "End",\n
            36 : "Home",\n
            37 : "Left",\n
            38 : "Up",\n
            39 : "Right",\n
            40 : "Down",\n
            44 : "Print",\n
            45 : "Insert",\n
            46 : "Delete",\n
            96 : "Numpad0",\n
            97 : "Numpad1",\n
            98 : "Numpad2",\n
            99 : "Numpad3",\n
            100: "Numpad4",\n
            101: "Numpad5",\n
            102: "Numpad6",\n
            103: "Numpad7",\n
            104: "Numpad8",\n
            105: "Numpad9",\n
            \'-13\': "NumpadEnter",\n
            112: "F1",\n
            113: "F2",\n
            114: "F3",\n
            115: "F4",\n
            116: "F5",\n
            117: "F6",\n
            118: "F7",\n
            119: "F8",\n
            120: "F9",\n
            121: "F10",\n
            122: "F11",\n
            123: "F12",\n
            144: "Numlock",\n
            145: "Scrolllock"\n
        },\n
\n
        PRINTABLE_KEYS: {\n
           32: \' \',  48: \'0\',  49: \'1\',  50: \'2\',  51: \'3\',  52: \'4\', 53:  \'5\',\n
           54: \'6\',  55: \'7\',  56: \'8\',  57: \'9\',  59: \';\',  61: \'=\', 65:  \'a\',\n
           66: \'b\',  67: \'c\',  68: \'d\',  69: \'e\',  70: \'f\',  71: \'g\', 72:  \'h\',\n
           73: \'i\',  74: \'j\',  75: \'k\',  76: \'l\',  77: \'m\',  78: \'n\', 79:  \'o\',\n
           80: \'p\',  81: \'q\',  82: \'r\',  83: \'s\',  84: \'t\',  85: \'u\', 86:  \'v\',\n
           87: \'w\',  88: \'x\',  89: \'y\',  90: \'z\', 107: \'+\', 109: \'-\', 110: \'.\',\n
          188: \',\', 190: \'.\', 191: \'/\', 192: \'`\', 219: \'[\', 220: \'\\\\\',\n
          221: \']\', 222: \'\\\'\'\n
        }\n
    };\n
    for (var i in ret.FUNCTION_KEYS) {\n
        var name = ret.FUNCTION_KEYS[i].toLowerCase();\n
        ret[name] = parseInt(i, 10);\n
    }\n
    oop.mixin(ret, ret.MODIFIER_KEYS);\n
    oop.mixin(ret, ret.PRINTABLE_KEYS);\n
    oop.mixin(ret, ret.FUNCTION_KEYS);\n
    ret.enter = ret["return"];\n
    ret.escape = ret.esc;\n
    ret.del = ret["delete"];\n
    ret[173] = \'-\';\n
\n
    return ret;\n
})();\n
oop.mixin(exports, Keys);\n
\n
exports.keyCodeToString = function(keyCode) {\n
    return (Keys[keyCode] || String.fromCharCode(keyCode)).toLowerCase();\n
}\n
\n
});\n
\n
define(\'ace/lib/oop\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
exports.inherits = (function() {\n
    var tempCtor = function() {};\n
    return function(ctor, superCtor) {\n
        tempCtor.prototype = superCtor.prototype;\n
        ctor.super_ = superCtor.prototype;\n
        ctor.prototype = new tempCtor();\n
        ctor.prototype.constructor = ctor;\n
    };\n
}());\n
\n
exports.mixin = function(obj, mixin) {\n
    for (var key in mixin) {\n
        obj[key] = mixin[key];\n
    }\n
    return obj;\n
};\n
\n
exports.implement = function(proto, mixin) {\n
    exports.mixin(proto, mixin);\n
};\n
\n
});\n
\n
define(\'ace/lib/useragent\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
exports.OS = {\n
    LINUX: "LINUX",\n
    MAC: "MAC",\n
    WINDOWS: "WINDOWS"\n
};\n
exports.getOS = function() {\n
    if (exports.isMac) {\n
        return exports.OS.MAC;\n
    } else if (exports.isLinux) {\n
        return exports.OS.LINUX;\n
    } else {\n
        return exports.OS.WINDOWS;\n
    }\n
};\n
if (typeof navigator != "object")\n
    return;\n
\n
var os = (navigator.platform.match(/mac|win|linux/i) || ["other"])[0].toLowerCase();\n
var ua = navigator.userAgent;\n
exports.isWin = (os == "win");\n
exports.isMac = (os == "mac");\n
exports.isLinux = (os == "linux");\n
exports.isIE = \n
    (navigator.appName == "Microsoft Internet Explorer" || navigator.appName.indexOf("MSAppHost") >= 0)\n
    && parseFloat(navigator.userAgent.match(/MSIE ([0-9]+[\\.0-9]+)/)[1]);\n
    \n
exports.isOldIE = exports.isIE && exports.isIE < 9;\n
exports.isGecko = exports.isMozilla = window.controllers && window.navigator.product === "Gecko";\n
exports.isOldGecko = exports.isGecko && parseInt((navigator.userAgent.match(/rv\\:(\\d+)/)||[])[1], 10) < 4;\n
exports.isOpera = window.opera && Object.prototype.toString.call(window.opera) == "[object Opera]";\n
exports.isWebKit = parseFloat(ua.split("WebKit/")[1]) || undefined;\n
\n
exports.isChrome = parseFloat(ua.split(" Chrome/")[1]) || undefined;\n
\n
exports.isAIR = ua.indexOf("AdobeAIR") >= 0;\n
\n
exports.isIPad = ua.indexOf("iPad") >= 0;\n
\n
exports.isTouchPad = ua.indexOf("TouchPad") >= 0;\n
\n
});\n
\n
define(\'ace/editor\', [\'require\', \'exports\', \'module\' , \'ace/lib/fixoldbrowsers\', \'ace/lib/oop\', \'ace/lib/dom\', \'ace/lib/lang\', \'ace/lib/useragent\', \'ace/keyboard/textinput\', \'ace/mouse/mouse_handler\', \'ace/mouse/fold_handler\', \'ace/keyboard/keybinding\', \'ace/edit_session\', \'ace/search\', \'ace/range\', \'ace/lib/event_emitter\', \'ace/commands/command_manager\', \'ace/commands/default_commands\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
require("./lib/fixoldbrowsers");\n
\n
var oop = require("./lib/oop");\n
var dom = require("./lib/dom");\n
var lang = require("./lib/lang");\n
var useragent = require("./lib/useragent");\n
var TextInput = require("./keyboard/textinput").TextInput;\n
var MouseHandler = require("./mouse/mouse_handler").MouseHandler;\n
var FoldHandler = require("./mouse/fold_handler").FoldHandler;\n
var KeyBinding = require("./keyboard/keybinding").KeyBinding;\n
var EditSession = require("./edit_session").EditSession;\n
var Search = require("./search").Search;\n
var Range = require("./range").Range;\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var CommandManager = require("./commands/command_manager").CommandManager;\n
var defaultCommands = require("./commands/default_commands").commands;\n
var config = require("./config");\n
var Editor = function(renderer, session) {\n
    var container = renderer.getContainerElement();\n
    this.container = container;\n
    this.renderer = renderer;\n
\n
    this.commands = new CommandManager(useragent.isMac ? "mac" : "win", defaultCommands);\n
    this.textInput  = new TextInput(renderer.getTextAreaContainer(), this);\n
    this.renderer.textarea = this.textInput.getElement();\n
    this.keyBinding = new KeyBinding(this);\n
    this.$mouseHandler = new MouseHandler(this);\n
    new FoldHandler(this);\n
\n
    this.$blockScrolling = 0;\n
    this.$search = new Search().set({\n
        wrap: true\n
    });\n
\n
    this.$historyTracker = this.$historyTracker.bind(this);\n
    this.commands.on("exec", this.$historyTracker);\n
\n
    this.$initOperationListeners();\n
    \n
    this._$emitInputEvent = lang.delayedCall(function() {\n
        this._signal("input", {});\n
        this.session.bgTokenizer && this.session.bgTokenizer.scheduleStart();\n
    }.bind(this));\n
    \n
    this.on("change", function(_, _self) {\n
        _self._$emitInputEvent.schedule(31);\n
    });\n
\n
    this.setSession(session || new EditSession(""));\n
    config.resetOptions(this);\n
    config._emit("editor", this);\n
};\n
\n
(function(){\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.$initOperationListeners = function() {\n
        function last(a) {return a[a.length - 1]};\n
\n
        this.selections = [];\n
        this.commands.on("exec", function(e) {\n
            this.startOperation(e);\n
\n
            var command = e.command;\n
            if (command.group == "fileJump") {\n
                var prev = this.prevOp;\n
                if (!prev || prev.command.group != "fileJump") {\n
                    this.lastFileJumpPos = last(this.selections)\n
                }\n
            } else {\n
                this.lastFileJumpPos = null;\n
            }\n
        }.bind(this), true);\n
\n
        this.commands.on("afterExec", function(e) {\n
            var command = e.command;\n
\n
            if (command.group == "fileJump") {\n
                if (this.lastFileJumpPos && !this.curOp.selectionChanged) {\n
                    this.selection.fromJSON(this.lastFileJumpPos);\n
                    return\n
                }\n
            }\n
            this.endOperation(e);\n
        }.bind(this), true);\n
\n
        this.$opResetTimer = lang.delayedCall(this.endOperation.bind(this));\n
\n
        this.on("change", function() {\n
            this.curOp || this.startOperation();\n
            this.curOp.docChanged = true;\n
        }.bind(this), true);\n
\n
        this.on("changeSelection", function() {\n
            this.curOp || this.startOperation();\n
            this.curOp.selectionChanged = true;\n
        }.bind(this), true);\n
    }\n
\n
    this.curOp = null;\n
    this.prevOp = {};\n
    this.startOperation = function(commadEvent) {\n
        if (this.curOp) {\n
            if (!commadEvent || this.curOp.command)\n
                return;\n
            this.prevOp = this.curOp;\n
        }\n
        if (!commadEvent) {\n
            this.previousCommand = null;\n
            commadEvent = {};\n
        }\n
\n
        this.$opResetTimer.schedule();\n
        this.curOp = {\n
            command: commadEvent.command || {},\n
            args: commadEvent.args\n
        };\n
\n
        this.selections.push(this.selection.toJSON());\n
    };\n
\n
    this.endOperation = function() {\n
        if (this.curOp) {\n
            this.prevOp = this.curOp;\n
            this.curOp = null;\n
        }\n
    };\n
\n
    this.$historyTracker = function(e) {\n
        if (!this.$mergeUndoDeltas)\n
            return;\n
\n
\n
        var prev = this.prevOp;\n
        var mergeableCommands = ["backspace", "del", "insertstring"];\n
        var shouldMerge = prev.command && (e.command.name == prev.command.name);\n
        if (e.command.name == "insertstring") {\n
            var text = e.args;\n
            if (this.mergeNextCommand === undefined)\n
                this.mergeNextCommand = true;\n
\n
            shouldMerge = shouldMerge\n
                && this.mergeNextCommand // previous command allows to coalesce with\n
                && (!/\\s/.test(text) || /\\s/.test(prev.args)) // previous insertion was of same type\n
\n
            this.mergeNextCommand = true;\n
        } else {\n
            shouldMerge = shouldMerge\n
                && mergeableCommands.indexOf(e.command.name) !== -1// the command is mergeable\n
        }\n
\n
        if (\n
            this.$mergeUndoDeltas != "always"\n
            && Date.now() - this.sequenceStartTime > 2000\n
        ) {\n
            shouldMerge = false; // the sequence is too long\n
        }\n
\n
        if (shouldMerge)\n
            this.session.mergeUndoDeltas = true;\n
        else if (mergeableCommands.indexOf(e.command.name) !== -1)\n
            this.sequenceStartTime = Date.now();\n
    };\n
    this.setKeyboardHandler = function(keyboardHandler) {\n
        if (!keyboardHandler) {\n
            this.keyBinding.setKeyboardHandler(null);\n
        } else if (typeof keyboardHandler == "string") {\n
            this.$keybindingId = keyboardHandler;\n
            var _self = this;\n
            config.loadModule(["keybinding", keyboardHandler], function(module) {\n
                if (_self.$keybindingId == keyboardHandler)\n
                    _self.keyBinding.setKeyboardHandler(module && module.handler);\n
            });\n
        } else {\n
            this.$keybindingId = null;\n
            this.keyBinding.setKeyboardHandler(keyboardHandler);\n
        }\n
    };\n
    this.getKeyboardHandler = function() {\n
        return this.keyBinding.getKeyboardHandler();\n
    };\n
    this.setSession = function(session) {\n
        if (this.session == session)\n
            return;\n
\n
        if (this.session) {\n
            var oldSession = this.session;\n
            this.session.removeEventListener("change", this.$onDocumentChange);\n
            this.session.removeEventListener("changeMode", this.$onChangeMode);\n
            this.session.removeEventListener("tokenizerUpdate", this.$onTokenizerUpdate);\n
            this.session.removeEventListener("changeTabSize", this.$onChangeTabSize);\n
            this.session.removeEventListener("changeWrapLimit", this.$onChangeWrapLimit);\n
            this.session.removeEventListener("changeWrapMode", this.$onChangeWrapMode);\n
            this.session.removeEventListener("onChangeFold", this.$onChangeFold);\n
            this.session.removeEventListener("changeFrontMarker", this.$onChangeFrontMarker);\n
            this.session.removeEventListener("changeBackMarker", this.$onChangeBackMarker);\n
            this.session.removeEventListener("changeBreakpoint", this.$onChangeBreakpoint);\n
            this.session.removeEventListener("changeAnnotation", this.$onChangeAnnotation);\n
            this.session.removeEventListener("changeOverwrite", this.$onCursorChange);\n
            this.session.removeEventListener("changeScrollTop", this.$onScrollTopChange);\n
            this.session.removeEventListener("changeScrollLeft", this.$onScrollLeftChange);\n
\n
            var selection = this.session.getSelection();\n
            selection.removeEventListener("changeCursor", this.$onCursorChange);\n
            selection.removeEventListener("changeSelection", this.$onSelectionChange);\n
        }\n
\n
        this.session = session;\n
\n
        this.$onDocumentChange = this.onDocumentChange.bind(this);\n
        session.addEventListener("change", this.$onDocumentChange);\n
        this.renderer.setSession(session);\n
\n
        this.$onChangeMode = this.onChangeMode.bind(this);\n
        session.addEventListener("changeMode", this.$onChangeMode);\n
\n
        this.$onTokenizerUpdate = this.onTokenizerUpdate.bind(this);\n
        session.addEventListener("tokenizerUpdate", this.$onTokenizerUpdate);\n
\n
        this.$onChangeTabSize = this.renderer.onChangeTabSize.bind(this.renderer);\n
        session.addEventListener("changeTabSize", this.$onChangeTabSize);\n
\n
        this.$onChangeWrapLimit = this.onChangeWrapLimit.bind(this);\n
        session.addEventListener("changeWrapLimit", this.$onChangeWrapLimit);\n
\n
        this.$onChangeWrapMode = this.onChangeWrapMode.bind(this);\n
        session.addEventListener("changeWrapMode", this.$onChangeWrapMode);\n
\n
        this.$onChangeFold = this.onChangeFold.bind(this);\n
        session.addEventListener("changeFold", this.$onChangeFold);\n
\n
        this.$onChangeFrontMarker = this.onChangeFrontMarker.bind(this);\n
        this.session.addEventListener("changeFrontMarker", this.$onChangeFrontMarker);\n
\n
        this.$onChangeBackMarker = this.onChangeBackMarker.bind(this);\n
        this.session.addEventListener("changeBackMarker", this.$onChangeBackMarker);\n
\n
        this.$onChangeBreakpoint = this.onChangeBreakpoint.bind(this);\n
        this.session.addEventListener("changeBreakpoint", this.$onChangeBreakpoint);\n
\n
        this.$onChangeAnnotation = this.onChangeAnnotation.bind(this);\n
        this.session.addEventListener("changeAnnotation", this.$onChangeAnnotation);\n
\n
        this.$onCursorChange = this.onCursorChange.bind(this);\n
        this.session.addEventListener("changeOverwrite", this.$onCursorChange);\n
\n
        this.$onScrollTopChange = this.onScrollTopChange.bind(this);\n
        this.session.addEventListener("changeScrollTop", this.$onScrollTopChange);\n
\n
        this.$onScrollLeftChange = this.onScrollLeftChange.bind(this);\n
        this.session.addEventListener("changeScrollLeft", this.$onScrollLeftChange);\n
\n
        this.selection = session.getSelection();\n
        this.selection.addEventListener("changeCursor", this.$onCursorChange);\n
\n
        this.$onSelectionChange = this.onSelectionChange.bind(this);\n
        this.selection.addEventListener("changeSelection", this.$onSelectionChange);\n
\n
        this.onChangeMode();\n
\n
        this.$blockScrolling += 1;\n
        this.onCursorChange();\n
        this.$blockScrolling -= 1;\n
\n
        this.onScrollTopChange();\n
        this.onScrollLeftChange();\n
        this.onSelectionChange();\n
        this.onChangeFrontMarker();\n
        this.onChangeBackMarker();\n
        this.onChangeBreakpoint();\n
        this.onChangeAnnotation();\n
        this.session.getUseWrapMode() && this.renderer.adjustWrapLimit();\n
        this.renderer.updateFull();\n
\n
        this._emit("changeSession", {\n
            session: session,\n
            oldSession: oldSession\n
        });\n
    };\n
    this.getSession = function() {\n
        return this.session;\n
    };\n
    this.setValue = function(val, cursorPos) {\n
        this.session.doc.setValue(val);\n
\n
        if (!cursorPos)\n
            this.selectAll();\n
        else if (cursorPos == 1)\n
            this.navigateFileEnd();\n
        else if (cursorPos == -1)\n
            this.navigateFileStart();\n
\n
        return val;\n
    };\n
    this.getValue = function() {\n
        return this.session.getValue();\n
    };\n
    this.getSelection = function() {\n
        return this.selection;\n
    };\n
    this.resize = function(force) {\n
        this.renderer.onResize(force);\n
    };\n
    this.setTheme = function(theme) {\n
        this.renderer.setTheme(theme);\n
    };\n
    this.getTheme = function() {\n
        return this.renderer.getTheme();\n
    };\n
    this.setStyle = function(style) {\n
        this.renderer.setStyle(style);\n
    };\n
    this.unsetStyle = function(style) {\n
        this.renderer.unsetStyle(style);\n
    };\n
    this.getFontSize = function () {\n
        return this.getOption("fontSize") ||\n
           dom.computedStyle(this.container, "fontSize");\n
    };\n
    this.setFontSize = function(size) {\n
        this.setOption("fontSize", size);\n
    };\n
\n
    this.$highlightBrackets = function() {\n
        if (this.session.$bracketHighlight) {\n
            this.session.removeMarker(this.session.$bracketHighlight);\n
            this.session.$bracketHighlight = null;\n
        }\n
\n
        if (this.$highlightPending) {\n
            return;\n
        }\n
        var self = this;\n
        this.$highlightPending = true;\n
        setTimeout(function() {\n
            self.$highlightPending = false;\n
\n
            var pos = self.session.findMatchingBracket(self.getCursorPosition());\n
            if (pos) {\n
                var range = new Range(pos.row, pos.column, pos.row, pos.column+1);\n
            } else if (self.session.$mode.getMatching) {\n
                var range = self.session.$mode.getMatching(self.session);\n
            }\n
            if (range)\n
                self.session.$bracketHighlight = self.session.addMarker(range, "ace_bracket", "text");\n
        }, 50);\n
    };\n
    this.focus = function() {\n
        var _self = this;\n
        setTimeout(function() {\n
            _self.textInput.focus();\n
        });\n
        this.textInput.focus();\n
    };\n
    this.isFocused = function() {\n
        return this.textInput.isFocused();\n
    };\n
    this.blur = function() {\n
        this.textInput.blur();\n
    };\n
    this.onFocus = function() {\n
        if (this.$isFocused)\n
            return;\n
        this.$isFocused = true;\n
        this.renderer.showCursor();\n
        this.renderer.visualizeFocus();\n
        this._emit("focus");\n
    };\n
    this.onBlur = function() {\n
        if (!this.$isFocused)\n
            return;\n
        this.$isFocused = false;\n
        this.renderer.hideCursor();\n
        this.renderer.visualizeBlur();\n
        this._emit("blur");\n
    };\n
\n
    this.$cursorChange = function() {\n
        this.renderer.updateCursor();\n
    };\n
    this.onDocumentChange = function(e) {\n
        var delta = e.data;\n
        var range = delta.range;\n
        var lastRow;\n
\n
        if (range.start.row == range.end.row && delta.action != "insertLines" && delta.action != "removeLines")\n
            lastRow = range.end.row;\n
        else\n
            lastRow = Infinity;\n
        this.renderer.updateLines(range.start.row, lastRow);\n
\n
        this._emit("change", e);\n
        this.$cursorChange();\n
    };\n
\n
    this.onTokenizerUpdate = function(e) {\n
        var rows = e.data;\n
        this.renderer.updateLines(rows.first, rows.last);\n
    };\n
\n
\n
    this.onScrollTopChange = function() {\n
        this.renderer.scrollToY(this.session.getScrollTop());\n
    };\n
\n
    this.onScrollLeftChange = function() {\n
        this.renderer.scrollToX(this.session.getScrollLeft());\n
    };\n
    this.onCursorChange = function() {\n
        this.$cursorChange();\n
\n
        if (!this.$blockScrolling) {\n
            this.renderer.scrollCursorIntoView();\n
        }\n
\n
        this.$highlightBrackets();\n
        this.$updateHighlightActiveLine();\n
        this._emit("changeSelection");\n
    };\n
\n
    this.$updateHighlightActiveLine = function() {\n
        var session = this.getSession();\n
\n
        var highlight;\n
        if (this.$highlightActiveLine) {\n
            if ((this.$selectionStyle != "line" || !this.selection.isMultiLine()))\n
                highlight = this.getCursorPosition();\n
            if (this.renderer.$maxLines && this.session.getLength() === 1)\n
                highlight = false;\n
        }\n
\n
        if (session.$highlightLineMarker && !highlight) {\n
            session.removeMarker(session.$highlightLineMarker.id);\n
            session.$highlightLineMarker = null;\n
        } else if (!session.$highlightLineMarker && highlight) {\n
            var range = new Range(highlight.row, highlight.column, highlight.row, Infinity);\n
            range.id = session.addMarker(range, "ace_active-line", "screenLine");\n
            session.$highlightLineMarker = range;\n
        } else if (highlight) {\n
            session.$highlightLineMarker.start.row = highlight.row;\n
            session.$highlightLineMarker.end.row = highlight.row;\n
            session.$highlightLineMarker.start.column = highlight.column;\n
            session._emit("changeBackMarker");\n
        }\n
    };\n
\n
    this.onSelectionChange = function(e) {\n
        var session = this.session;\n
\n
        if (session.$selectionMarker) {\n
            session.removeMarker(session.$selectionMarker);\n
        }\n
        session.$selectionMarker = null;\n
\n
        if (!this.selection.isEmpty()) {\n
            var range = this.selection.getRange();\n
            var style = this.getSelectionStyle();\n
            session.$selectionMarker = session.addMarker(range, "ace_selection", style);\n
        } else {\n
            this.$updateHighlightActiveLine();\n
        }\n
\n
        var re = this.$highlightSelectedWord && this.$getSelectionHighLightRegexp()\n
        this.session.highlight(re);\n
\n
        this._emit("changeSelection");\n
    };\n
\n
    this.$getSelectionHighLightRegexp = function() {\n
        var session = this.session;\n
\n
        var selection = this.getSelectionRange();\n
        if (selection.isEmpty() || selection.isMultiLine())\n
            return;\n
\n
        var startOuter = selection.start.column - 1;\n
        var endOuter = selection.end.column + 1;\n
        var line = session.getLine(selection.start.row);\n
        var lineCols = line.length;\n
        var needle = line.substring(Math.max(startOuter, 0),\n
                                    Math.min(endOuter, lineCols));\n
        if ((startOuter >= 0 && /^[\\w\\d]/.test(needle)) ||\n
            (endOuter <= lineCols && /[\\w\\d]$/.test(needle)))\n
            return;\n
\n
        needle = line.substring(selection.start.column, selection.end.column);\n
        if (!/^[\\w\\d]+$/.test(needle))\n
            return;\n
\n
        var re = this.$search.$assembleRegExp({\n
            wholeWord: true,\n
            caseSensitive: true,\n
            needle: needle\n
        });\n
\n
        return re;\n
    };\n
\n
\n
    this.onChangeFrontMarker = function() {\n
        this.renderer.updateFrontMarkers();\n
    };\n
\n
    this.onChangeBackMarker = function() {\n
        this.renderer.updateBackMarkers();\n
    };\n
\n
\n
    this.onChangeBreakpoint = function() {\n
        this.renderer.updateBreakpoints();\n
    };\n
\n
    this.onChangeAnnotation = function() {\n
        this.renderer.setAnnotations(this.session.getAnnotations());\n
    };\n
\n
\n
    this.onChangeMode = function(e) {\n
        this.renderer.updateText();\n
        this._emit("changeMode", e);\n
    };\n
\n
\n
    this.onChangeWrapLimit = function() {\n
        this.renderer.updateFull();\n
    };\n
\n
    this.onChangeWrapMode = function() {\n
        this.renderer.onResize(true);\n
    };\n
\n
\n
    this.onChangeFold = function() {\n
        this.$updateHighlightActiveLine();\n
        this.renderer.updateFull();\n
    };\n
    this.getSelectedText = function() {\n
        return this.session.getTextRange(this.getSelectionRange());\n
    };\n
    this.getCopyText = function() {\n
        var text = this.getSelectedText();\n
        this._signal("copy", text);\n
        return text;\n
    };\n
    this.onCopy = function() {\n
        this.commands.exec("copy", this);\n
    };\n
    this.onCut = function() {\n
        this.commands.exec("cut", this);\n
    };\n
    this.onPaste = function(text) {\n
        if (this.$readOnly)\n
            return;\n
        this._emit("paste", text);\n
        this.insert(text);\n
    };\n
\n
\n
    this.execCommand = function(command, args) {\n
        this.commands.exec(command, this, args);\n
    };\n
    this.insert = function(text) {\n
        var session = this.session;\n
        var mode = session.getMode();\n
        var cursor = this.getCursorPosition();\n
\n
        if (this.getBehavioursEnabled()) {\n
            var transform = mode.transformAction(session.getState(cursor.row), \'insertion\', this, session, text);\n
            if (transform) {\n
                if (text !== transform.text) {\n
                    this.session.mergeUndoDeltas = false;\n
                    this.$mergeNextCommand = false;\n
                }\n
                text = transform.text;\n
\n
            }\n
        }\n
        \n
        if (text == "\\t")\n
            text = this.session.getTabString();\n
        if (!this.selection.isEmpty()) {\n
            var range = this.getSelectionRange();\n
            cursor = this.session.remove(range);\n
            this.clearSelection();\n
        }\n
        else if (this.session.getOverwrite()) {\n
            var range = new Range.fromPoints(cursor, cursor);\n
            range.end.column += text.length;\n
            this.session.remove(range);\n
        }\n
\n
        if (text == "\\n" || text == "\\r\\n") {\n
            var line = session.getLine(cursor.row)\n
            if (cursor.column > line.search(/\\S|$/)) {\n
                var d = line.substr(cursor.column).search(/\\S|$/);\n
                session.doc.removeInLine(cursor.row, cursor.column, cursor.column + d);\n
            }\n
        }\n
        this.clearSelection();\n
\n
        var start = cursor.column;\n
        var lineState = session.getState(cursor.row);\n
        var line = session.getLine(cursor.row);\n
        var shouldOutdent = mode.checkOutdent(lineState, line, text);\n
        var end = session.insert(cursor, text);\n
\n
        if (transform && transform.selection) {\n
            if (transform.selection.length == 2) { // Transform relative to the current column\n
                this.selection.setSelectionRange(\n
                    new Range(cursor.row, start + transform.selection[0],\n
                              cursor.row, start + transform.selection[1]));\n
            } else { // Transform relative to the current row.\n
                this.selection.setSelectionRange(\n
                    new Range(cursor.row + transform.selection[0],\n
                              transform.selection[1],\n
                              cursor.row + transform.selection[2],\n
                              transform.selection[3]));\n
            }\n
        }\n
\n
        if (session.getDocument().isNewLine(text)) {\n
            var lineIndent = mode.getNextLineIndent(lineState, line.slice(0, cursor.column), session.getTabString());\n
\n
            session.insert({row: cursor.row+1, column: 0}, lineIndent);\n
        }\n
        if (shouldOutdent)\n
            mode.autoOutdent(lineState, session, cursor.row);\n
    };\n
\n
    this.onTextInput = function(text) {\n
        this.keyBinding.onTextInput(text);\n
    };\n
\n
    this.onCommandKey = function(e, hashId, keyCode) {\n
        this.keyBinding.onCommandKey(e, hashId, keyCode);\n
    };\n
    this.setOverwrite = function(overwrite) {\n
        this.session.setOverwrite(overwrite);\n
    };\n
    this.getOverwrite = function() {\n
        return this.session.getOverwrite();\n
    };\n
    this.toggleOverwrite = function() {\n
        this.session.toggleOverwrite();\n
    };\n
    this.setScrollSpeed = function(speed) {\n
        this.setOption("scrollSpeed", speed);\n
    };\n
    this.getScrollSpeed = function() {\n
        return this.getOption("scrollSpeed");\n
    };\n
    this.setDragDelay = function(dragDelay) {\n
        this.setOption("dragDelay", dragDelay);\n
    };\n
    this.getDragDelay = function() {\n
        return this.getOption("dragDelay");\n
    };\n
    this.setSelectionStyle = function(val) {\n
        this.setOption("selectionStyle", val);\n
    };\n
    this.getSelectionStyle = function() {\n
        return this.getOption("selectionStyle");\n
    };\n
    this.setHighlightActiveLine = function(shouldHighlight) {\n
        this.setOption("highlightActiveLine", shouldHighlight);\n
    };\n
    this.getHighlightActiveLine = function() {\n
        return this.getOption("highlightActiveLine");\n
    };\n
    this.setHighlightGutterLine = function(shouldHighlight) {\n
        this.setOption("highlightGutterLine", shouldHighlight);\n
    };\n
\n
    this.getHighlightGutterLine = function() {\n
        return this.getOption("highlightGutterLine");\n
    };\n
    this.setHighlightSelectedWord = function(shouldHighlight) {\n
        this.setOption("highlightSelectedWord", shouldHighlight);\n
    };\n
    this.getHighlightSelectedWord = function() {\n
        return this.$highlightSelectedWord;\n
    };\n
\n
    this.setAnimatedScroll = function(shouldAnimate){\n
        this.renderer.setAnimatedScroll(shouldAnimate);\n
    };\n
\n
    this.getAnimatedScroll = function(){\n
        return this.renderer.getAnimatedScroll();\n
    };\n
    this.setShowInvisibles = function(showInvisibles) {\n
        this.renderer.setShowInvisibles(showInvisibles);\n
    };\n
    this.getShowInvisibles = function() {\n
        return this.renderer.getShowInvisibles();\n
    };\n
\n
    this.setDisplayIndentGuides = function(display) {\n
        this.renderer.setDisplayIndentGuides(display);\n
    };\n
\n
    this.getDisplayIndentGuides = function() {\n
        return this.renderer.getDisplayIndentGuides();\n
    };\n
    this.setShowPrintMargin = function(showPrintMargin) {\n
        this.renderer.setShowPrintMargin(showPrintMargin);\n
    };\n
    this.getShowPrintMargin = function() {\n
        return this.renderer.getShowPrintMargin();\n
    };\n
    this.setPrintMarginColumn = function(showPrintMargin) {\n
        this.renderer.setPrintMarginColumn(showPrintMargin);\n
    };\n
    this.getPrintMarginColumn = function() {\n
        return this.renderer.getPrintMarginColumn();\n
    };\n
    this.setReadOnly = function(readOnly) {\n
        this.setOption("readOnly", readOnly);\n
    };\n
    this.getReadOnly = function() {\n
        return this.getOption("readOnly");\n
    };\n
    this.setBehavioursEnabled = function (enabled) {\n
        this.setOption("behavioursEnabled", enabled);\n
    };\n
    this.getBehavioursEnabled = function () {\n
        return this.getOption("behavioursEnabled");\n
    };\n
    this.setWrapBehavioursEnabled = function (enabled) {\n
        this.setOption("wrapBehavioursEnabled", enabled);\n
    };\n
    this.getWrapBehavioursEnabled = function () {\n
        return this.getOption("wrapBehavioursEnabled");\n
    };\n
    this.setShowFoldWidgets = function(show) {\n
        this.setOption("showFoldWidgets", show);\n
\n
    };\n
    this.getShowFoldWidgets = function() {\n
        return this.getOption("showFoldWidgets");\n
    };\n
\n
    this.setFadeFoldWidgets = function(fade) {\n
        this.setOption("fadeFoldWidgets", fade);\n
    };\n
\n
    this.getFadeFoldWidgets = function() {\n
        return this.getOption("fadeFoldWidgets");\n
    };\n
    this.remove = function(dir) {\n
        if (this.selection.isEmpty()){\n
            if (dir == "left")\n
                this.selection.selectLeft();\n
            else\n
                this.selection.selectRight();\n
        }\n
\n
        var range = this.getSelectionRange();\n
        if (this.getBehavioursEnabled()) {\n
            var session = this.session;\n
            var state = session.getState(range.start.row);\n
            var new_range = session.getMode().transformAction(state, \'deletion\', this, session, range);\n
\n
            if (range.end.column == 0) {\n
                var text = session.getTextRange(range);\n
                if (text[text.length - 1] == "\\n") {\n
                    var line = session.getLine(range.end.row)\n
                    if (/^\\s+$/.test(line)) {\n
                        range.end.column = line.length\n
                    }\n
                }\n
            }\n
            if (new_range)\n
                range = new_range;\n
        }\n
\n
        this.session.remove(range);\n
        this.clearSelection();\n
    };\n
    this.removeWordRight = function() {\n
        if (this.selection.isEmpty())\n
            this.selection.selectWordRight();\n
\n
        this.session.remove(this.getSelectionRange());\n
        this.clearSelection();\n
    };\n
    this.removeWordLeft = function() {\n
        if (this.selection.isEmpty())\n
            this.selection.selectWordLeft();\n
\n
        this.session.remove(this.getSelectionRange());\n
        this.clearSelection();\n
    };\n
    this.removeToLineStart = function() {\n
        if (this.selection.isEmpty())\n
            this.selection.selectLineStart();\n
\n
        this.session.remove(this.getSelectionRange());\n
        this.clearSelection();\n
    };\n
    this.removeToLineEnd = function() {\n
        if (this.selection.isEmpty())\n
            this.selection.selectLineEnd();\n
\n
        var range = this.getSelectionRange();\n
        if (range.start.column == range.end.column && range.start.row == range.end.row) {\n
            range.end.column = 0;\n
            range.end.row++;\n
        }\n
\n
        this.session.remove(range);\n
        this.clearSelection();\n
    };\n
    this.splitLine = function() {\n
        if (!this.selection.isEmpty()) {\n
            this.session.remove(this.getSelectionRange());\n
            this.clearSelection();\n
        }\n
\n
        var cursor = this.getCursorPosition();\n
        this.insert("\\n");\n
        this.moveCursorToPosition(cursor);\n
    };\n
    this.transposeLetters = function() {\n
        if (!this.selection.isEmpty()) {\n
            return;\n
        }\n
\n
        var cursor = this.getCursorPosition();\n
        var column = cursor.column;\n
        if (column === 0)\n
            return;\n
\n
        var line = this.session.getLine(cursor.row);\n
        var swap, range;\n
        if (column < line.length) {\n
            swap = line.charAt(column) + line.charAt(column-1);\n
            range = new Range(cursor.row, column-1, cursor.row, column+1);\n
        }\n
        else {\n
            swap = line.charAt(column-1) + line.charAt(column-2);\n
            range = new Range(cursor.row, column-2, cursor.row, column);\n
        }\n
        this.session.replace(range, swap);\n
    };\n
    this.toLowerCase = function() {\n
        var originalRange = this.getSelectionRange();\n
        if (this.selection.isEmpty()) {\n
            this.selection.selectWord();\n
        }\n
\n
        var range = this.getSelectionRange();\n
        var text = this.session.getTextRange(range);\n
        this.session.replace(range, text.toLowerCase());\n
        this.selection.setSelectionRange(originalRange);\n
    };\n
    this.toUpperCase = function() {\n
        var originalRange = this.getSelectionRange();\n
        if (this.selection.isEmpty()) {\n
            this.selection.selectWord();\n
        }\n
\n
        var range = this.getSelectionRange();\n
        var text = this.session.getTextRange(range);\n
        this.session.replace(range, text.toUpperCase());\n
        this.selection.setSelectionRange(originalRange);\n
    };\n
    this.indent = function() {\n
        var session = this.session;\n
        var range = this.getSelectionRange();\n
\n
        if (range.start.row < range.end.row) {\n
            var rows = this.$getSelectedRows();\n
            session.indentRows(rows.first, rows.last, "\\t");\n
            return;\n
        } else if (range.start.column < range.end.column) {\n
            var text = session.getTextRange(range)\n
            if (!/^\\s+$/.test(text)) {\n
                var rows = this.$getSelectedRows();\n
                session.indentRows(rows.first, rows.last, "\\t");\n
                return;\n
            }\n
        }\n
        \n
        var line = session.getLine(range.start.row)\n
        var position = range.start;\n
        var size = session.getTabSize();\n
        var column = session.documentToScreenColumn(position.row, position.column);\n
\n
        if (this.session.getUseSoftTabs()) {\n
            var count = (size - column % size);\n
            var indentString = lang.stringRepeat(" ", count);\n
        } else {\n
            var count = column % size;\n
            while (line[range.start.column] == " " && count) {\n
                range.start.column--;\n
                count--;\n
            }\n
            this.selection.setSelectionRange(range);\n
            indentString = "\\t";\n
        }\n
        return this.insert(indentString);\n
    };\n
    this.blockIndent = function() {\n
        var rows = this.$getSelectedRows();\n
        this.session.indentRows(rows.first, rows.last, "\\t");\n
    };\n
    this.blockOutdent = function() {\n
        var selection = this.session.getSelection();\n
        this.session.outdentRows(selection.getRange());\n
    };\n
    this.sortLines = function() {\n
        var rows = this.$getSelectedRows();\n
        var session = this.session;\n
\n
        var lines = [];\n
        for (i = rows.first; i <= rows.last; i++)\n
            lines.push(session.getLine(i));\n
\n
        lines.sort(function(a, b) {\n
            if (a.toLowerCase() < b.toLowerCase()) return -1;\n
            if (a.toLowerCase() > b.toLowerCase()) return 1;\n
            return 0;\n
        });\n
\n
        var deleteRange = new Range(0, 0, 0, 0);\n
        for (var i = rows.first; i <= rows.last; i++) {\n
            var line = session.getLine(i);\n
            deleteRange.start.row = i;\n
            deleteRange.end.row = i;\n
            deleteRange.end.column = line.length;\n
            session.replace(deleteRange, lines[i-rows.first]);\n
        }\n
    };\n
    this.toggleCommentLines = function() {\n
        var state = this.session.getState(this.getCursorPosition().row);\n
        var rows = this.$getSelectedRows();\n
        this.session.getMode().toggleCommentLines(state, this.session, rows.first, rows.last);\n
    };\n
\n
    this.toggleBlockComment = function() {\n
        var cursor = this.getCursorPosition();\n
        var state = this.session.getState(cursor.row);\n
        var range = this.getSelectionRange();\n
        this.session.getMode().toggleBlockComment(state, this.session, range, cursor);\n
    };\n
    this.getNumberAt = function( row, column ) {\n
        var _numberRx = /[\\-]?[0-9]+(?:\\.[0-9]+)?/g\n
        _numberRx.lastIndex = 0\n
\n
        var s = this.session.getLine(row)\n
        while (_numberRx.lastIndex < column) {\n
            var m = _numberRx.exec(s)\n
            if(m.index <= column && m.index+m[0].length >= column){\n
                var number = {\n
                    value: m[0],\n
                    start: m.index,\n
                    end: m.index+m[0].length\n
                }\n
                return number;\n
            }\n
        }\n
        return null;\n
    };\n
    this.modifyNumber = function(amount) {\n
        var row = this.selection.getCursor().row;\n
        var column = this.selection.getCursor().column;\n
        var charRange = new Range(row, column-1, row, column);\n
\n
        var c = this.session.getTextRange(charRange);\n
        if (!isNaN(parseFloat(c)) && isFinite(c)) {\n
            var nr = this.getNumberAt(row, column);\n
            if (nr) {\n
                var fp = nr.value.indexOf(".") >= 0 ? nr.start + nr.value.indexOf(".") + 1 : nr.end;\n
                var decimals = nr.start + nr.value.length - fp;\n
\n
                var t = parseFloat(nr.value);\n
                t *= Math.pow(10, decimals);\n
\n
\n
                if(fp !== nr.end && column < fp){\n
                    amount *= Math.pow(10, nr.end - column - 1);\n
                } else {\n
                    amount *= Math.pow(10, nr.end - column);\n
                }\n
\n
                t += amount;\n
                t /= Math.pow(10, decimals);\n
                var nnr = t.toFixed(decimals);\n
                var replaceRange = new Range(row, nr.start, row, nr.end);\n
                this.session.replace(replaceRange, nnr);\n
                this.moveCursorTo(row, Math.max(nr.start +1, column + nnr.length - nr.value.length));\n
\n
            }\n
        }\n
    };\n
    this.removeLines = function() {\n
        var rows = this.$getSelectedRows();\n
        var range;\n
        if (rows.first === 0 || rows.last+1 < this.session.getLength())\n
            range = new Range(rows.first, 0, rows.last+1, 0);\n
        else\n
            range = new Range(\n
                rows.first-1, this.session.getLine(rows.first-1).length,\n
                rows.last, this.session.getLine(rows.last).length\n
            );\n
        this.session.remove(range);\n
        this.clearSelection();\n
    };\n
\n
    this.duplicateSelection = function() {\n
        var sel = this.selection;\n
        var doc = this.session;\n
        var range = sel.getRange();\n
        var reverse = sel.isBackwards();\n
        if (range.isEmpty()) {\n
            var row = range.start.row;\n
            doc.duplicateLines(row, row);\n
        } else {\n
            var point = reverse ? range.start : range.end;\n
            var endPoint = doc.insert(point, doc.getTextRange(range), false);\n
            range.start = point;\n
            range.end = endPoint;\n
\n
            sel.setSelectionRange(range, reverse)\n
        }\n
    };\n
    this.moveLinesDown = function() {\n
        this.$moveLines(function(firstRow, lastRow) {\n
            return this.session.moveLinesDown(firstRow, lastRow);\n
        });\n
    };\n
    this.moveLinesUp = function() {\n
        this.$moveLines(function(firstRow, lastRow) {\n
            return this.session.moveLinesUp(firstRow, lastRow);\n
        });\n
    };\n
    this.moveText = function(range, toPosition, copy) {\n
        return this.session.moveText(range, toPosition, copy);\n
    };\n
    this.copyLinesUp = function() {\n
        this.$moveLines(function(firstRow, lastRow) {\n
            this.session.duplicateLines(firstRow, lastRow);\n
            return 0;\n
        });\n
    };\n
    this.copyLinesDown = function() {\n
        this.$moveLines(function(firstRow, lastRow) {\n
            return this.session.duplicateLines(firstRow, lastRow);\n
        });\n
    };\n
    this.$moveLines = function(mover) {\n
        var selection = this.selection;\n
        if (!selection.inMultiSelectMode || this.inVirtualSelectionMode) {\n
            var range = selection.toOrientedRange();\n
            var rows = this.$getSelectedRows(range);\n
            var linesMoved = mover.call(this, rows.first, rows.last);\n
            range.moveBy(linesMoved, 0);\n
            selection.fromOrientedRange(range);\n
        } else {\n
            var ranges = selection.rangeList.ranges;\n
            selection.rangeList.detach(this.session);\n
\n
            for (var i = ranges.length; i--; ) {\n
                var rangeIndex = i;\n
                var rows = ranges[i].collapseRows();\n
                var last = rows.end.row;\n
                var first = rows.start.row;\n
                while (i--) {\n
                    var rows = ranges[i].collapseRows();\n
                    if (first - rows.end.row <= 1)\n
                        first = rows.end.row;\n
                    else\n
                        break;\n
                }\n
                i++;\n
\n
                var linesMoved = mover.call(this, first, last);\n
                while (rangeIndex >= i) {\n
                    ranges[rangeIndex].moveBy(linesMoved, 0);\n
                    rangeIndex--;\n
                }\n
            }\n
            selection.fromOrientedRange(selection.ranges[0]);\n
            selection.rangeList.attach(this.session);\n
        }\n
    };\n
    this.$getSelectedRows = function() {\n
        var range = this.getSelectionRange().collapseRows();\n
\n
        return {\n
            first: range.start.row,\n
            last: range.end.row\n
        };\n
    };\n
\n
    this.onCompositionStart = function(text) {\n
        this.renderer.showComposition(this.getCursorPosition());\n
    };\n
\n
    this.onCompositionUpdate = function(text) {\n
        this.renderer.setCompositionText(text);\n
    };\n
\n
    this.onCompositionEnd = function() {\n
        this.renderer.hideComposition();\n
    };\n
    this.getFirstVisibleRow = function() {\n
        return this.renderer.getFirstVisibleRow();\n
    };\n
    this.getLastVisibleRow = function() {\n
        return this.renderer.getLastVisibleRow();\n
    };\n
    this.isRowVisible = function(row) {\n
        return (row >= this.getFirstVisibleRow() && row <= this.getLastVisibleRow());\n
    };\n
    this.isRowFullyVisible = function(row) {\n
        return (row >= this.renderer.getFirstFullyVisibleRow() && row <= this.renderer.getLastFullyVisibleRow());\n
    };\n
    this.$getVisibleRowCount = function() {\n
        return this.renderer.getScrollBottomRow() - this.renderer.getScrollTopRow() + 1;\n
    };\n
\n
    this.$moveByPage = function(dir, select) {\n
        var renderer = this.renderer;\n
        var config = this.renderer.layerConfig;\n
        var rows = dir * Math.floor(config.height / config.lineHeight);\n
\n
        this.$blockScrolling++;\n
        if (select == true) {\n
            this.selection.$moveSelection(function(){\n
                this.moveCursorBy(rows, 0);\n
            });\n
        } else if (select == false) {\n
            this.selection.moveCursorBy(rows, 0);\n
            this.selection.clearSelection();\n
        }\n
        this.$blockScrolling--;\n
\n
        var scrollTop = renderer.scrollTop;\n
\n
        renderer.scrollBy(0, rows * config.lineHeight);\n
        if (select != null)\n
            renderer.scrollCursorIntoView(null, 0.5);\n
\n
        renderer.animateScrolling(scrollTop);\n
    };\n
    this.selectPageDown = function() {\n
        this.$moveByPage(1, true);\n
    };\n
    this.selectPageUp = function() {\n
        this.$moveByPage(-1, true);\n
    };\n
    this.gotoPageDown = function() {\n
       this.$moveByPage(1, false);\n
    };\n
    this.gotoPageUp = function() {\n
        this.$moveByPage(-1, false);\n
    };\n
    this.scrollPageDown = function() {\n
        this.$moveByPage(1);\n
    };\n
    this.scrollPageUp = function() {\n
        this.$moveByPage(-1);\n
    };\n
    this.scrollToRow = function(row) {\n
        this.renderer.scrollToRow(row);\n
    };\n
    this.scrollToLine = function(line, center, animate, callback) {\n
        this.renderer.scrollToLine(line, center, animate, callback);\n
    };\n
    this.centerSelection = function() {\n
        var range = this.getSelectionRange();\n
        var pos = {\n
            row: Math.floor(range.start.row + (range.end.row - range.start.row) / 2),\n
            column: Math.floor(range.start.column + (range.end.column - range.start.column) / 2)\n
        }\n
        this.renderer.alignCursor(pos, 0.5);\n
    };\n
    this.getCursorPosition = function() {\n
        return this.selection.getCursor();\n
    };\n
    this.getCursorPositionScreen = function() {\n
        return this.session.documentToScreenPosition(this.getCursorPosition());\n
    };\n
    this.getSelectionRange = function() {\n
        return this.selection.getRange();\n
    };\n
    this.selectAll = function() {\n
        this.$blockScrolling += 1;\n
        this.selection.selectAll();\n
        this.$blockScrolling -= 1;\n
    };\n
    this.clearSelection = function() {\n
        this.selection.clearSelection();\n
    };\n
    this.moveCursorTo = function(row, column) {\n
        this.selection.moveCursorTo(row, column);\n
    };\n
    this.moveCursorToPosition = function(pos) {\n
        this.selection.moveCursorToPosition(pos);\n
    };\n
    this.jumpToMatching = function(select) {\n
        var cursor = this.getCursorPosition();\n
\n
        var range = this.session.getBracketRange(cursor);\n
        if (!range) {\n
            range = this.find({\n
                needle: /[{}()\\[\\]]/g,\n
                preventScroll:true,\n
                start: {row: cursor.row, column: cursor.column - 1}\n
            });\n
            if (!range)\n
                return;\n
            var pos = range.start;\n
            if (pos.row == cursor.row && Math.abs(pos.column - cursor.column) < 2)\n
                range = this.session.getBracketRange(pos);\n
        }\n
\n
        pos = range && range.cursor || pos;\n
        if (pos) {\n
            if (select) {\n
                if (range && range.isEqual(this.getSelectionRange()))\n
                    this.clearSelection();\n
                else\n
                    this.selection.selectTo(pos.row, pos.column);\n
            } else {\n
                this.clearSelection();\n
                this.moveCursorTo(pos.row, pos.column);\n
            }\n
        }\n
    };\n
    this.gotoLine = function(lineNumber, column, animate) {\n
        this.selection.clearSelection();\n
        this.session.unfold({row: lineNumber - 1, column: column || 0});\n
\n
        this.$blockScrolling += 1;\n
        this.exitMultiSelectMode && this.exitMultiSelectMode();\n
        this.moveCursorTo(lineNumber - 1, column || 0);\n
        this.$blockScrolling -= 1;\n
\n
        if (!this.isRowFullyVisible(lineNumber - 1))\n
            this.scrollToLine(lineNumber - 1, true, animate);\n
    };\n
    this.navigateTo = function(row, column) {\n
        this.clearSelection();\n
        this.moveCursorTo(row, column);\n
    };\n
    this.navigateUp = function(times) {\n
        if (this.selection.isMultiLine() && !this.selection.isBackwards()) {\n
            var selectionStart = this.selection.anchor.getPosition();\n
            return this.moveCursorToPosition(selectionStart);\n
        }\n
        this.selection.clearSelection();\n
        times = times || 1;\n
        this.selection.moveCursorBy(-times, 0);\n
    };\n
    this.navigateDown = function(times) {\n
        if (this.selection.isMultiLine() && this.selection.isBackwards()) {\n
            var selectionEnd = this.selection.anchor.getPosition();\n
            return this.moveCursorToPosition(selectionEnd);\n
        }\n
        this.selection.clearSelection();\n
        times = times || 1;\n
        this.selection.moveCursorBy(times, 0);\n
    };\n
    this.navigateLeft = function(times) {\n
        if (!this.selection.isEmpty()) {\n
            var selectionStart = this.getSelectionRange().start;\n
            this.moveCursorToPosition(selectionStart);\n
        }\n
        else {\n
            times = times || 1;\n
            while (times--) {\n
                this.selection.moveCursorLeft();\n
            }\n
        }\n
        this.clearSelection();\n
    };\n
    this.navigateRight = function(times) {\n
        if (!this.selection.isEmpty()) {\n
            var selectionEnd = this.getSelectionRange().end;\n
            this.moveCursorToPosition(selectionEnd);\n
        }\n
        else {\n
            times = times || 1;\n
            while (times--) {\n
                this.selection.moveCursorRight();\n
            }\n
        }\n
        this.clearSelection();\n
    };\n
    this.navigateLineStart = function() {\n
        this.selection.moveCursorLineStart();\n
        this.clearSelection();\n
    };\n
    this.navigateLineEnd = function() {\n
        this.selection.moveCursorLineEnd();\n
        this.clearSelection();\n
    };\n
    this.navigateFileEnd = function() {\n
        var scrollTop = this.renderer.scrollTop;\n
        this.selection.moveCursorFileEnd();\n
        this.clearSelection();\n
        this.renderer.animateScrolling(scrollTop);\n
    };\n
    this.navigateFileStart = function() {\n
        var scrollTop = this.renderer.scrollTop;\n
        this.selection.moveCursorFileStart();\n
        this.clearSelection();\n
        this.renderer.animateScrolling(scrollTop);\n
    };\n
    this.navigateWordRight = function() {\n
        this.selection.moveCursorWordRight();\n
        this.clearSelection();\n
    };\n
    this.navigateWordLeft = function() {\n
        this.selection.moveCursorWordLeft();\n
        this.clearSelection();\n
    };\n
    this.replace = function(replacement, options) {\n
        if (options)\n
            this.$search.set(options);\n
\n
        var range = this.$search.find(this.session);\n
        var replaced = 0;\n
        if (!range)\n
            return replaced;\n
\n
        if (this.$tryReplace(range, replacement)) {\n
            replaced = 1;\n
        }\n
        if (range !== null) {\n
            this.selection.setSelectionRange(range);\n
            this.renderer.scrollSelectionIntoView(range.start, range.end);\n
        }\n
\n
        return replaced;\n
    };\n
    this.replaceAll = function(replacement, options) {\n
        if (options) {\n
            this.$search.set(options);\n
        }\n
\n
        var ranges = this.$search.findAll(this.session);\n
        var replaced = 0;\n
        if (!ranges.length)\n
            return replaced;\n
\n
        this.$blockScrolling += 1;\n
\n
        var selection = this.getSelectionRange();\n
        this.clearSelection();\n
        this.selection.moveCursorTo(0, 0);\n
\n
        for (var i = ranges.length - 1; i >= 0; --i) {\n
            if(this.$tryReplace(ranges[i], replacement)) {\n
                replaced++;\n
            }\n
        }\n
\n
        this.selection.setSelectionRange(selection);\n
        this.$blockScrolling -= 1;\n
\n
        return replaced;\n
    };\n
\n
    this.$tryReplace = function(range, replacement) {\n
        var input = this.session.getTextRange(range);\n
        replacement = this.$search.replace(input, replacement);\n
        if (replacement !== null) {\n
            range.end = this.session.replace(range, replacement);\n
            return range;\n
        } else {\n
            return null;\n
        }\n
    };\n
    this.getLastSearchOptions = function() {\n
        return this.$search.getOptions();\n
    };\n
    this.find = function(needle, options, animate) {\n
        if (!options)\n
            options = {};\n
\n
        if (typeof needle == "string" || needle instanceof RegExp)\n
            options.needle = needle;\n
        else if (typeof needle == "object")\n
            oop.mixin(options, needle);\n
\n
        var range = this.selection.getRange();\n
        if (options.needle == null) {\n
            needle = this.session.getTextRange(range)\n
                || this.$search.$options.needle;\n
            if (!needle) {\n
                range = this.session.getWordRange(range.start.row, range.start.column);\n
                needle = this.session.getTextRange(range);\n
            }\n
            this.$search.set({needle: needle});\n
        }\n
\n
        this.$search.set(options);\n
        if (!options.start)\n
            this.$search.set({start: range});\n
\n
        var newRange = this.$search.find(this.session);\n
        if (options.preventScroll)\n
            return newRange;\n
        if (newRange) {\n
            this.revealRange(newRange, animate);\n
            return newRange;\n
        }\n
        if (options.backwards)\n
            range.start = range.end;\n
        else\n
            range.end = range.start;\n
        this.selection.setRange(range);\n
    };\n
    this.findNext = function(options, animate) {\n
        this.find({skipCurrent: true, backwards: false}, options, animate);\n
    };\n
    this.findPrevious = function(options, animate) {\n
        this.find(options, {skipCurrent: true, backwards: true}, animate);\n
    };\n
\n
    this.revealRange = function(range, animate) {\n
        this.$blockScrolling += 1;\n
        this.session.unfold(range);\n
        this.selection.setSelectionRange(range);\n
        this.$blockScrolling -= 1;\n
\n
        var scrollTop = this.renderer.scrollTop;\n
        this.renderer.scrollSelectionIntoView(range.start, range.end, 0.5);\n
        if (animate != false)\n
            this.renderer.animateScrolling(scrollTop);\n
    };\n
    this.undo = function() {\n
        this.$blockScrolling++;\n
        this.session.getUndoManager().undo();\n
        this.$blockScrolling--;\n
        this.renderer.scrollCursorIntoView(null, 0.5);\n
    };\n
    this.redo = function() {\n
        this.$blockScrolling++;\n
        this.session.getUndoManager().redo();\n
        this.$blockScrolling--;\n
        this.renderer.scrollCursorIntoView(null, 0.5);\n
    };\n
    this.destroy = function() {\n
        this.renderer.destroy();\n
        this._emit("destroy", this);\n
    };\n
    this.setAutoScrollEditorIntoView = function(enable) {\n
        if (enable === false)\n
            return;\n
        var rect;\n
        var self = this;\n
        var shouldScroll = false;\n
        if (!this.$scrollAnchor)\n
            this.$scrollAnchor = document.createElement("div");\n
        var scrollAnchor = this.$scrollAnchor;\n
        scrollAnchor.style.cssText = "position:absolute";\n
        this.container.insertBefore(scrollAnchor, this.container.firstChild);\n
        var onChangeSelection = this.on("changeSelection", function() {\n
            shouldScroll = true;\n
        });\n
        var onBeforeRender = this.renderer.on("beforeRender", function() {\n
            if (shouldScroll)\n
                rect = self.renderer.container.getBoundingClientRect();\n
        });\n
        var onAfterRender = this.renderer.on("afterRender", function() {\n
            if (shouldScroll && rect && self.isFocused()) {\n
                var renderer = self.renderer;\n
                var pos = renderer.$cursorLayer.$pixelPos;\n
                var config = renderer.layerConfig;\n
                var top = pos.top - config.offset;\n
                if (pos.top >= 0 && top + rect.top < 0) {\n
                    shouldScroll = true;\n
                } else if (pos.top < config.height &&\n
                    pos.top + rect.top + config.lineHeight > window.innerHeight) {\n
                    shouldScroll = false;\n
                } else {\n
                    shouldScroll = null;\n
                }\n
                if (shouldScroll != null) {\n
                    scrollAnchor.style.top = top + "px";\n
                    scrollAnchor.style.left = pos.left + "px";\n
                    scrollAnchor.style.height = config.lineHeight + "px";\n
                    scrollAnchor.scrollIntoView(shouldScroll);\n
                }\n
                shouldScroll = rect = null;\n
            }\n
        });\n
        this.setAutoScrollEditorIntoView = function(enable) {\n
            if (enable === true)\n
                return;\n
            delete this.setAutoScrollEditorIntoView;\n
            this.removeEventListener("changeSelection", onChangeSelection);\n
            this.renderer.removeEventListener("afterRender", onAfterRender);\n
            this.renderer.removeEventListener("beforeRender", onBeforeRender);\n
        };\n
    };\n
\n
\n
    this.$resetCursorStyle = function() {\n
        var style = this.$cursorStyle || "ace";\n
        var cursorLayer = this.renderer.$cursorLayer;\n
        if (!cursorLayer)\n
            return;\n
        cursorLayer.setSmoothBlinking(style == "smooth");\n
        cursorLayer.isBlinking = !this.$readOnly && style != "wide";\n
    };\n
\n
}).call(Editor.prototype);\n
\n
\n
\n
config.defineOptions(Editor.prototype, "editor", {\n
    selectionStyle: {\n
        set: function(style) {\n
            this.onSelectionChange();\n
            this._emit("changeSelectionStyle", {data: style});\n
        },\n
        initialValue: "line"\n
    },\n
    highlightActiveLine: {\n
        set: function() {this.$updateHighlightActiveLine();},\n
        initialValue: true\n
    },\n
    highlightSelectedWord: {\n
        set: function(shouldHighlight) {this.$onSelectionChange();},\n
        initialValue: true\n
    },\n
    readOnly: {\n
        set: function(readOnly) {\n
            this.textInput.setReadOnly(readOnly); \n
            this.$resetCursorStyle(); \n
        },\n
        initialValue: false\n
    },\n
    cursorStyle: {\n
        set: function(val) { this.$resetCursorStyle(); },\n
        values: ["ace", "slim", "smooth", "wide"],\n
        initialValue: "ace"\n
    },\n
    mergeUndoDeltas: {\n
        values: [false, true, "always"],\n
        initialValue: true\n
    },\n
    behavioursEnabled: {initialValue: true},\n
    wrapBehavioursEnabled: {initialValue: true},\n
\n
    hScrollBarAlwaysVisible: "renderer",\n
    vScrollBarAlwaysVisible: "renderer",\n
    highlightGutterLine: "renderer",\n
    animatedScroll: "renderer",\n
    showInvisibles: "renderer",\n
    showPrintMargin: "renderer",\n
    printMarginColumn: "renderer",\n
    printMargin: "renderer",\n
    fadeFoldWidgets: "renderer",\n
    showFoldWidgets: "renderer",\n
    showGutter: "renderer",\n
    displayIndentGuides: "renderer",\n
    fontSize: "renderer",\n
    fontFamily: "renderer",\n
    maxLines: "renderer",\n
    minLines: "renderer",\n
    scrollPastEnd: "renderer",\n
    fixedWidthGutter: "renderer",\n
\n
    scrollSpeed: "$mouseHandler",\n
    dragDelay: "$mouseHandler",\n
    dragEnabled: "$mouseHandler",\n
    focusTimout: "$mouseHandler",\n
\n
    firstLineNumber: "session",\n
    overwrite: "session",\n
    newLineMode: "session",\n
    useWorker: "session",\n
    useSoftTabs: "session",\n
    tabSize: "session",\n
    wrap: "session",\n
    foldStyle: "session"\n
});\n
\n
exports.Editor = Editor;\n
});\n
\n
define(\'ace/lib/lang\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
exports.stringReverse = function(string) {\n
    return string.split("").reverse().join("");\n
};\n
\n
exports.stringRepeat = function (string, count) {\n
    var result = \'\';\n
    while (count > 0) {\n
        if (count & 1)\n
            result += string;\n
\n
        if (count >>= 1)\n
            string += string;\n
    }\n
    return result;\n
};\n
\n
var trimBeginRegexp = /^\\s\\s*/;\n
var trimEndRegexp = /\\s\\s*$/;\n
\n
exports.stringTrimLeft = function (string) {\n
    return string.replace(trimBeginRegexp, \'\');\n
};\n
\n
exports.stringTrimRight = function (string) {\n
    return string.replace(trimEndRegexp, \'\');\n
};\n
\n
exports.copyObject = function(obj) {\n
    var copy = {};\n
    for (var key in obj) {\n
        copy[key] = obj[key];\n
    }\n
    return copy;\n
};\n
\n
exports.copyArray = function(array){\n
    var copy = [];\n
    for (var i=0, l=array.length; i<l; i++) {\n
        if (array[i] && typeof array[i] == "object")\n
            copy[i] = this.copyObject( array[i] );\n
        else \n
            copy[i] = array[i];\n
    }\n
    return copy;\n
};\n
\n
exports.deepCopy = function (obj) {\n
    if (typeof obj != "object") {\n
        return obj;\n
    }\n
    \n
    var copy = obj.constructor();\n
    for (var key in obj) {\n
        if (typeof obj[key] == "object") {\n
            copy[key] = this.deepCopy(obj[key]);\n
        } else {\n
            copy[key] = obj[key];\n
        }\n
    }\n
    return copy;\n
};\n
\n
exports.arrayToMap = function(arr) {\n
    var map = {};\n
    for (var i=0; i<arr.length; i++) {\n
        map[arr[i]] = 1;\n
    }\n
    return map;\n
\n
};\n
\n
exports.createMap = function(props) {\n
    var map = Object.create(null);\n
    for (var i in props) {\n
        map[i] = props[i];\n
    }\n
    return map;\n
};\n
exports.arrayRemove = function(array, value) {\n
  for (var i = 0; i <= array.length; i++) {\n
    if (value === array[i]) {\n
      array.splice(i, 1);\n
    }\n
  }\n
};\n
\n
exports.escapeRegExp = function(str) {\n
    return str.replace(/([.*+?^${}()|[\\]\\/\\\\])/g, \'\\\\$1\');\n
};\n
\n
exports.escapeHTML = function(str) {\n
    return str.replace(/&/g, "&#38;").replace(/"/g, "&#34;").replace(/\'/g, "&#39;").replace(/</g, "&#60;");\n
};\n
\n
exports.getMatchOffsets = function(string, regExp) {\n
    var matches = [];\n
\n
    string.replace(regExp, function(str) {\n
        matches.push({\n
            offset: arguments[arguments.length-2],\n
            length: str.length\n
        });\n
    });\n
\n
    return matches;\n
};\n
exports.deferredCall = function(fcn) {\n
\n
    var timer = null;\n
    var callback = function() {\n
        timer = null;\n
        fcn();\n
    };\n
\n
    var deferred = function(timeout) {\n
        deferred.cancel();\n
        timer = setTimeout(callback, timeout || 0);\n
        return deferred;\n
    };\n
\n
    deferred.schedule = deferred;\n
\n
    deferred.call = function() {\n
        this.cancel();\n
        fcn();\n
        return deferred;\n
    };\n
\n
    deferred.cancel = function() {\n
        clearTimeout(timer);\n
        timer = null;\n
        return deferred;\n
    };\n
\n
    return deferred;\n
};\n
\n
\n
exports.delayedCall = function(fcn, defaultTimeout) {\n
    var timer = null;\n
    var callback = function() {\n
        timer = null;\n
        fcn();\n
    };\n
\n
    var _self = function(timeout) {\n
        timer && clearTimeout(timer);\n
        timer = setTimeout(callback, timeout || defaultTimeout);\n
    };\n
\n
    _self.delay = _self;\n
    _self.schedule = function(timeout) {\n
        if (timer == null)\n
            timer = setTimeout(callback, timeout || 0);\n
    };\n
\n
    _self.call = function() {\n
        this.cancel();\n
        fcn();\n
    };\n
\n
    _self.cancel = function() {\n
        timer && clearTimeout(timer);\n
        timer = null;\n
    };\n
\n
    _self.isPending = function() {\n
        return timer;\n
    };\n
\n
    return _self;\n
};\n
});\n
\n
define(\'ace/keyboard/textinput\', [\'require\', \'exports\', \'module\' , \'ace/lib/event\', \'ace/lib/useragent\', \'ace/lib/dom\', \'ace/lib/lang\'], function(require, exports, module) {\n
\n
\n
var event = require("../lib/event");\n
var useragent = require("../lib/useragent");\n
var dom = require("../lib/dom");\n
var lang = require("../lib/lang");\n
var BROKEN_SETDATA = useragent.isChrome < 18;\n
\n
var TextInput = function(parentNode, host) {\n
    var text = dom.createElement("textarea");\n
    text.className = "ace_text-input";\n
\n
    if (useragent.isTouchPad)\n
        text.setAttribute("x-palm-disable-auto-cap", true);\n
\n
    text.wrap = "off";\n
    text.autocorrect = "off";\n
    text.autocapitalize = "off";\n
    text.spellcheck = false;\n
\n
    text.style.opacity = "0";\n
    parentNode.insertBefore(text, parentNode.firstChild);\n
\n
    var PLACEHOLDER = "\\x01\\x01";\n
\n
    var cut = false;\n
    var copied = false;\n
    var pasted = false;\n
    var inComposition = false;\n
    var tempStyle = \'\';\n
    var isSelectionEmpty = true;\n
    try { var isFocused = document.activeElement === text; } catch(e) {}\n
    \n
    event.addListener(text, "blur", function() {\n
        host.onBlur();\n
        isFocused = false;\n
    });\n
    event.addListener(text, "focus", function() {\n
        isFocused = true;\n
        host.onFocus();\n
        resetSelection();\n
    });\n
    this.focus = function() { text.focus(); };\n
    this.blur = function() { text.blur(); };\n
    this.isFocused = function() {\n
        return isFocused;\n
    };\n
    var syncSelection = lang.delayedCall(function() {\n
        isFocused && resetSelection(isSelectionEmpty);\n
    });\n
    var syncValue = lang.delayedCall(function() {\n
         if (!inComposition) {\n
            text.value = PLACEHOLDER;\n
            isFocused && resetSelection();\n
         }\n
    });\n
\n
    function resetSelection(isEmpty) {\n
        if (inComposition)\n
            return;\n
        if (inputHandler) {\n
            selectionStart = 0;\n
            selectionEnd = isEmpty ? 0 : text.value.length - 1;\n
        } else {\n
            var selectionStart = isEmpty ? 2 : 1;\n
            var selectionEnd = 2;\n
        }\n
        try {\n
            text.setSelectionRange(selectionStart, selectionEnd);\n
        } catch(e){}\n
    }\n
\n
    function resetValue() {\n
        if (inComposition)\n
            return;\n
        text.value = PLACEHOLDER;\n
        if (useragent.isWebKit)\n
            syncValue.schedule();\n
    }\n
\n
    useragent.isWebKit || host.addEventListener(\'changeSelection\', function() {\n
        if (host.selection.isEmpty() != isSelectionEmpty) {\n
            isSelectionEmpty = !isSelectionEmpty;\n
            syncSelection.schedule();\n
        }\n
    });\n
\n
    resetValue();\n
    if (isFocused)\n
        host.onFocus();\n
\n
\n
    var isAllSelected = function(text) {\n
        return text.selectionStart === 0 && text.selectionEnd === text.value.length;\n
    };\n
    if (!text.setSelectionRange && text.createTextRange) {\n
        text.setSelectionRange = function(selectionStart, selectionEnd) {\n
            var range = this.createTextRange();\n
            range.collapse(true);\n
            range.moveStart(\'character\', selectionStart);\n
            range.moveEnd(\'character\', selectionEnd);\n
            range.select();\n
        };\n
        isAllSelected = function(text) {\n
            try {\n
                var range = text.ownerDocument.selection.createRange();\n
            }catch(e) {}\n
            if (!range || range.parentElement() != text) return false;\n
                return range.text == text.value;\n
        }\n
    }\n
    if (useragent.isOldIE) {\n
        var inPropertyChange = false;\n
        var onPropertyChange = function(e){\n
            if (inPropertyChange)\n
                return;\n
            var data = text.value;\n
            if (inComposition || !data || data == PLACEHOLDER)\n
                return;\n
            if (e && data == PLACEHOLDER[0])\n
                return syncProperty.schedule();\n
\n
            sendText(data);\n
            inPropertyChange = true;\n
            resetValue();\n
            inPropertyChange = false;\n
        };\n
        var syncProperty = lang.delayedCall(onPropertyChange);\n
        event.addListener(text, "propertychange", onPropertyChange);\n
\n
        var keytable = { 13:1, 27:1 };\n
        event.addListener(text, "keyup", function (e) {\n
            if (inComposition && (!text.value || keytable[e.keyCode]))\n
                setTimeout(onCompositionEnd, 0);\n
            if ((text.value.charCodeAt(0)||0) < 129) {\n
                return syncProperty.call();\n
            }\n
            inComposition ? onCompositionUpdate() : onCompositionStart();\n
        });\n
        event.addListener(text, "keydown", function (e) {\n
            syncProperty.schedule(50);\n
        });\n
    }\n
\n
    var onSelect = function(e) {\n
        if (cut) {\n
            cut = false;\n
        } else if (copied) {\n
            copied = false;\n
        } else if (isAllSelected(text)) {\n
            host.selectAll();\n
            resetSelection();\n
        } else if (inputHandler) {\n
            resetSelection(host.selection.isEmpty());\n
        }\n
    };\n
\n
    var inputHandler = null;\n
    this.setInputHandler = function(cb) {inputHandler = cb};\n
    this.getInputHandler = function() {return inputHandler};\n
    var afterContextMenu = false;\n
    \n
    var sendText = function(data) {\n
        if (inputHandler) {\n
            data = inputHandler(data);\n
            inputHandler = null;\n
        }\n
        if (pasted) {\n
            resetSelection();\n
            if (data)\n
                host.onPaste(data);\n
            pasted = false;\n
        } else if (data == PLACEHOLDER.charAt(0)) {\n
            if (afterContextMenu)\n
                host.execCommand("del", {source: "ace"});\n
        } else {\n
            if (data.substring(0, 2) == PLACEHOLDER)\n
                data = data.substr(2);\n
            else if (data.charAt(0) == PLACEHOLDER.charAt(0))\n
                data = data.substr(1);\n
            else if (data.charAt(data.length - 1) == PLACEHOLDER.charAt(0))\n
                data = data.slice(0, -1);\n
            if (data.charAt(data.length - 1) == PLACEHOLDER.charAt(0))\n
                data = data.slice(0, -1);\n
            \n
            if (data)\n
                host.onTextInput(data);\n
        }\n
        if (afterContextMenu)\n
            afterContextMenu = false;\n
    };\n
    var onInput = function(e) {\n
        if (inComposition)\n
            return;\n
        var data = text.value;\n
        sendText(data);\n
        resetValue();\n
    };\n
\n
    var onCut = function(e) {\n
        var data = host.getCopyText();\n
        if (!data) {\n
            event.preventDefault(e);\n
            return;\n
        }\n
\n
        var clipboardData = e.clipboardData || window.clipboardData;\n
\n
        if (clipboardData && !BROKEN_SETDATA) {\n
            var supported = clipboardData.setData("Text", data);\n
            if (supported) {\n
                host.onCut();\n
                event.preventDefault(e);\n
            }\n
        }\n
\n
        if (!supported) {\n
            cut = true;\n
            text.value = data;\n
            text.select();\n
            setTimeout(function(){\n
                cut = false;\n
                resetValue();\n
                resetSelection();\n
                host.onCut();\n
            });\n
        }\n
    };\n
\n
    var onCopy = function(e) {\n
        var data = host.getCopyText();\n
        if (!data) {\n
            event.preventDefault(e);\n
            return;\n
        }\n
\n
        var clipboardData = e.clipboardData || window.clipboardData;\n
        if (clipboardData && !BROKEN_SETDATA) {\n
            var supported = clipboardData.setData("Text", data);\n
            if (supported) {\n
                host.onCopy();\n
                event.preventDefault(e);\n
            }\n
        }\n
        if (!supported) {\n
            copied = true;\n
            text.value = data;\n
            text.select();\n
            setTimeout(function(){\n
                copied = false;\n
                resetValue();\n
                resetSelection();\n
                host.onCopy();\n
            });\n
        }\n
    };\n
\n
    var onPaste = function(e) {\n
        var clipboardData = e.clipboardData || window.clipboardData;\n
\n
        if (clipboardData) {\n
            var data = clipboardData.getData("Text");\n
            if (data)\n
                host.onPaste(data);\n
            if (useragent.isIE)\n
                setTimeout(resetSelection);\n
            event.preventDefault(e);\n
        }\n
        else {\n
            text.value = "";\n
            pasted = true;\n
        }\n
    };\n
\n
    event.addCommandKeyListener(text, host.onCommandKey.bind(host));\n
\n
    event.addListener(text, "select", onSelect);\n
\n
    event.addListener(text, "input", onInput);\n
\n
    event.addListener(text, "cut", onCut);\n
    event.addListener(text, "copy", onCopy);\n
    event.addListener(text, "paste", onPaste);\n
    if (!(\'oncut\' in text) || !(\'oncopy\' in text) || !(\'onpaste\' in text)){\n
        event.addListener(parentNode, "keydown", function(e) {\n
            if ((useragent.isMac && !e.metaKey) || !e.ctrlKey)\n
            return;\n
\n
            switch (e.keyCode) {\n
                case 67:\n
                    onCopy(e);\n
                    break;\n
                case 86:\n
                    onPaste(e);\n
                    break;\n
                case 88:\n
                    onCut(e);\n
                    break;\n
            }\n
        });\n
    }\n
    var onCompositionStart = function(e) {\n
        if (inComposition) return;\n
        inComposition = {};\n
        host.onCompositionStart();\n
        setTimeout(onCompositionUpdate, 0);\n
        host.on("mousedown", onCompositionEnd);\n
        if (!host.selection.isEmpty()) {\n
            host.insert("");\n
            host.session.markUndoGroup();\n
            host.selection.clearSelection();\n
        }\n
        host.session.markUndoGroup();\n
    };\n
\n
    var onCompositionUpdate = function() {\n
        if (!inComposition) return;\n
        var val = text.value.replace(/\\x01/g, "");\n
        if (inComposition.lastValue === val) return;\n
        \n
        host.onCompositionUpdate(val);\n
        if (inComposition.lastValue)\n
            host.undo();\n
        inComposition.lastValue = val;\n
        if (inComposi

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

tion.lastValue) {\n
            var r = host.selection.getRange();\n
            host.insert(inComposition.lastValue);\n
            host.session.markUndoGroup();\n
            inComposition.range = host.selection.getRange();\n
            host.selection.setRange(r);\n
            host.selection.clearSelection();\n
        }\n
    };\n
\n
    var onCompositionEnd = function(e) {\n
        var c = inComposition;\n
        inComposition = false;\n
        var timer = setTimeout(function() {\n
            timer = null;\n
            var str = text.value.replace(/\\x01/g, "");\n
            if (inComposition)\n
                return\n
            else if (str == c.lastValue)\n
                resetValue();\n
            else if (!c.lastValue && str) {\n
                resetValue();\n
                sendText(str);\n
            }\n
        });\n
        inputHandler = function compositionInputHandler(str) {\n
            if (timer)\n
                clearTimeout(timer);\n
            str = str.replace(/\\x01/g, "");\n
            if (str == c.lastValue)\n
                return "";\n
            if (c.lastValue && timer)\n
                host.undo();\n
            return str;\n
        };\n
        host.onCompositionEnd();\n
        host.removeListener("mousedown", onCompositionEnd);\n
        if (e.type == "compositionend" && c.range) {\n
            host.selection.setRange(c.range);\n
        }\n
    };\n
    \n
    \n
\n
    var syncComposition = lang.delayedCall(onCompositionUpdate, 50);\n
\n
    event.addListener(text, "compositionstart", onCompositionStart);\n
    if (useragent.isGecko) {\n
        event.addListener(text, "text", function(){syncComposition.schedule()});\n
    } else {\n
        event.addListener(text, "keyup", function(){syncComposition.schedule()});\n
        event.addListener(text, "keydown", function(){syncComposition.schedule()});\n
    }\n
    event.addListener(text, "compositionend", onCompositionEnd);\n
\n
    this.getElement = function() {\n
        return text;\n
    };\n
\n
    this.setReadOnly = function(readOnly) {\n
       text.readOnly = readOnly;\n
    };\n
\n
    this.onContextMenu = function(e) {\n
        afterContextMenu = true;\n
        if (!tempStyle)\n
            tempStyle = text.style.cssText;\n
\n
        text.style.cssText = "z-index:100000;" + (useragent.isIE ? "opacity:0.1;" : "");\n
\n
        resetSelection(host.selection.isEmpty());\n
        host._emit("nativecontextmenu", {target: host, domEvent: e});\n
        var rect = host.container.getBoundingClientRect();\n
        var style = dom.computedStyle(host.container);\n
        var top = rect.top + (parseInt(style.borderTopWidth) || 0);\n
        var left = rect.left + (parseInt(rect.borderLeftWidth) || 0);\n
        var maxTop = rect.bottom - top - text.clientHeight;\n
        var move = function(e) {\n
            text.style.left = e.clientX - left - 2 + "px";\n
            text.style.top = Math.min(e.clientY - top - 2, maxTop) + "px";\n
        }; \n
        move(e);\n
\n
        if (e.type != "mousedown")\n
            return;\n
\n
        if (host.renderer.$keepTextAreaAtCursor)\n
            host.renderer.$keepTextAreaAtCursor = null;\n
        if (useragent.isWin)\n
            event.capture(host.container, move, onContextMenuClose);\n
    };\n
\n
    this.onContextMenuClose = onContextMenuClose;\n
    function onContextMenuClose() {\n
        setTimeout(function () {\n
            if (tempStyle) {\n
                text.style.cssText = tempStyle;\n
                tempStyle = \'\';\n
            }\n
            if (host.renderer.$keepTextAreaAtCursor == null) {\n
                host.renderer.$keepTextAreaAtCursor = true;\n
                host.renderer.$moveTextAreaToCursor();\n
            }\n
        }, 0);\n
    }\n
    if (!useragent.isGecko || useragent.isMac) {\n
        var onContextMenu = function(e) {\n
            host.textInput.onContextMenu(e);\n
            onContextMenuClose();\n
        };\n
        event.addListener(host.renderer.scroller, "contextmenu", onContextMenu);\n
        event.addListener(text, "contextmenu", onContextMenu);\n
    }\n
};\n
\n
exports.TextInput = TextInput;\n
});\n
\n
define(\'ace/mouse/mouse_handler\', [\'require\', \'exports\', \'module\' , \'ace/lib/event\', \'ace/lib/useragent\', \'ace/mouse/default_handlers\', \'ace/mouse/default_gutter_handler\', \'ace/mouse/mouse_event\', \'ace/mouse/dragdrop_handler\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
var event = require("../lib/event");\n
var useragent = require("../lib/useragent");\n
var DefaultHandlers = require("./default_handlers").DefaultHandlers;\n
var DefaultGutterHandler = require("./default_gutter_handler").GutterHandler;\n
var MouseEvent = require("./mouse_event").MouseEvent;\n
var DragdropHandler = require("./dragdrop_handler").DragdropHandler;\n
var config = require("../config");\n
\n
var MouseHandler = function(editor) {\n
    this.editor = editor;\n
\n
    new DefaultHandlers(this);\n
    new DefaultGutterHandler(this);\n
    new DragdropHandler(this);\n
\n
    var mouseTarget = editor.renderer.getMouseEventTarget();\n
    event.addListener(mouseTarget, "click", this.onMouseEvent.bind(this, "click"));\n
    event.addListener(mouseTarget, "mousemove", this.onMouseMove.bind(this, "mousemove"));\n
    event.addMultiMouseDownListener(mouseTarget, [300, 300, 250], this, "onMouseEvent");\n
    if (editor.renderer.scrollBarV) {\n
        event.addMultiMouseDownListener(editor.renderer.scrollBarV.inner, [300, 300, 250], this, "onMouseEvent");\n
        event.addMultiMouseDownListener(editor.renderer.scrollBarH.inner, [300, 300, 250], this, "onMouseEvent");\n
    }\n
    event.addMouseWheelListener(editor.container, this.onMouseWheel.bind(this, "mousewheel"));\n
\n
    var gutterEl = editor.renderer.$gutter;\n
    event.addListener(gutterEl, "mousedown", this.onMouseEvent.bind(this, "guttermousedown"));\n
    event.addListener(gutterEl, "click", this.onMouseEvent.bind(this, "gutterclick"));\n
    event.addListener(gutterEl, "dblclick", this.onMouseEvent.bind(this, "gutterdblclick"));\n
    event.addListener(gutterEl, "mousemove", this.onMouseEvent.bind(this, "guttermousemove"));\n
\n
    event.addListener(mouseTarget, "mousedown", function(e) {\n
        editor.focus();\n
    });\n
\n
    event.addListener(gutterEl, "mousedown", function(e) {\n
        editor.focus();\n
        return event.preventDefault(e);\n
    });\n
};\n
\n
(function() {\n
    this.onMouseEvent = function(name, e) {\n
        this.editor._emit(name, new MouseEvent(e, this.editor));\n
    };\n
\n
    this.onMouseMove = function(name, e) {\n
        var listeners = this.editor._eventRegistry && this.editor._eventRegistry.mousemove;\n
        if (!listeners || !listeners.length)\n
            return;\n
\n
        this.editor._emit(name, new MouseEvent(e, this.editor));\n
    };\n
\n
    this.onMouseWheel = function(name, e) {\n
        var mouseEvent = new MouseEvent(e, this.editor);\n
        mouseEvent.speed = this.$scrollSpeed * 2;\n
        mouseEvent.wheelX = e.wheelX;\n
        mouseEvent.wheelY = e.wheelY;\n
\n
        this.editor._emit(name, mouseEvent);\n
    };\n
\n
    this.setState = function(state) {\n
        this.state = state;\n
    };\n
\n
    this.captureMouse = function(ev, mouseMoveHandler) {\n
        this.x = ev.x;\n
        this.y = ev.y;\n
\n
        this.isMousePressed = true;\n
        var renderer = this.editor.renderer;\n
        if (renderer.$keepTextAreaAtCursor)\n
            renderer.$keepTextAreaAtCursor = null;\n
\n
        var self = this;\n
        var onMouseMove = function(e) {\n
            self.x = e.clientX;\n
            self.y = e.clientY;\n
            mouseMoveHandler && mouseMoveHandler(e);\n
        };\n
\n
        var onCaptureEnd = function(e) {\n
            clearInterval(timerId);\n
            onCaptureInterval();\n
            self[self.state + "End"] && self[self.state + "End"](e);\n
            self.$clickSelection = null;\n
            if (renderer.$keepTextAreaAtCursor == null) {\n
                renderer.$keepTextAreaAtCursor = true;\n
                renderer.$moveTextAreaToCursor();\n
            }\n
            self.isMousePressed = false;\n
            self.onMouseEvent("mouseup", e);\n
        };\n
\n
        var onCaptureInterval = function() {\n
            self[self.state] && self[self.state]();\n
        };\n
\n
        if (useragent.isOldIE && ev.domEvent.type == "dblclick") {\n
            return setTimeout(function() {onCaptureEnd(ev);});\n
        }\n
\n
        event.capture(this.editor.container, onMouseMove, onCaptureEnd);\n
        var timerId = setInterval(onCaptureInterval, 20);\n
    };\n
}).call(MouseHandler.prototype);\n
\n
config.defineOptions(MouseHandler.prototype, "mouseHandler", {\n
    scrollSpeed: {initialValue: 2},\n
    dragDelay: {initialValue: 150},\n
    dragEnabled: {initialValue: true},\n
    focusTimout: {initialValue: 0}\n
});\n
\n
\n
exports.MouseHandler = MouseHandler;\n
});\n
\n
define(\'ace/mouse/default_handlers\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/lib/event\', \'ace/lib/useragent\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
var event = require("../lib/event");\n
var useragent = require("../lib/useragent");\n
\n
var DRAG_OFFSET = 0; // pixels\n
\n
function DefaultHandlers(mouseHandler) {\n
    mouseHandler.$clickSelection = null;\n
\n
    var editor = mouseHandler.editor;\n
    editor.setDefaultHandler("mousedown", this.onMouseDown.bind(mouseHandler));\n
    editor.setDefaultHandler("dblclick", this.onDoubleClick.bind(mouseHandler));\n
    editor.setDefaultHandler("tripleclick", this.onTripleClick.bind(mouseHandler));\n
    editor.setDefaultHandler("quadclick", this.onQuadClick.bind(mouseHandler));\n
    editor.setDefaultHandler("mousewheel", this.onMouseWheel.bind(mouseHandler));\n
\n
    var exports = ["select", "startSelect", "selectEnd", "selectAllEnd", "selectByWordsEnd",\n
        "selectByLinesEnd", "dragWait", "dragWaitEnd", "focusWait"];\n
\n
    exports.forEach(function(x) {\n
        mouseHandler[x] = this[x];\n
    }, this);\n
\n
    mouseHandler.selectByLines = this.extendSelectionBy.bind(mouseHandler, "getLineRange");\n
    mouseHandler.selectByWords = this.extendSelectionBy.bind(mouseHandler, "getWordRange");\n
}\n
\n
(function() {\n
\n
    this.onMouseDown = function(ev) {\n
        var inSelection = ev.inSelection();\n
        var pos = ev.getDocumentPosition();\n
        this.mousedownEvent = ev;\n
        var editor = this.editor;\n
\n
        var button = ev.getButton();\n
        if (button !== 0) {\n
            var selectionRange = editor.getSelectionRange();\n
            var selectionEmpty = selectionRange.isEmpty();\n
\n
            if (selectionEmpty) {\n
                editor.moveCursorToPosition(pos);\n
                editor.selection.clearSelection();\n
            }\n
            editor.textInput.onContextMenu(ev.domEvent);\n
            return; // stopping event here breaks contextmenu on ff mac\n
        }\n
        if (inSelection && !editor.isFocused()) {\n
            editor.focus();\n
            if (this.$focusTimout && !this.$clickSelection && !editor.inMultiSelectMode) {\n
                this.mousedownEvent.time = (new Date()).getTime();\n
                this.setState("focusWait");\n
                this.captureMouse(ev);\n
                return;\n
            }\n
        }\n
\n
        if (!inSelection || this.$clickSelection || ev.getShiftKey() || editor.inMultiSelectMode) {\n
            this.startSelect(pos);\n
        } else if (inSelection) {\n
            this.mousedownEvent.time = (new Date()).getTime();\n
            this.startSelect(pos);\n
        }\n
        this.captureMouse(ev);\n
        return ev.preventDefault();\n
    };\n
\n
    this.startSelect = function(pos) {\n
        pos = pos || this.editor.renderer.screenToTextCoordinates(this.x, this.y);\n
        var editor = this.editor;\n
        setTimeout(function(){\n
            if (this.mousedownEvent.getShiftKey()) {\n
                editor.selection.selectToPosition(pos);\n
            }\n
            else if (!this.$clickSelection) {\n
                editor.moveCursorToPosition(pos);\n
                editor.selection.clearSelection();\n
            }\n
        }.bind(this), 0);\n
        if (editor.renderer.scroller.setCapture) {\n
            editor.renderer.scroller.setCapture();\n
        }\n
        editor.setStyle("ace_selecting");\n
        this.setState("select");\n
    };\n
\n
    this.select = function() {\n
        var anchor, editor = this.editor;\n
        var cursor = editor.renderer.screenToTextCoordinates(this.x, this.y);\n
\n
        if (this.$clickSelection) {\n
            var cmp = this.$clickSelection.comparePoint(cursor);\n
\n
            if (cmp == -1) {\n
                anchor = this.$clickSelection.end;\n
            } else if (cmp == 1) {\n
                anchor = this.$clickSelection.start;\n
            } else {\n
                var orientedRange = calcRangeOrientation(this.$clickSelection, cursor);\n
                cursor = orientedRange.cursor;\n
                anchor = orientedRange.anchor;\n
            }\n
            editor.selection.setSelectionAnchor(anchor.row, anchor.column);\n
        }\n
        editor.selection.selectToPosition(cursor);\n
\n
        editor.renderer.scrollCursorIntoView();\n
    };\n
\n
    this.extendSelectionBy = function(unitName) {\n
        var anchor, editor = this.editor;\n
        var cursor = editor.renderer.screenToTextCoordinates(this.x, this.y);\n
        var range = editor.selection[unitName](cursor.row, cursor.column);\n
\n
        if (this.$clickSelection) {\n
            var cmpStart = this.$clickSelection.comparePoint(range.start);\n
            var cmpEnd = this.$clickSelection.comparePoint(range.end);\n
\n
            if (cmpStart == -1 && cmpEnd <= 0) {\n
                anchor = this.$clickSelection.end;\n
                if (range.end.row != cursor.row || range.end.column != cursor.column)\n
                    cursor = range.start;\n
            } else if (cmpEnd == 1 && cmpStart >= 0) {\n
                anchor = this.$clickSelection.start;\n
                if (range.start.row != cursor.row || range.start.column != cursor.column)\n
                    cursor = range.end;\n
            } else if (cmpStart == -1 && cmpEnd == 1) {\n
                cursor = range.end;\n
                anchor = range.start;\n
            } else {\n
                var orientedRange = calcRangeOrientation(this.$clickSelection, cursor);\n
                cursor = orientedRange.cursor;\n
                anchor = orientedRange.anchor;\n
            }\n
            editor.selection.setSelectionAnchor(anchor.row, anchor.column);\n
        }\n
        editor.selection.selectToPosition(cursor);\n
\n
        editor.renderer.scrollCursorIntoView();\n
    };\n
\n
    this.selectEnd =\n
    this.selectAllEnd =\n
    this.selectByWordsEnd =\n
    this.selectByLinesEnd = function() {\n
        this.editor.unsetStyle("ace_selecting");\n
        if (this.editor.renderer.scroller.releaseCapture) {\n
            this.editor.renderer.scroller.releaseCapture();\n
        }\n
    };\n
\n
    this.focusWait = function() {\n
        var distance = calcDistance(this.mousedownEvent.x, this.mousedownEvent.y, this.x, this.y);\n
        var time = (new Date()).getTime();\n
\n
        if (distance > DRAG_OFFSET || time - this.mousedownEvent.time > this.$focusTimout)\n
            this.startSelect(this.mousedownEvent.getDocumentPosition());\n
    };\n
\n
    this.onDoubleClick = function(ev) {\n
        var pos = ev.getDocumentPosition();\n
        var editor = this.editor;\n
        var session = editor.session;\n
\n
        var range = session.getBracketRange(pos);\n
        if (range) {\n
            if (range.isEmpty()) {\n
                range.start.column--;\n
                range.end.column++;\n
            }\n
            this.$clickSelection = range;\n
            this.setState("select");\n
            return;\n
        }\n
\n
        this.$clickSelection = editor.selection.getWordRange(pos.row, pos.column);\n
        this.setState("selectByWords");\n
    };\n
\n
    this.onTripleClick = function(ev) {\n
        var pos = ev.getDocumentPosition();\n
        var editor = this.editor;\n
\n
        this.setState("selectByLines");\n
        this.$clickSelection = editor.selection.getLineRange(pos.row);\n
    };\n
\n
    this.onQuadClick = function(ev) {\n
        var editor = this.editor;\n
\n
        editor.selectAll();\n
        this.$clickSelection = editor.getSelectionRange();\n
        this.setState("selectAll");\n
    };\n
\n
    this.onMouseWheel = function(ev) {\n
        if (ev.getShiftKey() || ev.getAccelKey())\n
            return;\n
        var t = ev.domEvent.timeStamp;\n
        var dt = t - (this.$lastScrollTime||0);\n
        \n
        var editor = this.editor;\n
        var isScrolable = editor.renderer.isScrollableBy(ev.wheelX * ev.speed, ev.wheelY * ev.speed);\n
        if (isScrolable || dt < 200) {\n
            this.$lastScrollTime = t;\n
            editor.renderer.scrollBy(ev.wheelX * ev.speed, ev.wheelY * ev.speed);\n
            return ev.stop();\n
        }\n
    };\n
\n
}).call(DefaultHandlers.prototype);\n
\n
exports.DefaultHandlers = DefaultHandlers;\n
\n
function calcDistance(ax, ay, bx, by) {\n
    return Math.sqrt(Math.pow(bx - ax, 2) + Math.pow(by - ay, 2));\n
}\n
\n
function calcRangeOrientation(range, cursor) {\n
    if (range.start.row == range.end.row)\n
        var cmp = 2 * cursor.column - range.start.column - range.end.column;\n
    else if (range.start.row == range.end.row - 1 && !range.start.column && !range.end.column)\n
        var cmp = cursor.column - 4;\n
    else\n
        var cmp = 2 * cursor.row - range.start.row - range.end.row;\n
\n
    if (cmp < 0)\n
        return {cursor: range.start, anchor: range.end};\n
    else\n
        return {cursor: range.end, anchor: range.start};\n
}\n
\n
});\n
\n
define(\'ace/mouse/default_gutter_handler\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/lib/event\'], function(require, exports, module) {\n
\n
var dom = require("../lib/dom");\n
var event = require("../lib/event");\n
\n
function GutterHandler(mouseHandler) {\n
    var editor = mouseHandler.editor;\n
    var gutter = editor.renderer.$gutterLayer;\n
\n
    mouseHandler.editor.setDefaultHandler("guttermousedown", function(e) {\n
        if (!editor.isFocused() || e.getButton() != 0)\n
            return;\n
        var gutterRegion = gutter.getRegion(e);\n
\n
        if (gutterRegion == "foldWidgets")\n
            return;\n
\n
        var row = e.getDocumentPosition().row;\n
        var selection = editor.session.selection;\n
\n
        if (e.getShiftKey())\n
            selection.selectTo(row, 0);\n
        else {\n
            if (e.domEvent.detail == 2) {\n
                editor.selectAll();\n
                return e.preventDefault();\n
            }\n
            mouseHandler.$clickSelection = editor.selection.getLineRange(row);\n
        }\n
        mouseHandler.setState("selectByLines");\n
        mouseHandler.captureMouse(e);\n
        return e.preventDefault();\n
    });\n
\n
\n
    var tooltipTimeout, mouseEvent, tooltip, tooltipAnnotation;\n
    function createTooltip() {\n
        tooltip = dom.createElement("div");\n
        tooltip.className = "ace_gutter-tooltip";\n
        tooltip.style.display = "none";\n
        editor.container.appendChild(tooltip);\n
    }\n
\n
    function showTooltip() {\n
        if (!tooltip) {\n
            createTooltip();\n
        }\n
        var row = mouseEvent.getDocumentPosition().row;\n
        var annotation = gutter.$annotations[row];\n
        if (!annotation)\n
            return hideTooltip();\n
\n
        var maxRow = editor.session.getLength();\n
        if (row == maxRow) {\n
            var screenRow = editor.renderer.pixelToScreenCoordinates(0, mouseEvent.y).row;\n
            var pos = mouseEvent.$pos;\n
            if (screenRow > editor.session.documentToScreenRow(pos.row, pos.column))\n
                return hideTooltip();\n
        }\n
\n
        if (tooltipAnnotation == annotation)\n
            return;\n
        tooltipAnnotation = annotation.text.join("<br/>");\n
\n
        tooltip.style.display = "block";\n
        tooltip.innerHTML = tooltipAnnotation;\n
        editor.on("mousewheel", hideTooltip);\n
\n
        moveTooltip(mouseEvent);\n
    }\n
\n
    function hideTooltip() {\n
        if (tooltipTimeout)\n
            tooltipTimeout = clearTimeout(tooltipTimeout);\n
        if (tooltipAnnotation) {\n
            tooltip.style.display = "none";\n
            tooltipAnnotation = null;\n
            editor.removeEventListener("mousewheel", hideTooltip);\n
        }\n
    }\n
\n
    function moveTooltip(e) {\n
        var rect = editor.renderer.$gutter.getBoundingClientRect();\n
        tooltip.style.left = e.x + 15 + "px";\n
        if (e.y + 3 * editor.renderer.lineHeight + 15 < rect.bottom) {\n
            tooltip.style.bottom = "";\n
            tooltip.style.top =  e.y + 15 + "px";\n
        } else {\n
            tooltip.style.top = "";\n
            var innerHeight = window.innerHeight || document.documentElement.clientHeight;\n
            tooltip.style.bottom = innerHeight - e.y + 5 + "px";\n
        }\n
    }\n
\n
    mouseHandler.editor.setDefaultHandler("guttermousemove", function(e) {\n
        var target = e.domEvent.target || e.domEvent.srcElement;\n
        if (dom.hasCssClass(target, "ace_fold-widget"))\n
            return hideTooltip();\n
\n
        if (tooltipAnnotation)\n
            moveTooltip(e);\n
\n
        mouseEvent = e;\n
        if (tooltipTimeout)\n
            return;\n
        tooltipTimeout = setTimeout(function() {\n
            tooltipTimeout = null;\n
            if (mouseEvent && !mouseHandler.isMousePressed)\n
                showTooltip();\n
            else\n
                hideTooltip();\n
        }, 50);\n
    });\n
\n
    event.addListener(editor.renderer.$gutter, "mouseout", function(e) {\n
        mouseEvent = null;\n
        if (!tooltipAnnotation || tooltipTimeout)\n
            return;\n
\n
        tooltipTimeout = setTimeout(function() {\n
            tooltipTimeout = null;\n
            hideTooltip();\n
        }, 50);\n
    });\n
    \n
    editor.on("changeSession", hideTooltip);\n
}\n
\n
exports.GutterHandler = GutterHandler;\n
\n
});\n
\n
define(\'ace/mouse/mouse_event\', [\'require\', \'exports\', \'module\' , \'ace/lib/event\', \'ace/lib/useragent\'], function(require, exports, module) {\n
\n
\n
var event = require("../lib/event");\n
var useragent = require("../lib/useragent");\n
var MouseEvent = exports.MouseEvent = function(domEvent, editor) {\n
    this.domEvent = domEvent;\n
    this.editor = editor;\n
    \n
    this.x = this.clientX = domEvent.clientX;\n
    this.y = this.clientY = domEvent.clientY;\n
\n
    this.$pos = null;\n
    this.$inSelection = null;\n
    \n
    this.propagationStopped = false;\n
    this.defaultPrevented = false;\n
};\n
\n
(function() {  \n
    \n
    this.stopPropagation = function() {\n
        event.stopPropagation(this.domEvent);\n
        this.propagationStopped = true;\n
    };\n
    \n
    this.preventDefault = function() {\n
        event.preventDefault(this.domEvent);\n
        this.defaultPrevented = true;\n
    };\n
    \n
    this.stop = function() {\n
        this.stopPropagation();\n
        this.preventDefault();\n
    };\n
    this.getDocumentPosition = function() {\n
        if (this.$pos)\n
            return this.$pos;\n
        \n
        this.$pos = this.editor.renderer.screenToTextCoordinates(this.clientX, this.clientY);\n
        return this.$pos;\n
    };\n
    this.inSelection = function() {\n
        if (this.$inSelection !== null)\n
            return this.$inSelection;\n
            \n
        var editor = this.editor;\n
        \n
\n
        var selectionRange = editor.getSelectionRange();\n
        if (selectionRange.isEmpty())\n
            this.$inSelection = false;\n
        else {\n
            var pos = this.getDocumentPosition();\n
            this.$inSelection = selectionRange.contains(pos.row, pos.column);\n
        }\n
\n
        return this.$inSelection;\n
    };\n
    this.getButton = function() {\n
        return event.getButton(this.domEvent);\n
    };\n
    this.getShiftKey = function() {\n
        return this.domEvent.shiftKey;\n
    };\n
    \n
    this.getAccelKey = useragent.isMac\n
        ? function() { return this.domEvent.metaKey; }\n
        : function() { return this.domEvent.ctrlKey; };\n
    \n
}).call(MouseEvent.prototype);\n
\n
});\n
\n
define(\'ace/mouse/dragdrop_handler\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/lib/event\', \'ace/lib/useragent\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
var event = require("../lib/event");\n
var useragent = require("../lib/useragent");\n
\n
var AUTOSCROLL_DELAY = 200;\n
var SCROLL_CURSOR_DELAY = 200;\n
var SCROLL_CURSOR_HYSTERESIS = 5;\n
\n
function DragdropHandler(mouseHandler) {\n
\n
    var editor = mouseHandler.editor;\n
\n
    var blankImage = dom.createElement("img");\n
    blankImage.src = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";\n
    if (useragent.isOpera)\n
        blankImage.style.cssText = "width:1px;height:1px;position:fixed;top:0;left:0;z-index:2147483647;opacity:0;";\n
\n
    var exports = ["dragWait", "dragWaitEnd", "startDrag", "dragReadyEnd", "onMouseDrag"];\n
\n
     exports.forEach(function(x) {\n
         mouseHandler[x] = this[x];\n
    }, this);\n
    editor.addEventListener("mousedown", this.onMouseDown.bind(mouseHandler));\n
\n
\n
    var mouseTarget = editor.container;\n
    var dragSelectionMarker, x, y;\n
    var timerId, range;\n
    var dragCursor, counter = 0;\n
    var dragOperation;\n
    var isInternal;\n
    var autoScrollStartTime;\n
    var cursorMovedTime;\n
    var cursorPointOnCaretMoved;\n
\n
    this.onDragStart = function(e) {\n
        if (this.cancelDrag || !mouseTarget.draggable) {\n
            var self = this;\n
            setTimeout(function(){\n
                self.startSelect();\n
                self.captureMouse(e);\n
            }, 0);\n
            return e.preventDefault();\n
        }\n
        range = editor.getSelectionRange();\n
\n
        var dataTransfer = e.dataTransfer;\n
        dataTransfer.effectAllowed = editor.getReadOnly() ? "copy" : "copyMove";\n
        if (useragent.isOpera) {\n
            editor.container.appendChild(blankImage);\n
            blankImage._top = blankImage.offsetTop;\n
        }\n
        dataTransfer.setDragImage && dataTransfer.setDragImage(blankImage, 0, 0);\n
        if (useragent.isOpera) {\n
            editor.container.removeChild(blankImage);\n
        }\n
        dataTransfer.clearData();\n
        dataTransfer.setData("Text", editor.session.getTextRange());\n
\n
        isInternal = true;\n
        this.setState("drag");\n
    };\n
\n
    this.onDragEnd = function(e) {\n
        mouseTarget.draggable = false;\n
        isInternal = false;\n
        this.setState(null);\n
        if (!editor.getReadOnly()) {\n
            var dropEffect = e.dataTransfer.dropEffect;\n
            if (!dragOperation && dropEffect == "move")\n
                editor.session.remove(editor.getSelectionRange());\n
            editor.renderer.$cursorLayer.setBlinking(true);\n
        }\n
        this.editor.unsetStyle("ace_dragging");\n
    };\n
\n
    this.onDragEnter = function(e) {\n
        if (editor.getReadOnly() || !canAccept(e.dataTransfer))\n
            return;\n
        if (!dragSelectionMarker)\n
            addDragMarker();\n
        counter++;\n
        e.dataTransfer.dropEffect = dragOperation = getDropEffect(e);\n
        return event.preventDefault(e);\n
    };\n
\n
    this.onDragOver = function(e) {\n
        if (editor.getReadOnly() || !canAccept(e.dataTransfer))\n
            return;\n
        if (!dragSelectionMarker) {\n
            addDragMarker();\n
            counter++;\n
        }\n
        if (onMouseMoveTimer !== null)\n
            onMouseMoveTimer = null;\n
        x = e.clientX;\n
        y = e.clientY;\n
\n
        e.dataTransfer.dropEffect = dragOperation = getDropEffect(e);\n
        return event.preventDefault(e);\n
    };\n
\n
    this.onDragLeave = function(e) {\n
        counter--;\n
        if (counter <= 0 && dragSelectionMarker) {\n
            clearDragMarker();\n
            dragOperation = null;\n
            return event.preventDefault(e);\n
        }\n
    };\n
\n
    this.onDrop = function(e) {\n
        if (!dragSelectionMarker)\n
            return;\n
        var dataTransfer = e.dataTransfer;\n
        if (isInternal) {\n
            switch (dragOperation) {\n
                case "move":\n
                    if (range.contains(dragCursor.row, dragCursor.column)) {\n
                        range = {\n
                            start: dragCursor,\n
                            end: dragCursor\n
                        };\n
                    } else {\n
                        range = editor.moveText(range, dragCursor);\n
                    }\n
                    break;\n
                case "copy":\n
                    range = editor.moveText(range, dragCursor, true);\n
                    break;\n
            }\n
        } else {\n
            var dropData = dataTransfer.getData(\'Text\');\n
            range = {\n
                start: dragCursor,\n
                end: editor.session.insert(dragCursor, dropData)\n
            };\n
            editor.focus();\n
            dragOperation = null;\n
        }\n
        clearDragMarker();\n
        return event.preventDefault(e);\n
    };\n
\n
    event.addListener(mouseTarget, "dragstart", this.onDragStart.bind(mouseHandler));\n
    event.addListener(mouseTarget, "dragend", this.onDragEnd.bind(mouseHandler));\n
    event.addListener(mouseTarget, "dragenter", this.onDragEnter.bind(mouseHandler));\n
    event.addListener(mouseTarget, "dragover", this.onDragOver.bind(mouseHandler));\n
    event.addListener(mouseTarget, "dragleave", this.onDragLeave.bind(mouseHandler));\n
    event.addListener(mouseTarget, "drop", this.onDrop.bind(mouseHandler));\n
\n
    function scrollCursorIntoView(cursor, prevCursor) {\n
        var now = new Date().getTime();\n
        var vMovement = !prevCursor || cursor.row != prevCursor.row;\n
        var hMovement = !prevCursor || cursor.column != prevCursor.column;\n
        if (!cursorMovedTime || vMovement || hMovement) {\n
            editor.$blockScrolling += 1;\n
            editor.moveCursorToPosition(cursor);\n
            editor.$blockScrolling -= 1;\n
            cursorMovedTime = now;\n
            cursorPointOnCaretMoved = {x: x, y: y};\n
        } else {\n
            var distance = calcDistance(cursorPointOnCaretMoved.x, cursorPointOnCaretMoved.y, x, y);\n
            if (distance > SCROLL_CURSOR_HYSTERESIS) {\n
                cursorMovedTime = null;\n
            } else if (now - cursorMovedTime >= SCROLL_CURSOR_DELAY) {\n
                editor.renderer.scrollCursorIntoView();\n
                cursorMovedTime = null;\n
            }\n
        }\n
    }\n
\n
    function autoScroll(cursor, prevCursor) {\n
        var now = new Date().getTime();\n
        var lineHeight = editor.renderer.layerConfig.lineHeight;\n
        var characterWidth = editor.renderer.layerConfig.characterWidth;\n
        var editorRect = editor.renderer.scroller.getBoundingClientRect();\n
        var offsets = {\n
           x: {\n
               left: x - editorRect.left,\n
               right: editorRect.right - x\n
           },\n
           y: {\n
               top: y - editorRect.top,\n
               bottom: editorRect.bottom - y\n
           }\n
        };\n
        var nearestXOffset = Math.min(offsets.x.left, offsets.x.right);\n
        var nearestYOffset = Math.min(offsets.y.top, offsets.y.bottom);\n
        var scrollCursor = {row: cursor.row, column: cursor.column};\n
        if (nearestXOffset / characterWidth <= 2) {\n
            scrollCursor.column += (offsets.x.left < offsets.x.right ? -3 : +2);\n
        }\n
        if (nearestYOffset / lineHeight <= 1) {\n
            scrollCursor.row += (offsets.y.top < offsets.y.bottom ? -1 : +1);\n
        }\n
        var vScroll = cursor.row != scrollCursor.row;\n
        var hScroll = cursor.column != scrollCursor.column;\n
        var vMovement = !prevCursor || cursor.row != prevCursor.row;\n
        if (vScroll || (hScroll && !vMovement)) {\n
            if (!autoScrollStartTime)\n
                autoScrollStartTime = now;\n
            else if (now - autoScrollStartTime >= AUTOSCROLL_DELAY)\n
                editor.renderer.scrollCursorIntoView(scrollCursor);\n
        } else {\n
            autoScrollStartTime = null;\n
        }\n
    }\n
\n
    function onDragInterval() {\n
        var prevCursor = dragCursor;\n
        dragCursor = editor.renderer.screenToTextCoordinates(x, y);\n
        scrollCursorIntoView(dragCursor, prevCursor);\n
        autoScroll(dragCursor, prevCursor);\n
    }\n
\n
    function addDragMarker() {\n
        range = editor.selection.toOrientedRange();\n
        dragSelectionMarker = editor.session.addMarker(range, "ace_selection", editor.getSelectionStyle());\n
        editor.clearSelection();\n
        if (editor.isFocused())\n
            editor.renderer.$cursorLayer.setBlinking(false);\n
        clearInterval(timerId);\n
        timerId = setInterval(onDragInterval, 20);\n
        counter = 0;\n
        event.addListener(document, "mousemove", onMouseMove);\n
    }\n
\n
    function clearDragMarker() {\n
        clearInterval(timerId);\n
        editor.session.removeMarker(dragSelectionMarker);\n
        dragSelectionMarker = null;\n
        editor.$blockScrolling += 1;\n
        editor.selection.fromOrientedRange(range);\n
        editor.$blockScrolling -= 1;\n
        if (editor.isFocused() && !isInternal)\n
            editor.renderer.$cursorLayer.setBlinking(!editor.getReadOnly());\n
        range = null;\n
        counter = 0;\n
        autoScrollStartTime = null;\n
        cursorMovedTime = null;\n
        event.removeListener(document, "mousemove", onMouseMove);\n
    }\n
    var onMouseMoveTimer = null;\n
    function onMouseMove() {\n
        if (onMouseMoveTimer == null) {\n
            onMouseMoveTimer = setTimeout(function() {\n
                if (onMouseMoveTimer != null && dragSelectionMarker)\n
                    clearDragMarker();\n
            }, 20);\n
        }\n
    }\n
\n
    function canAccept(dataTransfer) {\n
        var types = dataTransfer.types;\n
        return !types || Array.prototype.some.call(types, function(type) {\n
            return type == \'text/plain\' || type == \'Text\';\n
        });\n
    }\n
\n
    function getDropEffect(e) {\n
        var copyAllowed = [\'copy\', \'copymove\', \'all\', \'uninitialized\'];\n
        var moveAllowed = [\'move\', \'copymove\', \'linkmove\', \'all\', \'uninitialized\'];\n
\n
        var copyModifierState = useragent.isMac ? e.altKey : e.ctrlKey;\n
        var effectAllowed = "uninitialized";\n
        try {\n
            effectAllowed = e.dataTransfer.effectAllowed.toLowerCase();\n
        } catch (e) {}\n
        var dropEffect = "none";\n
\n
        if (copyModifierState && copyAllowed.indexOf(effectAllowed) >= 0)\n
            dropEffect = "copy";\n
        else if (moveAllowed.indexOf(effectAllowed) >= 0)\n
            dropEffect = "move";\n
        else if (copyAllowed.indexOf(effectAllowed) >= 0)\n
            dropEffect = "copy";\n
\n
        return dropEffect;\n
    }\n
}\n
\n
(function() {\n
\n
    this.dragWait = function() {\n
        var interval = (new Date()).getTime() - this.mousedownEvent.time;\n
        if (interval > this.editor.getDragDelay())\n
            this.startDrag();\n
    };\n
\n
    this.dragWaitEnd = function() {\n
        var target = this.editor.container;\n
        target.draggable = false;\n
        this.startSelect(this.mousedownEvent.getDocumentPosition());\n
        this.selectEnd();\n
    };\n
\n
    this.dragReadyEnd = function(e) {\n
        this.editor.renderer.$cursorLayer.setBlinking(!this.editor.getReadOnly());\n
        this.editor.unsetStyle("ace_dragging");\n
        this.dragWaitEnd();\n
    };\n
\n
    this.startDrag = function(){\n
        this.cancelDrag = false;\n
        var target = this.editor.container;\n
        target.draggable = true;\n
        this.editor.renderer.$cursorLayer.setBlinking(false);\n
        this.editor.setStyle("ace_dragging");\n
        this.setState("dragReady");\n
    };\n
\n
    this.onMouseDrag = function(e) {\n
        var target = this.editor.container;\n
        if (useragent.isIE && this.state == "dragReady") {\n
            var distance = calcDistance(this.mousedownEvent.x, this.mousedownEvent.y, this.x, this.y);\n
            if (distance > 3)\n
                target.dragDrop();\n
        }\n
        if (this.state === "dragWait") {\n
            var distance = calcDistance(this.mousedownEvent.x, this.mousedownEvent.y, this.x, this.y);\n
            if (distance > 0) {\n
                target.draggable = false;\n
                this.startSelect(this.mousedownEvent.getDocumentPosition());\n
            }\n
        }\n
    };\n
\n
    this.onMouseDown = function(e) {\n
        if (!this.$dragEnabled)\n
            return;\n
        this.mousedownEvent = e;\n
        var editor = this.editor;\n
\n
        var inSelection = e.inSelection();\n
        var button = e.getButton();\n
        var clickCount = e.domEvent.detail || 1;\n
        if (clickCount === 1 && button === 0 && inSelection) {\n
            this.mousedownEvent.time = (new Date()).getTime();\n
            var eventTarget = e.domEvent.target || e.domEvent.srcElement;\n
            if ("unselectable" in eventTarget)\n
                eventTarget.unselectable = "on";\n
            if (editor.getDragDelay()) {\n
                if (useragent.isWebKit) {\n
                    self.cancelDrag = true;\n
                    var mouseTarget = editor.container;\n
                    mouseTarget.draggable = true;\n
                }\n
                this.setState("dragWait");\n
            } else {\n
                this.startDrag();\n
            }\n
            this.captureMouse(e, this.onMouseDrag.bind(this));\n
            e.defaultPrevented = true;\n
        }\n
    };\n
\n
}).call(DragdropHandler.prototype);\n
\n
\n
function calcDistance(ax, ay, bx, by) {\n
    return Math.sqrt(Math.pow(bx - ax, 2) + Math.pow(by - ay, 2));\n
}\n
\n
exports.DragdropHandler = DragdropHandler;\n
\n
});\n
\n
define(\'ace/config\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/lib/oop\', \'ace/lib/net\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
"no use strict";\n
\n
var lang = require("./lib/lang");\n
var oop = require("./lib/oop");\n
var net = require("./lib/net");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
\n
var global = (function() {\n
    return this;\n
})();\n
\n
var options = {\n
    packaged: false,\n
    workerPath: null,\n
    modePath: null,\n
    themePath: null,\n
    basePath: "",\n
    suffix: ".js",\n
    $moduleUrls: {}\n
};\n
\n
exports.get = function(key) {\n
    if (!options.hasOwnProperty(key))\n
        throw new Error("Unknown config key: " + key);\n
\n
    return options[key];\n
};\n
\n
exports.set = function(key, value) {\n
    if (!options.hasOwnProperty(key))\n
        throw new Error("Unknown config key: " + key);\n
\n
    options[key] = value;\n
};\n
\n
exports.all = function() {\n
    return lang.copyObject(options);\n
};\n
oop.implement(exports, EventEmitter);\n
\n
exports.moduleUrl = function(name, component) {\n
    if (options.$moduleUrls[name])\n
        return options.$moduleUrls[name];\n
\n
    var parts = name.split("/");\n
    component = component || parts[parts.length - 2] || "";\n
    var sep = component == "snippets" ? "/" : "-";\n
    var base = parts[parts.length - 1];    \n
    if (sep == "-") {\n
        var re = new RegExp("^" + component + "[\\\\-_]|[\\\\-_]" + component + "$", "g");\n
        base = base.replace(re, "");\n
    }\n
\n
    if ((!base || base == component) && parts.length > 1)\n
        base = parts[parts.length - 2];\n
    var path = options[component + "Path"];\n
    if (path == null) {\n
        path = options.basePath;\n
    } else if (sep == "/") {\n
        component = sep = "";\n
    }\n
    if (path && path.slice(-1) != "/")\n
        path += "/";\n
    return path + component + sep + base + this.get("suffix");\n
};\n
\n
exports.setModuleUrl = function(name, subst) {\n
    return options.$moduleUrls[name] = subst;\n
};\n
\n
exports.$loading = {};\n
exports.loadModule = function(moduleName, onLoad) {\n
    var module, moduleType;\n
    if (Array.isArray(moduleName)) {\n
        moduleType = moduleName[0];\n
        moduleName = moduleName[1];\n
    }\n
\n
    try {\n
        module = require(moduleName);\n
    } catch (e) {}\n
    if (module && !exports.$loading[moduleName])\n
        return onLoad && onLoad(module);\n
\n
    if (!exports.$loading[moduleName])\n
        exports.$loading[moduleName] = [];\n
\n
    exports.$loading[moduleName].push(onLoad);\n
\n
    if (exports.$loading[moduleName].length > 1)\n
        return;\n
\n
    var afterLoad = function() {\n
        require([moduleName], function(module) {\n
            exports._emit("load.module", {name: moduleName, module: module});\n
            var listeners = exports.$loading[moduleName];\n
            exports.$loading[moduleName] = null;\n
            listeners.forEach(function(onLoad) {\n
                onLoad && onLoad(module);\n
            });\n
        });\n
    };\n
\n
    if (!exports.get("packaged"))\n
        return afterLoad();\n
    net.loadScript(exports.moduleUrl(moduleName, moduleType), afterLoad);\n
};\n
exports.init = function() {\n
    options.packaged = require.packaged || module.packaged || (global.define && define.packaged);\n
\n
    if (!global.document)\n
        return "";\n
\n
    var scriptOptions = {};\n
    var scriptUrl = "";\n
\n
    var scripts = document.getElementsByTagName("script");\n
    for (var i=0; i<scripts.length; i++) {\n
        var script = scripts[i];\n
\n
        var src = script.src || script.getAttribute("src");\n
        if (!src)\n
            continue;\n
\n
        var attributes = script.attributes;\n
        for (var j=0, l=attributes.length; j < l; j++) {\n
            var attr = attributes[j];\n
            if (attr.name.indexOf("data-ace-") === 0) {\n
                scriptOptions[deHyphenate(attr.name.replace(/^data-ace-/, ""))] = attr.value;\n
            }\n
        }\n
\n
        var m = src.match(/^(.*)\\/ace(\\-\\w+)?\\.js(\\?|$)/);\n
        if (m)\n
            scriptUrl = m[1];\n
    }\n
\n
    if (scriptUrl) {\n
        scriptOptions.base = scriptOptions.base || scriptUrl;\n
        scriptOptions.packaged = true;\n
    }\n
\n
    scriptOptions.basePath = scriptOptions.base;\n
    scriptOptions.workerPath = scriptOptions.workerPath || scriptOptions.base;\n
    scriptOptions.modePath = scriptOptions.modePath || scriptOptions.base;\n
    scriptOptions.themePath = scriptOptions.themePath || scriptOptions.base;\n
    delete scriptOptions.base;\n
\n
    for (var key in scriptOptions)\n
        if (typeof scriptOptions[key] !== "undefined")\n
            exports.set(key, scriptOptions[key]);\n
};\n
\n
function deHyphenate(str) {\n
    return str.replace(/-(.)/g, function(m, m1) { return m1.toUpperCase(); });\n
}\n
\n
var optionsProvider = {\n
    setOptions: function(optList) {\n
        Object.keys(optList).forEach(function(key) {\n
            this.setOption(key, optList[key]);\n
        }, this);\n
    },\n
    getOptions: function(optionNames) {\n
        var result = {};\n
        if (!optionNames) {\n
            optionNames = Object.keys(this.$options);\n
        } else if (!Array.isArray(optionNames)) {\n
            result = optionNames;\n
            optionNames = Object.keys(result);\n
        }\n
        optionNames.forEach(function(key) {\n
            result[key] = this.getOption(key);\n
        }, this);\n
        return result;\n
    },\n
    setOption: function(name, value) {\n
        if (this["$" + name] === value)\n
            return;\n
        var opt = this.$options[name];\n
        if (!opt) {\n
            if (typeof console != "undefined" && console.warn)\n
                console.warn(\'misspelled option "\' + name + \'"\');\n
            return undefined;\n
        }\n
        if (opt.forwardTo)\n
            return this[opt.forwardTo] && this[opt.forwardTo].setOption(name, value);\n
\n
        if (!opt.handlesSet)\n
            this["$" + name] = value;\n
        if (opt && opt.set)\n
            opt.set.call(this, value);\n
    },\n
    getOption: function(name) {\n
        var opt = this.$options[name];\n
        if (!opt) {\n
            if (typeof console != "undefined" && console.warn)\n
                console.warn(\'misspelled option "\' + name + \'"\');\n
            return undefined;\n
        }\n
        if (opt.forwardTo)\n
            return this[opt.forwardTo] && this[opt.forwardTo].getOption(name);\n
        return opt && opt.get ? opt.get.call(this) : this["$" + name];\n
    }\n
};\n
\n
var defaultOptions = {};\n
exports.defineOptions = function(obj, path, options) {\n
    if (!obj.$options)\n
        defaultOptions[path] = obj.$options = {};\n
\n
    Object.keys(options).forEach(function(key) {\n
        var opt = options[key];\n
        if (typeof opt == "string")\n
            opt = {forwardTo: opt};\n
\n
        opt.name || (opt.name = key);\n
        obj.$options[opt.name] = opt;\n
        if ("initialValue" in opt)\n
            obj["$" + opt.name] = opt.initialValue;\n
    });\n
    oop.implement(obj, optionsProvider);\n
\n
    return this;\n
};\n
\n
exports.resetOptions = function(obj) {\n
    Object.keys(obj.$options).forEach(function(key) {\n
        var opt = obj.$options[key];\n
        if ("value" in opt)\n
            obj.setOption(key, opt.value);\n
    });\n
};\n
\n
exports.setDefaultValue = function(path, name, value) {\n
    var opts = defaultOptions[path] || (defaultOptions[path] = {});\n
    if (opts[name]) {\n
        if (opts.forwardTo)\n
            exports.setDefaultValue(opts.forwardTo, name, value);\n
        else\n
            opts[name].value = value;\n
    }\n
};\n
\n
exports.setDefaultValues = function(path, optionHash) {\n
    Object.keys(optionHash).forEach(function(key) {\n
        exports.setDefaultValue(path, key, optionHash[key]);\n
    });\n
};\n
\n
});\n
define(\'ace/lib/net\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
var dom = require("./dom");\n
\n
exports.get = function (url, callback) {\n
    var xhr = new XMLHttpRequest();\n
    xhr.open(\'GET\', url, true);\n
    xhr.onreadystatechange = function () {\n
        if (xhr.readyState === 4) {\n
            callback(xhr.responseText);\n
        }\n
    };\n
    xhr.send(null);\n
};\n
\n
exports.loadScript = function(path, callback) {\n
    var head = dom.getDocumentHead();\n
    var s = document.createElement(\'script\');\n
\n
    s.src = path;\n
    head.appendChild(s);\n
\n
    s.onload = s.onreadystatechange = function(_, isAbort) {\n
        if (isAbort || !s.readyState || s.readyState == "loaded" || s.readyState == "complete") {\n
            s = s.onload = s.onreadystatechange = null;\n
            if (!isAbort)\n
                callback();\n
        }\n
    };\n
};\n
\n
});\n
\n
define(\'ace/lib/event_emitter\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
var EventEmitter = {};\n
var stopPropagation = function() { this.propagationStopped = true; };\n
var preventDefault = function() { this.defaultPrevented = true; };\n
\n
EventEmitter._emit =\n
EventEmitter._dispatchEvent = function(eventName, e) {\n
    this._eventRegistry || (this._eventRegistry = {});\n
    this._defaultHandlers || (this._defaultHandlers = {});\n
\n
    var listeners = this._eventRegistry[eventName] || [];\n
    var defaultHandler = this._defaultHandlers[eventName];\n
    if (!listeners.length && !defaultHandler)\n
        return;\n
\n
    if (typeof e != "object" || !e)\n
        e = {};\n
\n
    if (!e.type)\n
        e.type = eventName;\n
    if (!e.stopPropagation)\n
        e.stopPropagation = stopPropagation;\n
    if (!e.preventDefault)\n
        e.preventDefault = preventDefault;\n
\n
    listeners = listeners.slice();\n
    for (var i=0; i<listeners.length; i++) {\n
        listeners[i](e, this);\n
        if (e.propagationStopped)\n
            break;\n
    }\n
    \n
    if (defaultHandler && !e.defaultPrevented)\n
        return defaultHandler(e, this);\n
};\n
\n
\n
EventEmitter._signal = function(eventName, e) {\n
    var listeners = (this._eventRegistry || {})[eventName];\n
    if (!listeners)\n
        return;\n
    listeners = listeners.slice();\n
    for (var i=0; i<listeners.length; i++)\n
        listeners[i](e, this);\n
};\n
\n
EventEmitter.once = function(eventName, callback) {\n
    var _self = this;\n
    callback && this.addEventListener(eventName, function newCallback() {\n
        _self.removeEventListener(eventName, newCallback);\n
        callback.apply(null, arguments);\n
    });\n
};\n
\n
\n
EventEmitter.setDefaultHandler = function(eventName, callback) {\n
    var handlers = this._defaultHandlers\n
    if (!handlers)\n
        handlers = this._defaultHandlers = {_disabled_: {}};\n
    \n
    if (handlers[eventName]) {\n
        var old = handlers[eventName];\n
        var disabled = handlers._disabled_[eventName];\n
        if (!disabled)\n
            handlers._disabled_[eventName] = disabled = [];\n
        disabled.push(old);\n
        var i = disabled.indexOf(callback);\n
        if (i != -1) \n
            disabled.splice(i, 1);\n
    }\n
    handlers[eventName] = callback;\n
};\n
EventEmitter.removeDefaultHandler = function(eventName, callback) {\n
    var handlers = this._defaultHandlers\n
    if (!handlers)\n
        return;\n
    var disabled = handlers._disabled_[eventName];\n
    \n
    if (handlers[eventName] == callback) {\n
        var old = handlers[eventName];\n
        if (disabled)\n
            this.setDefaultHandler(eventName, disabled.pop());\n
    } else if (disabled) {\n
        var i = disabled.indexOf(callback);\n
        if (i != -1)\n
            disabled.splice(i, 1);\n
    }\n
};\n
\n
EventEmitter.on =\n
EventEmitter.addEventListener = function(eventName, callback, capturing) {\n
    this._eventRegistry = this._eventRegistry || {};\n
\n
    var listeners = this._eventRegistry[eventName];\n
    if (!listeners)\n
        listeners = this._eventRegistry[eventName] = [];\n
\n
    if (listeners.indexOf(callback) == -1)\n
        listeners[capturing ? "unshift" : "push"](callback);\n
    return callback;\n
};\n
\n
EventEmitter.off =\n
EventEmitter.removeListener =\n
EventEmitter.removeEventListener = function(eventName, callback) {\n
    this._eventRegistry = this._eventRegistry || {};\n
\n
    var listeners = this._eventRegistry[eventName];\n
    if (!listeners)\n
        return;\n
\n
    var index = listeners.indexOf(callback);\n
    if (index !== -1)\n
        listeners.splice(index, 1);\n
};\n
\n
EventEmitter.removeAllListeners = function(eventName) {\n
    if (this._eventRegistry) this._eventRegistry[eventName] = [];\n
};\n
\n
exports.EventEmitter = EventEmitter;\n
\n
});\n
\n
define(\'ace/mouse/fold_handler\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
function FoldHandler(editor) {\n
\n
    editor.on("click", function(e) {\n
        var position = e.getDocumentPosition();\n
        var session = editor.session;\n
        var fold = session.getFoldAt(position.row, position.column, 1);\n
        if (fold) {\n
            if (e.getAccelKey())\n
                session.removeFold(fold);\n
            else\n
                session.expandFold(fold);\n
\n
            e.stop();\n
        }\n
    });\n
\n
    editor.on("gutterclick", function(e) {\n
        var gutterRegion = editor.renderer.$gutterLayer.getRegion(e);\n
\n
        if (gutterRegion == "foldWidgets") {\n
            var row = e.getDocumentPosition().row;\n
            var session = editor.session;\n
            if (session.foldWidgets && session.foldWidgets[row])\n
                editor.session.onFoldWidgetClick(row, e);\n
            if (!editor.isFocused())\n
                editor.focus();\n
            e.stop();\n
        }\n
    });\n
\n
    editor.on("gutterdblclick", function(e) {\n
        var gutterRegion = editor.renderer.$gutterLayer.getRegion(e);\n
\n
        if (gutterRegion == "foldWidgets") {\n
            var row = e.getDocumentPosition().row;\n
            var session = editor.session;\n
            var data = session.getParentFoldRangeData(row, true);\n
            var range = data.range || data.firstRange;\n
\n
            if (range) {\n
                var row = range.start.row;\n
                var fold = session.getFoldAt(row, session.getLine(row).length, 1);\n
\n
                if (fold) {\n
                    session.removeFold(fold);\n
                } else {\n
                    session.addFold("...", range);\n
                    editor.renderer.scrollCursorIntoView({row: range.start.row, column: 0});\n
                }\n
            }\n
            e.stop();\n
        }\n
    });\n
}\n
\n
exports.FoldHandler = FoldHandler;\n
\n
});\n
\n
define(\'ace/keyboard/keybinding\', [\'require\', \'exports\', \'module\' , \'ace/lib/keys\', \'ace/lib/event\'], function(require, exports, module) {\n
\n
\n
var keyUtil  = require("../lib/keys");\n
var event = require("../lib/event");\n
\n
var KeyBinding = function(editor) {\n
    this.$editor = editor;\n
    this.$data = { };\n
    this.$handlers = [];\n
    this.setDefaultHandler(editor.commands);\n
};\n
\n
(function() {\n
    this.setDefaultHandler = function(kb) {\n
        this.removeKeyboardHandler(this.$defaultHandler);\n
        this.$defaultHandler = kb;\n
        this.addKeyboardHandler(kb, 0);\n
        this.$data = {editor: this.$editor};\n
    };\n
\n
    this.setKeyboardHandler = function(kb) {\n
        var h = this.$handlers;\n
        if (h[h.length - 1] == kb)\n
            return;\n
\n
        while (h[h.length - 1] && h[h.length - 1] != this.$defaultHandler)\n
            this.removeKeyboardHandler(h[h.length - 1]);\n
\n
        this.addKeyboardHandler(kb, 1);\n
    };\n
\n
    this.addKeyboardHandler = function(kb, pos) {\n
        if (!kb)\n
            return;\n
        var i = this.$handlers.indexOf(kb);\n
        if (i != -1)\n
            this.$handlers.splice(i, 1);\n
\n
        if (pos == undefined)\n
            this.$handlers.push(kb);\n
        else\n
            this.$handlers.splice(pos, 0, kb);\n
\n
        if (i == -1 && kb.attach)\n
            kb.attach(this.$editor);\n
    };\n
\n
    this.removeKeyboardHandler = function(kb) {\n
        var i = this.$handlers.indexOf(kb);\n
        if (i == -1)\n
            return false;\n
        this.$handlers.splice(i, 1);\n
        kb.detach && kb.detach(this.$editor);\n
        return true;\n
    };\n
\n
    this.getKeyboardHandler = function() {\n
        return this.$handlers[this.$handlers.length - 1];\n
    };\n
\n
    this.$callKeyboardHandlers = function (hashId, keyString, keyCode, e) {\n
        var toExecute;\n
        var success = false;\n
        var commands = this.$editor.commands;\n
\n
        for (var i = this.$handlers.length; i--;) {\n
            toExecute = this.$handlers[i].handleKeyboard(\n
                this.$data, hashId, keyString, keyCode, e\n
            );\n
            if (!toExecute || !toExecute.command)\n
                continue;\n
            if (toExecute.command == "null") {\n
                success = true;\n
            } else {\n
                success = commands.exec(toExecute.command, this.$editor, toExecute.args, e);                \n
            }\n
            if (success && e && hashId != -1 && \n
                toExecute.passEvent != true && toExecute.command.passEvent != true\n
            ) {\n
                event.stopEvent(e);\n
            }\n
            if (success)\n
                break;\n
        }\n
        return success;\n
    };\n
\n
    this.onCommandKey = function(e, hashId, keyCode) {\n
        var keyString = keyUtil.keyCodeToString(keyCode);\n
        this.$callKeyboardHandlers(hashId, keyString, keyCode, e);\n
    };\n
\n
    this.onTextInput = function(text) {\n
        var success = this.$callKeyboardHandlers(-1, text);\n
        if (!success)\n
            this.$editor.commands.exec("insertstring", this.$editor, text);\n
    };\n
\n
}).call(KeyBinding.prototype);\n
\n
exports.KeyBinding = KeyBinding;\n
});\n
\n
define(\'ace/edit_session\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/config\', \'ace/lib/event_emitter\', \'ace/selection\', \'ace/mode/text\', \'ace/range\', \'ace/document\', \'ace/background_tokenizer\', \'ace/search_highlight\', \'ace/edit_session/folding\', \'ace/edit_session/bracket_match\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var lang = require("./lib/lang");\n
var config = require("./config");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var Selection = require("./selection").Selection;\n
var TextMode = require("./mode/text").Mode;\n
var Range = require("./range").Range;\n
var Document = require("./document").Document;\n
var BackgroundTokenizer = require("./background_tokenizer").BackgroundTokenizer;\n
var SearchHighlight = require("./search_highlight").SearchHighlight;\n
\n
var EditSession = function(text, mode) {\n
    this.$breakpoints = [];\n
    this.$decorations = [];\n
    this.$frontMarkers = {};\n
    this.$backMarkers = {};\n
    this.$markerId = 1;\n
    this.$undoSelect = true;\n
\n
    this.$foldData = [];\n
    this.$foldData.toString = function() {\n
        return this.join("\\n");\n
    }\n
    this.on("changeFold", this.onChangeFold.bind(this));\n
    this.$onChange = this.onChange.bind(this);\n
\n
    if (typeof text != "object" || !text.getLine)\n
        text = new Document(text);\n
\n
    this.setDocument(text);\n
    this.selection = new Selection(this);\n
\n
    config.resetOptions(this);\n
    this.setMode(mode);\n
    config._emit("session", this);\n
};\n
\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
    this.setDocument = function(doc) {\n
        if (this.doc)\n
            this.doc.removeListener("change", this.$onChange);\n
\n
        this.doc = doc;\n
        doc.on("change", this.$onChange);\n
\n
        if (this.bgTokenizer)\n
            this.bgTokenizer.setDocument(this.getDocument());\n
\n
        this.resetCaches();\n
    };\n
    this.getDocument = function() {\n
        return this.doc;\n
    };\n
    this.$resetRowCache = function(docRow) {\n
        if (!docRow) {\n
            this.$docRowCache = [];\n
            this.$screenRowCache = [];\n
            return;\n
        }\n
        var l = this.$docRowCache.length;\n
        var i = this.$getRowCacheIndex(this.$docRowCache, docRow) + 1;\n
        if (l > i) {\n
            this.$docRowCache.splice(i, l);\n
            this.$screenRowCache.splice(i, l);\n
        }\n
    };\n
\n
    this.$getRowCacheIndex = function(cacheArray, val) {\n
        var low = 0;\n
        var hi = cacheArray.length - 1;\n
\n
        while (low <= hi) {\n
            var mid = (low + hi) >> 1;\n
            var c = cacheArray[mid];\n
\n
            if (val > c)\n
                low = mid + 1;\n
            else if (val < c)\n
                hi = mid - 1;\n
            else\n
                return mid;\n
        }\n
\n
        return low -1;\n
    };\n
\n
    this.resetCaches = function() {\n
        this.$modified = true;\n
        this.$wrapData = [];\n
        this.$rowLengthCache = [];\n
        this.$resetRowCache(0);\n
        if (this.bgTokenizer)\n
            this.bgTokenizer.start(0);\n
    };\n
\n
    this.onChangeFold = function(e) {\n
        var fold = e.data;\n
        this.$resetRowCache(fold.start.row);\n
    };\n
\n
    this.onChange = function(e) {\n
        var delta = e.data;\n
        this.$modified = true;\n
\n
        this.$resetRowCache(delta.range.start.row);\n
\n
        var removedFolds = this.$updateInternalDataOnChange(e);\n
        if (!this.$fromUndo && this.$undoManager && !delta.ignore) {\n
            this.$deltasDoc.push(delta);\n
            if (removedFolds && removedFolds.length != 0) {\n
                this.$deltasFold.push({\n
                    action: "removeFolds",\n
                    folds:  removedFolds\n
                });\n
            }\n
\n
            this.$informUndoManager.schedule();\n
        }\n
\n
        this.bgTokenizer.$updateOnChange(delta);\n
        this._emit("change", e);\n
    };\n
    this.setValue = function(text) {\n
        this.doc.setValue(text);\n
        this.selection.moveCursorTo(0, 0);\n
        this.selection.clearSelection();\n
\n
        this.$resetRowCache(0);\n
        this.$deltas = [];\n
        this.$deltasDoc = [];\n
        this.$deltasFold = [];\n
        this.getUndoManager().reset();\n
    };\n
    this.getValue =\n
    this.toString = function() {\n
        return this.doc.getValue();\n
    };\n
    this.getSelection = function() {\n
        return this.selection;\n
    };\n
    this.getState = function(row) {\n
        return this.bgTokenizer.getState(row);\n
    };\n
    this.getTokens = function(row) {\n
        return this.bgTokenizer.getTokens(row);\n
    };\n
    this.getTokenAt = function(row, column) {\n
        var tokens = this.bgTokenizer.getTokens(row);\n
        var token, c = 0;\n
        if (column == null) {\n
            i = tokens.length - 1;\n
            c = this.getLine(row).length;\n
        } else {\n
            for (var i = 0; i < tokens.length; i++) {\n
                c += tokens[i].value.length;\n
                if (c >= column)\n
                    break;\n
            }\n
        }\n
        token = tokens[i];\n
        if (!token)\n
            return null;\n
        token.index = i;\n
        token.start = c - token.value.length;\n
        return token;\n
    };\n
    this.setUndoManager = function(undoManager) {\n
        this.$undoManager = undoManager;\n
        this.$deltas = [];\n
        this.$deltasDoc = [];\n
        this.$deltasFold = [];\n
\n
        if (this.$informUndoManager)\n
            this.$informUndoManager.cancel();\n
\n
        if (undoManager) {\n
            var self = this;\n
\n
            this.$syncInformUndoManager = function() {\n
                self.$informUndoManager.cancel();\n
\n
                if (self.$deltasFold.length) {\n
                    self.$deltas.push({\n
                        group: "fold",\n
                        deltas: self.$deltasFold\n
                    });\n
                    self.$deltasFold = [];\n
                }\n
\n
                if (self.$deltasDoc.length) {\n
                    self.$deltas.push({\n
                        group: "doc",\n
                        deltas: self.$deltasDoc\n
                    });\n
                    self.$deltasDoc = [];\n
                }\n
\n
                if (self.$deltas.length > 0) {\n
                    undoManager.execute({\n
                        action: "aceupdate",\n
                        args: [self.$deltas, self],\n
                        merge: self.mergeUndoDeltas\n
                    });\n
                }\n
                self.mergeUndoDeltas = false;\n
                self.$deltas = [];\n
            }\n
            this.$informUndoManager = lang.delayedCall(this.$syncInformUndoManager);\n
        }\n
    };\n
    this.markUndoGroup = function() {\n
        if (this.$syncInformUndoManager)\n
            this.$syncInformUndoManager();\n
    };\n
    \n
    this.$defaultUndoManager = {\n
        undo: function() {},\n
        redo: function() {},\n
        reset: function() {}\n
    };\n
    this.getUndoManager = function() {\n
        return this.$undoManager || this.$defaultUndoManager;\n
    };\n
    this.getTabString = function() {\n
        if (this.getUseSoftTabs()) {\n
            return lang.stringRepeat(" ", this.getTabSize());\n
        } else {\n
            return "\\t";\n
        }\n
    };\n
    this.setUseSoftTabs = function(val) {\n
        this.setOption("useSoftTabs", val);\n
    };\n
    this.getUseSoftTabs = function() {\n
        return this.$useSoftTabs && !this.$mode.$indentWithTabs;\n
    };\n
    this.setTabSize = function(tabSize) {\n
        this.setOption("tabSize", tabSize)\n
    };\n
    this.getTabSize = function() {\n
        return this.$tabSize;\n
    };\n
    this.isTabStop = function(position) {\n
        return this.$useSoftTabs && (position.column % this.$tabSize == 0);\n
    };\n
\n
    this.$overwrite = false;\n
    this.setOverwrite = function(overwrite) {\n
        this.setOption("overwrite", overwrite)\n
    };\n
    this.getOverwrite = function() {\n
        return this.$overwrite;\n
    };\n
    this.toggleOverwrite = function() {\n
        this.setOverwrite(!this.$overwrite);\n
    };\n
    this.addGutterDecoration = function(row, className) {\n
        if (!this.$decorations[row])\n
            this.$decorations[row] = "";\n
        this.$decorations[row] += " " + className;\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.removeGutterDecoration = function(row, className) {\n
        this.$decorations[row] = (this.$decorations[row] || "").replace(" " + className, "");\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.getBreakpoints = function() {\n
        return this.$breakpoints;\n
    };\n
    this.setBreakpoints = function(rows) {\n
        this.$breakpoints = [];\n
        for (var i=0; i<rows.length; i++) {\n
            this.$breakpoints[rows[i]] = "ace_breakpoint";\n
        }\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.clearBreakpoints = function() {\n
        this.$breakpoints = [];\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.setBreakpoint = function(row, className) {\n
        if (className === undefined)\n
            className = "ace_breakpoint";\n
        if (className)\n
            this.$breakpoints[row] = className;\n
        else\n
            delete this.$breakpoints[row];\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.clearBreakpoint = function(row) {\n
        delete this.$breakpoints[row];\n
        this._emit("changeBreakpoint", {});\n
    };\n
    this.addMarker = function(range, clazz, type, inFront) {\n
        var id = this.$markerId++;\n
\n
        var marker = {\n
            range : range,\n
            type : type || "line",\n
            renderer: typeof type == "function" ? type : null,\n
            clazz : clazz,\n
            inFront: !!inFront,\n
            id: id\n
        }\n
\n
        if (inFront) {\n
            this.$frontMarkers[id] = marker;\n
            this._emit("changeFrontMarker")\n
        } else {\n
            this.$backMarkers[id] = marker;\n
            this._emit("changeBackMarker")\n
        }\n
\n
        return id;\n
    };\n
    this.addDynamicMarker = function(marker, inFront) {\n
        if (!marker.update)\n
            return;\n
        var id = this.$markerId++;\n
        marker.id = id;\n
        marker.inFront = !!inFront;\n
\n
        if (inFront) {\n
            this.$frontMarkers[id] = marker;\n
            this._emit("changeFrontMarker")\n
        } else {\n
            this.$backMarkers[id] = marker;\n
            this._emit("changeBackMarker")\n
        }\n
\n
        return marker;\n
    };\n
    this.removeMarker = function(markerId) {\n
        var marker = this.$frontMarkers[markerId] || this.$backMarkers[markerId];\n
        if (!marker)\n
            return;\n
\n
        var markers = marker.inFront ? this.$frontMarkers : this.$backMarkers;\n
        if (marker) {\n
            delete (markers[markerId]);\n
            this._emit(marker.inFront ? "changeFrontMarker" : "changeBackMarker");\n
        }\n
    };\n
    this.getMarkers = function(inFront) {\n
        return inFront ? this.$frontMarkers : this.$backMarkers;\n
    };\n
\n
    this.highlight = function(re) {\n
        if (!this.$searchHighlight) {\n
            var highlight = new SearchHighlight(null, "ace_selected-word", "text");\n
            this.$searchHighlight = this.addDynamicMarker(highlight);\n
        }\n
        this.$searchHighlight.setRegexp(re);\n
    }\n
    this.highlightLines = function(startRow, endRow, clazz, inFront) {\n
        if (typeof endRow != "number") {\n
            clazz = endRow;\n
            endRow = startRow;\n
        }\n
        if (!clazz)\n
            clazz = "ace_step";\n
\n
        var range = new Range(startRow, 0, endRow, Infinity);\n
        range.id = this.addMarker(range, clazz, "fullLine", inFront);\n
        return range;\n
    };\n
    this.setAnnotations = function(annotations) {\n
        this.$annotations = annotations;\n
        this._emit("changeAnnotation", {});\n
    };\n
    this.getAnnotations = function() {\n
        return this.$annotations || [];\n
    };\n
    this.clearAnnotations = function() {\n
        this.setAnnotations([]);\n
  

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

  };\n
    this.$detectNewLine = function(text) {\n
        var match = text.match(/^.*?(\\r?\\n)/m);\n
        if (match) {\n
            this.$autoNewLine = match[1];\n
        } else {\n
            this.$autoNewLine = "\\n";\n
        }\n
    };\n
    this.getWordRange = function(row, column) {\n
        var line = this.getLine(row);\n
\n
        var inToken = false;\n
        if (column > 0)\n
            inToken = !!line.charAt(column - 1).match(this.tokenRe);\n
\n
        if (!inToken)\n
            inToken = !!line.charAt(column).match(this.tokenRe);\n
\n
        if (inToken)\n
            var re = this.tokenRe;\n
        else if (/^\\s+$/.test(line.slice(column-1, column+1)))\n
            var re = /\\s/;\n
        else\n
            var re = this.nonTokenRe;\n
\n
        var start = column;\n
        if (start > 0) {\n
            do {\n
                start--;\n
            }\n
            while (start >= 0 && line.charAt(start).match(re));\n
            start++;\n
        }\n
\n
        var end = column;\n
        while (end < line.length && line.charAt(end).match(re)) {\n
            end++;\n
        }\n
\n
        return new Range(row, start, row, end);\n
    };\n
    this.getAWordRange = function(row, column) {\n
        var wordRange = this.getWordRange(row, column);\n
        var line = this.getLine(wordRange.end.row);\n
\n
        while (line.charAt(wordRange.end.column).match(/[ \\t]/)) {\n
            wordRange.end.column += 1;\n
        }\n
        return wordRange;\n
    };\n
    this.setNewLineMode = function(newLineMode) {\n
        this.doc.setNewLineMode(newLineMode);\n
    };\n
    this.getNewLineMode = function() {\n
        return this.doc.getNewLineMode();\n
    };\n
    this.setUseWorker = function(useWorker) { this.setOption("useWorker", useWorker); };\n
    this.getUseWorker = function() { return this.$useWorker; };\n
    this.onReloadTokenizer = function(e) {\n
        var rows = e.data;\n
        this.bgTokenizer.start(rows.first);\n
        this._emit("tokenizerUpdate", e);\n
    };\n
\n
    this.$modes = {};\n
    this.$mode = null;\n
    this.$modeId = null;\n
    this.setMode = function(mode, cb) {\n
        if (mode && typeof mode === "object") {\n
            if (mode.getTokenizer)\n
                return this.$onChangeMode(mode);\n
            var options = mode;\n
            var path = options.path;\n
        } else {\n
            path = mode || "ace/mode/text";\n
        }\n
        if (!this.$modes["ace/mode/text"])\n
            this.$modes["ace/mode/text"] = new TextMode();\n
\n
        if (this.$modes[path] && !options) {\n
            this.$onChangeMode(this.$modes[path]);\n
            cb && cb();\n
            return;\n
        }\n
        this.$modeId = path;\n
        config.loadModule(["mode", path], function(m) {\n
            if (this.$modeId !== path)\n
                return cb && cb();\n
            if (this.$modes[path] && !options)\n
                return this.$onChangeMode(this.$modes[path]);\n
            if (m && m.Mode) {\n
                m = new m.Mode(options);\n
                if (!options) {\n
                    this.$modes[path] = m;\n
                    m.$id = path;\n
                }\n
                this.$onChangeMode(m);\n
                cb && cb();\n
            }\n
        }.bind(this));\n
        if (!this.$mode)\n
            this.$onChangeMode(this.$modes["ace/mode/text"], true);\n
    };\n
\n
    this.$onChangeMode = function(mode, $isPlaceholder) {\n
        if (!$isPlaceholder)\n
            this.$modeId = mode.$id;\n
        if (this.$mode === mode) \n
            return;\n
\n
        this.$mode = mode;\n
\n
        this.$stopWorker();\n
\n
        if (this.$useWorker)\n
            this.$startWorker();\n
\n
        var tokenizer = mode.getTokenizer();\n
\n
        if(tokenizer.addEventListener !== undefined) {\n
            var onReloadTokenizer = this.onReloadTokenizer.bind(this);\n
            tokenizer.addEventListener("update", onReloadTokenizer);\n
        }\n
\n
        if (!this.bgTokenizer) {\n
            this.bgTokenizer = new BackgroundTokenizer(tokenizer);\n
            var _self = this;\n
            this.bgTokenizer.addEventListener("update", function(e) {\n
                _self._emit("tokenizerUpdate", e);\n
            });\n
        } else {\n
            this.bgTokenizer.setTokenizer(tokenizer);\n
        }\n
\n
        this.bgTokenizer.setDocument(this.getDocument());\n
\n
        this.tokenRe = mode.tokenRe;\n
        this.nonTokenRe = mode.nonTokenRe;\n
\n
        this.$options.wrapMethod.set.call(this, this.$wrapMethod);\n
        \n
        if (!$isPlaceholder) {\n
            this.$setFolding(mode.foldingRules);\n
            this._emit("changeMode");\n
            this.bgTokenizer.start(0);\n
        }\n
    };\n
\n
\n
    this.$stopWorker = function() {\n
        if (this.$worker)\n
            this.$worker.terminate();\n
\n
        this.$worker = null;\n
    };\n
\n
    this.$startWorker = function() {\n
        if (typeof Worker !== "undefined" && !require.noWorker) {\n
            try {\n
                this.$worker = this.$mode.createWorker(this);\n
            } catch (e) {\n
                console.log("Could not load worker");\n
                console.log(e);\n
                this.$worker = null;\n
            }\n
        }\n
        else\n
            this.$worker = null;\n
    };\n
    this.getMode = function() {\n
        return this.$mode;\n
    };\n
\n
    this.$scrollTop = 0;\n
    this.setScrollTop = function(scrollTop) {\n
        if (this.$scrollTop === scrollTop || isNaN(scrollTop))\n
            return;\n
\n
        this.$scrollTop = scrollTop;\n
        this._signal("changeScrollTop", scrollTop);\n
    };\n
    this.getScrollTop = function() {\n
        return this.$scrollTop;\n
    };\n
\n
    this.$scrollLeft = 0;\n
    this.setScrollLeft = function(scrollLeft) {\n
        if (this.$scrollLeft === scrollLeft || isNaN(scrollLeft))\n
            return;\n
\n
        this.$scrollLeft = scrollLeft;\n
        this._signal("changeScrollLeft", scrollLeft);\n
    };\n
    this.getScrollLeft = function() {\n
        return this.$scrollLeft;\n
    };\n
    this.getScreenWidth = function() {\n
        this.$computeWidth();\n
        return this.screenWidth;\n
    };\n
\n
    this.$computeWidth = function(force) {\n
        if (this.$modified || force) {\n
            this.$modified = false;\n
\n
            if (this.$useWrapMode)\n
                return this.screenWidth = this.$wrapLimit;\n
\n
            var lines = this.doc.getAllLines();\n
            var cache = this.$rowLengthCache;\n
            var longestScreenLine = 0;\n
            var foldIndex = 0;\n
            var foldLine = this.$foldData[foldIndex];\n
            var foldStart = foldLine ? foldLine.start.row : Infinity;\n
            var len = lines.length;\n
\n
            for (var i = 0; i < len; i++) {\n
                if (i > foldStart) {\n
                    i = foldLine.end.row + 1;\n
                    if (i >= len)\n
                        break;\n
                    foldLine = this.$foldData[foldIndex++];\n
                    foldStart = foldLine ? foldLine.start.row : Infinity;\n
                }\n
\n
                if (cache[i] == null)\n
                    cache[i] = this.$getStringScreenWidth(lines[i])[0];\n
\n
                if (cache[i] > longestScreenLine)\n
                    longestScreenLine = cache[i];\n
            }\n
            this.screenWidth = longestScreenLine;\n
        }\n
    };\n
    this.getLine = function(row) {\n
        return this.doc.getLine(row);\n
    };\n
    this.getLines = function(firstRow, lastRow) {\n
        return this.doc.getLines(firstRow, lastRow);\n
    };\n
    this.getLength = function() {\n
        return this.doc.getLength();\n
    };\n
    this.getTextRange = function(range) {\n
        return this.doc.getTextRange(range || this.selection.getRange());\n
    };\n
    this.insert = function(position, text) {\n
        return this.doc.insert(position, text);\n
    };\n
    this.remove = function(range) {\n
        return this.doc.remove(range);\n
    };\n
    this.undoChanges = function(deltas, dontSelect) {\n
        if (!deltas.length)\n
            return;\n
\n
        this.$fromUndo = true;\n
        var lastUndoRange = null;\n
        for (var i = deltas.length - 1; i != -1; i--) {\n
            var delta = deltas[i];\n
            if (delta.group == "doc") {\n
                this.doc.revertDeltas(delta.deltas);\n
                lastUndoRange =\n
                    this.$getUndoSelection(delta.deltas, true, lastUndoRange);\n
            } else {\n
                delta.deltas.forEach(function(foldDelta) {\n
                    this.addFolds(foldDelta.folds);\n
                }, this);\n
            }\n
        }\n
        this.$fromUndo = false;\n
        lastUndoRange &&\n
            this.$undoSelect &&\n
            !dontSelect &&\n
            this.selection.setSelectionRange(lastUndoRange);\n
        return lastUndoRange;\n
    };\n
    this.redoChanges = function(deltas, dontSelect) {\n
        if (!deltas.length)\n
            return;\n
\n
        this.$fromUndo = true;\n
        var lastUndoRange = null;\n
        for (var i = 0; i < deltas.length; i++) {\n
            var delta = deltas[i];\n
            if (delta.group == "doc") {\n
                this.doc.applyDeltas(delta.deltas);\n
                lastUndoRange =\n
                    this.$getUndoSelection(delta.deltas, false, lastUndoRange);\n
            }\n
        }\n
        this.$fromUndo = false;\n
        lastUndoRange &&\n
            this.$undoSelect &&\n
            !dontSelect &&\n
            this.selection.setSelectionRange(lastUndoRange);\n
        return lastUndoRange;\n
    };\n
    this.setUndoSelect = function(enable) {\n
        this.$undoSelect = enable;\n
    };\n
\n
    this.$getUndoSelection = function(deltas, isUndo, lastUndoRange) {\n
        function isInsert(delta) {\n
            var insert =\n
                delta.action === "insertText" || delta.action === "insertLines";\n
            return isUndo ? !insert : insert;\n
        }\n
\n
        var delta = deltas[0];\n
        var range, point;\n
        var lastDeltaIsInsert = false;\n
        if (isInsert(delta)) {\n
            range = Range.fromPoints(delta.range.start, delta.range.end);\n
            lastDeltaIsInsert = true;\n
        } else {\n
            range = Range.fromPoints(delta.range.start, delta.range.start);\n
            lastDeltaIsInsert = false;\n
        }\n
\n
        for (var i = 1; i < deltas.length; i++) {\n
            delta = deltas[i];\n
            if (isInsert(delta)) {\n
                point = delta.range.start;\n
                if (range.compare(point.row, point.column) == -1) {\n
                    range.setStart(delta.range.start);\n
                }\n
                point = delta.range.end;\n
                if (range.compare(point.row, point.column) == 1) {\n
                    range.setEnd(delta.range.end);\n
                }\n
                lastDeltaIsInsert = true;\n
            } else {\n
                point = delta.range.start;\n
                if (range.compare(point.row, point.column) == -1) {\n
                    range =\n
                        Range.fromPoints(delta.range.start, delta.range.start);\n
                }\n
                lastDeltaIsInsert = false;\n
            }\n
        }\n
        if (lastUndoRange != null) {\n
            if (Range.comparePoints(lastUndoRange.start, range.start) == 0) {\n
                lastUndoRange.start.column += range.end.column - range.start.column;\n
                lastUndoRange.end.column += range.end.column - range.start.column;\n
            }\n
\n
            var cmp = lastUndoRange.compareRange(range);\n
            if (cmp == 1) {\n
                range.setStart(lastUndoRange.start);\n
            } else if (cmp == -1) {\n
                range.setEnd(lastUndoRange.end);\n
            }\n
        }\n
\n
        return range;\n
    };\n
    this.replace = function(range, text) {\n
        return this.doc.replace(range, text);\n
    };\n
    this.moveText = function(fromRange, toPosition, copy) {\n
        var text = this.getTextRange(fromRange);\n
        var folds = this.getFoldsInRange(fromRange);\n
\n
        var toRange = Range.fromPoints(toPosition, toPosition);\n
        if (!copy) {\n
            this.remove(fromRange);\n
            var rowDiff = fromRange.start.row - fromRange.end.row;\n
            var collDiff = rowDiff ? -fromRange.end.column : fromRange.start.column - fromRange.end.column;\n
            if (collDiff) {\n
                if (toRange.start.row == fromRange.end.row && toRange.start.column > fromRange.end.column)\n
                    toRange.start.column += collDiff;\n
                if (toRange.end.row == fromRange.end.row && toRange.end.column > fromRange.end.column)\n
                    toRange.end.column += collDiff;\n
            }\n
            if (rowDiff && toRange.start.row >= fromRange.end.row) {\n
                toRange.start.row += rowDiff;\n
                toRange.end.row += rowDiff;\n
            }\n
        }\n
\n
        toRange.end = this.insert(toRange.start, text);\n
        if (folds.length) {\n
            var oldStart = fromRange.start;\n
            var newStart = toRange.start;\n
            var rowDiff = newStart.row - oldStart.row;\n
            var collDiff = newStart.column - oldStart.column;\n
            this.addFolds(folds.map(function(x) {\n
                x = x.clone();\n
                if (x.start.row == oldStart.row)\n
                    x.start.column += collDiff;\n
                if (x.end.row == oldStart.row)\n
                    x.end.column += collDiff;\n
                x.start.row += rowDiff;\n
                x.end.row += rowDiff;\n
                return x;\n
            }));\n
        }\n
\n
        return toRange;\n
    };\n
    this.indentRows = function(startRow, endRow, indentString) {\n
        indentString = indentString.replace(/\\t/g, this.getTabString());\n
        for (var row=startRow; row<=endRow; row++)\n
            this.insert({row: row, column:0}, indentString);\n
    };\n
    this.outdentRows = function (range) {\n
        var rowRange = range.collapseRows();\n
        var deleteRange = new Range(0, 0, 0, 0);\n
        var size = this.getTabSize();\n
\n
        for (var i = rowRange.start.row; i <= rowRange.end.row; ++i) {\n
            var line = this.getLine(i);\n
\n
            deleteRange.start.row = i;\n
            deleteRange.end.row = i;\n
            for (var j = 0; j < size; ++j)\n
                if (line.charAt(j) != \' \')\n
                    break;\n
            if (j < size && line.charAt(j) == \'\\t\') {\n
                deleteRange.start.column = j;\n
                deleteRange.end.column = j + 1;\n
            } else {\n
                deleteRange.start.column = 0;\n
                deleteRange.end.column = j;\n
            }\n
            this.remove(deleteRange);\n
        }\n
    };\n
\n
    this.$moveLines = function(firstRow, lastRow, dir) {\n
        firstRow = this.getRowFoldStart(firstRow);\n
        lastRow = this.getRowFoldEnd(lastRow);\n
        if (dir < 0) {\n
            var row = this.getRowFoldStart(firstRow + dir);\n
            if (row < 0) return 0;\n
            var diff = row-firstRow;\n
        } else if (dir > 0) {\n
            var row = this.getRowFoldEnd(lastRow + dir);\n
            if (row > this.doc.getLength()-1) return 0;\n
            var diff = row-lastRow;\n
        } else {\n
            firstRow = this.$clipRowToDocument(firstRow);\n
            lastRow = this.$clipRowToDocument(lastRow);\n
            var diff = lastRow - firstRow + 1;\n
        }\n
\n
        var range = new Range(firstRow, 0, lastRow, Number.MAX_VALUE);\n
        var folds = this.getFoldsInRange(range).map(function(x){\n
            x = x.clone();\n
            x.start.row += diff;\n
            x.end.row += diff;\n
            return x;\n
        });\n
\n
        var lines = dir == 0\n
            ? this.doc.getLines(firstRow, lastRow)\n
            : this.doc.removeLines(firstRow, lastRow);\n
        this.doc.insertLines(firstRow+diff, lines);\n
        folds.length && this.addFolds(folds);\n
        return diff;\n
    };\n
    this.moveLinesUp = function(firstRow, lastRow) {\n
        return this.$moveLines(firstRow, lastRow, -1);\n
    };\n
    this.moveLinesDown = function(firstRow, lastRow) {\n
        return this.$moveLines(firstRow, lastRow, 1);\n
    };\n
    this.duplicateLines = function(firstRow, lastRow) {\n
        return this.$moveLines(firstRow, lastRow, 0);\n
    };\n
\n
\n
    this.$clipRowToDocument = function(row) {\n
        return Math.max(0, Math.min(row, this.doc.getLength()-1));\n
    };\n
\n
    this.$clipColumnToRow = function(row, column) {\n
        if (column < 0)\n
            return 0;\n
        return Math.min(this.doc.getLine(row).length, column);\n
    };\n
\n
\n
    this.$clipPositionToDocument = function(row, column) {\n
        column = Math.max(0, column);\n
\n
        if (row < 0) {\n
            row = 0;\n
            column = 0;\n
        } else {\n
            var len = this.doc.getLength();\n
            if (row >= len) {\n
                row = len - 1;\n
                column = this.doc.getLine(len-1).length;\n
            } else {\n
                column = Math.min(this.doc.getLine(row).length, column);\n
            }\n
        }\n
\n
        return {\n
            row: row,\n
            column: column\n
        };\n
    };\n
\n
    this.$clipRangeToDocument = function(range) {\n
        if (range.start.row < 0) {\n
            range.start.row = 0;\n
            range.start.column = 0;\n
        } else {\n
            range.start.column = this.$clipColumnToRow(\n
                range.start.row,\n
                range.start.column\n
            );\n
        }\n
\n
        var len = this.doc.getLength() - 1;\n
        if (range.end.row > len) {\n
            range.end.row = len;\n
            range.end.column = this.doc.getLine(len).length;\n
        } else {\n
            range.end.column = this.$clipColumnToRow(\n
                range.end.row,\n
                range.end.column\n
            );\n
        }\n
        return range;\n
    };\n
    this.$wrapLimit = 80;\n
    this.$useWrapMode = false;\n
    this.$wrapLimitRange = {\n
        min : null,\n
        max : null\n
    };\n
    this.setUseWrapMode = function(useWrapMode) {\n
        if (useWrapMode != this.$useWrapMode) {\n
            this.$useWrapMode = useWrapMode;\n
            this.$modified = true;\n
            this.$resetRowCache(0);\n
            if (useWrapMode) {\n
                var len = this.getLength();\n
                this.$wrapData = [];\n
                for (var i = 0; i < len; i++) {\n
                    this.$wrapData.push([]);\n
                }\n
                this.$updateWrapData(0, len - 1);\n
            }\n
\n
            this._emit("changeWrapMode");\n
        }\n
    };\n
    this.getUseWrapMode = function() {\n
        return this.$useWrapMode;\n
    };\n
    this.setWrapLimitRange = function(min, max) {\n
        if (this.$wrapLimitRange.min !== min || this.$wrapLimitRange.max !== max) {\n
            this.$wrapLimitRange = {\n
                min: min,\n
                max: max\n
            };\n
            this.$modified = true;\n
            this._emit("changeWrapMode");\n
        }\n
    };\n
    this.adjustWrapLimit = function(desiredLimit, $printMargin) {\n
        var limits = this.$wrapLimitRange\n
        if (limits.max < 0)\n
            limits = {min: $printMargin, max: $printMargin};\n
        var wrapLimit = this.$constrainWrapLimit(desiredLimit, limits.min, limits.max);\n
        if (wrapLimit != this.$wrapLimit && wrapLimit > 1) {\n
            this.$wrapLimit = wrapLimit;\n
            this.$modified = true;\n
            if (this.$useWrapMode) {\n
                this.$updateWrapData(0, this.getLength() - 1);\n
                this.$resetRowCache(0);\n
                this._emit("changeWrapLimit");\n
            }\n
            return true;\n
        }\n
        return false;\n
    };\n
\n
    this.$constrainWrapLimit = function(wrapLimit, min, max) {\n
        if (min)\n
            wrapLimit = Math.max(min, wrapLimit);\n
\n
        if (max)\n
            wrapLimit = Math.min(max, wrapLimit);\n
\n
        return wrapLimit;\n
    };\n
    this.getWrapLimit = function() {\n
        return this.$wrapLimit;\n
    };\n
    this.setWrapLimit = function (limit) {\n
        this.setWrapLimitRange(limit, limit);\n
    };\n
    this.getWrapLimitRange = function() {\n
        return {\n
            min : this.$wrapLimitRange.min,\n
            max : this.$wrapLimitRange.max\n
        };\n
    };\n
\n
    this.$updateInternalDataOnChange = function(e) {\n
        var useWrapMode = this.$useWrapMode;\n
        var len;\n
        var action = e.data.action;\n
        var firstRow = e.data.range.start.row;\n
        var lastRow = e.data.range.end.row;\n
        var start = e.data.range.start;\n
        var end = e.data.range.end;\n
        var removedFolds = null;\n
\n
        if (action.indexOf("Lines") != -1) {\n
            if (action == "insertLines") {\n
                lastRow = firstRow + (e.data.lines.length);\n
            } else {\n
                lastRow = firstRow;\n
            }\n
            len = e.data.lines ? e.data.lines.length : lastRow - firstRow;\n
        } else {\n
            len = lastRow - firstRow;\n
        }\n
\n
        this.$updating = true;\n
        if (len != 0) {\n
            if (action.indexOf("remove") != -1) {\n
                this[useWrapMode ? "$wrapData" : "$rowLengthCache"].splice(firstRow, len);\n
\n
                var foldLines = this.$foldData;\n
                removedFolds = this.getFoldsInRange(e.data.range);\n
                this.removeFolds(removedFolds);\n
\n
                var foldLine = this.getFoldLine(end.row);\n
                var idx = 0;\n
                if (foldLine) {\n
                    foldLine.addRemoveChars(end.row, end.column, start.column - end.column);\n
                    foldLine.shiftRow(-len);\n
\n
                    var foldLineBefore = this.getFoldLine(firstRow);\n
                    if (foldLineBefore && foldLineBefore !== foldLine) {\n
                        foldLineBefore.merge(foldLine);\n
                        foldLine = foldLineBefore;\n
                    }\n
                    idx = foldLines.indexOf(foldLine) + 1;\n
                }\n
\n
                for (idx; idx < foldLines.length; idx++) {\n
                    var foldLine = foldLines[idx];\n
                    if (foldLine.start.row >= end.row) {\n
                        foldLine.shiftRow(-len);\n
                    }\n
                }\n
\n
                lastRow = firstRow;\n
            } else {\n
                var args;\n
                if (useWrapMode) {\n
                    args = [firstRow, 0];\n
                    for (var i = 0; i < len; i++) args.push([]);\n
                    this.$wrapData.splice.apply(this.$wrapData, args);\n
                } else {\n
                    args = Array(len);\n
                    args.unshift(firstRow, 0);\n
                    this.$rowLengthCache.splice.apply(this.$rowLengthCache, args);\n
                }\n
                var foldLines = this.$foldData;\n
                var foldLine = this.getFoldLine(firstRow);\n
                var idx = 0;\n
                if (foldLine) {\n
                    var cmp = foldLine.range.compareInside(start.row, start.column)\n
                    if (cmp == 0) {\n
                        foldLine = foldLine.split(start.row, start.column);\n
                        foldLine.shiftRow(len);\n
                        foldLine.addRemoveChars(\n
                            lastRow, 0, end.column - start.column);\n
                    } else\n
                    if (cmp == -1) {\n
                        foldLine.addRemoveChars(firstRow, 0, end.column - start.column);\n
                        foldLine.shiftRow(len);\n
                    }\n
                    idx = foldLines.indexOf(foldLine) + 1;\n
                }\n
\n
                for (idx; idx < foldLines.length; idx++) {\n
                    var foldLine = foldLines[idx];\n
                    if (foldLine.start.row >= firstRow) {\n
                        foldLine.shiftRow(len);\n
                    }\n
                }\n
            }\n
        } else {\n
            len = Math.abs(e.data.range.start.column - e.data.range.end.column);\n
            if (action.indexOf("remove") != -1) {\n
                removedFolds = this.getFoldsInRange(e.data.range);\n
                this.removeFolds(removedFolds);\n
\n
                len = -len;\n
            }\n
            var foldLine = this.getFoldLine(firstRow);\n
            if (foldLine) {\n
                foldLine.addRemoveChars(firstRow, start.column, len);\n
            }\n
        }\n
\n
        if (useWrapMode && this.$wrapData.length != this.doc.getLength()) {\n
            console.error("doc.getLength() and $wrapData.length have to be the same!");\n
        }\n
        this.$updating = false;\n
\n
        if (useWrapMode)\n
            this.$updateWrapData(firstRow, lastRow);\n
        else\n
            this.$updateRowLengthCache(firstRow, lastRow);\n
\n
        return removedFolds;\n
    };\n
\n
    this.$updateRowLengthCache = function(firstRow, lastRow, b) {\n
        this.$rowLengthCache[firstRow] = null;\n
        this.$rowLengthCache[lastRow] = null;\n
    };\n
\n
    this.$updateWrapData = function(firstRow, lastRow) {\n
        var lines = this.doc.getAllLines();\n
        var tabSize = this.getTabSize();\n
        var wrapData = this.$wrapData;\n
        var wrapLimit = this.$wrapLimit;\n
        var tokens;\n
        var foldLine;\n
\n
        var row = firstRow;\n
        lastRow = Math.min(lastRow, lines.length - 1);\n
        while (row <= lastRow) {\n
            foldLine = this.getFoldLine(row, foldLine);\n
            if (!foldLine) {\n
                tokens = this.$getDisplayTokens(lines[row]);\n
                wrapData[row] = this.$computeWrapSplits(tokens, wrapLimit, tabSize);\n
                row ++;\n
            } else {\n
                tokens = [];\n
                foldLine.walk(function(placeholder, row, column, lastColumn) {\n
                        var walkTokens;\n
                        if (placeholder != null) {\n
                            walkTokens = this.$getDisplayTokens(\n
                                            placeholder, tokens.length);\n
                            walkTokens[0] = PLACEHOLDER_START;\n
                            for (var i = 1; i < walkTokens.length; i++) {\n
                                walkTokens[i] = PLACEHOLDER_BODY;\n
                            }\n
                        } else {\n
                            walkTokens = this.$getDisplayTokens(\n
                                lines[row].substring(lastColumn, column),\n
                                tokens.length);\n
                        }\n
                        tokens = tokens.concat(walkTokens);\n
                    }.bind(this),\n
                    foldLine.end.row,\n
                    lines[foldLine.end.row].length + 1\n
                );\n
\n
                wrapData[foldLine.start.row]\n
                    = this.$computeWrapSplits(tokens, wrapLimit, tabSize);\n
                row = foldLine.end.row + 1;\n
            }\n
        }\n
    };\n
    var CHAR = 1,\n
        CHAR_EXT = 2,\n
        PLACEHOLDER_START = 3,\n
        PLACEHOLDER_BODY =  4,\n
        PUNCTUATION = 9,\n
        SPACE = 10,\n
        TAB = 11,\n
        TAB_SPACE = 12;\n
\n
\n
    this.$computeWrapSplits = function(tokens, wrapLimit) {\n
        if (tokens.length == 0) {\n
            return [];\n
        }\n
\n
        var splits = [];\n
        var displayLength = tokens.length;\n
        var lastSplit = 0, lastDocSplit = 0;\n
\n
        var isCode = this.$wrapAsCode;\n
\n
        function addSplit(screenPos) {\n
            var displayed = tokens.slice(lastSplit, screenPos);\n
            var len = displayed.length;\n
            displayed.join("").\n
                replace(/12/g, function() {\n
                    len -= 1;\n
                }).\n
                replace(/2/g, function() {\n
                    len -= 1;\n
                });\n
\n
            lastDocSplit += len;\n
            splits.push(lastDocSplit);\n
            lastSplit = screenPos;\n
        }\n
\n
        while (displayLength - lastSplit > wrapLimit) {\n
            var split = lastSplit + wrapLimit;\n
            if (tokens[split - 1] >= SPACE && tokens[split] >= SPACE) {\n
                addSplit(split);\n
                continue;\n
            }\n
            if (tokens[split] == PLACEHOLDER_START || tokens[split] == PLACEHOLDER_BODY) {\n
                for (split; split != lastSplit - 1; split--) {\n
                    if (tokens[split] == PLACEHOLDER_START) {\n
                        break;\n
                    }\n
                }\n
                if (split > lastSplit) {\n
                    addSplit(split);\n
                    continue;\n
                }\n
                split = lastSplit + wrapLimit;\n
                for (split; split < tokens.length; split++) {\n
                    if (tokens[split] != PLACEHOLDER_BODY) {\n
                        break;\n
                    }\n
                }\n
                if (split == tokens.length) {\n
                    break;  // Breaks the while-loop.\n
                }\n
                addSplit(split);\n
                continue;\n
            }\n
            var minSplit = Math.max(split - (isCode ? 10 : wrapLimit-(wrapLimit>>2)), lastSplit - 1);\n
            while (split > minSplit && tokens[split] < PLACEHOLDER_START) {\n
                split --;\n
            }\n
            if (isCode) {\n
                while (split > minSplit && tokens[split] < PLACEHOLDER_START) {\n
                    split --;\n
                }\n
                while (split > minSplit && tokens[split] == PUNCTUATION) {\n
                    split --;\n
                }\n
            } else {\n
                while (split > minSplit && tokens[split] < SPACE) {\n
                    split --;\n
                }\n
            }\n
            if (split > minSplit) {\n
                addSplit(++split);\n
                continue;\n
            }\n
            split = lastSplit + wrapLimit;\n
            addSplit(split);\n
        }\n
        return splits;\n
    };\n
    this.$getDisplayTokens = function(str, offset) {\n
        var arr = [];\n
        var tabSize;\n
        offset = offset || 0;\n
\n
        for (var i = 0; i < str.length; i++) {\n
            var c = str.charCodeAt(i);\n
            if (c == 9) {\n
                tabSize = this.getScreenTabSize(arr.length + offset);\n
                arr.push(TAB);\n
                for (var n = 1; n < tabSize; n++) {\n
                    arr.push(TAB_SPACE);\n
                }\n
            }\n
            else if (c == 32) {\n
                arr.push(SPACE);\n
            } else if((c > 39 && c < 48) || (c > 57 && c < 64)) {\n
                arr.push(PUNCTUATION);\n
            }\n
            else if (c >= 0x1100 && isFullWidth(c)) {\n
                arr.push(CHAR, CHAR_EXT);\n
            } else {\n
                arr.push(CHAR);\n
            }\n
        }\n
        return arr;\n
    };\n
    this.$getStringScreenWidth = function(str, maxScreenColumn, screenColumn) {\n
        if (maxScreenColumn == 0)\n
            return [0, 0];\n
        if (maxScreenColumn == null)\n
            maxScreenColumn = Infinity;\n
        screenColumn = screenColumn || 0;\n
\n
        var c, column;\n
        for (column = 0; column < str.length; column++) {\n
            c = str.charCodeAt(column);\n
            if (c == 9) {\n
                screenColumn += this.getScreenTabSize(screenColumn);\n
            }\n
            else if (c >= 0x1100 && isFullWidth(c)) {\n
                screenColumn += 2;\n
            } else {\n
                screenColumn += 1;\n
            }\n
            if (screenColumn > maxScreenColumn) {\n
                break;\n
            }\n
        }\n
\n
        return [screenColumn, column];\n
    };\n
    this.getRowLength = function(row) {\n
        if (!this.$useWrapMode || !this.$wrapData[row]) {\n
            return 1;\n
        } else {\n
            return this.$wrapData[row].length + 1;\n
        }\n
    };\n
    this.getScreenLastRowColumn = function(screenRow) {\n
        var pos = this.screenToDocumentPosition(screenRow, Number.MAX_VALUE);\n
        return this.documentToScreenColumn(pos.row, pos.column);\n
    };\n
    this.getDocumentLastRowColumn = function(docRow, docColumn) {\n
        var screenRow = this.documentToScreenRow(docRow, docColumn);\n
        return this.getScreenLastRowColumn(screenRow);\n
    };\n
    this.getDocumentLastRowColumnPosition = function(docRow, docColumn) {\n
        var screenRow = this.documentToScreenRow(docRow, docColumn);\n
        return this.screenToDocumentPosition(screenRow, Number.MAX_VALUE / 10);\n
    };\n
    this.getRowSplitData = function(row) {\n
        if (!this.$useWrapMode) {\n
            return undefined;\n
        } else {\n
            return this.$wrapData[row];\n
        }\n
    };\n
    this.getScreenTabSize = function(screenColumn) {\n
        return this.$tabSize - screenColumn % this.$tabSize;\n
    };\n
\n
\n
    this.screenToDocumentRow = function(screenRow, screenColumn) {\n
        return this.screenToDocumentPosition(screenRow, screenColumn).row;\n
    };\n
\n
\n
    this.screenToDocumentColumn = function(screenRow, screenColumn) {\n
        return this.screenToDocumentPosition(screenRow, screenColumn).column;\n
    };\n
    this.screenToDocumentPosition = function(screenRow, screenColumn) {\n
        if (screenRow < 0)\n
            return {row: 0, column: 0};\n
\n
        var line;\n
        var docRow = 0;\n
        var docColumn = 0;\n
        var column;\n
        var row = 0;\n
        var rowLength = 0;\n
\n
        var rowCache = this.$screenRowCache;\n
        var i = this.$getRowCacheIndex(rowCache, screenRow);\n
        var l = rowCache.length;\n
        if (l && i >= 0) {\n
            var row = rowCache[i];\n
            var docRow = this.$docRowCache[i];\n
            var doCache = screenRow > rowCache[l - 1];\n
        } else {\n
            var doCache = !l;\n
        }\n
\n
        var maxRow = this.getLength() - 1;\n
        var foldLine = this.getNextFoldLine(docRow);\n
        var foldStart = foldLine ? foldLine.start.row : Infinity;\n
\n
        while (row <= screenRow) {\n
            rowLength = this.getRowLength(docRow);\n
            if (row + rowLength - 1 >= screenRow || docRow >= maxRow) {\n
                break;\n
            } else {\n
                row += rowLength;\n
                docRow++;\n
                if (docRow > foldStart) {\n
                    docRow = foldLine.end.row+1;\n
                    foldLine = this.getNextFoldLine(docRow, foldLine);\n
                    foldStart = foldLine ? foldLine.start.row : Infinity;\n
                }\n
            }\n
\n
            if (doCache) {\n
                this.$docRowCache.push(docRow);\n
                this.$screenRowCache.push(row);\n
            }\n
        }\n
\n
        if (foldLine && foldLine.start.row <= docRow) {\n
            line = this.getFoldDisplayLine(foldLine);\n
            docRow = foldLine.start.row;\n
        } else if (row + rowLength <= screenRow || docRow > maxRow) {\n
            return {\n
                row: maxRow,\n
                column: this.getLine(maxRow).length\n
            }\n
        } else {\n
            line = this.getLine(docRow);\n
            foldLine = null;\n
        }\n
\n
        if (this.$useWrapMode) {\n
            var splits = this.$wrapData[docRow];\n
            if (splits) {\n
                column = splits[screenRow - row];\n
                if(screenRow > row && splits.length) {\n
                    docColumn = splits[screenRow - row - 1] || splits[splits.length - 1];\n
                    line = line.substring(docColumn);\n
                }\n
            }\n
        }\n
\n
        docColumn += this.$getStringScreenWidth(line, screenColumn)[1];\n
        if (this.$useWrapMode && docColumn >= column)\n
            docColumn = column - 1;\n
\n
        if (foldLine)\n
            return foldLine.idxToPosition(docColumn);\n
\n
        return {row: docRow, column: docColumn};\n
    };\n
    this.documentToScreenPosition = function(docRow, docColumn) {\n
        if (typeof docColumn === "undefined")\n
            var pos = this.$clipPositionToDocument(docRow.row, docRow.column);\n
        else\n
            pos = this.$clipPositionToDocument(docRow, docColumn);\n
\n
        docRow = pos.row;\n
        docColumn = pos.column;\n
\n
        var screenRow = 0;\n
        var foldStartRow = null;\n
        var fold = null;\n
        fold = this.getFoldAt(docRow, docColumn, 1);\n
        if (fold) {\n
            docRow = fold.start.row;\n
            docColumn = fold.start.column;\n
        }\n
\n
        var rowEnd, row = 0;\n
\n
\n
        var rowCache = this.$docRowCache;\n
        var i = this.$getRowCacheIndex(rowCache, docRow);\n
        var l = rowCache.length;\n
        if (l && i >= 0) {\n
            var row = rowCache[i];\n
            var screenRow = this.$screenRowCache[i];\n
            var doCache = docRow > rowCache[l - 1];\n
        } else {\n
            var doCache = !l;\n
        }\n
\n
        var foldLine = this.getNextFoldLine(row);\n
        var foldStart = foldLine ?foldLine.start.row :Infinity;\n
\n
        while (row < docRow) {\n
            if (row >= foldStart) {\n
                rowEnd = foldLine.end.row + 1;\n
                if (rowEnd > docRow)\n
                    break;\n
                foldLine = this.getNextFoldLine(rowEnd, foldLine);\n
                foldStart = foldLine ?foldLine.start.row :Infinity;\n
            }\n
            else {\n
                rowEnd = row + 1;\n
            }\n
\n
            screenRow += this.getRowLength(row);\n
            row = rowEnd;\n
\n
            if (doCache) {\n
                this.$docRowCache.push(row);\n
                this.$screenRowCache.push(screenRow);\n
            }\n
        }\n
        var textLine = "";\n
        if (foldLine && row >= foldStart) {\n
            textLine = this.getFoldDisplayLine(foldLine, docRow, docColumn);\n
            foldStartRow = foldLine.start.row;\n
        } else {\n
            textLine = this.getLine(docRow).substring(0, docColumn);\n
            foldStartRow = docRow;\n
        }\n
        if (this.$useWrapMode) {\n
            var wrapRow = this.$wrapData[foldStartRow];\n
            var screenRowOffset = 0;\n
            while (textLine.length >= wrapRow[screenRowOffset]) {\n
                screenRow ++;\n
                screenRowOffset++;\n
            }\n
            textLine = textLine.substring(\n
                wrapRow[screenRowOffset - 1] || 0, textLine.length\n
            );\n
        }\n
\n
        return {\n
            row: screenRow,\n
            column: this.$getStringScreenWidth(textLine)[0]\n
        };\n
    };\n
    this.documentToScreenColumn = function(row, docColumn) {\n
        return this.documentToScreenPosition(row, docColumn).column;\n
    };\n
    this.documentToScreenRow = function(docRow, docColumn) {\n
        return this.documentToScreenPosition(docRow, docColumn).row;\n
    };\n
    this.getScreenLength = function() {\n
        var screenRows = 0;\n
        var fold = null;\n
        if (!this.$useWrapMode) {\n
            screenRows = this.getLength();\n
            var foldData = this.$foldData;\n
            for (var i = 0; i < foldData.length; i++) {\n
                fold = foldData[i];\n
                screenRows -= fold.end.row - fold.start.row;\n
            }\n
        } else {\n
            var lastRow = this.$wrapData.length;\n
            var row = 0, i = 0;\n
            var fold = this.$foldData[i++];\n
            var foldStart = fold ? fold.start.row :Infinity;\n
\n
            while (row < lastRow) {\n
                screenRows += this.$wrapData[row].length + 1;\n
                row ++;\n
                if (row > foldStart) {\n
                    row = fold.end.row+1;\n
                    fold = this.$foldData[i++];\n
                    foldStart = fold ?fold.start.row :Infinity;\n
                }\n
            }\n
        }\n
\n
        return screenRows;\n
    };\n
    function isFullWidth(c) {\n
        if (c < 0x1100)\n
            return false;\n
        return c >= 0x1100 && c <= 0x115F ||\n
               c >= 0x11A3 && c <= 0x11A7 ||\n
               c >= 0x11FA && c <= 0x11FF ||\n
               c >= 0x2329 && c <= 0x232A ||\n
               c >= 0x2E80 && c <= 0x2E99 ||\n
               c >= 0x2E9B && c <= 0x2EF3 ||\n
               c >= 0x2F00 && c <= 0x2FD5 ||\n
               c >= 0x2FF0 && c <= 0x2FFB ||\n
               c >= 0x3000 && c <= 0x303E ||\n
               c >= 0x3041 && c <= 0x3096 ||\n
               c >= 0x3099 && c <= 0x30FF ||\n
               c >= 0x3105 && c <= 0x312D ||\n
               c >= 0x3131 && c <= 0x318E ||\n
               c >= 0x3190 && c <= 0x31BA ||\n
               c >= 0x31C0 && c <= 0x31E3 ||\n
               c >= 0x31F0 && c <= 0x321E ||\n
               c >= 0x3220 && c <= 0x3247 ||\n
               c >= 0x3250 && c <= 0x32FE ||\n
               c >= 0x3300 && c <= 0x4DBF ||\n
               c >= 0x4E00 && c <= 0xA48C ||\n
               c >= 0xA490 && c <= 0xA4C6 ||\n
               c >= 0xA960 && c <= 0xA97C ||\n
               c >= 0xAC00 && c <= 0xD7A3 ||\n
               c >= 0xD7B0 && c <= 0xD7C6 ||\n
               c >= 0xD7CB && c <= 0xD7FB ||\n
               c >= 0xF900 && c <= 0xFAFF ||\n
               c >= 0xFE10 && c <= 0xFE19 ||\n
               c >= 0xFE30 && c <= 0xFE52 ||\n
               c >= 0xFE54 && c <= 0xFE66 ||\n
               c >= 0xFE68 && c <= 0xFE6B ||\n
               c >= 0xFF01 && c <= 0xFF60 ||\n
               c >= 0xFFE0 && c <= 0xFFE6;\n
    };\n
\n
}).call(EditSession.prototype);\n
\n
require("./edit_session/folding").Folding.call(EditSession.prototype);\n
require("./edit_session/bracket_match").BracketMatch.call(EditSession.prototype);\n
\n
\n
config.defineOptions(EditSession.prototype, "session", {\n
    wrap: {\n
        set: function(value) {\n
            if (!value || value == "off")\n
                value = false;\n
            else if (value == "free")\n
                value = true;\n
            else if (value == "printMargin")\n
                value = -1;\n
            else if (typeof value == "string")\n
                value = parseInt(value, 10) || false;\n
\n
            if (this.$wrap == value)\n
                return;\n
            if (!value) {\n
                this.setUseWrapMode(false);\n
            } else {\n
                var col = typeof value == "number" ? value : null;\n
                this.setWrapLimitRange(col, col);\n
                this.setUseWrapMode(true);\n
            }\n
            this.$wrap = value;\n
        },\n
        get: function() {\n
            return this.getUseWrapMode() ? this.getWrapLimitRange().min || "free" : "off";\n
        },\n
        handlesSet: true\n
    },    \n
    wrapMethod: {\n
        set: function(val) {\n
            if (val == "auto")\n
                this.$wrapAsCode = this.$mode.type != "text";\n
            else\n
                this.$wrapAsCode = val != "text";\n
        },\n
        initialValue: "auto"\n
    },\n
    firstLineNumber: {\n
        set: function() {this._emit("changeBreakpoint");},\n
        initialValue: 1\n
    },\n
    useWorker: {\n
        set: function(useWorker) {\n
            this.$useWorker = useWorker;\n
\n
            this.$stopWorker();\n
            if (useWorker)\n
                this.$startWorker();\n
        },\n
        initialValue: true\n
    },\n
    useSoftTabs: {initialValue: true},\n
    tabSize: {\n
        set: function(tabSize) {\n
            if (isNaN(tabSize) || this.$tabSize === tabSize) return;\n
\n
            this.$modified = true;\n
            this.$rowLengthCache = [];\n
            this.$tabSize = tabSize;\n
            this._emit("changeTabSize");\n
        },\n
        initialValue: 4,\n
        handlesSet: true\n
    },\n
    overwrite: {\n
        set: function(val) {this._emit("changeOverwrite");},\n
        initialValue: false\n
    },\n
    newLineMode: {\n
        set: function(val) {this.doc.setNewLineMode(val)},\n
        get: function() {return this.doc.getNewLineMode()},\n
        handlesSet: true\n
    }\n
});\n
\n
exports.EditSession = EditSession;\n
});\n
\n
define(\'ace/selection\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/lang\', \'ace/lib/event_emitter\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var lang = require("./lib/lang");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var Range = require("./range").Range;\n
var Selection = function(session) {\n
    this.session = session;\n
    this.doc = session.getDocument();\n
\n
    this.clearSelection();\n
    this.lead = this.selectionLead = this.doc.createAnchor(0, 0);\n
    this.anchor = this.selectionAnchor = this.doc.createAnchor(0, 0);\n
\n
    var self = this;\n
    this.lead.on("change", function(e) {\n
        self._emit("changeCursor");\n
        if (!self.$isEmpty)\n
            self._emit("changeSelection");\n
        if (!self.$keepDesiredColumnOnChange && e.old.column != e.value.column)\n
            self.$desiredColumn = null;\n
    });\n
\n
    this.selectionAnchor.on("change", function() {\n
        if (!self.$isEmpty)\n
            self._emit("changeSelection");\n
    });\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
    this.isEmpty = function() {\n
        return (this.$isEmpty || (\n
            this.anchor.row == this.lead.row &&\n
            this.anchor.column == this.lead.column\n
        ));\n
    };\n
    this.isMultiLine = function() {\n
        if (this.isEmpty()) {\n
            return false;\n
        }\n
\n
        return this.getRange().isMultiLine();\n
    };\n
    this.getCursor = function() {\n
        return this.lead.getPosition();\n
    };\n
    this.setSelectionAnchor = function(row, column) {\n
        this.anchor.setPosition(row, column);\n
\n
        if (this.$isEmpty) {\n
            this.$isEmpty = false;\n
            this._emit("changeSelection");\n
        }\n
    };\n
    this.getSelectionAnchor = function() {\n
        if (this.$isEmpty)\n
            return this.getSelectionLead()\n
        else\n
            return this.anchor.getPosition();\n
    };\n
    this.getSelectionLead = function() {\n
        return this.lead.getPosition();\n
    };\n
    this.shiftSelection = function(columns) {\n
        if (this.$isEmpty) {\n
            this.moveCursorTo(this.lead.row, this.lead.column + columns);\n
            return;\n
        };\n
\n
        var anchor = this.getSelectionAnchor();\n
        var lead = this.getSelectionLead();\n
\n
        var isBackwards = this.isBackwards();\n
\n
        if (!isBackwards || anchor.column !== 0)\n
            this.setSelectionAnchor(anchor.row, anchor.column + columns);\n
\n
        if (isBackwards || lead.column !== 0) {\n
            this.$moveSelection(function() {\n
                this.moveCursorTo(lead.row, lead.column + columns);\n
            });\n
        }\n
    };\n
    this.isBackwards = function() {\n
        var anchor = this.anchor;\n
        var lead = this.lead;\n
        return (anchor.row > lead.row || (anchor.row == lead.row && anchor.column > lead.column));\n
    };\n
    this.getRange = function() {\n
        var anchor = this.anchor;\n
        var lead = this.lead;\n
\n
        if (this.isEmpty())\n
            return Range.fromPoints(lead, lead);\n
\n
        if (this.isBackwards()) {\n
            return Range.fromPoints(lead, anchor);\n
        }\n
        else {\n
            return Range.fromPoints(anchor, lead);\n
        }\n
    };\n
    this.clearSelection = function() {\n
        if (!this.$isEmpty) {\n
            this.$isEmpty = true;\n
            this._emit("changeSelection");\n
        }\n
    };\n
    this.selectAll = function() {\n
        var lastRow = this.doc.getLength() - 1;\n
        this.setSelectionAnchor(0, 0);\n
        this.moveCursorTo(lastRow, this.doc.getLine(lastRow).length);\n
    };\n
    this.setRange =\n
    this.setSelectionRange = function(range, reverse) {\n
        if (reverse) {\n
            this.setSelectionAnchor(range.end.row, range.end.column);\n
            this.selectTo(range.start.row, range.start.column);\n
        } else {\n
            this.setSelectionAnchor(range.start.row, range.start.column);\n
            this.selectTo(range.end.row, range.end.column);\n
        }\n
        if (this.getRange().isEmpty())\n
            this.$isEmpty = true;\n
        this.$desiredColumn = null;\n
    };\n
\n
    this.$moveSelection = function(mover) {\n
        var lead = this.lead;\n
        if (this.$isEmpty)\n
            this.setSelectionAnchor(lead.row, lead.column);\n
\n
        mover.call(this);\n
    };\n
    this.selectTo = function(row, column) {\n
        this.$moveSelection(function() {\n
            this.moveCursorTo(row, column);\n
        });\n
    };\n
    this.selectToPosition = function(pos) {\n
        this.$moveSelection(function() {\n
            this.moveCursorToPosition(pos);\n
        });\n
    };\n
    this.selectUp = function() {\n
        this.$moveSelection(this.moveCursorUp);\n
    };\n
    this.selectDown = function() {\n
        this.$moveSelection(this.moveCursorDown);\n
    };\n
    this.selectRight = function() {\n
        this.$moveSelection(this.moveCursorRight);\n
    };\n
    this.selectLeft = function() {\n
        this.$moveSelection(this.moveCursorLeft);\n
    };\n
    this.selectLineStart = function() {\n
        this.$moveSelection(this.moveCursorLineStart);\n
    };\n
    this.selectLineEnd = function() {\n
        this.$moveSelection(this.moveCursorLineEnd);\n
    };\n
    this.selectFileEnd = function() {\n
        this.$moveSelection(this.moveCursorFileEnd);\n
    };\n
    this.selectFileStart = function() {\n
        this.$moveSelection(this.moveCursorFileStart);\n
    };\n
    this.selectWordRight = function() {\n
        this.$moveSelection(this.moveCursorWordRight);\n
    };\n
    this.selectWordLeft = function() {\n
        this.$moveSelection(this.moveCursorWordLeft);\n
    };\n
    this.getWordRange = function(row, column) {\n
        if (typeof column == "undefined") {\n
            var cursor = row || this.lead;\n
            row = cursor.row;\n
            column = cursor.column;\n
        }\n
        return this.session.getWordRange(row, column);\n
    };\n
    this.selectWord = function() {\n
        this.setSelectionRange(this.getWordRange());\n
    };\n
    this.selectAWord = function() {\n
        var cursor = this.getCursor();\n
        var range = this.session.getAWordRange(cursor.row, cursor.column);\n
        this.setSelectionRange(range);\n
    };\n
\n
    this.getLineRange = function(row, excludeLastChar) {\n
        var rowStart = typeof row == "number" ? row : this.lead.row;\n
        var rowEnd;\n
\n
        var foldLine = this.session.getFoldLine(rowStart);\n
        if (foldLine) {\n
            rowStart = foldLine.start.row;\n
            rowEnd = foldLine.end.row;\n
        } else {\n
            rowEnd = rowStart;\n
        }\n
        if (excludeLastChar === true)\n
            return new Range(rowStart, 0, rowEnd, this.session.getLine(rowEnd).length);\n
        else\n
            return new Range(rowStart, 0, rowEnd + 1, 0);\n
    };\n
    this.selectLine = function() {\n
        this.setSelectionRange(this.getLineRange());\n
    };\n
    this.moveCursorUp = function() {\n
        this.moveCursorBy(-1, 0);\n
    };\n
    this.moveCursorDown = function() {\n
        this.moveCursorBy(1, 0);\n
    };\n
    this.moveCursorLeft = function() {\n
        var cursor = this.lead.getPosition(),\n
            fold;\n
\n
        if (fold = this.session.getFoldAt(cursor.row, cursor.column, -1)) {\n
            this.moveCursorTo(fold.start.row, fold.start.column);\n
        } else if (cursor.column == 0) {\n
            if (cursor.row > 0) {\n
                this.moveCursorTo(cursor.row - 1, this.doc.getLine(cursor.row - 1).length);\n
            }\n
        }\n
        else {\n
            var tabSize = this.session.getTabSize();\n
            if (this.session.isTabStop(cursor) && this.doc.getLine(cursor.row).slice(cursor.column-tabSize, cursor.column).split(" ").length-1 == tabSize)\n
                this.moveCursorBy(0, -tabSize);\n
            else\n
                this.moveCursorBy(0, -1);\n
        }\n
    };\n
    this.moveCursorRight = function() {\n
        var cursor = this.lead.getPosition(),\n
            fold;\n
        if (fold = this.session.getFoldAt(cursor.row, cursor.column, 1)) {\n
            this.moveCursorTo(fold.end.row, fold.end.column);\n
        }\n
        else if (this.lead.column == this.doc.getLine(this.lead.row).length) {\n
            if (this.lead.row < this.doc.getLength() - 1) {\n
                this.moveCursorTo(this.lead.row + 1, 0);\n
            }\n
        }\n
        else {\n
            var tabSize = this.session.getTabSize();\n
            var cursor = this.lead;\n
            if (this.session.isTabStop(cursor) && this.doc.getLine(cursor.row).slice(cursor.column, cursor.column+tabSize).split(" ").length-1 == tabSize)\n
                this.moveCursorBy(0, tabSize);\n
            else\n
                this.moveCursorBy(0, 1);\n
        }\n
    };\n
    this.moveCursorLineStart = function() {\n
        var row = this.lead.row;\n
        var column = this.lead.column;\n
        var screenRow = this.session.documentToScreenRow(row, column);\n
        var firstColumnPosition = this.session.screenToDocumentPosition(screenRow, 0);\n
        var beforeCursor = this.session.getDisplayLine(\n
            row, null, firstColumnPosition.row,\n
            firstColumnPosition.column\n
        );\n
\n
        var leadingSpace = beforeCursor.match(/^\\s*/);\n
        if (leadingSpace[0].length != column && !this.session.$useEmacsStyleLineStart)\n
            firstColumnPosition.column += leadingSpace[0].length;\n
        this.moveCursorToPosition(firstColumnPosition);\n
    };\n
    this.moveCursorLineEnd = function() {\n
        var lead = this.lead;\n
        var lineEnd = this.session.getDocumentLastRowColumnPosition(lead.row, lead.column);\n
        if (this.lead.column == lineEnd.column) {\n
            var line = this.session.getLine(lineEnd.row);\n
            if (lineEnd.column == line.length) {\n
                var textEnd = line.search(/\\s+$/);\n
                if (textEnd > 0)\n
                    lineEnd.column = textEnd;\n
            }\n
        }\n
\n
        this.moveCursorTo(lineEnd.row, lineEnd.column);\n
    };\n
    this.moveCursorFileEnd = function() {\n
        var row = this.doc.getLength() - 1;\n
        var column = this.doc.getLine(row).length;\n
        this.moveCursorTo(row, column);\n
    };\n
    this.moveCursorFileStart = function() {\n
        this.moveCursorTo(0, 0);\n
    };\n
    this.moveCursorLongWordRight = function() {\n
        var row = this.lead.row;\n
        var column = this.lead.column;\n
        var line = this.doc.getLine(row);\n
        var rightOfCursor = line.substring(column);\n
\n
        var match;\n
        this.session.nonTokenRe.lastIndex = 0;\n
        this.session.tokenRe.lastIndex = 0;\n
        var fold = this.session.getFoldAt(row, column, 1);\n
        if (fold) {\n
            this.moveCursorTo(fold.end.row, fold.end.column);\n
            return;\n
        }\n
        if (match = this.session.nonTokenRe.exec(rightOfCursor)) {\n
            column += this.session.nonTokenRe.lastIndex;\n
            this.session.nonTokenRe.lastIndex = 0;\n
            rightOfCursor = line.substring(column);\n
        }\n
        if (column >= line.length) {\n
            this.moveCursorTo(row, line.length);\n
            this.moveCursorRight();\n
            if (row < this.doc.getLength() - 1)\n
                this.moveCursorWordRight();\n
            return;\n
        }\n
        if (match = this.session.tokenRe.exec(rightOfCursor)) {\n
            column += this.session.tokenRe.lastIndex;\n
            this.session.tokenRe.lastIndex = 0;\n
        }\n
\n
        this.moveCursorTo(row, column);\n
    };\n
    this.moveCursorLongWordLeft = function() {\n
        var row = this.lead.row;\n
        var column = this.lead.column;\n
        var fold;\n
        if (fold = this.session.getFoldAt(row, column, -1)) {\n
            this.moveCursorTo(fold.start.row, fold.start.column);\n
            return;\n
        }\n
\n
        var str = this.session.getFoldStringAt(row, column, -1);\n
        if (str == null) {\n
            str = this.doc.getLine(row).substring(0, column)\n
        }\n
\n
        var leftOfCursor = lang.stringReverse(str);\n
        var match;\n
        this.session.nonTokenRe.lastIndex = 0;\n
        this.session.tokenRe.lastIndex = 0;\n
        if (match = this.session.nonTokenRe.exec(leftOfCursor)) {\n
            column -= this.session.nonTokenRe.lastIndex;\n
            leftOfCursor = leftOfCursor.slice(this.session.nonTokenRe.lastIndex);\n
            this.session.nonTokenRe.lastIndex = 0;\n
        }\n
        if (column <= 0) {\n
            this.moveCursorTo(row, 0);\n
            this.moveCursorLeft();\n
            if (row > 0)\n
                this.moveCursorWordLeft();\n
            return;\n
        }\n
        if (match = this.session.tokenRe.exec(leftOfCursor)) {\n
            column -= this.session.tokenRe.lastIndex;\n
            this.session.tokenRe.lastIndex = 0;\n
        }\n
\n
        this.moveCursorTo(row, column);\n
    };\n
\n
    this.$shortWordEndIndex = function(rightOfCursor) {\n
        var match, index = 0, ch;\n
        var whitespaceRe = /\\s/;\n
        var tokenRe = this.session.tokenRe;\n
\n
        tokenRe.lastIndex = 0;\n
        if (match = this.session.tokenRe.exec(rightOfCursor)) {\n
            index = this.session.tokenRe.lastIndex;\n
        } else {\n
            while ((ch = rightOfCursor[index]) && whitespaceRe.test(ch))\n
                index ++;\n
\n
            if (index < 1) {\n
                tokenRe.lastIndex = 0;\n
                 while ((ch = rightOfCursor[index]) && !tokenRe.test(ch)) {\n
                    tokenRe.lastIndex = 0;\n
                    index ++;\n
                    if (whitespaceRe.test(ch)) {\n
                        if (index > 2) {\n
                            index--\n
                            break;\n
                        } else {\n
                            while ((ch = rightOfCursor[index]) && whitespaceRe.test(ch))\n
                                index ++;\n
                            if (index > 2)\n
                                break\n
                        }\n
                    }\n
                }\n
            }\n
        }\n
        tokenRe.lastIndex = 0;\n
\n
        return index;\n
    };\n
\n
    this.moveCursorShortWordRight = function() {\n
        var row = this.lead.row;\n
        var column = this.lead.column;\n
        var line = this.doc.getLine(row);\n
        var rightOfCursor = line.substring(column);\n
\n
        var fold = this.session.getFoldAt(row, column, 1);\n
        if (fold)\n
            return this.moveCursorTo(fold.end.row, fold.end.column);\n
\n
        if (column == line.length) {\n
            var l = this.doc.getLength();\n
            do {\n
                row++;\n
                rightOfCursor = this.doc.getLine(row)\n
            } while (row < l && /^\\s*$/.test(rightOfCursor))\n
\n
            if (!/^\\s+/.test(rightOfCursor))\n
                rightOfCursor = ""\n
            column = 0;\n
        }\n
\n
        var index = this.$shortWordEndIndex(rightOfCursor);\n
\n
        this.moveCursorTo(row, column + index);\n
    };\n
\n
    this.moveCursorShortWordLeft = function() {\n
        var row = this.lead.row;\n
        var column = this.lead.column;\n
\n
        var fold;\n
        if (fold = this.session.getFoldAt(row, column, -1))\n
            return this.moveCursorTo(fold.start.row, fold.start.column);\n
\n
        var line = this.session.getLine(row).substring(0, column);\n
        if (column == 0) {\n
            do {\n
                row--;\n
                line = this.doc.getLine(row);\n
            } while (row > 0 && /^\\s*$/.test(line))\n
\n
            column = line.length;\n
            if (!/\\s+$/.test(line))\n
                line = ""\n
        }\n
\n
        var leftOfCursor = lang.stringReverse(line);\n
        var index = this.$shortWordEndIndex(leftOfCursor);\n
\n
        return this.moveCursorTo(row, column - index);\n
    };\n
\n
    this.moveCursorWordRight = function() {\n
        if (this.session.$selectLongWords)\n
            this.moveCursorLongWordRight();\n
        else\n
            this.moveCursorShortWordRight();\n
    };\n
\n
    this.moveCursorWordLeft = function() {\n
        if (this.session.$selectLongWords)\n
            this.moveCursorLongWordLeft();\n
        else\n
            this.moveCursorShortWordLeft();\n
    };\n
    this.moveCursorBy = function(rows, chars) {\n
        var screenPos = this.session.documentToScreenPosition(\n
            this.lead.row,\n
            this.lead.column\n
        );\n
\n
        if (chars === 0) {\n
            if (this.$desiredColumn)\n
                screenPos.column = this.$desiredColumn;\n
            else\n
                this.$desiredColumn = screenPos.column;\n
        }\n
\n
        var docPos = this.session.screenToDocumentPosition(screenPos.row + rows, screenPos.column);\n
        this.moveCursorTo(docPos.row, docPos.column + chars, chars === 0);\n
    };\n
    this.moveCursorToPosition = function(position) {\n
        this.moveCursorTo(position.row, position.column);\n
    };\n
    this.moveCursorTo = function(row, column, keepDesiredColumn) {\n
        var fold = this.session.getFoldAt(row, column, 1);\n
        if (fold) {\n
            row = fold.start.row;\n
            column = fold.start.column;\n
        }\n
\n
        this.$keepDesiredColumnOnChange = true;\n
        this.lead.setPosition(row, column);\n
        this.$keepDesiredColumnOnChange = false;\n
\n
        if (!keepDesiredColumn)\n
            this.$desiredColumn = null;\n
    };\n
    this.moveCursorToScreen = function(row, column, keepDesiredColumn) {\n
        var pos = this.session.screenToDocumentPosition(row, column);\n
        this.moveCursorTo(pos.row, pos.column, keepDesiredColumn);\n
    };\n
    this.detach = function() {\n
        this.lead.detach();\n
        this.anchor.detach();\n
        this.session = this.doc = null;\n
    }\n
\n
    this.fromOrientedRange = function(range) {\n
        this.setSelectionRange(range, range.cursor == range.start);\n
        this.$desiredColumn = range.desiredColumn || this.$desiredColumn;\n
    }\n
\n
    this.toOrientedRange = function(range) {\n
        var r = this.getRange();\n
        if (range) {\n
            range.start.column = r.start.column;\n
            range.start.row = r.start.row;\n
            range.end.column = r.end.column;\n
            range.end.row = r.end.row;\n
        } else {\n
            range = r;\n
        }\n
\n
        range.cursor = this.isBackwards() ? range.start : range.end;\n
        range.desiredColumn = this.$desiredColumn;\n
        return range;\n
    }\n
\n
    this.toJSON = function() {\n
        if (this.rangeCount) {\n
            var data = this.ranges.map(function(r) {\n
                var r1 = r.clone();\n
                r1.isBackwards = r.cursor == r.start;\n
                return r1;\n
            });\n
        } else {\n
            var data = this.getRange();\n
            data.isBackwards = this.isBackwards();\n
        }\n
        return data;\n
    };\n
\n
    this.fromJSON = function(data) {\n
        if (data.start == undefined) {\n
            if (this.rangeList) {\n
                this.toSingleRange(data[0]);\n
                for (var i = data.length; i--; ) {\n
                    var r = Range.fromPoints(data[i].start, data[i].end);\n
                    if (data.isBackwards)\n
                        r.cursor = r.start;\n
                    this.addRange(r, true);\n
                }\n
                return;\n
            } else\n
                data = data[0];\n
        }\n
        if (this.rangeList)\n
            this.toSingleRange(data);\n
        this.setSelectionRange(data, data.isBackwards);\n
    };\n
\n
    this.isEqual = function(data) {\n
        if ((data.length || this.rangeCount) && data.length != this.rangeCount)\n
            return false;\n
        if (!data.length || !this.ranges)\n
            return this.getRange().isEqual(data);\n
\n
        for (var i = this.ranges.length; i--; ) {\n
            if (!this.ranges[i].isEqual(data[i]))\n
                return false\n
        }\n
        return true;\n
    }\n
\n
}).call(Selection.prototype);\n
\n
exports.Selection = Selection;\n
});\n
\n
define(\'ace/range\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
var comparePoints = function(p1, p2) {\n
    return p1.row - p2.row || p1.column - p2.column;\n
};\n
var Range = function(startRow, startColumn, endRow, endColumn) {\n
    this.start = {\n
        row: startRow,\n
        column: startColumn\n
    };\n
\n
    this.end = {\n
        row: endRow,\n
        column: endColumn\n
    };\n
};\n
\n
(function() {\n
    this.isEqual = function(range) {\n
        return this.start.row === range.start.row &&\n
            this.end.row === range.end.row &&\n
            this.start.column === range.start.column &&\n
            this.end.column === range.end.column;\n
    };\n
    this.toString = function() {\n
        return ("Range: [" + this.start.row + "/" + this.start.column +\n
            "] -> [" + this.end.row + "/" + this.end.column + "]");\n
    };\n
\n
    this.contains = function(row, column) {\n
        return this.compare(row, column) == 0;\n
    };\n
    this.compareRange = function(range) {\n
        var cmp,\n
            end = range.end,\n
            start = range.start;\n
\n
        cmp = this.compare(end.row, end.column);\n
        if (cmp == 1) {\n
            cmp = this.compare(start.row, start.column);\n
            if (cmp == 1) {\n
                return 2;\n
            } else if (cmp == 0) {\n
                return 1;\n
            } else {\n
                return 0;\n
            }\n
        } else if (cmp == -1) {\n
            return -2;\n
        } else {\n
            cmp = this.compare(start.row, start.column);\n
            if (cmp == -1) {\n
                return -1;\n
            } else if (cmp == 1) {\n
                return 42;\n
            } else {\n
                return 0;\n
            }\n
        }\n
    };\n
    this.comparePoint = function(p) {\n
        return this.compare(p.row, p.column);\n
    };\n
    this.containsRange = function(range) {\n
        return this.comparePoint(range.start) == 0 && this.comparePoint(range.end) == 0;\n
    };\n
    this.intersects = function(range) {\n
        var cmp = this.compareRange(range);\n
        return (cmp == -1 || cmp == 0 || cmp == 1);\n
    };\n
    this.isEnd = function(row, column) {\n
        return this.end.row == row && this.end.column == column;\n
    };\n
    this.isStart = function(row, column) {\n
        return this.start.row == row && this.start.column == column;\n
    };\n
    this.setStart = function(row, column) {\n
        if (typeof row == "object") {\n
            this.start.column = row.column;\n
            this.start.row = row.row;\n
        } else {\n
            this.start.row = row;\n
            this.start.column = column;\n
        }\n
    };\n
    this.setEnd = function(row, column) {\n
        if (typeof row == "object") {\n
            this.end.column = row.column;\n
            this.end.row = row.row;\n
        } else {\n
            this.end.row = row;\n
            this.end.column = column;\n
        }\n
    };\n
    this.inside = function(row, column) {\n
        if (this.compare(row, column) == 0) {\n
            if (this.isEnd(row, column) || this.isStart(row, column)) {\n
                return false;\n
            } else {\n
                return true;\n
            }\n
        }\n
        return false;\n
    };\n
    this.insideStart = function(row, column) {\n
        if (this.compare(row, column) == 0) {\n
            if (this.isEnd(row, column)) {\n
                return false;\n
            } else {\n
                return true;\n
            }\n
        }\n
        return false;\n
    };\n
    this.insideEnd = function(row, column) {\n
        if (this.compare(row, column) == 0) {\n
            if (this.isStart(

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAU=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="5" aka="AAAAAAAAAAU=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

row, column)) {\n
                return false;\n
            } else {\n
                return true;\n
            }\n
        }\n
        return false;\n
    };\n
    this.compare = function(row, column) {\n
        if (!this.isMultiLine()) {\n
            if (row === this.start.row) {\n
                return column < this.start.column ? -1 : (column > this.end.column ? 1 : 0);\n
            };\n
        }\n
\n
        if (row < this.start.row)\n
            return -1;\n
\n
        if (row > this.end.row)\n
            return 1;\n
\n
        if (this.start.row === row)\n
            return column >= this.start.column ? 0 : -1;\n
\n
        if (this.end.row === row)\n
            return column <= this.end.column ? 0 : 1;\n
\n
        return 0;\n
    };\n
    this.compareStart = function(row, column) {\n
        if (this.start.row == row && this.start.column == column) {\n
            return -1;\n
        } else {\n
            return this.compare(row, column);\n
        }\n
    };\n
    this.compareEnd = function(row, column) {\n
        if (this.end.row == row && this.end.column == column) {\n
            return 1;\n
        } else {\n
            return this.compare(row, column);\n
        }\n
    };\n
    this.compareInside = function(row, column) {\n
        if (this.end.row == row && this.end.column == column) {\n
            return 1;\n
        } else if (this.start.row == row && this.start.column == column) {\n
            return -1;\n
        } else {\n
            return this.compare(row, column);\n
        }\n
    };\n
    this.clipRows = function(firstRow, lastRow) {\n
        if (this.end.row > lastRow)\n
            var end = {row: lastRow + 1, column: 0};\n
        else if (this.end.row < firstRow)\n
            var end = {row: firstRow, column: 0};\n
\n
        if (this.start.row > lastRow)\n
            var start = {row: lastRow + 1, column: 0};\n
        else if (this.start.row < firstRow)\n
            var start = {row: firstRow, column: 0};\n
\n
        return Range.fromPoints(start || this.start, end || this.end);\n
    };\n
    this.extend = function(row, column) {\n
        var cmp = this.compare(row, column);\n
\n
        if (cmp == 0)\n
            return this;\n
        else if (cmp == -1)\n
            var start = {row: row, column: column};\n
        else\n
            var end = {row: row, column: column};\n
\n
        return Range.fromPoints(start || this.start, end || this.end);\n
    };\n
\n
    this.isEmpty = function() {\n
        return (this.start.row === this.end.row && this.start.column === this.end.column);\n
    };\n
    this.isMultiLine = function() {\n
        return (this.start.row !== this.end.row);\n
    };\n
    this.clone = function() {\n
        return Range.fromPoints(this.start, this.end);\n
    };\n
    this.collapseRows = function() {\n
        if (this.end.column == 0)\n
            return new Range(this.start.row, 0, Math.max(this.start.row, this.end.row-1), 0)\n
        else\n
            return new Range(this.start.row, 0, this.end.row, 0)\n
    };\n
    this.toScreenRange = function(session) {\n
        var screenPosStart = session.documentToScreenPosition(this.start);\n
        var screenPosEnd = session.documentToScreenPosition(this.end);\n
\n
        return new Range(\n
            screenPosStart.row, screenPosStart.column,\n
            screenPosEnd.row, screenPosEnd.column\n
        );\n
    };\n
    this.moveBy = function(row, column) {\n
        this.start.row += row;\n
        this.start.column += column;\n
        this.end.row += row;\n
        this.end.column += column;\n
    };\n
\n
}).call(Range.prototype);\n
Range.fromPoints = function(start, end) {\n
    return new Range(start.row, start.column, end.row, end.column);\n
};\n
Range.comparePoints = comparePoints;\n
\n
Range.comparePoints = function(p1, p2) {\n
    return p1.row - p2.row || p1.column - p2.column;\n
};\n
\n
\n
exports.Range = Range;\n
});\n
\n
define(\'ace/mode/text\', [\'require\', \'exports\', \'module\' , \'ace/tokenizer\', \'ace/mode/text_highlight_rules\', \'ace/mode/behaviour\', \'ace/unicode\', \'ace/lib/lang\', \'ace/token_iterator\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var Tokenizer = require("../tokenizer").Tokenizer;\n
var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;\n
var Behaviour = require("./behaviour").Behaviour;\n
var unicode = require("../unicode");\n
var lang = require("../lib/lang");\n
var TokenIterator = require("../token_iterator").TokenIterator;\n
var Range = require("../range").Range;\n
\n
var Mode = function() {\n
    this.HighlightRules = TextHighlightRules;\n
    this.$behaviour = new Behaviour();\n
};\n
\n
(function() {\n
\n
    this.tokenRe = new RegExp("^["\n
        + unicode.packages.L\n
        + unicode.packages.Mn + unicode.packages.Mc\n
        + unicode.packages.Nd\n
        + unicode.packages.Pc + "\\\\$_]+", "g"\n
    );\n
\n
    this.nonTokenRe = new RegExp("^(?:[^"\n
        + unicode.packages.L\n
        + unicode.packages.Mn + unicode.packages.Mc\n
        + unicode.packages.Nd\n
        + unicode.packages.Pc + "\\\\$_]|\\s])+", "g"\n
    );\n
\n
    this.getTokenizer = function() {\n
        if (!this.$tokenizer) {\n
            this.$highlightRules = new this.HighlightRules();\n
            this.$tokenizer = new Tokenizer(this.$highlightRules.getRules());\n
        }\n
        return this.$tokenizer;\n
    };\n
\n
    this.lineCommentStart = "";\n
    this.blockComment = "";\n
\n
    this.toggleCommentLines = function(state, session, startRow, endRow) {\n
        var doc = session.doc;\n
\n
        var ignoreBlankLines = true;\n
        var shouldRemove = true;\n
        var minIndent = Infinity;\n
        var tabSize = session.getTabSize();\n
        var insertAtTabStop = false;\n
\n
        if (!this.lineCommentStart) {\n
            if (!this.blockComment)\n
                return false;\n
            var lineCommentStart = this.blockComment.start;\n
            var lineCommentEnd = this.blockComment.end;\n
            var regexpStart = new RegExp("^(\\\\s*)(?:" + lang.escapeRegExp(lineCommentStart) + ")");\n
            var regexpEnd = new RegExp("(?:" + lang.escapeRegExp(lineCommentEnd) + ")\\\\s*$");\n
\n
            var comment = function(line, i) {\n
                if (testRemove(line, i))\n
                    return;\n
                if (!ignoreBlankLines || /\\S/.test(line)) {\n
                    doc.insertInLine({row: i, column: line.length}, lineCommentEnd);\n
                    doc.insertInLine({row: i, column: minIndent}, lineCommentStart);\n
                }\n
            };\n
\n
            var uncomment = function(line, i) {\n
                var m;\n
                if (m = line.match(regexpEnd))\n
                    doc.removeInLine(i, line.length - m[0].length, line.length);\n
                if (m = line.match(regexpStart))\n
                    doc.removeInLine(i, m[1].length, m[0].length);\n
            };\n
\n
            var testRemove = function(line, row) {\n
                if (regexpStart.test(line))\n
                    return true;\n
                var tokens = session.getTokens(row);\n
                for (var i = 0; i < tokens.length; i++) {\n
                    if (tokens[i].type === \'comment\')\n
                        return true;\n
                }\n
            };\n
        } else {\n
            if (Array.isArray(this.lineCommentStart)) {\n
                var regexpStart = this.lineCommentStart.map(lang.escapeRegExp).join("|");\n
                var lineCommentStart = this.lineCommentStart[0];\n
            } else {\n
                var regexpStart = lang.escapeRegExp(this.lineCommentStart);\n
                var lineCommentStart = this.lineCommentStart;\n
            }\n
            regexpStart = new RegExp("^(\\\\s*)(?:" + regexpStart + ") ?");\n
            \n
            insertAtTabStop = session.getUseSoftTabs();\n
\n
            var uncomment = function(line, i) {\n
                var m = line.match(regexpStart);\n
                if (!m) return;\n
                var start = m[1].length, end = m[0].length;\n
                if (!shouldInsertSpace(line, start, end) && m[0][end - 1] == " ")\n
                    end--;\n
                doc.removeInLine(i, start, end);\n
            };\n
            var commentWithSpace = lineCommentStart + " ";\n
            var comment = function(line, i) {\n
                if (!ignoreBlankLines || /\\S/.test(line)) {\n
                    if (shouldInsertSpace(line, minIndent, minIndent))\n
                        doc.insertInLine({row: i, column: minIndent}, commentWithSpace);\n
                    else\n
                        doc.insertInLine({row: i, column: minIndent}, lineCommentStart);\n
                }\n
            };\n
            var testRemove = function(line, i) {\n
                return regexpStart.test(line);\n
            };\n
            \n
            var shouldInsertSpace = function(line, before, after) {\n
                var spaces = 0;\n
                while (before-- && line.charAt(before) == " ")\n
                    spaces++;\n
                if (spaces % tabSize != 0)\n
                    return false;\n
                var spaces = 0;\n
                while (line.charAt(after++) == " ")\n
                    spaces++;\n
                if (tabSize > 2)\n
                    return spaces % tabSize != tabSize - 1;\n
                else\n
                    return spaces % tabSize == 0;\n
                return true;\n
            };\n
        }\n
\n
        function iter(fun) {\n
            for (var i = startRow; i <= endRow; i++)\n
                fun(doc.getLine(i), i);\n
        }\n
\n
\n
        var minEmptyLength = Infinity;\n
        iter(function(line, i) {\n
            var indent = line.search(/\\S/);\n
            if (indent !== -1) {\n
                if (indent < minIndent)\n
                    minIndent = indent;\n
                if (shouldRemove && !testRemove(line, i))\n
                    shouldRemove = false;\n
            } else if (minEmptyLength > line.length) {\n
                minEmptyLength = line.length;\n
            }\n
        });\n
\n
        if (minIndent == Infinity) {\n
            minIndent = minEmptyLength;\n
            ignoreBlankLines = false;\n
            shouldRemove = false;\n
        }\n
\n
        if (insertAtTabStop && minIndent % tabSize != 0)\n
            minIndent = Math.floor(minIndent / tabSize) * tabSize;\n
\n
        iter(shouldRemove ? uncomment : comment);\n
    };\n
\n
    this.toggleBlockComment = function(state, session, range, cursor) {\n
        var comment = this.blockComment;\n
        if (!comment)\n
            return;\n
        if (!comment.start && comment[0])\n
            comment = comment[0];\n
\n
        var iterator = new TokenIterator(session, cursor.row, cursor.column);\n
        var token = iterator.getCurrentToken();\n
\n
        var sel = session.selection;\n
        var initialRange = session.selection.toOrientedRange();\n
        var startRow, colDiff;\n
\n
        if (token && /comment/.test(token.type)) {\n
            var startRange, endRange;\n
            while (token && /comment/.test(token.type)) {\n
                var i = token.value.indexOf(comment.start);\n
                if (i != -1) {\n
                    var row = iterator.getCurrentTokenRow();\n
                    var column = iterator.getCurrentTokenColumn() + i;\n
                    startRange = new Range(row, column, row, column + comment.start.length);\n
                    break\n
                }\n
                token = iterator.stepBackward();\n
            };\n
\n
            var iterator = new TokenIterator(session, cursor.row, cursor.column);\n
            var token = iterator.getCurrentToken();\n
            while (token && /comment/.test(token.type)) {\n
                var i = token.value.indexOf(comment.end);\n
                if (i != -1) {\n
                    var row = iterator.getCurrentTokenRow();\n
                    var column = iterator.getCurrentTokenColumn() + i;\n
                    endRange = new Range(row, column, row, column + comment.end.length);\n
                    break;\n
                }\n
                token = iterator.stepForward();\n
            }\n
            if (endRange)\n
                session.remove(endRange);\n
            if (startRange) {\n
                session.remove(startRange);\n
                startRow = startRange.start.row;\n
                colDiff = -comment.start.length\n
            }\n
        } else {\n
            colDiff = comment.start.length\n
            startRow = range.start.row;\n
            session.insert(range.end, comment.end);\n
            session.insert(range.start, comment.start);\n
        }\n
        if (initialRange.start.row == startRow)\n
            initialRange.start.column += colDiff;\n
        if (initialRange.end.row == startRow)\n
            initialRange.end.column += colDiff;\n
        session.selection.fromOrientedRange(initialRange);\n
    };\n
\n
    this.getNextLineIndent = function(state, line, tab) {\n
        return this.$getIndent(line);\n
    };\n
\n
    this.checkOutdent = function(state, line, input) {\n
        return false;\n
    };\n
\n
    this.autoOutdent = function(state, doc, row) {\n
    };\n
\n
    this.$getIndent = function(line) {\n
        return line.match(/^\\s*/)[0];\n
    };\n
\n
    this.createWorker = function(session) {\n
        return null;\n
    };\n
\n
    this.createModeDelegates = function (mapping) {\n
        this.$embeds = [];\n
        this.$modes = {};\n
        for (var i in mapping) {\n
            if (mapping[i]) {\n
                this.$embeds.push(i);\n
                this.$modes[i] = new mapping[i]();\n
            }\n
        }\n
\n
        var delegations = [\'toggleCommentLines\', \'getNextLineIndent\', \'checkOutdent\', \'autoOutdent\', \'transformAction\', \'getCompletions\'];\n
\n
        for (var i = 0; i < delegations.length; i++) {\n
            (function(scope) {\n
              var functionName = delegations[i];\n
              var defaultHandler = scope[functionName];\n
              scope[delegations[i]] = function() {\n
                  return this.$delegator(functionName, arguments, defaultHandler);\n
              }\n
            } (this));\n
        }\n
    };\n
\n
    this.$delegator = function(method, args, defaultHandler) {\n
        var state = args[0];\n
        if (typeof state != "string")\n
            state = state[0];\n
        for (var i = 0; i < this.$embeds.length; i++) {\n
            if (!this.$modes[this.$embeds[i]]) continue;\n
\n
            var split = state.split(this.$embeds[i]);\n
            if (!split[0] && split[1]) {\n
                args[0] = split[1];\n
                var mode = this.$modes[this.$embeds[i]];\n
                return mode[method].apply(mode, args);\n
            }\n
        }\n
        var ret = defaultHandler.apply(this, args);\n
        return defaultHandler ? ret : undefined;\n
    };\n
\n
    this.transformAction = function(state, action, editor, session, param) {\n
        if (this.$behaviour) {\n
            var behaviours = this.$behaviour.getBehaviours();\n
            for (var key in behaviours) {\n
                if (behaviours[key][action]) {\n
                    var ret = behaviours[key][action].apply(this, arguments);\n
                    if (ret) {\n
                        return ret;\n
                    }\n
                }\n
            }\n
        }\n
    };\n
    \n
    this.getKeywords = function(append) {\n
        if (!this.completionKeywords) {\n
            var rules = this.$tokenizer.rules;\n
            var completionKeywords = [];\n
            for (var rule in rules) {\n
                var ruleItr = rules[rule];\n
                for (var r = 0, l = ruleItr.length; r < l; r++) {\n
                    if (typeof ruleItr[r].token === "string") {\n
                        if (/keyword|support|storage/.test(ruleItr[r].token))\n
                            completionKeywords.push(ruleItr[r].regex);\n
                    }\n
                    else if (typeof ruleItr[r].token === "object") {\n
                        for (var a = 0, aLength = ruleItr[r].token.length; a < aLength; a++) {    \n
                            if (/keyword|support|storage/.test(ruleItr[r].token[a])) {\n
                                var rule = ruleItr[r].regex.match(/\\(.+?\\)/g)[a];\n
                                completionKeywords.push(rule.substr(1, rule.length - 2));\n
                            }\n
                        }\n
                    }\n
                }\n
            }\n
            this.completionKeywords = completionKeywords;\n
        }\n
        if (!append)\n
            return this.$keywordList;\n
        return completionKeywords.concat(this.$keywordList || []);\n
    };\n
    \n
    this.$createKeywordList = function() {\n
        if (!this.$highlightRules)\n
            this.getTokenizer();\n
        return this.$keywordList = this.$highlightRules.$keywordList || [];\n
    }\n
\n
    this.getCompletions = function(state, session, pos, prefix) {\n
        var keywords = this.$keywordList || this.$createKeywordList();\n
        return keywords.map(function(word) {\n
            return {\n
                name: word,\n
                value: word,\n
                score: 0,\n
                meta: "keyword"\n
            };\n
        });\n
    };\n
\n
}).call(Mode.prototype);\n
\n
exports.Mode = Mode;\n
});\n
\n
define(\'ace/tokenizer\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
var MAX_TOKEN_COUNT = 1000;\n
var Tokenizer = function(rules) {\n
    this.states = rules;\n
\n
    this.regExps = {};\n
    this.matchMappings = {};\n
    for (var key in this.states) {\n
        var state = this.states[key];\n
        var ruleRegExps = [];\n
        var matchTotal = 0;\n
        var mapping = this.matchMappings[key] = {defaultToken: "text"};\n
        var flag = "g";\n
\n
        var splitterRurles = [];\n
        for (var i = 0; i < state.length; i++) {\n
            var rule = state[i];\n
            if (rule.defaultToken)\n
                mapping.defaultToken = rule.defaultToken;\n
            if (rule.caseInsensitive)\n
                flag = "gi";\n
            if (rule.regex == null)\n
                continue;\n
\n
            if (rule.regex instanceof RegExp)\n
                rule.regex = rule.regex.toString().slice(1, -1);\n
            var adjustedregex = rule.regex;\n
            var matchcount = new RegExp("(?:(" + adjustedregex + ")|(.))").exec("a").length - 2;\n
            if (Array.isArray(rule.token)) {\n
                if (rule.token.length == 1 || matchcount == 1) {\n
                    rule.token = rule.token[0];\n
                } else if (matchcount - 1 != rule.token.length) {\n
                    throw new Error("number of classes and regexp groups in \'" + \n
                        rule.token + "\'\\n\'" + rule.regex +  "\' doesn\'t match\\n"\n
                        + (matchcount - 1) + "!=" + rule.token.length);\n
                } else {\n
                    rule.tokenArray = rule.token;\n
                    rule.token = null;\n
                    rule.onMatch = this.$arrayTokens;\n
                }\n
            } else if (typeof rule.token == "function" && !rule.onMatch) {\n
                if (matchcount > 1)\n
                    rule.onMatch = this.$applyToken;\n
                else\n
                    rule.onMatch = rule.token;\n
            }\n
\n
            if (matchcount > 1) {\n
                if (/\\\\\\d/.test(rule.regex)) {\n
                    adjustedregex = rule.regex.replace(/\\\\([0-9]+)/g, function (match, digit) {\n
                        return "\\\\" + (parseInt(digit, 10) + matchTotal + 1);\n
                    });\n
                } else {\n
                    matchcount = 1;\n
                    adjustedregex = this.removeCapturingGroups(rule.regex);\n
                }\n
                if (!rule.splitRegex && typeof rule.token != "string")\n
                    splitterRurles.push(rule); // flag will be known only at the very end\n
            }\n
\n
            mapping[matchTotal] = i;\n
            matchTotal += matchcount;\n
\n
            ruleRegExps.push(adjustedregex);\n
            if (!rule.onMatch)\n
                rule.onMatch = null;\n
            rule.__proto__ = null;\n
        }\n
        \n
        splitterRurles.forEach(function(rule) {\n
            rule.splitRegex = this.createSplitterRegexp(rule.regex, flag);\n
        }, this);\n
\n
        this.regExps[key] = new RegExp("(" + ruleRegExps.join(")|(") + ")|($)", flag);\n
    }\n
};\n
\n
(function() {\n
    this.$setMaxTokenCount = function(m) {\n
        MAX_TOKEN_COUNT = m | 0;\n
    };\n
    \n
    this.$applyToken = function(str) {\n
        var values = this.splitRegex.exec(str).slice(1);\n
        var types = this.token.apply(this, values);\n
        if (typeof types === "string")\n
            return [{type: types, value: str}];\n
\n
        var tokens = [];\n
        for (var i = 0, l = types.length; i < l; i++) {\n
            if (values[i])\n
                tokens[tokens.length] = {\n
                    type: types[i],\n
                    value: values[i]\n
                };\n
        }\n
        return tokens;\n
    },\n
\n
    this.$arrayTokens = function(str) {\n
        if (!str)\n
            return [];\n
        var values = this.splitRegex.exec(str);\n
        if (!values)\n
            return "text";\n
        var tokens = [];\n
        var types = this.tokenArray;\n
        for (var i = 0, l = types.length; i < l; i++) {\n
            if (values[i + 1])\n
                tokens[tokens.length] = {\n
                    type: types[i],\n
                    value: values[i + 1]\n
                };\n
        }\n
        return tokens;\n
    };\n
\n
    this.removeCapturingGroups = function(src) {\n
        var r = src.replace(\n
            /\\[(?:\\\\.|[^\\]])*?\\]|\\\\.|\\(\\?[:=!]|(\\()/g,\n
            function(x, y) {return y ? "(?:" : x;}\n
        );\n
        return r;\n
    };\n
\n
    this.createSplitterRegexp = function(src, flag) {\n
        if (src.indexOf("(?=") != -1) {\n
            var stack = 0;\n
            var inChClass = false;\n
            var lastCapture = {};\n
            src.replace(/(\\\\.)|(\\((?:\\?[=!])?)|(\\))|([\\[\\]])/g, function(\n
                m, esc, parenOpen, parenClose, square, index\n
            ) {\n
                if (inChClass) {\n
                    inChClass = square != "]";\n
                } else if (square) {\n
                    inChClass = true;\n
                } else if (parenClose) {\n
                    if (stack == lastCapture.stack) {\n
                        lastCapture.end = index+1;\n
                        lastCapture.stack = -1;\n
                    }\n
                    stack--;\n
                } else if (parenOpen) {\n
                    stack++;\n
                    if (parenOpen.length != 1) {\n
                        lastCapture.stack = stack\n
                        lastCapture.start = index;\n
                    }\n
                }\n
                return m;\n
            });\n
\n
            if (lastCapture.end != null && /^\\)*$/.test(src.substr(lastCapture.end)))\n
                src = src.substring(0, lastCapture.start) + src.substr(lastCapture.end);\n
        }\n
        return new RegExp(src, (flag||"").replace("g", ""));\n
    };\n
    this.getLineTokens = function(line, startState) {\n
        if (startState && typeof startState != "string") {\n
            var stack = startState.slice(0);\n
            startState = stack[0];\n
        } else\n
            var stack = [];\n
\n
        var currentState = startState || "start";\n
        var state = this.states[currentState];\n
        var mapping = this.matchMappings[currentState];\n
        var re = this.regExps[currentState];\n
        re.lastIndex = 0;\n
\n
        var match, tokens = [];\n
        var lastIndex = 0;\n
\n
        var token = {type: null, value: ""};\n
\n
        while (match = re.exec(line)) {\n
            var type = mapping.defaultToken;\n
            var rule = null;\n
            var value = match[0];\n
            var index = re.lastIndex;\n
\n
            if (index - value.length > lastIndex) {\n
                var skipped = line.substring(lastIndex, index - value.length);\n
                if (token.type == type) {\n
                    token.value += skipped;\n
                } else {\n
                    if (token.type)\n
                        tokens.push(token);\n
                    token = {type: type, value: skipped};\n
                }\n
            }\n
\n
            for (var i = 0; i < match.length-2; i++) {\n
                if (match[i + 1] === undefined)\n
                    continue;\n
\n
                rule = state[mapping[i]];\n
\n
                if (rule.onMatch)\n
                    type = rule.onMatch(value, currentState, stack);\n
                else\n
                    type = rule.token;\n
\n
                if (rule.next) {\n
                    if (typeof rule.next == "string")\n
                        currentState = rule.next;\n
                    else\n
                        currentState = rule.next(currentState, stack);\n
\n
                    state = this.states[currentState];\n
                    if (!state) {\n
                        window.console && console.error && console.error(currentState, "doesn\'t exist");\n
                        currentState = "start";\n
                        state = this.states[currentState];\n
                    }\n
                    mapping = this.matchMappings[currentState];\n
                    lastIndex = index;\n
                    re = this.regExps[currentState];\n
                    re.lastIndex = index;\n
                }\n
                break;\n
            }\n
\n
            if (value) {\n
                if (typeof type == "string") {\n
                    if ((!rule || rule.merge !== false) && token.type === type) {\n
                        token.value += value;\n
                    } else {\n
                        if (token.type)\n
                            tokens.push(token);\n
                        token = {type: type, value: value};\n
                    }\n
                } else if (type) {\n
                    if (token.type)\n
                        tokens.push(token);\n
                    token = {type: null, value: ""};\n
                    for (var i = 0; i < type.length; i++)\n
                        tokens.push(type[i]);\n
                }\n
            }\n
\n
            if (lastIndex == line.length)\n
                break;\n
\n
            lastIndex = index;\n
\n
            if (tokens.length > MAX_TOKEN_COUNT) {\n
                while (lastIndex < line.length) {\n
                    if (token.type)\n
                        tokens.push(token);\n
                    token = {\n
                        value: line.substring(lastIndex, lastIndex += 2000),\n
                        type: "overflow"\n
                    }    \n
                }\n
                currentState = "start";\n
                stack = [];\n
                break;\n
            }\n
        }\n
\n
        if (token.type)\n
            tokens.push(token);\n
\n
        return {\n
            tokens : tokens,\n
            state : stack.length ? stack : currentState\n
        };\n
    };\n
\n
}).call(Tokenizer.prototype);\n
\n
exports.Tokenizer = Tokenizer;\n
});\n
\n
define(\'ace/mode/text_highlight_rules\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\'], function(require, exports, module) {\n
\n
\n
var lang = require("../lib/lang");\n
\n
var TextHighlightRules = function() {\n
\n
    this.$rules = {\n
        "start" : [{\n
            token : "empty_line",\n
            regex : \'^$\'\n
        }, {\n
            defaultToken : "text"\n
        }]\n
    };\n
};\n
\n
(function() {\n
\n
    this.addRules = function(rules, prefix) {\n
        if (!prefix) {\n
            for (var key in rules)\n
                this.$rules[key] = rules[key];\n
            return;\n
        }\n
        for (var key in rules) {\n
            var state = rules[key];\n
            for (var i = 0; i < state.length; i++) {\n
                var rule = state[i];\n
                if (rule.next) {\n
                    if (typeof rule.next != "string") {\n
                        if (rule.nextState && rule.nextState.indexOf(prefix) !== 0)\n
                            rule.nextState = prefix + rule.nextState;\n
                    } else {\n
                        if (rule.next.indexOf(prefix) !== 0)\n
                            rule.next = prefix + rule.next;\n
                    }\n
\n
                }\n
            }\n
            this.$rules[prefix + key] = state;\n
        }\n
    };\n
\n
    this.getRules = function() {\n
        return this.$rules;\n
    };\n
\n
    this.embedRules = function (HighlightRules, prefix, escapeRules, states, append) {\n
        var embedRules = new HighlightRules().getRules();\n
        if (states) {\n
            for (var i = 0; i < states.length; i++)\n
                states[i] = prefix + states[i];\n
        } else {\n
            states = [];\n
            for (var key in embedRules)\n
                states.push(prefix + key);\n
        }\n
\n
        this.addRules(embedRules, prefix);\n
\n
        if (escapeRules) {\n
            var addRules = Array.prototype[append ? "push" : "unshift"];\n
            for (var i = 0; i < states.length; i++)\n
                addRules.apply(this.$rules[states[i]], lang.deepCopy(escapeRules));\n
        }\n
\n
        if (!this.$embeds)\n
            this.$embeds = [];\n
        this.$embeds.push(prefix);\n
    };\n
\n
    this.getEmbeds = function() {\n
        return this.$embeds;\n
    };\n
\n
    var pushState = function(currentState, stack) {\n
        if (currentState != "start")\n
            stack.unshift(this.nextState, currentState);\n
        return this.nextState;\n
    };\n
    var popState = function(currentState, stack) {\n
        if (stack[0] !== currentState)\n
            return "start";\n
        stack.shift();\n
        return stack.shift();\n
    };\n
\n
    this.normalizeRules = function() {\n
        var id = 0;\n
        var rules = this.$rules;\n
        function processState(key) {\n
            var state = rules[key];\n
            state.processed = true;\n
            for (var i = 0; i < state.length; i++) {\n
                var rule = state[i];\n
                if (!rule.regex && rule.start) {\n
                    rule.regex = rule.start;\n
                    if (!rule.next)\n
                        rule.next = [];\n
                    rule.next.push({\n
                        defaultToken: rule.token\n
                    }, {\n
                        token: rule.token + ".end",\n
                        regex: rule.end || rule.start,\n
                        next: "pop"\n
                    });\n
                    rule.token = rule.token + ".start";\n
                    rule.push = true;\n
                }\n
                var next = rule.next || rule.push;\n
                if (next && Array.isArray(next)) {\n
                    var stateName = rule.stateName;\n
                    if (!stateName)  {\n
                        stateName = rule.token;\n
                        if (typeof stateName != "string")\n
                            stateName = stateName[0] || "";\n
                        if (rules[stateName])\n
                            stateName += id++;\n
                    }\n
                    rules[stateName] = next;\n
                    rule.next = stateName;\n
                    processState(stateName);\n
                } else if (next == "pop") {\n
                    rule.next = popState;\n
                }\n
\n
                if (rule.push) {\n
                    rule.nextState = rule.next || rule.push;\n
                    rule.next = pushState;\n
                    delete rule.push;\n
                }\n
\n
                if (rule.rules) {\n
                    for (var r in rule.rules) {\n
                        if (rules[r]) {\n
                            if (rules[r].push)\n
                                rules[r].push.apply(rules[r], rule.rules[r]);\n
                        } else {\n
                            rules[r] = rule.rules[r];\n
                        }\n
                    }\n
                }\n
                if (rule.include || typeof rule == "string") {\n
                    var includeName = rule.include || rule;\n
                    var toInsert = rules[includeName];\n
                } else if (Array.isArray(rule))\n
                    toInsert = rule;\n
\n
                if (toInsert) {\n
                    var args = [i, 1].concat(toInsert);\n
                    if (rule.noEscape)\n
                        args = args.filter(function(x) {return !x.next;});\n
                    state.splice.apply(state, args);\n
                    i--;\n
                    toInsert = null\n
                }\n
                \n
                if (rule.keywordMap) {\n
                    rule.token = this.createKeywordMapper(\n
                        rule.keywordMap, rule.defaultToken || "text", rule.caseInsensitive\n
                    );\n
                    delete rule.defaultToken;\n
                }\n
            }\n
        };\n
        Object.keys(rules).forEach(processState, this);\n
    };\n
\n
    this.createKeywordMapper = function(map, defaultToken, ignoreCase, splitChar) {\n
        var keywords = Object.create(null);\n
        Object.keys(map).forEach(function(className) {\n
            var a = map[className];\n
            if (ignoreCase)\n
                a = a.toLowerCase();\n
            var list = a.split(splitChar || "|");\n
            for (var i = list.length; i--; )\n
                keywords[list[i]] = className;\n
        });\n
        if (Object.getPrototypeOf(keywords)) {\n
            keywords.__proto__ = null;\n
        }\n
        this.$keywordList = Object.keys(keywords);\n
        map = null;\n
        return ignoreCase\n
            ? function(value) {return keywords[value.toLowerCase()] || defaultToken }\n
            : function(value) {return keywords[value] || defaultToken };\n
    }\n
\n
    this.getKeywords = function() {\n
        return this.$keywords;\n
    };\n
\n
}).call(TextHighlightRules.prototype);\n
\n
exports.TextHighlightRules = TextHighlightRules;\n
});\n
\n
define(\'ace/mode/behaviour\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
\n
var Behaviour = function() {\n
   this.$behaviours = {};\n
};\n
\n
(function () {\n
\n
    this.add = function (name, action, callback) {\n
        switch (undefined) {\n
          case this.$behaviours:\n
              this.$behaviours = {};\n
          case this.$behaviours[name]:\n
              this.$behaviours[name] = {};\n
        }\n
        this.$behaviours[name][action] = callback;\n
    }\n
    \n
    this.addBehaviours = function (behaviours) {\n
        for (var key in behaviours) {\n
            for (var action in behaviours[key]) {\n
                this.add(key, action, behaviours[key][action]);\n
            }\n
        }\n
    }\n
    \n
    this.remove = function (name) {\n
        if (this.$behaviours && this.$behaviours[name]) {\n
            delete this.$behaviours[name];\n
        }\n
    }\n
    \n
    this.inherit = function (mode, filter) {\n
        if (typeof mode === "function") {\n
            var behaviours = new mode().getBehaviours(filter);\n
        } else {\n
            var behaviours = mode.getBehaviours(filter);\n
        }\n
        this.addBehaviours(behaviours);\n
    }\n
    \n
    this.getBehaviours = function (filter) {\n
        if (!filter) {\n
            return this.$behaviours;\n
        } else {\n
            var ret = {}\n
            for (var i = 0; i < filter.length; i++) {\n
                if (this.$behaviours[filter[i]]) {\n
                    ret[filter[i]] = this.$behaviours[filter[i]];\n
                }\n
            }\n
            return ret;\n
        }\n
    }\n
\n
}).call(Behaviour.prototype);\n
\n
exports.Behaviour = Behaviour;\n
});\n
define(\'ace/unicode\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
exports.packages = {};\n
\n
addUnicodePackage({\n
    L:  "0041-005A0061-007A00AA00B500BA00C0-00D600D8-00F600F8-02C102C6-02D102E0-02E402EC02EE0370-037403760377037A-037D03860388-038A038C038E-03A103A3-03F503F7-0481048A-05250531-055605590561-058705D0-05EA05F0-05F20621-064A066E066F0671-06D306D506E506E606EE06EF06FA-06FC06FF07100712-072F074D-07A507B107CA-07EA07F407F507FA0800-0815081A082408280904-0939093D09500958-0961097109720979-097F0985-098C098F09900993-09A809AA-09B009B209B6-09B909BD09CE09DC09DD09DF-09E109F009F10A05-0A0A0A0F0A100A13-0A280A2A-0A300A320A330A350A360A380A390A59-0A5C0A5E0A72-0A740A85-0A8D0A8F-0A910A93-0AA80AAA-0AB00AB20AB30AB5-0AB90ABD0AD00AE00AE10B05-0B0C0B0F0B100B13-0B280B2A-0B300B320B330B35-0B390B3D0B5C0B5D0B5F-0B610B710B830B85-0B8A0B8E-0B900B92-0B950B990B9A0B9C0B9E0B9F0BA30BA40BA8-0BAA0BAE-0BB90BD00C05-0C0C0C0E-0C100C12-0C280C2A-0C330C35-0C390C3D0C580C590C600C610C85-0C8C0C8E-0C900C92-0CA80CAA-0CB30CB5-0CB90CBD0CDE0CE00CE10D05-0D0C0D0E-0D100D12-0D280D2A-0D390D3D0D600D610D7A-0D7F0D85-0D960D9A-0DB10DB3-0DBB0DBD0DC0-0DC60E01-0E300E320E330E40-0E460E810E820E840E870E880E8A0E8D0E94-0E970E99-0E9F0EA1-0EA30EA50EA70EAA0EAB0EAD-0EB00EB20EB30EBD0EC0-0EC40EC60EDC0EDD0F000F40-0F470F49-0F6C0F88-0F8B1000-102A103F1050-1055105A-105D106110651066106E-10701075-1081108E10A0-10C510D0-10FA10FC1100-1248124A-124D1250-12561258125A-125D1260-1288128A-128D1290-12B012B2-12B512B8-12BE12C012C2-12C512C8-12D612D8-13101312-13151318-135A1380-138F13A0-13F41401-166C166F-167F1681-169A16A0-16EA1700-170C170E-17111720-17311740-17511760-176C176E-17701780-17B317D717DC1820-18771880-18A818AA18B0-18F51900-191C1950-196D1970-19741980-19AB19C1-19C71A00-1A161A20-1A541AA71B05-1B331B45-1B4B1B83-1BA01BAE1BAF1C00-1C231C4D-1C4F1C5A-1C7D1CE9-1CEC1CEE-1CF11D00-1DBF1E00-1F151F18-1F1D1F20-1F451F48-1F4D1F50-1F571F591F5B1F5D1F5F-1F7D1F80-1FB41FB6-1FBC1FBE1FC2-1FC41FC6-1FCC1FD0-1FD31FD6-1FDB1FE0-1FEC1FF2-1FF41FF6-1FFC2071207F2090-209421022107210A-211321152119-211D212421262128212A-212D212F-2139213C-213F2145-2149214E218321842C00-2C2E2C30-2C5E2C60-2CE42CEB-2CEE2D00-2D252D30-2D652D6F2D80-2D962DA0-2DA62DA8-2DAE2DB0-2DB62DB8-2DBE2DC0-2DC62DC8-2DCE2DD0-2DD62DD8-2DDE2E2F300530063031-3035303B303C3041-3096309D-309F30A1-30FA30FC-30FF3105-312D3131-318E31A0-31B731F0-31FF3400-4DB54E00-9FCBA000-A48CA4D0-A4FDA500-A60CA610-A61FA62AA62BA640-A65FA662-A66EA67F-A697A6A0-A6E5A717-A71FA722-A788A78BA78CA7FB-A801A803-A805A807-A80AA80C-A822A840-A873A882-A8B3A8F2-A8F7A8FBA90A-A925A930-A946A960-A97CA984-A9B2A9CFAA00-AA28AA40-AA42AA44-AA4BAA60-AA76AA7AAA80-AAAFAAB1AAB5AAB6AAB9-AABDAAC0AAC2AADB-AADDABC0-ABE2AC00-D7A3D7B0-D7C6D7CB-D7FBF900-FA2DFA30-FA6DFA70-FAD9FB00-FB06FB13-FB17FB1DFB1F-FB28FB2A-FB36FB38-FB3CFB3EFB40FB41FB43FB44FB46-FBB1FBD3-FD3DFD50-FD8FFD92-FDC7FDF0-FDFBFE70-FE74FE76-FEFCFF21-FF3AFF41-FF5AFF66-FFBEFFC2-FFC7FFCA-FFCFFFD2-FFD7FFDA-FFDC",\n
    Ll: "0061-007A00AA00B500BA00DF-00F600F8-00FF01010103010501070109010B010D010F01110113011501170119011B011D011F01210123012501270129012B012D012F01310133013501370138013A013C013E014001420144014601480149014B014D014F01510153015501570159015B015D015F01610163016501670169016B016D016F0171017301750177017A017C017E-0180018301850188018C018D019201950199-019B019E01A101A301A501A801AA01AB01AD01B001B401B601B901BA01BD-01BF01C601C901CC01CE01D001D201D401D601D801DA01DC01DD01DF01E101E301E501E701E901EB01ED01EF01F001F301F501F901FB01FD01FF02010203020502070209020B020D020F02110213021502170219021B021D021F02210223022502270229022B022D022F02310233-0239023C023F0240024202470249024B024D024F-02930295-02AF037103730377037B-037D039003AC-03CE03D003D103D5-03D703D903DB03DD03DF03E103E303E503E703E903EB03ED03EF-03F303F503F803FB03FC0430-045F04610463046504670469046B046D046F04710473047504770479047B047D047F0481048B048D048F04910493049504970499049B049D049F04A104A304A504A704A904AB04AD04AF04B104B304B504B704B904BB04BD04BF04C204C404C604C804CA04CC04CE04CF04D104D304D504D704D904DB04DD04DF04E104E304E504E704E904EB04ED04EF04F104F304F504F704F904FB04FD04FF05010503050505070509050B050D050F05110513051505170519051B051D051F0521052305250561-05871D00-1D2B1D62-1D771D79-1D9A1E011E031E051E071E091E0B1E0D1E0F1E111E131E151E171E191E1B1E1D1E1F1E211E231E251E271E291E2B1E2D1E2F1E311E331E351E371E391E3B1E3D1E3F1E411E431E451E471E491E4B1E4D1E4F1E511E531E551E571E591E5B1E5D1E5F1E611E631E651E671E691E6B1E6D1E6F1E711E731E751E771E791E7B1E7D1E7F1E811E831E851E871E891E8B1E8D1E8F1E911E931E95-1E9D1E9F1EA11EA31EA51EA71EA91EAB1EAD1EAF1EB11EB31EB51EB71EB91EBB1EBD1EBF1EC11EC31EC51EC71EC91ECB1ECD1ECF1ED11ED31ED51ED71ED91EDB1EDD1EDF1EE11EE31EE51EE71EE91EEB1EED1EEF1EF11EF31EF51EF71EF91EFB1EFD1EFF-1F071F10-1F151F20-1F271F30-1F371F40-1F451F50-1F571F60-1F671F70-1F7D1F80-1F871F90-1F971FA0-1FA71FB0-1FB41FB61FB71FBE1FC2-1FC41FC61FC71FD0-1FD31FD61FD71FE0-1FE71FF2-1FF41FF61FF7210A210E210F2113212F21342139213C213D2146-2149214E21842C30-2C5E2C612C652C662C682C6A2C6C2C712C732C742C76-2C7C2C812C832C852C872C892C8B2C8D2C8F2C912C932C952C972C992C9B2C9D2C9F2CA12CA32CA52CA72CA92CAB2CAD2CAF2CB12CB32CB52CB72CB92CBB2CBD2CBF2CC12CC32CC52CC72CC92CCB2CCD2CCF2CD12CD32CD52CD72CD92CDB2CDD2CDF2CE12CE32CE42CEC2CEE2D00-2D25A641A643A645A647A649A64BA64DA64FA651A653A655A657A659A65BA65DA65FA663A665A667A669A66BA66DA681A683A685A687A689A68BA68DA68FA691A693A695A697A723A725A727A729A72BA72DA72F-A731A733A735A737A739A73BA73DA73FA741A743A745A747A749A74BA74DA74FA751A753A755A757A759A75BA75DA75FA761A763A765A767A769A76BA76DA76FA771-A778A77AA77CA77FA781A783A785A787A78CFB00-FB06FB13-FB17FF41-FF5A",\n
    Lu: "0041-005A00C0-00D600D8-00DE01000102010401060108010A010C010E01100112011401160118011A011C011E01200122012401260128012A012C012E01300132013401360139013B013D013F0141014301450147014A014C014E01500152015401560158015A015C015E01600162016401660168016A016C016E017001720174017601780179017B017D018101820184018601870189-018B018E-0191019301940196-0198019C019D019F01A001A201A401A601A701A901AC01AE01AF01B1-01B301B501B701B801BC01C401C701CA01CD01CF01D101D301D501D701D901DB01DE01E001E201E401E601E801EA01EC01EE01F101F401F6-01F801FA01FC01FE02000202020402060208020A020C020E02100212021402160218021A021C021E02200222022402260228022A022C022E02300232023A023B023D023E02410243-02460248024A024C024E03700372037603860388-038A038C038E038F0391-03A103A3-03AB03CF03D2-03D403D803DA03DC03DE03E003E203E403E603E803EA03EC03EE03F403F703F903FA03FD-042F04600462046404660468046A046C046E04700472047404760478047A047C047E0480048A048C048E04900492049404960498049A049C049E04A004A204A404A604A804AA04AC04AE04B004B204B404B604B804BA04BC04BE04C004C104C304C504C704C904CB04CD04D004D204D404D604D804DA04DC04DE04E004E204E404E604E804EA04EC04EE04F004F204F404F604F804FA04FC04FE05000502050405060508050A050C050E05100512051405160518051A051C051E0520052205240531-055610A0-10C51E001E021E041E061E081E0A1E0C1E0E1E101E121E141E161E181E1A1E1C1E1E1E201E221E241E261E281E2A1E2C1E2E1E301E321E341E361E381E3A1E3C1E3E1E401E421E441E461E481E4A1E4C1E4E1E501E521E541E561E581E5A1E5C1E5E1E601E621E641E661E681E6A1E6C1E6E1E701E721E741E761E781E7A1E7C1E7E1E801E821E841E861E881E8A1E8C1E8E1E901E921E941E9E1EA01EA21EA41EA61EA81EAA1EAC1EAE1EB01EB21EB41EB61EB81EBA1EBC1EBE1EC01EC21EC41EC61EC81ECA1ECC1ECE1ED01ED21ED41ED61ED81EDA1EDC1EDE1EE01EE21EE41EE61EE81EEA1EEC1EEE1EF01EF21EF41EF61EF81EFA1EFC1EFE1F08-1F0F1F18-1F1D1F28-1F2F1F38-1F3F1F48-1F4D1F591F5B1F5D1F5F1F68-1F6F1FB8-1FBB1FC8-1FCB1FD8-1FDB1FE8-1FEC1FF8-1FFB21022107210B-210D2110-211221152119-211D212421262128212A-212D2130-2133213E213F214521832C00-2C2E2C602C62-2C642C672C692C6B2C6D-2C702C722C752C7E-2C802C822C842C862C882C8A2C8C2C8E2C902C922C942C962C982C9A2C9C2C9E2CA02CA22CA42CA62CA82CAA2CAC2CAE2CB02CB22CB42CB62CB82CBA2CBC2CBE2CC02CC22CC42CC62CC82CCA2CCC2CCE2CD02CD22CD42CD62CD82CDA2CDC2CDE2CE02CE22CEB2CEDA640A642A644A646A648A64AA64CA64EA650A652A654A656A658A65AA65CA65EA662A664A666A668A66AA66CA680A682A684A686A688A68AA68CA68EA690A692A694A696A722A724A726A728A72AA72CA72EA732A734A736A738A73AA73CA73EA740A742A744A746A748A74AA74CA74EA750A752A754A756A758A75AA75CA75EA760A762A764A766A768A76AA76CA76EA779A77BA77DA77EA780A782A784A786A78BFF21-FF3A",\n
    Lt: "01C501C801CB01F21F88-1F8F1F98-1F9F1FA8-1FAF1FBC1FCC1FFC",\n
    Lm: "02B0-02C102C6-02D102E0-02E402EC02EE0374037A0559064006E506E607F407F507FA081A0824082809710E460EC610FC17D718431AA71C78-1C7D1D2C-1D611D781D9B-1DBF2071207F2090-20942C7D2D6F2E2F30053031-3035303B309D309E30FC-30FEA015A4F8-A4FDA60CA67FA717-A71FA770A788A9CFAA70AADDFF70FF9EFF9F",\n
    Lo: "01BB01C0-01C3029405D0-05EA05F0-05F20621-063F0641-064A066E066F0671-06D306D506EE06EF06FA-06FC06FF07100712-072F074D-07A507B107CA-07EA0800-08150904-0939093D09500958-096109720979-097F0985-098C098F09900993-09A809AA-09B009B209B6-09B909BD09CE09DC09DD09DF-09E109F009F10A05-0A0A0A0F0A100A13-0A280A2A-0A300A320A330A350A360A380A390A59-0A5C0A5E0A72-0A740A85-0A8D0A8F-0A910A93-0AA80AAA-0AB00AB20AB30AB5-0AB90ABD0AD00AE00AE10B05-0B0C0B0F0B100B13-0B280B2A-0B300B320B330B35-0B390B3D0B5C0B5D0B5F-0B610B710B830B85-0B8A0B8E-0B900B92-0B950B990B9A0B9C0B9E0B9F0BA30BA40BA8-0BAA0BAE-0BB90BD00C05-0C0C0C0E-0C100C12-0C280C2A-0C330C35-0C390C3D0C580C590C600C610C85-0C8C0C8E-0C900C92-0CA80CAA-0CB30CB5-0CB90CBD0CDE0CE00CE10D05-0D0C0D0E-0D100D12-0D280D2A-0D390D3D0D600D610D7A-0D7F0D85-0D960D9A-0DB10DB3-0DBB0DBD0DC0-0DC60E01-0E300E320E330E40-0E450E810E820E840E870E880E8A0E8D0E94-0E970E99-0E9F0EA1-0EA30EA50EA70EAA0EAB0EAD-0EB00EB20EB30EBD0EC0-0EC40EDC0EDD0F000F40-0F470F49-0F6C0F88-0F8B1000-102A103F1050-1055105A-105D106110651066106E-10701075-1081108E10D0-10FA1100-1248124A-124D1250-12561258125A-125D1260-1288128A-128D1290-12B012B2-12B512B8-12BE12C012C2-12C512C8-12D612D8-13101312-13151318-135A1380-138F13A0-13F41401-166C166F-167F1681-169A16A0-16EA1700-170C170E-17111720-17311740-17511760-176C176E-17701780-17B317DC1820-18421844-18771880-18A818AA18B0-18F51900-191C1950-196D1970-19741980-19AB19C1-19C71A00-1A161A20-1A541B05-1B331B45-1B4B1B83-1BA01BAE1BAF1C00-1C231C4D-1C4F1C5A-1C771CE9-1CEC1CEE-1CF12135-21382D30-2D652D80-2D962DA0-2DA62DA8-2DAE2DB0-2DB62DB8-2DBE2DC0-2DC62DC8-2DCE2DD0-2DD62DD8-2DDE3006303C3041-3096309F30A1-30FA30FF3105-312D3131-318E31A0-31B731F0-31FF3400-4DB54E00-9FCBA000-A014A016-A48CA4D0-A4F7A500-A60BA610-A61FA62AA62BA66EA6A0-A6E5A7FB-A801A803-A805A807-A80AA80C-A822A840-A873A882-A8B3A8F2-A8F7A8FBA90A-A925A930-A946A960-A97CA984-A9B2AA00-AA28AA40-AA42AA44-AA4BAA60-AA6FAA71-AA76AA7AAA80-AAAFAAB1AAB5AAB6AAB9-AABDAAC0AAC2AADBAADCABC0-ABE2AC00-D7A3D7B0-D7C6D7CB-D7FBF900-FA2DFA30-FA6DFA70-FAD9FB1DFB1F-FB28FB2A-FB36FB38-FB3CFB3EFB40FB41FB43FB44FB46-FBB1FBD3-FD3DFD50-FD8FFD92-FDC7FDF0-FDFBFE70-FE74FE76-FEFCFF66-FF6FFF71-FF9DFFA0-FFBEFFC2-FFC7FFCA-FFCFFFD2-FFD7FFDA-FFDC",\n
    M:  "0300-036F0483-04890591-05BD05BF05C105C205C405C505C70610-061A064B-065E067006D6-06DC06DE-06E406E706E806EA-06ED07110730-074A07A6-07B007EB-07F30816-0819081B-08230825-08270829-082D0900-0903093C093E-094E0951-0955096209630981-098309BC09BE-09C409C709C809CB-09CD09D709E209E30A01-0A030A3C0A3E-0A420A470A480A4B-0A4D0A510A700A710A750A81-0A830ABC0ABE-0AC50AC7-0AC90ACB-0ACD0AE20AE30B01-0B030B3C0B3E-0B440B470B480B4B-0B4D0B560B570B620B630B820BBE-0BC20BC6-0BC80BCA-0BCD0BD70C01-0C030C3E-0C440C46-0C480C4A-0C4D0C550C560C620C630C820C830CBC0CBE-0CC40CC6-0CC80CCA-0CCD0CD50CD60CE20CE30D020D030D3E-0D440D46-0D480D4A-0D4D0D570D620D630D820D830DCA0DCF-0DD40DD60DD8-0DDF0DF20DF30E310E34-0E3A0E47-0E4E0EB10EB4-0EB90EBB0EBC0EC8-0ECD0F180F190F350F370F390F3E0F3F0F71-0F840F860F870F90-0F970F99-0FBC0FC6102B-103E1056-1059105E-10601062-10641067-106D1071-10741082-108D108F109A-109D135F1712-17141732-1734175217531772177317B6-17D317DD180B-180D18A91920-192B1930-193B19B0-19C019C819C91A17-1A1B1A55-1A5E1A60-1A7C1A7F1B00-1B041B34-1B441B6B-1B731B80-1B821BA1-1BAA1C24-1C371CD0-1CD21CD4-1CE81CED1CF21DC0-1DE61DFD-1DFF20D0-20F02CEF-2CF12DE0-2DFF302A-302F3099309AA66F-A672A67CA67DA6F0A6F1A802A806A80BA823-A827A880A881A8B4-A8C4A8E0-A8F1A926-A92DA947-A953A980-A983A9B3-A9C0AA29-AA36AA43AA4CAA4DAA7BAAB0AAB2-AAB4AAB7AAB8AABEAABFAAC1ABE3-ABEAABECABEDFB1EFE00-FE0FFE20-FE26",\n
    Mn: "0300-036F0483-04870591-05BD05BF05C105C205C405C505C70610-061A064B-065E067006D6-06DC06DF-06E406E706E806EA-06ED07110730-074A07A6-07B007EB-07F30816-0819081B-08230825-08270829-082D0900-0902093C0941-0948094D0951-095509620963098109BC09C1-09C409CD09E209E30A010A020A3C0A410A420A470A480A4B-0A4D0A510A700A710A750A810A820ABC0AC1-0AC50AC70AC80ACD0AE20AE30B010B3C0B3F0B41-0B440B4D0B560B620B630B820BC00BCD0C3E-0C400C46-0C480C4A-0C4D0C550C560C620C630CBC0CBF0CC60CCC0CCD0CE20CE30D41-0D440D4D0D620D630DCA0DD2-0DD40DD60E310E34-0E3A0E47-0E4E0EB10EB4-0EB90EBB0EBC0EC8-0ECD0F180F190F350F370F390F71-0F7E0F80-0F840F860F870F90-0F970F99-0FBC0FC6102D-10301032-10371039103A103D103E10581059105E-10601071-1074108210851086108D109D135F1712-17141732-1734175217531772177317B7-17BD17C617C9-17D317DD180B-180D18A91920-19221927192819321939-193B1A171A181A561A58-1A5E1A601A621A65-1A6C1A73-1A7C1A7F1B00-1B031B341B36-1B3A1B3C1B421B6B-1B731B801B811BA2-1BA51BA81BA91C2C-1C331C361C371CD0-1CD21CD4-1CE01CE2-1CE81CED1DC0-1DE61DFD-1DFF20D0-20DC20E120E5-20F02CEF-2CF12DE0-2DFF302A-302F3099309AA66FA67CA67DA6F0A6F1A802A806A80BA825A826A8C4A8E0-A8F1A926-A92DA947-A951A980-A982A9B3A9B6-A9B9A9BCAA29-AA2EAA31AA32AA35AA36AA43AA4CAAB0AAB2-AAB4AAB7AAB8AABEAABFAAC1ABE5ABE8ABEDFB1EFE00-FE0FFE20-FE26",\n
    Mc: "0903093E-09400949-094C094E0982098309BE-09C009C709C809CB09CC09D70A030A3E-0A400A830ABE-0AC00AC90ACB0ACC0B020B030B3E0B400B470B480B4B0B4C0B570BBE0BBF0BC10BC20BC6-0BC80BCA-0BCC0BD70C01-0C030C41-0C440C820C830CBE0CC0-0CC40CC70CC80CCA0CCB0CD50CD60D020D030D3E-0D400D46-0D480D4A-0D4C0D570D820D830DCF-0DD10DD8-0DDF0DF20DF30F3E0F3F0F7F102B102C10311038103B103C105610571062-10641067-106D108310841087-108C108F109A-109C17B617BE-17C517C717C81923-19261929-192B193019311933-193819B0-19C019C819C91A19-1A1B1A551A571A611A631A641A6D-1A721B041B351B3B1B3D-1B411B431B441B821BA11BA61BA71BAA1C24-1C2B1C341C351CE11CF2A823A824A827A880A881A8B4-A8C3A952A953A983A9B4A9B5A9BAA9BBA9BD-A9C0AA2FAA30AA33AA34AA4DAA7BABE3ABE4ABE6ABE7ABE9ABEAABEC",\n
    Me: "0488048906DE20DD-20E020E2-20E4A670-A672",\n
    N:  "0030-003900B200B300B900BC-00BE0660-066906F0-06F907C0-07C90966-096F09E6-09EF09F4-09F90A66-0A6F0AE6-0AEF0B66-0B6F0BE6-0BF20C66-0C6F0C78-0C7E0CE6-0CEF0D66-0D750E50-0E590ED0-0ED90F20-0F331040-10491090-10991369-137C16EE-16F017E0-17E917F0-17F91810-18191946-194F19D0-19DA1A80-1A891A90-1A991B50-1B591BB0-1BB91C40-1C491C50-1C5920702074-20792080-20892150-21822185-21892460-249B24EA-24FF2776-27932CFD30073021-30293038-303A3192-31953220-32293251-325F3280-328932B1-32BFA620-A629A6E6-A6EFA830-A835A8D0-A8D9A900-A909A9D0-A9D9AA50-AA59ABF0-ABF9FF10-FF19",\n
    Nd: "0030-00390660-066906F0-06F907C0-07C90966-096F09E6-09EF0A66-0A6F0AE6-0AEF0B66-0B6F0BE6-0BEF0C66-0C6F0CE6-0CEF0D66-0D6F0E50-0E590ED0-0ED90F20-0F291040-10491090-109917E0-17E91810-18191946-194F19D0-19DA1A80-1A891A90-1A991B50-1B591BB0-1BB91C40-1C491C50-1C59A620-A629A8D0-A8D9A900-A909A9D0-A9D9AA50-AA59ABF0-ABF9FF10-FF19",\n
    Nl: "16EE-16F02160-21822185-218830073021-30293038-303AA6E6-A6EF",\n
    No: "00B200B300B900BC-00BE09F4-09F90BF0-0BF20C78-0C7E0D70-0D750F2A-0F331369-137C17F0-17F920702074-20792080-20892150-215F21892460-249B24EA-24FF2776-27932CFD3192-31953220-32293251-325F3280-328932B1-32BFA830-A835",\n
    P:  "0021-00230025-002A002C-002F003A003B003F0040005B-005D005F007B007D00A100AB00B700BB00BF037E0387055A-055F0589058A05BE05C005C305C605F305F40609060A060C060D061B061E061F066A-066D06D40700-070D07F7-07F90830-083E0964096509700DF40E4F0E5A0E5B0F04-0F120F3A-0F3D0F850FD0-0FD4104A-104F10FB1361-13681400166D166E169B169C16EB-16ED1735173617D4-17D617D8-17DA1800-180A1944194519DE19DF1A1E1A1F1AA0-1AA61AA8-1AAD1B5A-1B601C3B-1C3F1C7E1C7F1CD32010-20272030-20432045-20512053-205E207D207E208D208E2329232A2768-277527C527C627E6-27EF2983-299829D8-29DB29FC29FD2CF9-2CFC2CFE2CFF2E00-2E2E2E302E313001-30033008-30113014-301F3030303D30A030FBA4FEA4FFA60D-A60FA673A67EA6F2-A6F7A874-A877A8CEA8CFA8F8-A8FAA92EA92FA95FA9C1-A9CDA9DEA9DFAA5C-AA5FAADEAADFABEBFD3EFD3FFE10-FE19FE30-FE52FE54-FE61FE63FE68FE6AFE6BFF01-FF03FF05-FF0AFF0C-FF0FFF1AFF1BFF1FFF20FF3B-FF3DFF3FFF5BFF5DFF5F-FF65",\n
    Pd: "002D058A05BE140018062010-20152E172E1A301C303030A0FE31FE32FE58FE63FF0D",\n
    Ps: "0028005B007B0F3A0F3C169B201A201E2045207D208D23292768276A276C276E27702772277427C527E627E827EA27EC27EE2983298529872989298B298D298F299129932995299729D829DA29FC2E222E242E262E283008300A300C300E3010301430163018301A301DFD3EFE17FE35FE37FE39FE3BFE3DFE3FFE41FE43FE47FE59FE5BFE5DFF08FF3BFF5BFF5FFF62",\n
    Pe: "0029005D007D0F3B0F3D169C2046207E208E232A2769276B276D276F27712773277527C627E727E927EB27ED27EF298429862988298A298C298E2990299229942996299829D929DB29FD2E232E252E272E293009300B300D300F3011301530173019301B301E301FFD3FFE18FE36FE38FE3AFE3CFE3EFE40FE42FE44FE48FE5AFE5CFE5EFF09FF3DFF5DFF60FF63",\n
    Pi: "00AB2018201B201C201F20392E022E042E092E0C2E1C2E20",\n
    Pf: "00BB2019201D203A2E032E052E0A2E0D2E1D2E21",\n
    Pc: "005F203F20402054FE33FE34FE4D-FE4FFF3F",\n
    Po: "0021-00230025-0027002A002C002E002F003A003B003F0040005C00A100B700BF037E0387055A-055F058905C005C305C605F305F40609060A060C060D061B061E061F066A-066D06D40700-070D07F7-07F90830-083E0964096509700DF40E4F0E5A0E5B0F04-0F120F850FD0-0FD4104A-104F10FB1361-1368166D166E16EB-16ED1735173617D4-17D617D8-17DA1800-18051807-180A1944194519DE19DF1A1E1A1F1AA0-1AA61AA8-1AAD1B5A-1B601C3B-1C3F1C7E1C7F1CD3201620172020-20272030-2038203B-203E2041-20432047-205120532055-205E2CF9-2CFC2CFE2CFF2E002E012E06-2E082E0B2E0E-2E162E182E192E1B2E1E2E1F2E2A-2E2E2E302E313001-3003303D30FBA4FEA4FFA60D-A60FA673A67EA6F2-A6F7A874-A877A8CEA8CFA8F8-A8FAA92EA92FA95FA9C1-A9CDA9DEA9DFAA5C-AA5FAADEAADFABEBFE10-FE16FE19FE30FE45FE46FE49-FE4CFE50-FE52FE54-FE57FE5F-FE61FE68FE6AFE6BFF01-FF03FF05-FF07FF0AFF0CFF0EFF0FFF1AFF1BFF1FFF20FF3CFF61FF64FF65",\n
    S:  "0024002B003C-003E005E0060007C007E00A2-00A900AC00AE-00B100B400B600B800D700F702C2-02C502D2-02DF02E5-02EB02ED02EF-02FF03750384038503F604820606-0608060B060E060F06E906FD06FE07F609F209F309FA09FB0AF10B700BF3-0BFA0C7F0CF10CF20D790E3F0F01-0F030F13-0F170F1A-0F1F0F340F360F380FBE-0FC50FC7-0FCC0FCE0FCF0FD5-0FD8109E109F13601390-139917DB194019E0-19FF1B61-1B6A1B74-1B7C1FBD1FBF-1FC11FCD-1FCF1FDD-1FDF1FED-1FEF1FFD1FFE20442052207A-207C208A-208C20A0-20B8210021012103-21062108210921142116-2118211E-2123212521272129212E213A213B2140-2144214A-214D214F2190-2328232B-23E82400-24262440-244A249C-24E92500-26CD26CF-26E126E326E8-26FF2701-27042706-2709270C-27272729-274B274D274F-27522756-275E2761-276727942798-27AF27B1-27BE27C0-27C427C7-27CA27CC27D0-27E527F0-29822999-29D729DC-29FB29FE-2B4C2B50-2B592CE5-2CEA2E80-2E992E9B-2EF32F00-2FD52FF0-2FFB300430123013302030363037303E303F309B309C319031913196-319F31C0-31E33200-321E322A-32503260-327F328A-32B032C0-32FE3300-33FF4DC0-4DFFA490-A4C6A700-A716A720A721A789A78AA828-A82BA836-A839AA77-AA79FB29FDFCFDFDFE62FE64-FE66FE69FF04FF0BFF1C-FF1EFF3EFF40FF5CFF5EFFE0-FFE6FFE8-FFEEFFFCFFFD",\n
    Sm: "002B003C-003E007C007E00AC00B100D700F703F60606-060820442052207A-207C208A-208C2140-2144214B2190-2194219A219B21A021A321A621AE21CE21CF21D221D421F4-22FF2308-230B23202321237C239B-23B323DC-23E125B725C125F8-25FF266F27C0-27C427C7-27CA27CC27D0-27E527F0-27FF2900-29822999-29D729DC-29FB29FE-2AFF2B30-2B442B47-2B4CFB29FE62FE64-FE66FF0BFF1C-FF1EFF5CFF5EFFE2FFE9-FFEC",\n
    Sc: "002400A2-00A5060B09F209F309FB0AF10BF90E3F17DB20A0-20B8A838FDFCFE69FF04FFE0FFE1FFE5FFE6",\n
    Sk: "005E006000A800AF00B400B802C2-02C502D2-02DF02E5-02EB02ED02EF-02FF0375038403851FBD1FBF-1FC11FCD-1FCF1FDD-1FDF1FED-1FEF1FFD1FFE309B309CA700-A716A720A721A789A78AFF3EFF40FFE3",\n
    So: "00A600A700A900AE00B000B60482060E060F06E906FD06FE07F609FA0B700BF3-0BF80BFA0C7F0CF10CF20D790F01-0F030F13-0F170F1A-0F1F0F340F360F380FBE-0FC50FC7-0FCC0FCE0FCF0FD5-0FD8109E109F13601390-1399194019E0-19FF1B61-1B6A1B74-1B7C210021012103-21062108210921142116-2118211E-2123212521272129212E213A213B214A214C214D214F2195-2199219C-219F21A121A221A421A521A7-21AD21AF-21CD21D021D121D321D5-21F32300-2307230C-231F2322-2328232B-237B237D-239A23B4-23DB23E2-23E82400-24262440-244A249C-24E92500-25B625B8-25C025C2-25F72600-266E2670-26CD26CF-26E126E326E8-26FF2701-27042706-2709270C-27272729-274B274D274F-27522756-275E2761-276727942798-27AF27B1-27BE2800-28FF2B00-2B2F2B452B462B50-2B592CE5-2CEA2E80-2E992E9B-2EF32F00-2FD52FF0-2FFB300430123013302030363037303E303F319031913196-319F31C0-31E33200-321E322A-32503260-327F328A-32B032C0-32FE3300-33FF4DC0-4DFFA490-A4C6A828-A82BA836A837A839AA77-AA79FDFDFFE4FFE8FFEDFFEEFFFCFFFD",\n
    Z:  "002000A01680180E2000-200A20282029202F205F3000",\n
    Zs: "002000A01680180E2000-200A202F205F3000",\n
    Zl: "2028",\n
    Zp: "2029",\n
    C:  "0000-001F007F-009F00AD03780379037F-0383038B038D03A20526-05300557055805600588058B-059005C8-05CF05EB-05EF05F5-0605061C061D0620065F06DD070E070F074B074C07B2-07BF07FB-07FF082E082F083F-08FF093A093B094F095609570973-097809800984098D098E0991099209A909B109B3-09B509BA09BB09C509C609C909CA09CF-09D609D8-09DB09DE09E409E509FC-0A000A040A0B-0A0E0A110A120A290A310A340A370A3A0A3B0A3D0A43-0A460A490A4A0A4E-0A500A52-0A580A5D0A5F-0A650A76-0A800A840A8E0A920AA90AB10AB40ABA0ABB0AC60ACA0ACE0ACF0AD1-0ADF0AE40AE50AF00AF2-0B000B040B0D0B0E0B110B120B290B310B340B3A0B3B0B450B460B490B4A0B4E-0B550B58-0B5B0B5E0B640B650B72-0B810B840B8B-0B8D0B910B96-0B980B9B0B9D0BA0-0BA20BA5-0BA70BAB-0BAD0BBA-0BBD0BC3-0BC50BC90BCE0BCF0BD1-0BD60BD8-0BE50BFB-0C000C040C0D0C110C290C340C3A-0C3C0C450C490C4E-0C540C570C5A-0C5F0C640C650C70-0C770C800C810C840C8D0C910CA90CB40CBA0CBB0CC50CC90CCE-0CD40CD7-0CDD0CDF0CE40CE50CF00CF3-0D010D040D0D0D110D290D3A-0D3C0D450D490D4E-0D560D58-0D5F0D640D650D76-0D780D800D810D840D97-0D990DB20DBC0DBE0DBF0DC7-0DC90DCB-0DCE0DD50DD70DE0-0DF10DF5-0E000E3B-0E3E0E5C-0E800E830E850E860E890E8B0E8C0E8E-0E930E980EA00EA40EA60EA80EA90EAC0EBA0EBE0EBF0EC50EC70ECE0ECF0EDA0EDB0EDE-0EFF0F480F6D-0F700F8C-0F8F0F980FBD0FCD0FD9-0FFF10C6-10CF10FD-10FF1249124E124F12571259125E125F1289128E128F12B112B612B712BF12C112C612C712D7131113161317135B-135E137D-137F139A-139F13F5-13FF169D-169F16F1-16FF170D1715-171F1737-173F1754-175F176D17711774-177F17B417B517DE17DF17EA-17EF17FA-17FF180F181A-181F1878-187F18AB-18AF18F6-18FF191D-191F192C-192F193C-193F1941-1943196E196F1975-197F19AC-19AF19CA-19CF19DB-19DD1A1C1A1D1A5F1A7D1A7E1A8A-1A8F1A9A-1A9F1AAE-1AFF1B4C-1B4F1B7D-1B7F1BAB-1BAD1BBA-1BFF1C38-1C3A1C4A-1C4C1C80-1CCF1CF3-1CFF1DE7-1DFC1F161F171F1E1F1F1F461F471F4E1F4F1F581F5A1F5C1F5E1F7E1F7F1FB51FC51FD41FD51FDC1FF01FF11FF51FFF200B-200F202A-202E2060-206F20722073208F2095-209F20B9-20CF20F1-20FF218A-218F23E9-23FF2427-243F244B-245F26CE26E226E4-26E727002705270A270B2728274C274E2753-2755275F27602795-279727B027BF27CB27CD-27CF2B4D-2B4F2B5A-2BFF2C2F2C5F2CF2-2CF82D26-2D2F2D66-2D6E2D70-2D7F2D97-2D9F2DA72DAF2DB72DBF2DC72DCF2DD72DDF2E32-2E7F2E9A2EF4-2EFF2FD6-2FEF2FFC-2FFF3040309730983100-3104312E-3130318F31B8-31BF31E4-31EF321F32FF4DB6-4DBF9FCC-9FFFA48D-A48FA4C7-A4CFA62C-A63FA660A661A674-A67BA698-A69FA6F8-A6FFA78D-A7FAA82C-A82FA83A-A83FA878-A87FA8C5-A8CDA8DA-A8DFA8FC-A8FFA954-A95EA97D-A97FA9CEA9DA-A9DDA9E0-A9FFAA37-AA3FAA4EAA4FAA5AAA5BAA7C-AA7FAAC3-AADAAAE0-ABBFABEEABEFABFA-ABFFD7A4-D7AFD7C7-D7CAD7FC-F8FFFA2EFA2FFA6EFA6FFADA-FAFFFB07-FB12FB18-FB1CFB37FB3DFB3FFB42FB45FBB2-FBD2FD40-FD4FFD90FD91FDC8-FDEFFDFEFDFFFE1A-FE1FFE27-FE2FFE53FE67FE6C-FE6FFE75FEFD-FF00FFBF-FFC1FFC8FFC9FFD0FFD1FFD8FFD9FFDD-FFDFFFE7FFEF-FFFBFFFEFFFF",\n
    Cc: "0000-001F007F-009F",\n
    Cf: "00AD0600-060306DD070F17B417B5200B-200F202A-202E2060-2064206A-206FFEFFFFF9-FFFB",\n
    Co: "E000-F8FF",\n
    Cs: "D800-DFFF",\n
    Cn: "03780379037F-0383038B038D03A20526-05300557055805600588058B-059005C8-05CF05EB-05EF05F5-05FF06040605061C061D0620065F070E074B074C07B2-07BF07FB-07FF082E082F083F-08FF093A093B094F095609570973-097809800984098D098E0991099209A909B109B3-09B509BA09BB09C509C609C909CA09CF-09D609D8-09DB09DE09E409E509FC-0A000A040A0B-0A0E0A110A120A290A310A340A370A3A0A3B0A3D0A43-0A460A490A4A0A4E-0A500A52-0A580A5D0A5F-0A650A76-0A800A840A8E0A920AA90AB10AB40ABA0ABB0AC60ACA0ACE0ACF0AD1-0ADF0AE40AE50AF00AF2-0B000B040B0D0B0E0B110B120B290B310B340B3A0B3B0B450B460B490B4A0B4E-0B550B58-0B5B0B5E0B640B650B72-0B810B840B8B-0B8D0B910B96-0B980B9B0B9D0BA0-0BA20BA5-0BA70BAB-0BAD0BBA-0BBD0BC3-0BC50BC90BCE0BCF0BD1-0BD60BD8-0BE50BFB-0C000C040C0D0C110C290C340C3A-0C3C0C450C490C4E-0C540C570C5A-0C5F0C640C650C70-0C770C800C810C840C8D0C910CA90CB40CBA0CBB0CC50CC90CCE-0CD40CD7-0CDD0CDF0CE40CE50CF00CF3-0D010D040D0D0D110D290D3A-0D3C0D450D490D4E-0D560D58-0D5F0D640D650D76-0D780D800D810D840D97-0D990DB20DBC0DBE0DBF0DC7-0DC90DCB-0DCE0DD50DD70DE0-0DF10DF5-0E000E3B-0E3E0E5C-0E800E830E850E860E890E8B0E8C0E8E-0E930E980EA00EA40EA60EA80EA90EAC0EBA0EBE0EBF0EC50EC70ECE0ECF0EDA0EDB0EDE-0EFF0F480F6D-0F700F8C-0F8F0F980FBD0FCD0FD9-0FFF10C6-10CF10FD-10FF1249124E124F12571259125E125F1289128E128F12B112B612B712BF12C112C612C712D7131113161317135B-135E137D-137F139A-139F13F5-13FF169D-169F16F1-16FF170D1715-171F1737-173F1754-175F176D17711774-177F17DE17DF17EA-17EF17FA-17FF180F181A-181F1878-187F18AB-18AF18F6-18FF191D-191F192C-192F193C-193F1941-1943196E196F1975-197F19AC-19AF19CA-19CF19DB-19DD1A1C1A1D1A5F1A7D1A7E1A8A-1A8F1A9A-1A9F1AAE-1AFF1B4C-1B4F1B7D-1B7F1BAB-1BAD1BBA-1BFF1C38-1C3A1C4A-1C4C1C80-1CCF1CF3-1CFF1DE7-1DFC1F161F171F1E1F1F1F461F471F4E1F4F1F581F5A1F5C1F5E1F7E1F7F1FB51FC51FD41FD51FDC1FF01FF11FF51FFF2065-206920722073208F2095-209F20B9-20CF20F1-20FF218A-218F23E9-23FF2427-243F244B-245F26CE26E226E4-26E727002705270A270B2728274C274E2753-2755275F27602795-279727B027BF27CB27CD-27CF2B4D-2B4F2B5A-2BFF2C2F2C5F2CF2-2CF82D26-2D2F2D66-2D6E2D70-2D7F2D97-2D9F2DA72DAF2DB72DBF2DC72DCF2DD72DDF2E32-2E7F2E9A2EF4-2EFF2FD6-2FEF2FFC-2FFF3040309730983100-3104312E-3130318F31B8-31BF31E4-31EF321F32FF4DB6-4DBF9FCC-9FFFA48D-A48FA4C7-A4CFA62C-A63FA660A661A674-A67BA698-A69FA6F8-A6FFA78D-A7FAA82C-A82FA83A-A83FA878-A87FA8C5-A8CDA8DA-A8DFA8FC-A8FFA954-A95EA97D-A97FA9CEA9DA-A9DDA9E0-A9FFAA37-AA3FAA4EAA4FAA5AAA5BAA7C-AA7FAAC3-AADAAAE0-ABBFABEEABEFABFA-ABFFD7A4-D7AFD7C7-D7CAD7FC-D7FFFA2EFA2FFA6EFA6FFADA-FAFFFB07-FB12FB18-FB1CFB37FB3DFB3FFB42FB45FBB2-FBD2FD40-FD4FFD90FD91FDC8-FDEFFDFEFDFFFE1A-FE1FFE27-FE2FFE53FE67FE6C-FE6FFE75FEFDFEFEFF00FFBF-FFC1FFC8FFC9FFD0FFD1FFD8FFD9FFDD-FFDFFFE7FFEF-FFF8FFFEFFFF"\n
});\n
\n
function addUnicodePackage (pack) {\n
    var codePoint = /\\w{4}/g;\n
    for (var name in pack)\n
        exports.packages[name] = pack[name].replace(codePoint, "\\\\u$&");\n
};\n
\n
});\n
\n
define(\'ace/token_iterator\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
var TokenIterator = function(session, initialRow, initialColumn) {\n
    this.$session = session;\n
    this.$row = initialRow;\n
    this.$rowTokens = session.getTokens(initialRow);\n
\n
    var token = session.getTokenAt(initialRow, initialColumn);\n
    this.$tokenIndex = token ? token.index : -1;\n
};\n
\n
(function() { \n
    this.stepBackward = function() {\n
        this.$tokenIndex -= 1;\n
        \n
        while (this.$tokenIndex < 0) {\n
            this.$row -= 1;\n
            if (this.$row < 0) {\n
                this.$row = 0;\n
                return null;\n
            }\n
                \n
            this.$rowTokens = this.$session.getTokens(this.$row);\n
            this.$tokenIndex = this.$rowTokens.length - 1;\n
        }\n
            \n
        return this.$rowTokens[this.$tokenIndex];\n
    };   \n
    this.stepForward = function() {\n
        this.$tokenIndex += 1;\n
        var rowCount;\n
        while (this.$tokenIndex >= this.$rowTokens.length) {\n
            this.$row += 1;\n
            if (!rowCount)\n
                rowCount = this.$session.getLength();\n
            if (this.$row >= rowCount) {\n
                this.$row = rowCount - 1;\n
                return null;\n
            }\n
\n
            this.$rowTokens = this.$session.getTokens(this.$row);\n
            this.$tokenIndex = 0;\n
        }\n
            \n
        return this.$rowTokens[this.$tokenIndex];\n
    };      \n
    this.getCurrentToken = function () {\n
        return this.$rowTokens[this.$tokenIndex];\n
    };      \n
    this.getCurrentTokenRow = function () {\n
        return this.$row;\n
    };     \n
    this.getCurrentTokenColumn = function() {\n
        var rowTokens = this.$rowTokens;\n
        var tokenIndex = this.$tokenIndex;\n
        var column = rowTokens[tokenIndex].start;\n
        if (column !== undefined)\n
            return column;\n
            \n
        column = 0;\n
        while (tokenIndex > 0) {\n
            tokenIndex -= 1;\n
            column += rowTokens[tokenIndex].value.length;\n
        }\n
        \n
        return column;  \n
    };\n
            \n
}).call(TokenIterator.prototype);\n
\n
exports.TokenIterator = TokenIterator;\n
});\n
\n
define(\'ace/document\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/event_emitter\', \'ace/range\', \'ace/anchor\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var Range = require("./range").Range;\n
var Anchor = require("./anchor").Anchor;\n
\n
var Document = function(text) {\n
    this.$lines = [];\n
    if (text.length == 0) {\n
        this.$lines = [""];\n
    } else if (Array.isArray(text)) {\n
        this._insertLines(0, text);\n
    } else {\n
        this.insert({row: 0, column:0}, text);\n
    }\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
    this.setValue = function(text) {\n
        var len = this.getLength();\n
        this.remove(new Range(0, 0, len, this.getLine(len-1).length));\n
        this.insert({row: 0, column:0}, text);\n
    };\n
    this.getValue = function() {\n
        return this.getAllLines().join(this.getNewLineCharacter());\n
    };\n
    this.createAnchor = function(row, column) {\n
        return new Anchor(this, row, column);\n
    };\n
    if ("aaa".split(/a/).length == 0)\n
        this.$split = function(text) {\n
            return text.replace(/\\r\\n|\\r/g, "\\n").split("\\n");\n
        }\n
    else\n
        this.$split = function(text) {\n
            return text.split(/\\r\\n|\\r|\\n/);\n
        };\n
\n
\n
    this.$detectNewLine = function(text) {\n
        var match = text.match(/^.*?(\\r\\n|\\r|\\n)/m);\n
        this.$autoNewLine = match ? match[1] : "\\n";\n
    };\n
    this.getNewLineCharacter = function() {\n
        switch (this.$newLineMode) {\n
          case "windows":\n
            return "\\r\\n";\n
          case "unix":\n
            return "\\n";\n
          default:\n
            return this.$autoNewLine;\n
        }\n
    };\n
\n
    this.$autoNewLine = "\\n";\n
    this.$newLineMode = "auto";\n
    this.setNewLineMode = function(newLineMode) {\n
        if (this.$newLineMode === newLineMode)\n
            return;\n
\n
        this.$newLineMode = newLineMode;\n
    };\n
    this.getNewLineMode = function() {\n
        return this.$newLineMode;\n
    };\n
    this.isNewLine = function(text) {\n
        return (text == "\\r\\n" || text == "\\r" || text == "\\n");\n
    };\n
    this.getLine = function(row) {\n
        return this.$lines[row] || "";\n
    };\n
    this.getLines = function(firstRow, lastRow) {\n
        return this.$lines.slice(firstRow, lastRow + 1);\n
    };\n
    this.getAllLines = function() {\n
        return this.getLines(0, this.getLength());\n
    };\n
    this.getLength = function() {\n
        return this.$lines.length;\n
    };\n
    this.getTextRange = function(range) {\n
        if (range.start.row == range.end.row) {\n
            return this.getLine(range.start.row)\n
                .substring(range.start.column, range.end.column);\n
        }\n
        var lines = this.getLines(range.start.row, range.end.row);\n
        lines[0] = (lines[0] || "").substring(range.start.column);\n
        var l = lines.length - 1;\n
        if (range.end.row - range.start.row == l)\n
            lines[l] 

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAY=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="6" aka="AAAAAAAAAAY=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

= lines[l].substring(0, range.end.column);\n
        return lines.join(this.getNewLineCharacter());\n
    };\n
\n
    this.$clipPosition = function(position) {\n
        var length = this.getLength();\n
        if (position.row >= length) {\n
            position.row = Math.max(0, length - 1);\n
            position.column = this.getLine(length-1).length;\n
        } else if (position.row < 0)\n
            position.row = 0;\n
        return position;\n
    };\n
    this.insert = function(position, text) {\n
        if (!text || text.length === 0)\n
            return position;\n
\n
        position = this.$clipPosition(position);\n
        if (this.getLength() <= 1)\n
            this.$detectNewLine(text);\n
\n
        var lines = this.$split(text);\n
        var firstLine = lines.splice(0, 1)[0];\n
        var lastLine = lines.length == 0 ? null : lines.splice(lines.length - 1, 1)[0];\n
\n
        position = this.insertInLine(position, firstLine);\n
        if (lastLine !== null) {\n
            position = this.insertNewLine(position); // terminate first line\n
            position = this._insertLines(position.row, lines);\n
            position = this.insertInLine(position, lastLine || "");\n
        }\n
        return position;\n
    };\n
    this.insertLines = function(row, lines) {\n
        if (row >= this.getLength())\n
            return this.insert({row: row, column: 0}, "\\n" + lines.join("\\n"));\n
        return this._insertLines(Math.max(row, 0), lines);\n
    };\n
    this._insertLines = function(row, lines) {\n
        if (lines.length == 0)\n
            return {row: row, column: 0};\n
        if (lines.length > 0xFFFF) {\n
            var end = this._insertLines(row, lines.slice(0xFFFF));\n
            lines = lines.slice(0, 0xFFFF);\n
        }\n
\n
        var args = [row, 0];\n
        args.push.apply(args, lines);\n
        this.$lines.splice.apply(this.$lines, args);\n
\n
        var range = new Range(row, 0, row + lines.length, 0);\n
        var delta = {\n
            action: "insertLines",\n
            range: range,\n
            lines: lines\n
        };\n
        this._emit("change", { data: delta });\n
        return end || range.end;\n
    };\n
    this.insertNewLine = function(position) {\n
        position = this.$clipPosition(position);\n
        var line = this.$lines[position.row] || "";\n
\n
        this.$lines[position.row] = line.substring(0, position.column);\n
        this.$lines.splice(position.row + 1, 0, line.substring(position.column, line.length));\n
\n
        var end = {\n
            row : position.row + 1,\n
            column : 0\n
        };\n
\n
        var delta = {\n
            action: "insertText",\n
            range: Range.fromPoints(position, end),\n
            text: this.getNewLineCharacter()\n
        };\n
        this._emit("change", { data: delta });\n
\n
        return end;\n
    };\n
    this.insertInLine = function(position, text) {\n
        if (text.length == 0)\n
            return position;\n
\n
        var line = this.$lines[position.row] || "";\n
\n
        this.$lines[position.row] = line.substring(0, position.column) + text\n
                + line.substring(position.column);\n
\n
        var end = {\n
            row : position.row,\n
            column : position.column + text.length\n
        };\n
\n
        var delta = {\n
            action: "insertText",\n
            range: Range.fromPoints(position, end),\n
            text: text\n
        };\n
        this._emit("change", { data: delta });\n
\n
        return end;\n
    };\n
    this.remove = function(range) {\n
        if (!range instanceof Range)\n
            range = Range.fromPoints(range.start, range.end);\n
        range.start = this.$clipPosition(range.start);\n
        range.end = this.$clipPosition(range.end);\n
\n
        if (range.isEmpty())\n
            return range.start;\n
\n
        var firstRow = range.start.row;\n
        var lastRow = range.end.row;\n
\n
        if (range.isMultiLine()) {\n
            var firstFullRow = range.start.column == 0 ? firstRow : firstRow + 1;\n
            var lastFullRow = lastRow - 1;\n
\n
            if (range.end.column > 0)\n
                this.removeInLine(lastRow, 0, range.end.column);\n
\n
            if (lastFullRow >= firstFullRow)\n
                this._removeLines(firstFullRow, lastFullRow);\n
\n
            if (firstFullRow != firstRow) {\n
                this.removeInLine(firstRow, range.start.column, this.getLine(firstRow).length);\n
                this.removeNewLine(range.start.row);\n
            }\n
        }\n
        else {\n
            this.removeInLine(firstRow, range.start.column, range.end.column);\n
        }\n
        return range.start;\n
    };\n
    this.removeInLine = function(row, startColumn, endColumn) {\n
        if (startColumn == endColumn)\n
            return;\n
\n
        var range = new Range(row, startColumn, row, endColumn);\n
        var line = this.getLine(row);\n
        var removed = line.substring(startColumn, endColumn);\n
        var newLine = line.substring(0, startColumn) + line.substring(endColumn, line.length);\n
        this.$lines.splice(row, 1, newLine);\n
\n
        var delta = {\n
            action: "removeText",\n
            range: range,\n
            text: removed\n
        };\n
        this._emit("change", { data: delta });\n
        return range.start;\n
    };\n
    this.removeLines = function(firstRow, lastRow) {\n
        if (firstRow < 0 || lastRow >= this.getLength())\n
            return this.remove(new Range(firstRow, 0, lastRow + 1, 0));\n
        return this._removeLines(firstRow, lastRow);\n
    };\n
\n
    this._removeLines = function(firstRow, lastRow) {\n
        var range = new Range(firstRow, 0, lastRow + 1, 0);\n
        var removed = this.$lines.splice(firstRow, lastRow - firstRow + 1);\n
\n
        var delta = {\n
            action: "removeLines",\n
            range: range,\n
            nl: this.getNewLineCharacter(),\n
            lines: removed\n
        };\n
        this._emit("change", { data: delta });\n
        return removed;\n
    };\n
    this.removeNewLine = function(row) {\n
        var firstLine = this.getLine(row);\n
        var secondLine = this.getLine(row+1);\n
\n
        var range = new Range(row, firstLine.length, row+1, 0);\n
        var line = firstLine + secondLine;\n
\n
        this.$lines.splice(row, 2, line);\n
\n
        var delta = {\n
            action: "removeText",\n
            range: range,\n
            text: this.getNewLineCharacter()\n
        };\n
        this._emit("change", { data: delta });\n
    };\n
    this.replace = function(range, text) {\n
        if (!range instanceof Range)\n
            range = Range.fromPoints(range.start, range.end);\n
        if (text.length == 0 && range.isEmpty())\n
            return range.start;\n
        if (text == this.getTextRange(range))\n
            return range.end;\n
\n
        this.remove(range);\n
        if (text) {\n
            var end = this.insert(range.start, text);\n
        }\n
        else {\n
            end = range.start;\n
        }\n
\n
        return end;\n
    };\n
    this.applyDeltas = function(deltas) {\n
        for (var i=0; i<deltas.length; i++) {\n
            var delta = deltas[i];\n
            var range = Range.fromPoints(delta.range.start, delta.range.end);\n
\n
            if (delta.action == "insertLines")\n
                this.insertLines(range.start.row, delta.lines);\n
            else if (delta.action == "insertText")\n
                this.insert(range.start, delta.text);\n
            else if (delta.action == "removeLines")\n
                this._removeLines(range.start.row, range.end.row - 1);\n
            else if (delta.action == "removeText")\n
                this.remove(range);\n
        }\n
    };\n
    this.revertDeltas = function(deltas) {\n
        for (var i=deltas.length-1; i>=0; i--) {\n
            var delta = deltas[i];\n
\n
            var range = Range.fromPoints(delta.range.start, delta.range.end);\n
\n
            if (delta.action == "insertLines")\n
                this._removeLines(range.start.row, range.end.row - 1);\n
            else if (delta.action == "insertText")\n
                this.remove(range);\n
            else if (delta.action == "removeLines")\n
                this._insertLines(range.start.row, delta.lines);\n
            else if (delta.action == "removeText")\n
                this.insert(range.start, delta.text);\n
        }\n
    };\n
    this.indexToPosition = function(index, startRow) {\n
        var lines = this.$lines || this.getAllLines();\n
        var newlineLength = this.getNewLineCharacter().length;\n
        for (var i = startRow || 0, l = lines.length; i < l; i++) {\n
            index -= lines[i].length + newlineLength;\n
            if (index < 0)\n
                return {row: i, column: index + lines[i].length + newlineLength};\n
        }\n
        return {row: l-1, column: lines[l-1].length};\n
    };\n
    this.positionToIndex = function(pos, startRow) {\n
        var lines = this.$lines || this.getAllLines();\n
        var newlineLength = this.getNewLineCharacter().length;\n
        var index = 0;\n
        var row = Math.min(pos.row, lines.length);\n
        for (var i = startRow || 0; i < row; ++i)\n
            index += lines[i].length + newlineLength;\n
\n
        return index + pos.column;\n
    };\n
\n
}).call(Document.prototype);\n
\n
exports.Document = Document;\n
});\n
\n
define(\'ace/anchor\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
\n
var Anchor = exports.Anchor = function(doc, row, column) {\n
    this.$onChange = this.onChange.bind(this);\n
    this.attach(doc);\n
    \n
    if (typeof column == "undefined")\n
        this.setPosition(row.row, row.column);\n
    else\n
        this.setPosition(row, column);\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
    this.getPosition = function() {\n
        return this.$clipPositionToDocument(this.row, this.column);\n
    };\n
    this.getDocument = function() {\n
        return this.document;\n
    };\n
    this.$insertRight = false;\n
    this.onChange = function(e) {\n
        var delta = e.data;\n
        var range = delta.range;\n
\n
        if (range.start.row == range.end.row && range.start.row != this.row)\n
            return;\n
\n
        if (range.start.row > this.row)\n
            return;\n
\n
        if (range.start.row == this.row && range.start.column > this.column)\n
            return;\n
\n
        var row = this.row;\n
        var column = this.column;\n
        var start = range.start;\n
        var end = range.end;\n
\n
        if (delta.action === "insertText") {\n
            if (start.row === row && start.column <= column) {\n
                if (start.column === column && this.$insertRight) {\n
                } else if (start.row === end.row) {\n
                    column += end.column - start.column;\n
                } else {\n
                    column -= start.column;\n
                    row += end.row - start.row;\n
                }\n
            } else if (start.row !== end.row && start.row < row) {\n
                row += end.row - start.row;\n
            }\n
        } else if (delta.action === "insertLines") {\n
            if (start.row <= row) {\n
                row += end.row - start.row;\n
            }\n
        } else if (delta.action === "removeText") {\n
            if (start.row === row && start.column < column) {\n
                if (end.column >= column)\n
                    column = start.column;\n
                else\n
                    column = Math.max(0, column - (end.column - start.column));\n
\n
            } else if (start.row !== end.row && start.row < row) {\n
                if (end.row === row)\n
                    column = Math.max(0, column - end.column) + start.column;\n
                row -= (end.row - start.row);\n
            } else if (end.row === row) {\n
                row -= end.row - start.row;\n
                column = Math.max(0, column - end.column) + start.column;\n
            }\n
        } else if (delta.action == "removeLines") {\n
            if (start.row <= row) {\n
                if (end.row <= row)\n
                    row -= end.row - start.row;\n
                else {\n
                    row = start.row;\n
                    column = 0;\n
                }\n
            }\n
        }\n
\n
        this.setPosition(row, column, true);\n
    };\n
    this.setPosition = function(row, column, noClip) {\n
        var pos;\n
        if (noClip) {\n
            pos = {\n
                row: row,\n
                column: column\n
            };\n
        } else {\n
            pos = this.$clipPositionToDocument(row, column);\n
        }\n
\n
        if (this.row == pos.row && this.column == pos.column)\n
            return;\n
\n
        var old = {\n
            row: this.row,\n
            column: this.column\n
        };\n
\n
        this.row = pos.row;\n
        this.column = pos.column;\n
        this._emit("change", {\n
            old: old,\n
            value: pos\n
        });\n
    };\n
    this.detach = function() {\n
        this.document.removeEventListener("change", this.$onChange);\n
    };\n
    this.attach = function(doc) {\n
        this.document = doc || this.document;\n
        this.document.on("change", this.$onChange);\n
    };\n
    this.$clipPositionToDocument = function(row, column) {\n
        var pos = {};\n
\n
        if (row >= this.document.getLength()) {\n
            pos.row = Math.max(0, this.document.getLength() - 1);\n
            pos.column = this.document.getLine(pos.row).length;\n
        }\n
        else if (row < 0) {\n
            pos.row = 0;\n
            pos.column = 0;\n
        }\n
        else {\n
            pos.row = row;\n
            pos.column = Math.min(this.document.getLine(pos.row).length, Math.max(0, column));\n
        }\n
\n
        if (column < 0)\n
            pos.column = 0;\n
\n
        return pos;\n
    };\n
\n
}).call(Anchor.prototype);\n
\n
});\n
\n
define(\'ace/background_tokenizer\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
\n
var BackgroundTokenizer = function(tokenizer, editor) {\n
    this.running = false;\n
    this.lines = [];\n
    this.states = [];\n
    this.currentLine = 0;\n
    this.tokenizer = tokenizer;\n
\n
    var self = this;\n
\n
    this.$worker = function() {\n
        if (!self.running) { return; }\n
\n
        var workerStart = new Date();\n
        var currentLine = self.currentLine;\n
        var endLine = -1;\n
        var doc = self.doc;\n
\n
        while (self.lines[currentLine])\n
            currentLine++;\n
\n
        var startLine = currentLine;\n
\n
        var len = doc.getLength();\n
        var processedLines = 0;\n
        self.running = false;\n
        while (currentLine < len) {\n
            self.$tokenizeRow(currentLine);\n
            endLine = currentLine;\n
            do {\n
                currentLine++;\n
            } while (self.lines[currentLine]);\n
            processedLines ++;\n
            if ((processedLines % 5 == 0) && (new Date() - workerStart) > 20) {                \n
                self.running = setTimeout(self.$worker, 20);\n
                self.currentLine = currentLine;\n
                return;\n
            }\n
        }\n
        self.currentLine = currentLine;\n
        \n
        if (startLine <= endLine)\n
            self.fireUpdateEvent(startLine, endLine);\n
    };\n
};\n
\n
(function(){\n
\n
    oop.implement(this, EventEmitter);\n
    this.setTokenizer = function(tokenizer) {\n
        this.tokenizer = tokenizer;\n
        this.lines = [];\n
        this.states = [];\n
\n
        this.start(0);\n
    };\n
    this.setDocument = function(doc) {\n
        this.doc = doc;\n
        this.lines = [];\n
        this.states = [];\n
\n
        this.stop();\n
    };\n
    this.fireUpdateEvent = function(firstRow, lastRow) {\n
        var data = {\n
            first: firstRow,\n
            last: lastRow\n
        };\n
        this._emit("update", {data: data});\n
    };\n
    this.start = function(startRow) {\n
        this.currentLine = Math.min(startRow || 0, this.currentLine, this.doc.getLength());\n
        this.lines.splice(this.currentLine, this.lines.length);\n
        this.states.splice(this.currentLine, this.states.length);\n
\n
        this.stop();\n
        this.running = setTimeout(this.$worker, 700);\n
    };\n
    \n
    this.scheduleStart = function() {\n
        if (!this.running)\n
            this.running = setTimeout(this.$worker, 700);\n
    }\n
\n
    this.$updateOnChange = function(delta) {\n
        var range = delta.range;\n
        var startRow = range.start.row;\n
        var len = range.end.row - startRow;\n
\n
        if (len === 0) {\n
            this.lines[startRow] = null;\n
        } else if (delta.action == "removeText" || delta.action == "removeLines") {\n
            this.lines.splice(startRow, len + 1, null);\n
            this.states.splice(startRow, len + 1, null);\n
        } else {\n
            var args = Array(len + 1);\n
            args.unshift(startRow, 1);\n
            this.lines.splice.apply(this.lines, args);\n
            this.states.splice.apply(this.states, args);\n
        }\n
\n
        this.currentLine = Math.min(startRow, this.currentLine, this.doc.getLength());\n
\n
        this.stop();\n
    };\n
    this.stop = function() {\n
        if (this.running)\n
            clearTimeout(this.running);\n
        this.running = false;\n
    };\n
    this.getTokens = function(row) {\n
        return this.lines[row] || this.$tokenizeRow(row);\n
    };\n
    this.getState = function(row) {\n
        if (this.currentLine == row)\n
            this.$tokenizeRow(row);\n
        return this.states[row] || "start";\n
    };\n
\n
    this.$tokenizeRow = function(row) {\n
        var line = this.doc.getLine(row);\n
        var state = this.states[row - 1];\n
\n
        var data = this.tokenizer.getLineTokens(line, state, row);\n
\n
        if (this.states[row] + "" !== data.state + "") {\n
            this.states[row] = data.state;\n
            this.lines[row + 1] = null;\n
            if (this.currentLine > row + 1)\n
                this.currentLine = row + 1;\n
        } else if (this.currentLine == row) {\n
            this.currentLine = row + 1;\n
        }\n
\n
        return this.lines[row] = data.tokens;\n
    };\n
\n
}).call(BackgroundTokenizer.prototype);\n
\n
exports.BackgroundTokenizer = BackgroundTokenizer;\n
});\n
\n
define(\'ace/search_highlight\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/lib/oop\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var lang = require("./lib/lang");\n
var oop = require("./lib/oop");\n
var Range = require("./range").Range;\n
\n
var SearchHighlight = function(regExp, clazz, type) {\n
    this.setRegexp(regExp);\n
    this.clazz = clazz;\n
    this.type = type || "text";\n
};\n
\n
(function() {\n
    this.MAX_RANGES = 500;\n
    \n
    this.setRegexp = function(regExp) {\n
        if (this.regExp+"" == regExp+"")\n
            return;\n
        this.regExp = regExp;\n
        this.cache = [];\n
    };\n
\n
    this.update = function(html, markerLayer, session, config) {\n
        if (!this.regExp)\n
            return;\n
        var start = config.firstRow, end = config.lastRow;\n
\n
        for (var i = start; i <= end; i++) {\n
            var ranges = this.cache[i];\n
            if (ranges == null) {\n
                ranges = lang.getMatchOffsets(session.getLine(i), this.regExp);\n
                if (ranges.length > this.MAX_RANGES)\n
                    ranges = ranges.slice(0, this.MAX_RANGES);\n
                ranges = ranges.map(function(match) {\n
                    return new Range(i, match.offset, i, match.offset + match.length);\n
                });\n
                this.cache[i] = ranges.length ? ranges : "";\n
            }\n
\n
            for (var j = ranges.length; j --; ) {\n
                markerLayer.drawSingleLineMarker(\n
                    html, ranges[j].toScreenRange(session), this.clazz, config);\n
            }\n
        }\n
    };\n
\n
}).call(SearchHighlight.prototype);\n
\n
exports.SearchHighlight = SearchHighlight;\n
});\n
\n
define(\'ace/edit_session/folding\', [\'require\', \'exports\', \'module\' , \'ace/range\', \'ace/edit_session/fold_line\', \'ace/edit_session/fold\', \'ace/token_iterator\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
var FoldLine = require("./fold_line").FoldLine;\n
var Fold = require("./fold").Fold;\n
var TokenIterator = require("../token_iterator").TokenIterator;\n
\n
function Folding() {\n
    this.getFoldAt = function(row, column, side) {\n
        var foldLine = this.getFoldLine(row);\n
        if (!foldLine)\n
            return null;\n
\n
        var folds = foldLine.folds;\n
        for (var i = 0; i < folds.length; i++) {\n
            var fold = folds[i];\n
            if (fold.range.contains(row, column)) {\n
                if (side == 1 && fold.range.isEnd(row, column)) {\n
                    continue;\n
                } else if (side == -1 && fold.range.isStart(row, column)) {\n
                    continue;\n
                }\n
                return fold;\n
            }\n
        }\n
    };\n
    this.getFoldsInRange = function(range) {\n
        var start = range.start;\n
        var end = range.end;\n
        var foldLines = this.$foldData;\n
        var foundFolds = [];\n
\n
        start.column += 1;\n
        end.column -= 1;\n
\n
        for (var i = 0; i < foldLines.length; i++) {\n
            var cmp = foldLines[i].range.compareRange(range);\n
            if (cmp == 2) {\n
                continue;\n
            }\n
            else if (cmp == -2) {\n
                break;\n
            }\n
\n
            var folds = foldLines[i].folds;\n
            for (var j = 0; j < folds.length; j++) {\n
                var fold = folds[j];\n
                cmp = fold.range.compareRange(range);\n
                if (cmp == -2) {\n
                    break;\n
                } else if (cmp == 2) {\n
                    continue;\n
                } else\n
                if (cmp == 42) {\n
                    break;\n
                }\n
                foundFolds.push(fold);\n
            }\n
        }\n
        start.column -= 1;\n
        end.column += 1;\n
\n
        return foundFolds;\n
    };\n
    this.getAllFolds = function() {\n
        var folds = [];\n
        var foldLines = this.$foldData;\n
        \n
        function addFold(fold) {\n
            folds.push(fold);\n
        }\n
        \n
        for (var i = 0; i < foldLines.length; i++)\n
            for (var j = 0; j < foldLines[i].folds.length; j++)\n
                addFold(foldLines[i].folds[j]);\n
\n
        return folds;\n
    };\n
    this.getFoldStringAt = function(row, column, trim, foldLine) {\n
        foldLine = foldLine || this.getFoldLine(row);\n
        if (!foldLine)\n
            return null;\n
\n
        var lastFold = {\n
            end: { column: 0 }\n
        };\n
        var str, fold;\n
        for (var i = 0; i < foldLine.folds.length; i++) {\n
            fold = foldLine.folds[i];\n
            var cmp = fold.range.compareEnd(row, column);\n
            if (cmp == -1) {\n
                str = this\n
                    .getLine(fold.start.row)\n
                    .substring(lastFold.end.column, fold.start.column);\n
                break;\n
            }\n
            else if (cmp === 0) {\n
                return null;\n
            }\n
            lastFold = fold;\n
        }\n
        if (!str)\n
            str = this.getLine(fold.start.row).substring(lastFold.end.column);\n
\n
        if (trim == -1)\n
            return str.substring(0, column - lastFold.end.column);\n
        else if (trim == 1)\n
            return str.substring(column - lastFold.end.column);\n
        else\n
            return str;\n
    };\n
\n
    this.getFoldLine = function(docRow, startFoldLine) {\n
        var foldData = this.$foldData;\n
        var i = 0;\n
        if (startFoldLine)\n
            i = foldData.indexOf(startFoldLine);\n
        if (i == -1)\n
            i = 0;\n
        for (i; i < foldData.length; i++) {\n
            var foldLine = foldData[i];\n
            if (foldLine.start.row <= docRow && foldLine.end.row >= docRow) {\n
                return foldLine;\n
            } else if (foldLine.end.row > docRow) {\n
                return null;\n
            }\n
        }\n
        return null;\n
    };\n
    this.getNextFoldLine = function(docRow, startFoldLine) {\n
        var foldData = this.$foldData;\n
        var i = 0;\n
        if (startFoldLine)\n
            i = foldData.indexOf(startFoldLine);\n
        if (i == -1)\n
            i = 0;\n
        for (i; i < foldData.length; i++) {\n
            var foldLine = foldData[i];\n
            if (foldLine.end.row >= docRow) {\n
                return foldLine;\n
            }\n
        }\n
        return null;\n
    };\n
\n
    this.getFoldedRowCount = function(first, last) {\n
        var foldData = this.$foldData, rowCount = last-first+1;\n
        for (var i = 0; i < foldData.length; i++) {\n
            var foldLine = foldData[i],\n
                end = foldLine.end.row,\n
                start = foldLine.start.row;\n
            if (end >= last) {\n
                if(start < last) {\n
                    if(start >= first)\n
                        rowCount -= last-start;\n
                    else\n
                        rowCount = 0;//in one fold\n
                }\n
                break;\n
            } else if(end >= first){\n
                if (start >= first) //fold inside range\n
                    rowCount -=  end-start;\n
                else\n
                    rowCount -=  end-first+1;\n
            }\n
        }\n
        return rowCount;\n
    };\n
\n
    this.$addFoldLine = function(foldLine) {\n
        this.$foldData.push(foldLine);\n
        this.$foldData.sort(function(a, b) {\n
            return a.start.row - b.start.row;\n
        });\n
        return foldLine;\n
    };\n
    this.addFold = function(placeholder, range) {\n
        var foldData = this.$foldData;\n
        var added = false;\n
        var fold;\n
        \n
        if (placeholder instanceof Fold)\n
            fold = placeholder;\n
        else {\n
            fold = new Fold(range, placeholder);\n
            fold.collapseChildren = range.collapseChildren;\n
        }\n
        this.$clipRangeToDocument(fold.range);\n
\n
        var startRow = fold.start.row;\n
        var startColumn = fold.start.column;\n
        var endRow = fold.end.row;\n
        var endColumn = fold.end.column;\n
        if (!(startRow < endRow || \n
            startRow == endRow && startColumn <= endColumn - 2))\n
            throw new Error("The range has to be at least 2 characters width");\n
\n
        var startFold = this.getFoldAt(startRow, startColumn, 1);\n
        var endFold = this.getFoldAt(endRow, endColumn, -1);\n
        if (startFold && endFold == startFold)\n
            return startFold.addSubFold(fold);\n
\n
        if (\n
            (startFold && !startFold.range.isStart(startRow, startColumn))\n
            || (endFold && !endFold.range.isEnd(endRow, endColumn))\n
        ) {\n
            throw new Error("A fold can\'t intersect already existing fold" + fold.range + startFold.range);\n
        }\n
        var folds = this.getFoldsInRange(fold.range);\n
        if (folds.length > 0) {\n
            this.removeFolds(folds);\n
            folds.forEach(function(subFold) {\n
                fold.addSubFold(subFold);\n
            });\n
        }\n
\n
        for (var i = 0; i < foldData.length; i++) {\n
            var foldLine = foldData[i];\n
            if (endRow == foldLine.start.row) {\n
                foldLine.addFold(fold);\n
                added = true;\n
                break;\n
            } else if (startRow == foldLine.end.row) {\n
                foldLine.addFold(fold);\n
                added = true;\n
                if (!fold.sameRow) {\n
                    var foldLineNext = foldData[i + 1];\n
                    if (foldLineNext && foldLineNext.start.row == endRow) {\n
                        foldLine.merge(foldLineNext);\n
                        break;\n
                    }\n
                }\n
                break;\n
            } else if (endRow <= foldLine.start.row) {\n
                break;\n
            }\n
        }\n
\n
        if (!added)\n
            foldLine = this.$addFoldLine(new FoldLine(this.$foldData, fold));\n
\n
        if (this.$useWrapMode)\n
            this.$updateWrapData(foldLine.start.row, foldLine.start.row);\n
        else\n
            this.$updateRowLengthCache(foldLine.start.row, foldLine.start.row);\n
        this.$modified = true;\n
        this._emit("changeFold", { data: fold, action: "add" });\n
\n
        return fold;\n
    };\n
\n
    this.addFolds = function(folds) {\n
        folds.forEach(function(fold) {\n
            this.addFold(fold);\n
        }, this);\n
    };\n
\n
    this.removeFold = function(fold) {\n
        var foldLine = fold.foldLine;\n
        var startRow = foldLine.start.row;\n
        var endRow = foldLine.end.row;\n
\n
        var foldLines = this.$foldData;\n
        var folds = foldLine.folds;\n
        if (folds.length == 1) {\n
            foldLines.splice(foldLines.indexOf(foldLine), 1);\n
        } else\n
        if (foldLine.range.isEnd(fold.end.row, fold.end.column)) {\n
            folds.pop();\n
            foldLine.end.row = folds[folds.length - 1].end.row;\n
            foldLine.end.column = folds[folds.length - 1].end.column;\n
        } else\n
        if (foldLine.range.isStart(fold.start.row, fold.start.column)) {\n
            folds.shift();\n
            foldLine.start.row = folds[0].start.row;\n
            foldLine.start.column = folds[0].start.column;\n
        } else\n
        if (fold.sameRow) {\n
            folds.splice(folds.indexOf(fold), 1);\n
        } else\n
        {\n
            var newFoldLine = foldLine.split(fold.start.row, fold.start.column);\n
            folds = newFoldLine.folds;\n
            folds.shift();\n
            newFoldLine.start.row = folds[0].start.row;\n
            newFoldLine.start.column = folds[0].start.column;\n
        }\n
\n
        if (!this.$updating) {\n
            if (this.$useWrapMode)\n
                this.$updateWrapData(startRow, endRow);\n
            else\n
                this.$updateRowLengthCache(startRow, endRow);\n
        }\n
        this.$modified = true;\n
        this._emit("changeFold", { data: fold, action: "remove" });\n
    };\n
\n
    this.removeFolds = function(folds) {\n
        var cloneFolds = [];\n
        for (var i = 0; i < folds.length; i++) {\n
            cloneFolds.push(folds[i]);\n
        }\n
\n
        cloneFolds.forEach(function(fold) {\n
            this.removeFold(fold);\n
        }, this);\n
        this.$modified = true;\n
    };\n
\n
    this.expandFold = function(fold) {\n
        this.removeFold(fold);        \n
        fold.subFolds.forEach(function(subFold) {\n
            fold.restoreRange(subFold);\n
            this.addFold(subFold);\n
        }, this);\n
        if (fold.collapseChildren > 0) {\n
            this.foldAll(fold.start.row+1, fold.end.row, fold.collapseChildren-1);\n
        }\n
        fold.subFolds = [];\n
    };\n
\n
    this.expandFolds = function(folds) {\n
        folds.forEach(function(fold) {\n
            this.expandFold(fold);\n
        }, this);\n
    };\n
\n
    this.unfold = function(location, expandInner) {\n
        var range, folds;\n
        if (location == null) {\n
            range = new Range(0, 0, this.getLength(), 0);\n
            expandInner = true;\n
        } else if (typeof location == "number")\n
            range = new Range(location, 0, location, this.getLine(location).length);\n
        else if ("row" in location)\n
            range = Range.fromPoints(location, location);\n
        else\n
            range = location;\n
\n
        folds = this.getFoldsInRange(range);\n
        if (expandInner) {\n
            this.removeFolds(folds);\n
        } else {\n
            while (folds.length) {\n
                this.expandFolds(folds);\n
                folds = this.getFoldsInRange(range);\n
            }\n
        }\n
    };\n
    this.isRowFolded = function(docRow, startFoldRow) {\n
        return !!this.getFoldLine(docRow, startFoldRow);\n
    };\n
\n
    this.getRowFoldEnd = function(docRow, startFoldRow) {\n
        var foldLine = this.getFoldLine(docRow, startFoldRow);\n
        return foldLine ? foldLine.end.row : docRow;\n
    };\n
\n
    this.getRowFoldStart = function(docRow, startFoldRow) {\n
        var foldLine = this.getFoldLine(docRow, startFoldRow);\n
        return foldLine ? foldLine.start.row : docRow;\n
    };\n
\n
    this.getFoldDisplayLine = function(foldLine, endRow, endColumn, startRow, startColumn) {\n
        if (startRow == null) {\n
            startRow = foldLine.start.row;\n
            startColumn = 0;\n
        }\n
\n
        if (endRow == null) {\n
            endRow = foldLine.end.row;\n
            endColumn = this.getLine(endRow).length;\n
        }\n
        var doc = this.doc;\n
        var textLine = "";\n
\n
        foldLine.walk(function(placeholder, row, column, lastColumn) {\n
            if (row < startRow)\n
                return;\n
            if (row == startRow) {\n
                if (column < startColumn)\n
                    return;\n
                lastColumn = Math.max(startColumn, lastColumn);\n
            }\n
\n
            if (placeholder != null) {\n
                textLine += placeholder;\n
            } else {\n
                textLine += doc.getLine(row).substring(lastColumn, column);\n
            }\n
        }, endRow, endColumn);\n
        return textLine;\n
    };\n
\n
    this.getDisplayLine = function(row, endColumn, startRow, startColumn) {\n
        var foldLine = this.getFoldLine(row);\n
\n
        if (!foldLine) {\n
            var line;\n
            line = this.doc.getLine(row);\n
            return line.substring(startColumn || 0, endColumn || line.length);\n
        } else {\n
            return this.getFoldDisplayLine(\n
                foldLine, row, endColumn, startRow, startColumn);\n
        }\n
    };\n
\n
    this.$cloneFoldData = function() {\n
        var fd = [];\n
        fd = this.$foldData.map(function(foldLine) {\n
            var folds = foldLine.folds.map(function(fold) {\n
                return fold.clone();\n
            });\n
            return new FoldLine(fd, folds);\n
        });\n
\n
        return fd;\n
    };\n
\n
    this.toggleFold = function(tryToUnfold) {\n
        var selection = this.selection;\n
        var range = selection.getRange();\n
        var fold;\n
        var bracketPos;\n
\n
        if (range.isEmpty()) {\n
            var cursor = range.start;\n
            fold = this.getFoldAt(cursor.row, cursor.column);\n
\n
            if (fold) {\n
                this.expandFold(fold);\n
                return;\n
            } else if (bracketPos = this.findMatchingBracket(cursor)) {\n
                if (range.comparePoint(bracketPos) == 1) {\n
                    range.end = bracketPos;\n
                } else {\n
                    range.start = bracketPos;\n
                    range.start.column++;\n
                    range.end.column--;\n
                }\n
            } else if (bracketPos = this.findMatchingBracket({row: cursor.row, column: cursor.column + 1})) {\n
                if (range.comparePoint(bracketPos) == 1)\n
                    range.end = bracketPos;\n
                else\n
                    range.start = bracketPos;\n
\n
                range.start.column++;\n
            } else {\n
                range = this.getCommentFoldRange(cursor.row, cursor.column) || range;\n
            }\n
        } else {\n
            var folds = this.getFoldsInRange(range);\n
            if (tryToUnfold && folds.length) {\n
                this.expandFolds(folds);\n
                return;\n
            } else if (folds.length == 1 ) {\n
                fold = folds[0];\n
            }\n
        }\n
\n
        if (!fold)\n
            fold = this.getFoldAt(range.start.row, range.start.column);\n
\n
        if (fold && fold.range.toString() == range.toString()) {\n
            this.expandFold(fold);\n
            return;\n
        }\n
\n
        var placeholder = "...";\n
        if (!range.isMultiLine()) {\n
            placeholder = this.getTextRange(range);\n
            if(placeholder.length < 4)\n
                return;\n
            placeholder = placeholder.trim().substring(0, 2) + "..";\n
        }\n
\n
        this.addFold(placeholder, range);\n
    };\n
\n
    this.getCommentFoldRange = function(row, column, dir) {\n
        var iterator = new TokenIterator(this, row, column);\n
        var token = iterator.getCurrentToken();\n
        if (token && /^comment|string/.test(token.type)) {\n
            var range = new Range();\n
            var re = new RegExp(token.type.replace(/\\..*/, "\\\\."));\n
            if (dir != 1) {\n
                do {\n
                    token = iterator.stepBackward();\n
                } while(token && re.test(token.type));\n
                iterator.stepForward();\n
            }\n
            \n
            range.start.row = iterator.getCurrentTokenRow();\n
            range.start.column = iterator.getCurrentTokenColumn() + 2;\n
\n
            iterator = new TokenIterator(this, row, column);\n
            \n
            if (dir != -1) {\n
                do {\n
                    token = iterator.stepForward();\n
                } while(token && re.test(token.type));\n
                token = iterator.stepBackward();\n
            } else\n
                token = iterator.getCurrentToken();\n
\n
            range.end.row = iterator.getCurrentTokenRow();\n
            range.end.column = iterator.getCurrentTokenColumn() + token.value.length - 2;\n
            return range;\n
        }\n
    };\n
\n
    this.foldAll = function(startRow, endRow, depth) {\n
        if (depth == undefined)\n
            depth = 100000; // JSON.stringify doesn\'t hanle Infinity\n
        var foldWidgets = this.foldWidgets;\n
        endRow = endRow || this.getLength();\n
        startRow = startRow || 0;\n
        for (var row = startRow; row < endRow; row++) {\n
            if (foldWidgets[row] == null)\n
                foldWidgets[row] = this.getFoldWidget(row);\n
            if (foldWidgets[row] != "start")\n
                continue;\n
\n
            var range = this.getFoldWidgetRange(row);\n
            var rangeEndRow = range.end.row;\n
            if (range && range.isMultiLine()\n
                && rangeEndRow <= endRow\n
                && range.start.row >= startRow\n
            ) try {\n
                var fold = this.addFold("...", range);\n
                fold.collapseChildren = depth;\n
                row = rangeEndRow;\n
            } catch(e) {}\n
        }\n
    };\n
    this.$foldStyles = {\n
        "manual": 1,\n
        "markbegin": 1,\n
        "markbeginend": 1\n
    };\n
    this.$foldStyle = "markbegin";\n
    this.setFoldStyle = function(style) {\n
        if (!this.$foldStyles[style])\n
            throw new Error("invalid fold style: " + style + "[" + Object.keys(this.$foldStyles).join(", ") + "]");\n
        \n
        if (this.$foldStyle == style)\n
            return;\n
\n
        this.$foldStyle = style;\n
        \n
        if (style == "manual")\n
            this.unfold();\n
        var mode = this.$foldMode;\n
        this.$setFolding(null);\n
        this.$setFolding(mode);\n
    };\n
\n
    this.$setFolding = function(foldMode) {\n
        if (this.$foldMode == foldMode)\n
            return;\n
            \n
        this.$foldMode = foldMode;\n
        \n
        this.removeListener(\'change\', this.$updateFoldWidgets);\n
        this._emit("changeAnnotation");\n
        \n
        if (!foldMode || this.$foldStyle == "manual") {\n
            this.foldWidgets = null;\n
            return;\n
        }\n
        \n
        this.foldWidgets = [];\n
        this.getFoldWidget = foldMode.getFoldWidget.bind(foldMode, this, this.$foldStyle);\n
        this.getFoldWidgetRange = foldMode.getFoldWidgetRange.bind(foldMode, this, this.$foldStyle);\n
        \n
        this.$updateFoldWidgets = this.updateFoldWidgets.bind(this);\n
        this.on(\'change\', this.$updateFoldWidgets);\n
        \n
    };\n
\n
    this.getParentFoldRangeData = function (row, ignoreCurrent) {\n
        var fw = this.foldWidgets;\n
        if (!fw || (ignoreCurrent && fw[row]))\n
            return {};\n
\n
        var i = row - 1, firstRange;\n
        while (i >= 0) {\n
            var c = fw[i];\n
            if (c == null)\n
                c = fw[i] = this.getFoldWidget(i);\n
\n
            if (c == "start") {\n
                var range = this.getFoldWidgetRange(i);\n
                if (!firstRange)\n
                    firstRange = range;\n
                if (range && range.end.row >= row)\n
                    break;\n
            }\n
            i--;\n
        }\n
\n
        return {\n
            range: i !== -1 && range,\n
            firstRange: firstRange\n
        };\n
    }\n
\n
    this.onFoldWidgetClick = function(row, e) {\n
        var type = this.getFoldWidget(row);\n
        var line = this.getLine(row);\n
        e = e.domEvent;\n
        var children = e.shiftKey;\n
        var all = e.ctrlKey || e.metaKey;\n
        var siblings = e.altKey;\n
\n
        var dir = type === "end" ? -1 : 1;\n
        var fold = this.getFoldAt(row, dir === -1 ? 0 : line.length, dir);\n
\n
        if (fold) {\n
            if (children || all)\n
                this.removeFold(fold);\n
            else\n
                this.expandFold(fold);\n
            return;\n
        }\n
\n
        var range = this.getFoldWidgetRange(row);\n
        if (range && !range.isMultiLine()) {\n
            fold = this.getFoldAt(range.start.row, range.start.column, 1);\n
            if (fold && range.isEqual(fold.range)) {\n
                this.removeFold(fold);\n
                return;\n
            }\n
        }\n
        \n
        if (siblings) {\n
            var data = this.getParentFoldRangeData(row);\n
            if (data.range) {\n
                var startRow = data.range.start.row + 1;\n
                var endRow = data.range.end.row;\n
            }\n
            this.foldAll(startRow, endRow, all ? 10000 : 0);\n
        } else if (children) {\n
            var endRow = range ? range.end.row : this.getLength();\n
            this.foldAll(row + 1, range.end.row, all ? 10000 : 0);\n
        } else if (range) {\n
            if (all) \n
                range.collapseChildren = 10000;\n
            this.addFold("...", range);\n
        }\n
        \n
        if (!range)\n
            (e.target || e.srcElement).className += " ace_invalid"\n
    };\n
\n
    this.updateFoldWidgets = function(e) {\n
        var delta = e.data;\n
        var range = delta.range;\n
        var firstRow = range.start.row;\n
        var len = range.end.row - firstRow;\n
\n
        if (len === 0) {\n
            this.foldWidgets[firstRow] = null;\n
        } else if (delta.action == "removeText" || delta.action == "removeLines") {\n
            this.foldWidgets.splice(firstRow, len + 1, null);\n
        } else {\n
            var args = Array(len + 1);\n
            args.unshift(firstRow, 1);\n
            this.foldWidgets.splice.apply(this.foldWidgets, args);\n
        }\n
    };\n
\n
}\n
\n
exports.Folding = Folding;\n
\n
});\n
\n
define(\'ace/edit_session/fold_line\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
function FoldLine(foldData, folds) {\n
    this.foldData = foldData;\n
    if (Array.isArray(folds)) {\n
        this.folds = folds;\n
    } else {\n
        folds = this.folds = [ folds ];\n
    }\n
\n
    var last = folds[folds.length - 1]\n
    this.range = new Range(folds[0].start.row, folds[0].start.column,\n
                           last.end.row, last.end.column);\n
    this.start = this.range.start;\n
    this.end   = this.range.end;\n
\n
    this.folds.forEach(function(fold) {\n
        fold.setFoldLine(this);\n
    }, this);\n
}\n
\n
(function() {\n
    this.shiftRow = function(shift) {\n
        this.start.row += shift;\n
        this.end.row += shift;\n
        this.folds.forEach(function(fold) {\n
            fold.start.row += shift;\n
            fold.end.row += shift;\n
        });\n
    }\n
\n
    this.addFold = function(fold) {\n
        if (fold.sameRow) {\n
            if (fold.start.row < this.startRow || fold.endRow > this.endRow) {\n
                throw new Error("Can\'t add a fold to this FoldLine as it has no connection");\n
            }\n
            this.folds.push(fold);\n
            this.folds.sort(function(a, b) {\n
                return -a.range.compareEnd(b.start.row, b.start.column);\n
            });\n
            if (this.range.compareEnd(fold.start.row, fold.start.column) > 0) {\n
                this.end.row = fold.end.row;\n
                this.end.column =  fold.end.column;\n
            } else if (this.range.compareStart(fold.end.row, fold.end.column) < 0) {\n
                this.start.row = fold.start.row;\n
                this.start.column = fold.start.column;\n
            }\n
        } else if (fold.start.row == this.end.row) {\n
            this.folds.push(fold);\n
            this.end.row = fold.end.row;\n
            this.end.column = fold.end.column;\n
        } else if (fold.end.row == this.start.row) {\n
            this.folds.unshift(fold);\n
            this.start.row = fold.start.row;\n
            this.start.column = fold.start.column;\n
        } else {\n
            throw new Error("Trying to add fold to FoldRow that doesn\'t have a matching row");\n
        }\n
        fold.foldLine = this;\n
    }\n
\n
    this.containsRow = function(row) {\n
        return row >= this.start.row && row <= this.end.row;\n
    }\n
\n
    this.walk = function(callback, endRow, endColumn) {\n
        var lastEnd = 0,\n
            folds = this.folds,\n
            fold,\n
            comp, stop, isNewRow = true;\n
\n
        if (endRow == null) {\n
            endRow = this.end.row;\n
            endColumn = this.end.column;\n
        }\n
\n
        for (var i = 0; i < folds.length; i++) {\n
            fold = folds[i];\n
\n
            comp = fold.range.compareStart(endRow, endColumn);\n
            if (comp == -1) {\n
                callback(null, endRow, endColumn, lastEnd, isNewRow);\n
                return;\n
            }\n
\n
            stop = callback(null, fold.start.row, fold.start.column, lastEnd, isNewRow);\n
            stop = !stop && callback(fold.placeholder, fold.start.row, fold.start.column, lastEnd);\n
            if (stop || comp == 0) {\n
                return;\n
            }\n
            isNewRow = !fold.sameRow;\n
            lastEnd = fold.end.column;\n
        }\n
        callback(null, endRow, endColumn, lastEnd, isNewRow);\n
    }\n
\n
    this.getNextFoldTo = function(row, column) {\n
        var fold, cmp;\n
        for (var i = 0; i < this.folds.length; i++) {\n
            fold = this.folds[i];\n
            cmp = fold.range.compareEnd(row, column);\n
            if (cmp == -1) {\n
                return {\n
                    fold: fold,\n
                    kind: "after"\n
                };\n
            } else if (cmp == 0) {\n
                return {\n
                    fold: fold,\n
                    kind: "inside"\n
                }\n
            }\n
        }\n
        return null;\n
    }\n
\n
    this.addRemoveChars = function(row, column, len) {\n
        var ret = this.getNextFoldTo(row, column),\n
            fold, folds;\n
        if (ret) {\n
            fold = ret.fold;\n
            if (ret.kind == "inside"\n
                && fold.start.column != column\n
                && fold.start.row != row)\n
            {\n
                window.console && window.console.log(row, column, fold);\n
            } else if (fold.start.row == row) {\n
                folds = this.folds;\n
                var i = folds.indexOf(fold);\n
                if (i == 0) {\n
                    this.start.column += len;\n
                }\n
                for (i; i < folds.length; i++) {\n
                    fold = folds[i];\n
                    fold.start.column += len;\n
                    if (!fold.sameRow) {\n
                        return;\n
                    }\n
                    fold.end.column += len;\n
                }\n
                this.end.column += len;\n
            }\n
        }\n
    }\n
\n
    this.split = function(row, column) {\n
        var fold = this.getNextFoldTo(row, column).fold;\n
        var folds = this.folds;\n
        var foldData = this.foldData;\n
\n
        if (!fold)\n
            return null;\n
\n
        var i = folds.indexOf(fold);\n
        var foldBefore = folds[i - 1];\n
        this.end.row = foldBefore.end.row;\n
        this.end.column = foldBefore.end.column;\n
        folds = folds.splice(i, folds.length - i);\n
\n
        var newFoldLine = new FoldLine(foldData, folds);\n
        foldData.splice(foldData.indexOf(this) + 1, 0, newFoldLine);\n
        return newFoldLine;\n
    }\n
\n
    this.merge = function(foldLineNext) {\n
        var folds = foldLineNext.folds;\n
        for (var i = 0; i < folds.length; i++) {\n
            this.addFold(folds[i]);\n
        }\n
        var foldData = this.foldData;\n
        foldData.splice(foldData.indexOf(foldLineNext), 1);\n
    }\n
\n
    this.toString = function() {\n
        var ret = [this.range.toString() + ": [" ];\n
\n
        this.folds.forEach(function(fold) {\n
            ret.push("  " + fold.toString());\n
        });\n
        ret.push("]")\n
        return ret.join("\\n");\n
    }\n
\n
    this.idxToPosition = function(idx) {\n
        var lastFoldEndColumn = 0;\n
        var fold;\n
\n
        for (var i = 0; i < this.folds.length; i++) {\n
            var fold = this.folds[i];\n
\n
            idx -= fold.start.column - lastFoldEndColumn;\n
            if (idx < 0) {\n
                return {\n
                    row: fold.start.row,\n
                    column: fold.start.column + idx\n
                };\n
            }\n
\n
            idx -= fold.placeholder.length;\n
            if (idx < 0) {\n
                return fold.start;\n
            }\n
\n
            lastFoldEndColumn = fold.end.column;\n
        }\n
\n
        return {\n
            row: this.end.row,\n
            column: this.end.column + idx\n
        };\n
    }\n
}).call(FoldLine.prototype);\n
\n
exports.FoldLine = FoldLine;\n
});\n
\n
define(\'ace/edit_session/fold\', [\'require\', \'exports\', \'module\' , \'ace/range\', \'ace/range_list\', \'ace/lib/oop\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
var RangeList = require("../range_list").RangeList;\n
var oop = require("../lib/oop")\n
var Fold = exports.Fold = function(range, placeholder) {\n
    this.foldLine = null;\n
    this.placeholder = placeholder;\n
    this.range = range;\n
    this.start = range.start;\n
    this.end = range.end;\n
\n
    this.sameRow = range.start.row == range.end.row;\n
    this.subFolds = this.ranges = [];\n
};\n
\n
oop.inherits(Fold, RangeList);\n
\n
(function() {\n
\n
    this.toString = function() {\n
        return \'"\' + this.placeholder + \'" \' + this.range.toString();\n
    };\n
\n
    this.setFoldLine = function(foldLine) {\n
        this.foldLine = foldLine;\n
        this.subFolds.forEach(function(fold) {\n
            fold.setFoldLine(foldLine);\n
        });\n
    };\n
\n
    this.clone = function() {\n
        var range = this.range.clone();\n
        var fold = new Fold(range, this.placeholder);\n
        this.subFolds.forEach(function(subFold) {\n
            fold.subFolds.push(subFold.clone());\n
        });\n
        fold.collapseChildren = this.collapseChildren;\n
        return fold;\n
    };\n
\n
    this.addSubFold = function(fold) {\n
        if (this.range.isEqual(fold))\n
            return;\n
\n
        if (!this.range.containsRange(fold))\n
            throw new Error("A fold can\'t intersect already existing fold" + fold.range + this.range);\n
        consumeRange(fold, this.start);\n
\n
        var row = fold.start.row, column = fold.start.column;\n
        for (var i = 0, cmp = -1; i < this.subFolds.length; i++) {\n
            cmp = this.subFolds[i].range.compare(row, column);\n
            if (cmp != 1)\n
                break;\n
        }\n
        var afterStart = this.subFolds[i];\n
\n
        if (cmp == 0)\n
            return afterStart.addSubFold(fold);\n
        var row = fold.range.end.row, column = fold.range.end.column;\n
        for (var j = i, cmp = -1; j < this.subFolds.length; j++) {\n
            cmp = this.subFolds[j].range.compare(row, column);\n
            if (cmp != 1)\n
                break;\n
        }\n
        var afterEnd = this.subFolds[j];\n
\n
        if (cmp == 0)\n
            throw new Error("A fold can\'t intersect already existing fold" + fold.range + this.range);\n
\n
        var consumedFolds = this.subFolds.splice(i, j - i, fold);\n
        fold.setFoldLine(this.foldLine);\n
\n
        return fold;\n
    };\n
    \n
    this.restoreRange = function(range) {\n
        return restoreRange(range, this.start);\n
    };\n
\n
}).call(Fold.prototype);\n
\n
function consumePoint(point, anchor) {\n
    point.row -= anchor.row;\n
    if (point.row == 0)\n
        point.column -= anchor.column;\n
}\n
function consumeRange(range, anchor) {\n
    consumePoint(range.start, anchor);\n
    consumePoint(range.end, anchor);\n
}\n
function restorePoint(point, anchor) {\n
    if (point.row == 0)\n
        point.column += anchor.column;\n
    point.row += anchor.row;\n
}\n
function restoreRange(range, anchor) {\n
    restorePoint(range.start, anchor);\n
    restorePoint(range.end, anchor);\n
}\n
\n
});\n
\n
define(\'ace/range_list\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
\n
var Range = require("./range").Range;\n
var comparePoints = Range.comparePoints;\n
\n
var RangeList = function() {\n
    this.ranges = [];\n
};\n
\n
(function() {\n
    this.comparePoints = comparePoints;\n
\n
    this.pointIndex = function(pos, excludeEdges, startIndex) {\n
        var list = this.ranges;\n
\n
        for (var i = startIndex || 0; i < list.length; i++) {\n
            var range = list[i];\n
            var cmpEnd = comparePoints(pos, range.end);\n
            if (cmpEnd > 0)\n
                continue;\n
            var cmpStart = comparePoints(pos, range.start);\n
            if (cmpEnd === 0)\n
                return excludeEdges && cmpStart !== 0 ? -i-2 : i;\n
            if (cmpStart > 0 || (cmpStart === 0 && !excludeEdges))\n
                return i;\n
\n
            return -i-1;\n
        }\n
        return -i - 1;\n
    };\n
\n
    this.add = function(range) {\n
        var excludeEdges = !range.isEmpty();\n
        var startIndex = this.pointIndex(range.start, excludeEdges);\n
        if (startIndex < 0)\n
            startIndex = -startIndex - 1;\n
\n
        var endIndex = this.pointIndex(range.end, excludeEdges, startIndex);\n
\n
        if (endIndex < 0)\n
            endIndex = -endIndex - 1;\n
        else\n
            endIndex++;\n
        return this.ranges.splice(startIndex, endIndex - startIndex, range);\n
    };\n
\n
    this.addList = function(list) {\n
        var removed = [];\n
        for (var i = list.length; i--; ) {\n
            removed.push.call(removed, this.add(list[i]));\n
        }\n
        return removed;\n
    };\n
\n
    this.substractPoint = function(pos) {\n
        var i = this.pointIndex(pos);\n
\n
        if (i >= 0)\n
            return this.ranges.splice(i, 1);\n
    };\n
    this.merge = function() {\n
        var removed = [];\n
        var list = this.ranges;\n
        \n
        list = list.sort(function(a, b) {\n
            return comparePoints(a.start, b.start);\n
        });\n
        \n
        var next = list[0], range;\n
        for (var i = 1; i < list.length; i++) {\n
            range = next;\n
            next = list[i];\n
            var cmp = comparePoints(range.end, next.start);\n
            if (cmp < 0)\n
                continue;\n
\n
            if (cmp == 0 && !range.isEmpty() && !next.isEmpty())\n
                continue;\n
\n
            if (comparePoints(range.end, next.end) < 0) {\n
                range.end.row = next.end.row;\n
                range.end.column = next.end.column;\n
            }\n
\n
            list.splice(i, 1);\n
            removed.push(next);\n
            next = range;\n
            i--;\n
        }\n
        \n
        this.ranges = list;\n
\n
        return removed;\n
    };\n
\n
    this.contains = function(row, column) {\n
        return this.pointIndex({row: row, column: column}) >= 0;\n
    };\n
\n
    this.containsPoint = function(pos) {\n
        return this.pointIndex(pos) >= 0;\n
    };\n
\n
    this.rangeAtPoint = function(pos) {\n
        var i = this.pointIndex(pos);\n
        if (i >= 0)\n
            return this.ranges[i];\n
    };\n
\n
\n
    this.clipRows = function(startRow, endRow) {\n
        var list = this.ranges;\n
        if (list[0].start.row > endRow || list[list.length - 1].start.row < startRow)\n
            return [];\n
\n
        var startIndex = this.pointIndex({row: startRow, column: 0});\n
        if (startIndex < 0)\n
            startIndex = -startIndex - 1;\n
        var endIndex = this.pointIndex({row: endRow, column: 0}, startIndex);\n
        if (endIndex < 0)\n
            endIndex = -endIndex - 1;\n
\n
        var clipped = [];\n
        for (var i = startIndex; i < endIndex; i++) {\n
            clipped.push(list[i]);\n
        }\n
        return clipped;\n
    };\n
\n
    this.removeAll = function() {\n
        return this.ranges.splice(0, this.ranges.length);\n
    };\n
\n
    this.attach = function(session) {\n
        if (this.session)\n
            this.detach();\n
\n
        this.session = session;\n
        this.onChange = this.$onChange.bind(this);\n
\n
        this.session.on(\'change\', this.onChange);\n
    };\n
\n
    this.detach = function() {\n
        if (!this.session)\n
            return;\n
        this.session.removeListener(\'change\', this.onChange);\n
        this.session = null;\n
    };\n
\n
    this.$onChange = function(e) {\n
        var changeRange = e.data.range;\n
        if (e.data.action[0] == "i"){\n
            var start = changeRange.start;\n
            var end = changeRange.end;\n
        } else {\n
            var end = changeRange.start;\n
            var start = changeRange.end;\n
        }\n
        var startRow = start.row;\n
        var endRow = end.row;\n
        var lineDif = endRow - startRow;\n
\n
        var colDiff = -start.column + end.column;\n
        var ranges = this.ranges;\n
\n
        for (var i = 0, n = ranges.length; i < n; i++) {\n
            var r = ranges[i];\n
            if (r.end.row < startRow)\n
                continue;\n
            if (r.start.row > startRow)\n
                break;\n
\n
            if (r.start.row == startRow && r.start.column >= start.column ) {\n
                if (r.start.column == start.column && this.$insertRight) {\n
                } else {\n
                    r.start.column += colDiff;\n
                    r.start.row += lineDif;\n
                }\n
            }\n
            if (r.end.row == startRow && r.end.column >= start.column) {\n
                if (r.end.column == start.column && this.$insertRight) {\n
                    continue;\n
                }\n
                if (r.end.column == start.column && colDiff > 0 && i < n - 1) {                \n
                    if (r.end.column > r.start.column && r.end.column == ranges[i+1].start.column)\n
                        r.end.column -= colDiff;\n
                }\n
                r.end.column += colDiff;\n
                r.end.row += lineDif;\n
            }\n
        }\n
\n
        if (lineDif != 0 && i < n) {\n
            for (; i < n; i++) {\n
                var r = ranges[i];\n
                r.start.row += lineDif;\n
                r.end.row += lineDif;\n
            }\n
        }\n
    };\n
\n
}).call(RangeList.prototype);\n
\n
exports.RangeList = RangeList;\n
});\n
\n
define(\'ace/edit_session/bracket_match\', [\'require\', \'exports\', \'module\' , \'ace/token_iterator\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var TokenIterator = require("../token_iterator").TokenIterator;\n
var Range = require("../range").Range;\n
\n
\n
function BracketMatch() {\n
\n
    this.findMatchingBracket = function(position, chr) {\n
        if (position.column == 0) return null;\n
\n
        var charBeforeCursor = chr || this.getLine(position.row).charAt(position.column-1);\n
        if (charBeforeCursor == "") return null;\n
\n
        var match = charBeforeCursor.match(/([\\(\\[\\{])|([\\)\\]\\}])/);\n
        if (!match)\n
            return null;\n
\n
        if (match[1])\n
            return this.$findClosingBracket(match[1], position);\n
        else\n
            return this.$findOpeningBracket(match[2], position);\n
    };\n
    \n
    this.getBracketRange = function(pos) {\n
        var line = this.getLine(pos.row);\n
        var before = true, range;\n
\n
        var chr = line.charAt(pos.column-1);\n
        var match = chr && chr.match(/([\\(\\[\\{])|([\\)\\]\\}])/);\n
        if (!match) {\n
            chr = line.charAt(pos.column);\n
            pos = {row: pos.row, column: pos.column + 1};\n
            match = chr && chr.match(/([\\(\\[\\{])|([\\)\\]\\}])/);\n
            before = false;\n
        }\n
        if (!match)\n
            return null;\n
\n
        if (match[1]) {\n
            var bracketPos = this.$findClosingBracket(match[1], pos);\n
            if (!bracketPos)\n
                return null;\n
            range = Range.fromPoints(pos, bracketPos);\n
            if (!before) {\n
                range.end.column++;\n
                range.start.column--;\n
            }\n
            range.cursor = range.end;\n
        } else {\n
            var bracketPos = this.$findOpeningBracket(match[2], pos);\n
            if (!bracketPos)\n
                return null;\n
            range = Range.fromPoints(bracketPos, pos);\n
            if (!before) {\n
                range.start.column++;\n
                range.end.column--;\n
            }\n
            range.cursor = range.start;\n
        }\n
        \n
        return range;\n
    };\n
\n
    this.$brackets = {\n
        ")": "(",\n
        "(": ")",\n
        "]": "[",\n
        "[": "]",\n
        "{": "}",\n
        "}": "{"\n
    };\n
\n
    this.$findOpeningBracket = function(bracket, position, typeRe) {\n
        var openBracket = this.$brackets[bracket];\n
        var depth = 1;\n
\n
        var iterator = new TokenIterator(this, position.row, position.column);\n
        var token = iterator.getCurrentToken();\n
        if (!token)\n
            token = iterator.stepForward();\n
        if (!token)\n
            return;\n
        \n
         if (!typeRe){\n
            typeRe = new RegExp(\n
                "(\\\\.?" +\n
                token.type.replace(".", "\\\\.").replace("rparen", ".paren")\n
                + ")+"\n
            );\n
        }\n
        var valueIndex = position.column - iterator.getCurrentTokenColumn() - 2;\n
        var value = token.value;\n
        \n
        while (true) {\n
        \n
            while (valueIndex >= 0) {\n
                var chr = value.charAt(valueIndex);\n
                if (chr == openBracket) {\n
                    depth -= 1;\n
                    if (depth == 0) {\n
                        return {row: iterator.getCurrentTokenRow(),\n
                            column: valueIndex + iterator.getCurrentTokenColumn()};\n
                    }\n
                }\n
                else if (chr == bracket) {\n
                    depth += 1;\n
                }\n
                valueIndex -= 1;\n
            }\n
            do {\n
                token = iterator.stepBackward();\n
            } while (token && !typeRe.test(token.type));\n
\n
            if (token == null)\n
                break;\n
                \n
            value = token.value;\n
            valueIndex = value.length - 1;\n
        }\n
        \n
        return null;\n
    };\n
\n
    this.$findClosingBracket = function(bracket, position, typeRe) {\n
        var closingBracket = this.$brackets[bracket];\n
        var depth = 1;\n
\n
        var iterator = new TokenIterator(this, position.row, position.column);\n
        var token = iterator.getCurrentToken();\n
        if (!token)\n
            token = iterator.stepForward();\n
        if (!token)\n
            return;\n
\n
        if (!typeRe){\n
            typeRe = new RegExp(\n
                "(\\\\.?" +\n
                token.type.replace(".", "\\\\.").replace("lparen", ".paren")\n
                + ")+"\n
            );\n
        }\n
        var valueIndex = position.column - iterator.getCurrentTokenColumn();\n
\n
        while (true) {\n
\n
            var value = token.value;\n
            var valueLength = value.length;\n
            while (valueIndex < valueLength) {\n
                var chr = value.charAt(valueIndex);\n
                if (chr == closingBracket) {\n
                    depth -= 1;\n
                    if (depth == 0) {\n
                        return {row: iterator.getCurrentTokenRow(),\n
                            column: valueIndex + iterator.getCurrentTokenColumn()};\n
                    }\n
                }\n
                else if (chr == bracket) {\n
                    depth += 1;\n
                }\n
                valueIndex += 1;\n
            }\n
            do {\n
                token = iterator.stepForward();\n
            } while (token && !typeRe.test(token.type));\n
\n
            if (token == null)\n
                break;\n
\n
            valueIndex = 0;\n
        }\n
        \n
        return null;\n
    };\n
}\n
exports.BracketMatch = BracketMatch;\n
\n
});\n
\n
define(\'ace/search\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/lib/oop\', \'ace/range\'], function(require, exports, module) {\n
\n
\n
var lang = require("./lib/lang");\n
var oop = require("./lib/oop");\n
var Range = require("./range").Range;\n
\n
var Search = function() {\n
    this.$options = {};\n
};\n
\n
(function() {\n
    this.set = function(options) {\n
        oop.mixin(this.$options, options);\n
        return this;\n
    };\n
    this.getOptions = function() {\n
        return lang.copyObject(this.$options);\n
    };\n
    this.setOptions = function(options) {\n
        this.$options = options;\n
    };\n
    this.find = function(session) {\n
        var iterator = this.$matchIterator(session, this.$options);\n
\n
        if (!iterator)\n
            return false;\n
\n
        var firstRange = null;\n
        iterator.forEach(function(range, row, offset) {\n
            if (!range.start) {\n
                var column = range.offset + (offset || 0);\n
                firstRange = new Range(row, column, row, column+range.length);\n
            } else\n
                firstRange = range;\n
            return true;\n
        });\n
\n
        return firstRange;\n
    };\n
    this.findAll = function(session) {\n
        var options = this.$options;\n
        if (!options.needle)\n
            return [];\n
        this.$assembleRegExp(options);\n
\n
        var range = options.range;\n
        var lines = range\n
            ? session.getLines(range.start.row, range.end.row)\n
            : session.doc.getAllLines();\n
\n
        var ranges = [];\n
        var re = options.re;\n
        if (options.$isMultiLine) {\n
            var len = re.length;\n
            var maxRow = lines.length - len;\n
            for (var row = re.offset || 0; row <= maxRow; row++) {\n
                for (var j = 0; j < len; j++)\n
                    if (lines[row + j].search(re[j]) == -1)\n
                        break;\n
                \n
                var startLine = lines[row];\n
                var line = lines[row + len - 1];\n
                var startIndex = startLine.match(re[0])[0].length;\n
                var endIndex = line.match(re[len - 1])[0].length;\n
\n
                ranges.push(new Range(\n
                    row, startLine.length - startIndex,\n
                    row + len - 1, endIndex\n
                ));\n
            }\n
        } else {\n
            for (var i = 0; i < lines.length; i++) {\n
                var matches = lang.getMatchOffsets(lines[i], re);\n
                for (var j = 0; j < matches.length; j++) {\n
                    var match = matches[j];\n
                    ranges.push(new Range(i, match.offset, i, match.offset + match.length));\n
                }\n
  

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAc=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="7" aka="AAAAAAAAAAc=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

          }\n
        }\n
\n
        if (range) {\n
            var startColumn = range.start.column;\n
            var endColumn = range.start.column;\n
            var i = 0, j = ranges.length - 1;\n
            while (i < j && ranges[i].start.column < startColumn && ranges[i].start.row == range.start.row)\n
                i++;\n
\n
            while (i < j && ranges[j].end.column > endColumn && ranges[j].end.row == range.end.row)\n
                j--;\n
            \n
            ranges = ranges.slice(i, j + 1);\n
            for (i = 0, j = ranges.length; i < j; i++) {\n
                ranges[i].start.row += range.start.row;\n
                ranges[i].end.row += range.start.row;\n
            }\n
        }\n
\n
        return ranges;\n
    };\n
    this.replace = function(input, replacement) {\n
        var options = this.$options;\n
\n
        var re = this.$assembleRegExp(options);\n
        if (options.$isMultiLine)\n
            return replacement;\n
\n
        if (!re)\n
            return;\n
\n
        var match = re.exec(input);\n
        if (!match || match[0].length != input.length)\n
            return null;\n
        \n
        replacement = input.replace(re, replacement);\n
        if (options.preserveCase) {\n
            replacement = replacement.split("");\n
            for (var i = Math.min(input.length, input.length); i--; ) {\n
                var ch = input[i];\n
                if (ch && ch.toLowerCase() != ch)\n
                    replacement[i] = replacement[i].toUpperCase();\n
                else\n
                    replacement[i] = replacement[i].toLowerCase();\n
            }\n
            replacement = replacement.join("");\n
        }\n
        \n
        return replacement;\n
    };\n
\n
    this.$matchIterator = function(session, options) {\n
        var re = this.$assembleRegExp(options);\n
        if (!re)\n
            return false;\n
\n
        var self = this, callback, backwards = options.backwards;\n
\n
        if (options.$isMultiLine) {\n
            var len = re.length;\n
            var matchIterator = function(line, row, offset) {\n
                var startIndex = line.search(re[0]);\n
                if (startIndex == -1)\n
                    return;\n
                for (var i = 1; i < len; i++) {\n
                    line = session.getLine(row + i);\n
                    if (line.search(re[i]) == -1)\n
                        return;\n
                }\n
\n
                var endIndex = line.match(re[len - 1])[0].length;\n
\n
                var range = new Range(row, startIndex, row + len - 1, endIndex);\n
                if (re.offset == 1) {\n
                    range.start.row--;\n
                    range.start.column = Number.MAX_VALUE;\n
                } else if (offset)\n
                    range.start.column += offset;\n
\n
                if (callback(range))\n
                    return true;\n
            };\n
        } else if (backwards) {\n
            var matchIterator = function(line, row, startIndex) {\n
                var matches = lang.getMatchOffsets(line, re);\n
                for (var i = matches.length-1; i >= 0; i--)\n
                    if (callback(matches[i], row, startIndex))\n
                        return true;\n
            };\n
        } else {\n
            var matchIterator = function(line, row, startIndex) {\n
                var matches = lang.getMatchOffsets(line, re);\n
                for (var i = 0; i < matches.length; i++)\n
                    if (callback(matches[i], row, startIndex))\n
                        return true;\n
            };\n
        }\n
\n
        return {\n
            forEach: function(_callback) {\n
                callback = _callback;\n
                self.$lineIterator(session, options).forEach(matchIterator);\n
            }\n
        };\n
    };\n
\n
    this.$assembleRegExp = function(options, $disableFakeMultiline) {\n
        if (options.needle instanceof RegExp)\n
            return options.re = options.needle;\n
\n
        var needle = options.needle;\n
\n
        if (!options.needle)\n
            return options.re = false;\n
\n
        if (!options.regExp)\n
            needle = lang.escapeRegExp(needle);\n
\n
        if (options.wholeWord)\n
            needle = "\\\\b" + needle + "\\\\b";\n
\n
        var modifier = options.caseSensitive ? "g" : "gi";\n
\n
        options.$isMultiLine = !$disableFakeMultiline && /[\\n\\r]/.test(needle);\n
        if (options.$isMultiLine)\n
            return options.re = this.$assembleMultilineRegExp(needle, modifier);\n
\n
        try {\n
            var re = new RegExp(needle, modifier);\n
        } catch(e) {\n
            re = false;\n
        }\n
        return options.re = re;\n
    };\n
\n
    this.$assembleMultilineRegExp = function(needle, modifier) {\n
        var parts = needle.replace(/\\r\\n|\\r|\\n/g, "$\\n^").split("\\n");\n
        var re = [];\n
        for (var i = 0; i < parts.length; i++) try {\n
            re.push(new RegExp(parts[i], modifier));\n
        } catch(e) {\n
            return false;\n
        }\n
        if (parts[0] == "") {\n
            re.shift();\n
            re.offset = 1;\n
        } else {\n
            re.offset = 0;\n
        }\n
        return re;\n
    };\n
\n
    this.$lineIterator = function(session, options) {\n
        var backwards = options.backwards == true;\n
        var skipCurrent = options.skipCurrent != false;\n
\n
        var range = options.range;\n
        var start = options.start;\n
        if (!start)\n
            start = range ? range[backwards ? "end" : "start"] : session.selection.getRange();\n
         \n
        if (start.start)\n
            start = start[skipCurrent != backwards ? "end" : "start"];\n
\n
        var firstRow = range ? range.start.row : 0;\n
        var lastRow = range ? range.end.row : session.getLength() - 1;\n
\n
        var forEach = backwards ? function(callback) {\n
                var row = start.row;\n
\n
                var line = session.getLine(row).substring(0, start.column);\n
                if (callback(line, row))\n
                    return;\n
\n
                for (row--; row >= firstRow; row--)\n
                    if (callback(session.getLine(row), row))\n
                        return;\n
\n
                if (options.wrap == false)\n
                    return;\n
\n
                for (row = lastRow, firstRow = start.row; row >= firstRow; row--)\n
                    if (callback(session.getLine(row), row))\n
                        return;\n
            } : function(callback) {\n
                var row = start.row;\n
\n
                var line = session.getLine(row).substr(start.column);\n
                if (callback(line, row, start.column))\n
                    return;\n
\n
                for (row = row+1; row <= lastRow; row++)\n
                    if (callback(session.getLine(row), row))\n
                        return;\n
\n
                if (options.wrap == false)\n
                    return;\n
\n
                for (row = firstRow, lastRow = start.row; row <= lastRow; row++)\n
                    if (callback(session.getLine(row), row))\n
                        return;\n
            };\n
        \n
        return {forEach: forEach};\n
    };\n
\n
}).call(Search.prototype);\n
\n
exports.Search = Search;\n
});\n
define(\'ace/commands/command_manager\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/keyboard/hash_handler\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var HashHandler = require("../keyboard/hash_handler").HashHandler;\n
var EventEmitter = require("../lib/event_emitter").EventEmitter;\n
\n
var CommandManager = function(platform, commands) {\n
    HashHandler.call(this, commands, platform);\n
    this.byName = this.commands;\n
    this.setDefaultHandler("exec", function(e) {\n
        return e.command.exec(e.editor, e.args || {});\n
    });\n
};\n
\n
oop.inherits(CommandManager, HashHandler);\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.exec = function(command, editor, args) {\n
        if (typeof command === \'string\')\n
            command = this.commands[command];\n
\n
        if (!command)\n
            return false;\n
\n
        if (editor && editor.$readOnly && !command.readOnly)\n
            return false;\n
\n
        var e = {editor: editor, command: command, args: args};\n
        var retvalue = this._emit("exec", e);\n
        this._signal("afterExec", e);\n
\n
        return retvalue === false ? false : true;\n
    };\n
\n
    this.toggleRecording = function(editor) {\n
        if (this.$inReplay)\n
            return;\n
\n
        editor && editor._emit("changeStatus");\n
        if (this.recording) {\n
            this.macro.pop();\n
            this.removeEventListener("exec", this.$addCommandToMacro);\n
\n
            if (!this.macro.length)\n
                this.macro = this.oldMacro;\n
\n
            return this.recording = false;\n
        }\n
        if (!this.$addCommandToMacro) {\n
            this.$addCommandToMacro = function(e) {\n
                this.macro.push([e.command, e.args]);\n
            }.bind(this);\n
        }\n
\n
        this.oldMacro = this.macro;\n
        this.macro = [];\n
        this.on("exec", this.$addCommandToMacro);\n
        return this.recording = true;\n
    };\n
\n
    this.replay = function(editor) {\n
        if (this.$inReplay || !this.macro)\n
            return;\n
\n
        if (this.recording)\n
            return this.toggleRecording(editor);\n
\n
        try {\n
            this.$inReplay = true;\n
            this.macro.forEach(function(x) {\n
                if (typeof x == "string")\n
                    this.exec(x, editor);\n
                else\n
                    this.exec(x[0], editor, x[1]);\n
            }, this);\n
        } finally {\n
            this.$inReplay = false;\n
        }\n
    };\n
\n
    this.trimMacro = function(m) {\n
        return m.map(function(x){\n
            if (typeof x[0] != "string")\n
                x[0] = x[0].name;\n
            if (!x[1])\n
                x = x[0];\n
            return x;\n
        });\n
    };\n
\n
}).call(CommandManager.prototype);\n
\n
exports.CommandManager = CommandManager;\n
\n
});\n
\n
define(\'ace/keyboard/hash_handler\', [\'require\', \'exports\', \'module\' , \'ace/lib/keys\', \'ace/lib/useragent\'], function(require, exports, module) {\n
\n
\n
var keyUtil = require("../lib/keys");\n
var useragent = require("../lib/useragent");\n
\n
function HashHandler(config, platform) {\n
    this.platform = platform || (useragent.isMac ? "mac" : "win");\n
    this.commands = {};\n
    this.commandKeyBinding = {};\n
    if (this.__defineGetter__ && this.__defineSetter__ && typeof console != "undefined" && console.error) {\n
        var warned = false;\n
        var warn = function() {\n
            if (!warned) {\n
                warned = true;\n
                console.error("commmandKeyBinding has too many m\'s. use commandKeyBinding");\n
            }\n
        };\n
        this.__defineGetter__("commmandKeyBinding", function() {\n
            warn();\n
            return this.commandKeyBinding;\n
        });\n
        this.__defineSetter__("commmandKeyBinding", function(val) {\n
            warn();\n
            return this.commandKeyBinding = val;\n
        });\n
    } else {\n
        this.commmandKeyBinding = this.commandKeyBinding;\n
    }\n
\n
    this.addCommands(config);\n
};\n
\n
(function() {\n
\n
    this.addCommand = function(command) {\n
        if (this.commands[command.name])\n
            this.removeCommand(command);\n
\n
        this.commands[command.name] = command;\n
\n
        if (command.bindKey)\n
            this._buildKeyHash(command);\n
    };\n
\n
    this.removeCommand = function(command) {\n
        var name = (typeof command === \'string\' ? command : command.name);\n
        command = this.commands[name];\n
        delete this.commands[name];\n
        var ckb = this.commandKeyBinding;\n
        for (var hashId in ckb) {\n
            for (var key in ckb[hashId]) {\n
                if (ckb[hashId][key] == command)\n
                    delete ckb[hashId][key];\n
            }\n
        }\n
    };\n
\n
    this.bindKey = function(key, command) {\n
        if(!key)\n
            return;\n
        if (typeof command == "function") {\n
            this.addCommand({exec: command, bindKey: key, name: command.name || key});\n
            return;\n
        }\n
\n
        var ckb = this.commandKeyBinding;\n
        key.split("|").forEach(function(keyPart) {\n
            var binding = this.parseKeys(keyPart, command);\n
            var hashId = binding.hashId;\n
            (ckb[hashId] || (ckb[hashId] = {}))[binding.key] = command;\n
        }, this);\n
    };\n
\n
    this.addCommands = function(commands) {\n
        commands && Object.keys(commands).forEach(function(name) {\n
            var command = commands[name];\n
            if (!command)\n
                return;\n
            \n
            if (typeof command === "string")\n
                return this.bindKey(command, name);\n
\n
            if (typeof command === "function")\n
                command = { exec: command };\n
\n
            if (!command.name)\n
                command.name = name;\n
\n
            this.addCommand(command);\n
        }, this);\n
    };\n
\n
    this.removeCommands = function(commands) {\n
        Object.keys(commands).forEach(function(name) {\n
            this.removeCommand(commands[name]);\n
        }, this);\n
    };\n
\n
    this.bindKeys = function(keyList) {\n
        Object.keys(keyList).forEach(function(key) {\n
            this.bindKey(key, keyList[key]);\n
        }, this);\n
    };\n
\n
    this._buildKeyHash = function(command) {\n
        var binding = command.bindKey;\n
        if (!binding)\n
            return;\n
\n
        var key = typeof binding == "string" ? binding: binding[this.platform];\n
        this.bindKey(key, command);\n
    };\n
    this.parseKeys = function(keys) {\n
        if (keys.indexOf(" ") != -1)\n
            keys = keys.split(/\\s+/).pop();\n
\n
        var parts = keys.toLowerCase().split(/[\\-\\+]([\\-\\+])?/).filter(function(x){return x});\n
        var key = parts.pop();\n
\n
        var keyCode = keyUtil[key];\n
        if (keyUtil.FUNCTION_KEYS[keyCode])\n
            key = keyUtil.FUNCTION_KEYS[keyCode].toLowerCase();\n
        else if (!parts.length)\n
            return {key: key, hashId: -1};\n
        else if (parts.length == 1 && parts[0] == "shift")\n
            return {key: key.toUpperCase(), hashId: -1};\n
\n
        var hashId = 0;\n
        for (var i = parts.length; i--;) {\n
            var modifier = keyUtil.KEY_MODS[parts[i]];\n
            if (modifier == null) {\n
                if (typeof console != "undefined")\n
                console.error("invalid modifier " + parts[i] + " in " + keys);\n
                return false;\n
            }\n
            hashId |= modifier;\n
        }\n
        return {key: key, hashId: hashId};\n
    };\n
\n
    this.findKeyCommand = function findKeyCommand(hashId, keyString) {\n
        var ckbr = this.commandKeyBinding;\n
        return ckbr[hashId] && ckbr[hashId][keyString];\n
    };\n
\n
    this.handleKeyboard = function(data, hashId, keyString, keyCode) {\n
        return {\n
            command: this.findKeyCommand(hashId, keyString)\n
        };\n
    };\n
\n
}).call(HashHandler.prototype)\n
\n
exports.HashHandler = HashHandler;\n
});\n
\n
define(\'ace/commands/default_commands\', [\'require\', \'exports\', \'module\' , \'ace/lib/lang\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
var lang = require("../lib/lang");\n
var config = require("../config");\n
\n
function bindKey(win, mac) {\n
    return {\n
        win: win,\n
        mac: mac\n
    };\n
}\n
\n
exports.commands = [{\n
    name: "showSettingsMenu",\n
    bindKey: bindKey("Ctrl-,", "Command-,"),\n
    exec: function(editor) {\n
        config.loadModule("ace/ext/settings_menu", function(module) {\n
            module.init(editor);\n
            editor.showSettingsMenu();\n
        });\n
    },\n
    readOnly: true\n
}, {\n
    name: "selectall",\n
    bindKey: bindKey("Ctrl-A", "Command-A"),\n
    exec: function(editor) { editor.selectAll(); },\n
    readOnly: true\n
}, {\n
    name: "centerselection",\n
    bindKey: bindKey(null, "Ctrl-L"),\n
    exec: function(editor) { editor.centerSelection(); },\n
    readOnly: true\n
}, {\n
    name: "gotoline",\n
    bindKey: bindKey("Ctrl-L", "Command-L"),\n
    exec: function(editor) {\n
        var line = parseInt(prompt("Enter line number:"), 10);\n
        if (!isNaN(line)) {\n
            editor.gotoLine(line);\n
        }\n
    },\n
    readOnly: true\n
}, {\n
    name: "fold",\n
    bindKey: bindKey("Alt-L|Ctrl-F1", "Command-Alt-L|Command-F1"),\n
    exec: function(editor) { editor.session.toggleFold(false); },\n
    readOnly: true\n
}, {\n
    name: "unfold",\n
    bindKey: bindKey("Alt-Shift-L|Ctrl-Shift-F1", "Command-Alt-Shift-L|Command-Shift-F1"),\n
    exec: function(editor) { editor.session.toggleFold(true); },\n
    readOnly: true\n
}, {\n
    name: "foldall",\n
    bindKey: bindKey("Alt-0", "Command-Option-0"),\n
    exec: function(editor) { editor.session.foldAll(); },\n
    readOnly: true\n
}, {\n
    name: "unfoldall",\n
    bindKey: bindKey("Alt-Shift-0", "Command-Option-Shift-0"),\n
    exec: function(editor) { editor.session.unfold(); },\n
    readOnly: true\n
}, {\n
    name: "findnext",\n
    bindKey: bindKey("Ctrl-K", "Command-G"),\n
    exec: function(editor) { editor.findNext(); },\n
    readOnly: true\n
}, {\n
    name: "findprevious",\n
    bindKey: bindKey("Ctrl-Shift-K", "Command-Shift-G"),\n
    exec: function(editor) { editor.findPrevious(); },\n
    readOnly: true\n
}, {\n
    name: "find",\n
    bindKey: bindKey("Ctrl-F", "Command-F"),\n
    exec: function(editor) {\n
        config.loadModule("ace/ext/searchbox", function(e) {e.Search(editor)});\n
    },\n
    readOnly: true\n
}, {\n
    name: "overwrite",\n
    bindKey: "Insert",\n
    exec: function(editor) { editor.toggleOverwrite(); },\n
    readOnly: true\n
}, {\n
    name: "selecttostart",\n
    bindKey: bindKey("Ctrl-Shift-Home", "Command-Shift-Up"),\n
    exec: function(editor) { editor.getSelection().selectFileStart(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true,\n
    group: "fileJump"\n
}, {\n
    name: "gotostart",\n
    bindKey: bindKey("Ctrl-Home", "Command-Home|Command-Up"),\n
    exec: function(editor) { editor.navigateFileStart(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true,\n
    group: "fileJump"\n
}, {\n
    name: "selectup",\n
    bindKey: bindKey("Shift-Up", "Shift-Up"),\n
    exec: function(editor) { editor.getSelection().selectUp(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "golineup",\n
    bindKey: bindKey("Up", "Up|Ctrl-P"),\n
    exec: function(editor, args) { editor.navigateUp(args.times); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selecttoend",\n
    bindKey: bindKey("Ctrl-Shift-End", "Command-Shift-Down"),\n
    exec: function(editor) { editor.getSelection().selectFileEnd(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true,\n
    group: "fileJump"\n
}, {\n
    name: "gotoend",\n
    bindKey: bindKey("Ctrl-End", "Command-End|Command-Down"),\n
    exec: function(editor) { editor.navigateFileEnd(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true,\n
    group: "fileJump"\n
}, {\n
    name: "selectdown",\n
    bindKey: bindKey("Shift-Down", "Shift-Down"),\n
    exec: function(editor) { editor.getSelection().selectDown(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "golinedown",\n
    bindKey: bindKey("Down", "Down|Ctrl-N"),\n
    exec: function(editor, args) { editor.navigateDown(args.times); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectwordleft",\n
    bindKey: bindKey("Ctrl-Shift-Left", "Option-Shift-Left"),\n
    exec: function(editor) { editor.getSelection().selectWordLeft(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotowordleft",\n
    bindKey: bindKey("Ctrl-Left", "Option-Left"),\n
    exec: function(editor) { editor.navigateWordLeft(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selecttolinestart",\n
    bindKey: bindKey("Alt-Shift-Left", "Command-Shift-Left"),\n
    exec: function(editor) { editor.getSelection().selectLineStart(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotolinestart",\n
    bindKey: bindKey("Alt-Left|Home", "Command-Left|Home|Ctrl-A"),\n
    exec: function(editor) { editor.navigateLineStart(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectleft",\n
    bindKey: bindKey("Shift-Left", "Shift-Left"),\n
    exec: function(editor) { editor.getSelection().selectLeft(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotoleft",\n
    bindKey: bindKey("Left", "Left|Ctrl-B"),\n
    exec: function(editor, args) { editor.navigateLeft(args.times); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectwordright",\n
    bindKey: bindKey("Ctrl-Shift-Right", "Option-Shift-Right"),\n
    exec: function(editor) { editor.getSelection().selectWordRight(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotowordright",\n
    bindKey: bindKey("Ctrl-Right", "Option-Right"),\n
    exec: function(editor) { editor.navigateWordRight(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selecttolineend",\n
    bindKey: bindKey("Alt-Shift-Right", "Command-Shift-Right"),\n
    exec: function(editor) { editor.getSelection().selectLineEnd(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotolineend",\n
    bindKey: bindKey("Alt-Right|End", "Command-Right|End|Ctrl-E"),\n
    exec: function(editor) { editor.navigateLineEnd(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectright",\n
    bindKey: bindKey("Shift-Right", "Shift-Right"),\n
    exec: function(editor) { editor.getSelection().selectRight(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "gotoright",\n
    bindKey: bindKey("Right", "Right|Ctrl-F"),\n
    exec: function(editor, args) { editor.navigateRight(args.times); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectpagedown",\n
    bindKey: "Shift-PageDown",\n
    exec: function(editor) { editor.selectPageDown(); },\n
    readOnly: true\n
}, {\n
    name: "pagedown",\n
    bindKey: bindKey(null, "Option-PageDown"),\n
    exec: function(editor) { editor.scrollPageDown(); },\n
    readOnly: true\n
}, {\n
    name: "gotopagedown",\n
    bindKey: bindKey("PageDown", "PageDown|Ctrl-V"),\n
    exec: function(editor) { editor.gotoPageDown(); },\n
    readOnly: true\n
}, {\n
    name: "selectpageup",\n
    bindKey: "Shift-PageUp",\n
    exec: function(editor) { editor.selectPageUp(); },\n
    readOnly: true\n
}, {\n
    name: "pageup",\n
    bindKey: bindKey(null, "Option-PageUp"),\n
    exec: function(editor) { editor.scrollPageUp(); },\n
    readOnly: true\n
}, {\n
    name: "gotopageup",\n
    bindKey: "PageUp",\n
    exec: function(editor) { editor.gotoPageUp(); },\n
    readOnly: true\n
}, {\n
    name: "scrollup",\n
    bindKey: bindKey("Ctrl-Up", null),\n
    exec: function(e) { e.renderer.scrollBy(0, -2 * e.renderer.layerConfig.lineHeight); },\n
    readOnly: true\n
}, {\n
    name: "scrolldown",\n
    bindKey: bindKey("Ctrl-Down", null),\n
    exec: function(e) { e.renderer.scrollBy(0, 2 * e.renderer.layerConfig.lineHeight); },\n
    readOnly: true\n
}, {\n
    name: "selectlinestart",\n
    bindKey: "Shift-Home",\n
    exec: function(editor) { editor.getSelection().selectLineStart(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selectlineend",\n
    bindKey: "Shift-End",\n
    exec: function(editor) { editor.getSelection().selectLineEnd(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "togglerecording",\n
    bindKey: bindKey("Ctrl-Alt-E", "Command-Option-E"),\n
    exec: function(editor) { editor.commands.toggleRecording(editor); },\n
    readOnly: true\n
}, {\n
    name: "replaymacro",\n
    bindKey: bindKey("Ctrl-Shift-E", "Command-Shift-E"),\n
    exec: function(editor) { editor.commands.replay(editor); },\n
    readOnly: true\n
}, {\n
    name: "jumptomatching",\n
    bindKey: bindKey("Ctrl-P", "Ctrl-Shift-P"),\n
    exec: function(editor) { editor.jumpToMatching(); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, {\n
    name: "selecttomatching",\n
    bindKey: bindKey("Ctrl-Shift-P", null),\n
    exec: function(editor) { editor.jumpToMatching(true); },\n
    multiSelectAction: "forEach",\n
    readOnly: true\n
}, \n
{\n
    name: "cut",\n
    exec: function(editor) {\n
        var range = editor.getSelectionRange();\n
        editor._emit("cut", range);\n
\n
        if (!editor.selection.isEmpty()) {\n
            editor.session.remove(range);\n
            editor.clearSelection();\n
        }\n
    },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "removeline",\n
    bindKey: bindKey("Ctrl-D", "Command-D"),\n
    exec: function(editor) { editor.removeLines(); },\n
    multiSelectAction: "forEachLine"\n
}, {\n
    name: "duplicateSelection",\n
    bindKey: bindKey("Ctrl-Shift-D", "Command-Shift-D"),\n
    exec: function(editor) { editor.duplicateSelection(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "sortlines",\n
    bindKey: bindKey("Ctrl-Alt-S", "Command-Alt-S"),\n
    exec: function(editor) { editor.sortLines(); },\n
    multiSelectAction: "forEachLine"\n
}, {\n
    name: "togglecomment",\n
    bindKey: bindKey("Ctrl-/", "Command-/"),\n
    exec: function(editor) { editor.toggleCommentLines(); },\n
    multiSelectAction: "forEachLine"\n
}, {\n
    name: "toggleBlockComment",\n
    bindKey: bindKey("Ctrl-Shift-/", "Command-Shift-/"),\n
    exec: function(editor) { editor.toggleBlockComment(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "modifyNumberUp",\n
    bindKey: bindKey("Ctrl-Shift-Up", "Alt-Shift-Up"),\n
    exec: function(editor) { editor.modifyNumber(1); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "modifyNumberDown",\n
    bindKey: bindKey("Ctrl-Shift-Down", "Alt-Shift-Down"),\n
    exec: function(editor) { editor.modifyNumber(-1); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "replace",\n
    bindKey: bindKey("Ctrl-H", "Command-Option-F"),\n
    exec: function(editor) {\n
        config.loadModule("ace/ext/searchbox", function(e) {e.Search(editor, true)});\n
    }\n
}, {\n
    name: "undo",\n
    bindKey: bindKey("Ctrl-Z", "Command-Z"),\n
    exec: function(editor) { editor.undo(); }\n
}, {\n
    name: "redo",\n
    bindKey: bindKey("Ctrl-Shift-Z|Ctrl-Y", "Command-Shift-Z|Command-Y"),\n
    exec: function(editor) { editor.redo(); }\n
}, {\n
    name: "copylinesup",\n
    bindKey: bindKey("Alt-Shift-Up", "Command-Option-Up"),\n
    exec: function(editor) { editor.copyLinesUp(); }\n
}, {\n
    name: "movelinesup",\n
    bindKey: bindKey("Alt-Up", "Option-Up"),\n
    exec: function(editor) { editor.moveLinesUp(); }\n
}, {\n
    name: "copylinesdown",\n
    bindKey: bindKey("Alt-Shift-Down", "Command-Option-Down"),\n
    exec: function(editor) { editor.copyLinesDown(); }\n
}, {\n
    name: "movelinesdown",\n
    bindKey: bindKey("Alt-Down", "Option-Down"),\n
    exec: function(editor) { editor.moveLinesDown(); }\n
}, {\n
    name: "del",\n
    bindKey: bindKey("Delete", "Delete|Ctrl-D|Shift-Delete"),\n
    exec: function(editor) { editor.remove("right"); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "backspace",\n
    bindKey: bindKey(\n
        "Shift-Backspace|Backspace",\n
        "Ctrl-Backspace|Shift-Backspace|Backspace|Ctrl-H"\n
    ),\n
    exec: function(editor) { editor.remove("left"); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "cut_or_delete",\n
    bindKey: bindKey("Shift-Delete", null),\n
    exec: function(editor) { \n
        if (editor.selection.isEmpty()) {\n
            editor.remove("left");\n
        } else {\n
            return false;\n
        }\n
    },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "removetolinestart",\n
    bindKey: bindKey("Alt-Backspace", "Command-Backspace"),\n
    exec: function(editor) { editor.removeToLineStart(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "removetolineend",\n
    bindKey: bindKey("Alt-Delete", "Ctrl-K"),\n
    exec: function(editor) { editor.removeToLineEnd(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "removewordleft",\n
    bindKey: bindKey("Ctrl-Backspace", "Alt-Backspace|Ctrl-Alt-Backspace"),\n
    exec: function(editor) { editor.removeWordLeft(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "removewordright",\n
    bindKey: bindKey("Ctrl-Delete", "Alt-Delete"),\n
    exec: function(editor) { editor.removeWordRight(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "outdent",\n
    bindKey: bindKey("Shift-Tab", "Shift-Tab"),\n
    exec: function(editor) { editor.blockOutdent(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "indent",\n
    bindKey: bindKey("Tab", "Tab"),\n
    exec: function(editor) { editor.indent(); },\n
    multiSelectAction: "forEach"\n
},{\n
    name: "blockoutdent",\n
    bindKey: bindKey("Ctrl-[", "Ctrl-["),\n
    exec: function(editor) { editor.blockOutdent(); },\n
    multiSelectAction: "forEachLine"\n
},{\n
    name: "blockindent",\n
    bindKey: bindKey("Ctrl-]", "Ctrl-]"),\n
    exec: function(editor) { editor.blockIndent(); },\n
    multiSelectAction: "forEachLine"\n
}, {\n
    name: "insertstring",\n
    exec: function(editor, str) { editor.insert(str); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "inserttext",\n
    exec: function(editor, args) {\n
        editor.insert(lang.stringRepeat(args.text  || "", args.times || 1));\n
    },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "splitline",\n
    bindKey: bindKey(null, "Ctrl-O"),\n
    exec: function(editor) { editor.splitLine(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "transposeletters",\n
    bindKey: bindKey("Ctrl-T", "Ctrl-T"),\n
    exec: function(editor) { editor.transposeLetters(); },\n
    multiSelectAction: function(editor) {editor.transposeSelections(1); }\n
}, {\n
    name: "touppercase",\n
    bindKey: bindKey("Ctrl-U", "Ctrl-U"),\n
    exec: function(editor) { editor.toUpperCase(); },\n
    multiSelectAction: "forEach"\n
}, {\n
    name: "tolowercase",\n
    bindKey: bindKey("Ctrl-Shift-U", "Ctrl-Shift-U"),\n
    exec: function(editor) { editor.toLowerCase(); },\n
    multiSelectAction: "forEach"\n
}];\n
\n
});\n
\n
define(\'ace/undomanager\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
var UndoManager = function() {\n
    this.reset();\n
};\n
\n
(function() {\n
    this.execute = function(options) {\n
        var deltas = options.args[0];\n
        this.$doc  = options.args[1];\n
        if (options.merge && this.hasUndo()){\n
            deltas = this.$undoStack.pop().concat(deltas);\n
        }\n
        this.$undoStack.push(deltas);\n
        this.$redoStack = [];\n
\n
        if (this.dirtyCounter < 0) {\n
            this.dirtyCounter = NaN;\n
        }\n
        this.dirtyCounter++;\n
    };\n
    this.undo = function(dontSelect) {\n
        var deltas = this.$undoStack.pop();\n
        var undoSelectionRange = null;\n
        if (deltas) {\n
            undoSelectionRange =\n
                this.$doc.undoChanges(deltas, dontSelect);\n
            this.$redoStack.push(deltas);\n
            this.dirtyCounter--;\n
        }\n
\n
        return undoSelectionRange;\n
    };\n
    this.redo = function(dontSelect) {\n
        var deltas = this.$redoStack.pop();\n
        var redoSelectionRange = null;\n
        if (deltas) {\n
            redoSelectionRange =\n
                this.$doc.redoChanges(deltas, dontSelect);\n
            this.$undoStack.push(deltas);\n
            this.dirtyCounter++;\n
        }\n
\n
        return redoSelectionRange;\n
    };\n
    this.reset = function() {\n
        this.$undoStack = [];\n
        this.$redoStack = [];\n
        this.dirtyCounter = 0;\n
    };\n
    this.hasUndo = function() {\n
        return this.$undoStack.length > 0;\n
    };\n
    this.hasRedo = function() {\n
        return this.$redoStack.length > 0;\n
    };\n
    this.markClean = function() {\n
        this.dirtyCounter = 0;\n
    };\n
    this.isClean = function() {\n
        return this.dirtyCounter === 0;\n
    };\n
\n
}).call(UndoManager.prototype);\n
\n
exports.UndoManager = UndoManager;\n
});\n
\n
define(\'ace/virtual_renderer\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/dom\', \'ace/lib/useragent\', \'ace/config\', \'ace/layer/gutter\', \'ace/layer/marker\', \'ace/layer/text\', \'ace/layer/cursor\', \'ace/scrollbar\', \'ace/renderloop\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var dom = require("./lib/dom");\n
var useragent = require("./lib/useragent");\n
var config = require("./config");\n
var GutterLayer = require("./layer/gutter").Gutter;\n
var MarkerLayer = require("./layer/marker").Marker;\n
var TextLayer = require("./layer/text").Text;\n
var CursorLayer = require("./layer/cursor").Cursor;\n
var ScrollBarH = require("./scrollbar").ScrollBarH;\n
var ScrollBarV = require("./scrollbar").ScrollBarV;\n
var RenderLoop = require("./renderloop").RenderLoop;\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var editorCss = ".ace_editor {\\\n
position: relative;\\\n
overflow: hidden;\\\n
font-family: \'Monaco\', \'Menlo\', \'Ubuntu Mono\', \'Consolas\', \'source-code-pro\', monospace;\\\n
font-size: 12px;\\\n
line-height: normal;\\\n
color: black;\\\n
-ms-user-select: none;\\\n
-moz-user-select: none;\\\n
-webkit-user-select: none;\\\n
user-select: none;\\\n
}\\\n
.ace_scroller {\\\n
position: absolute;\\\n
overflow: hidden;\\\n
top: 0;\\\n
bottom: 0;\\\n
background-color: inherit;\\\n
}\\\n
.ace_content {\\\n
position: absolute;\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
cursor: text;\\\n
}\\\n
.ace_dragging, .ace_dragging * {\\\n
cursor: move !important;\\\n
}\\\n
.ace_dragging .ace_scroller:before{\\\n
position: absolute;\\\n
top: 0;\\\n
left: 0;\\\n
right: 0;\\\n
bottom: 0;\\\n
content: \'\';\\\n
background: rgba(250, 250, 250, 0.01);\\\n
z-index: 1000;\\\n
}\\\n
.ace_dragging.ace_dark .ace_scroller:before{\\\n
background: rgba(0, 0, 0, 0.01);\\\n
}\\\n
.ace_selecting, .ace_selecting * {\\\n
cursor: text !important;\\\n
}\\\n
.ace_gutter {\\\n
position: absolute;\\\n
overflow : hidden;\\\n
width: auto;\\\n
top: 0;\\\n
bottom: 0;\\\n
left: 0;\\\n
cursor: default;\\\n
z-index: 4;\\\n
}\\\n
.ace_gutter-active-line {\\\n
position: absolute;\\\n
left: 0;\\\n
right: 0;\\\n
}\\\n
.ace_scroller.ace_scroll-left {\\\n
box-shadow: 17px 0 16px -16px rgba(0, 0, 0, 0.4) inset;\\\n
}\\\n
.ace_gutter-cell {\\\n
padding-left: 19px;\\\n
padding-right: 6px;\\\n
background-repeat: no-repeat;\\\n
}\\\n
.ace_gutter-cell.ace_error {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYwIDYxLjEzNDc3NywgMjAxMC8wMi8xMi0xNzozMjowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNSBNYWNpbnRvc2giIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6QUM2OEZDQTQ4RTU0MTFFMUEzM0VFRTM2RUY1M0RBMjYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6QUM2OEZDQTU4RTU0MTFFMUEzM0VFRTM2RUY1M0RBMjYiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpBQzY4RkNBMjhFNTQxMUUxQTMzRUVFMzZFRjUzREEyNiIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBQzY4RkNBMzhFNTQxMUUxQTMzRUVFMzZFRjUzREEyNiIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PkgXxbAAAAJbSURBVHjapFNNaBNBFH4zs5vdZLP5sQmNpT82QY209heh1ioWisaDRcSKF0WKJ0GQnrzrxasHsR6EnlrwD0TagxJabaVEpFYxLWlLSS822tr87m66ccfd2GKyVhA6MMybgfe97/vmPUQphd0sZjto9XIn9OOsvlu2nkqRzVU+6vvlzPf8W6bk8dxQ0NPbxAALgCgg2JkaQuhzQau/El0zbmUA7U0Es8v2CiYmKQJHGO1QICCLoqilMhkmurDAyapKgqItezi/USRdJqEYY4D5jCy03ht2yMkkvL91jTTX10qzyyu2hruPRN7jgbH+EOsXcMLgYiThEgAMhABW85oqy1DXdRIdvP1AHJ2acQXvDIrVHcdQNrEKNYSVMSZGMjEzIIAwDXIo+6G/FxcGnzkC3T2oMhLjre49sBB+RRcHLqdafK6sYdE/GGBwU1VpFNj0aN8pJbe+BkZyevUrvLl6Xmm0W9IuTc0DxrDNAJd5oEvI/KRsNC3bQyNjPO9yQ1YHcfj2QvfQc/5TUhJTBc2iM0U7AWDQtc1nJHvD/cfO2s7jaGkiTEfa/Ep8coLu7zmNmh8+dc5lZDuUeFAGUNA/OY6JVaypQ0vjr7XYjUvJM37vt+j1vuTK5DgVfVUoTjVe+y3/LxMxY2GgU+CSLy4cpfsYorRXuXIOi0Vt40h67uZFTdIo6nLaZcwUJWAzwNS0tBnqqKzQDnjdG/iPyZxo46HaKUpbvYkj8qYRTZsBhge+JHhZyh0x9b95JqjVJkT084kZIPwu/mPWqPgfQ5jXh2+92Ay7HedfAgwA6KDWafb4w3cAAAAASUVORK5CYII=\\");\\\n
background-repeat: no-repeat;\\\n
background-position: 2px center;\\\n
}\\\n
.ace_gutter-cell.ace_warning {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYwIDYxLjEzNDc3NywgMjAxMC8wMi8xMi0xNzozMjowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNSBNYWNpbnRvc2giIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6QUM2OEZDQTg4RTU0MTFFMUEzM0VFRTM2RUY1M0RBMjYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6QUM2OEZDQTk4RTU0MTFFMUEzM0VFRTM2RUY1M0RBMjYiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpBQzY4RkNBNjhFNTQxMUUxQTMzRUVFMzZFRjUzREEyNiIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBQzY4RkNBNzhFNTQxMUUxQTMzRUVFMzZFRjUzREEyNiIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Pgd7PfIAAAGmSURBVHjaYvr//z8DJZiJgUIANoCRkREb9gLiSVAaQx4OQM7AAkwd7XU2/v++/rOttdYGEB9dASEvOMydGKfH8Gv/p4XTkvRBfLxeQAP+1cUhXopyvzhP7P/IoSj7g7Mw09cNKO6J1QQ0L4gICPIv/veg/8W+JdFvQNLHVsW9/nmn9zk7B+cCkDwhL7gt6knSZnx9/LuCEOcvkIAMP+cvto9nfqyZmmUAksfnBUtbM60gX/3/kgyv3/xSFOL5DZT+L8vP+Yfh5cvfPvp/xUHyQHXGyAYwgpwBjZYFT3Y1OEl/OfCH4ffv3wzc4iwMvNIsDJ+f/mH4+vIPAxsb631WW0Yln6ZpQLXdMK/DXGDflh+sIv37EivD5x//Gb7+YWT4y86sl7BCCkSD+Z++/1dkvsFRl+HnD1Rvje4F8whjMXmGj58YGf5zsDMwcnAwfPvKcml62DsQDeaDxN+/Y0qwlpEHqrdB94IRNIDUgfgfKJChGK4OikEW3gTiXUB950ASLFAF54AC94A0G9QAfOnmF9DCDzABFqS08IHYDIScdijOjQABBgC+/9awBH96jwAAAABJRU5ErkJggg==\\");\\\n
background-position: 2px center;\\\n
}\\\n
.ace_gutter-cell.ace_info {\\\n
background-image: url(\\"data:image/gif;base64,R0lGODlhEAAQAMQAAAAAAEFBQVJSUl5eXmRkZGtra39/f4WFhYmJiZGRkaampry8vMPDw8zMzNXV1dzc3OTk5Orq6vDw8P///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAkAABQALAAAAAAQABAAAAUuICWOZGmeaBml5XGwFCQSBGyXRSAwtqQIiRuiwIM5BoYVbEFIyGCQoeJGrVptIQA7\\");\\\n
background-position: 2px center;\\\n
}\\\n
.ace_dark .ace_gutter-cell.ace_info {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyRpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNiAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpGRTk5MTVGREIxNDkxMUUxOTc5Q0FFREQyMTNGMjBFQyIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpGRTk5MTVGRUIxNDkxMUUxOTc5Q0FFREQyMTNGMjBFQyI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOkZFOTkxNUZCQjE0OTExRTE5NzlDQUVERDIxM0YyMEVDIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOkZFOTkxNUZDQjE0OTExRTE5NzlDQUVERDIxM0YyMEVDIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+SIDkjAAAAJ1JREFUeNpi/P//PwMlgImBQkB7A6qrq/+DMC55FkIGKCoq4pVnpFkgTp069f/+/fv/r1u37r+tre1/kg0A+ptn9uzZYLaRkRHpLvjw4cNXWVlZhufPnzOcO3eOdAO0tbVPAjHDmzdvGA4fPsxIsgGSkpJmv379Ynj37h2DjIyMCMkG3LhxQ/T27dsMampqDHZ2dq/pH41DxwCAAAMAFdc68dUsFZgAAAAASUVORK5CYII=\\");\\\n
}\\\n
.ace_scrollbar {\\\n
position: absolute;\\\n
overflow-x: hidden;\\\n
overflow-y: auto;\\\n
right: 0;\\\n
top: 0;\\\n
bottom: 0;\\\n
z-index: 6;\\\n
}\\\n
.ace_scrollbar-inner {\\\n
position: absolute;\\\n
cursor: text;\\\n
left: 0;\\\n
top: 0;\\\n
}\\\n
.ace_scrollbar-h {\\\n
position: absolute;\\\n
overflow-x: auto;\\\n
overflow-y: hidden;\\\n
right: 0;\\\n
left: 0;\\\n
bottom: 0;\\\n
z-index: 6;\\\n
}\\\n
.ace_print-margin {\\\n
position: absolute;\\\n
height: 100%;\\\n
}\\\n
.ace_text-input {\\\n
position: absolute;\\\n
z-index: 0;\\\n
width: 0.5em;\\\n
height: 1em;\\\n
opacity: 0;\\\n
background: transparent;\\\n
-moz-appearance: none;\\\n
appearance: none;\\\n
border: none;\\\n
resize: none;\\\n
outline: none;\\\n
overflow: hidden;\\\n
font: inherit;\\\n
padding: 0 1px;\\\n
margin: 0 -1px;\\\n
text-indent: -1em;\\\n
}\\\n
.ace_text-input.ace_composition {\\\n
background: #f8f8f8;\\\n
color: #111;\\\n
z-index: 1000;\\\n
opacity: 1;\\\n
text-indent: 0;\\\n
}\\\n
.ace_layer {\\\n
z-index: 1;\\\n
position: absolute;\\\n
overflow: hidden;\\\n
white-space: nowrap;\\\n
height: 100%;\\\n
width: 100%;\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
/* setting pointer-events: auto; on node under the mouse, which changes\\\n
during scroll, will break mouse wheel scrolling in Safari */\\\n
pointer-events: none;\\\n
}\\\n
.ace_gutter-layer {\\\n
position: relative;\\\n
width: auto;\\\n
text-align: right;\\\n
pointer-events: auto;\\\n
}\\\n
.ace_text-layer {\\\n
font: inherit !important;\\\n
}\\\n
.ace_cjk {\\\n
display: inline-block;\\\n
text-align: center;\\\n
}\\\n
.ace_cursor-layer {\\\n
z-index: 4;\\\n
}\\\n
.ace_cursor {\\\n
z-index: 4;\\\n
position: absolute;\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
border-left: 2px solid\\\n
}\\\n
.ace_slim-cursors .ace_cursor {\\\n
border-left-width: 1px;\\\n
}\\\n
.ace_overwrite-cursors .ace_cursor {\\\n
border-left-width: 0px;\\\n
border-bottom: 1px solid;\\\n
}\\\n
.ace_hidden-cursors .ace_cursor {\\\n
opacity: 0.2;\\\n
}\\\n
.ace_smooth-blinking .ace_cursor {\\\n
-moz-transition: opacity 0.18s;\\\n
-webkit-transition: opacity 0.18s;\\\n
-o-transition: opacity 0.18s;\\\n
-ms-transition: opacity 0.18s;\\\n
transition: opacity 0.18s;\\\n
}\\\n
.ace_cursor[style*=\\"opacity: 0\\"]{\\\n
-ms-filter: \\"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)\\";\\\n
}\\\n
.ace_editor.ace_multiselect .ace_cursor {\\\n
border-left-width: 1px;\\\n
}\\\n
.ace_line {\\\n
white-space: nowrap;\\\n
}\\\n
.ace_marker-layer .ace_step, .ace_marker-layer .ace_stack {\\\n
position: absolute;\\\n
z-index: 3;\\\n
}\\\n
.ace_marker-layer .ace_selection {\\\n
position: absolute;\\\n
z-index: 5;\\\n
}\\\n
.ace_marker-layer .ace_bracket {\\\n
position: absolute;\\\n
z-index: 6;\\\n
}\\\n
.ace_marker-layer .ace_active-line {\\\n
position: absolute;\\\n
z-index: 2;\\\n
}\\\n
.ace_marker-layer .ace_selected-word {\\\n
position: absolute;\\\n
z-index: 4;\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
}\\\n
.ace_line .ace_fold {\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
display: inline-block;\\\n
height: 11px;\\\n
margin-top: -2px;\\\n
vertical-align: middle;\\\n
background-image:\\\n
url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%11%00%00%00%09%08%06%00%00%00%D4%E8%C7%0C%00%00%03%1EiCCPICC%20Profile%00%00x%01%85T%DFk%D3P%14%FE%DAe%9D%B0%E1%8B%3Ag%11%09%3Eh%91ndStC%9C%B6kW%BA%CDZ%EA6%B7!H%9B%A6m%5C%9A%C6%24%ED~%B0%07%D9%8Bo%3A%C5w%F1%07%3E%F9%07%0C%D9%83o%7B%92%0D%C6%14a%F8%AC%88%22L%F6%22%B3%9E%9B4M\'S%03%B9%F7%BB%DF%F9%EE9\'%E7%E4%5E%A0%F9qZ%D3%14%2F%0F%14USO%C5%C2%FC%C4%E4%14%DF%F2%01%5E%1CC%2B%FChM%8B%86%16J%26G%40%0F%D3%B2y%EF%B3%F3%0E%1E%C6lt%EEo%DF%AB%FEc%D5%9A%95%0C%11%F0%1C%20%BE%945%C4%22%E1Y%A0i%5C%D4t%13%E0%D6%89%EF%9D15%C2%CDLsX%A7%04%09%1Fg8oc%81%E1%8C%8D%23%96f45%40%9A%09%C2%07%C5B%3AK%B8%408%98i%E0%F3%0D%D8%CE%81%14%E4\'%26%A9%92.%8B%3C%ABER%2F%E5dE%B2%0C%F6%F0%1Fs%83%F2_%B0%A8%94%E9%9B%AD%E7%10%8Dm%9A%19N%D1%7C%8A%DE%1F9%7Dp%8C%E6%00%D5%C1%3F_%18%BDA%B8%9DpX6%E3%A35~B%CD%24%AE%11%26%BD%E7%EEti%98%EDe%9A%97Y)%12%25%1C%24%BCbT%AE3li%E6%0B%03%89%9A%E6%D3%ED%F4P%92%B0%9F4%BF43Y%F3%E3%EDP%95%04%EB1%C5%F5%F6KF%F4%BA%BD%D7%DB%91%93%07%E35%3E%A7)%D6%7F%40%FE%BD%F7%F5r%8A%E5y%92%F0%EB%B4%1E%8D%D5%F4%5B%92%3AV%DB%DB%E4%CD%A6%23%C3%C4wQ%3F%03HB%82%8E%1Cd(%E0%91B%0Ca%9Ac%C4%AA%F8L%16%19%22J%A4%D2itTy%B28%D6%3B(%93%96%ED%1CGx%C9_%0E%B8%5E%16%F5%5B%B2%B8%F6%E0%FB%9E%DD%25%D7%8E%BC%15%85%C5%B7%A3%D8Q%ED%B5%81%E9%BA%B2%13%9A%1B%7Fua%A5%A3n%E17%B9%E5%9B%1Bm%AB%0B%08Q%FE%8A%E5%B1H%5Ee%CAO%82Q%D7u6%E6%90S%97%FCu%0B%CF2%94%EE%25v%12X%0C%BA%AC%F0%5E%F8*l%0AO%85%17%C2%97%BF%D4%C8%CE%DE%AD%11%CB%80q%2C%3E%AB%9ES%CD%C6%EC%25%D2L%D2%EBd%B8%BF%8A%F5B%C6%18%F9%901CZ%9D%BE%24M%9C%8A9%F2%DAP%0B\'%06w%82%EB%E6%E2%5C%2F%D7%07%9E%BB%CC%5D%E1%FA%B9%08%AD.r%23%8E%C2%17%F5E%7C!%F0%BE3%BE%3E_%B7o%88a%A7%DB%BE%D3d%EB%A31Z%EB%BB%D3%91%BA%A2%B1z%94%8F%DB\'%F6%3D%8E%AA%13%19%B2%B1%BE%B1~V%08%2B%B4%A2cjJ%B3tO%00%03%25mN%97%F3%05%93%EF%11%84%0B%7C%88%AE-%89%8F%ABbW%90O%2B%0Ao%99%0C%5E%97%0CI%AFH%D9.%B0%3B%8F%ED%03%B6S%D6%5D%E6i_s9%F3*p%E9%1B%FD%C3%EB.7U%06%5E%19%C0%D1s.%17%A03u%E4%09%B0%7C%5E%2C%EB%15%DB%1F%3C%9E%B7%80%91%3B%DBc%AD%3Dma%BA%8B%3EV%AB%DBt.%5B%1E%01%BB%0F%AB%D5%9F%CF%AA%D5%DD%E7%E4%7F%0Bx%A3%FC%06%A9%23%0A%D6%C2%A1_2%00%00%00%09pHYs%00%00%0B%13%00%00%0B%13%01%00%9A%9C%18%00%00%00%B5IDAT(%15%A5%91%3D%0E%02!%10%85ac%E1%05%D6%CE%D6%C6%CE%D2%E8%ED%CD%DE%C0%C6%D6N.%E0V%F8%3D%9Ca%891XH%C2%BE%D9y%3F%90!%E6%9C%C3%BFk%E5%011%C6-%F5%C8N%04%DF%BD%FF%89%DFt%83DN%60%3E%F3%AB%A0%DE%1A%5Dg%BE%10Q%97%1B%40%9C%A8o%10%8F%5E%828%B4%1B%60%87%F6%02%26%85%1Ch%1E%C1%2B%5Bk%FF%86%EE%B7j%09%9A%DA%9B%ACe%A3%F9%EC%DA!9%B4%D5%A6%81%86%86%98%CC%3C%5B%40%FA%81%B3%E9%CB%23%94%C16Azo%05%D4%E1%C1%95a%3B%8A\'%A0%E8%CC%17%22%85%1D%BA%00%A2%FA%DC%0A%94%D1%D1%8D%8B%3A%84%17B%C7%60%1A%25Z%FC%8D%00%00%00%00IEND%AEB%60%82\\"),\\\n
url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%05%00%00%007%08%06%00%00%00%C4%DD%80C%00%00%03%1EiCCPICC%20Profile%00%00x%01%85T%DFk%D3P%14%FE%DAe%9D%B0%E1%8B%3Ag%11%09%3Eh%91ndStC%9C%B6kW%BA%CDZ%EA6%B7!H%9B%A6m%5C%9A%C6%24%ED~%B0%07%D9%8Bo%3A%C5w%F1%07%3E%F9%07%0C%D9%83o%7B%92%0D%C6%14a%F8%AC%88%22L%F6%22%B3%9E%9B4M\'S%03%B9%F7%BB%DF%F9%EE9\'%E7%E4%5E%A0%F9qZ%D3%14%2F%0F%14USO%C5%C2%FC%C4%E4%14%DF%F2%01%5E%1CC%2B%FChM%8B%86%16J%26G%40%0F%D3%B2y%EF%B3%F3%0E%1E%C6lt%EEo%DF%AB%FEc%D5%9A%95%0C%11%F0%1C%20%BE%945%C4%22%E1Y%A0i%5C%D4t%13%E0%D6%89%EF%9D15%C2%CDLsX%A7%04%09%1Fg8oc%81%E1%8C%8D%23%96f45%40%9A%09%C2%07%C5B%3AK%B8%408%98i%E0%F3%0D%D8%CE%81%14%E4\'%26%A9%92.%8B%3C%ABER%2F%E5dE%B2%0C%F6%F0%1Fs%83%F2_%B0%A8%94%E9%9B%AD%E7%10%8Dm%9A%19N%D1%7C%8A%DE%1F9%7Dp%8C%E6%00%D5%C1%3F_%18%BDA%B8%9DpX6%E3%A35~B%CD%24%AE%11%26%BD%E7%EEti%98%EDe%9A%97Y)%12%25%1C%24%BCbT%AE3li%E6%0B%03%89%9A%E6%D3%ED%F4P%92%B0%9F4%BF43Y%F3%E3%EDP%95%04%EB1%C5%F5%F6KF%F4%BA%BD%D7%DB%91%93%07%E35%3E%A7)%D6%7F%40%FE%BD%F7%F5r%8A%E5y%92%F0%EB%B4%1E%8D%D5%F4%5B%92%3AV%DB%DB%E4%CD%A6%23%C3%C4wQ%3F%03HB%82%8E%1Cd(%E0%91B%0Ca%9Ac%C4%AA%F8L%16%19%22J%A4%D2itTy%B28%D6%3B(%93%96%ED%1CGx%C9_%0E%B8%5E%16%F5%5B%B2%B8%F6%E0%FB%9E%DD%25%D7%8E%BC%15%85%C5%B7%A3%D8Q%ED%B5%81%E9%BA%B2%13%9A%1B%7Fua%A5%A3n%E17%B9%E5%9B%1Bm%AB%0B%08Q%FE%8A%E5%B1H%5Ee%CAO%82Q%D7u6%E6%90S%97%FCu%0B%CF2%94%EE%25v%12X%0C%BA%AC%F0%5E%F8*l%0AO%85%17%C2%97%BF%D4%C8%CE%DE%AD%11%CB%80q%2C%3E%AB%9ES%CD%C6%EC%25%D2L%D2%EBd%B8%BF%8A%F5B%C6%18%F9%901CZ%9D%BE%24M%9C%8A9%F2%DAP%0B\'%06w%82%EB%E6%E2%5C%2F%D7%07%9E%BB%CC%5D%E1%FA%B9%08%AD.r%23%8E%C2%17%F5E%7C!%F0%BE3%BE%3E_%B7o%88a%A7%DB%BE%D3d%EB%A31Z%EB%BB%D3%91%BA%A2%B1z%94%8F%DB\'%F6%3D%8E%AA%13%19%B2%B1%BE%B1~V%08%2B%B4%A2cjJ%B3tO%00%03%25mN%97%F3%05%93%EF%11%84%0B%7C%88%AE-%89%8F%ABbW%90O%2B%0Ao%99%0C%5E%97%0CI%AFH%D9.%B0%3B%8F%ED%03%B6S%D6%5D%E6i_s9%F3*p%E9%1B%FD%C3%EB.7U%06%5E%19%C0%D1s.%17%A03u%E4%09%B0%7C%5E%2C%EB%15%DB%1F%3C%9E%B7%80%91%3B%DBc%AD%3Dma%BA%8B%3EV%AB%DBt.%5B%1E%01%BB%0F%AB%D5%9F%CF%AA%D5%DD%E7%E4%7F%0Bx%A3%FC%06%A9%23%0A%D6%C2%A1_2%00%00%00%09pHYs%00%00%0B%13%00%00%0B%13%01%00%9A%9C%18%00%00%00%3AIDAT8%11c%FC%FF%FF%7F%18%03%1A%60%01%F2%3F%A0%891%80%04%FF%11-%F8%17%9BJ%E2%05%B1ZD%81v%26t%E7%80%F8%A3%82h%A12%1A%20%A3%01%02%0F%01%BA%25%06%00%19%C0%0D%AEF%D5%3ES%00%00%00%00IEND%AEB%60%82\\");\\\n
background-repeat: no-repeat, repeat-x;\\\n
background-position: center center, top left;\\\n
color: transparent;\\\n
border: 1px solid black;\\\n
-moz-border-radius: 2px;\\\n
-webkit-border-radius: 2px;\\\n
border-radius: 2px;\\\n
cursor: pointer;\\\n
pointer-events: auto;\\\n
}\\\n
.ace_dark .ace_fold {\\\n
}\\\n
.ace_fold:hover{\\\n
background-image:\\\n
url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%11%00%00%00%09%08%06%00%00%00%D4%E8%C7%0C%00%00%03%1EiCCPICC%20Profile%00%00x%01%85T%DFk%D3P%14%FE%DAe%9D%B0%E1%8B%3Ag%11%09%3Eh%91ndStC%9C%B6kW%BA%CDZ%EA6%B7!H%9B%A6m%5C%9A%C6%24%ED~%B0%07%D9%8Bo%3A%C5w%F1%07%3E%F9%07%0C%D9%83o%7B%92%0D%C6%14a%F8%AC%88%22L%F6%22%B3%9E%9B4M\'S%03%B9%F7%BB%DF%F9%EE9\'%E7%E4%5E%A0%F9qZ%D3%14%2F%0F%14USO%C5%C2%FC%C4%E4%14%DF%F2%01%5E%1CC%2B%FChM%8B%86%16J%26G%40%0F%D3%B2y%EF%B3%F3%0E%1E%C6lt%EEo%DF%AB%FEc%D5%9A%95%0C%11%F0%1C%20%BE%945%C4%22%E1Y%A0i%5C%D4t%13%E0%D6%89%EF%9D15%C2%CDLsX%A7%04%09%1Fg8oc%81%E1%8C%8D%23%96f45%40%9A%09%C2%07%C5B%3AK%B8%408%98i%E0%F3%0D%D8%CE%81%14%E4\'%26%A9%92.%8B%3C%ABER%2F%E5dE%B2%0C%F6%F0%1Fs%83%F2_%B0%A8%94%E9%9B%AD%E7%10%8Dm%9A%19N%D1%7C%8A%DE%1F9%7Dp%8C%E6%00%D5%C1%3F_%18%BDA%B8%9DpX6%E3%A35~B%CD%24%AE%11%26%BD%E7%EEti%98%EDe%9A%97Y)%12%25%1C%24%BCbT%AE3li%E6%0B%03%89%9A%E6%D3%ED%F4P%92%B0%9F4%BF43Y%F3%E3%EDP%95%04%EB1%C5%F5%F6KF%F4%BA%BD%D7%DB%91%93%07%E35%3E%A7)%D6%7F%40%FE%BD%F7%F5r%8A%E5y%92%F0%EB%B4%1E%8D%D5%F4%5B%92%3AV%DB%DB%E4%CD%A6%23%C3%C4wQ%3F%03HB%82%8E%1Cd(%E0%91B%0Ca%9Ac%C4%AA%F8L%16%19%22J%A4%D2itTy%B28%D6%3B(%93%96%ED%1CGx%C9_%0E%B8%5E%16%F5%5B%B2%B8%F6%E0%FB%9E%DD%25%D7%8E%BC%15%85%C5%B7%A3%D8Q%ED%B5%81%E9%BA%B2%13%9A%1B%7Fua%A5%A3n%E17%B9%E5%9B%1Bm%AB%0B%08Q%FE%8A%E5%B1H%5Ee%CAO%82Q%D7u6%E6%90S%97%FCu%0B%CF2%94%EE%25v%12X%0C%BA%AC%F0%5E%F8*l%0AO%85%17%C2%97%BF%D4%C8%CE%DE%AD%11%CB%80q%2C%3E%AB%9ES%CD%C6%EC%25%D2L%D2%EBd%B8%BF%8A%F5B%C6%18%F9%901CZ%9D%BE%24M%9C%8A9%F2%DAP%0B\'%06w%82%EB%E6%E2%5C%2F%D7%07%9E%BB%CC%5D%E1%FA%B9%08%AD.r%23%8E%C2%17%F5E%7C!%F0%BE3%BE%3E_%B7o%88a%A7%DB%BE%D3d%EB%A31Z%EB%BB%D3%91%BA%A2%B1z%94%8F%DB\'%F6%3D%8E%AA%13%19%B2%B1%BE%B1~V%08%2B%B4%A2cjJ%B3tO%00%03%25mN%97%F3%05%93%EF%11%84%0B%7C%88%AE-%89%8F%ABbW%90O%2B%0Ao%99%0C%5E%97%0CI%AFH%D9.%B0%3B%8F%ED%03%B6S%D6%5D%E6i_s9%F3*p%E9%1B%FD%C3%EB.7U%06%5E%19%C0%D1s.%17%A03u%E4%09%B0%7C%5E%2C%EB%15%DB%1F%3C%9E%B7%80%91%3B%DBc%AD%3Dma%BA%8B%3EV%AB%DBt.%5B%1E%01%BB%0F%AB%D5%9F%CF%AA%D5%DD%E7%E4%7F%0Bx%A3%FC%06%A9%23%0A%D6%C2%A1_2%00%00%00%09pHYs%00%00%0B%13%00%00%0B%13%01%00%9A%9C%18%00%00%00%B5IDAT(%15%A5%91%3D%0E%02!%10%85ac%E1%05%D6%CE%D6%C6%CE%D2%E8%ED%CD%DE%C0%C6%D6N.%E0V%F8%3D%9Ca%891XH%C2%BE%D9y%3F%90!%E6%9C%C3%BFk%E5%011%C6-%F5%C8N%04%DF%BD%FF%89%DFt%83DN%60%3E%F3%AB%A0%DE%1A%5Dg%BE%10Q%97%1B%40%9C%A8o%10%8F%5E%828%B4%1B%60%87%F6%02%26%85%1Ch%1E%C1%2B%5Bk%FF%86%EE%B7j%09%9A%DA%9B%ACe%A3%F9%EC%DA!9%B4%D5%A6%81%86%86%98%CC%3C%5B%40%FA%81%B3%E9%CB%23%94%C16Azo%05%D4%E1%C1%95a%3B%8A\'%A0%E8%CC%17%22%85%1D%BA%00%A2%FA%DC%0A%94%D1%D1%8D%8B%3A%84%17B%C7%60%1A%25Z%FC%8D%00%00%00%00IEND%AEB%60%82\\"),\\\n
url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%05%00%00%007%08%06%00%00%00%C4%DD%80C%00%00%03%1EiCCPICC%20Profile%00%00x%01%85T%DFk%D3P%14%FE%DAe%9D%B0%E1%8B%3Ag%11%09%3Eh%91ndStC%9C%B6kW%BA%CDZ%EA6%B7!H%9B%A6m%5C%9A%C6%24%ED~%B0%07%D9%8Bo%3A%C5w%F1%07%3E%F9%07%0C%D9%83o%7B%92%0D%C6%14a%F8%AC%88%22L%F6%22%B3%9E%9B4M\'S%03%B9%F7%BB%DF%F9%EE9\'%E7%E4%5E%A0%F9qZ%D3%14%2F%0F%14USO%C5%C2%FC%C4%E4%14%DF%F2%01%5E%1CC%2B%FChM%8B%86%16J%26G%40%0F%D3%B2y%EF%B3%F3%0E%1E%C6lt%EEo%DF%AB%FEc%D5%9A%95%0C%11%F0%1C%20%BE%945%C4%22%E1Y%A0i%5C%D4t%13%E0%D6%89%EF%9D15%C2%CDLsX%A7%04%09%1Fg8oc%81%E1%8C%8D%23%96f45%40%9A%09%C2%07%C5B%3AK%B8%408%98i%E0%F3%0D%D8%CE%81%14%E4\'%26%A9%92.%8B%3C%ABER%2F%E5dE%B2%0C%F6%F0%1Fs%83%F2_%B0%A8%94%E9%9B%AD%E7%10%8Dm%9A%19N%D1%7C%8A%DE%1F9%7Dp%8C%E6%00%D5%C1%3F_%18%BDA%B8%9DpX6%E3%A35~B%CD%24%AE%11%26%BD%E7%EEti%98%EDe%9A%97Y)%12%25%1C%24%BCbT%AE3li%E6%0B%03%89%9A%E6%D3%ED%F4P%92%B0%9F4%BF43Y%F3%E3%EDP%95%04%EB1%C5%F5%F6KF%F4%BA%BD%D7%DB%91%93%07%E35%3E%A7)%D6%7F%40%FE%BD%F7%F5r%8A%E5y%92%F0%EB%B4%1E%8D%D5%F4%5B%92%3AV%DB%DB%E4%CD%A6%23%C3%C4wQ%3F%03HB%82%8E%1Cd(%E0%91B%0Ca%9Ac%C4%AA%F8L%16%19%22J%A4%D2itTy%B28%D6%3B(%93%96%ED%1CGx%C9_%0E%B8%5E%16%F5%5B%B2%B8%F6%E0%FB%9E%DD%25%D7%8E%BC%15%85%C5%B7%A3%D8Q%ED%B5%81%E9%BA%B2%13%9A%1B%7Fua%A5%A3n%E17%B9%E5%9B%1Bm%AB%0B%08Q%FE%8A%E5%B1H%5Ee%CAO%82Q%D7u6%E6%90S%97%FCu%0B%CF2%94%EE%25v%12X%0C%BA%AC%F0%5E%F8*l%0AO%85%17%C2%97%BF%D4%C8%CE%DE%AD%11%CB%80q%2C%3E%AB%9ES%CD%C6%EC%25%D2L%D2%EBd%B8%BF%8A%F5B%C6%18%F9%901CZ%9D%BE%24M%9C%8A9%F2%DAP%0B\'%06w%82%EB%E6%E2%5C%2F%D7%07%9E%BB%CC%5D%E1%FA%B9%08%AD.r%23%8E%C2%17%F5E%7C!%F0%BE3%BE%3E_%B7o%88a%A7%DB%BE%D3d%EB%A31Z%EB%BB%D3%91%BA%A2%B1z%94%8F%DB\'%F6%3D%8E%AA%13%19%B2%B1%BE%B1~V%08%2B%B4%A2cjJ%B3tO%00%03%25mN%97%F3%05%93%EF%11%84%0B%7C%88%AE-%89%8F%ABbW%90O%2B%0Ao%99%0C%5E%97%0CI%AFH%D9.%B0%3B%8F%ED%03%B6S%D6%5D%E6i_s9%F3*p%E9%1B%FD%C3%EB.7U%06%5E%19%C0%D1s.%17%A03u%E4%09%B0%7C%5E%2C%EB%15%DB%1F%3C%9E%B7%80%91%3B%DBc%AD%3Dma%BA%8B%3EV%AB%DBt.%5B%1E%01%BB%0F%AB%D5%9F%CF%AA%D5%DD%E7%E4%7F%0Bx%A3%FC%06%A9%23%0A%D6%C2%A1_2%00%00%00%09pHYs%00%00%0B%13%00%00%0B%13%01%00%9A%9C%18%00%00%003IDAT8%11c%FC%FF%FF%7F%3E%03%1A%60%01%F2%3F%A3%891%80%04%FFQ%26%F8w%C0%B43%A1%DB%0C%E2%8F%0A%A2%85%CAh%80%8C%06%08%3C%04%E8%96%18%00%A3S%0D%CD%CF%D8%C1%9D%00%00%00%00IEND%AEB%60%82\\");\\\n
background-repeat: no-repeat, repeat-x;\\\n
background-position: center center, top left;\\\n
}\\\n
.ace_gutter-tooltip {\\\n
background-color: #FFF;\\\n
background-image: -webkit-linear-gradient(top, transparent, rgba(0, 0, 0, 0.1));\\\n
background-image: linear-gradient(to bottom, transparent, rgba(0, 0, 0, 0.1));\\\n
border: 1px solid gray;\\\n
border-radius: 1px;\\\n
box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);\\\n
color: black;\\\n
display: inline-block;\\\n
max-width: 500px;\\\n
padding: 4px;\\\n
position: fixed;\\\n
z-index: 999999;\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
cursor: default;\\\n
white-space: pre-line;\\\n
word-wrap: break-word;\\\n
line-height: normal;\\\n
font-style: normal;\\\n
font-weight: normal;\\\n
letter-spacing: normal;\\\n
}\\\n
.ace_folding-enabled > .ace_gutter-cell {\\\n
padding-right: 13px;\\\n
}\\\n
.ace_fold-widget {\\\n
-moz-box-sizing: border-box;\\\n
-webkit-box-sizing: border-box;\\\n
box-sizing: border-box;\\\n
margin: 0 -12px 0 1px;\\\n
display: none;\\\n
width: 11px;\\\n
vertical-align: top;\\\n
background-image: url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%05%00%00%00%05%08%06%00%00%00%8Do%26%E5%00%00%004IDATx%DAe%8A%B1%0D%000%0C%C2%F2%2CK%96%BC%D0%8F9%81%88H%E9%D0%0E%96%C0%10%92%3E%02%80%5E%82%E4%A9*-%EEsw%C8%CC%11%EE%96w%D8%DC%E9*Eh%0C%151(%00%00%00%00IEND%AEB%60%82\\");\\\n
background-repeat: no-repeat;\\\n
background-position: center;\\\n
border-radius: 3px;\\\n
border: 1px solid transparent;\\\n
cursor: pointer;\\\n
}\\\n
.ace_folding-enabled .ace_fold-widget {\\\n
display: inline-block;   \\\n
}\\\n
.ace_fold-widget.ace_end {\\\n
background-image: url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%05%00%00%00%05%08%06%00%00%00%8Do%26%E5%00%00%004IDATx%DAm%C7%C1%09%000%08C%D1%8C%ECE%C8E(%8E%EC%02)%1EZJ%F1%C1\'%04%07I%E1%E5%EE%CAL%F5%A2%99%99%22%E2%D6%1FU%B5%FE0%D9x%A7%26Wz5%0E%D5%00%00%00%00IEND%AEB%60%82\\");\\\n
}\\\n
.ace_fold-widget.ace_closed {\\\n
background-image: url(\\"data:image/png,%89PNG%0D%0A%1A%0A%00%00%00%0DIHDR%00%00%00%03%00%00%00%06%08%06%00%00%00%06%E5%24%0C%00%00%009IDATx%DA5%CA%C1%09%000%08%03%C0%AC*(%3E%04%C1%0D%BA%B1%23%A4Uh%E0%20%81%C0%CC%F8%82%81%AA%A2%AArGfr%88%08%11%11%1C%DD%7D%E0%EE%5B%F6%F6%CB%B8%05Q%2F%E9tai%D9%00%00%00%00IEND%AEB%60%82\\");\\\n
}\\\n
.ace_fold-widget:hover {\\\n
border: 1px solid rgba(0, 0, 0, 0.3);\\\n
background-color: rgba(255, 255, 255, 0.2);\\\n
-moz-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.7);\\\n
-webkit-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.7);\\\n
box-shadow: 0 1px 1px rgba(255, 255, 255, 0.7);\\\n
}\\\n
.ace_fold-widget:active {\\\n
border: 1px solid rgba(0, 0, 0, 0.4);\\\n
background-color: rgba(0, 0, 0, 0.05);\\\n
-moz-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.8);\\\n
-webkit-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.8);\\\n
box-shadow: 0 1px 1px rgba(255, 255, 255, 0.8);\\\n
}\\\n
/**\\\n
* Dark version for fold widgets\\\n
*/\\\n
.ace_dark .ace_fold-widget {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHklEQVQIW2P4//8/AzoGEQ7oGCaLLAhWiSwB146BAQCSTPYocqT0AAAAAElFTkSuQmCC\\");\\\n
}\\\n
.ace_dark .ace_fold-widget.ace_end {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAH0lEQVQIW2P4//8/AxQ7wNjIAjDMgC4AxjCVKBirIAAF0kz2rlhxpAAAAABJRU5ErkJggg==\\");\\\n
}\\\n
.ace_dark .ace_fold-widget.ace_closed {\\\n
background-image: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAMAAAAFCAYAAACAcVaiAAAAHElEQVQIW2P4//+/AxAzgDADlOOAznHAKgPWAwARji8UIDTfQQAAAABJRU5ErkJggg==\\");\\\n
}\\\n
.ace_dark .ace_fold-widget:hover {\\\n
box-shadow: 0 1px 1px rgba(255, 255, 255, 0.2);\\\n
background-color: rgba(255, 255, 255, 0.1);\\\n
}\\\n
.ace_dark .ace_fold-widget:active {\\\n
-moz-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.2);\\\n
-webkit-box-shadow: 0 1px 1px rgba(255, 255, 255, 0.2);\\\n
box-shadow: 0 1px 1px rgba(255, 255, 255, 0.2);\\\n
}\\\n
.ace_fold-widget.ace_invalid {\\\n
background-color: #FFB4B4;\\\n
border-color: #DE5555;\\\n
}\\\n
.ace_fade-fold-widgets .ace_fold-widget {\\\n
-moz-transition: opacity 0.4s ease 0.05s;\\\n
-webkit-transition: opacity 0.4s ease 0.05s;\\\n
-o-transition: opacity 0.4s ease 0.05s;\\\n
-ms-transition: opacity 0.4s ease 0.05s;\\\n
transition: opacity 0.4s ease 0.05s;\\\n
opacity: 0;\\\n
}\\\n
.ace_fade-fold-widgets:hover .ace_fold-widget {\\\n
-moz-transition: opacity 0.05s ease 0.05s;\\\n
-webkit-transition: opacity 0.05s ease 0.05s;\\\n
-o-transition: opacity 0.05s ease 0.05s;\\\n
-ms-transition: opacity 0.05s ease 0.05s;\\\n
transition: opacity 0.05s ease 0.05s;\\\n
opacity:1;\\\n
}\\\n
.ace_underline {\\\n
text-decoration: underline;\\\n
}\\\n
.ace_bold {\\\n
font-weight: bold;\\\n
}\\\n
.ace_nobold .ace_bold {\\\n
font-weight: normal;\\\n
}\\\n
.ace_italic {\\\n
font-style: italic;\\\n
}\\\n
.ace_error-marker {\\\n
background-color: rgba(255, 0, 0,0.2);\\\n
position: absolute;\\\n
z-index: 9;\\\n
}\\\n
.ace_highlight-marker {\\\n
background-color: rgba(255, 255, 0,0.2);\\\n
position: absolute;\\\n
z-index: 8;\\\n
}\\\n
";\n
\n
dom.importCssString(editorCss, "ace_editor");\n
\n
var VirtualRenderer = function(container, theme) {\n
    var _self = this;\n
\n
    this.container = container || dom.createElement("div");\n
    this.$keepTextAreaAtCursor = true;\n
\n
    dom.addCssClass(this.container, "ace_editor");\n
\n
    this.setTheme(theme);\n
\n
    this.$gutter = dom.createElement("div");\n
    this.$gutter.className = "ace_gutter";\n
    this.container.appendChild(this.$gutter);\n
\n
    this.scroller = dom.createElement("div");\n
    this.scroller.className = "ace_scroller";\n
    this.container.appendChild(this.scroller);\n
\n
    this.content = dom.createElement("div");\n
    this.content.className = "ace_content";\n
    this.scroller.appendChild(this.content);\n
\n
    this.$gutterLayer = new GutterLayer(this.$gutter);\n
    this.$gutterLayer.on("changeGutterWidth", this.onGutterResize.bind(this));\n
\n
    this.$markerBack = new MarkerLayer(this.content);\n
\n
    var textLayer = this.$textLayer = new TextLayer(this.content);\n
    this.canvas = textLayer.element;\n
\n
    this.$markerFront = new MarkerLayer(this.content);\n
\n
    this.$cursorLayer = new CursorLayer(this.content);\n
    this.$horizScroll = false;\n
    this.$vScroll = false;\n
\n
    this.scrollBar = \n
    this.scrollBarV = new ScrollBarV(this.container, this);\n
    this.scrollBarH = new ScrollBarH(this.container, this);\n
    this.scrollBarV.addEventListener("scroll", function(e) {\n
        if (!_self.$scrollAnimation)\n
            _self.session.setScrollTop(e.data - _self.scrollMargin.top);\n
    });\n
    this.scrollBarH.addEventListener("scroll", function(e) {\n
        if (!_self.$scrollAnimation)\n
            _self.session.setScrollLeft(e.data - _self.scrollMargin.left);\n
    });\n
\n
    this.scrollTop = 0;\n
    this.scrollLeft = 0;\n
\n
    this.cursorPos = {\n
        row : 0,\n
        column : 0\n
    };\n
\n
    this.$textLayer.addEventListener("changeCharacterSize", function() {\n
        _self.updateCharacterSize();\n
        _self.onResize(true);\n
        _self._signal("changeCharacterSize");\n
    });\n
\n
    this.$size = {\n
        width: 0,\n
        height: 0,\n
        scrollerHeight: 0,\n
        scrollerWidth: 0\n
    };\n
\n
    this.layerConfig = {\n
        width : 1,\n
        padding : 0,\n
        firstRow : 0,\n
        firstRowScreen: 0,\n
        lastRow : 0,\n
        lineHeight : 0,\n
        characterWidth : 0,\n
        minHeight : 1,\n
        maxHeight : 1,\n
        offset : 0,\n
        height : 1\n
    };\n
    \n
    this.scrollMargin = {\n
        left: 0,\n
        right: 0,\n
        top: 0,\n
        bottom: 0,\n
        v: 0,\n
        h: 0\n
    };\n
\n
    this.$loop = new RenderLoop(\n
        this.$renderChanges.bind(this),\n
        this.container.ownerDocument.defaultView\n
    );\n
    this.$loop.schedule(this.CHANGE_FULL);\n
\n
    this.updateCharacterSize();\n
    this.setPadding(4);\n
    config.resetOptions(this);\n
    config._emit("renderer", this);\n
};\n
\n
(function() {\n
\n
    this.CHANGE_CURSOR = 1;\n
    this.CHANGE_MARKER = 2;\n
    this.CHANGE_GUTTER = 4;\n
    this.CHANGE_SCROLL = 8;\n
    this.CHANGE_LINES = 16;\n
    this.CHANGE_TEXT = 32;\n
    this.CHANGE_SIZE = 64;\n
    this.CHANGE_MARKER_BACK = 128;\n
    this.CHANGE_MARKER_FRONT = 256;\n
    this.CHANGE_FULL = 512;\n
    this.CHANGE_H_SCROLL = 1024;\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.updateCharacterSize = function() {\n
        if (this.$textLayer.allowBoldFonts != this.$allowBoldFonts) {\n
            this.$allowBoldFonts = this.$textLayer.allowBoldFonts;\n
            this.setStyle("ace_nobold", !this.$allowBoldFonts);\n
        }\n
\n
        this.layerConfig.characterWidth =\n
        this.characterWidth = this.$textLayer.getCharacterWidth();\n
        this.layerConfig.lineHeight =\n
        this.lineHeight = this.$textLayer.getLineHeight();\n
        this.$updatePrintMargin();\n
    };\n
    this.setSession = function(session) {\n
        this.session = session;\n
\n
        this.scroller.className = "ace_scroller";\n
\n
        this.$cursorLayer.setSession(session);\n
        this.$markerBack.setSession(session);\n
        this.$markerFront.setSession(session);\n
        this.$gutterLayer.setSession(session);\n
        this.$textLayer.setSession(session);\n
        this.$loop.schedule(this.CHANGE_FULL);\n
\n
    };\n
    this.updateLines = function(firstRow, lastRow) {\n
        if (lastRow === undefined)\n
            lastRow = Infinity;\n
\n
        if (!this.$changedLines) {\n
            this.$changedLines = {\n
                firstRow: firstRow,\n
                lastRow: lastRow\n
            };\n
        }\n
        else {\n
            if (this.$changedLines.firstRow > firstRow)\n
                this.$changedLines.firstRow = firstRow;\n
\n
            if (this.$changedLines.lastRow < lastRow)\n
                this.$changedLines.lastRow = lastRow;\n
        }\n
\n
        if (this.$changedLines.firstRow > this.layerConfig.lastRow ||\n
            this.$changedLines.lastRow < this.layerConfig.firstRow)\n
            return;\n
        this.$loop.schedule(this.CHANGE_LINES);\n
    };\n
\n
    this.onChangeTabSize = function() {\n
        this.$loop.schedule(this.CHANGE_TEXT | this.CHANGE_MARKER);\n
        this.$textLayer.onChangeTabSize();\n
    };\n
    this.updateText = function() {\n
        this.$loop.schedule(this.CHANGE_TEXT);\n
    };\n
    this.updateFull = function(force) {\n
        if (force)\n
            this.$renderChanges(this.CHANGE_FULL, true);\n
        else\n
            this.$loop.schedule(this.CHANGE_FULL);\n
    };\n
    this.updateFontSize = function() {\n
        this.$textLayer.checkForSizeChanges();\n
    };\n
\n
    this.$changes = 0;\n
    this.onResize = function(force, gutterWidth, width, height) {\n
        if (this.resizing > 2)\n
            return;\n
        else if (this.resizing > 0)\n
            this.resizing++;\n
        else\n
            this.resizing = force ? 1 : 0;\n
        var el = this.container;\n
        if (!height)\n
            height = el.clientHeight || el.scrollHeight;\n
        if (!width)\n
            width = el.clientWidth || el.scrollWidth;\n
\n
        var changes = this.$updateCachedSize(force, gutterWidth, width, height);\n
        \n
        if (!this.$size.scrollerHeight || (!width && !height))\n
            return this.resizing = 0;\n
\n
        if (force)\n
            this.$gutterLayer.$padding = null;\n
\n
        if (force)\n
            this.$renderChanges(changes, true);\n
        else\n
            this.$loop.schedule(changes | this.$changes);\n
\n
        if (this.resizing)\n
            this.resizing = 0;\n
    };\n
    \n
    this.$updateCachedSize = function(force, gutterWidth, width, height) {\n
        var changes = 0;\n
        var size = this.$size;\n
        var oldSize = {\n
            width: size.width,\n
            height: size.height,\n
            scrollerHeight: size.scrollerHeight,\n
            scrollerWidth: size.scrollerWidth\n
        };\n
        if (height && (force || size.height != height)) {\n
            size.height = height;\n
            changes = this.CHANGE_SIZE;\n
\n
            size.scrollerHeight = size.height;\n
            if (this.$horizScroll)\n
                size.scrollerHeight -= this.scrollBarH.getHeight();\n
            this.scrollBarV.element.style.bottom = this.scrollBarH.getHeight() + "px";\n
\n
            if (this.session) {\n
                this.session.setScrollTop(this.getScrollTop());\n
                changes = changes | this.CHANGE_SCROLL;\n
            }\n
        }\n
\n
        if (width && (force || size.width != width)) {\n
            changes = this.CHANGE_SIZE;\n
            size.width = width;\n
            \n
            if (gutterWidth == null)\n
                gutterWidth = this.$showGutter ? this.$gutter.offsetWidth : 0;\n
            \n
            this.gutterWidth = gutterWidth;\n
            \n
            this.scrollBarH.element.style.left = \n
            this.scroller.style.left = gutterWidth + "px";\n
            size.scrollerWidth = Math.max(0, width - gutterWidth - this.scrollBarV.getWidth());           \n
            \n
            this.scrollBarH.element.style.right = \n
            this.scroller.style.right = this.scrollBarV.getWidth() + "px";\n
            this.scroller.style.bottom = this.scrollBarH.getHeight() + "px";\n
\n
            if (this.session && this.session.getUseWrapMode() && this.adjustWrapLimit() || force)\n
                changes = changes | this.CHANGE_FULL;\n
        }\n
        \n
        if (changes)\n
            this._signal("resize", oldSize);\n
\n
        return changes;\n
    };\n
\n
    this.onGutterResize = function() {\n
        var gutterWidth = this.$showGutter ? this.$gutter.offsetWidt

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAg=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="8" aka="AAAAAAAAAAg=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

h : 0;\n
        if (gutterWidth != this.gutterWidth)\n
            this.$changes |= this.$updateCachedSize(true, gutterWidth, this.$size.width, this.$size.height);\n
\n
        if (this.session.getUseWrapMode() && this.adjustWrapLimit())\n
            this.$loop.schedule(this.CHANGE_FULL);\n
        else {\n
            this.$computeLayerConfig();\n
            this.$loop.schedule(this.CHANGE_MARKER);\n
        }\n
    };\n
    this.adjustWrapLimit = function() {\n
        var availableWidth = this.$size.scrollerWidth - this.$padding * 2;\n
        var limit = Math.floor(availableWidth / this.characterWidth);\n
        return this.session.adjustWrapLimit(limit, this.$showPrintMargin && this.$printMarginColumn);\n
    };\n
    this.setAnimatedScroll = function(shouldAnimate){\n
        this.setOption("animatedScroll", shouldAnimate);\n
    };\n
    this.getAnimatedScroll = function() {\n
        return this.$animatedScroll;\n
    };\n
    this.setShowInvisibles = function(showInvisibles) {\n
        this.setOption("showInvisibles", showInvisibles);\n
    };\n
    this.getShowInvisibles = function() {\n
        return this.getOption("showInvisibles");\n
    };\n
    this.getDisplayIndentGuides = function() {\n
        return this.getOption("displayIndentGuides");\n
    };\n
\n
    this.setDisplayIndentGuides = function(display) {\n
        this.setOption("displayIndentGuides", display);\n
    };\n
    this.setShowPrintMargin = function(showPrintMargin) {\n
        this.setOption("showPrintMargin", showPrintMargin);\n
    };\n
    this.getShowPrintMargin = function() {\n
        return this.getOption("showPrintMargin");\n
    };\n
    this.setPrintMarginColumn = function(showPrintMargin) {\n
        this.setOption("printMarginColumn", showPrintMargin);\n
    };\n
    this.getPrintMarginColumn = function() {\n
        return this.getOption("printMarginColumn");\n
    };\n
    this.getShowGutter = function(){\n
        return this.getOption("showGutter");\n
    };\n
    this.setShowGutter = function(show){\n
        return this.setOption("showGutter", show);\n
    };\n
\n
    this.getFadeFoldWidgets = function(){\n
        return this.getOption("fadeFoldWidgets")\n
    };\n
\n
    this.setFadeFoldWidgets = function(show) {\n
        this.setOption("fadeFoldWidgets", show);\n
    };\n
\n
    this.setHighlightGutterLine = function(shouldHighlight) {\n
        this.setOption("highlightGutterLine", shouldHighlight);\n
    };\n
\n
    this.getHighlightGutterLine = function() {\n
        return this.getOption("highlightGutterLine");\n
    };\n
\n
    this.$updateGutterLineHighlight = function() {\n
        var pos = this.$cursorLayer.$pixelPos;\n
        var height = this.layerConfig.lineHeight;\n
        if (this.session.getUseWrapMode()) {\n
            var cursor = this.session.selection.getCursor();\n
            cursor.column = 0;\n
            pos = this.$cursorLayer.getPixelPosition(cursor, true);\n
            height *= this.session.getRowLength(cursor.row);\n
        }\n
        this.$gutterLineHighlight.style.top = pos.top - this.layerConfig.offset + "px";\n
        this.$gutterLineHighlight.style.height = height + "px";\n
    };\n
\n
    this.$updatePrintMargin = function() {\n
        if (!this.$showPrintMargin && !this.$printMarginEl)\n
            return;\n
\n
        if (!this.$printMarginEl) {\n
            var containerEl = dom.createElement("div");\n
            containerEl.className = "ace_layer ace_print-margin-layer";\n
            this.$printMarginEl = dom.createElement("div");\n
            this.$printMarginEl.className = "ace_print-margin";\n
            containerEl.appendChild(this.$printMarginEl);\n
            this.content.insertBefore(containerEl, this.content.firstChild);\n
        }\n
\n
        var style = this.$printMarginEl.style;\n
        style.left = ((this.characterWidth * this.$printMarginColumn) + this.$padding) + "px";\n
        style.visibility = this.$showPrintMargin ? "visible" : "hidden";\n
        \n
        if (this.session && this.session.$wrap == -1)\n
            this.adjustWrapLimit();\n
    };\n
    this.getContainerElement = function() {\n
        return this.container;\n
    };\n
    this.getMouseEventTarget = function() {\n
        return this.content;\n
    };\n
    this.getTextAreaContainer = function() {\n
        return this.container;\n
    };\n
    this.$moveTextAreaToCursor = function() {\n
        if (!this.$keepTextAreaAtCursor)\n
            return;\n
        var config = this.layerConfig;\n
        var posTop = this.$cursorLayer.$pixelPos.top;\n
        var posLeft = this.$cursorLayer.$pixelPos.left;\n
        posTop -= config.offset;\n
\n
        var h = this.lineHeight;\n
        if (posTop < 0 || posTop > config.height - h)\n
            return;\n
\n
        var w = this.characterWidth;\n
        if (this.$composition) {\n
            var val = this.textarea.value.replace(/^\\x01+/, "");\n
            w *= (this.session.$getStringScreenWidth(val)[0]+2);\n
            h += 2;\n
            posTop -= 1;\n
        }\n
        posLeft -= this.scrollLeft;\n
        if (posLeft > this.$size.scrollerWidth - w)\n
            posLeft = this.$size.scrollerWidth - w;\n
\n
        posLeft -= this.scrollBar.width;\n
\n
        this.textarea.style.height = h + "px";\n
        this.textarea.style.width = w + "px";\n
        this.textarea.style.right = Math.max(0, this.$size.scrollerWidth - posLeft - w) + "px";\n
        this.textarea.style.bottom = Math.max(0, this.$size.height - posTop - h) + "px";\n
    };\n
    this.getFirstVisibleRow = function() {\n
        return this.layerConfig.firstRow;\n
    };\n
    this.getFirstFullyVisibleRow = function() {\n
        return this.layerConfig.firstRow + (this.layerConfig.offset === 0 ? 0 : 1);\n
    };\n
    this.getLastFullyVisibleRow = function() {\n
        var flint = Math.floor((this.layerConfig.height + this.layerConfig.offset) / this.layerConfig.lineHeight);\n
        return this.layerConfig.firstRow - 1 + flint;\n
    };\n
    this.getLastVisibleRow = function() {\n
        return this.layerConfig.lastRow;\n
    };\n
\n
    this.$padding = null;\n
    this.setPadding = function(padding) {\n
        this.$padding = padding;\n
        this.$textLayer.setPadding(padding);\n
        this.$cursorLayer.setPadding(padding);\n
        this.$markerFront.setPadding(padding);\n
        this.$markerBack.setPadding(padding);\n
        this.$loop.schedule(this.CHANGE_FULL);\n
        this.$updatePrintMargin();\n
    };\n
    \n
    this.setScrollMargin = function(top, bottom, left, right) {\n
        var sm = this.scrollMargin;\n
        sm.top = top|0;\n
        sm.bottom = bottom|0;\n
        sm.right = right|0;\n
        sm.left = left|0;\n
        sm.v = sm.top + sm.bottom;\n
        sm.h = sm.left + sm.right;\n
        this.updateFull();\n
    };\n
    this.getHScrollBarAlwaysVisible = function() {\n
        return this.$hScrollBarAlwaysVisible;\n
    };\n
    this.setHScrollBarAlwaysVisible = function(alwaysVisible) {\n
        this.setOption("hScrollBarAlwaysVisible", alwaysVisible);\n
    };\n
    this.getVScrollBarAlwaysVisible = function() {\n
        return this.$hScrollBarAlwaysVisible;\n
    };\n
    this.setVScrollBarAlwaysVisible = function(alwaysVisible) {\n
        this.setOption("vScrollBarAlwaysVisible", alwaysVisible);\n
    };\n
\n
    this.$updateScrollBarV = function() {\n
        this.scrollBarV.setInnerHeight(this.layerConfig.maxHeight + this.scrollMargin.v);\n
        this.scrollBarV.setScrollTop(this.scrollTop + this.scrollMargin.top);\n
    };\n
    this.$updateScrollBarH = function() {\n
        this.scrollBarH.setInnerWidth(this.layerConfig.width + 2 * this.$padding + this.scrollMargin.h);\n
        this.scrollBarH.setScrollLeft(this.scrollLeft + this.scrollMargin.left);\n
    };\n
\n
    this.$renderChanges = function(changes, force) {\n
        if (this.$changes) {\n
            changes |= this.$changes;\n
            this.$changes = 0;\n
        }\n
        if ((!this.session || !this.container.offsetWidth) || (!changes && !force)) {\n
            this.$changes |= changes;\n
            return; \n
        } \n
        if (!this.$size.width) {\n
            this.$changes |= changes;\n
            return this.onResize(true);\n
        }\n
        if (!this.lineHeight) {\n
            this.$textLayer.checkForSizeChanges();\n
        }\n
        \n
        this._signal("beforeRender");\n
        if (changes & this.CHANGE_FULL ||\n
            changes & this.CHANGE_SIZE ||\n
            changes & this.CHANGE_TEXT ||\n
            changes & this.CHANGE_LINES ||\n
            changes & this.CHANGE_SCROLL ||\n
            changes & this.CHANGE_H_SCROLL\n
        )\n
            changes |= this.$computeLayerConfig();\n
        if (changes & this.CHANGE_H_SCROLL) {\n
            this.$updateScrollBarH();\n
            this.content.style.marginLeft = -this.scrollLeft + "px";\n
            this.scroller.className = this.scrollLeft <= 0 ? "ace_scroller" : "ace_scroller ace_scroll-left";\n
        }\n
        if (changes & this.CHANGE_FULL) {\n
            this.$updateScrollBarV();\n
            this.$updateScrollBarH();\n
            this.$textLayer.update(this.layerConfig);\n
            if (this.$showGutter)\n
                this.$gutterLayer.update(this.layerConfig);\n
            this.$markerBack.update(this.layerConfig);\n
            this.$markerFront.update(this.layerConfig);\n
            this.$cursorLayer.update(this.layerConfig);\n
            this.$moveTextAreaToCursor();\n
            this.$highlightGutterLine && this.$updateGutterLineHighlight();\n
            this._signal("afterRender");\n
            return;\n
        }\n
        if (changes & this.CHANGE_SCROLL) {\n
            this.$updateScrollBarV();\n
            if (changes & this.CHANGE_TEXT || changes & this.CHANGE_LINES)\n
                this.$textLayer.update(this.layerConfig);\n
            else\n
                this.$textLayer.scrollLines(this.layerConfig);\n
\n
            if (this.$showGutter)\n
                this.$gutterLayer.update(this.layerConfig);\n
            this.$markerBack.update(this.layerConfig);\n
            this.$markerFront.update(this.layerConfig);\n
            this.$cursorLayer.update(this.layerConfig);\n
            this.$highlightGutterLine && this.$updateGutterLineHighlight();\n
            this.$moveTextAreaToCursor();\n
            this._signal("afterRender");\n
            return;\n
        }\n
\n
        if (changes & this.CHANGE_TEXT) {\n
            this.$textLayer.update(this.layerConfig);\n
            if (this.$showGutter)\n
                this.$gutterLayer.update(this.layerConfig);\n
        }\n
        else if (changes & this.CHANGE_LINES) {\n
            if (this.$updateLines() || (changes & this.CHANGE_GUTTER) && this.$showGutter)\n
                this.$gutterLayer.update(this.layerConfig);\n
        }\n
        else if (changes & this.CHANGE_TEXT || changes & this.CHANGE_GUTTER) {\n
            if (this.$showGutter)\n
                this.$gutterLayer.update(this.layerConfig);\n
        }\n
\n
        if (changes & this.CHANGE_CURSOR) {\n
            this.$cursorLayer.update(this.layerConfig);\n
            this.$moveTextAreaToCursor();\n
            this.$highlightGutterLine && this.$updateGutterLineHighlight();\n
        }\n
\n
        if (changes & (this.CHANGE_MARKER | this.CHANGE_MARKER_FRONT)) {\n
            this.$markerFront.update(this.layerConfig);\n
        }\n
\n
        if (changes & (this.CHANGE_MARKER | this.CHANGE_MARKER_BACK)) {\n
            this.$markerBack.update(this.layerConfig);\n
        }\n
\n
        if (changes & this.CHANGE_SIZE || changes & this.CHANGE_LINES) {\n
            this.$updateScrollBarV();\n
            this.$updateScrollBarH();\n
        }\n
\n
        this._signal("afterRender");\n
    };\n
\n
    \n
    this.$autosize = function(height, width) {\n
        var height = this.session.getScreenLength() * this.lineHeight;\n
        var maxHeight = this.$maxLines * this.lineHeight;\n
        var desiredHeight = Math.max(\n
            (this.$minLines||1) * this.lineHeight,\n
            Math.min(maxHeight, height)\n
        );\n
        var vScroll = height > maxHeight;\n
        \n
        if (desiredHeight != this.desiredHeight ||\n
            this.$size.height != this.desiredHeight || vScroll != this.$vScroll) {\n
            if (vScroll != this.$vScroll) {\n
                this.$vScroll = vScroll;\n
                this.scrollBarV.setVisible(vScroll);\n
            }\n
            \n
            var w = this.container.clientWidth;\n
            this.container.style.height = desiredHeight + "px";\n
            this.$updateCachedSize(true, this.$gutterWidth, w, desiredHeight);\n
            this.desiredHeight = desiredHeight;\n
        }\n
    };\n
    \n
    this.$computeLayerConfig = function() {\n
        if (this.$maxLines && this.lineHeight > 1)\n
            this.$autosize();\n
\n
        var session = this.session;\n
        \n
        var hideScrollbars = this.$size.height <= 2 * this.lineHeight;\n
        var screenLines = this.session.getScreenLength()\n
        var maxHeight = screenLines * this.lineHeight;\n
\n
        var offset = this.scrollTop % this.lineHeight;\n
        var minHeight = this.$size.scrollerHeight + this.lineHeight;\n
\n
        var longestLine = this.$getLongestLine();\n
        \n
        var horizScroll = !hideScrollbars && (this.$hScrollBarAlwaysVisible ||\n
            this.$size.scrollerWidth - longestLine - 2 * this.$padding < 0);\n
\n
        var hScrollChanged = this.$horizScroll !== horizScroll;\n
        if (hScrollChanged) {\n
            this.$horizScroll = horizScroll;\n
            this.scrollBarH.setVisible(horizScroll);\n
        }\n
        \n
        if (!this.$maxLines && this.$scrollPastEnd) {\n
            if (this.scrollTop > maxHeight - this.$size.scrollerHeight)\n
                maxHeight += Math.min(\n
                    (this.$size.scrollerHeight - this.lineHeight) * this.$scrollPastEnd,\n
                    this.scrollTop - maxHeight + this.$size.scrollerHeight\n
                );\n
        }\n
        \n
        var vScroll = !hideScrollbars && (this.$vScrollBarAlwaysVisible ||\n
            this.$size.scrollerHeight - maxHeight < 0);\n
        var vScrollChanged = this.$vScroll !== vScroll;\n
        if (vScrollChanged) {\n
            this.$vScroll = vScroll;\n
            this.scrollBarV.setVisible(vScroll);\n
        }\n
        \n
        this.session.setScrollTop(Math.max(-this.scrollMargin.top,\n
            Math.min(this.scrollTop, maxHeight - this.$size.scrollerHeight + this.scrollMargin.v)));\n
\n
        this.session.setScrollLeft(Math.max(-this.scrollMargin.left, Math.min(this.scrollLeft, \n
            longestLine + 2 * this.$padding - this.$size.scrollerWidth + this.scrollMargin.h)));\n
\n
        var lineCount = Math.ceil(minHeight / this.lineHeight) - 1;\n
        var firstRow = Math.max(0, Math.round((this.scrollTop - offset) / this.lineHeight));\n
        var lastRow = firstRow + lineCount;\n
        var firstRowScreen, firstRowHeight;\n
        var lineHeight = this.lineHeight;\n
        firstRow = session.screenToDocumentRow(firstRow, 0);\n
        var foldLine = session.getFoldLine(firstRow);\n
        if (foldLine) {\n
            firstRow = foldLine.start.row;\n
        }\n
\n
        firstRowScreen = session.documentToScreenRow(firstRow, 0);\n
        firstRowHeight = session.getRowLength(firstRow) * lineHeight;\n
\n
        lastRow = Math.min(session.screenToDocumentRow(lastRow, 0), session.getLength() - 1);\n
        minHeight = this.$size.scrollerHeight + session.getRowLength(lastRow) * lineHeight +\n
                                                firstRowHeight;\n
\n
        offset = this.scrollTop - firstRowScreen * lineHeight;\n
\n
        var changes = 0;\n
        if (hScrollChanged || vScrollChanged) {\n
            changes = this.$updateCachedSize(true, this.gutterWidth, this.$size.width, this.$size.height);\n
            this._signal("scrollbarVisibilityChanged");\n
            if (vScrollChanged)\n
                longestLine = this.$getLongestLine();\n
        }\n
        \n
        this.layerConfig = {\n
            width : longestLine,\n
            padding : this.$padding,\n
            firstRow : firstRow,\n
            firstRowScreen: firstRowScreen,\n
            lastRow : lastRow,\n
            lineHeight : lineHeight,\n
            characterWidth : this.characterWidth,\n
            minHeight : minHeight,\n
            maxHeight : maxHeight,\n
            offset : offset,\n
            height : this.$size.scrollerHeight\n
        };\n
\n
        this.$gutterLayer.element.style.marginTop = (-offset) + "px";\n
        this.content.style.marginTop = (-offset) + "px";\n
        this.content.style.width = longestLine + 2 * this.$padding + "px";\n
        this.content.style.height = minHeight + "px";\n
\n
        return changes;\n
    };\n
\n
    this.$updateLines = function() {\n
        var firstRow = this.$changedLines.firstRow;\n
        var lastRow = this.$changedLines.lastRow;\n
        this.$changedLines = null;\n
\n
        var layerConfig = this.layerConfig;\n
\n
        if (firstRow > layerConfig.lastRow + 1) { return; }\n
        if (lastRow < layerConfig.firstRow) { return; }\n
        if (lastRow === Infinity) {\n
            if (this.$showGutter)\n
                this.$gutterLayer.update(layerConfig);\n
            this.$textLayer.update(layerConfig);\n
            return;\n
        }\n
        this.$textLayer.updateLines(layerConfig, firstRow, lastRow);\n
        return true;\n
    };\n
\n
    this.$getLongestLine = function() {\n
        var charCount = this.session.getScreenWidth();\n
        if (this.showInvisibles && !this.session.$useWrapMode)\n
            charCount += 1;\n
\n
        return Math.max(this.$size.scrollerWidth - 2 * this.$padding, Math.round(charCount * this.characterWidth));\n
    };\n
    this.updateFrontMarkers = function() {\n
        this.$markerFront.setMarkers(this.session.getMarkers(true));\n
        this.$loop.schedule(this.CHANGE_MARKER_FRONT);\n
    };\n
    this.updateBackMarkers = function() {\n
        this.$markerBack.setMarkers(this.session.getMarkers());\n
        this.$loop.schedule(this.CHANGE_MARKER_BACK);\n
    };\n
    this.addGutterDecoration = function(row, className){\n
        this.$gutterLayer.addGutterDecoration(row, className);\n
    };\n
    this.removeGutterDecoration = function(row, className){\n
        this.$gutterLayer.removeGutterDecoration(row, className);\n
    };\n
    this.updateBreakpoints = function(rows) {\n
        this.$loop.schedule(this.CHANGE_GUTTER);\n
    };\n
    this.setAnnotations = function(annotations) {\n
        this.$gutterLayer.setAnnotations(annotations);\n
        this.$loop.schedule(this.CHANGE_GUTTER);\n
    };\n
    this.updateCursor = function() {\n
        this.$loop.schedule(this.CHANGE_CURSOR);\n
    };\n
    this.hideCursor = function() {\n
        this.$cursorLayer.hideCursor();\n
    };\n
    this.showCursor = function() {\n
        this.$cursorLayer.showCursor();\n
    };\n
\n
    this.scrollSelectionIntoView = function(anchor, lead, offset) {\n
        this.scrollCursorIntoView(anchor, offset);\n
        this.scrollCursorIntoView(lead, offset);\n
    };\n
    this.scrollCursorIntoView = function(cursor, offset) {\n
        if (this.$size.scrollerHeight === 0)\n
            return;\n
\n
        var pos = this.$cursorLayer.getPixelPosition(cursor);\n
\n
        var left = pos.left;\n
        var top = pos.top;\n
        \n
        var scrollTop = this.$scrollAnimation ? this.session.getScrollTop() : this.scrollTop;\n
\n
        if (scrollTop > top) {\n
            if (offset)\n
                top -= offset * this.$size.scrollerHeight;\n
            if (top == 0)\n
                top = - this.scrollMargin.top;\n
            else if (top == 0)\n
                top = + this.scrollMargin.bottom;\n
            this.session.setScrollTop(top);\n
        } else if (scrollTop + this.$size.scrollerHeight < top + this.lineHeight) {\n
            if (offset)\n
                top += offset * this.$size.scrollerHeight;\n
            this.session.setScrollTop(top + this.lineHeight - this.$size.scrollerHeight);\n
        }\n
\n
        var scrollLeft = this.scrollLeft;\n
\n
        if (scrollLeft > left) {\n
            if (left < this.$padding + 2 * this.layerConfig.characterWidth)\n
                left = -this.scrollMargin.left;\n
            this.session.setScrollLeft(left);\n
        } else if (scrollLeft + this.$size.scrollerWidth < left + this.characterWidth) {\n
            this.session.setScrollLeft(Math.round(left + this.characterWidth - this.$size.scrollerWidth));\n
        } else if (scrollLeft <= this.$padding && left - scrollLeft < this.characterWidth) {\n
            this.session.setScrollLeft(0);\n
        }\n
    };\n
    this.getScrollTop = function() {\n
        return this.session.getScrollTop();\n
    };\n
    this.getScrollLeft = function() {\n
        return this.session.getScrollLeft();\n
    };\n
    this.getScrollTopRow = function() {\n
        return this.scrollTop / this.lineHeight;\n
    };\n
    this.getScrollBottomRow = function() {\n
        return Math.max(0, Math.floor((this.scrollTop + this.$size.scrollerHeight) / this.lineHeight) - 1);\n
    };\n
    this.scrollToRow = function(row) {\n
        this.session.setScrollTop(row * this.lineHeight);\n
    };\n
\n
    this.alignCursor = function(cursor, alignment) {\n
        if (typeof cursor == "number")\n
            cursor = {row: cursor, column: 0};\n
\n
        var pos = this.$cursorLayer.getPixelPosition(cursor);\n
        var h = this.$size.scrollerHeight - this.lineHeight;\n
        var offset = pos.top - h * (alignment || 0);\n
\n
        this.session.setScrollTop(offset);\n
        return offset;\n
    };\n
\n
    this.STEPS = 8;\n
    this.$calcSteps = function(fromValue, toValue){\n
        var i = 0;\n
        var l = this.STEPS;\n
        var steps = [];\n
\n
        var func  = function(t, x_min, dx) {\n
            return dx * (Math.pow(t - 1, 3) + 1) + x_min;\n
        };\n
\n
        for (i = 0; i < l; ++i)\n
            steps.push(func(i / this.STEPS, fromValue, toValue - fromValue));\n
\n
        return steps;\n
    };\n
    this.scrollToLine = function(line, center, animate, callback) {\n
        var pos = this.$cursorLayer.getPixelPosition({row: line, column: 0});\n
        var offset = pos.top;\n
        if (center)\n
            offset -= this.$size.scrollerHeight / 2;\n
\n
        var initialScroll = this.scrollTop;\n
        this.session.setScrollTop(offset);\n
        if (animate !== false)\n
            this.animateScrolling(initialScroll, callback);\n
    };\n
\n
    this.animateScrolling = function(fromValue, callback) {\n
        var toValue = this.scrollTop;\n
        if (!this.$animatedScroll)\n
            return;\n
        var _self = this;\n
        \n
        if (fromValue == toValue)\n
            return;\n
        \n
        if (this.$scrollAnimation) {\n
            var oldSteps = this.$scrollAnimation.steps;\n
            if (oldSteps.length) {\n
                fromValue = oldSteps[0];\n
                if (fromValue == toValue)\n
                    return;\n
            }\n
        }\n
        \n
        var steps = _self.$calcSteps(fromValue, toValue);\n
        this.$scrollAnimation = {from: fromValue, to: toValue, steps: steps};\n
\n
        clearInterval(this.$timer);\n
\n
        _self.session.setScrollTop(steps.shift());\n
        this.$timer = setInterval(function() {\n
            if (steps.length) {\n
                _self.session.setScrollTop(steps.shift());\n
                _self.session.$scrollTop = toValue;\n
            } else if (toValue != null) {\n
                _self.session.$scrollTop = -1;\n
                _self.session.setScrollTop(toValue);\n
                toValue = null;\n
            } else {\n
                _self.$timer = clearInterval(_self.$timer);\n
                _self.$scrollAnimation = null;\n
                callback && callback();\n
            }\n
        }, 10);\n
    };\n
    this.scrollToY = function(scrollTop) {\n
        if (this.scrollTop !== scrollTop) {\n
            this.$loop.schedule(this.CHANGE_SCROLL);\n
            this.scrollTop = scrollTop;\n
        }\n
    };\n
    this.scrollToX = function(scrollLeft) {\n
        if (this.scrollLeft !== scrollLeft)\n
            this.scrollLeft = scrollLeft;\n
        this.$loop.schedule(this.CHANGE_H_SCROLL);\n
    };\n
    this.scrollTo = function(x, y) {\n
        this.session.setScrollTop(y);\n
        this.session.setScrollLeft(y);\n
    };\n
    this.scrollBy = function(deltaX, deltaY) {\n
        deltaY && this.session.setScrollTop(this.session.getScrollTop() + deltaY);\n
        deltaX && this.session.setScrollLeft(this.session.getScrollLeft() + deltaX);\n
    };\n
    this.isScrollableBy = function(deltaX, deltaY) {\n
        if (deltaY < 0 && this.session.getScrollTop() >= 1 - this.scrollMargin.top)\n
           return true;\n
        if (deltaY > 0 && this.session.getScrollTop() + this.$size.scrollerHeight\n
            - this.layerConfig.maxHeight - (this.$size.scrollerHeight - this.lineHeight) * this.$scrollPastEnd\n
            < -1 + this.scrollMargin.bottom)\n
           return true;\n
        if (deltaX < 0 && this.session.getScrollLeft() >= 1 - this.scrollMargin.left)\n
            return true;\n
        if (deltaX > 0 && this.session.getScrollLeft() + this.$size.scrollerWidth\n
            - this.layerConfig.width < -1 + this.scrollMargin.right)\n
           return true;\n
    };\n
\n
    this.pixelToScreenCoordinates = function(x, y) {\n
        var canvasPos = this.scroller.getBoundingClientRect();\n
\n
        var offset = (x + this.scrollLeft - canvasPos.left - this.$padding) / this.characterWidth;\n
        var row = Math.floor((y + this.scrollTop - canvasPos.top) / this.lineHeight);\n
        var col = Math.round(offset);\n
\n
        return {row: row, column: col, side: offset - col > 0 ? 1 : -1};\n
    };\n
\n
    this.screenToTextCoordinates = function(x, y) {\n
        var canvasPos = this.scroller.getBoundingClientRect();\n
\n
        var col = Math.round(\n
            (x + this.scrollLeft - canvasPos.left - this.$padding) / this.characterWidth\n
        );\n
        var row = Math.floor(\n
            (y + this.scrollTop - canvasPos.top) / this.lineHeight\n
        );\n
\n
        return this.session.screenToDocumentPosition(row, Math.max(col, 0));\n
    };\n
    this.textToScreenCoordinates = function(row, column) {\n
        var canvasPos = this.scroller.getBoundingClientRect();\n
        var pos = this.session.documentToScreenPosition(row, column);\n
\n
        var x = this.$padding + Math.round(pos.column * this.characterWidth);\n
        var y = pos.row * this.lineHeight;\n
\n
        return {\n
            pageX: canvasPos.left + x - this.scrollLeft,\n
            pageY: canvasPos.top + y - this.scrollTop\n
        };\n
    };\n
    this.visualizeFocus = function() {\n
        dom.addCssClass(this.container, "ace_focus");\n
    };\n
    this.visualizeBlur = function() {\n
        dom.removeCssClass(this.container, "ace_focus");\n
    };\n
    this.showComposition = function(position) {\n
        if (!this.$composition)\n
            this.$composition = {\n
                keepTextAreaAtCursor: this.$keepTextAreaAtCursor,\n
                cssText: this.textarea.style.cssText\n
            };\n
\n
        this.$keepTextAreaAtCursor = true;\n
        dom.addCssClass(this.textarea, "ace_composition");\n
        this.textarea.style.cssText = "";\n
        this.$moveTextAreaToCursor();\n
    };\n
    this.setCompositionText = function(text) {\n
        this.$moveTextAreaToCursor();\n
    };\n
    this.hideComposition = function() {\n
        if (!this.$composition)\n
            return;\n
\n
        dom.removeCssClass(this.textarea, "ace_composition");\n
        this.$keepTextAreaAtCursor = this.$composition.keepTextAreaAtCursor;\n
        this.textarea.style.cssText = this.$composition.cssText;\n
        this.$composition = null;\n
    };\n
    this.setTheme = function(theme, cb) {\n
        var _self = this;\n
        this.$themeValue = theme;\n
        _self._dispatchEvent(\'themeChange\',{theme:theme});\n
\n
        if (!theme || typeof theme == "string") {\n
            var moduleName = theme || "ace/theme/textmate";\n
            config.loadModule(["theme", moduleName], afterLoad);\n
        } else {\n
            afterLoad(theme);\n
        }\n
\n
        function afterLoad(module) {\n
            if (_self.$themeValue != theme)\n
                return cb && cb();\n
            if (!module.cssClass)\n
                return;\n
            dom.importCssString(\n
                module.cssText,\n
                module.cssClass,\n
                _self.container.ownerDocument\n
            );\n
\n
            if (_self.theme)\n
                dom.removeCssClass(_self.container, _self.theme.cssClass);\n
            _self.$theme = module.cssClass;\n
\n
            _self.theme = module;\n
            dom.addCssClass(_self.container, module.cssClass);\n
            dom.setCssClass(_self.container, "ace_dark", module.isDark);\n
\n
            var padding = "padding" in module ? module.padding : 4;\n
            if (_self.$padding && padding != _self.$padding)\n
                _self.setPadding(padding);\n
            if (_self.$size) {\n
                _self.$size.width = 0;\n
                _self.onResize();\n
            }\n
\n
            _self._dispatchEvent(\'themeLoaded\', {theme:module});\n
            cb && cb();\n
        }\n
    };\n
    this.getTheme = function() {\n
        return this.$themeValue;\n
    };\n
    this.setStyle = function(style, include) {\n
        dom.setCssClass(this.container, style, include != false);\n
    };\n
    this.unsetStyle = function(style) {\n
        dom.removeCssClass(this.container, style);\n
    };\n
    this.setMouseCursor = function(cursorStyle) {\n
        this.content.style.cursor = cursorStyle;\n
    };\n
    this.destroy = function() {\n
        this.$textLayer.destroy();\n
        this.$cursorLayer.destroy();\n
    };\n
\n
}).call(VirtualRenderer.prototype);\n
\n
\n
config.defineOptions(VirtualRenderer.prototype, "renderer", {\n
    animatedScroll: {initialValue: false},\n
    showInvisibles: {\n
        set: function(value) {\n
            if (this.$textLayer.setShowInvisibles(value))\n
                this.$loop.schedule(this.CHANGE_TEXT);\n
        },\n
        initialValue: false\n
    },\n
    showPrintMargin: {\n
        set: function() { this.$updatePrintMargin(); },\n
        initialValue: true\n
    },\n
    printMarginColumn: {\n
        set: function() { this.$updatePrintMargin(); },\n
        initialValue: 80\n
    },\n
    printMargin: {\n
        set: function(val) {\n
            if (typeof val == "number")\n
                this.$printMarginColumn = val;\n
            this.$showPrintMargin = !!val;\n
            this.$updatePrintMargin();\n
        },\n
        get: function() {\n
            return this.$showPrintMargin && this.$printMarginColumn; \n
        }\n
    },\n
    showGutter: {\n
        set: function(show){\n
            this.$gutter.style.display = show ? "block" : "none";\n
            this.onGutterResize();\n
        },\n
        initialValue: true\n
    },\n
    fadeFoldWidgets: {\n
        set: function(show) {\n
            dom.setCssClass(this.$gutter, "ace_fade-fold-widgets", show);\n
        },\n
        initialValue: false\n
    },\n
    showFoldWidgets: {\n
        set: function(show) {this.$gutterLayer.setShowFoldWidgets(show)},\n
        initialValue: true\n
    },\n
    displayIndentGuides: {\n
        set: function(show) {\n
            if (this.$textLayer.setDisplayIndentGuides(show))\n
                this.$loop.schedule(this.CHANGE_TEXT);\n
        },\n
        initialValue: true\n
    },\n
    highlightGutterLine: {\n
        set: function(shouldHighlight) {\n
            if (!this.$gutterLineHighlight) {\n
                this.$gutterLineHighlight = dom.createElement("div");\n
                this.$gutterLineHighlight.className = "ace_gutter-active-line";\n
                this.$gutter.appendChild(this.$gutterLineHighlight);\n
                return;\n
            }\n
\n
            this.$gutterLineHighlight.style.display = shouldHighlight ? "" : "none";\n
            if (this.$cursorLayer.$pixelPos)\n
                this.$updateGutterLineHighlight();\n
        },\n
        initialValue: false,\n
        value: true\n
    },\n
    hScrollBarAlwaysVisible: {\n
        set: function(val) {\n
            if (!this.$hScrollBarAlwaysVisible || !this.$horizScroll)\n
                this.$loop.schedule(this.CHANGE_SCROLL);\n
        },\n
        initialValue: false\n
    },\n
    vScrollBarAlwaysVisible: {\n
        set: function(val) {\n
            if (!this.$vScrollBarAlwaysVisible || !this.$vScroll)\n
                this.$loop.schedule(this.CHANGE_SCROLL);\n
        },\n
        initialValue: false\n
    },\n
    fontSize:  {\n
        set: function(size) {\n
            if (typeof size == "number")\n
                size = size + "px";\n
            this.container.style.fontSize = size;\n
            this.updateFontSize();\n
        },\n
        initialValue: 12\n
    },\n
    fontFamily: {\n
        set: function(name) {\n
            this.container.style.fontFamily = name;\n
            this.updateFontSize();\n
        }\n
    },\n
    maxLines: {\n
        set: function(val) {\n
            this.updateFull();\n
        }\n
    },\n
    minLines: {\n
        set: function(val) {\n
            this.updateFull();\n
        }\n
    },\n
    scrollPastEnd: {\n
        set: function(val) {\n
            val = +val || 0;\n
            if (this.$scrollPastEnd == val)\n
                return;\n
            this.$scrollPastEnd = val;\n
            this.$loop.schedule(this.CHANGE_SCROLL);\n
        },\n
        initialValue: 0,\n
        handlesSet: true\n
    },\n
    fixedWidthGutter: {\n
        set: function(val) {\n
            this.$gutterLayer.$fixedWidth = !!val;\n
            this.$loop.schedule(this.CHANGE_GUTTER);\n
        }\n
    }\n
});\n
\n
exports.VirtualRenderer = VirtualRenderer;\n
});\n
\n
define(\'ace/layer/gutter\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\', \'ace/lib/oop\', \'ace/lib/lang\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
var oop = require("../lib/oop");\n
var lang = require("../lib/lang");\n
var EventEmitter = require("../lib/event_emitter").EventEmitter;\n
\n
var Gutter = function(parentEl) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_layer ace_gutter-layer";\n
    parentEl.appendChild(this.element);\n
    this.setShowFoldWidgets(this.$showFoldWidgets);\n
    \n
    this.gutterWidth = 0;\n
\n
    this.$annotations = [];\n
    this.$updateAnnotations = this.$updateAnnotations.bind(this);\n
\n
    this.$cells = [];\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.setSession = function(session) {\n
        if (this.session)\n
            this.session.removeEventListener("change", this.$updateAnnotations);\n
        this.session = session;\n
        session.on("change", this.$updateAnnotations);\n
    };\n
\n
    this.addGutterDecoration = function(row, className){\n
        if (window.console)\n
            console.warn && console.warn("deprecated use session.addGutterDecoration");\n
        this.session.addGutterDecoration(row, className);\n
    };\n
\n
    this.removeGutterDecoration = function(row, className){\n
        if (window.console)\n
            console.warn && console.warn("deprecated use session.removeGutterDecoration");\n
        this.session.removeGutterDecoration(row, className);\n
    };\n
\n
    this.setAnnotations = function(annotations) {\n
        this.$annotations = []\n
        var rowInfo, row;\n
        for (var i = 0; i < annotations.length; i++) {\n
            var annotation = annotations[i];\n
            var row = annotation.row;\n
            var rowInfo = this.$annotations[row];\n
            if (!rowInfo)\n
                rowInfo = this.$annotations[row] = {text: []};\n
           \n
            var annoText = annotation.text;\n
            annoText = annoText ? lang.escapeHTML(annoText) : annotation.html || "";\n
\n
            if (rowInfo.text.indexOf(annoText) === -1)\n
                rowInfo.text.push(annoText);\n
\n
            var type = annotation.type;\n
            if (type == "error")\n
                rowInfo.className = " ace_error";\n
            else if (type == "warning" && rowInfo.className != " ace_error")\n
                rowInfo.className = " ace_warning";\n
            else if (type == "info" && (!rowInfo.className))\n
                rowInfo.className = " ace_info";\n
        }\n
    };\n
\n
    this.$updateAnnotations = function (e) {\n
        if (!this.$annotations.length)\n
            return;\n
        var delta = e.data;\n
        var range = delta.range;\n
        var firstRow = range.start.row;\n
        var len = range.end.row - firstRow;\n
        if (len === 0) {\n
        } else if (delta.action == "removeText" || delta.action == "removeLines") {\n
            this.$annotations.splice(firstRow, len + 1, null);\n
        } else {\n
            var args = Array(len + 1);\n
            args.unshift(firstRow, 1);\n
            this.$annotations.splice.apply(this.$annotations, args);\n
        }\n
    };\n
\n
    this.update = function(config) {\n
        var firstRow = config.firstRow;\n
        var lastRow = config.lastRow;\n
        var fold = this.session.getNextFoldLine(firstRow);\n
        var foldStart = fold ? fold.start.row : Infinity;\n
        var foldWidgets = this.$showFoldWidgets && this.session.foldWidgets;\n
        var breakpoints = this.session.$breakpoints;\n
        var decorations = this.session.$decorations;\n
        var firstLineNumber = this.session.$firstLineNumber;\n
        var lastLineNumber = 0;\n
\n
        var cell = null;\n
        var index = -1;\n
        var row = firstRow;\n
        while (true) {\n
            if (row > foldStart) {\n
                row = fold.end.row + 1;\n
                fold = this.session.getNextFoldLine(row, fold);\n
                foldStart = fold ? fold.start.row : Infinity;\n
            }\n
            if (row > lastRow) {\n
                while (this.$cells.length > index + 1) {\n
                    cell = this.$cells.pop();\n
                    this.element.removeChild(cell.element);\n
                }\n
                break;\n
            }\n
\n
            cell = this.$cells[++index];\n
            if (!cell) {\n
                cell = {element: null, textNode: null, foldWidget: null};\n
                cell.element = dom.createElement("div");\n
                cell.textNode = document.createTextNode(\'\');\n
                cell.element.appendChild(cell.textNode);\n
                this.element.appendChild(cell.element);\n
                this.$cells[index] = cell;\n
            }\n
\n
            var className = "ace_gutter-cell ";\n
            if (breakpoints[row])\n
                className += breakpoints[row];\n
            if (decorations[row])\n
                className += decorations[row];\n
            if (this.$annotations[row])\n
                className += this.$annotations[row].className;\n
            if (cell.element.className != className)\n
                cell.element.className = className;\n
\n
            var height = this.session.getRowLength(row) * config.lineHeight + "px";\n
            if (height != cell.element.style.height)\n
                cell.element.style.height = height;\n
\n
            var text = lastLineNumber = row + firstLineNumber;\n
            if (text != cell.textNode.data)\n
                cell.textNode.data  = text;\n
\n
            if (foldWidgets) {\n
                var c = foldWidgets[row];\n
                if (c == null)\n
                    c = foldWidgets[row] = this.session.getFoldWidget(row);\n
            }\n
\n
            if (c) {\n
                if (!cell.foldWidget) {\n
                    cell.foldWidget = dom.createElement("span");\n
                    cell.element.appendChild(cell.foldWidget);\n
                }\n
                var className = "ace_fold-widget ace_" + c;\n
                if (c == "start" && row == foldStart && row < fold.end.row)\n
                    className += " ace_closed";\n
                else\n
                    className += " ace_open";\n
                if (cell.foldWidget.className != className)\n
                    cell.foldWidget.className = className;\n
\n
                var height = config.lineHeight + "px";\n
                if (cell.foldWidget.style.height != height)\n
                    cell.foldWidget.style.height = height;\n
            } else {\n
                if (cell.foldWidget != null) {\n
                    cell.element.removeChild(cell.foldWidget);\n
                    cell.foldWidget = null;\n
                }\n
            }\n
\n
            row++;\n
        }\n
\n
        this.element.style.height = config.minHeight + "px";\n
\n
        if (this.$fixedWidth || this.session.$useWrapMode)\n
            lastLineNumber = this.session.getLength();\n
\n
        var gutterWidth = lastLineNumber.toString().length * config.characterWidth;\n
        var padding = this.$padding || this.$computePadding();\n
        gutterWidth += padding.left + padding.right;\n
        if (gutterWidth !== this.gutterWidth && !isNaN(gutterWidth)) {\n
            this.gutterWidth = gutterWidth;\n
            this.element.style.width = Math.ceil(this.gutterWidth) + "px";\n
            this._emit("changeGutterWidth", gutterWidth);\n
        }\n
    };\n
\n
    this.$fixedWidth = false;\n
    \n
    this.$showFoldWidgets = true;\n
    this.setShowFoldWidgets = function(show) {\n
        if (show)\n
            dom.addCssClass(this.element, "ace_folding-enabled");\n
        else\n
            dom.removeCssClass(this.element, "ace_folding-enabled");\n
\n
        this.$showFoldWidgets = show;\n
        this.$padding = null;\n
    };\n
    \n
    this.getShowFoldWidgets = function() {\n
        return this.$showFoldWidgets;\n
    };\n
\n
    this.$computePadding = function() {\n
        if (!this.element.firstChild)\n
            return {left: 0, right: 0};\n
        var style = dom.computedStyle(this.element.firstChild);\n
        this.$padding = {};\n
        this.$padding.left = parseInt(style.paddingLeft) + 1 || 0;\n
        this.$padding.right = parseInt(style.paddingRight) || 0;\n
        return this.$padding;\n
    };\n
\n
    this.getRegion = function(point) {\n
        var padding = this.$padding || this.$computePadding();\n
        var rect = this.element.getBoundingClientRect();\n
        if (point.x < padding.left + rect.left)\n
            return "markers";\n
        if (this.$showFoldWidgets && point.x > rect.right - padding.right)\n
            return "foldWidgets";\n
    };\n
\n
}).call(Gutter.prototype);\n
\n
exports.Gutter = Gutter;\n
\n
});\n
\n
define(\'ace/layer/marker\', [\'require\', \'exports\', \'module\' , \'ace/range\', \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
var Range = require("../range").Range;\n
var dom = require("../lib/dom");\n
\n
var Marker = function(parentEl) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_layer ace_marker-layer";\n
    parentEl.appendChild(this.element);\n
};\n
\n
(function() {\n
\n
    this.$padding = 0;\n
\n
    this.setPadding = function(padding) {\n
        this.$padding = padding;\n
    };\n
    this.setSession = function(session) {\n
        this.session = session;\n
    };\n
    \n
    this.setMarkers = function(markers) {\n
        this.markers = markers;\n
    };\n
\n
    this.update = function(config) {\n
        var config = config || this.config;\n
        if (!config)\n
            return;\n
\n
        this.config = config;\n
\n
\n
        var html = [];\n
        for (var key in this.markers) {\n
            var marker = this.markers[key];\n
\n
            if (!marker.range) {\n
                marker.update(html, this, this.session, config);\n
                continue;\n
            }\n
\n
            var range = marker.range.clipRows(config.firstRow, config.lastRow);\n
            if (range.isEmpty()) continue;\n
\n
            range = range.toScreenRange(this.session);\n
            if (marker.renderer) {\n
                var top = this.$getTop(range.start.row, config);\n
                var left = this.$padding + range.start.column * config.characterWidth;\n
                marker.renderer(html, range, left, top, config);\n
            } else if (marker.type == "fullLine") {\n
                this.drawFullLineMarker(html, range, marker.clazz, config);\n
            } else if (marker.type == "screenLine") {\n
                this.drawScreenLineMarker(html, range, marker.clazz, config);\n
            } else if (range.isMultiLine()) {\n
                if (marker.type == "text")\n
                    this.drawTextMarker(html, range, marker.clazz, config);\n
                else\n
                    this.drawMultiLineMarker(html, range, marker.clazz, config);\n
            } else {\n
                this.drawSingleLineMarker(html, range, marker.clazz + " ace_start", config);\n
            }\n
        }\n
        this.element = dom.setInnerHtml(this.element, html.join(""));\n
    };\n
\n
    this.$getTop = function(row, layerConfig) {\n
        return (row - layerConfig.firstRowScreen) * layerConfig.lineHeight;\n
    };\n
    this.drawTextMarker = function(stringBuilder, range, clazz, layerConfig, extraStyle) {\n
        var row = range.start.row;\n
\n
        var lineRange = new Range(\n
            row, range.start.column,\n
            row, this.session.getScreenLastRowColumn(row)\n
        );\n
        this.drawSingleLineMarker(stringBuilder, lineRange, clazz + " ace_start", layerConfig, 1, extraStyle);\n
        row = range.end.row;\n
        lineRange = new Range(row, 0, row, range.end.column);\n
        this.drawSingleLineMarker(stringBuilder, lineRange, clazz, layerConfig, 0, extraStyle);\n
\n
        for (row = range.start.row + 1; row < range.end.row; row++) {\n
            lineRange.start.row = row;\n
            lineRange.end.row = row;\n
            lineRange.end.column = this.session.getScreenLastRowColumn(row);\n
            this.drawSingleLineMarker(stringBuilder, lineRange, clazz, layerConfig, 1, extraStyle);\n
        }\n
    };\n
    this.drawMultiLineMarker = function(stringBuilder, range, clazz, config, extraStyle) {\n
        var padding = this.$padding;\n
        var height = config.lineHeight;\n
        var top = this.$getTop(range.start.row, config);\n
        var left = padding + range.start.column * config.characterWidth;\n
        extraStyle = extraStyle || "";\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, " ace_start\' style=\'",\n
            "height:", height, "px;",\n
            "right:0;",\n
            "top:", top, "px;",\n
            "left:", left, "px;", extraStyle, "\'></div>"\n
        );\n
        top = this.$getTop(range.end.row, config);\n
        var width = range.end.column * config.characterWidth;\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, "\' style=\'",\n
            "height:", height, "px;",\n
            "width:", width, "px;",\n
            "top:", top, "px;",\n
            "left:", padding, "px;", extraStyle, "\'></div>"\n
        );\n
        height = (range.end.row - range.start.row - 1) * config.lineHeight;\n
        if (height < 0)\n
            return;\n
        top = this.$getTop(range.start.row + 1, config);\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, "\' style=\'",\n
            "height:", height, "px;",\n
            "right:0;",\n
            "top:", top, "px;",\n
            "left:", padding, "px;", extraStyle, "\'></div>"\n
        );\n
    };\n
    this.drawSingleLineMarker = function(stringBuilder, range, clazz, config, extraLength, extraStyle) {\n
        var height = config.lineHeight;\n
        var width = (range.end.column + (extraLength || 0) - range.start.column) * config.characterWidth;\n
\n
        var top = this.$getTop(range.start.row, config);\n
        var left = this.$padding + range.start.column * config.characterWidth;\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, "\' style=\'",\n
            "height:", height, "px;",\n
            "width:", width, "px;",\n
            "top:", top, "px;",\n
            "left:", left, "px;", extraStyle || "", "\'></div>"\n
        );\n
    };\n
\n
    this.drawFullLineMarker = function(stringBuilder, range, clazz, config, extraStyle) {\n
        var top = this.$getTop(range.start.row, config);\n
        var height = config.lineHeight;\n
        if (range.start.row != range.end.row)\n
            height += this.$getTop(range.end.row, config) - top;\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, "\' style=\'",\n
            "height:", height, "px;",\n
            "top:", top, "px;",\n
            "left:0;right:0;", extraStyle || "", "\'></div>"\n
        );\n
    };\n
    \n
    this.drawScreenLineMarker = function(stringBuilder, range, clazz, config, extraStyle) {\n
        var top = this.$getTop(range.start.row, config);\n
        var height = config.lineHeight;\n
\n
        stringBuilder.push(\n
            "<div class=\'", clazz, "\' style=\'",\n
            "height:", height, "px;",\n
            "top:", top, "px;",\n
            "left:0;right:0;", extraStyle || "", "\'></div>"\n
        );\n
    };\n
\n
}).call(Marker.prototype);\n
\n
exports.Marker = Marker;\n
\n
});\n
\n
define(\'ace/layer/text\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/dom\', \'ace/lib/lang\', \'ace/lib/useragent\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var dom = require("../lib/dom");\n
var lang = require("../lib/lang");\n
var useragent = require("../lib/useragent");\n
var EventEmitter = require("../lib/event_emitter").EventEmitter;\n
\n
var Text = function(parentEl) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_layer ace_text-layer";\n
    parentEl.appendChild(this.element);\n
\n
    this.$characterSize = {width: 0, height: 0};\n
    this.checkForSizeChanges();\n
    this.$pollSizeChanges();\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.EOF_CHAR = "\\xB6"; //"&para;";\n
    this.EOL_CHAR = "\\xAC"; //"&not;";\n
    this.TAB_CHAR = "\\u2192"; //"&rarr;" "\\u21E5";\n
    this.SPACE_CHAR = "\\xB7"; //"&middot;";\n
    this.$padding = 0;\n
\n
    this.setPadding = function(padding) {\n
        this.$padding = padding;\n
        this.element.style.padding = "0 " + padding + "px";\n
    };\n
\n
    this.getLineHeight = function() {\n
        return this.$characterSize.height || 0;\n
    };\n
\n
    this.getCharacterWidth = function() {\n
        return this.$characterSize.width || 0;\n
    };\n
\n
    this.checkForSizeChanges = function() {\n
        var size = this.$measureSizes();\n
        if (size && (this.$characterSize.width !== size.width || this.$characterSize.height !== size.height)) {\n
            this.$measureNode.style.fontWeight = "bold";\n
            var boldSize = this.$measureSizes();\n
            this.$measureNode.style.fontWeight = "";\n
            this.$characterSize = size;\n
            this.allowBoldFonts = boldSize && boldSize.width === size.width && boldSize.height === size.height;\n
            this._emit("changeCharacterSize", {data: size});\n
        }\n
    };\n
\n
    this.$pollSizeChanges = function() {\n
        var self = this;\n
        this.$pollSizeChangesTimer = setInterval(function() {\n
            self.checkForSizeChanges();\n
        }, 500);\n
    };\n
\n
    this.$fontStyles = {\n
        fontFamily : 1,\n
        fontSize : 1,\n
        fontWeight : 1,\n
        fontStyle : 1,\n
        lineHeight : 1\n
    };\n
\n
    this.$measureSizes = useragent.isIE || useragent.isOldGecko ? function() {\n
        var n = 1000;\n
        if (!this.$measureNode) {\n
            var measureNode = this.$measureNode = dom.createElement("div");\n
            var style = measureNode.style;\n
\n
            style.width = style.height = "auto";\n
            style.left = style.top = (-n * 40)  + "px";\n
\n
            style.visibility = "hidden";\n
            style.position = "fixed";\n
            style.overflow = "visible";\n
            style.whiteSpace = "nowrap";\n
            measureNode.innerHTML = lang.stringRepeat("Xy", n);\n
\n
            if (this.element.ownerDocument.body) {\n
                this.element.ownerDocument.body.appendChild(measureNode);\n
            } else {\n
                var container = this.element.parentNode;\n
                while (!dom.hasCssClass(container, "ace_editor"))\n
                    container = container.parentNode;\n
                container.appendChild(measureNode);\n
            }\n
        }\n
        if (!this.element.offsetWidth)\n
            return null;\n
\n
        var style = this.$measureNode.style;\n
        var computedStyle = dom.computedStyle(this.element);\n
        for (var prop in this.$fontStyles)\n
            style[prop] = computedStyle[prop];\n
\n
        var size = {\n
            height: this.$measureNode.offsetHeight,\n
            width: this.$measureNode.offsetWidth / (n * 2)\n
        };\n
        if (size.width == 0 || size.height == 0)\n
            return null;\n
\n
        return size;\n
    }\n
    : function() {\n
        if (!this.$measureNode) {\n
            var measureNode = this.$measureNode = dom.createElement("div");\n
            var style = measureNode.style;\n
\n
            style.width = style.height = "auto";\n
            style.left = style.top = -100 + "px";\n
\n
            style.visibility = "hidden";\n
            style.position = "fixed";\n
            style.overflow = "visible";\n
            style.whiteSpace = "nowrap";\n
            measureNode.innerHTML = lang.stringRepeat("X", 100);\n
\n
            var container = this.element.parentNode;\n
            while (container && !dom.hasCssClass(container, "ace_editor"))\n
                container = container.parentNode;\n
\n
            if (!container)\n
                return this.$measureNode = null;\n
\n
            container.appendChild(measureNode);\n
        }\n
\n
        var rect = this.$measureNode.getBoundingClientRect();\n
\n
        var size = {\n
            height: rect.height,\n
            width: rect.width / 100\n
        };\n
        if (size.width == 0 || size.height == 0)\n
            return null;\n
\n
        return size;\n
    };\n
\n
    this.setSession = function(session) {\n
        this.session = session;\n
        this.$computeTabString();\n
    };\n
\n
    this.showInvisibles = false;\n
    this.setShowInvisibles = function(showInvisibles) {\n
        if (this.showInvisibles == showInvisibles)\n
            return false;\n
\n
        this.showInvisibles = showInvisibles;\n
        this.$computeTabString();\n
        return true;\n
    };\n
\n
    this.displayIndentGuides = true;\n
    this.setDisplayIndentGuides = function(display) {\n
        if (this.displayIndentGuides == display)\n
            return false;\n
\n
        this.displayIndentGuides = display;\n
        this.$computeTabString();\n
        return true;\n
    };\n
\n
    this.$tabStrings = [];\n
    this.onChangeTabSize =\n
    this.$computeTabString = function() {\n
        var tabSize = this.session.getTabSize();\n
        this.tabSize = tabSize;\n
        var tabStr = this.$tabStrings = [0];\n
        for (var i = 1; i < tabSize + 1; i++) {\n
            if (this.showInvisibles) {\n
                tabStr.push("<span class=\'ace_invisible\'>"\n
                    + this.TAB_CHAR\n
                    + lang.stringRepeat("\\xa0", i - 1)\n
                    + "</span>");\n
            } else {\n
                tabStr.push(lang.stringRepeat("\\xa0", i));\n
            }\n
        }\n
        if (this.displayIndentGuides) {\n
            this.$indentGuideRe =  /\\s\\S| \\t|\\t |\\s$/;\n
            var className = "ace_indent-guide";\n
            if (this.showInvisibles) {\n
                className += " ace_invisible";\n
                var spaceContent = lang.stringRepeat(this.SPACE_CHAR, this.tabSize);\n
                var tabContent = this.TAB_CHAR + lang.stringRepeat("\\xa0", this.tabSize - 1);\n
            } else{\n
                var spaceContent = lang.stringRepeat("\\xa0", this.tabSize);\n
                var tabContent = spaceContent;\n
            }\n
\n
            this.$tabStrings[" "] = "<span class=\'" + className + "\'>" + spaceContent + "</span>";\n
            this.$tabStrings["\\t"] = "<span class=\'" + className + "\'>" + tabContent + "</span>";\n
        }\n
    };\n
\n
    this.updateLines = function(config, firstRow, lastRow) {\n
        if (this.config.lastRow != config.lastRow ||\n
            this.config.firstRow != config.firstRow) {\n
            this.scrollLines(config);\n
        }\n
        this.config = config;\n
\n
        var first = Math.max(firstRow, config.firstRow);\n
        var last = Math.min(lastRow, config.lastRow);\n
\n
        var lineElements = this.element.childNodes;\n
        var lineElementsIdx = 0;\n
\n
        for (var row = config.firstRow; row < first; row++) {\n
            var foldLine = this.session.getFoldLine(row);\n
            if (foldLine) {\n
                if (foldLine.containsRow(first)) {\n
                    first = foldLine.start.row;\n
                    break;\n
                } else {\n
                    row = foldLine.end.row;\n
                }\n
            }\n
            lineElementsIdx ++;\n
        }\n
\n
        var row = first;\n
        var foldLine = this.session.getNextFoldLine(row);\n
        var foldStart = foldLine ? foldLine.start.row : Infinity;\n
\n
        while (true) {\n
            if (row > foldStart) {\n
                row = foldLine.end.row+1;\n
                foldLine = this.session.getNextFoldLine(row, foldLine);\n
                foldStart = foldLine ? foldLine.start.row :Infinity;\n
            }\n
            if (row > last)\n
                break;\n
\n
            var lineElement = lineElements[lineElementsIdx++];\n
            if (lineElement) {\n
                var html = [];\n
                this.$renderLine(\n
                    html, row, !this.$useLineGroups(), row == foldStart ? foldLine : false\n
                );\n
                dom.setInnerHtml(lineElement, html.join(""));\n
            }\n
            row++;\n
        }\n
    };\n
\n
    this.scrollLines = function(config) {\n
        var oldConfig = this.config;\n
        this.config = config;\n
\n
        if (!oldConfig || oldConfig.lastRow < config.firstRow)\n
            return this.update(config);\n
\n
        if (config.lastRow < oldConfig.firstRow)\n
            return this.update(config);\n
\n
        var el = this.element;\n
        if (oldConfig.firstRow < config.firstRow)\n
            for (var row=this.session.getFoldedRowCount(oldConfig.firstRow, config.firstRow - 1); row>0; row--)\n
                el.removeChild(el.firstChild);\n
\n
        if (oldConfig.lastRow > config.lastRow)\n
            for (var row=this.session.getFoldedRowCount(config.lastRow + 1, oldConfig.lastRow); row>0; row--)\n
                el.removeChild(el.lastChild);\n
\n
        if (config.firstRow < oldConfig.firstRow) {\n
            var fragment = this.$renderLinesFragment(config, config.firstRow, oldConfig.firstRow - 1);\n
            if (el.firstChild)\n
                el.insertBefore(fragment, el.firstChild);\n
            else\n
                el.appendChild(fragment);\n
        }\n
\n
        if (config.lastRow > oldConfig.lastRow) {\n
            var fragment = this.$renderLinesFragment(config, oldConfig.lastRow + 1, config.lastRow);\n
            el.appendChild(fragment);\n
        }\n
    };\n
\n
    this.$renderLinesFragment = function(config, firstRow, lastRow) {\n
        var fragment = this.element.ownerDocument.createDocumentFragment();\n
        var row = firstRow;\n
        var foldLine = this.session.getNextFoldLine(row);\n
        var foldStart = foldLine ? foldLine.start.row : Infinity;\n
\n
        while (true) {\n
            if (row > foldStart) {\n
                row = foldLine.end.row+1;\n
                foldLine = this.session.getNextFoldLine(row, foldLine);\n
                foldStart = foldLine ? foldLine.start.row : Infinity;\n
            }\n
            if (row > lastRow)\n
                break;\n
\n
            var container = dom.createElement("div");\n
\n
            var html = [];\n
            this.$renderLine(html, row, false, row == foldStart ? foldLine : false);\n
            container.innerHTML = html.join("");\n
            if (this.$useLineGroups()) {\n
                container.className = \'ace_line_group\';\n
                fragment.appendChild(container);\n
            } else {\n
                var lines = container.childNodes\n
                while(lines.length)\n
                    fragment.appendChild(lines[0]);\n
            }\n
\n
            row++;\n
        }\n
        return fragment;\n
    };\n
\n
    this.update = function(config) {\n
        this.config = config;\n
\n
        var html = [];\n
        var firstRow = config.firstRow, lastRow = config.lastRow;\n
\n
        var row = firstRow;\n
        var foldLine = this.session.getNextFoldLine(row);\n
        var foldStart = foldLine ? foldLine.start.row : Infinity;\n
\n
        while (true) {\n
            if (row > foldStart) {\n
                row = foldLine.end.row+1;\n
                foldLine = this.session.getNextFoldLine(row, foldLine);\n
                foldStart = foldLine ? foldLine.start.row :Infinity;\n
            }\n
            if (row > lastRow)\n
                break;\n
\n
            if (this.$useLineGroups())\n
                html.push("<div class=\'ace_line_group\'>")\n
\n
            this.$renderLine(html, row, false, row == foldStart ? foldLine : false);\n
\n
            if (this.$useLineGroups())\n
                html.push("</div>"); // end the line group\n
\n
            row++;\n
        }\n
        this.element = dom.setInnerHtml(this.element, html.join(""));\n
    };\n
\n
    this.$textToken = {\n
        "text": true,\n
        "rparen": true,\n
        "lparen": true\n
    };\n
\n
    this.$renderToken = function(stringBuilder, screenColumn, token, value) {\n
        var self = this;\n
        var replaceReg = /\\t|&|<|( +)|([\\x00-\\x1f\\x80-\\xa0\\u1680\\u180E\\u2000-\\u200f\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF])|[\\u1100-\\u115F\\u11A3-\\u11A7\\u11FA-\\u11FF\\u2329-\\u232A\\u2E80-\\u2E99\\u2E9B-\\u2EF3\\u2F00-\\u2FD5\\u2FF0-\\u2FFB\\u3000-\\u303E\\u3041-\\u3096\\u3099-\\u30FF\\u3105-\\u312D\\u3131-\\u318E\\u3190-\\u31BA\\u31C0-\\u31E3\\u31F0-\\u321E\\u3220-\\u3247\\u3250-\\u32FE\\u3300-\\u4DBF\\u4E00-\\uA48C\\uA490-\\uA4C6\\uA960-\\uA97C\\uAC00-\\uD7A3\\uD7B0-\\uD7C6\\uD7CB-\\uD7FB\\uF900-\\uFAFF\\uFE10-\\uFE19\\uFE30-\\uFE52\\uFE54-\\uFE66\\uFE68-\\uFE6B\\uFF01-\\uFF60\\uFFE0-\\uFFE6]/g;\n
        var replaceFunc = function(c, a, b, tabIdx, idx4) {\n
            if (a) {\n
                return self.showInvisibles ?\n
                    "<span class=\'ace_invisible\'>" + lang.stringRepeat(self.SPACE_CHAR, c.length) + "</span>" :\n
                    lang.stringRepeat("\\xa0", c.length);\n
            } else if (c == "&") {\n
                return "&#38;";\n
            } else if (c == "<") {\n
                return "&#60;";\n
            } else if (c == "\\t") {\n
                var tabSize = self.session.getScreenTabSize(screenColumn + tabIdx);\n
                screenColumn += tabSize - 1;\n
                return self.$tabStrings[tabSize];\n
            } else if (c == "\\u3000") {\n
                var classToUse = self.showInvisibles ? "ace_cjk ace_invisible" : "ace_cjk";\n
                var space = self.showInvisibles ? self.SPACE_CHAR : "";\n
                screenColumn += 1;\n
                return "<span class=\'" + classToUse + "\' style=\'width:" +\n
                    (self.config.characterWidth * 2) +\n
                    "px\'>" + space + "</span>";\n
            } else if (b) {\n
                return "<span class=\'ace_invisible ace_invalid\'>" + self.SPACE_CHAR + "</span>";\n
            } else {\n
                screenColumn += 1;\n
                return "<span class=\'ace_cjk\' style=\'width:" +\n
                    (self.config.characterWidth * 2) +\n
                    "px\'>" + c + "</span>";\n
            }\n
        };\n
\n
        var output = value.replace(replaceReg, replaceFunc);\n
\n
        if (!this.$textToken[token.type]) {\n
            var classes = "ace_" + token.type.replace(/\\./g, " ace_");\n
            var style = "";\n
            if (token.type == "fold")\n
                style = " style=\'width:" + (token.value.length * this.config.characterWidth) + "px;\' ";\n
            stringBuilder.push("<span class=\'", classes, "\'", style, ">", output, "</span>");\n
        }\n
        else {\n
            stringBuilder.push(output);\n
        }\n
        return screenColumn + value.length;\n
    };\n
\n
    this.renderIndentGuide = function(stringBuilder, value, max) {\n
        var cols = value.search(this.$indentGuideRe);\n
        if (cols <= 0 || cols >= max)\n
            return value;\n
        if (value[0] == " ") {\n
            cols -= cols % this.tabSize;\n
            stringBuilder.push(lang.stringRepeat(this.$tabStrings[" "], cols/this.tabSize));\n
            return value.substr(cols);\n
        } else if (value[0] == "\\t") {\n
            stringBuilder.push(lang.stringRepeat(this.$tabStrings["\\t"], cols));\n
            return value.substr(cols);\n
        }\n
        return value;\n
    };\n
\n
    this.$renderWrappedLine = function(stringBuilder, tokens, splits, onlyContents) {\n
        var chars = 0;\n
        var split = 0;\n
        var splitChars = splits[0];\n
        var screenColumn = 0;\n
\n
        for (var i = 0; i < tokens.length; i++) {\n
            var token = tokens[i];\n
            var value = token.value;\n
            if (i == 0 && this.displayIndentGuides) {\n
                chars = value.length;\n
                value = this.renderIndentGuide(stringBuilder, value, splitChars);\n
                if (!value)\n
                    continue;\n
                chars -= value.length;\n
            }\n
\n
            if (chars + value.length < splitChars) {\n
                screenColumn = this.$renderToken(stringBuilder, screenColumn, token, value);\n
                chars += value.length;\n
            } else {\n
                while (chars + value.length >= splitChars) {\n
                    screenColumn = this.$renderToken(\n
                        stringBuilder, screenColumn,\n
                        token, value.substring(0, splitChars - chars)\n
                    );\n
                    value = value.substring(splitChars - chars);\n
                    chars = splitChars;\n
\n
                    if (!onlyContents) {\n
                        stringBuilder.push("</div>",\n
                            "<div class=\'ace_line\' style=\'height:",\n
                            this.config.lineHeight, "px\'>"\n
                        );\n
                    }\n
\n
                    split ++;\n
                    screenColumn = 0;\n
                    splitChars = splits[split] || Number.MAX_VALUE;\n
                }\n
                if (value.length != 0) {\n
                    chars += value.length;\n
                    screenColumn = this.$renderToken(\n
                        stringBuilder, screenColumn, token, value\n
                    );\n
                }\n
            }\n
        }\n
    };\n
\n
    this.$renderSimpleLine = function(stringBuilder, tokens) {\n
        var screenColumn = 0;\n
        var token = tokens[0];\n
        var value = token.value;\n
        if (this.displayIndentGuides)\n
            value = this.renderIndentGuide(stringBuilder, value);\n
        if (value)\n
            screenColumn = this.$renderToken(stringBuilder, screenColumn, token, value);\n
        for (var i = 1; i < tokens.length; i++) {\n
            token = tokens[i];\n
            value = token.value;\n
            screenColumn = this.$renderToken(stringBuilder, screenColumn, token, value);\n
        }\n
    };\n
    this.$renderLine = function(stringBuilder, row, onlyContents, foldLine) {\n
        if (!foldLine && foldLine != false)\n
            foldLine = this.session.getFoldLine(row);\n
\n
        if (foldLine)\n
            var tokens = this.$getFoldLineTokens(row, f

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAk=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="9" aka="AAAAAAAAAAk=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

oldLine);\n
        else\n
            var tokens = this.session.getTokens(row);\n
\n
\n
        if (!onlyContents) {\n
            stringBuilder.push(\n
                "<div class=\'ace_line\' style=\'height:", this.config.lineHeight, "px\'>"\n
            );\n
        }\n
\n
        if (tokens.length) {\n
            var splits = this.session.getRowSplitData(row);\n
            if (splits && splits.length)\n
                this.$renderWrappedLine(stringBuilder, tokens, splits, onlyContents);\n
            else\n
                this.$renderSimpleLine(stringBuilder, tokens);\n
        }\n
\n
        if (this.showInvisibles) {\n
            if (foldLine)\n
                row = foldLine.end.row\n
\n
            stringBuilder.push(\n
                "<span class=\'ace_invisible\'>",\n
                row == this.session.getLength() - 1 ? this.EOF_CHAR : this.EOL_CHAR,\n
                "</span>"\n
            );\n
        }\n
        if (!onlyContents)\n
            stringBuilder.push("</div>");\n
    };\n
\n
    this.$getFoldLineTokens = function(row, foldLine) {\n
        var session = this.session;\n
        var renderTokens = [];\n
\n
        function addTokens(tokens, from, to) {\n
            var idx = 0, col = 0;\n
            while ((col + tokens[idx].value.length) < from) {\n
                col += tokens[idx].value.length;\n
                idx++;\n
\n
                if (idx == tokens.length)\n
                    return;\n
            }\n
            if (col != from) {\n
                var value = tokens[idx].value.substring(from - col);\n
                if (value.length > (to - from))\n
                    value = value.substring(0, to - from);\n
\n
                renderTokens.push({\n
                    type: tokens[idx].type,\n
                    value: value\n
                });\n
\n
                col = from + value.length;\n
                idx += 1;\n
            }\n
\n
            while (col < to && idx < tokens.length) {\n
                var value = tokens[idx].value;\n
                if (value.length + col > to) {\n
                    renderTokens.push({\n
                        type: tokens[idx].type,\n
                        value: value.substring(0, to - col)\n
                    });\n
                } else\n
                    renderTokens.push(tokens[idx]);\n
                col += value.length;\n
                idx += 1;\n
            }\n
        }\n
\n
        var tokens = session.getTokens(row);\n
        foldLine.walk(function(placeholder, row, column, lastColumn, isNewRow) {\n
            if (placeholder != null) {\n
                renderTokens.push({\n
                    type: "fold",\n
                    value: placeholder\n
                });\n
            } else {\n
                if (isNewRow)\n
                    tokens = session.getTokens(row);\n
\n
                if (tokens.length)\n
                    addTokens(tokens, lastColumn, column);\n
            }\n
        }, foldLine.end.row, this.session.getLine(foldLine.end.row).length);\n
\n
        return renderTokens;\n
    };\n
\n
    this.$useLineGroups = function() {\n
        return this.session.getUseWrapMode();\n
    };\n
\n
    this.destroy = function() {\n
        clearInterval(this.$pollSizeChangesTimer);\n
        if (this.$measureNode)\n
            this.$measureNode.parentNode.removeChild(this.$measureNode);\n
        delete this.$measureNode;\n
    };\n
\n
}).call(Text.prototype);\n
\n
exports.Text = Text;\n
\n
});\n
\n
define(\'ace/layer/cursor\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
var dom = require("../lib/dom");\n
\n
var Cursor = function(parentEl) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_layer ace_cursor-layer";\n
    parentEl.appendChild(this.element);\n
\n
    this.isVisible = false;\n
    this.isBlinking = true;\n
    this.blinkInterval = 1000;\n
    this.smoothBlinking = false;\n
\n
    this.cursors = [];\n
    this.cursor = this.addCursor();\n
    dom.addCssClass(this.element, "ace_hidden-cursors");\n
};\n
\n
(function() {\n
\n
    this.$padding = 0;\n
    this.setPadding = function(padding) {\n
        this.$padding = padding;\n
    };\n
\n
    this.setSession = function(session) {\n
        this.session = session;\n
    };\n
\n
    this.setBlinking = function(blinking) {\n
        if (blinking != this.isBlinking){\n
            this.isBlinking = blinking;\n
            this.restartTimer();\n
        }\n
    };\n
\n
    this.setBlinkInterval = function(blinkInterval) {\n
        if (blinkInterval != this.blinkInterval){\n
            this.blinkInterval = blinkInterval;\n
            this.restartTimer();\n
        }\n
    };\n
\n
    this.setSmoothBlinking = function(smoothBlinking) {\n
        if (smoothBlinking != this.smoothBlinking) {\n
            this.smoothBlinking = smoothBlinking;\n
            if (smoothBlinking)\n
                dom.addCssClass(this.element, "ace_smooth-blinking");\n
            else\n
                dom.removeCssClass(this.element, "ace_smooth-blinking");\n
            this.restartTimer();\n
        }\n
    };\n
\n
    this.addCursor = function() {\n
        var el = dom.createElement("div");\n
        el.className = "ace_cursor";\n
        this.element.appendChild(el);\n
        this.cursors.push(el);\n
        return el;\n
    };\n
\n
    this.removeCursor = function() {\n
        if (this.cursors.length > 1) {\n
            var el = this.cursors.pop();\n
            el.parentNode.removeChild(el);\n
            return el;\n
        }\n
    };\n
\n
    this.hideCursor = function() {\n
        this.isVisible = false;\n
        dom.addCssClass(this.element, "ace_hidden-cursors");\n
        this.restartTimer();\n
    };\n
\n
    this.showCursor = function() {\n
        this.isVisible = true;\n
        dom.removeCssClass(this.element, "ace_hidden-cursors");\n
        this.restartTimer();\n
    };\n
\n
    this.restartTimer = function() {\n
        clearInterval(this.intervalId);\n
        clearTimeout(this.timeoutId);\n
        if (this.smoothBlinking)\n
            dom.removeCssClass(this.element, "ace_smooth-blinking");\n
        for (var i = this.cursors.length; i--; )\n
            this.cursors[i].style.opacity = "";\n
\n
        if (!this.isBlinking || !this.blinkInterval || !this.isVisible)\n
            return;\n
\n
        if (this.smoothBlinking)\n
            setTimeout(function(){\n
                dom.addCssClass(this.element, "ace_smooth-blinking");\n
            }.bind(this));\n
\n
        var blink = function(){\n
            this.timeoutId = setTimeout(function() {\n
                for (var i = this.cursors.length; i--; ) {\n
                    this.cursors[i].style.opacity = 0;\n
                }\n
            }.bind(this), 0.6 * this.blinkInterval);\n
        }.bind(this);\n
\n
        this.intervalId = setInterval(function() {\n
            for (var i = this.cursors.length; i--; ) {\n
                this.cursors[i].style.opacity = "";\n
            }\n
            blink();\n
        }.bind(this), this.blinkInterval);\n
\n
        blink();\n
    };\n
\n
    this.getPixelPosition = function(position, onScreen) {\n
        if (!this.config || !this.session)\n
            return {left : 0, top : 0};\n
\n
        if (!position)\n
            position = this.session.selection.getCursor();\n
        var pos = this.session.documentToScreenPosition(position);\n
        var cursorLeft = this.$padding + pos.column * this.config.characterWidth;\n
        var cursorTop = (pos.row - (onScreen ? this.config.firstRowScreen : 0)) *\n
            this.config.lineHeight;\n
\n
        return {left : cursorLeft, top : cursorTop};\n
    };\n
\n
    this.update = function(config) {\n
        this.config = config;\n
\n
        var selections = this.session.$selectionMarkers;\n
        var i = 0, cursorIndex = 0;\n
\n
        if (selections === undefined || selections.length === 0){\n
            selections = [{cursor: null}];\n
        }\n
\n
        for (var i = 0, n = selections.length; i < n; i++) {\n
            var pixelPos = this.getPixelPosition(selections[i].cursor, true);\n
            if ((pixelPos.top > config.height + config.offset ||\n
                 pixelPos.top < -config.offset) && i > 1) {\n
                continue;\n
            }\n
\n
            var style = (this.cursors[cursorIndex++] || this.addCursor()).style;\n
\n
            style.left = pixelPos.left + "px";\n
            style.top = pixelPos.top + "px";\n
            style.width = config.characterWidth + "px";\n
            style.height = config.lineHeight + "px";\n
        }\n
        while (this.cursors.length > cursorIndex)\n
            this.removeCursor();\n
\n
        var overwrite = this.session.getOverwrite();\n
        this.$setOverwrite(overwrite);\n
        this.$pixelPos = pixelPos;\n
        this.restartTimer();\n
    };\n
\n
    this.$setOverwrite = function(overwrite) {\n
        if (overwrite != this.overwrite) {\n
            this.overwrite = overwrite;\n
            if (overwrite)\n
                dom.addCssClass(this.element, "ace_overwrite-cursors");\n
            else\n
                dom.removeCssClass(this.element, "ace_overwrite-cursors");\n
        }\n
    };\n
\n
    this.destroy = function() {\n
        clearInterval(this.intervalId);\n
        clearTimeout(this.timeoutId);\n
    };\n
\n
}).call(Cursor.prototype);\n
\n
exports.Cursor = Cursor;\n
\n
});\n
\n
define(\'ace/scrollbar\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/dom\', \'ace/lib/event\', \'ace/lib/event_emitter\'], function(require, exports, module) {\n
\n
\n
var oop = require("./lib/oop");\n
var dom = require("./lib/dom");\n
var event = require("./lib/event");\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var ScrollBarV = function(parent, renderer) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_scrollbar";\n
\n
    this.inner = dom.createElement("div");\n
    this.inner.className = "ace_scrollbar-inner";\n
    this.element.appendChild(this.inner);\n
\n
    parent.appendChild(this.element);\n
    renderer.$scrollbarWidth = \n
    this.width = dom.scrollbarWidth(parent.ownerDocument);\n
    renderer.$scrollbarWidth = \n
    this.width = dom.scrollbarWidth(parent.ownerDocument);\n
    this.fullWidth = this.width;\n
    this.inner.style.width =\n
    this.element.style.width = (this.width || 15) + 5 + "px";\n
    this.setVisible(false);\n
    this.element.style.overflowY = "scroll";\n
    \n
    event.addListener(this.element, "scroll", this.onScrollV.bind(this));\n
    event.addListener(this.element, "mousedown", event.preventDefault);\n
};\n
\n
var ScrollBarH = function(parent, renderer) {\n
    this.element = dom.createElement("div");\n
    this.element.className = "ace_scrollbar-h";\n
\n
    this.inner = dom.createElement("div");\n
    this.inner.className = "ace_scrollbar-inner";\n
    this.element.appendChild(this.inner);\n
\n
    parent.appendChild(this.element);\n
    this.height = renderer.$scrollbarWidth;\n
    this.fullHeight = this.height;\n
    this.inner.style.height =\n
    this.element.style.height = (this.height || 15) + 5 + "px";\n
    this.setVisible(false);\n
    this.element.style.overflowX = "scroll";\n
\n
    event.addListener(this.element, "scroll", this.onScrollH.bind(this));\n
    event.addListener(this.element, "mousedown", event.preventDefault);\n
};\n
\n
(function() {\n
    oop.implement(this, EventEmitter);\n
\n
    this.setVisible = function(show) {\n
        if (show) {\n
            this.element.style.display = "";\n
            if (this.fullWidth)\n
                this.width = this.fullWidth;\n
            if (this.fullHeight)\n
                this.height = this.fullHeight;\n
        } else {\n
            this.element.style.display = "none";\n
            this.height = this.width = 0;\n
        }\n
    };\n
    this.onScrollV = function() {\n
        if (!this.skipEvent) {\n
            this.scrollTop = this.element.scrollTop;\n
            this._emit("scroll", {data: this.scrollTop});\n
        }\n
        this.skipEvent = false;\n
    };\n
    this.onScrollH = function() {\n
        if (!this.skipEvent) {\n
            this.scrollLeft = this.element.scrollLeft;\n
            this._emit("scroll", {data: this.scrollLeft});\n
        }\n
        this.skipEvent = false;\n
    };\n
    this.getWidth = function() {\n
        return this.width;\n
    };\n
\n
    this.getHeight = function() {\n
        return this.height;\n
    };\n
    this.setHeight = function(height) {\n
        this.element.style.height = height + "px";\n
    };\n
    \n
    this.setWidth = function(width) {\n
        this.element.style.width = width + "px";\n
    };\n
    this.setInnerHeight = function(height) {\n
        this.inner.style.height = height + "px";\n
    };\n
    \n
    this.setInnerWidth = function(width) {\n
        this.inner.style.width = width + "px";\n
    };\n
    this.setScrollTop = function(scrollTop) {\n
        if (this.scrollTop != scrollTop) {\n
            this.skipEvent = true;\n
            this.scrollTop = this.element.scrollTop = scrollTop;\n
        }\n
    };\n
    this.setScrollLeft = function(scrollLeft) {\n
        if (this.scrollLeft != scrollLeft) {\n
            this.skipEvent = true;\n
            this.scrollLeft = this.element.scrollLeft = scrollLeft;\n
        }\n
    };\n
\n
}).call(ScrollBarV.prototype);\n
ScrollBarH.prototype = ScrollBarV.prototype;\n
\n
\n
\n
exports.ScrollBar = ScrollBarV; // backward compatibility\n
exports.ScrollBarV = ScrollBarV;\n
exports.ScrollBarH = ScrollBarH;\n
});\n
\n
define(\'ace/renderloop\', [\'require\', \'exports\', \'module\' , \'ace/lib/event\'], function(require, exports, module) {\n
\n
\n
var event = require("./lib/event");\n
\n
\n
var RenderLoop = function(onRender, win) {\n
    this.onRender = onRender;\n
    this.pending = false;\n
    this.changes = 0;\n
    this.window = win || window;\n
};\n
\n
(function() {\n
\n
\n
    this.schedule = function(change) {\n
        this.changes = this.changes | change;\n
        if (!this.pending) {\n
            this.pending = true;\n
            var _self = this;\n
            event.nextFrame(function() {\n
                _self.pending = false;\n
                var changes;\n
                while (changes = _self.changes) {\n
                    _self.changes = 0;\n
                    _self.onRender(changes);\n
                }\n
            }, this.window);\n
        }\n
    };\n
\n
}).call(RenderLoop.prototype);\n
\n
exports.RenderLoop = RenderLoop;\n
});\n
\n
define(\'ace/multi_select\', [\'require\', \'exports\', \'module\' , \'ace/range_list\', \'ace/range\', \'ace/selection\', \'ace/mouse/multi_select_handler\', \'ace/lib/event\', \'ace/lib/lang\', \'ace/commands/multi_select_commands\', \'ace/search\', \'ace/edit_session\', \'ace/editor\', \'ace/config\'], function(require, exports, module) {\n
\n
var RangeList = require("./range_list").RangeList;\n
var Range = require("./range").Range;\n
var Selection = require("./selection").Selection;\n
var onMouseDown = require("./mouse/multi_select_handler").onMouseDown;\n
var event = require("./lib/event");\n
var lang = require("./lib/lang");\n
var commands = require("./commands/multi_select_commands");\n
exports.commands = commands.defaultCommands.concat(commands.multiSelectCommands);\n
var Search = require("./search").Search;\n
var search = new Search();\n
\n
function find(session, needle, dir) {\n
    search.$options.wrap = true;\n
    search.$options.needle = needle;\n
    search.$options.backwards = dir == -1;\n
    return search.find(session);\n
}\n
var EditSession = require("./edit_session").EditSession;\n
(function() {\n
    this.getSelectionMarkers = function() {\n
        return this.$selectionMarkers;\n
    };\n
}).call(EditSession.prototype);\n
(function() {\n
    this.ranges = null;\n
    this.rangeList = null;\n
    this.addRange = function(range, $blockChangeEvents) {\n
        if (!range)\n
            return;\n
\n
        if (!this.inMultiSelectMode && this.rangeCount == 0) {\n
            var oldRange = this.toOrientedRange();\n
            this.rangeList.add(oldRange);\n
            this.rangeList.add(range);\n
            if (this.rangeList.ranges.length != 2) {\n
                this.rangeList.removeAll();\n
                return $blockChangeEvents || this.fromOrientedRange(range);\n
            }\n
            this.rangeList.removeAll();\n
            this.rangeList.add(oldRange);\n
            this.$onAddRange(oldRange);\n
        }\n
\n
        if (!range.cursor)\n
            range.cursor = range.end;\n
\n
        var removed = this.rangeList.add(range);\n
\n
        this.$onAddRange(range);\n
\n
        if (removed.length)\n
            this.$onRemoveRange(removed);\n
\n
        if (this.rangeCount > 1 && !this.inMultiSelectMode) {\n
            this._emit("multiSelect");\n
            this.inMultiSelectMode = true;\n
            this.session.$undoSelect = false;\n
            this.rangeList.attach(this.session);\n
        }\n
\n
        return $blockChangeEvents || this.fromOrientedRange(range);\n
    };\n
\n
    this.toSingleRange = function(range) {\n
        range = range || this.ranges[0];\n
        var removed = this.rangeList.removeAll();\n
        if (removed.length)\n
            this.$onRemoveRange(removed);\n
\n
        range && this.fromOrientedRange(range);\n
    };\n
    this.substractPoint = function(pos) {\n
        var removed = this.rangeList.substractPoint(pos);\n
        if (removed) {\n
            this.$onRemoveRange(removed);\n
            return removed[0];\n
        }\n
    };\n
    this.mergeOverlappingRanges = function() {\n
        var removed = this.rangeList.merge();\n
        if (removed.length)\n
            this.$onRemoveRange(removed);\n
        else if(this.ranges[0])\n
            this.fromOrientedRange(this.ranges[0]);\n
    };\n
\n
    this.$onAddRange = function(range) {\n
        this.rangeCount = this.rangeList.ranges.length;\n
        this.ranges.unshift(range);\n
        this._emit("addRange", {range: range});\n
    };\n
\n
    this.$onRemoveRange = function(removed) {\n
        this.rangeCount = this.rangeList.ranges.length;\n
        if (this.rangeCount == 1 && this.inMultiSelectMode) {\n
            var lastRange = this.rangeList.ranges.pop();\n
            removed.push(lastRange);\n
            this.rangeCount = 0;\n
        }\n
\n
        for (var i = removed.length; i--; ) {\n
            var index = this.ranges.indexOf(removed[i]);\n
            this.ranges.splice(index, 1);\n
        }\n
\n
        this._emit("removeRange", {ranges: removed});\n
\n
        if (this.rangeCount == 0 && this.inMultiSelectMode) {\n
            this.inMultiSelectMode = false;\n
            this._emit("singleSelect");\n
            this.session.$undoSelect = true;\n
            this.rangeList.detach(this.session);\n
        }\n
\n
        lastRange = lastRange || this.ranges[0];\n
        if (lastRange && !lastRange.isEqual(this.getRange()))\n
            this.fromOrientedRange(lastRange);\n
    };\n
    this.$initRangeList = function() {\n
        if (this.rangeList)\n
            return;\n
\n
        this.rangeList = new RangeList();\n
        this.ranges = [];\n
        this.rangeCount = 0;\n
    };\n
    this.getAllRanges = function() {\n
        return this.rangeCount ? this.rangeList.ranges.concat() : [this.getRange()];\n
    };\n
\n
    this.splitIntoLines = function () {\n
        if (this.rangeCount > 1) {\n
            var ranges = this.rangeList.ranges;\n
            var lastRange = ranges[ranges.length - 1];\n
            var range = Range.fromPoints(ranges[0].start, lastRange.end);\n
\n
            this.toSingleRange();\n
            this.setSelectionRange(range, lastRange.cursor == lastRange.start);\n
        } else {\n
            var range = this.getRange();\n
            var isBackwards = this.isBackwards();\n
            var startRow = range.start.row;\n
            var endRow = range.end.row;\n
            if (startRow == endRow) {\n
                if (isBackwards)\n
                    var start = range.end, end = range.start;\n
                else\n
                    var start = range.start, end = range.end;\n
                \n
                this.addRange(Range.fromPoints(end, end));\n
                this.addRange(Range.fromPoints(start, start));\n
                return;\n
            }\n
\n
            var rectSel = [];\n
            var r = this.getLineRange(startRow, true);\n
            r.start.column = range.start.column;\n
            rectSel.push(r);\n
\n
            for (var i = startRow + 1; i < endRow; i++)\n
                rectSel.push(this.getLineRange(i, true));\n
\n
            r = this.getLineRange(endRow, true);\n
            r.end.column = range.end.column;\n
            rectSel.push(r);\n
\n
            rectSel.forEach(this.addRange, this);\n
        }\n
    };\n
    this.toggleBlockSelection = function () {\n
        if (this.rangeCount > 1) {\n
            var ranges = this.rangeList.ranges;\n
            var lastRange = ranges[ranges.length - 1];\n
            var range = Range.fromPoints(ranges[0].start, lastRange.end);\n
\n
            this.toSingleRange();\n
            this.setSelectionRange(range, lastRange.cursor == lastRange.start);\n
        } else {\n
            var cursor = this.session.documentToScreenPosition(this.selectionLead);\n
            var anchor = this.session.documentToScreenPosition(this.selectionAnchor);\n
\n
            var rectSel = this.rectangularRangeBlock(cursor, anchor);\n
            rectSel.forEach(this.addRange, this);\n
        }\n
    };\n
    this.rectangularRangeBlock = function(screenCursor, screenAnchor, includeEmptyLines) {\n
        var rectSel = [];\n
\n
        var xBackwards = screenCursor.column < screenAnchor.column;\n
        if (xBackwards) {\n
            var startColumn = screenCursor.column;\n
            var endColumn = screenAnchor.column;\n
        } else {\n
            var startColumn = screenAnchor.column;\n
            var endColumn = screenCursor.column;\n
        }\n
\n
        var yBackwards = screenCursor.row < screenAnchor.row;\n
        if (yBackwards) {\n
            var startRow = screenCursor.row;\n
            var endRow = screenAnchor.row;\n
        } else {\n
            var startRow = screenAnchor.row;\n
            var endRow = screenCursor.row;\n
        }\n
\n
        if (startColumn < 0)\n
            startColumn = 0;\n
        if (startRow < 0)\n
            startRow = 0;\n
\n
        if (startRow == endRow)\n
            includeEmptyLines = true;\n
\n
        for (var row = startRow; row <= endRow; row++) {\n
            var range = Range.fromPoints(\n
                this.session.screenToDocumentPosition(row, startColumn),\n
                this.session.screenToDocumentPosition(row, endColumn)\n
            );\n
            if (range.isEmpty()) {\n
                if (docEnd && isSamePoint(range.end, docEnd))\n
                    break;\n
                var docEnd = range.end;\n
            }\n
            range.cursor = xBackwards ? range.start : range.end;\n
            rectSel.push(range);\n
        }\n
\n
        if (yBackwards)\n
            rectSel.reverse();\n
\n
        if (!includeEmptyLines) {\n
            var end = rectSel.length - 1;\n
            while (rectSel[end].isEmpty() && end > 0)\n
                end--;\n
            if (end > 0) {\n
                var start = 0;\n
                while (rectSel[start].isEmpty())\n
                    start++;\n
            }\n
            for (var i = end; i >= start; i--) {\n
                if (rectSel[i].isEmpty())\n
                    rectSel.splice(i, 1);\n
            }\n
        }\n
\n
        return rectSel;\n
    };\n
}).call(Selection.prototype);\n
var Editor = require("./editor").Editor;\n
(function() {\n
    this.updateSelectionMarkers = function() {\n
        this.renderer.updateCursor();\n
        this.renderer.updateBackMarkers();\n
    };\n
    this.addSelectionMarker = function(orientedRange) {\n
        if (!orientedRange.cursor)\n
            orientedRange.cursor = orientedRange.end;\n
\n
        var style = this.getSelectionStyle();\n
        orientedRange.marker = this.session.addMarker(orientedRange, "ace_selection", style);\n
\n
        this.session.$selectionMarkers.push(orientedRange);\n
        this.session.selectionMarkerCount = this.session.$selectionMarkers.length;\n
        return orientedRange;\n
    };\n
    this.removeSelectionMarker = function(range) {\n
        if (!range.marker)\n
            return;\n
        this.session.removeMarker(range.marker);\n
        var index = this.session.$selectionMarkers.indexOf(range);\n
        if (index != -1)\n
            this.session.$selectionMarkers.splice(index, 1);\n
        this.session.selectionMarkerCount = this.session.$selectionMarkers.length;\n
    };\n
\n
    this.removeSelectionMarkers = function(ranges) {\n
        var markerList = this.session.$selectionMarkers;\n
        for (var i = ranges.length; i--; ) {\n
            var range = ranges[i];\n
            if (!range.marker)\n
                continue;\n
            this.session.removeMarker(range.marker);\n
            var index = markerList.indexOf(range);\n
            if (index != -1)\n
                markerList.splice(index, 1);\n
        }\n
        this.session.selectionMarkerCount = markerList.length;\n
    };\n
\n
    this.$onAddRange = function(e) {\n
        this.addSelectionMarker(e.range);\n
        this.renderer.updateCursor();\n
        this.renderer.updateBackMarkers();\n
    };\n
\n
    this.$onRemoveRange = function(e) {\n
        this.removeSelectionMarkers(e.ranges);\n
        this.renderer.updateCursor();\n
        this.renderer.updateBackMarkers();\n
    };\n
\n
    this.$onMultiSelect = function(e) {\n
        if (this.inMultiSelectMode)\n
            return;\n
        this.inMultiSelectMode = true;\n
\n
        this.setStyle("ace_multiselect");\n
        this.keyBinding.addKeyboardHandler(commands.keyboardHandler);\n
        this.commands.setDefaultHandler("exec", this.$onMultiSelectExec);\n
\n
        this.renderer.updateCursor();\n
        this.renderer.updateBackMarkers();\n
    };\n
\n
    this.$onSingleSelect = function(e) {\n
        if (this.session.multiSelect.inVirtualMode)\n
            return;\n
        this.inMultiSelectMode = false;\n
\n
        this.unsetStyle("ace_multiselect");\n
        this.keyBinding.removeKeyboardHandler(commands.keyboardHandler);\n
\n
        this.commands.removeDefaultHandler("exec", this.$onMultiSelectExec);\n
        this.renderer.updateCursor();\n
        this.renderer.updateBackMarkers();\n
    };\n
\n
    this.$onMultiSelectExec = function(e) {\n
        var command = e.command;\n
        var editor = e.editor;\n
        if (!editor.multiSelect)\n
            return;\n
        if (!command.multiSelectAction) {\n
            var result = command.exec(editor, e.args || {});\n
            editor.multiSelect.addRange(editor.multiSelect.toOrientedRange());\n
            editor.multiSelect.mergeOverlappingRanges();\n
        } else if (command.multiSelectAction == "forEach") {\n
            result = editor.forEachSelection(command, e.args);\n
        } else if (command.multiSelectAction == "forEachLine") {\n
            result = editor.forEachSelection(command, e.args, true);\n
        } else if (command.multiSelectAction == "single") {\n
            editor.exitMultiSelectMode();\n
            result = command.exec(editor, e.args || {});\n
        } else {\n
            result = command.multiSelectAction(editor, e.args || {});\n
        }\n
        return result;\n
    }; \n
    this.forEachSelection = function(cmd, args, $byLines) {\n
        if (this.inVirtualSelectionMode)\n
            return;\n
\n
        var session = this.session;\n
        var selection = this.selection;\n
        var rangeList = selection.rangeList;\n
        var result;\n
        \n
        var reg = selection._eventRegistry;\n
        selection._eventRegistry = {};\n
\n
        var tmpSel = new Selection(session);\n
        this.inVirtualSelectionMode = true;\n
        for (var i = rangeList.ranges.length; i--;) {\n
            if ($byLines) {\n
                while (i > 0 && rangeList.ranges[i].start.row == rangeList.ranges[i - 1].end.row)\n
                    i--;\n
            }\n
            tmpSel.fromOrientedRange(rangeList.ranges[i]);\n
            this.selection = session.selection = tmpSel;\n
            var cmdResult = cmd.exec(this, args || {});\n
            if (!result == undefined)\n
                result = cmdResult;\n
            tmpSel.toOrientedRange(rangeList.ranges[i]);\n
        }\n
        tmpSel.detach();\n
\n
        this.selection = session.selection = selection;\n
        this.inVirtualSelectionMode = false;\n
        selection._eventRegistry = reg;\n
        selection.mergeOverlappingRanges();\n
        \n
        var anim = this.renderer.$scrollAnimation;\n
        this.onCursorChange();\n
        this.onSelectionChange();\n
        if (anim && anim.from == anim.to)\n
            this.renderer.animateScrolling(anim.from);\n
        \n
        return result;\n
    };\n
    this.exitMultiSelectMode = function() {\n
        if (!this.inMultiSelectMode || this.inVirtualSelectionMode)\n
            return;\n
        this.multiSelect.toSingleRange();\n
    };\n
\n
    this.getSelectedText = function() {\n
        var text = "";\n
        if (this.inMultiSelectMode && !this.inVirtualSelectionMode) {\n
            var ranges = this.multiSelect.rangeList.ranges;\n
            var buf = [];\n
            for (var i = 0; i < ranges.length; i++) {\n
                buf.push(this.session.getTextRange(ranges[i]));\n
            }\n
            var nl = this.session.getDocument().getNewLineCharacter();\n
            text = buf.join(nl);\n
            if (text.length == (buf.length - 1) * nl.length)\n
                text = "";\n
        } else if (!this.selection.isEmpty()) {\n
            text = this.session.getTextRange(this.getSelectionRange());\n
        }\n
        return text;\n
    };\n
    this.onPaste = function(text) {\n
        if (this.$readOnly)\n
            return;\n
\n
        this._signal("paste", text);\n
        if (!this.inMultiSelectMode || this.inVirtualSelectionMode)\n
            return this.insert(text);\n
\n
        var lines = text.split(/\\r\\n|\\r|\\n/);\n
        var ranges = this.selection.rangeList.ranges;\n
\n
        if (lines.length > ranges.length || lines.length < 2 || !lines[1])\n
            return this.commands.exec("insertstring", this, text);\n
\n
        for (var i = ranges.length; i--;) {\n
            var range = ranges[i];\n
            if (!range.isEmpty())\n
                this.session.remove(range);\n
\n
            this.session.insert(range.start, lines[i]);\n
        }\n
    };\n
    this.findAll = function(needle, options, additive) {\n
        options = options || {};\n
        options.needle = needle || options.needle;\n
        this.$search.set(options);\n
\n
        var ranges = this.$search.findAll(this.session);\n
        if (!ranges.length)\n
            return 0;\n
\n
        this.$blockScrolling += 1;\n
        var selection = this.multiSelect;\n
\n
        if (!additive)\n
            selection.toSingleRange(ranges[0]);\n
\n
        for (var i = ranges.length; i--; )\n
            selection.addRange(ranges[i], true);\n
\n
        this.$blockScrolling -= 1;\n
\n
        return ranges.length;\n
    };\n
    this.selectMoreLines = function(dir, skip) {\n
        var range = this.selection.toOrientedRange();\n
        var isBackwards = range.cursor == range.end;\n
\n
        var screenLead = this.session.documentToScreenPosition(range.cursor);\n
        if (this.selection.$desiredColumn)\n
            screenLead.column = this.selection.$desiredColumn;\n
\n
        var lead = this.session.screenToDocumentPosition(screenLead.row + dir, screenLead.column);\n
\n
        if (!range.isEmpty()) {\n
            var screenAnchor = this.session.documentToScreenPosition(isBackwards ? range.end : range.start);\n
            var anchor = this.session.screenToDocumentPosition(screenAnchor.row + dir, screenAnchor.column);\n
        } else {\n
            var anchor = lead;\n
        }\n
\n
        if (isBackwards) {\n
            var newRange = Range.fromPoints(lead, anchor);\n
            newRange.cursor = newRange.start;\n
        } else {\n
            var newRange = Range.fromPoints(anchor, lead);\n
            newRange.cursor = newRange.end;\n
        }\n
\n
        newRange.desiredColumn = screenLead.column;\n
        if (!this.selection.inMultiSelectMode) {\n
            this.selection.addRange(range);\n
        } else {\n
            if (skip)\n
                var toRemove = range.cursor;\n
        }\n
\n
        this.selection.addRange(newRange);\n
        if (toRemove)\n
            this.selection.substractPoint(toRemove);\n
    };\n
    this.transposeSelections = function(dir) {\n
        var session = this.session;\n
        var sel = session.multiSelect;\n
        var all = sel.ranges;\n
\n
        for (var i = all.length; i--; ) {\n
            var range = all[i];\n
            if (range.isEmpty()) {\n
                var tmp = session.getWordRange(range.start.row, range.start.column);\n
                range.start.row = tmp.start.row;\n
                range.start.column = tmp.start.column;\n
                range.end.row = tmp.end.row;\n
                range.end.column = tmp.end.column;\n
            }\n
        }\n
        sel.mergeOverlappingRanges();\n
\n
        var words = [];\n
        for (var i = all.length; i--; ) {\n
            var range = all[i];\n
            words.unshift(session.getTextRange(range));\n
        }\n
\n
        if (dir < 0)\n
            words.unshift(words.pop());\n
        else\n
            words.push(words.shift());\n
\n
        for (var i = all.length; i--; ) {\n
            var range = all[i];\n
            var tmp = range.clone();\n
            session.replace(range, words[i]);\n
            range.start.row = tmp.start.row;\n
            range.start.column = tmp.start.column;\n
        }\n
    };\n
    this.selectMore = function(dir, skip) {\n
        var session = this.session;\n
        var sel = session.multiSelect;\n
\n
        var range = sel.toOrientedRange();\n
        if (range.isEmpty()) {\n
            var range = session.getWordRange(range.start.row, range.start.column);\n
            range.cursor = dir == -1 ? range.start : range.end;\n
            this.multiSelect.addRange(range);\n
            return;\n
        }\n
        var needle = session.getTextRange(range);\n
\n
        var newRange = find(session, needle, dir);\n
        if (newRange) {\n
            newRange.cursor = dir == -1 ? newRange.start : newRange.end;\n
            this.multiSelect.addRange(newRange);\n
        }\n
        if (skip)\n
            this.multiSelect.substractPoint(range.cursor);\n
    };\n
    this.alignCursors = function() {\n
        var session = this.session;\n
        var sel = session.multiSelect;\n
        var ranges = sel.ranges;\n
\n
        if (!ranges.length) {\n
            var range = this.selection.getRange();\n
            var fr = range.start.row, lr = range.end.row;\n
            var lines = this.session.doc.removeLines(fr, lr);\n
            lines = this.$reAlignText(lines);\n
            this.session.doc.insertLines(fr, lines);\n
            range.start.column = 0;\n
            range.end.column = lines[lines.length - 1].length;\n
            this.selection.setRange(range);\n
        } else {\n
            var row = -1;\n
            var sameRowRanges = ranges.filter(function(r) {\n
                if (r.cursor.row == row)\n
                    return true;\n
                row = r.cursor.row;\n
            });\n
            sel.$onRemoveRange(sameRowRanges);\n
\n
            var maxCol = 0;\n
            var minSpace = Infinity;\n
            var spaceOffsets = ranges.map(function(r) {\n
                var p = r.cursor;\n
                var line = session.getLine(p.row);\n
                var spaceOffset = line.substr(p.column).search(/\\S/g);\n
                if (spaceOffset == -1)\n
                    spaceOffset = 0;\n
\n
                if (p.column > maxCol)\n
                    maxCol = p.column;\n
                if (spaceOffset < minSpace)\n
                    minSpace = spaceOffset;\n
                return spaceOffset;\n
            });\n
            ranges.forEach(function(r, i) {\n
                var p = r.cursor;\n
                var l = maxCol - p.column;\n
                var d = spaceOffsets[i] - minSpace;\n
                if (l > d)\n
                    session.insert(p, lang.stringRepeat(" ", l - d));\n
                else\n
                    session.remove(new Range(p.row, p.column, p.row, p.column - l + d));\n
\n
                r.start.column = r.end.column = maxCol;\n
                r.start.row = r.end.row = p.row;\n
                r.cursor = r.end;\n
            });\n
            sel.fromOrientedRange(ranges[0]);\n
            this.renderer.updateCursor();\n
            this.renderer.updateBackMarkers();\n
        }\n
    };\n
\n
    this.$reAlignText = function(lines) {\n
        var isLeftAligned = true, isRightAligned = true;\n
        var startW, textW, endW;\n
\n
        return lines.map(function(line) {\n
            var m = line.match(/(\\s*)(.*?)(\\s*)([=:].*)/);\n
            if (!m)\n
                return [line];\n
\n
            if (startW == null) {\n
                startW = m[1].length;\n
                textW = m[2].length;\n
                endW = m[3].length;\n
                return m;\n
            }\n
\n
            if (startW + textW + endW != m[1].length + m[2].length + m[3].length)\n
                isRightAligned = false;\n
            if (startW != m[1].length)\n
                isLeftAligned = false;\n
\n
            if (startW > m[1].length)\n
                startW = m[1].length;\n
            if (textW < m[2].length)\n
                textW = m[2].length;\n
            if (endW > m[3].length)\n
                endW = m[3].length;\n
\n
            return m;\n
        }).map(isLeftAligned ? isRightAligned ? alignRight : alignLeft : unAlign);\n
\n
        function spaces(n) {\n
            return lang.stringRepeat(" ", n);\n
        }\n
\n
        function alignLeft(m) {\n
            return !m[2] ? m[0] : spaces(startW) + m[2]\n
                + spaces(textW - m[2].length + endW)\n
                + m[4].replace(/^([=:])\\s+/, "$1 ")\n
        }\n
        function alignRight(m) {\n
            return !m[2] ? m[0] : spaces(startW + textW - m[2].length) + m[2]\n
                + spaces(endW, " ")\n
                + m[4].replace(/^([=:])\\s+/, "$1 ")\n
        }\n
        function unAlign(m) {\n
            return !m[2] ? m[0] : spaces(startW) + m[2]\n
                + spaces(endW)\n
                + m[4].replace(/^([=:])\\s+/, "$1 ")\n
        }\n
    }\n
}).call(Editor.prototype);\n
\n
\n
function isSamePoint(p1, p2) {\n
    return p1.row == p2.row && p1.column == p2.column;\n
}\n
exports.onSessionChange = function(e) {\n
    var session = e.session;\n
    if (!session.multiSelect) {\n
        session.$selectionMarkers = [];\n
        session.selection.$initRangeList();\n
        session.multiSelect = session.selection;\n
    }\n
    this.multiSelect = session.multiSelect;\n
\n
    var oldSession = e.oldSession;\n
    if (oldSession) {\n
        oldSession.multiSelect.removeEventListener("addRange", this.$onAddRange);\n
        oldSession.multiSelect.removeEventListener("removeRange", this.$onRemoveRange);\n
        oldSession.multiSelect.removeEventListener("multiSelect", this.$onMultiSelect);\n
        oldSession.multiSelect.removeEventListener("singleSelect", this.$onSingleSelect);\n
    }\n
\n
    session.multiSelect.on("addRange", this.$onAddRange);\n
    session.multiSelect.on("removeRange", this.$onRemoveRange);\n
    session.multiSelect.on("multiSelect", this.$onMultiSelect);\n
    session.multiSelect.on("singleSelect", this.$onSingleSelect);\n
\n
    if (this.inMultiSelectMode != session.selection.inMultiSelectMode) {\n
        if (session.selection.inMultiSelectMode)\n
            this.$onMultiSelect();\n
        else\n
            this.$onSingleSelect();\n
    }\n
};\n
function MultiSelect(editor) {\n
    if (editor.$multiselectOnSessionChange)\n
        return;\n
    editor.$onAddRange = editor.$onAddRange.bind(editor);\n
    editor.$onRemoveRange = editor.$onRemoveRange.bind(editor);\n
    editor.$onMultiSelect = editor.$onMultiSelect.bind(editor);\n
    editor.$onSingleSelect = editor.$onSingleSelect.bind(editor);\n
    editor.$multiselectOnSessionChange = exports.onSessionChange.bind(editor);\n
\n
    editor.$multiselectOnSessionChange(editor);\n
    editor.on("changeSession", editor.$multiselectOnSessionChange);\n
\n
    editor.on("mousedown", onMouseDown);\n
    editor.commands.addCommands(commands.defaultCommands);\n
\n
    addAltCursorListeners(editor);\n
}\n
\n
function addAltCursorListeners(editor){\n
    var el = editor.textInput.getElement();\n
    var altCursor = false;\n
    event.addListener(el, "keydown", function(e) {\n
        if (e.keyCode == 18 && !(e.ctrlKey || e.shiftKey || e.metaKey)) {\n
            if (!altCursor) {\n
                editor.renderer.setMouseCursor("crosshair");\n
                altCursor = true;\n
            }\n
        } else if (altCursor) {\n
            reset();\n
        }\n
    });\n
\n
    event.addListener(el, "keyup", reset);\n
    event.addListener(el, "blur", reset);\n
    function reset(e) {\n
        if (altCursor) {\n
            editor.renderer.setMouseCursor("");\n
            altCursor = false;\n
        }\n
    }\n
}\n
\n
exports.MultiSelect = MultiSelect;\n
\n
\n
require("./config").defineOptions(Editor.prototype, "editor", {\n
    enableMultiselect: {\n
        set: function(val) {\n
            MultiSelect(this);\n
            if (val) {\n
                this.on("changeSession", this.$multiselectOnSessionChange);\n
                this.on("mousedown", onMouseDown);\n
            } else {\n
                this.off("changeSession", this.$multiselectOnSessionChange);\n
                this.off("mousedown", onMouseDown);\n
            }\n
        },\n
        value: true\n
    }\n
})\n
\n
\n
\n
});\n
\n
define(\'ace/mouse/multi_select_handler\', [\'require\', \'exports\', \'module\' , \'ace/lib/event\'], function(require, exports, module) {\n
\n
var event = require("../lib/event");\n
function isSamePoint(p1, p2) {\n
    return p1.row == p2.row && p1.column == p2.column;\n
}\n
\n
function onMouseDown(e) {\n
    var ev = e.domEvent;\n
    var alt = ev.altKey;\n
    var shift = ev.shiftKey;\n
    var ctrl = e.getAccelKey();\n
    var button = e.getButton();\n
\n
    if (e.editor.inMultiSelectMode && button == 2) {\n
        e.editor.textInput.onContextMenu(e.domEvent);\n
        return;\n
    }\n
    \n
    if (!ctrl && !alt) {\n
        if (button == 0 && e.editor.inMultiSelectMode)\n
            e.editor.exitMultiSelectMode();\n
        return;\n
    }\n
\n
    var editor = e.editor;\n
    var selection = editor.selection;\n
    var isMultiSelect = editor.inMultiSelectMode;\n
    var pos = e.getDocumentPosition();\n
    var cursor = selection.getCursor();\n
    var inSelection = e.inSelection() || (selection.isEmpty() && isSamePoint(pos, cursor));\n
\n
\n
    var mouseX = e.x, mouseY = e.y;\n
    var onMouseSelection = function(e) {\n
        mouseX = e.clientX;\n
        mouseY = e.clientY;\n
    };\n
\n
    var blockSelect = function() {\n
        var newCursor = editor.renderer.pixelToScreenCoordinates(mouseX, mouseY);\n
        var cursor = session.screenToDocumentPosition(newCursor.row, newCursor.column);\n
\n
        if (isSamePoint(screenCursor, newCursor)\n
            && isSamePoint(cursor, selection.selectionLead))\n
            return;\n
        screenCursor = newCursor;\n
\n
        editor.selection.moveCursorToPosition(cursor);\n
        editor.selection.clearSelection();\n
        editor.renderer.scrollCursorIntoView();\n
\n
        editor.removeSelectionMarkers(rectSel);\n
        rectSel = selection.rectangularRangeBlock(screenCursor, screenAnchor);\n
        rectSel.forEach(editor.addSelectionMarker, editor);\n
        editor.updateSelectionMarkers();\n
    };\n
    \n
    var session = editor.session;\n
    var screenAnchor = editor.renderer.pixelToScreenCoordinates(mouseX, mouseY);\n
    var screenCursor = screenAnchor;\n
\n
    \n
\n
    if (ctrl && !shift && !alt && button == 0) {\n
        if (!isMultiSelect && inSelection)\n
            return; // dragging\n
\n
        if (!isMultiSelect) {\n
            var range = selection.toOrientedRange();\n
            editor.addSelectionMarker(range);\n
        }\n
\n
        var oldRange = selection.rangeList.rangeAtPoint(pos);\n
\n
        editor.once("mouseup", function() {\n
            var tmpSel = selection.toOrientedRange();\n
\n
            if (oldRange && tmpSel.isEmpty() && isSamePoint(oldRange.cursor, tmpSel.cursor))\n
                selection.substractPoint(tmpSel.cursor);\n
            else {\n
                if (range) {\n
                    editor.removeSelectionMarker(range);\n
                    selection.addRange(range);\n
                }\n
                selection.addRange(tmpSel);\n
            }\n
        });\n
\n
    } else if (alt && button == 0) {\n
        e.stop();\n
\n
        if (isMultiSelect && !ctrl)\n
            selection.toSingleRange();\n
        else if (!isMultiSelect && ctrl)\n
            selection.addRange();\n
\n
        var rectSel = [];\n
        if (shift) {\n
            screenAnchor = session.documentToScreenPosition(selection.lead);\n
            blockSelect();\n
        } else {\n
            selection.moveCursorToPosition(pos);\n
            selection.clearSelection();\n
        }\n
\n
\n
        var onMouseSelectionEnd = function(e) {\n
            clearInterval(timerId);\n
            editor.removeSelectionMarkers(rectSel);\n
            for (var i = 0; i < rectSel.length; i++)\n
                selection.addRange(rectSel[i]);\n
        };\n
\n
        var onSelectionInterval = blockSelect;\n
\n
        event.capture(editor.container, onMouseSelection, onMouseSelectionEnd);\n
        var timerId = setInterval(function() {onSelectionInterval();}, 20);\n
\n
        return e.preventDefault();\n
    }\n
}\n
\n
\n
exports.onMouseDown = onMouseDown;\n
\n
});\n
\n
define(\'ace/commands/multi_select_commands\', [\'require\', \'exports\', \'module\' , \'ace/keyboard/hash_handler\'], function(require, exports, module) {\n
exports.defaultCommands = [{\n
    name: "addCursorAbove",\n
    exec: function(editor) { editor.selectMoreLines(-1); },\n
    bindKey: {win: "Ctrl-Alt-Up", mac: "Ctrl-Alt-Up"},\n
    readonly: true\n
}, {\n
    name: "addCursorBelow",\n
    exec: function(editor) { editor.selectMoreLines(1); },\n
    bindKey: {win: "Ctrl-Alt-Down", mac: "Ctrl-Alt-Down"},\n
    readonly: true\n
}, {\n
    name: "addCursorAboveSkipCurrent",\n
    exec: function(editor) { editor.selectMoreLines(-1, true); },\n
    bindKey: {win: "Ctrl-Alt-Shift-Up", mac: "Ctrl-Alt-Shift-Up"},\n
    readonly: true\n
}, {\n
    name: "addCursorBelowSkipCurrent",\n
    exec: function(editor) { editor.selectMoreLines(1, true); },\n
    bindKey: {win: "Ctrl-Alt-Shift-Down", mac: "Ctrl-Alt-Shift-Down"},\n
    readonly: true\n
}, {\n
    name: "selectMoreBefore",\n
    exec: function(editor) { editor.selectMore(-1); },\n
    bindKey: {win: "Ctrl-Alt-Left", mac: "Ctrl-Alt-Left"},\n
    readonly: true\n
}, {\n
    name: "selectMoreAfter",\n
    exec: function(editor) { editor.selectMore(1); },\n
    bindKey: {win: "Ctrl-Alt-Right", mac: "Ctrl-Alt-Right"},\n
    readonly: true\n
}, {\n
    name: "selectNextBefore",\n
    exec: function(editor) { editor.selectMore(-1, true); },\n
    bindKey: {win: "Ctrl-Alt-Shift-Left", mac: "Ctrl-Alt-Shift-Left"},\n
    readonly: true\n
}, {\n
    name: "selectNextAfter",\n
    exec: function(editor) { editor.selectMore(1, true); },\n
    bindKey: {win: "Ctrl-Alt-Shift-Right", mac: "Ctrl-Alt-Shift-Right"},\n
    readonly: true\n
}, {\n
    name: "splitIntoLines",\n
    exec: function(editor) { editor.multiSelect.splitIntoLines(); },\n
    bindKey: {win: "Ctrl-Alt-L", mac: "Ctrl-Alt-L"},\n
    readonly: true\n
}, {\n
    name: "alignCursors",\n
    exec: function(editor) { editor.alignCursors(); },\n
    bindKey: {win: "Ctrl-Alt-A", mac: "Ctrl-Alt-A"}\n
}];\n
exports.multiSelectCommands = [{\n
    name: "singleSelection",\n
    bindKey: "esc",\n
    exec: function(editor) { editor.exitMultiSelectMode(); },\n
    readonly: true,\n
    isAvailable: function(editor) {return editor && editor.inMultiSelectMode}\n
}];\n
\n
var HashHandler = require("../keyboard/hash_handler").HashHandler;\n
exports.keyboardHandler = new HashHandler(exports.multiSelectCommands);\n
\n
});\n
\n
define(\'ace/worker/worker_client\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/lib/event_emitter\', \'ace/config\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var EventEmitter = require("../lib/event_emitter").EventEmitter;\n
var config = require("../config");\n
\n
var WorkerClient = function(topLevelNamespaces, mod, classname) {\n
    this.$sendDeltaQueue = this.$sendDeltaQueue.bind(this);\n
    this.changeListener = this.changeListener.bind(this);\n
    this.onMessage = this.onMessage.bind(this);\n
    this.onError = this.onError.bind(this);\n
    if (require.nameToUrl && !require.toUrl)\n
        require.toUrl = require.nameToUrl;\n
\n
    var workerUrl;\n
    if (config.get("packaged") || !require.toUrl) {\n
        workerUrl = config.moduleUrl(mod, "worker");\n
    } else {\n
        var normalizePath = this.$normalizePath;\n
        workerUrl = normalizePath(require.toUrl("ace/worker/worker.js", null, "_"));\n
\n
        var tlns = {};\n
        topLevelNamespaces.forEach(function(ns) {\n
            tlns[ns] = normalizePath(require.toUrl(ns, null, "_").replace(/(\\.js)?(\\?.*)?$/, ""));\n
        });\n
    }\n
\n
    this.$worker = new Worker(workerUrl);\n
    this.$worker.postMessage({\n
        init : true,\n
        tlns: tlns,\n
        module: mod,\n
        classname: classname\n
    });\n
\n
    this.callbackId = 1;\n
    this.callbacks = {};\n
\n
    this.$worker.onerror = this.onError;\n
    this.$worker.onmessage = this.onMessage;\n
};\n
\n
(function(){\n
\n
    oop.implement(this, EventEmitter);\n
\n
    this.onError = function(e) {\n
        window.console && console.log && console.log(e);\n
        throw e;\n
    };\n
\n
    this.onMessage = function(e) {\n
        var msg = e.data;\n
        switch(msg.type) {\n
            case "log":\n
                window.console && console.log && console.log.apply(console, msg.data);\n
                break;\n
\n
            case "event":\n
                this._emit(msg.name, {data: msg.data});\n
                break;\n
\n
            case "call":\n
                var callback = this.callbacks[msg.id];\n
                if (callback) {\n
                    callback(msg.data);\n
                    delete this.callbacks[msg.id];\n
                }\n
                break;\n
        }\n
    };\n
\n
    this.$normalizePath = function(path) {\n
        if (!location.host) // needed for file:// protocol\n
            return path;\n
        path = path.replace(/^[a-z]+:\\/\\/[^\\/]+/, ""); // Remove domain name and rebuild it\n
        path = location.protocol + "//" + location.host\n
            + (path.charAt(0) == "/" ? "" : location.pathname.replace(/\\/[^\\/]*$/, ""))\n
            + "/" + path.replace(/^[\\/]+/, "");\n
        return path;\n
    };\n
\n
    this.terminate = function() {\n
        this._emit("terminate", {});\n
        this.deltaQueue = null;\n
        this.$worker.terminate();\n
        this.$worker = null;\n
        this.$doc.removeEventListener("change", this.changeListener);\n
        this.$doc = null;\n
    };\n
\n
    this.send = function(cmd, args) {\n
        this.$worker.postMessage({command: cmd, args: args});\n
    };\n
\n
    this.call = function(cmd, args, callback) {\n
        if (callback) {\n
            var id = this.callbackId++;\n
            this.callbacks[id] = callback;\n
            args.push(id);\n
        }\n
        this.send(cmd, args);\n
    };\n
\n
    this.emit = function(event, data) {\n
        try {\n
            this.$worker.postMessage({event: event, data: {data: data.data}});\n
        }\n
        catch(ex) {}\n
    };\n
\n
    this.attachToDocument = function(doc) {\n
        if(this.$doc)\n
            this.terminate();\n
\n
        this.$doc = doc;\n
        this.call("setValue", [doc.getValue()]);\n
        doc.on("change", this.changeListener);\n
    };\n
\n
    this.changeListener = function(e) {\n
        if (!this.deltaQueue) {\n
            this.deltaQueue = [e.data];\n
            setTimeout(this.$sendDeltaQueue, 1);\n
        } else\n
            this.deltaQueue.push(e.data);\n
    };\n
\n
    this.$sendDeltaQueue = function() {\n
        var q = this.deltaQueue;\n
        if (!q) return;\n
        this.deltaQueue = null;\n
        if (q.length > 20 && q.length > this.$doc.getLength() >> 1) {\n
            this.call("setValue", [this.$doc.getValue()]);\n
        } else\n
            this.emit("change", {data: q});\n
    }\n
\n
}).call(WorkerClient.prototype);\n
\n
\n
var UIWorkerClient = function(topLevelNamespaces, mod, classname) {\n
    this.$sendDeltaQueue = this.$sendDeltaQueue.bind(this);\n
    this.changeListener = this.changeListener.bind(this);\n
    this.callbackId = 1;\n
    this.callbacks = {};\n
    this.messageBuffer = [];\n
\n
    var main = null;\n
    var sender = Object.create(EventEmitter);\n
    var _self = this;\n
\n
    this.$worker = {};\n
    this.$worker.terminate = function() {};\n
    this.$worker.postMessage = function(e) {\n
        _self.messageBuffer.push(e);\n
        main && setTimeout(processNext);\n
    };\n
\n
    var processNext = function() {\n
        var msg = _self.messageBuffer.shift();\n
        if (msg.command)\n
            main[msg.command].apply(main, msg.args);\n
        else if (msg.event)\n
            sender._emit(msg.event, msg.data);\n
    };\n
\n
    sender.postMessage = function(msg) {\n
        _self.onMessage({data: msg});\n
    };\n
    sender.callback = function(data, callbackId) {\n
        this.postMessage({type: "call", id: callbackId, data: data});\n
    };\n
    sender.emit = function(name, data) {\n
        this.postMessage({type: "event", name: name, data: data});\n
    };\n
\n
    config.loadModule(["worker", mod], function(Main) {\n
        main = new Main[classname](sender);\n
        while (_self.messageBuffer.length)\n
            processNext();\n
    });\n
};\n
\n
UIWorkerClient.prototype = WorkerClient.prototype;\n
\n
exports.UIWorkerClient = UIWorkerClient;\n
exports.WorkerClient = WorkerClient;\n
\n
});\n
define(\'ace/placeholder\', [\'require\', \'exports\', \'module\' , \'ace/range\', \'ace/lib/event_emitter\', \'ace/lib/oop\'], function(require, exports, module) {\n
\n
\n
var Range = require("./range").Range;\n
var EventEmitter = require("./lib/event_emitter").EventEmitter;\n
var oop = require("./lib/oop");\n
\n
var PlaceHolder = function(session, length, pos, others, mainClass, othersClass) {\n
    var _self = this;\n
    this.length = length;\n
    this.session = session;\n
    this.doc = session.getDocument();\n
    this.mainClass = mainClass;\n
    this.othersClass = othersClass;\n
    this.$onUpdate = this.onUpdate.bind(this);\n
    this.doc.on("change", this.$onUpdate);\n
    this.$others = others;\n
    \n
    this.$onCursorChange = function() {\n
        setTimeout(function() {\n
            _self.onCursorChange();\n
        });\n
    };\n
    \n
    this.$pos = pos;\n
    var undoStack = session.getUndoManager().$undoStack || session.getUndoManager().$undostack || {length: -1};\n
    this.$undoStackDepth =  undoStack.length;\n
    this.setup();\n
\n
    session.selection.on("changeCursor", this.$onCursorChange);\n
};\n
\n
(function() {\n
\n
    oop.implement(this, EventEmitter);\n
    this.setup = function() {\n
        var _self = this;\n
        var doc = this.doc;\n
        var session = this.session;\n
        var pos = this.$pos;\n
\n
        this.pos = doc.createAnchor(pos.row, pos.column);\n
        this.markerId = session.addMarker(new Range(pos.row, pos.column, pos.row, pos.column + this.length), this.mainClass, null, false);\n
        this.pos.on("change", function(event) {\n
            session.removeMarker(_self.markerId);\n
            _self.markerId = session.addMarker(new Range(event.value.row, event.value.column, event.value.row, event.value.column+_self.length), _self.mainClass, null, false);\n
        });\n
        this.others = [];\n
        this.$others.forEach(function(other) {\n
            var anchor = doc.createAnchor(other.row, other.column);\n
            _self.others.push(anchor);\n
        });\n
        session.setUndoSelect(false);\n
    };\n
    this.showOtherMarkers = function() {\n
        if(this.othersActive) return;\n
        var session = this.session;\n
        var _self = this;\n
        this.othersActive = true;\n
        this.others.forEach(function(anchor) {\n
            anchor.markerId = session.addMarker(new Range(anchor.row, anchor.column, anchor.row, anchor.column+_self.length), _self.othersClass, null, false);\n
            anchor.on("change", function(event) {\n
                session.removeMarker(anchor.markerId);\n
                anchor.markerId = session.addMarker(new Range(event.value.row, event.value.column, event.value.row, event.value.column+_self.length), _self.othersClass, null, false);\n
            });\n
        });\n
    };\n
    this.hideOtherMarkers = function() {\n
        if(!this.othersActive) return;\n
        this.othersActive = false;\n
        for (var i = 0; i < this.others.length; i++) {\n
            this.session.removeMarker(this.others[i].markerId);\n
        }\n
    };\n
    this.onUpdate = function(event) {\n
        var delta = event.data;\n
        var range = delta.range;\n
        if(range.start.row !== range.end.row) return;\n
        if(range.start.row !== this.pos.row) return;\n
        if (this.$updating) return;\n
        this.$updating = true;\n
        var lengthDiff = delta.action === "insertText" ? range.end.column - range.start.column : range.start.column - range.end.column;\n
        \n
        if(range.start.column >= this.pos.column && range.start.column <= this.pos.column + this.length + 1) {\n
            var distanceFromStart = range.start.column - this.pos.column;\n
            this.length += lengthDiff;\n
            if(!this.session.$fromUndo) {\n
                if(delta.action === "insertText") {\n
                    for (var i = this.others.length - 1; i >= 0; i--) {\n
                        var otherPos = this.others[i];\n
                        var newPos = {row: otherPos.row, column: otherPos.column + distanceFromStart};\n
                        if(otherPos.row === range.start.row && range.start.column < otherPos.column)\n
                            newPos.column += lengthDiff;\n
                        this.doc.insert(newPos, delta.text);\n
                    }\n
                } else if(delta.action === "removeText") {\n
                    for (var i = this.others.length - 1; i >= 0; i--) {\n
                        var otherPos = this.others[i];\n
                        var newPos = {row: otherPos.row, column: otherPos.column + distanceFromStart};\n
                        if(otherPos.row === range.start.row && range.start.column < otherPos.column)\n
                            newPos.column += lengthDiff;\n
                        this.doc.remove(new Range(newPos.row, newPos.column, newPos.row, newPos.column - lengthDiff));\n
                    }\n
                }\n
                if(range.start.column === this.pos.column && delta.action === "insertText") {\n
                    setTimeout(function() {\n
                        this.pos.setPosition(this.pos.row, this.pos.column - lengthDiff);\n
                        for (var i = 0; i < this.others.length; i++) {\n
                            var other = this.others[i];\n
                            var newPos = {row: other.row, column: other.column - lengthDiff};\n
                            if(other.row === range.start.row && range.start.column < other.column)\n
                                newPos.column += lengthDiff;\n
                            other.setPosition(newPos.row, newPos.column);\n
                        }\n
                    }.bind(this), 0);\n
                }\n
                else if(range.start.column === this.pos.column && delta.action === "removeText") {\n
                    setTimeout(function() {\n
                        for (var i = 0; i < this.others.length; i++) {\n
                            var other = this.others[i];\n
                            if(other.row === range.start.row && range.start.column < other.column) {\n
                                other.setPosition(other.row, other.column - lengthDiff);\n
                            }\n
                        }\n
                    }.bind(this), 0);\n
                }\n
            }\n
            this.pos._emit("change", {value: this.pos});\n
            for (var i = 0; i < this.others.length; i++) {\n
                this.others[i]._emit("change", {value: this.others[i]});\n
            }\n
        }\n
        this.$updating = false;\n
    };\n
\n
    this.onCursorChange = function(event) {\n
        if (this.$updating) return;\n
        var pos = this.session.selection.getCursor();\n
        if(pos.row === this.pos.row && pos.column >= this.pos.column && pos.column <= this.pos.column + this.length) {\n
            this.showOtherMarkers();\n
            this._emit("cursorEnter", event);\n
        } else {\n
            this.hideOtherMarkers();\n
            this._emit("cursorLeave", event);\n
        }\n
    };    \n
    this.detach = function() {\n
        this.session.removeMarker(this.markerId);\n
        this.hideOtherMarkers();\n
        this.doc.removeEventListener("change", this.$onUpdate);\n
        this.session.selection.removeEventListener("changeCursor", this.$onCursorChange);\n
        this.pos.detach();\n
        for (var i = 0; i < this.others.length; i++) {\n
            this.others[i].detach();\n
        }\n
        this.session.setUndoSelect(true);\n
    };\n
    this.cancel = function() {\n
        if(this.$undoStackDepth === -1)\n
            throw Error("Canceling placeholders only supported with undo manager attached to session.");\n
        var undoManager = this.session.getUndoManager();\n
        var undosRequired = (undoManager.$undoStack || undoManager.$undostack).length - this.$undoStackDepth;\n
        for (var i = 0; i < undosRequired; i++) {\n
            undoManager.undo(true);\n
        }\n
    };\n
}).call(PlaceHolder.prototype);\n
\n
\n
exports.PlaceHolder = PlaceHolder;\n
});\n
\n
define(\'ace/mode/folding/fold_mode\', [\'require\', \'exports\', \'module\' , \'ace/range\'], function(require, exports, module) {\n
\n
\n
var Range = require("../../range").Range;\n
\n
var FoldMode = exports.FoldMode = function() {};\n
\n
(function() {\n
\n
    this.foldingStartMarker = null;\n
    this.foldingStopMarker = null;\n
    this.getFoldWidget = function(session, foldStyle, row) {\n
        var line = session.getLine(row);\n
        if (this.foldingStartMarker.test(line))\n
            return "start";\n
        if (foldStyle == "markbeginend"\n
                && this.foldingStopMarker\n
                && this.foldingStopMarker.test(line))\n
            return "end";\n
        return "";\n
    };\n
\n
    this.getFoldWidgetRange = function(session, foldStyle, row) {\n
        return null;\n
    };\n
\n
    this.indentationBlock = function(session, row, column) {\n
        var re = /\\S/;\n
        var line = session.getLine(row);\n
        var startLevel = line.search(re);\n
        if (startLevel == -1)\n
            return;\n
\n
        var startColumn = column || line.length;\n
        var maxRow = session.getLength();\n
        var startRow = row;\n
        var endRow = row;\n
\n
        while (++row < maxRow) {\n
            var level = session.getLine(row).search(re);\n
\n
            if (level == -1)\n
                continue;\n
\n
            if (level <= startLevel)\n
                break;\n
\n
            endRow = row;\n
        }\n
\n
        if (endRow > startRow) {\n
            var endColumn = session.getLine(endRow).length;\n
            return new Range(startRow, startColumn, endRow, endColumn);\n
        }\n
    };\n
\n
    this.openingBracketBlock = function(session, bracket, row, column, typeRe) {\n
        var start = {row: row, column: column + 1};\n
        var end = session.$findClosingBracket(bracket, start, typeRe);\n
        if (!end)\n
            return;\n
\n
        var fw = session.foldWidgets[end.row];\n
        if (fw == null)\n
            fw = this.getFoldWidget(session, end.row);\n
\n
        if (fw == "start" && end.row > start.row) {\n
            end.row --;\n
            end.column = session.getLine(end.row).length;\n
        }\n
        return Range.fromPoints(start, end);\n
    };\n
\n
    this.closingBracketBlock = function(session, bracket, row, column, typeRe) {\n
        var end = {row: row, column: column};\n
        var start = session.$findOpeningBracket(bracket, end);\n
\n
        if (!start)\n
            return;\n
\n
        start.column++;\n
        end.column--;\n
\n
        return  Range.fromPoints(start, end);\n
    };\n
}).call(FoldMode.prototype);\n
\n
});\n
\n
define(\'ace/theme/textmate\', [\'require\', \'exports\', \'module\' , \'ace/lib/dom\'], function(require, exports, module) {\n
\n
\n
exports.isDark = false;\n
exports.cssClass = "ace-tm";\n
exports.cssText = ".ace-tm .ace_gutter {\\\n
background: #f0f0f0;\\\n
color: #333;\\\n
}\\\n
.ace-tm .ace_print-margin {\\\n
width: 1px;\\\n
background: #e8e8e8;\\\n
}\\\n
.ace-tm .ace_fold {\\\n
background-color: #6B72E6;\\\n
}\\\n
.ace-tm {\\\n
background-color: #FFFFFF;\\\n
}\\\n
.ace-tm .ace_cursor {\\\n
color: black;\\\n
}\\\n
.ace-tm .ace_invisible {\\\n
color: rgb(191, 191, 191);\\\n
}\\\n
.ace-tm .ace_storage,\\\n
.ace-tm .ace_keyword {\\\n
color: blue;\\\n
}\\\n
.ace-tm .ace_constant {\\\n
color: rgb(197, 6, 11);\\\n
}\\\n
.ace-tm .ace_constant.ace_buildin {\\\n
color: rgb(88, 72, 246);\\\n
}\\\n
.ace-tm .ace_constant.ace_language {\\\n
color: rgb(88, 92, 246);\\\n
}\\\n
.ace-tm .ace_constant.ace_library {\\\n
color: rgb(6, 150, 14);\\\n
}\\\n
.ace-tm .ace_invalid {\\\n
background-color: rgba(255, 0, 0, 0.1);\\\n
color: red;\\\n
}\\\n
.ace-tm .ace_support.ace_function {\\\n
color: rgb(60, 76, 114);\\\n
}\\\n
.ace-tm .ace_support.ace_constant {\\\n
color: rgb(6, 150, 14);\\\n
}\\\n
.ace-tm .ace_support.ace_type,\\\n
.ace-tm .ace_support.ace_class {\\\n
color: rgb(109, 121, 222);\\\n
}\\\n
.ace-tm .ace_keyword.ace_operator {\\\n
color: rgb(104, 118, 135);\\\n
}\\\n
.ace-tm .ace_string {\\\n
color: rgb(3, 106, 7);\\\n
}\\\n
.ace-tm .ace_comment {\\\n
color: rgb(76, 136, 107);\\\n
}\\\n
.ace-tm .ace_comment.ace_doc {\\\n
color: rgb(0, 102, 255);\\\n
}\\\n
.ace-tm .ace_comment.ace_doc.ace_tag {\\\n
color: rgb(128, 159, 191);\\\n
}\\\n
.ace-tm .ace_constant.ace_numeric {\\\n
color: rgb(0, 0, 205);\\\n
}\\\n
.ace-tm .ace_variable {\\\n
color: rgb(49, 132, 149);\\\n
}\\\n
.ace-tm .ace_xml-pe {\\\n
color: rgb(104, 104, 91);\\\n
}\\\n
.ace-tm .ace_entity.ace_name.ace_function {\\\n
color: #0000A2;\\\n
}\\\n
.ace-tm .ace_heading {\\\n
color: rgb(12, 7, 255);\\\n
}\\\n
.ace-tm .ace_list {\\\n
color:rgb(185, 6, 144);\\\n
}\\\n
.ace-tm .ace_meta.ace_tag {\\\n
color:rgb(0, 22, 142);\\\n
}\\\n
.ace-tm .ace_string.ace_regex {\\\n
color: rgb(255, 0, 0)\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_selection {\\\n
background: rgb(181, 213, 255);\\\n
}\\\n
.ace-tm.ace_multiselect .ace_selection.ace_start {\\\n
box-shadow: 0 0 3px 0px white;\\\n
border-radius: 2px;\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_step {\\\n
background: rgb(252, 255, 0);\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_stack {\\\n
background: rgb(164, 229, 101);\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_bracket {\\\n
margin: -1px 0 0 -1px;\\\n
border: 1px solid rgb(192, 192, 192);\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_active-line {\\\n
background: rgba(0, 0, 0, 0.07);\\\n
}\\\n
.ace-tm .ace_gutter-active-line {\\\n
background-color : #dcdcdc;\\\n
}\\\n
.ace-tm .ace_marker-layer .ace_selected-word {\\\n
background: rgb(250, 250, 255);\\\n
border: 1px solid rgb(200, 200, 250);\\\n
}\\\n
.ace-tm .ace_indent-guide {\\\n
background: url(\\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAE0lEQVQImWP4////f4bLly//BwAmVgd1/w11/gAAAABJRU5ErkJggg==\\") right repeat-y;\\\n
}\\\n
";\n
\n
var dom = require("../lib/dom");\n
dom.importCssString(exports.cssText, exports.cssClass);\n
});\n
;\n
            (function() {\n
                window.require(["ace/ace"], function(a) {\n
                    a && a.config.init();\n
                    if (!window.ace)\n
                        window.ace = {};\n
                    for (var key in a) if (a.hasOwnProperty(key))\n
                        ace[key] = a[key];\n
                });\n
            })();\n
        

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <none/>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
