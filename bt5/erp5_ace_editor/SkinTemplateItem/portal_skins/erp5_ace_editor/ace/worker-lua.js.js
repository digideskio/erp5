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
            <value> <string>ts83646621.49</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>worker-lua.js</string> </value>
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
            <value> <int>100225</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
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

"no use strict";\n
;(function(window) {\n
if (typeof window.window != "undefined" && window.document) {\n
    return;\n
}\n
\n
window.console = function() {\n
    var msgs = Array.prototype.slice.call(arguments, 0);\n
    postMessage({type: "log", data: msgs});\n
};\n
window.console.error =\n
window.console.warn = \n
window.console.log =\n
window.console.trace = window.console;\n
\n
window.window = window;\n
window.ace = window;\n
\n
window.normalizeModule = function(parentId, moduleName) {\n
    if (moduleName.indexOf("!") !== -1) {\n
        var chunks = moduleName.split("!");\n
        return window.normalizeModule(parentId, chunks[0]) + "!" + window.normalizeModule(parentId, chunks[1]);\n
    }\n
    if (moduleName.charAt(0) == ".") {\n
        var base = parentId.split("/").slice(0, -1).join("/");\n
        moduleName = (base ? base + "/" : "") + moduleName;\n
        \n
        while(moduleName.indexOf(".") !== -1 && previous != moduleName) {\n
            var previous = moduleName;\n
            moduleName = moduleName.replace(/^\\.\\//, "").replace(/\\/\\.\\//, "/").replace(/[^\\/]+\\/\\.\\.\\//, "");\n
        }\n
    }\n
    \n
    return moduleName;\n
};\n
\n
window.require = function(parentId, id) {\n
    if (!id) {\n
        id = parentId\n
        parentId = null;\n
    }\n
    if (!id.charAt)\n
        throw new Error("worker.js require() accepts only (parentId, id) as arguments");\n
\n
    id = window.normalizeModule(parentId, id);\n
\n
    var module = window.require.modules[id];\n
    if (module) {\n
        if (!module.initialized) {\n
            module.initialized = true;\n
            module.exports = module.factory().exports;\n
        }\n
        return module.exports;\n
    }\n
    \n
    var chunks = id.split("/");\n
    if (!window.require.tlns)\n
        return console.log("unable to load " + id);\n
    chunks[0] = window.require.tlns[chunks[0]] || chunks[0];\n
    var path = chunks.join("/") + ".js";\n
    \n
    window.require.id = id;\n
    importScripts(path);\n
    return window.require(parentId, id);\n
};\n
window.require.modules = {};\n
window.require.tlns = {};\n
\n
window.define = function(id, deps, factory) {\n
    if (arguments.length == 2) {\n
        factory = deps;\n
        if (typeof id != "string") {\n
            deps = id;\n
            id = window.require.id;\n
        }\n
    } else if (arguments.length == 1) {\n
        factory = id;\n
        deps = []\n
        id = window.require.id;\n
    }\n
\n
    if (!deps.length)\n
        deps = [\'require\', \'exports\', \'module\']\n
\n
    if (id.indexOf("text!") === 0) \n
        return;\n
    \n
    var req = function(childId) {\n
        return window.require(id, childId);\n
    };\n
\n
    window.require.modules[id] = {\n
        exports: {},\n
        factory: function() {\n
            var module = this;\n
            var returnExports = factory.apply(this, deps.map(function(dep) {\n
              switch(dep) {\n
                  case \'require\': return req\n
                  case \'exports\': return module.exports\n
                  case \'module\':  return module\n
                  default:        return req(dep)\n
              }\n
            }));\n
            if (returnExports)\n
                module.exports = returnExports;\n
            return module;\n
        }\n
    };\n
};\n
window.define.amd = {}\n
\n
window.initBaseUrls  = function initBaseUrls(topLevelNamespaces) {\n
    require.tlns = topLevelNamespaces;\n
}\n
\n
window.initSender = function initSender() {\n
\n
    var EventEmitter = window.require("ace/lib/event_emitter").EventEmitter;\n
    var oop = window.require("ace/lib/oop");\n
    \n
    var Sender = function() {};\n
    \n
    (function() {\n
        \n
        oop.implement(this, EventEmitter);\n
                \n
        this.callback = function(data, callbackId) {\n
            postMessage({\n
                type: "call",\n
                id: callbackId,\n
                data: data\n
            });\n
        };\n
    \n
        this.emit = function(name, data) {\n
            postMessage({\n
                type: "event",\n
                name: name,\n
                data: data\n
            });\n
        };\n
        \n
    }).call(Sender.prototype);\n
    \n
    return new Sender();\n
}\n
\n
window.main = null;\n
window.sender = null;\n
\n
window.onmessage = function(e) {\n
    var msg = e.data;\n
    if (msg.command) {\n
        if (main[msg.command])\n
            main[msg.command].apply(main, msg.args);\n
        else\n
            throw new Error("Unknown command:" + msg.command);\n
    }\n
    else if (msg.init) {        \n
        initBaseUrls(msg.tlns);\n
        require("ace/lib/es5-shim");\n
        sender = initSender();\n
        var clazz = require(msg.module)[msg.classname];\n
        main = new clazz(sender);\n
    } \n
    else if (msg.event && sender) {\n
        sender._emit(msg.event, msg.data);\n
    }\n
};\n
})(this);// https://github.com/kriskowal/es5-shim\n
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
define(\'ace/mode/lua_worker\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/worker/mirror\', \'ace/mode/lua/luaparse\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var Mirror = require("../worker/mirror").Mirror;\n
var luaparse = require("../mode/lua/luaparse");\n
\n
var Worker = exports.Worker = function(sender) {\n
    Mirror.call(this, sender);\n
    this.setTimeout(500);\n
};\n
\n
oop.inherits(Worker, Mirror);\n
\n
(function() {\n
\n
    this.onUpdate = function() {\n
        var value = this.doc.getValue();\n
        try {\n
            luaparse.parse(value);\n
        } catch(e) {\n
            if (e instanceof SyntaxError) {\n
                this.sender.emit("error", {\n
\t\t\t\t\trow: e.line - 1,\n
\t\t\t\t\tcolumn: e.column,\n
\t\t\t\t\ttext: e.message,\n
\t\t\t\t\ttype: "error"\n
\t\t\t\t});\n
            }\n
            return;\n
        }\n
        this.sender.emit("ok");\n
    };\n
\n
}).call(Worker.prototype);\n
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
define(\'ace/worker/mirror\', [\'require\', \'exports\', \'module\' , \'ace/document\', \'ace/lib/lang\'], function(require, exports, module) {\n
\n
\n
var Document = require("../document").Document;\n
var lang = require("../lib/lang");\n
    \n
var Mirror = exports.Mirror = function(sender) {\n
    this.sender = sender;\n
    var doc = this.doc = new Document("");\n
    \n
    var deferredUpdate = this.deferredUpdate = lang.delayedCall(this.onUpdate.bind(this));\n
    \n
    var _self = this;\n
    sender.on("change", function(e) {\n
        doc.applyDeltas(e.data);\n
        deferredUpdate.schedule(_self.$timeout);\n
    });\n
};\n
\n
(function() {\n
    \n
    this.$timeout = 500;\n
    \n
    this.setTimeout = function(timeout) {\n
        this.$timeout = timeout;\n
    };\n
    \n
    this.setValue = function(value) {\n
        this.doc.setValue(value);\n
        this.deferredUpdate.schedule(this.$timeout);\n
    };\n
    \n
    this.getValue = function(callbackId) {\n
        this.sender.callback(this.doc.getValue(), callbackId);\n
    };\n
    \n
    this.onUpdate = function() {\n
    };\n
    \n
}).call(Mirror.prototype);\n
\n
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
            lines[l] = lines[l].substring(0, range.end.column);\n
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
            if (this.isStart(row, column)) {\n
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
define(\'ace/mode/lua/luaparse\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
(function (root, name, factory) {\n
   factory(exports)\n
}(this, \'luaparse\', function (exports) {\n
  \n
\n
  exports.version = \'0.1.4\';\n
\n
  var input, options, length;\n
  var defaultOptions = exports.defaultOptions = {\n
      wait: false\n
    , comments: true\n
    , scope: false\n
    , locations: false\n
    , ranges: false\n
  };\n
\n
  var EOF = 1, StringLiteral = 2, Keyword = 4, Identifier = 8\n
    , NumericLiteral = 16, Punctuator = 32, BooleanLiteral = 64\n
    , NilLiteral = 128, VarargLiteral = 256;\n
\n
  exports.tokenTypes = { EOF: EOF, StringLiteral: StringLiteral\n
    , Keyword: Keyword, Identifier: Identifier, NumericLiteral: NumericLiteral\n
    , Punctuator: Punctuator, BooleanLiteral: BooleanLiteral\n
    , NilLiteral: NilLiteral, VarargLiteral: VarargLiteral\n
  };\n
\n
  var errors = exports.errors = {\n
      unexpected: \'Unexpected %1 \\\'%2\\\' near \\\'%3\\\'\'\n
    , expected: \'\\\'%1\\\' expected near \\\'%2\\\'\'\n
    , expectedToken: \'%1 expected near \\\'%2\\\'\'\n
    , unfinishedString: \'unfinished string near \\\'%1\\\'\'\n
    , malformedNumber: \'malformed number near \\\'%1\\\'\'\n
  };\n
\n
  var ast = exports.ast = {\n
      labelStatement: function(label) {\n
      return {\n
          type: \'LabelStatement\'\n
        , label: label\n
      };\n
    }\n
\n
    , breakStatement: function() {\n
      return {\n
          type: \'BreakStatement\'\n
      };\n
    }\n
\n
    , gotoStatement: function(label) {\n
      return {\n
          type: \'GotoStatement\'\n
        , label: label\n
      };\n
    }\n
\n
    , returnStatement: function(args) {\n
      return {\n
          type: \'ReturnStatement\'\n
        , \'arguments\': args\n
      };\n
    }\n
\n
    , ifStatement: function(clauses) {\n
      return {\n
          type: \'IfStatement\'\n
        , clauses: clauses\n
      };\n
    }\n
    , ifClause: function(condition, body) {\n
      return {\n
          type: \'IfClause\'\n
        , condition: condition\n
        , body: body\n
      };\n
    }\n
    , elseifClause: function(condition, body) {\n
      return {\n
          type: \'ElseifClause\'\n
        , condition: condition\n
        , body: body\n
      };\n
    }\n
    , elseClause: function(body) {\n
      return {\n
          type: \'ElseClause\'\n
        , body: body\n
      };\n
    }\n
\n
    , whileStatement: function(condition, body) {\n
      return {\n
          type: \'WhileStatement\'\n
        , condition: condition\n
        , body: body\n
      };\n
    }\n
\n
    , doStatement: function(body) {\n
      return {\n
          type: \'DoStatement\'\n
        , body: body\n
      };\n
    }\n
\n
    , repeatStatement: function(condition, body) {\n
      return {\n
          type: \'RepeatStatement\'\n
        , condition: condition\n
        , body: body\n
      };\n
    }\n
\n
    , localStatement: function(variables, init) {\n
      return {\n
          type: \'LocalStatement\'\n
        , variables: variables\n
        , init: init\n
      };\n
    }\n
\n
    , assignmentStatement: function(variables, init) {\n
      return {\n
          type: \'AssignmentStatement\'\n
        , variables: variables\n
        , init: init\n
      };\n
    }\n
\n
    , callStatement: function(expression) {\n
      return {\n
          type: \'CallStatement\'\n
        , expression: expression\n
      };\n
    }\n
\n
    , functionStatement: function(identifier, parameters, isLocal, body) {\n
      return {\n
          type: \'FunctionDeclaration\'\n
        , identifier: identifier\n
        , isLocal: isLocal\n
        , parameters: parameters\n
        , body: body\n
      };\n
    }\n
\n
    , forNumericStatement: function(variable, start, end, step, body) {\n
      return {\n
          type: \'ForNumericStatement\'\n
        , variable: variable\n
        , start: start\n
        , end: end\n
        , step: step\n
        , body: body\n
      };\n
    }\n
\n
    , forGenericStatement: function(variables, iterators, body) {\n
      return {\n
          type: \'ForGenericStatement\'\n
        , variables: variables\n
        , iterators: iterators\n
        , body: body\n
      };\n
    }\n
\n
    , chunk: function(body) {\n
      return {\n
          type: \'Chunk\'\n
        , body: body\n
      };\n
    }\n
\n
    , identifier: function(name) {\n
      return {\n
          type: \'Identifier\'\n
        , name: name\n
      };\n
    }\n
\n
    , literal: function(type, value, raw) {\n
      type = (type === StringLiteral) ? \'StringLiteral\'\n
        : (type === NumericLiteral) ? \'NumericLiteral\'\n
        : (type === BooleanLiteral) ? \'BooleanLiteral\'\n
        : (type === NilLiteral) ? \'NilLiteral\'\n
        : \'VarargLiteral\';\n
\n
      return {\n
          type: type\n
        , value: value\n
        , raw: raw\n
      };\n
    }\n
\n
    , tableKey: function(key, value) {\n
      return {\n
          type: \'TableKey\'\n
        , key: key\n
        , value: value\n
      };\n
    }\n
    , tableKeyString: function(key, value) {\n
      return {\n
          type: \'TableKeyString\'\n
        , key: key\n
        , value: value\n
      };\n
    }\n
    , tableValue: function(value) {\n
      return {\n
          type: \'TableValue\'\n
        , value: value\n
      };\n
    }\n
\n
\n
    , tableConstructorExpression: function(fields) {\n
      return {\n
          type: \'TableConstructorExpression\'\n
        , fields: fields\n
      };\n
    }\n
    , binaryExpression: function(operator, left, right) {\n
      var type = (\'and\' === operator || \'or\' === operator) ?\n
        \'LogicalExpression\' :\n
        \'BinaryExpression\';\n
\n
      return {\n
          type: type\n
        , operator: operator\n
        , left: left\n
        , right: right\n
      };\n
    }\n
    , unaryExpression: function(operator, argument) {\n
      return {\n
          type: \'UnaryExpression\'\n
        , operator: operator\n
        , argument: argument\n
      };\n
    }\n
    , memberExpression: function(base, indexer, identifier) {\n
      return {\n
          type: \'MemberExpression\'\n
        , indexer: indexer\n
        , identifier: identifier\n
        , base: base\n
      };\n
    }\n
\n
    , indexExpression: function(base, index) {\n
      return {\n
          type: \'IndexExpression\'\n
        , base: base\n
        , index: index\n
      };\n
    }\n
\n
    , callExpression: function(base, args) {\n
      return {\n
          type: \'CallExpression\'\n
        , base: base\n
        , \'arguments\': args\n
      };\n
    }\n
\n
    , tableCallExpression: function(base, args) {\n
      return {\n
          type: \'TableCallExpression\'\n
        , base: base\n
        , \'arguments\': args\n
      };\n
    }\n
\n
    , stringCallExpression: function(base, argument) {\n
      return {\n
          type: \'StringCallExpression\'\n
        , base: base\n
        , argument: argument\n
      };\n
    }\n
\n
    , comment: function(value, raw) {\n
      return {\n
          type: \'Comment\'\n
        , value: value\n
        , raw: raw\n
      };\n
    }\n
  };\n
\n
  function finishNode(node) {\n
    if (trackLocations) {\n
      var location = locations.pop();\n
      location.complete();\n
      if (options.locations) node.loc = location.loc;\n
      if (options.ranges) node.range = location.range;\n
    }\n
    return node;\n
  }\n
\n
  var slice = Array.prototype.slice\n
    , toString = Object.prototype.toString\n
    , indexOf = function indexOf(array, element) {\n
      for (var i = 0, length = array.length; i < length; i++) {\n
        if (array[i] === element) return i;\n
      }\n
      return -1;\n
    };\n
\n
  function indexOfObject(array, property, element) {\n
    for (var i = 0, length = array.length; i < length; i++) {\n
      if (array[i][property] === element) return i;\n
    }\n
    return -1;\n
  }\n
\n
  function sprintf(format) {\n
    var args = slice.call(arguments, 1);\n
    format = format.replace(/%(\\d)/g, function (match, index) {\n
      return \'\' + args[index - 1] || \'\';\n
    });\n
    return format;\n
  }\n
\n
  function extend() {\n
    var args = slice.call(arguments)\n
      , dest = {}\n
      , src, prop;\n
\n
    for (var i = 0, length = args.length; i < length; i++) {\n
      src = args[i];\n
      for (prop in src) if (src.hasOwnProperty(prop)) {\n
        dest[prop] = src[prop];\n
      }\n
    }\n
    return dest;\n
  }\n
\n
  function raise(token) {\n
    var message = sprintf.apply(null, slice.call(arguments, 1))\n
      , error, col;\n
\n
    if (\'undefined\' !== typeof token.line) {\n
      col = token.range[0] - token.lineStart;\n
      error = new SyntaxError(sprintf(\'[%1:%2] %3\', token.line, col, message));\n
      error.line = token.line;\n
      error.index = token.range[0];\n
      error.column = col;\n
    } else {\n
      col = index - lineStart + 1;\n
      error = new SyntaxError(sprintf(\'[%1:%2] %3\', line, col, message));\n
      error.index = index;\n
      error.line = line;\n
      error.column = col;\n
    }\n
    throw error;\n
  }\n
\n
  function raiseUnexpectedToken(type, token) {\n
    raise(token, errors.expectedToken, type, token.value);\n
  }\n
\n
  function unexpected(found, near) {\n
    if (\'undefined\' === typeof near) near = lookahead.value;\n
    if (\'undefined\' !== typeof found.type) {\n
      var type;\n
      switch (found.type) {\n
        case StringLiteral:   type = \'string\';      break;\n
        case Keyword:         type = \'keyword\';     break;\n
        case Identifier:      type = \'identifier\';  break;\n
        case NumericLiteral:  type = \'number\';      break;\n
        case Punctuator:      type = \'symbol\';      break;\n
        case BooleanLiteral:  type = \'boolean\';     break;\n
        case NilLiteral:\n
          return raise(found, errors.unexpected, \'symbol\', \'nil\', near);\n
      }\n
      return raise(found, errors.unexpected, type, found.value, near);\n
    }\n
    return raise(found, errors.unexpected, \'symbol\', found, near);\n
  }\n
\n
  var index\n
    , token\n
    , previousToken\n
    , lookahead\n
    , comments\n
    , tokenStart\n
    , line\n
    , lineStart;\n
\n
  exports.lex = lex;\n
\n
  function lex() {\n
    skipWhiteSpace();\n
    while (45 === input.charCodeAt(index) &&\n
           45 === input.charCodeAt(index + 1)) {\n
      scanComment();\n
      skipWhiteSpace();\n
    }\n
    if (index >= length) return {\n
        type : EOF\n
      , value: \'<eof>\'\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [index, index]\n
    };\n
\n
    var charCode = input.charCodeAt(index)\n
      , next = input.charCodeAt(index + 1);\n
    tokenStart = index;\n
    if (isIdentifierStart(charCode)) return scanIdentifierOrKeyword();\n
\n
    switch (charCode) {\n
      case 39: case 34: // \'"\n
        return scanStringLiteral();\n
      case 48: case 49: case 50: case 51: case 52: case 53:\n
      case 54: case 55: case 56: case 57:\n
        return scanNumericLiteral();\n
\n
      case 46: // .\n
        if (isDecDigit(next)) return scanNumericLiteral();\n
        if (46 === next) {\n
          if (46 === input.charCodeAt(index + 2)) return scanVarargLiteral();\n
          return scanPunctuator(\'..\');\n
        }\n
        return scanPunctuator(\'.\');\n
\n
      case 61: // =\n
        if (61 === next) return scanPunctuator(\'==\');\n
        return scanPunctuator(\'=\');\n
\n
      case 62: // >\n
        if (61 === next) return scanPunctuator(\'>=\');\n
        return scanPunctuator(\'>\');\n
\n
      case 60: // <\n
        if (61 === next) return scanPunctuator(\'<=\');\n
        return scanPunctuator(\'<\');\n
\n
      case 126: // ~\n
        if (61 === next) return scanPunctuator(\'~=\');\n
        return raise({}, errors.expected, \'=\', \'~\');\n
\n
      case 58: // :\n
        if (58 === next) return scanPunctuator(\'::\');\n
        return scanPunctuator(\':\');\n
\n
      case 91: // [\n
        if (91 === next || 61 === next) return scanLongStringLiteral();\n
        return scanPunctuator(\'[\');\n
      case 42: case 47: case 94: case 37: case 44: case 123: case 125:\n
      case 93: case 40: case 41: case 59: case 35: case 45: case 43:\n
        return scanPunctuator(input.charAt(index));\n
    }\n
\n
    return unexpected(input.charAt(index));\n
  }\n
\n
  function skipWhiteSpace() {\n
    while (index < length) {\n
      var charCode = input.charCodeAt(index);\n
      if (isWhiteSpace(charCode)) {\n
        index++;\n
      } else if (isLineTerminator(charCode)) {\n
        line++;\n
        lineStart = ++index;\n
      } else {\n
        break;\n
      }\n
    }\n
  }\n
\n
  function scanIdentifierOrKeyword() {\n
    var value, type;\n
    while (isIdentifierPart(input.charCodeAt(++index)));\n
    value = input.slice(tokenStart, index);\n
    if (isKeyword(value)) {\n
      type = Keyword;\n
    } else if (\'true\' === value || \'false\' === value) {\n
      type = BooleanLiteral;\n
      value = (\'true\' === value);\n
    } else if (\'nil\' === value) {\n
      type = NilLiteral;\n
      value = null;\n
    } else {\n
      type = Identifier;\n
    }\n
\n
    return {\n
        type: type\n
      , value: value\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function scanPunctuator(value) {\n
    index += value.length;\n
    return {\n
        type: Punctuator\n
      , value: value\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function scanVarargLiteral() {\n
    index += 3;\n
    return {\n
        type: VarargLiteral\n
      , value: \'...\'\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function scanStringLiteral() {\n
    var delimiter = input.charCodeAt(index++)\n
      , stringStart = index\n
      , string = \'\'\n
      , charCode;\n
\n
    while (index < length) {\n
      charCode = input.charCodeAt(index++);\n
      if (delimiter === charCode) break;\n
      if (92 === charCode) { // \\\n
        string += input.slice(stringStart, index - 1) + readEscapeSequence();\n
        stringStart = index;\n
      }\n
      else if (index >= length || isLineTerminator(charCode)) {\n
        string += input.slice(stringStart, index - 1);\n
        raise({}, errors.unfinishedString, string + String.fromCharCode(charCode));\n
      }\n
    }\n
    string += input.slice(stringStart, index - 1);\n
\n
    return {\n
        type: StringLiteral\n
      , value: string\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function scanLongStringLiteral() {\n
    var string = readLongString();\n
    if (false === string) raise(token, errors.expected, \'[\', token.value);\n
\n
    return {\n
        type: StringLiteral\n
      , value: string\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function scanNumericLiteral() {\n
    var character = input.charAt(index)\n
      , next = input.charAt(index + 1);\n
\n
    var value = (\'0\' === character && \'xX\'.indexOf(next || null) >= 0) ?\n
      readHexLiteral() : readDecLiteral();\n
\n
    return {\n
        type: NumericLiteral\n
      , value: value\n
      , line: line\n
      , lineStart: lineStart\n
      , range: [tokenStart, index]\n
    };\n
  }\n
\n
  function readHexLiteral() {\n
    var fraction = 0 // defaults to 0 as it gets summed\n
      , binaryExponent = 1 // defaults to 1 as it gets multiplied\n
      , binarySign = 1 // positive\n
      , digit, fractionStart, exponentStart, digitStart;\n
\n
    digitStart = index += 2; // Skip 0x part\n
    if (!isHexDigit(input.charCodeAt(index)))\n
      raise({}, errors.malformedNumber, input.slice(tokenStart, index));\n
\n
    while (isHexDigit(input.charCodeAt(index))) index++;\n
    digit = parseInt(input.slice(digitStart, index), 16);\n
    if (\'.\' === input.charAt(index)) {\n
      fractionStart = ++index;\n
\n
      while (isHexDigit(input.charCodeAt(index))) index++;\n
      fraction = input.slice(fractionStart, index);\n
      fraction = (fractionStart === index) ? 0\n
        : parseInt(fraction, 16) / Math.pow(16, index - fractionStart);\n
    }\n
    if (\'pP\'.indexOf(input.charAt(index) || null) >= 0) {\n
      index++;\n
      if (\'+-\'.indexOf(input.charAt(index) || null) >= 0)\n
        binarySign = (\'+\' === input.charAt(index++)) ? 1 : -1;\n
\n
      exponentStart = index;\n
      if (!isDecDigit(input.charCodeAt(index)))\n
        raise({}, errors.malformedNumber, input.slice(tokenStart, index));\n
\n
      while (isDecDigit(input.charCodeAt(index))) index++;\n
      binaryExponent = input.slice(exponentStart, index);\n
      binaryExponent = Math.pow(2, binaryExponent * binarySign);\n
    }\n
\n
    return (digit + fraction) * binaryExponent;\n
  }\n
\n
  function readDecLiteral() {\n
    while (isDecDigit(input.charCodeAt(index))) index++;\n
    if (\'.\' === input.charAt(index)) {\n
      index++;\n
      while (isDecDigit(input.charCodeAt(index))) index++;\n
    }\n
    if (\'eE\'.indexOf(input.charAt(index) || null) >= 0) {\n
      index++;\n
      if (\'+-\'.indexOf(input.charAt(index) || null) >= 0) index++;\n
      if (!isDecDigit(input.charCodeAt(index)))\n
        raise({}, errors.malformedNumber, input.slice(tokenStart, index));\n
\n
      while (isDecDigit(input.charCodeAt(index))) index++;\n
    }\n
\n
    return parseFloat(input.slice(tokenStart, index));\n
  }\n
\n
  function readEscapeSequence() {\n
    var sequenceStart = index;\n
    switch (input.charAt(index)) {\n
      case \'n\': index++; return \'\\n\';\n
      case \'r\': index++; return \'\\r\';\n
      case \'t\': index++; return \'\\t\';\n
      case \'v\': index++; return \'\\x0B\';\n
      case \'b\': index++; return \'\\b\';\n
      case \'f\': index++; return \'\\f\';\n
      case \'z\': index++; skipWhiteSpace(); return \'\';\n
      case \'x\':\n
        if (isHexDigit(input.charCodeAt(index + 1)) &&\n
            isHexDigit(input.charCodeAt(index + 2))) {\n
          index += 3;\n
          return \'\\\\\' + input.slice(sequenceStart, index);\n
        }\n
        return \'\\\\\' + input.charAt(index++);\n
      default:\n
        if (isDecDigit(input.charCodeAt(index))) {\n
          while (isDecDigit(input.charCodeAt(++index)));\n
          return \'\\\\\' + input.slice(sequenceStart, index);\n
        }\n
        return input.charAt(index++);\n
    }\n
  }\n
\n
  function scanComment() {\n
    tokenStart = index;\n
    index += 2; // --\n
\n
    var character = input.charAt(index)\n
      , content = \'\'\n
      , isLong = false\n
      , commentStart = index\n
      , lineStartComment = lineStart\n
      , lineComment = line;\n
\n
    if (\'[\' === character) {\n
      content = readLongString();\n
      if (false === content) content = character;\n
      else isLong = true;\n
    }\n
    if (!isLong) {\n
      while (index < length) {\n
        if (isLineTerminator(input.charCodeAt(index))) break;\n
        index++;\n
      }\n
      if (options.comments) content = input.slice(commentStart, index);\n
    }\n
\n
    if (options.comments) {\n
      var node = ast.comment(content, input.slice(tokenStart, index));\n
      if (options.locations) {\n
        node.loc = {\n
            start: { line: lineComment, column: tokenStart - lineStartComment }\n
          , end: { line: line, column: index - lineStart }\n
        };\n
      }\n
      if (options.ranges) {\n
        node.range = [tokenStart, index];\n
      }\n
      comments.push(node);\n
    }\n
  }\n
\n
  function readLongString() {\n
    var level = 0\n
      , content = \'\'\n
      , terminator = false\n
      , character, stringStart;\n
\n
    index++; // [\n
    while (\'=\' === input.charAt(index + level)) level++;\n
    if (\'[\' !== input.charAt(index + level)) return false;\n
\n
    index += level + 1;\n
    if (isLineTerminator(input.charCodeAt(index))) {\n
      line++;\n
      lineStart = index++;\n
    }\n
\n
    stringStart = index;\n
    while (index < length) {\n
      character = input.charAt(index++);\n
      if (isLineTerminator(character.charCodeAt(0))) {\n
        line++;\n
        lineStart = index;\n
      }\n
      if (\']\' === character) {\n
        terminator = true;\n
        for (var i = 0; i < level; i++) {\n
          if (\'=\' !== input.charAt(index + i)) terminator = false;\n
        }\n
        if (\']\' !== input.charAt(index + level)) terminator = false;\n
      }\n
      if (terminator) break;\n
    }\n
    content += input.slice(stringStart, index - 1);\n
    index += level + 1;\n
\n
    return content;\n
  }\n
\n
  function next() {\n
    previousToken = token;\n
    token = lookahead;\n
    lookahead = lex();\n
  }\n
\n
  function consume(value) {\n
    if (value === token.value) {\n
      next();\n
      return true;\n
    }\n
    return false;\n
  }\n
\n
  function expect(value) {\n
    if (value === token.value) next();\n
    else raise(token, errors.expected, value, token.value);\n
  }\n
\n
  function isWhiteSpace(charCode) {\n
    return 9 === charCode || 32 === charCode || 0xB === charCode || 0xC === charCode;\n
  }\n
\n
  function isLineTerminator(charCode) {\n
    return 10 === charCode || 13 === charCode;\n
  }\n
\n
  function isDecDigit(charCode) {\n
    return charCode >= 48 && charCode <= 57;\n
  }\n
\n
  function isHexDigit(charCode) {\n
    return (charCode >= 48 && charCode <= 57) || (charCode >= 97 && charCode <= 102) || (charCode >= 65 && charCode <= 70);\n
  }\n
\n
  function isIdentifierStart(charCode) {\n
    return (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122) || 95 === charCode;\n
  }\n
\n
  function isIdentifierPart(charCode) {\n
    return (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122) || 95 === charCode || (charCode >= 48 && charCode <= 57);\n
  }\n
\n
  function isKeyword(id) {\n
    switch (id.length) {\n
      case 2:\n
        return \'do\' === id || \'if\' === id || \'in\' === id || \'or\' === id;\n
      case 3:\n
        return \'and\' === id || \'end\' === id || \'for\' === id || \'not\' === id;\n
      case 4:\n
        return \'else\' === id || \'goto\' === id || \'then\' === id;\n
      case 5:\n
        return \'break\' === id || \'local\' === id || \'until\' === id || \'while\' === id;\n
      case 6:\n
        return \'elseif\' === id || \'repeat\' === id || \'return\' === id;\n
      case 8:\n
        return \'function\' === id;\n
    }\n
    return false;\n
  }\n
\n
  function isUnary(token) {\n
    if (Punctuator === token.type) return \'#-\'.indexOf(token.value) >= 0;\n
    if (Keyword === token.type) return \'not\' === token.value;\n
    return false;\n
  }\n
  function isCallExpression(expression) {\n
    switch (expression.type) {\n
      case \'CallExpression\':\n
      case \'TableCallExpression\':\n
      case \'StringCallExpression\':\n
        return true;\n
    }\n
    return false;\n
  }\n
\n
  function isBlockFollow(token) {\n
    if (EOF === token.type) return true;\n
    if (Keyword !== token.type) return false;\n
    switch (token.value) {\n
      case \'else\': case \'elseif\':\n
      case \'end\': case \'until\':\n
        return true;\n
      default:\n
        return false;\n
    }\n
  }\n
  var scopes\n
    , scopeDepth\n
    , globals;\n
  function createScope() {\n
    scopes.push(Array.apply(null, scopes[scopeDepth++]));\n
  }\n
  function exitScope() {\n
    scopes.pop();\n
    scopeDepth--;\n
  }\n
  function scopeIdentifierName(name) {\n
    if (-1 !== indexOf(scopes[scopeDepth], name)) return;\n
    scopes[scopeDepth].push(name);\n
  }\n
  function scopeIdentifier(node) {\n
    scopeIdentifierName(node.name);\n
    attachScope(node, true);\n
  }\n
  function attachScope(node, isLocal) {\n
    if (!isLocal && -1 === indexOfObject(globals, \'name\', node.name))\n
      globals.push(node);\n
\n
    node.isLocal = isLocal;\n
  }\n
  function scopeHasName(name) {\n
    return (-1 !== indexOf(scopes[scopeDepth], name));\n
  }\n
\n
  var locations = []\n
    , trackLocations;\n
\n
  function createLocationMarker() {\n
    return new Marker(token);\n
  }\n
\n
  function Marker(token) {\n
    if (options.locations) {\n
      this.loc = {\n
          start: {\n
            line: token.line\n
          , column: token.range[0] - token.lineStart\n
        }\n
        , end: {\n
            line: 0\n
          , column: 0\n
        }\n
      };\n
    }\n
    if (options.ranges) this.range = [token.range[0], 0];\n
  }\n
  Marker.prototype.complete = function() {\n
    if (options.locations) {\n
      this.loc.end.line = previousToken.line;\n
      this.loc.end.column = previousToken.range[1] - previousToken.lineStart;\n
    }\n
    if (options.ranges) {\n
      this.range[1] = previousToken.range[1];\n
    }\n
  };\n
  function markLocation() {\n
    if (trackLocations) locations.push(createLocationMarker());\n
  }\n
  function pushLocation(marker) {\n
    if (trackLocations) locations.push(marker);\n
  }\n
\n
  function parseChunk() {\n
    next();\n
    markLocation();\n
    var body = parseBlock();\n
    if (EOF !== token.type) unexpected(token);\n
    if (trackLocations && !body.length) previousToken = token;\n
    return finishNode(ast.chunk(body));\n
  }\n
\n
  function parseBlock(terminator) {\n
    var block = []\n
      , statement;\n
    if (options.scope) createScope();\n
\n
    while (!isBlockFollow(token)) {\n
      if (\'return\' === token.value) {\n
        block.push(parseStatement());\n
        break;\n
      }\n
      statement = parseStatement();\n
      if (statement) block.push(statement);\n
    }\n
\n
    if (options.scope) exitScope();\n
    return block;\n
  }\n
\n
  function parseStatement() {\n
    markLocation();\n
    if (Keyword === token.type) {\n
      switch (token.value) {\n
        case \'local\':    next(); return parseLocalStatement();\n
        case \'if\':       next(); return parseIfStatement();\n
        case \'return\':   next(); return parseReturnStatement();\n
        case \'function\': next();\n
          var name = parseFunctionName();\n
          return parseFunctionDeclaration(name);\n
        case \'while\':    next(); return parseWhileStatement();\n
        case \'for\':      next(); return parseForStatement();\n
        case \'repeat\':   next(); return parseRepeatStatement();\n
        case \'break\':    next(); return parseBreakStatement();\n
        case \'do\':       next(); return parseDoStatement();\n
        case \'goto\':     next(); return parseGotoStatement();\n
      }\n
    }\n
\n
    if (Punctuator === token.type) {\n
      if (consume(\'::\')) return parseLabelStatement();\n
    }\n
    if (trackLocations) locations.pop();\n
    if (consume(\';\')) return;\n
\n
    return parseAssignmentOrCallStatement();\n
  }\n
\n
  function parseLabelStatement() {\n
    var name = token.value\n
      , label = parseIdentifier();\n
\n
    if (options.scope) {\n
      scopeIdentifierName(\'::\' + name + \'::\');\n
      attachScope(label, true);\n
    }\n
\n
    expect(\'::\');\n
    return finishNode(ast.labelStatement(label));\n
  }\n
\n
  function parseBreakStatement() {\n
    return finishNode(ast.breakStatement());\n
  }\n
\n
  function parseGotoStatement() {\n
    var name = token.value\n
      , label = parseIdentifier();\n
\n
    if (options.scope) label.isLabel = scopeHasName(\'::\' + name + \'::\');\n
    return finishNode(ast.gotoStatement(label));\n
  }\n
\n
  function parseDoStatement() {\n
    var body = parseBlock();\n
    expect(\'end\');\n
    return finishNode(ast.doStatement(body));\n
  }\n
\n
  function parseWhileStatement() {\n
    var condition = parseExpectedExpression();\n
    expect(\'do\');\n
    var body = parseBlock();\n
    expect(\'end\');\n
    return finishNode(ast.whileStatement(condition, body));\n
  }\n
\n
  function parseRepeatStatement() {\n
    var body = parseBlock();\n
    expect(\'until\');\n
    var condition = parseExpectedExpression();\n
    return finishNode(ast.repeatStatement(condition, body));\n
  }\n
\n
  function parseReturnStatement() {\n
    var expressions = [];\n
\n
    if (\'end\' !== token.value) {\n
      var expression = parseExpression();\n
      if (null != expression) expressions.push(expression);\n
      while (consume(\',\')) {\n
        expression = parseExpectedExpression();\n
        expressions.push(expression);\n
      }\n
      consume(\';\'); // grammar tells us ; is optional here.\n
    }\n
    return finishNode(ast.returnStatement(expressions));\n
  }\n
\n
  function parseIfStatement() {\n
    var clauses = []\n
      , condition\n
      , body\n
      , marker;\n
    if (trackLocations) {\n
      marker = locations[locations.length - 1];\n
      locations.push(marker);\n
    }\n
    condition = parseExpectedExpression();\n
    expect(\'then\');\n
    body = parseBlock();\n
    clauses.push(finishNode(ast.ifClause(condition, body)));\n
\n
    if (trackLocations) marker = createLocationMarker();\n
    while (consume(\'elseif\')) {\n
      pushLocation(marker);\n
      condition = parseExpectedExpression();\n
      expect(\'then\');\n
      body = parseBlock();\n
      clauses.push(finishNode(ast.elseifClause(condition, body)));\n
      if (trackLocations) marker = createLocationMarker();\n
    }\n
\n
    if (consume(\'else\')) {\n
      if (trackLocations) {\n
        marker = new Marker(previousToken);\n
        locations.push(marker);\n
      }\n
      body = parseBlock();\n
      clauses.push(finishNode(ast.elseClause(body)));\n
    }\n
\n
    expect(\'end\');\n
    return finishNode(ast.ifStatement(clauses));\n
  }\n
\n
  function parseForStatement() {\n
    var variable = parseIdentifier()\n
      , body;\n
    if (options.scope) scopeIdentifier(variable);\n
    if (consume(\'=\')) {\n
      var start = parseExpectedExpression();\n
      expect(\',\');\n
      var end = parseExpectedExpression();\n
      var step = consume(\',\') ? parseExpectedExpression() : null;\n
\n
      expect(\'do\');\n
      body = parseBlock();\n
      expect(\'end\');\n
\n
      return finishNode(ast.forNumericStatement(variable, start, end, step, body));\n
    }\n
    else {\n
      var variables = [variable];\n
      while (consume(\',\')) {\n
        variable = parseIdentifier();\n
        if (options.scope) scopeIdentifier(variable);\n
        variables.push(variable);\n
      }\n
      expect(\'in\');\n
      var iterators = [];\n
      do {\n
        var expression = parseExpectedExpression();\n
        iterators.push(expression);\n
      } while (consume(\',\'));\n
\n
      expect(\'do\');\n
      body = parseBlock();\n
      expect(\'end\');\n
\n
      return finishNode(ast.forGenericStatement(variables, iterators, body));\n
    }\n
  }\n
\n
  function parseLocalStatement() {\n
    var name;\n
\n
    if (Identifier === token.type) {\n
      var variables = []\n
        , init = [];\n
\n
      do {\n
        name = parseIdentifier();\n
\n
        variables.push(name);\n
      } while (consume(\',\'));\n
\n
      if (consume(\'=\')) {\n
        do {\n
          var expression = parseExpectedExpression();\n
          init.push(expression);\n
        } while (consume(\',\'));\n
      }\n
      if (options.scope) {\n
        for (var i = 0, l = variables.length; i < l; i++) {\n
          scopeIdentifier(variables[i]);\n
        }\n
      }\n
\n
      return finishNode(ast.localStatement(variables, init));\n
    }\n
    if (consume(\'function\')) {\n
      name = parseIdentifier();\n
      if (options.scope) scopeIdentifier(name);\n
      return parseFunctionDeclaration(name, true);\n
    } else {\n
      raiseUnexpectedToken(\'<name>\', token);\n
    }\n
  }\n
\n
  function parseAssignmentOrCallStatement() {\n
    var previous = token\n
      , expression, marker;\n
\n
    if (trackLocations) marker = createLocationMarker();\n
    expression = parsePrefixExpression();\n
\n
    if (null == expression) return unexpected(token);\n
    if (\',=\'.indexOf(token.value) >= 0) {\n
      var variables = [expression]\n
        , init = []\n
        , exp;\n
\n
      while (consume(\',\')) {\n
        exp = parsePrefixExpression();\n
        if (null == exp) raiseUnexpectedToken(\'<expression>\', token);\n
        variables.push(exp);\n
      }\n
      expect(\'=\');\n
      do {\n
        exp = parseExpectedExpression();\n
        init.push(exp);\n
      } while (consume(\',\'));\n
\n
      pushLocation(marker);\n
      return finishNode(ast.assignmentStatement(variables, init));\n
    }\n
    if (isCallExpression(expression)) {\n
      pushLocation(marker);\n
      return finishNode(ast.callStatement(expression));\n
    }\n
    return unexpected(previous);\n
  }\n
\n
  function parseIdentifier() {\n
    markLocation();\n
    var identifier = token.value;\n
    if (Identifier !== token.type) raiseUnexpectedToken(\'<name>\', token);\n
    next();\n
    return finishNode(ast.identifier(identifier));\n
  }\n
\n
  function parseFunctionDeclaration(name, isLocal) {\n
    var parameters = [];\n
    expect(\'(\');\n
    if (!consume(\')\')) {\n
      while (true) {\n
        if (Identifier === token.type) {\n
          var parameter = parseIdentifier();\n
          if (options.scope) scopeIdentifier(parameter);\n
\n
          parameters.push(parameter);\n
\n
          if (consume(\',\')) continue;\n
          else if (consume(\')\')) break;\n
        }\n
        else if (VarargLiteral === token.type) {\n
          parameters.push(parsePrimaryExpression());\n
          expect(\')\');\n
          break;\n
        } else {\n
          raiseUnexpectedToken(\'<name> or \\\'...\\\'\', token);\n
        }\n
      }\n
    }\n
\n
    var body = parseBlock();\n
    expect(\'end\');\n
\n
    isLocal = isLocal || false;\n
    return finishNode(ast.functionStatement(name, parameters, isLocal, body));\n
  }\n
\n
  function parseFunctionName() {\n
    var base, name, marker;\n
\n
    if (trackLocations) marker = createLocationMarker();\n
    base = parseIdentifier();\n
\n
    if (options.scope) attachScope(base, false);\n
\n
    while (consume(\'.\')) {\n
      pushLocation(marker);\n
      name = parseIdentifier();\n
      if (options.scope) attachScope(name, false);\n
      base = finishNode(ast.memberExpression(base, \'.\', name));\n
    }\n
\n
    if (consume(\':\')) {\n
      pushLocation(marker);\n
      name = parseIdentifier();\n
      if (options.scope) attachScope(name, false);\n
      base = finishNode(ast.memberExpression(base, \':\', name));\n
    }\n
\n
    return base;\n
  }\n
\n
  function parseTableConstructor() {\n
    var fields = []\n
      , key, value;\n
\n
    while (true) {\n
      markLocation();\n
      if (Punctuator === token.type && consume(\'[\')) {\n
        key = parseExpectedExpression();\n
        expect(\']\');\n
        expect(\'=\');\n
        value = parseExpectedExpression();\n
        fields.push(finishNode(ast.tableKey(key, value)));\n
      } else if (Identifier === token.type) {\n
        key = parseExpectedExpression();\n
        if (consume(\'=\')) {\n
          value = parseExpectedExpression();\n
          fields.push(finishNode(ast.tableKeyString(key, value)));\n
        } else {\n
          fields.push(finishNode(ast.tableValue(key)));\n
        }\n
      } else {\n
        if (null == (value = parseExpression())) {\n
          locations.pop();\n
          break;\n
        }\n
        fields.push(finishNode(ast.tableValue(value)));\n
      }\n
      if (\',;\'.indexOf(token.value) >= 0) {\n
        next();\n
        continue;\n
      }\n
      if (\'}\' === token.value) break;\n
    }\n
    expect(\'}\');\n
    return finishNode(ast.tableConstructorExpression(fields));\n
  }\n
\n
  function parseExpression() {\n
    var expression = parseSubExpression(0);\n
    return expression;\n
  }\n
\n
  function parseExpectedExpression() {\n
    var expression = parseExpression();\n
    if (null == expression) raiseUnexpectedToken(\'<expression>\', token);\n
    else return expression;\n
  }\n
\n
  function binaryPrecedence(operator) {\n
    var charCode = operator.charCodeAt(0)\n
      , length = operator.length;\n
\n
    if (1 === length) {\n
      switch (charCode) {\n
        case 94: return 10; // ^\n
        case 42: case 47: case 37: return 7; // * / %\n
        case 43: case 45: return 6; // + -\n
        case 60: case 62: return 3; // < >\n
      }\n
    } else if (2 === length) {\n
      switch (charCode) {\n
        case 46: return 5; // ..\n
        case 60: case 62: case 61: case 126: return 3; // <= >= == ~=\n
        case 111: return 1; // or\n
      }\n
    } else if (97 === charCode && \'and\' === operator) return 2;\n
    return 0;\n
  }\n
\n
  function parseSubExpression(minPrecedence) {\n
    var operator = token.value\n
      , expression, marker;\n
\n
    if (trackLocations) marker = createLocationMarker();\n
    if (isUnary(token)) {\n
      markLocation();\n
      next();\n
      var argument = parseSubExpression(8);\n
      if (argument == null) raiseUnexpectedToken(\'<expression>\', token);\n
      expression = finishNode(ast.unaryExpression(operator, argument));\n
    }\n
    if (null == expression) {\n
      expression = parsePrimaryExpression();\n
      if (null == expression) {\n
        expression = parsePrefixExpression();\n
      }\n
    }\n
    if (null == expression) return null;\n
\n
    var precedence;\n
    while (true) {\n
      operator = token.value;\n
\n
      precedence = (Punctuator === token.type || Keyword === token.type) ?\n
        binaryPrecedence(operator) : 0;\n
\n
      if (precedence === 0 || precedence <= minPrecedence) break;\n
      if (\'^\' === operator || \'..\' === operator) precedence--;\n
      next();\n
      var right = parseSubExpression(precedence);\n
      if (null == right) raiseUnexpectedToken(\'<expression>\', token);\n
      if (trackLocations) locations.push(marker);\n
      expression = finishNode(ast.binaryExpression(operator, expression, right));\n
\n
    }\n
    return expression;\n
  }\n
\n
  function parsePrefixExpression() {\n
    var base, name, marker\n
      , isLocal;\n
\n
    if (trackLocations) marker = createLocationMarker();\n
    if (Identifier === token.type) {\n
      name = token.value;\n
      base = parseIdentifier();\n
      if (options.scope) attachScope(base, isLocal = scopeHasName(name));\n
    } else if (consume(\'(\')) {\n
      base = parseExpectedExpression();\n
      expect(\')\');\n
      if (options.scope) isLocal = base.isLocal;\n
    } else {\n
      return null;\n
    }\n
    var expression, identifier;\n
    while (true) {\n
      if (Punctuator === token.type) {\n
        switch (token.value) {\n
          case \'[\':\n
            pushLocation(marker);\n
            next();\n
            expression = parseExpectedExpression();\n
            base = finishNode(ast.indexExpression(base, expression));\n
            expect(\']\');\n
            break;\n
          case \'.\':\n
            pushLocation(marker);\n
            next();\n
            identifier = parseIdentifier();\n
            if (options.scope) attachScope(identifier, isLocal);\n
            base = finishNode(ast.memberExpression(base, \'.\', identifier));\n
            break;\n
          case \':\':\n
            pushLocation(marker);\n
            next();\n
            identifier = parseIdentifier();\n
            if (options.scope) attachScope(identifier, isLocal);\n
            base = finishNode(ast.memberExpression(base, \':\', identifier));\n
            pushLocation(marker);\n
            base = parseCallExpression(base);\n
            break;\n
          case \'(\': case \'{\': // args\n
            pushLocation(marker);\n
            base = parseCallExpression(base);\n
            break;\n
          default:\n
            return base;\n
        }\n
      } else if (StringLiteral === token.type) {\n
        pushLocation(marker);\n
        base = parseCallExpression(base);\n
      } else {\n
        break;\n
      }\n
    }\n
\n
    return base;\n
  }\n
\n
  function parseCallExpression(base) {\n
    if (Punctuator === token.type) {\n
      switch (token.value) {\n
        case \'(\':\n
          next();\n
          var expressions = [];\n
          var expression = parseExpression();\n
          if (null != expression) expressions.push(expression);\n
          while (consume(\',\')) {\n
            expression = parseExpectedExpression();\n
            expressions.push(expression);\n
          }\n
\n
          expect(\')\');\n
          return finishNode(ast.callExpression(base, expressions));\n
\n
        case \'{\':\n
          markLocation();\n
          next();\n
          var table = parseTableConstructor();\n
          return finishNode(ast.tableCallExpression(base, table));\n
      }\n
    } else if (StringLiteral === token.type) {\n
      return finishNode(ast.stringCallExpression(base, parsePrimaryExpression()));\n
    }\n
\n
    raiseUnexpectedToken(\'function arguments\', token);\n
  }\n
\n
  function parsePrimaryExpression() {\n
    var literals = StringLiteral | NumericLiteral | BooleanLiteral | NilLiteral | VarargLiteral\n
      , value = token.value\n
      , type = token.type\n
      , marker;\n
\n
    if (trackLocations) marker = createLocationMarker();\n
\n
    if (type & literals) {\n
      pushLocation(marker);\n
      var raw = input.slice(token.range[0], token.range[1]);\n
      next();\n
      return finishNode(ast.literal(type, value, raw));\n
    } else if (Keyword === type && \'function\' === value) {\n
      pushLocation(marker);\n
      next();\n
      return parseFunctionDeclaration(null);\n
    } else if (consume(\'{\')) {\n
      pushLocation(marker);\n
      return parseTableConstructor();\n
    }\n
  }\n
\n
  exports.parse = parse;\n
\n
  function parse(_input, _options) {\n
    if (\'undefined\' === typeof _options && \'object\' === typeof _input) {\n
      _options = _input;\n
      _input = undefined;\n
    }\n
    if (!_options) _options = {};\n
\n
    input = _input || \'\';\n
    options = extend(defaultOptions, _options);\n
    index = 0;\n
    line = 1;\n
    lineStart = 0;\n
    length = input.length;\n
    scopes = [[]];\n
    scopeDepth = 0;\n
    globals = [];\n
    locations = [];\n
\n
    if (options.comments) comments = [];\n
    if (!options.wait) return end();\n
    return exports;\n
  }\n
  exports.write = write;\n
\n
  function write(_input) {\n
    input += String(_input);\n
    length = input.length;\n
    return exports;\n
  }\n
  exports.end = end;\n
\n
  function end(_input) {\n
    if (\'undefined\' !== typeof _input) write(_input);\n
\n
    length = input.length;\n
    trackLocations = options.locations || options.ranges;\n
    lookahead = lex();\n
\n
    var chunk = parseChunk();\n
    if (options.comments) chunk.comments = comments;\n
    if (options.scope) chunk.globals = globals;\n
\n
    if (locations.length > 0)\n
      throw new Error(\'Location tracking failed. This is most likely a bug in luaparse\');\n
\n
    return chunk;\n
  }\n
\n
}));\n
\n
});

]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
