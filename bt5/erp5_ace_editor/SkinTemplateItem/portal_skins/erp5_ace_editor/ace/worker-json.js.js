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
            <value> <string>ts83646620.5</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>worker-json.js</string> </value>
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
            <value> <int>67205</int> </value>
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
define(\'ace/mode/json_worker\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/worker/mirror\', \'ace/mode/json/json_parse\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var Mirror = require("../worker/mirror").Mirror;\n
var parse = require("./json/json_parse");\n
\n
var JsonWorker = exports.JsonWorker = function(sender) {\n
    Mirror.call(this, sender);\n
    this.setTimeout(200);\n
};\n
\n
oop.inherits(JsonWorker, Mirror);\n
\n
(function() {\n
\n
    this.onUpdate = function() {\n
        var value = this.doc.getValue();\n
\n
        try {\n
            var result = parse(value);\n
        } catch (e) {\n
            var pos = this.doc.indexToPosition(e.at-1);\n
            this.sender.emit("error", {\n
                row: pos.row,\n
                column: pos.column,\n
                text: e.message,\n
                type: "error"\n
            });\n
            return;\n
        }\n
        this.sender.emit("ok");\n
    };\n
\n
}).call(JsonWorker.prototype);\n
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
\n
define(\'ace/mode/json/json_parse\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
    var at,     // The index of the current character\n
        ch,     // The current character\n
        escapee = {\n
            \'"\':  \'"\',\n
            \'\\\\\': \'\\\\\',\n
            \'/\':  \'/\',\n
            b:    \'\\b\',\n
            f:    \'\\f\',\n
            n:    \'\\n\',\n
            r:    \'\\r\',\n
            t:    \'\\t\'\n
        },\n
        text,\n
\n
        error = function (m) {\n
\n
            throw {\n
                name:    \'SyntaxError\',\n
                message: m,\n
                at:      at,\n
                text:    text\n
            };\n
        },\n
\n
        next = function (c) {\n
\n
            if (c && c !== ch) {\n
                error("Expected \'" + c + "\' instead of \'" + ch + "\'");\n
            }\n
\n
            ch = text.charAt(at);\n
            at += 1;\n
            return ch;\n
        },\n
\n
        number = function () {\n
\n
            var number,\n
                string = \'\';\n
\n
            if (ch === \'-\') {\n
                string = \'-\';\n
                next(\'-\');\n
            }\n
            while (ch >= \'0\' && ch <= \'9\') {\n
                string += ch;\n
                next();\n
            }\n
            if (ch === \'.\') {\n
                string += \'.\';\n
                while (next() && ch >= \'0\' && ch <= \'9\') {\n
                    string += ch;\n
                }\n
            }\n
            if (ch === \'e\' || ch === \'E\') {\n
                string += ch;\n
                next();\n
                if (ch === \'-\' || ch === \'+\') {\n
                    string += ch;\n
                    next();\n
                }\n
                while (ch >= \'0\' && ch <= \'9\') {\n
                    string += ch;\n
                    next();\n
                }\n
            }\n
            number = +string;\n
            if (isNaN(number)) {\n
                error("Bad number");\n
            } else {\n
                return number;\n
            }\n
        },\n
\n
        string = function () {\n
\n
            var hex,\n
                i,\n
                string = \'\',\n
                uffff;\n
\n
            if (ch === \'"\') {\n
                while (next()) {\n
                    if (ch === \'"\') {\n
                        next();\n
                        return string;\n
                    } else if (ch === \'\\\\\') {\n
                        next();\n
                        if (ch === \'u\') {\n
                            uffff = 0;\n
                            for (i = 0; i < 4; i += 1) {\n
                                hex = parseInt(next(), 16);\n
                                if (!isFinite(hex)) {\n
                                    break;\n
                                }\n
                                uffff = uffff * 16 + hex;\n
                            }\n
                            string += String.fromCharCode(uffff);\n
                        } else if (typeof escapee[ch] === \'string\') {\n
                            string += escapee[ch];\n
                        } else {\n
                            break;\n
                        }\n
                    } else {\n
                        string += ch;\n
                    }\n
                }\n
            }\n
            error("Bad string");\n
        },\n
\n
        white = function () {\n
\n
            while (ch && ch <= \' \') {\n
                next();\n
            }\n
        },\n
\n
        word = function () {\n
\n
            switch (ch) {\n
            case \'t\':\n
                next(\'t\');\n
                next(\'r\');\n
                next(\'u\');\n
                next(\'e\');\n
                return true;\n
            case \'f\':\n
                next(\'f\');\n
                next(\'a\');\n
                next(\'l\');\n
                next(\'s\');\n
                next(\'e\');\n
                return false;\n
            case \'n\':\n
                next(\'n\');\n
                next(\'u\');\n
                next(\'l\');\n
                next(\'l\');\n
                return null;\n
            }\n
            error("Unexpected \'" + ch + "\'");\n
        },\n
\n
        value,  // Place holder for the value function.\n
\n
        array = function () {\n
\n
            var array = [];\n
\n
            if (ch === \'[\') {\n
                next(\'[\');\n
                white();\n
                if (ch === \']\') {\n
                    next(\']\');\n
                    return array;   // empty array\n
                }\n
                while (ch) {\n
                    array.push(value());\n
                    white();\n
                    if (ch === \']\') {\n
                        next(\']\');\n
                        return array;\n
                    }\n
                    next(\',\');\n
                    white();\n
                }\n
            }\n
            error("Bad array");\n
        },\n
\n
        object = function () {\n
\n
            var key,\n
                object = {};\n
\n
            if (ch === \'{\') {\n
                next(\'{\');\n
                white();\n
                if (ch === \'}\') {\n
                    next(\'}\');\n
                    return object;   // empty object\n
                }\n
                while (ch) {\n
                    key = string();\n
                    white();\n
                    next(\':\');\n
                    if (Object.hasOwnProperty.call(object, key)) {\n
                        error(\'Duplicate key "\' + key + \'"\');\n
                    }\n
                    object[key] = value();\n
                    white();\n
                    if (ch === \'}\') {\n
                        next(\'}\');\n
                        return object;\n
                    }\n
                    next(\',\');\n
                    white();\n
                }\n
            }\n
            error("Bad object");\n
        };\n
\n
    value = function () {\n
\n
        white();\n
        switch (ch) {\n
        case \'{\':\n
            return object();\n
        case \'[\':\n
            return array();\n
        case \'"\':\n
            return string();\n
        case \'-\':\n
            return number();\n
        default:\n
            return ch >= \'0\' && ch <= \'9\' ? number() : word();\n
        }\n
    };\n
\n
    return function (source, reviver) {\n
        var result;\n
\n
        text = source;\n
        at = 0;\n
        ch = \' \';\n
        result = value();\n
        white();\n
        if (ch) {\n
            error("Syntax error");\n
        }\n
\n
        return typeof reviver === \'function\' ? function walk(holder, key) {\n
            var k, v, value = holder[key];\n
            if (value && typeof value === \'object\') {\n
                for (k in value) {\n
                    if (Object.hasOwnProperty.call(value, k)) {\n
                        v = walk(value, k);\n
                        if (v !== undefined) {\n
                            value[k] = v;\n
                        } else {\n
                            delete value[k];\n
                        }\n
                    }\n
                }\n
            }\n
            return reviver.call(holder, key, value);\n
        }({\'\': result}, \'\') : result;\n
    };\n
});\n


]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
