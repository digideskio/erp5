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
            <value> <string>ts83646620.53</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>worker-javascript.js</string> </value>
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
            <value> <int>262743</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>worker-javascript.js</string> </value>
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
define(\'ace/mode/javascript_worker\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/worker/mirror\', \'ace/mode/javascript/jshint\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var Mirror = require("../worker/mirror").Mirror;\n
var lint = require("./javascript/jshint").JSHINT;\n
\n
function startRegex(arr) {\n
    return RegExp("^(" + arr.join("|") + ")");\n
}\n
\n
var disabledWarningsRe = startRegex([\n
    "Bad for in variable \'(.+)\'.",\n
    \'Missing "use strict"\'\n
]);\n
var errorsRe = startRegex([\n
    "Unexpected",\n
    "Expected ",\n
    "Confusing (plus|minus)",\n
    "\\\\{a\\\\} unterminated regular expression",\n
    "Unclosed ",\n
    "Unmatched ",\n
    "Unbegun comment",\n
    "Bad invocation",\n
    "Missing space after",\n
    "Missing operator at"\n
]);\n
var infoRe = startRegex([\n
    "Expected an assignment",\n
    "Bad escapement of EOL",\n
    "Unexpected comma",\n
    "Unexpected space",\n
    "Missing radix parameter.",\n
    "A leading decimal point can",\n
    "\\\\[\'{a}\'\\\\] is better written in dot notation.",\n
    "\'{a}\' used out of scope"\n
]);\n
\n
var JavaScriptWorker = exports.JavaScriptWorker = function(sender) {\n
    Mirror.call(this, sender);\n
    this.setTimeout(500);\n
    this.setOptions();\n
};\n
\n
oop.inherits(JavaScriptWorker, Mirror);\n
\n
(function() {\n
    this.setOptions = function(options) {\n
        this.options = options || {\n
            esnext: true,\n
            moz: true,\n
            devel: true,\n
            browser: true,\n
            node: true,\n
            laxcomma: true,\n
            laxbreak: true,\n
            lastsemic: true,\n
            onevar: false,\n
            passfail: false,\n
            maxerr: 100,\n
            expr: true,\n
            multistr: true,\n
            globalstrict: true\n
        };\n
        this.doc.getValue() && this.deferredUpdate.schedule(100);\n
    };\n
\n
    this.changeOptions = function(newOptions) {\n
        oop.mixin(this.options, newOptions);\n
        this.doc.getValue() && this.deferredUpdate.schedule(100);\n
    };\n
\n
    this.isValidJS = function(str) {\n
        try {\n
            eval("throw 0;" + str);\n
        } catch(e) {\n
            if (e === 0)\n
                return true;\n
        }\n
        return false\n
    };\n
\n
    this.onUpdate = function() {\n
        var value = this.doc.getValue();\n
        value = value.replace(/^#!.*\\n/, "\\n");\n
        if (!value) {\n
            this.sender.emit("jslint", []);\n
            return;\n
        }\n
        var errors = [];\n
        var maxErrorLevel = this.isValidJS(value) ? "warning" : "error";\n
        lint(value, this.options);\n
        var results = lint.errors;\n
\n
        var errorAdded = false\n
        for (var i = 0; i < results.length; i++) {\n
            var error = results[i];\n
            if (!error)\n
                continue;\n
            var raw = error.raw;\n
            var type = "warning";\n
\n
            if (raw == "Missing semicolon.") {\n
                var str = error.evidence.substr(error.character);\n
                str = str.charAt(str.search(/\\S/));\n
                if (maxErrorLevel == "error" && str && /[\\w\\d{([\'"]/.test(str)) {\n
                    error.reason = \'Missing ";" before statement\';\n
                    type = "error";\n
                } else {\n
                    type = "info";\n
                }\n
            }\n
            else if (disabledWarningsRe.test(raw)) {\n
                continue;\n
            }\n
            else if (infoRe.test(raw)) {\n
                type = "info"\n
            }\n
            else if (errorsRe.test(raw)) {\n
                errorAdded  = true;\n
                type = maxErrorLevel;\n
            }\n
            else if (raw == "\'{a}\' is not defined.") {\n
                type = "warning";\n
            }\n
            else if (raw == "\'{a}\' is defined but never used.") {\n
                type = "info";\n
            }\n
\n
            errors.push({\n
                row: error.line-1,\n
                column: error.character-1,\n
                text: error.reason,\n
                type: type,\n
                raw: raw\n
            });\n
\n
            if (errorAdded) {\n
            }\n
        }\n
\n
        this.sender.emit("jslint", errors);\n
    };\n
\n
}).call(JavaScriptWorker.prototype);\n
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
define(\'ace/mode/javascript/jshint\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
require = null;\n
require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module \'"+o+"\'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({\n
9:[function (req,module,exports){\n
        ["log", "info", "warn", "error", \n
        "time","timeEnd", "trace", "dir", "assert"\n
        ].forEach(function(x) {exports[x] = nop;});\n
        function nop() {}\n
    },{}],\n
1:[function(req,module,exports){\n
\n
(function() {\n
  var root = this;\n
  var previousUnderscore = root._;\n
  var breaker = {};\n
  var ArrayProto = Array.prototype, ObjProto = Object.prototype, FuncProto = Function.prototype;\n
  var push             = ArrayProto.push,\n
      slice            = ArrayProto.slice,\n
      concat           = ArrayProto.concat,\n
      toString         = ObjProto.toString,\n
      hasOwnProperty   = ObjProto.hasOwnProperty;\n
  var\n
    nativeForEach      = ArrayProto.forEach,\n
    nativeMap          = ArrayProto.map,\n
    nativeReduce       = ArrayProto.reduce,\n
    nativeReduceRight  = ArrayProto.reduceRight,\n
    nativeFilter       = ArrayProto.filter,\n
    nativeEvery        = ArrayProto.every,\n
    nativeSome         = ArrayProto.some,\n
    nativeIndexOf      = ArrayProto.indexOf,\n
    nativeLastIndexOf  = ArrayProto.lastIndexOf,\n
    nativeIsArray      = Array.isArray,\n
    nativeKeys         = Object.keys,\n
    nativeBind         = FuncProto.bind;\n
  var _ = function(obj) {\n
    if (obj instanceof _) return obj;\n
    if (!(this instanceof _)) return new _(obj);\n
    this._wrapped = obj;\n
  };\n
  if (typeof exports !== \'undefined\') {\n
    if (typeof module !== \'undefined\' && module.exports) {\n
      exports = module.exports = _;\n
    }\n
    exports._ = _;\n
  } else {\n
    root._ = _;\n
  }\n
  _.VERSION = \'1.4.4\';\n
  var each = _.each = _.forEach = function(obj, iterator, context) {\n
    if (obj == null) return;\n
    if (nativeForEach && obj.forEach === nativeForEach) {\n
      obj.forEach(iterator, context);\n
    } else if (obj.length === +obj.length) {\n
      for (var i = 0, l = obj.length; i < l; i++) {\n
        if (iterator.call(context, obj[i], i, obj) === breaker) return;\n
      }\n
    } else {\n
      for (var key in obj) {\n
        if (_.has(obj, key)) {\n
          if

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

 (iterator.call(context, obj[key], key, obj) === breaker) return;\n
        }\n
      }\n
    }\n
  };\n
  _.map = _.collect = function(obj, iterator, context) {\n
    var results = [];\n
    if (obj == null) return results;\n
    if (nativeMap && obj.map === nativeMap) return obj.map(iterator, context);\n
    each(obj, function(value, index, list) {\n
      results[results.length] = iterator.call(context, value, index, list);\n
    });\n
    return results;\n
  };\n
\n
  var reduceError = \'Reduce of empty array with no initial value\';\n
  _.reduce = _.foldl = _.inject = function(obj, iterator, memo, context) {\n
    var initial = arguments.length > 2;\n
    if (obj == null) obj = [];\n
    if (nativeReduce && obj.reduce === nativeReduce) {\n
      if (context) iterator = _.bind(iterator, context);\n
      return initial ? obj.reduce(iterator, memo) : obj.reduce(iterator);\n
    }\n
    each(obj, function(value, index, list) {\n
      if (!initial) {\n
        memo = value;\n
        initial = true;\n
      } else {\n
        memo = iterator.call(context, memo, value, index, list);\n
      }\n
    });\n
    if (!initial) throw new TypeError(reduceError);\n
    return memo;\n
  };\n
  _.reduceRight = _.foldr = function(obj, iterator, memo, context) {\n
    var initial = arguments.length > 2;\n
    if (obj == null) obj = [];\n
    if (nativeReduceRight && obj.reduceRight === nativeReduceRight) {\n
      if (context) iterator = _.bind(iterator, context);\n
      return initial ? obj.reduceRight(iterator, memo) : obj.reduceRight(iterator);\n
    }\n
    var length = obj.length;\n
    if (length !== +length) {\n
      var keys = _.keys(obj);\n
      length = keys.length;\n
    }\n
    each(obj, function(value, index, list) {\n
      index = keys ? keys[--length] : --length;\n
      if (!initial) {\n
        memo = obj[index];\n
        initial = true;\n
      } else {\n
        memo = iterator.call(context, memo, obj[index], index, list);\n
      }\n
    });\n
    if (!initial) throw new TypeError(reduceError);\n
    return memo;\n
  };\n
  _.find = _.detect = function(obj, iterator, context) {\n
    var result;\n
    any(obj, function(value, index, list) {\n
      if (iterator.call(context, value, index, list)) {\n
        result = value;\n
        return true;\n
      }\n
    });\n
    return result;\n
  };\n
  _.filter = _.select = function(obj, iterator, context) {\n
    var results = [];\n
    if (obj == null) return results;\n
    if (nativeFilter && obj.filter === nativeFilter) return obj.filter(iterator, context);\n
    each(obj, function(value, index, list) {\n
      if (iterator.call(context, value, index, list)) results[results.length] = value;\n
    });\n
    return results;\n
  };\n
  _.reject = function(obj, iterator, context) {\n
    return _.filter(obj, function(value, index, list) {\n
      return !iterator.call(context, value, index, list);\n
    }, context);\n
  };\n
  _.every = _.all = function(obj, iterator, context) {\n
    iterator || (iterator = _.identity);\n
    var result = true;\n
    if (obj == null) return result;\n
    if (nativeEvery && obj.every === nativeEvery) return obj.every(iterator, context);\n
    each(obj, function(value, index, list) {\n
      if (!(result = result && iterator.call(context, value, index, list))) return breaker;\n
    });\n
    return !!result;\n
  };\n
  var any = _.some = _.any = function(obj, iterator, context) {\n
    iterator || (iterator = _.identity);\n
    var result = false;\n
    if (obj == null) return result;\n
    if (nativeSome && obj.some === nativeSome) return obj.some(iterator, context);\n
    each(obj, function(value, index, list) {\n
      if (result || (result = iterator.call(context, value, index, list))) return breaker;\n
    });\n
    return !!result;\n
  };\n
  _.contains = _.include = function(obj, target) {\n
    if (obj == null) return false;\n
    if (nativeIndexOf && obj.indexOf === nativeIndexOf) return obj.indexOf(target) != -1;\n
    return any(obj, function(value) {\n
      return value === target;\n
    });\n
  };\n
  _.invoke = function(obj, method) {\n
    var args = slice.call(arguments, 2);\n
    var isFunc = _.isFunction(method);\n
    return _.map(obj, function(value) {\n
      return (isFunc ? method : value[method]).apply(value, args);\n
    });\n
  };\n
  _.pluck = function(obj, key) {\n
    return _.map(obj, function(value){ return value[key]; });\n
  };\n
  _.where = function(obj, attrs, first) {\n
    if (_.isEmpty(attrs)) return first ? null : [];\n
    return _[first ? \'find\' : \'filter\'](obj, function(value) {\n
      for (var key in attrs) {\n
        if (attrs[key] !== value[key]) return false;\n
      }\n
      return true;\n
    });\n
  };\n
  _.findWhere = function(obj, attrs) {\n
    return _.where(obj, attrs, true);\n
  };\n
  _.max = function(obj, iterator, context) {\n
    if (!iterator && _.isArray(obj) && obj[0] === +obj[0] && obj.length < 65535) {\n
      return Math.max.apply(Math, obj);\n
    }\n
    if (!iterator && _.isEmpty(obj)) return -Infinity;\n
    var result = {computed : -Infinity, value: -Infinity};\n
    each(obj, function(value, index, list) {\n
      var computed = iterator ? iterator.call(context, value, index, list) : value;\n
      computed >= result.computed && (result = {value : value, computed : computed});\n
    });\n
    return result.value;\n
  };\n
  _.min = function(obj, iterator, context) {\n
    if (!iterator && _.isArray(obj) && obj[0] === +obj[0] && obj.length < 65535) {\n
      return Math.min.apply(Math, obj);\n
    }\n
    if (!iterator && _.isEmpty(obj)) return Infinity;\n
    var result = {computed : Infinity, value: Infinity};\n
    each(obj, function(value, index, list) {\n
      var computed = iterator ? iterator.call(context, value, index, list) : value;\n
      computed < result.computed && (result = {value : value, computed : computed});\n
    });\n
    return result.value;\n
  };\n
  _.shuffle = function(obj) {\n
    var rand;\n
    var index = 0;\n
    var shuffled = [];\n
    each(obj, function(value) {\n
      rand = _.random(index++);\n
      shuffled[index - 1] = shuffled[rand];\n
      shuffled[rand] = value;\n
    });\n
    return shuffled;\n
  };\n
  var lookupIterator = function(value) {\n
    return _.isFunction(value) ? value : function(obj){ return obj[value]; };\n
  };\n
  _.sortBy = function(obj, value, context) {\n
    var iterator = lookupIterator(value);\n
    return _.pluck(_.map(obj, function(value, index, list) {\n
      return {\n
        value : value,\n
        index : index,\n
        criteria : iterator.call(context, value, index, list)\n
      };\n
    }).sort(function(left, right) {\n
      var a = left.criteria;\n
      var b = right.criteria;\n
      if (a !== b) {\n
        if (a > b || a === void 0) return 1;\n
        if (a < b || b === void 0) return -1;\n
      }\n
      return left.index < right.index ? -1 : 1;\n
    }), \'value\');\n
  };\n
  var group = function(obj, value, context, behavior) {\n
    var result = {};\n
    var iterator = lookupIterator(value || _.identity);\n
    each(obj, function(value, index) {\n
      var key = iterator.call(context, value, index, obj);\n
      behavior(result, key, value);\n
    });\n
    return result;\n
  };\n
  _.groupBy = function(obj, value, context) {\n
    return group(obj, value, context, function(result, key, value) {\n
      (_.has(result, key) ? result[key] : (result[key] = [])).push(value);\n
    });\n
  };\n
  _.countBy = function(obj, value, context) {\n
    return group(obj, value, context, function(result, key) {\n
      if (!_.has(result, key)) result[key] = 0;\n
      result[key]++;\n
    });\n
  };\n
  _.sortedIndex = function(array, obj, iterator, context) {\n
    iterator = iterator == null ? _.identity : lookupIterator(iterator);\n
    var value = iterator.call(context, obj);\n
    var low = 0, high = array.length;\n
    while (low < high) {\n
      var mid = (low + high) >>> 1;\n
      iterator.call(context, array[mid]) < value ? low = mid + 1 : high = mid;\n
    }\n
    return low;\n
  };\n
  _.toArray = function(obj) {\n
    if (!obj) return [];\n
    if (_.isArray(obj)) return slice.call(obj);\n
    if (obj.length === +obj.length) return _.map(obj, _.identity);\n
    return _.values(obj);\n
  };\n
  _.size = function(obj) {\n
    if (obj == null) return 0;\n
    return (obj.length === +obj.length) ? obj.length : _.keys(obj).length;\n
  };\n
  _.first = _.head = _.take = function(array, n, guard) {\n
    if (array == null) return void 0;\n
    return (n != null) && !guard ? slice.call(array, 0, n) : array[0];\n
  };\n
  _.initial = function(array, n, guard) {\n
    return slice.call(array, 0, array.length - ((n == null) || guard ? 1 : n));\n
  };\n
  _.last = function(array, n, guard) {\n
    if (array == null) return void 0;\n
    if ((n != null) && !guard) {\n
      return slice.call(array, Math.max(array.length - n, 0));\n
    } else {\n
      return array[array.length - 1];\n
    }\n
  };\n
  _.rest = _.tail = _.drop = function(array, n, guard) {\n
    return slice.call(array, (n == null) || guard ? 1 : n);\n
  };\n
  _.compact = function(array) {\n
    return _.filter(array, _.identity);\n
  };\n
  var flatten = function(input, shallow, output) {\n
    each(input, function(value) {\n
      if (_.isArray(value)) {\n
        shallow ? push.apply(output, value) : flatten(value, shallow, output);\n
      } else {\n
        output.push(value);\n
      }\n
    });\n
    return output;\n
  };\n
  _.flatten = function(array, shallow) {\n
    return flatten(array, shallow, []);\n
  };\n
  _.without = function(array) {\n
    return _.difference(array, slice.call(arguments, 1));\n
  };\n
  _.uniq = _.unique = function(array, isSorted, iterator, context) {\n
    if (_.isFunction(isSorted)) {\n
      context = iterator;\n
      iterator = isSorted;\n
      isSorted = false;\n
    }\n
    var initial = iterator ? _.map(array, iterator, context) : array;\n
    var results = [];\n
    var seen = [];\n
    each(initial, function(value, index) {\n
      if (isSorted ? (!index || seen[seen.length - 1] !== value) : !_.contains(seen, value)) {\n
        seen.push(value);\n
        results.push(array[index]);\n
      }\n
    });\n
    return results;\n
  };\n
  _.union = function() {\n
    return _.uniq(concat.apply(ArrayProto, arguments));\n
  };\n
  _.intersection = function(array) {\n
    var rest = slice.call(arguments, 1);\n
    return _.filter(_.uniq(array), function(item) {\n
      return _.every(rest, function(other) {\n
        return _.indexOf(other, item) >= 0;\n
      });\n
    });\n
  };\n
  _.difference = function(array) {\n
    var rest = concat.apply(ArrayProto, slice.call(arguments, 1));\n
    return _.filter(array, function(value){ return !_.contains(rest, value); });\n
  };\n
  _.zip = function() {\n
    var args = slice.call(arguments);\n
    var length = _.max(_.pluck(args, \'length\'));\n
    var results = new Array(length);\n
    for (var i = 0; i < length; i++) {\n
      results[i] = _.pluck(args, "" + i);\n
    }\n
    return results;\n
  };\n
  _.object = function(list, values) {\n
    if (list == null) return {};\n
    var result = {};\n
    for (var i = 0, l = list.length; i < l; i++) {\n
      if (values) {\n
        result[list[i]] = values[i];\n
      } else {\n
        result[list[i][0]] = list[i][1];\n
      }\n
    }\n
    return result;\n
  };\n
  _.indexOf = function(array, item, isSorted) {\n
    if (array == null) return -1;\n
    var i = 0, l = array.length;\n
    if (isSorted) {\n
      if (typeof isSorted == \'number\') {\n
        i = (isSorted < 0 ? Math.max(0, l + isSorted) : isSorted);\n
      } else {\n
        i = _.sortedIndex(array, item);\n
        return array[i] === item ? i : -1;\n
      }\n
    }\n
    if (nativeIndexOf && array.indexOf === nativeIndexOf) return array.indexOf(item, isSorted);\n
    for (; i < l; i++) if (array[i] === item) return i;\n
    return -1;\n
  };\n
  _.lastIndexOf = function(array, item, from) {\n
    if (array == null) return -1;\n
    var hasIndex = from != null;\n
    if (nativeLastIndexOf && array.lastIndexOf === nativeLastIndexOf) {\n
      return hasIndex ? array.lastIndexOf(item, from) : array.lastIndexOf(item);\n
    }\n
    var i = (hasIndex ? from : array.length);\n
    while (i--) if (array[i] === item) return i;\n
    return -1;\n
  };\n
  _.range = function(start, stop, step) {\n
    if (arguments.length <= 1) {\n
      stop = start || 0;\n
      start = 0;\n
    }\n
    step = arguments[2] || 1;\n
\n
    var len = Math.max(Math.ceil((stop - start) / step), 0);\n
    var idx = 0;\n
    var range = new Array(len);\n
\n
    while(idx < len) {\n
      range[idx++] = start;\n
      start += step;\n
    }\n
\n
    return range;\n
  };\n
  _.bind = function(func, context) {\n
    if (func.bind === nativeBind && nativeBind) return nativeBind.apply(func, slice.call(arguments, 1));\n
    var args = slice.call(arguments, 2);\n
    return function() {\n
      return func.apply(context, args.concat(slice.call(arguments)));\n
    };\n
  };\n
  _.partial = function(func) {\n
    var args = slice.call(arguments, 1);\n
    return function() {\n
      return func.apply(this, args.concat(slice.call(arguments)));\n
    };\n
  };\n
  _.bindAll = function(obj) {\n
    var funcs = slice.call(arguments, 1);\n
    if (funcs.length === 0) funcs = _.functions(obj);\n
    each(funcs, function(f) { obj[f] = _.bind(obj[f], obj); });\n
    return obj;\n
  };\n
  _.memoize = function(func, hasher) {\n
    var memo = {};\n
    hasher || (hasher = _.identity);\n
    return function() {\n
      var key = hasher.apply(this, arguments);\n
      return _.has(memo, key) ? memo[key] : (memo[key] = func.apply(this, arguments));\n
    };\n
  };\n
  _.delay = function(func, wait) {\n
    var args = slice.call(arguments, 2);\n
    return setTimeout(function(){ return func.apply(null, args); }, wait);\n
  };\n
  _.defer = function(func) {\n
    return _.delay.apply(_, [func, 1].concat(slice.call(arguments, 1)));\n
  };\n
  _.throttle = function(func, wait) {\n
    var context, args, timeout, result;\n
    var previous = 0;\n
    var later = function() {\n
      previous = new Date;\n
      timeout = null;\n
      result = func.apply(context, args);\n
    };\n
    return function() {\n
      var now = new Date;\n
      var remaining = wait - (now - previous);\n
      context = this;\n
      args = arguments;\n
      if (remaining <= 0) {\n
        clearTimeout(timeout);\n
        timeout = null;\n
        previous = now;\n
        result = func.apply(context, args);\n
      } else if (!timeout) {\n
        timeout = setTimeout(later, remaining);\n
      }\n
      return result;\n
    };\n
  };\n
  _.debounce = function(func, wait, immediate) {\n
    var timeout, result;\n
    return function() {\n
      var context = this, args = arguments;\n
      var later = function() {\n
        timeout = null;\n
        if (!immediate) result = func.apply(context, args);\n
      };\n
      var callNow = immediate && !timeout;\n
      clearTimeout(timeout);\n
      timeout = setTimeout(later, wait);\n
      if (callNow) result = func.apply(context, args);\n
      return result;\n
    };\n
  };\n
  _.once = function(func) {\n
    var ran = false, memo;\n
    return function() {\n
      if (ran) return memo;\n
      ran = true;\n
      memo = func.apply(this, arguments);\n
      func = null;\n
      return memo;\n
    };\n
  };\n
  _.wrap = function(func, wrapper) {\n
    return function() {\n
      var args = [func];\n
      push.apply(args, arguments);\n
      return wrapper.apply(this, args);\n
    };\n
  };\n
  _.compose = function() {\n
    var funcs = arguments;\n
    return function() {\n
      var args = arguments;\n
      for (var i = funcs.length - 1; i >= 0; i--) {\n
        args = [funcs[i].apply(this, args)];\n
      }\n
      return args[0];\n
    };\n
  };\n
  _.after = function(times, func) {\n
    if (times <= 0) return func();\n
    return function() {\n
      if (--times < 1) {\n
        return func.apply(this, arguments);\n
      }\n
    };\n
  };\n
  _.keys = nativeKeys || function(obj) {\n
    if (obj !== Object(obj)) throw new TypeError(\'Invalid object\');\n
    var keys = [];\n
    for (var key in obj) if (_.has(obj, key)) keys[keys.length] = key;\n
    return keys;\n
  };\n
  _.values = function(obj) {\n
    var values = [];\n
    for (var key in obj) if (_.has(obj, key)) values.push(obj[key]);\n
    return values;\n
  };\n
  _.pairs = function(obj) {\n
    var pairs = [];\n
    for (var key in obj) if (_.has(obj, key)) pairs.push([key, obj[key]]);\n
    return pairs;\n
  };\n
  _.invert = function(obj) {\n
    var result = {};\n
    for (var key in obj) if (_.has(obj, key)) result[obj[key]] = key;\n
    return result;\n
  };\n
  _.functions = _.methods = function(obj) {\n
    var names = [];\n
    for (var key in obj) {\n
      if (_.isFunction(obj[key])) names.push(key);\n
    }\n
    return names.sort();\n
  };\n
  _.extend = function(obj) {\n
    each(slice.call(arguments, 1), function(source) {\n
      if (source) {\n
        for (var prop in source) {\n
          obj[prop] = source[prop];\n
        }\n
      }\n
    });\n
    return obj;\n
  };\n
  _.pick = function(obj) {\n
    var copy = {};\n
    var keys = concat.apply(ArrayProto, slice.call(arguments, 1));\n
    each(keys, function(key) {\n
      if (key in obj) copy[key] = obj[key];\n
    });\n
    return copy;\n
  };\n
  _.omit = function(obj) {\n
    var copy = {};\n
    var keys = concat.apply(ArrayProto, slice.call(arguments, 1));\n
    for (var key in obj) {\n
      if (!_.contains(keys, key)) copy[key] = obj[key];\n
    }\n
    return copy;\n
  };\n
  _.defaults = function(obj) {\n
    each(slice.call(arguments, 1), function(source) {\n
      if (source) {\n
        for (var prop in source) {\n
          if (obj[prop] == null) obj[prop] = source[prop];\n
        }\n
      }\n
    });\n
    return obj;\n
  };\n
  _.clone = function(obj) {\n
    if (!_.isObject(obj)) return obj;\n
    return _.isArray(obj) ? obj.slice() : _.extend({}, obj);\n
  };\n
  _.tap = function(obj, interceptor) {\n
    interceptor(obj);\n
    return obj;\n
  };\n
  var eq = function(a, b, aStack, bStack) {\n
    if (a === b) return a !== 0 || 1 / a == 1 / b;\n
    if (a == null || b == null) return a === b;\n
    if (a instanceof _) a = a._wrapped;\n
    if (b instanceof _) b = b._wrapped;\n
    var className = toString.call(a);\n
    if (className != toString.call(b)) return false;\n
    switch (className) {\n
      case \'[object String]\':\n
        return a == String(b);\n
      case \'[object Number]\':\n
        return a != +a ? b != +b : (a == 0 ? 1 / a == 1 / b : a == +b);\n
      case \'[object Date]\':\n
      case \'[object Boolean]\':\n
        return +a == +b;\n
      case \'[object RegExp]\':\n
        return a.source == b.source &&\n
               a.global == b.global &&\n
               a.multiline == b.multiline &&\n
               a.ignoreCase == b.ignoreCase;\n
    }\n
    if (typeof a != \'object\' || typeof b != \'object\') return false;\n
    var length = aStack.length;\n
    while (length--) {\n
      if (aStack[length] == a) return bStack[length] == b;\n
    }\n
    aStack.push(a);\n
    bStack.push(b);\n
    var size = 0, result = true;\n
    if (className == \'[object Array]\') {\n
      size = a.length;\n
      result = size == b.length;\n
      if (result) {\n
        while (size--) {\n
          if (!(result = eq(a[size], b[size], aStack, bStack))) break;\n
        }\n
      }\n
    } else {\n
      var aCtor = a.constructor, bCtor = b.constructor;\n
      if (aCtor !== bCtor && !(_.isFunction(aCtor) && (aCtor instanceof aCtor) &&\n
                               _.isFunction(bCtor) && (bCtor instanceof bCtor))) {\n
        return false;\n
      }\n
      for (var key in a) {\n
        if (_.has(a, key)) {\n
          size++;\n
          if (!(result = _.has(b, key) && eq(a[key], b[key], aStack, bStack))) break;\n
        }\n
      }\n
      if (result) {\n
        for (key in b) {\n
          if (_.has(b, key) && !(size--)) break;\n
        }\n
        result = !size;\n
      }\n
    }\n
    aStack.pop();\n
    bStack.pop();\n
    return result;\n
  };\n
  _.isEqual = function(a, b) {\n
    return eq(a, b, [], []);\n
  };\n
  _.isEmpty = function(obj) {\n
    if (obj == null) return true;\n
    if (_.isArray(obj) || _.isString(obj)) return obj.length === 0;\n
    for (var key in obj) if (_.has(obj, key)) return false;\n
    return true;\n
  };\n
  _.isElement = function(obj) {\n
    return !!(obj && obj.nodeType === 1);\n
  };\n
  _.isArray = nativeIsArray || function(obj) {\n
    return toString.call(obj) == \'[object Array]\';\n
  };\n
  _.isObject = function(obj) {\n
    return obj === Object(obj);\n
  };\n
  each([\'Arguments\', \'Function\', \'String\', \'Number\', \'Date\', \'RegExp\'], function(name) {\n
    _[\'is\' + name] = function(obj) {\n
      return toString.call(obj) == \'[object \' + name + \']\';\n
    };\n
  });\n
  if (!_.isArguments(arguments)) {\n
    _.isArguments = function(obj) {\n
      return !!(obj && _.has(obj, \'callee\'));\n
    };\n
  }\n
  if (typeof (/./) !== \'function\') {\n
    _.isFunction = function(obj) {\n
      return typeof obj === \'function\';\n
    };\n
  }\n
  _.isFinite = function(obj) {\n
    return isFinite(obj) && !isNaN(parseFloat(obj));\n
  };\n
  _.isNaN = function(obj) {\n
    return _.isNumber(obj) && obj != +obj;\n
  };\n
  _.isBoolean = function(obj) {\n
    return obj === true || obj === false || toString.call(obj) == \'[object Boolean]\';\n
  };\n
  _.isNull = function(obj) {\n
    return obj === null;\n
  };\n
  _.isUndefined = function(obj) {\n
    return obj === void 0;\n
  };\n
  _.has = function(obj, key) {\n
    return hasOwnProperty.call(obj, key);\n
  };\n
  _.noConflict = function() {\n
    root._ = previousUnderscore;\n
    return this;\n
  };\n
  _.identity = function(value) {\n
    return value;\n
  };\n
  _.times = function(n, iterator, context) {\n
    var accum = Array(n);\n
    for (var i = 0; i < n; i++) accum[i] = iterator.call(context, i);\n
    return accum;\n
  };\n
  _.random = function(min, max) {\n
    if (max == null) {\n
      max = min;\n
      min = 0;\n
    }\n
    return min + Math.floor(Math.random() * (max - min + 1));\n
  };\n
  var entityMap = {\n
    escape: {\n
      \'&\': \'&amp;\',\n
      \'<\': \'&lt;\',\n
      \'>\': \'&gt;\',\n
      \'"\': \'&quot;\',\n
      "\'": \'&#x27;\',\n
      \'/\': \'&#x2F;\'\n
    }\n
  };\n
  entityMap.unescape = _.invert(entityMap.escape);\n
  var entityRegexes = {\n
    escape:   new RegExp(\'[\' + _.keys(entityMap.escape).join(\'\') + \']\', \'g\'),\n
    unescape: new RegExp(\'(\' + _.keys(entityMap.unescape).join(\'|\') + \')\', \'g\')\n
  };\n
  _.each([\'escape\', \'unescape\'], function(method) {\n
    _[method] = function(string) {\n
      if (string == null) return \'\';\n
      return (\'\' + string).replace(entityRegexes[method], function(match) {\n
        return entityMap[method][match];\n
      });\n
    };\n
  });\n
  _.result = function(object, property) {\n
    if (object == null) return null;\n
    var value = object[property];\n
    return _.isFunction(value) ? value.call(object) : value;\n
  };\n
  _.mixin = function(obj) {\n
    each(_.functions(obj), function(name){\n
      var func = _[name] = obj[name];\n
      _.prototype[name] = function() {\n
        var args = [this._wrapped];\n
        push.apply(args, arguments);\n
        return result.call(this, func.apply(_, args));\n
      };\n
    });\n
  };\n
  var idCounter = 0;\n
  _.uniqueId = function(prefix) {\n
    var id = ++idCounter + \'\';\n
    return prefix ? prefix + id : id;\n
  };\n
  _.templateSettings = {\n
    evaluate    : /<%([\\s\\S]+?)%>/g,\n
    interpolate : /<%=([\\s\\S]+?)%>/g,\n
    escape      : /<%-([\\s\\S]+?)%>/g\n
  };\n
  var noMatch = /(.)^/;\n
  var escapes = {\n
    "\'":      "\'",\n
    \'\\\\\':     \'\\\\\',\n
    \'\\r\':     \'r\',\n
    \'\\n\':     \'n\',\n
    \'\\t\':     \'t\',\n
    \'\\u2028\': \'u2028\',\n
    \'\\u2029\': \'u2029\'\n
  };\n
\n
  var escaper = /\\\\|\'|\\r|\\n|\\t|\\u2028|\\u2029/g;\n
  _.template = function(text, data, settings) {\n
    var render;\n
    settings = _.defaults({}, settings, _.templateSettings);\n
    var matcher = new RegExp([\n
      (settings.escape || noMatch).source,\n
      (settings.interpolate || noMatch).source,\n
      (settings.evaluate || noMatch).source\n
    ].join(\'|\') + \'|$\', \'g\');\n
    var index = 0;\n
    var source = "__p+=\'";\n
    text.replace(matcher, function(match, escape, interpolate, evaluate, offset) {\n
      source += text.slice(index, offset)\n
        .replace(escaper, function(match) { return \'\\\\\' + escapes[match]; });\n
\n
      if (escape) {\n
        source += "\'+\\n((__t=(" + escape + "))==null?\'\':_.escape(__t))+\\n\'";\n
      }\n
      if (interpolate) {\n
        source += "\'+\\n((__t=(" + interpolate + "))==null?\'\':__t)+\\n\'";\n
      }\n
      if (evaluate) {\n
        source += "\';\\n" + evaluate + "\\n__p+=\'";\n
      }\n
      index = offset + match.length;\n
      return match;\n
    });\n
    source += "\';\\n";\n
    if (!settings.variable) source = \'with(obj||{}){\\n\' + source + \'}\\n\';\n
\n
    source = "var __t,__p=\'\',__j=Array.prototype.join," +\n
      "print=function(){__p+=__j.call(arguments,\'\');};\\n" +\n
      source + "return __p;\\n";\n
\n
    try {\n
      render = new Function(settings.variable || \'obj\', \'_\', source);\n
    } catch (e) {\n
      e.source = source;\n
      throw e;\n
    }\n
\n
    if (data) return render(data, _);\n
    var template = function(data) {\n
      return render.call(this, data, _);\n
    };\n
    template.source = \'function(\' + (settings.variable || \'obj\') + \'){\\n\' + source + \'}\';\n
\n
    return template;\n
  };\n
  _.chain = function(obj) {\n
    return _(obj).chain();\n
  };\n
  var result = function(obj) {\n
    return this._chain ? _(obj).chain() : obj;\n
  };\n
  _.mixin(_);\n
  each([\'pop\', \'push\', \'reverse\', \'shift\', \'sort\', \'splice\', \'unshift\'], function(name) {\n
    var method = ArrayProto[name];\n
    _.prototype[name] = function() {\n
      var obj = this._wrapped;\n
      method.apply(obj, arguments);\n
      if ((name == \'shift\' || name == \'splice\') && obj.length === 0) delete obj[0];\n
      return result.call(this, obj);\n
    };\n
  });\n
  each([\'concat\', \'join\', \'slice\'], function(name) {\n
    var method = ArrayProto[name];\n
    _.prototype[name] = function() {\n
      return result.call(this, method.apply(this._wrapped, arguments));\n
    };\n
  });\n
\n
  _.extend(_.prototype, {\n
    chain: function() {\n
      this._chain = true;\n
      return this;\n
    },\n
    value: function() {\n
      return this._wrapped;\n
    }\n
\n
  });\n
\n
}).call(this);\n
\n
},\n
{}],\n
2:[function(req,module,exports){\n
\n
\n
var _ = req("underscore");\n
\n
var errors = {\n
\tE001: "Bad option: \'{a}\'.",\n
\tE002: "Bad option value.",\n
\tE003: "Expected a JSON value.",\n
\tE004: "Input is neither a string nor an array of strings.",\n
\tE005: "Input is empty.",\n
\tE006: "Unexpected early end of program.",\n
\tE007: "Missing \\"use strict\\" statement.",\n
\tE008: "Strict violation.",\n
\tE009: "Option \'validthis\' can\'t be used in a global scope.",\n
\tE010: "\'with\' is not allowed in strict mode.",\n
\tE011: "const \'{a}\' has already been declared.",\n
\tE012: "const \'{a}\' is initialized to \'undefined\'.",\n
\tE013: "Attempting to override \'{a}\' which is a constant.",\n
\tE014: "A regular expression literal can be confused with \'/=\'.",\n
\tE015: "Unclosed regular expression.",\n
\tE016: "Invalid regular expression.",\n
\tE017: "Unclosed comment.",\n
\tE018: "Unbegun comment.",\n
\tE019: "Unmatched \'{a}\'.",\n
\tE020: "Expected \'{a}\' to match \'{b}\' from line {c} and instead saw \'{d}\'.",\n
\tE021: "Expected \'{a}\' and instead saw \'{b}\'.",\n
\tE022: "Line breaking error \'{a}\'.",\n
\tE023: "Missing \'{a}\'.",\n
\tE024: "Unexpected \'{a}\'.",\n
\tE025: "Missing \':\' on a case clause.",\n
\tE026: "Missing \'}\' to match \'{\' from line {a}.",\n
\tE027: "Missing \']\' to match \'[\' form line {a}.",\n
\tE028: "Illegal comma.",\n
\tE029: "Unclosed string.",\n
\tE030: "Expected an identifier and instead saw \'{a}\'.",\n
\tE031: "Bad assignment.", // FIXME: Rephrase\n
\tE032: "Expected a small integer or \'false\' and instead saw \'{a}\'.",\n
\tE033: "Expected an operator and instead saw \'{a}\'.",\n
\tE034: "get/set are ES5 features.",\n
\tE035: "Missing property name.",\n
\tE036: "Expected to see a statement and instead saw a block.",\n
\tE037: null, // Vacant\n
\tE038: null, // Vacant\n
\tE039: "Function declarations are not invocable. Wrap the whole function invocation in parens.",\n
\tE040: "Each value should have its own case label.",\n
\tE041: "Unrecoverable syntax error.",\n
\tE042: "Stopping.",\n
\tE043: "Too many errors.",\n
\tE044: "\'{a}\' is already defined and can\'t be redefined.",\n
\tE045: "Invalid for each loop.",\n
\tE046: "A yield statement shall be within a generator function (with syntax: `function*`)",\n
\tE047: "A generator function shall contain a yield statement.",\n
\tE048: "Let declaration not directly within block.",\n
\tE049: "A {a} cannot be named \'{b}\'.",\n
\tE050: "Mozilla requires the yield expression to be parenthesized here.",\n
\tE051: "Regular parameters cannot come after default parameters."\n
};\n
\n
var warnings = {\n
\tW001: "\'hasOwnProperty\' is a really bad name.",\n
\tW002: "Value of \'{a}\' may be overwritten in IE 8 and earlier.",\n
\tW003: "\'{a}\' was used before it was defined.",\n
\tW004: "\'{a}\' is already defined.",\n
\tW005: "A dot following a number can be confused with a decimal point.",\n
\tW006: "Confusing minuses.",\n
\tW007: "Confusing pluses.",\n
\tW008: "A leading decimal point can be confused with a dot: \'{a}\'.",\n
\tW009: "The array literal notation [] is preferrable.",\n
\tW010: "The object literal notation {} is preferrable.",\n
\tW011: "Unexpected space after \'{a}\'.",\n
\tW012: "Unexpected space before \'{a}\'.",\n
\tW013: "Missing space after \'{a}\'.",\n
\tW014: "Bad line breaking before \'{a}\'.",\n
\tW015: "Expected \'{a}\' to have an indentation at {b} instead at {c}.",\n
\tW016: "Unexpected use of \'{a}\'.",\n
\tW017: "Bad operand.",\n
\tW018: "Confusing use of \'{a}\'.",\n
\tW019: "Use the isNaN function to compare with NaN.",\n
\tW020: "Read only.",\n
\tW021: "\'{a}\' is a function.",\n
\tW022: "Do not assign to the exception parameter.",\n
\tW023: "Expected an identifier in an assignment and instead saw a function invocation.",\n
\tW024: "Expected an identifier and instead saw \'{a}\' (a reserved word).",\n
\tW025: "Missing name in function declaration.",\n
\tW026: "Inner functions should be listed at the top of the outer function.",\n
\tW027: "Unreachable \'{a}\' after \'{b}\'.",\n
\tW028: "Label \'{a}\' on {b} statement.",\n
\tW030: "Expected an assignment or function call and instead saw an expression.",\n
\tW031: "Do not use \'new\' for side effects.",\n
\tW032: "Unnecessary semicolon.",\n
\tW033: "Missing semicolon.",\n
\tW034: "Unnecessary directive \\"{a}\\".",\n
\tW035: "Empty block.",\n
\tW036: "Unexpected /*member \'{a}\'.",\n
\tW037: "\'{a}\' is a statement label.",\n
\tW038: "\'{a}\' used out of scope.",\n
\tW039: "\'{a}\' is not allowed.",\n
\tW040: "Possible strict violation.",\n
\tW041: "Use \'{a}\' to compare with \'{b}\'.",\n
\tW042: "Avoid EOL escaping.",\n
\tW043: "Bad escaping of EOL. Use option multistr if needed.",\n
\tW044: "Bad or unnecessary escaping.",\n
\tW045: "Bad number \'{a}\'.",\n
\tW046: "Don\'t use extra leading zeros \'{a}\'.",\n
\tW047: "A trailing decimal point can be confused with a dot: \'{a}\'.",\n
\tW048: "Unexpected control character in regular expression.",\n
\tW049: "Unexpected escaped character \'{a}\' in regular expression.",\n
\tW050: "JavaScript URL.",\n
\tW051: "Variables should not be deleted.",\n
\tW052: "Unexpected \'{a}\'.",\n
\tW053: "Do not use {a} as a constructor.",\n
\tW054: "The Function constructor is a form of eval.",\n
\tW055: "A constructor name should start with an uppercase letter.",\n
\tW056: "Bad constructor.",\n
\tW057: "Weird construction. Is \'new\' unnecessary?",\n
\tW058: "Missing \'()\' invoking a constructor.",\n
\tW059: "Avoid arguments.{a}.",\n
\tW060: "document.write can be a form of eval.",\n
\tW061: "eval can be harmful.",\n
\tW062: "Wrap an immediate function invocation in parens " +\n
\t\t"to assist the reader in understanding that the expression " +\n
\t\t"is the result of a function, and not the function itself.",\n
\tW063: "Math is not a function.",\n
\tW064: "Missing \'new\' prefix when invoking a constructor.",\n
\tW065: "Missing radix parameter.",\n
\tW066: "Implied eval. Consider passing a function instead of a string.",\n
\tW067: "Bad invocation.",\n
\tW068: "Wrapping non-IIFE function literals in parens is unnecessary.",\n
\tW069: "[\'{a}\'] is better written in dot notation.",\n
\tW070: "Extra comma. (it breaks older versions of IE)",\n
\tW071: "This function has too many statements. ({a})",\n
\tW072: "This function has too many parameters. ({a})",\n
\tW073: "Blocks are nested too deeply. ({a})",\n
\tW074: "This function\'s cyclomatic complexity is too high. ({a})",\n
\tW075: "Duplicate key \'{a}\'.",\n
\tW076: "Unexpected parameter \'{a}\' in get {b} function.",\n
\tW077: "Expected a single parameter in set {a} function.",\n
\tW078: "Setter is defined without getter.",\n
\tW079: "Redefinition of \'{a}\'.",\n
\tW080: "It\'s not necessary to initialize \'{a}\' to \'undefined\'.",\n
\tW081: "Too many var statements.",\n
\tW082: "Function declarations should not be placed in blocks. " +\n
\t\t"Use a function expression or move the statement to the top of " +\n
\t\t"the outer function.",\n
\tW083: "Don\'t make functions within a loop.",\n
\tW084: "Assignment in conditional expression",\n
\tW085: "Don\'t use \'with\'.",\n
\tW086: "Expected a \'break\' statement before \'{a}\'.",\n
\tW087: "Forgotten \'debugger\' statement?",\n
\tW088: "Creating global \'for\' variable. Should be \'for (var {a} ...\'.",\n
\tW089: "The body of a for in should be wrapped in an if statement to filter " +\n
\t\t"unwanted properties from the prototype.",\n
\tW090: "\'{a}\' is not a statement label.",\n
\tW091: "\'{a}\' is out of scope.",\n
\tW092: "Wrap the /regexp/ literal in parens to disambiguate the slash operator.",\n
\tW093: "Did you mean to return a conditional instead of an assignment?",\n
\tW094: "Unexpected comma.",\n
\tW095: "Expected a string and instead saw {a}.",\n
\tW096: "The \'{a}\' key may produce unexpected results.",\n
\tW097: "Use the function form of \\"use strict\\".",\n
\tW098: "\'{a}\' is defined but never used.",\n
\tW099: "Mixed spaces and tabs.",\n
\tW100: "This character may get silently deleted by one or more browsers.",\n
\tW101: "Line is too long.",\n
\tW102: "Trailing whitespace.",\n
\tW103: "The \'{a}\' property is deprecated.",\n
\tW104: "\'{a}\' is only available in JavaScript 1.7.",\n
\tW105: "Unexpected {a} in \'{b}\'.",\n
\tW106: "Identifier \'{a}\' is not in camel case.",\n
\tW107: "Script URL.",\n
\tW108: "Strings must use doublequote.",\n
\tW109: "Strings must use singlequote.",\n
\tW110: "Mixed double and single quotes.",\n
\tW112: "Unclosed string.",\n
\tW113: "Control character in string: {a}.",\n
\tW114: "Avoid {a}.",\n
\tW115: "Octal literals are not allowed in strict mode.",\n
\tW116: "Expected \'{a}\' and instead saw \'{b}\'.",\n
\tW117: "\'{a}\' is not defined.",\n
\tW118: "\'{a}\' is only available in Mozilla JavaScript extensions (use moz option).",\n
\tW119: "\'{a}\' is only available in ES6 (use esnext option).",\n
\tW120: "You might be leaking a variable ({a}) here."\n
};\n
\n
var info = {\n
\tI001: "Comma warnings can be turned off with \'laxcomma\'.",\n
\tI002: "Reserved words as properties can be used under the \'es5\' option.",\n
\tI003: "ES5 option is now set per default"\n
};\n
\n
exports.errors = {};\n
exports.warnings = {};\n
exports.info = {};\n
\n
_.each(errors, function (desc, code) {\n
\texports.errors[code] = { code: code, desc: desc };\n
});\n
\n
_.each(warnings, function (desc, code) {\n
\texports.warnings[code] = { code: code, desc: desc };\n
});\n
\n
_.each(info, function (desc, code) {\n
\texports.info[code] = { code: code, desc: desc };\n
});\n
\n
},\n
{"underscore":1}],\n
3:[function(req,module,exports){\n
\n
exports.reservedVars = {\n
\targuments : false,\n
\tNaN       : false\n
};\n
\n
exports.ecmaIdentifiers = {\n
\tArray              : false,\n
\tBoolean            : false,\n
\tDate               : false,\n
\tdecodeURI          : false,\n
\tdecodeURIComponent : false,\n
\tencodeURI          : false,\n
\tencodeURIComponent : false,\n
\tError              : false,\n
\t"eval"             : false,\n
\tEvalError          : false,\n
\tFunction           : false,\n
\thasOwnProperty     : false,\n
\tisFinite           : false,\n
\tisNaN              : false,\n
\tJSON               : false,\n
\tMath               : false,\n
\tMap                : false,\n
\tNumber             : false,\n
\tObject             : false,\n
\tparseInt           : false,\n
\tparseFloat         : false,\n
\tRangeError         : false,\n
\tReferenceError     : false,\n
\tRegExp             : false,\n
\tSet                : false,\n
\tString             : false,\n
\tSyntaxError        : false,\n
\tTypeError          : false,\n
\tURIError           : false,\n
\tWeakMap            : false\n
};\n
\n
exports.browser = {\n
\tArrayBuffer          : false,\n
\tArrayBufferView      : false,\n
\tAudio                : false,\n
\tBlob                 : false,\n
\taddEventListener     : false,\n
\tapplicationCache     : false,\n
\tatob                 : false,\n
\tblur                 : false,\n
\tbtoa                 : false,\n
\tclearInterval        : false,\n
\tclearTimeout         : false,\n
\tclose                : false,\n
\tclosed               : false,\n
\tCustomEvent          : false,\n
\tDataView             : false,\n
\tDOMParser            : false,\n
\tdefaultStatus        : false,\n
\tdocument             : false,\n
\tElement              : false,\n
\tElementTimeControl   : false,\n
\tevent                : false,\n
\tFileReader           : false,\n
\tFloat32Array         : false,\n
\tFloat64Array         : false,\n
\tFormData             : false,\n
\tfocus                : false,\n
\tframes               : false,\n
\tgetComputedStyle     : false,\n
\tHTMLElement          : false,\n
\tHTMLAnchorElement    : false,\n
\tHTMLBaseElement      : false,\n
\tHTMLBlockquoteElement: false,\n
\tHTMLBodyElement      : false,\n
\tHTMLBRElement        : false,\n
\tHTMLButtonElement    : false,\n
\tHTMLCanvasElement    : false,\n
\tHTMLDirectoryElement : false,\n
\tHTMLDivElement       : false,\n
\tHTMLDListElement     : false,\n
\tHTMLFieldSetElement  : false,\n
\tHTMLFontElement      : false,\n
\tHTMLFormElement      : false,\n
\tHTMLFrameElement     : false,\n
\tHTMLFrameSetElement  : false,\n
\tHTMLHeadElement      : false,\n
\tHTMLHeadingElement   : false,\n
\tHTMLHRElement        : false,\n
\tHTMLHtmlElement      : false,\n
\tHTMLIFrameElement    : false,\n
\tHTMLImageElement     : false,\n
\tHTMLInputElement     : false,\n
\tHTMLIsIndexElement   : false,\n
\tHTMLLabelElement     : false,\n
\tHTMLLayerElement     : false,\n
\tHTMLLegendElement    : false,\n
\tHTMLLIElement        : false,\n
\tHTMLLinkElement      : false,\n
\tHTMLMapElement       : false,\n
\tHTMLMenuElement      : false,\n
\tHTMLMetaElement      : false,\n
\tHTMLModElement       : false,\n
\tHTMLObjectElement    : false,\n
\tHTMLOListElement     : false,\n
\tHTMLOptGroupElement  : false,\n
\tHTMLOptionElement    : false,\n
\tHTMLParagraphElement : false,\n
\tHTMLParamElement     : false,\n
\tHTMLPreElement       : false,\n
\tHTMLQuoteElement     : false,\n
\tHTMLScriptElement    : false,\n
\tHTMLSelectElement    : false,\n
\tHTMLStyleElement     : false,\n
\tHTMLTableCaptionElement: false,\n
\tHTMLTableCellElement : false,\n
\tHTMLTableColElement  : false,\n
\tHTMLTableElement     : false,\n
\tHTMLTableRowElement  : false,\n
\tHTMLTableSectionElement: false,\n
\tHTMLTextAreaElement  : false,\n
\tHTMLTitleElement     : false,\n
\tHTMLUListElement     : false,\n
\tHTMLVideoElement     : false,\n
\thistory              : false,\n
\tInt16Array           : false,\n
\tInt32Array           : false,\n
\tInt8Array            : false,\n
\tImage                : false,\n
\tlength               : false,\n
\tlocalStorage         : false,\n
\tlocation             : false,\n
\tMessageChannel       : false,\n
\tMessageEvent         : false,\n
\tMessagePort          : false,\n
\tMouseEvent           : false,\n
\tmoveBy               : false,\n
\tmoveTo               : false,\n
\tMutationObserver     : false,\n
\tname                 : false,\n
\tNode                 : false,\n
\tNodeFilter           : false,\n
\tnavigator            : false,\n
\tonbeforeunload       : true,\n
\tonblur               : true,\n
\tonerror              : true,\n
\tonfocus              : true,\n
\tonload               : true,\n
\tonresize             : true,\n
\tonunload             : true,\n
\topen                 : false,\n
\topenDatabase         : false,\n
\topener               : false,\n
\tOption               : false,\n
\tparent               : false,\n
\tprint                : false,\n
\tremoveEventListener  : false,\n
\tresizeBy             : false,\n
\tresizeTo             : false,\n
\tscreen               : false,\n
\tscroll               : false,\n
\tscrollBy             : false,\n
\tscrollTo             : false,\n
\tsessionStorage       : false,\n
\tsetInterval          : false,\n
\tsetTimeout           : false,\n
\tSharedWorker         : false,\n
\tstatus               : false,\n
\tSVGAElement          : false,\n
\tSVGAltGlyphDefElement: false,\n
\tSVGAltGlyphElement   : false,\n
\tSVGAltGlyphItemElement: false,\n
\tSVGAngle             : false,\n
\tSVGAnimateColorElement: false,\n
\tSVGAnimateElement    : false,\n
\tSVGAnimateMotionElement: false,\n
\tSVGAnimateTransformElement: false,\n
\tSVGAnimatedAngle     : false,\n
\tSVGAnimatedBoolean   : false,\n
\tSVGAnimatedEnumeration: false,\n
\tSVGAnimatedInteger   : false,\n
\tSVGAnimatedLength    : false,\n
\tSVGAnimatedLengthList: false,\n
\tSVGAnimatedNumber    : false,\n
\tSVGAnimatedNumberList: false,\n
\tSVGAnimatedPathData  : false,\n
\tSVGAnimatedPoints    : false,\n
\tSVGAnimatedPreserveAspectRatio: false,\n
\tSVGAnimatedRect      : false,\n
\tSVGAnimatedString    : false,\n
\tSVGAnimatedTransformList: false,\n
\tSVGAnimationElement  : false,\n
\tSVGCSSRule           : false,\n
\tSVGCircleElement     : false,\n
\tSVGClipPathElement   : false,\n
\tSVGColor             : false,\n
\tSVGColorProfileElement: false,\n
\tSVGColorProfileRule  : false,\n
\tSVGComponentTransferFunctionElement: false,\n
\tSVGCursorElement     : false,\n
\tSVGDefsElement       : false,\n
\tSVGDescElement       : false,\n
\tSVGDocument          : false,\n
\tSVGElement           : false,\n
\tSVGElementInstance   : false,\n
\tSVGElementInstanceList: false,\n
\tSVGEllipseElement    : false,\n
\tSVGExternalResourcesRequired: false,\n
\tSVGFEBlendElement    : false,\n
\tSVGFEColorMatrixElement: false,\n
\tSVGFEComponentTransferElement: false,\n
\tSVGFECompositeElement: false,\n
\tSVGFEConvolveMatrixElement: false,\n
\tSVGFEDiffuseLightingElement: false,\n
\tSVGFEDisplacementMapElement: false,\n
\tSVGFEDistantLightElement: false,\n
\tSVGFEFloodElement    : false,\n
\tSVGFEFuncAElement    : false,\n
\tSVGFEFuncBElement    : false,\n
\tSVGFEFuncGElement    : false,\n
\tSVGFEFuncRElement    : false,\n
\tSVGFEGaussianBlurElement: false,\n
\tSVGFEImageElement    : false,\n
\tSVGFEMergeElement    : false,\n
\tSVGFEMergeNodeElement: false,\n
\tSVGFEMorphologyElement: false,\n
\tSVGFEOffsetElement   : false,\n
\tSVGFEPointLightElement: false,\n
\tSVGFESpecularLightingElement: false,\n
\tSVGFESpotLightElement: false,\n
\tSVGFETileElement     : false,\n
\tSVGFETurbulenceElement: false,\n
\tSVGFilterElement     : false,\n
\tSVGFilterPrimitiveStandardAttributes: false,\n
\tSVGFitToViewBox      : false,\n
\tSVGFontElement       : false,\n
\tSVGFontFaceElement   : false,\n
\tSVGFontFaceFormatElement: false,\n
\tSVGFontFaceNameElement: false,\n
\tSVGFontFaceSrcElement: false,\n
\tSVGFontFaceUriElement: false,\n
\tSVGForeignObjectElement: false,\n
\tSVGGElement          : false,\n
\tSVGGlyphElement      : false,\n
\tSVGGlyphRefElement   : false,\n
\tSVGGradientElement   : false,\n
\tSVGHKernElement      : false,\n
\tSVGICCColor          : false,\n
\tSVGImageElement      : false,\n
\tSVGLangSpace         : false,\n
\tSVGLength            : false,\n
\tSVGLengthList        : false,\n
\tSVGLineElement       : false,\n
\tSVGLinearGradientElement: false,\n
\tSVGLocatable         : false,\n
\tSVGMPathElement      : false,\n
\tSVGMarkerElement     : false,\n
\tSVGMaskElement       : false,\n
\tSVGMatrix            : false,\n
\tSVGMetadataElement   : false,\n
\tSVGMissingGlyphElement: false,\n
\tSVGNumber            : false,\n
\tSVGNumberList        : false,\n
\tSVGPaint             : false,\n
\tSVGPathElement       : false,\n
\tSVGPathSeg           : false,\n
\tSVGPathSegArcAbs     : false,\n
\tSVGPathSegArcRel     : false,\n
\tSVGPathSegClosePath  : false,\n
\tSVGPathSegCurvetoCubicAbs: false,\n
\tSVGPathSegCurvetoCubicRel: false,\n
\tSVGPathSegCurvetoCubicSmoothAbs: false,\n
\tSVGPathSegCurvetoCubicSmoothRel: false,\n
\tSVGPathSegCurvetoQuadraticAbs: false,\n
\tSVGPathSegCurvetoQuadraticRel: false,\n
\tSVGPathSegCurvetoQuadraticSmoothAbs: false,\n
\tSVGPathSegCurvetoQuadraticSmoothRel: false,\n
\tSVGPathSegLinetoAbs  : false,\n
\tSVGPathSegLinetoHorizontalAbs: false,\n
\tSVGPathSegLinetoHorizontalRel: false,\n
\tSVGPathSegLinetoRel  : false,\n
\tSVGPathSegLinetoVerticalAbs: false,\n
\tSVGPathSegLinetoVerticalRel: false,\n
\tSVGPathSegList       : false,\n
\tSVGPathSegMovetoAbs  : false,\n
\tSVGPathSegMovetoRel  : false,\n
\tSVGPatternElement    : false,\n
\tSVGPoint             : false,\n
\tSVGPointList         : false,\n
\tSVGPolygonElement    : false,\n
\tSVGPolylineElement   : false,\n
\tSVGPreserveAspectRatio: false,\n
\tSVGRadialGradientElement: false,\n
\tSVGRect              : false,\n
\tSVGRectElement       : false,\n
\tSVGRenderingIntent   : false,\n
\tSVGSVGElement        : false,\n
\tSVGScriptElement     : false,\n
\tSVGSetElement        : false,\n
\tSVGStopElement       : false,\n
\tSVGStringList        : false,\n
\tSVGStylable          : false,\n
\tSVGStyleElement      : false,\n
\tSVGSwitchElement     : false,\n
\tSVGSymbolElement     : false,\n
\tSVGTRefElement       : false,\n
\tSVGTSpanElement      : false,\n
\tSVGTests             : false,\n
\tSVGTextContentElement: false,\n
\tSVGTextElement       : false,\n
\tSVGTextPathElement   : false,\n
\tSVGTextPositioningElement: false,\n
\tSVGTitleElement      : false,\n
\tSVGTransform         : false,\n
\tSVGTransformList     : false,\n
\tSVGTransformable     : false,\n
\tSVGURIReference      : false,\n
\tSVGUnitTypes         : false,\n
\tSVGUseElement        : false,\n
\tSVGVKernElement      : false,\n
\tSVGViewElement       : false,\n
\tSVGViewSpec          : false,\n
\tSVGZoomAndPan        : false,\n
\tTimeEvent            : false,\n
\ttop                  : false,\n
\tUint16Array          : false,\n
\tUint32Array          : false,\n
\tUint8Array           : false,\n
\tUint8ClampedArray    : false,\n
\tWebSocket            : false,\n
\twindow               : false,\n
\tWorker               : false,\n
\tXMLHttpRequest       : false,\n
\tXMLSerializer        : false,\n
\tXPathEvaluator       : false,\n
\tXPathException       : false,\n
\tXPathExpression      : false,\n
\tXPathNamespace       : false,\n
\tXPathNSResolver      : false,\n
\tXPathResult          : false\n
};\n
\n
exports.devel = {\n
\talert  : false,\n
\tconfirm: false,\n
\tconsole: false,\n
\tDebug  : false,\n
\topera  : false,\n
\tprompt : false\n
};\n
\n
exports.worker = {\n
\timportScripts: true,\n
\tpostMessage  : true,\n
\tself         : true\n
};\n
exports.nonstandard = {\n
\tescape  : false,\n
\tunescape: false\n
};\n
\n
exports.couch = {\n
\t"require" : false,\n
\trespond   : false,\n
\tgetRow    : false,\n
\temit      : false,\n
\tsend      : false,\n
\tstart     : false,\n
\tsum       : false,\n
\tlog       : false,\n
\texports   : false,\n
\tmodule    : false,\n
\tprovides  : false\n
};\n
\n
exports.node = {\n
\t__filename    : false,\n
\t__dirname     : false,\n
\tBuffer        : false,\n
\tDataView      : false,\n
\tconsole       : false,\n
\texports       : true,  // In Node it is ok to exports = module.exports = foo();\n
\tGLOBAL        : false,\n
\tglobal        : false,\n
\tmodule        : false,\n
\tprocess       : false,\n
\trequire       : false,\n
\tsetTimeout    : false,\n
\tclearTimeout  : false,\n
\tsetInterval   : false,\n
\tclearInterval : false,\n
\tsetImmediate  : false, // v0.9.1+\n
\tclearImmediate: false  // v0.9.1+\n
};\n
\n
exports.phantom = {\n
\tphantom      : true,\n
\trequire      : true,\n
\tWebPage      : true\n
};\n
\n
exports.rhino = {\n
\tdefineClass  : false,\n
\tdeserialize  : false,\n
\tgc           : false,\n
\thelp         : false,\n
\timportPackage: false,\n
\t"java"       : false,\n
\tload         : false,\n
\tloadClass    : false,\n
\tprint        : false,\n
\tquit         : false,\n
\treadFile     : false,\n
\treadUrl      : false,\n
\trunCommand   : false,\n
\tseal         : false,\n
\tserialize    : false,\n
\tspawn        : false,\n
\tsync         : false,\n
\ttoint32      : false,\n
\tversion      : false\n
};\n
\n
exports.shelljs = {\n
\ttarget       : false,\n
\techo         : false,\n
\texit         : false,\n
\tcd           : false,\n
\tpwd          : false,\n
\tls           : false,\n
\tfind         : false,\n
\tcp           : false,\n
\trm           : false,\n
\tmv           : false,\n
\tmkdir        : false,\n
\ttest         : false,\n
\tcat          : false,\n
\tsed          : false,\n
\tgrep         : false,\n
\twhich        : false,\n
\tdirs         : false,\n
\tpushd        : false,\n
\tpopd         : false,\n
\tenv          : false,\n
\texec         : false,\n
\tchmod        : false,\n
\tconfig       : false,\n
\terror        : false,\n
\ttempdir      : false\n
};\n
\n
exports.wsh = {\n
\tActiveXObject            : true,\n
\tEnumerator               : true,\n
\tGetObject                : true,\n
\tScriptEngine             : true,\n
\tScriptEngineBuildVersion : true,\n
\tScriptEngineMajorVersion : true,\n
\tScriptEngineMinorVersion : true,\n
\tVBArray                  : true,\n
\tWSH                      : true,\n
\tWScript                  : true,\n
\tXDomainRequest           : true\n
};\n
\n
exports.dojo = {\n
\tdojo     : false,\n
\tdijit    : false,\n
\tdojox    : false,\n
\tdefine\t : false,\n
\t"require": false\n
};\n
\n
exports.jquery = {\n
\t"$"    : false,\n
\tjQuery : false\n
};\n
\n
exports.mootools = {\n
\t"$"           : false,\n
\t"$$"          : false,\n
\tAsset         : false,\n
\tBrowser       : false,\n
\tChain         : false,\n
\tClass         : false,\n
\tColor         : false,\n
\tCookie        : false,\n
\tCore          : false,\n
\tDocument      : false,\n
\tDomReady      : false,\n
\tDOMEvent      : false,\n
\tDOMReady      : false,\n
\tDrag          : false,\n
\tElement       : false,\n
\tElements      : false,\n
\tEvent         : false,\n
\tEvents        : false,\n
\tFx            : false,\n
\tGroup         : false,\n
\tHash          : false,\n
\tHtmlTable     : false,\n
\tIframe        : false,\n
\tIframeShim    : false,\n
\tInputValidator: false,\n
\tinstanceOf    : false,\n
\tKeyboard      : false,\n
\tLocale        : false,\n
\tMask          : false,\n
\tMooTools      : false,\n
\tNative        : false,\n
\tOptions       : false,\n
\tOverText      : false,\n
\tRequest       : false,\n
\tScroller      : false,\n
\tSlick         : false,\n
\tSlider        : false,\n
\tSortables     : false,\n
\tSpinner       : false,\n
\tSwiff         : false,\n
\tTips          : false,\n
\tType          : false,\n
\ttypeOf        : false,\n
\tURI           : false,\n
\tWindow        : false\n
};\n
\n
exports.prototypejs = {\n
\t"$"               : false,\n
\t"$$"              : false,\n
\t"$A"              : false,\n
\t"$F"              : false,\n
\t"$H"              : false,\n
\t"$R"              : false,\n
\t"$break"          : false,\n
\t"$continue"       : false,\n
\t"$w"              : false,\n
\tAbstract          : false,\n
\tAjax              : false,\n
\tClass             : false,\n
\tEnumerable        : false,\n
\tElement           : false,\n
\tEvent             : false,\n
\tField             : false,\n
\tForm              : false,\n
\tHash              : false,\n
\tInsertion         : false,\n
\tObjectRange       : false,\n
\tPeriodicalExecuter: false,\n
\tPosition          : false,\n
\tPrototype         : false,\n
\tSelector          : false,\n
\tTemplate          : false,\n
\tToggle            : false,\n
\tTry               : false,\n
\tAutocompleter     : false,\n
\tBuilder           : false,\n
\tControl           : false,\n
\tDraggable         : false,\n
\tDraggables        : false,\n
\tDroppables        : false,\n
\tEffect            : false,\n
\tSortable          : false,\n
\tSortableObserver  : false,\n
\tSound             : false,\n
\tScriptaculous     : false\n
};\n
\n
exports.yui = {\n
\tYUI       : false,\n
\tY         : false,\n
\tYUI_config: false\n
};\n
\n
\n
},\n
{}],\n
"n4bKNg":[function(req,module,exports){\n
\n
var _        = req("underscore");\n
var events   = req("events");\n
var vars     = req("../shared/vars.js");\n
var messages = req("../shared/messages.js");\n
var Lexer    = req("./lex.js").Lexer;\n
var reg      = req("./reg.js");\n
var state    = req("./state.js").state;\n
var style    = req("./style.js");\n
var console = req("console-browserify");\n
\n
var JSHINT = (function () {\n
\t\n
\n
\tvar anonname, // The guessed name for anonymous functions.\n
\t\tapi, // Extension API\n
\t\tbang = {\n
\t\t\t"<"  : true,\n
\t\t\t"<=" : true,\n
\t\t\t"==" : true,\n
\t\t\t"===": true,\n
\t\t\t"!==": true,\n
\t\t\t"!=" : true,\n
\t\t\t">"  : true,\n
\t\t\t">=" : true,\n
\t\t\t"+"  : true,\n
\t\t\t"-"  : true,\n
\t\t\t"*"  : true,\n
\t\t\t"/"  : true,\n
\t\t\t"%"  : true\n
\t\t},\n
\t\tboolOptions = {\n
\t\t\tasi         : true, // if automatic semicolon insertion should be tolerated\n
\t\t\tbitwise     : true, // if bitwise operators should not be allowed\n
\t\t\tboss        : true, // if advanced usage of assignments should be allowed\n
\t\t\tbrowser     : true, // if the standard browser globals should be predefined\n
\t\t\tcamelcase   : true, // if identifiers should be required in camel case\n
\t\t\tcouch       : true, // if CouchDB globals should be predefined\n
\t\t\tcurly       : true, // if curly braces around all blocks should be required\n
\t\t\tdebug       : true, // if debugger statements should be allowed\n
\t\t\tdevel       : true, // if logging globals should be predefined (console, alert, etc.)\n
\t\t\tdojo        : true, // if Dojo Toolkit globals should be predefined\n
\t\t\teqeqeq      : true, // if === should be required\n
\t\t\teqnull      : true, // if == null comparisons should be tolerated\n
\t\t\tes3         : true, // if ES3 syntax should be allowed\n
\t\t\tes5         : true, // if ES5 syntax should be allowed (is now set per default)\n
\t\t\tesnext      : true, // if es.next specific syntax should be allowed\n
\t\t\tmoz         : true, // if mozilla specific syntax should be allowed\n
\t\t\tevil        : true, // if eval should be allowed\n
\t\t\texpr        : true, // if ExpressionStatement should be allowed as Programs\n
\t\t\tforin       : true, // if for in statements must filter\n
\t\t\tfuncscope   : true, // if only function scope should be used for scope tests\n
\t\t\tgcl         : true, // if JSHint should be compatible with Google Closure Linter\n
\t\t\tglobalstrict: true, // if global  should be allowed (also enables \'strict\')\n
\t\t\timmed       : true, // if immediate invocations must be wrapped in parens\n
\t\t\titerator    : true, // if the `__iterator__` property should be allowed\n
\t\t\tjquery      : true, // if jQuery globals should be predefined\n
\t\t\tlastsemic   : true, // if semicolons may be ommitted for the trailing\n
\t\t\tlaxbreak    : true, // if line breaks should not be checked\n
\t\t\tlaxcomma    : true, // if line breaks should not be checked around commas\n
\t\t\tloopfunc    : true, // if functions should be allowed to be defined within\n
\t\t\tmootools    : true, // if MooTools globals should be predefined\n
\t\t\tmultistr    : true, // allow multiline strings\n
\t\t\tnewcap      : true, // if constructor names must be capitalized\n
\t\t\tnoarg       : true, // if arguments.caller and arguments.callee should be\n
\t\t\tnode        : true, // if the Node.js environment globals should be\n
\t\t\tnoempty     : true, // if empty blocks should be disallowed\n
\t\t\tnonew       : true, // if using `new` for side-effects should be disallowed\n
\t\t\tnonstandard : true, // if non-standard (but widely adopted) globals should\n
\t\t\tnomen       : true, // if names should be checked\n
\t\t\tonevar      : true, // if only one var statement per function should be\n
\t\t\tpassfail    : true, // if the scan should stop on first error\n
\t\t\tphantom     : true, // if PhantomJS symbols should be allowed\n
\t\t\tplusplus    : true, // if increment/decrement should not be allowed\n
\t\t\tproto       : true, // if the `__proto__` property should be allowed\n
\t\t\tprototypejs : true, // if Prototype and Scriptaculous globals should be\n
\t\t\trhino       : true, // if the Rhino environment globals should be predefined\n
\t\t\tshelljs     : true, // if ShellJS globals should be predefined\n
\t\t\tundef       : true, // if variables should be declared before used\n
\t\t\tscripturl   : true, // if script-targeted URLs should be tolerated\n
\t\t\tshadow      : true, // if variable shadowing should be tolerated\n
\t\t\tsmarttabs   : true, // if smarttabs should be tolerated\n
\t\t\tstrict      : true, // require the  pragma\n
\t\t\tsub         : true, // if all forms of subscript notation are tolerated\n
\t\t\tsupernew    : true, // if `new function () { ... };` and `new Object;`\n
\t\t\ttrailing    : true, // if trailing whitespace rules apply\n
\t\t\tvalidthis   : true, // if \'this\' inside a non-constructor function is valid.\n
\t\t\twithstmt    : true, // if with statements should be allowed\n
\t\t\twhite       : true, // if strict whitespace rules apply\n
\t\t\tworker      : true, // if Web Worker script symbols should be allowed\n
\t\t\twsh         : true, // if the Windows Scripting Host environment globals\n
\t\t\tyui         : true, // YUI variables should be predefined\n
\t\t\tonecase     : true, // if one case switch statements should be allowed\n
\t\t\tregexp      : true, // if the . should not be allowed in regexp literals\n
\t\t\tregexdash   : true  // if unescaped first/last dash (-) inside brackets\n
\t\t},\n
\t\tvalOptions = {\n
\t\t\tmaxlen       : false,\n
\t\t\tindent       : false,\n
\t\t\tmaxerr       : false,\n
\t\t\tpredef       : false,\n
\t\t\tquotmark     : false, //\'single\'|\'double\'|true\n
\t\t\tscope        : false,\n
\t\t\tmaxstatements: false, // {int} max statements per function\n
\t\t\tmaxdepth     : false, // {int} max nested block depth per function\n
\t\t\tmaxparams    : false, // {int} max params per function\n
\t\t\tmaxcomplexity: false, // {int} max cyclomatic complexity per function\n
\t\t\tunused       : true,  // warn if variables are unused. Available options:\n
\t\t\tlatedef      : false  // warn if the variable is used before its definition\n
\t\t},\n
\t\tinvertedOptions = {\n
\t\t\tbitwise : true,\n
\t\t\tforin   : true,\n
\t\t\tnewcap  : true,\n
\t\t\tnomen   : true,\n
\t\t\tplusplus: true,\n
\t\t\tregexp  : true,\n
\t\t\tundef   : true,\n
\t\t\twhite   : true,\n
\t\t\teqeqeq  : true,\n
\t\t\tonevar  : true,\n
\t\t\tstrict  : true\n
\t\t},\n
\t\trenamedOptions = {\n
\t\t\teqeq   : "eqeqeq",\n
\t\t\tvars   : "onevar",\n
\t\t\twindows: "wsh",\n
\t\t\tsloppy : "strict"\n
\t\t},\n
\n
\t\tdeclared, // Globals that were declared using /*global ... */ syntax.\n
\t\texported, // Variables that are used outside of the current file.\n
\n
\t\tfunctionicity = [\n
\t\t\t"closure", "exception", "global", "label",\n
\t\t\t"outer", "unused", "var"\n
\t\t],\n
\n
\t\tfunct, // The current function\n
\t\tfunctions, // All of the functions\n
\n
\t\tglobal, // The global scope\n
\t\timplied, // Implied globals\n
\t\tinblock,\n
\t\tindent,\n
\t\tlookahead,\n
\t\tlex,\n
\t\tmember,\n
\t\tmembersOnly,\n
\t\tnoreach,\n
\t\tpredefined,\t\t// Global variables defined by option\n
\n
\t\tscope,  // The current scope\n
\t\tstack,\n
\t\tunuseds,\n
\t\turls,\n
\t\twarnings,\n
\n
\t\textraModules = [],\n
\t\temitter = new events.EventEmitter();\n
\n
\tfunction checkOption(name, t) {\n
\t\tname = name.trim();\n
\n
\t\tif (/^[+-]W\\d{3}$/g.test(name)) {\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\tif (valOptions[name] === undefined && boolOptions[name] === undefined) {\n
\t\t\tif (t.type !== "jslint") {\n
\t\t\t\terror("E001", t, name);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn true;\n
\t}\n
\n
\tfunction isString(obj) {\n
\t\treturn Object.prototype.toString.call(obj) === "[object String]";\n
\t}\n
\n
\tfunction isIdentifier(tkn, value) {\n
\t\tif (!tkn)\n
\t\t\treturn false;\n
\n
\t\tif (!tkn.identifier || tkn.value !== value)\n
\t\t\treturn false;\n
\n
\t\treturn true;\n
\t}\n
\n
\tfunction isReserved(token) {\n
\t\tif (!token.reserved) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tvar meta = token.meta;\n
\n
\t\tif (meta && meta.isFutureReservedWord && state.option.inES5()) {\n
\t\t\tif (!meta.es5) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tif (meta.strictOnly) {\n
\t\t\t\tif (!state.option.strict && !state.directive["use strict"]) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (token.isProperty) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn true;\n
\t}\n
\n
\tfunction supplant(str, data) {\n
\t\treturn str.replace(/\\{([^{}]*)\\}/g, function (a, b) {\n
\t\t\tvar r = data[b];\n
\t\t\treturn typeof r === "string" || typeof r === "number" ? r : a;\n
\t\t});\n
\t}\n
\n
\tfunction combine(t, o) {\n
\t\tvar n;\n
\t\tfor (n in o) {\n
\t\t\tif (_.has(o, n) && !_.has(JSHINT.blacklist, n)) {\n
\t\t\t\tt[n] = o[n];\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction updatePredefined() {\n
\t\tObject.keys(JSHINT.blacklist).forEach(function (key) {\n
\t\t\tdelete predefined[key];\n
\t\t});\n
\t}\n
\n
\tfunction assume() {\n
\t\tif (state.option.couch) {\n
\t\t\tcombine(predefined, vars.couch);\n
\t\t}\n
\n
\t\tif (state.option.rhino) {\n
\t\t\tcombine(predefined, vars.rhino);\n
\t\t}\n
\n
\t\tif (state.option.shelljs) {\n
\t\t\tcombine(predefined, vars.shelljs);\n
\t\t\tcombine(predefined, vars.node);\n
\t\t}\n
\n
\t\tif (state.option.phantom) {\n
\t\t\tcombine(predefined, vars.phantom);\n
\t\t}\n
\n
\t\tif (state.option.prototypejs) {\n
\t\t\tcombine(predefined, vars.prototypejs);\n
\t\t}\n
\n
\t\tif (state.option.node) {\n
\t\t\tcombine(predefined, vars.node);\n
\t\t}\n
\n
\t\tif (state.option.devel) {\n
\t\t\tcombine(predefined, vars.devel);\n
\t\t}\n
\n
\t\tif (state.option.dojo) {\n
\t\t\tcombine(predefined, vars.dojo);\n
\t\t}\n
\n
\t\tif (state.option.browser) {\n
\t\t\tcombine(predefined, vars.browser);\n
\t\t}\n
\n
\t\tif (state.option.nonstandard) {\n
\t\t\tcombine(predefined, vars.nonstandard);\n
\t\t}\n
\n
\t\tif (state.option.jquery) {\n
\t\t\tcombine(predefined, vars.jquery);\n
\t\t}\n
\n
\t\tif (state.option.mootools) {\n
\t\t\tcombine(predefined, vars.mootools);\n
\t\t}\n
\n
\t\tif (state.option.worker) {\n
\t\t\tcombine(predefined, vars.worker);\n
\t\t}\n
\n
\t\tif (state.option.wsh) {\n
\t\t\tcombine(predefined, vars.wsh);\n
\t\t}\n
\n
\t\tif (state.option.globalstrict && state.option.strict !== false) {\n
\t\t\tstate.option.strict = true;\n
\t\t}\n
\n
\t\tif (state.option.yui) {\n
\t\t\tcombine(predefined, vars.yui);\n
\t\t}\n
\n
\t\tstate.option.inMoz = function (strict) {\n
\t\t\treturn state.option.moz;\n
\t\t};\n
\n
\t\tstate.option.inESNext = function (strict) {\n
\t\t\treturn state.option.moz || state.option.esnext;\n
\t\t};\n
\n
\t\tstate.option.inES5 = function (/* strict */) {\n
\t\t\treturn !state.option.es3;\n
\t\t};\n
\n
\t\tstate.option.inES3 = function (strict) {\n
\t\t\tif (strict) {\n
\t\t\t\treturn !state.option.moz && !state.option.esnext && state.option.es3;\n
\t\t\t}\n
\t\t\treturn state.option.es3;\n
\t\t};\n
\t}\n
\tfunction quit(code, line, chr) {\n
\t\tvar percentage = Math.floor((line / state.lines.length) * 100);\n
\t\tvar message = messages.errors[code].desc;\n
\n
\t\tthrow {\n
\t\t\tname: "JSHintError",\n
\t\t\tline: line,\n
\t\t\tcharacter: chr,\n
\t\t\tmessage: message + " (" + percentage + "% scanned).",\n
\t\t\traw: message,\n
\t\t\tcode: code\n
\t\t};\n
\t}\n
\n
\tfunction isundef(scope, code, token, a) {\n
\t\treturn JSHINT.undefs.push([scope, code, token, a]);\n
\t}\n
\n
\tfunction warning(code, t, a, b, c, d) {\n
\t\tvar ch, l, w, msg;\n
\n
\t\tif (/^W\\d{3}$/.test(code)) {\n
\t\t\tif (state.ignored[code])\n
\t\t\t\treturn;\n
\n
\t\t\tmsg = messages.warnings[code];\n
\t\t} else if (/E\\d{3}/.test(code)) {\n
\t\t\tmsg = messages.errors[code];\n
\t\t} else if (/I\\d{3}/.test(code)) {\n
\t\t\tmsg = messages.info[code];\n
\t\t}\n
\n
\t\tt = t || state.tokens.next;\n
\t\tif (t.id === "(end)") {  // `~\n
\t\t\tt = state.tokens.curr;\n
\t\t}\n
\n
\t\tl = t.line || 0;\n
\t\tch = t.from || 0;\n
\n
\t\tw = {\n
\t\t\tid: "(error)",\n
\t\t\traw: msg.desc,\n
\t\t\tcode: msg.code,\n
\t\t\tevidence: state.lines[l - 1] || "",\n
\t\t\tline: l,\n
\t\t\tcharacter: ch,\n
\t\t\tscope: JSHINT.scope,\n
\t\t\ta: a,\n
\t\t\tb: b,\n
\t\t\tc: c,\n
\t\t\td: d\n
\t\t};\n
\n
\t\tw.reason = supplant(msg.desc, w);\n
\t\tJSHINT.errors.push(w);\n
\n
\t\tif (state.option.passfail) {\n
\t\t\tquit("E042", l, ch);\n
\t\t}\n
\n
\t\twarnings += 1;\n
\t\tif (warnings >= state.option.maxerr) {\n
\t\t\tquit("E043", l, ch);\n
\t\t}\n
\n
\t\treturn w;\n
\t}\n
\n
\tfunction warningAt(m, l, ch, a, b, c, d) {\n
\t\treturn warning(m, {\n
\t\t\tline: l,\n
\t\t\tfrom: ch\n
\t\t}, a, b, c, d);\n
\t}\n
\n
\tfunction error(m, t, a, b, c, d) {\n
\t\twarning(m, t, a, b, c, d);\n
\t}\n
\n
\tfunction errorAt(m, l, ch, a, b, c, d) {\n
\t\treturn error(m, {\n
\t\t\tline: l,\n
\t\t\tfrom: ch\n
\t\t}, a, b, c, d);\n
\t}\n
\tfunction addInternalSrc(elem, src) {\n
\t\tvar i;\n
\t\ti = {\n
\t\t\tid: "(internal)",\n
\t\t\telem: elem,\n
\t\t\tvalue: src\n
\t\t};\n
\t\tJSHINT.internals.push(i);\n
\t\treturn i;\n
\t}\n
\n
\tfunction addlabel(t, type, tkn, islet) {\n
\t\tif (type === "exception") {\n
\t\t\tif (_.has(funct["(context)"], t)) {\n
\t\t\t\tif (funct[t] !== true && !state.option.node) {\n
\t\t\t\t\twarning("W002", state.tokens.next, t);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (_.has(funct, t) && !funct["(global)"]) {\n
\t\t\tif (funct[t] === true) {\n
\t\t\t\tif (state.option.latedef) {\n
\t\t\t\t\tif ((state.option.latedef === true && _.contains([funct[t], type], "unction")) ||\n
\t\t\t\t\t\t\t!_.contains([funct[t], type], "unction")) {\n
\t\t\t\t\t\twarning("W003", state.tokens.next, t);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tif (!state.option.shadow && type !== "exception" ||\n
\t\t\t\t\t\t\t(funct["(blockscope)"].getlabel(t))) {\n
\t\t\t\t\twarning("W004", state.tokens.next, t);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tif (funct["(blockscope)"] && funct["(blockscope)"].current.has(t)) {\n
\t\t\terror("E044", state.tokens.next, t);\n
\t\t}\n
\t\tif (islet) {\n
\t\t\tfunct["(blockscope)"].current.add(t, type, state.tokens.curr);\n
\t\t} else {\n
\n
\t\t\tfunct[t] = type;\n
\n
\t\t\tif (tkn) {\n
\t\t\t\tfunct["(tokens)"][t] = tkn;\n
\t\t\t}\n
\n
\t\t\tif (funct["(global)"]) {\n
\t\t\t\tglobal[t] = funct;\n
\t\t\t\tif (_.has(implied, t)) {\n
\t\t\t\t\tif (state.option.latedef) {\n
\t\t\t\t\t\tif ((state.option.latedef === true && _.contains([funct[t], type], "unction")) ||\n
\t\t\t\t\t\t\t\t!_.contains([funct[t], type], "unction")) {\n
\t\t\t\t\t\t\twarning("W003", state.tokens.next, t);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tdelete implied[t];\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tscope[t] = funct;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction doOption() {\n
\t\tvar nt = state.tokens.next;\n
\t\tvar body = nt.body.match(/(-\\s+)?[^\\s,]+(?:\\s*:\\s*(-\\s+)?[^\\s,]+)?/g);\n
\t\tvar predef = {};\n
\n
\t\tif (nt.type === "globals") {\n
\t\t\tbody.forEach(function (g) {\n
\t\t\t\tg = g.split(":");\n
\t\t\t\tvar key = (g[0] || "").trim();\n
\t\t\t\tvar val = (g[1] || "").trim();\n
\n
\t\t\t\tif (key.charAt(0) === "-") {\n
\t\t\t\t\tkey = key.slice(1);\n
\t\t\t\t\tval = false;\n
\n
\t\t\t\t\tJSHINT.blacklist[key] = key;\n
\t\t\t\t\tupdatePredefined();\n
\t\t\t\t} else {\n
\t\t\t\t\tpredef[key] = (val === "true");\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\tcombine(predefined, predef);\n
\n
\t\t\tfor (var key in predef) {\n
\t\t\t\tif (_.has(predef, key)) {\n
\t\t\t\t\tdeclared[key] = nt;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (nt.type === "exported") {\n
\t\t\tbody.forEach(function (e) {\n
\t\t\t\texported[e] = true;\n
\t\t\t});\n
\t\t}\n
\n
\t\tif (nt.type === "members") {\n
\t\t\tmembersOnly = membersOnly || {};\n
\n
\t\t\tbody.forEach(function (m) {\n
\t\t\t\tvar ch1 = m.charAt(0);\n
\t\t\t\tvar ch2 = m.charAt(m.length - 1);\n
\n
\t\t\t\tif (ch1 === ch2 && (ch1 === "\\"" || ch1 === "\'")) {\n
\t\t\t\t\tm = m\n
\t\t\t\t\t\t.substr(1, m.length - 2)\n
\t\t\t\t\t\t.replace("\\\\b", "\\b")\n
\t\t\t\t\t\t.replace("\\\\t", "\\t")\n
\t\t\t\t\t\t.replace("\\\\n", "\\n")\n
\t\t\t\t\t\t.replace("\\\\v", "\\v")\n
\t\t\t\t\t\t.replace("\\\\f", "\\f")\n
\t\t\t\t\t\t.replace("\\\\r", "\\r")\n
\t\t\t\t\t\t.replace("\\\\\\\\", "\\\\")\n
\t\t\t\t\t\t.replace("\\\\\\"", "\\"");\n
\t\t\t\t}\n
\n
\t\t\t\tmembersOnly[m] = false;\n
\t\t\t});\n
\t\t}\n
\n
\t\tvar numvals = [\n
\t\t\t"maxstatements",\n
\t\t\t"maxparams",\n
\t\t\t"maxdepth",\n
\t\t\t"maxcomplexity",\n
\t\t\t"maxerr",\n
\t\t\t"maxlen",\n
\t\t\t"indent"\n
\t\t];\n
\n
\t\tif (nt.type === "jshint" || nt.type === "jslint") {\n
\t\t\tbody.forEach(function (g) {\n
\t\t\t\tg = g.split(":");\n
\t\t\t\tvar key = (g[0] || "").trim();\n
\t\t\t\tvar val = (g[1] || "").trim();\n
\n
\t\t\t\tif (!checkOption(key, nt)) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (numvals.indexOf(key) >= 0) {\n
\t\t\t\t\tif (val !== "false") {\n
\t\t\t\t\t\tval = +val;\n
\n
\t\t\t\t\t\tif (typeof val !== "number" || !isFinite(val) || val <= 0 || Math.floor(val) !== val) {\n
\t\t\t\t\t\t\terror("E032", nt, g[1].trim());\n
\t\t\t\t\t\t\treturn;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tif (key === "indent") {\n
\t\t\t\t\t\t\tstate.option["(explicitIndent)"] = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tstate.option[key] = val;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif (key === "indent") {\n
\t\t\t\t\t\t\tstate.option["(explicitIndent)"] = false;\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tstate.option[key] = false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (key === "validthis") {\n
\t\t\t\t\tif (funct["(global)"]) {\n
\t\t\t\t\t\terror("E009");\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif (val === "true" || val === "false") {\n
\t\t\t\t\t\t\tstate.option.validthis = (val === "true");\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\terror("E002", nt);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (key === "quotmark") {\n
\t\t\t\t\tswitch (val) {\n
\t\t\t\t\tcase "true":\n
\t\t\t\t\tcase "false":\n
\t\t\t\t\t\tstate.option.quotmark = (val === "true");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "double":\n
\t\t\t\t\tcase "single":\n
\t\t\t\t\t\tstate.option.quotmark = val;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\terror("E002", nt);\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (key === "unused") {\n
\t\t\t\t\tswitch (val) {\n
\t\t\t\t\tcase "true":\n
\t\t\t\t\t\tstate.option.unused = true;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "false":\n
\t\t\t\t\t\tstate.option.unused = false;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "vars":\n
\t\t\t\t\tcase "strict":\n
\t\t\t\t\t\tstate.option.unused = val;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\terror("E002", nt);\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (key === "latedef") {\n
\t\t\t\t\tswitch (val) {\n
\t\t\t\t\tcase "true":\n
\t\t\t\t\t\tstat

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

e.option.latedef = true;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "false":\n
\t\t\t\t\t\tstate.option.latedef = false;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "nofunc":\n
\t\t\t\t\t\tstate.option.latedef = "nofunc";\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\terror("E002", nt);\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tvar match = /^([+-])(W\\d{3})$/g.exec(key);\n
\t\t\t\tif (match) {\n
\t\t\t\t\tstate.ignored[match[2]] = (match[1] === "-");\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tvar tn;\n
\t\t\t\tif (val === "true" || val === "false") {\n
\t\t\t\t\tif (nt.type === "jslint") {\n
\t\t\t\t\t\ttn = renamedOptions[key] || key;\n
\t\t\t\t\t\tstate.option[tn] = (val === "true");\n
\n
\t\t\t\t\t\tif (invertedOptions[tn] !== undefined) {\n
\t\t\t\t\t\t\tstate.option[tn] = !state.option[tn];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tstate.option[key] = (val === "true");\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif (key === "newcap") {\n
\t\t\t\t\t\tstate.option["(explicitNewcap)"] = true;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\terror("E002", nt);\n
\t\t\t});\n
\n
\t\t\tassume();\n
\t\t}\n
\t}\n
\n
\tfunction peek(p) {\n
\t\tvar i = p || 0, j = 0, t;\n
\n
\t\twhile (j <= i) {\n
\t\t\tt = lookahead[j];\n
\t\t\tif (!t) {\n
\t\t\t\tt = lookahead[j] = lex.token();\n
\t\t\t}\n
\t\t\tj += 1;\n
\t\t}\n
\t\treturn t;\n
\t}\n
\n
\tfunction advance(id, t) {\n
\t\tswitch (state.tokens.curr.id) {\n
\t\tcase "(number)":\n
\t\t\tif (state.tokens.next.id === ".") {\n
\t\t\t\twarning("W005", state.tokens.curr);\n
\t\t\t}\n
\t\t\tbreak;\n
\t\tcase "-":\n
\t\t\tif (state.tokens.next.id === "-" || state.tokens.next.id === "--") {\n
\t\t\t\twarning("W006");\n
\t\t\t}\n
\t\t\tbreak;\n
\t\tcase "+":\n
\t\t\tif (state.tokens.next.id === "+" || state.tokens.next.id === "++") {\n
\t\t\t\twarning("W007");\n
\t\t\t}\n
\t\t\tbreak;\n
\t\t}\n
\n
\t\tif (state.tokens.curr.type === "(string)" || state.tokens.curr.identifier) {\n
\t\t\tanonname = state.tokens.curr.value;\n
\t\t}\n
\n
\t\tif (id && state.tokens.next.id !== id) {\n
\t\t\tif (t) {\n
\t\t\t\tif (state.tokens.next.id === "(end)") {\n
\t\t\t\t\terror("E019", t, t.id);\n
\t\t\t\t} else {\n
\t\t\t\t\terror("E020", state.tokens.next, id, t.id, t.line, state.tokens.next.value);\n
\t\t\t\t}\n
\t\t\t} else if (state.tokens.next.type !== "(identifier)" || state.tokens.next.value !== id) {\n
\t\t\t\twarning("W116", state.tokens.next, id, state.tokens.next.value);\n
\t\t\t}\n
\t\t}\n
\n
\t\tstate.tokens.prev = state.tokens.curr;\n
\t\tstate.tokens.curr = state.tokens.next;\n
\t\tfor (;;) {\n
\t\t\tstate.tokens.next = lookahead.shift() || lex.token();\n
\n
\t\t\tif (!state.tokens.next) { // No more tokens left, give up\n
\t\t\t\tquit("E041", state.tokens.curr.line);\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id === "(end)" || state.tokens.next.id === "(error)") {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.check) {\n
\t\t\t\tstate.tokens.next.check();\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.isSpecial) {\n
\t\t\t\tdoOption();\n
\t\t\t} else {\n
\t\t\t\tif (state.tokens.next.id !== "(endline)") {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction isInfix(token) {\n
\t\treturn token.infix || (!token.identifier && !!token.led);\n
\t}\n
\n
\tfunction isEndOfExpr() {\n
\t\tvar curr = state.tokens.curr;\n
\t\tvar next = state.tokens.next;\n
\t\tif (next.id === ";" || next.id === "}" || next.id === ":") {\n
\t\t\treturn true;\n
\t\t}\n
\t\tif (isInfix(next) === isInfix(curr) || (curr.id === "yield" && state.option.inMoz(true))) {\n
\t\t\treturn curr.line !== next.line;\n
\t\t}\n
\t\treturn false;\n
\t}\n
\n
\tfunction expression(rbp, initial) {\n
\t\tvar left, isArray = false, isObject = false, isLetExpr = false;\n
\t\tif (!initial && state.tokens.next.value === "let" && peek(0).value === "(") {\n
\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\twarning("W118", state.tokens.next, "let expressions");\n
\t\t\t}\n
\t\t\tisLetExpr = true;\n
\t\t\tfunct["(blockscope)"].stack();\n
\t\t\tadvance("let");\n
\t\t\tadvance("(");\n
\t\t\tstate.syntax["let"].fud.call(state.syntax["let"].fud, false);\n
\t\t\tadvance(")");\n
\t\t}\n
\n
\t\tif (state.tokens.next.id === "(end)")\n
\t\t\terror("E006", state.tokens.curr);\n
\n
\t\tadvance();\n
\n
\t\tif (initial) {\n
\t\t\tanonname = "anonymous";\n
\t\t\tfunct["(verb)"] = state.tokens.curr.value;\n
\t\t}\n
\n
\t\tif (initial === true && state.tokens.curr.fud) {\n
\t\t\tleft = state.tokens.curr.fud();\n
\t\t} else {\n
\t\t\tif (state.tokens.curr.nud) {\n
\t\t\t\tleft = state.tokens.curr.nud();\n
\t\t\t} else {\n
\t\t\t\terror("E030", state.tokens.curr, state.tokens.curr.id);\n
\t\t\t}\n
\n
\t\t\twhile (rbp < state.tokens.next.lbp && !isEndOfExpr()) {\n
\t\t\t\tisArray = state.tokens.curr.value === "Array";\n
\t\t\t\tisObject = state.tokens.curr.value === "Object";\n
\t\t\t\tif (left && (left.value || (left.first && left.first.value))) {\n
\t\t\t\t\tif (left.value !== "new" ||\n
\t\t\t\t\t  (left.first && left.first.value && left.first.value === ".")) {\n
\t\t\t\t\t\tisArray = false;\n
\t\t\t\t\t\tif (left.value !== state.tokens.curr.value) {\n
\t\t\t\t\t\t\tisObject = false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tadvance();\n
\n
\t\t\t\tif (isArray && state.tokens.curr.id === "(" && state.tokens.next.id === ")") {\n
\t\t\t\t\twarning("W009", state.tokens.curr);\n
\t\t\t\t}\n
\n
\t\t\t\tif (isObject && state.tokens.curr.id === "(" && state.tokens.next.id === ")") {\n
\t\t\t\t\twarning("W010", state.tokens.curr);\n
\t\t\t\t}\n
\n
\t\t\t\tif (left && state.tokens.curr.led) {\n
\t\t\t\t\tleft = state.tokens.curr.led(left);\n
\t\t\t\t} else {\n
\t\t\t\t\terror("E033", state.tokens.curr, state.tokens.curr.id);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tif (isLetExpr) {\n
\t\t\tfunct["(blockscope)"].unstack();\n
\t\t}\n
\t\treturn left;\n
\t}\n
\n
\tfunction adjacent(left, right) {\n
\t\tleft = left || state.tokens.curr;\n
\t\tright = right || state.tokens.next;\n
\t\tif (state.option.white) {\n
\t\t\tif (left.character !== right.from && left.line === right.line) {\n
\t\t\t\tleft.from += (left.character - left.from);\n
\t\t\t\twarning("W011", left, left.value);\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction nobreak(left, right) {\n
\t\tleft = left || state.tokens.curr;\n
\t\tright = right || state.tokens.next;\n
\t\tif (state.option.white && (left.character !== right.from || left.line !== right.line)) {\n
\t\t\twarning("W012", right, right.value);\n
\t\t}\n
\t}\n
\n
\tfunction nospace(left, right) {\n
\t\tleft = left || state.tokens.curr;\n
\t\tright = right || state.tokens.next;\n
\t\tif (state.option.white && !left.comment) {\n
\t\t\tif (left.line === right.line) {\n
\t\t\t\tadjacent(left, right);\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction nonadjacent(left, right) {\n
\t\tif (state.option.white) {\n
\t\t\tleft = left || state.tokens.curr;\n
\t\t\tright = right || state.tokens.next;\n
\n
\t\t\tif (left.value === ";" && right.value === ";") {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif (left.line === right.line && left.character === right.from) {\n
\t\t\t\tleft.from += (left.character - left.from);\n
\t\t\t\twarning("W013", left, left.value);\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction nobreaknonadjacent(left, right) {\n
\t\tleft = left || state.tokens.curr;\n
\t\tright = right || state.tokens.next;\n
\t\tif (!state.option.laxbreak && left.line !== right.line) {\n
\t\t\twarning("W014", right, right.value);\n
\t\t} else if (state.option.white) {\n
\t\t\tleft = left || state.tokens.curr;\n
\t\t\tright = right || state.tokens.next;\n
\t\t\tif (left.character === right.from) {\n
\t\t\t\tleft.from += (left.character - left.from);\n
\t\t\t\twarning("W013", left, left.value);\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfunction indentation(bias) {\n
\t\tif (!state.option.white && !state.option["(explicitIndent)"]) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (state.tokens.next.id === "(end)") {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar i = indent + (bias || 0);\n
\t\tif (state.tokens.next.from !== i) {\n
\t\t\twarning("W015", state.tokens.next, state.tokens.next.value, i, state.tokens.next.from);\n
\t\t}\n
\t}\n
\n
\tfunction nolinebreak(t) {\n
\t\tt = t || state.tokens.curr;\n
\t\tif (t.line !== state.tokens.next.line) {\n
\t\t\twarning("E022", t, t.value);\n
\t\t}\n
\t}\n
\n
\tfunction nobreakcomma(left, right) {\n
\t\tif (left.line !== right.line) {\n
\t\t\tif (!state.option.laxcomma) {\n
\t\t\t\tif (comma.first) {\n
\t\t\t\t\twarning("I001");\n
\t\t\t\t\tcomma.first = false;\n
\t\t\t\t}\n
\t\t\t\twarning("W014", left, right.value);\n
\t\t\t}\n
\t\t} else if (!left.comment && left.character !== right.from && state.option.white) {\n
\t\t\tleft.from += (left.character - left.from);\n
\t\t\twarning("W011", left, left.value);\n
\t\t}\n
\t}\n
\n
\tfunction comma(opts) {\n
\t\topts = opts || {};\n
\n
\t\tif (!opts.peek) {\n
\t\t\tnobreakcomma(state.tokens.curr, state.tokens.next);\n
\t\t\tadvance(",");\n
\t\t} else {\n
\t\t\tnobreakcomma(state.tokens.prev, state.tokens.curr);\n
\t\t}\n
\n
\t\tif (state.tokens.next.value !== "]" && state.tokens.next.value !== "}") {\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t}\n
\n
\t\tif (state.tokens.next.identifier && !(opts.property && state.option.inES5())) {\n
\t\t\tswitch (state.tokens.next.value) {\n
\t\t\tcase "break":\n
\t\t\tcase "case":\n
\t\t\tcase "catch":\n
\t\t\tcase "continue":\n
\t\t\tcase "default":\n
\t\t\tcase "do":\n
\t\t\tcase "else":\n
\t\t\tcase "finally":\n
\t\t\tcase "for":\n
\t\t\tcase "if":\n
\t\t\tcase "in":\n
\t\t\tcase "instanceof":\n
\t\t\tcase "return":\n
\t\t\tcase "switch":\n
\t\t\tcase "throw":\n
\t\t\tcase "try":\n
\t\t\tcase "var":\n
\t\t\tcase "let":\n
\t\t\tcase "while":\n
\t\t\tcase "with":\n
\t\t\t\terror("E024", state.tokens.next, state.tokens.next.value);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (state.tokens.next.type === "(punctuator)") {\n
\t\t\tswitch (state.tokens.next.value) {\n
\t\t\tcase "}":\n
\t\t\tcase "]":\n
\t\t\tcase ",":\n
\t\t\t\tif (opts.allowTrailing) {\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\t\t\tcase ")":\n
\t\t\t\terror("E024", state.tokens.next, state.tokens.next.value);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\t\treturn true;\n
\t}\n
\n
\tfunction symbol(s, p) {\n
\t\tvar x = state.syntax[s];\n
\t\tif (!x || typeof x !== "object") {\n
\t\t\tstate.syntax[s] = x = {\n
\t\t\t\tid: s,\n
\t\t\t\tlbp: p,\n
\t\t\t\tvalue: s\n
\t\t\t};\n
\t\t}\n
\t\treturn x;\n
\t}\n
\n
\tfunction delim(s) {\n
\t\treturn symbol(s, 0);\n
\t}\n
\n
\tfunction stmt(s, f) {\n
\t\tvar x = delim(s);\n
\t\tx.identifier = x.reserved = true;\n
\t\tx.fud = f;\n
\t\treturn x;\n
\t}\n
\n
\tfunction blockstmt(s, f) {\n
\t\tvar x = stmt(s, f);\n
\t\tx.block = true;\n
\t\treturn x;\n
\t}\n
\n
\tfunction reserveName(x) {\n
\t\tvar c = x.id.charAt(0);\n
\t\tif ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z")) {\n
\t\t\tx.identifier = x.reserved = true;\n
\t\t}\n
\t\treturn x;\n
\t}\n
\n
\tfunction prefix(s, f) {\n
\t\tvar x = symbol(s, 150);\n
\t\treserveName(x);\n
\t\tx.nud = (typeof f === "function") ? f : function () {\n
\t\t\tthis.right = expression(150);\n
\t\t\tthis.arity = "unary";\n
\t\t\tif (this.id === "++" || this.id === "--") {\n
\t\t\t\tif (state.option.plusplus) {\n
\t\t\t\t\twarning("W016", this, this.id);\n
\t\t\t\t} else if ((!this.right.identifier || isReserved(this.right)) &&\n
\t\t\t\t\t\tthis.right.id !== "." && this.right.id !== "[") {\n
\t\t\t\t\twarning("W017", this);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\tfunction type(s, f) {\n
\t\tvar x = delim(s);\n
\t\tx.type = s;\n
\t\tx.nud = f;\n
\t\treturn x;\n
\t}\n
\n
\tfunction reserve(name, func) {\n
\t\tvar x = type(name, func);\n
\t\tx.identifier = true;\n
\t\tx.reserved = true;\n
\t\treturn x;\n
\t}\n
\n
\tfunction FutureReservedWord(name, meta) {\n
\t\tvar x = type(name, (meta && meta.nud) || function () {\n
\t\t\treturn this;\n
\t\t});\n
\n
\t\tmeta = meta || {};\n
\t\tmeta.isFutureReservedWord = true;\n
\n
\t\tx.value = name;\n
\t\tx.identifier = true;\n
\t\tx.reserved = true;\n
\t\tx.meta = meta;\n
\n
\t\treturn x;\n
\t}\n
\n
\tfunction reservevar(s, v) {\n
\t\treturn reserve(s, function () {\n
\t\t\tif (typeof v === "function") {\n
\t\t\t\tv(this);\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t});\n
\t}\n
\n
\tfunction infix(s, f, p, w) {\n
\t\tvar x = symbol(s, p);\n
\t\treserveName(x);\n
\t\tx.infix = true;\n
\t\tx.led = function (left) {\n
\t\t\tif (!w) {\n
\t\t\t\tnobreaknonadjacent(state.tokens.prev, state.tokens.curr);\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t}\n
\t\t\tif (s === "in" && left.id === "!") {\n
\t\t\t\twarning("W018", left, "!");\n
\t\t\t}\n
\t\t\tif (typeof f === "function") {\n
\t\t\t\treturn f(left, this);\n
\t\t\t} else {\n
\t\t\t\tthis.left = left;\n
\t\t\t\tthis.right = expression(p);\n
\t\t\t\treturn this;\n
\t\t\t}\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\n
\tfunction application(s) {\n
\t\tvar x = symbol(s, 42);\n
\n
\t\tx.led = function (left) {\n
\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\twarning("W104", state.tokens.curr, "arrow function syntax (=>)");\n
\t\t\t}\n
\n
\t\t\tnobreaknonadjacent(state.tokens.prev, state.tokens.curr);\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\n
\t\t\tthis.left = left;\n
\t\t\tthis.right = doFunction(undefined, undefined, false, left);\n
\t\t\treturn this;\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\tfunction relation(s, f) {\n
\t\tvar x = symbol(s, 100);\n
\n
\t\tx.led = function (left) {\n
\t\t\tnobreaknonadjacent(state.tokens.prev, state.tokens.curr);\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tvar right = expression(100);\n
\n
\t\t\tif (isIdentifier(left, "NaN") || isIdentifier(right, "NaN")) {\n
\t\t\t\twarning("W019", this);\n
\t\t\t} else if (f) {\n
\t\t\t\tf.apply(this, [left, right]);\n
\t\t\t}\n
\n
\t\t\tif (!left || !right) {\n
\t\t\t\tquit("E041", state.tokens.curr.line);\n
\t\t\t}\n
\n
\t\t\tif (left.id === "!") {\n
\t\t\t\twarning("W018", left, "!");\n
\t\t\t}\n
\n
\t\t\tif (right.id === "!") {\n
\t\t\t\twarning("W018", right, "!");\n
\t\t\t}\n
\n
\t\t\tthis.left = left;\n
\t\t\tthis.right = right;\n
\t\t\treturn this;\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\tfunction isPoorRelation(node) {\n
\t\treturn node &&\n
\t\t\t  ((node.type === "(number)" && +node.value === 0) ||\n
\t\t\t   (node.type === "(string)" && node.value === "") ||\n
\t\t\t   (node.type === "null" && !state.option.eqnull) ||\n
\t\t\t\tnode.type === "true" ||\n
\t\t\t\tnode.type === "false" ||\n
\t\t\t\tnode.type === "undefined");\n
\t}\n
\n
\tfunction assignop(s, f, p) {\n
\t\tvar x = infix(s, typeof f === "function" ? f : function (left, that) {\n
\t\t\tthat.left = left;\n
\n
\t\t\tif (left) {\n
\t\t\t\tif (predefined[left.value] === false &&\n
\t\t\t\t\t\tscope[left.value]["(global)"] === true) {\n
\t\t\t\t\twarning("W020", left);\n
\t\t\t\t} else if (left["function"]) {\n
\t\t\t\t\twarning("W021", left, left.value);\n
\t\t\t\t}\n
\n
\t\t\t\tif (funct[left.value] === "const") {\n
\t\t\t\t\terror("E013", left, left.value);\n
\t\t\t\t}\n
\n
\t\t\t\tif (left.id === ".") {\n
\t\t\t\t\tif (!left.left) {\n
\t\t\t\t\t\twarning("E031", that);\n
\t\t\t\t\t} else if (left.left.value === "arguments" && !state.directive["use strict"]) {\n
\t\t\t\t\t\twarning("E031", that);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tthat.right = expression(10);\n
\t\t\t\t\treturn that;\n
\t\t\t\t} else if (left.id === "[") {\n
\t\t\t\t\tif (state.tokens.curr.left.first) {\n
\t\t\t\t\t\tstate.tokens.curr.left.first.forEach(function (t) {\n
\t\t\t\t\t\t\tif (funct[t.value] === "const") {\n
\t\t\t\t\t\t\t\terror("E013", t, t.value);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t} else if (!left.left) {\n
\t\t\t\t\t\twarning("E031", that);\n
\t\t\t\t\t} else if (left.left.value === "arguments" && !state.directive["use strict"]) {\n
\t\t\t\t\t\twarning("E031", that);\n
\t\t\t\t\t}\n
\t\t\t\t\tthat.right = expression(10);\n
\t\t\t\t\treturn that;\n
\t\t\t\t} else if (left.identifier && !isReserved(left)) {\n
\t\t\t\t\tif (funct[left.value] === "exception") {\n
\t\t\t\t\t\twarning("W022", left);\n
\t\t\t\t\t}\n
\t\t\t\t\tthat.right = expression(10);\n
\t\t\t\t\treturn that;\n
\t\t\t\t}\n
\n
\t\t\t\tif (left === state.syntax["function"]) {\n
\t\t\t\t\twarning("W023", state.tokens.curr);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\terror("E031", that);\n
\t\t}, p);\n
\n
\t\tx.exps = true;\n
\t\tx.assign = true;\n
\t\treturn x;\n
\t}\n
\n
\n
\tfunction bitwise(s, f, p) {\n
\t\tvar x = symbol(s, p);\n
\t\treserveName(x);\n
\t\tx.led = (typeof f === "function") ? f : function (left) {\n
\t\t\tif (state.option.bitwise) {\n
\t\t\t\twarning("W016", this, this.id);\n
\t\t\t}\n
\t\t\tthis.left = left;\n
\t\t\tthis.right = expression(p);\n
\t\t\treturn this;\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\n
\tfunction bitwiseassignop(s) {\n
\t\treturn assignop(s, function (left, that) {\n
\t\t\tif (state.option.bitwise) {\n
\t\t\t\twarning("W016", that, that.id);\n
\t\t\t}\n
\t\t\tnonadjacent(state.tokens.prev, state.tokens.curr);\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tif (left) {\n
\t\t\t\tif (left.id === "." || left.id === "[" ||\n
\t\t\t\t\t\t(left.identifier && !isReserved(left))) {\n
\t\t\t\t\texpression(10);\n
\t\t\t\t\treturn that;\n
\t\t\t\t}\n
\t\t\t\tif (left === state.syntax["function"]) {\n
\t\t\t\t\twarning("W023", state.tokens.curr);\n
\t\t\t\t}\n
\t\t\t\treturn that;\n
\t\t\t}\n
\t\t\terror("E031", that);\n
\t\t}, 20);\n
\t}\n
\n
\n
\tfunction suffix(s) {\n
\t\tvar x = symbol(s, 150);\n
\n
\t\tx.led = function (left) {\n
\t\t\tif (state.option.plusplus) {\n
\t\t\t\twarning("W016", this, this.id);\n
\t\t\t} else if ((!left.identifier || isReserved(left)) && left.id !== "." && left.id !== "[") {\n
\t\t\t\twarning("W017", this);\n
\t\t\t}\n
\n
\t\t\tthis.left = left;\n
\t\t\treturn this;\n
\t\t};\n
\t\treturn x;\n
\t}\n
\n
\tfunction optionalidentifier(fnparam, prop) {\n
\t\tif (!state.tokens.next.identifier) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tadvance();\n
\n
\t\tvar curr = state.tokens.curr;\n
\t\tvar val  = state.tokens.curr.value;\n
\n
\t\tif (!isReserved(curr)) {\n
\t\t\treturn val;\n
\t\t}\n
\n
\t\tif (prop) {\n
\t\t\tif (state.option.inES5()) {\n
\t\t\t\treturn val;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (fnparam && val === "undefined") {\n
\t\t\treturn val;\n
\t\t}\n
\t\tif (prop && !api.getCache("displayed:I002")) {\n
\t\t\tapi.setCache("displayed:I002", true);\n
\t\t\twarning("I002");\n
\t\t}\n
\n
\t\twarning("W024", state.tokens.curr, state.tokens.curr.id);\n
\t\treturn val;\n
\t}\n
\tfunction identifier(fnparam, prop) {\n
\t\tvar i = optionalidentifier(fnparam, prop);\n
\t\tif (i) {\n
\t\t\treturn i;\n
\t\t}\n
\t\tif (state.tokens.curr.id === "function" && state.tokens.next.id === "(") {\n
\t\t\twarning("W025");\n
\t\t} else {\n
\t\t\terror("E030", state.tokens.next, state.tokens.next.value);\n
\t\t}\n
\t}\n
\n
\n
\tfunction reachable(s) {\n
\t\tvar i = 0, t;\n
\t\tif (state.tokens.next.id !== ";" || noreach) {\n
\t\t\treturn;\n
\t\t}\n
\t\tfor (;;) {\n
\t\t\tt = peek(i);\n
\t\t\tif (t.reach) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif (t.id !== "(endline)") {\n
\t\t\t\tif (t.id === "function") {\n
\t\t\t\t\tif (!state.option.latedef) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\twarning("W026", t);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\twarning("W027", t, t.value, s);\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\ti += 1;\n
\t\t}\n
\t}\n
\n
\n
\tfunction statement(noindent) {\n
\t\tvar values;\n
\t\tvar i = indent, r, s = scope, t = state.tokens.next;\n
\n
\t\tif (t.id === ";") {\n
\t\t\tadvance(";");\n
\t\t\treturn;\n
\t\t}\n
\t\tvar res = isReserved(t);\n
\n
\t\tif (res && t.meta && t.meta.isFutureReservedWord && peek().id === ":") {\n
\t\t\twarning("W024", t, t.id);\n
\t\t\tres = false;\n
\t\t}\n
\t\tif (_.has(["[", "{"], t.value)) {\n
\t\t\tif (lookupBlockType().isDestAssign) {\n
\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\twarning("W104", state.tokens.curr, "destructuring expression");\n
\t\t\t\t}\n
\t\t\t\tvalues = destructuringExpression();\n
\t\t\t\tvalues.forEach(function (tok) {\n
\t\t\t\t\tisundef(funct, "W117", tok.token, tok.id);\n
\t\t\t\t});\n
\t\t\t\tadvance("=");\n
\t\t\t\tdestructuringExpressionMatch(values, expression(10, true));\n
\t\t\t\tadvance(";");\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t}\n
\t\tif (t.identifier && !res && peek().id === ":") {\n
\t\t\tadvance();\n
\t\t\tadvance(":");\n
\t\t\tscope = Object.create(s);\n
\t\t\taddlabel(t.value, "label");\n
\n
\t\t\tif (!state.tokens.next.labelled && state.tokens.next.value !== "{") {\n
\t\t\t\twarning("W028", state.tokens.next, t.value, state.tokens.next.value);\n
\t\t\t}\n
\n
\t\t\tstate.tokens.next.label = t.value;\n
\t\t\tt = state.tokens.next;\n
\t\t}\n
\n
\t\tif (t.id === "{") {\n
\t\t\tblock(true, true);\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (!noindent) {\n
\t\t\tindentation();\n
\t\t}\n
\t\tr = expression(0, true);\n
\n
\t\tif (!t.block) {\n
\t\t\tif (!state.option.expr && (!r || !r.exps)) {\n
\t\t\t\twarning("W030", state.tokens.curr);\n
\t\t\t} else if (state.option.nonew && r && r.left && r.id === "(" && r.left.id === "new") {\n
\t\t\t\twarning("W031", t);\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id !== ";") {\n
\t\t\t\tif (!state.option.asi) {\n
\t\t\t\t\tif (!state.option.lastsemic || state.tokens.next.id !== "}" ||\n
\t\t\t\t\t\tstate.tokens.next.line !== state.tokens.curr.line) {\n
\t\t\t\t\t\twarningAt("W033", state.tokens.curr.line, state.tokens.curr.character);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tadvance(";");\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t}\n
\t\t}\n
\n
\t\tindent = i;\n
\t\tscope = s;\n
\t\treturn r;\n
\t}\n
\n
\n
\tfunction statements(startLine) {\n
\t\tvar a = [], p;\n
\n
\t\twhile (!state.tokens.next.reach && state.tokens.next.id !== "(end)") {\n
\t\t\tif (state.tokens.next.id === ";") {\n
\t\t\t\tp = peek();\n
\n
\t\t\t\tif (!p || (p.id !== "(" && p.id !== "[")) {\n
\t\t\t\t\twarning("W032");\n
\t\t\t\t}\n
\n
\t\t\t\tadvance(";");\n
\t\t\t} else {\n
\t\t\t\ta.push(statement(startLine === state.tokens.next.line));\n
\t\t\t}\n
\t\t}\n
\t\treturn a;\n
\t}\n
\tfunction directives() {\n
\t\tvar i, p, pn;\n
\n
\t\tfor (;;) {\n
\t\t\tif (state.tokens.next.id === "(string)") {\n
\t\t\t\tp = peek(0);\n
\t\t\t\tif (p.id === "(endline)") {\n
\t\t\t\t\ti = 1;\n
\t\t\t\t\tdo {\n
\t\t\t\t\t\tpn = peek(i);\n
\t\t\t\t\t\ti = i + 1;\n
\t\t\t\t\t} while (pn.id === "(endline)");\n
\n
\t\t\t\t\tif (pn.id !== ";") {\n
\t\t\t\t\t\tif (pn.id !== "(string)" && pn.id !== "(number)" &&\n
\t\t\t\t\t\t\tpn.id !== "(regexp)" && pn.identifier !== true &&\n
\t\t\t\t\t\t\tpn.id !== "}") {\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\twarning("W033", state.tokens.next);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tp = pn;\n
\t\t\t\t\t}\n
\t\t\t\t} else if (p.id === "}") {\n
\t\t\t\t\twarning("W033", p);\n
\t\t\t\t} else if (p.id !== ";") {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tindentation();\n
\t\t\t\tadvance();\n
\t\t\t\tif (state.directive[state.tokens.curr.value]) {\n
\t\t\t\t\twarning("W034", state.tokens.curr, state.tokens.curr.value);\n
\t\t\t\t}\n
\n
\t\t\t\tif (state.tokens.curr.value === "use strict") {\n
\t\t\t\t\tif (!state.option["(explicitNewcap)"])\n
\t\t\t\t\t\tstate.option.newcap = true;\n
\t\t\t\t\tstate.option.undef = true;\n
\t\t\t\t}\n
\t\t\t\tstate.directive[state.tokens.curr.value] = true;\n
\n
\t\t\t\tif (p.id === ";") {\n
\t\t\t\t\tadvance(";");\n
\t\t\t\t}\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\t\t\tbreak;\n
\t\t}\n
\t}\n
\tfunction block(ordinary, stmt, isfunc, isfatarrow) {\n
\t\tvar a,\n
\t\t\tb = inblock,\n
\t\t\told_indent = indent,\n
\t\t\tm,\n
\t\t\ts = scope,\n
\t\t\tt,\n
\t\t\tline,\n
\t\t\td;\n
\n
\t\tinblock = ordinary;\n
\n
\t\tif (!ordinary || !state.option.funcscope)\n
\t\t\tscope = Object.create(scope);\n
\n
\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\tt = state.tokens.next;\n
\n
\t\tvar metrics = funct["(metrics)"];\n
\t\tmetrics.nestedBlockDepth += 1;\n
\t\tmetrics.verifyMaxNestedBlockDepthPerFunction();\n
\n
\t\tif (state.tokens.next.id === "{") {\n
\t\t\tadvance("{");\n
\t\t\tfunct["(blockscope)"].stack();\n
\n
\t\t\tline = state.tokens.curr.line;\n
\t\t\tif (state.tokens.next.id !== "}") {\n
\t\t\t\tindent += state.option.indent;\n
\t\t\t\twhile (!ordinary && state.tokens.next.from > indent) {\n
\t\t\t\t\tindent += state.option.indent;\n
\t\t\t\t}\n
\n
\t\t\t\tif (isfunc) {\n
\t\t\t\t\tm = {};\n
\t\t\t\t\tfor (d in state.directive) {\n
\t\t\t\t\t\tif (_.has(state.directive, d)) {\n
\t\t\t\t\t\t\tm[d] = state.directive[d];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tdirectives();\n
\n
\t\t\t\t\tif (state.option.strict && funct["(context)"]["(global)"]) {\n
\t\t\t\t\t\tif (!m["use strict"] && !state.directive["use strict"]) {\n
\t\t\t\t\t\t\twarning("E007");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\ta = statements(line);\n
\n
\t\t\t\tmetrics.statementCount += a.length;\n
\n
\t\t\t\tif (isfunc) {\n
\t\t\t\t\tstate.directive = m;\n
\t\t\t\t}\n
\n
\t\t\t\tindent -= state.option.indent;\n
\t\t\t\tif (line !== state.tokens.next.line) {\n
\t\t\t\t\tindentation();\n
\t\t\t\t}\n
\t\t\t} else if (line !== state.tokens.next.line) {\n
\t\t\t\tindentation();\n
\t\t\t}\n
\t\t\tadvance("}", t);\n
\n
\t\t\tfunct["(blockscope)"].unstack();\n
\n
\t\t\tindent = old_indent;\n
\t\t} else if (!ordinary) {\n
\t\t\tif (isfunc) {\n
\t\t\t\tm = {};\n
\t\t\t\tif (stmt && !isfatarrow && !state.option.inMoz(true)) {\n
\t\t\t\t\terror("W118", state.tokens.curr, "function closure expressions");\n
\t\t\t\t}\n
\n
\t\t\t\tif (!stmt) {\n
\t\t\t\t\tfor (d in state.directive) {\n
\t\t\t\t\t\tif (_.has(state.directive, d)) {\n
\t\t\t\t\t\t\tm[d] = state.directive[d];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\texpression(10);\n
\n
\t\t\t\tif (state.option.strict && funct["(context)"]["(global)"]) {\n
\t\t\t\t\tif (!m["use strict"] && !state.directive["use strict"]) {\n
\t\t\t\t\t\twarning("E007");\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\terror("E021", state.tokens.next, "{", state.tokens.next.value);\n
\t\t\t}\n
\t\t} else {\n
\t\t\tfunct["(nolet)"] = true;\n
\n
\t\t\tif (!stmt || state.option.curly) {\n
\t\t\t\twarning("W116", state.tokens.next, "{", state.tokens.next.value);\n
\t\t\t}\n
\n
\t\t\tnoreach = true;\n
\t\t\tindent += state.option.indent;\n
\t\t\ta = [statement(state.tokens.next.line === state.tokens.curr.line)];\n
\t\t\tindent -= state.option.indent;\n
\t\t\tnoreach = false;\n
\n
\t\t\tdelete funct["(nolet)"];\n
\t\t}\n
\t\tfunct["(verb)"] = null;\n
\t\tif (!ordinary || !state.option.funcscope) scope = s;\n
\t\tinblock = b;\n
\t\tif (ordinary && state.option.noempty && (!a || a.length === 0)) {\n
\t\t\twarning("W035");\n
\t\t}\n
\t\tmetrics.nestedBlockDepth -= 1;\n
\t\treturn a;\n
\t}\n
\n
\n
\tfunction countMember(m) {\n
\t\tif (membersOnly && typeof membersOnly[m] !== "boolean") {\n
\t\t\twarning("W036", state.tokens.curr, m);\n
\t\t}\n
\t\tif (typeof member[m] === "number") {\n
\t\t\tmember[m] += 1;\n
\t\t} else {\n
\t\t\tmember[m] = 1;\n
\t\t}\n
\t}\n
\n
\n
\tfunction note_implied(tkn) {\n
\t\tvar name = tkn.value, line = tkn.line, a = implied[name];\n
\t\tif (typeof a === "function") {\n
\t\t\ta = false;\n
\t\t}\n
\n
\t\tif (!a) {\n
\t\t\ta = [line];\n
\t\t\timplied[name] = a;\n
\t\t} else if (a[a.length - 1] !== line) {\n
\t\t\ta.push(line);\n
\t\t}\n
\t}\n
\n
\ttype("(number)", function () {\n
\t\treturn this;\n
\t});\n
\n
\ttype("(string)", function () {\n
\t\treturn this;\n
\t});\n
\n
\tstate.syntax["(identifier)"] = {\n
\t\ttype: "(identifier)",\n
\t\tlbp: 0,\n
\t\tidentifier: true,\n
\t\tnud: function () {\n
\t\t\tvar v = this.value,\n
\t\t\t\ts = scope[v],\n
\t\t\t\tf;\n
\n
\t\t\tif (typeof s === "function") {\n
\t\t\t\ts = undefined;\n
\t\t\t} else if (typeof s === "boolean") {\n
\t\t\t\tf = funct;\n
\t\t\t\tfunct = functions[0];\n
\t\t\t\taddlabel(v, "var");\n
\t\t\t\ts = funct;\n
\t\t\t\tfunct = f;\n
\t\t\t}\n
\t\t\tvar block;\n
\t\t\tif (_.has(funct, "(blockscope)")) {\n
\t\t\t\tblock = funct["(blockscope)"].getlabel(v);\n
\t\t\t}\n
\t\t\tif (funct === s || block) {\n
\t\t\t\tswitch (block ? block[v]["(type)"] : funct[v]) {\n
\t\t\t\tcase "unused":\n
\t\t\t\t\tif (block) block[v]["(type)"] = "var";\n
\t\t\t\t\telse funct[v] = "var";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "unction":\n
\t\t\t\t\tif (block) block[v]["(type)"] = "function";\n
\t\t\t\t\telse funct[v] = "function";\n
\t\t\t\t\tthis["function"] = true;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "function":\n
\t\t\t\t\tthis["function"] = true;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "label":\n
\t\t\t\t\twarning("W037", state.tokens.curr, v);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t} else if (funct["(global)"]) {\n
\n
\t\t\t\tif (typeof predefined[v] !== "boolean") {\n
\t\t\t\t\tif (!(anonname === "typeof" || anonname === "delete") ||\n
\t\t\t\t\t\t(state.tokens.next && (state.tokens.next.value === "." ||\n
\t\t\t\t\t\t\tstate.tokens.next.value === "["))) {\n
\n
\t\t\t\t\t\tif (!funct["(comparray)"].check(v)) {\n
\t\t\t\t\t\t\tisundef(funct, "W117", state.tokens.curr, v);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tnote_implied(state.tokens.curr);\n
\t\t\t} else {\n
\n
\t\t\t\tswitch (funct[v]) {\n
\t\t\t\tcase "closure":\n
\t\t\t\tcase "function":\n
\t\t\t\tcase "var":\n
\t\t\t\tcase "unused":\n
\t\t\t\t\twarning("W038", state.tokens.curr, v);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "label":\n
\t\t\t\t\twarning("W037", state.tokens.curr, v);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "outer":\n
\t\t\t\tcase "global":\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tif (s === true) {\n
\t\t\t\t\t\tfunct[v] = true;\n
\t\t\t\t\t} else if (s === null) {\n
\t\t\t\t\t\twarning("W039", state.tokens.curr, v);\n
\t\t\t\t\t\tnote_implied(state.tokens.curr);\n
\t\t\t\t\t} else if (typeof s !== "object") {\n
\t\t\t\t\t\tif (!(anonname === "typeof" || anonname === "delete") ||\n
\t\t\t\t\t\t\t(state.tokens.next &&\n
\t\t\t\t\t\t\t\t(state.tokens.next.value === "." || state.tokens.next.value === "["))) {\n
\n
\t\t\t\t\t\t\tisundef(funct, "W117", state.tokens.curr, v);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tfunct[v] = true;\n
\t\t\t\t\t\tnote_implied(state.tokens.curr);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tswitch (s[v]) {\n
\t\t\t\t\t\tcase "function":\n
\t\t\t\t\t\tcase "unction":\n
\t\t\t\t\t\t\tthis["function"] = true;\n
\t\t\t\t\t\t\ts[v] = "closure";\n
\t\t\t\t\t\t\tfunct[v] = s["(global)"] ? "global" : "outer";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "var":\n
\t\t\t\t\t\tcase "unused":\n
\t\t\t\t\t\t\ts[v] = "closure";\n
\t\t\t\t\t\t\tfunct[v] = s["(global)"] ? "global" : "outer";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "closure":\n
\t\t\t\t\t\t\tfunct[v] = s["(global)"] ? "global" : "outer";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "label":\n
\t\t\t\t\t\t\twarning("W037", state.tokens.curr, v);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t},\n
\t\tled: function () {\n
\t\t\terror("E033", state.tokens.next, state.tokens.next.value);\n
\t\t}\n
\t};\n
\n
\ttype("(regexp)", function () {\n
\t\treturn this;\n
\t});\n
\n
\tdelim("(endline)");\n
\tdelim("(begin)");\n
\tdelim("(end)").reach = true;\n
\tdelim("(error)").reach = true;\n
\tdelim("}").reach = true;\n
\tdelim(")");\n
\tdelim("]");\n
\tdelim("\\"").reach = true;\n
\tdelim("\'").reach = true;\n
\tdelim(";");\n
\tdelim(":").reach = true;\n
\tdelim("#");\n
\n
\treserve("else");\n
\treserve("case").reach = true;\n
\treserve("catch");\n
\treserve("default").reach = true;\n
\treserve("finally");\n
\treservevar("arguments", function (x) {\n
\t\tif (state.directive["use strict"] && funct["(global)"]) {\n
\t\t\twarning("E008", x);\n
\t\t}\n
\t});\n
\treservevar("eval");\n
\treservevar("false");\n
\treservevar("Infinity");\n
\treservevar("null");\n
\treservevar("this", function (x) {\n
\t\tif (state.directive["use strict"] && !state.option.validthis && ((funct["(statement)"] &&\n
\t\t\t\tfunct["(name)"].charAt(0) > "Z") || funct["(global)"])) {\n
\t\t\twarning("W040", x);\n
\t\t}\n
\t});\n
\treservevar("true");\n
\treservevar("undefined");\n
\n
\tassignop("=", "assign", 20);\n
\tassignop("+=", "assignadd", 20);\n
\tassignop("-=", "assignsub", 20);\n
\tassignop("*=", "assignmult", 20);\n
\tassignop("/=", "assigndiv", 20).nud = function () {\n
\t\terror("E014");\n
\t};\n
\tassignop("%=", "assignmod", 20);\n
\n
\tbitwiseassignop("&=", "assignbitand", 20);\n
\tbitwiseassignop("|=", "assignbitor", 20);\n
\tbitwiseassignop("^=", "assignbitxor", 20);\n
\tbitwiseassignop("<<=", "assignshiftleft", 20);\n
\tbitwiseassignop(">>=", "assignshiftright", 20);\n
\tbitwiseassignop(">>>=", "assignshiftrightunsigned", 20);\n
\tinfix(",", function (left, that) {\n
\t\tvar expr;\n
\t\tthat.exprs = [left];\n
\t\tif (!comma({peek: true})) {\n
\t\t\treturn that;\n
\t\t}\n
\t\twhile (true) {\n
\t\t\tif (!(expr = expression(10)))  {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tthat.exprs.push(expr);\n
\t\t\tif (state.tokens.next.value !== "," || !comma()) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\treturn that;\n
\t}, 10, true);\n
\n
\tinfix("?", function (left, that) {\n
\t\tincreaseComplexityCount();\n
\t\tthat.left = left;\n
\t\tthat.right = expression(10);\n
\t\tadvance(":");\n
\t\tthat["else"] = expression(10);\n
\t\treturn that;\n
\t}, 30);\n
\n
\tvar orPrecendence = 40;\n
\tinfix("||", function (left, that) {\n
\t\tincreaseComplexityCount();\n
\t\tthat.left = left;\n
\t\tthat.right = expression(orPrecendence);\n
\t\treturn that;\n
\t}, orPrecendence);\n
\tinfix("&&", "and", 50);\n
\tbitwise("|", "bitor", 70);\n
\tbitwise("^", "bitxor", 80);\n
\tbitwise("&", "bitand", 90);\n
\trelation("==", function (left, right) {\n
\t\tvar eqnull = state.option.eqnull && (left.value === "null" || right.value === "null");\n
\n
\t\tif (!eqnull && state.option.eqeqeq)\n
\t\t\twarning("W116", this, "===", "==");\n
\t\telse if (isPoorRelation(left))\n
\t\t\twarning("W041", this, "===", left.value);\n
\t\telse if (isPoorRelation(right))\n
\t\t\twarning("W041", this, "===", right.value);\n
\n
\t\treturn this;\n
\t});\n
\trelation("===");\n
\trelation("!=", function (left, right) {\n
\t\tvar eqnull = state.option.eqnull &&\n
\t\t\t\t(left.value === "null" || right.value === "null");\n
\n
\t\tif (!eqnull && state.option.eqeqeq) {\n
\t\t\twarning("W116", this, "!==", "!=");\n
\t\t} else if (isPoorRelation(left)) {\n
\t\t\twarning("W041", this, "!==", left.value);\n
\t\t} else if (isPoorRelation(right)) {\n
\t\t\twarning("W041", this, "!==", right.value);\n
\t\t}\n
\t\treturn this;\n
\t});\n
\trelation("!==");\n
\trelation("<");\n
\trelation(">");\n
\trelation("<=");\n
\trelation(">=");\n
\tbitwise("<<", "shiftleft", 120);\n
\tbitwise(">>", "shiftright", 120);\n
\tbitwise(">>>", "shiftrightunsigned", 120);\n
\tinfix("in", "in", 120);\n
\tinfix("instanceof", "instanceof", 120);\n
\tinfix("+", function (left, that) {\n
\t\tvar right = expression(130);\n
\t\tif (left && right && left.id === "(string)" && right.id === "(string)") {\n
\t\t\tleft.value += right.value;\n
\t\t\tleft.character = right.character;\n
\t\t\tif (!state.option.scripturl && reg.javascriptURL.test(left.value)) {\n
\t\t\t\twarning("W050", left);\n
\t\t\t}\n
\t\t\treturn left;\n
\t\t}\n
\t\tthat.left = left;\n
\t\tthat.right = right;\n
\t\treturn that;\n
\t}, 130);\n
\tprefix("+", "num");\n
\tprefix("+++", function () {\n
\t\twarning("W007");\n
\t\tthis.right = expression(150);\n
\t\tthis.arity = "unary";\n
\t\treturn this;\n
\t});\n
\tinfix("+++", function (left) {\n
\t\twarning("W007");\n
\t\tthis.left = left;\n
\t\tthis.right = expression(130);\n
\t\treturn this;\n
\t}, 130);\n
\tinfix("-", "sub", 130);\n
\tprefix("-", "neg");\n
\tprefix("---", function () {\n
\t\twarning("W006");\n
\t\tthis.right = expression(150);\n
\t\tthis.arity = "unary";\n
\t\treturn this;\n
\t});\n
\tinfix("---", function (left) {\n
\t\twarning("W006");\n
\t\tthis.left = left;\n
\t\tthis.right = expression(130);\n
\t\treturn this;\n
\t}, 130);\n
\tinfix("*", "mult", 140);\n
\tinfix("/", "div", 140);\n
\tinfix("%", "mod", 140);\n
\n
\tsuffix("++", "postinc");\n
\tprefix("++", "preinc");\n
\tstate.syntax["++"].exps = true;\n
\n
\tsuffix("--", "postdec");\n
\tprefix("--", "predec");\n
\tstate.syntax["--"].exps = true;\n
\tprefix("delete", function () {\n
\t\tvar p = expression(10);\n
\t\tif (!p || (p.id !== "." && p.id !== "[")) {\n
\t\t\twarning("W051");\n
\t\t}\n
\t\tthis.first = p;\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\tprefix("~", function () {\n
\t\tif (state.option.bitwise) {\n
\t\t\twarning("W052", this, "~");\n
\t\t}\n
\t\texpression(150);\n
\t\treturn this;\n
\t});\n
\n
\tprefix("...", function () {\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W104", this, "spread/rest operator");\n
\t\t}\n
\t\tif (!state.tokens.next.identifier) {\n
\t\t\terror("E030", state.tokens.next, state.tokens.next.value);\n
\t\t}\n
\t\texpression(150);\n
\t\treturn this;\n
\t});\n
\n
\tprefix("!", function () {\n
\t\tthis.right = expression(150);\n
\t\tthis.arity = "unary";\n
\n
\t\tif (!this.right) { // \'!\' followed by nothing? Give up.\n
\t\t\tquit("E041", this.line || 0);\n
\t\t}\n
\n
\t\tif (bang[this.right.id] === true) {\n
\t\t\twarning("W018", this, "!");\n
\t\t}\n
\t\treturn this;\n
\t});\n
\n
\tprefix("typeof", "typeof");\n
\tprefix("new", function () {\n
\t\tvar c = expression(155), i;\n
\t\tif (c && c.id !== "function") {\n
\t\t\tif (c.identifier) {\n
\t\t\t\tc["new"] = true;\n
\t\t\t\tswitch (c.value) {\n
\t\t\t\tcase "Number":\n
\t\t\t\tcase "String":\n
\t\t\t\tcase "Boolean":\n
\t\t\t\tcase "Math":\n
\t\t\t\tcase "JSON":\n
\t\t\t\t\twarning("W053", state.tokens.prev, c.value);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "Function":\n
\t\t\t\t\tif (!state.option.evil) {\n
\t\t\t\t\t\twarning("W054");\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "Date":\n
\t\t\t\tcase "RegExp":\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tif (c.id !== "function") {\n
\t\t\t\t\t\ti = c.value.substr(0, 1);\n
\t\t\t\t\t\tif (state.option.newcap && (i < "A" || i > "Z") && !_.has(global, c.value)) {\n
\t\t\t\t\t\t\twarning("W055", state.tokens.curr);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tif (c.id !== "." && c.id !== "[" && c.id !== "(") {\n
\t\t\t\t\twarning("W056", state.tokens.curr);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tif (!state.option.supernew)\n
\t\t\t\twarning("W057", this);\n
\t\t}\n
\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\tif (state.tokens.next.id !== "(" && !state.option.supernew) {\n
\t\t\twarning("W058", state.tokens.curr, state.tokens.curr.value);\n
\t\t}\n
\t\tthis.first = c;\n
\t\treturn this;\n
\t});\n
\tstate.syntax["new"].exps = true;\n
\n
\tprefix("void").exps = true;\n
\n
\tinfix(".", function (left, that) {\n
\t\tadjacent(state.tokens.prev, state.tokens.curr);\n
\t\tnobreak();\n
\t\tvar m = identifier(false, true);\n
\n
\t\tif (typeof m === "string") {\n
\t\t\tcountMember(m);\n
\t\t}\n
\n
\t\tthat.left = left;\n
\t\tthat.right = m;\n
\n
\t\tif (m && m === "hasOwnProperty" && state.tokens.next.value === "=") {\n
\t\t\twarning("W001");\n
\t\t}\n
\n
\t\tif (left && left.value === "arguments" && (m === "callee" || m === "caller")) {\n
\t\t\tif (state.option.noarg)\n
\t\t\t\twarning("W059", left, m);\n
\t\t\telse if (state.directive["use strict"])\n
\t\t\t\terror("E008");\n
\t\t} else if (!state.option.evil && left && left.value === "document" &&\n
\t\t\t\t(m === "write" || m === "writeln")) {\n
\t\t\twarning("W060", left);\n
\t\t}\n
\n
\t\tif (!state.option.evil && (m === "eval" || m === "execScript")) {\n
\t\t\twarning("W061");\n
\t\t}\n
\n
\t\treturn that;\n
\t}, 160, true);\n
\n
\tinfix("(", function (left, that) {\n
\t\tif (state.tokens.prev.id !== "}" && state.tokens.prev.id !== ")") {\n
\t\t\tnobreak(state.tokens.prev, state.tokens.curr);\n
\t\t}\n
\n
\t\tnospace();\n
\t\tif (state.option.immed && left && !left.immed && left.id === "function") {\n
\t\t\twarning("W062");\n
\t\t}\n
\n
\t\tvar n = 0;\n
\t\tvar p = [];\n
\n
\t\tif (left) {\n
\t\t\tif (left.type === "(identifier)") {\n
\t\t\t\tif (left.value.match(/^[A-Z]([A-Z0-9_$]*[a-z][A-Za-z0-9_$]*)?$/)) {\n
\t\t\t\t\tif ("Number String Boolean Date Object".indexOf(left.value) === -1) {\n
\t\t\t\t\t\tif (left.value === "Math") {\n
\t\t\t\t\t\t\twarning("W063", left);\n
\t\t\t\t\t\t} else if (state.option.newcap) {\n
\t\t\t\t\t\t\twarning("W064", left);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (state.tokens.next.id !== ")") {\n
\t\t\tfor (;;) {\n
\t\t\t\tp[p.length] = expression(10);\n
\t\t\t\tn += 1;\n
\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tcomma();\n
\t\t\t}\n
\t\t}\n
\n
\t\tadvance(")");\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\n
\t\tif (typeof left === "object") {\n
\t\t\tif (left.value === "parseInt" && n === 1) {\n
\t\t\t\twarning("W065", state.tokens.curr);\n
\t\t\t}\n
\t\t\tif (!state.option.evil) {\n
\t\t\t\tif (left.value === "eval" || left.value === "Function" ||\n
\t\t\t\t\t\tleft.value === "execScript") {\n
\t\t\t\t\twarning("W061", left);\n
\n
\t\t\t\t\tif (p[0] && [0].id === "(string)") {\n
\t\t\t\t\t\taddInternalSrc(left, p[0].value);\n
\t\t\t\t\t}\n
\t\t\t\t} else if (p[0] && p[0].id === "(string)" &&\n
\t\t\t\t\t   (left.value === "setTimeout" ||\n
\t\t\t\t\t\tleft.value === "setInterval")) {\n
\t\t\t\t\twarning("W066", left);\n
\t\t\t\t\taddInternalSrc(left, p[0].value);\n
\t\t\t\t} else if (p[0] && p[0].id === "(string)" &&\n
\t\t\t\t\t   left.value === "." &&\n
\t\t\t\t\t   left.left.value === "window" &&\n
\t\t\t\t\t   (left.right === "setTimeout" ||\n
\t\t\t\t\t\tleft.right === "setInterval")) {\n
\t\t\t\t\twarning("W066", left);\n
\t\t\t\t\taddInternalSrc(left, p[0].value);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (!left.identifier && left.id !== "." && left.id !== "[" &&\n
\t\t\t\t\tleft.id !== "(" && left.id !== "&&" && left.id !== "||" &&\n
\t\t\t\t\tleft.id !== "?") {\n
\t\t\t\twarning("W067", left);\n
\t\t\t}\n
\t\t}\n
\n
\t\tthat.left = left;\n
\t\treturn that;\n
\t}, 155, true).exps = true;\n
\n
\tprefix("(", function () {\n
\t\tnospace();\n
\t\tvar bracket, brackets = [];\n
\t\tvar pn, pn1, i = 0;\n
\t\tvar ret;\n
\n
\t\tdo {\n
\t\t\tpn = peek(i);\n
\t\t\ti += 1;\n
\t\t\tpn1 = peek(i);\n
\t\t\ti += 1;\n
\t\t} while (pn.value !== ")" && pn1.value !== "=>" && pn1.value !== ";" && pn1.type !== "(end)");\n
\n
\t\tif (state.tokens.next.id === "function") {\n
\t\t\tstate.tokens.next.immed = true;\n
\t\t}\n
\n
\t\tvar exprs = [];\n
\n
\t\tif (state.tokens.next.id !== ")") {\n
\t\t\tfor (;;) {\n
\t\t\t\tif (pn1.value === "=>" && state.tokens.next.value === "{") {\n
\t\t\t\t\tbracket = state.tokens.next;\n
\t\t\t\t\tbracket.left = destructuringExpression();\n
\t\t\t\t\tbrackets.push(bracket);\n
\t\t\t\t\tfor (var t in bracket.left) {\n
\t\t\t\t\t\texprs.push(bracket.left[t].token);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\texprs.push(expression(10));\n
\t\t\t\t}\n
\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tcomma();\n
\t\t\t}\n
\t\t}\n
\n
\t\tadvance(")", this);\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tif (state.option.immed && exprs[0] && exprs[0].id === "function") {\n
\t\t\tif (state.tokens.next.id !== "(" &&\n
\t\t\t  (state.tokens.next.id !== "." || (peek().value !== "call" && peek().value !== "apply"))) {\n
\t\t\t\twarning("W068", this);\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (state.tokens.next.value === "=>") {\n
\t\t\treturn exprs;\n
\t\t}\n
\t\tif (!exprs.length) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif (exprs.length > 1) {\n
\t\t\tret = Object.create(state.syntax[","]);\n
\t\t\tret.exprs = exprs;\n
\t\t} else {\n
\t\t\tret = exprs[0];\n
\t\t}\n
\t\tif (ret) {\n
\t\t\tret.paren = true;\n
\t\t}\n
\t\treturn ret;\n
\t});\n
\n
\tapplication("=>");\n
\n
\tinfix("[", function (left, that) {\n
\t\tnobreak(state.tokens.prev, state.tokens.curr);\n
\t\tnospace();\n
\t\tvar e = expression(10), s;\n
\t\tif (e && e.type === "(string)") {\n
\t\t\tif (!state.option.evil && (e.value === "eval" || e.value === "execScript")) {\n
\t\t\t\twarning("W061", that);\n
\t\t\t}\n
\n
\t\t\tcountMember(e.value);\n
\t\t\tif (!state.option.sub && reg.identifier.test(e.value)) {\n
\t\t\t\ts = state.syntax[e.value];\n
\t\t\t\tif (!s || !isReserved(s)) {\n
\t\t\t\t\twarning("W069", state.tokens.prev, e.value);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tadvance("]", that);\n
\n
\t\tif (e && e.value === "hasOwnProperty" && state.tokens.next.value === "=") {\n
\t\t\twarning("W001");\n
\t\t}\n
\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tthat.left = left;\n
\t\tthat.right = e;\n
\t\treturn that;\n
\t}, 160, true);\n
\n
\tfunction comprehensiveArrayExpression() {\n
\t\tvar res = {};\n
\t\tres.exps = true;\n
\t\tfunct["(comparray)"].stack();\n
\n
\t\tres.right = expression(10);\n
\t\tadvance("for");\n
\t\tif (state.tokens.next.value === "each") {\n
\t\t\tadvance("each");\n
\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\twarning("W118", state.tokens.curr, "for each");\n
\t\t\t}\n
\t\t}\n
\t\tadvance("(");\n
\t\tfunct["(comparray)"].setState("define");\n
\t\tres.left = expression(10);\n
\t\tadvance(")");\n
\t\tif (state.tokens.next.value === "if") {\n
\t\t\tadvance("if");\n
\t\t\tadvance("(");\n
\t\t\tfunct["(comparray)"].setState("filter");\n
\t\t\tres.filter = expression(10);\n
\t\t\tadvance(")");\n
\t\t}\n
\t\tadvance("]");\n
\t\tfunct["(comparray)"].unstack();\n
\t\treturn res;\n
\t}\n
\n
\tprefix("[", function () {\n
\t\tvar blocktype = lookupBlockType(true);\n
\t\tif (blocktype.isCompArray) {\n
\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\twarning("W118", state.tokens.curr, "array comprehension");\n
\t\t\t}\n
\t\t\treturn comprehensiveArrayExpression();\n
\t\t} else if (blocktype.isDestAssign && !state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "destructuring assignment");\n
\t\t}\n
\t\tvar b = state.tokens.curr.line !== state.tokens.next.line;\n
\t\tthis.first = [];\n
\t\tif (b) {\n
\t\t\tindent += state.option.indent;\n
\t\t\tif (state.tokens.next.from === indent + state.option.indent) {\n
\t\t\t\tindent += state.option.indent;\n
\t\t\t}\n
\t\t}\n
\t\twhile (state.tokens.next.id !== "(end)") {\n
\t\t\twhile (state.tokens.next.id === ",") {\n
\t\t\t\tif (!state.option.inES5())\n
\t\t\t\t\twarning("W070");\n
\t\t\t\tadvance(",");\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id === "]") {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tif (b && state.tokens.curr.line !== state.tokens.next.line) {\n
\t\t\t\tindentation();\n
\t\t\t}\n
\t\t\tthis.first.push(expression(10));\n
\t\t\tif (state.tokens.next.id === ",") {\n
\t\t\t\tcomma({ allowTrailing: true });\n
\t\t\t\tif (state.tokens.next.id === "]" && !state.option.inES5(true)) {\n
\t\t\t\t\twarning("W070", state.tokens.curr);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tif (b) {\n
\t\t\tindent -= state.option.indent;\n
\t\t\tindentation();\n
\t\t}\n
\t\tadvance("]", this);\n
\t\treturn this;\n
\t}, 160);\n
\n
\n
\tfunction property_name() {\n
\t\tvar id = optionalidentifier(false, true);\n
\n
\t\tif (!id) {\n
\t\t\tif (state.tokens.next.id === "(string)") {\n
\t\t\t\tid = state.tokens.next.value;\n
\t\t\t\tadvance();\n
\t\t\t} else if (state.tokens.next.id === "(number)") {\n
\t\t\t\tid = state.tokens.next.value.toString();\n
\t\t\t\tadvance();\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (id === "hasOwnProperty") {\n
\t\t\twarning("W001");\n
\t\t}\n
\n
\t\treturn id;\n
\t}\n
\n
\n
\tfunction functionparams(parsed) {\n
\t\tvar curr, next;\n
\t\tvar params = [];\n
\t\tvar ident;\n
\t\tvar tokens = [];\n
\t\tvar t;\n
\t\tvar pastDefault = false;\n
\n
\t\tif (parsed) {\n
\t\t\tif (parsed instanceof Array) {\n
\t\t\t\tfor (var i in parsed) {\n
\t\t\t\t\tcurr = parsed[i];\n
\t\t\t\t\tif (_.contains(["{", "["], curr.id)) {\n
\t\t\t\t\t\tfor (t in curr.left) {\n
\t\t\t\t\t\t\tt = tokens[t];\n
\t\t\t\t\t\t\tif (t.id) {\n
\t\t\t\t\t\t\t\tparams.push(t.id);\n
\t\t\t\t\t\t\t\taddlabel(t.id, "unused", t.token);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if (curr.value === "...") {\n
\t\t\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\t\t\twarning("W104", curr, "spread/rest operator");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\taddlabel(curr.value, "unused", curr);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn params;\n
\t\t\t} else {\n
\t\t\t\tif (parsed.identifier === true) {\n
\t\t\t\t\taddlabel(parsed.value, "unused", parsed);\n
\t\t\t\t\treturn [parsed];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tnext = state.tokens.next;\n
\n
\t\tadvance("(");\n
\t\tnospace();\n
\n
\t\tif (state.tokens.next.id === ")") {\n
\t\t\tadvance(")");\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tfor (;;) {\n
\t\t\tif (_.contains(["{", "["], state.tokens.next.id)) {\n
\t\t\t\ttokens = destructuringExpression();\n
\t\t\t\tfor (t in tokens) {\n
\t\t\t\t\tt = tokens[t];\n
\t\t\t\t\tif (t.id) {\n
\t\t\t\t\t\tparams.push(t.id);\n
\t\t\t\t\t\taddlabel(t.id, "unused", t.token);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else if (state.tokens.next.value === "...") {\n
\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\twarning("W104", state.tokens.next, "spread/rest operator");\n
\t\t\t\t}\n
\t\t\t\tadvance("...");\n
\t\t\t\tnospace();\n
\t\t\t\tident = identifier(true);\n
\t\t\t\tparams.push(ident);\n
\t\t\t\taddlabel(ident, "unused", state.tokens.curr);\n
\t\t\t} else {\n
\t\t\t\tident = identifier(true);\n
\t\t\t\tparams.push(ident);\n
\t\t\t\taddlabel(ident, "unused", state.tokens.curr);\n
\t\t\t}\n
\t\t\tif (pastDefault) {\n
\t\t\t\tif (state.tokens.next.id !== "=") {\n
\t\t\t\t\terror("E051", state.tokens.current);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id === "=") {\n
\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\twarning("W119", state.tokens.next, "default parameters");\n
\t\t\t\t}\n
\t\t\t\tadvance("=");\n
\t\t\t\tpastDefault = true;\n
\t\t\t\texpression(10);\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id === ",") {\n
\t\t\t\tcomma();\n
\t\t\t} else {\n
\t\t\t\tadvance(")", next);\n
\t\t\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\t\t\treturn params;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\n
\tfunction doFunction(name, statement, generator, fatarrowparams) {\n
\t\tvar f;\n
\t\tvar oldOption = state.option;\n
\t\tvar oldIgnored = state.ignored;\n
\t\tvar oldScope  = scope;\n
\n
\t\tstate.option = Object.create(state.option);\n
\t\tstate.ignored = Object.create(state.ignored);\n
\t\tscope  = Object.create(scope);\n
\n
\t\tfunct = {\n
\t\t\t"(name)"      : name || "\\"" + anonname + "\\"",\n
\t\t\t"(line)"      : state.tokens.next.line,\n
\t\t\t"(character)" : state.tokens.next.character,\n
\t\t\t"(context)"   : funct,\n
\t\t\t"(breakage)"  : 0,\n
\t\t\t"(loopage)"   : 0,\n
\t\t\t"(metrics)"   : createMetrics(state.tokens.next),\n
\t\t\t"(scope)"     : scope,\n
\t\t\t"(statement)" : statement,\n
\t\t\t"(tokens)"    : {},\n
\t\t\t"(blockscope)": funct["(blockscope)"],\n
\t\t\t"(comparray)" : funct["(comparray)"]\n
\t\t};\n
\n
\t\tif (generator) {\n
\t\t\tfunct["(generator)"] = true;\n
\t\t}\n
\n
\t\tf = funct;\n
\t\tstate.tokens.curr.funct = funct;\n
\n
\t\tfunctions.push(funct);\n
\n
\t\tif (name) {\n
\t\t\taddlabel(name, "function");\n
\t\t}\n
\n
\t\tfunct["(params)"] = functionparams(fatarrowparams);\n
\n
\t\tfunct["(metrics)"].verifyMaxParametersPerFunction(funct["(params)"]);\n
\n
\t\tblock(false, true, true, fatarrowparams ? true:false);\n
\n
\t\tif (generator && funct["(generator)"] !== "yielded") {\n
\t\t\terror("E047", state.tokens.curr);\n
\t\t}\n
\n
\t\tfunct["(metrics)"].verifyMaxStatementsPerFunction();\n
\t\tfunct["(metrics)"].verifyMaxComplexityPerFunction();\n
\t\tfunct["(unusedOption)"] = state.option.unused;\n
\n
\t\tscope = oldScope;\n
\t\tstate.option = oldOption;\n
\t\tstate.ignored = oldIgnored;\n
\t\tfunct["(last)"] = state.tokens.curr.line;\n
\t\tfunct["(lastcharacter)"] = state.tokens.curr.character;\n
\t\tfunct = funct["(context)"];\n
\n
\t\treturn f;\n
\t}\n
\n
\tfunction createMetrics(functionStartToken) {\n
\t\treturn {\n
\t\t\tstatementCount: 0,\n
\t\t\tnestedBlockDepth: -1,\n
\t\t\tComplexityCount: 1,\n
\t\t\tverifyMaxStatementsPerFunction: function () {\n
\t\t\t\tif (state.option.maxstatements &&\n
\t\t\t\t\tthis.statementCount > state.option.maxstatements) {\n
\t\t\t\t\twarning("W071", functionStartToken, this.statementCount);\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\tverifyMaxParametersPerFunction: function (params) {\n
\t\t\t\tparams = params || [];\n
\n
\t\t\t\tif (state.option.maxparams && params.length > state.option.maxparams) {\n
\t\t\t\t\twarning("W072", functionStartToken, params.length);\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\tverifyMaxNestedBlockDepthPerFunction: function () {\n
\t\t\t\tif (state.option.maxdepth &&\n
\t\t\t\t\tthis.nestedBlockDepth > 0 &&\n
\t\t\t\t\tthis.nestedBlockDepth === state.option.maxdepth + 1) {\n
\t\t\t\t\twarning("W073", null, this.nestedBlockDepth);\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\tverifyMaxComplexityPerFunction: function () {\n
\t\t\t\tvar max = state.option.maxcomplexity;\n
\t\t\t\tvar cc = this.ComplexityCount;\n
\t\t\t\tif (max && cc > max) {\n
\t\t\t\t\twarning("W074", functionStartToken, cc);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\t}\n
\n
\tfunction increaseComplexityCount() {\n
\t\tfunct["(metrics)"].ComplexityCount += 1;\n
\t}\n
\n
\tfunction checkCondAssignment(expr) {\n
\t\tvar id, paren;\n
\t\tif (expr) {\n
\t\t\tid = expr.id;\n
\t\t\tparen = expr.paren;\n
\t\t\tif (id === "," && (expr = expr.exprs[expr.exprs.length - 1])) {\n
\t\t\t\tid = expr.id;\n
\t\t\t\tparen = paren || expr.paren;\n
\t\t\t}\n
\t\t}\n
\t\tswitch (id) {\n
\t\tcase "=":\n
\t\tcase "+=":\n
\t\tcase "-=":\n
\t\tcase "*=":\n
\t\tcase "%=":\n
\t\tcase "&=":\n
\t\tcase "|=":\n
\t\tcase "^=":\n
\t\tcase "/=":\n
\t\t\tif (!paren && !state.option.boss) {\n
\t\t\t\twarning("W084");\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\n
\t(function (x) {\n
\t\tx.nud = function (isclassdef) {\n
\t\t\tvar b, f, i, p, t, g;\n
\t\t\tvar props = {}; // All properties, including accessors\n
\t\t\tvar tag = "";\n
\n
\t\t\tfunction saveProperty(name, tkn) {\n
\t\t\t\tif (props[name] && _.has(props, name))\n
\t\t\t\t\twarning("W075", state.tokens.next, i);\n
\t\t\t\telse\n
\t\t\t\t\tprops[name] = {};\n
\n
\t\t\t\tprops[name].basic = true;\n
\t\t\t\tprops[name].basictkn = tkn;\n
\t\t\t}\n
\n
\t\t\tfunction saveSetter(name, tkn) {\n
\t\t\t\tif (props[name] && _.has(props, name)) {\n
\t\t\t\t\tif (props[name].basic || props[name].setter)\n
\t\t\t\t\t\twarning("W075", state.tokens.next, i);\n
\t\t\t\t} else {\n
\t\t\t\t\tprops[name] = {};\n
\t\t\t\t}\n
\n
\t\t\t\tprops[name].setter = true;\n
\t\t\t\tprops[name].setterToken = tkn;\n
\t\t\t}\n
\n
\t\t\tfunction saveGetter(name) {\n
\t\t\t\tif (props[name] && _.has(props, name)) {\n
\t\t\t\t\tif (props[name].basic || props[name].getter)\n
\t\t\t\t\t\twarning("W075", state.tokens.next, i);\n
\t\t\t\t} else {\n
\t\t\t\t\tprops[name] = {};\n
\t\t\t\t}\n
\n
\t\t\t\tprops[name].getter = true;\n
\t\t\t\tprops[name].getterToken = state.tokens.curr;\n
\t\t\t}\n
\n
\t\t\tb = state.tokens.curr.line !== state.tokens.next.line;\n
\t\t\tif (b) {\n
\t\t\t\tindent += state.option.indent;\n
\t\t\t\tif (state.tokens.next.from === indent + state.option.indent) {\n
\t\t\t\t\tindent += state.option.indent;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tfor (;;) {\n
\t\t\t\tif (state.tokens.next.id === "}") {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tif (b) {\n
\t\t\t\t\tindentation();\n
\t\t\t\t}\n
\n
\t\t\t\tif (isclassdef && state.tokens.next.value === "static") {\n
\t\t\t\t\tadvance("static");\n
\t\t\t\t\ttag = "static ";\n
\t\t\t\t}\n
\n
\t\t\t\tif (state.tokens.next.value === "get" && peek().id !== ":") {\n
\t\t\t\t\tadvance("get");\n
\n
\t\t\t\t\tif (!state.option.inES5(!isclassdef)) {\n
\t\t\t\t\t\terror("E034");\n
\t\t\t\t\t}\n
\n
\t\t\t\t\ti = property_name();\n
\t\t\t\t\tif (!i) {\n
\t\t\t\t\t\terror("E035");\n
\t\t\t\t\t}\n
\t\t\t\t\tif (isclassdef && i === "constructor") {\n
\t\t\t\t\t\terror("E049", state.tokens.next, "class getter method", i);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tsaveGetter(tag + i);\n
\t\t\t\t\tt = state.tokens.next;\n
\t\t\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\t\tf = doFunction();\n
\t\t\t\t\tp = f["(params)"];\n
\n
\t\t\t\t\tif (p) {\n
\t\t\t\t\t\twarning("W076", t, p[0], i);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\t} else if (state.tokens.next.value === "set" && peek().id !== ":") {\n
\t\t\t\t\tadvance("set");\n
\n
\t\t\t\t\tif (!state.option.inES5(!isclassdef)) {\n
\t\t\t\t\t\terror("E034");\n
\t\t\t\t\t}\n
\n
\t\t\t\t\ti = property_name();\n
\t\t\t\t\tif (!i) {\n
\t\t\t\t\t\terror("E035");\n
\t\t\t\t\t}\n
\t\t\t\t\tif (isclassdef && i === "constructor") {\n
\t\t\t\t\t\terror("E049", state.tokens.next, "class setter method", i);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tsaveSetter(tag + i, state.tokens.next);\n
\t\t\t\t\tt = state.tokens.next;\n
\t\t\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\t\tf = doFunction();\n
\t\t\t\t\tp = f["(params)"];\n
\n
\t\t\t\t\tif (!p || p.length !== 1) {\n
\t\t\t\t\t\twarning("W077", t, i);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tg = false;\n
\t\t\t\t\tif (state.tokens.next.value === "*" && state.tokens.next.type === "(punctuator)") {\n
\t\t\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\t\t\twarning("W104", state.tokens.next, "generator functions");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tadvance("*");\n
\t\t\t\t\t\tg = true;\n
\t\t\t\t\t}\n
\t\t\t\t\ti = property_name();\n
\t\t\t\t\tsaveProperty(tag + i, state.tokens.next);\n
\n
\t\t\t\t\tif (typeof i !== "string") {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif (state.tokens.next.value === "(") {\n
\t\t\t\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\t\t\t\twarning("W104", state.tokens.curr, "concise methods");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tdoFunction(i, undefined, g);\n
\t\t\t\t\t} else if (!isclassdef) {\n
\t\t\t\t\t\tadvance(":");\n
\t\t\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\t\t\texpression(10);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tif (isclassdef && i === "prototype") {\n
\t\t\t\t\terror("E049", state.tokens.next, "class method", i);\n
\t\t\t\t}\n
\n
\t\t\t\tcountMember(i);\n
\t\t\t\tif (isclassdef) {\n
\t\t\t\t\ttag = "";\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t\tif (state.tokens.next.id === ",") {\n
\t\t\t\t\tcomma({ allowTrailing: true, property: true });\n
\t\t\t\t\tif (state.tokens.next.id === ",") {\n
\t\t\t\t\t\twarning("W070", state.tokens.curr);\n
\t\t\t\t\t} else if (state.tokens.next.id === "}" && !state.option.inES5(true)) {\n
\t\t\t\t\t\twarning("W070", state.tokens.curr);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (b) {\n
\t\t\t\tindent -= state.option.indent;\n
\t\t\t\tindentation();\n
\t\t\t}\n
\t\t\tadvance("}", this);\n
\t\t\tif (state.option.inES5()) {\n
\t\t\t\tfor (var name in props) {\n
\t\t\t\t\tif (_.has(props, name) && props[name].setter && !props[name].getter) {\n
\t\t\t\t\t\twarning("W078", props[name].setterToken);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t};\n
\t\tx.fud = function () {\n
\t\t\terror("E036", state.tokens.curr);\n
\t\t};\n
\t}(delim("{")));\n
\n
\tfunction destructuringExpression() {\n
\t\tvar id, ids;\n
\t\tvar identifiers = [];\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "destructuring expression");\n
\t\t}\n
\t\tvar nextInnerDE = function () {\n
\t\t\tvar ident;\n
\t\t\tif (_.contains(["[", "{"], state.tokens.next.value)) {\n
\t\t\t\tids = destructuringExpression();\n
\t\t\t\tfor (var id in ids) {\n
\t\t\t\t\tid = ids[id];\n
\t\t\t\t\tidentifiers.push({ id: id.id, token: id.token });\n
\t\t\t\t}\n
\t\t\t} else if (state.tokens.next.value === ",") {\n
\t\t\t\tidentifiers.push({ id: null, token: state.tokens.curr });\n
\t\t\t} else {\n
\t\t\t\tident = identifier();\n
\t\t\t\tif (ident)\n
\t\t\t\t\tidentifiers.push({ id: ident, token: state.tokens.curr });\n
\t\t\t}\n
\t\t};\n
\t\tif (state.tokens.next.value === "[") {\n
\t\t\tadvance("[");\n
\t\t\tnextInnerDE();\n
\t\t\twhile (state.tokens.next.value !== "]") {\n
\t\t\t\tadvance(",");\n
\t\t\t\tnextInnerDE();\n
\t\t\t}\n
\t\t\tadvance("]");\n
\t\t} else if (state.tokens.next.value === "{") {\n
\t\t\tadvance("{");\n
\t\t\tid = identifier();\n
\t\t\tif (state.tokens.next.value === ":") {\n
\t\t\t\tadvance(":");\n
\t\t\t\tnextInnerDE();\n
\t\t\t} else {\n
\t\t\t\tidentifiers.push({ id: id, token: state.tokens.curr });\n
\t\t\t}\n
\t\t\twhile (state.tokens.next.value !== "}") {\n
\t\t\t\tadvance(",");\n
\t\t\t\tid = identifier();\n
\t\t\t\tif (state.tokens.next.value === ":") {\n
\t\t\t\t\tadvance(":");\n
\t\t\t\t\tnextInnerDE();\n
\t\t\t\t} else {\n
\t\t\t\t\tidentifiers.push({ id: id, token: state.tokens.curr });\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tadvance("}");\n
\t\t}\n
\t\treturn identifiers;\n
\t}\n
\tfunction destructuringExpressionMatch(tokens, value) {\n
\t\tif (value.first) {\n
\t\t\t_.zip(tokens, value.first).forEach(function (val) {\n
\t\t\t\tvar token = val[0];\n
\t\t\t\tvar value = val[1];\n
\t\t\t\tif (token && value) {\n
\t\t\t\t\ttoken.first = value;\n
\t\t\t\t} else if (token && token.first && !value) {\n
\t\t\t\t\twarning("W080", token.first, token.first.value);\n
\t\t\t\t} /* else {\n
\t\t\t\t\tXXX value is discarded: wouldn\'t it need a warning ?\n
\t\t\t\t} */\n
\t\t\t});\n
\t\t}\n
\t}\n
\n
\tvar conststatement = stmt("const", function (prefix) {\n
\t\tvar tokens, value;\n
\t\tvar lone;\n
\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "const");\n
\t\t}\n
\n
\t\tthis.first = [];\n
\t\tfor (;;) {\n
\t\t\tvar names = [];\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tif (_.contains(["{", "["], state.tokens.next.value)) {\n
\t\t\t\ttokens = destructuringExpression();\n
\t\t\t\tlone = false;\n
\t\t\t} else {\n
\t\t\t\ttokens = [ { id: identifier(), token: state.tokens.curr } ];\n
\t\t\t\tlone = true;\n
\t\t\t}\n
\t\t\tfor (var t in tokens) {\n
\t\t\t\tt = tokens[t];\n
\t\t\t\tif (funct[t.id] === "const") {\n
\t\t\t\t\twarning("E011", null, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (funct["(global)"] && predefined[t.id] === false) {\n
\t\t\t\t\twarning("W079", t.token, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (t.id) {\n
\t\t\t\t\taddlabel(t.id, "const");\n
\t\t\t\t\tnames.push(t.token);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (prefix) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tthis.first = this.first.concat(names);\n
\n
\t\t\tif (state.tokens.next.id !== "=") {\n
\t\t\t\twarning("E012", state.tokens.curr, state.tokens.curr.value);\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id === "=") {\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tadvance("=");\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tif (state.tokens.next.id === "undefined") {\n
\t\t\t\t\twarning("W080", state.tokens.prev, state.tokens.prev.value);\n
\t\t\t\t}\n
\t\t\t\tif (peek(0).id === "=" && state.tokens.next.identifier) {\n
\t\t\t\t\twarning("W120", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t}\n
\t\t\t\tvalue = expression(10);\n
\t\t\t\tif (lone) {\n
\t\t\t\t\ttokens[0].first = value;\n
\t\t\t\t} else {\n
\t\t\t\t\tdestructuringExpressionMatch(names, value);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tcomma();\n
\t\t}\n
\t\treturn this;\n
\t});\n
\tconststatement.exps = true;\n
\tvar varstatement = stmt("var", function (prefix) {\n
\t\tvar tokens, lone, value;\n
\n
\t\tif (funct["(onevar)"] && state.option.onevar) {\n
\t\t\twarning("W081");\n
\t\t} else if (!funct["(global)"]) {\n
\t\t\tfunct["(onevar)"] = true;\n
\t\t}\n
\n
\t\tthis.first = [];\n
\t\tfor (;;) {\n
\t\t\tvar names = [];\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tif (_.contains(["{", "["], state.tokens.next.value)) {\n
\t\t\t\ttokens = destructuringExpression();\n
\t\t\t\tlone = false;\n
\t\t\t} else {\n
\t\t\t\ttokens = [ { id: identifier(), token: state.tokens.curr } ];\n
\t\t\t\tlone = true;\n
\t\t\t}\n
\t\t\tfor (var t in tokens) {\n
\t\t\t\tt = tokens[t];\n
\t\t\t\tif (state.option.inESNext() && funct[t.id] === "const") {\n
\t\t\t\t\twarning("E011", null, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (funct["(global)"] && predefined[t.id] === false) {\n
\t\t\t\t\twarning("W079", t.token, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (t.id) {\n
\t\t\t\t\taddlabel(t.id, "unused", t.token);\n
\t\t\t\t\tnames.push(t.token);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (prefix) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tthis.first = this.first.concat(names);\n
\n
\t\t\tif (state.tokens.next.id === "=") {\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tadvance("=");\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tif (state.tokens.next.id === "undefined") {\n
\t\t\t\t\twarning("W080", state.tokens.prev, state.tokens.prev.value);\n
\t\t\t\t}\n
\t\t\t\tif (peek(0).id === "=" && state.tokens.next.identifier) {\n
\t\t\t\t\twarning("W120", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t}\n
\t\t\t\tvalue = expression(10);\n
\t\t\t\tif (lone) {\n
\t\t\t\t\ttokens[0].first = value;\n
\t\t\t\t} else {\n
\t\t\t\t\tdestructuringExpressionMatch(names, value);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tcomma();\n
\t\t}\n
\t\treturn this;\n
\t});\n
\tvarstatement.exps = true;\n
\tvar letstatement = stmt("let", function (prefix) {\n
\t\tvar tokens, lone, value, letblock;\n
\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "let");\n
\t\t}\n
\n
\t\tif (state.tokens.next.value === "(") {\n
\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\twarning("W118", state.tokens.next, "let block");\n
\t\t\t}\n
\t\t\tadvance("(");\n
\t\t\tfunct["(blockscope)"].stack();\n
\t\t\tletblock = true;\n
\t\t} else if (funct["(nolet)"]) {\n
\t\t\terror("E048", state.tokens.curr);\n
\t\t}\n
\n
\t\tif (funct["(onevar)"] && state.option.onevar) {\n
\t\t\twarning("W081");\n
\t\t} else if (!funct["(global)"]) {\n
\t\t\tfunct["(onevar)"] = true;\n
\t\t}\n
\n
\t\tthis.first = [];\n
\t\tfor (;;) {\n
\t\t\tvar names = [];\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tif (_.contains(["{", "["], state.tokens.next.value)) {\n
\t\t\t\ttokens = destructuringExpression();\n
\t\t\t\tlone = false;\n
\t\t\t} else {\n
\t\t\t\ttokens = [ { id: identifier(), token: state.tokens.curr.value } ];\n
\t\t\t\tlone = true;\n
\t\t\t}\n
\t\t\tfor (var t in tokens) {\n
\t\t\t\tt = tokens[t];\n
\t\t\t\tif (state.option.inESNext() && funct[t.id] === "const") {\n
\t\t\t\t\twarning("E011", null, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (funct["(global)"] && predefined[t.id] === false) {\n
\t\t\t\t\twarning("W079", t.token, t.id);\n
\t\t\t\t}\n
\t\t\t\tif (t.id && !funct["(nolet)"]) {\n
\t\t\t\t\taddlabel(t.id, "unused", t.token, true);\n
\t\t\t\t\tnames.push(t.token);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif (prefix) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tthis.first = this.first.concat(names);\n
\n
\t\t\tif (state.tokens.next.id === "=") {\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tadvance("=");\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tif (state.tokens.next.id === "undefined") {\n
\t\t\t\t\twarning("W080", state.tokens.prev, state.tokens.prev.value);\n
\t\t\t\t}\n
\t\t\t\tif (peek(0).id === "=" && state.tokens.next.identifier) {\n
\t\t\t\t\twarning("W120", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t}\n
\t\t\t\tvalue = expression(10);\n
\t\t\t\tif (lone) {\n
\t\t\t\t\ttokens[0].first = value;\n
\t\t\t\t} else {\n
\t\t\t\t\tdestructuringExpressionMatch(names, value);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tcomma();\n
\t\t}\n
\t\tif (letblock) {\n
\t\t\tadvance(")");\n
\t\t\tblock(true, true);\n
\t\t\tthis.block = true;\n
\t\t\tfunct["(blockscope)"].unstack();\n
\t\t}\n
\n
\t\treturn this;\n
\t});\n
\tletstatement.exps = true;\n
\n
\tblockstmt("class", function () {\n
\t\treturn classdef.call(this, true);\n
\t});\n
\n
\tfunction classdef(stmt) {\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "class");\n
\t\t}\n
\t\tif (stmt) {\n
\t\t\tthis.name = identifier();\n
\t\t\taddlabel(this.name, "unused", state.tokens.curr);\n
\t\t} else if (state.tokens.next.identifier && state.tokens.next.value !== "extends") {\n
\t\t\tthis.name = identifier();\n
\t\t}\n
\t\tclasstail(this);\n
\t\treturn this;\n
\t}\n
\n
\tfunction classtail(c) {\n
\t\tvar strictness = state.directive["use strict"];\n
\t\tif (state.tokens.next.value === "extends") {\n
\t\t\tadvance("extends");\n
\t\t\tc.heritage = expression(10);\n
\t\t}\n
\t\tstate.directive["use strict"] = true;\n
\t\tadvance("{");\n
\t\tc.body = state.syntax["{"].nud(true);\n
\t\tstate.directive["use strict"] = strictness;\n
\t}\n
\n
\tblockstmt("function", function () {\n
\t\tvar generator = false;\n
\t\tif (state.tokens.next.value === "*") {\n
\t\t\tadvance("*");\n
\t\t\tif (state.option.inESNext(true)) {\n
\t\t\t\tgenerator = true;\n
\t\t\t} else {\n
\t\t\t\twarning("W119", state.tokens.curr, "function*");\n
\t\t\t}\n
\t\t}\n
\t\tif (inblock) {\n
\t\t\twarning("W082", state.tokens.curr);\n
\n
\t\t}\n
\t\tvar i = identifier();\n
\t\tif (funct[i] === "const") {\n
\t\t\twarning("E011", null, i);\n
\t\t}\n
\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\taddlabel(i, "unction", state.tokens.curr);\n
\n
\t\tdoFunction(i, { statement: true }, generator);\n
\t\tif (state.tokens.next.id === "(" && state.tokens.next.line === state.tokens.curr.line) {\n
\t\t\terror("E039");\n
\t\t}\n
\t\treturn this;\n
\t});\n
\n
\tprefix("function", function () {\n
\t\tvar generator = false;\n
\t\tif (state.tokens.next.value === "*") {\n
\t\t\tif (!state.option.inESNext()) {\n
\t\t\t\twarning("W119", state.tokens.curr, "function*");\n
\t\t\t}\n
\t\t\tadvance("*");\n
\t\t\tgenerator = true;\n
\t\t}\n
\t\tvar i = optionalidentifier();\n
\t\tif (i || state.option.gcl) {\n
\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t} else {\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t}\n
\t\tdoFunction(i, undefined, generator);\n
\t\tif (!state.option.loopfunc && funct["(loopage)"]) {\n
\t\t\twarning("W083");\n
\t\t}\n
\t\treturn this;\n
\t});\n
\n
\tblockstmt("if", function () {\n
\t\tvar t = state.tokens.next;\n
\t\tincreaseComplexityCount();\n
\t\tstate.condition = true;\n
\t\tadvance("(");\n
\t\tnonadjacent(this, t);\n
\t\tnospace();\n
\t\tcheckCondAssignment(expression(0));\n
\t\tadvance(")", t);\n
\t\tstate.condition = false;\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tblock(true, true);\n
\t\tif (state.tokens.next.id === "else") {\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tadvance("else");\n
\t\t\tif (state.tokens.next.id === "if" || state.tokens.next.id === "switch") {\n
\t\t\t\tstatement(true);\n
\t\t\t} else {\n
\t\t\t\tblock(true, true);\n
\t\t\t}\n
\t\t}\n
\t\treturn this;\n
\t});\n
\n
\tblockstmt("try", function () {\n
\t\tvar b;\n
\n
\t\tfunction doCatch() {\n
\t\t\tvar oldScope = scope;\n
\t\t\tvar e;\n
\n
\t\t\tadvance("catch");\n
\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tadvance("(");\n
\n
\t\t\tscope = Object.create(oldScope);\n
\n
\t\t\te = state.tokens.next.value;\n
\t\t\tif (state.tokens.next.type !== "(identifier)") {\n
\t\t\t\te = null;\n
\t\t\t\twarning("E030", state.tokens.next, e);\n
\t\t\t}\n
\n
\t\t\tadvance();\n
\n
\t\t\tfunct = {\n
\t\t\t\t"(name)"     : "(catch)",\n
\t\t\t\t"(line)"     : state.tokens.next.line,\n
\t\t\t\t"(character)": state.tokens.next.character,\n
\t\t\t\t"(context)"  : funct,\n
\t\t\t\t"(breakage)" : funct["(breakage)"],\n
\t\t\t\t"(loopage)"  : funct["(loopage)"],\n
\t\t\t\t"(scope)"    : scope,\n
\t\t\t\t"(statement)": false,\n
\t\t\t\t"(metrics)"  : createMetrics(state.tokens.next),\n
\t\t\t\t"(catch)"    : true,\n
\t\t\t\t"(tokens)"   : {},\n
\t\t\t\t"(blockscope)": funct["(blockscope)"],\n
\t\t\t\t"(comparray)": funct["(comparray)"]\n
\t\t\t};\n
\n
\t\t\tif (e) {\n
\t\t\t\taddlabel(e, "exception");\n
\t\t\t}\n
\n
\t\t\tif (state.tokens.next.value === "if") {\n
\t\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\t\twarning("W118", state.tokens.curr, "catch filter");\n
\t\t\t\t}\n
\t\t\t\tadvance("if");\n
\t\t\t\texpression(0);\n
\t\t\t}\n
\n
\t\t\tadvance(")");\n
\n
\t\t\tstate.tokens.curr.funct = funct;\n
\t\t\tfunctions.push(funct);\n
\n
\t\t\tblock(false);\n
\n
\t\t\tscope = oldScope;\n
\n
\t\t\tfunct["(last)"] = state.tokens.curr.line;\n
\t\t\tfunct["(lastcharacter)"] = state.tokens.curr.character;\n
\t\t\tfunct = funct["(context)"];\n
\t\t}\n
\n
\t\tblock(false);\n
\n
\t\twhile (state.tokens.next.id === "catch") {\n
\t\t\tincreaseComplexityCount();\n
\t\t\tif (b && (!state.option.inMoz(true))) {\n
\t\t\t\twarning("W118", state.tokens.next, "multiple catch blocks");\n
\t\t\t}\n
\t\t\tdoCatch();\n
\t\t\tb = true;\n
\t\t}\n
\n
\t\tif (state.tokens.next.id === "finally") {\n
\t\t\tadvance("finally");\n
\t\t\tblock(false);\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (!b) {\n
\t\t\terror("E021", state.tokens.next, "catch", state.tokens.next.value);\n
\t\t}\n
\n
\t\treturn this;\n
\t});\n
\n
\tblockstmt("while", function () {\n
\t\tvar t = state.tokens.next;\n
\t\tfunct["(breakage)"] += 1;\n
\t\tfunct["(loopage)"] += 1;\n
\t\tincreaseComplexityCount();\n
\t\tadvance("(");\n
\t\tnonadjacent(this, t);\n
\t\tnospace();\n
\t\tcheckCondAssignment(expression(0));\n
\t\tadvance(")", t);\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tblock(true, true);\n
\t\tfunct["(breakage)"] -= 1;\n
\t\tfunct["(loopage)"] -= 1;\n
\t\treturn this;\n
\t}).labelled = true;\n
\n
\tblockstmt("with", function () {\n
\t\tvar t = state.tokens.next;\n
\t\tif (state.directive["use strict"]) {\n
\t\t\terror("E010", state.tokens.curr);\n
\t\t} else if (!state.option.withstmt) {\n
\t\t\twarning("W085", state.tokens.curr);\n
\t\t}\n
\n
\t\tadvance("(");\n
\t\tnonadjacent(this, t);\n
\t\tnospace();\n
\t\texpression(0);\n
\t\tadvance(")", t);\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tblock(true, true);\n
\n
\t\treturn this;\n
\t});\n
\n
\tblockstmt("switch", function () {\n
\t\tvar t = state.tokens.next,\n
\t\t\tg = false;\n
\t\tfunct["(breakage)"] += 1;\n
\t\tadvance("(");\n
\t\tnonadjacent(this, t);\n
\t\tnospace();\n
\t\tcheckCondAssignment(expression(0));\n
\t\tadvance(")", t);\n
\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\tt = state.tokens.next;\n
\t\tadvance("{");\n
\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\tindent += state.option.indent;\n
\t\tthis.cases = [];\n
\n
\t\tfor (;;) {\n
\t\t\tswitch (state.tokens.next.id) {\n
\t\t\tcase "case":\n
\t\t\t\tswitch (funct["(verb)"]) {\n
\t\t\t\tcase "yield":\n
\t\t\t\tcase "break":\n
\t\t\t\tcase "case":\n
\t\t\t\tcase "continue":\n
\t\t\t\tcase "return":\n
\t\t\t\tcase "switch":\n
\t\t\t\tcase "throw":\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tif (!reg.fallsThrough.test(state.lines[state.tokens.next.line - 2])) {\n
\t\t\t\t\t\twarning("W086", state.tokens.curr, "case");\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tindentation(-state.option.indent);\n
\t\t\t\tadvance("case");\n
\t\t\t\tthis.cases.push(expression(20));\n
\t\t\t\tincreaseComplexityCount();\n
\t\t\t\tg = true;\n
\t\t\t\tadvance(":");\n
\t\t\t\tfunct["(verb)"] = "case";\n
\t\t\t\tbreak;\n
\t\t\tcase "default":\n
\t\t\t\tswitch (funct["(verb)"]) {\n
\t\t\t\tcase "yield":\n
\t\t\t\tcase "break":\n
\t\t\t\tcase "continue":\n
\t\t\t\tcase "return":\n
\t\t\t\tcase "throw":\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tif (this.cases.length) {\n
\t\t\t\t\t\tif (!reg.fallsThrough.test(state.lines[state.tokens.next.line - 2])) {\n
\t\t\t\t\t\t\twarning("W086", state.tokens.curr, "default");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tindentation(-state.option.indent);\n
\t\t\t\tadvance("default");\n
\t\t\t\tg = true;\n
\t\t\t\tadvance(":");\n
\t\t\t\tbreak;\n
\t\t\tcase "}":\n
\t\t\t\tindent -= state.option.indent;\n
\t\t\t\tindentation();\n
\t\t\t\tadvance("}", t);\n
\t\t\t\tfunct["(breakage)"] -= 1;\n
\t\t\t\tfunct["(verb)"] = undefined;\n
\t\t\t\treturn;\n
\t\t\tcase "(end)":\n
\t\t\t\terror("E023", state.tokens.next, "}");\n
\t\t\t\treturn;\n
\t\t\tdefault:\n
\t\t\t\tif (g) {\n
\t\t\t\t\tswitch (state.tokens.curr.id) {\n
\t\t\t\t\tcase ",":\n
\t\t\t\t\t\terror("E040");\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\tcase ":":\n
\t\t\t\t\t\tg = false;\n
\t\t\t\t\t\tstatements();\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\terror("E025", state.tokens.curr);\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tif (state.tokens.curr.id === ":") {\n
\t\t\t\t\t\tadvance(":");\n
\t\t\t\t\t\terror("E024", state.tokens.curr, ":");\n
\t\t\t\t\t\tstatements();\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\terror("E021", state.tokens.next, "case", state.tokens.next.value);\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}).labelled = true;\n
\n
\tstmt("debugger", function () {\n
\t\tif (!state.option.debug) {\n
\t\t\twarning("W087");\n
\t\t}\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\t(function () {\n
\t\tvar x = stmt("do", function () {\n
\t\t\tfunct["(breakage)"] += 1;\n
\t\t\tfunct["(loopage)"] += 1;\n
\t\t\tincreaseComplexityCount();\n
\n
\t\t\tthis.first = block(true, true);\n
\t\t\tadvance("while");\n
\t\t\tvar t = state.tokens.next;\n
\t\t\tnonadjacent(state.tokens.curr, t);\n
\t\t\tadvance("(");\n
\t\t\tnospace();\n
\t\t\tcheckCondAssignment(expression(0));\n
\t\t\tadvance(")", t);\n
\t\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\t\tfunct["(breakage)"] -= 1;\n
\t\t\tfunct["(loopage)"] -= 1;\n
\t\t\treturn this;\n
\t\t});\n
\t\tx.labelled = true;\n
\t\tx.exps = true;\n
\t}());\n
\n
\tblockstmt("for", function () {\n
\t\tvar s, t = state.tokens.next;\n
\t\tvar letscope = false;\n
\t\tvar foreachtok = null;\n
\n
\t\tif (t.value === "each") {\n
\t\t\tforeachtok = t;\n
\t\t\tadvance("each");\n
\t\t\tif (!state.option.inMoz(true)) {\n
\t\t\t\twarning("W118", state.tokens.curr, "for each");\n
\t\t\t}\n
\t\t}\n
\n
\t\tfunct["(breakage)"] += 1;\n
\t\tfunct["(loopage)"] += 1;\n
\t\tincreaseComplexityCount();\n
\t\tadvance("(");\n
\t\tnonadjacent(this, t);\n
\t\tnospace();\n
\t\tvar nextop; // contains the token of the "in" or "of" operator\n
\t\tvar i = 0;\n
\t\tvar inof = ["in", "of"];\n
\t\tdo {\n
\t\t\tnextop = peek(i);\n
\t\t\t++i;\n
\t\t} while (!_.contains(inof, nextop.value) && nextop.value !== ";" &&\n
\t\t\t\t\tnextop.type !== "(end)");\n
\t\tif (_.contains(inof, nextop.value)) {\n
\t\t\tif (!state.option.inESNext() && nextop.value === "of") {\n
\t\t\t\terror("W104", nextop, "for of");\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id === "var") {\n
\t\t\t\tadvance("var");\n
\t\t\t\tstate.syntax["var"].fud.call(state.syntax["var"].fud, true);\n
\t\t\t} else if (state.tokens.next.

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

id === "let") {\n
\t\t\t\tadvance("let");\n
\t\t\t\tletscope = true;\n
\t\t\t\tfunct["(blockscope)"].stack();\n
\t\t\t\tstate.syntax["let"].fud.call(state.syntax["let"].fud, true);\n
\t\t\t} else {\n
\t\t\t\tswitch (funct[state.tokens.next.value]) {\n
\t\t\t\tcase "unused":\n
\t\t\t\t\tfunct[state.tokens.next.value] = "var";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "var":\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tif (!funct["(blockscope)"].getlabel(state.tokens.next.value))\n
\t\t\t\t\t\twarning("W088", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t}\n
\t\t\t\tadvance();\n
\t\t\t}\n
\t\t\tadvance(nextop.value);\n
\t\t\texpression(20);\n
\t\t\tadvance(")", t);\n
\t\t\ts = block(true, true);\n
\t\t\tif (state.option.forin && s && (s.length > 1 || typeof s[0] !== "object" ||\n
\t\t\t\t\ts[0].value !== "if")) {\n
\t\t\t\twarning("W089", this);\n
\t\t\t}\n
\t\t\tfunct["(breakage)"] -= 1;\n
\t\t\tfunct["(loopage)"] -= 1;\n
\t\t} else {\n
\t\t\tif (foreachtok) {\n
\t\t\t\terror("E045", foreachtok);\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id !== ";") {\n
\t\t\t\tif (state.tokens.next.id === "var") {\n
\t\t\t\t\tadvance("var");\n
\t\t\t\t\tstate.syntax["var"].fud.call(state.syntax["var"].fud);\n
\t\t\t\t} else if (state.tokens.next.id === "let") {\n
\t\t\t\t\tadvance("let");\n
\t\t\t\t\tletscope = true;\n
\t\t\t\t\tfunct["(blockscope)"].stack();\n
\t\t\t\t\tstate.syntax["let"].fud.call(state.syntax["let"].fud);\n
\t\t\t\t} else {\n
\t\t\t\t\tfor (;;) {\n
\t\t\t\t\t\texpression(0, "for");\n
\t\t\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tcomma();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tnolinebreak(state.tokens.curr);\n
\t\t\tadvance(";");\n
\t\t\tif (state.tokens.next.id !== ";") {\n
\t\t\t\tcheckCondAssignment(expression(0));\n
\t\t\t}\n
\t\t\tnolinebreak(state.tokens.curr);\n
\t\t\tadvance(";");\n
\t\t\tif (state.tokens.next.id === ";") {\n
\t\t\t\terror("E021", state.tokens.next, ")", ";");\n
\t\t\t}\n
\t\t\tif (state.tokens.next.id !== ")") {\n
\t\t\t\tfor (;;) {\n
\t\t\t\t\texpression(0, "for");\n
\t\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tcomma();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tadvance(")", t);\n
\t\t\tnospace(state.tokens.prev, state.tokens.curr);\n
\t\t\tblock(true, true);\n
\t\t\tfunct["(breakage)"] -= 1;\n
\t\t\tfunct["(loopage)"] -= 1;\n
\n
\t\t}\n
\t\tif (letscope) {\n
\t\t\tfunct["(blockscope)"].unstack();\n
\t\t}\n
\t\treturn this;\n
\t}).labelled = true;\n
\n
\n
\tstmt("break", function () {\n
\t\tvar v = state.tokens.next.value;\n
\n
\t\tif (funct["(breakage)"] === 0)\n
\t\t\twarning("W052", state.tokens.next, this.value);\n
\n
\t\tif (!state.option.asi)\n
\t\t\tnolinebreak(this);\n
\n
\t\tif (state.tokens.next.id !== ";" && !state.tokens.next.reach) {\n
\t\t\tif (state.tokens.curr.line === state.tokens.next.line) {\n
\t\t\t\tif (funct[v] !== "label") {\n
\t\t\t\t\twarning("W090", state.tokens.next, v);\n
\t\t\t\t} else if (scope[v] !== funct) {\n
\t\t\t\t\twarning("W091", state.tokens.next, v);\n
\t\t\t\t}\n
\t\t\t\tthis.first = state.tokens.next;\n
\t\t\t\tadvance();\n
\t\t\t}\n
\t\t}\n
\t\treachable("break");\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\n
\tstmt("continue", function () {\n
\t\tvar v = state.tokens.next.value;\n
\n
\t\tif (funct["(breakage)"] === 0)\n
\t\t\twarning("W052", state.tokens.next, this.value);\n
\n
\t\tif (!state.option.asi)\n
\t\t\tnolinebreak(this);\n
\n
\t\tif (state.tokens.next.id !== ";" && !state.tokens.next.reach) {\n
\t\t\tif (state.tokens.curr.line === state.tokens.next.line) {\n
\t\t\t\tif (funct[v] !== "label") {\n
\t\t\t\t\twarning("W090", state.tokens.next, v);\n
\t\t\t\t} else if (scope[v] !== funct) {\n
\t\t\t\t\twarning("W091", state.tokens.next, v);\n
\t\t\t\t}\n
\t\t\t\tthis.first = state.tokens.next;\n
\t\t\t\tadvance();\n
\t\t\t}\n
\t\t} else if (!funct["(loopage)"]) {\n
\t\t\twarning("W052", state.tokens.next, this.value);\n
\t\t}\n
\t\treachable("continue");\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\n
\tstmt("return", function () {\n
\t\tif (this.line === state.tokens.next.line) {\n
\t\t\tif (state.tokens.next.id === "(regexp)")\n
\t\t\t\twarning("W092");\n
\n
\t\t\tif (state.tokens.next.id !== ";" && !state.tokens.next.reach) {\n
\t\t\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tthis.first = expression(0);\n
\n
\t\t\t\tif (this.first &&\n
\t\t\t\t\t\tthis.first.type === "(punctuator)" && this.first.value === "=" && !state.option.boss) {\n
\t\t\t\t\twarningAt("W093", this.first.line, this.first.character);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tif (state.tokens.next.type === "(punctuator)" &&\n
\t\t\t\t["[", "{", "+", "-"].indexOf(state.tokens.next.value) > -1) {\n
\t\t\t\tnolinebreak(this); // always warn (Line breaking error)\n
\t\t\t}\n
\t\t}\n
\t\treachable("return");\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\t(function (x) {\n
\t\tx.exps = true;\n
\t\tx.lbp = 25;\n
\t}(prefix("yield", function () {\n
\t\tvar prev = state.tokens.prev;\n
\t\tif (state.option.inESNext(true) && !funct["(generator)"]) {\n
\t\t\terror("E046", state.tokens.curr, "yield");\n
\t\t} else if (!state.option.inESNext()) {\n
\t\t\twarning("W104", state.tokens.curr, "yield");\n
\t\t}\n
\t\tfunct["(generator)"] = "yielded";\n
\t\tif (this.line === state.tokens.next.line || !state.option.inMoz(true)) {\n
\t\t\tif (state.tokens.next.id === "(regexp)")\n
\t\t\t\twarning("W092");\n
\n
\t\t\tif (state.tokens.next.id !== ";" && !state.tokens.next.reach && state.tokens.next.nud) {\n
\t\t\t\tnobreaknonadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\t\tthis.first = expression(10);\n
\n
\t\t\t\tif (this.first.type === "(punctuator)" && this.first.value === "=" && !state.option.boss) {\n
\t\t\t\t\twarningAt("W093", this.first.line, this.first.character);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (state.option.inMoz(true) && state.tokens.next.id !== ")" &&\n
\t\t\t\t\t(prev.lbp > 30 || (!prev.assign && !isEndOfExpr()) || prev.id === "yield")) {\n
\t\t\t\terror("E050", this);\n
\t\t\t}\n
\t\t} else if (!state.option.asi) {\n
\t\t\tnolinebreak(this); // always warn (Line breaking error)\n
\t\t}\n
\t\treturn this;\n
\t})));\n
\n
\n
\tstmt("throw", function () {\n
\t\tnolinebreak(this);\n
\t\tnonadjacent(state.tokens.curr, state.tokens.next);\n
\t\tthis.first = expression(20);\n
\t\treachable("throw");\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\tstmt("import", function () {\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W119", state.tokens.curr, "import");\n
\t\t}\n
\n
\t\tif (state.tokens.next.identifier) {\n
\t\t\tthis.name = identifier();\n
\t\t\taddlabel(this.name, "unused", state.tokens.curr);\n
\t\t} else {\n
\t\t\tadvance("{");\n
\t\t\tfor (;;) {\n
\t\t\t\tvar importName;\n
\t\t\t\tif (state.tokens.next.type === "default") {\n
\t\t\t\t\timportName = "default";\n
\t\t\t\t\tadvance("default");\n
\t\t\t\t} else {\n
\t\t\t\t\timportName = identifier();\n
\t\t\t\t}\n
\t\t\t\tif (state.tokens.next.value === "as") {\n
\t\t\t\t\tadvance("as");\n
\t\t\t\t\timportName = identifier();\n
\t\t\t\t}\n
\t\t\t\taddlabel(importName, "unused", state.tokens.curr);\n
\n
\t\t\t\tif (state.tokens.next.value === ",") {\n
\t\t\t\t\tadvance(",");\n
\t\t\t\t} else if (state.tokens.next.value === "}") {\n
\t\t\t\t\tadvance("}");\n
\t\t\t\t\tbreak;\n
\t\t\t\t} else {\n
\t\t\t\t\terror("E024", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tadvance("from");\n
\t\tadvance("(string)");\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\tstmt("export", function () {\n
\t\tif (!state.option.inESNext()) {\n
\t\t\twarning("W119", state.tokens.curr, "export");\n
\t\t}\n
\n
\t\tif (state.tokens.next.type === "default") {\n
\t\t\tadvance("default");\n
\t\t\tif (state.tokens.next.id === "function" || state.tokens.next.id === "class") {\n
\t\t\t\tthis.block = true;\n
\t\t\t}\n
\t\t\tthis.exportee = expression(10);\n
\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tif (state.tokens.next.value === "{") {\n
\t\t\tadvance("{");\n
\t\t\tfor (;;) {\n
\t\t\t\tidentifier();\n
\n
\t\t\t\tif (state.tokens.next.value === ",") {\n
\t\t\t\t\tadvance(",");\n
\t\t\t\t} else if (state.tokens.next.value === "}") {\n
\t\t\t\t\tadvance("}");\n
\t\t\t\t\tbreak;\n
\t\t\t\t} else {\n
\t\t\t\t\terror("E024", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tif (state.tokens.next.id === "var") {\n
\t\t\tadvance("var");\n
\t\t\tstate.syntax["var"].fud.call(state.syntax["var"].fud);\n
\t\t} else if (state.tokens.next.id === "let") {\n
\t\t\tadvance("let");\n
\t\t\tstate.syntax["let"].fud.call(state.syntax["let"].fud);\n
\t\t} else if (state.tokens.next.id === "const") {\n
\t\t\tadvance("const");\n
\t\t\tstate.syntax["const"].fud.call(state.syntax["const"].fud);\n
\t\t} else if (state.tokens.next.id === "function") {\n
\t\t\tthis.block = true;\n
\t\t\tadvance("function");\n
\t\t\tstate.syntax["function"].fud();\n
\t\t} else if (state.tokens.next.id === "class") {\n
\t\t\tthis.block = true;\n
\t\t\tadvance("class");\n
\t\t\tstate.syntax["class"].fud();\n
\t\t} else {\n
\t\t\terror("E024", state.tokens.next, state.tokens.next.value);\n
\t\t}\n
\n
\t\treturn this;\n
\t}).exps = true;\n
\n
\tFutureReservedWord("abstract");\n
\tFutureReservedWord("boolean");\n
\tFutureReservedWord("byte");\n
\tFutureReservedWord("char");\n
\tFutureReservedWord("class", { es5: true, nud: classdef });\n
\tFutureReservedWord("double");\n
\tFutureReservedWord("enum", { es5: true });\n
\tFutureReservedWord("export", { es5: true });\n
\tFutureReservedWord("extends", { es5: true });\n
\tFutureReservedWord("final");\n
\tFutureReservedWord("float");\n
\tFutureReservedWord("goto");\n
\tFutureReservedWord("implements", { es5: true, strictOnly: true });\n
\tFutureReservedWord("import", { es5: true });\n
\tFutureReservedWord("int");\n
\tFutureReservedWord("interface", { es5: true, strictOnly: true });\n
\tFutureReservedWord("long");\n
\tFutureReservedWord("native");\n
\tFutureReservedWord("package", { es5: true, strictOnly: true });\n
\tFutureReservedWord("private", { es5: true, strictOnly: true });\n
\tFutureReservedWord("protected", { es5: true, strictOnly: true });\n
\tFutureReservedWord("public", { es5: true, strictOnly: true });\n
\tFutureReservedWord("short");\n
\tFutureReservedWord("static", { es5: true, strictOnly: true });\n
\tFutureReservedWord("super", { es5: true });\n
\tFutureReservedWord("synchronized");\n
\tFutureReservedWord("throws");\n
\tFutureReservedWord("transient");\n
\tFutureReservedWord("volatile");\n
\n
\tvar lookupBlockType = function () {\n
\t\tvar pn, pn1;\n
\t\tvar i = 0;\n
\t\tvar bracketStack = 0;\n
\t\tvar ret = {};\n
\t\tif (_.contains(["[", "{"], state.tokens.curr.value))\n
\t\t\tbracketStack += 1;\n
\t\tif (_.contains(["[", "{"], state.tokens.next.value))\n
\t\t\tbracketStack += 1;\n
\t\tif (_.contains(["]", "}"], state.tokens.next.value))\n
\t\t\tbracketStack -= 1;\n
\t\tdo {\n
\t\t\tpn = peek(i);\n
\t\t\tpn1 = peek(i + 1);\n
\t\t\ti = i + 1;\n
\t\t\tif (_.contains(["[", "{"], pn.value)) {\n
\t\t\t\tbracketStack += 1;\n
\t\t\t} else if (_.contains(["]", "}"], pn.value)) {\n
\t\t\t\tbracketStack -= 1;\n
\t\t\t}\n
\t\t\tif (pn.identifier && pn.value === "for" && bracketStack === 1) {\n
\t\t\t\tret.isCompArray = true;\n
\t\t\t\tret.notJson = true;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tif (_.contains(["}", "]"], pn.value) && pn1.value === "=") {\n
\t\t\t\tret.isDestAssign = true;\n
\t\t\t\tret.notJson = true;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tif (pn.value === ";") {\n
\t\t\t\tret.isBlock = true;\n
\t\t\t\tret.notJson = true;\n
\t\t\t}\n
\t\t} while (bracketStack > 0 && pn.id !== "(end)" && i < 15);\n
\t\treturn ret;\n
\t};\n
\tfunction destructuringAssignOrJsonValue() {\n
\n
\t\tvar block = lookupBlockType();\n
\t\tif (block.notJson) {\n
\t\t\tif (!state.option.inESNext() && block.isDestAssign) {\n
\t\t\t\twarning("W104", state.tokens.curr, "destructuring assignment");\n
\t\t\t}\n
\t\t\tstatements();\n
\t\t} else {\n
\t\t\tstate.option.laxbreak = true;\n
\t\t\tstate.jsonMode = true;\n
\t\t\tjsonValue();\n
\t\t}\n
\t}\n
\n
\tvar arrayComprehension = function () {\n
\t\tvar CompArray = function () {\n
\t\t\tthis.mode = "use";\n
\t\t\tthis.variables = [];\n
\t\t};\n
\t\tvar _carrays = [];\n
\t\tvar _current;\n
\t\tfunction declare(v) {\n
\t\t\tvar l = _current.variables.filter(function (elt) {\n
\t\t\t\tif (elt.value === v) {\n
\t\t\t\t\telt.undef = false;\n
\t\t\t\t\treturn v;\n
\t\t\t\t}\n
\t\t\t}).length;\n
\t\t\treturn l !== 0;\n
\t\t}\n
\t\tfunction use(v) {\n
\t\t\tvar l = _current.variables.filter(function (elt) {\n
\t\t\t\tif (elt.value === v && !elt.undef) {\n
\t\t\t\t\tif (elt.unused === true) {\n
\t\t\t\t\t\telt.unused = false;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn v;\n
\t\t\t\t}\n
\t\t\t}).length;\n
\t\t\treturn (l === 0);\n
\t\t}\n
\t\treturn {stack: function () {\n
\t\t\t\t\t_current = new CompArray();\n
\t\t\t\t\t_carrays.push(_current);\n
\t\t\t\t},\n
\t\t\t\tunstack: function () {\n
\t\t\t\t\t_current.variables.filter(function (v) {\n
\t\t\t\t\t\tif (v.unused)\n
\t\t\t\t\t\t\twarning("W098", v.token, v.value);\n
\t\t\t\t\t\tif (v.undef)\n
\t\t\t\t\t\t\tisundef(v.funct, "W117", v.token, v.value);\n
\t\t\t\t\t});\n
\t\t\t\t\t_carrays.splice(_carrays[_carrays.length - 1], 1);\n
\t\t\t\t\t_current = _carrays[_carrays.length - 1];\n
\t\t\t\t},\n
\t\t\t\tsetState: function (s) {\n
\t\t\t\t\tif (_.contains(["use", "define", "filter"], s))\n
\t\t\t\t\t\t_current.mode = s;\n
\t\t\t\t},\n
\t\t\t\tcheck: function (v) {\n
\t\t\t\t\tif (_current && _current.mode === "use") {\n
\t\t\t\t\t\t_current.variables.push({funct: funct,\n
\t\t\t\t\t\t\t\t\t\t\t\t\ttoken: state.tokens.curr,\n
\t\t\t\t\t\t\t\t\t\t\t\t\tvalue: v,\n
\t\t\t\t\t\t\t\t\t\t\t\t\tundef: true,\n
\t\t\t\t\t\t\t\t\t\t\t\t\tunused: false});\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t} else if (_current && _current.mode === "define") {\n
\t\t\t\t\t\tif (!declare(v)) {\n
\t\t\t\t\t\t\t_current.variables.push({funct: funct,\n
\t\t\t\t\t\t\t\t\t\t\t\t\t\ttoken: state.tokens.curr,\n
\t\t\t\t\t\t\t\t\t\t\t\t\t\tvalue: v,\n
\t\t\t\t\t\t\t\t\t\t\t\t\t\tundef: false,\n
\t\t\t\t\t\t\t\t\t\t\t\t\t\tunused: true});\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t} else if (_current && _current.mode === "filter") {\n
\t\t\t\t\t\tif (use(v)) {\n
\t\t\t\t\t\t\tisundef(funct, "W117", state.tokens.curr, v);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t};\n
\t};\n
\n
\tfunction jsonValue() {\n
\n
\t\tfunction jsonObject() {\n
\t\t\tvar o = {}, t = state.tokens.next;\n
\t\t\tadvance("{");\n
\t\t\tif (state.tokens.next.id !== "}") {\n
\t\t\t\tfor (;;) {\n
\t\t\t\t\tif (state.tokens.next.id === "(end)") {\n
\t\t\t\t\t\terror("E026", state.tokens.next, t.line);\n
\t\t\t\t\t} else if (state.tokens.next.id === "}") {\n
\t\t\t\t\t\twarning("W094", state.tokens.curr);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t} else if (state.tokens.next.id === ",") {\n
\t\t\t\t\t\terror("E028", state.tokens.next);\n
\t\t\t\t\t} else if (state.tokens.next.id !== "(string)") {\n
\t\t\t\t\t\twarning("W095", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t\t}\n
\t\t\t\t\tif (o[state.tokens.next.value] === true) {\n
\t\t\t\t\t\twarning("W075", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t\t} else if ((state.tokens.next.value === "__proto__" &&\n
\t\t\t\t\t\t!state.option.proto) || (state.tokens.next.value === "__iterator__" &&\n
\t\t\t\t\t\t!state.option.iterator)) {\n
\t\t\t\t\t\twarning("W096", state.tokens.next, state.tokens.next.value);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\to[state.tokens.next.value] = true;\n
\t\t\t\t\t}\n
\t\t\t\t\tadvance();\n
\t\t\t\t\tadvance(":");\n
\t\t\t\t\tjsonValue();\n
\t\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tadvance(",");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tadvance("}");\n
\t\t}\n
\n
\t\tfunction jsonArray() {\n
\t\t\tvar t = state.tokens.next;\n
\t\t\tadvance("[");\n
\t\t\tif (state.tokens.next.id !== "]") {\n
\t\t\t\tfor (;;) {\n
\t\t\t\t\tif (state.tokens.next.id === "(end)") {\n
\t\t\t\t\t\terror("E027", state.tokens.next, t.line);\n
\t\t\t\t\t} else if (state.tokens.next.id === "]") {\n
\t\t\t\t\t\twarning("W094", state.tokens.curr);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t} else if (state.tokens.next.id === ",") {\n
\t\t\t\t\t\terror("E028", state.tokens.next);\n
\t\t\t\t\t}\n
\t\t\t\t\tjsonValue();\n
\t\t\t\t\tif (state.tokens.next.id !== ",") {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tadvance(",");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tadvance("]");\n
\t\t}\n
\n
\t\tswitch (state.tokens.next.id) {\n
\t\tcase "{":\n
\t\t\tjsonObject();\n
\t\t\tbreak;\n
\t\tcase "[":\n
\t\t\tjsonArray();\n
\t\t\tbreak;\n
\t\tcase "true":\n
\t\tcase "false":\n
\t\tcase "null":\n
\t\tcase "(number)":\n
\t\tcase "(string)":\n
\t\t\tadvance();\n
\t\t\tbreak;\n
\t\tcase "-":\n
\t\t\tadvance("-");\n
\t\t\tif (state.tokens.curr.character !== state.tokens.next.from) {\n
\t\t\t\twarning("W011", state.tokens.curr);\n
\t\t\t}\n
\t\t\tadjacent(state.tokens.curr, state.tokens.next);\n
\t\t\tadvance("(number)");\n
\t\t\tbreak;\n
\t\tdefault:\n
\t\t\terror("E003", state.tokens.next);\n
\t\t}\n
\t}\n
\n
\tvar blockScope = function () {\n
\t\tvar _current = {};\n
\t\tvar _variables = [_current];\n
\n
\t\tfunction _checkBlockLabels() {\n
\t\t\tfor (var t in _current) {\n
\t\t\t\tif (_current[t]["(type)"] === "unused") {\n
\t\t\t\t\tif (state.option.unused) {\n
\t\t\t\t\t\tvar tkn = _current[t]["(token)"];\n
\t\t\t\t\t\tvar line = tkn.line;\n
\t\t\t\t\t\tvar chr  = tkn.character;\n
\t\t\t\t\t\twarningAt("W098", line, chr, t);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn {\n
\t\t\tstack: function () {\n
\t\t\t\t_current = {};\n
\t\t\t\t_variables.push(_current);\n
\t\t\t},\n
\n
\t\t\tunstack: function () {\n
\t\t\t\t_checkBlockLabels();\n
\t\t\t\t_variables.splice(_variables.length - 1, 1);\n
\t\t\t\t_current = _.last(_variables);\n
\t\t\t},\n
\n
\t\t\tgetlabel: function (l) {\n
\t\t\t\tfor (var i = _variables.length - 1 ; i >= 0; --i) {\n
\t\t\t\t\tif (_.has(_variables[i], l)) {\n
\t\t\t\t\t\treturn _variables[i];\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\tcurrent: {\n
\t\t\t\thas: function (t) {\n
\t\t\t\t\treturn _.has(_current, t);\n
\t\t\t\t},\n
\t\t\t\tadd: function (t, type, tok) {\n
\t\t\t\t\t_current[t] = { "(type)" : type,\n
\t\t\t\t\t\t\t\t\t"(token)": tok };\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\t};\n
\tvar itself = function (s, o, g) {\n
\t\tvar i, k, x;\n
\t\tvar optionKeys;\n
\t\tvar newOptionObj = {};\n
\t\tvar newIgnoredObj = {};\n
\n
\t\tstate.reset();\n
\n
\t\tif (o && o.scope) {\n
\t\t\tJSHINT.scope = o.scope;\n
\t\t} else {\n
\t\t\tJSHINT.errors = [];\n
\t\t\tJSHINT.undefs = [];\n
\t\t\tJSHINT.internals = [];\n
\t\t\tJSHINT.blacklist = {};\n
\t\t\tJSHINT.scope = "(main)";\n
\t\t}\n
\n
\t\tpredefined = Object.create(null);\n
\t\tcombine(predefined, vars.ecmaIdentifiers);\n
\t\tcombine(predefined, vars.reservedVars);\n
\n
\t\tcombine(predefined, g || {});\n
\n
\t\tdeclared = Object.create(null);\n
\t\texported = Object.create(null);\n
\n
\t\tfunction each(obj, cb) {\n
\t\t\tif (!obj)\n
\t\t\t\treturn;\n
\n
\t\t\tif (!Array.isArray(obj) && typeof obj === "object")\n
\t\t\t\tobj = Object.keys(obj);\n
\n
\t\t\tobj.forEach(cb);\n
\t\t}\n
\n
\t\tif (o) {\n
\t\t\teach(o.predef || null, function (item) {\n
\t\t\t\tvar slice, prop;\n
\n
\t\t\t\tif (item[0] === "-") {\n
\t\t\t\t\tslice = item.slice(1);\n
\t\t\t\t\tJSHINT.blacklist[slice] = slice;\n
\t\t\t\t} else {\n
\t\t\t\t\tprop = Object.getOwnPropertyDescriptor(o.predef, item);\n
\t\t\t\t\tpredefined[item] = prop ? prop.value : false;\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\teach(o.exported || null, function (item) {\n
\t\t\t\texported[item] = true;\n
\t\t\t});\n
\n
\t\t\tdelete o.predef;\n
\t\t\tdelete o.exported;\n
\n
\t\t\toptionKeys = Object.keys(o);\n
\t\t\tfor (x = 0; x < optionKeys.length; x++) {\n
\t\t\t\tif (/^-W\\d{3}$/g.test(optionKeys[x])) {\n
\t\t\t\t\tnewIgnoredObj[optionKeys[x].slice(1)] = true;\n
\t\t\t\t} else {\n
\t\t\t\t\tnewOptionObj[optionKeys[x]] = o[optionKeys[x]];\n
\n
\t\t\t\t\tif (optionKeys[x] === "newcap" && o[optionKeys[x]] === false)\n
\t\t\t\t\t\tnewOptionObj["(explicitNewcap)"] = true;\n
\n
\t\t\t\t\tif (optionKeys[x] === "indent")\n
\t\t\t\t\t\tnewOptionObj["(explicitIndent)"] = o[optionKeys[x]] === false ? false : true;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tstate.option = newOptionObj;\n
\t\tstate.ignored = newIgnoredObj;\n
\n
\t\tstate.option.indent = state.option.indent || 4;\n
\t\tstate.option.maxerr = state.option.maxerr || 50;\n
\n
\t\tindent = 1;\n
\t\tglobal = Object.create(predefined);\n
\t\tscope = global;\n
\t\tfunct = {\n
\t\t\t"(global)":   true,\n
\t\t\t"(name)":\t  "(global)",\n
\t\t\t"(scope)":\t  scope,\n
\t\t\t"(breakage)": 0,\n
\t\t\t"(loopage)":  0,\n
\t\t\t"(tokens)":   {},\n
\t\t\t"(metrics)":   createMetrics(state.tokens.next),\n
\t\t\t"(blockscope)": blockScope(),\n
\t\t\t"(comparray)": arrayComprehension()\n
\t\t};\n
\t\tfunctions = [funct];\n
\t\turls = [];\n
\t\tstack = null;\n
\t\tmember = {};\n
\t\tmembersOnly = null;\n
\t\timplied = {};\n
\t\tinblock = false;\n
\t\tlookahead = [];\n
\t\twarnings = 0;\n
\t\tunuseds = [];\n
\n
\t\tif (!isString(s) && !Array.isArray(s)) {\n
\t\t\terrorAt("E004", 0);\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tapi = {\n
\t\t\tget isJSON() {\n
\t\t\t\treturn state.jsonMode;\n
\t\t\t},\n
\n
\t\t\tgetOption: function (name) {\n
\t\t\t\treturn state.option[name] || null;\n
\t\t\t},\n
\n
\t\t\tgetCache: function (name) {\n
\t\t\t\treturn state.cache[name];\n
\t\t\t},\n
\n
\t\t\tsetCache: function (name, value) {\n
\t\t\t\tstate.cache[name] = value;\n
\t\t\t},\n
\n
\t\t\twarn: function (code, data) {\n
\t\t\t\twarningAt.apply(null, [ code, data.line, data.char ].concat(data.data));\n
\t\t\t},\n
\n
\t\t\ton: function (names, listener) {\n
\t\t\t\tnames.split(" ").forEach(function (name) {\n
\t\t\t\t\temitter.on(name, listener);\n
\t\t\t\t}.bind(this));\n
\t\t\t}\n
\t\t};\n
\n
\t\temitter.removeAllListeners();\n
\t\t(extraModules || []).forEach(function (func) {\n
\t\t\tfunc(api);\n
\t\t});\n
\n
\t\tstate.tokens.prev = state.tokens.curr = state.tokens.next = state.syntax["(begin)"];\n
\n
\t\tlex = new Lexer(s);\n
\n
\t\tlex.on("warning", function (ev) {\n
\t\t\twarningAt.apply(null, [ ev.code, ev.line, ev.character].concat(ev.data));\n
\t\t});\n
\n
\t\tlex.on("error", function (ev) {\n
\t\t\terrorAt.apply(null, [ ev.code, ev.line, ev.character ].concat(ev.data));\n
\t\t});\n
\n
\t\tlex.on("fatal", function (ev) {\n
\t\t\tquit("E041", ev.line, ev.from);\n
\t\t});\n
\n
\t\tlex.on("Identifier", function (ev) {\n
\t\t\temitter.emit("Identifier", ev);\n
\t\t});\n
\n
\t\tlex.on("String", function (ev) {\n
\t\t\temitter.emit("String", ev);\n
\t\t});\n
\n
\t\tlex.on("Number", function (ev) {\n
\t\t\temitter.emit("Number", ev);\n
\t\t});\n
\n
\t\tlex.start();\n
\t\tfor (var name in o) {\n
\t\t\tif (_.has(o, name)) {\n
\t\t\t\tcheckOption(name, state.tokens.curr);\n
\t\t\t}\n
\t\t}\n
\n
\t\tassume();\n
\t\tcombine(predefined, g || {});\n
\t\tcomma.first = true;\n
\n
\t\ttry {\n
\t\t\tadvance();\n
\t\t\tswitch (state.tokens.next.id) {\n
\t\t\tcase "{":\n
\t\t\tcase "[":\n
\t\t\t\tdestructuringAssignOrJsonValue();\n
\t\t\t\tbreak;\n
\t\t\tdefault:\n
\t\t\t\tdirectives();\n
\n
\t\t\t\tif (state.directive["use strict"]) {\n
\t\t\t\t\tif (!state.option.globalstrict && !state.option.node) {\n
\t\t\t\t\t\twarning("W097", state.tokens.prev);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tstatements();\n
\t\t\t}\n
\t\t\tadvance((state.tokens.next && state.tokens.next.value !== ".")\t? "(end)" : undefined);\n
\t\t\tfunct["(blockscope)"].unstack();\n
\n
\t\t\tvar markDefined = function (name, context) {\n
\t\t\t\tdo {\n
\t\t\t\t\tif (typeof context[name] === "string") {\n
\n
\t\t\t\t\t\tif (context[name] === "unused")\n
\t\t\t\t\t\t\tcontext[name] = "var";\n
\t\t\t\t\t\telse if (context[name] === "unction")\n
\t\t\t\t\t\t\tcontext[name] = "closure";\n
\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tcontext = context["(context)"];\n
\t\t\t\t} while (context);\n
\n
\t\t\t\treturn false;\n
\t\t\t};\n
\n
\t\t\tvar clearImplied = function (name, line) {\n
\t\t\t\tif (!implied[name])\n
\t\t\t\t\treturn;\n
\n
\t\t\t\tvar newImplied = [];\n
\t\t\t\tfor (var i = 0; i < implied[name].length; i += 1) {\n
\t\t\t\t\tif (implied[name][i] !== line)\n
\t\t\t\t\t\tnewImplied.push(implied[name][i]);\n
\t\t\t\t}\n
\n
\t\t\t\tif (newImplied.length === 0)\n
\t\t\t\t\tdelete implied[name];\n
\t\t\t\telse\n
\t\t\t\t\timplied[name] = newImplied;\n
\t\t\t};\n
\n
\t\t\tvar warnUnused = function (name, tkn, type, unused_opt) {\n
\t\t\t\tvar line = tkn.line;\n
\t\t\t\tvar chr  = tkn.character;\n
\n
\t\t\t\tif (unused_opt === undefined) {\n
\t\t\t\t\tunused_opt = state.option.unused;\n
\t\t\t\t}\n
\n
\t\t\t\tif (unused_opt === true) {\n
\t\t\t\t\tunused_opt = "last-param";\n
\t\t\t\t}\n
\n
\t\t\t\tvar warnable_types = {\n
\t\t\t\t\t"vars": ["var"],\n
\t\t\t\t\t"last-param": ["var", "param"],\n
\t\t\t\t\t"strict": ["var", "param", "last-param"]\n
\t\t\t\t};\n
\n
\t\t\t\tif (unused_opt) {\n
\t\t\t\t\tif (warnable_types[unused_opt] && warnable_types[unused_opt].indexOf(type) !== -1) {\n
\t\t\t\t\t\twarningAt("W098", line, chr, name);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tunuseds.push({\n
\t\t\t\t\tname: name,\n
\t\t\t\t\tline: line,\n
\t\t\t\t\tcharacter: chr\n
\t\t\t\t});\n
\t\t\t};\n
\n
\t\t\tvar checkUnused = function (func, key) {\n
\t\t\t\tvar type = func[key];\n
\t\t\t\tvar tkn = func["(tokens)"][key];\n
\n
\t\t\t\tif (key.charAt(0) === "(")\n
\t\t\t\t\treturn;\n
\n
\t\t\t\tif (type !== "unused" && type !== "unction")\n
\t\t\t\t\treturn;\n
\t\t\t\tif (func["(params)"] && func["(params)"].indexOf(key) !== -1)\n
\t\t\t\t\treturn;\n
\t\t\t\tif (func["(global)"] && _.has(exported, key)) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\twarnUnused(key, tkn, "var");\n
\t\t\t};\n
\t\t\tfor (i = 0; i < JSHINT.undefs.length; i += 1) {\n
\t\t\t\tk = JSHINT.undefs[i].slice(0);\n
\n
\t\t\t\tif (markDefined(k[2].value, k[0])) {\n
\t\t\t\t\tclearImplied(k[2].value, k[2].line);\n
\t\t\t\t} else if (state.option.undef) {\n
\t\t\t\t\twarning.apply(warning, k.slice(1));\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tfunctions.forEach(function (func) {\n
\t\t\t\tif (func["(unusedOption)"] === false) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tfor (var key in func) {\n
\t\t\t\t\tif (_.has(func, key)) {\n
\t\t\t\t\t\tcheckUnused(func, key);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif (!func["(params)"])\n
\t\t\t\t\treturn;\n
\n
\t\t\t\tvar params = func["(params)"].slice();\n
\t\t\t\tvar param  = params.pop();\n
\t\t\t\tvar type, unused_opt;\n
\n
\t\t\t\twhile (param) {\n
\t\t\t\t\ttype = func[param];\n
\t\t\t\t\tunused_opt = func["(unusedOption)"] || state.option.unused;\n
\t\t\t\t\tunused_opt = unused_opt === true ? "last-param" : unused_opt;\n
\n
\t\t\t\t\tif (param === "undefined")\n
\t\t\t\t\t\treturn;\n
\n
\t\t\t\t\tif (type === "unused" || type === "unction") {\n
\t\t\t\t\t\twarnUnused(param, func["(tokens)"][param], "param", func["(unusedOption)"]);\n
\t\t\t\t\t} else if (unused_opt === "last-param") {\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tparam = params.pop();\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\tfor (var key in declared) {\n
\t\t\t\tif (_.has(declared, key) && !_.has(global, key)) {\n
\t\t\t\t\twarnUnused(key, declared[key], "var");\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t} catch (err) {\n
\t\t\tif (err && err.name === "JSHintError") {\n
\t\t\t\tvar nt = state.tokens.next || {};\n
\t\t\t\tJSHINT.errors.push({\n
\t\t\t\t\tscope     : "(main)",\n
\t\t\t\t\traw       : err.raw,\n
\t\t\t\t\tcode      : err.code,\n
\t\t\t\t\treason    : err.message,\n
\t\t\t\t\tline      : err.line || nt.line,\n
\t\t\t\t\tcharacter : err.character || nt.from\n
\t\t\t\t}, null);\n
\t\t\t} else {\n
\t\t\t\tthrow err;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (JSHINT.scope === "(main)") {\n
\t\t\to = o || {};\n
\n
\t\t\tfor (i = 0; i < JSHINT.internals.length; i += 1) {\n
\t\t\t\tk = JSHINT.internals[i];\n
\t\t\t\to.scope = k.elem;\n
\t\t\t\titself(k.value, o, g);\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn JSHINT.errors.length === 0;\n
\t};\n
\titself.addModule = function (func) {\n
\t\textraModules.push(func);\n
\t};\n
\n
\titself.addModule(style.register);\n
\titself.data = function () {\n
\t\tvar data = {\n
\t\t\tfunctions: [],\n
\t\t\toptions: state.option\n
\t\t};\n
\t\tvar implieds = [];\n
\t\tvar members = [];\n
\t\tvar fu, f, i, j, n, globals;\n
\n
\t\tif (itself.errors.length) {\n
\t\t\tdata.errors = itself.errors;\n
\t\t}\n
\n
\t\tif (state.jsonMode) {\n
\t\t\tdata.json = true;\n
\t\t}\n
\n
\t\tfor (n in implied) {\n
\t\t\tif (_.has(implied, n)) {\n
\t\t\t\timplieds.push({\n
\t\t\t\t\tname: n,\n
\t\t\t\t\tline: implied[n]\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (implieds.length > 0) {\n
\t\t\tdata.implieds = implieds;\n
\t\t}\n
\n
\t\tif (urls.length > 0) {\n
\t\t\tdata.urls = urls;\n
\t\t}\n
\n
\t\tglobals = Object.keys(scope);\n
\t\tif (globals.length > 0) {\n
\t\t\tdata.globals = globals;\n
\t\t}\n
\n
\t\tfor (i = 1; i < functions.length; i += 1) {\n
\t\t\tf = functions[i];\n
\t\t\tfu = {};\n
\n
\t\t\tfor (j = 0; j < functionicity.length; j += 1) {\n
\t\t\t\tfu[functionicity[j]] = [];\n
\t\t\t}\n
\n
\t\t\tfor (j = 0; j < functionicity.length; j += 1) {\n
\t\t\t\tif (fu[functionicity[j]].length === 0) {\n
\t\t\t\t\tdelete fu[functionicity[j]];\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tfu.name = f["(name)"];\n
\t\t\tfu.param = f["(params)"];\n
\t\t\tfu.line = f["(line)"];\n
\t\t\tfu.character = f["(character)"];\n
\t\t\tfu.last = f["(last)"];\n
\t\t\tfu.lastcharacter = f["(lastcharacter)"];\n
\t\t\tdata.functions.push(fu);\n
\t\t}\n
\n
\t\tif (unuseds.length > 0) {\n
\t\t\tdata.unused = unuseds;\n
\t\t}\n
\n
\t\tmembers = [];\n
\t\tfor (n in member) {\n
\t\t\tif (typeof member[n] === "number") {\n
\t\t\t\tdata.member = member;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn data;\n
\t};\n
\n
\titself.jshint = itself;\n
\n
\treturn itself;\n
}());\n
if (typeof exports === "object" && exports) {\n
\texports.JSHINT = JSHINT;\n
}\n
\n
},\n
{"../shared/messages.js":2,"../shared/vars.js":3,"./lex.js":5,"./reg.js":6,"./state.js":7,"./style.js":8,"console-browserify":9,"events":10,"underscore":1}],\n
5:[function(req,module,exports){\n
\n
\n
\n
var _      = req("underscore");\n
var events = req("events");\n
var reg    = req("./reg.js");\n
var state  = req("./state.js").state;\n
\n
var Token = {\n
\tIdentifier: 1,\n
\tPunctuator: 2,\n
\tNumericLiteral: 3,\n
\tStringLiteral: 4,\n
\tComment: 5,\n
\tKeyword: 6,\n
\tNullLiteral: 7,\n
\tBooleanLiteral: 8,\n
\tRegExp: 9\n
};\n
\n
var unicodeLetterTable = [\n
\t170, 170, 181, 181, 186, 186, 192, 214,\n
\t216, 246, 248, 705, 710, 721, 736, 740, 748, 748, 750, 750,\n
\t880, 884, 886, 887, 890, 893, 902, 902, 904, 906, 908, 908,\n
\t910, 929, 931, 1013, 1015, 1153, 1162, 1319, 1329, 1366,\n
\t1369, 1369, 1377, 1415, 1488, 1514, 1520, 1522, 1568, 1610,\n
\t1646, 1647, 1649, 1747, 1749, 1749, 1765, 1766, 1774, 1775,\n
\t1786, 1788, 1791, 1791, 1808, 1808, 1810, 1839, 1869, 1957,\n
\t1969, 1969, 1994, 2026, 2036, 2037, 2042, 2042, 2048, 2069,\n
\t2074, 2074, 2084, 2084, 2088, 2088, 2112, 2136, 2308, 2361,\n
\t2365, 2365, 2384, 2384, 2392, 2401, 2417, 2423, 2425, 2431,\n
\t2437, 2444, 2447, 2448, 2451, 2472, 2474, 2480, 2482, 2482,\n
\t2486, 2489, 2493, 2493, 2510, 2510, 2524, 2525, 2527, 2529,\n
\t2544, 2545, 2565, 2570, 2575, 2576, 2579, 2600, 2602, 2608,\n
\t2610, 2611, 2613, 2614, 2616, 2617, 2649, 2652, 2654, 2654,\n
\t2674, 2676, 2693, 2701, 2703, 2705, 2707, 2728, 2730, 2736,\n
\t2738, 2739, 2741, 2745, 2749, 2749, 2768, 2768, 2784, 2785,\n
\t2821, 2828, 2831, 2832, 2835, 2856, 2858, 2864, 2866, 2867,\n
\t2869, 2873, 2877, 2877, 2908, 2909, 2911, 2913, 2929, 2929,\n
\t2947, 2947, 2949, 2954, 2958, 2960, 2962, 2965, 2969, 2970,\n
\t2972, 2972, 2974, 2975, 2979, 2980, 2984, 2986, 2990, 3001,\n
\t3024, 3024, 3077, 3084, 3086, 3088, 3090, 3112, 3114, 3123,\n
\t3125, 3129, 3133, 3133, 3160, 3161, 3168, 3169, 3205, 3212,\n
\t3214, 3216, 3218, 3240, 3242, 3251, 3253, 3257, 3261, 3261,\n
\t3294, 3294, 3296, 3297, 3313, 3314, 3333, 3340, 3342, 3344,\n
\t3346, 3386, 3389, 3389, 3406, 3406, 3424, 3425, 3450, 3455,\n
\t3461, 3478, 3482, 3505, 3507, 3515, 3517, 3517, 3520, 3526,\n
\t3585, 3632, 3634, 3635, 3648, 3654, 3713, 3714, 3716, 3716,\n
\t3719, 3720, 3722, 3722, 3725, 3725, 3732, 3735, 3737, 3743,\n
\t3745, 3747, 3749, 3749, 3751, 3751, 3754, 3755, 3757, 3760,\n
\t3762, 3763, 3773, 3773, 3776, 3780, 3782, 3782, 3804, 3805,\n
\t3840, 3840, 3904, 3911, 3913, 3948, 3976, 3980, 4096, 4138,\n
\t4159, 4159, 4176, 4181, 4186, 4189, 4193, 4193, 4197, 4198,\n
\t4206, 4208, 4213, 4225, 4238, 4238, 4256, 4293, 4304, 4346,\n
\t4348, 4348, 4352, 4680, 4682, 4685, 4688, 4694, 4696, 4696,\n
\t4698, 4701, 4704, 4744, 4746, 4749, 4752, 4784, 4786, 4789,\n
\t4792, 4798, 4800, 4800, 4802, 4805, 4808, 4822, 4824, 4880,\n
\t4882, 4885, 4888, 4954, 4992, 5007, 5024, 5108, 5121, 5740,\n
\t5743, 5759, 5761, 5786, 5792, 5866, 5870, 5872, 5888, 5900,\n
\t5902, 5905, 5920, 5937, 5952, 5969, 5984, 5996, 5998, 6000,\n
\t6016, 6067, 6103, 6103, 6108, 6108, 6176, 6263, 6272, 6312,\n
\t6314, 6314, 6320, 6389, 6400, 6428, 6480, 6509, 6512, 6516,\n
\t6528, 6571, 6593, 6599, 6656, 6678, 6688, 6740, 6823, 6823,\n
\t6917, 6963, 6981, 6987, 7043, 7072, 7086, 7087, 7104, 7141,\n
\t7168, 7203, 7245, 7247, 7258, 7293, 7401, 7404, 7406, 7409,\n
\t7424, 7615, 7680, 7957, 7960, 7965, 7968, 8005, 8008, 8013,\n
\t8016, 8023, 8025, 8025, 8027, 8027, 8029, 8029, 8031, 8061,\n
\t8064, 8116, 8118, 8124, 8126, 8126, 8130, 8132, 8134, 8140,\n
\t8144, 8147, 8150, 8155, 8160, 8172, 8178, 8180, 8182, 8188,\n
\t8305, 8305, 8319, 8319, 8336, 8348, 8450, 8450, 8455, 8455,\n
\t8458, 8467, 8469, 8469, 8473, 8477, 8484, 8484, 8486, 8486,\n
\t8488, 8488, 8490, 8493, 8495, 8505, 8508, 8511, 8517, 8521,\n
\t8526, 8526, 8544, 8584, 11264, 11310, 11312, 11358,\n
\t11360, 11492, 11499, 11502, 11520, 11557, 11568, 11621,\n
\t11631, 11631, 11648, 11670, 11680, 11686, 11688, 11694,\n
\t11696, 11702, 11704, 11710, 11712, 11718, 11720, 11726,\n
\t11728, 11734, 11736, 11742, 11823, 11823, 12293, 12295,\n
\t12321, 12329, 12337, 12341, 12344, 12348, 12353, 12438,\n
\t12445, 12447, 12449, 12538, 12540, 12543, 12549, 12589,\n
\t12593, 12686, 12704, 12730, 12784, 12799, 13312, 13312,\n
\t19893, 19893, 19968, 19968, 40907, 40907, 40960, 42124,\n
\t42192, 42237, 42240, 42508, 42512, 42527, 42538, 42539,\n
\t42560, 42606, 42623, 42647, 42656, 42735, 42775, 42783,\n
\t42786, 42888, 42891, 42894, 42896, 42897, 42912, 42921,\n
\t43002, 43009, 43011, 43013, 43015, 43018, 43020, 43042,\n
\t43072, 43123, 43138, 43187, 43250, 43255, 43259, 43259,\n
\t43274, 43301, 43312, 43334, 43360, 43388, 43396, 43442,\n
\t43471, 43471, 43520, 43560, 43584, 43586, 43588, 43595,\n
\t43616, 43638, 43642, 43642, 43648, 43695, 43697, 43697,\n
\t43701, 43702, 43705, 43709, 43712, 43712, 43714, 43714,\n
\t43739, 43741, 43777, 43782, 43785, 43790, 43793, 43798,\n
\t43808, 43814, 43816, 43822, 43968, 44002, 44032, 44032,\n
\t55203, 55203, 55216, 55238, 55243, 55291, 63744, 64045,\n
\t64048, 64109, 64112, 64217, 64256, 64262, 64275, 64279,\n
\t64285, 64285, 64287, 64296, 64298, 64310, 64312, 64316,\n
\t64318, 64318, 64320, 64321, 64323, 64324, 64326, 64433,\n
\t64467, 64829, 64848, 64911, 64914, 64967, 65008, 65019,\n
\t65136, 65140, 65142, 65276, 65313, 65338, 65345, 65370,\n
\t65382, 65470, 65474, 65479, 65482, 65487, 65490, 65495,\n
\t65498, 65500, 65536, 65547, 65549, 65574, 65576, 65594,\n
\t65596, 65597, 65599, 65613, 65616, 65629, 65664, 65786,\n
\t65856, 65908, 66176, 66204, 66208, 66256, 66304, 66334,\n
\t66352, 66378, 66432, 66461, 66464, 66499, 66504, 66511,\n
\t66513, 66517, 66560, 66717, 67584, 67589, 67592, 67592,\n
\t67594, 67637, 67639, 67640, 67644, 67644, 67647, 67669,\n
\t67840, 67861, 67872, 67897, 68096, 68096, 68112, 68115,\n
\t68117, 68119, 68121, 68147, 68192, 68220, 68352, 68405,\n
\t68416, 68437, 68448, 68466, 68608, 68680, 69635, 69687,\n
\t69763, 69807, 73728, 74606, 74752, 74850, 77824, 78894,\n
\t92160, 92728, 110592, 110593, 119808, 119892, 119894, 119964,\n
\t119966, 119967, 119970, 119970, 119973, 119974, 119977, 119980,\n
\t119982, 119993, 119995, 119995, 119997, 120003, 120005, 120069,\n
\t120071, 120074, 120077, 120084, 120086, 120092, 120094, 120121,\n
\t120123, 120126, 120128, 120132, 120134, 120134, 120138, 120144,\n
\t120146, 120485, 120488, 120512, 120514, 120538, 120540, 120570,\n
\t120572, 120596, 120598, 120628, 120630, 120654, 120656, 120686,\n
\t120688, 120712, 120714, 120744, 120746, 120770, 120772, 120779,\n
\t131072, 131072, 173782, 173782, 173824, 173824, 177972, 177972,\n
\t177984, 177984, 178205, 178205, 194560, 195101\n
];\n
\n
var identifierStartTable = [];\n
\n
for (var i = 0; i < 128; i++) {\n
\tidentifierStartTable[i] =\n
\t\ti === 36 ||           // $\n
\t\ti >= 65 && i <= 90 || // A-Z\n
\t\ti === 95 ||           // _\n
\t\ti >= 97 && i <= 122;  // a-z\n
}\n
\n
var identifierPartTable = [];\n
\n
for (var i = 0; i < 128; i++) {\n
\tidentifierPartTable[i] =\n
\t\tidentifierStartTable[i] || // $, _, A-Z, a-z\n
\t\ti >= 48 && i <= 57;        // 0-9\n
}\n
\n
function asyncTrigger() {\n
\tvar _checks = [];\n
\n
\treturn {\n
\t\tpush: function (fn) {\n
\t\t\t_checks.push(fn);\n
\t\t},\n
\n
\t\tcheck: function () {\n
\t\t\tfor (var check = 0; check < _checks.length; ++check) {\n
\t\t\t\t_checks[check]();\n
\t\t\t}\n
\n
\t\t\t_checks.splice(0, _checks.length);\n
\t\t}\n
\t};\n
}\n
function Lexer(source) {\n
\tvar lines = source;\n
\n
\tif (typeof lines === "string") {\n
\t\tlines = lines\n
\t\t\t.replace(/\\r\\n/g, "\\n")\n
\t\t\t.replace(/\\r/g, "\\n")\n
\t\t\t.split("\\n");\n
\t}\n
\n
\tif (lines[0] && lines[0].substr(0, 2) === "#!") {\n
\t\tlines[0] = "";\n
\t}\n
\n
\tthis.emitter = new events.EventEmitter();\n
\tthis.source = source;\n
\tthis.setLines(lines);\n
\tthis.prereg = true;\n
\n
\tthis.line = 0;\n
\tthis.char = 1;\n
\tthis.from = 1;\n
\tthis.input = "";\n
\n
\tfor (var i = 0; i < state.option.indent; i += 1) {\n
\t\tstate.tab += " ";\n
\t}\n
}\n
\n
Lexer.prototype = {\n
\t_lines: [],\n
\n
\tgetLines: function () {\n
\t\tthis._lines = state.lines;\n
\t\treturn this._lines;\n
\t},\n
\n
\tsetLines: function (val) {\n
\t\tthis._lines = val;\n
\t\tstate.lines = this._lines;\n
\t},\n
\tpeek: function (i) {\n
\t\treturn this.input.charAt(i || 0);\n
\t},\n
\tskip: function (i) {\n
\t\ti = i || 1;\n
\t\tthis.char += i;\n
\t\tthis.input = this.input.slice(i);\n
\t},\n
\ton: function (names, listener) {\n
\t\tnames.split(" ").forEach(function (name) {\n
\t\t\tthis.emitter.on(name, listener);\n
\t\t}.bind(this));\n
\t},\n
\ttrigger: function () {\n
\t\tthis.emitter.emit.apply(this.emitter, Array.prototype.slice.call(arguments));\n
\t},\n
\ttriggerAsync: function (type, args, checks, fn) {\n
\t\tchecks.push(function () {\n
\t\t\tif (fn()) {\n
\t\t\t\tthis.trigger(type, args);\n
\t\t\t}\n
\t\t}.bind(this));\n
\t},\n
\tscanPunctuator: function () {\n
\t\tvar ch1 = this.peek();\n
\t\tvar ch2, ch3, ch4;\n
\n
\t\tswitch (ch1) {\n
\t\tcase ".":\n
\t\t\tif ((/^[0-9]$/).test(this.peek(1))) {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t\tif (this.peek(1) === "." && this.peek(2) === ".") {\n
\t\t\t\treturn {\n
\t\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\t\tvalue: "..."\n
\t\t\t\t};\n
\t\t\t}\n
\t\tcase "(":\n
\t\tcase ")":\n
\t\tcase ";":\n
\t\tcase ",":\n
\t\tcase "{":\n
\t\tcase "}":\n
\t\tcase "[":\n
\t\tcase "]":\n
\t\tcase ":":\n
\t\tcase "~":\n
\t\tcase "?":\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ch1\n
\t\t\t};\n
\t\tcase "#":\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ch1\n
\t\t\t};\n
\t\tcase "":\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tch2 = this.peek(1);\n
\t\tch3 = this.peek(2);\n
\t\tch4 = this.peek(3);\n
\n
\t\tif (ch1 === ">" && ch2 === ">" && ch3 === ">" && ch4 === "=") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ">>>="\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === "=" && ch2 === "=" && ch3 === "=") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: "==="\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === "!" && ch2 === "=" && ch3 === "=") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: "!=="\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === ">" && ch2 === ">" && ch3 === ">") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ">>>"\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === "<" && ch2 === "<" && ch3 === "=") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: "<<="\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === ">" && ch2 === ">" && ch3 === "=") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ">>="\n
\t\t\t};\n
\t\t}\n
\t\tif (ch1 === "=" && ch2 === ">") {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ch1 + ch2\n
\t\t\t};\n
\t\t}\n
\t\tif (ch1 === ch2 && ("+-<>&|".indexOf(ch1) >= 0)) {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ch1 + ch2\n
\t\t\t};\n
\t\t}\n
\n
\t\tif ("<>=!+-*%&|^".indexOf(ch1) >= 0) {\n
\t\t\tif (ch2 === "=") {\n
\t\t\t\treturn {\n
\t\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\t\tvalue: ch1 + ch2\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: ch1\n
\t\t\t};\n
\t\t}\n
\n
\t\tif (ch1 === "/") {\n
\t\t\tif (ch2 === "=" && /\\/=(?!(\\S*\\/[gim]?))/.test(this.input)) {\n
\t\t\t\treturn {\n
\t\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\t\tvalue: "/="\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Punctuator,\n
\t\t\t\tvalue: "/"\n
\t\t\t};\n
\t\t}\n
\n
\t\treturn null;\n
\t},\n
\tscanComments: function () {\n
\t\tvar ch1 = this.peek();\n
\t\tvar ch2 = this.peek(1);\n
\t\tvar rest = this.input.substr(2);\n
\t\tvar startLine = this.line;\n
\t\tvar startChar = this.char;\n
\n
\t\tfunction commentToken(label, body, opt) {\n
\t\t\tvar special = ["jshint", "jslint", "members", "member", "globals", "global", "exported"];\n
\t\t\tvar isSpecial = false;\n
\t\t\tvar value = label + body;\n
\t\t\tvar commentType = "plain";\n
\t\t\topt = opt || {};\n
\n
\t\t\tif (opt.isMultiline) {\n
\t\t\t\tvalue += "*/";\n
\t\t\t}\n
\n
\t\t\tspecial.forEach(function (str) {\n
\t\t\t\tif (isSpecial) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tif (label === "//" && str !== "jshint") {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tif (body.substr(0, str.length) === str) {\n
\t\t\t\t\tisSpecial = true;\n
\t\t\t\t\tlabel = label + str;\n
\t\t\t\t\tbody = body.substr(str.length);\n
\t\t\t\t}\n
\n
\t\t\t\tif (!isSpecial && body.charAt(0) === " " && body.substr(1, str.length) === str) {\n
\t\t\t\t\tisSpecial = true;\n
\t\t\t\t\tlabel = label + " " + str;\n
\t\t\t\t\tbody = body.substr(str.length + 1);\n
\t\t\t\t}\n
\n
\t\t\t\tif (!isSpecial) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tswitch (str) {\n
\t\t\t\tcase "member":\n
\t\t\t\t\tcommentType = "members";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "global":\n
\t\t\t\t\tcommentType = "globals";\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tcommentType = str;\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Comment,\n
\t\t\t\tcommentType: commentType,\n
\t\t\t\tvalue: value,\n
\t\t\t\tbody: body,\n
\t\t\t\tisSpecial: isSpecial,\n
\t\t\t\tisMultiline: opt.isMultiline || false,\n
\t\t\t\tisMalformed: opt.isMalformed || false\n
\t\t\t};\n
\t\t}\n
\t\tif (ch1 === "*" && ch2 === "/") {\n
\t\t\tthis.trigger("error", {\n
\t\t\t\tcode: "E018",\n
\t\t\t\tline: startLine,\n
\t\t\t\tcharacter: startChar\n
\t\t\t});\n
\n
\t\t\tthis.skip(2);\n
\t\t\treturn null;\n
\t\t}\n
\t\tif (ch1 !== "/" || (ch2 !== "*" && ch2 !== "/")) {\n
\t\t\treturn null;\n
\t\t}\n
\t\tif (ch2 === "/") {\n
\t\t\tthis.skip(this.input.length); // Skip to the EOL.\n
\t\t\treturn commentToken("//", rest);\n
\t\t}\n
\n
\t\tvar body = "";\n
\t\tif (ch2 === "*") {\n
\t\t\tthis.skip(2);\n
\n
\t\t\twhile (this.peek() !== "*" || this.peek(1) !== "/") {\n
\t\t\t\tif (this.peek() === "") { // End of Line\n
\t\t\t\t\tbody += "\\n";\n
\t\t\t\t\tif (!this.nextLine()) {\n
\t\t\t\t\t\tthis.trigger("error", {\n
\t\t\t\t\t\t\tcode: "E017",\n
\t\t\t\t\t\t\tline: startLine,\n
\t\t\t\t\t\t\tcharacter: startChar\n
\t\t\t\t\t\t});\n
\n
\t\t\t\t\t\treturn commentToken("/*", body, {\n
\t\t\t\t\t\t\tisMultiline: true,\n
\t\t\t\t\t\t\tisMalformed: true\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tbody += this.peek();\n
\t\t\t\t\tthis.skip();\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tthis.skip(2);\n
\t\t\treturn commentToken("/*", body, { isMultiline: true });\n
\t\t}\n
\t},\n
\tscanKeyword: function () {\n
\t\tvar result = /^[a-zA-Z_$][a-zA-Z0-9_$]*/.exec(this.input);\n
\t\tvar keywords = [\n
\t\t\t"if", "in", "do", "var", "for", "new",\n
\t\t\t"try", "let", "this", "else", "case",\n
\t\t\t"void", "with", "enum", "while", "break",\n
\t\t\t"catch", "throw", "const", "yield", "class",\n
\t\t\t"super", "return", "typeof", "delete",\n
\t\t\t"switch", "export", "import", "default",\n
\t\t\t"finally", "extends", "function", "continue",\n
\t\t\t"debugger", "instanceof"\n
\t\t];\n
\n
\t\tif (result && keywords.indexOf(result[0]) >= 0) {\n
\t\t\treturn {\n
\t\t\t\ttype: Token.Keyword,\n
\t\t\t\tvalue: result[0]\n
\t\t\t};\n
\t\t}\n
\n
\t\treturn null;\n
\t},\n
\tscanIdentifier: function () {\n
\t\tvar id = "";\n
\t\tvar index = 0;\n
\t\tvar type, char;\n
\n
\t\tfunction isUnicodeLetter(code) {\n
\t\t\tfor (var i = 0; i < unicodeLetterTable.length;) {\n
\t\t\t\tif (code < unicodeLetterTable[i++]) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\n
\t\t\t\tif (code <= unicodeLetterTable[i++]) {\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tfunction isHexDigit(str) {\n
\t\t\treturn (/^[0-9a-fA-F]$/).test(str);\n
\t\t}\n
\n
\t\tvar readUnicodeEscapeSequence = function () {\n
\t\t\tindex += 1;\n
\n
\t\t\tif (this.peek(index) !== "u") {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\n
\t\t\tvar ch1 = this.peek(index + 1);\n
\t\t\tvar ch2 = this.peek(index + 2);\n
\t\t\tvar ch3 = this.peek(index + 3);\n
\t\t\tvar ch4 = this.peek(index + 4);\n
\t\t\tvar code;\n
\n
\t\t\tif (isHexDigit(ch1) && isHexDigit(ch2) && isHexDigit(ch3) && isHexDigit(ch4)) {\n
\t\t\t\tcode = parseInt(ch1 + ch2 + ch3 + ch4, 16);\n
\n
\t\t\t\tif (isUnicodeLetter(code)) {\n
\t\t\t\t\tindex += 5;\n
\t\t\t\t\treturn "\\\\u" + ch1 + ch2 + ch3 + ch4;\n
\t\t\t\t}\n
\n
\t\t\t\treturn null;\n
\t\t\t}\n
\n
\t\t\treturn null;\n
\t\t}.bind(this);\n
\n
\t\tvar getIdentifierStart = function () {\n
\t\t\tvar chr = this.peek(index);\n
\t\t\tvar code = chr.charCodeAt(0);\n
\n
\t\t\tif (code === 92) {\n
\t\t\t\treturn readUnicodeEscapeSequence();\n
\t\t\t}\n
\n
\t\t\tif (code < 128) {\n
\t\t\t\tif (identifierStartTable[code]) {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\treturn chr;\n
\t\t\t\t}\n
\n
\t\t\t\treturn null;\n
\t\t\t}\n
\n
\t\t\tif (isUnicodeLetter(code)) {\n
\t\t\t\tindex += 1;\n
\t\t\t\treturn chr;\n
\t\t\t}\n
\n
\t\t\treturn null;\n
\t\t}.bind(this);\n
\n
\t\tvar getIdentifierPart = function () {\n
\t\t\tvar chr = this.peek(index);\n
\t\t\tvar code = chr.charCodeAt(0);\n
\n
\t\t\tif (code === 92) {\n
\t\t\t\treturn readUnicodeEscapeSequence();\n
\t\t\t}\n
\n
\t\t\tif (code < 128) {\n
\t\t\t\tif (identifierPartTable[code]) {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\treturn chr;\n
\t\t\t\t}\n
\n
\t\t\t\treturn null;\n
\t\t\t}\n
\n
\t\t\tif (isUnicodeLetter(code)) {\n
\t\t\t\tindex += 1;\n
\t\t\t\treturn chr;\n
\t\t\t}\n
\n
\t\t\treturn null;\n
\t\t}.bind(this);\n
\n
\t\tchar = getIdentifierStart();\n
\t\tif (char === null) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tid = char;\n
\t\tfor (;;) {\n
\t\t\tchar = getIdentifierPart();\n
\n
\t\t\tif (char === null) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tid += char;\n
\t\t}\n
\n
\t\tswitch (id) {\n
\t\tcase "true":\n
\t\tcase "false":\n
\t\t\ttype = Token.BooleanLiteral;\n
\t\t\tbreak;\n
\t\tcase "null":\n
\t\t\ttype = Token.NullLiteral;\n
\t\t\tbreak;\n
\t\tdefault:\n
\t\t\ttype = Token.Identifier;\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttype: type,\n
\t\t\tvalue: id\n
\t\t};\n
\t},\n
\tscanNumericLiteral: function () {\n
\t\tvar index = 0;\n
\t\tvar value = "";\n
\t\tvar length = this.input.length;\n
\t\tvar char = this.peek(index);\n
\t\tvar bad;\n
\n
\t\tfunction isDecimalDigit(str) {\n
\t\t\treturn (/^[0-9]$/).test(str);\n
\t\t}\n
\n
\t\tfunction isOctalDigit(str) {\n
\t\t\treturn (/^[0-7]$/).test(str);\n
\t\t}\n
\n
\t\tfunction isHexDigit(str) {\n
\t\t\treturn (/^[0-9a-fA-F]$/).test(str);\n
\t\t}\n
\n
\t\tfunction isIdentifierStart(ch) {\n
\t\t\treturn (ch === "$") || (ch === "_") || (ch === "\\\\") ||\n
\t\t\t\t(ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z");\n
\t\t}\n
\n
\t\tif (char !== "." && !isDecimalDigit(char)) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tif (char !== ".") {\n
\t\t\tvalue = this.peek(index);\n
\t\t\tindex += 1;\n
\t\t\tchar = this.peek(index);\n
\n
\t\t\tif (value === "0") {\n
\t\t\t\tif (char === "x" || char === "X") {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tvalue += char;\n
\n
\t\t\t\t\twhile (index < length) {\n
\t\t\t\t\t\tchar = this.peek(index);\n
\t\t\t\t\t\tif (!isHexDigit(char)) {\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tvalue += char;\n
\t\t\t\t\t\tindex += 1;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif (value.length <= 2) { // 0x\n
\t\t\t\t\t\treturn {\n
\t\t\t\t\t\t\ttype: Token.NumericLiteral,\n
\t\t\t\t\t\t\tvalue: value,\n
\t\t\t\t\t\t\tisMalformed: true\n
\t\t\t\t\t\t};\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif (index < length) {\n
\t\t\t\t\t\tchar = this.peek(index);\n
\t\t\t\t\t\tif (isIdentifierStart(char)) {\n
\t\t\t\t\t\t\treturn null;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\ttype: Token.NumericLiteral,\n
\t\t\t\t\t\tvalue: value,\n
\t\t\t\t\t\tbase: 16,\n
\t\t\t\t\t\tisMalformed: false\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t\tif (isOctalDigit(char)) {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tvalue += char;\n
\t\t\t\t\tbad = false;\n
\n
\t\t\t\t\twhile (index < length) {\n
\t\t\t\t\t\tchar = this.peek(index);\n
\n
\t\t\t\t\t\tif (isDecimalDigit(char)) {\n
\t\t\t\t\t\t\tbad = true;\n
\t\t\t\t\t\t} else if (!isOctalDigit(char)) {\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tvalue += char;\n
\t\t\t\t\t\tindex += 1;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif (index < length) {\n
\t\t\t\t\t\tchar = this.peek(index);\n
\t\t\t\t\t\tif (isIdentifierStart(char)) {\n
\t\t\t\t\t\t\treturn null;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\ttype: Token.NumericLiteral,\n
\t\t\t\t\t\tvalue: value,\n
\t\t\t\t\t\tbase: 8,\n
\t\t\t\t\t\tisMalformed: false\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\n
\t\t\t\tif (isDecimalDigit(char)) {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tvalue += char;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\twhile (index < length) {\n
\t\t\t\tchar = this.peek(index);\n
\t\t\t\tif (!isDecimalDigit(char)) {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tvalue += char;\n
\t\t\t\tindex += 1;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (char === ".") {\n
\t\t\tvalue += char;\n
\t\t\tindex += 1;\n
\n
\t\t\twhile (index < length) {\n
\t\t\t\tchar = this.peek(index);\n
\t\t\t\tif (!isDecimalDigit(char)) {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tvalue += char;\n
\t\t\t\tindex += 1;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (char === "e" || char === "E") {\n
\t\t\tvalue += char;\n
\t\t\tindex += 1;\n
\t\t\tchar = this.peek(index);\n
\n
\t\t\tif (char === "+" || char === "-") {\n
\t\t\t\tvalue += this.peek(index);\n
\t\t\t\tindex += 1;\n
\t\t\t}\n
\n
\t\t\tchar = this.peek(index);\n
\t\t\tif (isDecimalDigit(char)) {\n
\t\t\t\tvalue += char;\n
\t\t\t\tindex += 1;\n
\n
\t\t\t\twhile (index < length) {\n
\t\t\t\t\tchar = this.peek(index);\n
\t\t\t\t\tif (!isDecimalDigit(char)) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\tvalue += char;\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (index < length) {\n
\t\t\tchar = this.peek(index);\n
\t\t\tif (isIdentifierStart(char)) {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttype: Token.NumericLiteral,\n
\t\t\tvalue: value,\n
\t\t\tbase: 10,\n
\t\t\tisMalformed: !isFinite(value)\n
\t\t};\n
\t},\n
\tscanStringLiteral: function (checks) {\n
\t\tvar quote = this.peek();\n
\t\tif (quote !== "\\"" && quote !== "\'") {\n
\t\t\treturn null;\n
\t\t}\n
\t\tthis.triggerAsync("warning", {\n
\t\t\tcode: "W108",\n
\t\t\tline: this.line,\n
\t\t\tcharacter: this.char // +1?\n
\t\t}, checks, function () { return state.jsonMode && quote !== "\\""; });\n
\n
\t\tvar value = "";\n
\t\tvar startLine = this.line;\n
\t\tvar startChar = this.char;\n
\t\tvar allowNewLine = false;\n
\n
\t\tthis.skip();\n
\n
\t\twhile (this.peek() !== quote) {\n
\t\t\twhile (this.peek() === "") { // End Of Line\n
\n
\t\t\t\tif (!allowNewLine) {\n
\t\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\t\tcode: "W112",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char\n
\t\t\t\t\t});\n
\t\t\t\t} else {\n
\t\t\t\t\tallowNewLine = false;\n
\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W043",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char\n
\t\t\t\t\t}, checks, function () { return !state.option.multistr; });\n
\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W042",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char\n
\t\t\t\t\t}, checks, function () { return state.jsonMode && state.option.multistr; });\n
\t\t\t\t}\n
\n
\t\t\t\tif (!this.nextLine()) {\n
\t\t\t\t\tthis.trigger("error", {\n
\t\t\t\t\t\tcode: "E029",\n
\t\t\t\t\t\tline: startLine,\n
\t\t\t\t\t\tcharacter: startChar\n
\t\t\t\t\t});\n
\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\ttype: Token.StringLiteral,\n
\t\t\t\t\t\tvalue: value,\n
\t\t\t\t\t\tisUnclosed: true,\n
\t\t\t\t\t\tquote: quote\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tallowNewLine = false;\n
\t\t\tvar char = this.peek();\n
\t\t\tvar jump = 1; // A length of a jump, after we\'re done\n
\n
\t\t\tif (char < " ") {\n
\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\tcode: "W113",\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\tdata: [ "<non-printable>" ]\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif (char === "\\\\") {\n
\t\t\t\tthis.skip();\n
\t\t\t\tchar = this.peek();\n
\n
\t\t\t\tswitch (char) {\n
\t\t\t\tcase "\'":\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W114",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tdata: [ "\\\\\'" ]\n
\t\t\t\t\t}, checks, function () {return state.jsonMode; });\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "b":\n
\t\t\t\t\tchar = "\\b";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "f":\n
\t\t\t\t\tchar = "\\f";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "n":\n
\t\t\t\t\tchar = "\\n";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "r":\n
\t\t\t\t\tchar = "\\r";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "t":\n
\t\t\t\t\tchar = "\\t";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "0":\n
\t\t\t\t\tchar = "\\0";\n
\t\t\t\t\tvar n = parseInt(this.peek(1), 10);\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W115",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char\n
\t\t\t\t\t}, checks,\n
\t\t\t\t\tfunction () { return n >= 0 && n <= 7 && state.directive["use strict"]; });\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "u":\n
\t\t\t\t\tchar = String.fromCharCode(parseInt(this.input.substr(1, 4), 16));\n
\t\t\t\t\tjump = 5;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "v":\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W114",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tdata: [ "\\\\v" ]\n
\t\t\t\t\t}, checks, function () { return state.jsonMode; });\n
\n
\t\t\t\t\tchar = "\\v";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "x":\n
\t\t\t\t\tvar\tx = parseInt(this.input.substr(1, 2), 16);\n
\n
\t\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\t\tcode: "W114",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tdata: [ "\\\\x-" ]\n
\t\t\t\t\t}, checks, function () { return state.jsonMode; });\n
\n
\t\t\t\t\tchar = String.fromCharCode(x);\n
\t\t\t\t\tjump = 3;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "\\\\":\n
\t\t\t\tcase "\\"":\n
\t\t\t\tcase "/":\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "":\n
\t\t\t\t\tallowNewLine = true;\n
\t\t\t\t\tchar = "";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "!":\n
\t\t\t\t\tif (value.slice(value.length - 2) === "<") {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\tdefault:\n
\t\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\t\tcode: "W044",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tvalue += char;\n
\t\t\tthis.skip(jump);\n
\t\t}\n
\n
\t\tthis.skip();\n
\t\treturn {\n
\t\t\ttype: Token.StringLiteral,\n
\t\t\tvalue: value,\n
\t\t\tisUnclosed: false,\n
\t\t\tquote: quote\n
\t\t};\n
\t},\n
\tscanRegExp: function () {\n
\t\tvar index = 0;\n
\t\tvar length = this.input.length;\n
\t\tvar char = this.peek();\n
\t\tvar value = char;\n
\t\tvar body = "";\n
\t\tvar flags = [];\n
\t\tvar malformed = false;\n
\t\tvar isCharSet = false;\n
\t\tvar terminated;\n
\n
\t\tvar scanUnexpectedChars = function () {\n
\t\t\tif (char < " ") {\n
\t\t\t\tmalformed = true;\n
\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\tcode: "W048",\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tcharacter: this.char\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\tif (char === "<") {\n
\t\t\t\tmalformed = true;\n
\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\tcode: "W049",\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\tdata: [ char ]\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}.bind(this);\n
\t\tif (!this.prereg || char !== "/") {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tindex += 1;\n
\t\tterminated = false;\n
\n
\t\twhile (index < length) {\n
\t\t\tchar = this.peek(index);\n
\t\t\tvalue += char;\n
\t\t\tbody += char;\n
\n
\t\t\tif (isCharSet) {\n
\t\t\t\tif (char === "]") {\n
\t\t\t\t\tif (this.peek(index - 1) !== "\\\\" || this.peek(index - 2) === "\\\\") {\n
\t\t\t\t\t\tisCharSet = false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif (char === "\\\\") {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tchar = this.peek(index);\n
\t\t\t\t\tbody += char;\n
\t\t\t\t\tvalue += char;\n
\n
\t\t\t\t\tscanUnexpectedChars();\n
\t\t\t\t}\n
\n
\t\t\t\tindex += 1;\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif (char === "\\\\") {\n
\t\t\t\tindex += 1;\n
\t\t\t\tchar = this.peek(index);\n
\t\t\t\tbody += char;\n
\t\t\t\tvalue += char;\n
\n
\t\t\t\tscanUnexpectedChars();\n
\n
\t\t\t\tif (char === "/") {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\tif (char === "[") {\n
\t\t\t\t\tindex += 1;\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (char === "[") {\n
\t\t\t\tisCharSet = true;\n
\t\t\t\tindex += 1;\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif (char === "/") {\n
\t\t\t\tbody = body.substr(0, body.length - 1);\n
\t\t\t\tterminated = true;\n
\t\t\t\tindex += 1;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tindex += 1;\n
\t\t}\n
\n
\t\tif (!terminated) {\n
\t\t\tthis.trigger("error", {\n
\t\t\t\tcode: "E015",\n
\t\t\t\tline: this.line,\n
\t\t\t\tcharacter: this.from\n
\t\t\t});\n
\n
\t\t\treturn void this.trigger("fatal", {\n
\t\t\t\tline: this.line,\n
\t\t\t\tfrom: this.from\n
\t\t\t});\n
\t\t}\n
\n
\t\twhile (index < length) {\n
\t\t\tchar = this.peek(index);\n
\t\t\tif (!/[gim]/.test(char)) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\tflags.push(char);\n
\t\t\tvalue += char;\n
\t\t\tindex += 1;\n
\t\t}\n
\n
\t\ttry {\n
\t\t\tnew RegExp(body, flags.join(""));\n
\t\t} catch (err) {\n
\t\t\tmalformed = true;\n
\t\t\tthis.trigger("error", {\n
\t\t\t\tcode: "E016",\n
\t\t\t\tline: this.line,\n
\t\t\t\tcharacter: this.char,\n
\t\t\t\tdata: [ err.message ] // Platform dependent!\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttype: Token.RegExp,\n
\t\t\tvalue: value,\n
\t\t\tflags: flags,\n
\t\t\tisMalformed: malformed\n
\t\t};\n
\t},\n
\tscanMixedSpacesAndTabs: function () {\n
\t\tvar at, match;\n
\n
\t\tif (state.option.smarttabs) {\n
\t\t\tmatch = this.input.match(/(\\/\\/|^\\s?\\*)? \\t/);\n
\t\t\tat = match && !match[1] ? 0 : -1;\n
\t\t} else {\n
\t\t\tat = this.input.search(/ \\t|\\t [^\\*]/);\n
\t\t}\n
\n
\t\treturn at;\n
\t},\n
\tscanUnsafeChars: function () {\n
\t\treturn this.input.search(reg.unsafeChars);\n
\t},\n
\tnext: function (checks) {\n
\t\tthis.from = this.char;\n
\t\tvar start;\n
\t\tif (/\\s/.test(this.peek())) {\n
\t\t\tstart = this.char;\n
\n
\t\t\twhile (/\\s/.test(this.peek())) {\n
\t\t\t\tthis.from += 1;\n
\t\t\t\tthis.skip();\n
\t\t\t}\n
\n
\t\t\tif (this.peek() === "") { // EOL\n
\t\t\t\tif (!/^\\s*$/.test(this.getLines()[this.line - 1]) && state.option.trailing) {\n
\t\t\t\t\tthis.trigger("warning", { code: "W102", line: this.line, character: start });\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tvar match = this.scanComments() ||\n
\t\t\tthis.scanStringLiteral(checks);\n
\n
\t\tif (match) {\n
\t\t\treturn match;\n
\t\t}\n
\n
\t\tmatch =\n
\t\t\tthis.scanRegExp() ||\n
\t\t\tthis.scanPunctuator() ||\n
\t\t\tthis.scanKeyword() ||\n
\t\t\tthis.scanIdentifier() ||\n
\t\t\tthis.scanNumericLiteral();\n
\n
\t\tif (match) {\n
\t\t\tthis.skip(match.value.length);\n
\t\t\treturn match;\n
\t\t}\n
\n
\t\treturn null;\n
\t},\n
\tnextLine: function () {\n
\t\tvar char;\n
\n
\t\tif (this.line >= this.getLines().length) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tthis.input = this.getLines()[this.line];\n
\t\tthis.line += 1;\n
\t\tthis.char = 1;\n
\t\tthis.from = 1;\n
\n
\t\tchar = this.scanMixedSpacesAndTabs();\n
\t\tif (char >= 0) {\n
\t\t\tthis.trigger("warning", { code: "W099", line: this.line, character: char + 1 });\n
\t\t}\n
\n
\t\tthis.input = this.input.replace(/\\t/g, state.tab);\n
\t\tchar = this.scanUnsafeChars();\n
\n
\t\tif (char >= 0) {\n
\t\t\tthis.trigger("warning", { code: "W100", line: this.line, character: char });\n
\t\t}\n
\n
\t\tif (state.option.maxlen && state.option.maxlen < this.input.length) {\n
\t\t\tthis.trigger("warning", { code: "W101", line: this.line, character: this.input.length });\n
\t\t}\n
\n
\t\treturn true;\n
\t},\n
\tstart: function () {\n
\t\tthis.nextLine();\n
\t},\n
\ttoken: function () {\n
\t\tvar checks = asyncTrigger();\n
\t\tvar token;\n
\n
\n
\t\tfunction isReserved(token, isProperty) {\n
\t\t\tif (!token.reserved) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tvar meta = token.meta;\n
\n
\t\t\tif (meta && meta.isFutureReservedWord && state.option.inES5()) {\n
\t\t\t\tif (!meta.es5) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\tif (meta.strictOnly) {\n
\t\t\t\t\tif (!state.option.strict && !state.directive["use strict"]) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif (isProperty) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn true;\n
\t\t}\n
\t\tvar create = function (type, value, isProperty) {\n
\t\t\tvar obj;\n
\n
\t\t\tif (type !== "(endline)" && type !== "(end)") {\n
\t\t\t\tthis.prereg = false;\n
\t\t\t}\n
\n
\t\t\tif (type === "(punctuator)") {\n
\t\t\t\tswitch (value) {\n
\t\t\t\tcase ".":\n
\t\t\t\tcase ")":\n
\t\t\t\tcase "~":\n
\t\t\t\tcase "#":\n
\t\t\t\tcase "]":\n
\t\t\t\t\tthis.prereg = false;\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tthis.prereg = true;\n
\t\t\t\t}\n
\n
\t\t\t\tobj = Object.create(state.syntax[value] || state.syntax["(error)"]);\n
\t\t\t}\n
\n
\t\t\tif (type === "(identifier)") {\n
\t\t\t\tif (value === "return" || value === "case" || value === "typeof") {\n
\t\t\t\t\tthis.prereg = true;\n
\t\t\t\t}\n
\n
\t\t\t\tif (_.has(state.syntax, value)) {\n
\t\t\t\t\tobj = Object.create(state.syntax[value] || state.syntax["(error)"]);\n
\t\t\t\t\tif (!isReserved(obj, isProperty && type === "(identifier)")) {\n
\t\t\t\t\t\tobj = null;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (!obj) {\n
\t\t\t\tobj = Object.create(state.syntax[type]);\n
\t\t\t}\n
\n
\t\t\tobj.identifier = (type === "(identifier)");\n
\t\t\tobj.type = obj.type || type;\n
\t\t\tobj.value = value;\n
\t\t\tobj.line = this.line;\n
\t\t\tobj.character = this.char;\n
\t\t\tobj.from = this.from;\n
\n
\t\t\tif (isProperty && obj.identifier) {\n
\t\t\t\tobj.isProperty = isProperty;\n
\t\t\t}\n
\n
\t\t\tobj.check = checks.check;\n
\n
\t\t\treturn obj;\n
\t\t}.bind(this);\n
\n
\t\tfor (;;) {\n
\t\t\tif (!this.input.length) {\n
\t\t\t\treturn create(this.nextLine() ? "(endline)" : "(end)", "");\n
\t\t\t}\n
\n
\t\t\ttoken = this.next(checks);\n
\n
\t\t\tif (!token) {\n
\t\t\t\tif (this.input.length) {\n
\t\t\t\t\tthis.trigger("error", {\n
\t\t\t\t\t\tcode: "E024",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tdata: [ this.peek() ]\n
\t\t\t\t\t});\n
\n
\t\t\t\t\tthis.input = "";\n
\t\t\t\t}\n
\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tswitch (token.type) {\n
\t\t\tcase Token.StringLiteral:\n
\t\t\t\tthis.triggerAsync("String", {\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tchar: this.char,\n
\t\t\t\t\tfrom: this.from,\n
\t\t\t\t\tvalue: token.value,\n
\t\t\t\t\tquote: token.quote\n
\t\t\t\t}, checks, function () { return true; });\n
\n
\t\t\t\treturn create("(string)", token.value);\n
\t\t\tcase Token.Identifier:\n
\t\t\t\tthis.trigger("Identifier", {\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tchar: this.char,\n
\t\t\t\t\tfrom: this.form,\n
\t\t\t\t\tname: token.value,\n
\t\t\t\t\tisProperty: state.tokens.curr.id === "."\n
\t\t\t\t});\n
\t\t\tcase Token.Keyword:\n
\t\t\tcase Token.NullLiteral:\n
\t\t\tcase Token.BooleanLiteral:\n
\t\t\t\treturn create("(identifier)", token.value, state.tokens.curr.id === ".");\n
\n
\t\t\tcase Token.NumericLiteral:\n
\t\t\t\tif (token.isMalformed) {\n
\t\t\t\t\tthis.trigger("warning", {\n
\t\t\t\t\t\tcode: "W045",\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tdata: [ token.value ]\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\n
\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\tcode: "W114",\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\tdata: [ "0x-" ]\n
\t\t\t\t}, checks, function () { return token.base === 16 && state.jsonMode; });\n
\n
\t\t\t\tthis.triggerAsync("warning", {\n
\t\t\t\t\tcode: "W115",\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tcharacter: this.char\n
\t\t\t\t}, checks, function () {\n
\t\t\t\t\treturn state.directive["use strict"] && token.base === 8; \n
\t\t\t\t});\n
\n
\t\t\t\tthis.trigger("Number", {\n
\t\t\t\t\tline: this.line,\n
\t\t\t\t\tchar: this.char,\n
\t\t\t\t\tfrom: this.from,\n
\t\t\t\t\tvalue: token.value,\n
\t\t\t\t\tbase: token.base,\n
\t\t\t\t\tisMalformed: token.malformed\n
\t\t\t\t});\n
\n
\t\t\t\treturn create("(number)", token.value);\n
\n
\t\t\tcase Token.RegExp:\n
\t\t\t\treturn create("(regexp)", token.value);\n
\n
\t\t\tcase Token.Comment:\n
\t\t\t\tstate.tokens.curr.comment = true;\n
\n
\t\t\t\tif (token.isSpecial) {\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\tvalue: token.value,\n
\t\t\t\t\t\tbody: token.body,\n
\t\t\t\t\t\ttype: token.commentType,\n
\t\t\t\t\t\tisSpecial: token.isSpecial,\n
\t\t\t\t\t\tline: this.line,\n
\t\t\t\t\t\tcharacter: this.char,\n
\t\t\t\t\t\tfrom: this.from\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\n
\t\t\t\tbreak;\n
\n
\t\t\tcase "":\n
\t\t\t\tbreak;\n
\n
\t\t\tdefault:\n
\t\t\t\treturn create("(punctuator)", token.value);\n
\t\t\t}\n
\t\t}\n
\t}\n
};\n
\n
exports.Lexer = Lexer;\n
\n
},\n
{"./reg.js":6,"./state.js":7,"events":10,"underscore":1}],\n
6:[function(req,module,exports){\n
\n
"use string";\n
exports.unsafeString =\n
\t/@cc|<\\/?|script|\\]\\s*\\]|<\\s*!|&lt/i;\n
exports.unsafeChars =\n
\t/[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/;\n
exports.needEsc =\n
\t/[\\u0000-\\u001f&<"\\/\\\\\\u007f-\\u009f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/;\n
\n
exports.needEscGlobal =\n
\t/[\\u0000-\\u001f&<"\\/\\\\\\u007f-\\u009f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/g;\n
exports.starSlash = /\\*\\//;\n
exports.identifier = /^([a-zA-Z_$][a-zA-Z0-9_$]*)$/;\n
exports.javascriptURL = /^(?:javascript|jscript|ecmascript|vbscript|mocha|livescript)\\s*:/i;\n
exports.fallsThrough = /^\\s*\\/\\*\\s*falls?\\sthrough\\s*\\*\\/\\s*$/;\n
\n
},\n
{}],\n
7:[function(req,module,exports){\n
\n
\n
var state = {\n
\tsyntax: {},\n
\n
\treset: function () {\n
\t\tthis.tokens = {\n
\t\t\tprev: null,\n
\t\t\tnext: null,\n
\t\t\tcurr: null\n
\t\t};\n
\n
\t\tthis.option = {};\n
\t\tthis.ignored = {};\n
\t\tthis.directive = {};\n
\t\tthis.jsonMode = false;\n
\t\tthis.jsonWarnings = [];\n
\t\tthis.lines = [];\n
\t\tthis.tab = "";\n
\t\tthis.cache = {}; // Node.JS doesn\'t have Map. Sniff.\n
\t}\n
};\n
\n
exports.state = state;\n
\n
},\n
{}],\n
8:[function(req,module,exports){\n
\n
\n
exports.register = function (linter) {\n
\n
\tlinter.on("Identifier", function style_scanProto(data) {\n
\t\tif (linter.getOption("proto")) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (data.name === "__proto__") {\n
\t\t\tlinter.warn("W103", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t\tdata: [ data.name ]\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("Identifier", function style_scanIterator(data) {\n
\t\tif (linter.getOption("iterator")) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (data.name === "__iterator__") {\n
\t\t\tlinter.warn("W104", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t\tdata: [ data.name ]\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("Identifier", function style_scanDangling(data) {\n
\t\tif (!linter.getOption("nomen")) {\n
\t\t\treturn;\n
\t\t}\n
\t\tif (data.name === "_") {\n
\t\t\treturn;\n
\t\t}\n
\t\tif (linter.getOption("node")) {\n
\t\t\tif (/^(__dirname|__filename)$/.test(data.name) && !data.isProperty) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (/^(_+.*|.*_+)$/.test(data.name)) {\n
\t\t\tlinter.warn("W105", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.from,\n
\t\t\t\tdata: [ "dangling \'_\'", data.name ]\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("Identifier", function style_scanCamelCase(data) {\n
\t\tif (!linter.getOption("camelcase")) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (data.name.replace(/^_+/, "").indexOf("_") > -1 && !data.name.match(/^[A-Z0-9_]*$/)) {\n
\t\t\tlinter.warn("W106", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.from,\n
\t\t\t\tdata: [ data.name ]\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("String", function style_scanQuotes(data) {\n
\t\tvar quotmark = linter.getOption("quotmark");\n
\t\tvar code;\n
\n
\t\tif (!quotmark) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (quotmark === "single" && data.quote !== "\'") {\n
\t\t\tcode = "W109";\n
\t\t}\n
\n
\t\tif (quotmark === "double" && data.quote !== "\\"") {\n
\t\t\tcode = "W108";\n
\t\t}\n
\n
\t\tif (quotmark === true) {\n
\t\t\tif (!linter.getCache("quotmark")) {\n
\t\t\t\tlinter.setCache("quotmark", data.quote);\n
\t\t\t}\n
\n
\t\t\tif (linter.getCache("quotmark") !== data.quote) {\n
\t\t\t\tcode = "W110";\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (code) {\n
\t\t\tlinter.warn(code, {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("Number", function style_scanNumbers(data) {\n
\t\tif (data.value.charAt(0) === ".") {\n
\t\t\tlinter.warn("W008", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t\tdata: [ data.value ]\n
\t\t\t});\n
\t\t}\n
\n
\t\tif (data.value.substr(data.value.length - 1) === ".") {\n
\t\t\tlinter.warn("W047", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t\tdata: [ data.value ]\n
\t\t\t});\n
\t\t}\n
\n
\t\tif (/^00+/.test(data.value)) {\n
\t\t\tlinter.warn("W046", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char,\n
\t\t\t\tdata: [ data.value ]\n
\t\t\t});\n
\t\t}\n
\t});\n
\n
\tlinter.on("String", function style_scanJavaScriptURLs(data) {\n
\t\tvar re = /^(?:javascript|jscript|ecmascript|vbscript|mocha|livescript)\\s*:/i;\n
\n
\t\tif (linter.getOption("scripturl")) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif (re.test(data.value)) {\n
\t\t\tlinter.warn("W107", {\n
\t\t\t\tline: data.line,\n
\t\t\t\tchar: data.char\n
\t\t\t});\n
\t\t}\n
\t});\n
};\n
},\n
{}],\n
9:[function(req,module,exports){\n
\n
},\n
{}],\n
10:[function(req,module,exports){\n
var process=req("__browserify_process");if (!process.EventEmitter) process.EventEmitter = function () {};\n
\n
var EventEmitter = exports.EventEmitter = process.EventEmitter;\n
var isArray = typeof Array.isArray === \'function\'\n
    ? Array.isArray\n
    : function (xs) {\n
        return Object.prototype.toString.call(xs) === \'[object Array]\'\n
    }\n
;\n
function indexOf (xs, x) {\n
    if (xs.indexOf) return xs.indexOf(x);\n
    for (var i = 0; i < xs.length; i++) {\n
        if (x === xs[i]) return i;\n
    }\n
    return -1;\n
}\n
var defaultMaxListeners = 200;\n
EventEmitter.prototype.setMaxListeners = function(n) {\n
  if (!this._events) this._events = {};\n
  this._events.maxListeners = n;\n
};\n
\n
\n
EventEmitter.prototype.emit = function(type) {\n
  if (type === \'error\') {\n
    if (!this._events || !this._events.error ||\n
        (isArray(this._events.error) && !this._events.error.length))\n
    {\n
      if (arguments[1] instanceof Error) {\n
        throw arguments[1]; // Unhandled \'error\' event\n
      } else {\n
        throw new Error("Uncaught, unspecified \'error\' event.");\n
      }\n
      return false;\n
    }\n
  }\n
\n
  if (!this._events) return false;\n
  var handler = this._events[type];\n
  if (!handler) return false;\n
\n
  if (typeof handler == \'function\') {\n
    switch (arguments.length) {\n
      case 1:\n
        handler.call(this);\n
        break;\n
      case 2:\n
        handler.call(this, arguments[1]);\n
        break;\n
      case 3:\n
        handler.call(this, arguments[1], arguments[2]);\n
        break;\n
      default:\n
        var args = Array.prototype.slice.call(arguments, 1);\n
        handler.apply(this, args);\n
    }\n
    return true;\n
\n
  } else if (isArray(handler)) {\n
    var args = Array.prototype.slice.call(arguments, 1);\n
\n
    var listeners = handler.slice();\n
    for (var i = 0, l = listeners.length; i < l; i++) {\n
      listeners[i].apply(this, args);\n
    }\n
    return true;\n
\n
  } else {\n
    return false;\n
  }\n
};\n
EventEmitter.prototype.addListener = function(type, listener) {\n
  if (\'function\' !== typeof listener) {\n
    throw new Error(\'addListener only takes instances of Function\');\n
  }\n
\n
  if (!this._events) this._events = {};\n
  this.emit(\'newListener\', type, listener);\n
\n
  if (!this._events[type]) {\n
    this._events[type] = listener;\n
  } else if (isArray(this._events[type])) {\n
    if (!this._events[type].warned) {\n
      var m;\n
      if (this._events.maxListeners !== undefined) {\n
        m = this._events.maxListeners;\n
      } else {\n
        m = defaultMaxListeners;\n
      }\n
\n
      if (m && m > 0 && this._events[type].length > m) {\n
        this._events[type].warned = true;\n
        console.error(\'(node) warning: possible EventEmitter memory \' +\n
                      \'leak detected. %d listeners added. \' +\n
                      \'Use emitter.setMaxListeners() to increase limit.\',\n
                      this._events[type].length);\n
        console.trace();\n
      }\n
    }\n
    this._events[type].push(listener);\n
  } else {\n
    this._events[type] = [this._events[type], listener];\n
  }\n
\n
  return this;\n
};\n
\n
EventEmitter.prototype.on = EventEmitter.prototype.addListener;\n
\n
EventEmitter.prototype.once = function(type, listener) {\n
  var self = this;\n
  self.on(type, function g() {\n
    self.removeListener(type, g);\n
    listener.apply(this, arguments);\n
  });\n
\n
  return this;\n
};\n
\n
EventEmitter.prototype.removeListener = function(type, listener) {\n
  if (\'function\' !== typeof listener) {\n
    throw new Error(\'removeListener only takes instances of Function\');\n
  }\n
  if (!this._events || !this._events[type]) return this;\n
\n
  var list = this._events[type];\n
\n
  if (isArray(list)) {\n
    var i = indexOf(list, listener);\n
    if (i < 0) return this;\n
    list.splice(i, 1);\n
    if (list.length == 0)\n
      delete this._events[type];\n
  } else if (this._events[type] === listener) {\n
    delete this._events[type];\n
  }\n
\n
  return this;\n
};\n
\n
EventEmitter.prototype.removeAllListeners = function(type) {\n
  if (arguments.length === 0) {\n
    this._events = {};\n
    return this;\n
  }\n
  if (type && this._events && this._events[type]) this._events[type] = null;\n
  return this;\n
};\n
\n
EventEmitter.prototype.listeners = function(type) {\n
  if (!this._events) this._events = {};\n
  if (!this._events[type]) this._events[type] = [];\n
  if (!isArray(this._events[type])) {\n
    this._events[type] = [this._events[type]];\n
  }\n
  return this._events[type];\n
};\n
\n
EventEmitter.listenerCount = function(emitter, type) {\n
  var ret;\n
  if (!emitter._events || !emitter._events[type])\n
    ret = 0;\n
  else if (typeof emitter._events[type] === \'function\')\n
    ret = 1;\n
  else\n
    ret = emitter._events[type].length;\n
  return ret;\n
};\n
\n
},\n
{"__browserify_process":11}],\n
11:[function(req,module,exports){\n
\n
var process = module.exports = {};\n
\n
process.nextTick = (function () {\n
    var canSetImmediate = typeof window !== \'undefined\'\n
    && window.setImmediate;\n
    var canPost = typeof window !== \'undefined\'\n
    && window.postMessage && window.addEventListener\n
    ;\n
\n
    if (canSetImmediate) {\n
        return function (f) { return window.setImmediate(f) };\n
    }\n
\n
    if (canPost) {\n
        var queue = [];\n
        window.addEventListener(\'message\', function (ev) {\n
            if (ev.source === window && ev.data === \'process-tick\') {\n
                ev.stopPropagation();\n
                if (queue.length > 0) {\n
                    var fn = queue.shift();\n
                    fn();\n
                }\n
            }\n
        }, true);\n
\n
        return function nextTick(fn) {\n
            queue.push(fn);\n
            window.postMessage(\'process-tick\', \'*\');\n
        };\n
    }\n
\n
    return function nextTick(fn) {\n
        setTimeout(fn, 0);\n
    };\n
})();\n
\n
process.title = \'browser\';\n
process.browser = true;\n
process.env = {};\n
process.argv = [];\n
\n
process.binding = function (name) {\n
    throw new Error(\'process.binding is not supported\');\n
}\n
process.cwd = function () { return \'/\' };\n
process.chdir = function (dir) {\n
    throw new Error(\'process.chdir is not supported\');\n
};\n
\n
},\n
{}],\n
"jshint":[function(req,module,exports){\n
module.exports=req(\'n4bKNg\');\n
},\n
{}]},{},["n4bKNg"])\n
;\n
\n
function req() {return require.apply(this, arguments)}\n
module.exports = req("jshint");\n
\n
});

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
