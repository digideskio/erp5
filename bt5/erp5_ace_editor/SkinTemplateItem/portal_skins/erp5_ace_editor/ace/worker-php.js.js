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
            <value> <string>ts83646620.49</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>worker-php.js</string> </value>
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
            <value> <int>229384</int> </value>
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
define(\'ace/mode/php_worker\', [\'require\', \'exports\', \'module\' , \'ace/lib/oop\', \'ace/worker/mirror\', \'ace/mode/php/php\'], function(require, exports, module) {\n
\n
\n
var oop = require("../lib/oop");\n
var Mirror = require("../worker/mirror").Mirror;\n
var PHP = require("./php/php").PHP;\n
\n
var PhpWorker = exports.PhpWorker = function(sender) {\n
    Mirror.call(this, sender);\n
    this.setTimeout(500);\n
};\n
\n
oop.inherits(PhpWorker, Mirror);\n
\n
(function() {\n
\n
    this.onUpdate = function() {\n
        var value = this.doc.getValue();\n
        var errors = [];\n
\n
        var tokens = PHP.Lexer(value, {short_open_tag: 1});\n
        try {\n
            new PHP.Parser(tokens);\n
        } catch(e) {\n
            errors.push({\n
                row: e.line - 1,\n
                column: null,\n
                text: e.message.charAt(0).toUpperCase() + e.message.substring(1),\n
                type: "error"\n
            });\n
        }\n
\n
        if (errors.length) {\n
            this.sender.emit("error", errors);\n
        } else {\n
            this.sender.emit("ok");\n
        }\n
    };\n
\n
}).call(PhpWorker.prototype);\n
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
\n
\n
define(\'ace/mode/php/php\', [\'require\', \'exports\', \'module\' ], function(require, exports, module) {\n
\n
var PHP = {Constants:{}};\n
\n
\n
\n
\n
PHP.Constants.T_INCLUDE = 262;\n
PHP.Constants.T_INCLUDE_ONCE = 261;\n
PHP.Constants.T_EVAL = 260;\n
PHP.Constants.T_REQUIRE = 259;\n
PHP.Constants.T_REQUIRE_ONCE = 258;\n
PHP.Constants.T_LOGICAL_OR = 263;\n
PHP.Constants.T_LOGICAL_XOR = 264;\n
PHP.Constants.T_LOGICAL_AND = 265;\n
PHP.Constants.T_PRINT = 266;\n
PHP.Constants.T_PLUS_EQUAL = 277;\n
PHP.Constants.T_MINUS_EQUAL = 276;\n
PHP.Constants.T_MUL_EQUAL = 275;\n
PHP.Constants.T_DIV_EQUAL = 274;\n
PHP.Constants.T_CONCAT_EQUAL = 273;\n
PHP.Constants.T_MOD_EQUAL = 272;\n
PHP.Constants.T_AND_EQUAL = 271;\n
PHP.Constants.T_OR_EQUAL = 270;\n
PHP.Constants.T_XOR_EQUAL = 269;\n
PHP.Constants.T_SL_EQUAL = 268;\n
PHP.Constants.T_SR_EQUAL = 267;\n
PHP.Constants.T_BOOLEAN_OR = 278;\n
PHP.Constants.T_BOOLEAN_AND = 279;\n
PHP.Constants.T_IS_EQUAL = 283;\n
PHP.Constants.T_IS_NOT_EQUAL = 282;\n
PHP.Constants.T_IS_IDENTICAL = 281;\n
PHP.Constants.T_IS_NOT_IDENTICAL = 280;\n
PHP.Constants.T_IS_SMALLER_OR_EQUAL = 285;\n
PHP.Constants.T_IS_GREATER_OR_EQUAL = 284;\n
PHP.Constants.T_SL = 287;\n
PHP.Constants.T_SR = 286;\n
PHP.Constants.T_INSTANCEOF = 288;\n
PHP.Constants.T_INC = 297;\n
PHP.Constants.T_DEC = 296;\n
PHP.Constants.T_INT_CAST = 295;\n
PHP.Constants.T_DOUBLE_CAST = 294;\n
PHP.Constants.T_STRING_CAST = 293;\n
PHP.Constants.T_ARRAY_CAST = 292;\n
PHP.Constants.T_OBJECT_CAST = 291;\n
PHP.Constants.T_BOOL_CAST = 290;\n
PHP.Constants.T_UNSET_CAST = 289;\n
PHP.Constants.T_NEW = 299;\n
PHP.Constants.T_CLONE = 298;\n
PHP.Constants.T_EXIT = 300;\n
PHP.Constants.T_IF = 301;\n
PHP.Constants.T_ELSEIF = 302;\n
PHP.Constants.T_ELSE = 303;\n
PHP.Constants.T_ENDIF = 304;\n
PHP.Constants.T_LNUMBER = 305;\n
PHP.Constants.T_DNUMBER = 306;\n
PHP.Constants.T_STRING = 307;\n
PHP.Constants.T_STRING_VARNAME = 308;\n
PHP.Constants.T_VARIABLE = 309;\n
PHP.Constants.T_NUM_STRING = 310;\n
PHP.Constants.T_INLINE_HTML = 311;\n
PHP.Constants.T_CHARACTER = 312;\n
PHP.Constants.T_BAD_CHARACTER = 313;\n
PHP.Constants.T_ENCAPSED_AND_WHITESPACE = 314;\n
PHP.Constants.T_CONSTANT_ENCAPSED_STRING = 315;\n
PHP.Constants.T_ECHO = 316;\n
PHP.Constants.T_DO = 317;\n
PHP.Constants.T_WHILE = 318;\n
PHP.Constants.T_ENDWHILE = 319;\n
PHP.Constants.T_FOR = 320;\n
PHP.Constants.T_ENDFOR = 321;\n
PHP.Constants.T_FOREACH = 322;\n
PHP.Constants.T_ENDFOREACH = 323;\n
PHP.Constants.T_DECLARE = 324;\n
PHP.Constants.T_ENDDECLARE = 325;\n
PHP.Constants.T_AS = 326;\n
PHP.Constants.T_SWITCH = 327;\n
PHP.Constants.T_ENDSWITCH = 328;\n
PHP.Constants.T_CASE = 329;\n
PHP.Constants.T_DEFAULT = 330;\n
PHP.Constants.T_BREAK = 331;\n
PHP.Constants.T_CONTINUE = 332;\n
PHP.Constants.T_GOTO = 333;\n
PHP.Constants.T_FUNCTION = 334;\n
PHP.Constants.T_CONST = 335;\n
PHP.Constants.T_RETURN = 336;\n
PHP.Constants.T_TRY = 337;\n
PHP.Constants.T_CATCH = 338;\n
PHP.Constants.T_THROW = 339;\n
PHP.Constants.T_USE = 340;\n
PHP.Constants.T_GLOBAL = 341;\n
PHP.Constants.T_STATIC = 347;\n
PHP.Constants.T_ABSTRACT = 346;\n
PHP.Constants.T_FINAL = 345;\n
PHP.Constants.T_PRIVATE = 344;\n
PHP.Constants.T_PROTECTED = 343;\n
PHP.Constants.T_PUBLIC = 342;\n
PHP.Constants.T_VAR = 348;\n
PHP.Constants.T_UNSET = 349;\n
PHP.Constants.T_ISSET = 350;\n
PHP.Constants.T_EMPTY = 351;\n
PHP.Constants.T_HALT_COMPILER = 352;\n
PHP.Constants.T_CLASS = 353;\n
PHP.Constants.T_TRAIT = 382;\n
PHP.Constants.T_INTERFACE = 354;\n
PHP.Constants.T_EXTENDS = 355;\n
PHP.Constants.T_IMPLEMENTS = 356;\n
PHP.Constants.T_OBJECT_OPERATOR = 357;\n
PHP.Constants.T_DOUBLE_ARROW = 358;\n
PHP.Constants.T_LIST = 359;\n
PHP.Constants.T_ARRAY = 360;\n
PHP.Constants.T_CLASS_C = 361;\n
PHP.Constants.T_TRAIT_C = 381;\n
PHP.Constants.T_METHOD_C = 362;\n
PHP.Constants.T_FUNC_C = 363;\n
PHP.Constants.T_LINE = 364;\n
PHP.Constants.T_FILE = 365;\n
PHP.Constants.T_COMMENT = 366;\n
PHP.Constants.T_DOC_COMMENT = 367;\n
PHP.Constants.T_OPEN_TAG = 368;\n
PHP.Constants.T_OPEN_TAG_WITH_ECHO = 369;\n
PHP.Constants.T_CLOSE_TAG = 370;\n
PHP.Constants.T_WHITESPACE = 371;\n
PHP.Constants.T_START_HEREDOC = 372;\n
PHP.Constants.T_END_HEREDOC = 373;\n
PHP.Constants.T_DOLLAR_OPEN_CURLY_BRACES = 374;\n
PHP.Constants.T_CURLY_OPEN = 375;\n
PHP.Constants.T_PAAMAYIM_NEKUDOTAYIM = 376;\n
PHP.Constants.T_DOUBLE_COLON = 376;\n
PHP.Constants.T_NAMESPACE = 377;\n
PHP.Constants.T_NS_C = 378;\n
PHP.Constants.T_DIR = 379;\n
PHP.Constants.T_NS_SEPARATOR = 380;\n
PHP.Lexer = function( src, ini ) {\n
\n
\n
    var heredoc,\n
    lineBreaker = function( result ) {\n
        if (result.match(/\\n/) !== null) {\n
            var quote = result.substring(0, 1);\n
            result = \'[\' + result.split(/\\n/).join( quote + "," + quote ) + \'].join("\\\\n")\';\n
\n
        }\n
\n
        return result;\n
    },\n
    prev,\n
\n
    openTag = (ini === undefined || (/^(on|true|1)$/i.test(ini.short_open_tag) ) ? /(\\<\\?php\\s|\\<\\?|\\<\\%|\\<script language\\=(\'|")?php(\'|")?\\>)/i : /(\\<\\?php\\s|<\\?=|\\<script language\\=(\'|")?php(\'|")?\\>)/i),\n
        openTagStart = (ini === undefined || (/^(on|true|1)$/i.test(ini.short_open_tag)) ? /^(\\<\\?php\\s|\\<\\?|\\<\\%|\\<script language\\=(\'|")?php(\'|")?\\>)/i : /^(\\<\\?php\\s|<\\?=|\\<script language\\=(\'|")?php(\'|")?\\>)/i),\n
            tokens = [\n
            {\n
                value: PHP.Constants.T_NAMESPACE,\n
                re: /^namespace(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_USE,\n
                re: /^use(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ABSTRACT,\n
                re: /^abstract(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_IMPLEMENTS,\n
                re: /^implements(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_INTERFACE,\n
                re: /^interface(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_CONST,\n
                re: /^const(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_STATIC,\n
                re: /^static(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_FINAL,\n
                re: /^final(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_VAR,\n
                re: /^var(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_GLOBAL,\n
                re: /^global(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_CLONE,\n
                re: /^clone(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_THROW,\n
                re: /^throw(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_EXTENDS,\n
                re: /^extends(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_AND_EQUAL,\n
                re: /^&=/\n
            },\n
            {\n
                value: PHP.Constants.T_AS,\n
                re: /^as(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ARRAY_CAST,\n
                re: /^\\(array\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_BOOL_CAST,\n
                re: /^\\((bool|boolean)\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_DOUBLE_CAST,\n
                re: /^\\((real|float|double)\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_INT_CAST,\n
                re: /^\\((int|integer)\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_OBJECT_CAST,\n
                re: /^\\(object\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_STRING_CAST,\n
                re: /^\\(string\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_UNSET_CAST,\n
                re: /^\\(unset\\)/i\n
            },\n
            {\n
                value: PHP.Constants.T_TRY,\n
                re: /^try(?=\\s*{)/i\n
            },\n
            {\n
                value: PHP.Constants.T_CATCH,\n
                re: /^catch(?=\\s*\\()/i\n
            },\n
            {\n
                value: PHP.Constants.T_INSTANCEOF,\n
                re: /^instanceof(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_LOGICAL_OR,\n
                re: /^or(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_LOGICAL_AND,\n
                re: /^and(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_LOGICAL_XOR,\n
                re: /^xor(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_BOOLEAN_AND,\n
                re: /^&&/\n
            },\n
            {\n
                value: PHP.Constants.T_BOOLEAN_OR,\n
                re: /^\\|\\|/\n
            },\n
            {\n
                value: PHP.Constants.T_CONTINUE,\n
                re: /^continue(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_BREAK,\n
                re: /^break(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDDECLARE,\n
                re: /^enddeclare(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDFOR,\n
                re: /^endfor(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDFOREACH,\n
                re: /^endforeach(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDIF,\n
                re: /^endif(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDSWITCH,\n
                re: /^endswitch(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_ENDWHILE,\n
                re: /^endwhile(?=\\s|;)/i\n
            },\n
            {\n
                value: PHP.Constants.T_CASE,\n
                re: /^case(?=\\s)/i\n
            },\n
            {\n
                value: PHP.Constants.T_DEFAULT,\n
                re: /^default(?=\\s|:)/i\n
            },\n
            {\n
                value: PHP.Constants.T_SWITCH,\n
                re: /^switch(?=[ (])/i\n
            },\n
            {\n
                value: PHP.Constants.T_EXIT,\n
                re: /^(exit|die)(?=[ \\(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_CLOSE_TAG,\n
                re: /^(\\?\\>|\\%\\>|\\<\\/script\\>)\\s?\\s?/i,\n
                func: function( result ) {\n
                    insidePHP = false;\n
                    return result;\n
                }\n
            },\n
            {\n
                value: PHP.Constants.T_DOUBLE_ARROW,\n
                re: /^\\=\\>/\n
            },\n
            {\n
                value: PHP.Constants.T_DOUBLE_COLON,\n
                re: /^\\:\\:/\n
            },\n
            {\n
                value: PHP.Constants.T_METHOD_C,\n
                re: /^__METHOD__/\n
            },\n
            {\n
                value: PHP.Constants.T_LINE,\n
                re: /^__LINE__/\n
            },\n
            {\n
                value: PHP.Constants.T_FILE,\n
                re: /^__FILE__/\n
            },\n
            {\n
                value: PHP.Constants.T_FUNC_C,\n
                re: /^__FUNCTION__/\n
            },\n
            {\n
                value: PHP.Constants.T_NS_C,\n
                re: /^__NAMESPACE__/\n
            },\n
            {\n
                value: PHP.Constants.T_TRAIT_C,\n
                re: /^__TRAIT__/\n
            },\n
            {\n
                value: PHP.Constants.T_DIR,\n
                re: /^__DIR__/\n
            },\n
            {\n
                value: PHP.Constants.T_CLASS_C,\n
                re: /^__CLASS__/\n
            },\n
            {\n
                value: PHP.Constants.T_INC,\n
                re: /^\\+\\+/\n
            },\n
            {\n
                value: PHP.Constants.T_DEC,\n
                re: /^\\-\\-/\n
            },\n
            {\n
                value: PHP.Constants.T_CONCAT_EQUAL,\n
                re: /^\\.\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_DIV_EQUAL,\n
                re: /^\\/\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_XOR_EQUAL,\n
                re: /^\\^\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_MUL_EQUAL,\n
                re: /^\\*\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_MOD_EQUAL,\n
                re: /^\\%\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_SL_EQUAL,\n
                re: /^<<=/\n
            },\n
            {\n
                value: PHP.Constants.T_START_HEREDOC,\n
                re: /^<<<[A-Z_0-9]+\\s/i,\n
                func: function( result ){\n
                    heredoc = result.substring(3, result.length - 1);\n
                    return result;\n
                }\n
            },\n
            {\n
                value: PHP.Constants.T_SL,\n
                re: /^<</\n
            },\n
            {\n
                value: PHP.Constants.T_IS_SMALLER_OR_EQUAL,\n
                re: /^<=/\n
            },\n
            {\n
                value: PHP.Constants.T_SR_EQUAL,\n
                re: /^>>=/\n
            },\n
            {\n
                value: PHP.Constants.T_SR,\n
                re: /^>>/\n
            },\n
            {\n
                value: PHP.Constants.T_IS_GREATER_OR_EQUAL,\n
                re: /^>=/\n
            },\n
            {\n
                value: PHP.Constants.T_OR_EQUAL,\n
                re: /^\\|\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_PLUS_EQUAL,\n
                re: /^\\+\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_MINUS_EQUAL,\n
                re: /^-\\=/\n
            },\n
            {\n
                value: PHP.Constants.T_OBJECT_OPERATOR,\n
                re: /^\\-\\>/i\n
            },\n
            {\n
                value: PHP.Constants.T_CLASS,\n
                re: /^class(?=[\\s\\{])/i,\n
                afterWhitespace: true\n
            },\n
            {\n
                value: PHP.Constants.T_TRAIT,\n
                re: /^trait(?=[\\s]+[A-Za-z])/i,\n
            },\n
            {\n
                value: PHP.Constants.T_PUBLIC,\n
                re: /^public(?=[\\s])/i\n
            },\n
            {\n
                value: PHP.Constants.T_PRIVATE,\n
                re: /^private(?=[\\s])/i\n
            },\n
            {\n
                value: PHP.Constants.T_PROTECTED,\n
                re: /^protected(?=[\\s])/i\n
            },\n
            {\n
                value: PHP.Constants.T_ARRAY,\n
                re: /^array(?=\\s*?\\()/i\n
            },\n
            {\n
                value: PHP.Constants.T_EMPTY,\n
                re: /^empty(?=[ \\(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_ISSET,\n
                re: /^isset(?=[ \\(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_UNSET,\n
                re: /^unset(?=[ \\(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_RETURN,\n
                re: /^return(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_FUNCTION,\n
                re: /^function(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_ECHO,\n
                re: /^echo(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_LIST,\n
                re: /^list(?=\\s*?\\()/i\n
            },\n
            {\n
                value: PHP.Constants.T_PRINT,\n
                re: /^print(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_INCLUDE,\n
                re: /^include(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_INCLUDE_ONCE,\n
                re: /^include_once(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_REQUIRE,\n
                re: /^require(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_REQUIRE_ONCE,\n
                re: /^require_once(?=[ "\'(;])/i\n
            },\n
            {\n
                value: PHP.Constants.T_NEW,\n
                re: /^new(?=[ ])/i\n
            },\n
            {\n
                value: PHP.Constants.T_COMMENT,\n
                re: /^\\/\\*([\\S\\s]*?)(?:\\*\\/|$)/\n
            },\n
            {\n
                value: PHP.Constants.T_COMMENT,\n
                re: /^\\/\\/.*(\\s)?/\n
            },\n
            {\n
                value: PHP.Constants.T_COMMENT,\n
                re: /^\\#.*(\\s)?/\n
            },\n
            {\n
                value: PHP.Constants.T_ELSEIF,\n
                re: /^elseif(?=[\\s(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_GOTO,\n
                re: /^goto(?=[\\s(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_ELSE,\n
                re: /^else(?=[\\s{:])/i\n
            },\n
            {\n
                value: PHP.Constants.T_IF,\n
                re: /^if(?=[\\s(])/i\n
            },\n
            {\n
                value: PHP.Constants.T_DO,\n
                re: /^do(?=[ {])/i\n
            },\n
            {\n
                value: PHP.Constants.T_WHILE,\n
                re: /^while(?=[ (])/i\n
            },\n
            {\n
                value: PHP.Constants.T_FOREACH,\n
                re: /^foreach(?=[ (])/i\n
            },\n
            {\n
                value: PHP.Constants.T_ISSET,\n
                re: /^isset(?=[ (])/i\n
            },\n
            {\n
                value: PHP.Constants.T_IS_IDENTICAL,\n
                re: /^===/\n
            },\n
            {\n
                value: PHP.Constants.T_IS_EQUAL,\n
                re: /^==/\n
            },\n
            {\n
                value: PHP.Constants.T_IS_NOT_IDENTICAL,\n
                re: /^\\!==/\n
            },\n
            {\n
                value: PHP.Constants.T_IS_NOT_EQUAL,\n
                re: /^(\\!=|\\<\\>)/\n
            },\n
            {\n
                value: PHP.Constants.T_FOR,\n
                re: /^for(?=[ (])/i\n
            },\n
\n
            {\n
                value: PHP.Constants.T_DNUMBER,\n
                re: /^[0-9]*\\.[0-9]+([eE][-]?[0-9]*)?/\n
\n
            },\n
            {\n
                value: PHP.Constants.T_LNUMBER,\n
                re: /^(0x[0-9A-F]+|[0-9]+)/i\n
            },\n
            {\n
                value: PHP.Constants.T_OPEN_TAG_WITH_ECHO,\n
                re: /^(\\<\\?=|\\<\\%=)/i\n
            },\n
            {\n
                value: PHP.Constants.T_OPEN_TAG,\n
                re: openTagStart\n
            },\n
            {\n
                value: PHP.Constants.T_VARIABLE,\n
                re: /^\\$[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*/\n
            },\n
            {\n
                value: PHP.Constants.T_WHITESPACE,\n
                re: /^\\s+/\n
            },\n
            {\n
                value: PHP.Constants.T_CONSTANT_ENCAPSED_STRING,\n
                re: /^("(?:[^"\\\\]|\\\\[\\s\\S])*"|\'(?:[^\'\\\\]|\\\\[\\s\\S])*\')/,\n
                func: function( result, token ) {\n
\n
                    var curlyOpen = 0,\n
                    len,\n
                    bracketOpen = 0;\n
\n
                    if (result.substring( 0,1 ) === "\'") {\n
                        return result;\n
                    }\n
\n
                    var match = result.match( /(?:[^\\\\]|\\\\.)*[^\\\\]\\$[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*/g );\n
                    if ( match !== null ) {\n
\n
                        while( result.length > 0 ) {\n
                            len = result.length;\n
                            match = result.match( /^[\\[\\]\\;\\:\\?\\(\\)\\!\\.\\,\\>\\<\\=\\+\\-\\/\\*\\|\\&\\@\\^\\%\\"\\\'\\{\\}]/ );\n
\n
                            if ( match !== null ) {\n
\n
                                results.push( match[ 0 ] );\n
                                result = result.substring( 1 );\n
\n
                                if ( curlyOpen > 0 && match[ 0 ] === "}") {\n
                                    curlyOpen--;\n
                                }\n
\n
                                if ( match[ 0 ] === "[" ) {\n
                                    bracketOpen++;\n
                                }\n
\n
                                if ( match[ 0 ] === "]" ) {\n
                                    bracketOpen--;\n
                                }\n
\n
                            }\n
\n
                            match = result.match(/^\\$[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*/);\n
\n
\n
\n
                            if ( match !== null ) {\n
\n
                                results.push([\n
                                    parseInt(PHP.Constants.T_VARIABLE, 10),\n
                                    match[ 0 ],\n
                                    line\n
                                    ]);\n
\n
                                result = result.substring( match[ 0 ].length );\n
\n
                                match = result.match(/^(\\-\\>)\\s*([a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*)\\s*(\\()/);\n
\n
                                if ( match !== null ) {\n
\n
                                    results.push([\n
                                        parseInt(PHP.Constants.T_OBJECT_OPERATOR, 10),\n
                                        match[ 1 ],\n
                                        line\n
                                        ]);\n
                                    results.push([\n
                                        parseInt(PHP.Constants.T_STRING, 10),\n
                                        match[ 2 ],\n
                                        line\n
                                        ]);\n
                                    if (match[3]) {\n
                                        results.push(match[3]);\n
                                    }\n
                                    result = result.substring( match[ 0 ].length );\n
                                }\n
\n
\n
                                if ( result.match( /^\\[/g ) !== null ) {\n
                                    continue;\n
                                }\n
                            }\n
\n
                            var re;\n
                            if ( curlyOpen > 0) {\n
                                re = /^([^\\\\\\$"{}\\]\\)]|\\\\.)+/g;\n
                            } else {\n
                                re = /^([^\\\\\\$"{]|\\\\.|{[^\\$]|\\$(?=[^a-zA-Z_\\x7f-\\xff]))+/g;;\n
                            }\n
\n
                            while(( match = result.match( re )) !== null ) {\n
\n
\n
                                if (result.length === 1) {\n
                                    throw new Error(match);\n
                                }\n
\n
\n
\n
                                results.push([\n
                                    parseInt(( curlyOpen > 0 ) ? PHP.Constants.T_CONSTANT_ENCAPSED_STRING : PHP.Constants.T_ENCAPSED_AND_WHITESPACE, 10),\n
                                    match[ 0 ].replace(/\\n/g,"\\\\n").replace(/\\r/g,""),\n
                                    line\n
                                    ]);\n
\n
                                line += match[ 0 ].split(\'\\n\').length - 1;\n
\n
                                result = result.substring( match[ 0 ].length );\n
\n
                            }\n
\n
                            if( result.match(/^{\\$/) !== null ) {\n
\n
                                results.push([\n
                                    parseInt(PHP.Constants.T_CURLY_OPEN, 10),\n
                                    "{",\n
                                    line\n
                                    ]);\n
                                result = result.substring( 1 );\n
                                curlyOpen++;\n
                            }\n
\n
                            if (len === result.length) {\n
                                if ((match =  result.match( /^(([^\\\\]|\\\\.)*?[^\\\\]\\$[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*)/g )) !== null) {\n
                                    return;\n
                                }\n
                            }\n
\n
                        }\n
\n
                        return undefined;\n
\n
                    } else {\n
                        result = result.replace(/\\r/g,"");\n
                    }\n
                    return result;\n
                }\n
            },\n
            {\n
                value: PHP.Constants.T_NS_SEPARATOR,\n
                re: /^\\\\(?=[a-zA-Z_])/\n
            },\n
            {\n
                value: PHP.Constants.T_STRING,\n
                re: /^[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]*/\n
            },\n
            {\n
                value: -1,\n
                re: /^[\\[\\]\\;\\:\\?\\(\\)\\!\\.\\,\\>\\<\\=\\+\\-\\/\\*\\|\\&\\{\\}\\@\\^\\%\\"\\\'\\$\\~]/\n
            }];\n
\n
\n
\n
\n
\n
            var results = [],\n
            line = 1,\n
            insidePHP = false,\n
            cancel = true;\n
\n
            if ( src === null ) {\n
                return results;\n
            }\n
\n
            if ( typeof src !== "string" ) {\n
                src = src.toString();\n
            }\n
\n
\n
\n
            while (src.length > 0 && cancel === true) {\n
\n
                if ( insidePHP === true ) {\n
\n
                    if ( heredoc !== undefined ) {\n
\n
                        var regexp = new RegExp(\'([\\\\S\\\\s]*?)(\\\\r\\\\n|\\\\n|\\\\r)(\' + heredoc + \')(;|\\\\r\\\\n|\\\\n)\',"i");\n
\n
\n
\n
                        var result = src.match( regexp );\n
                        if ( result !== null ) {\n
\n
                            results.push([\n
                                parseInt(PHP.Constants.T_ENCAPSED_AND_WHITESPACE, 10),\n
                                result[ 1 ].replace(/^\\n/g,"").replace(/\\\\\\$/g,"$") + "\\n",\n
                                line\n
                                ]);\n
                            line += result[ 1 ].split(\'\\n\').length;\n
                            results.push([\n
                                parseInt(PHP.Constants.T_END_HEREDOC, 10),\n
                                result[ 3 ],\n
                                line\n
                                ]);\n
\n
                            src = src.substring( result[1].length + result[2].length + result[3].length );\n
                            heredoc = undefined;\n
                        }\n
\n
                        if (result === null) {\n
                            throw Error("sup");\n
                        }\n
\n
\n
                    } else {\n
                        cancel =  tokens.some(function( token ){\n
                            if ( token.afterWhitespace === true ) {\n
                                var last = results[ results.length - 1 ];\n
                                if ( !Array.isArray( last ) || (last[ 0 ] !== PHP.Constants.T_WHITESPACE && last[ 0 ] !== PHP.Constants.T_OPEN_TAG  && last[ 0 ] !== PHP.Constants.T_COMMENT)) {\n
                                    return false;\n
                                }\n
                            }\n
                            var result = src.match( token.re );\n
\n
                            if ( result !== null ) {\n
                                if ( token.value !== -1) {\n
                                    var resultString = result[ 0 ];\n
\n
\n
\n
                                    if (token.func !== undefined ) {\n
                                        resultString = token.func( resultString, token );\n
                                    }\n
                                    if (resultString !== undefined ) {\n
\n
                                        results.push([\n
                                            parseInt(token.value, 10),\n
                                            resultString,\n
                                            line\n
                                            ]);\n
                                        line += resultString.split(\'\\n\').length - 1;\n
                                    }\n
\n
                                } else {\n
                                    results.push( result[ 0 ] );\n
                                }\n
\n
                                src = src.substring(result[ 0 ].length);\n
\n
                                return true;\n
                            }\n
                            return false;\n
\n
\n
                        });\n
                    }\n
\n
                } else {\n
\n
                    var result = openTag.exec( src );\n
\n
\n
                    if ( result !== null ) {\n
                        if ( result.index > 0 ) {\n
                            var resultString = src.substring(0, result.index);\n
                            results.push ([\n
                                parseInt(PHP.Constants.T_INLINE_HTML, 10),\n
                                resultString,\n
                                line\n
                                ]);\n
\n
                            line += resultString.split(\'\\n\').length - 1;\n
\n
                            src = src.substring( result.index );\n
                        }\n
\n
                        insidePHP = true;\n
                    } else {\n
\n
                        results.push ([\n
                            parseInt(PHP.Constants.T_INLINE_HTML, 10),\n
                            src.replace(/^\\n/, ""),\n
                            line\n
                            ]);\n
                        return results;\n
                    }\n
\n
                }\n
\n
\n
\n
            }\n
\n
\n
\n
            return results;\n
\n
\n
\n
        };\n
\n
\n
PHP.Parser = function ( preprocessedTokens, eval ) {\n
\n
    var yybase = this.yybase,\n
    yydefault = this.yydefault,\n
    yycheck = this.yycheck,\n
    yyaction = this.yyaction,\n
    yylen = this.yylen,\n
    yygbase = this.yygbase,\n
    yygcheck = this.yygcheck,\n
    yyp = this.yyp,\n
    yygoto = this.yygoto,\n
    yylhs = this.yylhs,\n
    terminals = this.terminals,\n
    translate = this.translate,\n
    yygdefault = this.yygdefault;\n
\n
\n
    this.pos = -1;\n
    this.line = 1;\n
\n
    this.tokenMap = this.createTokenMap( );\n
\n
    this.dropTokens = {};\n
    this.dropTokens[ PHP.Constants.T_WHITESPACE ] = 1;\n
    this.dropTokens[ PHP.Constants.T_OPEN_TAG ] = 1;\n
    var tokens = [];\n
    preprocessedTokens.forEach( function( token, index ) {\n
        if ( typeof token === "object" && token[ 0 ] === PHP.Constants.T_OPEN_TAG_WITH_ECHO) {\n
            tokens.push([\n
                PHP.Constants.T_OPEN_TAG,\n
                token[ 1 ],\n
                token[ 2 ]\n
                ]);\n
            tokens.push([\n
                PHP.Constants.T_ECHO,\n
                token[ 1 ],\n
                token[ 2 ]\n
                ]);\n
        } else {\n
            tokens.push( token );\n
        }\n
    });\n
    this.tokens = tokens;\n
    var tokenId = this.TOKEN_NONE;\n
    this.startAttributes = {\n
        \'startLine\': 1\n
    };\n
\n
    this.endAttributes = {};\n
    var attributeStack = [ this.startAttributes ];\n
    var state = 0;\n
    var stateStack = [ state ];\n
    this.yyastk = [];\n
    this.stackPos  = 0;\n
\n
    var yyn;\n
\n
    var origTokenId;\n
\n
\n
    for (;;) {\n
\n
        if ( yybase[ state ] === 0 ) {\n
            yyn = yydefault[ state ];\n
        } else {\n
            if (tokenId === this.TOKEN_NONE ) {\n
                origTokenId = this.getNextToken( );\n
                tokenId = (origTokenId >= 0 && origTokenId < this.TOKEN_MAP_SIZE) ? translate[ origTokenId ] : this.TOKEN_INVALID;\n
\n
                attributeStack[ this.stackPos ] = this.startAttributes;\n
            }\n
\n
            if (((yyn = yybase[ state ] + tokenId) >= 0\n
                && yyn < this.YYLAST && yycheck[ yyn ] === tokenId\n
                || (state < this.YY2TBLSTATE\n
                    && (yyn = yybase[state + this.YYNLSTATES] + tokenId) >= 0\n
                    && yyn < this.YYLAST\n
                    && yycheck[ yyn ] === tokenId))\n
            && (yyn = yyaction[ yyn ]) !== this.YYDEFAULT ) {\n
                if (yyn > 0) {\n
                    ++this.stackPos;\n
\n
                    stateStack[ this.stackPos ] = state = yyn;\n
                    this.yyastk[ this.stackPos ] = this.tokenValue;\n
                    attributeStack[ this.stackPos ] = this.startAttributes;\n
                    tokenId = this.TOKEN_NONE;\n
\n
                    if (yyn < this.YYNLSTATES)\n
                        continue;\n
                    yyn -= this.YYNLSTATES;\n
                } else {\n
                    yyn = -yyn;\n
                }\n
            } else {\n
                yyn = yydefault[ state ];\n
            }\n
        }\n
\n
        for (;;) {\n
\n
            if ( yyn === 0 ) {\n
                return this.yyval;\n
            } else if (yyn !== this.YYUNEXPECTED ) {\n
                for (var attr in this.endAttributes) {\n
                    attributeStack[ this.stackPos - yylen[ yyn ] ][ attr ] = this.endAttributes[ attr ];\n
                }\n
                try {\n
                    this[\'yyn\' + yyn](attributeStack[ this.stackPos - yylen[ yyn ] ]);\n
                } catch (e) {\n
                    throw e;\n
                }\n
                this.stackPos -= yylen[ yyn ];\n
                yyn = yylhs[ yyn ];\n
                if ((yyp = yygbase[ yyn ] + stateStack[ this.stackPos ]) >= 0\n
                    && yyp < this.YYGLAST\n
                    && yygcheck[ yyp ] === yyn) {\n
                    state = yygoto[ yyp ];\n
                } else {\n
                    state = yygdefault[ yyn ];\n
                }\n
\n
                ++this.stackPos;\n
\n
                stateStack[ this.stackPos ] = state;\n
                this.yyastk[ this.stackPos ] = this.yyval;\n
                attributeStack[ this.stackPos ] = this.startAttributes;\n
            } else {\n
                if (eval !== true) {\n
\n
                    var expected = [];\n
\n
                    for (var i = 0; i < this.TOKEN_MAP_SIZE; ++i) {\n
                        if ((yyn = yybase[ state ] + i) >= 0 && yyn < this.YYLAST && yycheck[ yyn ] == i\n
                         || state < this.YY2TBLSTATE\n
                            && (yyn = yybase[ state + this.YYNLSTATES] + i)\n
                            && yyn < this.YYLAST && yycheck[ yyn ] == i\n
                        ) {\n
                            if (yyaction[ yyn ] != this.YYUNEXPECTED) {\n
                                if (expected.length == 4) {\n
                                    expected = [];\n
                                    break;\n
                                }\n
\n
                                expected.push( this.terminals[ i ] );\n
                            }\n
                        }\n
                    }\n
\n
                    var expectedString = \'\';\n
                    if (expected.length) {\n
                        expectedString = \', expecting \' + expected.join(\' or \');\n
                    }\n
                    throw new PHP.ParseError(\'syntax error, unexpected \' + terminals[ tokenId ] + expectedString, this.startAttributes[\'startLine\']);\n
                } else {\n
                    return this.startAttributes[\'startLine\'];\n
                }\n
\n
            }\n
\n
            if (state < this.YYNLSTATES)\n
                break;\n
            yyn = state - this.YYNLSTATES;\n
        }\n
    }\n
};\n
\n
PHP.ParseError = function( msg, line ) {\n
    this.message = msg;\n
    this.line = line;\n
};\n
\n
PHP.Parser.prototype.MODIFIER_PUBLIC    =  1;\n
PHP.Parser.prototype.MODIFIER_PROTECTED =  2;\n
PHP.Parser.prototype.MODIFIER_PRIVATE   =  4;\n
PHP.Parser.prototype.MODIFIER_STATIC    =  8;\n
PHP.Parser.prototype.MODIFIER_ABSTRACT  = 16;\n
PHP.Parser.prototype.MODIFIER_FINAL     = 32;\n
\n
PHP.Parser.prototype.getNextToken = function( ) {\n
\n
    this.startAttributes = {};\n
    this.endAttributes = {};\n
\n
    var token,\n
    tmp;\n
\n
    while (this.tokens[++this.pos] !== undefined) {\n
        token = this.tokens[this.pos];\n
\n
        if (typeof token === "string") {\n
            this.startAttributes[\'startLine\'] = this.line;\n
            this.endAttributes[\'endLine\'] = this.line;\n
            if (\'b"\' === token) {\n
                this.tokenValue = \'b"\';\n
                return \'"\'.charCodeAt(0);\n
            } else {\n
                this.tokenValue = token;\n
                return token.charCodeAt(0);\n
            }\n
        } else {\n
\n
\n
\n
            this.line += ((tmp = token[ 1 ].match(/\\n/g)) === null) ? 0 : tmp.length;\n
\n
            if (PHP.Constants.T_COMMENT === token[0]) {\n
\n
                if (!Array.isArray(this.startAttributes[\'comments\'])) {\n
                    this.startAttributes[\'comments\'] = [];\n
                }\n
\n
                this.startAttributes[\'comments\'].push( {\n
                    type: "comment",\n
                    comment: token[1],\n
                    line: token[2]\n
                });\n
\n
            } else if (PHP.Constants.T_DOC_COMMENT === token[0]) {\n
                this.startAttributes[\'comments\'].push( new PHPParser_Comment_Doc(token[1], token[2]) );\n
            } else if (this.dropTokens[token[0]] === undefined) {\n
                this.tokenValue = token[1];\n
                this.startAttributes[\'startLine\'] = token[2];\n
                this.endAttributes[\'endLine\'] = this.line;\n
\n
                return this.tokenMap[token[0]];\n
            }\n
        }\n
    }\n
\n
    this.startAttributes[\'startLine\'] = this.line;\n
    return 0;\n
};\n
\n
PHP.Parser.prototype.tokenName = function( token ) {\n
    var constants = ["T_INCLUDE","T_INCLUDE_ONCE","T_EVAL","T_REQUIRE","T_REQUIRE_ONCE","T_LOGICAL_OR","T_LOGICAL_XOR","T_LOGICAL_AND","T_PRINT","T_PLUS_EQUAL","T_MINUS_EQUAL","T_MUL_EQUAL","T_DIV_EQUAL","T_CONCAT_EQUAL","T_MOD_EQUAL","T_AND_EQUAL","T_OR_EQUAL","T_XOR_EQUAL","T_SL_EQUAL","T_SR_EQUAL","T_BOOLEAN_OR","T_BOOLEAN_AND","T_IS_EQUAL","T_IS_NOT_EQUAL","T_IS_IDENTICAL","T_IS_NOT_IDENTICAL","T_IS_SMALLER_OR_EQUAL","T_IS_GREATER_OR_EQUAL","T_SL","T_SR","T_INSTANCEOF","T_INC","T_DEC","T_INT_CAST","T_DOUBLE_CAST","T_STRING_CAST","T_ARRAY_CAST","T_OBJECT_CAST","T_BOOL_CAST","T_UNSET_CAST","T_NEW","T_CLONE","T_EXIT","T_IF","T_ELSEIF","T_ELSE","T_ENDIF","T_LNUMBER","T_DNUMBER","T_STRING","T_STRING_VARNAME","T_VARIABLE","T_NUM_STRING","T_INLINE_HTML","T_CHARACTER","T_BAD_CHARACTER","T_ENCAPSED_AND_WHITESPACE","T_CONSTANT_ENCAPSED_STRING","T_ECHO","T_DO","T_WHILE","T_ENDWHILE","T_FOR","T_ENDFOR","T_FOREACH","T_ENDFOREACH","T_DECLARE","T_ENDDECLARE","T_AS","T_SWITCH","T_ENDSWITCH","T_CASE","T_DEFAULT","T_BREAK","T_CONTINUE","T_GOTO","T_FUNCTION","T_CONST","T_RETURN","T_TRY","T_CATCH","T_THROW","T_USE","T_INSTEADOF","T_GLOBAL","T_STATIC","T_ABSTRACT","T_FINAL","T_PRIVATE","T_PROTECTED","T_PUBLIC","T_VAR","T_UNSET","T_ISSET","T_EMPTY","T_HALT_COMPILER","T_CLASS","T_TRAIT","T_INTERFACE","T_EXTENDS","T_IMPLEMENTS","T_OBJECT_OPERATOR","T_DOUBLE_ARROW","T_LIST","T_ARRAY","T_CALLABLE","T_CLASS_C","T_TRAIT_C","T_METHOD_C","T_FUNC_C","T_LINE","T_FILE","T_COMMENT","T_DOC_COMMENT","T_OPEN_TAG","T_OPEN_TAG_WITH_ECHO","T_CLOSE_TAG","T_WHITESPACE","T_START_HEREDOC","T_END_HEREDOC","T_DOLLAR_OPEN_CURLY_BRACES","T_CURLY_OPEN","T_PAAMAYIM_NEKUDOTAYIM","T_DOUBLE_COLON","T_NAMESPACE","T_NS_C","T_DIR","T_NS_SEPARATOR"];\n
    var current = "UNKNOWN";\n
    constants.some(function( constant ) {\n
        if (PHP.Constants[ constan

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

t ] === token) {\n
            current = constant;\n
            return true;\n
        } else {\n
            return false;\n
        }\n
    });\n
\n
    return current;\n
};\n
\n
PHP.Parser.prototype.createTokenMap = function() {\n
    var tokenMap = {},\n
    name,\n
    i;\n
    var T_DOUBLE_COLON = PHP.Constants.T_PAAMAYIM_NEKUDOTAYIM;\n
    for ( i = 256; i < 1000; ++i ) {\n
        if ( T_DOUBLE_COLON === i ) {\n
            tokenMap[ i ] = this.T_PAAMAYIM_NEKUDOTAYIM;\n
        } else if( PHP.Constants.T_OPEN_TAG_WITH_ECHO === i ) {\n
            tokenMap[ i ] = PHP.Constants.T_ECHO;\n
        } else if( PHP.Constants.T_CLOSE_TAG === i ) {\n
            tokenMap[ i ] = 59;\n
        } else if ( \'UNKNOWN\' !== (name = this.tokenName( i ) ) ) { \n
            tokenMap[ i ] =  this[name];\n
        }\n
    }\n
    return tokenMap;\n
};\n
\n
var yynStandard = function () {\n
    this.yyval =  this.yyastk[ this.stackPos-(1-1) ];\n
};\n
\n
PHP.Parser.prototype.MakeArray = function( arr ) {\n
    return Array.isArray( arr ) ? arr : [ arr ];\n
}\n
\n
\n
PHP.Parser.prototype.parseString = function( str ) {\n
    var bLength = 0;\n
    if (\'b\' === str[0]) {\n
        bLength = 1;\n
    }\n
\n
    if (\'\\\'\' === str[ bLength ]) {\n
        str = str.replace(\n
            [\'\\\\\\\\\', \'\\\\\\\'\'],\n
            [  \'\\\\\',   \'\\\'\']);\n
    } else {\n
\n
        str = this.parseEscapeSequences( str, \'"\');\n
\n
    }\n
\n
    return str;\n
\n
};\n
\n
PHP.Parser.prototype.parseEscapeSequences = function( str, quote ) {\n
\n
\n
\n
    if (undefined !== quote) {\n
        str = str.replace(new RegExp(\'\\\\\' + quote, "g"), quote);\n
    }\n
\n
    var replacements = {\n
        \'\\\\\': \'\\\\\',\n
        \'$\':  \'$\',\n
        \'n\': "\\n",\n
        \'r\': "\\r",\n
        \'t\': "\\t",\n
        \'f\': "\\f",\n
        \'v\': "\\v",\n
        \'e\': "\\x1B"\n
    };\n
\n
    return str.replace(\n
        /~\\\\\\\\([\\\\\\\\$nrtfve]|[xX][0-9a-fA-F]{1,2}|[0-7]{1,3})~/g,\n
        function ( matches ){\n
            var str = matches[1];\n
\n
            if ( replacements[ str ] !== undefined ) {\n
                return replacements[ str ];\n
            } else if (\'x\' === str[ 0 ] || \'X\' === str[ 0 ]) {\n
                return chr(hexdec(str));\n
            } else {\n
                return chr(octdec(str));\n
            }\n
        }\n
        );\n
\n
    return str;\n
};\n
\n
PHP.Parser.prototype.TOKEN_NONE    = -1;\n
PHP.Parser.prototype.TOKEN_INVALID = 149;\n
\n
PHP.Parser.prototype.TOKEN_MAP_SIZE = 384;\n
\n
PHP.Parser.prototype.YYLAST       = 913;\n
PHP.Parser.prototype.YY2TBLSTATE  = 328;\n
PHP.Parser.prototype.YYGLAST      = 415;\n
PHP.Parser.prototype.YYNLSTATES   = 544;\n
PHP.Parser.prototype.YYUNEXPECTED = 32767;\n
PHP.Parser.prototype.YYDEFAULT    = -32766;\n
PHP.Parser.prototype.YYERRTOK = 256;\n
PHP.Parser.prototype.T_INCLUDE = 257;\n
PHP.Parser.prototype.T_INCLUDE_ONCE = 258;\n
PHP.Parser.prototype.T_EVAL = 259;\n
PHP.Parser.prototype.T_REQUIRE = 260;\n
PHP.Parser.prototype.T_REQUIRE_ONCE = 261;\n
PHP.Parser.prototype.T_LOGICAL_OR = 262;\n
PHP.Parser.prototype.T_LOGICAL_XOR = 263;\n
PHP.Parser.prototype.T_LOGICAL_AND = 264;\n
PHP.Parser.prototype.T_PRINT = 265;\n
PHP.Parser.prototype.T_PLUS_EQUAL = 266;\n
PHP.Parser.prototype.T_MINUS_EQUAL = 267;\n
PHP.Parser.prototype.T_MUL_EQUAL = 268;\n
PHP.Parser.prototype.T_DIV_EQUAL = 269;\n
PHP.Parser.prototype.T_CONCAT_EQUAL = 270;\n
PHP.Parser.prototype.T_MOD_EQUAL = 271;\n
PHP.Parser.prototype.T_AND_EQUAL = 272;\n
PHP.Parser.prototype.T_OR_EQUAL = 273;\n
PHP.Parser.prototype.T_XOR_EQUAL = 274;\n
PHP.Parser.prototype.T_SL_EQUAL = 275;\n
PHP.Parser.prototype.T_SR_EQUAL = 276;\n
PHP.Parser.prototype.T_BOOLEAN_OR = 277;\n
PHP.Parser.prototype.T_BOOLEAN_AND = 278;\n
PHP.Parser.prototype.T_IS_EQUAL = 279;\n
PHP.Parser.prototype.T_IS_NOT_EQUAL = 280;\n
PHP.Parser.prototype.T_IS_IDENTICAL = 281;\n
PHP.Parser.prototype.T_IS_NOT_IDENTICAL = 282;\n
PHP.Parser.prototype.T_IS_SMALLER_OR_EQUAL = 283;\n
PHP.Parser.prototype.T_IS_GREATER_OR_EQUAL = 284;\n
PHP.Parser.prototype.T_SL = 285;\n
PHP.Parser.prototype.T_SR = 286;\n
PHP.Parser.prototype.T_INSTANCEOF = 287;\n
PHP.Parser.prototype.T_INC = 288;\n
PHP.Parser.prototype.T_DEC = 289;\n
PHP.Parser.prototype.T_INT_CAST = 290;\n
PHP.Parser.prototype.T_DOUBLE_CAST = 291;\n
PHP.Parser.prototype.T_STRING_CAST = 292;\n
PHP.Parser.prototype.T_ARRAY_CAST = 293;\n
PHP.Parser.prototype.T_OBJECT_CAST = 294;\n
PHP.Parser.prototype.T_BOOL_CAST = 295;\n
PHP.Parser.prototype.T_UNSET_CAST = 296;\n
PHP.Parser.prototype.T_NEW = 297;\n
PHP.Parser.prototype.T_CLONE = 298;\n
PHP.Parser.prototype.T_EXIT = 299;\n
PHP.Parser.prototype.T_IF = 300;\n
PHP.Parser.prototype.T_ELSEIF = 301;\n
PHP.Parser.prototype.T_ELSE = 302;\n
PHP.Parser.prototype.T_ENDIF = 303;\n
PHP.Parser.prototype.T_LNUMBER = 304;\n
PHP.Parser.prototype.T_DNUMBER = 305;\n
PHP.Parser.prototype.T_STRING = 306;\n
PHP.Parser.prototype.T_STRING_VARNAME = 307;\n
PHP.Parser.prototype.T_VARIABLE = 308;\n
PHP.Parser.prototype.T_NUM_STRING = 309;\n
PHP.Parser.prototype.T_INLINE_HTML = 310;\n
PHP.Parser.prototype.T_CHARACTER = 311;\n
PHP.Parser.prototype.T_BAD_CHARACTER = 312;\n
PHP.Parser.prototype.T_ENCAPSED_AND_WHITESPACE = 313;\n
PHP.Parser.prototype.T_CONSTANT_ENCAPSED_STRING = 314;\n
PHP.Parser.prototype.T_ECHO = 315;\n
PHP.Parser.prototype.T_DO = 316;\n
PHP.Parser.prototype.T_WHILE = 317;\n
PHP.Parser.prototype.T_ENDWHILE = 318;\n
PHP.Parser.prototype.T_FOR = 319;\n
PHP.Parser.prototype.T_ENDFOR = 320;\n
PHP.Parser.prototype.T_FOREACH = 321;\n
PHP.Parser.prototype.T_ENDFOREACH = 322;\n
PHP.Parser.prototype.T_DECLARE = 323;\n
PHP.Parser.prototype.T_ENDDECLARE = 324;\n
PHP.Parser.prototype.T_AS = 325;\n
PHP.Parser.prototype.T_SWITCH = 326;\n
PHP.Parser.prototype.T_ENDSWITCH = 327;\n
PHP.Parser.prototype.T_CASE = 328;\n
PHP.Parser.prototype.T_DEFAULT = 329;\n
PHP.Parser.prototype.T_BREAK = 330;\n
PHP.Parser.prototype.T_CONTINUE = 331;\n
PHP.Parser.prototype.T_GOTO = 332;\n
PHP.Parser.prototype.T_FUNCTION = 333;\n
PHP.Parser.prototype.T_CONST = 334;\n
PHP.Parser.prototype.T_RETURN = 335;\n
PHP.Parser.prototype.T_TRY = 336;\n
PHP.Parser.prototype.T_CATCH = 337;\n
PHP.Parser.prototype.T_THROW = 338;\n
PHP.Parser.prototype.T_USE = 339;\n
PHP.Parser.prototype.T_INSTEADOF = 340;\n
PHP.Parser.prototype.T_GLOBAL = 341;\n
PHP.Parser.prototype.T_STATIC = 342;\n
PHP.Parser.prototype.T_ABSTRACT = 343;\n
PHP.Parser.prototype.T_FINAL = 344;\n
PHP.Parser.prototype.T_PRIVATE = 345;\n
PHP.Parser.prototype.T_PROTECTED = 346;\n
PHP.Parser.prototype.T_PUBLIC = 347;\n
PHP.Parser.prototype.T_VAR = 348;\n
PHP.Parser.prototype.T_UNSET = 349;\n
PHP.Parser.prototype.T_ISSET = 350;\n
PHP.Parser.prototype.T_EMPTY = 351;\n
PHP.Parser.prototype.T_HALT_COMPILER = 352;\n
PHP.Parser.prototype.T_CLASS = 353;\n
PHP.Parser.prototype.T_TRAIT = 354;\n
PHP.Parser.prototype.T_INTERFACE = 355;\n
PHP.Parser.prototype.T_EXTENDS = 356;\n
PHP.Parser.prototype.T_IMPLEMENTS = 357;\n
PHP.Parser.prototype.T_OBJECT_OPERATOR = 358;\n
PHP.Parser.prototype.T_DOUBLE_ARROW = 359;\n
PHP.Parser.prototype.T_LIST = 360;\n
PHP.Parser.prototype.T_ARRAY = 361;\n
PHP.Parser.prototype.T_CALLABLE = 362;\n
PHP.Parser.prototype.T_CLASS_C = 363;\n
PHP.Parser.prototype.T_TRAIT_C = 364;\n
PHP.Parser.prototype.T_METHOD_C = 365;\n
PHP.Parser.prototype.T_FUNC_C = 366;\n
PHP.Parser.prototype.T_LINE = 367;\n
PHP.Parser.prototype.T_FILE = 368;\n
PHP.Parser.prototype.T_COMMENT = 369;\n
PHP.Parser.prototype.T_DOC_COMMENT = 370;\n
PHP.Parser.prototype.T_OPEN_TAG = 371;\n
PHP.Parser.prototype.T_OPEN_TAG_WITH_ECHO = 372;\n
PHP.Parser.prototype.T_CLOSE_TAG = 373;\n
PHP.Parser.prototype.T_WHITESPACE = 374;\n
PHP.Parser.prototype.T_START_HEREDOC = 375;\n
PHP.Parser.prototype.T_END_HEREDOC = 376;\n
PHP.Parser.prototype.T_DOLLAR_OPEN_CURLY_BRACES = 377;\n
PHP.Parser.prototype.T_CURLY_OPEN = 378;\n
PHP.Parser.prototype.T_PAAMAYIM_NEKUDOTAYIM = 379;\n
PHP.Parser.prototype.T_NAMESPACE = 380;\n
PHP.Parser.prototype.T_NS_C = 381;\n
PHP.Parser.prototype.T_DIR = 382;\n
PHP.Parser.prototype.T_NS_SEPARATOR = 383;\n
PHP.Parser.prototype.terminals = [\n
    "$EOF",\n
    "error",\n
    "T_INCLUDE",\n
    "T_INCLUDE_ONCE",\n
    "T_EVAL",\n
    "T_REQUIRE",\n
    "T_REQUIRE_ONCE",\n
    "\',\'",\n
    "T_LOGICAL_OR",\n
    "T_LOGICAL_XOR",\n
    "T_LOGICAL_AND",\n
    "T_PRINT",\n
    "\'=\'",\n
    "T_PLUS_EQUAL",\n
    "T_MINUS_EQUAL",\n
    "T_MUL_EQUAL",\n
    "T_DIV_EQUAL",\n
    "T_CONCAT_EQUAL",\n
    "T_MOD_EQUAL",\n
    "T_AND_EQUAL",\n
    "T_OR_EQUAL",\n
    "T_XOR_EQUAL",\n
    "T_SL_EQUAL",\n
    "T_SR_EQUAL",\n
    "\'?\'",\n
    "\':\'",\n
    "T_BOOLEAN_OR",\n
    "T_BOOLEAN_AND",\n
    "\'|\'",\n
    "\'^\'",\n
    "\'&\'",\n
    "T_IS_EQUAL",\n
    "T_IS_NOT_EQUAL",\n
    "T_IS_IDENTICAL",\n
    "T_IS_NOT_IDENTICAL",\n
    "\'<\'",\n
    "T_IS_SMALLER_OR_EQUAL",\n
    "\'>\'",\n
    "T_IS_GREATER_OR_EQUAL",\n
    "T_SL",\n
    "T_SR",\n
    "\'+\'",\n
    "\'-\'",\n
    "\'.\'",\n
    "\'*\'",\n
    "\'/\'",\n
    "\'%\'",\n
    "\'!\'",\n
    "T_INSTANCEOF",\n
    "\'~\'",\n
    "T_INC",\n
    "T_DEC",\n
    "T_INT_CAST",\n
    "T_DOUBLE_CAST",\n
    "T_STRING_CAST",\n
    "T_ARRAY_CAST",\n
    "T_OBJECT_CAST",\n
    "T_BOOL_CAST",\n
    "T_UNSET_CAST",\n
    "\'@\'",\n
    "\'[\'",\n
    "T_NEW",\n
    "T_CLONE",\n
    "T_EXIT",\n
    "T_IF",\n
    "T_ELSEIF",\n
    "T_ELSE",\n
    "T_ENDIF",\n
    "T_LNUMBER",\n
    "T_DNUMBER",\n
    "T_STRING",\n
    "T_STRING_VARNAME",\n
    "T_VARIABLE",\n
    "T_NUM_STRING",\n
    "T_INLINE_HTML",\n
    "T_ENCAPSED_AND_WHITESPACE",\n
    "T_CONSTANT_ENCAPSED_STRING",\n
    "T_ECHO",\n
    "T_DO",\n
    "T_WHILE",\n
    "T_ENDWHILE",\n
    "T_FOR",\n
    "T_ENDFOR",\n
    "T_FOREACH",\n
    "T_ENDFOREACH",\n
    "T_DECLARE",\n
    "T_ENDDECLARE",\n
    "T_AS",\n
    "T_SWITCH",\n
    "T_ENDSWITCH",\n
    "T_CASE",\n
    "T_DEFAULT",\n
    "T_BREAK",\n
    "T_CONTINUE",\n
    "T_GOTO",\n
    "T_FUNCTION",\n
    "T_CONST",\n
    "T_RETURN",\n
    "T_TRY",\n
    "T_CATCH",\n
    "T_THROW",\n
    "T_USE",\n
    "T_INSTEADOF",\n
    "T_GLOBAL",\n
    "T_STATIC",\n
    "T_ABSTRACT",\n
    "T_FINAL",\n
    "T_PRIVATE",\n
    "T_PROTECTED",\n
    "T_PUBLIC",\n
    "T_VAR",\n
    "T_UNSET",\n
    "T_ISSET",\n
    "T_EMPTY",\n
    "T_HALT_COMPILER",\n
    "T_CLASS",\n
    "T_TRAIT",\n
    "T_INTERFACE",\n
    "T_EXTENDS",\n
    "T_IMPLEMENTS",\n
    "T_OBJECT_OPERATOR",\n
    "T_DOUBLE_ARROW",\n
    "T_LIST",\n
    "T_ARRAY",\n
    "T_CALLABLE",\n
    "T_CLASS_C",\n
    "T_TRAIT_C",\n
    "T_METHOD_C",\n
    "T_FUNC_C",\n
    "T_LINE",\n
    "T_FILE",\n
    "T_START_HEREDOC",\n
    "T_END_HEREDOC",\n
    "T_DOLLAR_OPEN_CURLY_BRACES",\n
    "T_CURLY_OPEN",\n
    "T_PAAMAYIM_NEKUDOTAYIM",\n
    "T_NAMESPACE",\n
    "T_NS_C",\n
    "T_DIR",\n
    "T_NS_SEPARATOR",\n
    "\';\'",\n
    "\'{\'",\n
    "\'}\'",\n
    "\'(\'",\n
    "\')\'",\n
    "\'$\'",\n
    "\']\'",\n
    "\'`\'",\n
    "\'\\"\'"\n
    , "???"\n
];\n
PHP.Parser.prototype.translate = [\n
        0,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,   47,  148,  149,  145,   46,   30,  149,\n
      143,  144,   44,   41,    7,   42,   43,   45,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,   25,  140,\n
       35,   12,   37,   24,   59,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,   60,  149,  146,   29,  149,  147,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  141,   28,  142,   49,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,  149,  149,  149,  149,\n
      149,  149,  149,  149,  149,  149,    1,    2,    3,    4,\n
        5,    6,    8,    9,   10,   11,   13,   14,   15,   16,\n
       17,   18,   19,   20,   21,   22,   23,   26,   27,   31,\n
       32,   33,   34,   36,   38,   39,   40,   48,   50,   51,\n
       52,   53,   54,   55,   56,   57,   58,   61,   62,   63,\n
       64,   65,   66,   67,   68,   69,   70,   71,   72,   73,\n
       74,  149,  149,   75,   76,   77,   78,   79,   80,   81,\n
       82,   83,   84,   85,   86,   87,   88,   89,   90,   91,\n
       92,   93,   94,   95,   96,   97,   98,   99,  100,  101,\n
      102,  103,  104,  105,  106,  107,  108,  109,  110,  111,\n
      112,  113,  114,  115,  116,  117,  118,  119,  120,  121,\n
      122,  123,  124,  125,  126,  127,  128,  129,  130,  149,\n
      149,  149,  149,  149,  149,  131,  132,  133,  134,  135,\n
      136,  137,  138,  139\n
];\n
\n
PHP.Parser.prototype.yyaction = [\n
       61,   62,  363,   63,   64,-32766,-32766,-32766,  509,   65,\n
      708,  709,  710,  707,  706,  705,-32766,-32766,-32766,-32766,\n
    -32766,-32766,  132,-32766,-32766,-32766,-32766,-32766,-32767,-32767,\n
    -32767,-32767,-32766,  335,-32766,-32766,-32766,-32766,-32766,   66,\n
       67,  351,  663,  664,   40,   68,  548,   69,  232,  233,\n
       70,   71,   72,   73,   74,   75,   76,   77,   30,  246,\n
       78,  336,  364, -112,    0,  469,  833,  834,  365,  641,\n
      890,  436,  590,   41,  835,   53,   27,  366,  294,  367,\n
      687,  368,  921,  369,  923,  922,  370,-32766,-32766,-32766,\n
       42,   43,  371,  339,  126,   44,  372,  337,   79,  297,\n
      349,  292,  293,-32766,  918,-32766,-32766,  373,  374,  375,\n
      376,  377,  391,  199,  361,  338,  573,  613,  378,  379,\n
      380,  381,  845,  839,  840,  841,  842,  836,  837,  253,\n
    -32766,   87,   88,   89,  391,  843,  838,  338,  597,  519,\n
      128,   80,  129,  273,  332,  257,  261,   47,  673,   90,\n
       91,   92,   93,   94,   95,   96,   97,   98,   99,  100,\n
      101,  102,  103,  104,  105,  106,  107,  108,  109,  110,\n
      799,  247,  884,  108,  109,  110,  226,  247,   21,-32766,\n
      310,-32766,-32766,-32766,  642,  548,-32766,-32766,-32766,-32766,\n
       56,  353,-32766,-32766,-32766,   55,-32766,-32766,-32766,-32766,\n
    -32766,   58,-32766,-32766,-32766,-32766,-32766,-32766,-32766,-32766,\n
    -32766,  557,-32766,-32766,  518,-32766,  548,  890,-32766,  390,\n
    -32766,  228,  252,-32766,-32766,-32766,-32766,-32766,  275,-32766,\n
      234,-32766,  587,  588,-32766,-32766,-32766,-32766,-32766,-32766,\n
    -32766,   46,  236,-32766,-32766,  281,-32766,  682,  348,-32766,\n
      390,-32766,  346,  333,  521,-32766,-32766,-32766,  271,  911,\n
      262,  237,  446,  911,-32766,  894,   59,  700,  358,  135,\n
      548,  123,  538,   35,-32766,  333,  122,-32766,-32766,-32766,\n
      271,-32766,  124,-32766,  692,-32766,-32766,-32766,-32766,  700,\n
      273,   22,-32766,-32766,-32766,-32766,  239,-32766,-32766,  612,\n
    -32766,  548,  134,-32766,  390,-32766,  462,  354,-32766,-32766,\n
    -32766,-32766,-32766,  227,-32766,  238,-32766,  845,  542,-32766,\n
      856,  611,  200,-32766,-32766,-32766,  259,  280,-32766,-32766,\n
      201,-32766,  855,  129,-32766,  390,  130,  202,  333,  206,\n
    -32766,-32766,-32766,  271,-32766,-32766,-32766,  125,  601,-32766,\n
      136,  299,  700,  489,   28,  548,  105,  106,  107,-32766,\n
      498,  499,-32766,-32766,-32766,  207,-32766,  133,-32766,  525,\n
    -32766,-32766,-32766,-32766,  663,  664,  527,-32766,-32766,-32766,\n
    -32766,  528,-32766,-32766,  610,-32766,  548,  427,-32766,  390,\n
    -32766,  532,  539,-32766,-32766,-32766,-32766,-32766,  240,-32766,\n
      247,-32766,  697,  543,-32766,  554,  523,  608,-32766,-32766,\n
    -32766,  686,  535,-32766,-32766,   54,-32766,   57,   60,-32766,\n
      390,  246, -155,  278,  345,-32766,-32766,-32766,  506,  347,\n
     -152,  471,  402,  403,-32766,  405,  404,  272,  493,  416,\n
      548,  318,  417,  505,-32766,  517,  548,-32766,-32766,-32766,\n
      549,-32766,  562,-32766,  916,-32766,-32766,-32766,-32766,  564,\n
      826,  848,-32766,-32766,-32766,-32766,  694,-32766,-32766,  485,\n
    -32766,  548,  487,-32766,  390,-32766,  504,  802,-32766,-32766,\n
    -32766,-32766,-32766,  279,-32766,  911,-32766,  502,  492,-32766,\n
      413,  483,  269,-32766,-32766,-32766,  243,  337,-32766,-32766,\n
      418,-32766,  454,  229,-32766,  390,  274,  373,  374,  344,\n
    -32766,-32766,-32766,  360,  614,-32766,  573,  613,  378,  379,\n
     -274,  548,  615, -332,  844,-32766,  258,   51,-32766,-32766,\n
    -32766,  270,-32766,  346,-32766,   52,-32766,  260,    0,-32766,\n
     -333,-32766,-32766,-32766,-32766,-32766,-32766,  205,-32766,-32766,\n
       49,-32766,  548,  424,-32766,  390,-32766, -266,  264,-32766,\n
    -32766,-32766,-32766,-32766,  409,-32766,  343,-32766,  265,  312,\n
    -32766,  470,  513, -275,-32766,-32766,-32766,  920,  337,-32766,\n
    -32766,  530,-32766,  531,  600,-32766,  390,  592,  373,  374,\n
      578,  581,-32766,-32766,  644,  629,-32766,  573,  613,  378,\n
      379,  635,  548,  636,  576,  627,-32766,  625,  693,-32766,\n
    -32766,-32766,  691,-32766,  591,-32766,  582,-32766,  203,  204,\n
    -32766,  584,  583,-32766,-32766,-32766,-32766,  586,  599,-32766,\n
    -32766,  589,-32766,  690,  558,-32766,  390,  197,  683,  919,\n
       86,  520,  522,-32766,  524,  833,  834,  529,  533,-32766,\n
      534,  537,  541,  835,   48,  111,  112,  113,  114,  115,\n
      116,  117,  118,  119,  120,  121,  127,   31,  633,  337,\n
      330,  634,  585,-32766,   32,  291,  337,  330,  478,  373,\n
      374,  917,  291,  891,  889,  875,  373,  374,  553,  613,\n
      378,  379,  737,  739,  887,  553,  613,  378,  379,  824,\n
      451,  675,  839,  840,  841,  842,  836,  837,  320,  895,\n
      277,  885,   23,   33,  843,  838,  556,  277,  337,  330,\n
    -32766,   34,-32766,  555,  291,   36,   37,   38,  373,  374,\n
       39,   45,   50,   81,   82,   83,   84,  553,  613,  378,\n
      379,-32767,-32767,-32767,-32767,  103,  104,  105,  106,  107,\n
      337,   85,  131,  137,  337,  138,  198,  224,  225,  277,\n
      373,  374, -332,  230,  373,  374,   24,  337,  231,  573,\n
      613,  378,  379,  573,  613,  378,  379,  373,  374,  235,\n
      248,  249,  250,  337,  251,    0,  573,  613,  378,  379,\n
      276,  329,  331,  373,  374,-32766,  337,  574,  490,  792,\n
      337,  609,  573,  613,  378,  379,  373,  374,   25,  300,\n
      373,  374,  319,  337,  795,  573,  613,  378,  379,  573,\n
      613,  378,  379,  373,  374,  516,  355,  359,  445,  482,\n
      796,  507,  573,  613,  378,  379,  508,  548,  337,  890,\n
      775,  791,  337,  604,  803,  808,  806,  698,  373,  374,\n
      888,  807,  373,  374,-32766,-32766,-32766,  573,  613,  378,\n
      379,  573,  613,  378,  379,  873,  832,  804,  872,  851,\n
    -32766,  809,-32766,-32766,-32766,-32766,  805,   20,   26,   29,\n
      298,  480,  515,  770,  778,  827,  457,    0,  900,  455,\n
      774,    0,    0,    0,  874,  870,  886,  823,  915,  852,\n
      869,  488,    0,  391,  793,    0,  338,    0,    0,    0,\n
      340,    0,  273\n
];\n
\n
PHP.Parser.prototype.yycheck = [\n
        2,    3,    4,    5,    6,    8,    9,   10,   70,   11,\n
      104,  105,  106,  107,  108,  109,    8,    9,   10,    8,\n
        9,   24,   60,   26,   27,   28,   29,   30,   31,   32,\n
       33,   34,   24,    7,   26,   27,   28,   29,   30,   41,\n
       42,    7,  123,  124,    7,   47,   70,   49,   50,   51,\n
       52,   53,   54,   55,   56,   57,   58,   59,   60,   61,\n
       62,   63,   64,  144,    0,   75,   68,   69,   70,   25,\n
       72,   70,   74,    7,   76,   77,   78,   79,    7,   81,\n
      142,   83,   70,   85,   72,   73,   88,    8,    9,   10,\n
       92,   93,   94,   95,    7,   97,   98,   95,  100,    7,\n
        7,  103,  104,   24,  142,   26,   27,  105,  106,  111,\n
      112,  113,  136,    7,    7,  139,  114,  115,  116,  117,\n
      122,  123,  132,  125,  126,  127,  128,  129,  130,  131,\n
        8,    8,    9,   10,  136,  137,  138,  139,  140,  141,\n
       25,  143,  141,  145,  142,  147,  148,   24,   72,   26,\n
       27,   28,   29,   30,   31,   32,   33,   34,   35,   36,\n
       37,   38,   39,   40,   41,   42,   43,   44,   45,   46,\n
      144,   48,   72,   44,   45,   46,   30,   48,  144,   64,\n
       72,    8,    9,   10,  140,   70,    8,    9,   10,   74,\n
       60,   25,   77,   78,   79,   60,   81,   24,   83,   26,\n
       85,   60,   24,   88,   26,   27,   28,   92,   93,   94,\n
       64,  140,   97,   98,   70,  100,   70,   72,  103,  104,\n
       74,  145,    7,   77,   78,   79,  111,   81,    7,   83,\n
       30,   85,  140,  140,   88,    8,    9,   10,   92,   93,\n
       94,  133,  134,   97,   98,  145,  100,  140,    7,  103,\n
      104,   24,  139,   96,  141,  140,  141,  111,  101,   75,\n
       75,   30,   70,   75,   64,   70,   60,  110,  121,   12,\n
       70,  141,   25,  143,   74,   96,  141,   77,   78,   79,\n
      101,   81,  141,   83,  140,   85,  140,  141,   88,  110,\n
      145,  144,   92,   93,   94,   64,    7,   97,   98,  142,\n
      100,   70,  141,  103,  104,   74,  145,  141,   77,   78,\n
       79,  111,   81,    7,   83,   30,   85,  132,   25,   88,\n
      132,  142,   12,   92,   93,   94,  120,   60,   97,   98,\n
       12,  100,  148,  141,  103,  104,  141,   12,   96,   12,\n
      140,  141,  111,  101,    8,    9,   10,  141,   25,   64,\n
       90,   91,  110,   65,   66,   70,   41,   42,   43,   74,\n
       65,   66,   77,   78,   79,   12,   81,   25,   83,   25,\n
       85,  140,  141,   88,  123,  124,   25,   92,   93,   94,\n
       64,   25,   97,   98,  142,  100,   70,  120,  103,  104,\n
       74,   25,   25,   77,   78,   79,  111,   81,   30,   83,\n
       48,   85,  140,  141,   88,  140,  141,   30,   92,   93,\n
       94,  140,  141,   97,   98,   60,  100,   60,   60,  103,\n
      104,   61,   72,   75,   70,  140,  141,  111,   67,   70,\n
       87,   99,   70,   70,   64,   70,   72,  102,   89,   70,\n
       70,   71,   70,   70,   74,   70,   70,   77,   78,   79,\n
       70,   81,   70,   83,   70,   85,  140,  141,   88,   70,\n
      144,   70,   92,   93,   94,   64,   70,   97,   98,   72,\n
      100,   70,   72,  103,  104,   74,   72,   72,   77,   78,\n
       79,  111,   81,   75,   83,   75,   85,   89,   86,   88,\n
       79,  101,  118,   92,   93,   94,   87,   95,   97,   98,\n
       87,  100,   87,   87,  103,  104,  118,  105,  106,   95,\n
      140,  141,  111,   95,  115,   64,  114,  115,  116,  117,\n
      135,   70,  115,  120,  132,   74,  120,  140,   77,   78,\n
       79,  119,   81,  139,   83,  140,   85,  120,   -1,   88,\n
      120,  140,  141,   92,   93,   94,   64,  121,   97,   98,\n
      121,  100,   70,  122,  103,  104,   74,  135,  135,   77,\n
       78,   79,  111,   81,  139,   83,  139,   85,  135,  135,\n
       88,  135,  135,  135,   92,   93,   94,  142,   95,   97,\n
       98,  140,  100,  140,  140,  103,  104,  140,  105,  106,\n
      140,  140,  141,  111,  140,  140,   64,  114,  115,  116,\n
      117,  140,   70,  140,  140,  140,   74,  140,  140,   77,\n
       78,   79,  140,   81,  140,   83,  140,   85,   41,   42,\n
       88,  140,  140,  141,   92,   93,   94,  140,  140,   97,\n
       98,  140,  100,  140,  140,  103,  104,   60,  140,  142,\n
      141,  141,  141,  111,  141,   68,   69,  141,  141,   72,\n
      141,  141,  141,   76,   12,   13,   14,   15,   16,   17,\n
       18,   19,   20,   21,   22,   23,  141,  143,  142,   95,\n
       96,  142,  140,  141,  143,  101,   95,   96,  142,  105,\n
      106,  142,  101,  142,  142,  142,  105,  106,  114,  115,\n
      116,  117,   50,   51,  142,  114,  115,  116,  117,  142,\n
      123,  142,  125,  126,  127,  128,  129,  130,  131,  142,\n
      136,  142,  144,  143,  137,  138,  142,  136,   95,   96,\n
      143,  143,  145,  142,  101,  143,  143,  143,  105,  106,\n
      143,  143,  143,  143,  143,  143,  143,  114,  115,  116,\n
      117,   35,   36,   37,   38,   39,   40,   41,   42,   43,\n
       95,  143,  143,  143,   95,  143,  143,  143,  143,  136,\n
      105,  106,  120,  143,  105,  106,  144,   95,  143,  114,\n
      115,  116,  117,  114,  115,  116,  117,  105,  106,  143,\n
      143,  143,  143,   95,  143,   -1,  114,  115,  116,  117,\n
      143,  143,  143,  105,  106,  143,   95,  142,   80,  146,\n
       95,  142,  114,  115,  116,  117,  105,  106,  144,  144,\n
      105,  106,  144,   95,  142,  114,  115,  116,  117,  114,\n
      115,  116,  117,  105,  106,   82,  144,  144,  144,  144,\n
      142,   84,  114,  115,  116,  117,  144,   70,   95,   72,\n
      144,  144,   95,  142,  144,  146,  144,  142,  105,  106,\n
      146,  144,  105,  106,    8,    9,   10,  114,  115,  116,\n
      117,  114,  115,  116,  117,  144,  144,  144,  144,  144,\n
       24,  104,   26,   27,   28,   29,  144,  144,  144,  144,\n
      144,  144,  144,  144,  144,  144,  144,   -1,  144,  144,\n
      144,   -1,   -1,   -1,  146,  146,  146,  146,  146,  146,\n
      146,  146,   -1,  136,  147,   -1,  139,   -1,   -1,   -1,\n
      143,   -1,  145\n
];\n
\n
PHP.Parser.prototype.yybase = [\n
        0,  574,  581,  623,  655,    2,  718,  402,  747,  659,\n
      672,  688,  743,  701,  705,  483,  483,  483,  483,  483,\n
      351,  356,  366,  366,  367,  366,  344,   -2,   -2,   -2,\n
      200,  200,  231,  231,  231,  231,  231,  231,  231,  231,\n
      200,  231,  451,  482,  532,  316,  370,  115,  146,  285,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,  401,\n
      401,  401,  401,  401,  401,  401,  401,  401,  401,   44,\n
      474,  429,  476,  481,  487,  488,  739,  740,  741,  734,\n
      733,  416,  736,  539,  541,  342,  542,  543,  552,  557,\n
      559,  536,  567,  737,  755,  569,  735,  738,  123,  123,\n
      123,  123,  123,  123,  123,  123,  123,  122,   11,  336,\n
      336,  336,  336,  336,  336,  336,  336,  336,  336,  336,\n
      336,  336,  336,  336,  227,  227,  173,  577,  577,  577,\n
      577,  577,  577,  577,  577,  577,  577,  577,   79,  178,\n
      846,    8,   -3,   -3,   -3,   -3,  642,  706,  706,  706,\n
      706,  157,  179,  242,  431,  431,  360,  431,  525,  368,\n
      767,  767,  767,  767,  767,  767,  767,  767,  767,  767,\n
      767,  767,  350,  375,  315,  315,  652,  652,  -81,  -81,\n
      -81,  -81,  251,  185,  188,  184,  -62,  348,  195,  195,\n
      195,  408,  392,  410,    1,  192,  129,  129,  129,  -24,\n
      -24,  -24,  -24,  499,  -24,  -24,  -24,  113,  108,  108,\n
       12,  161,  349,  526,  271,  398,  529,  438,  130,  206,\n
      265,  427,   76,  414,  427,  288,  295,   76,  166,   44,\n
      262,  422,  141,  491,  372,  494,  413,   71,   92,   93,\n
      267,  135,  100,   34,  415,  745,  746,  742,  -38,  420,\n
      -10,  135,  147,  744,  498,  107,   26,  493,  144,  377,\n
      363,  369,  332,  363,  400,  377,  588,  377,  376,  377,\n
      360,   37,  582,  376,  377,  374,  376,  388,  363,  364,\n
      412,  369,  377,  441,  443,  390,  106,  332,  377,  390,\n
      377,  400,   64,  590,  591,  323,  592,  589,  593,  649,\n
      608,  362,  500,  399,  407,  620,  625,  636,  365,  354,\n
      614,  524,  425,  359,  355,  423,  570,  578,  357,  406,\n
      414,  394,  352,  403,  531,  433,  403,  653,  434,  385,\n
      417,  411,  444,  310,  318,  501,  425,  668,  757,  380,\n
      637,  684,  403,  609,  387,   87,  325,  638,  382,  403,\n
      639,  403,  696,  503,  615,  403,  697,  384,  435,  425,\n
      352,  352,  352,  700,   66,  699,  583,  702,  707,  704,\n
      748,  721,  749,  584,  750,  358,  583,  722,  751,  682,\n
      215,  613,  422,  436,  389,  447,  221,  257,  752,  403,\n
      403,  506,  499,  403,  395,  685,  397,  426,  753,  392,\n
      391,  647,  683,  403,  418,  754,  221,  723,  587,  724,\n
      450,  568,  507,  648,  509,  327,  725,  353,  497,  610,\n
      454,  622,  455,  461,  404,  510,  373,  732,  612,  247,\n
      361,  664,  463,  405,  692,  641,  464,  465,  511,  343,\n
      437,  335,  409,  396,  665,  293,  467,  468,  472,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,    0,    0,    0,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,   -2,\n
       -2,   -2,   -2,  123,  123,  123,  123,  123,  123,  123,\n
      123,  123,  123,  123,  123,  123,  123,  123,  123,  123,\n
      123,  123,  123,  123,  123,  123,  123,  123,  123,  123,\n
      123,  123,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,  123,  123,  123,  123,  123,  123,  123,  123,  123,\n
      123,  123,  123,  123,  123,  123,  123,  123,  123,  123,\n
      123,  767,  767,  767,  767,  767,  767,  767,  767,  767,\n
      767,  767,  123,  123,  123,  123,  123,  123,  123,  123,\n
        0,  129,  129,  129,  129,  -94,  -94,  -94,  767,  767,\n
      767,  767,  767,  767,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,  -94,  -94,  129,  129,\n
      767,  767,  -24,  -24,  -24,  -24,  -24,  108,  108,  108,\n
      -24,  108,  145,  145,  145,  108,  108,  108,  100,  100,\n
        0,    0,    0,    0,    0,    0,    0,  145,    0,    0,\n
        0,  376,    0,    0,    0,  145,  260,  260,  221,  260,\n
      260,  135,    0,    0,  425,  376,    0,  364,  376,    0,\n
        0,    0,    0,    0,    0,  531,    0,   87,  637,  241,\n
      425,    0,    0,    0,    0,    0,    0,    0,  425,  289,\n
      289,  306,    0,  358,    0,    0,    0,  306,  241,    0,\n
        0,  221\n
];\n
\n
PHP.Parser.prototype.yydefault = [\n
        3,32767,32767,    1,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,  104,   96,  110,   95,  106,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
      358,  358,  122,  122,  122,  122,  122,  122,  122,  122,\n
      316,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
      173,  173,  173,32767,  348,  348,  348,  348,  348,  348,\n
      348,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,  363,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,  232,  233,\n
      235,  236,  172,  125,  349,  362,  171,  199,  201,  250,\n
      200,  177,  182,  183,  184,  185,  186,  187,  188,  189,\n
      190,  191,  192,  176,  229,  228,  197,  313,  313,  316,\n
    32767,32767,32767,32767,32767,32767,32767,32767,  198,  202,\n
      204,  203,  219,  220,  217,  218,  175,  221,  222,  223,\n
      224,  157,  157,  157,  357,  357,32767,  357,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,  158,32767,  211,  212,  276,  276,  117,  117,\n
      117,  117,  117,32767,32767,32767,32767,  284,32767,32767,\n
    32767,32767,32767,  286,32767,32767,  206,  207,  205,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,  285,32767,\n
    32767,32767,32767,32767,32767,32767,32767,  334,  321,  272,\n
    32767,32767,32767,  265,32767,  107,  109,32767,32767,32767,\n
    32767,  302,  339,32767,32767,32767,   17,32767,32767,32767,\n
      370,  334,32767,32767,   19,32767,32767,32767,32767,  227,\n
    32767,  338,  332,32767,32767,32767,32767,32767,32767,   63,\n
    32767,32767,32767,32767,32767,   63,  281,   63,32767,   63,\n
    32767,  315,  287,32767,   63,   74,32767,   72,32767,32767,\n
       76,32767,   63,   93,   93,  254,  315,   54,   63,  254,\n
       63,32767,32767,32767,32767,    4,32767,32767,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,32767,  267,32767,  323,32767,  337,  336,  324,32767,\n
      265,32767,  215,  194,  266,32767,  196,32767,32767,  270,\n
      273,32767,32767,32767,  134,32767,  268,  180,32767,32767,\n
    32767,32767,  365,32767,32767,  174,32767,32767,32767,  130,\n
    32767,   61,  332,32767,32767,  355,32767,32767,  332,  269,\n
      208,  209,  210,32767,  121,32767,  310,32767,32767,32767,\n
    32767,32767,32767,  327,32767,  333,32767,32767,32767,32767,\n
      111,32767,  302,32767,32767,32767,   75,32767,32767,  178,\n
      126,32767,32767,  364,32767,32767,32767,  320,32767,32767,\n
    32767,32767,32767,   62,32767,32767,   77,32767,32767,32767,\n
    32767,  332,32767,32767,32767,  115,32767,  169,32767,32767,\n
    32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,\n
    32767,  332,32767,32767,32767,32767,32767,32767,32767,    4,\n
    32767,  151,32767,32767,32767,32767,32767,32767,32767,   25,\n
       25,    3,  137,    3,  137,   25,  101,   25,   25,  137,\n
       93,   93,   25,   25,   25,  144,   25,   25,   25,   25,\n
       25,   25,   25,   25\n
];\n
\n
PHP.Parser.prototype.yygoto = [\n
      141,  141,  173,  173,  173,  173,  173,  173,  173,  173,\n
      141,  173,  142,  143,  144,  148,  153,  155,  181,  175,\n
      172,  172,  172,  172,  174,  174,  174,  174,  174,  174,\n
      174,  168,  169,  170,  171,  179,  757,  758,  392,  760,\n
      781,  782,  783,  784,  785,  786,  787,  789,  725,  145,\n
      146,  147,  149,  150,  151,  152,  154,  177,  178,  180,\n
      196,  208,  209,  210,  211,  212,  213,  214,  215,  217,\n
      218,  219,  220,  244,  245,  266,  267,  268,  430,  431,\n
      432,  182,  183,  184,  185,  186,  187,  188,  189,  190,\n
      191,  192,  156,  157,  158,  159,  176,  160,  194,  161,\n
      162,  163,  164,  195,  165,  193,  139,  166,  167,  452,\n
      452,  452,  452,  452,  452,  452,  452,  452,  452,  452,\n
      453,  453,  453,  453,  453,  453,  453,  453,  453,  453,\n
      453,  551,  551,  551,  464,  491,  394,  394,  394,  394,\n
      394,  394,  394,  394,  394,  394,  394,  394,  394,  394,\n
      394,  394,  394,  394,  407,  552,  552,  552,  810,  810,\n
      662,  662,  662,  662,  662,  594,  283,  595,  510,  399,\n
      399,  567,  679,  632,  849,  850,  863,  660,  714,  426,\n
      222,  622,  622,  622,  622,  223,  617,  623,  494,  395,\n
      395,  395,  395,  395,  395,  395,  395,  395,  395,  395,\n
      395,  395,  395,  395,  395,  395,  395,  465,  472,  514,\n
      904,  398,  398,  425,  425,  459,  425,  419,  322,  421,\n
      421,  393,  396,  412,  422,  428,  460,  463,  473,  481,\n
      501,    5,  476,  284,  327,    1,   15,    2,    6,    7,\n
      550,  550,  550,    8,    9,   10,  668,   16,   11,   17,\n
       12,   18,   13,   19,   14,  704,  328,  881,  881,  643,\n
      628,  626,  626,  624,  626,  526,  401,  652,  647,  847,\n
      847,  847,  847,  847,  847,  847,  847,  847,  847,  847,\n
      437,  438,  441,  447,  477,  479,  497,  290,  910,  910,\n
      400,  400,  486,  880,  880,  263,  913,  910,  303,  255,\n
      723,  306,  822,  821,  306,  896,  896,  896,  861,  304,\n
      323,  410,  913,  913,  897,  316,  420,  769,  658,  559,\n
      879,  671,  536,  324,  466,  565,  311,  311,  311,  801,\n
      241,  676,  496,  439,  440,  442,  444,  448,  475,  631,\n
      858,  311,  285,  286,  603,  495,  712,    0,  406,  321,\n
        0,    0,    0,  314,    0,    0,  429,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\n
        0,    0,    0,    0,  411\n
];\n
\n
PHP.Parser.prototype.yygcheck = [\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   35,\n
       35,   35,   35,   35,   35,   35,   35,   35,   35,   35,\n
       86,   86,   86,   86,   86,   86,   86,   86,   86,   86,\n
       86,    6,    6,    6,   21,   21,   35,   35,   35,   35,\n
       35,   35,   35,   35,   35,   35,   35,   35,   35,   35,\n
       35,   35,   35,   35,   71,    7,    7,    7,   35,   35,\n
       35,   35,   35,   35,   35,   29,   44,   29,   35,   86,\n
       86,   12,   12,   12,   12,   12,   12,   12,   12,   75,\n
       40,   35,   35,   35,   35,   40,   35,   35,   35,   82,\n
       82,   82,   82,   82,   82,   82,   82,   82,   82,   82,\n
       82,   82,   82,   82,   82,   82,   82,   36,   36,   36,\n
      104,   82,   82,   28,   28,   28,   28,   28,   28,   28,\n
       28,   28,   28,   28,   28,   28,   28,   28,   28,   28,\n
       28,   13,   42,   42,   42,    2,   13,    2,   13,   13,\n
        5,    5,    5,   13,   13,   13,   54,   13,   13,   13,\n
       13,   13,   13,   13,   13,   67,   67,   83,   83,    5,\n
        5,    5,    5,    5,    5,    5,    5,    5,    5,   93,\n
       93,   93,   93,   93,   93,   93,   93,   93,   93,   93,\n
       52,   52,   52,   52,   52,   52,   52,    4,  105,  105,\n
       89,   89,   94,   84,   84,   92,  105,  105,   26,   92,\n
       71,    4,   91,   91,    4,   84,   84,   84,   97,   30,\n
       70,   30,  105,  105,  102,   27,   30,   72,   50,   10,\n
       84,   55,   46,    9,   30,   11,   90,   90,   90,   80,\n
       30,   56,   30,   85,   85,   85,   85,   85,   85,   43,\n
       96,   90,   44,   44,   34,   77,   69,   -1,    4,   90,\n
       -1,   -1,   -1,    4,   -1,   -1,    4,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,\n
       -1,   -1,   -1,   -1,   71\n
];\n
\n
PHP.Parser.prototype.yygbase = [\n
        0,    0, -286,    0,   10,  239,  130,  154,    0,  -10,\n
       25,  -23,  -29, -289,    0,  -30,    0,    0,    0,    0,\n
        0,   83,    0,    0,    0,    0,  245,   84,  -11,  142,\n
      -28,    0,    0,    0,  -13,  -88,  -42,    0,    0,    0,\n
     -344,    0,  -38,  -12, -188,    0,   23,    0,    0,    0,\n
       66,    0,  247,    0,  205,   24,  -18,    0,    0,    0,\n
        0,    0,    0,    0,    0,    0,    0,   13,    0,  -15,\n
       85,   74,   70,    0,    0,  148,    0,  -14,    0,    0,\n
       -6,    0,  -35,   11,   47,  278,  -77,    0,    0,   44,\n
       68,   43,   38,   72,   94,    0,  -16,  109,    0,    0,\n
        0,    0,   87,    0,  170,   34,    0\n
];\n
\n
PHP.Parser.prototype.yygdefault = [\n
    -32768,  362,    3,  546,  382,  570,  571,  572,  307,  305,\n
      560,  566,  467,    4,  568,  140,  295,  575,  296,  500,\n
      577,  414,  579,  580,  308,  309,  415,  315,  216,  593,\n
      503,  313,  596,  357,  602,  301,  449,  383,  350,  461,\n
      221,  423,  456,  630,  282,  638,  540,  646,  649,  450,\n
      657,  352,  433,  434,  667,  672,  677,  680,  334,  325,\n
      474,  684,  685,  256,  689,  511,  512,  703,  242,  711,\n
      317,  724,  342,  788,  790,  397,  408,  484,  797,  326,\n
      800,  384,  385,  386,  387,  435,  818,  815,  289,  866,\n
      287,  443,  254,  853,  468,  356,  903,  862,  288,  388,\n
      389,  302,  898,  341,  905,  912,  458\n
];\n
\n
PHP.Parser.prototype.yylhs = [\n
        0,    1,    2,    2,    4,    4,    3,    3,    3,    3,\n
        3,    3,    3,    3,    3,    8,    8,   10,   10,   10,\n
       10,    9,    9,   11,   13,   13,   14,   14,   14,   14,\n
        5,    5,    5,    5,    5,    5,    5,    5,    5,    5,\n
        5,    5,    5,    5,    5,    5,    5,    5,    5,    5,\n
        5,    5,    5,    5,    5,    5,    5,    5,   33,   33,\n
       34,   27,   27,   30,   30,    6,    7,    7,    7,   37,\n
       37,   37,   38,   38,   41,   41,   39,   39,   42,   42,\n
       22,   22,   29,   29,   32,   32,   31,   31,   43,   23,\n
       23,   23,   23,   44,   44,   45,   45,   46,   46,   20,\n
       20,   16,   16,   47,   18,   18,   48,   17,   17,   19,\n
       19,   36,   36,   49,   49,   50,   50,   51,   51,   51,\n
       51,   52,   52,   53,   53,   54,   54,   24,   24,   55,\n
       55,   55,   25,   25,   56,   56,   40,   40,   57,   57,\n
       57,   57,   62,   62,   63,   63,   64,   64,   64,   64,\n
       65,   66,   66,   61,   61,   58,   58,   60,   60,   68,\n
       68,   67,   67,   67,   67,   67,   67,   59,   59,   69,\n
       69,   26,   26,   21,   21,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,\n
       15,   15,   15,   71,   77,   77,   79,   79,   80,   81,\n
       81,   81,   81,   81,   81,   86,   86,   35,   35,   35,\n
       72,   72,   87,   87,   82,   82,   88,   88,   88,   88,\n
       88,   73,   73,   73,   76,   76,   76,   78,   78,   93,\n
       93,   93,   93,   93,   93,   93,   93,   93,   93,   93,\n
       93,   93,   93,   12,   12,   12,   12,   12,   12,   74,\n
       74,   74,   74,   94,   94,   96,   96,   95,   95,   97,\n
       97,   28,   28,   28,   28,   99,   99,   98,   98,   98,\n
       98,   98,  100,  100,   84,   84,   89,   89,   83,   83,\n
      101,  101,  101,  101,   90,   90,   90,   90,   85,   85,\n
       91,   91,   91,   70,   70,  102,  102,  102,   75,   75,\n
      103,  103,  104,  104,  104,  104,   92,   92,   92,   92,\n
      105,  105,  105,  105,  105,  105,  105,  106,  106,  106\n
];\n
\n
PHP.Parser.prototype.yylen = [\n
        1,    1,    2,    0,    1,    3,    1,    1,    1,    1,\n
        3,    5,    4,    3,    3,    3,    1,    1,    3,    2,\n
        4,    3,    1,    3,    2,    0,    1,    1,    1,    1,\n
        3,    7,   10,    5,    7,    9,    5,    2,    3,    2,\n
        3,    2,    3,    3,    3,    3,    1,    2,    5,    7,\n
        8,   10,    5,    1,    5,    3,    3,    2,    1,    2,\n
        8,    1,    3,    0,    1,    9,    7,    6,    5,    1,\n
        2,    2,    0,    2,    0,    2,    0,    2,    1,    3,\n
        1,    4,    1,    4,    1,    4,    1,    3,    3,    3,\n
        4,    4,    5,    0,    2,    4,    3,    1,    1,    1,\n
        4,    0,    2,    5,    0,    2,    6,    0,    2,    0,\n
        3,    1,    0,    1,    3,    3,    5,    0,    1,    1,\n
        1,    1,    0,    1,    3,    1,    2,    3,    1,    1,\n
        2,    4,    3,    1,    1,    3,    2,    0,    3,    3,\n
        8,    3,    1,    3,    0,    2,    4,    5,    4,    4,\n
        3,    1,    1,    1,    3,    1,    1,    0,    1,    1,\n
        2,    1,    1,    1,    1,    1,    1,    1,    3,    1,\n
        3,    3,    1,    0,    1,    1,    6,    3,    4,    4,\n
        1,    2,    3,    3,    3,    3,    3,    3,    3,    3,\n
        3,    3,    3,    2,    2,    2,    2,    3,    3,    3,\n
        3,    3,    3,    3,    3,    3,    3,    3,    3,    3,\n
        3,    3,    3,    2,    2,    2,    2,    3,    3,    3,\n
        3,    3,    3,    3,    3,    3,    3,    3,    5,    4,\n
        4,    4,    2,    2,    4,    2,    2,    2,    2,    2,\n
        2,    2,    2,    2,    2,    2,    1,    4,    3,    3,\n
        2,    9,   10,    3,    0,    4,    1,    3,    2,    4,\n
        6,    8,    4,    4,    4,    1,    1,    1,    2,    3,\n
        1,    1,    1,    1,    1,    1,    0,    3,    3,    4,\n
        4,    0,    2,    3,    0,    1,    1,    0,    3,    1,\n
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,\n
        3,    2,    1,    1,    3,    2,    2,    4,    3,    1,\n
        3,    3,    3,    0,    2,    0,    1,    3,    1,    3,\n
        1,    1,    1,    1,    1,    6,    4,    3,    6,    4,\n
        4,    4,    1,    3,    1,    2,    1,    1,    4,    1,\n
        3,    6,    4,    4,    4,    4,    1,    4,    0,    1,\n
        1,    3,    1,    3,    1,    1,    4,    0,    0,    2,\n
        3,    1,    3,    1,    4,    2,    2,    2,    1,    2,\n
        1,    4,    3,    3,    3,    6,    3,    1,    1,    1\n
];\n
\n
\n
\n
\n
\n
\n
\n
PHP.Parser.prototype.yyn0 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn1 = function ( attributes ) {\n
     this.yyval = this.Stmt_Namespace_postprocess(this.yyastk[ this.stackPos-(1-1) ]); \n
};\n
\n
PHP.Parser.prototype.yyn2 = function ( attributes ) {\n
     if (Array.isArray(this.yyastk[ this.stackPos-(2-2) ])) { this.yyval = this.yyastk[ this.stackPos-(2-1) ].concat( this.yyastk[ this.stackPos-(2-2) ]); } else { this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; }; \n
};\n
\n
PHP.Parser.prototype.yyn3 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn4 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn5 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn6 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn7 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn8 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn9 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_HaltCompiler(attributes); \n
};\n
\n
PHP.Parser.prototype.yyn10 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Namespace(this.Node_Name(this.yyastk[ this.stackPos-(3-2) ], attributes), null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn11 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Namespace(this.Node_Name(this.yyastk[ this.stackPos-(5-2) ], attributes), this.yyastk[ this.stackPos-(5-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn12 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Namespace(null, this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn13 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Use(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn14 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Const(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn15 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn16 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn17 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_UseUse(this.Node_Name(this.yyastk[ this.stackPos-(1-1) ], attributes), null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn18 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_UseUse(this.Node_Name(this.yyastk[ this.stackPos-(3-1) ], attributes), this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn19 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_UseUse(this.Node_Name(this.yyastk[ this.stackPos-(2-2) ], attributes), null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn20 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_UseUse(this.Node_Name(this.yyastk[ this.stackPos-(4-2) ], attributes), this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn21 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn22 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn23 = function ( attributes ) {\n
     this.yyval = this.Node_Const(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn24 = function ( attributes ) {\n
     if (Array.isArray(this.yyastk[ this.stackPos-(2-2) ])) { this.yyval = this.yyastk[ this.stackPos-(2-1) ].concat( this.yyastk[ this.stackPos-(2-2) ]); } else { this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; }; \n
};\n
\n
PHP.Parser.prototype.yyn25 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn26 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn27 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn28 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn29 = function ( attributes ) {\n
     throw new Error(\'__halt_compiler() can only be used from the outermost scope\'); \n
};\n
\n
PHP.Parser.prototype.yyn30 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn31 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_If(this.yyastk[ this.stackPos-(7-3) ], {\'stmts\':  Array.isArray(this.yyastk[ this.stackPos-(7-5) ]) ? this.yyastk[ this.stackPos-(7-5) ] : [this.yyastk[ this.stackPos-(7-5) ]], \'elseifs\':  this.yyastk[ this.stackPos-(7-6) ], \'Else\':  this.yyastk[ this.stackPos-(7-7) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn32 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_If(this.yyastk[ this.stackPos-(10-3) ], {\'stmts\':  this.yyastk[ this.stackPos-(10-6) ], \'elseifs\':  this.yyastk[ this.stackPos-(10-7) ], \'else\':  this.yyastk[ this.stackPos-(10-8) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn33 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_While(this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn34 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Do(this.yyastk[ this.stackPos-(7-5) ], Array.isArray(this.yyastk[ this.stackPos-(7-2) ]) ? this.yyastk[ this.stackPos-(7-2) ] : [this.yyastk[ this.stackPos-(7-2) ]], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn35 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_For({\'init\':  this.yyastk[ this.stackPos-(9-3) ], \'cond\':  this.yyastk[ this.stackPos-(9-5) ], \'loop\':  this.yyastk[ this.stackPos-(9-7) ], \'stmts\':  this.yyastk[ this.stackPos-(9-9) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn36 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Switch(this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn37 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Break(null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn38 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Break(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn39 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Continue(null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn40 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Continue(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn41 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Return(null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn42 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Return(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn43 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Global(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn44 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Static(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn45 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Echo(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn46 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_InlineHTML(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn47 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn48 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Unset(this.yyastk[ this.stackPos-(5-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn49 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Foreach(this.yyastk[ this.stackPos-(7-3) ], this.yyastk[ this.stackPos-(7-5) ], {\'keyVar\':  null, \'byRef\':  false, \'stmts\':  this.yyastk[ this.stackPos-(7-7) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn50 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Foreach(this.yyastk[ this.stackPos-(8-3) ], this.yyastk[ this.stackPos-(8-6) ], {\'keyVar\':  null, \'byRef\':  true, \'stmts\':  this.yyastk[ this.stackPos-(8-8) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn51 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Foreach(this.yyastk[ this.stackPos-(10-3) ], this.yyastk[ this.stackPos-(10-8) ], {\'keyVar\':  this.yyastk[ this.stackPos-(10-5) ], \'byRef\':  this.yyastk[ this.stackPos-(10-7) ], \'stmts\':  this.yyastk[ this.stackPos-(10-10) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn52 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Declare(this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn53 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn54 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TryCatch(this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn55 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Throw(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn56 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Goto(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn57 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Label(this.yyastk[ this.stackPos-(2-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn58 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn59 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn60 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Catch(this.yyastk[ this.stackPos-(8-3) ], this.yyastk[ this.stackPos-(8-4) ].substring( 1 ), this.yyastk[ this.stackPos-(8-7) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn61 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn62 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn63 = function ( attributes ) {\n
     this.yyval = false; \n
};\n
\n
PHP.Parser.prototype.yyn64 = function ( attributes ) {\n
     this.yyval = true; \n
};\n
\n
PHP.Parser.prototype.yyn65 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Function(this.yyastk[ this.stackPos-(9-3) ], {\'byRef\':  this.yyastk[ this.stackPos-(9-2) ], \'params\':  this.yyastk[ this.stackPos-(9-5) ], \'stmts\':  this.yyastk[ this.stackPos-(9-8) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn66 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Class(this.yyastk[ this.stackPos-(7-2) ], {\'type\':  this.yyastk[ this.stackPos-(7-1) ], \'Extends\':  this.yyastk[ this.stackPos-(7-3) ], \'Implements\':  this.yyastk[ this.stackPos-(7-4) ], \'stmts\':  this.yyastk[ this.stackPos-(7-6) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn67 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Interface(this.yyastk[ this.stackPos-(6-2) ], {\'Extends\':  this.yyastk[ this.stackPos-(6-3) ], \'stmts\':  this.yyastk[ this.stackPos-(6-5) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn68 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Trait(this.yyastk[ this.stackPos-(5-2) ], this.yyastk[ this.stackPos-(5-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn69 = function ( attributes ) {\n
     this.yyval = 0; \n
};\n
\n
PHP.Parser.prototype.yyn70 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_ABSTRACT; \n
};\n
\n
PHP.Parser.prototype.yyn71 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_FINAL; \n
};\n
\n
PHP.Parser.prototype.yyn72 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn73 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn74 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn75 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn76 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn77 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn78 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn79 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn80 = function ( attributes ) {\n
     this.yyval = Array.isArray(this.yyastk[ this.stackPos-(1-1) ]) ? this.yyastk[ this.stackPos-(1-1) ] : [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn81 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn82 = function ( attributes ) {\n
     this.yyval = Array.isArray(this.yyastk[ this.stackPos-(1-1) ]) ? this.yyastk[ this.stackPos-(1-1) ] : [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn83 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn84 = function ( attributes ) {\n
     this.yyval = Array.isArray(this.yyastk[ this.stackPos-(1-1) ]) ? this.yyastk[ this.stackPos-(1-1) ] : [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn85 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn86 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn87 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn88 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_DeclareDeclare(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn89 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn90 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-3) ]; \n
};\n
\n
PHP.Parser.prototype.yyn91 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn92 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(5-3) ]; \n
};\n
\n
PHP.Parser.prototype.yyn93 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn94 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn95 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Case(this.yyastk[ this.stackPos-(4-2) ], this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn96 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Case(null, this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn97 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn98 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn99 = function ( attributes ) {\n
     this.yyval = Array.isArray(this.yyastk[ this.stackPos-(1-1) ]) ? this.yyastk[ this.stackPos-(1-1) ] : [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn100 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn101 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn102 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn103 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_ElseIf(this.yyastk[ this.stackPos-(5-3) ], Array.isArray(this.yyastk[ this.stackPos-(5-5) ]) ? this.yyastk[ this.stackPos-(5-5) ] : [this.yyastk[ this.stackPos-(5-5) ]], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn104 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn105 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn106 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_ElseIf(this.yyastk[ this.stackPos-(6-3) ], this.yyastk[ this.stackPos-(6-6) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn107 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn108 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Else(Array.isArray(this.yyastk[ this.stackPos-(2-2) ]) ? this.yyastk[ this.stackPos-(2-2) ] : [this.yyastk[ this.stackPos-(2-2) ]], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn109 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn110 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Else(this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn111 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn112 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn113 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn114 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn115 = function ( attributes ) {\n
     this.yyval = this.Node_Param(this.yyastk[ this.stackPos-(3-3) ].substring( 1 ), null, this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn116 = function ( attributes ) {\n
     this.yyval = this.Node_Param(this.yyastk[ this.stackPos-(5-3) ].substring( 1 ), this.yyastk[ this.stackPos-(5-5) ], this.yyastk[ this.stackPos-(5-1) ], this.yyastk[ this.stackPos-(5-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn117 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn118 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn119 = function ( attributes ) {\n
     this.yyval = \'array\'; \n
};\n
\n
PHP.Parser.prototype.yyn120 = function ( attributes ) {\n
     this.yyval = \'callable\'; \n
};\n
\n
PHP.Parser.prototype.yyn121 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn122 = function ( attributes ) {\n
     this.yyval = []; \n
};

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
            <value> <string>\n
\n
PHP.Parser.prototype.yyn123 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn124 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn125 = function ( attributes ) {\n
     this.yyval = this.Node_Arg(this.yyastk[ this.stackPos-(1-1) ], false, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn126 = function ( attributes ) {\n
     this.yyval = this.Node_Arg(this.yyastk[ this.stackPos-(2-2) ], true, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn127 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn128 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn129 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn130 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn131 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn132 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn133 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn134 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_StaticVar(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn135 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_StaticVar(this.yyastk[ this.stackPos-(3-1) ].substring( 1 ), this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn136 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn137 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn138 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_Property(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn139 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_ClassConst(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn140 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_ClassMethod(this.yyastk[ this.stackPos-(8-4) ], {\'type\':  this.yyastk[ this.stackPos-(8-1) ], \'byRef\':  this.yyastk[ this.stackPos-(8-3) ], \'params\':  this.yyastk[ this.stackPos-(8-6) ], \'stmts\':  this.yyastk[ this.stackPos-(8-8) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn141 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TraitUse(this.yyastk[ this.stackPos-(3-2) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn142 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn143 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn144 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn145 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn146 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TraitUseAdaptation_Precedence(this.yyastk[ this.stackPos-(4-1) ][0], this.yyastk[ this.stackPos-(4-1) ][1], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn147 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TraitUseAdaptation_Alias(this.yyastk[ this.stackPos-(5-1) ][0], this.yyastk[ this.stackPos-(5-1) ][1], this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn148 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TraitUseAdaptation_Alias(this.yyastk[ this.stackPos-(4-1) ][0], this.yyastk[ this.stackPos-(4-1) ][1], this.yyastk[ this.stackPos-(4-3) ], null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn149 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_TraitUseAdaptation_Alias(this.yyastk[ this.stackPos-(4-1) ][0], this.yyastk[ this.stackPos-(4-1) ][1], null, this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn150 = function ( attributes ) {\n
     this.yyval = array(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ]); \n
};\n
\n
PHP.Parser.prototype.yyn151 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn152 = function ( attributes ) {\n
     this.yyval = array(null, this.yyastk[ this.stackPos-(1-1) ]); \n
};\n
\n
PHP.Parser.prototype.yyn153 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn154 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn155 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn156 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_PUBLIC; \n
};\n
\n
PHP.Parser.prototype.yyn157 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_PUBLIC; \n
};\n
\n
PHP.Parser.prototype.yyn158 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn159 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn160 = function ( attributes ) {\n
     this.Stmt_Class_verifyModifier(this.yyastk[ this.stackPos-(2-1) ], this.yyastk[ this.stackPos-(2-2) ]); this.yyval = this.yyastk[ this.stackPos-(2-1) ] | this.yyastk[ this.stackPos-(2-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn161 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_PUBLIC; \n
};\n
\n
PHP.Parser.prototype.yyn162 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_PROTECTED; \n
};\n
\n
PHP.Parser.prototype.yyn163 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_PRIVATE; \n
};\n
\n
PHP.Parser.prototype.yyn164 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_STATIC; \n
};\n
\n
PHP.Parser.prototype.yyn165 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_ABSTRACT; \n
};\n
\n
PHP.Parser.prototype.yyn166 = function ( attributes ) {\n
     this.yyval = this.MODIFIER_FINAL; \n
};\n
\n
PHP.Parser.prototype.yyn167 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn168 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn169 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_PropertyProperty(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), null, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn170 = function ( attributes ) {\n
     this.yyval = this.Node_Stmt_PropertyProperty(this.yyastk[ this.stackPos-(3-1) ].substring( 1 ), this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn171 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn172 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn173 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn174 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn175 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn176 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignList(this.yyastk[ this.stackPos-(6-3) ], this.yyastk[ this.stackPos-(6-6) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn177 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Assign(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn178 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignRef(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn179 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignRef(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn180 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn181 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Clone(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn182 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignPlus(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn183 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignMinus(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn184 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignMul(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn185 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignDiv(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn186 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignConcat(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn187 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignMod(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn188 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignBitwiseAnd(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn189 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignBitwiseOr(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn190 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignBitwiseXor(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn191 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignShiftLeft(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn192 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_AssignShiftRight(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn193 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PostInc(this.yyastk[ this.stackPos-(2-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn194 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PreInc(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn195 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PostDec(this.yyastk[ this.stackPos-(2-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn196 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PreDec(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn197 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BooleanOr(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn198 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BooleanAnd(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn199 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_LogicalOr(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn200 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_LogicalAnd(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn201 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_LogicalXor(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn202 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BitwiseOr(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn203 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BitwiseAnd(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn204 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BitwiseXor(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn205 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Concat(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn206 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Plus(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn207 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Minus(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn208 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Mul(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn209 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Div(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn210 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Mod(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn211 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ShiftLeft(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn212 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ShiftRight(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn213 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_UnaryPlus(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn214 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_UnaryMinus(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn215 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BooleanNot(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn216 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_BitwiseNot(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn217 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Identical(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn218 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_NotIdentical(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn219 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Equal(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn220 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_NotEqual(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn221 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Smaller(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn222 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_SmallerOrEqual(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn223 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Greater(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn224 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_GreaterOrEqual(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn225 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Instanceof(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn226 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn227 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn228 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Ternary(this.yyastk[ this.stackPos-(5-1) ], this.yyastk[ this.stackPos-(5-3) ], this.yyastk[ this.stackPos-(5-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn229 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Ternary(this.yyastk[ this.stackPos-(4-1) ], null, this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn230 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Isset(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn231 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Empty(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn232 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Include(this.yyastk[ this.stackPos-(2-2) ], "Node_Expr_Include", attributes); \n
};\n
\n
PHP.Parser.prototype.yyn233 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Include(this.yyastk[ this.stackPos-(2-2) ], "Node_Expr_IncludeOnce", attributes); \n
};\n
\n
PHP.Parser.prototype.yyn234 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Eval(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn235 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Include(this.yyastk[ this.stackPos-(2-2) ], "Node_Expr_Require", attributes); \n
};\n
\n
PHP.Parser.prototype.yyn236 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Include(this.yyastk[ this.stackPos-(2-2) ], "Node_Expr_RequireOnce", attributes); \n
};\n
\n
PHP.Parser.prototype.yyn237 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Int(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn238 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Double(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn239 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_String(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn240 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Array(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn241 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Object(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn242 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Bool(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn243 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Cast_Unset(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn244 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Exit(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn245 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ErrorSuppress(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn246 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn247 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Array(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn248 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Array(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn249 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ShellExec(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn250 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Print(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn251 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Closure({\'static\':  false, \'byRef\':  this.yyastk[ this.stackPos-(9-2) ], \'params\':  this.yyastk[ this.stackPos-(9-4) ], \'uses\':  this.yyastk[ this.stackPos-(9-6) ], \'stmts\':  this.yyastk[ this.stackPos-(9-8) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn252 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Closure({\'static\':  true, \'byRef\':  this.yyastk[ this.stackPos-(10-3) ], \'params\':  this.yyastk[ this.stackPos-(10-5) ], \'uses\':  this.yyastk[ this.stackPos-(10-7) ], \'stmts\':  this.yyastk[ this.stackPos-(10-9) ]}, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn253 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_New(this.yyastk[ this.stackPos-(3-2) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn254 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn255 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-3) ]; \n
};\n
\n
PHP.Parser.prototype.yyn256 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn257 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn258 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ClosureUse(this.yyastk[ this.stackPos-(2-2) ].substring( 1 ), this.yyastk[ this.stackPos-(2-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn259 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_FuncCall(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn260 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_StaticCall(this.yyastk[ this.stackPos-(6-1) ], this.yyastk[ this.stackPos-(6-3) ], this.yyastk[ this.stackPos-(6-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn261 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_StaticCall(this.yyastk[ this.stackPos-(8-1) ], this.yyastk[ this.stackPos-(8-4) ], this.yyastk[ this.stackPos-(8-7) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn262 = function ( attributes ) {\n
    \n
            if (this.yyastk[ this.stackPos-(4-1) ].type === "Node_Expr_StaticPropertyFetch") {\n
                this.yyval = this.Node_Expr_StaticCall(this.yyastk[ this.stackPos-(4-1) ].Class, this.Node_Expr_Variable(this.yyastk[ this.stackPos-(4-1) ].name, attributes), this.yyastk[ this.stackPos-(4-3) ], attributes);\n
            } else if (this.yyastk[ this.stackPos-(4-1) ].type === "Node_Expr_ArrayDimFetch") {\n
                var tmp = this.yyastk[ this.stackPos-(4-1) ];\n
                while (tmp.variable.type === "Node_Expr_ArrayDimFetch") {\n
                    tmp = tmp.variable;\n
                }\n
\n
                this.yyval = this.Node_Expr_StaticCall(tmp.variable.Class, this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes);\n
                tmp.variable = this.Node_Expr_Variable(tmp.variable.name, attributes);\n
            } else {\n
                throw new Exception;\n
            }\n
          \n
};\n
\n
PHP.Parser.prototype.yyn263 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_FuncCall(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn264 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn265 = function ( attributes ) {\n
     this.yyval = this.Node_Name(\'static\', attributes); \n
};\n
\n
PHP.Parser.prototype.yyn266 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn267 = function ( attributes ) {\n
     this.yyval = this.Node_Name(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn268 = function ( attributes ) {\n
     this.yyval = this.Node_Name_FullyQualified(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn269 = function ( attributes ) {\n
     this.yyval = this.Node_Name_Relative(this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn270 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn271 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn272 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn273 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn274 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn275 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn276 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn277 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PropertyFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn278 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PropertyFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn279 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn280 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn281 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn282 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn283 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn284 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn285 = function ( attributes ) {\n
     this.yyval = [this.Scalar_String_parseEscapeSequences(this.yyastk[ this.stackPos-(1-1) ], \'`\')]; \n
};\n
\n
PHP.Parser.prototype.yyn286 = function ( attributes ) {\n
     ; this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn287 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn288 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn289 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_LNumber(this.Scalar_LNumber_parse(this.yyastk[ this.stackPos-(1-1) ]), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn290 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_DNumber(this.Scalar_DNumber_parse(this.yyastk[ this.stackPos-(1-1) ]), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn291 = function ( attributes ) {\n
     this.yyval = this.Scalar_String_create(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn292 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_LineConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn293 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_FileConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn294 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_DirConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn295 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_ClassConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn296 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_TraitConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn297 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_MethodConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn298 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_FuncConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn299 = function ( attributes ) {\n
     this.yyval = {type: "Node_Scalar_NSConst", attributes: attributes}; \n
};\n
\n
PHP.Parser.prototype.yyn300 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_String(this.Scalar_String_parseDocString(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-2) ]), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn301 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_String(\'\', attributes); \n
};\n
\n
PHP.Parser.prototype.yyn302 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ConstFetch(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn303 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn304 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ClassConstFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn305 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_UnaryPlus(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn306 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_UnaryMinus(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn307 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Array(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn308 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Array(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn309 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn310 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ClassConstFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn311 = function ( attributes ) {\n
     ; this.yyval = this.Node_Scalar_Encapsed(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn312 = function ( attributes ) {\n
     ; this.yyval = this.Node_Scalar_Encapsed(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn313 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn314 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn315 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn316 = function () {\n
    this.yyval = this.yyastk[ this.stackPos ];\n
};\n
\n
PHP.Parser.prototype.yyn317 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn318 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn319 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(3-3) ], this.yyastk[ this.stackPos-(3-1) ], false, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn320 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(1-1) ], null, false, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn321 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn322 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn323 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn324 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn325 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(6-2) ], this.yyastk[ this.stackPos-(6-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn326 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn327 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PropertyFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn328 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_MethodCall(this.yyastk[ this.stackPos-(6-1) ], this.yyastk[ this.stackPos-(6-3) ], this.yyastk[ this.stackPos-(6-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn329 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_FuncCall(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn330 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn331 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn332 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn333 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn334 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn335 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(2-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn336 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn337 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn338 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_StaticPropertyFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn339 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn340 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_StaticPropertyFetch(this.yyastk[ this.stackPos-(3-1) ], this.yyastk[ this.stackPos-(3-3) ].substring( 1 ), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn341 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_StaticPropertyFetch(this.yyastk[ this.stackPos-(6-1) ], this.yyastk[ this.stackPos-(6-5) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn342 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn343 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn344 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn345 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.yyastk[ this.stackPos-(4-1) ], this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn346 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn347 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn348 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn349 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn350 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn351 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn352 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn353 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn354 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn355 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(1-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn356 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(4-3) ]; \n
};\n
\n
PHP.Parser.prototype.yyn357 = function ( attributes ) {\n
     this.yyval = null; \n
};\n
\n
PHP.Parser.prototype.yyn358 = function ( attributes ) {\n
     this.yyval = []; \n
};\n
\n
PHP.Parser.prototype.yyn359 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn360 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(3-1) ].push( this.yyastk[ this.stackPos-(3-3) ] ); this.yyval = this.yyastk[ this.stackPos-(3-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn361 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn362 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(3-3) ], this.yyastk[ this.stackPos-(3-1) ], false, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn363 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(1-1) ], null, false, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn364 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(4-4) ], this.yyastk[ this.stackPos-(4-1) ], true, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn365 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayItem(this.yyastk[ this.stackPos-(2-2) ], null, true, attributes); \n
};\n
\n
PHP.Parser.prototype.yyn366 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn367 = function ( attributes ) {\n
     this.yyastk[ this.stackPos-(2-1) ].push( this.yyastk[ this.stackPos-(2-2) ] ); this.yyval = this.yyastk[ this.stackPos-(2-1) ]; \n
};\n
\n
PHP.Parser.prototype.yyn368 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(1-1) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn369 = function ( attributes ) {\n
     this.yyval = [this.yyastk[ this.stackPos-(2-1) ], this.yyastk[ this.stackPos-(2-2) ]]; \n
};\n
\n
PHP.Parser.prototype.yyn370 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), attributes); \n
};\n
\n
PHP.Parser.prototype.yyn371 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.Node_Expr_Variable(this.yyastk[ this.stackPos-(4-1) ].substring( 1 ), attributes), this.yyastk[ this.stackPos-(4-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn372 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_PropertyFetch(this.Node_Expr_Variable(this.yyastk[ this.stackPos-(3-1) ].substring( 1 ), attributes), this.yyastk[ this.stackPos-(3-3) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn373 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn374 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(3-2) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn375 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_ArrayDimFetch(this.Node_Expr_Variable(this.yyastk[ this.stackPos-(6-2) ], attributes), this.yyastk[ this.stackPos-(6-4) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn376 = function ( attributes ) {\n
     this.yyval = this.yyastk[ this.stackPos-(3-2) ]; \n
};\n
\n
PHP.Parser.prototype.yyn377 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_String(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn378 = function ( attributes ) {\n
     this.yyval = this.Node_Scalar_String(this.yyastk[ this.stackPos-(1-1) ], attributes); \n
};\n
\n
PHP.Parser.prototype.yyn379 = function ( attributes ) {\n
     this.yyval = this.Node_Expr_Variable(this.yyastk[ this.stackPos-(1-1) ].substring( 1 ), attributes); \n
};\n
\n
\n
PHP.Parser.prototype.Stmt_Namespace_postprocess = function( a ) {\n
  return a;  \n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_Echo = function() {\n
    return {\n
        type: "Node_Stmt_Echo",\n
        exprs: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_If = function() {\n
    return {\n
        type: "Node_Stmt_If",\n
        cond: arguments[ 0 ],\n
        stmts: arguments[ 1 ].stmts,\n
        elseifs: arguments[ 1 ].elseifs,\n
        Else: arguments[ 1 ].Else || null,\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_For = function() {\n
    \n
    return {\n
        type: "Node_Stmt_For",\n
        init: arguments[ 0 ].init,\n
        cond: arguments[ 0 ].cond,\n
        loop: arguments[ 0 ].loop,\n
        stmts: arguments[ 0 ].stmts,\n
        attributes: arguments[ 1 ]\n
    };   \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Function = function() {\n
    return {\n
        type: "Node_Stmt_Function",\n
        name: arguments[ 0 ],\n
        byRef: arguments[ 1 ].byRef,\n
        params: arguments[ 1 ].params,\n
        stmts: arguments[ 1 ].stmts,\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Stmt_Class_verifyModifier = function() {\n
  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Namespace = function() {\n
    return {\n
        type: "Node_Stmt_Namespace",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Use = function() {\n
    return {\n
        type: "Node_Stmt_Use",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_UseUse = function() {\n
    return {\n
        type: "Node_Stmt_UseUse",\n
        name: arguments[ 0 ],\n
        as: arguments[1],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_TraitUseAdaptation_Precedence = function() {\n
    return {\n
        type: "Node_Stmt_TraitUseAdaptation_Precedence",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_TraitUseAdaptation_Alias = function() {\n
    return {\n
        type: "Node_Stmt_TraitUseAdaptation_Alias",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Trait = function() {\n
    return {\n
        type: "Node_Stmt_Trait",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_TraitUse = function() {\n
    return {\n
        type: "Node_Stmt_TraitUse",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Class = function() {\n
    return {\n
        type: "Node_Stmt_Class",\n
        name: arguments[ 0 ],\n
        Type: arguments[ 1 ].type,\n
        Extends: arguments[ 1 ].Extends,\n
        Implements: arguments[ 1 ].Implements,\n
        stmts: arguments[ 1 ].stmts,\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_ClassMethod = function() {\n
    return {\n
        type: "Node_Stmt_ClassMethod",\n
        name: arguments[ 0 ],\n
        Type: arguments[ 1 ].type,\n
        byRef: arguments[ 1 ].byRef,\n
        params: arguments[ 1 ].params,\n
        stmts: arguments[ 1 ].stmts,\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_ClassConst = function() {\n
    return {\n
        type: "Node_Stmt_ClassConst",\n
        consts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Interface = function() {\n
    return {\n
        type: "Node_Stmt_Interface",\n
        name: arguments[ 0 ],\n
        Extends: arguments[ 1 ].Extends,\n
        stmts: arguments[ 1 ].stmts,\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Throw = function() {\n
    return {\n
        type: "Node_Stmt_Throw",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Catch = function() {\n
    return {\n
        type: "Node_Stmt_Catch",\n
        Type: arguments[ 0 ],\n
        variable: arguments[ 1 ],\n
        stmts: arguments[ 2 ],\n
        attributes: arguments[ 3 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_TryCatch = function() {\n
    return {\n
        type: "Node_Stmt_TryCatch",\n
        stmts: arguments[ 0 ],\n
        catches: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_Foreach = function() {\n
    return {\n
        type: "Node_Stmt_Foreach",\n
        expr: arguments[ 0 ],\n
        valueVar: arguments[ 1 ],\n
        keyVar: arguments[ 2 ].keyVar,\n
        byRef: arguments[ 2 ].byRef,\n
        stmts: arguments[ 2 ].stmts,\n
        attributes: arguments[ 3 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_While = function() {\n
    return {\n
        type: "Node_Stmt_While",\n
        cond: arguments[ 0 ],\n
        stmts: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Do = function() {\n
    return {\n
        type: "Node_Stmt_Do",\n
        cond: arguments[ 0 ],\n
        stmts: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Break = function() {\n
    return {\n
        type: "Node_Stmt_Break",\n
        num: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Continue = function() {\n
    return {\n
        type: "Node_Stmt_Continue",\n
        num: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Return = function() {\n
    return {\n
        type: "Node_Stmt_Return",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Case = function() {\n
    return {\n
        type: "Node_Stmt_Case",\n
        cond: arguments[ 0 ],\n
        stmts: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Switch = function() {\n
    return {\n
        type: "Node_Stmt_Switch",\n
        cond: arguments[ 0 ],\n
        cases: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Else = function() {\n
   \n
    return {\n
        type: "Node_Stmt_Else",\n
        stmts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_ElseIf = function() {\n
    return {\n
        type: "Node_Stmt_ElseIf",\n
        cond: arguments[ 0 ],\n
        stmts: arguments[ 1 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_InlineHTML = function() {\n
    return {\n
        type: "Node_Stmt_InlineHTML",\n
        value: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_StaticVar = function() {\n
    return {\n
        type: "Node_Stmt_StaticVar",\n
        name: arguments[ 0 ],\n
        def: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_Static = function() {\n
    return {\n
        type: "Node_Stmt_Static",\n
        vars: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Global = function() {\n
    return {\n
        type: "Node_Stmt_Global",\n
        vars: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_PropertyProperty = function() {\n
    return {\n
        type: "Node_Stmt_PropertyProperty",\n
        name: arguments[ 0 ],\n
        def: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Stmt_Property = function() {\n
    return {\n
        type: "Node_Stmt_Property",\n
        Type: arguments[ 0 ],\n
        props: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Stmt_Unset = function() {\n
    return {\n
        type: "Node_Stmt_Unset",\n
        variables: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Variable = function( a ) {\n
    return {\n
        type: "Node_Expr_Variable",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
};\n
\n
PHP.Parser.prototype.Node_Expr_FuncCall = function() {\n
\n
    return {\n
        type: "Node_Expr_FuncCall",\n
        func: arguments[ 0 ],\n
        args: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_MethodCall = function() {\n
\n
    return {\n
        type: "Node_Expr_MethodCall",\n
        variable: arguments[ 0 ],\n
        name: arguments[ 1 ],\n
        args: arguments[ 2 ],\n
        attributes: arguments[ 3 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_StaticCall = function() {\n
\n
    return {\n
        type: "Node_Expr_StaticCall",\n
        Class: arguments[ 0 ],\n
        func: arguments[ 1 ],\n
        args: arguments[ 2 ],\n
        attributes: arguments[ 3 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Ternary = function() {\n
\n
    return {\n
        type: "Node_Expr_Ternary",\n
        cond: arguments[ 0 ],\n
        If: arguments[ 1 ],\n
        Else: arguments[ 2 ],\n
        attributes: arguments[ 3 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignList = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignList",\n
        assignList: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Assign = function() {\n
\n
    return {\n
        type: "Node_Expr_Assign",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignConcat = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignConcat",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignMinus = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignMinus",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignPlus = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignPlus",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignDiv = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignDiv",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignRef = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignRef",\n
        variable: arguments[ 0 ],\n
        refVar: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignMul = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignMul",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_AssignMod = function() {\n
\n
    return {\n
        type: "Node_Expr_AssignMod",\n
        variable: arguments[ 0 ],\n
        expr: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Plus = function() {\n
\n
    return {\n
        type: "Node_Expr_Plus",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Minus = function() {\n
\n
    return {\n
        type: "Node_Expr_Minus",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Mul = function() {\n
\n
    return {\n
        type: "Node_Expr_Mul",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Div = function() {\n
\n
    return {\n
        type: "Node_Expr_Div",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Mod = function() {\n
\n
    return {\n
        type: "Node_Expr_Mod",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Greater = function() {\n
\n
    return {\n
        type: "Node_Expr_Greater",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Equal = function() {\n
\n
    return {\n
        type: "Node_Expr_Equal",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_NotEqual = function() {\n
\n
    return {\n
        type: "Node_Expr_NotEqual",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Identical = function() {\n
\n
    return {\n
        type: "Node_Expr_Identical",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_NotIdentical = function() {\n
\n
    return {\n
        type: "Node_Expr_NotIdentical",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_GreaterOrEqual = function() {\n
\n
    return {\n
        type: "Node_Expr_GreaterOrEqual",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_SmallerOrEqual = function() {\n
\n
    return {\n
        type: "Node_Expr_SmallerOrEqual",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Concat = function() {\n
\n
    return {\n
        type: "Node_Expr_Concat",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Smaller = function() {\n
\n
    return {\n
        type: "Node_Expr_Smaller",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_PostInc = function() {\n
\n
    return {\n
        type: "Node_Expr_PostInc",\n
        variable: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_PostDec = function() {\n
\n
    return {\n
        type: "Node_Expr_PostDec",\n
        variable: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_PreInc = function() {\n
\n
    return {\n
        type: "Node_Expr_PreInc",\n
        variable: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_PreDec = function() {\n
\n
    return {\n
        type: "Node_Expr_PreDec",\n
        variable: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Include = function() {\n
    return {\n
        expr: arguments[ 0 ],\n
        type: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
};\n
\n
PHP.Parser.prototype.Node_Expr_ArrayDimFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_ArrayDimFetch",\n
        variable: arguments[ 0 ],\n
        dim: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_StaticPropertyFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_StaticPropertyFetch",\n
        Class: arguments[ 0 ],\n
        name: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_ClassConstFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_ClassConstFetch",\n
        Class: arguments[ 0 ],\n
        name: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_StaticPropertyFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_StaticPropertyFetch",\n
        Class: arguments[ 0 ],\n
        name: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_ConstFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_ConstFetch",\n
        name: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_ArrayItem = function() {\n
\n
    return {\n
        type: "Node_Expr_ArrayItem",\n
        value: arguments[ 0 ],\n
        key: arguments[ 1 ],\n
        byRef: arguments[ 2 ],\n
        attributes: arguments[ 3 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Array = function() {\n
\n
    return {\n
        type: "Node_Expr_Array",\n
        items: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_PropertyFetch = function() {\n
\n
    return {\n
        type: "Node_Expr_PropertyFetch",\n
        variable: arguments[ 0 ],\n
        name: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_New = function() {\n
\n
    return {\n
        type: "Node_Expr_New",\n
        Class: arguments[ 0 ],\n
        args: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Print = function() {\n
    return {\n
        type: "Node_Expr_Print",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Exit = function() {\n
    return {\n
        type: "Node_Expr_Exit",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Cast_Bool = function() {\n
    return {\n
        type: "Node_Expr_Cast_Bool",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Cast_Int = function() {\n
    return {\n
        type: "Node_Expr_Cast_Int",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Cast_String = function() {\n
    return {\n
        type: "Node_Expr_Cast_String",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Cast_Double = function() {\n
    return {\n
        type: "Node_Expr_Cast_Double",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Cast_Array = function() {\n
    return {\n
        type: "Node_Expr_Cast_Array",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Cast_Object = function() {\n
    return {\n
        type: "Node_Expr_Cast_Object",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_ErrorSuppress = function() {\n
    return {\n
        type: "Node_Expr_ErrorSuppress",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_Isset = function() {\n
    return {\n
        type: "Node_Expr_Isset",\n
        variables: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
\n
\n
PHP.Parser.prototype.Node_Expr_UnaryMinus = function() {\n
    return {\n
        type: "Node_Expr_UnaryMinus",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_UnaryPlus = function() {\n
    return {\n
        type: "Node_Expr_UnaryPlus",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Empty = function() {\n
    return {\n
        type: "Node_Expr_Empty",\n
        variable: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BooleanOr = function() {\n
    return {\n
        type: "Node_Expr_BooleanOr",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_LogicalOr = function() {\n
    return {\n
        type: "Node_Expr_LogicalOr",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_LogicalAnd = function() {\n
    return {\n
        type: "Node_Expr_LogicalAnd",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
\n
PHP.Parser.prototype.Node_Expr_LogicalXor = function() {\n
    return {\n
        type: "Node_Expr_LogicalXor",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BitwiseAnd = function() {\n
    return {\n
        type: "Node_Expr_BitwiseAnd",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BitwiseOr = function() {\n
    return {\n
        type: "Node_Expr_BitwiseOr",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BitwiseNot = function() {\n
    return {\n
        type: "Node_Expr_BitwiseNot",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BooleanNot = function() {\n
    return {\n
        type: "Node_Expr_BooleanNot",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_BooleanAnd = function() {\n
    return {\n
        type: "Node_Expr_BooleanAnd",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Instanceof = function() {\n
\n
    return {\n
        type: "Node_Expr_Instanceof",\n
        left: arguments[ 0 ],\n
        right: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };\n
\n
};\n
\n
PHP.Parser.prototype.Node_Expr_Clone = function() {\n
\n
    return {\n
        type: "Node_Expr_Clone",\n
        expr: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };\n
\n
};\n
\n
\n
\n
PHP.Parser.prototype.Scalar_LNumber_parse = function( a ) {\n
   \n
    return a;  \n
};\n
\n
PHP.Parser.prototype.Scalar_DNumber_parse = function( a ) {\n
   \n
    return a;  \n
};\n
\n
PHP.Parser.prototype.Scalar_String_parseDocString = function() {\n
    \n
    return \'"\' + arguments[ 1 ].replace(/([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"/g, \'$1\\\\"\') + \'"\';\n
};\n
\n
\n
PHP.Parser.prototype.Node_Scalar_String = function( ) {\n
   \n
    return {\n
        type: "Node_Scalar_String",\n
        value: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Scalar_String_create = function( ) {\n
    return {\n
        type: "Node_Scalar_String",\n
        value: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
\n
};\n
\n
PHP.Parser.prototype.Node_Scalar_LNumber = function() {\n
   \n
    return {\n
        type: "Node_Scalar_LNumber",\n
        value: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
\n
PHP.Parser.prototype.Node_Scalar_DNumber = function() {\n
   \n
    return {\n
        type: "Node_Scalar_DNumber",\n
        value: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
\n
PHP.Parser.prototype.Node_Scalar_Encapsed = function() {\n
   \n
    return {\n
        type: "Node_Scalar_Encapsed",\n
        parts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Name = function() {\n
   \n
    return {\n
        type: "Node_Name",\n
        parts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Name_FullyQualified = function() {\n
   \n
    return {\n
        type: "Node_Name_FullyQualified",\n
        parts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Name_Relative = function() {\n
   \n
    return {\n
        type: "Node_Name_Relative",\n
        parts: arguments[ 0 ],\n
        attributes: arguments[ 1 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Param = function() {\n
   \n
    return {\n
        type: "Node_Param",\n
        name: arguments[ 0 ],\n
        def: arguments[ 1 ],\n
        Type: arguments[ 2 ],\n
        byRef: arguments[ 3 ],\n
        attributes: arguments[ 4 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Arg = function() {\n
   \n
    return {\n
        type: "Node_Name",\n
        value: arguments[ 0 ],\n
        byRef: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
  \n
};\n
\n
PHP.Parser.prototype.Node_Const = function() {\n
   \n
    return {\n
        type: "Node_Const",\n
        name: arguments[ 0 ],\n
        value: arguments[ 1 ],\n
        attributes: arguments[ 2 ]\n
    };  \n
  \n
};\n
\n
\n
exports.PHP = PHP;\n
});\n
</string> </value>
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
