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
            <value> <string>ts65545394.14</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery-ui-1.7.2.custom.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
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
            <value> <long>305667</long> </value>
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
      <tuple>
        <global name="Pdata" module="OFS.Image"/>
        <tuple/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI\n
 */\n
;jQuery.ui || (function($) {\n
\n
var _remove = $.fn.remove,\n
\tisFF2 = $.browser.mozilla && (parseFloat($.browser.version) < 1.9);\n
\n
//Helper functions and ui object\n
$.ui = {\n
\tversion: "1.7.2",\n
\n
\t// $.ui.plugin is deprecated.  Use the proxy pattern instead.\n
\tplugin: {\n
\t\tadd: function(module, option, set) {\n
\t\t\tvar proto = $.ui[module].prototype;\n
\t\t\tfor(var i in set) {\n
\t\t\t\tproto.plugins[i] = proto.plugins[i] || [];\n
\t\t\t\tproto.plugins[i].push([option, set[i]]);\n
\t\t\t}\n
\t\t},\n
\t\tcall: function(instance, name, args) {\n
\t\t\tvar set = instance.plugins[name];\n
\t\t\tif(!set || !instance.element[0].parentNode) { return; }\n
\n
\t\t\tfor (var i = 0; i < set.length; i++) {\n
\t\t\t\tif (instance.options[set[i][0]]) {\n
\t\t\t\t\tset[i][1].apply(instance.element, args);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\tcontains: function(a, b) {\n
\t\treturn document.compareDocumentPosition\n
\t\t\t? a.compareDocumentPosition(b) & 16\n
\t\t\t: a !== b && a.contains(b);\n
\t},\n
\n
\thasScroll: function(el, a) {\n
\n
\t\t//If overflow is hidden, the element might have extra content, but the user wants to hide it\n
\t\tif ($(el).css(\'overflow\') == \'hidden\') { return false; }\n
\n
\t\tvar scroll = (a && a == \'left\') ? \'scrollLeft\' : \'scrollTop\',\n
\t\t\thas = false;\n
\n
\t\tif (el[scroll] > 0) { return true; }\n
\n
\t\t// TODO: determine which cases actually cause this to happen\n
\t\t// if the element doesn\'t have the scroll set, see if it\'s possible to\n
\t\t// set the scroll\n
\t\tel[scroll] = 1;\n
\t\thas = (el[scroll] > 0);\n
\t\tel[scroll] = 0;\n
\t\treturn has;\n
\t},\n
\n
\tisOverAxis: function(x, reference, size) {\n
\t\t//Determines when x coordinate is over "b" element axis\n
\t\treturn (x > reference) && (x < (reference + size));\n
\t},\n
\n
\tisOver: function(y, x, top, left, height, width) {\n
\t\t//Determines when x, y coordinates is over "b" element\n
\t\treturn $.ui.isOverAxis(y, top, height) && $.ui.isOverAxis(x, left, width);\n
\t},\n
\n
\tkeyCode: {\n
\t\tBACKSPACE: 8,\n
\t\tCAPS_LOCK: 20,\n
\t\tCOMMA: 188,\n
\t\tCONTROL: 17,\n
\t\tDELETE: 46,\n
\t\tDOWN: 40,\n
\t\tEND: 35,\n
\t\tENTER: 13,\n
\t\tESCAPE: 27,\n
\t\tHOME: 36,\n
\t\tINSERT: 45,\n
\t\tLEFT: 37,\n
\t\tNUMPAD_ADD: 107,\n
\t\tNUMPAD_DECIMAL: 110,\n
\t\tNUMPAD_DIVIDE: 111,\n
\t\tNUMPAD_ENTER: 108,\n
\t\tNUMPAD_MULTIPLY: 106,\n
\t\tNUMPAD_SUBTRACT: 109,\n
\t\tPAGE_DOWN: 34,\n
\t\tPAGE_UP: 33,\n
\t\tPERIOD: 190,\n
\t\tRIGHT: 39,\n
\t\tSHIFT: 16,\n
\t\tSPACE: 32,\n
\t\tTAB: 9,\n
\t\tUP: 38\n
\t}\n
};\n
\n
// WAI-ARIA normalization\n
if (isFF2) {\n
\tvar attr = $.attr,\n
\t\tremoveAttr = $.fn.removeAttr,\n
\t\tariaNS = "http://www.w3.org/2005/07/aaa",\n
\t\tariaState = /^aria-/,\n
\t\tariaRole = /^wairole:/;\n
\n
\t$.attr = function(elem, name, value) {\n
\t\tvar set = value !== undefined;\n
\n
\t\treturn (name == \'role\'\n
\t\t\t? (set\n
\t\t\t\t? attr.call(this, elem, name, "wairole:" + value)\n
\t\t\t\t: (attr.apply(this, arguments) || "").replace(ariaRole, ""))\n
\t\t\t: (ariaState.test(name)\n
\t\t\t\t? (set\n
\t\t\t\t\t? elem.setAttributeNS(ariaNS,\n
\t\t\t\t\t\tname.replace(ariaState, "aaa:"), value)\n
\t\t\t\t\t: attr.call(this, elem, name.replace(ariaState, "aaa:")))\n
\t\t\t\t: attr.apply(this, arguments)));\n
\t};\n
\n
\t$.fn.removeAttr = function(name) {\n
\t\treturn (ariaState.test(name)\n
\t\t\t? this.each(function() {\n
\t\t\t\tthis.removeAttributeNS(ariaNS, name.replace(ariaState, ""));\n
\t\t\t}) : removeAttr.call(this, name));\n
\t};\n
}\n
\n
//jQuery plugins\n
$.fn.extend({\n
\tremove: function() {\n
\t\t// Safari has a native remove event which actually removes DOM elements,\n
\t\t// so we have to use triggerHandler instead of trigger (#3037).\n
\t\t$("*", this).add(this).each(function() {\n
\t\t\t$(this).triggerHandler("remove");\n
\t\t});\n
\t\treturn _remove.apply(this, arguments );\n
\t},\n
\n
\tenableSelection: function() {\n
\t\treturn this\n
\t\t\t.attr(\'unselectable\', \'off\')\n
\t\t\t.css(\'MozUserSelect\', \'\')\n
\t\t\t.unbind(\'selectstart.ui\');\n
\t},\n
\n
\tdisableSelection: function() {\n
\t\treturn this\n
\t\t\t.attr(\'unselectable\', \'on\')\n
\t\t\t.css(\'MozUserSelect\', \'none\')\n
\t\t\t.bind(\'selectstart.ui\', function() { return false; });\n
\t},\n
\n
\tscrollParent: function() {\n
\t\tvar scrollParent;\n
\t\tif(($.browser.msie && (/(static|relative)/).test(this.css(\'position\'))) || (/absolute/).test(this.css(\'position\'))) {\n
\t\t\tscrollParent = this.parents().filter(function() {\n
\t\t\t\treturn (/(relative|absolute|fixed)/).test($.curCSS(this,\'position\',1)) && (/(auto|scroll)/).test($.curCSS(this,\'overflow\',1)+$.curCSS(this,\'overflow-y\',1)+$.curCSS(this,\'overflow-x\',1));\n
\t\t\t}).eq(0);\n
\t\t} else {\n
\t\t\tscrollParent = this.parents().filter(function() {\n
\t\t\t\treturn (/(auto|scroll)/).test($.curCSS(this,\'overflow\',1)+$.curCSS(this,\'overflow-y\',1)+$.curCSS(this,\'overflow-x\',1));\n
\t\t\t}).eq(0);\n
\t\t}\n
\n
\t\treturn (/fixed/).test(this.css(\'position\')) || !scrollParent.length ? $(document) : scrollParent;\n
\t}\n
});\n
\n
\n
//Additional selectors\n
$.extend($.expr[\':\'], {\n
\tdata: function(elem, i, match) {\n
\t\treturn !!$.data(elem, match[3]);\n
\t},\n
\n
\tfocusable: function(element) {\n
\t\tvar nodeName = element.nodeName.toLowerCase(),\n
\t\t\ttabIndex = $.attr(element, \'tabindex\');\n
\t\treturn (/input|select|textarea|button|object/.test(nodeName)\n
\t\t\t? !element.disabled\n
\t\t\t: \'a\' == nodeName || \'area\' == nodeName\n
\t\t\t\t? element.href || !isNaN(tabIndex)\n
\t\t\t\t: !isNaN(tabIndex))\n
\t\t\t// the element and all of its ancestors must be visible\n
\t\t\t// the browser may report that the area is hidden\n
\t\t\t&& !$(element)[\'area\' == nodeName ? \'parents\' : \'closest\'](\':hidden\').length;\n
\t},\n
\n
\ttabbable: function(element) {\n
\t\tvar tabIndex = $.attr(element, \'tabindex\');\n
\t\treturn (isNaN(tabIndex) || tabIndex >= 0) && $(element).is(\':focusable\');\n
\t}\n
});\n
\n
\n
// $.widget is a factory to create jQuery plugins\n
// taking some boilerplate code out of the plugin code\n
function getter(namespace, plugin, method, args) {\n
\tfunction getMethods(type) {\n
\t\tvar methods = $[namespace][plugin][type] || [];\n
\t\treturn (typeof methods == \'string\' ? methods.split(/,?\\s+/) : methods);\n
\t}\n
\n
\tvar methods = getMethods(\'getter\');\n
\tif (args.length == 1 && typeof args[0] == \'string\') {\n
\t\tmethods = methods.concat(getMethods(\'getterSetter\'));\n
\t}\n
\treturn ($.inArray(method, methods) != -1);\n
}\n
\n
$.widget = function(name, prototype) {\n
\tvar namespace = name.split(".")[0];\n
\tname = name.split(".")[1];\n
\n
\t// create plugin method\n
\t$.fn[name] = function(options) {\n
\t\tvar isMethodCall = (typeof options == \'string\'),\n
\t\t\targs = Array.prototype.slice.call(arguments, 1);\n
\n
\t\t// prevent calls to internal methods\n
\t\tif (isMethodCall && options.substring(0, 1) == \'_\') {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// handle getter methods\n
\t\tif (isMethodCall && getter(namespace, name, options, args)) {\n
\t\t\tvar instance = $.data(this[0], name);\n
\t\t\treturn (instance ? instance[options].apply(instance, args)\n
\t\t\t\t: undefined);\n
\t\t}\n
\n
\t\t// handle initialization and non-getter methods\n
\t\treturn this.each(function() {\n
\t\t\tvar instance = $.data(this, name);\n
\n
\t\t\t// constructor\n
\t\t\t(!instance && !isMethodCall &&\n
\t\t\t\t$.data(this, name, new $[namespace][name](this, options))._init());\n
\n
\t\t\t// method call\n
\t\t\t(instance && isMethodCall && $.isFunction(instance[options]) &&\n
\t\t\t\tinstance[options].apply(instance, args));\n
\t\t});\n
\t};\n
\n
\t// create widget constructor\n
\t$[namespace] = $[namespace] || {};\n
\t$[namespace][name] = function(element, options) {\n
\t\tvar self = this;\n
\n
\t\tthis.namespace = namespace;\n
\t\tthis.widgetName = name;\n
\t\tthis.widgetEventPrefix = $[namespace][name].eventPrefix || name;\n
\t\tthis.widgetBaseClass = namespace + \'-\' + name;\n
\n
\t\tthis.options = $.extend({},\n
\t\t\t$.widget.defaults,\n
\t\t\t$[namespace][name].defaults,\n
\t\t\t$.metadata && $.metadata.get(element)[name],\n
\t\t\toptions);\n
\n
\t\tthis.element = $(element)\n
\t\t\t.bind(\'setData.\' + name, function(event, key, value) {\n
\t\t\t\tif (event.target == element) {\n
\t\t\t\t\treturn self._setData(key, value);\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t.bind(\'getData.\' + name, function(event, key) {\n
\t\t\t\tif (event.target == element) {\n
\t\t\t\t\treturn self._getData(key);\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t.bind(\'remove\', function() {\n
\t\t\t\treturn self.destroy();\n
\t\t\t});\n
\t};\n
\n
\t// add widget prototype\n
\t$[namespace][name].prototype = $.extend({}, $.widget.prototype, prototype);\n
\n
\t// TODO: merge getter and getterSetter properties from widget prototype\n
\t// and plugin prototype\n
\t$[namespace][name].getterSetter = \'option\';\n
};\n
\n
$.widget.prototype = {\n
\t_init: function() {},\n
\tdestroy: function() {\n
\t\tthis.element.removeData(this.widgetName)\n
\t\t\t.removeClass(this.widgetBaseClass + \'-disabled\' + \' \' + this.namespace + \'-state-disabled\')\n
\t\t\t.removeAttr(\'aria-disabled\');\n
\t},\n
\n
\toption: function(key, value) {\n
\t\tvar options = key,\n
\t\t\tself = this;\n
\n
\t\tif (typeof key == "string") {\n
\t\t\tif (value === undefined) {\n
\t\t\t\treturn this._getData(key);\n
\t\t\t}\n
\t\t\toptions = {};\n
\t\t\toptions[key] = value;\n
\t\t}\n
\n
\t\t$.each(options, function(key, value) {\n
\t\t\tself._setData(key, value);\n
\t\t});\n
\t},\n
\t_getData: function(key) {\n
\t\treturn this.options[key];\n
\t},\n
\t_setData: function(key, value) {\n
\t\tthis.options[key] = value;\n
\n
\t\tif (key == \'disabled\') {\n
\t\t\tthis.element\n
\t\t\t\t[value ? \'addClass\' : \'removeClass\'](\n
\t\t\t\t\tthis.widgetBaseClass + \'-disabled\' + \' \' +\n
\t\t\t\t\tthis.namespace + \'-state-disabled\')\n
\t\t\t\t.attr("aria-disabled", value);\n
\t\t}\n
\t},\n
\n
\tenable: function() {\n
\t\tthis._setData(\'disabled\', false);\n
\t},\n
\tdisable: function() {\n
\t\tthis._setData(\'disabled\', true);\n
\t},\n
\n
\t_trigger: function(type, event, data) {\n
\t\tvar callback = this.options[type],\n
\t\t\teventName = (type == this.widgetEventPrefix\n
\t\t\t\t? type : this.widgetEventPrefix + type);\n
\n
\t\tevent = $.Event(event);\n
\t\tevent.type = eventName;\n
\n
\t\t// copy original event properties over to the new event\n
\t\t// this would happen if we could call $.event.fix instead of $.Event\n
\t\t// but we don\'t have a way to force an event to be fixed multiple times\n
\t\tif (event.originalEvent) {\n
\t\t\tfor (var i = $.event.props.length, prop; i;) {\n
\t\t\t\tprop = $.event.props[--i];\n
\t\t\t\tevent[prop] = event.originalEvent[prop];\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.element.trigger(event, data);\n
\n
\t\treturn !($.isFunction(callback) && callback.call(this.element[0], event, data) === false\n
\t\t\t|| event.isDefaultPrevented());\n
\t}\n
};\n
\n
$.widget.defaults = {\n
\tdisabled: false\n
};\n
\n
\n
/** Mouse Interaction Plugin **/\n
\n
$.ui.mouse = {\n
\t_mouseInit: function() {\n
\t\tvar self = this;\n
\n
\t\tthis.element\n
\t\t\t.bind(\'mousedown.\'+this.widgetName, function(event) {\n
\t\t\t\treturn self._mouseDown(event);\n
\t\t\t})\n
\t\t\t.bind(\'click.\'+this.widgetName, function(event) {\n
\t\t\t\tif(self._preventClickEvent) {\n
\t\t\t\t\tself._preventClickEvent = false;\n
\t\t\t\t\tevent.stopImmediatePropagation();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t// Prevent text selection in IE\n
\t\tif ($.browser.msie) {\n
\t\t\tthis._mouseUnselectable = this.element.attr(\'unselectable\');\n
\t\t\tthis.element.attr(\'unselectable\', \'on\');\n
\t\t}\n
\n
\t\tthis.started = false;\n
\t},\n
\n
\t// TODO: make sure destroying one instance of mouse doesn\'t mess with\n
\t// other instances of mouse\n
\t_mouseDestroy: function() {\n
\t\tthis.element.unbind(\'.\'+this.widgetName);\n
\n
\t\t// Restore text selection in IE\n
\t\t($.browser.msie\n
\t\t\t&& this.element.attr(\'unselectable\', this._mouseUnselectable));\n
\t},\n
\n
\t_mouseDown: function(event) {\n
\t\t// don\'t let more than one widget handle mouseStart\n
\t\t// TODO: figure out why we have to use originalEvent\n
\t\tevent.originalEvent = event.originalEvent || {};\n
\t\tif (event.originalEvent.mouseHandled) { return; }\n
\n
\t\t// we may have missed mouseup (out of window)\n
\t\t(this._mouseStarted && this._mouseUp(event));\n
\n
\t\tthis._mouseDownEvent = event;\n
\n
\t\tvar self = this,\n
\t\t\tbtnIsLeft = (event.which == 1),\n
\t\t\telIsCancel = (typeof this.options.cancel == "string" ? $(event.target).parents().add(event.target).filter(this.options.cancel).length : false);\n
\t\tif (!btnIsLeft || elIsCancel || !this._mouseCapture(event)) {\n
\t\t\treturn true;\n
\t\t}\n
\n
\t\tthis.mouseDelayMet = !this.options.delay;\n
\t\tif (!this.mouseDelayMet) {\n
\t\t\tthis._mouseDelayTimer = setTimeout(function() {\n
\t\t\t\tself.mouseDelayMet = true;\n
\t\t\t}, this.options.delay);\n
\t\t}\n
\n
\t\tif (this._mouseDistanceMet(event) && this._mouseDelayMet(event)) {\n
\t\t\tthis._mouseStarted = (this._mouseStart(event) !== false);\n
\t\t\tif (!this._mouseStarted) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// these delegates are required to keep context\n
\t\tthis._mouseMoveDelegate = function(event) {\n
\t\t\treturn self._mouseMove(event);\n
\t\t};\n
\t\tthis._mouseUpDelegate = function(event) {\n
\t\t\treturn self._mouseUp(event);\n
\t\t};\n
\t\t$(document)\n
\t\t\t.bind(\'mousemove.\'+this.widgetName, this._mouseMoveDelegate)\n
\t\t\t.bind(\'mouseup.\'+this.widgetName, this._mouseUpDelegate);\n
\n
\t\t// preventDefault() is used to prevent the selection of text here -\n
\t\t// however, in Safari, this causes select boxes not to be selectable\n
\t\t// anymore, so this fix is needed\n
\t\t($.browser.safari || event.preventDefault());\n
\n
\t\tevent.originalEvent.mouseHandled = true;\n
\t\treturn true;\n
\t},\n
\n
\t_mouseMove: function(event) {\n
\t\t// IE mouseup check - mouseup happened when mouse was out of window\n
\t\tif ($.browser.msie && !event.button) {\n
\t\t\treturn this._mouseUp(event);\n
\t\t}\n
\n
\t\tif (this._mouseStarted) {\n
\t\t\tthis._mouseDrag(event);\n
\t\t\treturn event.preventDefault();\n
\t\t}\n
\n
\t\tif (this._mouseDistanceMet(event) && this._mouseDelayMet(event)) {\n
\t\t\tthis._mouseStarted =\n
\t\t\t\t(this._mouseStart(this._mouseDownEvent, event) !== false);\n
\t\t\t(this._mouseStarted ? this._mouseDrag(event) : this._mouseUp(event));\n
\t\t}\n
\n
\t\treturn !this._mouseStarted;\n
\t},\n
\n
\t_mouseUp: function(event) {\n
\t\t$(document)\n
\t\t\t.unbind(\'mousemove.\'+this.widgetName, this._mouseMoveDelegate)\n
\t\t\t.unbind(\'mouseup.\'+this.widgetName, this._mouseUpDelegate);\n
\n
\t\tif (this._mouseStarted) {\n
\t\t\tthis._mouseStarted = false;\n
\t\t\tthis._preventClickEvent = (event.target == this._mouseDownEvent.target);\n
\t\t\tthis._mouseStop(event);\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseDistanceMet: function(event) {\n
\t\treturn (Math.max(\n
\t\t\t\tMath.abs(this._mouseDownEvent.pageX - event.pageX),\n
\t\t\t\tMath.abs(this._mouseDownEvent.pageY - event.pageY)\n
\t\t\t) >= this.options.distance\n
\t\t);\n
\t},\n
\n
\t_mouseDelayMet: function(event) {\n
\t\treturn this.mouseDelayMet;\n
\t},\n
\n
\t// These are placeholder methods, to be overriden by extending plugin\n
\t_mouseStart: function(event) {},\n
\t_mouseDrag: function(event) {},\n
\t_mouseStop: function(event) {},\n
\t_mouseCapture: function(event) { return true; }\n
};\n
\n
$.ui.mouse.defaults = {\n
\tcancel: null,\n
\tdistance: 1,\n
\tdelay: 0\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Draggable 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Draggables\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.draggable", $.extend({}, $.ui.mouse, {\n
\n
\t_init: function() {\n
\n
\t\tif (this.options.helper == \'original\' && !(/^(?:r|a|f)/).test(this.element.css("position")))\n
\t\t\tthis.element[0].style.position = \'relative\';\n
\n
\t\t(this.options.addClasses && this.element.addClass("ui-draggable"));\n
\t\t(this.options.disabled && this.element.addClass("ui-draggable-disabled"));\n
\n
\t\tthis._mouseInit();\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tif(!this.element.data(\'draggable\')) return;\n
\t\tthis.element\n
\t\t\t.removeData("draggable")\n
\t\t\t.unbind(".draggable")\n
\t\t\t.removeClass("ui-draggable"\n
\t\t\t\t+ " ui-draggable-dragging"\n
\t\t\t\t+ " ui-draggable-disabled");\n
\t\tthis._mouseDestroy();\n
\t},\n
\n
\t_mouseCapture: function(event) {\n
\n
\t\tvar o = this.options;\n
\n
\t\tif (this.helper || o.disabled || $(event.target).is(\'.ui-resizable-handle\'))\n
\t\t\treturn false;\n
\n
\t\t//Quit if we\'re not on a valid handle\n
\t\tthis.handle = this._getHandle(event);\n
\t\tif (!this.handle)\n
\t\t\treturn false;\n
\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\n
\t\tvar o = this.options;\n
\n
\t\t//Create and append the visible helper\n
\t\tthis.helper = this._createHelper(event);\n
\n
\t\t//Cache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t//If ddmanager is used for droppables, set the global draggable\n
\t\tif($.ui.ddmanager)\n
\t\t\t$.ui.ddmanager.current = this;\n
\n
\t\t/*\n
\t\t * - Position generation -\n
\t\t * This block generates everything position related - it\'s the core of draggables.\n
\t\t */\n
\n
\t\t//Cache the margins of the original element\n
\t\tthis._cacheMargins();\n
\n
\t\t//Store the helper\'s css position\n
\t\tthis.cssPosition = this.helper.css("position");\n
\t\tthis.scrollParent = this.helper.scrollParent();\n
\n
\t\t//The element\'s absolute position on the page minus margins\n
\t\tthis.offset = this.element.offset();\n
\t\tthis.offset = {\n
\t\t\ttop: this.offset.top - this.margins.top,\n
\t\t\tleft: this.offset.left - this.margins.left\n
\t\t};\n
\n
\t\t$.extend(this.offset, {\n
\t\t\tclick: { //Where the click happened, relative to the element\n
\t\t\t\tleft: event.pageX - this.offset.left,\n
\t\t\t\ttop: event.pageY - this.offset.top\n
\t\t\t},\n
\t\t\tparent: this._getParentOffset(),\n
\t\t\trelative: this._getRelativeOffset() //This is a relative to absolute position minus the actual position calculation - only used for relative positioned helper\n
\t\t});\n
\n
\t\t//Generate the original position\n
\t\tthis.originalPosition = this._generatePosition(event);\n
\t\tthis.originalPageX = event.pageX;\n
\t\tthis.originalPageY = event.pageY;\n
\n
\t\t//Adjust the mouse offset relative to the helper if \'cursorAt\' is supplied\n
\t\tif(o.cursorAt)\n
\t\t\tthis._adjustOffsetFromHelper(o.cursorAt);\n
\n
\t\t//Set a containment if given in the options\n
\t\tif(o.containment)\n
\t\t\tthis._setContainment();\n
\n
\t\t//Call plugins and callbacks\n
\t\tthis._trigger("start", event);\n
\n
\t\t//Recache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t//Prepare the droppable offsets\n
\t\tif ($.ui.ddmanager && !o.dropBehaviour)\n
\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\n
\t\tthis.helper.addClass("ui-draggable-dragging");\n
\t\tthis._mouseDrag(event, true); //Execute the drag once - this causes the helper not to be visible before getting its correct position\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function(event, noPropagation) {\n
\n
\t\t//Compute the helpers position\n
\t\tthis.position = this._generatePosition(event);\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\t//Call plugins and callbacks and use the resulting position if something is returned\n
\t\tif (!noPropagation) {\n
\t\t\tvar ui = this._uiHash();\n
\t\t\tthis._trigger(\'drag\', event, ui);\n
\t\t\tthis.position = ui.position;\n
\t\t}\n
\n
\t\tif(!this.options.axis || this.options.axis != "y") this.helper[0].style.left = this.position.left+\'px\';\n
\t\tif(!this.options.axis || this.options.axis != "x") this.helper[0].style.top = this.position.top+\'px\';\n
\t\tif($.ui.ddmanager) $.ui.ddmanager.drag(this, event);\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\n
\t\t//If we are using droppables, inform the manager about the drop\n
\t\tvar dropped = false;\n
\t\tif ($.ui.ddmanager && !this.options.dropBehaviour)\n
\t\t\tdropped = $.ui.ddmanager.drop(this, event);\n
\n
\t\t//if a drop comes from outside (a sortable)\n
\t\tif(this.dropped) {\n
\t\t\tdropped = this.dropped;\n
\t\t\tthis.dropped = false;\n
\t\t}\n
\n
\t\tif((this.options.revert == "invalid" && !dropped) || (this.options.revert == "valid" && dropped) || this.options.revert === true || ($.isFunction(this.options.revert) && this.options.revert.call(this.element, dropped))) {\n
\t\t\tvar self = this;\n
\t\t\t$(this.helper).animate(this.originalPosition, parseInt(this.options.revertDuration, 10), function() {\n
\t\t\t\tself._trigger("stop", event);\n
\t\t\t\tself._clear();\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis._trigger("stop", event);\n
\t\t\tthis._clear();\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\t_getHandle: function(event) {\n
\n
\t\tvar handle = !this.options.handle || !$(this.options.handle, this.element).length ? true : false;\n
\t\t$(this.options.handle, this.element)\n
\t\t\t.find("*")\n
\t\t\t.andSelf()\n
\t\t\t.each(function() {\n
\t\t\t\tif(this == event.target) handle = true;\n
\t\t\t});\n
\n
\t\treturn handle;\n
\n
\t},\n
\n
\t_createHelper: function(event) {\n
\n
\t\tvar o = this.options;\n
\t\tvar helper = $.isFunction(o.helper) ? $(o.helper.apply(this.element[0], [event])) : (o.helper == \'clone\' ? this.element.clone() : this.element);\n
\n
\t\tif(!helper.parents(\'body\').length)\n
\t\t\thelper.appendTo((o.appendTo == \'parent\' ? this.element[0].parentNode : o.appendTo));\n
\n
\t\tif(helper[0] != this.element[0] && !(/(fixed|absolute)/).test(helper.css("position")))\n
\t\t\thelper.css("position", "absolute");\n
\n
\t\treturn helper;\n
\n
\t},\n
\n
\t_adjustOffsetFromHelper: function(obj) {\n
\t\tif(obj.left != undefined) this.offset.click.left = obj.left + this.margins.left;\n
\t\tif(obj.right != undefined) this.offset.click.left = this.helperProportions.width - obj.right + this.margins.left;\n
\t\tif(obj.top != undefined) this.offset.click.top = obj.top + this.margins.top;\n
\t\tif(obj.bottom != undefined) this.offset.click.top = this.helperProportions.height - obj.bottom + this.margins.top;\n
\t},\n
\n
\t_getParentOffset: function() {\n
\n
\t\t//Get the offsetParent and cache its position\n
\t\tthis.offsetParent = this.helper.offsetParent();\n
\t\tvar po = this.offsetParent.offset();\n
\n
\t\t// This is a special case where we need to modify a offset calculated on start, since the following happened:\n
\t\t// 1. The position of the helper is absolute, so it\'s position is calculated based on the next positioned parent\n
\t\t// 2. The actual offset parent is a child of the scroll parent, and the scroll parent isn\'t the document, which means that\n
\t\t//    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag\n
\t\tif(this.cssPosition == \'absolute\' && this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) {\n
\t\t\tpo.left += this.scrollParent.scrollLeft();\n
\t\t\tpo.top += this.scrollParent.scrollTop();\n
\t\t}\n
\n
\t\tif((this.offsetParent[0] == document.body) //This needs to be actually done for all browsers, since pageX/pageY includes this information\n
\t\t|| (this.offsetParent[0].tagName && this.offsetParent[0].tagName.toLowerCase() == \'html\' && $.browser.msie)) //Ugly IE fix\n
\t\t\tpo = { top: 0, left: 0 };\n
\n
\t\treturn {\n
\t\t\ttop: po.top + (parseInt(this.offsetParent.css("borderTopWidth"),10) || 0),\n
\t\t\tleft: po.left + (parseInt(this.offsetParent.css("borderLeftWidth"),10) || 0)\n
\t\t};\n
\n
\t},\n
\n
\t_getRelativeOffset: function() {\n
\n
\t\tif(this.cssPosition == "relative") {\n
\t\t\tvar p = this.element.position();\n
\t\t\treturn {\n
\t\t\t\ttop: p.top - (parseInt(this.helper.css("top"),10) || 0) + this.scrollParent.scrollTop(),\n
\t\t\t\tleft: p.left - (parseInt(this.helper.css("left"),10) || 0) + this.scrollParent.scrollLeft()\n
\t\t\t};\n
\t\t} else {\n
\t\t\treturn { top: 0, left: 0 };\n
\t\t}\n
\n
\t},\n
\n
\t_cacheMargins: function() {\n
\t\tthis.margins = {\n
\t\t\tleft: (parseInt(this.element.css("marginLeft"),10) || 0),\n
\t\t\ttop: (parseInt(this.element.css("marginTop"),10) || 0)\n
\t\t};\n
\t},\n
\n
\t_cacheHelperProportions: function() {\n
\t\tthis.helperProportions = {\n
\t\t\twidth: this.helper.outerWidth(),\n
\t\t\theight: this.helper.outerHeight()\n
\t\t};\n
\t},\n
\n
\t_setContainment: function() {\n
\n
\t\tvar o = this.options;\n
\t\tif(o.containment == \'parent\') o.containment = this.helper[0].parentNode;\n
\t\tif(o.containment == \'document\' || o.containment == \'window\') this.containment = [\n
\t\t\t0 - this.offset.relative.left - this.offset.parent.left,\n
\t\t\t0 - this.offset.relative.top - this.offset.parent.top,\n
\t\t\t$(o.containment == \'document\' ? document : window).width() - this.helperProportions.width - this.margins.left,\n
\t\t\t($(o.containment == \'document\' ? document : window).height() || document.body.parentNode.scrollHeight) - this.helperProportions.height - this.margins.top\n
\t\t];\n
\n
\t\tif(!(/^(document|window|parent)$/).test(o.containment) && o.containment.constructor != Array) {\n
\t\t\tvar ce = $(o.containment)[0]; if(!ce) return;\n
\t\t\tvar co = $(o.containment).offset();\n
\t\t\tvar over = ($(ce).css("overflow") != \'hidden\');\n
\n
\t\t\tthis.containment = [\n
\t\t\t\tco.left + (parseInt($(ce).css("borderLeftWidth"),10) || 0) + (parseInt($(ce).css("paddingLeft"),10) || 0) - this.margins.left,\n
\t\t\t\tco.top + (parseInt($(ce).css("borderTopWidth"),10) || 0) + (parseInt($(ce).css("paddingTop"),10) || 0) - this.margins.top,\n
\t\t\t\tco.left+(over ? Math.max(ce.scrollWidth,ce.offsetWidth) : ce.offsetWidth) - (parseInt($(ce).css("borderLeftWidth"),10) || 0) - (parseInt($(ce).css("paddingRight"),10) || 0) - this.helperProportions.width - this.margins.left,\n
\t\t\t\tco.top+(over ? Math.max(ce.scrollHeight,ce.offsetHeight) : ce.offsetHeight) - (parseInt($(ce).css("borderTopWidth"),10) || 0) - (parseInt($(ce).css("paddingBottom"),10) || 0) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t} else if(o.containment.constructor == Array) {\n
\t\t\tthis.containment = o.containment;\n
\t\t}\n
\n
\t},\n
\n
\t_convertPositionTo: function(d, pos) {\n
\n
\t\tif(!pos) pos = this.position;\n
\t\tvar mod = d == "absolute" ? 1 : -1;\n
\t\tvar o = this.options, scroll = this.cssPosition == \'absolute\' && !(this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent, scrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpos.top\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t+ this.offset.relative.top * mod\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t+ this.offset.parent.top * mod\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t- ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ) * mod)\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpos.left\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t+ this.offset.relative.left * mod\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t+ this.offset.parent.left * mod\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t- ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ) * mod)\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_generatePosition: function(event) {\n
\n
\t\tvar o = this.options, scroll = this.cssPosition == \'absolute\' && !(this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent, scrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\t// This is another very weird special case that only happens for relative elements:\n
\t\t// 1. If the css position is relative\n
\t\t// 2. and the scroll parent is the document or similar to the offset parent\n
\t\t// we have to refresh the relative offset during the scroll so there are no jumps\n
\t\tif(this.cssPosition == \'relative\' && !(this.scrollParent[0] != document && this.scrollParent[0] != this.offsetParent[0])) {\n
\t\t\tthis.offset.relative = this._getRelativeOffset();\n
\t\t}\n
\n
\t\tvar pageX = event.pageX;\n
\t\tvar pageY = event.pageY;\n
\n
\t\t/*\n
\t\t * - Position constraining -\n
\t\t * Constrain the position to a mix of grid, containment.\n
\t\t */\n
\n
\t\tif(this.originalPosition) { //If we are not dragging yet, we won\'t check for options\n
\n
\t\t\tif(this.containment) {\n
\t\t\t\tif(event.pageX - this.offset.click.left < this.containment[0]) pageX = this.containment[0] + this.offset.click.left;\n
\t\t\t\tif(event.pageY - this.offset.click.top < this.containment[1]) pageY = this.containment[1] + this.offset.click.top;\n
\t\t\t\tif(event.pageX - this.offset.click.left > this.containment[2]) pageX = this.containment[2] + this.offset.click.left;\n
\t\t\t\tif(event.pageY - this.offset.click.top > this.containment[3]) pageY = this.containment[3] + this.offset.click.top;\n
\t\t\t}\n
\n
\t\t\tif(o.grid) {\n
\t\t\t\tvar top = this.originalPageY + Math.round((pageY - this.originalPageY) / o.grid[1]) * o.grid[1];\n
\t\t\t\tpageY = this.containment ? (!(top - this.offset.click.top < this.containment[1] || top - this.offset.click.top > this.containment[3]) ? top : (!(top - this.offset.click.top < this.containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;\n
\n
\t\t\t\tvar left = this.originalPageX + Math.round((pageX - this.originalPageX) / o.grid[0]) * o.grid[0];\n
\t\t\t\tpageX = this.containment ? (!(left - this.offset.click.left < this.containment[0] || left - this.offset.click.left > this.containment[2]) ? left : (!(left - this.offset.click.left < this.containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpageY\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t- this.offset.click.top\t\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\t- this.offset.relative.top\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t- this.offset.parent.top\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t+ ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ))\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpageX\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t- this.offset.click.left\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\t- this.offset.relative.left\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t- this.offset.parent.left\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t+ ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ))\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_clear: function() {\n
\t\tthis.helper.removeClass("ui-draggable-dragging");\n
\t\tif(this.helper[0] != this.element[0] && !this.cancelHelperRemoval) this.helper.remove();\n
\t\t//if($.ui.ddmanager) $.ui.ddmanager.current = null;\n
\t\tthis.helper = null;\n
\t\tthis.cancelHelperRemoval = false;\n
\t},\n
\n
\t// From now on bulk stuff - mainly helpers\n
\n
\t_trigger: function(type, event, ui) {\n
\t\tui = ui || this._uiHash();\n
\t\t$.ui.plugin.call(this, type, [event, ui]);\n
\t\tif(type == "drag") this.positionAbs = this._convertPositionTo("absolute"); //The absolute position has to be recalculated after plugins\n
\t\treturn $.widget.prototype._trigger.call(this, type, event, ui);\n
\t},\n
\n
\tplugins: {},\n
\n
\t_uiHash: function(event) {\n
\t\treturn {\n
\t\t\thelper: this.helper,\n
\t\t\tposition: this.position,\n
\t\t\tabsolutePosition: this.positionAbs, //deprecated\n
\t\t\toffset: this.positionAbs\n
\t\t};\n
\t}\n
\n
}));\n
\n
$.extend($.ui.draggable, {\n
\tversion: "1.7.2",\n
\teventPrefix: "drag",\n
\tdefaults: {\n
\t\taddClasses: true,\n
\t\tappendTo: "parent",\n
\t\taxis: false,\n
\t\tcancel: ":input,option",\n
\t\tconnectToSortable: false,\n
\t\tcontainment: false,\n
\t\tcursor: "auto",\n
\t\tcursorAt: false,\n
\t\tdelay: 0,\n
\t\tdistance: 1,\n
\t\tgrid: false,\n
\t\thandle: false,\n
\t\thelper: "original",\n
\t\tiframeFix: false,\n
\t\topacity: false,\n
\t\trefreshPositions: false,\n
\t\trevert: false,\n
\t\trevertDuration: 500,\n
\t\tscope: "default",\n
\t\tscroll: true,\n
\t\tscrollSensitivity: 20,\n
\t\tscrollSpeed: 20,\n
\t\tsnap: false,\n
\t\tsnapMode: "both",\n
\t\tsnapTolerance: 20,\n
\t\tstack: false,\n
\t\tzIndex: false\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "connectToSortable", {\n
\tstart: function(event, ui) {\n
\n
\t\tvar inst = $(this).data("draggable"), o = inst.options,\n
\t\t\tuiSortable = $.extend({}, ui, { item: inst.element });\n
\t\tinst.sortables = [];\n
\t\t$(o.connectToSortable).each(function() {\n
\t\t\tvar sortable = $.data(this, \'sortable\');\n
\t\t\tif (sortable && !sortable.options.disabled) {\n
\t\t\t\tinst.sortables.push({\n
\t\t\t\t\tinstance: sortable,\n
\t\t\t\t\tshouldRevert: sortable.options.revert\n
\t\t\t\t});\n
\t\t\t\tsortable._refreshItems();\t//Do a one-time refresh at start to refresh the containerCache\n
\t\t\t\tsortable._trigger("activate", event, uiSortable);\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\tstop: function(event, ui) {\n
\n
\t\t//If we are still over the sortable, we fake the stop event of the sortable, but also remove helper\n
\t\tvar inst = $(this).data("draggable"),\n
\t\t\tuiSortable = $.extend({}, ui, { item: inst.element });\n
\n
\t\t$.each(inst.sortables, function() {\n
\t\t\tif(this.instance.isOver) {\n
\n
\t\t\t\tthis.instance.isOver = 0;\n
\n
\t\t\t\tinst.cancelHelperRemoval = true; //Don\'t remove the helper in the draggable instance\n
\t\t\t\tthis.instance.cancelHelperRemoval = false; //Remove it in the sortable instance (so sortable plugins like revert still work)\n
\n
\t\t\t\t//The sortable revert is supported, and we have to set a temporary dropped variable on the draggable to support revert: \'valid/invalid\'\n
\t\t\t\tif(this.shouldRevert) this.instance.options.revert = true;\n
\n
\t\t\t\t//Trigger the stop of the sortable\n
\t\t\t\tthis.instance._mouseStop(event);\n
\n
\t\t\t\tthis.instance.options.helper = this.instance.options._helper;\n
\n
\t\t\t\t//If the helper has been the original item, restore properties in the sortable\n
\t\t\t\tif(inst.options.helper == \'original\')\n
\t\t\t\t\tthis.instance.currentItem.css({ top: \'auto\', left: \'auto\' });\n
\n
\t\t\t} else {\n
\t\t\t\tthis.instance.cancelHelperRemoval = false; //Remove the helper in the sortable instance\n
\t\t\t\tthis.instance._trigger("deactivate", event, uiSortable);\n
\t\t\t}\n
\n
\t\t});\n
\n
\t},\n
\tdrag: function(event, ui) {\n
\n
\t\tvar inst = $(this).data("draggable"), self = this;\n
\n
\t\tvar checkPos = function(o) {\n
\t\t\tvar dyClick = this.offset.click.top, dxClick = this.offset.click.left;\n
\t\t\tvar helperTop = this.positionAbs.top, helperLeft = this.positionAbs.left;\n
\t\t\tvar itemHeight = o.height, itemWidth = o.width;\n
\t\t\tvar itemTop = o.top, itemLeft = o.left;\n
\n
\t\t\treturn $.ui.isOver(helperTop + dyClick, helperLeft + dxClick, itemTop, itemLeft, itemHeight, itemWidth);\n
\t\t};\n
\n
\t\t$.each(inst.sortables, function(i) {\n
\t\t\t\n
\t\t\t//Copy over some variables to allow calling the sortable\'s native _intersectsWith\n
\t\t\tthis.instance.positionAbs = inst.positionAbs;\n
\t\t\tthis.instance.helperProportions = inst.helperProportions;\n
\t\t\tthis.instance.offset.click = inst.offset.click;\n
\t\t\t\n
\t\t\tif(this.instance._intersectsWith(this.instance.containerCache)) {\n
\n
\t\t\t\t//If it intersects, we use a little isOver variable and set it once, so our move-in stuff gets fired only once\n
\t\t\t\tif(!this.instance.isOver) {\n
\n
\t\t\t\t\tthis.instance.isOver = 1;\n
\t\t\t\t\t//Now we fake the start of dragging for the sortable instance,\n
\t\t\t\t\t//by cloning the list group item, appending it to the sortable and using it as inst.currentItem\n
\t\t\t\t\t//We can then fire the start event of the sortable with our passed browser event, and our own helper (so it doesn\'t create a new one)\n
\t\t\t\t\tthis.instance.currentItem = $(self).clone().appendTo(this.instance.element).data("sortable-item", true);\n
\t\t\t\t\tthis.instance.options._helper = this.instance.options.helper; //Store helper option to later restore it\n
\t\t\t\t\tthis.instance.options.helper = function() { return ui.helper[0]; };\n
\n
\t\t\t\t\tevent.target = this.instance.currentItem[0];\n
\t\t\t\t\tthis.instance._mouseCapture(event, true);\n
\t\t\t\t\tthis.instance._mouseStart(event, true, true);\n
\n
\t\t\t\t\t//Because the browser event is way off the new appended portlet, we modify a couple of variables to reflect the changes\n
\t\t\t\t\tthis.instance.offset.click.top = inst.offset.click.top;\n
\t\t\t\t\tthis.instance.offset.click.left = inst.offset.click.left;\n
\t\t\t\t\tthis.instance.offset.parent.left -= inst.offset.parent.left - this.instance.offset.parent.left;\n
\t\t\t\t\tthis.instance.offset.parent.top -= inst.offset.parent.top - this.instance.offset.parent.top;\n
\n
\t\t\t\t\tinst._trigger("toSortable", event);\n
\t\t\t\t\tinst.dropped = this.instance.element; //draggable revert needs that\n
\t\t\t\t\t//hack so receive/update callbacks work (mostly)\n
\t\t\t\t\tinst.currentItem = inst.element;\n
\t\t\t\t\tthis.instance.fromOutside = inst;\n
\n
\t\t\t\t}\n
\n
\t\t\t\t//Provided we did all the previous steps, we can fire the drag event of the sortable on every draggable drag, when it intersects with the sortable\n
\t\t\t\tif(this.instance.currentItem) this.instance._mouseDrag(event);\n
\n
\t\t\t} else {\n
\n
\t\t\t\t//If it doesn\'t intersect with the sortable, and it intersected before,\n
\t\t\t\t//we fake the drag stop of the sortable, but make sure it doesn\'t remove the helper by using cancelHelperRemoval\n
\t\t\t\tif(this.instance.isOver) {\n
\n
\t\t\t\t\tthis.instance.isOver = 0;\n
\t\t\t\t\tthis.instance.cancelHelperRemoval = true;\n
\t\t\t\t\t\n
\t\t\t\t\t//Prevent reverting on this forced stop\n
\t\t\t\t\tthis.instance.options.revert = false;\n
\t\t\t\t\t\n
\t\t\t\t\t// The out event needs to be triggered independently\n
\t\t\t\t\tthis.instance._trigger(\'out\', event, this.instance._uiHash(this.instance));\n
\t\t\t\t\t\n
\t\t\t\t\tthis.instance._mouseStop(event, true);\n
\t\t\t\t\tthis.instance.options.helper = this.instance.options._helper;\n
\n
\t\t\t\t\t//Now we remove our currentItem, the list group clone again, and the placeholder, and animate the helper back to it\'s original size\n
\t\t\t\t\tthis.instance.currentItem.remove();\n
\t\t\t\t\tif(this.instance.placeholder) this.instance.placeholder.remove();\n
\n
\t\t\t\t\tinst._trigger("fromSortable", event);\n
\t\t\t\t\tinst.dropped = false; //draggable revert needs that\n
\t\t\t\t}\n
\n
\t\t\t};\n
\n
\t\t});\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "cursor", {\n
\tstart: function(event, ui) {\n
\t\tvar t = $(\'body\'), o = $(this).data(\'draggable\').options;\n
\t\tif (t.css("cursor")) o._cursor = t.css("cursor");\n
\t\tt.css("cursor", o.cursor);\n
\t},\n
\tstop: function(event, ui) {\n
\t\tvar o = $(this).data(\'draggable\').options;\n
\t\tif (o._cursor) $(\'body\').css("cursor", o._cursor);\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "iframeFix", {\n
\tstart: function(event, ui) {\n
\t\tvar o = $(this).data(\'draggable\').options;\n
\t\t$(o.iframeFix === true ? "iframe" : o.iframeFix).each(function() {\n
\t\t\t$(\'<div class="ui-draggable-iframeFix" style="background: #fff;"></div>\')\n
\t\t\t.css({\n
\t\t\t\twidth: this.offsetWidth+"px", height: this.offsetHeight+"px",\n
\t\t\t\tposition: "absolute", opacity: "0.001", zIndex: 1000\n
\t\t\t})\n
\t\t\t.css($(this).offset())\n
\t\t\t.appendTo("body");\n
\t\t});\n
\t},\n
\tstop: function(event, ui) {\n
\t\t$("div.ui-draggable-iframeFix").each(function() { this.parentNode.removeChild(this); }); //Remove frame helpers\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "opacity", {\n
\tstart: function(event, ui) {\n
\t\tvar t = $(ui.helper), o = $(this).data(\'draggable\').options;\n
\t\tif(t.css("opacity")) o._opacity = t.css("opacity");\n
\t\tt.css(\'opacity\', o.opacity);\n
\t},\n
\tstop: function(event, ui) {\n
\t\tvar o = $(this).data(\'draggable\').options;\n
\t\tif(o._opacity) $(ui.helper).css(\'opacity\', o._opacity);\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "scroll", {\n
\tstart: function(event, ui) {\n
\t\tvar i = $(this).data("draggable");\n
\t\tif(i.scrollParent[0] != document && i.scrollParent[0].tagName != \'HTML\') i.overflowOffset = i.scrollParent.offset();\n
\t},\n
\tdrag: function(event, ui) {\n
\n
\t\tvar i = $(this).data("draggable"), o = i.options, scrolled = false;\n
\n
\t\tif(i.scrollParent[0] != document && i.scrollParent[0].tagName != \'HTML\') {\n
\n
\t\t\tif(!o.axis || o.axis != \'x\') {\n
\t\t\t\tif((i.overflowOffset.top + i.scrollParent[0].offsetHeight) - event.pageY < o.scrollSensitivity)\n
\t\t\t\t\ti.scrollParent[0].scrollTop = scrolled = i.scrollParent[0].scrollTop + o.scrollSpeed;\n
\t\t\t\telse if(event.pageY - i.overflowOffset.top < o.scrollSensitivity)\n
\t\t\t\t\ti.scrollParent[0].scrollTop = scrolled = i.scrollParent[0].scrollTop - o.scrollSpeed;\n
\t\t\t}\n
\n
\t\t\tif(!o.axis || o.axis != \'y\') {\n
\t\t\t\tif((i.overflowOffset.left + i.scrollParent[0].offsetWidth) - event.pageX < o.scrollSensitivity)\n
\t\t\t\t\ti.scrollParent[0].scrollLeft = scrolled = i.scrollParent[0].scrollLeft + o.scrollSpeed;\n
\t\t\t\telse if(event.pageX - i.overflowOffset.left < o.scrollSensitivity)\n
\t\t\t\t\ti.scrollParent[0].scrollLeft = scrolled = i.scrollParent[0].scrollLeft - o.scrollSpeed;\n
\t\t\t}\n
\n
\t\t} else {\n
\n
\t\t\tif(!o.axis || o.axis != \'x\') {\n
\t\t\t\tif(event.pageY - $(document).scrollTop() < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() - o.scrollSpeed);\n
\t\t\t\telse if($(window).height() - (event.pageY - $(document).scrollTop()) < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() + o.scrollSpeed);\n
\t\t\t}\n
\n
\t\t\tif(!o.axis || o.axis != \'y\') {\n
\t\t\t\tif(event.pageX - $(document).scrollLeft() < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() - o.scrollSpeed);\n
\t\t\t\telse if($(window).width() - (event.pageX - $(document).scrollLeft()) < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() + o.scrollSpeed);\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\tif(scrolled !== false && $.ui.ddmanager && !o.dropBehaviour)\n
\t\t\t$.ui.ddmanager.prepareOffsets(i, event);\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "snap", {\n
\tstart: function(event, ui) {\n
\n
\t\tvar i = $(this).data("draggable"), o = i.options;\n
\t\ti.snapElements = [];\n
\n
\t\t$(o.snap.constructor != String ? ( o.snap.items || \':data(draggable)\' ) : o.snap).each(function() {\n
\t\t\tvar $t = $(this); var $o = $t.offset();\n
\t\t\tif(this != i.element[0]) i.snapElements.push({\n
\t\t\t\titem: this,\n
\t\t\t\twidth: $t.outerWidth(), height: $t.outerHeight(),\n
\t\t\t\ttop: $o.top, left: $o.left\n
\t\t\t});\n
\t\t});\n
\n
\t},\n
\tdrag: function(event, ui) {\n
\n
\t\tvar inst = $(this).data("draggable"), o = inst.options;\n
\t\tvar d = o.snapTolerance;\n
\n
\t\tvar x1 = ui.offset.left, x2 = x1 + inst.helperProportions.width,\n
\t\t\ty1 = ui.offset.top, y2 = y1 + inst.helperProportions.height;\n
\n
\t\tfor (var i = inst.snapElements.length - 1; i >= 0; i--){\n
\n
\t\t\tvar l = inst.snapElements[i].left, r = l + inst.snapElements[i].width,\n
\t\t\t\tt = inst.snapElements[i].top, b = t + inst.snapElements[i].height;\n
\n
\t\t\t//Yes, I know, this is insane ;)\n
\t\t\tif(!((l-d < x1 && x1 < r+d && t-d < y1 && y1 < b+d) || (l-d < x1 && x1 < r+d && t-d < y2 && y2 < b+d) || (l-d < x2 && x2 < r+d && t-d < y1 && y1 < b+d) || (l-d < x2 && x2 < r+d && t-d < y2 && y2 < b+d))) {\n
\t\t\t\tif(inst.snapElements[i].snapping) (inst.options.snap.release && inst.options.snap.release.call(inst.element, event, $.extend(inst._uiHash(), { snapItem: inst.snapElements[i].item })));\n
\t\t\t\tinst.snapElements[i].snapping = false;\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif(o.snapMode != \'inner\') {\n
\t\t\t\tvar ts = Math.abs(t - y2) <= d;\n
\t\t\t\tvar bs = Math.abs(b - y1) <= d;\n
\t\t\t\tvar ls = Math.abs(l - x2) <= d;\n
\t\t\t\tvar rs = Math.abs(r - x1) <= d;\n
\t\t\t\tif(ts) ui.position.top = inst._convertPositionTo("relative", { top: t - inst.helperProportions.height, left: 0 }).top - inst.margins.top;\n
\t\t\t\tif(bs) ui.position.top = inst._convertPositionTo("relative", { top: b, left: 0 }).top - inst.margins.top;\n
\t\t\t\tif(ls) ui.position.left = inst._convertPositionTo("relative", { top: 0, left: l - inst.helperProportions.width }).left - inst.margins.left;\n
\t\t\t\tif(rs) ui.position.left = inst._convertPositionTo("relative", { top: 0, left: r }).left - inst.margins.left;\n
\t\t\t}\n
\n
\t\t\tvar first = (ts || bs || ls || rs);\n
\n
\t\t\tif(o.snapMode != \'outer\') {\n
\t\t\t\tvar ts = Math.abs(t - y1) <= d;\n
\t\t\t\tvar bs = Math.abs(b - y2) <= d;\n
\t\t\t\tvar ls = Math.abs(l - x1) <= d;\n
\t\t\t\tvar rs = Math.abs(r - x2) <= d;\n
\t\t\t\tif(ts) ui.position.top = inst._convertPositionTo("relative", { top: t, left: 0 }).top - inst.margins.top;\n
\t\t\t\tif(bs) ui.position.top = inst._convertPositionTo("relative", { top: b - inst.helperProportions.height, left: 0 }).top - inst.margins.top;\n
\t\t\t\tif(ls) ui.position.left = inst._convertPositionTo("relative", { top: 0, left: l }).left - inst.margins.left;\n
\t\t\t\tif(rs) ui.position.left = inst._convertPositionTo("relative", { top: 0, left: r - inst.helperProportions.width }).left - inst.margins.left;\n
\t\t\t}\n
\n
\t\t\tif(!inst.snapElements[i].snapping && (ts || bs || ls || rs || first))\n
\t\t\t\t(inst.options.snap.snap && inst.options.snap.snap.call(inst.element, event, $.extend(inst._uiHash(), { snapItem: inst.snapElements[i].item })));\n
\t\t\tinst.snapElements[i].snapping = (ts || bs || ls || rs || first);\n
\n
\t\t};\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "stack", {\n
\tstart: function(event, ui) {\n
\n
\t\tvar o = $(this).data("draggable").options;\n
\n
\t\tvar group = $.makeArray($(o.stack.group)).sort(function(a,b) {\n
\t\t\treturn (parseInt($(a).css("zIndex"),10) || o.stack.min) - (parseInt($(b).css("zIndex"),10) || o.stack.min);\n
\t\t});\n
\n
\t\t$(group).each(function(i) {\n
\t\t\tthis.style.zIndex = o.stack.min + i;\n
\t\t});\n
\n
\t\tthis[0].style.zIndex = o.stack.min + group.length;\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("draggable", "zIndex", {\n
\tstart: function(event, ui) {\n
\t\tvar t = $(ui.helper), o = $(this).data("draggable").options;\n
\t\tif(t.css("zIndex")) o._zIndex = t.css("zIndex");\n
\t\tt.css(\'zIndex\', o.zIndex);\n
\t},\n
\tstop: function(event, ui) {\n
\t\tvar o = $(this).data("draggable").options;\n
\t\tif(o._zIndex) $(ui.helper).css(\'zIndex\', o._zIndex);\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Droppable 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Droppables\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 *\tui.draggable.js\n
 */\n
(function($) {\n
\n
$.widget("ui.droppable", {\n
\n
\t_init: function() {\n
\n
\t\tvar o = this.options, accept = o.accept;\n
\t\tthis.isover = 0; this.isout = 1;\n
\n
\t\tthis.options.accept = this.options.accept && $.isFunction(this.options.accept) ? this.options.accept : function(d) {\n
\t\t\treturn d.is(accept);\n
\t\t};\n
\n
\t\t//Store the droppable\'s proportions\n
\t\tthis.proportions = { width: this.element[0].offsetWidth, height: this.element[0].offsetHeight };\n
\n
\t\t// Add the reference and positions to the manager\n
\t\t$.ui.ddmanager.droppables[this.options.scope] = $.ui.ddmanager.droppables[this.options.scope] || [];\n
\t\t$.ui.ddmanager.droppables[this.options.scope].push(this);\n
\n
\t\t(this.options.addClasses && this.element.addClass("ui-droppable"));\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tvar drop = $.ui.ddmanager.droppables[this.options.scope];\n
\t\tfor ( var i = 0; i < drop.length; i++ )\n
\t\t\tif ( drop[i] == this )\n
\t\t\t\tdrop.splice(i, 1);\n
\n
\t\tthis.element\n
\t\t\t.removeClass("ui-droppable ui-droppable-disabled")\n
\t\t\t.removeData("droppable")\n
\t\t\t.unbind(".droppable");\n
\t},\n
\n
\t_setData: function(key, value) {\n
\n
\t\tif(key == \'accept\') {\n
\t\t\tthis.options.accept = value && $.isFunction(value) ? value : function(d) {\n
\t\t\t\treturn d.is(value);\n
\t\t\t};\n
\t\t} else {\n
\t\t\t$.widget.prototype._setData.apply(this, arguments);\n
\t\t}\n
\n
\t},\n
\n
\t_activate: function(event) {\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif(this.options.activeClass) this.element.addClass(this.options.activeClass);\n
\t\t(draggable && this._trigger(\'activate\', event, this.ui(draggable)));\n
\t},\n
\n
\t_deactivate: function(event) {\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif(this.options.activeClass) this.element.removeClass(this.options.activeClass);\n
\t\t(draggable && this._trigger(\'deactivate\', event, this.ui(draggable)));\n
\t},\n
\n
\t_over: function(event) {\n
\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] == this.element[0]) return; // Bail if draggable and droppable are same element\n
\n
\t\tif (this.options.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.hoverClass) this.element.addClass(this.options.hoverClass);\n
\t\t\tthis._trigger(\'over\', event, this.ui(draggable));\n
\t\t}\n
\n
\t},\n
\n
\t_out: function(event) {\n
\n
\t\tvar draggable = $.ui.ddmanager.current;\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] == this.element[0]) return; // Bail if draggable and droppable are same element\n
\n
\t\tif (this.options.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.hoverClass) this.element.removeClass(this.options.hoverClass);\n
\t\t\tthis._trigger(\'out\', event, this.ui(draggable));\n
\t\t}\n
\n
\t},\n
\n
\t_drop: function(event,custom) {\n
\n
\t\tvar draggable = custom || $.ui.ddmanager.current;\n
\t\tif (!draggable || (draggable.currentItem || draggable.element)[0] == this.element[0]) return false; // Bail if draggable and droppable are same element\n
\n
\t\tvar childrenIntersection = false;\n
\t\tthis.element.find(":data(droppable)").not(".ui-draggable-dragging").each(function() {\n
\t\t\tvar inst = $.data(this, \'droppable\');\n
\t\t\tif(inst.options.greedy && $.ui.intersect(draggable, $.extend(inst, { offset: inst.element.offset() }), inst.options.tolerance)) {\n
\t\t\t\tchildrenIntersection = true; return false;\n
\t\t\t}\n
\t\t});\n
\t\tif(childrenIntersection) return false;\n
\n
\t\tif(this.options.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\tif(this.options.activeClass) this.element.removeClass(this.options.activeClass);\n
\t\t\tif(this.options.hoverClass) this.element.removeClass(this.options.hoverClass);\n
\t\t\tthis._trigger(\'drop\', event, this.ui(draggable));\n
\t\t\treturn this.element;\n
\t\t}\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\tui: function(c) {\n
\t\treturn {\n
\t\t\tdraggable: (c.currentItem || c.element),\n
\t\t\thelper: c.helper,\n
\t\t\tposition: c.position,\n
\t\t\tabsolutePosition: c.positionAbs, //deprecated\n
\t\t\toffset: c.positionAbs\n
\t\t};\n
\t}\n
\n
});\n
\n
$.extend($.ui.droppable, {\n
\tversion: "1.7.2",\n
\teventPrefix: \'drop\',\n
\tdefaults: {\n
\t\taccept: \'*\',\n
\t\tactiveClass: false,\n
\t\taddClasses: true,\n
\t\tgreedy: false,\n
\t\thoverClass: false,\n
\t\tscope: \'default\',\n
\t\ttolerance: \'intersect\'\n
\t}\n
});\n
\n
$.ui.intersect = function(draggable, droppable, toleranceMode) {\n
\n
\tif (!droppable.offset) return false;\n
\n
\tvar x1 = (draggable.positionAbs || draggable.position.absolute).left, x2 = x1 + draggable.helperProportions.width,\n
\t\ty1 = (draggable.positionAbs || draggable.position.absolute).top, y2 = y1 + draggable.helperProportions.height;\n
\tvar l = droppable.offset.left, r = l + droppable.proportions.width,\n
\t\tt = droppable.offset.top, b = t + droppable.proportions.height;\n
\n
\tswitch (toleranceMode) {\n
\t\tcase \'fit\':\n
\t\t\treturn (l < x1 && x2 < r\n
\t\t\t\t&& t < y1 && y2 < b);\n
\t\t\tbreak;\n
\t\tcase \'intersect\':\n
\t\t\treturn (l < x1 + (draggable.helperProportions.width / 2) // Right Half\n
\t\t\t\t&& x2 - (draggable.helperProportions.width / 2) < r // Left Half\n
\t\t\t\t&& t < y1 + (draggable.helperProportions.height / 2) // Bottom Half\n
\t\t\t\t&& y2 - (draggable.helperProportions.height / 2) < b ); // Top Half\n
\t\t\tbreak;\n
\t\tcase \'pointer\':\n
\t\t\tvar draggableLeft = ((draggable.positionAbs || draggable.position.absolute).left + (draggable.clickOffset || draggable.offset.click).left),\n
\t\t\t\tdraggableTop = ((draggable.positionAbs || draggable.position.absolute).top + (draggable.clickOffset || draggable.offset.click).top),\n
\t\t\t\tisOver = $.ui.isOver(draggableTop, draggableLeft, t, l, droppable.proportions.height, droppable.proportions.width);\n
\t\t\treturn isOver;\n
\t\t\tbreak;\n
\t\tcase \'touch\':\n
\t\t\treturn (\n
\t\t\t\t\t(y1 >= t && y1 <= b) ||\t// Top edge touching\n
\t\t\t\t\t(y2 >= t && y2 <= b) ||\t// Bottom edge touching\n
\t\t\t\t\t(y1 < t && y2 > b)\t\t// Surrounded vertically\n
\t\t\t\t) && (\n
\t\t\t\t\t(x1 >= l && x1 <= r) ||\t// Left edge touching\n
\t\t\t\t\t(x2 >= l && x2 <= r) ||\t// Right edge touching\n
\t\t\t\t\t(x1 < l && x2 > r)\t\t// Surrounded horizontally\n
\t\t\t\t);\n
\t\t\tbreak;\n
\t\tdefault:\n
\t\t\treturn false;\n
\t\t\tbreak;\n
\t\t}\n
\n
};\n
\n
/*\n
\tThis manager tracks offsets of draggables and droppables\n
*/\n
$.ui.ddmanager = {\n
\tcurrent: null,\n
\tdroppables: { \'default\': [] },\n
\tprepareOffsets: function(t, event) {\n
\n
\t\tvar m = $.ui.ddmanager.droppables[t.options.scope];\n
\t\tvar type = event ? event.type : null; // workaround for #2317\n
\t\tvar list = (t.currentItem || t.element).find(":data(droppable)").andSelf();\n
\n
\t\tdroppablesLoop: for (var i = 0; i < m.length; i++) {\n
\n
\t\t\tif(m[i].options.disabled || (t && !m[i].options.accept.call(m[i].element[0],(t.currentItem || t.element)))) continue;\t//No disabled and non-accepted\n
\t\t\tfor (var j=0; j < list.length; j++) { if(list[j] == m[i].element[0]) { m[i].proportions.height = 0; continue droppablesLoop; } }; //Filter out elements in the current dragged item\n
\t\t\tm[i].visible = m[i].element.css("display") != "none"; if(!m[i].visible) continue; \t\t\t\t\t\t\t\t\t//If the element is not visible, continue\n
\n
\t\t\tm[i].offset = m[i].element.offset();\n
\t\t\tm[i].proportions = { width: m[i].element[0].offsetWidth, height: m[i].element[0].offsetHeight };\n
\n
\t\t\tif(type == "mousedown") m[i]._activate.call(m[i], event); //Activate the droppable if used directly from draggables\n
\n
\t\t}\n
\n
\t},\n
\tdrop: function(draggable, event) {\n
\n
\t\tvar dropped = false;\n
\t\t$.each($.ui.ddmanager.droppables[draggable.options.scope], function() {\n
\n
\t\t\tif(!this.options) return;\n
\t\t\tif (!this.options.disabled && this.visible && $.ui.intersect(draggable, this, this.options.tolerance))\n
\t\t\t\tdropped = this._drop.call(this, event);\n
\n
\t\t\tif (!this.options.disabled && this.visible && this.options.accept.call(this.element[0],(draggable.currentItem || draggable.element))) {\n
\t\t\t\tthis.isout = 1; this.isover = 0;\n
\t\t\t\tthis._deactivate.call(this, event);\n
\t\t\t}\n
\n
\t\t});\n
\t\treturn dropped;\n
\n
\t},\n
\tdrag: function(draggable, event) {\n
\n
\t\t//If you have a highly dynamic page, you might try this option. It renders positions every time you move the mouse.\n
\t\tif(draggable.options.refreshPositions) $.ui.ddmanager.prepareOffsets(draggable, event);\n
\n
\t\t//Run through all droppables and check their positions based on specific tolerance options\n
\n
\t\t$.each($.ui.ddmanager.droppables[draggable.options.scope], function() {\n
\n
\t\t\tif(this.options.disabled || this.greedyChild || !this.visible) return;\n
\t\t\tvar intersects = $.ui.intersect(draggable, this, this.options.tolerance);\n
\n
\t\t\tvar c = !intersects && this.isover == 1 ? \'isout\' : (intersects && this.isover == 0 ? \'isover\' : null);\n
\t\t\tif(!c) return;\n
\n
\t\t\tvar parentInstance;\n
\t\t\tif (this.options.greedy) {\n
\t\t\t\tvar parent = this.element.parents(\':data(droppable):eq(0)\');\n
\t\t\t\tif (parent.length) {\n
\t\t\t\t\tparentInstance = $.data(parent[0], \'droppable\');\n
\t\t\t\t\tparentInstance.greedyChild = (c == \'isover\' ? 1 : 0);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// we just moved into a greedy child\n
\t\t\tif (parentInstance && c == \'isover\') {\n
\t\t\t\tparentInstance[\'isover\'] = 0;\n
\t\t\t\tparentInstance[\'isout\'] = 1;\n
\t\t\t\tparentInstance._out.call(parentInstance, event);\n
\t\t\t}\n
\n
\t\t\tthis[c] = 1; this[c == \'isout\' ? \'isover\' : \'isout\'] = 0;\n
\t\t\tthis[c == "isover" ? "_over" : "_out"].call(this, event);\n
\n
\t\t\t// we just moved out of a greedy child\n
\t\t\tif (parentInstance && c == \'isout\') {\n
\t\t\t\tparentInstance[\'isout\'] = 0;\n
\t\t\t\tparentInstance[\'isover\'] = 1;\n
\t\t\t\tparentInstance._over.call(parentInstance, event);\n
\t\t\t}\n
\t\t});\n
\n
\t}\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Resizable 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Resizables\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.resizable", $.extend({}, $.ui.mouse, {\n
\n
\t_init: function() {\n
\n
\t\tvar self = this, o = this.options;\n
\t\tthis.element.addClass("ui-resizable");\n
\n
\t\t$.extend(this, {\n
\t\t\t_aspectRatio: !!(o.aspectRatio),\n
\t\t\taspectRatio: o.aspectRatio,\n
\t\t\toriginalElement: this.element,\n
\t\t\t_proportionallyResizeElements: [],\n
\t\t\t_helper: o.helper || o.ghost || o.animate ? o.helper || \'ui-resizable-helper\' : null\n
\t\t});\n
\n
\t\t//Wrap the element if it cannot hold child nodes\n
\t\tif(this.element[0].nodeName.match(/canvas|textarea|input|select|button|img/i)) {\n
\n
\t\t\t//Opera fix for relative positioning\n
\t\t\tif (/relative/.test(this.element.css(\'position\')) && $.browser.opera)\n
\t\t\t\tthis.element.css({ position: \'relative\', top: \'auto\', left: \'auto\' });\n
\n
\t\t\t//Create a wrapper element and set the wrapper to the new current internal element\n
\t\t\tthis.element.wrap(\n
\t\t\t\t$(\'<div class="ui-wrapper" style="overflow: hidden;"></div>\').css({\n
\t\t\t\t\tposition: this.element.css(\'position\'),\n
\t\t\t\t\twidth: this.element.outerWidth(),\n
\t\t\t\t\theight: this.element.outerHeight(),\n
\t\t\t\t\ttop: this.element.css(\'top\'),\n
\t\t\t\t\tleft: this.element.css(\'left\')\n
\t\t\t\t})\n
\t\t\t);\n
\n
\t\t\t//Overwrite the original this.element\n
\t\t\tthis.element = this.element.parent().data(\n
\t\t\t\t"resizable", this.element.data(\'resizable\')\n
\t\t\t);\n
\n
\t\t\tthis.elementIsWrapper = true;\n
\n
\t\t\t//Move margins to the wrapper\n
\t\t\tthis.element.css({ marginLeft: this.originalElement.css("marginLeft"), marginTop: this.originalElement.css("marginTop"), marginRight: this.originalElement.css("marginRight"), marginBottom: this.originalElement.css("marginBottom") });\n
\t\t\tthis.originalElement.css({ marginLeft: 0, marginTop: 0, marginRight: 0, marginBottom: 0});\n
\n
\t\t\t//Prevent Safari textarea resize\n
\t\t\tthis.originalResizeStyle = this.originalElement.css(\'resize\');\n
\t\t\tthis.originalElement.css(\'resize\', \'none\');\n
\n
\t\t\t//Push the actual element to our proportionallyResize internal array\n
\t\t\tthis._proportionallyResizeElements.push(this.originalElement.css({ position: \'static\', zoom: 1, display: \'block\' }));\n
\n
\t\t\t// avoid IE jump (hard set the margin)\n
\t\t\tthis.originalElement.css({ margin: this.originalElement.css(\'margin\') });\n
\n
\t\t\t// fix handlers offset\n
\t\t\tthis._proportionallyResize();\n
\n
\t\t}\n
\n
\t\tthis.handles = o.handles || (!$(\'.ui-resizable-handle\', this.element).length ? "e,s,se" : { n: \'.ui-resizable-n\', e: \'.ui-resizable-e\', s: \'.ui-resizable-s\', w: \'.ui-resizable-w\', se: \'.ui-resizable-se\', sw: \'.ui-resizable-sw\', ne: \'.ui-resizable-ne\', nw: \'.ui-resizable-nw\' });\n
\t\tif(this.handles.constructor == String) {\n
\n
\t\t\tif(this.handles == \'all\') this.handles = \'n,e,s,w,se,sw,ne,nw\';\n
\t\t\tvar n = this.handles.split(","); this.handles = {};\n
\n
\t\t\tfor(var i = 0; i < n.length; i++) {\n
\n
\t\t\t\tvar handle = $.trim(n[i]), hname = \'ui-resizable-\'+handle;\n
\t\t\t\tvar axis = $(\'<div class="ui-resizable-handle \' + hname + \'"></div>\');\n
\n
\t\t\t\t// increase zIndex of sw, se, ne, nw axis\n
\t\t\t\t//TODO : this modifies original option\n
\t\t\t\tif(/sw|se|ne|nw/.test(handle)) axis.css({ zIndex: ++o.zIndex });\n
\n
\t\t\t\t//TODO : What\'s going on here?\n
\t\t\t\tif (\'se\' == handle) {\n
\t\t\t\t\taxis.addClass(\'ui-icon ui-icon-gripsmall-diagonal-se\');\n
\t\t\t\t};\n
\n
\t\t\t\t//Insert into internal handles object and append to element\n
\t\t\t\tthis.handles[handle] = \'.ui-resizable-\'+handle;\n
\t\t\t\tthis.element.append(axis);\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\tthis._renderAxis = function(target) {\n
\n
\t\t\ttarget = target || this.element;\n
\n
\t\t\tfor(var i in this.handles) {\n
\n
\t\t\t\tif(this.handles[i].constructor == String)\n
\t\t\t\t\tthis.handles[i] = $(this.handles[i], this.element).show();\n
\n
\t\t\t\t//Apply pad to wrapper element, needed to fix axis position (textarea, inputs, scrolls)\n
\t\t\t\tif (this.elementIsWrapper && this.originalElement[0].nodeName.match(/textarea|input|select|button/i)) {\n
\n
\t\t\t\t\tvar axis = $(this.handles[i], this.element), padWrapper = 0;\n
\n
\t\t\t\t\t//Checking the correct pad and border\n
\t\t\t\t\tpadWrapper = /sw|ne|nw|se|n|s/.test(i) ? axis.outerHeight() : axis.outerWidth();\n
\n
\t\t\t\t\t//The padding type i have to apply...\n
\t\t\t\t\tvar padPos = [ \'padding\',\n
\t\t\t\t\t\t/ne|nw|n/.test(i) ? \'Top\' :\n
\t\t\t\t\t\t/se|sw|s/.test(i) ? \'Bottom\' :\n
\t\t\t\t\t\t/^e$/.test(i) ? \'Right\' : \'Left\' ].join("");\n
\n
\t\t\t\t\ttarget.css(padPos, padWrapper);\n
\n
\t\t\t\t\tthis._proportionallyResize();\n
\n
\t\t\t\t}\n
\n
\t\t\t\t//TODO: What\'s that good for? There\'s not anything to be executed left\n
\t\t\t\tif(!$(this.handles[i]).length)\n
\t\t\t\t\tcontinue;\n
\n
\t\t\t}\n
\t\t};\n
\n
\t\t//TODO: make renderAxis a prototype function\n
\t\tthis._renderAxis(this.element);\n
\n
\t\tthis._handles = $(\'.ui-resizable-handle\', this.element)\n
\t\t\t.disableSelection();\n
\n
\t\t//Matching axis name\n
\t\tthis._handles.mouseover(function() {\n
\t\t\tif (!self.resizing) {\n
\t\t\t\tif (this.className)\n
\t\t\t\t\tvar axis = this.className.match(/ui-resizable-(se|sw|ne|nw|n|e|s|w)/i);\n
\t\t\t\t//Axis, default = se\n
\t\t\t\tself.axis = axis && axis[1] ? axis[1] : \'se\';\n
\t\t\t}\n
\t\t});\n
\n
\t\t//If we want to auto hide the elements\n
\t\tif (o.autoHide) {\n
\t\t\tthis._handles.hide();\n
\t\t\t$(this.element)\n
\t\t\t\t.addClass("ui-resizable-autohide")\n
\t\t\t\t.hover(function() {\n
\t\t\t\t\t$(this).removeClass("ui-resizable-autohide");\n
\t\t\t\t\tself._handles.show();\n
\t\t\t\t},\n
\t\t\t\tfunction(){\n
\t\t\t\t\tif (!self.resizing) {\n
\t\t\t\t\t\t$(this).addClass("ui-resizable-autohide");\n
\t\t\t\t\t\tself._handles.hide();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t}\n
\n
\t\t//Initialize the mouse interaction\n
\t\tthis._mouseInit();\n
\n
\t},\n
\n
\tdestroy: function() {\n
\n
\t\tthis._mouseDestroy();\n
\n
\t\tvar _destroy = function(exp) {\n
\t\t\t$(exp).removeClass("ui-resizable ui-resizable-disabled ui-resizable-resizing")\n
\t\t\t\t.removeData("resizable").unbind(".resizable").find(\'.ui-resizable-handle\').remove();\n
\t\t};\n
\n
\t\t//TODO: Unwrap at same DOM position\n
\t\tif (this.elementIsWrapper) {\n
\t\t\t_destroy(this.element);\n
\t\t\tvar wrapper = this.element;\n
\t\t\twrapper.parent().append(\n
\t\t\t\tthis.originalElement.css({\n
\t\t\t\t\tposition: wrapper.css(\'position\'),\n
\t\t\t\t\twidth: wrapper.outerWidth(),\n
\t\t\t\t\theight: wrapper.outerHeight(),\n
\t\t\t\t\ttop: wrapper.css(\'top\'),\n
\t\t\t\t\tleft: wrapper.css(\'left\')\n
\t\t\t\t})\n
\t\t\t).end().remove();\n
\t\t}\n
\n
\t\tthis.originalElement.css(\'resize\', this.originalResizeStyle);\n
\t\t_destroy(this.originalElement);\n
\n
\t},\n
\n
\t_mouseCapture: function(event) {\n
\n
\t\tvar handle = false;\n
\t\tfor(var i in this.handles) {\n
\t\t\tif($(this.handles[i])[0] == event.target) handle = true;\n
\t\t}\n
\n
\t\treturn this.options.disabled || !!handle;\n
\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\n
\t\tvar o = this.options, iniPos = this.element.position(), el = this.element;\n
\n
\t\tthis.resizing = true;\n
\t\tthis.documentScroll = { top: $(document).scrollTop(), left: $(document).scrollLeft() };\n
\n
\t\t// bugfix for http://dev.jquery.com/ticket/1749\n
\t\tif (el.is(\'.ui-draggable\') || (/absolute/).test(el.css(\'position\'))) {\n
\t\t\tel.css({ position: \'absolute\', top: iniPos.top, left: iniPos.left });\n
\t\t}\n
\n
\t\t//Opera fixing relative position\n
\t\tif ($.browser.opera && (/relative/).test(el.css(\'position\')))\n
\t\t\tel.css({ position: \'relative\', top: \'auto\', left: \'auto\' });\n
\n
\t\tthis._renderProxy();\n
\n
\t\tvar curleft = num(this.helper.css(\'left\')), curtop = num(this.helper.css(\'top\'));\n
\n
\t\tif (o.containment) {\n
\t\t\tcurleft += $(o.containment).scrollLeft() || 0;\n
\t\t\tcurtop += $(o.containment).scrollTop() || 0;\n
\t\t}\n
\n
\t\t//Store needed variables\n
\t\tthis.offset = this.helper.offset();\n
\t\tthis.position = { left: curleft, top: curtop };\n
\t\tthis.size = this._helper ? { width: el.outerWidth(), height: el.outerHeight() } : { width: el.width(), height: el.height() };\n
\t\tthis.originalSize = this._helper ? { width: el.outerWidth(), height: el.outerHeight() } : { width: el.width(), height: el.height() };\n
\t\tthis.originalPosition = { left: curleft, top: curtop };\n
\t\tthis.sizeDiff = { width: el.outerWidth() - el.width(), height: el.outerHeight() - el.height() };\n
\t\tthis.originalMousePosition = { left: event.pageX, top: event.pageY };\n
\n
\t\t//Aspect Ratio\n
\t\tthis.aspectRatio = (typeof o.aspectRatio == \'number\') ? o.aspectRatio : ((this.originalSize.width / this.originalSize.height) || 1);\n
\n
\t    var cursor = $(\'.ui-resizable-\' + this.axis).css(\'cursor\');\n
\t    $(\'body\').css(\'cursor\', cursor == \'auto\' ? this.axis + \'-resize\' : cursor);\n
\n
\t\tel.addClass("ui-resizable-resizing");\n
\t\tthis._propagate("start", event);\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\n
\t\t//Increase performance, avoid regex\n
\t\tvar el = this.helper, o = this.options, props = {},\n
\t\t\tself = this, smp = this.originalMousePosition, a = this.axis;\n
\n
\t\tvar dx = (event.pageX-smp.left)||0, dy = (event.pageY-smp.top)||0;\n
\t\tvar trigger = this._change[a];\n
\t\tif (!trigger) return false;\n
\n
\t\t// Calculate the attrs that will be change\n
\t\tvar data = trigger.apply(this, [event, dx, dy]), ie6 = $.browser.msie && $.browser.version < 7, csdif = this.sizeDiff;\n
\n
\t\tif (this._aspectRatio || event.shiftKey)\n
\t\t\tdata = this._updateRatio(data, event);\n
\n
\t\tdata = this._respectSize(data, event);\n
\n
\t\t// plugins callbacks need to be called first\n
\t\tthis._propagate("resize", event);\n
\n
\t\tel.css({\n
\t\t\ttop: this.position.top + "px", left: this.position.left + "px",\n
\t\t\twidth: this.size.width + "px", height: this.size.height + "px"\n
\t\t});\n
\n
\t\tif (!this._helper && this._proportionallyResizeElements.length)\n
\t\t\tthis._proportionallyResize();\n
\n
\t\tthis._updateCache(data);\n
\n
\t\t// calling the user callback at the end\n
\t\tthis._trigger(\'resize\', event, this.ui());\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\n
\t\tthis.resizing = false;\n
\t\tvar o = this.options, self = this;\n
\n
\t\tif(this._helper) {\n
\t\t\tvar pr = this._proportionallyResizeElements, ista = pr.length && (/textarea/i).test(pr[0].nodeName),\n
\t\t\t\t\t\tsoffseth = ista && $.ui.hasScroll(pr[0], \'left\') /* TODO - jump height */ ? 0 : self.sizeDiff.height,\n
\t\t\t\t\t\t\tsoffsetw = ista ? 0 : self.sizeDiff.width;\n
\n
\t\t\tvar s = { width: (self.size.width - soffsetw), height: (self.size.height - soffseth) },\n
\t\t\t\tleft = (parseInt(self.element.css(\'left\'), 10) + (self.position.left - self.originalPosition.left)) || null,\n
\t\t\t\ttop = (parseInt(self.element.css(\'top\'), 10) + (self.position.top - self.originalPosition.top)) || null;\n
\n
\t\t\tif (!o.animate)\n
\t\t\t\tthis.element.css($.extend(s, { top: top, left: left }));\n
\n
\t\t\tself.helper.height(self.size.height);\n
\t\t\tself.helper.width(self.size.width);\n
\n
\t\t\tif (this._helper && !o.animate) this._proportionallyResize();\n
\t\t}\n
\n
\t\t$(\'body\').css(\'cursor\', \'auto\');\n
\n
\t\tthis.element.removeClass("ui-resizable-resizing");\n
\n
\t\tthis._propagate("stop", event);\n
\n
\t\tif (this._helper) this.helper.remove();\n
\t\treturn false;\n
\n
\t},\n
\n
\t_updateCache: function(data) {\n
\t\tvar o = this.options;\n
\t\tthis.offset = this.helper.offset();\n
\t\tif (isNumber(data.left)) this.position.left = data.left;\n
\t\tif (isNumber(data.top)) this.position.top = data.top;\n
\t\tif (isNumber(data.height)) this.size.height = data.height;\n
\t\tif (isNumber(data.width)) this.size.width = data.width;\n
\t},\n
\n
\t_updateRatio: function(data, event) {\n
\n
\t\tvar o = this.options, cpos = this.position, csize = this.size, a = this.axis;\n
\n
\t\tif (data.height) data.width = (csize.height * this.aspectRatio);\n
\t\telse if (data.width) data.height = (csize.width / this.aspectRatio);\n
\n
\t\tif (a == \'sw\') {\n
\t\t\tdata.left = cpos.left + (csize.width - data.width);\n
\t\t\tdata.top = null;\n
\t\t}\n
\t\tif (a == \'nw\') {\n
\t\t\tdata.top = cpos.top + (csize.height - data.height);\n
\t\t\tdata.left = cpos.left + (csize.width - data.width);\n
\t\t}\n
\n
\t\treturn data;\n
\t},\n
\n
\t_respectSize: function(data, event) {\n
\n
\t\tvar el = this.helper, o = this.options, pRatio = this._aspectRatio || event.shiftKey, a = this.axis,\n
\t\t\t\tismaxw = isNumber(data.width) && o.maxWidth && (o.maxWidth < data.width), ismaxh = isNumber(data.height) && o.maxHeight && (o.maxHeight < data.height),\n
\t\t\t\t\tisminw = isNumber(data.width) && o.minWidth && (o.minWidth > data.width), isminh = isNumber(data.height) && o.minHeight && (o.minHeight > data.height);\n
\n
\t\tif (isminw) data.width = o.minWidth;\n
\t\tif (isminh) data.height = o.minHeight;\n
\t\tif (ismaxw) data.width = o.maxWidth;\n
\t\tif (ismaxh) data.height = o.maxHeight;\n
\n
\t\tvar dw = this.originalPosition.left + this.originalSize.width, dh = this.position.top + this.size.height;\n
\t\tvar cw = /sw|nw|w/.test(a), ch = /nw|ne|n/.test(a);\n
\n
\t\tif (isminw && cw) data.left = dw - o.minWidth;\n
\t\tif (ismaxw && cw) data.left = dw - o.maxWidth;\n
\t\tif (isminh && ch)\tdata.top = dh - o.minHeight;\n
\t\tif (ismaxh && ch)\tdata.top = dh - o.maxHeight;\n
\n
\t\t// fixing jump error on top/left - bug #2330\n
\t\tvar isNotwh = !data.width && !data.height;\n
\t\tif (isNotwh && !data.left && data.top) data.top = null;\n
\t\telse if (isNotwh && !data.top && data.left) data.left = null;\n
\n
\t\treturn data;\n
\t},\n
\n
\t_proportionallyResize: function() {\n
\n
\t\tvar o = this.options;\n
\t\tif (!this._proportionallyResizeElements.length) return;\n
\t\tvar element = this.helper || this.element;\n
\n
\t\tfor (var i=0; i < this._proportionallyResizeElements.length; i++) {\n
\n
\t\t\tvar prel = this._proportionallyResizeElements[i];\n
\n
\t\t\tif (!this.borderDif) {\n
\t\t\t\tvar b = [prel.css(\'borderTopWidth\'), prel.css(\'borderRightWidth\'), prel.css(\'borderBottomWidth\'), prel.css(\'borderLeftWidth\')],\n
\t\t\t\t\tp = [prel.css(\'paddingTop\'), prel.css(\'paddingRight\'), prel.css(\'paddingBottom\'), prel.css(\'paddingLeft\')];\n
\n
\t\t\t\tthis.borderDif = $.map(b, function(v, i) {\n
\t\t\t\t\tvar border = parseInt(v,10)||0, padding = parseInt(p[i],10)||0;\n
\t\t\t\t\treturn border + padding;\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif ($.browser.msie && !(!($(element).is(\':hidden\') || $(element).parents(\':hidden\').length)))\n
\t\t\t\tcontinue;\n
\n
\t\t\tprel.css({\n
\t\t\t\theight: (element.height() - this.borderDif[0] - this.borderDif[2]) || 0,\n
\t\t\t\twidth: (element.width() - this.borderDif[1] - this.borderDif[3]) || 0\n
\t\t\t});\n
\n
\t\t};\n
\n
\t},\n
\n
\t_renderProxy: function() {\n
\n
\t\tvar el = this.element, o = this.options;\n
\t\tthis.elementOffset = el.offset();\n
\n
\t\tif(this._helper) {\n
\n
\t\t\tthis.helper = this.helper || $(\'<div style="overflow:hidden;"></div>\');\n
\n
\t\t\t// fix ie6 offset TODO: This seems broken\n
\t\t\tvar ie6 = $.browser.msie && $.browser.version < 7, ie6offset = (ie6 ? 1 : 0),\n
\t\t\tpxyoffset = ( ie6 ? 2 : -1 );\n
\n
\t\t\tthis.helper.addClass(this._helper).css({\n
\t\t\t\twidth: this.element.outerWidth() + pxyoffset,\n
\t\t\t\theight: this.element.outerHeight() + pxyoffset,\n
\t\t\t\tposition: \'absolute\',\n
\t\t\t\tleft: this.elementOffset.left - ie6offset +\'px\',\n
\t\t\t\ttop: this.elementOffset.top - ie6offset +\'px\',\n
\t\t\t\tzIndex: ++o.zIndex //TODO: Don\'t modify option\n
\t\t\t});\n
\n
\t\t\tthis.helper\n
\t\t\t\t.appendTo("body")\n
\t\t\t\t.disableSelection();\n
\n
\t\t} else {\n
\t\t\tthis.helper = this.element;\n
\t\t}\n
\n
\t},\n
\n
\t_change: {\n
\t\te: function(event, dx, dy) {\n
\t\t\treturn { width: this.originalSize.width + dx };\n
\t\t},\n
\t\tw: function(event, dx, dy) {\n
\t\t\tvar o = this.options, cs = this.originalSize, sp = this.originalPosition;\n
\t\t\treturn { left: sp.left + dx, width: cs.width - dx };\n
\t\t},\n
\t\tn: function(event, dx, dy) {\n
\t\t\tvar o = this.options, cs = this.originalSize, sp = this.originalPosition;\n
\t\t\treturn { top: sp.top + dy, height: cs.height - dy };\n
\t\t},\n
\t\ts: function(event, dx, dy) {\n
\t\t\treturn { height: this.originalSize.height + dy };\n
\t\t},\n
\t\tse: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.s.apply(this, arguments), this._change.e.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tsw: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.s.apply(this, arguments), this._change.w.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tne: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.n.apply(this, arguments), this._change.e.apply(this, [event, dx, dy]));\n
\t\t},\n
\t\tnw: function(event, dx, dy) {\n
\t\t\treturn $.extend(this._change.n.apply(this, arguments), this._change.w.apply(this, [event, dx, dy]));\n
\t\t}\n
\t},\n
\n
\t_propagate: function(n, event) {\n
\t\t$.ui.plugin.call(this, n, [event, this.ui()]);\n
\t\t(n != "resize" && this._trigger(n, event, this.ui()));\n
\t},\n
\n
\tplugins: {},\n
\n
\tui: function() {\n
\t\treturn {\n
\t\t\toriginalElement: this.originalElement,\n
\t\t\telement: this.element,\n
\t\t\thelper: this.helper,\n
\t\t\tposition: this.position,\n
\t\t\tsize: this.size,\n
\t\t\toriginalSize: this.originalSize,\n
\t\t\toriginalPosition: this.originalPosition\n
\t\t};\n
\t}\n
\n
}));\n
\n
$.extend($.ui.resizable, {\n
\tversion: "1.7.2",\n
\teventPrefix: "resize",\n
\tdefaults: {\n
\t\talsoResize: false,\n
\t\tanimate: false,\n
\t\tanimateDuration: "slow",\n
\t\tanimateEasing: "swing",\n
\t\taspectRatio: false,\n
\t\tautoHide: false,\n
\t\tcancel: ":input,option",\n
\t\tcontainment: false,\n
\t\tdelay: 0,\n
\t\tdistance: 1,\n
\t\tghost: false,\n
\t\tgrid: false,\n
\t\thandles: "e,s,se",\n
\t\thelper: false,\n
\t\tmaxHeight: null,\n
\t\tmaxWidth: null,\n
\t\tminHeight: 10,\n
\t\tminWidth: 10,\n
\t\tzIndex: 1000\n
\t}\n
});\n
\n
/*\n
 * Resizable Extensions\n
 */\n
\n
$.ui.plugin.add("resizable", "alsoResize", {\n
\n
\tstart: function(event, ui) {\n
\n
\t\tvar self = $(this).data("resizable"), o = self.options;\n
\n
\t\t_store = function(exp) {\n
\t\t\t$(exp).each(function() {\n
\t\t\t\t$(this).data("resizable-alsoresize", {\n
\t\t\t\t\twidth: parseInt($(this).width(), 10), height: parseInt($(this).height(), 10),\n
\t\t\t\t\tleft: parseInt($(this).css(\'left\'), 10), top: parseInt($(this).css(\'top\'), 10)\n
\t\t\t\t});\n
\t\t\t});\n
\t\t};\n
\n
\t\tif (typeof(o.alsoResize) == \'object\' && !o.alsoResize.parentNode) {\n
\t\t\tif (o.alsoResize.length) { o.alsoResize = o.alsoResize[0];\t_store(o.alsoResize); }\n
\t\t\telse { $.each(o.alsoResize, function(exp, c) { _store(exp); }); }\n
\t\t}else{\n
\t\t\t_store(o.alsoResize);\n
\t\t}\n
\t},\n
\n
\tresize: function(event, ui){\n
\t\tvar self = $(this).data("resizable"), o = self.options, os = self.originalSize, op = self.originalPosition;\n
\n
\t\tvar delta = {\n
\t\t\theight: (self.size.height - os.height) || 0, width: (self.size.width - os.width) || 0,\n
\t\t\ttop: (self.position.top - op.top) || 0, left: (self.position.left - op.left) || 0\n
\t\t},\n
\n
\t\t_alsoResize = function(exp, c) {\n
\t\t\t$(exp).each(function() {\n
\t\t\t\tvar el = $(this), start = $(this).data("resizable-alsoresize"), style = {}, css = c && c.length ? c : [\'width\', \'height\', \'top\', \'left\'];\n
\n
\t\t\t\t$.each(css || [\'width\', \'height\', \'top\', \'left\'], function(i, prop) {\n
\t\t\t\t\tvar sum = (start[prop]||0) + (delta[prop]||0);\n
\t\t\t\t\tif (sum && sum >= 0)\n
\t\t\t\t\t\tstyle[prop] = sum || null;\n
\t\t\t\t});\n
\n
\t\t\t\t//Opera fixing relative position\n
\t\t\t\tif (/relative/.test(el.css(\'position\')) && $.browser.opera) {\n
\t\t\t\t\tself._revertToRelativePosition = true;\n
\t\t\t\t\tel.css({ position: \'absolute\', top: \'auto\', left: \'auto\' });\n
\t\t\t\t}\n
\n
\t\t\t\tel.css(style);\n
\t\t\t});\n
\t\t};\n
\n
\t\tif (typeof(o.alsoResize) == \'object\' && !o.alsoResize.nodeType) {\n
\t\t\t$.each(o.alsoResize, function(exp, c) { _alsoResize(exp, c); });\n
\t\t}else{\n
\t\t\t_alsoResize(o.alsoResize);\n
\t\t}\n
\t},\n
\n
\tstop: function(event, ui){\n
\t\tvar self = $(this).data("resizable");\n
\n
\t\t//Opera fixing relative position\n
\t\tif (self._revertToRelativePosition && $.browser.opera) {\n
\t\t\tself._revertToRelativePosition = false;\n
\t\t\tel.css({ position: \'relative\' });\n
\t\t}\n
\n
\t\t$(this).removeData("resizable-alsoresize-start");\n
\t}\n
});\n
\n
$.ui.plugin.add("resizable", "animate", {\n
\n
\tstop: function(event, ui) {\n
\t\tvar self = $(this).data("resizable"), o = self.options;\n
\n
\t\tvar pr = self._proportionallyResizeElements, ista = pr.length && (/textarea/i).test(pr[0].nodeName),\n
\t\t\t\t\tsoffseth = ista && $.ui.hasScroll(pr[0], \'left\') /* TODO - jump height */ ? 0 : self.sizeDiff.height,\n
\t\t\t\t\t\tsoffsetw = ista ? 0 : self.sizeDiff.width;\n
\n
\t\tvar style = { width: (self.size.width - soffsetw), height: (self.size.height - soffseth) },\n
\t\t\t\t\tleft = (parseInt(self.element.css(\'left\'), 10) + (self.position.left - self.originalPosition.left)) || null,\n
\t\t\t\t\t\ttop = (parseInt(self.element.css(\'top\'), 10) + (self.position.top - self.originalPosition.top)) || null;\n
\n
\t\tself.element.animate(\n
\t\t\t$.extend(style, top && left ? { top: top, left: left } : {}), {\n
\t\t\t\tduration: o.animateDuration,\n
\t\t\t\teasing: o.animateEasing,\n
\t\t\t\tstep: function() {\n
\n
\t\t\t\t\tvar data = {\n
\t\t\t\t\t\twidth: parseInt(self.element.css(\'width\'), 10),\n
\t\t\t\t\t\theight: parseInt(self.element.css(\'height\'), 10),\n
\t\t\t\t\t\ttop: parseInt(self.element.css(\'top\'), 10),\n
\t\t\t\t\t\tleft: parseInt(self.element.css(\'left\'), 10)\n
\t\t\t\t\t};\n
\n
\t\t\t\t\tif (pr && pr.length) $(pr[0]).css({ width: data.width, height: data.height });\n
\n
\t\t\t\t\t// propagating resize, and updating values for each animation step\n
\t\t\t\t\tself._updateCache(data);\n
\t\t\t\t\tself._propagate("resize", event);\n
\n
\t\t\t\t}\n
\t\t\t}\n
\t\t);\n
\t}\n
\n
});\n
\n
$.ui.plugin.add("resizable", "containment", {\n
\n
\tstart: function(event, ui) {\n
\t\tvar self = $(this).data("resizable"), o = self.options, el = self.element;\n
\t\tvar oc = o.containment,\tce = (oc instanceof $) ? oc.get(0) : (/parent/.test(oc)) ? el.parent().get(0) : oc;\n
\t\tif (!ce) return;\n
\n
\t\tself.containerElement = $(ce);\n
\n
\t\tif (/document/.test(oc) || oc == document) {\n
\t\t\tself.containerOffset = { left: 0, top: 0 };\n
\t\t\tself.containerPosition = { left: 0, top: 0 };\n
\n
\t\t\tself.parentData = {\n
\t\t\t\telement: $(document), left: 0, top: 0,\n
\t\t\t\twidth: $(document).width(), height: $(document).height() || document.body.parentNode.scrollHeight\n
\t\t\t};\n
\t\t}\n
\n
\t\t// i\'m a node, so compute top, left, right, bottom\n
\t\telse {\n
\t\t\tvar element = $(ce), p = [];\n
\t\t\t$([ "Top", "Right", "Left", "Bottom" ]).each(function(i, name) { p[i] = num(element.css("padding" + name)); });\n
\n
\t\t\tself.containerOffset = element.offset();\n
\t\t\tself.containerPosition = element.position();\n
\t\t\tself.containerSize = { height: (element.innerHeight() - p[3]), width: (element.innerWidth() - p[1]) };\n
\n
\t\t\tvar co = self.containerOffset, ch = self.containerSize.height,\tcw = self.containerSize.width,\n
\t\t\t\t\t\twidth = ($.ui.hasScroll(ce, "left") ? ce.scrollWidth : cw ), height = ($.ui.hasScroll(ce) ? ce.scrollHeight : ch);\n
\n
\t\t\tself.parentData = {\n
\t\t\t\telement: ce, left: co.left, top: co.top, width: width, height: height\n
\t\t\t};\n
\t\t}\n
\t},\n
\n
\tresize: function(event, ui) {\n
\t\tvar self = $(this).data("resizable"), o = self.options,\n
\t\t\t\tps = self.containerSize, co = self.containerOffset, cs = self.size, cp = self.position,\n
\t\t\t\tpRatio = self._aspectRatio || event.shiftKey, cop = { top:0, left:0 }, ce = self.containerElement;\n
\n
\t\tif (ce[0] != document && (/static/).test(ce.css(\'position\'))) cop = co;\n
\n
\t\tif (cp.left < (self._helper ? co.left : 0)) {\n
\t\t\tself.size.width = self.size.width + (self._helper ? (self.position.left - co.left) : (self.position.left - cop.left));\n
\t\t\tif (pRatio) self.size.height = self.size.width / o.aspectRatio;\n
\t\t\tself.position.left = o.helper ? co.left : 0;\n
\t\t}\n
\n
\t\tif (cp.top < (self._helper ? co.top : 0)) {\n
\t\t\tself.size.height = self.size.height + (self._helper ? (self.position.top - co.top) : self.position.top);\n
\t\t\tif (pRatio) self.size.width = self.size.height * o.aspectRatio;\n
\t\t\tself.position.top = self._helper ? co.top : 0;\n
\t\t}\n
\n
\t\tself.offset.left = self.parentData.left+self.position.left;\n
\t\tself.offset.top = self.parentData.top+self.position.top;\n
\n
\t\tvar woset = Math.abs( (self._helper ? self.offset.left - cop.left : (self.offset.left - cop.left)) + self.sizeDiff.width ),\n
\t\t\t\t\thoset = Math.abs( (self._helper ? self.offset.top - cop.top : (self.offset.top - co.top)) + self.sizeDiff.height );\n
\n
\t\tvar isParent = self.containerElement.get(0) == self.element.parent().get(0),\n
\t\t    isOffsetRelative = /relative|absolute/.test(self.containerElement.css(\'position\'));\n
\n
\t\tif(isParent && isOffsetRelative) woset -= self.parentData.left;\n
\n
\t\tif (woset + self.size.width >= self.parentData.width) {\n
\t\t\tself.size.width = self.parentData.width - woset;\n
\t\t\tif (pRatio) self.size.height = self.size.width / self.aspectRatio;\n
\t\t}\n
\n
\t\tif (hoset + self.size.height >= self.parentData.height) {\n
\t\t\tself.size.height = self.parentData.height - hoset;\n
\t\t\tif (pRatio) self.size.width = self.size.height * self.aspectRatio;\n
\t\t}\n
\t},\n
\n
\tstop: function(event, ui){\n
\t\tvar self = $(this).data("resizable"), o = self.options, cp = self.position,\n
\t\t\t\tco = self.containerOffset, cop = self.containerPosition, ce = self.containerElement;\n
\n
\t\tvar helper = $(self.helper), ho = helper.offset(), w = helper.outerWidth() - self.sizeDiff.width, h = helper.outerHeight() - self.sizeDiff.height;\n
\n
\t\tif (self._helper && !o.animate && (/relative/).test(ce.css(\'position\')))\n
\t\t\t$(this).css({ left: ho.left - cop.left - co.left, width: w, height: h });\n
\n
\t\tif (self._helper && !o.animate && (/static/).test(ce.css(\'position\')))\n
\t\t\t$(this).css({ left: ho.left - cop.left - co.left, width: w, height: h });\n
\n
\t}\n
});\n
\n
$.ui.plugin.add("resizable", "ghost", {\n
\n
\tstart: function(event, ui) {\n
\n
\t\tvar self = $(this).data("resizable"), o = self.options, cs = self.size;\n
\n
\t\tself.ghost = self.originalElement.clone();\n
\t\tself.ghost\n
\t\t\t.css({ opacity: .25, display: \'block\', position: \'relative\', height: cs.height, width: cs.width, margin: 0, left: 0, top: 0 })\n
\t\t\t.addClass(\'ui-resizable-ghost\')\n
\t\t\t.addClass(typeof o.ghost == \'string\' ? o.ghost : \'\');\n
\n
\t\tself.ghost.appendTo(self.helper);\n
\n
\t},\n
\n
\tresize: function(event, ui){\n
\t\tvar self = $(this).data("resizable"), o = self.options;\n
\t\tif (self.ghost) self.ghost.css({ position: \'relative\', height: self.size.height, width: self.size.width });\n
\t},\n
\n
\tstop: function(event, ui){\n
\t\tvar self = $(this).data("resizable"), o = self.options;\n
\t\tif (self.ghost && self.helper) self.helper.get(0).removeChild(self.ghost.get(0));\n
\t}\n
\n
});\n
\n
$.ui.plugin.add("resizable", "grid", {\n
\n
\tresize: function(event, ui) {\n
\t\tvar self = $(this).data("resizable"), o = self.options, cs = self.size, os = self.originalSize, op = self.originalPosition, a = self.axis, ratio = o._aspectRatio || event.shiftKey;\n
\t\to.grid = typeof o.grid == "number" ? [o.grid, o.grid] : o.grid;\n
\t\tvar ox = Math.round((cs.width - os.width) / (o.grid[0]||1)) * (o.grid[0]||1), oy = Math.round((cs.height - os.height) / (o.grid[1]||1)) * (o.grid[1]||1);\n
\n
\t\tif (/^(se|s|e)$/.test(a)) {\n
\t\t\tself.size.width = os.width + ox;\n
\t\t\tself.size.height = os.height + oy;\n
\t\t}\n
\t\telse if (/^(ne)$/.test(a)) {\n
\t\t\tself.size.width = os.width + ox;\n
\t\t\tself.size.height = os.height + oy;\n
\t\t\tself.position.top = op.top - oy;\n
\t\t}\n
\t\telse if (/^(sw)$/.test(a)) {\n
\t\t\tself.size.width = os.width + ox;\n
\t\t\tself.size.height = os.height + oy;\n
\t\t\tself.position.left = op.left - ox;\n
\t\t}\n
\t\telse {\n
\t\t\tself.size.width = os.width + ox;\n
\t\t\tself.size.height = os.height + oy;\n
\t\t\tself.position.top = op.top - oy;\n
\t\t\tself.position.left = op.left - ox;\n
\t\t}\n
\t}\n
\n
});\n
\n
var num = function(v) {\n
\treturn parseInt(v, 10) || 0;\n
};\n
\n
var isNumber = function(value) {\n
\treturn !isNaN(parseInt(value, 10));\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Selectable 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Selectables\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.selectable", $.extend({}, $.ui.mouse, {\n
\n
\t_init: function() {\n
\t\tvar self = this;\n
\n
\t\tthis.element.addClass("ui-selectable");\n
\n
\t\tthis.dragged = false;\n
\n
\t\t// cache selectee children based on filter\n
\t\tvar selectees;\n
\t\tthis.refresh = function() {\n
\t\t\tselectees = $(self.options.filter, self.element[0]);\n
\t\t\tselectees.each(function() {\n
\t\t\t\tvar $this = $(this);\n
\t\t\t\tvar pos = $this.offset();\n
\t\t\t\t$.data(this, "selectable-item", {\n
\t\t\t\t\telement: this,\n
\t\t\t\t\t$element: $this,\n
\t\t\t\t\tleft: pos.left,\n
\t\t\t\t\ttop: pos.top,\n
\t\t\t\t\tright: pos.left + $this.outerWidth(),\n
\t\t\t\t\tbottom: pos.top + $this.outerHeight(),\n
\t\t\t\t\tstartselected: false,\n
\t\t\t\t\tselected: $this.hasClass(\'ui-selected\'),\n
\t\t\t\t\tselecting: $this.hasClass(\'ui-selecting\'),\n
\t\t\t\t\tunselecting: $this.hasClass(\'ui-unselecting\')\n
\t\t\t\t});\n
\t\t\t});\n
\t\t};\n
\t\tthis.refresh();\n
\n
\t\tthis.selectees = selectees.addClass("ui-selectee");\n
\n
\t\tthis._mouseInit();\n
\n
\t\tthis.helper = $(document.createElement(\'div\'))\n
\t\t\t.css({border:\'1px dotted black\'})\n
\t\t\t.addClass("ui-selectable-helper");\n
\t},\n
\n
\tdestroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass("ui-selectable ui-selectable-disabled")\n
\t\t\t.removeData("selectable")\n
\t\t\t.unbind(".selectable");\n
\t\tthis._mouseDestroy();\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\t\tvar self = this;\n
\n
\t\tthis.opos = [event.pageX, event.pageY];\n
\n
\t\tif (this.options.disabled)\n
\t\t\treturn;\n
\n
\t\tvar options = this.options;\n
\n
\t\tthis.selectees = $(options.filter, this.element[0]);\n
\n
\t\tthis._trigger("start", event);\n
\n
\t\t$(options.appendTo).append(this.helper);\n
\t\t// position helper (lasso)\n
\t\tthis.helper.css({\n
\t\t\t"z-index": 100,\n
\t\t\t"position": "absolute",\n
\t\t\t"left": event.clientX,\n
\t\t\t"top": event.clientY,\n
\t\t\t"width": 0,\n
\t\t\t"height": 0\n
\t\t});\n
\n
\t\tif (options.autoRefresh) {\n
\t\t\tthis.refresh();\n
\t\t}\n
\n
\t\tthis.selectees.filter(\'.ui-selected\').each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.startselected = true;\n
\t\t\tif (!event.metaKey) {\n
\t\t\t\tselectee.$element.removeClass(\'ui-selected\');\n
\t\t\t\tselectee.selected = false;\n
\t\t\t\tselectee.$element.addClass(\'ui-unselecting\');\n
\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\tself._trigger("unselecting", event, {\n
\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t});\n
\t\t\t}\n
\t\t});\n
\n
\t\t$(event.target).parents().andSelf().each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tif (selectee) {\n
\t\t\t\tselectee.$element.removeClass("ui-unselecting").addClass(\'ui-selecting\');\n
\t\t\t\tselectee.unselecting = false;\n
\t\t\t\tselectee.selecting = true;\n
\t\t\t\tselectee.selected = true;\n
\t\t\t\t// selectable SELECTING callback\n
\t\t\t\tself._trigger("selecting", event, {\n
\t\t\t\t\tselecting: selectee.element\n
\t\t\t\t});\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t});\n
\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\t\tvar self = this;\n
\t\tthis.dragged = true;\n
\n
\t\tif (this.options.disabled)\n
\t\t\treturn;\n
\n
\t\tvar options = this.options;\n
\n
\t\tvar x1 = this.opos[0], y1 = this.opos[1], x2 = event.pageX, y2 = event.pageY;\n
\t\tif (x1 > x2) { var tmp = x2; x2 = x1; x1 = tmp; }\n
\t\tif (y1 > y2) { var tmp = y2; y2 = y1; y1 = tmp; }\n
\t\tthis.helper.css({left: x1, top: y1, width: x2-x1, height: y2-y1});\n
\n
\t\tthis.selectees.each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\t//prevent helper from being selected if appendTo: selectable\n
\t\t\tif (!selectee || selectee.element == self.element[0])\n
\t\t\t\treturn;\n
\t\t\tvar hit = false;\n
\t\t\tif (options.tolerance == \'touch\') {\n
\t\t\t\thit = ( !(selectee.left > x2 || selectee.right < x1 || selectee.top > y2 || selectee.bottom < y1) );\n
\t\t\t} else if (options.tolerance == \'fit\') {\n
\t\t\t\thit = (selectee.left > x1 && selectee.right < x2 && selectee.top > y1 && selectee.bottom < y2);\n
\t\t\t}\n
\n
\t\t\tif (hit) {\n
\t\t\t\t// SELECT\n
\t\t\t\tif (selectee.selected) {\n
\t\t\t\t\tselectee.$element.removeClass(\'ui-selected\');\n
\t\t\t\t\tselectee.selected = false;\n
\t\t\t\t}\n
\t\t\t\tif (selectee.unselecting) {\n
\t\t\t\t\tselectee.$element.removeClass(\'ui-unselecting\');\n
\t\t\t\t\tselectee.unselecting = false;\n
\t\t\t\t}\n
\t\t\t\tif (!selectee.selecting) {\n
\t\t\t\t\tselectee.$element.addClass(\'ui-selecting\');\n
\t\t\t\t\tselectee.selecting = true;\n
\t\t\t\t\t// selectable SELECTING callback\n
\t\t\t\t\tself._trigger("selecting", event, {\n
\t\t\t\t\t\tselecting: selectee.element\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\t// UNSELECT\n
\t\t\t\tif (selectee.selecting) {\n
\t\t\t\t\tif (event.metaKey && selectee.startselected) {\n
\t\t\t\t\t\tselectee.$element.removeClass(\'ui-selecting\');\n
\t\t\t\t\t\tselectee.selecting = false;\n
\t\t\t\t\t\tselectee.$element.addClass(\'ui-selected\');\n
\t\t\t\t\t\tselectee.selected = true;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tselectee.$element.removeClass(\'ui-selecting\');\n
\t\t\t\t\t\tselectee.selecting = false;\n
\t\t\t\t\t\tif (selectee.startselected) {\n
\t\t\t\t\t\t\tselectee.$element.addClass(\'ui-unselecting\');\n
\t\t\t\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\t\t\tself._trigger("unselecting", event, {\n
\t\t\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tif (selectee.selected) {\n
\t\t\t\t\tif (!event.metaKey && !selectee.startselected) {\n
\t\t\t\t\t\tselectee.$element.removeClass(\'ui-selected\');\n
\t\t\t\t\t\tselectee.selected = false;\n
\n
\t\t\t\t\t\tselectee.$element.addClass(\'ui-unselecting\');\n
\t\t\t\t\t\tselectee.unselecting = true;\n
\t\t\t\t\t\t// selectable UNSELECTING callback\n
\t\t\t\t\t\tself._trigger("unselecting", event, {\n
\t\t\t\t\t\t\tunselecting: selectee.element\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\treturn false;\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\t\tvar self = this;\n
\n
\t\tthis.dragged = false;\n
\n
\t\tvar options = this.options;\n
\n
\t\t$(\'.ui-unselecting\', this.element[0]).each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.$element.removeClass(\'ui-unselecting\');\n
\t\t\tselectee.unselecting = false;\n
\t\t\tselectee.startselected = false;\n
\t\t\tself._trigger("unselected", event, {\n
\t\t\t\tunselected: selectee.element\n
\t\t\t});\n
\t\t});\n
\t\t$(\'.ui-selecting\', this.element[0]).each(function() {\n
\t\t\tvar selectee = $.data(this, "selectable-item");\n
\t\t\tselectee.$element.removeClass(\'ui-selecting\').addClass(\'ui-selected\');\n
\t\t\tselectee.selecting = false;\n
\t\t\tselectee.selected = true;\n
\t\t\tselectee.startselected = true;\n
\t\t\tself._trigger("selected", event, {\n
\t\t\t\tselected: selectee.element\n
\t\t\t});\n
\t\t});\n
\t\tthis._trigger("stop", event);\n
\n
\t\tthis.helper.remove();\n
\n
\t\treturn false;\n
\t}\n
\n
}));\n
\n
$.extend($.ui.selectable, {\n
\tversion: "1.7.2",\n
\tdefaults: {\n
\t\tappendTo: \'body\',\n
\t\tautoRefresh: true,\n
\t\tcancel: ":input,option",\n
\t\tdelay: 0,\n
\t\tdistance: 0,\n
\t\tfilter: \'*\',\n
\t\ttolerance: \'touch\'\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Sortable 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Sortables\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.sortable", $.extend({}, $.ui.mouse, {\n
\t_init: function() {\n
\n
\t\tvar o = this.options;\n
\t\tthis.containerCache = {};\n
\t\tthis.element.addClass("ui-sortable");\n
\n
\t\t//Get the items\n
\t\tthis.refresh();\n
\n
\t\t//Let\'s determine if the items are floating\n
\t\tthis.floating = this.items.length ? (/left|right/).test(this.items[0].item.css(\'float\')) : false;\n
\n
\t\t//Let\'s determine the parent\'s offset\n
\t\tthis.offset = this.element.offset();\n
\n
\t\t//Initialize mouse events for interaction\n
\t\tthis._mouseInit();\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass("ui-sortable ui-sortable-disabled")\n
\t\t\t.removeData("sortable")\n
\t\t\t.unbind(".sortable");\n
\t\tthis._mouseDestroy();\n
\n
\t\tfor ( var i = this.items.length - 1; i >= 0; i-- )\n
\t\t\tthis.items[i].item.removeData("sortable-item");\n
\t},\n
\n
\t_mouseCapture: function(event, overrideHandle) {\n
\n
\t\tif (this.reverting) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif(this.options.disabled || this.options.type == \'static\') return false;\n
\n
\t\t//We have to refresh the items data once first\n
\t\tthis._refreshItems(event);\n
\n
\t\t//Find out if the clicked node (or one of its parents) is a actual item in this.items\n
\t\tvar currentItem = null, self = this, nodes = $(event.target).parents().each(function() {\n
\t\t\tif($.data(this, \'sortable-item\') == self) {\n
\t\t\t\tcurrentItem = $(this);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t});\n
\t\tif($.data(event.target, \'sortable-item\') == self) currentItem = $(event.target);\n
\n
\t\tif(!currentItem) return false;\n
\t\tif(this.options.handle && !overrideHandle) {\n
\t\t\tvar validHandle = false;\n
\n
\t\t\t$(this.options.handle, currentItem).find("*").andSelf().each(function() { if(this == event.target) validHandle = true; });\n
\t\t\tif(!validHandle) return false;\n
\t\t}\n
\n
\t\tthis.currentItem = currentItem;\n
\t\tthis._removeCurrentsFromItems();\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseStart: function(event, overrideHandle, noActivation) {\n
\n
\t\tvar o = this.options, self = this;\n
\t\tthis.currentContainer = this;\n
\n
\t\t//We only need to call refreshPositions, because the refreshItems call has been moved to mouseCapture\n
\t\tthis.refreshPositions();\n
\n
\t\t//Create and append the visible helper\n
\t\tthis.helper = this._createHelper(event);\n
\n
\t\t//Cache the helper size\n
\t\tthis._cacheHelperProportions();\n
\n
\t\t/*\n
\t\t * - Position generation -\n
\t\t * This block generates everything position related - it\'s the core of draggables.\n
\t\t */\n
\n
\t\t//Cache the margins of the original element\n
\t\tthis._cacheMargins();\n
\n
\t\t//Get the next scrolling parent\n
\t\tthis.scrollParent = this.helper.scrollParent();\n
\n
\t\t//The element\'s absolute position on the page minus margins\n
\t\tthis.offset = this.currentItem.offset();\n
\t\tthis.offset = {\n
\t\t\ttop: this.offset.top - this.margins.top,\n
\t\t\tleft: this.offset.left - this.margins.left\n
\t\t};\n
\n
\t\t// Only after we got the offset, we can change the helper\'s position to absolute\n
\t\t// TODO: Still need to figure out a way to make relative sorting possible\n
\t\tthis.helper.css("position", "absolute");\n
\t\tthis.cssPosition = this.helper.css("position");\n
\n
\t\t$.extend(this.offset, {\n
\t\t\tclick: { //Where the click happened, relative to the element\n
\t\t\t\tleft: event.pageX - this.offset.left,\n
\t\t\t\ttop: event.pageY - this.offset.top\n
\t\t\t},\n
\t\t\tparent: this._getParentOffset(),\n
\t\t\trelative: this._getRelativeOffset() //This is a relative to absolute position minus the actual position calculation - only used for relative positioned helper\n
\t\t});\n
\n
\t\t//Generate the original position\n
\t\tthis.originalPosition = this._generatePosition(event);\n
\t\tthis.originalPageX = event.pageX;\n
\t\tthis.originalPageY = event.pageY;\n
\n
\t\t//Adjust the mouse offset relative to the helper if \'cursorAt\' is supplied\n
\t\tif(o.cursorAt)\n
\t\t\tthis._adjustOffsetFromHelper(o.cursorAt);\n
\n
\t\t//Cache the former DOM position\n
\t\tthis.domPosition = { prev: this.currentItem.prev()[0], parent: this.currentItem.parent()[0] };\n
\n
\t\t//If the helper is not the original, hide the original so it\'s not playing any role during the drag, won\'t cause anything bad this way\n
\t\tif(this.helper[0] != this.currentItem[0]) {\n
\t\t\tthis.currentItem.hide();\n
\t\t}\n
\n
\t\t//Create the placeholder\n
\t\tthis._createPlaceholder();\n
\n
\t\t//Set a containment if given in the options\n
\t\tif(o.containment)\n
\t\t\tthis._setContainment();\n
\n
\t\tif(o.cursor) { // cursor option\n
\t\t\tif ($(\'body\').css("cursor")) this._storedCursor = $(\'body\').css("cursor");\n
\t\t\t$(\'body\').css("cursor", o.cursor);\n
\t\t}\n
\n
\t\tif(o.opacity) { // opacity option\n
\t\t\tif (this.helper.css("opacity")) this._storedOpacity = this.helper.css("opacity");\n
\t\t\tthis.helper.css("opacity", o.opacity);\n
\t\t}\n
\n
\t\tif(o.zIndex) { // zIndex option\n
\t\t\tif (this.helper.css("zIndex")) this._storedZIndex = this.helper.css("zIndex");\n
\t\t\tthis.helper.css("zIndex", o.zIndex);\n
\t\t}\n
\n
\t\t//Prepare scrolling\n
\t\tif(this.scrollParent[0] != document && this.scrollParent[0].tagName != \'HTML\')\n
\t\t\tthis.overflowOffset = this.scrollParent.offset();\n
\n
\t\t//Call callbacks\n
\t\tthis._trigger("start", event, this._uiHash());\n
\n
\t\t//Recache the helper size\n
\t\tif(!this._preserveHelperProportions)\n
\t\t\tthis._cacheHelperProportions();\n
\n
\n
\t\t//Post \'activate\' events to possible containers\n
\t\tif(!noActivation) {\n
\t\t\t for (var i = this.containers.length - 1; i >= 0; i--) { this.containers[i]._trigger("activate", event, self._uiHash(this)); }\n
\t\t}\n
\n
\t\t//Prepare possible droppables\n
\t\tif($.ui.ddmanager)\n
\t\t\t$.ui.ddmanager.current = this;\n
\n
\t\tif ($.ui.ddmanager && !o.dropBehaviour)\n
\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\n
\t\tthis.dragging = true;\n
\n
\t\tthis.helper.addClass("ui-sortable-helper");\n
\t\tthis._mouseDrag(event); //Execute the drag once - this causes the helper not to be visible before getting its correct position\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\n
\t\t//Compute the helpers position\n
\t\tthis.position = this._generatePosition(event);\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\tif (!this.lastPositionAbs) {\n
\t\t\tthis.lastPositionAbs = this.positionAbs;\n
\t\t}\n
\n
\t\t//Do scrolling\n
\t\tif(this.options.scroll) {\n
\t\t\tvar o = this.options, scrolled = false;\n
\t\t\tif(this.scrollParent[0] != document && this.scrollParent[0].tagName != \'HTML\') {\n
\n
\t\t\t\tif((this.overflowOffset.top + this.scrollParent[0].offsetHeight) - event.pageY < o.scrollSensitivity)\n
\t\t\t\t\tthis.scrollParent[0].scrollTop = scrolled = this.scrollParent[0].scrollTop + o.scrollSpeed;\n
\t\t\t\telse if(event.pageY - this.overflowOffset.top < o.scrollSensitivity)\n
\t\t\t\t\tthis.scrollParent[0].scrollTop = scrolled = this.scrollParent[0].scrollTop - o.scrollSpeed;\n
\n
\t\t\t\tif((this.overflowOffset.left + this.scrollParent[0].offsetWidth) - event.pageX < o.scrollSensitivity)\n
\t\t\t\t\tthis.scrollParent[0].scrollLeft = scrolled = this.scrollParent[0].scrollLeft + o.scrollSpeed;\n
\t\t\t\telse if(event.pageX - this.overflowOffset.left < o.scrollSensitivity)\n
\t\t\t\t\tthis.scrollParent[0].scrollLeft = scrolled = this.scrollParent[0].scrollLeft - o.scrollSpeed;\n
\n
\t\t\t} else {\n
\n
\t\t\t\tif(event.pageY - $(document).scrollTop() < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() - o.scrollSpeed);\n
\t\t\t\telse if($(window).height() - (event.pageY - $(document).scrollTop()) < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollTop($(document).scrollTop() + o.scrollSpeed);\n
\n
\t\t\t\tif(event.pageX - $(document).scrollLeft() < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() - o.scrollSpeed);\n
\t\t\t\telse if($(window).width() - (event.pageX - $(document).scrollLeft()) < o.scrollSensitivity)\n
\t\t\t\t\tscrolled = $(document).scrollLeft($(document).scrollLeft() + o.scrollSpeed);\n
\n
\t\t\t}\n
\n
\t\t\tif(scrolled !== false && $.ui.ddmanager && !o.dropBehaviour)\n
\t\t\t\t$.ui.ddmanager.prepareOffsets(this, event);\n
\t\t}\n
\n
\t\t//Regenerate the absolute position used for position checks\n
\t\tthis.positionAbs = this._convertPositionTo("absolute");\n
\n
\t\t//Set the helper position\n
\t\tif(!this.options.axis || this.options.axis != "y") this.helper[0].style.left = this.position.left+\'px\';\n
\t\tif(!this.options.axis || this.options.axis != "x") this.helper[0].style.top = this.position.top+\'px\';\n
\n
\t\t//Rearrange\n
\t\tfor (var i = this.items.length - 1; i >= 0; i--) {\n
\n
\t\t\t//Cache variables and intersection, continue if no intersection\n
\t\t\tvar item = this.items[i], itemElement = item.item[0], intersection = this._intersectsWithPointer(item);\n
\t\t\tif (!intersection) continue;\n
\n
\t\t\tif(itemElement != this.currentItem[0] //cannot intersect with itself\n
\t\t\t\t&&\tthis.placeholder[intersection == 1 ? "next" : "prev"]()[0] != itemElement //no useless actions that have been done before\n
\t\t\t\t&&\t!$.ui.contains(this.placeholder[0], itemElement) //no action if the item moved is the parent of the item checked\n
\t\t\t\t&& (this.options.type == \'semi-dynamic\' ? !$.ui.contains(this.element[0], itemElement) : true)\n
\t\t\t) {\n
\n
\t\t\t\tthis.direction = intersection == 1 ? "down" : "up";\n
\n
\t\t\t\tif (this.options.tolerance == "pointer" || this._intersectsWithSides(item)) {\n
\t\t\t\t\tthis._rearrange(event, item);\n
\t\t\t\t} else {\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tthis._trigger("change", event, this._uiHash());\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Post events to containers\n
\t\tthis._contactContainers(event);\n
\n
\t\t//Interconnect with droppables\n
\t\tif($.ui.ddmanager) $.ui.ddmanager.drag(this, event);\n
\n
\t\t//Call callbacks\n
\t\tthis._trigger(\'sort\', event, this._uiHash());\n
\n
\t\tthis.lastPositionAbs = this.positionAbs;\n
\t\treturn false;\n
\n
\t},\n
\n
\t_mouseStop: function(event, noPropagation) {\n
\n
\t\tif(!event) return;\n
\n
\t\t//If we are using droppables, inform the manager about the drop\n
\t\tif ($.ui.ddmanager && !this.options.dropBehaviour)\n
\t\t\t$.ui.ddmanager.drop(this, event);\n
\n
\t\tif(this.options.revert) {\n
\t\t\tvar self = this;\n
\t\t\tvar cur = self.placeholder.offset();\n
\n
\t\t\tself.reverting = true;\n
\n
\t\t\t$(this.helper).animate({\n
\t\t\t\tleft: cur.left - this.offset.parent.left - self.margins.left + (this.offsetParent[0] == document.body ? 0 : this.offsetParent[0].scrollLeft),\n
\t\t\t\ttop: cur.top - this.offset.parent.top - self.margins.top + (this.offsetParent[0] == document.body ? 0 : this.offsetParent[0].scrollTop)\n
\t\t\t}, parseInt(this.options.revert, 10) || 500, function() {\n
\t\t\t\tself._clear(event);\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis._clear(event, noPropagation);\n
\t\t}\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\tcancel: function() {\n
\n
\t\tvar self = this;\n
\n
\t\tif(this.dragging) {\n
\n
\t\t\tthis._mouseUp();\n
\n
\t\t\tif(this.options.helper == "original")\n
\t\t\t\tthis.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");\n
\t\t\telse\n
\t\t\t\tthis.currentItem.show();\n
\n
\t\t\t//Post deactivating events to containers\n
\t\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\t\t\t\tthis.containers[i]._trigger("deactivate", null, self._uiHash(this));\n
\t\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\t\tthis.containers[i]._trigger("out", null, self._uiHash(this));\n
\t\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\t//$(this.placeholder[0]).remove(); would have been the jQuery way - unfortunately, it unbinds ALL events from the original node!\n
\t\tif(this.placeholder[0].parentNode) this.placeholder[0].parentNode.removeChild(this.placeholder[0]);\n
\t\tif(this.options.helper != "original" && this.helper && this.helper[0].parentNode) this.helper.remove();\n
\n
\t\t$.extend(this, {\n
\t\t\thelper: null,\n
\t\t\tdragging: false,\n
\t\t\treverting: false,\n
\t\t\t_noFinalSort: null\n
\t\t});\n
\n
\t\tif(this.domPosition.prev) {\n
\t\t\t$(this.domPosition.prev).after(this.currentItem);\n
\t\t} else {\n
\t\t\t$(this.domPosition.parent).prepend(this.currentItem);\n
\t\t}\n
\n
\t\treturn true;\n
\n
\t},\n
\n
\tserialize: function(o) {\n
\n
\t\tvar items = this._getItemsAsjQuery(o && o.connected);\n
\t\tvar str = []; o = o || {};\n
\n
\t\t$(items).each(function() {\n
\t\t\tvar res = ($(o.item || this).attr(o.attribute || \'id\') || \'\').match(o.expression || (/(.+)[-=_](.+)/));\n
\t\t\tif(res) str.push((o.key || res[1]+\'[]\')+\'=\'+(o.key && o.expression ? res[1] : res[2]));\n
\t\t});\n
\n
\t\treturn str.join(\'&\');\n
\n
\t},\n
\n
\ttoArray: function(o) {\n
\n
\t\tvar items = this._getItemsAsjQuery(o && o.connected);\n
\t\tvar ret = []; o = o || {};\n
\n
\t\titems.each(function() { ret.push($(o.item || this).attr(o.attribute || \'id\') || \'\'); });\n
\t\treturn ret;\n
\n
\t},\n
\n
\t/* Be careful with the following core functions */\n
\t_intersectsWith: function(item) {\n
\n
\t\tvar x1 = this.positionAbs.left,\n
\t\t\tx2 = x1 + this.helperProportions.width,\n
\t\t\ty1 = this.positionAbs.top,\n
\t\t\ty2 = y1 + this.helperProportions.height;\n
\n
\t\tvar l = item.left,\n
\t\t\tr = l + item.width,\n
\t\t\tt = item.top,\n
\t\t\tb = t + item.height;\n
\n
\t\tvar dyClick = this.offset.click.top,\n
\t\t\tdxClick = this.offset.click.left;\n
\n
\t\tvar isOverElement = (y1 + dyClick) > t && (y1 + dyClick) < b && (x1 + dxClick) > l && (x1 + dxClick) < r;\n
\n
\t\tif(\t   this.options.tolerance == "pointer"\n
\t\t\t|| this.options.forcePointerForContainers\n
\t\t\t|| (this.options.tolerance != "pointer" && this.helperProportions[this.floating ? \'width\' : \'height\'] > item[this.floating ? \'width\' : \'height\'])\n
\t\t) {\n
\t\t\treturn isOverElement;\n
\t\t} else {\n
\n
\t\t\treturn (l < x1 + (this.helperProportions.width / 2) // Right Half\n
\t\t\t\t&& x2 - (this.helperProportions.width / 2) < r // Left Half\n
\t\t\t\t&& t < y1 + (this.helperProportions.height / 2) // Bottom Half\n
\t\t\t\t&& y2 - (this.helperProportions.height / 2) < b ); // Top Half\n
\n
\t\t}\n
\t},\n
\n
\t_intersectsWithPointer: function(item) {\n
\n
\t\tvar isOverElementHeight = $.ui.isOverAxis(this.positionAbs.top + this.offset.click.top, item.top, item.height),\n
\t\t\tisOverElementWidth = $.ui.isOverAxis(this.positionAbs.left + this.offset.click.left, item.left, item.width),\n
\t\t\tisOverElement = isOverElementHeight && isOverElementWidth,\n
\t\t\tverticalDirection = this._getDragVerticalDirection(),\n
\t\t\thorizontalDirection = this._getDragHorizontalDirection();\n
\n
\t\tif (!isOverElement)\n
\t\t\treturn false;\n
\n
\t\treturn this.floating ?\n
\t\t\t( ((horizontalDirection && horizontalDirection == "right") || verticalDirection == "down") ? 2 : 1 )\n
\t\t\t: ( verticalDirection && (verticalDirection == "down" ? 2 : 1) );\n
\n
\t},\n
\n
\t_intersectsWithSides: function(item) {\n
\n
\t\tvar isOverBottomHalf = $.ui.isOverAxis(this.positionAbs.top + this.offset.click.top, item.top + (item.height/2), item.height),\n
\t\t\tisOverRightHalf = $.ui.isOverAxis(this.positionAbs.left + this.offset.click.left, item.left + (item.width/2), item.width),\n
\t\t\tverticalDirection = this._getDragVerticalDirection(),\n
\t\t\thorizontalDirection = this._getDragHorizontalDirection();\n
\n
\t\tif (this.floating && horizontalDirection) {\n
\t\t\treturn ((horizontalDirection == "right" && isOverRightHalf) || (horizontalDirection == "left" && !isOverRightHalf));\n
\t\t} else {\n
\t\t\treturn verticalDirection && ((verticalDirection == "down" && isOverBottomHalf) || (verticalDirection == "up" && !isOverBottomHalf));\n
\t\t}\n
\n
\t},\n
\n
\t_getDragVerticalDirection: function() {\n
\t\tvar delta = this.positionAbs.top - this.lastPositionAbs.top;\n
\t\treturn delta != 0 && (delta > 0 ? "down" : "up");\n
\t},\n
\n
\t_getDragHorizontalDirection: function() {\n
\t\tvar delta = this.positionAbs.left - this.lastPositionAbs.left;\n
\t\treturn delta != 0 && (delta > 0 ? "right" : "left");\n
\t},\n
\n
\trefresh: function(event) {\n
\t\tthis._refreshItems(event);\n
\t\tthis.refreshPositions();\n
\t},\n
\n
\t_connectWith: function() {\n
\t\tvar options = this.options;\n
\t\treturn options.connectWith.constructor == String\n
\t\t\t? [options.connectWith]\n
\t\t\t: options.connectWith;\n
\t},\n
\t\n
\t_getItemsAsjQuery: function(connected) {\n
\n
\t\tvar self = this;\n
\t\tvar items = [];\n
\t\tvar queries = [];\n
\t\tvar connectWith = this._connectWith();\n
\n
\t\tif(connectWith && connected) {\n
\t\t\tfor (var i = connectWith.length - 1; i >= 0; i--){\n
\t\t\t\tvar cur = $(connectWith[i]);\n
\t\t\t\tfor (var j = cur.length - 1; j >= 0; j--){\n
\t\t\t\t\tvar inst = $.data(cur[j], \'sortable\');\n
\t\t\t\t\tif(inst && inst != this && !inst.options.disabled) {\n
\t\t\t\t\t\tqueries.push([$.isFunction(inst.options.items) ? inst.options.items.call(inst.element) : $(inst.options.items, inst.element).not(".ui-sortable-helper"), inst]);\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t};\n
\t\t}\n
\n
\t\tqueries.push([$.isFunction(this.options.items) ? this.options.items.call(this.element, null, { options: this.options, item: this.currentItem }) : $(this.options.items, this.element).not(".ui-sortable-helper"), this]);\n
\n
\t\tfor (var i = queries.length - 1; i >= 0; i--){\n
\t\t\tqueries[i][0].each(function() {\n
\t\t\t\titems.push(this);\n
\t\t\t});\n
\t\t};\n
\n
\t\treturn $(items);\n
\n
\t},\n
\n
\t_removeCurrentsFromItems: function() {\n
\n
\t\tvar list = this.currentItem.find(":data(sortable-item)");\n
\n
\t\tfor (var i=0; i < this.items.length; i++) {\n
\n
\t\t\tfor (var j=0; j < list.length; j++) {\n
\t\t\t\tif(list[j] == this.items[i].item[0])\n
\t\t\t\t\tthis.items.splice(i,1);\n
\t\t\t};\n
\n
\t\t};\n
\n
\t},\n
\n
\t_refreshItems: function(event) {\n
\n
\t\tthis.items = [];\n
\t\tthis.containers = [this];\n
\t\tvar items = this.items;\n
\t\tvar self = this;\n
\t\tvar queries = [[$.isFunction(this.options.items) ? this.options.items.call(this.element[0], event, { item: this.currentItem }) : $(this.options.items, this.element), this]];\n
\t\tvar connectWith = this._connectWith();\n
\n
\t\tif(connectWith) {\n
\t\t\tfor (var i = connectWith.length - 1; i >= 0; i--){\n
\t\t\t\tvar cur = $(connectWith[i]);\n
\t\t\t\tfor (var j = cur.length - 1; j >= 0; j--){\n
\t\t\t\t\tvar inst = $.data(cur[j], \'sortable\');\n
\t\t\t\t\tif(inst && inst != this && !inst.options.disabled) {\n
\t\t\t\t\t\tqueries.push([$.isFunction(inst.options.items) ? inst.options.items.call(inst.element[0], event, { item: this.currentItem }) : $(inst.options.items, inst.element), inst]);\n
\t\t\t\t\t\tthis.containers.push(inst);\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t};\n
\t\t}\n
\n
\t\tfor (var i = queries.length - 1; i >= 0; i--) {\n
\t\t\tvar targetData = queries[i][1];\n
\t\t\tvar _queries = queries[i][0];\n
\n
\t\t\tfor (var j=0, queriesLength = _queries.length; j < queriesLength; j++) {\n
\t\t\t\tvar item = $(_queries[j]);\n
\n
\t\t\t\titem.data(\'sortable-item\', targetData); // Data for target checking (mouse manager)\n
\n
\t\t\t\titems.push({\n
\t\t\t\t\titem: item,\n
\t\t\t\t\tinstance: targetData,\n
\t\t\t\t\twidth: 0, height: 0,\n
\t\t\t\t\tleft: 0, top: 0\n
\t\t\t\t});\n
\t\t\t};\n
\t\t};\n
\n
\t},\n
\n
\trefreshPositions: function(fast) {\n
\n
\t\t//This has to be redone because due to the item being moved out/into the offsetParent, the offsetParent\'s position will change\n
\t\tif(this.offsetParent && this.helper) {\n
\t\t\tthis.offset.parent = this._getParentOffset();\n
\t\t}\n
\n
\t\tfor (var i = this.items.length - 1; i >= 0; i--){\n
\t\t\tvar item = this.items[i];\n
\n
\t\t\t//We ignore calculating positions of all connected containers when we\'re not over them\n
\t\t\tif(item.instance != this.currentContainer && this.currentContainer && item.item[0] != this.currentItem[0])\n
\t\t\t\tcontinue;\n
\n
\t\t\tvar t = this.options.toleranceElement ? $(this.options.toleranceElement, item.item) : item.item;\n
\n
\t\t\tif (!fast) {\n
\t\t\t\titem.width = t.outerWidth();\n
\t\t\t\titem.height = t.outerHeight();\n
\t\t\t}\n
\n
\t\t\tvar p = t.offset();\n
\t\t\titem.left = p.left;\n
\t\t\titem.top = p.top;\n
\t\t};\n
\n
\t\tif(this.options.custom && this.options.custom.refreshContainers) {\n
\t\t\tthis.options.custom.refreshContainers.call(this);\n
\t\t} else {\n
\t\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\t\t\t\tvar p = this.containers[i].element.offset();\n
\t\t\t\tthis.containers[i].containerCache.left = p.left;\n
\t\t\t\tthis.containers[i].containerCache.top = p.top;\n
\t\t\t\tthis.containers[i].containerCache.width\t= this.containers[i].element.outerWidth();\n
\t\t\t\tthis.containers[i].containerCache.height = this.containers[i].element.outerHeight();\n
\t\t\t};\n
\t\t}\n
\n
\t},\n
\n
\t_createPlaceholder: function(that) {\n
\n
\t\tvar self = that || this, o = self.options;\n
\n
\t\tif(!o.placeholder || o.placeholder.constructor == String) {\n
\t\t\tvar className = o.placeholder;\n
\t\t\to.placeholder = {\n
\t\t\t\telement: function() {\n
\n
\t\t\t\t\tvar el = $(document.createElement(self.currentItem[0].nodeName))\n
\t\t\t\t\t\t.addClass(className || self.currentItem[0].className+" ui-sortable-placeholder")\n
\t\t\t\t\t\t.removeClass("ui-sortable-helper")[0];\n
\n
\t\t\t\t\tif(!className)\n
\t\t\t\t\t\tel.style.visibility = "hidden";\n
\n
\t\t\t\t\treturn el;\n
\t\t\t\t},\n
\t\t\t\tupdate: function(container, p) {\n
\n
\t\t\t\t\t// 1. If a className is set as \'placeholder option, we don\'t force sizes - the class is responsible for that\n
\t\t\t\t\t// 2. The option \'forcePlaceholderSize can be enabled to force it even if a class name is specified\n
\t\t\t\t\tif(className && !o.forcePlaceholderSize) return;\n
\n
\t\t\t\t\t//If the element doesn\'t have a actual height by itself (without styles coming from a stylesheet), it receives the inline height from the dragged item\n
\t\t\t\t\tif(!p.height()) { p.height(self.currentItem.innerHeight() - parseInt(self.currentItem.css(\'paddingTop\')||0, 10) - parseInt(self.currentItem.css(\'paddingBottom\')||0, 10)); };\n
\t\t\t\t\tif(!p.width()) { p.width(self.currentItem.innerWidth() - parseInt(self.currentItem.css(\'paddingLeft\')||0, 10) - parseInt(self.currentItem.css(\'paddingRight\')||0, 10)); };\n
\t\t\t\t}\n
\t\t\t};\n
\t\t}\n
\n
\t\t//Create the placeholder\n
\t\tself.placeholder = $(o.placeholder.element.call(self.element, self.currentItem));\n
\n
\t\t//Append it after the actual current item\n
\t\tself.currentItem.after(self.placeholder);\n
\n
\t\t//Update the size of the placeholder (TODO: Logic to fuzzy, see line 316/317)\n
\t\to.placeholder.update(self, self.placeholder);\n
\n
\t},\n
\n
\t_contactContainers: function(event) {\n
\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\n
\t\t\tif(this._intersectsWith(this.containers[i].containerCache)) {\n
\t\t\t\tif(!this.containers[i].containerCache.over) {\n
\n
\t\t\t\t\tif(this.currentContainer != this.containers[i]) {\n
\n
\t\t\t\t\t\t//When entering a new container, we will find the item with the least distance and append our item near it\n
\t\t\t\t\t\tvar dist = 10000; var itemWithLeastDistance = null; var base = this.positionAbs[this.containers[i].floating ? \'left\' : \'top\'];\n
\t\t\t\t\t\tfor (var j = this.items.length - 1; j >= 0; j--) {\n
\t\t\t\t\t\t\tif(!$.ui.contains(this.containers[i].element[0], this.items[j].item[0])) continue;\n
\t\t\t\t\t\t\tvar cur = this.items[j][this.containers[i].floating ? \'left\' : \'top\'];\n
\t\t\t\t\t\t\tif(Math.abs(cur - base) < dist) {\n
\t\t\t\t\t\t\t\tdist = Math.abs(cur - base); itemWithLeastDistance = this.items[j];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tif(!itemWithLeastDistance && !this.options.dropOnEmpty) //Check if dropOnEmpty is enabled\n
\t\t\t\t\t\t\tcontinue;\n
\n
\t\t\t\t\t\tthis.currentContainer = this.containers[i];\n
\t\t\t\t\t\titemWithLeastDistance ? this._rearrange(event, itemWithLeastDistance, null, true) : this._rearrange(event, null, this.containers[i].element, true);\n
\t\t\t\t\t\tthis._trigger("change", event, this._uiHash());\n
\t\t\t\t\t\tthis.containers[i]._trigger("change", event, this._uiHash(this));\n
\n
\t\t\t\t\t\t//Update the placeholder\n
\t\t\t\t\t\tthis.options.placeholder.update(this.currentContainer, this.placeholder);\n
\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tthis.containers[i]._trigger("over", event, this._uiHash(this));\n
\t\t\t\t\tthis.containers[i].containerCache.over = 1;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\t\tthis.containers[i]._trigger("out", event, this._uiHash(this));\n
\t\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t};\n
\t},\n
\n
\t_createHelper: function(event) {\n
\n
\t\tvar o = this.options;\n
\t\tvar helper = $.isFunction(o.helper) ? $(o.helper.apply(this.element[0], [event, this.currentItem])) : (o.helper == \'clone\' ? this.currentItem.clone() : this.currentItem);\n
\n
\t\tif(!helper.parents(\'body\').length) //Add the helper to the DOM if that didn\'t happen already\n
\t\t\t$(o.appendTo != \'parent\' ? o.appendTo : this.currentItem[0].parentNode)[0].appendChild(helper[0]);\n
\n
\t\tif(helper[0] == this.currentItem[0])\n
\t\t\tthis._storedCSS = { width: this.currentItem[0].style.width, height: this.currentItem[0].style.height, position: this.currentItem.css("position"), top: this.currentItem.css("top"), left: this.currentItem.css("left") };\n
\n
\t\tif(helper[0].style.width == \'\' || o.forceHelperSize) helper.width(this.currentItem.width());\n
\t\tif(helper[0].style.height == \'\' || o.forceHelperSize) helper.height(this.currentItem.height());\n
\n
\t\treturn helper;\n
\n
\t},\n
\n
\t_adjustOffsetFromHelper: function(obj) {\n
\t\tif(obj.left != undefined) this.offset.click.left = obj.left + this.margins.left;\n
\t\tif(obj.right != undefined) this.offset.click.left = this.helperProportions.width - obj.right + this.margins.left;\n
\t\tif(obj.top != undefined) this.offset.click.top = obj.top + this.margins.top;\n
\t\tif(obj.bottom != undefined) this.offset.click.top = this.helperProportions.height - obj.bottom + this.margins.top;\n
\t},\n
\n
\t_getParentOffset: function() {\n
\n
\n
\t\t//Get the offsetParent and cache its position\n
\t\tthis.offsetParent = this.helper.offsetParent();\n
\t\tvar po = this.offsetParent.offset();\n
\n
\t\t// This is a special case where we need to modify a offset calculated on start, since the following happened:\n
\t\t// 1. The position of the helper is absolute, so it\'s position is calculated based on the next positioned parent\n
\t\t// 2. 

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
      <tuple>
        <global name="Pdata" module="OFS.Image"/>
        <tuple/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

The actual offset parent is a child of the scroll parent, and the scroll parent isn\'t the document, which means that\n
\t\t//    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag\n
\t\tif(this.cssPosition == \'absolute\' && this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) {\n
\t\t\tpo.left += this.scrollParent.scrollLeft();\n
\t\t\tpo.top += this.scrollParent.scrollTop();\n
\t\t}\n
\n
\t\tif((this.offsetParent[0] == document.body) //This needs to be actually done for all browsers, since pageX/pageY includes this information\n
\t\t|| (this.offsetParent[0].tagName && this.offsetParent[0].tagName.toLowerCase() == \'html\' && $.browser.msie)) //Ugly IE fix\n
\t\t\tpo = { top: 0, left: 0 };\n
\n
\t\treturn {\n
\t\t\ttop: po.top + (parseInt(this.offsetParent.css("borderTopWidth"),10) || 0),\n
\t\t\tleft: po.left + (parseInt(this.offsetParent.css("borderLeftWidth"),10) || 0)\n
\t\t};\n
\n
\t},\n
\n
\t_getRelativeOffset: function() {\n
\n
\t\tif(this.cssPosition == "relative") {\n
\t\t\tvar p = this.currentItem.position();\n
\t\t\treturn {\n
\t\t\t\ttop: p.top - (parseInt(this.helper.css("top"),10) || 0) + this.scrollParent.scrollTop(),\n
\t\t\t\tleft: p.left - (parseInt(this.helper.css("left"),10) || 0) + this.scrollParent.scrollLeft()\n
\t\t\t};\n
\t\t} else {\n
\t\t\treturn { top: 0, left: 0 };\n
\t\t}\n
\n
\t},\n
\n
\t_cacheMargins: function() {\n
\t\tthis.margins = {\n
\t\t\tleft: (parseInt(this.currentItem.css("marginLeft"),10) || 0),\n
\t\t\ttop: (parseInt(this.currentItem.css("marginTop"),10) || 0)\n
\t\t};\n
\t},\n
\n
\t_cacheHelperProportions: function() {\n
\t\tthis.helperProportions = {\n
\t\t\twidth: this.helper.outerWidth(),\n
\t\t\theight: this.helper.outerHeight()\n
\t\t};\n
\t},\n
\n
\t_setContainment: function() {\n
\n
\t\tvar o = this.options;\n
\t\tif(o.containment == \'parent\') o.containment = this.helper[0].parentNode;\n
\t\tif(o.containment == \'document\' || o.containment == \'window\') this.containment = [\n
\t\t\t0 - this.offset.relative.left - this.offset.parent.left,\n
\t\t\t0 - this.offset.relative.top - this.offset.parent.top,\n
\t\t\t$(o.containment == \'document\' ? document : window).width() - this.helperProportions.width - this.margins.left,\n
\t\t\t($(o.containment == \'document\' ? document : window).height() || document.body.parentNode.scrollHeight) - this.helperProportions.height - this.margins.top\n
\t\t];\n
\n
\t\tif(!(/^(document|window|parent)$/).test(o.containment)) {\n
\t\t\tvar ce = $(o.containment)[0];\n
\t\t\tvar co = $(o.containment).offset();\n
\t\t\tvar over = ($(ce).css("overflow") != \'hidden\');\n
\n
\t\t\tthis.containment = [\n
\t\t\t\tco.left + (parseInt($(ce).css("borderLeftWidth"),10) || 0) + (parseInt($(ce).css("paddingLeft"),10) || 0) - this.margins.left,\n
\t\t\t\tco.top + (parseInt($(ce).css("borderTopWidth"),10) || 0) + (parseInt($(ce).css("paddingTop"),10) || 0) - this.margins.top,\n
\t\t\t\tco.left+(over ? Math.max(ce.scrollWidth,ce.offsetWidth) : ce.offsetWidth) - (parseInt($(ce).css("borderLeftWidth"),10) || 0) - (parseInt($(ce).css("paddingRight"),10) || 0) - this.helperProportions.width - this.margins.left,\n
\t\t\t\tco.top+(over ? Math.max(ce.scrollHeight,ce.offsetHeight) : ce.offsetHeight) - (parseInt($(ce).css("borderTopWidth"),10) || 0) - (parseInt($(ce).css("paddingBottom"),10) || 0) - this.helperProportions.height - this.margins.top\n
\t\t\t];\n
\t\t}\n
\n
\t},\n
\n
\t_convertPositionTo: function(d, pos) {\n
\n
\t\tif(!pos) pos = this.position;\n
\t\tvar mod = d == "absolute" ? 1 : -1;\n
\t\tvar o = this.options, scroll = this.cssPosition == \'absolute\' && !(this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent, scrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpos.top\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t+ this.offset.relative.top * mod\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t+ this.offset.parent.top * mod\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t- ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ) * mod)\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpos.left\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t+ this.offset.relative.left * mod\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t+ this.offset.parent.left * mod\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t- ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ) * mod)\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_generatePosition: function(event) {\n
\n
\t\tvar o = this.options, scroll = this.cssPosition == \'absolute\' && !(this.scrollParent[0] != document && $.ui.contains(this.scrollParent[0], this.offsetParent[0])) ? this.offsetParent : this.scrollParent, scrollIsRootNode = (/(html|body)/i).test(scroll[0].tagName);\n
\n
\t\t// This is another very weird special case that only happens for relative elements:\n
\t\t// 1. If the css position is relative\n
\t\t// 2. and the scroll parent is the document or similar to the offset parent\n
\t\t// we have to refresh the relative offset during the scroll so there are no jumps\n
\t\tif(this.cssPosition == \'relative\' && !(this.scrollParent[0] != document && this.scrollParent[0] != this.offsetParent[0])) {\n
\t\t\tthis.offset.relative = this._getRelativeOffset();\n
\t\t}\n
\n
\t\tvar pageX = event.pageX;\n
\t\tvar pageY = event.pageY;\n
\n
\t\t/*\n
\t\t * - Position constraining -\n
\t\t * Constrain the position to a mix of grid, containment.\n
\t\t */\n
\n
\t\tif(this.originalPosition) { //If we are not dragging yet, we won\'t check for options\n
\n
\t\t\tif(this.containment) {\n
\t\t\t\tif(event.pageX - this.offset.click.left < this.containment[0]) pageX = this.containment[0] + this.offset.click.left;\n
\t\t\t\tif(event.pageY - this.offset.click.top < this.containment[1]) pageY = this.containment[1] + this.offset.click.top;\n
\t\t\t\tif(event.pageX - this.offset.click.left > this.containment[2]) pageX = this.containment[2] + this.offset.click.left;\n
\t\t\t\tif(event.pageY - this.offset.click.top > this.containment[3]) pageY = this.containment[3] + this.offset.click.top;\n
\t\t\t}\n
\n
\t\t\tif(o.grid) {\n
\t\t\t\tvar top = this.originalPageY + Math.round((pageY - this.originalPageY) / o.grid[1]) * o.grid[1];\n
\t\t\t\tpageY = this.containment ? (!(top - this.offset.click.top < this.containment[1] || top - this.offset.click.top > this.containment[3]) ? top : (!(top - this.offset.click.top < this.containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;\n
\n
\t\t\t\tvar left = this.originalPageX + Math.round((pageX - this.originalPageX) / o.grid[0]) * o.grid[0];\n
\t\t\t\tpageX = this.containment ? (!(left - this.offset.click.left < this.containment[0] || left - this.offset.click.left > this.containment[2]) ? left : (!(left - this.offset.click.left < this.containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;\n
\t\t\t}\n
\n
\t\t}\n
\n
\t\treturn {\n
\t\t\ttop: (\n
\t\t\t\tpageY\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t- this.offset.click.top\t\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\t- this.offset.relative.top\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t- this.offset.parent.top\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t+ ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollTop() : ( scrollIsRootNode ? 0 : scroll.scrollTop() ) ))\n
\t\t\t),\n
\t\t\tleft: (\n
\t\t\t\tpageX\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// The absolute mouse position\n
\t\t\t\t- this.offset.click.left\t\t\t\t\t\t\t\t\t\t\t\t// Click offset (relative to the element)\n
\t\t\t\t- this.offset.relative.left\t\t\t\t\t\t\t\t\t\t\t\t// Only for relative positioned nodes: Relative offset from element to offset parent\n
\t\t\t\t- this.offset.parent.left\t\t\t\t\t\t\t\t\t\t\t\t// The offsetParent\'s offset without borders (offset + border)\n
\t\t\t\t+ ($.browser.safari && this.cssPosition == \'fixed\' ? 0 : ( this.cssPosition == \'fixed\' ? -this.scrollParent.scrollLeft() : scrollIsRootNode ? 0 : scroll.scrollLeft() ))\n
\t\t\t)\n
\t\t};\n
\n
\t},\n
\n
\t_rearrange: function(event, i, a, hardRefresh) {\n
\n
\t\ta ? a[0].appendChild(this.placeholder[0]) : i.item[0].parentNode.insertBefore(this.placeholder[0], (this.direction == \'down\' ? i.item[0] : i.item[0].nextSibling));\n
\n
\t\t//Various things done here to improve the performance:\n
\t\t// 1. we create a setTimeout, that calls refreshPositions\n
\t\t// 2. on the instance, we have a counter variable, that get\'s higher after every append\n
\t\t// 3. on the local scope, we copy the counter variable, and check in the timeout, if it\'s still the same\n
\t\t// 4. this lets only the last addition to the timeout stack through\n
\t\tthis.counter = this.counter ? ++this.counter : 1;\n
\t\tvar self = this, counter = this.counter;\n
\n
\t\twindow.setTimeout(function() {\n
\t\t\tif(counter == self.counter) self.refreshPositions(!hardRefresh); //Precompute after each DOM insertion, NOT on mousemove\n
\t\t},0);\n
\n
\t},\n
\n
\t_clear: function(event, noPropagation) {\n
\n
\t\tthis.reverting = false;\n
\t\t// We delay all events that have to be triggered to after the point where the placeholder has been removed and\n
\t\t// everything else normalized again\n
\t\tvar delayedTriggers = [], self = this;\n
\n
\t\t// We first have to update the dom position of the actual currentItem\n
\t\t// Note: don\'t do it if the current item is already removed (by a user), or it gets reappended (see #4088)\n
\t\tif(!this._noFinalSort && this.currentItem[0].parentNode) this.placeholder.before(this.currentItem);\n
\t\tthis._noFinalSort = null;\n
\n
\t\tif(this.helper[0] == this.currentItem[0]) {\n
\t\t\tfor(var i in this._storedCSS) {\n
\t\t\t\tif(this._storedCSS[i] == \'auto\' || this._storedCSS[i] == \'static\') this._storedCSS[i] = \'\';\n
\t\t\t}\n
\t\t\tthis.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");\n
\t\t} else {\n
\t\t\tthis.currentItem.show();\n
\t\t}\n
\n
\t\tif(this.fromOutside && !noPropagation) delayedTriggers.push(function(event) { this._trigger("receive", event, this._uiHash(this.fromOutside)); });\n
\t\tif((this.fromOutside || this.domPosition.prev != this.currentItem.prev().not(".ui-sortable-helper")[0] || this.domPosition.parent != this.currentItem.parent()[0]) && !noPropagation) delayedTriggers.push(function(event) { this._trigger("update", event, this._uiHash()); }); //Trigger update callback if the DOM position has changed\n
\t\tif(!$.ui.contains(this.element[0], this.currentItem[0])) { //Node was moved out of the current element\n
\t\t\tif(!noPropagation) delayedTriggers.push(function(event) { this._trigger("remove", event, this._uiHash()); });\n
\t\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\t\t\t\tif($.ui.contains(this.containers[i].element[0], this.currentItem[0]) && !noPropagation) {\n
\t\t\t\t\tdelayedTriggers.push((function(c) { return function(event) { c._trigger("receive", event, this._uiHash(this)); };  }).call(this, this.containers[i]));\n
\t\t\t\t\tdelayedTriggers.push((function(c) { return function(event) { c._trigger("update", event, this._uiHash(this));  }; }).call(this, this.containers[i]));\n
\t\t\t\t}\n
\t\t\t};\n
\t\t};\n
\n
\t\t//Post events to containers\n
\t\tfor (var i = this.containers.length - 1; i >= 0; i--){\n
\t\t\tif(!noPropagation) delayedTriggers.push((function(c) { return function(event) { c._trigger("deactivate", event, this._uiHash(this)); };  }).call(this, this.containers[i]));\n
\t\t\tif(this.containers[i].containerCache.over) {\n
\t\t\t\tdelayedTriggers.push((function(c) { return function(event) { c._trigger("out", event, this._uiHash(this)); };  }).call(this, this.containers[i]));\n
\t\t\t\tthis.containers[i].containerCache.over = 0;\n
\t\t\t}\n
\t\t}\n
\n
\t\t//Do what was originally in plugins\n
\t\tif(this._storedCursor) $(\'body\').css("cursor", this._storedCursor); //Reset cursor\n
\t\tif(this._storedOpacity) this.helper.css("opacity", this._storedOpacity); //Reset cursor\n
\t\tif(this._storedZIndex) this.helper.css("zIndex", this._storedZIndex == \'auto\' ? \'\' : this._storedZIndex); //Reset z-index\n
\n
\t\tthis.dragging = false;\n
\t\tif(this.cancelHelperRemoval) {\n
\t\t\tif(!noPropagation) {\n
\t\t\t\tthis._trigger("beforeStop", event, this._uiHash());\n
\t\t\t\tfor (var i=0; i < delayedTriggers.length; i++) { delayedTriggers[i].call(this, event); }; //Trigger all delayed events\n
\t\t\t\tthis._trigger("stop", event, this._uiHash());\n
\t\t\t}\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif(!noPropagation) this._trigger("beforeStop", event, this._uiHash());\n
\n
\t\t//$(this.placeholder[0]).remove(); would have been the jQuery way - unfortunately, it unbinds ALL events from the original node!\n
\t\tthis.placeholder[0].parentNode.removeChild(this.placeholder[0]);\n
\n
\t\tif(this.helper[0] != this.currentItem[0]) this.helper.remove(); this.helper = null;\n
\n
\t\tif(!noPropagation) {\n
\t\t\tfor (var i=0; i < delayedTriggers.length; i++) { delayedTriggers[i].call(this, event); }; //Trigger all delayed events\n
\t\t\tthis._trigger("stop", event, this._uiHash());\n
\t\t}\n
\n
\t\tthis.fromOutside = false;\n
\t\treturn true;\n
\n
\t},\n
\n
\t_trigger: function() {\n
\t\tif ($.widget.prototype._trigger.apply(this, arguments) === false) {\n
\t\t\tthis.cancel();\n
\t\t}\n
\t},\n
\n
\t_uiHash: function(inst) {\n
\t\tvar self = inst || this;\n
\t\treturn {\n
\t\t\thelper: self.helper,\n
\t\t\tplaceholder: self.placeholder || $([]),\n
\t\t\tposition: self.position,\n
\t\t\tabsolutePosition: self.positionAbs, //deprecated\n
\t\t\toffset: self.positionAbs,\n
\t\t\titem: self.currentItem,\n
\t\t\tsender: inst ? inst.element : null\n
\t\t};\n
\t}\n
\n
}));\n
\n
$.extend($.ui.sortable, {\n
\tgetter: "serialize toArray",\n
\tversion: "1.7.2",\n
\teventPrefix: "sort",\n
\tdefaults: {\n
\t\tappendTo: "parent",\n
\t\taxis: false,\n
\t\tcancel: ":input,option",\n
\t\tconnectWith: false,\n
\t\tcontainment: false,\n
\t\tcursor: \'auto\',\n
\t\tcursorAt: false,\n
\t\tdelay: 0,\n
\t\tdistance: 1,\n
\t\tdropOnEmpty: true,\n
\t\tforcePlaceholderSize: false,\n
\t\tforceHelperSize: false,\n
\t\tgrid: false,\n
\t\thandle: false,\n
\t\thelper: "original",\n
\t\titems: \'> *\',\n
\t\topacity: false,\n
\t\tplaceholder: false,\n
\t\trevert: false,\n
\t\tscroll: true,\n
\t\tscrollSensitivity: 20,\n
\t\tscrollSpeed: 20,\n
\t\tscope: "default",\n
\t\ttolerance: "intersect",\n
\t\tzIndex: 1000\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Accordion 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Accordion\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.accordion", {\n
\n
\t_init: function() {\n
\n
\t\tvar o = this.options, self = this;\n
\t\tthis.running = 0;\n
\n
\t\t// if the user set the alwaysOpen option on init\n
\t\t// then we need to set the collapsible option\n
\t\t// if they set both on init, collapsible will take priority\n
\t\tif (o.collapsible == $.ui.accordion.defaults.collapsible &&\n
\t\t\to.alwaysOpen != $.ui.accordion.defaults.alwaysOpen) {\n
\t\t\to.collapsible = !o.alwaysOpen;\n
\t\t}\n
\n
\t\tif ( o.navigation ) {\n
\t\t\tvar current = this.element.find("a").filter(o.navigationFilter);\n
\t\t\tif ( current.length ) {\n
\t\t\t\tif ( current.filter(o.header).length ) {\n
\t\t\t\t\tthis.active = current;\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.active = current.parent().parent().prev();\n
\t\t\t\t\tcurrent.addClass("ui-accordion-content-active");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\tthis.element.addClass("ui-accordion ui-widget ui-helper-reset");\n
\t\t\n
\t\t// in lack of child-selectors in CSS we need to mark top-LIs in a UL-accordion for some IE-fix\n
\t\tif (this.element[0].nodeName == "UL") {\n
\t\t\tthis.element.children("li").addClass("ui-accordion-li-fix");\n
\t\t}\n
\n
\t\tthis.headers = this.element.find(o.header).addClass("ui-accordion-header ui-helper-reset ui-state-default ui-corner-all")\n
\t\t\t.bind("mouseenter.accordion", function(){ $(this).addClass(\'ui-state-hover\'); })\n
\t\t\t.bind("mouseleave.accordion", function(){ $(this).removeClass(\'ui-state-hover\'); })\n
\t\t\t.bind("focus.accordion", function(){ $(this).addClass(\'ui-state-focus\'); })\n
\t\t\t.bind("blur.accordion", function(){ $(this).removeClass(\'ui-state-focus\'); });\n
\n
\t\tthis.headers\n
\t\t\t.next()\n
\t\t\t\t.addClass("ui-accordion-content ui-helper-reset ui-widget-content ui-corner-bottom");\n
\n
\t\tthis.active = this._findActive(this.active || o.active).toggleClass("ui-state-default").toggleClass("ui-state-active").toggleClass("ui-corner-all").toggleClass("ui-corner-top");\n
\t\tthis.active.next().addClass(\'ui-accordion-content-active\');\n
\n
\t\t//Append icon elements\n
\t\t$("<span/>").addClass("ui-icon " + o.icons.header).prependTo(this.headers);\n
\t\tthis.active.find(".ui-icon").toggleClass(o.icons.header).toggleClass(o.icons.headerSelected);\n
\n
\t\t// IE7-/Win - Extra vertical space in lists fixed\n
\t\tif ($.browser.msie) {\n
\t\t\tthis.element.find(\'a\').css(\'zoom\', \'1\');\n
\t\t}\n
\n
\t\tthis.resize();\n
\n
\t\t//ARIA\n
\t\tthis.element.attr(\'role\',\'tablist\');\n
\n
\t\tthis.headers\n
\t\t\t.attr(\'role\',\'tab\')\n
\t\t\t.bind(\'keydown\', function(event) { return self._keydown(event); })\n
\t\t\t.next()\n
\t\t\t.attr(\'role\',\'tabpanel\');\n
\n
\t\tthis.headers\n
\t\t\t.not(this.active || "")\n
\t\t\t.attr(\'aria-expanded\',\'false\')\n
\t\t\t.attr("tabIndex", "-1")\n
\t\t\t.next()\n
\t\t\t.hide();\n
\n
\t\t// make sure at least one header is in the tab order\n
\t\tif (!this.active.length) {\n
\t\t\tthis.headers.eq(0).attr(\'tabIndex\',\'0\');\n
\t\t} else {\n
\t\t\tthis.active\n
\t\t\t\t.attr(\'aria-expanded\',\'true\')\n
\t\t\t\t.attr(\'tabIndex\', \'0\');\n
\t\t}\n
\n
\t\t// only need links in taborder for Safari\n
\t\tif (!$.browser.safari)\n
\t\t\tthis.headers.find(\'a\').attr(\'tabIndex\',\'-1\');\n
\n
\t\tif (o.event) {\n
\t\t\tthis.headers.bind((o.event) + ".accordion", function(event) { return self._clickHandler.call(self, event, this); });\n
\t\t}\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tvar o = this.options;\n
\n
\t\tthis.element\n
\t\t\t.removeClass("ui-accordion ui-widget ui-helper-reset")\n
\t\t\t.removeAttr("role")\n
\t\t\t.unbind(\'.accordion\')\n
\t\t\t.removeData(\'accordion\');\n
\n
\t\tthis.headers\n
\t\t\t.unbind(".accordion")\n
\t\t\t.removeClass("ui-accordion-header ui-helper-reset ui-state-default ui-corner-all ui-state-active ui-corner-top")\n
\t\t\t.removeAttr("role").removeAttr("aria-expanded").removeAttr("tabindex");\n
\n
\t\tthis.headers.find("a").removeAttr("tabindex");\n
\t\tthis.headers.children(".ui-icon").remove();\n
\t\tvar contents = this.headers.next().css("display", "").removeAttr("role").removeClass("ui-helper-reset ui-widget-content ui-corner-bottom ui-accordion-content ui-accordion-content-active");\n
\t\tif (o.autoHeight || o.fillHeight) {\n
\t\t\tcontents.css("height", "");\n
\t\t}\n
\t},\n
\t\n
\t_setData: function(key, value) {\n
\t\tif(key == \'alwaysOpen\') { key = \'collapsible\'; value = !value; }\n
\t\t$.widget.prototype._setData.apply(this, arguments);\t\n
\t},\n
\n
\t_keydown: function(event) {\n
\n
\t\tvar o = this.options, keyCode = $.ui.keyCode;\n
\n
\t\tif (o.disabled || event.altKey || event.ctrlKey)\n
\t\t\treturn;\n
\n
\t\tvar length = this.headers.length;\n
\t\tvar currentIndex = this.headers.index(event.target);\n
\t\tvar toFocus = false;\n
\n
\t\tswitch(event.keyCode) {\n
\t\t\tcase keyCode.RIGHT:\n
\t\t\tcase keyCode.DOWN:\n
\t\t\t\ttoFocus = this.headers[(currentIndex + 1) % length];\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.LEFT:\n
\t\t\tcase keyCode.UP:\n
\t\t\t\ttoFocus = this.headers[(currentIndex - 1 + length) % length];\n
\t\t\t\tbreak;\n
\t\t\tcase keyCode.SPACE:\n
\t\t\tcase keyCode.ENTER:\n
\t\t\t\treturn this._clickHandler({ target: event.target }, event.target);\n
\t\t}\n
\n
\t\tif (toFocus) {\n
\t\t\t$(event.target).attr(\'tabIndex\',\'-1\');\n
\t\t\t$(toFocus).attr(\'tabIndex\',\'0\');\n
\t\t\ttoFocus.focus();\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\treturn true;\n
\n
\t},\n
\n
\tresize: function() {\n
\n
\t\tvar o = this.options, maxHeight;\n
\n
\t\tif (o.fillSpace) {\n
\t\t\t\n
\t\t\tif($.browser.msie) { var defOverflow = this.element.parent().css(\'overflow\'); this.element.parent().css(\'overflow\', \'hidden\'); }\n
\t\t\tmaxHeight = this.element.parent().height();\n
\t\t\tif($.browser.msie) { this.element.parent().css(\'overflow\', defOverflow); }\n
\t\n
\t\t\tthis.headers.each(function() {\n
\t\t\t\tmaxHeight -= $(this).outerHeight();\n
\t\t\t});\n
\n
\t\t\tvar maxPadding = 0;\n
\t\t\tthis.headers.next().each(function() {\n
\t\t\t\tmaxPadding = Math.max(maxPadding, $(this).innerHeight() - $(this).height());\n
\t\t\t}).height(Math.max(0, maxHeight - maxPadding))\n
\t\t\t.css(\'overflow\', \'auto\');\n
\n
\t\t} else if ( o.autoHeight ) {\n
\t\t\tmaxHeight = 0;\n
\t\t\tthis.headers.next().each(function() {\n
\t\t\t\tmaxHeight = Math.max(maxHeight, $(this).outerHeight());\n
\t\t\t}).height(maxHeight);\n
\t\t}\n
\n
\t},\n
\n
\tactivate: function(index) {\n
\t\t// call clickHandler with custom event\n
\t\tvar active = this._findActive(index)[0];\n
\t\tthis._clickHandler({ target: active }, active);\n
\t},\n
\n
\t_findActive: function(selector) {\n
\t\treturn selector\n
\t\t\t? typeof selector == "number"\n
\t\t\t\t? this.headers.filter(":eq(" + selector + ")")\n
\t\t\t\t: this.headers.not(this.headers.not(selector))\n
\t\t\t: selector === false\n
\t\t\t\t? $([])\n
\t\t\t\t: this.headers.filter(":eq(0)");\n
\t},\n
\n
\t_clickHandler: function(event, target) {\n
\n
\t\tvar o = this.options;\n
\t\tif (o.disabled) return false;\n
\n
\t\t// called only when using activate(false) to close all parts programmatically\n
\t\tif (!event.target && o.collapsible) {\n
\t\t\tthis.active.removeClass("ui-state-active ui-corner-top").addClass("ui-state-default ui-corner-all")\n
\t\t\t\t.find(".ui-icon").removeClass(o.icons.headerSelected).addClass(o.icons.header);\n
\t\t\tthis.active.next().addClass(\'ui-accordion-content-active\');\n
\t\t\tvar toHide = this.active.next(),\n
\t\t\t\tdata = {\n
\t\t\t\t\toptions: o,\n
\t\t\t\t\tnewHeader: $([]),\n
\t\t\t\t\toldHeader: o.active,\n
\t\t\t\t\tnewContent: $([]),\n
\t\t\t\t\toldContent: toHide\n
\t\t\t\t},\n
\t\t\t\ttoShow = (this.active = $([]));\n
\t\t\tthis._toggle(toShow, toHide, data);\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t// get the click target\n
\t\tvar clicked = $(event.currentTarget || target);\n
\t\tvar clickedIsActive = clicked[0] == this.active[0];\n
\n
\t\t// if animations are still active, or the active header is the target, ignore click\n
\t\tif (this.running || (!o.collapsible && clickedIsActive)) {\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\t// switch classes\n
\t\tthis.active.removeClass("ui-state-active ui-corner-top").addClass("ui-state-default ui-corner-all")\n
\t\t\t.find(".ui-icon").removeClass(o.icons.headerSelected).addClass(o.icons.header);\n
\t\tthis.active.next().addClass(\'ui-accordion-content-active\');\n
\t\tif (!clickedIsActive) {\n
\t\t\tclicked.removeClass("ui-state-default ui-corner-all").addClass("ui-state-active ui-corner-top")\n
\t\t\t\t.find(".ui-icon").removeClass(o.icons.header).addClass(o.icons.headerSelected);\n
\t\t\tclicked.next().addClass(\'ui-accordion-content-active\');\n
\t\t}\n
\n
\t\t// find elements to show and hide\n
\t\tvar toShow = clicked.next(),\n
\t\t\ttoHide = this.active.next(),\n
\t\t\tdata = {\n
\t\t\t\toptions: o,\n
\t\t\t\tnewHeader: clickedIsActive && o.collapsible ? $([]) : clicked,\n
\t\t\t\toldHeader: this.active,\n
\t\t\t\tnewContent: clickedIsActive && o.collapsible ? $([]) : toShow.find(\'> *\'),\n
\t\t\t\toldContent: toHide.find(\'> *\')\n
\t\t\t},\n
\t\t\tdown = this.headers.index( this.active[0] ) > this.headers.index( clicked[0] );\n
\n
\t\tthis.active = clickedIsActive ? $([]) : clicked;\n
\t\tthis._toggle(toShow, toHide, data, clickedIsActive, down);\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\t_toggle: function(toShow, toHide, data, clickedIsActive, down) {\n
\n
\t\tvar o = this.options, self = this;\n
\n
\t\tthis.toShow = toShow;\n
\t\tthis.toHide = toHide;\n
\t\tthis.data = data;\n
\n
\t\tvar complete = function() { if(!self) return; return self._completed.apply(self, arguments); };\n
\n
\t\t// trigger changestart event\n
\t\tthis._trigger("changestart", null, this.data);\n
\n
\t\t// count elements to animate\n
\t\tthis.running = toHide.size() === 0 ? toShow.size() : toHide.size();\n
\n
\t\tif (o.animated) {\n
\n
\t\t\tvar animOptions = {};\n
\n
\t\t\tif ( o.collapsible && clickedIsActive ) {\n
\t\t\t\tanimOptions = {\n
\t\t\t\t\ttoShow: $([]),\n
\t\t\t\t\ttoHide: toHide,\n
\t\t\t\t\tcomplete: complete,\n
\t\t\t\t\tdown: down,\n
\t\t\t\t\tautoHeight: o.autoHeight || o.fillSpace\n
\t\t\t\t};\n
\t\t\t} else {\n
\t\t\t\tanimOptions = {\n
\t\t\t\t\ttoShow: toShow,\n
\t\t\t\t\ttoHide: toHide,\n
\t\t\t\t\tcomplete: complete,\n
\t\t\t\t\tdown: down,\n
\t\t\t\t\tautoHeight: o.autoHeight || o.fillSpace\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\tif (!o.proxied) {\n
\t\t\t\to.proxied = o.animated;\n
\t\t\t}\n
\n
\t\t\tif (!o.proxiedDuration) {\n
\t\t\t\to.proxiedDuration = o.duration;\n
\t\t\t}\n
\n
\t\t\to.animated = $.isFunction(o.proxied) ?\n
\t\t\t\to.proxied(animOptions) : o.proxied;\n
\n
\t\t\to.duration = $.isFunction(o.proxiedDuration) ?\n
\t\t\t\to.proxiedDuration(animOptions) : o.proxiedDuration;\n
\n
\t\t\tvar animations = $.ui.accordion.animations,\n
\t\t\t\tduration = o.duration,\n
\t\t\t\teasing = o.animated;\n
\n
\t\t\tif (!animations[easing]) {\n
\t\t\t\tanimations[easing] = function(options) {\n
\t\t\t\t\tthis.slide(options, {\n
\t\t\t\t\t\teasing: easing,\n
\t\t\t\t\t\tduration: duration || 700\n
\t\t\t\t\t});\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\tanimations[easing](animOptions);\n
\n
\t\t} else {\n
\n
\t\t\tif (o.collapsible && clickedIsActive) {\n
\t\t\t\ttoShow.toggle();\n
\t\t\t} else {\n
\t\t\t\ttoHide.hide();\n
\t\t\t\ttoShow.show();\n
\t\t\t}\n
\n
\t\t\tcomplete(true);\n
\n
\t\t}\n
\n
\t\ttoHide.prev().attr(\'aria-expanded\',\'false\').attr("tabIndex", "-1").blur();\n
\t\ttoShow.prev().attr(\'aria-expanded\',\'true\').attr("tabIndex", "0").focus();\n
\n
\t},\n
\n
\t_completed: function(cancel) {\n
\n
\t\tvar o = this.options;\n
\n
\t\tthis.running = cancel ? 0 : --this.running;\n
\t\tif (this.running) return;\n
\n
\t\tif (o.clearStyle) {\n
\t\t\tthis.toShow.add(this.toHide).css({\n
\t\t\t\theight: "",\n
\t\t\t\toverflow: ""\n
\t\t\t});\n
\t\t}\n
\n
\t\tthis._trigger(\'change\', null, this.data);\n
\t}\n
\n
});\n
\n
\n
$.extend($.ui.accordion, {\n
\tversion: "1.7.2",\n
\tdefaults: {\n
\t\tactive: null,\n
\t\talwaysOpen: true, //deprecated, use collapsible\n
\t\tanimated: \'slide\',\n
\t\tautoHeight: true,\n
\t\tclearStyle: false,\n
\t\tcollapsible: false,\n
\t\tevent: "click",\n
\t\tfillSpace: false,\n
\t\theader: "> li > :first-child,> :not(li):even",\n
\t\ticons: {\n
\t\t\theader: "ui-icon-triangle-1-e",\n
\t\t\theaderSelected: "ui-icon-triangle-1-s"\n
\t\t},\n
\t\tnavigation: false,\n
\t\tnavigationFilter: function() {\n
\t\t\treturn this.href.toLowerCase() == location.href.toLowerCase();\n
\t\t}\n
\t},\n
\tanimations: {\n
\t\tslide: function(options, additions) {\n
\t\t\toptions = $.extend({\n
\t\t\t\teasing: "swing",\n
\t\t\t\tduration: 300\n
\t\t\t}, options, additions);\n
\t\t\tif ( !options.toHide.size() ) {\n
\t\t\t\toptions.toShow.animate({height: "show"}, options);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( !options.toShow.size() ) {\n
\t\t\t\toptions.toHide.animate({height: "hide"}, options);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tvar overflow = options.toShow.css(\'overflow\'),\n
\t\t\t\tpercentDone,\n
\t\t\t\tshowProps = {},\n
\t\t\t\thideProps = {},\n
\t\t\t\tfxAttrs = [ "height", "paddingTop", "paddingBottom" ],\n
\t\t\t\toriginalWidth;\n
\t\t\t// fix width before calculating height of hidden element\n
\t\t\tvar s = options.toShow;\n
\t\t\toriginalWidth = s[0].style.width;\n
\t\t\ts.width( parseInt(s.parent().width(),10) - parseInt(s.css("paddingLeft"),10) - parseInt(s.css("paddingRight"),10) - (parseInt(s.css("borderLeftWidth"),10) || 0) - (parseInt(s.css("borderRightWidth"),10) || 0) );\n
\t\t\t\n
\t\t\t$.each(fxAttrs, function(i, prop) {\n
\t\t\t\thideProps[prop] = \'hide\';\n
\t\t\t\t\n
\t\t\t\tvar parts = (\'\' + $.css(options.toShow[0], prop)).match(/^([\\d+-.]+)(.*)$/);\n
\t\t\t\tshowProps[prop] = {\n
\t\t\t\t\tvalue: parts[1],\n
\t\t\t\t\tunit: parts[2] || \'px\'\n
\t\t\t\t};\n
\t\t\t});\n
\t\t\toptions.toShow.css({ height: 0, overflow: \'hidden\' }).show();\n
\t\t\toptions.toHide.filter(":hidden").each(options.complete).end().filter(":visible").animate(hideProps,{\n
\t\t\t\tstep: function(now, settings) {\n
\t\t\t\t\t// only calculate the percent when animating height\n
\t\t\t\t\t// IE gets very inconsistent results when animating elements\n
\t\t\t\t\t// with small values, which is common for padding\n
\t\t\t\t\tif (settings.prop == \'height\') {\n
\t\t\t\t\t\tpercentDone = (settings.now - settings.start) / (settings.end - settings.start);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\toptions.toShow[0].style[settings.prop] =\n
\t\t\t\t\t\t(percentDone * showProps[settings.prop].value) + showProps[settings.prop].unit;\n
\t\t\t\t},\n
\t\t\t\tduration: options.duration,\n
\t\t\t\teasing: options.easing,\n
\t\t\t\tcomplete: function() {\n
\t\t\t\t\tif ( !options.autoHeight ) {\n
\t\t\t\t\t\toptions.toShow.css("height", "");\n
\t\t\t\t\t}\n
\t\t\t\t\toptions.toShow.css("width", originalWidth);\n
\t\t\t\t\toptions.toShow.css({overflow: overflow});\n
\t\t\t\t\toptions.complete();\n
\t\t\t\t}\n
\t\t\t});\n
\t\t},\n
\t\tbounceslide: function(options) {\n
\t\t\tthis.slide(options, {\n
\t\t\t\teasing: options.down ? "easeOutBounce" : "swing",\n
\t\t\t\tduration: options.down ? 1000 : 200\n
\t\t\t});\n
\t\t},\n
\t\teaseslide: function(options) {\n
\t\t\tthis.slide(options, {\n
\t\t\t\teasing: "easeinout",\n
\t\t\t\tduration: 700\n
\t\t\t});\n
\t\t}\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Dialog 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Dialog\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 *\tui.draggable.js\n
 *\tui.resizable.js\n
 */\n
(function($) {\n
\n
var setDataSwitch = {\n
\t\tdragStart: "start.draggable",\n
\t\tdrag: "drag.draggable",\n
\t\tdragStop: "stop.draggable",\n
\t\tmaxHeight: "maxHeight.resizable",\n
\t\tminHeight: "minHeight.resizable",\n
\t\tmaxWidth: "maxWidth.resizable",\n
\t\tminWidth: "minWidth.resizable",\n
\t\tresizeStart: "start.resizable",\n
\t\tresize: "drag.resizable",\n
\t\tresizeStop: "stop.resizable"\n
\t},\n
\t\n
\tuiDialogClasses =\n
\t\t\'ui-dialog \' +\n
\t\t\'ui-widget \' +\n
\t\t\'ui-widget-content \' +\n
\t\t\'ui-corner-all \';\n
\n
$.widget("ui.dialog", {\n
\n
\t_init: function() {\n
\t\tthis.originalTitle = this.element.attr(\'title\');\n
\n
\t\tvar self = this,\n
\t\t\toptions = this.options,\n
\n
\t\t\ttitle = options.title || this.originalTitle || \'&nbsp;\',\n
\t\t\ttitleId = $.ui.dialog.getTitleId(this.element),\n
\n
\t\t\tuiDialog = (this.uiDialog = $(\'<div/>\'))\n
\t\t\t\t.appendTo(document.body)\n
\t\t\t\t.hide()\n
\t\t\t\t.addClass(uiDialogClasses + options.dialogClass)\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\toverflow: \'hidden\',\n
\t\t\t\t\tzIndex: options.zIndex\n
\t\t\t\t})\n
\t\t\t\t// setting tabIndex makes the div focusable\n
\t\t\t\t// setting outline to 0 prevents a border on focus in Mozilla\n
\t\t\t\t.attr(\'tabIndex\', -1).css(\'outline\', 0).keydown(function(event) {\n
\t\t\t\t\t(options.closeOnEscape && event.keyCode\n
\t\t\t\t\t\t&& event.keyCode == $.ui.keyCode.ESCAPE && self.close(event));\n
\t\t\t\t})\n
\t\t\t\t.attr({\n
\t\t\t\t\trole: \'dialog\',\n
\t\t\t\t\t\'aria-labelledby\': titleId\n
\t\t\t\t})\n
\t\t\t\t.mousedown(function(event) {\n
\t\t\t\t\tself.moveToTop(false, event);\n
\t\t\t\t}),\n
\n
\t\t\tuiDialogContent = this.element\n
\t\t\t\t.show()\n
\t\t\t\t.removeAttr(\'title\')\n
\t\t\t\t.addClass(\n
\t\t\t\t\t\'ui-dialog-content \' +\n
\t\t\t\t\t\'ui-widget-content\')\n
\t\t\t\t.appendTo(uiDialog),\n
\n
\t\t\tuiDialogTitlebar = (this.uiDialogTitlebar = $(\'<div></div>\'))\n
\t\t\t\t.addClass(\n
\t\t\t\t\t\'ui-dialog-titlebar \' +\n
\t\t\t\t\t\'ui-widget-header \' +\n
\t\t\t\t\t\'ui-corner-all \' +\n
\t\t\t\t\t\'ui-helper-clearfix\'\n
\t\t\t\t)\n
\t\t\t\t.prependTo(uiDialog),\n
\n
\t\t\tuiDialogTitlebarClose = $(\'<a href="#"/>\')\n
\t\t\t\t.addClass(\n
\t\t\t\t\t\'ui-dialog-titlebar-close \' +\n
\t\t\t\t\t\'ui-corner-all\'\n
\t\t\t\t)\n
\t\t\t\t.attr(\'role\', \'button\')\n
\t\t\t\t.hover(\n
\t\t\t\t\tfunction() {\n
\t\t\t\t\t\tuiDialogTitlebarClose.addClass(\'ui-state-hover\');\n
\t\t\t\t\t},\n
\t\t\t\t\tfunction() {\n
\t\t\t\t\t\tuiDialogTitlebarClose.removeClass(\'ui-state-hover\');\n
\t\t\t\t\t}\n
\t\t\t\t)\n
\t\t\t\t.focus(function() {\n
\t\t\t\t\tuiDialogTitlebarClose.addClass(\'ui-state-focus\');\n
\t\t\t\t})\n
\t\t\t\t.blur(function() {\n
\t\t\t\t\tuiDialogTitlebarClose.removeClass(\'ui-state-focus\');\n
\t\t\t\t})\n
\t\t\t\t.mousedown(function(ev) {\n
\t\t\t\t\tev.stopPropagation();\n
\t\t\t\t})\n
\t\t\t\t.click(function(event) {\n
\t\t\t\t\tself.close(event);\n
\t\t\t\t\treturn false;\n
\t\t\t\t})\n
\t\t\t\t.appendTo(uiDialogTitlebar),\n
\n
\t\t\tuiDialogTitlebarCloseText = (this.uiDialogTitlebarCloseText = $(\'<span/>\'))\n
\t\t\t\t.addClass(\n
\t\t\t\t\t\'ui-icon \' +\n
\t\t\t\t\t\'ui-icon-closethick\'\n
\t\t\t\t)\n
\t\t\t\t.text(options.closeText)\n
\t\t\t\t.appendTo(uiDialogTitlebarClose),\n
\n
\t\t\tuiDialogTitle = $(\'<span/>\')\n
\t\t\t\t.addClass(\'ui-dialog-title\')\n
\t\t\t\t.attr(\'id\', titleId)\n
\t\t\t\t.html(title)\n
\t\t\t\t.prependTo(uiDialogTitlebar);\n
\n
\t\tuiDialogTitlebar.find("*").add(uiDialogTitlebar).disableSelection();\n
\n
\t\t(options.draggable && $.fn.draggable && this._makeDraggable());\n
\t\t(options.resizable && $.fn.resizable && this._makeResizable());\n
\n
\t\tthis._createButtons(options.buttons);\n
\t\tthis._isOpen = false;\n
\n
\t\t(options.bgiframe && $.fn.bgiframe && uiDialog.bgiframe());\n
\t\t(options.autoOpen && this.open());\n
\t\t\n
\t},\n
\n
\tdestroy: function() {\n
\t\t(this.overlay && this.overlay.destroy());\n
\t\tthis.uiDialog.hide();\n
\t\tthis.element\n
\t\t\t.unbind(\'.dialog\')\n
\t\t\t.removeData(\'dialog\')\n
\t\t\t.removeClass(\'ui-dialog-content ui-widget-content\')\n
\t\t\t.hide().appendTo(\'body\');\n
\t\tthis.uiDialog.remove();\n
\n
\t\t(this.originalTitle && this.element.attr(\'title\', this.originalTitle));\n
\t},\n
\n
\tclose: function(event) {\n
\t\tvar self = this;\n
\t\t\n
\t\tif (false === self._trigger(\'beforeclose\', event)) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t(self.overlay && self.overlay.destroy());\n
\t\tself.uiDialog.unbind(\'keypress.ui-dialog\');\n
\n
\t\t(self.options.hide\n
\t\t\t? self.uiDialog.hide(self.options.hide, function() {\n
\t\t\t\tself._trigger(\'close\', event);\n
\t\t\t})\n
\t\t\t: self.uiDialog.hide() && self._trigger(\'close\', event));\n
\n
\t\t$.ui.dialog.overlay.resize();\n
\n
\t\tself._isOpen = false;\n
\t\t\n
\t\t// adjust the maxZ to allow other modal dialogs to continue to work (see #4309)\n
\t\tif (self.options.modal) {\n
\t\t\tvar maxZ = 0;\n
\t\t\t$(\'.ui-dialog\').each(function() {\n
\t\t\t\tif (this != self.uiDialog[0]) {\n
\t\t\t\t\tmaxZ = Math.max(maxZ, $(this).css(\'z-index\'));\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t$.ui.dialog.maxZ = maxZ;\n
\t\t}\n
\t},\n
\n
\tisOpen: function() {\n
\t\treturn this._isOpen;\n
\t},\n
\n
\t// the force parameter allows us to move modal dialogs to their correct\n
\t// position on open\n
\tmoveToTop: function(force, event) {\n
\n
\t\tif ((this.options.modal && !force)\n
\t\t\t|| (!this.options.stack && !this.options.modal)) {\n
\t\t\treturn this._trigger(\'focus\', event);\n
\t\t}\n
\t\t\n
\t\tif (this.options.zIndex > $.ui.dialog.maxZ) {\n
\t\t\t$.ui.dialog.maxZ = this.options.zIndex;\n
\t\t}\n
\t\t(this.overlay && this.overlay.$el.css(\'z-index\', $.ui.dialog.overlay.maxZ = ++$.ui.dialog.maxZ));\n
\n
\t\t//Save and then restore scroll since Opera 9.5+ resets when parent z-Index is changed.\n
\t\t//  http://ui.jquery.com/bugs/ticket/3193\n
\t\tvar saveScroll = { scrollTop: this.element.attr(\'scrollTop\'), scrollLeft: this.element.attr(\'scrollLeft\') };\n
\t\tthis.uiDialog.css(\'z-index\', ++$.ui.dialog.maxZ);\n
\t\tthis.element.attr(saveScroll);\n
\t\tthis._trigger(\'focus\', event);\n
\t},\n
\n
\topen: function() {\n
\t\tif (this._isOpen) { return; }\n
\n
\t\tvar options = this.options,\n
\t\t\tuiDialog = this.uiDialog;\n
\n
\t\tthis.overlay = options.modal ? new $.ui.dialog.overlay(this) : null;\n
\t\t(uiDialog.next().length && uiDialog.appendTo(\'body\'));\n
\t\tthis._size();\n
\t\tthis._position(options.position);\n
\t\tuiDialog.show(options.show);\n
\t\tthis.moveToTop(true);\n
\n
\t\t// prevent tabbing out of modal dialogs\n
\t\t(options.modal && uiDialog.bind(\'keypress.ui-dialog\', function(event) {\n
\t\t\tif (event.keyCode != $.ui.keyCode.TAB) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tvar tabbables = $(\':tabbable\', this),\n
\t\t\t\tfirst = tabbables.filter(\':first\')[0],\n
\t\t\t\tlast  = tabbables.filter(\':last\')[0];\n
\n
\t\t\tif (event.target == last && !event.shiftKey) {\n
\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\tfirst.focus();\n
\t\t\t\t}, 1);\n
\t\t\t} else if (event.target == first && event.shiftKey) {\n
\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\tlast.focus();\n
\t\t\t\t}, 1);\n
\t\t\t}\n
\t\t}));\n
\n
\t\t// set focus to the first tabbable element in the content area or the first button\n
\t\t// if there are no tabbable elements, set focus on the dialog itself\n
\t\t$([])\n
\t\t\t.add(uiDialog.find(\'.ui-dialog-content :tabbable:first\'))\n
\t\t\t.add(uiDialog.find(\'.ui-dialog-buttonpane :tabbable:first\'))\n
\t\t\t.add(uiDialog)\n
\t\t\t.filter(\':first\')\n
\t\t\t.focus();\n
\n
\t\tthis._trigger(\'open\');\n
\t\tthis._isOpen = true;\n
\t},\n
\n
\t_createButtons: function(buttons) {\n
\t\tvar self = this,\n
\t\t\thasButtons = false,\n
\t\t\tuiDialogButtonPane = $(\'<div></div>\')\n
\t\t\t\t.addClass(\n
\t\t\t\t\t\'ui-dialog-buttonpane \' +\n
\t\t\t\t\t\'ui-widget-content \' +\n
\t\t\t\t\t\'ui-helper-clearfix\'\n
\t\t\t\t);\n
\n
\t\t// if we already have a button pane, remove it\n
\t\tthis.uiDialog.find(\'.ui-dialog-buttonpane\').remove();\n
\n
\t\t(typeof buttons == \'object\' && buttons !== null &&\n
\t\t\t$.each(buttons, function() { return !(hasButtons = true); }));\n
\t\tif (hasButtons) {\n
\t\t\t$.each(buttons, function(name, fn) {\n
\t\t\t\t$(\'<button type="button"></button>\')\n
\t\t\t\t\t.addClass(\n
\t\t\t\t\t\t\'ui-state-default \' +\n
\t\t\t\t\t\t\'ui-corner-all\'\n
\t\t\t\t\t)\n
\t\t\t\t\t.text(name)\n
\t\t\t\t\t.click(function() { fn.apply(self.element[0], arguments); })\n
\t\t\t\t\t.hover(\n
\t\t\t\t\t\tfunction() {\n
\t\t\t\t\t\t\t$(this).addClass(\'ui-state-hover\');\n
\t\t\t\t\t\t},\n
\t\t\t\t\t\tfunction() {\n
\t\t\t\t\t\t\t$(this).removeClass(\'ui-state-hover\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t)\n
\t\t\t\t\t.focus(function() {\n
\t\t\t\t\t\t$(this).addClass(\'ui-state-focus\');\n
\t\t\t\t\t})\n
\t\t\t\t\t.blur(function() {\n
\t\t\t\t\t\t$(this).removeClass(\'ui-state-focus\');\n
\t\t\t\t\t})\n
\t\t\t\t\t.appendTo(uiDialogButtonPane);\n
\t\t\t});\n
\t\t\tuiDialogButtonPane.appendTo(this.uiDialog);\n
\t\t}\n
\t},\n
\n
\t_makeDraggable: function() {\n
\t\tvar self = this,\n
\t\t\toptions = this.options,\n
\t\t\theightBeforeDrag;\n
\n
\t\tthis.uiDialog.draggable({\n
\t\t\tcancel: \'.ui-dialog-content\',\n
\t\t\thandle: \'.ui-dialog-titlebar\',\n
\t\t\tcontainment: \'document\',\n
\t\t\tstart: function() {\n
\t\t\t\theightBeforeDrag = options.height;\n
\t\t\t\t$(this).height($(this).height()).addClass("ui-dialog-dragging");\n
\t\t\t\t(options.dragStart && options.dragStart.apply(self.element[0], arguments));\n
\t\t\t},\n
\t\t\tdrag: function() {\n
\t\t\t\t(options.drag && options.drag.apply(self.element[0], arguments));\n
\t\t\t},\n
\t\t\tstop: function() {\n
\t\t\t\t$(this).removeClass("ui-dialog-dragging").height(heightBeforeDrag);\n
\t\t\t\t(options.dragStop && options.dragStop.apply(self.element[0], arguments));\n
\t\t\t\t$.ui.dialog.overlay.resize();\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\t_makeResizable: function(handles) {\n
\t\thandles = (handles === undefined ? this.options.resizable : handles);\n
\t\tvar self = this,\n
\t\t\toptions = this.options,\n
\t\t\tresizeHandles = typeof handles == \'string\'\n
\t\t\t\t? handles\n
\t\t\t\t: \'n,e,s,w,se,sw,ne,nw\';\n
\n
\t\tthis.uiDialog.resizable({\n
\t\t\tcancel: \'.ui-dialog-content\',\n
\t\t\talsoResize: this.element,\n
\t\t\tmaxWidth: options.maxWidth,\n
\t\t\tmaxHeight: options.maxHeight,\n
\t\t\tminWidth: options.minWidth,\n
\t\t\tminHeight: options.minHeight,\n
\t\t\tstart: function() {\n
\t\t\t\t$(this).addClass("ui-dialog-resizing");\n
\t\t\t\t(options.resizeStart && options.resizeStart.apply(self.element[0], arguments));\n
\t\t\t},\n
\t\t\tresize: function() {\n
\t\t\t\t(options.resize && options.resize.apply(self.element[0], arguments));\n
\t\t\t},\n
\t\t\thandles: resizeHandles,\n
\t\t\tstop: function() {\n
\t\t\t\t$(this).removeClass("ui-dialog-resizing");\n
\t\t\t\toptions.height = $(this).height();\n
\t\t\t\toptions.width = $(this).width();\n
\t\t\t\t(options.resizeStop && options.resizeStop.apply(self.element[0], arguments));\n
\t\t\t\t$.ui.dialog.overlay.resize();\n
\t\t\t}\n
\t\t})\n
\t\t.find(\'.ui-resizable-se\').addClass(\'ui-icon ui-icon-grip-diagonal-se\');\n
\t},\n
\n
\t_position: function(pos) {\n
\t\tvar wnd = $(window), doc = $(document),\n
\t\t\tpTop = doc.scrollTop(), pLeft = doc.scrollLeft(),\n
\t\t\tminTop = pTop;\n
\n
\t\tif ($.inArray(pos, [\'center\',\'top\',\'right\',\'bottom\',\'left\']) >= 0) {\n
\t\t\tpos = [\n
\t\t\t\tpos == \'right\' || pos == \'left\' ? pos : \'center\',\n
\t\t\t\tpos == \'top\' || pos == \'bottom\' ? pos : \'middle\'\n
\t\t\t];\n
\t\t}\n
\t\tif (pos.constructor != Array) {\n
\t\t\tpos = [\'center\', \'middle\'];\n
\t\t}\n
\t\tif (pos[0].constructor == Number) {\n
\t\t\tpLeft += pos[0];\n
\t\t} else {\n
\t\t\tswitch (pos[0]) {\n
\t\t\t\tcase \'left\':\n
\t\t\t\t\tpLeft += 0;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'right\':\n
\t\t\t\t\tpLeft += wnd.width() - this.uiDialog.outerWidth();\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\tcase \'center\':\n
\t\t\t\t\tpLeft += (wnd.width() - this.uiDialog.outerWidth()) / 2;\n
\t\t\t}\n
\t\t}\n
\t\tif (pos[1].constructor == Number) {\n
\t\t\tpTop += pos[1];\n
\t\t} else {\n
\t\t\tswitch (pos[1]) {\n
\t\t\t\tcase \'top\':\n
\t\t\t\t\tpTop += 0;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'bottom\':\n
\t\t\t\t\tpTop += wnd.height() - this.uiDialog.outerHeight();\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\tcase \'middle\':\n
\t\t\t\t\tpTop += (wnd.height() - this.uiDialog.outerHeight()) / 2;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// prevent the dialog from being too high (make sure the titlebar\n
\t\t// is accessible)\n
\t\tpTop = Math.max(pTop, minTop);\n
\t\tthis.uiDialog.css({top: pTop, left: pLeft});\n
\t},\n
\n
\t_setData: function(key, value){\n
\t\t(setDataSwitch[key] && this.uiDialog.data(setDataSwitch[key], value));\n
\t\tswitch (key) {\n
\t\t\tcase "buttons":\n
\t\t\t\tthis._createButtons(value);\n
\t\t\t\tbreak;\n
\t\t\tcase "closeText":\n
\t\t\t\tthis.uiDialogTitlebarCloseText.text(value);\n
\t\t\t\tbreak;\n
\t\t\tcase "dialogClass":\n
\t\t\t\tthis.uiDialog\n
\t\t\t\t\t.removeClass(this.options.dialogClass)\n
\t\t\t\t\t.addClass(uiDialogClasses + value);\n
\t\t\t\tbreak;\n
\t\t\tcase "draggable":\n
\t\t\t\t(value\n
\t\t\t\t\t? this._makeDraggable()\n
\t\t\t\t\t: this.uiDialog.draggable(\'destroy\'));\n
\t\t\t\tbreak;\n
\t\t\tcase "height":\n
\t\t\t\tthis.uiDialog.height(value);\n
\t\t\t\tbreak;\n
\t\t\tcase "position":\n
\t\t\t\tthis._position(value);\n
\t\t\t\tbreak;\n
\t\t\tcase "resizable":\n
\t\t\t\tvar uiDialog = this.uiDialog,\n
\t\t\t\t\tisResizable = this.uiDialog.is(\':data(resizable)\');\n
\n
\t\t\t\t// currently resizable, becoming non-resizable\n
\t\t\t\t(isResizable && !value && uiDialog.resizable(\'destroy\'));\n
\n
\t\t\t\t// currently resizable, changing handles\n
\t\t\t\t(isResizable && typeof value == \'string\' &&\n
\t\t\t\t\tuiDialog.resizable(\'option\', \'handles\', value));\n
\n
\t\t\t\t// currently non-resizable, becoming resizable\n
\t\t\t\t(isResizable || this._makeResizable(value));\n
\t\t\t\tbreak;\n
\t\t\tcase "title":\n
\t\t\t\t$(".ui-dialog-title", this.uiDialogTitlebar).html(value || \'&nbsp;\');\n
\t\t\t\tbreak;\n
\t\t\tcase "width":\n
\t\t\t\tthis.uiDialog.width(value);\n
\t\t\t\tbreak;\n
\t\t}\n
\n
\t\t$.widget.prototype._setData.apply(this, arguments);\n
\t},\n
\n
\t_size: function() {\n
\t\t/* If the user has resized the dialog, the .ui-dialog and .ui-dialog-content\n
\t\t * divs will both have width and height set, so we need to reset them\n
\t\t */\n
\t\tvar options = this.options;\n
\n
\t\t// reset content sizing\n
\t\tthis.element.css({\n
\t\t\theight: 0,\n
\t\t\tminHeight: 0,\n
\t\t\twidth: \'auto\'\n
\t\t});\n
\n
\t\t// reset wrapper sizing\n
\t\t// determine the height of all the non-content elements\n
\t\tvar nonContentHeight = this.uiDialog.css({\n
\t\t\t\theight: \'auto\',\n
\t\t\t\twidth: options.width\n
\t\t\t})\n
\t\t\t.height();\n
\n
\t\tthis.element\n
\t\t\t.css({\n
\t\t\t\tminHeight: Math.max(options.minHeight - nonContentHeight, 0),\n
\t\t\t\theight: options.height == \'auto\'\n
\t\t\t\t\t? \'auto\'\n
\t\t\t\t\t: Math.max(options.height - nonContentHeight, 0)\n
\t\t\t});\n
\t}\n
});\n
\n
$.extend($.ui.dialog, {\n
\tversion: "1.7.2",\n
\tdefaults: {\n
\t\tautoOpen: true,\n
\t\tbgiframe: false,\n
\t\tbuttons: {},\n
\t\tcloseOnEscape: true,\n
\t\tcloseText: \'close\',\n
\t\tdialogClass: \'\',\n
\t\tdraggable: true,\n
\t\thide: null,\n
\t\theight: \'auto\',\n
\t\tmaxHeight: false,\n
\t\tmaxWidth: false,\n
\t\tminHeight: 150,\n
\t\tminWidth: 150,\n
\t\tmodal: false,\n
\t\tposition: \'center\',\n
\t\tresizable: true,\n
\t\tshow: null,\n
\t\tstack: true,\n
\t\ttitle: \'\',\n
\t\twidth: 300,\n
\t\tzIndex: 1000\n
\t},\n
\n
\tgetter: \'isOpen\',\n
\n
\tuuid: 0,\n
\tmaxZ: 0,\n
\n
\tgetTitleId: function($el) {\n
\t\treturn \'ui-dialog-title-\' + ($el.attr(\'id\') || ++this.uuid);\n
\t},\n
\n
\toverlay: function(dialog) {\n
\t\tthis.$el = $.ui.dialog.overlay.create(dialog);\n
\t}\n
});\n
\n
$.extend($.ui.dialog.overlay, {\n
\tinstances: [],\n
\tmaxZ: 0,\n
\tevents: $.map(\'focus,mousedown,mouseup,keydown,keypress,click\'.split(\',\'),\n
\t\tfunction(event) { return event + \'.dialog-overlay\'; }).join(\' \'),\n
\tcreate: function(dialog) {\n
\t\tif (this.instances.length === 0) {\n
\t\t\t// prevent use of anchors and inputs\n
\t\t\t// we use a setTimeout in case the overlay is created from an\n
\t\t\t// event that we\'re going to be cancelling (see #2804)\n
\t\t\tsetTimeout(function() {\n
\t\t\t\t// handle $(el).dialog().dialog(\'close\') (see #4065)\n
\t\t\t\tif ($.ui.dialog.overlay.instances.length) {\n
\t\t\t\t\t$(document).bind($.ui.dialog.overlay.events, function(event) {\n
\t\t\t\t\t\tvar dialogZ = $(event.target).parents(\'.ui-dialog\').css(\'zIndex\') || 0;\n
\t\t\t\t\t\treturn (dialogZ > $.ui.dialog.overlay.maxZ);\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}, 1);\n
\n
\t\t\t// allow closing by pressing the escape key\n
\t\t\t$(document).bind(\'keydown.dialog-overlay\', function(event) {\n
\t\t\t\t(dialog.options.closeOnEscape && event.keyCode\n
\t\t\t\t\t\t&& event.keyCode == $.ui.keyCode.ESCAPE && dialog.close(event));\n
\t\t\t});\n
\n
\t\t\t// handle window resize\n
\t\t\t$(window).bind(\'resize.dialog-overlay\', $.ui.dialog.overlay.resize);\n
\t\t}\n
\n
\t\tvar $el = $(\'<div></div>\').appendTo(document.body)\n
\t\t\t.addClass(\'ui-widget-overlay\').css({\n
\t\t\t\twidth: this.width(),\n
\t\t\t\theight: this.height()\n
\t\t\t});\n
\n
\t\t(dialog.options.bgiframe && $.fn.bgiframe && $el.bgiframe());\n
\n
\t\tthis.instances.push($el);\n
\t\treturn $el;\n
\t},\n
\n
\tdestroy: function($el) {\n
\t\tthis.instances.splice($.inArray(this.instances, $el), 1);\n
\n
\t\tif (this.instances.length === 0) {\n
\t\t\t$([document, window]).unbind(\'.dialog-overlay\');\n
\t\t}\n
\n
\t\t$el.remove();\n
\t\t\n
\t\t// adjust the maxZ to allow other modal dialogs to continue to work (see #4309)\n
\t\tvar maxZ = 0;\n
\t\t$.each(this.instances, function() {\n
\t\t\tmaxZ = Math.max(maxZ, this.css(\'z-index\'));\n
\t\t});\n
\t\tthis.maxZ = maxZ;\n
\t},\n
\n
\theight: function() {\n
\t\t// handle IE 6\n
\t\tif ($.browser.msie && $.browser.version < 7) {\n
\t\t\tvar scrollHeight = Math.max(\n
\t\t\t\tdocument.documentElement.scrollHeight,\n
\t\t\t\tdocument.body.scrollHeight\n
\t\t\t);\n
\t\t\tvar offsetHeight = Math.max(\n
\t\t\t\tdocument.documentElement.offsetHeight,\n
\t\t\t\tdocument.body.offsetHeight\n
\t\t\t);\n
\n
\t\t\tif (scrollHeight < offsetHeight) {\n
\t\t\t\treturn $(window).height() + \'px\';\n
\t\t\t} else {\n
\t\t\t\treturn scrollHeight + \'px\';\n
\t\t\t}\n
\t\t// handle "good" browsers\n
\t\t} else {\n
\t\t\treturn $(document).height() + \'px\';\n
\t\t}\n
\t},\n
\n
\twidth: function() {\n
\t\t// handle IE 6\n
\t\tif ($.browser.msie && $.browser.version < 7) {\n
\t\t\tvar scrollWidth = Math.max(\n
\t\t\t\tdocument.documentElement.scrollWidth,\n
\t\t\t\tdocument.body.scrollWidth\n
\t\t\t);\n
\t\t\tvar offsetWidth = Math.max(\n
\t\t\t\tdocument.documentElement.offsetWidth,\n
\t\t\t\tdocument.body.offsetWidth\n
\t\t\t);\n
\n
\t\t\tif (scrollWidth < offsetWidth) {\n
\t\t\t\treturn $(window).width() + \'px\';\n
\t\t\t} else {\n
\t\t\t\treturn scrollWidth + \'px\';\n
\t\t\t}\n
\t\t// handle "good" browsers\n
\t\t} else {\n
\t\t\treturn $(document).width() + \'px\';\n
\t\t}\n
\t},\n
\n
\tresize: function() {\n
\t\t/* If the dialog is draggable and the user drags it past the\n
\t\t * right edge of the window, the document becomes wider so we\n
\t\t * need to stretch the overlay. If the user then drags the\n
\t\t * dialog back to the left, the document will become narrower,\n
\t\t * so we need to shrink the overlay to the appropriate size.\n
\t\t * This is handled by shrinking the overlay before setting it\n
\t\t * to the full document size.\n
\t\t */\n
\t\tvar $overlays = $([]);\n
\t\t$.each($.ui.dialog.overlay.instances, function() {\n
\t\t\t$overlays = $overlays.add(this);\n
\t\t});\n
\n
\t\t$overlays.css({\n
\t\t\twidth: 0,\n
\t\t\theight: 0\n
\t\t}).css({\n
\t\t\twidth: $.ui.dialog.overlay.width(),\n
\t\t\theight: $.ui.dialog.overlay.height()\n
\t\t});\n
\t}\n
});\n
\n
$.extend($.ui.dialog.overlay.prototype, {\n
\tdestroy: function() {\n
\t\t$.ui.dialog.overlay.destroy(this.$el);\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Slider 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Slider\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
\n
(function($) {\n
\n
$.widget("ui.slider", $.extend({}, $.ui.mouse, {\n
\n
\t_init: function() {\n
\n
\t\tvar self = this, o = this.options;\n
\t\tthis._keySliding = false;\n
\t\tthis._handleIndex = null;\n
\t\tthis._detectOrientation();\n
\t\tthis._mouseInit();\n
\n
\t\tthis.element\n
\t\t\t.addClass("ui-slider"\n
\t\t\t\t+ " ui-slider-" + this.orientation\n
\t\t\t\t+ " ui-widget"\n
\t\t\t\t+ " ui-widget-content"\n
\t\t\t\t+ " ui-corner-all");\n
\n
\t\tthis.range = $([]);\n
\n
\t\tif (o.range) {\n
\n
\t\t\tif (o.range === true) {\n
\t\t\t\tthis.range = $(\'<div></div>\');\n
\t\t\t\tif (!o.values) o.values = [this._valueMin(), this._valueMin()];\n
\t\t\t\tif (o.values.length && o.values.length != 2) {\n
\t\t\t\t\to.values = [o.values[0], o.values[0]];\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tthis.range = $(\'<div></div>\');\n
\t\t\t}\n
\n
\t\t\tthis.range\n
\t\t\t\t.appendTo(this.element)\n
\t\t\t\t.addClass("ui-slider-range");\n
\n
\t\t\tif (o.range == "min" || o.range == "max") {\n
\t\t\t\tthis.range.addClass("ui-slider-range-" + o.range);\n
\t\t\t}\n
\n
\t\t\t// note: this isn\'t the most fittingly semantic framework class for this element,\n
\t\t\t// but worked best visually with a variety of themes\n
\t\t\tthis.range.addClass("ui-widget-header");\n
\n
\t\t}\n
\n
\t\tif ($(".ui-slider-handle", this.element).length == 0)\n
\t\t\t$(\'<a href="#"></a>\')\n
\t\t\t\t.appendTo(this.element)\n
\t\t\t\t.addClass("ui-slider-handle");\n
\n
\t\tif (o.values && o.values.length) {\n
\t\t\twhile ($(".ui-slider-handle", this.element).length < o.values.length)\n
\t\t\t\t$(\'<a href="#"></a>\')\n
\t\t\t\t\t.appendTo(this.element)\n
\t\t\t\t\t.addClass("ui-slider-handle");\n
\t\t}\n
\n
\t\tthis.handles = $(".ui-slider-handle", this.element)\n
\t\t\t.addClass("ui-state-default"\n
\t\t\t\t+ " ui-corner-all");\n
\n
\t\tthis.handle = this.handles.eq(0);\n
\n
\t\tthis.handles.add(this.range).filter("a")\n
\t\t\t.click(function(event) {\n
\t\t\t\tevent.preventDefault();\n
\t\t\t})\n
\t\t\t.hover(function() {\n
\t\t\t\tif (!o.disabled) {\n
\t\t\t\t\t$(this).addClass(\'ui-state-hover\');\n
\t\t\t\t}\n
\t\t\t}, function() {\n
\t\t\t\t$(this).removeClass(\'ui-state-hover\');\n
\t\t\t})\n
\t\t\t.focus(function() {\n
\t\t\t\tif (!o.disabled) {\n
\t\t\t\t\t$(".ui-slider .ui-state-focus").removeClass(\'ui-state-focus\'); $(this).addClass(\'ui-state-focus\');\n
\t\t\t\t} else {\n
\t\t\t\t\t$(this).blur();\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t.blur(function() {\n
\t\t\t\t$(this).removeClass(\'ui-state-focus\');\n
\t\t\t});\n
\n
\t\tthis.handles.each(function(i) {\n
\t\t\t$(this).data("index.ui-slider-handle", i);\n
\t\t});\n
\n
\t\tthis.handles.keydown(function(event) {\n
\n
\t\t\tvar ret = true;\n
\n
\t\t\tvar index = $(this).data("index.ui-slider-handle");\n
\n
\t\t\tif (self.options.disabled)\n
\t\t\t\treturn;\n
\n
\t\t\tswitch (event.keyCode) {\n
\t\t\t\tcase $.ui.keyCode.HOME:\n
\t\t\t\tcase $.ui.keyCode.END:\n
\t\t\t\tcase $.ui.keyCode.UP:\n
\t\t\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\t\tcase $.ui.keyCode.DOWN:\n
\t\t\t\tcase $.ui.keyCode.LEFT:\n
\t\t\t\t\tret = false;\n
\t\t\t\t\tif (!self._keySliding) {\n
\t\t\t\t\t\tself._keySliding = true;\n
\t\t\t\t\t\t$(this).addClass("ui-state-active");\n
\t\t\t\t\t\tself._start(event, index);\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tvar curVal, newVal, step = self._step();\n
\t\t\tif (self.options.values && self.options.values.length) {\n
\t\t\t\tcurVal = newVal = self.values(index);\n
\t\t\t} else {\n
\t\t\t\tcurVal = newVal = self.value();\n
\t\t\t}\n
\n
\t\t\tswitch (event.keyCode) {\n
\t\t\t\tcase $.ui.keyCode.HOME:\n
\t\t\t\t\tnewVal = self._valueMin();\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.END:\n
\t\t\t\t\tnewVal = self._valueMax();\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.UP:\n
\t\t\t\tcase $.ui.keyCode.RIGHT:\n
\t\t\t\t\tif(curVal == self._valueMax()) return;\n
\t\t\t\t\tnewVal = curVal + step;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase $.ui.keyCode.DOWN:\n
\t\t\t\tcase $.ui.keyCode.LEFT:\n
\t\t\t\t\tif(curVal == self._valueMin()) return;\n
\t\t\t\t\tnewVal = curVal - step;\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tself._slide(event, index, newVal);\n
\n
\t\t\treturn ret;\n
\n
\t\t}).keyup(function(event) {\n
\n
\t\t\tvar index = $(this).data("index.ui-slider-handle");\n
\n
\t\t\tif (self._keySliding) {\n
\t\t\t\tself._stop(event, index);\n
\t\t\t\tself._change(event, index);\n
\t\t\t\tself._keySliding = false;\n
\t\t\t\t$(this).removeClass("ui-state-active");\n
\t\t\t}\n
\n
\t\t});\n
\n
\t\tthis._refreshValue();\n
\n
\t},\n
\n
\tdestroy: function() {\n
\n
\t\tthis.handles.remove();\n
\t\tthis.range.remove();\n
\n
\t\tthis.element\n
\t\t\t.removeClass("ui-slider"\n
\t\t\t\t+ " ui-slider-horizontal"\n
\t\t\t\t+ " ui-slider-vertical"\n
\t\t\t\t+ " ui-slider-disabled"\n
\t\t\t\t+ " ui-widget"\n
\t\t\t\t+ " ui-widget-content"\n
\t\t\t\t+ " ui-corner-all")\n
\t\t\t.removeData("slider")\n
\t\t\t.unbind(".slider");\n
\n
\t\tthis._mouseDestroy();\n
\n
\t},\n
\n
\t_mouseCapture: function(event) {\n
\n
\t\tvar o = this.options;\n
\n
\t\tif (o.disabled)\n
\t\t\treturn false;\n
\n
\t\tthis.elementSize = {\n
\t\t\twidth: this.element.outerWidth(),\n
\t\t\theight: this.element.outerHeight()\n
\t\t};\n
\t\tthis.elementOffset = this.element.offset();\n
\n
\t\tvar position = { x: event.pageX, y: event.pageY };\n
\t\tvar normValue = this._normValueFromMouse(position);\n
\n
\t\tvar distance = this._valueMax() - this._valueMin() + 1, closestHandle;\n
\t\tvar self = this, index;\n
\t\tthis.handles.each(function(i) {\n
\t\t\tvar thisDistance = Math.abs(normValue - self.values(i));\n
\t\t\tif (distance > thisDistance) {\n
\t\t\t\tdistance = thisDistance;\n
\t\t\t\tclosestHandle = $(this);\n
\t\t\t\tindex = i;\n
\t\t\t}\n
\t\t});\n
\n
\t\t// workaround for bug #3736 (if both handles of a range are at 0,\n
\t\t// the first is always used as the one with least distance,\n
\t\t// and moving it is obviously prevented by preventing negative ranges)\n
\t\tif(o.range == true && this.values(1) == o.min) {\n
\t\t\tclosestHandle = $(this.handles[++index]);\n
\t\t}\n
\n
\t\tthis._start(event, index);\n
\n
\t\tself._handleIndex = index;\n
\n
\t\tclosestHandle\n
\t\t\t.addClass("ui-state-active")\n
\t\t\t.focus();\n
\t\t\n
\t\tvar offset = closestHandle.offset();\n
\t\tvar mouseOverHandle = !$(event.target).parents().andSelf().is(\'.ui-slider-handle\');\n
\t\tthis._clickOffset = mouseOverHandle ? { left: 0, top: 0 } : {\n
\t\t\tleft: event.pageX - offset.left - (closestHandle.width() / 2),\n
\t\t\ttop: event.pageY - offset.top\n
\t\t\t\t- (closestHandle.height() / 2)\n
\t\t\t\t- (parseInt(closestHandle.css(\'borderTopWidth\'),10) || 0)\n
\t\t\t\t- (parseInt(closestHandle.css(\'borderBottomWidth\'),10) || 0)\n
\t\t\t\t+ (parseInt(closestHandle.css(\'marginTop\'),10) || 0)\n
\t\t};\n
\n
\t\tnormValue = this._normValueFromMouse(position);\n
\t\tthis._slide(event, index, normValue);\n
\t\treturn true;\n
\n
\t},\n
\n
\t_mouseStart: function(event) {\n
\t\treturn true;\n
\t},\n
\n
\t_mouseDrag: function(event) {\n
\n
\t\tvar position = { x: event.pageX, y: event.pageY };\n
\t\tvar normValue = this._normValueFromMouse(position);\n
\t\t\n
\t\tthis._slide(event, this._handleIndex, normValue);\n
\n
\t\treturn false;\n
\n
\t},\n
\n
\t_mouseStop: function(event) {\n
\n
\t\tthis.handles.removeClass("ui-state-active");\n
\t\tthis._stop(event, this._handleIndex);\n
\t\tthis._change(event, this._handleIndex);\n
\t\tthis._handleIndex = null;\n
\t\tthis._clickOffset = null;\n
\n
\t\treturn false;\n
\n
\t},\n
\t\n
\t_detectOrientation: function() {\n
\t\tthis.orientation = this.options.orientation == \'vertical\' ? \'vertical\' : \'horizontal\';\n
\t},\n
\n
\t_normValueFromMouse: function(position) {\n
\n
\t\tvar pixelTotal, pixelMouse;\n
\t\tif (\'horizontal\' == this.orientation) {\n
\t\t\tpixelTotal = this.elementSize.width;\n
\t\t\tpixelMouse = position.x - this.elementOffset.left - (this._clickOffset ? this._clickOffset.left : 0);\n
\t\t} else {\n
\t\t\tpixelTotal = this.elementSize.height;\n
\t\t\tpixelMouse = position.y - this.elementOffset.top - (this._clickOffset ? this._clickOffset.top : 0);\n
\t\t}\n
\n
\t\tvar percentMouse = (pixelMouse / pixelTotal);\n
\t\tif (percentMouse > 1) percentMouse = 1;\n
\t\tif (percentMouse < 0) percentMouse = 0;\n
\t\tif (\'vertical\' == this.orientation)\n
\t\t\tpercentMouse = 1 - percentMouse;\n
\n
\t\tvar valueTotal = this._valueMax() - this._valueMin(),\n
\t\t\tvalueMouse = percentMouse * valueTotal,\n
\t\t\tvalueMouseModStep = valueMouse % this.options.step,\n
\t\t\tnormValue = this._valueMin() + valueMouse - valueMouseModStep;\n
\n
\t\tif (valueMouseModStep > (this.options.step / 2))\n
\t\t\tnormValue += this.options.step;\n
\n
\t\t// Since JavaScript has problems with large floats, round\n
\t\t// the final value to 5 digits after the decimal point (see #4124)\n
\t\treturn parseFloat(normValue.toFixed(5));\n
\n
\t},\n
\n
\t_start: function(event, index) {\n
\t\tvar uiHash = {\n
\t\t\thandle: this.handles[index],\n
\t\t\tvalue: this.value()\n
\t\t};\n
\t\tif (this.options.values && this.options.values.length) {\n
\t\t\tuiHash.value = this.values(index);\n
\t\t\tuiHash.values = this.values();\n
\t\t}\n
\t\tthis._trigger("start", event, uiHash);\n
\t},\n
\n
\t_slide: function(event, index, newVal) {\n
\n
\t\tvar handle = this.handles[index];\n
\n
\t\tif (this.options.values && this.options.values.length) {\n
\n
\t\t\tvar otherVal = this.values(index ? 0 : 1);\n
\n
\t\t\tif ((this.options.values.length == 2 && this.options.range === true) && \n
\t\t\t\t((index == 0 && newVal > otherVal) || (index == 1 && newVal < otherVal))){\n
 \t\t\t\tnewVal = otherVal;\n
\t\t\t}\n
\n
\t\t\tif (newVal != this.values(index)) {\n
\t\t\t\tvar newValues = this.values();\n
\t\t\t\tnewValues[index] = newVal;\n
\t\t\t\t// A slide can be canceled by returning false from the slide callback\n
\t\t\t\tvar allowed = this._trigger("slide", event, {\n
\t\t\t\t\thandle: this.handles[index],\n
\t\t\t\t\tvalue: newVal,\n
\t\t\t\t\tvalues: newValues\n
\t\t\t\t});\n
\t\t\t\tvar otherVal = this.values(index ? 0 : 1);\n
\t\t\t\tif (allowed !== false) {\n
\t\t\t\t\tthis.values(index, newVal, ( event.type == \'mousedown\' && this.options.animate ), true);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t} else {\n
\n
\t\t\tif (newVal != this.value()) {\n
\t\t\t\t// A slide can be canceled by returning false from the slide callback\n
\t\t\t\tvar allowed = this._trigger("slide", event, {\n
\t\t\t\t\thandle: this.handles[index],\n
\t\t\t\t\tvalue: newVal\n
\t\t\t\t});\n
\t\t\t\tif (allowed !== false) {\n
\t\t\t\t\tthis._setData(\'value\', newVal, ( event.type == \'mousedown\' && this.options.animate ));\n
\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t}\n
\n
\t\t}\n
\n
\t},\n
\n
\t_stop: function(event, index) {\n
\t\tvar uiHash = {\n
\t\t\thandle: this.handles[index],\n
\t\t\tvalue: this.value()\n
\t\t};\n
\t\tif (this.options.values && this.options.values.length) {\n
\t\t\tuiHash.value = this.values(index);\n
\t\t\tuiHash.values = this.values();\n
\t\t}\n
\t\tthis._trigger("stop", event, uiHash);\n
\t},\n
\n
\t_change: function(event, index) {\n
\t\tvar uiHash = {\n
\t\t\thandle: this.handles[index],\n
\t\t\tvalue: this.value()\n
\t\t};\n
\t\tif (this.options.values && this.options.values.length) {\n
\t\t\tuiHash.value = this.values(index);\n
\t\t\tuiHash.values = this.values();\n
\t\t}\n
\t\tthis._trigger("change", event, uiHash);\n
\t},\n
\n
\tvalue: function(newValue) {\n
\n
\t\tif (arguments.length) {\n
\t\t\tthis._setData("value", newValue);\n
\t\t\tthis._change(null, 0);\n
\t\t}\n
\n
\t\treturn this._value();\n
\n
\t},\n
\n
\tvalues: function(index, newValue, animated, noPropagation) {\n
\n
\t\tif (arguments.length > 1) {\n
\t\t\tthis.options.values[index] = newValue;\n
\t\t\tthis._refreshValue(animated);\n
\t\t\tif(!noPropagation) this._change(null, index);\n
\t\t}\n
\n
\t\tif (arguments.length) {\n
\t\t\tif (this.options.values && this.options.values.length) {\n
\t\t\t\treturn this._values(index);\n
\t\t\t} else {\n
\t\t\t\treturn this.value();\n
\t\t\t}\n
\t\t} else {\n
\t\t\treturn this._values();\n
\t\t}\n
\n
\t},\n
\n
\t_setData: function(key, value, animated) {\n
\n
\t\t$.widget.prototype._setData.apply(this, arguments);\n
\n
\t\tswitch (key) {\n
\t\t\tcase \'disabled\':\n
\t\t\t\tif (value) {\n
\t\t\t\t\tthis.handles.filter(".ui-state-focus").blur();\n
\t\t\t\t\tthis.handles.removeClass("ui-state-hover");\n
\t\t\t\t\tthis.handles.attr("disabled", "disabled");\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.handles.removeAttr("disabled");\n
\t\t\t\t}\n
\t\t\tcase \'orientation\':\n
\n
\t\t\t\tthis._detectOrientation();\n
\t\t\t\t\n
\t\t\t\tthis.element\n
\t\t\t\t\t.removeClass("ui-slider-horizontal ui-slider-vertical")\n
\t\t\t\t\t.addClass("ui-slider-" + this.orientation);\n
\t\t\t\tthis._refreshValue(animated);\n
\t\t\t\tbreak;\n
\t\t\tcase \'value\':\n
\t\t\t\tthis._refreshValue(animated);\n
\t\t\t\tbreak;\n
\t\t}\n
\n
\t},\n
\n
\t_step: function() {\n
\t\tvar step = this.options.step;\n
\t\treturn step;\n
\t},\n
\n
\t_value: function() {\n
\n
\t\tvar val = this.options.value;\n
\t\tif (val < this._valueMin()) val = this._valueMin();\n
\t\tif (val > this._valueMax()) val = this._valueMax();\n
\n
\t\treturn val;\n
\n
\t},\n
\n
\t_values: function(index) {\n
\n
\t\tif (arguments.length) {\n
\t\t\tvar val = this.options.values[index];\n
\t\t\tif (val < this._valueMin()) val = this._valueMin();\n
\t\t\tif (val > this._valueMax()) val = this._valueMax();\n
\n
\t\t\treturn val;\n
\t\t} else {\n
\t\t\treturn this.options.values;\n
\t\t}\n
\n
\t},\n
\n
\t_valueMin: function() {\n
\t\tvar valueMin = this.options.min;\n
\t\treturn valueMin;\n
\t},\n
\n
\t_valueMax: function() {\n
\t\tvar valueMax = this.options.max;\n
\t\treturn valueMax;\n
\t},\n
\n
\t_refreshValue: function(animate) {\n
\n
\t\tvar oRange = this.options.range, o = this.options, self = this;\n
\n
\t\tif (this.options.values && this.options.values.length) {\n
\t\t\tvar vp0, vp1;\n
\t\t\tthis.handles.each(function(i, j) {\n
\t\t\t\tvar valPercent = (self.values(i) - self._valueMin()) / (self._valueMax() - self._valueMin()) * 100;\n
\t\t\t\tvar _set = {}; _set[self.orientation == \'horizontal\' ? \'left\' : \'bottom\'] = valPercent + \'%\';\n
\t\t\t\t$(this).stop(1,1)[animate ? \'animate\' : \'css\'](_set, o.animate);\n
\t\t\t\tif (self.options.range === true) {\n
\t\t\t\t\tif (self.orientation == \'horizontal\') {\n
\t\t\t\t\t\t(i == 0) && self.range.stop(1,1)[animate ? \'animate\' : \'css\']({ left: valPercent + \'%\' }, o.animate);\n
\t\t\t\t\t\t(i == 1) && self.range[animate ? \'animate\' : \'css\']({ width: (valPercent - lastValPercent) + \'%\' }, { queue: false, duration: o.animate });\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t(i == 0) && self.range.stop(1,1)[animate ? \'animate\' : \'css\']({ bottom: (valPercent) + \'%\' }, o.animate);\n
\t\t\t\t\t\t(i == 1) && self.range[animate ? \'animate\' : \'css\']({ height: (valPercent - lastValPercent) + \'%\' }, { queue: false, duration: o.animate });\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tlastValPercent = valPercent;\n
\t\t\t});\n
\t\t} else {\n
\t\t\tvar value = this.value(),\n
\t\t\t\tvalueMin = this._valueMin(),\n
\t\t\t\tvalueMax = this._valueMax(),\n
\t\t\t\tvalPercent = valueMax != valueMin\n
\t\t\t\t\t? (value - valueMin) / (valueMax - valueMin) * 100\n
\t\t\t\t\t: 0;\n
\t\t\tvar _set = {}; _set[self.orientation == \'horizontal\' ? \'left\' : \'bottom\'] = valPercent + \'%\';\n
\t\t\tthis.handle.stop(1,1)[animate ? \'animate\' : \'css\'](_set, o.animate);\n
\n
\t\t\t(oRange == "min") && (this.orientation == "horizontal") && this.range.stop(1,1)[animate ? \'animate\' : \'css\']({ width: valPercent + \'%\' }, o.animate);\n
\t\t\t(oRange == "max") && (this.orientation == "horizontal") && this.range[animate ? \'animate\' : \'css\']({ width: (100 - valPercent) + \'%\' }, { queue: false, duration: o.animate });\n
\t\t\t(oRange == "min") && (this.orientation == "vertical") && this.range.stop(1,1)[animate ? \'animate\' : \'css\']({ height: valPercent + \'%\' }, o.animate);\n
\t\t\t(oRange == "max") && (this.orientation == "vertical") && this.range[animate ? \'animate\' : \'css\']({ height: (100 - valPercent) + \'%\' }, { queue: false, duration: o.animate });\n
\t\t}\n
\n
\t}\n
\t\n
}));\n
\n
$.extend($.ui.slider, {\n
\tgetter: "value values",\n
\tversion: "1.7.2",\n
\teventPrefix: "slide",\n
\tdefaults: {\n
\t\tanimate: false,\n
\t\tdelay: 0,\n
\t\tdistance: 0,\n
\t\tmax: 100,\n
\t\tmin: 0,\n
\t\torientation: \'horizontal\',\n
\t\trange: false,\n
\t\tstep: 1,\n
\t\tvalue: 0,\n
\t\tvalues: null\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Tabs 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Tabs\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.tabs", {\n
\n
\t_init: function() {\n
\t\tif (this.options.deselectable !== undefined) {\n
\t\t\tthis.options.collapsible = this.options.deselectable;\n
\t\t}\n
\t\tthis._tabify(true);\n
\t},\n
\n
\t_setData: function(key, value) {\n
\t\tif (key == \'selected\') {\n
\t\t\tif (this.options.collapsible && value == this.options.selected) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tthis.select(value);\n
\t\t}\n
\t\telse {\n
\t\t\tthis.options[key] = value;\n
\t\t\tif (key == \'deselectable\') {\n
\t\t\t\tthis.options.collapsible = value;\n
\t\t\t}\n
\t\t\tthis._tabify();\n
\t\t}\n
\t},\n
\n
\t_tabId: function(a) {\n
\t\treturn a.title && a.title.replace(/\\s/g, \'_\').replace(/[^A-Za-z0-9\\-_:\\.]/g, \'\') ||\n
\t\t\tthis.options.idPrefix + $.data(a);\n
\t},\n
\n
\t_sanitizeSelector: function(hash) {\n
\t\treturn hash.replace(/:/g, \'\\\\:\'); // we need this because an id may contain a ":"\n
\t},\n
\n
\t_cookie: function() {\n
\t\tvar cookie = this.cookie || (this.cookie = this.options.cookie.name || \'ui-tabs-\' + $.data(this.list[0]));\n
\t\treturn $.cookie.apply(null, [cookie].concat($.makeArray(arguments)));\n
\t},\n
\n
\t_ui: function(tab, panel) {\n
\t\treturn {\n
\t\t\ttab: tab,\n
\t\t\tpanel: panel,\n
\t\t\tindex: this.anchors.index(tab)\n
\t\t};\n
\t},\n
\n
\t_cleanup: function() {\n
\t\t// restore all former loading tabs labels\n
\t\tthis.lis.filter(\'.ui-state-processing\').removeClass(\'ui-state-processing\')\n
\t\t\t\t.find(\'span:data(label.tabs)\')\n
\t\t\t\t.each(function() {\n
\t\t\t\t\tvar el = $(this);\n
\t\t\t\t\tel.html(el.data(\'label.tabs\')).removeData(\'label.tabs\');\n
\t\t\t\t});\n
\t},\n
\n
\t_tabify: function(init) {\n
\n
\t\tthis.list = this.element.children(\'ul:first\');\n
\t\tthis.lis = $(\'li:has(a[href])\', this.list);\n
\t\tthis.anchors = this.lis.map(function() { return $(\'a\', this)[0]; });\n
\t\tthis.panels = $([]);\n
\n
\t\tvar self = this, o = this.options;\n
\n
\t\tvar fragmentId = /^#.+/; // Safari 2 reports \'#\' for an empty hash\n
\t\tthis.anchors.each(function(i, a) {\n
\t\t\tvar href = $(a).attr(\'href\');\n
\n
\t\t\t// For dynamically created HTML that contains a hash as href IE < 8 expands\n
\t\t\t// such href to the full page url with hash and then misinterprets tab as ajax.\n
\t\t\t// Same consideration applies for an added tab with a fragment identifier\n
\t\t\t// since a[href=#fragment-identifier] does unexpectedly not match.\n
\t\t\t// Thus normalize href attribute...\n
\t\t\tvar hrefBase = href.split(\'#\')[0], baseEl;\n
\t\t\tif (hrefBase && (hrefBase === location.toString().split(\'#\')[0] ||\n
\t\t\t\t\t(baseEl = $(\'base\')[0]) && hrefBase === baseEl.href)) {\n
\t\t\t\thref = a.hash;\n
\t\t\t\ta.href = href;\n
\t\t\t}\n
\n
\t\t\t// inline tab\n
\t\t\tif (fragmentId.test(href)) {\n
\t\t\t\tself.panels = self.panels.add(self._sanitizeSelector(href));\n
\t\t\t}\n
\n
\t\t\t// remote tab\n
\t\t\telse if (href != \'#\') { // prevent loading the page itself if href is just "#"\n
\t\t\t\t$.data(a, \'href.tabs\', href); // required for restore on destroy\n
\n
\t\t\t\t// TODO until #3808 is fixed strip fragment identifier from url\n
\t\t\t\t// (IE fails to load from such url)\n
\t\t\t\t$.data(a, \'load.tabs\', href.replace(/#.*$/, \'\')); // mutable data\n
\n
\t\t\t\tvar id = self._tabId(a);\n
\t\t\t\ta.href = \'#\' + id;\n
\t\t\t\tvar $panel = $(\'#\' + id);\n
\t\t\t\tif (!$panel.length) {\n
\t\t\t\t\t$panel = $(o.panelTemplate).attr(\'id\', id).addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom\')\n
\t\t\t\t\t\t.insertAfter(self.panels[i - 1] || self.list);\n
\t\t\t\t\t$panel.data(\'destroy.tabs\', true);\n
\t\t\t\t}\n
\t\t\t\tself.panels = self.panels.add($panel);\n
\t\t\t}\n
\n
\t\t\t// invalid tab href\n
\t\t\telse {\n
\t\t\t\to.disabled.push(i);\n
\t\t\t}\n
\t\t});\n
\n
\t\t// initialization from scratch\n
\t\tif (init) {\n
\n
\t\t\t// attach necessary classes for styling\n
\t\t\tthis.element.addClass(\'ui-tabs ui-widget ui-widget-content ui-corner-all\');\n
\t\t\tthis.list.addClass(\'ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all\');\n
\t\t\tthis.lis.addClass(\'ui-state-default ui-corner-top\');\n
\t\t\tthis.panels.addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom\');\n
\n
\t\t\t// Selected tab\n
\t\t\t// use "selected" option or try to retrieve:\n
\t\t\t// 1. from fragment identifier in url\n
\t\t\t// 2. from cookie\n
\t\t\t// 3. from selected class attribute on <li>\n
\t\t\tif (o.selected === undefined) {\n
\t\t\t\tif (location.hash) {\n
\t\t\t\t\tthis.anchors.each(function(i, a) {\n
\t\t\t\t\t\tif (a.hash == location.hash) {\n
\t\t\t\t\t\t\to.selected = i;\n
\t\t\t\t\t\t\treturn false; // break\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\tif (typeof o.selected != \'number\' && o.cookie) {\n
\t\t\t\t\to.selected = parseInt(self._cookie(), 10);\n
\t\t\t\t}\n
\t\t\t\tif (typeof o.selected != \'number\' && this.lis.filter(\'.ui-tabs-selected\').length) {\n
\t\t\t\t\to.selected = this.lis.index(this.lis.filter(\'.ui-tabs-selected\'));\n
\t\t\t\t}\n
\t\t\t\to.selected = o.selected || 0;\n
\t\t\t}\n
\t\t\telse if (o.selected === null) { // usage of null is deprecated, TODO remove in next release\n
\t\t\t\to.selected = -1;\n
\t\t\t}\n
\n
\t\t\t// sanity check - default to first tab...\n
\t\t\to.selected = ((o.selected >= 0 && this.anchors[o.selected]) || o.selected < 0) ? o.selected : 0;\n
\n
\t\t\t// Take disabling tabs via class attribute from HTML\n
\t\t\t// into account and update option properly.\n
\t\t\t// A selected tab cannot become disabled.\n
\t\t\to.disabled = $.unique(o.disabled.concat(\n
\t\t\t\t$.map(this.lis.filter(\'.ui-state-disabled\'),\n
\t\t\t\t\tfunction(n, i) { return self.lis.index(n); } )\n
\t\t\t)).sort();\n
\n
\t\t\tif ($.inArray(o.selected, o.disabled) != -1) {\n
\t\t\t\to.disabled.splice($.inArray(o.selected, o.disabled), 1);\n
\t\t\t}\n
\n
\t\t\t// highlight selected tab\n
\t\t\tthis.panels.addClass(\'ui-tabs-hide\');\n
\t\t\tthis.lis.removeClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\tif (o.selected >= 0 && this.anchors.length) { // check for length avoids error when initializing empty list\n
\t\t\t\tthis.panels.eq(o.selected).removeClass(\'ui-tabs-hide\');\n
\t\t\t\tthis.lis.eq(o.selected).addClass(\'ui-tabs-selected ui-state-active\');\n
\n
\t\t\t\t// seems to be expected behavior that the show callback is fired\n
\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\tself._trigger(\'show\', null, self._ui(self.anchors[o.selected], self.panels[o.selected]));\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tthis.load(o.selected);\n
\t\t\t}\n
\n
\t\t\t// clean up to avoid memory leaks in certain versions of IE 6\n
\t\t\t$(window).bind(\'unload\', function() {\n
\t\t\t\tself.lis.add(self.anchors).unbind(\'.tabs\');\n
\t\t\t\tself.lis = self.anchors = self.panels = null;\n
\t\t\t});\n
\n
\t\t}\n
\t\t// update selected after add/remove\n
\t\telse {\n
\t\t\to.selected = this.lis.index(this.lis.filter(\'.ui-tabs-selected\'));\n
\t\t}\n
\n
\t\t// update collapsible\n
\t\tthis.element[o.collapsible ? \'addClass\' : \'removeClass\'](\'ui-tabs-collapsible\');\n
\n
\t\t// set or update cookie after init and add/remove respectively\n
\t\tif (o.cookie) {\n
\t\t\tth

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
      <tuple>
        <global name="Pdata" module="OFS.Image"/>
        <tuple/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

is._cookie(o.selected, o.cookie);\n
\t\t}\n
\n
\t\t// disable tabs\n
\t\tfor (var i = 0, li; (li = this.lis[i]); i++) {\n
\t\t\t$(li)[$.inArray(i, o.disabled) != -1 &&\n
\t\t\t\t!$(li).hasClass(\'ui-tabs-selected\') ? \'addClass\' : \'removeClass\'](\'ui-state-disabled\');\n
\t\t}\n
\n
\t\t// reset cache if switching from cached to not cached\n
\t\tif (o.cache === false) {\n
\t\t\tthis.anchors.removeData(\'cache.tabs\');\n
\t\t}\n
\n
\t\t// remove all handlers before, tabify may run on existing tabs after add or option change\n
\t\tthis.lis.add(this.anchors).unbind(\'.tabs\');\n
\n
\t\tif (o.event != \'mouseover\') {\n
\t\t\tvar addState = function(state, el) {\n
\t\t\t\tif (el.is(\':not(.ui-state-disabled)\')) {\n
\t\t\t\t\tel.addClass(\'ui-state-\' + state);\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\tvar removeState = function(state, el) {\n
\t\t\t\tel.removeClass(\'ui-state-\' + state);\n
\t\t\t};\n
\t\t\tthis.lis.bind(\'mouseover.tabs\', function() {\n
\t\t\t\taddState(\'hover\', $(this));\n
\t\t\t});\n
\t\t\tthis.lis.bind(\'mouseout.tabs\', function() {\n
\t\t\t\tremoveState(\'hover\', $(this));\n
\t\t\t});\n
\t\t\tthis.anchors.bind(\'focus.tabs\', function() {\n
\t\t\t\taddState(\'focus\', $(this).closest(\'li\'));\n
\t\t\t});\n
\t\t\tthis.anchors.bind(\'blur.tabs\', function() {\n
\t\t\t\tremoveState(\'focus\', $(this).closest(\'li\'));\n
\t\t\t});\n
\t\t}\n
\n
\t\t// set up animations\n
\t\tvar hideFx, showFx;\n
\t\tif (o.fx) {\n
\t\t\tif ($.isArray(o.fx)) {\n
\t\t\t\thideFx = o.fx[0];\n
\t\t\t\tshowFx = o.fx[1];\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\thideFx = showFx = o.fx;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Reset certain styles left over from animation\n
\t\t// and prevent IE\'s ClearType bug...\n
\t\tfunction resetStyle($el, fx) {\n
\t\t\t$el.css({ display: \'\' });\n
\t\t\tif ($.browser.msie && fx.opacity) {\n
\t\t\t\t$el[0].style.removeAttribute(\'filter\');\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Show a tab...\n
\t\tvar showTab = showFx ?\n
\t\t\tfunction(clicked, $show) {\n
\t\t\t\t$(clicked).closest(\'li\').removeClass(\'ui-state-default\').addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t\t$show.hide().removeClass(\'ui-tabs-hide\') // avoid flicker that way\n
\t\t\t\t\t.animate(showFx, showFx.duration || \'normal\', function() {\n
\t\t\t\t\t\tresetStyle($show, showFx);\n
\t\t\t\t\t\tself._trigger(\'show\', null, self._ui(clicked, $show[0]));\n
\t\t\t\t\t});\n
\t\t\t} :\n
\t\t\tfunction(clicked, $show) {\n
\t\t\t\t$(clicked).closest(\'li\').removeClass(\'ui-state-default\').addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t\t$show.removeClass(\'ui-tabs-hide\');\n
\t\t\t\tself._trigger(\'show\', null, self._ui(clicked, $show[0]));\n
\t\t\t};\n
\n
\t\t// Hide a tab, $show is optional...\n
\t\tvar hideTab = hideFx ?\n
\t\t\tfunction(clicked, $hide) {\n
\t\t\t\t$hide.animate(hideFx, hideFx.duration || \'normal\', function() {\n
\t\t\t\t\tself.lis.removeClass(\'ui-tabs-selected ui-state-active\').addClass(\'ui-state-default\');\n
\t\t\t\t\t$hide.addClass(\'ui-tabs-hide\');\n
\t\t\t\t\tresetStyle($hide, hideFx);\n
\t\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t\t});\n
\t\t\t} :\n
\t\t\tfunction(clicked, $hide, $show) {\n
\t\t\t\tself.lis.removeClass(\'ui-tabs-selected ui-state-active\').addClass(\'ui-state-default\');\n
\t\t\t\t$hide.addClass(\'ui-tabs-hide\');\n
\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t};\n
\n
\t\t// attach tab event handler, unbind to avoid duplicates from former tabifying...\n
\t\tthis.anchors.bind(o.event + \'.tabs\', function() {\n
\t\t\tvar el = this, $li = $(this).closest(\'li\'), $hide = self.panels.filter(\':not(.ui-tabs-hide)\'),\n
\t\t\t\t\t$show = $(self._sanitizeSelector(this.hash));\n
\n
\t\t\t// If tab is already selected and not collapsible or tab disabled or\n
\t\t\t// or is already loading or click callback returns false stop here.\n
\t\t\t// Check if click handler returns false last so that it is not executed\n
\t\t\t// for a disabled or loading tab!\n
\t\t\tif (($li.hasClass(\'ui-tabs-selected\') && !o.collapsible) ||\n
\t\t\t\t$li.hasClass(\'ui-state-disabled\') ||\n
\t\t\t\t$li.hasClass(\'ui-state-processing\') ||\n
\t\t\t\tself._trigger(\'select\', null, self._ui(this, $show[0])) === false) {\n
\t\t\t\tthis.blur();\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\to.selected = self.anchors.index(this);\n
\n
\t\t\tself.abort();\n
\n
\t\t\t// if tab may be closed\n
\t\t\tif (o.collapsible) {\n
\t\t\t\tif ($li.hasClass(\'ui-tabs-selected\')) {\n
\t\t\t\t\to.selected = -1;\n
\n
\t\t\t\t\tif (o.cookie) {\n
\t\t\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\thideTab(el, $hide);\n
\t\t\t\t\t}).dequeue("tabs");\n
\t\t\t\t\t\n
\t\t\t\t\tthis.blur();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\telse if (!$hide.length) {\n
\t\t\t\t\tif (o.cookie) {\n
\t\t\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\tshowTab(el, $show);\n
\t\t\t\t\t});\n
\n
\t\t\t\t\tself.load(self.anchors.index(this)); // TODO make passing in node possible, see also http://dev.jqueryui.com/ticket/3171\n
\t\t\t\t\t\n
\t\t\t\t\tthis.blur();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (o.cookie) {\n
\t\t\t\tself._cookie(o.selected, o.cookie);\n
\t\t\t}\n
\n
\t\t\t// show new tab\n
\t\t\tif ($show.length) {\n
\t\t\t\tif ($hide.length) {\n
\t\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\t\thideTab(el, $hide);\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\tself.element.queue("tabs", function() {\n
\t\t\t\t\tshowTab(el, $show);\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tself.load(self.anchors.index(this));\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tthrow \'jQuery UI Tabs: Mismatching fragment identifier.\';\n
\t\t\t}\n
\n
\t\t\t// Prevent IE from keeping other link focussed when using the back button\n
\t\t\t// and remove dotted border from clicked link. This is controlled via CSS\n
\t\t\t// in modern browsers; blur() removes focus from address bar in Firefox\n
\t\t\t// which can become a usability and annoying problem with tabs(\'rotate\').\n
\t\t\tif ($.browser.msie) {\n
\t\t\t\tthis.blur();\n
\t\t\t}\n
\n
\t\t});\n
\n
\t\t// disable click in any case\n
\t\tthis.anchors.bind(\'click.tabs\', function(){return false;});\n
\n
\t},\n
\n
\tdestroy: function() {\n
\t\tvar o = this.options;\n
\n
\t\tthis.abort();\n
\t\t\n
\t\tthis.element.unbind(\'.tabs\')\n
\t\t\t.removeClass(\'ui-tabs ui-widget ui-widget-content ui-corner-all ui-tabs-collapsible\')\n
\t\t\t.removeData(\'tabs\');\n
\n
\t\tthis.list.removeClass(\'ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all\');\n
\n
\t\tthis.anchors.each(function() {\n
\t\t\tvar href = $.data(this, \'href.tabs\');\n
\t\t\tif (href) {\n
\t\t\t\tthis.href = href;\n
\t\t\t}\n
\t\t\tvar $this = $(this).unbind(\'.tabs\');\n
\t\t\t$.each([\'href\', \'load\', \'cache\'], function(i, prefix) {\n
\t\t\t\t$this.removeData(prefix + \'.tabs\');\n
\t\t\t});\n
\t\t});\n
\n
\t\tthis.lis.unbind(\'.tabs\').add(this.panels).each(function() {\n
\t\t\tif ($.data(this, \'destroy.tabs\')) {\n
\t\t\t\t$(this).remove();\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\t$(this).removeClass([\n
\t\t\t\t\t\'ui-state-default\',\n
\t\t\t\t\t\'ui-corner-top\',\n
\t\t\t\t\t\'ui-tabs-selected\',\n
\t\t\t\t\t\'ui-state-active\',\n
\t\t\t\t\t\'ui-state-hover\',\n
\t\t\t\t\t\'ui-state-focus\',\n
\t\t\t\t\t\'ui-state-disabled\',\n
\t\t\t\t\t\'ui-tabs-panel\',\n
\t\t\t\t\t\'ui-widget-content\',\n
\t\t\t\t\t\'ui-corner-bottom\',\n
\t\t\t\t\t\'ui-tabs-hide\'\n
\t\t\t\t].join(\' \'));\n
\t\t\t}\n
\t\t});\n
\n
\t\tif (o.cookie) {\n
\t\t\tthis._cookie(null, o.cookie);\n
\t\t}\n
\t},\n
\n
\tadd: function(url, label, index) {\n
\t\tif (index === undefined) {\n
\t\t\tindex = this.anchors.length; // append by default\n
\t\t}\n
\n
\t\tvar self = this, o = this.options,\n
\t\t\t$li = $(o.tabTemplate.replace(/#\\{href\\}/g, url).replace(/#\\{label\\}/g, label)),\n
\t\t\tid = !url.indexOf(\'#\') ? url.replace(\'#\', \'\') : this._tabId($(\'a\', $li)[0]);\n
\n
\t\t$li.addClass(\'ui-state-default ui-corner-top\').data(\'destroy.tabs\', true);\n
\n
\t\t// try to find an existing element before creating a new one\n
\t\tvar $panel = $(\'#\' + id);\n
\t\tif (!$panel.length) {\n
\t\t\t$panel = $(o.panelTemplate).attr(\'id\', id).data(\'destroy.tabs\', true);\n
\t\t}\n
\t\t$panel.addClass(\'ui-tabs-panel ui-widget-content ui-corner-bottom ui-tabs-hide\');\n
\n
\t\tif (index >= this.lis.length) {\n
\t\t\t$li.appendTo(this.list);\n
\t\t\t$panel.appendTo(this.list[0].parentNode);\n
\t\t}\n
\t\telse {\n
\t\t\t$li.insertBefore(this.lis[index]);\n
\t\t\t$panel.insertBefore(this.panels[index]);\n
\t\t}\n
\n
\t\to.disabled = $.map(o.disabled,\n
\t\t\tfunction(n, i) { return n >= index ? ++n : n; });\n
\n
\t\tthis._tabify();\n
\n
\t\tif (this.anchors.length == 1) { // after tabify\n
\t\t\t$li.addClass(\'ui-tabs-selected ui-state-active\');\n
\t\t\t$panel.removeClass(\'ui-tabs-hide\');\n
\t\t\tthis.element.queue("tabs", function() {\n
\t\t\t\tself._trigger(\'show\', null, self._ui(self.anchors[0], self.panels[0]));\n
\t\t\t});\n
\t\t\t\t\n
\t\t\tthis.load(0);\n
\t\t}\n
\n
\t\t// callback\n
\t\tthis._trigger(\'add\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t},\n
\n
\tremove: function(index) {\n
\t\tvar o = this.options, $li = this.lis.eq(index).remove(),\n
\t\t\t$panel = this.panels.eq(index).remove();\n
\n
\t\t// If selected tab was removed focus tab to the right or\n
\t\t// in case the last tab was removed the tab to the left.\n
\t\tif ($li.hasClass(\'ui-tabs-selected\') && this.anchors.length > 1) {\n
\t\t\tthis.select(index + (index + 1 < this.anchors.length ? 1 : -1));\n
\t\t}\n
\n
\t\to.disabled = $.map($.grep(o.disabled, function(n, i) { return n != index; }),\n
\t\t\tfunction(n, i) { return n >= index ? --n : n; });\n
\n
\t\tthis._tabify();\n
\n
\t\t// callback\n
\t\tthis._trigger(\'remove\', null, this._ui($li.find(\'a\')[0], $panel[0]));\n
\t},\n
\n
\tenable: function(index) {\n
\t\tvar o = this.options;\n
\t\tif ($.inArray(index, o.disabled) == -1) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tthis.lis.eq(index).removeClass(\'ui-state-disabled\');\n
\t\to.disabled = $.grep(o.disabled, function(n, i) { return n != index; });\n
\n
\t\t// callback\n
\t\tthis._trigger(\'enable\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t},\n
\n
\tdisable: function(index) {\n
\t\tvar self = this, o = this.options;\n
\t\tif (index != o.selected) { // cannot disable already selected tab\n
\t\t\tthis.lis.eq(index).addClass(\'ui-state-disabled\');\n
\n
\t\t\to.disabled.push(index);\n
\t\t\to.disabled.sort();\n
\n
\t\t\t// callback\n
\t\t\tthis._trigger(\'disable\', null, this._ui(this.anchors[index], this.panels[index]));\n
\t\t}\n
\t},\n
\n
\tselect: function(index) {\n
\t\tif (typeof index == \'string\') {\n
\t\t\tindex = this.anchors.index(this.anchors.filter(\'[href$=\' + index + \']\'));\n
\t\t}\n
\t\telse if (index === null) { // usage of null is deprecated, TODO remove in next release\n
\t\t\tindex = -1;\n
\t\t}\n
\t\tif (index == -1 && this.options.collapsible) {\n
\t\t\tindex = this.options.selected;\n
\t\t}\n
\n
\t\tthis.anchors.eq(index).trigger(this.options.event + \'.tabs\');\n
\t},\n
\n
\tload: function(index) {\n
\t\tvar self = this, o = this.options, a = this.anchors.eq(index)[0], url = $.data(a, \'load.tabs\');\n
\n
\t\tthis.abort();\n
\n
\t\t// not remote or from cache\n
\t\tif (!url || this.element.queue("tabs").length !== 0 && $.data(a, \'cache.tabs\')) {\n
\t\t\tthis.element.dequeue("tabs");\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// load remote from here on\n
\t\tthis.lis.eq(index).addClass(\'ui-state-processing\');\n
\n
\t\tif (o.spinner) {\n
\t\t\tvar span = $(\'span\', a);\n
\t\t\tspan.data(\'label.tabs\', span.html()).html(o.spinner);\n
\t\t}\n
\n
\t\tthis.xhr = $.ajax($.extend({}, o.ajaxOptions, {\n
\t\t\turl: url,\n
\t\t\tsuccess: function(r, s) {\n
\t\t\t\t$(self._sanitizeSelector(a.hash)).html(r);\n
\n
\t\t\t\t// take care of tab labels\n
\t\t\t\tself._cleanup();\n
\n
\t\t\t\tif (o.cache) {\n
\t\t\t\t\t$.data(a, \'cache.tabs\', true); // if loaded once do not load them again\n
\t\t\t\t}\n
\n
\t\t\t\t// callbacks\n
\t\t\t\tself._trigger(\'load\', null, self._ui(self.anchors[index], self.panels[index]));\n
\t\t\t\ttry {\n
\t\t\t\t\to.ajaxOptions.success(r, s);\n
\t\t\t\t}\n
\t\t\t\tcatch (e) {}\n
\n
\t\t\t\t// last, so that load event is fired before show...\n
\t\t\t\tself.element.dequeue("tabs");\n
\t\t\t}\n
\t\t}));\n
\t},\n
\n
\tabort: function() {\n
\t\t// stop possibly running animations\n
\t\tthis.element.queue([]);\n
\t\tthis.panels.stop(false, true);\n
\n
\t\t// terminate pending requests from other tabs\n
\t\tif (this.xhr) {\n
\t\t\tthis.xhr.abort();\n
\t\t\tdelete this.xhr;\n
\t\t}\n
\n
\t\t// take care of tab labels\n
\t\tthis._cleanup();\n
\n
\t},\n
\n
\turl: function(index, url) {\n
\t\tthis.anchors.eq(index).removeData(\'cache.tabs\').data(\'load.tabs\', url);\n
\t},\n
\n
\tlength: function() {\n
\t\treturn this.anchors.length;\n
\t}\n
\n
});\n
\n
$.extend($.ui.tabs, {\n
\tversion: \'1.7.2\',\n
\tgetter: \'length\',\n
\tdefaults: {\n
\t\tajaxOptions: null,\n
\t\tcache: false,\n
\t\tcookie: null, // e.g. { expires: 7, path: \'/\', domain: \'jquery.com\', secure: true }\n
\t\tcollapsible: false,\n
\t\tdisabled: [],\n
\t\tevent: \'click\',\n
\t\tfx: null, // e.g. { height: \'toggle\', opacity: \'toggle\', duration: 200 }\n
\t\tidPrefix: \'ui-tabs-\',\n
\t\tpanelTemplate: \'<div></div>\',\n
\t\tspinner: \'<em>Loading&#8230;</em>\',\n
\t\ttabTemplate: \'<li><a href="#{href}"><span>#{label}</span></a></li>\'\n
\t}\n
});\n
\n
/*\n
 * Tabs Extensions\n
 */\n
\n
/*\n
 * Rotate\n
 */\n
$.extend($.ui.tabs.prototype, {\n
\trotation: null,\n
\trotate: function(ms, continuing) {\n
\n
\t\tvar self = this, o = this.options;\n
\t\t\n
\t\tvar rotate = self._rotate || (self._rotate = function(e) {\n
\t\t\tclearTimeout(self.rotation);\n
\t\t\tself.rotation = setTimeout(function() {\n
\t\t\t\tvar t = o.selected;\n
\t\t\t\tself.select( ++t < self.anchors.length ? t : 0 );\n
\t\t\t}, ms);\n
\t\t\t\n
\t\t\tif (e) {\n
\t\t\t\te.stopPropagation();\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tvar stop = self._unrotate || (self._unrotate = !continuing ?\n
\t\t\tfunction(e) {\n
\t\t\t\tif (e.clientX) { // in case of a true click\n
\t\t\t\t\tself.rotate(null);\n
\t\t\t\t}\n
\t\t\t} :\n
\t\t\tfunction(e) {\n
\t\t\t\tt = o.selected;\n
\t\t\t\trotate();\n
\t\t\t});\n
\n
\t\t// start rotation\n
\t\tif (ms) {\n
\t\t\tthis.element.bind(\'tabsshow\', rotate);\n
\t\t\tthis.anchors.bind(o.event + \'.tabs\', stop);\n
\t\t\trotate();\n
\t\t}\n
\t\t// stop rotation\n
\t\telse {\n
\t\t\tclearTimeout(self.rotation);\n
\t\t\tthis.element.unbind(\'tabsshow\', rotate);\n
\t\t\tthis.anchors.unbind(o.event + \'.tabs\', stop);\n
\t\t\tdelete this._rotate;\n
\t\t\tdelete this._unrotate;\n
\t\t}\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Datepicker 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Datepicker\n
 *\n
 * Depends:\n
 *\tui.core.js\n
 */\n
\n
(function($) { // hide the namespace\n
\n
$.extend($.ui, { datepicker: { version: "1.7.2" } });\n
\n
var PROP_NAME = \'datepicker\';\n
\n
/* Date picker manager.\n
   Use the singleton instance of this class, $.datepicker, to interact with the date picker.\n
   Settings for (groups of) date pickers are maintained in an instance object,\n
   allowing multiple different settings on the same page. */\n
\n
function Datepicker() {\n
\tthis.debug = false; // Change this to true to start debugging\n
\tthis._curInst = null; // The current instance in use\n
\tthis._keyEvent = false; // If the last event was a key event\n
\tthis._disabledInputs = []; // List of date picker inputs that have been disabled\n
\tthis._datepickerShowing = false; // True if the popup picker is showing , false if not\n
\tthis._inDialog = false; // True if showing within a "dialog", false if not\n
\tthis._mainDivId = \'ui-datepicker-div\'; // The ID of the main datepicker division\n
\tthis._inlineClass = \'ui-datepicker-inline\'; // The name of the inline marker class\n
\tthis._appendClass = \'ui-datepicker-append\'; // The name of the append marker class\n
\tthis._triggerClass = \'ui-datepicker-trigger\'; // The name of the trigger marker class\n
\tthis._dialogClass = \'ui-datepicker-dialog\'; // The name of the dialog marker class\n
\tthis._disableClass = \'ui-datepicker-disabled\'; // The name of the disabled covering marker class\n
\tthis._unselectableClass = \'ui-datepicker-unselectable\'; // The name of the unselectable cell marker class\n
\tthis._currentClass = \'ui-datepicker-current-day\'; // The name of the current day marker class\n
\tthis._dayOverClass = \'ui-datepicker-days-cell-over\'; // The name of the day hover marker class\n
\tthis.regional = []; // Available regional settings, indexed by language code\n
\tthis.regional[\'\'] = { // Default regional settings\n
\t\tcloseText: \'Done\', // Display text for close link\n
\t\tprevText: \'Prev\', // Display text for previous month link\n
\t\tnextText: \'Next\', // Display text for next month link\n
\t\tcurrentText: \'Today\', // Display text for current month link\n
\t\tmonthNames: [\'January\',\'February\',\'March\',\'April\',\'May\',\'June\',\n
\t\t\t\'July\',\'August\',\'September\',\'October\',\'November\',\'December\'], // Names of months for drop-down and formatting\n
\t\tmonthNamesShort: [\'Jan\', \'Feb\', \'Mar\', \'Apr\', \'May\', \'Jun\', \'Jul\', \'Aug\', \'Sep\', \'Oct\', \'Nov\', \'Dec\'], // For formatting\n
\t\tdayNames: [\'Sunday\', \'Monday\', \'Tuesday\', \'Wednesday\', \'Thursday\', \'Friday\', \'Saturday\'], // For formatting\n
\t\tdayNamesShort: [\'Sun\', \'Mon\', \'Tue\', \'Wed\', \'Thu\', \'Fri\', \'Sat\'], // For formatting\n
\t\tdayNamesMin: [\'Su\',\'Mo\',\'Tu\',\'We\',\'Th\',\'Fr\',\'Sa\'], // Column headings for days starting at Sunday\n
\t\tdateFormat: \'mm/dd/yy\', // See format options on parseDate\n
\t\tfirstDay: 0, // The first day of the week, Sun = 0, Mon = 1, ...\n
\t\tisRTL: false // True if right-to-left language, false if left-to-right\n
\t};\n
\tthis._defaults = { // Global defaults for all the date picker instances\n
\t\tshowOn: \'focus\', // \'focus\' for popup on focus,\n
\t\t\t// \'button\' for trigger button, or \'both\' for either\n
\t\tshowAnim: \'show\', // Name of jQuery animation for popup\n
\t\tshowOptions: {}, // Options for enhanced animations\n
\t\tdefaultDate: null, // Used when field is blank: actual date,\n
\t\t\t// +/-number for offset from today, null for today\n
\t\tappendText: \'\', // Display text following the input box, e.g. showing the format\n
\t\tbuttonText: \'...\', // Text for trigger button\n
\t\tbuttonImage: \'\', // URL for trigger button image\n
\t\tbuttonImageOnly: false, // True if the image appears alone, false if it appears on a button\n
\t\thideIfNoPrevNext: false, // True to hide next/previous month links\n
\t\t\t// if not applicable, false to just disable them\n
\t\tnavigationAsDateFormat: false, // True if date formatting applied to prev/today/next links\n
\t\tgotoCurrent: false, // True if today link goes back to current selection instead\n
\t\tchangeMonth: false, // True if month can be selected directly, false if only prev/next\n
\t\tchangeYear: false, // True if year can be selected directly, false if only prev/next\n
\t\tshowMonthAfterYear: false, // True if the year select precedes month, false for month then year\n
\t\tyearRange: \'-10:+10\', // Range of years to display in drop-down,\n
\t\t\t// either relative to current year (-nn:+nn) or absolute (nnnn:nnnn)\n
\t\tshowOtherMonths: false, // True to show dates in other months, false to leave blank\n
\t\tcalculateWeek: this.iso8601Week, // How to calculate the week of the year,\n
\t\t\t// takes a Date and returns the number of the week for it\n
\t\tshortYearCutoff: \'+10\', // Short year values < this are in the current century,\n
\t\t\t// > this are in the previous century,\n
\t\t\t// string value starting with \'+\' for current year + value\n
\t\tminDate: null, // The earliest selectable date, or null for no limit\n
\t\tmaxDate: null, // The latest selectable date, or null for no limit\n
\t\tduration: \'normal\', // Duration of display/closure\n
\t\tbeforeShowDay: null, // Function that takes a date and returns an array with\n
\t\t\t// [0] = true if selectable, false if not, [1] = custom CSS class name(s) or \'\',\n
\t\t\t// [2] = cell title (optional), e.g. $.datepicker.noWeekends\n
\t\tbeforeShow: null, // Function that takes an input field and\n
\t\t\t// returns a set of custom settings for the date picker\n
\t\tonSelect: null, // Define a callback function when a date is selected\n
\t\tonChangeMonthYear: null, // Define a callback function when the month or year is changed\n
\t\tonClose: null, // Define a callback function when the datepicker is closed\n
\t\tnumberOfMonths: 1, // Number of months to show at a time\n
\t\tshowCurrentAtPos: 0, // The position in multipe months at which to show the current month (starting at 0)\n
\t\tstepMonths: 1, // Number of months to step back/forward\n
\t\tstepBigMonths: 12, // Number of months to step back/forward for the big links\n
\t\taltField: \'\', // Selector for an alternate field to store selected dates into\n
\t\taltFormat: \'\', // The date format to use for the alternate field\n
\t\tconstrainInput: true, // The input is constrained by the current date format\n
\t\tshowButtonPanel: false // True to show button panel, false to not show it\n
\t};\n
\t$.extend(this._defaults, this.regional[\'\']);\n
\tthis.dpDiv = $(\'<div id="\' + this._mainDivId + \'" class="ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all ui-helper-hidden-accessible"></div>\');\n
}\n
\n
$.extend(Datepicker.prototype, {\n
\t/* Class name added to elements to indicate already configured with a date picker. */\n
\tmarkerClassName: \'hasDatepicker\',\n
\n
\t/* Debug logging (if enabled). */\n
\tlog: function () {\n
\t\tif (this.debug)\n
\t\t\tconsole.log.apply(\'\', arguments);\n
\t},\n
\n
\t/* Override the default settings for all instances of the date picker.\n
\t   @param  settings  object - the new settings to use as defaults (anonymous object)\n
\t   @return the manager object */\n
\tsetDefaults: function(settings) {\n
\t\textendRemove(this._defaults, settings || {});\n
\t\treturn this;\n
\t},\n
\n
\t/* Attach the date picker to a jQuery selection.\n
\t   @param  target    element - the target input field or division or span\n
\t   @param  settings  object - the new settings to use for this date picker instance (anonymous) */\n
\t_attachDatepicker: function(target, settings) {\n
\t\t// check for settings on the control itself - in namespace \'date:\'\n
\t\tvar inlineSettings = null;\n
\t\tfor (var attrName in this._defaults) {\n
\t\t\tvar attrValue = target.getAttribute(\'date:\' + attrName);\n
\t\t\tif (attrValue) {\n
\t\t\t\tinlineSettings = inlineSettings || {};\n
\t\t\t\ttry {\n
\t\t\t\t\tinlineSettings[attrName] = eval(attrValue);\n
\t\t\t\t} catch (err) {\n
\t\t\t\t\tinlineSettings[attrName] = attrValue;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tvar nodeName = target.nodeName.toLowerCase();\n
\t\tvar inline = (nodeName == \'div\' || nodeName == \'span\');\n
\t\tif (!target.id)\n
\t\t\ttarget.id = \'dp\' + (++this.uuid);\n
\t\tvar inst = this._newInst($(target), inline);\n
\t\tinst.settings = $.extend({}, settings || {}, inlineSettings || {});\n
\t\tif (nodeName == \'input\') {\n
\t\t\tthis._connectDatepicker(target, inst);\n
\t\t} else if (inline) {\n
\t\t\tthis._inlineDatepicker(target, inst);\n
\t\t}\n
\t},\n
\n
\t/* Create a new instance object. */\n
\t_newInst: function(target, inline) {\n
\t\tvar id = target[0].id.replace(/([:\\[\\]\\.])/g, \'\\\\\\\\$1\'); // escape jQuery meta chars\n
\t\treturn {id: id, input: target, // associated target\n
\t\t\tselectedDay: 0, selectedMonth: 0, selectedYear: 0, // current selection\n
\t\t\tdrawMonth: 0, drawYear: 0, // month being drawn\n
\t\t\tinline: inline, // is datepicker inline or not\n
\t\t\tdpDiv: (!inline ? this.dpDiv : // presentation div\n
\t\t\t$(\'<div class="\' + this._inlineClass + \' ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all"></div>\'))};\n
\t},\n
\n
\t/* Attach the date picker to an input field. */\n
\t_connectDatepicker: function(target, inst) {\n
\t\tvar input = $(target);\n
\t\tinst.append = $([]);\n
\t\tinst.trigger = $([]);\n
\t\tif (input.hasClass(this.markerClassName))\n
\t\t\treturn;\n
\t\tvar appendText = this._get(inst, \'appendText\');\n
\t\tvar isRTL = this._get(inst, \'isRTL\');\n
\t\tif (appendText) {\n
\t\t\tinst.append = $(\'<span class="\' + this._appendClass + \'">\' + appendText + \'</span>\');\n
\t\t\tinput[isRTL ? \'before\' : \'after\'](inst.append);\n
\t\t}\n
\t\tvar showOn = this._get(inst, \'showOn\');\n
\t\tif (showOn == \'focus\' || showOn == \'both\') // pop-up date picker when in the marked field\n
\t\t\tinput.focus(this._showDatepicker);\n
\t\tif (showOn == \'button\' || showOn == \'both\') { // pop-up date picker when button clicked\n
\t\t\tvar buttonText = this._get(inst, \'buttonText\');\n
\t\t\tvar buttonImage = this._get(inst, \'buttonImage\');\n
\t\t\tinst.trigger = $(this._get(inst, \'buttonImageOnly\') ?\n
\t\t\t\t$(\'<img/>\').addClass(this._triggerClass).\n
\t\t\t\t\tattr({ src: buttonImage, alt: buttonText, title: buttonText }) :\n
\t\t\t\t$(\'<button type="button"></button>\').addClass(this._triggerClass).\n
\t\t\t\t\thtml(buttonImage == \'\' ? buttonText : $(\'<img/>\').attr(\n
\t\t\t\t\t{ src:buttonImage, alt:buttonText, title:buttonText })));\n
\t\t\tinput[isRTL ? \'before\' : \'after\'](inst.trigger);\n
\t\t\tinst.trigger.click(function() {\n
\t\t\t\tif ($.datepicker._datepickerShowing && $.datepicker._lastInput == target)\n
\t\t\t\t\t$.datepicker._hideDatepicker();\n
\t\t\t\telse\n
\t\t\t\t\t$.datepicker._showDatepicker(target);\n
\t\t\t\treturn false;\n
\t\t\t});\n
\t\t}\n
\t\tinput.addClass(this.markerClassName).keydown(this._doKeyDown).keypress(this._doKeyPress).\n
\t\t\tbind("setData.datepicker", function(event, key, value) {\n
\t\t\t\tinst.settings[key] = value;\n
\t\t\t}).bind("getData.datepicker", function(event, key) {\n
\t\t\t\treturn this._get(inst, key);\n
\t\t\t});\n
\t\t$.data(target, PROP_NAME, inst);\n
\t},\n
\n
\t/* Attach an inline date picker to a div. */\n
\t_inlineDatepicker: function(target, inst) {\n
\t\tvar divSpan = $(target);\n
\t\tif (divSpan.hasClass(this.markerClassName))\n
\t\t\treturn;\n
\t\tdivSpan.addClass(this.markerClassName).append(inst.dpDiv).\n
\t\t\tbind("setData.datepicker", function(event, key, value){\n
\t\t\t\tinst.settings[key] = value;\n
\t\t\t}).bind("getData.datepicker", function(event, key){\n
\t\t\t\treturn this._get(inst, key);\n
\t\t\t});\n
\t\t$.data(target, PROP_NAME, inst);\n
\t\tthis._setDate(inst, this._getDefaultDate(inst));\n
\t\tthis._updateDatepicker(inst);\n
\t\tthis._updateAlternate(inst);\n
\t},\n
\n
\t/* Pop-up the date picker in a "dialog" box.\n
\t   @param  input     element - ignored\n
\t   @param  dateText  string - the initial date to display (in the current format)\n
\t   @param  onSelect  function - the function(dateText) to call when a date is selected\n
\t   @param  settings  object - update the dialog date picker instance\'s settings (anonymous object)\n
\t   @param  pos       int[2] - coordinates for the dialog\'s position within the screen or\n
\t                     event - with x/y coordinates or\n
\t                     leave empty for default (screen centre)\n
\t   @return the manager object */\n
\t_dialogDatepicker: function(input, dateText, onSelect, settings, pos) {\n
\t\tvar inst = this._dialogInst; // internal instance\n
\t\tif (!inst) {\n
\t\t\tvar id = \'dp\' + (++this.uuid);\n
\t\t\tthis._dialogInput = $(\'<input type="text" id="\' + id +\n
\t\t\t\t\'" size="1" style="position: absolute; top: -100px;"/>\');\n
\t\t\tthis._dialogInput.keydown(this._doKeyDown);\n
\t\t\t$(\'body\').append(this._dialogInput);\n
\t\t\tinst = this._dialogInst = this._newInst(this._dialogInput, false);\n
\t\t\tinst.settings = {};\n
\t\t\t$.data(this._dialogInput[0], PROP_NAME, inst);\n
\t\t}\n
\t\textendRemove(inst.settings, settings || {});\n
\t\tthis._dialogInput.val(dateText);\n
\n
\t\tthis._pos = (pos ? (pos.length ? pos : [pos.pageX, pos.pageY]) : null);\n
\t\tif (!this._pos) {\n
\t\t\tvar browserWidth = window.innerWidth || document.documentElement.clientWidth ||\tdocument.body.clientWidth;\n
\t\t\tvar browserHeight = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight;\n
\t\t\tvar scrollX = document.documentElement.scrollLeft || document.body.scrollLeft;\n
\t\t\tvar scrollY = document.documentElement.scrollTop || document.body.scrollTop;\n
\t\t\tthis._pos = // should use actual width/height below\n
\t\t\t\t[(browserWidth / 2) - 100 + scrollX, (browserHeight / 2) - 150 + scrollY];\n
\t\t}\n
\n
\t\t// move input on screen for focus, but hidden behind dialog\n
\t\tthis._dialogInput.css(\'left\', this._pos[0] + \'px\').css(\'top\', this._pos[1] + \'px\');\n
\t\tinst.settings.onSelect = onSelect;\n
\t\tthis._inDialog = true;\n
\t\tthis.dpDiv.addClass(this._dialogClass);\n
\t\tthis._showDatepicker(this._dialogInput[0]);\n
\t\tif ($.blockUI)\n
\t\t\t$.blockUI(this.dpDiv);\n
\t\t$.data(this._dialogInput[0], PROP_NAME, inst);\n
\t\treturn this;\n
\t},\n
\n
\t/* Detach a datepicker from its control.\n
\t   @param  target    element - the target input field or division or span */\n
\t_destroyDatepicker: function(target) {\n
\t\tvar $target = $(target);\n
\t\tvar inst = $.data(target, PROP_NAME);\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\t\tvar nodeName = target.nodeName.toLowerCase();\n
\t\t$.removeData(target, PROP_NAME);\n
\t\tif (nodeName == \'input\') {\n
\t\t\tinst.append.remove();\n
\t\t\tinst.trigger.remove();\n
\t\t\t$target.removeClass(this.markerClassName).\n
\t\t\t\tunbind(\'focus\', this._showDatepicker).\n
\t\t\t\tunbind(\'keydown\', this._doKeyDown).\n
\t\t\t\tunbind(\'keypress\', this._doKeyPress);\n
\t\t} else if (nodeName == \'div\' || nodeName == \'span\')\n
\t\t\t$target.removeClass(this.markerClassName).empty();\n
\t},\n
\n
\t/* Enable the date picker to a jQuery selection.\n
\t   @param  target    element - the target input field or division or span */\n
\t_enableDatepicker: function(target) {\n
\t\tvar $target = $(target);\n
\t\tvar inst = $.data(target, PROP_NAME);\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\t\tvar nodeName = target.nodeName.toLowerCase();\n
\t\tif (nodeName == \'input\') {\n
\t\t\ttarget.disabled = false;\n
\t\t\tinst.trigger.filter(\'button\').\n
\t\t\t\teach(function() { this.disabled = false; }).end().\n
\t\t\t\tfilter(\'img\').css({opacity: \'1.0\', cursor: \'\'});\n
\t\t}\n
\t\telse if (nodeName == \'div\' || nodeName == \'span\') {\n
\t\t\tvar inline = $target.children(\'.\' + this._inlineClass);\n
\t\t\tinline.children().removeClass(\'ui-state-disabled\');\n
\t\t}\n
\t\tthis._disabledInputs = $.map(this._disabledInputs,\n
\t\t\tfunction(value) { return (value == target ? null : value); }); // delete entry\n
\t},\n
\n
\t/* Disable the date picker to a jQuery selection.\n
\t   @param  target    element - the target input field or division or span */\n
\t_disableDatepicker: function(target) {\n
\t\tvar $target = $(target);\n
\t\tvar inst = $.data(target, PROP_NAME);\n
\t\tif (!$target.hasClass(this.markerClassName)) {\n
\t\t\treturn;\n
\t\t}\n
\t\tvar nodeName = target.nodeName.toLowerCase();\n
\t\tif (nodeName == \'input\') {\n
\t\t\ttarget.disabled = true;\n
\t\t\tinst.trigger.filter(\'button\').\n
\t\t\t\teach(function() { this.disabled = true; }).end().\n
\t\t\t\tfilter(\'img\').css({opacity: \'0.5\', cursor: \'default\'});\n
\t\t}\n
\t\telse if (nodeName == \'div\' || nodeName == \'span\') {\n
\t\t\tvar inline = $target.children(\'.\' + this._inlineClass);\n
\t\t\tinline.children().addClass(\'ui-state-disabled\');\n
\t\t}\n
\t\tthis._disabledInputs = $.map(this._disabledInputs,\n
\t\t\tfunction(value) { return (value == target ? null : value); }); // delete entry\n
\t\tthis._disabledInputs[this._disabledInputs.length] = target;\n
\t},\n
\n
\t/* Is the first field in a jQuery collection disabled as a datepicker?\n
\t   @param  target    element - the target input field or division or span\n
\t   @return boolean - true if disabled, false if enabled */\n
\t_isDisabledDatepicker: function(target) {\n
\t\tif (!target) {\n
\t\t\treturn false;\n
\t\t}\n
\t\tfor (var i = 0; i < this._disabledInputs.length; i++) {\n
\t\t\tif (this._disabledInputs[i] == target)\n
\t\t\t\treturn true;\n
\t\t}\n
\t\treturn false;\n
\t},\n
\n
\t/* Retrieve the instance data for the target control.\n
\t   @param  target  element - the target input field or division or span\n
\t   @return  object - the associated instance data\n
\t   @throws  error if a jQuery problem getting data */\n
\t_getInst: function(target) {\n
\t\ttry {\n
\t\t\treturn $.data(target, PROP_NAME);\n
\t\t}\n
\t\tcatch (err) {\n
\t\t\tthrow \'Missing instance data for this datepicker\';\n
\t\t}\n
\t},\n
\n
\t/* Update or retrieve the settings for a date picker attached to an input field or division.\n
\t   @param  target  element - the target input field or division or span\n
\t   @param  name    object - the new settings to update or\n
\t                   string - the name of the setting to change or retrieve,\n
\t                   when retrieving also \'all\' for all instance settings or\n
\t                   \'defaults\' for all global defaults\n
\t   @param  value   any - the new value for the setting\n
\t                   (omit if above is an object or to retrieve a value) */\n
\t_optionDatepicker: function(target, name, value) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (arguments.length == 2 && typeof name == \'string\') {\n
\t\t\treturn (name == \'defaults\' ? $.extend({}, $.datepicker._defaults) :\n
\t\t\t\t(inst ? (name == \'all\' ? $.extend({}, inst.settings) :\n
\t\t\t\tthis._get(inst, name)) : null));\n
\t\t}\n
\t\tvar settings = name || {};\n
\t\tif (typeof name == \'string\') {\n
\t\t\tsettings = {};\n
\t\t\tsettings[name] = value;\n
\t\t}\n
\t\tif (inst) {\n
\t\t\tif (this._curInst == inst) {\n
\t\t\t\tthis._hideDatepicker(null);\n
\t\t\t}\n
\t\t\tvar date = this._getDateDatepicker(target);\n
\t\t\textendRemove(inst.settings, settings);\n
\t\t\tthis._setDateDatepicker(target, date);\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t}\n
\t},\n
\n
\t// change method deprecated\n
\t_changeDatepicker: function(target, name, value) {\n
\t\tthis._optionDatepicker(target, name, value);\n
\t},\n
\n
\t/* Redraw the date picker attached to an input field or division.\n
\t   @param  target  element - the target input field or division or span */\n
\t_refreshDatepicker: function(target) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst) {\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t}\n
\t},\n
\n
\t/* Set the dates for a jQuery selection.\n
\t   @param  target   element - the target input field or division or span\n
\t   @param  date     Date - the new date\n
\t   @param  endDate  Date - the new end date for a range (optional) */\n
\t_setDateDatepicker: function(target, date, endDate) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst) {\n
\t\t\tthis._setDate(inst, date, endDate);\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t\tthis._updateAlternate(inst);\n
\t\t}\n
\t},\n
\n
\t/* Get the date(s) for the first entry in a jQuery selection.\n
\t   @param  target  element - the target input field or division or span\n
\t   @return Date - the current date or\n
\t           Date[2] - the current dates for a range */\n
\t_getDateDatepicker: function(target) {\n
\t\tvar inst = this._getInst(target);\n
\t\tif (inst && !inst.inline)\n
\t\t\tthis._setDateFromField(inst);\n
\t\treturn (inst ? this._getDate(inst) : null);\n
\t},\n
\n
\t/* Handle keystrokes. */\n
\t_doKeyDown: function(event) {\n
\t\tvar inst = $.datepicker._getInst(event.target);\n
\t\tvar handled = true;\n
\t\tvar isRTL = inst.dpDiv.is(\'.ui-datepicker-rtl\');\n
\t\tinst._keyEvent = true;\n
\t\tif ($.datepicker._datepickerShowing)\n
\t\t\tswitch (event.keyCode) {\n
\t\t\t\tcase 9:  $.datepicker._hideDatepicker(null, \'\');\n
\t\t\t\t\t\tbreak; // hide on tab out\n
\t\t\t\tcase 13: var sel = $(\'td.\' + $.datepicker._dayOverClass +\n
\t\t\t\t\t\t\t\', td.\' + $.datepicker._currentClass, inst.dpDiv);\n
\t\t\t\t\t\tif (sel[0])\n
\t\t\t\t\t\t\t$.datepicker._selectDay(event.target, inst.selectedMonth, inst.selectedYear, sel[0]);\n
\t\t\t\t\t\telse\n
\t\t\t\t\t\t\t$.datepicker._hideDatepicker(null, $.datepicker._get(inst, \'duration\'));\n
\t\t\t\t\t\treturn false; // don\'t submit the form\n
\t\t\t\t\t\tbreak; // select the value on enter\n
\t\t\t\tcase 27: $.datepicker._hideDatepicker(null, $.datepicker._get(inst, \'duration\'));\n
\t\t\t\t\t\tbreak; // hide on escape\n
\t\t\t\tcase 33: $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t-$.datepicker._get(inst, \'stepBigMonths\') :\n
\t\t\t\t\t\t\t-$.datepicker._get(inst, \'stepMonths\')), \'M\');\n
\t\t\t\t\t\tbreak; // previous month/year on page up/+ ctrl\n
\t\t\t\tcase 34: $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t+$.datepicker._get(inst, \'stepBigMonths\') :\n
\t\t\t\t\t\t\t+$.datepicker._get(inst, \'stepMonths\')), \'M\');\n
\t\t\t\t\t\tbreak; // next month/year on page down/+ ctrl\n
\t\t\t\tcase 35: if (event.ctrlKey || event.metaKey) $.datepicker._clearDate(event.target);\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // clear on ctrl or command +end\n
\t\t\t\tcase 36: if (event.ctrlKey || event.metaKey) $.datepicker._gotoToday(event.target);\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // current on ctrl or command +home\n
\t\t\t\tcase 37: if (event.ctrlKey || event.metaKey) $.datepicker._adjustDate(event.target, (isRTL ? +1 : -1), \'D\');\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\t// -1 day on ctrl or command +left\n
\t\t\t\t\t\tif (event.originalEvent.altKey) $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t\t\t-$.datepicker._get(inst, \'stepBigMonths\') :\n
\t\t\t\t\t\t\t\t\t-$.datepicker._get(inst, \'stepMonths\')), \'M\');\n
\t\t\t\t\t\t// next month/year on alt +left on Mac\n
\t\t\t\t\t\tbreak;\n
\t\t\t\tcase 38: if (event.ctrlKey || event.metaKey) $.datepicker._adjustDate(event.target, -7, \'D\');\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // -1 week on ctrl or command +up\n
\t\t\t\tcase 39: if (event.ctrlKey || event.metaKey) $.datepicker._adjustDate(event.target, (isRTL ? -1 : +1), \'D\');\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\t// +1 day on ctrl or command +right\n
\t\t\t\t\t\tif (event.originalEvent.altKey) $.datepicker._adjustDate(event.target, (event.ctrlKey ?\n
\t\t\t\t\t\t\t\t\t+$.datepicker._get(inst, \'stepBigMonths\') :\n
\t\t\t\t\t\t\t\t\t+$.datepicker._get(inst, \'stepMonths\')), \'M\');\n
\t\t\t\t\t\t// next month/year on alt +right\n
\t\t\t\t\t\tbreak;\n
\t\t\t\tcase 40: if (event.ctrlKey || event.metaKey) $.datepicker._adjustDate(event.target, +7, \'D\');\n
\t\t\t\t\t\thandled = event.ctrlKey || event.metaKey;\n
\t\t\t\t\t\tbreak; // +1 week on ctrl or command +down\n
\t\t\t\tdefault: handled = false;\n
\t\t\t}\n
\t\telse if (event.keyCode == 36 && event.ctrlKey) // display the date picker on ctrl+home\n
\t\t\t$.datepicker._showDatepicker(this);\n
\t\telse {\n
\t\t\thandled = false;\n
\t\t}\n
\t\tif (handled) {\n
\t\t\tevent.preventDefault();\n
\t\t\tevent.stopPropagation();\n
\t\t}\n
\t},\n
\n
\t/* Filter entered characters - based on date format. */\n
\t_doKeyPress: function(event) {\n
\t\tvar inst = $.datepicker._getInst(event.target);\n
\t\tif ($.datepicker._get(inst, \'constrainInput\')) {\n
\t\t\tvar chars = $.datepicker._possibleChars($.datepicker._get(inst, \'dateFormat\'));\n
\t\t\tvar chr = String.fromCharCode(event.charCode == undefined ? event.keyCode : event.charCode);\n
\t\t\treturn event.ctrlKey || (chr < \' \' || !chars || chars.indexOf(chr) > -1);\n
\t\t}\n
\t},\n
\n
\t/* Pop-up the date picker for a given input field.\n
\t   @param  input  element - the input field attached to the date picker or\n
\t                  event - if triggered by focus */\n
\t_showDatepicker: function(input) {\n
\t\tinput = input.target || input;\n
\t\tif (input.nodeName.toLowerCase() != \'input\') // find from button/image trigger\n
\t\t\tinput = $(\'input\', input.parentNode)[0];\n
\t\tif ($.datepicker._isDisabledDatepicker(input) || $.datepicker._lastInput == input) // already here\n
\t\t\treturn;\n
\t\tvar inst = $.datepicker._getInst(input);\n
\t\tvar beforeShow = $.datepicker._get(inst, \'beforeShow\');\n
\t\textendRemove(inst.settings, (beforeShow ? beforeShow.apply(input, [input, inst]) : {}));\n
\t\t$.datepicker._hideDatepicker(null, \'\');\n
\t\t$.datepicker._lastInput = input;\n
\t\t$.datepicker._setDateFromField(inst);\n
\t\tif ($.datepicker._inDialog) // hide cursor\n
\t\t\tinput.value = \'\';\n
\t\tif (!$.datepicker._pos) { // position below input\n
\t\t\t$.datepicker._pos = $.datepicker._findPos(input);\n
\t\t\t$.datepicker._pos[1] += input.offsetHeight; // add the height\n
\t\t}\n
\t\tvar isFixed = false;\n
\t\t$(input).parents().each(function() {\n
\t\t\tisFixed |= $(this).css(\'position\') == \'fixed\';\n
\t\t\treturn !isFixed;\n
\t\t});\n
\t\tif (isFixed && $.browser.opera) { // correction for Opera when fixed and scrolled\n
\t\t\t$.datepicker._pos[0] -= document.documentElement.scrollLeft;\n
\t\t\t$.datepicker._pos[1] -= document.documentElement.scrollTop;\n
\t\t}\n
\t\tvar offset = {left: $.datepicker._pos[0], top: $.datepicker._pos[1]};\n
\t\t$.datepicker._pos = null;\n
\t\tinst.rangeStart = null;\n
\t\t// determine sizing offscreen\n
\t\tinst.dpDiv.css({position: \'absolute\', display: \'block\', top: \'-1000px\'});\n
\t\t$.datepicker._updateDatepicker(inst);\n
\t\t// fix width for dynamic number of date pickers\n
\t\t// and adjust position before showing\n
\t\toffset = $.datepicker._checkOffset(inst, offset, isFixed);\n
\t\tinst.dpDiv.css({position: ($.datepicker._inDialog && $.blockUI ?\n
\t\t\t\'static\' : (isFixed ? \'fixed\' : \'absolute\')), display: \'none\',\n
\t\t\tleft: offset.left + \'px\', top: offset.top + \'px\'});\n
\t\tif (!inst.inline) {\n
\t\t\tvar showAnim = $.datepicker._get(inst, \'showAnim\') || \'show\';\n
\t\t\tvar duration = $.datepicker._get(inst, \'duration\');\n
\t\t\tvar postProcess = function() {\n
\t\t\t\t$.datepicker._datepickerShowing = true;\n
\t\t\t\tif ($.browser.msie && parseInt($.browser.version,10) < 7) // fix IE < 7 select problems\n
\t\t\t\t\t$(\'iframe.ui-datepicker-cover\').css({width: inst.dpDiv.width() + 4,\n
\t\t\t\t\t\theight: inst.dpDiv.height() + 4});\n
\t\t\t};\n
\t\t\tif ($.effects && $.effects[showAnim])\n
\t\t\t\tinst.dpDiv.show(showAnim, $.datepicker._get(inst, \'showOptions\'), duration, postProcess);\n
\t\t\telse\n
\t\t\t\tinst.dpDiv[showAnim](duration, postProcess);\n
\t\t\tif (duration == \'\')\n
\t\t\t\tpostProcess();\n
\t\t\tif (inst.input[0].type != \'hidden\')\n
\t\t\t\tinst.input[0].focus();\n
\t\t\t$.datepicker._curInst = inst;\n
\t\t}\n
\t},\n
\n
\t/* Generate the date picker content. */\n
\t_updateDatepicker: function(inst) {\n
\t\tvar dims = {width: inst.dpDiv.width() + 4,\n
\t\t\theight: inst.dpDiv.height() + 4};\n
\t\tvar self = this;\n
\t\tinst.dpDiv.empty().append(this._generateHTML(inst))\n
\t\t\t.find(\'iframe.ui-datepicker-cover\').\n
\t\t\t\tcss({width: dims.width, height: dims.height})\n
\t\t\t.end()\n
\t\t\t.find(\'button, .ui-datepicker-prev, .ui-datepicker-next, .ui-datepicker-calendar td a\')\n
\t\t\t\t.bind(\'mouseout\', function(){\n
\t\t\t\t\t$(this).removeClass(\'ui-state-hover\');\n
\t\t\t\t\tif(this.className.indexOf(\'ui-datepicker-prev\') != -1) $(this).removeClass(\'ui-datepicker-prev-hover\');\n
\t\t\t\t\tif(this.className.indexOf(\'ui-datepicker-next\') != -1) $(this).removeClass(\'ui-datepicker-next-hover\');\n
\t\t\t\t})\n
\t\t\t\t.bind(\'mouseover\', function(){\n
\t\t\t\t\tif (!self._isDisabledDatepicker( inst.inline ? inst.dpDiv.parent()[0] : inst.input[0])) {\n
\t\t\t\t\t\t$(this).parents(\'.ui-datepicker-calendar\').find(\'a\').removeClass(\'ui-state-hover\');\n
\t\t\t\t\t\t$(this).addClass(\'ui-state-hover\');\n
\t\t\t\t\t\tif(this.className.indexOf(\'ui-datepicker-prev\') != -1) $(this).addClass(\'ui-datepicker-prev-hover\');\n
\t\t\t\t\t\tif(this.className.indexOf(\'ui-datepicker-next\') != -1) $(this).addClass(\'ui-datepicker-next-hover\');\n
\t\t\t\t\t}\n
\t\t\t\t})\n
\t\t\t.end()\n
\t\t\t.find(\'.\' + this._dayOverClass + \' a\')\n
\t\t\t\t.trigger(\'mouseover\')\n
\t\t\t.end();\n
\t\tvar numMonths = this._getNumberOfMonths(inst);\n
\t\tvar cols = numMonths[1];\n
\t\tvar width = 17;\n
\t\tif (cols > 1) {\n
\t\t\tinst.dpDiv.addClass(\'ui-datepicker-multi-\' + cols).css(\'width\', (width * cols) + \'em\');\n
\t\t} else {\n
\t\t\tinst.dpDiv.removeClass(\'ui-datepicker-multi-2 ui-datepicker-multi-3 ui-datepicker-multi-4\').width(\'\');\n
\t\t}\n
\t\tinst.dpDiv[(numMonths[0] != 1 || numMonths[1] != 1 ? \'add\' : \'remove\') +\n
\t\t\t\'Class\'](\'ui-datepicker-multi\');\n
\t\tinst.dpDiv[(this._get(inst, \'isRTL\') ? \'add\' : \'remove\') +\n
\t\t\t\'Class\'](\'ui-datepicker-rtl\');\n
\t\tif (inst.input && inst.input[0].type != \'hidden\' && inst == $.datepicker._curInst)\n
\t\t\t$(inst.input[0]).focus();\n
\t},\n
\n
\t/* Check positioning to remain on screen. */\n
\t_checkOffset: function(inst, offset, isFixed) {\n
\t\tvar dpWidth = inst.dpDiv.outerWidth();\n
\t\tvar dpHeight = inst.dpDiv.outerHeight();\n
\t\tvar inputWidth = inst.input ? inst.input.outerWidth() : 0;\n
\t\tvar inputHeight = inst.input ? inst.input.outerHeight() : 0;\n
\t\tvar viewWidth = (window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth) + $(document).scrollLeft();\n
\t\tvar viewHeight = (window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight) + $(document).scrollTop();\n
\n
\t\toffset.left -= (this._get(inst, \'isRTL\') ? (dpWidth - inputWidth) : 0);\n
\t\toffset.left -= (isFixed && offset.left == inst.input.offset().left) ? $(document).scrollLeft() : 0;\n
\t\toffset.top -= (isFixed && offset.top == (inst.input.offset().top + inputHeight)) ? $(document).scrollTop() : 0;\n
\n
\t\t// now check if datepicker is showing outside window viewport - move to a better place if so.\n
\t\toffset.left -= (offset.left + dpWidth > viewWidth && viewWidth > dpWidth) ? Math.abs(offset.left + dpWidth - viewWidth) : 0;\n
\t\toffset.top -= (offset.top + dpHeight > viewHeight && viewHeight > dpHeight) ? Math.abs(offset.top + dpHeight + inputHeight*2 - viewHeight) : 0;\n
\n
\t\treturn offset;\n
\t},\n
\n
\t/* Find an object\'s position on the screen. */\n
\t_findPos: function(obj) {\n
        while (obj && (obj.type == \'hidden\' || obj.nodeType != 1)) {\n
            obj = obj.nextSibling;\n
        }\n
        var position = $(obj).offset();\n
\t    return [position.left, position.top];\n
\t},\n
\n
\t/* Hide the date picker from view.\n
\t   @param  input  element - the input field attached to the date picker\n
\t   @param  duration  string - the duration over which to close the date picker */\n
\t_hideDatepicker: function(input, duration) {\n
\t\tvar inst = this._curInst;\n
\t\tif (!inst || (input && inst != $.data(input, PROP_NAME)))\n
\t\t\treturn;\n
\t\tif (inst.stayOpen)\n
\t\t\tthis._selectDate(\'#\' + inst.id, this._formatDate(inst,\n
\t\t\t\tinst.currentDay, inst.currentMonth, inst.currentYear));\n
\t\tinst.stayOpen = false;\n
\t\tif (this._datepickerShowing) {\n
\t\t\tduration = (duration != null ? duration : this._get(inst, \'duration\'));\n
\t\t\tvar showAnim = this._get(inst, \'showAnim\');\n
\t\t\tvar postProcess = function() {\n
\t\t\t\t$.datepicker._tidyDialog(inst);\n
\t\t\t};\n
\t\t\tif (duration != \'\' && $.effects && $.effects[showAnim])\n
\t\t\t\tinst.dpDiv.hide(showAnim, $.datepicker._get(inst, \'showOptions\'),\n
\t\t\t\t\tduration, postProcess);\n
\t\t\telse\n
\t\t\t\tinst.dpDiv[(duration == \'\' ? \'hide\' : (showAnim == \'slideDown\' ? \'slideUp\' :\n
\t\t\t\t\t(showAnim == \'fadeIn\' ? \'fadeOut\' : \'hide\')))](duration, postProcess);\n
\t\t\tif (duration == \'\')\n
\t\t\t\tthis._tidyDialog(inst);\n
\t\t\tvar onClose = this._get(inst, \'onClose\');\n
\t\t\tif (onClose)\n
\t\t\t\tonClose.apply((inst.input ? inst.input[0] : null),\n
\t\t\t\t\t[(inst.input ? inst.input.val() : \'\'), inst]);  // trigger custom callback\n
\t\t\tthis._datepickerShowing = false;\n
\t\t\tthis._lastInput = null;\n
\t\t\tif (this._inDialog) {\n
\t\t\t\tthis._dialogInput.css({ position: \'absolute\', left: \'0\', top: \'-100px\' });\n
\t\t\t\tif ($.blockUI) {\n
\t\t\t\t\t$.unblockUI();\n
\t\t\t\t\t$(\'body\').append(this.dpDiv);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis._inDialog = false;\n
\t\t}\n
\t\tthis._curInst = null;\n
\t},\n
\n
\t/* Tidy up after a dialog display. */\n
\t_tidyDialog: function(inst) {\n
\t\tinst.dpDiv.removeClass(this._dialogClass).unbind(\'.ui-datepicker-calendar\');\n
\t},\n
\n
\t/* Close date picker if clicked elsewhere. */\n
\t_checkExternalClick: function(event) {\n
\t\tif (!$.datepicker._curInst)\n
\t\t\treturn;\n
\t\tvar $target = $(event.target);\n
\t\tif (($target.parents(\'#\' + $.datepicker._mainDivId).length == 0) &&\n
\t\t\t\t!$target.hasClass($.datepicker.markerClassName) &&\n
\t\t\t\t!$target.hasClass($.datepicker._triggerClass) &&\n
\t\t\t\t$.datepicker._datepickerShowing && !($.datepicker._inDialog && $.blockUI))\n
\t\t\t$.datepicker._hideDatepicker(null, \'\');\n
\t},\n
\n
\t/* Adjust one of the date sub-fields. */\n
\t_adjustDate: function(id, offset, period) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tif (this._isDisabledDatepicker(target[0])) {\n
\t\t\treturn;\n
\t\t}\n
\t\tthis._adjustInstDate(inst, offset +\n
\t\t\t(period == \'M\' ? this._get(inst, \'showCurrentAtPos\') : 0), // undo positioning\n
\t\t\tperiod);\n
\t\tthis._updateDatepicker(inst);\n
\t},\n
\n
\t/* Action for current link. */\n
\t_gotoToday: function(id) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tif (this._get(inst, \'gotoCurrent\') && inst.currentDay) {\n
\t\t\tinst.selectedDay = inst.currentDay;\n
\t\t\tinst.drawMonth = inst.selectedMonth = inst.currentMonth;\n
\t\t\tinst.drawYear = inst.selectedYear = inst.currentYear;\n
\t\t}\n
\t\telse {\n
\t\tvar date = new Date();\n
\t\tinst.selectedDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\t}\n
\t\tthis._notifyChange(inst);\n
\t\tthis._adjustDate(target);\n
\t},\n
\n
\t/* Action for selecting a new month/year. */\n
\t_selectMonthYear: function(id, select, period) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tinst._selectingMonthYear = false;\n
\t\tinst[\'selected\' + (period == \'M\' ? \'Month\' : \'Year\')] =\n
\t\tinst[\'draw\' + (period == \'M\' ? \'Month\' : \'Year\')] =\n
\t\t\tparseInt(select.options[select.selectedIndex].value,10);\n
\t\tthis._notifyChange(inst);\n
\t\tthis._adjustDate(target);\n
\t},\n
\n
\t/* Restore input focus after not changing month/year. */\n
\t_clickMonthYear: function(id) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tif (inst.input && inst._selectingMonthYear && !$.browser.msie)\n
\t\t\tinst.input[0].focus();\n
\t\tinst._selectingMonthYear = !inst._selectingMonthYear;\n
\t},\n
\n
\t/* Action for selecting a day. */\n
\t_selectDay: function(id, month, year, td) {\n
\t\tvar target = $(id);\n
\t\tif ($(td).hasClass(this._unselectableClass) || this._isDisabledDatepicker(target[0])) {\n
\t\t\treturn;\n
\t\t}\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tinst.selectedDay = inst.currentDay = $(\'a\', td).html();\n
\t\tinst.selectedMonth = inst.currentMonth = month;\n
\t\tinst.selectedYear = inst.currentYear = year;\n
\t\tif (inst.stayOpen) {\n
\t\t\tinst.endDay = inst.endMonth = inst.endYear = null;\n
\t\t}\n
\t\tthis._selectDate(id, this._formatDate(inst,\n
\t\t\tinst.currentDay, inst.currentMonth, inst.currentYear));\n
\t\tif (inst.stayOpen) {\n
\t\t\tinst.rangeStart = this._daylightSavingAdjust(\n
\t\t\t\tnew Date(inst.currentYear, inst.currentMonth, inst.currentDay));\n
\t\t\tthis._updateDatepicker(inst);\n
\t\t}\n
\t},\n
\n
\t/* Erase the input field and hide the date picker. */\n
\t_clearDate: function(id) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tinst.stayOpen = false;\n
\t\tinst.endDay = inst.endMonth = inst.endYear = inst.rangeStart = null;\n
\t\tthis._selectDate(target, \'\');\n
\t},\n
\n
\t/* Update the input field with the selected date. */\n
\t_selectDate: function(id, dateStr) {\n
\t\tvar target = $(id);\n
\t\tvar inst = this._getInst(target[0]);\n
\t\tdateStr = (dateStr != null ? dateStr : this._formatDate(inst));\n
\t\tif (inst.input)\n
\t\t\tinst.input.val(dateStr);\n
\t\tthis._updateAlternate(inst);\n
\t\tvar onSelect = this._get(inst, \'onSelect\');\n
\t\tif (onSelect)\n
\t\t\tonSelect.apply((inst.input ? inst.input[0] : null), [dateStr, inst]);  // trigger custom callback\n
\t\telse if (inst.input)\n
\t\t\tinst.input.trigger(\'change\'); // fire the change event\n
\t\tif (inst.inline)\n
\t\t\tthis._updateDatepicker(inst);\n
\t\telse if (!inst.stayOpen) {\n
\t\t\tthis._hideDatepicker(null, this._get(inst, \'duration\'));\n
\t\t\tthis._lastInput = inst.input[0];\n
\t\t\tif (typeof(inst.input[0]) != \'object\')\n
\t\t\t\tinst.input[0].focus(); // restore focus\n
\t\t\tthis._lastInput = null;\n
\t\t}\n
\t},\n
\n
\t/* Update any alternate field to synchronise with the main field. */\n
\t_updateAlternate: function(inst) {\n
\t\tvar altField = this._get(inst, \'altField\');\n
\t\tif (altField) { // update alternate field too\n
\t\t\tvar altFormat = this._get(inst, \'altFormat\') || this._get(inst, \'dateFormat\');\n
\t\t\tvar date = this._getDate(inst);\n
\t\t\tdateStr = this.formatDate(altFormat, date, this._getFormatConfig(inst));\n
\t\t\t$(altField).each(function() { $(this).val(dateStr); });\n
\t\t}\n
\t},\n
\n
\t/* Set as beforeShowDay function to prevent selection of weekends.\n
\t   @param  date  Date - the date to customise\n
\t   @return [boolean, string] - is this date selectable?, what is its CSS class? */\n
\tnoWeekends: function(date) {\n
\t\tvar day = date.getDay();\n
\t\treturn [(day > 0 && day < 6), \'\'];\n
\t},\n
\n
\t/* Set as calculateWeek to determine the week of the year based on the ISO 8601 definition.\n
\t   @param  date  Date - the date to get the week for\n
\t   @return  number - the number of the week within the year that contains this date */\n
\tiso8601Week: function(date) {\n
\t\tvar checkDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());\n
\t\tvar firstMon = new Date(checkDate.getFullYear(), 1 - 1, 4); // First week always contains 4 Jan\n
\t\tvar firstDay = firstMon.getDay() || 7; // Day of week: Mon = 1, ..., Sun = 7\n
\t\tfirstMon.setDate(firstMon.getDate() + 1 - firstDay); // Preceding Monday\n
\t\tif (firstDay < 4 && checkDate < firstMon) { // Adjust first three days in year if necessary\n
\t\t\tcheckDate.setDate(checkDate.getDate() - 3); // Generate for previous year\n
\t\t\treturn $.datepicker.iso8601Week(checkDate);\n
\t\t} else if (checkDate > new Date(checkDate.getFullYear(), 12 - 1, 28)) { // Check last three days in year\n
\t\t\tfirstDay = new Date(checkDate.getFullYear() + 1, 1 - 1, 4).getDay() || 7;\n
\t\t\tif (firstDay > 4 && (checkDate.getDay() || 7) < firstDay - 3) { // Adjust if necessary\n
\t\t\t\treturn 1;\n
\t\t\t}\n
\t\t}\n
\t\treturn Math.floor(((checkDate - firstMon) / 86400000) / 7) + 1; // Weeks to given date\n
\t},\n
\n
\t/* Parse a string value into a date object.\n
\t   See formatDate below for the possible formats.\n
\n
\t   @param  format    string - the expected format of the date\n
\t   @param  value     string - the date in the above format\n
\t   @param  settings  Object - attributes include:\n
\t                     shortYearCutoff  number - the cutoff year for determining the century (optional)\n
\t                     dayNamesShort    string[7] - abbreviated names of the days from Sunday (optional)\n
\t                     dayNames         string[7] - names of the days from Sunday (optional)\n
\t                     monthNamesShort  string[12] - abbreviated names of the months (optional)\n
\t                     monthNames       string[12] - names of the months (optional)\n
\t   @return  Date - the extracted date value or null if value is blank */\n
\tparseDate: function (format, value, settings) {\n
\t\tif (format == null || value == null)\n
\t\t\tthrow \'Invalid arguments\';\n
\t\tvalue = (typeof value == \'object\' ? value.toString() : value + \'\');\n
\t\tif (value == \'\')\n
\t\t\treturn null;\n
\t\tvar shortYearCutoff = (settings ? settings.shortYearCutoff : null) || this._defaults.shortYearCutoff;\n
\t\tvar dayNamesShort = (settings ? settings.dayNamesShort : null) || this._defaults.dayNamesShort;\n
\t\tvar dayNames = (settings ? settings.dayNames : null) || this._defaults.dayNames;\n
\t\tvar monthNamesShort = (settings ? settings.monthNamesShort : null) || this._defaults.monthNamesShort;\n
\t\tvar monthNames = (settings ? settings.monthNames : null) || this._defaults.monthNames;\n
\t\tvar year = -1;\n
\t\tvar month = -1;\n
\t\tvar day = -1;\n
\t\tvar doy = -1;\n
\t\tvar literal = false;\n
\t\t// Check whether a format character is doubled\n
\t\tvar lookAhead = function(match) {\n
\t\t\tvar matches = (iFormat + 1 < format.length && format.charAt(iFormat + 1) == match);\n
\t\t\tif (matches)\n
\t\t\t\tiFormat++;\n
\t\t\treturn matches;\n
\t\t};\n
\t\t// Extract a number from the string value\n
\t\tvar getNumber = function(match) {\n
\t\t\tlookAhead(match);\n
\t\t\tvar origSize = (match == \'@\' ? 14 : (match == \'y\' ? 4 : (match == \'o\' ? 3 : 2)));\n
\t\t\tvar size = origSize;\n
\t\t\tvar num = 0;\n
\t\t\twhile (size > 0 && iValue < value.length &&\n
\t\t\t\t\tvalue.charAt(iValue) >= \'0\' && value.charAt(iValue) <= \'9\') {\n
\t\t\t\tnum = num * 10 + parseInt(value.charAt(iValue++),10);\n
\t\t\t\tsize--;\n
\t\t\t}\n
\t\t\tif (size == origSize)\n
\t\t\t\tthrow \'Missing number at position \' + iValue;\n
\t\t\treturn num;\n
\t\t};\n
\t\t// Extract a name from the string value and convert to an index\n
\t\tvar getName = function(match, shortNames, longNames) {\n
\t\t\tvar names = (lookAhead(match) ? longNames : shortNames);\n
\t\t\tvar size = 0;\n
\t\t\tfor (var j = 0; j < names.length; j++)\n
\t\t\t\tsize = Math.max(size, names[j].length);\n
\t\t\tvar name = \'\';\n
\t\t\tvar iInit = iValue;\n
\t\t\twhile (size > 0 && iValue < value.length) {\n
\t\t\t\tname += value.charAt(iValue++);\n
\t\t\t\tfor (var i = 0; i < names.length; i++)\n
\t\t\t\t\tif (name == names[i])\n
\t\t\t\t\t\treturn i + 1;\n
\t\t\t\tsize--;\n
\t\t\t}\n
\t\t\tthrow \'Unknown name at position \' + iInit;\n
\t\t};\n
\t\t// Confirm that a literal character matches the string value\n
\t\tvar checkLiteral = function() {\n
\t\t\tif (value.charAt(iValue) != format.charAt(iFormat))\n
\t\t\t\tthrow \'Unexpected literal at position \' + iValue;\n
\t\t\tiValue++;\n
\t\t};\n
\t\tvar iValue = 0;\n
\t\tfor (var iFormat = 0; iFormat < format.length; iFormat++) {\n
\t\t\tif (literal)\n
\t\t\t\tif (format.charAt(iFormat) == "\'" && !lookAhead("\'"))\n
\t\t\t\t\tliteral = false;\n
\t\t\t\telse\n
\t\t\t\t\tcheckLiteral();\n
\t\t\telse\n
\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\tcase \'d\':\n
\t\t\t\t\t\tday = getNumber(\'d\');\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'D\':\n
\t\t\t\t\t\tgetName(\'D\', dayNamesShort, dayNames);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'o\':\n
\t\t\t\t\t\tdoy = getNumber(\'o\');\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'m\':\n
\t\t\t\t\t\tmonth = getNumber(\'m\');\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'M\':\n
\t\t\t\t\t\tmonth = getName(\'M\', monthNamesShort, monthNames);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'y\':\n
\t\t\t\t\t\tyear = getNumber(\'y\');\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'@\':\n
\t\t\t\t\t\tvar date = new Date(getNumber(\'@\'));\n
\t\t\t\t\t\tyear = date.getFullYear();\n
\t\t\t\t\t\tmonth = date.getMonth() + 1;\n
\t\t\t\t\t\tday = date.getDate();\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\tif (lookAhead("\'"))\n
\t\t\t\t\t\t\tcheckLiteral();\n
\t\t\t\t\t\telse\n
\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\tcheckLiteral();\n
\t\t\t\t}\n
\t\t}\n
\t\tif (year == -1)\n
\t\t\tyear = new Date().getFullYear();\n
\t\telse if (year < 100)\n
\t\t\tyear += new Date().getFullYear() - new Date().getFullYear() % 100 +\n
\t\t\t\t(year <= shortYearCutoff ? 0 : -100);\n
\t\tif (doy > -1) {\n
\t\t\tmonth = 1;\n
\t\t\tday = doy;\n
\t\t\tdo {\n
\t\t\t\tvar dim = this._getDaysInMonth(year, month - 1);\n
\t\t\t\tif (day <= dim)\n
\t\t\t\t\tbreak;\n
\t\t\t\tmonth++;\n
\t\t\t\tday -= dim;\n
\t\t\t} while (true);\n
\t\t}\n
\t\tvar date = this._daylightSavingAdjust(new Date(year, month - 1, day));\n
\t\tif (date.getFullYear() != year || date.getMonth() + 1 != month || date.getDate() != day)\n
\t\t\tthrow \'Invalid date\'; // E.g. 31/02/*\n
\t\treturn date;\n
\t},\n
\n
\t/* Standard date formats. */\n
\tATOM: \'yy-mm-dd\', // RFC 3339 (ISO 8601)\n
\tCOOKIE: \'D, dd M yy\',\n
\tISO_8601: \'yy-mm-dd\',\n
\tRFC_822: \'D, d M y\',\n
\tRFC_850: \'DD, dd-M-y\',\n
\tRFC_1036: \'D, d M y\',\n
\tRFC_1123: \'D, d M yy\',\n
\tRFC_2822: \'D, d M yy\',\n
\tRSS: \'D, d M y\', // RFC 822\n
\tTIMESTAMP: \'@\',\n
\tW3C: \'yy-mm-dd\', // ISO 8601\n
\n
\t/* Format a date object into a string value.\n
\t   The format can be combinations of the following:\n
\t   d  - day of month (no leading zero)\n
\t   dd - day of month (two digit)\n
\t   o  - day of year (no leading zeros)\n
\t   oo - day of year (three digit)\n
\t   D  - day name short\n
\t   DD - day name long\n
\t   m  - month of year (no leading zero)\n
\t   mm - month of year (two digit)\n
\t   M  - month name short\n
\t   MM - month name long\n
\t   y  - year (two digit)\n
\t   yy - year (four digit)\n
\t   @ - Unix timestamp (ms since 01/01/1970)\n
\t   \'...\' - literal text\n
\t   \'\' - single quote\n
\n
\t   @param  format    string - the desired format of the date\n
\t   @param  date      Date - the date value to format\n
\t   @param  settings  Object - attributes include:\n
\t                     dayNamesShort    string[7] - abbreviated names of the days from Sunday (optional)\n
\t                     dayNames         string[7] - names of the days from Sunday (optional)\n
\t                     monthNamesShort  string[12] - abbreviated names of the months (optional)\n
\t                     monthNames       string[12] - names of the months (optional)\n
\t   @return  string - the date in the above format */\n
\tformatDate: function (format, date, settings) {\n
\t\tif (!date)\n
\t\t\treturn \'\';\n
\t\tvar dayNamesShort = (settings ? settings.dayNamesShort : null) || this._defaults.dayNamesShort;\n
\t\tvar dayNames = (settings ? settings.dayNames : null) || this._defaults.dayNames;\n
\t\tvar monthNamesShort = (settings ? settings.monthNamesShort : null) || this._defaults.monthNamesShort;\n
\t\tvar monthNames = (settings ? settings.monthNames : null) || this._defaults.monthNames;\n
\t\t// Check whether a format character is doubled\n
\t\tvar lookAhead = function(match) {\n
\t\t\tvar matches = (iFormat + 1 < format.length && format.charAt(iFormat + 1) == match);\n
\t\t\tif (matches)\n
\t\t\t\tiFormat++;\n
\t\t\treturn matches;\n
\t\t};\n
\t\t// Format a number, with leading zero if necessary\n
\t\tvar formatNumber = function(match, value, len) {\n
\t\t\tvar num = \'\' + value;\n
\t\t\tif (lookAhead(match))\n
\t\t\t\twhile (num.length < len)\n
\t\t\t\t\tnum = \'0\' + num;\n
\t\t\treturn num;\n
\t\t};\n
\t\t// Format a name, short or long as requested\n
\t\tvar formatName = function(match, value, shortNames, longNames) {\n
\t\t\treturn (lookAhead(match) ? longNames[value] : shortNames[value]);\n
\t\t};\n
\t\tvar output = \'\';\n
\t\tvar literal = false;\n
\t\tif (date)\n
\t\t\tfor (var iFormat = 0; iFormat < format.length; iFormat++) {\n
\t\t\t\tif (literal)\n
\t\t\t\t\tif (format.charAt(iFormat) == "\'" && !lookAhead("\'"))\n
\t\t\t\t\t\tliteral = false;\n
\t\t\t\t\telse\n
\t\t\t\t\t\toutput += format.charAt(iFormat);\n
\t\t\t\telse\n
\t\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\t\tcase \'d\':\n
\t\t\t\t\t\t\toutput += formatNumber(\'d\', date.getDate(), 2);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'D\':\n
\t\t\t\t\t\t\toutput += formatName(\'D\', date.getDay(), dayNamesShort, dayNames);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'o\':\n
\t\t\t\t\t\t\tvar doy = date.getDate();\n
\t\t\t\t\t\t\tfor (var m = date.getMonth() - 1; m >= 0; m--)\n
\t\t\t\t\t\t\t\tdoy += this._getDaysInMonth(date.getFullYear(), m);\n
\t\t\t\t\t\t\toutput += formatNumber(\'o\', doy, 3);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'m\':\n
\t\t\t\t\t\t\toutput += formatNumber(\'m\', date.getMonth() + 1, 2);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'M\':\n
\t\t\t\t\t\t\toutput += formatName(\'M\', date.getMonth(), monthNamesShort, monthNames);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'y\':\n
\t\t\t\t\t\t\toutput += (lookAhead(\'y\') ? date.getFullYear() :\n
\t\t\t\t\t\t\t\t(date.getYear() % 100 < 10 ? \'0\' : \'\') + date.getYear() % 100);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'@\':\n
\t\t\t\t\t\t\toutput += date.getTime();\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\t\tif (lookAhead("\'"))\n
\t\t\t\t\t\t\t\toutput += "\'";\n
\t\t\t\t\t\t\telse\n
\t\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tdefault:\n
\t\t\t\t\t\t\toutput += format.charAt(iFormat);\n
\t\t\t\t\t}\n
\t\t\t}\n
\t\treturn output;\n
\t},\n
\n
\t/* Extract all possible characters from the date format. */\n
\t_possibleChars: function (format) {\n
\t\tvar chars = \'\';\n
\t\tvar literal = false;\n
\t\tfor (var iFormat = 0; iFormat < format.length; iFormat++)\n
\t\t\tif (literal)\n
\t\t\t\tif (format.charAt(iFormat) == "\'" && !lookAhead("\'"))\n
\t\t\t\t\tliteral = false;\n
\t\t\t\telse\n
\t\t\t\t\tchars += format.charAt(iFormat);\n
\t\t\telse\n
\t\t\t\tswitch (format.charAt(iFormat)) {\n
\t\t\t\t\tcase \'d\': case \'m\': case \'y\': case \'@\':\n
\t\t\t\t\t\tchars += \'0123456789\';\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'D\': case \'M\':\n
\t\t\t\t\t\treturn null; // Accept anything\n
\t\t\t\t\tcase "\'":\n
\t\t\t\t\t\tif (lookAhead("\'"))\n
\t\t\t\t\t\t\tchars += "\'";\n
\t\t\t\t\t\telse\n
\t\t\t\t\t\t\tliteral = true;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\tchars += format.charAt(iFormat);\n
\t\t\t\t}\n
\t\treturn chars;\n
\t},\n
\n
\t/* Get a setting value, defaulting if necessary. */\n
\t_get: function(inst, name) {\n
\t\treturn inst.settings[name] !== undefined ?\n
\t\t\tinst.settings[name] : this._defaults[name];\n
\t},\n
\n
\t/* Parse existing date and initialise date picker. */\n
\t_setDateFromField: function(inst) {\n
\t\tvar dateFormat = this._get(inst, \'dateFormat\');\n
\t\tvar dates = inst.input ? inst.input.val() : null;\n
\t\tinst.endDay = inst.endMonth = inst.endYear = null;\n
\t\tvar date = defaultDate = this._getDefaultDate(inst);\n
\t\tvar settings = this._getFormatConfig(inst);\n
\t\ttry {\n
\t\t\tdate = this.parseDate(dateFormat, dates, settings) || defaultDate;\n
\t\t} catch (event) {\n
\t\t\tthis.log(event);\n
\t\t\tdate = defaultDate;\n
\t\t}\n
\t\tinst.selectedDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\tinst.currentDay = (dates ? date.getDate() : 0);\n
\t\tinst.currentMonth = (dates ? date.getMonth() : 0);\n
\t\tinst.currentYear = (dates ? date.getFullYear() : 0);\n
\t\tthis._adjustInstDate(inst);\n
\t},\n
\n
\t/* Retrieve the default date shown on opening. */\n
\t_getDefaultDate: function(inst) {\n
\t\tvar date = this._determineDate(this._get(inst, \'defaultDate\'), new Date());\n
\t\tvar minDate = this._getMinMaxDate(inst, \'min\', true);\n
\t\tvar maxDate = this._getMinMaxDate(inst, \'max\');\n
\t\tdate = (minDate && date < minDate ? minDate : date);\n
\t\tdate = (maxDate && date > maxDate ? maxDate : date);\n
\t\treturn date;\n
\t},\n
\n
\t/* A date may be specified as an exact value or a relative one. */\n
\t_determineDate: function(date, defaultDate) {\n
\t\tvar offsetNumeric = function(offset) {\n
\t\t\tvar date = new Date();\n
\t\t\tdate.setDate(date.getDate() + offset);\n
\t\t\treturn date;\n
\t\t};\n
\t\tvar offsetString = function(offset, getDaysInMonth) {\n
\t\t\tvar date = new Date();\n
\t\t\tvar year = date.getFullYear();\n
\t\t\tvar month = date.getMonth();\n
\t\t\tvar day = date.getDate();\n
\t\t\tvar pattern = /([+-]?[0-9]+)\\s*(d|D|w|W|m|M|y|Y)?/g;\n
\t\t\tvar matches = pattern.exec(offset);\n
\t\t\twhile (matches) {\n
\t\t\t\tswitch (matches[2] || \'d\') {\n
\t\t\t\t\tcase \'d\' : case \'D\' :\n
\t\t\t\t\t\tday += parseInt(matches[1],10); break;\n
\t\t\t\t\tcase \'w\' : case \'W\' :\n
\t\t\t\t\t\tday += parseInt(matches[1],10) * 7; break;\n
\t\t\t\t\tcase \'m\' : case \'M\' :\n
\t\t\t\t\t\tmonth += parseInt(matches[1],10);\n
\t\t\t\t\t\tday = Math.min(day, getDaysInMonth(year, month));\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase \'y\': case \'Y\' :\n
\t\t\t\t\t\tyear += parseInt(matches[1],10);\n
\t\t\t\t\t\tday = Math.min(day, getDaysInMonth(year, month));\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tmatches = pattern.exec(offset);\n
\t\t\t}\n
\t\t\treturn new Date(year, month, day);\n
\t\t};\n
\t\tdate = (date == null ? defaultDate :\n
\t\t\t(typeof date == \'string\' ? offsetString(date, this._getDaysInMonth) :\n
\t\t\t(typeof date == \'number\' ? (isNaN(date) ? defaultDate : offsetNumeric(date)) : date)));\n
\t\tdate = (date && date.toString() == \'Invalid Date\' ? defaultDate : date);\n
\t\tif (date) {\n
\t\t\tdate.setHours(0);\n
\t\t\tdate.setMinutes(0);\n
\t\t\tdate.setSeconds(0);\n
\t\t\tdate.setMilliseconds(0);\n
\t\t}\n
\t\treturn this._daylightSavingAdjust(date);\n
\t},\n
\n
\t/* Handle switch to/from daylight saving.\n
\t   Hours may be non-zero on daylight saving cut-over:\n
\t   > 12 when midnight changeover, but then cannot generate\n
\t   midnight datetime, so jump to 1AM, otherwise reset.\n
\t   @param  date  (Date) the date to check\n
\t   @return  (Date) the corrected date */\n
\t_daylightSavingAdjust: function(date) {\n
\t\tif (!date) return null;\n
\t\tdate.setHours(date.getHours() > 12 ? date.getHours() + 2 : 0);\n
\t\treturn date;\n
\t},\n
\n
\t/* Set the date(s) directly. */\n
\t_setDate: function(inst, date, endDate) {\n
\t\tvar clear = !(date);\n
\t\tvar origMonth = inst.selectedMonth;\n
\t\tvar origYear = inst.selectedYear;\n
\t\tdate = this._determineDate(date, new Date());\n
\t\tinst.selectedDay = inst.currentDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = inst.currentMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = inst.currentYear = date.getFullYear();\n
\t\tif (origMonth != inst.selectedMonth || origYear != inst.selectedYear)\n
\t\t\tthis._notifyChange(inst);\n
\t\tthis._adjustInstDate(inst);\n
\t\tif (inst.input) {\n
\t\t\tinst.input.val(clear ? \'\' : this._formatDate(inst));\n
\t\t}\n
\t},\n
\n
\t/* Retrieve the date(s) directly. */\n
\t_getDate: function(inst) {\n
\t\tvar startDate = (!inst.currentYear || (inst.input && inst.input.val() == \'\') ? null :\n
\t\t\tthis._daylightSavingAdjust(new Date(\n
\t\t\tinst.currentYear, inst.currentMonth, inst.currentDay)));\n
\t\t\treturn startDate;\n
\t},\n
\n
\t/* Generate the HTML for the current state of the date picker. */\n
\t_generateHTML: function(inst) {\n
\t\tvar today = new Date();\n
\t\ttoday = this._daylightSavingAdjust(\n
\t\t\tnew Date(today.getFullYear(), today.getMonth(), today.getDate())); // clear time\n
\t\tvar isRTL = this._get(inst, \'isRTL\');\n
\t\tvar showButtonPanel = this._get(inst, \'showButtonPanel\');\n
\t\tvar hideIfNoPrevNext = this._get(inst, \'hideIfNoPrevNext\');\n
\t\tvar navigationAsDateFormat = this._get(inst, \'navigationAsDateFormat\');\n
\t\tvar numMonths = this._getNumberOfMonths(inst);\n
\t\tvar showCurrentAtPos = this._get(inst, \'showCurrentAtPos\');\n
\t\tvar stepMonths = this._get(inst, \'stepMonths\');\n
\t\tvar stepBigMonths = this._get(inst, \'stepBigMonths\');\n
\t\tvar isMultiMonth = (numMonths[0] != 1 || numMonths[1] != 1);\n
\t\tvar currentDate = this._daylightSavingAdjust((!inst.currentDay ? new Date(9999, 9, 9) :\n
\t\t\tnew Date(inst.currentYear, inst.currentMonth, inst.currentDay)));\n
\t\tvar minDate = this._getMinMaxDate(inst, \'min\', true);\n
\t\tvar maxDate = this._getMinMaxDate(inst, \'max\');\n
\t\tvar drawMonth = inst.drawMonth - showCurrentAtPos;\n
\t\tvar drawYear = inst.drawYear;\n
\t\tif (drawMonth < 0) {\n
\t\t\tdrawMonth += 12;\n
\t\t\tdrawYear--;\n
\t\t}\n
\t\tif (maxDate) {\n
\t\t\tvar maxDraw = this._daylightSavingAdjust(new Date(maxDate.getFullYear(),\n
\t\t\t\tmaxDate.getMonth() - numMonths[1] + 1, maxDate.getDate()));\n
\t\t\tmaxDraw = (minDate && maxDraw < minDate ? minDate : maxDraw);\n
\t\t\twhile (this._daylightSavingAdjust(new Date(drawYear, drawMonth, 1)) > maxDraw) {\n
\t\t\t\tdrawMonth--;\n
\t\t\t\tif (drawMonth < 0) {\n
\t\t\t\t\tdrawMonth = 11;\n
\t\t\t\t\tdrawYear--;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tinst.drawMonth = drawMonth;\n
\t\tinst.drawYear = drawYear;\n
\t\tvar prevText = this._get(inst, \'prevText\');\n
\t\tprevText = (!navigationAsDateFormat ? prevText : this.formatDate(prevText,\n
\t\t\tthis._daylightSavingAdjust(new Date(drawYear, drawMonth - stepMonths, 1)),\n
\t\t\tthis._getFormatConfig(inst)));\n
\t\tvar prev = (this._canAdjustMonth(inst, -1, drawYear, drawMonth) ?\n
\t\t\t\'<a class="ui-datepicker-prev ui-corner-all" onclick="DP_jQuery.datepicker._adjustDate(\\\'#\' + inst.id + \'\\\', -\' + stepMonths + \', \\\'M\\\');"\' +\n
\t\t\t\' title="\' + prevText + \'"><span class="ui-icon ui-icon-circle-triangle-\' + ( isRTL ? \'e\' : \'w\') + \'">\' + prevText + \'</span></a>\' :\n
\t\t\t(hideIfNoPrevNext ? \'\' : \'<a class="ui-datepicke

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
      <tuple>
        <global name="Pdata" module="OFS.Image"/>
        <tuple/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

r-prev ui-corner-all ui-state-disabled" title="\'+ prevText +\'"><span class="ui-icon ui-icon-circle-triangle-\' + ( isRTL ? \'e\' : \'w\') + \'">\' + prevText + \'</span></a>\'));\n
\t\tvar nextText = this._get(inst, \'nextText\');\n
\t\tnextText = (!navigationAsDateFormat ? nextText : this.formatDate(nextText,\n
\t\t\tthis._daylightSavingAdjust(new Date(drawYear, drawMonth + stepMonths, 1)),\n
\t\t\tthis._getFormatConfig(inst)));\n
\t\tvar next = (this._canAdjustMonth(inst, +1, drawYear, drawMonth) ?\n
\t\t\t\'<a class="ui-datepicker-next ui-corner-all" onclick="DP_jQuery.datepicker._adjustDate(\\\'#\' + inst.id + \'\\\', +\' + stepMonths + \', \\\'M\\\');"\' +\n
\t\t\t\' title="\' + nextText + \'"><span class="ui-icon ui-icon-circle-triangle-\' + ( isRTL ? \'w\' : \'e\') + \'">\' + nextText + \'</span></a>\' :\n
\t\t\t(hideIfNoPrevNext ? \'\' : \'<a class="ui-datepicker-next ui-corner-all ui-state-disabled" title="\'+ nextText + \'"><span class="ui-icon ui-icon-circle-triangle-\' + ( isRTL ? \'w\' : \'e\') + \'">\' + nextText + \'</span></a>\'));\n
\t\tvar currentText = this._get(inst, \'currentText\');\n
\t\tvar gotoDate = (this._get(inst, \'gotoCurrent\') && inst.currentDay ? currentDate : today);\n
\t\tcurrentText = (!navigationAsDateFormat ? currentText :\n
\t\t\tthis.formatDate(currentText, gotoDate, this._getFormatConfig(inst)));\n
\t\tvar controls = (!inst.inline ? \'<button type="button" class="ui-datepicker-close ui-state-default ui-priority-primary ui-corner-all" onclick="DP_jQuery.datepicker._hideDatepicker();">\' + this._get(inst, \'closeText\') + \'</button>\' : \'\');\n
\t\tvar buttonPanel = (showButtonPanel) ? \'<div class="ui-datepicker-buttonpane ui-widget-content">\' + (isRTL ? controls : \'\') +\n
\t\t\t(this._isInRange(inst, gotoDate) ? \'<button type="button" class="ui-datepicker-current ui-state-default ui-priority-secondary ui-corner-all" onclick="DP_jQuery.datepicker._gotoToday(\\\'#\' + inst.id + \'\\\');"\' +\n
\t\t\t\'>\' + currentText + \'</button>\' : \'\') + (isRTL ? \'\' : controls) + \'</div>\' : \'\';\n
\t\tvar firstDay = parseInt(this._get(inst, \'firstDay\'),10);\n
\t\tfirstDay = (isNaN(firstDay) ? 0 : firstDay);\n
\t\tvar dayNames = this._get(inst, \'dayNames\');\n
\t\tvar dayNamesShort = this._get(inst, \'dayNamesShort\');\n
\t\tvar dayNamesMin = this._get(inst, \'dayNamesMin\');\n
\t\tvar monthNames = this._get(inst, \'monthNames\');\n
\t\tvar monthNamesShort = this._get(inst, \'monthNamesShort\');\n
\t\tvar beforeShowDay = this._get(inst, \'beforeShowDay\');\n
\t\tvar showOtherMonths = this._get(inst, \'showOtherMonths\');\n
\t\tvar calculateWeek = this._get(inst, \'calculateWeek\') || this.iso8601Week;\n
\t\tvar endDate = inst.endDay ? this._daylightSavingAdjust(\n
\t\t\tnew Date(inst.endYear, inst.endMonth, inst.endDay)) : currentDate;\n
\t\tvar defaultDate = this._getDefaultDate(inst);\n
\t\tvar html = \'\';\n
\t\tfor (var row = 0; row < numMonths[0]; row++) {\n
\t\t\tvar group = \'\';\n
\t\t\tfor (var col = 0; col < numMonths[1]; col++) {\n
\t\t\t\tvar selectedDate = this._daylightSavingAdjust(new Date(drawYear, drawMonth, inst.selectedDay));\n
\t\t\t\tvar cornerClass = \' ui-corner-all\';\n
\t\t\t\tvar calender = \'\';\n
\t\t\t\tif (isMultiMonth) {\n
\t\t\t\t\tcalender += \'<div class="ui-datepicker-group ui-datepicker-group-\';\n
\t\t\t\t\tswitch (col) {\n
\t\t\t\t\t\tcase 0: calender += \'first\'; cornerClass = \' ui-corner-\' + (isRTL ? \'right\' : \'left\'); break;\n
\t\t\t\t\t\tcase numMonths[1]-1: calender += \'last\'; cornerClass = \' ui-corner-\' + (isRTL ? \'left\' : \'right\'); break;\n
\t\t\t\t\t\tdefault: calender += \'middle\'; cornerClass = \'\'; break;\n
\t\t\t\t\t}\n
\t\t\t\t\tcalender += \'">\';\n
\t\t\t\t}\n
\t\t\t\tcalender += \'<div class="ui-datepicker-header ui-widget-header ui-helper-clearfix\' + cornerClass + \'">\' +\n
\t\t\t\t\t(/all|left/.test(cornerClass) && row == 0 ? (isRTL ? next : prev) : \'\') +\n
\t\t\t\t\t(/all|right/.test(cornerClass) && row == 0 ? (isRTL ? prev : next) : \'\') +\n
\t\t\t\t\tthis._generateMonthYearHeader(inst, drawMonth, drawYear, minDate, maxDate,\n
\t\t\t\t\tselectedDate, row > 0 || col > 0, monthNames, monthNamesShort) + // draw month headers\n
\t\t\t\t\t\'</div><table class="ui-datepicker-calendar"><thead>\' +\n
\t\t\t\t\t\'<tr>\';\n
\t\t\t\tvar thead = \'\';\n
\t\t\t\tfor (var dow = 0; dow < 7; dow++) { // days of the week\n
\t\t\t\t\tvar day = (dow + firstDay) % 7;\n
\t\t\t\t\tthead += \'<th\' + ((dow + firstDay + 6) % 7 >= 5 ? \' class="ui-datepicker-week-end"\' : \'\') + \'>\' +\n
\t\t\t\t\t\t\'<span title="\' + dayNames[day] + \'">\' + dayNamesMin[day] + \'</span></th>\';\n
\t\t\t\t}\n
\t\t\t\tcalender += thead + \'</tr></thead><tbody>\';\n
\t\t\t\tvar daysInMonth = this._getDaysInMonth(drawYear, drawMonth);\n
\t\t\t\tif (drawYear == inst.selectedYear && drawMonth == inst.selectedMonth)\n
\t\t\t\t\tinst.selectedDay = Math.min(inst.selectedDay, daysInMonth);\n
\t\t\t\tvar leadDays = (this._getFirstDayOfMonth(drawYear, drawMonth) - firstDay + 7) % 7;\n
\t\t\t\tvar numRows = (isMultiMonth ? 6 : Math.ceil((leadDays + daysInMonth) / 7)); // calculate the number of rows to generate\n
\t\t\t\tvar printDate = this._daylightSavingAdjust(new Date(drawYear, drawMonth, 1 - leadDays));\n
\t\t\t\tfor (var dRow = 0; dRow < numRows; dRow++) { // create date picker rows\n
\t\t\t\t\tcalender += \'<tr>\';\n
\t\t\t\t\tvar tbody = \'\';\n
\t\t\t\t\tfor (var dow = 0; dow < 7; dow++) { // create date picker days\n
\t\t\t\t\t\tvar daySettings = (beforeShowDay ?\n
\t\t\t\t\t\t\tbeforeShowDay.apply((inst.input ? inst.input[0] : null), [printDate]) : [true, \'\']);\n
\t\t\t\t\t\tvar otherMonth = (printDate.getMonth() != drawMonth);\n
\t\t\t\t\t\tvar unselectable = otherMonth || !daySettings[0] ||\n
\t\t\t\t\t\t\t(minDate && printDate < minDate) || (maxDate && printDate > maxDate);\n
\t\t\t\t\t\ttbody += \'<td class="\' +\n
\t\t\t\t\t\t\t((dow + firstDay + 6) % 7 >= 5 ? \' ui-datepicker-week-end\' : \'\') + // highlight weekends\n
\t\t\t\t\t\t\t(otherMonth ? \' ui-datepicker-other-month\' : \'\') + // highlight days from other months\n
\t\t\t\t\t\t\t((printDate.getTime() == selectedDate.getTime() && drawMonth == inst.selectedMonth && inst._keyEvent) || // user pressed key\n
\t\t\t\t\t\t\t(defaultDate.getTime() == printDate.getTime() && defaultDate.getTime() == selectedDate.getTime()) ?\n
\t\t\t\t\t\t\t// or defaultDate is current printedDate and defaultDate is selectedDate\n
\t\t\t\t\t\t\t\' \' + this._dayOverClass : \'\') + // highlight selected day\n
\t\t\t\t\t\t\t(unselectable ? \' \' + this._unselectableClass + \' ui-state-disabled\': \'\') +  // highlight unselectable days\n
\t\t\t\t\t\t\t(otherMonth && !showOtherMonths ? \'\' : \' \' + daySettings[1] + // highlight custom dates\n
\t\t\t\t\t\t\t(printDate.getTime() >= currentDate.getTime() && printDate.getTime() <= endDate.getTime() ? // in current range\n
\t\t\t\t\t\t\t\' \' + this._currentClass : \'\') + // highlight selected day\n
\t\t\t\t\t\t\t(printDate.getTime() == today.getTime() ? \' ui-datepicker-today\' : \'\')) + \'"\' + // highlight today (if different)\n
\t\t\t\t\t\t\t((!otherMonth || showOtherMonths) && daySettings[2] ? \' title="\' + daySettings[2] + \'"\' : \'\') + // cell title\n
\t\t\t\t\t\t\t(unselectable ? \'\' : \' onclick="DP_jQuery.datepicker._selectDay(\\\'#\' +\n
\t\t\t\t\t\t\tinst.id + \'\\\',\' + drawMonth + \',\' + drawYear + \', this);return false;"\') + \'>\' + // actions\n
\t\t\t\t\t\t\t(otherMonth ? (showOtherMonths ? printDate.getDate() : \'&#xa0;\') : // display for other months\n
\t\t\t\t\t\t\t(unselectable ? \'<span class="ui-state-default">\' + printDate.getDate() + \'</span>\' : \'<a class="ui-state-default\' +\n
\t\t\t\t\t\t\t(printDate.getTime() == today.getTime() ? \' ui-state-highlight\' : \'\') +\n
\t\t\t\t\t\t\t(printDate.getTime() >= currentDate.getTime() && printDate.getTime() <= endDate.getTime() ? // in current range\n
\t\t\t\t\t\t\t\' ui-state-active\' : \'\') + // highlight selected day\n
\t\t\t\t\t\t\t\'" href="#">\' + printDate.getDate() + \'</a>\')) + \'</td>\'; // display for this month\n
\t\t\t\t\t\tprintDate.setDate(printDate.getDate() + 1);\n
\t\t\t\t\t\tprintDate = this._daylightSavingAdjust(printDate);\n
\t\t\t\t\t}\n
\t\t\t\t\tcalender += tbody + \'</tr>\';\n
\t\t\t\t}\n
\t\t\t\tdrawMonth++;\n
\t\t\t\tif (drawMonth > 11) {\n
\t\t\t\t\tdrawMonth = 0;\n
\t\t\t\t\tdrawYear++;\n
\t\t\t\t}\n
\t\t\t\tcalender += \'</tbody></table>\' + (isMultiMonth ? \'</div>\' + \n
\t\t\t\t\t\t\t((numMonths[0] > 0 && col == numMonths[1]-1) ? \'<div class="ui-datepicker-row-break"></div>\' : \'\') : \'\');\n
\t\t\t\tgroup += calender;\n
\t\t\t}\n
\t\t\thtml += group;\n
\t\t}\n
\t\thtml += buttonPanel + ($.browser.msie && parseInt($.browser.version,10) < 7 && !inst.inline ?\n
\t\t\t\'<iframe src="javascript:false;" class="ui-datepicker-cover" frameborder="0"></iframe>\' : \'\');\n
\t\tinst._keyEvent = false;\n
\t\treturn html;\n
\t},\n
\n
\t/* Generate the month and year header. */\n
\t_generateMonthYearHeader: function(inst, drawMonth, drawYear, minDate, maxDate,\n
\t\t\tselectedDate, secondary, monthNames, monthNamesShort) {\n
\t\tminDate = (inst.rangeStart && minDate && selectedDate < minDate ? selectedDate : minDate);\n
\t\tvar changeMonth = this._get(inst, \'changeMonth\');\n
\t\tvar changeYear = this._get(inst, \'changeYear\');\n
\t\tvar showMonthAfterYear = this._get(inst, \'showMonthAfterYear\');\n
\t\tvar html = \'<div class="ui-datepicker-title">\';\n
\t\tvar monthHtml = \'\';\n
\t\t// month selection\n
\t\tif (secondary || !changeMonth)\n
\t\t\tmonthHtml += \'<span class="ui-datepicker-month">\' + monthNames[drawMonth] + \'</span> \';\n
\t\telse {\n
\t\t\tvar inMinYear = (minDate && minDate.getFullYear() == drawYear);\n
\t\t\tvar inMaxYear = (maxDate && maxDate.getFullYear() == drawYear);\n
\t\t\tmonthHtml += \'<select class="ui-datepicker-month" \' +\n
\t\t\t\t\'onchange="DP_jQuery.datepicker._selectMonthYear(\\\'#\' + inst.id + \'\\\', this, \\\'M\\\');" \' +\n
\t\t\t\t\'onclick="DP_jQuery.datepicker._clickMonthYear(\\\'#\' + inst.id + \'\\\');"\' +\n
\t\t\t \t\'>\';\n
\t\t\tfor (var month = 0; month < 12; month++) {\n
\t\t\t\tif ((!inMinYear || month >= minDate.getMonth()) &&\n
\t\t\t\t\t\t(!inMaxYear || month <= maxDate.getMonth()))\n
\t\t\t\t\tmonthHtml += \'<option value="\' + month + \'"\' +\n
\t\t\t\t\t\t(month == drawMonth ? \' selected="selected"\' : \'\') +\n
\t\t\t\t\t\t\'>\' + monthNamesShort[month] + \'</option>\';\n
\t\t\t}\n
\t\t\tmonthHtml += \'</select>\';\n
\t\t}\n
\t\tif (!showMonthAfterYear)\n
\t\t\thtml += monthHtml + ((secondary || changeMonth || changeYear) && (!(changeMonth && changeYear)) ? \'&#xa0;\' : \'\');\n
\t\t// year selection\n
\t\tif (secondary || !changeYear)\n
\t\t\thtml += \'<span class="ui-datepicker-year">\' + drawYear + \'</span>\';\n
\t\telse {\n
\t\t\t// determine range of years to display\n
\t\t\tvar years = this._get(inst, \'yearRange\').split(\':\');\n
\t\t\tvar year = 0;\n
\t\t\tvar endYear = 0;\n
\t\t\tif (years.length != 2) {\n
\t\t\t\tyear = drawYear - 10;\n
\t\t\t\tendYear = drawYear + 10;\n
\t\t\t} else if (years[0].charAt(0) == \'+\' || years[0].charAt(0) == \'-\') {\n
\t\t\t\tyear = drawYear + parseInt(years[0], 10);\n
\t\t\t\tendYear = drawYear + parseInt(years[1], 10);\n
\t\t\t} else {\n
\t\t\t\tyear = parseInt(years[0], 10);\n
\t\t\t\tendYear = parseInt(years[1], 10);\n
\t\t\t}\n
\t\t\tyear = (minDate ? Math.max(year, minDate.getFullYear()) : year);\n
\t\t\tendYear = (maxDate ? Math.min(endYear, maxDate.getFullYear()) : endYear);\n
\t\t\thtml += \'<select class="ui-datepicker-year" \' +\n
\t\t\t\t\'onchange="DP_jQuery.datepicker._selectMonthYear(\\\'#\' + inst.id + \'\\\', this, \\\'Y\\\');" \' +\n
\t\t\t\t\'onclick="DP_jQuery.datepicker._clickMonthYear(\\\'#\' + inst.id + \'\\\');"\' +\n
\t\t\t\t\'>\';\n
\t\t\tfor (; year <= endYear; year++) {\n
\t\t\t\thtml += \'<option value="\' + year + \'"\' +\n
\t\t\t\t\t(year == drawYear ? \' selected="selected"\' : \'\') +\n
\t\t\t\t\t\'>\' + year + \'</option>\';\n
\t\t\t}\n
\t\t\thtml += \'</select>\';\n
\t\t}\n
\t\tif (showMonthAfterYear)\n
\t\t\thtml += (secondary || changeMonth || changeYear ? \'&#xa0;\' : \'\') + monthHtml;\n
\t\thtml += \'</div>\'; // Close datepicker_header\n
\t\treturn html;\n
\t},\n
\n
\t/* Adjust one of the date sub-fields. */\n
\t_adjustInstDate: function(inst, offset, period) {\n
\t\tvar year = inst.drawYear + (period == \'Y\' ? offset : 0);\n
\t\tvar month = inst.drawMonth + (period == \'M\' ? offset : 0);\n
\t\tvar day = Math.min(inst.selectedDay, this._getDaysInMonth(year, month)) +\n
\t\t\t(period == \'D\' ? offset : 0);\n
\t\tvar date = this._daylightSavingAdjust(new Date(year, month, day));\n
\t\t// ensure it is within the bounds set\n
\t\tvar minDate = this._getMinMaxDate(inst, \'min\', true);\n
\t\tvar maxDate = this._getMinMaxDate(inst, \'max\');\n
\t\tdate = (minDate && date < minDate ? minDate : date);\n
\t\tdate = (maxDate && date > maxDate ? maxDate : date);\n
\t\tinst.selectedDay = date.getDate();\n
\t\tinst.drawMonth = inst.selectedMonth = date.getMonth();\n
\t\tinst.drawYear = inst.selectedYear = date.getFullYear();\n
\t\tif (period == \'M\' || period == \'Y\')\n
\t\t\tthis._notifyChange(inst);\n
\t},\n
\n
\t/* Notify change of month/year. */\n
\t_notifyChange: function(inst) {\n
\t\tvar onChange = this._get(inst, \'onChangeMonthYear\');\n
\t\tif (onChange)\n
\t\t\tonChange.apply((inst.input ? inst.input[0] : null),\n
\t\t\t\t[inst.selectedYear, inst.selectedMonth + 1, inst]);\n
\t},\n
\n
\t/* Determine the number of months to show. */\n
\t_getNumberOfMonths: function(inst) {\n
\t\tvar numMonths = this._get(inst, \'numberOfMonths\');\n
\t\treturn (numMonths == null ? [1, 1] : (typeof numMonths == \'number\' ? [1, numMonths] : numMonths));\n
\t},\n
\n
\t/* Determine the current maximum date - ensure no time components are set - may be overridden for a range. */\n
\t_getMinMaxDate: function(inst, minMax, checkRange) {\n
\t\tvar date = this._determineDate(this._get(inst, minMax + \'Date\'), null);\n
\t\treturn (!checkRange || !inst.rangeStart ? date :\n
\t\t\t(!date || inst.rangeStart > date ? inst.rangeStart : date));\n
\t},\n
\n
\t/* Find the number of days in a given month. */\n
\t_getDaysInMonth: function(year, month) {\n
\t\treturn 32 - new Date(year, month, 32).getDate();\n
\t},\n
\n
\t/* Find the day of the week of the first of a month. */\n
\t_getFirstDayOfMonth: function(year, month) {\n
\t\treturn new Date(year, month, 1).getDay();\n
\t},\n
\n
\t/* Determines if we should allow a "next/prev" month display change. */\n
\t_canAdjustMonth: function(inst, offset, curYear, curMonth) {\n
\t\tvar numMonths = this._getNumberOfMonths(inst);\n
\t\tvar date = this._daylightSavingAdjust(new Date(\n
\t\t\tcurYear, curMonth + (offset < 0 ? offset : numMonths[1]), 1));\n
\t\tif (offset < 0)\n
\t\t\tdate.setDate(this._getDaysInMonth(date.getFullYear(), date.getMonth()));\n
\t\treturn this._isInRange(inst, date);\n
\t},\n
\n
\t/* Is the given date in the accepted range? */\n
\t_isInRange: function(inst, date) {\n
\t\t// during range selection, use minimum of selected date and range start\n
\t\tvar newMinDate = (!inst.rangeStart ? null : this._daylightSavingAdjust(\n
\t\t\tnew Date(inst.selectedYear, inst.selectedMonth, inst.selectedDay)));\n
\t\tnewMinDate = (newMinDate && inst.rangeStart < newMinDate ? inst.rangeStart : newMinDate);\n
\t\tvar minDate = newMinDate || this._getMinMaxDate(inst, \'min\');\n
\t\tvar maxDate = this._getMinMaxDate(inst, \'max\');\n
\t\treturn ((!minDate || date >= minDate) && (!maxDate || date <= maxDate));\n
\t},\n
\n
\t/* Provide the configuration settings for formatting/parsing. */\n
\t_getFormatConfig: function(inst) {\n
\t\tvar shortYearCutoff = this._get(inst, \'shortYearCutoff\');\n
\t\tshortYearCutoff = (typeof shortYearCutoff != \'string\' ? shortYearCutoff :\n
\t\t\tnew Date().getFullYear() % 100 + parseInt(shortYearCutoff, 10));\n
\t\treturn {shortYearCutoff: shortYearCutoff,\n
\t\t\tdayNamesShort: this._get(inst, \'dayNamesShort\'), dayNames: this._get(inst, \'dayNames\'),\n
\t\t\tmonthNamesShort: this._get(inst, \'monthNamesShort\'), monthNames: this._get(inst, \'monthNames\')};\n
\t},\n
\n
\t/* Format the given date for display. */\n
\t_formatDate: function(inst, day, month, year) {\n
\t\tif (!day) {\n
\t\t\tinst.currentDay = inst.selectedDay;\n
\t\t\tinst.currentMonth = inst.selectedMonth;\n
\t\t\tinst.currentYear = inst.selectedYear;\n
\t\t}\n
\t\tvar date = (day ? (typeof day == \'object\' ? day :\n
\t\t\tthis._daylightSavingAdjust(new Date(year, month, day))) :\n
\t\t\tthis._daylightSavingAdjust(new Date(inst.currentYear, inst.currentMonth, inst.currentDay)));\n
\t\treturn this.formatDate(this._get(inst, \'dateFormat\'), date, this._getFormatConfig(inst));\n
\t}\n
});\n
\n
/* jQuery extend now ignores nulls! */\n
function extendRemove(target, props) {\n
\t$.extend(target, props);\n
\tfor (var name in props)\n
\t\tif (props[name] == null || props[name] == undefined)\n
\t\t\ttarget[name] = props[name];\n
\treturn target;\n
};\n
\n
/* Determine whether an object is an array. */\n
function isArray(a) {\n
\treturn (a && (($.browser.safari && typeof a == \'object\' && a.length) ||\n
\t\t(a.constructor && a.constructor.toString().match(/\\Array\\(\\)/))));\n
};\n
\n
/* Invoke the datepicker functionality.\n
   @param  options  string - a command, optionally followed by additional parameters or\n
                    Object - settings for attaching new datepicker functionality\n
   @return  jQuery object */\n
$.fn.datepicker = function(options){\n
\n
\t/* Initialise the date picker. */\n
\tif (!$.datepicker.initialized) {\n
\t\t$(document).mousedown($.datepicker._checkExternalClick).\n
\t\t\tfind(\'body\').append($.datepicker.dpDiv);\n
\t\t$.datepicker.initialized = true;\n
\t}\n
\n
\tvar otherArgs = Array.prototype.slice.call(arguments, 1);\n
\tif (typeof options == \'string\' && (options == \'isDisabled\' || options == \'getDate\'))\n
\t\treturn $.datepicker[\'_\' + options + \'Datepicker\'].\n
\t\t\tapply($.datepicker, [this[0]].concat(otherArgs));\n
\tif (options == \'option\' && arguments.length == 2 && typeof arguments[1] == \'string\')\n
\t\treturn $.datepicker[\'_\' + options + \'Datepicker\'].\n
\t\t\tapply($.datepicker, [this[0]].concat(otherArgs));\n
\treturn this.each(function() {\n
\t\ttypeof options == \'string\' ?\n
\t\t\t$.datepicker[\'_\' + options + \'Datepicker\'].\n
\t\t\t\tapply($.datepicker, [this].concat(otherArgs)) :\n
\t\t\t$.datepicker._attachDatepicker(this, options);\n
\t});\n
};\n
\n
$.datepicker = new Datepicker(); // singleton instance\n
$.datepicker.initialized = false;\n
$.datepicker.uuid = new Date().getTime();\n
$.datepicker.version = "1.7.2";\n
\n
// Workaround for #4055\n
// Add another global to avoid noConflict issues with inline event handlers\n
window.DP_jQuery = $;\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Progressbar 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Progressbar\n
 *\n
 * Depends:\n
 *   ui.core.js\n
 */\n
(function($) {\n
\n
$.widget("ui.progressbar", {\n
\n
\t_init: function() {\n
\n
\t\tthis.element\n
\t\t\t.addClass("ui-progressbar"\n
\t\t\t\t+ " ui-widget"\n
\t\t\t\t+ " ui-widget-content"\n
\t\t\t\t+ " ui-corner-all")\n
\t\t\t.attr({\n
\t\t\t\trole: "progressbar",\n
\t\t\t\t"aria-valuemin": this._valueMin(),\n
\t\t\t\t"aria-valuemax": this._valueMax(),\n
\t\t\t\t"aria-valuenow": this._value()\n
\t\t\t});\n
\n
\t\tthis.valueDiv = $(\'<div class="ui-progressbar-value ui-widget-header ui-corner-left"></div>\').appendTo(this.element);\n
\n
\t\tthis._refreshValue();\n
\n
\t},\n
\n
\tdestroy: function() {\n
\n
\t\tthis.element\n
\t\t\t.removeClass("ui-progressbar"\n
\t\t\t\t+ " ui-widget"\n
\t\t\t\t+ " ui-widget-content"\n
\t\t\t\t+ " ui-corner-all")\n
\t\t\t.removeAttr("role")\n
\t\t\t.removeAttr("aria-valuemin")\n
\t\t\t.removeAttr("aria-valuemax")\n
\t\t\t.removeAttr("aria-valuenow")\n
\t\t\t.removeData("progressbar")\n
\t\t\t.unbind(".progressbar");\n
\n
\t\tthis.valueDiv.remove();\n
\n
\t\t$.widget.prototype.destroy.apply(this, arguments);\n
\n
\t},\n
\n
\tvalue: function(newValue) {\n
\t\tif (newValue === undefined) {\n
\t\t\treturn this._value();\n
\t\t}\n
\t\t\n
\t\tthis._setData(\'value\', newValue);\n
\t\treturn this;\n
\t},\n
\n
\t_setData: function(key, value) {\n
\n
\t\tswitch (key) {\n
\t\t\tcase \'value\':\n
\t\t\t\tthis.options.value = value;\n
\t\t\t\tthis._refreshValue();\n
\t\t\t\tthis._trigger(\'change\', null, {});\n
\t\t\t\tbreak;\n
\t\t}\n
\n
\t\t$.widget.prototype._setData.apply(this, arguments);\n
\n
\t},\n
\n
\t_value: function() {\n
\n
\t\tvar val = this.options.value;\n
\t\tif (val < this._valueMin()) val = this._valueMin();\n
\t\tif (val > this._valueMax()) val = this._valueMax();\n
\n
\t\treturn val;\n
\n
\t},\n
\n
\t_valueMin: function() {\n
\t\tvar valueMin = 0;\n
\t\treturn valueMin;\n
\t},\n
\n
\t_valueMax: function() {\n
\t\tvar valueMax = 100;\n
\t\treturn valueMax;\n
\t},\n
\n
\t_refreshValue: function() {\n
\t\tvar value = this.value();\n
\t\tthis.valueDiv[value == this._valueMax() ? \'addClass\' : \'removeClass\']("ui-corner-right");\n
\t\tthis.valueDiv.width(value + \'%\');\n
\t\tthis.element.attr("aria-valuenow", value);\n
\t}\n
\n
});\n
\n
$.extend($.ui.progressbar, {\n
\tversion: "1.7.2",\n
\tdefaults: {\n
\t\tvalue: 0\n
\t}\n
});\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/\n
 */\n
;jQuery.effects || (function($) {\n
\n
$.effects = {\n
\tversion: "1.7.2",\n
\n
\t// Saves a set of properties in a data storage\n
\tsave: function(element, set) {\n
\t\tfor(var i=0; i < set.length; i++) {\n
\t\t\tif(set[i] !== null) element.data("ec.storage."+set[i], element[0].style[set[i]]);\n
\t\t}\n
\t},\n
\n
\t// Restores a set of previously saved properties from a data storage\n
\trestore: function(element, set) {\n
\t\tfor(var i=0; i < set.length; i++) {\n
\t\t\tif(set[i] !== null) element.css(set[i], element.data("ec.storage."+set[i]));\n
\t\t}\n
\t},\n
\n
\tsetMode: function(el, mode) {\n
\t\tif (mode == \'toggle\') mode = el.is(\':hidden\') ? \'show\' : \'hide\'; // Set for toggle\n
\t\treturn mode;\n
\t},\n
\n
\tgetBaseline: function(origin, original) { // Translates a [top,left] array into a baseline value\n
\t\t// this should be a little more flexible in the future to handle a string & hash\n
\t\tvar y, x;\n
\t\tswitch (origin[0]) {\n
\t\t\tcase \'top\': y = 0; break;\n
\t\t\tcase \'middle\': y = 0.5; break;\n
\t\t\tcase \'bottom\': y = 1; break;\n
\t\t\tdefault: y = origin[0] / original.height;\n
\t\t};\n
\t\tswitch (origin[1]) {\n
\t\t\tcase \'left\': x = 0; break;\n
\t\t\tcase \'center\': x = 0.5; break;\n
\t\t\tcase \'right\': x = 1; break;\n
\t\t\tdefault: x = origin[1] / original.width;\n
\t\t};\n
\t\treturn {x: x, y: y};\n
\t},\n
\n
\t// Wraps the element around a wrapper that copies position properties\n
\tcreateWrapper: function(element) {\n
\n
\t\t//if the element is already wrapped, return it\n
\t\tif (element.parent().is(\'.ui-effects-wrapper\'))\n
\t\t\treturn element.parent();\n
\n
\t\t//Cache width,height and float properties of the element, and create a wrapper around it\n
\t\tvar props = { width: element.outerWidth(true), height: element.outerHeight(true), \'float\': element.css(\'float\') };\n
\t\telement.wrap(\'<div class="ui-effects-wrapper" style="font-size:100%;background:transparent;border:none;margin:0;padding:0"></div>\');\n
\t\tvar wrapper = element.parent();\n
\n
\t\t//Transfer the positioning of the element to the wrapper\n
\t\tif (element.css(\'position\') == \'static\') {\n
\t\t\twrapper.css({ position: \'relative\' });\n
\t\t\telement.css({ position: \'relative\'} );\n
\t\t} else {\n
\t\t\tvar top = element.css(\'top\'); if(isNaN(parseInt(top,10))) top = \'auto\';\n
\t\t\tvar left = element.css(\'left\'); if(isNaN(parseInt(left,10))) left = \'auto\';\n
\t\t\twrapper.css({ position: element.css(\'position\'), top: top, left: left, zIndex: element.css(\'z-index\') }).show();\n
\t\t\telement.css({position: \'relative\', top: 0, left: 0 });\n
\t\t}\n
\n
\t\twrapper.css(props);\n
\t\treturn wrapper;\n
\t},\n
\n
\tremoveWrapper: function(element) {\n
\t\tif (element.parent().is(\'.ui-effects-wrapper\'))\n
\t\t\treturn element.parent().replaceWith(element);\n
\t\treturn element;\n
\t},\n
\n
\tsetTransition: function(element, list, factor, value) {\n
\t\tvalue = value || {};\n
\t\t$.each(list, function(i, x){\n
\t\t\tunit = element.cssUnit(x);\n
\t\t\tif (unit[0] > 0) value[x] = unit[0] * factor + unit[1];\n
\t\t});\n
\t\treturn value;\n
\t},\n
\n
\t//Base function to animate from one class to another in a seamless transition\n
\tanimateClass: function(value, duration, easing, callback) {\n
\n
\t\tvar cb = (typeof easing == "function" ? easing : (callback ? callback : null));\n
\t\tvar ea = (typeof easing == "string" ? easing : null);\n
\n
\t\treturn this.each(function() {\n
\n
\t\t\tvar offset = {}; var that = $(this); var oldStyleAttr = that.attr("style") || \'\';\n
\t\t\tif(typeof oldStyleAttr == \'object\') oldStyleAttr = oldStyleAttr["cssText"]; /* Stupidly in IE, style is a object.. */\n
\t\t\tif(value.toggle) { that.hasClass(value.toggle) ? value.remove = value.toggle : value.add = value.toggle; }\n
\n
\t\t\t//Let\'s get a style offset\n
\t\t\tvar oldStyle = $.extend({}, (document.defaultView ? document.defaultView.getComputedStyle(this,null) : this.currentStyle));\n
\t\t\tif(value.add) that.addClass(value.add); if(value.remove) that.removeClass(value.remove);\n
\t\t\tvar newStyle = $.extend({}, (document.defaultView ? document.defaultView.getComputedStyle(this,null) : this.currentStyle));\n
\t\t\tif(value.add) that.removeClass(value.add); if(value.remove) that.addClass(value.remove);\n
\n
\t\t\t// The main function to form the object for animation\n
\t\t\tfor(var n in newStyle) {\n
\t\t\t\tif( typeof newStyle[n] != "function" && newStyle[n] /* No functions and null properties */\n
\t\t\t\t&& n.indexOf("Moz") == -1 && n.indexOf("length") == -1 /* No mozilla spezific render properties. */\n
\t\t\t\t&& newStyle[n] != oldStyle[n] /* Only values that have changed are used for the animation */\n
\t\t\t\t&& (n.match(/color/i) || (!n.match(/color/i) && !isNaN(parseInt(newStyle[n],10)))) /* Only things that can be parsed to integers or colors */\n
\t\t\t\t&& (oldStyle.position != "static" || (oldStyle.position == "static" && !n.match(/left|top|bottom|right/))) /* No need for positions when dealing with static positions */\n
\t\t\t\t) offset[n] = newStyle[n];\n
\t\t\t}\n
\n
\t\t\tthat.animate(offset, duration, ea, function() { // Animate the newly constructed offset object\n
\t\t\t\t// Change style attribute back to original. For stupid IE, we need to clear the damn object.\n
\t\t\t\tif(typeof $(this).attr("style") == \'object\') { $(this).attr("style")["cssText"] = ""; $(this).attr("style")["cssText"] = oldStyleAttr; } else $(this).attr("style", oldStyleAttr);\n
\t\t\t\tif(value.add) $(this).addClass(value.add); if(value.remove) $(this).removeClass(value.remove);\n
\t\t\t\tif(cb) cb.apply(this, arguments);\n
\t\t\t});\n
\n
\t\t});\n
\t}\n
};\n
\n
\n
function _normalizeArguments(a, m) {\n
\n
\tvar o = a[1] && a[1].constructor == Object ? a[1] : {}; if(m) o.mode = m;\n
\tvar speed = a[1] && a[1].constructor != Object ? a[1] : (o.duration ? o.duration : a[2]); //either comes from options.duration or the secon/third argument\n
\t\tspeed = $.fx.off ? 0 : typeof speed === "number" ? speed : $.fx.speeds[speed] || $.fx.speeds._default;\n
\tvar callback = o.callback || ( $.isFunction(a[1]) && a[1] ) || ( $.isFunction(a[2]) && a[2] ) || ( $.isFunction(a[3]) && a[3] );\n
\n
\treturn [a[0], o, speed, callback];\n
\t\n
}\n
\n
//Extend the methods of jQuery\n
$.fn.extend({\n
\n
\t//Save old methods\n
\t_show: $.fn.show,\n
\t_hide: $.fn.hide,\n
\t__toggle: $.fn.toggle,\n
\t_addClass: $.fn.addClass,\n
\t_removeClass: $.fn.removeClass,\n
\t_toggleClass: $.fn.toggleClass,\n
\n
\t// New effect methods\n
\teffect: function(fx, options, speed, callback) {\n
\t\treturn $.effects[fx] ? $.effects[fx].call(this, {method: fx, options: options || {}, duration: speed, callback: callback }) : null;\n
\t},\n
\n
\tshow: function() {\n
\t\tif(!arguments[0] || (arguments[0].constructor == Number || (/(slow|normal|fast)/).test(arguments[0])))\n
\t\t\treturn this._show.apply(this, arguments);\n
\t\telse {\n
\t\t\treturn this.effect.apply(this, _normalizeArguments(arguments, \'show\'));\n
\t\t}\n
\t},\n
\n
\thide: function() {\n
\t\tif(!arguments[0] || (arguments[0].constructor == Number || (/(slow|normal|fast)/).test(arguments[0])))\n
\t\t\treturn this._hide.apply(this, arguments);\n
\t\telse {\n
\t\t\treturn this.effect.apply(this, _normalizeArguments(arguments, \'hide\'));\n
\t\t}\n
\t},\n
\n
\ttoggle: function(){\n
\t\tif(!arguments[0] ||\n
\t\t\t(arguments[0].constructor == Number || (/(slow|normal|fast)/).test(arguments[0])) ||\n
\t\t\t($.isFunction(arguments[0]) || typeof arguments[0] == \'boolean\')) {\n
\t\t\treturn this.__toggle.apply(this, arguments);\n
\t\t} else {\n
\t\t\treturn this.effect.apply(this, _normalizeArguments(arguments, \'toggle\'));\n
\t\t}\n
\t},\n
\n
\taddClass: function(classNames, speed, easing, callback) {\n
\t\treturn speed ? $.effects.animateClass.apply(this, [{ add: classNames },speed,easing,callback]) : this._addClass(classNames);\n
\t},\n
\tremoveClass: function(classNames,speed,easing,callback) {\n
\t\treturn speed ? $.effects.animateClass.apply(this, [{ remove: classNames },speed,easing,callback]) : this._removeClass(classNames);\n
\t},\n
\ttoggleClass: function(classNames,speed,easing,callback) {\n
\t\treturn ( (typeof speed !== "boolean") && speed ) ? $.effects.animateClass.apply(this, [{ toggle: classNames },speed,easing,callback]) : this._toggleClass(classNames, speed);\n
\t},\n
\tmorph: function(remove,add,speed,easing,callback) {\n
\t\treturn $.effects.animateClass.apply(this, [{ add: add, remove: remove },speed,easing,callback]);\n
\t},\n
\tswitchClass: function() {\n
\t\treturn this.morph.apply(this, arguments);\n
\t},\n
\n
\t// helper functions\n
\tcssUnit: function(key) {\n
\t\tvar style = this.css(key), val = [];\n
\t\t$.each( [\'em\',\'px\',\'%\',\'pt\'], function(i, unit){\n
\t\t\tif(style.indexOf(unit) > 0)\n
\t\t\t\tval = [parseFloat(style), unit];\n
\t\t});\n
\t\treturn val;\n
\t}\n
});\n
\n
/*\n
 * jQuery Color Animations\n
 * Copyright 2007 John Resig\n
 * Released under the MIT and GPL licenses.\n
 */\n
\n
// We override the animation for all of these color styles\n
$.each([\'backgroundColor\', \'borderBottomColor\', \'borderLeftColor\', \'borderRightColor\', \'borderTopColor\', \'color\', \'outlineColor\'], function(i,attr){\n
\t\t$.fx.step[attr] = function(fx) {\n
\t\t\t\tif ( fx.state == 0 ) {\n
\t\t\t\t\t\tfx.start = getColor( fx.elem, attr );\n
\t\t\t\t\t\tfx.end = getRGB( fx.end );\n
\t\t\t\t}\n
\n
\t\t\t\tfx.elem.style[attr] = "rgb(" + [\n
\t\t\t\t\t\tMath.max(Math.min( parseInt((fx.pos * (fx.end[0] - fx.start[0])) + fx.start[0],10), 255), 0),\n
\t\t\t\t\t\tMath.max(Math.min( parseInt((fx.pos * (fx.end[1] - fx.start[1])) + fx.start[1],10), 255), 0),\n
\t\t\t\t\t\tMath.max(Math.min( parseInt((fx.pos * (fx.end[2] - fx.start[2])) + fx.start[2],10), 255), 0)\n
\t\t\t\t].join(",") + ")";\n
\t\t\t};\n
});\n
\n
// Color Conversion functions from highlightFade\n
// By Blair Mitchelmore\n
// http://jquery.offput.ca/highlightFade/\n
\n
// Parse strings looking for color tuples [255,255,255]\n
function getRGB(color) {\n
\t\tvar result;\n
\n
\t\t// Check if we\'re already dealing with an array of colors\n
\t\tif ( color && color.constructor == Array && color.length == 3 )\n
\t\t\t\treturn color;\n
\n
\t\t// Look for rgb(num,num,num)\n
\t\tif (result = /rgb\\(\\s*([0-9]{1,3})\\s*,\\s*([0-9]{1,3})\\s*,\\s*([0-9]{1,3})\\s*\\)/.exec(color))\n
\t\t\t\treturn [parseInt(result[1],10), parseInt(result[2],10), parseInt(result[3],10)];\n
\n
\t\t// Look for rgb(num%,num%,num%)\n
\t\tif (result = /rgb\\(\\s*([0-9]+(?:\\.[0-9]+)?)\\%\\s*,\\s*([0-9]+(?:\\.[0-9]+)?)\\%\\s*,\\s*([0-9]+(?:\\.[0-9]+)?)\\%\\s*\\)/.exec(color))\n
\t\t\t\treturn [parseFloat(result[1])*2.55, parseFloat(result[2])*2.55, parseFloat(result[3])*2.55];\n
\n
\t\t// Look for #a0b1c2\n
\t\tif (result = /#([a-fA-F0-9]{2})([a-fA-F0-9]{2})([a-fA-F0-9]{2})/.exec(color))\n
\t\t\t\treturn [parseInt(result[1],16), parseInt(result[2],16), parseInt(result[3],16)];\n
\n
\t\t// Look for #fff\n
\t\tif (result = /#([a-fA-F0-9])([a-fA-F0-9])([a-fA-F0-9])/.exec(color))\n
\t\t\t\treturn [parseInt(result[1]+result[1],16), parseInt(result[2]+result[2],16), parseInt(result[3]+result[3],16)];\n
\n
\t\t// Look for rgba(0, 0, 0, 0) == transparent in Safari 3\n
\t\tif (result = /rgba\\(0, 0, 0, 0\\)/.exec(color))\n
\t\t\t\treturn colors[\'transparent\'];\n
\n
\t\t// Otherwise, we\'re most likely dealing with a named color\n
\t\treturn colors[$.trim(color).toLowerCase()];\n
}\n
\n
function getColor(elem, attr) {\n
\t\tvar color;\n
\n
\t\tdo {\n
\t\t\t\tcolor = $.curCSS(elem, attr);\n
\n
\t\t\t\t// Keep going until we find an element that has color, or we hit the body\n
\t\t\t\tif ( color != \'\' && color != \'transparent\' || $.nodeName(elem, "body") )\n
\t\t\t\t\t\tbreak;\n
\n
\t\t\t\tattr = "backgroundColor";\n
\t\t} while ( elem = elem.parentNode );\n
\n
\t\treturn getRGB(color);\n
};\n
\n
// Some named colors to work with\n
// From Interface by Stefan Petre\n
// http://interface.eyecon.ro/\n
\n
var colors = {\n
\taqua:[0,255,255],\n
\tazure:[240,255,255],\n
\tbeige:[245,245,220],\n
\tblack:[0,0,0],\n
\tblue:[0,0,255],\n
\tbrown:[165,42,42],\n
\tcyan:[0,255,255],\n
\tdarkblue:[0,0,139],\n
\tdarkcyan:[0,139,139],\n
\tdarkgrey:[169,169,169],\n
\tdarkgreen:[0,100,0],\n
\tdarkkhaki:[189,183,107],\n
\tdarkmagenta:[139,0,139],\n
\tdarkolivegreen:[85,107,47],\n
\tdarkorange:[255,140,0],\n
\tdarkorchid:[153,50,204],\n
\tdarkred:[139,0,0],\n
\tdarksalmon:[233,150,122],\n
\tdarkviolet:[148,0,211],\n
\tfuchsia:[255,0,255],\n
\tgold:[255,215,0],\n
\tgreen:[0,128,0],\n
\tindigo:[75,0,130],\n
\tkhaki:[240,230,140],\n
\tlightblue:[173,216,230],\n
\tlightcyan:[224,255,255],\n
\tlightgreen:[144,238,144],\n
\tlightgrey:[211,211,211],\n
\tlightpink:[255,182,193],\n
\tlightyellow:[255,255,224],\n
\tlime:[0,255,0],\n
\tmagenta:[255,0,255],\n
\tmaroon:[128,0,0],\n
\tnavy:[0,0,128],\n
\tolive:[128,128,0],\n
\torange:[255,165,0],\n
\tpink:[255,192,203],\n
\tpurple:[128,0,128],\n
\tviolet:[128,0,128],\n
\tred:[255,0,0],\n
\tsilver:[192,192,192],\n
\twhite:[255,255,255],\n
\tyellow:[255,255,0],\n
\ttransparent: [255,255,255]\n
};\n
\n
/*\n
 * jQuery Easing v1.3 - http://gsgd.co.uk/sandbox/jquery/easing/\n
 *\n
 * Uses the built in easing capabilities added In jQuery 1.1\n
 * to offer multiple easing options\n
 *\n
 * TERMS OF USE - jQuery Easing\n
 *\n
 * Open source under the BSD License.\n
 *\n
 * Copyright 2008 George McGinley Smith\n
 * All rights reserved.\n
 *\n
 * Redistribution and use in source and binary forms, with or without modification,\n
 * are permitted provided that the following conditions are met:\n
 *\n
 * Redistributions of source code must retain the above copyright notice, this list of\n
 * conditions and the following disclaimer.\n
 * Redistributions in binary form must reproduce the above copyright notice, this list\n
 * of conditions and the following disclaimer in the documentation and/or other materials\n
 * provided with the distribution.\n
 *\n
 * Neither the name of the author nor the names of contributors may be used to endorse\n
 * or promote products derived from this software without specific prior written permission.\n
 *\n
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY\n
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE\n
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,\n
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE\n
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED\n
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING\n
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n
 * OF THE POSSIBILITY OF SUCH DAMAGE.\n
 *\n
*/\n
\n
// t: current time, b: begInnIng value, c: change In value, d: duration\n
$.easing.jswing = $.easing.swing;\n
\n
$.extend($.easing,\n
{\n
\tdef: \'easeOutQuad\',\n
\tswing: function (x, t, b, c, d) {\n
\t\t//alert($.easing.default);\n
\t\treturn $.easing[$.easing.def](x, t, b, c, d);\n
\t},\n
\teaseInQuad: function (x, t, b, c, d) {\n
\t\treturn c*(t/=d)*t + b;\n
\t},\n
\teaseOutQuad: function (x, t, b, c, d) {\n
\t\treturn -c *(t/=d)*(t-2) + b;\n
\t},\n
\teaseInOutQuad: function (x, t, b, c, d) {\n
\t\tif ((t/=d/2) < 1) return c/2*t*t + b;\n
\t\treturn -c/2 * ((--t)*(t-2) - 1) + b;\n
\t},\n
\teaseInCubic: function (x, t, b, c, d) {\n
\t\treturn c*(t/=d)*t*t + b;\n
\t},\n
\teaseOutCubic: function (x, t, b, c, d) {\n
\t\treturn c*((t=t/d-1)*t*t + 1) + b;\n
\t},\n
\teaseInOutCubic: function (x, t, b, c, d) {\n
\t\tif ((t/=d/2) < 1) return c/2*t*t*t + b;\n
\t\treturn c/2*((t-=2)*t*t + 2) + b;\n
\t},\n
\teaseInQuart: function (x, t, b, c, d) {\n
\t\treturn c*(t/=d)*t*t*t + b;\n
\t},\n
\teaseOutQuart: function (x, t, b, c, d) {\n
\t\treturn -c * ((t=t/d-1)*t*t*t - 1) + b;\n
\t},\n
\teaseInOutQuart: function (x, t, b, c, d) {\n
\t\tif ((t/=d/2) < 1) return c/2*t*t*t*t + b;\n
\t\treturn -c/2 * ((t-=2)*t*t*t - 2) + b;\n
\t},\n
\teaseInQuint: function (x, t, b, c, d) {\n
\t\treturn c*(t/=d)*t*t*t*t + b;\n
\t},\n
\teaseOutQuint: function (x, t, b, c, d) {\n
\t\treturn c*((t=t/d-1)*t*t*t*t + 1) + b;\n
\t},\n
\teaseInOutQuint: function (x, t, b, c, d) {\n
\t\tif ((t/=d/2) < 1) return c/2*t*t*t*t*t + b;\n
\t\treturn c/2*((t-=2)*t*t*t*t + 2) + b;\n
\t},\n
\teaseInSine: function (x, t, b, c, d) {\n
\t\treturn -c * Math.cos(t/d * (Math.PI/2)) + c + b;\n
\t},\n
\teaseOutSine: function (x, t, b, c, d) {\n
\t\treturn c * Math.sin(t/d * (Math.PI/2)) + b;\n
\t},\n
\teaseInOutSine: function (x, t, b, c, d) {\n
\t\treturn -c/2 * (Math.cos(Math.PI*t/d) - 1) + b;\n
\t},\n
\teaseInExpo: function (x, t, b, c, d) {\n
\t\treturn (t==0) ? b : c * Math.pow(2, 10 * (t/d - 1)) + b;\n
\t},\n
\teaseOutExpo: function (x, t, b, c, d) {\n
\t\treturn (t==d) ? b+c : c * (-Math.pow(2, -10 * t/d) + 1) + b;\n
\t},\n
\teaseInOutExpo: function (x, t, b, c, d) {\n
\t\tif (t==0) return b;\n
\t\tif (t==d) return b+c;\n
\t\tif ((t/=d/2) < 1) return c/2 * Math.pow(2, 10 * (t - 1)) + b;\n
\t\treturn c/2 * (-Math.pow(2, -10 * --t) + 2) + b;\n
\t},\n
\teaseInCirc: function (x, t, b, c, d) {\n
\t\treturn -c * (Math.sqrt(1 - (t/=d)*t) - 1) + b;\n
\t},\n
\teaseOutCirc: function (x, t, b, c, d) {\n
\t\treturn c * Math.sqrt(1 - (t=t/d-1)*t) + b;\n
\t},\n
\teaseInOutCirc: function (x, t, b, c, d) {\n
\t\tif ((t/=d/2) < 1) return -c/2 * (Math.sqrt(1 - t*t) - 1) + b;\n
\t\treturn c/2 * (Math.sqrt(1 - (t-=2)*t) + 1) + b;\n
\t},\n
\teaseInElastic: function (x, t, b, c, d) {\n
\t\tvar s=1.70158;var p=0;var a=c;\n
\t\tif (t==0) return b;  if ((t/=d)==1) return b+c;  if (!p) p=d*.3;\n
\t\tif (a < Math.abs(c)) { a=c; var s=p/4; }\n
\t\telse var s = p/(2*Math.PI) * Math.asin (c/a);\n
\t\treturn -(a*Math.pow(2,10*(t-=1)) * Math.sin( (t*d-s)*(2*Math.PI)/p )) + b;\n
\t},\n
\teaseOutElastic: function (x, t, b, c, d) {\n
\t\tvar s=1.70158;var p=0;var a=c;\n
\t\tif (t==0) return b;  if ((t/=d)==1) return b+c;  if (!p) p=d*.3;\n
\t\tif (a < Math.abs(c)) { a=c; var s=p/4; }\n
\t\telse var s = p/(2*Math.PI) * Math.asin (c/a);\n
\t\treturn a*Math.pow(2,-10*t) * Math.sin( (t*d-s)*(2*Math.PI)/p ) + c + b;\n
\t},\n
\teaseInOutElastic: function (x, t, b, c, d) {\n
\t\tvar s=1.70158;var p=0;var a=c;\n
\t\tif (t==0) return b;  if ((t/=d/2)==2) return b+c;  if (!p) p=d*(.3*1.5);\n
\t\tif (a < Math.abs(c)) { a=c; var s=p/4; }\n
\t\telse var s = p/(2*Math.PI) * Math.asin (c/a);\n
\t\tif (t < 1) return -.5*(a*Math.pow(2,10*(t-=1)) * Math.sin( (t*d-s)*(2*Math.PI)/p )) + b;\n
\t\treturn a*Math.pow(2,-10*(t-=1)) * Math.sin( (t*d-s)*(2*Math.PI)/p )*.5 + c + b;\n
\t},\n
\teaseInBack: function (x, t, b, c, d, s) {\n
\t\tif (s == undefined) s = 1.70158;\n
\t\treturn c*(t/=d)*t*((s+1)*t - s) + b;\n
\t},\n
\teaseOutBack: function (x, t, b, c, d, s) {\n
\t\tif (s == undefined) s = 1.70158;\n
\t\treturn c*((t=t/d-1)*t*((s+1)*t + s) + 1) + b;\n
\t},\n
\teaseInOutBack: function (x, t, b, c, d, s) {\n
\t\tif (s == undefined) s = 1.70158;\n
\t\tif ((t/=d/2) < 1) return c/2*(t*t*(((s*=(1.525))+1)*t - s)) + b;\n
\t\treturn c/2*((t-=2)*t*(((s*=(1.525))+1)*t + s) + 2) + b;\n
\t},\n
\teaseInBounce: function (x, t, b, c, d) {\n
\t\treturn c - $.easing.easeOutBounce (x, d-t, 0, c, d) + b;\n
\t},\n
\teaseOutBounce: function (x, t, b, c, d) {\n
\t\tif ((t/=d) < (1/2.75)) {\n
\t\t\treturn c*(7.5625*t*t) + b;\n
\t\t} else if (t < (2/2.75)) {\n
\t\t\treturn c*(7.5625*(t-=(1.5/2.75))*t + .75) + b;\n
\t\t} else if (t < (2.5/2.75)) {\n
\t\t\treturn c*(7.5625*(t-=(2.25/2.75))*t + .9375) + b;\n
\t\t} else {\n
\t\t\treturn c*(7.5625*(t-=(2.625/2.75))*t + .984375) + b;\n
\t\t}\n
\t},\n
\teaseInOutBounce: function (x, t, b, c, d) {\n
\t\tif (t < d/2) return $.easing.easeInBounce (x, t*2, 0, c, d) * .5 + b;\n
\t\treturn $.easing.easeOutBounce (x, t*2-d, 0, c, d) * .5 + c*.5 + b;\n
\t}\n
});\n
\n
/*\n
 *\n
 * TERMS OF USE - EASING EQUATIONS\n
 *\n
 * Open source under the BSD License.\n
 *\n
 * Copyright 2001 Robert Penner\n
 * All rights reserved.\n
 *\n
 * Redistribution and use in source and binary forms, with or without modification,\n
 * are permitted provided that the following conditions are met:\n
 *\n
 * Redistributions of source code must retain the above copyright notice, this list of\n
 * conditions and the following disclaimer.\n
 * Redistributions in binary form must reproduce the above copyright notice, this list\n
 * of conditions and the following disclaimer in the documentation and/or other materials\n
 * provided with the distribution.\n
 *\n
 * Neither the name of the author nor the names of contributors may be used to endorse\n
 * or promote products derived from this software without specific prior written permission.\n
 *\n
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY\n
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE\n
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,\n
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE\n
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED\n
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING\n
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n
 * OF THE POSSIBILITY OF SUCH DAMAGE.\n
 *\n
 */\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Blind 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Blind\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.blind = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'hide\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'vertical\'; // Default direction\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\tvar wrapper = $.effects.createWrapper(el).css({overflow:\'hidden\'}); // Create Wrapper\n
\t\tvar ref = (direction == \'vertical\') ? \'height\' : \'width\';\n
\t\tvar distance = (direction == \'vertical\') ? wrapper.height() : wrapper.width();\n
\t\tif(mode == \'show\') wrapper.css(ref, 0); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {};\n
\t\tanimation[ref] = mode == \'show\' ? distance : 0;\n
\n
\t\t// Animate\n
\t\twrapper.animate(animation, o.duration, o.options.easing, function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(el[0], arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Bounce 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Bounce\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.bounce = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'effect\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'up\'; // Default direction\n
\t\tvar distance = o.options.distance || 20; // Default distance\n
\t\tvar times = o.options.times || 5; // Default # of times\n
\t\tvar speed = o.duration || 250; // Default speed per bounce\n
\t\tif (/show|hide/.test(mode)) props.push(\'opacity\'); // Avoid touching opacity to prevent clearType and PNG issues in IE\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\t$.effects.createWrapper(el); // Create Wrapper\n
\t\tvar ref = (direction == \'up\' || direction == \'down\') ? \'top\' : \'left\';\n
\t\tvar motion = (direction == \'up\' || direction == \'left\') ? \'pos\' : \'neg\';\n
\t\tvar distance = o.options.distance || (ref == \'top\' ? el.outerHeight({margin:true}) / 3 : el.outerWidth({margin:true}) / 3);\n
\t\tif (mode == \'show\') el.css(\'opacity\', 0).css(ref, motion == \'pos\' ? -distance : distance); // Shift\n
\t\tif (mode == \'hide\') distance = distance / (times * 2);\n
\t\tif (mode != \'hide\') times--;\n
\n
\t\t// Animate\n
\t\tif (mode == \'show\') { // Show Bounce\n
\t\t\tvar animation = {opacity: 1};\n
\t\t\tanimation[ref] = (motion == \'pos\' ? \'+=\' : \'-=\') + distance;\n
\t\t\tel.animate(animation, speed / 2, o.options.easing);\n
\t\t\tdistance = distance / 2;\n
\t\t\ttimes--;\n
\t\t};\n
\t\tfor (var i = 0; i < times; i++) { // Bounces\n
\t\t\tvar animation1 = {}, animation2 = {};\n
\t\t\tanimation1[ref] = (motion == \'pos\' ? \'-=\' : \'+=\') + distance;\n
\t\t\tanimation2[ref] = (motion == \'pos\' ? \'+=\' : \'-=\') + distance;\n
\t\t\tel.animate(animation1, speed / 2, o.options.easing).animate(animation2, speed / 2, o.options.easing);\n
\t\t\tdistance = (mode == \'hide\') ? distance * 2 : distance / 2;\n
\t\t};\n
\t\tif (mode == \'hide\') { // Last Bounce\n
\t\t\tvar animation = {opacity: 0};\n
\t\t\tanimation[ref] = (motion == \'pos\' ? \'-=\' : \'+=\')  + distance;\n
\t\t\tel.animate(animation, speed / 2, o.options.easing, function(){\n
\t\t\t\tel.hide(); // Hide\n
\t\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\t});\n
\t\t} else {\n
\t\t\tvar animation1 = {}, animation2 = {};\n
\t\t\tanimation1[ref] = (motion == \'pos\' ? \'-=\' : \'+=\') + distance;\n
\t\t\tanimation2[ref] = (motion == \'pos\' ? \'+=\' : \'-=\') + distance;\n
\t\t\tel.animate(animation1, speed / 2, o.options.easing).animate(animation2, speed / 2, o.options.easing, function(){\n
\t\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\t});\n
\t\t};\n
\t\tel.queue(\'fx\', function() { el.dequeue(); });\n
\t\tel.dequeue();\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Clip 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Clip\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.clip = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\',\'height\',\'width\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'hide\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'vertical\'; // Default direction\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\tvar wrapper = $.effects.createWrapper(el).css({overflow:\'hidden\'}); // Create Wrapper\n
\t\tvar animate = el[0].tagName == \'IMG\' ? wrapper : el;\n
\t\tvar ref = {\n
\t\t\tsize: (direction == \'vertical\') ? \'height\' : \'width\',\n
\t\t\tposition: (direction == \'vertical\') ? \'top\' : \'left\'\n
\t\t};\n
\t\tvar distance = (direction == \'vertical\') ? animate.height() : animate.width();\n
\t\tif(mode == \'show\') { animate.css(ref.size, 0); animate.css(ref.position, distance / 2); } // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {};\n
\t\tanimation[ref.size] = mode == \'show\' ? distance : 0;\n
\t\tanimation[ref.position] = mode == \'show\' ? 0 : distance / 2;\n
\n
\t\t// Animate\n
\t\tanimate.animate(animation, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(el[0], arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Drop 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Drop\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.drop = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\',\'opacity\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'hide\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'left\'; // Default Direction\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\t$.effects.createWrapper(el); // Create Wrapper\n
\t\tvar ref = (direction == \'up\' || direction == \'down\') ? \'top\' : \'left\';\n
\t\tvar motion = (direction == \'up\' || direction == \'left\') ? \'pos\' : \'neg\';\n
\t\tvar distance = o.options.distance || (ref == \'top\' ? el.outerHeight({margin:true}) / 2 : el.outerWidth({margin:true}) / 2);\n
\t\tif (mode == \'show\') el.css(\'opacity\', 0).css(ref, motion == \'pos\' ? -distance : distance); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {opacity: mode == \'show\' ? 1 : 0};\n
\t\tanimation[ref] = (mode == \'show\' ? (motion == \'pos\' ? \'+=\' : \'-=\') : (motion == \'pos\' ? \'-=\' : \'+=\')) + distance;\n
\n
\t\t// Animate\n
\t\tel.animate(animation, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Explode 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Explode\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.explode = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\tvar rows = o.options.pieces ? Math.round(Math.sqrt(o.options.pieces)) : 3;\n
\tvar cells = o.options.pieces ? Math.round(Math.sqrt(o.options.pieces)) : 3;\n
\n
\to.options.mode = o.options.mode == \'toggle\' ? ($(this).is(\':visible\') ? \'hide\' : \'show\') : o.options.mode;\n
\tvar el = $(this).show().css(\'visibility\', \'hidden\');\n
\tvar offset = el.offset();\n
\n
\t//Substract the margins - not fixing the problem yet.\n
\toffset.top -= parseInt(el.css("marginTop"),10) || 0;\n
\toffset.left -= parseInt(el.css("marginLeft"),10) || 0;\n
\n
\tvar width = el.outerWidth(true);\n
\tvar height = el.outerHeight(true);\n
\n
\tfor(var i=0;i<rows;i++) { // =\n
\t\tfor(var j=0;j<cells;j++) { // ||\n
\t\t\tel\n
\t\t\t\t.clone()\n
\t\t\t\t.appendTo(\'body\')\n
\t\t\t\t.wrap(\'<div></div>\')\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\tvisibility: \'visible\',\n
\t\t\t\t\tleft: -j*(width/cells),\n
\t\t\t\t\ttop: -i*(height/rows)\n
\t\t\t\t})\n
\t\t\t\t.parent()\n
\t\t\t\t.addClass(\'ui-effects-explode\')\n
\t\t\t\t.css({\n
\t\t\t\t\tposition: \'absolute\',\n
\t\t\t\t\toverflow: \'hidden\',\n
\t\t\t\t\twidth: width/cells,\n
\t\t\t\t\theight: height/rows,\n
\t\t\t\t\tleft: offset.left + j*(width/cells) + (o.options.mode == \'show\' ? (j-Math.floor(cells/2))*(width/cells) : 0),\n
\t\t\t\t\ttop: offset.top + i*(height/rows) + (o.options.mode == \'show\' ? (i-Math.floor(rows/2))*(height/rows) : 0),\n
\t\t\t\t\topacity: o.options.mode == \'show\' ? 0 : 1\n
\t\t\t\t}).animate({\n
\t\t\t\t\tleft: offset.left + j*(width/cells) + (o.options.mode == \'show\' ? 0 : (j-Math.floor(cells/2))*(width/cells)),\n
\t\t\t\t\ttop: offset.top + i*(height/rows) + (o.options.mode == \'show\' ? 0 : (i-Math.floor(rows/2))*(height/rows)),\n
\t\t\t\t\topacity: o.options.mode == \'show\' ? 1 : 0\n
\t\t\t\t}, o.duration || 500);\n
\t\t}\n
\t}\n
\n
\t// Set a timeout, to call the callback approx. when the other animations have finished\n
\tsetTimeout(function() {\n
\n
\t\to.options.mode == \'show\' ? el.css({ visibility: \'visible\' }) : el.css({ visibility: \'visible\' }).hide();\n
\t\t\t\tif(o.callback) o.callback.apply(el[0]); // Callback\n
\t\t\t\tel.dequeue();\n
\n
\t\t\t\t$(\'div.ui-effects-explode\').remove();\n
\n
\t}, o.duration || 500);\n
\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Fold 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Fold\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.fold = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'hide\'); // Set Mode\n
\t\tvar size = o.options.size || 15; // Default fold size\n
\t\tvar horizFirst = !(!o.options.horizFirst); // Ensure a boolean value\n
\t\tvar duration = o.duration ? o.duration / 2 : $.fx.speeds._default / 2;\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\tvar wrapper = $.effects.createWrapper(el).css({overflow:\'hidden\'}); // Create Wrapper\n
\t\tvar widthFirst = ((mode == \'show\') != horizFirst);\n
\t\tvar ref = widthFirst ? [\'width\', \'height\'] : [\'height\', \'width\'];\n
\t\tvar distance = widthFirst ? [wrapper.width(), wrapper.height()] : [wrapper.height(), wrapper.width()];\n
\t\tvar percent = /([0-9]+)%/.exec(size);\n
\t\tif(percent) size = parseInt(percent[1],10) / 100 * distance[mode == \'hide\' ? 0 : 1];\n
\t\tif(mode == \'show\') wrapper.css(horizFirst ? {height: 0, width: size} : {height: size, width: 0}); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation1 = {}, animation2 = {};\n
\t\tanimation1[ref[0]] = mode == \'show\' ? distance[0] : size;\n
\t\tanimation2[ref[1]] = mode == \'show\' ? distance[1] : 0;\n
\n
\t\t// Animate\n
\t\twrapper.animate(animation1, duration, o.options.easing)\n
\t\t.animate(animation2, duration, o.options.easing, function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(el[0], arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Highlight 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Highlight\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.highlight = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'backgroundImage\',\'backgroundColor\',\'opacity\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'show\'); // Set Mode\n
\t\tvar color = o.options.color || "#ffff99"; // Default highlight color\n
\t\tvar oldColor = el.css("backgroundColor");\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\tel.css({backgroundImage: \'none\', backgroundColor: color}); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {backgroundColor: oldColor };\n
\t\tif (mode == "hide") animation[\'opacity\'] = 0;\n
\n
\t\t// Animate\n
\t\tel.animate(animation, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == "hide") el.hide();\n
\t\t\t$.effects.restore(el, props);\n
\t\tif (mode == "show" && $.browser.msie) this.style.removeAttribute(\'filter\');\n
\t\t\tif(o.callback) o.callback.apply(this, arguments);\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Pulsate 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Pulsate\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.pulsate = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this);\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'show\'); // Set Mode\n
\t\tvar times = o.options.times || 5; // Default # of times\n
\t\tvar duration = o.duration ? o.duration / 2 : $.fx.speeds._default / 2;\n
\n
\t\t// Adjust\n
\t\tif (mode == \'hide\') times--;\n
\t\tif (el.is(\':hidden\')) { // Show fadeIn\n
\t\t\tel.css(\'opacity\', 0);\n
\t\t\tel.show(); // Show\n
\t\t\tel.animate({opacity: 1}, duration, o.options.easing);\n
\t\t\ttimes = times-2;\n
\t\t}\n
\n
\t\t// Animate\n
\t\tfor (var i = 0; i < times; i++) { // Pulsate\n
\t\t\tel.animate({opacity: 0}, duration, o.options.easing).animate({opacity: 1}, duration, o.options.easing);\n
\t\t};\n
\t\tif (mode == \'hide\') { // Last Pulse\n
\t\t\tel.animate({opacity: 0}, duration, o.options.easing, function(){\n
\t\t\t\tel.hide(); // Hide\n
\t\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\t});\n
\t\t} else {\n
\t\t\tel.animate({opacity: 0}, duration, o.options.easing).animate({opacity: 1}, duration, o.options.easing, function(){\n
\t\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\t});\n
\t\t};\n
\t\tel.queue(\'fx\', function() { el.dequeue(); });\n
\t\tel.dequeue();\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Scale 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Scale\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.puff = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this);\n
\n
\t\t// Set options\n
\t\tvar options = $.extend(true, {}, o.options);\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'hide\'); // Set Mode\n
\t\tvar percent = parseInt(o.options.percent,10) || 150; // Set default puff percent\n
\t\toptions.fade = true; // It\'s not a puff if it doesn\'t fade! :)\n
\t\tvar original = {height: el.height(), width: el.width()}; // Save original\n
\n
\t\t// Adjust\n
\t\tvar factor = percent / 100;\n
\t\tel.from = (mode == \'hide\') ? original : {height: original.height * factor, width: original.width * factor};\n
\n
\t\t// Animation\n
\t\toptions.from = el.from;\n
\t\toptions.percent = (mode == \'hide\') ? percent : 100;\n
\t\toptions.mode = mode;\n
\n
\t\t// Animate\n
\t\tel.effect(\'scale\', options, o.duration, o.callback);\n
\t\tel.dequeue();\n
\t});\n
\n
};\n
\n
$.effects.scale = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this);\n
\n
\t\t// Set options\n
\t\tvar options = $.extend(true, {}, o.options);\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'effect\'); // Set Mode\n
\t\tvar percent = parseInt(o.options.percent,10) || (parseInt(o.options.percent,10) == 0 ? 0 : (mode == \'hide\' ? 0 : 100)); // Set default scaling percent\n
\t\tvar direction = o.options.direction || \'both\'; // Set default axis\n
\t\tvar origin = o.options.origin; // The origin of the scaling\n
\t\tif (mode != \'effect\') { // Set default origin and restore for show/hide\n
\t\t\toptions.origin = origin || [\'middle\',\'center\'];\n
\t\t\toptions.restore = true;\n
\t\t}\n
\t\tvar original = {height: el.height(), width: el.width()}; // Save original\n
\t\tel.from = o.options.from || (mode == \'show\' ? {height: 0, width: 0} : original); // Default from state\n
\n
\t\t// Adjust\n
\t\tvar factor = { // Set scaling factor\n
\t\t\ty: direction != \'horizontal\' ? (percent / 100) : 1,\n
\t\t\tx: direction != \'vertical\' ? (percent / 100) : 1\n
\t\t};\n
\t\tel.to = {height: original.height * factor.y, width: original.width * factor.x}; // Set to state\n
\n
\t\tif (o.options.fade) { // Fade option to support puff\n
\t\t\tif (mode == \'show\') {el.from.opacity = 0; el.to.opacity = 1;};\n
\t\t\tif (mode == \'hide\') {el.from.opacity = 1; el.to.opacity = 0;};\n
\t\t};\n
\n
\t\t// Animation\n
\t\toptions.from = el.from; options.to = el.to; options.mode = mode;\n
\n
\t\t// Animate\n
\t\tel.effect(\'size\', options, o.duration, o.callback);\n
\t\tel.dequeue();\n
\t});\n
\n
};\n
\n
$.effects.size = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\',\'width\',\'height\',\'overflow\',\'opacity\'];\n
\t\tvar props1 = [\'position\',\'top\',\'left\',\'overflow\',\'opacity\']; // Always restore\n
\t\tvar props2 = [\'width\',\'height\',\'overflow\']; // Copy for children\n
\t\tvar cProps = [\'fontSize\'];\n
\t\tvar vProps = [\'borderTopWidth\', \'borderBottomWidth\', \'paddingTop\', \'paddingBottom\'];\n
\t\tvar hProps = [\'borderLeftWidth\', \'borderRightWidth\', \'paddingLeft\', \'paddingRight\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'effect\'); // Set Mode\n
\t\tvar restore = o.options.restore || false; // Default restore\n
\t\tvar scale = o.options.scale || \'both\'; // Default scale mode\n
\t\tvar origin = o.options.origin; // The origin of the sizing\n
\t\tvar original = {height: el.height(), width: el.width()}; // Save original\n
\t\tel.from = o.options.from || original; // Default from state\n
\t\tel.to = o.options.to || original; // Default to state\n
\t\t// Adjust\n
\t\tif (origin) { // Calculate baseline shifts\n
\t\t\tvar baseline = $.effects.getBaseline(origin, original);\n
\t\t\tel.from.top = (original.height - el.from.height) * baseline.y;\n
\t\t\tel.from.left = (original.width - el.from.width) * baseline.x;\n
\t\t\tel.to.top = (original.height - el.to.height) * baseline.y;\n
\t\t\tel.to.left = (original.width - el.to.width) * baseline.x;\n
\t\t};\n
\t\tvar factor = { // Set scaling factor\n
\t\t\tfrom: {y: el.from.height / original.height, x: el.from.width / original.width},\n
\t\t\tto: {y: el.to.height / original.height, x: el.to.width / original.width}\n
\t\t};\n
\t\tif (scale == \'box\' || scale == \'both\') { // Scale the css box\n
\t\t\tif (factor.from.y != factor.to.y) { // Vertical props scaling\n
\t\t\t\tprops = props.concat(vProps);\n
\t\t\t\tel.from = $.effects.setTransition(el, vProps, factor.from.y, el.from);\n
\t\t\t\tel.to = $.effects.setTransition(el, vProps, factor.to.y, el.to);\n
\t\t\t};\n
\t\t\tif (factor.from.x != factor.to.x) { // Horizontal props scaling\n
\t\t\t\tprops = props.concat(hProps);\n
\t\t\t\tel.from = $.effects.setTransition(el, hProps, factor.from.x, el.from);\n
\t\t\t\tel.to = $.effects.setTransition(el, hProps, factor.to.x, el.to);\n
\t\t\t};\n
\t\t};\n
\t\tif (scale == \'content\' || scale == \'both\') { // Scale the content\n
\t\t\tif (factor.from.y != factor.to.y) { // Vertical props scaling\n
\t\t\t\tprops = props.concat(cProps);\n
\t\t\t\tel.from = $.effects.setTransition(el, cProps, factor.from.y, el.from);\n
\t\t\t\tel.to = $.effects.setTransition(el, cProps, factor.to.y, el.to);\n
\t\t\t};\n
\t\t};\n
\t\t$.effects.save(el, restore ? props : props1); el.show(); // Save & Show\n
\t\t$.effects.createWrapper(el); // Create Wrapper\n
\t\tel.css(\'overflow\',\'hidden\').css(el.from); // Shift\n
\n
\t\t// Animate\n
\t\tif (scale == \'content\' || scale == \'both\') { // Scale the children\n
\t\t\tvProps = vProps.concat([\'marginTop\',\'marginBottom\']).concat(cProps); // Add margins/font-size\n
\t\t\thProps = hProps.concat([\'marginLeft\',\'marginRight\']); // Add margins\n
\t\t\tprops2 = props.concat(vProps).concat(hProps); // Concat\n
\t\t\tel.find("*[width]").each(function(){\n
\t\t\t\tchild = $(this);\n
\t\t\t\tif (restore) $.effects.save(child, props2);\n
\t\t\t\tvar c_original = {height: child.height(), width: child.width()}; // Save original\n
\t\t\t\tchild.from = {height: c_original.height * factor.from.y, width: c_original.width * factor.from.x};\n
\t\t\t\tchild.to = {height: c_original.height * factor.to.y, width: c_original.width * factor.to.x};\n
\t\t\t\tif (factor.from.y != factor.to.y) { // Vertical props scaling\n
\t\t\t\t\tchild.from = $.effects.setTransition(child, vProps, factor.from.y, child.from);\n
\t\t\t\t\tchild.to = $.effects.setTransition(child, vProps, factor.to.y, child.to);\n
\t\t\t\t};\n
\t\t\t\tif (factor.from.x != factor.to.x) { // Horizontal props scaling\n
\t\t\t\t\tchild.from = $.effects.setTransition(child, hProps, factor.from.x, child.from);\n
\t\t\t\t\tchild.to = $.effects.setTransition(child, hProps, factor.to.x, child.to);\n
\t\t\t\t};\n
\t\t\t\tchild.css(child.from); // Shift children\n
\t\t\t\tchild.animate(child.to, o.duration, o.options.easing, function(){\n
\t\t\t\t\tif (restore) $.effects.restore(child, props2); // Restore children\n
\t\t\t\t}); // Animate children\n
\t\t\t});\n
\t\t};\n
\n
\t\t// Animate\n
\t\tel.animate(el.to, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, restore ? props : props1); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Shake 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Shake\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.shake = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'effect\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'left\'; // Default direction\n
\t\tvar distance = o.options.distance || 20; // Default distance\n
\t\tvar times = o.options.times || 3; // Default # of times\n
\t\tvar speed = o.duration || o.options.duration || 140; // Default speed per shake\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\t$.effects.createWrapper(el); // Create Wrapper\n
\t\tvar ref = (direction == \'up\' || direction == \'down\') ? \'top\' : \'left\';\n
\t\tvar motion = (direction == \'up\' || direction == \'left\') ? \'pos\' : \'neg\';\n
\n
\t\t// Animation\n
\t\tvar animation = {}, animation1 = {}, animation2 = {};\n
\t\tanimation[ref] = (motion == \'pos\' ? \'-=\' : \'+=\')  + distance;\n
\t\tanimation1[ref] = (motion == \'pos\' ? \'+=\' : \'-=\')  + distance * 2;\n
\t\tanimation2[ref] = (motion == \'pos\' ? \'-=\' : \'+=\')  + distance * 2;\n
\n
\t\t// Animate\n
\t\tel.animate(animation, speed, o.options.easing);\n
\t\tfor (var i = 1; i < times; i++) { // Shakes\n
\t\t\tel.animate(animation1, speed, o.options.easing).animate(animation2, speed, o.options.easing);\n
\t\t};\n
\t\tel.animate(animation1, speed, o.options.easing).\n
\t\tanimate(animation, speed / 2, o.options.easing, function(){ // Last shake\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t});\n
\t\tel.queue(\'fx\', function() { el.dequeue(); });\n
\t\tel.dequeue();\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Slide 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Slide\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.slide = function(o) {\n
\n
\treturn this.queue(function() {\n
\n
\t\t// Create element\n
\t\tvar el = $(this), props = [\'position\',\'top\',\'left\'];\n
\n
\t\t// Set options\n
\t\tvar mode = $.effects.setMode(el, o.options.mode || \'show\'); // Set Mode\n
\t\tvar direction = o.options.direction || \'left\'; // Default Direction\n
\n
\t\t// Adjust\n
\t\t$.effects.save(el, props); el.show(); // Save & Show\n
\t\t$.effects.createWrapper(el).css({overflow:\'hidden\'}); // Create Wrapper\n
\t\tvar ref = (direction == \'up\' || direction == \'down\') ? \'top\' : \'left\';\n
\t\tvar motion = (direction == \'up\' || direction == \'left\') ? \'pos\' : \'neg\';\n
\t\tvar distance = o.options.distance || (ref == \'top\' ? el.outerHeight({margin:true}) : el.outerWidth({margin:true}));\n
\t\tif (mode == \'show\') el.css(ref, motion == \'pos\' ? -distance : distance); // Shift\n
\n
\t\t// Animation\n
\t\tvar animation = {};\n
\t\tanimation[ref] = (mode == \'show\' ? (motion == \'pos\' ? \'+=\' : \'-=\') : (motion == \'pos\' ? \'-=\' : \'+=\')) + distance;\n
\n
\t\t// Animate\n
\t\tel.animate(animation, { queue: false, duration: o.duration, easing: o.options.easing, complete: function() {\n
\t\t\tif(mode == \'hide\') el.hide(); // Hide\n
\t\t\t$.effects.restore(el, props); $.effects.removeWrapper(el); // Restore\n
\t\t\tif(o.callback) o.callback.apply(this, arguments); // Callback\n
\t\t\tel.dequeue();\n
\t\t}});\n
\n
\t});\n
\n
};\n
\n
})(jQuery);\n
/*\n
 * jQuery UI Effects Transfer 1.7.2\n
 *\n
 * Copyright (c) 2009 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/Transfer\n
 *\n
 * Depends:\n
 *\teffects.core.js\n
 */\n
(function($) {\n
\n
$.effects.transfer = function(o) {\n
\treturn this.queue(function() {\n
\t\tvar elem = $(this),\n
\t\t\ttarget = $(o.options.to),\n
\t\t\tendPosition = target.offset(),\n
\t\t\tanimation = {\n
\t\t\t\ttop: endPosition.top,\n
\t\t\t\tleft: endPosition.left,\n
\t\t\t\theight: target.innerHeight(),\n
\t\t\t\twidth: target.innerWidth()\n
\t\t\t},\n
\t\t\tstartPosition = elem.offset(),\n
\t\t\ttransfer = $(\'<div class="ui-effects-transfer"></div>\')\n
\t\t\t\t.appendTo(document.body)\n
\t\t\t\t.addClass(o.options.className)\n
\t\t\t\t.css({\n
\t\t\t\t\ttop: startPosition.top,\n
\t\t\t\t\tleft: startPosition.left,\n
\t\t\t\t\theight: elem.innerHeight(),\n
\t\t\t\t\twidth: elem.innerWidth(),\n
\t\t\t\t\tposition: \'absolute\'\n
\t\t\t\t})\n
\t\t\t\t.animate(animation, o.duration, o.options.easing, function() {\n
\t\t\t\t\ttransfer.remove();\n
\t\t\t\t\t(o.callback && o.callback.apply(elem[0], arguments));\n
\t\t\t\t\telem.dequeue();\n
\t\t\t\t});\n
\t});\n
};\n
\n
})(jQuery);\n


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
