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
            <value> <string>ts77895655.21</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.effects.core.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Effects 1.8.2\n
 *\n
 * Copyright (c) 2010 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Effects/\n
 */\n
;jQuery.effects || (function($) {\n
\n
$.effects = {};\n
\n
\n
\n
/******************************************************************************/\n
/****************************** COLOR ANIMATIONS ******************************/\n
/******************************************************************************/\n
\n
// override the animation for color styles\n
$.each([\'backgroundColor\', \'borderBottomColor\', \'borderLeftColor\',\n
\t\'borderRightColor\', \'borderTopColor\', \'color\', \'outlineColor\'],\n
function(i, attr) {\n
\t$.fx.step[attr] = function(fx) {\n
\t\tif (!fx.colorInit) {\n
\t\t\tfx.start = getColor(fx.elem, attr);\n
\t\t\tfx.end = getRGB(fx.end);\n
\t\t\tfx.colorInit = true;\n
\t\t}\n
\n
\t\tfx.elem.style[attr] = \'rgb(\' +\n
\t\t\tMath.max(Math.min(parseInt((fx.pos * (fx.end[0] - fx.start[0])) + fx.start[0], 10), 255), 0) + \',\' +\n
\t\t\tMath.max(Math.min(parseInt((fx.pos * (fx.end[1] - fx.start[1])) + fx.start[1], 10), 255), 0) + \',\' +\n
\t\t\tMath.max(Math.min(parseInt((fx.pos * (fx.end[2] - fx.start[2])) + fx.start[2], 10), 255), 0) + \')\';\n
\t};\n
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
\n
\n
/******************************************************************************/\n
/****************************** CLASS ANIMATIONS ******************************/\n
/******************************************************************************/\n
\n
var classAnimationActions = [\'add\', \'remove\', \'toggle\'],\n
\tshorthandStyles = {\n
\t\tborder: 1,\n
\t\tborderBottom: 1,\n
\t\tborderColor: 1,\n
\t\tborderLeft: 1,\n
\t\tborderRight: 1,\n
\t\tborderTop: 1,\n
\t\tborderWidth: 1,\n
\t\tmargin: 1,\n
\t\tpadding: 1\n
\t};\n
\n
function getElementStyles() {\n
\tvar style = document.defaultView\n
\t\t\t? document.defaultView.getComputedStyle(this, null)\n
\t\t\t: this.currentStyle,\n
\t\tnewStyle = {},\n
\t\tkey,\n
\t\tcamelCase;\n
\n
\t// webkit enumerates style porperties\n
\tif (style && style.length && style[0] && style[style[0]]) {\n
\t\tvar len = style.length;\n
\t\twhile (len--) {\n
\t\t\tkey = style[len];\n
\t\t\tif (typeof style[key] == \'string\') {\n
\t\t\t\tcamelCase = key.replace(/\\-(\\w)/g, function(all, letter){\n
\t\t\t\t\treturn letter.toUpperCase();\n
\t\t\t\t});\n
\t\t\t\tnewStyle[camelCase] = style[key];\n
\t\t\t}\n
\t\t}\n
\t} else {\n
\t\tfor (key in style) {\n
\t\t\tif (typeof style[key] === \'string\') {\n
\t\t\t\tnewStyle[key] = style[key];\n
\t\t\t}\n
\t\t}\n
\t}\n
\t\n
\treturn newStyle;\n
}\n
\n
function filterStyles(styles) {\n
\tvar name, value;\n
\tfor (name in styles) {\n
\t\tvalue = styles[name];\n
\t\tif (\n
\t\t\t// ignore null and undefined values\n
\t\t\tvalue == null ||\n
\t\t\t// ignore functions (when does this occur?)\n
\t\t\t$.isFunction(value) ||\n
\t\t\t// shorthand styles that need to be expanded\n
\t\t\tname in shorthandStyles ||\n
\t\t\t// ignore scrollbars (break in IE)\n
\t\t\t(/scrollbar/).test(name) ||\n
\n
\t\t\t// only colors or values that can be converted to numbers\n
\t\t\t(!(/color/i).test(name) && isNaN(parseFloat(value)))\n
\t\t) {\n
\t\t\tdelete styles[name];\n
\t\t}\n
\t}\n
\t\n
\treturn styles;\n
}\n
\n
function styleDifference(oldStyle, newStyle) {\n
\tvar diff = { _: 0 }, // http://dev.jquery.com/ticket/5459\n
\t\tname;\n
\n
\tfor (name in newStyle) {\n
\t\tif (oldStyle[name] != newStyle[name]) {\n
\t\t\tdiff[name] = newStyle[name];\n
\t\t}\n
\t}\n
\n
\treturn diff;\n
}\n
\n
$.effects.animateClass = function(value, duration, easing, callback) {\n
\tif ($.isFunction(easing)) {\n
\t\tcallback = easing;\n
\t\teasing = null;\n
\t}\n
\n
\treturn this.each(function() {\n
\n
\t\tvar that = $(this),\n
\t\t\toriginalStyleAttr = that.attr(\'style\') || \' \',\n
\t\t\toriginalStyle = filterStyles(getElementStyles.call(this)),\n
\t\t\tnewStyle,\n
\t\t\tclassName = that.attr(\'className\');\n
\n
\t\t$.each(classAnimationActions, function(i, action) {\n
\t\t\tif (value[action]) {\n
\t\t\t\tthat[action + \'Class\'](value[action]);\n
\t\t\t}\n
\t\t});\n
\t\tnewStyle = filterStyles(getElementStyles.call(this));\n
\t\tthat.attr(\'className\', className);\n
\n
\t\tthat.animate(styleDifference(originalStyle, newStyle), duration, easing, function() {\n
\t\t\t$.each(classAnimationActions, function(i, action) {\n
\t\t\t\tif (value[action]) { that[action + \'Class\'](value[action]); }\n
\t\t\t});\n
\t\t\t// work around bug in IE by clearing the cssText before setting it\n
\t\t\tif (typeof that.attr(\'style\') == \'object\') {\n
\t\t\t\tthat.attr(\'style\').cssText = \'\';\n
\t\t\t\tthat.attr(\'style\').cssText = originalStyleAttr;\n
\t\t\t} else {\n
\t\t\t\tthat.attr(\'style\', originalStyleAttr);\n
\t\t\t}\n
\t\t\tif (callback) { callback.apply(this, arguments); }\n
\t\t});\n
\t});\n
};\n
\n
$.fn.extend({\n
\t_addClass: $.fn.addClass,\n
\taddClass: function(classNames, speed, easing, callback) {\n
\t\treturn speed ? $.effects.animateClass.apply(this, [{ add: classNames },speed,easing,callback]) : this._addClass(classNames);\n
\t},\n
\n
\t_removeClass: $.fn.removeClass,\n
\tremoveClass: function(classNames,speed,easing,callback) {\n
\t\treturn speed ? $.effects.animateClass.apply(this, [{ remove: classNames },speed,easing,callback]) : this._removeClass(classNames);\n
\t},\n
\n
\t_toggleClass: $.fn.toggleClass,\n
\ttoggleClass: function(classNames, force, speed, easing, callback) {\n
\t\tif ( typeof force == "boolean" || force === undefined ) {\n
\t\t\tif ( !speed ) {\n
\t\t\t\t// without speed parameter;\n
\t\t\t\treturn this._toggleClass(classNames, force);\n
\t\t\t} else {\n
\t\t\t\treturn $.effects.animateClass.apply(this, [(force?{add:classNames}:{remove:classNames}),speed,easing,callback]);\n
\t\t\t}\n
\t\t} else {\n
\t\t\t// without switch parameter;\n
\t\t\treturn $.effects.animateClass.apply(this, [{ toggle: classNames },force,speed,easing]);\n
\t\t}\n
\t},\n
\n
\tswitchClass: function(remove,add,speed,easing,callback) {\n
\t\treturn $.effects.animateClass.apply(this, [{ add: add, remove: remove },speed,easing,callback]);\n
\t}\n
});\n
\n
\n
\n
/******************************************************************************/\n
/*********************************** EFFECTS **********************************/\n
/******************************************************************************/\n
\n
$.extend($.effects, {\n
\tversion: "1.8.2",\n
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
\t\t// if the element is already wrapped, return it\n
\t\tif (element.parent().is(\'.ui-effects-wrapper\')) {\n
\t\t\treturn element.parent();\n
\t\t}\n
\n
\t\t// wrap the element\n
\t\tvar props = {\n
\t\t\t\twidth: element.outerWidth(true),\n
\t\t\t\theight: element.outerHeight(true),\n
\t\t\t\t\'float\': element.css(\'float\')\n
\t\t\t},\n
\t\t\twrapper = $(\'<div></div>\')\n
\t\t\t\t.addClass(\'ui-effects-wrapper\')\n
\t\t\t\t.css({\n
\t\t\t\t\tfontSize: \'100%\',\n
\t\t\t\t\tbackground: \'transparent\',\n
\t\t\t\t\tborder: \'none\',\n
\t\t\t\t\tmargin: 0,\n
\t\t\t\t\tpadding: 0\n
\t\t\t\t});\n
\n
\t\telement.wrap(wrapper);\n
\t\twrapper = element.parent(); //Hotfix for jQuery 1.4 since some change in wrap() seems to actually loose the reference to the wrapped element\n
\n
\t\t// transfer positioning properties to the wrapper\n
\t\tif (element.css(\'position\') == \'static\') {\n
\t\t\twrapper.css({ position: \'relative\' });\n
\t\t\telement.css({ position: \'relative\' });\n
\t\t} else {\n
\t\t\t$.extend(props, {\n
\t\t\t\tposition: element.css(\'position\'),\n
\t\t\t\tzIndex: element.css(\'z-index\')\n
\t\t\t});\n
\t\t\t$.each([\'top\', \'left\', \'bottom\', \'right\'], function(i, pos) {\n
\t\t\t\tprops[pos] = element.css(pos);\n
\t\t\t\tif (isNaN(parseInt(props[pos], 10))) {\n
\t\t\t\t\tprops[pos] = \'auto\';\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\telement.css({position: \'relative\', top: 0, left: 0 });\n
\t\t}\n
\n
\t\treturn wrapper.css(props).show();\n
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
\t}\n
});\n
\n
\n
function _normalizeArguments(effect, options, speed, callback) {\n
\t// shift params for method overloading\n
\tif (typeof effect == \'object\') {\n
\t\tcallback = options;\n
\t\tspeed = null;\n
\t\toptions = effect;\n
\t\teffect = options.effect;\n
\t}\n
\tif ($.isFunction(options)) {\n
\t\tcallback = options;\n
\t\tspeed = null;\n
\t\toptions = {};\n
\t}\n
\tif ($.isFunction(speed)) {\n
\t\tcallback = speed;\n
\t\tspeed = null;\n
\t}\n
\tif (typeof options == \'number\' || $.fx.speeds[options]) {\n
\t\tcallback = speed;\n
\t\tspeed = options;\n
\t\toptions = {};\n
\t}\n
\n
\toptions = options || {};\n
\n
\tspeed = speed || options.duration;\n
\tspeed = $.fx.off ? 0 : typeof speed == \'number\'\n
\t\t? speed : $.fx.speeds[speed] || $.fx.speeds._default;\n
\n
\tcallback = callback || options.complete;\n
\n
\treturn [effect, options, speed, callback];\n
}\n
\n
$.fn.extend({\n
\teffect: function(effect, options, speed, callback) {\n
\t\tvar args = _normalizeArguments.apply(this, arguments),\n
\t\t\t// TODO: make effects takes actual parameters instead of a hash\n
\t\t\targs2 = {\n
\t\t\t\toptions: args[1],\n
\t\t\t\tduration: args[2],\n
\t\t\t\tcallback: args[3]\n
\t\t\t},\n
\t\t\teffectMethod = $.effects[effect];\n
\t\t\n
\t\treturn effectMethod && !$.fx.off ? effectMethod.call(this, args2) : this;\n
\t},\n
\n
\t_show: $.fn.show,\n
\tshow: function(speed) {\n
\t\tif (!speed || typeof speed == \'number\' || $.fx.speeds[speed]) {\n
\t\t\treturn this._show.apply(this, arguments);\n
\t\t} else {\n
\t\t\tvar args = _normalizeArguments.apply(this, arguments);\n
\t\t\targs[1].mode = \'show\';\n
\t\t\treturn this.effect.apply(this, args);\n
\t\t}\n
\t},\n
\n
\t_hide: $.fn.hide,\n
\thide: function(speed) {\n
\t\tif (!speed || typeof speed == \'number\' || $.fx.speeds[speed]) {\n
\t\t\treturn this._hide.apply(this, arguments);\n
\t\t} else {\n
\t\t\tvar args = _normalizeArguments.apply(this, arguments);\n
\t\t\targs[1].mode = \'hide\';\n
\t\t\treturn this.effect.apply(this, args);\n
\t\t}\n
\t},\n
\n
\t// jQuery core overloads toggle and create _toggle\n
\t__toggle: $.fn.toggle,\n
\ttoggle: function(speed) {\n
\t\tif (!speed || typeof speed == \'number\' || $.fx.speeds[speed] ||\n
\t\t\ttypeof speed == \'boolean\' || $.isFunction(speed)) {\n
\t\t\treturn this.__toggle.apply(this, arguments);\n
\t\t} else {\n
\t\t\tvar args = _normalizeArguments.apply(this, arguments);\n
\t\t\targs[1].mode = \'toggle\';\n
\t\t\treturn this.effect.apply(this, args);\n
\t\t}\n
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
\n
\n
/******************************************************************************/\n
/*********************************** EASING ***********************************/\n
/******************************************************************************/\n
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


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>22225</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
