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
            <value> <string>ts80046429.02</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>svgcanvas.js</string> </value>
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
            <value> <int>288396</int> </value>
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

﻿/*\n
 * svgcanvas.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 * Copyright(c) 2010 Pavol Rusnak\n
 * Copyright(c) 2010 Jeff Schiller\n
 *\n
 */\n
\n
if(!window.console) {\n
\twindow.console = {};\n
\twindow.console.log = function(str) {};\n
\twindow.console.dir = function(str) {};\n
}\n
\n
if(window.opera) {\n
\twindow.console.log = function(str) {opera.postError(str);};\n
\twindow.console.dir = function(str) {};\n
}\n
\n
(function() {\n
\n
\t// This fixes $(...).attr() to work as expected with SVG elements.\n
\t// Does not currently use *AttributeNS() since we rarely need that.\n
\t\n
\t// See http://api.jquery.com/attr/ for basic documentation of .attr()\n
\t\n
\t// Additional functionality: \n
\t// - When getting attributes, a string that\'s a number is return as type number.\n
\t// - If an array is supplied as first parameter, multiple values are returned\n
\t// as an object with values for each given attributes\n
\t\n
\tvar proxied = jQuery.fn.attr, svgns = "http://www.w3.org/2000/svg";\n
\tjQuery.fn.attr = function(key, value) {\n
\t\tvar len = this.length;\n
\t\tif(!len) return this;\n
\t\tfor(var i=0; i<len; i++) {\n
\t\t\tvar elem = this[i];\n
\t\t\t// set/get SVG attribute\n
\t\t\tif(elem.namespaceURI === svgns) {\n
\t\t\t\t// Setting attribute\n
\t\t\t\tif(value !== undefined) {\n
\t\t\t\t\telem.setAttribute(key, value);\n
\t\t\t\t} else if($.isArray(key)) {\n
\t\t\t\t\t// Getting attributes from array\n
\t\t\t\t\tvar j = key.length, obj = {};\n
\n
\t\t\t\t\twhile(j--) {\n
\t\t\t\t\t\tvar aname = key[j];\n
\t\t\t\t\t\tvar attr = elem.getAttribute(aname);\n
\t\t\t\t\t\t// This returns a number when appropriate\n
\t\t\t\t\t\tif(attr || attr === "0") {\n
\t\t\t\t\t\t\tattr = isNaN(attr)?attr:attr-0;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tobj[aname] = attr;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn obj;\n
\t\t\t\t\n
\t\t\t\t} else if(typeof key === "object") {\n
\t\t\t\t\t// Setting attributes form object\n
\t\t\t\t\tfor(var v in key) {\n
\t\t\t\t\t\telem.setAttribute(v, key[v]);\n
\t\t\t\t\t}\n
\t\t\t\t// Getting attribute\n
\t\t\t\t} else {\n
\t\t\t\t\tvar attr = elem.getAttribute(key);\n
\t\t\t\t\tif(attr || attr === "0") {\n
\t\t\t\t\t\tattr = isNaN(attr)?attr:attr-0;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn attr;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\treturn proxied.apply(this, arguments);\n
\t\t\t}\n
\t\t}\n
\t\treturn this;\n
\t};\n
\n
}());\n
\n
\n
$.SvgCanvas = function(container, config)\n
{\n
var isOpera = !!window.opera,\n
\tisWebkit = navigator.userAgent.indexOf("AppleWebKit") != -1,\n
\tsupport = {},\n
\n
// this defines which elements and attributes that we support\n
\tsvgWhiteList = {\n
\t// SVG Elements\n
\t"a": ["class", "clip-path", "clip-rule", "fill", "fill-opacity", "fill-rule", "filter", "id", "mask", "opacity", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform", "xlink:href", "xlink:title"],\n
\t"circle": ["class", "clip-path", "clip-rule", "cx", "cy", "fill", "fill-opacity", "fill-rule", "filter", "id", "mask", "opacity", "r", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"clipPath": ["class", "clipPathUnits", "id"],\n
\t"defs": [],\n
\t"desc": [],\n
\t"ellipse": ["class", "clip-path", "clip-rule", "cx", "cy", "fill", "fill-opacity", "fill-rule", "filter", "id", "mask", "opacity", "requiredFeatures", "rx", "ry", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"feGaussianBlur": ["class", "color-interpolation-filters", "id", "requiredFeatures", "stdDeviation"],\n
\t"filter": ["class", "color-interpolation-filters", "filterRes", "filterUnits", "height", "id", "primitiveUnits", "requiredFeatures", "width", "x", "xlink:href", "y"],\n
\t"foreignObject": ["class", "font-size", "height", "id", "opacity", "requiredFeatures", "style", "transform", "width", "x", "y"],\n
\t"g": ["class", "clip-path", "clip-rule", "id", "display", "fill", "fill-opacity", "fill-rule", "filter", "mask", "opacity", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"image": ["class", "clip-path", "clip-rule", "filter", "height", "id", "mask", "opacity", "requiredFeatures", "style", "systemLanguage", "transform", "width", "x", "xlink:href", "xlink:title", "y"],\n
\t"line": ["class", "clip-path", "clip-rule", "fill", "fill-opacity", "fill-rule", "filter", "id", "marker-end", "marker-mid", "marker-start", "mask", "opacity", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform", "x1", "x2", "y1", "y2"],\n
\t"linearGradient": ["class", "id", "gradientTransform", "gradientUnits", "requiredFeatures", "spreadMethod", "systemLanguage", "x1", "x2", "xlink:href", "y1", "y2"],\n
\t"marker": ["id", "class", "markerHeight", "markerUnits", "markerWidth", "orient", "preserveAspectRatio", "refX", "refY", "systemLanguage", "viewBox"],\n
\t"mask": ["class", "height", "id", "maskContentUnits", "maskUnits", "width", "x", "y"],\n
\t"metadata": ["class", "id"],\n
\t"path": ["class", "clip-path", "clip-rule", "d", "fill", "fill-opacity", "fill-rule", "filter", "id", "marker-end", "marker-mid", "marker-start", "mask", "opacity", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"pattern": ["class", "height", "id", "patternContentUnits", "patternTransform", "patternUnits", "requiredFeatures", "style", "systemLanguage", "width", "x", "xlink:href", "y"],\n
\t"polygon": ["class", "clip-path", "clip-rule", "id", "fill", "fill-opacity", "fill-rule", "filter", "id", "class", "marker-end", "marker-mid", "marker-start", "mask", "opacity", "points", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"polyline": ["class", "clip-path", "clip-rule", "id", "fill", "fill-opacity", "fill-rule", "filter", "marker-end", "marker-mid", "marker-start", "mask", "opacity", "points", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform"],\n
\t"radialGradient": ["class", "cx", "cy", "fx", "fy", "gradientTransform", "gradientUnits", "id", "r", "requiredFeatures", "spreadMethod", "systemLanguage", "xlink:href"],\n
\t"rect": ["class", "clip-path", "clip-rule", "fill", "fill-opacity", "fill-rule", "filter", "height", "id", "mask", "opacity", "requiredFeatures", "rx", "ry", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform", "width", "x", "y"],\n
\t"stop": ["class", "id", "offset", "requiredFeatures", "stop-color", "stop-opacity", "style", "systemLanguage"],\n
\t"svg": ["class", "clip-path", "clip-rule", "filter", "id", "height", "mask", "preserveAspectRatio", "requiredFeatures", "style", "systemLanguage", "viewBox", "width", "x", "xmlns", "xmlns:se", "xmlns:xlink", "y"],\n
\t"switch": ["class", "id", "requiredFeatures", "systemLanguage"],\n
\t"symbol": ["class", "fill", "fill-opacity", "fill-rule", "filter", "font-family", "font-size", "font-style", "font-weight", "id", "opacity", "preserveAspectRatio", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "transform", "viewBox"],\n
\t"text": ["class", "clip-path", "clip-rule", "fill", "fill-opacity", "fill-rule", "filter", "font-family", "font-size", "font-style", "font-weight", "id", "mask", "opacity", "requiredFeatures", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "text-anchor", "transform", "x", "xml:space", "y"],\n
\t"textPath": ["class", "id", "method", "requiredFeatures", "spacing", "startOffset", "style", "systemLanguage", "transform", "xlink:href"],\n
\t"title": [],\n
\t"tspan": ["class", "clip-path", "clip-rule", "dx", "dy", "fill", "fill-opacity", "fill-rule", "filter", "font-family", "font-size", "font-style", "font-weight", "id", "mask", "opacity", "requiredFeatures", "rotate", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "systemLanguage", "text-anchor", "textLength", "transform", "x", "xml:space", "y"],\n
\t"use": ["class", "clip-path", "clip-rule", "fill", "fill-opacity", "fill-rule", "filter", "height", "id", "mask", "stroke", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width", "style", "transform", "width", "x", "xlink:href", "y"],\n
\t\n
\t// MathML Elements\n
\t"annotation": ["encoding"],\n
\t"annotation-xml": ["encoding"],\n
\t"maction": ["actiontype", "other", "selection"],\n
\t"math": ["class", "id", "display", "xmlns"],\n
\t"merror": [],\n
\t"mfrac": ["linethickness"],\n
\t"mi": ["mathvariant"],\n
\t"mmultiscripts": [],\n
\t"mn": [],\n
\t"mo": ["fence", "lspace", "maxsize", "minsize", "rspace", "stretchy"],\n
\t"mover": [],\n
\t"mpadded": ["lspace", "width"],\n
\t"mphantom": [],\n
\t"mprescripts": [],\n
\t"mroot": [],\n
\t"mrow": ["xlink:href", "xlink:type", "xmlns:xlink"],\n
\t"mspace": ["depth", "height", "width"],\n
\t"msqrt": [],\n
\t"mstyle": ["displaystyle", "mathbackground", "mathcolor", "mathvariant", "scriptlevel"],\n
\t"msub": [],\n
\t"msubsup": [],\n
\t"msup": [],\n
\t"mtable": ["align", "columnalign", "columnlines", "columnspacing", "displaystyle", "equalcolumns", "equalrows", "frame", "rowalign", "rowlines", "rowspacing", "width"],\n
\t"mtd": ["columnalign", "columnspan", "rowalign", "rowspan"],\n
\t"mtext": [],\n
\t"mtr": ["columnalign", "rowalign"],\n
\t"munder": [],\n
\t"munderover": [],\n
\t"none": [],\n
\t"semantics": []\n
\t},\n
\n
\n
// console.log(\'Start profiling\')\n
// setTimeout(function() {\n
// \tcanvas.addToSelection(canvas.getVisibleElements());\n
// \tconsole.log(\'Stop profiling\')\n
// },3000);\n
\n
\n
\tuiStrings = {\n
\t\t"pathNodeTooltip": "Drag node to move it. Double-click node to change segment type",\n
\t\t"pathCtrlPtTooltip": "Drag control point to adjust curve properties",\n
\t\t"exportNoBlur": "Blurred elements will appear as un-blurred",\n
\t\t"exportNoImage": "Image elements will not appear",\n
\t\t"exportNoforeignObject": "foreignObject elements will not appear",\n
\t\t"exportNoDashArray": "Strokes will appear filled",\n
\t\t"exportNoText": "Text may not appear as expected"\n
\t},\n
\t\n
\tcurConfig = {\n
\t\tshow_outside_canvas: true,\n
\t\tdimensions: [640, 480]\n
\t},\n
\t\n
\ttoXml = function(str) {\n
\t\treturn $(\'<p/>\').text(str).html();\n
\t},\n
\t\n
\tfromXml = function(str) {\n
\t\treturn $(\'<p/>\').html(str).text();\n
\t};\n
\n
\tif(config) {\n
\t\t$.extend(curConfig, config);\n
\t}\n
\n
\tvar unit_types = {\'em\':0,\'ex\':0,\'px\':1,\'cm\':35.43307,\'mm\':3.543307,\'in\':90,\'pt\':1.25,\'pc\':15,\'%\':0};\n
\t\n
// These command objects are used for the Undo/Redo stack\n
// attrs contains the values that the attributes had before the change\n
function ChangeElementCommand(elem, attrs, text) {\n
\tthis.elem = elem;\n
\tthis.text = text ? ("Change " + elem.tagName + " " + text) : ("Change " + elem.tagName);\n
\tthis.newValues = {};\n
\tthis.oldValues = attrs;\n
\tfor (var attr in attrs) {\n
\t\tif (attr == "#text") this.newValues[attr] = elem.textContent;\n
\t\telse if (attr == "#href") this.newValues[attr] = elem.getAttributeNS(xlinkns, "href");\n
\t\telse this.newValues[attr] = elem.getAttribute(attr);\n
\t}\n
\n
\tthis.apply = function() {\n
\t\tvar bChangedTransform = false;\n
\t\tfor(var attr in this.newValues ) {\n
\t\t\tif (this.newValues[attr]) {\n
\t\t\t\tif (attr == "#text") this.elem.textContent = this.newValues[attr];\n
\t\t\t\telse if (attr == "#href") this.elem.setAttributeNS(xlinkns, "xlink:href", this.newValues[attr])\n
\t\t\t\telse this.elem.setAttribute(attr, this.newValues[attr]);\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tif (attr == "#text") this.elem.textContent = "";\n
\t\t\t\telse {\n
\t\t\t\t\tthis.elem.setAttribute(attr, "");\n
\t\t\t\t\tthis.elem.removeAttribute(attr);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tif (attr == "transform") { bChangedTransform = true; }\n
\t\t\telse if (attr == "stdDeviation") { canvas.setBlurOffsets(this.elem.parentNode, this.newValues[attr]); }\n
\t\t\t\n
\t\t}\n
\t\t// relocate rotational transform, if necessary\n
\t\tif(!bChangedTransform) {\n
\t\t\tvar angle = canvas.getRotationAngle(elem);\n
\t\t\tif (angle) {\n
\t\t\t\tvar bbox = elem.getBBox();\n
\t\t\t\tvar cx = bbox.x + bbox.width/2,\n
\t\t\t\t\tcy = bbox.y + bbox.height/2;\n
\t\t\t\tvar rotate = ["rotate(", angle, " ", cx, ",", cy, ")"].join(\'\');\n
\t\t\t\tif (rotate != elem.getAttribute("transform")) {\n
\t\t\t\t\telem.setAttribute("transform", rotate);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// if we are changing layer names, re-identify all layers\n
\t\tif (this.elem.tagName == "title" && this.elem.parentNode.parentNode == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t\treturn true;\n
\t};\n
\n
\tthis.unapply = function() {\n
\t\tvar bChangedTransform = false;\n
\t\tfor(var attr in this.oldValues ) {\n
\t\t\tif (this.oldValues[attr]) {\n
\t\t\t\tif (attr == "#text") this.elem.textContent = this.oldValues[attr];\n
\t\t\t\telse if (attr == "#href") this.elem.setAttributeNS(xlinkns, "xlink:href", this.oldValues[attr]);\n
\t\t\t\telse this.elem.setAttribute(attr, this.oldValues[attr]);\n
\t\t\t\t\n
\t\t\t\tif (attr == "stdDeviation") canvas.setBlurOffsets(this.elem.parentNode, this.oldValues[attr]);\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tif (attr == "#text") this.elem.textContent = "";\n
\t\t\t\telse this.elem.removeAttribute(attr);\n
\t\t\t}\n
\t\t\tif (attr == "transform") { bChangedTransform = true; }\n
\t\t}\n
\t\t// relocate rotational transform, if necessary\n
\t\tif(!bChangedTransform) {\n
\t\t\tvar angle = canvas.getRotationAngle(elem);\n
\t\t\tif (angle) {\n
\t\t\t\tvar bbox = elem.getBBox();\n
\t\t\t\tvar cx = bbox.x + bbox.width/2,\n
\t\t\t\t\tcy = bbox.y + bbox.height/2;\n
\t\t\t\tvar rotate = ["rotate(", angle, " ", cx, ",", cy, ")"].join(\'\');\n
\t\t\t\tif (rotate != elem.getAttribute("transform")) {\n
\t\t\t\t\telem.setAttribute("transform", rotate);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// if we are changing layer names, re-identify all layers\n
\t\tif (this.elem.tagName == "title" && this.elem.parentNode.parentNode == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t\t\n
\t\t// Remove transformlist to prevent confusion that causes bugs like 575.\n
\t\tif (svgTransformLists[this.elem.id]) {\n
\t\t\tdelete svgTransformLists[this.elem.id];\n
\t\t}\t\n
\t\t\n
\t\treturn true;\n
\t};\n
\n
\tthis.elements = function() { return [this.elem]; }\n
}\n
\n
function InsertElementCommand(elem, text) {\n
\tthis.elem = elem;\n
\tthis.text = text || ("Create " + elem.tagName);\n
\tthis.parent = elem.parentNode;\n
\n
\tthis.apply = function() { \n
\t\tthis.elem = this.parent.insertBefore(this.elem, this.elem.nextSibling); \n
\t\tif (this.parent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t};\n
\n
\tthis.unapply = function() {\n
\t\tthis.parent = this.elem.parentNode;\n
\t\tthis.elem = this.elem.parentNode.removeChild(this.elem);\n
\t\tif (this.parent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t};\n
\n
\tthis.elements = function() { return [this.elem]; };\n
}\n
\n
// this is created for an element that has or will be removed from the DOM\n
// (creating this object does not remove the element from the DOM itself)\n
function RemoveElementCommand(elem, parent, text) {\n
\tthis.elem = elem;\n
\tthis.text = text || ("Delete " + elem.tagName);\n
\tthis.parent = parent;\n
\n
\tthis.apply = function() {\t\n
\t\tif (svgTransformLists[this.elem.id]) {\n
\t\t\tdelete svgTransformLists[this.elem.id];\n
\t\t}\t\n
\t\n
\t\tthis.parent = this.elem.parentNode;\n
\t\tthis.elem = this.parent.removeChild(this.elem);\n
\t\tif (this.parent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t};\n
\n
\tthis.unapply = function() { \n
\t\tif (svgTransformLists[this.elem.id]) {\n
\t\t\tdelete svgTransformLists[this.elem.id];\n
\t\t}\n
\n
\t\tthis.elem = this.parent.insertBefore(this.elem, this.elem.nextSibling); \n
\t\tif (this.parent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\t\t\n
\t};\n
\n
\tthis.elements = function() { return [this.elem]; };\n
\t\n
\t// special hack for webkit: remove this element\'s entry in the svgTransformLists map\n
\tif (svgTransformLists[elem.id]) {\n
\t\tdelete svgTransformLists[elem.id];\n
\t}\n
\n
}\n
\n
function MoveElementCommand(elem, oldNextSibling, oldParent, text) {\n
\tthis.elem = elem;\n
\tthis.text = text ? ("Move " + elem.tagName + " to " + text) : ("Move " + elem.tagName);\n
\tthis.oldNextSibling = oldNextSibling;\n
\tthis.oldParent = oldParent;\n
\tthis.newNextSibling = elem.nextSibling;\n
\tthis.newParent = elem.parentNode;\n
\n
\tthis.apply = function() {\n
\t\tthis.elem = this.newParent.insertBefore(this.elem, this.newNextSibling);\n
\t\tif (this.newParent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\n
\t};\n
\n
\tthis.unapply = function() {\n
\t\tthis.elem = this.oldParent.insertBefore(this.elem, this.oldNextSibling);\n
\t\tif (this.oldParent == svgcontent) {\n
\t\t\tidentifyLayers();\n
\t\t}\n
\t};\n
\n
\tthis.elements = function() { return [this.elem]; };\n
}\n
\n
// TODO: create a \'typing\' command object that tracks changes in text\n
// if a new Typing command is created and the top command on the stack is also a Typing\n
// and they both affect the same element, then collapse the two commands into one\n
\n
// this command object acts an arbitrary number of subcommands \n
function BatchCommand(text) {\n
\tthis.text = text || "Batch Command";\n
\tthis.stack = [];\n
\n
\tthis.apply = function() {\n
\t\tvar len = this.stack.length;\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tthis.stack[i].apply();\n
\t\t}\n
\t};\n
\n
\tthis.unapply = function() {\n
\t\tfor (var i = this.stack.length-1; i >= 0; i--) {\n
\t\t\tthis.stack[i].unapply();\n
\t\t}\n
\t};\n
\n
\tthis.elements = function() {\n
\t\t// iterate through all our subcommands and find all the elements we are changing\n
\t\tvar elems = [];\n
\t\tvar cmd = this.stack.length;\n
\t\twhile (cmd--) {\n
\t\t\tvar thisElems = this.stack[cmd].elements();\n
\t\t\tvar elem = thisElems.length;\n
\t\t\twhile (elem--) {\n
\t\t\t\tif (elems.indexOf(thisElems[elem]) == -1) elems.push(thisElems[elem]);\n
\t\t\t}\n
\t\t}\n
\t\treturn elems; \n
\t};\n
\n
\tthis.addSubCommand = function(cmd) { this.stack.push(cmd); };\n
\n
\tthis.isEmpty = function() { return this.stack.length == 0; };\n
}\n
\n
// private members\n
\n
\t// **************************************************************************************\n
\tfunction Selector(id, elem) {\n
\t\t// this is the selector\'s unique number\n
\t\tthis.id = id;\n
\n
\t\t// this holds a reference to the element for which this selector is being used\n
\t\tthis.selectedElement = elem;\n
\n
\t\t// this is a flag used internally to track whether the selector is being used or not\n
\t\tthis.locked = true;\n
\n
\t\t// this function is used to reset the id and element that the selector is attached to\n
\t\tthis.reset = function(e, update) {\n
\t\t\tthis.locked = true;\n
\t\t\tthis.selectedElement = e;\n
\t\t\tthis.resize();\n
\t\t\tthis.selectorGroup.setAttribute("display", "inline");\n
\t\t};\n
\n
\t\t// this holds a reference to the <g> element that holds all visual elements of the selector\n
\t\tthis.selectorGroup = addSvgElementFromJson({ "element": "g",\n
\t\t\t\t\t\t\t\t\t\t\t\t\t"attr": {"id": ("selectorGroup"+this.id)}\n
\t\t\t\t\t\t\t\t\t\t\t\t\t});\n
\n
\t\t// this holds a reference to the path rect\n
\t\tthis.selectorRect = this.selectorGroup.appendChild( addSvgElementFromJson({\n
\t\t\t\t\t\t\t\t"element": "path",\n
\t\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t\t"id": ("selectedBox"+this.id),\n
\t\t\t\t\t\t\t\t\t"fill": "none",\n
\t\t\t\t\t\t\t\t\t"stroke": "#22C",\n
\t\t\t\t\t\t\t\t\t"stroke-width": "1",\n
\t\t\t\t\t\t\t\t\t"stroke-dasharray": "5,5",\n
\t\t\t\t\t\t\t\t\t// need to specify this so that the rect is not selectable\n
\t\t\t\t\t\t\t\t\t"style": "pointer-events:none"\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}) );\n
\n
\t\t// this holds a reference to the grip elements for this selector\n
\t\tthis.selectorGrips = {\t"nw":null,\n
\t\t\t\t\t\t\t\t"n":null,\n
\t\t\t\t\t\t\t\t"ne":null,\n
\t\t\t\t\t\t\t\t"e":null,\n
\t\t\t\t\t\t\t\t"se":null,\n
\t\t\t\t\t\t\t\t"s":null,\n
\t\t\t\t\t\t\t\t"sw":null,\n
\t\t\t\t\t\t\t\t"w":null\n
\t\t\t\t\t\t\t\t};\n
\t\tthis.rotateGripConnector = this.selectorGroup.appendChild( addSvgElementFromJson({\n
\t\t\t\t\t\t\t"element": "line",\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"id": ("selectorGrip_rotateconnector_" + this.id),\n
\t\t\t\t\t\t\t\t"stroke": "#22C",\n
\t\t\t\t\t\t\t\t"stroke-width": "1"\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}) );\n
\t\t\t\t\t\t\n
\t\tthis.rotateGrip = this.selectorGroup.appendChild( addSvgElementFromJson({\n
\t\t\t\t\t\t\t"element": "circle",\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"id": ("selectorGrip_rotate_" + this.id),\n
\t\t\t\t\t\t\t\t"fill": "lime",\n
\t\t\t\t\t\t\t\t"r": 4,\n
\t\t\t\t\t\t\t\t"stroke": "#22C",\n
\t\t\t\t\t\t\t\t"stroke-width": 2,\n
\t\t\t\t\t\t\t\t"style": "cursor:url(" + curConfig.imgPath + "rotate.png) 12 12, auto;"\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}) );\n
\t\t\n
\t\t// add the corner grips\n
\t\tfor (var dir in this.selectorGrips) {\n
\t\t\tthis.selectorGrips[dir] = this.selectorGroup.appendChild( \n
\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t"element": "circle",\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"id": ("selectorGrip_resize_" + dir + "_" + this.id),\n
\t\t\t\t\t\t"fill": "#22C",\n
\t\t\t\t\t\t"r": 4,\n
\t\t\t\t\t\t"style": ("cursor:" + dir + "-resize"),\n
\t\t\t\t\t\t// This expands the mouse-able area of the grips making them\n
\t\t\t\t\t\t// easier to grab with the mouse.\n
\t\t\t\t\t\t// This works in Opera and WebKit, but does not work in Firefox\n
\t\t\t\t\t\t// see https://bugzilla.mozilla.org/show_bug.cgi?id=500174\n
\t\t\t\t\t\t"stroke-width": 2,\n
\t\t\t\t\t\t"pointer-events":"all",\n
\t\t\t\t\t\t"display":"none"\n
\t\t\t\t\t}\n
\t\t\t\t}) );\n
\t\t}\n
\n
\t\tthis.showGrips = function(show) {\n
\t\t\t// TODO: use suspendRedraw() here\n
\t\t\tvar bShow = show ? "inline" : "none";\n
\t\t\tthis.rotateGrip.setAttribute("display", bShow);\n
\t\t\tthis.rotateGripConnector.setAttribute("display", bShow);\n
\t\t\tvar elem = this.selectedElement;\n
\t\t\tfor (var dir in this.selectorGrips) {\n
\t\t\t\tthis.selectorGrips[dir].setAttribute("display", bShow);\n
\t\t\t}\n
\t\t\tif(elem) this.updateGripCursors(canvas.getRotationAngle(elem));\n
\t\t};\n
\t\t\n
\t\t// Updates cursors for corner grips on rotation so arrows point the right way\n
\t\tthis.updateGripCursors = function(angle) {\n
\t\t\tvar dir_arr = [];\n
\t\t\tvar steps = Math.round(angle / 45);\n
\t\t\tif(steps < 0) steps += 8;\n
\t\t\tfor (var dir in this.selectorGrips) {\n
\t\t\t\tdir_arr.push(dir);\n
\t\t\t}\n
\t\t\twhile(steps > 0) {\n
\t\t\t\tdir_arr.push(dir_arr.shift());\n
\t\t\t\tsteps--;\n
\t\t\t}\n
\t\t\tvar i = 0;\n
\t\t\tfor (var dir in this.selectorGrips) {\n
\t\t\t\tthis.selectorGrips[dir].setAttribute(\'style\', ("cursor:" + dir_arr[i] + "-resize"));\n
\t\t\t\ti++;\n
\t\t\t};\n
\t\t};\n
\t\t\n
\t\tthis.resize = function() {\n
\t\t\tvar selectedBox = this.selectorRect,\n
\t\t\t\tselectedGrips = this.selectorGrips,\n
\t\t\t\tselected = this.selectedElement,\n
\t\t\t\t sw = selected.getAttribute("stroke-width");\n
\t\t\tvar offset = 1/current_zoom;\n
\t\t\tif (selected.getAttribute("stroke") != "none" && !isNaN(sw)) {\n
\t\t\t\toffset += (sw/2);\n
\t\t\t}\n
\t\t\tif (selected.tagName == "text") {\n
\t\t\t\toffset += 2/current_zoom;\n
\t\t\t}\n
\t\t\tvar bbox = canvas.getBBox(selected);\n
\t\t\tif(selected.tagName == \'g\') {\n
\t\t\t\t// The bbox for a group does not include stroke vals, so we\n
\t\t\t\t// get the bbox based on its children. \n
\t\t\t\tvar stroked_bbox = canvas.getStrokedBBox(selected.childNodes);\n
\t\t\t\t$.each(bbox, function(key, val) {\n
\t\t\t\t\tbbox[key] = stroked_bbox[key];\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\t// loop and transform our bounding box until we reach our first rotation\n
\t\t\tvar m = getMatrix(selected);\n
\n
\t\t\t// This should probably be handled somewhere else, but for now\n
\t\t\t// it keeps the selection box correctly positioned when zoomed\n
\t\t\tm.e *= current_zoom;\n
\t\t\tm.f *= current_zoom;\n
\t\t\t\n
\t\t\t// apply the transforms\n
\t\t\tvar l=bbox.x-offset, t=bbox.y-offset, w=bbox.width+(offset*2), h=bbox.height+(offset*2),\n
\t\t\t\tbbox = {x:l, y:t, width:w, height:h};\n
\t\t\t\n
\t\t\t// we need to handle temporary transforms too\n
\t\t\t// if skewed, get its transformed box, then find its axis-aligned bbox\n
\t\t\t\n
\t\t\t//*\n
\t\t\tvar nbox = transformBox(l*current_zoom, t*current_zoom, w*current_zoom, h*current_zoom, m),\n
\t\t\t\tnbax = nbox.aabox.x,\n
\t\t\t\tnbay = nbox.aabox.y,\n
\t\t\t\tnbaw = nbox.aabox.width,\n
\t\t\t\tnbah = nbox.aabox.height;\n
\t\t\t\t\n
\t\t\t// now if the shape is rotated, un-rotate it\n
\t\t\tvar cx = nbax + nbaw/2,\n
\t\t\t\tcy = nbay + nbah/2;\n
\t\t\tvar angle = canvas.getRotationAngle(selected);\n
\t\t\tif (angle) {\n
\t\t\t\t\n
\t\t\t\tvar rot = svgroot.createSVGTransform();\n
\t\t\t\trot.setRotate(-angle,cx,cy);\n
\t\t\t\tvar rotm = rot.matrix;\n
\t\t\t\tnbox.tl = transformPoint(nbox.tl.x,nbox.tl.y,rotm);\n
\t\t\t\tnbox.tr = transformPoint(nbox.tr.x,nbox.tr.y,rotm);\n
\t\t\t\tnbox.bl = transformPoint(nbox.bl.x,nbox.bl.y,rotm);\n
\t\t\t\tnbox.br = transformPoint(nbox.br.x,nbox.br.y,rotm);\n
\t\t\t\t\n
\t\t\t\t// calculate the axis-aligned bbox\n
\t\t\t\tvar minx = nbox.tl.x,\n
\t\t\t\t\tminy = nbox.tl.y,\n
\t\t\t\t\tmaxx = nbox.tl.x,\n
\t\t\t\t\tmaxy = nbox.tl.y;\n
\t\t\t\t\n
\t\t\t\tminx = Math.min(minx, Math.min(nbox.tr.x, Math.min(nbox.bl.x, nbox.br.x) ) );\n
\t\t\t\tminy = Math.min(miny, Math.min(nbox.tr.y, Math.min(nbox.bl.y, nbox.br.y) ) );\n
\t\t\t\tmaxx = Math.max(maxx, Math.max(nbox.tr.x, Math.max(nbox.bl.x, nbox.br.x) ) );\n
\t\t\t\tmaxy = Math.max(maxy, Math.max(nbox.tr.y, Math.max(nbox.bl.y, nbox.br.y) ) );\n
\t\t\t\t\n
\t\t\t\tnbax = minx;\n
\t\t\t\tnbay = miny;\n
\t\t\t\tnbaw = (maxx-minx);\n
\t\t\t\tnbah = (maxy-miny);\n
\t\t\t}\n
\n
\t\t\tvar sr_handle = svgroot.suspendRedraw(100);\n
\n
\t\t\tvar dstr = "M" + nbax + "," + nbay\n
\t\t\t\t\t\t+ " L" + (nbax+nbaw) + "," + nbay\n
\t\t\t\t\t\t+ " " + (nbax+nbaw) + "," + (nbay+nbah)\n
\t\t\t\t\t\t+ " " + nbax + "," + (nbay+nbah) + "z";\n
\t\t\tassignAttributes(selectedBox, {\'d\': dstr});\n
\t\t\t\n
\t\t\tvar gripCoords = {\n
\t\t\t\tnw: [nbax, nbay],\n
\t\t\t\tne: [nbax+nbaw, nbay],\n
\t\t\t\tsw: [nbax, nbay+nbah],\n
\t\t\t\tse: [nbax+nbaw, nbay+nbah],\n
\t\t\t\tn:  [nbax + (nbaw)/2, nbay],\n
\t\t\t\tw:\t[nbax, nbay + (nbah)/2],\n
\t\t\t\te:\t[nbax + nbaw, nbay + (nbah)/2],\n
\t\t\t\ts:\t[nbax + (nbaw)/2, nbay + nbah]\n
\t\t\t};\n
\t\t\t\n
\t\t\tif(selected == selectedElements[0]) {\n
\t\t\t\tfor(var dir in gripCoords) {\n
\t\t\t\t\tvar coords = gripCoords[dir];\n
\t\t\t\t\tassignAttributes(selectedGrips[dir], {\n
\t\t\t\t\t\tcx: coords[0], cy: coords[1]\n
\t\t\t\t\t});\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\tif (angle) {\n
\t\t\t\tthis.selectorGroup.setAttribute("transform", "rotate(" + [angle,cx,cy].join(",") + ")");\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tthis.selectorGroup.setAttribute("transform", "");\n
\t\t\t}\n
\n
\t\t\t// we want to go 20 pixels in the negative transformed y direction, ignoring scale\n
\t\t\tassignAttributes(this.rotateGripConnector, { x1: nbax + (nbaw)/2, \n
\t\t\t\t\t\t\t\t\t\t\t\t\t\ty1: nbay, \n
\t\t\t\t\t\t\t\t\t\t\t\t\t\tx2: nbax + (nbaw)/2, \n
\t\t\t\t\t\t\t\t\t\t\t\t\t\ty2: nbay- 20});\n
\t\t\tassignAttributes(this.rotateGrip, { cx: nbax + (nbaw)/2, \n
\t\t\t\t\t\t\t\t\t\t\t\tcy: nbay - 20 });\n
\t\t\t\n
\t\t\tsvgroot.unsuspendRedraw(sr_handle);\n
\t\t};\n
\n
\t\t// now initialize the selector\n
\t\tthis.reset(elem);\n
\t};\n
\n
\tfunction SelectorManager() {\n
\n
\t\t// this will hold the <g> element that contains all selector rects/grips\n
\t\tthis.selectorParentGroup = null;\n
\n
\t\t// this is a special rect that is used for multi-select\n
\t\tthis.rubberBandBox = null;\n
\n
\t\t// this will hold objects of type Selector (see above)\n
\t\tthis.selectors = [];\n
\n
\t\t// this holds a map of SVG elements to their Selector object\n
\t\tthis.selectorMap = {};\n
\n
\t\t// local reference to this object\n
\t\tvar mgr = this;\n
\n
\t\tthis.initGroup = function() {\n
\t\t\t// remove old selector parent group if it existed\n
\t\t\tif (mgr.selectorParentGroup && mgr.selectorParentGroup.parentNode) {\n
\t\t\t\tmgr.selectorParentGroup.parentNode.removeChild(mgr.selectorParentGroup);\n
\t\t\t}\n
\t\t\t// create parent selector group and add it to svgroot\n
\t\t\tmgr.selectorParentGroup = svgdoc.createElementNS(svgns, "g");\n
\t\t\tmgr.selectorParentGroup.setAttribute("id", "selectorParentGroup");\n
\t\t\tsvgroot.appendChild(mgr.selectorParentGroup);\n
\t\t\tmgr.selectorMap = {};\n
\t\t\tmgr.selectors = [];\n
\t\t\tmgr.rubberBandBox = null;\n
\t\t\t\n
\t\t\tif($("#canvasBackground").length) return;\n
\n
\t\t\tvar canvasbg = svgdoc.createElementNS(svgns, "svg");\n
\t\t\tvar dims = curConfig.dimensions;\n
\t\t\tassignAttributes(canvasbg, {\n
\t\t\t\t\'id\':\'canvasBackground\',\n
\t\t\t\t\'width\': dims[0],\n
\t\t\t\t\'height\': dims[1],\n
\t\t\t\t\'x\': 0,\n
\t\t\t\t\'y\': 0,\n
\t\t\t\t\'overflow\': \'visible\',\n
\t\t\t\t\'style\': \'pointer-events:none\'\n
\t\t\t});\n
\t\t\t\n
\t\t\tvar rect = svgdoc.createElementNS(svgns, "rect");\n
\t\t\tassignAttributes(rect, {\n
\t\t\t\t\'width\': \'100%\',\n
\t\t\t\t\'height\': \'100%\',\n
\t\t\t\t\'x\': 0,\n
\t\t\t\t\'y\': 0,\n
\t\t\t\t\'stroke-width\': 1,\n
\t\t\t\t\'stroke\': \'#000\',\n
\t\t\t\t\'fill\': \'#FFF\',\n
\t\t\t\t\'style\': \'pointer-events:none\'\n
\t\t\t});\n
\t\t\t// Both Firefox and WebKit are too slow with this filter region (especially at higher\n
\t\t\t// zoom levels) and Opera has at least one bug\n
//\t\t\tif (!window.opera) rect.setAttribute(\'filter\', \'url(#canvashadow)\');\n
\t\t\tcanvasbg.appendChild(rect);\n
\t\t\tsvgroot.insertBefore(canvasbg, svgcontent);\n
\t\t};\n
\n
\t\tthis.requestSelector = function(elem) {\n
\t\t\tif (elem == null) return null;\n
\t\t\tvar N = this.selectors.length;\n
\t\t\t// if we\'ve already acquired one for this element, return it\n
\t\t\tif (typeof(this.selectorMap[elem.id]) == "object") {\n
\t\t\t\tthis.selectorMap[elem.id].locked = true;\n
\t\t\t\treturn this.selectorMap[elem.id];\n
\t\t\t}\n
\t\t\tfor (var i = 0; i < N; ++i) {\n
\t\t\t\tif (this.selectors[i] && !this.selectors[i].locked) {\n
\t\t\t\t\tthis.selectors[i].locked = true;\n
\t\t\t\t\tthis.selectors[i].reset(elem);\n
\t\t\t\t\tthis.selectorMap[elem.id] = this.selectors[i];\n
\t\t\t\t\treturn this.selectors[i];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// if we reached here, no available selectors were found, we create one\n
\t\t\tthis.selectors[N] = new Selector(N, elem);\n
\t\t\tthis.selectorParentGroup.appendChild(this.selectors[N].selectorGroup);\n
\t\t\tthis.selectorMap[elem.id] = this.selectors[N];\n
\t\t\treturn this.selectors[N];\n
\t\t};\n
\t\tthis.releaseSelector = function(elem) {\n
\t\t\tif (elem == null) return;\n
\t\t\tvar N = this.selectors.length,\n
\t\t\t\tsel = this.selectorMap[elem.id];\n
\t\t\tfor (var i = 0; i < N; ++i) {\n
\t\t\t\tif (this.selectors[i] && this.selectors[i] == sel) {\n
\t\t\t\t\tif (sel.locked == false) {\n
\t\t\t\t\t\tconsole.log("WARNING! selector was released but was already unlocked");\n
\t\t\t\t\t}\n
\t\t\t\t\tdelete this.selectorMap[elem.id];\n
\t\t\t\t\tsel.locked = false;\n
\t\t\t\t\tsel.selectedElement = null;\n
\t\t\t\t\tsel.showGrips(false);\n
\n
\t\t\t\t\t// remove from DOM and store reference in JS but only if it exists in the DOM\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\tsel.selectorGroup.setAttribute("display", "none");\n
\t\t\t\t\t} catch(e) { }\n
\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\n
\t\tthis.getRubberBandBox = function() {\n
\t\t\tif (this.rubberBandBox == null) {\n
\t\t\t\tthis.rubberBandBox = this.selectorParentGroup.appendChild(\n
\t\t\t\t\t\taddSvgElementFromJson({ "element": "rect",\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"id": "selectorRubberBand",\n
\t\t\t\t\t\t\t\t"fill": "#22C",\n
\t\t\t\t\t\t\t\t"fill-opacity": 0.15,\n
\t\t\t\t\t\t\t\t"stroke": "#22C",\n
\t\t\t\t\t\t\t\t"stroke-width": 0.5,\n
\t\t\t\t\t\t\t\t"display": "none",\n
\t\t\t\t\t\t\t\t"style": "pointer-events:none"\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}));\n
\t\t\t}\n
\t\t\treturn this.rubberBandBox;\n
\t\t};\n
\n
\t\tthis.initGroup();\n
\t}\n
\t// **************************************************************************************\n
\n
\t// **************************************************************************************\n
\t// SVGTransformList implementation for Webkit \n
\t// These methods do not currently raise any exceptions.\n
\t// These methods also do not check that transforms are being inserted or handle if\n
\t// a transform is already in the list, etc.  This is basically implementing as much\n
\t// of SVGTransformList that we need to get the job done.\n
\t//\n
\t//  interface SVGEditTransformList { \n
\t//\t\tattribute unsigned long numberOfItems;\n
\t//\t\tvoid   clear (  )\n
\t//\t\tSVGTransform initialize ( in SVGTransform newItem )\n
\t//\t\tSVGTransform getItem ( in unsigned long index )\n
\t//\t\tSVGTransform insertItemBefore ( in SVGTransform newItem, in unsigned long index )\n
\t//\t\tSVGTransform replaceItem ( in SVGTransform newItem, in unsigned long index )\n
\t//\t\tSVGTransform removeItem ( in unsigned long index )\n
\t//\t\tSVGTransform appendItem ( in SVGTransform newItem )\n
\t//\t\tNOT IMPLEMENTED: SVGTransform createSVGTransformFromMatrix ( in SVGMatrix matrix );\n
\t//\t\tNOT IMPLEMENTED: SVGTransform consolidate (  );\n
\t//\t}\n
\t// **************************************************************************************\n
\tvar svgTransformLists = {};\n
\tvar SVGEditTransformList = function(elem) {\n
\t\tthis._elem = elem || null;\n
\t\tthis._xforms = [];\n
\t\t// TODO: how do we capture the undo-ability in the changed transform list?\n
\t\tthis._update = function() {\n
\t\t\tvar tstr = "";\n
\t\t\tvar concatMatrix = svgroot.createSVGMatrix();\n
\t\t\tfor (var i = 0; i < this.numberOfItems; ++i) {\n
\t\t\t\tvar xform = this._list.getItem(i);\n
\t\t\t\ttstr += transformToObj(xform).text + " ";\n
\t\t\t}\n
\t\t\tthis._elem.setAttribute("transform", tstr);\n
\t\t};\n
\t\tthis._list = this;\n
\t\tthis._init = function() {\n
\t\t\t// Transform attribute parser\n
\t\t\tvar str = this._elem.getAttribute("transform");\n
\t\t\tif(!str) return;\n
\t\t\t\n
\t\t\t// TODO: Add skew support in future\n
\t\t\tvar re = /\\s*((scale|matrix|rotate|translate)\\s*\\(.*?\\))\\s*,?\\s*/;\n
\t\t\tvar arr = [];\n
\t\t\tvar m = true;\n
\t\t\twhile(m) {\n
\t\t\t\tm = str.match(re);\n
\t\t\t\tstr = str.replace(re,\'\');\n
\t\t\t\tif(m && m[1]) {\n
\t\t\t\t\tvar x = m[1];\n
\t\t\t\t\tvar bits = x.split(/\\s*\\(/);\n
\t\t\t\t\tvar name = bits[0];\n
\t\t\t\t\tvar val_bits = bits[1].match(/\\s*(.*?)\\s*\\)/);\n
\t\t\t\t\tvar val_arr = val_bits[1].split(/[, ]+/);\n
\t\t\t\t\tvar letters = \'abcdef\'.split(\'\');\n
\t\t\t\t\tvar mtx = svgroot.createSVGMatrix();\n
\t\t\t\t\t$.each(val_arr, function(i, item) {\n
\t\t\t\t\t\tval_arr[i] = parseFloat(item);\n
\t\t\t\t\t\tif(name == \'matrix\') {\n
\t\t\t\t\t\t\tmtx[letters[i]] = val_arr[i];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tvar xform = svgroot.createSVGTransform();\n
\t\t\t\t\tvar fname = \'set\' + name.charAt(0).toUpperCase() + name.slice(1);\n
\t\t\t\t\tvar values = name==\'matrix\'?[mtx]:val_arr;\n
\t\t\t\t\txform[fname].apply(xform, values);\n
\t\t\t\t\tthis._list.appendItem(xform);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tthis.numberOfItems = 0;\n
\t\tthis.clear = function() { \n
\t\t\tthis.numberOfItems = 0;\n
\t\t\tthis._xforms = [];\n
\t\t};\n
\t\t\n
\t\tthis.initialize = function(newItem) {\n
\t\t\tthis.numberOfItems = 1;\n
\t\t\tthis._xforms = [newItem];\n
\t\t};\n
\t\t\n
\t\tthis.getItem = function(index) {\n
\t\t\tif (index < this.numberOfItems && index >= 0) {\n
\t\t\t\treturn this._xforms[index];\n
\t\t\t}\n
\t\t\treturn null;\n
\t\t};\n
\t\t\n
\t\tthis.insertItemBefore = function(newItem, index) {\n
\t\t\tvar retValue = null;\n
\t\t\tif (index >= 0) {\n
\t\t\t\tif (index < this.numberOfItems) {\n
\t\t\t\t\tvar newxforms = new Array(this.numberOfItems + 1);\n
\t\t\t\t\t// TODO: use array copying and slicing\n
\t\t\t\t\tfor ( var i = 0; i < index; ++i) {\n
\t\t\t\t\t\tnewxforms[i] = this._xforms[i];\n
\t\t\t\t\t}\n
\t\t\t\t\tnewxforms[i] = newItem;\n
\t\t\t\t\tfor ( var j = i+1; i < this.numberOfItems; ++j, ++i) {\n
\t\t\t\t\t\tnewxforms[j] = this._xforms[i];\n
\t\t\t\t\t}\n
\t\t\t\t\tthis.numberOfItems++;\n
\t\t\t\t\tthis._xforms = newxforms;\n
\t\t\t\t\tretValue = newItem;\n
\t\t\t\t\tthis._list._update();\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tretValue = this._list.appendItem(newItem);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn retValue;\n
\t\t};\n
\t\t\n
\t\tthis.replaceItem = function(newItem, index) {\n
\t\t\tvar retValue = null;\n
\t\t\tif (index < this.numberOfItems && index >= 0) {\n
\t\t\t\tthis._xforms[index] = newItem;\n
\t\t\t\tretValue = newItem;\n
\t\t\t\tthis._list._update();\n
\t\t\t}\n
\t\t\treturn retValue;\n
\t\t};\n
\t\t\n
\t\tthis.removeItem = function(index) {\n
\t\t\tvar retValue = null;\n
\t\t\tif (index < this.numberOfItems && index >= 0) {\n
\t\t\t\tvar retValue = this._xforms[index];\n
\t\t\t\tvar newxforms = new Array(this.numberOfItems - 1);\n
\t\t\t\tfor (var i = 0; i < index; ++i) {\n
\t\t\t\t\tnewxforms[i] = this._xforms[i];\n
\t\t\t\t}\n
\t\t\t\tfor (var j = i; j < this.numberOfItems-1; ++j, ++i) {\n
\t\t\t\t\tnewxforms[j] = this._xforms[i+1];\n
\t\t\t\t}\n
\t\t\t\tthis.numberOfItems--;\n
\t\t\t\tthis._xforms = newxforms;\n
\t\t\t\tthis._list._update();\n
\t\t\t}\n
\t\t\treturn retValue;\n
\t\t};\n
\t\t\n
\t\tthis.appendItem = function(newItem) {\n
\t\t\tthis._xforms.push(newItem);\n
\t\t\tthis.numberOfItems++;\n
\t\t\tthis._list._update();\n
\t\t\treturn newItem;\n
\t\t};\n
\t};\n
\t// **************************************************************************************\n
\n
\tvar addSvgElementFromJson = function(data) {\n
\t\treturn canvas.updateElementFromJson(data)\n
\t};\n
\n
\t// TODO: declare the variables and set them as null, then move this setup stuff to\n
\t// an initialization function - probably just use clear()\n
\t\n
\tvar canvas = this,\n
\t\tsvgns = "http://www.w3.org/2000/svg",\n
\t\txlinkns = "http://www.w3.org/1999/xlink",\n
\t\txmlns = "http://www.w3.org/XML/1998/namespace",\n
\t\txmlnsns = "http://www.w3.org/2000/xmlns/", // see http://www.w3.org/TR/REC-xml-names/#xmlReserved\n
\t\tse_ns = "http://svg-edit.googlecode.com",\n
\t\thtmlns = "http://www.w3.org/1999/xhtml",\n
\t\tmathns = "http://www.w3.org/1998/Math/MathML",\n
\t\tidprefix = "svg_",\n
\t\tsvgdoc  = container.ownerDocument,\n
\t\tdimensions = curConfig.dimensions,\n
\t\tsvgroot = svgdoc.importNode(Utils.text2xml(\'<svg id="svgroot" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" \' +\n
\t\t\t\t\t\t\'width="\' + dimensions[0] + \'" height="\' + dimensions[1] + \'" x="\' + dimensions[0] + \'" y="\' + dimensions[1] + \'" overflow="visible">\' +\n
\t\t\t\t\t\t\'<defs>\' +\n
\t\t\t\t\t\t\t\'<filter id="canvashadow" filterUnits="objectBoundingBox">\' +\n
\t\t\t\t\t\t\t\t\'<feGaussianBlur in="SourceAlpha" stdDeviation="4" result="blur"/>\'+\n
\t\t\t\t\t\t\t\t\'<feOffset in="blur" dx="5" dy="5" result="offsetBlur"/>\'+\n
\t\t\t\t\t\t\t\t\'<feMerge>\'+\n
\t\t\t\t\t\t\t\t\t\'<feMergeNode in="offsetBlur"/>\'+\n
\t\t\t\t\t\t\t\t\t\'<feMergeNode in="SourceGraphic"/>\'+\n
\t\t\t\t\t\t\t\t\'</feMerge>\'+\n
\t\t\t\t\t\t\t\'</filter>\'+\n
\t\t\t\t\t\t\'</defs>\'+\n
\t\t\t\t\t\'</svg>\').documentElement, true);\n
\t\t\n
\t\t$(svgroot).appendTo(container);\n
\t\tvar opac_ani = document.createElementNS(svgns, \'animate\');\n
 \t\t$(opac_ani).attr({\n
 \t\t\tattributeName: \'opacity\',\n
 \t\t\tbegin: \'indefinite\',\n
 \t\t\tdur: 1,\n
 \t\t\tfill: \'freeze\'\n
 \t\t}).appendTo(svgroot);\n
\t\n
    //nonce to uniquify id\'s\n
    var nonce = Math.floor(Math.random()*100001);\n
    var randomize_ids = false;\n
    \n
\t// map namespace URIs to prefixes\n
\tvar nsMap = {};\n
\tnsMap[xlinkns] = \'xlink\';\n
\tnsMap[xmlns] = \'xml\';\n
\tnsMap[xmlnsns] = \'xmlns\';\n
\tnsMap[se_ns] = \'se\';\n
\tnsMap[htmlns] = \'xhtml\';\n
\tnsMap[mathns] = \'mathml\';\n
\n
\t// map prefixes to namespace URIs\n
\tvar nsRevMap = {};\n
\t$.each(nsMap, function(key,value){\n
\t\tnsRevMap[value] = key;\n
    });\n
\n
\t// Produce a Namespace-aware version of svgWhitelist\n
\tvar svgWhiteListNS = {};\n
    $.each(svgWhiteList, function(elt,atts){\n
\t\tvar attNS = {};\n
\t\t$.each(atts, function(i, att){\n
\t\t\tif (att.indexOf(\':\') != -1) {\n
\t\t\t\tvar v = att.split(\':\');\n
\t\t\t\tattNS[v[1]] = nsRevMap[v[0]];\n
\t\t\t} else {\n
\t\t\t\tattNS[att] = att == \'xmlns\' ? xmlnsns : null;\n
\t\t\t}\n
\t\t});\n
\t\tsvgWhiteListNS[elt] = attNS;\n
\t});\n
\t\n
\tvar svgcontent = svgdoc.createElementNS(svgns, "svg");\n
\t$(svgcontent).attr({\n
\t\tid: \'svgcontent\',\n
\t\twidth: dimensions[0],\n
\t\theight: dimensions[1],\n
\t\tx: dimensions[0],\n
\t\ty: dimensions[1],\n
\t\toverflow: curConfig.show_outside_canvas?\'visible\':\'hidden\',\n
\t\txmlns: svgns,\n
\t\t"xmlns:se": se_ns,\n
\t\t"xmlns:xlink": xlinkns\n
\t}).appendTo(svgroot);\n
\tif (randomize_ids) svgcontent.setAttributeNS(se_ns, \'se:nonce\', nonce);\n
\n
\tvar convertToNum, convertToUnit, setUnitAttr;\n
\t\n
\t(function() {\n
\t\tvar w_attrs = [\'x\', \'x1\', \'cx\', \'rx\', \'width\'];\n
\t\tvar h_attrs = [\'y\', \'y1\', \'cy\', \'ry\', \'height\'];\n
\t\tvar unit_attrs = $.merge([\'r\',\'radius\'], w_attrs);\n
\t\t$.merge(unit_attrs, h_attrs);\n
\t\t\n
\t\t// Converts given values to numbers. Attributes must be supplied in \n
\t\t// case a percentage is given\n
\t\tconvertToNum = function(attr, val) {\n
\t\t\t// Return a number if that\'s what it already is\n
\t\t\tif(!isNaN(val)) return val-0;\n
\t\t\t\n
\t\t\tif(val.substr(-1) === \'%\') {\n
\t\t\t\t// Deal with percentage, depends on attribute\n
\t\t\t\tvar num = val.substr(0, val.length-1)/100;\n
\t\t\t\tvar res = canvas.getResolution();\n
\t\t\t\t\n
\t\t\t\tif($.inArray(attr, w_attrs) !== -1) {\n
\t\t\t\t\treturn num * res.w;\n
\t\t\t\t} else if($.inArray(attr, h_attrs) !== -1) {\n
\t\t\t\t\treturn num * res.h;\n
\t\t\t\t} else {\n
\t\t\t\t\treturn num * Math.sqrt((res.w*res.w) + (res.h*res.h))/Math.sqrt(2);\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tvar unit = val.substr(-2);\n
\t\t\t\tvar num = val.substr(0, val.length-2);\n
\t\t\t\t// Note that this multiplication turns the string into a number\n
\t\t\t\treturn num * unit_types[unit];\n
\t\t\t}\n
\t\t};\n
\t\t\n
\t\tsetUnitAttr = function(elem, attr, val) {\n
\t\t\tif(!isNaN(val)) {\n
\t\t\t\t// New value is a number, so check currently used unit\n
\t\t\t\tvar old_val = elem.getAttribute(attr);\n
\t\t\t\t\n
\t\t\t\tif(old_val !== null && isNaN(old_val)) {\n
\t\t\t\t\t// Old value was a number, so get unit, then convert\n
\t\t\t\t\tvar unit;\n
\t\t\t\t\tif(old_val.substr(-1) === \'%\') {\n
\t\t\t\t\t\tvar res = canvas.getResolution();\n
\t\t\t\t\t\tunit = \'%\';\n
\t\t\t\t\t\tval *= 100;\n
\t\t\t\t\t\tif($.inArray(attr, w_attrs) !== -1) {\n
\t\t\t\t\t\t\tval = val / res.w;\n
\t\t\t\t\t\t} else if($.inArray(attr, h_attrs) !== -1) {\n
\t\t\t\t\t\t\tval = val / res.h;\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\treturn val / Math.sqrt((res.w*res.w) + (res.h*res.h))/Math.sqrt(2);\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tunit = old_val.substr(-2);\n
\t\t\t\t\t\tval = val / unit_types[unit];\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tval += unit;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\telem.setAttribute(attr, val);\n
\t\t}\n
\t\t\n
\t\tcanvas.isValidUnit = function(attr, val) {\n
\t\t\tvar valid = false;\n
\t\t\tif($.inArray(attr, unit_attrs) != -1) {\n
\t\t\t\t// True if it\'s just a number\n
\t\t\t\tif(!isNaN(val)) {\n
\t\t\t\t\tvalid = true;\n
\t\t\t\t} else {\n
\t\t\t\t// Not a number, check if it has a valid unit\n
\t\t\t\t\tval = val.toLowerCase();\n
\t\t\t\t\t$.each(unit_types, function(unit) {\n
\t\t\t\t\t\tif(valid) return;\n
\t\t\t\t\t\tvar re = new RegExp(\'^-?[\\\\d\\\\.]+\' + unit + \'$\');\n
\t\t\t\t\t\tif(re.test(val)) valid = true;\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t} else if (attr == "id") {\n
\t\t\t\t// if we\'re trying to change the id, make sure it\'s not already present in the doc\n
\t\t\t\t// and the id value is valid.\n
\n
\t\t\t\tvar result = false;\n
\t\t\t\t// because getElem() can throw an exception in the case of an invalid id\n
\t\t\t\t// (according to http://www.w3.org/TR/xml-id/ IDs must be a NCName)\n
\t\t\t\t// we wrap it in an exception and only return true if the ID was valid and\n
\t\t\t\t// not already present\n
\t\t\t\ttry {\n
\t\t\t\t\tvar elem = getElem(val);\n
\t\t\t\t\tresult = (elem == null);\n
\t\t\t\t} catch(e) {}\n
\t\t\t\treturn result;\n
\t\t\t} else valid = true;\t\t\t\n
\t\t\t\n
\t\t\treturn valid;\n
\t\t}\n
\t\t\n
\t})();\n
\n
\tvar assignAttributes = function(node, attrs, suspendLength, unitCheck) {\n
\t\tif(!suspendLength) suspendLength = 0;\n
\t\t// Opera has a problem with suspendRedraw() apparently\n
\t\tvar handle = null;\n
\t\tif (!window.opera) svgroot.suspendRedraw(suspendLength);\n
\n
\t\tfor (var i in attrs) {\n
\t\t\tvar ns = (i.substr(0,4) == "xml:" ? xmlns : \n
\t\t\t\ti.substr(0,6) == "xlink:" ? xlinkns : null);\n
\t\t\t\t\n
\t\t\tif(ns || !unitCheck) {\n
\t\t\t\tnode.setAttributeNS(ns, i, attrs[i]);\n
\t\t\t} else {\n
\t\t\t\tsetUnitAttr(node, i, attrs[i]);\n
\t\t\t}\n
\t\t\t\n
\t\t}\n
\t\t\n
\t\tif (!window.opera) svgroot.unsuspendRedraw(handle);\n
\t};\n
\n
\t// remove unneeded attributes\n
\t// makes resulting SVG smaller\n
\tvar cleanupElement = function(element) {\n
\t\tvar handle = svgroot.suspendRedraw(60);\n
\t\tvar defaults = {\n
\t\t\t\'fill-opacity\':1,\n
\t\t\t\'stop-opacity\':1,\n
\t\t\t\'opacity\':1,\n
\t\t\t\'stroke\':\'none\',\n
\t\t\t\'stroke-dasharray\':\'none\',\n
\t\t\t\'stroke-linejoin\':\'miter\',\n
\t\t\t\'stroke-linecap\':\'butt\',\n
\t\t\t\'stroke-opacity\':1,\n
\t\t\t\'stroke-width\':1,\n
\t\t\t\'rx\':0,\n
\t\t\t\'ry\':0\n
\t\t}\n
\t\tfor(var attr in defaults) {\n
\t\t\tvar val = defaults[attr];\n
\t\t\tif(element.getAttribute(attr) == val) {\n
\t\t\t\telement.removeAttribute(attr);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tsvgroot.unsuspendRedraw(handle);\n
\t};\n
\n
\tthis.updateElementFromJson = function(data) {\n
\t\tvar shape = getElem(data.attr.id);\n
\t\t// if shape is a path but we need to create a rect/ellipse, then remove the path\n
\t\tif (shape && data.element != shape.tagName) {\n
\t\t\tcurrent_layer.removeChild(shape);\n
\t\t\tshape = null;\n
\t\t}\n
\t\tif (!shape) {\n
\t\t\tshape = svgdoc.createElementNS(svgns, data.element);\n
\t\t\tif (current_layer) {\n
\t\t\t\tcurrent_layer.appendChild(shape);\n
\t\t\t}\n
\t\t}\n
\t\tif(data.curStyles) {\n
\t\t\tassignAttributes(shape, {\n
\t\t\t\t"fill": cur_shape.fill,\n
\t\t\t\t"stroke": cur_shape.stroke,\n
\t\t\t\t"stroke-width": cur_shape.stroke_width,\n
\t\t\t\t"stroke-dasharray": cur_shape.stroke_dasharray,\n
\t\t\t\t"stroke-linejoin": cur_shape.stroke_linejoin,\n
\t\t\t\t"stroke-linecap": cur_shape.stroke_linecap,\n
\t\t\t\t"stroke-opacity": cur_shape.stroke_opacity,\n
\t\t\t\t"fill-opacity": cur_shape.fill_opacity,\n
\t\t\t\t"opacity": cur_shape.opacity / 2,\n
\t\t\t\t"style": "pointer-events:inherit"\n
\t\t\t}, 100);\n
\t\t}\n
\t\tassignAttributes(shape, data.attr, 100);\n
\t\tcleanupElement(shape);\n
\t\treturn shape;\n
\t};\n
\n
\t(function() {\n
\t\t// TODO: make this string optional and set by the client\n
\t\tvar comment = svgdoc.createComment(" Created with SVG-edit - http://svg-edit.googlecode.com/ ");\n
\t\tsvgcontent.appendChild(comment);\n
\n
\t\t// TODO For Issue 208: this is a start on a thumbnail\n
\t\t//\tvar svgthumb = svgdoc.createElementNS(svgns, "use");\n
\t\t//\tsvgthumb.setAttribute(\'width\', \'100\');\n
\t\t//\tsvgthumb.setAttribute(\'height\', \'100\');\n
\t\t//\tsvgthumb.setAttributeNS(xlinkns, \'href\', \'#svgcontent\');\n
\t\t//\tsvgroot.appendChild(svgthumb);\n
\n
\t})();\n
\t// z-ordered array of tuples containing layer names and <g> elements\n
\t// the first layer is the one at the bottom of the rendering\n
\tvar all_layers = [],\n
\t\tencodableImages = {},\n
\t\tlast_good_img_url = curConfig.imgPath + \'logo.png\',\n
\t\t// pointer to the current layer <g>\n
\t\tcurrent_layer = null,\n
\t\tsave_options = {round_digits: 5},\n
\t\tstarted = false,\n
\t\tobj_num = 1,\n
\t\tstart_transform = null,\n
\t\tcurrent_mode = "select",\n
\t\tcurrent_resize_mode = "none",\n
\t\tall_properties = {\n
\t\t\tshape: {\n
\t\t\t\tfill: "#" + curConfig.initFill.color,\n
\t\t\t\tfill_paint: null,\n
\t\t\t\tfill_opacity: curConfig.initFill.opacity,\n
\t\t\t\tstroke: "#" + curConfig.initStroke.color,\n
\t\t\t\tstroke_paint: null,\n
\t\t\t\tstroke_opacity: curConfig.initStroke.opacity,\n
\t\t\t\tstroke_width: curConfig.initStroke.width,\n
\t\t\t\tstroke_dasharray: \'none\',\n
\t\t\t\tstroke_linejoin: \'miter\',\n
\t\t\t\tstroke_linecap: \'butt\',\n
\t\t\t\topacity: curConfig.initOpacity\n
\t\t\t}\n
\t\t};\n
\t\n
\tall_properties.text = $.extend(true, {}, all_properties.shape);\n
\t$.extend(all_properties.text, {\n
\t\tfill: "#000000",\n
\t\tstroke_width: 0,\n
\t\tfont_size: 24,\n
\t\tfont_family: \'serif\'\n
\t});\n
\n
\tvar cur_shape = all_properties.shape,\n
\t\tcur_text = all_properties.text,\n
\t\tcur_properties = cur_shape,\n
\t\tcurrent_zoom = 1,\n
\t\t// this will hold all the currently selected elements\n
\t\t// default size of 1 until it needs to grow bigger\n
\t\tselectedElements = new Array(1),\n
\t\t// this holds the selected\'s bbox\n
\t\tselectedBBoxes = new Array(1),\n
\t\tjustSelected = null,\n
\t\t// this object manages selectors for us\n
\t\tselectorManager = new SelectorManager(),\n
\t\trubberBox = null,\n
\t\tevents = {},\n
\t\tundoStackPointer = 0,\n
\t\tundoStack = [],\n
\t\tcurBBoxes = [],\n
\t\textensions = {};\n
\t\n
\t// Should this return an array by default, so extension results aren\'t overwritten?\n
\tvar runExtensions = this.runExtensions = function(action, vars, returnArray) {\n
\t\tvar result = false;\n
\t\tif(returnArray) result = [];\n
\t\t$.each(extensions, function(name, opts) {\n
\t\t\tif(action in opts) {\n
\t\t\t\tif(returnArray) {\n
\t\t\t\t\tresult.push(opts[action](vars))\n
\t\t\t\t} else {\n
\t\t\t\t\tresult = opts[action](vars);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\t\treturn result;\n
\t}\n
\t\n
\t// This method rounds the incoming value to the nearest value based on the current_zoom\n
\tvar round = function(val){\n
\t\treturn parseInt(val*current_zoom)/current_zoom;\n
\t};\n
\n
\t// This method sends back an array or a NodeList full of elements that\n
\t// intersect the multi-select rubber-band-box on the current_layer only.\n
\t// \n
\t// Since the only browser that supports the SVG DOM getIntersectionList is Opera, \n
\t// we need to provide an implementation here.  We brute-force it for now.\n
\t// \n
\t// Reference:\n
\t// Firefox does not implement getIntersectionList(), see https://bugzilla.mozilla.org/show_bug.cgi?id=501421\n
\t// Webkit does not implement getIntersectionList(), see https://bugs.webkit.org/show_bug.cgi?id=11274\n
\tvar getIntersectionList = function(rect) {\n
\t\tif (rubberBox == null) { return null; }\n
\n
\t\tif(!curBBoxes.length) {\n
\t\t\t// Cache all bboxes\n
\t\t\tcurBBoxes = canvas.getVisibleElements(current_layer, true);\n
\t\t}\n
\t\t\n
\t\tvar resultList = null;\n
\t\ttry {\n
\t\t\tresultList = current_layer.getIntersectionList(rect, null);\n
\t\t} catch(e) { }\n
\n
\t\tif (resultList == null || typeof(resultList.item) != "function") {\n
\t\t\tresultList = [];\n
\n
\t\t\tvar rubberBBox = rubberBox.getBBox();\n
\t\t\t$.each(rubberBBox, function(key, val) {\n
\t\t\t\trubberBBox[key] = val / current_zoom;\n
\t\t\t});\n
\t\t\tvar i = curBBoxes.length;\n
\t\t\twhile (i--) {\n
\t\t\t\tif(!rubberBBox.width || !rubberBBox.width) continue;\n
\t\t\t\tif (Utils.rectsIntersect(rubberBBox, curBBoxes[i].bbox))  {\n
\t\t\t\t\tresultList.push(curBBoxes[i].elem);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// addToSelection expects an array, but it\'s ok to pass a NodeList \n
\t\t// because using square-bracket notation is allowed: \n
\t\t// http://www.w3.org/TR/DOM-Level-2-Core/ecma-script-binding.html\n
\t\treturn resultList;\n
\t};\n
\n
\t// FIXME: we MUST compress consecutive text changes to the same element\n
\t// (right now each keystroke is saved as a separate command that includes the\n
\t// entire text contents of the text element)\n
\t// TODO: consider limiting the history that we store here (need to do some slicing)\n
\tvar addCommandToHistory = function(cmd) {\n
\t\t// if our stack pointer is not at the end, then we have to remove\n
\t\t// all commands after the pointer and insert the new command\n
\t\tif (undoStackPointer < undoStack.length && undoStack.length > 0) {\n
\t\t\tundoStack = undoStack.splice(0, undoStackPointer);\n
\t\t}\n
\t\tundoStack.push(cmd);\n
\t\tundoStackPointer = undoStack.length;\n
\t};\n
\t\n
\tthis.getHistoryPosition = function() {\n
\t\treturn undoStackPointer;\n
\t};\n
\n
// private functions\n
\tvar getId = function() {\n
\t\tif (events["getid"]) return call("getid", obj_num);\n
\t\tif (randomize_ids) {\n
\t\t  return idprefix + nonce +\'_\' + obj_num;\n
\t\t} else {\n
\t\treturn idprefix + obj_num;\n
\t\t}\n
\t};\n
\n
\tvar getNextId = function() {\n
\t\t// ensure the ID does not exist\n
\t\tvar id = getId();\n
\t\t\n
\t\twhile (getElem(id)) {\n
\t\t\tobj_num++;\n
\t\t\tid = getId();\n
\t\t}\n
\t\treturn id;\n
\t};\n
\n
\tvar call = function(event, arg) {\n
\t\tif (events[event]) {\n
\t\t\treturn events[event](this,arg);\n
\t\t}\n
\t};\n
\n
\t// this function sanitizes the input node and its children\n
\t// this function only keeps what is allowed from our whitelist defined above\n
\tvar sanitizeSvg = function(node) {\n
\t\t// we only care about element nodes\n
\t\t// automatically return for all comment, etc nodes\n
\t\t// for text, we do a whitespace trim\n
\t\tif (node.nodeType == 3) {\n
\t\t\tnode.nodeValue = node.nodeValue.replace(/^\\s+|\\s+$/g, "");\n
\t\t\t// Remove empty text nodes\n
\t\t\tif(!node.nodeValue.length) node.parentNode.removeChild(node);\n
\t\t}\n
\t\tif (node.nodeType != 1) return;\n
\t\tvar doc = node.ownerDocument;\n
\t\tvar parent = node.parentNode;\n
\t\t// can parent ever be null here?  I think the root node\'s parent is the document...\n
\t\tif (!doc || !parent) return;\n
\n
\t\tvar allowedAttrs = svgWhiteList[node.nodeName];\n
\t\tvar allowedAttrsNS = svgWhiteListNS[node.nodeName];\n
\n
\t\t// if this element is allowed\n
\t\tif (allowedAttrs != undefined) {\n
\t\t\tvar se_attrs = [];\n
\t\t\n
\t\t\tvar i = node.attributes.length;\n
\t\t\twhile (i--) {\n
\t\t\t\t// if the attribute is not in our whitelist, then remove it\n
\t\t\t\t// could use jQuery\'s inArray(), but I don\'t know if that\'s any better\n
\t\t\t\tvar attr = node.attributes.item(i);\n
\t\t\t\tvar attrName = attr.nodeName;\n
\t\t\t\tvar attrLocalName = attr.localName;\n
\t\t\t\tvar attrNsURI = attr.namespaceURI;\n
\t\t\t\t// Check that an attribute with the correct localName in the correct namespace is on \n
\t\t\t\t// our whitelist or is a namespace declaration for one of our allowed namespaces\n
\t\t\t\tif (!(allowedAttrsNS.hasOwnProperty(attrLocalName) && attrNsURI == allowedAttrsNS[attrLocalName] && attrNsURI != xmlnsns) &&\n
\t\t\t\t\t!(attrNsURI == xmlnsns && nsMap[attr.nodeValue]) ) \n
\t\t\t\t{\n
\t\t\t\t\t// Bypassing the whitelist to allow se: prefixes. Is there\n
\t\t\t\t\t// a more appropriate way to do this?\n
\t\t\t\t\tif(attrName.indexOf(\'se:\') == 0) {\n
\t\t\t\t\t\tse_attrs.push([attrName, attr.nodeValue]);\n
\t\t\t\t\t} \n
\t\t\t\t\tnode.removeAttributeNS(attrNsURI, attrLocalName);\n
\t\t\t\t}\n
\t\t\t\t// special handling for path d attribute\n
\t\t\t\tif (node.nodeName == \'path\' && attrName == \'d\') {\n
\t\t\t\t\t// Convert to absolute\n
\t\t\t\t\tnode.setAttribute(\'d\',pathActions.convertPath(node));\n
\t\t\t\t\tpathActions.fixEnd(node);\n
\t\t\t\t}\n
\t\t\t\t// for the style attribute, rewrite it in terms of XML presentational attributes\n
\t\t\t\tif (attrName == "style") {\n
\t\t\t\t\tvar props = attr.nodeValue.split(";"),\n
\t\t\t\t\t\tp = props.length;\n
\t\t\t\t\twhile(p--) {\n
\t\t\t\t\t\tvar nv = props[p].split(":");\n
\t\t\t\t\t\t// now check that this attribute is supported\n
\t\t\t\t\t\tif (allowedAttrs.indexOf(nv[0]) != -1) {\n
\t\t\t\t\t\t\tnode.setAttribute(nv[0],nv[1]);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tnode.removeAttribute(\'style\');\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t$.each(se_attrs, function(i, attr) {\n
\t\t\t\tnode.setAttributeNS(se_ns, attr[0], attr[1]);\n
\t\t\t});\n
\t\t\t\n
\t\t\t// for some elements that have a xlink:href, ensure the URI refers to a local element\n
\t\t\t// (but not for links)\n
\t\t\tvar href = node.getAttributeNS(xlinkns,"href");\n
\t\t\tif(href && \n
\t\t\t   $.inArray(node.nodeName, ["filter", "linearGradient", "pattern", \n
\t\t\t   \t\t\t\t\t\t\t "radialGradient", "textPath", "use"]) != -1)\n
\t\t\t{\n
\t\t\t\t// TODO: we simply check if the first character is a #, is this bullet-proof?\n
\t\t\t\tif (href[0] != "#") {\n
\t\t\t\t\t// remove the attribute (but keep the element)\n
\t\t\t\t\tnode.setAttributeNS(xlinkns, "xlink:href", "");\n
\t\t\t\t\tnode.removeAttributeNS(xlinkns, "href");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// Safari crashes on a <use> without a xlink:href, so we just remove the node here\n
\t\t\tif (node.nodeName == "use" && !node.getAttributeNS(xlinkns,"href")) {\n
\t\t\t\tparent.removeChild(node);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\t// if the element has attributes pointing to a non-local reference, \n
\t\t\t// need to remove the attribute\n
\t\t\t$.each(["clip-path", "fill", "filter", "marker-end", "marker-mid", "marker-start", "mask", "stroke"],function(i,attr) {\n
\t\t\t\tvar val = node.getAttribute(attr);\n
\t\t\t\tif (val) {\n
\t\t\t\t\tval = getUrlFromAttr(val);\n
\t\t\t\t\t// simply check for first character being a \'#\'\n
\t\t\t\t\tif (val && val[0] != "#") {\n
\t\t\t\t\t\tnode.setAttribute(attr, "");\n
\t\t\t\t\t\tnode.removeAttribute(attr);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\t// recurse to children\n
\t\t\ti = node.childNodes.length;\n
\t\t\twhile (i--) { sanitizeSvg(node.childNodes.item(i)); }\n
\t\t}\n
\t\t// else, remove this element\n
\t\telse {\n
\t\t\t// remove all children from this node and insert them before this node\n
\t\t\t// FIXME: in the case of animation elements this will hardly ever be correct\n
\t\t\tvar children = [];\n
\t\t\twhile (node.hasChildNodes()) {\n
\t\t\t\tchildren.push(parent.insertBefore(node.firstChild, node));\n
\t\t\t}\n
\n
\t\t\t// remove this node from the document altogether\n
\t\t\tparent.removeChild(node);\n
\n
\t\t\t// call sanitizeSvg on each of those children\n
\t\t\tvar i = children.length;\n
\t\t\twhile (i--) { sanitizeSvg(children[i]); }\n
\n
\t\t}\n
\t};\n
\t\n
\t// extracts the URL from the url(...) syntax of some attributes.  Three variants:\n
\t// i.e. <circle fill="url(someFile.svg#foo)" /> or\n
\t//      <circle fill="url(\'someFile.svg#foo\')" /> or\n
\t//      <circle fill=\'url("someFile.svg#foo")\' />\n
\tthis.getUrlFromAttr = function(attrVal) {\n
\t\tif (attrVal) {\t\t\n
\t\t\t// url("#somegrad")\n
\t\t\tif (attrVal.indexOf(\'url("\') == 0) {\n
\t\t\t\treturn attrVal.substring(5,attrVal.indexOf(\'"\',6));\n
\t\t\t}\n
\t\t\t// url(\'#somegrad\')\n
\t\t\telse if (attrVal.indexOf("url(\'") == 0) {\n
\t\t\t\treturn attrVal.substring(5,attrVal.indexOf("\'",6));\n
\t\t\t}\n
\t\t\telse if (attrVal.indexOf("url(") == 0) {\n
\t\t\t\treturn attrVal.substring(4,attrVal.indexOf(\')\'));\n
\t\t\t}\n
\t\t}\n
\t\treturn null;\n
\t};\n
\tvar getUrlFromAttr = this.getUrlFromAttr;\n
\n
\tvar removeUnusedDefElems = function() {\n
\t\tvar defs = svgcontent.getElementsByTagNameNS(svgns, "defs");\n
\t\tif(!defs || !defs.length) return 0;\n
\t\t\n
\t\tvar defelem_uses = [],\n
\t\t\tnumRemoved = 0;\n
\t\tvar attrs = [\'fill\', \'stroke\', \'filter\', \'marker-start\', \'marker-mid\', \'marker-end\'];\n
\t\tvar alen = attrs.length;\n
\t\t\n
\t\tvar all_els = svgcontent.getElementsByTagNameNS(svgns, \'*\');\n
\t\tvar all_len = all_els.length;\n
\t\t\n
\t\tfor(var i=0; i<all_len; i++) {\n
\t\t\tvar el = all_els[i];\n
\t\t\tfor(var j = 0; j < alen; j++) {\n
\t\t\t\tvar ref = getUrlFromAttr(el.getAttribute(attrs[j]));\n
\t\t\t\tif(ref) defelem_uses.push(ref.substr(1));\n
\t\t\t}\n
\t\t\t\n
\t\t\t// gradients can refer to other gradients\n
\t\t\tvar href = el.getAttributeNS(xlinkns, "href");\n
\t\t\tif (href && href.indexOf(\'#\') == 0) {\n
\t\t\t\tdefelem_uses.push(href.substr(1));\n
\t\t\t}\n
\t\t};\n
\t\t\n
\t\tvar defelems = $(svgcontent).find("linearGradient, radialGradient, filter, marker");\n
\t\t\tdefelem_ids = [],\n
\t\t\ti = defelems.length;\n
\t\twhile (i--) {\n
\t\t\tvar defelem = defelems[i];\n
\t\t\tvar id = defelem.id;\n
\t\t\tif($.inArray(id, defelem_uses) == -1) {\n
\t\t\t\t// Not found, so remove\n
\t\t\t\tdefelem.parentNode.removeChild(defelem);\n
\t\t\t\tnumRemoved++;\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\t// Remove defs if empty\n
\t\tvar i = defs.length;\n
\t\twhile (i--) {\n
\t\t\tvar def = defs[i];\n
\t\t\tif(!def.getElementsByTagNameNS(svgns,\'*\').length) {\n
\t\t\t\tdef.parentNode.removeChild(def);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn numRemoved;\n
\t}\n
\t\n
\tvar svgCanvasToString = function() {\n
\t\t// keep calling it until there are none to remove\n
\t\twhile (removeUnusedDefElems() > 0) {};\n
\t\t\n
\t\tpathActions.clear(true);\n
\t\t\n
\t\t// Keep SVG-Edit comment on top\n
\t\t$.each(svgcontent.childNodes, function(i, node) {\n
\t\t\tif(i && node.nodeType == 8 && node.data.indexOf(\'Created with\') != -1) {\n
\t\t\t\tsvgcontent.insertBefore(node, svgcontent.firstChild);\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tvar output = svgToString(svgcontent, 0);\n
\t\treturn output;\n
\t}\n
\n
\tvar svgToString = function(elem, indent) {\n
\t\tvar out = new Array();\n
\n
\t\tif (elem) {\n
\t\t\tcleanupElement(elem);\n
\t\t\tvar attrs = elem.attributes,\n
\t\t\t\tattr,\n
\t\t\t\ti,\n
\t\t\t\tchilds = elem.childNodes;\n
\t\t\t\n
\t\t\tfor (var i=0; i<indent; i++) out.push(" ");\n
\t\t\tout.push("<"); out.push(elem.nodeName);\t\t\t\n
\t\t\tif(elem.id == \'svgcontent\') {\n
\t\t\t\t// Process root element separately\n
\t\t\t\tvar res = canvas.getResolution();\n
\t\t\t\tout.push(\' width="\' + res.w + \'" height="\' + res.h + \'" xmlns="\'+svgns+\'"\');\n
\t\t\t\t\n
\t\t\t\tvar nsuris = {};\n
\t\t\t\t\n
\t\t\t\t// Check elements for namespaces, add if found\n
\t\t\t\t$(elem).find(\'*\').andSelf().each(function() {\n
\t\t\t\t\tvar el = this;\n
\t\t\t\t\t$.each(this.attributes, function(i, attr) {\n
\t\t\t\t\t\tvar uri = attr.namespaceURI;\n
\t\t\t\t\t\tif(uri && !nsuris[uri] && nsMap[uri] !== \'xmlns\' && nsMap[uri] !== \'xml\' ) {\n
\t\t\t\t\t\t\tnsuris[uri] = true;\n
\t\t\t\t\t\t\tout.push(" xmlns:" + nsMap[uri] + \'="\' + uri +\'"\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tvar i = attrs.length;\n
\t\t\t\twhile (i--) {\n
\t\t\t\t\tattr = attrs.item(i);\n
\t\t\t\t\tvar attrVal = toXml(attr.nodeValue);\n
\t\t\t\t\t\n
\t\t\t\t\t// Namespaces have already been dealt with, so skip\n
\t\t\t\t\tif(attr.nodeName.indexOf(\'xmlns:\') === 0) continue;\n
\n
\t\t\t\t\t// only serialize attributes we don\'t use internally\n
\t\t\t\t\tif (attrVal != "" && \n
\t\t\t\t\t\t$.inArray(attr.localName, [\'width\',\'height\',\'xmlns\',\'x\',\'y\',\'viewBox\',\'id\',\'overflow\']) == -1) \n
\t\t\t\t\t{\n
\n
\t\t\t\t\t\tif(!attr.namespaceURI || nsMap[attr.namespaceURI]) {\n
\t\t\t\t\t\t\tout.push(\' \'); \n
\t\t\t\t\t\t\tout.push(attr.nodeName); out.push("=\\"");\n
\t\t\t\t\t\t\tout.push(attrVal); out.push("\\"");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor (var i=attrs.length-1; i>=0; i--) {\n
\t\t\t\t\tattr = attrs.item(i);\n
\t\t\t\t\tvar attrVal = toXml(attr.nodeValue);\n
\t\t\t\t\t//remove bogus attributes added by Gecko\n
\t\t\t\t\tif ($.inArray(attr.localName, [\'-moz-math-font-style\', \'_moz-math-font-style\']) !== -1) continue;\n
\t\t\t\t\tif (attrVal != "") {\n
\t\t\t\t\t\tif(attrVal.indexOf(\'pointer-events\') == 0) continue;\n
\t\t\t\t\t\tif(attr.localName == "class" && attrVal.indexOf(\'se_\') == 0) continue;\n
\t\t\t\t\t\tout.push(" "); \n
\t\t\t\t\t\tif(attr.localName == \'d\') attrVal = pathActions.convertPath(elem, true);\n
\t\t\t\t\t\tif(!isNaN(attrVal)) {\n
\t\t\t\t\t\t\tattrVal = shortFloat(attrVal);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Embed images when saving \n
\t\t\t\t\t\tif(save_options.apply\n
\t\t\t\t\t\t\t&& elem.nodeName == \'image\' \n
\t\t\t\t\t\t\t&& attr.localName == \'href\'\n
\t\t\t\t\t\t\t&& save_options.images\n
\t\t\t\t\t\t\t&& save_options.images == \'embed\') \n
\t\t\t\t\t\t{\n
\t\t\t\t\t\t\tvar img = encodableImages[attrVal];\n
\t\t\t\t\t\t\tif(img) attrVal = img;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// map various namespaces to our fixed namespace prefixes\n
\t\t\t\t\t\t// (the default xmlns attribute itself does not get a prefix)\n
\t\t\t\t\t\tif(!attr.namespaceURI || attr.namespaceURI == svgns || nsMap[attr.namespaceURI]) {\n
\t\t\t\t\t\t\tout.push(attr.nodeName); out.push("=\\"");\n
\t\t\t\t\t\t\tout.push(attrVal); out.push("\\"");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (elem.hasChildNodes()) {\n
\t\t\t\tout.push(">");\n
\t\t\t\tindent++;\n
\t\t\t\tvar bOneLine = false;\n
\t\t\t\tfor (var i=0; i<childs.length; i++)\n
\t\t\t\t{\n
\t\t\t\t\tvar child = childs.item(i);\n
\t\t\t\t\tswitch(child.nodeType) {\n
\t\t\t\t\tcase 1: // element node\n
\t\t\t\t\t\tout.push("\\n");\n
\t\t\t\t\t\tout.push(svgToString(childs.item(i), indent));\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 3: // text node\n
\t\t\t\t\t\tvar str = child.nodeValue.replace(/^\\s+|\\s+$/g, "");\n
\t\t\t\t\t\tif (str != "") {\n
\t\t\t\t\t\t\tbOneLine = true;\n
\t\t\t\t\t\t\tout.push(toXml(str) + "");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 8: // comment\n
\t\t\t\t\t\tout.push("\\n");\n
\t\t\t\t\t\tout.push(new Array(indent+1).join(" "));\n
\t\t\t\t\t\tout.push("<!--");\n
\t\t\t\t\t\tout.push(child.data);\n
\t\t\t\t\t\tout.push("-->");\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t} // switch on node type\n
\t\t\t\t}\n
\t\t\t\tindent--;\n
\t\t\t\tif (!bOneLine) {\n
\t\t\t\t\tout.push("\\n");\n
\t\t\t\t\tfor (var i=0; i<indent; i++) out.push(" ");\n
\t\t\t\t}\n
\t\t\t\tout.push("</"); out.push(elem.nodeName); out.push(">");\n
\t\t\t} else {\n
\t\t\t\tout.push("/>");\n
\t\t\t}\n
\t\t}\n
\t\treturn out.join(\'\');\n
\t}; // end svgToString()\n
\n
\tthis.embedImage = function(val, callback) {\n
\t\n
\t\t// load in the image and once it\'s loaded, get the dimensions\n
\t\t$(new Image()).load(function() {\n
\t\t\t// create a canvas the same size as the raster image\n
\t\t\tvar canvas = document.createElement("canvas");\n
\t\t\tcanvas.width = this.width;\n
\t\t\tcanvas.height = this.height;\n
\t\t\t// load the raster image into the canvas\n
\t\t\tcanvas.getContext("2d").drawImage(this,0,0);\n
\t\t\t// retrieve the data: URL\n
\t\t\ttry {\n
\t\t\t\tvar urldata = \';svgedit_url=\' + encodeURIComponent(val);\n
\t\t\t\turldata = canvas.toDataURL().replace(\';base64\',urldata+\';base64\');\n
\t\t\t\tencodableImages[val] = urldata;\n
\t\t\t} catch(e) {\n
\t\t\t\tencodableImages[val] = false;\n
\t\t\t}\n
\t\t\tlast_good_img_url = val;\n
\t\t\tif(callback) callback(encodableImages[val]);\n
\t\t}).attr(\'src\',val);\n
\t}\n
\n
\t// importNode, like cloneNode, causes the comma-to-period\n
\t// issue in Opera/Win/non-en. Thankfully we can compare to the original XML\n
\t// and simply use the original value when necessary\n
\tthis.fixOperaXML = function(elem, orig_el) {\n
\t\tvar x_attrs = elem.attributes;\n
\t\t$.each(x_attrs, function(i, attr) {\n
\t\t\tif(attr.nodeValue.indexOf(\',\') == -1) return;\n
\t\t\t// attr val has comma, so let\'s get the good value\n
\t\t\tvar ns = attr.prefix == \'xlink\' ? xlinkns : \n
\t\t\t\tattr.prefix == "xml" ? xmlns : null;\n
\t\t\tvar good_attrval = orig_el.getAttribute(attr.localName);\n
\t\t\tif(ns) {\n
\t\t\t\telem.setAttributeNS(ns, attr.nodeName, good_attrval);\n
\t\t\t} else {\n
\t\t\t\telem.setAttribute(attr.nodeName, good_attrval);\n
\t\t\t}\n
\t\t});\n
\n
\t\tvar childs = elem.childNodes;\n
\t\tvar o_childs = orig_el.childNodes;\n
\t\t$.each(childs, function(i, child) {\n
\t\t\tif(child.nodeType == 1) {\n
\t\t\t\tcanvas.fixOperaXML(child, o_childs[i]);\n
\t\t\t}\n
\t\t});\n
\t}\n
\n
\tvar recalculateAllSelectedDimensions = function() {\n
\t\tvar text = (current_resize_mode == "none" ? "position" : "size");\n
\t\tvar batchCmd = new BatchCommand(text);\n
\n
\t\tvar i = selectedElements.length;\n
\t\twhile(i--) {\n
\t\t\tvar elem = selectedElements[i];\n
// \t\t\tif(canvas.getRotationAngle(elem) && !hasMatrixTransform(canvas.getTransformList(elem))) continue;\n
\t\t\tvar cmd = recalculateDimensions(elem);\n
\t\t\tif (cmd) {\n
\t\t\t\tbatchCmd.addSubCommand(cmd);\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (!batchCmd.isEmpty()) {\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcall("changed", selectedElements);\n
\t\t}\n
\t};\n
\n
\t// this is how we map paths to our preferred relative segment types\n
\tvar pathMap = [0, \'z\', \'M\', \'m\', \'L\', \'l\', \'C\', \'c\', \'Q\', \'q\', \'A\', \'a\', \n
\t\t\t\t\t\t\'H\', \'h\', \'V\', \'v\', \'S\', \'s\', \'T\', \'t\'];\n
\n
\tvar logMatrix = function(m) {\n
\t\tconsole.log([m.a,m.b,m.c,m.d,m.e,m.f]);\n
\t};\n
\t\n
\tvar remapElement = function(selected,changes,m) {\n
\t\tvar remap = function(x,y) { return transformPoint(x,y,m); },\n
\t\t\tscalew = function(w) { return m.a*w; },\n
\t\t\tscaleh = function(h) { return m.d*h; },\n
\t\t\tbox = canvas.getBBox(selected);\n
\n
\t\tswitch (selected.tagName)\n
\t\t{\n
\t\t\tcase "line":\n
\t\t\t\tvar pt1 = remap(changes["x1"],changes["y1"]),\n
\t\t\t\t\tpt2 = remap(changes["x2"],changes["y2"]);\n
\t\t\t\tchanges["x1"] = pt1.x;\n
\t\t\t\tchanges["y1"] = pt1.y;\n
\t\t\t\tchanges["x2"] = pt2.x;\n
\t\t\t\tchanges["y2"] = pt2.y;\n
\t\t\t\tbreak;\n
\t\t\tcase "circle":\n
\t\t\t\tvar c = remap(changes["cx"],changes["cy"]);\n
\t\t\t\tchanges["cx"] = c.x;\n
\t\t\t\tchanges["cy"] = c.y;\n
\t\t\t\t// take the minimum of the new selected box\'s dimensions for the new circle radius\n
\t\t\t\tvar tbox = transformBox(box.x, box.y, box.width, box.height, m);\n
\t\t\t\tvar w = tbox.tr.x - tbox.tl.x, h = tbox.bl.y - tbox.tl.y;\n
\t\t\t\tchanges["r"] = Math.min(w/2, h/2);\n
\t\t\t\tbreak;\n
\t\t\tcase "ellipse":\n
\t\t\t\tvar c = remap(changes["cx"],changes["cy"]);\n
\t\t\t\tchanges["cx"] = c.x;\n
\t\t\t\tchanges["cy"] = c.y;\n
\t\t\t\tchanges["rx"] = scalew(changes["rx"]);\n
\t\t\t\tchanges["ry"] = scaleh(changes["ry"]);\n
\t\t\t\tbreak;\n
\t\t\tcase "foreignObject":\n
\t\t\tcase "rect":\n
\t\t\tcase "image":\n
\t\t\t\tvar pt1 = remap(changes["x"],changes["y"]);\n
\t\t\t\tchanges["x"] = pt1.x;\n
\t\t\t\tchanges["y"] = pt1.y;\n
\t\t\t\tchanges["width"] = scalew(changes["width"]);\n
\t\t\t\tchanges["height"] = scaleh(changes["height"]);\n
\t\t\t\tbreak;\n
\t\t\tcase "use":\n
\t\t\t\tvar pt1 = remap(changes["x"],changes["y"]);\n
\t\t\t\tchanges["x"] = pt1.x;\n
\t\t\t\tchanges["y"] = pt1.y;\n
\t\t\t\tbreak;\n
\t\t\tcase "text":\n
\t\t\t\t// if it was a translate, then just update x,y\n
\t\t\t\tif (m.a == 1 && m.b == 0 && m.c == 0 && m.d == 1 && \n
\t\t\t\t\t(m.e != 0 || m.f != 0) ) \n
\t\t\t\t{\n
\t\t\t\t\t// [T][M] = [M][T\']\n
\t\t\t\t\t// therefore [T\'] = [M_inv][T][M]\n
\t\t\t\t\tvar existing = transformListToTransform(selected).matrix,\n
\t\t\t\t\t\tt_new = matrixMultiply(existing.inverse(), m, existing);\n
\t\t\t\t\tchanges["x"] = parseFloat(changes["x"]) + t_new.e;\n
\t\t\t\t\tchanges["y"] = parseFloat(changes["y"]) + t_new.f;\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\t// we just absorb all matrices into the element and don\'t do any remapping\n
\t\t\t\t\tvar chlist = canvas.getTransformList(selected);\n
\t\t\t\t\tvar mt = svgroot.createSVGTransform();\n
\t\t\t\t\tmt.setMatrix(matrixMultiply(transformListToTransform(chlist).matrix,m));\n
\t\t\t\t\tchlist.clear();\n
\t\t\t\t\tchlist.appendItem(mt);\n
\t\t\t\t}\n
\t\t\t\tbreak;\n
\t\t\tcase "polygon":\n
\t\t\tcase "polyline":\n
\t\t\t\tvar len = changes["points"].length;\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar pt = changes["points"][i];\n
\t\t\t\t\tpt = remap(pt.x,pt.y);\n
\t\t\t\t\tchanges["points"][i].x = pt.x;\n
\t\t\t\t\tchanges["points"][i].y = pt.y;\n
\t\t\t\t}\n
\t\t\t\tbreak;\n
\t\t\tcase "path":\n
\t\t\t\tvar segList = selected.pathSegList;\n
\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\tchanges.d = new Array(len);\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar seg = segList.getItem(i);\n
\t\t\t\t\tchanges.d[i] = {\n
\t\t\t\t\t\ttype: seg.pathSegType,\n
\t\t\t\t\t\tx: seg.x,\n
\t\t\t\t\t\ty: seg.y,\n
\t\t\t\t\t\tx1: seg.x1,\n
\t\t\t\t\t\ty1: seg.y1,\n
\t\t\t\t\t\tx2: seg.x2,\n
\t\t\t\t\t\ty2: seg.y2,\n
\t\t\t\t\t\tr1: seg.r1,\n
\t\t\t\t\t\tr2: seg.r2,\n
\t\t\t\t\t\tangle: seg.angle,\n
\t\t\t\t\t\tlargeArcFlag: seg.largeArcFlag,\n
\t\t\t\t\t\tsweepFlag: seg.sweepFlag\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar len = changes["d"].length,\n
\t\t\t\t\tfirstseg = changes["d"][0],\n
\t\t\t\t\tcurrentpt = remap(firstseg.x,firstseg.y);\n
\t\t\t\tchanges["d"][0].x = currentpt.x;\n
\t\t\t\tchanges["d"][0].y = currentpt.y;\n
\t\t\t\tfor (var i = 1; i < len; ++i) {\n
\t\t\t\t\tvar seg = changes["d"][i];\n
\t\t\t\t\tvar type = seg.type;\n
\t\t\t\t\t// if absolute or first segment, we want to remap x, y, x1, y1, x2, y2\n
\t\t\t\t\t// if relative, we want to scalew, scaleh\n
\t\t\t\t\tif (type % 2 == 0) { // absolute\n
\t\t\t\t\t\tvar thisx = (seg.x != undefined) ? seg.x : currentpt.x, // for V commands\n
\t\t\t\t\t\t\tthisy = (seg.y != undefined) ? seg.y : currentpt.y, // for H commands\n
\t\t\t\t\t\t\tpt = remap(thisx,thisy),\n
\t\t\t\t\t\t\tpt1 = remap(seg.x1,seg.y1),\n
\t\t\t\t\t\t\tpt2 = remap(seg.x2,seg.y2);\n
\t\t\t\t\t\tseg.x = pt.x;\n
\t\t\t\t\t\tseg.y = pt.y;\n
\t\t\t\t\t\tseg.x1 = pt1.x;\n
\t\t\t\t\t\tseg.y1 = pt1.y;\n
\t\t\t\t\t\tseg.x2 = pt2.x;\n
\t\t\t\t\t\tseg.y2 = pt2.y;\n
\t\t\t\t\t\tseg.r1 = scalew(seg.r1),\n
\t\t\t\t\t\tseg.r2 = scaleh(seg.r2);\n
\t\t\t\t\t}\n
\t\t\t\t\telse { // relative\n
\t\t\t\t\t\tseg.x = scalew(seg.x);\n
\t\t\t\t\t\tseg.y = scaleh(seg.y);\n
\t\t\t\t\t\tseg.x1 = scalew(seg.x1);\n
\t\t\t\t\t\tseg.y1 = scaleh(seg.y1);\n
\t\t\t\t\t\tseg.x2 = scalew(seg.x2);\n
\t\t\t\t\t\tseg.y2 = scaleh(seg.y2);\n
\t\t\t\t\t\tseg.r1 = scalew(seg.r1),\n
\t\t\t\t\t\tseg.r2 = scaleh(seg.r2);\n
\t\t\t\t\t}\n
\t\t\t\t\t// tracks the current position (for H,V commands)\n
\t\t\t\t\tif (seg.x) currentpt.x = seg.x;\n
\t\t\t\t\tif (seg.y) currentpt.y = seg.y;\n
\t\t\t\t} // for each segment\n
\t\t\t\tbreak;\n
\t\t} // switch on element type to get initial values\n
\t\t\n
\t\t// now we have a set of changes and an applied reduced transform list\n
\t\t// we apply the changes directly to the DOM\n
\t\t// TODO: merge this switch with the above one and optimize\n
\t\tswitch (selected.tagName)\n
\t\t{\n
\t\t\tcase "foreignObject":\n
\t\t\tcase "rect":\n
\t\t\tcase "image":\n
\t\t\t\tchanges.x = changes.x-0 + Math.min(0,changes.width);\n
\t\t\t\tchanges.y = changes.y-0 + Math.min(0,changes.height);\n
\t\t\t\tchanges.width = Math.abs(changes.width);\n
\t\t\t\tchanges.height = Math.abs(changes.height);\n
\t\t\t\tassignAttributes(selected, changes, 1000, true);\n
\t\t\t\tbreak;\n
\t\t\tcase "use":\n
\t\t\t\tassignAttributes(selected, changes, 1000, true);\n
\t\t\t\tbreak;\n
\t\t\tcase "ellipse":\n
\t\t\t\tchanges.rx = Math.abs(changes.rx);\n
\t\t\t\tchanges.ry = Math.abs(changes.ry);\n
\t\t\tcase "circle":\n
\t\t\t\tif(changes.r) changes.r = Math.abs(changes.r);\n
\t\t\tcase "line":\n
\t\t\tcase "text":\n
\t\t\t\tassignAttributes(selected, changes, 1000, true);\n
\t\t\t\tbreak;\n
\t\t\tcase "polyline":\n
\t\t\tcase "polygon":\n
\t\t\t\tvar len = changes["points"].length;\n
\t\t\t\tvar pstr = "";\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar pt = changes["points"][i];\n
\t\t\t\t\tpstr += pt.x + "," + pt.y + " ";\n
\t\t\t\t}\n
\t\t\t\tselected.setAttribute("points", pstr);\n
\t\t\t\tbreak;\n
\t\t\tcase "path":\n
\t\t\t\tvar dstr = "";\n
\t\t\t\tvar len = changes["d"].length;\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar seg = changes["d"][i];\n
\t\t\t\t\tvar type = seg.type;\n
\t\t\t\t\tdstr += pathMap[type];\n
\t\t\t\t\tswitch(type) {\n
\t\t\t\t\t\tcase 13: // relative horizontal line (h)\n
\t\t\t\t\t\tcase 12: // absolute horizontal line (H)\n
\t\t\t\t\t\t\tdstr += seg.x + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 15: // relative vertical line (v)\n
\t\t\t\t\t\tcase 14: // absolute vertical line (V)\n
\t\t\t\t\t\t\tdstr += seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 3: // relative move (m)\n
\t\t\t\t\t\tcase 5: // relative line (l)\n
\t\t\t\t\t\tcase 19: // relative smooth quad (t)\n
\t\t\t\t\t\tcase 2: // absolute move (M)\n
\t\t\t\t\t\tcase 4: // absolute line (L)\n
\t\t\t\t\t\tcase 18: // absolute smooth quad (T)\n
\t\t\t\t\t\t\tdstr += seg.x + "," + seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 7: // relative cubic (c)\n
\t\t\t\t\t\tcase 6: // absolute cubic (C)\n
\t\t\t\t\t\t\tdstr += seg.x1 + "," + seg.y1 + " " + seg.x2 + "," + seg.y2 + " " +\n
\t\t\t\t\t\t\t\t seg.x + "," + seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 9: // relative quad (q) \n
\t\t\t\t\t\tcase 8: // absolute quad (Q)\n
\t\t\t\t\t\t\tdstr += seg.x1 + "," + seg.y1 + " " + seg.x + "," + seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 11: // relative elliptical arc (a)\n
\t\t\t\t\t\tcase 10: // absolute elliptical arc (A)\n
\t\t\t\t\t\t\tdstr += seg.r1 + "," + seg.r2 + " " + seg.angle + " " + Number(seg.largeArcFlag) +\n
\t\t\t\t\t\t\t\t" " + Number(seg.sweepFlag) + " " + seg.x + "," + seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 17: // relative smooth cubic (s)\n
\t\t\t\t\t\tcase 16: // absolute smooth cubic (S)\n
\t\t\t\t\t\t\tdstr += seg.x2 + "," + seg.y2 + " " + seg.x + "," + seg.y + " ";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tselected.setAttribute("d", dstr);\n
\t\t\t\tbreak;\n
\t\t}\n
\t\t\n
\t};\n
\t\n
\t// this function returns the command which resulted from the selected change\n
\t// TODO: use suspendRedraw() and unsuspendRedraw() around this function\n
\tvar recalculateDimensions = function(selected) {\n
\t\tif (selected == null) return null;\n
\t\t\n
\t\tvar tlist = canvas.getTransformList(selected);\n
\n
\t\t// remove any unnecessary transforms\n
\t\tif (tlist && tlist.numberOfItems > 0) {\n
\t\t\tvar k = tlist.numberOfItems;\n
\t\t\twhile (k--) {\n
\t\t\t\tvar xform = tlist.getItem(k);\n
\t\t\t\tif (xform.type == 0) {\n
\t\t\t\t\ttlist.removeItem(k);\n
\t\t\t\t}\n
\t\t\t\t// remove identity matrices\n
\t\t\t\telse if (xform.type == 1) {\n
\t\t\t\t\tif (isIdentity(xform.matrix)) {\n
\t\t\t\t\t\ttlist.removeItem(k);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t// remove zero-degree rotations\n
\t\t\t\telse if (xform.type == 4) {\n
\t\t\t\t\tif (xform.angle == 0) {\n
\t\t\t\t\t\ttlist.removeItem(k);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// End here if all it has is a rotation\n
\t\t\tif(tlist.numberOfItems == 1 && canvas.getRotationAngle(selected)) return null;\n
\t\t}\n
\t\t\n
\t\t// if this element had no transforms, we are done\n
\t\tif (!tlist || tlist.numberOfItems == 0) {\n
\t\t\tselected.removeAttribute("transform");\n
\t\t\treturn null;\n
\t\t}\n
\t\t\n
\t\t// we know we have some transforms, so set up return variable\t\t\n
\t\tvar batchCmd = new BatchCommand("Transform");\n
\t\t\n
\t\t// store initial values that will be affected by reducing the transform list\n
\t\tvar changes = {}, initial = null, attrs = [];\n
\t\tswitch (selected.tagName)\n
\t\t{\n
\t\t\tcase "line":\n
\t\t\t\tattrs = ["x1", "y1", "x2", "y2"];\n
\t\t\t\tbreak;\n
\t\t\tcase "circle":\n
\t\t\t\tattrs = ["cx", "cy", "r"];\n
\t\t\t\tbreak;\n
\t\t\tcase "ellipse":\n
\t\t\t\tattrs = ["cx", "cy", "rx", "ry"];\n
\t\t\t\tbreak;\n
\t\t\tcase "foreignObject":\n
\t\t\tcase "rect":\n
\t\t\tcase "image":\n
\t\t\t\tattrs = ["width", "height", "x", "y"];\n
\t\t\t\tbreak;\n
\t\t\tcase "use":\n
\t\t\t\tattrs = ["x", "y"];\n
\t\t\t\tbreak;\n
\t\t\tcase "text":\n
\t\t\t\tattrs = ["x", "y"];\n
\t\t\t\tbreak;\n
\t\t\tcase "polygon":\n
\t\t\tcase "polyline":\n
\t\t\t\tinitial = {};\n
\t\t\t\tinitial["points"] = selected.getAttribute("points");\n
\t\t\t\tvar list = selected.points;\n
\t\t\t\tvar len = list.numberOfItems;\n
\t\t\t\tchanges["points"] = new Array(len);\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar pt = list.getItem(i);\n
\t\t\t\t\tchanges["points"][i] = {x:pt.x,y:pt.y};\n
\t\t\t\t}\n
\t\t\t\tbreak;\n
\t\t\tcase "path":\n
\t\t\t\tinitial = {};\n
\t\t\t\tinitial["d"] = selected.getAttribute("d");\n
\t\t\t\tchanges["d"] = selected.getAttribute("d");\n
\t\t\t\tbreak;\n
\t\t} // switch on element type to get initial values\n
\t\t\n
\t\tif(attrs.length) {\n
\t\t\tchanges = $(selected).attr(attrs);\n
\t\t\t$.each(changes, function(attr, val) {\n
\t\t\t\tchanges[attr] = convertToNum(attr, val);\n
\t\t\t});\n
\t\t}\n
\t\t\n
\t\t// if we haven\'t created an initial array in polygon/polyline/path, then \n
\t\t// make a copy of initial values and include the transform\n
\t\tif (initial == null) {\n
\t\t\tinitial = $.extend(true, {}, changes);\n
\t\t\t$.each(initial, function(attr, val) {\n
\t\t\t\tinitial[attr] = convertToNum(attr, val);\n
\t\t\t});\n
\t\t}\n
\t\t// save the start transform value too\n
\t\tinitial["transform"] = start_transform ? start_transform : "";\n
\t\t\n
\t\t// if it\'s a group, we have special processing to flatten transforms\n
\t\tif (selected.tagName == "g" || selected.tagName == "a") {\n
\t\t\tvar box = canvas.getBBox(selected),\n
\t\t\t\toldcenter = {x: box.x+box.width/2, y: box.y+box.height/2},\n
\t\t\t\tnewcenter = transformPoint(box.x+box.width/2, box.y+box.height/2,\n
\t\t\t\t\t\t\t\ttransformListToTransform(tlist).matrix),\n
\t\t\t\tm = svgroot.createSVGMatrix();\n
\t\t\t\n
\t\t\t\n
\t\t\t// temporarily strip off the rotate and save the old center\n
\t\t\tvar gangle = canvas.getRotationAngle(selected);\n
\t\t\tif (gangle) {\n
\t\t\t\tvar a = gangle * Math.PI / 180;\n
\t\t\t\tif ( Math.abs(a) > (1.0e-10) ) {\n
\t\t\t\t\tvar s = Math.sin(a)/(1 - Math.cos(a));\n
\t\t\t\t} else {\n
\t\t\t\t\t// FIXME: This blows up if the angle is exactly 0!\n
\t\t\t\t\tvar s = 2/a;\n
\t\t\t\t}\n
\t\t\t\tfor (var i = 0; i < tlist.numberOfItems; ++i) {\n
\t\t\t\t\tvar xform = tlist.getItem(i);\n
\t\t\t\t\tif (xform.type == 4) {\n
\t\t\t\t\t\t// extract old center through mystical arts\n
\t\t\t\t\t\tvar rm = xform.matrix;\n
\t\t\t\t\t\toldcenter.y = (s*rm.e + rm.f)/2;\n
\t\t\t\t\t\toldcenter.x = (rm.e - s*rm.f)/2;\n
\t\t\t\t\t\ttlist.removeItem(i);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tvar tx = 0, ty = 0,\n
\t\t\t\toperation = 0,\n
\t\t\t\tN = tlist.numberOfItems;\n
\n
\t\t\tif(N) {\n
\t\t\t\tvar first_m = tlist.getItem(0).matrix;\n
\t\t\t}\n
\n
\t\t\t// first, if it was a scale then the second-last transform will be it\n
\t\t\tif (N >= 3 && tlist.getItem(N-2).type == 3 && \n
\t\t\t\ttlist.getItem(N-3).type == 2 && tlist.getItem(N-1).type == 2) \n
\t\t\t{\n
\t\t\t\toperation = 3; // scale\n
\t\t\t\n
\t\t\t\t// if the children are unrotated, pass the scale down directly\n
\t\t\t\t// otherwise pass the equivalent matrix() down directly\n
\t\t\t\tvar tm = tlist.getItem(N-3).matrix,\n
\t\t\t\t\tsm = tlist.getItem(N-2).matrix,\n
\t\t\t\t\ttmn = tlist.getItem(N-1).matrix;\n
\t\t\t\n
\t\t\t\tvar children = selected.childNodes;\n
\t\t\t\tvar c = children.length;\n
\t\t\t\twhile (c--) {\n
\t\t\t\t\tvar child = children.item(c);\n
\t\t\t\t\ttx = 0;\n
\t\t\t\t\tty = 0;\n
\t\t\t\t\tif (child.nodeType == 1) {\n
\t\t\t\t\t\tvar childTlist = canvas.getTransformList(child);\n
\n
\t\t\t\t\t\t// some children might not have a transform (<metadata>, <defs>, etc)\n
\t\t\t\t\t\tif (!childTlist) continue;\n
\n
\t\t\t\t\t\tvar m = transformListToTransform(childTlist).matrix;\n
\t\t\t\t\t\n
\t\t\t\t\t\tvar angle = canvas.getRotationAngle(child);\n
\t\t\t\t\t\tvar old_start_transform = start_transform;\n
\t\t\t\t\t\tvar childxforms = [];\n
\t\t\t\t\t\tstart_transform = child.getAttribute("transform");\n
\t\t\t\t\t\tif(angle || hasMatrixTransform(childTlist)) {\n
\t\t\t\t\t\t\tvar e2t = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\te2t.setMatrix(matrixMultiply(tm, sm, tmn, m));\n
\t\t\t\t\t\t\tchildTlist.clear();\n
\t\t\t\t\t\t\tchildTlist.appendItem(e2t);\n
\t\t\t\t\t\t\tchildxforms.push(e2t);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// if not rotated or skewed, push the [T][S][-T] down to the child\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\t// update the transform list with translate,scale,translate\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// slide the [T][S][-T] from the front to the back\n
\t\t\t\t\t\t\t// [T][S][-T][M] = [M][T2][S2][-T2]\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// (only bringing [-T] to the right of [M])\n
\t\t\t\t\t\t\t// [T][S][-T][M] = [T][S][M][-T2]\n
\t\t\t\t\t\t\t// [-T2] = [M_inv][-T][M]\n
\t\t\t\t\t\t\tvar t2n = matrixMultiply(m.inverse(), tmn, m);\n
\t\t\t\t\t\t\t// [T2] is always negative translation of [-T2]\n
\t\t\t\t\t\t\tvar t2 = svgroot.createSVGMatrix();\n
\t\t\t\t\t\t\tt2.e = -t2n.e;\n
\t\t\t\t\t\t\tt2.f = -t2n.f;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// [T][S][-T][M] = [M][T2][S2][-T2]\n
\t\t\t\t\t\t\t// [S2] = [T2_inv][M_inv][T][S][-T][M][-T2_inv]\n
\t\t\t\t\t\t\tvar s2 = matrixMultiply(t2.inverse(), m.inverse(), tm, sm, tmn, m, t2n.inverse());\n
\n
\t\t\t\t\t\t\tvar translateOrigin = svgroot.createSVGTransform(),\n
\t\t\t\t\t\t\t\tscale = svgroot.createSVGTransform(),\n
\t\t\t\t\t\t\t\ttranslateBack = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\ttranslateOrigin.setTranslate(t2n.e, t2n.f);\n
\t\t\t\t\t\t\tscale.setScale(s2.a, s2.d);\n
\t\t\t\t\t\t\ttranslateBack.setTranslate(t2.e, t2.f);\n
\t\t\t\t\t\t\tchildTlist.appendItem(translateBack);\n
\t\t\t\t\t\t\tchildTlist.appendItem(scale);\n
\t\t\t\t\t\t\tchildTlist.appendItem(translateOrigin);\n
\t\t\t\t\t\t\tchildxforms.push(translateBack);\n
\t\t\t\t\t\t\tchildxforms.push(scale);\n
\t\t\t\t\t\t\tchildxforms.push(translateOrigin);\n
\t\t\t\t\t\t\tlogMatrix(translateBack.matrix);\n
\t\t\t\t\t\t\tlogMatrix(scale.matrix);\n
\t\t\t\t\t\t} // not rotated\n
\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(child) );\n
\t\t\t\t\t\t// TODO: If any <use> have this group as a parent and are \n
\t\t\t\t\t\t// referencing this child, then we need to impose a reverse \n
\t\t\t\t\t\t// scale on it so that when it won\'t get double-translated\n
//\t\t\t\t\t\tvar uses = selected.getElementsByTagNameNS(svgns, "use");\n
//\t\t\t\t\t\tvar href = "#"+child.id;\n
//\t\t\t\t\t\tvar u = uses.length;\n
//\t\t\t\t\t\twhile (u--) {\n
//\t\t\t\t\t\t\tvar useElem = uses.item(u);\n
//\t\t\t\t\t\t\tif(href == useElem.getAttributeNS(xlinkns, "href")) {\n
//\t\t\t\t\t\t\t\tvar usexlate = svgroot.createSVGTransform();\n
//\t\t\t\t\t\t\t\tusexlate.setTranslate(-tx,-ty);\n
//\t\t\t\t\t\t\t\tcanvas.getTransformList(useElem).insertItemBefore(usexlate,0);\n
//\t\t\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(useElem) );\n
//\t\t\t\t\t\t\t}\n
//\t\t\t\t\t\t}\n
\t\t\t\t\t\tstart_transform = old_start_transform;\n
\t\t\t\t\t} // element\n
\t\t\t\t} // for each child\n
\t\t\t\t// Remove these transforms from group\n
\t\t\t\ttlist.removeItem(N-1);\n
\t\t\t\ttlist.removeItem(N-2);\n
\t\t\t\ttlist.removeItem(N-3);\n
\t\t\t}\n
\t\t\telse if (N >= 3 && tlist.getItem(N-1).type == 1)\n
\t\t\t{\n
\t\t\t\toperation = 3; // scale\n
\t\t\t\tm = transformListToTransform(tlist).matrix;\n
\t\t\t\tvar e2t = svgroot.createSVGTransform();\n
\t\t\t\te2t.setMatrix(m);\n
\t\t\t\ttlist.clear();\n
\t\t\t\ttlist.appendItem(e2t);\n
\t\t\t}\t\t\t\n
\t\t\t// next, check if the first transform was a translate \n
\t\t\t// if we had [ T1 ] [ M ] we want to transform this into [ M ] [ T2 ]\n
\t\t\t// therefore [ T2 ] = [ M_inv ] [ T1 ] [ M ]\n
\t\t\telse if ( (N == 1 || (N > 1 && tlist.getItem(1).type != 3)) && \n
\t\t\t\ttlist.getItem(0).type == 2) \n
\t\t\t{\n
\t\t\t\toperation = 2; // translate\n
\t\t\t\tvar T_M = transformListToTransform(tlist).matrix;\n
\t\t\t\ttlist.removeItem(0);\n
\t\t\t\tvar M_inv = transformListToTransform(tlist).matrix.inverse();\n
\t\t\t\tvar M2 = matrixMultiply( M_inv, T_M );\n
\t\t\t\t\n
\t\t\t\ttx = M2.e;\n
\t\t\t\tty = M2.f;\n
\n
\t\t\t\tif (tx != 0 || ty != 0) {\n
\t\t\t\t\t// we pass the translates down to the individual children\n
\t\t\t\t\tvar children = selected.childNodes;\n
\t\t\t\t\tvar c = children.length;\n
\t\t\t\t\twhile (c--) {\n
\t\t\t\t\t\tvar child = children.item(c);\n
\t\t\t\t\t\tif (child.nodeType == 1) {\n
\t\t\t\t\t\t\tvar old_start_transform = start_transform;\n
\t\t\t\t\t\t\tstart_transform = child.getAttribute("transform");\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar childTlist = canvas.getTransformList(child);\n
\t\t\t\t\t\t\t// some children might not have a transform (<metadata>, <defs>, etc)\n
\t\t\t\t\t\t\tif (childTlist) {\n
\t\t\t\t\t\t\t\tvar newxlate = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\t\tnewxlate.setTranslate(tx,ty);\n
\t\t\t\t\t\t\t\tchildTlist.insertItemBefore(newxlate, 0);\n
\t\t\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(child) );\n
\t\t\t\t\t\t\t\t// If any <use> have this group as a parent and are \n
\t\t\t\t\t\t\t\t// referencing this child, then impose a reverse translate on it\n
\t\t\t\t\t\t\t\t// so that when it won\'t get double-translated\n
\t\t\t\t\t\t\t\tvar uses = selected.getElementsByTagNameNS(svgns, "use");\n
\t\t\t\t\t\t\t\tvar href = "#"+child.id;\n
\t\t\t\t\t\t\t\tvar u = uses.length;\n
\t\t\t\t\t\t\t\twhile (u--) {\n
\t\t\t\t\t\t\t\t\tvar useElem = uses.item(u);\n
\t\t\t\t\t\t\t\t\tif(href == useElem.getAttributeNS(xlinkns, "href")) {\n
\t\t\t\t\t\t\t\t\t\tvar usexlate = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\t\t\t\tusexlate.setTranslate(-tx,-ty);\n
\t\t\t\t\t\t\t\t\t\tcanvas.getTransformList(useElem).insertItemBefore(usexlate,0);\n
\t\t\t\t\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(useElem) );\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tstart_transform = old_start_transform;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tstart_transform = old_start_transform;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// else, a matrix imposition from a parent group\n
\t\t\t// keep pushing it down to the children\n
\t\t\telse if (N == 1 && tlist.getItem(0).type == 1 && !gangle) {\n
\t\t\t\toperation = 1;\n
\t\t\t\tvar m = tlist.getItem(0).matrix,\n
\t\t\t\t\tchildren = selected.childNodes,\n
\t\t\t\t\tc = children.length;\n
\t\t\t\twhile (c--) {\n
\t\t\t\t\tvar child = children.item(c);\n
\t\t\t\t\tif (child.nodeType == 1) {\n
\t\t\t\t\t\tvar old_start_transform = start_transform;\n
\t\t\t\t\t\tstart_transform = child.getAttribute("transform");\n
\t\t\t\t\t\tvar childTlist = canvas.getTransformList(child);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar em = matrixMultiply(m, transformListToTransform(childTlist).matrix);\n
\t\t\t\t\t\tvar e2m = svgroot.createSVGTransform();\n
\t\t\t\t\t\te2m.setMatrix(em);\n
\t\t\t\t\t\tchildTlist.clear();\n
\t\t\t\t\t\tchildTlist.appendItem(e2m,0);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(child) );\n
\t\t\t\t\t\tstart_transform = old_start_transform;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\ttlist.clear();\n
\t\t\t}\n
\t\t\t// else it was just a rotate\n
\t\t\telse {\n
\t\t\t\tif (gangle) {\n
\t\t\t\t\tvar newRot = svgroot.createSVGTransform();\n
\t\t\t\t\tnewRot.setRotate(gangle,newcenter.x,newcenter.y);\n
\t\t\t\t\ttlist.insertItemBefore(newRot, 0);\n
\t\t\t\t}\n
\t\t\t\tif (tlist.numberOfItems == 0) {\n
\t\t\t\t\tselected.removeAttribute("transform");\n
\t\t\t\t}\n
\t\t\t\treturn null;\t\t\t\n
\t\t\t}\n
\t\t\t\n
\t\t\t// if it was a translate, put back the rotate at the new center\n
\t\t\tif (operation == 2) {\n
\t\t\t\tif (gangle) {\n
\t\t\t\t\tnewcenter = {\n
\t\t\t\t\t\tx: oldcenter.x + first_m.e,\n
\t\t\t\t\t\ty: oldcenter.y + first_m.f\n
\t\t\t\t\t};\n
\t\t\t\t\n
\t\t\t\t\tvar newRot = svgroot.createSVGTransform();\n
\t\t\t\t\tnewRot.setRotate(gangle,newcenter.x,newcenter.y);\n
\t\t\t\t\ttlist.insertItemBefore(newRot, 0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// if it was a resize\n
\t\t\telse if (operation == 3) {\n
\t\t\t\tvar m = transformListToTransform(tlist).matrix;\n
\t\t\t\tvar roldt = svgroot.createSVGTransform();\n
\t\t\t\troldt.setRotate(gangle, oldcenter.x, oldcenter.y);\n
\t\t\t\tvar rold = roldt.matrix;\n
\t\t\t\tvar rnew = svgroot.createSVGTransform();\n
\t\t\t\trnew.setRotate(gangle, newcenter.x, newcenter.y);\n
\t\t\t\tvar rnew_inv = rnew.matrix.inverse(),\n
\t\t\t\t\tm_inv = m.inverse(),\n
\t\t\t\t\textrat = matrixMultiply(m_inv, rnew_inv, rold, m);\n
\n
\t\t\t\ttx = extrat.e;\n
\t\t\t\tty = extrat.f;\n
\n
\t\t\t\tif (tx != 0 || ty != 0) {\n
\t\t\t\t\t// now push this transform down to the children\n
\t\t\t\t\t// we pass the translates down to the individual children\n
\t\t\t\t\tvar children = selected.childNodes;\n
\t\t\t\t\tvar c = children.length;\n
\t\t\t\t\twhile (c--) {\n
\t\t\t\t\t\tvar child = children.item(c);\n
\t\t\t\t\t\tif (child.nodeType == 1) {\n
\t\t\t\t\t\t\tvar old_start_transform = start_transform;\n
\t\t\t\t\t\t\tstart_transform = child.getAttribute("transform");\n
\t\t\t\t\t\t\tvar childTlist = canvas.getTransformList(child);\n
\t\t\t\t\t\t\tvar newxlate = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\tnewxlate.setTranslate(tx,ty);\n
\t\t\t\t\t\t\tchildTlist.insertItemBefore(newxlate, 0);\n
\t\t\t\t\t\t\tbatchCmd.addSubCommand( recalculateDimensions(child) );\n
\t\t\t\t\t\t\tstart_transform = old_start_transform;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif (gangle) {\n
\t\t\t\t\ttlist.insertItemBefore(rnew, 0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// else, it\'s a non-group\n
\t\telse {\n
\t\t\t// FIXME: box might be null for some elements (<metadata> etc), need to handle this\n
\t\t\tvar box = canvas.getBBox(selected);\n
\t\t\tif(!box) return null;\n
\t\t\t\n
\t\t\tvar oldcenter = {x: box.x+box.width/2, y: box.y+box.height/2},\n
\t\t\t\tnewcenter = transformPoint(box.x+box.width/2, box.y+box.height/2,\n
\t\t\t\t\t\t\t\ttransformListToTransform(tlist).matrix),\n
\t\t\t\tm = svgroot.createSVGMatrix(),\n
\t\t\t\t// temporarily strip off the rotate and save the old center\n
\t\t\t\tangle = canvas.getRotationAngle(selected);\n
\t\t\tif (angle) {\n
\t\t\t\tvar a = angle * Math.PI / 180;\n
\t\t\t\tif ( Math.abs(a) > (1.0e-10) ) {\n
\t\t\t\t\tvar s = Math.sin(a)/(1 - Math.cos(a));\n
\t\t\t\t} else {\n
\t\t\t\t\t// FIXME: This blows up if the angle is exactly 0!\n
\t\t\t\t\tvar s = 2/a;\n
\t\t\t\t}\n
\t\t\t\tfor (var i = 0; i < tlist.numberOfItems; ++i) {\n
\t\t\t\t\tvar xform = tlist.getItem(i);\n
\t\t\t\t\tif (xform.type == 4) {\n
\t\t\t\t\t\t// extract old center through mystical arts\n
\t\t\t\t\t\tvar rm = xform.matrix;\n
\t\t\t\t\t\toldcenter.y = (s*rm.e + rm.f)/2;\n
\t\t\t\t\t\toldcenter.x = (rm.e - s*rm.f)/2;\n
\t\t\t\t\t\ttlist.removeItem(i);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// 2 = translate, 3 = scale, 4 = rotate, 1 = matrix imposition\n
\t\t\tvar operation = 0;\n
\t\t\tvar N = tlist.numberOfItems;\n
\t\t\t\n
\t\t\t\n
\t\t\t// Check if it has a gradient with userSpaceOnUse, in which case\n
\t\t\t// adjust it by recalculating the matrix transform.\n
\t\t\t// TODO: Make this work in Webkit using SVGEditTransformList\n
\t\t\tif(!isWebkit) {\n
\t\t\t\tvar fill = selected.getAttribute(\'fill\');\n
\t\t\t\tif(fill && fill.indexOf(\'url(\') === 0) {\n
\t\t\t\t\tvar grad = getElem(getUrlFromAttr(fill).substr(1));\n
\t\t\t\t\tif(grad.getAttribute(\'gradientUnits\') === \'userSpaceOnUse\') {\n
\t\t\t\t\t\t//Update the userSpaceOnUse element\n
\t\t\t\t\t\tvar grad = $(grad);\n
\t\t\t\t\t\tm = transformListToTransform(tlist).matrix;\n
\t\t\t\t\t\tvar gtlist = canvas.getTransformList(grad[0]);\n
\t\t\t\t\t\tvar gmatrix = transformListToTransform(gtlist).matrix;\n
\t\t\t\t\t\tm = matrixMultiply(m, gmatrix);\n
\t\t\t\t\t\tvar m_str = "matrix(" + [m.a,m.b,m.c,m.d,m.e,m.f].join(",") + ")";\n
\t\t\t\t\t\tgrad.attr(\'gradientTransform\', m_str);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// first, if it was a scale of a non-skewed element, then the second-last  \n
\t\t\t// transform will be the [S]\n
\t\t\t// if we had [M][T][S][T] we want to extract the matrix equivalent of\n
\t\t\t// [T][S][T] and push it down to the element\n
\t\t\tif (N >= 3 && tlist.getItem(N-2).type == 3 && \n
\t\t\t\ttlist.getItem(N-3).type == 2 && tlist.getItem(N-1).type == 2 &&\n
\t\t\t\tselected.nodeName != "use") \n
\t\t\t{\n
\t\t\t\toperation = 3; // scale\n
\t\t\t\tm = transformListToTransform(tlist,N-3,N-1).matrix;\n
\t\t\t\ttlist.removeItem(N-1);\n
\t\t\t\ttlist.removeItem(N-2);\n
\t\t\t\ttlist.removeItem(N-3);\n
\t\t\t} // if we had [T][S][-T][M], then this was a skewed element being resized\n
\t\t\t// Thus, we simply combine it all into one matrix\n
\t\t\telse if(N == 4 && tlist.getItem(N-1).type == 1) {\n
\t\t\t\toperation = 3; // scale\n
\t\t\t\tm = transformListToTransform(tlist).matrix;\n
\t\t\t\tvar e2t = svgroot.createSVGTransform();\n
\t\t\t\te2t.setMatrix(m);\n
\t\t\t\ttlist.clear();\n
\t\t\t\ttlist.appendItem(e2t);\n
\t\t\t\t// reset the matrix so that the element is not re-mapped\n
\t\t\t\tm = svgroot.createSVGMatrix();\n
\t\t\t} // if we had [R][T][S][-T][M], then this was a rotated matrix-element  \n
\t\t\t// if we had [T1][M] we want to transform this into [M][T2]\n
\t\t\t// therefore [ T2 ] = [ M_inv ] [ T1 ] [ M ] and we can push [T2] \n
\t\t\t// down to the element\n
\t\t\telse if ( (N == 1 || (N > 1 && tlist.getItem(1).type != 3)) && \n
\t\t\t\ttlist.getItem(0).type == 2) \n
\t\t\t{\n
\t\t\t\toperation = 2; // translate\n
\t\t\t\tvar oldxlate = tlist.getItem(0).matrix,\n
\t\t\t\t\tmeq = transformListToTransform(tlist,1).matrix,\n
\t\t\t\t\tmeq_inv = meq.inverse();\n
\t\t\t\tm = matrixMultiply( meq_inv, oldxlate, meq );\n
\t\t\t\ttlist.removeItem(0);\n
\t\t\t}\n
\t\t\t// else if this child now has a matrix imposition (from a parent group)\n
\t\t\t// we might be able to simplify\n
\t\t\telse if (N == 1 && tlist.getItem(0).type == 1 && !angle) {\n
\t\t\t\t// Remap all point-based elements\n
\t\t\t\tm = transformListToTransform(tlist).matrix;\n
\t\t\t\tswitch (selected.tagName) {\n
\t\t\t\t\tcase \'line\':\n
\t\t\t\t\t\tchanges = $(selected).attr(["x1","y1","x2","y2"]);\n
\t\t\t\t\tcase \'polyline\':\n
\t\t\t\t\tcase \'polygon\':\n
\t\t\t\t\t\tchanges.points = selected.getAttribute("points");\n
\t\t\t\t\t\tif(changes.points) {\n
\t\t\t\t\t\t\tvar list = selected.points;\n
\t\t\t\t\t\t\tvar len = list.numberOfItems;\n
\t\t\t\t\t\t\tchanges.points = new Array(len);\n
\t\t\t\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\t\t\t\tvar pt = list.getItem(i);\n
\t\t\t\t\t\t\t\tchanges.points[i] = {x:pt.x,y:pt.y};\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\tcase \'path\':\n
\t\t\t\t\t\tchanges.d = selected.getAttribute("d");\n
\t\t\t\t\t\toperation = 1;\n
\t\t\t\t\t\ttlist.clear();\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault:\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// if it was a rotation, put the rotate back and return without a command\n
\t\t\t// (this function has zero work to do for a rotate())\n
\t\t\telse {\n
\t\t\t\toperation = 4; // rotation\n
\t\t\t\tif (angle) {\n
\t\t\t\t\tvar newRot = svgroot.createSVGTransform();\n
\t\t\t\t\tnewRot.setRotate(angle,newcenter.x,newcenter.y);\n
\t\t\t\t\ttlist.insertItemBefore(newRot, 0);\n
\t\t\t\t}\n
\t\t\t\tif (tlist.numberOfItems == 0) {\n
\t\t\t\t\tselected.removeAttribute("transform");\n
\t\t\t\t}\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// if it was a translate or resize, we need to remap the element and absorb the xform\n
\t\t\tif (operation == 1 || operation == 2 || operation == 3) {\n
\t\t\t\tremapElement(selected,changes,m);\n
\t\t\t} // if we are remapping\n
\t\t\t\n
\t\t\t// if it was a translate, put back the rotate at the new center\n
\t\t\tif (operation == 2) {\n
\t\t\t\tif (angle) {\n
\t\t\t\t\tnewcenter = {\n
\t\t\t\t\t\tx: oldcenter.x + m.e,\n
\t\t\t\t\t\ty: oldcenter.y + m.f\n
\t\t\t\t\t};\n
\t\t\t\t\tvar newRot = svgroot.createSVGTransform();\n
\t\t\t\t\tnewRot.setRotate(angle, newcenter.x, newcenter.y);\n
\t\t\t\t\ttlist.insertItemBefore(newRot, 0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t// [Rold][M][T][S][-T] became [Rold][M]\n
\t\t\t// we want it to be [Rnew][M][Tr] where Tr is the\n
\t\t\t// translation required to re-center it\n
\t\t\t// Therefore, [Tr] = [M_inv][Rnew_inv][Rold][M]\n
\t\t\telse if (operation == 3) {\n
\t\t\t\tvar m = transformListToTransform(tlist).matrix;\n
\t\t\t\tvar roldt = svgroot.createSVGTransform();\n
\t\t\t\troldt.setRotate(angle, oldcenter.x, oldcenter.y);\n
\t\t\t\tvar rold = roldt.matrix;\n
\t\t\t\tvar rnew = svgroot.createSVGTransform();\n
\t\t\t\trnew.setRotate(angle, newcenter.x, newcenter.y);\n
\t\t\t\tvar rnew_inv = rnew.matrix.inverse();\n
\t\t\t\tvar m_inv = m.inverse();\n
\t\t\t\tvar extrat = matrixMultiply(m_inv, rnew_inv, rold, m);\n
\t\t\t\n
\t\t\t\tremapElement(selected,changes,extrat);\n
\t\t\t\tif (angle) {\n
\t\t\t\t\ttlist.insertItemBefore(rnew,0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} // a non-group\n
\n
\t\t// if the transform list has been emptied, remove it\n
\t\tif (tlist.numberOfItems == 0) {\n
\t\t\tselected.removeAttribute("transform");\n
\t\t}\n
\t\tbatchCmd.addSubCommand(new ChangeElementCommand(selected, initial));\n
\t\t\n
\t\treturn batchCmd;\n
\t};\n
\n
// public events\n
\n
\t// Group: Selection\n
\n
\t// Function: clearSelection\n
\t// Clears the selection.  The \'selected\' handler is then called.\n
\tthis.clearSelection = function(noCall) {\n
\t\tif (selectedElements[0] != null) {\n
\t\t\tvar len = selectedElements.length;\n
\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\tvar elem = selectedElements[i];\n
\t\t\t\tif (elem == null) break;\n
\t\t\t\tselectorManager.releaseSelector(elem);\n
\t\t\t\tselectedElements[i] = null;\n
\t\t\t}\n
\t\t\tselectedBBoxes[0] = null;\n
\t\t}\n
\t\tif(!noCall) call("selected", selectedElements);\n
\t};\n
\n
\t// TODO: do we need to worry about selectedBBoxes here?\n
\t\n
\t// Function: addToSelection\n
\t// Adds a list of elements to the selection.  The \'selected\' handler is then called.\n
\t//\n
\t// Parameters:\n
\t// elemsToAdd - an array of DOM elements to add to the selection\n
\t// showGrips - a boolean flag indicating whether the resize grips should be shown\n
\tthis.addToSelection = function(elemsToAdd, showGrips) {\n
\t\tif (elemsToAdd.length == 0) { return; }\n
\t\t// find the first null in our selectedElements array\n
\t\tvar j = 0;\n
\t\twhile (j < selectedElements.length) {\n
\t\t\tif (selectedElements[j] == null) { \n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\t++j;\n
\t\t}\n
\n
\t\t// now add each element consecutively\n
\t\tvar i = elemsToAdd.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = elemsToAdd[i];\n
\t\t\tif (!elem || !this.getBBox(elem)) continue;\n
\t\t\t// if it\'s not already there, add it\n
\t\t\tif (selectedElements.indexOf(elem) == -1) {\n
\t\t\t\tselectedElements[j] = elem;\n
\t\t\t\t// only the first selectedBBoxes element is ever used in the codebase these days\n
\t\t\t\tif (j == 0) selectedBBoxes[j] = this.getBBox(elem);\n
\t\t\t\tj++;\n
\t\t\t\tvar sel = selectorManager.requestSelector(elem);\n
\t\t\n
\t\t\t\tif (selectedElements.length > 1) {\n
\t\t\t\t\tsel.showGrips(false);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tif(selectedElements[0] && selectedElements.length === 1 && selectedElements[0].tagName == \'a\') {\n
\t\t\t// Make "a" element\'s child be the selected element \n
\t\t\tselectedElements[0] = selectedElements[0].firstChild;\n
\t\t}\n
\t\t\n
\t\tcall("selected", selectedElements);\n
\t\t\n
\t\tif (showGrips || selectedElements.length == 1) {\n
\t\t\tselectorManager.requestSelector(selectedElements[0]).showGrips(true);\n
\t\t}\n
\t\telse {\n
\t\t\tselectorManager.requestSelector(selectedElements[0]).showGrips(false);\n
\t\t}\n
\n
\t\t// make sure the elements are in the correct order\n
\t\t// See: http://www.w3.org/TR/DOM-Level-3-Core/core.html#Node3-compareDocumentPosition\n
\t\n
\t\tselectedElements.sort(function(a,b) {\n
\t\t\tif(a && b && a.compareDocumentPosition) {\n
\t\t\t\treturn 3 - (b.compareDocumentPosition(a) & 6);\t\n
\t\t\t} else if(a == null) {\n
\t\t\t\treturn 1;\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\t// Make sure first elements are not null\n
\t\twhile(selectedElements[0] == null) selectedElements.shift(0);\n
\t};\n
\n
\t// TODO: could use slice here to make this faster?\n
\t// TODO: should the \'selected\' handler\n
\t\n
\t// Function: removeFromSelection\n
\t// Removes elements from the selection.\n
\t//\n
\t// Parameters:\n
\t// elemsToRemove - an array of elements to remove from selection\n
\tthis.removeFromSelection = function(elemsToRemove) {\n
\t\tif (selectedElements[0] == null) { return; }\n
\t\tif (elemsToRemove.length == 0) { return; }\n
\n
\t\t// find every element and remove it from our array copy\n
\t\tvar newSelectedItems = new Array(selectedElements.length),\n
\t\t\tnewSelectedBBoxes = new Array(selectedBBoxes.length),\n
\t\t\tj = 0,\n
\t\t\tlen = selectedElements.length;\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (

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

elem) {\n
\t\t\t\t// keep the item\n
\t\t\t\tif (elemsToRemove.indexOf(elem) == -1) {\n
\t\t\t\t\tnewSelectedItems[j] = elem;\n
\t\t\t\t\tif (j==0) newSelectedBBoxes[j] = selectedBBoxes[i];\n
\t\t\t\t\tj++;\n
\t\t\t\t}\n
\t\t\t\telse { // remove the item and its selector\n
\t\t\t\t\tselectorManager.releaseSelector(elem);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// the copy becomes the master now\n
\t\tselectedElements = newSelectedItems;\n
\t\tselectedBBoxes = newSelectedBBoxes;\n
\t};\n
\t\n
\t// Some global variables that we may need to refactor\n
\tvar root_sctm = null;\n
\n
\t// A (hopefully) quicker function to transform a point by a matrix\n
\t// (this function avoids any DOM calls and just does the math)\n
\t// Returns a x,y object representing the transformed point\n
\tvar transformPoint = function(x, y, m) {\n
\t\treturn { x: m.a * x + m.c * y + m.e, y: m.b * x + m.d * y + m.f};\n
\t};\n
\t\n
\tvar isIdentity = function(m) {\n
\t\treturn (m.a == 1 && m.b == 0 && m.c == 0 && m.d == 1 && m.e == 0 && m.f == 0);\n
\t}\n
\t\n
\t// expects three points to be sent, each point must have an x,y field\n
\t// returns an array of two points that are the smoothed\n
\tthis.smoothControlPoints = function(ct1, ct2, pt) {\n
\t\t// each point must not be the origin\n
\t\tvar x1 = ct1.x - pt.x,\n
\t\t\ty1 = ct1.y - pt.y,\n
\t\t\tx2 = ct2.x - pt.x,\n
\t\t\ty2 = ct2.y - pt.y;\n
\t\t\t\n
\t\tif ( (x1 != 0 || y1 != 0) && (x2 != 0 || y2 != 0) ) {\n
\t\t\tvar anglea = Math.atan2(y1,x1),\n
\t\t\t\tangleb = Math.atan2(y2,x2),\n
\t\t\t\tr1 = Math.sqrt(x1*x1+y1*y1),\n
\t\t\t\tr2 = Math.sqrt(x2*x2+y2*y2),\n
\t\t\t\tnct1 = svgroot.createSVGPoint(),\n
\t\t\t\tnct2 = svgroot.createSVGPoint();\t\t\t\t\n
\t\t\tif (anglea < 0) { anglea += 2*Math.PI; }\n
\t\t\tif (angleb < 0) { angleb += 2*Math.PI; }\n
\t\t\t\n
\t\t\tvar angleBetween = Math.abs(anglea - angleb),\n
\t\t\t\tangleDiff = Math.abs(Math.PI - angleBetween)/2;\n
\t\t\t\n
\t\t\tvar new_anglea, new_angleb;\n
\t\t\tif (anglea - angleb > 0) {\n
\t\t\t\tnew_anglea = angleBetween < Math.PI ? (anglea + angleDiff) : (anglea - angleDiff);\n
\t\t\t\tnew_angleb = angleBetween < Math.PI ? (angleb - angleDiff) : (angleb + angleDiff);\n
\t\t\t}\n
\t\t\telse {\n
\t\t\t\tnew_anglea = angleBetween < Math.PI ? (anglea - angleDiff) : (anglea + angleDiff);\n
\t\t\t\tnew_angleb = angleBetween < Math.PI ? (angleb + angleDiff) : (angleb - angleDiff);\n
\t\t\t}\n
\t\t\t\n
\t\t\t// rotate the points\n
\t\t\tnct1.x = r1 * Math.cos(new_anglea) + pt.x;\n
\t\t\tnct1.y = r1 * Math.sin(new_anglea) + pt.y;\n
\t\t\tnct2.x = r2 * Math.cos(new_angleb) + pt.x;\n
\t\t\tnct2.y = r2 * Math.sin(new_angleb) + pt.y;\n
\t\t\t\n
\t\t\treturn [nct1, nct2];\n
\t\t}\n
\t\treturn undefined;\n
\t};\n
\tvar smoothControlPoints = this.smoothControlPoints;\n
\t\t\n
\n
\t// matrixMultiply() is provided because WebKit didn\'t implement multiply() correctly\n
\t// on the SVGMatrix interface.  See https://bugs.webkit.org/show_bug.cgi?id=16062\n
\t// This function tries to return a SVGMatrix that is the multiplication m1*m2.\n
\t// We also round to zero when it\'s near zero\n
\tthis.matrixMultiply = function() {\n
\t\tvar NEAR_ZERO = 1e-14,\n
\t\t\tmulti2 = function(m1, m2) {\n
\t\t\t\tvar m = svgroot.createSVGMatrix();\n
\t\t\t\tm.a = m1.a*m2.a + m1.c*m2.b;\n
\t\t\t\tm.b = m1.b*m2.a + m1.d*m2.b,\n
\t\t\t\tm.c = m1.a*m2.c + m1.c*m2.d,\n
\t\t\t\tm.d = m1.b*m2.c + m1.d*m2.d,\n
\t\t\t\tm.e = m1.a*m2.e + m1.c*m2.f + m1.e,\n
\t\t\t\tm.f = m1.b*m2.e + m1.d*m2.f + m1.f;\n
\t\t\t\treturn m;\n
\t\t\t},\n
\t\t\targs = arguments, i = args.length, m = args[i-1];\n
\t\t\n
\t\twhile(i-- > 1) {\n
\t\t\tvar m1 = args[i-1];\n
\t\t\tm = multi2(m1, m);\n
\t\t}\n
\t\tif (Math.abs(m.a) < NEAR_ZERO) m.a = 0;\n
\t\tif (Math.abs(m.b) < NEAR_ZERO) m.b = 0;\n
\t\tif (Math.abs(m.c) < NEAR_ZERO) m.c = 0;\n
\t\tif (Math.abs(m.d) < NEAR_ZERO) m.d = 0;\n
\t\tif (Math.abs(m.e) < NEAR_ZERO) m.e = 0;\n
\t\tif (Math.abs(m.f) < NEAR_ZERO) m.f = 0;\n
\t\t\n
\t\treturn m;\n
\t}\n
\tvar matrixMultiply = this.matrixMultiply;\n
\t\n
\t// This returns a single matrix Transform for a given Transform List\n
\t// (this is the equivalent of SVGTransformList.consolidate() but unlike\n
\t//  that method, this one does not modify the actual SVGTransformList)\n
\t// This function is very liberal with its min,max arguments\n
\tvar transformListToTransform = function(tlist, min, max) {\n
\t\tvar min = min == undefined ? 0 : min;\n
\t\tvar max = max == undefined ? (tlist.numberOfItems-1) : max;\n
\t\tmin = parseInt(min);\n
\t\tmax = parseInt(max);\n
\t\tif (min > max) { var temp = max; max = min; min = temp; }\n
\t\tvar m = svgroot.createSVGMatrix();\n
\t\tfor (var i = min; i <= max; ++i) {\n
\t\t\t// if our indices are out of range, just use a harmless identity matrix\n
\t\t\tvar mtom = (i >= 0 && i < tlist.numberOfItems ? \n
\t\t\t\t\t\t\ttlist.getItem(i).matrix :\n
\t\t\t\t\t\t\tsvgroot.createSVGMatrix());\n
\t\t\tm = matrixMultiply(m, mtom);\n
\t\t}\n
\t\treturn svgroot.createSVGTransformFromMatrix(m);\n
\t};\n
\t\n
\tvar hasMatrixTransform = function(tlist) {\n
\t\tif(!tlist) return false;\n
\t\tvar num = tlist.numberOfItems;\n
\t\twhile (num--) {\n
\t\t\tvar xform = tlist.getItem(num);\n
\t\t\tif (xform.type == 1 && !isIdentity(xform.matrix)) return true;\n
\t\t}\n
\t\treturn false;\n
\t}\n
\t\n
\tvar getMatrix = function(elem) {\n
\t\tvar tlist = canvas.getTransformList(elem);\n
\t\treturn transformListToTransform(tlist).matrix;\n
\t}\n
\t\n
    // FIXME: this should not have anything to do with zoom here - update the one place it is used this way\n
    // converts a tiny object equivalent of a SVGTransform\n
\t// has the following properties:\n
\t// - tx, ty, sx, sy, angle, cx, cy, string\n
\tvar transformToObj = function(xform, mZoom) {\n
\t\tvar m = xform.matrix,\n
\t\t\ttobj = {tx:0,ty:0,sx:1,sy:1,angle:0,cx:0,cy:0,text:""},\n
\t\t\tz = mZoom?current_zoom:1;\n
\t\tswitch(xform.type) {\n
\t\t\tcase 1: // MATRIX\n
\t\t\t\ttobj.text = "matrix(" + [m.a,m.b,m.c,m.d,m.e,m.f].join(",") + ")";\n
\t\t\t\tbreak;\n
\t\t\tcase 2: // TRANSLATE\n
\t\t\t\ttobj.tx = m.e;\n
\t\t\t\ttobj.ty = m.f;\n
\t\t\t\ttobj.text = "translate(" + m.e*z + "," + m.f*z + ")";\n
\t\t\t\tbreak;\n
\t\t\tcase 3: // SCALE\n
\t\t\t\ttobj.sx = m.a;\n
\t\t\t\ttobj.sy = m.d;\n
\t\t\t\tif (m.a == m.d) tobj.text = "scale(" + m.a + ")";\n
\t\t\t\telse tobj.text = "scale(" + m.a + "," + m.d + ")";\n
\t\t\t\tbreak;\n
\t\t\tcase 4: // ROTATE\n
\t\t\t\ttobj.angle = xform.angle;\n
\t\t\t\t// this prevents divide by zero\n
\t\t\t\tif (xform.angle != 0) {\n
\t\t\t\t\tvar K = 1 - m.a;\n
\t\t\t\t\ttobj.cy = ( K * m.f + m.b*m.e ) / ( K*K + m.b*m.b );\n
\t\t\t\t\ttobj.cx = ( m.e - m.b * tobj.cy ) / K;\n
\t\t\t\t}\n
\t\t\t\ttobj.text = "rotate(" + xform.angle + " " + tobj.cx*z + "," + tobj.cy*z + ")";\n
\t\t\t\tbreak;\n
\t\t}\n
\t\treturn tobj;\n
\t};\n
\t\n
\tvar transformBox = function(l, t, w, h, m) {\n
\t\tvar topleft = {x:l,y:t},\n
\t\t\ttopright = {x:(l+w),y:t},\n
\t\t\tbotright = {x:(l+w),y:(t+h)},\n
\t\t\tbotleft = {x:l,y:(t+h)};\n
\t\ttopleft = transformPoint( topleft.x, topleft.y, m );\n
\t\tvar minx = topleft.x,\n
\t\t\tmaxx = topleft.x,\n
\t\t\tminy = topleft.y,\n
\t\t\tmaxy = topleft.y;\n
\t\ttopright = transformPoint( topright.x, topright.y, m );\n
\t\tminx = Math.min(minx, topright.x);\n
\t\tmaxx = Math.max(maxx, topright.x);\n
\t\tminy = Math.min(miny, topright.y);\n
\t\tmaxy = Math.max(maxy, topright.y);\n
\t\tbotleft = transformPoint( botleft.x, botleft.y, m);\n
\t\tminx = Math.min(minx, botleft.x);\n
\t\tmaxx = Math.max(maxx, botleft.x);\n
\t\tminy = Math.min(miny, botleft.y);\n
\t\tmaxy = Math.max(maxy, botleft.y);\n
\t\tbotright = transformPoint( botright.x, botright.y, m );\n
\t\tminx = Math.min(minx, botright.x);\n
\t\tmaxx = Math.max(maxx, botright.x);\n
\t\tminy = Math.min(miny, botright.y);\n
\t\tmaxy = Math.max(maxy, botright.y);\n
\n
\t\treturn {tl:topleft, tr:topright, bl:botleft, br:botright, \n
\t\t\t\taabox: {x:minx, y:miny, width:(maxx-minx), height:(maxy-miny)} };\n
\t};\n
\t\n
\tvar getMouseTarget = function(evt) {\n
\t\tif (evt == null) {\n
\t\t\treturn null;\n
\t\t}\n
\t\tvar mouse_target = evt.target;\n
\t\t\n
\t\t// if it was a <use>, Opera and WebKit return the SVGElementInstance\n
\t\tif (mouse_target.correspondingUseElement)\n
\t\t\n
\t\tmouse_target = mouse_target.correspondingUseElement;\n
\t\t// for foreign content, go up until we find the foreignObject\n
\t\t// WebKit browsers set the mouse target to the svgcanvas div \n
\t\tif ($.inArray(mouse_target.namespaceURI, [mathns, htmlns]) != -1 && \n
\t\t\tmouse_target.id != "svgcanvas") \n
\t\t{\n
\t\t\twhile (mouse_target.nodeName != "foreignObject") {\n
\t\t\t\tmouse_target = mouse_target.parentNode;\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\t// go up until we hit a child of a layer\n
\t\twhile (mouse_target.parentNode.parentNode.tagName == "g") {\n
\t\t\tmouse_target = mouse_target.parentNode;\n
\t\t}\n
\t\t// Webkit bubbles the mouse event all the way up to the div, so we\n
\t\t// set the mouse_target to the svgroot like the other browsers\n
\t\tif (mouse_target.nodeName.toLowerCase() == "div") {\n
\t\t\tmouse_target = svgroot;\n
\t\t}\n
\t\t\n
\t\treturn mouse_target;\n
\t};\n
\n
\t// Mouse events\n
\t(function() {\n
\t\t\n
\t\tvar d_attr = null,\n
\t\t\tstart_x = null,\n
\t\t\tstart_y = null,\n
\t\t\tinit_bbox = {},\n
\t\t\tfreehand = {\n
\t\t\t\tminx: null,\n
\t\t\t\tminy: null,\n
\t\t\t\tmaxx: null,\n
\t\t\t\tmaxy: null\n
\t\t\t};\n
\t\t\n
\t\t// - when we are in a create mode, the element is added to the canvas\n
\t\t//   but the action is not recorded until mousing up\n
\t\t// - when we are in select mode, select the element, remember the position\n
\t\t//   and do nothing else\n
\t\tvar mouseDown = function(evt)\n
\t\t{\n
\t\t\tif(evt.button === 1 || canvas.spaceKey) return;\n
\t\t\troot_sctm = svgcontent.getScreenCTM().inverse();\n
\t\t\tvar pt = transformPoint( evt.pageX, evt.pageY, root_sctm ),\n
\t\t\t\tmouse_x = pt.x * current_zoom,\n
\t\t\t\tmouse_y = pt.y * current_zoom;\n
\t\t\tevt.preventDefault();\n
\t\t\n
\t\t\tif($.inArray(current_mode, [\'select\', \'resize\']) == -1) {\n
\t\t\t\taddGradient();\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar x = mouse_x / current_zoom,\n
\t\t\t\ty = mouse_y / current_zoom,\n
\t\t\t\tmouse_target = getMouseTarget(evt);\n
\t\t\t\n
\t\t\tstart_x = x;\n
\t\t\tstart_y = y;\n
\t\n
\t\t\t// if it is a selector grip, then it must be a single element selected, \n
\t\t\t// set the mouse_target to that and update the mode to rotate/resize\n
\t\t\tif (mouse_target.parentNode == selectorManager.selectorParentGroup && selectedElements[0] != null) {\n
\t\t\t\tvar gripid = evt.target.id,\n
\t\t\t\t\tgriptype = gripid.substr(0,20);\n
\t\t\t\t// rotating\n
\t\t\t\tif (griptype == "selectorGrip_rotate_") {\n
\t\t\t\t\tcurrent_mode = "rotate";\n
\t\t\t\t}\n
\t\t\t\t// resizing\n
\t\t\t\telse if(griptype == "selectorGrip_resize_") {\n
\t\t\t\t\tcurrent_mode = "resize";\n
\t\t\t\t\tcurrent_resize_mode = gripid.substr(20,gripid.indexOf("_",20)-20);\n
\t\t\t\t}\n
\t\t\t\tmouse_target = selectedElements[0];\n
\t\t\t}\n
\t\t\t\n
\t\t\tstart_transform = mouse_target.getAttribute("transform");\n
\t\t\tvar tlist = canvas.getTransformList(mouse_target);\n
\t\t\tswitch (current_mode) {\n
\t\t\t\tcase "select":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tcurrent_resize_mode = "none";\n
\t\t\t\t\t\n
\t\t\t\t\tif (mouse_target != svgroot) {\n
\t\t\t\t\t\t// if this element is not yet selected, clear selection and select it\n
\t\t\t\t\t\tif (selectedElements.indexOf(mouse_target) == -1) {\n
\t\t\t\t\t\t\t// only clear selection if shift is not pressed (otherwise, add \n
\t\t\t\t\t\t\t// element to selection)\n
\t\t\t\t\t\t\tif (!evt.shiftKey) {\n
\t\t\t\t\t\t\t\t// No need to do the call here as it will be done on addToSelection\n
\t\t\t\t\t\t\t\tcanvas.clearSelection(true);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tcanvas.addToSelection([mouse_target]);\n
\t\t\t\t\t\t\tjustSelected = mouse_target;\n
\t\t\t\t\t\t\tpathActions.clear();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// else if it\'s a path, go into pathedit mode in mouseup\n
\t\n
\t\t\t\t\t\t// insert a dummy transform so if the element(s) are moved it will have\n
\t\t\t\t\t\t// a transform to use for its translate\n
\t\t\t\t\t\tfor (var i = 0; i < selectedElements.length; ++i) {\n
\t\t\t\t\t\t\tif(selectedElements[i] == null) continue;\n
\t\t\t\t\t\t\tvar slist = canvas.getTransformList(selectedElements[i]);\n
\t\t\t\t\t\t\tslist.insertItemBefore(svgroot.createSVGTransform(), 0);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse {\n
\t\t\t\t\t\tcanvas.clearSelection();\n
\t\t\t\t\t\tcurrent_mode = "multiselect";\n
\t\t\t\t\t\tif (rubberBox == null) {\n
\t\t\t\t\t\t\trubberBox = selectorManager.getRubberBandBox();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tstart_x *= current_zoom;\n
\t\t\t\t\t\tstart_y *= current_zoom;\n
\t\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\t\'x\': start_x,\n
\t\t\t\t\t\t\t\'y\': start_y,\n
\t\t\t\t\t\t\t\'width\': 0,\n
\t\t\t\t\t\t\t\'height\': 0,\n
\t\t\t\t\t\t\t\'display\': \'inline\'\n
\t\t\t\t\t\t}, 100);\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "zoom": \n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\tif (rubberBox == null) {\n
\t\t\t\t\t\trubberBox = selectorManager.getRubberBandBox();\n
\t\t\t\t\t}\n
\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\t\'x\': start_x * current_zoom,\n
\t\t\t\t\t\t\t\'y\': start_y * current_zoom,\n
\t\t\t\t\t\t\t\'width\': 0,\n
\t\t\t\t\t\t\t\'height\': 0,\n
\t\t\t\t\t\t\t\'display\': \'inline\'\n
\t\t\t\t\t}, 100);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "resize":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\t\n
\t\t\t\t\t// Getting the BBox from the selection box, since we know we\n
\t\t\t\t\t// want to orient around it\n
\t\t\t\t\tinit_bbox = canvas.getBBox($(\'#selectedBox0\')[0]);\n
\t\t\t\t\t$.each(init_bbox, function(key, val) {\n
\t\t\t\t\t\tinit_bbox[key] = val/current_zoom;\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\t// append three dummy transforms to the tlist so that\n
\t\t\t\t\t// we can translate,scale,translate in mousemove\n
\t\t\t\t\tvar pos = canvas.getRotationAngle(mouse_target)?1:0;\n
\t\t\t\t\t\n
\t\t\t\t\tif(hasMatrixTransform(tlist)) {\n
\t\t\t\t\t\ttlist.insertItemBefore(svgroot.createSVGTransform(), pos);\n
\t\t\t\t\t\ttlist.insertItemBefore(svgroot.createSVGTransform(), pos);\n
\t\t\t\t\t\ttlist.insertItemBefore(svgroot.createSVGTransform(), pos);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\ttlist.appendItem(svgroot.createSVGTransform());\n
\t\t\t\t\t\ttlist.appendItem(svgroot.createSVGTransform());\n
\t\t\t\t\t\ttlist.appendItem(svgroot.createSVGTransform());\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "fhellipse":\n
\t\t\t\tcase "fhrect":\n
\t\t\t\tcase "fhpath":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\td_attr = x + "," + y + " ";\n
\t\t\t\t\tvar stroke_w = cur_shape.stroke_width == 0?1:cur_shape.stroke_width;\n
\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t"element": "polyline",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"points": d_attr,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"fill": "none",\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2,\n
\t\t\t\t\t\t\t"stroke-linecap": "round",\n
\t\t\t\t\t\t\t"style": "pointer-events:none"\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tfreehand.minx = x;\n
\t\t\t\t\tfreehand.maxx = x;\n
\t\t\t\t\tfreehand.miny = y;\n
\t\t\t\t\tfreehand.maxy = y;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "image":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\tvar newImage = addSvgElementFromJson({\n
\t\t\t\t\t\t"element": "image",\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"x": x,\n
\t\t\t\t\t\t\t"y": y,\n
\t\t\t\t\t\t\t"width": 0,\n
\t\t\t\t\t\t\t"height": 0,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2,\n
\t\t\t\t\t\t\t"style": "pointer-events:inherit"\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tnewImage.setAttributeNS(xlinkns, "xlink:href", last_good_img_url);\n
\t\t\t\t\tpreventClickDefault(newImage);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "square":\n
\t\t\t\t\t// FIXME: once we create the rect, we lose information that this was a square\n
\t\t\t\t\t// (for resizing purposes this could be important)\n
\t\t\t\tcase "rect":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t"element": "rect",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"x": x,\n
\t\t\t\t\t\t\t"y": y,\n
\t\t\t\t\t\t\t"width": 0,\n
\t\t\t\t\t\t\t"height": 0,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "line":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tvar stroke_w = cur_shape.stroke_width == 0?1:cur_shape.stroke_width;\n
\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t"element": "line",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"x1": x,\n
\t\t\t\t\t\t\t"y1": y,\n
\t\t\t\t\t\t\t"x2": x,\n
\t\t\t\t\t\t\t"y2": y,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"stroke": cur_shape.stroke,\n
\t\t\t\t\t\t\t"stroke-width": stroke_w,\n
\t\t\t\t\t\t\t"stroke-dasharray": cur_shape.stroke_dasharray,\n
\t\t\t\t\t\t\t"stroke-linejoin": cur_shape.stroke_linejoin,\n
\t\t\t\t\t\t\t"stroke-linecap": cur_shape.stroke_linecap,\n
\t\t\t\t\t\t\t"stroke-opacity": cur_shape.stroke_opacity,\n
\t\t\t\t\t\t\t"fill": "none",\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2,\n
\t\t\t\t\t\t\t"style": "pointer-events:none"\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "circle":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t"element": "circle",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"cx": x,\n
\t\t\t\t\t\t\t"cy": y,\n
\t\t\t\t\t\t\t"r": 0,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "ellipse":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t"element": "ellipse",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"cx": x,\n
\t\t\t\t\t\t\t"cy": y,\n
\t\t\t\t\t\t\t"rx": 0,\n
\t\t\t\t\t\t\t"ry": 0,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "text":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tvar newText = addSvgElementFromJson({\n
\t\t\t\t\t\t"element": "text",\n
\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"x": x,\n
\t\t\t\t\t\t\t"y": y,\n
\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t"fill": cur_text.fill,\n
\t\t\t\t\t\t\t"stroke-width": cur_text.stroke_width,\n
\t\t\t\t\t\t\t"font-size": cur_text.font_size,\n
\t\t\t\t\t\t\t"font-family": cur_text.font_family,\n
\t\t\t\t\t\t\t"text-anchor": "middle",\n
\t\t\t\t\t\t\t"xml:space": "preserve"\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
// \t\t\t\t\tnewText.textContent = "text";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "path":\n
\t\t\t\t\t// Fall through\n
\t\t\t\tcase "pathedit":\n
\t\t\t\t\tstart_x *= current_zoom;\n
\t\t\t\t\tstart_y *= current_zoom;\n
\t\t\t\t\tpathActions.mouseDown(evt, mouse_target, start_x, start_y);\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "textedit":\n
\t\t\t\t\tstart_x *= current_zoom;\n
\t\t\t\t\tstart_y *= current_zoom;\n
\t\t\t\t\ttextActions.mouseDown(evt, mouse_target, start_x, start_y);\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "rotate":\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\t// we are starting an undoable change (a drag-rotation)\n
\t\t\t\t\tcanvas.beginUndoableChange("transform", selectedElements);\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\t// This could occur in an extension\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar ext_result = runExtensions("mouseDown", {\n
\t\t\t\tevent: evt,\n
\t\t\t\tstart_x: start_x,\n
\t\t\t\tstart_y: start_y,\n
\t\t\t\tselectedElements: selectedElements\n
\t\t\t}, true);\n
\t\t\t\n
\t\t\t$.each(ext_result, function(i, r) {\n
\t\t\t\tif(r && r.started) {\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t};\n
\n
\t\t\n
\t\t// in this function we do not record any state changes yet (but we do update\n
\t\t// any elements that are still being created, moved or resized on the canvas)\n
\t\t// TODO: svgcanvas should just retain a reference to the image being dragged instead\n
\t\t// of the getId() and getElementById() funkiness - this will help us customize the ids \n
\t\t// a little bit for squares and paths\n
\t\tvar mouseMove = function(evt)\n
\t\t{\n
\t\t\tif (!started) return;\n
\t\t\tif(evt.button === 1 || canvas.spaceKey) return;\n
\t\t\tvar selected = selectedElements[0],\n
\t\t\t\tpt = transformPoint( evt.pageX, evt.pageY, root_sctm ),\n
\t\t\t\tmouse_x = pt.x * current_zoom,\n
\t\t\t\tmouse_y = pt.y * current_zoom,\n
\t\t\t\tshape = getElem(getId());\n
\t\t\n
\t\t\tx = mouse_x / current_zoom;\n
\t\t\ty = mouse_y / current_zoom;\n
\t\t\n
\t\t\tevt.preventDefault();\n
\t\t\t\n
\t\t\tswitch (current_mode)\n
\t\t\t{\n
\t\t\t\tcase "select":\n
\t\t\t\t\t// we temporarily use a translate on the element(s) being dragged\n
\t\t\t\t\t// this transform is removed upon mousing up and the element is \n
\t\t\t\t\t// relocated to the new location\n
\t\t\t\t\tif (selectedElements[0] != null) {\n
\t\t\t\t\t\tvar dx = x - start_x;\n
\t\t\t\t\t\tvar dy = y - start_y;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif(evt.shiftKey) { var xya = Utils.snapToAngle(start_x,start_y,x,y); x=xya.x; y=xya.y; }\n
\n
\t\t\t\t\t\tif (dx != 0 || dy != 0) {\n
\t\t\t\t\t\t\tvar len = selectedElements.length;\n
\t\t\t\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\t\t\t\tvar selected = selectedElements[i];\n
\t\t\t\t\t\t\t\tif (selected == null) break;\n
\t\t\t\t\t\t\t\tif (i==0) {\n
\t\t\t\t\t\t\t\t\tvar box = canvas.getBBox(selected);\n
// \t\t\t\t\t\t\t\t\tselectedBBoxes[i].x = box.x + dx;\n
// \t\t\t\t\t\t\t\t\tselectedBBoxes[i].y = box.y + dy;\n
\t\t\t\t\t\t\t\t}\n
\t\n
\t\t\t\t\t\t\t\t// update the dummy transform in our transform list\n
\t\t\t\t\t\t\t\t// to be a translate\n
\t\t\t\t\t\t\t\tvar xform = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\t\tvar tlist = canvas.getTransformList(selected);\n
\t\t\t\t\t\t\t\txform.setTranslate(dx,dy);\n
\t\t\t\t\t\t\t\tif(tlist.numberOfItems) {\n
\t\t\t\t\t\t\t\t\ttlist.replaceItem(xform, 0);\n
\t\t\t\t\t\t\t\t\t// TODO: Webkit returns null here, find out why\n
\t// \t\t\t\t\t\t\t\tconsole.log(selected.getAttribute("transform"))\n
\t\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\ttlist.appendItem(xform);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t// update our internal bbox that we\'re tracking while dragging\n
\t\t\t\t\t\t\t\tselectorManager.requestSelector(selected).resize();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "multiselect":\n
\t\t\t\t\tx *= current_zoom;\n
\t\t\t\t\ty *= current_zoom;\n
\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\'x\': Math.min(start_x,x),\n
\t\t\t\t\t\t\'y\': Math.min(start_y,y),\n
\t\t\t\t\t\t\'width\': Math.abs(x-start_x),\n
\t\t\t\t\t\t\'height\': Math.abs(y-start_y)\n
\t\t\t\t\t},100);\n
\t\n
\t\t\t\t\t// for each selected:\n
\t\t\t\t\t// - if newList contains selected, do nothing\n
\t\t\t\t\t// - if newList doesn\'t contain selected, remove it from selected\n
\t\t\t\t\t// - for any newList that was not in selectedElements, add it to selected\n
\t\t\t\t\tvar elemsToRemove = [], elemsToAdd = [],\n
\t\t\t\t\t\tnewList = getIntersectionList(),\n
\t\t\t\t\t\tlen = selectedElements.length;\n
\t\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\t\tvar ind = newList.indexOf(selectedElements[i]);\n
\t\t\t\t\t\tif (ind == -1) {\n
\t\t\t\t\t\t\telemsToRemove.push(selectedElements[i]);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\tnewList[ind] = null;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tlen = newList.length;\n
\t\t\t\t\tfor (i = 0; i < len; ++i) { if (newList[i]) elemsToAdd.push(newList[i]); }\n
\t\t\t\t\t\n
\t\t\t\t\tif (elemsToRemove.length > 0) \n
\t\t\t\t\t\tcanvas.removeFromSelection(elemsToRemove);\n
\t\t\t\t\t\n
\t\t\t\t\tif (elemsToAdd.length > 0) \n
\t\t\t\t\t\tcanvas.addToSelection(elemsToAdd);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "resize":\n
\t\t\t\t\t// we track the resize bounding box and translate/scale the selected element\n
\t\t\t\t\t// while the mouse is down, when mouse goes up, we use this to recalculate\n
\t\t\t\t\t// the shape\'s coordinates\n
\t\t\t\t\tvar tlist = canvas.getTransformList(selected),\n
\t\t\t\t\t\thasMatrix = hasMatrixTransform(tlist),\n
\t\t\t\t\t\tbox=hasMatrix?init_bbox:canvas.getBBox(selected), \n
\t\t\t\t\t\tleft=box.x, top=box.y, width=box.width,\n
\t\t\t\t\t\theight=box.height, dx=(x-start_x), dy=(y-start_y);\n
\t\t\t\t\t\t\t\t\t\n
\t\t\t\t\t// if rotated, adjust the dx,dy values\n
\t\t\t\t\tvar angle = canvas.getRotationAngle(selected);\n
\t\t\t\t\tif (angle) {\n
\t\t\t\t\t\tvar r = Math.sqrt( dx*dx + dy*dy ),\n
\t\t\t\t\t\t\ttheta = Math.atan2(dy,dx) - angle * Math.PI / 180.0;\n
\t\t\t\t\t\tdx = r * Math.cos(theta);\n
\t\t\t\t\t\tdy = r * Math.sin(theta);\n
\t\t\t\t\t}\n
\t\n
\t\t\t\t\t// if not stretching in y direction, set dy to 0\n
\t\t\t\t\t// if not stretching in x direction, set dx to 0\n
\t\t\t\t\tif(current_resize_mode.indexOf("n")==-1 && current_resize_mode.indexOf("s")==-1) {\n
\t\t\t\t\t\tdy = 0;\n
\t\t\t\t\t}\n
\t\t\t\t\tif(current_resize_mode.indexOf("e")==-1 && current_resize_mode.indexOf("w")==-1) {\n
\t\t\t\t\t\tdx = 0;\n
\t\t\t\t\t}\t\t\t\t\n
\t\t\t\t\t\n
\t\t\t\t\tvar ts = null,\n
\t\t\t\t\t\ttx = 0, ty = 0,\n
\t\t\t\t\t\tsy = height ? (height+dy)/height : 1, \n
\t\t\t\t\t\tsx = width ? (width+dx)/width : 1;\n
\t\t\t\t\t// if we are dragging on the north side, then adjust the scale factor and ty\n
\t\t\t\t\tif(current_resize_mode.indexOf("n") != -1) {\n
\t\t\t\t\t\tsy = height ? (height-dy)/height : 1;\n
\t\t\t\t\t\tty = height;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// if we dragging on the east side, then adjust the scale factor and tx\n
\t\t\t\t\tif(current_resize_mode.indexOf("w") != -1) {\n
\t\t\t\t\t\tsx = width ? (width-dx)/width : 1;\n
\t\t\t\t\t\ttx = width;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// update the transform list with translate,scale,translate\n
\t\t\t\t\tvar translateOrigin = svgroot.createSVGTransform(),\n
\t\t\t\t\t\tscale = svgroot.createSVGTransform(),\n
\t\t\t\t\t\ttranslateBack = svgroot.createSVGTransform();\n
\t\t\t\t\ttranslateOrigin.setTranslate(-(left+tx),-(top+ty));\n
\t\t\t\t\tif(evt.shiftKey) {\n
\t\t\t\t\t\tif(sx == 1) sx = sy\n
\t\t\t\t\t\telse sy = sx;\n
\t\t\t\t\t}\n
\t\t\t\t\tscale.setScale(sx,sy);\n
\t\t\t\t\t\n
\t\t\t\t\ttranslateBack.setTranslate(left+tx,top+ty);\n
\t\t\t\t\tif(hasMatrix) {\n
\t\t\t\t\t\tvar diff = angle?1:0;\n
\t\t\t\t\t\ttlist.replaceItem(translateOrigin, 2+diff);\n
\t\t\t\t\t\ttlist.replaceItem(scale, 1+diff);\n
\t\t\t\t\t\ttlist.replaceItem(translateBack, 0+diff);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tvar N = tlist.numberOfItems;\n
\t\t\t\t\t\ttlist.replaceItem(translateBack, N-3);\n
\t\t\t\t\t\ttlist.replaceItem(scale, N-2);\n
\t\t\t\t\t\ttlist.replaceItem(translateOrigin, N-1);\n
\t\t\t\t\t}\n
\t\t\t\t\tvar selectedBBox = selectedBBoxes[0];\t\t\t\t\n
\t\n
\t\t\t\t\t// reset selected bbox top-left position\n
\t\t\t\t\tselectedBBox.x = left;\n
\t\t\t\t\tselectedBBox.y = top;\n
\t\t\t\t\t\n
\t\t\t\t\t// if this is a translate, adjust the box position\n
\t\t\t\t\tif (tx) {\n
\t\t\t\t\t\tselectedBBox.x += dx;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (ty) {\n
\t\t\t\t\t\tselectedBBox.y += dy;\n
\t\t\t\t\t}\n
\t\n
\t\t\t\t\tselectorManager.requestSelector(selected).resize();\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "zoom":\n
\t\t\t\t\tx *= current_zoom;\n
\t\t\t\t\ty *= current_zoom;\n
\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\'x\': Math.min(start_x*current_zoom,x),\n
\t\t\t\t\t\t\'y\': Math.min(start_y*current_zoom,y),\n
\t\t\t\t\t\t\'width\': Math.abs(x-start_x*current_zoom),\n
\t\t\t\t\t\t\'height\': Math.abs(y-start_y*current_zoom)\n
\t\t\t\t\t},100);\t\t\t\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "text":\n
\t\t\t\t\tassignAttributes(shape,{\n
\t\t\t\t\t\t\'x\': x,\n
\t\t\t\t\t\t\'y\': y\n
\t\t\t\t\t},1000);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "line":\n
\t\t\t\t\t// Opera has a problem with suspendRedraw() apparently\n
\t\t\t\t\tvar handle = null;\n
\t\t\t\t\tif (!window.opera) svgroot.suspendRedraw(1000);\n
\n
\t\t\t\t\tvar x2 = x;\n
\t\t\t\t\tvar y2 = y;\t\t\t\t\t\n
\n
\t\t\t\t\tif(evt.shiftKey) { var xya=Utils.snapToAngle(start_x,start_y,x2,y2); x2=xya.x; y2=xya.y; }\n
\t\t\t\t\t\n
\t\t\t\t\tshape.setAttributeNS(null, "x2", x2);\n
\t\t\t\t\tshape.setAttributeNS(null, "y2", y2);\n
\t\t\t\t\tif (!window.opera) svgroot.unsuspendRedraw(handle);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "foreignObject":\n
\t\t\t\t\t// fall through\n
\t\t\t\tcase "square":\n
\t\t\t\t\t// fall through\n
\t\t\t\tcase "rect":\n
\t\t\t\t\t// fall through\n
\t\t\t\tcase "image":\n
\t\t\t\t\tvar square = (current_mode == \'square\') || evt.shiftKey,\n
\t\t\t\t\t\tw = Math.abs(x - start_x),\n
\t\t\t\t\t\th = Math.abs(y - start_y),\n
\t\t\t\t\t\tnew_x, new_y;\n
\t\t\t\t\tif(square) {\n
\t\t\t\t\t\tw = h = Math.max(w, h);\n
\t\t\t\t\t\tnew_x = start_x < x ? start_x : start_x - w;\n
\t\t\t\t\t\tnew_y = start_y < y ? start_y : start_y - h;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tnew_x = Math.min(start_x,x);\n
\t\t\t\t\t\tnew_y = Math.min(start_y,y);\n
\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\tassignAttributes(shape,{\n
\t\t\t\t\t\t\'width\': w,\n
\t\t\t\t\t\t\'height\': h,\n
\t\t\t\t\t\t\'x\': new_x,\n
\t\t\t\t\t\t\'y\': new_y\n
\t\t\t\t\t},1000);\n
\t\t\t\t\t\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "circle":\n
\t\t\t\t\tvar c = $(shape).attr(["cx", "cy"]);\n
\t\t\t\t\tvar cx = c.cx, cy = c.cy,\n
\t\t\t\t\t\trad = Math.sqrt( (x-cx)*(x-cx) + (y-cy)*(y-cy) );\n
\t\t\t\t\tshape.setAttributeNS(null, "r", rad);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "ellipse":\n
\t\t\t\t\tvar c = $(shape).attr(["cx", "cy"]);\n
\t\t\t\t\tvar cx = c.cx, cy = c.cy;\n
\t\t\t\t\t// Opera has a problem with suspendRedraw() apparently\n
\t\t\t\t\t\thandle = null;\n
\t\t\t\t\tif (!window.opera) svgroot.suspendRedraw(1000);\n
\t\t\t\t\tshape.setAttributeNS(null, "rx", Math.abs(x - cx) );\n
\t\t\t\t\tvar ry = Math.abs(evt.shiftKey?(x - cx):(y - cy));\n
\t\t\t\t\tshape.setAttributeNS(null, "ry", ry );\n
\t\t\t\t\tif (!window.opera) svgroot.unsuspendRedraw(handle);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "fhellipse":\n
\t\t\t\tcase "fhrect":\n
\t\t\t\t\tfreehand.minx = Math.min(x, freehand.minx);\n
\t\t\t\t\tfreehand.maxx = Math.max(x, freehand.maxx);\n
\t\t\t\t\tfreehand.miny = Math.min(y, freehand.miny);\n
\t\t\t\t\tfreehand.maxy = Math.max(y, freehand.maxy);\n
\t\t\t\t// break; missing on purpose\n
\t\t\t\tcase "fhpath":\n
\t\t\t\t\tstart_x = x;\n
\t\t\t\t\tstart_y = y;\n
\t\t\t\t\td_attr += + x + "," + y + " ";\n
\t\t\t\t\tshape.setAttributeNS(null, "points", d_attr);\n
\t\t\t\t\tbreak;\n
\t\t\t\t// update path stretch line coordinates\n
\t\t\t\tcase "path":\n
\t\t\t\t\t// fall through\n
\t\t\t\tcase "pathedit":\n
\t\t\t\t\tx *= current_zoom;\n
\t\t\t\t\ty *= current_zoom;\n
\t\t\t\t\t\n
\t\t\t\t\tif(evt.shiftKey) {\n
\t\t\t\t\t\tvar x1 = path.dragging?path.dragging[0]:start_x;\n
\t\t\t\t\t\tvar y1 = path.dragging?path.dragging[1]:start_y;\n
\t\t\t\t\t    var xya=Utils.snapToAngle(x1,y1,x,y);\n
\t\t\t\t\t    x=xya.x; y=xya.y;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(rubberBox && rubberBox.getAttribute(\'display\') != \'none\') {\n
\t\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\t\'x\': Math.min(start_x,x),\n
\t\t\t\t\t\t\t\'y\': Math.min(start_y,y),\n
\t\t\t\t\t\t\t\'width\': Math.abs(x-start_x),\n
\t\t\t\t\t\t\t\'height\': Math.abs(y-start_y)\n
\t\t\t\t\t\t},100);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tpathActions.mouseMove(x, y);\n
\t\t\t\t\t\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "textedit":\n
\t\t\t\t\tx *= current_zoom;\n
\t\t\t\t\ty *= current_zoom;\n
// \t\t\t\t\tif(rubberBox && rubberBox.getAttribute(\'display\') != \'none\') {\n
// \t\t\t\t\t\tassignAttributes(rubberBox, {\n
// \t\t\t\t\t\t\t\'x\': Math.min(start_x,x),\n
// \t\t\t\t\t\t\t\'y\': Math.min(start_y,y),\n
// \t\t\t\t\t\t\t\'width\': Math.abs(x-start_x),\n
// \t\t\t\t\t\t\t\'height\': Math.abs(y-start_y)\n
// \t\t\t\t\t\t},100);\n
// \t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\ttextActions.mouseMove(mouse_x, mouse_y);\n
\t\t\t\t\t\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "rotate":\n
\t\t\t\t\tvar box = canvas.getBBox(selected),\n
\t\t\t\t\t\tcx = box.x + box.width/2, \n
\t\t\t\t\t\tcy = box.y + box.height/2,\n
\t\t\t\t\t\tm = getMatrix(selected),\n
\t\t\t\t\t\tcenter = transformPoint(cx,cy,m);\n
\t\t\t\t\tcx = center.x;\n
\t\t\t\t\tcy = center.y;\n
\t\t\t\t\tvar angle = ((Math.atan2(cy-y,cx-x)  * (180/Math.PI))-90) % 360;\n
                    \n
\t\t\t\t\tif(evt.shiftKey) { // restrict rotations to nice angles (WRS)\n
                        var snap = 45;\n
                        angle= Math.round(angle/snap)*snap;\n
                    }\n
\n
\t\t\t\t\tcanvas.setRotationAngle(angle<-180?(360+angle):angle, true);\n
\t\t\t\t\tcall("changed", selectedElements);\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\t\n
\t\t\trunExtensions("mouseMove", {\n
\t\t\t\tevent: evt,\n
\t\t\t\tmouse_x: mouse_x,\n
\t\t\t\tmouse_y: mouse_y,\n
\t\t\t\tselected: selected\n
\t\t\t});\n
\n
\t\t}; // mouseMove()\n
\t\t\n
\t\tvar mouseUp = function(evt)\n
\t\t{\n
\t\t\tif(evt.button === 1) return;\n
\t\t\tvar tempJustSelected = justSelected;\n
\t\t\tjustSelected = null;\n
\t\t\tif (!started) return;\n
\t\t\tvar pt = transformPoint( evt.pageX, evt.pageY, root_sctm ),\n
\t\t\t\tmouse_x = pt.x * current_zoom,\n
\t\t\t\tmouse_y = pt.y * current_zoom,\n
\t\t\t\tx = mouse_x / current_zoom,\n
\t\t\t\ty = mouse_y / current_zoom,\n
\t\t\t\telement = getElem(getId()),\n
\t\t\t\tkeep = false;\n
\t\t\t\t\t\n
\t\t\tstarted = false;\n
\t\t\tswitch (current_mode)\n
\t\t\t{\n
\t\t\t\t// intentionally fall-through to select here\n
\t\t\t\tcase "resize":\n
\t\t\t\tcase "multiselect":\n
\t\t\t\t\tif (rubberBox != null) {\n
\t\t\t\t\t\trubberBox.setAttribute("display", "none");\n
\t\t\t\t\t\tcurBBoxes = [];\n
\t\t\t\t\t}\n
\t\t\t\t\tcurrent_mode = "select";\n
\t\t\t\tcase "select":\n
\t\t\t\t\tif (selectedElements[0] != null) {\n
\t\t\t\t\t\t// if we only have one selected element\n
\t\t\t\t\t\tif (selectedElements[1] == null) {\n
\t\t\t\t\t\t\t// set our current stroke/fill properties to the element\'s\n
\t\t\t\t\t\t\tvar selected = selectedElements[0];\n
\t\t\t\t\t\t\tif (selected.tagName != "g" && selected.tagName != "image" && selected.tagName != "foreignObject") {\n
\t\t\t\t\t\t\t\tcur_properties.fill = selected.getAttribute("fill");\n
\t\t\t\t\t\t\t\tcur_properties.fill_opacity = selected.getAttribute("fill-opacity");\n
\t\t\t\t\t\t\t\tcur_properties.stroke = selected.getAttribute("stroke");\n
\t\t\t\t\t\t\t\tcur_properties.stroke_opacity = selected.getAttribute("stroke-opacity");\n
\t\t\t\t\t\t\t\tcur_properties.stroke_width = selected.getAttribute("stroke-width");\n
\t\t\t\t\t\t\t\tcur_properties.stroke_dasharray = selected.getAttribute("stroke-dasharray");\n
\t\t\t\t\t\t\t\tcur_properties.stroke_linejoin = selected.getAttribute("stroke-linejoin");\n
\t\t\t\t\t\t\t\tcur_properties.stroke_linecap = selected.getAttribute("stroke-linecap");\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tif (selected.tagName == "text") {\n
\t\t\t\t\t\t\t\tcur_text.font_size = selected.getAttribute("font-size");\n
\t\t\t\t\t\t\t\tcur_text.font_family = selected.getAttribute("font-family");\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tselectorManager.requestSelector(selected).showGrips(true);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// This shouldn\'t be necessary as it was done on mouseDown...\n
// \t\t\t\t\t\t\tcall("selected", [selected]);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// always recalculate dimensions to strip off stray identity transforms\n
\t\t\t\t\t\trecalculateAllSelectedDimensions();\n
\t\t\t\t\t\t// if it was being dragged/resized\n
\t\t\t\t\t\tif (x != start_x || y != start_y) {\n
\t\t\t\t\t\t\tvar len = selectedElements.length;\n
\t\t\t\t\t\t\tfor\t(var i = 0; i < len; ++i) {\n
\t\t\t\t\t\t\t\tif (selectedElements[i] == null) break;\n
\t\t\t\t\t\t\t\tif(selectedElements[i].tagName != \'g\') {\n
\t\t\t\t\t\t\t\t\t// Not needed for groups (incorrectly resizes elems), possibly not needed at all?\n
\t\t\t\t\t\t\t\t\tselectorManager.requestSelector(selectedElements[i]).resize();\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// no change in position/size, so maybe we should move to pathedit\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\tvar t = evt.target;\n
\t\t\t\t\t\t\tif (selectedElements[0].nodeName == "path" && selectedElements[1] == null) {\n
\t\t\t\t\t\t\t\tpathActions.select(t);\n
\t\t\t\t\t\t\t} // if it was a path\n
\t\t\t\t\t\t\telse if (selectedElements[0].nodeName == "text" && selectedElements[1] == null) {\n
\t\t\t\t\t\t\t\ttextActions.select(t, x, y);\n
\t\t\t\t\t\t\t} // if it was a path\n
\t\t\t\t\t\t\t// else, if it was selected and this is a shift-click, remove it from selection\n
\t\t\t\t\t\t\telse if (evt.shiftKey) {\n
\t\t\t\t\t\t\t\tif(tempJustSelected != t) {\n
\t\t\t\t\t\t\t\t\tcanvas.removeFromSelection([t]);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} // no change in mouse position\n
\t\t\t\t\t}\n
\t\t\t\t\t// we return immediately from select so that the obj_num is not incremented\n
\t\t\t\t\treturn;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "zoom":\n
\t\t\t\t\tif (rubberBox != null) {\n
\t\t\t\t\t\trubberBox.setAttribute("display", "none");\n
\t\t\t\t\t}\n
\t\t\t\t\tvar factor = evt.shiftKey?.5:2;\n
\t\t\t\t\tcall("zoomed", {\n
\t\t\t\t\t\t\'x\': Math.min(start_x,x),\n
\t\t\t\t\t\t\'y\': Math.min(start_y,y),\n
\t\t\t\t\t\t\'width\': Math.abs(x-start_x),\n
\t\t\t\t\t\t\'height\': Math.abs(y-start_y),\n
\t\t\t\t\t\t\'factor\': factor\n
\t\t\t\t\t});\n
\t\t\t\t\treturn;\n
\t\t\t\tcase "fhpath":\n
\t\t\t\t\t// Check that the path contains at least 2 points; a degenerate one-point path\n
\t\t\t\t\t// causes problems.\n
\t\t\t\t\t// Webkit ignores how we set the points attribute with commas and uses space\n
\t\t\t\t\t// to separate all coordinates, see https://bugs.webkit.org/show_bug.cgi?id=29870\n
\t\t\t\t\tvar coords = element.getAttribute(\'points\');\n
\t\t\t\t\tvar commaIndex = coords.indexOf(\',\');\n
\t\t\t\t\tif (commaIndex >= 0) {\n
\t\t\t\t\t\tkeep = coords.indexOf(\',\', commaIndex+1) >= 0;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tkeep = coords.indexOf(\' \', coords.indexOf(\' \')+1) >= 0;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (keep) {\n
\t\t\t\t\t\telement = pathActions.smoothPolylineIntoPath(element);\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "line":\n
\t\t\t\t\tvar attrs = $(element).attr(["x1", "x2", "y1", "y2"]);\n
\t\t\t\t\tkeep = (attrs.x1 != attrs.x2 || attrs.y1 != attrs.y2);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "foreignObject":\n
\t\t\t\tcase "square":\n
\t\t\t\tcase "rect":\n
\t\t\t\tcase "image":\n
\t\t\t\t\tvar attrs = $(element).attr(["width", "height"]);\n
\t\t\t\t\t// Image should be kept regardless of size (use inherit dimensions later)\n
\t\t\t\t\tkeep = (attrs.width != 0 || attrs.height != 0) || current_mode === "image";\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "circle":\n
\t\t\t\t\tkeep = (element.getAttribute(\'r\') != 0);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "ellipse":\n
\t\t\t\t\tvar attrs = $(element).attr(["rx", "ry"]);\n
\t\t\t\t\tkeep = (attrs.rx != null || attrs.ry != null);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "fhellipse":\n
\t\t\t\t\tif ((freehand.maxx - freehand.minx) > 0 &&\n
\t\t\t\t\t\t(freehand.maxy - freehand.miny) > 0) {\n
\t\t\t\t\t\telement = addSvgElementFromJson({\n
\t\t\t\t\t\t\t"element": "ellipse",\n
\t\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"cx": (freehand.minx + freehand.maxx) / 2,\n
\t\t\t\t\t\t\t\t"cy": (freehand.miny + freehand.maxy) / 2,\n
\t\t\t\t\t\t\t\t"rx": (freehand.maxx - freehand.minx) / 2,\n
\t\t\t\t\t\t\t\t"ry": (freehand.maxy - freehand.miny) / 2,\n
\t\t\t\t\t\t\t\t"id": getId()\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tcall("changed",[element]);\n
\t\t\t\t\t\tkeep = true;\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "fhrect":\n
\t\t\t\t\tif ((freehand.maxx - freehand.minx) > 0 &&\n
\t\t\t\t\t\t(freehand.maxy - freehand.miny) > 0) {\n
\t\t\t\t\t\telement = addSvgElementFromJson({\n
\t\t\t\t\t\t\t"element": "rect",\n
\t\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"x": freehand.minx,\n
\t\t\t\t\t\t\t\t"y": freehand.miny,\n
\t\t\t\t\t\t\t\t"width": (freehand.maxx - freehand.minx),\n
\t\t\t\t\t\t\t\t"height": (freehand.maxy - freehand.miny),\n
\t\t\t\t\t\t\t\t"id": getId()\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tcall("changed",[element]);\n
\t\t\t\t\t\tkeep = true;\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "text":\n
\t\t\t\t\tkeep = true;\n
\t\t\t\t\tcanvas.addToSelection([element]);\n
\t\t\t\t\ttextActions.start(element);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "path":\n
\t\t\t\t\t// set element to null here so that it is not removed nor finalized\n
\t\t\t\t\telement = null;\n
\t\t\t\t\t// continue to be set to true so that mouseMove happens\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\t\n
\t\t\t\t\tvar res = pathActions.mouseUp(evt, element, mouse_x, mouse_y);\n
\t\t\t\t\telement = res.element\n
\t\t\t\t\tkeep = res.keep;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "pathedit":\n
\t\t\t\t\tkeep = true;\n
\t\t\t\t\telement = null;\n
\t\t\t\t\tpathActions.mouseUp(evt);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "textedit":\n
\t\t\t\t\tkeep = false;\n
\t\t\t\t\telement = null;\n
\t\t\t\t\ttextActions.mouseUp(evt, mouse_x, mouse_y);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "rotate":\n
\t\t\t\t\tkeep = true;\n
\t\t\t\t\telement = null;\n
\t\t\t\t\tcurrent_mode = "select";\n
\t\t\t\t\tvar batchCmd = canvas.finishUndoableChange();\n
\t\t\t\t\tif (!batchCmd.isEmpty()) { \n
\t\t\t\t\t\taddCommandToHistory(batchCmd);\n
\t\t\t\t\t}\n
\t\t\t\t\t// perform recalculation to weed out any stray identity transforms that might get stuck\n
\t\t\t\t\trecalculateAllSelectedDimensions();\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\t// This could occur in an extension\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar ext_result = runExtensions("mouseUp", {\n
\t\t\t\tevent: evt,\n
\t\t\t\tmouse_x: mouse_x,\n
\t\t\t\tmouse_y: mouse_y\n
\t\t\t}, true);\n
\t\t\t\n
\t\t\t$.each(ext_result, function(i, r) {\n
\t\t\t\tif(r) {\n
\t\t\t\t\tkeep = r.keep || keep;\n
\t\t\t\t\telement = r.element;\n
\t\t\t\t\tstarted = r.started || started;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\tif (!keep && element != null) {\n
\t\t\t\telement.parentNode.removeChild(element);\n
\t\t\t\telement = null;\n
\t\t\t\t\n
\t\t\t\tvar t = evt.target;\n
\t\t\t\t\n
\t\t\t\t// if this element is in a group, go up until we reach the top-level group \n
\t\t\t\t// just below the layer groups\n
\t\t\t\t// TODO: once we implement links, we also would have to check for <a> elements\n
\t\t\t\twhile (t.parentNode.parentNode.tagName == "g") {\n
\t\t\t\t\tt = t.parentNode;\n
\t\t\t\t}\n
\t\t\t\t// if we are not in the middle of creating a path, and we\'ve clicked on some shape, \n
\t\t\t\t// then go to Select mode.\n
\t\t\t\t// WebKit returns <div> when the canvas is clicked, Firefox/Opera return <svg>\n
\t\t\t\tif ( (current_mode != "path" || current_path_pts.length == 0) &&\n
\t\t\t\t\tt.parentNode.id != "selectorParentGroup" &&\n
\t\t\t\t\tt.id != "svgcanvas" && t.id != "svgroot") \n
\t\t\t\t{\n
\t\t\t\t\t// switch into "select" mode if we\'ve clicked on an element\n
\t\t\t\t\tcanvas.addToSelection([t], true);\n
\t\t\t\t\tcanvas.setMode("select");\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t} else if (element != null) {\n
\t\t\t\tcanvas.addedNew = true;\n
\t\t\t\tvar ani_dur = .2, c_ani;\n
\t\t\t\tif(opac_ani.beginElement && element.getAttribute(\'opacity\') != cur_shape.opacity) {\n
\t\t\t\t\tc_ani = $(opac_ani).clone().attr({\n
\t\t\t\t\t\tto: cur_shape.opacity,\n
\t\t\t\t\t\tdur: ani_dur\n
\t\t\t\t\t}).appendTo(element);\n
\t\t\t\t\tc_ani[0].beginElement();\n
\t\t\t\t} else {\n
\t\t\t\t\tani_dur = 0;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Ideally this would be done on the endEvent of the animation,\n
\t\t\t\t// but that doesn\'t seem to be supported in Webkit\n
\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\tif(c_ani) c_ani.remove();\n
\t\t\t\t\telement.setAttribute("opacity", cur_shape.opacity);\n
\t\t\t\t\telement.setAttribute("style", "pointer-events:inherit");\n
\t\t\t\t\tcleanupElement(element);\n
\t\t\t\t\tif(current_mode == "path") {\n
\t\t\t\t\t\tpathActions.toEditMode(element);\n
\t\t\t\t\t} else if (current_mode == "text" || current_mode == "image" || current_mode == "foreignObject") {\n
\t\t\t\t\t\t// keep us in the tool we were in unless it was a text or image element\n
\t\t\t\t\t\tcanvas.addToSelection([element], true);\n
\t\t\t\t\t}\n
\t\t\t\t\t// we create the insert command that is stored on the stack\n
\t\t\t\t\t// undo means to call cmd.unapply(), redo means to call cmd.apply()\n
\t\t\t\t\taddCommandToHistory(new InsertElementCommand(element));\n
\t\t\t\t\tcall("changed",[element]);\n
\t\t\t\t}, ani_dur * 1000);\n
\t\t\t}\n
\t\t\t\n
\t\t\tstart_transform = null;\n
\t\t};\n
\n
\t\t// prevent links from being followed in the canvas\n
\t\tvar handleLinkInCanvas = function(e) {\n
\t\t\te.preventDefault();\n
\t\t\treturn false;\n
\t\t};\n
\t\t\n
\t\t$(container).mousedown(mouseDown).mousemove(mouseMove).click(handleLinkInCanvas);\n
\t\t$(window).mouseup(mouseUp);\n
\t\t\n
\t\t$(container).bind("mousewheel DOMMouseScroll", function(e){\n
\t\t\tif(!e.shiftKey) return;\n
\t\t\te.preventDefault();\n
\n
\t\t\troot_sctm = svgcontent.getScreenCTM().inverse();\n
\t\t\tvar pt = transformPoint( e.pageX, e.pageY, root_sctm );\n
\t\t\tvar bbox = {\n
\t\t\t\t\'x\': pt.x,\n
\t\t\t\t\'y\': pt.y,\n
\t\t\t\t\'width\': 0,\n
\t\t\t\t\'height\': 0\n
\t\t\t};\n
\n
\t\t\t// Respond to mouse wheel in IE/Webkit/Opera.\n
\t\t\t// (It returns up/dn motion in multiples of 120)\n
\t\t\tif(e.wheelDelta) {\n
\t\t\t\tif (e.wheelDelta >= 120) {\n
\t\t\t\t\tbbox.factor = 2;\n
\t\t\t\t} else if (e.wheelDelta <= -120) {\n
\t\t\t\t\tbbox.factor = .5;\n
\t\t\t\t}\n
\t\t\t} else if(e.detail) {\n
\t\t\t\tif (e.detail > 0) {\n
\t\t\t\t\tbbox.factor = .5;\n
\t\t\t\t} else if (e.detail < 0) {\n
\t\t\t\t\tbbox.factor = 2;\t\t\t\n
\t\t\t\t}\t\t\t\t\n
\t\t\t}\n
\t\t\t\n
\t\t\tif(!bbox.factor) return;\n
\t\t\tcall("zoomed", bbox);\n
\t\t});\n
\t\t\n
\t}());\n
\n
\tvar textActions = canvas.textActions = function() {\n
\t\tvar curtext, current_text;\n
\t\tvar textinput;\n
\t\tvar cursor;\n
\t\tvar selblock;\n
\t\tvar blinker;\n
\t\tvar chardata = [];\n
\t\tvar textbb, transbb;\n
\t\tvar matrix;\n
\t\tvar last_x, last_y;\n
\t\tvar allow_dbl;\n
\t\t\n
\t\tfunction setCursor(index) {\n
\t\t\tvar empty = (textinput.value === "");\n
\t\t\n
\t\t\tif(!arguments.length) {\n
\t\t\t\tif(empty) {\n
\t\t\t\t\tindex = 0;\n
\t\t\t\t} else {\n
\t\t\t\t\tif(textinput.selectionEnd !== textinput.selectionStart) return;\n
\t\t\t\t\tindex = textinput.selectionEnd;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar charbb;\n
\t\t\tcharbb = chardata[index];\n
\t\t\tif(!empty) {\n
\t\t\t\ttextinput.setSelectionRange(index, index);\n
\t\t\t}\n
\t\t\tcursor = getElem("text_cursor");\n
\t\t\tif (!cursor) {\n
\t\t\t\tcursor = document.createElementNS(svgns, "line");\n
\t\t\t\tassignAttributes(cursor, {\n
\t\t\t\t\t\'id\': "text_cursor",\n
\t\t\t\t\t\'stroke\': "#333",\n
\t\t\t\t\t\'stroke-width\': 1\n
\t\t\t\t});\n
\t\t\t\tcursor = getElem("selectorParentGroup").appendChild(cursor);\n
\t\t\t}\n
\t\t\t\n
\t\t\tif(!blinker) {\n
\t\t\t\tblinker = setInterval(function() {\n
\t\t\t\t\tvar show = (cursor.getAttribute(\'display\') === \'none\');\n
\t\t\t\t\tcursor.setAttribute(\'display\', show?\'inline\':\'none\');\n
\t\t\t\t}, 600);\n
\n
\t\t\t}\n
\t\t\t\n
\t\t\t\n
\t\t\tvar start_pt = ptToScreen(charbb.x, textbb.y);\n
\t\t\tvar end_pt = ptToScreen(charbb.x, (textbb.y + textbb.height));\n
\t\t\t\n
\t\t\tassignAttributes(cursor, {\n
\t\t\t\tx1: start_pt.x,\n
\t\t\t\ty1: start_pt.y,\n
\t\t\t\tx2: end_pt.x,\n
\t\t\t\ty2: end_pt.y,\n
\t\t\t\tvisibility: \'visible\',\n
\t\t\t\tdisplay: \'inline\'\n
\t\t\t});\n
\t\t\t\n
\t\t\tif(selblock) selblock.setAttribute(\'d\', \'\');\n
\t\t}\n
\t\t\n
\t\tfunction setSelection(start, end, skipInput) {\n
\t\t\tif(start === end) {\n
\t\t\t\tsetCursor(end);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\n
\t\t\tif(!skipInput) {\n
\t\t\t\ttextinput.setSelectionRange(start, end);\n
\t\t\t}\n
\t\t\t\n
\t\t\tselblock = getElem("text_selectblock");\n
\t\t\tif (!selblock) {\n
\n
\t\t\t\tselblock = document.createElementNS(svgns, "path");\n
\t\t\t\tassignAttributes(selblock, {\n
\t\t\t\t\t\'id\': "text_selectblock",\n
\t\t\t\t\t\'fill\': "green",\n
\t\t\t\t\t\'opacity\': .5,\n
\t\t\t\t\t\'style\': "pointer-events:none"\n
\t\t\t\t});\n
\t\t\t\tgetElem("selectorParentGroup").appendChild(selblock);\n
\t\t\t}\n
\n
\t\t\t\n
\t\t\tvar startbb = chardata[start];\n
\t\t\t\n
\t\t\tvar endbb = chardata[end];\n
\t\t\t\n
\t\t\tcursor.setAttribute(\'visibility\', \'hidden\');\n
\t\t\t\n
\t\t\tvar tl = ptToScreen(startbb.x, textbb.y),\n
\t\t\t\ttr = ptToScreen(startbb.x + (endbb.x - startbb.x), textbb.y),\n
\t\t\t\tbl = ptToScreen(startbb.x, textbb.y + textbb.height),\n
\t\t\t\tbr = ptToScreen(startbb.x + (endbb.x - startbb.x), textbb.y + textbb.height);\n
\t\t\t\n
\t\t\t\n
\t\t\tvar dstr = "M" + tl.x + "," + tl.y\n
\t\t\t\t\t\t+ " L" + tr.x + "," + tr.y\n
\t\t\t\t\t\t+ " " + br.x + "," + br.y\n
\t\t\t\t\t\t+ " " + bl.x + "," + bl.y + "z";\n
\t\t\t\n
\t\t\tassignAttributes(selblock, {\n
\t\t\t\td: dstr,\n
\t\t\t\t\'display\': \'inline\'\n
\t\t\t});\n
\t\t}\n
\t\t\n
\t\tfunction getIndexFromPoint(mouse_x, mouse_y) {\n
\t\t\t// Position cursor here\n
\t\t\tvar pt = svgroot.createSVGPoint();\n
\t\t\tpt.x = mouse_x;\n
\t\t\tpt.y = mouse_y;\n
\n
\t\t\t// No content, so return 0\n
\t\t\tif(chardata.length == 1) return 0;\n
\t\t\t\n
\t\t\t// Determine if cursor should be on left or right of character\n
\t\t\tvar charpos = curtext.getCharNumAtPosition(pt);\n
\t\t\tif(charpos < 0) {\n
\t\t\t\t// Out of text range, look at mouse coords\n
\t\t\t\tcharpos = chardata.length - 2;\n
\t\t\t\tif(mouse_x <= chardata[0].x) {\n
\t\t\t\t\tcharpos = 0;\n
\t\t\t\t}\n
\t\t\t} else if(charpos >= chardata.length - 2) {\n
\t\t\t\tcharpos = chardata.length - 2;\n
\t\t\t}\n
\t\t\tvar charbb = chardata[charpos];\n
\t\t\tvar mid = charbb.x + (charbb.width/2);\n
\t\t\tif(mouse_x > mid) {\n
\t\t\t\tcharpos++;\n
\t\t\t}\n
\t\t\treturn charpos;\n
\t\t}\n
\t\t\n
\t\tfunction setCursorFromPoint(mouse_x, mouse_y) {\n
\t\t\tsetCursor(getIndexFromPoint(mouse_x, mouse_y));\n
\t\t}\n
\t\t\n
\t\tfunction setEndSelectionFromPoint(x, y, apply) {\n
\t\t\tvar i1 = textinput.selectionStart;\n
\t\t\tvar i2 = getIndexFromPoint(x, y);\n
\t\t\t\n
\t\t\tvar start = Math.min(i1, i2);\n
\t\t\tvar end = Math.max(i1, i2);\n
\t\t\tsetSelection(start, end, !apply);\n
\t\t}\n
\t\t\t\n
\t\tfunction screenToPt(x_in, y_in) {\n
\t\t\tvar out = {\n
\t\t\t\tx: x_in,\n
\t\t\t\ty: y_in\n
\t\t\t}\n
\t\t\t\n
\t\t\tout.x /= current_zoom;\n
\t\t\tout.y /= current_zoom;\t\t\t\n
\n
\t\t\tif(matrix) {\n
\t\t\t\tvar pt = transformPoint(out.x, out.y, matrix.inverse());\n
\t\t\t\tout.x = pt.x;\n
\t\t\t\tout.y = pt.y;\n
\t\t\t}\n
\t\t\t\n
\t\t\treturn out;\n
\t\t}\t\n
\t\t\n
\t\tfunction ptToScreen(x_in, y_in) {\n
\t\t\tvar out = {\n
\t\t\t\tx: x_in,\n
\t\t\t\ty: y_in\n
\t\t\t}\n
\t\t\t\n
\t\t\tif(matrix) {\n
\t\t\t\tvar pt = transformPoint(out.x, out.y, matrix);\n
\t\t\t\tout.x = pt.x;\n
\t\t\t\tout.y = pt.y;\n
\t\t\t}\n
\t\t\t\n
\t\t\tout.x *= current_zoom;\n
\t\t\tout.y *= current_zoom;\n
\t\t\t\n
\t\t\treturn out;\n
\t\t}\n
\t\t\n
\t\tfunction hideCursor() {\n
\t\t\tif(cursor) {\n
\t\t\t\tcursor.setAttribute(\'visibility\', \'hidden\');\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tfunction selectAll(evt) {\n
\t\t\tsetSelection(0, curtext.textContent.length);\n
\t\t\t$(this).unbind(evt);\n
\t\t}\n
\n
\t\tfunction selectWord(evt) {\n
\t\t\tif(!allow_dbl) return;\n
\t\t\n
\t\t\tvar ept = transformPoint( evt.pageX, evt.pageY, root_sctm ),\n
\t\t\t\tmouse_x = ept.x * current_zoom,\n
\t\t\t\tmouse_y = ept.y * current_zoom;\n
\t\t\tvar pt = screenToPt(mouse_x, mouse_y);\n
\t\t\t\n
\t\t\tvar index = getIndexFromPoint(pt.x, pt.y);\n
\t\t\tvar str = curtext.textContent;\n
\t\t\tvar first = str.substr(0, index).replace(/[a-z0-9]+$/i, \'\').length;\n
\t\t\tvar m = str.substr(index).match(/^[a-z0-9]+/i);\n
\t\t\tvar last = (m?m[0].length:0) + index;\n
\t\t\tsetSelection(first, last);\n
\t\t\t\n
\t\t\t// Set tripleclick\n
\t\t\t$(evt.target).click(selectAll);\n
\t\t\tsetTimeout(function() {\n
\t\t\t\t$(evt.target).unbind(\'click\', selectAll);\n
\t\t\t}, 300);\n
\t\t\t\n
\t\t}\n
\n
\t\treturn {\n
\t\t\tselect: function(target, x, y) {\n
\t\t\t\tif (current_text == target) {\n
\t\t\t\t\tcurtext = target;\n
\t\t\t\t\ttextActions.toEditMode(x, y);\n
\t\t\t\t} // going into pathedit mode\n
\t\t\t\telse {\n
\t\t\t\t\tcurrent_text = target;\n
\t\t\t\t}\t\n
\t\t\t},\n
\t\t\tstart: function(elem) {\n
\t\t\t\tcurtext = elem;\n
\t\t\t\ttextActions.toEditMode();\n
\t\t\t},\n
\t\t\tmouseDown: function(evt, mouse_target, start_x, start_y) {\n
\t\t\t\tvar pt = screenToPt(start_x, start_y);\n
\t\t\t\n
\t\t\t\ttextinput.focus();\n
\t\t\t\tsetCursorFromPoint(pt.x, pt.y);\n
\t\t\t\tlast_x = start_x;\n
\t\t\t\tlast_y = start_y;\n
\t\t\t\t\n
\t\t\t\t// TODO: Find way to block native selection\n
\t\t\t},\n
\t\t\tmouseMove: function(mouse_x, mouse_y) {\n
\t\t\t\tvar pt = screenToPt(mouse_x, mouse_y);\n
\t\t\t\tsetEndSelectionFromPoint(pt.x, pt.y);\n
\t\t\t},\t\t\t\n
\t\t\tmouseUp: function(evt, mouse_x, mouse_y) {\n
\t\t\t\tvar pt = screenToPt(mouse_x, mouse_y);\n
\t\t\t\t\n
\t\t\t\tsetEndSelectionFromPoint(pt.x, pt.y, true);\n
\t\t\t\t\n
\t\t\t\t// TODO: Find a way to make this work: Use transformed BBox instead of evt.target \n
// \t\t\t\tif(last_x === mouse_x && last_y === mouse_y\n
// \t\t\t\t\t&& !Utils.rectsIntersect(transbb, {x: pt.x, y: pt.y, width:0, height:0})) {\n
// \t\t\t\t\ttextActions.toSelectMode(true);\t\t\t\t\n
// \t\t\t\t}\n
\t\t\t\tif(last_x === mouse_x && last_y === mouse_y && evt.target !== curtext) {\n
\t\t\t\t\ttextActions.toSelectMode(true);\n
\t\t\t\t}\n
\n
\t\t\t},\n
\t\t\tsetCursor: setCursor,\n
\t\t\ttoEditMode: function(x, y) {\n
\t\t\t\tallow_dbl = false;\n
\t\t\t\tcurrent_mode = "textedit";\n
\t\t\t\tselectorManager.requestSelector(curtext).showGrips(false);\n
\t\t\t\t\n
\t\t\t\ttextActions.init();\n
\t\t\t\t$(curtext).css(\'cursor\', \'text\');\n
\t\t\t\t\n
// \t\t\t\tif(support.editableText) {\n
// \t\t\t\t\tcurtext.setAttribute(\'editable\', \'simple\');\n
// \t\t\t\t\treturn;\n
// \t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(!arguments.length) {\n
\t\t\t\t\tsetCursor();\n
\t\t\t\t} else {\n
\t\t\t\t\tvar pt = screenToPt(x, y);\n
\t\t\t\t\tsetCursorFromPoint(pt.x, pt.y);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\tallow_dbl = true;\n
\t\t\t\t}, 300);\n
\t\t\t},\n
\t\t\ttoSelectMode: function(selectElem) {\n
\t\t\t\tcurrent_mode = "select";\n
\t\t\t\tclearInterval(blinker);\n
\t\t\t\tblinker = null;\n
\t\t\t\tif(selblock) $(selblock).attr(\'display\',\'none\');\n
\t\t\t\tif(cursor) $(cursor).attr(\'visibility\',\'hidden\');\n
\t\t\t\t$(curtext).css(\'cursor\', \'move\');\n
\t\t\t\t\n
\t\t\t\tif(selectElem) {\n
\t\t\t\t\tcanvas.clearSelection();\n
\t\t\t\t\t$(curtext).css(\'cursor\', \'move\');\n
\t\t\t\t\t\n
\t\t\t\t\tcall("selected", [curtext]);\n
\t\t\t\t\tcanvas.addToSelection([curtext], true);\n
\t\t\t\t}\n
\t\t\t\tif(curtext && !curtext.textContent.length) {\n
\t\t\t\t\t// No content, so delete\n
\t\t\t\t\tcanvas.deleteSelectedElements();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$(textinput).blur();\n
\t\t\t\t\n
\t\t\t\tcurtext = false;\n
\t\t\t\t\n
// \t\t\t\tif(support.editableText) {\n
// \t\t\t\t\tcurtext.removeAttribute(\'editable\');\n
// \t\t\t\t}\n
\t\t\t},\n
\t\t\tsetInputElem: function(elem) {\n
\t\t\t\ttextinput = elem;\n
\t\t\t\t$(textinput).blur(hideCursor);\n
\t\t\t},\n
\t\t\tclear: function() {\n
\t\t\t\tcurrent_text = null;\n
\t\t\t\tif(current_mode == "textedit") {\n
\t\t\t\t\ttextActions.toSelectMode();\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tinit: function(inputElem) {\n
\t\t\t\tif(!curtext) return;\n
\n
// \t\t\t\tif(support.editableText) {\n
// \t\t\t\t\tcurtext.select();\n
// \t\t\t\t\treturn;\n
// \t\t\t\t}\n
\t\t\t\n
\t\t\t\tif(!curtext.parentNode) {\n
\t\t\t\t\t// Result of the ffClone, need to get correct element\n
\t\t\t\t\tcurtext = selectedElements[0];\n
\t\t\t\t\tselectorManager.requestSelector(curtext).showGrips(false);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar str = curtext.textContent;\n
\t\t\t\tvar len = str.length;\n
\t\t\t\t\n
\t\t\t\tvar xform = curtext.getAttribute(\'transform\');\n
\n
\t\t\t\ttextbb = canvas.getBBox(curtext);\n
\t\t\t\t\n
\t\t\t\tmatrix = xform?getMatrix(curtext):null;\n
\n
\t\t\t\tchardata = Array(len);\n
\t\t\t\ttextinput.focus();\n
\t\t\t\t\n
\t\t\t\t$(curtext).unbind(\'dblclick\', selectWord).dblclick(selectWord);\n
\t\t\t\t\n
\t\t\t\tif(!len) {\n
\t\t\t\t\tvar end = {x: textbb.x + (textbb.width/2), width: 0};\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\t\tvar start = curtext.getStartPositionOfChar(i);\n
\t\t\t\t\tvar end = curtext.getEndPositionOfChar(i);\n
\t\t\t\t\t\n
\t\t\t\t\t// Get a "bbox" equivalent for each character. Uses the\n
\t\t\t\t\t// bbox data of the actual text for y, height purposes\n
\t\t\t\t\t\n
\t\t\t\t\t// TODO: Decide if y, width and height are actually necessary\n
\t\t\t\t\tchardata[i] = {\n
\t\t\t\t\t\tx: start.x,\n
\t\t\t\t\t\ty: textbb.y, // start.y?\n
\t\t\t\t\t\twidth: end.x - start.x,\n
\t\t\t\t\t\theight: textbb.height\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Add a last bbox for cursor at end of text\n
\t\t\t\tchardata.push({\n
\t\t\t\t\tx: end.x,\n
\t\t\t\t\twidth: 0\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tsetSelection(textinput.selectionStart, textinput.selectionEnd, true);\n
\t\t\t}\n
\t\t}\n
\t}();\n
\t\n
\tvar pathActions = function() {\n
\t\t\n
\t\tvar subpath = false;\n
\t\tvar pathData = {};\n
\t\tvar current_path;\n
\t\tvar path;\n
\t\tvar segData = {\n
\t\t\t2: [\'x\',\'y\'],\n
\t\t\t4: [\'x\',\'y\'],\n
\t\t\t6: [\'x\',\'y\',\'x1\',\'y1\',\'x2\',\'y2\'],\n
\t\t\t8: [\'x\',\'y\',\'x1\',\'y1\'],\n
\t\t\t10: [\'x\',\'y\',\'r1\',\'r2\',\'angle\',\'largeArcFlag\',\'sweepFlag\'],\n
\t\t\t12: [\'x\'],\n
\t\t\t14: [\'y\']\n
\t\t};\n
\t\t\n
\t\tfunction retPath() {\n
\t\t\treturn path;\n
\t\t}\n
\n
\t\tfunction resetD(p) {\n
\t\t\tp.setAttribute("d", pathActions.convertPath(p));\n
\t\t}\n
\t\t\n
\t\tfunction insertItemBefore(elem, newseg, index) {\n
\t\t\t// Support insertItemBefore on paths for FF2\n
\t\t\tvar list = elem.pathSegList;\n
\t\t\t\n
\t\t\tif(support.pathInsertItemBefore) {\n
\t\t\t\tlist.insertItemBefore(newseg, index);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tvar len = list.numberOfItems;\n
\t\t\tvar arr = [];\n
\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\tvar cur_seg = list.getItem(i);\n
\t\t\t\tarr.push(cur_seg)\t\t\t\t\n
\t\t\t}\n
\t\t\tlist.clear();\n
\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\tif(i == index) { //index+1\n
\t\t\t\t\tlist.appendItem(newseg);\n
\t\t\t\t}\n
\t\t\t\tlist.appendItem(arr[i]);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\t// TODO: See if this should just live in replacePathSeg\n
\t\tfunction ptObjToArr(type, seg_item) {\n
\t\t\tvar arr = segData[type], len = arr.length;\n
\t\t\tvar out = Array(len);\n
\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\tout[i] = seg_item[arr[i]];\n
\t\t\t}\n
\t\t\treturn out;\n
\t\t}\n
\n
\t\tfunction getGripContainer() {\n
\t\t\tvar c = getElem("pathpointgrip_container");\n
\t\t\tif (!c) {\n
\t\t\t\tvar parent = getElem("selectorParentGroup");\n
\t\t\t\tc = parent.appendChild(document.createElementNS(svgns, "g"));\n
\t\t\t\tc.id = "pathpointgrip_container";\n
\t\t\t}\n
\t\t\treturn c;\n
\t\t}\n
\t\n
\t\tvar addPointGrip = function(index, x, y) {\n
\t\t\t// create the container of all the point grips\n
\t\t\tvar pointGripContainer = getGripContainer();\n
\t\n
\t\t\tvar pointGrip = getElem("pathpointgrip_"+index);\n
\t\t\t// create it\n
\t\t\tif (!pointGrip) {\n
\t\t\t\tpointGrip = document.createElementNS(svgns, "circle");\n
\t\t\t\tassignAttributes(pointGrip, {\n
\t\t\t\t\t\'id\': "pathpointgrip_" + index,\n
\t\t\t\t\t\'display\': "none",\n
\t\t\t\t\t\'r\': 4,\n
\t\t\t\t\t\'fill\': "#0FF",\n
\t\t\t\t\t\'stroke\': "#00F",\n
\t\t\t\t\t\'stroke-width\': 2,\n
\t\t\t\t\t\'cursor\': \'move\',\n
\t\t\t\t\t\'style\': \'pointer-events:all\',\n
\t\t\t\t\t\'xlink:title\': uiStrings.pathNodeTooltip\n
\t\t\t\t});\n
\t\t\t\tpointGrip = pointGripContainer.appendChild(pointGrip);\n
\t\n
\t\t\t\tvar grip = $(\'#pathpointgrip_\'+index);\n
\t\t\t\tgrip.dblclick(function() {\n
\t\t\t\t\tif(path) path.setSegType();\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\tif(x && y) {\n
\t\t\t\t// set up the point grip element and display it\n
\t\t\t\tassignAttributes(pointGrip, {\n
\t\t\t\t\t\'cx\': x,\n
\t\t\t\t\t\'cy\': y,\n
\t\t\t\t\t\'display\': "inline"\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\treturn pointGrip;\n
\t\t};\n
\t\t\n
\t\tvar getPointGrip = function(seg, update) {\n
\t\t\tvar index = seg.index;\n
\t\t\tvar pointGrip = addPointGrip(index);\n
\n
\t\t\tif(update) {\n
\t\t\t\tvar pt = getGripPt(seg);\n
\t\t\t\tassignAttributes(pointGrip, {\n
\t\t\t\t\t\'cx\': pt.x,\n
\t\t\t\t\t\'cy\': pt.y,\n
\t\t\t\t\t\'display\': "inline"\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\treturn pointGrip;\n
\t\t}\n
\t\t\n
\t\tvar getSegSelector = function(seg, update) {\n
\t\t\tvar index = seg.index;\n
\t\t\tvar segLine = getElem("segline_" + index);\n
\t\t\tif(!segLine) {\n
\t\t\t\tvar pointGripContainer = getGripContainer();\n
\t\t\t\t// create segline\n
\t\t\t\tsegLine = document.createElementNS(svgns, "path");\n
\t\t\t\tassignAttributes(segLine, {\n
\t\t\t\t\t\'id\': "segline_" + index,\n
\t\t\t\t\t\'display\': \'none\',\n
\t\t\t\t\t\'fill\': "none",\n
\t\t\t\t\t\'stroke\': "#0FF",\n
\t\t\t\t\t\'stroke-width\': 2,\n
\t\t\t\t\t\'style\':\'pointer-events:none\',\n
\t\t\t\t\t\'d\': \'M0,0 0,0\'\n
\t\t\t\t});\n
\t\t\t\tpointGripContainer.appendChild(segLine);\n
\t\t\t} \n
\t\t\t\n
\t\t\tif(update) {\n
\t\t\t\tvar prev = seg.prev;\n
\t\t\t\tif(!prev) {\n
\t\t\t\t\tsegLine.setAttribute("display", "none");\n
\t\t\t\t\treturn segLine;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar pt = getGripPt(prev);\n
\t\t\t\t// Set start point\n
\t\t\t\treplacePathSeg(2, 0, [pt.x, pt.y], segLine);\n
\t\t\t\t\n
\t\t\t\tvar pts = ptObjToArr(seg.type, seg.item, true);\n
\t\t\t\tfor(var i=0; i < pts.length; i+=2) {\n
\t\t\t\t\tvar pt = getGripPt(seg, {x:pts[i], y:pts[i+1]});\n
\t\t\t\t\tpts[i] = pt.x;\n
\t\t\t\t\tpts[i+1] = pt.y;\n
\t\t\t\t}\n
\n
\t\t\t\treplacePathSeg(seg.type, 1, pts, segLine);\n
\t\t\t}\n
\t\t\treturn segLine;\n
\t\t}\n
\t\t\n
\t\tvar getControlPoints = function(seg) {\n
\t\t\tvar item = seg.item;\n
\t\t\tvar index = seg.index;\n
\t\t\tif(!("x1" in item) || !("x2" in item)) return null;\n
\t\t\tvar cpt = {};\t\t\t\n
\t\t\tvar pointGripContainer = getGripContainer();\n
\t\t\n
\t\t\t// Note that this is intentionally not seg.prev.item\n
\t\t\tvar prev = path.segs[index-1].item;\n
\n
\t\t\tvar seg_items = [prev, item];\n
\t\t\t\n
\t\t\tfor(var i=1; i<3; i++) {\n
\t\t\t\tvar id = index + \'c\' + i;\n
\t\t\t\tvar ctrlLine = cpt[\'c\' + i + \'_line\'] = getElem("ctrlLine_"+id);\n
\t\t\t\t\n
\t\t\t\tif(!ctrlLine) {\n
\t\t\t\t\tctrlLine = document.createElementNS(svgns, "line");\n
\t\t\t\t\tassignAttributes(ctrlLine, {\n
\t\t\t\t\t\t\'id\': "ctrlLine_"+id,\n
\t\t\t\t\t\t\'stroke\': "#555",\n
\t\t\t\t\t\t\'stroke-width\': 1,\n
\t\t\t\t\t\t"style": "pointer-events:none"\n
\t\t\t\t\t});\n
\t\t\t\t\tpointGripContainer.appendChild(ctrlLine);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar pt = getGripPt(seg, {x:item[\'x\' + i], y:item[\'y\' + i]});\n
\t\t\t\tvar gpt = getGripPt(seg, {x:seg_items[i-1].x, y:seg_items[i-1].y});\n
\t\t\t\t\n
\t\t\t\tassignAttributes(ctrlLine, {\n
\t\t\t\t\t\'x1\': pt.x,\n
\t\t\t\t\t\'y1\': pt.y,\n
\t\t\t\t\t\'x2\': gpt.x,\n
\t\t\t\t\t\'y2\': gpt.y,\n
\t\t\t\t\t\'display\': "inline"\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tcpt[\'c\' + i + \'_line\'] = ctrlLine;\n
\t\t\t\t\t\n
\t\t\t\tvar pointGrip = cpt[\'c\' + i] = getElem("ctrlpointgrip_"+id);\n
\t\t\t\t// create it\n
\t\t\t\tif (!pointGrip) {\n
\t\t\t\t\tpointGrip = document.createElementNS(svgns, "circle");\n
\t\t\t\t\tassignAttributes(pointGrip, {\n
\t\t\t\t\t\t\'id\': "ctrlpointgrip_" + id,\n
\t\t\t\t\t\t\'display\': "none",\n
\t\t\t\t\t\t\'r\': 4,\n
\t\t\t\t\t\t\'fill\': "#0FF",\n
\t\t\t\t\t\t\'stroke\': "#55F",\n
\t\t\t\t\t\t\'stroke-width\': 1,\n
\t\t\t\t\t\t\'cursor\': \'move\',\n
\t\t\t\t\t\t\'style\': \'pointer-events:all\',\n
\t\t\t\t\t\t\'xlink:title\': uiStrings.pathCtrlPtTooltip\n
\t\t\t\t\t});\n
\t\t\t\t\tpointGripContainer.appendChild(pointGrip);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tassignAttributes(pointGrip, {\n
\t\t\t\t\t\'cx\': pt.x,\n
\t\t\t\t\t\'cy\': pt.y,\n
\t\t\t\t\t\'display\': "inline"\n
\t\t\t\t});\n
\t\t\t\tcpt[\'c\' + i] = pointGrip;\n
\t\t\t}\n
\t\t\treturn cpt;\n
\t\t}\n
\t\t\n
\t\tfunction getGripPt(seg, alt_pt) {\n
\t\t\tvar out = {\n
\t\t\t\tx: alt_pt? alt_pt.x : seg.item.x,\n
\t\t\t\ty: alt_pt? alt_pt.y : seg.item.y\n
\t\t\t}, path = seg.path;\n
\n
\t\t\t\n
\t\t\tif(path.matrix) {\n
\t\t\t\tvar pt = transformPoint(out.x, out.y, path.matrix);\n
\t\t\t\tout = pt;\n
\t\t\t}\n
\n
\t\t\tout.x *= current_zoom;\n
\t\t\tout.y *= current_zoom;\n
\t\t\t\n
\t\t\treturn out;\n
\t\t}\n
\t\t\n
\t\tfunction getPointFromGrip(pt, path) {\n
\t\t\tvar out = {\n
\t\t\t\tx: pt.x,\n
\t\t\t\ty: pt.y\n
\t\t\t}\n
\t\t\t\n
\t\t\tif(path.matrix) {\n
\t\t\t\tvar pt = transformPoint(out.x, out.y, path.imatrix);\n
\t\t\t\tout.x = pt.x;\n
\t\t\t\tout.y = pt.y;\n
\t\t\t}\n
\t\t\t\n
\t\t\tout.x /= current_zoom;\n
\t\t\tout.y /= current_zoom;\t\t\t\n
\t\t\t\n
\t\t\treturn out;\n
\t\t}\n
\t\t\n
\t\tfunction Segment(index, item) {\n
\t\t\tvar s = this;\n
\t\t\t\n
\t\t\ts.index = index;\n
\t\t\ts.selected = false;\n
\t\t\ts.type = item.pathSegType;\n
\t\t\tvar grip;\n
\n
\t\t\ts.addGrip = function() {\n
\t\t\t\tgrip = s.ptgrip = getPointGrip(s, true);\n
\t\t\t\ts.ctrlpts = getControlPoints(s, true);\n
\t\t\t\ts.segsel = getSegSelector(s, true);\n
\t\t\t}\n
\t\t\t\n
\t\t\ts.item = item;\n
\t\t\ts.show = function(y) {\n
\t\t\t\tif(grip) {\n
\t\t\t\t\tgrip.setAttribute("display", y?"inline":"none");\n
\t\t\t\t\ts.segsel.setAttribute("display", y?"inline":"none");\n
\t\t\t\t\t\n
\t\t\t\t\t// Show/hide all control points if available\n
\t\t\t\t\ts.showCtrlPts(y);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\ts.select = function(y) {\n
\t\t\t\tif(grip) {\n
\t\t\t\t\tgrip.setAttribute("stroke", y?"#0FF":"#00F");\n
\t\t\t\t\ts.segsel.setAttribute("display", y?"inline":"none");\n
\t\t\t\t\tif(s.ctrlpts) {\n
\t\t\t\t\t\ts.selectCtrls(y);\n
\t\t\t\t\t}\n
\t\t\t\t\ts.selected = y;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\ts.selectCtrls = function(y) {\n
\t\t\t\t$(\'#ctrlpointgrip_\' + s.index + \'c1, #ctrlpointgrip_\' + s.index + \'c2\').attr(\'fill\',y?\'#0FF\':\'#EEE\');\n
\t\t\t}\n
\t\t\ts.update = function(full) {\n
\t\t\t\titem = s.item;\n
\t\t\t\tif(grip) {\n
\t\t\t\t\tvar pt = getGripPt(s);\n
\t\t\t\t\tassignAttributes(grip, {\n
\t\t\t\t\t\t\'cx\': pt.x,\n
\t\t\t\t\t\t\'cy\': pt.y\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\tgetSegSelector(s, true);\n
\t\t\t\t\t\n
\t\t\t\t\tif(s.ctrlpts) {\n
\t\t\t\t\t\tif(full) {\n
\t\t\t\t\t\t\ts.item = path.elem.pathSegList.getItem(s.index);\n
\t\t\t\t\t\t\ts.type = s.item.pathSegType;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tgetControlPoints(s);\n
\t\t\t\t\t} \n
\t\t\t\t\t// this.segsel.setAttribute("display", y?"inline":"none");\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\ts.move = function(dx, dy) {\n
\t\t\t\tvar item = s.item;\n
\t\t\t\t\n
\t\t\t\tvar cur = s;\n
\t\t\t\t\n
\t\t\t\tif(cur.ctrlpts) {\n
\t\t\t\t\tvar cur_pts = [item.x += dx, item.y += dy, \n
\t\t\t\t\t\titem.x1, item.y1, item.x2 += dx, item.y2 += dy];\n
\t\t\t\t} else {\n
\t\t\t\t\tvar cur_pts = [item.x += dx, item.y += dy];\n
\t\t\t\t}\n
\t\t\t\treplacePathSeg(cur.type, cur.index, cur_pts);\n
\n
\t\t\t\tif(s.next && s.next.ctrlpts) {\n
\t\t\t\t\tvar next = s.next.item;\n
\t\t\t\t\tvar next_pts = [next.x, next.y, \n
\t\t\t\t\t\tnext.x1 += dx, next.y1 += dy, next.x2, next.y2];\n
\t\t\t\t\treplacePathSeg(s.next.type, s.next.index, next_pts);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(s.mate) {\n
\t\t\t\t\t// The last point of a closed subpath has a "mate",\n
\t\t\t\t\t// which is the "M" segment of the subpath\n
\t\t\t\t\tvar item = s.mate.item;\n
\t\t\t\t\tvar pts = [item.x += dx, item.y += dy];\n
\t\t\t\t\treplacePathSeg(s.mate.type, s.mate.index, pts);\n
\t\t\t\t\t// Has no grip, so does not need "updating"?\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\ts.update(true);\n
\t\t\t\tif(s.next) s.next.update(true);\n
\t\t\t}\n
\t\t\ts.setLinked = function(num) {\n
\t\t\t\tvar seg, anum, pt;\n
\t\t\t\tif(num == 2) {\n
\t\t\t\t\tanum = 1;\n
\t\t\t\t\tseg = s.next;\n
\t\t\t\t\tif(!seg) return;\n
\t\t\t\t\tpt = s.item;\n
\t\t\t\t} else {\n
\t\t\t\t\tanum = 2;\n
\t\t\t\t\tseg = s.prev;\n
\t\t\t\t\tif(!seg) return;\n
\t\t\t\t\tpt = seg.item;\n
\t\t\t\t}\n
\t\t\t\tvar item = seg.item;\n
\t\t\t\t\n
\t\t\t\titem[\'x\' + anum] = pt.x + (pt.x - s.item[\'x\' + num]);\n
\t\t\t\titem[\'y\' + anum] = pt.y + (pt.y - s.item[\'y\' + num]);\n
\t\t\t\t\n
\t\t\t\tvar pts = [item.x,item.y,\n
\t\t\t\t\titem.x1,item.y1, item.x2,item.y2];\n
\t\t\t\t\t\n
\t\t\t\treplacePathSeg(seg.type, seg.index, pts);\n
\t\t\t\tseg.update(true);\n
\n
\t\t\t}\n
\t\t\ts.moveCtrl = function(num, dx, dy) {\n
\t\t\t\tvar item = s.item;\n
\n
\t\t\t\titem[\'x\' + num] += dx;\n
\t\t\t\titem[\'y\' + num] += dy;\n
\t\t\t\t\n
\t\t\t\tvar pts = [item.x,item.y,\n
\t\t\t\t\titem.x1,item.y1, item.x2,item.y2];\n
\t\t\t\t\t\n
\t\t\t\treplacePathSeg(s.type, s.index, pts);\n
\t\t\t\ts.update(true);\n
\t\t\t}\n
\t\t\ts.setType = function(new_type, pts) {\n
\t\t\t\treplacePathSeg(new_type, index, pts);\n
\t\t\t\ts.type = new_type;\n
\t\t\t\ts.item = path.elem.pathSegList.getItem(index);\n
\t\t\t\ts.showCtrlPts(new_type === 6);\n
\t\t\t\ts.ctrlpts = getControlPoints(s);\n
\t\t\t\ts.update(true);\n
\t\t\t}\n
\t\t\ts.showCtrlPts = function(y) {\n
\t\t\t\tif(s.ctrlpts) {\n
\t\t\t\t\tfor (var o in s.ctrlpts) {\n
\t\t\t\t\t\ts.ctrlpts[o].setAttribute("display", y?"inline":"none");\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tfunction Path(elem) {\n
\t\t\tif(!elem || elem.tagName !== "path") return false;\n
\t\t\n
\t\t\tvar p = path = this;\n
\t\t\tthis.elem = elem;\n
\t\t\tthis.segs = [];\n
\t\t\tthis.selected_pts = [];\n
\t\t\t\n
\t\t\t// Reset path data\n
\t\t\tthis.init = function() {\n
\t\t\t\t// Hide all grips, etc\n
\t\t\t\t$(getGripContainer()).find("*").attr("display", "none");\n
\t\t\t\tvar segList = elem.pathSegList;\n
\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\tp.segs = [];\n
\t\t\t\tp.selected_pts = [];\n
\t\t\t\tp.first_seg = null;\n
\t\t\t\t\n
\t\t\t\t// Set up segs array\n
\t\t\t\tfor(var i=0; i < len; i++) {\n
\t\t\t\t\tvar item = segList.getItem(i);\n
\t\t\t\t\tvar segment = new Segment(i, item);\n
\t\t\t\t\tsegment.path = p;\n
\t\t\t\t\tp.segs.push(segment);\n
\t\t\t\t}\t\n
\t\t\t\t\n
\t\t\t\tvar segs = p.segs;\n
\t\t\t\tvar start_i = null;\n
\n
\t\t\t\tfor(var i=0; i < len; i++) {\n
\t\t\t\t\tvar seg = segs[i]; \n
\t\t\t\t\tvar next_seg = (i+1) >= len ? null : segs[i+1];\n
\t\t\t\t\tvar prev_seg = (i-1) < 0 ? null : segs[i-1];\n
\t\t\t\t\t\n
\t\t\t\t\tif(seg.type === 2) {\n
\t\t\t\t\t\tif(prev_seg && prev_seg.type !== 1) {\n
\t\t\t\t\t\t\t// New sub-path, last one is open,\n
\t\t\t\t\t\t\t// so add a grip to last sub-path\'s first point\n
\t\t\t\t\t\t\tvar start_seg = segs[start_i];\n
\t\t\t\t\t\t\tstart_seg.next = segs[start_i+1];\n
\t\t\t\t\t\t\tstart_seg.next.prev = start_seg;\n
\t\t\t\t\t\t\tstart_seg.addGrip();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// Remember that this is a starter seg\n
\t\t\t\t\t\tstart_i = i;\n
\t\t\t\t\t} else if(next_seg && next_seg.type === 1) {\n
\t\t\t\t\t\t// This is the last real segment of a closed sub-path\n
\t\t\t\t\t\t// Next is first seg after "M"\n
\t\t\t\t\t\tseg.next = segs[start_i+1];\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// First seg after "M"\'s prev is this\n
\t\t\t\t\t\tseg.next.prev = seg;\n
\t\t\t\t\t\tseg.mate = segs[start_i];\n
\t\t\t\t\t\tseg.addGrip();\n
\t\t\t\t\t\tif(p.first_seg == null) {\n
\t\t\t\t\t\t\tp.first_seg = seg;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if(!next_seg) {\n
\t\t\t\t\t\tif(seg.type !== 1) {\n
\t\t\t\t\t\t\t// Last seg, doesn\'t close so add a grip\n
\t\t\t\t\t\t\t// to last sub-path\'s first point\n
\t\t\t\t\t\t\tvar start_seg = segs[start_i];\n
\t\t\t\t\t\t\tstart_seg.next = segs[start_i+1];\n
\t\t\t\t\t\t\tstart_seg.next.prev = start_seg;\n
\t\t\t\t\t\t\tstart_seg.addGrip();\n
\t\t\t\t\t\t\tseg.addGrip();\n
\n
\t\t\t\t\t\t\tif(!p.first_seg) {\n
\t\t\t\t\t\t\t\t// Open path, so set first as real first and add grip\n
\t\t\t\t\t\t\t\tp.first_seg = segs[start_i];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if(seg.type !== 1){\n
\t\t\t\t\t\t// Regular segment, so add grip and its "next"\n
\t\t\t\t\t\tseg.addGrip();\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Don\'t set its "next" if it\'s an "M"\n
\t\t\t\t\t\tif(next_seg && next_seg.type !== 2) {\n
\t\t\t\t\t\t\tseg.next = next_seg;\n
\t\t\t\t\t\t\tseg.next.prev = seg;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\treturn p;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.init();\n
\t\t\t\n
\t\t\t// Update position of all points\n
\t\t\tthis.update = function() {\n
\t\t\t\tif(canvas.getRotationAngle(p.elem)) {\n
\t\t\t\t\tp.matrix = getMatrix(path.elem);\n
\t\t\t\t\tp.imatrix = p.matrix.inverse();\n
\t\t\t\t}\n
\n
\t\t\t\tp.eachSeg(function(i) {\n
\t\t\t\t\tthis.item = elem.pathSegList.getItem(i);\n
\t\t\t\t\tthis.update();\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\treturn p;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.eachSeg = function(fn) {\n
\t\t\t\tvar len = p.segs.length\n
\t\t\t\tfor(var i=0; i < len; i++) {\n
\t\t\t\t\tvar ret = fn.call(p.segs[i], i);\n
\t\t\t\t\tif(ret === false) break;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.addSeg = function(index) {\n
\t\t\t\t// Adds a new segment\n
\t\t\t\tvar seg = p.segs[index];\n
\t\t\t\tif(!seg.prev) return;\n
\t\t\t\t\n
\t\t\t\tvar prev = seg.prev;\n
\t\t\t\tvar newseg;\n
\t\t\t\tswitch(seg.item.pathSegType) {\n
\t\t\t\tcase 4:\n
\t\t\t\t\tvar new_x = (seg.item.x + prev.item.x) / 2;\n
\t\t\t\t\tvar new_y = (seg.item.y + prev.item.y) / 2;\n
\t\t\t\t\tnewseg = elem.createSVGPathSegLinetoAbs(new_x, new_y);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase 6: //make it a curved segment to preserve the shape (WRS)\n
\t\t\t\t\t// http://en.wikipedia.org/wiki/De_Casteljau%27s_algorithm#Geometric_interpretation\n
\t\t\t\t\tvar p0_x = (prev.item.x + seg.item.x1)/2;\n
\t\t\t\t\tvar p1_x = (seg.item.x1 + seg.item.x2)/2;\n
\t\t\t\t\tvar p2_x = (seg.item.x2 + seg.item.x)/2;\n
\t\t\t\t\tvar p01_x = (p0_x + p1_x)/2;\n
\t\t\t\t\tvar p12_x = (p1_x + p2_x)/2;\n
\t\t\t\t\tvar new_x = (p01_x + p12_x)/2;\n
\t\t\t\t\tvar p0_y = (prev.item.y + seg.item.y1)/2;\n
\t\t\t\t\tvar p1_y = (seg.item.y1 + seg.item.y2)/2;\n
\t\t\t\t\tvar p2_y = (seg.item.y2 + seg.item.y)/2;\n
\t\t\t\t\tvar p01_y = (p0_y + p1_y)/2;\n
\t\t\t\t\tvar p12_y = (p1_y + p2_y)/2;\n
\t\t\t\t\tvar new_y = (p01_y + p12_y)/2;\n
\t\t\t\t\tnewseg = elem.createSVGPathSegCurvetoCubicAbs(new_x,new_y, p0_x,p0_y, p01_x,p01_y);\n
\t\t\t\t\tvar pts = [seg.item.x,seg.item.y,p12_x,p12_y,p2_x,p2_y];\n
\t\t\t\t\treplacePathSeg(seg.type,index,pts);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\tinsertItemBefore(elem, newseg, index);\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.deleteSeg = function(index) {\n
\t\t\t\tvar seg = p.segs[index];\n
\t\t\t\tvar list = elem.pathSegList;\n
\t\t\t\t\n
\t\t\t\tseg.show(false);\n
\t\t\t\tvar next = seg.next;\n
\t\t\t\tif(seg.mate) {\n
\t\t\t\t\t// Make the next point be the "M" point\n
\t\t\t\t\tvar pt = [next.item.x, next.item.y];\n
\t\t\t\t\treplacePathSeg(2, next.index, pt);\n
\t\t\t\t\t\n
\t\t\t\t\t// Reposition last node\n
\t\t\t\t\treplacePathSeg(4, seg.index, pt);\n
\t\t\t\t\t\n
\t\t\t\t\tlist.removeItem(seg.mate.index);\n
\t\t\t\t} else if(!seg.prev) {\n
\t\t\t\t\t// First node of open path, make next point the M\n
\t\t\t\t\tvar item = seg.item;\n
\t\t\t\t\tvar pt = [next.item.x, next.item.y];\n
\t\t\t\t\treplacePathSeg(2, seg.next.index, pt);\n
\t\t\t\t\tlist.removeItem(index);\n
\t\t\t\t\t\n
\t\t\t\t} else {\n
\t\t\t\t\tlist.removeItem(index);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.endChanges = function(text) {\n
\t\t\t\tif(isWebkit) resetD(p.elem);\n
\t\t\t\tvar cmd = new ChangeElementCommand(elem, {d: p.last_d}, text);\n
\t\t\t\taddCommandToHistory(cmd);\n
\t\t\t\tcall("changed", [elem]);\n
\t\t\t}\n
\n
\t\t\tthis.subpathIsClosed = function(index) {\n
\t\t\t\tvar closed = false;\n
\t\t\t\t// Check if subpath is already open\n
\t\t\t\tpath.eachSeg(function(i) {\n
\t\t\t\t\tif(i <= index) return true;\n
\t\t\t\t\tif(this.type === 2) {\n
\t\t\t\t\t\t// Found M first, so open\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t} else if(this.type === 1) {\n
\t\t\t\t\t\t// Found Z first, so closed\n
\t\t\t\t\t\tclosed = true;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\treturn closed;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.addPtsToSelection = function(indexes) {\n
\t\t\t\tif(!$.isArray(indexes)) indexes = [indexes];\n
\t\t\t\tfor(var i=0; i< indexes.length; i++) {\n
\t\t\t\t\tvar index = indexes[i];\n
\t\t\t\t\tvar seg = p.segs[index];\n
\t\t\t\t\tif(seg.ptgrip) {\n
\t\t\t\t\t\tif($.inArray(index, p.selected_pts) == -1 && index >= 0) {\n
\t\t\t\t\t\t\tp.selected_pts.push(index);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t\tp.selected_pts.sort();\n
\t\t\t\tvar i = p.selected_pts.length,\n
\t\t\t\t\tgrips = new Array(i);\n
\t\t\t\t// Loop through points to be selected and highlight each\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar pt = p.selected_pts[i];\n
\t\t\t\t\tvar seg = p.segs[pt];\n
\t\t\t\t\tseg.select(true);\n
\t\t\t\t\tgrips[i] = seg.ptgrip;\n
\t\t\t\t}\n
\t\t\t\t// TODO: Correct this:\n
\t\t\t\tpathActions.canDeleteNodes = true;\n
\t\t\t\t\n
\t\t\t\tpathActions.closed_subpath = p.subpathIsClosed(p.selected_pts[0]);\n
\t\t\t\t\n
\t\t\t\tcall("selected", grips);\n
\t\t\t}\n
\n
\t\t\tthis.removePtFromSelection = function(index) {\n
\t\t\t\tvar pos = $.inArray(index, p.selected_pts);\n
\t\t\t\tif(pos == -1) {\n
\t\t\t\t\treturn;\n
\t\t\t\t} \n
\t\t\t\tp.segs[index].select(false);\n
\t\t\t\tp.selected_pts.splice(pos, 1);\n
\t\t\t}\n
\n
\t\t\t\n
\t\t\tthis.clearSelection = function() {\n
\t\t\t\tp.eachSeg(function(i) {\n
\t\t\t\t\tthis.select(false);\n
\t\t\t\t});\n
\t\t\t\tp.selected_pts = [];\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.selectPt = function(pt, ctrl_num) {\n
\t\t\t\tp.clearSelection();\n
\t\t\t\tif(pt == null) {\n
\t\t\t\t\tp.eachSeg(function(i) {\n
\t\t\t\t\t\tif(this.prev) {\n
\t\t\t\t\t\t\tpt = i;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\tp.addPtsToSelection(pt);\n
\t\t\t\tif(ctrl_num) {\n
\t\t\t\t\tp.dragctrl = ctrl_num;\n
\t\t\t\t\t\n
\t\t\t\t\tif(link_control_pts) {\n
\t\t\t\t\t\tp.segs[pt].setLinked(ctrl_num);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.storeD = function() {\n
\t\t\t\tthis.last_d = elem.getAttribute(\'d\');\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.show = function(y) {\n
\t\t\t\t// Shows this path\'s segment grips \n
\t\t\t\tp.eachSeg(function() {\n
\t\t\t\t\tthis.show(y);\n
\t\t\t\t});\n
\t\t\t\tif(y) {\n
\t\t\t\t\tp.selectPt(p.first_seg.index);\n
\t\t\t\t}\n
\t\t\t\treturn p;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// Move selected points \n
\t\t\tthis.movePts = function(d_x, d_y) {\n
\t\t\t\tvar i = p.selected_pts.length;\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar seg = p.segs[p.selected_pts[i]];\n
\t\t\t\t\tseg.move(d_x, d_y);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.moveCtrl = function(d_x, d_y) {\n
\t\t\t\tvar seg = p.segs[p.selected_pts[0]];\n
\t\t\t\tseg.moveCtrl(p.dragctrl, d_x, d_y);\n
\t\t\t\tif(link_control_pts) {\n
\t\t\t\t\tseg.setLinked(p.dragctrl);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.setSegType = function(new_type) {\n
\t\t\t\tp.storeD();\n
\t\t\t\tvar i = p.selected_pts.length;\n
\t\t\t\tvar text;\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar sel_pt = p.selected_pts[i];\n
\t\t\t\t\t\n
\t\t\t\t\t// Selected seg\n
\t\t\t\t\tvar cur = p.segs[sel_pt];\n
\t\t\t\t\tvar prev = cur.prev;\n
\t\t\t\t\tif

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

(!prev) continue;\n
\t\t\t\t\t\n
\t\t\t\t\tif(!new_type) { // double-click, so just toggle\n
\t\t\t\t\t\ttext = "Toggle Path Segment Type";\n
\t\t\t\n
\t\t\t\t\t\t// Toggle segment to curve/straight line\n
\t\t\t\t\t\tvar old_type = cur.type;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tnew_type = (old_type == 6) ? 4 : 6;\n
\t\t\t\t\t} \n
\t\t\t\t\t\n
\t\t\t\t\tnew_type = new_type-0;\n
\t\t\t\t\t\n
\t\t\t\t\tvar cur_x = cur.item.x;\n
\t\t\t\t\tvar cur_y = cur.item.y;\n
\t\t\t\t\tvar prev_x = prev.item.x;\n
\t\t\t\t\tvar prev_y = prev.item.y;\n
\t\t\t\t\tvar points;\n
\t\t\t\t\tswitch ( new_type ) {\n
\t\t\t\t\tcase 6:\n
\t\t\t\t\t\tif(cur.olditem) {\n
\t\t\t\t\t\t\tvar old = cur.olditem;\n
\t\t\t\t\t\t\tpoints = [cur_x,cur_y, old.x1,old.y1, old.x2,old.y2];\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tvar diff_x = cur_x - prev_x;\n
\t\t\t\t\t\t\tvar diff_y = cur_y - prev_y;\n
\t\t\t\t\t\t\t// get control points from straight line segment\n
\t\t\t\t\t\t\t/*\n
\t\t\t\t\t\t\tvar ct1_x = (prev_x + (diff_y/2));\n
\t\t\t\t\t\t\tvar ct1_y = (prev_y - (diff_x/2));\n
\t\t\t\t\t\t\tvar ct2_x = (cur_x + (diff_y/2));\n
\t\t\t\t\t\t\tvar ct2_y = (cur_y - (diff_x/2));\n
\t\t\t\t\t\t\t*/\n
\t\t\t\t\t\t\t//create control points on the line to preserve the shape (WRS)\n
\t\t\t\t\t\t\tvar ct1_x = (prev_x + (diff_x/3));\n
\t\t\t\t\t\t\tvar ct1_y = (prev_y + (diff_y/3));\n
\t\t\t\t\t\t\tvar ct2_x = (cur_x - (diff_x/3));\n
\t\t\t\t\t\t\tvar ct2_y = (cur_y - (diff_y/3));\n
\t\t\t\t\t\t\tpoints = [cur_x,cur_y, ct1_x,ct1_y, ct2_x,ct2_y];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase 4:\n
\t\t\t\t\t\tpoints = [cur_x,cur_y];\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Store original prevve segment nums\n
\t\t\t\t\t\tcur.olditem = cur.item;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tcur.setType(new_type, points);\n
\t\t\t\t}\n
\t\t\t\tpath.endChanges(text);\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t}\n
\t\t\n
\t\tfunction getPath(elem) {\n
\t\t\tvar p = pathData[elem.id];\n
\t\t\tif(!p) p = pathData[elem.id] = new Path(elem);\n
\t\t\treturn p;\n
\t\t}\n
\t\t\n
\t\t\n
\t\tvar pathFuncs = [],\n
\t\t\tcurrent_path = null,\n
\t\t\tcurrent_path_pts = [],\n
\t\t\tlink_control_pts = false,\n
\t\t\thasMoved = false;\n
\t\t\n
\t\t// This function converts a polyline (created by the fh_path tool) into\n
\t\t// a path element and coverts every three line segments into a single bezier\n
\t\t// curve in an attempt to smooth out the free-hand\n
\t\tvar smoothPolylineIntoPath = function(element) {\n
\t\t\tvar points = element.points;\n
\t\t\tvar N = points.numberOfItems;\n
\t\t\tif (N >= 4) {\n
\t\t\t\t// loop through every 3 points and convert to a cubic bezier curve segment\n
\t\t\t\t// \n
\t\t\t\t// NOTE: this is cheating, it means that every 3 points has the potential to \n
\t\t\t\t// be a corner instead of treating each point in an equal manner.  In general,\n
\t\t\t\t// this technique does not look that good.\n
\t\t\t\t// \n
\t\t\t\t// I am open to better ideas!\n
\t\t\t\t// \n
\t\t\t\t// Reading:\n
\t\t\t\t// - http://www.efg2.com/Lab/Graphics/Jean-YvesQueinecBezierCurves.htm\n
\t\t\t\t// - http://www.codeproject.com/KB/graphics/BezierSpline.aspx?msg=2956963\n
\t\t\t\t// - http://www.ian-ko.com/ET_GeoWizards/UserGuide/smooth.htm\n
\t\t\t\t// - http://www.cs.mtu.edu/~shene/COURSES/cs3621/NOTES/spline/Bezier/bezier-der.html\n
\t\t\t\tvar curpos = points.getItem(0), prevCtlPt = null;\n
\t\t\t\tvar d = [];\n
\t\t\t\td.push(["M",curpos.x,",",curpos.y," C"].join(""));\n
\t\t\t\tfor (var i = 1; i <= (N-4); i += 3) {\n
\t\t\t\t\tvar ct1 = points.getItem(i);\n
\t\t\t\t\tvar ct2 = points.getItem(i+1);\n
\t\t\t\t\tvar end = points.getItem(i+2);\n
\t\t\t\t\t\n
\t\t\t\t\t// if the previous segment had a control point, we want to smooth out\n
\t\t\t\t\t// the control points on both sides\n
\t\t\t\t\tif (prevCtlPt) {\n
\t\t\t\t\t\tvar newpts = smoothControlPoints( prevCtlPt, ct1, curpos );\n
\t\t\t\t\t\tif (newpts && newpts.length == 2) {\n
\t\t\t\t\t\t\tvar prevArr = d[d.length-1].split(\',\');\n
\t\t\t\t\t\t\tprevArr[2] = newpts[0].x;\n
\t\t\t\t\t\t\tprevArr[3] = newpts[0].y;\n
\t\t\t\t\t\t\td[d.length-1] = prevArr.join(\',\');\n
\t\t\t\t\t\t\tct1 = newpts[1];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\td.push([ct1.x,ct1.y,ct2.x,ct2.y,end.x,end.y].join(\',\'));\n
\t\t\t\t\t\n
\t\t\t\t\tcurpos = end;\n
\t\t\t\t\tprevCtlPt = ct2;\n
\t\t\t\t}\n
\t\t\t\t// handle remaining line segments\n
\t\t\t\td.push("L");\n
\t\t\t\tfor(;i < N;++i) {\n
\t\t\t\t\tvar pt = points.getItem(i);\n
\t\t\t\t\td.push([pt.x,pt.y].join(","));\n
\t\t\t\t}\n
\t\t\t\td = d.join(" ");\n
\n
\t\t\t\t// create new path element\n
\t\t\t\telement = addSvgElementFromJson({\n
\t\t\t\t\t"element": "path",\n
\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"id": getId(),\n
\t\t\t\t\t\t"d": d,\n
\t\t\t\t\t\t"fill": "none"\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\tcall("changed",[element]);\n
\t\t\t}\n
\t\t\treturn element;\n
\t\t};\n
\t\t\n
\t\t// This replaces the segment at the given index. Type is given as number.\n
\t\tvar replacePathSeg = function(type, index, pts, elem) {\n
\t\t\tvar path = elem || retPath().elem;\n
\t\t\tvar func = \'createSVGPathSeg\' + pathFuncs[type];\n
\t\t\tvar seg = path[func].apply(path, pts);\n
\t\t\t\n
\t\t\tif(support.pathReplaceItem) {\n
\t\t\t\tpath.pathSegList.replaceItem(seg, index);\n
\t\t\t} else {\n
\t\t\t\tvar segList = path.pathSegList;\n
\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\tvar arr = [];\n
\t\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\t\tvar cur_seg = segList.getItem(i);\n
\t\t\t\t\tarr.push(cur_seg)\t\t\t\t\n
\t\t\t\t}\n
\t\t\t\tsegList.clear();\n
\t\t\t\tfor(var i=0; i<len; i++) {\n
\t\t\t\t\tif(i == index) {\n
\t\t\t\t\t\tsegList.appendItem(seg);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tsegList.appendItem(arr[i]);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
 \t\t// If the path was rotated, we must now pay the piper:\n
\t\t// Every path point must be rotated into the rotated coordinate system of \n
\t\t// its old center, then determine the new center, then rotate it back\n
\t\t// This is because we want the path to remember its rotation\n
\t\t\n
\t\t// TODO: This is still using ye olde transform methods, can probably\n
\t\t// be optimized or even taken care of by recalculateDimensions\n
\t\tvar recalcRotatedPath = function() {\n
\t\t\tvar current_path = path.elem;\n
\t\t\tvar angle = canvas.getRotationAngle(current_path, true);\n
\t\t\tif(!angle) return;\n
\t\t\tselectedBBoxes[0] = path.oldbbox;\n
\t\t\tvar box = canvas.getBBox(current_path),\n
\t\t\t\toldbox = selectedBBoxes[0],\n
\t\t\t\toldcx = oldbox.x + oldbox.width/2,\n
\t\t\t\toldcy = oldbox.y + oldbox.height/2,\n
\t\t\t\tnewcx = box.x + box.width/2,\n
\t\t\t\tnewcy = box.y + box.height/2,\n
\t\t\t\n
\t\t\t// un-rotate the new center to the proper position\n
\t\t\t\tdx = newcx - oldcx,\n
\t\t\t\tdy = newcy - oldcy,\n
\t\t\t\tr = Math.sqrt(dx*dx + dy*dy),\n
\t\t\t\ttheta = Math.atan2(dy,dx) + angle;\n
\t\t\t\t\n
\t\t\tnewcx = r * Math.cos(theta) + oldcx;\n
\t\t\tnewcy = r * Math.sin(theta) + oldcy;\n
\t\t\t\n
\t\t\tvar getRotVals = function(x, y) {\n
\t\t\t\tdx = x - oldcx;\n
\t\t\t\tdy = y - oldcy;\n
\t\t\t\t\n
\t\t\t\t// rotate the point around the old center\n
\t\t\t\tr = Math.sqrt(dx*dx + dy*dy);\n
\t\t\t\ttheta = Math.atan2(dy,dx) + angle;\n
\t\t\t\tdx = r * Math.cos(theta) + oldcx;\n
\t\t\t\tdy = r * Math.sin(theta) + oldcy;\n
\t\t\t\t\n
\t\t\t\t// dx,dy should now hold the actual coordinates of each\n
\t\t\t\t// point after being rotated\n
\t\n
\t\t\t\t// now we want to rotate them around the new center in the reverse direction\n
\t\t\t\tdx -= newcx;\n
\t\t\t\tdy -= newcy;\n
\t\t\t\t\n
\t\t\t\tr = Math.sqrt(dx*dx + dy*dy);\n
\t\t\t\ttheta = Math.atan2(dy,dx) - angle;\n
\t\t\t\t\n
\t\t\t\treturn {\'x\':(r * Math.cos(theta) + newcx)/1,\n
\t\t\t\t\t\'y\':(r * Math.sin(theta) + newcy)/1};\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar list = current_path.pathSegList,\n
\t\t\t\ti = list.numberOfItems;\n
\t\t\twhile (i) {\n
\t\t\t\ti -= 1;\n
\t\t\t\tvar seg = list.getItem(i),\n
\t\t\t\t\ttype = seg.pathSegType;\n
\t\t\t\tif(type == 1) continue;\n
\t\t\t\t\n
\t\t\t\tvar rvals = getRotVals(seg.x,seg.y),\n
\t\t\t\t\tpoints = [rvals.x, rvals.y];\n
\t\t\t\tif(seg.x1 != null && seg.x2 != null) {\n
\t\t\t\t\tc_vals1 = getRotVals(seg.x1, seg.y1);\n
\t\t\t\t\tc_vals2 = getRotVals(seg.x2, seg.y2);\n
\t\t\t\t\tpoints.splice(points.length, 0, c_vals1.x , c_vals1.y, c_vals2.x, c_vals2.y);\n
\t\t\t\t}\n
\t\t\t\treplacePathSeg(type, i, points);\n
\t\t\t} // loop for each point\n
\t\n
\t\t\tbox = canvas.getBBox(current_path);\t\t\t\t\t\t\n
\t\t\tselectedBBoxes[0].x = box.x; selectedBBoxes[0].y = box.y;\n
\t\t\tselectedBBoxes[0].width = box.width; selectedBBoxes[0].height = box.height;\n
\t\t\t\n
\t\t\t// now we must set the new transform to be rotated around the new center\n
\t\t\tvar R_nc = svgroot.createSVGTransform(),\n
\t\t\t\ttlist = canvas.getTransformList(current_path);\n
\t\t\tR_nc.setRotate((angle * 180.0 / Math.PI), newcx, newcy);\n
\t\t\ttlist.replaceItem(R_nc,0);\n
\t\t}\n
\t\t\n
\t\treturn {\n
\t\t\tinit: function() {\n
\t\t\t\tpathFuncs = [0,\'ClosePath\'];\n
\t\t\t\tvar pathFuncsStrs = [\'Moveto\',\'Lineto\',\'CurvetoCubic\',\'CurvetoQuadratic\',\'Arc\',\'LinetoHorizontal\',\'LinetoVertical\',\'CurvetoCubicSmooth\',\'CurvetoQuadraticSmooth\'];\n
\t\t\t\t$.each(pathFuncsStrs,function(i,s){pathFuncs.push(s+\'Abs\');pathFuncs.push(s+\'Rel\');});\n
\t\t\t},\n
\t\t\tgetPath: function() {\n
\t\t\t\treturn path;\n
\t\t\t},\n
\t\t\tmouseDown: function(evt, mouse_target, start_x, start_y) {\n
\t\t\t\tif(current_mode == "path") return;\n
\t\t\t\t\n
\t\t\t\t// TODO: Make sure current_path isn\'t null at this point\n
\t\t\t\tif(!path) return;\n
\t\t\t\t\n
\t\t\t\tpath.storeD();\n
\t\t\t\t\n
\t\t\t\tvar id = evt.target.id;\n
\t\t\t\tif (id.substr(0,14) == "pathpointgrip_") {\n
\t\t\t\t\t// Select this point\n
\t\t\t\t\tvar cur_pt = path.cur_pt = parseInt(id.substr(14));\n
\t\t\t\t\tpath.dragging = [start_x, start_y];\n
\t\t\t\t\tvar seg = path.segs[cur_pt];\n
\t\t\t\t\t\n
\t\t\t\t\t// only clear selection if shift is not pressed (otherwise, add \n
\t\t\t\t\t// node to selection)\n
\t\t\t\t\tif (!evt.shiftKey) {\n
\t\t\t\t\t\tif(path.selected_pts.length <= 1 || !seg.selected) {\n
\t\t\t\t\t\t\tpath.clearSelection();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tpath.addPtsToSelection(cur_pt);\n
\t\t\t\t\t} else if(seg.selected) {\n
\t\t\t\t\t\tpath.removePtFromSelection(cur_pt);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tpath.addPtsToSelection(cur_pt);\n
\t\t\t\t\t}\n
\t\t\t\t} else if(id.indexOf("ctrlpointgrip_") == 0) {\n
\t\t\t\t\tpath.dragging = [start_x, start_y];\n
\t\t\t\t\t\n
\t\t\t\t\tvar parts = id.split(\'_\')[1].split(\'c\');\n
\t\t\t\t\tvar cur_pt = parts[0]-0;\n
\t\t\t\t\tvar ctrl_num = parts[1]-0;\n
\t\t\t\t\tpath.selectPt(cur_pt, ctrl_num);\n
\t\t\t\t}\n
\n
\t\t\t\t// Start selection box\n
\t\t\t\tif(!path.dragging) {\n
\t\t\t\t\tif (rubberBox == null) {\n
\t\t\t\t\t\trubberBox = selectorManager.getRubberBandBox();\n
\t\t\t\t\t}\n
\t\t\t\t\tassignAttributes(rubberBox, {\n
\t\t\t\t\t\t\t\'x\': start_x * current_zoom,\n
\t\t\t\t\t\t\t\'y\': start_y * current_zoom,\n
\t\t\t\t\t\t\t\'width\': 0,\n
\t\t\t\t\t\t\t\'height\': 0,\n
\t\t\t\t\t\t\t\'display\': \'inline\'\n
\t\t\t\t\t}, 100);\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tmouseMove: function(mouse_x, mouse_y) {\n
\t\t\t\thasMoved = true;\n
\t\t\t\tif(current_mode == "path") {\n
\t\t\t\t\tvar line = getElem("path_stretch_line");\n
\t\t\t\t\tif (line) {\n
\t\t\t\t\t\tline.setAttribute("x2", mouse_x);\n
\t\t\t\t\t\tline.setAttribute("y2", mouse_y);\n
\t\t\t\t\t}\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t// if we are dragging a point, let\'s move it\n
\t\t\t\tif (path.dragging) {\n
\t\t\t\t\tvar pt = getPointFromGrip({\n
\t\t\t\t\t\tx: path.dragging[0],\n
\t\t\t\t\t\ty: path.dragging[1]\n
\t\t\t\t\t}, path);\n
\t\t\t\t\tvar mpt = getPointFromGrip({\n
\t\t\t\t\t\tx: mouse_x,\n
\t\t\t\t\t\ty: mouse_y\n
\t\t\t\t\t}, path);\n
\t\t\t\t\tvar diff_x = mpt.x - pt.x;\n
\t\t\t\t\tvar diff_y = mpt.y - pt.y;\n
\t\t\t\t\tpath.dragging = [mouse_x, mouse_y];\n
\t\t\t\t\t\n
\t\t\t\t\tif(path.dragctrl) {\n
\t\t\t\t\t\tpath.moveCtrl(diff_x, diff_y);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tpath.movePts(diff_x, diff_y);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tpath.selected_pts = [];\n
\t\t\t\t\tpath.eachSeg(function(i) {\n
\t\t\t\t\t\tvar seg = this;\n
\t\t\t\t\t\tif(!seg.next && !seg.prev) return;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\tvar item = seg.item;\n
\t\t\t\t\t\tvar rbb = rubberBox.getBBox();\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar pt = getGripPt(seg);\n
\t\t\t\t\t\tvar pt_bb = {\n
\t\t\t\t\t\t\tx: pt.x,\n
\t\t\t\t\t\t\ty: pt.y,\n
\t\t\t\t\t\t\twidth: 0,\n
\t\t\t\t\t\t\theight: 0\n
\t\t\t\t\t\t};\n
\t\t\t\t\t\n
\t\t\t\t\t\tvar sel = Utils.rectsIntersect(rbb, pt_bb);\n
\n
\t\t\t\t\t\tthis.select(sel);\n
\t\t\t\t\t\t//Note that addPtsToSelection is not being run\n
\t\t\t\t\t\tif(sel) path.selected_pts.push(seg.index);\n
\t\t\t\t\t});\n
\n
\t\t\t\t}\n
\t\t\t}, \n
\t\t\tmouseUp: function(evt, element, mouse_x, mouse_y) {\n
\t\t\t\t\n
\t\t\t\t// Create mode\n
\t\t\t\tif(current_mode == "path") {\n
\t\t\t\t\tvar x = mouse_x/current_zoom,\n
\t\t\t\t\t\ty = mouse_y/current_zoom,\n
\t\t\t\t\t\tstretchy = getElem("path_stretch_line");\n
\t\t\t\t\tif (!stretchy) {\n
\t\t\t\t\t\tstretchy = document.createElementNS(svgns, "line");\n
\t\t\t\t\t\tassignAttributes(stretchy, {\n
\t\t\t\t\t\t\t\'id\': "path_stretch_line",\n
\t\t\t\t\t\t\t\'stroke\': "#22C",\n
\t\t\t\t\t\t\t\'stroke-width\': "0.5"\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tstretchy = getElem("selectorParentGroup").appendChild(stretchy);\n
\t\t\t\t\t}\n
\t\t\t\t\tstretchy.setAttribute("display", "inline");\n
\t\t\t\t\t\n
\t\t\t\t\tvar keep = null;\n
\t\t\t\t\t\n
\t\t\t\t\t// if pts array is empty, create path element with M at current point\n
\t\t\t\t\tif (current_path_pts.length == 0) {\n
\t\t\t\t\t\tcurrent_path_pts.push(x);\n
\t\t\t\t\t\tcurrent_path_pts.push(y);\n
\t\t\t\t\t\td_attr = "M" + x + "," + y + " ";\n
\t\t\t\t\t\taddSvgElementFromJson({\n
\t\t\t\t\t\t\t"element": "path",\n
\t\t\t\t\t\t\t"curStyles": true,\n
\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t"d": d_attr,\n
\t\t\t\t\t\t\t\t"id": getNextId(),\n
\t\t\t\t\t\t\t\t"opacity": cur_shape.opacity / 2,\n
\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t// set stretchy line to first point\n
\t\t\t\t\t\tassignAttributes(stretchy, {\n
\t\t\t\t\t\t\t\'x1\': mouse_x,\n
\t\t\t\t\t\t\t\'y1\': mouse_y,\n
\t\t\t\t\t\t\t\'x2\': mouse_x,\n
\t\t\t\t\t\t\t\'y2\': mouse_y\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tvar index = subpath ? path.segs.length : 0;\n
\t\t\t\t\t\taddPointGrip(index, mouse_x, mouse_y);\n
\t\t\t\t\t}\n
\t\t\t\t\telse {\n
\t\t\t\t\t\t// determine if we clicked on an existing point\n
\t\t\t\t\t\tvar i = current_path_pts.length;\n
\t\t\t\t\t\tvar FUZZ = 6/current_zoom;\n
\t\t\t\t\t\tvar clickOnPoint = false;\n
\t\t\t\t\t\twhile(i) {\n
\t\t\t\t\t\t\ti -= 2;\n
\t\t\t\t\t\t\tvar px = current_path_pts[i], py = current_path_pts[i+1];\n
\t\t\t\t\t\t\t// found a matching point\n
\t\t\t\t\t\t\tif ( x >= (px-FUZZ) && x <= (px+FUZZ) && y >= (py-FUZZ) && y <= (py+FUZZ) ) {\n
\t\t\t\t\t\t\t\tclickOnPoint = true;\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// get path element that we are in the process of creating\n
\t\t\t\t\t\tvar id = getId();\n
\t\t\t\t\t\n
\t\t\t\t\t\t// Remove previous path object if previously created\n
\t\t\t\t\t\tif(id in pathData) delete pathData[id];\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar newpath = getElem(id);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar len = current_path_pts.length;\n
\t\t\t\t\t\t// if we clicked on an existing point, then we are done this path, commit it\n
\t\t\t\t\t\t// (i,i+1) are the x,y that were clicked on\n
\t\t\t\t\t\tif (clickOnPoint) {\n
\t\t\t\t\t\t\t// if clicked on any other point but the first OR\n
\t\t\t\t\t\t\t// the first point was clicked on and there are less than 3 points\n
\t\t\t\t\t\t\t// then leave the path open\n
\t\t\t\t\t\t\t// otherwise, close the path\n
\t\t\t\t\t\t\tif (i == 0 && len >= 6) {\n
\t\t\t\t\t\t\t\t// Create end segment\n
\t\t\t\t\t\t\t\tvar abs_x = current_path_pts[0];\n
\t\t\t\t\t\t\t\tvar abs_y = current_path_pts[1];\n
\t\t\t\t\t\t\t\td_attr += [\'L\',abs_x,\',\',abs_y,\'z\'].join(\'\');\n
\t\t\t\t\t\t\t\tnewpath.setAttribute("d", d_attr);\n
\t\t\t\t\t\t\t} else if(len < 3) {\n
\t\t\t\t\t\t\t\tkeep = false;\n
\t\t\t\t\t\t\t\treturn keep;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t$(stretchy).remove();\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// this will signal to commit the path\n
\t\t\t\t\t\t\telement = newpath;\n
\t\t\t\t\t\t\tcurrent_path_pts = [];\n
\t\t\t\t\t\t\tstarted = false;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(subpath) {\n
\t\t\t\t\t\t\t\tif(path.matrix) {\n
\t\t\t\t\t\t\t\t\tremapElement(newpath, {}, path.matrix.inverse());\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\tvar new_d = newpath.getAttribute("d");\n
\t\t\t\t\t\t\t\tvar orig_d = $(path.elem).attr("d");\n
\t\t\t\t\t\t\t\t$(path.elem).attr("d", orig_d + new_d);\n
\t\t\t\t\t\t\t\t$(newpath).remove();\n
\t\t\t\t\t\t\t\tif(path.matrix) {\n
\t\t\t\t\t\t\t\t\trecalcRotatedPath();\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tpath.init();\n
\t\t\t\t\t\t\t\tpathActions.toEditMode(path.elem);\n
\t\t\t\t\t\t\t\tpath.selectPt();\n
\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// else, create a new point, append to pts array, update path element\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\t// Checks if current target or parents are #svgcontent\n
\t\t\t\t\t\t\tif(!$.contains(container, getMouseTarget(evt))) {\n
\t\t\t\t\t\t\t\t// Clicked outside canvas, so don\'t make point\n
\t\t\t\t\t\t\t\tconsole.log("Clicked outside canvas");\n
\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\tvar lastx = current_path_pts[len-2], lasty = current_path_pts[len-1];\n
\n
\t\t\t\t\t\t\tif(evt.shiftKey) { var xya=Utils.snapToAngle(lastx,lasty,x,y); x=xya.x; y=xya.y; }\n
\n
\t\t\t\t\t\t\t// we store absolute values in our path points array for easy checking above\n
\t\t\t\t\t\t\tcurrent_path_pts.push(x);\n
\t\t\t\t\t\t\tcurrent_path_pts.push(y);\n
\t\t\t\t\t\t\td_attr += "L" + round(x) + "," + round(y) + " ";\n
\n
\t\t\t\t\t\t\tnewpath.setAttribute("d", d_attr);\n
\t\n
\t\t\t\t\t\t\t// set stretchy line to latest point\n
\t\t\t\t\t\t\tassignAttributes(stretchy, {\n
\t\t\t\t\t\t\t\t\'x1\': x,\n
\t\t\t\t\t\t\t\t\'y1\': y,\n
\t\t\t\t\t\t\t\t\'x2\': x,\n
\t\t\t\t\t\t\t\t\'y2\': y\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\tvar index = (current_path_pts.length/2 - 1);\n
\t\t\t\t\t\t\tif(subpath) index += path.segs.length;\n
\t\t\t\t\t\t\taddPointGrip(index, x, y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tkeep = true;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\tkeep: keep,\n
\t\t\t\t\t\telement: element\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Edit mode\n
\t\t\t\t\n
\t\t\t\tif (path.dragging) {\n
\t\t\t\t\tvar last_pt = path.cur_pt;\n
\n
\t\t\t\t\tpath.dragging = false;\n
\t\t\t\t\tpath.dragctrl = false;\n
\t\t\t\t\tpath.update();\n
\t\t\t\t\t\n
\t\t\t\t\n
\t\t\t\t\tif(hasMoved) {\n
\t\t\t\t\t\tpath.endChanges("Move path point(s)");\n
\t\t\t\t\t} \n
\t\t\t\t\t\n
\t\t\t\t\tif(!evt.shiftKey && !hasMoved) {\n
\t\t\t\t\t\tpath.selectPt(last_pt);\n
\t\t\t\t\t} \n
\t\t\t\t}\n
\t\t\t\telse if(rubberBox && rubberBox.getAttribute(\'display\') != \'none\') {\n
\t\t\t\t\t// Done with multi-node-select\n
\t\t\t\t\trubberBox.setAttribute("display", "none");\n
\t\t\t\t\t\n
\t\t\t\t\tif(rubberBox.getAttribute(\'width\') <= 2 && rubberBox.getAttribute(\'height\') <= 2) {\n
\t\t\t\t\t\tpathActions.toSelectMode(evt.target);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t// else, move back to select mode\t\n
\t\t\t\t} else {\n
\t\t\t\t\tpathActions.toSelectMode(evt.target);\n
\t\t\t\t}\n
\t\t\t\thasMoved = false;\n
\t\t\t},\n
\t\t\tclearData: function() {\n
\t\t\t\tpathData = {};\n
\t\t\t},\n
\t\t\ttoEditMode: function(element) {\n
\t\t\t\tpath = getPath(element);\n
\t\t\t\tcurrent_mode = "pathedit";\n
\t\t\t\tcanvas.clearSelection();\n
\t\t\t\tpath.show(true).update();\n
\t\t\t\tpath.oldbbox = canvas.getBBox(path.elem);\n
\t\t\t\tsubpath = false;\n
\t\t\t},\n
\t\t\ttoSelectMode: function(elem) {\n
\t\t\t\tvar selPath = (elem == path.elem);\n
\t\t\t\tcurrent_mode = "select";\n
\t\t\t\tpath.show(false);\n
\t\t\t\tcurrent_path = false;\n
\t\t\t\tcanvas.clearSelection();\n
\t\t\t\t\n
\t\t\t\tif(path.matrix) {\n
\t\t\t\t\t// Rotated, so may need to re-calculate the center\n
\t\t\t\t\trecalcRotatedPath();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(selPath) {\n
\t\t\t\t\tcall("selected", [elem]);\n
\t\t\t\t\tcanvas.addToSelection([elem], true);\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\taddSubPath: function(on) {\n
\t\t\t\tif(on) {\n
\t\t\t\t\t// Internally we go into "path" mode, but in the UI it will\n
\t\t\t\t\t// still appear as if in "pathedit" mode.\n
\t\t\t\t\tcurrent_mode = "path";\n
\t\t\t\t\tsubpath = true;\n
\t\t\t\t} else {\n
\t\t\t\t\tpathActions.clear(true);\n
\t\t\t\t\tpathActions.toEditMode(path.elem);\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tselect: function(target) {\n
\t\t\t\tif (current_path == target) {\n
\t\t\t\t\tpathActions.toEditMode(target);\n
\t\t\t\t\tcurrent_mode = "pathedit";\n
\t\t\t\t} // going into pathedit mode\n
\t\t\t\telse {\n
\t\t\t\t\tcurrent_path = target;\n
\t\t\t\t}\t\n
\t\t\t},\n
\t\t\treorient: function() {\n
\t\t\t\tvar elem = selectedElements[0];\n
\t\t\t\tif(!elem) return;\n
\t\t\t\tvar angle = canvas.getRotationAngle(elem);\n
\t\t\t\tif(angle == 0) return;\n
\t\t\t\t\n
\t\t\t\tvar batchCmd = new BatchCommand("Reorient path");\n
\t\t\t\tvar changes = {\n
\t\t\t\t\td: elem.getAttribute(\'d\'),\n
\t\t\t\t\ttransform: elem.getAttribute(\'transform\')\n
\t\t\t\t};\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, changes));\n
\t\t\t\tcanvas.clearSelection();\n
\t\t\t\tthis.resetOrientation(elem);\n
\t\t\t\t\n
\t\t\t\taddCommandToHistory(batchCmd);\n
\n
\t\t\t\t// Set matrix to null\n
\t\t\t\tgetPath(elem).show(false).matrix = null; \n
\n
\t\t\t\tthis.clear();\n
\t\t\n
\t\t\t\tcanvas.addToSelection([elem], true);\n
\t\t\t\tcall("changed", selectedElements);\n
\t\t\t},\n
\t\t\t\n
\t\t\tclear: function(remove) {\n
\t\t\t\tcurrent_path = null;\n
\t\t\t\tif (current_mode == "path" && current_path_pts.length > 0) {\n
\t\t\t\t\tvar elem = getElem(getId());\n
\t\t\t\t\t$(getElem("path_stretch_line")).remove();\n
\t\t\t\t\t$(elem).remove();\n
\t\t\t\t\t$(getElem("pathpointgrip_container")).find(\'*\').attr(\'display\', \'none\');\n
\t\t\t\t\tcurrent_path_pts = [];\n
\t\t\t\t\tstarted = false;\n
\t\t\t\t} else if (current_mode == "pathedit") {\n
\t\t\t\t\tthis.toSelectMode();\n
\t\t\t\t}\n
\t\t\t\tif(path) path.init().show(false);\n
\t\t\t},\n
\t\t\tresetOrientation: function(path) {\n
\t\t\t\tif(path == null || path.nodeName != \'path\') return false;\n
\t\t\t\tvar tlist = canvas.getTransformList(path);\n
\t\t\t\tvar m = transformListToTransform(tlist).matrix;\n
\t\t\t\ttlist.clear();\n
\t\t\t\tpath.removeAttribute("transform");\n
\t\t\t\tvar segList = path.pathSegList;\n
\t\t\t\t\n
\t\t\t\t// Opera/win/non-EN throws an error here.\n
\t\t\t\t// TODO: Find out why!\n
\t\t\t\ttry {\n
\t\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\t} catch(err) {\n
\t\t\t\t\tvar fixed_d = pathActions.convertPath(path);\n
\t\t\t\t\tpath.setAttribute(\'d\', fixed_d);\n
\t\t\t\t\tsegList = path.pathSegList;\n
\t\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\t}\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar seg = segList.getItem(i);\n
\t\t\t\t\tvar type = seg.pathSegType;\n
\t\t\t\t\tif(type == 1) continue;\n
\t\t\t\t\tvar pts = [];\n
\t\t\t\t\t$.each([\'\',1,2], function(j, n) {\n
\t\t\t\t\t\tvar x = seg[\'x\'+n], y = seg[\'y\'+n];\n
\t\t\t\t\t\tif(x && y) {\n
\t\t\t\t\t\t\tvar pt = transformPoint(x, y, m);\n
\t\t\t\t\t\t\tpts.splice(pts.length, 0, pt.x, pt.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\treplacePathSeg(type, i, pts, path);\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tzoomChange: function() {\n
\t\t\t\tif(current_mode == "pathedit") {\n
\t\t\t\t\tpath.update();\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tgetNodePoint: function() {\n
\t\t\t\tvar sel_pt = path.selected_pts.length ? path.selected_pts[0] : 1;\n
\n
\t\t\t\tvar seg = path.segs[sel_pt];\n
\t\t\t\treturn {\n
\t\t\t\t\tx: seg.item.x,\n
\t\t\t\t\ty: seg.item.y,\n
\t\t\t\t\ttype: seg.type\n
\t\t\t\t};\n
\t\t\t}, \n
\t\t\tlinkControlPoints: function(linkPoints) {\n
\t\t\t\tlink_control_pts = linkPoints;\n
\t\t\t},\n
\t\t\tclonePathNode: function() {\n
\t\t\t\tpath.storeD();\n
\t\t\t\t\n
\t\t\t\tvar sel_pts = path.selected_pts;\n
\t\t\t\tvar segs = path.segs;\n
\t\t\t\t\n
\t\t\t\tvar i = sel_pts.length;\n
\t\t\t\tvar nums = [];\n
\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar pt = sel_pts[i];\n
\t\t\t\t\tpath.addSeg(pt);\n
\t\t\t\t\t\n
\t\t\t\t\tnums.push(pt + i);\n
\t\t\t\t\tnums.push(pt + i + 1);\n
\t\t\t\t}\n
\t\t\t\tpath.init().addPtsToSelection(nums);\n
\n
\t\t\t\tpath.endChanges("Clone path node(s)");\n
\t\t\t},\n
\t\t\topencloseSubPath: function() {\n
\t\t\t\tvar sel_pts = path.selected_pts;\n
\t\t\t\t// Only allow one selected node for now\n
\t\t\t\tif(sel_pts.length !== 1) return;\n
\t\t\t\t\n
\t\t\t\tvar elem = path.elem;\n
\t\t\t\tvar list = elem.pathSegList;\n
\n
\t\t\t\tvar len = list.numberOfItems;\n
\n
\t\t\t\tvar index = sel_pts[0];\n
\t\t\t\t\n
\t\t\t\tvar open_pt = null;\n
\t\t\t\tvar start_item = null;\n
\n
\t\t\t\t// Check if subpath is already open\n
\t\t\t\tpath.eachSeg(function(i) {\n
\t\t\t\t\tif(this.type === 2 && i <= index) {\n
\t\t\t\t\t\tstart_item = this.item;\n
\t\t\t\t\t}\n
\t\t\t\t\tif(i <= index) return true;\n
\t\t\t\t\tif(this.type === 2) {\n
\t\t\t\t\t\t// Found M first, so open\n
\t\t\t\t\t\topen_pt = i;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t} else if(this.type === 1) {\n
\t\t\t\t\t\t// Found Z first, so closed\n
\t\t\t\t\t\topen_pt = false;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tif(open_pt == null) {\n
\t\t\t\t\t// Single path, so close last seg\n
\t\t\t\t\topen_pt = path.segs.length - 1;\n
\t\t\t\t}\n
\n
\t\t\t\tif(open_pt !== false) {\n
\t\t\t\t\t// Close this path\n
\t\t\t\t\t\n
\t\t\t\t\t// Create a line going to the previous "M"\n
\t\t\t\t\tvar newseg = elem.createSVGPathSegLinetoAbs(start_item.x, start_item.y);\n
\t\t\t\t\n
\t\t\t\t\tvar closer = elem.createSVGPathSegClosePath();\n
\t\t\t\t\tif(open_pt == path.segs.length - 1) {\n
\t\t\t\t\t\tlist.appendItem(newseg);\n
\t\t\t\t\t\tlist.appendItem(closer);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tinsertItemBefore(elem, closer, open_pt);\n
\t\t\t\t\t\tinsertItemBefore(elem, newseg, open_pt);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tpath.init().selectPt(open_pt+1);\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t\n
\n
\t\t\t\t// M 1,1 L 2,2 L 3,3 L 1,1 z // open at 2,2\n
\t\t\t\t// M 2,2 L 3,3 L 1,1\n
\t\t\t\t\n
\t\t\t\t// M 1,1 L 2,2 L 1,1 z M 4,4 L 5,5 L6,6 L 5,5 z \n
\t\t\t\t// M 1,1 L 2,2 L 1,1 z [M 4,4] L 5,5 L(M)6,6 L 5,5 z \n
\t\t\t\t\n
\t\t\t\tvar seg = path.segs[index];\n
\t\t\t\t\n
\t\t\t\tif(seg.mate) {\n
\t\t\t\t\tlist.removeItem(index); // Removes last "L"\n
\t\t\t\t\tlist.removeItem(index); // Removes the "Z"\n
\t\t\t\t\tpath.init().selectPt(index - 1);\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar last_m, z_seg;\n
\t\t\t\t\n
\t\t\t\t// Find this sub-path\'s closing point and remove\n
\t\t\t\tfor(var i=0; i<list.numberOfItems; i++) {\n
\t\t\t\t\tvar item = list.getItem(i);\n
\n
\t\t\t\t\tif(item.pathSegType === 2) {\n
\t\t\t\t\t\t// Find the preceding M\n
\t\t\t\t\t\tlast_m = i;\n
\t\t\t\t\t} else if(i === index) {\n
\t\t\t\t\t\t// Remove it\n
\t\t\t\t\t\tlist.removeItem(last_m);\n
// \t\t\t\t\t\tindex--;\n
\t\t\t\t\t} else if(item.pathSegType === 1 && index < i) {\n
\t\t\t\t\t\t// Remove the closing seg of this subpath\n
\t\t\t\t\t\tz_seg = i-1;\n
\t\t\t\t\t\tlist.removeItem(i);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar num = (index - last_m) - 1;\n
\t\t\t\t\n
\t\t\t\twhile(num--) {\n
\t\t\t\t\tinsertItemBefore(elem, list.getItem(last_m), z_seg);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar pt = list.getItem(last_m);\n
\t\t\t\t\n
\t\t\t\t// Make this point the new "M"\n
\t\t\t\treplacePathSeg(2, last_m, [pt.x, pt.y]);\n
\t\t\t\t\n
\t\t\t\tvar i = index\n
\t\t\t\t\n
\t\t\t\tpath.init().selectPt(0);\n
\t\t\t},\n
\t\t\tdeletePathNode: function() {\n
\t\t\t\tif(!pathActions.canDeleteNodes) return;\n
\t\t\t\tpath.storeD();\n
\t\t\t\t\n
\t\t\t\tvar sel_pts = path.selected_pts;\n
\t\t\t\tvar i = sel_pts.length;\n
\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar pt = sel_pts[i];\n
\t\t\t\t\tpath.deleteSeg(pt);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Cleanup\n
\t\t\t\tvar cleanup = function() {\n
\t\t\t\t\tvar segList = path.elem.pathSegList;\n
\t\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\t\t\n
\t\t\t\t\tvar remItems = function(pos, count) {\n
\t\t\t\t\t\twhile(count--) {\n
\t\t\t\t\t\t\tsegList.removeItem(pos);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif(len <= 1) return true;\n
\t\t\t\t\t\n
\t\t\t\t\twhile(len--) {\n
\t\t\t\t\t\tvar item = segList.getItem(len);\n
\t\t\t\t\t\tif(item.pathSegType === 1) {\n
\t\t\t\t\t\t\tvar prev = segList.getItem(len-1);\n
\t\t\t\t\t\t\tvar nprev = segList.getItem(len-2);\n
\t\t\t\t\t\t\tif(prev.pathSegType === 2) {\n
\t\t\t\t\t\t\t\tremItems(len-1, 2);\n
\t\t\t\t\t\t\t\tcleanup();\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t} else if(nprev.pathSegType === 2) {\n
\t\t\t\t\t\t\t\tremItems(len-2, 3);\n
\t\t\t\t\t\t\t\tcleanup();\n
\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t} else if(item.pathSegType === 2) {\n
\t\t\t\t\t\t\tif(len > 0) {\n
\t\t\t\t\t\t\t\tvar prev_type = segList.getItem(len-1).pathSegType;\n
\t\t\t\t\t\t\t\t// Path has M M  \n
\t\t\t\t\t\t\t\tif(prev_type === 2) {\n
\t\t\t\t\t\t\t\t\tremItems(len-1, 1);\n
\t\t\t\t\t\t\t\t\tcleanup();\n
\t\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t\t// Entire path ends with Z M \n
\t\t\t\t\t\t\t\t} else if(prev_type === 1 && segList.numberOfItems-1 === len) {\n
\t\t\t\t\t\t\t\t\tremItems(len, 1);\n
\t\t\t\t\t\t\t\t\tcleanup();\n
\t\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\t\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tcleanup();\n
\t\t\t\t\n
\t\t\t\t// Completely delete a path with 1 or 0 segments\n
\t\t\t\tif(path.elem.pathSegList.numberOfItems <= 1) {\n
\t\t\t\t\tpathActions.toSelectMode(path.elem);\n
\t\t\t\t\tcanvas.deleteSelectedElements();\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tpath.init();\n
\t\t\t\t\n
\t\t\t\tpath.clearSelection();\n
\t\t\t\t\n
\t\t\t\t// TODO: Find right way to select point now\n
\t\t\t\t// path.selectPt(sel_pt);\n
\t\t\t\tif(window.opera) { // Opera repaints incorrectly\n
\t\t\t\t\tvar cp = $(path.elem); cp.attr(\'d\',cp.attr(\'d\'));\n
\t\t\t\t}\n
\t\t\t\tpath.endChanges("Delete path node(s)");\n
\t\t\t},\n
\t\t\tsmoothPolylineIntoPath: smoothPolylineIntoPath,\n
\t\t\tsetSegType: function(v) {\n
\t\t\t\tpath.setSegType(v);\n
\t\t\t},\n
\t\t\tmoveNode: function(attr, newValue) {\n
\t\t\t\tvar sel_pts = path.selected_pts;\n
\t\t\t\tif(!sel_pts.length) return;\n
\t\t\t\t\n
\t\t\t\tpath.storeD();\n
\t\t\t\t\n
\t\t\t\t// Get first selected point\n
\t\t\t\tvar seg = path.segs[sel_pts[0]];\n
\t\t\t\tvar diff = {x:0, y:0};\n
\t\t\t\tdiff[attr] = newValue - seg.item[attr];\n
\t\t\t\t\n
\t\t\t\tseg.move(diff.x, diff.y);\n
\t\t\t\tpath.endChanges("Move path point");\n
\t\t\t},\n
\t\t\tfixEnd: function(elem) {\n
\t\t\t\t// Adds an extra segment if the last seg before a Z doesn\'t end\n
\t\t\t\t// at its M point\n
\t\t\t\t// M0,0 L0,100 L100,100 z\n
\t\t\t\tvar segList = elem.pathSegList;\n
\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\tvar last_m;\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar item = segList.getItem(i);\n
\t\t\t\t\tif(item.pathSegType === 2) {\n
\t\t\t\t\t\tlast_m = item;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(item.pathSegType === 1) {\n
\t\t\t\t\t\tvar prev = segList.getItem(i-1);\n
\t\t\t\t\t\tif(prev.x != last_m.x || prev.y != last_m.y) {\n
\t\t\t\t\t\t\t// Add an L segment here\n
\t\t\t\t\t\t\tvar newseg = elem.createSVGPathSegLinetoAbs(last_m.x, last_m.y);\n
\t\t\t\t\t\t\tinsertItemBefore(elem, newseg, i);\n
\t\t\t\t\t\t\t// Can this be done better?\n
\t\t\t\t\t\t\tpathActions.fixEnd(elem);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tif(isWebkit) resetD(elem);\n
\t\t\t},\n
\t\t\t// Convert a path to one with only absolute or relative values\n
\t\t\tconvertPath: function(path, toRel) {\n
\t\t\t\tvar segList = path.pathSegList;\n
\t\t\t\tvar len = segList.numberOfItems;\n
\t\t\t\tvar curx = 0, cury = 0;\n
\t\t\t\tvar d = "";\n
\t\t\t\tvar last_m = null;\n
\t\t\t\t\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar seg = segList.getItem(i);\n
\t\t\t\t\t// if these properties are not in the segment, set them to zero\n
\t\t\t\t\tvar x = seg.x || 0,\n
\t\t\t\t\t\ty = seg.y || 0,\n
\t\t\t\t\t\tx1 = seg.x1 || 0,\n
\t\t\t\t\t\ty1 = seg.y1 || 0,\n
\t\t\t\t\t\tx2 = seg.x2 || 0,\n
\t\t\t\t\t\ty2 = seg.y2 || 0;\n
\t\t\n
\t\t\t\t\tvar type = seg.pathSegType;\n
\t\t\t\t\tvar letter = pathMap[type][\'to\'+(toRel?\'Lower\':\'Upper\')+\'Case\']();\n
\t\t\t\t\t\n
\t\t\t\t\tvar addToD = function(pnts, more, last) {\n
\t\t\t\t\t\tvar str = \'\';\n
\t\t\t\t\t\tvar more = more?\' \'+more.join(\' \'):\'\';\n
\t\t\t\t\t\tvar last = last?shortFloat(last):\'\';\n
\t\t\t\t\t\t$.each(pnts, function(i, pnt) {\n
\t\t\t\t\t\t\tpnts[i] = shortFloat(pnt);\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\td += letter + pnts.join(\' \') + more + last;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tswitch (type) {\n
\t\t\t\t\t\tcase 1: // z,Z closepath (Z/z)\n
\t\t\t\t\t\t\td += "z";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 12: // absolute horizontal line (H)\n
\t\t\t\t\t\t\tx -= curx;\n
\t\t\t\t\t\tcase 13: // relative horizontal line (h)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[x]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 14: // absolute vertical line (V)\n
\t\t\t\t\t\t\ty -= cury;\n
\t\t\t\t\t\tcase 15: // relative vertical line (v)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\ty += cury;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[y]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 2: // absolute move (M)\n
\t\t\t\t\t\tcase 4: // absolute line (L)\n
\t\t\t\t\t\tcase 18: // absolute smooth quad (T)\n
\t\t\t\t\t\t\tx -= curx;\n
\t\t\t\t\t\t\ty -= cury;\n
\t\t\t\t\t\tcase 5: // relative line (l)\n
\t\t\t\t\t\tcase 3: // relative move (m)\n
\t\t\t\t\t\t\t// If the last segment was a "z", this must be relative to \n
\t\t\t\t\t\t\tif(last_m && segList.getItem(i-1).pathSegType === 1 && !toRel) {\n
\t\t\t\t\t\t\t\tcurx = last_m[0];\n
\t\t\t\t\t\t\t\tcury = last_m[1];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tcase 19: // relative smooth quad (t)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx;\n
\t\t\t\t\t\t\t\ty += cury;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tif(type === 3) last_m = [curx, cury];\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\taddToD([[x,y]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 6: // absolute cubic (C)\n
\t\t\t\t\t\t\tx -= curx; x1 -= curx; x2 -= curx;\n
\t\t\t\t\t\t\ty -= cury; y1 -= cury; y2 -= cury;\n
\t\t\t\t\t\tcase 7: // relative cubic (c)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx; x1 += curx; x2 += curx;\n
\t\t\t\t\t\t\t\ty += cury; y1 += cury; y2 += cury;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[x1,y1],[x2,y2],[x,y]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 8: // absolute quad (Q)\n
\t\t\t\t\t\t\tx -= curx; x1 -= curx;\n
\t\t\t\t\t\t\ty -= cury; y1 -= cury;\n
\t\t\t\t\t\tcase 9: // relative quad (q) \n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx; x1 += curx;\n
\t\t\t\t\t\t\t\ty += cury; y1 += cury;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[x1,y1],[x,y]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 10: // absolute elliptical arc (A)\n
\t\t\t\t\t\t\tx -= curx;\n
\t\t\t\t\t\t\ty -= cury;\n
\t\t\t\t\t\tcase 11: // relative elliptical arc (a)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx;\n
\t\t\t\t\t\t\t\ty += cury;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[seg.r1,seg.r2]], [\n
\t\t\t\t\t\t\t\t\tseg.angle,\n
\t\t\t\t\t\t\t\t\t(seg.largeArcFlag ? 1 : 0),\n
\t\t\t\t\t\t\t\t\t(seg.sweepFlag ? 1 : 0)\n
\t\t\t\t\t\t\t\t],[x,y]\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase 16: // absolute smooth cubic (S)\n
\t\t\t\t\t\t\tx -= curx; x2 -= curx;\n
\t\t\t\t\t\t\ty -= cury; y2 -= cury;\n
\t\t\t\t\t\tcase 17: // relative smooth cubic (s)\n
\t\t\t\t\t\t\tif(toRel) {\n
\t\t\t\t\t\t\t\tcurx += x;\n
\t\t\t\t\t\t\t\tcury += y;\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx += curx; x2 += curx;\n
\t\t\t\t\t\t\t\ty += cury; y2 += cury;\n
\t\t\t\t\t\t\t\tcurx = x;\n
\t\t\t\t\t\t\t\tcury = y;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\taddToD([[x2,y2],[x,y]]);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t} // switch on path segment type\n
\t\t\t\t} // for each segment\n
\t\t\t\treturn d;\n
\t\t\t}\n
\t\t}\n
\t}();\n
\n
\tpathActions.init();\n
\tthis.pathActions = pathActions;\n
\t\n
\tvar shortFloat = function(val) {\n
\t\tvar digits = save_options.round_digits;\n
\t\tif(!isNaN(val)) {\n
\t\t\treturn Number(Number(val).toFixed(digits));\n
\t\t} else if($.isArray(val)) {\n
\t\t\treturn shortFloat(val[0]) + \',\' + shortFloat(val[1]);\n
\t\t}\n
\t}\n
\t\n
\t// Convert an element to a path\n
\tthis.convertToPath = function(elem, getBBox, angle) {\n
\t\tif(elem == null) {\n
\t\t\tvar elems = selectedElements;\n
\t\t\t$.each(selectedElements, function(i, elem) {\n
\t\t\t\tif(elem) canvas.convertToPath(elem);\n
\t\t\t});\n
\t\t\treturn;\n
\t\t}\n
\t\t\n
\t\tif(!getBBox) {\n
\t\t\tvar batchCmd = new BatchCommand("Convert element to Path");\n
\t\t}\n
\t\t\n
\t\tvar attrs = getBBox?{}:{\n
\t\t\t"fill": cur_shape.fill,\n
\t\t\t"fill-opacity": cur_shape.fill_opacity,\n
\t\t\t"stroke": cur_shape.stroke,\n
\t\t\t"stroke-width": cur_shape.stroke_width,\n
\t\t\t"stroke-dasharray": cur_shape.stroke_dasharray,\n
\t\t\t"stroke-linejoin": cur_shape.stroke_linejoin,\n
\t\t\t"stroke-linecap": cur_shape.stroke_linecap,\n
\t\t\t"stroke-opacity": cur_shape.stroke_opacity,\n
\t\t\t"opacity": cur_shape.opacity,\n
\t\t\t"visibility":"hidden"\n
\t\t};\n
\t\t\n
\t\t// any attribute on the element not covered by the above\n
\t\t// TODO: make this list global so that we can properly maintain it\n
\t\t// TODO: what about @transform, @clip-rule, @fill-rule, etc?\n
\t\t$.each([\'marker-start\', \'marker-end\', \'marker-mid\', \'filter\', \'clip-path\'], function() {\n
\t\t\tif (elem.getAttribute(this)) {\n
\t\t\t\tattrs[this] = elem.getAttribute(this);\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tvar path = addSvgElementFromJson({\n
\t\t\t"element": "path",\n
\t\t\t"attr": attrs\n
\t\t});\n
\t\t\n
\t\tvar eltrans = elem.getAttribute("transform");\n
\t\tif(eltrans) {\n
\t\t\tpath.setAttribute("transform",eltrans);\n
\t\t}\n
\t\t\n
\t\tvar id = elem.id;\n
\t\tvar parent = elem.parentNode;\n
\t\tif(elem.nextSibling) {\n
\t\t\tparent.insertBefore(path, elem);\n
\t\t} else {\n
\t\t\tparent.appendChild(path);\n
\t\t}\n
\t\t\n
\t\tvar d = \'\';\n
\t\t\n
\t\tvar joinSegs = function(segs) {\n
\t\t\t$.each(segs, function(j, seg) {\n
\t\t\t\tvar l = seg[0], pts = seg[1];\n
\t\t\t\td += l;\n
\t\t\t\tfor(var i=0; i < pts.length; i+=2) {\n
\t\t\t\t\td += (pts[i] +\',\'+pts[i+1]) + \' \';\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\t// Possibly the cubed root of 6, but 1.81 works best\n
\t\tvar num = 1.81;\n
\n
\t\tswitch (elem.tagName) {\n
\t\tcase \'ellipse\':\n
\t\tcase \'circle\':\n
\t\t\tvar a = $(elem).attr([\'rx\', \'ry\', \'cx\', \'cy\']);\n
\t\t\tvar cx = a.cx, cy = a.cy, rx = a.rx, ry = a.ry;\n
\t\t\tif(elem.tagName == \'circle\') {\n
\t\t\t\trx = ry = $(elem).attr(\'r\');\n
\t\t\t}\n
\t\t\n
\t\t\tjoinSegs([\n
\t\t\t\t[\'M\',[(cx-rx),(cy)]],\n
\t\t\t\t[\'C\',[(cx-rx),(cy-ry/num), (cx-rx/num),(cy-ry), (cx),(cy-ry)]],\n
\t\t\t\t[\'C\',[(cx+rx/num),(cy-ry), (cx+rx),(cy-ry/num), (cx+rx),(cy)]],\n
\t\t\t\t[\'C\',[(cx+rx),(cy+ry/num), (cx+rx/num),(cy+ry), (cx),(cy+ry)]],\n
\t\t\t\t[\'C\',[(cx-rx/num),(cy+ry), (cx-rx),(cy+ry/num), (cx-rx),(cy)]],\n
\t\t\t\t[\'Z\',[]]\n
\t\t\t]);\n
\t\t\tbreak;\n
\t\tcase \'path\':\n
\t\t\td = elem.getAttribute(\'d\');\n
\t\t\tbreak;\n
\t\tcase \'line\':\n
\t\t\tvar a = $(elem).attr(["x1", "y1", "x2", "y2"]);\n
\t\t\td = "M"+a.x1+","+a.y1+"L"+a.x2+","+a.y2;\n
\t\t\tbreak;\n
\t\tcase \'polyline\':\n
\t\tcase \'polygon\':\n
\t\t\td = "M" + elem.getAttribute(\'points\');\n
\t\t\tbreak;\n
\t\tcase \'rect\':\n
\t\t\tvar r = $(elem).attr([\'rx\', \'ry\']);\n
\t\t\tvar rx = r.rx, ry = r.ry;\n
\t\t\tvar b = elem.getBBox();\n
\t\t\tvar x = b.x, y = b.y, w = b.width, h = b.height;\n
\t\t\tvar num = 4-num; // Why? Because!\n
\t\t\t\n
\t\t\tif(!rx && !ry) {\n
\t\t\t\t// Regular rect\n
\t\t\t\tjoinSegs([\n
\t\t\t\t\t[\'M\',[x, y]],\n
\t\t\t\t\t[\'L\',[x+w, y]],\n
\t\t\t\t\t[\'L\',[x+w, y+h]],\n
\t\t\t\t\t[\'L\',[x, y+h]],\n
\t\t\t\t\t[\'L\',[x, y]],\n
\t\t\t\t\t[\'Z\',[]]\n
\t\t\t\t]);\n
\t\t\t} else {\n
\t\t\t\tjoinSegs([\n
\t\t\t\t\t[\'M\',[x, y+ry]],\n
\t\t\t\t\t[\'C\',[x,y+ry/num, x+rx/num,y, x+rx,y]],\n
\t\t\t\t\t[\'L\',[x+w-rx, y]],\n
\t\t\t\t\t[\'C\',[x+w-rx/num,y, x+w,y+ry/num, x+w,y+ry]],\n
\t\t\t\t\t[\'L\',[x+w, y+h-ry]],\n
\t\t\t\t\t[\'C\',[x+w, y+h-ry/num, x+w-rx/num,y+h, x+w-rx,y+h]],\n
\t\t\t\t\t[\'L\',[x+rx, y+h]],\n
\t\t\t\t\t[\'C\',[x+rx/num, y+h, x,y+h-ry/num, x,y+h-ry]],\n
\t\t\t\t\t[\'L\',[x, y+ry]],\n
\t\t\t\t\t[\'Z\',[]]\n
\t\t\t\t]);\n
\t\t\t}\n
\t\t\tbreak;\n
\t\tdefault:\n
\t\t\tpath.parentNode.removeChild(path);\n
\t\t\tbreak;\n
\t\t}\n
\t\t\n
\t\tif(d) {\n
\t\t\tpath.setAttribute(\'d\',d);\n
\t\t}\n
\t\t\n
\t\tif(!getBBox) {\n
\t\t\t// Replace the current element with the converted one\n
\t\t\t\n
\t\t\t// Reorient if it has a matrix\n
\t\t\tif(eltrans) {\n
\t\t\t\tvar tlist = canvas.getTransformList(path);\n
\t\t\t\tif(hasMatrixTransform(tlist)) {\n
\t\t\t\t\tpathActions.resetOrientation(path);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tbatchCmd.addSubCommand(new RemoveElementCommand(elem, parent));\n
\t\t\tbatchCmd.addSubCommand(new InsertElementCommand(path));\n
\n
\t\t\tcanvas.clearSelection();\n
\t\t\telem.parentNode.removeChild(elem)\n
\t\t\tpath.setAttribute(\'id\', id);\n
\t\t\tpath.removeAttribute("visibility");\n
\t\t\tcanvas.addToSelection([path], true);\n
\t\t\t\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\t\n
\t\t} else {\n
\t\t\t// Get the correct BBox of the new path, then discard it\n
\t\t\tpathActions.resetOrientation(path);\n
\t\t\tvar bb = false;\n
\t\t\ttry {\n
\t\t\t\tbb = path.getBBox();\n
\t\t\t} catch(e) {\n
\t\t\t\t// Firefox fails\n
\t\t\t}\n
\t\t\tpath.parentNode.removeChild(path);\n
\t\t\treturn bb;\n
\t\t}\n
\t}\n
\t\n
\n
\n
\t// - in create mode, the element\'s opacity is set properly, we create an InsertElementCommand\n
\t//   and store it on the Undo stack\n
\t// - in move/resize mode, the element\'s attributes which were affected by the move/resize are\n
\t//   identified, a ChangeElementCommand is created and stored on the stack for those attrs\n
\t//   this is done in when we recalculate the selected dimensions()\n
\n
// public functions\n
\n
\t// Group: Serialization\n
\n
\tthis.open = function() {\n
\t\t// Nothing by default, handled by optional widget/extension\n
\t};\n
\n
\t// Function: save\n
\t// Serializes the current drawing into SVG XML text and returns it to the \'saved\' handler.\n
\t// This function also includes the XML prolog.  Clients of the SvgCanvas bind their save\n
\t// function to the \'saved\' event.\n
\t//\n
\t// Returns: \n
\t// Nothing\n
\tthis.save = function(opts) {\n
\t\t// remove the selected outline before serializing\n
\t\tthis.clearSelection();\n
\t\t// Update save options if provided\n
\t\tif(opts) $.extend(save_options, opts);\n
\t\tsave_options.apply = true;\n
\t\t\n
\t\t// no need for doctype, see http://jwatt.org/svg/authoring/#doctype-declaration\n
\t\tvar str = svgCanvasToString();\n
\t\tcall("saved", str);\n
\t};\n
\n
\tthis.rasterExport = function() {\n
\t\t// remove the selected outline before serializing\n
\t\tthis.clearSelection();\n
\t\t\n
\t\t// Check for known CanVG issues \n
\t\tvar issues = [];\n
\t\t\n
\t\t// Selector and notice\n
\t\tvar issue_list = {\n
\t\t\t\'feGaussianBlur\': uiStrings.exportNoBlur,\n
\t\t\t\'image\': uiStrings.exportNoImage,\n
\t\t\t\'foreignObject\': uiStrings.exportNoforeignObject,\n
\t\t\t\'[stroke-dasharray]\': uiStrings.exportNoDashArray\n
\t\t};\n
\t\tvar content = $(svgcontent);\n
\t\t\n
\t\t// Add font/text check if Canvas Text API is not implemented\n
\t\tif(!("font" in $(\'<canvas>\')[0].getContext(\'2d\'))) {\n
\t\t\tissue_list[\'text\'] = uiStrings.exportNoText;\n
\t\t}\n
\t\t\n
\t\t$.each(issue_list, function(sel, descr) {\n
\t\t\tif(content.find(sel).length) {\n
\t\t\t\tissues.push(descr);\n
\t\t\t}\n
\t\t});\n
\n
\t\tvar str = svgCanvasToString();\n
\t\tcall("exported", {svg: str, issues: issues});\n
\t};\n
\t\n
\t// Walks the tree and executes the callback on each element in a top-down fashion\n
\tvar walkTree = function(elem, cbFn){\n
\t\tif (elem && elem.nodeType == 1) {\n
\t\t\tcbFn(elem);\n
\t\t\tvar i = elem.childNodes.length;\n
\t\t\twhile (i--) {\n
\t\t\t\twalkTree(elem.childNodes.item(i), cbFn);\n
\t\t\t}\n
\t\t}\n
\t};\n
\t// Walks the tree and executes the callback on each element in a depth-first fashion\n
\tvar walkTreePost = function(elem, cbFn) {\n
\t\tif (elem && elem.nodeType == 1) {\n
\t\t\tvar i = elem.childNodes.length;\n
\t\t\twhile (i--) {\n
\t\t\t\twalkTree(elem.childNodes.item(i), cbFn);\n
\t\t\t}\n
\t\t\tcbFn(elem);\n
\t\t}\n
\t};\n
\t\n
\t// Function: getSvgString\n
\t// Returns the current drawing as raw SVG XML text.\n
\t//\n
\t// Returns:\n
\t// The current drawing as raw SVG XML text.\n
\tthis.getSvgString = function() {\n
\t\tsave_options.apply = false;\n
\t\treturn svgCanvasToString();\n
\t};\n
\n
\t//function randomizeIds\n
\t// This function determines whether to add a nonce to the prefix, when\n
\t// generating IDs in SVG-Edit\n
\t// \n
\t//  Parameters:\n
\t//   an opional boolean, which, if true, adds a nonce to the prefix. Thus\n
\t//     svgCanvas.randomizeIds()  <==> svgCanvas.randomizeIds(true)\n
\t//\n
\t// if you\'re controlling SVG-Edit externally, and want randomized IDs, call\n
\t// this BEFORE calling svgCanvas.setSvgString\n
\t//\n
\tthis.randomizeIds = function() {\n
\t   if (arguments.length > 0 && arguments[0] == false) {\n
\t     randomize_ids = false;\n
\t     if (extensions["Arrows"])  call("unsetarrownonce") ;\n
\t   } else {\n
\t     randomize_ids = true;\n
\t     if (!svgcontent.getAttributeNS(se_ns, \'nonce\')) {\n
        \t\tsvgcontent.setAttributeNS(se_ns, \'se:nonce\', nonce); \n
        \t\tif (extensions["Arrows"])  call("setarrownonce", nonce) ;\n
\t     }\n
\t   }\n
\t}\n
\n
\t//   \n
\t// Function: setSvgString\n
\t// This function sets the current drawing as the input SVG XML.\n
\t//\n
\t// Parameters:\n
\t// xmlString - The SVG as XML text.\n
\t//\n
\t// Returns:\n
\t// This function returns false if the set was unsuccessful, true otherwise.\n
\tthis.setSvgString = function(xmlString) {\n
\t\ttry {\n
\t\t\t// convert string into XML document\n
\t\t\tvar newDoc = Utils.text2xml(xmlString);\n
\t\t\t// run it through our sanitizer to remove anything we do not support\n
\t        sanitizeSvg(newDoc.documentElement);\n
\n
\t\t\tvar batchCmd = new BatchCommand("Change Source");\n
\n
        \t// remove old svg document\n
    \t    var oldzoom = svgroot.removeChild(svgcontent);\n
\t\t\tbatchCmd.addSubCommand(new RemoveElementCommand(oldzoom, svgroot));\n
        \n
    \t    // set new svg document\n
        \tsvgcontent = svgroot.appendChild(svgdoc.importNode(newDoc.documentElement, true));\n
        \t// retrieve or set the nonce\n
        \tn = svgcontent.getAttributeNS(se_ns, \'nonce\');\n
        \tif (n) {\n
        \t\trandomize_ids = true;\n
        \t\tnonce = n;\n
        \t\tif (extensions["Arrows"])  call("setarrownonce", n) ;\n
        \t} else if (randomize_ids) {\n
        \t\tsvgcontent.setAttributeNS(xmlnsns, \'xmlns:se\', se_ns);\n
        \t\tsvgcontent.setAttributeNS(se_ns, \'se:nonce\', nonce); \n
        \t\tif (extensions["Arrows"])  call("setarrownonce", nonce) ;\n
         \t}         \n
        \t// change image href vals if possible\n
        \t$(svgcontent).find(\'image\').each(function() {\n
        \t\tvar image = this;\n
        \t\tpreventClickDefault(image);\n
        \t\tvar val = this.getAttributeNS(xlinkns, "href");\n
\t\t\t\tif(val.indexOf(\'data:\') === 0) {\n
\t\t\t\t\t// Check if an SVG-edit data URI\n
\t\t\t\t\tvar m = val.match(/svgedit_url=(.*?);/);\n
\t\t\t\t\tif(m) {\n
\t\t\t\t\t\tvar url = decodeURIComponent(m[1]);\n
\t\t\t\t\t\t$(new Image()).load(function() {\n
\t\t\t\t\t\t\timage.setAttributeNS(xlinkns,\'xlink:href\',url);\n
\t\t\t\t\t\t}).attr(\'src\',url);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
        \t\t// Add to encodableImages if it loads\n
        \t\tcanvas.embedImage(val);\n
        \t});\n
        \t\n
        \t// convert gradients with userSpaceOnUse to objectBoundingBox\n
        \t$(svgcontent).find(\'linearGradient, radialGradient\').each(function() {\n
        \t\tvar grad = this;\n
        \t\tif($(grad).attr(\'gradientUnits\') === \'userSpaceOnUse\') {\n
        \t\t\t// TODO: Support more than one element with this ref by duplicating parent grad\n
        \t\t\tvar elems = $(svgcontent).find(\'[fill=url(#\' + grad.id + \')],[stroke=url(#\' + grad.id + \')]\');\n
        \t\t\tif(!elems.length) return;\n
        \t\t\t\n
        \t\t\t// get object\'s bounding box\n
        \t\t\tvar bb = elems[0].getBBox();\n
        \t\t\t\n
        \t\t\tif(grad.tagName === \'linearGradient\') {\n
\t\t\t\t\t\tvar g_coords = $(grad).attr([\'x1\', \'y1\', \'x2\', \'y2\']);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t$(grad).attr({\n
\t\t\t\t\t\t\tx1: (g_coords.x1 - bb.x) / bb.width,\n
\t\t\t\t\t\t\ty1: (g_coords.y1 - bb.y) / bb.height,\n
\t\t\t\t\t\t\tx2: (g_coords.x2 - bb.x) / bb.width,\n
\t\t\t\t\t\t\ty2: (g_coords.y1 - bb.y) / bb.height\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t\n
\t        \t\t\tgrad.removeAttribute(\'gradientUnits\');\n
        \t\t\t} else {\n
        \t\t\t\t// Note: radialGradient elements cannot be easily converted \n
        \t\t\t\t// because userSpaceOnUse will keep circular gradients, while\n
        \t\t\t\t// objectBoundingBox will x/y scale the gradient according to\n
        \t\t\t\t// its bbox. \n
        \t\t\t\t\n
        \t\t\t\t// For now we\'ll do nothing, though we should probably have\n
        \t\t\t\t// the gradient be updated as the element is moved, as \n
        \t\t\t\t// inkscape/illustrator do.\n
        \t\t\t\n
//         \t\t\t\tvar g_coords = $(grad).attr([\'cx\', \'cy\', \'r\']);\n
//         \t\t\t\t\n
// \t\t\t\t\t\t$(grad).attr({\n
// \t\t\t\t\t\t\tcx: (g_coords.cx - bb.x) / bb.width,\n
// \t\t\t\t\t\t\tcy: (g_coords.cy - bb.y) / bb.height,\n
// \t\t\t\t\t\t\tr: g_coords.r\n
// \t\t\t\t\t\t});\n
// \t\t\t\t\t\t\n
// \t        \t\t\tgrad.removeAttribute(\'gradientUnits\');\n
        \t\t\t}\n
        \t\t\t\n
\n
        \t\t}\n
        \t});\n
        \t\n
        \t// Fix XML for Opera/Win/Non-EN\n
\t\t\tif(!support.goodDecimals) {\n
\t\t\t\tcanvas.fixOperaXML(svgcontent, newDoc.documentElement);\n
\t\t\t}\n
\t\t\t\n
\t\t\t// recalculate dimensions on the top-level children so that unnecessary transforms\n
\t\t\t// are removed\n
\t\t\twalkTreePost(svgcontent, function(n){try{recalculateDimensions(n)}catch(e){console.log(e)}});\n
\t\t\t\n
\t\t\tvar content = $(svgcontent);\n
        \t\n
\t\t\tvar attrs = {\n
\t\t\t\tid: \'svgcontent\',\n
\t\t\t\toverflow: curConfig.show_outside_canvas?\'visible\':\'hidden\'\n
\t\t\t};\n
\t\t\t\n
\t\t\t// determine proper size\n
\t\t\tif (content.attr("viewBox")) {\n
\t\t\t\tvar vb = content.attr("viewBox").split(\' \');\n
\t\t\t\tattrs.width = vb[2];\n
\t\t\t\tattrs.height = vb[3];\n
\t\t\t}\n
\t\t\t// handle content that doesn\'t have a viewBox\n
\t\t\telse {\n
\t\t\t\t$.each([\'width\', \'height\'], function(i, dim) {\n
\t\t\t\t\t// Set to 100 if not given\n
\t\t\t\t\tvar val = content.attr(dim) || 100;\n
\n
\t\t\t\t\tif((val+\'\').substr(-1) === "%") {\n
\t\t\t\t\t\t// Use user units if percentage given\n
\t\t\t\t\t\tattrs[dim] = parseInt(val);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tattrs[dim] = convertToNum(dim, val);\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\tcontent.attr(attrs);\n
\t\t\tthis.contentW = attrs[\'width\'];\n
\t\t\tthis.contentH = attrs[\'height\'];\n
\t\t\t\n
\t\t\tbatchCmd.addSubCommand(new InsertElementCommand(svgcontent));\n
\t\t\t// update root to the correct size\n
\t\t\tvar changes = content.attr(["width", "height"]);\n
\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(svgroot, changes));\n
\t\t\t\n
\t\t\t// reset zoom\n
\t\t\tcurrent_zoom = 1;\n
\t\t\t\n
\t\t\t// identify layers\n
\t\t\tidentifyLayers();\n
\t\t\t\n
\t\t\t// reset transform lists\n
\t\t\tsvgTransformLists = {};\n
\t\t\tcanvas.clearSelection();\n
\t\t\tpathActions.clearData();\n
\t\t\tsvgroot.appendChild(selectorManager.selectorParentGroup);\n
\t\t\t\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcall("changed", [svgcontent]);\n
\t\t} catch(e) {\n
\t\t\tconsole.log(e);\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\treturn true;\n
\t};\n
\n
\t// Function: importSvgString\n
\t// This function imports the input SVG XML into the current layer in the drawing\n
\t//\n
\t// Parameters:\n
\t// xmlString - The SVG as XML text.\n
\t//\n
\t// Returns:\n
\t// This function returns false if the import was unsuccessful, true otherwise.\n
\n
\t// TODO: properly handle if namespace is introduced by imported content (must add to svgcontent\n
\t//       and update all prefixes in the imported node)\n
\t// TODO: properly handle recalculating dimensions, recalculateDimensions() doesn\'t handle\n
\t//       arbitrary transform lists, but makes some assumptions about how the transform list \n
\t//       was obtained\n
\t// TODO: import should happen in top-left of current zoomed viewport\t\n
\t// TODO: create a new layer for the imported SVG\n
\tthis.importSvgString = function(xmlString) {\n
\t\ttry {\n
\t\t\t// convert string into XML document\n
\t\t\tvar newDoc = Utils.text2xml(xmlString);\n
\t\t\t// run it through our sanitizer to remove anything we do not support\n
\t        sanitizeSvg(newDoc.documentElement);\n
\n
\t\t\tvar batchCmd = new BatchCommand("Change Source");\n
\n
\t\t\t// import new svg document into our document\n
\t\t\tvar importedNode = svgdoc.importNode(newDoc.documentElement, true);\n
        \n
\t\t\tif (current_layer) {\n
\t\t\t\t// TODO: properly handle if width/height are not specified or if in percentages\n
\t\t\t\t// TODO: properly handle if width/height are in units (px, etc)\n
\t\t\t\tvar innerw = importedNode.getAttribute("width"),\n
\t\t\t\t\tinnerh = importedNode.getAttribute("height"),\n
\t\t\t\t\tinnervb = importedNode.getAttribute("viewBox"),\n
\t\t\t\t\t// if no explicit viewbox, create one out of the width and height\n
\t\t\t\t\tvb = innervb ? innervb.split(" ") : [0,0,innerw,innerh];\n
\t\t\t\tfor (var j = 0; j < 4; ++j)\n
\t\t\t\t\tvb[j] = Number(vb[j]);\n
\n
\t\t\t\t// TODO: properly handle preserveAspectRatio\n
\t\t\t\tvar canvasw = Number(svgcontent.getAttribute("width")),\n
\t\t\t\t\tcanvash = Number(svgcontent.getAttribute("height"));\n
\t\t\t\t// imported content should be 1/3 of the canvas on its largest dimension\n
\t\t\t\tif (innerh > innerw) {\n
\t\t\t\t\tvar ts = "scale(" + (canvash/3)/vb[3] + ")";\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tvar ts = "scale(" + (canvash/3)/vb[2] + ")";\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Hack to make recalculateDimensions understand how to scale\n
\t\t\t\tts = "translate(0) " + ts + " translate(0)";\n
\t\t\t\t\n
\t\t\t\t// TODO: Find way to add this in a recalculateDimensions-parsable way\n
// \t\t\t\tif (vb[0] != 0 || vb[1] != 0)\n
// \t\t\t\t\tts = "translate(" + (-vb[0]) + "," + (-vb[1]) + ") " + ts;\n
\n
\t\t\t\t// add all children of the imported <svg> to the <g> we create\n
\t\t\t\tvar g = svgdoc.createElementNS(svgns, "g");\n
\t\t\t\twhile (importedNode.hasChildNodes())\n
\t\t\t\t\tg.appendChild(importedNode.firstChild);\n
\t\t\t\tif (ts)\n
\t\t\t\t\tg.setAttribute("transform", ts);\n
    \t    \t\t\n
\t\t\t\t// now ensure each element has a unique ID\n
\t\t\t\tvar ids = {};\n
\t\t\t\twalkTree(g, function(n) {\n
\t\t\t\t\t// if it\'s an element node\n
\t\t\t\t\tif (n.nodeType == 1) {\n
\t\t\t\t\t\t// and the element has an ID\n
\t\t\t\t\t\tif (n.id) {\n
\t\t\t\t\t\t\t// and we haven\'t tracked this ID yet\n
\t    \t    \t\t\tif (!(n.id in ids)) {\n
    \t\t    \t\t\t\t// add this id to our map\n
\t\t\t    \t    \t\tids[n.id] = {elem:null, attrs:[], hrefs:[]};\n
\t    \t\t\t    \t}\n
\t    \t\t\t    \tids[n.id]["elem"] = n;\n
\t    \t    \t\t}\n
\t    \t    \t\t\n
\t    \t    \t\t// now search for all attributes on this element that might refer\n
\t    \t    \t\t// to other elements\n
\t\t\t\t\t\t$.each(["clip-path", "fill", "filter", "marker-end", "marker-mid", "marker-start", "mask", "stroke"],function(i,attr) {\n
\t\t\t\t\t\t\tvar attrnode = n.getAttributeNode(attr);\n
\t\t\t\t\t\t\tif (attrnode) {\n
\t\t\t\t\t\t\t\t// the incoming file has been sanitized, so we should be able to safely just strip off the leading #\n
\t\t\t\t\t\t\t\tvar url = getUrlFromAttr(attrnode.value),\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t\trefid = url ? url.substr(1) : null;\n
\t\t\t\t\t\t\t\tif (refid) {\n
\t\t\t\t\t\t\t\t\tif (!(refid in ids)) {\n
\t\t\t\t\t\t\t\t\t\t// add this id to our map\n
\t\t\t\t\t\t\t\t\t\tids[refid] = {elem:null, attrs:[], hrefs:[]};\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\tids[refid]["attrs"].push(attrnode);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// check xlink:href now\n
\t\t\t\t\t\tvar href = n.getAttributeNS(xlinkns,"href");\n
\t\t\t\t\t\t// TODO: what if an <image> or <a> element refers to an element internally?\n
\t\t\t\t\t\tif(href && \n
\t\t\t   \t\t\t\t$.inArray(n.nodeName, ["filter", "linearGradient", "pattern", \n
\t\t\t   \t\t\t\t\t\t\t "radialGradient", "textPath", "use"]) != -1)\n
\t\t\t\t\t\t{\n
\t\t\t\t\t\t\tvar refid = href.substr(1);\n
\t\t\t\t\t\t\tif (!(refid in ids)) {\n
\t\t\t\t\t\t\t\t// add this id to our map\n
\t\t\t\t\t\t\t\tids[refid] = {elem:null, attrs:[], hrefs:[]};\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tids[refid]["hrefs"].push(n);\n
\t\t\t\t\t\t}\t\t\t\t\t\t\n
\t    \t    \t}\n
    \t    \t});\n
    \t    \t\n
    \t    \t// in ids, we now have a map of ids, elements and attributes, let\'s re-identify\n
    \t    \tfor (var oldid in ids) {\n
    \t    \t\tvar elem = ids[oldid]["elem"];\n
    \t    \t\tif (elem) {\n
    \t    \t\t\tvar newid = getNextId();\n
\t\t\t\t\t\t// manually increment obj_num because our cloned elements are not in the DOM yet\n
\t\t\t\t\t\tobj_num++;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// assign element its new id\n
    \t    \t\t\telem.id = newid;\n
    \t    \t\t\t\n
    \t    \t\t\t// remap all url() attributes\n
    \t    \t\t\tvar attrs = ids[oldid]["attrs"];\n
    \t    \t\t\tvar j = attrs.length;\n
    \t    \t\t\twhile (j--) {\n
    \t    \t\t\t\tvar attr = attrs[j];\n
    \t    \t\t\t\tattr.ownerElement.setAttribute(attr.name, "url(#" + newid + ")");\n
    \t    \t\t\t}\n
    \t    \t\t\t\n
    \t    \t\t\t// remap all href attributes\n
    \t    \t\t\tvar hreffers = ids[oldid]["hrefs"];\n
    \t    \t\t\tvar k = hreffers.length;\n
    \t    \t\t\twhile (k--) {\n
    \t    \t\t\t\tvar hreffer = hreffers[k];\n
    \t    \t\t\t\threffer.setAttributeNS(xlinkns, "xlink:href", "#"+newid);\n
    \t    \t\t\t}\n
    \t    \t\t}\n
    \t    \t}\n
    \t    \t\n
    \t    \t// now give the g itself a new id\n
    \t    \t\n
\t\t\t\tg.id = getNextId();\n
\t\t\t\t// manually increment obj_num because our cloned elements are not in the DOM yet\n
\t\t\t\tobj_num++;\n
\t\t\t\t\n
    \t    \tcurrent_layer.appendChild(g);\n
    \t    }\n
    \t    \n
        \t// change image href vals if possible\n
//        \t$(svgcontent).find(\'image\').each(function() {\n
//        \t\tvar image = this;\n
//        \t\tpreventClickDefault(image);\n
//        \t\tvar val = this.getAttributeNS(xlinkns, "href");\n
//\t\t\t\tif(val.indexOf(\'data:\') === 0) {\n
//\t\t\t\t\t// Check if an SVG-edit data URI\n
//\t\t\t\t\tvar m = val.match(/svgedit_url=(.*?);/);\n
//\t\t\t\t\tif(m) {\n
//\t\t\t\t\t\tvar url = decodeURIComponent(m[1]);\n
//\t\t\t\t\t\t$(new Image()).load(function() {\n
//\t\t\t\t\t\t\timage.setAttributeNS(xlinkns,\'xlink:href\',url);\n
//\t\t\t\t\t\t}).attr(\'src\',url);\n
//\t\t\t\t\t}\n
//\t\t\t\t}\n
//        \t\t// Add to encodableImages if it loads\n
//        \t\tcanvas.embedImage(val);\n
//        \t});\n
        \t\n
        \t// Fix XML for Opera/Win/Non-EN\n
\t\t\tif(!support.goodDecimals) {\n
\t\t\t\tcanvas.fixOperaXML(svgcontent, importedNode);\n
\t\t\t}\n
\t\t\t\n
\t\t\t// recalculate dimensions on the top-level children so that unnecessary transforms\n
\t\t\t// are removed\n
\t\t\twalkTreePost(svgcontent, function(n){try{recalculateDimensions(n)}catch(e){console.log(e)}});\n
\t\t\t\n
\t\t\t\n
\t\t\tbatchCmd.addSubCommand(new InsertElementCommand(svgcontent));\n
\n
\t\t\t// reset zoom - TODO: why?\n
//\t\t\tcurrent_zoom = 1;\n
\t\t\t\n
\t\t\t// identify layers\n
//\t\t\tidentifyLayers();\n
\t\t\t\n
\t\t\t// reset transform lists\n
\t\t\tsvgTransformLists = {};\n
\t\t\tcanvas.clearSelection();\n
\t\t\t\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcall("changed", [svgcontent]);\n
\t\t} catch(e) {\n
\t\t\tconsole.log(e);\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\treturn true;\n
\t};\n
\t\n
\t// Layer API Functions\n
\n
\t// Group: Layers\n
\n
\tvar identifyLayers = function() {\n
\t\tall_layers = [];\n
\t\tvar numchildren = svgcontent.childNodes.length;\n
\t\t// loop through all children of svgcontent\n
\t\tvar orphans = [], layernames = [];\n
\t\tfor (var i = 0; i < numchildren; ++i) {\n
\t\t\tvar child = svgcontent.childNodes.item(i);\n
\t\t\t// for each g, find its layer name\n
\t\t\tif (child && child.nodeType == 1) {\n
\t\t\t\tif (child.tagName == "g") {\n
\t\t\t\t\tvar name = $("title",child).text();\n
\t\t\t\t\t// store layer and name in global variable\n
\t\t\t\t\tif (name) {\n
\t\t\t\t\t\tlayernames.push(name);\n
\t\t\t\t\t\tall_layers.push( [name,child] );\n
\t\t\t\t\t\tcurrent_layer = child;\n
\t\t\t\t\t\twalkTree(child, function(e){e.setAttribute("style", "pointer-events:inherit");});\n
\t\t\t\t\t\tcurrent_layer.setAttribute("style", "pointer-events:none");\n
\t\t\t\t\t}\n
\t\t\t\t\t// if group did not have a name, it is an orphan\n
\t\t\t\t\telse {\n
\t\t\t\t\t\torphans.push(child);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t// if child has a bbox (i.e. not a <title> or <defs> element), then it is an orphan\n
\t\t\t\telse if(canvas.getBBox(child) && child.nodeName != \'defs\') { // Opera returns a BBox for defs\n
\t\t\t\t\tvar bb = canvas.getBBox(child);\n
\t\t\t\t\torphans.push(child);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t// create a new layer and add all the orphans to it\n
\t\tif (orphans.length > 0) {\n
\t\t\tvar i = 1;\n
\t\t\twhile ($.inArray(("Layer " + i), layernames) != -1) { i++; }\n
\t\t\tvar newname = "Layer " + i;\n
\t\t\tcurrent_layer = svgdoc.createElementNS(svgns, "g");\n
\t\t\tvar layer_title = svgdoc.createElementNS(svgns, "title");\n
\t\t\tlayer_title.textContent = newname;\n
\t\t\tcurrent_layer.appendChild(layer_title);\n
\t\t\tfor (var j = 0; j < orphans.length; ++j) {\n
\t\t\t\tcurrent_layer.appendChild(orphans[j]);\n
\t\t\t}\n
\t\t\tcurrent_layer = svgcontent.appendChild(current_layer);\n
\t\t\tall_layers.push( [newname, current_layer] );\n
\t\t}\n
\t\twalkTree(current_layer, function(e){e.setAttribute("style","pointer-events:inherit");});\n
\t\tcurrent_layer.setAttribute("style","pointer-events:all");\n
\t};\n
\t\n
\t// Function: createLayer\n
\t// Creates a new top-level layer in the drawing with the given name, sets the current layer \n
\t// to it, and then clears the selection  This function then calls the \'changed\' handler.\n
\t// This is an undoable action.\n
\t//\n
\t// Parameters:\n
\t// name - The given name\n
\tthis.createLayer = function(name) {\n
\t\tvar batchCmd = new BatchCommand("Create Layer");\n
\t\tvar new_layer = svgdoc.createElementNS(svgns, "g");\n
\t\tvar layer_title = svgdoc.createElementNS(svgns, "title");\n
\t\tlayer_title.textContent = name;\n
\t\tnew_layer.appendChild(layer_title);\n
\t\tnew_layer = svgcontent.appendChild(new_layer);\n
\t\tbatchCmd.addSubCommand(new InsertElementCommand(new_layer));\n
\t\taddCommandToHistory(batchCmd);\n
\t\tcanvas.clearSelection();\n
\t\tidentifyLayers();\n
\t\tcanvas.setCurrentLayer(name);\n
\t\tcall("changed", [new_layer]);\n
\t};\n
\t\n
\t// Function: deleteCurrentLayer\n
\t// Deletes the current layer from the drawing and then clears the selection. This function \n
\t// then calls the \'changed\' handler.  This is an undoable action.\n
\tthis.deleteCurrentLayer = function() {\n
\t\tif (current_layer && all_layers.length > 1) {\n
\t\t\tvar batchCmd = new BatchCommand("Delete Layer");\n
\t\t\t// actually delete from the DOM and store in our Undo History\n
\t\t\tvar parent = current_layer.parentNode;\n
\t\t\tbatchCmd.addSubCommand(new RemoveElementCommand(current_layer, parent));\n
\t\t\tparent.removeChild(current_layer);\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcanvas.clearSelection();\n
\t\t\tidentifyLayers();\n
\t\t\tcanvas.setCurrentLayer(all_layers[all_layers.length-1][0]);\n
\t\t\tcall("changed", [svgcontent]);\n
\t\t\treturn true;\n
\t\t}\n
\t\treturn false;\n
\t};\n
\t\n
\t// Function: getNumLayers\n
\t// Returns the number of layers in the current drawing.\n
\t// \n
\t// Returns:\n
\t// The number of layers in the current drawing.\n
\tthis.getNumLayers = function() {\n
\t\treturn all_layers.length;\n
\t};\n
\t\n
\t// Function: getLayer\n
\t// Returns the name of the ith layer. If the index is out of range, an empty string is returned.\n
\t//\n
\t// Parameters:\n
\t// i - the zero-based index of the layer you are querying.\n
\t// \n
\t// Returns:\n
\t// The name of the ith layer\n
\tthis.getLayer = function(i) {\n
\t\tif (i >= 0 && i < canvas.getNumLayers()) {\n
\t\t\treturn all_layers[i][0];\n
\t\t}\n
\t\treturn "";\n
\t};\n
\t\n
\t// Function: getCurrentLayer\n
\t// Returns the name of the currently selected layer. If an error occurs, an empty string \n
\t// is returned.\n
\t//\n
\t// Returns:\n
\t// The name of the currently active layer.\n
\tthis.getCurrentLayer = function() {\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][1] == current_layer) {\n
\t\t\t\treturn all_layers[i][0];\n
\t\t\t}\n
\t\t}\n
\t\treturn "";\n
\t};\n
\t\n
\t// Function: setCurrentLayer\n
\t// Sets the current layer. If the name is not a valid layer name, then this function returns\n
\t// false. Otherwise it returns true. This is not an undo-able action.\n
\t//\n
\t// Parameters:\n
\t// name - the name of the layer you want to switch to.\n
\t//\n
\t// Returns:\n
\t// true if the current layer was switched, otherwise false\n
\tthis.setCurrentLayer = function(name) {\n
\t\tname = toXml(name);\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (name == all_layers[i][0]) {\n
\t\t\t\tif (current_layer != all_layers[i][1]) {\n
\t\t\t\t\tcanvas.clearSelection();\n
\t\t\t\t\tcurrent_layer.setAttribute("style", "pointer-events:none");\n
\t\t\t\t\tcurrent_layer = all_layers[i][1];\n
\t\t\t\t\tcurrent_layer.setAttribute("style", "pointer-events:all");\n
\t\t\t\t}\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\t\treturn false;\n
\t};\n
\t\n
\t// Function: renameCurrentLayer\n
\t// Renames the current layer. If the layer name is not valid (i.e. unique), then this function \n
\t// does nothing and returns false, otherwise it returns true. This is an undo-able action.\n
\t// \n
\t// Parameters:\n
\t// newname - the new name you want to give the current layer.  This name must be unique \n
\t// among all layer names.\n
\t//\n
\t// Returns:\n
\t// true if the rename succeeded, false otherwise.\n
\tthis.renameCurrentLayer = function(newname) {\n
\t\tif (current_layer) {\n
\t\t\tvar oldLayer = current_layer;\n
\t\t\t// setCurrentLayer will return false if the name doesn\'t already exists\n
\t\t\tif (!canvas.setCurrentLayer(newname)) {\n
\t\t\t\tvar batchCmd = new BatchCommand("Rename Layer");\n
\t\t\t\t// find the index of the layer\n
\t\t\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\t\t\tif (all_layers[i][1] == oldLayer) break;\n
\t\t\t\t}\n
\t\t\t\tvar oldname = all_layers[i][0];\n
\t\t\t\tall_layers[i][0] = toXml(newname);\n
\t\t\t\n
\t\t\t\t// now change the underlying title element contents\n
\t\t\t\tvar len = oldLayer.childNodes.length;\n
\t\t\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\t\t\tvar child = oldLayer.childNodes.item(i);\n
\t\t\t\t\t// found the <title> element, now append all the\n
\t\t\t\t\tif (child && child.tagName == "title") {\n
\t\t\t\t\t\t// wipe out old name \n
\t\t\t\t\t\twhile (child.firstChild) { child.removeChild(child.firstChild); }\n
\t\t\t\t\t\tchild.textContent = newname;\n
\n
\t\t\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(child, {"#text":oldname}));\n
\t\t\t\t\t\taddCommandToHistory(batchCmd);\n
\t\t\t\t\t\tcall("changed", [oldLayer]);\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tcurrent_layer = oldLayer;\n
\t\t}\n
\t\treturn false;\n
\t};\n
\t\n
\t// Function: setCurrentLayerPosition\n
\t// Changes the position of the current layer to the new value. If the new index is not valid, \n
\t// this function does nothing and returns false, otherwise it returns true. This is an\n
\t// undo-able action.\n
\t//\n
\t// Parameters:\n
\t// newpos - The zero-based index of the new position of the layer.  This should be between\n
\t// 0 and (number of layers - 1)\n
\t// \n
\t// Returns:\n
\t// true if the current layer position was changed, false otherwise.\n
\tthis.setCurrentLayerPosition = function(newpos) {\n
\t\tif (current_layer && newpos >= 0 && newpos < all_layers.length) {\n
\t\t\tfor (var oldpos = 0; oldpos < all_layers.length; ++oldpos) {\n
\t\t\t\tif (all_layers[oldpos][1] == current_layer) break;\n
\t\t\t}\n
\t\t\t// some unknown error condition (current_layer not in all_layers)\n
\t\t\tif (oldpos == all_layers.length) { return false; }\n
\t\t\t\n
\t\t\tif (oldpos != newpos) {\n
\t\t\t\t// if our new position is below us, we need to insert before the node after newpos\n
\t\t\t\tvar refLayer = null;\n
\t\t\t\tvar oldNextSibling = current_layer.nextSibling;\n
\t\t\t\tif (newpos > oldpos ) {\n
\t\t\t\t\tif (newpos < all_layers.length-1) {\n
\t\t\t\t\t\trefLayer = all_layers[newpos+1][1];\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t// if our new position is above us, we need to insert before the node at newpos\n
\t\t\t\telse {\n
\t\t\t\t\trefLayer = all_layers[newpos][1];\n
\t\t\t\t}\n
\t\t\t\tsvgcontent.insertBefore(current_layer, refLayer);\n
\t\t\t\taddCommandToHistory(new MoveElementCommand(current_layer, oldNextSibling, svgcontent));\n
\t\t\t\t\n
\t\t\t\tidentifyLayers();\n
\t\t\t\tcanvas.setCurrentLayer(all_layers[newpos][0]);\n
\t\t\t\t\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn false;\n
\t};\n
\t\n
\t// Function: getLayerVisibility\n
\t// Returns whether the layer is visible.  If the layer name is not valid, then this function\n
\t// returns false.\n
\t//\n
\t// Parameters:\n
\t// layername - the name of the layer which you want to query.\n
\t//\n
\t// Returns:\n
\t// The visibility state of the layer, or false if the layer name was invalid.\n
\tthis.getLayerVisibility = function(layername) {\n
\t\t// find the layer\n
\t\tvar layer = null;\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][0] == layername) {\n
\t\t\t\tlayer = all_layers[i][1];\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tif (!layer) return false;\n
\t\treturn (layer.getAttribute("display") != "none");\n
\t};\n
\t\n
\t// Function: setLayerVisibility\n
\t// Sets the visibility of the layer. If the layer name is not valid, this function return \n
\t// false, otherwise it returns true. This is an undo-able action.\n
\t//\n
\t// Parameters:\n
\t// layername - the name of the layer to change the visibility\n
\t// bVisible - true/false, whether the layer should be visible\n
\t//\n
\t// Returns:\n
\t// true if the layer\'s visibility was set, false otherwise\n
\tthis.setLayerVisibility = function(layername, bVisible) {\n
\t\t// find the layer\n
\t\tvar layer = null;\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][0] == layername) {\n
\t\t\t\tlayer = all_layers[i][1];\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tif (!layer) return false;\n
\t\t\n
\t\tvar oldDisplay = layer.getAttribute("display");\n
\t\tif (!oldDisplay) oldDisplay = "inline";\n
\t\tlayer.setAttribute("display", bVisible ? "inline" : "none");\n
\t\taddCommandToHistory(new ChangeElementCommand(layer, {"display":oldDisplay}, "Layer Visibility"));\n
\t\t\n
\t\tif (layer == current_layer) {\n
\t\t\tcanvas.clearSelection();\n
\t\t\tpathActions.clear();\n
\t\t}\n
//\t\tcall("changed", [selected]);\n
\t\t\n
\t\treturn true;\n
\t};\n
\t\n
\t// Function: moveSelectedToLayer\n
\t// Moves the selected elements to layername. If the name is not a valid layer name, then false \n
\t// is returned.  Otherwise it returns true. This is an undo-able action.\n
\t//\n
\t// Parameters:\n
\t// layername - the name of the layer you want to which you want to move the selected elements\n
\t//\n
\t// Returns:\n
\t// true if the selected elements were moved to the layer, false otherwise.\n
\tthis.moveSelectedToLayer = function(layername) {\n
\t\t// find the layer\n
\t\tvar layer = null;\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][0] == layername) {\n
\t\t\t\tlayer = all_layers[i][1];\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tif (!layer) return false;\n
\t\t\n
\t\tvar batchCmd = new BatchCommand("Move Elements to Layer");\n
\t\t\n
\t\t// loop for each selected element and move it\n
\t\tvar selElems = selectedElements;\n
\t\tvar i = selElems.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selElems[i];\n
\t\t\tif (!elem) continue;\n
\t\t\tvar oldNextSibling = elem.nextSibling;\n
\t\t\t// TODO: this is pretty brittle!\n
\t\t\tvar oldLayer = elem.parentNode;\n
\t\t\tlayer.appendChild(elem);\n
\t\t\tbatchCmd.addSubCommand(new MoveElementCommand(elem, oldNextSibling, oldLayer));\n
\t\t}\n
\t\t\n
\t\taddCommandToHistory(batchCmd);\n
\t\t\n
\t\treturn true;\n
\t};\n
\t\n
\t// Function: getLayerOpacity\n
\t// Returns the opacity of the given layer.  If the input name is not a layer, null is returned.\n
\t//\n
\t// Parameters: \n
\t// layername - name of the layer on which to get the opacity\n
\t//\n
\t// Returns:\n
\t// The opacity value of the given layer.  This will be a value between 0.0 and 1.0, or null\n
\t// if layername is not a valid layer\n
\tthis.getLayerOpacity = function(layername) {\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][0] == layername) {\n
\t\t\t\tvar g = all_layers[i][1];\n
\t\t\t\tvar opacity = g.getAttribute("opacity");\n
\t\t\t\tif (!opacity) {\n
\t\t\t\t\topacity = "1.0";\n
\t\t\t\t}\n
\t\t\t\treturn parseFloat(opacity);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn null;\n
\t};\n
\t\n
\t// Function: setLayerOpacity\n
\t// Sets the opacity of the given layer.  If the input name is not a layer, nothing happens.\n
\t// This is not an undo-able action.  NOTE: this function exists solely to apply\n
\t// a highlighting/de-emphasis effect to a layer, when it is possible for a user to affect\n
\t// the opacity of a layer, we will need to allow this function to produce an undo-able action.\n
\t// If opacity is not a value between 0.0 and 1.0, then nothing happens.\n
\t//\n
\t// Parameters:\n
\t// layername - name of the layer on which to set the opacity\n
\t// opacity - a float value in the range 0.0-1.0\n
\tthis.setLayerOpacity = function(layername, opacity) {\n
\t\tif (opacity < 0.0 || opacity > 1.0) return;\n
\t\tfor (var i = 0; i < all_layers.length; ++i) {\n
\t\t\tif (all_layers[i][0] == layername) {\n
\t\t\t\tvar g = all_layers[i][1];\n
\t\t\t\tg.setAttribute("opacity", opacity);\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t};\n
\t\n
\t// Function: selectAllInCurrentLayer\n
\t// Clears the selection, then adds all elements in the current layer to the selection.\n
\t// This function then fires the selected event.\n
\tthis.selectAllInCurrentLayer = function() {\n
\t\tif (current_layer) {\n
\t\t\tcanvas.clearSelection();\n
\t\t\tcanvas.addToSelection($(current_layer).children());\n
\t\t\tcurrent_mode = "select";\n
\t\t\tcall("selected", selectedElements);\t\t\t\n
\t\t}\n
\t};\n
\n
\t// Function: clear\n
\t// Clears the current document.  This is not an undoable action.\n
\tthis.clear = function() {\n
\t\tpathActions.clear();\n
\n
\t\t// clear the svgcontent node\n
\t\tvar nodes = svgcontent.childNodes;\n
\t\tvar len = svgcontent.childNodes.length;\n
\t\tvar i = 0;\n
\t\tthis.clearSelection();\n
\t\tfor(var rep = 0; rep < len; rep++){\n
\t\t\tif (nodes[i].nodeType == 1) { // element node\n
\t\t\t\tsvgcontent.removeChild(nodes[i]);\n
\t\t\t} else {\n
\t\t\t\ti++;\n
\t\t\t}\n
\t\t}\n
\t\t// create empty first layer\n
\t\tall_layers = [];\n
\t\tcanvas.createLayer("Layer 1");\n
\t\t\n
\t\t// clear the undo stack\n
\t\tresetUndoStack();\n
\t\t// reset the selector manager\n
\t\tselectorManager.initGroup();\n
\t\t// reset the rubber band box\n
\t\trubberBox = selectorManager.getRubberBandBox();\n
\t\tcall("cleared");\n
\t};\n
\t\n
\tthis.linkControlPoints = function(linkPoints) {\n
\t\tpathActions.linkControlPoints(linkPoints);\n
\t}\n
\n
\tthis.getContentElem = function() { return svgcontent; };\n
\tthis.getRootElem = function() { return svgroot; };\n
\tthis.getSelectedElems = function() { return selectedElements; };\n
\n
\tthis.getResolution = function() {\n
// \t\tvar vb = svgcontent.getAttribute("viewBox").split(\' \');\n
// \t\treturn {\'w\':vb[2], \'h\':vb[3], \'zoom\': current_zoom};\n
\t\t\t\n
\t\treturn {\n
\t\t\t\'w\':svgcontent.getAttribute("width")/current_zoom,\n
\t\t\t\'h\':svgcontent.getAttribute("he

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

ight")/current_zoom,\n
\t\t\t\'zoom\': current_zoom\n
\t\t};\n
\t};\n
\t\n
\tthis.getDocumentTitle = function() {\n
\t\tvar childs = svgcontent.childNodes;\n
\t\tfor (var i=0; i<childs.length; i++) {\n
\t\t\tif(childs[i].nodeName == \'title\') {\n
\t\t\t\treturn childs[i].textContent;\n
\t\t\t}\n
\t\t}\n
\t\treturn \'\';\n
\t}\n
\t\n
\tthis.setDocumentTitle = function(newtitle) {\n
\t\tvar childs = svgcontent.childNodes, doc_title = false, old_title = \'\';\n
\t\t\n
\t\tvar batchCmd = new BatchCommand("Change Image Title");\n
\t\t\n
\t\tfor (var i=0; i<childs.length; i++) {\n
\t\t\tif(childs[i].nodeName == \'title\') {\n
\t\t\t\tdoc_title = childs[i];\n
\t\t\t\told_title = doc_title.textContent;\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tif(!doc_title) {\n
\t\t\tdoc_title = svgdoc.createElementNS(svgns, "title");\n
\t\t\tsvgcontent.insertBefore(doc_title, svgcontent.firstChild);\n
\t\t} \n
\t\t\n
\t\tif(newtitle.length) {\n
\t\t\tdoc_title.textContent = newtitle;\n
\t\t} else {\n
\t\t\t// No title given, so element is not necessary\n
\t\t\tdoc_title.parentNode.removeChild(doc_title);\n
\t\t}\n
\t\tbatchCmd.addSubCommand(new ChangeElementCommand(doc_title, {\'#text\': old_title}));\n
\t\taddCommandToHistory(batchCmd);\n
\t}\n
\t\n
\tthis.getEditorNS = function(add) {\n
\t\tif(add) {\n
\t\t\tsvgcontent.setAttribute(\'xmlns:se\', se_ns);\n
\t\t}\n
\t\treturn se_ns;\n
\t}\n
\t\n
\tthis.setResolution = function(x, y) {\n
\t\tvar res = canvas.getResolution();\n
\t\tvar w = res.w, h = res.h;\n
\t\tvar batchCmd;\n
\n
\t\tif(x == \'fit\') {\n
\t\t\t// Get bounding box\n
\t\t\tvar bbox = canvas.getStrokedBBox();\n
\t\t\t\n
\t\t\tif(bbox) {\n
\t\t\t\tbatchCmd = new BatchCommand("Fit Canvas to Content");\n
\t\t\t\tvar visEls = canvas.getVisibleElements();\n
\t\t\t\tcanvas.addToSelection(visEls);\n
\t\t\t\tvar dx = [], dy = [];\n
\t\t\t\t$.each(visEls, function(i, item) {\n
\t\t\t\t\tdx.push(bbox.x*-1);\n
\t\t\t\t\tdy.push(bbox.y*-1);\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tvar cmd = canvas.moveSelectedElements(dx, dy, true);\n
\t\t\t\tbatchCmd.addSubCommand(cmd);\n
\t\t\t\tcanvas.clearSelection();\n
\t\t\t\t\n
\t\t\t\tx = Math.round(bbox.width);\n
\t\t\t\ty = Math.round(bbox.height);\n
\t\t\t} else {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t}\n
\t\tif (x != w || y != h) {\n
\t\t\tvar handle = svgroot.suspendRedraw(1000);\n
\t\t\tif(!batchCmd) {\n
\t\t\t\tbatchCmd = new BatchCommand("Change Image Dimensions");\n
\t\t\t}\n
\t\t\tx = convertToNum(\'width\', x);\n
\t\t\ty = convertToNum(\'height\', y);\n
\t\t\t\n
\t\t\tsvgcontent.setAttribute(\'width\', x);\n
\t\t\tsvgcontent.setAttribute(\'height\', y);\n
\t\t\tthis.contentW = x;\n
\t\t\tthis.contentH = y;\n
\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(svgcontent, {"width":w, "height":h}));\n
\n
\t\t\tsvgcontent.setAttribute("viewBox", [0, 0, x/current_zoom, y/current_zoom].join(\' \'));\n
\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(svgcontent, {"viewBox": ["0 0", w, h].join(\' \')}));\n
\t\t\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tsvgroot.unsuspendRedraw(handle);\n
\t\t\tcall("changed", [svgcontent]);\n
\t\t}\n
\t\treturn true;\n
\t};\n
\t\n
\tthis.getOffset = function() {\n
\t\treturn $(svgcontent).attr([\'x\', \'y\']);\n
\t}\n
\t\n
\tthis.setBBoxZoom = function(val, editor_w, editor_h) {\n
\t\tvar spacer = .85;\n
\t\tvar bb;\n
\t\tvar calcZoom = function(bb) {\n
\t\t\tif(!bb) return false;\n
\t\t\tvar w_zoom = Math.round((editor_w / bb.width)*100 * spacer)/100;\n
\t\t\tvar h_zoom = Math.round((editor_h / bb.height)*100 * spacer)/100;\t\n
\t\t\tvar zoomlevel = Math.min(w_zoom,h_zoom);\n
\t\t\tcanvas.setZoom(zoomlevel);\n
\t\t\treturn {\'zoom\': zoomlevel, \'bbox\': bb};\n
\t\t}\n
\t\t\n
\t\tif(typeof val == \'object\') {\n
\t\t\tbb = val;\n
\t\t\tif(bb.width == 0 || bb.height == 0) {\n
\t\t\t\tvar newzoom = bb.zoom?bb.zoom:current_zoom * bb.factor;\n
\t\t\t\tcanvas.setZoom(newzoom);\n
\t\t\t\treturn {\'zoom\': current_zoom, \'bbox\': bb};\n
\t\t\t}\n
\t\t\treturn calcZoom(bb);\n
\t\t}\n
\t\n
\t\tswitch (val) {\n
\t\t\tcase \'selection\':\n
\t\t\t\tif(!selectedElements[0]) return;\n
\t\t\t\tvar sel_elems = $.map(selectedElements, function(n){ if(n) return n; });\n
\t\t\t\tbb = canvas.getStrokedBBox(sel_elems);\n
\t\t\t\tbreak;\n
\t\t\tcase \'canvas\':\n
\t\t\t\tvar res = canvas.getResolution();\n
\t\t\t\tspacer = .95;\n
\t\t\t\tbb = {width:res.w, height:res.h ,x:0, y:0};\n
\t\t\t\tbreak;\n
\t\t\tcase \'content\':\n
\t\t\t\tbb = canvas.getStrokedBBox();\n
\t\t\t\tbreak;\n
\t\t\tcase \'layer\':\n
\t\t\t\tbb = canvas.getStrokedBBox(canvas.getVisibleElements(current_layer));\n
\t\t\t\tbreak;\n
\t\t\tdefault:\n
\t\t\t\treturn;\n
\t\t}\n
\t\treturn calcZoom(bb);\n
\t}\n
\n
\tthis.setZoom = function(zoomlevel) {\n
\t\tvar res = canvas.getResolution();\n
\t\tsvgcontent.setAttribute("viewBox", "0 0 " + res.w/zoomlevel + " " + res.h/zoomlevel);\n
\t\tcurrent_zoom = zoomlevel;\n
\t\t$.each(selectedElements, function(i, elem) {\n
\t\t\tif(!elem) return;\n
\t\t\tselectorManager.requestSelector(elem).resize();\n
\t\t});\n
\t\tpathActions.zoomChange();\n
\t\trunExtensions("zoomChanged", zoomlevel);\n
\t}\n
\n
\tthis.getMode = function() {\n
\t\treturn current_mode;\n
\t};\n
\n
\tthis.setMode = function(name) {\n
\t\tpathActions.clear(true);\n
\t\ttextActions.clear();\n
\t\t\n
\t\tcur_properties = (selectedElements[0] && selectedElements[0].nodeName == \'text\') ? cur_text : cur_shape;\n
\t\tcurrent_mode = name;\n
\t};\n
\n
\tthis.getStrokeColor = function() {\n
\t\treturn cur_properties.stroke;\n
\t};\n
\n
\t// TODO: rewrite setFillColor(), setStrokeColor(), setStrokeWidth(), setStrokeStyle() \n
\t// to use a common function?\n
\tthis.setStrokeColor = function(val,preventUndo) {\n
\t\tcur_shape.stroke = val;\n
\t\tcur_properties.stroke_paint = {type:"solidColor"};\n
\t\tvar elems = [];\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem) {\n
\t\t\t\tif (elem.tagName == "g")\n
\t\t\t\t\twalkTree(elem, function(e){if(e.nodeName!="g") elems.push(e);});\n
\t\t\t\telse\n
\t\t\t\t\telems.push(elem);\n
\t\t\t}\n
\t\t}\n
\n
\t\tif (elems.length > 0) {\n
\t\t\tif (!preventUndo) {\n
\t\t\t\tthis.changeSelectedAttribute("stroke", val, elems);\n
\t\t\t\tcall("changed", elems);\n
\t\t\t} else \n
\t\t\t\tthis.changeSelectedAttributeNoUndo("stroke", val, elems);\n
\t\t}\n
\t};\n
\n
\tthis.getFillColor = function() {\n
\t\treturn cur_properties.fill;\n
\t};\n
\n
\tthis.setFillColor = function(val,preventUndo) {\n
\t\tcur_properties.fill = val;\n
\t\tcur_properties.fill_paint = {type:"solidColor"};\n
\t\t// take out any path/line elements when setting fill\n
\t\t// add all descendants of groups (but remove groups)\n
\t\tvar elems = [];\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem) {\n
\t\t\t\tif (elem.tagName == "g")\n
\t\t\t\t\twalkTree(elem, function(e){if(e.nodeName!="g") elems.push(e);});\n
\t\t\t\telse if (elem.tagName != "polyline" && elem.tagName != "line")\n
\t\t\t\t\telems.push(elem);\n
\t\t\t}\n
\t\t}\n
\t\tif (elems.length > 0) {\n
\t\t\tif (!preventUndo) {\n
\t\t\t\tthis.changeSelectedAttribute("fill", val, elems);\n
\t\t\t\tcall("changed", elems);\n
\t\t\t} else\n
\t\t\t\tthis.changeSelectedAttributeNoUndo("fill", val, elems);\n
\t\t}\n
\t};\n
\n
\tvar findDefs = function() {\n
\t\tvar defs = svgcontent.getElementsByTagNameNS(svgns, "defs");\n
\t\tif (defs.length > 0) {\n
\t\t\tdefs = defs[0];\n
\t\t}\n
\t\telse {\n
\t\t\t// first child is a comment, so call nextSibling\n
\t\t\tdefs = svgcontent.insertBefore( svgdoc.createElementNS(svgns, "defs" ), svgcontent.firstChild.nextSibling);\n
\t\t}\n
\t\treturn defs;\n
\t};\n
\n
\tvar addGradient = function() {\n
\t\t$.each([\'stroke\',\'fill\'],function(i,type) {\n
\t\t\t\n
\t\t\tif(!cur_properties[type + \'_paint\'] || cur_properties[type + \'_paint\'].type == "solidColor") return;\n
\t\t\tvar grad = canvas[type + \'Grad\'];\n
\t\t\t// find out if there is a duplicate gradient already in the defs\n
\t\t\tvar duplicate_grad = findDuplicateGradient(grad);\n
\t\t\tvar defs = findDefs();\n
\t\t\t// no duplicate found, so import gradient into defs\n
\t\t\tif (!duplicate_grad) {\n
\t\t\t\tvar orig_grad = grad;\n
\t\t\t\tgrad = defs.appendChild( svgdoc.importNode(grad, true) );\n
\t\t\t\tcanvas.fixOperaXML(grad, orig_grad);\n
\t\t\t\t// get next id and set it on the grad\n
\t\t\t\tgrad.id = getNextId();\n
\t\t\t}\n
\t\t\telse { // use existing gradient\n
\t\t\t\tgrad = duplicate_grad;\n
\t\t\t}\n
\t\t\tvar functype = type==\'fill\'?\'Fill\':\'Stroke\';\n
\t\t\tcanvas[\'set\'+ functype +\'Color\']("url(#" + grad.id + ")");\n
\t\t});\n
\t}\n
\n
\tvar findDuplicateGradient = function(grad) {\n
\t\tvar defs = findDefs();\n
\t\tvar existing_grads = $(defs).find("linearGradient, radialGradient");\n
\t\tvar i = existing_grads.length;\n
\t\tvar rad_attrs = [\'r\',\'cx\',\'cy\',\'fx\',\'fy\'];\n
\t\twhile (i--) {\n
\t\t\tvar og = existing_grads[i];\n
\t\t\tif(grad.tagName == "linearGradient") {\n
\t\t\t\tif (grad.getAttribute(\'x1\') != og.getAttribute(\'x1\') ||\n
\t\t\t\t\tgrad.getAttribute(\'y1\') != og.getAttribute(\'y1\') ||\n
\t\t\t\t\tgrad.getAttribute(\'x2\') != og.getAttribute(\'x2\') ||\n
\t\t\t\t\tgrad.getAttribute(\'y2\') != og.getAttribute(\'y2\')) \n
\t\t\t\t{\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tvar grad_attrs = $(grad).attr(rad_attrs);\n
\t\t\t\tvar og_attrs = $(og).attr(rad_attrs);\n
\t\t\t\t\n
\t\t\t\tvar diff = false;\n
\t\t\t\t$.each(rad_attrs, function(i, attr) {\n
\t\t\t\t\tif(grad_attrs[attr] != og_attrs[attr]) diff = true;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tif(diff) continue;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// else could be a duplicate, iterate through stops\n
\t\t\tvar stops = grad.getElementsByTagNameNS(svgns, "stop");\n
\t\t\tvar ostops = og.getElementsByTagNameNS(svgns, "stop");\n
\n
\t\t\tif (stops.length != ostops.length) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tvar j = stops.length;\n
\t\t\twhile(j--) {\n
\t\t\t\tvar stop = stops[j];\n
\t\t\t\tvar ostop = ostops[j];\n
\n
\t\t\t\tif (stop.getAttribute(\'offset\') != ostop.getAttribute(\'offset\') ||\n
\t\t\t\t\tstop.getAttribute(\'stop-opacity\') != ostop.getAttribute(\'stop-opacity\') ||\n
\t\t\t\t\tstop.getAttribute(\'stop-color\') != ostop.getAttribute(\'stop-color\')) \n
\t\t\t\t{\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif (j == -1) {\n
\t\t\t\treturn og;\n
\t\t\t}\n
\t\t} // for each gradient in defs\n
\n
\t\treturn null;\n
\t};\n
\t\n
\t// Group: Fill and Stroke\n
\n
\tthis.setStrokePaint = function(p, addGrad) {\n
\t\t// make a copy\n
\t\tvar p = new $.jGraduate.Paint(p);\n
\t\tthis.setStrokeOpacity(p.alpha/100);\n
\n
\t\t// now set the current paint object\n
\t\tcur_properties.stroke_paint = p;\n
\t\tif (p.type == "solidColor") {\n
\t\t\tthis.setStrokeColor(p.solidColor != "none" ? "#"+p.solidColor : "none");\n
\t\t}\n
\t\telse if(p.type == "linearGradient") {\n
\t\t\tcanvas.strokeGrad = p.linearGradient;\n
\t\t\tif(addGrad) addGradient(); \n
\t\t}\n
\t\telse if(p.type == "radialGradient") {\n
\t\t\tcanvas.strokeGrad = p.radialGradient;\n
\t\t\tif(addGrad) addGradient(); \n
\t\t}\n
\t\telse {\n
//\t\t\tconsole.log("none!");\n
\t\t}\n
\t};\n
\n
\tthis.setFillPaint = function(p, addGrad) {\n
\t\t// make a copy\n
\t\tvar p = new $.jGraduate.Paint(p);\n
\t\tthis.setFillOpacity(p.alpha/100, true);\n
\n
\t\t// now set the current paint object\n
\t\tcur_properties.fill_paint = p;\n
\t\tif (p.type == "solidColor") {\n
\t\t\tthis.setFillColor(p.solidColor != "none" ? "#"+p.solidColor : "none");\n
\t\t}\n
\t\telse if(p.type == "linearGradient") {\n
\t\t\tcanvas.fillGrad = p.linearGradient;\n
\t\t\tif(addGrad) addGradient(); \n
\t\t}\n
\t\telse if(p.type == "radialGradient") {\n
\t\t\tcanvas.fillGrad = p.radialGradient;\n
\t\t\tif(addGrad) addGradient(); \n
\t\t}\n
\t\telse {\n
//\t\t\tconsole.log("none!");\n
\t\t}\n
\t};\n
\n
\tthis.getStrokeWidth = function() {\n
\t\treturn cur_properties.stroke_width;\n
\t};\n
\n
\t// When attempting to set a line\'s width to 0, change it to 1 instead\n
\tthis.setStrokeWidth = function(val) {\n
\t\tif(val == 0 && $.inArray(current_mode, [\'line\', \'path\']) != -1) {\n
\t\t\tcanvas.setStrokeWidth(1);\n
\t\t\treturn;\n
\t\t}\n
\t\tcur_properties.stroke_width = val;\n
\t\t\n
\t\tvar elems = [];\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem) {\n
\t\t\t\tif (elem.tagName == "g")\n
\t\t\t\t\twalkTree(elem, function(e){if(e.nodeName!="g") elems.push(e);});\n
\t\t\t\telse \n
\t\t\t\t\telems.push(elem);\n
\t\t\t}\n
\t\t}\t\t\n
\t\tif (elems.length > 0) {\n
\t\t\tthis.changeSelectedAttribute("stroke-width", val, elems);\n
\t\t\tcall("changed", selectedElements);\n
\t\t}\n
\t};\n
\n
\tthis.setStrokeAttr = function(attr, val) {\n
\t\tcur_shape[attr.replace(\'-\',\'_\')] = val;\n
\t\tvar elems = [];\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem) {\n
\t\t\t\tif (elem.tagName == "g")\n
\t\t\t\t\twalkTree(elem, function(e){if(e.nodeName!="g") elems.push(e);});\n
\t\t\t\telse \n
\t\t\t\t\telems.push(elem);\n
\t\t\t}\n
\t\t}\t\t\n
\t\tif (elems.length > 0) {\n
\t\t\tthis.changeSelectedAttribute(attr, val, elems);\n
\t\t\tcall("changed", selectedElements);\n
\t\t}\n
\t};\n
\t\n
\tthis.getOpacity = function() {\n
\t\treturn cur_shape.opacity;\n
\t};\n
\n
\tthis.setOpacity = function(val) {\n
\t\tcur_shape.opacity = val;\n
\t\tthis.changeSelectedAttribute("opacity", val);\n
\t};\n
\n
\tthis.getBlur = function(elem) {\n
\t\tvar val = 0;\n
// \t\tvar elem = selectedElements[0];\n
\t\t\n
\t\tif(elem) {\n
\t\t\tvar filter_url = elem.getAttribute(\'filter\');\n
\t\t\tif(filter_url) {\n
\t\t\t\tvar blur = getElem(elem.id + \'_blur\');\n
\t\t\t\tif(blur) {\n
\t\t\t\t\tval = blur.firstChild.getAttribute(\'stdDeviation\');\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\treturn val;\n
\t};\n
\n
\t(function() {\n
\t\tvar cur_command = null;\n
\t\tvar filter = null;\n
\t\tvar filterHidden = false;\n
\t\t\n
\t\tcanvas.setBlurNoUndo = function(val) {\n
\t\t\tif(!filter) {\n
\t\t\t\tcanvas.setBlur(val);\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif(val === 0) {\n
\t\t\t\t// Don\'t change the StdDev, as that will hide the element.\n
\t\t\t\t// Instead, just remove the value for "filter"\n
\t\t\t\tcanvas.changeSelectedAttributeNoUndo("filter", "");\n
\t\t\t\tfilterHidden = true;\n
\t\t\t} else {\n
\t\t\t\tif(filterHidden) {\n
\t\t\t\t\tcanvas.changeSelectedAttributeNoUndo("filter", \'url(#\' + selectedElements[0].id + \'_blur)\');\n
\t\t\t\t}\n
\t\t\t\tcanvas.changeSelectedAttributeNoUndo("stdDeviation", val, [filter.firstChild]);\n
\t\t\t\tcanvas.setBlurOffsets(filter, val);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tfunction finishChange() {\n
\t\t\tvar bCmd = canvas.finishUndoableChange();\n
\t\t\tcur_command.addSubCommand(bCmd);\n
\t\t\taddCommandToHistory(cur_command);\n
\t\t\tcur_command = null;\t\n
\t\t\tfilter = null;\n
\t\t}\n
\t\n
\t\tcanvas.setBlurOffsets = function(filter, stdDev) {\n
\t\t\tif(stdDev > 3) {\n
\t\t\t\t// TODO: Create algorithm here where size is based on expected blur\n
\t\t\t\tassignAttributes(filter, {\n
\t\t\t\t\tx: \'-50%\',\n
\t\t\t\t\ty: \'-50%\',\n
\t\t\t\t\twidth: \'200%\',\n
\t\t\t\t\theight: \'200%\',\n
\t\t\t\t}, 100);\n
\t\t\t} else {\n
\t\t\t\tfilter.removeAttribute(\'x\');\n
\t\t\t\tfilter.removeAttribute(\'y\');\n
\t\t\t\tfilter.removeAttribute(\'width\');\n
\t\t\t\tfilter.removeAttribute(\'height\');\n
\t\t\t}\n
\t\t}\n
\t\n
\t\tcanvas.setBlur = function(val, complete) {\n
\t\t\tif(cur_command) {\n
\t\t\t\tfinishChange();\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\n
\t\t\t// Looks for associated blur, creates one if not found\n
\t\t\tvar elem = selectedElements[0];\n
\t\t\tvar elem_id = elem.id;\n
\t\t\tfilter = getElem(elem_id + \'_blur\');\n
\t\t\t\n
\t\t\tval -= 0;\n
\t\t\t\n
\t\t\tvar batchCmd = new BatchCommand();\n
\t\t\t\n
\t\t\t// Blur found!\n
\t\t\tif(filter) {\n
\t\t\t\tif(val === 0) {\n
\t\t\t\t\tfilter = null;\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\t// Not found, so create\n
\t\t\t\tvar newblur = addSvgElementFromJson({ "element": "feGaussianBlur",\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"in": \'SourceGraphic\',\n
\t\t\t\t\t\t"stdDeviation": val\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tfilter = addSvgElementFromJson({ "element": "filter",\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"id": elem_id + \'_blur\'\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tfilter.appendChild(newblur);\n
\t\t\t\tfindDefs().appendChild(filter);\n
\t\t\t\t\n
\t\t\t\tbatchCmd.addSubCommand(new InsertElementCommand(filter));\n
\t\t\t}\n
\t\n
\t\t\tvar changes = {filter: elem.getAttribute(\'filter\')};\n
\t\t\t\n
\t\t\tif(val === 0) {\n
\t\t\t\telem.removeAttribute("filter");\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, changes));\n
\t\t\t\treturn;\n
\t\t\t} else {\n
\t\t\t\tthis.changeSelectedAttribute("filter", \'url(#\' + elem_id + \'_blur)\');\n
\t\t\t\t\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, changes));\n
\t\t\t\t\n
\t\t\t\tcanvas.setBlurOffsets(filter, val);\n
\t\t\t}\n
\t\t\t\n
\t\t\tcur_command = batchCmd;\n
\t\t\tcanvas.beginUndoableChange("stdDeviation", [filter?filter.firstChild:null]);\n
\t\t\tif(complete) {\n
\t\t\t\tcanvas.setBlurNoUndo(val);\n
\t\t\t\tfinishChange();\n
\t\t\t}\n
\t\t};\n
\t}());\n
\t\n
\tthis.getFillOpacity = function() {\n
\t\treturn cur_shape.fill_opacity;\n
\t};\n
\n
\tthis.setFillOpacity = function(val, preventUndo) {\n
\t\tcur_shape.fill_opacity = val;\n
\t\tif (!preventUndo)\n
\t\t\tthis.changeSelectedAttribute("fill-opacity", val);\n
\t\telse\n
\t\t\tthis.changeSelectedAttributeNoUndo("fill-opacity", val);\n
\t};\n
\n
\tthis.getStrokeOpacity = function() {\n
\t\treturn cur_shape.stroke_opacity;\n
\t};\n
\n
\tthis.setStrokeOpacity = function(val, preventUndo) {\n
\t\tcur_shape.stroke_opacity = val;\n
\t\tif (!preventUndo)\n
\t\t\tthis.changeSelectedAttribute("stroke-opacity", val);\n
\t\telse\n
\t\t\tthis.changeSelectedAttributeNoUndo("stroke-opacity", val);\n
\t};\n
\n
\t// returns an object that behaves like a SVGTransformList\n
\tthis.getTransformList = function(elem) {\n
\t\t// Opera is included here because Opera/Win/Non-EN seems to change \n
\t\t// transformlist float vals to use a comma rather than a period.\n
\t\tif (isWebkit || !support.goodDecimals) {\n
\t\t\tvar id = elem.id;\n
\t\t\tif(!id) {\n
\t\t\t\t// Get unique ID for temporary element\n
\t\t\t\tid = \'temp\';\n
\t\t\t}\n
\t\t\tvar t = svgTransformLists[id];\n
\t\t\tif (!t || id == \'temp\') {\n
\t\t\t\tsvgTransformLists[id] = new SVGEditTransformList(elem);\n
\t\t\t\tsvgTransformLists[id]._init();\n
\t\t\t\tt = svgTransformLists[id];\n
\t\t\t}\n
\t\t\treturn t;\n
\t\t}\n
\t\telse if (elem.transform) {\n
\t\t\treturn elem.transform.baseVal;\n
\t\t}\n
\t\telse if (elem.gradientTransform) {\n
\t\t\treturn elem.gradientTransform.baseVal;\n
\t\t}\n
\t\treturn null;\n
\t};\n
\n
\tthis.getBBox = function(elem) {\n
\t\tvar selected = elem || selectedElements[0];\n
\t\tif (elem.nodeType != 1) return null;\n
\t\tvar ret = null;\n
\t\tif(elem.nodeName == \'text\' && selected.textContent == \'\') {\n
\t\t\tselected.textContent = \'a\'; // Some character needed for the selector to use.\n
\t\t\tret = selected.getBBox();\n
\t\t\tselected.textContent = \'\';\n
\t\t} else if (elem.nodeName == \'g\' && isOpera) {\n
\t\t\t// deal with an opera bug here\n
\t\t\t// the bbox on a \'g\' is not correct if the elements inside have been moved\n
\t\t\t// so we create a new g, add all the children to it, add it to the DOM, get its bbox\n
\t\t\t// then put all the children back on the old g and remove the new g\n
\t\t\t// (this means we make no changes to the DOM, which saves us a lot of headache at\n
\t\t\t//  the cost of performance)\n
\t\t\tret = selected.getBBox();\n
\t\t\tvar newg = document.createElementNS(svgns, "g");\n
\t\t\twhile (selected.firstChild) { newg.appendChild(selected.firstChild); }\n
\t\t\tvar i = selected.attributes.length;\n
\t\t\twhile(i--) { newg.setAttributeNode(selected.attributes.item(i).cloneNode(true)); }\n
\t\t\tselected.parentNode.appendChild(newg);\n
\t\t\tret = newg.getBBox();\n
\t\t\twhile (newg.firstChild) { selected.appendChild(newg.firstChild); }\n
\t\t\tselected.parentNode.removeChild(newg);\n
\t\t} else if(elem.nodeName == \'path\' && isWebkit) {\n
\t\t\tret = getPathBBox(selected);\n
\t\t} else if(elem.nodeName == \'use\' && !isWebkit) {\n
\t\t\tret = selected.getBBox();\n
\t\t\tret.x += parseFloat(selected.getAttribute(\'x\')||0);\n
\t\t\tret.y += parseFloat(selected.getAttribute(\'y\')||0);\n
\t\t} else if(elem.nodeName == \'foreignObject\') {\n
\t\t\tret = selected.getBBox();\n
\t\t\tret.x += parseFloat(selected.getAttribute(\'x\')||0);\n
\t\t\tret.y += parseFloat(selected.getAttribute(\'y\')||0);\n
\t\t} else {\n
\t\t\ttry { ret = selected.getBBox(); } \n
\t\t\tcatch(e) { \n
\t\t\t\t// Check if element is child of a foreignObject\n
\t\t\t\tvar fo = $(selected).closest("foreignObject");\n
\t\t\t\tif(fo.length) {\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\tret = fo[0].getBBox();\t\t\t\t\t\t\n
\t\t\t\t\t} catch(e) {\n
\t\t\t\t\t\tret = null;\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tret = null;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// get the bounding box from the DOM (which is in that element\'s coordinate system)\n
\t\treturn ret;\n
\t};\n
\n
\t// we get the rotation angle in the tlist\n
\tthis.getRotationAngle = function(elem, to_rad) {\n
\t\tvar selected = elem || selectedElements[0];\n
\t\t// find the rotation transform (if any) and set it\n
\t\tvar tlist = canvas.getTransformList(selected);\n
\t\tif(!tlist) return 0; // <svg> elements have no tlist\n
\t\tvar N = tlist.numberOfItems;\n
\t\tfor (var i = 0; i < N; ++i) {\n
\t\t\tvar xform = tlist.getItem(i);\n
\t\t\tif (xform.type == 4) {\n
\t\t\t\treturn to_rad ? xform.angle * Math.PI / 180.0 : xform.angle;\n
\t\t\t}\n
\t\t}\n
\t\treturn 0.0;\n
\t};\n
\n
\t// this should:\n
\t// - remove any old rotations if present\n
\t// - prepend a new rotation at the transformed center\n
\tthis.setRotationAngle = function(val,preventUndo) {\n
\t\t// ensure val is the proper type\n
\t\tval = parseFloat(val);\n
\t\tvar elem = selectedElements[0];\n
\t\tvar oldTransform = elem.getAttribute("transform");\n
\t\tvar bbox = canvas.getBBox(elem);\n
\t\tvar cx = bbox.x+bbox.width/2, cy = bbox.y+bbox.height/2;\n
\t\tvar tlist = canvas.getTransformList(elem);\n
\t\t\n
\t\t// only remove the real rotational transform if present (i.e. at index=0)\n
\t\tif (tlist.numberOfItems > 0) {\n
\t\t\tvar xform = tlist.getItem(0);\n
\t\t\tif (xform.type == 4) {\n
\t\t\t\ttlist.removeItem(0);\n
\t\t\t}\n
\t\t}\n
\t\t// find R_nc and insert it\n
\t\tif (val != 0) {\n
\t\t\tvar center = transformPoint(cx,cy,transformListToTransform(tlist).matrix);\n
\t\t\tvar R_nc = svgroot.createSVGTransform();\n
\t\t\tR_nc.setRotate(val, center.x, center.y);\n
\t\t\ttlist.insertItemBefore(R_nc,0);\n
\t\t}\n
\t\telse if (tlist.numberOfItems == 0) {\n
\t\t\telem.removeAttribute("transform");\n
\t\t}\n
\t\t\n
\t\tif (!preventUndo) {\n
\t\t\t// we need to undo it, then redo it so it can be undo-able! :)\n
\t\t\t// TODO: figure out how to make changes to transform list undo-able cross-browser?\n
\t\t\tvar newTransform = elem.getAttribute("transform");\n
\t\t\telem.setAttribute("transform", oldTransform);\n
\t\t\tthis.changeSelectedAttribute("transform",newTransform,selectedElements);\n
\t\t}\n
\t\tvar pointGripContainer = getElem("pathpointgrip_container");\n
// \t\tif(elem.nodeName == "path" && pointGripContainer) {\n
// \t\t\tpathActions.setPointContainerTransform(elem.getAttribute("transform"));\n
// \t\t}\n
\t\tvar selector = selectorManager.requestSelector(selectedElements[0]);\n
\t\tselector.resize();\n
\t\tselector.updateGripCursors(val);\n
\t};\n
\n
\tthis.each = function(cb) {\n
\t\t$(svgroot).children().each(cb);\n
\t};\n
\n
\tthis.bind = function(event, f) {\n
\t  var old = events[event];\n
\t\tevents[event] = f;\n
\t\treturn old;\n
\t};\n
\n
\tthis.setIdPrefix = function(p) {\n
\t\tidprefix = p;\n
\t};\n
\n
\tthis.getBold = function() {\n
\t\t// should only have one element selected\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null && selected.tagName  == "text" &&\n
\t\t\tselectedElements[1] == null) \n
\t\t{\n
\t\t\treturn (selected.getAttribute("font-weight") == "bold");\n
\t\t}\n
\t\treturn false;\n
\t};\n
\n
\tthis.setBold = function(b) {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null && selected.tagName  == "text" &&\n
\t\t\tselectedElements[1] == null) \n
\t\t{\n
\t\t\tthis.changeSelectedAttribute("font-weight", b ? "bold" : "normal");\n
\t\t}\n
\t};\n
\n
\tthis.getItalic = function() {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null && selected.tagName  == "text" &&\n
\t\t\tselectedElements[1] == null) \n
\t\t{\n
\t\t\treturn (selected.getAttribute("font-style") == "italic");\n
\t\t}\n
\t\treturn false;\n
\t};\n
\n
\tthis.setItalic = function(i) {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null && selected.tagName  == "text" &&\n
\t\t\tselectedElements[1] == null) \n
\t\t{\n
\t\t\tthis.changeSelectedAttribute("font-style", i ? "italic" : "normal");\n
\t\t}\n
\t};\n
\n
\tthis.getFontFamily = function() {\n
\t\treturn cur_text.font_family;\n
\t};\n
\n
\tthis.setFontFamily = function(val) {\n
    \tcur_text.font_family = val;\n
\t\tthis.changeSelectedAttribute("font-family", val);\n
\t};\n
\n
\tthis.getFontSize = function() {\n
\t\treturn cur_text.font_size;\n
\t};\n
\n
\tthis.setFontSize = function(val) {\n
\t\tcur_text.font_size = val;\n
\t\ttextActions.toSelectMode();\n
\t\tthis.changeSelectedAttribute("font-size", val);\n
\t};\n
\n
\tthis.getText = function() {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected == null) { return ""; }\n
\t\treturn selected.textContent;\n
\t};\n
\n
\tthis.setTextContent = function(val) {\n
\t\tthis.changeSelectedAttribute("#text", val);\n
\t\ttextActions.init(val);\n
\t\ttextActions.setCursor();\n
\t};\n
\t\n
\tthis.setImageURL = function(val) {\n
\t\tvar elem = selectedElements[0];\n
\t\tif(!elem) return;\n
\t\t\n
\t\tvar attrs = $(elem).attr([\'width\', \'height\']);\n
\t\tvar setsize = (!attrs.width || !attrs.height);\n
\n
\t\tvar cur_href = elem.getAttributeNS(xlinkns, "href");\n
\t\t\n
\t\t// Do nothing if no URL change or size change\n
\t\tif(cur_href !== val) {\n
\t\t\tsetsize = true;\n
\t\t} else if(!setsize) return;\n
\n
\t\tvar batchCmd = new BatchCommand("Change Image URL");\n
\t\n
\t\telem.setAttributeNS(xlinkns, "xlink:href", val);\n
\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, {\n
\t\t\t"#href": cur_href\n
\t\t}));\n
\t\n
\t\tif(setsize) {\n
\t\t\t$(new Image()).load(function() {\n
\t\t\t\tvar changes = $(elem).attr([\'width\', \'height\']);\n
\t\t\t\n
\t\t\t\t$(elem).attr({\n
\t\t\t\t\twidth: this.width,\n
\t\t\t\t\theight: this.height\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tselectorManager.requestSelector(elem).resize();\n
\t\t\t\t\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, changes));\n
\t\t\t\taddCommandToHistory(batchCmd);\n
\t\t\t\tcall("changed", elem);\n
\t\t\t}).attr(\'src\',val);\n
\t\t} else {\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t}\n
\t};\n
\n
\tthis.setRectRadius = function(val) {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null && selected.tagName == "rect") {\n
\t\t\tvar r = selected.getAttribute("rx");\n
\t\t\tif (r != val) {\n
\t\t\t\tselected.setAttribute("rx", val);\n
\t\t\t\tselected.setAttribute("ry", val);\n
\t\t\t\taddCommandToHistory(new ChangeElementCommand(selected, {"rx":r, "ry":r}, "Radius"));\n
\t\t\t\tcall("changed", [selected]);\n
\t\t\t}\n
\t\t}\n
\t};\n
\t\n
\tthis.setSegType = function(new_type) {\n
\t\tpathActions.setSegType(new_type);\n
\t}\n
\t\n
\tvar ffClone = function(elem) {\n
\t\t// Hack for Firefox bugs where text element features aren\'t updated\n
\t\tif(navigator.userAgent.indexOf(\'Gecko/\') == -1) return elem;\n
\t\tvar clone = elem.cloneNode(true)\n
\t\telem.parentNode.insertBefore(clone, elem);\n
\t\telem.parentNode.removeChild(elem);\n
\t\tselectorManager.releaseSelector(elem);\n
\t\tselectedElements[0] = clone;\n
\t\tselectorManager.requestSelector(clone).showGrips(true);\n
\t\treturn clone;\n
\t}\n
\n
\t// New functions for refactoring of Undo/Redo\n
\t\n
\t// this is the stack that stores the original values, the elements and\n
\t// the attribute name for begin/finish\n
\tvar undoChangeStackPointer = -1;\n
\tvar undoableChangeStack = [];\n
\t\n
\t// This function tells the canvas to remember the old values of the \n
\t// attrName attribute for each element sent in.  The elements and values \n
\t// are stored on a stack, so the next call to finishUndoableChange() will \n
\t// pop the elements and old values off the stack, gets the current values\n
\t// from the DOM and uses all of these to construct the undo-able command.\n
\tthis.beginUndoableChange = function(attrName, elems) {\n
\t\tvar p = ++undoChangeStackPointer;\n
\t\tvar i = elems.length;\n
\t\tvar oldValues = new Array(i), elements = new Array(i);\n
\t\twhile (i--) {\n
\t\t\tvar elem = elems[i];\n
\t\t\tif (elem == null) continue;\n
\t\t\telements[i] = elem;\n
\t\t\toldValues[i] = elem.getAttribute(attrName);\n
\t\t}\n
\t\tundoableChangeStack[p] = {\'attrName\': attrName,\n
\t\t\t\t\t\t\t\t\'oldValues\': oldValues,\n
\t\t\t\t\t\t\t\t\'elements\': elements};\n
\t};\n
\t\n
\t// This function makes the changes to the elements\n
\tthis.changeSelectedAttributeNoUndo = function(attr, newValue, elems) {\n
\t\tvar handle = svgroot.suspendRedraw(1000);\n
\t\tif(current_mode == \'pathedit\') {\n
\t\t\t// Editing node\n
\t\t\tpathActions.moveNode(attr, newValue);\n
\t\t}\n
\t\tvar elems = elems || selectedElements;\n
\t\tvar i = elems.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = elems[i];\n
\t\t\tif (elem == null) continue;\n
\t\t\t\n
\t\t\t// Go into "select" mode for text changes\n
\t\t\tif(current_mode === "textedit" && attr !== "#text") {\n
\t\t\t\ttextActions.toSelectMode(elem);\n
\t\t\t}\n
\t\t\t\n
\t\t\t// Set x,y vals on elements that don\'t have them\n
\t\t\tif((attr == \'x\' || attr == \'y\') && $.inArray(elem.tagName, [\'g\', \'polyline\', \'path\']) != -1) {\n
\t\t\t\tvar bbox = canvas.getStrokedBBox([elem]);\n
\t\t\t\tvar diff_x = attr == \'x\' ? newValue - bbox.x : 0;\n
\t\t\t\tvar diff_y = attr == \'y\' ? newValue - bbox.y : 0;\n
\t\t\t\tcanvas.moveSelectedElements(diff_x*current_zoom, diff_y*current_zoom, true);\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// only allow the transform/opacity attribute to change on <g> elements, slightly hacky\n
\t\t\tif (elem.tagName == "g" && $.inArray(attr, [\'transform\', \'opacity\', \'filter\']) !== -1);\n
\t\t\tvar oldval = attr == "#text" ? elem.textContent : elem.getAttribute(attr);\n
\t\t\tif (oldval == null)  oldval = "";\n
\t\t\tif (oldval != String(newValue)) {\n
\t\t\t\tif (attr == "#text") {\n
\t\t\t\t\tvar old_w = canvas.getBBox(elem).width;\n
\t\t\t\t\telem.textContent = newValue;\n
\t\t\t\t\telem = ffClone(elem);\n
\t\t\t\t\t\n
\t\t\t\t\t// Hoped to solve the issue of moving text with text-anchor="start",\n
\t\t\t\t\t// but this doesn\'t actually fix it. Hopefully on the right track, though. -Fyrd\n
\t\t\t\t\t\n
// \t\t\t\t\tvar box=canvas.getBBox(elem), left=box.x, top=box.y, width=box.width,\n
// \t\t\t\t\t\theight=box.height, dx = width - old_w, dy=0;\n
// \t\t\t\t\tvar angle = canvas.getRotationAngle(elem, true);\n
// \t\t\t\t\tif (angle) {\n
// \t\t\t\t\t\tvar r = Math.sqrt( dx*dx + dy*dy );\n
// \t\t\t\t\t\tvar theta = Math.atan2(dy,dx) - angle;\n
// \t\t\t\t\t\tdx = r * Math.cos(theta);\n
// \t\t\t\t\t\tdy = r * Math.sin(theta);\n
// \t\t\t\t\t\t\n
// \t\t\t\t\t\telem.setAttribute(\'x\', elem.getAttribute(\'x\')-dx);\n
// \t\t\t\t\t\telem.setAttribute(\'y\', elem.getAttribute(\'y\')-dy);\n
// \t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t} else if (attr == "#href") {\n
\t\t\t\t\telem.setAttributeNS(xlinkns, "xlink:href", newValue);\n
        \t\t}\n
\t\t\t\telse elem.setAttribute(attr, newValue);\n
\t\t\t\tif (i==0)\n
\t\t\t\t\tselectedBBoxes[i] = this.getBBox(elem);\n
\t\t\t\t// Use the Firefox ffClone hack for text elements with gradients or\n
\t\t\t\t// where other text attributes are changed. \n
\t\t\t\tif(elem.nodeName == \'text\') {\n
\t\t\t\t\tif((newValue+\'\').indexOf(\'url\') == 0 || $.inArray(attr, [\'font-size\',\'font-family\',\'x\',\'y\']) != -1) {\n
\t\t\t\t\t\telem = ffClone(elem);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t// Timeout needed for Opera & Firefox\n
\t\t\t\t// codedread: it is now possible for this function to be called with elements\n
\t\t\t\t// that are not in the selectedElements array, we need to only request a\n
\t\t\t\t// selector if the element is in that array\n
\t\t\t\tif ($.inArray(elem, selectedElements) != -1) {\n
\t\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t\t// Due to element replacement, this element may no longer\n
\t\t\t\t\t\t// be part of the DOM\n
\t\t\t\t\t\tif(!elem.parentNode) return;\n
\t\t\t\t\t\tselectorManager.requestSelector(elem).resize();\n
\t\t\t\t\t},0);\n
\t\t\t\t}\n
\t\t\t\t// if this element was rotated, and we changed the position of this element\n
\t\t\t\t// we need to update the rotational transform attribute \n
\t\t\t\tvar angle = canvas.getRotationAngle(elem);\n
\t\t\t\tif (angle != 0 && attr != "transform") {\n
\t\t\t\t\tvar tlist = canvas.getTransformList(elem);\n
\t\t\t\t\tvar n = tlist.numberOfItems;\n
\t\t\t\t\twhile (n--) {\n
\t\t\t\t\t\tvar xform = tlist.getItem(n);\n
\t\t\t\t\t\tif (xform.type == 4) {\n
\t\t\t\t\t\t\t// remove old rotate\n
\t\t\t\t\t\t\ttlist.removeItem(n);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar box = canvas.getBBox(elem);\n
\t\t\t\t\t\t\tvar center = transformPoint(box.x+box.width/2, box.y+box.height/2, transformListToTransform(tlist).matrix);\n
\t\t\t\t\t\t\tvar cx = center.x,\n
\t\t\t\t\t\t\t\tcy = center.y;\n
\t\t\t\t\t\t\tvar newrot = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\tnewrot.setRotate(angle, cx, cy);\n
\t\t\t\t\t\t\ttlist.insertItemBefore(newrot, n);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} // if oldValue != newValue\n
\t\t} // for each elem\n
\t\tsvgroot.unsuspendRedraw(handle);\t\n
\t};\n
\t\n
\t// This function returns a BatchCommand object which summarizes the\n
\t// change since beginUndoableChange was called.  The command can then\n
\t// be added to the command history\n
\tthis.finishUndoableChange = function() {\n
\t\tvar p = undoChangeStackPointer--;\n
\t\tvar changeset = undoableChangeStack[p];\n
\t\tvar i = changeset[\'elements\'].length;\n
\t\tvar attrName = changeset[\'attrName\'];\n
\t\tvar batchCmd = new BatchCommand("Change " + attrName);\n
\t\twhile (i--) {\n
\t\t\tvar elem = changeset[\'elements\'][i];\n
\t\t\tif (elem == null) continue;\n
\t\t\tvar changes = {};\n
\t\t\tchanges[attrName] = changeset[\'oldValues\'][i];\n
\t\t\tif (changes[attrName] != elem.getAttribute(attrName)) {\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(elem, changes, attrName));\n
\t\t\t}\n
\t\t}\n
\t\tundoableChangeStack[p] = null;\n
\t\treturn batchCmd;\n
\t};\n
\n
\t// If you want to change all selectedElements, ignore the elems argument.\n
\t// If you want to change only a subset of selectedElements, then send the\n
\t// subset to this function in the elems argument.\n
\tthis.changeSelectedAttribute = function(attr, val, elems) {\n
\t\tvar elems = elems || selectedElements;\n
\t\tcanvas.beginUndoableChange(attr, elems);\n
\t\tvar i = elems.length;\n
\n
\t\tcanvas.changeSelectedAttributeNoUndo(attr, val, elems);\n
\n
\t\tvar batchCmd = canvas.finishUndoableChange();\n
\t\tif (!batchCmd.isEmpty()) { \n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t}\n
\t};\n
\t\n
\tthis.deleteSelectedElements = function() {\n
\t\tvar batchCmd = new BatchCommand("Delete Elements");\n
\t\tvar len = selectedElements.length;\n
\t\tvar selectedCopy = []; //selectedElements is being deleted\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tvar selected = selectedElements[i];\n
\t\t\tif (selected == null) break;\n
\n
\t\t\tvar parent = selected.parentNode;\n
\t\t\tvar t = selected;\n
\t\t\t// this will unselect the element and remove the selectedOutline\n
\t\t\tselectorManager.releaseSelector(t);\n
\t\t\tvar elem = parent.removeChild(t);\n
\t\t\tselectedCopy.push(selected) //for the copy\n
\t\t\tselectedElements[i] = null;\n
\t\t\tbatchCmd.addSubCommand(new RemoveElementCommand(elem, parent));\n
\t\t}\n
\t\tif (!batchCmd.isEmpty()) addCommandToHistory(batchCmd);\n
\t\tcall("changed", selectedCopy);\n
\t\tcanvas.clearSelection();\n
\t};\n
\t\n
\tthis.groupSelectedElements = function() {\n
\t\tvar batchCmd = new BatchCommand("Group Elements");\n
\t\t\n
\t\t// create and insert the group element\n
\t\tvar g = addSvgElementFromJson({\n
\t\t\t\t\t\t\t\t"element": "g",\n
\t\t\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t\t\t"id": getNextId()\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t});\n
\t\tbatchCmd.addSubCommand(new InsertElementCommand(g));\n
\t\t\n
\t\t// now move all children into the group\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem == null) continue;\n
\t\t\tvar oldNextSibling = elem.nextSibling;\n
\t\t\tvar oldParent = elem.parentNode;\n
\t\t\tg.appendChild(elem);\n
\t\t\tbatchCmd.addSubCommand(new MoveElementCommand(elem, oldNextSibling, oldParent));\t\t\t\n
\t\t}\n
\t\tif (!batchCmd.isEmpty()) addCommandToHistory(batchCmd);\n
\t\t\n
\t\t// update selection\n
\t\tcanvas.clearSelection();\n
\t\tcanvas.addToSelection([g], true);\n
\t};\n
\n
\tthis.ungroupSelectedElement = function() {\n
\t\tvar g = selectedElements[0];\n
\t\tif (g.tagName == "g") {\n
\t\t\tvar batchCmd = new BatchCommand("Ungroup Elements");\n
\t\t\tvar parent = g.parentNode;\n
\t\t\tvar anchor = g.previousSibling;\n
\t\t\tvar children = new Array(g.childNodes.length);\n
\t\t\tvar xform = g.getAttribute("transform");\n
\t\t\t// get consolidated matrix\n
\t\t\tvar glist = canvas.getTransformList(g);\n
\t\t\tvar m = transformListToTransform(glist).matrix;\n
\n
\t\t\t// TODO: get all fill/stroke properties from the group that we are about to destroy\n
\t\t\t// "fill", "fill-opacity", "fill-rule", "stroke", "stroke-dasharray", "stroke-dashoffset", \n
\t\t\t// "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", \n
\t\t\t// "stroke-width"\n
\t\t\t// and then for each child, if they do not have the attribute (or the value is \'inherit\')\n
\t\t\t// then set the child\'s attribute\n
\t\t\t\n
\t\t\tvar i = 0;\n
\t\t\tvar gangle = canvas.getRotationAngle(g);\n
\t\t\t\n
\t\t\tvar gattrs = $(g).attr([\'filter\', \'opacity\']);\n
\t\t\tvar gfilter, gblur;\n
\t\t\t\n
\t\t\twhile (g.firstChild) {\n
\t\t\t\tvar elem = g.firstChild;\n
\t\t\t\tvar oldNextSibling = elem.nextSibling;\n
\t\t\t\tvar oldParent = elem.parentNode;\n
\t\t\t\tchildren[i++] = elem = parent.insertBefore(elem, anchor);\n
\t\t\t\tbatchCmd.addSubCommand(new MoveElementCommand(elem, oldNextSibling, oldParent));\n
\t\t\t\t\n
\t\t\t\tif(gattrs.opacity !== null && gattrs.opacity !== 1) {\n
\t\t\t\t\tvar c_opac = elem.getAttribute(\'opacity\') || 1;\n
\t\t\t\t\tvar new_opac = Math.round((elem.getAttribute(\'opacity\') || 1) * gattrs.opacity * 100)/100;\n
\t\t\t\t\tthis.changeSelectedAttribute(\'opacity\', new_opac, [elem]);\n
\t\t\t\t}\n
\n
\t\t\t\tif(gattrs.filter) {\n
\t\t\t\t\tvar cblur = this.getBlur(elem);\n
\t\t\t\t\tvar orig_cblur = cblur;\n
\t\t\t\t\tif(!gblur) gblur = this.getBlur(g);\n
\t\t\t\t\tif(cblur) {\n
\t\t\t\t\t\t// Is this formula correct?\n
\t\t\t\t\t\tcblur = (gblur-0) + (cblur-0);\n
\t\t\t\t\t} else if(cblur === 0) {\n
\t\t\t\t\t\tcblur = gblur;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// If child has no current filter, get group\'s filter or clone it.\n
\t\t\t\t\tif(!orig_cblur) {\n
\t\t\t\t\t\t// Set group\'s filter to use first child\'s ID\n
\t\t\t\t\t\tif(!gfilter) {\n
\t\t\t\t\t\t\tgfilter = getElem(getUrlFromAttr(gattrs.filter).substr(1));\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t// Clone the group\'s filter\n
\t\t\t\t\t\t\tgfilter = copyElem(gfilter);\n
\t\t\t\t\t\t\tfindDefs().appendChild(gfilter);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tgfilter = getElem(getUrlFromAttr(elem.getAttribute(\'filter\')).substr(1));\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Change this in future for different filters\n
\t\t\t\t\tvar suffix = (gfilter.firstChild.tagName === \'feGaussianBlur\')?\'blur\':\'filter\'; \n
\t\t\t\t\tgfilter.id = elem.id + \'_\' + suffix;\n
\t\t\t\t\tthis.changeSelectedAttribute(\'filter\', \'url(#\' + gfilter.id + \')\', [elem]);\n
\t\t\t\t\t\n
\t\t\t\t\t// Update blur value \n
\t\t\t\t\tif(cblur) {\n
\t\t\t\t\t\tthis.changeSelectedAttribute(\'stdDeviation\', cblur, [gfilter.firstChild]);\n
\t\t\t\t\t\tcanvas.setBlurOffsets(gfilter, cblur);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar chtlist = canvas.getTransformList(elem);\n
\t\t\t\t\n
\t\t\t\tif (glist.numberOfItems) {\n
\t\t\t\t\t// TODO: if the group\'s transform is just a rotate, we can always transfer the\n
\t\t\t\t\t// rotate() down to the children (collapsing consecutive rotates and factoring\n
\t\t\t\t\t// out any translates)\n
\t\t\t\t\tif (gangle && glist.numberOfItems == 1) {\n
\t\t\t\t\t\t// [Rg] [Rc] [Mc]\n
\t\t\t\t\t\t// we want [Tr] [Rc2] [Mc] where:\n
\t\t\t\t\t\t// \t- [Rc2] is at the child\'s current center but has the \n
\t\t\t\t\t\t//\t  sum of the group and child\'s rotation angles\n
\t\t\t\t\t\t// \t- [Tr] is the equivalent translation that this child \n
\t\t\t\t\t\t// \t  undergoes if the group wasn\'t there\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// [Tr] = [Rg] [Rc] [Rc2_inv]\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// get group\'s rotation matrix (Rg)\n
\t\t\t\t\t\tvar rgm = glist.getItem(0).matrix;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// get child\'s rotation matrix (Rc)\n
\t\t\t\t\t\tvar rcm = svgroot.createSVGMatrix();\n
\t\t\t\t\t\tvar cangle = canvas.getRotationAngle(elem);\n
\t\t\t\t\t\tif (cangle) {\n
\t\t\t\t\t\t\trcm = chtlist.getItem(0).matrix;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// get child\'s old center of rotation\n
\t\t\t\t\t\tvar cbox = canvas.getBBox(elem);\n
\t\t\t\t\t\tvar ceqm = transformListToTransform(chtlist).matrix;\n
\t\t\t\t\t\tvar coldc = transformPoint(cbox.x+cbox.width/2, cbox.y+cbox.height/2,ceqm);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// sum group and child\'s angles\n
\t\t\t\t\t\tvar sangle = gangle + cangle;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// get child\'s rotation at the old center (Rc2_inv)\n
\t\t\t\t\t\tvar r2 = svgroot.createSVGTransform();\n
\t\t\t\t\t\tr2.setRotate(sangle, coldc.x, coldc.y);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// calculate equivalent translate\n
\t\t\t\t\t\tvar trm = matrixMultiply(rgm, rcm, r2.matrix.inverse());\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// set up tlist\n
\t\t\t\t\t\tif (cangle) {\n
\t\t\t\t\t\t\tchtlist.removeItem(0);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif (sangle) {\n
\t\t\t\t\t\t\tchtlist.insertItemBefore(r2, 0);\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tif (trm.e || trm.f) {\n
\t\t\t\t\t\t\tvar tr = svgroot.createSVGTransform();\n
\t\t\t\t\t\t\ttr.setTranslate(trm.e, trm.f);\n
\t\t\t\t\t\t\tchtlist.insertItemBefore(tr, 0);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse { // more complicated than just a rotate\n
\t\t\t\t\t\t// transfer the group\'s transform down to each child and then\n
\t\t\t\t\t\t// call recalculateDimensions()\t\t\t\t\n
\t\t\t\t\t\tvar oldxform = elem.getAttribute("transform");\n
\t\t\t\t\t\tvar changes = {};\n
\t\t\t\t\t\tchanges["transform"] = oldxform ? oldxform : "";\n
\n
\t\t\t\t\t\tvar newxform = svgroot.createSVGTransform();\n
\n
\t\t\t\t\t\t// [ gm ] [ chm ] = [ chm ] [ gm\' ]\n
\t\t\t\t\t\t// [ gm\' ] = [ chm_inv ] [ gm ] [ chm ]\n
\t\t\t\t\t\tvar chm = transformListToTransform(chtlist).matrix,\n
\t\t\t\t\t\t\tchm_inv = chm.inverse();\n
\t\t\t\t\t\tvar gm = matrixMultiply( chm_inv, m, chm );\n
\t\t\t\t\t\tnewxform.setMatrix(gm);\n
\t\t\t\t\t\tchtlist.appendItem(newxform);\n
\t\t\t\t\t}\n
\t\t\t\t\tbatchCmd.addSubCommand(recalculateDimensions(elem));\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t\n
\t\t\t// remove transform and make it undo-able\n
\t\t\tif (xform) {\n
\t\t\t\tvar changes = {};\n
\t\t\t\tchanges["transform"] = xform;\n
\t\t\t\tg.setAttribute("transform", "");\n
\t\t\t\tg.removeAttribute("transform");\t\t\t\t\n
\t\t\t\tbatchCmd.addSubCommand(new ChangeElementCommand(g, changes));\n
\t\t\t}\n
\n
\t\t\t// remove the group from the selection\t\t\t\n
\t\t\tcanvas.clearSelection();\n
\t\t\t\n
\t\t\t// delete the group element (but make undo-able)\n
\t\t\tg = parent.removeChild(g);\n
\t\t\tbatchCmd.addSubCommand(new RemoveElementCommand(g, parent));\n
\n
\t\t\tif (!batchCmd.isEmpty()) addCommandToHistory(batchCmd);\n
\t\t\t\n
\t\t\t// update selection\n
\t\t\tcanvas.addToSelection(children);\n
\t\t}\n
\t};\n
\n
\tthis.moveToTopSelectedElement = function() {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null) {\n
\t\t\tvar t = selected;\n
\t\t\tvar oldParent = t.parentNode;\n
\t\t\tvar oldNextSibling = t.nextSibling;\n
\t\t\tif (oldNextSibling == selectorManager.selectorParentGroup) oldNextSibling = null;\n
\t\t\tt = t.parentNode.appendChild(t);\n
\t\t\taddCommandToHistory(new MoveElementCommand(t, oldNextSibling, oldParent, "top"));\n
\t\t}\n
\t};\n
\n
\tthis.moveToBottomSelectedElement = function() {\n
\t\tvar selected = selectedElements[0];\n
\t\tif (selected != null) {\n
\t\t\tvar t = selected;\n
\t\t\tvar oldParent = t.parentNode;\n
\t\t\tvar oldNextSibling = t.nextSibling;\n
\t\t\tif (oldNextSibling == selectorManager.selectorParentGroup) oldNextSibling = null;\n
\t\t\tvar firstChild = t.parentNode.firstChild;\n
\t\t\tif (firstChild.tagName == \'title\') {\n
\t\t\t\tfirstChild = firstChild.nextSibling;\n
\t\t\t}\n
\t\t\t// This can probably be removed, as the defs should not ever apppear\n
\t\t\t// inside a layer group\n
\t\t\tif (firstChild.tagName == \'defs\') {\n
\t\t\t\tfirstChild = firstChild.nextSibling;\n
\t\t\t}\n
\t\t\tt = t.parentNode.insertBefore(t, firstChild);\n
\t\t\taddCommandToHistory(new MoveElementCommand(t, oldNextSibling, oldParent, "bottom"));\n
\t\t}\n
\t};\n
\n
\tthis.moveSelectedElements = function(dx,dy,undoable) {\n
\t\t// if undoable is not sent, default to true\n
\t\t// if single values, scale them to the zoom\n
\t\tif (dx.constructor != Array) {\n
\t\t\tdx /= current_zoom;\n
\t\t\tdy /= current_zoom;\n
\t\t}\n
\t\tvar undoable = undoable || true;\n
\t\tvar batchCmd = new BatchCommand("position");\n
\t\tvar i = selectedElements.length;\n
\t\twhile (i--) {\n
\t\t\tvar selected = selectedElements[i];\n
\t\t\tif (selected != null) {\n
\t\t\t\tif (i==0)\n
\t\t\t\t\tselectedBBoxes[i] = this.getBBox(selected);\n
\t\t\t\t\n
\t\t\t\tvar xform = svgroot.createSVGTransform();\n
\t\t\t\tvar tlist = canvas.getTransformList(selected);\n
\t\t\t\t\n
\t\t\t\t// dx and dy could be arrays\n
\t\t\t\tif (dx.constructor == Array) {\n
\t\t\t\t\tif (i==0) {\n
\t\t\t\t\t\tselectedBBoxes[i].x += dx[i];\n
\t\t\t\t\t\tselectedBBoxes[i].y += dy[i];\n
\t\t\t\t\t}\n
\t\t\t\t\txform.setTranslate(dx[i],dy[i]);\n
\t\t\t\t} else {\n
\t\t\t\t\tif (i==0) {\n
\t\t\t\t\t\tselectedBBoxes[i].x += dx;\n
\t\t\t\t\t\tselectedBBoxes[i].y += dy;\n
\t\t\t\t\t}\n
\t\t\t\t\txform.setTranslate(dx,dy);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\ttlist.insertItemBefore(xform, 0);\n
\t\t\t\t\n
\t\t\t\tvar cmd = recalculateDimensions(selected);\n
\t\t\t\tif (cmd) {\n
\t\t\t\t\tbatchCmd.addSubCommand(cmd);\n
\t\t\t\t}\n
\t\t\t\tselectorManager.requestSelector(selected).resize();\n
\t\t\t}\n
\t\t}\n
\t\tif (!batchCmd.isEmpty()) {\n
\t\t\tif (undoable)\n
\t\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcall("changed", selectedElements);\n
\t\t\treturn batchCmd;\n
\t\t}\n
\t};\n
\n
\tvar getPathBBox = function(path) {\n
\t\t// Get correct BBox for a path in Webkit\n
\t\n
\t\t// Converted from code found here:\n
\t\t// http://blog.hackers-cafe.net/2009/06/how-to-calculate-bezier-curves-bounding.html\n
\t\n
\t\tvar seglist = path.pathSegList;\n
\t\tvar tot = seglist.numberOfItems;\n
\t\t\n
\t\tvar bounds = [[], []];\n
\t\tvar start = seglist.getItem(0);\n
\t\tvar P0 = [start.x, start.y];\n
\t\t\n
\t\tfor(var i=0; i < tot; i++) {\n
\t\t\tvar seg = seglist.getItem(i);\n
\t\t\tif(!seg.x) continue;\n
\t\t\t\n
\t\t\t// Add actual points to limits\n
\t\t\tbounds[0].push(P0[0]);\n
\t\t\tbounds[1].push(P0[1]);\n
\t\t\t\n
\t\t\tif(seg.x1) {\n
\t\t\t\tvar P1 = [seg.x1, seg.y1],\n
\t\t\t\t\tP2 = [seg.x2, seg.y2],\n
\t\t\t\t\tP3 = [seg.x, seg.y];\n
\n
\t\t\t\tfor(var j=0; j < 2; j++) {\n
\n
\t\t\t\t\tvar calc = function(t) {\n
\t\t\t\t\t\treturn Math.pow(1-t,3) * P0[j] \n
\t\t\t\t\t\t\t+ 3 * Math.pow(1-t,2) * t * P1[j]\n
\t\t\t\t\t\t\t+ 3 * (1-t) * Math.pow(t,2) * P2[j]\n
\t\t\t\t\t\t\t+ Math.pow(t,3) * P3[j];\n
\t\t\t\t\t};\n
\n
\t\t\t\t\tvar b = 6 * P0[j] - 12 * P1[j] + 6 * P2[j];\n
\t\t\t\t\tvar a = -3 * P0[j] + 9 * P1[j] - 9 * P2[j] + 3 * P3[j];\n
\t\t\t\t\tvar c = 3 * P1[j] - 3 * P0[j];\n
\t\t\t\t\t\n
\t\t\t\t\tif(a == 0) {\n
\t\t\t\t\t\tif(b == 0) {\n
\t\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tvar t = -c / b;\n
\t\t\t\t\t\tif(0 < t && t < 1) {\n
\t\t\t\t\t\t\tbounds[j].push(calc(t));\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar b2ac = Math.pow(b,2) - 4 * c * a;\n
\t\t\t\t\tif(b2ac < 0) continue;\n
\t\t\t\t\tvar t1 = (-b + Math.sqrt(b2ac))/(2 * a);\n
\t\t\t\t\tif(0 < t1 && t1 < 1) bounds[j].push(calc(t1));\n
\t\t\t\t\tvar t2 = (-b - Math.sqrt(b2ac))/(2 * a);\n
\t\t\t\t\tif(0 < t2 && t2 < 1) bounds[j].push(calc(t2));\n
\t\t\t\t}\n
\t\t\t\tP0 = P3;\n
\t\t\t} else {\n
\t\t\t\tbounds[0].push(seg.x);\n
\t\t\t\tbounds[1].push(seg.y);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tvar x = Math.min.apply(null, bounds[0]);\n
\t\tvar w = Math.max.apply(null, bounds[0]) - x;\n
\t\tvar y = Math.min.apply(null, bounds[1]);\n
\t\tvar h = Math.max.apply(null, bounds[1]) - y;\n
\t\treturn {\n
\t\t\t\'x\': x,\n
\t\t\t\'y\': y,\n
\t\t\t\'width\': w,\n
\t\t\t\'height\': h\n
\t\t};\n
\t}\n
\t\n
\tthis.contentW = this.getResolution().w;\n
\tthis.contentH = this.getResolution().h;\n
\t\n
\tthis.updateCanvas = function(w, h, w_orig, h_orig) {\n
\t\tsvgroot.setAttribute("width", w);\n
\t\tsvgroot.setAttribute("height", h);\n
\t\tvar bg = $(\'#canvasBackground\')[0];\n
\t\tvar old_x = svgcontent.getAttribute(\'x\');\n
\t\tvar old_y = svgcontent.getAttribute(\'y\');\n
\t\tvar x = (w/2 - this.contentW*current_zoom/2);\n
\t\tvar y = (h/2 - this.contentH*current_zoom/2);\n
\t\n
\t\tassignAttributes(svgcontent, {\n
\t\t\twidth: this.contentW*current_zoom,\n
\t\t\theight: this.contentH*current_zoom,\n
\t\t\t\'x\': x,\n
\t\t\t\'y\': y,\n
\t\t\t"viewBox" : "0 0 " + this.contentW + " " + this.contentH\n
\t\t});\n
\t\t\n
\t\tassignAttributes(bg, {\n
\t\t\twidth: svgcontent.getAttribute(\'width\'),\n
\t\t\theight: svgcontent.getAttribute(\'height\'),\n
\t\t\tx: x,\n
\t\t\ty: y\n
\t\t});\n
\t\t\n
\t\tselectorManager.selectorParentGroup.setAttribute("transform","translate(" + x + "," + y + ")");\n
\t\t\n
\t\treturn {x:x, y:y, old_x:old_x, old_y:old_y, d_x:x - old_x, d_y:y - old_y};\n
\t}\n
\n
\tthis.getStrokedBBox = function(elems) {\n
\t\tif(!elems) elems = canvas.getVisibleElements();\n
\t\tif(!elems.length) return false;\n
\t\t// Make sure the expected BBox is returned if the element is a group\n
\t\tvar getCheckedBBox = function(elem) {\n
\t\t\n
\t\t\ttry {\n
\t\t\t\t// TODO: Fix issue with rotated groups. Currently they work\n
\t\t\t\t// fine in FF, but not in other browsers (same problem mentioned\n
\t\t\t\t// in Issue 339 comment #2).\n
\t\t\t\t\n
\t\t\t\tvar bb = canvas.getBBox(elem);\n
\t\t\t\t\n
\t\t\t\tvar angle = canvas.getRotationAngle(elem);\n
\t\t\t\tif ((angle && angle % 90) || hasMatrixTransform(canvas.getTransformList(elem))) {\n
\t\t\t\t\t// Accurate way to get BBox of rotated element in Firefox:\n
\t\t\t\t\t// Put element in group and get its BBox\n
\t\t\t\t\t\n
\t\t\t\t\tvar good_bb = false;\n
\t\t\t\t\t\n
\t\t\t\t\t// Get the BBox from the raw path for these elements\n
\t\t\t\t\tvar elemNames = [\'ellipse\',\'path\',\'line\',\'polyline\',\'polygon\'];\n
\t\t\t\t\tif($.inArray(elem.tagName, elemNames) != -1) {\n
\t\t\t\t\t\tbb = good_bb = canvas.convertToPath(elem, true, angle);\n
\t\t\t\t\t} else if(elem.tagName == \'rect\') {\n
\t\t\t\t\t\t// Look for radius\n
\t\t\t\t\t\tvar rx = elem.getAttribute(\'rx\');\n
\t\t\t\t\t\tvar ry = elem.getAttribute(\'ry\');\n
\t\t\t\t\t\tif(rx || ry) {\n
\t\t\t\t\t\t\tbb = good_bb = canvas.convertToPath(elem, true, angle);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(!good_bb) {\n
\t\t\t\t\t\tvar g = document.createElementNS(svgns, "g");\n
\t\t\t\t\t\tvar parent = elem.parentNode;\n
\t\t\t\t\t\tparent.replaceChild(g, elem);\n
\t\t\t\t\t\tg.appendChild(elem);\n
\t\t\t\t\t\tbb = g.getBBox();\n
\t\t\t\t\t\tparent.insertBefore(elem,g);\n
\t\t\t\t\t\tparent.removeChild(g);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\n
\t\t\t\t\t// Old method: Works by giving the rotated BBox,\n
\t\t\t\t\t// this is (unfortunately) what Opera and Safari do\n
\t\t\t\t\t// natively when getting the BBox of the parent group\n
// \t\t\t\t\t\tvar angle = angle * Math.PI / 180.0;\n
// \t\t\t\t\t\tvar rminx = Number.MAX_VALUE, rminy = Number.MAX_VALUE, \n
// \t\t\t\t\t\t\trmaxx = Number.MIN_VALUE, rmaxy = Number.MIN_VALUE;\n
// \t\t\t\t\t\tvar cx = round(bb.x + bb.width/2),\n
// \t\t\t\t\t\t\tcy = round(bb.y + bb.height/2);\n
// \t\t\t\t\t\tvar pts = [ [bb.x - cx, bb.y - cy], \n
// \t\t\t\t\t\t\t\t\t[bb.x + bb.width - cx, bb.y - cy],\n
// \t\t\t\t\t\t\t\t\t[bb.x + bb.width - cx, bb.y + bb.height - cy],\n
// \t\t\t\t\t\t\t\t\t[bb.x - cx, bb.y + bb.height - cy] ];\n
// \t\t\t\t\t\tvar j = 4;\n
// \t\t\t\t\t\twhile (j--) {\n
// \t\t\t\t\t\t\tvar x = pts[j][0],\n
// \t\t\t\t\t\t\t\ty = pts[j][1],\n
// \t\t\t\t\t\t\t\tr = Math.sqrt( x*x + y*y );\n
// \t\t\t\t\t\t\tvar theta = Math.atan2(y,x) + angle;\n
// \t\t\t\t\t\t\tx = round(r * Math.cos(theta) + cx);\n
// \t\t\t\t\t\t\ty = round(r * Math.sin(theta) + cy);\n
// \t\t\n
// \t\t\t\t\t\t\t// now set the bbox for the shape after it\'s been rotated\n
// \t\t\t\t\t\t\tif (x < rminx) rminx = x;\n
// \t\t\t\t\t\t\tif (y < rminy) rminy = y;\n
// \t\t\t\t\t\t\tif (x > rmaxx) rmaxx = x;\n
// \t\t\t\t\t\t\tif (y > rmaxy) rmaxy = y;\n
// \t\t\t\t\t\t}\n
// \t\t\t\t\t\t\n
// \t\t\t\t\t\tbb.x = rminx;\n
// \t\t\t\t\t\tbb.y = rminy;\n
// \t\t\t\t\t\tbb.width = rmaxx - rminx;\n
// \t\t\t\t\t\tbb.height = rmaxy - rminy;\n
\t\t\t\t}\n
\t\t\t\n
\t\t\t\treturn bb;\n
\t\t\t} catch(e) { \n
\t\t\t\tconsole.log(elem, e);\n
\t\t\t\treturn null;\n
\t\t\t} \n
\n
\t\t}\n
\t\tvar full_bb;\n
\t\t$.each(elems, function() {\n
\t\t\tif(full_bb) return;\n
\t\t\tif(!this.parentNode) return;\n
\t\t\tfull_bb = getCheckedBBox(this);\n
\t\t});\n
\t\t\n
\t\t// This shouldn\'t ever happen...\n
\t\tif(full_bb == null) return null;\n
\t\t\n
\t\t// full_bb doesn\'t include the stoke, so this does no good!\n
// \t\tif(elems.length == 1) return full_bb;\n
\t\t\n
\t\tvar max_x = full_bb.x + full_bb.width;\n
\t\tvar max_y = full_bb.y + full_bb.height;\n
\t\tvar min_x = full_bb.x;\n
\t\tvar min_y = full_bb.y;\n
\t\t\n
\t\t// FIXME: same re-creation problem with this function as getCheckedBBox() above\n
\t\tvar getOffset = function(elem) {\n
\t\t\tvar sw = elem.getAttribute("stroke-width");\n
\t\t\tvar offset = 0;\n
\t\t\tif (elem.getAttribute("stroke") != "none" && !isNaN(sw)) {\n
\t\t\t\toffset += sw/2;\n
\t\t\t}\n
\t\t\treturn offset;\n
\t\t}\n
\t\tvar bboxes = [];\n
\t\t$.each(elems, function(i, elem) {\n
\t\t\tvar cur_bb = getCheckedBBox(elem);\n
\t\t\tif(cur_bb) {\n
\t\t\t\tvar offset = getOffset(elem);\n
\t\t\t\tmin_x = Math.min(min_x, cur_bb.x - offset);\n
\t\t\t\tmin_y = Math.min(min_y, cur_bb.y - offset);\n
\t\t\t\tbboxes.push(cur_bb);\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tfull_bb.x = min_x;\n
\t\tfull_bb.y = min_y;\n
\t\t\n
\t\t$.each(elems, function(i, elem) {\n
\t\t\tvar cur_bb = bboxes[i];\n
\t\t\t// ensure that elem is really an element node\n
\t\t\tif (cur_bb && elem.nodeType == 1) {\n
\t\t\t\tvar offset = getOffset(elem);\n
\t\t\t\tmax_x = Math.max(max_x, cur_bb.x + cur_bb.width + offset);\n
\t\t\t\tmax_y = Math.max(max_y, cur_bb.y + cur_bb.height + offset);\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\tfull_bb.width = max_x - min_x;\n
\t\tfull_bb.height = max_y - min_y;\n
\t\treturn full_bb;\n
\t}\n
\n
\tthis.getVisibleElements = function(parent, includeBBox) {\n
\t\tif(!parent) parent = $(svgcontent).children(); // Prevent layers from being included\n
\t\t\n
\t\tvar contentElems = [];\n
\t\t$(parent).children().each(function(i, elem) {\n
\t\t\ttry {\n
\t\t\t\tvar box = elem.getBBox();\n
\t\t\t\tif (box) {\n
\t\t\t\t\tvar item = includeBBox?{\'elem\':elem, \'bbox\':canvas.getStrokedBBox([elem])}:elem;\n
\t\t\t\t\tcontentElems.push(item);\n
\t\t\t\t}\n
\t\t\t} catch(e) {}\n
\t\t});\n
\t\treturn contentElems.reverse();\n
\t}\n
\t\n
\tthis.cycleElement = function(next) {\n
\t\tvar cur_elem = selectedElements[0];\n
\t\tvar elem = false;\n
\t\tvar all_elems = this.getVisibleElements(current_layer);\n
\t\tif (cur_elem == null) {\n
\t\t\tvar num = next?all_elems.length-1:0;\n
\t\t\telem = all_elems[num];\n
\t\t} else {\n
\t\t\tvar i = all_elems.length;\n
\t\t\twhile(i--) {\n
\t\t\t\tif(all_elems[i] == cur_elem) {\n
\t\t\t\t\tvar num = next?i-1:i+1;\n
\t\t\t\t\tif(num >= all_elems.length) {\n
\t\t\t\t\t\tnum = 0;\n
\t\t\t\t\t} else if(num < 0) {\n
\t\t\t\t\t\tnum = all_elems.length-1;\n
\t\t\t\t\t} \n
\t\t\t\t\telem = all_elems[num];\n
\t\t\t\t\tbreak;\n
\t\t\t\t} \n
\t\t\t}\n
\t\t}\t\t\n
\t\tcanvas.clearSelection();\n
\t\tcanvas.addToSelection([elem], true);\n
\t\tcall("selected", selectedElements);\n
\t}\n
\n
\tvar resetUndoStack = function() {\n
\t\tundoStack = [];\n
\t\tundoStackPointer = 0;\n
\t};\n
\n
\tthis.getUndoStackSize = function() { return undoStackPointer; };\n
\tthis.getRedoStackSize = function() { return undoStack.length - undoStackPointer; };\n
\n
\tthis.getNextUndoCommandText = function() { \n
\t\tif (undoStackPointer > 0) \n
\t\t\treturn undoStack[undoStackPointer-1].text;\n
\t\treturn "";\n
\t};\n
\tthis.getNextRedoCommandText = function() { \n
\t\tif (undoStackPointer < undoStack.length) \n
\t\t\treturn undoStack[undoStackPointer].text;\n
\t\treturn "";\n
\t};\n
\n
\tthis.undo = function() {\n
\t\tif (undoStackPointer > 0) {\n
\t\t\tthis.clearSelection();\n
\t\t\tvar cmd = undoStack[--undoStackPointer];\n
\t\t\tcmd.unapply();\n
\t\t\tpathActions.clear();\n
\t\t\tcall("changed", cmd.elements());\n
\t\t}\n
\t};\n
\tthis.redo = function() {\n
\t\tif (undoStackPointer < undoStack.length && undoStack.length > 0) {\n
\t\t\tthis.clearSelection();\n
\t\t\tvar cmd = undoStack[undoStackPointer++];\n
\t\t\tcmd.apply();\n
\t\t\tpathActions.clear();\n
\t\t\tcall("changed", cmd.elements());\n
\t\t}\n
\t};\n
\n
\t// this function no longer uses cloneNode because we need to update the id\n
\t// of every copied element (even the descendants)\n
\t// we also do it manually because Opera/Win/non-EN puts , instead of .\n
\tvar copyElem = function(el) {\n
\t\t// manually create a copy of the element\n
\t\tvar new_el = document.createElementNS(el.namespaceURI, el.nodeName);\n
\t\t$.each(el.attributes, function(i, attr) {\n
\t\t\tif (attr.localName != \'-moz-math-font-style\') {\n
\t\t\t\tnew_el.setAttributeNS(attr.namespaceURI, attr.nodeName, attr.nodeValue);\n
\t\t\t}\n
\t\t});\n
\t\t// set the copied element\'s new id\n
\t\tnew_el.removeAttribute("id");\n
\t\tnew_el.id = getNextId();\n
\t\t// manually increment obj_num because our cloned elements are not in the DOM yet\n
\t\tobj_num++; \n
\t\t\n
\t\t// Opera\'s "d" value needs to be reset for Opera/Win/non-EN\n
\t\t// Also needed for webkit (else does not keep curved segments on clone)\n
\t\tif((isWebkit || !support.goodDecimals) && el.nodeName == \'path\') {\n
\t\t\tvar fixed_d = pathActions.convertPath(el);\n
\t\t\tnew_el.setAttribute(\'d\', fixed_d);\n
\t\t}\n
\n
\t\t// now create copies of all children\n
\t\t$.each(el.childNodes, function(i, child) {\n
\t\t\tswitch(child.nodeType) {\n
\t\t\t\tcase 1: // element node\n
\t\t\t\t\tnew_el.appendChild(copyElem(child));\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase 3: // text node\n
\t\t\t\t\tnew_el.textContent = child.nodeValue;\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault:\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t});\n
\t\tif(new_el.tagName == \'image\') {\n
\t\t\tpreventClickDefault(new_el);\n
\t\t}\n
\t\treturn new_el;\n
\t};\n
\t\n
\tvar preventClickDefault = function(img) {\n
     \t$(img).click(function(e){e.preventDefault()});\n
\t}\n
\t\n
\t// this creates deep DOM copies (clones) of all selected elements\n
\tthis.cloneSelectedElements = function() {\n
\t\tvar batchCmd = new BatchCommand("Clone Elements");\n
\t\t// find all the elements selected (stop at first null)\n
\t\tvar len = selectedElements.length;\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tif (elem == null) break;\n
\t\t}\n
\t\t// use slice to quickly get the subset of elements we need\n
\t\tvar copiedElements = selectedElements.slice(0,i);\n
\t\tthis.clearSelection();\n
\t\t// note that we loop in the reverse way because of the way elements are added\n
\t\t// to the selectedElements array (top-first)\n
\t\tvar i = copiedElements.length;\n
\t\twhile (i--) {\n
\t\t\t// clone each element and replace it within copiedElements\n
\t\t\tvar elem = copiedElements[i] = copyElem(copiedElements[i]);\n
\t\t\tcurrent_layer.appendChild(elem);\n
\t\t\tbatchCmd.addSubCommand(new InsertElementCommand(elem));\n
\t\t}\n
\t\t\n
\t\tif (!batchCmd.isEmpty()) {\n
\t\t\tthis.addToSelection(copiedElements.reverse()); // Need to reverse for correct selection-adding\n
\t\t\tthis.moveSelectedElements(20,20,false);\n
\t\t\taddCommandToHistory(batchCmd);\n
\t\t\tcall("selected", selectedElements);\n
\t\t}\n
\t};\n
\n
\tthis.setBackground = function(color, url) {\n
\t\tvar bg =  getElem(\'canvasBackground\');\n
\t\tvar border = $(bg).find(\'rect\')[0];\n
\t\tvar bg_img = getElem(\'background_image\');\n
\t\tborder.setAttribute(\'fill\',color);\n
\t\tif(url) {\n
\t\t\tif(!bg_img) {\n
\t\t\t\tbg_img = svgdoc.createElementNS(svgns, "image");\n
\t\t\t\tassignAttributes(bg_img, {\n
\t\t\t\t\t\'id\': \'background_image\',\n
\t\t\t\t\t\'width\': \'100%\',\n
\t\t\t\t\t\'height\': \'100%\',\n
\t\t\t\t\t\'preserveAspectRatio\': \'xMinYMin\',\n
\t\t\t\t\t\'style\':\'pointer-events:none\'\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\tbg_img.setAttributeNS(xlinkns, "xlink:href", url);\n
\t\t\tbg.appendChild(bg_img);\n
\t\t} else if(bg_img) {\n
\t\t\tbg_img.parentNode.removeChild(bg_img);\n
\t\t}\n
\t}\n
\n
\t// aligns selected elements (type is a char - see switch below for explanation)\n
\t// relative_to can be "selected", "largest", "smallest", "page"\n
\tthis.alignSelectedElements = function(type, relative_to) {\n
\t\tvar bboxes = [], angles = [];\n
\t\tvar minx = Number.MAX_VALUE, maxx = Number.MIN_VALUE, miny = Number.MAX_VALUE, maxy = Number.MIN_VALUE;\n
\t\tvar curwidth = Number.MIN_VALUE, curheight = Number.MIN_VALUE;\n
\t\tvar len = selectedElements.length;\n
\t\tif (!len) return;\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tif (selectedElements[i] == null) break;\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tbboxes[i] = canvas.getStrokedBBox([elem]);\n
\t\t\t\n
\t\t\t// now bbox is axis-aligned and handles rotation\n
\t\t\tswitch (relative_to) {\n
\t\t\t\tcase \'smallest\':\n
\t\t\t\t\tif ( (type == \'l\' || type == \'c\' || type == \'r\') && (curwidth == Number.MIN_VALUE || curwidth > bboxes[i].width) ||\n
\t\t\t\t\t     (type == \'t\' || type == \'m\' || type == \'b\') && (curheight == Number.MIN_VALUE || curheight > bboxes[i].height) ) {\n
\t\t\t\t\t\tminx = bboxes[i].x;\n
\t\t\t\t\t\tminy = bboxes[i].y;\n
\t\t\t\t\t\tmaxx = bboxes[i].x + bboxes[i].width;\n
\t\t\t\t\t\tmaxy = bboxes[i].y + bboxes[i].height;\n
\t\t\t\t\t\tcurwidth = bboxes[i].width;\n
\t\t\t\t\t\tcurheight = bboxes[i].height;\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'largest\':\n
\t\t\t\t\tif ( (type == \'l\' || type == \'c\' || type == \'r\') && (curwidth == Number.MIN_VALUE || curwidth < bboxes[i].width) ||\n
\t\t\t\t\t     (type == \'t\' || type == \'m\' || type == \'b\') && (curheight == Number.MIN_VALUE || curheight < bboxes[i].height) ) {\n
\t\t\t\t\t\tminx = bboxes[i].x;\n
\t\t\t\t\t\tminy = bboxes[i].y;\n
\t\t\t\t\t\tmaxx = bboxes[i].x + bboxes[i].width;\n
\t\t\t\t\t\tmaxy = bboxes[i].y + bboxes[i].height;\n
\t\t\t\t\t\tcurwidth = bboxes[i].width;\n
\t\t\t\t\t\tcurheight = bboxes[i].height;\n
\t\t\t\t\t}\n
\t\t\t\t\tbreak;\n
\t\t\t\tdefault: // \'selected\'\n
\t\t\t\t\tif (bboxes[i].x < minx) minx = bboxes[i].x;\n
\t\t\t\t\tif (bboxes[i].y < miny) miny = bboxes[i].y;\n
\t\t\t\t\tif (bboxes[i].x + bboxes[i].width > maxx) maxx = bboxes[i].x + bboxes[i].width;\n
\t\t\t\t\tif (bboxes[i].y + bboxes[i].height > maxy) maxy = bboxes[i].y + bboxes[i].height;\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t} // loop for each element to find the bbox and adjust min/max\n
\n
\t\tif (relative_to == \'page\') {\n
\t\t\tminx = 0;\n
\t\t\tminy = 0;\n
\t\t\tmaxx = canvas.contentW;\n
\t\t\tmaxy = canvas.contentH;\n
\t\t}\n
\n
\t\tvar dx = new Array(len);\n
\t\tvar dy = new Array(len);\n
\t\tfor (var i = 0; i < len; ++i) {\n
\t\t\tif (selectedElements[i] == null) break;\n
\t\t\tvar elem = selectedElements[i];\n
\t\t\tvar bbox = bboxes[i];\n
\t\t\tdx[i] = 0;\n
\t\t\tdy[i] = 0;\n
\t\t\tswitch (type) {\n
\t\t\t\tcase \'l\': // left (horizontal)\n
\t\t\t\t\tdx[i] = minx - bbox.x;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'c\': // center (horizontal)\n
\t\t\t\t\tdx[i] = (minx+maxx)/2 - (bbox.x + bbox.width/2);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'r\': // right (horizontal)\n
\t\t\t\t\tdx[i] = maxx - (bbox.x + bbox.width);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'t\': // top (vertical)\n
\t\t\t\t\tdy[i] = miny - bbox.y;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'m\': // middle (vertical)\n
\t\t\t\t\tdy[i] = (miny+maxy)/2 - (bbox.y + bbox.height/2);\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase \'b\': // bottom (vertical)\n
\t\t\t\t\tdy[i] = maxy - (bbox.y + bbox.height);\n
\t\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\t\tthis.moveSelectedElements(dx,dy);\n
\t};\n
\tthis.getZoom = function(){return current_zoom;};\n
\t\n
\t// Function: getVersion\n
\t// Returns a string which describes the revision number of SvgCanvas.\n
\tthis.getVersion = function() {\n
\t\treturn "svgcanvas.js ($Rev: 1600 $)";\n
\t};\n
\t\n
\tthis.setUiStrings = function(strs) {\n
\t\t$.extend(uiStrings, strs);\n
\t}\n
\n
\tthis.setConfig = function(opts) {\n
\t\t$.extend(curConfig, opts);\n
\t}\n
\t\n
\tthis.clear();\n
\n
\tfunction getElem(id) {\n
\t\tif(svgroot.querySelector) {\n
\t\t\t// querySelector lookup\n
\t\t\treturn svgroot.querySelector(\'#\'+id);\n
\t\t} else if(svgdoc.evaluate) {\n
\t\t\t// xpath lookup\n
\t\t\treturn svgdoc.evaluate(\'svg:svg[@id="svgroot"]//svg:*[@id="\'+id+\'"]\', container, function() { return "http://www.w3.org/2000/svg"; }, 9, null).singleNodeValue;\n
\t\t} else {\n
\t\t\t// jQuery lookup: twice as slow as xpath in FF\n
\t\t\treturn $(svgroot).find(\'[id=\' + id + \']\')[0];\n
\t\t}\n
\t\t\n
\t\t// getElementById lookup: includes icons, not good\n
\t\t// return svgdoc.getElementById(id);\n
\t}\n
\t\n
\t// Being able to access private methods publicly seems wrong somehow,\n
\t// but currently appears to be the best way to allow testing and provide\n
\t// access to them to plugins.\n
\tthis.getPrivateMethods = function() {\n
\t\treturn {\n
\t\t\taddCommandToHistory: addCommandToHistory,\n
\t\t\taddGradient: addGradient,\n
\t\t\taddSvgElementFromJson: addSvgElementFromJson,\n
\t\t\tassignAttributes: assignAttributes,\n
\t\t\tBatchCommand: BatchCommand,\n
\t\t\tcall: call,\n
\t\t\tChangeElementCommand: ChangeElementCommand,\n
\t\t\tcleanupElement: cleanupElement,\n
\t\t\tcopyElem: copyElem,\n
\t\t\tffClone: ffClone,\n
\t\t\tfindDefs: findDefs,\n
\t\t\tfindDuplicateGradient: findDuplicateGradient,\n
\t\t\tfromXml: fromXml,\n
\t\t\tgetElem: getElem,\n
\t\t\tgetId: getId,\n
\t\t\tgetIntersectionList: getIntersectionList,\n
\t\t\tgetMouseTarget: getMouseTarget,\n
\t\t\tgetNextId: getNextId,\n
\t\t\tgetPathBBox: getPathBBox,\n
\t\t\tgetUrlFromAttr: getUrlFromAttr,\n
\t\t\thasMatrixTransform: hasMatrixTransform,\n
\t\t\tidentifyLayers: identifyLayers,\n
\t\t\tInsertElementCommand: InsertElementCommand,\n
\t\t\tisIdentity: isIdentity,\n
\t\t\tlogMatrix: logMatrix,\n
\t\t\tmatrixMultiply: matrixMultiply,\n
\t\t\tMoveElementCommand: MoveElementCommand,\n
\t\t\tpreventClickDefault: preventClickDefault,\n
\t\t\trecalculateAllSelectedDimensions: recalculateAllSelectedDimensions,\n
\t\t\trecalculateDimensions: recalculateDimensions,\n
\t\t\tremapElement: remapElement,\n
\t\t\tRemoveElementCommand: RemoveElementCommand,\n
\t\t\tremoveUnusedDefElems: removeUnusedDefElems,\n
\t\t\tresetUndoStack: resetUndoStack,\n
\t\t\tround: round,\n
\t\t\trunExtensions: runExtensions,\n
\t\t\tsanitizeSvg: sanitizeSvg,\n
\t\t\tSelector: Selector,\n
\t\t\tSelectorManager: SelectorManager,\n
\t\t\tshortFloat: shortFloat,\n
\t\t\tsvgCanvasToString: svgCanvasToString,\n
\t\t\tSVGEditTransformList: SVGEditTransformList,\n
\t\t\tsvgToString: svgToString,\n
\t\t\ttoString: toString,\n
\t\t\ttoXml: toXml,\n
\t\t\ttransformBox: transformBox,\n
\t\t\ttransformListToTransform: transformListToTransform,\n
\t\t\ttransformPoint: transformPoint,\n
\t\t\ttransformToObj: transformToObj,\n
\t\t\twalkTree: walkTree\n
\t\t}\n
\t}\n
\t\n
\tthis.addExtension = function(name, ext_func) {\n
\t\tif(!(name in extensions)) {\n
\t\t\t// Provide private vars/funcs here. Is there a better way to do this?\n
\t\t\tvar ext = ext_func($.extend(canvas.getPrivateMethods(), {\n
\t\t\t\tsvgroot: svgroot,\n
\t\t\t\tsvgcontent: svgcontent,\n
\t\t\t\tnonce: nonce,\n
\t\t\t\tselectorManager: selectorManager\n
\t\t\t}));\n
\t\t\textensions[name] = ext;\n
\t\t\tcall("extension_added", ext);\n
\t\t} else {\n
\t\t\tconsole.log(\'Cannot add extension "\' + name + \'", an extension by that name already exists"\');\n
\t\t}\n
\t};\n
\t\n
\t// Test support for features/bugs\n
\t(function() {\n
\t\t// segList functions (for FF1.5 and 2.0)\n
\t\tvar path = document.createElementNS(svgns,\'path\');\n
\t\tpath.setAttribute(\'d\',\'M0,0 10,10\');\n
\t\tvar seglist = path.pathSegList;\n
\t\tvar seg = path.createSVGPathSegLinetoAbs(5,5);\n
\t\ttry {\n
\t\t\tseglist.replaceItem(seg, 0);\n
\t\t\tsupport.pathReplaceItem = true;\n
\t\t} catch(err) {\n
\t\t\tsupport.pathReplaceItem = false;\n
\t\t}\n
\t\t\n
\t\ttry {\n
\t\t\tseglist.insertItemBefore(seg, 0);\n
\t\t\tsupport.pathInsertItemBefore = true;\n
\t\t} catch(err) {\n
\t\t\tsupport.pathInsertItemBefore = false;\n
\t\t}\n
\t\t\n
\t\t// TODO: Find better way to check support for this\n
\t\tsupport.editableText = isOpera;\n
\t\t\n
\t\t// Correct decimals on clone attributes (Opera/win/non-en)\n
\t\tvar rect = document.createElementNS(svgns,\'rect\');\n
\t\trect.setAttribute(\'x\',.1);\n
\t\tvar crect = rect.cloneNode(false);\n
\t\tsupport.goodDecimals = (crect.getAttribute(\'x\').indexOf(\',\') == -1);\n
\t\t\n
\t\t// Get correct em/ex values\n
\t\tvar rect = document.createElementNS(svgns,\'rect\');\n
\t\trect.setAttribute(\'width\',"1em");\n
\t\trect.setAttribute(\'height\',"1ex");\n
\t\tsvgcontent.appendChild(rect);\n
\t\tvar bb = rect.getBBox();\n
\t\tunit_types.em = bb.width;\n
\t\tunit_types.ex = bb.height;\n
\t\tsvgcontent.removeChild(rect);\n
\t}());\n
}\n
// Static class for various utility functions\n
\n
var Utils = {\n
\n
// This code was written by Tyler Akins and has been placed in the\n
// public domain.  It would be nice if you left this header intact.\n
// Base64 code from Tyler Akins -- http://rumkin.com\n
\n
// schiller: Removed string concatenation in favour of Array.join() optimization,\n
//           also precalculate the size of the array needed.\n
\n
\t"_keyStr" : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",\n
\n
\t"encode64" : function(input) {\n
\t\t// base64 strings are 4/3 larger than the original string\n
//\t\tinput = Utils.encodeUTF8(input); // convert non-ASCII characters\n
\t\tinput = Utils.convertToXMLReferences(input);\n
\t\tif(window.btoa) return window.btoa(input); // Use native if available\n
\t\tvar output = new Array( Math.floor( (input.length + 2) / 3 ) * 4 );\n
\t\tvar chr1, chr2, chr3;\n
\t\tvar enc1, enc2, enc3, enc4;\n
\t\tvar i = 0, p = 0;\n
\n
\t\tdo {\n
\t\t\tchr1 = input.charCodeAt(i++);\n
\t\t\tchr2 = input.charCodeAt(i++);\n
\t\t\tchr3 = input.charCodeAt(i++);\n
\n
\t\t\tenc1 = chr1 >> 2;\n
\t\t\tenc2 = ((chr1 & 3) << 4) | (chr2 >> 4);\n
\t\t\tenc3 = ((chr2 & 15) << 2) | (chr3 >> 6);\n
\t\t\tenc4 = chr3 & 63;\n
\n
\t\t\tif (isNaN(chr2)) {\n
\t\t\t\tenc3 = enc4 = 64;\n
\t\t\t} else if (isNaN(chr3)) {\n
\t\t\t\tenc4 = 64;\n
\t\t\t}\n
\n
\t\t\toutput[p++] = this._keyStr.charAt(enc1);\n
\t\t\toutput[p++] = this._keyStr.charAt(enc2);\n
\t\t\toutput[p++] = this._keyStr.charAt(enc3);\n
\t\t\toutput[p++] = this._keyStr.charAt(enc4);\n
\t\t} while (i < input.length);\n
\n
\t\treturn output.join(\'\');\n
\t},\n
\t\n
\t"decode64" : function(input) {\n
\t\tif(window.atob) return window.atob(input);\n
\t\tvar output = "";\n
\t\tvar chr1, chr2, chr3 = "";\n
\t\tvar enc1, enc2, enc3, enc4 = "";\n
\t\tvar i = 0;\n
\t\n
\t\t // remove all characters that are not A-Z, a-z, 0-9, +, /, or =\n
\t\t input = input.replace(/[^A-Za-z0-9\\+\\/\\=]/g, "");\n
\t\n
\t\t do {\n
\t\t\tenc1 = this._keyStr.indexOf(input.charAt(i++));\n
\t\t\tenc2 = this._keyStr.indexOf(input.charAt(i++));\n
\t\t\tenc3 = this._keyStr.indexOf(input.charAt(i++));\n
\t\t\tenc4 = this._keyStr.indexOf(input.charAt(i++));\n
\t\n
\t\t\tchr1 = (enc1 << 2) | (enc2 >> 4);\n
\t\t\tchr2 = ((enc2 & 15) << 4) | (enc3 >> 2);\n
\t\t\tchr3 = ((enc3 & 3) << 6) | enc4;\n
\t\n
\t\t\toutput = output + String.fromCharCode(chr1);\n
\t\n
\t\t\tif (enc3 != 64) {\n
\t\t\t   output = output + String.fromCharCode(chr2);\n
\t\t\t}\n
\t\t\tif (enc4 != 64) {\n
\t\t\t   output = output + String.fromCharCode(chr3);\n
\t\t\t}\n
\t\n
\t\t\tchr1 = chr2 = chr3 = "";\n
\t\t\tenc1 = enc2 = enc3 = enc4 = "";\n
\t\n
\t\t } while (i < input.length);\n
\t\t return unescape(output);\n
\t},\n
\t\n
\t// based on http://phpjs.org/functions/utf8_encode:577\n
\t// codedread:does not seem to work with webkit-based browsers on OSX\n
\t"encodeUTF8": function(input) {\n
\t\t//return unescape(encodeURIComponent(input)); //may or may not work\n
\t\tvar output = \'\';\n
\t\tfor (var n = 0; n < input.length; n++){\n
\t\t\tvar c = input.charCodeAt(n);\n
\t\t\tif (c < 128) {\n
\t\t\t\toutput += input[n];\n
\t\t\t}\n
\t\t\telse if (c > 127) {\n
\t\t\t\tif (c < 2048){\n
\t\t\t\t\toutput += String.fromCharCode((c >> 6) | 192);\n
\t\t\t\t} \n
\t\t\t\telse {\n
\t\t\t\t\toutput += String.fromCharCode((c >> 12) | 224) + String.fromCharCode((c >> 6) & 63 | 128);\n
\t\t\t\t}\n
\t\t\t\toutput += String.fromCharCode((c & 63) | 128);\n
\t\t\t}\n
\t\t}\n
\t\treturn output;\n
\t},\n
\t\n
\t"convertToXMLReferences": function(input) {\n
\t\tvar output = \'\';\n
\t\tfor (var n = 0; n < input.length; n++){\n
\t\t\tvar c = input.charCodeAt(n);\n
\t\t\tif (c < 128) {\n
\t\t\t\toutput += input[n];\n
\t\t\t}\n
\t\t\telse if(c > 127) {\n
\t\t\t\toutput += ("&#" + c + ";");\n
\t\t\t}\n
\t\t}\n
\t\treturn output;\n
\t},\n
\n
\t"rectsIntersect": function(r1, r2) {\n
\t\treturn r2.x < (r1.x+r1.width) && \n
\t\t\t(r2.x+r2.width) > r1.x &&\n
\t\t\tr2.y < (r1.y+r1.height) &&\n
\t\t\t(r2.y+r2.height) > r1.y;\n
\t},\n
\n
\t"snapToAngle": function(x1,y1,x2,y2) {\n
\t\tvar snap = Math.PI/4; // 45 degrees\n
\t\tvar dx = x2 - x1;\n
\t\tvar dy = y2 - y1;\n
\t\tvar angle = Math.atan2(dy,dx);\n
\t\tvar dist = Math.sqrt(dx * dx + dy * dy);\n
\t\tvar snapangle= Math.round(angle/snap)*snap;\n
\t\tvar x = x1 + dist*Math.cos(snapangle);\t\n
\t\tvar y = y1 + dist*Math.sin(snapangle);\n
\t\t//console.log(x1,y1,x2,y2,x,y,angle)\n
\t\treturn {x:x, y:y, a:snapangle};\n
\t},\n
\t\n
\t// found this function http://groups.google.com/group/jquery-dev/browse_thread/thread/c6d11387c580a77f\n
\t"text2xml": function(sXML) {\n
\t\t// NOTE: I\'d like to use jQuery for this, but jQuery makes all tags uppercase\n
\t\t//return $(xml)[0];\n
\t\tvar out;\n
\t\ttry{\n
\t\t\tvar dXML = ($.browser.msie)?new ActiveXObject("Microsoft.XMLDOM"):new DOMParser();\n
\t\t\tdXML.async = false;\n
\t\t} catch(e){ \n
\t\t\tthrow new Error("XML Parser could not be instantiated"); \n
\t\t};\n
\t\ttry{\n
\t\t\tif($.browser.msie) out = (dXML.loadXML(sXML))?dXML:false;\n
\t\t\telse out = dXML.parseFromString(sXML, "text/xml");\n
\t\t}\n
\t\tcatch(e){ throw new Error("Error parsing XML string"); };\n
\t\treturn out;\n
\t}\n
\n
};\n


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
