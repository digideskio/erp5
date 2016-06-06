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
            <value> <string>anonymous_http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts52852111.41</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>browser.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/**\n
 * Package: svgedit.browser\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Jeff Schiller\n
 * Copyright(c) 2010 Alexis Deveria\n
 */\n
\n
// Dependencies:\n
// 1) jQuery (for $.alert())\n
\n
var svgedit = svgedit || {};\n
\n
(function() {\n
\n
if (!svgedit.browser) {\n
  svgedit.browser = {};\n
}\n
var supportsSvg_ = (function() {\n
        return !!document.createElementNS && !!document.createElementNS(\'http://www.w3.org/2000/svg\', \'svg\').createSVGRect;\n
})();\n
svgedit.browser.supportsSvg = function() { return supportsSvg_; }\n
if(!svgedit.browser.supportsSvg()) {\n
  window.location = "browser-not-supported.html";\n
}\n
else{\n
\n
var svgns = \'http://www.w3.org/2000/svg\';\n
var userAgent = navigator.userAgent;\n
var svg = document.createElementNS(svgns, \'svg\');\n
\n
// Note: Browser sniffing should only be used if no other detection method is possible\n
var isOpera_ = !!window.opera;\n
var isWebkit_ = userAgent.indexOf("AppleWebKit") >= 0;\n
var isGecko_ = userAgent.indexOf(\'Gecko/\') >= 0;\n
var isIE_ = userAgent.indexOf(\'MSIE\') >= 0;\n
var isChrome_ = userAgent.indexOf(\'Chrome/\') >= 0;\n
var isWindows_ = userAgent.indexOf(\'Windows\') >= 0;\n
var isMac_ = userAgent.indexOf(\'Macintosh\') >= 0;\n
var isTouch_ = \'ontouchstart\' in window;\n
\n
var supportsSelectors_ = (function() {\n
  return !!svg.querySelector;\n
})();\n
\n
var supportsXpath_ = (function() {\n
  return !!document.evaluate;\n
})();\n
\n
// text character positioning (for IE9)\n
var supportsGoodTextCharPos_ = (function() {\n
   var retValue = false;\n
   var svgroot = document.createElementNS(svgns, \'svg\');\n
   var svgcontent = document.createElementNS(svgns, \'svg\');\n
   document.documentElement.appendChild(svgroot);\n
   svgcontent.setAttribute(\'x\', 5);\n
   svgroot.appendChild(svgcontent);\n
   var text = document.createElementNS(svgns,\'text\');\n
   text.textContent = \'a\';\n
   svgcontent.appendChild(text);\n
   var pos = text.getStartPositionOfChar(0)\n
   pos = pos.x; //if you put it on one line it fails when compiled\n
   document.documentElement.removeChild(svgroot);\n
   return (pos === 0);\n
})();\n
\n
var supportsPathBBox_ = (function() {\n
  var svgcontent = document.createElementNS(svgns, \'svg\');\n
  document.documentElement.appendChild(svgcontent);\n
  var path = document.createElementNS(svgns, \'path\');\n
  path.setAttribute(\'d\',\'M0,0 C0,0 10,10 10,0\');\n
  svgcontent.appendChild(path);\n
  var bbox = path.getBBox();\n
  document.documentElement.removeChild(svgcontent);\n
  return (bbox.height > 4 && bbox.height < 5);\n
})();\n
\n
// Support for correct bbox sizing on groups with horizontal/vertical lines\n
var supportsHVLineContainerBBox_ = (function() {\n
  var svgcontent = document.createElementNS(svgns, \'svg\');\n
  document.documentElement.appendChild(svgcontent);\n
  var path = document.createElementNS(svgns, \'path\');\n
  path.setAttribute(\'d\',\'M0,0 10,0\');\n
  var path2 = document.createElementNS(svgns, \'path\');\n
  path2.setAttribute(\'d\',\'M5,0 15,0\');\n
  var g = document.createElementNS(svgns, \'g\');\n
  g.appendChild(path);\n
  g.appendChild(path2);\n
  svgcontent.appendChild(g);\n
  var bbox = g.getBBox();\n
  document.documentElement.removeChild(svgcontent);\n
  // Webkit gives 0, FF gives 10, Opera (correctly) gives 15\n
  return (bbox.width == 15);\n
})();\n
\n
var supportsEditableText_ = (function() {\n
  // TODO: Find better way to check support for this\n
  return isOpera_;\n
})();\n
\n
var supportsGoodDecimals_ = (function() {\n
  // Correct decimals on clone attributes (Opera < 10.5/win/non-en)\n
  var rect = document.createElementNS(svgns, \'rect\');\n
  rect.setAttribute(\'x\',.1);\n
  var crect = rect.cloneNode(false);\n
  var retValue = (crect.getAttribute(\'x\').indexOf(\',\') == -1);\n
  if(!retValue) {\n
    $.alert("NOTE: This version of Opera is known to contain bugs in SVG-edit.\\n\\\n
    Please upgrade to the <a href=\'http://opera.com\'>latest version</a> in which the problems have been fixed.");\n
  }\n
  return retValue;\n
})();\n
\n
var supportsNonScalingStroke_ = (function() {\n
  var rect = document.createElementNS(svgns, \'rect\');\n
  rect.setAttribute(\'style\',\'vector-effect:non-scaling-stroke\');\n
  return rect.style.vectorEffect === \'non-scaling-stroke\';\n
})();\n
\n
var supportsNativeSVGTransformLists_ = (function() {\n
  var rect = document.createElementNS(svgns, \'rect\');\n
  var rxform = rect.transform.baseVal;\n
  \n
  var t1 = svg.createSVGTransform();\n
  rxform.appendItem(t1);\n
  return rxform.getItem(0) == t1;\n
})();\n
\n
var supportsBlobs_ = (function() {\n
  if (typeof Blob != \'function\') return false;\n
  // check if download is supported\n
  var svg = new Blob(\n
    ["<svg xmlns=\'http://www.w3.org/2000/svg\'></svg>"],\n
    {type: "image/svg+xml;charset=utf-8"}\n
  );\n
  var img = new Image();\n
  var support = false;\n
  img.onload = function()  { svgedit.browser.supportsBlobs = function() {return true} };\n
  img.onerror = function() { svgedit.browser.supportsBlobs = function() {return false} };\n
  img.src = URL.createObjectURL(svg);\n
  return false;\n
})();\n
\n
\n
\n
// Public API\n
\n
svgedit.browser.isOpera = function() { return isOpera_; }\n
svgedit.browser.isWebkit = function() { return isWebkit_; }\n
svgedit.browser.isGecko = function() { return isGecko_; }\n
svgedit.browser.isIE = function() { return isIE_; }\n
svgedit.browser.isChrome = function() { return isChrome_; }\n
svgedit.browser.isWindows = function() { return isWindows_; }\n
svgedit.browser.isMac = function() { return isMac_; }\n
svgedit.browser.isTouch = function() { return isTouch_; }\n
\n
svgedit.browser.supportsSelectors = function() { return supportsSelectors_; }\n
svgedit.browser.supportsXpath = function() { return supportsXpath_; }\n
\n
svgedit.browser.supportsPathBBox = function() { return supportsPathBBox_; }\n
svgedit.browser.supportsHVLineContainerBBox = function() { return supportsHVLineContainerBBox_; }\n
svgedit.browser.supportsGoodTextCharPos = function() { return supportsGoodTextCharPos_; }\n
svgedit.browser.supportsEditableText = function() { return supportsEditableText_; }\n
svgedit.browser.supportsGoodDecimals = function() { return supportsGoodDecimals_; }\n
svgedit.browser.supportsNonScalingStroke = function() { return supportsNonScalingStroke_; }\n
svgedit.browser.supportsNativeTransformLists = function() { return supportsNativeSVGTransformLists_; }\n
svgedit.browser.supportsBlobs = function() {return supportsBlobs_; }\n
}\n
\n
})();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>6168</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
