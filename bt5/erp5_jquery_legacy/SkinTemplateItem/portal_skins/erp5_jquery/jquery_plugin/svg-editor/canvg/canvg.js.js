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
            <value> <string>ts80002936.33</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>canvg.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * canvg.js - Javascript SVG parser and renderer on Canvas\n
 * MIT Licensed \n
 * Gabe Lerner (gabelerner@gmail.com)\n
 * http://code.google.com/p/canvg/\n
 *\n
 * Requires: rgbcolor.js - http://www.phpied.com/rgb-color-parser-in-javascript/\n
 */\n
if(!window.console) {\n
\twindow.console = {};\n
\twindow.console.log = function(str) {};\n
\twindow.console.dir = function(str) {};\n
}\n
(function(){\n
\t// canvg(target, s)\n
\t// target: canvas element or the id of a canvas element\n
\t// s: svg string or url to svg file\n
\tthis.canvg = function (target, s) {\n
\t\tif (typeof target == \'string\') {\n
\t\t\ttarget = document.getElementById(target);\n
\t\t}\n
\t\t\n
\t\t// reuse class per canvas\n
\t\tvar svg;\n
\t\tif (target.svg == null) {\n
\t\t\tsvg = build();\n
\t\t\ttarget.svg = svg;\n
\t\t}\n
\t\telse {\n
\t\t\tsvg = target.svg;\n
\t\t\tsvg.stop();\n
\t\t}\n
\t\t\n
\t\tvar ctx = target.getContext(\'2d\');\n
\t\tif (s.substr(0,1) == \'<\') {\n
\t\t\t// load from xml string\n
\t\t\tsvg.loadXml(ctx, s);\n
\t\t}\n
\t\telse {\n
\t\t\t// load from url\n
\t\t\tsvg.load(ctx, s);\n
\t\t}\n
\t}\n
\n
\tfunction build() {\n
\t\tvar svg = {};\n
\t\t\n
\t\tsvg.FRAMERATE = 30;\n
\t\t\n
\t\t// globals\n
\t\tsvg.init = function(ctx) {\n
\t\t\tsvg.Definitions = {};\n
\t\t\tsvg.Styles = {};\n
\t\t\tsvg.Animations = [];\n
\t\t\tsvg.ctx = ctx;\n
\t\t\tsvg.ViewPort = new (function () {\n
\t\t\t\tthis.viewPorts = [];\n
\t\t\t\tthis.SetCurrent = function(width, height) { this.viewPorts.push({ width: width, height: height }); }\n
\t\t\t\tthis.RemoveCurrent = function() { this.viewPorts.pop(); }\n
\t\t\t\tthis.Current = function() { return this.viewPorts[this.viewPorts.length - 1]; }\n
\t\t\t\tthis.width = function() { return this.Current().width; }\n
\t\t\t\tthis.height = function() { return this.Current().height; }\n
\t\t\t\tthis.ComputeSize = function(d) {\n
\t\t\t\t\tif (d != null && typeof(d) == \'number\') return d;\n
\t\t\t\t\tif (d == \'x\') return this.width();\n
\t\t\t\t\tif (d == \'y\') return this.height();\n
\t\t\t\t\treturn Math.sqrt(Math.pow(this.width(), 2) + Math.pow(this.height(), 2)) / Math.sqrt(2);\t\t\t\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t\tsvg.init();\n
\n
\t\t// trim\n
\t\tsvg.trim = function(s) { return s.replace(/^\\s+|\\s+$/g, \'\'); }\n
\t\t\n
\t\t// compress spaces\n
\t\tsvg.compressSpaces = function(s) { return s.replace(/[\\s\\r\\t\\n]+/gm,\' \'); }\n
\t\t\n
\t\t// ajax\n
\t\tsvg.ajax = function(url) {\n
\t\t\tvar AJAX;\n
\t\t\tif(window.XMLHttpRequest){AJAX=new XMLHttpRequest();}\n
\t\t\telse{AJAX=new ActiveXObject(\'Microsoft.XMLHTTP\');}\n
\t\t\tif(AJAX){\n
\t\t\t   AJAX.open(\'GET\',url,false);\n
\t\t\t   AJAX.send(null);\n
\t\t\t   return AJAX.responseText;\n
\t\t\t}\n
\t\t\treturn null;\n
\t\t} \n
\t\t\n
\t\t// parse xml\n
\t\tsvg.parseXml = function(xml) {\n
\t\t\tif (window.DOMParser)\n
\t\t\t{\n
\t\t\t\tvar parser = new DOMParser();\n
\t\t\t\treturn parser.parseFromString(xml, \'text/xml\');\n
\t\t\t}\n
\t\t\telse \n
\t\t\t{\n
\t\t\t\txml = xml.replace(/<!DOCTYPE svg[^>]*>/, \'\');\n
\t\t\t\tvar xmlDoc = new ActiveXObject(\'Microsoft.XMLDOM\');\n
\t\t\t\txmlDoc.async = \'false\';\n
\t\t\t\txmlDoc.loadXML(xml); \n
\t\t\t\treturn xmlDoc;\n
\t\t\t}\t\t\n
\t\t}\n
\t\t\n
\t\tsvg.Property = function(name, value) {\n
\t\t\tthis.name = name;\n
\t\t\tthis.value = value;\n
\t\t\t\n
\t\t\tthis.hasValue = function() {\n
\t\t\t\treturn (this.value != null && this.value != \'\');\n
\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t// return the numerical value of the property\n
\t\t\tthis.numValue = function() {\n
\t\t\t\tif (!this.hasValue()) return 0;\n
\t\t\t\t\n
\t\t\t\tvar n = parseFloat(this.value);\n
\t\t\t\tif ((this.value + \'\').match(/%$/)) {\n
\t\t\t\t\tn = n / 100.0;\n
\t\t\t\t}\n
\t\t\t\treturn n;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.valueOrDefault = function(def) {\n
\t\t\t\tif (this.hasValue()) return this.value;\n
\t\t\t\treturn def;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.numValueOrDefault = function(def) {\n
\t\t\t\tif (this.hasValue()) return this.numValue();\n
\t\t\t\treturn def;\n
\t\t\t}\n
\t\t\t\n
\t\t\t/* EXTENSIONS */\n
\t\t\tvar that = this;\n
\t\t\t\n
\t\t\t// color extensions\n
\t\t\tthis.Color = {\n
\t\t\t\t// augment the current color value with the opacity\n
\t\t\t\taddOpacity: function(opacity) {\n
\t\t\t\t\tvar newValue = that.value;\n
\t\t\t\t\tif (opacity != null && opacity != \'\') {\n
\t\t\t\t\t\tvar color = new RGBColor(that.value);\n
\t\t\t\t\t\tif (color.ok) {\n
\t\t\t\t\t\t\tnewValue = \'rgba(\' + color.r + \', \' + color.g + \', \' + color.b + \', \' + opacity + \')\';\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn new svg.Property(that.name, newValue);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// definition extensions\n
\t\t\tthis.Definition = {\n
\t\t\t\t// get the definition from the definitions table\n
\t\t\t\tgetDefinition: function() {\n
\t\t\t\t\tvar name = that.value.replace(/^(url\\()?#([^\\)]+)\\)?$/, \'$2\');\n
\t\t\t\t\treturn svg.Definitions[name];\n
\t\t\t\t},\n
\t\t\t\t\n
\t\t\t\tisUrl: function() {\n
\t\t\t\t\treturn that.value.indexOf(\'url(\') == 0\n
\t\t\t\t},\n
\t\t\t\t\n
\t\t\t\tgetFillStyle: function(e) {\n
\t\t\t\t\tvar def = this.getDefinition();\n
\t\t\t\t\t\n
\t\t\t\t\t// gradient\n
\t\t\t\t\tif (def != null && def.createGradient) {\n
\t\t\t\t\t\treturn def.createGradient(svg.ctx, e);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// pattern\n
\t\t\t\t\tif (def != null && def.createPattern) {\n
\t\t\t\t\t\treturn def.createPattern(svg.ctx, e);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\treturn null;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// length extensions\n
\t\t\tthis.Length = {\n
\t\t\t\tDPI: function(viewPort) {\n
\t\t\t\t\treturn 96.0; // TODO: compute?\n
\t\t\t\t},\n
\t\t\t\t\n
\t\t\t\tEM: function(viewPort) {\n
\t\t\t\t\tvar em = 12;\n
\t\t\t\t\t\n
\t\t\t\t\tvar fontSize = new svg.Property(\'fontSize\', svg.Font.Parse(svg.ctx.font).fontSize);\n
\t\t\t\t\tif (fontSize.hasValue()) em = fontSize.Length.toPixels(viewPort);\n
\t\t\t\t\t\n
\t\t\t\t\treturn em;\n
\t\t\t\t},\n
\t\t\t\n
\t\t\t\t// get the length as pixels\n
\t\t\t\ttoPixels: function(viewPort) {\n
\t\t\t\t\tif (!that.hasValue()) return 0;\n
\t\t\t\t\tvar s = that.value+\'\';\n
\t\t\t\t\tif (s.match(/em$/)) return that.numValue() * this.EM(viewPort);\n
\t\t\t\t\tif (s.match(/ex$/)) return that.numValue() * this.EM(viewPort) / 2.0;\n
\t\t\t\t\tif (s.match(/px$/)) return that.numValue();\n
\t\t\t\t\tif (s.match(/pt$/)) return that.numValue() * 1.25;\n
\t\t\t\t\tif (s.match(/pc$/)) return that.numValue() * 15;\n
\t\t\t\t\tif (s.match(/cm$/)) return that.numValue() * this.DPI(viewPort) / 2.54;\n
\t\t\t\t\tif (s.match(/mm$/)) return that.numValue() * this.DPI(viewPort) / 25.4;\n
\t\t\t\t\tif (s.match(/in$/)) return that.numValue() * this.DPI(viewPort);\n
\t\t\t\t\tif (s.match(/%$/)) return that.numValue() * svg.ViewPort.ComputeSize(viewPort);\n
\t\t\t\t\treturn that.numValue();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// time extensions\n
\t\t\tthis.Time = {\n
\t\t\t\t// get the time as milliseconds\n
\t\t\t\ttoMilliseconds: function() {\n
\t\t\t\t\tif (!that.hasValue()) return 0;\n
\t\t\t\t\tvar s = that.value+\'\';\n
\t\t\t\t\tif (s.match(/s$/)) return that.numValue() * 1000;\n
\t\t\t\t\tif (s.match(/ms$/)) return that.numValue();\n
\t\t\t\t\treturn that.numValue();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// angle extensions\n
\t\t\tthis.Angle = {\n
\t\t\t\t// get the angle as radians\n
\t\t\t\ttoRadians: function() {\n
\t\t\t\t\tif (!that.hasValue()) return 0;\n
\t\t\t\t\tvar s = that.value+\'\';\n
\t\t\t\t\tif (s.match(/deg$/)) return that.numValue() * (Math.PI / 180.0);\n
\t\t\t\t\tif (s.match(/grad$/)) return that.numValue() * (Math.PI / 200.0);\n
\t\t\t\t\tif (s.match(/rad$/)) return that.numValue();\n
\t\t\t\t\treturn that.numValue() * (Math.PI / 180.0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\t// fonts\n
\t\tsvg.Font = new (function() {\n
\t\t\tthis.Styles = [\'normal\',\'italic\',\'oblique\',\'inherit\'];\n
\t\t\tthis.Variants = [\'normal\',\'small-caps\',\'inherit\'];\n
\t\t\tthis.Weights = [\'normal\',\'bold\',\'bolder\',\'lighter\',\'100\',\'200\',\'300\',\'400\',\'500\',\'600\',\'700\',\'800\',\'900\',\'inherit\'];\n
\t\t\t\n
\t\t\tthis.CreateFont = function(fontStyle, fontVariant, fontWeight, fontSize, fontFamily, inherit) { \n
\t\t\t\tvar f = inherit != null ? this.Parse(inherit) : this.CreateFont(\'\', \'\', \'\', \'\', \'\', svg.ctx.font);\n
\t\t\t\treturn { \n
\t\t\t\t\tfontFamily: fontFamily || f.fontFamily, \n
\t\t\t\t\tfontSize: fontSize || f.fontSize, \n
\t\t\t\t\tfontStyle: fontStyle || f.fontStyle, \n
\t\t\t\t\tfontWeight: fontWeight || f.fontWeight, \n
\t\t\t\t\tfontVariant: fontVariant || f.fontVariant,\n
\t\t\t\t\ttoString: function () { return [this.fontStyle, this.fontVariant, this.fontWeight, this.fontSize, this.fontFamily].join(\' \') } \n
\t\t\t\t} \n
\t\t\t}\n
\t\t\t\n
\t\t\tvar that = this;\n
\t\t\tthis.Parse = function(s) {\n
\t\t\t\tvar f = {};\n
\t\t\t\tvar d = svg.trim(svg.compressSpaces(s || \'\')).split(\' \');\n
\t\t\t\tvar set = { fontSize: false, fontStyle: false, fontWeight: false, fontVariant: false }\n
\t\t\t\tvar ff = \'\';\n
\t\t\t\tfor (var i=0; i<d.length; i++) {\n
\t\t\t\t\tif (!set.fontStyle && that.Styles.indexOf(d[i]) != -1) { if (d[i] != \'inherit\') f.fontStyle = d[i]; set.fontStyle = true; }\n
\t\t\t\t\telse if (!set.fontVariant && that.Variants.indexOf(d[i]) != -1) { if (d[i] != \'inherit\') f.fontVariant = d[i]; set.fontStyle = set.fontVariant = true;\t}\n
\t\t\t\t\telse if (!set.fontWeight && that.Weights.indexOf(d[i]) != -1) {\tif (d[i] != \'inherit\') f.fontWeight = d[i]; set.fontStyle = set.fontVariant = set.fontWeight = true; }\n
\t\t\t\t\telse if (!set.fontSize) { if (d[i] != \'inherit\') f.fontSize = d[i].split(\'/\')[0]; set.fontStyle = set.fontVariant = set.fontWeight = set.fontSize = true; }\n
\t\t\t\t\telse { if (d[i] != \'inherit\') ff += d[i]; }\n
\t\t\t\t} if (ff != \'\') f.fontFamily = ff;\n
\t\t\t\treturn f;\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\t// points and paths\n
\t\tsvg.ToNumberArray = function(s) {\n
\t\t\tvar a = svg.trim(svg.compressSpaces((s || \'\').replace(/,/g, \' \'))).split(\' \');\n
\t\t\tfor (var i=0; i<a.length; i++) {\n
\t\t\t\ta[i] = parseFloat(a[i]);\n
\t\t\t}\n
\t\t\treturn a;\n
\t\t}\t\t\n
\t\tsvg.Point = function(x, y) {\n
\t\t\tthis.x = x;\n
\t\t\tthis.y = y;\n
\t\t\t\n
\t\t\tthis.angleTo = function(p) {\n
\t\t\t\treturn Math.atan2(p.y - this.y, p.x - this.x);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.CreatePoint = function(s) {\n
\t\t\tvar a = svg.ToNumberArray(s);\n
\t\t\treturn new svg.Point(a[0], a[1]);\n
\t\t}\n
\t\tsvg.CreatePath = function(s) {\n
\t\t\tvar a = svg.ToNumberArray(s);\n
\t\t\tvar path = [];\n
\t\t\tfor (var i=0; i<a.length; i+=2) {\n
\t\t\t\tpath.push(new svg.Point(a[i], a[i+1]));\n
\t\t\t}\n
\t\t\treturn path;\n
\t\t}\n
\t\t\n
\t\t// bounding box\n
\t\tsvg.BoundingBox = function(x1, y1, x2, y2) { // pass in initial points if you want\n
\t\t\tthis.x1 = Number.NaN;\n
\t\t\tthis.y1 = Number.NaN;\n
\t\t\tthis.x2 = Number.NaN;\n
\t\t\tthis.y2 = Number.NaN;\n
\t\t\t\n
\t\t\tthis.x = function() { return this.x1; }\n
\t\t\tthis.y = function() { return this.y1; }\n
\t\t\tthis.width = function() { return this.x2 - this.x1; }\n
\t\t\tthis.height = function() { return this.y2 - this.y1; }\n
\t\t\t\n
\t\t\tthis.addPoint = function(x, y) {\t\n
\t\t\t\tif (x != null) {\n
\t\t\t\t\tif (isNaN(this.x1) || isNaN(this.x2)) {\n
\t\t\t\t\t\tthis.x1 = x;\n
\t\t\t\t\t\tthis.x2 = x;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (x < this.x1) this.x1 = x;\n
\t\t\t\t\tif (x > this.x2) this.x2 = x;\n
\t\t\t\t}\n
\t\t\t\n
\t\t\t\tif (y != null) {\n
\t\t\t\t\tif (isNaN(this.y1) || isNaN(this.y2)) {\n
\t\t\t\t\t\tthis.y1 = y;\n
\t\t\t\t\t\tthis.y2 = y;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (y < this.y1) this.y1 = y;\n
\t\t\t\t\tif (y > this.y2) this.y2 = y;\n
\t\t\t\t}\n
\t\t\t}\t\t\t\n
\t\t\tthis.addX = function(x) { this.addPoint(x, null); }\n
\t\t\tthis.addY = function(y) { this.addPoint(null, y); }\n
\t\t\t\n
\t\t\tthis.addQuadraticCurve = function(p0x, p0y, p1x, p1y, p2x, p2y) {\n
\t\t\t\tvar cp1x = p0x + 2/3 * (p1x - p0x); // CP1 = QP0 + 2/3 *(QP1-QP0)\n
\t\t\t\tvar cp1y = p0y + 2/3 * (p1y - p0y); // CP1 = QP0 + 2/3 *(QP1-QP0)\n
\t\t\t\tvar cp2x = cp1x + 1/3 * (p2x - p0x); // CP2 = CP1 + 1/3 *(QP2-QP0)\n
\t\t\t\tvar cp2y = cp1y + 1/3 * (p2y - p0y); // CP2 = CP1 + 1/3 *(QP2-QP0)\n
\t\t\t\tthis.addBezierCurve(p0x, p0y, cp1x, cp2x, cp1y,\tcp2y, p2x, p2y);\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.addBezierCurve = function(p0x, p0y, p1x, p1y, p2x, p2y, p3x, p3y) {\n
\t\t\t\t// from http://blog.hackers-cafe.net/2009/06/how-to-calculate-bezier-curves-bounding.html\n
\t\t\t\tvar p0 = [p0x, p0y], p1 = [p1x, p1y], p2 = [p2x, p2y], p3 = [p3x, p3y];\n
\t\t\t\tthis.addPoint(p0[0], p0[1]);\n
\t\t\t\tthis.addPoint(p3[0], p3[1]);\n
\t\t\t\t\n
\t\t\t\tfor (i=0; i<=1; i++) {\n
\t\t\t\t\tvar f = function(t) { \n
\t\t\t\t\t\treturn Math.pow(1-t, 3) * p0[i]\n
\t\t\t\t\t\t+ 3 * Math.pow(1-t, 2) * t * p1[i]\n
\t\t\t\t\t\t+ 3 * (1-t) * Math.pow(t, 2) * p2[i]\n
\t\t\t\t\t\t+ Math.pow(t, 3) * p3[i];\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar b = 6 * p0[i] - 12 * p1[i] + 6 * p2[i];\n
\t\t\t\t\tvar a = -3 * p0[i] + 9 * p1[i] - 9 * p2[i] + 3 * p3[i];\n
\t\t\t\t\tvar c = 3 * p1[i] - 3 * p0[i];\n
\t\t\t\t\t\n
\t\t\t\t\tif (a == 0) {\n
\t\t\t\t\t\tif (b == 0) continue;\n
\t\t\t\t\t\tvar t = -c / b;\n
\t\t\t\t\t\tif (0 < t && t < 1) {\n
\t\t\t\t\t\t\tif (i == 0) this.addX(f(t));\n
\t\t\t\t\t\t\tif (i == 1) this.addY(f(t));\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar b2ac = Math.pow(b, 2) - 4 * c * a;\n
\t\t\t\t\tif (b2ac < 0) continue;\n
\t\t\t\t\tvar t1 = (-b + Math.sqrt(b2ac)) / (2 * a);\n
\t\t\t\t\tif (0 < t1 && t1 < 1) {\n
\t\t\t\t\t\tif (i == 0) this.addX(f(t1));\n
\t\t\t\t\t\tif (i == 1) this.addY(f(t1));\n
\t\t\t\t\t}\n
\t\t\t\t\tvar t2 = (-b - Math.sqrt(b2ac)) / (2 * a);\n
\t\t\t\t\tif (0 < t2 && t2 < 1) {\n
\t\t\t\t\t\tif (i == 0) this.addX(f(t2));\n
\t\t\t\t\t\tif (i == 1) this.addY(f(t2));\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.addPoint(x1, y1);\n
\t\t\tthis.addPoint(x2, y2);\n
\t\t}\n
\t\t\n
\t\t// transforms\n
\t\tsvg.Transform = function(v) {\t\n
\t\t\tvar that = this;\n
\t\t\tthis.Type = {}\n
\t\t\n
\t\t\t// translate\n
\t\t\tthis.Type.translate = function(s) {\n
\t\t\t\tthis.p = svg.CreatePoint(s);\t\t\t\n
\t\t\t\tthis.apply = function(ctx) {\n
\t\t\t\t\tctx.translate(this.p.x || 0.0, this.p.y || 0.0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// rotate\n
\t\t\tthis.Type.rotate = function(s) {\n
\t\t\t\tvar a = svg.ToNumberArray(s);\n
\t\t\t\tthis.angle = new svg.Property(\'angle\', a[0]);\n
\t\t\t\tthis.cx = a[1] || 0;\n
\t\t\t\tthis.cy = a[2] || 0;\n
\t\t\t\tthis.apply = function(ctx) {\n
\t\t\t\t\tctx.translate(this.cx, this.cy);\n
\t\t\t\t\tctx.rotate(this.angle.Angle.toRadians());\n
\t\t\t\t\tctx.translate(-this.cx, -this.cy);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.Type.scale = function(s) {\n
\t\t\t\tthis.p = svg.CreatePoint(s);\n
\t\t\t\tthis.apply = function(ctx) {\n
\t\t\t\t\tctx.scale(this.p.x || 1.0, this.p.y || this.p.x || 1.0);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.Type.matrix = function(s) {\n
\t\t\t\tthis.m = svg.ToNumberArray(s);\n
\t\t\t\tthis.apply = function(ctx) {\n
\t\t\t\t\tctx.transform(this.m[0], this.m[1], this.m[2], this.m[3], this.m[4], this.m[5]);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.Type.SkewBase = function(s) {\n
\t\t\t\tthis.base = that.Type.matrix;\n
\t\t\t\tthis.base(s);\n
\t\t\t\tthis.angle = new svg.Property(\'angle\', s);\n
\t\t\t}\n
\t\t\tthis.Type.SkewBase.prototype = new this.Type.matrix;\n
\t\t\t\n
\t\t\tthis.Type.skewX = function(s) {\n
\t\t\t\tthis.base = that.Type.SkewBase;\n
\t\t\t\tthis.base(s);\n
\t\t\t\tthis.m = [1, 0, Math.tan(this.angle.Angle.toRadians()), 1, 0, 0];\n
\t\t\t}\n
\t\t\tthis.Type.skewX.prototype = new this.Type.SkewBase;\n
\t\t\t\n
\t\t\tthis.Type.skewY = function(s) {\n
\t\t\t\tthis.base = that.Type.SkewBase;\n
\t\t\t\tthis.base(s);\n
\t\t\t\tthis.m = [1, Math.tan(this.angle.Angle.toRadians()), 0, 1, 0, 0];\n
\t\t\t}\n
\t\t\tthis.Type.skewY.prototype = new this.Type.SkewBase;\n
\t\t\n
\t\t\tthis.transforms = [];\n
\t\t\tthis.apply = function(ctx) {\n
\t\t\t\tfor (var i=0; i<this.transforms.length; i++) {\n
\t\t\t\t\tthis.transforms[i].apply(ctx);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar data = v.split(/\\s(?=[a-z])/);\n
\t\t\tfor (var i=0; i<data.length; i++) {\n
\t\t\t\tvar type = data[i].split(\'(\')[0];\n
\t\t\t\tvar s = data[i].split(\'(\')[1].replace(\')\',\'\');\n
\t\t\t\tvar transform = eval(\'new this.Type.\' + type + \'(s)\');\n
\t\t\t\tthis.transforms.push(transform);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\t// elements\n
\t\tsvg.Element = {}\n
\t\t\n
\t\tsvg.Element.ElementBase = function(node) {\t\n
\t\t\tthis.attributes = {};\n
\t\t\tthis.styles = {};\n
\t\t\tthis.children = [];\n
\t\t\t\n
\t\t\t// get or create attribute\n
\t\t\tthis.attribute = function(name, createIfNotExists) {\n
\t\t\t\tvar a = this.attributes[name];\n
\t\t\t\tif (a != null) return a;\n
\t\t\t\t\t\t\t\n
\t\t\t\ta = new svg.Property(name, \'\');\n
\t\t\t\tif (createIfNotExists == true) this.attributes[name] = a;\n
\t\t\t\treturn a;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// get or create style\n
\t\t\tthis.style = function(name, createIfNotExists) {\n
\t\t\t\tvar s = this.styles[name];\n
\t\t\t\tif (s != null) return s;\n
\t\t\t\t\n
\t\t\t\tvar a = this.attribute(name);\n
\t\t\t\tif (a != null && a.hasValue()) {\n
\t\t\t\t\treturn a;\n
\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\ts = new svg.Property(name, \'\');\n
\t\t\t\tif (createIfNotExists == true) this.styles[name] = s;\n
\t\t\t\treturn s;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// base render\n
\t\t\tthis.render = function(ctx) {\n
\t\t\t\tctx.save();\n
\t\t\t\tthis.setContext(ctx);\n
\t\t\t\tthis.renderChildren(ctx);\n
\t\t\t\tthis.clearContext(ctx);\n
\t\t\t\tctx.restore();\n
\t\t\t}\n
\t\t\t\n
\t\t\t// base set context\n
\t\t\tthis.setContext = function(ctx) {\n
\t\t\t\t// OVERRIDE ME!\n
\t\t\t}\n
\t\t\t\n
\t\t\t// base clear context\n
\t\t\tthis.clearContext = function(ctx) {\n
\t\t\t\t// OVERRIDE ME!\n
\t\t\t}\t\t\t\n
\t\t\t\n
\t\t\t// base render children\n
\t\t\tthis.renderChildren = function(ctx) {\n
\t\t\t\tfor (var i=0; i<this.children.length; i++) {\n
\t\t\t\t\tthis.children[i].render(ctx);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.addChild = function(childNode, create) {\n
\t\t\t\tvar child = childNode;\n
\t\t\t\tif (create) child = svg.CreateElement(childNode);\n
\t\t\t\tchild.parent = this;\n
\t\t\t\tthis.children.push(child);\t\t\t\n
\t\t\t}\n
\t\t\t\t\n
\t\t\tif (node != null && node.nodeType == 1) { //ELEMENT_NODE\n
\t\t\t\t// add children\n
\t\t\t\tfor (var i=0; i<node.childNodes.length; i++) {\n
\t\t\t\t\tvar childNode = node.childNodes[i];\n
\t\t\t\t\tif (childNode.nodeType == 1) this.addChild(childNode, true); //ELEMENT_NODE\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// add attributes\n
\t\t\t\tfor (var i=0; i<node.attributes.length; i++) {\n
\t\t\t\t\tvar attribute = node.attributes[i];\n
\t\t\t\t\tthis.attributes[attribute.nodeName] = new svg.Property(attribute.nodeName, attribute.nodeValue);\n
\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\t\n
\t\t\t\t// add tag styles\n
\t\t\t\tvar styles = svg.Styles[this.type];\n
\t\t\t\tif (styles != null) {\n
\t\t\t\t\tfor (var name in styles) {\n
\t\t\t\t\t\tthis.styles[name] = styles[name];\n
\t\t\t\t\t}\n
\t\t\t\t}\t\t\t\t\t\n
\t\t\t\t\n
\t\t\t\t// add class styles\n
\t\t\t\tif (this.attribute(\'class\').hasValue()) {\n
\t\t\t\t\tvar classes = svg.compressSpaces(this.attribute(\'class\').value).split(\' \');\n
\t\t\t\t\tfor (var j=0; j<classes.length; j++) {\n
\t\t\t\t\t\tstyles = svg.Styles[\'.\'+classes[j]];\n
\t\t\t\t\t\tif (styles != null) {\n
\t\t\t\t\t\t\tfor (var name in styles) {\n
\t\t\t\t\t\t\t\tthis.styles[name] = styles[name];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// add inline styles\n
\t\t\t\tif (this.attribute(\'style\').hasValue()) {\n
\t\t\t\t\tvar styles = this.attribute(\'style\').value.split(\';\');\n
\t\t\t\t\tfor (var i=0; i<styles.length; i++) {\n
\t\t\t\t\t\tif (svg.trim(styles[i]) != \'\') {\n
\t\t\t\t\t\t\tvar style = styles[i].split(\':\');\n
\t\t\t\t\t\t\tvar name = svg.trim(style[0]);\n
\t\t\t\t\t\t\tvar value = svg.trim(style[1]);\n
\t\t\t\t\t\t\tthis.styles[name] = new svg.Property(name, value);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// set id\n
\t\t\t\tif (this.attribute(\'id\').hasValue()) svg.Definitions[this.attribute(\'id\').value] = this;\t\t\t\t\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tsvg.Element.RenderedElementBase = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.setContext = function(ctx) {\n
\t\t\t\t// fill\n
\t\t\t\tif (this.style(\'fill\').Definition.isUrl()) {\n
\t\t\t\t\tvar fs = this.style(\'fill\').Definition.getFillStyle(this);\n
\t\t\t\t\tif (fs != null) ctx.fillStyle = fs;\n
\t\t\t\t}\n
\t\t\t\telse if (this.style(\'fill\').hasValue()) {\n
\t\t\t\t\tvar fillStyle = this.style(\'fill\');\n
\t\t\t\t\tif (this.style(\'fill-opacity\').hasValue()) fillStyle = fillStyle.Color.addOpacity(this.style(\'fill-opacity\').value);\n
\t\t\t\t\tctx.fillStyle = (fillStyle.value == \'none\' ? \'rgba(0,0,0,0)\' : fillStyle.value);\n
\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\n
\t\t\t\t// stroke\n
\t\t\t\tif (this.style(\'stroke\').Definition.isUrl()) {\n
\t\t\t\t\tvar fs = this.style(\'stroke\').Definition.getFillStyle(this);\n
\t\t\t\t\tif (fs != null) ctx.strokeStyle = fs;\n
\t\t\t\t}\n
\t\t\t\telse if (this.style(\'stroke\').hasValue()) {\n
\t\t\t\t\tvar strokeStyle = this.style(\'stroke\');\n
\t\t\t\t\tif (this.style(\'stroke-opacity\').hasValue()) strokeStyle = strokeStyle.Color.addOpacity(this.style(\'stroke-opacity\').value);\n
\t\t\t\t\tctx.strokeStyle = (strokeStyle.value == \'none\' ? \'rgba(0,0,0,0)\' : strokeStyle.value);\n
\t\t\t\t}\n
\t\t\t\tif (this.style(\'stroke-width\').hasValue()) ctx.lineWidth = this.style(\'stroke-width\').Length.toPixels();\n
\t\t\t\tif (this.style(\'stroke-linecap\').hasValue()) ctx.lineCap = this.style(\'stroke-linecap\').value;\n
\t\t\t\tif (this.style(\'stroke-linejoin\').hasValue()) ctx.lineJoin = this.style(\'stroke-linejoin\').value;\n
\t\t\t\tif (this.style(\'stroke-miterlimit\').hasValue()) ctx.miterLimit = this.style(\'stroke-miterlimit\').value;\n
\n
\t\t\t\t// font\n
\t\t\t\tif (typeof(ctx.font) != \'undefined\') {\n
\t\t\t\t\tctx.font = svg.Font.CreateFont( \n
\t\t\t\t\t\tthis.style(\'font-style\').value, \n
\t\t\t\t\t\tthis.style(\'font-variant\').value, \n
\t\t\t\t\t\tthis.style(\'font-weight\').value, \n
\t\t\t\t\t\tthis.style(\'font-size\').hasValue() ? this.style(\'font-size\').Length.toPixels() + \'px\' : \'\', \n
\t\t\t\t\t\tthis.style(\'font-family\').value).toString();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// transform\n
\t\t\t\tif (this.attribute(\'transform\').hasValue()) { \n
\t\t\t\t\tvar transform = new svg.Transform(this.attribute(\'transform\').value);\n
\t\t\t\t\ttransform.apply(ctx);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// clip\n
\t\t\t\tif (this.attribute(\'clip-path\').hasValue()) {\n
\t\t\t\t\tvar clip = this.attribute(\'clip-path\').Definition.getDefinition();\n
\t\t\t\t\tif (clip != null) clip.apply(ctx);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// opacity\n
\t\t\t\tif (this.style(\'opacity\').hasValue()) {\n
\t\t\t\t\tctx.globalAlpha = this.style(\'opacity\').numValue();\n
\t\t\t\t}\n
\t\t\t}\t\t\n
\t\t}\n
\t\tsvg.Element.RenderedElementBase.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\tsvg.Element.PathElementBase = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tif (ctx != null) ctx.beginPath();\n
\t\t\t\treturn new svg.BoundingBox();\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.renderChildren = function(ctx) {\n
\t\t\t\tthis.path(ctx);\n
\t\t\t\tif (ctx.fillStyle != \'\') ctx.fill();\n
\t\t\t\tif (ctx.strokeStyle != \'\') ctx.stroke();\n
\t\t\t\t\n
\t\t\t\tvar markers = this.getMarkers();\n
\t\t\t\tif (markers != null) {\n
\t\t\t\t\tif (this.attribute(\'marker-start\').Definition.isUrl()) {\n
\t\t\t\t\t\tvar marker = this.attribute(\'marker-start\').Definition.getDefinition();\n
\t\t\t\t\t\tmarker.render(ctx, markers[0][0], markers[0][1]);\n
\t\t\t\t\t}\n
\t\t\t\t\tif (this.attribute(\'marker-mid\').Definition.isUrl()) {\n
\t\t\t\t\t\tvar marker = this.attribute(\'marker-mid\').Definition.getDefinition();\n
\t\t\t\t\t\tfor (var i=1;i<markers.length-1;i++) {\n
\t\t\t\t\t\t\tmarker.render(ctx, markers[i][0], markers[i][1]);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tif (this.attribute(\'marker-end\').Definition.isUrl()) {\n
\t\t\t\t\t\tvar marker = this.attribute(\'marker-end\').Definition.getDefinition();\n
\t\t\t\t\t\tmarker.render(ctx, markers[markers.length-1][0], markers[markers.length-1][1]);\n
\t\t\t\t\t}\n
\t\t\t\t}\t\t\t\t\t\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getBoundingBox = function() {\n
\t\t\t\treturn this.path();\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getMarkers = function() {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.PathElementBase.prototype = new svg.Element.RenderedElementBase;\n
\t\t\n
\t\t// svg element\n
\t\tsvg.Element.svg = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.baseClearContext = this.clearContext;\n
\t\t\tthis.clearContext = function(ctx) {\n
\t\t\t\tthis.baseClearContext(ctx);\n
\t\t\t\tsvg.ViewPort.RemoveCurrent();\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.baseSetContext = this.setContext;\n
\t\t\tthis.setContext = function(ctx) {\n
\t\t\t\tthis.baseSetContext(ctx);\n
\t\t\t\t\n
\t\t\t\t// create new view port\n
\t\t\t\tif (this.attribute(\'x\').hasValue() && this.attribute(\'y\').hasValue()) {\n
\t\t\t\t\tctx.translate(this.attribute(\'x\').Length.toPixels(\'x\'), this.attribute(\'y\').Length.toPixels(\'y\'));\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar width = svg.ViewPort.width();\n
\t\t\t\tvar height = svg.ViewPort.height();\n
\t\t\t\tif (this.attribute(\'width\').hasValue() && this.attribute(\'height\').hasValue()) {\n
\t\t\t\t\twidth = this.attribute(\'width\').Length.toPixels(\'x\');\n
\t\t\t\t\theight = this.attribute(\'height\').Length.toPixels(\'y\');\n
\t\t\t\t\t\n
\t\t\t\t\tvar x = 0;\n
\t\t\t\t\tvar y = 0;\n
\t\t\t\t\tif (this.attribute(\'refX\').hasValue() && this.attribute(\'refY\').hasValue()) {\n
\t\t\t\t\t\tx = -this.attribute(\'refX\').Length.toPixels(\'x\');\n
\t\t\t\t\t\ty = -this.attribute(\'refY\').Length.toPixels(\'y\');\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.moveTo(x, y);\n
\t\t\t\t\tctx.lineTo(width, y);\n
\t\t\t\t\tctx.lineTo(width, height);\n
\t\t\t\t\tctx.lineTo(x, height);\n
\t\t\t\t\tctx.closePath();\n
\t\t\t\t\tctx.clip();\n
\t\t\t\t}\n
\t\t\t\tsvg.ViewPort.SetCurrent(width, height);\t\n
\t\t\t\t\t\t\n
\t\t\t\t// viewbox\n
\t\t\t\tif (this.attribute(\'viewBox\').hasValue()) {\t\t\t\t\n
\t\t\t\t\tvar viewBox = svg.ToNumberArray(this.attribute(\'viewBox\').value);\n
\t\t\t\t\tvar minX = viewBox[0];\n
\t\t\t\t\tvar minY = viewBox[1];\n
\t\t\t\t\twidth = viewBox[2];\n
\t\t\t\t\theight = viewBox[3];\n
\t\t\t\t\t\n
\t\t\t\t\t// aspect ratio - http://www.w3.org/TR/SVG/coords.html#PreserveAspectRatioAttribute\n
\t\t\t\t\tvar preserveAspectRatio = svg.compressSpaces(this.attribute(\'preserveAspectRatio\').value);\n
\t\t\t\t\tpreserveAspectRatio = preserveAspectRatio.replace(/^defer\\s/,\'\'); // ignore defer\n
\t\t\t\t\tvar align = preserveAspectRatio.split(\' \')[0] || \'xMidYMid\';\n
\t\t\t\t\tvar meetOrSlice = preserveAspectRatio.split(\' \')[1] || \'meet\';\t\t\t\t\t\n
\t\t\t\t\t\n
\t\t\t\t\t// calculate scale\n
\t\t\t\t\tvar scaleX = svg.ViewPort.width() / width;\n
\t\t\t\t\tvar scaleY = svg.ViewPort.height() / height;\n
\t\t\t\t\tvar scaleMin = Math.min(scaleX, scaleY);\n
\t\t\t\t\tvar scaleMax = Math.max(scaleX, scaleY);\n
\t\t\t\t\tif (meetOrSlice == \'meet\') { width *= scaleMin; height *= scaleMin; }\n
\t\t\t\t\tif (meetOrSlice == \'slice\') { width *= scaleMax; height *= scaleMax; }\t\n
\t\t\t\t\t\n
\t\t\t\t\tif (this.attribute(\'refX\').hasValue() && this.attribute(\'refY\').hasValue()) {\n
\t\t\t\t\t\tctx.translate(-scaleMin * this.attribute(\'refX\').Length.toPixels(\'x\'), -scaleMin * this.attribute(\'refY\').Length.toPixels(\'y\'));\n
\t\t\t\t\t} \n
\t\t\t\t\telse {\t\t\t\t\t\n
\t\t\t\t\t\t// align\n
\t\t\t\t\t\tif (align.match(/^xMid/) && ((meetOrSlice == \'meet\' && scaleMin == scaleY) || (meetOrSlice == \'slice\' && scaleMax == scaleY))) ctx.translate(svg.ViewPort.width() / 2.0 - width / 2.0, 0); \n
\t\t\t\t\t\tif (align.match(/YMid$/) && ((meetOrSlice == \'meet\' && scaleMin == scaleX) || (meetOrSlice == \'slice\' && scaleMax == scaleX))) ctx.translate(0, svg.ViewPort.height() / 2.0 - height / 2.0); \n
\t\t\t\t\t\tif (align.match(/^xMax/) && ((meetOrSlice == \'meet\' && scaleMin == scaleY) || (meetOrSlice == \'slice\' && scaleMax == scaleY))) ctx.translate(svg.ViewPort.width() - width, 0); \n
\t\t\t\t\t\tif (align.match(/YMax$/) && ((meetOrSlice == \'meet\' && scaleMin == scaleX) || (meetOrSlice == \'slice\' && scaleMax == scaleX))) ctx.translate(0, svg.ViewPort.height() - height); \n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// scale\n
\t\t\t\t\tif (meetOrSlice == \'meet\') ctx.scale(scaleMin, scaleMin); \n
\t\t\t\t\tif (meetOrSlice == \'slice\') ctx.scale(scaleMax, scaleMax); \t\n
\t\t\t\t\tctx.translate(-minX, -minY);\t\n
\t\t\t\t\t\n
\t\t\t\t\tsvg.ViewPort.RemoveCurrent();\t\n
\t\t\t\t\tsvg.ViewPort.SetCurrent(viewBox[2], viewBox[3]);\t\t\t\t\t\t\n
\t\t\t\t}\t\t\t\t\n
\t\t\t\t\n
\t\t\t\t// initial values\n
\t\t\t\tctx.strokeStyle = \'rgba(0,0,0,0)\';\n
\t\t\t\tctx.lineCap = \'butt\';\n
\t\t\t\tctx.lineJoin = \'miter\';\n
\t\t\t\tctx.miterLimit = 4;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.svg.prototype = new svg.Element.RenderedElementBase;\n
\n
\t\t// rect element\n
\t\tsvg.Element.rect = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar x = this.attribute(\'x\').Length.toPixels(\'x\');\n
\t\t\t\tvar y = this.attribute(\'y\').Length.toPixels(\'y\');\n
\t\t\t\tvar width = this.attribute(\'width\').Length.toPixels(\'x\');\n
\t\t\t\tvar height = this.attribute(\'height\').Length.toPixels(\'y\');\n
\t\t\t\tvar rx = this.attribute(\'rx\').Length.toPixels(\'x\');\n
\t\t\t\tvar ry = this.attribute(\'ry\').Length.toPixels(\'y\');\n
\t\t\t\tif (this.attribute(\'rx\').hasValue() && !this.attribute(\'ry\').hasValue()) ry = rx;\n
\t\t\t\tif (this.attribute(\'ry\').hasValue() && !this.attribute(\'rx\').hasValue()) rx = ry;\n
\t\t\t\t\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.moveTo(x + rx, y);\n
\t\t\t\t\tctx.lineTo(x + width - rx, y);\n
\t\t\t\t\tctx.quadraticCurveTo(x + width, y, x + width, y + ry)\n
\t\t\t\t\tctx.lineTo(x + width, y + height - ry);\n
\t\t\t\t\tctx.quadraticCurveTo(x + width, y + height, x + width - rx, y + height)\n
\t\t\t\t\tctx.lineTo(x + rx, y + height);\n
\t\t\t\t\tctx.quadraticCurveTo(x, y + height, x, y + height - ry)\n
\t\t\t\t\tctx.lineTo(x, y + ry);\n
\t\t\t\t\tctx.quadraticCurveTo(x, y, x + rx, y)\n
\t\t\t\t\tctx.closePath();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\treturn new svg.BoundingBox(x, y, x + width, y + height);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.rect.prototype = new svg.Element.PathElementBase;\n
\t\t\n
\t\t// circle element\n
\t\tsvg.Element.circle = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar cx = this.attribute(\'cx\').Length.toPixels(\'x\');\n
\t\t\t\tvar cy = this.attribute(\'cy\').Length.toPixels(\'y\');\n
\t\t\t\tvar r = this.attribute(\'r\').Length.toPixels();\n
\t\t\t\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.arc(cx, cy, r, 0, Math.PI * 2, true); \n
\t\t\t\t\tctx.closePath();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\treturn new svg.BoundingBox(cx - r, cy - r, cx + r, cy + r);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.circle.prototype = new svg.Element.PathElementBase;\t\n
\n
\t\t// ellipse element\n
\t\tsvg.Element.ellipse = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar KAPPA = 4 * ((Math.sqrt(2) - 1) / 3);\n
\t\t\t\tvar rx = this.attribute(\'rx\').Length.toPixels(\'x\');\n
\t\t\t\tvar ry = this.attribute(\'ry\').Length.toPixels(\'y\');\n
\t\t\t\tvar cx = this.attribute(\'cx\').Length.toPixels(\'x\');\n
\t\t\t\tvar cy = this.attribute(\'cy\').Length.toPixels(\'y\');\n
\t\t\t\t\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.moveTo(cx, cy - ry);\n
\t\t\t\t\tctx.bezierCurveTo(cx + (KAPPA * rx), cy - ry,  cx + rx, cy - (KAPPA * ry), cx + rx, cy);\n
\t\t\t\t\tctx.bezierCurveTo(cx + rx, cy + (KAPPA * ry), cx + (KAPPA * rx), cy + ry, cx, cy + ry);\n
\t\t\t\t\tctx.bezierCurveTo(cx - (KAPPA * rx), cy + ry, cx - rx, cy + (KAPPA * ry), cx - rx, cy);\n
\t\t\t\t\tctx.bezierCurveTo(cx - rx, cy - (KAPPA * ry), cx - (KAPPA * rx), cy - ry, cx, cy - ry);\n
\t\t\t\t\tctx.closePath();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\treturn new svg.BoundingBox(cx - rx, cy - ry, cx + rx, cy + ry);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.ellipse.prototype = new svg.Element.PathElementBase;\t\t\t\n
\t\t\n
\t\t// line element\n
\t\tsvg.Element.line = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.getPoints = function() {\n
\t\t\t\treturn [\n
\t\t\t\t\tnew svg.Point(this.attribute(\'x1\').Length.toPixels(\'x\'), this.attribute(\'y1\').Length.toPixels(\'y\')),\n
\t\t\t\t\tnew svg.Point(this.attribute(\'x2\').Length.toPixels(\'x\'), this.attribute(\'y2\').Length.toPixels(\'y\'))];\n
\t\t\t}\n
\t\t\t\t\t\t\t\t\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar points = this.getPoints();\n
\t\t\t\t\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.moveTo(points[0].x, points[0].y);\n
\t\t\t\t\tctx.lineTo(points[1].x, points[1].y);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\treturn new svg.BoundingBox(points[0].x, points[0].y, points[1].x, points[1].y);\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getMarkers = function() {\n
\t\t\t\tvar points = this.getPoints();\t\n
\t\t\t\tvar a = points[0].angleTo(points[1]);\n
\t\t\t\treturn [[points[0], a], [points[1], a]];\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.line.prototype = new svg.Element.PathElementBase;\t\t\n
\t\t\t\t\n
\t\t// polyline element\n
\t\tsvg.Element.polyline = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.points = svg.CreatePath(this.attribute(\'points\').value);\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar bb = new svg.BoundingBox(this.points[0].x, this.points[0].y);\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.beginPath();\n
\t\t\t\t\tctx.moveTo(this.points[0].x, this.points[0].y);\n
\t\t\t\t}\n
\t\t\t\tfor (var i=1; i<this.points.length; i++) {\n
\t\t\t\t\tbb.addPoint(this.points[i].x, this.points[i].y);\n
\t\t\t\t\tif (ctx != null) ctx.lineTo(this.points[i].x, this.points[i].y);\n
\t\t\t\t}\n
\t\t\t\treturn bb;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getMarkers = function() {\n
\t\t\t\tvar markers = [];\n
\t\t\t\tfor (var i=0; i<this.points.length - 1; i++) {\n
\t\t\t\t\tmarkers.push([this.points[i], this.points[i].angleTo(this.points[i+1])]);\n
\t\t\t\t}\n
\t\t\t\tmarkers.push([this.points[this.points.length-1], markers[markers.length-1][1]]);\n
\t\t\t\treturn markers;\n
\t\t\t}\t\t\t\n
\t\t}\n
\t\tsvg.Element.polyline.prototype = new svg.Element.PathElementBase;\t\t\t\t\n
\t\t\t\t\n
\t\t// polygon element\n
\t\tsvg.Element.polygon = function(node) {\n
\t\t\tthis.base = svg.Element.polyline;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.basePath = this.path;\n
\t\t\tthis.path = function(ctx) {\n
\t\t\t\tvar bb = this.basePath(ctx);\n
\t\t\t\tif (ctx != null) {\n
\t\t\t\t\tctx.lineTo(this.points[0].x, this.points[0].y);\n
\t\t\t\t\tctx.closePath();\n
\t\t\t\t}\n
\t\t\t\treturn bb;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.polygon.prototype = new svg.Element.polyline;\n
\n
\t\t// path element\n
\t\tsvg.Element.path = function(node) {\n
\t\t\tthis.base = svg.Element.PathElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\t\t\n
\t\t\tvar d = this.attribute(\'d\').value;\n
\t\t\t// TODO: floating points, convert to real lexer based on http://www.w3.org/TR/SVG11/paths.html#PathDataBNF\n
\t\t\td = d.replace(/,/gm,\' \'); // get rid of all commas\n
\t\t\td = d.replace(/([A-Za-z])([A-Za-z])/gm,\'$1 $2\'); // separate commands from commands\n
\t\t\td = d.replace(/([A-Za-z])([A-Za-z])/gm,\'$1 $2\'); // separate commands from commands\n
\t\t\td = d.replace(/([A-Za-z])([^\\s])/gm,\'$1 $2\'); // separate commands from points\n
\t\t\td = d.replace(/([^\\s])([A-Za-z])/gm,\'$1 $2\'); // separate commands from points\n
\t\t\td = d.replace(/([0-9])([+\\-])/gm,\'$1 $2\'); // separate digits when no comma\n
\t\t\td = d.replace(/(\\.[0-9]*)(\\.)/gm,\'$1 $2\'); // separate digits when no comma\n
\t\t\td = d.replace(/([Aa](\\s+[0-9]+){3})\\s+([01])\\s*([01])/gm,\'$1 $3 $4 \'); // shorthand elliptical arc path syntax\n
\t\t\td = svg.compressSpaces(d); // compress multiple spaces\n
\t\t\td = svg.trim(d);\n
\t\t\tthis.PathParser = new (function(d) {\n
\t\t\t\tthis.tokens = d.split(\' \');\n
\t\t\t\t\n
\t\t\t\tthis.reset = function() {\n
\t\t\t\t\tthis.i = -1;\n
\t\t\t\t\tthis.command = \'\';\n
\t\t\t\t\tthis.control = new svg.Point(0, 0);\n
\t\t\t\t\tthis.current = new svg.Point(0, 0);\n
\t\t\t\t\tthis.points = [];\n
\t\t\t\t\tthis.angles = [];\n
\t\t\t\t}\n
\t\t\t\t\t\t\t\t\n
\t\t\t\tthis.isEnd = function() {\n
\t\t\t\t\treturn this.i == this.tokens.length - 1;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.isCommandOrEnd = function() {\n
\t\t\t\t\tif (this.isEnd()) return true;\n
\t\t\t\t\treturn this.tokens[this.i + 1].match(/[A-Za-z]/) != null;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.isRelativeCommand = function() {\n
\t\t\t\t\treturn this.command == this.command.toLowerCase();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.getToken = function() {\n
\t\t\t\t\tthis.i = this.i + 1;\n
\t\t\t\t\treturn this.tokens[this.i];\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.getScalar = function() {\n
\t\t\t\t\treturn parseFloat(this.getToken());\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.nextCommand = function() {\n
\t\t\t\t\tthis.command = this.getToken();\n
\t\t\t\t}\t\t\t\t\n
\t\t\t\t\n
\t\t\t\tthis.getPoint = function() {\n
\t\t\t\t\tvar p = new svg.Point(this.getScalar(), this.getScalar());\n
\t\t\t\t\treturn this.makeAbsolute(p);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.getAsControlPoint = function() {\n
\t\t\t\t\tvar p = this.getPoint();\n
\t\t\t\t\tthis.control = p;\n
\t\t\t\t\treturn p;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.getAsCurrentPoint = function() {\n
\t\t\t\t\tvar p = this.getPoint();\n
\t\t\t\t\tthis.current = p;\n
\t\t\t\t\treturn p;\t\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.getReflectedControlPoint = function() {\n
\t\t\t\t\tvar p = new svg.Point(2 * this.current.x - this.control.x, 2 * this.current.y - this.control.y);\t\t\t\t\t\n
\t\t\t\t\treturn this.makeAbsolute(p);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.makeAbsolute = function(p) {\n
\t\t\t\t\tif (this.isRelativeCommand()) {\n
\t\t\t\t\t\tp.x = this.current.x + p.x;\n
\t\t\t\t\t\tp.y = this.current.y + p.y;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn p;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.addMarker = function(p, from) {\n
\t\t\t\t\tthis.addMarkerAngle(p, from == null ? null : from.angleTo(p));\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tthis.addMarkerAngle = function(p, a) {\n
\t\t\t\t\tthis.points.push(p);\n
\t\t\t\t\tthis.angles.push(a);\n
\t\t\t\t}\t\t\t\t\n
\t\t\t\t\n
\t\t\t\tthis.getMarkerPoints = function() { return this.points; }\n
\t\t\t\tthis.getMarkerAngles = function() {\n
\t\t\t\t\tfor (var i=0; i<this.angles.length; i++) {\n
\t\t\t\t\t\tif (this.angles[i] == null) {\n
\t\t\t\t\t\t\tfor (var j=i+1; j<this.angles.length; j++) {\n
\t\t\t\t\t\t\t\tif (this.angles[j] != null) {\n
\t\t\t\t\t\t\t\t\tthis.angles[i] = this.angles[j];\n
\t\t\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn this.angles;\n
\t\t\t\t}\n
\t\t\t})(d);\n
\t\t\t\n
\t\t\tthis.path = function(ctx) {\t\t\n
\t\t\t\tvar pp = this.PathParser;\n
\t\t\t\tpp.reset();\n
\t\t\t\t\n
\t\t\t\tvar bb = new svg.BoundingBox();\n
\t\t\t\tif (ctx != null) ctx.beginPath();\n
\t\t\t\twhile (!pp.isEnd()) {\n
\t\t\t\t\tpp.nextCommand();\n
\t\t\t\t\tif (pp.command.toUpperCase() == \'M\') {\n
\t\t\t\t\t\tvar p = pp.getAsCurrentPoint();\n
\t\t\t\t\t\tpp.addMarker(p);\n
\t\t\t\t\t\tbb.addPoint(p.x, p.y);\n
\t\t\t\t\t\tif (ctx != null) ctx.moveTo(p.x, p.y);\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar p = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(p);\n
\t\t\t\t\t\t\tbb.addPoint(p.x, p.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.lineTo(p.x, p.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'L\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar c = pp.current;\n
\t\t\t\t\t\t\tvar p = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(p, c);\n
\t\t\t\t\t\t\tbb.addPoint(p.x, p.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.lineTo(p.x, p.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'H\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar newP = new svg.Point((pp.isRelativeCommand() ? pp.current.x : 0) + pp.getScalar(), pp.current.y);\n
\t\t\t\t\t\t\tpp.addMarker(newP, pp.current);\n
\t\t\t\t\t\t\tpp.current = newP;\n
\t\t\t\t\t\t\tbb.addPoint(pp.current.x, pp.current.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.lineTo(pp.current.x, pp.current.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'V\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar newP = new svg.Point(pp.current.x, (pp.isRelativeCommand() ? pp.current.y : 0) + pp.getScalar());\n
\t\t\t\t\t\t\tpp.addMarker(newP, pp.current);\n
\t\t\t\t\t\t\tpp.current = newP;\n
\t\t\t\t\t\t\tbb.addPoint(pp.current.x, pp.current.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.lineTo(pp.current.x, pp.current.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'C\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar curr = pp.current;\n
\t\t\t\t\t\t\tvar p1 = pp.getPoint();\n
\t\t\t\t\t\t\tvar cntrl = pp.getAsControlPoint();\n
\t\t\t\t\t\t\tvar cp = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(cp, cntrl);\n
\t\t\t\t\t\t\tbb.addBezierCurve(curr.x, curr.y, p1.x, p1.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.bezierCurveTo(p1.x, p1.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'S\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar curr = pp.current;\n
\t\t\t\t\t\t\tvar p1 = pp.getReflectedControlPoint();\n
\t\t\t\t\t\t\tvar cntrl = pp.getAsControlPoint();\n
\t\t\t\t\t\t\tvar cp = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(cp, cntrl);\n
\t\t\t\t\t\t\tbb.addBezierCurve(curr.x, curr.y, p1.x, p1.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.bezierCurveTo(p1.x, p1.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t}\t\t\t\t\n
\t\t\t\t\t}\t\t\t\t\t\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'Q\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar curr = pp.current;\n
\t\t\t\t\t\t\tvar cntrl = pp.getAsControlPoint();\n
\t\t\t\t\t\t\tvar cp = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(cp, cntrl);\n
\t\t\t\t\t\t\tbb.addQuadraticCurve(curr.x, curr.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.quadraticCurveTo(cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\t\t\t\t\t\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'T\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t\tvar curr = pp.current;\n
\t\t\t\t\t\t\tvar cntrl = pp.getReflectedControlPoint();\n
\t\t\t\t\t\t\tpp.control = cntrl;\n
\t\t\t\t\t\t\tvar cp = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\tpp.addMarker(cp, cntrl);\n
\t\t\t\t\t\t\tbb.addQuadraticCurve(curr.x, curr.y, cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t\tif (ctx != null) ctx.quadraticCurveTo(cntrl.x, cntrl.y, cp.x, cp.y);\n
\t\t\t\t\t\t}\t\t\t\t\t\n
\t\t\t\t\t}\n
\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'A\') {\n
\t\t\t\t\t\twhile (!pp.isCommandOrEnd()) {\n
\t\t\t\t\t\t    var curr = pp.current;\n
\t\t\t\t\t\t\tvar rx = pp.getScalar();\n
\t\t\t\t\t\t\tvar ry = pp.getScalar();\n
\t\t\t\t\t\t\tvar xAxisRotation = pp.getScalar() * (Math.PI / 180.0);\n
\t\t\t\t\t\t\tvar largeArcFlag = pp.getScalar();\n
\t\t\t\t\t\t\tvar sweepFlag = pp.getScalar();\n
\t\t\t\t\t\t\tvar cp = pp.getAsCurrentPoint();\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Conversion from endpoint to center parameterization\n
\t\t\t\t\t\t\t// http://www.w3.org/TR/SVG11/implnote.html#ArcImplementationNotes\n
\t\t\t\t\t\t\t// x1\', y1\'\n
\t\t\t\t\t\t\tvar currp = new svg.Point(\n
\t\t\t\t\t\t\t\tMath.cos(xAxisRotation) * (curr.x - cp.x) / 2.0 + Math.sin(xAxisRotation) * (curr.y - cp.y) / 2.0,\n
\t\t\t\t\t\t\t\t-Math.sin(xAxisRotation) * (curr.x - cp.x) / 2.0 + Math.cos(xAxisRotation) * (curr.y - cp.y) / 2.0\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t\t// adjust radii\n
\t\t\t\t\t\t\tvar l = Math.pow(currp.x,2)/Math.pow(rx,2)+Math.pow(currp.y,2)/Math.pow(ry,2);\n
\t\t\t\t\t\t\tif (l > 1) {\n
\t\t\t\t\t\t\t\trx *= Math.sqrt(l);\n
\t\t\t\t\t\t\t\try *= Math.sqrt(l);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t// cx\', cy\'\n
\t\t\t\t\t\t\tvar s = (largeArcFlag == sweepFlag ? -1 : 1) * Math.sqrt(\n
\t\t\t\t\t\t\t\t((Math.pow(rx,2)*Math.pow(ry,2))-(Math.pow(rx,2)*Math.pow(currp.y,2))-(Math.pow(ry,2)*Math.pow(currp.x,2))) /\n
\t\t\t\t\t\t\t\t(Math.pow(rx,2)*Math.pow(currp.y,2)+Math.pow(ry,2)*Math.pow(currp.x,2))\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t\tif (isNaN(s)) s = 0;\n
\t\t\t\t\t\t\tvar cpp = new svg.Point(s * rx * currp.y / ry, s * -ry * currp.x / rx);\n
\t\t\t\t\t\t\t// cx, cy\n
\t\t\t\t\t\t\tvar centp = new svg.Point(\n
\t\t\t\t\t\t\t\t(curr.x + cp.x) / 2.0 + Math.cos(xAxisRotation) * cpp.x - Math.sin(xAxisRotation) * cpp.y,\n
\t\t\t\t\t\t\t\t(curr.y + cp.y) / 2.0 + Math.sin(xAxisRotation) * cpp.x + Math.cos(xAxisRotation) * cpp.y\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t\t// vector magnitude\n
\t\t\t\t\t\t\tvar m = function(v) { return Math.sqrt(Math.pow(v[0],2) + Math.pow(v[1],2)); }\n
\t\t\t\t\t\t\t// ratio between two vectors\n
\t\t\t\t\t\t\tvar r = function(u, v) { return (u[0]*v[0]+u[1]*v[1]) / (m(u)*m(v)) }\n
\t\t\t\t\t\t\t// angle between two vectors\n
\t\t\t\t\t\t\tvar a = function(u, v) { return (u[0]*v[1] < u[1]*v[0] ? -1 : 1) * Math.acos(r(u,v)); }\n
\t\t\t\t\t\t\t// initial angle\n
\t\t\t\t\t\t\tvar a1 = a([1,0], [(currp.x-cpp.x)/rx,(currp.y-cpp.y)/ry]);\n
\t\t\t\t\t\t\t// angle delta\n
\t\t\t\t\t\t\tvar u = [(currp.x-cpp.x)/rx,(currp.y-cpp.y)/ry];\n
\t\t\t\t\t\t\tvar v = [(-currp.x-cpp.x)/rx,(-currp.y-cpp.y)/ry];\n
\t\t\t\t\t\t\tvar ad = a(u, v);\n
\t\t\t\t\t\t\tif (r(u,v) <= -1) ad = Math.PI;\n
\t\t\t\t\t\t\tif (r(u,v) >= 1) ad = 0;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif (sweepFlag == 0 && ad > 0) ad = ad - 2 * Math.PI;\n
\t\t\t\t\t\t\tif (sweepFlag == 1 && ad < 0) ad = ad + 2 * Math.PI;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// for markers\n
\t\t\t\t\t\t\tvar halfWay = new svg.Point(\n
\t\t\t\t\t\t\t\tcentp.x - rx * Math.cos((a1 + ad) / 2),\n
\t\t\t\t\t\t\t\tcentp.y - ry * Math.sin((a1 + ad) / 2)\n
\t\t\t\t\t\t\t);\n
\t\t\t\t\t\t\tpp.addMarkerAngle(halfWay, (a1 + ad) / 2 + (sweepFlag == 0 ? 1 : -1) * Math.PI / 2);\n
\t\t\t\t\t\t\tpp.addMarkerAngle(cp, ad + (sweepFlag == 0 ? 1 : -1) * Math.PI / 2);\n
\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tbb.addPoint(cp.x, cp.y); // TODO: this is too naive, make it better\n
\t\t\t\t\t\t\tif (ctx != null) {\n
\t\t\t\t\t\t\t\tvar r = rx > ry ? rx : ry;\n
\t\t\t\t\t\t\t\tvar sx = rx > ry ? 1 : rx / ry;\n
\t\t\t\t\t\t\t\tvar sy = rx > ry ? ry / rx : 1;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\tctx.translate(centp.x, centp.y);\n
\t\t\t\t\t\t\t\tctx.rotate(xAxisRotation);\n
\t\t\t\t\t\t\t\tctx.scale(sx, sy);\n
\t\t\t\t\t\t\t\tctx.arc(0, 0, r, a1, a1 + ad, 1 - sweepFlag);\n
\t\t\t\t\t\t\t\tctx.scale(1/sx, 1/sy);\n
\t\t\t\t\t\t\t\tctx.rotate(-xAxisRotation);\n
\t\t\t\t\t\t\t\tctx.translate(-centp.x, -centp.y);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (pp.command.toUpperCase() == \'Z\') {\n
\t\t\t\t\t\tif (ctx != null) ctx.closePath();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\treturn bb;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getMarkers = function() {\n
\t\t\t\tvar points = this.PathParser.getMarkerPoints();\n
\t\t\t\tvar angles = this.PathParser.getMarkerAngles();\n
\t\t\t\t\n
\t\t\t\tvar markers = [];\n
\t\t\t\tfor (var i=0; i<points.length; i++) {\n
\t\t\t\t\tmarkers.push([points[i], angles[i]]);\n
\t\t\t\t}\n
\t\t\t\treturn markers;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.path.prototype = new svg.Element.PathElementBase;\n
\t\t\n
\t\t// pattern element\n
\t\tsvg.Element.pattern = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.createPattern = function(ctx, element) {\n
\t\t\t\t// render me using a temporary svg element\n
\t\t\t\tvar tempSvg = new svg.Element.svg();\n
\t\t\t\ttempSvg.attributes[\'viewBox\'] = new svg.Property(\'viewBox\', this.attribute(\'viewBox\').value);\n
\t\t\t\ttempSvg.attributes[\'x\'] = new svg.Property(\'x\', this.attribute(\'x\').value);\n
\t\t\t\ttempSvg.attributes[\'y\'] = new svg.Property(\'y\', this.attribute(\'y\').value);\n
\t\t\t\ttempSvg.attributes[\'width\'] = new svg.Property(\'width\', this.attribute(\'width\').value);\n
\t\t\t\ttempSvg.attributes[\'height\'] = new svg.Property(\'height\', this.attribute(\'height\').value);\n
\t\t\t\ttempSvg.children = this.children;\n
\t\t\t\t\n
\t\t\t\tvar c = document.createElement(\'canvas\');\n
\t\t\t\tc.width = this.attribute(\'width\').Length.toPixels();\n
\t\t\t\tc.height = this.attribute(\'height\').Length.toPixels();\n
\t\t\t\ttempSvg.render(c.getContext(\'2d\'));\t\t\n
\t\t\t\treturn ctx.createPattern(c, \'repeat\');\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.pattern.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// marker element\n
\t\tsvg.Element.marker = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.baseRender = this.render;\n
\t\t\tthis.render = function(ctx, point, angle) {\n
\t\t\t\tctx.translate(point.x, point.y);\n
\t\t\t\tif (this.attribute(\'orient\').valueOrDefault(\'auto\') == \'auto\') ctx.rotate(angle);\n
\t\t\t\tif (this.attribute(\'markerUnits\').valueOrDefault(\'strokeWidth\') == \'strokeWidth\') ctx.scale(ctx.lineWidth, ctx.lineWidth);\n
\t\t\t\tctx.save();\n
\t\t\t\t\t\t\t\n
\t\t\t\t// render me using a temporary svg element\n
\t\t\t\tvar tempSvg = new svg.Element.svg();\n
\t\t\t\ttempSvg.attributes[\'viewBox\'] = new svg.Property(\'viewBox\', this.attribute(\'viewBox\').value);\n
\t\t\t\ttempSvg.attributes[\'refX\'] = new svg.Property(\'refX\', this.attribute(\'refX\').value);\n
\t\t\t\ttempSvg.attributes[\'refY\'] = new svg.Property(\'refY\', this.attribute(\'refY\').value);\n
\t\t\t\ttempSvg.attributes[\'width\'] = new svg.Property(\'width\', this.attribute(\'markerWidth\').value);\n
\t\t\t\ttempSvg.attributes[\'height\'] = new svg.Property(\'height\', this.attribute(\'markerHeight\').value);\n
\t\t\t\ttempSvg.attributes[\'fill\'] = new svg.Property(\'fill\', this.attribute(\'fill\').valueOrDefault(\'black\'));\n
\t\t\t\ttempSvg.attributes[\'stroke\'] = new svg.Property(\'stroke\', this.attribute(\'stroke\').valueOrDefault(\'none\'));\n
\t\t\t\ttempSvg.children = this.children;\n
\t\t\t\ttempSvg.render(ctx);\n
\t\t\t\t\n
\t\t\t\tctx.restore();\n
\t\t\t\tif (this.attribute(\'markerUnits\').valueOrDefault(\'strokeWidth\') == \'strokeWidth\') ctx.scale(1/ctx.lineWidth, 1/ctx.lineWidth);\n
\t\t\t\tif (this.attribute(\'orient\').valueOrDefault(\'auto\') == \'auto\') ctx.rotate(-angle);\n
\t\t\t\tctx.translate(-point.x, -point.y);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.marker.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// definitions element\n
\t\tsvg.Element.defs = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\t\t\t\n
\t\t\t\n
\t\t\tthis.render = function(ctx) {\n
\t\t\t\t// NOOP\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.defs.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// base for gradients\n
\t\tsvg.Element.GradientBase = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.gradientUnits = this.attribute(\'gradientUnits\').valueOrDefault(\'objectBoundingBox\');\n
\t\t\t\n
\t\t\tthis.stops = [];\t\t\t\n
\t\t\tfor (var i=0; i<this.children.length; i++) {\n
\t\t\t\tvar child = this.children[i];\n
\t\t\t\tthis.stops.push(child);\n
\t\t\t}\t\n
\n
\t\t\tthis.getGradient = function() {\n
\t\t\t\t// OVERRIDE ME!\n
\t\t\t}\t\t\t\n
\n
\t\t\tthis.createGradient = function(ctx, element) {\n
\t\t\t\tvar g = this.getGradient(ctx, element);\n
\t\t\t\tfor (var i=0; i<this.stops.length; i++) {\n
\t\t\t\t\tg.addColorStop(this.stops[i].offset, this.stops[i].color);\n
\t\t\t\t}\n
\t\t\t\treturn g;\t\t\t\t\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.GradientBase.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// linear gradient element\n
\t\tsvg.Element.linearGradient = function(node) {\n
\t\t\tthis.base = svg.Element.GradientBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.getGradient = function(ctx, element) {\n
\t\t\t\tvar bb = element.getBoundingBox();\n
\t\t\t\t\n
\t\t\t\tvar x1 = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.x() + bb.width() * this.attribute(\'x1\').numValue() \n
\t\t\t\t\t: this.attribute(\'x1\').Length.toPixels(\'x\'));\n
\t\t\t\tvar y1 = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.y() + bb.height() * this.attribute(\'y1\').numValue()\n
\t\t\t\t\t: this.attribute(\'y1\').Length.toPixels(\'y\'));\n
\t\t\t\tvar x2 = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.x() + bb.width() * this.attribute(\'x2\').numValue()\n
\t\t\t\t\t: this.attribute(\'x2\').Length.toPixels(\'x\'));\n
\t\t\t\tvar y2 = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.y() + bb.height() * this.attribute(\'y2\').numValue()\n
\t\t\t\t\t: this.attribute(\'y2\').Length.toPixels(\'y\'));\n
\t\t\t\t\n
\t\t\t\treturn ctx.createLinearGradient(x1, y1, x2, y2);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.linearGradient.prototype = new svg.Element.GradientBase;\n
\t\t\n
\t\t// radial gradient element\n
\t\tsvg.Element.radialGradient = function(node) {\n
\t\t\tthis.base = svg.Element.GradientBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.getGradient = function(ctx, element) {\n
\t\t\t\tvar bb = element.getBoundingBox();\n
\t\t\t\t\n
\t\t\t\tvar cx = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.x() + bb.width() * this.attribute(\'cx\').numValue() \n
\t\t\t\t\t: this.attribute(\'cx\').Length.toPixels(\'x\'));\n
\t\t\t\tvar cy = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.y() + bb.height() * this.attribute(\'cy\').numValue() \n
\t\t\t\t\t: this.attribute(\'cy\').Length.toPixels(\'y\'));\n
\t\t\t\t\n
\t\t\t\tvar fx = cx;\n
\t\t\t\tvar fy = cy;\n
\t\t\t\tif (this.attribute(\'fx\').hasValue()) {\n
\t\t\t\t\tfx = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.x() + bb.width() * this.attribute(\'fx\').numValue() \n
\t\t\t\t\t: this.attribute(\'fx\').Length.toPixels(\'x\'));\n
\t\t\t\t}\n
\t\t\t\tif (this.attribute(\'fy\').hasValue()) {\n
\t\t\t\t\tfy = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? bb.y() + bb.height() * this.attribute(\'fy\').numValue() \n
\t\t\t\t\t: this.attribute(\'fy\').Length.toPixels(\'y\'));\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar r = (this.gradientUnits == \'objectBoundingBox\' \n
\t\t\t\t\t? (bb.width() + bb.height()) / 2.0 * this.attribute(\'r\').numValue()\n
\t\t\t\t\t: this.attribute(\'r\').Length.toPixels());\n
\t\t\t\t\n
\t\t\t\treturn ctx.createRadialGradient(fx, fy, 0, cx, cy, r);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.radialGradient.prototype = new svg.Element.GradientBase;\n
\t\t\n
\t\t// gradient stop element\n
\t\tsvg.Element.stop = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.offset = this.attribute(\'offset\').numValue();\n
\t\t\t\n
\t\t\tvar stopColor = this.style(\'stop-color\');\n
\t\t\tif (this.style(\'stop-opacity\').hasValue()) stopColor = stopColor.Color.addOpacity(this.style(\'stop-opacity\').value);\n
\t\t\tthis.color = stopColor.value;\n
\t\t}\n
\t\tsvg.Element.stop.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// animation base element\n
\t\tsvg.Element.AnimateBase = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tsvg.Animations.push(this);\n
\t\t\t\n
\t\t\tthis.duration = 0.0;\n
\t\t\tthis.begin = this.attribute(\'begin\').Time.toMilliseconds();\n
\t\t\tthis.maxDuration = this.begin + this.attribute(\'dur\').Time.toMilliseconds();\n
\n
\t\t\tthis.calcValue = function() {\n
\t\t\t\t// OVERRIDE ME!\n
\t\t\t\treturn \'\';\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.update = function(delta) {\t\t\t\n
\t\t\t\t// if we\'re past the end time\n
\t\t\t\tif (this.duration > this.maxDuration) {\n
\t\t\t\t\t// loop for indefinitely repeating animations\n
\t\t\t\t\tif (this.attribute(\'repeatCount\').value == \'indefinite\') {\n
\t\t\t\t\t\tthis.duration = 0.0\n
\t\t\t\t\t}\n
\t\t\t\t\telse {\n
\t\t\t\t\t\treturn false; // no updates made\n
\t\t\t\t\t}\n
\t\t\t\t}\t\t\t\n
\t\t\t\tthis.duration = this.duration + delta;\n
\t\t\t\n
\t\t\t\t// if we\'re past the begin time\n
\t\t\t\tvar updated = false;\n
\t\t\t\tif (this.begin < this.duration) {\n
\t\t\t\t\tvar newValue = this.calcValue(); // tween\n
\t\t\t\t\tvar attributeType = this.attribute(\'attributeType\').value;\n
\t\t\t\t\tvar attributeName = this.attribute(\'attributeName\').value;\n
\t\t\t\t\t\n
\t\t\t\t\tif (this.parent != null) {\n
\t\t\t\t\t\tif (attributeType == \'CSS\') {\n
\t\t\t\t\t\t\tthis.parent.style(attributeName, true).value = newValue;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telse { // default or XML\n
\t\t\t\t\t\t\tif (this.attribute(\'type\').hasValue()) {\n
\t\t\t\t\t\t\t\t// for transform, etc.\n
\t\t\t\t\t\t\t\tvar type = this.attribute(\'type\').value;\n
\t\t\t\t\t\t\t\tthis.parent.attribute(attributeName, true).value = type + \'(\' + newValue + \')\';\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\t\tthis.parent.attribute(attributeName, true).value = newValue;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tupdated = true;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\treturn updated;\n
\t\t\t}\n
\t\t\t\n
\t\t\t// fraction of duration we\'ve covered\n
\t\t\tthis.progress = function() {\n
\t\t\t\treturn ((this.duration - this.begin) / (this.maxDuration - this.begin));\n
\t\t\t}\t\t\t\n
\t\t}\n
\t\tsvg.Element.AnimateBase.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// animate element\n
\t\tsvg.Element.animate = function(node) {\n
\t\t\tthis.base = svg.Element.AnimateBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.calcValue = function() {\n
\t\t\t\tvar from = this.attribute(\'from\').numValue();\n
\t\t\t\tvar to = this.attribute(\'to\').numValue();\n
\t\t\t\t\n
\t\t\t\t// tween value linearly\n
\t\t\t\treturn from + (to - from) * this.progress(); \n
\t\t\t};\n
\t\t}\n
\t\tsvg.Element.animate.prototype = new svg.Element.AnimateBase;\n
\t\t\t\n
\t\t// animate color element\n
\t\tsvg.Element.animateColor = function(node) {\n
\t\t\tthis.base = svg.Element.AnimateBase;\n
\t\t\tthis.base(node);\n
\n
\t\t\tthis.calcValue = function() {\n
\t\t\t\tvar from = new RGBColor(this.attribute(\'from\').value);\n
\t\t\t\tvar to = new RGBColor(this.attribute(\'to\').value);\n
\t\t\t\t\n
\t\t\t\tif (from.ok && to.ok) {\n
\t\t\t\t\t// tween color linearly\n
\t\t\t\t\tvar r = from.r + (to.r - from.r) * this.progress();\n
\t\t\t\t\tvar g = from.g + (to.g - from.g) * this.progress();\n
\t\t\t\t\tvar b = from.b + (to.b - from.b) * this.progress();\n
\t\t\t\t\treturn \'rgb(\'+parseInt(r,10)+\',\'+parseInt(g,10)+\',\'+parseInt(b,10)+\')\';\n
\t\t\t\t}\n
\t\t\t\treturn this.attribute(\'from\').value;\n
\t\t\t};\n
\t\t}\n
\t\tsvg.Element.animateColor.prototype = new svg.Element.AnimateBase;\n
\t\t\n
\t\t// animate transform element\n
\t\tsvg.Element.animateTransform = function(node) {\n
\t\t\tthis.base = svg.Element.animate;\n
\t\t\tthis.base(node);\n
\t\t}\n
\t\tsvg.Element.animateTransform.prototype = new svg.Element.animate;\n
\t\t\n
\t\t// text element\n
\t\tsvg.Element.text = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tif (node != null) {\n
\t\t\t\t// add children\n
\t\t\t\tthis.children = [];\n
\t\t\t\tfor (var i=0; i<node.childNodes.length; i++) {\n
\t\t\t\t\tvar childNode = node.childNodes[i];\n
\t\t\t\t\tif (childNode.nodeType == 1) { // capture tspan and tref nodes\n
\t\t\t\t\t\tthis.addChild(childNode, true);\n
\t\t\t\t\t}\n
\t\t\t\t\telse if (childNode.nodeType == 3) { // capture text\n
\t\t\t\t\t\tthis.addChild(new svg.Element.tspan(childNode), false);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.baseSetContext = this.setContext;\n
\t\t\tthis.setContext = function(ctx) {\n
\t\t\t\tthis.baseSetContext(ctx);\n
\t\t\t\tif (this.attribute(\'text-anchor\').hasValue()) {\n
\t\t\t\t\tvar textAnchor = this.attribute(\'text-anchor\').value;\n
\t\t\t\t\tctx.textAlign = textAnchor == \'middle\' ? \'center\' : textAnchor;\n
\t\t\t\t}\n
\t\t\t\tif (this.attribute(\'alignment-baseline\').hasValue()) ctx.textBaseline = this.attribute(\'alignment-baseline\').value;\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.renderChildren = function(ctx) {\n
\t\t\t\tvar x = this.attribute(\'x\').Length.toPixels(\'x\');\n
\t\t\t\tvar y = this.attribute(\'y\').Length.toPixels(\'y\');\n
\t\t\t\tfor (var i=0; i<this.children.length; i++) {\n
\t\t\t\t\tthis.children[i].x = x;\n
\t\t\t\t\tthis.children[i].y = y;\n
\t\t\t\t\tthis.children[i].render(ctx);\n
\t\t\t\t\tx += this.children[i].measureText(ctx);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.text.prototype = new svg.Element.RenderedElementBase;\n
\t\t\n
\t\t// text base\n
\t\tsvg.Element.TextElementBase = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.renderChildren = function(ctx) {\n
\t\t\t\tctx.fillText(svg.compressSpaces(this.getText()), this.x, this.y);\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.getText = function() {\n
\t\t\t\t// OVERRIDE ME\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.measureText = function(ctx) {\n
\t\t\t\treturn ctx.measureText(svg.compressSpaces(this.getText())).width;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.TextElementBase.prototype = new svg.Element.RenderedElementBase;\n
\t\t\n
\t\t// tspan \n
\t\tsvg.Element.tspan = function(node) {\n
\t\t\tthis.base = svg.Element.TextElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\t//\t\t\t\t\t\t\t\t TEXT\t\t\t  ELEMENT\n
\t\t\tthis.text = node.nodeType == 3 ? node.nodeValue : node.childNodes[0].nodeValue;\n
\t\t\tthis.getText = function() {\n
\t\t\t\treturn this.text;\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.tspan.prototype = new svg.Element.TextElementBase;\n
\t\t\n
\t\t// tref\n
\t\tsvg.Element.tref = function(node) {\n
\t\t\tthis.base = svg.Element.TextElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.getText = function() {\n
\t\t\t\tvar element = this.attribute(\'xlink:href\').Definition.getDefinition();\n
\t\t\t\tif (element != null) return element.children[0].getText();\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.tref.prototype = new svg.Element.TextElementBase;\t\t\n
\t\t\n
\t\t// group element\n
\t\tsvg.Element.g = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t}\n
\t\tsvg.Element.g.prototype = new svg.Element.RenderedElementBase;\n
\n
\t\t// symbol element\n
\t\tsvg.Element.symbol = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t}\n
\t\tsvg.Element.symbol.prototype = new svg.Element.RenderedElementBase;\t\t\n
\t\t\n
\t\t// a element\n
\t\tsvg.Element.a = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t}\n
\t\tsvg.Element.a.prototype = new svg.Element.RenderedElementBase;\n
\t\t\n
\t\t// style element\n
\t\tsvg.Element.style = function(node) { \n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tvar css = node.childNodes[0].nodeValue;\n
\t\t\tcss = css.replace(/(\\/\\*([^*]|[\\r\\n]|(\\*+([^*\\/]|[\\r\\n])))*\\*+\\/)|(\\/\\/.*)/gm, \'\'); // remove comments\n
\t\t\tcss = svg.compressSpaces(css); // replace whitespace\n
\t\t\tvar cssDefs = css.split(\'}\');\n
\t\t\tfor (var i=0; i<cssDefs.length; i++) {\n
\t\t\t\tif (svg.trim(cssDefs[i]) != \'\') {\n
\t\t\t\t\tvar cssDef = cssDefs[i].split(\'{\');\n
\t\t\t\t\tvar cssClasses = cssDef[0].split(\',\');\n
\t\t\t\t\tvar cssProps = cssDef[1].split(\';\');\n
\t\t\t\t\tfor (var j=0; j<cssClasses.length; j++) {\n
\t\t\t\t\t\tvar cssClass = svg.trim(cssClasses[j]);\n
\t\t\t\t\t\tif (cssClass != \'\') {\n
\t\t\t\t\t\t\tvar props = {};\n
\t\t\t\t\t\t\tfor (var k=0; k<cssProps.length; k++) {\n
\t\t\t\t\t\t\t\tvar prop = cssProps[k].split(\':\');\n
\t\t\t\t\t\t\t\tvar name = prop[0];\n
\t\t\t\t\t\t\t\tvar value = prop[1];\n
\t\t\t\t\t\t\t\tif (name != null && value != null) {\n
\t\t\t\t\t\t\t\t\tprops[svg.trim(prop[0])] = new svg.Property(svg.trim(prop[0]), svg.trim(prop[1]));\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tsvg.Styles[cssClass] = props;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.style.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// use element \n
\t\tsvg.Element.use = function(node) {\n
\t\t\tthis.base = svg.Element.RenderedElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.baseSetContext = this.setContext;\n
\t\t\tthis.setContext = function(ctx) {\n
\t\t\t\tthis.baseSetContext(ctx);\n
\t\t\t\tif (this.attribute(\'x\').hasValue()) ctx.translate(this.attribute(\'x\').Length.toPixels(\'x\'), 0);\n
\t\t\t\tif (this.attribute(\'y\').hasValue()) ctx.translate(0, this.attribute(\'y\').Length.toPixels(\'y\'));\n
\t\t\t}\n
\t\t\t\n
\t\t\tthis.renderChildren = function(ctx) {\n
\t\t\t\tvar element = this.attribute(\'xlink:href\').Definition.getDefinition();\n
\t\t\t\tif (element != null) element.render(ctx);\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.use.prototype = new svg.Element.RenderedElementBase;\n
\t\t\n
\t\t// clip element\n
\t\tsvg.Element.clipPath = function(node) {\n
\t\t\tthis.base = svg.Element.ElementBase;\n
\t\t\tthis.base(node);\n
\t\t\t\n
\t\t\tthis.apply = function(ctx) {\n
\t\t\t\tfor (var i=0; i<this.children.length; i++) {\n
\t\t\t\t\tif (this.children[i].path) {\n
\t\t\t\t\t\tthis.children[i].path(ctx);\n
\t\t\t\t\t\tctx.clip();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\tsvg.Element.clipPath.prototype = new svg.Element.ElementBase;\n
\n
\t\t// title element, do nothing\n
\t\tsvg.Element.title = function(node) {\n
\t\t}\n
\t\tsvg.Element.title.prototype = new svg.Element.ElementBase;\n
\n
\t\t// desc element, do nothing\n
\t\tsvg.Element.desc = function(node) {\n
\t\t}\n
\t\tsvg.Element.desc.prototype = new svg.Element.ElementBase;\t\t\n
\t\t\n
\t\tsvg.Element.MISSING = function(node) {\n
\t\t\tconsole.log(\'ERROR: Element \\\'\' + node.nodeName + \'\\\' not yet implemented.\');\n
\t\t}\n
\t\tsvg.Element.MISSING.prototype = new svg.Element.ElementBase;\n
\t\t\n
\t\t// element factory\n
\t\tsvg.CreateElement = function(node) {\n
\t\t\tvar className = \'svg.Element.\' + node.nodeName.replace(/^[^:]+:/,\'\');\n
\t\t\tif (!eval(className)) className = \'svg.Element.MISSING\';\n
\t\t\n
\t\t\tvar e = eval(\'new \' + className + \'(node)\');\n
\t\t\te.type = node.nodeName;\n
\t\t\treturn e;\n
\t\t}\n
\t\t\t\t\n
\t\t// load from url\n
\t\tsvg.load = function(ctx, url) {\n
\t\t\tsvg.loadXml(ctx, svg.ajax(url));\n
\t\t}\n
\t\t\n
\t\t// load from xml\n
\t\tsvg.loadXml = function(ctx, xml) {\n
\t\t\tsvg.init(ctx);\n
\t\t\n
\t\t\tvar dom = svg.parseXml(xml);\n
\t\t\tvar e = svg.CreateElement(dom.documentElement);\n
\t\t\t\n
\t\t\t// set canvas size\n
\t\t\tif (e.attribute(\'width\').hasValue()) {\n
\t\t\t\tctx.canvas.width = e.attribute(\'width\').Length.toPixels(ctx.canvas.parentNode.clientWidth);\n
\t\t\t}\n
\t\t\tif (e.attribute(\'height\').hasValue()) {\n
\t\t\t\tctx.canvas.height = e.attribute(\'height\').Length.toPixels(ctx.canvas.parentNode.clientHeight);\n
\t\t\t}\n
\t\t\tsvg.ViewPort.SetCurrent(ctx.canvas.clientWidth, ctx.canvas.clientHeight);\n
\t\t\t\n
\t\t\t// render loop\n
\t\t\tctx.clearRect(0, 0, ctx.canvas.clientWidth, ctx.canvas.clientHeight);\n
\t\t\te.render(ctx);\n
\t\t\tsvg.intervalID = setInterval(function() { \n
\t\t\t\t// update animations\n
\t\t\t\tvar needUpdate = false;\n
\t\t\t\tfor (var i=0; i<svg.Animations.length; i++) {\n
\t\t\t\t\tneedUpdate = needUpdate | svg.Animations[i].update(1000 / svg.FRAMERATE);\n
\t\t\t\t}\n
\t\t\t\n
\t\t\t\t// render if needed\n
\t\t\t\tif (needUpdate) {\n
\t\t\t\t\tctx.clearRect(0, 0, ctx.canvas.clientWidth, ctx.canvas.clientHeight);\n
\t\t\t\t\te.render(ctx);\n
\t\t\t\t}\n
\t\t\t}, 1000 / svg.FRAMERATE);\n
\t\t}\n
\t\t\n
\t\tsvg.stop = function() {\n
\t\t\tif (svg.intervalID) {\n
\t\t\t\tclearInterval(svg.intervalID);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn svg;\n
\t}\n
})();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>57968</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
