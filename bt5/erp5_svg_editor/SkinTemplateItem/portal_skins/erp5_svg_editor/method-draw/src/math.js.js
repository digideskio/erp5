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
            <value> <string>ts52852059.37</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>math.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/**\n
 * Package: svedit.math\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 * Copyright(c) 2010 Jeff Schiller\n
 */\n
\n
// Dependencies:\n
// None.\n
\n
var svgedit = svgedit || {};\n
\n
(function() {\n
\n
if (!svgedit.math) {\n
  svgedit.math = {};\n
}\n
\n
// Constants\n
var NEAR_ZERO = 1e-14;\n
\n
// Throw away SVGSVGElement used for creating matrices/transforms.\n
var svg = document.createElementNS(\'http://www.w3.org/2000/svg\', \'svg\');\n
\n
// Function: svgedit.math.transformPoint\n
// A (hopefully) quicker function to transform a point by a matrix\n
// (this function avoids any DOM calls and just does the math)\n
// \n
// Parameters:\n
// x - Float representing the x coordinate\n
// y - Float representing the y coordinate\n
// m - Matrix object to transform the point with\n
// Returns a x,y object representing the transformed point\n
svgedit.math.transformPoint = function(x, y, m) {\n
  return { x: m.a * x + m.c * y + m.e, y: m.b * x + m.d * y + m.f};\n
};\n
\n
\n
// Function: svgedit.math.isIdentity\n
// Helper function to check if the matrix performs no actual transform \n
// (i.e. exists for identity purposes)\n
//\n
// Parameters: \n
// m - The matrix object to check\n
//\n
// Returns:\n
// Boolean indicating whether or not the matrix is 1,0,0,1,0,0\n
svgedit.math.isIdentity = function(m) {\n
  return (m.a === 1 && m.b === 0 && m.c === 0 && m.d === 1 && m.e === 0 && m.f === 0);\n
};\n
\n
\n
// Function: svgedit.math.matrixMultiply\n
// This function tries to return a SVGMatrix that is the multiplication m1*m2.\n
// We also round to zero when it\'s near zero\n
// \n
// Parameters:\n
// >= 2 Matrix objects to multiply\n
//\n
// Returns: \n
// The matrix object resulting from the calculation\n
svgedit.math.matrixMultiply = function() {\n
  var args = arguments, i = args.length, m = args[i-1];\n
  \n
  while(i-- > 1) {\n
    var m1 = args[i-1];\n
    m = m1.multiply(m);\n
  }\n
  if (Math.abs(m.a) < NEAR_ZERO) m.a = 0;\n
  if (Math.abs(m.b) < NEAR_ZERO) m.b = 0;\n
  if (Math.abs(m.c) < NEAR_ZERO) m.c = 0;\n
  if (Math.abs(m.d) < NEAR_ZERO) m.d = 0;\n
  if (Math.abs(m.e) < NEAR_ZERO) m.e = 0;\n
  if (Math.abs(m.f) < NEAR_ZERO) m.f = 0;\n
  \n
  return m;\n
};\n
\n
// Function: svgedit.math.hasMatrixTransform\n
// See if the given transformlist includes a non-indentity matrix transform\n
//\n
// Parameters: \n
// tlist - The transformlist to check\n
//\n
// Returns: \n
// Boolean on whether or not a matrix transform was found\n
svgedit.math.hasMatrixTransform = function(tlist) {\n
  if(!tlist) return false;\n
  var num = tlist.numberOfItems;\n
  while (num--) {\n
    var xform = tlist.getItem(num);\n
    if (xform.type == 1 && !svgedit.math.isIdentity(xform.matrix)) return true;\n
  }\n
  return false;\n
};\n
\n
// Function: svgedit.math.transformBox\n
// Transforms a rectangle based on the given matrix\n
//\n
// Parameters:\n
// l - Float with the box\'s left coordinate\n
// t - Float with the box\'s top coordinate\n
// w - Float with the box width\n
// h - Float with the box height\n
// m - Matrix object to transform the box by\n
// \n
// Returns:\n
// An object with the following values:\n
// * tl - The top left coordinate (x,y object)\n
// * tr - The top right coordinate (x,y object)\n
// * bl - The bottom left coordinate (x,y object)\n
// * br - The bottom right coordinate (x,y object)\n
// * aabox - Object with the following values:\n
// * Float with the axis-aligned x coordinate\n
// * Float with the axis-aligned y coordinate\n
// * Float with the axis-aligned width coordinate\n
// * Float with the axis-aligned height coordinate\n
svgedit.math.transformBox = function(l, t, w, h, m) {\n
  var topleft = {x:l,y:t},\n
    topright = {x:(l+w),y:t},\n
    botright = {x:(l+w),y:(t+h)},\n
    botleft = {x:l,y:(t+h)};\n
  var transformPoint = svgedit.math.transformPoint;\n
  topleft = transformPoint( topleft.x, topleft.y, m );\n
  var minx = topleft.x,\n
    maxx = topleft.x,\n
    miny = topleft.y,\n
    maxy = topleft.y;\n
  topright = transformPoint( topright.x, topright.y, m );\n
  minx = Math.min(minx, topright.x);\n
  maxx = Math.max(maxx, topright.x);\n
  miny = Math.min(miny, topright.y);\n
  maxy = Math.max(maxy, topright.y);\n
  botleft = transformPoint( botleft.x, botleft.y, m);\n
  minx = Math.min(minx, botleft.x);\n
  maxx = Math.max(maxx, botleft.x);\n
  miny = Math.min(miny, botleft.y);\n
  maxy = Math.max(maxy, botleft.y);\n
  botright = transformPoint( botright.x, botright.y, m );\n
  minx = Math.min(minx, botright.x);\n
  maxx = Math.max(maxx, botright.x);\n
  miny = Math.min(miny, botright.y);\n
  maxy = Math.max(maxy, botright.y);\n
\n
  return {tl:topleft, tr:topright, bl:botleft, br:botright, \n
      aabox: {x:minx, y:miny, width:(maxx-minx), height:(maxy-miny)} };\n
};\n
\n
// Function: svgedit.math.transformListToTransform\n
// This returns a single matrix Transform for a given Transform List\n
// (this is the equivalent of SVGTransformList.consolidate() but unlike\n
//  that method, this one does not modify the actual SVGTransformList)\n
// This function is very liberal with its min,max arguments\n
// \n
// Parameters:\n
// tlist - The transformlist object\n
// min - Optional integer indicating start transform position\n
// max - Optional integer indicating end transform position\n
//\n
// Returns:\n
// A single matrix transform object\n
svgedit.math.transformListToTransform = function(tlist, min, max) {\n
  if(tlist == null) {\n
    // Or should tlist = null have been prevented before this?\n
    return svg.createSVGTransformFromMatrix(svg.createSVGMatrix());\n
  }\n
  var min = min == undefined ? 0 : min;\n
  var max = max == undefined ? (tlist.numberOfItems-1) : max;\n
  min = parseInt(min);\n
  max = parseInt(max);\n
  if (min > max) { var temp = max; max = min; min = temp; }\n
  var m = svg.createSVGMatrix();\n
  for (var i = min; i <= max; ++i) {\n
    // if our indices are out of range, just use a harmless identity matrix\n
    var mtom = (i >= 0 && i < tlist.numberOfItems ? \n
            tlist.getItem(i).matrix :\n
            svg.createSVGMatrix());\n
    m = svgedit.math.matrixMultiply(m, mtom);\n
  }\n
  return svg.createSVGTransformFromMatrix(m);\n
};\n
\n
\n
// Function: svgedit.math.getMatrix\n
// Get the matrix object for a given element\n
//\n
// Parameters:\n
// elem - The DOM element to check\n
// \n
// Returns:\n
// The matrix object associated with the element\'s transformlist\n
svgedit.math.getMatrix = function(elem) {\n
  var tlist = svgedit.transformlist.getTransformList(elem);\n
  return svgedit.math.transformListToTransform(tlist).matrix;\n
};\n
\n
\n
// Function: svgedit.math.snapToAngle\n
// Returns a 45 degree angle coordinate associated with the two given \n
// coordinates\n
// \n
// Parameters:\n
// x1 - First coordinate\'s x value\n
// x2 - Second coordinate\'s x value\n
// y1 - First coordinate\'s y value\n
// y2 - Second coordinate\'s y value\n
//\n
// Returns: \n
// Object with the following values:\n
// x - The angle-snapped x value\n
// y - The angle-snapped y value\n
// snapangle - The angle at which to snap\n
svgedit.math.snapToAngle = function(x1,y1,x2,y2) {\n
  var snap = Math.PI/4; // 45 degrees\n
  var dx = x2 - x1;\n
  var dy = y2 - y1;\n
  var angle = Math.atan2(dy,dx);\n
  var dist = Math.sqrt(dx * dx + dy * dy);\n
  var snapangle= Math.round(angle/snap)*snap;\n
  var x = x1 + dist*Math.cos(snapangle);  \n
  var y = y1 + dist*Math.sin(snapangle);\n
  //console.log(x1,y1,x2,y2,x,y,angle)\n
  return {x:x, y:y, a:snapangle};\n
};\n
\n
\n
// Function: rectsIntersect\n
// Check if two rectangles (BBoxes objects) intersect each other\n
//\n
// Paramaters:\n
// r1 - The first BBox-like object\n
// r2 - The second BBox-like object\n
//\n
// Returns:\n
// Boolean that\'s true if rectangles intersect\n
svgedit.math.rectsIntersect = function(r1, r2) {\n
  if (!r1 || !r2) return false;\n
  return r2.x < (r1.x+r1.width) && \n
    (r2.x+r2.width) > r1.x &&\n
    r2.y < (r1.y+r1.height) &&\n
    (r2.y+r2.height) > r1.y;\n
};\n
\n
\n
})();

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>7603</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
