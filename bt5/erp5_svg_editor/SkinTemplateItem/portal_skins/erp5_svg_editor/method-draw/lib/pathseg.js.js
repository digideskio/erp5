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
            <value> <string>ts52852170.94</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>pathseg.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// SVGPathSeg API polyfill\n
// https://github.com/progers/pathseg\n
//\n
// This is a drop-in replacement for the SVGPathSeg and SVGPathSegList APIs that were removed from\n
// SVG2 (https://lists.w3.org/Archives/Public/www-svg/2015Jun/0044.html), including the latest spec\n
// changes which were implemented in Firefox 43 and Chrome 46.\n
\n
(function() { "use strict";\n
    if (!("SVGPathSeg" in window)) {\n
        // Spec: http://www.w3.org/TR/SVG11/single-page.html#paths-InterfaceSVGPathSeg\n
        window.SVGPathSeg = function(type, typeAsLetter, owningPathSegList) {\n
            this.pathSegType = type;\n
            this.pathSegTypeAsLetter = typeAsLetter;\n
            this._owningPathSegList = owningPathSegList;\n
        }\n
\n
        SVGPathSeg.PATHSEG_UNKNOWN = 0;\n
        SVGPathSeg.PATHSEG_CLOSEPATH = 1;\n
        SVGPathSeg.PATHSEG_MOVETO_ABS = 2;\n
        SVGPathSeg.PATHSEG_MOVETO_REL = 3;\n
        SVGPathSeg.PATHSEG_LINETO_ABS = 4;\n
        SVGPathSeg.PATHSEG_LINETO_REL = 5;\n
        SVGPathSeg.PATHSEG_CURVETO_CUBIC_ABS = 6;\n
        SVGPathSeg.PATHSEG_CURVETO_CUBIC_REL = 7;\n
        SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_ABS = 8;\n
        SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_REL = 9;\n
        SVGPathSeg.PATHSEG_ARC_ABS = 10;\n
        SVGPathSeg.PATHSEG_ARC_REL = 11;\n
        SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_ABS = 12;\n
        SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_REL = 13;\n
        SVGPathSeg.PATHSEG_LINETO_VERTICAL_ABS = 14;\n
        SVGPathSeg.PATHSEG_LINETO_VERTICAL_REL = 15;\n
        SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_ABS = 16;\n
        SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_REL = 17;\n
        SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_ABS = 18;\n
        SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_REL = 19;\n
\n
        // Notify owning PathSegList on any changes so they can be synchronized back to the path element.\n
        SVGPathSeg.prototype._segmentChanged = function() {\n
            if (this._owningPathSegList)\n
                this._owningPathSegList.segmentChanged(this);\n
        }\n
\n
        window.SVGPathSegClosePath = function(owningPathSegList) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CLOSEPATH, "z", owningPathSegList);\n
        }\n
        SVGPathSegClosePath.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegClosePath.prototype.toString = function() { return "[object SVGPathSegClosePath]"; }\n
        SVGPathSegClosePath.prototype._asPathString = function() { return this.pathSegTypeAsLetter; }\n
        SVGPathSegClosePath.prototype.clone = function() { return new SVGPathSegClosePath(undefined); }\n
\n
        window.SVGPathSegMovetoAbs = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_MOVETO_ABS, "M", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegMovetoAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegMovetoAbs.prototype.toString = function() { return "[object SVGPathSegMovetoAbs]"; }\n
        SVGPathSegMovetoAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegMovetoAbs.prototype.clone = function() { return new SVGPathSegMovetoAbs(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegMovetoAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegMovetoAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegMovetoRel = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_MOVETO_REL, "m", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegMovetoRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegMovetoRel.prototype.toString = function() { return "[object SVGPathSegMovetoRel]"; }\n
        SVGPathSegMovetoRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegMovetoRel.prototype.clone = function() { return new SVGPathSegMovetoRel(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegMovetoRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegMovetoRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoAbs = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_ABS, "L", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegLinetoAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoAbs.prototype.toString = function() { return "[object SVGPathSegLinetoAbs]"; }\n
        SVGPathSegLinetoAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegLinetoAbs.prototype.clone = function() { return new SVGPathSegLinetoAbs(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegLinetoAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegLinetoAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoRel = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_REL, "l", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegLinetoRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoRel.prototype.toString = function() { return "[object SVGPathSegLinetoRel]"; }\n
        SVGPathSegLinetoRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegLinetoRel.prototype.clone = function() { return new SVGPathSegLinetoRel(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegLinetoRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegLinetoRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoCubicAbs = function(owningPathSegList, x, y, x1, y1, x2, y2) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_CUBIC_ABS, "C", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x1 = x1;\n
            this._y1 = y1;\n
            this._x2 = x2;\n
            this._y2 = y2;\n
        }\n
        SVGPathSegCurvetoCubicAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoCubicAbs.prototype.toString = function() { return "[object SVGPathSegCurvetoCubicAbs]"; }\n
        SVGPathSegCurvetoCubicAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x1 + " " + this._y1 + " " + this._x2 + " " + this._y2 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoCubicAbs.prototype.clone = function() { return new SVGPathSegCurvetoCubicAbs(undefined, this._x, this._y, this._x1, this._y1, this._x2, this._y2); }\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "x1", { get: function() { return this._x1; }, set: function(x1) { this._x1 = x1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "y1", { get: function() { return this._y1; }, set: function(y1) { this._y1 = y1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "x2", { get: function() { return this._x2; }, set: function(x2) { this._x2 = x2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicAbs.prototype, "y2", { get: function() { return this._y2; }, set: function(y2) { this._y2 = y2; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoCubicRel = function(owningPathSegList, x, y, x1, y1, x2, y2) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_CUBIC_REL, "c", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x1 = x1;\n
            this._y1 = y1;\n
            this._x2 = x2;\n
            this._y2 = y2;\n
        }\n
        SVGPathSegCurvetoCubicRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoCubicRel.prototype.toString = function() { return "[object SVGPathSegCurvetoCubicRel]"; }\n
        SVGPathSegCurvetoCubicRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x1 + " " + this._y1 + " " + this._x2 + " " + this._y2 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoCubicRel.prototype.clone = function() { return new SVGPathSegCurvetoCubicRel(undefined, this._x, this._y, this._x1, this._y1, this._x2, this._y2); }\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "x1", { get: function() { return this._x1; }, set: function(x1) { this._x1 = x1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "y1", { get: function() { return this._y1; }, set: function(y1) { this._y1 = y1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "x2", { get: function() { return this._x2; }, set: function(x2) { this._x2 = x2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicRel.prototype, "y2", { get: function() { return this._y2; }, set: function(y2) { this._y2 = y2; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoQuadraticAbs = function(owningPathSegList, x, y, x1, y1) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_ABS, "Q", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x1 = x1;\n
            this._y1 = y1;\n
        }\n
        SVGPathSegCurvetoQuadraticAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoQuadraticAbs.prototype.toString = function() { return "[object SVGPathSegCurvetoQuadraticAbs]"; }\n
        SVGPathSegCurvetoQuadraticAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x1 + " " + this._y1 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoQuadraticAbs.prototype.clone = function() { return new SVGPathSegCurvetoQuadraticAbs(undefined, this._x, this._y, this._x1, this._y1); }\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticAbs.prototype, "x1", { get: function() { return this._x1; }, set: function(x1) { this._x1 = x1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticAbs.prototype, "y1", { get: function() { return this._y1; }, set: function(y1) { this._y1 = y1; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoQuadraticRel = function(owningPathSegList, x, y, x1, y1) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_REL, "q", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x1 = x1;\n
            this._y1 = y1;\n
        }\n
        SVGPathSegCurvetoQuadraticRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoQuadraticRel.prototype.toString = function() { return "[object SVGPathSegCurvetoQuadraticRel]"; }\n
        SVGPathSegCurvetoQuadraticRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x1 + " " + this._y1 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoQuadraticRel.prototype.clone = function() { return new SVGPathSegCurvetoQuadraticRel(undefined, this._x, this._y, this._x1, this._y1); }\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticRel.prototype, "x1", { get: function() { return this._x1; }, set: function(x1) { this._x1 = x1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticRel.prototype, "y1", { get: function() { return this._y1; }, set: function(y1) { this._y1 = y1; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegArcAbs = function(owningPathSegList, x, y, r1, r2, angle, largeArcFlag, sweepFlag) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_ARC_ABS, "A", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._r1 = r1;\n
            this._r2 = r2;\n
            this._angle = angle;\n
            this._largeArcFlag = largeArcFlag;\n
            this._sweepFlag = sweepFlag;\n
        }\n
        SVGPathSegArcAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegArcAbs.prototype.toString = function() { return "[object SVGPathSegArcAbs]"; }\n
        SVGPathSegArcAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._r1 + " " + this._r2 + " " + this._angle + " " + (this._largeArcFlag ? "1" : "0") + " " + (this._sweepFlag ? "1" : "0") + " " + this._x + " " + this._y; }\n
        SVGPathSegArcAbs.prototype.clone = function() { return new SVGPathSegArcAbs(undefined, this._x, this._y, this._r1, this._r2, this._angle, this._largeArcFlag, this._sweepFlag); }\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "r1", { get: function() { return this._r1; }, set: function(r1) { this._r1 = r1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "r2", { get: function() { return this._r2; }, set: function(r2) { this._r2 = r2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "angle", { get: function() { return this._angle; }, set: function(angle) { this._angle = angle; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "largeArcFlag", { get: function() { return this._largeArcFlag; }, set: function(largeArcFlag) { this._largeArcFlag = largeArcFlag; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcAbs.prototype, "sweepFlag", { get: function() { return this._sweepFlag; }, set: function(sweepFlag) { this._sweepFlag = sweepFlag; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegArcRel = function(owningPathSegList, x, y, r1, r2, angle, largeArcFlag, sweepFlag) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_ARC_REL, "a", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._r1 = r1;\n
            this._r2 = r2;\n
            this._angle = angle;\n
            this._largeArcFlag = largeArcFlag;\n
            this._sweepFlag = sweepFlag;\n
        }\n
        SVGPathSegArcRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegArcRel.prototype.toString = function() { return "[object SVGPathSegArcRel]"; }\n
        SVGPathSegArcRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._r1 + " " + this._r2 + " " + this._angle + " " + (this._largeArcFlag ? "1" : "0") + " " + (this._sweepFlag ? "1" : "0") + " " + this._x + " " + this._y; }\n
        SVGPathSegArcRel.prototype.clone = function() { return new SVGPathSegArcRel(undefined, this._x, this._y, this._r1, this._r2, this._angle, this._largeArcFlag, this._sweepFlag); }\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "r1", { get: function() { return this._r1; }, set: function(r1) { this._r1 = r1; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "r2", { get: function() { return this._r2; }, set: function(r2) { this._r2 = r2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "angle", { get: function() { return this._angle; }, set: function(angle) { this._angle = angle; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "largeArcFlag", { get: function() { return this._largeArcFlag; }, set: function(largeArcFlag) { this._largeArcFlag = largeArcFlag; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegArcRel.prototype, "sweepFlag", { get: function() { return this._sweepFlag; }, set: function(sweepFlag) { this._sweepFlag = sweepFlag; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoHorizontalAbs = function(owningPathSegList, x) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_ABS, "H", owningPathSegList);\n
            this._x = x;\n
        }\n
        SVGPathSegLinetoHorizontalAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoHorizontalAbs.prototype.toString = function() { return "[object SVGPathSegLinetoHorizontalAbs]"; }\n
        SVGPathSegLinetoHorizontalAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x; }\n
        SVGPathSegLinetoHorizontalAbs.prototype.clone = function() { return new SVGPathSegLinetoHorizontalAbs(undefined, this._x); }\n
        Object.defineProperty(SVGPathSegLinetoHorizontalAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoHorizontalRel = function(owningPathSegList, x) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_REL, "h", owningPathSegList);\n
            this._x = x;\n
        }\n
        SVGPathSegLinetoHorizontalRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoHorizontalRel.prototype.toString = function() { return "[object SVGPathSegLinetoHorizontalRel]"; }\n
        SVGPathSegLinetoHorizontalRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x; }\n
        SVGPathSegLinetoHorizontalRel.prototype.clone = function() { return new SVGPathSegLinetoHorizontalRel(undefined, this._x); }\n
        Object.defineProperty(SVGPathSegLinetoHorizontalRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoVerticalAbs = function(owningPathSegList, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_VERTICAL_ABS, "V", owningPathSegList);\n
            this._y = y;\n
        }\n
        SVGPathSegLinetoVerticalAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoVerticalAbs.prototype.toString = function() { return "[object SVGPathSegLinetoVerticalAbs]"; }\n
        SVGPathSegLinetoVerticalAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._y; }\n
        SVGPathSegLinetoVerticalAbs.prototype.clone = function() { return new SVGPathSegLinetoVerticalAbs(undefined, this._y); }\n
        Object.defineProperty(SVGPathSegLinetoVerticalAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegLinetoVerticalRel = function(owningPathSegList, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_LINETO_VERTICAL_REL, "v", owningPathSegList);\n
            this._y = y;\n
        }\n
        SVGPathSegLinetoVerticalRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegLinetoVerticalRel.prototype.toString = function() { return "[object SVGPathSegLinetoVerticalRel]"; }\n
        SVGPathSegLinetoVerticalRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._y; }\n
        SVGPathSegLinetoVerticalRel.prototype.clone = function() { return new SVGPathSegLinetoVerticalRel(undefined, this._y); }\n
        Object.defineProperty(SVGPathSegLinetoVerticalRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoCubicSmoothAbs = function(owningPathSegList, x, y, x2, y2) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_ABS, "S", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x2 = x2;\n
            this._y2 = y2;\n
        }\n
        SVGPathSegCurvetoCubicSmoothAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoCubicSmoothAbs.prototype.toString = function() { return "[object SVGPathSegCurvetoCubicSmoothAbs]"; }\n
        SVGPathSegCurvetoCubicSmoothAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x2 + " " + this._y2 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoCubicSmoothAbs.prototype.clone = function() { return new SVGPathSegCurvetoCubicSmoothAbs(undefined, this._x, this._y, this._x2, this._y2); }\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothAbs.prototype, "x2", { get: function() { return this._x2; }, set: function(x2) { this._x2 = x2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothAbs.prototype, "y2", { get: function() { return this._y2; }, set: function(y2) { this._y2 = y2; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoCubicSmoothRel = function(owningPathSegList, x, y, x2, y2) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_REL, "s", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
            this._x2 = x2;\n
            this._y2 = y2;\n
        }\n
        SVGPathSegCurvetoCubicSmoothRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoCubicSmoothRel.prototype.toString = function() { return "[object SVGPathSegCurvetoCubicSmoothRel]"; }\n
        SVGPathSegCurvetoCubicSmoothRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x2 + " " + this._y2 + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoCubicSmoothRel.prototype.clone = function() { return new SVGPathSegCurvetoCubicSmoothRel(undefined, this._x, this._y, this._x2, this._y2); }\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothRel.prototype, "x2", { get: function() { return this._x2; }, set: function(x2) { this._x2 = x2; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoCubicSmoothRel.prototype, "y2", { get: function() { return this._y2; }, set: function(y2) { this._y2 = y2; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoQuadraticSmoothAbs = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_ABS, "T", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegCurvetoQuadraticSmoothAbs.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoQuadraticSmoothAbs.prototype.toString = function() { return "[object SVGPathSegCurvetoQuadraticSmoothAbs]"; }\n
        SVGPathSegCurvetoQuadraticSmoothAbs.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoQuadraticSmoothAbs.prototype.clone = function() { return new SVGPathSegCurvetoQuadraticSmoothAbs(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticSmoothAbs.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticSmoothAbs.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        window.SVGPathSegCurvetoQuadraticSmoothRel = function(owningPathSegList, x, y) {\n
            SVGPathSeg.call(this, SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_REL, "t", owningPathSegList);\n
            this._x = x;\n
            this._y = y;\n
        }\n
        SVGPathSegCurvetoQuadraticSmoothRel.prototype = Object.create(SVGPathSeg.prototype);\n
        SVGPathSegCurvetoQuadraticSmoothRel.prototype.toString = function() { return "[object SVGPathSegCurvetoQuadraticSmoothRel]"; }\n
        SVGPathSegCurvetoQuadraticSmoothRel.prototype._asPathString = function() { return this.pathSegTypeAsLetter + " " + this._x + " " + this._y; }\n
        SVGPathSegCurvetoQuadraticSmoothRel.prototype.clone = function() { return new SVGPathSegCurvetoQuadraticSmoothRel(undefined, this._x, this._y); }\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticSmoothRel.prototype, "x", { get: function() { return this._x; }, set: function(x) { this._x = x; this._segmentChanged(); }, enumerable: true });\n
        Object.defineProperty(SVGPathSegCurvetoQuadraticSmoothRel.prototype, "y", { get: function() { return this._y; }, set: function(y) { this._y = y; this._segmentChanged(); }, enumerable: true });\n
\n
        // Add createSVGPathSeg* functions to SVGPathElement.\n
        // Spec: http://www.w3.org/TR/SVG11/single-page.html#paths-InterfaceSVGPathElement.\n
        SVGPathElement.prototype.createSVGPathSegClosePath = function() { return new SVGPathSegClosePath(undefined); }\n
        SVGPathElement.prototype.createSVGPathSegMovetoAbs = function(x, y) { return new SVGPathSegMovetoAbs(undefined, x, y); }\n
        SVGPathElement.prototype.createSVGPathSegMovetoRel = function(x, y) { return new SVGPathSegMovetoRel(undefined, x, y); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoAbs = function(x, y) { return new SVGPathSegLinetoAbs(undefined, x, y); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoRel = function(x, y) { return new SVGPathSegLinetoRel(undefined, x, y); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoCubicAbs = function(x, y, x1, y1, x2, y2) { return new SVGPathSegCurvetoCubicAbs(undefined, x, y, x1, y1, x2, y2); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoCubicRel = function(x, y, x1, y1, x2, y2) { return new SVGPathSegCurvetoCubicRel(undefined, x, y, x1, y1, x2, y2); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoQuadraticAbs = function(x, y, x1, y1) { return new SVGPathSegCurvetoQuadraticAbs(undefined, x, y, x1, y1); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoQuadraticRel = function(x, y, x1, y1) { return new SVGPathSegCurvetoQuadraticRel(undefined, x, y, x1, y1); }\n
        SVGPathElement.prototype.createSVGPathSegArcAbs = function(x, y, r1, r2, angle, largeArcFlag, sweepFlag) { return new SVGPathSegArcAbs(undefined, x, y, r1, r2, angle, largeArcFlag, sweepFlag); }\n
        SVGPathElement.prototype.createSVGPathSegArcRel = function(x, y, r1, r2, angle, largeArcFlag, sweepFlag) { return new SVGPathSegArcRel(undefined, x, y, r1, r2, angle, largeArcFlag, sweepFlag); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoHorizontalAbs = function(x) { return new SVGPathSegLinetoHorizontalAbs(undefined, x); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoHorizontalRel = function(x) { return new SVGPathSegLinetoHorizontalRel(undefined, x); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoVerticalAbs = function(y) { return new SVGPathSegLinetoVerticalAbs(undefined, y); }\n
        SVGPathElement.prototype.createSVGPathSegLinetoVerticalRel = function(y) { return new SVGPathSegLinetoVerticalRel(undefined, y); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoCubicSmoothAbs = function(x, y, x2, y2) { return new SVGPathSegCurvetoCubicSmoothAbs(undefined, x, y, x2, y2); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoCubicSmoothRel = function(x, y, x2, y2) { return new SVGPathSegCurvetoCubicSmoothRel(undefined, x, y, x2, y2); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoQuadraticSmoothAbs = function(x, y) { return new SVGPathSegCurvetoQuadraticSmoothAbs(undefined, x, y); }\n
        SVGPathElement.prototype.createSVGPathSegCurvetoQuadraticSmoothRel = function(x, y) { return new SVGPathSegCurvetoQuadraticSmoothRel(undefined, x, y); }\n
    }\n
\n
    if (!("SVGPathSegList" in window)) {\n
        // Spec: http://www.w3.org/TR/SVG11/single-page.html#paths-InterfaceSVGPathSegList\n
        window.SVGPathSegList = function(pathElement) {\n
            this._pathElement = pathElement;\n
            this._list = this._parsePath(this._pathElement.getAttribute("d"));\n
\n
            // Use a MutationObserver to catch changes to the path\'s "d" attribute.\n
            this._mutationObserverConfig = { "attributes": true, "attributeFilter": ["d"] };\n
            this._pathElementMutationObserver = new MutationObserver(this._updateListFromPathMutations.bind(this));\n
            this._pathElementMutationObserver.observe(this._pathElement, this._mutationObserverConfig);\n
        }\n
\n
        Object.defineProperty(SVGPathSegList.prototype, "numberOfItems", {\n
            get: function() {\n
                this._checkPathSynchronizedToList();\n
                return this._list.length;\n
            },\n
            enumerable: true\n
        });\n
\n
        // Add the pathSegList accessors to SVGPathElement.\n
        // Spec: http://www.w3.org/TR/SVG11/single-page.html#paths-InterfaceSVGAnimatedPathData\n
        Object.defineProperty(SVGPathElement.prototype, "pathSegList", {\n
            get: function() {\n
                if (!this._pathSegList)\n
                    this._pathSegList = new SVGPathSegList(this);\n
                return this._pathSegList;\n
            },\n
            enumerable: true\n
        });\n
        // FIXME: The following are not implemented and simply return SVGPathElement.pathSegList.\n
        Object.defineProperty(SVGPathElement.prototype, "normalizedPathSegList", { get: function() { return this.pathSegList; }, enumerable: true });\n
        Object.defineProperty(SVGPathElement.prototype, "animatedPathSegList", { get: function() { return this.pathSegList; }, enumerable: true });\n
        Object.defineProperty(SVGPathElement.prototype, "animatedNormalizedPathSegList", { get: function() { return this.pathSegList; }, enumerable: true });\n
\n
        // Process any pending mutations to the path element and update the list as needed.\n
        // This should be the first call of all public functions and is needed because\n
        // MutationObservers are not synchronous so we can have pending asynchronous mutations.\n
        SVGPathSegList.prototype._checkPathSynchronizedToList = function() {\n
            this._updateListFromPathMutations(this._pathElementMutationObserver.takeRecords());\n
        }\n
\n
        SVGPathSegList.prototype._updateListFromPathMutations = function(mutationRecords) {\n
            if (!this._pathElement)\n
                return;\n
            var hasPathMutations = false;\n
            mutationRecords.forEach(function(record) {\n
                if (record.attributeName == "d")\n
                    hasPathMutations = true;\n
            });\n
            if (hasPathMutations)\n
                this._list = this._parsePath(this._pathElement.getAttribute("d"));\n
        }\n
\n
        // Serialize the list and update the path\'s \'d\' attribute.\n
        SVGPathSegList.prototype._writeListToPath = function() {\n
            this._pathElementMutationObserver.disconnect();\n
            this._pathElement.setAttribute("d", SVGPathSegList._pathSegArrayAsString(this._list));\n
            this._pathElementMutationObserver.observe(this._pathElement, this._mutationObserverConfig);\n
        }\n
\n
        // When a path segment changes the list needs to be synchronized back to the path element.\n
        SVGPathSegList.prototype.segmentChanged = function(pathSeg) {\n
            this._writeListToPath();\n
        }\n
\n
        SVGPathSegList.prototype.clear = function() {\n
            this._checkPathSynchronizedToList();\n
\n
            this._list.forEach(function(pathSeg) {\n
                pathSeg._owningPathSegList = null;\n
            });\n
            this._list = [];\n
            this._writeListToPath();\n
        }\n
\n
        SVGPathSegList.prototype.initialize = function(newItem) {\n
            this._checkPathSynchronizedToList();\n
\n
            this._list = [newItem];\n
            newItem._owningPathSegList = this;\n
            this._writeListToPath();\n
            return newItem;\n
        }\n
\n
        SVGPathSegList.prototype._checkValidIndex = function(index) {\n
            if (isNaN(index) || index < 0 || index >= this.numberOfItems)\n
                throw "INDEX_SIZE_ERR";\n
        }\n
\n
        SVGPathSegList.prototype.getItem = function(index) {\n
            this._checkPathSynchronizedToList();\n
\n
            this._checkValidIndex(index);\n
            return this._list[index];\n
        }\n
\n
        SVGPathSegList.prototype.insertItemBefore = function(newItem, index) {\n
            this._checkPathSynchronizedToList();\n
\n
            // Spec: If the index is greater than or equal to numberOfItems, then the new item is appended to the end of the list.\n
            if (index > this.numberOfItems)\n
                index = this.numberOfItems;\n
            if (newItem._owningPathSegList) {\n
                // SVG2 spec says to make a copy.\n
                newItem = newItem.clone();\n
            }\n
            this._list.splice(index, 0, newItem);\n
            newItem._owningPathSegList = this;\n
            this._writeListToPath();\n
            return newItem;\n
        }\n
\n
        SVGPathSegList.prototype.replaceItem = function(newItem, index) {\n
            this._checkPathSynchronizedToList();\n
\n
            if (newItem._owningPathSegList) {\n
                // SVG2 spec says to make a copy.\n
                newItem = newItem.clone();\n
            }\n
            this._checkValidIndex(index);\n
            this._list[index] = newItem;\n
            newItem._owningPathSegList = this;\n
            this._writeListToPath();\n
            return newItem;\n
        }\n
\n
        SVGPathSegList.prototype.removeItem = function(index) {\n
            this._checkPathSynchronizedToList();\n
\n
            this._checkValidIndex(index);\n
            var item = this._list[index];\n
            this._list.splice(index, 1);\n
            this._writeListToPath();\n
            return item;\n
        }\n
\n
        SVGPathSegList.prototype.appendItem = function(newItem) {\n
            this._checkPathSynchronizedToList();\n
\n
            if (newItem._owningPathSegList) {\n
                // SVG2 spec says to make a copy.\n
                newItem = newItem.clone();\n
            }\n
            this._list.push(newItem);\n
            newItem._owningPathSegList = this;\n
            // TODO: Optimize this to just append to the existing attribute.\n
            this._writeListToPath();\n
            return newItem;\n
        }\n
\n
        SVGPathSegList._pathSegArrayAsString = function(pathSegArray) {\n
            var string = "";\n
            var first = true;\n
            pathSegArray.forEach(function(pathSeg) {\n
                if (first) {\n
                    first = false;\n
                    string += pathSeg._asPathString();\n
                } else {\n
                    string += " " + pathSeg._asPathString();\n
                }\n
            });\n
            return string;\n
        }\n
\n
        // This closely follows SVGPathParser::parsePath from Source/core/svg/SVGPathParser.cpp.\n
        SVGPathSegList.prototype._parsePath = function(string) {\n
            if (!string || string.length == 0)\n
                return [];\n
\n
            var owningPathSegList = this;\n
\n
            var Builder = function() {\n
                this.pathSegList = [];\n
            }\n
\n
            Builder.prototype.appendSegment = function(pathSeg) {\n
                this.pathSegList.push(pathSeg);\n
            }\n
\n
            var Source = function(string) {\n
                this._string = string;\n
                this._currentIndex = 0;\n
                this._endIndex = this._string.length;\n
                this._previousCommand = SVGPathSeg.PATHSEG_UNKNOWN;\n
\n
                this._skipOptionalSpaces();\n
            }\n
\n
            Source.prototype._isCurrentSpace = function() {\n
                var character = this._string[this._currentIndex];\n
                return character <= " " && (character == " " || character == "\\n" || character == "\\t" || character == "\\r" || character == "\\f");\n
            }\n
\n
            Source.prototype._skipOptionalSpaces = function() {\n
                while (this._currentIndex < this._endIndex && this._isCurrentSpace())\n
                    this._currentIndex++;\n
                return this._currentIndex < this._endIndex;\n
            }\n
\n
            Source.prototype._skipOptionalSpacesOrDelimiter = function() {\n
                if (this._currentIndex < this._endIndex && !this._isCurrentSpace() && this._string.charAt(this._currentIndex) != ",")\n
                    return false;\n
                if (this._skipOptionalSpaces()) {\n
                    if (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) == ",") {\n
                        this._currentIndex++;\n
                        this._skipOptionalSpaces();\n
                    }\n
                }\n
                return this._currentIndex < this._endIndex;\n
            }\n
\n
            Source.prototype.hasMoreData = function() {\n
                return this._currentIndex < this._endIndex;\n
            }\n
\n
            Source.prototype.peekSegmentType = function() {\n
                var lookahead = this._string[this._currentIndex];\n
                return this._pathSegTypeFromChar(lookahead);\n
            }\n
\n
            Source.prototype._pathSegTypeFromChar = function(lookahead) {\n
                switch (lookahead) {\n
                case "Z":\n
                case "z":\n
                    return SVGPathSeg.PATHSEG_CLOSEPATH;\n
                case "M":\n
                    return SVGPathSeg.PATHSEG_MOVETO_ABS;\n
                case "m":\n
                    return SVGPathSeg.PATHSEG_MOVETO_REL;\n
                case "L":\n
                    return SVGPathSeg.PATHSEG_LINETO_ABS;\n
                case "l":\n
                    return SVGPathSeg.PATHSEG_LINETO_REL;\n
                case "C":\n
                    return SVGPathSeg.PATHSEG_CURVETO_CUBIC_ABS;\n
                case "c":\n
                    return SVGPathSeg.PATHSEG_CURVETO_CUBIC_REL;\n
                case "Q":\n
                    return SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_ABS;\n
                case "q":\n
                    return SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_REL;\n
                case "A":\n
                    return SVGPathSeg.PATHSEG_ARC_ABS;\n
                case "a":\n
                    return SVGPathSeg.PATHSEG_ARC_REL;\n
                case "H":\n
                    return SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_ABS;\n
                case "h":\n
                    return SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_REL;\n
                case "V":\n
                    return SVGPathSeg.PATHSEG_LINETO_VERTICAL_ABS;\n
                case "v":\n
                    return SVGPathSeg.PATHSEG_LINETO_VERTICAL_REL;\n
                case "S":\n
                    return SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_ABS;\n
                case "s":\n
                    return SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_REL;\n
                case "T":\n
                    return SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_ABS;\n
                case "t":\n
                    return SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_REL;\n
                default:\n
                    return SVGPathSeg.PATHSEG_UNKNOWN;\n
                }\n
            }\n
\n
            Source.prototype._nextCommandHelper = function(lookahead, previousCommand) {\n
                // Check for remaining coordinates in the current command.\n
                if ((lookahead == "+" || lookahead == "-" || lookahead == "." || (lookahead >= "0" && lookahead <= "9")) && previousCommand != SVGPathSeg.PATHSEG_CLOSEPATH) {\n
                    if (previousCommand == SVGPathSeg.PATHSEG_MOVETO_ABS)\n
                        return SVGPathSeg.PATHSEG_LINETO_ABS;\n
                    if (previousCommand == SVGPathSeg.PATHSEG_MOVETO_REL)\n
                        return SVGPathSeg.PATHSEG_LINETO_REL;\n
                    return previousCommand;\n
                }\n
                return SVGPathSeg.PATHSEG_UNKNOWN;\n
            }\n
\n
            Source.prototype.initialCommandIsMoveTo = function() {\n
                // If the path is empty it is still valid, so return true.\n
                if (!this.hasMoreData())\n
                    return true;\n
                var command = this.peekSegmentType();\n
                // Path must start with moveTo.\n
                return command == SVGPathSeg.PATHSEG_MOVETO_ABS || command == SVGPathSeg.PATHSEG_MOVETO_REL;\n
            }\n
\n
            // Parse a number from an SVG path. This very closely follows genericParseNumber(...) from Source/core/svg/SVGParserUtilities.cpp.\n
            // Spec: http://www.w3.org/TR/SVG11/single-page.html#paths-PathDataBNF\n
            Source.prototype._parseNumber = function() {\n
                var exponent = 0;\n
                var integer = 0;\n
                var frac = 1;\n
                var decimal = 0;\n
                var sign = 1;\n
                var expsign = 1;\n
\n
                var startIndex = this._currentIndex;\n
\n
                this._skipOptionalSpaces();\n
\n
                // Read the sign.\n
                if (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) == "+")\n
                    this._currentIndex++;\n
                else if (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) == "-") {\n
                    this._currentIndex++;\n
                    sign = -1;\n
                }\n
\n
                if (this._currentIndex == this._endIndex || ((this._string.charAt(this._currentIndex) < "0" || this._string.charAt(this._currentIndex) > "9") && this._string.charAt(this._currentIndex) != "."))\n
                    // The first character of a number must be one of [0-9+-.].\n
                    return undefined;\n
\n
                // Read the integer part, build right-to-left.\n
                var startIntPartIndex = this._currentIndex;\n
                while (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) >= "0" && this._string.charAt(this._currentIndex) <= "9")\n
                    this._currentIndex++; // Advance to first non-digit.\n
\n
                if (this._currentIndex != startIntPartIndex) {\n
                    var scanIntPartIndex = this._currentIndex - 1;\n
                    var multiplier = 1;\n
                    while (scanIntPartIndex >= startIntPartIndex) {\n
                        integer += multiplier * (this._string.charAt(scanIntPartIndex--) - "0");\n
                        multiplier *= 10;\n
                    }\n
                }\n
\n
                // Read the decimals.\n
                if (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) == ".") {\n
                    this._currentIndex++;\n
\n
                    // There must be a least one digit following the .\n
                    if (this._currentIndex >= this._endIndex || this._string.charAt(this._currentIndex) < "0" || this._string.charAt(this._currentIndex) > "9")\n
                        return undefined;\n
                    while (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) >= "0" && this._string.charAt(this._currentIndex) <= "9")\n
                        decimal += (this._string.charAt(this._currentIndex++) - "0") * (frac *= 0.1);\n
                }\n
\n
                // Read the exponent part.\n
                if (this._currentIndex != startIndex && this._currentIndex + 1 < this._endIndex && (this._string.charAt(this._currentIndex) == "e" || this._string.charAt(this._currentIndex) == "E") && (this._string.charAt(this._currentIndex + 1) != "x" && this._string.charAt(this._currentIndex + 1) != "m")) {\n
                    this._currentIndex++;\n
\n
                    // Read the sign of the exponent.\n
                    if (this._string.charAt(this._currentIndex) == "+") {\n
                        this._currentIndex++;\n
                    } else if (this._string.charAt(this._currentIndex) == "-") {\n
                        this._currentIndex++;\n
                        expsign = -1;\n
                    }\n
\n
                    // There must be an exponent.\n
                    if (this._currentIndex >= this._endIndex || this._string.charAt(this._currentIndex) < "0" || this._string.charAt(this._currentIndex) > "9")\n
                        return undefined;\n
\n
                    while (this._currentIndex < this._endIndex && this._string.charAt(this._currentIndex) >= "0" && this._string.charAt(this._currentIndex) <= "9") {\n
                        exponent *= 10;\n
                        exponent += (this._string.charAt(this._currentIndex) - "0");\n
                        this._currentIndex++;\n
                    }\n
                }\n
\n
                var number = integer + decimal;\n
                number *= sign;\n
\n
                if (exponent)\n
                    number *= Math.pow(10, expsign * exponent);\n
\n
                if (startIndex == this._currentIndex)\n
                    return undefined;\n
\n
                this._skipOptionalSpacesOrDelimiter();\n
\n
                return number;\n
            }\n
\n
            Source.prototype._parseArcFlag = function() {\n
                if (this._currentIndex >= this._endIndex)\n
                    return undefined;\n
                var flag = false;\n
                var flagChar = this._string.charAt(this._currentIndex++);\n
                if (flagChar == "0")\n
                    flag = false;\n
                else if (flagChar == "1")\n
                    flag = true;\n
                else\n
                    return undefined;\n
\n
                this._skipOptionalSpacesOrDelimiter();\n
                return flag;\n
            }\n
\n
            Source.prototype.parseSegment = function() {\n
                var lookahead = this._string[this._currentIndex];\n
                var command = this._pathSegTypeFromChar(lookahead);\n
                if (command == SVGPathSeg.PATHSEG_UNKNOWN) {\n
                    // Possibly an implicit command. Not allowed if this is the first command.\n
                    if (this._previousCommand == SVGPathSeg.PATHSEG_UNKNOWN)\n
                        return null;\n
                    command = this._nextCommandHelper(lookahead, this._previousCommand);\n
                    if (command == SVGPathSeg.PATHSEG_UNKNOWN)\n
                        return null;\n
                } else {\n
                    this._currentIndex++;\n
                }\n
\n
                this._previousCommand = command;\n
\n
                switch (command) {\n
                case SVGPathSeg.PATHSEG_MOVETO_REL:\n
                    return new SVGPathSegMovetoRel(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_MOVETO_ABS:\n
                    return new SVGPathSegMovetoAbs(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_REL:\n
                    return new SVGPathSegLinetoRel(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_ABS:\n
                    return new SVGPathSegLinetoAbs(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_REL:\n
                    return new SVGPathSegLinetoHorizontalRel(owningPathSegList, this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_HORIZONTAL_ABS:\n
                    return new SVGPathSegLinetoHorizontalAbs(owningPathSegList, this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_VERTICAL_REL:\n
                    return new SVGPathSegLinetoVerticalRel(owningPathSegList, this._parseNumber());\n
                case SVGPathSeg.PATHSEG_LINETO_VERTICAL_ABS:\n
                    return new SVGPathSegLinetoVerticalAbs(owningPathSegList, this._parseNumber());\n
                case SVGPathSeg.PATHSEG_CLOSEPATH:\n
                    this._skipOptionalSpaces();\n
                    return new SVGPathSegClosePath(owningPathSegList);\n
                case SVGPathSeg.PATHSEG_CURVETO_CUBIC_REL:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), x2: this._parseNumber(), y2: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoCubicRel(owningPathSegList, points.x, points.y, points.x1, points.y1, points.x2, points.y2);\n
                case SVGPathSeg.PATHSEG_CURVETO_CUBIC_ABS:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), x2: this._parseNumber(), y2: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoCubicAbs(owningPathSegList, points.x, points.y, points.x1, points.y1, points.x2, points.y2);\n
                case SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_REL:\n
                    var points = {x2: this._parseNumber(), y2: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoCubicSmoothRel(owningPathSegList, points.x, points.y, points.x2, points.y2);\n
                case SVGPathSeg.PATHSEG_CURVETO_CUBIC_SMOOTH_ABS:\n
                    var points = {x2: this._parseNumber(), y2: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoCubicSmoothAbs(owningPathSegList, points.x, points.y, points.x2, points.y2);\n
                case SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_REL:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoQuadraticRel(owningPathSegList, points.x, points.y, points.x1, points.y1);\n
                case SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_ABS:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegCurvetoQuadraticAbs(owningPathSegList, points.x, points.y, points.x1, points.y1);\n
                case SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_REL:\n
                    return new SVGPathSegCurvetoQuadraticSmoothRel(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_CURVETO_QUADRATIC_SMOOTH_ABS:\n
                    return new SVGPathSegCurvetoQuadraticSmoothAbs(owningPathSegList, this._parseNumber(), this._parseNumber());\n
                case SVGPathSeg.PATHSEG_ARC_REL:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), arcAngle: this._parseNumber(), arcLarge: this._parseArcFlag(), arcSweep: this._parseArcFlag(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegArcRel(owningPathSegList, points.x, points.y, points.x1, points.y1, points.arcAngle, points.arcLarge, points.arcSweep);\n
                case SVGPathSeg.PATHSEG_ARC_ABS:\n
                    var points = {x1: this._parseNumber(), y1: this._parseNumber(), arcAngle: this._parseNumber(), arcLarge: this._parseArcFlag(), arcSweep: this._parseArcFlag(), x: this._parseNumber(), y: this._parseNumber()};\n
                    return new SVGPathSegArcAbs(owningPathSegList, points.x, points.y, points.x1, points.y1, points.arcAngle, points.arcLarge, points.arcSweep);\n
                default:\n
                    throw "Unknown path seg type."\n
                }\n
            }\n
\n
            var builder = new Builder();\n
            var source = new Source(string);\n
\n
            if (!source.initialCommandIsMoveTo())\n
                return [];\n
            while (source.hasMoreData()) {\n
                var pathSeg = source.parseSegment();\n
                if (!pathSeg)\n
                    return [];\n
                builder.appendSegment(pathSeg);\n
            }\n
\n
            return builder.pathSegList;\n
        }\n
    }\n
}());

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>55188</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
