<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="DTMLMethod" module="OFS.DTMLMethod"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>BespinMain.js</string> </value>
        </item>
        <item>
            <key> <string>_vars</string> </key>
            <value>
              <dictionary/>
            </value>
        </item>
        <item>
            <key> <string>globals</string> </key>
            <value>
              <dictionary/>
            </value>
        </item>
        <item>
            <key> <string>raw</string> </key>
            <value> <string encoding="cdata"><![CDATA[

;bespin.tiki.register("::text_editor", {\n
    name: "text_editor",\n
    dependencies: { "completion": "0.0.0", "undomanager": "0.0.0", "settings": "0.0.0", "canon": "0.0.0", "rangeutils": "0.0.0", "traits": "0.0.0", "theme_manager": "0.0.0", "keyboard": "0.0.0", "edit_session": "0.0.0", "syntax_manager": "0.0.0" }\n
});\n
bespin.tiki.module("text_editor:views/gutter",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
\n
var CanvasView = require(\'views/canvas\').CanvasView;\n
\n
/*\n
 * A view that renders the gutter for the editor.\n
 *\n
 * The domNode attribute contains the domNode for this view that should be\n
 * added to the document appropriately.\n
 */\n
exports.GutterView = function(container, editor) {\n
    CanvasView.call(this, container, true /* preventDownsize */ );\n
\n
    this.editor = editor;\n
};\n
\n
exports.GutterView.prototype = new CanvasView();\n
\n
util.mixin(exports.GutterView.prototype, {\n
    drawRect: function(rect, context) {\n
        var theme = this.editor.themeData.gutter;\n
\n
        context.fillStyle = theme.backgroundColor;\n
        context.fillRect(rect.x, rect.y, rect.width, rect.height);\n
\n
        context.save();\n
\n
        var paddingLeft = theme.paddingLeft;\n
        context.translate(paddingLeft, 0);\n
\n
        var layoutManager = this.editor.layoutManager;\n
        var range = layoutManager.characterRangeForBoundingRect(rect);\n
        var endRow = Math.min(range.end.row,\n
            layoutManager.textLines.length - 1);\n
        var lineAscent = layoutManager.fontDimension.lineAscent;\n
\n
        context.fillStyle = theme.color;\n
        context.font = this.editor.font;\n
\n
        for (var row = range.start.row; row <= endRow; row++) {\n
            // TODO: breakpoints\n
            context.fillText(\'\' + (row + 1), -0.5,\n
                layoutManager.lineRectForRow(row).y + lineAscent - 0.5);\n
        }\n
\n
        context.restore();\n
    },\n
\n
    computeWidth: function() {\n
        var theme = this.editor.themeData.gutter;\n
        var paddingWidth = theme.paddingLeft + theme.paddingRight;\n
\n
        var lineNumberFont = this.editor.font;\n
\n
        var layoutManager = this.editor.layoutManager;\n
        var lineCount = layoutManager.textLines.length;\n
        var lineCountStr = \'\' + lineCount;\n
\n
        var characterWidth = layoutManager.fontDimension.characterWidth;\n
        var strWidth = characterWidth * lineCountStr.length;\n
\n
        return strWidth + paddingWidth;\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:views/scroller",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var Event = require(\'events\').Event;\n
var console = require(\'bespin:console\').console;\n
\n
var Rect = require(\'utils/rect\');\n
\n
var CanvasView = require(\'views/canvas\').CanvasView;\n
\n
var LINE_HEIGHT                 = 15;\n
var MINIMUM_HANDLE_SIZE         = 20;\n
var NIB_ARROW_PADDING_BEFORE    = 3;\n
var NIB_ARROW_PADDING_AFTER     = 5;\n
var NIB_LENGTH                  = 15;\n
var NIB_PADDING                 = 8;    // 15/2\n
\n
var LAYOUT_HORIZONTAL = exports.LAYOUT_HORIZONTAL = 0;\n
var LAYOUT_VERTICAL = exports.LAYOUT_VERTICAL = 1;\n
\n
exports.ScrollerCanvasView = function(editor, layoutDirection) {\n
    CanvasView.call(this, editor.container, false /* preventDownsize */,\n
        true /* clearOnFullInvalid */);\n
    this.editor = editor;\n
    this.layoutDirection = layoutDirection;\n
\n
    var on = function(eventName, func, target) {\n
        target = target || this.domNode;\n
        target.addEventListener(eventName, function(evt) {\n
            func.call(this, evt);\n
            util.stopEvent(evt);\n
        }.bind(this), false);\n
    }.bind(this);\n
\n
    on(\'mouseover\', this.mouseEntered);\n
    on(\'mouseout\', this.mouseExited);\n
    on(\'mousedown\', this.mouseDown);\n
    // Bind the following events to the window as we want to catch them\n
    // even when the mouse is outside of the scroller.\n
    on(\'mouseup\', this.mouseUp, window);\n
    on(\'mousemove\', this.mouseMove, window);\n
\n
    this.valueChanged = new Event();\n
};\n
\n
exports.ScrollerCanvasView.prototype = new CanvasView();\n
\n
util.mixin(exports.ScrollerCanvasView.prototype, {\n
    lineHeight: 20,\n
\n
    proportion: 0,\n
\n
    /**\n
     * @property\n
     * Specifies the direction of the scroll bar: one of LAYOUT_HORIZONTAL\n
     * or LAYOUT_VERTICAL.\n
     *\n
     * Changes to this value after the view has been created have no effect.\n
     */\n
    layoutDirection: LAYOUT_VERTICAL,\n
\n
    _isVisible: false,\n
\n
    _maximum: 0,\n
\n
    _value: 0,\n
\n
    valueChanged: null,\n
\n
    /**\n
     * @property\n
     * The dimensions of transparent space inside the frame, given as an object\n
     * with \'left\', \'bottom\', \'top\', and \'right\' properties.\n
     *\n
     * Note that the scrollerThickness property includes the padding on the\n
     * sides of the bar.\n
     */\n
    padding: { left: 0, bottom: 0, top: 0, right: 0 },\n
\n
    _mouseDownScreenPoint: null,\n
    _mouseDownValue: null,\n
    _isMouseOver: false,\n
    _scrollTimer: null,\n
    _mouseEventPosition: null,\n
    _mouseOverHandle: false,\n
\n
    _drawNib: function(ctx, alpha) {\n
        var theme = this.editor.themeData.scroller;\n
        var fillStyle, arrowStyle, strokeStyle;\n
\n
        fillStyle   = theme.nibStyle;\n
        arrowStyle  = theme.nibArrowStyle;\n
        strokeStyle = theme.nibStrokeStyle;\n
\n
        var midpoint = Math.floor(NIB_LENGTH / 2);\n
\n
        ctx.fillStyle = fillStyle;\n
        ctx.beginPath();\n
        ctx.arc(0, 0, Math.floor(NIB_LENGTH / 2), 0, Math.PI * 2, true);\n
        ctx.closePath();\n
        ctx.fill();\n
        ctx.strokeStyle = strokeStyle;\n
        ctx.stroke();\n
\n
        ctx.fillStyle = arrowStyle;\n
        ctx.beginPath();\n
        ctx.moveTo(0, -midpoint + NIB_ARROW_PADDING_BEFORE);\n
        ctx.lineTo(-midpoint + NIB_ARROW_PADDING_BEFORE,\n
            midpoint - NIB_ARROW_PADDING_AFTER);\n
        ctx.lineTo(midpoint - NIB_ARROW_PADDING_BEFORE,\n
            midpoint - NIB_ARROW_PADDING_AFTER);\n
        ctx.closePath();\n
        ctx.fill();\n
    },\n
\n
    _drawNibs: function(ctx, alpha) {\n
        var thickness = this._getClientThickness();\n
        var parentView = this.parentView;\n
        var value = this._value;\n
        var maximum = this._maximum;\n
        var highlighted = this._isHighlighted();\n
\n
        // Starting nib\n
        if (highlighted || value !== 0) {\n
            ctx.save();\n
            ctx.translate(NIB_PADDING, thickness / 2);\n
            ctx.rotate(Math.PI * 1.5);\n
            ctx.moveTo(0, 0);\n
            this._drawNib(ctx, alpha);\n
            ctx.restore();\n
        }\n
\n
        // Ending nib\n
        if (highlighted || value !== maximum) {\n
            ctx.save();\n
            ctx.translate(this._getClientLength() - NIB_PADDING,\n
                thickness / 2);\n
            ctx.rotate(Math.PI * 0.5);\n
            ctx.moveTo(0, 0);\n
            this._drawNib(ctx, alpha);\n
            ctx.restore();\n
        }\n
    },\n
\n
    // Returns the frame of the scroll bar, not counting any padding.\n
    _getClientFrame: function() {\n
        var frame = this.frame;\n
        var padding = this.padding;\n
        return {\n
            x:      padding.left,\n
            y:      padding.top,\n
            width:  frame.width - (padding.left + padding.right),\n
            height: frame.height - (padding.top + padding.bottom)\n
        };\n
    },\n
\n
    // Returns the length of the scroll bar, not counting any padding. Equal to\n
    // the width or height of the client frame, depending on the layout\n
    // direction.\n
    _getClientLength: function() {\n
        var clientFrame = this._getClientFrame();\n
        switch (this.layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            return clientFrame.width;\n
        case LAYOUT_VERTICAL:\n
            return clientFrame.height;\n
        default:\n
            console.error("unknown layout direction");\n
            return null;\n
        }\n
    },\n
\n
    // Returns the thickness of the scroll bar, not counting any padding.\n
    _getClientThickness: function() {\n
        var padding = this.padding;\n
        var scrollerThickness = this.editor.themeData.scroller.thickness;\n
\n
        switch (this.layoutDirection) {\n
        case LAYOUT_VERTICAL:\n
            return scrollerThickness - (padding.left + padding.right);\n
        case LAYOUT_HORIZONTAL:\n
            return scrollerThickness - (padding.top + padding.bottom);\n
        default:\n
            console.error("unknown layout direction");\n
            return null;\n
        }\n
    },\n
\n
    // The length of the scroll bar, counting the padding. Equal to frame.width\n
    // or frame.height, depending on the layout direction of the bar.\n
    // Read-only.\n
    _getFrameLength: function() {\n
        switch (this.layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            return this.frame.width;\n
        case LAYOUT_VERTICAL:\n
            return this.frame.height;\n
        default:\n
            console.error("unknown layout direction");\n
            return null;\n
        }\n
    },\n
\n
    // The dimensions of the gutter (the middle area between the buttons, which\n
    // contains the handle or knob).\n
    _getGutterFrame: function() {\n
        var clientFrame = this._getClientFrame();\n
        var thickness = this._getClientThickness();\n
        switch (this.layoutDirection) {\n
        case LAYOUT_VERTICAL:\n
            return {\n
                x:      clientFrame.x,\n
                y:      clientFrame.y + NIB_LENGTH,\n
                width:  thickness,\n
                height: Math.max(0, clientFrame.height - 2*NIB_LENGTH)\n
            };\n
        case LAYOUT_HORIZONTAL:\n
            return {\n
                x:      clientFrame.x + NIB_LENGTH,\n
                y:      clientFrame.y,\n
                width:  Math.max(0, clientFrame.width - 2*NIB_LENGTH),\n
                height: thickness\n
            };\n
        default:\n
            console.error("unknown layout direction");\n
            return null;\n
        }\n
    },\n
\n
    // The length of the gutter, equal to gutterFrame.width or\n
    // gutterFrame.height depending on the scroll bar\'s layout direction.\n
    _getGutterLength: function() {\n
        var gutterFrame = this._getGutterFrame();\n
        var gutterLength;\n
        switch (this.layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            gutterLength = gutterFrame.width;\n
            break;\n
        case LAYOUT_VERTICAL:\n
            gutterLength = gutterFrame.height;\n
            break;\n
        default:\n
            console.error("unknown layout direction");\n
            break;\n
        }\n
        return gutterLength;\n
    },\n
\n
    // Returns the dimensions of the handle or knob.\n
    _getHandleFrame: function() {\n
        var gutterFrame = this._getGutterFrame();\n
        var handleOffset = this._getHandleOffset();\n
        var handleLength = this._getHandleLength();\n
        switch (this.layoutDirection) {\n
        case LAYOUT_VERTICAL:\n
            return {\n
                x:      gutterFrame.x,\n
                y:      gutterFrame.y + handleOffset,\n
                width:  gutterFrame.width,\n
                height: handleLength\n
            };\n
        case LAYOUT_HORIZONTAL:\n
            return {\n
                x:      gutterFrame.x + handleOffset,\n
                y:      gutterFrame.y,\n
                width:  handleLength,\n
                height: gutterFrame.height\n
            };\n
        }\n
    },\n
\n
    // Returns the length of the handle or knob.\n
    _getHandleLength: function() {\n
        var gutterLength = this._getGutterLength();\n
        return Math.max(gutterLength * this.proportion, MINIMUM_HANDLE_SIZE);\n
    },\n
\n
    // Returns the starting offset of the handle or knob.\n
    _getHandleOffset: function() {\n
        var maximum = this._maximum;\n
        if (maximum === 0) {\n
            return 0;\n
        }\n
\n
        var gutterLength = this._getGutterLength();\n
        var handleLength = this._getHandleLength();\n
        var emptyGutterLength = gutterLength - handleLength;\n
\n
        return emptyGutterLength * this._value / maximum;\n
    },\n
\n
    // Determines whether the scroll bar is highlighted.\n
    _isHighlighted: function() {\n
        return this._isMouseOver === true ||\n
            this._mouseDownScreenPoint !== null;\n
    },\n
\n
    _segmentForMouseEvent: function(evt) {\n
        var point = { x: evt.layerX, y: evt.layerY };\n
        var clientFrame = this._getClientFrame();\n
        var padding = this.padding;\n
\n
        if (!Rect.pointInRect(point, clientFrame)) {\n
            return null;\n
        }\n
\n
        var layoutDirection = this.layoutDirection;\n
        switch (layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            if ((point.x - padding.left) < NIB_LENGTH) {\n
                return \'nib-start\';\n
            } else if (point.x >= clientFrame.width - NIB_LENGTH) {\n
                return \'nib-end\';\n
            }\n
            break;\n
        case LAYOUT_VERTICAL:\n
            if ((point.y - padding.top) < NIB_LENGTH) {\n
                return \'nib-start\';\n
            } else if (point.y >= clientFrame.height - NIB_LENGTH) {\n
                return \'nib-end\';\n
            }\n
            break;\n
        default:\n
            console.error("unknown layout direction");\n
            break;\n
        }\n
\n
        var handleFrame = this._getHandleFrame();\n
        if (Rect.pointInRect(point, handleFrame)) {\n
            return \'handle\';\n
        }\n
\n
        switch (layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            if (point.x < handleFrame.x) {\n
                return \'gutter-before\';\n
            } else if (point.x >= handleFrame.x + handleFrame.width) {\n
                return \'gutter-after\';\n
            }\n
            break;\n
        case LAYOUT_VERTICAL:\n
            if (point.y < handleFrame.y) {\n
                return \'gutter-before\';\n
            } else if (point.y >= handleFrame.y + handleFrame.height) {\n
                return \'gutter-after\';\n
            }\n
            break;\n
        default:\n
            console.error("unknown layout direction");\n
            break;\n
        }\n
\n
        console.error("_segmentForMouseEvent: point ", point,\n
            " outside view with handle frame ", handleFrame,\n
            " and client frame ", clientFrame);\n
        return null;\n
    },\n
\n
    /**\n
     * Adjusts the canvas view\'s frame to match the parent container\'s frame.\n
     */\n
    adjustFrame: function() {\n
        var parentFrame = this.frame;\n
        this.set(\'layout\', {\n
            left:   0,\n
            top:    0,\n
            width:  parentFrame.width,\n
            height: parentFrame.height\n
        });\n
    },\n
\n
    drawRect: function(rect, ctx) {\n
        // Only draw when visible.\n
        if (!this._isVisible) {\n
            return;\n
        }\n
\n
        var highlighted = this._isHighlighted();\n
        var theme = this.editor.themeData.scroller;\n
        var alpha = (highlighted) ? theme.fullAlpha : theme.particalAlpha;\n
\n
        var frame = this.frame;\n
        ctx.clearRect(0, 0, frame.width, frame.height);\n
\n
        // Begin master drawing context\n
        ctx.save();\n
\n
        // Translate so that we\'re only drawing in the padding.\n
        var padding = this.padding;\n
        ctx.translate(padding.left, padding.top);\n
\n
        var handleFrame = this._getHandleFrame();\n
        var gutterLength = this._getGutterLength();\n
        var thickness = this._getClientThickness();\n
        var halfThickness = thickness / 2;\n
\n
        var layoutDirection = this.layoutDirection;\n
        var handleOffset = this._getHandleOffset() + NIB_LENGTH;\n
        var handleLength = this._getHandleLength();\n
\n
        if (layoutDirection === LAYOUT_VERTICAL) {\n
            // The rest of the drawing code assumes the scroll bar is\n
            // horizontal. Create that fiction by installing a 90 degree\n
            // rotation.\n
            ctx.translate(thickness + 1, 0);\n
            ctx.rotate(Math.PI * 0.5);\n
        }\n
\n
        if (gutterLength <= handleLength) {\n
            return; // Don\'t display the scroll bar.\n
        }\n
\n
        ctx.globalAlpha = alpha;\n
\n
        if (highlighted) {\n
            // Draw the scroll track rectangle.\n
            var clientLength = this._getClientLength();\n
            ctx.fillStyle = theme.trackFillStyle;\n
            ctx.fillRect(NIB_PADDING + 0.5, 0.5,\n
                clientLength - 2*NIB_PADDING, thickness - 1);\n
            ctx.strokeStyle = theme.trackStrokeStyle;\n
            ctx.strokeRect(NIB_PADDING + 0.5, 0.5,\n
                clientLength - 2*NIB_PADDING, thickness - 1);\n
        }\n
\n
        var buildHandlePath = function() {\n
            ctx.beginPath();\n
            ctx.arc(handleOffset + halfThickness + 0.5,                 // x\n
                halfThickness,                                          // y\n
                halfThickness - 0.5, Math.PI / 2, 3 * Math.PI / 2, false);\n
            ctx.arc(handleOffset + handleLength - halfThickness - 0.5,  // x\n
                halfThickness,                                          // y\n
                halfThickness - 0.5, 3 * Math.PI / 2, Math.PI / 2, false);\n
            ctx.lineTo(handleOffset + halfThickness + 0.5, thickness - 0.5);\n
            ctx.closePath();\n
        };\n
        buildHandlePath();\n
\n
        // Paint the interior of the handle path.\n
        var gradient = ctx.createLinearGradient(handleOffset, 0, handleOffset,\n
            thickness);\n
        gradient.addColorStop(0, theme.barFillGradientTopStart);\n
        gradient.addColorStop(0.4, theme.barFillGradientTopStop);\n
        gradient.addColorStop(0.41, theme.barFillStyle);\n
        gradient.addColorStop(0.8, theme.barFillGradientBottomStart);\n
        gradient.addColorStop(1, theme.barFillGradientBottomStop);\n
        ctx.fillStyle = gradient;\n
        ctx.fill();\n
\n
        // Begin handle shine edge context\n
        ctx.save();\n
        ctx.clip();\n
\n
        // Draw the little shines in the handle.\n
        ctx.fillStyle = theme.barFillStyle;\n
        ctx.beginPath();\n
        ctx.moveTo(handleOffset + halfThickness * 0.4, halfThickness * 0.6);\n
        ctx.lineTo(handleOffset + halfThickness * 0.9, thickness * 0.4);\n
        ctx.lineTo(handleOffset, thickness * 0.4);\n
        ctx.closePath();\n
        ctx.fill();\n
        ctx.beginPath();\n
        ctx.moveTo(handleOffset + handleLength - (halfThickness * 0.4),\n
            0 + (halfThickness * 0.6));\n
        ctx.lineTo(handleOffset + handleLength - (halfThickness * 0.9),\n
            0 + (thickness * 0.4));\n
        ctx.lineTo(handleOffset + handleLength, 0 + (thickness * 0.4));\n
        ctx.closePath();\n
        ctx.fill();\n
\n
        ctx.restore();\n
        // End handle border context\n
\n
        // Begin handle outline context\n
        ctx.save();\n
        buildHandlePath();\n
        ctx.strokeStyle = theme.trackStrokeStyle;\n
        ctx.stroke();\n
        ctx.restore();\n
        // End handle outline context\n
\n
        this._drawNibs(ctx, alpha);\n
\n
        ctx.restore();\n
        // End master drawing context\n
    },\n
\n
    _repeatAction: function(method, interval) {\n
        var repeat = method();\n
        if (repeat !== false) {\n
            var func = function() {\n
                this._repeatAction(method, 100);\n
            }.bind(this);\n
            this._scrollTimer = setTimeout(func, interval);\n
        }\n
    },\n
\n
    _scrollByDelta: function(delta) {\n
        this.value = this._value + delta;\n
    },\n
\n
    _scrollUpOneLine: function() {\n
        this._scrollByDelta(-this.lineHeight);\n
        return true;\n
    },\n
\n
    _scrollDownOneLine: function() {\n
        this._scrollByDelta(this.lineHeight);\n
        return true;\n
    },\n
\n
    /**\n
     * Scrolls the page depending on the last mouse position. Scrolling is only\n
     * performed if the mouse is on the segment gutter-before or -after.\n
     */\n
    _scrollPage: function() {\n
        switch (this._segmentForMouseEvent(this._mouseEventPosition)) {\n
            case \'gutter-before\':\n
                this._scrollByDelta(this._getGutterLength() * -1);\n
            break;\n
            case \'gutter-after\':\n
                this._scrollByDelta(this._getGutterLength());\n
            break;\n
            case null:\n
                // The mouse is outside of the scroller. Just wait, until it\n
                // comes back in.\n
            break;\n
            default:\n
                // Do not continue repeating this function.\n
                return false;\n
            break;\n
        }\n
\n
        return true;\n
    },\n
\n
    mouseDown: function(evt) {\n
        this._mouseEventPosition = evt;\n
        this._mouseOverHandle = false;\n
\n
        var parentView = this.parentView;\n
        var value = this._value;\n
        var gutterLength = this._getGutterLength();\n
\n
        switch (this._segmentForMouseEvent(evt)) {\n
        case \'nib-start\':\n
            this._repeatAction(this._scrollUpOneLine.bind(this), 500);\n
            break;\n
        case \'nib-end\':\n
            this._repeatAction(this._scrollDownOneLine.bind(this), 500);\n
            break;\n
        case \'gutter-before\':\n
            this._repeatAction(this._scrollPage.bind(this), 500);\n
            break;\n
        case \'gutter-after\':\n
            this._repeatAction(this._scrollPage.bind(this), 500);\n
            break;\n
        case \'handle\':\n
            break;\n
        default:\n
            console.error("_segmentForMouseEvent returned an unknown value");\n
            break;\n
        }\n
\n
        // The _mouseDownScreenPoint value might be needed although the segment\n
        // was not the handle at the moment.\n
        switch (this.layoutDirection) {\n
        case LAYOUT_HORIZONTAL:\n
            this._mouseDownScreenPoint = evt.pageX;\n
            break;\n
        case LAYOUT_VERTICAL:\n
            this._mouseDownScreenPoint = evt.pageY;\n
            break;\n
        default:\n
            console.error("unknown layout direction");\n
            break;\n
        }\n
    },\n
\n
    mouseMove: function(evt) {\n
        if (this._mouseDownScreenPoint === null) {\n
            return;\n
        }\n
\n
        // Handle the segments. If the current segment is the handle or\n
        // nothing, then drag the handle around (as null = mouse outside of\n
        // scrollbar)\n
        var segment = this._segmentForMouseEvent(evt);\n
        if (segment == \'handle\' || this._mouseOverHandle === true) {\n
            this._mouseOverHandle = true;\n
            if (this._scrollTimer !== null) {\n
                clearTimeout(this._scrollTimer);\n
                this._scrollTimer = null;\n
            }\n
\n
            var eventDistance;\n
            switch (this.layoutDirection) {\n
                case LAYOUT_HORIZONTAL:\n
                    eventDistance = evt.pageX;\n
                    break;\n
                case LAYOUT_VERTICAL:\n
                    eventDistance = evt.pageY;\n
                    break;\n
                default:\n
                    console.error("unknown layout direction");\n
                    break;\n
            }\n
\n
            var eventDelta = eventDistance - this._mouseDownScreenPoint;\n
\n
            var maximum = this._maximum;\n
            var oldValue = this._value;\n
            var gutterLength = this._getGutterLength();\n
            var handleLength = this._getHandleLength();\n
            var emptyGutterLength = gutterLength - handleLength;\n
            var valueDelta = maximum * eventDelta / emptyGutterLength;\n
            this.value = oldValue + valueDelta;\n
\n
            this._mouseDownScreenPoint = eventDistance;\n
        }\n
\n
        this._mouseEventPosition = evt;\n
    },\n
\n
    mouseEntered: function(evt) {\n
        this._isMouseOver = true;\n
        this.invalidate();\n
    },\n
\n
    mouseExited: function(evt) {\n
        this._isMouseOver = false;\n
        this.invalidate();\n
    },\n
\n
    mouseUp: function(evt) {\n
        this._mouseDownScreenPoint = null;\n
        this._mouseDownValue = null;\n
        if (this._scrollTimer) {\n
            clearTimeout(this._scrollTimer);\n
            this._scrollTimer = null;\n
        }\n
        this.invalidate();\n
    }\n
\n
    // mouseWheel: function(evt) {\n
    //     var parentView = this.get(\'parentView\');\n
    //\n
    //     var delta;\n
    //     switch (parentView.get(\'layoutDirection\')) {\n
    //     case LAYOUT_HORIZONTAL:\n
    //         delta = evt.wheelDeltaX;\n
    //         break;\n
    //     case LAYOUT_VERTICAL:\n
    //         delta = evt.wheelDeltaY;\n
    //         break;\n
    //     default:\n
    //         console.error("unknown layout direction");\n
    //         return;\n
    //     }\n
    //\n
    //     parentView.set(\'value\', parentView.get(\'value\') + 2*delta);\n
    // }\n
});\n
\n
Object.defineProperties(exports.ScrollerCanvasView.prototype, {\n
    isVisible: {\n
        set: function(isVisible) {\n
            if (this._isVisible === isVisible) {\n
                return;\n
            }\n
\n
            this._isVisible = isVisible;\n
            this.domNode.style.display = isVisible ? \'block\' : \'none\';\n
            if (isVisible) {\n
                this.invalidate();\n
            }\n
        }\n
    },\n
\n
    maximum: {\n
        set: function(maximum) {\n
            if (this._value > this._maximum) {\n
                this._value = this._maximum;\n
            }\n
\n
            if (maximum === this._maximum) {\n
                return;\n
            }\n
\n
            this._maximum = maximum;\n
            this.invalidate();\n
        }\n
    },\n
\n
    value: {\n
        set: function(value) {\n
            if (value < 0) {\n
                value = 0;\n
            } else if (value > this._maximum) {\n
                value = this._maximum;\n
            }\n
\n
            if (value === this._value) {\n
                return;\n
            }\n
\n
            this._value = value;\n
            this.valueChanged(value);\n
            this.invalidate();\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:views/editor",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var rangeutils = require(\'rangeutils:utils/range\');\n
var scroller = require(\'views/scroller\');\n
var util = require(\'bespin:util/util\');\n
\n
var Buffer = require(\'models/buffer\').Buffer;\n
var CompletionController = require(\'completion:controller\').\n
    CompletionController;\n
var EditorSearchController = require(\'controllers/search\').\n
    EditorSearchController;\n
var EditorUndoController = require(\'controllers/undo\').EditorUndoController;\n
var Event = require(\'events\').Event;\n
var GutterView = require(\'views/gutter\').GutterView;\n
var LayoutManager = require(\'controllers/layoutmanager\').LayoutManager;\n
var ScrollerView = scroller.ScrollerCanvasView;\n
var TextView = require(\'views/text\').TextView;\n
\n
var _ = require(\'underscore\')._;\n
var catalog = require(\'bespin:plugins\').catalog;\n
var keyboardManager = require(\'keyboard:keyboard\').keyboardManager;\n
var settings = require(\'settings\').settings;\n
\n
// Caches the theme data for the entire editor (editor, highlighter, and\n
// gutter).\n
var editorThemeData = {};\n
\n
function computeThemeData(themeManager) {\n
    var plugin = catalog.plugins[\'text_editor\'];\n
    var provides = plugin.provides;\n
    var i = provides.length;\n
    var themeData = {};\n
\n
    // If a themeManager was passed, try to access the themeData for the\n
    // `text_editor` plugin.\n
    if (themeManager) {\n
        var themestyles = themeManager.themestyles;\n
\n
        if (themestyles.currentThemeVariables &&\n
                themestyles.currentThemeVariables[\'text_editor\']) {\n
            themeData = themestyles.currentThemeVariables[\'text_editor\'];\n
        }\n
    }\n
\n
    while (i--) {\n
        if (provides[i].ep === \'themevariable\') {\n
            var value = util.mixin(util.clone(provides[i].defaultValue),\n
                                        themeData[provides[i].name]);\n
\n
            switch (provides[i].name) {\n
                case \'gutter\':\n
                case \'editor\':\n
                case \'scroller\':\n
                case \'highlighter\':\n
                    editorThemeData[provides[i].name] = value;\n
            }\n
        }\n
    }\n
}\n
\n
// Compute the themeData to make sure there is one when the editor comes up.\n
computeThemeData();\n
\n
catalog.registerExtension(\'themeChange\', {\n
    pointer: computeThemeData\n
});\n
\n
/**\n
 * @class\n
 *\n
 * A view responsible for laying out a scrollable text view and its associated\n
 * gutter view, as well as maintaining a layout manager.\n
 */\n
exports.EditorView = function(initialContent) {\n
    this.elementAppended = new Event();\n
\n
    this.element = this.container = document.createElement("div");\n
\n
    var container = this.container;\n
    container.style.overflow = \'visible\';\n
    container.style.position = \'relative\';\n
\n
    this.scrollOffsetChanged = new Event();\n
    this.willChangeBuffer = new Event();\n
\n
    this.selectionChanged = new Event();\n
    this.textChanged = new Event();\n
\n
    var gutterView = this.gutterView = new GutterView(container, this);\n
    var textView = this.textView = new TextView(container, this);\n
    var verticalScroller = new ScrollerView(this, scroller.LAYOUT_VERTICAL);\n
    var horizontalScroller = new ScrollerView(this,\n
        scroller.LAYOUT_HORIZONTAL);\n
    this.verticalScroller = verticalScroller;\n
    this.horizontalScroller = horizontalScroller;\n
\n
    this.completionController = new CompletionController(this);\n
    this.editorUndoController = new EditorUndoController(this);\n
    this.searchController = new EditorSearchController(this);\n
\n
    this._textViewSize = this._oldSize = { width: 0, height: 0 };\n
\n
    this._themeData = editorThemeData;\n
\n
    // Create a buffer for the editor and use initialContent as the initial\n
    // content for the textStorage object.\n
    this.buffer = new Buffer(null, initialContent);\n
\n
    // Create all the necessary stuff once the container has been added.\n
    this.elementAppended.add(function() {\n
        // Set the font property.\n
        var fontSize = settings.get(\'fontsize\');\n
        var fontFace = settings.get(\'fontface\');\n
        this._font = fontSize + \'px \' + fontFace;\n
\n
        // Repaint when the theme changes.\n
        catalog.registerExtension(\'themeChange\', {\n
            pointer: this._themeVariableChange.bind(this)\n
        });\n
\n
        // When the font changes, set our local font property, and repaint.\n
        catalog.registerExtension(\'settingChange\', {\n
            match: "font[size|face]",\n
            pointer: this._fontSettingChanged.bind(this)\n
        });\n
\n
        // Likewise when the dimensions change.\n
        catalog.registerExtension(\'dimensionsChanged\', {\n
            pointer: this.dimensionsChanged.bind(this)\n
        });\n
\n
        // Allow the layout to be recomputed.\n
        this._dontRecomputeLayout = false;\n
        this._recomputeLayout();\n
\n
        var wheelEvent = util.isMozilla ? \'DOMMouseScroll\' : \'mousewheel\';\n
        container.addEventListener(wheelEvent, this._onMouseWheel.bind(this),\n
            false);\n
\n
        verticalScroller.valueChanged.add(function(value) {\n
            this.scrollOffset = { y: value };\n
        }.bind(this));\n
\n
        horizontalScroller.valueChanged.add(function(value) {\n
            this.scrollOffset = { x: value };\n
        }.bind(this));\n
\n
        this.scrollOffsetChanged.add(function(offset) {\n
            this._updateScrollOffsetChanged(offset);\n
        }.bind(this));\n
    }.bind(this));\n
};\n
\n
\n
exports.EditorView.prototype = {\n
    elementAppended: null,\n
\n
    textChanged: null,\n
    selectionChanged: null,\n
\n
    scrollOffsetChanged: null,\n
    willChangeBuffer: null,\n
\n
    _textViewSize: null,\n
\n
    _textLinesCount: 0,\n
    _gutterViewWidth: 0,\n
    _oldSize: null,\n
\n
    _buffer: null,\n
\n
    _dontRecomputeLayout: true,\n
\n
    _themeData: null,\n
\n
    _layoutManagerSizeChanged: function(size) {\n
        var fontDimension = this.layoutManager.fontDimension;\n
        this._textViewSize = {\n
            width: size.width * fontDimension.characterWidth,\n
            height: size.height * fontDimension.lineHeight\n
        };\n
\n
        if (this._textLinesCount !== size.height) {\n
            var gutterWidth = this.gutterView.computeWidth();\n
            if (gutterWidth !== this._gutterViewWidth) {\n
                this._recomputeLayout(true /* force layout update */);\n
            } else {\n
                this.gutterView.invalidate();\n
            }\n
            this._textLinesLength = size.height;\n
        }\n
\n
        // Clamp the current scrollOffset position.\n
        this._updateScrollers();\n
        this.scrollOffset = {};\n
    },\n
\n
    _updateScrollers: function() {\n
        // Don\'t change anything on the scrollers until the layout is setup.\n
        if (this._dontRecomputeLayout) {\n
            return;\n
        }\n
\n
        var frame = this.textViewPaddingFrame;\n
        var width = this._textViewSize.width;\n
        var height = this._textViewSize.height;\n
        var scrollOffset = this.scrollOffset;\n
        var verticalScroller = this.verticalScroller;\n
        var horizontalScroller = this.horizontalScroller;\n
\n
        if (height < frame.height) {\n
            verticalScroller.isVisible = false;\n
        } else {\n
            verticalScroller.isVisible = true;\n
            verticalScroller.proportion = frame.height / height;\n
            verticalScroller.maximum = height - frame.height;\n
            verticalScroller.value = scrollOffset.y;\n
        }\n
\n
        if (width < frame.width) {\n
            horizontalScroller.isVisible = false;\n
        } else {\n
            horizontalScroller.isVisible = true;\n
            horizontalScroller.proportion = frame.width / width;\n
            horizontalScroller.maximum = width - frame.width;\n
            horizontalScroller.value = scrollOffset.x;\n
        }\n
    },\n
\n
    _onMouseWheel: function(evt) {\n
        var delta = 0;\n
        if (evt.wheelDelta) {\n
            delta = -evt.wheelDelta;\n
        } else if (evt.detail) {\n
            delta = evt.detail * 40;\n
        }\n
\n
        var isVertical = true;\n
        if (evt.axis) { // Firefox 3.1 world\n
            if (evt.axis == evt.HORIZONTAL_AXIS) isVertical = false;\n
        } else if (evt.wheelDeltaY || evt.wheelDeltaX) {\n
            if (evt.wheelDeltaX == evt.wheelDelta) isVertical = false;\n
        } else if (evt.shiftKey) isVertical = false;\n
\n
        if (isVertical) {\n
            this.scrollBy(0, delta);\n
        } else {\n
            this.scrollBy(delta * 5, 0);\n
        }\n
\n
        util.stopEvent(evt);\n
    },\n
\n
    scrollTo: function(pos) {\n
        this.scrollOffset = pos;\n
    },\n
\n
    scrollBy: function(deltaX, deltaY) {\n
        this.scrollOffset = {\n
            x: this.scrollOffset.x + deltaX,\n
            y: this.scrollOffset.y + deltaY\n
        };\n
    },\n
\n
    _recomputeLayout: function(forceLayout) {\n
        // This is necessary as _recomputeLayout is called sometimes when the\n
        // size of the container is not yet ready (because of FlexBox).\n
        if (this._dontRecomputeLayout) {\n
            return;\n
        }\n
\n
        var width = this.container.offsetWidth;\n
        var height = this.container.offsetHeight;\n
\n
        // Don\'t recompute unless the size actually changed.\n
        if (!forceLayout && width == this._oldSize.width\n
                                    && height == this._oldSize.height) {\n
            return;\n
        }\n
\n
        this._oldSize = {\n
            width: width,\n
            height: height\n
        };\n
\n
        var gutterWidth = this.gutterView.computeWidth();\n
        this._gutterViewWidth = gutterWidth;\n
\n
        this.gutterView.frame = {\n
            x: 0,\n
            y: 0,\n
            width: gutterWidth,\n
            height: height\n
        };\n
\n
        this.textView.frame = {\n
            x: gutterWidth,\n
            y: 0,\n
            width: width - gutterWidth,\n
            height: height\n
        };\n
\n
        // TODO: Get these values from the scroller theme.\n
        var scrollerPadding = this._themeData.scroller.padding;\n
        var scrollerSize = this._themeData.scroller.thickness;\n
\n
        this.horizontalScroller.frame = {\n
            x: gutterWidth + scrollerPadding,\n
            y: height - (scrollerSize + scrollerPadding),\n
            width: width - (gutterWidth + 2 * scrollerPadding + scrollerSize),\n
            height: scrollerSize\n
        };\n
\n
        this.verticalScroller.frame = {\n
            x: width - (scrollerPadding + scrollerSize),\n
            y: scrollerPadding,\n
            width: scrollerSize,\n
            height: height - (2 * scrollerPadding + scrollerSize)\n
        };\n
\n
        // Calls the setter scrollOffset which then clamps the current\n
        // scrollOffset as needed.\n
        this.scrollOffset = {};\n
\n
        this._updateScrollers();\n
        this.gutterView.invalidate();\n
        this.textView.invalidate();\n
        this.verticalScroller.invalidate();\n
        this.horizontalScroller.invalidate();\n
    },\n
\n
    dimensionsChanged: function() {\n
        this._recomputeLayout();\n
    },\n
\n
    /**\n
     * @property{string}\n
     *\n
     * The font to use for the text view and the gutter view. Typically, this\n
     * value is set via the font settings.\n
     */\n
    _font: null,\n
\n
    _fontSettingChanged: function() {\n
        var fontSize = settings.get(\'fontsize\');\n
        var fontFace = settings.get(\'fontface\');\n
        this._font = fontSize + \'px \' + fontFace;\n
\n
        // Recompute the layouts.\n
        this.layoutManager._recalculateMaximumWidth();\n
        this._layoutManagerSizeChanged(this.layoutManager.size);\n
        this.textView.invalidate();\n
    },\n
\n
    _themeVariableChange: function() {\n
        // Recompute the entire layout as the gutter might now have a different\n
        // size. Just calling invalidate() on the gutter wouldn\'t be enough.\n
        this._recomputeLayout(true);\n
    },\n
\n
    _updateScrollOffsetChanged: function(offset) {\n
        this.verticalScroller.value = offset.y;\n
        this.horizontalScroller.value = offset.x;\n
\n
        this.textView.clippingFrame = { x: offset.x, y: offset.y };\n
\n
        this.gutterView.clippingFrame = { y: offset.y };\n
\n
        this._updateScrollers();\n
        this.gutterView.invalidate();\n
        this.textView.invalidate();\n
    },\n
\n
    /**\n
     * The text view uses this function to forward key events to the keyboard\n
     * manager. The editor view is used as a middleman so that it can append\n
     * predicates as necessary.\n
     */\n
    processKeyEvent: function(evt, sender, preds) {\n
        preds = _(preds).clone();\n
        preds.completing = this.completionController.isCompleting();\n
        return keyboardManager.processKeyEvent(evt, sender, preds);\n
    },\n
\n
    /**\n
     * Converts a point in the coordinate system of the document being edited\n
     * (i.e. of the text view) to the coordinate system of the editor (i.e. of\n
     * the DOM component containing Bespin).\n
     */\n
    convertTextViewPoint: function(pt) {\n
        var scrollOffset = this.scrollOffset;\n
        return {\n
            x: pt.x - scrollOffset.x + this._gutterViewWidth,\n
            y: pt.y - scrollOffset.y\n
        };\n
    },\n
\n
    // ------------------------------------------------------------------------\n
    // Helper API:\n
\n
    /**\n
     * Replaces the text within a range, as an undoable action.\n
     *\n
     * @param {Range} range The range to replace.\n
     * @param {string} newText The text to insert.\n
     * @param {boolean} keepSelection True if the selection should be\n
     *     be preserved, otherwise the cursor is set after newText.\n
     * @return Returns true if the replacement completed successfully,\n
     *     otherwise returns false.\n
     */\n
    replace: function(range, newText, keepSelection) {\n
        if (!rangeutils.isRange(range)) {\n
            throw new Error(\'replace(): expected range but found "\' + range +\n
                "\'");\n
        }\n
        if (!util.isString(newText)) {\n
            throw new Error(\'replace(): expected text string but found "\' +\n
                text + \'"\');\n
        }\n
\n
        var normalized = rangeutils.normalizeRange(range);\n
\n
        var view = this.textView;\n
        var oldSelection = view.getSelectedRange(false);\n
        return view.groupChanges(function() {\n
            view.replaceCharacters(normalized, newText);\n
            if (keepSelection) {\n
                view.setSelection(oldSelection);\n
            } else {\n
                var lines = newText.split(\'\\n\');\n
\n
                var destPosition;\n
                if (lines.length > 1) {\n
                    destPosition = {\n
                        row: range.start.row + lines.length - 1,\n
                        col: lines[lines.length - 1].length\n
                    };\n
                } else {\n
                    destPosition = rangeutils.addPositions(range.start,\n
                        { row: 0, col: newText.length });\n
                }\n
                view.moveCursorTo(destPosition);\n
            }\n
        });\n
    },\n
\n
    getText: function(range) {\n
        if (!rangeutils.isRange(range)) {\n
            throw new Error(\'getText(): expected range but found "\' + range +\n
                \'"\');\n
        }\n
\n
        var textStorage = this.layoutManager.textStorage;\n
        return textStorage.getCharacters(rangeutils.normalizeRange(range));\n
    },\n
\n
    /** Scrolls and moves the insertion point to the given line number. */\n
    setLineNumber: function(lineNumber) {\n
        if (!util.isNumber(lineNumber)) {\n
            throw new Error(\'setLineNumber(): lineNumber must be a number\');\n
        }\n
\n
        var newPosition = { row: lineNumber - 1, col: 0 };\n
        this.textView.moveCursorTo(newPosition);\n
    },\n
\n
    /** Sets the position of the cursor. */\n
    setCursor: function(newPosition) {\n
        if (!rangeutils.isPosition(newPosition)) {\n
            throw new Error(\'setCursor(): expected position but found "\' +\n
                newPosition + \'"\');\n
        }\n
\n
        this.textView.moveCursorTo(newPosition);\n
    },\n
\n
    /**\n
     * Group changes so that they are only one undo/redo step.\n
     * Returns true if the changes were successful.\n
     */\n
    changeGroup: function(func) {\n
        return this.textView.groupChanges(function() {\n
            func(this);\n
        }.bind(this));\n
    },\n
\n
    /**\n
     * Adds the supplied tags to the completion manager.\n
     */\n
    addTags: function(newTags) {\n
        this.completionController.tags.add(newTags);\n
    }\n
};\n
\n
Object.defineProperties(exports.EditorView.prototype, {\n
    themeData: {\n
        get: function() {\n
            return this._themeData;\n
        },\n
\n
        set: function() {\n
            throw new Error(\'themeData can\\\'t be changed directly.\' +\n
                                \' Use themeManager.\');\n
        }\n
    },\n
\n
    font: {\n
        get: function() {\n
            return this._font;\n
        },\n
\n
        set: function() {\n
            throw new Error(\'font can\\\'t be changed directly.\' +\n
                    \' Use settings fontsize and fontface.\');\n
        }\n
    },\n
\n
    buffer: {\n
        /**\n
         * Sets a new buffer.\n
         * The buffer\'s file has to be loaded when passing to this setter.\n
         */\n
        set: function(newBuffer) {\n
            if (newBuffer === this._buffer) {\n
                return;\n
            }\n
\n
            if (!newBuffer.loadPromise.isResolved()) {\n
                throw new Error(\'buffer.set(): the new buffer must first be \' +\n
                    \'loaded!\');\n
            }\n
\n
            // Was there a former buffer? If yes, then remove some events.\n
            if (this._buffer !== null) {\n
                this.layoutManager.sizeChanged.remove(this);\n
                this.layoutManager.textStorage.changed.remove(this);\n
                this.textView.selectionChanged.remove(this);\n
            }\n
\n
            this.willChangeBuffer(newBuffer);\n
            catalog.publish(this, \'editorChange\', \'buffer\', newBuffer);\n
\n
            this.layoutManager = newBuffer.layoutManager;\n
            this._buffer = newBuffer;\n
\n
            var lm = this.layoutManager;\n
            var tv = this.textView;\n
\n
            // Watch out for changes to the layoutManager\'s internal size.\n
            lm.sizeChanged.add(this,\n
                this._layoutManagerSizeChanged.bind(this));\n
\n
            // Map internal events so that developers can listen much easier.\n
            lm.textStorage.changed.add(this, this.textChanged.bind(this));\n
            tv.selectionChanged.add(this, this.selectionChanged.bind(this));\n
\n
            this.textView.setSelection(newBuffer._selectedRange, false);\n
            this.scrollOffsetChanged(newBuffer._scrollOffset);\n
\n
            // The layoutManager changed and its size as well. Call the\n
            // layoutManager.sizeChanged event manually.\n
            this.layoutManager.sizeChanged(this.layoutManager.size);\n
\n
            this._recomputeLayout();\n
        },\n
\n
        get: function() {\n
            return this._buffer;\n
        }\n
    },\n
\n
    frame: {\n
        get: function() {\n
            return {\n
                width: this.container.offsetWidth,\n
                height: this.container.offsetHeight\n
            };\n
        }\n
    },\n
\n
    textViewPaddingFrame: {\n
        get: function() {\n
            var frame = util.clone(this.textView.frame);\n
            var padding = this.textView.padding;\n
\n
            frame.width -= padding.left + padding.right;\n
            frame.height -= padding.top + padding.bottom;\n
            return frame;\n
        }\n
    },\n
\n
    scrollOffset: {\n
        set: function(pos) {\n
            if (pos.x === undefined) pos.x = this.scrollOffset.x;\n
            if (pos.y === undefined) pos.y = this.scrollOffset.y;\n
\n
            var frame = this.textViewPaddingFrame;\n
\n
            if (pos.y < 0) {\n
                pos.y = 0;\n
            } else if (this._textViewSize.height < frame.height) {\n
                pos.y = 0;\n
            } else if (pos.y + frame.height > this._textViewSize.height) {\n
                pos.y = this._textViewSize.height - frame.height;\n
            }\n
\n
            if (pos.x < 0) {\n
                pos.x = 0;\n
            } else if (this._textViewSize.width < frame.width) {\n
                pos.x = 0;\n
            } else if (pos.x + frame.width > this._textViewSize.width) {\n
                pos.x = this._textViewSize.width - frame.width;\n
            }\n
\n
            if (pos.x === this.scrollOffset.x && pos.y === this.scrollOffset.y) {\n
                return;\n
            }\n
\n
            this.buffer._scrollOffset = pos;\n
\n
            this.scrollOffsetChanged(pos);\n
            catalog.publish(this, \'editorChange\', \'scrollOffset\', pos);\n
        },\n
\n
        get: function() {\n
            return this.buffer._scrollOffset;\n
        }\n
    },\n
\n
    // -------------------------------------------------------------------------\n
    // Helper API:\n
\n
    readOnly: {\n
        get: function() {\n
            return this._buffer.model.readOnly;\n
        },\n
\n
        set: function(newValue) {\n
            this._buffer.model.readOnly = newValue;\n
        }\n
    },\n
\n
    focus: {\n
        get: function() {\n
            return this.textView.hasFocus;\n
        },\n
\n
        set: function(setFocus) {\n
            if (!util.isBoolean(setFocus)) {\n
                throw new Error(\'set focus: expected boolean but found "\' +\n
                                    setFocus + \'"\');\n
            }\n
            this.textView.hasFocus = setFocus;\n
        }\n
    },\n
\n
    selection: {\n
        /** Returns the currently-selected range. */\n
        get: function() {\n
            return util.clone(this.textView.getSelectedRange(false));\n
        },\n
\n
        /** Alters the selection. */\n
        set: function(newSelection) {\n
            if (!rangeutils.isRange(newSelection)) {\n
                throw new Error(\'set selection: position/selection\' +\n
                                    \' must be supplied\');\n
            }\n
\n
            this.textView.setSelection(newSelection);\n
        }\n
    },\n
\n
    selectedText: {\n
        /** Returns the text within the given range. */\n
        get: function() {\n
            return this.getText(this.selection);\n
        },\n
\n
        /** Replaces the current text selection with the given text. */\n
        set: function(newText) {\n
            if (!util.isString(newText)) {\n
                throw new Error(\'set selectedText: expected string but\' +\n
                    \' found "\' + newText + \'"\');\n
            }\n
\n
            return this.replace(this.selection, newText);\n
        }\n
    },\n
\n
    value: {\n
        /** Returns the current text. */\n
        get: function() {\n
            return this.layoutManager.textStorage.value;\n
        },\n
\n
        set: function(newValue) {\n
            if (!util.isString(newValue)) {\n
                throw new Error(\'set value: expected string but found "\' +\n
                                        newValue + \'"\');\n
            }\n
\n
            // Use the replace function and not this.model.value = newValue\n
            // directly as this wouldn\'t create a new undoable action.\n
            return this.replace(this.layoutManager.textStorage.range,\n
                                        newValue, false);\n
        }\n
    },\n
\n
    syntax: {\n
        /**\n
         * Returns the initial syntax highlighting context (i.e. the language).\n
         */\n
        get: function(newSyntax) {\n
            return this.layoutManager.syntaxManager.getSyntax();\n
        },\n
\n
        /**\n
         * Sets the initial syntax highlighting context (i.e. the language).\n
         */\n
        set: function(newSyntax) {\n
            if (!util.isString(newSyntax)) {\n
                throw new Error(\'set syntax: expected string but found "\' +\n
                                        newValue + \'"\');\n
            }\n
\n
            return this.layoutManager.syntaxManager.setSyntax(newSyntax);\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:views/textinput",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var Event = require(\'events\').Event;\n
\n
var KeyUtil = require(\'keyboard:keyutil\');\n
\n
/**\n
 * @namespace\n
 *\n
 * This class provides a hidden text input to provide events similar to those\n
 * defined in the DOM Level 3 specification. It allows views to support\n
 * internationalized text input via non-US keyboards, dead keys, and/or IMEs.\n
 * It also provides support for copy and paste. Currently, an invisible\n
 * textarea is used, but in the future this module should use\n
 * DOM 3 TextInput events directly where available.\n
 *\n
 * To use this class, instantiate it and provide the optional functions\n
 *   - copy: function() { return \'text for clipboard\' }\n
 *   - cut: function() { \'Cut some text\'; return \'text for clipboard\'}\n
 *   - textInserted: function(newInsertedText) { \'handle new inserted text\'; }\n
 * Note: Pasted text is provided through the textInserted(pastedText) function.\n
 *\n
 * You can also provide an DOM node to take focus from by providing the optional\n
 * "takeFocusFrom" parameter.\n
 *\n
 * The DOM node created for text input is in the "domNode" attribute\n
 * and that caller should add the DOM node to the document in the appropriate\n
 * place.\n
 */\n
exports.TextInput = function(container, delegate) {\n
    var domNode = this.domNode = document.createElement(\'textarea\');\n
    domNode.setAttribute(\'style\', \'position: absolute; z-index: -99999; \' +\n
          \'width: 0px; height: 0px; margin: 0px; outline: none; border: 0;\');\n
         // \'z-index: 100; top: 20px; left: 20px; width: 50px; \' +\n
         // \'height: 50px\');\n
\n
    container.appendChild(domNode);\n
\n
    this.delegate = delegate;\n
\n
    this._attachEvents();\n
};\n
\n
exports.TextInput.prototype = {\n
    _composing: false,\n
\n
    domNode: null,\n
\n
    delegate: null,\n
\n
    // This function doesn\'t work on WebKit! The textContent comes out empty...\n
    _textFieldChanged: function() {\n
        if (this._composing || this._ignore) {\n
            return;\n
        }\n
\n
        var textField = this.domNode;\n
        var text = textField.value;\n
        // On FF textFieldChanged is called sometimes although nothing changed.\n
        // -> don\'t call textInserted() in such a case.\n
        if (text == \'\') {\n
            return;\n
        }\n
        textField.value = \'\';\n
\n
        this._textInserted(text);\n
    },\n
\n
    _copy: function() {\n
        var copyData = false;\n
        var delegate = this.delegate;\n
        if (delegate && delegate.copy) {\n
            copyData = delegate.copy();\n
        }\n
        return copyData;\n
    },\n
\n
    _cut: function() {\n
        var cutData = false;\n
        var delegate = this.delegate;\n
        if (delegate && delegate.cut) {\n
            cutData = delegate.cut();\n
        }\n
        return cutData;\n
    },\n
\n
    _textInserted: function(text) {\n
        var delegate = this.delegate;\n
        if (delegate && delegate.textInserted) {\n
            delegate.textInserted(text);\n
        }\n
    },\n
\n
    _setValueAndSelect: function(text) {\n
        var textField = this.domNode;\n
        textField.value = text;\n
        textField.select();\n
    },\n
\n
    /**\n
     * Gives focus to the field editor so that input events will be\n
     * delivered to the view. If you override willBecomeKeyResponderFrom(),\n
     * you should call this function in your implementation.\n
     */\n
    focus: function() {\n
        this.domNode.focus();\n
    },\n
\n
    /**\n
     * Removes focus from the invisible text input so that input events are no\n
     * longer delivered to this view. If you override willLoseKeyResponderTo(),\n
     * you should call this function in your implementation.\n
     */\n
     blur: function() {\n
        this.domNode.blur();\n
    },\n
\n
    /**\n
     * Attaches notification listeners to the text field so that your view will\n
     * be notified of events. If you override this method, you should call\n
     * that function as well.\n
     */\n
    _attachEvents: function() {\n
        var textField = this.domNode, self = this;\n
\n
        // Listen focus/blur event.\n
        textField.addEventListener(\'focus\', function(evt) {\n
            if (self.delegate && self.delegate.didFocus) {\n
                self.delegate.didFocus();\n
            }\n
        }, false);\n
        textField.addEventListener(\'blur\', function(evt) {\n
            if (self.delegate && self.delegate.didBlur) {\n
                self.delegate.didBlur();\n
            }\n
        }, false);\n
\n
        KeyUtil.addKeyDownListener(textField, function(evt) {\n
            if (self.delegate && self.delegate.keyDown) {\n
                return self.delegate.keyDown(evt);\n
            } else {\n
                return false;\n
            }\n
        });\n
\n
        // No way that I can see around this ugly browser sniffing, without\n
        // more complicated hacks. No browsers have a complete enough\n
        // implementation of DOM 3 events at the current time (12/2009). --pcw\n
        if (util.isWebKit) {    // Chrome too\n
            // On Chrome the compositionend event is fired as well as the\n
            // textInput event, but only one of them has to be handled.\n
            if (!util.isChrome) {\n
                textField.addEventListener(\'compositionend\', function(evt) {\n
                    self._textInserted(evt.data);\n
                }, false);\n
            }\n
            textField.addEventListener(\'textInput\', function(evt) {\n
                self._textInserted(evt.data);\n
            }, false);\n
            textField.addEventListener(\'paste\', function(evt) {\n
                self._textInserted(evt.clipboardData.\n
                    getData(\'text/plain\'));\n
                evt.preventDefault();\n
            }, false);\n
        } else {\n
            var textFieldChangedFn = self._textFieldChanged.bind(self);\n
\n
            // Same as above, but executes after all pending events. This\n
            // ensures that content gets added to the text field before the\n
            // value field is read.\n
            var textFieldChangedLater = function() {\n
                window.setTimeout(textFieldChangedFn, 0);\n
            };\n
\n
            textField.addEventListener(\'keydown\', textFieldChangedLater,\n
                false);\n
            textField.addEventListener(\'keypress\', textFieldChangedFn, false);\n
            textField.addEventListener(\'keyup\', textFieldChangedFn, false);\n
\n
            textField.addEventListener(\'compositionstart\', function(evt) {\n
                self._composing = true;\n
            }, false);\n
            textField.addEventListener(\'compositionend\', function(evt) {\n
                self._composing = false;\n
                self._textFieldChanged();\n
            }, false);\n
\n
            textField.addEventListener(\'paste\', function(evt) {\n
                // FIXME: This is ugly and could result in extraneous text\n
                // being included as part of the text if extra DOMNodeInserted\n
                // or DOMCharacterDataModified events happen to be in the queue\n
                // when this function runs. But until Fx supports TextInput\n
                // events, there\'s nothing better we can do.\n
\n
                // Waits till the paste content is pasted to the textarea.\n
                // Sometimes a delay of 0 is too short for Fx. In such a case\n
                // the keyUp events occur a little bit later and the pasted\n
                // content is detected there.\n
                self._setValueAndSelect(\'\');\n
                window.setTimeout(function() {\n
                    self._textFieldChanged();\n
                }, 0);\n
            }, false);\n
        }\n
\n
        // Here comes the code for copy and cut...\n
\n
        // This is the basic copy and cut function. Depending on the\n
        // OS and browser this function needs to be extended.\n
        var copyCutBaseFn = function(evt) {\n
            // Get the data that should be copied/cutted.\n
            var copyCutData = evt.type.indexOf(\'copy\') != -1 ?\n
                            self._copy() :\n
                            self._cut();\n
            // Set the textField\'s value equal to the copyCutData.\n
            // After this function is called, the real copy or cut\n
            // event takes place and the selected text in the\n
            // textField is pushed to the OS\'s clipboard.\n
            self._setValueAndSelect(copyCutData);\n
        };\n
\n
        // For all browsers that are not Safari running on Mac.\n
        if (!(util.isWebKit && !util.isChrome && util.isMac)) {\n
            var copyCutMozillaFn = false;\n
            if (util.isMozilla) {\n
                // If the browser is Mozilla like, the copyCut function has to\n
                // be extended.\n
                copyCutMozillaFn = function(evt) {\n
                    // Call the basic copyCut function.\n
                    copyCutBaseFn(evt);\n
\n
                    self._ignore = true;\n
                    window.setTimeout(function() {\n
                        self._setValueAndSelect(\'\');\n
                        self._ignore = false;\n
                    }, 0);\n
                };\n
            }\n
            textField.addEventListener(\'copy\', copyCutMozillaFn ||\n
                copyCutBaseFn, false);\n
            textField.addEventListener(\'cut\',  copyCutMozillaFn ||\n
                copyCutBaseFn, false);\n
         } else {\n
            // For Safari on Mac (only!) the copy and cut event only occurs if\n
            // you have some text selected. Fortunately, the beforecopy and\n
            // beforecut event occurs before the copy or cut event does so we\n
            // can put the to be copied or cutted text in the textarea.\n
\n
            // Also, the cut event is fired twice. If it\'s fired twice within a\n
            // certain time period, the second call will be skipped.\n
            var lastCutCall = new Date().getTime();\n
            var copyCutSafariMacFn = function(evt) {\n
                var doCut = evt.type.indexOf(\'cut\') != -1;\n
                if (doCut && new Date().getTime() - lastCutCall < 10) {\n
                    return;\n
                }\n
\n
                // Call the basic copyCut function.\n
                copyCutBaseFn(evt);\n
\n
                if (doCut) {\n
                    lastCutCall = new Date().getTime();\n
                }\n
            };\n
\n
            textField.addEventListener(\'beforecopy\', copyCutSafariMacFn,\n
                false);\n
            textField.addEventListener(\'beforecut\',  copyCutSafariMacFn,\n
                false);\n
        }\n
    }\n
};\n
\n
\n
});\n
\n
bespin.tiki.module("text_editor:views/canvas",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var Rect = require(\'utils/rect\');\n
var Event = require(\'events\').Event;\n
\n
/**\n
 * @class\n
 *\n
 * This class provides support for manual scrolling and positioning for canvas-\n
 * based elements. Getting these elements to play nicely with SproutCore is\n
 * tricky and error-prone, so all canvas-based views should consider deriving\n
 * from this class. Derived views should implement drawRect() in order to\n
 * perform the appropriate canvas drawing logic.\n
 *\n
 * The actual size of the canvas is always the size of the container the canvas\n
 * view is placed in.\n
 *\n
 * The canvas that is created is available in the domNode attribute and should\n
 * be added to the document by the caller.\n
 */\n
exports.CanvasView = function(container, preventDownsize, clearOnFullInvalid) {\n
    if (!container) {\n
        return;\n
    }\n
\n
    this._preventDownsize = preventDownsize || false;\n
    this._clearOnFullInvalid = clearOnFullInvalid || false;\n
    this._clippingFrame = this._frame = {\n
        x: 0,\n
        y: 0,\n
        width: 0,\n
        height: 0\n
    };\n
    this._invalidRects = [];\n
\n
    var canvas = document.createElement(\'canvas\');\n
    canvas.setAttribute(\'style\', \'position: absolute\');\n
    canvas.innerHTML = \'canvas tag not supported by your browser\';\n
    container.appendChild(canvas);\n
    this.domNode = canvas;\n
\n
    this.clippingChanged = new Event();\n
    this.clippingChanged.add(this.clippingFrameChanged.bind(this));\n
};\n
\n
exports.CanvasView.prototype = {\n
    domNode: null,\n
\n
    clippingChanged: null,\n
\n
    _canvasContext: null,\n
    _canvasId: null,\n
    _invalidRects: null,\n
    _lastRedrawTime: null,\n
    _redrawTimer: null,\n
    _clippingFrame: null,\n
    _preventDownsize: false,\n
    _clearOnFullInvalid: false,\n
\n
    _frame: null,\n
\n
    _getContext: function() {\n
        if (this._canvasContext === null) {\n
            this._canvasContext = this.domNode.getContext(\'2d\');\n
        }\n
        return this._canvasContext;\n
    },\n
\n
    computeWithClippingFrame: function(x, y) {\n
        var clippingFrame = this.clippingFrame;\n
        return {\n
            x: x + clippingFrame.x,\n
            y: y + clippingFrame.y\n
        };\n
    },\n
\n
    /**\n
     * @property{Number}\n
     *\n
     * The minimum delay between canvas redraws in milliseconds, equal to 1000\n
     * divided by the desired number of frames per second.\n
     */\n
    minimumRedrawDelay: 1000.0 / 30.0,\n
\n
    /**\n
     * Subclasses can override this method to provide custom behavior whenever\n
     * the clipping frame changes. The default implementation simply\n
     * invalidates the entire visible area.\n
     */\n
    clippingFrameChanged: function() {\n
        this.invalidate();\n
    },\n
\n
    drawRect: function(rect, context) { },\n
\n
    /**\n
     * Render the canvas. Rendering is delayed by a few ms to empty the call\n
     * stack first before rendering. If the canvas was rendered in less then\n
     * this.minimumRedrawDelay ms, then the next rendering will take in\n
     * this.minimumRedrawDelay - now + lastRendering ms.\n
     */\n
    render: function() {\n
         // Don\'t continue if there is a rendering or redraw timer already.\n
        if (this._renderTimer || this._redrawTimer) {\n
            return;\n
        }\n
\n
        // Queue the redraw at the end of the current event queue to make sure\n
        // everyting is done when redrawing.\n
        this._renderTimer = setTimeout(this._tryRedraw.bind(this), 0);\n
    },\n
\n
    /**\n
     * Invalidates the entire visible region of the canvas.\n
     */\n
    invalidate: function(rect) {\n
        this._invalidRects = \'all\';\n
        this.render();\n
    },\n
\n
    /**\n
     * Invalidates the given rect of the canvas, and schedules that portion of\n
     * the canvas to be redrawn at the end of the run loop.\n
     */\n
    invalidateRect: function(rect) {\n
        var invalidRects = this._invalidRects;\n
        if (invalidRects !== \'all\') {\n
            invalidRects.push(rect);\n
            this.render();\n
        }\n
    },\n
\n
    _tryRedraw: function(context) {\n
        this._renderTimer = null;\n
\n
        var now = new Date().getTime();\n
        var lastRedrawTime = this._lastRedrawTime;\n
        var minimumRedrawDelay = this.minimumRedrawDelay;\n
\n
        if (lastRedrawTime === null ||\n
                now - lastRedrawTime >= minimumRedrawDelay) {\n
            this._redraw();\n
            return;\n
        }\n
\n
        var redrawTimer = this._redrawTimer;\n
        if (redrawTimer !== null) {\n
            return; // already scheduled\n
        }\n
\n
        // TODO This is not as good as SC.Timer... Will it work?\n
        this._redrawTimer = window.setTimeout(this._redraw.bind(this),\n
            minimumRedrawDelay);\n
    },\n
\n
     /**\n
     * Calls drawRect() on all the invalid rects to redraw the canvas contents.\n
     * Generally, you should not need to call this function unless you override\n
     * the default implementations of didCreateLayer() or render().\n
     */\n
    _redraw: function() {\n
        var clippingFrame = this.clippingFrame;\n
        clippingFrame = {\n
            x:      Math.round(clippingFrame.x),\n
            y:      Math.round(clippingFrame.y),\n
            width:  clippingFrame.width,\n
            height: clippingFrame.height\n
        };\n
\n
        var context = this._getContext();\n
        context.save();\n
        context.translate(-clippingFrame.x, -clippingFrame.y);\n
\n
        var invalidRects = this._invalidRects;\n
        if (invalidRects === \'all\') {\n
            if (this._clearOnFullInvalid) {\n
                context.clearRect(0, 0, this.domNode.width, this.domNode.height);\n
            }\n
            this.drawRect(clippingFrame, context);\n
        } else {\n
            Rect.merge(invalidRects).forEach(function(rect) {\n
                rect = Rect.intersectRects(rect, clippingFrame);\n
                if (rect.width !== 0 && rect.height !== 0) {\n
                    context.save();\n
\n
                    var x = rect.x, y = rect.y;\n
                    var width = rect.width, height = rect.height;\n
                    context.beginPath();\n
                    context.moveTo(x, y);\n
                    context.lineTo(x + width, y);\n
                    context.lineTo(x + width, y + height);\n
                    context.lineTo(x, y + height);\n
                    context.closePath();\n
                    context.clip();\n
\n
                    this.drawRect(rect, context);\n
\n
                    context.restore();\n
                }\n
\n
            }, this);\n
        }\n
\n
        context.restore();\n
\n
        this._invalidRects = [];\n
        this._redrawTimer = null;\n
        this._lastRedrawTime = new Date().getTime();\n
    }\n
};\n
\n
Object.defineProperties(exports.CanvasView.prototype, {\n
    clippingFrame: {\n
        get: function() {\n
            return this._clippingFrame;\n
        },\n
\n
        set: function(clippingFrame) {\n
            clippingFrame = util.mixin(util.clone(this._clippingFrame), clippingFrame);\n
\n
            if (this._clippingFrame === null ||\n
                    !Rect.rectsEqual(clippingFrame, this._clippingFrame)) {\n
                this._clippingFrame = clippingFrame;\n
                this.clippingChanged();\n
            }\n
        }\n
    },\n
\n
    frame: {\n
        get: function() {\n
            return this._frame;\n
        },\n
        \n
        set: function(frame) {\n
            var domNode = this.domNode;\n
            var domStyle = domNode.style;\n
            var preventDownsize = this._preventDownsize;\n
            var domWidth = domNode.width;\n
            var domHeight = domNode.height;\n
            var domStyle = domNode.style;\n
            domStyle.left = frame.x + \'px\';\n
            domStyle.top = frame.y + \'px\';\n
\n
            var widthChanged, heightChanged;\n
            if (frame.width !== domWidth) {\n
                if (frame.width < domWidth) {\n
                    if (!preventDownsize) {\n
                        widthChanged = true;\n
                    }\n
                } else {\n
                    widthChanged = true;\n
                }\n
            }\n
            if (frame.height !== domHeight) {\n
                if (frame.height < domHeight) {\n
                    if (!preventDownsize) {\n
                        heightChanged = true;\n
                    }\n
                } else {\n
                    heightChanged = true;\n
                }\n
            }\n
\n
            if (widthChanged) {\n
                this.domNode.width = frame.width;\n
            }\n
            if (heightChanged) {\n
                this.domNode.height = frame.height;\n
            }\n
\n
            this._frame = frame;\n
\n
            // The clipping frame might have changed if the size changed.\n
            this.clippingFrame = {\n
                width: frame.width,\n
                height: frame.height\n
            };\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:views/text",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var util = require(\'bespin:util/util\');\n
\n
var Event = require(\'events\').Event;\n
var CanvasView = require(\'views/canvas\').CanvasView;\n
var LayoutManager = require(\'controllers/layoutmanager\').LayoutManager;\n
var Range = require(\'rangeutils:utils/range\');\n
var Rect = require(\'utils/rect\');\n
var TextInput = require(\'views/textinput\').TextInput;\n
var console = require(\'bespin:console\').console;\n
var settings = require(\'settings\').settings;\n
\n
// Set this to true to outline all text ranges with a box. This may be useful\n
// when optimizing syntax highlighting engines.\n
var DEBUG_TEXT_RANGES = false;\n
\n
\n
exports.TextView = function(container, editor) {\n
    CanvasView.call(this, container, true /* preventDownsize */ );\n
    this.editor = editor;\n
\n
    // Takes the layoutManager of the editor and uses it.\n
    var textInput = this.textInput = new TextInput(container, this);\n
\n
    this.padding = {\n
        top: 0,\n
        bottom: 30,\n
        left: 0,\n
        right: 30\n
    };\n
\n
    this.clippingChanged.add(this.clippingFrameChanged.bind(this));\n
\n
    var dom = this.domNode;\n
    dom.style.cursor = "text";\n
    dom.addEventListener(\'mousedown\', this.mouseDown.bind(this), false);\n
    dom.addEventListener(\'mousemove\', this.mouseMove.bind(this), false);\n
    window.addEventListener(\'mouseup\', this.mouseUp.bind(this), false);\n
\n
    editor.willChangeBuffer.add(this.editorWillChangeBuffer.bind(this));\n
\n
    // Changeevents.\n
    this.selectionChanged = new Event();\n
    this.beganChangeGroup = new Event();\n
    this.endedChangeGroup = new Event();\n
    this.willReplaceRange = new Event();\n
    this.replacedCharacters = new Event();\n
};\n
\n
exports.TextView.prototype = new CanvasView();\n
\n
util.mixin(exports.TextView.prototype, {\n
    _dragPoint: null,\n
    _dragTimer: null,\n
    _enclosingScrollView: null,\n
    _inChangeGroup: false,\n
    _insertionPointBlinkTimer: null,\n
    _insertionPointVisible: true,\n
\n
\n
    // FIXME: These should be public, not private.\n
    _keyBuffer: \'\',\n
    _keyMetaBuffer: \'\',\n
    _keyState: \'start\',\n
\n
    _hasFocus: false,\n
    _mouseIsDown: false,\n
\n
    selectionChanged: null,\n
    beganChangeGroup: null,\n
    endedChangeGroup: null,\n
    willReplaceRange: null,\n
    replacedCharacters: null,\n
\n
    editorWillChangeBuffer: function(newBuffer) {\n
        if (this.editor.layoutManager) {\n
            // Remove events from the old layoutManager.\n
            var layoutManager = this.editor.layoutManager;\n
            layoutManager.invalidatedRects.remove(this);\n
            layoutManager.changedTextAtRow.remove(this);\n
        }\n
\n
        // Add the events to the new layoutManager.\n
        layoutManager = newBuffer.layoutManager;\n
        layoutManager.invalidatedRects.add(this,\n
                                this.layoutManagerInvalidatedRects.bind(this));\n
        layoutManager.changedTextAtRow.add(this,\n
                                this.layoutManagerChangedTextAtRow.bind(this));\n
    },\n
\n
    /**\n
     * Called by the textInput whenever the textInput gained the focus.\n
     */\n
    didFocus: function() {\n
        // Call _setFocus and not this.hasFocus as we have to pass the\n
        // \'isFromTextInput\' flag.\n
        this._setFocus(true, true /* fromTextInput */);\n
    },\n
\n
    /**\n
     * Called by the textInput whenever the textinput lost the focus.\n
     */\n
    didBlur: function() {\n
        // Call _setFocus and not this.hasFocus as we have to pass the\n
        // \'isFromTextInput\' flag.\n
        this._setFocus(false, true /* fromTextInput */);\n
    },\n
\n
    _drag: function() {\n
        var point = this._dragPoint;\n
        var offset = Rect.offsetFromRect(this.clippingFrame, point);\n
\n
        this.moveCursorTo(this._selectionPositionForPoint({\n
                x:  point.x - offset.x,\n
                y:  point.y - offset.y\n
            }), true);\n
    },\n
\n
    // Draws a single insertion point.\n
    _drawInsertionPoint: function(rect, context) {\n
        if (!this._insertionPointVisible) {\n
            return;\n
        }\n
\n
        var range = this.editor.buffer._selectedRange;\n
        var characterRect = this.editor.layoutManager.\n
            characterRectForPosition(range.start);\n
        var x = Math.floor(characterRect.x), y = characterRect.y;\n
        var width = Math.ceil(characterRect.width);\n
        var height = characterRect.height;\n
\n
        context.save();\n
\n
        var theme = this.editor.themeData.editor;\n
        if (this._hasFocus) {\n
            context.strokeStyle = theme.cursorColor;\n
            context.beginPath();\n
            context.moveTo(x + 0.5, y);\n
            context.lineTo(x + 0.5, y + height);\n
            context.closePath();\n
            context.stroke();\n
        } else {\n
            context.fillStyle = theme.unfocusedCursorBackgroundColor;\n
            context.fillRect(x + 0.5, y, width - 0.5, height);\n
            context.strokeStyle = theme.unfocusedCursorColor;\n
            context.strokeRect(x + 0.5, y + 0.5, width - 1, height - 1);\n
        }\n
\n
        context.restore();\n
    },\n
\n
    _drawLines: function(rect, context) {\n
        var layoutManager = this.editor.layoutManager;\n
        var textLines = layoutManager.textLines;\n
        var lineAscent = layoutManager.fontDimension.lineAscent;\n
        var themeHighlighter = this.editor.themeData.highlighter\n
\n
        context.save();\n
        context.font = this.editor.font;\n
\n
        var range = layoutManager.characterRangeForBoundingRect(rect);\n
        var rangeStart = range.start, rangeEnd = range.end;\n
        var startRow = rangeStart.row, endRow = rangeEnd.row;\n
        for (var row = startRow; row <= endRow; row++) {\n
            var textLine = textLines[row];\n
            if (util.none(textLine)) {\n
                continue;\n
            }\n
\n
            // Clamp the start column and end column to fit within the line\n
            // text.\n
            var characters = textLine.characters;\n
            var length = characters.length;\n
            var endCol = Math.min(rangeEnd.col, length);\n
            var startCol = rangeStart.col;\n
            if (startCol >= length) {\n
                continue;\n
            }\n
\n
            // Get the color ranges, or synthesize one if it doesn\'t exist. We\n
            // have to be tolerant of bad data, because we may be drawing ahead\n
            // of the syntax highlighter.\n
            var colorRanges = textLine.colors;\n
            if (colorRanges == null) {\n
                colorRanges = [];\n
            }\n
\n
            // Figure out which color range to start in.\n
            var colorIndex = 0;\n
            while (colorIndex < colorRanges.length &&\n
                    startCol < colorRanges[colorIndex].start) {\n
                colorIndex++;\n
            }\n
\n
            var col = (colorIndex < colorRanges.length)\n
                      ? colorRanges[colorIndex].start\n
                      : startCol;\n
\n
            // And finally draw the line.\n
            while (col < endCol) {\n
                var colorRange = colorRanges[colorIndex];\n
                var end = colorRange != null ? colorRange.end : endCol;\n
                var tag = colorRange != null ? colorRange.tag : \'plain\';\n
\n
                var color = themeHighlighter.hasOwnProperty(tag)\n
                            ? themeHighlighter[tag]\n
                            : \'red\';\n
                context.fillStyle = color;\n
\n
                var pos = { row: row, col: col };\n
                var rect = layoutManager.characterRectForPosition(pos);\n
\n
                var snippet = characters.substring(col, end);\n
                context.fillText(snippet, rect.x, rect.y + lineAscent);\n
\n
                if (DEBUG_TEXT_RANGES) {\n
                    context.strokeStyle = color;\n
                    context.strokeRect(rect.x + 0.5, rect.y + 0.5,\n
                        rect.width * snippet.length - 1, rect.height - 1);\n
                }\n
\n
                col = end;\n
                colorIndex++;\n
            }\n
        }\n
\n
        context.restore();\n
    },\n
\n
    // Draws the background highlight for selections.\n
    _drawSelectionHighlight: function(rect, context) {\n
        var theme = this.editor.themeData.editor;\n
        var fillStyle = this._hasFocus ?\n
            theme.selectedTextBackgroundColor :\n
            theme.unfocusedCursorBackgroundColor;\n
        var layoutManager = this.editor.layoutManager;\n
\n
        context.save();\n
\n
        var range = Range.normalizeRange(this.editor.buffer._selectedRange);\n
        context.fillStyle = fillStyle;\n
        layoutManager.rectsForRange(range).forEach(function(rect) {\n
            context.fillRect(rect.x, rect.y, rect.width, rect.height);\n
        });\n
\n
        context.restore();\n
    },\n
\n
    // Draws either the selection or the insertion point.\n
    _drawSelection: function(rect, context) {\n
        if (this._rangeIsInsertionPoint(this.editor.buffer._selectedRange)) {\n
            this._drawInsertionPoint(rect, context);\n
        } else {\n
            this._drawSelectionHighlight(rect, context);\n
        }\n
    },\n
\n
    _getVirtualSelection: function(startPropertyAsWell) {\n
        var selectedRange = this.editor.buffer._selectedRange;\n
        var selectedRangeEndVirtual = this.editor.buffer._selectedRangeEndVirtual;\n
\n
        return {\n
            start:  startPropertyAsWell && selectedRangeEndVirtual ?\n
                    selectedRangeEndVirtual : selectedRange.start,\n
            end:    selectedRangeEndVirtual || selectedRange.end\n
        };\n
    },\n
\n
    _invalidateSelection: function() {\n
        var adjustRect = function(rect) {\n
            return {\n
                x:      rect.x - 1,\n
                y:      rect.y,\n
                width:  rect.width + 2,\n
                height: rect.height\n
            };\n
        };\n
\n
        var layoutManager = this.editor.layoutManager;\n
        var range = Range.normalizeRange(this.editor.buffer._selectedRange);\n
        if (!this._rangeIsInsertionPoint(range)) {\n
            var rects = layoutManager.rectsForRange(range);\n
            rects.forEach(function(rect) {\n
                this.invalidateRect(adjustRect(rect));\n
            }, this);\n
\n
            return;\n
        }\n
\n
        var rect = layoutManager.characterRectForPosition(range.start);\n
        this.invalidateRect(adjustRect(rect));\n
    },\n
\n
    _isReadOnly: function() {\n
        return this.editor.layoutManager.textStorage.readOnly;\n
    },\n
\n
    _keymappingChanged: function() {\n
        this._keyBuffer = \'\';\n
        this._keyState = \'start\';\n
    },\n
\n
    _performVerticalKeyboardSelection: function(offset) {\n
        var textStorage = this.editor.layoutManager.textStorage;\n
        var selectedRangeEndVirtual = this.editor.buffer._selectedRangeEndVirtual;\n
        var oldPosition = selectedRangeEndVirtual !== null ?\n
            selectedRangeEndVirtual : this.editor.buffer._selectedRange.end;\n
        var newPosition = Range.addPositions(oldPosition,\n
            { row: offset, col: 0 });\n
\n
        this.moveCursorTo(newPosition, true, true);\n
    },\n
\n
    _rangeIsInsertionPoint: function(range) {\n
        return Range.isZeroLength(range);\n
    },\n
\n
    _rearmInsertionPointBlinkTimer: function() {\n
        if (!this._insertionPointVisible) {\n
            // Make sure it ends up visible.\n
            this.blinkInsertionPoint();\n
        }\n
\n
        if (this._insertionPointBlinkTimer !== null) {\n
            clearInterval(this._insertionPointBlinkTimer);\n
        }\n
\n
        this._insertionPointBlinkTimer = setInterval(\n
                                            this.blinkInsertionPoint.bind(this),\n
                                            750);\n
    },\n
\n
    // Moves the selection, if necessary, to keep all the positions pointing to\n
    // actual characters.\n
    _repositionSelection: function() {\n
        var textLines = this.editor.layoutManager.textLines;\n
        var textLineLength = textLines.length;\n
\n
        var range = this.editor.buffer._selectedRange;\n
        var newStartRow = Math.min(range.start.row, textLineLength - 1);\n
        var newEndRow = Math.min(range.end.row, textLineLength - 1);\n
        var startLine = textLines[newStartRow];\n
        var endLine = textLines[newEndRow];\n
        this.setSelection({\n
            start: {\n
                row: newStartRow,\n
                col: Math.min(range.start.col, startLine.characters.length)\n
            },\n
            end: {\n
                row: newEndRow,\n
                col: Math.min(range.end.col, endLine.characters.length)\n
            }\n
        });\n
    },\n
\n
    _scrollPage: function(scrollUp) {\n
        var clippingFrame = this.clippingFrame;\n
        var lineAscent = this.editor.layoutManager.fontDimension.lineAscent;\n
        this.editor.scrollBy(0,\n
                    (clippingFrame.height + lineAscent) * (scrollUp ? -1 : 1));\n
    },\n
\n
    _scrollWhileDragging: function() {\n
        var point = this._dragPoint;\n
        var newPoint = this.computeWithClippingFrame(point.layerX, point.layerY);\n
        util.mixin(this._dragPoint, newPoint);\n
        this._drag();\n
    },\n
\n
    // Returns the character closest to the given point, obeying the selection\n
    // rules (including the partialFraction field).\n
    _selectionPositionForPoint: function(point) {\n
        var position = this.editor.layoutManager.characterAtPoint(point);\n
        return position.partialFraction < 0.5 ? position :\n
            Range.addPositions(position, { row: 0, col: 1 });\n
    },\n
\n
    _syntaxManagerUpdatedSyntaxForRows: function(startRow, endRow) {\n
        if (startRow === endRow) {\n
            return;\n
        }\n
\n
        var layoutManager = this.editor.layoutManager;\n
        layoutManager.updateTextRows(startRow, endRow);\n
\n
        layoutManager.rectsForRange({\n
                start:  { row: startRow, col: 0 },\n
                end:    { row: endRow,   col: 0 }\n
            }).forEach(this.invalidateRect, this);\n
    },\n
\n
    /**\n
     * Toggles the visible state of the insertion point.\n
     */\n
    blinkInsertionPoint: function() {\n
        this._insertionPointVisible = !this._insertionPointVisible;\n
        this._invalidateSelection();\n
    },\n
\n
    /**\n
     * Returns the selected characters.\n
     */\n
    copy: function() {\n
        return this.getSelectedCharacters();\n
    },\n
\n
    /**\n
     * Removes the selected characters from the text buffer and returns them.\n
     */\n
    cut: function() {\n
        var cutData = this.getSelectedCharacters();\n
\n
        if (cutData != \'\') {\n
            this.performBackspaceOrDelete(false);\n
        }\n
\n
        return cutData;\n
    },\n
\n
    /**\n
     * This is where the editor is painted from head to toe. Pitiful tricks are\n
     * used to draw as little as possible.\n
     */\n
    drawRect: function(rect, context) {\n
        context.fillStyle = this.editor.themeData.editor.backgroundColor;\n
        context.fillRect(rect.x, rect.y, rect.width, rect.height);\n
\n
        this._drawSelection(rect, context);\n
        this._drawLines(rect, context);\n
    },\n
\n
    /**\n
     * Directs keyboard input to this text view.\n
     */\n
    focus: function() {\n
        this.textInput.focus();\n
    },\n
\n
    /** Returns the location of the insertion point in pixels. */\n
    getInsertionPointPosition: function() {\n
        var editor = this.editor;\n
        var range = editor.buffer._selectedRange;\n
        var rect = editor.layoutManager.characterRectForPosition(range.start);\n
        return { x: rect.x, y: rect.y };\n
    },\n
\n
    /**\n
     * Returns the characters that are currently selected as a string, or the\n
     * empty string if none are selected.\n
     */\n
    getSelectedCharacters: function() {\n
        return this._rangeIsInsertionPoint(this.editor.buffer._selectedRange) ? \'\' :\n
            this.editor.layoutManager.textStorage.getCharacters(Range.\n
            normalizeRange(this.editor.buffer._selectedRange));\n
    },\n
\n
    /*\n
     * Returns the currently selected range.\n
     *\n
     * @param raw If true, the direction of the selection is preserved: the\n
     *            \'start\' field will be the selection origin, and the \'end\'\n
     *            field will always be the selection tail.\n
     */\n
    getSelectedRange: function(raw) {\n
        if (!raw) {\n
            return Range.normalizeRange(this.editor.buffer._selectedRange);\n
        } else {\n
            return this.editor.buffer._selectedRange;\n
        }\n
    },\n
\n
    /**\n
     * Groups all the changes in the callback into a single undoable action.\n
     * Nested change groups are supported; one undoable action is created for\n
     * the entire group of changes.\n
     */\n
    groupChanges: function(performChanges) {\n
        if (this._isReadOnly()) {\n
            return false;\n
        }\n
\n
        if (this._inChangeGroup) {\n
            performChanges();\n
            return true;\n
        }\n
\n
        this._inChangeGroup = true;\n
        this.beganChangeGroup(this, this.editor.buffer._selectedRange);\n
\n
        try {\n
            performChanges();\n
        } catch (e) {\n
            console.error("Error in groupChanges(): " + e);\n
            this._inChangeGroup = false;\n
            this.endedChangeGroup(this, this.editor.buffer._selectedRange);\n
            return false;\n
        } finally {\n
            this._inChangeGroup = false;\n
            this.endedChangeGroup(this, this.editor.buffer._selectedRange);\n
            return true;\n
        }\n
    },\n
\n
    /**\n
     * Replaces the selection with the given text and updates the selection\n
     * boundaries appropriately.\n
     *\n
     * @return True if the text view was successfully updated; false if the\n
     *     change couldn\'t be made because the text view is read-only.\n
     */\n
    insertText: function(text) {\n
        if (this._isReadOnly()) {\n
            return false;\n
        }\n
\n
        this.groupChanges(function() {\n
            var textStorage = this.editor.layoutManager.textStorage;\n
            var range = Range.normalizeRange(this.editor.buffer._selectedRange);\n
\n
            this.replaceCharacters(range, text);\n
\n
            // Update the selection to point immediately after the inserted\n
            // text.\n
            var lines = text.split(\'\\n\');\n
\n
            var destPosition;\n
            if (lines.length > 1) {\n
                destPosition = {\n
                    row:    range.start.row + lines.length - 1,\n
                    col: lines[lines.length - 1].length\n
                };\n
            } else {\n
                destPosition = Range.addPositions(range.start,\n
                    { row: 0, col: text.length });\n
            }\n
\n
            this.moveCursorTo(destPosition);\n
        }.bind(this));\n
\n
        return true;\n
    },\n
\n
    /**\n
     * Returns true if the given character is a word separator.\n
     */\n
    isDelimiter: function(character) {\n
        return \'"\\\',;.!~@#$%^&*?[]<>():/\\\\-+ \\t\'.indexOf(character) !== -1;\n
    },\n
\n
    keyDown: function(evt) {\n
        if (evt.charCode === 0 || evt._charCode === 0) {    // hack for Fx\n
            var preds = { isTextView: true };\n
            return this.editor.processKeyEvent(evt, this, preds);\n
        } else if (evt.keyCode === 9) {\n
            // Stops the tab. Otherwise the editor can lose focus.\n
            evt.preventDefault();\n
        } else {\n
            // This is a real keyPress event. This should not be handled,\n
            // otherwise the textInput mixin can\'t detect the key events.\n
            return false;\n
        }\n
    },\n
\n
    /**\n
     * Runs the syntax highlighter from the given row to the end of the visible\n
     * range, and repositions the selection.\n
     */\n
    layoutManagerChangedTextAtRow: function(sender, row) {\n
        this._repositionSelection();\n
    },\n
\n
    /**\n
     * Marks the given rectangles as invalid.\n
     */\n
    layoutManagerInvalidatedRects: function(sender, rects) {\n
        rects.forEach(this.invalidateRect, this);\n
    },\n
\n
    mouseDown: function(evt) {\n
        util.stopEvent(evt);\n
\n
        this.hasFocus = true;\n
        this._mouseIsDown = true;\n
\n
        var point = this.computeWithClippingFrame(evt.layerX, evt.layerY);\n
        util.mixin(point, { layerX: evt.layerX, layerY: evt.layerY});\n
\n
        switch (evt.detail) {\n
        case 1:\n
            var pos = this._selectionPositionForPoint(point);\n
            this.moveCursorTo(pos, evt.shiftKey);\n
            break;\n
\n
        // Select the word under the cursor.\n
        case 2:\n
            var pos = this._selectionPositionForPoint(point);\n
            var line = this.editor.layoutManager.textStorage.lines[pos.row];\n
\n
            // If there is nothing to select in this line, then skip.\n
            if (line.length === 0) {\n
                return true;\n
            }\n
\n
            pos.col -= (pos.col == line.length ? 1 : 0);\n
            var skipOnDelimiter = !this.isDelimiter(line[pos.col]);\n
\n
            var thisTextView = this;\n
            var searchForDelimiter = function(pos, dir) {\n
                for (pos; pos > -1 && pos < line.length; pos += dir) {\n
                    if (thisTextView.isDelimiter(line[pos]) ===\n
                            skipOnDelimiter) {\n
                        break;\n
                    }\n
                }\n
                return pos + (dir == 1 ? 0 : 1);\n
            };\n
\n
            var colFrom = searchForDelimiter(pos.col, -1);\n
            var colTo   = searchForDelimiter(pos.col, 1);\n
\n
            this.moveCursorTo({ row: pos.row, col: colFrom });\n
            this.moveCursorTo({ row: pos.row, col: colTo }, true);\n
\n
            break;\n
\n
        case 3:\n
            var lines = this.editor.layoutManager.textStorage.lines;\n
            var pos = this._selectionPositionForPoint(point);\n
            this.setSelection({\n
                start: {\n
                    row: pos.row,\n
                    col: 0\n
                },\n
                end: {\n
                    row: pos.row,\n
                    col: lines[pos.row].length\n
                }\n
            });\n
            break;\n
        }\n
\n
        this._dragPoint = point;\n
        this._dragTimer = setInterval(this._scrollWhileDragging.bind(this), 100);\n
    },\n
\n
    mouseMove: function(evt) {\n
        if (this._mouseIsDown) {\n
            this._dragPoint = this.computeWithClippingFrame(evt.layerX, evt.layerY);\n
            util.mixin(this._dragPoint, { layerX: evt.layerX, layerY: evt.layerY});\n
            this._drag();\n
        }\n
    },\n
\n
    mouseUp: function(evt) {\n
        this._mouseIsDown = false;\n
        if (this._dragTimer !== null) {\n
            clearInterval(this._dragTimer);\n
            this._dragTimer = null;\n
        }\n
    },\n
\n
    /**\n
     * Moves the cursor.\n
     *\n
     * @param position{Position} The position to move the cursor to.\n
     *\n
     * @param select{bool} Whether to preserve the selection origin. If this\n
     *        parameter is false, the selection is removed, and the insertion\n
     *        point moves to @position. Typically, this parameter is set when\n
     *        the mouse is being dragged or the shift key is held down.\n
     *\n
     * @param virtual{bool} Whether to save the current end position as the\n
     *        virtual insertion point. Typically, this parameter is set when\n
     *        moving vertically.\n
     */\n
    moveCursorTo: function(position, select, virtual) {\n
        var textStorage = this.editor.layoutManager.textStorage;\n
        var positionToUse = textStorage.clampPosition(position);\n
\n
        this.setSelection({\n
            start:  select ? this.editor.buffer._selectedRange.start : positionToUse,\n
            end:    positionToUse\n
        });\n
\n
        if (virtual) {\n
            var lineCount = textStorage.lines.length;\n
            var row = position.row, col = position.col;\n
            if (row > 0 && row < lineCount) {\n
                this.editor.buffer._selectedRangeEndVirtual = position;\n
            } else {\n
                this.editor.buffer._selectedRangeEndVirtual = {\n
                    row: row < 1 ? 0 : lineCount - 1,\n
                    col: col\n
                };\n
            }\n
        } else {\n
            this.editor.buffer._selectedRangeEndVirtual = null;\n
        }\n
\n
        this.scrollToPosition(this.editor.buffer._selectedRange.end);\n
    },\n
\n
    moveDown: function() {\n
        var selection = this._getVirtualSelection();\n
        var range = Range.normalizeRange(selection);\n
        var position;\n
        if (this._rangeIsInsertionPoint(this.editor.buffer._selectedRange)) {\n
            position = range.end;\n
        } else {\n
            // Yes, this is actually what Cocoa does... weird, huh?\n
            position = { row: range.end.row, col: range.start.col };\n
        }\n
        position = Range.addPositions(position, { row: 1, col: 0 });\n
\n
        this.moveCursorTo(position, false, true);\n
    },\n
\n
    moveLeft: function() {\n
        var range = Range.normalizeRange(this.editor.buffer._selectedRange);\n
        if (this._rangeIsInsertionPoint(range)) {\n
            this.moveCursorTo(this.editor.layoutManager.textStorage.\n
                displacePosition(range.start, -1));\n
        } else {\n
            this.moveCursorTo(range.start);\n
        }\n
    },\n
\n
    moveRight: function() {\n
        var range = Range.normalizeRange(this.editor.buffer._selectedRange);\n
        if (this._rangeIsInsertionPoint(range)) {\n
            this.moveCursorTo(this.editor.layoutManager.textStorage.\n
                displacePosition(range.end, 1));\n
        } else {\n
            this.moveCursorTo(range.end);\n
        }\n
    },\n
\n
    moveUp: function() {\n
        var range = Range.normalizeRange(this._getVirtualSelection(true));\n
        position = Range.addPositions({\n
            row: range.start.row,\n
            col: this._getVirtualSelection().end.col\n
        }, { row: -1, col: 0 });\n
\n
        this.moveCursorTo(position, false, true);\n
    },\n
\n
    parentViewFrameChanged: function() {\n
        arguments.callee.base.apply(this, arguments);\n
        this._resize();\n
    },\n
\n
    /**\n
     * As an undoable action, replaces the characters within the old range with\n
     * the supplied characters.\n
     *\n
     * TODO: Factor this out into the undo controller. The fact that commands\n
     * have to go through the view in order to make undoable changes is\n
     * counterintuitive.\n
     *\n
     * @param oldRange{Range}    The range of characters to modify.\n
     * @param characters{string} The string to replace the characters with.\n
     *\n
     * @return True if the changes were successfully made; false if the changes\n
     *     couldn\'t be made because the editor is read-only.\n
     */\n
    replaceCharacters: function(oldRange, characters) {\n
        if (this._isReadOnly()) {\n
            return false;\n
        }\n
\n
        this.groupChanges(function() {\n
            oldRange = Range.normalizeRange(oldRange);\n
            this.willReplaceRange(this, oldRange);\n
\n
            var textStorage = this.editor.layoutManager.textStorage;\n
            textStorage.replaceCharacters(oldRange, characters);\n
            this.replacedCharacters(this, oldRange, characters);\n
        }.bind(this));\n
\n
        return true;\n
    },\n
\n
    /**\n
     * Performs a delete-backward or delete-forward operation.\n
     *\n
     * @param isBackspace{boolean} If true, the deletion proceeds backward (as if\n
     *     the backspace key were pressed); otherwise, deletion proceeds forward.\n
     *\n
     * @return True if the operation was successfully performed; false if the\n
     *     operation failed because the editor is read-only.\n
     */\n
    performBackspaceOrDelete: function(isBackspace) {\n
        if (this._isReadOnly()) {\n
            return false;\n
        }\n
\n
        var model = this.editor.layoutManager.textStorage;\n
\n
        var lines = model.lines;\n
        var line = \'\', count = 0;\n
        var tabstop = settings.get(\'tabstop\');\n
        var range = this.getSelectedRange();\n
\n
        if (Range.isZeroLength(range)) {\n
            if (isBackspace) {\n
                var start = range.start;\n
                line = lines[start.row];\n
                var preWhitespaces = line.substring(0, start.col).\n
                                                    match(/\\s*$/)[0].length;\n
\n
                // If there are less then n-tabstop whitespaces in front, OR\n
                // the current cursor position is not n times tabstop, THEN\n
                // delete only 1 character.\n
                if (preWhitespaces < tabstop\n
                        || (start.col - tabstop) % tabstop != 0) {\n
                    count = 1;\n
                } else {\n
                    // Otherwise delete tabstop whitespaces.\n
                    count = tabstop;\n
                }\n
\n
                range = {\n
                    start:  model.displacePosition(start, count * -1),\n
                    end:    range.end\n
                };\n
            } else {\n
                var end = range.end;\n
                line = lines[end.row];\n
                var trailingWhitespaces = line.substring(end.col).\n
                                                    match(/^\\s*/)[0].length;\n
\n
                // If there are less then n-tabstop whitespaces after the cursor\n
                // position, then delete only 1 character. Otherwise delete\n
                // tabstop whitespaces.\n
                if (trailingWhitespaces < tabstop) {\n
                    count = 1;\n
                } else {\n
                    count = tabstop;\n
                }\n
\n
                range = {\n
                    start:  range.start,\n
                    end:    model.displacePosition(range.end, count)\n
                };\n
            }\n
        }\n
\n
        this.groupChanges(function() {\n
            this.replaceCharacters(range, \'\');\n
\n
            // Position the insertion point at the start of all the ranges that\n
            // were just deleted.\n
            this.moveCursorTo(range.start);\n
        }.bind(this));\n
\n
        return true;\n
    },\n
\n
    /** Removes all buffered keys. */\n
    resetKeyBuffers: function() {\n
        this._keyBuffer = \'\';\n
        this._keyMetaBuffer = \'\';\n
    },\n
\n
    /**\n
     * If the text view is inside a scrollable view, scrolls down by one page.\n
     */\n
    scrollPageDown: function() {\n
        this._scrollPage(false);\n
    },\n
\n
    /**\n
     * If the text view is inside a scrollable view, scrolls up by one page.\n
     */\n
    scrollPageUp: function() {\n
        this._scrollPage(true);\n
    },\n
\n
    /**\n
     * If this view is in a scrollable container, scrolls to the given\n
     * character position.\n
     */\n
    scrollToPosition: function(position) {\n
        var rect = this.editor.layoutManager.characterRectForPosition(position);\n
        var rectX = rect.x, rectY = rect.y;\n
        var rectWidth = rect.width, rectHeight = rect.height;\n
\n
        var frame = this.clippingFrame;\n
        var frameX = frame.x, frameY = frame.y;\n
\n
        var padding = this.padding;\n
        var width = frame.width - padding.right;\n
        var height = frame.height - padding.bottom;\n
\n
        var x;\n
        if (rectX >= frameX + 30 /* This is a hack to allow dragging to the left */\n
                    && rectX + rectWidth < frameX + width) {\n
            x = frameX;\n
        } else {\n
            x = rectX - width / 2 + rectWidth / 2;\n
        }\n
\n
        var y;\n
        if (rectY >= frameY && rectY + rectHeight < frameY + height) {\n
            y = frameY;\n
        } else {\n
            y = rectY - height / 2 + rectHeight / 2;\n
        }\n
\n
        this.editor.scrollTo({ x: x, y: y });\n
    },\n
\n
    /**\n
     * Selects all characters in the buffer.\n
     */\n
    selectAll: function() {\n
        var lines = this.editor.layoutManager.textStorage.lines;\n
        var lastRow = lines.length - 1;\n
        this.setSelection({\n
            start:  { row: 0, col: 0 },\n
            end:    { row: lastRow, col: lines[lastRow].length }\n
        });\n
    },\n
\n
    selectDown: function() {\n
        this._performVerticalKeyboardSelection(1);\n
    },\n
\n
    selectLeft: function() {\n
        this.moveCursorTo((this.editor.layoutManager.textStorage.\n
            displacePosition(this.editor.buffer._selectedRange.end, -1)), true);\n
    },\n
\n
    selectRight: function() {\n
        this.moveCursorTo((this.editor.layoutManager.textStorage.\n
            displacePosition(this.editor.buffer._selectedRange.end, 1)), true);\n
    },\n
\n
    selectUp: function() {\n
        this._performVerticalKeyboardSelection(-1);\n
    },\n
\n
    /**\n
     * Directly replaces the current selection with a new one.\n
     */\n
    setSelection: function(newRange, ensureVisible) {\n
        var textStorage = this.editor.layoutManager.textStorage;\n
\n
        newRange = textStorage.clampRange(newRange);\n
        if (Range.equal(newRange, this.editor.buffer._selectedRange)) {\n
            return;\n
        }\n
\n
        // Invalidate the old selection.\n
        this._invalidateSelection();\n
\n
        // Set the new selection and invalidate it.\n
        this.editor.buffer._selectedRange = newRange =\n
                                                textStorage.clampRange(newRange);\n
        this._invalidateSelection();\n
\n
        if (this._hasFocus) {\n
            this._rearmInsertionPointBlinkTimer();\n
        }\n
\n
        if (ensureVisible) {\n
            this.scrollToPosition(newRange.end);\n
        }\n
\n
        this.selectionChanged(newRange);\n
        catalog.publish(this.editor, \'editorChange\', \'selection\', newRange);\n
    },\n
\n
    textInserted: function(text) {\n
        // We don\'t handle the new line char at this point.\n
        if (text === \'\\n\') {\n
            return;\n
        }\n
\n
        var preds = { isTextView: true, isCommandKey: false };\n
        if (!this.editor.processKeyEvent(text, this, preds)) {\n
            this.insertText(text);\n
            this.resetKeyBuffers();\n
        }\n
    },\n
\n
    /**\n
     * Changes the internal hasFocus flag if the current hasFocus value is not\n
     * equal to the parameter \'value\'. If \'fromTextInput\' is true, then\n
     * the textInput.focus() and textInput.blur() is not called. This is\n
     * necessary as otherwise the textInput detects the blur event, calls\n
     * hasFocus = false and the _setFocus function calls textInput.blur() again.\n
     * If the textInput was blured, because the entire page lost the focus, then\n
     * the foucs is not reset to the textInput when the page gains the focus again.\n
     */\n
    _setFocus: function(value, fromTextInput) {\n
        if (value == this._hasFocus) {\n
            return;\n
        }\n
\n
        this._hasFocus = value;\n
\n
        if (this._hasFocus) {\n
            this._rearmInsertionPointBlinkTimer();\n
            this._invalidateSelection();\n
            if (!fromTextInput) {\n
                 this.textInput.focus();\n
            }\n
        } else {\n
            if (this._insertionPointBlinkTimer) {\n
                clearInterval(this._insertionPointBlinkTimer);\n
                this._insertionPointBlinkTimer = null;\n
            }\n
            this._insertionPointVisible = true;\n
            this._invalidateSelection();\n
            if (!fromTextInput) {\n
                 this.textInput.blur();\n
            }\n
        }\n
    }\n
});\n
\n
Object.defineProperties(exports.TextView.prototype, {\n
    hasFocus: {\n
        get: function() {\n
            return this._hasFocus;\n
        },\n
\n
        set: function(value) {\n
            this._setFocus(value, false /* fromTextInput*/);\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:models/buffer",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var env = require(\'environment\').env;\n
\n
var util = require(\'bespin:util/util\');\n
\n
var Promise = require(\'bespin:promise\').Promise;\n
var TextStorage = require(\'models/textstorage\').TextStorage;\n
var LayoutManager = require(\'controllers/layoutmanager\').LayoutManager;\n
var UndoManager = require(\'undomanager\').UndoManager;\n
\n
/**\n
 * A Buffer connects a model and file together. It also holds the layoutManager\n
 * that is bound to the model. The syntaxManager can get accessed via the\n
 * layoutManager as well.\n
 *\n
 * Per opened file there is one buffer which means that one buffer is\n
 * corresponding to one file on the disk. If you open different file, you have\n
 * to create a new buffer for that file.\n
 *\n
 * To create a buffer that is (not yet) bound to a file, just create the Buffer\n
 * without a file passed.\n
 */\n
exports.Buffer = function(file, initialContent) {\n
    this._file = file;\n
    this._model = new TextStorage(initialContent);\n
    this._layoutManager = new LayoutManager({\n
        textStorage: this._model\n
    });\n
\n
    this.undoManager = new UndoManager();\n
\n
    // If a file is passed, then load it. This is the same as calling reload.\n
    if (file) {\n
        this.reload().then(function() {\n
            this._updateSyntaxManagerInitialContext();\n
        }.bind(this));\n
    } else {\n
        this.loadPromise = new Promise();\n
        this.loadPromise.resolve();\n
    }\n
\n
    // Restore the state of the buffer (selection + scrollOffset).\n
    // TODO: Refactor this code into the ViewState.\n
    var history = (env.session ? env.session.history : null);\n
    var item, selection, scrollOffset;\n
\n
    // If\n
    //  1.  Check if a history exists and the buffer has a file (-> path)\n
    //  2.  Ask the history object for the history for the current file.\n
    //      If no history is found, null is returned.\n
    if (history && file &&                                  // 1.\n
            (item = history.getHistoryForPath(file.path))   // 2.\n
    ) {\n
        // There is no state saved in the buffer and the history object\n
        // has a state saved.\n
        selection = item.selection;\n
        scrollOffset = item.scroll;\n
    }\n
\n
    // Use the saved values from the history or the default values.\n
    this._selectedRange = selection || {\n
        start: { row: 0, col: 0 },\n
        end: { row: 0, col: 0 }\n
    };\n
\n
    this._scrollOffset = scrollOffset || { x: 0, y: 0 };\n
};\n
\n
exports.Buffer.prototype = {\n
    /**\n
     * The undoManager where the undo/redo stack is stored and handled.\n
     */\n
    undoManager: null,\n
\n
    loadPromise: null,\n
\n
    _scrollOffset: null,\n
    _selectedRange: null,\n
    _selectedRangeEndVirtual: null,\n
\n
    /**\n
     * The syntax manager associated with this file.\n
     */\n
    _layoutManager: null,\n
\n
    /**\n
     * The file object associated with this buffer. The file instance can only\n
     * be assigned when constructing the buffer or calling saveAs.\n
     */\n
    _file: null,\n
\n
   /**\n
    * The text model that is holding the content of the file.\n
    */\n
    _model: null,\n
\n
    /**\n
     * Save the contents of this buffer. Returns a promise that resolves\n
     * once the file is saved.\n
     */\n
    save: function() {\n
        return this._file.saveContents(this._model.value);\n
    },\n
\n
    /**\n
     * Saves the contents of this buffer to a new file, and updates the file\n
     * field of this buffer to point to the result.\n
     *\n
     * @param dir{Directory} The directory to save in.\n
     * @param filename{string} The name of the file in the directory.\n
     * @return A promise to return the newly-saved file.\n
     */\n
    saveAs: function(newFile) {\n
        var promise = new Promise();\n
\n
        newFile.saveContents(this._model.value).then(function() {\n
            this._file = newFile;\n
            this._updateSyntaxManagerInitialContext();\n
            promise.resolve();\n
        }.bind(this), function(error) {\n
            promise.reject(error);\n
        });\n
\n
        return promise;\n
    },\n
\n
    /**\n
     * Reload the existing file contents from the server.\n
     */\n
    reload: function() {\n
        var file = this._file;\n
        var self = this;\n
\n
        var pr;\n
        pr =  file.loadContents().then(function(contents) {\n
            self._model.value = contents;\n
        });\n
        this.loadPromise = pr;\n
        return pr;\n
    },\n
\n
    _updateSyntaxManagerInitialContext: function() {\n
        var ext = this._file.extension();\n
        var syntaxManager = this._layoutManager.syntaxManager;\n
        syntaxManager.setSyntaxFromFileExt(ext === null ? \'\' : ext);\n
    },\n
\n
    /**\n
     * Returns true if the file is untitled (i.e. it is new and has not yet\n
     * been saved with @saveAs) or false otherwise.\n
     */\n
    untitled: function() {\n
        return util.none(this._file);\n
    }\n
};\n
\n
Object.defineProperties(exports.Buffer.prototype, {\n
    layoutManager: {\n
        get: function() {\n
            return this._layoutManager;\n
        }\n
    },\n
\n
    syntaxManager: {\n
        get: function() {\n
            this._layoutManager.syntaxManager;\n
        }\n
    },\n
\n
    file: {\n
        get: function() {\n
            return this._file;\n
        }\n
    },\n
\n
    model: {\n
        get: function() {\n
            return this._model;\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:models/textstorage",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Event = require(\'events\').Event;\n
var util = require(\'bespin:util/util\');\n
\n
var TextStorage;\n
\n
/**\n
 * Creates a new text storage object holding the given string (if supplied).\n
 *\n
 * @constructor\n
 * @exports TextStorage as text_editor:models.textstorage.TextStorage\n
 */\n
TextStorage = function(initialValue) {\n
    if (initialValue !== null && initialValue !== undefined) {\n
        this._lines = initialValue.split("\\n");\n
    } else {\n
        this._lines = [ \'\' ];\n
    }\n
\n
    /**\n
     * Called whenever the text changes with the old and new ranges supplied.\n
     */\n
    this.changed = new Event();\n
\n
    return this;\n
};\n
\n
TextStorage.prototype = {\n
    /** @lends TextStorage */\n
\n
    _lines: null,\n
\n
    /**\n
     * Whether this model is read-only. Attempts to modify a read-only model\n
     * result in exceptions.\n
     *\n
     * @type {boolean}\n
     */\n
    readOnly: false,\n
\n
    /**\n
     * Returns the position of the nearest character to the given position,\n
     * according to the selection rules.\n
     *\n
     * @param {position} pos The position to clamp.\n
     */\n
    clampPosition: function(pos) {\n
        var lines = this._lines;\n
\n
        var row = pos.row;\n
        if (row < 0) {\n
            return { row: 0, col: 0 };\n
        } else if (row >= lines.length) {\n
            return this.range.end;\n
        }\n
\n
        var col = Math.max(0, Math.min(pos.col, lines[row].length));\n
        return { row: row, col: col };\n
    },\n
\n
    /**\n
     * Returns the actual range closest to the given range, according to the\n
     * selection rules.\n
     */\n
    clampRange: function(range) {\n
        var start = this.clampPosition(range.start);\n
        var end = this.clampPosition(range.end);\n
        return { start: start, end: end };\n
    },\n
\n
    /** Deletes all characters in the range. */\n
    deleteCharacters: function(range) {\n
        this.replaceCharacters(range, \'\');\n
    },\n
\n
    /**\n
     * Returns the result of displacing the given position by count characters\n
     * forward (if count > 0) or backward (if count < 0).\n
     */\n
    displacePosition: function(pos, count) {\n
        var forward = count > 0;\n
        var lines = this._lines;\n
        var lineCount = lines.length;\n
\n
        for (var i = Math.abs(count); i !== 0; i--) {\n
            if (forward) {\n
                var rowLength = lines[pos.row].length;\n
                if (pos.row === lineCount - 1 && pos.col === rowLength) {\n
                    return pos;\n
                }\n
                pos = pos.col === rowLength ?\n
                    { row: pos.row + 1, col: 0            } :\n
                    { row: pos.row,     col: pos.col + 1  };\n
            } else {\n
                if (pos.row === 0 && pos.col == 0) {\n
                    return pos;\n
                }\n
\n
                if (pos.col === 0) {\n
                    lines = this._lines;\n
                    pos = {\n
                        row:    pos.row - 1,\n
                        col: lines[pos.row - 1].length\n
                    };\n
                } else {\n
                    pos = { row: pos.row, col: pos.col - 1 };\n
                }\n
            }\n
        }\n
        return pos;\n
    },\n
\n
    /**\n
     * Returns the characters in the given range as a string.\n
     */\n
    getCharacters: function(range) {\n
        var lines = this._lines;\n
        var start = range.start, end = range.end;\n
        var startRow = start.row, endRow = end.row;\n
        var startCol = start.col, endCol = end.col;\n
\n
        if (startRow === endRow) {\n
            return lines[startRow].substring(startCol, endCol);\n
        }\n
\n
        var firstLine = lines[startRow].substring(startCol);\n
        var middleLines = lines.slice(startRow + 1, endRow);\n
        var endLine = lines[endRow].substring(0, endCol);\n
        return [ firstLine ].concat(middleLines, endLine).join(\'\\n\');\n
    },\n
\n
    /** Returns the lines of the text storage as a read-only array. */\n
    getLines: function() {\n
        return this._lines;\n
    },\n
\n
    /** Returns the span of the entire text content. */\n
    getRange: function() {\n
        var lines = this._lines;\n
        var endRow = lines.length - 1;\n
        var endCol = lines[endRow].length;\n
        var start = { row: 0, col: 0 }, end = { row: endRow, col: endCol };\n
        return { start: start, end: end };\n
    },\n
\n
    /** Returns the text in the text storage as a string. */\n
    getValue: function() {\n
        return this._lines.join(\'\\n\');\n
    },\n
\n
    /** Inserts characters at the supplied position. */\n
    insertCharacters: function(pos, chars) {\n
        this.replaceCharacters({ start: pos, end: pos }, chars);\n
    },\n
\n
    /** Replaces the characters within the supplied range. */\n
    replaceCharacters: function(oldRange, characters) {\n
        if (this.readOnly) {\n
            throw new Error("Attempt to modify a read-only text storage " +\n
                "object");\n
        }\n
\n
        var addedLines = characters.split(\'\\n\');\n
        var addedLineCount = addedLines.length;\n
\n
        var newRange = this.resultingRangeForReplacement(oldRange, addedLines);\n
\n
        var oldStart = oldRange.start, oldEnd = oldRange.end;\n
        var oldStartRow = oldStart.row, oldEndRow = oldEnd.row;\n
        var oldStartColumn = oldStart.col;\n
\n
        var lines = this._lines;\n
        addedLines[0] = lines[oldStartRow].substring(0, oldStartColumn) +\n
            addedLines[0];\n
        addedLines[addedLineCount - 1] +=\n
            lines[oldEndRow].substring(oldEnd.col);\n
\n
        this._lines = util.replace(lines, oldStartRow, oldEndRow - oldStartRow + 1, addedLines);\n
\n
        this.changed(oldRange, newRange, characters);\n
    },\n
\n
    /**\n
     * Returns the character range that would be modified if the range were\n
     * replaced with the given lines.\n
     */\n
    resultingRangeForReplacement: function(range, lines) {\n
        var lineCount = lines.length;\n
        var lastLineLength = lines[lineCount - 1].length;\n
        var start = range.start;\n
        var endRow = start.row + lineCount - 1;\n
        var endCol = (lineCount === 1 ? start.col : 0) + lastLineLength;\n
        return { start: start, end: { row: endRow, col: endCol } };\n
    },\n
\n
    setLines: function(newLines) {\n
        this.setValue(newLines.join(\'\\n\'));\n
    },\n
\n
    setValue: function(newValue) {\n
        this.replaceCharacters(this.range, newValue);\n
    }\n
};\n
\n
exports.TextStorage = TextStorage;\n
\n
Object.defineProperties(exports.TextStorage.prototype, {\n
    lines: {\n
        get: function() {\n
            return this.getLines();\n
        },\n
        set: function(newLines) {\n
            return this.setLines(newLines);\n
        }\n
    },\n
    \n
    range: {\n
        get: function() {\n
            return this.getRange();\n
        }\n
    },\n
    \n
    value: {\n
        get: function() {\n
            return this.getValue();\n
        },\n
        set: function(newValue) {\n
            this.setValue(newValue);\n
        }\n
    }\n
});\n
\n
});\n
\n
bespin.tiki.module("text_editor:utils/rect",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
/**\n
 * @private\n
 *\n
 * Returns the distance between the given value and the given inclusive upper\n
 * and lower bounds, or 0 if the value lies between them.\n
 *\n
 * Exported so that the function can be unit tested.\n
 */\n
exports._distanceFromBounds = function(value, low, high) {\n
    if (value < low) {\n
        return value - low;\n
    }\n
    if (value >= high) {\n
        return value - high;\n
    }\n
    return 0;\n
};\n
\n
/**\n
 * Merges the rectangles in a given set and returns the resulting set of non-\n
 * overlapping rectanlges.\n
 */\n
exports.merge = function(set) {\n
    var modified;\n
    do {\n
        modified = false;\n
        var newSet = [];\n
\n
        for (var i = 0; i < set.length; i++) {\n
            var rectA = set[i];\n
            newSet.push(rectA);\n
            for (var j = i+1; j < set.length; j++) {\n
                var rectB = set[j];\n
                if (exports.rectsSideBySide(rectA, rectB) ||\n
                                        exports.rectsIntersect(rectA, rectB)) {\n
                    set.splice(j, 1);\n
\n
                    // There\'s room for optimization here...\n
                    newSet[newSet.length - 1] = exports.unionRects(rectA, rectB);\n
\n
                    modified = true;\n
                    break;\n
                }\n
            }\n
        }\n
\n
        set = newSet;\n
    } while (modified);\n
\n
    return set;\n
};\n
\n
/**\n
 * Returns the vector representing the shortest offset between the given\n
 * rectangle and the given point.\n
 */\n
exports.offsetFromRect = function(rect, point) {\n
    return {\n
        x: exports._distanceFromBounds(point.x, rect.x, exports.maxX(rect)),\n
        y: exports._distanceFromBounds(point.y, rect.y, exports.maxY(rect))\n
    };\n
};\n
\n
/**\n
 * Returns true if the rectanges intersect or false otherwise. Adjacent\n
 * rectangles don\'t count; they must actually overlap some region.\n
 */\n
exports.rectsIntersect = function(a, b) {\n
    var intersection = exports.intersectRects(a, b);\n
    return intersection.width !== 0 && intersection.height !== 0;\n
};\n
\n
/**\n
 * Checks if two rects lay side by side. Returns true if this is true.\n
 * For example:\n
 *      +------------+---------------+\n
 *      |    A       |       B       |\n
 *      +------------+---------------+\n
 * will be true, but if B is only one pixel shifted up,\n
 * then it would return false.\n
 */\n
exports.rectsSideBySide = function(a, b) {\n
    if (a.x == b.x && a.width == b.width) {\n
        if (a.y < b.y) {\n
            return (a.y + a.height) == b.y;\n
        } else {\n
            return (b.y + b.height) == a.y;\n
        }\n
    } else if (a.y == b.y && a.height == b.height) {\n
        if (a.x < b.x) {\n
            return (a.x + a.width) == b.x;\n
        } else {\n
            return (b.x + b.width) == a.x;\n
        }\n
    }\n
    return false;\n
};\n
\n
// extracted from SproutCore\n
exports.intersectRects = function(r1, r2) {\n
  // find all four edges\n
  var ret = {\n
    x: Math.max(exports.minX(r1), exports.minX(r2)),\n
    y: Math.max(exports.minY(r1), exports.minY(r2)),\n
    width: Math.min(exports.maxX(r1), exports.maxX(r2)),\n
    height: Math.min(exports.maxY(r1), exports.maxY(r2))\n
  } ;\n
\n
  // convert edges to w/h\n
  ret.width = Math.max(0, ret.width - ret.x) ;\n
  ret.height = Math.max(0, ret.height - ret.y) ;\n
  return ret ;\n
};\n
\n
/** Return the left edge of the frame */\n
exports.minX = function(frame) {\n
  return frame.x || 0;\n
};\n
\n
/** Return the right edge of the frame. */\n
exports.maxX = function(frame) {\n
  return (frame.x || 0) + (frame.width || 0);\n
};\n
\n
/** Return the top edge of the frame */\n
exports.minY = function(frame) {\n
  return frame.y || 0 ;\n
};\n
\n
/** Return the bottom edge of the frame */\n
exports.maxY = function(frame) {\n
  return (frame.y || 0) + (frame.height || 0) ;\n
};\n
\n
/** Check if the given point is inside the rect. */\n
exports.pointInRect = function(point, f) {\n
    return  (point.x >= exports.minX(f)) &&\n
            (point.y >= exports.minY(f)) &&\n
            (point.x <= exports.maxX(f)) &&\n
            (point.y <= exports.maxY(f)) ;\n
};\n
\n
/** Returns the union between two rectangles\n
\n
  @param r1 {Rect} The first rect\n
  @param r2 {Rect} The second rect\n
  @returns {Rect} The union rect.\n
*/\n
exports.unionRects = function(r1, r2) {\n
  // find all four edges\n
  var ret = {\n
    x: Math.min(exports.minX(r1), exports.minX(r2)),\n
    y: Math.min(exports.minY(r1), exports.minY(r2)),\n
    width: Math.max(exports.maxX(r1), exports.maxX(r2)),\n
    height: Math.max(exports.maxY(r1), exports.maxY(r2))\n
  } ;\n
\n
  // convert edges to w/h\n
  ret.width = Math.max(0, ret.width - ret.x) ;\n
  ret.height = Math.max(0, ret.height - ret.y) ;\n
  return ret ;\n
};\n
\n
/** Return true if the two frames match.  You can also pass only points or sizes.\n
\n
  @param r1 {Rect} the first rect\n
  @param r2 {Rect} the second rect\n
  @param delta {Float} an optional delta that allows for rects that do not match exactly. Defaults to 0.1\n
  @returns {Boolean} true if rects match\n
 */\n
exports.rectsEqual = function(r1, r2, delta) {\n
    if (!r1 || !r2) return (r1 == r2) ;\n
    if (!delta && delta !== 0) delta = 0.1;\n
    if ((r1.y != r2.y) && (Math.abs(r1.y - r2.y) > delta)) return false ;\n
    if ((r1.x != r2.x) && (Math.abs(r1.x - r2.x) > delta)) return false ;\n
    if ((r1.width != r2.width) && (Math.abs(r1.width - r2.width) > delta)) return false ;\n
    if ((r1.height != r2.height) && (Math.abs(r1.height - r2.height) > delta)) return false ;\n
    return true ;\n
};\n
\n
});\n
\n
bespin.tiki.module("text_editor:controllers/layoutmanager",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var Event = require("events").Event;\n
var Range = require(\'rangeutils:utils/range\');\n
var SyntaxManager = require(\'syntax_manager\').SyntaxManager;\n
var TextStorage = require(\'models/textstorage\').TextStorage;\n
var catalog = require(\'bespin:plugins\').catalog;\n
var settings = require(\'settings\').settings;\n
var m_scratchcanvas = require(\'bespin:util/scratchcanvas\');\n
\n
var fontDimension = {};\n
\n
var computeFontDimension = function() {\n
    var fontSize = settings.get(\'fontsize\');\n
    var fontFace = settings.get(\'fontface\');\n
    var font = fontSize + \'px \' + fontFace;\n
\n
    var canvas = m_scratchcanvas.get();\n
\n
    // Measure a large string to work around the fact that width and height\n
    // are truncated to the nearest integer in the canvas API.\n
    var str = \'\';\n
    for (var i = 0; i < 100; i++) {\n
        str += \'M\';\n
    }\n
\n
    var width = canvas.measureStringWidth(font, str) / 100;\n
\n
    fontDimension.characterWidth = width;\n
\n
    fontDimension.lineHeight = Math.floor(fontSize * 1.6);\n
    fontDimension.lineAscent = Math.floor(fontSize * 1.3);\n
};\n
\n
computeFontDimension();\n
\n
catalog.registerExtension(\'settingChange\', {\n
    match: "font[size|face]",\n
    pointer: computeFontDimension\n
});\n
\n
exports.LayoutManager = function(opts) {\n
    this.changedTextAtRow = new Event();\n
    this.invalidatedRects = new Event();\n
\n
    // Put the global variable on the instance.\n
    this.fontDimension = fontDimension;\n
\n
    // There is no setter for textStorage so we have to change it to\n
    // _textStorage to make things work with util.mixin().\n
    if (opts.textStorage) {\n
        opts._textStorage = opts.textStorage;\n
        delete opts.textStorage;\n
    } else {\n
        this._textStorage = new TextStorage();\n
    }\n
\n
    util.mixin(this, opts);\n
\n
    this._textStorage.changed.add(this.textStorageChanged.bind(this));\n
\n
    this.textLines = [\n
        {\n
            characters: \'\',\n
            colors:     [\n
                {\n
                    start:  0,\n
                    end:    0,\n
                    color:  \'plain\'\n
                }\n
            ]\n
        }\n
    ];\n
\n
    var syntaxManager = new SyntaxManager(this);\n
    this.syntaxManager = syntaxManager;\n
    syntaxManager.attrsChanged.add(this._attrsChanged.bind(this));\n
\n
    this._size = { width: 0, height: 0 };\n
    this.sizeChanged = new Event();\n
\n
    this._height = 0;\n
\n
    // Now that the syntax manager is set up, we can recompute the layout.\n
    // (See comments in _textStorageChanged().)\n
    this._recomputeEntireLayout();\n
};\n
\n
exports.LayoutManager.prototype = {\n
    _maximumWidth: 0,\n
    _textStorage: null,\n
\n
    _size: null,\n
    sizeChanged: null,\n
\n
    /**\n
     * Theme colors. Value is set by editorView class. Don\'t change this\n
     * property directly. Use the editorView function to adjust it.\n
     */\n
    _theme: { },\n
\n
    /**\n
     * @property\n
     *\n
     * The margins on each edge in pixels, expressed as an object with \'left\',\n
     * \'bottom\', \'top\', and \'right\' properties.\n
     *\n
     * Do not modify the properties of this object directly; clone, adjust, and\n
     * reset the margin property of the layout manager instead.\n
     */\n
    margin: { left: 5, bottom: 6, top: 0, right: 12 },\n
\n
    /**\n
     * @property\n
     *\n
     * The plugin catalog to use. Typically this will be plugins.catalog, but\n
     * for testing this may be replaced with a mock object.\n
     */\n
    pluginCatalog: catalog,\n
\n
    /** The syntax manager in use. */\n
    syntaxManager: null,\n
\n
    /**\n
     * @property{Array<object>}\n
     *\n
     * The marked-up lines of text. Each line has the properties \'characters\',\n
     * \'colors\', and \'lineHeight\'.\n
     */\n
    textLines: null,\n
\n
    // Called whenever the text attributes (which usually consist of syntax\n
    // highlighting) change.\n
    _attrsChanged: function(startRow, endRow) {\n
        this.updateTextRows(startRow, endRow);\n
\n
        var invalidRects = this.rectsForRange({\n
            start:  { row: startRow, col: 0 },\n
            end:    { row: endRow, col: 0 }\n
        });\n
\n
        this.invalidatedRects(this, invalidRects);\n
    },\n
\n
    _computeInvalidRects: function(oldRange, newRange) {\n
        var startRect = this.characterRectForPosition(oldRange.start);\n
\n
        var lineRect = {\n
            x:      startRect.x,\n
            y:      startRect.y,\n
            width:  Number.MAX_VALUE,\n
            height: startRect.height\n
        };\n
\n
        return oldRange.end.row === newRange.end.row ?\n
            [ lineRect ] :\n
            [\n
                lineRect,\n
                {\n
                    x:      0,\n
                    y:      startRect.y + fontDimension.lineHeight,\n
                    width:  Number.MAX_VALUE,\n
                    height: Number.MAX_VALUE\n
                }\n
            ];\n
    },\n
\n
    // Returns the last valid position in the buffer.\n
    _lastCharacterPosition: function() {\n
        return {\n
            row: this.textLines.length - 1,\n
            col: this._maximumWidth\n
        };\n
    },\n
\n
    _recalculateMaximumWidth: function() {\n
        // Lots of room for optimization here if this turns out to be slow. But\n
        // for now...\n
        var textLines = this.textLines;\n
        var max = 0;\n
        textLines.forEach(function(line) {\n
            var width = line.characters.length;\n
            if (max < width) {\n
                max = width;\n
            }\n
        });\n
        this._maximumWidth = max;\n
\n
        this.size = { width: max, height: this.textLines.length };\n
    },\n
\n
    _recomputeEntireLayout: function() {\n
        var entireRange = this._textStorage.range;\n
        this._recomputeLayoutForRanges(entireRange, entireRange);\n
    },\n
\n
    _recomputeLayoutForRanges: function(oldRange, newRange) {\n
        var oldStartRow = oldRange.start.row, oldEndRow = oldRange.end.row;\n
        var newEndRow = newRange.end.row;\n
        var newRowCount = newEndRow - oldStartRow + 1;\n
\n
        var lines = this._textStorage.lines;\n
        var theme = this._theme;\n
        var plainColor = theme.plain;\n
\n
        var newTextLines = [];\n
        for (var i = 0; i < newRowCount; i++) {\n
            var line = lines[oldStartRow + i];\n
            newTextLines[i] = {\n
                characters: line,\n
                colors: [ { start: 0, end: null, color: plainColor } ]\n
            };\n
        }\n
\n
        this.textLines = util.replace(this.textLines, oldStartRow,\n
                                oldEndRow - oldStartRow + 1, newTextLines);\n
        this._recalculateMaximumWidth();\n
\n
        // Resize if necessary.\n
        var newHeight = this.textLines.length;\n
        var syntaxManager = this.syntaxManager;\n
        if (this._height !== newHeight) {\n
            this._height = newHeight;\n
        }\n
\n
        // Invalidate the start row (starting the syntax highlighting).\n
        syntaxManager.invalidateRow(oldStartRow);\n
\n
        // Take the cached attributes from the syntax manager.\n
        this.updateTextRows(oldStartRow, newEndRow + 1);\n
\n
        this.changedTextAtRow(this, oldStartRow);\n
\n
        var invalidRects = this._computeInvalidRects(oldRange, newRange);\n
        this.invalidatedRects(this, invalidRects);\n
    },\n
\n
    /**\n
     * Determines the boundaries of the entire text area.\n
     *\n
     * TODO: Unit test.\n
     */\n
    boundingRect: function() {\n
        return this.rectsForRange({\n
            start:  { row: 0, col: 0 },\n
            end:    {\n
                row: this.textLines.length - 1,\n
                col: this._maximumWidth\n
            }\n
        })[0];\n
    },\n
\n
    /**\n
     * Determines the location of the character underneath the given point.\n
     *\n
     * @return Returns an object with three properties:\n
     *   * row: The row of the character nearest the point.\n
     *   * col: The col of the character nearest the point.\n
     *   * partialFraction: The fraction of the horizontal distance between\n
     *       this character and the next character. The extreme left of the\n
     *       character is 0.0, while the extreme right of the character is 1.0.\n
     *       If you are calling this function to determine where to place the\n
     *       cursor, then you should place the cursor after the returned\n
     *       character if this value is greater than 0.5.\n
     *\n
     * If there is no character under the point, then the character nearest the\n
     * given point is returned, according to the selection rules.\n
     */\n
    characterAtPoint: function(point) {\n
        var margin = this.margin;\n
        var x = point.x - margin.left, y = point.y - margin.top;\n
\n
        var characterWidth = fontDimension.characterWidth;\n
        var textStorage = this._textStorage;\n
        var clampedPosition = textStorage.clampPosition({\n
            row: Math.floor(y / fontDimension.lineHeight),\n
            col: Math.floor(x / characterWidth)\n
        });\n
\n
        var lineLength = textStorage.lines[clampedPosition.row].length;\n
        clampedPosition.partialFraction = x < 0 ||\n
            clampedPosition.col === lineLength ? 0.0 :\n
            x % characterWidth / characterWidth;\n
\n
        return clampedPosition;\n
    },\n
\n
    /**\n
     * Given a rectangle expressed in pixels, returns the range of characters\n
     * that lie at least partially within the rectangle as an object.\n
     *\n
     * TODO: Write unit tests for this method.\n
     */\n
    characterRangeForBoundingRect: function(rect) {\n
        // TODO: variable line heights, needed for word wrap and perhaps\n
        // extensions as well\n
        var lineHeight = fontDimension.lineHeight;\n
        var characterWidth = fontDimension.characterWidth;\n
        var margin = this.margin;\n
        var x = rect.x - margin.left, y = rect.y - margin.top;\n
        return {\n
            start:  {\n
                row: Math.max(Math.floor(y / lineHeight), 0),\n
                col: Math.max(Math.floor(x / characterWidth), 0)\n
            },\n
            end:    {\n
                row: Math.floor((y + rect.height - 1) / lineHeight),\n
                col: Math.floor((x + rect.width - 1) / characterWidth) + 1\n
            }\n
        };\n
    },\n
\n
    /**\n
     * Returns the boundaries of the character at the given position.\n
     */\n
    characterRectForPosition: function(position) {\n
        return this.rectsForRange({\n
            start:  position,\n
            end:    { row: position.row, col: position.col + 1 }\n
        })[0];\n
    },\n
\n
    /**\n
     * Returns the pixel boundaries of the given line.\n
     *\n
     * TODO: Unit test.\n
     */\n
    lineRectForRow: function(row) {\n
        return this.rectsForRange({\n
            start:  { row: row, col: 0                   },\n
            end:    { row: row, col: this._maximumWidth  }\n
        })[0];\n
    },\n
\n
    rectForPosition: function(position) {\n
        var margin = this.margin;\n
        var characterWidth = fontDimension.characterWidth;\n
        var lineHeight = fontDimension.lineHeight;\n
        return {\n
            x:      margin.left + characterWidth * position.col,\n
            y:      margin.top + lineHeight * position.row,\n
            width:  characterWidth,\n
            height: lineHeight\n
        };\n
    },\n
\n
    /**\n
     * Returns the 1, 2, or 3 rectangles that make up the given range.\n
     */\n
    rectsForRange: function(range) {\n
        var characterWidth = fontDimension.characterWidth;\n
        var lineHeight = fontDimension.lineHeight;\n
        var maximumWidth = this._maximumWidth;\n
        var margin = this.margin;\n
\n
        var start = range.start, end = range.end;\n
        var startRow = start.row, startColumn = start.col;\n
        var endRow = end.row, endColumn = end.col;\n
\n
        if (startRow === endRow) {\n
            // The simple rectangle case.\n
            return [\n
                {\n
                    x:      margin.left + characterWidth * startColumn,\n
                    y:      margin.top + lineHeight * startRow,\n
                    width:  characterWidth * (endColumn - startColumn),\n
                    height: lineHeight\n
                }\n
            ];\n
        }\n
\n
        var rects = [];\n
\n
        // Top line\n
        var middleStartRow;\n
        if (startColumn === 0) {\n
            middleStartRow = startRow;\n
        } else {\n
            middleStartRow = startRow + 1;\n
            rects.push({\n
                x:      margin.left + characterWidth * startColumn,\n
                y:      margin.top + lineHeight * startRow,\n
                width:  99999, // < Number.MAX_VALUE is not working here.\n
                height: lineHeight\n
            });\n
        }\n
\n
        // Bottom line\n
        var middleEndRow;\n
        if (endColumn === 0) {\n
            middleEndRow = endRow - 1;\n
        } else if (endColumn === maximumWidth) {\n
            middleEndRow = endRow;\n
        } else {\n
            middleEndRow = endRow - 1;\n
            rects.push({\n
                x:      margin.left,\n
                y:      margin.top + lineHeight * endRow,\n
                width:  characterWidth * endColumn,\n
                height: lineHeight\n
            });\n
        }\n
\n
        // Middle area\n
        rects.push({\n
            x:      margin.left,\n
            y:      margin.top + lineHeight * middleStartRow,\n
            width:  99999, // < Number.MAX_VALUE is not working here.\n
            height: lineHeight * (middleEndRow - middleStartRow + 1)\n
        });\n
\n
        return rects;\n
    },\n
\n
    textStorageChanged: function(oldRange, newRange) {\n
        this._recomputeLayoutForRanges(oldRange, newRange);\n
    },\n
\n
    /**\n
     * Updates the text lines in the given range to correspond to the current\n
     * state of the syntax highlighter. Does not actually run the syntax\n
     * highlighters.\n
     */\n
    updateTextRows: function(startRow, endRow) {\n
        var textLines = this.textLines;\n
        var attrs = this.syntaxManager.getAttrsForRows(startRow, endRow);\n
        var theme = this._theme;\n
\n
        for (var i = 0; i < attrs.length; i++) {\n
            textLines[startRow + i].colors = attrs[i];\n
        }\n
    }\n
};\n
\n
Object.defineProperties(exports.LayoutManager.prototype, {\n
    size: {\n
        set: function(size) {\n
            if (size.width !== this._size.width || size.height !== this._size.height) {\n
                this.sizeChanged(size);\n
                this._size = size;\n
            }\n
        },\n
\n
        get: function() {\n
            return this._size;\n
        }\n
    },\n
\n
    textStorage: {\n
        get: function() {\n
            return this._textStorage;\n
        }\n
    }\n
})\n
\n
});\n
\n
bespin.tiki.module("text_editor:controllers/search",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var Range = require(\'rangeutils:utils/range\');\n
var console = require(\'bespin:console\').console;\n
\n
/**\n
 * @class\n
 *\n
 * Manages the Find functionality.\n
 */\n
exports.EditorSearchController = function(editor) {\n
    this.editor = editor;\n
};\n
\n
exports.EditorSearchController.prototype = {\n
\n
    /**\n
     * The editor holding the buffer object to search in.\n
     */\n
    editor: null,\n
\n
    /**\n
     * This is based on the idea from:\n
     *      http://simonwillison.net/2006/Jan/20/escape/.\n
     */\n
    _escapeString: /(\\/|\\.|\\*|\\+|\\?|\\||\\(|\\)|\\[|\\]|\\{|\\}|\\\\)/g,\n
\n
    _findMatchesInString: function(str) {\n
        var result = [];\n
        var searchRegExp = this.searchRegExp;\n
        var searchResult;\n
        var endIndex;\n
\n
        searchRegExp.lastIndex = 0;\n
\n
        while (true) {\n
            searchResult = searchRegExp.exec(str);\n
            if (searchResult === null) {\n
                break;\n
            }\n
\n
            result.push(searchResult);\n
\n
            var index = searchResult.index;\n
            searchRegExp.lastIndex = index + searchResult[0].length;\n
        }\n
\n
        return result;\n
    },\n
\n
    _makeRange: function(searchResult, row) {\n
        return {\n
            start: { row: row, col: searchResult.index },\n
            end: {\n
                row: row,\n
                col: searchResult.index + searchResult[0].length\n
            }\n
        };\n
    },\n
\n
    /**\n
     * @property{boolean}\n
     *\n
     * True if the search query is a regular expression, false if it\'s a\n
     * literal string.\n
     */\n
    isRegExp: null,\n
\n
    /**\n
     * @property{RegExp}\n
     *\n
     * The current search query as a regular expression.\n
     */\n
    searchRegExp: null,\n
\n
    /**\n
     * @property{String}\n
     *\n
     * The current search text.\n
     */\n
    searchText: null,\n
\n
    /**\n
     * Sets the search query.\n
     *\n
     * @param text     The search query to set.\n
     * @param isRegExp True if the text is a regex, false if it\'s a literal\n
     *                 string.\n
     */\n
    setSearchText: function(text, isRegExp) {\n
        var regExp;\n
        // If the search string is not a RegExp make sure to escape the\n
        if (!isRegExp) {\n
            regExp = new RegExp(text.replace(this._escapeString, \'\\\\$1\'), \'gi\');\n
        } else {\n
            regExp = new RegExp(text);\n
        }\n
        this.searchRegExp = regExp;\n
        this.isRegExp = isRegExp;\n
        this.searchText = text;\n
    },\n
\n
    /**\n
     * Finds the next occurrence of the search query.\n
     *\n
     * @param startPos       The position at which to restart the search.\n
     * @param allowFromStart True if the search is allowed to wrap.\n
     */\n
    findNext: function(startPos, allowFromStart) {\n
        var searchRegExp = this.searchRegExp;\n
        if (util.none(searchRegExp)) {\n
            return null;\n
        }\n
\n
        startPos = startPos || this.editor.textView.getSelectedRange().end;\n
\n
        var lines = this.editor.layoutManager.textStorage.lines;\n
        var searchResult;\n
\n
        searchRegExp.lastIndex = startPos.col;\n
\n
        var row;\n
        for (row = startPos.row; row < lines.length; row++) {\n
            searchResult = searchRegExp.exec(lines[row]);\n
            if (!util.none(searchResult)) {\n
                return this._makeRange(searchResult, row);\n
            }\n
        }\n
\n
        if (!allowFromStart) {\n
            return null;\n
        }\n
\n
        // Wrap around.\n
        for (row = 0; row <= startPos.row; row++) {\n
            searchResult = searchRegExp.exec(lines[row]);\n
            if (!util.none(searchResult)) {\n
                return this._makeRange(searchResult, row);\n
            }\n
        }\n
\n
        return null;\n
    },\n
\n
    /**\n
     * Finds the previous occurrence of the search query.\n
     *\n
     * @param startPos       The position at which to restart the search.\n
     * @param allowFromStart True if the search is allowed to wrap.\n
     */\n
    findPrevious: function(startPos, allowFromEnd) {\n
        var searchRegExp = this.searchRegExp;\n
        if (util.none(searchRegExp)) {\n
            return null;\n
        }\n
\n
        startPos = startPos || this.editor.textView.getSelectedRange().start;\n
\n
        var lines = this.editor.buffer.layoutManager.textStorage.lines;\n
        var searchResults;\n
\n
        // Treat the first line specially.\n
        var firstLine = lines[startPos.row].substring(0, startPos.col);\n
        searchResults = this._findMatchesInString(firstLine);\n
\n
        if (searchResults.length !== 0) {\n
            return this._makeRange(searchResults[searchResults.length - 1],\n
                                                                startPos.row);\n
        }\n
\n
        // Loop over all other lines.\n
        var row;\n
        for (row = startPos.row - 1; row !== -1; row--) {\n
            searchResults = this._findMatchesInString(lines[row]);\n
            if (searchResults.length !== 0) {\n
                return this._makeRange(searchResults[searchResults.length - 1],\n
                                                                        row);\n
            }\n
        }\n
\n
        if (!allowFromEnd) {\n
            return null;\n
        }\n
\n
        // Wrap around.\n
        for (row = lines.length - 1; row >= startPos.row; row--) {\n
            searchResults = this._findMatchesInString(lines[row]);\n
            if (searchResults.length !== 0) {\n
                return this._makeRange(searchResults[searchResults.length - 1],\n
                                                                        row);\n
            }\n
        }\n
\n
        return null;\n
    }\n
};\n
\n
\n
});\n
\n
bespin.tiki.module("text_editor:controllers/undo",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var console = require(\'bespin:console\').console;\n
var env = require(\'environment\').env;\n
\n
/**\n
 * @class\n
 *\n
 * The editor undo controller is a delegate of the text view that groups\n
 * changes into patches and saves them with the undo manager.\n
 *\n
 * This object does not assume that it has exclusive write access to the text\n
 * storage object, and as such it tries to maintain sensible behavior in the\n
 * presence of direct modification to the text storage by other objects. This\n
 * is important for collaboration.\n
 */\n
exports.EditorUndoController = function(editor) {\n
    this.editor = editor;\n
    var textView = this.textView = editor.textView;\n
\n
    textView.beganChangeGroup.add(function(sender, selection) {\n
        this._beginTransaction();\n
        this._record.selectionBefore = selection;\n
    }.bind(this));\n
\n
    textView.endedChangeGroup.add(function(sender, selection) {\n
        this._record.selectionAfter = selection;\n
        this._endTransaction();\n
    }.bind(this));\n
\n
    textView.replacedCharacters.add(function(sender, oldRange, characters) {\n
        if (!this._inTransaction) {\n
            throw new Error(\'UndoController.textViewReplacedCharacters()\' +\n
                \' called outside a transaction\');\n
        }\n
\n
        this._record.patches.push({\n
            oldCharacters:  this._deletedCharacters,\n
            oldRange:       oldRange,\n
            newCharacters:  characters,\n
            newRange:       this.editor.layoutManager.textStorage.\n
                            resultingRangeForReplacement(oldRange,\n
                            characters.split(\'\\n\'))\n
        });\n
\n
        this._deletedCharacters = null;\n
    }.bind(this));\n
\n
    textView.willReplaceRange.add(function(sender, oldRange) {\n
        if (!this._inTransaction) {\n
            throw new Error(\'UndoController.textViewWillReplaceRange() called\' +\n
                \' outside a transaction\');\n
        }\n
\n
        this._deletedCharacters = this.editor.layoutManager.textStorage.\n
                            getCharacters(oldRange);\n
    }.bind(this));\n
};\n
\n
exports.EditorUndoController.prototype = {\n
    _inTransaction: false,\n
    _record: null,\n
\n
    /**\n
     * @property{TextView}\n
     *\n
     * The view object to forward changes to. This property must be set upon\n
     * instantiating the undo controller.\n
     */\n
    textView: null,\n
\n
    _beginTransaction: function() {\n
        if (this._inTransaction) {\n
            console.trace();\n
            throw new Error(\'UndoController._beginTransaction() called with a \' +\n
                \'transaction already in place\');\n
        }\n
\n
        this._inTransaction = true;\n
        this._record = { patches: [] };\n
    },\n
\n
    _endTransaction: function() {\n
        if (!this._inTransaction) {\n
            throw new Error(\'UndoController._endTransaction() called without a \' +\n
                \'transaction in place\');\n
        }\n
\n
        this.editor.buffer.undoManager.registerUndo(this, this._record);\n
        this._record = null;\n
\n
        this._inTransaction = false;\n
    },\n
\n
    _tryApplyingPatches: function(patches) {\n
        var textStorage = this.editor.layoutManager.textStorage;\n
        patches.forEach(function(patch) {\n
            textStorage.replaceCharacters(patch.oldRange, patch.newCharacters);\n
        });\n
        return true;\n
    },\n
\n
    _undoOrRedo: function(patches, selection) {\n
        if (this._inTransaction) {\n
            // Can\'t think of any reason why this should be supported, and it\'s\n
            // often an indication that someone forgot an endTransaction()\n
            // call somewhere...\n
            throw new Error(\'UndoController._undoOrRedo() called while in a transaction\');\n
        }\n
\n
        if (!this._tryApplyingPatches(patches)) {\n
            return false;\n
        }\n
\n
        this.textView.setSelection(selection, true);\n
        return true;\n
    },\n
\n
    redo: function(record) {\n
        var patches = record.patches.concat();\n
        patches.reverse();\n
        return this._undoOrRedo(patches, record.selectionAfter);\n
    },\n
\n
    undo: function(record) {\n
        return this._undoOrRedo(record.patches.map(function(patch) {\n
                return {\n
                    oldCharacters:  patch.newCharacters,\n
                    oldRange:       patch.newRange,\n
                    newCharacters:  patch.oldCharacters,\n
                    newRange:       patch.oldRange\n
                };\n
            }), record.selectionBefore);\n
    }\n
};\n
\n
exports.undoManagerCommand = function(args, request) {\n
    var editor = env.editor;\n
    editor.buffer.undoManager[request.commandExt.name]()\n
};\n
\n
});\n
\n
bespin.tiki.module("text_editor:commands/scrolling",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
 \n
var env = require(\'environment\').env;\n
\n
// Scrolling commands.\n
\n
/**\n
 * Scrolls to the start of the document.\n
 */\n
exports.scrollDocStart = function(args, request) {\n
    env.view.scrollToPosition({ col: 0, row: 0 });\n
};\n
\n
/**\n
 * Scrolls to the end of the document.\n
 */\n
exports.scrollDocEnd = function(args, request) {\n
    env.view.scrollToPosition(env.model.range.end);\n
};\n
\n
/**\n
 * Scrolls down by one screenful of text.\n
 */\n
exports.scrollPageDown = function(args, request) {\n
    env.view.scrollPageDown();\n
};\n
\n
/**\n
 * Scrolls up by one screenful of text.\n
 */\n
exports.scrollPageUp = function(args, request) {\n
    env.view.scrollPageUp();\n
};\n
\n
\n
});\n
\n
bespin.tiki.module("text_editor:commands/editing",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var settings = require(\'settings\').settings;\n
var env = require(\'environment\').env;\n
var m_range = require(\'rangeutils:utils/range\');\n
\n
/*\n
 * Commands that delete text.\n
 */\n
\n
/**\n
 * Deletes the selection or the previous character, if the selection is an\n
 * insertion point.\n
 */\n
exports.backspace = function(args, request) {\n
    var view = env.view;\n
    view.performBackspaceOrDelete(true);\n
};\n
\n
/**\n
 * Deletes the selection or the next character, if the selection is an\n
 * insertion point.\n
 */\n
exports.deleteCommand = function(args, request) {\n
    var view = env.view;\n
    view.performBackspaceOrDelete(false);\n
};\n
\n
/**\n
 * Deletes all lines that are partially or fully selected, and position the\n
 * insertion point at the end of the deleted range.\n
 */\n
exports.deleteLines = function(args, request) {\n
    if (env.model.readOnly) {\n
        return;\n
    }\n
\n
    // In the case of just one line, do nothing.\n
    if (env.model.lines.length == 1) {\n
        return;\n
    }\n
\n
    var view = env.view;\n
    view.groupChanges(function() {\n
        var range = view.getSelectedRange();\n
        var lines = env.model.lines;\n
        var lastLine = lines.length - 1;\n
        var startPos, endPos;\n
\n
        // Last row gets special treatment.\n
        if (range.start.row == lastLine) {\n
            startPos = { col: lines[lastLine - 1].length, row: lastLine - 1 };\n
        } else {\n
            startPos = { col: 0, row: range.start.row };\n
        }\n
\n
        // Last row gets special treatment.\n
        if (range.end.row == lastLine) {\n
            endPos = { col: lines[lastLine].length, row: lastLine};\n
        } else {\n
            endPos = { col: 0, row: range.end.row + 1 };\n
        }\n
\n
        view.replaceCharacters({\n
            start: startPos,\n
            end:   endPos\n
        }, \'\');\n
\n
        view.moveCursorTo(startPos);\n
    });\n
};\n
\n
/*\n
 * Commands that insert text.\n
 */\n
\n
// Inserts a newline, and copies the spaces at the beginning of the current row\n
// to autoindent.\n
var newline = function(model, view) {\n
    var selection = view.getSelectedRange();\n
    var position = selection.start;\n
    var row = position.row, col = position.col;\n
\n
    var lines = model.lines;\n
    var prefix = lines[row].substring(0, col);\n
\n
    var spaces = /^\\s*/.exec(prefix);\n
    view.insertText(\'\\n\' + spaces);\n
};\n
\n
/**\n
 * Replaces the selection with the given text and updates the selection\n
 * boundaries appropriately.\n
 */\n
exports.insertText = function(args, request) {\n
    var view = env.view;\n
    var text = args.text;\n
    view.insertText(text);\n
};\n
\n
/**\n
 * Inserts a newline at the insertion point.\n
 */\n
exports.newline = function(args, request) {\n
    var model = env.model, view = env.view;\n
    newline(model, view);\n
};\n
\n
/**\n
 * Join the following line with the current one. Removes trailing whitespaces.\n
 */\n
exports.joinLines = function(args, request) {\n
    var model = env.model;\n
    if (model.readOnly) {\n
        return;\n
    }\n
\n
    var view = env.view;\n
    var selection = view.getSelectedRange();\n
    var lines = model.lines;\n
    var row = selection.end.row;\n
\n
    // Last line selected, which can\'t get joined.\n
    if (lines.length == row) {\n
        return;\n
    }\n
\n
    view.groupChanges(function() {\n
        var endCol = lines[row].length;\n
\n
        view.replaceCharacters({\n
            start: {\n
                col: endCol,\n
                row: row\n
            },\n
            end: {\n
                col: /^\\s*/.exec(lines[row + 1])[0].length,\n
                row: row + 1\n
        }}, \'\');\n
    });\n
};\n
\n
/**\n
 * Creates a new, empty line below the current one, and places the insertion\n
 * point there.\n
 */\n
exports.openLine = function(args, request) {\n
    if (env.model.readOnly) {\n
        return;\n
    }\n
\n
    var model = env.model, view = env.view;\n
\n
    var selection = view.getSelectedRange();\n
    var row = selection.end.row;\n
    var lines = model.lines;\n
    view.moveCursorTo({ row: row, col: lines[row].length });\n
\n
    newline(model, view);\n
};\n
\n
/**\n
 * Inserts a new tab. This is smart about the current inserted whitespaces and\n
 * the current position of the cursor. If some text is selected, the selected\n
 * lines will be indented by tabstop spaces.\n
 */\n
exports.tab = function(args, request) {\n
    var view = env.view;\n
\n
    view.groupChanges(function() {\n
        var tabstop = settings.get(\'tabstop\');\n
        var selection = view.getSelectedRange();\n
        var str = \'\';\n
\n
        if (m_range.isZeroLength(selection)){\n
            var line = env.model.lines[selection.start.row];\n
            var trailspaces = line.substring(selection.start.col).\n
                                            match(/^\\s*/)[0].length;\n
            var count = tabstop - (selection.start.col + trailspaces) % tabstop;\n
\n
            for (var i = 0; i < count; i++) {\n
                str += \' \';\n
            }\n
\n
            view.replaceCharacters({\n
                 start: selection.start,\n
                 end:   selection.start\n
             }, str);\n
\n
            view.moveCursorTo({\n
                col: selection.start.col + count + trailspaces,\n
                row: selection.end.row\n
            });\n
        } else {\n
            for (var i = 0; i < tabstop; i++) {\n
                str += \' \';\n
            }\n
\n
            var startCol;\n
            var row = selection.start.row - 1;\n
            while (row++ < selection.end.row) {\n
                startCol = row == selection.start.row ? selection.start.col : 0;\n
\n
                view.replaceCharacters({\n
                    start: { row:  row, col: startCol},\n
                    end:   { row:  row, col: startCol}\n
                }, str);\n
            }\n
\n
            view.setSelection({\n
                start: selection.start,\n
                end: {\n
                    col: selection.end.col + tabstop,\n
                    row:  selection.end.row\n
                }\n
            });\n
        }\n
    }.bind(this));\n
};\n
\n
/**\n
 * Removes a tab of whitespaces. If there is no selection, whitespaces in front\n
 * of the cursor will be removed. The number of removed whitespaces depends on\n
 * the setting tabstop and the current cursor position. If there is a selection,\n
 * then the selected lines are unindented by tabstop spaces.\n
 */\n
exports.untab = function(args, request) {\n
    var view = env.view;\n
\n
    view.groupChanges(function() {\n
        var tabstop = settings.get(\'tabstop\');\n
        var selection = view.getSelectedRange();\n
        var lines = env.model.lines;\n
        var count = 0;\n
\n
        if (m_range.isZeroLength(selection)){\n
            count = Math.min(\n
                lines[selection.start.row].substring(0, selection.start.col).\n
                                                    match(/\\s*$/)[0].length,\n
                (selection.start.col - tabstop) % tabstop || tabstop);\n
\n
            view.replaceCharacters({\n
                start: {\n
                    col: selection.start.col - count,\n
                    row: selection.start.row\n
                },\n
                end: selection.start\n
            }, \'\');\n
\n
            view.moveCursorTo({\n
                row:  selection.start.row,\n
                col: selection.end.col - count\n
            });\n
        } else {\n
            var startCol;\n
            var row = selection.start.row - 1;\n
            while (row++ < selection.end.row) {\n
                startCol = row == selection.start.row ? selection.start.col : 0;\n
\n
                count = Math.min(\n
                    lines[row].substring(startCol).match(/^\\s*/)[0].length,\n
                    tabstop);\n
\n
                view.replaceCharacters({\n
                     start: { row: row, col: startCol},\n
                     end:   { row: row, col: startCol + count}\n
                 }, \'\');\n
            }\n
\n
             view.setSelection({\n
                 start: { row:  selection.start.row, col: selection.start.col},\n
                 end:   { row:  selection.end.row, col: selection.end.col - count}\n
             });\n
       }\n
    }.bind(this));\n
};\n
\n
});\n
\n
bespin.tiki.module("text_editor:commands/editor",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var settings = require(\'settings\').settings;\n
var env = require(\'environment\').env;\n
\n
exports.findNextCommand = function(args, request) {\n
    var view = env.view, search = view.editor.searchController;\n
    var sel = view.getSelectedRange();\n
    var match = search.findNext(sel.end, true);\n
    if (match) {\n
        view.setSelection(match, true);\n
        view.focus();\n
    }\n
};\n
\n
exports.findPrevCommand = function(args, request) {\n
    var view = env.view, search = view.editor.searchController;\n
    var sel = view.getSelectedRange();\n
    var match = search.findPrevious(sel.start, true);\n
    if (match) {\n
        view.setSelection(match, true);\n
        view.focus();\n
    }\n
};\n
\n
/**\n
 * Utility to allow us to alter the current selection\n
 * TODO: If the selection is empty, broaden the scope to the whole file?\n
 */\n
var withSelection = function(action) {\n
    var view = env.view;\n
    var selection = view.getSelectedCharacters();\n
\n
    var replacement = action(selection);\n
\n
    var range = view.getSelectedRange();\n
    var model = env.model;\n
    model.replaceCharacters(range, replacement);\n
};\n
\n
/**\n
 * \'replace\' command\n
 */\n
exports.replaceCommand = function(args, request) {\n
    withSelection(function(selected) {\n
        return selected.replace(args.search + \'/g\', args.replace);\n
    });\n
};\n
\n
/**\n
 * \'entab\' command\n
 */\n
exports.entabCommand = function(args, request) {\n
    tabstop = settings.get(\'tabstop\');\n
    withSelection(function(selected) {\n
        return selected.replace(\' {\' + tabstop + \'}\', \'\\t\');\n
    });\n
};\n
\n
/**\n
 * \'detab\' command\n
 */\n
exports.detabCommand = function(args, request) {\n
    tabstop = settings.get(\'tabstop\');\n
    withSelection(function(selected) {\n
        return selected.replace(\'\\t\', new Array(tabstop + 1).join(\' \'));\n
    });\n
};\n
\n
/**\n
 * \'trim\' command\n
 */\n
exports.trimCommand = function(args, request) {\n
    withSelection(function(selected) {\n
        var lines = selected.split(\'\\n\');\n
        lines = lines.map(function(line) {\n
            if (args.side === \'left\' || args.side === \'both\') {\n
                line = line.replace(/^\\s+/, \'\');\n
            }\n
            if (args.side === \'right\' || args.side === \'both\') {\n
                line = line.replace(/\\s+$/, \'\');\n
            }\n
            return line;\n
        });\n
        return lines.join(\'\\n\');\n
    });\n
};\n
\n
/**\n
 * \'uc\' command\n
 */\n
exports.ucCommand = function(args, request) {\n
    withSelection(function(selected) {\n
        return selected.toUpperCase();\n
    });\n
};\n
\n
/**\n
 * \'lc\' command\n
 */\n
exports.lcCommand = function(args, request) {\n
    withSelection(function(selected) {\n
        return selected.toLowerCase();\n
    });\n
};\n
\n
});\n
\n
bespin.tiki.module("text_editor:commands/movement",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Range = require(\'rangeutils:utils/range\');\n
var env = require(\'environment\').env;\n
\n
// TODO: These should not be using private APIs of the view.\n
\n
//\n
// Simple movement.\n
//\n
// These simply delegate to the text view, because they take the text view\'s\n
// private virtual selection into account.\n
//\n
\n
exports.moveDown = function(args, request) {\n
    var view = env.view;\n
    view.moveDown();\n
};\n
\n
exports.moveLeft = function(args, request) {\n
    var view = env.view;\n
    view.moveLeft();\n
};\n
\n
exports.moveRight = function(args, request) {\n
    var view = env.view;\n
    view.moveRight();\n
};\n
\n
exports.moveUp = function(args, request) {\n
    var view = env.view;\n
    view.moveUp();\n
};\n
\n
//\n
// Simple selection.\n
//\n
\n
exports.selectDown = function(args, request) {\n
    var view = env.view;\n
    view.selectDown();\n
};\n
\n
exports.selectLeft = function(args, request) {\n
    var view = env.view;\n
    view.selectLeft();\n
};\n
\n
exports.selectRight = function(args, request) {\n
    var view = env.view;\n
    view.selectRight();\n
};\n
\n
exports.selectUp = function(args, request) {\n
    var view = env.view;\n
    view.selectUp();\n
};\n
\n
//\n
// Move or select to the end of the line or document.\n
//\n
\n
var moveOrSelectEnd = function(shift, inLine) {\n
    var view = env.view, model = env.model;\n
    var lines = model.lines;\n
    var selectedRange = view.getSelectedRange(true);\n
    var row = inLine ? selectedRange.end.row : lines.length - 1;\n
    view.moveCursorTo({ row: row, col: lines[row].length }, shift);\n
};\n
\n
exports.moveLineEnd = function(args, request) {\n
    moveOrSelectEnd(false, true);\n
};\n
\n
exports.selectLineEnd = function(args, request) {\n
    moveOrSelectEnd(true, true);\n
};\n
\n
exports.moveDocEnd = function(args, request) {\n
    moveOrSelectEnd(false, false);\n
};\n
\n
exports.selectDocEnd = function(args, request) {\n
    moveOrSelectEnd(true, false);\n
};\n
\n
//\n
// Move or select to the beginning of the line or document.\n
//\n
\n
var moveOrSelectStart = function(shift, inLine) {\n
    var view = env.view;\n
    var range = view.getSelectedRange(true);\n
    var row = inLine ? range.end.row : 0;\n
    var position = { row: row, col: 0 };\n
    view.moveCursorTo(position, shift);\n
};\n
\n
exports.moveLineStart = function (args, request) {\n
    moveOrSelectStart(false, true);\n
};\n
\n
exports.selectLineStart = function(args, request) {\n
    moveOrSelectStart(true, true);\n
};\n
\n
exports.moveDocStart = function(args, request) {\n
    moveOrSelectStart(false, false);\n
};\n
\n
exports.selectDocStart = function(args, request) {\n
    moveOrSelectStart(true, false);\n
};\n
\n
//\n
// Move or select to the next or previous word.\n
//\n
\n
var seekNextStop = function(view, text, col, dir, rowChanged) {\n
    var isDelim;\n
    var countDelim = 0;\n
    var wasOverNonDelim = false;\n
\n
    if (dir < 0) {\n
        col--;\n
        if (rowChanged) {\n
            countDelim = 1;\n
        }\n
    }\n
\n
    while (col < text.length && col > -1) {\n
        isDelim = view.isDelimiter(text[col]);\n
        if (isDelim) {\n
            countDelim++;\n
        } else {\n
            wasOverNonDelim = true;\n
        }\n
        if ((isDelim || countDelim > 1) && wasOverNonDelim) {\n
            break;\n
        }\n
        col += dir;\n
    }\n
\n
    if (dir < 0) {\n
        col++;\n
    }\n
\n
    return col;\n
};\n
\n
var moveOrSelectNextWord = function(shiftDown) {\n
    var view = env.view, model = env.model;\n
    var lines = model.lines;\n
\n
    var selectedRange = view.getSelectedRange(true);\n
    var end = selectedRange.end;\n
    var row = end.row, col = end.col;\n
\n
    var currentLine = lines[row];\n
    var changedRow = false;\n
\n
    if (col >= currentLine.length) {\n
        row++;\n
        changedRow = true;\n
        if (row < lines.length) {\n
            col = 0;\n
            currentLine = lines[row];\n
        } else {\n
            currentLine = \'\';\n
        }\n
    }\n
\n
    col = seekNextStop(view, currentLine, col, 1, changedRow);\n
\n
    view.moveCursorTo({ row: row, col: col }, shiftDown);\n
};\n
\n
var moveOrSelectPreviousWord = function(shiftDown) {\n
    var view = env.view, model = env.model;\n
\n
    var lines = model.lines;\n
    var selectedRange = view.getSelectedRange(true);\n
    var end = selectedRange.end;\n
    var row = end.row, col = end.col;\n
\n
    var currentLine = lines[row];\n
    var changedRow = false;\n
\n
    if (col > currentLine.length) {\n
        col = currentLine.length;\n
    } else if (col == 0) {\n
        row--;\n
        changedRow = true;\n
        if (row > -1) {\n
            currentLine = lines[row];\n
            col = currentLine.length;\n
        } else {\n
            currentLine = \'\';\n
        }\n
    }\n
\n
    col = seekNextStop(view, currentLine, col, -1, changedRow);\n
\n
    view.moveCursorTo({ row: row, col: col }, shiftDown);\n
};\n
\n
exports.moveNextWord = function(args, request) {\n
    moveOrSelectNextWord(false);\n
};\n
\n
exports.selectNextWord = function(args, request) {\n
    moveOrSelectNextWord(true);\n
};\n
\n
exports.movePreviousWord = function(args, request) {\n
    moveOrSelectPreviousWord(false);\n
};\n
\n
exports.selectPreviousWord = function(args, request) {\n
    moveOrSelectPreviousWord(true);\n
};\n
\n
//\n
// Miscellaneous.\n
//\n
\n
/**\n
 * Selects all characters in the buffer.\n
 */\n
exports.selectAll = function(args, request) {\n
    var view = env.view;\n
    view.selectAll();\n
};\n
\n
});\n
\n
bespin.tiki.module("text_editor:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::less", {\n
    name: "less",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("less:index",function(require,exports,module) {\n
"define metadata";\n
({\n
    "description": "Leaner CSS",\n
    "url": "http://lesscss.org",\n
    "dependencies": {},\n
    "provides": [],\n
    "keywords": ["css", "parser", "lesscss", "browser"],\n
    "author": "Alexis Sellier <self@cloudhead.net>",\n
    "contributors": [],\n
    "version": "1.0.11"\n
});\n
"end";\n
\n
// --- Begin less.js ---\n
\n
//\n
// LESS - Leaner CSS v1.0.11\n
// http://lesscss.org\n
// \n
// Copyright (c) 2010, Alexis Sellier\n
// Licensed under the MIT license.\n
//\n
\n
// Tell the LESS library that this is a dist build. Important when using the\n
// dist build as a one-file CommonJS package.\n
var __LESS_DIST__ = true;\n
\n
// ecma-5.js\n
//\n
// -- kriskowal Kris Kowal Copyright (C) 2009-2010 MIT License\n
// -- tlrobinson Tom Robinson\n
// dantman Daniel Friesen\n
\n
//\n
// Array\n
//\n
if (!Array.isArray) {\n
    Array.isArray = function(obj) {\n
        return Object.prototype.toString.call(obj) === "[object Array]" ||\n
               (obj instanceof Array);\n
    };\n
}\n
if (!Array.prototype.forEach) {\n
    Array.prototype.forEach =  function(block, thisObject) {\n
        var len = this.length >>> 0;\n
        for (var i = 0; i < len; i++) {\n
            if (i in this) {\n
                block.call(thisObject, this[i], i, this);\n
            }\n
        }\n
    };\n
}\n
if (!Array.prototype.map) {\n
    Array.prototype.map = function(fun /*, thisp*/) {\n
        var len = this.length >>> 0;\n
        var res = new Array(len);\n
        var thisp = arguments[1];\n
\n
        for (var i = 0; i < len; i++) {\n
            if (i in this) {\n
                res[i] = fun.call(thisp, this[i], i, this);\n
            }\n
        }\n
        return res;\n
    };\n
}\n
if (!Array.prototype.filter) {\n
    Array.prototype.filter = function (block /*, thisp */) {\n
        var values = [];\n
        var thisp = arguments[1];\n
        for (var i = 0; i < this.length; i++) {\n
            if (block.call(thisp, this[i])) {\n
                values.push(this[i]);\n
            }\n
        }\n
        return values;\n
    };\n
}\n
if (!Array.prototype.reduce) {\n
    Array.prototype.reduce = function(fun /*, initial*/) {\n
        var len = this.length >>> 0;\n
        var i = 0;\n
\n
        // no value to return if no initial value and an empty array\n
        if (len === 0 && arguments.length === 1) throw new TypeError();\n
\n
        if (arguments.length >= 2) {\n
            var rv = arguments[1];\n
        } else {\n
            do {\n
                if (i in this) {\n
                    rv = this[i++];\n
                    break;\n
                }\n
                // if array contains no values, no initial value to return\n
                if (++i >= len) throw new TypeError();\n
            } while (true);\n
        }\n
        for (; i < len; i++) {\n
            if (i in this) {\n
                rv = fun.call(null, rv, this[i], i, this);\n
            }\n
        }\n
        return rv;\n
    };\n
}\n
if (!Array.prototype.indexOf) {\n
    Array.prototype.indexOf = function (value /*, fromIndex */ ) {\n
        var length = this.length;\n
        var i = arguments[1] || 0;\n
\n
        if (!length)     return -1;\n
        if (i >= length) return -1;\n
        if (i < 0)       i += length;\n
\n
        for (; i < length; i++) {\n
            if (!Object.prototype.hasOwnProperty.call(this, i)) { continue }\n
            if (value === this[i]) return i;\n
        }\n
        return -1;\n
    };\n
}\n
\n
//\n
// Object\n
//\n
if (!Object.keys) {\n
    Object.keys = function (object) {\n
        var keys = [];\n
        for (var name in object) {\n
            if (Object.prototype.hasOwnProperty.call(object, name)) {\n
                keys.push(name);\n
            }\n
        }\n
        return keys;\n
    };\n
}\n
\n
//\n
// String\n
//\n
if (!String.prototype.trim) {\n
    String.prototype.trim = function () {\n
        return String(this).replace(/^\\s\\s*/, \'\').replace(/\\s\\s*$/, \'\');\n
    };\n
}\n
if (typeof(require) !== \'undefined\') {\n
    var less = exports;\n
\n
    if (typeof(__LESS_DIST__) === \'undefined\') {\n
        var tree = require(\'less/tree\');\n
    } else {\n
        var tree = {};\n
    }\n
} else {\n
    var less = tree = {};\n
}\n
//\n
// less.js - parser\n
//\n
//    A relatively straight-forward recursive-descent parser.\n
//    There is no tokenization/lexing stage, the input is parsed\n
//    in one sweep.\n
//\n
//    To make the parser fast enough to run in the browser, several\n
//    optimization had to be made:\n
//\n
//    - Instead of the more commonly used technique of slicing the\n
//      input string on every match, we use global regexps (/g),\n
//      and move the `lastIndex` pointer on match, foregoing `slice()`\n
//      completely. This gives us a 3x speed-up.\n
//\n
//    - Matching on a huge input is often cause of slowdowns,\n
//      especially with the /g flag. The solution to that is to\n
//      chunkify the input: we split it by /\\n\\n/, just to be on\n
//      the safe side. The chunks are stored in the `chunks` var,\n
//      `j` holds the current chunk index, and `current` holds\n
//      the index of the current chunk in relation to `input`.\n
//      This gives us an almost 4x speed-up.\n
//\n
//    - In many cases, we don\'t need to match individual tokens;\n
//      for example, if a value doesn\'t hold any variables, operations\n
//      or dynamic references, the parser can effectively \'skip\' it,\n
//      treating it as a literal.\n
//      An example would be \'1px solid #000\' - which evaluates to itself,\n
//      we don\'t need to know what the individual components are.\n
//      The drawback, of course is that you don\'t get the benefits of\n
//      syntax-checking on the CSS. This gives us a 50% speed-up in the parser,\n
//      and a smaller speed-up in the code-gen.\n
//\n
//\n
//    Token matching is done with the `$` function, which either takes\n
//    a terminal string or regexp, or a non-terminal function to call.\n
//    It also takes care of moving all the indices forwards.\n
//\n
//\n
less.Parser = function Parser(env) {\n
    var input,       // LeSS input string\n
        i,           // current index in `input`\n
        j,           // current chunk\n
        furthest,    // furthest index the parser has gone to\n
        chunks,      // chunkified input\n
        current,     // index of current chunk, in `input`\n
        inputLength,\n
        parser;\n
\n
    var that = this;\n
\n
    // This function is called after all files\n
    // have been imported through `@import`.\n
    var finish = function () {};\n
\n
    var imports = this.imports = {\n
        paths: env && env.paths || [],  // Search paths, when importing\n
        queue: [],                      // Files which haven\'t been imported yet\n
        files: {},                      // Holds the imported parse trees\n
        push: function (path, callback) {\n
            var that = this;\n
            this.queue.push(path);\n
\n
            //\n
            // Import a file asynchronously\n
            //\n
            less.Parser.importer(path, this.paths, function (root) {\n
                that.queue.splice(that.queue.indexOf(path), 1); // Remove the path from the queue\n
                that.files[path] = root;                        // Store the root\n
\n
                callback(root);\n
\n
                if (that.queue.length === 0) { finish() }       // Call `finish` if we\'re done importing\n
            });\n
        }\n
    };\n
\n
    //\n
    // Parse from a token, regexp or string, and move forward if match\n
    //\n
    function $(tok) {\n
        var match, args, length, c, index, endIndex;\n
\n
        //\n
        // Non-terminal\n
        //\n
        if (tok instanceof Function) {\n
            return tok.call(parser.parsers);\n
        //\n
        // Terminal\n
        //\n
        //     Either match a single character in the input,\n
        //     or match a regexp in the current chunk (chunk[j]).\n
        //\n
        } else if (typeof(tok) === \'string\') {\n
            match = input.charAt(i) === tok ? tok : null;\n
            length = 1;\n
\n
        //  1. We move to the next chunk, if necessary.\n
        //  2. Set the `lastIndex` to be relative\n
        //     to the current chunk, and try to match in it.\n
        //  3. Make sure we matched at `index`. Because we use\n
        //     the /g flag, the match could be anywhere in the\n
        //     chunk. We have to make sure it\'s at our previous\n
        //     index, which we stored in [2].\n
        //\n
        } else {\n
            if (i >= current + chunks[j].length &&\n
                j < chunks.length - 1) { // 1.\n
                current += chunks[j++].length;\n
            }\n
            tok.lastIndex = index =  i - current; // 2.\n
            match = tok.exec(chunks[j]);\n
\n
            if (match) {\n
                length = match[0].length;\n
                if (tok.lastIndex - length !== index) { return } // 3.\n
            }\n
        }\n
\n
        // The match is confirmed, add the match length to `i`,\n
        // and consume any extra white-space characters (\' \' || \'\\n\')\n
        // which come after that. The reason for this is that LeSS\'s\n
        // grammar is mostly white-space insensitive.\n
        //\n
        if (match) {\n
            i += length;\n
            endIndex = current + chunks[j].length;\n
\n
            while (i <= endIndex) {\n
                c = input.charCodeAt(i);\n
                if (! (c === 32 || c === 10 || c === 9)) { break }\n
                i++;\n
            }\n
\n
            if(typeof(match) === \'string\') {\n
                return match;\n
            } else {\n
                return match.length === 1 ? match[0] : match;\n
            }\n
        }\n
    }\n
\n
    // Same as $(), but don\'t change the state of the parser,\n
    // just return the match.\n
    function peek(tok) {\n
        var match;\n
\n
        if (typeof(tok) === \'string\') {\n
            return input.charAt(i) === tok;\n
        } else {\n
            tok.lastIndex = i;\n
\n
            if ((match = tok.exec(input)) &&\n
               (tok.lastIndex - match[0].length === i)) {\n
                return match;\n
            }\n
        }\n
    }\n
\n
    this.env = env || {};\n
\n
    // The optimization level dictates the thoroughness of the parser,\n
    // the lower the number, the less nodes it will create in the tree.\n
    // This could matter for debugging, or if you want to access\n
    // the individual nodes in the tree.\n
    this.optimization = (\'optimization\' in this.env) ? this.env.optimization : 1;\n
\n
    //\n
    // The Parser\n
    //\n
    return parser = {\n
\n
        imports: imports,\n
        //\n
        // Parse an input string into an abstract syntax tree,\n
        // call `callback` when done.\n
        //\n
        parse: function (str, callback) {\n
            var root, start, end, zone, line, lines, buff = [], c, error = null;\n
\n
            i = j = current = furthest = 0;\n
            chunks = [];\n
            input = str.replace(/\\r\\n/g, \'\\n\');\n
\n
            // Split the input into chunks,\n
            // delimited by /\\n\\n/ and \n
            // removing comments (see rationale above),\n
            // depending on the level of optimization.\n
            if (that.optimization > 0) {\n
                input = input.replace(/\\/\\*(?:[^*]|\\*+[^\\/*])*\\*+\\//g, function (comment) {\n
                    return that.optimization > 1 ? \'\' : comment.replace(/\\n(\\s*\\n)+/g, \'\\n\');\n
                });\n
                chunks = input.split(/^(?=\\n)/mg);\n
            } else {\n
                chunks = [input];\n
            }\n
            inputLength = input.length;\n
\n
            // Start with the primary rule.\n
            // The whole syntax tree is held under a Ruleset node,\n
            // with the `root` property set to true, so no `{}` are\n
            // output. The callback is called when the input is parsed.\n
            root = new(tree.Ruleset)([], $(this.parsers.primary));\n
            root.root = true;\n
\n
            root.toCSS = (function (toCSS) {\n
                var line, lines, column;\n
\n
                return function () {\n
                    try {\n
                        return toCSS.call(this);\n
                    } catch (e) {\n
                        lines = input.split(\'\\n\');\n
                        line = (input.slice(0, e.index).match(/\\n/g) || "").length + 1;\n
                        for (var n = e.index, column = -1;\n
                                 n >= 0 && input.charAt(n) !== \'\\n\';\n
                                 n--) { column++ }\n
\n
                        throw {\n
                            name: "NameError",\n
                            message: e.message,\n
                            line: line,\n
                            column: column,\n
                            extract: [\n
                                lines[line - 2],\n
                                lines[line - 1],\n
                                lines[line]\n
                            ]\n
                        };\n
                    }\n
                };\n
            })(root.toCSS);\n
\n
            // If `i` is smaller than the `input.length - 1`,\n
            // it means the parser wasn\'t able to parse the whole\n
            // string, so we\'ve got a parsing error.\n
            //\n
            // We try to extract a \\n delimited string,\n
            // showing the line where the parse error occured.\n
            // We split it up into two parts (the part which parsed,\n
            // and the part which didn\'t), so we can color them differently.\n
            if (i < input.length - 1) {\n
                i = furthest;\n
                lines = input.split(\'\\n\');\n
                line = (input.slice(0, i).match(/\\n/g) || "").length + 1;\n
\n
                for (var n = i, column = -1; n >= 0 && input.charAt(n) !== \'\\n\'; n--) { column++ }\n
\n
                error = {\n
                    name: "ParseError",\n
                    message: "Syntax Error on line " + line,\n
                    filename: env.filename,\n
                    line: line,\n
                    column: column,\n
                    extract: [\n
                        lines[line - 2],\n
                        lines[line - 1],\n
                        lines[line]\n
                    ]\n
                };\n
            }\n
\n
            if (this.imports.queue.length > 0) {\n
                finish = function () { callback(error, root) };\n
            } else {\n
                callback(error, root);\n
            }\n
        },\n
\n
        //\n
        // Here in, the parsing rules/functions\n
        //\n
        // The basic structure of the syntax tree generated is as follows:\n
        //\n
        //   Ruleset ->  Rule -> Value -> Expression -> Entity\n
        //\n
        // Here\'s some LESS code:\n
        //\n
        //    .class {\n
        //      color: #fff;\n
        //      border: 1px solid #000;\n
        //      width: @w + 4px;\n
        //      > .child {...}\n
        //    }\n
        //\n
        // And here\'s what the parse tree might look like:\n
        //\n
        //     Ruleset (Selector \'.class\', [\n
        //         Rule ("color",  Value ([Expression [Color #fff]]))\n
        //         Rule ("border", Value ([Expression [Dimension 1px][Keyword "solid"][Color #000]]))\n
        //         Rule ("width",  Value ([Expression [Operation "+" [Variable "@w"][Dimension 4px]]]))\n
        //         Ruleset (Selector [Element \'>\', \'.child\'], [...])\n
        //     ])\n
        //\n
        //  In general, most rules will try to parse a token with the `$()` function, and if the return\n
        //  value is truly, will return a new node, of the relevant type. Sometimes, we need to check\n
        //  first, before parsing, that\'s when we use `peek()`.\n
        //\n
        parsers: {\n
            //\n
            // The `primary` rule is the *entry* and *exit* point of the parser.\n
            // The rules here can appear at any level of the parse tree.\n
            //\n
            // The recursive nature of the grammar is an interplay between the `block`\n
            // rule, which represents `{ ... }`, the `ruleset` rule, and this `primary` rule,\n
            // as represented by this simplified grammar:\n
            //\n
            //     primary  →  (ruleset | rule)+\n
            //     ruleset  →  selector+ block\n
            //     block    →  \'{\' primary \'}\'\n
            //\n
            // Only at one point is the primary rule not called from the\n
            // block rule: at the root level.\n
            //\n
            primary: function () {\n
                var node, root = [];\n
\n
                while (node = $(this.mixin.definition) || $(this.rule)    ||  $(this.ruleset) ||\n
                              $(this.mixin.call)       || $(this.comment) ||\n
                              $(/[\\n\\s]+/g)            || $(this.directive)) {\n
                    root.push(node);\n
                }\n
                return root;\n
            },\n
\n
            // We create a Comment node for CSS comments `/* */`,\n
            // but keep the LeSS comments `//` silent, by just skipping\n
            // over them.\n
            comment: function () {\n
                var comment;\n
\n
                if (input.charAt(i) !== \'/\') return;\n
\n
                if (comment = $(/\\/\\*(?:[^*]|\\*+[^\\/*])*\\*+\\/\\n?/g)) {\n
                    return new(tree.Comment)(comment);\n
                } else {\n
                    return $(/\\/\\/.*/g);\n
                }\n
            },\n
\n
            //\n
            // Entities are tokens which can be found inside an Expression\n
            //\n
            entities: {\n
                //\n
                // A string, which supports escaping " and \'\n
                //\n
                //     "milky way" \'he\\\'s the one!\'\n
                //\n
                quoted: function () {\n
                    var str;\n
                    if (input.charAt(i) !== \'"\' && input.charAt(i) !== "\'") return;\n
\n
                    if (str = $(/"((?:[^"\\\\\\r\\n]|\\\\.)*)"|\'((?:[^\'\\\\\\r\\n]|\\\\.)*)\'/g)) {\n
                        return new(tree.Quoted)(str[0], str[1] || str[2]);\n
                    }\n
                },\n
\n
                //\n
                // A catch-all word, such as:\n
                //\n
                //     black border-collapse\n
                //\n
                keyword: function () {\n
                    var k;\n
                    if (k = $(/[A-Za-z-]+/g)) { return new(tree.Keyword)(k) }\n
                },\n
\n
                //\n
                // A function call\n
                //\n
                //     rgb(255, 0, 255)\n
                //\n
                // We also try to catch IE\'s `alpha()`, but let the `alpha` parser\n
                // deal with the details.\n
                //\n
                // The arguments are parsed with the `entities.arguments` parser.\n
                //\n
                call: function () {\n
                    var name, args;\n
\n
                    if (! (name = $(/([a-zA-Z0-9_-]+|%)\\(/g))) return;\n
\n
                    if (name[1].toLowerCase() === \'alpha\') { return $(this.alpha) }\n
\n
                    args = $(this.entities.arguments);\n
\n
                    if (! $(\')\')) return;\n
\n
                    if (name) { return new(tree.Call)(name[1], args) }\n
                },\n
                arguments: function () {\n
                    var args = [], arg;\n
\n
                    while (arg = $(this.expression)) {\n
                        args.push(arg);\n
                        if (! $(\',\')) { break }\n
                    }\n
                    return args;\n
                },\n
                literal: function () {\n
                    return $(this.entities.dimension) ||\n
                           $(this.entities.color) ||\n
                           $(this.entities.quoted);\n
                },\n
\n
                //\n
                // Parse url() tokens\n
                //\n
                // We use a specific rule for urls, because they don\'t really behave like\n
                // standard function calls. The difference is that the argument doesn\'t have\n
                // to be enclosed within a string, so it can\'t be parsed as an Expression.\n
                //\n
                url: function () {\n
                    var value;\n
\n
                    if (input.charAt(i) !== \'u\' || !$(/url\\(/g)) return;\n
                    value = $(this.entities.quoted) || $(/[-a-zA-Z0-9_%@$\\/.&=:;#+?]+/g);\n
                    if (! $(\')\')) throw new(Error)("missing closing ) for url()");\n
\n
                    return new(tree.URL)(value.value ? value : new(tree.Anonymous)(value));\n
                },\n
\n
                //\n
                // A Variable entity, such as `@fink`, in\n
                //\n
                //     width: @fink + 2px\n
                //\n
                // We use a different parser for variable definitions,\n
                // see `parsers.variable`.\n
                //\n
                variable: function () {\n
                    var name, index = i;\n
\n
                    if (input.charAt(i) === \'@\' && (name = $(/@[a-zA-Z0-9_-]+/g))) {\n
                        return new(tree.Variable)(name, index);\n
                    }\n
                },\n
\n
                //\n
                // A Hexadecimal color\n
                //\n
                //     #4F3C2F\n
                //\n
                // `rgb` and `hsl` colors are parsed through the `entities.call` parser.\n
                //\n
                color: function () {\n
                    var rgb;\n
\n
                    if (input.charAt(i) === \'#\' && (rgb = $(/#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})/g))) {\n
                        return new(tree.Color)(rgb[1]);\n
                    }\n
                },\n
\n
                //\n
                // A Dimension, that is, a number and a unit\n
                //\n
                //     0.5em 95%\n
                //\n
                dimension: function () {\n
                    var value, c = input.charCodeAt(i);\n
                    if ((c > 57 || c < 45) || c === 47) return;\n
\n
                    if (value = $(/(-?[0-9]*\\.?[0-9]+)(px|%|em|pc|ex|in|deg|s|ms|pt|cm|mm)?/g)) {\n
                        return new(tree.Dimension)(value[1], value[2]);\n
                    }\n
                }\n
            },\n
\n
            //\n
            // The variable part of a variable definition. Used in the `rule` parser\n
            //\n
            //     @fink:\n
            //\n
            variable: function () {\n
                var name;\n
\n
                if (input.charAt(i) === \'@\' && (name = $(/(@[a-zA-Z0-9_-]+)\\s*:/g))) { return name[1] }\n
            },\n
\n
            //\n
            // A font size/line-height shorthand\n
            //\n
            //     small/12px\n
            //\n
            // We need to peek first, or we\'ll match on keywords and dimensions\n
            //\n
            shorthand: function () {\n
                var a, b;\n
\n
                if (! peek(/[@\\w.-]+\\/[@\\w.-]+/g)) return;\n
\n
                if ((a = $(this.entity)) && $(\'/\') && (b = $(this.entity))) {\n
                    return new(tree.Shorthand)(a, b);\n
                }\n
            },\n
\n
            //\n
            // Mixins\n
            //\n
            mixin: {\n
                //\n
                // A Mixin call, with an optional argument list\n
                //\n
                //     #mixins > .square(#fff);\n
                //     .rounded(4px, black);\n
                //     .button;\n
                //\n
                // The `while` loop is there because mixins can be\n
                // namespaced, but we only support the child and descendant\n
                // selector for now.\n
                //\n
                call: function () {\n
                    var elements = [], e, c, args, index = i;\n
\n
                    while (e = $(/[#.][a-zA-Z0-9_-]+/g)) {\n
                        elements.push(new(tree.Element)(c, e));\n
                        c = $(\'>\');\n
                    }\n
                    $(\'(\') && (args = $(this.entities.arguments)) && $(\')\');\n
\n
                    if (elements.length > 0 && ($(\';\') || peek(\'}\'))) {\n
                        return new(tree.mixin.Call)(elements, args, index);\n
                    }\n
                },\n
\n
                //\n
                // A Mixin definition, with a list of parameters\n
                //\n
                //     .rounded (@radius: 2px, @color) {\n
                //        ...\n
                //     }\n
                //\n
                // Until we have a finer grained state-machine, we have to\n
                // do a look-ahead, to make sure we don\'t have a mixin call.\n
                // See the `rule` function for more information.\n
                //\n
                // We start by matching `.rounded (`, and then proceed on to\n
                // the argument list, which has optional default values.\n
                // We store the parameters in `params`, with a `value` key,\n
                // if there is a value, such as in the case of `@radius`.\n
                //\n
                // Once we\'ve got our params list, and a closing `)`, we parse\n
                // the `{...}` block.\n
                //\n
                definition: function () {\n
                    var name, params = [], match, ruleset, param, value;\n
\n
                    if (input.charAt(i) !== \'.\' || peek(/[^{]*(;|})/g)) return;\n
\n
                    if (match = $(/([#.][a-zA-Z0-9_-]+)\\s*\\(/g)) {\n
                        name = match[1];\n
\n
                        while (param = $(/@[\\w-]+/g) || $(this.entities.literal)\n
                                                     || $(this.entities.keyword)) {\n
                            // Variable\n
                            if (param[0] === \'@\') {\n
                                if ($(\':\')) {\n
                                    if (value = $(this.expression)) {\n
                                        params.push({ name: param, value: value });\n
                                    } else {\n
                                        throw new(Error)("Expected value");\n
                                    }\n
                                } else {\n
                                    params.push({ name: param });\n
                                }\n
                            } else {\n
                                params.push({ value: param });\n
                            }\n
                            if (! $(\',\')) { break }\n
                        }\n
                        if (! $(\')\')) throw new(Error)("Expected )");\n
\n
                        ruleset = $(this.block);\n
\n
                        if (ruleset) {\n
                            return new(tree.mixin.Definition)(name, params, ruleset);\n
                        }\n
                    }\n
                }\n
            },\n
\n
            //\n
            // Entities are the smallest recognized token,\n
            // and can be found inside a rule\'s value.\n
            //\n
            entity: function () {\n
                return $(this.entities.literal) || $(this.entities.variable) || $(this.entities.url) ||\n
                       $(this.entities.call)    || $(this.entities.keyword);\n
            },\n
\n
            //\n
            // A Rule terminator. Note that we use `peek()` to check for \'}\',\n
            // because the `block` rule will be expecting it, but we still need to make sure\n
            // it\'s there, if \';\' was ommitted.\n
            //\n
            end: function () {\n
                return $(\';\') || peek(\'}\');\n
            },\n
\n
            //\n
            // IE\'s alpha function\n
            //\n
            //     alpha(opacity=88)\n
            //\n
            alpha: function () {\n
                var value;\n
\n
                if (! $(/opacity=/gi)) return;\n
                if (value = $(/[0-9]+/g) || $(this.entities.variable)) {\n
                    if (! $(\')\')) throw new(Error)("missing closing ) for alpha()");\n
                    return new(tree.Alpha)(value);\n
                }\n
            },\n
\n
            //\n
            // A Selector Element\n
            //\n
            //     div\n
            //     + h1\n
            //     #socks\n
            //     input[type="text"]\n
            //\n
            // Elements are the building blocks for Selectors,\n
            // they are made out of a `Combinator` (see combinator rule),\n
            // and an element name, such as a tag a class, or `*`.\n
            //\n
            element: function () {\n
                var e, t;\n
\n
                c = $(this.combinator);\n
                e = $(/[.#:]?[a-zA-Z0-9_-]+/g) || $(\'*\') || $(this.attribute) || $(/\\([^)@]+\\)/g);\n
\n
                if (e) { return new(tree.Element)(c, e) }\n
            },\n
\n
            //\n
            // Combinators combine elements together, in a Selector.\n
            //\n
            // Because our parser isn\'t white-space sensitive, special care\n
            // has to be taken, when parsing the descendant combinator, ` `,\n
            // as it\'s an empty space. We have to check the previous character\n
            // in the input, to see if it\'s a ` ` character. More info on how\n
            // we deal with this in *combinator.js*.\n
            //\n
            combinator: function () {\n
                var match;\n
                if (match = $(/[+>~]/g) || $(\'&\') || $(/::/g)) {\n
                    return new(tree.Combinator)(match);\n
                } else {\n
                    return new(tree.Combinator)(input.charAt(i - 1) === " " ? " " : null);\n
                }\n
            },\n
\n
            //\n
            // A CSS Selector\n
            //\n
            //     .class > div + h1\n
            //     li a:hover\n
            //\n
            // Selectors are made out of one or more Elements, see above.\n
            //\n
            selector: function () {\n
                var sel, e, elements = [], match;\n
\n
                while (e = $(this.element)) { elements.push(e) }\n
\n
                if (elements.length > 0) { return new(tree.Selector)(elements) }\n
            },\n
            tag: function () {\n
                return $(/[a-zA-Z][a-zA-Z-]*[0-9]?/g) || $(\'*\');\n
            },\n
            attribute: function () {\n
                var attr = \'\', key, val, op;\n
\n
                if (! $(\'[\')) return;\n
\n
                if (key = $(/[a-z-]+/g) || $(this.entities.quoted)) {\n
                    if ((op = $(/[|~*$^]?=/g)) &&\n
                        (val = $(this.entities.quoted) || $(/[\\w-]+/g))) {\n
                        attr = [key, op, val.toCSS ? val.toCSS() : val].join(\'\');\n
                    } else { attr = key }\n
                }\n
\n
                if (! $(\']\')) return;\n
\n
                if (attr) { return "[" + attr + "]" }\n
            },\n
\n
            //\n
            // The `block` rule is used by `ruleset` and `mixin.definition`.\n
            // It\'s a wrapper around the `primary` rule, with added `{}`.\n
            //\n
            block: function () {\n
                var content;\n
\n
                if ($(\'{\') && (content = $(this.primary)) && $(\'}\')) {\n
                    return content;\n
                }\n
            },\n
\n
            //\n
            // div, .class, body > p {...}\n
            //\n
            ruleset: function () {\n
                var selectors = [], s, rules, match, memo = i;\n
\n
                if (match = peek(/([a-z.#: _-]+)[\\s\\n]*\\{/g)) {\n
                    i += match[0].length - 1;\n
                    selectors = [new(tree.Selector)([new(tree.Element)(null, match[1])])];\n
                } else {\n
                    while (s = $(this.selector)) {\n
                        selectors.push(s);\n
                        if (! $(\',\')) { break }\n
                    }\n
                    if (s) $(this.comment);\n
                }\n
\n
                if (selectors.length > 0 && (rules = $(this.block))) {\n
                    return new(tree.Ruleset)(selectors, rules);\n
                } else {\n
                    // Backtrack\n
                    furthest = i;\n
                    i = memo;\n
                }\n
            },\n
            rule: function () {\n
                var value;\n
                var memo = i;\n
\n
                if (name = $(this.property) || $(this.variable)) {\n
                    if ((name.charAt(0) != \'@\') && (match = peek(/([^@+\\/*(;{}-]*);/g))) {\n
                        i += match[0].length - 1;\n
                        value = new(tree.Anonymous)(match[1]);\n
                    } else if (name === "font") {\n
                        value = $(this.font);\n
                    } else {\n
                        value = $(this.value);\n
                    }\n
\n
                    if ($(this.end)) {\n
                        return new(tree.Rule)(name, value, memo);\n
                    } else {\n
                        furthest = i;\n
                        i = memo;\n
                    }\n
                }\n
            },\n
\n
            //\n
            // An @import directive\n
            //\n
            //     @import "lib";\n
            //\n
            // Depending on our environemnt, importing is done differently:\n
            // In the browser, it\'s an XHR request, in Node, it would be a\n
            // file-system operation. The function used for importing is\n
            // stored in `import`, which we pass to the Import constructor.\n
            //\n
            "import": function () {\n
                var path;\n
                if ($(/@import\\s+/g) &&\n
                    (path = $(this.entities.quoted) || $(this.entities.url)) &&\n
                    $(\';\')) {\n
                    return new(tree.Import)(path, imports);\n
                }\n
            },\n
\n
            //\n
            // A CSS Directive\n
            //\n
            //     @charset "utf-8";\n
            //\n
            directive: function () {\n
                var name, value, rules, types;\n
\n
                if (input.charAt(i) !== \'@\') return;\n
\n
                if (value = $(this[\'import\'])) {\n
                    return value;\n
                } else if (name = $(/@media|@page/g)) {\n
                    types = $(/[^{]+/g).trim();\n
                    if (rules = $(this.block)) {\n
                        return new(tree.Directive)(name + " " + types, rules);\n
                    }\n
                } else if (name = $(/@[-a-z]+/g)) {\n
                    if (name === \'@font-face\') {\n
                        if (rules = $(this.block)) {\n
                            return new(tree.Directive)(name, rules);\n
                        }\n
                    } else if ((value = $(this.entity)) && $(\';\')) {\n
                        return new(tree.Directive)(name, value);\n
                    }\n
                }\n
            },\n
            font: function () {\n
                var value = [], expression = [], weight, shorthand, font, e;\n
\n
                while (e = $(this.shorthand) || $(this.entity)) {\n
                    expression.push(e);\n
                }\n
                value.push(new(tree.Expression)(expression));\n
\n
                if ($(\',\')) {\n
                    while (e = $(this.expression)) {\n
                        value.push(e);\n
                        if (! $(\',\')) { break }\n
                    }\n
                }\n
                return new(tree.Value)(value, $(this.important));\n
            },\n
\n
            //\n
            // A Value is a comma-delimited list of Expressions\n
            //\n
            //     font-family: Baskerville, Georgia, serif;\n
            //\n
            // In a Rule, a Value represents everything after the `:`,\n
            // and before the `;`.\n
            //\n
            value: function () {\n
                var e, expressions = [], important;\n
\n
                while (e = $(this.expression)) {\n
                    expressions.push(e);\n
                    if (! $(\',\')) { break }\n
                }\n
                important = $(this.important);\n
\n
                if (expressions.length > 0) {\n
                    return new(tree.Value)(expressions, important);\n
                }\n
            },\n
            important: function () {\n
                return $(/!\\s*important/g);\n
            },\n
            sub: function () {\n
                var e;\n
\n
                if ($(\'(\') && (e = $(this.expression)) && $(\')\')) {\n
                    return e;\n
                }\n
            },\n
            multiplication: function () {\n
                var m, a, op, operation;\n
                if (m = $(this.operand)) {\n
                    while ((op = $(/[\\/*]/g)) && (a = $(this.operand))) {\n
                        operation = new(tree.Operation)(op, [operation || m, a]);\n
                    }\n
                    return operation || m;\n
                }\n
            },\n
            addition: function () {\n
                var m, a, op, operation;\n
                if (m = $(this.multiplication)) {\n
                    while ((op = $(/[-+]\\s+/g) || (input.charAt(i - 1) != \' \' && $(/[-+]/g))) &&\n
                           (a = $(this.multiplication))) {\n
                        operation = new(tree.Operation)(op, [operation || m, a]);\n
                    }\n
                    return operation || m;\n
                }\n
            },\n
\n
            //\n
            // An operand is anything that can be part of an operation,\n
            // such as a Color, or a Variable\n
            //\n
            operand: function () {\n
                return $(this.sub) || $(this.entities.dimension) ||\n
                       $(this.entities.color) || $(this.entities.variable);\n
            },\n
\n
            //\n
            // Expressions either represent mathematical operations,\n
            // or white-space delimited Entities.\n
            //\n
            //     1px solid black\n
            //     @var * 2\n
            //\n
            expression: function () {\n
                var e, delim, entities = [], d;\n
\n
                while (e = $(this.addition) || $(this.entity)) {\n
                    entities.push(e);\n
                }\n
                if (entities.length > 0) {\n
                    return new(tree.Expression)(entities);\n
                }\n
            },\n
            property: function () {\n
                var name;\n
\n
                if (name = $(/(\\*?-?[-a-z_0-9]+)\\s*:/g)) {\n
                    return name[1];\n
                }\n
            }\n
        }\n
    };\n
};\n
\n
less.Parser.importer = null;\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.functions = {\n
    rgb: function (r, g, b) {\n
        return this.rgba(r, g, b, 1.0);\n
    },\n
    rgba: function (r, g, b, a) {\n
        var rgb = [r, g, b].map(function (c) { return number(c) }),\n
            a = number(a);\n
        return new(tree.Color)(rgb, a);\n
    },\n
    hsl: function (h, s, l) {\n
        return this.hsla(h, s, l, 1.0);\n
    },\n
    hsla: function (h, s, l, a) {\n
        h = (((number(h) % 360) + 360) % 360) / 360;\n
        s = number(s); l = number(l); a = number(a);\n
\n
        //require(\'sys\').puts(h, s, l)\n
\n
        var m2 = l <= 0.5 ? l * (s + 1) : l + s - l * s;\n
        var m1 = l * 2 - m2;\n
\n
        return this.rgba(hue(h + 1/3) * 255,\n
                         hue(h)       * 255,\n
                         hue(h - 1/3) * 255,\n
                         a);\n
\n
        function hue(h) {\n
            h = h < 0 ? h + 1 : (h > 1 ? h - 1 : h);\n
            if      (h * 6 < 1) return m1 + (m2 - m1) * h * 6;\n
            else if (h * 2 < 1) return m2;\n
            else if (h * 3 < 2) return m1 + (m2 - m1) * (2/3 - h) * 6;\n
            else                return m1;\n
        }\n
    },\n
    opacity: function(color, amount) {\n
        var alpha = number(amount) * (color.alpha || 1.0);\n
        return new(tree.Color)(color.rgb, number(amount));\n
    },\n
    saturate: function (color, amount) {\n
        var hsl = color.toHSL();\n
\n
        hsl.s += amount.value / 100;\n
        hsl.s = clamp(hsl.s);\n
        return this.hsl(hsl.h, hsl.s, hsl.l);\n
    },\n
    desaturate: function (color, amount) {\n
        var hsl = color.toHSL();\n
\n
        hsl.s -= amount.value / 100;\n
        hsl.s = clamp(hsl.s);\n
        return this.hsl(hsl.h, hsl.s, hsl.l);\n
    },\n
    lighten: function (color, amount) {\n
        var hsl = color.toHSL();\n
\n
        hsl.l *= (1 + amount.value / 100);\n
        hsl.l = clamp(hsl.l);\n
        return this.hsl(hsl.h, hsl.s, hsl.l);\n
    },\n
    darken: function (color, amount) {\n
        var hsl = color.toHSL();\n
\n
        hsl.l *= (1 - amount.value / 100);\n
        hsl.l = clamp(hsl.l);\n
        return this.hsl(hsl.h, hsl.s, hsl.l);\n
    },\n
    greyscale: function (color, amount) {\n
        return this.desaturate(color, new(tree.Dimension)(100));\n
    },\n
    e: function (str) {\n
        return new(tree.Anonymous)(str);\n
    },\n
    \'%\': function (quoted /* arg, arg, ...*/) {\n
        var args = Array.prototype.slice.call(arguments, 1),\n
            str = quoted.content;\n
\n
        for (var i = 0; i < args.length; i++) {\n
            str = str.replace(/%s/,    args[i].content)\n
                     .replace(/%[da]/, args[i].toCSS());\n
        }\n
        str = str.replace(/%%/g, \'%\');\n
        return new(tree.Quoted)(\'"\' + str + \'"\', str);\n
    }\n
};\n
\n
function number(n) {\n
    if (n instanceof tree.Dimension) {\n
        return parseFloat(n.unit == \'%\' ? n.value / 100 : n.value);\n
    } else if (typeof(n) === \'number\') {\n
        return n;\n
    } else {\n
        throw {\n
            error: "RuntimeError",\n
            message: "color functions take numbers as parameters"\n
        };\n
    }\n
}\n
\n
function clamp(val) {\n
    return Math.min(1, Math.max(0, val));\n
}\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Alpha = function Alpha(val) {\n
    this.value = val;\n
};\n
tree.Alpha.prototype = {\n
    toCSS: function () {\n
        return "alpha(opacity=" + this.value.toCSS() + ")";\n
    },\n
    eval: function () { return this }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Anonymous = function Anonymous(string) {\n
    this.value = string.content || string;\n
};\n
tree.Anonymous.prototype = {\n
    toCSS: function () {\n
        return this.value;\n
    },\n
    eval: function () { return this }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
//\n
// A function call node.\n
//\n
tree.Call = function Call(name, args) {\n
    this.name = name;\n
    this.args = args;\n
};\n
tree.Call.prototype = {\n
    //\n
    // When evaluating a function call,\n
    // we either find the function in `tree.functions` [1],\n
    // in which case we call it, passing the  evaluated arguments,\n
    // or we simply print it out as it appeared originally [2].\n
    //\n
    // The *functions.js* file contains the built-in functions.\n
    //\n
    // The reason why we evaluate the arguments, is in the case where\n
    // we try to pass a variable to a function, like: `saturate(@color)`.\n
    // The function should receive the value, not the variable.\n
    //\n
    eval: function (env) {\n
        var args = this.args.map(function (a) { return a.eval(env) });\n
\n
        if (this.name in tree.functions) { // 1.\n
            return tree.functions[this.name].apply(tree.functions, args);\n
        } else { // 2.\n
            return new(tree.Anonymous)(this.name +\n
                   "(" + args.map(function (a) { return a.toCSS() }).join(\', \') + ")");\n
        }\n
    },\n
\n
    toCSS: function (env) {\n
        return this.eval(env).toCSS();\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
//\n
// RGB Colors - #ff0014, #eee\n
//\n
tree.Color = function Color(rgb, a) {\n
    //\n
    // The end goal here, is to parse the arguments\n
    // into an integer triplet, such as `128, 255, 0`\n
    //\n
    // This facilitates operations and conversions.\n
    //\n
    if (Array.isArray(rgb)) {\n
        this.rgb = rgb;\n
        this.alpha = a;\n
    } else if (rgb.length == 6) {\n
        this.rgb = rgb.match(/.{2}/g).map(function (c) {\n
            return parseInt(c, 16);\n
        });\n
    } else {\n
        this.rgb = rgb.split(\'\').map(function (c) {\n
            return parseInt(c + c, 16);\n
        });\n
    }\n
};\n
tree.Color.prototype = {\n
    eval: function () { return this },\n
\n
    //\n
    // If we have some transparency, the only way to represent it\n
    // is via `rgba`. Otherwise, we use the hex representation,\n
    // which has better compatibility with older browsers.\n
    // Values are capped between `0` and `255`, rounded and zero-padded.\n
    //\n
    toCSS: function () {\n
        if (this.alpha && this.alpha < 1.0) {\n
            return "rgba(" + this.rgb.concat(this.alpha).join(\', \') + ")";\n
        } else {\n
            return \'#\' + this.rgb.map(function (i) {\n
                i = Math.round(i);\n
                i = (i > 255 ? 255 : (i < 0 ? 0 : i)).toString(16);\n
                return i.length === 1 ? \'0\' + i : i;\n
            }).join(\'\');\n
        }\n
    },\n
\n
    //\n
    // Operations have to be done per-channel, if not,\n
    // channels will spill onto each other. Once we have\n
    // our result, in the form of an integer triplet,\n
    // we create a new Color node to hold the result.\n
    //\n
    operate: function (op, other) {\n
        var result = [];\n
\n
        if (! (other instanceof tree.Color)) {\n
            other = other.toColor();\n
        }\n
\n
        for (var c = 0; c < 3; c++) {\n
            result[c] = tree.operate(op, this.rgb[c], other.rgb[c]);\n
        }\n
        return new(tree.Color)(result);\n
    },\n
\n
    toHSL: function () {\n
        var r = this.rgb[0] / 255,\n
            g = this.rgb[1] / 255,\n
            b = this.rgb[2] / 255;\n
\n
        var max = Math.max(r, g, b), min = Math.min(r, g, b);\n
        var h, s, l = (max + min) / 2, d = max - min;\n
\n
        if (max === min) {\n
            h = s = 0;\n
        } else {\n
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);\n
\n
            switch (max) {\n
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;\n
                case g: h = (b - r) / d + 2;               break;\n
                case b: h = (r - g) / d + 4;               break;\n
            }\n
            h /= 6;\n
        }\n
        return { h: h * 360, s: s, l: l };\n
    }\n
};\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Comment = function Comment(value) {\n
    this.value = value;\n
};\n
tree.Comment.prototype = {\n
    toCSS: function () {\n
        return this.value;\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
//\n
// A number with a unit\n
//\n
tree.Dimension = function Dimension(value, unit) {\n
    this.value = parseFloat(value);\n
    this.unit = unit || null;\n
};\n
\n
tree.Dimension.prototype = {\n
    eval: function () { return this },\n
    toColor: function () {\n
        return new(tree.Color)([this.value, this.value, this.value]);\n
    },\n
    toCSS: function () {\n
        var css = this.value + this.unit;\n
        return css;\n
    },\n
\n
    // In an operation between two Dimensions,\n
    // we default to the first Dimension\'s unit,\n
    // so `1px + 2em` will yield `3px`.\n
    // In the future, we could implement some unit\n
    // conversions such that `100cm + 10mm` would yield\n
    // `101cm`.\n
    operate: function (op, other) {\n
        return new(tree.Dimension)\n
                  (tree.operate(op, this.value, other.value),\n
                  this.unit || other.unit);\n
    }\n
};\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Directive = function Directive(name, value) {\n
    this.name = name;\n
    if (Array.isArray(value)) {\n
        this.ruleset = new(tree.Ruleset)([], value);\n
    } else {\n
        this.value = value;\n
    }\n
};\n
tree.Directive.prototype = {\n
    toCSS: function (ctx, env) {\n
        if (this.ruleset) {\n
            this.ruleset.root = true;\n
            return this.name + \' {\\n  \' +\n
                   this.ruleset.toCSS(ctx, env).trim().replace(/\\n/g, \'\\n  \') + \'\\n}\\n\';\n
        } else {\n
            return this.name + \' \' + this.value.toCSS() + \';\\n\';\n
        }\n
    },\n
    eval: function (env) {\n
        env.frames.unshift(this);\n
        this.ruleset && this.ruleset.evalRules(env);\n
        env.frames.shift();\n
        return this;\n
    },\n
    variable: function (name) { return tree.Ruleset.prototype.variable.call(this.ruleset, name) },\n
    find: function () { return tree.Ruleset.prototype.find.apply(this.ruleset, arguments) },\n
    rulesets: function () { return tree.Ruleset.prototype.rulesets.apply(this.ruleset) }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Element = function Element(combinator, value) {\n
    this.combinator = combinator instanceof tree.Combinator ?\n
                      combinator : new(tree.Combinator)(combinator);\n
    this.value = value.trim();\n
};\n
tree.Element.prototype.toCSS = function () {\n
    return this.combinator.toCSS() + this.value;\n
};\n
\n
tree.Combinator = function Combinator(value) {\n
    if (value === \' \') {\n
        this.value = \' \';\n
    } else {\n
        this.value = value ? value.trim() : "";\n
    }\n
};\n
tree.Combinator.prototype.toCSS = function () {\n
    switch (this.value) {\n
        case \'\'  : return \'\';\n
        case \' \' : return \' \';\n
        case \'&\' : return \'\';\n
        case \':\' : return \' :\';\n
        case \'::\': return \'::\';\n
        case \'+\' : return \' + \';\n
        case \'~\' : return \' ~ \';\n
        case \'>\' : return \' > \';\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Expression = function Expression(value) { this.value = value };\n
tree.Expression.prototype = {\n
    eval: function (env) {\n
        if (this.value.length > 1) {\n
            return new(tree.Expression)(this.value.map(function (e) {\n
                return e.eval(env);\n
            }));\n
        } else {\n
            return this.value[0].eval(env);\n
        }\n
    },\n
    toCSS: function () {\n
        return this.value.map(function (e) {\n
            return e.toCSS();\n
        }).join(\' \');\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
//\n
// CSS @import node\n
//\n
// The general strategy here is that we don\'t want to wait\n
// for the parsing to be completed, before we start importing\n
// the file. That\'s because in the context of a browser,\n
// most of the time will be spent waiting for the server to respond.\n
//\n
// On creation, we push the import path to our import queue, though\n
// `import,push`, we also pass it a callback, which it\'ll call once\n
// the file has been fetched, and parsed.\n
//\n
tree.Import = function Import(path, imports) {\n
    var that = this;\n
\n
    this._path = path;\n
\n
    // The \'.less\' extension is optional\n
    if (path instanceof tree.Quoted) {\n
        this.path = /\\.(le?|c)ss$/.test(path.content) ? path.content : path.content + \'.less\';\n
    } else {\n
        this.path = path.value.content || path.value;\n
    }\n
\n
    this.css = /css$/.test(this.path);\n
\n
    // Only pre-compile .less files\n
    if (! this.css) {\n
        imports.push(this.path, function (root) {\n
            that.root = root;\n
        });\n
    }\n
};\n
\n
//\n
// The actual import node doesn\'t return anything, when converted to CSS.\n
// The reason is that it\'s used at the evaluation stage, so that the rules\n
// it imports can be treated like any other rules.\n
//\n
// In `eval`, we make sure all Import nodes get evaluated, recursively, so\n
// we end up with a flat structure, which can easily be imported in the parent\n
// ruleset.\n
//\n
tree.Import.prototype = {\n
    toCSS: function () {\n
        if (this.css) {\n
            return "@import " + this._path.toCSS() + \';\\n\';\n
        } else {\n
            return "";\n
        }\n
    },\n
    eval: function () {\n
        if (this.css) {\n
            return this;\n
        } else {\n
            for (var i = 0; i < this.root.rules.length; i++) {\n
                if (this.root.rules[i] instanceof tree.Import) {\n
                    Array.prototype\n
                         .splice\n
                         .apply(this.root.rules,\n
                                [i, 1].concat(this.root.rules[i].eval()));\n
                }\n
            }\n
            return this.root.rules;\n
        }\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Keyword = function Keyword(value) { this.value = value };\n
tree.Keyword.prototype = {\n
    eval: function () { return this },\n
    toCSS: function () { return this.value }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.mixin = {};\n
tree.mixin.Call = function MixinCall(elements, args, index) {\n
    this.selector = new(tree.Selector)(elements);\n
    this.arguments = args;\n
    this.index = index;\n
};\n
tree.mixin.Call.prototype = {\n
    eval: function (env) {\n
        var mixins, rules = [], match = false;\n
\n
        for (var i = 0; i < env.frames.length; i++) {\n
            if ((mixins = env.frames[i].find(this.selector)).length > 0) {\n
                for (var m = 0; m < mixins.length; m++) {\n
                    if (mixins[m].match(this.arguments, env)) {\n
                        try {\n
                            Array.prototype.push.apply(\n
                                  rules, mixins[m].eval(this.arguments, env).rules);\n
                            match = true;\n
                        } catch (e) {\n
                            throw { message: e.message, index: this.index };\n
                        }\n
                    }\n
                }\n
                if (match) {\n
                    return rules;\n
                } else {\n
                    throw { message: \'No matching definition was found for `\' +\n
                                      this.selector.toCSS().trim() + \'(\'      +\n
                                      this.arguments.map(function (a) {\n
                                          return a.toCSS();\n
                                      }).join(\', \') + ")`",\n
                            index:   this.index };\n
                }\n
            }\n
        }\n
        throw { message: this.selector.toCSS().trim() + " is undefined",\n
                index: this.index };\n
    }\n
};\n
\n
tree.mixin.Definition = function MixinDefinition(name, params, rules) {\n
    this.name = name;\n
    this.selectors = [new(tree.Selector)([new(tree.Element)(null, name)])];\n
    this.params = params;\n
    this.arity = params.length;\n
    this.rules = rules;\n
    this._lookups = {};\n
    this.required = params.reduce(function (count, p) {\n
        if (p.name && !p.value) { return count + 1 }\n
        else                    { return count }\n
    }, 0);\n
};\n
tree.mixin.Definition.prototype = {\n
    toCSS: function () { return "" },\n
    variable: function (name) { return tree.Ruleset.prototype.variable.call(this, name) },\n
    find: function () { return tree.Ruleset.prototype.find.apply(this, arguments) },\n
    rulesets: function () { return tree.Ruleset.prototype.rulesets.apply(this) },\n
\n
    eval: function (args, env) {\n
        var frame = new(tree.Ruleset)(null, []), context;\n
\n
        for (var i = 0, val; i < this.params.length; i++) {\n
            if (this.params[i].name) {\n
                if (val = (args && args[i]) || this.params[i].value) {\n
                    frame.rules.unshift(new(tree.Rule)(this.params[i].name, val.eval(env)));\n
                } else {\n
                    throw { message: "wrong number of arguments for " + this.name +\n
                            \' (\' + args.length + \' for \' + this.arity + \')\' };\n
                }\n
            }\n
        }\n
        return new(tree.Ruleset)(null, this.rules).evalRules({\n
            frames: [this, frame].concat(env.frames)\n
        });\n
    },\n
    match: function (args, env) {\n
        var argsLength = (args && args.length) || 0;\n
\n
        if (argsLength < this.required) {\n
            return false;\n
        }\n
\n
        for (var i = 0; i < Math.min(argsLength, this.arity); i++) {\n
            if (!this.params[i].name) {\n
                if (args[i].wildcard) { continue }\n
                else if (args[i].eval(env).toCSS() != this.params[i].value.eval(env).toCSS()) {\n
                    return false;\n
                }\n
            }\n
        }\n
        return true;\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Operation = function Operation(op, operands) {\n
    this.op = op.trim();\n
    this.operands = operands;\n
};\n
tree.Operation.prototype.eval = function (env) {\n
    var a = this.operands[0].eval(env),\n
        b = this.operands[1].eval(env),\n
        temp;\n
\n
    if (a instanceof tree.Dimension && b instanceof tree.Color) {\n
        if (this.op === \'*\' || this.op === \'+\') {\n
            temp = b, b = a, a = temp;\n
        } else {\n
            throw { name: "OperationError",\n
                    message: "Can\'t substract or divide a color from a number" };\n
        }\n
    }\n
    return a.operate(this.op, b);\n
};\n
\n
tree.operate = function (op, a, b) {\n
    switch (op) {\n
        case \'+\': return a + b;\n
        case \'-\': return a - b;\n
        case \'*\': return a * b;\n
        case \'/\': return a / b;\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Quoted = function Quoted(value, content) {\n
    this.value = value;\n
    this.content = content;\n
};\n
tree.Quoted.prototype = {\n
    toCSS: function () {\n
        var css = this.value;\n
        return css;\n
    },\n
    eval: function () {\n
        return this;\n
    }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Rule = function Rule(name, value, index) {\n
    this.name = name;\n
    this.value = (value instanceof tree.Value) ? value : new(tree.Value)([value]);\n
    this.index = index;\n
\n
    if (name.charAt(0) === \'@\') {\n
        this.variable = true;\n
    } else { this.variable = false }\n
};\n
tree.Rule.prototype.toCSS = function () {\n
    if (this.variable) { return "" }\n
    else {\n
        return this.name + ": " + this.value.toCSS() + ";";\n
    }\n
};\n
\n
tree.Rule.prototype.eval = function (context) {\n
    return new(tree.Rule)(this.name, this.value.eval(context));\n
};\n
\n
tree.Value = function Value(value) {\n
    this.value = value;\n
    this.is = \'value\';\n
};\n
tree.Value.prototype = {\n
    eval: function (env) {\n
        if (this.value.length === 1) {\n
            return this.value[0].eval(env);\n
        } else {\n
            return new(tree.Value)(this.value.map(function (v) {\n
                return v.eval(env);\n
            }));\n
        }\n
    },\n
    toCSS: function () {\n
        return this.value.map(function (e) {\n
            return e.toCSS();\n
        }).join(\', \');\n
    }\n
};\n
\n
tree.Shorthand = function Shorthand(a, b) {\n
    this.a = a;\n
    this.b = b;\n
};\n
\n
tree.Shorthand.prototype = {\n
    toCSS: function (env) {\n
        return this.a.toCSS(env) + "/" + this.b.toCSS(env);\n
    },\n
    eval: function () { return this }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Ruleset = function Ruleset(selectors, rules) {\n
    this.selectors = selectors;\n
    this.rules = rules;\n
    this._lookups = {};\n
};\n
tree.Ruleset.prototype = {\n
    eval: function () { return this },\n
    evalRules: function (context) {\n
        var rules = [];\n
\n
        this.rules.forEach(function (rule) {\n
            if (rule.evalRules) {\n
                rules.push(rule.evalRules(context));\n
            } else if (rule instanceof tree.mixin.Call) {\n
                Array.prototype.push.apply(rules, rule.eval(context));\n
            } else {\n
                rules.push(rule.eval(context));\n
            }\n
        });\n
        this.rules = rules;\n
        return this;\n
    },\n
    match: function (args) {\n
        return !args || args.length === 0;\n
    },\n
    variable: function (name) {\n
        if (this._variables) { return this._variables[name] }\n
        else {\n
            return (this._variables = this.rules.reduce(function (hash, r) {\n
                if (r instanceof tree.Rule && r.variable === true) {\n
                    hash[r.name] = r;\n
                }\n
                return hash;\n
            }, {}))[name];\n
        }\n
    },\n
    rulesets: function () {\n
        if (this._rulesets) { return this._rulesets }\n
        else {\n
            return this._rulesets = this.rules.filter(function (r) {\n
                if (r instanceof tree.Ruleset || r instanceof tree.mixin.Definition) { return r }\n
            });\n
        }\n
    },\n
    find: function (selector, self) {\n
        self = self || this;\n
        var rules = [], rule, match,\n
            key = selector.toCSS();\n
\n
        if (key in this._lookups) { return this._lookups[key] }\n
\n
        this.rulesets().forEach(function (rule) {\n
            if (rule !== self) {\n
                for (var j = 0; j < rule.selectors.length; j++) {\n
                    if (match = selector.match(rule.selectors[j])) {\n
                        if (selector.elements.length > 1) {\n
                            Array.prototype.push.apply(rules, rule.find(\n
                                new(tree.Selector)(selector.elements.slice(1)), self));\n
                        } else {\n
                            rules.push(rule);\n
                        }\n
                        break;\n
                    }\n
                }\n
            }\n
        });\n
        return this._lookups[key] = rules;\n
    },\n
    //\n
    // Entry point for code generation\n
    //\n
    //     `context` holds an array of arrays.\n
    //\n
    toCSS: function (context, env) {\n
        var css = [],      // The CSS output\n
            rules = [],    // node.Rule instances\n
            rulesets = [], // node.Ruleset instances\n
            paths = [],    // Current selectors\n
            selector,      // The fully rendered selector\n
            rule;\n
\n
        if (! this.root) {\n
            if (context.length === 0) {\n
                paths = this.selectors.map(function (s) { return [s] });\n
            } else {\n
                for (var s = 0; s < this.selectors.length; s++) {\n
                    for (var c = 0; c < context.length; c++) {\n
                        paths.push(context[c].concat([this.selectors[s]]));\n
                    }\n
                }\n
            }\n
        } else {\n
            context = [], env = { frames: [] }\n
            for (var i = 0; i < this.rules.length; i++) {\n
                if (this.rules[i] instanceof tree.Import) {\n
                    Array.prototype.splice\n
                         .apply(this.rules, [i, 1].concat(this.rules[i].eval(env)));\n
                }\n
            }\n
        }\n
\n
        // push the current ruleset to the frames stack\n
        env.frames.unshift(this);\n
\n
        // Evaluate mixins\n
        for (var i = 0; i < this.rules.length; i++) {\n
            if (this.rules[i] instanceof tree.mixin.Call) {\n
                Array.prototype.splice\n
                     .apply(this.rules, [i, 1].concat(this.rules[i].eval(env)));\n
            }\n
        }\n
\n
        // Evaluate rules and rulesets\n
        for (var i = 0; i < this.rules.length; i++) {\n
            rule = this.rules[i];\n
\n
            if (rule instanceof tree.Directive) {\n
                rulesets.push(rule.eval(env).toCSS(paths, env));\n
            } else if (rule.rules) {\n
                rulesets.push(rule.toCSS(paths, env));\n
            } else if (rule instanceof tree.Comment) {\n
                if (this.root) {\n
                    rulesets.push(rule.toCSS());\n
                } else {\n
                    rules.push(rule.toCSS());\n
                }\n
            } else {\n
                if (rule.toCSS && !rule.variable) {\n
                    rules.push(rule.eval(env).toCSS());\n
                } else if (rule.value && !rule.variable) {\n
                    rules.push(rule.value.toString());\n
                }\n
            }\n
        } \n
\n
        rulesets = rulesets.join(\'\');\n
\n
        // If this is the root node, we don\'t render\n
        // a selector, or {}.\n
        // Otherwise, only output if this ruleset has rules.\n
        if (this.root) {\n
            css.push(rules.join(\'\\n\'));\n
        } else {\n
            if (rules.length > 0) {\n
                selector = paths.map(function (p) {\n
                    return p.map(function (s) {\n
                        return s.toCSS();\n
                    }).join(\'\').trim();\n
                }).join(paths.length > 3 ? \',\\n\' : \', \');\n
                css.push(selector, " {\\n  " + rules.join(\'\\n  \') + "\\n}\\n");\n
            }\n
        }\n
        css.push(rulesets);\n
\n
        // Pop the stack\n
        env.frames.shift();\n
\n
        return css.join(\'\');\n
    }\n
};\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Selector = function Selector(elements) {\n
    this.elements = elements;\n
    if (this.elements[0].combinator.value === "") {\n
        this.elements[0].combinator.value = \' \';\n
    }\n
};\n
tree.Selector.prototype.match = function (other) {\n
    if (this.elements[0].value === other.elements[0].value) {\n
        return true;\n
    } else {\n
        return false;\n
    }\n
};\n
tree.Selector.prototype.toCSS = function () {\n
    if (this._css) { return this._css }\n
\n
    return this._css = this.elements.map(function (e) {\n
        if (typeof(e) === \'string\') {\n
            return \' \' + e.trim();\n
        } else {\n
            return e.toCSS();\n
        }\n
    }).join(\'\');\n
};\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.URL = function URL(val) {\n
    this.value = val;\n
};\n
tree.URL.prototype = {\n
    toCSS: function () {\n
        return "url(" + this.value.toCSS() + ")";\n
    },\n
    eval: function () { return this }\n
};\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.Variable = function Variable(name, index) { this.name = name, this.index = index };\n
tree.Variable.prototype = {\n
    eval: function (env) {\n
        var variable, v, name = this.name;\n
\n
        if (variable = tree.find(env.frames, function (frame) {\n
            if (v = frame.variable(name)) {\n
                return v.value.eval(env);\n
            }\n
        })) { return variable }\n
        else {\n
            throw { message: "variable " + this.name + " is undefined",\n
                    index: this.index };\n
        }\n
    }\n
};\n
\n
if (typeof(require) !== \'undefined\' && typeof(__LESS_DIST__) === \'undefined\') { var tree = require(\'less/tree\') }\n
\n
tree.find = function (obj, fun) {\n
    for (var i = 0, r; i < obj.length; i++) {\n
        if (r = fun.call(obj, obj[i])) { return r }\n
    }\n
    return null;\n
};\n
(function () {\n
//\n
// Select all links with the \'rel\' attribute set to "less"\n
//\n
var sheets = [];\n
\n
less.env = location.hostname == \'127.0.0.1\' ||\n
           location.hostname == \'0.0.0.0\'   ||\n
           location.hostname == \'localhost\' ||\n
           location.protocol == \'file:\'     ? \'development\'\n
                                            : \'production\';\n
\n
\n
// Load the stylesheets when the body is ready\n
var readyTimer = setInterval(function () {\n
    if (document.body) {\n
        if (!document.querySelectorAll && typeof(jQuery) === "undefined") {\n
            log("No selector method found");\n
        } else {\n
            sheets = (document.querySelectorAll || jQuery).call(document, \'link[rel="stylesheet/less"]\');\n
        }\n
        clearInterval(readyTimer);\n
\n
        loadStyleSheets(function (root, sheet, env) {\n
            createCSS(root.toCSS(), sheet, env.lastModified);\n
\n
            if (env.local) {\n
                log("less: loading " + sheet.href + " from local storage.");\n
            } else {\n
                log("less: parsed " + sheet.href + " successfully.");\n
            }\n
        });\n
    }\n
}, 10);\n
\n
//\n
// Auto-refresh\n
//\n
if (less.env === \'development\') {\n
    refreshTimer = setInterval(function () {\n
        if (/!refresh/.test(location.hash)) {\n
            loadStyleSheets(function (root, sheet, lastModified) {\n
                createCSS(root.toCSS(), sheet, lastModified);\n
            });\n
        }\n
    }, 1000);\n
}\n
\n
function loadStyleSheets(callback) {\n
    for (var i = 0; i < sheets.length; i++) {\n
        loadStyleSheet(sheets[i], callback);\n
    }\n
}\n
\n
function loadStyleSheet(sheet, callback) {\n
    var css = typeof(localStorage) !== "undefined" && localStorage.getItem(sheet.href);\n
    var styles = css && JSON.parse(css);\n
\n
    xhr(sheet.href, function (data, lastModified) {\n
        if (styles && (new(Date)(lastModified).valueOf() ===\n
                       new(Date)(styles.timestamp).valueOf())) {\n
            // Use local copy\n
            createCSS(styles.css, sheet);\n
            callback(null, sheet, { local: true });\n
        } else {\n
            // Use remote copy (re-parse)\n
            new(less.Parser)({ optimization: 3 }).parse(data, function (e, root) {\n
                if (e) { return error(e, sheet.href) }\n
                try {\n
                    callback(root, sheet, { local: false, lastModified: lastModified });\n
                } catch (e) {\n
                    error(e, sheet.href);\n
                }\n
            });\n
        }\n
    }, function (status) {\n
        throw new(Error)("Couldn\'t load " + sheet.href + " (" + status + ")");\n
    });\n
}\n
\n
function createCSS(styles, sheet, lastModified) {\n
    var css = document.createElement(\'style\');\n
    css.type = \'text/css\';\n
    css.media = \'screen\';\n
    css.title = \'less-sheet\';\n
\n
    if (sheet) {\n
        css.title = sheet.title || sheet.href.match(/(?:^|\\/)([-\\w]+)\\.[a-z]+$/i)[1];\n
\n
        // Don\'t update the local store if the file wasn\'t modified\n
        if (lastModified && typeof(localStorage) !== "undefined") {\n
            localStorage.setItem(sheet.href, JSON.stringify({ timestamp: lastModified, css: styles }));\n
        }\n
    }\n
\n
    if (css.styleSheet) {\n
        css.styleSheet.cssText = styles;\n
    } else {\n
        css.appendChild(document.createTextNode(styles));\n
    }\n
    document.getElementsByTagName(\'head\')[0].appendChild(css);\n
}\n
\n
function xhr(url, callback, errback) {\n
    var xhr = getXMLHttpRequest();\n
\n
    if (window.location.protocol === "file:") {\n
        xhr.open(\'GET\', url, false);\n
        xhr.send(null);\n
        if (xhr.status === 0) {\n
            callback(xhr.responseText);\n
        } else {\n
            errback(xhr.status);\n
        }\n
    } else {\n
        xhr.open(\'GET\', url, true);\n
        xhr.onreadystatechange = function () {\n
            if (xhr.readyState == 4) {\n
                if (xhr.status >= 200 && xhr.status < 300) {\n
                    callback(xhr.responseText,\n
                             xhr.getResponseHeader("Last-Modified"));\n
                } else if (typeof(errback) === \'function\') {\n
                    errback(xhr.status);\n
                }\n
            }\n
        };\n
        xhr.send(null);\n
    }\n
}\n
\n
function getXMLHttpRequest() {\n
    if (window.XMLHttpRequest) {\n
        return new(XMLHttpRequest);\n
    } else {\n
        try {\n
            return new(ActiveXObject)("MSXML2.XMLHTTP.3.0");\n
        } catch (e) {\n
            log("less: browser doesn\'t support AJAX.");\n
            return null;\n
        }\n
    }\n
}\n
\n
function log(str) {\n
    if (less.env == \'development\' && typeof(console) !== "undefined") { console.log(str) }\n
}\n
\n
function error(e, href) {\n
    var template = [\'<div>\',\n
                        \'<pre class="ctx"><span>[-1]</span>{0}</pre>\',\n
                        \'<pre><span>[0]</span>{current}</pre>\',\n
                        \'<pre class="ctx"><span>[1]</span>{2}</pre>\',\n
                    \'</div>\'].join(\'\\n\');\n
\n
    var elem = document.createElement(\'div\'), timer;\n
    elem.id = "less-error-message";\n
    elem.innerHTML = \'<h3>\' + (e.message || \'There is an error in your .less file\') + \'</h3>\' +\n
                     \'<p><a href="\' + href   + \'">\' + href + "</a> "                +\n
                     \'on line \'     + e.line + \', column \' + (e.column + 1)         + \':</p>\' +\n
                     template.replace(/\\[(-?\\d)\\]/g, function (_, i) {\n
                         return e.line + parseInt(i);\n
                     }).replace(/\\{(\\d)\\}/g, function (_, i) {\n
                         return e.extract[parseInt(i)];\n
                     }).replace(/\\{current\\}/, e.extract[1].slice(0, e.column)      +\n
                                               \'<span class="error">\'               +\n
                                               e.extract[1].slice(e.column)         +\n
                                               \'</span>\');\n
    // CSS for error messages\n
    createCSS([\n
        \'#less-error-message span {\',\n
            \'margin-right: 15px;\',\n
        \'}\',\n
        \'#less-error-message pre {\',\n
            \'color: #ee4444;\',\n
            \'padding: 4px 0;\',\n
            \'margin: 0;\',\n
        \'}\',\n
        \'#less-error-message pre.ctx {\',\n
            \'color: #dd7777;\',\n
        \'}\',\n
        \'#less-error-message h3 {\',\n
            \'padding: 15px 0 5px 0;\',\n
            \'margin: 0;\',\n
        \'}\',\n
        \'#less-error-message a {\',\n
            \'color: #10a\',\n
        \'}\',\n
        \'#less-error-message .error {\',\n
            \'color: red;\',\n
            \'font-weight: bold;\',\n
            \'padding-bottom: 2px;\',\n
            \'border-bottom: 1px dashed red;\',\n
        \'}\'\n
    ].join(\'\'));\n
\n
    elem.style.cssText = [\n
        "font-family: Arial, sans-serif",\n
        "border: 1px solid #e00",\n
        "background-color: #eee",\n
        "border-radius: 5px",\n
        "color: #e00",\n
        "padding: 15px",\n
        "margin-bottom: 15px"\n
    ].join(\';\');\n
\n
    if (less.env == \'development\') {\n
        timer = setInterval(function () {\n
            if (document.body) {\n
                document.body.insertBefore(elem, document.body.childNodes[0]);\n
                clearInterval(timer);\n
            }\n
        }, 10);\n
    }\n
}\n
\n
less.Parser.importer = function (path, paths, callback) {\n
    loadStyleSheet({ href: path, title: path }, function (root) {\n
        callback(root);\n
    });\n
};\n
\n
})();\n
\n
// --- End less.js ---\n
\n
});\n
;bespin.tiki.register("::theme_manager_base", {\n
    name: "theme_manager_base",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("theme_manager_base:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
"define metadata";\n
({\n
    "description": "Defines extension points required for theming",\n
    "dependencies": { },\n
    "environments": { "main": true },\n
    "share": true,\n
    "provides": [\n
        {\n
            "ep": "extensionpoint",\n
            "name": "themestyles",\n
            "description": "(Less)files holding the CSS style information for the UI.",\n
\n
            "params": [\n
                {\n
                    "name": "url",\n
                    "required": true,\n
                    "description": "Name of the ThemeStylesFile - can also be an array of files."\n
                }\n
            ]\n
        },\n
        {\n
            "ep": "extensionpoint",\n
            "name": "themeChange",\n
            "description": "Event: Notify when the theme(styles) changed.",\n
\n
            "params": [\n
                {\n
                    "name": "pointer",\n
                    "required": true,\n
                    "description": "Function that is called whenever the theme is changed."\n
                }\n
            ]\n
\n
        },\n
        {\n
            "ep": "extensionpoint",\n
            "name": "theme",\n
            "indexOn": "name",\n
            "description": "A theme is a way change the look of the application.",\n
\n
            "params": [\n
                {\n
                    "name": "url",\n
                    "required": false,\n
                    "description": "Name of a ThemeStylesFile that holds theme specific CSS rules - can also be an array of files."\n
                },\n
                {\n
                    "name": "pointer",\n
                    "required": true,\n
                    "description": "Function that returns the ThemeData"\n
                }\n
            ]\n
        }\n
    ]\n
})\n
"end";\n
\n
});\n
;bespin.tiki.register("::keyboard", {\n
    name: "keyboard",\n
    dependencies: { "canon": "0.0.0", "settings": "0.0.0" }\n
});\n
bespin.tiki.module("keyboard:keyboard",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var console = require(\'bespin:console\').console;\n
var Trace = require(\'bespin:util/stacktrace\').Trace;\n
var util = require(\'bespin:util/util\');\n
\n
var settings = require(\'settings\').settings;\n
\n
var keyutil = require(\'keyboard:keyutil\');\n
var history = require(\'canon:history\');\n
var Request = require(\'canon:request\').Request;\n
var env = require(\'environment\').env;\n
\n
/*\n
 * Things to do to sanitize this code:\n
 * - \'no command\' is a bizarre special value at the very least it should be a\n
 *   constant to make typos more obvious, but it would be better to refactor\n
 *   so that a natural value like null worked.\n
 * - sender seems to be totally customized to the editor case, and the functions\n
 *   that we assume that it has make no sense for the commandLine case. We\n
 *   should either document and implement the same function set for both cases\n
 *   or admit that the cases are different enough to have separate\n
 *   implementations.\n
 * - remove remaining sproutcore-isms\n
 * - fold buildFlags into processKeyEvent or something better, preferably the\n
 *   latter. We don\'t want the environment to become a singleton\n
 */\n
\n
/**\n
 * Every time we call processKeyEvent, we pass in some flags that require the\n
 * same processing to set them up. This function can be called to do that\n
 * setup.\n
 * @param env Probably environment.env\n
 * @param flags Probably {} (but check other places where this is called)\n
 */\n
exports.buildFlags = function(flags) {\n
    flags.context = env.contexts[0];\n
    return flags;\n
};\n
\n
/**\n
 * The canon, or the repository of commands, contains functions to process\n
 * events and dispatch command messages to targets.\n
 * @class\n
 */\n
var KeyboardManager = function() { };\n
\n
util.mixin(KeyboardManager.prototype, {\n
    _customKeymappingCache: { states: {} },\n
\n
    /**\n
     * Searches through the command canon for an event matching the given flags\n
     * with a key equivalent matching the given SproutCore event, and, if the\n
     * command is found, sends a message to the appropriate target.\n
     *\n
     * This will get a couple of upgrades in the not-too-distant future:\n
     * 1. caching in the Canon for fast lookup based on key\n
     * 2. there will be an extra layer in between to allow remapping via\n
     *    user preferences and keyboard mapping plugins\n
     *\n
     * @return True if a matching command was found, false otherwise.\n
     */\n
    processKeyEvent: function(evt, sender, flags) {\n
        // Use our modified commandCodes function to detect the meta key in\n
        // more circumstances than SproutCore alone does.\n
        var symbolicName = keyutil.commandCodes(evt, true)[0];\n
        if (util.none(symbolicName)) {\n
            return false;\n
        }\n
\n
        // TODO: Maybe it should be the job of our caller to do this?\n
        exports.buildFlags(flags);\n
\n
        flags.isCommandKey = true;\n
        return this._matchCommand(symbolicName, sender, flags);\n
    },\n
\n
    _matchCommand: function(symbolicName, sender, flags) {\n
        var match = this._findCommandExtension(symbolicName, sender, flags);\n
        if (match && match.commandExt !== \'no command\') {\n
            if (flags.isTextView) {\n
                sender.resetKeyBuffers();\n
            }\n
\n
            var commandExt = match.commandExt;\n
            commandExt.load(function(command) {\n
                var request = new Request({\n
                    command: command,\n
                    commandExt: commandExt\n
                });\n
                history.execute(match.args, request);\n
            });\n
            return true;\n
        }\n
\n
        // \'no command\' is returned if a keyevent is handled but there is no\n
        // command executed (for example when switchting the keyboard state).\n
        if (match && match.commandExt === \'no command\') {\n
            return true;\n
        } else {\n
            return false;\n
        }\n
    },\n
\n
    _buildBindingsRegex: function(bindings) {\n
        // Escape a given Regex string.\n
        bindings.forEach(function(binding) {\n
            if (!util.none(binding.key)) {\n
                binding.key = new RegExp(\'^\' + binding.key + \'$\');\n
            } else if (Array.isArray(binding.regex)) {\n
                binding.key = new RegExp(\'^\' + binding.regex[1] + \'$\');\n
                binding.regex = new RegExp(binding.regex.join(\'\') + \'$\');\n
            } else {\n
                binding.regex = new RegExp(binding.regex + \'$\');\n
            }\n
        });\n
    },\n
\n
    /**\n
     * Build the RegExp from the keymapping as RegExp can\'t stored directly\n
     * in the metadata JSON and as the RegExp used to match the keys/buffer\n
     * need to be adapted.\n
     */\n
    _buildKeymappingRegex: function(keymapping) {\n
        for (state in keymapping.states) {\n
            this._buildBindingsRegex(keymapping.states[state]);\n
        }\n
        keymapping._convertedRegExp = true;\n
    },\n
\n
    /**\n
     * Loop through the commands in the canon, looking for something that\n
     * matches according to #_commandMatches, and return that.\n
     */\n
    _findCommandExtension: function(symbolicName, sender, flags) {\n
        // If the flags indicate that we handle the textView\'s input then take\n
        // a look at keymappings as well.\n
        if (flags.isTextView) {\n
            var currentState = sender._keyState;\n
\n
            // Don\'t add the symbolic name to the key buffer if the alt_ key is\n
            // part of the symbolic name. If it starts with alt_, this means\n
            // that the user hit an alt keycombo and there will be a single,\n
            // new character detected after this event, which then will be\n
            // added to the buffer (e.g. alt_j will result in ∆).\n
            if (!flags.isCommandKey || symbolicName.indexOf(\'alt_\') === -1) {\n
                sender._keyBuffer +=\n
                    symbolicName.replace(/ctrl_meta|meta/,\'ctrl\');\n
                sender._keyMetaBuffer += symbolicName;\n
            }\n
\n
            // List of all the keymappings to look at.\n
            var ak = [ this._customKeymappingCache ];\n
\n
            // Get keymapping extension points.\n
            ak = ak.concat(catalog.getExtensions(\'keymapping\'));\n
\n
            for (var i = 0; i < ak.length; i++) {\n
                // Check if the keymapping has the current state.\n
                if (util.none(ak[i].states[currentState])) {\n
                    continue;\n
                }\n
\n
                if (util.none(ak[i]._convertedRegExp)) {\n
                    this._buildKeymappingRegex(ak[i]);\n
                }\n
\n
                // Try to match the current mapping.\n
                var result = this._bindingsMatch(\n
                                    symbolicName,\n
                                    flags,\n
                                    sender,\n
                                    ak[i]);\n
\n
                if (!util.none(result)) {\n
                    return result;\n
                }\n
            }\n
        }\n
\n
        var commandExts = catalog.getExtensions(\'command\');\n
        var reply = null;\n
        var args = {};\n
\n
        symbolicName = symbolicName.replace(/ctrl_meta|meta/,\'ctrl\');\n
\n
        commandExts.some(function(commandExt) {\n
            if (this._commandMatches(commandExt, symbolicName, flags)) {\n
                reply = commandExt;\n
                return true;\n
            }\n
            return false;\n
        }.bind(this));\n
\n
        return util.none(reply) ? null : { commandExt: reply, args: args };\n
    },\n
\n
\n
    /**\n
     * Checks if the given parameters fit to one binding in the given bindings.\n
     * Returns the command and arguments if a command was matched.\n
     */\n
    _bindingsMatch: function(symbolicName, flags, sender, keymapping) {\n
        var match;\n
        var commandExt = null;\n
        var args = {};\n
        var bufferToUse;\n
\n
        if (!util.none(keymapping.hasMetaKey)) {\n
            bufferToUse = sender._keyBuffer;\n
        } else {\n
            bufferToUse = sender._keyMetaBuffer;\n
        }\n
\n
        // Add the alt_key to the buffer as we don\'t want it to be in the buffer\n
        // that is saved but for matching, it needs to be there.\n
        if (symbolicName.indexOf(\'alt_\') === 0 && flags.isCommandKey) {\n
            bufferToUse += symbolicName;\n
        }\n
\n
        // Loop over all the bindings of the keymapp until a match is found.\n
        keymapping.states[sender._keyState].some(function(binding) {\n
            // Check if the key matches.\n
            if (binding.key && !binding.key.test(symbolicName)) {\n
                return false;\n
            }\n
\n
            // Check if the regex matches.\n
            if (binding.regex && !(match = binding.regex.exec(bufferToUse))) {\n
                return false;\n
            }\n
\n
            // Check for disallowed matches.\n
            if (binding.disallowMatches) {\n
                for (var i = 0; i < binding.disallowMatches.length; i++) {\n
                    if (!!match[binding.disallowMatches[i]]) {\n
                        return true;\n
                    }\n
                }\n
            }\n
\n
            // Check predicates.\n
            if (!exports.flagsMatch(binding.predicates, flags)) {\n
                return false;\n
            }\n
\n
            // If there is a command to execute, then figure out the\n
            // comand and the arguments.\n
            if (binding.exec) {\n
                // Get the command.\n
                commandExt = catalog.getExtensionByKey(\'command\', binding.exec);\n
                if (util.none(commandExt)) {\n
                    throw new Error(\'Can\\\'t find command \' + binding.exec +\n
                        \' in state=\' + sender._keyState +\n
                        \', symbolicName=\' + symbolicName);\n
                }\n
\n
                // Bulid the arguments.\n
                if (binding.params) {\n
                    var value;\n
                    binding.params.forEach(function(param) {\n
                        if (!util.none(param.match) && !util.none(match)) {\n
                            value = match[param.match] || param.defaultValue;\n
                        } else {\n
                            value = param.defaultValue;\n
                        }\n
\n
                        if (param.type === \'number\') {\n
                            value = parseInt(value);\n
                        }\n
\n
                        args[param.name] = value;\n
                    });\n
                }\n
                sender.resetKeyBuffers();\n
            }\n
\n
            // Handle the \'then\' property.\n
            if (binding.then) {\n
                sender._keyState = binding.then;\n
                sender.resetKeyBuffers();\n
            }\n
\n
            // If there is no command matched now, then return a \'false\'\n
            // command to stop matching.\n
            if (util.none(commandExt)) {\n
                commandExt = \'no command\';\n
            }\n
\n
            return true;\n
        });\n
\n
        if (util.none(commandExt)) {\n
            return null;\n
        }\n
\n
        return { commandExt: commandExt, args: args };\n
    },\n
\n
    /**\n
     * Check that the given command fits the given key name and flags.\n
     */\n
    _commandMatches: function(commandExt, symbolicName, flags) {\n
        var mappedKeys = commandExt.key;\n
        if (!mappedKeys) {\n
            return false;\n
        }\n
\n
        // Check predicates\n
        if (!exports.flagsMatch(commandExt.predicates, flags)) {\n
            return false;\n
        }\n
\n
        if (typeof(mappedKeys) === \'string\') {\n
            if (mappedKeys != symbolicName) {\n
                return false;\n
            }\n
            return true;\n
        }\n
\n
        if (!Array.isArray(mappedKeys)) {\n
            mappedKeys = [mappedKeys];\n
            commandExt.key = mappedKeys;\n
        }\n
\n
        for (var i = 0; i < mappedKeys.length; i++) {\n
            var keymap = mappedKeys[i];\n
            if (typeof(keymap) === \'string\') {\n
                if (keymap == symbolicName) {\n
                    return true;\n
                }\n
                continue;\n
            }\n
\n
            if (keymap.key != symbolicName) {\n
                continue;\n
            }\n
\n
            return exports.flagsMatch(keymap.predicates, flags);\n
        }\n
        return false;\n
    },\n
\n
    /**\n
     * Build a cache of custom keymappings whenever the associated setting\n
     * changes.\n
     */\n
    _customKeymappingChanged: function() {\n
        var ckc = this._customKeymappingCache =\n
                            JSON.parse(settings.get(\'customKeymapping\'));\n
\n
        ckc.states = ckc.states || {};\n
\n
        for (state in ckc.states) {\n
            this._buildBindingsRegex(ckc.states[state]);\n
        }\n
        ckc._convertedRegExp = true;\n
    }\n
});\n
\n
/**\n
 *\n
 */\n
exports.flagsMatch = function(predicates, flags) {\n
    if (util.none(predicates)) {\n
        return true;\n
    }\n
\n
    if (!flags) {\n
        return false;\n
    }\n
\n
    for (var flagName in predicates) {\n
        if (flags[flagName] !== predicates[flagName]) {\n
            return false;\n
        }\n
    }\n
\n
    return true;\n
};\n
\n
/**\n
 * The global exported KeyboardManager\n
 */\n
exports.keyboardManager = new KeyboardManager();\n
\n
catalog.registerExtension(\'settingChange\', {\n
    match: "customKeymapping",\n
    pointer: exports.keyboardManager._customKeymappingChanged\n
                                        .bind(exports.keyboardManager)\n
});\n
\n
});\n
\n
bespin.tiki.module("keyboard:keyutil",function(require,exports,module) {\n
/*! @license\n
==========================================================================\n
SproutCore -- JavaScript Application Framework\n
copyright 2006-2009, Sprout Systems Inc., Apple Inc. and contributors.\n
\n
Permission is hereby granted, free of charge, to any person obtaining a\n
copy of this software and associated documentation files (the "Software"),\n
to deal in the Software without restriction, including without limitation\n
the rights to use, copy, modify, merge, publish, distribute, sublicense,\n
and/or sell copies of the Software, and to permit persons to whom the\n
Software is furnished to do so, subject to the following conditions:\n
\n
The above copyright notice and this permission notice shall be included in\n
all copies or substantial portions of the Software.\n
\n
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n
DEALINGS IN THE SOFTWARE.\n
\n
SproutCore and the SproutCore logo are trademarks of Sprout Systems, Inc.\n
\n
For more information about SproutCore, visit http://www.sproutcore.com\n
\n
\n
==========================================================================\n
@license */\n
\n
// Most of the following code is taken from SproutCore with a few changes.\n
\n
var util = require(\'bespin:util/util\');\n
\n
/**\n
 * Helper functions and hashes for key handling.\n
 */\n
exports.KeyHelper = function() {\n
    var ret = {\n
        MODIFIER_KEYS: {\n
            16: \'shift\', 17: \'ctrl\', 18: \'alt\', 224: \'meta\'\n
        },\n
\n
        FUNCTION_KEYS : {\n
              8: \'backspace\', 9: \'tab\',         13: \'return\',   19: \'pause\',\n
             27: \'escape\',   33: \'pageup\',      34: \'pagedown\', 35: \'end\',\n
             36: \'home\',     37: \'left\',        38: \'up\',       39: \'right\',\n
             40: \'down\',     44: \'printscreen\', 45: \'insert\',   46: \'delete\',\n
            112: \'f1\',      113: \'f2\',         114: \'f3\',      115: \'f4\',\n
            116: \'f5\',      117: \'f7\',         119: \'f8\',      120: \'f9\',\n
            121: \'f10\',     122: \'f11\',        123: \'f12\',     144: \'numlock\',\n
            145: \'scrolllock\'\n
        },\n
\n
        PRINTABLE_KEYS: {\n
           32: \' \',  48: \'0\',  49: \'1\',  50: \'2\',  51: \'3\',  52: \'4\', 53:  \'5\',\n
           54: \'6\',  55: \'7\',  56: \'8\',  57: \'9\',  59: \';\',  61: \'=\', 65:  \'a\',\n
           66: \'b\',  67: \'c\',  68: \'d\',  69: \'e\',  70: \'f\',  71: \'g\', 72:  \'h\',\n
           73: \'i\',  74: \'j\',  75: \'k\',  76: \'l\',  77: \'m\',  78: \'n\', 79:  \'o\',\n
           80: \'p\',  81: \'q\',  82: \'r\',  83: \'s\',  84: \'t\',  85: \'u\', 86:  \'v\',\n
           87: \'w\',  88: \'x\',  89: \'y\',  90: \'z\', 107: \'+\', 109: \'-\', 110: \'.\',\n
          188: \',\', 190: \'.\', 191: \'/\', 192: \'`\', 219: \'[\', 220: \'\\\\\',\n
          221: \']\', 222: \'\\"\'\n
        },\n
\n
        /**\n
         * Create the lookup table for Firefox to convert charCodes to keyCodes\n
         * in the keyPress event.\n
         */\n
        PRINTABLE_KEYS_CHARCODE: {},\n
\n
        /**\n
         * Allow us to lookup keyCodes by symbolic name rather than number\n
         */\n
        KEY: {}\n
    };\n
\n
    // Create the PRINTABLE_KEYS_CHARCODE hash.\n
    for (var i in ret.PRINTABLE_KEYS) {\n
        var k = ret.PRINTABLE_KEYS[i];\n
        ret.PRINTABLE_KEYS_CHARCODE[k.charCodeAt(0)] = i;\n
        if (k.toUpperCase() != k) {\n
            ret.PRINTABLE_KEYS_CHARCODE[k.toUpperCase().charCodeAt(0)] = i;\n
        }\n
    }\n
\n
    // A reverse map of FUNCTION_KEYS\n
    for (i in ret.FUNCTION_KEYS) {\n
        var name = ret.FUNCTION_KEYS[i].toUpperCase();\n
        ret.KEY[name] = parseInt(i, 10);\n
    }\n
\n
    return ret;\n
}();\n
\n
/**\n
 * Determines if the keyDown event is a non-printable or function key.\n
 * These kinds of events are processed as keyboard shortcuts.\n
 * If no shortcut handles the event, then it will be sent as a regular\n
 * keyDown event.\n
 * @private\n
 */\n
var isFunctionOrNonPrintableKey = function(evt) {\n
    return !!(evt.altKey || evt.ctrlKey || evt.metaKey ||\n
            ((evt.charCode !== evt.which) &&\n
                    exports.KeyHelper.FUNCTION_KEYS[evt.which]));\n
};\n
\n
/**\n
 * Returns character codes for the event.\n
 * The first value is the normalized code string, with any Shift or Ctrl\n
 * characters added to the beginning.\n
 * The second value is the char string by itself.\n
 * @return {Array}\n
 */\n
exports.commandCodes = function(evt, dontIgnoreMeta) {\n
    var code = evt._keyCode || evt.keyCode;\n
    var charCode = (evt._charCode === undefined ? evt.charCode : evt._charCode);\n
    var ret = null;\n
    var key = null;\n
    var modifiers = \'\';\n
    var lowercase;\n
    var allowShift = true;\n
\n
    // Absent a value for \'keyCode\' or \'which\', we can\'t compute the\n
    // command codes. Bail out.\n
    if (code === 0 && evt.which === 0) {\n
        return false;\n
    }\n
\n
    // If the charCode is not zero, then we do not handle a command key\n
    // here. Bail out.\n
    if (charCode !== 0) {\n
        return false;\n
    }\n
\n
    // Check for modifier keys.\n
    if (exports.KeyHelper.MODIFIER_KEYS[charCode]) {\n
        return [exports.KeyHelper.MODIFIER_KEYS[charCode], null];\n
    }\n
\n
    // handle function keys.\n
    if (code) {\n
        ret = exports.KeyHelper.FUNCTION_KEYS[code];\n
        if (!ret && (evt.altKey || evt.ctrlKey || evt.metaKey)) {\n
            ret = exports.KeyHelper.PRINTABLE_KEYS[code];\n
            // Don\'t handle the shift key if the combo is\n
            //    (meta_|ctrl_)<number>\n
            // This is necessary for the French keyboard. On that keyboard,\n
            // you have to hold down the shift key to access the number\n
            // characters.\n
            if (code > 47 && code < 58) {\n
                allowShift = evt.altKey;\n
            }\n
        }\n
\n
        if (ret) {\n
           if (evt.altKey) {\n
               modifiers += \'alt_\';\n
           }\n
           if (evt.ctrlKey) {\n
               modifiers += \'ctrl_\';\n
           }\n
           if (evt.metaKey) {\n
               modifiers += \'meta_\';\n
           }\n
        } else if (evt.ctrlKey || evt.metaKey) {\n
            return false;\n
        }\n
    }\n
\n
    // otherwise just go get the right key.\n
    if (!ret) {\n
        code = evt.which;\n
        key = ret = String.fromCharCode(code);\n
        lowercase = ret.toLowerCase();\n
\n
        if (evt.metaKey) {\n
           modifiers = \'meta_\';\n
           ret = lowercase;\n
\n
        } else ret = null;\n
    }\n
\n
    if (evt.shiftKey && ret && allowShift) {\n
        modifiers += \'shift_\';\n
    }\n
\n
    if (ret) {\n
        ret = modifiers + ret;\n
    }\n
\n
    if (!dontIgnoreMeta && ret) {\n
        ret = ret.replace(/ctrl_meta|meta/,\'ctrl\');\n
    }\n
\n
    return [ret, key];\n
};\n
\n
// Note: Most of the following code is taken from SproutCore with a few changes.\n
\n
/**\n
 * Firefox sends a few key events twice: the first time to the keydown event\n
 * and then later again to the keypress event. To handle them correct, they\n
 * should be processed only once. Due to this, we will skip these events\n
 * in keydown and handle them then in keypress.\n
 */\n
exports.addKeyDownListener = function(element, boundFunction) {\n
\n
    var handleBoundFunction = function(ev) {\n
        var handled = boundFunction(ev);\n
        // If the boundFunction returned true, then stop the event.\n
        if (handled) {\n
            util.stopEvent(ev);\n
        }\n
        return handled;\n
    };\n
\n
    element.addEventListener(\'keydown\', function(ev) {\n
        if (util.isMozilla) {\n
            // Check for function keys (like DELETE, TAB, LEFT, RIGHT...)\n
            if (exports.KeyHelper.FUNCTION_KEYS[ev.keyCode]) {\n
                return true;\n
                // Check for command keys (like ctrl_c, ctrl_z...)\n
            } else if ((ev.ctrlKey || ev.metaKey) &&\n
                    exports.KeyHelper.PRINTABLE_KEYS[ev.keyCode]) {\n
                return true;\n
            }\n
        }\n
\n
        if (isFunctionOrNonPrintableKey(ev)) {\n
            return handleBoundFunction(ev);\n
        }\n
\n
        return true;\n
    }, false);\n
\n
    element.addEventListener(\'keypress\', function(ev) {\n
        if (util.isMozilla) {\n
            // If this is a function key, we have to use the keyCode.\n
            if (exports.KeyHelper.FUNCTION_KEYS[ev.keyCode]) {\n
                return handleBoundFunction(ev);\n
            } else if ((ev.ctrlKey || ev.metaKey) &&\n
                    exports.KeyHelper.PRINTABLE_KEYS_CHARCODE[ev.charCode]){\n
                // Check for command keys (like ctrl_c, ctrl_z...).\n
                // For command keys have to convert the charCode to a keyCode\n
                // as it has been sent from the keydown event to be in line\n
                // with the other browsers implementations.\n
\n
                // FF does not allow let you change the keyCode or charCode\n
                // property. Store to a custom keyCode/charCode variable.\n
                // The getCommandCodes() function takes care of these\n
                // special variables.\n
                ev._keyCode = exports.KeyHelper.PRINTABLE_KEYS_CHARCODE[ev.charCode];\n
                ev._charCode = 0;\n
                return handleBoundFunction(ev);\n
            }\n
        }\n
\n
        // normal processing: send keyDown for printable keys.\n
        if (ev.charCode !== undefined && ev.charCode === 0) {\n
            return true;\n
        }\n
\n
        return handleBoundFunction(ev);\n
    }, false);\n
};\n
\n
});\n
\n
bespin.tiki.module("keyboard:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::edit_session", {\n
    name: "edit_session",\n
    dependencies: { "events": "0.0.0" }\n
});\n
bespin.tiki.module("edit_session:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Promise = require(\'bespin:promise\').Promise;\n
var catalog = require(\'bespin:plugins\').catalog;\n
var util = require(\'bespin:util/util\');\n
\n
var Event = require("events").Event;\n
\n
exports.EditSession = function() { };\n
\n
exports.EditSession.prototype = {\n
    /**\n
     * @property{TextView}\n
     *\n
     * The \'current\' view is the editor component that most recently had\n
     * the focus.\n
     */\n
    _currentView: null,\n
\n
\n
    /**\n
     * @type{string}\n
     * The name of the user, or null if no user is logged in.\n
     */\n
    currentUser: null,\n
\n
    /**\n
     * The history object to store file history in.\n
     */\n
    history: null,\n
\n
    /**\n
     * figures out the full path, taking into account the current file\n
     * being edited.\n
     */\n
    getCompletePath: function(path) {\n
        if (path == null) {\n
            path = \'\';\n
        }\n
\n
        if (path == null || path.substring(0, 1) != \'/\') {\n
            var buffer;\n
            if (this._currentView && this._currentView.buffer) {\n
                buffer = this._currentView.buffer;\n
            }\n
            var file;\n
            if (buffer) {\n
                file = buffer.file;\n
            }\n
            if (!file) {\n
                path = \'/\' + path;\n
            } else {\n
                path = file.parentdir() + path;\n
            }\n
        }\n
\n
        return path;\n
    }\n
};\n
\n
Object.defineProperties(exports.EditSession.prototype, {\n
    currentView: {\n
        set: function(newView) {\n
            var oldView = this._currentView;\n
            if (newView !== oldView) {\n
                this._currentView = newView;\n
            }\n
        },\n
        \n
        get: function() {\n
            return this._currentView;\n
        }\n
    }\n
});\n
\n
/*\n
 * set up a session based on a view. This seems a bit convoluted and is\n
 * likely to change.\n
 */\n
exports.createSession = function(view, user) {\n
    var session = new exports.EditSession();\n
    if (view) {\n
        session.currentView = view.textView;\n
    }\n
    if (user) {\n
        session.currentUser = user;\n
    }\n
    return session;\n
};\n
\n
});\n
;bespin.tiki.register("::completion", {\n
    name: "completion",\n
    dependencies: { "jquery": "0.0.0", "ctags": "0.0.0", "rangeutils": "0.0.0", "canon": "0.0.0", "underscore": "0.0.0" }\n
});\n
bespin.tiki.module("completion:ui",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var $ = require(\'jquery\').$;\n
var _ = require(\'underscore\')._;\n
\n
var ANIMATION_SPEED = 100;  // in ms\n
\n
var populate_container_template =\n
    _.template(\'<span class="bespin-completion-container"> &mdash; \' +\n
        \'<%= container %></span>\');\n
var populate_second_row_template =\n
    _.template(\'<div class="bespin-completion-second-row"><%= type %></div>\');\n
var populate_item_template =\n
    _.template(\'<li><div class="bespin-completion-top-row">\' +\n
        \'<span class="bespin-completion-kind bespin-completion-kind-\' +\n
            \'<%= kind %>"><%= kind %></span>\' +\n
        \'<span class="bespin-completion-ident"><%= ident %></span>\' +\n
            \'<%= container %></div><%= second_row %></li>\');\n
\n
function CompletionUI(parent) {\n
    var id = _.uniqueId(\'bespin-completion-panel\');\n
\n
    var panel = document.createElement("div");\n
    panel.id = id;\n
    panel.className = "bespin-completion-panel";\n
    panel.style.display = \'none\';\n
    panel.innerHTML =\n
        \'<div class="bespin-completion-pointer"></div>\' +\n
        \'<div class="bespin-completion-bubble-outer">\' +\n
            \'<div class="bespin-completion-bubble-inner">\' +\n
                \'<div class="bespin-completion-highlight"></div>\' +\n
                \'<ul></ul>\' +\n
            \'</div>\' +\n
        \'</div>\';\n
\n
    $(parent).append(panel);\n
\n
    this.panel = $(panel);\n
    this.parent = $(parent);\n
}\n
\n
CompletionUI.prototype = {\n
    _fromBottom: false,\n
    _index: 0,\n
    _tags: null,\n
\n
    _getHighlightDimensions: function(elem) {\n
        var pos = elem.position();\n
        var height = elem.outerHeight() - 2;\n
        var width = elem.outerWidth() - 2;\n
        return { left: pos.left, top: pos.top, height: height, width: width };\n
    },\n
\n
    _listItemForIndex: function(idx) {\n
        return this.panel.find("li:eq(" + idx + ")");\n
    },\n
\n
    _populate: function() {\n
        var html = _(this._tags).map(function(tag) {\n
            var klass = tag[\'class\'], module = tag.module, ns = tag.namespace;\n
\n
            var container;\n
            if (klass != null) {\n
                container = klass;\n
            } else if (ns != null) {\n
                container = ns;\n
            } else {\n
                container = "";\n
            }\n
\n
            if (module != null) {\n
                container = module + (container != "" ? "#" + container : "");\n
            }\n
\n
            var container_html = (container == "") ? "" :\n
                populate_container_template({ container: container });\n
\n
            var type = tag.type;\n
            var second_row_html = (type == null) ? "" :\n
                populate_second_row_template({ type: type });\n
\n
            return populate_item_template({\n
                kind:       tag.kind,\n
                ident:      tag.name,\n
                container:  container_html,\n
                second_row: second_row_html\n
            });\n
        });\n
\n
        this.panel.find("ul").html(html.join("\\n"));\n
    },\n
\n
    panel: null,\n
    visible: false,\n
\n
    getCompletion: function() {\n
        return this.visible ? this._tags[this._index] : null;\n
    },\n
\n
    hide: function() {\n
        if (!this.visible) {\n
            return;\n
        }\n
\n
        this.panel.fadeOut(ANIMATION_SPEED);\n
        this.visible = false;\n
    },\n
\n
    move: function(dir) {\n
        var index = this._index;\n
\n
        var sel = this._listItemForIndex(index);\n
\n
        var unsel = (dir === \'up\') ? sel.prev() : sel.next();\n
        if (unsel.length === 0) {\n
            return;\n
        }\n
\n
        index = (dir === \'up\') ? index - 1 : index + 1;\n
        this._index = index;\n
\n
        var selFirstRow = $(sel).find(\'.bespin-completion-top-row\');\n
        var selSecondRow = $(sel).find(\'.bespin-completion-second-row\');\n
        var unselFirstRow = $(unsel).find(\'.bespin-completion-top-row\');\n
        var unselSecondRow = $(unsel).find(\'.bespin-completion-second-row\');\n
\n
        selSecondRow.hide();\n
        unselSecondRow.show();\n
\n
        var highlight = this.panel.find(".bespin-completion-highlight");\n
        highlight.stop(true, true);\n
        var highlightDimensions = this._getHighlightDimensions(unsel);\n
        highlight.animate(highlightDimensions, ANIMATION_SPEED);\n
        unselSecondRow.hide();\n
\n
        if (dir === \'down\') {\n
            var height = selSecondRow.height();\n
            unselFirstRow.css(\'top\', height);\n
            unselFirstRow.animate({ top: 0 }, ANIMATION_SPEED);\n
        } else {\n
            var height = unselSecondRow.height();\n
            selFirstRow.css(\'top\', -height);\n
            selFirstRow.animate({ top: 0 }, ANIMATION_SPEED);\n
        }\n
\n
        unselSecondRow.fadeIn();\n
    },\n
\n
    show: function(tags, point, lineHeight) {\n
        var tags = _(tags).clone();\n
        this._tags = tags;\n
\n
        this._populate();\n
\n
        var visible = this.visible;\n
        var panel = this.panel;\n
        panel.stop(true, true);\n
        if (!visible) {\n
            panel.show();\n
        }\n
\n
        var parentOffset = this.parent.offset();\n
        var parentX = parentOffset.left, parentY = parentOffset.top;\n
        var absX = parentX + point.x, absY = parentY + point.y;\n
\n
        var panelWidth = panel.outerWidth(), panelHeight = panel.outerHeight();\n
        var windowWidth = $(window).width(), windowHeight = $(window).height();\n
\n
        var fromBottom = absY + panelHeight + lineHeight > windowHeight;\n
        this._fromBottom = fromBottom;\n
\n
        if (this._index >= tags.length) {\n
            this._index = tags.length - 1;\n
        }\n
\n
        var pointer;\n
        if (fromBottom) {\n
            pointer = panel.find(\'.bespin-completion-pointer\');\n
            pointer.removeClass(\'bespin-completion-pointer-up\');\n
            pointer.addClass(\'bespin-completion-pointer-down\');\n
            panel.css({ bottom: -point.y, top: "" });\n
\n
            // Reverse the list.\n
            this._tags.reverse();\n
            this._populate();\n
\n
            if (!visible) {\n
                this._index = tags.length - 1;\n
            }\n
        } else {\n
            pointer = panel.find(\'.bespin-completion-pointer\');\n
            pointer.removeClass(\'bespin-completion-pointer-down\');\n
            pointer.addClass(\'bespin-completion-pointer-up\');\n
            panel.css({ top: point.y + lineHeight, bottom: "" });\n
\n
            if (!visible) {\n
                this._index = 0;\n
            }\n
        }\n
\n
        if (!visible) {\n
            var fromRight = absX + point.x + panelWidth > windowWidth;\n
            if (fromRight) {\n
                pointer.css({ left: "", right: 32 });\n
                panel.css(\'left\', Math.min(windowWidth - panelWidth - parentX,\n
                    point.x - panelWidth + 43));\n
            } else {\n
                pointer.css({ left: 32, right: "" });\n
                panel.css(\'left\', Math.max(parentX, point.x - 43));\n
            }\n
\n
            panel.hide().animate({ opacity: \'show\' }, ANIMATION_SPEED);\n
        }\n
\n
        var highlight = panel.find(".bespin-completion-highlight");\n
        highlight.stop(true, true);\n
        var sel = this._listItemForIndex(this._index);\n
        sel.find(".bespin-completion-second-row").show();\n
\n
        var highlightDimensions = this._getHighlightDimensions(sel);\n
        var highlightWidth = highlightDimensions.width;\n
        var highlightHeight = highlightDimensions.height;\n
        highlight.css(highlightDimensions);\n
\n
        this.visible = true;\n
    }\n
};\n
\n
exports.CompletionUI = CompletionUI;\n
\n
\n
});\n
\n
bespin.tiki.module("completion:controller",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var ctags = require(\'ctags\');\n
var range = require(\'rangeutils:utils/range\');\n
var CompletionUI = require(\'completion:ui\').CompletionUI;\n
var catalog = require(\'bespin:plugins\').catalog;\n
var env = require(\'environment\').env;\n
\n
function CompletionController(editorView) {\n
    this._editorView = editorView;\n
    editorView.selectionChanged.add(this._selectionChanged.bind(this));\n
    editorView.willChangeBuffer.add(this._willChangeBuffer.bind(this));\n
\n
    // Prebind _syntaxChanged so that we can attach and detach it.\n
    this._syntaxChanged = this._syntaxChanged.bind(this);\n
\n
    this.tags = new ctags.Tags();\n
    this.ui = new CompletionUI(editorView.element);\n
}\n
\n
CompletionController.prototype = {\n
    _buffer: null,\n
    _completionEngine: null,\n
    _completions: null,\n
    _stem: null,\n
\n
    _hideCompletions: function() {\n
        this.ui.hide();\n
    },\n
\n
    _selectionChanged: function(newRange) {\n
        var engine = this._completionEngine;\n
        if (engine == null || !range.isZeroLength(newRange)) {\n
            return;\n
        }\n
\n
        var layoutManager = this._buffer.layoutManager;\n
        var textStorage = layoutManager.textStorage;\n
        var syntaxManager = layoutManager.syntaxManager;\n
\n
        var pos = newRange.start;\n
        var row = pos.row, col = pos.col;\n
        var line = textStorage.lines[row];\n
        var prefix = line.substring(0, col), suffix = line.substring(col);\n
\n
        var completions = engine.getCompletions(prefix, suffix, syntaxManager);\n
        if (completions == null) {\n
            this._hideCompletions();\n
            return;\n
        }\n
\n
        var tags = completions.tags;\n
        this._stem = completions.stem;\n
        this._showCompletions(tags);\n
    },\n
\n
    _showCompletions: function(completions) {\n
        var editorView = this._editorView;\n
        var cursorPt = editorView.textView.getInsertionPointPosition();\n
        var pt = editorView.convertTextViewPoint(cursorPt);\n
        var lineHeight = editorView.layoutManager.fontDimension.lineHeight;\n
        this.ui.show(completions, pt, lineHeight);\n
    },\n
\n
    _syntaxChanged: function(newSyntax) {\n
        var ext = catalog.getExtensionByKey(\'completion\', newSyntax);\n
        if (ext == null) {\n
            this._completionEngine = null;\n
            return;\n
        }\n
\n
        ext.load().then(function(engine) {\n
            this._completionEngine = new engine(this.tags);\n
        }.bind(this));\n
    },\n
\n
    _willChangeBuffer: function(newBuffer) {\n
        var oldBuffer = this._buffer;\n
        if (oldBuffer != null) {\n
            var oldSyntaxManager = oldBuffer.layoutManager.syntaxManager;\n
            oldSyntaxManager.syntaxChanged.remove(this._syntaxChanged);\n
        }\n
\n
        var newSyntaxManager = newBuffer.layoutManager.syntaxManager;\n
        newSyntaxManager.syntaxChanged.add(this._syntaxChanged);\n
\n
        this._buffer = newBuffer;\n
    },\n
\n
    cancel: function(env) {\n
        this.ui.hide();\n
    },\n
\n
    complete: function(env) {\n
        var ui = this.ui;\n
        var tag = ui.getCompletion();\n
        var ident = tag.name;\n
        env.view.insertText(ident.substring(this._stem.length));\n
        ui.hide();\n
    },\n
\n
    isCompleting: function() {\n
        return this.ui.visible;\n
    },\n
\n
    moveDown: function(env) {\n
        this.ui.move(\'down\');\n
    },\n
\n
    moveUp: function(env) {\n
        this.ui.move(\'up\');\n
    },\n
\n
    /** The current store of tags. */\n
    tags: null\n
};\n
\n
function makeCommand(name) {\n
    return function(args, req) {\n
        return env.editor.completionController[name](env);\n
    };\n
}\n
\n
exports.CompletionController = CompletionController;\n
exports.completeCommand = makeCommand(\'complete\');\n
exports.completeCancelCommand = makeCommand(\'cancel\');\n
exports.completeDownCommand = makeCommand(\'moveDown\');\n
exports.completeUpCommand = makeCommand(\'moveUp\');\n
\n
\n
});\n
\n
bespin.tiki.module("completion:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::rangeutils", {\n
    name: "rangeutils",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("rangeutils:utils/range",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
\n
/**\n
 * Returns the result of adding the two positions.\n
 */\n
exports.addPositions = function(a, b) {\n
    return { row: a.row + b.row, col: a.col + b.col };\n
};\n
\n
/** Returns a copy of the given range. */\n
exports.cloneRange = function(range) {\n
    var oldStart = range.start, oldEnd = range.end;\n
    var newStart = { row: oldStart.row, col: oldStart.col };\n
    var newEnd = { row: oldEnd.row, col: oldEnd.col };\n
    return { start: newStart, end: newEnd };\n
};\n
\n
/**\n
 * Given two positions a and b, returns a negative number if a < b, 0 if a = b,\n
 * or a positive number if a > b.\n
 */\n
exports.comparePositions = function(positionA, positionB) {\n
    var rowDiff = positionA.row - positionB.row;\n
    return rowDiff === 0 ? positionA.col - positionB.col : rowDiff;\n
};\n
\n
/**\n
 * Returns true if the two ranges are equal and false otherwise.\n
 */\n
exports.equal = function(rangeA, rangeB) {\n
    return (exports.comparePositions(rangeA.start, rangeB.start) === 0 &&\n
                exports.comparePositions(rangeA.end, rangeB.end) === 0);\n
};\n
\n
exports.extendRange = function(range, delta) {\n
    var end = range.end;\n
    return {\n
        start: range.start,\n
        end:   {\n
            row: end.row + delta.row,\n
            col: end.col + delta.col\n
        }\n
    };\n
};\n
\n
/**\n
 * Given two sets of ranges, returns the ranges of characters that exist in one\n
 * of the sets but not both.\n
 */\n
exports.intersectRangeSets = function(setA, setB) {\n
    var stackA = util.clone(setA), stackB = util.clone(setB);\n
    var result = [];\n
    while (stackA.length > 0 && stackB.length > 0) {\n
        var rangeA = stackA.shift(), rangeB = stackB.shift();\n
        var startDiff = exports.comparePositions(rangeA.start, rangeB.start);\n
        var endDiff = exports.comparePositions(rangeA.end, rangeB.end);\n
\n
        if (exports.comparePositions(rangeA.end, rangeB.start) < 0) {\n
            // A is completely before B\n
            result.push(rangeA);\n
            stackB.unshift(rangeB);\n
        } else if (exports.comparePositions(rangeB.end, rangeA.start) < 0) {\n
            // B is completely before A\n
            result.push(rangeB);\n
            stackA.unshift(rangeA);\n
        } else if (startDiff < 0) {     // A starts before B\n
            result.push({ start: rangeA.start, end: rangeB.start });\n
            stackA.unshift({ start: rangeB.start, end: rangeA.end });\n
            stackB.unshift(rangeB);\n
        } else if (startDiff === 0) {   // A and B start at the same place\n
            if (endDiff < 0) {          // A ends before B\n
                stackB.unshift({ start: rangeA.end, end: rangeB.end });\n
            } else if (endDiff > 0) {   // A ends after B\n
                stackA.unshift({ start: rangeB.end, end: rangeA.end });\n
            }\n
        } else if (startDiff > 0) {     // A starts after B\n
            result.push({ start: rangeB.start, end: rangeA.start });\n
            stackA.unshift(rangeA);\n
            stackB.unshift({ start: rangeA.start, end: rangeB.end });\n
        }\n
    }\n
    return result.concat(stackA, stackB);\n
};\n
\n
exports.isZeroLength = function(range) {\n
    return range.start.row === range.end.row &&\n
        range.start.col === range.end.col;\n
};\n
\n
/**\n
 * Returns the greater of the two positions.\n
 */\n
exports.maxPosition = function(a, b) {\n
    return exports.comparePositions(a, b) > 0 ? a : b;\n
};\n
\n
/**\n
 * Converts a range with swapped \'end\' and \'start\' values into one with the\n
 * values in the correct order.\n
 *\n
 * TODO: Unit test.\n
 */\n
exports.normalizeRange = function(range) {\n
    return this.comparePositions(range.start, range.end) < 0 ? range :\n
        { start: range.end, end: range.start };\n
};\n
\n
/**\n
 * Returns a single range that spans the entire given set of ranges.\n
 */\n
exports.rangeSetBoundaries = function(rangeSet) {\n
    return {\n
        start:  rangeSet[0].start,\n
        end:    rangeSet[rangeSet.length - 1].end\n
    };\n
};\n
\n
exports.toString = function(range) {\n
    var start = range.start, end = range.end;\n
    return \'[ \' + start.row + \', \' + start.col + \' \' + end.row + \',\' + + end.col +\' ]\';\n
};\n
\n
/**\n
 * Returns the union of the two ranges.\n
 */\n
exports.unionRanges = function(a, b) {\n
    return {\n
        start:  a.start.row < b.start.row ||\n
            (a.start.row === b.start.row && a.start.col < b.start.col) ?\n
            a.start : b.start,\n
        end:    a.end.row > b.end.row ||\n
            (a.end.row === b.end.row && a.end.col > b.end.col) ?\n
            a.end : b.end\n
    };\n
};\n
\n
exports.isPosition = function(pos) {\n
    return !util.none(pos) && !util.none(pos.row) && !util.none(pos.col);\n
};\n
\n
exports.isRange = function(range) {\n
    return (!util.none(range) && exports.isPosition(range.start) &&\n
                                                exports.isPosition(range.end));\n
};\n
\n
});\n
\n
bespin.tiki.module("rangeutils:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::undomanager", {\n
    name: "undomanager",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("undomanager:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var env = require(\'environment\').env;\n
\n
/**\n
 * This simple undo manager coordinates undo for the app that embeds Bespin.\n
 * It\'s similar to SproutCore\'s UndoManager class, but it separates undo and\n
 * redo and correctly flushes the redo stack when an action is performed.\n
 */\n
exports.UndoManager = function() {};\n
\n
util.mixin(exports.UndoManager.prototype, {\n
    _redoStack: [],\n
    _undoStack: [],\n
\n
    _undoOrRedo: function(method, stack, otherStack) {\n
        if (stack.length === 0) {\n
            return false;\n
        }\n
\n
        var record = stack.pop();\n
        if (!record.target[method](record.context)) {\n
            this._redoStack = [];\n
            this._undoStack = [];\n
            return false;\n
        }\n
\n
        otherStack.push(record);\n
        return true;\n
    },\n
\n
    /**\n
     * Redo the last undone action.\n
     * @return{boolean} True if the action was successfully redone, false\n
     *     otherwise.\n
     */\n
    redo: function() {\n
        return this._undoOrRedo(\'redo\', this._redoStack, this._undoStack);\n
    },\n
\n
    /**\n
     * Notifies the undo manager that an action was performed. When the action\n
     * is to be undone, the \'undo\' message will be sent to the target with the\n
     * given context. When the action is to be redone, the \'redo\' message is\n
     * sent in the same way.\n
     */\n
    registerUndo: function(target, context) {\n
        this._redoStack = [];\n
        this._undoStack.push({ target: target, context: context });\n
    },\n
\n
    /**\n
     * Undoes the last action.\n
     *\n
     * @return{boolean} True if the action was successfully undone, false\n
     *     otherwise.\n
     */\n
    undo: function() {\n
        return this._undoOrRedo(\'undo\', this._undoStack, this._redoStack);\n
    }\n
});\n
\n
exports.global = new exports.UndoManager();\n
\n
/**\n
 *\n
 */\n
exports.undoManagerCommand = function(args, request) {\n
    exports.global[request.commandExt.name]();\n
};\n
\n
});\n
;bespin.tiki.register("::ctags", {\n
    name: "ctags",\n
    dependencies: { "traits": "0.0.0", "underscore": "0.0.0" }\n
});\n
bespin.tiki.module("ctags:reader",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var _ = require(\'underscore\')._;\n
var Trait = require(\'traits\').Trait;\n
\n
exports.TagReader = Trait({\n
    readLines: function(lines) {\n
        var tags = [];\n
\n
        _(lines).each(function(line) {\n
            var parts = line.split("\\t");\n
            if (parts.length < 3) {\n
                return;\n
            }\n
\n
            var name = parts[0];\n
            if (/^!_TAG_/.test(name)) {\n
                return;\n
            }\n
\n
            // TODO: cope with tab characters in the addr\n
            var tag = { name: name, tagfile: parts[1], addr: parts[2] };\n
\n
            var fieldIndex;\n
            if (parts.length > 3 && parts[3].indexOf(":") === -1) {\n
                tag.kind = parts[3];\n
                fieldIndex = 4;\n
            } else {\n
                fieldIndex = 3;\n
            }\n
\n
            var fields = {};\n
            _(parts.slice(fieldIndex)).each(function(field) {\n
                var match = /^([^:]+):(.*)/.exec(field);\n
                fields[match[1]] = match[2];\n
            });\n
            tag.fields = fields;\n
\n
            tags.push(tag);\n
        });\n
\n
        this.add(tags);\n
    },\n
\n
    readString: function(str) {\n
        this.readLines(str.split("\\n"));\n
    }\n
});\n
\n
\n
});\n
\n
bespin.tiki.module("ctags:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var _ = require(\'underscore\')._;\n
var TagReader = require(\'./reader\').TagReader;\n
var Trait = require(\'traits\').Trait;\n
\n
exports.Tags = function() {\n
    this.tags = [];\n
};\n
\n
exports.Tags.prototype = Object.create(Object.prototype, Trait.compose(Trait({\n
    _search: function(id, pred) {\n
        var shadowTag = { name: id };\n
        var tags = this.tags;\n
        var index = _(tags).sortedIndex(shadowTag, function(tag) {\n
            return tag.name;\n
        });\n
\n
        var start = index, end = index;\n
        while (start >= 0 && start < tags.length && pred(tags[start])) {\n
            start--;\n
        }\n
        while (end >= 0 && end < tags.length && pred(tags[end])) {\n
            end++;\n
        }\n
\n
        return tags.slice(start + 1, end);\n
    },\n
\n
    add: function(newTags) {\n
        var tags = this.tags;\n
        Array.prototype.push.apply(tags, newTags);\n
\n
        tags.sort(function(a, b) {\n
            var nameA = a.name, nameB = b.name;\n
            if (nameA < nameB) {\n
                return -1;\n
            }\n
            if (nameA === nameB) {\n
                return 0;\n
            }\n
            return 1;\n
        });\n
    },\n
\n
    /** Returns all the tags that match the given identifier. */\n
    get: function(id) {\n
        return this._search(id, function(tag) { return tag.name === id; });\n
    },\n
\n
    /**\n
     * Adds the tags from the supplied JavaScript file to the internal store of\n
     * tags.\n
     */\n
    scan: function(src, file, opts) {\n
        if (opts === null || opts === undefined) {\n
            opts = {};\n
        }\n
\n
        var lines = src.split("\\n");\n
        var ast = parse(src, file, 1);\n
\n
        var interp = new Interpreter(ast, file, lines, opts);\n
        interp.interpret();\n
        this.add(interp.tags);\n
    },\n
\n
    /** Returns all the tags that begin with the given prefix. */\n
    stem: function(prefix) {\n
        var len = prefix.length;\n
        return this._search(prefix, function(tag) {\n
            return tag.name.substring(0, len) === prefix;\n
        });\n
    }\n
}), TagReader));\n
\n
\n
});\n
;bespin.tiki.register("::theme_manager", {\n
    name: "theme_manager",\n
    dependencies: { "theme_manager_base": "0.0.0", "settings": "0.0.0", "events": "0.0.0", "less": "0.0.0" }\n
});\n
bespin.tiki.module("theme_manager:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Promise = require(\'bespin:promise\').Promise;\n
var catalog = require(\'bespin:plugins\').catalog;\n
var Event = require(\'events\').Event;\n
var themestyles = require(\'themestyles\');\n
var settings = require(\'settings\').settings;\n
\n
// The current themeExt used on the page.\n
var currentThemeExt = null;\n
\n
// Name of the themePlugin that is used as standard theme. This is not the\n
// base theme.\n
var standardThemeName = null;\n
\n
// Load promise for the basePlugin.\n
var basePluginLoadPromise = null;\n
\n
// Export the themeStyles object. This is necessary, as in some cases you want\n
// to access the themeStyles object when the `themeChange` event was fired.\n
exports.themestyles = themestyles;\n
\n
exports.themeSettingChanged = function(source, settingName, themeName) {\n
    // Get the themeExtensionPoint for \'themeName\'\n
    var themeExt = catalog.getExtensionByKey(\'theme\', themeName);\n
\n
    // \'themeName\' === standard : Remove the current set theme.\n
    // !themeName || !themeExt  : The named theme couldn\'t get found\n
    if (themeName === \'standard\' || !themeName || !themeExt) {\n
        themeExt = null;\n
        // If a standardTheme is given, try to get it.\n
        if (standardThemeName !== null) {\n
            themeExt = catalog.getExtensionByKey(\'theme\', standardThemeName);\n
\n
        }\n
    }\n
\n
    // If no theme should get applied (including no standardTheme).\n
    if (!themeExt) {\n
        // If there is a currentTheme before switching to \'standard\' which means\n
        // removing the currentTheme as applied on the page.\n
        if (currentThemeExt) {\n
            // There might be a themeStyle file to remove.\n
            themestyles.unregisterThemeStyles(currentThemeExt);\n
\n
            currentThemeExt = null;\n
\n
            // Reset the themeVariables applied by the theme.\n
            themestyles.currentThemeVariables = null;\n
\n
            // Update the globalVariables.\n
            themestyles.parseGlobalVariables();\n
\n
            // Reparse all the applied themeStyles.\n
            themestyles.reparse();\n
\n
            // Publish the \'themeChange\' event.\n
            catalog.publish(this, \'themeChange\');\n
        }\n
        return;\n
    } else {\n
        themeExt.load().then(function(theme) {\n
            // Remove the former themeStyle file, if the former extension has\n
            // one declaired.\n
            if (currentThemeExt) {\n
                themestyles.unregisterThemeStyles(currentThemeExt);\n
            }\n
\n
            // The theme is a function. Execute it to get the themeData.\n
            themestyles.currentThemeVariables = theme();\n
\n
            // Store the data for later use.\n
            currentThemeExt = themeExt;\n
\n
            // Update the globalVariables.\n
            themestyles.parseGlobalVariables();\n
\n
            // Reparse all the applied themeStyles.\n
            themestyles.reparse();\n
\n
            // If the theme has a url that points to a themeStyles file, then\n
            // register it.\n
            if (themeExt.url) {\n
                themestyles.registerThemeStyles(themeExt);\n
            }\n
\n
            // Publish the \'themeChange\' event.\n
            catalog.publish(exports, \'themeChange\');\n
        });\n
    }\n
};\n
\n
catalog.registerExtension(\'settingChange\', {\n
    match: "theme",\n
    pointer: exports.themeSettingChanged.bind(exports)\n
});\n
\n
/**\n
 * Sets the standard theme that is used when no other theme is specified or\n
 * the specified theme is not around.\n
 */\n
exports.setStandardTheme = function(themeName) {\n
    standardThemeName = themeName;\n
\n
    // If the current theme is equal to themeName, then the theme is already\n
    // applied. Otherwise, call themeSttingChanged which handles the standard-\n
    // theme change then.\n
    if (themeName !== settings.get(\'theme\')) {\n
        exports.themeSettingChanged(this);\n
    }\n
};\n
\n
/**\n
 * Sets the plugin that should get treated as \'basePlugin\'. BasePlugins contains\n
 * the generic theming for buttons, inputs, panes etc.\n
 */\n
exports.setBasePlugin = function(pluginName) {\n
    // Set the basePlugin.\n
    themestyles.basePluginName = pluginName;\n
};\n
\n
/**\n
 * This function has to be called to enable parsing. Before calling this\n
 * function, parsing is prevented. This allows the developer to prevent parsing\n
 * until certain basic theme plugins are loaded.\n
 * Returns a promise that is resolved after all currently applied themeStyles\n
 * are parsed.\n
 */\n
exports.startParsing = function() {\n
    // Allow the parsing.\n
    themestyles.preventParsing = false;\n
\n
    // Reparse all the applied themeStyles.\n
    return themestyles.reparse();\n
};\n
\n
exports.registerTheme = function(extension) {\n
    var currentThemeName = settings.get(\'theme\');\n
    if (extension.name === currentThemeName) {\n
        exports.themeSettingChanged(this, \'theme\', extension.name);\n
    }\n
};\n
\n
exports.unregisterTheme = function(extension) {\n
    if (extension.name === settings.get(\'theme\')) {\n
        exports.themeSettingChanged(this);\n
    }\n
};\n
\n
// Called when the app is launched.\n
exports.appLaunched = function() {\n
    // Fire the `themeChange` event as some plugins might haven\'t triggered it\n
    // during the launch of the app.\n
    catalog.publish(exports, \'themeChange\');\n
};\n
\n
});\n
\n
bespin.tiki.module("theme_manager:themestyles",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
var catalog = require(\'bespin:plugins\').catalog;\n
var console = require(\'bespin:console\').console;\n
var Promise = require(\'bespin:promise\').Promise;\n
var group = require(\'bespin:promise\').group;\n
\n
var proxy = require(\'bespin:proxy\');\n
\n
var less = require(\'less\');\n
\n
// The less parser to use.\n
var lessParser = new less.Parser({ optimization: 3 });\n
\n
// The incremented styleID number.\n
var styleID = 1;\n
\n
// The theme variables as set by the current theme.\n
exports.currentThemeVariables = null;\n
\n
// The plugin that should get applied before any other plugins get applied.\n
exports.basePluginName = null;\n
\n
// If true, no less file is parsed.\n
exports.preventParsing = true;\n
\n
// Stores the variableHeader used by every themeStyleFile for the global\n
// ThemeVariables.\n
var globalVariableHeader = \'\';\n
\n
// The globalThemeVariables as a combination of the build in once and variables\n
// defined in a custom theme plugin.\n
exports.globalThemeVariables = {};\n
\n
// Stores the internal styleID used with a extension.\n
var extensionStyleID = {};\n
\n
// Stores the ThemeStyleFiles\' content per plugin - somewhat like a par plugin\n
// themeStyle cache.\n
var extensionStyleData = {};\n
\n
// Takes an JS object that and makes it \'linear\'. Every item gets prefixed with\n
// \'global\':\n
//\n
//      globalValues = {\n
//          a: {\n
//              b: \'test\'\n
//          }\n
//      }\n
//\n
//      returns: { \'global_a_b\': \'test\' }\n
var parseGlobalThemeVariables = function(globalValues) {\n
    var ret = {};\n
    var nameStack = [];\n
\n
    var parseSub = function(name, key) {\n
        nameStack.push(name);\n
        if (typeof key != \'object\') {\n
            ret[nameStack.join(\'_\')] = key;\n
        } else {\n
            for (prop in key) {\n
                parseSub(prop, key[prop]);\n
            }\n
        }\n
        nameStack.pop();\n
    };\n
\n
    parseSub(\'global\', globalValues);\n
    return ret;\n
};\n
\n
//------------------------------------------------------------------------------\n
// BEGIN: THIS PART IS OVERRIDDEN BY dryice\n
\n
// Stores the StyleFiles content per plugin during the build of Bespin.\n
// The variable scheme looks like: { pluginName: { "fileName": data } };\n
var extensionStyleBuildData = {};\n
\n
// Stores the default globalTheme ThemeVariables, that are available to every\n
// ThemeStyleFile.\n
var defaultGlobalTheme = {\n
    // standard font.\n
    font:           \'arial, lucida, helvetica, sans-serif\',\n
    // standard font size.\n
    font_size:      \'14px\',\n
    // standard line_height.\n
    line_height:    \'1.8em\',\n
    // text color.\n
    color:          \'#DAD4BA\',\n
\n
    text_shadow:    \'1px 1px rgba(0, 0, 0, 0.4)\',\n
    // text error color.\n
    error_color:    \'#F99\',\n
    // the color for headers (<h1> etc).\n
    header_color:   \'white\',\n
    // the color for links.\n
    link_color:     \'#ACF\',\n
\n
    // Basic colors for a controller: textInput, tree etc.\n
    control: {\n
        color:          \'#E1B41F\',\n
        border:         \'1px solid rgba(0, 0, 0, 0.2)\',\n
        border_radius:  \'0.25em\',\n
        background:     \'rgba(0, 0, 0, 0.2)\',\n
\n
        active: {\n
            color:          \'#FF9600\',\n
            border:         \'1px solid #E1B41F\',\n
            inset_color:    \'#ff9600\',\n
            background:     \'rgba(0, 0, 0, 0.2)\'\n
        }\n
    },\n
\n
    pane: {\n
        h1: {\n
           font:        "\'MuseoSans\', Helvetica",\n
           font_size:   \'2.8em\',\n
           color:       "white"\n
        },\n
\n
        color:          \'#DAD4BA\',\n
        text_shadow:    \'1px 1px rgba(0, 0, 0, 0.4)\',\n
\n
        link_color:     \'white\',\n
\n
        background:     \'#45443C\',\n
        border_radius:  \'.5em\'\n
    },\n
\n
    form: {\n
        color: \'white\',\n
        text_shadow: \'1px 1px rgba(0, 0, 0, 0.4)\',\n
\n
        font: "\'Lucida Sans\',\'Lucida Grande\',Verdana,Arial,sans-serif",\n
        font_size: \'@global_font_size\',\n
        line_height: \'@global_line_height\'\n
    },\n
\n
    button: {\n
        color: \'white\',\n
        background: \'#3E6CB9\'\n
    },\n
\n
    container: {\n
        background:     \'#1E1916\',\n
        border:         \'1px solid black\'\n
    },\n
\n
    // The items in the command line menu or something else,\n
    // that can get selected.\n
    selectable: {\n
        color:          \'white\',\n
        border:         \'0px solid transparent\',\n
        background:     \'transparent\',\n
\n
        active: {\n
            color:          \'black\',\n
            border:         \'0px solid transparent\',\n
            background:     \'#FF8E00\'\n
        },\n
\n
        hover: {\n
            color:          \'black\',\n
            border:         \'0px solid transparent\',\n
            background:     \'#FF8E00\'\n
        }\n
    },\n
\n
    // A small hint text.\n
    hint: {\n
        color:          \'#AAA\',\n
\n
        active: {\n
            color:      \'black\'\n
        },\n
\n
        hover: {\n
            color:      \'black\'\n
        }\n
    },\n
\n
    // E.g. in the command line menu, the \'ALT+2\'.\n
    accelerator: {\n
        color:          \'#996633\',\n
\n
        active: {\n
            color:      \'black\'\n
        },\n
\n
        hover: {\n
            color:      \'black\'\n
        }\n
    },\n
\n
    menu: {\n
        border_color:           \'black\',\n
        inset_color_right:      \'#1E1916\',\n
        inset_color_top_left:   \'#3E3936\',\n
        background:             \'transparent\'\n
    }\n
};\n
\n
defaultGlobalTheme = parseGlobalThemeVariables(defaultGlobalTheme);\n
\n
// END: THIS PART IS OVERRIDDEN BY dryice\n
//------------------------------------------------------------------------------\n
\n
/**\n
 * Returns an object with all the themeVariables value for a given plugin.\n
 */\n
exports.getPluginThemeVariables = function(pluginName) {\n
    var plugin = catalog.plugins[pluginName];\n
\n
    if (!plugin) {\n
        return null;\n
    }\n
\n
    // Hash to look for custom theme variables.\n
    var themeVariables = {};\n
    if (exports.currentThemeVariables &&\n
            exports.currentThemeVariables[pluginName]) {\n
        themeVariables = exports.currentThemeVariables[pluginName];\n
    }\n
\n
    // Set the value for all themeVariables in this plugin.\n
    plugin.provides.forEach(function(ext) {\n
        if (ext.ep === \'themevariable\') {\n
            var value = ext.name;\n
            // The value is the customThemeVariable OR the defaultValue if the\n
            // customThemeVariable is not given.\n
            themeVariables[value] = themeVariables[value] || ext.defaultValue;\n
        }\n
    });\n
\n
    return themeVariables;\n
};\n
\n
/**\n
 * Update the globalThemeVariables. This is called whenever the theme changes.\n
 */\n
exports.parseGlobalVariables = function() {\n
    var globalObj = {};\n
    var globalHeader = \'\';\n
    var currentThemeVariables = exports.currentThemeVariables;\n
\n
    util.mixin(globalObj, defaultGlobalTheme);\n
\n
    if (currentThemeVariables  && currentThemeVariables[\'global\']) {\n
        util.mixin(globalObj,\n
                    parseGlobalThemeVariables(currentThemeVariables[\'global\']));\n
    }\n
\n
    exports.globalThemeVariables = globalObj;\n
\n
    for (prop in globalObj) {\n
        globalHeader += \'@\' + prop + \':\' + globalObj[prop] + \';\';\n
    }\n
\n
    globalVariableHeader = globalHeader;\n
};\n
\n
// Parse the globalThemeVariables.\n
exports.parseGlobalVariables();\n
\n
/**\n
 * Parse one less files.\n
 */\n
var parseLess = function(pr, pluginName, variableHeader) {\n
    // Use already existing DOM style element or create a new one on the page.\n
    if (extensionStyleID[pluginName]) {\n
        styleElem = document.getElementById(\'_bespin_theme_style_\' +\n
                                                extensionStyleID[pluginName]);\n
    } else {\n
        styleElem = document.createElement(\'style\');\n
        styleElem.setAttribute(\'id\', \'_bespin_theme_style_\' + styleID);\n
        extensionStyleID[pluginName] = styleID;\n
        styleID ++;\n
        document.body.appendChild(styleElem);\n
    }\n
\n
    // DEBUG ONLY.\n
    // var timer = new Date();\n
\n
    // Parse the data.\n
    var dataToParse = globalVariableHeader + // global ThemeVariables\n
                            variableHeader + // plugin specific ThemeVariables\n
                            extensionStyleData[pluginName]; // and the data\n
    lessParser.parse(dataToParse, function(e, tree) {\n
        var errMsg;\n
        if (e) {\n
            errMsg = \'Error less parsing \' +  pluginName + \' \' +  e.message;\n
            console.error(errMsg);\n
            pr.reject(errMsg);\n
            return;\n
        }\n
\n
        try {\n
            var css = tree.toCSS();\n
\n
            // DEBUG ONLY.\n
            // console.log(\'  parsing took: \', (new Date()) - timer, \'ms\');\n
        } catch (e) {\n
            errMsg = \'Error less parsing \' + pluginName + \' \' + e;\n
            console.error(errMsg);\n
            pr.reject(errMsg);\n
            return;\n
        }\n
\n
        // Add the parsed CSS content in the styleElement.\n
        if (styleElem && styleElem.firstChild) {\n
            styleElem.firstChild.textContent = css;\n
        } else {\n
            var cssContentNode = document.createTextNode(css);\n
            styleElem.appendChild(cssContentNode);\n
        }\n
        pr.resolve();\n
    });\n
};\n
\n
// Queue with all the plugins waiting to get updated.\n
var parseQueue = {};\n
\n
/**\n
 * Parse the less files for a entire plugin. The plugin is not parsed directly,\n
 * but with a small delay. Otherwise it could happen that the plugin is parsed\n
 * although not all themeVariables are available.\n
 * Returns a promise that is resolved after the plugin is successfully parsed.\n
 * An error during parsing rejects the promise.\n
 */\n
exports.parsePlugin = function(pluginName) {\n
    // Parse only if this is permitted.\n
    if (exports.preventParsing) {\n
        return (new Promise).resolve();\n
    }\n
\n
    var plugin = catalog.plugins[pluginName];\n
\n
    if (!plugin) {\n
        throw "reparsePlugin: plugin " + pluginName + " is not defined!";\n
    }\n
\n
    // Start parsing only if it isn\'t started already.\n
    if (!parseQueue[pluginName]) {\n
        // Mark that the plugin is queued.\n
        parseQueue[pluginName] = new Promise();\n
\n
        setTimeout(function() {\n
            // DEBUG ONLY:\n
            // console.log(\'=== Parse Plugin: \' + pluginName + \' ===\');\n
            // var time = new Date();\n
\n
            var themeVariables = exports.getPluginThemeVariables(pluginName);\n
\n
            // Store the StyleVariables for the StyleData to parse.\n
            var variableHeader = \'\';\n
\n
            for (prop in themeVariables) {\n
                variableHeader += \'@\' + prop + \':\' + themeVariables[prop] + \';\';\n
            }\n
\n
            // DEBUG ONLY:\n
            // console.log(\'  variables: \', variableHeader, globalVariableHeader);\n
\n
            var parsePr = new Promise;\n
            parsePr.then(function(data) {\n
                parseQueue[this.name].resolve(data);\n
                parseQueue[this.name] = null;\n
            }.bind(this), function() {\n
                parseQueue[this.name].reject(data);\n
                parseQueue[this.name] = null;\n
            }.bind(this))\n
\n
            parseLess(parsePr, pluginName, variableHeader);\n
\n
            // DEBUG ONLY:\n
            // console.log(\'everything took: \', (new Date()) - time, \'ms\');\n
        }.bind(plugin), 0);\n
    }\n
\n
    return parseQueue[pluginName];\n
};\n
\n
// Function that pocesses the loaded StyleFile content.\n
var processStyleContent = function(resourceURL, pluginName, data, p) {\n
    // Convert url(something) to url(resourceURL/something).\n
    data = data.replace(/url\\([\'"]*([^\'")]*)([\'"]*)\\)/g,\n
                                      \'url(\' + resourceURL + \'$1)\');\n
    extensionStyleData[pluginName] += data;\n
\n
    // Resolve the promise when given.\n
    if (p) {\n
        p.resolve();\n
    }\n
};\n
\n
var themeDataLoadPromise = null;\n
\n
exports.registerThemeStyles = function(extension) {\n
    var pluginName = extension.getPluginName();\n
    var resourceURL = catalog.getResourceURL(pluginName);\n
\n
    // Make the extension.url parameter an array if it isn\'t yet.\n
    if (!(extension.url instanceof Array)) {\n
        extension.url = [ extension.url ];\n
    }\n
\n
    // (Re)set the loaded StyleData for the plugin.\n
    extensionStyleData[pluginName] = \'\';\n
\n
    var loadPromises = [];\n
\n
    var preventParsing = exports.preventParsing;\n
\n
    // Load the StyleFiles.\n
    extension.url.forEach(function(styleFile) {\n
        if (extensionStyleBuildData[pluginName] &&\n
                extensionStyleBuildData[pluginName][styleFile]) {\n
            // Process the StyleContent.\n
            processStyleContent(resourceURL, pluginName,\n
                                extensionStyleBuildData[pluginName][styleFile]);\n
        } else {\n
            var p = new Promise();\n
            loadPromises.push(p);\n
\n
            var url = resourceURL + styleFile + \'?\' + (new Date).getTime();\n
            proxy.xhr(\'GET\', url, true, function(xhr) {\n
                xhr.overrideMimeType(\'text/plain\');\n
            }).then(function(response) {\n
                  processStyleContent(resourceURL, pluginName, response, p);\n
            }, function(err) {\n
                console.error(\'registerLessFile: Could not load \' +\n
                        resourceURL + styleFile);\n
\n
                // The file couldn\'t get loaded but to make the group\n
                // work we have to mark this loadPromise as resolved so that\n
                // at least the other sucessfully loaded files can get\n
                // proceeded.\n
                p.resolve();\n
            });\n
        }\n
    });\n
\n
    if (loadPromises.length === 0) {\n
        exports.parsePlugin(pluginName);\n
    } else {\n
        // If parsing is allowed, then wait until all the styleFiles are loaded\n
        // and parse the plugin.\n
        if (!preventParsing) {\n
            group(loadPromises).then(function() {\n
                exports.parsePlugin(pluginName);\n
            });\n
        }\n
\n
        if (themeDataLoadPromise !== null) {\n
            loadPromises = loadPromises.concat(themeDataLoadPromise);\n
        }\n
        themeDataLoadPromise = group(loadPromises);\n
    }\n
};\n
\n
/**\n
 * Call this function to reparse all the ThemeStyles files.\n
 * Returns a promise. The promise is resolved after all themeStyles are reparsed.\n
 */\n
exports.reparse = function() {\n
    var pr = new Promise();\n
\n
    // Reparse only if this is permitted.\n
    if (exports.preventParsing) {\n
        return pr.resolve();\n
    }\n
\n
    // Reparsing makes only sense if there is a themeDataLoadPromise.\n
    // If the value is null, then no styleFile was loaded and there is nothing\n
    // to reparse.\n
    if (themeDataLoadPromise) {\n
        // When all the styleFiles are loaded.\n
        themeDataLoadPromise.then(function() {\n
            var parsePromises = [];\n
\n
            // Reparese all the themeStyles. Instead of loading the themeStyles\n
            // again from the server, the cache extensionStyleData is used.\n
            // Every plugin in this cache is reparsed.\n
\n
            // Check if a basePlugin is set and parse this one first.\n
            var basePluginName = exports.basePluginName;\n
            if (basePluginName !== null && extensionStyleData[basePluginName]) {\n
                parsePromises.push(exports.parsePlugin(basePluginName));\n
            }\n
\n
            // Parse the other plugins.\n
            for (var pluginName in extensionStyleData) {\n
                // Skip the basePlugin as this is already parsed.\n
                if (pluginName === basePluginName) {\n
                    continue;\n
                }\n
                parsePromises.push(exports.parsePlugin(pluginName));\n
            }\n
\n
            // After all themeStyles are parsed, resolve the returned promise.\n
            group(parsePromises).then(pr.resolve.bind(pr), pr.reject.bind(pr));\n
        }, function(err) {\n
            pr.reject(err);\n
        });\n
    } else {\n
        pr.resolve();\n
    }\n
    return pr;\n
};\n
\n
/**\n
 * Unregister a themeStyle.\n
 * @param The extension to unregister.\n
 */\n
exports.unregisterThemeStyles = function(extension) {\n
    var pluginName = extension.getPluginName();\n
    if (!extensionStyleID[pluginName]) {\n
        return;\n
    }\n
\n
    // Remove the style element from the page.\n
    var styleID = \'_bespin_theme_style_\' + extensionStyleID[pluginName];\n
    var styleElement = document.getElementById(styleID);\n
    styleElement.parentNode.removeChild(styleElement);\n
\n
    // Remove the style reference.\n
    delete extensionStyleID[pluginName];\n
    // Remove the themeStyle cache.\n
    delete extensionStyleData[pluginName];\n
};\n
\n
});\n
;bespin.tiki.register("::jquery", {\n
    name: "jquery",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("jquery:index",function(require,exports,module) {\n
"define metadata";\n
({});\n
"end";\n
\n
/*!\n
 * jQuery JavaScript Library v1.4.2\n
 * http://jquery.com/\n
 *\n
 * Copyright 2010, John Resig\n
 * Dual licensed under the MIT or GPL Version 2 licenses.\n
 * http://jquery.org/license\n
 *\n
 * Includes Sizzle.js\n
 * http://sizzlejs.com/\n
 * Copyright 2010, The Dojo Foundation\n
 * Released under the MIT, BSD, and GPL Licenses.\n
 *\n
 * Date: Sat Feb 13 22:33:48 2010 -0500\n
 */\n
\n
// Define a local copy of jQuery\n
var jQuery = function( selector, context ) {\n
\t\t// The jQuery object is actually just the init constructor \'enhanced\'\n
\t\treturn new jQuery.fn.init( selector, context );\n
\t},\n
\n
\t// Map over jQuery in case of overwrite\n
\t_jQuery = window.jQuery,\n
\n
\t// Map over the $ in case of overwrite\n
\t_$ = window.$,\n
\n
\t// Use the correct document accordingly with window argument (sandbox)\n
\tdocument = window.document,\n
\n
\t// A central reference to the root jQuery(document)\n
\trootjQuery,\n
\n
\t// A simple way to check for HTML strings or ID strings\n
\t// (both of which we optimize for)\n
\tquickExpr = /^[^<]*(<[\\w\\W]+>)[^>]*$|^#([\\w-]+)$/,\n
\n
\t// Is it a simple selector\n
\tisSimple = /^.[^:#\\[\\.,]*$/,\n
\n
\t// Check if a string has a non-whitespace character in it\n
\trnotwhite = /\\S/,\n
\n
\t// Used for trimming whitespace\n
\trtrim = /^(\\s|\\u00A0)+|(\\s|\\u00A0)+$/g,\n
\n
\t// Match a standalone tag\n
\trsingleTag = /^<(\\w+)\\s*\\/?>(?:<\\/\\1>)?$/,\n
\n
\t// Keep a UserAgent string for use with jQuery.browser\n
\tuserAgent = navigator.userAgent,\n
\n
\t// For matching the engine and version of the browser\n
\tbrowserMatch,\n
\t\n
\t// Has the ready events already been bound?\n
\treadyBound = false,\n
\t\n
\t// The functions to execute on DOM ready\n
\treadyList = [],\n
\n
\t// The ready event handler\n
\tDOMContentLoaded,\n
\n
\t// Save a reference to some core methods\n
\ttoString = Object.prototype.toString,\n
\thasOwnProperty = Object.prototype.hasOwnProperty,\n
\tpush = Array.prototype.push,\n
\tslice = Array.prototype.slice,\n
\tindexOf = Array.prototype.indexOf;\n
\n
jQuery.fn = jQuery.prototype = {\n
\tinit: function( selector, context ) {\n
\t\tvar match, elem, ret, doc;\n
\n
\t\t// Handle $(""), $(null), or $(undefined)\n
\t\tif ( !selector ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// Handle $(DOMElement)\n
\t\tif ( selector.nodeType ) {\n
\t\t\tthis.context = this[0] = selector;\n
\t\t\tthis.length = 1;\n
\t\t\treturn this;\n
\t\t}\n
\t\t\n
\t\t// The body element only exists once, optimize finding it\n
\t\tif ( selector === "body" && !context ) {\n
\t\t\tthis.context = document;\n
\t\t\tthis[0] = document.body;\n
\t\t\tthis.selector = "body";\n
\t\t\tthis.length = 1;\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\t// Handle HTML strings\n
\t\tif ( typeof selector === "string" ) {\n
\t\t\t// Are we dealing with HTML string or an ID?\n
\t\t\tmatch = quickExpr.exec( selector );\n
\n
\t\t\t// Verify a match, and that no context was specified for #id\n
\t\t\tif ( match && (match[1] || !context) ) {\n
\n
\t\t\t\t// HANDLE: $(html) -> $(array)\n
\t\t\t\tif ( match[1] ) {\n
\t\t\t\t\tdoc = (context ? context.ownerDocument || context : document);\n
\n
\t\t\t\t\t// If a single string is passed in and it\'s a single tag\n
\t\t\t\t\t// just do a createElement and skip the rest\n
\t\t\t\t\tret = rsingleTag.exec( selector );\n
\n
\t\t\t\t\tif ( ret ) {\n
\t\t\t\t\t\tif ( jQuery.isPlainObject( context ) ) {\n
\t\t\t\t\t\t\tselector = [ document.createElement( ret[1] ) ];\n
\t\t\t\t\t\t\tjQuery.fn.attr.call( selector, context, true );\n
\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tselector = [ doc.createElement( ret[1] ) ];\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tret = buildFragment( [ match[1] ], [ doc ] );\n
\t\t\t\t\t\tselector = (ret.cacheable ? ret.fragment.cloneNode(true) : ret.fragment).childNodes;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\treturn jQuery.merge( this, selector );\n
\t\t\t\t\t\n
\t\t\t\t// HANDLE: $("#id")\n
\t\t\t\t} else {\n
\t\t\t\t\telem = document.getElementById( match[2] );\n
\n
\t\t\t\t\tif ( elem ) {\n
\t\t\t\t\t\t// Handle the case where IE and Opera return items\n
\t\t\t\t\t\t// by name instead of ID\n
\t\t\t\t\t\tif ( elem.id !== match[2] ) {\n
\t\t\t\t\t\t\treturn rootjQuery.find( selector );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// Otherwise, we inject the element directly into the jQuery object\n
\t\t\t\t\t\tthis.length = 1;\n
\t\t\t\t\t\tthis[0] = elem;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tthis.context = document;\n
\t\t\t\t\tthis.selector = selector;\n
\t\t\t\t\treturn this;\n
\t\t\t\t}\n
\n
\t\t\t// HANDLE: $("TAG")\n
\t\t\t} else if ( !context && /^\\w+$/.test( selector ) ) {\n
\t\t\t\tthis.selector = selector;\n
\t\t\t\tthis.context = document;\n
\t\t\t\tselector = document.getElementsByTagName( selector );\n
\t\t\t\treturn jQuery.merge( this, selector );\n
\n
\t\t\t// HANDLE: $(expr, $(...))\n
\t\t\t} else if ( !context || context.jquery ) {\n
\t\t\t\treturn (context || rootjQuery).find( selector );\n
\n
\t\t\t// HANDLE: $(expr, context)\n
\t\t\t// (which is just equivalent to: $(context).find(expr)\n
\t\t\t} else {\n
\t\t\t\treturn jQuery( context ).find( selector );\n
\t\t\t}\n
\n
\t\t// HANDLE: $(function)\n
\t\t// Shortcut for document ready\n
\t\t} else if ( jQuery.isFunction( selector ) ) {\n
\t\t\treturn rootjQuery.ready( selector );\n
\t\t}\n
\n
\t\tif (selector.selector !== undefined) {\n
\t\t\tthis.selector = selector.selector;\n
\t\t\tthis.context = selector.context;\n
\t\t}\n
\n
\t\treturn jQuery.makeArray( selector, this );\n
\t},\n
\n
\t// Start with an empty selector\n
\tselector: "",\n
\n
\t// The current version of jQuery being used\n
\tjquery: "1.4.2",\n
\n
\t// The default length of a jQuery object is 0\n
\tlength: 0,\n
\n
\t// The number of elements contained in the matched element set\n
\tsize: function() {\n
\t\treturn this.length;\n
\t},\n
\n
\ttoArray: function() {\n
\t\treturn slice.call( this, 0 );\n
\t},\n
\n
\t// Get the Nth element in the matched element set OR\n
\t// Get the whole matched element set as a clean array\n
\tget: function( num ) {\n
\t\treturn num == null ?\n
\n
\t\t\t// Return a \'clean\' array\n
\t\t\tthis.toArray() :\n
\n
\t\t\t// Return just the object\n
\t\t\t( num < 0 ? this.slice(num)[ 0 ] : this[ num ] );\n
\t},\n
\n
\t// Take an array of elements and push it onto the stack\n
\t// (returning the new matched element set)\n
\tpushStack: function( elems, name, selector ) {\n
\t\t// Build a new jQuery matched element set\n
\t\tvar ret = jQuery();\n
\n
\t\tif ( jQuery.isArray( elems ) ) {\n
\t\t\tpush.apply( ret, elems );\n
\t\t\n
\t\t} else {\n
\t\t\tjQuery.merge( ret, elems );\n
\t\t}\n
\n
\t\t// Add the old object onto the stack (as a reference)\n
\t\tret.prevObject = this;\n
\n
\t\tret.context = this.context;\n
\n
\t\tif ( name === "find" ) {\n
\t\t\tret.selector = this.selector + (this.selector ? " " : "") + selector;\n
\t\t} else if ( name ) {\n
\t\t\tret.selector = this.selector + "." + name + "(" + selector + ")";\n
\t\t}\n
\n
\t\t// Return the newly-formed element set\n
\t\treturn ret;\n
\t},\n
\n
\t// Execute a callback for every element in the matched set.\n
\t// (You can seed the arguments with an array of args, but this is\n
\t// only used internally.)\n
\teach: function( callback, args ) {\n
\t\treturn jQuery.each( this, callback, args );\n
\t},\n
\t\n
\tready: function( fn ) {\n
\t\t// Attach the listeners\n
\t\tjQuery.bindReady();\n
\n
\t\t// If the DOM is already ready\n
\t\tif ( jQuery.isReady ) {\n
\t\t\t// Execute the function immediately\n
\t\t\tfn.call( document, jQuery );\n
\n
\t\t// Otherwise, remember the function for later\n
\t\t} else if ( readyList ) {\n
\t\t\t// Add the function to the wait list\n
\t\t\treadyList.push( fn );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\t\n
\teq: function( i ) {\n
\t\treturn i === -1 ?\n
\t\t\tthis.slice( i ) :\n
\t\t\tthis.slice( i, +i + 1 );\n
\t},\n
\n
\tfirst: function() {\n
\t\treturn this.eq( 0 );\n
\t},\n
\n
\tlast: function() {\n
\t\treturn this.eq( -1 );\n
\t},\n
\n
\tslice: function() {\n
\t\treturn this.pushStack( slice.apply( this, arguments ),\n
\t\t\t"slice", slice.call(arguments).join(",") );\n
\t},\n
\n
\tmap: function( callback ) {\n
\t\treturn this.pushStack( jQuery.map(this, function( elem, i ) {\n
\t\t\treturn callback.call( elem, i, elem );\n
\t\t}));\n
\t},\n
\t\n
\tend: function() {\n
\t\treturn this.prevObject || jQuery(null);\n
\t},\n
\n
\t// For internal use only.\n
\t// Behaves like an Array\'s method, not like a jQuery method.\n
\tpush: push,\n
\tsort: [].sort,\n
\tsplice: [].splice\n
};\n
\n
// Give the init function the jQuery prototype for later instantiation\n
jQuery.fn.init.prototype = jQuery.fn;\n
\n
jQuery.extend = jQuery.fn.extend = function() {\n
\t// copy reference to target object\n
\tvar target = arguments[0] || {}, i = 1, length = arguments.length, deep = false, options, name, src, copy;\n
\n
\t// Handle a deep copy situation\n
\tif ( typeof target === "boolean" ) {\n
\t\tdeep = target;\n
\t\ttarget = arguments[1] || {};\n
\t\t// skip the boolean and the target\n
\t\ti = 2;\n
\t}\n
\n
\t// Handle case when target is a string or something (possible in deep copy)\n
\tif ( typeof target !== "object" && !jQuery.isFunction(target) ) {\n
\t\ttarget = {};\n
\t}\n
\n
\t// extend jQuery itself if only one argument is passed\n
\tif ( length === i ) {\n
\t\ttarget = this;\n
\t\t--i;\n
\t}\n
\n
\tfor ( ; i < length; i++ ) {\n
\t\t// Only deal with non-null/undefined values\n
\t\tif ( (options = arguments[ i ]) != null ) {\n
\t\t\t// Extend the base object\n
\t\t\tfor ( name in options ) {\n
\t\t\t\tsrc = target[ name ];\n
\t\t\t\tcopy = options[ name ];\n
\n
\t\t\t\t// Prevent never-ending loop\n
\t\t\t\tif ( target === copy ) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\t// Recurse if we\'re merging object literal values or arrays\n
\t\t\t\tif ( deep && copy && ( jQuery.isPlainObject(copy) || jQuery.isArray(copy) ) ) {\n
\t\t\t\t\tvar clone = src && ( jQuery.isPlainObject(src) || jQuery.isArray(src) ) ? src\n
\t\t\t\t\t\t: jQuery.isArray(copy) ? [] : {};\n
\n
\t\t\t\t\t// Never move original objects, clone them\n
\t\t\t\t\ttarget[ name ] = jQuery.extend( deep, clone, copy );\n
\n
\t\t\t\t// Don\'t bring in undefined values\n
\t\t\t\t} else if ( copy !== undefined ) {\n
\t\t\t\t\ttarget[ name ] = copy;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\t// Return the modified object\n
\treturn target;\n
};\n
\n
jQuery.extend({\n
\tnoConflict: function( deep ) {\n
\t\twindow.$ = _$;\n
\n
\t\tif ( deep ) {\n
\t\t\twindow.jQuery = _jQuery;\n
\t\t}\n
\n
\t\treturn jQuery;\n
\t},\n
\t\n
\t// Is the DOM ready to be used? Set to true once it occurs.\n
\tisReady: false,\n
\t\n
\t// Handle when the DOM is ready\n
\tready: function() {\n
\t\t// Make sure that the DOM is not already loaded\n
\t\tif ( !jQuery.isReady ) {\n
\t\t\t// Make sure body exists, at least, in case IE gets a little overzealous (ticket #5443).\n
\t\t\tif ( !document.body ) {\n
\t\t\t\treturn setTimeout( jQuery.ready, 13 );\n
\t\t\t}\n
\n
\t\t\t// Remember that the DOM is ready\n
\t\t\tjQuery.isReady = true;\n
\n
\t\t\t// If there are functions bound, to execute\n
\t\t\tif ( readyList ) {\n
\t\t\t\t// Execute all of them\n
\t\t\t\tvar fn, i = 0;\n
\t\t\t\twhile ( (fn = readyList[ i++ ]) ) {\n
\t\t\t\t\tfn.call( document, jQuery );\n
\t\t\t\t}\n
\n
\t\t\t\t// Reset the list of functions\n
\t\t\t\treadyList = null;\n
\t\t\t}\n
\n
\t\t\t// Trigger any bound ready events\n
\t\t\tif ( jQuery.fn.triggerHandler ) {\n
\t\t\t\tjQuery( document ).triggerHandler( "ready" );\n
\t\t\t}\n
\t\t}\n
\t},\n
\t\n
\tbindReady: function() {\n
\t\tif ( readyBound ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\treadyBound = true;\n
\n
\t\t// Catch cases where $(document).ready() is called after the\n
\t\t// browser event has already occurred.\n
\t\tif ( document.readyState === "complete" ) {\n
\t\t\treturn jQuery.ready();\n
\t\t}\n
\n
\t\t// Mozilla, Opera and webkit nightlies currently support this event\n
\t\tif ( document.addEventListener ) {\n
\t\t\t// Use the handy event callback\n
\t\t\tdocument.addEventListener( "DOMContentLoaded", DOMContentLoaded, false );\n
\t\t\t\n
\t\t\t// A fallback to window.onload, that will always work\n
\t\t\twindow.addEventListener( "load", jQuery.ready, false );\n
\n
\t\t// If IE event model is used\n
\t\t} else if ( document.attachEvent ) {\n
\t\t\t// ensure firing before onload,\n
\t\t\t// maybe late but safe also for iframes\n
\t\t\tdocument.attachEvent("onreadystatechange", DOMContentLoaded);\n
\t\t\t\n
\t\t\t// A fallback to window.onload, that will always work\n
\t\t\twindow.attachEvent( "onload", jQuery.ready );\n
\n
\t\t\t// If IE and not a frame\n
\t\t\t// continually check to see if the document is ready\n
\t\t\tvar toplevel = false;\n
\n
\t\t\ttry {\n
\t\t\t\ttoplevel = window.frameElement == null;\n
\t\t\t} catch(e) {}\n
\n
\t\t\tif ( document.documentElement.doScroll && toplevel ) {\n
\t\t\t\tdoScrollCheck();\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// See test/unit/core.js for details concerning isFunction.\n
\t// Since version 1.3, DOM methods and functions like alert\n
\t// aren\'t supported. They return false on IE (#2968).\n
\tisFunction: function( obj ) {\n
\t\treturn toString.call(obj) === "[object Function]";\n
\t},\n
\n
\tisArray: function( obj ) {\n
\t\treturn toString.call(obj) === "[object Array]";\n
\t},\n
\n
\tisPlainObject: function( obj ) {\n
\t\t// Must be an Object.\n
\t\t// Because of IE, we also have to check the presence of the constructor property.\n
\t\t// Make sure that DOM nodes and window objects don\'t pass through, as well\n
\t\tif ( !obj || toString.call(obj) !== "[object Object]" || obj.nodeType || obj.setInterval ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\t\n
\t\t// Not own constructor property must be Object\n
\t\tif ( obj.constructor\n
\t\t\t&& !hasOwnProperty.call(obj, "constructor")\n
\t\t\t&& !hasOwnProperty.call(obj.constructor.prototype, "isPrototypeOf") ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\t\n
\t\t// Own properties are enumerated firstly, so to speed up,\n
\t\t// if last one is own, then all properties are own.\n
\t\n
\t\tvar key;\n
\t\tfor ( key in obj ) {}\n
\t\t\n
\t\treturn key === undefined || hasOwnProperty.call( obj, key );\n
\t},\n
\n
\tisEmptyObject: function( obj ) {\n
\t\tfor ( var name in obj ) {\n
\t\t\treturn false;\n
\t\t}\n
\t\treturn true;\n
\t},\n
\t\n
\terror: function( msg ) {\n
\t\tthrow msg;\n
\t},\n
\t\n
\tparseJSON: function( data ) {\n
\t\tif ( typeof data !== "string" || !data ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\t// Make sure leading/trailing whitespace is removed (IE can\'t handle it)\n
\t\tdata = jQuery.trim( data );\n
\t\t\n
\t\t// Make sure the incoming data is actual JSON\n
\t\t// Logic borrowed from http://json.org/json2.js\n
\t\tif ( /^[\\],:{}\\s]*$/.test(data.replace(/\\\\(?:["\\\\\\/bfnrt]|u[0-9a-fA-F]{4})/g, "@")\n
\t\t\t.replace(/"[^"\\\\\\n\\r]*"|true|false|null|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?/g, "]")\n
\t\t\t.replace(/(?:^|:|,)(?:\\s*\\[)+/g, "")) ) {\n
\n
\t\t\t// Try to use the native JSON parser first\n
\t\t\treturn window.JSON && window.JSON.parse ?\n
\t\t\t\twindow.JSON.parse( data ) :\n
\t\t\t\t(new Function("return " + data))();\n
\n
\t\t} else {\n
\t\t\tjQuery.error( "Invalid JSON: " + data );\n
\t\t}\n
\t},\n
\n
\tnoop: function() {},\n
\n
\t// Evalulates a script in a global context\n
\tglobalEval: function( data ) {\n
\t\tif ( data && rnotwhite.test(data) ) {\n
\t\t\t// Inspired by code by Andrea Giammarchi\n
\t\t\t// http://webreflection.blogspot.com/2007/08/global-scope-evaluation-and-dom.html\n
\t\t\tvar head = document.getElementsByTagName("head")[0] || document.documentElement,\n
\t\t\t\tscript = document.createElement("script");\n
\n
\t\t\tscript.type = "text/javascript";\n
\n
\t\t\tif ( jQuery.support.scriptEval ) {\n
\t\t\t\tscript.appendChild( document.createTextNode( data ) );\n
\t\t\t} else {\n
\t\t\t\tscript.text = data;\n
\t\t\t}\n
\n
\t\t\t// Use insertBefore instead of appendChild to circumvent an IE6 bug.\n
\t\t\t// This arises when a base node is used (#2709).\n
\t\t\thead.insertBefore( script, head.firstChild );\n
\t\t\thead.removeChild( script );\n
\t\t}\n
\t},\n
\n
\tnodeName: function( elem, name ) {\n
\t\treturn elem.nodeName && elem.nodeName.toUpperCase() === name.toUpperCase();\n
\t},\n
\n
\t// args is for internal usage only\n
\teach: function( object, callback, args ) {\n
\t\tvar name, i = 0,\n
\t\t\tlength = object.length,\n
\t\t\tisObj = length === undefined || jQuery.isFunction(object);\n
\n
\t\tif ( args ) {\n
\t\t\tif ( isObj ) {\n
\t\t\t\tfor ( name in object ) {\n
\t\t\t\t\tif ( callback.apply( object[ name ], args ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( ; i < length; ) {\n
\t\t\t\t\tif ( callback.apply( object[ i++ ], args ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t// A special, fast, case for the most common use of each\n
\t\t} else {\n
\t\t\tif ( isObj ) {\n
\t\t\t\tfor ( name in object ) {\n
\t\t\t\t\tif ( callback.call( object[ name ], name, object[ name ] ) === false ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( var value = object[0];\n
\t\t\t\t\ti < length && callback.call( value, i, value ) !== false; value = object[++i] ) {}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn object;\n
\t},\n
\n
\ttrim: function( text ) {\n
\t\treturn (text || "").replace( rtrim, "" );\n
\t},\n
\n
\t// results is for internal usage only\n
\tmakeArray: function( array, results ) {\n
\t\tvar ret = results || [];\n
\n
\t\tif ( array != null ) {\n
\t\t\t// The window, strings (and functions) also have \'length\'\n
\t\t\t// The extra typeof function check is to prevent crashes\n
\t\t\t// in Safari 2 (See: #3039)\n
\t\t\tif ( array.length == null || typeof array === "string" || jQuery.isFunction(array) || (typeof array !== "function" && array.setInterval) ) {\n
\t\t\t\tpush.call( ret, array );\n
\t\t\t} else {\n
\t\t\t\tjQuery.merge( ret, array );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\tinArray: function( elem, array ) {\n
\t\tif ( array.indexOf ) {\n
\t\t\treturn array.indexOf( elem );\n
\t\t}\n
\n
\t\tfor ( var i = 0, length = array.length; i < length; i++ ) {\n
\t\t\tif ( array[ i ] === elem ) {\n
\t\t\t\treturn i;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn -1;\n
\t},\n
\n
\tmerge: function( first, second ) {\n
\t\tvar i = first.length, j = 0;\n
\n
\t\tif ( typeof second.length === "number" ) {\n
\t\t\tfor ( var l = second.length; j < l; j++ ) {\n
\t\t\t\tfirst[ i++ ] = second[ j ];\n
\t\t\t}\n
\t\t\n
\t\t} else {\n
\t\t\twhile ( second[j] !== undefined ) {\n
\t\t\t\tfirst[ i++ ] = second[ j++ ];\n
\t\t\t}\n
\t\t}\n
\n
\t\tfirst.length = i;\n
\n
\t\treturn first;\n
\t},\n
\n
\tgrep: function( elems, callback, inv ) {\n
\t\tvar ret = [];\n
\n
\t\t// Go through the array, only saving the items\n
\t\t// that pass the validator function\n
\t\tfor ( var i = 0, length = elems.length; i < length; i++ ) {\n
\t\t\tif ( !inv !== !callback( elems[ i ], i ) ) {\n
\t\t\t\tret.push( elems[ i ] );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t// arg is for internal usage only\n
\tmap: function( elems, callback, arg ) {\n
\t\tvar ret = [], value;\n
\n
\t\t// Go through the array, translating each of the items to their\n
\t\t// new value (or values).\n
\t\tfor ( var i = 0, length = elems.length; i < length; i++ ) {\n
\t\t\tvalue = callback( elems[ i ], i, arg );\n
\n
\t\t\tif ( value != null ) {\n
\t\t\t\tret[ ret.length ] = value;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret.concat.apply( [], ret );\n
\t},\n
\n
\t// A global GUID counter for objects\n
\tguid: 1,\n
\n
\tproxy: function( fn, proxy, thisObject ) {\n
\t\tif ( arguments.length === 2 ) {\n
\t\t\tif ( typeof proxy === "string" ) {\n
\t\t\t\tthisObject = fn;\n
\t\t\t\tfn = thisObject[ proxy ];\n
\t\t\t\tproxy = undefined;\n
\n
\t\t\t} else if ( proxy && !jQuery.isFunction( proxy ) ) {\n
\t\t\t\tthisObject = proxy;\n
\t\t\t\tproxy = undefined;\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !proxy && fn ) {\n
\t\t\tproxy = function() {\n
\t\t\t\treturn fn.apply( thisObject || this, arguments );\n
\t\t\t};\n
\t\t}\n
\n
\t\t// Set the guid of unique handler to the same of original handler, so it can be removed\n
\t\tif ( fn ) {\n
\t\t\tproxy.guid = fn.guid = fn.guid || proxy.guid || jQuery.guid++;\n
\t\t}\n
\n
\t\t// So proxy can be declared as an argument\n
\t\treturn proxy;\n
\t},\n
\n
\t// Use of jQuery.browser is frowned upon.\n
\t// More details: http://docs.jquery.com/Utilities/jQuery.browser\n
\tuaMatch: function( ua ) {\n
\t\tua = ua.toLowerCase();\n
\n
\t\tvar match = /(webkit)[ \\/]([\\w.]+)/.exec( ua ) ||\n
\t\t\t/(opera)(?:.*version)?[ \\/]([\\w.]+)/.exec( ua ) ||\n
\t\t\t/(msie) ([\\w.]+)/.exec( ua ) ||\n
\t\t\t!/compatible/.test( ua ) && /(mozilla)(?:.*? rv:([\\w.]+))?/.exec( ua ) ||\n
\t\t  \t[];\n
\n
\t\treturn { browser: match[1] || "", version: match[2] || "0" };\n
\t},\n
\n
\tbrowser: {}\n
});\n
\n
browserMatch = jQuery.uaMatch( userAgent );\n
if ( browserMatch.browser ) {\n
\tjQuery.browser[ browserMatch.browser ] = true;\n
\tjQuery.browser.version = browserMatch.version;\n
}\n
\n
// Deprecated, use jQuery.browser.webkit instead\n
if ( jQuery.browser.webkit ) {\n
\tjQuery.browser.safari = true;\n
}\n
\n
if ( indexOf ) {\n
\tjQuery.inArray = function( elem, array ) {\n
\t\treturn indexOf.call( array, elem );\n
\t};\n
}\n
\n
// All jQuery objects should point back to these\n
rootjQuery = jQuery(document);\n
\n
// Cleanup functions for the document ready method\n
if ( document.addEventListener ) {\n
\tDOMContentLoaded = function() {\n
\t\tdocument.removeEventListener( "DOMContentLoaded", DOMContentLoaded, false );\n
\t\tjQuery.ready();\n
\t};\n
\n
} else if ( document.attachEvent ) {\n
\tDOMContentLoaded = function() {\n
\t\t// Make sure body exists, at least, in case IE gets a little overzealous (ticket #5443).\n
\t\tif ( document.readyState === "complete" ) {\n
\t\t\tdocument.detachEvent( "onreadystatechange", DOMContentLoaded );\n
\t\t\tjQuery.ready();\n
\t\t}\n
\t};\n
}\n
\n
// The DOM ready check for Internet Explorer\n
function doScrollCheck() {\n
\tif ( jQuery.isReady ) {\n
\t\treturn;\n
\t}\n
\n
\ttry {\n
\t\t// If IE is used, use the trick by Diego Perini\n
\t\t// http://javascript.nwbox.com/IEContentLoaded/\n
\t\tdocument.documentElement.doScroll("left");\n
\t} catch( error ) {\n
\t\tsetTimeout( doScrollCheck, 1 );\n
\t\treturn;\n
\t}\n
\n
\t// and execute any waiting functions\n
\tjQuery.ready();\n
}\n
\n
function evalScript( i, elem ) {\n
\tif ( elem.src ) {\n
\t\tjQuery.ajax({\n
\t\t\turl: elem.src,\n
\t\t\tasync: false,\n
\t\t\tdataType: "script"\n
\t\t});\n
\t} else {\n
\t\tjQuery.globalEval( elem.text || elem.textContent || elem.innerHTML || "" );\n
\t}\n
\n
\tif ( elem.parentNode ) {\n
\t\telem.parentNode.removeChild( elem );\n
\t}\n
}\n
\n
// Mutifunctional method to get and set values to a collection\n
// The value/s can be optionally by executed if its a function\n
function access( elems, key, value, exec, fn, pass ) {\n
\tvar length = elems.length;\n
\t\n
\t// Setting many attributes\n
\tif ( typeof key === "object" ) {\n
\t\tfor ( var k in key ) {\n
\t\t\taccess( elems, k, key[k], exec, fn, value );\n
\t\t}\n
\t\treturn elems;\n
\t}\n
\t\n
\t// Setting one attribute\n
\tif ( value !== undefined ) {\n
\t\t// Optionally, function values get executed if exec is true\n
\t\texec = !pass && exec && jQuery.isFunction(value);\n
\t\t\n
\t\tfor ( var i = 0; i < length; i++ ) {\n
\t\t\tfn( elems[i], key, exec ? value.call( elems[i], i, fn( elems[i], key ) ) : value, pass );\n
\t\t}\n
\t\t\n
\t\treturn elems;\n
\t}\n
\t\n
\t// Getting an attribute\n
\treturn length ? fn( elems[0], key ) : undefined;\n
}\n
\n
function now() {\n
\treturn (new Date).getTime();\n
}\n
(function() {\n
\n
\tjQuery.support = {};\n
\n
\tvar root = document.documentElement,\n
\t\tscript = document.createElement("script"),\n
\t\tdiv = document.createElement("div"),\n
\t\tid = "script" + now();\n
\n
\tdiv.style.display = "none";\n
\tdiv.innerHTML = "   <link/><table></table><a href=\'/a\' style=\'color:red;float:left;opacity:.55;\'>a</a><input type=\'checkbox\'/>";\n
\n
\tvar all = div.getElementsByTagName("*"),\n
\t\ta = div.getElementsByTagName("a")[0];\n
\n
\t// Can\'t get basic test support\n
\tif ( !all || !all.length || !a ) {\n
\t\treturn;\n
\t}\n
\n
\tjQuery.support = {\n
\t\t// IE strips leading whitespace when .innerHTML is used\n
\t\tleadingWhitespace: div.firstChild.nodeType === 3,\n
\n
\t\t// Make sure that tbody elements aren\'t automatically inserted\n
\t\t// IE will insert them into empty tables\n
\t\ttbody: !div.getElementsByTagName("tbody").length,\n
\n
\t\t// Make sure that link elements get serialized correctly by innerHTML\n
\t\t// This requires a wrapper element in IE\n
\t\thtmlSerialize: !!div.getElementsByTagName("link").length,\n
\n
\t\t// Get the style information from getAttribute\n
\t\t// (IE uses .cssText insted)\n
\t\tstyle: /red/.test( a.getAttribute("style") ),\n
\n
\t\t// Make sure that URLs aren\'t manipulated\n
\t\t// (IE normalizes it by default)\n
\t\threfNormalized: a.getAttribute("href") === "/a",\n
\n
\t\t// Make sure that element opacity exists\n
\t\t// (IE uses filter instead)\n
\t\t// Use a regex to work around a WebKit issue. See #5145\n
\t\topacity: /^0.55$/.test( a.style.opacity ),\n
\n
\t\t// Verify style float existence\n
\t\t// (IE uses styleFloat instead of cssFloat)\n
\t\tcssFloat: !!a.style.cssFloat,\n
\n
\t\t// Make sure that if no value is specified for a checkbox\n
\t\t// that it defaults to "on".\n
\t\t// (WebKit defaults to "" instead)\n
\t\tcheckOn: div.getElementsByTagName("input")[0].value === "on",\n
\n
\t\t// Make sure that a selected-by-default option has a working selected property.\n
\t\t// (WebKit defaults to false instead of true, IE too, if it\'s in an optgroup)\n
\t\toptSelected: document.createElement("select").appendChild( document.createElement("option") ).selected,\n
\n
\t\tparentNode: div.removeChild( div.appendChild( document.createElement("div") ) ).parentNode === null,\n
\n
\t\t// Will be defined later\n
\t\tdeleteExpando: true,\n
\t\tcheckClone: false,\n
\t\tscriptEval: false,\n
\t\tnoCloneEvent: true,\n
\t\tboxModel: null\n
\t};\n
\n
\tscript.type = "text/javascript";\n
\ttry {\n
\t\tscript.appendChild( document.createTextNode( "window." + id + "=1;" ) );\n
\t} catch(e) {}\n
\n
\troot.insertBefore( script, root.firstChild );\n
\n
\t// Make sure that the execution of code works by injecting a script\n
\t// tag with appendChild/createTextNode\n
\t// (IE doesn\'t support this, fails, and uses .text instead)\n
\tif ( window[ id ] ) {\n
\t\tjQuery.support.scriptEval = true;\n
\t\tdelete window[ id ];\n
\t}\n
\n
\t// Test to see if it\'s possible to delete an expando from an element\n
\t// Fails in Internet Explorer\n
\ttry {\n
\t\tdelete script.test;\n
\t\n
\t} catch(e) {\n
\t\tjQuery.support.deleteExpando = false;\n
\t}\n
\n
\troot.removeChild( script );\n
\n
\tif ( div.attachEvent && div.fireEvent ) {\n
\t\tdiv.attachEvent("onclick", function click() {\n
\t\t\t// Cloning a node shouldn\'t copy over any\n
\t\t\t// bound event handlers (IE does this)\n
\t\t\tjQuery.support.noCloneEvent = false;\n
\t\t\tdiv.detachEvent("onclick", click);\n
\t\t});\n
\t\tdiv.cloneNode(true).fireEvent("onclick");\n
\t}\n
\n
\tdiv = document.createElement("div");\n
\tdiv.innerHTML = "<input type=\'radio\' name=\'radiotest\' checked=\'checked\'/>";\n
\n
\tvar fragment = document.createDocumentFragment();\n
\tfragment.appendChild( div.firstChild );\n
\n
\t// WebKit doesn\'t clone checked state correctly in fragments\n
\tjQuery.support.checkClone = fragment.cloneNode(true).cloneNode(true).lastChild.checked;\n
\n
\t// Figure out if the W3C box model works as expected\n
\t// document.body must exist before we can do this\n
\tjQuery(function() {\n
\t\tvar div = document.createElement("div");\n
\t\tdiv.style.width = div.style.paddingLeft = "1px";\n
\n
\t\tdocument.body.appendChild( div );\n
\t\tjQuery.boxModel = jQuery.support.boxModel = div.offsetWidth === 2;\n
\t\tdocument.body.removeChild( div ).style.display = \'none\';\n
\n
\t\tdiv = null;\n
\t});\n
\n
\t// Technique from Juriy Zaytsev\n
\t// http://thinkweb2.com/projects/prototype/detecting-event-support-without-browser-sniffing/\n
\tvar eventSupported = function( eventName ) { \n
\t\tvar el = document.createElement("div"); \n
\t\teventName = "on" + eventName; \n
\n
\t\tvar isSupported = (eventName in el); \n
\t\tif ( !isSupported ) { \n
\t\t\tel.setAttribute(eventName, "return;"); \n
\t\t\tisSupported = typeof el[eventName] === "function"; \n
\t\t} \n
\t\tel = null; \n
\n
\t\treturn isSupported; \n
\t};\n
\t\n
\tjQuery.support.submitBubbles = eventSupported("submit");\n
\tjQuery.support.changeBubbles = eventSupported("change");\n
\n
\t// release memory in IE\n
\troot = script = div = all = a = null;\n
})();\n
\n
jQuery.props = {\n
\t"for": "htmlFor",\n
\t"class": "className",\n
\treadonly: "readOnly",\n
\tmaxlength: "maxLength",\n
\tcellspacing: "cellSpacing",\n
\trowspan: "rowSpan",\n
\tcolspan: "colSpan",\n
\ttabindex: "tabIndex",\n
\tusemap: "useMap",\n
\tframeborder: "frameBorder"\n
};\n
var expando = "jQuery" + now(), uuid = 0, windowData = {};\n
\n
jQuery.extend({\n
\tcache: {},\n
\t\n
\texpando:expando,\n
\n
\t// The following elements throw uncatchable exceptions if you\n
\t// attempt to add expando properties to them.\n
\tnoData: {\n
\t\t"embed": true,\n
\t\t"object": true,\n
\t\t"applet": true\n
\t},\n
\n
\tdata: function( elem, name, data ) {\n
\t\tif ( elem.nodeName && jQuery.noData[elem.nodeName.toLowerCase()] ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\telem = elem == window ?\n
\t\t\twindowData :\n
\t\t\telem;\n
\n
\t\tvar id = elem[ expando ], cache = jQuery.cache, thisCache;\n
\n
\t\tif ( !id && typeof name === "string" && data === undefined ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\t// Compute a unique ID for the element\n
\t\tif ( !id ) { \n
\t\t\tid = ++uuid;\n
\t\t}\n
\n
\t\t// Avoid generating a new cache unless none exists and we\n
\t\t// want to manipulate it.\n
\t\tif ( typeof name === "object" ) {\n
\t\t\telem[ expando ] = id;\n
\t\t\tthisCache = cache[ id ] = jQuery.extend(true, {}, name);\n
\n
\t\t} else if ( !cache[ id ] ) {\n
\t\t\telem[ expando ] = id;\n
\t\t\tcache[ id ] = {};\n
\t\t}\n
\n
\t\tthisCache = cache[ id ];\n
\n
\t\t// Prevent overriding the named cache with undefined values\n
\t\tif ( data !== undefined ) {\n
\t\t\tthisCache[ name ] = data;\n
\t\t}\n
\n
\t\treturn typeof name === "string" ? thisCache[ name ] : thisCache;\n
\t},\n
\n
\tremoveData: function( elem, name ) {\n
\t\tif ( elem.nodeName && jQuery.noData[elem.nodeName.toLowerCase()] ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\telem = elem == window ?\n
\t\t\twindowData :\n
\t\t\telem;\n
\n
\t\tvar id = elem[ expando ], cache = jQuery.cache, thisCache = cache[ id ];\n
\n
\t\t// If we want to remove a specific section of the element\'s data\n
\t\tif ( name ) {\n
\t\t\tif ( thisCache ) {\n
\t\t\t\t// Remove the section of cache data\n
\t\t\t\tdelete thisCache[ name ];\n
\n
\t\t\t\t// If we\'ve removed all the data, remove the element\'s cache\n
\t\t\t\tif ( jQuery.isEmptyObject(thisCache) ) {\n
\t\t\t\t\tjQuery.removeData( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t// Otherwise, we want to remove all of the element\'s data\n
\t\t} else {\n
\t\t\tif ( jQuery.support.deleteExpando ) {\n
\t\t\t\tdelete elem[ jQuery.expando ];\n
\n
\t\t\t} else if ( elem.removeAttribute ) {\n
\t\t\t\telem.removeAttribute( jQuery.expando );\n
\t\t\t}\n
\n
\t\t\t// Completely remove the data cache\n
\t\t\tdelete cache[ id ];\n
\t\t}\n
\t}\n
});\n
\n
jQuery.fn.extend({\n
\tdata: function( key, value ) {\n
\t\tif ( typeof key === "undefined" && this.length ) {\n
\t\t\treturn jQuery.data( this[0] );\n
\n
\t\t} else if ( typeof key === "object" ) {\n
\t\t\treturn this.each(function() {\n
\t\t\t\tjQuery.data( this, key );\n
\t\t\t});\n
\t\t}\n
\n
\t\tvar parts = key.split(".");\n
\t\tparts[1] = parts[1] ? "." + parts[1] : "";\n
\n
\t\tif ( value === undefined ) {\n
\t\t\tvar data = this.triggerHandler("getData" + parts[1] + "!", [parts[0]]);\n
\n
\t\t\tif ( data === undefined && this.length ) {\n
\t\t\t\tdata = jQuery.data( this[0], key );\n
\t\t\t}\n
\t\t\treturn data === undefined && parts[1] ?\n
\t\t\t\tthis.data( parts[0] ) :\n
\t\t\t\tdata;\n
\t\t} else {\n
\t\t\treturn this.trigger("setData" + parts[1] + "!", [parts[0], value]).each(function() {\n
\t\t\t\tjQuery.data( this, key, value );\n
\t\t\t});\n
\t\t}\n
\t},\n
\n
\tremoveData: function( key ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.removeData( this, key );\n
\t\t});\n
\t}\n
});\n
jQuery.extend({\n
\tqueue: function( elem, type, data ) {\n
\t\tif ( !elem ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\ttype = (type || "fx") + "queue";\n
\t\tvar q = jQuery.data( elem, type );\n
\n
\t\t// Speed up dequeue by getting out quickly if this is just a lookup\n
\t\tif ( !data ) {\n
\t\t\treturn q || [];\n
\t\t}\n
\n
\t\tif ( !q || jQuery.isArray(data) ) {\n
\t\t\tq = jQuery.data( elem, type, jQuery.makeArray(data) );\n
\n
\t\t} else {\n
\t\t\tq.push( data );\n
\t\t}\n
\n
\t\treturn q;\n
\t},\n
\n
\tdequeue: function( elem, type ) {\n
\t\ttype = type || "fx";\n
\n
\t\tvar queue = jQuery.queue( elem, type ), fn = queue.shift();\n
\n
\t\t// If the fx queue is dequeued, always remove the progress sentinel\n
\t\tif ( fn === "inprogress" ) {\n
\t\t\tfn = queue.shift();\n
\t\t}\n
\n
\t\tif ( fn ) {\n
\t\t\t// Add a progress sentinel to prevent the fx queue from being\n
\t\t\t// automatically dequeued\n
\t\t\tif ( type === "fx" ) {\n
\t\t\t\tqueue.unshift("inprogress");\n
\t\t\t}\n
\n
\t\t\tfn.call(elem, function() {\n
\t\t\t\tjQuery.dequeue(elem, type);\n
\t\t\t});\n
\t\t}\n
\t}\n
});\n
\n
jQuery.fn.extend({\n
\tqueue: function( type, data ) {\n
\t\tif ( typeof type !== "string" ) {\n
\t\t\tdata = type;\n
\t\t\ttype = "fx";\n
\t\t}\n
\n
\t\tif ( data === undefined ) {\n
\t\t\treturn jQuery.queue( this[0], type );\n
\t\t}\n
\t\treturn this.each(function( i, elem ) {\n
\t\t\tvar queue = jQuery.queue( this, type, data );\n
\n
\t\t\tif ( type === "fx" && queue[0] !== "inprogress" ) {\n
\t\t\t\tjQuery.dequeue( this, type );\n
\t\t\t}\n
\t\t});\n
\t},\n
\tdequeue: function( type ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.dequeue( this, type );\n
\t\t});\n
\t},\n
\n
\t// Based off of the plugin by Clint Helfers, with permission.\n
\t// http://blindsignals.com/index.php/2009/07/jquery-delay/\n
\tdelay: function( time, type ) {\n
\t\ttime = jQuery.fx ? jQuery.fx.speeds[time] || time : time;\n
\t\ttype = type || "fx";\n
\n
\t\treturn this.queue( type, function() {\n
\t\t\tvar elem = this;\n
\t\t\tsetTimeout(function() {\n
\t\t\t\tjQuery.dequeue( elem, type );\n
\t\t\t}, time );\n
\t\t});\n
\t},\n
\n
\tclearQueue: function( type ) {\n
\t\treturn this.queue( type || "fx", [] );\n
\t}\n
});\n
var rclass = /[\\n\\t]/g,\n
\trspace = /\\s+/,\n
\trreturn = /\\r/g,\n
\trspecialurl = /href|src|style/,\n
\trtype = /(button|input)/i,\n
\trfocusable = /(button|input|object|select|textarea)/i,\n
\trclickable = /^(a|area)$/i,\n
\trradiocheck = /radio|checkbox/;\n
\n
jQuery.fn.extend({\n
\tattr: function( name, value ) {\n
\t\treturn access( this, name, value, true, jQuery.attr );\n
\t},\n
\n
\tremoveAttr: function( name, fn ) {\n
\t\treturn this.each(function(){\n
\t\t\tjQuery.attr( this, name, "" );\n
\t\t\tif ( this.nodeType === 1 ) {\n
\t\t\t\tthis.removeAttribute( name );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\taddClass: function( value ) {\n
\t\tif ( jQuery.isFunction(value) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\tself.addClass( value.call(this, i, self.attr("class")) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( value && typeof value === "string" ) {\n
\t\t\tvar classNames = (value || "").split( rspace );\n
\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tvar elem = this[i];\n
\n
\t\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\t\tif ( !elem.className ) {\n
\t\t\t\t\t\telem.className = value;\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tvar className = " " + elem.className + " ", setClass = elem.className;\n
\t\t\t\t\t\tfor ( var c = 0, cl = classNames.length; c < cl; c++ ) {\n
\t\t\t\t\t\t\tif ( className.indexOf( " " + classNames[c] + " " ) < 0 ) {\n
\t\t\t\t\t\t\t\tsetClass += " " + classNames[c];\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telem.className = jQuery.trim( setClass );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tremoveClass: function( value ) {\n
\t\tif ( jQuery.isFunction(value) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\tself.removeClass( value.call(this, i, self.attr("class")) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( (value && typeof value === "string") || value === undefined ) {\n
\t\t\tvar classNames = (value || "").split(rspace);\n
\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tvar elem = this[i];\n
\n
\t\t\t\tif ( elem.nodeType === 1 && elem.className ) {\n
\t\t\t\t\tif ( value ) {\n
\t\t\t\t\t\tvar className = (" " + elem.className + " ").replace(rclass, " ");\n
\t\t\t\t\t\tfor ( var c = 0, cl = classNames.length; c < cl; c++ ) {\n
\t\t\t\t\t\t\tclassName = className.replace(" " + classNames[c] + " ", " ");\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telem.className = jQuery.trim( className );\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\telem.className = "";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\ttoggleClass: function( value, stateVal ) {\n
\t\tvar type = typeof value, isBool = typeof stateVal === "boolean";\n
\n
\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\tself.toggleClass( value.call(this, i, self.attr("class"), stateVal), stateVal );\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn this.each(function() {\n
\t\t\tif ( type === "string" ) {\n
\t\t\t\t// toggle individual class names\n
\t\t\t\tvar className, i = 0, self = jQuery(this),\n
\t\t\t\t\tstate = stateVal,\n
\t\t\t\t\tclassNames = value.split( rspace );\n
\n
\t\t\t\twhile ( (className = classNames[ i++ ]) ) {\n
\t\t\t\t\t// check each className given, space seperated list\n
\t\t\t\t\tstate = isBool ? state : !self.hasClass( className );\n
\t\t\t\t\tself[ state ? "addClass" : "removeClass" ]( className );\n
\t\t\t\t}\n
\n
\t\t\t} else if ( type === "undefined" || type === "boolean" ) {\n
\t\t\t\tif ( this.className ) {\n
\t\t\t\t\t// store className if set\n
\t\t\t\t\tjQuery.data( this, "__className__", this.className );\n
\t\t\t\t}\n
\n
\t\t\t\t// toggle whole className\n
\t\t\t\tthis.className = this.className || value === false ? "" : jQuery.data( this, "__className__" ) || "";\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\thasClass: function( selector ) {\n
\t\tvar className = " " + selector + " ";\n
\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\tif ( (" " + this[i].className + " ").replace(rclass, " ").indexOf( className ) > -1 ) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn false;\n
\t},\n
\n
\tval: function( value ) {\n
\t\tif ( value === undefined ) {\n
\t\t\tvar elem = this[0];\n
\n
\t\t\tif ( elem ) {\n
\t\t\t\tif ( jQuery.nodeName( elem, "option" ) ) {\n
\t\t\t\t\treturn (elem.attributes.value || {}).specified ? elem.value : elem.text;\n
\t\t\t\t}\n
\n
\t\t\t\t// We need to handle select boxes special\n
\t\t\t\tif ( jQuery.nodeName( elem, "select" ) ) {\n
\t\t\t\t\tvar index = elem.selectedIndex,\n
\t\t\t\t\t\tvalues = [],\n
\t\t\t\t\t\toptions = elem.options,\n
\t\t\t\t\t\tone = elem.type === "select-one";\n
\n
\t\t\t\t\t// Nothing was selected\n
\t\t\t\t\tif ( index < 0 ) {\n
\t\t\t\t\t\treturn null;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\t// Loop through all the selected options\n
\t\t\t\t\tfor ( var i = one ? index : 0, max = one ? index + 1 : options.length; i < max; i++ ) {\n
\t\t\t\t\t\tvar option = options[ i ];\n
\n
\t\t\t\t\t\tif ( option.selected ) {\n
\t\t\t\t\t\t\t// Get the specifc value for the option\n
\t\t\t\t\t\t\tvalue = jQuery(option).val();\n
\n
\t\t\t\t\t\t\t// We don\'t need an array for one selects\n
\t\t\t\t\t\t\tif ( one ) {\n
\t\t\t\t\t\t\t\treturn value;\n
\t\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t\t// Multi-Selects return an array\n
\t\t\t\t\t\t\tvalues.push( value );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\treturn values;\n
\t\t\t\t}\n
\n
\t\t\t\t// Handle the case where in Webkit "" is returned instead of "on" if a value isn\'t specified\n
\t\t\t\tif ( rradiocheck.test( elem.type ) && !jQuery.support.checkOn ) {\n
\t\t\t\t\treturn elem.getAttribute("value") === null ? "on" : elem.value;\n
\t\t\t\t}\n
\t\t\t\t\n
\n
\t\t\t\t// Everything else, we just grab the value\n
\t\t\t\treturn (elem.value || "").replace(rreturn, "");\n
\n
\t\t\t}\n
\n
\t\t\treturn undefined;\n
\t\t}\n
\n
\t\tvar isFunction = jQuery.isFunction(value);\n
\n
\t\treturn this.each(function(i) {\n
\t\t\tvar self = jQuery(this), val = value;\n
\n
\t\t\tif ( this.nodeType !== 1 ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\n
\t\t\tif ( isFunction ) {\n
\t\t\t\tval = value.call(this, i, self.val());\n
\t\t\t}\n
\n
\t\t\t// Typecast each time if the value is a Function and the appended\n
\t\t\t// value is therefore different each time.\n
\t\t\tif ( typeof val === "number" ) {\n
\t\t\t\tval += "";\n
\t\t\t}\n
\n
\t\t\tif ( jQuery.isArray(val) && rradiocheck.test( this.type ) ) {\n
\t\t\t\tthis.checked = jQuery.inArray( self.val(), val ) >= 0;\n
\n
\t\t\t} else if ( jQuery.nodeName( this, "select" ) ) {\n
\t\t\t\tvar values = jQuery.makeArray(val);\n
\n
\t\t\t\tjQuery( "option", this ).each(function() {\n
\t\t\t\t\tthis.selected = jQuery.inArray( jQuery(this).val(), values ) >= 0;\n
\t\t\t\t});\n
\n
\t\t\t\tif ( !values.length ) {\n
\t\t\t\t\tthis.selectedIndex = -1;\n
\t\t\t\t}\n
\n
\t\t\t} else {\n
\t\t\t\tthis.value = val;\n
\t\t\t}\n
\t\t});\n
\t}\n
});\n
\n
jQuery.extend({\n
\tattrFn: {\n
\t\tval: true,\n
\t\tcss: true,\n
\t\thtml: true,\n
\t\ttext: true,\n
\t\tdata: true,\n
\t\twidth: true,\n
\t\theight: true,\n
\t\toffset: true\n
\t},\n
\t\t\n
\tattr: function( elem, name, value, pass ) {\n
\t\t// don\'t set attributes on text and comment nodes\n
\t\tif ( !elem || elem.nodeType === 3 || elem.nodeType === 8 ) {\n
\t\t\treturn undefined;\n
\t\t}\n
\n
\t\tif ( pass && name in jQuery.attrFn ) {\n
\t\t\treturn jQuery(elem)[name](value);\n
\t\t}\n
\n
\t\tvar notxml = elem.nodeType !== 1 || !jQuery.isXMLDoc( elem ),\n
\t\t\t// Whether we are setting (or getting)\n
\t\t\tset = value !== undefined;\n
\n
\t\t// Try to normalize/fix the name\n
\t\tname = notxml && jQuery.props[ name ] || name;\n
\n
\t\t// Only do all the following if this is a node (faster for style)\n
\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t// These attributes require special treatment\n
\t\t\tvar special = rspecialurl.test( name );\n
\n
\t\t\t// Safari mis-reports the default selected property of an option\n
\t\t\t// Accessing the parent\'s selectedIndex property fixes it\n
\t\t\tif ( name === "selected" && !jQuery.support.optSelected ) {\n
\t\t\t\tvar parent = elem.parentNode;\n
\t\t\t\tif ( parent ) {\n
\t\t\t\t\tparent.selectedIndex;\n
\t\n
\t\t\t\t\t// Make sure that it also works with optgroups, see #5701\n
\t\t\t\t\tif ( parent.parentNode ) {\n
\t\t\t\t\t\tparent.parentNode.selectedIndex;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// If applicable, access the attribute via the DOM 0 way\n
\t\t\tif ( name in elem && notxml && !special ) {\n
\t\t\t\tif ( set ) {\n
\t\t\t\t\t// We can\'t allow the type property to be changed (since it causes problems in IE)\n
\t\t\t\t\tif ( name === "type" && rtype.test( elem.nodeName ) && elem.parentNode ) {\n
\t\t\t\t\t\tjQuery.error( "type property can\'t be changed" );\n
\t\t\t\t\t}\n
\n
\t\t\t\t\telem[ name ] = value;\n
\t\t\t\t}\n
\n
\t\t\t\t// browsers index elements by id/name on forms, give priority to attributes.\n
\t\t\t\tif ( jQuery.nodeName( elem, "form" ) && elem.getAttributeNode(name) ) {\n
\t\t\t\t\treturn elem.getAttributeNode( name ).nodeValue;\n
\t\t\t\t}\n
\n
\t\t\t\t// elem.tabIndex doesn\'t always return the correct value when it hasn\'t been explicitly set\n
\t\t\t\t// http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-values-with-javascript/\n
\t\t\t\tif ( name === "tabIndex" ) {\n
\t\t\t\t\tvar attributeNode = elem.getAttributeNode( "tabIndex" );\n
\n
\t\t\t\t\treturn attributeNode && attributeNode.specified ?\n
\t\t\t\t\t\tattributeNode.value :\n
\t\t\t\t\t\trfocusable.test( elem.nodeName ) || rclickable.test( elem.nodeName ) && elem.href ?\n
\t\t\t\t\t\t\t0 :\n
\t\t\t\t\t\t\tundefined;\n
\t\t\t\t}\n
\n
\t\t\t\treturn elem[ name ];\n
\t\t\t}\n
\n
\t\t\tif ( !jQuery.support.style && notxml && name === "style" ) {\n
\t\t\t\tif ( set ) {\n
\t\t\t\t\telem.style.cssText = "" + value;\n
\t\t\t\t}\n
\n
\t\t\t\treturn elem.style.cssText;\n
\t\t\t}\n
\n
\t\t\tif ( set ) {\n
\t\t\t\t// convert the value to a string (all browsers do this but IE) see #1070\n
\t\t\t\telem.setAttribute( name, "" + value );\n
\t\t\t}\n
\n
\t\t\tvar attr = !jQuery.support.hrefNormalized && notxml && special ?\n
\t\t\t\t\t// Some attributes require a special call on IE\n
\t\t\t\t\telem.getAttribute( name, 2 ) :\n
\t\t\t\t\telem.getAttribute( name );\n
\n
\t\t\t// Non-existent attributes return null, we normalize to undefined\n
\t\t\treturn attr === null ? undefined : attr;\n
\t\t}\n
\n
\t\t// elem is actually elem.style ... set the style\n
\t\t// Using attr for specific style information is now deprecated. Use style instead.\n
\t\treturn jQuery.style( elem, name, value );\n
\t}\n
});\n
var rnamespaces = /\\.(.*)$/,\n
\tfcleanup = function( nm ) {\n
\t\treturn nm.replace(/[^\\w\\s\\.\\|`]/g, function( ch ) {\n
\t\t\treturn "\\\\" + ch;\n
\t\t});\n
\t};\n
\n
/*\n
 * A number of helper functions used for managing events.\n
 * Many of the ideas behind this code originated from\n
 * Dean Edwards\' addEvent library.\n
 */\n
jQuery.event = {\n
\n
\t// Bind an event to an element\n
\t// Original by Dean Edwards\n
\tadd: function( elem, types, handler, data ) {\n
\t\tif ( elem.nodeType === 3 || elem.nodeType === 8 ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// For whatever reason, IE has trouble passing the window object\n
\t\t// around, causing it to be cloned in the process\n
\t\tif ( elem.setInterval && ( elem !== window && !elem.frameElement ) ) {\n
\t\t\telem = window;\n
\t\t}\n
\n
\t\tvar handleObjIn, handleObj;\n
\n
\t\tif ( handler.handler ) {\n
\t\t\thandleObjIn = handler;\n
\t\t\thandler = handleObjIn.handler;\n
\t\t}\n
\n
\t\t// Make sure that the function being executed has a unique ID\n
\t\tif ( !handler.guid ) {\n
\t\t\thandler.guid = jQuery.guid++;\n
\t\t}\n
\n
\t\t// Init the element\'s event structure\n
\t\tvar elemData = jQuery.data( elem );\n
\n
\t\t// If no elemData is found then we must be trying to bind to one of the\n
\t\t// banned noData elements\n
\t\tif ( !elemData ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar events = elemData.events = elemData.events || {},\n
\t\t\teventHandle = elemData.handle, eventHandle;\n
\n
\t\tif ( !eventHandle ) {\n
\t\t\telemData.handle = eventHandle = function() {\n
\t\t\t\t// Handle the second event of a trigger and when\n
\t\t\t\t// an event is called after a page has unloaded\n
\t\t\t\treturn typeof jQuery !== "undefined" && !jQuery.event.triggered ?\n
\t\t\t\t\tjQuery.event.handle.apply( eventHandle.elem, arguments ) :\n
\t\t\t\t\tundefined;\n
\t\t\t};\n
\t\t}\n
\n
\t\t// Add elem as a property of the handle function\n
\t\t// This is to prevent a memory leak with non-native events in IE.\n
\t\teventHandle.elem = elem;\n
\n
\t\t// Handle multiple events separated by a space\n
\t\t// jQuery(...).bind("mouseover mouseout", fn);\n
\t\ttypes = types.split(" ");\n
\n
\t\tvar type, i = 0, namespaces;\n
\n
\t\twhile ( (type = types[ i++ ]) ) {\n
\t\t\thandleObj = handleObjIn ?\n
\t\t\t\tjQuery.extend({}, handleObjIn) :\n
\t\t\t\t{ handler: handler, data: data };\n
\n
\t\t\t// Namespaced event handlers\n
\t\t\tif ( type.indexOf(".") > -1 ) {\n
\t\t\t\tnamespaces = type.split(".");\n
\t\t\t\ttype = namespaces.shift();\n
\t\t\t\thandleObj.namespace = namespaces.slice(0).sort().join(".");\n
\n
\t\t\t} else {\n
\t\t\t\tnamespaces = [];\n
\t\t\t\thandleObj.namespace = "";\n
\t\t\t}\n
\n
\t\t\thandleObj.type = type;\n
\t\t\thandleObj.guid = handler.guid;\n
\n
\t\t\t// Get the current list of functions bound to this event\n
\t\t\tvar handlers = events[ type ],\n
\t\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\n
\t\t\t// Init the event handler queue\n
\t\t\tif ( !handlers ) {\n
\t\t\t\thandlers = events[ type ] = [];\n
\n
\t\t\t\t// Check for a special event handler\n
\t\t\t\t// Only use addEventListener/attachEvent if the special\n
\t\t\t\t// events handler returns false\n
\t\t\t\tif ( !special.setup || special.setup.call( elem, data, namespaces, eventHandle ) === false ) {\n
\t\t\t\t\t// Bind the global event handler to the element\n
\t\t\t\t\tif ( elem.addEventListener ) {\n
\t\t\t\t\t\telem.addEventListener( type, eventHandle, false );\n
\n
\t\t\t\t\t} else if ( elem.attachEvent ) {\n
\t\t\t\t\t\telem.attachEvent( "on" + type, eventHandle );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tif ( special.add ) { \n
\t\t\t\tspecial.add.call( elem, handleObj ); \n
\n
\t\t\t\tif ( !handleObj.handler.guid ) {\n
\t\t\t\t\thandleObj.handler.guid = handler.guid;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Add the function to the element\'s handler list\n
\t\t\thandlers.push( handleObj );\n
\n
\t\t\t// Keep track of which events have been used, for global triggering\n
\t\t\tjQuery.event.global[ type ] = true;\n
\t\t}\n
\n
\t\t// Nullify elem to prevent memory leaks in IE\n
\t\telem = null;\n
\t},\n
\n
\tglobal: {},\n
\n
\t// Detach an event or set of events from an element\n
\tremove: function( elem, types, handler, pos ) {\n
\t\t// don\'t do events on text and comment nodes\n
\t\tif ( elem.nodeType === 3 || elem.nodeType === 8 ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar ret, type, fn, i = 0, all, namespaces, namespace, special, eventType, handleObj, origType,\n
\t\t\telemData = jQuery.data( elem ),\n
\t\t\tevents = elemData && elemData.events;\n
\n
\t\tif ( !elemData || !events ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// types is actually an event object here\n
\t\tif ( types && types.type ) {\n
\t\t\thandler = types.handler;\n
\t\t\ttypes = types.type;\n
\t\t}\n
\n
\t\t// Unbind all events for the element\n
\t\tif ( !types || typeof types === "string" && types.charAt(0) === "." ) {\n
\t\t\ttypes = types || "";\n
\n
\t\t\tfor ( type in events ) {\n
\t\t\t\tjQuery.event.remove( elem, type + types );\n
\t\t\t}\n
\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Handle multiple events separated by a space\n
\t\t// jQuery(...).unbind("mouseover mouseout", fn);\n
\t\ttypes = types.split(" ");\n
\n
\t\twhile ( (type = types[ i++ ]) ) {\n
\t\t\torigType = type;\n
\t\t\thandleObj = null;\n
\t\t\tall = type.indexOf(".") < 0;\n
\t\t\tnamespaces = [];\n
\n
\t\t\tif ( !all ) {\n
\t\t\t\t// Namespaced event handlers\n
\t\t\t\tnamespaces = type.split(".");\n
\t\t\t\ttype = namespaces.shift();\n
\n
\t\t\t\tnamespace = new RegExp("(^|\\\\.)" + \n
\t\t\t\t\tjQuery.map( namespaces.slice(0).sort(), fcleanup ).join("\\\\.(?:.*\\\\.)?") + "(\\\\.|$)")\n
\t\t\t}\n
\n
\t\t\teventType = events[ type ];\n
\n
\t\t\tif ( !eventType ) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tif ( !handler ) {\n
\t\t\t\tfor ( var j = 0; j < eventType.length; j++ ) {\n
\t\t\t\t\thandleObj = eventType[ j ];\n
\n
\t\t\t\t\tif ( all || namespace.test( handleObj.namespace ) ) {\n
\t\t\t\t\t\tjQuery.event.remove( elem, origType, handleObj.handler, j );\n
\t\t\t\t\t\teventType.splice( j--, 1 );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\n
\t\t\tfor ( var j = pos || 0; j < eventType.length; j++ ) {\n
\t\t\t\thandleObj = eventType[ j ];\n
\n
\t\t\t\tif ( handler.guid === handleObj.guid ) {\n
\t\t\t\t\t// remove the given handler for the given type\n
\t\t\t\t\tif ( all || namespace.test( handleObj.namespace ) ) {\n
\t\t\t\t\t\tif ( pos == null ) {\n
\t\t\t\t\t\t\teventType.splice( j--, 1 );\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tif ( special.remove ) {\n
\t\t\t\t\t\t\tspecial.remove.call( elem, handleObj );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( pos != null ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// remove generic event handler if no more handlers exist\n
\t\t\tif ( eventType.length === 0 || pos != null && eventType.length === 1 ) {\n
\t\t\t\tif ( !special.teardown || special.teardown.call( elem, namespaces ) === false ) {\n
\t\t\t\t\tremoveEvent( elem, type, elemData.handle );\n
\t\t\t\t}\n
\n
\t\t\t\tret = null;\n
\t\t\t\tdelete events[ type ];\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Remove the expando if it\'s no longer used\n
\t\tif ( jQuery.isEmptyObject( events ) ) {\n
\t\t\tvar handle = elemData.handle;\n
\t\t\tif ( handle ) {\n
\t\t\t\thandle.elem = null;\n
\t\t\t}\n
\n
\t\t\tdelete elemData.events;\n
\t\t\tdelete elemData.handle;\n
\n
\t\t\tif ( jQuery.isEmptyObject( elemData ) ) {\n
\t\t\t\tjQuery.removeData( elem );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// bubbling is internal\n
\ttrigger: function( event, data, elem /*, bubbling */ ) {\n
\t\t// Event object or event type\n
\t\tvar type = event.type || event,\n
\t\t\tbubbling = arguments[3];\n
\n
\t\tif ( !bubbling ) {\n
\t\t\tevent = typeof event === "object" ?\n
\t\t\t\t// jQuery.Event object\n
\t\t\t\tevent[expando] ? event :\n
\t\t\t\t// Object literal\n
\t\t\t\tjQuery.extend( jQuery.Event(type), event ) :\n
\t\t\t\t// Just the event type (string)\n
\t\t\t\tjQuery.Event(type);\n
\n
\t\t\tif ( type.indexOf("!") >= 0 ) {\n
\t\t\t\tevent.type = type = type.slice(0, -1);\n
\t\t\t\tevent.exclusive = true;\n
\t\t\t}\n
\n
\t\t\t// Handle a global trigger\n
\t\t\tif ( !elem ) {\n
\t\t\t\t// Don\'t bubble custom events when global (to avoid too much overhead)\n
\t\t\t\tevent.stopPropagation();\n
\n
\t\t\t\t// Only trigger if we\'ve ever bound an event for it\n
\t\t\t\tif ( jQuery.event.global[ type ] ) {\n
\t\t\t\t\tjQuery.each( jQuery.cache, function() {\n
\t\t\t\t\t\tif ( this.events && this.events[type] ) {\n
\t\t\t\t\t\t\tjQuery.event.trigger( event, data, this.handle.elem );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Handle triggering a single element\n
\n
\t\t\t// don\'t do events on text and comment nodes\n
\t\t\tif ( !elem || elem.nodeType === 3 || elem.nodeType === 8 ) {\n
\t\t\t\treturn undefined;\n
\t\t\t}\n
\n
\t\t\t// Clean up in case it is reused\n
\t\t\tevent.result = undefined;\n
\t\t\tevent.target = elem;\n
\n
\t\t\t// Clone the incoming data, if any\n
\t\t\tdata = jQuery.makeArray( data );\n
\t\t\tdata.unshift( event );\n
\t\t}\n
\n
\t\tevent.currentTarget = elem;\n
\n
\t\t// Trigger the event, it is assumed that "handle" is a function\n
\t\tvar handle = jQuery.data( elem, "handle" );\n
\t\tif ( handle ) {\n
\t\t\thandle.apply( elem, data );\n
\t\t}\n
\n
\t\tvar parent = elem.parentNode || elem.ownerDocument;\n
\n
\t\t// Trigger an inline bound script\n
\t\ttry {\n
\t\t\tif ( !(elem && elem.nodeName && jQuery.noData[elem.nodeName.toLowerCase()]) ) {\n
\t\t\t\tif ( elem[ "on" + type ] && elem[ "on" + type ].apply( elem, data ) === false ) {\n
\t\t\t\t\tevent.result = false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t// prevent IE from throwing an error for some elements with some event types, see #3533\n
\t\t} catch (e) {}\n
\n
\t\tif ( !event.isPropagationStopped() && parent ) {\n
\t\t\tjQuery.event.trigger( event, data, parent, true );\n
\n
\t\t} else if ( !event.isDefaultPrevented() ) {\n
\t\t\tvar target = event.target, old,\n
\t\t\t\tisClick = jQuery.nodeName(target, "a") && type === "click",\n
\t\t\t\tspecial = jQuery.event.special[ type ] || {};\n
\n
\t\t\tif ( (!special._default || special._default.call( elem, event ) === false) && \n
\t\t\t\t!isClick && !(target && target.nodeName && jQuery.noData[target.nodeName.toLowerCase()]) ) {\n
\n
\t\t\t\ttry {\n
\t\t\t\t\tif ( target[ type ] ) {\n
\t\t\t\t\t\t// Make sure that we don\'t accidentally re-trigger the onFOO events\n
\t\t\t\t\t\told = target[ "on" + type ];\n
\n
\t\t\t\t\t\tif ( old ) {\n
\t\t\t\t\t\t\ttarget[ "on" + type ] = null;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\tjQuery.event.triggered = true;\n
\t\t\t\t\t\ttarget[ type ]();\n
\t\t\t\t\t}\n
\n
\t\t\t\t// prevent IE from throwing an error for some elements with some event types, see #3533\n
\t\t\t\t} catch (e) {}\n
\n
\t\t\t\tif ( old ) {\n
\t\t\t\t\ttarget[ "on" + type ] = old;\n
\t\t\t\t}\n
\n
\t\t\t\tjQuery.event.triggered = false;\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\thandle: function( event ) {\n
\t\tvar all, handlers, namespaces, namespace, events;\n
\n
\t\tevent = arguments[0] = jQuery.event.fix( event || window.event );\n
\t\tevent.currentTarget = this;\n
\n
\t\t// Namespaced event handlers\n
\t\tall = event.type.indexOf(".") < 0 && !event.exclusive;\n
\n
\t\tif ( !all ) {\n
\t\t\tnamespaces = event.type.split(".");\n
\t\t\tevent.type = namespaces.shift();\n
\t\t\tnamespace = new RegExp("(^|\\\\.)" + namespaces.slice(0).sort().join("\\\\.(?:.*\\\\.)?") + "(\\\\.|$)");\n
\t\t}\n
\n
\t\tvar events = jQuery.data(this, "events"), handlers = events[ event.type ];\n
\n
\t\tif ( events && handlers ) {\n
\t\t\t// Clone the handlers to prevent manipulation\n
\t\t\thandlers = handlers.slice(0);\n
\n
\t\t\tfor ( var j = 0, l = handlers.length; j < l; j++ ) {\n
\t\t\t\tvar handleObj = handlers[ j ];\n
\n
\t\t\t\t// Filter the functions by class\n
\t\t\t\tif ( all || namespace.test( handleObj.namespace ) ) {\n
\t\t\t\t\t// Pass in a reference to the handler function itself\n
\t\t\t\t\t// So that we can later remove it\n
\t\t\t\t\tevent.handler = handleObj.handler;\n
\t\t\t\t\tevent.data = handleObj.data;\n
\t\t\t\t\tevent.handleObj = handleObj;\n
\t\n
\t\t\t\t\tvar ret = handleObj.handler.apply( this, arguments );\n
\n
\t\t\t\t\tif ( ret !== undefined ) {\n
\t\t\t\t\t\tevent.result = ret;\n
\t\t\t\t\t\tif ( ret === false ) {\n
\t\t\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t\t\t\tevent.stopPropagation();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( event.isImmediatePropagationStopped() ) {\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn event.result;\n
\t},\n
\n
\tprops: "altKey attrChange attrName bubbles button cancelable charCode clientX clientY ctrlKey currentTarget data detail eventPhase fromElement handler keyCode layerX layerY metaKey newValue offsetX offsetY originalTarget pageX pageY prevValue relatedNode relatedTarget screenX screenY shiftKey srcElement target toElement view wheelDelta which".split(" "),\n
\n
\tfix: function( event ) {\n
\t\tif ( event[ expando ] ) {\n
\t\t\treturn event;\n
\t\t}\n
\n
\t\t// store a copy of the original event object\n
\t\t// and "clone" to set read-only properties\n
\t\tvar originalEvent = event;\n
\t\tevent = jQuery.Event( originalEvent );\n
\n
\t\tfor ( var i = this.props.length, prop; i; ) {\n
\t\t\tprop = this.props[ --i ];\n
\t\t\tevent[ prop ] = originalEvent[ prop ];\n
\t\t}\n
\n
\t\t// Fix target property, if necessary\n
\t\tif ( !event.target ) {\n
\t\t\tevent.target = event.srcElement || document; // Fixes #1925 where srcElement might not be defined either\n
\t\t}\n
\n
\t\t// check if target is a textnode (safari)\n
\t\tif ( event.target.nodeType === 3 ) {\n
\t\t\tevent.target = event.target.parentNode;\n
\t\t}\n
\n
\t\t// Add relatedTarget, if necessary\n
\t\tif ( !event.relatedTarget && event.fromElement ) {\n
\t\t\tevent.relatedTarget = event.fromElement === event.target ? event.toElement : event.fromElement;\n
\t\t}\n
\n
\t\t// Calculate pageX/Y if missing and clientX/Y available\n
\t\tif ( event.pageX == null && event.clientX != null ) {\n
\t\t\tvar doc = document.documentElement, body = document.body;\n
\t\t\tevent.pageX = event.clientX + (doc && doc.scrollLeft || body && body.scrollLeft || 0) - (doc && doc.clientLeft || body && body.clientLeft || 0);\n
\t\t\tevent.pageY = event.clientY + (doc && doc.scrollTop  || body && body.scrollTop  || 0) - (doc && doc.clientTop  || body && body.clientTop  || 0);\n
\t\t}\n
\n
\t\t// Add which for key events\n
\t\tif ( !event.which && ((event.charCode || event.charCode === 0) ? event.charCode : event.keyCode) ) {\n
\t\t\tevent.which = event.charCode || event.keyCode;\n
\t\t}\n
\n
\t\t// Add metaKey to non-Mac browsers (use ctrl for PC\'s and Meta for Macs)\n
\t\tif ( !event.metaKey && event.ctrlKey ) {\n
\t\t\tevent.metaKey = event.ctrlKey;\n
\t\t}\n
\n
\t\t// Add which for click: 1 === left; 2 === middle; 3 === right\n
\t\t// Note: button is not normalized, so don\'t use it\n
\t\tif ( !event.which && event.button !== undefined ) {\n
\t\t\tevent.which = (event.button & 1 ? 1 : ( event.button & 2 ? 3 : ( event.button & 4 ? 2 : 0 ) ));\n
\t\t}\n
\n
\t\treturn event;\n
\t},\n
\n
\t// Deprecated, use jQuery.guid instead\n
\tguid: 1E8,\n
\n
\t// Deprecated, use jQuery.proxy instead\n
\tproxy: jQuery.proxy,\n
\n
\tspecial: {\n
\t\tready: {\n
\t\t\t// Make sure the ready event is setup\n
\t\t\tsetup: jQuery.bindReady,\n
\t\t\tteardown: jQuery.noop\n
\t\t},\n
\n
\t\tlive: {\n
\t\t\tadd: function( handleObj ) {\n
\t\t\t\tjQuery.event.add( this, handleObj.origType, jQuery.extend({}, handleObj, {handler: liveHandler}) ); \n
\t\t\t},\n
\n
\t\t\tremove: function( handleObj ) {\n
\t\t\t\tvar remove = true,\n
\t\t\t\t\ttype = handleObj.origType.replace(rnamespaces, "");\n
\t\t\t\t\n
\t\t\t\tjQuery.each( jQuery.data(this, "events").live || [], function() {\n
\t\t\t\t\tif ( type === this.origType.replace(rnamespaces, "") ) {\n
\t\t\t\t\t\tremove = false;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\n
\t\t\t\tif ( remove ) {\n
\t\t\t\t\tjQuery.event.remove( this, handleObj.origType, liveHandler );\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t},\n
\n
\t\tbeforeunload: {\n
\t\t\tsetup: function( data, namespaces, eventHandle ) {\n
\t\t\t\t// We only want to do this special case on windows\n
\t\t\t\tif ( this.setInterval ) {\n
\t\t\t\t\tthis.onbeforeunload = eventHandle;\n
\t\t\t\t}\n
\n
\t\t\t\treturn false;\n
\t\t\t},\n
\t\t\tteardown: function( namespaces, eventHandle ) {\n
\t\t\t\tif ( this.onbeforeunload === eventHandle ) {\n
\t\t\t\t\tthis.onbeforeunload = null;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
};\n
\n
var removeEvent = document.removeEventListener ?\n
\tfunction( elem, type, handle ) {\n
\t\telem.removeEventListener( type, handle, false );\n
\t} : \n
\tfunction( elem, type, handle ) {\n
\t\telem.detachEvent( "on" + type, handle );\n
\t};\n
\n
jQuery.Event = function( src ) {\n
\t// Allow instantiation without the \'new\' keyword\n
\tif ( !this.preventDefault ) {\n
\t\treturn new jQuery.Event( src );\n
\t}\n
\n
\t// Event object\n
\tif ( src && src.type ) {\n
\t\tthis.originalEvent = src;\n
\t\tthis.type = src.type;\n
\t// Event type\n
\t} else {\n
\t\tthis.type = src;\n
\t}\n
\n
\t// timeStamp is buggy for some events on Firefox(#3843)\n
\t// So we won\'t rely on the native value\n
\tthis.timeStamp = now();\n
\n
\t// Mark it as fixed\n
\tthis[ expando ] = true;\n
};\n
\n
function returnFalse() {\n
\treturn false;\n
}\n
function returnTrue() {\n
\treturn true;\n
}\n
\n
// jQuery.Event is based on DOM3 Events as specified by the ECMAScript Language Binding\n
// http://www.w3.org/TR/2003/WD-DOM-Level-3-Events-20030331/ecma-script-binding.html\n
jQuery.Event.prototype = {\n
\tpreventDefault: function() {\n
\t\tthis.isDefaultPrevented = returnTrue;\n
\n
\t\tvar e = this.originalEvent;\n
\t\tif ( !e ) {\n
\t\t\treturn;\n
\t\t}\n
\t\t\n
\t\t// if preventDefault exists run it on the original event\n
\t\tif ( e.preventDefault ) {\n
\t\t\te.preventDefault();\n
\t\t}\n
\t\t// otherwise set the returnValue property of the original event to false (IE)\n
\t\te.returnValue = false;\n
\t},\n
\tstopPropagation: function() {\n
\t\tthis.isPropagationStopped = returnTrue;\n
\n
\t\tvar e = this.originalEvent;\n
\t\tif ( !e ) {\n
\t\t\treturn;\n
\t\t}\n
\t\t// if stopPropagation exists run it on the original event\n
\t\tif ( e.stopPropagation ) {\n
\t\t\te.stopPropagation();\n
\t\t}\n
\t\t// otherwise set the cancelBubble property of the original event to true (IE)\n
\t\te.cancelBubble = true;\n
\t},\n
\tstopImmediatePropagation: function() {\n
\t\tthis.isImmediatePropagationStopped = returnTrue;\n
\t\tthis.stopPropagation();\n
\t},\n
\tisDefaultPrevented: returnFalse,\n
\tisPropagationStopped: returnFalse,\n
\tisImmediatePropagationStopped: returnFalse\n
};\n
\n
// Checks if an event happened on an element within another element\n
// Used in jQuery.event.special.mouseenter and mouseleave handlers\n
var withinElement = function( event ) {\n
\t// Check if mouse(over|out) are still within the same parent element\n
\tvar parent = event.relatedTarget;\n
\n
\t// Firefox sometimes assigns relatedTarget a XUL element\n
\t// which we cannot access the parentNode property of\n
\ttry {\n
\t\t// Traverse up the tree\n
\t\twhile ( parent && parent !== this ) {\n
\t\t\tparent = parent.parentNode;\n
\t\t}\n
\n
\t\tif ( parent !== this ) {\n
\t\t\t// set the correct event type\n
\t\t\tevent.type = event.data;\n
\n
\t\t\t// handle event if we actually just moused on to a non sub-element\n
\t\t\tjQuery.event.handle.apply( this, arguments );\n
\t\t}\n
\n
\t// assuming we\'ve left the element since we most likely mousedover a xul element\n
\t} catch(e) { }\n
},\n
\n
// In case of event delegation, we only need to rename the event.type,\n
// liveHandler will take care of the rest.\n
delegate = function( event ) {\n
\tevent.type = event.data;\n
\tjQuery.event.handle.apply( this, arguments );\n
};\n
\n
// Create mouseenter and mouseleave events\n
jQuery.each({\n
\tmouseenter: "mouseover",\n
\tmouseleave: "mouseout"\n
}, function( orig, fix ) {\n
\tjQuery.event.special[ orig ] = {\n
\t\tsetup: function( data ) {\n
\t\t\tjQuery.event.add( this, fix, data && data.selector ? delegate : withinElement, orig );\n
\t\t},\n
\t\tteardown: function( data ) {\n
\t\t\tjQuery.event.remove( this, fix, data && data.selector ? delegate : withinElement );\n
\t\t}\n
\t};\n
});\n
\n
// submit delegation\n
if ( !jQuery.support.submitBubbles ) {\n
\n
\tjQuery.event.special.submit = {\n
\t\tsetup: function( data, namespaces ) {\n
\t\t\tif ( this.nodeName.toLowerCase() !== "form" ) {\n
\t\t\t\tjQuery.event.add(this, "click.specialSubmit", function( e ) {\n
\t\t\t\t\tvar elem = e.target, type = elem.type;\n
\n
\t\t\t\t\tif ( (type === "submit" || type === "image") && jQuery( elem ).closest("form").length ) {\n
\t\t\t\t\t\treturn trigger( "submit", this, arguments );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t \n
\t\t\t\tjQuery.event.add(this, "keypress.specialSubmit", function( e ) {\n
\t\t\t\t\tvar elem = e.target, type = elem.type;\n
\n
\t\t\t\t\tif ( (type === "text" || type === "password") && jQuery( elem ).closest("form").length && e.keyCode === 13 ) {\n
\t\t\t\t\t\treturn trigger( "submit", this, arguments );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\n
\t\t\t} else {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t},\n
\n
\t\tteardown: function( namespaces ) {\n
\t\t\tjQuery.event.remove( this, ".specialSubmit" );\n
\t\t}\n
\t};\n
\n
}\n
\n
// change delegation, happens here so we have bind.\n
if ( !jQuery.support.changeBubbles ) {\n
\n
\tvar formElems = /textarea|input|select/i,\n
\n
\tchangeFilters,\n
\n
\tgetVal = function( elem ) {\n
\t\tvar type = elem.type, val = elem.value;\n
\n
\t\tif ( type === "radio" || type === "checkbox" ) {\n
\t\t\tval = elem.checked;\n
\n
\t\t} else if ( type === "select-multiple" ) {\n
\t\t\tval = elem.selectedIndex > -1 ?\n
\t\t\t\tjQuery.map( elem.options, function( elem ) {\n
\t\t\t\t\treturn elem.selected;\n
\t\t\t\t}).join("-") :\n
\t\t\t\t"";\n
\n
\t\t} else if ( elem.nodeName.toLowerCase() === "select" ) {\n
\t\t\tval = elem.selectedIndex;\n
\t\t}\n
\n
\t\treturn val;\n
\t},\n
\n
\ttestChange = function testChange( e ) {\n
\t\tvar elem = e.target, data, val;\n
\n
\t\tif ( !formElems.test( elem.nodeName ) || elem.readOnly ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tdata = jQuery.data( elem, "_change_data" );\n
\t\tval = getVal(elem);\n
\n
\t\t// the current data will be also retrieved by beforeactivate\n
\t\tif ( e.type !== "focusout" || elem.type !== "radio" ) {\n
\t\t\tjQuery.data( elem, "_change_data", val );\n
\t\t}\n
\t\t\n
\t\tif ( data === undefined || val === data ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tif ( data != null || val ) {\n
\t\t\te.type = "change";\n
\t\t\treturn jQuery.event.trigger( e, arguments[1], elem );\n
\t\t}\n
\t};\n
\n
\tjQuery.event.special.change = {\n
\t\tfilters: {\n
\t\t\tfocusout: testChange, \n
\n
\t\t\tclick: function( e ) {\n
\t\t\t\tvar elem = e.target, type = elem.type;\n
\n
\t\t\t\tif ( type === "radio" || type === "checkbox" || elem.nodeName.toLowerCase() === "select" ) {\n
\t\t\t\t\treturn testChange.call( this, e );\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\t// Change has to be called before submit\n
\t\t\t// Keydown will be called before keypress, which is used in submit-event delegation\n
\t\t\tkeydown: function( e ) {\n
\t\t\t\tvar elem = e.target, type = elem.type;\n
\n
\t\t\t\tif ( (e.keyCode === 13 && elem.nodeName.toLowerCase() !== "textarea") ||\n
\t\t\t\t\t(e.keyCode === 32 && (type === "checkbox" || type === "radio")) ||\n
\t\t\t\t\ttype === "select-multiple" ) {\n
\t\t\t\t\treturn testChange.call( this, e );\n
\t\t\t\t}\n
\t\t\t},\n
\n
\t\t\t// Beforeactivate happens also before the previous element is blurred\n
\t\t\t// with this event you can\'t trigger a change event, but you can store\n
\t\t\t// information/focus[in] is not needed anymore\n
\t\t\tbeforeactivate: function( e ) {\n
\t\t\t\tvar elem = e.target;\n
\t\t\t\tjQuery.data( elem, "_change_data", getVal(elem) );\n
\t\t\t}\n
\t\t},\n
\n
\t\tsetup: function( data, namespaces ) {\n
\t\t\tif ( this.type === "file" ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\n
\t\t\tfor ( var type in changeFilters ) {\n
\t\t\t\tjQuery.event.add( this, type + ".specialChange", changeFilters[type] );\n
\t\t\t}\n
\n
\t\t\treturn formElems.test( this.nodeName );\n
\t\t},\n
\n
\t\tteardown: function( namespaces ) {\n
\t\t\tjQuery.event.remove( this, ".specialChange" );\n
\n
\t\t\treturn formElems.test( this.nodeName );\n
\t\t}\n
\t};\n
\n
\tchangeFilters = jQuery.event.special.change.filters;\n
}\n
\n
function trigger( type, elem, args ) {\n
\targs[0].type = type;\n
\treturn jQuery.event.handle.apply( elem, args );\n
}\n
\n
// Create "bubbling" focus and blur events\n
if ( document.addEventListener ) {\n
\tjQuery.each({ focus: "focusin", blur: "focusout" }, function( orig, fix ) {\n
\t\tjQuery.event.special[ fix ] = {\n
\t\t\tsetup: function() {\n
\t\t\t\tthis.addEventListener( orig, handler, true );\n
\t\t\t}, \n
\t\t\tteardown: function() { \n
\t\t\t\tthis.removeEventListener( orig, handler, true );\n
\t\t\t}\n
\t\t};\n
\n
\t\tfunction handler( e ) { \n
\t\t\te = jQuery.event.fix( e );\n
\t\t\te.type = fix;\n
\t\t\treturn jQuery.event.handle.call( this, e );\n
\t\t}\n
\t});\n
}\n
\n
jQuery.each(["bind", "one"], function( i, name ) {\n
\tjQuery.fn[ name ] = function( type, data, fn ) {\n
\t\t// Handle object literals\n
\t\tif ( typeof type === "object" ) {\n
\t\t\tfor ( var key in type ) {\n
\t\t\t\tthis[ name ](key, data, type[key], fn);\n
\t\t\t}\n
\t\t\treturn this;\n
\t\t}\n
\t\t\n
\t\tif ( jQuery.isFunction( data ) ) {\n
\t\t\tfn = data;\n
\t\t\tdata = undefined;\n
\t\t}\n
\n
\t\tvar handler = name === "one" ? jQuery.proxy( fn, function( event ) {\n
\t\t\tjQuery( this ).unbind( event, handler );\n
\t\t\treturn fn.apply( this, arguments );\n
\t\t}) : fn;\n
\n
\t\tif ( type === "unload" && name !== "one" ) {\n
\t\t\tthis.one( type, data, fn );\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tjQuery.event.add( this[i], type, handler, data );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t};\n
});\n
\n
jQuery.fn.extend({\n
\tunbind: function( type, fn ) {\n
\t\t// Handle object literals\n
\t\tif ( typeof type === "object" && !type.preventDefault ) {\n
\t\t\tfor ( var key in type ) {\n
\t\t\t\tthis.unbind(key, type[key]);\n
\t\t\t}\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tjQuery.event.remove( this[i], type, fn );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\t\n
\tdelegate: function( selector, types, data, fn ) {\n
\t\treturn this.live( types, data, fn, selector );\n
\t},\n
\t\n
\tundelegate: function( selector, types, fn ) {\n
\t\tif ( arguments.length === 0 ) {\n
\t\t\t\treturn this.unbind( "live" );\n
\t\t\n
\t\t} else {\n
\t\t\treturn this.die( types, null, fn, selector );\n
\t\t}\n
\t},\n
\t\n
\ttrigger: function( type, data ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery.event.trigger( type, data, this );\n
\t\t});\n
\t},\n
\n
\ttriggerHandler: function( type, data ) {\n
\t\tif ( this[0] ) {\n
\t\t\tvar event = jQuery.Event( type );\n
\t\t\tevent.preventDefault();\n
\t\t\tevent.stopPropagation();\n
\t\t\tjQuery.event.trigger( event, data, this[0] );\n
\t\t\treturn event.result;\n
\t\t}\n
\t},\n
\n
\ttoggle: function( fn ) {\n
\t\t// Save reference to arguments for access in closure\n
\t\tvar args = arguments, i = 1;\n
\n
\t\t// link all the functions, so any of them can unbind this click handler\n
\t\twhile ( i < args.length ) {\n
\t\t\tjQuery.proxy( fn, args[ i++ ] );\n
\t\t}\n
\n
\t\treturn this.click( jQuery.proxy( fn, function( event ) {\n
\t\t\t// Figure out which function to execute\n
\t\t\tvar lastToggle = ( jQuery.data( this, "lastToggle" + fn.guid ) || 0 ) % i;\n
\t\t\tjQuery.data( this, "lastToggle" + fn.guid, lastToggle + 1 );\n
\n
\t\t\t// Make sure that clicks stop\n
\t\t\tevent.preventDefault();\n
\n
\t\t\t// and execute the function\n
\t\t\treturn args[ lastToggle ].apply( this, arguments ) || false;\n
\t\t}));\n
\t},\n
\n
\thover: function( fnOver, fnOut ) {\n
\t\treturn this.mouseenter( fnOver ).mouseleave( fnOut || fnOver );\n
\t}\n
});\n
\n
var liveMap = {\n
\tfocus: "focusin",\n
\tblur: "focusout",\n
\tmouseenter: "mouseover",\n
\tmouseleave: "mouseout"\n
};\n
\n
jQuery.each(["live", "die"], function( i, name ) {\n
\tjQuery.fn[ name ] = function( types, data, fn, origSelector /* Internal Use Only */ ) {\n
\t\tvar type, i = 0, match, namespaces, preType,\n
\t\t\tselector = origSelector || this.selector,\n
\t\t\tcontext = origSelector ? this : jQuery( this.context );\n
\n
\t\tif ( jQuery.isFunction( data ) ) {\n
\t\t\tfn = data;\n
\t\t\tdata = undefined;\n
\t\t}\n
\n
\t\ttypes = (types || "").split(" ");\n
\n
\t\twhile ( (type = types[ i++ ]) != null ) {\n
\t\t\tmatch = rnamespaces.exec( type );\n
\t\t\tnamespaces = "";\n
\n
\t\t\tif ( match )  {\n
\t\t\t\tnamespaces = match[0];\n
\t\t\t\ttype = type.replace( rnamespaces, "" );\n
\t\t\t}\n
\n
\t\t\tif ( type === "hover" ) {\n
\t\t\t\ttypes.push( "mouseenter" + namespaces, "mouseleave" + namespaces );\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\tpreType = type;\n
\n
\t\t\tif ( type === "focus" || type === "blur" ) {\n
\t\t\t\ttypes.push( liveMap[ type ] + namespaces );\n
\t\t\t\ttype = type + namespaces;\n
\n
\t\t\t} else {\n
\t\t\t\ttype = (liveMap[ type ] || type) + namespaces;\n
\t\t\t}\n
\n
\t\t\tif ( name === "live" ) {\n
\t\t\t\t// bind live handler\n
\t\t\t\tcontext.each(function(){\n
\t\t\t\t\tjQuery.event.add( this, liveConvert( type, selector ),\n
\t\t\t\t\t\t{ data: data, selector: selector, handler: fn, origType: type, origHandler: fn, preType: preType } );\n
\t\t\t\t});\n
\n
\t\t\t} else {\n
\t\t\t\t// unbind live handler\n
\t\t\t\tcontext.unbind( liveConvert( type, selector ), fn );\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn this;\n
\t}\n
});\n
\n
function liveHandler( event ) {\n
\tvar stop, elems = [], selectors = [], args = arguments,\n
\t\trelated, match, handleObj, elem, j, i, l, data,\n
\t\tevents = jQuery.data( this, "events" );\n
\n
\t// Make sure we avoid non-left-click bubbling in Firefox (#3861)\n
\tif ( event.liveFired === this || !events || !events.live || event.button && event.type === "click" ) {\n
\t\treturn;\n
\t}\n
\n
\tevent.liveFired = this;\n
\n
\tvar live = events.live.slice(0);\n
\n
\tfor ( j = 0; j < live.length; j++ ) {\n
\t\thandleObj = live[j];\n
\n
\t\tif ( handleObj.origType.replace( rnamespaces, "" ) === event.type ) {\n
\t\t\tselectors.push( handleObj.selector );\n
\n
\t\t} else {\n
\t\t\tlive.splice( j--, 1 );\n
\t\t}\n
\t}\n
\n
\tmatch = jQuery( event.target ).closest( selectors, event.currentTarget );\n
\n
\tfor ( i = 0, l = match.length; i < l; i++ ) {\n
\t\tfor ( j = 0; j < live.length; j++ ) {\n
\t\t\thandleObj = live[j];\n
\n
\t\t\tif ( match[i].selector === handleObj.selector ) {\n
\t\t\t\telem = match[i].elem;\n
\t\t\t\trelated = null;\n
\n
\t\t\t\t// Those two events require additional checking\n
\t\t\t\tif ( handleObj.preType === "mouseenter" || handleObj.preType === "mouseleave" ) {\n
\t\t\t\t\trelated = jQuery( event.relatedTarget ).closest( handleObj.selector )[0];\n
\t\t\t\t}\n
\n
\t\t\t\tif ( !related || related !== elem ) {\n
\t\t\t\t\telems.push({ elem: elem, handleObj: handleObj });\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tfor ( i = 0, l = elems.length; i < l; i++ ) {\n
\t\tmatch = elems[i];\n
\t\tevent.currentTarget = match.elem;\n
\t\tevent.data = match.handleObj.data;\n
\t\tevent.handleObj = match.handleObj;\n
\n
\t\tif ( match.handleObj.origHandler.apply( match.elem, args ) === false ) {\n
\t\t\tstop = false;\n
\t\t\tbreak;\n
\t\t}\n
\t}\n
\n
\treturn stop;\n
}\n
\n
function liveConvert( type, selector ) {\n
\treturn "live." + (type && type !== "*" ? type + "." : "") + selector.replace(/\\./g, "`").replace(/ /g, "&");\n
}\n
\n
jQuery.each( ("blur focus focusin focusout load resize scroll unload click dblclick " +\n
\t"mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave " +\n
\t"change select submit keydown keypress keyup error").split(" "), function( i, name ) {\n
\n
\t// Handle event binding\n
\tjQuery.fn[ name ] = function( fn ) {\n
\t\treturn fn ? this.bind( name, fn ) : this.trigger( name );\n
\t};\n
\n
\tif ( jQuery.attrFn ) {\n
\t\tjQuery.attrFn[ name ] = true;\n
\t}\n
});\n
\n
// Prevent memory leaks in IE\n
// Window isn\'t included so as not to unbind existing unload events\n
// More info:\n
//  - http://isaacschlueter.com/2006/10/msie-memory-leaks/\n
if ( window.attachEvent && !window.addEventListener ) {\n
\twindow.attachEvent("onunload", function() {\n
\t\tfor ( var id in jQuery.cache ) {\n
\t\t\tif ( jQuery.cache[ id ].handle ) {\n
\t\t\t\t// Try/Catch is to handle iframes being unloaded, see #4280\n
\t\t\t\ttry {\n
\t\t\t\t\tjQuery.event.remove( jQuery.cache[ id ].handle.elem );\n
\t\t\t\t} catch(e) {}\n
\t\t\t}\n
\t\t}\n
\t});\n
}\n
/*!\n
 * Sizzle CSS Selector Engine - v1.0\n
 *  Copyright 2009, The Dojo Foundation\n
 *  Released under the MIT, BSD, and GPL Licenses.\n
 *  More information: http://sizzlejs.com/\n
 */\n
(function(){\n
\n
var chunker = /((?:\\((?:\\([^()]+\\)|[^()]+)+\\)|\\[(?:\\[[^[\\]]*\\]|[\'"][^\'"]*[\'"]|[^[\\]\'"]+)+\\]|\\\\.|[^ >+~,(\\[\\\\]+)+|[>+~])(\\s*,\\s*)?((?:.|\\r|\\n)*)/g,\n
\tdone = 0,\n
\ttoString = Object.prototype.toString,\n
\thasDuplicate = false,\n
\tbaseHasDuplicate = true;\n
\n
// Here we check if the JavaScript engine is using some sort of\n
// optimization where it does not always call our comparision\n
// function. If that is the case, discard the hasDuplicate value.\n
//   Thus far that includes Google Chrome.\n
[0, 0].sort(function(){\n
\tbaseHasDuplicate = false;\n
\treturn 0;\n
});\n
\n
var Sizzle = function(selector, context, results, seed) {\n
\tresults = results || [];\n
\tvar origContext = context = context || document;\n
\n
\tif ( context.nodeType !== 1 && context.nodeType !== 9 ) {\n
\t\treturn [];\n
\t}\n
\t\n
\tif ( !selector || typeof selector !== "string" ) {\n
\t\treturn results;\n
\t}\n
\n
\tvar parts = [], m, set, checkSet, extra, prune = true, contextXML = isXML(context),\n
\t\tsoFar = selector;\n
\t\n
\t// Reset the position of the chunker regexp (start from head)\n
\twhile ( (chunker.exec(""), m = chunker.exec(soFar)) !== null ) {\n
\t\tsoFar = m[3];\n
\t\t\n
\t\tparts.push( m[1] );\n
\t\t\n
\t\tif ( m[2] ) {\n
\t\t\textra = m[3];\n
\t\t\tbreak;\n
\t\t}\n
\t}\n
\n
\tif ( parts.length > 1 && origPOS.exec( selector ) ) {\n
\t\tif ( parts.length === 2 && Expr.relative[ parts[0] ] ) {\n
\t\t\tset = posProcess( parts[0] + parts[1], context );\n
\t\t} else {\n
\t\t\tset = Expr.relative[ parts[0] ] ?\n
\t\t\t\t[ context ] :\n
\t\t\t\tSizzle( parts.shift(), context );\n
\n
\t\t\twhile ( parts.length ) {\n
\t\t\t\tselector = parts.shift();\n
\n
\t\t\t\tif ( Expr.relative[ selector ] ) {\n
\t\t\t\t\tselector += parts.shift();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tset = posProcess( selector, set );\n
\t\t\t}\n
\t\t}\n
\t} else {\n
\t\t// Take a shortcut and set the context if the root selector is an ID\n
\t\t// (but not if it\'ll be faster if the inner selector is an ID)\n
\t\tif ( !seed && parts.length > 1 && context.nodeType === 9 && !contextXML &&\n
\t\t\t\tExpr.match.ID.test(parts[0]) && !Expr.match.ID.test(parts[parts.length - 1]) ) {\n
\t\t\tvar ret = Sizzle.find( parts.shift(), context, contextXML );\n
\t\t\tcontext = ret.expr ? Sizzle.filter( ret.expr, ret.set )[0] : ret.set[0];\n
\t\t}\n
\n
\t\tif ( context ) {\n
\t\t\tvar ret = seed ?\n
\t\t\t\t{ expr: parts.pop(), set: makeArray(seed) } :\n
\t\t\t\tSizzle.find( parts.pop(), parts.length === 1 && (parts[0] === "~" || parts[0] === "+") && context.parentNode ? context.parentNode : context, contextXML );\n
\t\t\tset = ret.expr ? Sizzle.filter( ret.expr, ret.set ) : ret.set;\n
\n
\t\t\tif ( parts.length > 0 ) {\n
\t\t\t\tcheckSet = makeArray(set);\n
\t\t\t} else {\n
\t\t\t\tprune = false;\n
\t\t\t}\n
\n
\t\t\twhile ( parts.length ) {\n
\t\t\t\tvar cur = parts.pop(), pop = cur;\n
\n
\t\t\t\tif ( !Expr.relative[ cur ] ) {\n
\t\t\t\t\tcur = "";\n
\t\t\t\t} else {\n
\t\t\t\t\tpop = parts.pop();\n
\t\t\t\t}\n
\n
\t\t\t\tif ( pop == null ) {\n
\t\t\t\t\tpop = context;\n
\t\t\t\t}\n
\n
\t\t\t\tExpr.relative[ cur ]( checkSet, pop, contextXML );\n
\t\t\t}\n
\t\t} else {\n
\t\t\tcheckSet = parts = [];\n
\t\t}\n
\t}\n
\n
\tif ( !checkSet ) {\n
\t\tcheckSet = set;\n
\t}\n
\n
\tif ( !checkSet ) {\n
\t\tSizzle.error( cur || selector );\n
\t}\n
\n
\tif ( toString.call(checkSet) === "[object Array]" ) {\n
\t\tif ( !prune ) {\n
\t\t\tresults.push.apply( results, checkSet );\n
\t\t} else if ( context && context.nodeType === 1 ) {\n
\t\t\tfor ( var i = 0; checkSet[i] != null; i++ ) {\n
\t\t\t\tif ( checkSet[i] && (checkSet[i] === true || checkSet[i].nodeType === 1 && contains(context, checkSet[i])) ) {\n
\t\t\t\t\tresults.push( set[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tfor ( var i = 0; checkSet[i] != null; i++ ) {\n
\t\t\t\tif ( checkSet[i] && checkSet[i].nodeType === 1 ) {\n
\t\t\t\t\tresults.push( set[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t} else {\n
\t\tmakeArray( checkSet, results );\n
\t}\n
\n
\tif ( extra ) {\n
\t\tSizzle( extra, origContext, results, seed );\n
\t\tSizzle.uniqueSort( results );\n
\t}\n
\n
\treturn results;\n
};\n
\n
Sizzle.uniqueSort = function(results){\n
\tif ( sortOrder ) {\n
\t\thasDuplicate = baseHasDuplicate;\n
\t\tresults.sort(sortOrder);\n
\n
\t\tif ( hasDuplicate ) {\n
\t\t\tfor ( var i = 1; i < results.length; i++ ) {\n
\t\t\t\tif ( results[i] === results[i-1] ) {\n
\t\t\t\t\tresults.splice(i--, 1);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\treturn results;\n
};\n
\n
Sizzle.matches = function(expr, set){\n
\treturn Sizzle(expr, null, null, set);\n
};\n
\n
Sizzle.find = function(expr, context, isXML){\n
\tvar set, match;\n
\n
\tif ( !expr ) {\n
\t\treturn [];\n
\t}\n
\n
\tfor ( var i = 0, l = Expr.order.length; i < l; i++ ) {\n
\t\tvar type = Expr.order[i], match;\n
\t\t\n
\t\tif ( (match = Expr.leftMatch[ type ].exec( expr )) ) {\n
\t\t\tvar left = match[1];\n
\t\t\tmatch.splice(1,1);\n
\n
\t\t\tif ( left.substr( left.length - 1 ) !== "\\\\" ) {\n
\t\t\t\tmatch[1] = (match[1] || "").replace(/\\\\/g, "");\n
\t\t\t\tset = Expr.find[ type ]( match, context, isXML );\n
\t\t\t\tif ( set != null ) {\n
\t\t\t\t\texpr = expr.replace( Expr.match[ type ], "" );\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tif ( !set ) {\n
\t\tset = context.getElementsByTagName("*");\n
\t}\n
\n
\treturn {set: set, expr: expr};\n
};\n
\n
Sizzle.filter = function(expr, set, inplace, not){\n
\tvar old = expr, result = [], curLoop = set, match, anyFound,\n
\t\tisXMLFilter = set && set[0] && isXML(set[0]);\n
\n
\twhile ( expr && set.length ) {\n
\t\tfor ( var type in Expr.filter ) {\n
\t\t\tif ( (match = Expr.leftMatch[ type ].exec( expr )) != null && match[2] ) {\n
\t\t\t\tvar filter = Expr.filter[ type ], found, item, left = match[1];\n
\t\t\t\tanyFound = false;\n
\n
\t\t\t\tmatch.splice(1,1);\n
\n
\t\t\t\tif ( left.substr( left.length - 1 ) === "\\\\" ) {\n
\t\t\t\t\tcontinue;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( curLoop === result ) {\n
\t\t\t\t\tresult = [];\n
\t\t\t\t}\n
\n
\t\t\t\tif ( Expr.preFilter[ type ] ) {\n
\t\t\t\t\tmatch = Expr.preFilter[ type ]( match, curLoop, inplace, result, not, isXMLFilter );\n
\n
\t\t\t\t\tif ( !match ) {\n
\t\t\t\t\t\tanyFound = found = true;\n
\t\t\t\t\t} else if ( match === true ) {\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( match ) {\n
\t\t\t\t\tfor ( var i = 0; (item = curLoop[i]) != null; i++ ) {\n
\t\t\t\t\t\tif ( item ) {\n
\t\t\t\t\t\t\tfound = filter( item, match, i, curLoop );\n
\t\t\t\t\t\t\tvar pass = not ^ !!found;\n
\n
\t\t\t\t\t\t\tif ( inplace && found != null ) {\n
\t\t\t\t\t\t\t\tif ( pass ) {\n
\t\t\t\t\t\t\t\t\tanyFound = true;\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tcurLoop[i] = false;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t} else if ( pass ) {\n
\t\t\t\t\t\t\t\tresult.push( item );\n
\t\t\t\t\t\t\t\tanyFound = true;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( found !== undefined ) {\n
\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\tcurLoop = result;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\texpr = expr.replace( Expr.match[ type ], "" );\n
\n
\t\t\t\t\tif ( !anyFound ) {\n
\t\t\t\t\t\treturn [];\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Improper expression\n
\t\tif ( expr === old ) {\n
\t\t\tif ( anyFound == null ) {\n
\t\t\t\tSizzle.error( expr );\n
\t\t\t} else {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\told = expr;\n
\t}\n
\n
\treturn curLoop;\n
};\n
\n
Sizzle.error = function( msg ) {\n
\tthrow "Syntax error, unrecognized expression: " + msg;\n
};\n
\n
var Expr = Sizzle.selectors = {\n
\torder: [ "ID", "NAME", "TAG" ],\n
\tmatch: {\n
\t\tID: /#((?:[\\w\\u00c0-\\uFFFF-]|\\\\.)+)/,\n
\t\tCLASS: /\\.((?:[\\w\\u00c0-\\uFFFF-]|\\\\.)+)/,\n
\t\tNAME: /\\[name=[\'"]*((?:[\\w\\u00c0-\\uFFFF-]|\\\\.)+)[\'"]*\\]/,\n
\t\tATTR: /\\[\\s*((?:[\\w\\u00c0-\\uFFFF-]|\\\\.)+)\\s*(?:(\\S?=)\\s*([\'"]*)(.*?)\\3|)\\s*\\]/,\n
\t\tTAG: /^((?:[\\w\\u00c0-\\uFFFF\\*-]|\\\\.)+)/,\n
\t\tCHILD: /:(only|nth|last|first)-child(?:\\((even|odd|[\\dn+-]*)\\))?/,\n
\t\tPOS: /:(nth|eq|gt|lt|first|last|even|odd)(?:\\((\\d*)\\))?(?=[^-]|$)/,\n
\t\tPSEUDO: /:((?:[\\w\\u00c0-\\uFFFF-]|\\\\.)+)(?:\\(([\'"]?)((?:\\([^\\)]+\\)|[^\\(\\)]*)+)\\2\\))?/\n
\t},\n
\tleftMatch: {},\n
\tattrMap: {\n
\t\t"class": "className",\n
\t\t"for": "htmlFor"\n
\t},\n
\tattrHandle: {\n
\t\thref: function(elem){\n
\t\t\treturn elem.getAttribute("href");\n
\t\t}\n
\t},\n
\trelative: {\n
\t\t"+": function(checkSet, part){\n
\t\t\tvar isPartStr = typeof part === "string",\n
\t\t\t\tisTag = isPartStr && !/\\W/.test(part),\n
\t\t\t\tisPartStrNotTag = isPartStr && !isTag;\n
\n
\t\t\tif ( isTag ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\t\t\t}\n
\n
\t\t\tfor ( var i = 0, l = checkSet.length, elem; i < l; i++ ) {\n
\t\t\t\tif ( (elem = checkSet[i]) ) {\n
\t\t\t\t\twhile ( (elem = elem.previousSibling) && elem.nodeType !== 1 ) {}\n
\n
\t\t\t\t\tcheckSet[i] = isPartStrNotTag || elem && elem.nodeName.toLowerCase() === part ?\n
\t\t\t\t\t\telem || false :\n
\t\t\t\t\t\telem === part;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( isPartStrNotTag ) {\n
\t\t\t\tSizzle.filter( part, checkSet, true );\n
\t\t\t}\n
\t\t},\n
\t\t">": function(checkSet, part){\n
\t\t\tvar isPartStr = typeof part === "string";\n
\n
\t\t\tif ( isPartStr && !/\\W/.test(part) ) {\n
\t\t\t\tpart = part.toLowerCase();\n
\n
\t\t\t\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\t\t\t\tvar elem = checkSet[i];\n
\t\t\t\t\tif ( elem ) {\n
\t\t\t\t\t\tvar parent = elem.parentNode;\n
\t\t\t\t\t\tcheckSet[i] = parent.nodeName.toLowerCase() === part ? parent : false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\t\t\t\tvar elem = checkSet[i];\n
\t\t\t\t\tif ( elem ) {\n
\t\t\t\t\t\tcheckSet[i] = isPartStr ?\n
\t\t\t\t\t\t\telem.parentNode :\n
\t\t\t\t\t\t\telem.parentNode === part;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tif ( isPartStr ) {\n
\t\t\t\t\tSizzle.filter( part, checkSet, true );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\t"": function(checkSet, part, isXML){\n
\t\t\tvar doneName = done++, checkFn = dirCheck;\n
\n
\t\t\tif ( typeof part === "string" && !/\\W/.test(part) ) {\n
\t\t\t\tvar nodeCheck = part = part.toLowerCase();\n
\t\t\t\tcheckFn = dirNodeCheck;\n
\t\t\t}\n
\n
\t\t\tcheckFn("parentNode", part, doneName, checkSet, nodeCheck, isXML);\n
\t\t},\n
\t\t"~": function(checkSet, part, isXML){\n
\t\t\tvar doneName = done++, checkFn = dirCheck;\n
\n
\t\t\tif ( typeof part === "string" && !/\\W/.test(part) ) {\n
\t\t\t\tvar nodeCheck = part = part.toLowerCase();\n
\t\t\t\tcheckFn = dirNodeCheck;\n
\t\t\t}\n
\n
\t\t\tcheckFn("previousSibling", part, doneName, checkSet, nodeCheck, isXML);\n
\t\t}\n
\t},\n
\tfind: {\n
\t\tID: function(match, context, isXML){\n
\t\t\tif ( typeof context.getElementById !== "undefined" && !isXML ) {\n
\t\t\t\tvar m = context.getElementById(match[1]);\n
\t\t\t\treturn m ? [m] : [];\n
\t\t\t}\n
\t\t},\n
\t\tNAME: function(match, context){\n
\t\t\tif ( typeof context.getElementsByName !== "undefined" ) {\n
\t\t\t\tvar ret = [], results = context.getElementsByName(match[1]);\n
\n
\t\t\t\tfor ( var i = 0, l = results.length; i < l; i++ ) {\n
\t\t\t\t\tif ( results[i].getAttribute("name") === match[1] ) {\n
\t\t\t\t\t\tret.push( results[i] );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\treturn ret.length === 0 ? null : ret;\n
\t\t\t}\n
\t\t},\n
\t\tTAG: function(match, context){\n
\t\t\treturn context.getElementsByTagName(match[1]);\n
\t\t}\n
\t},\n
\tpreFilter: {\n
\t\tCLASS: function(match, curLoop, inplace, result, not, isXML){\n
\t\t\tmatch = " " + match[1].replace(/\\\\/g, "") + " ";\n
\n
\t\t\tif ( isXML ) {\n
\t\t\t\treturn match;\n
\t\t\t}\n
\n
\t\t\tfor ( var i = 0, elem; (elem = curLoop[i]) != null; i++ ) {\n
\t\t\t\tif ( elem ) {\n
\t\t\t\t\tif ( not ^ (elem.className && (" " + elem.className + " ").replace(/[\\t\\n]/g, " ").indexOf(match) >= 0) ) {\n
\t\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\t\tresult.push( elem );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if ( inplace ) {\n
\t\t\t\t\t\tcurLoop[i] = false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn false;\n
\t\t},\n
\t\tID: function(match){\n
\t\t\treturn match[1].replace(/\\\\/g, "");\n
\t\t},\n
\t\tTAG: function(match, curLoop){\n
\t\t\treturn match[1].toLowerCase();\n
\t\t},\n
\t\tCHILD: function(match){\n
\t\t\tif ( match[1] === "nth" ) {\n
\t\t\t\t// parse equations like \'even\', \'odd\', \'5\', \'2n\', \'3n+2\', \'4n-1\', \'-n+6\'\n
\t\t\t\tvar test = /(-?)(\\d*)n((?:\\+|-)?\\d*)/.exec(\n
\t\t\t\t\tmatch[2] === "even" && "2n" || match[2] === "odd" && "2n+1" ||\n
\t\t\t\t\t!/\\D/.test( match[2] ) && "0n+" + match[2] || match[2]);\n
\n
\t\t\t\t// calculate the numbers (first)n+(last) including if they are negative\n
\t\t\t\tmatch[2] = (test[1] + (test[2] || 1)) - 0;\n
\t\t\t\tmatch[3] = test[3] - 0;\n
\t\t\t}\n
\n
\t\t\t// TODO: Move to normal caching system\n
\t\t\tmatch[0] = done++;\n
\n
\t\t\treturn match;\n
\t\t},\n
\t\tATTR: function(match, curLoop, inplace, result, not, isXML){\n
\t\t\tvar name = match[1].replace(/\\\\/g, "");\n
\t\t\t\n
\t\t\tif ( !isXML && Expr.attrMap[name] ) {\n
\t\t\t\tmatch[1] = Expr.attrMap[name];\n
\t\t\t}\n
\n
\t\t\tif ( match[2] === "~=" ) {\n
\t\t\t\tmatch[4] = " " + match[4] + " ";\n
\t\t\t}\n
\n
\t\t\treturn match;\n
\t\t},\n
\t\tPSEUDO: function(match, curLoop, inplace, result, not){\n
\t\t\tif ( match[1] === "not" ) {\n
\t\t\t\t// If we\'re dealing with a complex expression, or a simple one\n
\t\t\t\tif ( ( chunker.exec(match[3]) || "" ).length > 1 || /^\\w/.test(match[3]) ) {\n
\t\t\t\t\tmatch[3] = Sizzle(match[3], null, null, curLoop);\n
\t\t\t\t} else {\n
\t\t\t\t\tvar ret = Sizzle.filter(match[3], curLoop, inplace, true ^ not);\n
\t\t\t\t\tif ( !inplace ) {\n
\t\t\t\t\t\tresult.push.apply( result, ret );\n
\t\t\t\t\t}\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t} else if ( Expr.match.POS.test( match[0] ) || Expr.match.CHILD.test( match[0] ) ) {\n
\t\t\t\treturn true;\n
\t\t\t}\n
\t\t\t\n
\t\t\treturn match;\n
\t\t},\n
\t\tPOS: function(match){\n
\t\t\tmatch.unshift( true );\n
\t\t\treturn match;\n
\t\t}\n
\t},\n
\tfilters: {\n
\t\tenabled: function(elem){\n
\t\t\treturn elem.disabled === false && elem.type !== "hidden";\n
\t\t},\n
\t\tdisabled: function(elem){\n
\t\t\treturn elem.disabled === true;\n
\t\t},\n
\t\tchecked: function(elem){\n
\t\t\treturn elem.checked === true;\n
\t\t},\n
\t\tselected: function(elem){\n
\t\t\t// Accessing this property makes selected-by-default\n
\t\t\t// options in Safari work properly\n
\t\t\telem.parentNode.selectedIndex;\n
\t\t\treturn elem.selected === true;\n
\t\t},\n
\t\tparent: function(elem){\n
\t\t\treturn !!elem.firstChild;\n
\t\t},\n
\t\tempty: function(elem){\n
\t\t\treturn !elem.firstChild;\n
\t\t},\n
\t\thas: function(elem, i, match){\n
\t\t\treturn !!Sizzle( match[3], elem ).length;\n
\t\t},\n
\t\theader: function(elem){\n
\t\t\treturn /h\\d/i.test( elem.nodeName );\n
\t\t},\n
\t\ttext: function(elem){\n
\t\t\treturn "text" === elem.type;\n
\t\t},\n
\t\tradio: function(elem){\n
\t\t\treturn "radio" === elem.type;\n
\t\t},\n
\t\tcheckbox: function(elem){\n
\t\t\treturn "checkbox" === elem.type;\n
\t\t},\n
\t\tfile: function(elem){\n
\t\t\treturn "file" === elem.type;\n
\t\t},\n
\t\tpassword: function(elem){\n
\t\t\treturn "password" === elem.type;\n
\t\t},\n
\t\tsubmit: function(elem){\n
\t\t\treturn "submit" === elem.type;\n
\t\t},\n
\t\timage: function(elem){\n
\t\t\treturn "image" === elem.type;\n
\t\t},\n
\t\treset: function(elem){\n
\t\t\treturn "reset" === elem.type;\n
\t\t},\n
\t\tbutton: function(elem){\n
\t\t\treturn "button" === elem.type || elem.nodeName.toLowerCase() === "button";\n
\t\t},\n
\t\tinput: function(elem){\n
\t\t\treturn /input|select|textarea|button/i.test(elem.nodeName);\n
\t\t}\n
\t},\n
\tsetFilters: {\n
\t\tfirst: function(elem, i){\n
\t\t\treturn i === 0;\n
\t\t},\n
\t\tlast: function(elem, i, match, array){\n
\t\t\treturn i === array.length - 1;\n
\t\t},\n
\t\teven: function(elem, i){\n
\t\t\treturn i % 2 === 0;\n
\t\t},\n
\t\todd: function(elem, i){\n
\t\t\treturn i % 2 === 1;\n
\t\t},\n
\t\tlt: function(elem, i, match){\n
\t\t\treturn i < match[3] - 0;\n
\t\t},\n
\t\tgt: function(elem, i, match){\n
\t\t\treturn i > match[3] - 0;\n
\t\t},\n
\t\tnth: function(elem, i, match){\n
\t\t\treturn match[3] - 0 === i;\n
\t\t},\n
\t\teq: function(elem, i, match){\n
\t\t\treturn match[3] - 0 === i;\n
\t\t}\n
\t},\n
\tfilter: {\n
\t\tPSEUDO: function(elem, match, i, array){\n
\t\t\tvar name = match[1], filter = Expr.filters[ name ];\n
\n
\t\t\tif ( filter ) {\n
\t\t\t\treturn filter( elem, i, match, array );\n
\t\t\t} else if ( name === "contains" ) {\n
\t\t\t\treturn (elem.textContent || elem.innerText || getText([ elem ]) || "").indexOf(match[3]) >= 0;\n
\t\t\t} else if ( name === "not" ) {\n
\t\t\t\tvar not = match[3];\n
\n
\t\t\t\tfor ( var i = 0, l = not.length; i < l; i++ ) {\n
\t\t\t\t\tif ( not[i] === elem ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\treturn true;\n
\t\t\t} else {\n
\t\t\t\tSizzle.error( "Syntax error, unrecognized expression: " + name );\n
\t\t\t}\n
\t\t},\n
\t\tCHILD: function(elem, match){\n
\t\t\tvar type = match[1], node = elem;\n
\t\t\tswitch (type) {\n
\t\t\t\tcase \'only\':\n
\t\t\t\tcase \'first\':\n
\t\t\t\t\twhile ( (node = node.previousSibling) )\t {\n
\t\t\t\t\t\tif ( node.nodeType === 1 ) { \n
\t\t\t\t\t\t\treturn false; \n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( type === "first" ) { \n
\t\t\t\t\t\treturn true; \n
\t\t\t\t\t}\n
\t\t\t\t\tnode = elem;\n
\t\t\t\tcase \'last\':\n
\t\t\t\t\twhile ( (node = node.nextSibling) )\t {\n
\t\t\t\t\t\tif ( node.nodeType === 1 ) { \n
\t\t\t\t\t\t\treturn false; \n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\treturn true;\n
\t\t\t\tcase \'nth\':\n
\t\t\t\t\tvar first = match[2], last = match[3];\n
\n
\t\t\t\t\tif ( first === 1 && last === 0 ) {\n
\t\t\t\t\t\treturn true;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar doneName = match[0],\n
\t\t\t\t\t\tparent = elem.parentNode;\n
\t\n
\t\t\t\t\tif ( parent && (parent.sizcache !== doneName || !elem.nodeIndex) ) {\n
\t\t\t\t\t\tvar count = 0;\n
\t\t\t\t\t\tfor ( node = parent.firstChild; node; node = node.nextSibling ) {\n
\t\t\t\t\t\t\tif ( node.nodeType === 1 ) {\n
\t\t\t\t\t\t\t\tnode.nodeIndex = ++count;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} \n
\t\t\t\t\t\tparent.sizcache = doneName;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar diff = elem.nodeIndex - last;\n
\t\t\t\t\tif ( first === 0 ) {\n
\t\t\t\t\t\treturn diff === 0;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn ( diff % first === 0 && diff / first >= 0 );\n
\t\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\t\tID: function(elem, match){\n
\t\t\treturn elem.nodeType === 1 && elem.getAttribute("id") === match;\n
\t\t},\n
\t\tTAG: function(elem, match){\n
\t\t\treturn (match === "*" && elem.nodeType === 1) || elem.nodeName.toLowerCase() === match;\n
\t\t},\n
\t\tCLASS: function(elem, match){\n
\t\t\treturn (" " + (elem.className || elem.getAttribute("class")) + " ")\n
\t\t\t\t.indexOf( match ) > -1;\n
\t\t},\n
\t\tATTR: function(elem, match){\n
\t\t\tvar name = match[1],\n
\t\t\t\tresult = Expr.attrHandle[ name ] ?\n
\t\t\t\t\tExpr.attrHandle[ name ]( elem ) :\n
\t\t\t\t\telem[ name ] != null ?\n
\t\t\t\t\t\telem[ name ] :\n
\t\t\t\t\t\telem.getAttribute( name ),\n
\t\t\t\tvalue = result + "",\n
\t\t\t\ttype = match[2],\n
\t\t\t\tcheck = match[4];\n
\n
\t\t\treturn result == null ?\n
\t\t\t\ttype === "!=" :\n
\t\t\t\ttype === "=" ?\n
\t\t\t\tvalue === check :\n
\t\t\t\ttype === "*=" ?\n
\t\t\t\tvalue.indexOf(check) >= 0 :\n
\t\t\t\ttype === "~=" ?\n
\t\t\t\t(" " + value + " ").indexOf(check) >= 0 :\n
\t\t\t\t!check ?\n
\t\t\t\tvalue && result !== false :\n
\t\t\t\ttype === "!=" ?\n
\t\t\t\tvalue !== check :\n
\t\t\t\ttype === "^=" ?\n
\t\t\t\tvalue.indexOf(check) === 0 :\n
\t\t\t\ttype === "$=" ?\n
\t\t\t\tvalue.substr(value.length - check.length) === check :\n
\t\t\t\ttype === "|=" ?\n
\t\t\t\tvalue === check || value.substr(0, check.length + 1) === check + "-" :\n
\t\t\t\tfalse;\n
\t\t},\n
\t\tPOS: function(elem, match, i, array){\n
\t\t\tvar name = match[2], filter = Expr.setFilters[ name ];\n
\n
\t\t\tif ( filter ) {\n
\t\t\t\treturn filter( elem, i, match, array );\n
\t\t\t}\n
\t\t}\n
\t}\n
};\n
\n
var origPOS = Expr.match.POS;\n
\n
for ( var type in Expr.match ) {\n
\tExpr.match[ type ] = new RegExp( Expr.match[ type ].source + /(?![^\\[]*\\])(?![^\\(]*\\))/.source );\n
\tExpr.leftMatch[ type ] = new RegExp( /(^(?:.|\\r|\\n)*?)/.source + Expr.match[ type ].source.replace(/\\\\(\\d+)/g, function(all, num){\n
\t\treturn "\\\\" + (num - 0 + 1);\n
\t}));\n
}\n
\n
var makeArray = function(array, results) {\n
\tarray = Array.prototype.slice.call( array, 0 );\n
\n
\tif ( results ) {\n
\t\tresults.push.apply( results, array );\n
\t\treturn results;\n
\t}\n
\t\n
\treturn array;\n
};\n
\n
// Perform a simple check to determine if the browser is capable of\n
// converting a NodeList to an array using builtin methods.\n
// Also verifies that the returned array holds DOM nodes\n
// (which is not the case in the Blackberry browser)\n
try {\n
\tArray.prototype.slice.call( document.documentElement.childNodes, 0 )[0].nodeType;\n
\n
// Provide a fallback method if it does not work\n
} catch(e){\n
\tmakeArray = function(array, results) {\n
\t\tvar ret = results || [];\n
\n
\t\tif ( toString.call(array) === "[object Array]" ) {\n
\t\t\tArray.prototype.push.apply( ret, array );\n
\t\t} else {\n
\t\t\tif ( typeof array.length === "number" ) {\n
\t\t\t\tfor ( var i = 0, l = array.length; i < l; i++ ) {\n
\t\t\t\t\tret.push( array[i] );\n
\t\t\t\t}\n
\t\t\t} else {\n
\t\t\t\tfor ( var i = 0; array[i]; i++ ) {\n
\t\t\t\t\tret.push( array[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t};\n
}\n
\n
var sortOrder;\n
\n
if ( document.documentElement.compareDocumentPosition ) {\n
\tsortOrder = function( a, b ) {\n
\t\tif ( !a.compareDocumentPosition || !b.compareDocumentPosition ) {\n
\t\t\tif ( a == b ) {\n
\t\t\t\thasDuplicate = true;\n
\t\t\t}\n
\t\t\treturn a.compareDocumentPosition ? -1 : 1;\n
\t\t}\n
\n
\t\tvar ret = a.compareDocumentPosition(b) & 4 ? -1 : a === b ? 0 : 1;\n
\t\tif ( ret === 0 ) {\n
\t\t\thasDuplicate = true;\n
\t\t}\n
\t\treturn ret;\n
\t};\n
} else if ( "sourceIndex" in document.documentElement ) {\n
\tsortOrder = function( a, b ) {\n
\t\tif ( !a.sourceIndex || !b.sourceIndex ) {\n
\t\t\tif ( a == b ) {\n
\t\t\t\thasDuplicate = true;\n
\t\t\t}\n
\t\t\treturn a.sourceIndex ? -1 : 1;\n
\t\t}\n
\n
\t\tvar ret = a.sourceIndex - b.sourceIndex;\n
\t\tif ( ret === 0 ) {\n
\t\t\thasDuplicate = true;\n
\t\t}\n
\t\treturn ret;\n
\t};\n
} else if ( document.createRange ) {\n
\tsortOrder = function( a, b ) {\n
\t\tif ( !a.ownerDocument || !b.ownerDocument ) {\n
\t\t\tif ( a == b ) {\n
\t\t\t\thasDuplicate = true;\n
\t\t\t}\n
\t\t\treturn a.ownerDocument ? -1 : 1;\n
\t\t}\n
\n
\t\tvar aRange = a.ownerDocument.createRange(), bRange = b.ownerDocument.createRange();\n
\t\taRange.setStart(a, 0);\n
\t\taRange.setEnd(a, 0);\n
\t\tbRange.setStart(b, 0);\n
\t\tbRange.setEnd(b, 0);\n
\t\tvar ret = aRange.compareBoundaryPoints(Range.START_TO_END, bRange);\n
\t\tif ( ret === 0 ) {\n
\t\t\thasDuplicate = true;\n
\t\t}\n
\t\treturn ret;\n
\t};\n
}\n
\n
// Utility function for retreiving the text value of an array of DOM nodes\n
function getText( elems ) {\n
\tvar ret = "", elem;\n
\n
\tfor ( var i = 0; elems[i]; i++ ) {\n
\t\telem = elems[i];\n
\n
\t\t// Get the text from text nodes and CDATA nodes\n
\t\tif ( elem.nodeType === 3 || elem.nodeType === 4 ) {\n
\t\t\tret += elem.nodeValue;\n
\n
\t\t// Traverse everything else, except comment nodes\n
\t\t} else if ( elem.nodeType !== 8 ) {\n
\t\t\tret += getText( elem.childNodes );\n
\t\t}\n
\t}\n
\n
\treturn ret;\n
}\n
\n
// Check to see if the browser returns elements by name when\n
// querying by getElementById (and provide a workaround)\n
(function(){\n
\t// We\'re going to inject a fake input element with a specified name\n
\tvar form = document.createElement("div"),\n
\t\tid = "script" + (new Date).getTime();\n
\tform.innerHTML = "<a name=\'" + id + "\'/>";\n
\n
\t// Inject it into the root element, check its status, and remove it quickly\n
\tvar root = document.documentElement;\n
\troot.insertBefore( form, root.firstChild );\n
\n
\t// The workaround has to do additional checks after a getElementById\n
\t// Which slows things down for other browsers (hence the branching)\n
\tif ( document.getElementById( id ) ) {\n
\t\tExpr.find.ID = function(match, context, isXML){\n
\t\t\tif ( typeof context.getElementById !== "undefined" && !isXML ) {\n
\t\t\t\tvar m = context.getElementById(match[1]);\n
\t\t\t\treturn m ? m.id === match[1] || typeof m.getAttributeNode !== "undefined" && m.getAttributeNode("id").nodeValue === match[1] ? [m] : undefined : [];\n
\t\t\t}\n
\t\t};\n
\n
\t\tExpr.filter.ID = function(elem, match){\n
\t\t\tvar node = typeof elem.getAttributeNode !== "undefined" && elem.getAttributeNode("id");\n
\t\t\treturn elem.nodeType === 1 && node && node.nodeValue === match;\n
\t\t};\n
\t}\n
\n
\troot.removeChild( form );\n
\troot = form = null; // release memory in IE\n
})();\n
\n
(function(){\n
\t// Check to see if the browser returns only elements\n
\t// when doing getElementsByTagName("*")\n
\n
\t// Create a fake element\n
\tvar div = document.createElement("div");\n
\tdiv.appendChild( document.createComment("") );\n
\n
\t// Make sure no comments are found\n
\tif ( div.getElementsByTagName("*").length > 0 ) {\n
\t\tExpr.find.TAG = function(match, context){\n
\t\t\tvar results = context.getElementsByTagName(match[1]);\n
\n
\t\t\t// Filter out possible comments\n
\t\t\tif ( match[1] === "*" ) {\n
\t\t\t\tvar tmp = [];\n
\n
\t\t\t\tfor ( var i = 0; results[i]; i++ ) {\n
\t\t\t\t\tif ( results[i].nodeType === 1 ) {\n
\t\t\t\t\t\ttmp.push( results[i] );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\tresults = tmp;\n
\t\t\t}\n
\n
\t\t\treturn results;\n
\t\t};\n
\t}\n
\n
\t// Check to see if an attribute returns normalized href attributes\n
\tdiv.innerHTML = "<a href=\'#\'></a>";\n
\tif ( div.firstChild && typeof div.firstChild.getAttribute !== "undefined" &&\n
\t\t\tdiv.firstChild.getAttribute("href") !== "#" ) {\n
\t\tExpr.attrHandle.href = function(elem){\n
\t\t\treturn elem.getAttribute("href", 2);\n
\t\t};\n
\t}\n
\n
\tdiv = null; // release memory in IE\n
})();\n
\n
if ( document.querySelectorAll ) {\n
\t(function(){\n
\t\tvar oldSizzle = Sizzle, div = document.createElement("div");\n
\t\tdiv.innerHTML = "<p class=\'TEST\'></p>";\n
\n
\t\t// Safari can\'t handle uppercase or unicode characters when\n
\t\t// in quirks mode.\n
\t\tif ( div.querySelectorAll && div.querySelectorAll(".TEST").length === 0 ) {\n
\t\t\treturn;\n
\t\t}\n
\t\n
\t\tSizzle = function(query, context, extra, seed){\n
\t\t\tcontext = context || document;\n
\n
\t\t\t// Only use querySelectorAll on non-XML documents\n
\t\t\t// (ID selectors don\'t work in non-HTML documents)\n
\t\t\tif ( !seed && context.nodeType === 9 && !isXML(context) ) {\n
\t\t\t\ttry {\n
\t\t\t\t\treturn makeArray( context.querySelectorAll(query), extra );\n
\t\t\t\t} catch(e){}\n
\t\t\t}\n
\t\t\n
\t\t\treturn oldSizzle(query, context, extra, seed);\n
\t\t};\n
\n
\t\tfor ( var prop in oldSizzle ) {\n
\t\t\tSizzle[ prop ] = oldSizzle[ prop ];\n
\t\t}\n
\n
\t\tdiv = null; // release memory in IE\n
\t})();\n
}\n
\n
(function(){\n
\tvar div = document.createElement("div");\n
\n
\tdiv.innerHTML = "<div class=\'test e\'></div><div class=\'test\'></div>";\n
\n
\t// Opera can\'t find a second classname (in 9.6)\n
\t// Also, make sure that getElementsByClassName actually exists\n
\tif ( !div.getElementsByClassName || div.getElementsByClassName("e").length === 0 ) {\n
\t\treturn;\n
\t}\n
\n
\t// Safari caches class attributes, doesn\'t catch changes (in 3.2)\n
\tdiv.lastChild.className = "e";\n
\n
\tif ( div.getElementsByClassName("e").length === 1 ) {\n
\t\treturn;\n
\t}\n
\t\n
\tExpr.order.splice(1, 0, "CLASS");\n
\tExpr.find.CLASS = function(match, context, isXML) {\n
\t\tif ( typeof context.getElementsByClassName !== "undefined" && !isXML ) {\n
\t\t\treturn context.getElementsByClassName(match[1]);\n
\t\t}\n
\t};\n
\n
\tdiv = null; // release memory in IE\n
})();\n
\n
function dirNodeCheck( dir, cur, doneName, checkSet, nodeCheck, isXML ) {\n
\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\tvar elem = checkSet[i];\n
\t\tif ( elem ) {\n
\t\t\telem = elem[dir];\n
\t\t\tvar match = false;\n
\n
\t\t\twhile ( elem ) {\n
\t\t\t\tif ( elem.sizcache === doneName ) {\n
\t\t\t\t\tmatch = checkSet[elem.sizset];\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeType === 1 && !isXML ){\n
\t\t\t\t\telem.sizcache = doneName;\n
\t\t\t\t\telem.sizset = i;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeName.toLowerCase() === cur ) {\n
\t\t\t\t\tmatch = elem;\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\telem = elem[dir];\n
\t\t\t}\n
\n
\t\t\tcheckSet[i] = match;\n
\t\t}\n
\t}\n
}\n
\n
function dirCheck( dir, cur, doneName, checkSet, nodeCheck, isXML ) {\n
\tfor ( var i = 0, l = checkSet.length; i < l; i++ ) {\n
\t\tvar elem = checkSet[i];\n
\t\tif ( elem ) {\n
\t\t\telem = elem[dir];\n
\t\t\tvar match = false;\n
\n
\t\t\twhile ( elem ) {\n
\t\t\t\tif ( elem.sizcache === doneName ) {\n
\t\t\t\t\tmatch = checkSet[elem.sizset];\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\t\tif ( !isXML ) {\n
\t\t\t\t\t\telem.sizcache = doneName;\n
\t\t\t\t\t\telem.sizset = i;\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( typeof cur !== "string" ) {\n
\t\t\t\t\t\tif ( elem === cur ) {\n
\t\t\t\t\t\t\tmatch = true;\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t} else if ( Sizzle.filter( cur, [elem] ).length > 0 ) {\n
\t\t\t\t\t\tmatch = elem;\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\telem = elem[dir];\n
\t\t\t}\n
\n
\t\t\tcheckSet[i] = match;\n
\t\t}\n
\t}\n
}\n
\n
var contains = document.compareDocumentPosition ? function(a, b){\n
\treturn !!(a.compareDocumentPosition(b) & 16);\n
} : function(a, b){\n
\treturn a !== b && (a.contains ? a.contains(b) : true);\n
};\n
\n
var isXML = function(elem){\n
\t// documentElement is verified for cases where it doesn\'t yet exist\n
\t// (such as loading iframes in IE - #4833) \n
\tvar documentElement = (elem ? elem.ownerDocument || elem : 0).documentElement;\n
\treturn documentElement ? documentElement.nodeName !== "HTML" : false;\n
};\n
\n
var posProcess = function(selector, context){\n
\tvar tmpSet = [], later = "", match,\n
\t\troot = context.nodeType ? [context] : context;\n
\n
\t// Position selectors must be done after the filter\n
\t// And so must :not(positional) so we move all PSEUDOs to the end\n
\twhile ( (match = Expr.match.PSEUDO.exec( selector )) ) {\n
\t\tlater += match[0];\n
\t\tselector = selector.replace( Expr.match.PSEUDO, "" );\n
\t}\n
\n
\tselector = Expr.relative[selector] ? selector + "*" : selector;\n
\n
\tfor ( var i = 0, l = root.length; i < l; i++ ) {\n
\t\tSizzle( selector, root[i], tmpSet );\n
\t}\n
\n
\treturn Sizzle.filter( later, tmpSet );\n
};\n
\n
// EXPOSE\n
jQuery.find = Sizzle;\n
jQuery.expr = Sizzle.selectors;\n
jQuery.expr[":"] = jQuery.expr.filters;\n
jQuery.unique = Sizzle.uniqueSort;\n
jQuery.text = getText;\n
jQuery.isXMLDoc = isXML;\n
jQuery.contains = contains;\n
\n
return;\n
\n
window.Sizzle = Sizzle;\n
\n
})();\n
var runtil = /Until$/,\n
\trparentsprev = /^(?:parents|prevUntil|prevAll)/,\n
\t// Note: This RegExp should be improved, or likely pulled from Sizzle\n
\trmultiselector = /,/,\n
\tslice = Array.prototype.slice;\n
\n
// Implement the identical functionality for filter and not\n
var winnow = function( elements, qualifier, keep ) {\n
\tif ( jQuery.isFunction( qualifier ) ) {\n
\t\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\t\treturn !!qualifier.call( elem, i, elem ) === keep;\n
\t\t});\n
\n
\t} else if ( qualifier.nodeType ) {\n
\t\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\t\treturn (elem === qualifier) === keep;\n
\t\t});\n
\n
\t} else if ( typeof qualifier === "string" ) {\n
\t\tvar filtered = jQuery.grep(elements, function( elem ) {\n
\t\t\treturn elem.nodeType === 1;\n
\t\t});\n
\n
\t\tif ( isSimple.test( qualifier ) ) {\n
\t\t\treturn jQuery.filter(qualifier, filtered, !keep);\n
\t\t} else {\n
\t\t\tqualifier = jQuery.filter( qualifier, filtered );\n
\t\t}\n
\t}\n
\n
\treturn jQuery.grep(elements, function( elem, i ) {\n
\t\treturn (jQuery.inArray( elem, qualifier ) >= 0) === keep;\n
\t});\n
};\n
\n
jQuery.fn.extend({\n
\tfind: function( selector ) {\n
\t\tvar ret = this.pushStack( "", "find", selector ), length = 0;\n
\n
\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\tlength = ret.length;\n
\t\t\tjQuery.find( selector, this[i], ret );\n
\n
\t\t\tif ( i > 0 ) {\n
\t\t\t\t// Make sure that the results are unique\n
\t\t\t\tfor ( var n = length; n < ret.length; n++ ) {\n
\t\t\t\t\tfor ( var r = 0; r < length; r++ ) {\n
\t\t\t\t\t\tif ( ret[r] === ret[n] ) {\n
\t\t\t\t\t\t\tret.splice(n--, 1);\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\thas: function( target ) {\n
\t\tvar targets = jQuery( target );\n
\t\treturn this.filter(function() {\n
\t\t\tfor ( var i = 0, l = targets.length; i < l; i++ ) {\n
\t\t\t\tif ( jQuery.contains( this, targets[i] ) ) {\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tnot: function( selector ) {\n
\t\treturn this.pushStack( winnow(this, selector, false), "not", selector);\n
\t},\n
\n
\tfilter: function( selector ) {\n
\t\treturn this.pushStack( winnow(this, selector, true), "filter", selector );\n
\t},\n
\t\n
\tis: function( selector ) {\n
\t\treturn !!selector && jQuery.filter( selector, this ).length > 0;\n
\t},\n
\n
\tclosest: function( selectors, context ) {\n
\t\tif ( jQuery.isArray( selectors ) ) {\n
\t\t\tvar ret = [], cur = this[0], match, matches = {}, selector;\n
\n
\t\t\tif ( cur && selectors.length ) {\n
\t\t\t\tfor ( var i = 0, l = selectors.length; i < l; i++ ) {\n
\t\t\t\t\tselector = selectors[i];\n
\n
\t\t\t\t\tif ( !matches[selector] ) {\n
\t\t\t\t\t\tmatches[selector] = jQuery.expr.match.POS.test( selector ) ? \n
\t\t\t\t\t\t\tjQuery( selector, context || this.context ) :\n
\t\t\t\t\t\t\tselector;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\twhile ( cur && cur.ownerDocument && cur !== context ) {\n
\t\t\t\t\tfor ( selector in matches ) {\n
\t\t\t\t\t\tmatch = matches[selector];\n
\n
\t\t\t\t\t\tif ( match.jquery ? match.index(cur) > -1 : jQuery(cur).is(match) ) {\n
\t\t\t\t\t\t\tret.push({ selector: selector, elem: cur });\n
\t\t\t\t\t\t\tdelete matches[selector];\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\tcur = cur.parentNode;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn ret;\n
\t\t}\n
\n
\t\tvar pos = jQuery.expr.match.POS.test( selectors ) ? \n
\t\t\tjQuery( selectors, context || this.context ) : null;\n
\n
\t\treturn this.map(function( i, cur ) {\n
\t\t\twhile ( cur && cur.ownerDocument && cur !== context ) {\n
\t\t\t\tif ( pos ? pos.index(cur) > -1 : jQuery(cur).is(selectors) ) {\n
\t\t\t\t\treturn cur;\n
\t\t\t\t}\n
\t\t\t\tcur = cur.parentNode;\n
\t\t\t}\n
\t\t\treturn null;\n
\t\t});\n
\t},\n
\t\n
\t// Determine the position of an element within\n
\t// the matched set of elements\n
\tindex: function( elem ) {\n
\t\tif ( !elem || typeof elem === "string" ) {\n
\t\t\treturn jQuery.inArray( this[0],\n
\t\t\t\t// If it receives a string, the selector is used\n
\t\t\t\t// If it receives nothing, the siblings are used\n
\t\t\t\telem ? jQuery( elem ) : this.parent().children() );\n
\t\t}\n
\t\t// Locate the position of the desired element\n
\t\treturn jQuery.inArray(\n
\t\t\t// If it receives a jQuery object, the first element is used\n
\t\t\telem.jquery ? elem[0] : elem, this );\n
\t},\n
\n
\tadd: function( selector, context ) {\n
\t\tvar set = typeof selector === "string" ?\n
\t\t\t\tjQuery( selector, context || this.context ) :\n
\t\t\t\tjQuery.makeArray( selector ),\n
\t\t\tall = jQuery.merge( this.get(), set );\n
\n
\t\treturn this.pushStack( isDisconnected( set[0] ) || isDisconnected( all[0] ) ?\n
\t\t\tall :\n
\t\t\tjQuery.unique( all ) );\n
\t},\n
\n
\tandSelf: function() {\n
\t\treturn this.add( this.prevObject );\n
\t}\n
});\n
\n
// A painfully simple check to see if an element is disconnected\n
// from a document (should be improved, where feasible).\n
function isDisconnected( node ) {\n
\treturn !node || !node.parentNode || node.parentNode.nodeType === 11;\n
}\n
\n
jQuery.each({\n
\tparent: function( elem ) {\n
\t\tvar parent = elem.parentNode;\n
\t\treturn parent && parent.nodeType !== 11 ? parent : null;\n
\t},\n
\tparents: function( elem ) {\n
\t\treturn jQuery.dir( elem, "parentNode" );\n
\t},\n
\tparentsUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "parentNode", until );\n
\t},\n
\tnext: function( elem ) {\n
\t\treturn jQuery.nth( elem, 2, "nextSibling" );\n
\t},\n
\tprev: function( elem ) {\n
\t\treturn jQuery.nth( elem, 2, "previousSibling" );\n
\t},\n
\tnextAll: function( elem ) {\n
\t\treturn jQuery.dir( elem, "nextSibling" );\n
\t},\n
\tprevAll: function( elem ) {\n
\t\treturn jQuery.dir( elem, "previousSibling" );\n
\t},\n
\tnextUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "nextSibling", until );\n
\t},\n
\tprevUntil: function( elem, i, until ) {\n
\t\treturn jQuery.dir( elem, "previousSibling", until );\n
\t},\n
\tsiblings: function( elem ) {\n
\t\treturn jQuery.sibling( elem.parentNode.firstChild, elem );\n
\t},\n
\tchildren: function( elem ) {\n
\t\treturn jQuery.sibling( elem.firstChild );\n
\t},\n
\tcontents: function( elem ) {\n
\t\treturn jQuery.nodeName( elem, "iframe" ) ?\n
\t\t\telem.contentDocument || elem.contentWindow.document :\n
\t\t\tjQuery.makeArray( elem.childNodes );\n
\t}\n
}, function( name, fn ) {\n
\tjQuery.fn[ name ] = function( until, selector ) {\n
\t\tvar ret = jQuery.map( this, fn, until );\n
\t\t\n
\t\tif ( !runtil.test( name ) ) {\n
\t\t\tselector = until;\n
\t\t}\n
\n
\t\tif ( selector && typeof selector === "string" ) {\n
\t\t\tret = jQuery.filter( selector, ret );\n
\t\t}\n
\n
\t\tret = this.length > 1 ? jQuery.unique( ret ) : ret;\n
\n
\t\tif ( (this.length > 1 || rmultiselector.test( selector )) && rparentsprev.test( name ) ) {\n
\t\t\tret = ret.reverse();\n
\t\t}\n
\n
\t\treturn this.pushStack( ret, name, slice.call(arguments).join(",") );\n
\t};\n
});\n
\n
jQuery.extend({\n
\tfilter: function( expr, elems, not ) {\n
\t\tif ( not ) {\n
\t\t\texpr = ":not(" + expr + ")";\n
\t\t}\n
\n
\t\treturn jQuery.find.matches(expr, elems);\n
\t},\n
\t\n
\tdir: function( elem, dir, until ) {\n
\t\tvar matched = [], cur = elem[dir];\n
\t\twhile ( cur && cur.nodeType !== 9 && (until === undefined || cur.nodeType !== 1 || !jQuery( cur ).is( until )) ) {\n
\t\t\tif ( cur.nodeType === 1 ) {\n
\t\t\t\tmatched.push( cur );\n
\t\t\t}\n
\t\t\tcur = cur[dir];\n
\t\t}\n
\t\treturn matched;\n
\t},\n
\n
\tnth: function( cur, result, dir, elem ) {\n
\t\tresult = result || 1;\n
\t\tvar num = 0;\n
\n
\t\tfor ( ; cur; cur = cur[dir] ) {\n
\t\t\tif ( cur.nodeType === 1 && ++num === result ) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn cur;\n
\t},\n
\n
\tsibling: function( n, elem ) {\n
\t\tvar r = [];\n
\n
\t\tfor ( ; n; n = n.nextSibling ) {\n
\t\t\tif ( n.nodeType === 1 && n !== elem ) {\n
\t\t\t\tr.push( n );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn r;\n
\t}\n
});\n
var rinlinejQuery = / jQuery\\d+="(?:\\d+|null)"/g,\n
\trleadingWhitespace = /^\\s+/,\n
\trxhtmlTag = /(<([\\w:]+)[^>]*?)\\/>/g,\n
\trselfClosing = /^(?:area|br|col|embed|hr|img|input|link|meta|param)$/i,\n
\trtagName = /<([\\w:]+)/,\n
\trtbody = /<tbody/i,\n
\trhtml = /<|&#?\\w+;/,\n
\trnocache = /<script|<object|<embed|<option|<style/i,\n
\trchecked = /checked\\s*(?:[^=]|=\\s*.checked.)/i,  // checked="checked" or checked (html5)\n
\tfcloseTag = function( all, front, tag ) {\n
\t\treturn rselfClosing.test( tag ) ?\n
\t\t\tall :\n
\t\t\tfront + "></" + tag + ">";\n
\t},\n
\twrapMap = {\n
\t\toption: [ 1, "<select multiple=\'multiple\'>", "</select>" ],\n
\t\tlegend: [ 1, "<fieldset>", "</fieldset>" ],\n
\t\tthead: [ 1, "<table>", "</table>" ],\n
\t\ttr: [ 2, "<table><tbody>", "</tbody></table>" ],\n
\t\ttd: [ 3, "<table><tbody><tr>", "</tr></tbody></table>" ],\n
\t\tcol: [ 2, "<table><tbody></tbody><colgroup>", "</colgroup></table>" ],\n
\t\tarea: [ 1, "<map>", "</map>" ],\n
\t\t_default: [ 0, "", "" ]\n
\t};\n
\n
wrapMap.optgroup = wrapMap.option;\n
wrapMap.tbody = wrapMap.tfoot = wrapMap.colgroup = wrapMap.caption = wrapMap.thead;\n
wrapMap.th = wrapMap.td;\n
\n
// IE can\'t serialize <link> and <script> tags normally\n
if ( !jQuery.support.htmlSerialize ) {\n
\twrapMap._default = [ 1, "div<div>", "</div>" ];\n
}\n
\n
jQuery.fn.extend({\n
\ttext: function( text ) {\n
\t\tif ( jQuery.isFunction(text) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\tself.text( text.call(this, i, self.text()) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( typeof text !== "object" && text !== undefined ) {\n
\t\t\treturn this.empty().append( (this[0] && this[0].ownerDocument || document).createTextNode( text ) );\n
\t\t}\n
\n
\t\treturn jQuery.text( this );\n
\t},\n
\n
\twrapAll: function( html ) {\n
\t\tif ( jQuery.isFunction( html ) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tjQuery(this).wrapAll( html.call(this, i) );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this[0] ) {\n
\t\t\t// The elements to wrap the target around\n
\t\t\tvar wrap = jQuery( html, this[0].ownerDocument ).eq(0).clone(true);\n
\n
\t\t\tif ( this[0].parentNode ) {\n
\t\t\t\twrap.insertBefore( this[0] );\n
\t\t\t}\n
\n
\t\t\twrap.map(function() {\n
\t\t\t\tvar elem = this;\n
\n
\t\t\t\twhile ( elem.firstChild && elem.firstChild.nodeType === 1 ) {\n
\t\t\t\t\telem = elem.firstChild;\n
\t\t\t\t}\n
\n
\t\t\t\treturn elem;\n
\t\t\t}).append(this);\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\twrapInner: function( html ) {\n
\t\tif ( jQuery.isFunction( html ) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tjQuery(this).wrapInner( html.call(this, i) );\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn this.each(function() {\n
\t\t\tvar self = jQuery( this ), contents = self.contents();\n
\n
\t\t\tif ( contents.length ) {\n
\t\t\t\tcontents.wrapAll( html );\n
\n
\t\t\t} else {\n
\t\t\t\tself.append( html );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\twrap: function( html ) {\n
\t\treturn this.each(function() {\n
\t\t\tjQuery( this ).wrapAll( html );\n
\t\t});\n
\t},\n
\n
\tunwrap: function() {\n
\t\treturn this.parent().each(function() {\n
\t\t\tif ( !jQuery.nodeName( this, "body" ) ) {\n
\t\t\t\tjQuery( this ).replaceWith( this.childNodes );\n
\t\t\t}\n
\t\t}).end();\n
\t},\n
\n
\tappend: function() {\n
\t\treturn this.domManip(arguments, true, function( elem ) {\n
\t\t\tif ( this.nodeType === 1 ) {\n
\t\t\t\tthis.appendChild( elem );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tprepend: function() {\n
\t\treturn this.domManip(arguments, true, function( elem ) {\n
\t\t\tif ( this.nodeType === 1 ) {\n
\t\t\t\tthis.insertBefore( elem, this.firstChild );\n
\t\t\t}\n
\t\t});\n
\t},\n
\n
\tbefore: function() {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\treturn this.domManip(arguments, false, function( elem ) {\n
\t\t\t\tthis.parentNode.insertBefore( elem, this );\n
\t\t\t});\n
\t\t} else if ( arguments.length ) {\n
\t\t\tvar set = jQuery(arguments[0]);\n
\t\t\tset.push.apply( set, this.toArray() );\n
\t\t\treturn this.pushStack( set, "before", arguments );\n
\t\t}\n
\t},\n
\n
\tafter: function() {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\treturn this.domManip(arguments, false, function( elem ) {\n
\t\t\t\tthis.parentNode.insertBefore( elem, this.nextSibling );\n
\t\t\t});\n
\t\t} else if ( arguments.length ) {\n
\t\t\tvar set = this.pushStack( this, "after", arguments );\n
\t\t\tset.push.apply( set, jQuery(arguments[0]).toArray() );\n
\t\t\treturn set;\n
\t\t}\n
\t},\n
\t\n
\t// keepData is for internal use only--do not document\n
\tremove: function( selector, keepData ) {\n
\t\tfor ( var i = 0, elem; (elem = this[i]) != null; i++ ) {\n
\t\t\tif ( !selector || jQuery.filter( selector, [ elem ] ).length ) {\n
\t\t\t\tif ( !keepData && elem.nodeType === 1 ) {\n
\t\t\t\t\tjQuery.cleanData( elem.getElementsByTagName("*") );\n
\t\t\t\t\tjQuery.cleanData( [ elem ] );\n
\t\t\t\t}\n
\n
\t\t\t\tif ( elem.parentNode ) {\n
\t\t\t\t\t elem.parentNode.removeChild( elem );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn this;\n
\t},\n
\n
\tempty: function() {\n
\t\tfor ( var i = 0, elem; (elem = this[i]) != null; i++ ) {\n
\t\t\t// Remove element nodes and prevent memory leaks\n
\t\t\tif ( elem.nodeType === 1 ) {\n
\t\t\t\tjQuery.cleanData( elem.getElementsByTagName("*") );\n
\t\t\t}\n
\n
\t\t\t// Remove any remaining nodes\n
\t\t\twhile ( elem.firstChild ) {\n
\t\t\t\telem.removeChild( elem.firstChild );\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\treturn this;\n
\t},\n
\n
\tclone: function( events ) {\n
\t\t// Do the clone\n
\t\tvar ret = this.map(function() {\n
\t\t\tif ( !jQuery.support.noCloneEvent && !jQuery.isXMLDoc(this) ) {\n
\t\t\t\t// IE copies events bound via attachEvent when\n
\t\t\t\t// using cloneNode. Calling detachEvent on the\n
\t\t\t\t// clone will also remove the events from the orignal\n
\t\t\t\t// In order to get around this, we use innerHTML.\n
\t\t\t\t// Unfortunately, this means some modifications to\n
\t\t\t\t// attributes in IE that are actually only stored\n
\t\t\t\t// as properties will not be copied (such as the\n
\t\t\t\t// the name attribute on an input).\n
\t\t\t\tvar html = this.outerHTML, ownerDocument = this.ownerDocument;\n
\t\t\t\tif ( !html ) {\n
\t\t\t\t\tvar div = ownerDocument.createElement("div");\n
\t\t\t\t\tdiv.appendChild( this.cloneNode(true) );\n
\t\t\t\t\thtml = div.innerHTML;\n
\t\t\t\t}\n
\n
\t\t\t\treturn jQuery.clean([html.replace(rinlinejQuery, "")\n
\t\t\t\t\t// Handle the case in IE 8 where action=/test/> self-closes a tag\n
\t\t\t\t\t.replace(/=([^="\'>\\s]+\\/)>/g, \'="$1">\')\n
\t\t\t\t\t.replace(rleadingWhitespace, "")], ownerDocument)[0];\n
\t\t\t} else {\n
\t\t\t\treturn this.cloneNode(true);\n
\t\t\t}\n
\t\t});\n
\n
\t\t// Copy the events from the original to the clone\n
\t\tif ( events === true ) {\n
\t\t\tcloneCopyEvent( this, ret );\n
\t\t\tcloneCopyEvent( this.find("*"), ret.find("*") );\n
\t\t}\n
\n
\t\t// Return the cloned set\n
\t\treturn ret;\n
\t},\n
\n
\thtml: function( value ) {\n
\t\tif ( value === undefined ) {\n
\t\t\treturn this[0] && this[0].nodeType === 1 ?\n
\t\t\t\tthis[0].innerHTML.replace(rinlinejQuery, "") :\n
\t\t\t\tnull;\n
\n
\t\t// See if we can take a shortcut and just use innerHTML\n
\t\t} else if ( typeof value === "string" && !rnocache.test( value ) &&\n
\t\t\t(jQuery.support.leadingWhitespace || !rleadingWhitespace.test( value )) &&\n
\t\t\t!wrapMap[ (rtagName.exec( value ) || ["", ""])[1].toLowerCase() ] ) {\n
\n
\t\t\tvalue = value.replace(rxhtmlTag, fcloseTag);\n
\n
\t\t\ttry {\n
\t\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\t\t// Remove element nodes and prevent memory leaks\n
\t\t\t\t\tif ( this[i].nodeType === 1 ) {\n
\t\t\t\t\t\tjQuery.cleanData( this[i].getElementsByTagName("*") );\n
\t\t\t\t\t\tthis[i].innerHTML = value;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t// If using innerHTML throws an exception, use the fallback method\n
\t\t\t} catch(e) {\n
\t\t\t\tthis.empty().append( value );\n
\t\t\t}\n
\n
\t\t} else if ( jQuery.isFunction( value ) ) {\n
\t\t\tthis.each(function(i){\n
\t\t\t\tvar self = jQuery(this), old = self.html();\n
\t\t\t\tself.empty().append(function(){\n
\t\t\t\t\treturn value.call( this, i, old );\n
\t\t\t\t});\n
\t\t\t});\n
\n
\t\t} else {\n
\t\t\tthis.empty().append( value );\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\treplaceWith: function( value ) {\n
\t\tif ( this[0] && this[0].parentNode ) {\n
\t\t\t// Make sure that the elements are removed from the DOM before they are inserted\n
\t\t\t// this can help fix replacing a parent with child elements\n
\t\t\tif ( jQuery.isFunction( value ) ) {\n
\t\t\t\treturn this.each(function(i) {\n
\t\t\t\t\tvar self = jQuery(this), old = self.html();\n
\t\t\t\t\tself.replaceWith( value.call( this, i, old ) );\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif ( typeof value !== "string" ) {\n
\t\t\t\tvalue = jQuery(value).detach();\n
\t\t\t}\n
\n
\t\t\treturn this.each(function() {\n
\t\t\t\tvar next = this.nextSibling, parent = this.parentNode;\n
\n
\t\t\t\tjQuery(this).remove();\n
\n
\t\t\t\tif ( next ) {\n
\t\t\t\t\tjQuery(next).before( value );\n
\t\t\t\t} else {\n
\t\t\t\t\tjQuery(parent).append( value );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\treturn this.pushStack( jQuery(jQuery.isFunction(value) ? value() : value), "replaceWith", value );\n
\t\t}\n
\t},\n
\n
\tdetach: function( selector ) {\n
\t\treturn this.remove( selector, true );\n
\t},\n
\n
\tdomManip: function( args, table, callback ) {\n
\t\tvar results, first, value = args[0], scripts = [], fragment, parent;\n
\n
\t\t// We can\'t cloneNode fragments that contain checked, in WebKit\n
\t\tif ( !jQuery.support.checkClone && arguments.length === 3 && typeof value === "string" && rchecked.test( value ) ) {\n
\t\t\treturn this.each(function() {\n
\t\t\t\tjQuery(this).domManip( args, table, callback, true );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( jQuery.isFunction(value) ) {\n
\t\t\treturn this.each(function(i) {\n
\t\t\t\tvar self = jQuery(this);\n
\t\t\t\targs[0] = value.call(this, i, table ? self.html() : undefined);\n
\t\t\t\tself.domManip( args, table, callback );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this[0] ) {\n
\t\t\tparent = value && value.parentNode;\n
\n
\t\t\t// If we\'re in a fragment, just use that instead of building a new one\n
\t\t\tif ( jQuery.support.parentNode && parent && parent.nodeType === 11 && parent.childNodes.length === this.length ) {\n
\t\t\t\tresults = { fragment: parent };\n
\n
\t\t\t} else {\n
\t\t\t\tresults = buildFragment( args, this, scripts );\n
\t\t\t}\n
\t\t\t\n
\t\t\tfragment = results.fragment;\n
\t\t\t\n
\t\t\tif ( fragment.childNodes.length === 1 ) {\n
\t\t\t\tfirst = fragment = fragment.firstChild;\n
\t\t\t} else {\n
\t\t\t\tfirst = fragment.firstChild;\n
\t\t\t}\n
\n
\t\t\tif ( first ) {\n
\t\t\t\ttable = table && jQuery.nodeName( first, "tr" );\n
\n
\t\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\t\tcallback.call(\n
\t\t\t\t\t\ttable ?\n
\t\t\t\t\t\t\troot(this[i], first) :\n
\t\t\t\t\t\t\tthis[i],\n
\t\t\t\t\t\ti > 0 || results.cacheable || this.length > 1  ?\n
\t\t\t\t\t\t\tfragment.cloneNode(true) :\n
\t\t\t\t\t\t\tfragment\n
\t\t\t\t\t);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( scripts.length ) {\n
\t\t\t\tjQuery.each( scripts, evalScript );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn this;\n
\n
\t\tfunction root( elem, cur ) {\n
\t\t\treturn jQuery.nodeName(elem, "table") ?\n
\t\t\t\t(elem.getElementsByTagName("tbody")[0] ||\n
\t\t\t\telem.appendChild(elem.ownerDocument.createElement("tbody"))) :\n
\t\t\t\telem;\n
\t\t}\n
\t}\n
});\n
\n
function cloneCopyEvent(orig, ret) {\n
\tvar i = 0;\n
\n
\tret.each(function() {\n
\t\tif ( this.nodeName !== (orig[i] && orig[i].nodeName) ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\tvar oldData = jQuery.data( orig[i++] ), curData = jQuery.data( this, oldData ), events = oldData && oldData.events;\n
\n
\t\tif ( events ) {\n
\t\t\tdelete curData.handle;\n
\t\t\tcurData.events = {};\n
\n
\t\t\tfor ( var type in events ) {\n
\t\t\t\tfor ( var handler in events[ type ] ) {\n
\t\t\t\t\tjQuery.event.add( this, type, events[ type ][ handler ], events[ type ][ handler ].data );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t});\n
}\n
\n
function buildFragment( args, nodes, scripts ) {\n
\tvar fragment, cacheable, cacheresults,\n
\t\tdoc = (nodes && nodes[0] ? nodes[0].ownerDocument || nodes[0] : document);\n
\n
\t// Only cache "small" (1/2 KB) strings that are associated with the main document\n
\t// Cloning options loses the selected state, so don\'t cache them\n
\t// IE 6 doesn\'t like it when you put <object> or <embed> elements in a fragment\n
\t// Also, WebKit does not clone \'checked\' attributes on cloneNode, so don\'t cache\n
\tif ( args.length === 1 && typeof args[0] === "string" && args[0].length < 512 && doc === document &&\n
\t\t!rnocache.test( args[0] ) && (jQuery.support.checkClone || !rchecked.test( args[0] )) ) {\n
\n
\t\tcacheable = true;\n
\t\tcacheresults = jQuery.fragments[ args[0] ];\n
\t\tif ( cacheresults ) {\n
\t\t\tif ( cacheresults !== 1 ) {\n
\t\t\t\tfragment = cacheresults;\n
\t\t\t}\n
\t\t}\n
\t}\n
\n
\tif ( !fragment ) {\n
\t\tfragment = doc.createDocumentFragment();\n
\t\tjQuery.clean( args, doc, fragment, scripts );\n
\t}\n
\n
\tif ( cacheable ) {\n
\t\tjQuery.fragments[ args[0] ] = cacheresults ? fragment : 1;\n
\t}\n
\n
\treturn { fragment: fragment, cacheable: cacheable };\n
}\n
\n
jQuery.fragments = {};\n
\n
jQuery.each({\n
\tappendTo: "append",\n
\tprependTo: "prepend",\n
\tinsertBefore: "before",\n
\tinsertAfter: "after",\n
\treplaceAll: "replaceWith"\n
}, function( name, original ) {\n
\tjQuery.fn[ name ] = function( selector ) {\n
\t\tvar ret = [], insert = jQuery( selector ),\n
\t\t\tparent = this.length === 1 && this[0].parentNode;\n
\t\t\n
\t\tif ( parent && parent.nodeType === 11 && parent.childNodes.length === 1 && insert.length === 1 ) {\n
\t\t\tinsert[ original ]( this[0] );\n
\t\t\treturn this;\n
\t\t\t\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = insert.length; i < l; i++ ) {\n
\t\t\t\tvar elems = (i > 0 ? this.clone(true) : this).get();\n
\t\t\t\tjQuery.fn[ original ].apply( jQuery(insert[i]), elems );\n
\t\t\t\tret = ret.concat( elems );\n
\t\t\t}\n
\t\t\n
\t\t\treturn this.pushStack( ret, name, insert.selector );\n
\t\t}\n
\t};\n
});\n
\n
jQuery.extend({\n
\tclean: function( elems, context, fragment, scripts ) {\n
\t\tcontext = context || document;\n
\n
\t\t// !context.createElement fails in IE with an error but returns typeof \'object\'\n
\t\tif ( typeof context.createElement === "undefined" ) {\n
\t\t\tcontext = context.ownerDocument || context[0] && context[0].ownerDocument || document;\n
\t\t}\n
\n
\t\tvar ret = [];\n
\n
\t\tfor ( var i = 0, elem; (elem = elems[i]) != null; i++ ) {\n
\t\t\tif ( typeof elem === "number" ) {\n
\t\t\t\telem += "";\n
\t\t\t}\n
\n
\t\t\tif ( !elem ) {\n
\t\t\t\tcontinue;\n
\t\t\t}\n
\n
\t\t\t// Convert html string into DOM nodes\n
\t\t\tif ( typeof elem === "string" && !rhtml.test( elem ) ) {\n
\t\t\t\telem = context.createTextNode( elem );\n
\n
\t\t\t} else if ( typeof elem === "string" ) {\n
\t\t\t\t// Fix "XHTML"-style tags in all browsers\n
\t\t\t\telem = elem.replace(rxhtmlTag, fcloseTag);\n
\n
\t\t\t\t// Trim whitespace, otherwise indexOf won\'t work as expected\n
\t\t\t\tvar tag = (rtagName.exec( elem ) || ["", ""])[1].toLowerCase(),\n
\t\t\t\t\twrap = wrapMap[ tag ] || wrapMap._default,\n
\t\t\t\t\tdepth = wrap[0],\n
\t\t\t\t\tdiv = context.createElement("div");\n
\n
\t\t\t\t// Go to html and back, then peel off extra wrappers\n
\t\t\t\tdiv.innerHTML = wrap[1] + elem + wrap[2];\n
\n
\t\t\t\t// Move to the right depth\n
\t\t\t\twhile ( depth-- ) {\n
\t\t\t\t\tdiv = div.lastChild;\n
\t\t\t\t}\n
\n
\t\t\t\t// Remove IE\'s autoinserted <tbody> from table fragments\n
\t\t\t\tif ( !jQuery.support.tbody ) {\n
\n
\t\t\t\t\t// String was a <table>, *may* have spurious <tbody>\n
\t\t\t\t\tvar hasBody = rtbody.test(elem),\n
\t\t\t\t\t\ttbody = tag === "table" && !hasBody ?\n
\t\t\t\t\t\t\tdiv.firstChild && div.firstChild.childNodes :\n
\n
\t\t\t\t\t\t\t// String was a bare <thead> or <tfoot>\n
\t\t\t\t\t\t\twrap[1] === "<table>" && !hasBody ?\n
\t\t\t\t\t\t\t\tdiv.childNodes :\n
\t\t\t\t\t\t\t\t[];\n
\n
\t\t\t\t\tfor ( var j = tbody.length - 1; j >= 0 ; --j ) {\n
\t\t\t\t\t\tif ( jQuery.nodeName( tbody[ j ], "tbody" ) && !tbody[ j ].childNodes.length ) {\n
\t\t\t\t\t\t\ttbody[ j ].parentNode.removeChild( tbody[ j ] );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\n
\t\t\t\t}\n
\n
\t\t\t\t// IE completely kills leading whitespace when innerHTML is used\n
\t\t\t\tif ( !jQuery.support.leadingWhitespace && rleadingWhitespace.test( elem ) ) {\n
\t\t\t\t\tdiv.insertBefore( context.createTextNode( rleadingWhitespace.exec(elem)[0] ), div.firstChild );\n
\t\t\t\t}\n
\n
\t\t\t\telem = div.childNodes;\n
\t\t\t}\n
\n
\t\t\tif ( elem.nodeType ) {\n
\t\t\t\tret.push( elem );\n
\t\t\t} else {\n
\t\t\t\tret = jQuery.merge( ret, elem );\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( fragment ) {\n
\t\t\tfor ( var i = 0; ret[i]; i++ ) {\n
\t\t\t\tif ( scripts && jQuery.nodeName( ret[i], "script" ) && (!ret[i].type || ret[i].type.toLowerCase() === "text/javascript") ) {\n
\t\t\t\t\tscripts.push( ret[i].parentNode ? ret[i].parentNode.removeChild( ret[i] ) : ret[i] );\n
\t\t\t\t\n
\t\t\t\t} else {\n
\t\t\t\t\tif ( ret[i].nodeType === 1 ) {\n
\t\t\t\t\t\tret.splice.apply( ret, [i + 1, 0].concat(jQuery.makeArray(ret[i].getElementsByTagName("script"))) );\n
\t\t\t\t\t}\n
\t\t\t\t\tfragment.appendChild( ret[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\t\n
\tcleanData: function( elems ) {\n
\t\tvar data, id, cache = jQuery.cache,\n
\t\t\tspecial = jQuery.event.special,\n
\t\t\tdeleteExpando = jQuery.support.deleteExpando;\n
\t\t\n
\t\tfor ( var i = 0, elem; (elem = elems[i]) != null; i++ ) {\n
\t\t\tid = elem[ jQuery.expando ];\n
\t\t\t\n
\t\t\tif ( id ) {\n
\t\t\t\tdata = cache[ id ];\n
\t\t\t\t\n
\t\t\t\tif ( data.events ) {\n
\t\t\t\t\tfor ( var type in data.events ) {\n
\t\t\t\t\t\tif ( special[ type ] ) {\n
\t\t\t\t\t\t\tjQuery.event.remove( elem, type );\n
\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tremoveEvent( elem, type, data.handle );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif ( deleteExpando ) {\n
\t\t\t\t\tdelete elem[ jQuery.expando ];\n
\n
\t\t\t\t} else if ( elem.removeAttribute ) {\n
\t\t\t\t\telem.removeAttribute( jQuery.expando );\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tdelete cache[ id ];\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
// exclude the following css properties to add px\n
var rexclude = /z-?index|font-?weight|opacity|zoom|line-?height/i,\n
\tralpha = /alpha\\([^)]*\\)/,\n
\tropacity = /opacity=([^)]*)/,\n
\trfloat = /float/i,\n
\trdashAlpha = /-([a-z])/ig,\n
\trupper = /([A-Z])/g,\n
\trnumpx = /^-?\\d+(?:px)?$/i,\n
\trnum = /^-?\\d/,\n
\n
\tcssShow = { position: "absolute", visibility: "hidden", display:"block" },\n
\tcssWidth = [ "Left", "Right" ],\n
\tcssHeight = [ "Top", "Bottom" ],\n
\n
\t// cache check for defaultView.getComputedStyle\n
\tgetComputedStyle = document.defaultView && document.defaultView.getComputedStyle,\n
\t// normalize float css property\n
\tstyleFloat = jQuery.support.cssFloat ? "cssFloat" : "styleFloat",\n
\tfcamelCase = function( all, letter ) {\n
\t\treturn letter.toUpperCase();\n
\t};\n
\n
jQuery.fn.css = function( name, value ) {\n
\treturn access( this, name, value, true, function( elem, name, value ) {\n
\t\tif ( value === undefined ) {\n
\t\t\treturn jQuery.curCSS( elem, name );\n
\t\t}\n
\t\t\n
\t\tif ( typeof value === "number" && !rexclude.test(name) ) {\n
\t\t\tvalue += "px";\n
\t\t}\n
\n
\t\tjQuery.style( elem, name, value );\n
\t});\n
};\n
\n
jQuery.extend({\n
\tstyle: function( elem, name, value ) {\n
\t\t// don\'t set styles on text and comment nodes\n
\t\tif ( !elem || elem.nodeType === 3 || elem.nodeType === 8 ) {\n
\t\t\treturn undefined;\n
\t\t}\n
\n
\t\t// ignore negative width and height values #1599\n
\t\tif ( (name === "width" || name === "height") && parseFloat(value) < 0 ) {\n
\t\t\tvalue = undefined;\n
\t\t}\n
\n
\t\tvar style = elem.style || elem, set = value !== undefined;\n
\n
\t\t// IE uses filters for opacity\n
\t\tif ( !jQuery.support.opacity && name === "opacity" ) {\n
\t\t\tif ( set ) {\n
\t\t\t\t// IE has trouble with opacity if it does not have layout\n
\t\t\t\t// Force it by setting the zoom level\n
\t\t\t\tstyle.zoom = 1;\n
\n
\t\t\t\t// Set the alpha filter to set the opacity\n
\t\t\t\tvar opacity = parseInt( value, 10 ) + "" === "NaN" ? "" : "alpha(opacity=" + value * 100 + ")";\n
\t\t\t\tvar filter = style.filter || jQuery.curCSS( elem, "filter" ) || "";\n
\t\t\t\tstyle.filter = ralpha.test(filter) ? filter.replace(ralpha, opacity) : opacity;\n
\t\t\t}\n
\n
\t\t\treturn style.filter && style.filter.indexOf("opacity=") >= 0 ?\n
\t\t\t\t(parseFloat( ropacity.exec(style.filter)[1] ) / 100) + "":\n
\t\t\t\t"";\n
\t\t}\n
\n
\t\t// Make sure we\'re using the right name for getting the float value\n
\t\tif ( rfloat.test( name ) ) {\n
\t\t\tname = styleFloat;\n
\t\t}\n
\n
\t\tname = name.replace(rdashAlpha, fcamelCase);\n
\n
\t\tif ( set ) {\n
\t\t\tstyle[ name ] = value;\n
\t\t}\n
\n
\t\treturn style[ name ];\n
\t},\n
\n
\tcss: function( elem, name, force, extra ) {\n
\t\tif ( name === "width" || name === "height" ) {\n
\t\t\tvar val, props = cssShow, which = name === "width" ? cssWidth : cssHeight;\n
\n
\t\t\tfunction getWH() {\n
\t\t\t\tval = name === "width" ? elem.offsetWidth : elem.offsetHeight;\n
\n
\t\t\t\tif ( extra === "border" ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\n
\t\t\t\tjQuery.each( which, function() {\n
\t\t\t\t\tif ( !extra ) {\n
\t\t\t\t\t\tval -= parseFloat(jQuery.curCSS( elem, "padding" + this, true)) || 0;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( extra === "margin" ) {\n
\t\t\t\t\t\tval += parseFloat(jQuery.curCSS( elem, "margin" + this, true)) || 0;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tval -= parseFloat(jQuery.curCSS( elem, "border" + this + "Width", true)) || 0;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tif ( elem.offsetWidth !== 0 ) {\n
\t\t\t\tgetWH();\n
\t\t\t} else {\n
\t\t\t\tjQuery.swap( elem, props, getWH );\n
\t\t\t}\n
\n
\t\t\treturn Math.max(0, Math.round(val));\n
\t\t}\n
\n
\t\treturn jQuery.curCSS( elem, name, force );\n
\t},\n
\n
\tcurCSS: function( elem, name, force ) {\n
\t\tvar ret, style = elem.style, filter;\n
\n
\t\t// IE uses filters for opacity\n
\t\tif ( !jQuery.support.opacity && name === "opacity" && elem.currentStyle ) {\n
\t\t\tret = ropacity.test(elem.currentStyle.filter || "") ?\n
\t\t\t\t(parseFloat(RegExp.$1) / 100) + "" :\n
\t\t\t\t"";\n
\n
\t\t\treturn ret === "" ?\n
\t\t\t\t"1" :\n
\t\t\t\tret;\n
\t\t}\n
\n
\t\t// Make sure we\'re using the right name for getting the float value\n
\t\tif ( rfloat.test( name ) ) {\n
\t\t\tname = styleFloat;\n
\t\t}\n
\n
\t\tif ( !force && style && style[ name ] ) {\n
\t\t\tret = style[ name ];\n
\n
\t\t} else if ( getComputedStyle ) {\n
\n
\t\t\t// Only "float" is needed here\n
\t\t\tif ( rfloat.test( name ) ) {\n
\t\t\t\tname = "float";\n
\t\t\t}\n
\n
\t\t\tname = name.replace( rupper, "-$1" ).toLowerCase();\n
\n
\t\t\tvar defaultView = elem.ownerDocument.defaultView;\n
\n
\t\t\tif ( !defaultView ) {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\n
\t\t\tvar computedStyle = defaultView.getComputedStyle( elem, null );\n
\n
\t\t\tif ( computedStyle ) {\n
\t\t\t\tret = computedStyle.getPropertyValue( name );\n
\t\t\t}\n
\n
\t\t\t// We should always get a number back from opacity\n
\t\t\tif ( name === "opacity" && ret === "" ) {\n
\t\t\t\tret = "1";\n
\t\t\t}\n
\n
\t\t} else if ( elem.currentStyle ) {\n
\t\t\tvar camelCase = name.replace(rdashAlpha, fcamelCase);\n
\n
\t\t\tret = elem.currentStyle[ name ] || elem.currentStyle[ camelCase ];\n
\n
\t\t\t// From the awesome hack by Dean Edwards\n
\t\t\t// http://erik.eae.net/archives/2007/07/27/18.54.15/#comment-102291\n
\n
\t\t\t// If we\'re not dealing with a regular pixel number\n
\t\t\t// but a number that has a weird ending, we need to convert it to pixels\n
\t\t\tif ( !rnumpx.test( ret ) && rnum.test( ret ) ) {\n
\t\t\t\t// Remember the original values\n
\t\t\t\tvar left = style.left, rsLeft = elem.runtimeStyle.left;\n
\n
\t\t\t\t// Put in the new values to get a computed value out\n
\t\t\t\telem.runtimeStyle.left = elem.currentStyle.left;\n
\t\t\t\tstyle.left = camelCase === "fontSize" ? "1em" : (ret || 0);\n
\t\t\t\tret = style.pixelLeft + "px";\n
\n
\t\t\t\t// Revert the changed values\n
\t\t\t\tstyle.left = left;\n
\t\t\t\telem.runtimeStyle.left = rsLeft;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn ret;\n
\t},\n
\n
\t// A method for quickly swapping in/out CSS properties to get correct calculations\n
\tswap: function( elem, options, callback ) {\n
\t\tvar old = {};\n
\n
\t\t// Remember the old values, and insert the new ones\n
\t\tfor ( var name in options ) {\n
\t\t\told[ name ] = elem.style[ name ];\n
\t\t\telem.style[ name ] = options[ name ];\n
\t\t}\n
\n
\t\tcallback.call( elem );\n
\n
\t\t// Revert the old values\n
\t\tfor ( var name in options ) {\n
\t\t\telem.style[ name ] = old[ name ];\n
\t\t}\n
\t}\n
});\n
\n
if ( jQuery.expr && jQuery.expr.filters ) {\n
\tjQuery.expr.filters.hidden = function( elem ) {\n
\t\tvar width = elem.offsetWidth, height = elem.offsetHeight,\n
\t\t\tskip = elem.nodeName.toLowerCase() === "tr";\n
\n
\t\treturn width === 0 && height === 0 && !skip ?\n
\t\t\ttrue :\n
\t\t\twidth > 0 && height > 0 && !skip ?\n
\t\t\t\tfalse :\n
\t\t\t\tjQuery.curCSS(elem, "display") === "none";\n
\t};\n
\n
\tjQuery.expr.filters.visible = function( elem ) {\n
\t\treturn !jQuery.expr.filters.hidden( elem );\n
\t};\n
}\n
var jsc = now(),\n
\trscript = /<script(.|\\s)*?\\/script>/gi,\n
\trselectTextarea = /select|textarea/i,\n
\trinput = /color|date|datetime|email|hidden|month|number|password|range|search|tel|text|time|url|week/i,\n
\tjsre = /=\\?(&|$)/,\n
\trquery = /\\?/,\n
\trts = /(\\?|&)_=.*?(&|$)/,\n
\trurl = /^(\\w+:)?\\/\\/([^\\/?#]+)/,\n
\tr20 = /%20/g,\n
\n
\t// Keep a copy of the old load method\n
\t_load = jQuery.fn.load;\n
\n
jQuery.fn.extend({\n
\tload: function( url, params, callback ) {\n
\t\tif ( typeof url !== "string" ) {\n
\t\t\treturn _load.call( this, url );\n
\n
\t\t// Don\'t do a request if no elements are being requested\n
\t\t} else if ( !this.length ) {\n
\t\t\treturn this;\n
\t\t}\n
\n
\t\tvar off = url.indexOf(" ");\n
\t\tif ( off >= 0 ) {\n
\t\t\tvar selector = url.slice(off, url.length);\n
\t\t\turl = url.slice(0, off);\n
\t\t}\n
\n
\t\t// Default to a GET request\n
\t\tvar type = "GET";\n
\n
\t\t// If the second parameter was provided\n
\t\tif ( params ) {\n
\t\t\t// If it\'s a function\n
\t\t\tif ( jQuery.isFunction( params ) ) {\n
\t\t\t\t// We assume that it\'s the callback\n
\t\t\t\tcallback = params;\n
\t\t\t\tparams = null;\n
\n
\t\t\t// Otherwise, build a param string\n
\t\t\t} else if ( typeof params === "object" ) {\n
\t\t\t\tparams = jQuery.param( params, jQuery.ajaxSettings.traditional );\n
\t\t\t\ttype = "POST";\n
\t\t\t}\n
\t\t}\n
\n
\t\tvar self = this;\n
\n
\t\t// Request the remote document\n
\t\tjQuery.ajax({\n
\t\t\turl: url,\n
\t\t\ttype: type,\n
\t\t\tdataType: "html",\n
\t\t\tdata: params,\n
\t\t\tcomplete: function( res, status ) {\n
\t\t\t\t// If successful, inject the HTML into all the matched elements\n
\t\t\t\tif ( status === "success" || status === "notmodified" ) {\n
\t\t\t\t\t// See if a selector was specified\n
\t\t\t\t\tself.html( selector ?\n
\t\t\t\t\t\t// Create a dummy div to hold the results\n
\t\t\t\t\t\tjQuery("<div />")\n
\t\t\t\t\t\t\t// inject the contents of the document in, removing the scripts\n
\t\t\t\t\t\t\t// to avoid any \'Permission Denied\' errors in IE\n
\t\t\t\t\t\t\t.append(res.responseText.replace(rscript, ""))\n
\n
\t\t\t\t\t\t\t// Locate the specified elements\n
\t\t\t\t\t\t\t.find(selector) :\n
\n
\t\t\t\t\t\t// If not, just inject the full result\n
\t\t\t\t\t\tres.responseText );\n
\t\t\t\t}\n
\n
\t\t\t\tif ( callback ) {\n
\t\t\t\t\tself.each( callback, [res.responseText, status, res] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\treturn this;\n
\t},\n
\n
\tserialize: function() {\n
\t\treturn jQuery.param(this.serializeArray());\n
\t},\n
\tserializeArray: function() {\n
\t\treturn this.map(function() {\n
\t\t\treturn this.elements ? jQuery.makeArray(this.elements) : this;\n
\t\t})\n
\t\t.filter(function() {\n
\t\t\treturn this.name && !this.disabled &&\n
\t\t\t\t(this.checked || rselectTextarea.test(this.nodeName) ||\n
\t\t\t\t\trinput.test(this.type));\n
\t\t})\n
\t\t.map(function( i, elem ) {\n
\t\t\tvar val = jQuery(this).val();\n
\n
\t\t\treturn val == null ?\n
\t\t\t\tnull :\n
\t\t\t\tjQuery.isArray(val) ?\n
\t\t\t\t\tjQuery.map( val, function( val, i ) {\n
\t\t\t\t\t\treturn { name: elem.name, value: val };\n
\t\t\t\t\t}) :\n
\t\t\t\t\t{ name: elem.name, value: val };\n
\t\t}).get();\n
\t}\n
});\n
\n
// Attach a bunch of functions for handling common AJAX events\n
jQuery.each( "ajaxStart ajaxStop ajaxComplete ajaxError ajaxSuccess ajaxSend".split(" "), function( i, o ) {\n
\tjQuery.fn[o] = function( f ) {\n
\t\treturn this.bind(o, f);\n
\t};\n
});\n
\n
jQuery.extend({\n
\n
\tget: function( url, data, callback, type ) {\n
\t\t// shift arguments if data argument was omited\n
\t\tif ( jQuery.isFunction( data ) ) {\n
\t\t\ttype = type || callback;\n
\t\t\tcallback = data;\n
\t\t\tdata = null;\n
\t\t}\n
\n
\t\treturn jQuery.ajax({\n
\t\t\ttype: "GET",\n
\t\t\turl: url,\n
\t\t\tdata: data,\n
\t\t\tsuccess: callback,\n
\t\t\tdataType: type\n
\t\t});\n
\t},\n
\n
\tgetScript: function( url, callback ) {\n
\t\treturn jQuery.get(url, null, callback, "script");\n
\t},\n
\n
\tgetJSON: function( url, data, callback ) {\n
\t\treturn jQuery.get(url, data, callback, "json");\n
\t},\n
\n
\tpost: function( url, data, callback, type ) {\n
\t\t// shift arguments if data argument was omited\n
\t\tif ( jQuery.isFunction( data ) ) {\n
\t\t\ttype = type || callback;\n
\t\t\tcallback = data;\n
\t\t\tdata = {};\n
\t\t}\n
\n
\t\treturn jQuery.ajax({\n
\t\t\ttype: "POST",\n
\t\t\turl: url,\n
\t\t\tdata: data,\n
\t\t\tsuccess: callback,\n
\t\t\tdataType: type\n
\t\t});\n
\t},\n
\n
\tajaxSetup: function( settings ) {\n
\t\tjQuery.extend( jQuery.ajaxSettings, settings );\n
\t},\n
\n
\tajaxSettings: {\n
\t\turl: location.href,\n
\t\tglobal: true,\n
\t\ttype: "GET",\n
\t\tcontentType: "application/x-www-form-urlencoded",\n
\t\tprocessData: true,\n
\t\tasync: true,\n
\t\t/*\n
\t\ttimeout: 0,\n
\t\tdata: null,\n
\t\tusername: null,\n
\t\tpassword: null,\n
\t\ttraditional: false,\n
\t\t*/\n
\t\t// Create the request object; Microsoft failed to properly\n
\t\t// implement the XMLHttpRequest in IE7 (can\'t request local files),\n
\t\t// so we use the ActiveXObject when it is available\n
\t\t// This function can be overriden by calling jQuery.ajaxSetup\n
\t\txhr: window.XMLHttpRequest && (window.location.protocol !== "file:" || !window.ActiveXObject) ?\n
\t\t\tfunction() {\n
\t\t\t\treturn new window.XMLHttpRequest();\n
\t\t\t} :\n
\t\t\tfunction() {\n
\t\t\t\ttry {\n
\t\t\t\t\treturn new window.ActiveXObject("Microsoft.XMLHTTP");\n
\t\t\t\t} catch(e) {}\n
\t\t\t},\n
\t\taccepts: {\n
\t\t\txml: "application/xml, text/xml",\n
\t\t\thtml: "text/html",\n
\t\t\tscript: "text/javascript, application/javascript",\n
\t\t\tjson: "application/json, text/javascript",\n
\t\t\ttext: "text/plain",\n
\t\t\t_default: "*/*"\n
\t\t}\n
\t},\n
\n
\t// Last-Modified header cache for next request\n
\tlastModified: {},\n
\tetag: {},\n
\n
\tajax: function( origSettings ) {\n
\t\tvar s = jQuery.extend(true, {}, jQuery.ajaxSettings, origSettings);\n
\t\t\n
\t\tvar jsonp, status, data,\n
\t\t\tcallbackContext = origSettings && origSettings.context || s,\n
\t\t\ttype = s.type.toUpperCase();\n
\n
\t\t// convert data if not already a string\n
\t\tif ( s.data && s.processData && typeof s.data !== "string" ) {\n
\t\t\ts.data = jQuery.param( s.data, s.traditional );\n
\t\t}\n
\n
\t\t// Handle JSONP Parameter Callbacks\n
\t\tif ( s.dataType === "jsonp" ) {\n
\t\t\tif ( type === "GET" ) {\n
\t\t\t\tif ( !jsre.test( s.url ) ) {\n
\t\t\t\t\ts.url += (rquery.test( s.url ) ? "&" : "?") + (s.jsonp || "callback") + "=?";\n
\t\t\t\t}\n
\t\t\t} else if ( !s.data || !jsre.test(s.data) ) {\n
\t\t\t\ts.data = (s.data ? s.data + "&" : "") + (s.jsonp || "callback") + "=?";\n
\t\t\t}\n
\t\t\ts.dataType = "json";\n
\t\t}\n
\n
\t\t// Build temporary JSONP function\n
\t\tif ( s.dataType === "json" && (s.data && jsre.test(s.data) || jsre.test(s.url)) ) {\n
\t\t\tjsonp = s.jsonpCallback || ("jsonp" + jsc++);\n
\n
\t\t\t// Replace the =? sequence both in the query string and the data\n
\t\t\tif ( s.data ) {\n
\t\t\t\ts.data = (s.data + "").replace(jsre, "=" + jsonp + "$1");\n
\t\t\t}\n
\n
\t\t\ts.url = s.url.replace(jsre, "=" + jsonp + "$1");\n
\n
\t\t\t// We need to make sure\n
\t\t\t// that a JSONP style response is executed properly\n
\t\t\ts.dataType = "script";\n
\n
\t\t\t// Handle JSONP-style loading\n
\t\t\twindow[ jsonp ] = window[ jsonp ] || function( tmp ) {\n
\t\t\t\tdata = tmp;\n
\t\t\t\tsuccess();\n
\t\t\t\tcomplete();\n
\t\t\t\t// Garbage collect\n
\t\t\t\twindow[ jsonp ] = undefined;\n
\n
\t\t\t\ttry {\n
\t\t\t\t\tdelete window[ jsonp ];\n
\t\t\t\t} catch(e) {}\n
\n
\t\t\t\tif ( head ) {\n
\t\t\t\t\thead.removeChild( script );\n
\t\t\t\t}\n
\t\t\t};\n
\t\t}\n
\n
\t\tif ( s.dataType === "script" && s.cache === null ) {\n
\t\t\ts.cache = false;\n
\t\t}\n
\n
\t\tif ( s.cache === false && type === "GET" ) {\n
\t\t\tvar ts = now();\n
\n
\t\t\t// try replacing _= if it is there\n
\t\t\tvar ret = s.url.replace(rts, "$1_=" + ts + "$2");\n
\n
\t\t\t// if nothing was replaced, add timestamp to the end\n
\t\t\ts.url = ret + ((ret === s.url) ? (rquery.test(s.url) ? "&" : "?") + "_=" + ts : "");\n
\t\t}\n
\n
\t\t// If data is available, append data to url for get requests\n
\t\tif ( s.data && type === "GET" ) {\n
\t\t\ts.url += (rquery.test(s.url) ? "&" : "?") + s.data;\n
\t\t}\n
\n
\t\t// Watch for a new set of requests\n
\t\tif ( s.global && ! jQuery.active++ ) {\n
\t\t\tjQuery.event.trigger( "ajaxStart" );\n
\t\t}\n
\n
\t\t// Matches an absolute URL, and saves the domain\n
\t\tvar parts = rurl.exec( s.url ),\n
\t\t\tremote = parts && (parts[1] && parts[1] !== location.protocol || parts[2] !== location.host);\n
\n
\t\t// If we\'re requesting a remote document\n
\t\t// and trying to load JSON or Script with a GET\n
\t\tif ( s.dataType === "script" && type === "GET" && remote ) {\n
\t\t\tvar head = document.getElementsByTagName("head")[0] || document.documentElement;\n
\t\t\tvar script = document.createElement("script");\n
\t\t\tscript.src = s.url;\n
\t\t\tif ( s.scriptCharset ) {\n
\t\t\t\tscript.charset = s.scriptCharset;\n
\t\t\t}\n
\n
\t\t\t// Handle Script loading\n
\t\t\tif ( !jsonp ) {\n
\t\t\t\tvar done = false;\n
\n
\t\t\t\t// Attach handlers for all browsers\n
\t\t\t\tscript.onload = script.onreadystatechange = function() {\n
\t\t\t\t\tif ( !done && (!this.readyState ||\n
\t\t\t\t\t\t\tthis.readyState === "loaded" || this.readyState === "complete") ) {\n
\t\t\t\t\t\tdone = true;\n
\t\t\t\t\t\tsuccess();\n
\t\t\t\t\t\tcomplete();\n
\n
\t\t\t\t\t\t// Handle memory leak in IE\n
\t\t\t\t\t\tscript.onload = script.onreadystatechange = null;\n
\t\t\t\t\t\tif ( head && script.parentNode ) {\n
\t\t\t\t\t\t\thead.removeChild( script );\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t}\n
\n
\t\t\t// Use insertBefore instead of appendChild  to circumvent an IE6 bug.\n
\t\t\t// This arises when a base node is used (#2709 and #4378).\n
\t\t\thead.insertBefore( script, head.firstChild );\n
\n
\t\t\t// We handle everything using the script element injection\n
\t\t\treturn undefined;\n
\t\t}\n
\n
\t\tvar requestDone = false;\n
\n
\t\t// Create the request object\n
\t\tvar xhr = s.xhr();\n
\n
\t\tif ( !xhr ) {\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// Open the socket\n
\t\t// Passing null username, generates a login popup on Opera (#2865)\n
\t\tif ( s.username ) {\n
\t\t\txhr.open(type, s.url, s.async, s.username, s.password);\n
\t\t} else {\n
\t\t\txhr.open(type, s.url, s.async);\n
\t\t}\n
\n
\t\t// Need an extra try/catch for cross domain requests in Firefox 3\n
\t\ttry {\n
\t\t\t// Set the correct header, if data is being sent\n
\t\t\tif ( s.data || origSettings && origSettings.contentType ) {\n
\t\t\t\txhr.setRequestHeader("Content-Type", s.contentType);\n
\t\t\t}\n
\n
\t\t\t// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.\n
\t\t\tif ( s.ifModified ) {\n
\t\t\t\tif ( jQuery.lastModified[s.url] ) {\n
\t\t\t\t\txhr.setRequestHeader("If-Modified-Since", jQuery.lastModified[s.url]);\n
\t\t\t\t}\n
\n
\t\t\t\tif ( jQuery.etag[s.url] ) {\n
\t\t\t\t\txhr.setRequestHeader("If-None-Match", jQuery.etag[s.url]);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set header so the called script knows that it\'s an XMLHttpRequest\n
\t\t\t// Only send the header if it\'s not a remote XHR\n
\t\t\tif ( !remote ) {\n
\t\t\t\txhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");\n
\t\t\t}\n
\n
\t\t\t// Set the Accepts header for the server, depending on the dataType\n
\t\t\txhr.setRequestHeader("Accept", s.dataType && s.accepts[ s.dataType ] ?\n
\t\t\t\ts.accepts[ s.dataType ] + ", */*" :\n
\t\t\t\ts.accepts._default );\n
\t\t} catch(e) {}\n
\n
\t\t// Allow custom headers/mimetypes and early abort\n
\t\tif ( s.beforeSend && s.beforeSend.call(callbackContext, xhr, s) === false ) {\n
\t\t\t// Handle the global AJAX counter\n
\t\t\tif ( s.global && ! --jQuery.active ) {\n
\t\t\t\tjQuery.event.trigger( "ajaxStop" );\n
\t\t\t}\n
\n
\t\t\t// close opended socket\n
\t\t\txhr.abort();\n
\t\t\treturn false;\n
\t\t}\n
\n
\t\tif ( s.global ) {\n
\t\t\ttrigger("ajaxSend", [xhr, s]);\n
\t\t}\n
\n
\t\t// Wait for a response to come back\n
\t\tvar onreadystatechange = xhr.onreadystatechange = function( isTimeout ) {\n
\t\t\t// The request was aborted\n
\t\t\tif ( !xhr || xhr.readyState === 0 || isTimeout === "abort" ) {\n
\t\t\t\t// Opera doesn\'t call onreadystatechange before this point\n
\t\t\t\t// so we simulate the call\n
\t\t\t\tif ( !requestDone ) {\n
\t\t\t\t\tcomplete();\n
\t\t\t\t}\n
\n
\t\t\t\trequestDone = true;\n
\t\t\t\tif ( xhr ) {\n
\t\t\t\t\txhr.onreadystatechange = jQuery.noop;\n
\t\t\t\t}\n
\n
\t\t\t// The transfer is complete and the data is available, or the request timed out\n
\t\t\t} else if ( !requestDone && xhr && (xhr.readyState === 4 || isTimeout === "timeout") ) {\n
\t\t\t\trequestDone = true;\n
\t\t\t\txhr.onreadystatechange = jQuery.noop;\n
\n
\t\t\t\tstatus = isTimeout === "timeout" ?\n
\t\t\t\t\t"timeout" :\n
\t\t\t\t\t!jQuery.httpSuccess( xhr ) ?\n
\t\t\t\t\t\t"error" :\n
\t\t\t\t\t\ts.ifModified && jQuery.httpNotModified( xhr, s.url ) ?\n
\t\t\t\t\t\t\t"notmodified" :\n
\t\t\t\t\t\t\t"success";\n
\n
\t\t\t\tvar errMsg;\n
\n
\t\t\t\tif ( status === "success" ) {\n
\t\t\t\t\t// Watch for, and catch, XML document parse errors\n
\t\t\t\t\ttry {\n
\t\t\t\t\t\t// process the data (runs the xml through httpData regardless of callback)\n
\t\t\t\t\t\tdata = jQuery.httpData( xhr, s.dataType, s );\n
\t\t\t\t\t} catch(err) {\n
\t\t\t\t\t\tstatus = "parsererror";\n
\t\t\t\t\t\terrMsg = err;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Make sure that the request was successful or notmodified\n
\t\t\t\tif ( status === "success" || status === "notmodified" ) {\n
\t\t\t\t\t// JSONP handles its own success callback\n
\t\t\t\t\tif ( !jsonp ) {\n
\t\t\t\t\t\tsuccess();\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tjQuery.handleError(s, xhr, status, errMsg);\n
\t\t\t\t}\n
\n
\t\t\t\t// Fire the complete handlers\n
\t\t\t\tcomplete();\n
\n
\t\t\t\tif ( isTimeout === "timeout" ) {\n
\t\t\t\t\txhr.abort();\n
\t\t\t\t}\n
\n
\t\t\t\t// Stop memory leaks\n
\t\t\t\tif ( s.async ) {\n
\t\t\t\t\txhr = null;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
\n
\t\t// Override the abort handler, if we can (IE doesn\'t allow it, but that\'s OK)\n
\t\t// Opera doesn\'t fire onreadystatechange at all on abort\n
\t\ttry {\n
\t\t\tvar oldAbort = xhr.abort;\n
\t\t\txhr.abort = function() {\n
\t\t\t\tif ( xhr ) {\n
\t\t\t\t\toldAbort.call( xhr );\n
\t\t\t\t}\n
\n
\t\t\t\tonreadystatechange( "abort" );\n
\t\t\t};\n
\t\t} catch(e) { }\n
\n
\t\t// Timeout checker\n
\t\tif ( s.async && s.timeout > 0 ) {\n
\t\t\tsetTimeout(function() {\n
\t\t\t\t// Check to see if the request is still happening\n
\t\t\t\tif ( xhr && !requestDone ) {\n
\t\t\t\t\tonreadystatechange( "timeout" );\n
\t\t\t\t}\n
\t\t\t}, s.timeout);\n
\t\t}\n
\n
\t\t// Send the data\n
\t\ttry {\n
\t\t\txhr.send( type === "POST" || type === "PUT" || type === "DELETE" ? s.data : null );\n
\t\t} catch(e) {\n
\t\t\tjQuery.handleError(s, xhr, null, e);\n
\t\t\t// Fire the complete handlers\n
\t\t\tcomplete();\n
\t\t}\n
\n
\t\t// firefox 1.5 doesn\'t fire statechange for sync requests\n
\t\tif ( !s.async ) {\n
\t\t\tonreadystatechange();\n
\t\t}\n
\n
\t\tfunction success() {\n
\t\t\t// If a local callback was specified, fire it and pass it the data\n
\t\t\tif ( s.success ) {\n
\t\t\t\ts.success.call( callbackContext, data, status, xhr );\n
\t\t\t}\n
\n
\t\t\t// Fire the global callback\n
\t\t\tif ( s.global ) {\n
\t\t\t\ttrigger( "ajaxSuccess", [xhr, s] );\n
\t\t\t}\n
\t\t}\n
\n
\t\tfunction complete() {\n
\t\t\t// Process result\n
\t\t\tif ( s.complete ) {\n
\t\t\t\ts.complete.call( callbackContext, xhr, status);\n
\t\t\t}\n
\n
\t\t\t// The request was completed\n
\t\t\tif ( s.global ) {\n
\t\t\t\ttrigger( "ajaxComplete", [xhr, s] );\n
\t\t\t}\n
\n
\t\t\t// Handle the global AJAX counter\n
\t\t\tif ( s.global && ! --jQuery.active ) {\n
\t\t\t\tjQuery.event.trigger( "ajaxStop" );\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tfunction trigger(type, args) {\n
\t\t\t(s.context ? jQuery(s.context) : jQuery.event).trigger(type, args);\n
\t\t}\n
\n
\t\t// return XMLHttpRequest to allow aborting the request etc.\n
\t\treturn xhr;\n
\t},\n
\n
\thandleError: function( s, xhr, status, e ) {\n
\t\t// If a local callback was specified, fire it\n
\t\tif ( s.error ) {\n
\t\t\ts.error.call( s.context || s, xhr, status, e );\n
\t\t}\n
\n
\t\t// Fire the global callback\n
\t\tif ( s.global ) {\n
\t\t\t(s.context ? jQuery(s.context) : jQuery.event).trigger( "ajaxError", [xhr, s, e] );\n
\t\t}\n
\t},\n
\n
\t// Counter for holding the number of active queries\n
\tactive: 0,\n
\n
\t// Determines if an XMLHttpRequest was successful or not\n
\thttpSuccess: function( xhr ) {\n
\t\ttry {\n
\t\t\t// IE error sometimes returns 1223 when it should be 204 so treat it as success, see #1450\n
\t\t\treturn !xhr.status && location.protocol === "file:" ||\n
\t\t\t\t// Opera returns 0 when status is 304\n
\t\t\t\t( xhr.status >= 200 && xhr.status < 300 ) ||\n
\t\t\t\txhr.status === 304 || xhr.status === 1223 || xhr.status === 0;\n
\t\t} catch(e) {}\n
\n
\t\treturn false;\n
\t},\n
\n
\t// Determines if an XMLHttpRequest returns NotModified\n
\thttpNotModified: function( xhr, url ) {\n
\t\tvar lastModified = xhr.getResponseHeader("Last-Modified"),\n
\t\t\tetag = xhr.getResponseHeader("Etag");\n
\n
\t\tif ( lastModified ) {\n
\t\t\tjQuery.lastModified[url] = lastModified;\n
\t\t}\n
\n
\t\tif ( etag ) {\n
\t\t\tjQuery.etag[url] = etag;\n
\t\t}\n
\n
\t\t// Opera returns 0 when status is 304\n
\t\treturn xhr.status === 304 || xhr.status === 0;\n
\t},\n
\n
\thttpData: function( xhr, type, s ) {\n
\t\tvar ct = xhr.getResponseHeader("content-type") || "",\n
\t\t\txml = type === "xml" || !type && ct.indexOf("xml") >= 0,\n
\t\t\tdata = xml ? xhr.responseXML : xhr.responseText;\n
\n
\t\tif ( xml && data.documentElement.nodeName === "parsererror" ) {\n
\t\t\tjQuery.error( "parsererror" );\n
\t\t}\n
\n
\t\t// Allow a pre-filtering function to sanitize the response\n
\t\t// s is checked to keep backwards compatibility\n
\t\tif ( s && s.dataFilter ) {\n
\t\t\tdata = s.dataFilter( data, type );\n
\t\t}\n
\n
\t\t// The filter can actually parse the response\n
\t\tif ( typeof data === "string" ) {\n
\t\t\t// Get the JavaScript object, if JSON is used.\n
\t\t\tif ( type === "json" || !type && ct.indexOf("json") >= 0 ) {\n
\t\t\t\tdata = jQuery.parseJSON( data );\n
\n
\t\t\t// If the type is "script", eval it in global context\n
\t\t\t} else if ( type === "script" || !type && ct.indexOf("javascript") >= 0 ) {\n
\t\t\t\tjQuery.globalEval( data );\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn data;\n
\t},\n
\n
\t// Serialize an array of form elements or a set of\n
\t// key/values into a query string\n
\tparam: function( a, traditional ) {\n
\t\tvar s = [];\n
\t\t\n
\t\t// Set traditional to true for jQuery <= 1.3.2 behavior.\n
\t\tif ( traditional === undefined ) {\n
\t\t\ttraditional = jQuery.ajaxSettings.traditional;\n
\t\t}\n
\t\t\n
\t\t// If an array was passed in, assume that it is an array of form elements.\n
\t\tif ( jQuery.isArray(a) || a.jquery ) {\n
\t\t\t// Serialize the form elements\n
\t\t\tjQuery.each( a, function() {\n
\t\t\t\tadd( this.name, this.value );\n
\t\t\t});\n
\t\t\t\n
\t\t} else {\n
\t\t\t// If traditional, encode the "old" way (the way 1.3.2 or older\n
\t\t\t// did it), otherwise encode params recursively.\n
\t\t\tfor ( var prefix in a ) {\n
\t\t\t\tbuildParams( prefix, a[prefix] );\n
\t\t\t}\n
\t\t}\n
\n
\t\t// Return the resulting serialization\n
\t\treturn s.join("&").replace(r20, "+");\n
\n
\t\tfunction buildParams( prefix, obj ) {\n
\t\t\tif ( jQuery.isArray(obj) ) {\n
\t\t\t\t// Serialize array item.\n
\t\t\t\tjQuery.each( obj, function( i, v ) {\n
\t\t\t\t\tif ( traditional || /\\[\\]$/.test( prefix ) ) {\n
\t\t\t\t\t\t// Treat each array item as a scalar.\n
\t\t\t\t\t\tadd( prefix, v );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t// If array item is non-scalar (array or object), encode its\n
\t\t\t\t\t\t// numeric index to resolve deserialization ambiguity issues.\n
\t\t\t\t\t\t// Note that rack (as of 1.0.0) can\'t currently deserialize\n
\t\t\t\t\t\t// nested arrays properly, and attempting to do so may cause\n
\t\t\t\t\t\t// a server error. Possible fixes are to modify rack\'s\n
\t\t\t\t\t\t// deserialization algorithm or to provide an option or flag\n
\t\t\t\t\t\t// to force array serialization to be shallow.\n
\t\t\t\t\t\tbuildParams( prefix + "[" + ( typeof v === "object" || jQuery.isArray(v) ? i : "" ) + "]", v );\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t} else if ( !traditional && obj != null && typeof obj === "object" ) {\n
\t\t\t\t// Serialize object item.\n
\t\t\t\tjQuery.each( obj, function( k, v ) {\n
\t\t\t\t\tbuildParams( prefix + "[" + k + "]", v );\n
\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t} else {\n
\t\t\t\t// Serialize scalar item.\n
\t\t\t\tadd( prefix, obj );\n
\t\t\t}\n
\t\t}\n
\n
\t\tfunction add( key, value ) {\n
\t\t\t// If value is a function, invoke it and return its value\n
\t\t\tvalue = jQuery.isFunction(value) ? value() : value;\n
\t\t\ts[ s.length ] = encodeURIComponent(key) + "=" + encodeURIComponent(value);\n
\t\t}\n
\t}\n
});\n
var elemdisplay = {},\n
\trfxtypes = /toggle|show|hide/,\n
\trfxnum = /^([+-]=)?([\\d+-.]+)(.*)$/,\n
\ttimerId,\n
\tfxAttrs = [\n
\t\t// height animations\n
\t\t[ "height", "marginTop", "marginBottom", "paddingTop", "paddingBottom" ],\n
\t\t// width animations\n
\t\t[ "width", "marginLeft", "marginRight", "paddingLeft", "paddingRight" ],\n
\t\t// opacity animations\n
\t\t[ "opacity" ]\n
\t];\n
\n
jQuery.fn.extend({\n
\tshow: function( speed, callback ) {\n
\t\tif ( speed || speed === 0) {\n
\t\t\treturn this.animate( genFx("show", 3), speed, callback);\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tvar old = jQuery.data(this[i], "olddisplay");\n
\n
\t\t\t\tthis[i].style.display = old || "";\n
\n
\t\t\t\tif ( jQuery.css(this[i], "display") === "none" ) {\n
\t\t\t\t\tvar nodeName = this[i].nodeName, display;\n
\n
\t\t\t\t\tif ( elemdisplay[ nodeName ] ) {\n
\t\t\t\t\t\tdisplay = elemdisplay[ nodeName ];\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tvar elem = jQuery("<" + nodeName + " />").appendTo("body");\n
\n
\t\t\t\t\t\tdisplay = elem.css("display");\n
\n
\t\t\t\t\t\tif ( display === "none" ) {\n
\t\t\t\t\t\t\tdisplay = "block";\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\telem.remove();\n
\n
\t\t\t\t\t\telemdisplay[ nodeName ] = display;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tjQuery.data(this[i], "olddisplay", display);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set the display of the elements in a second loop\n
\t\t\t// to avoid the constant reflow\n
\t\t\tfor ( var j = 0, k = this.length; j < k; j++ ) {\n
\t\t\t\tthis[j].style.display = jQuery.data(this[j], "olddisplay") || "";\n
\t\t\t}\n
\n
\t\t\treturn this;\n
\t\t}\n
\t},\n
\n
\thide: function( speed, callback ) {\n
\t\tif ( speed || speed === 0 ) {\n
\t\t\treturn this.animate( genFx("hide", 3), speed, callback);\n
\n
\t\t} else {\n
\t\t\tfor ( var i = 0, l = this.length; i < l; i++ ) {\n
\t\t\t\tvar old = jQuery.data(this[i], "olddisplay");\n
\t\t\t\tif ( !old && old !== "none" ) {\n
\t\t\t\t\tjQuery.data(this[i], "olddisplay", jQuery.css(this[i], "display"));\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\t// Set the display of the elements in a second loop\n
\t\t\t// to avoid the constant reflow\n
\t\t\tfor ( var j = 0, k = this.length; j < k; j++ ) {\n
\t\t\t\tthis[j].style.display = "none";\n
\t\t\t}\n
\n
\t\t\treturn this;\n
\t\t}\n
\t},\n
\n
\t// Save the old toggle function\n
\t_toggle: jQuery.fn.toggle,\n
\n
\ttoggle: function( fn, fn2 ) {\n
\t\tvar bool = typeof fn === "boolean";\n
\n
\t\tif ( jQuery.isFunction(fn) && jQuery.isFunction(fn2) ) {\n
\t\t\tthis._toggle.apply( this, arguments );\n
\n
\t\t} else if ( fn == null || bool ) {\n
\t\t\tthis.each(function() {\n
\t\t\t\tvar state = bool ? fn : jQuery(this).is(":hidden");\n
\t\t\t\tjQuery(this)[ state ? "show" : "hide" ]();\n
\t\t\t});\n
\n
\t\t} else {\n
\t\t\tthis.animate(genFx("toggle", 3), fn, fn2);\n
\t\t}\n
\n
\t\treturn this;\n
\t},\n
\n
\tfadeTo: function( speed, to, callback ) {\n
\t\treturn this.filter(":hidden").css("opacity", 0).show().end()\n
\t\t\t\t\t.animate({opacity: to}, speed, callback);\n
\t},\n
\n
\tanimate: function( prop, speed, easing, callback ) {\n
\t\tvar optall = jQuery.speed(speed, easing, callback);\n
\n
\t\tif ( jQuery.isEmptyObject( prop ) ) {\n
\t\t\treturn this.each( optall.complete );\n
\t\t}\n
\n
\t\treturn this[ optall.queue === false ? "each" : "queue" ](function() {\n
\t\t\tvar opt = jQuery.extend({}, optall), p,\n
\t\t\t\thidden = this.nodeType === 1 && jQuery(this).is(":hidden"),\n
\t\t\t\tself = this;\n
\n
\t\t\tfor ( p in prop ) {\n
\t\t\t\tvar name = p.replace(rdashAlpha, fcamelCase);\n
\n
\t\t\t\tif ( p !== name ) {\n
\t\t\t\t\tprop[ name ] = prop[ p ];\n
\t\t\t\t\tdelete prop[ p ];\n
\t\t\t\t\tp = name;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( prop[p] === "hide" && hidden || prop[p] === "show" && !hidden ) {\n
\t\t\t\t\treturn opt.complete.call(this);\n
\t\t\t\t}\n
\n
\t\t\t\tif ( ( p === "height" || p === "width" ) && this.style ) {\n
\t\t\t\t\t// Store display property\n
\t\t\t\t\topt.display = jQuery.css(this, "display");\n
\n
\t\t\t\t\t// Make sure that nothing sneaks out\n
\t\t\t\t\topt.overflow = this.style.overflow;\n
\t\t\t\t}\n
\n
\t\t\t\tif ( jQuery.isArray( prop[p] ) ) {\n
\t\t\t\t\t// Create (if needed) and add to specialEasing\n
\t\t\t\t\t(opt.specialEasing = opt.specialEasing || {})[p] = prop[p][1];\n
\t\t\t\t\tprop[p] = prop[p][0];\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( opt.overflow != null ) {\n
\t\t\t\tthis.style.overflow = "hidden";\n
\t\t\t}\n
\n
\t\t\topt.curAnim = jQuery.extend({}, prop);\n
\n
\t\t\tjQuery.each( prop, function( name, val ) {\n
\t\t\t\tvar e = new jQuery.fx( self, opt, name );\n
\n
\t\t\t\tif ( rfxtypes.test(val) ) {\n
\t\t\t\t\te[ val === "toggle" ? hidden ? "show" : "hide" : val ]( prop );\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tvar parts = rfxnum.exec(val),\n
\t\t\t\t\t\tstart = e.cur(true) || 0;\n
\n
\t\t\t\t\tif ( parts ) {\n
\t\t\t\t\t\tvar end = parseFloat( parts[2] ),\n
\t\t\t\t\t\t\tunit = parts[3] || "px";\n
\n
\t\t\t\t\t\t// We need to compute starting value\n
\t\t\t\t\t\tif ( unit !== "px" ) {\n
\t\t\t\t\t\t\tself.style[ name ] = (end || 1) + unit;\n
\t\t\t\t\t\t\tstart = ((end || 1) / e.cur(true)) * start;\n
\t\t\t\t\t\t\tself.style[ name ] = start + unit;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\t// If a +=/-= token was provided, we\'re doing a relative animation\n
\t\t\t\t\t\tif ( parts[1] ) {\n
\t\t\t\t\t\t\tend = ((parts[1] === "-=" ? -1 : 1) * end) + start;\n
\t\t\t\t\t\t}\n
\n
\t\t\t\t\t\te.custom( start, end, unit );\n
\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\te.custom( start, val, "" );\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\t// For JS strict compliance\n
\t\t\treturn true;\n
\t\t});\n
\t},\n
\n
\tstop: function( clearQueue, gotoEnd ) {\n
\t\tvar timers = jQuery.timers;\n
\n
\t\tif ( clearQueue ) {\n
\t\t\tthis.queue([]);\n
\t\t}\n
\n
\t\tthis.each(function() {\n
\t\t\t// go in reverse order so anything added to the queue during the loop is ignored\n
\t\t\tfor ( var i = timers.length - 1; i >= 0; i-- ) {\n
\t\t\t\tif ( timers[i].elem === this ) {\n
\t\t\t\t\tif (gotoEnd) {\n
\t\t\t\t\t\t// force the next step to be the last\n
\t\t\t\t\t\ttimers[i](true);\n
\t\t\t\t\t}\n
\n
\t\t\t\t\ttimers.splice(i, 1);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\t// start the next in the queue if the last step wasn\'t forced\n
\t\tif ( !gotoEnd ) {\n
\t\t\tthis.dequeue();\n
\t\t}\n
\n
\t\treturn this;\n
\t}\n
\n
});\n
\n
// Generate shortcuts for custom animations\n
jQuery.each({\n
\tslideDown: genFx("show", 1),\n
\tslideUp: genFx("hide", 1),\n
\tslideToggle: genFx("toggle", 1),\n
\tfadeIn: { opacity: "show" },\n
\tfadeOut: { opacity: "hide" }\n
}, function( name, props ) {\n
\tjQuery.fn[ name ] = function( speed, callback ) {\n
\t\treturn this.animate( props, speed, callback );\n
\t};\n
});\n
\n
jQuery.extend({\n
\tspeed: function( speed, easing, fn ) {\n
\t\tvar opt = speed && typeof speed === "object" ? speed : {\n
\t\t\tcomplete: fn || !fn && easing ||\n
\t\t\t\tjQuery.isFunction( speed ) && speed,\n
\t\t\tduration: speed,\n
\t\t\teasing: fn && easing || easing && !jQuery.isFunction(easing) && easing\n
\t\t};\n
\n
\t\topt.duration = jQuery.fx.off ? 0 : typeof opt.duration === "number" ? opt.duration :\n
\t\t\tjQuery.fx.speeds[opt.duration] || jQuery.fx.speeds._default;\n
\n
\t\t// Queueing\n
\t\topt.old = opt.complete;\n
\t\topt.complete = function() {\n
\t\t\tif ( opt.queue !== false ) {\n
\t\t\t\tjQuery(this).dequeue();\n
\t\t\t}\n
\t\t\tif ( jQuery.isFunction( opt.old ) ) {\n
\t\t\t\topt.old.call( this );\n
\t\t\t}\n
\t\t};\n
\n
\t\treturn opt;\n
\t},\n
\n
\teasing: {\n
\t\tlinear: function( p, n, firstNum, diff ) {\n
\t\t\treturn firstNum + diff * p;\n
\t\t},\n
\t\tswing: function( p, n, firstNum, diff ) {\n
\t\t\treturn ((-Math.cos(p*Math.PI)/2) + 0.5) * diff + firstNum;\n
\t\t}\n
\t},\n
\n
\ttimers: [],\n
\n
\tfx: function( elem, options, prop ) {\n
\t\tthis.options = options;\n
\t\tthis.elem = elem;\n
\t\tthis.prop = prop;\n
\n
\t\tif ( !options.orig ) {\n
\t\t\toptions.orig = {};\n
\t\t}\n
\t}\n
\n
});\n
\n
jQuery.fx.prototype = {\n
\t// Simple function for setting a style value\n
\tupdate: function() {\n
\t\tif ( this.options.step ) {\n
\t\t\tthis.options.step.call( this.elem, this.now, this );\n
\t\t}\n
\n
\t\t(jQuery.fx.step[this.prop] || jQuery.fx.step._default)( this );\n
\n
\t\t// Set display property to block for height/width animations\n
\t\tif ( ( this.prop === "height" || this.prop === "width" ) && this.elem.style ) {\n
\t\t\tthis.elem.style.display = "block";\n
\t\t}\n
\t},\n
\n
\t// Get the current size\n
\tcur: function( force ) {\n
\t\tif ( this.elem[this.prop] != null && (!this.elem.style || this.elem.style[this.prop] == null) ) {\n
\t\t\treturn this.elem[ this.prop ];\n
\t\t}\n
\n
\t\tvar r = parseFloat(jQuery.css(this.elem, this.prop, force));\n
\t\treturn r && r > -10000 ? r : parseFloat(jQuery.curCSS(this.elem, this.prop)) || 0;\n
\t},\n
\n
\t// Start an animation from one number to another\n
\tcustom: function( from, to, unit ) {\n
\t\tthis.startTime = now();\n
\t\tthis.start = from;\n
\t\tthis.end = to;\n
\t\tthis.unit = unit || this.unit || "px";\n
\t\tthis.now = this.start;\n
\t\tthis.pos = this.state = 0;\n
\n
\t\tvar self = this;\n
\t\tfunction t( gotoEnd ) {\n
\t\t\treturn self.step(gotoEnd);\n
\t\t}\n
\n
\t\tt.elem = this.elem;\n
\n
\t\tif ( t() && jQuery.timers.push(t) && !timerId ) {\n
\t\t\ttimerId = setInterval(jQuery.fx.tick, 13);\n
\t\t}\n
\t},\n
\n
\t// Simple \'show\' function\n
\tshow: function() {\n
\t\t// Remember where we started, so that we can go back to it later\n
\t\tthis.options.orig[this.prop] = jQuery.style( this.elem, this.prop );\n
\t\tthis.options.show = true;\n
\n
\t\t// Begin the animation\n
\t\t// Make sure that we start at a small width/height to avoid any\n
\t\t// flash of content\n
\t\tthis.custom(this.prop === "width" || this.prop === "height" ? 1 : 0, this.cur());\n
\n
\t\t// Start by showing the element\n
\t\tjQuery( this.elem ).show();\n
\t},\n
\n
\t// Simple \'hide\' function\n
\thide: function() {\n
\t\t// Remember where we started, so that we can go back to it later\n
\t\tthis.options.orig[this.prop] = jQuery.style( this.elem, this.prop );\n
\t\tthis.options.hide = true;\n
\n
\t\t// Begin the animation\n
\t\tthis.custom(this.cur(), 0);\n
\t},\n
\n
\t// Each step of an animation\n
\tstep: function( gotoEnd ) {\n
\t\tvar t = now(), done = true;\n
\n
\t\tif ( gotoEnd || t >= this.options.duration + this.startTime ) {\n
\t\t\tthis.now = this.end;\n
\t\t\tthis.pos = this.state = 1;\n
\t\t\tthis.update();\n
\n
\t\t\tthis.options.curAnim[ this.prop ] = true;\n
\n
\t\t\tfor ( var i in this.options.curAnim ) {\n
\t\t\t\tif ( this.options.curAnim[i] !== true ) {\n
\t\t\t\t\tdone = false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif ( done ) {\n
\t\t\t\tif ( this.options.display != null ) {\n
\t\t\t\t\t// Reset the overflow\n
\t\t\t\t\tthis.elem.style.overflow = this.options.overflow;\n
\n
\t\t\t\t\t// Reset the display\n
\t\t\t\t\tvar old = jQuery.data(this.elem, "olddisplay");\n
\t\t\t\t\tthis.elem.style.display = old ? old : this.options.display;\n
\n
\t\t\t\t\tif ( jQuery.css(this.elem, "display") === "none" ) {\n
\t\t\t\t\t\tthis.elem.style.display = "block";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Hide the element if the "hide" operation was done\n
\t\t\t\tif ( this.options.hide ) {\n
\t\t\t\t\tjQuery(this.elem).hide();\n
\t\t\t\t}\n
\n
\t\t\t\t// Reset the properties, if the item has been hidden or shown\n
\t\t\t\tif ( this.options.hide || this.options.show ) {\n
\t\t\t\t\tfor ( var p in this.options.curAnim ) {\n
\t\t\t\t\t\tjQuery.style(this.elem, p, this.options.orig[p]);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\n
\t\t\t\t// Execute the complete function\n
\t\t\t\tthis.options.complete.call( this.elem );\n
\t\t\t}\n
\n
\t\t\treturn false;\n
\n
\t\t} else {\n
\t\t\tvar n = t - this.startTime;\n
\t\t\tthis.state = n / this.options.duration;\n
\n
\t\t\t// Perform the easing function, defaults to swing\n
\t\t\tvar specialEasing = this.options.specialEasing && this.options.specialEasing[this.prop];\n
\t\t\tvar defaultEasing = this.options.easing || (jQuery.easing.swing ? "swing" : "linear");\n
\t\t\tthis.pos = jQuery.easing[specialEasing || defaultEasing](this.state, n, 0, 1, this.options.duration);\n
\t\t\tthis.now = this.start + ((this.end - this.start) * this.pos);\n
\n
\t\t\t// Perform the next step of the animation\n
\t\t\tthis.update();\n
\t\t}\n
\n
\t\treturn true;\n
\t}\n
};\n
\n
jQuery.extend( jQuery.fx, {\n
\ttick: function() {\n
\t\tvar timers = jQuery.timers;\n
\n
\t\tfor ( var i = 0; i < timers.length; i++ ) {\n
\t\t\tif ( !timers[i]() ) {\n
\t\t\t\ttimers.splice(i--, 1);\n
\t\t\t}\n
\t\t}\n
\n
\t\tif ( !timers.length ) {\n
\t\t\tjQuery.fx.stop();\n
\t\t}\n
\t},\n
\t\t\n
\tstop: function() {\n
\t\tclearInterval( timerId );\n
\t\ttimerId = null;\n
\t},\n
\t\n
\tspeeds: {\n
\t\tslow: 600,\n
 \t\tfast: 200,\n
 \t\t// Default speed\n
 \t\t_default: 400\n
\t},\n
\n
\tstep: {\n
\t\topacity: function( fx ) {\n
\t\t\tjQuery.style(fx.elem, "opacity", fx.now);\n
\t\t},\n
\n
\t\t_default: function( fx ) {\n
\t\t\tif ( fx.elem.style && fx.elem.style[ fx.prop ] != null ) {\n
\t\t\t\tfx.elem.style[ fx.prop ] = (fx.prop === "width" || fx.prop === "height" ? Math.max(0, fx.now) : fx.now) + fx.unit;\n
\t\t\t} else {\n
\t\t\t\tfx.elem[ fx.prop ] = fx.now;\n
\t\t\t}\n
\t\t}\n
\t}\n
});\n
\n
if ( jQuery.expr && jQuery.expr.filters ) {\n
\tjQuery.expr.filters.animated = function( elem ) {\n
\t\treturn jQuery.grep(jQuery.timers, function( fn ) {\n
\t\t\treturn elem === fn.elem;\n
\t\t}).length;\n
\t};\n
}\n
\n
function genFx( type, num ) {\n
\tvar obj = {};\n
\n
\tjQuery.each( fxAttrs.concat.apply([], fxAttrs.slice(0,num)), function() {\n
\t\tobj[ this ] = type;\n
\t});\n
\n
\treturn obj;\n
}\n
if ( "getBoundingClientRect" in document.documentElement ) {\n
\tjQuery.fn.offset = function( options ) {\n
\t\tvar elem = this[0];\n
\n
\t\tif ( options ) { \n
\t\t\treturn this.each(function( i ) {\n
\t\t\t\tjQuery.offset.setOffset( this, options, i );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( !elem || !elem.ownerDocument ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tif ( elem === elem.ownerDocument.body ) {\n
\t\t\treturn jQuery.offset.bodyOffset( elem );\n
\t\t}\n
\n
\t\tvar box = elem.getBoundingClientRect(), doc = elem.ownerDocument, body = doc.body, docElem = doc.documentElement,\n
\t\t\tclientTop = docElem.clientTop || body.clientTop || 0, clientLeft = docElem.clientLeft || body.clientLeft || 0,\n
\t\t\ttop  = box.top  + (self.pageYOffset || jQuery.support.boxModel && docElem.scrollTop  || body.scrollTop ) - clientTop,\n
\t\t\tleft = box.left + (self.pageXOffset || jQuery.support.boxModel && docElem.scrollLeft || body.scrollLeft) - clientLeft;\n
\n
\t\treturn { top: top, left: left };\n
\t};\n
\n
} else {\n
\tjQuery.fn.offset = function( options ) {\n
\t\tvar elem = this[0];\n
\n
\t\tif ( options ) { \n
\t\t\treturn this.each(function( i ) {\n
\t\t\t\tjQuery.offset.setOffset( this, options, i );\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( !elem || !elem.ownerDocument ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tif ( elem === elem.ownerDocument.body ) {\n
\t\t\treturn jQuery.offset.bodyOffset( elem );\n
\t\t}\n
\n
\t\tjQuery.offset.initialize();\n
\n
\t\tvar offsetParent = elem.offsetParent, prevOffsetParent = elem,\n
\t\t\tdoc = elem.ownerDocument, computedStyle, docElem = doc.documentElement,\n
\t\t\tbody = doc.body, defaultView = doc.defaultView,\n
\t\t\tprevComputedStyle = defaultView ? defaultView.getComputedStyle( elem, null ) : elem.currentStyle,\n
\t\t\ttop = elem.offsetTop, left = elem.offsetLeft;\n
\n
\t\twhile ( (elem = elem.parentNode) && elem !== body && elem !== docElem ) {\n
\t\t\tif ( jQuery.offset.supportsFixedPosition && prevComputedStyle.position === "fixed" ) {\n
\t\t\t\tbreak;\n
\t\t\t}\n
\n
\t\t\tcomputedStyle = defaultView ? defaultView.getComputedStyle(elem, null) : elem.currentStyle;\n
\t\t\ttop  -= elem.scrollTop;\n
\t\t\tleft -= elem.scrollLeft;\n
\n
\t\t\tif ( elem === offsetParent ) {\n
\t\t\t\ttop  += elem.offsetTop;\n
\t\t\t\tleft += elem.offsetLeft;\n
\n
\t\t\t\tif ( jQuery.offset.doesNotAddBorder && !(jQuery.offset.doesAddBorderForTableAndCells && /^t(able|d|h)$/i.test(elem.nodeName)) ) {\n
\t\t\t\t\ttop  += parseFloat( computedStyle.borderTopWidth  ) || 0;\n
\t\t\t\t\tleft += parseFloat( computedStyle.borderLeftWidth ) || 0;\n
\t\t\t\t}\n
\n
\t\t\t\tprevOffsetParent = offsetParent, offsetParent = elem.offsetParent;\n
\t\t\t}\n
\n
\t\t\tif ( jQuery.offset.subtractsBorderForOverflowNotVisible && computedStyle.overflow !== "visible" ) {\n
\t\t\t\ttop  += parseFloat( computedStyle.borderTopWidth  ) || 0;\n
\t\t\t\tleft += parseFloat( computedStyle.borderLeftWidth ) || 0;\n
\t\t\t}\n
\n
\t\t\tprevComputedStyle = computedStyle;\n
\t\t}\n
\n
\t\tif ( prevComputedStyle.position === "relative" || prevComputedStyle.position === "static" ) {\n
\t\t\ttop  += body.offsetTop;\n
\t\t\tleft += body.offsetLeft;\n
\t\t}\n
\n
\t\tif ( jQuery.offset.supportsFixedPosition && prevComputedStyle.position === "fixed" ) {\n
\t\t\ttop  += Math.max( docElem.scrollTop, body.scrollTop );\n
\t\t\tleft += Math.max( docElem.scrollLeft, body.scrollLeft );\n
\t\t}\n
\n
\t\treturn { top: top, left: left };\n
\t};\n
}\n
\n
jQuery.offset = {\n
\tinitialize: function() {\n
\t\tvar body = document.body, container = document.createElement("div"), innerDiv, checkDiv, table, td, bodyMarginTop = parseFloat( jQuery.curCSS(body, "marginTop", true) ) || 0,\n
\t\t\thtml = "<div style=\'position:absolute;top:0;left:0;margin:0;border:5px solid #000;padding:0;width:1px;height:1px;\'><div></div></div><table style=\'position:absolute;top:0;left:0;margin:0;border:5px solid #000;padding:0;width:1px;height:1px;\' cellpadding=\'0\' cellspacing=\'0\'><tr><td></td></tr></table>";\n
\n
\t\tjQuery.extend( container.style, { position: "absolute", top: 0, left: 0, margin: 0, border: 0, width: "1px", height: "1px", visibility: "hidden" } );\n
\n
\t\tcontainer.innerHTML = html;\n
\t\tbody.insertBefore( container, body.firstChild );\n
\t\tinnerDiv = container.firstChild;\n
\t\tcheckDiv = innerDiv.firstChild;\n
\t\ttd = innerDiv.nextSibling.firstChild.firstChild;\n
\n
\t\tthis.doesNotAddBorder = (checkDiv.offsetTop !== 5);\n
\t\tthis.doesAddBorderForTableAndCells = (td.offsetTop === 5);\n
\n
\t\tcheckDiv.style.position = "fixed", checkDiv.style.top = "20px";\n
\t\t// safari subtracts parent border width here which is 5px\n
\t\tthis.supportsFixedPosition = (checkDiv.offsetTop === 20 || checkDiv.offsetTop === 15);\n
\t\tcheckDiv.style.position = checkDiv.style.top = "";\n
\n
\t\tinnerDiv.style.overflow = "hidden", innerDiv.style.position = "relative";\n
\t\tthis.subtractsBorderForOverflowNotVisible = (checkDiv.offsetTop === -5);\n
\n
\t\tthis.doesNotIncludeMarginInBodyOffset = (body.offsetTop !== bodyMarginTop);\n
\n
\t\tbody.removeChild( container );\n
\t\tbody = container = innerDiv = checkDiv = table = td = null;\n
\t\tjQuery.offset.initialize = jQuery.noop;\n
\t},\n
\n
\tbodyOffset: function( body ) {\n
\t\tvar top = body.offsetTop, left = body.offsetLeft;\n
\n
\t\tjQuery.offset.initialize();\n
\n
\t\tif ( jQuery.offset.doesNotIncludeMarginInBodyOffset ) {\n
\t\t\ttop  += parseFloat( jQuery.curCSS(body, "marginTop",  true) ) || 0;\n
\t\t\tleft += parseFloat( jQuery.curCSS(body, "marginLeft", true) ) || 0;\n
\t\t}\n
\n
\t\treturn { top: top, left: left };\n
\t},\n
\t\n
\tsetOffset: function( elem, options, i ) {\n
\t\t// set position first, in-case top/left are set even on static elem\n
\t\tif ( /static/.test( jQuery.curCSS( elem, "position" ) ) ) {\n
\t\t\telem.style.position = "relative";\n
\t\t}\n
\t\tvar curElem   = jQuery( elem ),\n
\t\t\tcurOffset = curElem.offset(),\n
\t\t\tcurTop    = parseInt( jQuery.curCSS( elem, "top",  true ), 10 ) || 0,\n
\t\t\tcurLeft   = parseInt( jQuery.curCSS( elem, "left", true ), 10 ) || 0;\n
\n
\t\tif ( jQuery.isFunction( options ) ) {\n
\t\t\toptions = options.call( elem, i, curOffset );\n
\t\t}\n
\n
\t\tvar props = {\n
\t\t\ttop:  (options.top  - curOffset.top)  + curTop,\n
\t\t\tleft: (options.left - curOffset.left) + curLeft\n
\t\t};\n
\t\t\n
\t\tif ( "using" in options ) {\n
\t\t\toptions.using.call( elem, props );\n
\t\t} else {\n
\t\t\tcurElem.css( props );\n
\t\t}\n
\t}\n
};\n
\n
\n
jQuery.fn.extend({\n
\tposition: function() {\n
\t\tif ( !this[0] ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tvar elem = this[0],\n
\n
\t\t// Get *real* offsetParent\n
\t\toffsetParent = this.offsetParent(),\n
\n
\t\t// Get correct offsets\n
\t\toffset       = this.offset(),\n
\t\tparentOffset = /^body|html$/i.test(offsetParent[0].nodeName) ? { top: 0, left: 0 } : offsetParent.offset();\n
\n
\t\t// Subtract element margins\n
\t\t// note: when an element has margin: auto the offsetLeft and marginLeft\n
\t\t// are the same in Safari causing offset.left to incorrectly be 0\n
\t\toffset.top  -= parseFloat( jQuery.curCSS(elem, "marginTop",  true) ) || 0;\n
\t\toffset.left -= parseFloat( jQuery.curCSS(elem, "marginLeft", true) ) || 0;\n
\n
\t\t// Add offsetParent borders\n
\t\tparentOffset.top  += parseFloat( jQuery.curCSS(offsetParent[0], "borderTopWidth",  true) ) || 0;\n
\t\tparentOffset.left += parseFloat( jQuery.curCSS(offsetParent[0], "borderLeftWidth", true) ) || 0;\n
\n
\t\t// Subtract the two offsets\n
\t\treturn {\n
\t\t\ttop:  offset.top  - parentOffset.top,\n
\t\t\tleft: offset.left - parentOffset.left\n
\t\t};\n
\t},\n
\n
\toffsetParent: function() {\n
\t\treturn this.map(function() {\n
\t\t\tvar offsetParent = this.offsetParent || document.body;\n
\t\t\twhile ( offsetParent && (!/^body|html$/i.test(offsetParent.nodeName) && jQuery.css(offsetParent, "position") === "static") ) {\n
\t\t\t\toffsetParent = offsetParent.offsetParent;\n
\t\t\t}\n
\t\t\treturn offsetParent;\n
\t\t});\n
\t}\n
});\n
\n
\n
// Create scrollLeft and scrollTop methods\n
jQuery.each( ["Left", "Top"], function( i, name ) {\n
\tvar method = "scroll" + name;\n
\n
\tjQuery.fn[ method ] = function(val) {\n
\t\tvar elem = this[0], win;\n
\t\t\n
\t\tif ( !elem ) {\n
\t\t\treturn null;\n
\t\t}\n
\n
\t\tif ( val !== undefined ) {\n
\t\t\t// Set the scroll offset\n
\t\t\treturn this.each(function() {\n
\t\t\t\twin = getWindow( this );\n
\n
\t\t\t\tif ( win ) {\n
\t\t\t\t\twin.scrollTo(\n
\t\t\t\t\t\t!i ? val : jQuery(win).scrollLeft(),\n
\t\t\t\t\t\t i ? val : jQuery(win).scrollTop()\n
\t\t\t\t\t);\n
\n
\t\t\t\t} else {\n
\t\t\t\t\tthis[ method ] = val;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else {\n
\t\t\twin = getWindow( elem );\n
\n
\t\t\t// Return the scroll offset\n
\t\t\treturn win ? ("pageXOffset" in win) ? win[ i ? "pageYOffset" : "pageXOffset" ] :\n
\t\t\t\tjQuery.support.boxModel && win.document.documentElement[ method ] ||\n
\t\t\t\t\twin.document.body[ method ] :\n
\t\t\t\telem[ method ];\n
\t\t}\n
\t};\n
});\n
\n
function getWindow( elem ) {\n
\treturn ("scrollTo" in elem && elem.document) ?\n
\t\telem :\n
\t\telem.nodeType === 9 ?\n
\t\t\telem.defaultView || elem.parentWindow :\n
\t\t\tfalse;\n
}\n
// Create innerHeight, innerWidth, outerHeight and outerWidth methods\n
jQuery.each([ "Height", "Width" ], function( i, name ) {\n
\n
\tvar type = name.toLowerCase();\n
\n
\t// innerHeight and innerWidth\n
\tjQuery.fn["inner" + name] = function() {\n
\t\treturn this[0] ?\n
\t\t\tjQuery.css( this[0], type, false, "padding" ) :\n
\t\t\tnull;\n
\t};\n
\n
\t// outerHeight and outerWidth\n
\tjQuery.fn["outer" + name] = function( margin ) {\n
\t\treturn this[0] ?\n
\t\t\tjQuery.css( this[0], type, false, margin ? "margin" : "border" ) :\n
\t\t\tnull;\n
\t};\n
\n
\tjQuery.fn[ type ] = function( size ) {\n
\t\t// Get window width or height\n
\t\tvar elem = this[0];\n
\t\tif ( !elem ) {\n
\t\t\treturn size == null ? null : this;\n
\t\t}\n
\t\t\n
\t\tif ( jQuery.isFunction( size ) ) {\n
\t\t\treturn this.each(function( i ) {\n
\t\t\t\tvar self = jQuery( this );\n
\t\t\t\tself[ type ]( size.call( this, i, self[ type ]() ) );\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn ("scrollTo" in elem && elem.document) ? // does it walk and quack like a window?\n
\t\t\t// Everyone else use document.documentElement or document.body depending on Quirks vs Standards mode\n
\t\t\telem.document.compatMode === "CSS1Compat" && elem.document.documentElement[ "client" + name ] ||\n
\t\t\telem.document.body[ "client" + name ] :\n
\n
\t\t\t// Get document width or height\n
\t\t\t(elem.nodeType === 9) ? // is it a document\n
\t\t\t\t// Either scroll[Width/Height] or offset[Width/Height], whichever is greater\n
\t\t\t\tMath.max(\n
\t\t\t\t\telem.documentElement["client" + name],\n
\t\t\t\t\telem.body["scroll" + name], elem.documentElement["scroll" + name],\n
\t\t\t\t\telem.body["offset" + name], elem.documentElement["offset" + name]\n
\t\t\t\t) :\n
\n
\t\t\t\t// Get or set width or height on the element\n
\t\t\t\tsize === undefined ?\n
\t\t\t\t\t// Get width or height on the element\n
\t\t\t\t\tjQuery.css( elem, type ) :\n
\n
\t\t\t\t\t// Set the width or height on the element (default to pixels if value is unitless)\n
\t\t\t\t\tthis.css( type, typeof size === "string" ? size : size + "px" );\n
\t};\n
\n
});\n
\n
exports.$ = exports.jQuery = jQuery;\n
\n
});\n
;bespin.tiki.register("::embedded", {\n
    name: "embedded",\n
    dependencies: { "theme_manager": "0.0.0", "text_editor": "0.0.0", "appconfig": "0.0.0", "edit_session": "0.0.0", "screen_theme": "0.0.0" }\n
});\n
bespin.tiki.module("embedded:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
"define metadata";\n
({\n
    "dependencies": {\n
        "appconfig": "0.0.0",\n
        "edit_session": "0.0.0",\n
        "theme_manager": "0.0.0",\n
        "screen_theme": "0.0.0",\n
        "text_editor": "0.0.0"\n
    }\n
});\n
"end";\n
\n
// This plugin is artificial as a convenience. It\'s just here to collect up\n
// the common dependencies for embedded use\n
\n
});\n
;bespin.tiki.register("::appconfig", {\n
    name: "appconfig",\n
    dependencies: { "jquery": "0.0.0", "canon": "0.0.0", "settings": "0.0.0" }\n
});\n
bespin.tiki.module("appconfig:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var $ = require(\'jquery\').$;\n
var settings = require(\'settings\').settings;\n
var group = require("bespin:promise").group;\n
var Promise = require("bespin:promise").Promise;\n
var console = require("bespin:console").console;\n
var Trace = require("bespin:util/stacktrace").Trace;\n
var util = require(\'bespin:util/util\');\n
\n
var firstBespin = true;\n
\n
/*\n
 * launch Bespin with the configuration provided. The configuration is\n
 * an object with the following properties:\n
 * - theme: an object with the basePlugin as string and the standardTheme as\n
 *          string. Both are optional. If no basePlugin is given, screen_theme\n
 *          is used if this exists.\n
 * - objects: an object with a collection of named objects that will be\n
 *            registered with the plugin catalog (see PluginCatalog.registerObject)\n
 *            This will automatically be augmented with sane defaults (for\n
 *            example, most Bespin users want a text editor!)\n
 * - gui: instructions on how to build a GUI. Specifically, the current border\n
 *        layout positions will be filled in. Again this provides sane defaults.\n
 * - container: node to attach to (optional). If not provided a node will be\n
 *              created. and added to the body.\n
 * - settings: settings to preconfigure\n
 */\n
exports.launch = function(config) {\n
    var launchPromise = new Promise();\n
\n
    // Remove the "Loading..." hint.\n
    $(\'#_bespin_loading\').remove();\n
\n
    // This will hold the require function to get the catalog.\n
    var require;\n
\n
    // Is this the fist Bespin?\n
    if (firstBespin) {\n
        // Use the global require.\n
        require = bespin.tiki.require;\n
        firstBespin = false;\n
    } else {\n
        // Otherwise create a new tiki-bespin sandbox and a new require function.\n
        var sandbox = new (bespin.tiki.require(\'bespin:sandbox\').Sandbox);\n
        require = sandbox.createRequire({\n
            id: \'index\',\n
            ownerPackage: bespin.tiki.loader.anonymousPackage\n
        });\n
    }\n
\n
    // Here we go: Require the catalog that is used for this Bespin instance.\n
    var catalog = require(\'bespin:plugins\').catalog;\n
\n
    // Launch Bespin!\n
    config = config || {};\n
    exports.normalizeConfig(catalog, config);\n
    var objects = config.objects;\n
    for (var key in objects) {\n
        catalog.registerObject(key, objects[key]);\n
    }\n
\n
    for (var setting in config.settings) {\n
        settings.set(setting, config.settings[setting]);\n
    }\n
\n
    // Resolve the launchPromise and pass the env variable along.\n
    var resolveLaunchPromise = function() {\n
        var env = require("environment").env;\n
\n
        var editor = env.editor;\n
        if (editor) {\n
            if (config.lineNumber) {\n
                editor.setLineNumber(config.lineNumber);\n
            }\n
            if (config.stealFocus) {\n
                editor.focus = true;\n
            }\n
            if (config.readOnly) {\n
                editor.readOnly = config.readOnly;\n
            }\n
            if (config.syntax) {\n
                editor.syntax = config.syntax;\n
            }\n
        }\n
        var commandLine = catalog.getObject(\'commandLine\');\n
        if (commandLine) {\n
            env.commandLine = commandLine;\n
        }\n
\n
        catalog.publish(this, \'appLaunched\');\n
\n
        launchPromise.resolve(env);\n
    }.bind(this);\n
\n
    var themeLoadingPromise = new Promise();\n
\n
    themeLoadingPromise.then(function() {\n
        if (objects.loginController) {\n
            catalog.createObject("loginController").then(\n
                function(loginController) {\n
                    var pr = loginController.showLogin();\n
                    pr.then(function(username) {\n
                        // Add the username as constructor argument.\n
                        config.objects.session.arguments.push(username);\n
\n
                        exports.launchEditor(catalog, config).then(resolveLaunchPromise,\n
                                        launchPromise.reject.bind(launchPromise));\n
                    });\n
                });\n
        } else {\n
            exports.launchEditor(catalog, config).then(resolveLaunchPromise,\n
                                        launchPromise.reject.bind(launchPromise));\n
        }\n
    }, function(error) {\n
        launchPromise.reject(error);\n
    });\n
\n
    // If the themeManager plugin is there, then check for theme configuration.\n
    if (catalog.plugins.theme_manager) {\n
        bespin.tiki.require.ensurePackage(\'::theme_manager\', function() {\n
            var themeManager = require(\'theme_manager\');\n
            if (config.theme.basePlugin) {\n
                themeManager.setBasePlugin(config.theme.basePlugin);\n
            }\n
            if (config.theme.standard) {\n
                themeManager.setStandardTheme(config.theme.standard);\n
            }\n
            themeManager.startParsing().then(function() {\n
                themeLoadingPromise.resolve();\n
            }, function(error) {\n
                themeLoadingPromise.reject(error);\n
            });\n
        });\n
    } else {\n
        themeLoadingPromise.resolve();\n
    }\n
\n
    return launchPromise;\n
};\n
\n
exports.normalizeConfig = function(catalog, config) {\n
    if (config.objects === undefined) {\n
        config.objects = {};\n
    }\n
    if (config.autoload === undefined) {\n
        config.autoload = [];\n
    }\n
    if (config.theme === undefined) {\n
        config.theme = {};\n
    }\n
    if (!config.theme.basePlugin && catalog.plugins.screen_theme) {\n
        config.theme.basePlugin = \'screen_theme\';\n
    }\n
    if (!config.initialContent) {\n
        config.initialContent = \'\';\n
    }\n
    if (!config.settings) {\n
        config.settings = {};\n
    }\n
\n
    if (!config.objects.notifier && catalog.plugins.notifier) {\n
        config.objects.notifier = {\n
        };\n
    }\n
\n
    if (!config.objects.loginController && catalog.plugins.userident) {\n
        config.objects.loginController = {\n
        };\n
    }\n
    if (!config.objects.fileHistory && catalog.plugins.file_history) {\n
        config.objects.fileHistory = {\n
            factory: \'file_history\',\n
            arguments: [\n
                "session"\n
            ],\n
            objects: {\n
                "0": "session"\n
            }\n
        };\n
    }\n
    if (!config.objects.server && catalog.plugins.bespin_server) {\n
        config.objects.server = {\n
            factory: "bespin_server"\n
        };\n
        config.objects.filesource = {\n
            factory: "bespin_filesource",\n
            arguments: [\n
                "server"\n
            ],\n
            objects: {\n
                "0": "server"\n
            }\n
        };\n
    }\n
    if (!config.objects.files && catalog.plugins.filesystem &&\n
        config.objects.filesource) {\n
        config.objects.files = {\n
            arguments: [\n
                "filesource"\n
            ],\n
            "objects": {\n
                "0": "filesource"\n
            }\n
        };\n
    }\n
    if (!config.objects.editor) {\n
        config.objects.editor = {\n
            factory: "text_editor",\n
            arguments: [\n
                config.initialContent\n
            ]\n
        };\n
    }\n
    if (!config.objects.session) {\n
        config.objects.session = {\n
            arguments: [\n
                "editor"\n
            ],\n
            "objects": {\n
                "0": "editor"\n
            }\n
        };\n
    }\n
    if (!config.objects.commandLine && catalog.plugins.command_line) {\n
        config.objects.commandLine = {\n
        };\n
    }\n
\n
    if (config.gui === undefined) {\n
        config.gui = {};\n
    }\n
\n
    var alreadyRegistered = {};\n
    for (var key in config.gui) {\n
        var desc = config.gui[key];\n
        if (desc.component) {\n
            alreadyRegistered[desc.component] = true;\n
        }\n
    }\n
\n
    if (!config.gui.center && config.objects.editor\n
        && !alreadyRegistered.editor) {\n
        config.gui.center = { component: "editor" };\n
    }\n
    if (!config.gui.south && config.objects.commandLine\n
        && !alreadyRegistered.commandLine) {\n
        config.gui.south = { component: "commandLine" };\n
    }\n
};\n
\n
exports.launchEditor = function(catalog, config) {\n
    var retPr = new Promise();\n
\n
    if (config === null) {\n
        var message = \'Cannot start editor without a configuration!\';\n
        console.error(message);\n
        retPr.reject(message);\n
        return retPr;\n
    }\n
\n
    var pr = createAllObjects(catalog, config);\n
    pr.then(function() {\n
        generateGUI(catalog, config, retPr);\n
    }, function(error) {\n
        console.error(\'Error while creating objects\');\n
        new Trace(error).log();\n
        retPr.reject(error);\n
    });\n
\n
    return retPr;\n
};\n
\n
var createAllObjects = function(catalog, config) {\n
    var promises = [];\n
    for (var objectName in config.objects) {\n
        promises.push(catalog.createObject(objectName));\n
    }\n
    return group(promises);\n
};\n
\n
var generateGUI = function(catalog, config, pr) {\n
    var error;\n
\n
    var container = document.createElement(\'div\');\n
    container.setAttribute(\'class\', \'container\');\n
\n
    var centerContainer = document.createElement(\'div\');\n
    centerContainer.setAttribute(\'class\', \'center-container\');\n
    container.appendChild(centerContainer);\n
\n
    var element = config.element || document.body;\n
    // Add the \'bespin\' class to the element in case it doesn\'t have this already.\n
    util.addClass(element, \'bespin\');\n
    element.appendChild(container);\n
\n
    for (var place in config.gui) {\n
        var descriptor = config.gui[place];\n
\n
        var component = catalog.getObject(descriptor.component);\n
        if (!component) {\n
            error = \'Cannot find object \' + descriptor.component +\n
                            \' to attach to the Bespin UI\';\n
            console.error(error);\n
            pr.reject(error);\n
            return;\n
        }\n
\n
        element = component.element;\n
        if (!element) {\n
            error = \'Component \' + descriptor.component + \' does not have\' +\n
                          \' an "element" attribute to attach to the Bespin UI\';\n
            console.error(error);\n
            pr.reject(error);\n
            return;\n
        }\n
\n
        $(element).addClass(place);\n
\n
        if (place == \'west\' || place == \'east\' || place == \'center\') {\n
            centerContainer.appendChild(element);\n
        } else {\n
            container.appendChild(element);\n
        }\n
\n
        // Call the elementAppended event if there is one.\n
        if (component.elementAppended) {\n
            component.elementAppended();\n
        }\n
    }\n
\n
    pr.resolve();\n
};\n
\n
});\n
;bespin.tiki.register("::screen_theme", {\n
    name: "screen_theme",\n
    dependencies: { "theme_manager": "0.0.0" }\n
});\n
bespin.tiki.module("screen_theme:index",function(require,exports,module) {\n
\n
});\n
\n
(function() {\n
var $ = bespin.tiki.require("jquery").$;\n
$(document).ready(function() {\n
    bespin.tiki.require("bespin:plugins").catalog.registerMetadata({"text_editor": {"resourceURL": "resources/text_editor/", "description": "Canvas-based text editor component and many common editing commands", "dependencies": {"completion": "0.0.0", "undomanager": "0.0.0", "settings": "0.0.0", "canon": "0.0.0", "rangeutils": "0.0.0", "traits": "0.0.0", "theme_manager": "0.0.0", "keyboard": "0.0.0", "edit_session": "0.0.0", "syntax_manager": "0.0.0"}, "testmodules": ["tests/testScratchcanvas", "tests/models/testTextstorage", "tests/utils/testRect", "tests/controllers/testLayoutmanager"], "provides": [{"action": "new", "pointer": "views/editor#EditorView", "ep": "factory", "name": "text_editor"}, {"pointer": "views/editor#EditorView", "ep": "appcomponent", "name": "editor_view"}, {"predicates": {"isTextView": true}, "pointer": "commands/editing#backspace", "ep": "command", "key": "backspace", "name": "backspace"}, {"predicates": {"isTextView": true}, "pointer": "commands/editing#deleteCommand", "ep": "command", "key": "delete", "name": "delete"}, {"description": "Delete all lines currently selected", "key": "ctrl_d", "predicates": {"isTextView": true}, "pointer": "commands/editing#deleteLines", "ep": "command", "name": "deletelines"}, {"description": "Create a new, empty line below the current one", "key": "ctrl_return", "predicates": {"isTextView": true}, "pointer": "commands/editing#openLine", "ep": "command", "name": "openline"}, {"description": "Join the current line with the following", "key": "ctrl_shift_j", "predicates": {"isTextView": true}, "pointer": "commands/editing#joinLines", "ep": "command", "name": "joinline"}, {"params": [{"defaultValue": "", "type": "text", "name": "text", "description": "The text to insert"}], "pointer": "commands/editing#insertText", "ep": "command", "name": "insertText"}, {"predicates": {"completing": false, "isTextView": true}, "pointer": "commands/editing#newline", "ep": "command", "key": "return", "name": "newline"}, {"predicates": {"completing": false, "isTextView": true}, "pointer": "commands/editing#tab", "ep": "command", "key": "tab", "name": "tab"}, {"predicates": {"isTextView": true}, "pointer": "commands/editing#untab", "ep": "command", "key": "shift_tab", "name": "untab"}, {"predicates": {"isTextView": true}, "ep": "command", "name": "move"}, {"description": "Repeat the last search (forward)", "pointer": "commands/editor#findNextCommand", "ep": "command", "key": "ctrl_g", "name": "findnext"}, {"description": "Repeat the last search (backward)", "pointer": "commands/editor#findPrevCommand", "ep": "command", "key": "ctrl_shift_g", "name": "findprev"}, {"predicates": {"completing": false, "isTextView": true}, "pointer": "commands/movement#moveDown", "ep": "command", "key": "down", "name": "move down"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveLeft", "ep": "command", "key": "left", "name": "move left"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveRight", "ep": "command", "key": "right", "name": "move right"}, {"predicates": {"completing": false, "isTextView": true}, "pointer": "commands/movement#moveUp", "ep": "command", "key": "up", "name": "move up"}, {"predicates": {"isTextView": true}, "ep": "command", "name": "select"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectDown", "ep": "command", "key": "shift_down", "name": "select down"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectLeft", "ep": "command", "key": "shift_left", "name": "select left"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectRight", "ep": "command", "key": "shift_right", "name": "select right"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectUp", "ep": "command", "key": "shift_up", "name": "select up"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveLineEnd", "ep": "command", "key": ["end", "ctrl_right"], "name": "move lineend"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectLineEnd", "ep": "command", "key": ["shift_end", "ctrl_shift_right"], "name": "select lineend"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveDocEnd", "ep": "command", "key": "ctrl_down", "name": "move docend"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectDocEnd", "ep": "command", "key": "ctrl_shift_down", "name": "select docend"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveLineStart", "ep": "command", "key": ["home", "ctrl_left"], "name": "move linestart"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectLineStart", "ep": "command", "key": ["shift_home", "ctrl_shift_left"], "name": "select linestart"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveDocStart", "ep": "command", "key": "ctrl_up", "name": "move docstart"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectDocStart", "ep": "command", "key": "ctrl_shift_up", "name": "select docstart"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#moveNextWord", "ep": "command", "key": ["alt_right"], "name": "move nextword"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectNextWord", "ep": "command", "key": ["alt_shift_right"], "name": "select nextword"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#movePreviousWord", "ep": "command", "key": ["alt_left"], "name": "move prevword"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectPreviousWord", "ep": "command", "key": ["alt_shift_left"], "name": "select prevword"}, {"predicates": {"isTextView": true}, "pointer": "commands/movement#selectAll", "ep": "command", "key": ["ctrl_a", "meta_a"], "name": "select all"}, {"predicates": {"isTextView": true}, "ep": "command", "name": "scroll"}, {"predicates": {"isTextView": true}, "pointer": "commands/scrolling#scrollDocStart", "ep": "command", "key": "ctrl_home", "name": "scroll start"}, {"predicates": {"isTextView": true}, "pointer": "commands/scrolling#scrollDocEnd", "ep": "command", "key": "ctrl_end", "name": "scroll end"}, {"predicates": {"isTextView": true}, "pointer": "commands/scrolling#scrollPageDown", "ep": "command", "key": "pagedown", "name": "scroll down"}, {"predicates": {"isTextView": true}, "pointer": "commands/scrolling#scrollPageUp", "ep": "command", "key": "pageup", "name": "scroll up"}, {"pointer": "commands/editor#lcCommand", "description": "Change all selected text to lowercase", "withKey": "CMD SHIFT L", "ep": "command", "name": "lc"}, {"pointer": "commands/editor#detabCommand", "description": "Convert tabs to spaces.", "params": [{"defaultValue": null, "type": "text", "name": "tabsize", "description": "Optionally, specify a tab size. (Defaults to setting.)"}], "ep": "command", "name": "detab"}, {"pointer": "commands/editor#entabCommand", "description": "Convert spaces to tabs.", "params": [{"defaultValue": null, "type": "text", "name": "tabsize", "description": "Optionally, specify a tab size. (Defaults to setting.)"}], "ep": "command", "name": "entab"}, {"pointer": "commands/editor#trimCommand", "description": "trim trailing or leading whitespace from each line in selection", "params": [{"defaultValue": "both", "type": {"data": [{"name": "left"}, {"name": "right"}, {"name": "both"}], "name": "selection"}, "name": "side", "description": "Do we trim from the left, right or both"}], "ep": "command", "name": "trim"}, {"pointer": "commands/editor#ucCommand", "description": "Change all selected text to uppercase", "withKey": "CMD SHIFT U", "ep": "command", "name": "uc"}, {"predicates": {"isTextView": true}, "pointer": "controllers/undo#undoManagerCommand", "ep": "command", "key": ["ctrl_shift_z"], "name": "redo"}, {"predicates": {"isTextView": true}, "pointer": "controllers/undo#undoManagerCommand", "ep": "command", "key": ["ctrl_z"], "name": "undo"}, {"description": "The distance in characters between each tab", "defaultValue": 8, "type": "number", "ep": "setting", "name": "tabstop"}, {"description": "Customize the keymapping", "defaultValue": "{}", "type": "text", "ep": "setting", "name": "customKeymapping"}, {"description": "The keymapping to use", "defaultValue": "standard", "type": "text", "ep": "setting", "name": "keymapping"}, {"description": "The editor font size in pixels", "defaultValue": 14, "type": "number", "ep": "setting", "name": "fontsize"}, {"description": "The editor font face", "defaultValue": "Monaco, Lucida Console, monospace", "type": "text", "ep": "setting", "name": "fontface"}, {"defaultValue": {"color": "#e5c138", "paddingLeft": 5, "backgroundColor": "#4c4a41", "paddingRight": 10}, "ep": "themevariable", "name": "gutter"}, {"defaultValue": {"color": "#e6e6e6", "selectedTextBackgroundColor": "#526da5", "backgroundColor": "#2a211c", "cursorColor": "#879aff", "unfocusedCursorBackgroundColor": "#73171e", "unfocusedCursorColor": "#ff0033"}, "ep": "themevariable", "name": "editor"}, {"defaultValue": {"comment": "#666666", "directive": "#999999", "keyword": "#42A8ED", "plain": "#e6e6e6", "error": "#ff0000", "operator": "#88BBFF", "identifier": "#D841FF", "string": "#039A0A"}, "ep": "themevariable", "name": "highlighter"}, {"defaultValue": {"nibStrokeStyle": "rgb(150, 150, 150)", "fullAlpha": 1.0, "barFillStyle": "rgb(0, 0, 0)", "particalAlpha": 0.29999999999999999, "barFillGradientBottomStop": "rgb(44, 44, 44)", "backgroundStyle": "#2A211C", "thickness": 17, "padding": 5, "trackStrokeStyle": "rgb(150, 150, 150)", "nibArrowStyle": "rgb(255, 255, 255)", "barFillGradientBottomStart": "rgb(22, 22, 22)", "barFillGradientTopStop": "rgb(40, 40, 40)", "barFillGradientTopStart": "rgb(90, 90, 90)", "nibStyle": "rgb(100, 100, 100)", "trackFillStyle": "rgba(50, 50, 50, 0.8)"}, "ep": "themevariable", "name": "scroller"}, {"description": "Event: Notify when something within the editor changed.", "params": [{"required": true, "name": "pointer", "description": "Function that is called whenever a change happened."}], "ep": "extensionpoint", "name": "editorChange"}], "type": "plugins/supported", "name": "text_editor"}, "completion": {"resourceURL": "resources/completion/", "description": "Code completion support", "dependencies": {"jquery": "0.0.0", "ctags": "0.0.0", "rangeutils": "0.0.0", "canon": "0.0.0", "underscore": "0.0.0"}, "testmodules": [], "provides": [{"indexOn": "name", "description": "Code completion support for specific languages", "ep": "extensionpoint", "name": "completion"}, {"description": "Accept the chosen completion", "key": ["return", "tab"], "predicates": {"completing": true}, "pointer": "controller#completeCommand", "ep": "command", "name": "complete"}, {"description": "Abandon the completion", "key": "escape", "predicates": {"completing": true}, "pointer": "controller#completeCancelCommand", "ep": "command", "name": "complete cancel"}, {"description": "Choose the completion below", "key": "down", "predicates": {"completing": true}, "pointer": "controller#completeDownCommand", "ep": "command", "name": "complete down"}, {"description": "Choose the completion above", "key": "up", "predicates": {"completing": true}, "pointer": "controller#completeUpCommand", "ep": "command", "name": "complete up"}], "type": "plugins/supported", "name": "completion"}, "syntax_worker": {"resourceURL": "resources/syntax_worker/", "description": "Coordinates multiple syntax engines", "environments": {"worker": true}, "dependencies": {"syntax_directory": "0.0.0", "underscore": "0.0.0"}, "testmodules": [], "type": "plugins/supported", "name": "syntax_worker"}, "undomanager": {"resourceURL": "resources/undomanager/", "description": "Manages undoable events", "testmodules": ["tests/testUndomanager"], "provides": [{"pointer": "#undoManagerCommand", "ep": "command", "key": ["ctrl_shift_z"], "name": "redo"}, {"pointer": "#undoManagerCommand", "ep": "command", "key": ["ctrl_z"], "name": "undo"}], "type": "plugins/supported", "name": "undomanager"}, "embedded": {"testmodules": [], "dependencies": {"theme_manager": "0.0.0", "text_editor": "0.0.0", "appconfig": "0.0.0", "edit_session": "0.0.0", "screen_theme": "0.0.0"}, "resourceURL": "resources/embedded/", "name": "embedded", "type": "plugins/supported"}, "less": {"resourceURL": "resources/less/", "description": "Leaner CSS", "contributors": [], "author": "Alexis Sellier <self@cloudhead.net>", "url": "http://lesscss.org", "version": "1.0.11", "dependencies": {}, "testmodules": [], "provides": [], "keywords": ["css", "parser", "lesscss", "browser"], "type": "plugins/thirdparty", "name": "less"}, "python": {"resourceURL": "resources/python/", "name": "python", "environments": {"worker": true}, "dependencies": {"syntax_manager": "0.0.0"}, "testmodules": [], "provides": [{"pointer": "#PySyntax", "ep": "syntax", "fileexts": ["py"], "name": "py"}], "type": "plugins/thirdparty", "description": "Python syntax highlighter"}, "jquery": {"testmodules": [], "resourceURL": "resources/jquery/", "name": "jquery", "type": "plugins/thirdparty"}, "theme_manager_base": {"resourceURL": "resources/theme_manager_base/", "name": "theme_manager_base", "share": true, "environments": {"main": true}, "dependencies": {}, "testmodules": [], "provides": [{"description": "(Less)files holding the CSS style information for the UI.", "params": [{"required": true, "name": "url", "description": "Name of the ThemeStylesFile - can also be an array of files."}], "ep": "extensionpoint", "name": "themestyles"}, {"description": "Event: Notify when the theme(styles) changed.", "params": [{"required": true, "name": "pointer", "description": "Function that is called whenever the theme is changed."}], "ep": "extensionpoint", "name": "themeChange"}, {"indexOn": "name", "description": "A theme is a way change the look of the application.", "params": [{"required": false, "name": "url", "description": "Name of a ThemeStylesFile that holds theme specific CSS rules - can also be an array of files."}, {"required": true, "name": "pointer", "description": "Function that returns the ThemeData"}], "ep": "extensionpoint", "name": "theme"}], "type": "plugins/supported", "description": "Defines extension points required for theming"}, "stylesheet": {"resourceURL": "resources/stylesheet/", "name": "stylesheet", "environments": {"worker": true}, "dependencies": {"standard_syntax": "0.0.0"}, "testmodules": [], "provides": [{"pointer": "#CSSSyntax", "ep": "syntax", "fileexts": ["css", "less"], "name": "css"}], "type": "plugins/supported", "description": "CSS syntax highlighter"}, "rangeutils": {"testmodules": ["tests/test"], "type": "plugins/supported", "resourceURL": "resources/rangeutils/", "description": "Utility functions for dealing with ranges of text", "name": "rangeutils"}, "theme_manager": {"resourceURL": "resources/theme_manager/", "name": "theme_manager", "share": true, "environments": {"main": true, "worker": false}, "dependencies": {"theme_manager_base": "0.0.0", "settings": "0.0.0", "events": "0.0.0", "less": "0.0.0"}, "testmodules": [], "provides": [{"unregister": "themestyles#unregisterThemeStyles", "register": "themestyles#registerThemeStyles", "ep": "extensionhandler", "name": "themestyles"}, {"unregister": "index#unregisterTheme", "register": "index#registerTheme", "ep": "extensionhandler", "name": "theme"}, {"defaultValue": "standard", "description": "The theme plugin\'s name to use. If set to \'standard\' no theme will be used", "type": "text", "ep": "setting", "name": "theme"}, {"pointer": "#appLaunched", "ep": "appLaunched"}], "type": "plugins/supported", "description": "Handles colors in Bespin"}, "html": {"resourceURL": "resources/html/", "name": "html", "environments": {"worker": true}, "dependencies": {"standard_syntax": "0.0.0"}, "testmodules": [], "provides": [{"pointer": "#HTMLSyntax", "ep": "syntax", "fileexts": ["htm", "html"], "name": "html"}], "type": "plugins/supported", "description": "HTML syntax highlighter"}, "appconfig": {"resourceURL": "resources/appconfig/", "description": "Instantiates components and displays the GUI based on configuration.", "dependencies": {"jquery": "0.0.0", "canon": "0.0.0", "settings": "0.0.0"}, "testmodules": [], "provides": [{"description": "Event: Fired when the app is completely launched.", "ep": "extensionpoint", "name": "appLaunched"}], "type": "plugins/supported", "name": "appconfig"}, "keyboard": {"resourceURL": "resources/keyboard/", "description": "Keyboard shortcuts", "dependencies": {"canon": "0.0", "settings": "0.0"}, "testmodules": ["tests/testKeyboard"], "provides": [{"description": "A keymapping defines how keystrokes are interpreted.", "params": [{"required": true, "name": "states", "description": "Holds the states and all the informations about the keymapping. See docs: pluginguide/keymapping"}], "ep": "extensionpoint", "name": "keymapping"}], "type": "plugins/supported", "name": "keyboard"}, "js_syntax": {"resourceURL": "resources/js_syntax/", "name": "js_syntax", "environments": {"worker": true}, "dependencies": {"standard_syntax": "0.0.0"}, "testmodules": [], "provides": [{"pointer": "#JSSyntax", "ep": "syntax", "fileexts": ["js", "json"], "name": "js"}], "type": "plugins/supported", "description": "JavaScript syntax highlighter"}, "ctags": {"resourceURL": "resources/ctags/", "description": "Reads and writes tag files", "dependencies": {"traits": "0.0.0", "underscore": "0.0.0"}, "testmodules": [], "type": "plugins/supported", "name": "ctags"}, "standard_syntax": {"resourceURL": "resources/standard_syntax/", "description": "Easy-to-use basis for syntax engines", "environments": {"worker": true}, "dependencies": {"syntax_worker": "0.0.0", "syntax_directory": "0.0.0", "underscore": "0.0.0"}, "testmodules": [], "type": "plugins/supported", "name": "standard_syntax"}, "edit_session": {"resourceURL": "resources/edit_session/", "description": "Ties together the files being edited with the views on screen", "dependencies": {"events": "0.0.0"}, "testmodules": ["tests/testSession"], "provides": [{"action": "call", "pointer": "#createSession", "ep": "factory", "name": "session"}], "type": "plugins/supported", "name": "edit_session"}, "screen_theme": {"resourceURL": "resources/screen_theme/", "description": "Bespins standard theme basePlugin", "dependencies": {"theme_manager": "0.0.0"}, "testmodules": [], "provides": [{"url": ["theme.less"], "ep": "themestyles"}, {"defaultValue": "@global_font", "ep": "themevariable", "name": "container_font"}, {"defaultValue": "@global_font_size", "ep": "themevariable", "name": "container_font_size"}, {"defaultValue": "@global_container_background", "ep": "themevariable", "name": "container_bg"}, {"defaultValue": "@global_color", "ep": "themevariable", "name": "container_color"}, {"defaultValue": "@global_line_height", "ep": "themevariable", "name": "container_line_height"}, {"defaultValue": "@global_pane_background", "ep": "themevariable", "name": "pane_bg"}, {"defaultValue": "@global_pane_border_radius", "ep": "themevariable", "name": "pane_border_radius"}, {"defaultValue": "@global_form_font", "ep": "themevariable", "name": "form_font"}, {"defaultValue": "@global_form_font_size", "ep": "themevariable", "name": "form_font_size"}, {"defaultValue": "@global_form_line_height", "ep": "themevariable", "name": "form_line_height"}, {"defaultValue": "@global_form_color", "ep": "themevariable", "name": "form_color"}, {"defaultValue": "@global_form_text_shadow", "ep": "themevariable", "name": "form_text_shadow"}, {"defaultValue": "@global_pane_link_color", "ep": "themevariable", "name": "pane_a_color"}, {"defaultValue": "@global_font", "ep": "themevariable", "name": "pane_font"}, {"defaultValue": "@global_font_size", "ep": "themevariable", "name": "pane_font_size"}, {"defaultValue": "@global_pane_text_shadow", "ep": "themevariable", "name": "pane_text_shadow"}, {"defaultValue": "@global_pane_h1_font", "ep": "themevariable", "name": "pane_h1_font"}, {"defaultValue": "@global_pane_h1_font_size", "ep": "themevariable", "name": "pane_h1_font_size"}, {"defaultValue": "@global_pane_h1_color", "ep": "themevariable", "name": "pane_h1_color"}, {"defaultValue": "@global_font_size * 1.8", "ep": "themevariable", "name": "pane_line_height"}, {"defaultValue": "@global_pane_color", "ep": "themevariable", "name": "pane_color"}, {"defaultValue": "@global_text_shadow", "ep": "themevariable", "name": "pane_text_shadow"}, {"defaultValue": "@global_font", "ep": "themevariable", "name": "button_font"}, {"defaultValue": "@global_font_size", "ep": "themevariable", "name": "button_font_size"}, {"defaultValue": "@global_button_color", "ep": "themevariable", "name": "button_color"}, {"defaultValue": "@global_button_background", "ep": "themevariable", "name": "button_bg"}, {"defaultValue": "@button_bg - #063A27", "ep": "themevariable", "name": "button_bg2"}, {"defaultValue": "@button_bg - #194A5E", "ep": "themevariable", "name": "button_border"}, {"defaultValue": "@global_control_background", "ep": "themevariable", "name": "control_bg"}, {"defaultValue": "@global_control_color", "ep": "themevariable", "name": "control_color"}, {"defaultValue": "@global_control_border", "ep": "themevariable", "name": "control_border"}, {"defaultValue": "@global_control_border_radius", "ep": "themevariable", "name": "control_border_radius"}, {"defaultValue": "@global_control_active_background", "ep": "themevariable", "name": "control_active_bg"}, {"defaultValue": "@global_control_active_border", "ep": "themevariable", "name": "control_active_border"}, {"defaultValue": "@global_control_active_color", "ep": "themevariable", "name": "control_active_color"}, {"defaultValue": "@global_control_active_inset_color", "ep": "themevariable", "name": "control_active_inset_color"}], "type": "plugins/supported", "name": "screen_theme"}});;\n
});\n
})();\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
// This script appears at the end of BespinEmbeddedMain and is responsible\n
// for firing up Bespin on the page.\n
// This module depends only on Tiki.\n
\n
\n
(function() {\n
\n
var $ = bespin.tiki.require("jquery").$;\n
/**\n
 * Returns the CSS property of element.\n
 *   1) If the CSS property is on the style object of the element, use it, OR\n
 *   2) Compute the CSS property\n
 *\n
 * If the property can\'t get computed, is \'auto\' or \'intrinsic\', the former\n
 * calculated property is uesd (this can happen in cases where the textarea\n
 * is hidden and has no dimension styles).\n
 */\n
var getCSSProperty = function(element, container, property) {\n
    var ret = element.style[property]\n
                || document.defaultView.getComputedStyle(element, \'\').\n
                                        getPropertyValue(property);\n
\n
    if (!ret || ret == \'auto\' || ret == \'intrinsic\') {\n
        ret = container.style[property];\n
    }\n
    return ret;\n
};\n
\n
/**\n
 * Returns the sum of all passed property values. Calls internal getCSSProperty\n
 * to get the value of the individual peroperties.\n
  */\n
// var sumCSSProperties = function(element, container, props) {\n
//     var ret = document.defaultView.getComputedStyle(element, \'\').\n
//                                         getPropertyValue(props[0]);\n
//\n
//     if (!ret || ret == \'auto\' || ret == \'intrinsic\') {\n
//         return container.style[props[0]];\n
//     }\n
//\n
//     var sum = props.map(function(item) {\n
//         var cssProp = getCSSProperty(element, container, item);\n
//         // Remove the \'px; and parse the property to a floating point.\n
//         return parseFloat(cssProp.replace(\'px\', \'\'));\n
//     }).reduce(function(a, b) {\n
//         return a + b;\n
//     });\n
//\n
//     return sum;\n
// };\n
\n
bespin.useBespin = function(element, options) {\n
    var util = bespin.tiki.require(\'bespin:util/util\');\n
\n
    var baseConfig = {};\n
    var baseSettings = baseConfig.settings;\n
    options = options || {};\n
    for (var key in options) {\n
        baseConfig[key] = options[key];\n
    }\n
\n
    // we need to separately merge the configured settings\n
    var configSettings = baseConfig.settings;\n
    if (baseSettings !== undefined) {\n
        for (key in baseSettings) {\n
            if (configSettings[key] === undefined) {\n
                baseConfig.settings[key] = baseSettings[key];\n
            }\n
        }\n
    }\n
\n
    var Promise = bespin.tiki.require(\'bespin:promise\').Promise;\n
    var prEnv = null;\n
    var pr = new Promise();\n
\n
    bespin.tiki.require.ensurePackage("::appconfig", function() {\n
        var appconfig = bespin.tiki.require("appconfig");\n
        if (util.isString(element)) {\n
            element = document.getElementById(element);\n
        }\n
\n
        if (util.none(baseConfig.initialContent)) {\n
            baseConfig.initialContent = element.value || element.innerHTML;\n
        }\n
\n
        element.innerHTML = \'\';\n
\n
        if (element.type == \'textarea\') {\n
            var parentNode = element.parentNode;\n
            // This will hold the Bespin editor.\n
            var container = document.createElement(\'div\');\n
\n
            // To put Bespin in the place of the textarea, we have to copy a\n
            // few of the textarea\'s style attributes to the div container.\n
            //\n
            // The problem is, that the properties have to get computed (they\n
            // might be defined by a CSS file on the page - you can\'t access\n
            // such rules that apply to an element via elm.style). Computed\n
            // properties are converted to pixels although the dimension might\n
            // be given as percentage. When the window resizes, the dimensions\n
            // defined by percentages changes, so the properties have to get\n
            // recomputed to get the new/true pixels.\n
            var resizeEvent = function() {\n
                var style = \'position:relative;\';\n
                [\n
                    \'margin-top\', \'margin-left\', \'margin-right\', \'margin-bottom\'\n
                ].forEach(function(item) {\n
                    style += item + \':\' +\n
                                getCSSProperty(element, container, item) + \';\';\n
                });\n
\n
                // Calculating the width/height of the textarea is somewhat\n
                // tricky. To do it right, you have to include the paddings\n
                // to the sides as well (eg. width = width + padding-left, -right).\n
                // This works well, as long as the width of the element is not\n
                // set or given in pixels. In this case and after the textarea\n
                // is hidden, getCSSProperty(element, container, \'width\') will\n
                // still return pixel value. If the element has realtiv dimensions\n
                // (e.g. width=\'95<percent>\') getCSSProperty(...) will return pixel values\n
                // only as long as the textarea is visible. After it is hidden\n
                // getCSSProperty will return the relativ dimensions as they\n
                // are set on the element (in the case of width, 95<percent>).\n
                // Making the sum of pixel vaules (e.g. padding) and realtive\n
                // values (e.g. <percent>) is not possible. As such the padding styles\n
                // are ignored.\n
\n
                // The complete width is the width of the textarea + the padding\n
                // to the left and right.\n
                // var width = sumCSSProperties(element, container, [\n
                //     \'width\', \'padding-left\', \'padding-right\'\n
                // ]) + \'px\';\n
                // var height = sumCSSProperties(element, container, [\n
                //     \'height\', \'padding-top\', \'padding-bottom\'\n
                // ]) + \'px\';\n
                var width = getCSSProperty(element, container, \'width\');\n
                var height = getCSSProperty(element, container, \'height\');\n
                style += \'height:\' + height + \';width:\' + width + \';\';\n
\n
                // Set the display property to \'inline-block\'.\n
                style += \'display:inline-block;\';\n
                container.setAttribute(\'style\', style);\n
            };\n
            window.addEventListener(\'resize\', resizeEvent, false);\n
\n
            // Call the resizeEvent once, so that the size of the container is\n
            // calculated.\n
            resizeEvent();\n
\n
            // Insert the div container after the element.\n
            if (element.nextSibling) {\n
                parentNode.insertBefore(container, element.nextSibling);\n
            } else {\n
                parentNode.appendChild(container);\n
            }\n
\n
            // Override the forms onsubmit function. Set the innerHTML and value\n
            // of the textarea before submitting.\n
            while (parentNode !== document) {\n
                if (parentNode.tagName.toUpperCase() === \'FORM\') {\n
                    var oldSumit = parentNode.onsubmit;\n
                    // Override the onsubmit function of the form.\n
                    parentNode.onsubmit = function(evt) {\n
                        element.value = prEnv.editor.value;\n
                        element.innerHTML = prEnv.editor.value;\n
                        // If there is a onsubmit function already, then call\n
                        // it with the current context and pass the event.\n
                        if (oldSumit) {\n
                            oldSumit.call(this, evt);\n
                        }\n
                    }\n
                    break;\n
                }\n
                parentNode = parentNode.parentNode;\n
            }\n
\n
            // Hide the element.\n
            element.style.display = \'none\';\n
\n
            // The div container is the new element that is passed to appconfig.\n
            baseConfig.element = container;\n
\n
            // Check if the textarea has the \'readonly\' flag and set it\n
            // on the config object so that the editor is readonly.\n
            if (!util.none(element.getAttribute(\'readonly\'))) {\n
                baseConfig.readOnly = true;\n
            }\n
        } else {\n
            baseConfig.element = element;\n
        }\n
\n
        appconfig.launch(baseConfig).then(function(env) {\n
            prEnv = env;\n
            pr.resolve(env);\n
        });\n
    });\n
\n
    return pr;\n
};\n
\n
$(document).ready(function() {\n
    // Holds the lauch promises of all launched Bespins.\n
    var launchBespinPromises = [];\n
\n
    var nodes = document.querySelectorAll(".bespin");\n
    for (var i = 0; i < nodes.length; i++) {\n
        var node = nodes[i];\n
        var options = node.getAttribute(\'data-bespinoptions\') || \'{}\';\n
        var pr = bespin.useBespin(node, JSON.parse(options));\n
        pr.then(function(env) {\n
            node.bespin = env;\n
        }, function(error) {\n
            throw new Error(\'Launch failed: \' + error);\n
        });\n
        launchBespinPromises.push(pr);\n
    }\n
\n
    // If users want a custom startup\n
    if (window.onBespinLoad) {\n
        // group-promise function.\n
        var group = bespin.tiki.require("bespin:promise").group;\n
\n
        // Call the window.onBespinLoad() function after all launched Bespins\n
        // are ready or throw an error otherwise.\n
        group(launchBespinPromises).then(function() {\n
            window.onBespinLoad();\n
        }, function() {\n
            throw new Error(\'At least one Bespin failed to launch!\');\n
        });\n
    }\n
});\n
\n
})();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
