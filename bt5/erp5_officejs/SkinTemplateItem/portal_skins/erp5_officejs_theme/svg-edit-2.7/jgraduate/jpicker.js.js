<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts40515059.52</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jpicker.js</string> </value>
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
            <value> <int>100055</int> </value>
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
 * jPicker 1.1.6\n
 *\n
 * jQuery Plugin for Photoshop style color picker\n
 *\n
 * Copyright (c) 2010 Christopher T. Tillman\n
 * Digital Magic Productions, Inc. (http://www.digitalmagicpro.com/)\n
 * MIT style license, FREE to use, alter, copy, sell, and especially ENHANCE\n
 *\n
 * Painstakingly ported from John Dyers\' excellent work on his own color picker based on the Prototype framework.\n
 *\n
 * John Dyers\' website: (http://johndyer.name)\n
 * Color Picker page:   (http://johndyer.name/post/2007/09/PhotoShop-like-JavaScript-Color-Picker.aspx)\n
 *\n
 */\n
(function($, version)\n
{\n
  Math.precision = function(value, precision)\n
    {\n
      if (precision === undefined) precision = 0;\n
      return Math.round(value * Math.pow(10, precision)) / Math.pow(10, precision);\n
    };\n
  var Slider = // encapsulate slider functionality for the ColorMap and ColorBar - could be useful to use a jQuery UI draggable for this with certain extensions\n
      function(bar, options)\n
      {\n
        var $this = this, // private properties, methods, and events - keep these variables and classes invisible to outside code\n
          arrow = bar.find(\'img:first\'), // the arrow image to drag\n
          minX = 0,\n
          maxX = 100,\n
          rangeX = 100,\n
          minY = 0,\n
          maxY = 100,\n
          rangeY = 100,\n
          x = 0,\n
          y = 0,\n
          offset,\n
          timeout,\n
          changeEvents = new Array(),\n
          fireChangeEvents =\n
            function(context)\n
            {\n
              for (var i = 0; i < changeEvents.length; i++) changeEvents[i].call($this, $this, context);\n
            },\n
          mouseDown = // bind the mousedown to the bar not the arrow for quick snapping to the clicked location\n
            function(e)\n
            {\n
              var off = bar.offset();\n
              offset = { l: off.left | 0, t: off.top | 0 };\n
              clearTimeout(timeout);\n
              timeout = setTimeout( // using setTimeout for visual updates - once the style is updated the browser will re-render internally allowing the next Javascript to run\n
                function()\n
                {\n
                  setValuesFromMousePosition.call($this, e);\n
                }, 0);\n
              // Bind mousemove and mouseup event to the document so it responds when dragged of of the bar - we will unbind these when on mouseup to save processing\n
              $(document).bind(\'mousemove\', mouseMove).bind(\'mouseup\', mouseUp);\n
              e.preventDefault(); // don\'t try to select anything or drag the image to the desktop\n
            },\n
          mouseMove = // set the values as the mouse moves\n
            function(e)\n
            {\n
              clearTimeout(timeout);\n
              timeout = setTimeout(\n
                function()\n
                {\n
                  setValuesFromMousePosition.call($this, e);\n
                }, 0);\n
              e.stopPropagation();\n
              e.preventDefault();\n
              return false;\n
            },\n
          mouseUp = // unbind the document events - they aren\'t needed when not dragging\n
            function(e)\n
            {\n
              $(document).unbind(\'mouseup\', mouseUp).unbind(\'mousemove\', mouseMove);\n
              e.stopPropagation();\n
              e.preventDefault();\n
              return false;\n
            },\n
          setValuesFromMousePosition = // calculate mouse position and set value within the current range\n
            function(e)\n
            {\n
              var locX = e.pageX - offset.l,\n
                  locY = e.pageY - offset.t,\n
                  barW = bar.w, // local copies for YUI compressor\n
                  barH = bar.h;\n
              // keep the arrow within the bounds of the bar\n
              if (locX < 0) locX = 0;\n
              else if (locX > barW) locX = barW;\n
              if (locY < 0) locY = 0;\n
              else if (locY > barH) locY = barH;\n
              val.call($this, \'xy\', { x: ((locX / barW) * rangeX) + minX, y: ((locY / barH) * rangeY) + minY });\n
            },\n
          draw =\n
            function()\n
            {\n
              var arrowOffsetX = 0,\n
                arrowOffsetY = 0,\n
                barW = bar.w,\n
                barH = bar.h,\n
                arrowW = arrow.w,\n
                arrowH = arrow.h;\n
              setTimeout(\n
                function()\n
                {\n
                  if (rangeX > 0) // range is greater than zero\n
                  {\n
                    // constrain to bounds\n
                    if (x == maxX) arrowOffsetX = barW;\n
                    else arrowOffsetX = ((x / rangeX) * barW) | 0;\n
                  }\n
                  if (rangeY > 0) // range is greater than zero\n
                  {\n
                    // constrain to bounds\n
                    if (y == maxY) arrowOffsetY = barH;\n
                    else arrowOffsetY = ((y / rangeY) * barH) | 0;\n
                  }\n
                  // if arrow width is greater than bar width, center arrow and prevent horizontal dragging\n
                  if (arrowW >= barW) arrowOffsetX = (barW >> 1) - (arrowW >> 1); // number >> 1 - superfast bitwise divide by two and truncate (move bits over one bit discarding lowest)\n
                  else arrowOffsetX -= arrowW >> 1;\n
                  // if arrow height is greater than bar height, center arrow and prevent vertical dragging\n
                  if (arrowH >= barH) arrowOffsetY = (barH >> 1) - (arrowH >> 1);\n
                  else arrowOffsetY -= arrowH >> 1;\n
                  // set the arrow position based on these offsets\n
                  arrow.css({ left: arrowOffsetX + \'px\', top: arrowOffsetY + \'px\' });\n
                }, 0);\n
            },\n
          val =\n
            function(name, value, context)\n
            {\n
              var set = value !== undefined;\n
              if (!set)\n
              {\n
                if (name === undefined || name == null) name = \'xy\';\n
                switch (name.toLowerCase())\n
                {\n
                  case \'x\': return x;\n
                  case \'y\': return y;\n
                  case \'xy\':\n
                  default: return { x: x, y: y };\n
                }\n
              }\n
              if (context != null && context == $this) return;\n
              var changed = false,\n
                  newX,\n
                  newY;\n
              if (name == null) name = \'xy\';\n
              switch (name.toLowerCase())\n
              {\n
                case \'x\':\n
                  newX = value && (value.x && value.x | 0 || value | 0) || 0;\n
                  break;\n
                case \'y\':\n
                  newY = value && (value.y && value.y | 0 || value | 0) || 0;\n
                  break;\n
                case \'xy\':\n
                default:\n
                  newX = value && value.x && value.x | 0 || 0;\n
                  newY = value && value.y && value.y | 0 || 0;\n
                  break;\n
              }\n
              if (newX != null)\n
              {\n
                if (newX < minX) newX = minX;\n
                else if (newX > maxX) newX = maxX;\n
                if (x != newX)\n
                {\n
                  x = newX;\n
                  changed = true;\n
                }\n
              }\n
              if (newY != null)\n
              {\n
                if (newY < minY) newY = minY;\n
                else if (newY > maxY) newY = maxY;\n
                if (y != newY)\n
                {\n
                  y = newY;\n
                  changed = true;\n
                }\n
              }\n
              changed && fireChangeEvents.call($this, context || $this);\n
            },\n
          range =\n
            function (name, value)\n
            {\n
              var set = value !== undefined;\n
              if (!set)\n
              {\n
                if (name === undefined || name == null) name = \'all\';\n
                switch (name.toLowerCase())\n
                {\n
                  case \'minx\': return minX;\n
                  case \'maxx\': return maxX;\n
                  case \'rangex\': return { minX: minX, maxX: maxX, rangeX: rangeX };\n
                  case \'miny\': return minY;\n
                  case \'maxy\': return maxY;\n
                  case \'rangey\': return { minY: minY, maxY: maxY, rangeY: rangeY };\n
                  case \'all\':\n
                  default: return { minX: minX, maxX: maxX, rangeX: rangeX, minY: minY, maxY: maxY, rangeY: rangeY };\n
                }\n
              }\n
              var changed = false,\n
                  newMinX,\n
                  newMaxX,\n
                  newMinY,\n
                  newMaxY;\n
              if (name == null) name = \'all\';\n
              switch (name.toLowerCase())\n
              {\n
                case \'minx\':\n
                  newMinX = value && (value.minX && value.minX | 0 || value | 0) || 0;\n
                  break;\n
                case \'maxx\':\n
                  newMaxX = value && (value.maxX && value.maxX | 0 || value | 0) || 0;\n
                  break;\n
                case \'rangex\':\n
                  newMinX = value && value.minX && value.minX | 0 || 0;\n
                  newMaxX = value && value.maxX && value.maxX | 0 || 0;\n
                  break;\n
                case \'miny\':\n
                  newMinY = value && (value.minY && value.minY | 0 || value | 0) || 0;\n
                  break;\n
                case \'maxy\':\n
                  newMaxY = value && (value.maxY && value.maxY | 0 || value | 0) || 0;\n
                  break;\n
                case \'rangey\':\n
                  newMinY = value && value.minY && value.minY | 0 || 0;\n
                  newMaxY = value && value.maxY && value.maxY | 0 || 0;\n
                  break;\n
                case \'all\':\n
                default:\n
                  newMinX = value && value.minX && value.minX | 0 || 0;\n
                  newMaxX = value && value.maxX && value.maxX | 0 || 0;\n
                  newMinY = value && value.minY && value.minY | 0 || 0;\n
                  newMaxY = value && value.maxY && value.maxY | 0 || 0;\n
                  break;\n
              }\n
              if (newMinX != null && minX != newMinX)\n
              {\n
                minX = newMinX;\n
                rangeX = maxX - minX;\n
              }\n
              if (newMaxX != null && maxX != newMaxX)\n
              {\n
                maxX = newMaxX;\n
                rangeX = maxX - minX;\n
              }\n
              if (newMinY != null && minY != newMinY)\n
              {\n
                minY = newMinY;\n
                rangeY = maxY - minY;\n
              }\n
              if (newMaxY != null && maxY != newMaxY)\n
              {\n
                maxY = newMaxY;\n
                rangeY = maxY - minY;\n
              }\n
            },\n
          bind =\n
            function (callback)\n
            {\n
              if ($.isFunction(callback)) changeEvents.push(callback);\n
            },\n
          unbind =\n
            function (callback)\n
            {\n
              if (!$.isFunction(callback)) return;\n
              var i;\n
              while ((i = $.inArray(callback, changeEvents)) != -1) changeEvents.splice(i, 1);\n
            },\n
          destroy =\n
            function()\n
            {\n
              // unbind all possible events and null objects\n
              $(document).unbind(\'mouseup\', mouseUp).unbind(\'mousemove\', mouseMove);\n
              bar.unbind(\'mousedown\', mouseDown);\n
              bar = null;\n
              arrow = null;\n
              changeEvents = null;\n
            };\n
        $.extend(true, $this, // public properties, methods, and event bindings - these we need to access from other controls\n
          {\n
            val: val,\n
            range: range,\n
            bind: bind,\n
            unbind: unbind,\n
            destroy: destroy\n
          });\n
        // initialize this control\n
        arrow.src = options.arrow && options.arrow.image;\n
        arrow.w = options.arrow && options.arrow.width || arrow.width();\n
        arrow.h = options.arrow && options.arrow.height || arrow.height();\n
        bar.w = options.map && options.map.width || bar.width();\n
        bar.h = options.map && options.map.height || bar.height();\n
        // bind mousedown event\n
        bar.bind(\'mousedown\', mouseDown);\n
        bind.call($this, draw);\n
      },\n
    ColorValuePicker = // controls for all the input elements for the typing in color values\n
      function(picker, color, bindedHex, alphaPrecision)\n
      {\n
        var $this = this, // private properties and methods\n
          inputs = picker.find(\'td.Text input\'),\n
          red = inputs.eq(3),\n
          green = inputs.eq(4),\n
          blue = inputs.eq(5),\n
          alpha = inputs.length > 7 ? inputs.eq(6) : null,\n
          hue = inputs.eq(0),\n
          saturation = inputs.eq(1),\n
          value = inputs.eq(2),\n
          hex = inputs.eq(inputs.length > 7 ? 7 : 6),\n
          ahex = inputs.length > 7 ? inputs.eq(8) : null,\n
          keyDown = // input box key down - use arrows to alter color\n
            function(e)\n
            {\n
              if (e.target.value == \'\' && e.target != hex.get(0) && (bindedHex != null && e.target != bindedHex.get(0) || bindedHex == null)) return;\n
              if (!validateKey(e)) return e;\n
              switch (e.target)\n
              {\n
                case red.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      red.val(setValueInRange.call($this, (red.val() << 0) + 1, 0, 255));\n
                      color.val(\'r\', red.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      red.val(setValueInRange.call($this, (red.val() << 0) - 1, 0, 255));\n
                      color.val(\'r\', red.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case green.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      green.val(setValueInRange.call($this, (green.val() << 0) + 1, 0, 255));\n
                      color.val(\'g\', green.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      green.val(setValueInRange.call($this, (green.val() << 0) - 1, 0, 255));\n
                      color.val(\'g\', green.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case blue.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      blue.val(setValueInRange.call($this, (blue.val() << 0) + 1, 0, 255));\n
                      color.val(\'b\', blue.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      blue.val(setValueInRange.call($this, (blue.val() << 0) - 1, 0, 255));\n
                      color.val(\'b\', blue.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case alpha && alpha.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      alpha.val(setValueInRange.call($this, parseFloat(alpha.val()) + 1, 0, 100));\n
                      color.val(\'a\', Math.precision((alpha.val() * 255) / 100, alphaPrecision), e.target);\n
                      return false;\n
                    case 40:\n
                      alpha.val(setValueInRange.call($this, parseFloat(alpha.val()) - 1, 0, 100));\n
                      color.val(\'a\', Math.precision((alpha.val() * 255) / 100, alphaPrecision), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case hue.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      hue.val(setValueInRange.call($this, (hue.val() << 0) + 1, 0, 360));\n
                      color.val(\'h\', hue.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      hue.val(setValueInRange.call($this, (hue.val() << 0) - 1, 0, 360));\n
                      color.val(\'h\', hue.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case saturation.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      saturation.val(setValueInRange.call($this, (saturation.val() << 0) + 1, 0, 100));\n
                      color.val(\'s\', saturation.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      saturation.val(setValueInRange.call($this, (saturation.val() << 0) - 1, 0, 100));\n
                      color.val(\'s\', saturation.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
                case value.get(0):\n
                  switch (e.keyCode)\n
                  {\n
                    case 38:\n
                      value.val(setValueInRange.call($this, (value.val() << 0) + 1, 0, 100));\n
                      color.val(\'v\', value.val(), e.target);\n
                      return false;\n
                    case 40:\n
                      value.val(setValueInRange.call($this, (value.val() << 0) - 1, 0, 100));\n
                      color.val(\'v\', value.val(), e.target);\n
                      return false;\n
                  }\n
                  break;\n
              }\n
            },\n
          keyUp = // input box key up - validate value and set color\n
            function(e)\n
            {\n
              if (e.target.value == \'\' && e.target != hex.get(0) && (bindedHex != null && e.target != bindedHex.get(0) || bindedHex == null)) return;\n
              if (!validateKey(e)) return e;\n
              switch (e.target)\n
              {\n
                case red.get(0):\n
                  red.val(setValueInRange.call($this, red.val(), 0, 255));\n
                  color.val(\'r\', red.val(), e.target);\n
                  break;\n
                case green.get(0):\n
                  green.val(setValueInRange.call($this, green.val(), 0, 255));\n
                  color.val(\'g\', green.val(), e.target);\n
                  break;\n
                case blue.get(0):\n
                  blue.val(setValueInRange.call($this, blue.val(), 0, 255));\n
                  color.val(\'b\', blue.val(), e.target);\n
                  break;\n
                case alpha && alpha.get(0):\n
                  alpha.val(setValueInRange.call($this, alpha.val(), 0, 100));\n
                  color.val(\'a\', Math.precision((alpha.val() * 255) / 100, alphaPrecision), e.target);\n
                  break;\n
                case hue.get(0):\n
                  hue.val(setValueInRange.call($this, hue.val(), 0, 360));\n
                  color.val(\'h\', hue.val(), e.target);\n
                  break;\n
                case saturation.get(0):\n
                  saturation.val(setValueInRange.call($this, saturation.val(), 0, 100));\n
                  color.val(\'s\', saturation.val(), e.target);\n
                  break;\n
                case value.get(0):\n
                  value.val(setValueInRange.call($this, value.val(), 0, 100));\n
                  color.val(\'v\', value.val(), e.target);\n
                  break;\n
                case hex.get(0):\n
                  hex.val(hex.val().replace(/[^a-fA-F0-9]/g, \'\').toLowerCase().substring(0, 6));\n
                  bindedHex && bindedHex.val(hex.val());\n
                  color.val(\'hex\', hex.val() != \'\' ? hex.val() : null, e.target);\n
                  break;\n
                case bindedHex && bindedHex.get(0):\n
                  bindedHex.val(bindedHex.val().replace(/[^a-fA-F0-9]/g, \'\').toLowerCase().substring(0, 6));\n
                  hex.val(bindedHex.val());\n
                  color.val(\'hex\', bindedHex.val() != \'\' ? bindedHex.val() : null, e.target);\n
                  break;\n
                case ahex && ahex.get(0):\n
                  ahex.val(ahex.val().replace(/[^a-fA-F0-9]/g, \'\').toLowerCase().substring(0, 2));\n
                  color.val(\'a\', ahex.val() != null ? parseInt(ahex.val(), 16) : null, e.target);\n
                  break;\n
              }\n
            },\n
          blur = // input box blur - reset to original if value empty\n
            function(e)\n
            {\n
              if (color.val() != null)\n
              {\n
                switch (e.target)\n
                {\n
                  case red.get(0): red.val(color.val(\'r\')); break;\n
                  case green.get(0): green.val(color.val(\'g\')); break;\n
                  case blue.get(0): blue.val(color.val(\'b\')); break;\n
                  case alpha && alpha.get(0): alpha.val(Math.precision((color.val(\'a\') * 100) / 255, alphaPrecision)); break;\n
                  case hue.get(0): hue.val(color.val(\'h\')); break;\n
                  case saturation.get(0): saturation.val(color.val(\'s\')); break;\n
                  case value.get(0): value.val(color.val(\'v\')); break;\n
                  case hex.get(0):\n
                  case bindedHex && bindedHex.get(0):\n
                    hex.val(color.val(\'hex\'));\n
                    bindedHex && bindedHex.val(color.val(\'hex\'));\n
                    break;\n
                  case ahex && ahex.get(0): ahex.val(color.val(\'ahex\').substring(6)); break;\n
                }\n
              }\n
            },\n
          validateKey = // validate key\n
            function(e)\n
            {\n
              switch(e.keyCode)\n
              {\n
                case 9:\n
                case 16:\n
                case 29:\n
                case 37:\n
                case 39:\n
                  return false;\n
                case \'c\'.charCodeAt():\n
                case \'v\'.charCodeAt():\n
                  if (e.ctrlKey) return false;\n
              }\n
              return true;\n
            },\n
          setValueInRange = // constrain value within range\n
            function(value, min, max)\n
            {\n
              if (value == \'\' || isNaN(value)) return min;\n
              if (value > max) return max;\n
              if (value < min) return min;\n
              return value;\n
            },\n
          colorChanged =\n
            function(ui, context)\n
            {\n
              var all = ui.val(\'all\');\n
              if (context != red.get(0)) red.val(all != null ? all.r : \'\');\n
              if (context != green.get(0)) green.val(all != null ? all.g : \'\');\n
              if (context != blue.get(0)) blue.val(all != null ? all.b : \'\');\n
              if (alpha && context != alpha.get(0)) alpha.val(all != null ? Math.precision((all.a * 100) / 255, alphaPrecision) : \'\');\n
              if (context != hue.get(0)) hue.val(all != null ? all.h : \'\');\n
              if (context != saturation.get(0)) saturation.val(all != null ? all.s : \'\');\n
              if (context != value.get(0)) value.val(all != null ? all.v : \'\');\n
              if (context != hex.get(0) && (bindedHex && context != bindedHex.get(0) || !bindedHex)) hex.val(all != null ? all.hex : \'\');\n
              if (bindedHex && context != bindedHex.get(0) && context != hex.get(0)) bindedHex.val(all != null ? all.hex : \'\');\n
              if (ahex && context != ahex.get(0)) ahex.val(all != null ? all.ahex.substring(6) : \'\');\n
            },\n
          destroy =\n
            function()\n
            {\n
              // unbind all events and null objects\n
              red.add(green).add(blue).add(alpha).add(hue).add(saturation).add(value).add(hex).add(bindedHex).add(ahex).unbind(\'keyup\', keyUp).unbind(\'blur\', blur);\n
              red.add(green).add(blue).add(alpha).add(hue).add(saturation).add(value).unbind(\'keydown\', keyDown);\n
              color.unbind(colorChanged);\n
              red = null;\n
              green = null;\n
              blue = null;\n
              alpha = null;\n
              hue = null;\n
              saturation = null;\n
              value = null;\n
              hex = null;\n
              ahex = null;\n
            };\n
        $.extend(true, $this, // public properties and methods\n
          {\n
            destroy: destroy\n
          });\n
        red.add(green).add(blue).add(alpha).add(hue).add(saturation).add(value).add(hex).add(bindedHex).add(ahex).bind(\'keyup\', keyUp).bind(\'blur\', blur);\n
        red.add(green).add(blue).add(alpha).add(hue).add(saturation).add(value).bind(\'keydown\', keyDown);\n
        color.bind(colorChanged);\n
      };\n
  $.jPicker =\n
    {\n
      List: [], // array holding references to each active instance of the control\n
      Color: // color object - we will be able to assign by any color space type or retrieve any color space info\n
             // we want this public so we can optionally assign new color objects to initial values using inputs other than a string hex value (also supported)\n
        function(init)\n
        {\n
          var $this = this,\n
            r,\n
            g,\n
            b,\n
            a,\n
            h,\n
            s,\n
            v,\n
            changeEvents = new Array(),\n
            fireChangeEvents = \n
              function(context)\n
              {\n
                for (var i = 0; i < changeEvents.length; i++) changeEvents[i].call($this, $this, context);\n
              },\n
            val =\n
              function(name, value, context)\n
              {\n
                // Kind of ugly\n
                var set = Boolean(value);\n
                if (set && value.ahex === "") value.ahex = "00000000";\n
                if (!set)\n
                {\n
                  if (name === undefined || name == null || name == \'\') name = \'all\';\n
                  if (r == null) return null;\n
                  switch (name.toLowerCase())\n
                  {\n
                    case \'ahex\': return ColorMethods.rgbaToHex({ r: r, g: g, b: b, a: a });\n
                    case \'hex\': return val(\'ahex\').substring(0, 6);\n
                    case \'all\': return { r: r, g: g, b: b, a: a, h: h, s: s, v: v, hex: val.call($this, \'hex\'), ahex: val.call($this, \'ahex\') };\n
                    default:\n
                      var ret={};\n
                      for (var i = 0; i < name.length; i++)\n
                      {\n
                        switch (name.charAt(i))\n
                        {\n
                          case \'r\':\n
                            if (name.length == 1) ret = r;\n
                            else ret.r = r;\n
                            break;\n
                          case \'g\':\n
                            if (name.length == 1) ret = g;\n
                            else ret.g = g;\n
                            break;\n
                          case \'b\':\n
                            if (name.length == 1) ret = b;\n
                            else ret.b = b;\n
                            break;\n
                          case \'a\':\n
                            if (name.length == 1) ret = a;\n
                            else ret.a = a;\n
                            break;\n
                          case \'h\':\n
                            if (name.length == 1) ret = h;\n
                            else ret.h = h;\n
                            break;\n
                          case \'s\':\n
                            if (name.length == 1) ret = s;\n
                            else ret.s = s;\n
                            break;\n
                          case \'v\':\n
                            if (name.length == 1) ret = v;\n
                            else ret.v = v;\n
                            break;\n
                        }\n
                      }\n
                      return ret == {} ? val.call($this, \'all\') : ret;\n
                      break;\n
                  }\n
                }\n
                if (context != null && context == $this) return;\n
                var changed = false;\n
                if (name == null) name = \'\';\n
                if (value == null)\n
                {\n
                  if (r != null)\n
                  {\n
                    r = null;\n
                    changed = true;\n
                  }\n
                  if (g != null)\n
                  {\n
                    g = null;\n
                    changed = true;\n
                  }\n
                  if (b != null)\n
                  {\n
                    b = null;\n
                    changed = true;\n
                  }\n
                  if (a != null)\n
                  {\n
                    a = null;\n
                    changed = true;\n
                  }\n
                  if (h != null)\n
                  {\n
                    h = null;\n
                    changed = true;\n
                  }\n
                  if (s != null)\n
                  {\n
                    s = null;\n
                    changed = true;\n
                  }\n
                  if (v != null)\n
                  {\n
                    v = null;\n
                    changed = true;\n
                  }\n
                  changed && fireChangeEvents.call($this, context || $this);\n
                  return;\n
                }\n
                switch (name.toLowerCase())\n
                {\n
                  case \'ahex\':\n
                  case \'hex\':\n
                    var ret = ColorMethods.hexToRgba(value && (value.ahex || value.hex) || value || \'none\');\n
\n
                    val.call($this, \'rgba\', { r: ret.r, g: ret.g, b: ret.b, a: name == \'ahex\' ? ret.a : a != null ? a : 255 }, context);\n
                    break;\n
                  default:\n
                    if (value && (value.ahex != null || value.hex != null))\n
                    {\n
                      val.call($this, \'ahex\', value.ahex || value.hex || \'00000000\', context);\n
                      return;\n
                    }\n
                    var newV = {}, rgb = false, hsv = false;\n
                    if (value.r !== undefined && !name.indexOf(\'r\') == -1) name += \'r\';\n
                    if (value.g !== undefined && !name.indexOf(\'g\') == -1) name += \'g\';\n
                    if (value.b !== undefined && !name.indexOf(\'b\') == -1) name += \'b\';\n
                    if (value.a !== undefined && !name.indexOf(\'a\') == -1) name += \'a\';\n
                    if (value.h !== undefined && !name.indexOf(\'h\') == -1) name += \'h\';\n
                    if (value.s !== undefined && !name.indexOf(\'s\') == -1) name += \'s\';\n
                    if (value.v !== undefined && !name.indexOf(\'v\') == -1) name += \'v\';\n
                    for (var i = 0; i < name.length; i++)\n
                    {\n
                      switch (name.charAt(i))\n
                      {\n
                        case \'r\':\n
                          if (hsv) continue;\n
                          rgb = true;\n
                          newV.r = value && value.r && value.r | 0 || value && value | 0 || 0;\n
                          if (newV.r < 0) newV.r = 0;\n
                          else if (newV.r > 255) newV.r = 255;\n
                          if (r != newV.r)\n
                          {\n
                            r = newV.r;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'g\':\n
                          if (hsv) continue;\n
                          rgb = true;\n
                          newV.g = value && value.g && value.g | 0 || value && value | 0 || 0;\n
                          if (newV.g < 0) newV.g = 0;\n
                          else if (newV.g > 255) newV.g = 255;\n
                          if (g != newV.g)\n
                          {\n
                            g = newV.g;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'b\':\n
                          if (hsv) continue;\n
                          rgb = true;\n
                          newV.b = value && value.b && value.b | 0 || value && value | 0 || 0;\n
                          if (newV.b < 0) newV.b = 0;\n
                          else if (newV.b > 255) newV.b = 255;\n
                          if (b != newV.b)\n
                          {\n
                            b = newV.b;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'a\':\n
                          newV.a = value && value.a != null ? value.a | 0 : value != null ? value | 0 : 255;\n
                          if (newV.a < 0) newV.a = 0;\n
                          else if (newV.a > 255) newV.a = 255;\n
                          if (a != newV.a)\n
                          {\n
                            a = newV.a;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'h\':\n
                          if (rgb) continue;\n
                          hsv = true;\n
                          newV.h = value && value.h && value.h | 0 || value && value | 0 || 0;\n
                          if (newV.h < 0) newV.h = 0;\n
                          else if (newV.h > 360) newV.h = 360;\n
                          if (h != newV.h)\n
                          {\n
                            h = newV.h;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'s\':\n
                          if (rgb) continue;\n
                          hsv = true;\n
                          newV.s = value && value.s != null ? value.s | 0 : value != null ? value | 0 : 100;\n
                          if (newV.s < 0) newV.s = 0;\n
                          else if (newV.s > 100) newV.s = 100;\n
                          if (s != newV.s)\n
                          {\n
                            s = newV.s;\n
                            changed = true;\n
                          }\n
                          break;\n
                        case \'v\':\n
                          if (rgb) continue;\n
                          hsv = true;\n
                          newV.v = value && value.v != null ? value.v | 0 : value != null ? value | 0 : 100;\n
                          if (newV.v < 0) newV.v = 0;\n
                          else if (newV.v > 100) newV.v = 100;\n
                          if (v != newV.v)\n
                          {\n
                            v = newV.v;\n
                            changed = true;\n
                          }\n
                          break;\n
                      }\n
                    }\n
                    if (changed)\n
                    {\n
                      if (rgb)\n
                      {\n
                        r = r || 0;\n
                        g = g || 0;\n
                        b = b || 0;\n
                        var ret = ColorMethods.rgbToHsv({ r: r, g: g, b: b });\n
                        h = ret.h;\n
                        s = ret.s;\n
                        v = ret.v;\n
                      }\n
                      else if (hsv)\n
                      {\n
                        h = h || 0;\n
                        s = s != null ? s : 100;\n
                        v = v != null ? v : 100;\n
                        var ret = ColorMethods.hsvToRgb({ h: h, s: s, v: v });\n
                        r = ret.r;\n
                        g = ret.g;\n
                        b = ret.b;\n
                      }\n
                      a = a != null ? a : 255;\n
                      fireChangeEvents.call($this, context || $this);\n
                    }\n
                    break;\n
                }\n
              },\n
            bind =\n
              function(callback)\n
              {\n
                if ($.isFunction(callback)) changeEvents.push(callback);\n
              },\n
            unbind =\n
              function(callback)\n
              {\n
                if (!$.isFunction(callback)) return;\n
                var i;\n
                while ((i = $.inArray(callback, changeEvents)) != -1) changeEvents.splice(i, 1);\n
              },\n
            destroy =\n
              function()\n
              {\n
                changeEvents = null;\n
              }\n
          $.extend(true, $this, // public properties and methods\n
            {\n
              val: val,\n
              bind: bind,\n
              unbind: unbind,\n
              destroy: destroy\n
            });\n
          if (init)\n
          {\n
            if (init.ahex != null) val(\'ahex\', init);\n
            else if (init.hex != null) val((init.a != null ? \'a\' : \'\') + \'hex\', init.a != null ? { ahex: init.hex + ColorMethods.intToHex(init.a) } : init);\n
            else if (init.r != null && init.g != null && init.b != null) val(\'rgb\' + (init.a != null ? \'a\' : \'\'), init);\n
            else if (init.h != null && init.s != null && init.v != null) val(\'hsv\' + (init.a != null ? \'a\' : \'\'), init);\n
          }\n
        },\n
      ColorMethods: // color conversion methods  - make public to give use to external scripts\n
        {\n
          hexToRgba:\n
            function(hex)\n
            {\n
              if (hex === \'\' || hex === \'none\') return { r: null, g: null, b: null, a: null };\n
              hex = this.validateHex(hex);\n
              var r = \'00\', g = \'00\', b = \'00\', a = \'255\';\n
              if (hex.length == 6) hex += \'ff\';\n
              if (hex.length > 6)\n
              {\n
                r = hex.substring(0, 2);\n
                g = hex.substring(2, 4);\n
                b = hex.substring(4, 6);\n
                a = hex.substring(6, hex.length);\n
              }\n
              else\n
              {\n
                if (hex.length > 4)\n
                {\n
                  r = hex.substring(4, hex.length);\n
                  hex = hex.substring(0, 4);\n
                }\n
                if (hex.length > 2)\n
                {\n
                  g = hex.substring(2, hex.length);\n
                  hex = hex.substring(0, 2);\n
                }\n
                if (hex.length > 0) b = hex.substring(0, hex.length);\n
              }\n
              return { r: this.hexToInt(r), g: this.hexToInt(g), b: this.hexToInt(b), a: this.hexToInt(a) };\n
            },\n
          validateHex:\n
            function(hex)\n
            {\n
              //if (typeof hex === "object") return "";\n
              hex = hex.toLowerCase().replace(/[^a-f0-9]/g, \'\');\n
              if (hex.length > 8) hex = hex.substring(0, 8);\n
              return hex;\n
            },\n
          rgbaToHex:\n
            function(rgba)\n
            {\n
              return this.intToHex(rgba.r) + this.intToHex(rgba.g) + this.intToHex(rgba.b) + this.intToHex(rgba.a);\n
            },\n
          intToHex:\n
            function(dec)\n
            {\n
              var result = (dec | 0).toString(16);\n
              if (result.length == 1) result = (\'0\' + result);\n
              return result.toLowerCase();\n
            },\n
          hexToInt:\n
            function(hex)\n
            {\n
              return parseInt(hex, 16);\n
            },\n
          rgbToHsv:\n
            function(rgb)\n
            {\n
              var r = rgb.r / 255, g = rgb.g / 255, b = rgb.b / 255, hsv = { h: 0, s: 0, v: 0 }, min = 0, max = 0, delta;\n
              if (r >= g && r >= b)\n
              {\n
                max = r;\n
                min = g > b ? b : g;\n
              }\n
              else if (g >= b && g >= r)\n
              {\n
                max = g;\n
                min = r > b ? b : r;\n
              }\n
              else\n
              {\n
                max = b;\n
                min = g > r ? r : g;\n
              }\n
              hsv.v = max;\n
              hsv.s = max ? (max - min) / max : 0;\n
              if (!hsv.s) hsv.h = 0;\n
              else\n
              {\n
                delta = max - min;\n
                if (r == max) hsv.h = (g - b) / delta;\n
                else if (g == max) hsv.h = 2 + (b - r) / delta;\n
                else hsv.h = 4 + (r - g) / delta;\n
                hsv.h = parseInt(hsv.h * 60);\n
                if (hsv.h < 0) hsv.h += 360;\n
              }\n
              hsv.s = (hsv.s * 100) | 0;\n
              hsv.v = (hsv.v * 100) | 0;\n
              return hsv;\n
            },\n
          hsvToRgb:\n
            function(hsv)\n
            {\n
              var rgb = { r: 0, g: 0, b: 0, a: 100 }, h = hsv.h, s = hsv.s, v = hsv.v;\n
              if (s == 0)\n
              {\n
                if (v == 0) rgb.r = rgb.g = rgb.b = 0;\n
                else rgb.r = rgb.g = rgb.b = (v * 255 / 100) | 0;\n
              }\n
              else\n
              {\n
                if (h == 360) h = 0;\n
                h /= 60;\n
                s = s / 100;\n
                v = v / 100;\n
                var i = h | 0,\n
                    f = h - i,\n
                    p = v * (1 - s),\n
                    q = v * (1 - (s * f)),\n
                    t = v * (1 - (s * (1 - f)));\n
                switch (i)\n
                {\n
                  case 0:\n
                    rgb.r = v;\n
                    rgb.g = t;\n
                    rgb.b = p;\n
                    break;\n
                  case 1:\n
                    rgb.r = q;\n
                    rgb.g = v;\n
                    rgb.b = p;\n
                    break;\n
                  case 2:\n
                    rgb.r = p;\n
                    rgb.g = v;\n
                    rgb.b = t;\n
                    break;\n
                  case 3:\n
                    rgb.r = p;\n
                    rgb.g = q;\n
                    rgb.b = v;\n
                    break;\n
                  case 4:\n
                    rgb.r = t;\n
                    rgb.g = p;\n
                    rgb.b = v;\n
                    break;\n
                  case 5:\n
                    rgb.r = v;\n
                    rgb.g = p;\n
                    rgb.b = q;\n
                    break;\n
                }\n
                rgb.r = (rgb.r * 255) | 0;\n
                rgb.g = (rgb.g * 255) | 0;\n
                rgb.b = (rgb.b * 255) | 0;\n
              }\n
              return rgb;\n
            }\n
        }\n
    };\n
  var Color = $.jPicker.Color, List = $.jPicker.List, ColorMethods = $.jPicker.ColorMethods; // local copies for YUI compressor\n
  $.fn.jPicker =\n
    function(options)\n
    {\n
      var $arguments = arguments;\n
      return this.each(\n
        function()\n
        {\n
          var $this = this, settings = $.extend(true, {}, $.fn.jPicker.defaults, options); // local copies for YUI compressor\n
          if ($($this).get(0).nodeName.toLowerCase() == \'input\') // Add color picker icon if binding to an input element and bind the events to the input\n
          {\n
            $.extend(true, settings,\n
              {\n
                window:\n
                {\n
                  bindToInput: true,\n
                  expandable: true,\n
                  input: $($this)\n
                }\n
              });\n
            if($($this).val()==\'\')\n
            {\n
              settings.color.active = new Color({ hex: null });\n
              settings.color.current = new Color({ hex: null });\n
            }\n
            else if (ColorMethods.validateHex($($this).val()))\n
            {\n
              settings.color.active = new Color({ hex: $($this).val(), a: settings.color.active.val(\'a\') });\n
              settings.color.current = new Color({ hex: $($this).val(), a: settings.color.active.val(\'a\') });\n
            }\n
          }\n
          if (settings.window.expandable)\n
            $($this).after(\'<span class="jPicker"><span class="Icon"><span class="Color">&nbsp;</span><span class="Alpha">&nbsp;</span><span class="Image" title="Click To Open Color Picker">&nbsp;</span><span class="Container">&nbsp;</span></span></span>\');\n
          else settings.window.liveUpdate = false; // Basic control binding for inline use - You will need to override the liveCallback or commitCallback function to retrieve results\n
          var isLessThanIE7 = parseFloat(navigator.appVersion.split(\'MSIE\')[1]) < 7 && document.body.filters, // needed to run the AlphaImageLoader function for IE6\n
            container = null,\n
            colorMapDiv = null,\n
            colorBarDiv = null,\n
            colorMapL1 = null, // different layers of colorMap and colorBar\n
            colorMapL2 = null,\n
            colorMapL3 = null,\n
            colorBarL1 = null,\n
            colorBarL2 = null,\n
            colorBarL3 = null,\n
            colorBarL4 = null,\n
            colorBarL5 = null,\n
            colorBarL6 = null,\n
            colorMap = null, // color maps\n
            colorBar = null,\n
            colorPicker = null,\n
            elementStartX = null, // Used to record the starting css positions for dragging the control\n
            elementStartY = null,\n
            pageStartX = null, // Used to record the mousedown coordinates for dragging the control\n
            pageStartY = null,\n
            activePreview = null, // color boxes above the radio buttons\n
            currentPreview = null,\n
            okButton = null,\n
            cancelButton = null,\n
            grid = null, // preset colors grid\n
            iconColor = null, // iconColor for popup icon\n
            iconAlpha = null, // iconAlpha for popup icon\n
            iconImage = null, // iconImage popup icon\n
            moveBar = null, // drag bar\n
            setColorMode = // set color mode and update visuals for the new color mode\n
              function(colorMode)\n
              {\n
                var active = color.active, // local copies for YUI compressor\n
                  clientPath = images.clientPath,\n
                  hex = active.val(\'hex\'),\n
                  rgbMap,\n
                  rgbBar;\n
                settings.color.mode = colorMode;\n
                switch (colorMode)\n
                {\n
                  case \'h\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setBG.call($this, colorMapDiv, \'transparent\');\n
                        setImgLoc.call($this, colorMapL1, 0);\n
                        setAlpha.call($this, colorMapL1, 100);\n
                        setImgLoc.call($this, colorMapL2, 260);\n
                        setAlpha.call($this, colorMapL2, 100);\n
                        setBG.call($this, colorBarDiv, \'transparent\');\n
                        setImgLoc.call($this, colorBarL1, 0);\n
                        setAlpha.call($this, colorBarL1, 100);\n
                        setImgLoc.call($this, colorBarL2, 260);\n
                        setAlpha.call($this, colorBarL2, 100);\n
                        setImgLoc.call($this, colorBarL3, 260);\n
                        setAlpha.call($this, colorBarL3, 100);\n
                        setImgLoc.call($this, colorBarL4, 260);\n
                        setAlpha.call($this, colorBarL4, 100);\n
                        setImgLoc.call($this, colorBarL6, 260);\n
                        setAlpha.call($this, colorBarL6, 100);\n
                      }, 0);\n
                    colorMap.range(\'all\', { minX: 0, maxX: 100, minY: 0, maxY: 100 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 360 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'s\'), y: 100 - active.val(\'v\') }, colorMap);\n
                    colorBar.val(\'y\', 360 - active.val(\'h\'), colorBar);\n
                    break;\n
                  case \'s\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setBG.call($this, colorMapDiv, \'transparent\');\n
                        setImgLoc.call($this, colorMapL1, -260);\n
                        setImgLoc.call($this, colorMapL2, -520);\n
                        setImgLoc.call($this, colorBarL1, -260);\n
                        setImgLoc.call($this, colorBarL2, -520);\n
                        setImgLoc.call($this, colorBarL6, 260);\n
                        setAlpha.call($this, colorBarL6, 100);\n
                      }, 0);\n
                    colorMap.range(\'all\', { minX: 0, maxX: 360, minY: 0, maxY: 100 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 100 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'h\'), y: 100 - active.val(\'v\') }, colorMap);\n
                    colorBar.val(\'y\', 100 - active.val(\'s\'), colorBar);\n
                    break;\n
                  case \'v\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setBG.call($this, colorMapDiv, \'000000\');\n
                        setImgLoc.call($this, colorMapL1, -780);\n
                        setImgLoc.call($this, colorMapL2, 260);\n
                        setBG.call($this, colorBarDiv, hex);\n
                        setImgLoc.call($this, colorBarL1, -520);\n
                        setImgLoc.call($this, colorBarL2, 260);\n
                        setAlpha.call($this, colorBarL2, 100);\n
                        setImgLoc.call($this, colorBarL6, 260);\n
                        setAlpha.call($this, colorBarL6, 100);\n
                      }, 0);\n
                    colorMap.range(\'all\', { minX: 0, maxX: 360, minY: 0, maxY: 100 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 100 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'h\'), y: 100 - active.val(\'s\') }, colorMap);\n
                    colorBar.val(\'y\', 100 - active.val(\'v\'), colorBar);\n
                    break;\n
                  case \'r\':\n
                    rgbMap = -1040;\n
                    rgbBar = -780;\n
                    colorMap.range(\'all\', { minX: 0, maxX: 255, minY: 0, maxY: 255 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 255 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'b\'), y: 255 - active.val(\'g\') }, colorMap);\n
                    colorBar.val(\'y\', 255 - active.val(\'r\'), colorBar);\n
                    break;\n
                  case \'g\':\n
                    rgbMap = -1560;\n
                    rgbBar = -1820;\n
                    colorMap.range(\'all\', { minX: 0, maxX: 255, minY: 0, maxY: 255 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 255 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'b\'), y: 255 - active.val(\'r\') }, colorMap);\n
                    colorBar.val(\'y\', 255 - active.val(\'g\'), colorBar);\n
                    break;\n
                  case \'b\':\n
                    rgbMap = -2080;\n
                    rgbBar = -2860;\n
                    colorMap.range(\'all\', { minX: 0, maxX: 255, minY: 0, maxY: 255 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 255 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'r\'), y: 255 - active.val(\'g\') }, colorMap);\n
                    colorBar.val(\'y\', 255 - active.val(\'b\'), colorBar);\n
                    break;\n
                  case \'a\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setBG.call($this, colorMapDiv, \'transparent\');\n
                        setImgLoc.call($this, colorMapL1, -260);\n
                        setImgLoc.call($this, colorMapL2, -520);\n
                        setImgLoc.call($this, colorBarL1, 260);\n
                        setImgLoc.call($this, colorBarL2, 260);\n
                        setAlpha.call($this, colorBarL2, 100);\n
                        setImgLoc.call($this, colorBarL6, 0);\n
                        setAlpha.call($this, colorBarL6, 100);\n
                      }, 0);\n
                    colorMap.range(\'all\', { minX: 0, maxX: 360, minY: 0, maxY: 100 });\n
                    colorBar.range(\'rangeY\', { minY: 0, maxY: 255 });\n
                    if (active.val(\'ahex\') == null) break;\n
                    colorMap.val(\'xy\', { x: active.val(\'h\'), y: 100 - active.val(\'v\') }, colorMap);\n
                    colorBar.val(\'y\', 255 - active.val(\'a\'), colorBar);\n
                    break;\n
                  default:\n
                    throw (\'Invalid Mode\');\n
                    break;\n
                }\n
                switch (colorMode)\n
                {\n
                  case \'h\':\n
                    break;\n
                  case \'s\':\n
                  case \'v\':\n
                  case \'a\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setAlpha.call($this, colorMapL1, 100);\n
                        setAlpha.call($this, colorBarL1, 100);\n
                        setImgLoc.call($this, colorBarL3, 260);\n
                        setAlpha.call($this, colorBarL3, 100);\n
                        setImgLoc.call($this, colorBarL4, 260);\n
                        setAlpha.call($this, colorBarL4, 100);\n
                      }, 0);\n
                    break;\n
                  case \'r\':\n
                  case \'g\':\n
                  case \'b\':\n
                    setTimeout(\n
                      function()\n
                      {\n
                        setBG.call($this, colorMapDiv, \'transparent\');\n
                        setBG.call($this, colorBarDiv, \'transparent\');\n
                        setAlpha.call($this, colorBarL1, 100);\n
                        setAlpha.call($this, colorMapL1, 100);\n
                        setImgLoc.call($this, colorMapL1, rgbMap);\n
                        setImgLoc.call($this, colorMapL2, rgbMap - 260);\n
                        setImgLoc.call($this, colorBarL1, rgbBar - 780);\n
                        setImgLoc.call($this, colorBarL2, rgbBar - 520);\n
                        setImgLoc.call($this, colorBarL3, rgbBar);\n
                        setImgLoc.call($this, colorBarL4, rgbBar - 260);\n
                        setImgLoc.call($this, colorBarL6, 260);\n
                        setAlpha.call($this, colorBarL6, 100);\n
                      }, 0);\n
                    break;\n
                }\n
                if (active.val(\'ahex\') == null) return;\n
                activeColorChanged.call($this, active);\n
              },\n
            activeColorChanged = // Update color when user changes text values\n
              function(ui, context)\n
              {\n
                if (context == null || (context != colorBar && context != colorMap)) positionMapAndBarArrows.call($this, ui, context);\n
                setTimeout(\n
                  function()\n
                  {\n
                    updatePreview.call($this, ui);\n
                    updateMapVisuals.call($this, ui);\n
                    updateBarVisuals.call($this, ui);\n
                  }, 0);\n
              },\n
            mapValueChanged = // user has dragged the ColorMap pointer\n
              function(ui, context)\n
              {\n
                var active = color.active;\n
                if (context != colorMap && active.val() == null) return;\n
                var xy = ui.val(\'all\');\n
                switch (settings.color.mode)\n
                {\n
                  case \'h\':\n
                    active.val(\'sv\', { s: xy.x, v: 100 - xy.y }, context);\n
                    break;\n
                  case \'s\':\n
                  case \'a\':\n
                    active.val(\'hv\', { h: xy.x, v: 100 - xy.y }, context);\n
                    break;\n
                  case \'v\':\n
                    active.val(\'hs\', { h: xy.x, s: 100 - xy.y }, context);\n
                    break;\n
                  case \'r\':\n
                    active.val(\'gb\', { g: 255 - xy.y, b: xy.x }, context);\n
                    break;\n
                  case \'g\':\n
                    active.val(\'rb\', { r: 255 - xy.y, b: xy.x }, context);\n
                    break;\n
                  case \'b\':\n
                    active.val(\'rg\', { r: xy.x, g: 255 - xy.y }, context);\n
                    break;\n
                }\n
              },\n
            colorBarValueChanged = // user has dragged the ColorBar slider\n
              function(ui, context)\n
              {\n
                var active = color.active;\n
                if (context != colorBar && active.val() == null) return;\n
                switch (settings.color.mode)\n
                {\n
                  case \'h\':\n
                    active.val(\'h\', { h: 360 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'s\':\n
                    active.val(\'s\', { s: 100 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'v\':\n
                    active.val(\'v\', { v: 100 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'r\':\n
                    active.val(\'r\', { r: 255 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'g\':\n
                    active.val(\'g\', { g: 255 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'b\':\n
                    active.val(\'b\', { b: 255 - ui.val(\'y\') }, context);\n
                    break;\n
                  case \'a\':\n
                    active.val(\'a\', 255 - ui.val(\'y\'), context);\n
                    break;\n
                }\n
              },\n
            positionMapAndBarArrows = // position map and bar arrows to match current color\n
              function(ui, context)\n
              {\n
                if (context != colorMap)\n
                {\n
                  switch (settings.color.mode)\n
                  {\n
                    case \'h\':\n
                      var sv = ui.val(\'sv\');\n
                      colorMap.val(\'xy\', { x: sv != null ? sv.s : 100, y: 100 - (sv != null ? sv.v : 100) }, context);\n
                      break;\n
                    case \'s\':\n
                    case \'a\':\n
                      var hv = ui.val(\'hv\');\n
                      colorMap.val(\'xy\', { x: hv && hv.h || 0, y: 100 - (hv != null ? hv.v : 100) }, context);\n
                      break;\n
                    case \'v\':\n
                      var hs = ui.val(\'hs\');\n
                      colorMap.val(\'xy\', { x: hs && hs.h || 0, y: 100 - (hs != null ? hs.s : 100) }, context);\n
                      break;\n
                    case \'r\':\n
                      var bg = ui.val(\'bg\');\n
                      colorMap.val(\'xy\', { x: bg && bg.b || 0, y: 255 - (bg && bg.g || 0) }, context);\n
                      break;\n
                    case \'g\':\n
                      var br = ui.val(\'br\');\n
                      colorMap.val(\'xy\', { x: br && br.b || 0, y: 255 - (br && br.r || 0) }, context);\n
                      break;\n
                    case \'b\':\n
                      var rg = ui.val(\'rg\');\n
                      colorMap.val(\'xy\', { x: rg && rg.r || 0, y: 255 - (rg && rg.g || 0) }, context);\n
                      break;\n
                  }\n
                }\n
                if (context != colorBar)\n
                {\n
                  switch (settings.color.mode)\n
                  {\n
                    case \'h\':\n
                      colorBar.val(\'y\', 360 - (ui.val(\'h\') || 0), context);\n
                      break;\n
                    case \'s\':\n
                      var s = ui.val(\'s\');\n
                      colorBar.val(\'y\', 100 - (s != null ? s : 100), context);\n
                      break;\n
                    case \'v\':\n
                      var v = ui.val(\'v\');\n
                      colorBar.val(\'y\', 100 - (v != null ? v : 100), context);\n
                      break;\n
                    case \'r\':\n
                      colorBar.val(\'y\', 255 - (ui.val(\'r\') || 0), context);\n
                      break;\n
                    case \'g\':\n
                      colorBar.val(\'y\', 255 - (ui.val(\'g\') || 0), context);\n
                      break;\n
                    case \'b\':\n
                      colorBar.val(\'y\', 255 - (ui.val(\'b\') || 0), context);\n
                      break;\n
                    case \'a\':\n
                      var a = ui.val(\'a\');\n
                      colorBar.val(\'y\', 255 - (a != null ? a : 255), context);\n
                      break;\n
                  }\n
                }\n
              },\n
            updatePreview =\n
              function(ui)\n
              {\n
                try\n
                {\n
                  var all = ui.val(\'all\');\n
                  activePreview.css({ backgroundColor: all && \'#\' + all.hex || \'transparent\' });\n
                  setAlpha.call($this, activePreview, all && Math.precision((all.a * 100) / 255, 4) || 0);\n
                }\n
                catch (e) { }\n
              },\n
            updateMapVisuals =\n
              function(ui)\n
              {\n
                switch (settings.color.mode)\n
                {\n
                  case \'h\':\n
                    setBG.call($this, colorMapDiv, new Color({ h: ui.val(\'h\') || 0, s: 100, v: 100 }).val(\'hex\'));\n
                    break;\n
                  case \'s\':\n
                  case \'a\':\n
                    var s = ui.val(\'s\');\n
                    setAlpha.call($this, colorMapL2, 100 - (s != null ? s : 100));\n
                    break;\n
                  case \'v\':\n
                    var v = ui.val(\'v\');\n
                    setAlpha.call($this, colorMapL1, v != null ? v : 100);\n
                    break;\n
                  case \'r\':\n
                    setAlpha.call($this, colorMapL2, Math.precision((ui.val(\'r\') || 0) / 255 * 100, 4));\n
                    break;\n
                  case \'g\':\n
                    setAlpha.call($this, colorMapL2, Math.precision((ui.val(\'g\') || 0) / 255 * 100, 4));\n
                    break;\n
                  case \'b\':\n
                    setAlpha.call($this, colorMapL2, Math.precision((ui.val(\'b\') || 0) / 255 * 100));\n
                    break;\n
                }\n
                var a = ui.val(\'a\');\n
                setAlpha.call($this, colorMapL3, Math.precision(((255 - (a || 0)) * 100) / 255, 4));\n
              },\n
            updateBarVisuals =\n
              function(ui)\n
              {\n
                switch (settings.color.mode)\n
                {\n
                  case \'h\':\n
                    var a = ui.val(\'a\');\n
                    setAlpha.call($this, colorBarL5, Math.precision(((255 - (a || 0)) * 100) / 255, 4));\n
                    break;\n
                  case \'s\':\n
                    var hva = ui.val(\'hva\'),\n
                        saturatedColor = new Color({ h: hva && hva.h || 0, s: 100, v: hva != null ? hva.v : 100 });\n
                    setBG.call($this, colorBarDiv, saturatedColor.val(\'hex\'));\n
                    setAlpha.call($this, colorBarL2, 100 - (hva != null ? hva.v : 100));\n
                    setAlpha.call($this, colorBarL5, Math.precision(((255 - (hva && hva.a || 0)) * 100) / 255, 4));\n
                    break;\n
                  case \'v\':\n
                    var hsa = ui.val(\'hsa\'),\n
                        valueColor = new Color({ h: hsa && hsa.h || 0, s: hsa != null ? hsa.s : 100, v: 100 });\n
                    setBG.call($this, colorBarDiv, valueColor.val(\'hex\'));\n
                    setAlpha.call($this, colorBarL5, Math.precision(((255 - (hsa && hsa.a || 0)) * 100) / 255, 4));\n
                    break;\n
                  case \'r\':\n
                  case \'g\':\n
                  case \'b\':\n
                    var hValue = 0, vValue = 0, rgba = ui.val(\'rgba\');\n
                    if (settings.color.mode == \'r\')\n
                    {\n
                      hValue = rgba && rgba.b || 0;\n
                      vValue = rgba && rgba.g || 0;\n
                    }\n
                    else if (settings.color.mode == \'g\')\n
                    {\n
                      hValue = rgba && rgba.b || 0;\n
                      vValue = rgba && rgba.r || 0;\n
                    }\n
                    else if (settings.color.mode == \'b\')\n
                    {\n
                      hValue = rgba && rgba.r || 0;\n
                      vValue = rgba && rgba.g || 0;\n
                    }\n
                    var middle = vValue > hValue ? hValue : vValue;\n
                    setAlpha.call($this, colorBarL2, hValue > vValue ? Math.precision(((hValue - vValue) / (255 - vValue)) * 100, 4) : 0);\n
                    setAlpha.call($this, colorBarL3, vValue > hValue ? Math.precision(((vValue - hValue) / (255 - hValue)) * 100, 4) : 0);\n
                    setAlpha.call($this, colorBarL4, Math.precision((middle / 255) * 100, 4));\n
                    setAlpha.call($this, colorBarL5, Math.precision(((255 - (rgba && rgba.a || 0)) * 100) / 255, 4));\n
                    break;\n
                  case \'a\':\n
                    var a = ui.val(\'a\');\n
                    setBG.call($this, colorBarDiv, ui.val(\'hex\') || \'000000\');\n
                    setAlpha.call($this, colorBarL5, a != null ? 0 : 100);\n
                    setAlpha.call($this, colorBarL6, a != null ? 100 : 0);\n
                    break;\n
                }\n
              },\n
            setBG =\n
              function(el, c)\n
              {\n
                el.css({ backgroundColor: c && c.length == 6 && \'#\' + c || \'transparent\' });\n
              },\n
            setImg =\n
              function(img, src)\n
              {\n
                if (isLessThanIE7 && (src.indexOf(\'AlphaBar.png\') != -1 || src.indexOf(\'Bars.png\') != -1 || src.indexOf(\'Maps.png\') != -1))\n
                {\n
                  img.attr(\'pngSrc\', src);\n
                  img.css({ backgroundImage: \'none\', filter: \'progid:DXImageTransform.Microsoft.AlphaImageLoader(src=\\\'\' + src + \'\\\', sizingMethod=\\\'scale\\\')\' });\n
                }\n
                else img.css({ backgroundImage: \'url(\\\'\' + src + \'\\\')\' });\n
              },\n
            setImgLoc =\n
              function(img, y)\n
              {\n
                img.css({ top: y + \'px\' });\n
              },\n
            setAlpha =\n
              function(obj, alpha)\n
              {\n
                obj.css({ visibility: alpha > 0 ? \'visible\' : \'hidden\' });\n
                if (alpha > 0 && alpha < 100)\n
                {\n
                  if (isLessThanIE7)\n
                  {\n
                    var src = obj.attr(\'pngSrc\');\n
                    if (src != null && (src.indexOf(\'AlphaBar.png\') != -1 || src.indexOf(\'Bars.png\') != -1 || src.indexOf(\'Maps.png\') != -1))\n
                      obj.css({ filter: \'progid:DXImageTransform.Microsoft.AlphaImageLoader(src=\\\'\' + src + \'\\\', sizingMethod=\\\'scale\\\') progid:DXImageTransform.Microsoft.Alpha(opacity=\' + alpha + \')\' });\n
                    else obj.css({ opacity: Math.precision(alpha / 100, 4) });\n
                  }\n
                  else obj.css({ opacity: Math.precision(alpha / 100, 4) });\n
                }\n
                else if (alpha == 0 || alpha == 100)\n
                {\n
                  if (isLessThanIE7)\n
                  {\n
                    var src = obj.attr(\'pngSrc\');\n
                    if (src != null && (src.indexOf(\'AlphaBar.png\') != -1 || src.indexOf(\'Bars.png\') != -1 || src.indexOf(\'Maps.png\') != -1))\n
                      obj.css({ filter: \'progid:DXImageTransform.Microsoft.AlphaImageLoader(src=\\\'\' + src + \'\\\', sizingMethod=\\\'scale\\\')\' });\n
                    else obj.css({ opacity: \'\' });\n
                  }\n
                  else obj.css({ opacity: \'\' });\n
                }\n
              },\n
            revertColor = // revert color to original color when opened\n
              function()\n
              {\n
                color.active.val(\'ahex\', color.current.val(\'ahex\'));\n
              },\n
            commitColor = // commit the color changes\n
              function()\n
              {\n
                color.current.val(\'ahex\', color.active.val(\'ahex\'));\n
              },\n
            radioClicked =\n
              function(e)\n
              {\n
                $(this).parents(\'tbody:first\').find(\'input:radio[value!="\'+e.target.value+\'"]\').removeAttr(\'checked\');\n
                setColorMode.call($this, e.target.value);\n
              },\n
            currentClicked =\n
              function()\n
              {\n
                revertColor.call($this);\n
              },\n
            cancelClicked =\n
              function()\n
              {\n
                revertColor.call($this);\n
                settings.window.expandable && hide.call($this);\n
                $.isFunction(cancelCallback) && cancelCallback.call($this, color.active, cancelButton);\n
              },\n
            okClicked =\n
              function()\n
              {\n
                commitColor.call($this);\n
                settings.window.expandable && hide.call($this);\n
                $.isFunction(commitCallback) && commitCallback.call($this, color.active, okButton);\n
              },\n
            iconImageClicked =\n
              function()\n
              {\n
                show.call($this);\n
              },\n
            currentColorChanged =\n
              function(ui, context)\n
              {\n
                var hex = ui.val(\'hex\');\n
                currentPreview.css({ backgroundColor: hex && \'#\' + hex || \'transparent\' });\n
                setAlpha.call($this, currentPreview, Math.precision(((ui.val(\'a\') || 0) * 100) / 255, 4));\n
              },\n
            expandableColorChanged =\n
              function(ui, context)\n
              {\n
                var hex = ui.val(\'hex\');\n
                var va = ui.val(\'va\');\n
                iconColor.css({ backgroundColor: hex && \'#\' + hex || \'transparent\' });\n
                setAlpha.call($this, iconAlpha, Math.precision(((255 - (va && va.a || 0)) * 100) / 255, 4));\n
                if (settings.window.bindToInput&&settings.window.updateInputColor)\n
                  settings.window.input.css(\n
                    {\n
                      backgroundColor: hex && \'#\' + hex || \'transparent\',\n
                      color: va == null || va.v > 75 ? \'#000000\' : \'#ffffff\'\n
                    });\n
              },\n
            moveBarMouseDown =\n
              function(e)\n
              {\n
                var element = settings.window.element, // local copies for YUI compressor\n
                  page = settings.window.page;\n
                elementStartX = parseInt(container.css(\'left\'));\n
                elementStartY = parseInt(container.css(\'top\'));\n
                pageStartX = e.pageX;\n
                pageStartY = e.pageY;\n
                // bind events to document to move window - we will unbind these on mouseup\n
                $(document).bind(\'mousemove\', documentMouseMove).bind(\'mouseup\', documentMouseUp);\n
                e.preventDefault(); // prevent attempted dragging of the column\n
              },\n
            documentMouseMove =\n
              function(e)\n
              {\n
                container.css({ left: elementStartX - (pageStartX - e.pageX) + \'px\', top: elementStartY - (pageStartY - e.pageY) + \'px\' });\n
                if (settings.window.expandable && !$.support.boxModel) container.prev().css({ left: container.css("left"), top: container.css("top") });\n
                e.stopPropagation();\n
                e.preventDefault();\n
                return false;\n
              },\n
            documentMouseUp =\n
              function(e)\n
              {\n
                $(document).unbind(\'mousemove\', documentMouseMove).unbind(\'mouseup\', documentMouseUp);\n
                e.stopPropagation();\n
                e.preventDefault();\n
                return false;\n
              },\n
            quickPickClicked =\n
              function(e)\n
              {\n
                e.preventDefault();\n
                e.stopPropagation();\n
                color.active.val(\'ahex\', $(this).attr(\'title\') || null, e.target);\n
                return false;\n
              },\n
            commitCallback = $.isFunction($arguments[1]) && $arguments[1] || null,\n
            liveCallback = $.isFunction($arguments[2]) && $arguments[2] || null,\n
            cancelCallback = $.isFunction($arguments[3]) && $arguments[3] || null,\n
            show =\n
              function()\n
              {\n
                color.current.val(\'ahex\', color.active.val(\'ahex\'));\n
                var attachIFrame = function()\n
                  {\n
                    if (!settings.window.expandable || $.support.boxModel) return;\n
                    var table = container.find(\'table:first\');\n
                    container.before(\'<iframe/>\');\n
                    container.prev().css({ width: table.width(), height: container.height(), opacity: 0, position: \'absolute\', left: container.css("left"), top: container.css("top") });\n
                  };\n
                if (settings.window.expandable)\n
                {\n
                  $(document.body).children(\'div.jPicker.Container\').css({zIndex:10});\n
                  container.css({zIndex:20});\n
                }\n
                switch (settings.window.effects.type)\n
                {\n
                  case \'fade\':\n
                    container.fadeIn(settings.window.effects.speed.show, attachIFrame);\n
                    break;\n
                  case \'slide\':\n
                    container.slideDown(settings.window.effects.speed.show, attachIFrame);\n
                    break;\n
                  case \'show\':\n
                  default:\n
                    container.show(settings.window.effects.speed.show, attachIFrame);\n
                    break;\n
                }\n
              },\n
            hide =\n
              function()\n
              {\n
                var removeIFrame = function()\n
                  {\n
                    if (settings.window.expandable) container.css({ zIndex: 10 });\n
                    if (!settings.window.expandable || $.support.boxModel) return;\n
                    container.prev().remove();\n
                  };\n
                switch (settings.window.effects.type)\n
                {\n
                  case \'fade\':\n
                    container.fadeOut(settings.window.effects.speed.hide, removeIFrame);\n
                    break;\n
                  case \'slide\':\n
                    container.slideUp(settings.window.effects.speed.hide, removeIFrame);\n
                    break;\n
                  case \'show\':\n
                  default:\n
                    container.hide(settings.window.effects.speed.hide, removeIFrame);\n
                    break;\n
                }\n
              },\n
            initialize =\n
              function()\n
              {\n
                var win = settings.window,\n
                    popup = win.expandable ? $($this).next().find(\'.Container:first\') : null;\n
                container = win.expandable ? $(\'<div/>\') : $($this);\n
                container.addClass(\'jPicker Container\');\n
                if (win.expandable) container.hide();\n
                container.get(0).onselectstart = function(event){ if (event.target.nodeName.toLowerCase() !== \'input\') return false; };\n
                // inject html source code - we are using a single table for this control - I know tables are considered bad, but it takes care of equal height columns and\n
                // this control really is tabular data, so I believe it is the right move\n
                var all = color.active.val(\'all\');\n
                if (win.alphaPrecision < 0) win.alphaPrecision = 0;\n
                else if (win.alphaPrecision > 2) win.alphaPrecision = 2;\n
                var controlHtml=\'<table class="jPicker" cellpadding="0" cellspacing="0"><tbody>\' + (win.expandable ? \'<tr><td class="Move" colspan="5">&nbsp;</td></tr>\' : \'\') + \'<tr><td rowspan="9"><h2 class="Title">\' + (win.title || localization.text.title) + \'</h2><div class="Map"><span class="Map1">&nbsp;</span><span class="Map2">&nbsp;</span><span class="Map3">&nbsp;</span><img src="\' + images.clientPath + images.colorMap.arrow.file + \'" class="Arrow"/></div></td><td rowspan="9"><div class="Bar"><span class="Map1">&nbsp;</span><span class="Map2">&nbsp;</span><span class="Map3">&nbsp;</span><span class="Map4">&nbsp;</span><span class="Map5">&nbsp;</span><span class="Map6">&nbsp;</span><img src="\' + images.clientPath + images.colorBar.arrow.file + \'" class="Arrow"/></div></td><td colspan="2" class="Preview">\' + localization.text.newColor + \'<div><span class="Active" title="\' + localization.tooltips.colors.newColor + \'">&nbsp;</span><span class="Current" title="\' + localization.tooltips.colors.currentColor + \'">&nbsp;</span></div>\' + localization.text.currentColor + \'</td><td rowspan="9" class="Button"><input type="button" class="Ok" value="\' + localization.text.ok + \'" title="\' + localization.tooltips.buttons.ok + \'"/><input type="button" class="Cancel" value="\' + localization.text.cancel + \'" title="\' + localization.tooltips.buttons.cancel + \'"/><hr/><div class="Grid">&nbsp;</div></td></tr><tr class="Hue"><td class="Radio"><label title="\' + localization.tooltips.hue.radio + \'"><input type="radio" value="h"\' + (settings.color.mode == \'h\' ? \' checked="checked"\' : \'\') + \'/>H:</label></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.h : \'\') + \'" title="\' + localization.tooltips.hue.textbox + \'"/>&nbsp;&deg;</td></tr><tr class="Saturation"><td class="Radio"><label title="\' + localization.tooltips.saturation.radio + \'"><input type="radio" value="s"\' + (settings.color.mode == \'s\' ? \' checked="checked"\' : \'\') + \'/>S:</label></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.s : \'\') + \'" title="\' + localization.tooltips.saturation.textbox + \'"/>&nbsp;%</td></tr><tr class="Value"><td class="Radio"><label title="\' + localization.tooltips.value.radio + \'"><input type="radio" value="v"\' + (settings.color.mode == \'v\' ? \' checked="checked"\' : \'\') + \'/>V:</label><br/><br/></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.v : \'\') + \'" title="\' + localization.tooltips.value.textbox + \'"/>&nbsp;%<br/><br/></td></tr><tr class="Red"><td class="Radio"><label title="\' + localization.tooltips.red.radio + \'"><input type="radio" value="r"\' + (settings.color.mode == \'r\' ? \' checked="checked"\' : \'\') + \'/>R:</label></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.r : \'\') + \'" title="\' + localization.tooltips.red.textbox + \'"/></td></tr><tr class="Green"><td class="Radio"><label title="\' + localization.tooltips.green.radio + \'"><input type="radio" value="g"\' + (settings.color.mode == \'g\' ? \' checked="checked"\' : \'\') + \'/>G:</label></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.g : \'\') + \'" title="\' + localization.tooltips.green.textbox + \'"/></td></tr><tr class="Blue"><td class="Radio"><label title="\' + localization.tooltips.blue.radio + \'"><input type="radio" value="b"\' + (settings.color.mode == \'b\' ? \' checked="checked"\' : \'\') + \'/>B:</label></td><td class="Text"><input type="text" maxlength="3" value="\' + (all != null ? all.b : \'\') + \'" title="\' + localization.tooltips.blue.textbox + \'"/></td></tr><tr class="Alpha"><td class="Radio">\' + (win.alphaSupport ? \'<label title="\' + localization.tooltips.alpha.radio + \'"><input type="radio" value="a"\' + (settings.color.mode == \'a\' ? \' checked="checked"\' : \'\') + \'/>A:</label>\' : \'&nbsp;\') + \'</td><td class="Text">\' + (win.alphaSupport ? \'<input type="text" maxlength="\' + (3 + win.alphaPrecision) + \'" value="\' + (all != null ? Math.precision((all.a * 100) / 255, win.alphaPrecision) : \'\') + \'" title="\' + localization.tooltips.alpha.textbox + \'"/>&nbsp;%\' : \'&nbsp;\') + \'</td></tr><tr class="Hex"><td colspan="2" class="Text"><label title="\' + localization.tooltips.hex.textbox + \'">#:<input type="text" maxlength="6" class="Hex" value="\' + (all != null ? all.hex : \'\') + \'"/></label>\' + (win.alphaSupport ? \'<input type="text" maxlength="2" class="AHex" value="\' + (all != null ? all.ahex.substring(6) : \'\') + \'" title="\' + localization.tooltips.hex.alpha + \'"/></td>\' : \'&nbsp;\') + \'</tr></tbody></table>\';\n
                if (win.expandable)\n
                {\n
                  container.html(controlHtml);\n
                  if($(document.body).children(\'div.jPicker.Container\').length==0)$(document.body).prepend(container);\n
                  else $(document.body).children(\'div.jPicker.Container:last\').after(container);\n
                  container.mousedown(\n
                    function()\n
                    {\n
                      $(document.body).children(\'div.jPicker.Container\').css({zIndex:10});\n
                      container.css({zIndex:20});\n
                    });\n
                  container.css( // positions must be set and display set to absolute before source code injection or IE will size the container to fit the window\n
                    {\n
                      left:\n
                        win.position.x == \'left\' ? (popup.offset().left - 530 - (win.position.y == \'center\' ? 25 : 0)) + \'px\' :\n
                        win.position.x == \'center\' ? (popup.offset().left - 260) + \'px\' :\n
                        win.position.x == \'right\' ? (popup.offset().left - 10 + (win.position.y == \'center\' ? 25 : 0)) + \'px\' :\n
                        win.position.x == \'screenCenter\' ? (($(document).width() >> 1) - 260) + \'px\' : (popup.offset().left + parseInt(win.position.x)) + \'px\',\n
                      position: \'absolute\',\n
                      top: win.position.y == \'top\' ? (popup.offset().top - 312) + \'px\' :\n
                           win.position.y == \'center\' ? (popup.offset().top - 156) + \'px\' :\n
                           win.position.y == \'bottom\' ? (popup.offset().top + 25) + \'px\' : (popup.offset().top + parseInt(win.position.y)) + \'px\'\n
                    });\n
                }\n
                else\n
                {\n
                  container = $($this);\n
                  container.html(controlHtml);\n
                }\n
                // initialize the objects to the source code just injected\n
                var tbody = container.find(\'tbody:first\');\n
                colorMapDiv = tbody.find(\'div.Map:first\');\n
                colorBarDiv = tbody.find(\'div.Bar:first\');\n
                var MapMaps = colorMapDiv.find(\'span\'),\n
                    BarMaps = colorBarDiv.find(\'span\');\n
                colorMapL1 = MapMaps.filter(\'.Map1:first\');\n
                colorMapL2 = MapMaps.filter(\'.Map2:first\');\n
                colorMapL3 = MapMaps.filter(\'.Map3:first\');\n
                colorBarL1 = BarMaps.filter(\'.Map1:first\');\n
                colorBarL2 = BarMaps.filter(\'.Map2:first\');\n
                colorBarL3 = BarMaps.filter(\'.Map3:first\');\n
                colorBarL4 = BarMaps.filter(\'.Map4:first\');\n
                colorBarL5 = BarMaps.filter(\'.Map5:first\');\n
                colorBarL6 = BarMaps.filter(\'.Map6:first\');\n
                // create color pickers and maps\n
                colorMap = new Slider(colorMapDiv,\n
                  {\n
                    map:\n
                    {\n
                      width: images.colorMap.width,\n
                      height: images.colorMap.height\n
                    },\n
                    arrow:\n
                    {\n
                      image: images.clientPath + images.colorMap.arrow.file,\n
                      width: images.colorMap.arrow.width,\n
                      height: images.colorMap.arrow.height\n
                    }\n
                  });\n
                colorMap.bind(mapValueChanged);\n
                colorBar = new Slider(colorBarDiv,\n
                  {\n
                    map:\n
                    {\n
                      width: images.colorBar.width,\n
                      height: images.colorBar.height\n
                    },\n
                    arrow:\n
                    {\n
                      image: images.clientPath + images.colorBar.arrow.file,\n
                      width: images.colorBar.arrow.width,\n
                      height: images.colorBar.arrow.height\n
                    }\n
                  });\n
                colorBar.bind(colorBarValueChanged);\n
                colorPicker = new ColorValuePicker(tbody, color.active, win.expandable && win.bindToInput ? win.input : null, win.alphaPrecision);\n
                var hex = all != null ? all.hex : null,\n
                    preview = tbody.find(\'.Preview\'),\n
                    button = tbody.find(\'.Button\');\n
                activePreview = preview.find(\'.Active:first\').css({ backgroundColor: hex && \'#\' + hex || \'transparent\' });\n
                currentPreview = preview.find(\'.Current:first\').css({ backgroundColor: hex && \'#\' + hex || \'transparent\' }).bind(\'click\', currentClicked);\n
                setAlpha.call($this, currentPreview, Math.precision(color.current.val(\'a\') * 100) / 255, 4);\n
                okButton = button.find(\'.Ok:first\').bind(\'click\', okClicked);\n
                cancelButton = button.find(\'.Cancel:first\').bind(\'click\', cancelClicked);\n
                grid = button.find(\'.Grid:first\');\n
                setTimeout(\n
                  function()\n
                  {\n
                    setImg.call($this, colorMapL1, images.clientPath + \'Maps.png\');\n
                    setImg.call($this, colorMapL2, images.clientPath + \'Maps.png\');\n
                    setImg.call($this, colorMapL3, images.clientPath + \'map-opacity.png\');\n
                    setImg.call($this, colorBarL1, images.clientPath + \'Bars.png\');\n
                    setImg.call($this, colorBarL2, images.clientPath + \'Bars.png\');\n
                    setImg.call($this, colorBarL3, images.clientPath + \'Bars.png\');\n
                    setImg.call($this, colorBarL4, images.clientPath + \'Bars.png\');\n
                    setImg.call($this, colorBarL5, images.clientPath + \'bar-opacity.png\');\n
                    setImg.call($this, colorBarL6, images.clientPath + \'AlphaBar.png\');\n
                    setImg.call($this, preview.find(\'div:first\'), images.clientPath + \'preview-opacity.png\');\n
                  }, 0);\n
                tbody.find(\'td.Radio input\').bind(\'click\', radioClicked);\n
                // initialize quick list\n
                if (color.quickList && color.quickList.length > 0)\n
                {\n
                  var html = \'\';\n
                  for (i = 0; i < color.quickList.length; i++)\n
                  {\n
                    /* if default colors are hex strings, change them to color objects */\n
                    if ((typeof (color.quickList[i])).toString().toLowerCase() == \'string\') color.quickList[i] = new Color({ hex: color.quickList[i] });\n
                    var alpha = color.quickList[i].val(\'a\');\n
                    var ahex = color.quickList[i].val(\'ahex\');\n
                    if (!win.alphaSupport && ahex) ahex = ahex.substring(0, 6) + \'ff\';\n
                    var quickHex = color.quickList[i].val(\'hex\');\n
                    if(!ahex) ahex = "00000000";\n
                    html+=\'<span class="QuickColor"\' + (ahex && \' title="#\' + ahex + \'"\' || \'none\') + \' style="background-color:\' + (quickHex && \'#\' + quickHex || \'\') + \';\' + (quickHex ? \'\' : \'background-image:url(\' + images.clientPath + \'NoColor.png)\') + (win.alphaSupport && alpha && alpha < 255 ? \';opacity:\' + Math.precision(alpha / 255, 4) + \';filter:Alpha(opacity=\' + Math.precision(alpha / 2.55, 4) + \')\' : \'\') + \'">&nbsp;</span>\';\n
                  }\n
                  setImg.call($this, grid, images.clientPath + \'bar-opacity.png\');\n
                  grid.html(html);\n
                  grid.find(\'.QuickColor\').click(quickPickClicked);\n
                }\n
                setColorMode.call($this, settings.color.mode);\n
                color.active.bind(activeColorChanged);\n
                $.isFunction(liveCallback) && color.active.bind(liveCallback);\n
                color.current.bind(currentColorChanged);\n
                // bind to input\n
                if (win.expandable)\n
                {\n
                  $this.icon = popup.parents(\'.Icon:first\');\n
                  iconColor = $this.icon.find(\'.Color:first\').css({ backgroundColor: hex && \'#\' + hex || \'transparent\' });\n
                  iconAlpha = $this.icon.find(\'.Alpha:first\');\n
                  setImg.call($this, iconAlpha, images.clientPath + \'bar-opacity.png\');\n
                  setAlpha.call($this, iconAlpha, Math.precision(((255 - (all != null ? all.a : 0)) * 100) / 255, 4));\n
                  iconImage = $this.icon.find(\'.Image:first\').css(\n
                    {\n
                      backgroundImage: \'url(\\\'\' + images.clientPath + images.picker.file + \'\\\')\'\n
                    }).bind(\'click\', iconImageClicked);\n
                  if (win.bindToInput&&win.updateInputColor)\n
                    win.input.css(\n
                      {\n
                        backgroundColor: hex && \'#\' + hex || \'transparent\',\n
                        color: all == null || all.v > 75 ? \'#000000\' : \'#ffffff\'\n
                      });\n
                  moveBar = tbody.find(\'.Move:first\').bind(\'mousedown\', moveBarMouseDown);\n
                  color.active.bind(expandableColorChanged);\n
                }\n
                else show.call($this);\n
              },\n
            destroy =\n
              function()\n
              {\n
                container.find(\'td.Radio input\').unbind(\'click\', radioClicked);\n
                currentPreview.unbind(\'click\', currentClicked);\n
                cancelButton.unbind(\'click\', cancelClicked);\n
                okButton.unbind(\'click\', okClicked);\n
                if (settings.window.expandable)\n
                {\n
                  iconImage.unbind(\'click\', iconImageClicked);\n
                  moveBar.unbind(\'mousedown\', moveBarMouseDown);\n
                  $this.icon = null;\n
                }\n
                container.find(\'.QuickColor\').unbind(\'click\', quickPickClicked);\n
                colorMapDiv = null;\n
                colorBarDiv = null;\n
                colorMapL1 = null;\n
                colorMapL2 = null;\n
                colorMapL3 = null;\n
                colorBarL1 = null;\n
                colorBarL2 = null;\n
                colorBarL3 = null;\n
                colorBarL4 = null;\n
                colorBarL5 = null;\n
                colorBarL6 = null;\n
                colorMap.destroy();\n
                colorMap = null;\n
                colorBar.destroy();\n
                colorBar = null;\n
                colorPicker.destroy();\n
                colorPicker = null;\n
                activePreview = null;\n
                currentPreview = null;\n
                okButton = null;\n
                cancelButton = null;\n
                grid = null;\n
                commitCallback = null;\n
                cancelCallback = null;\n
                liveCallback = null;\n
                container.html(\'\');\n
                for (i = 0; i < List.length; i++) if (List[i] == $this) List.splice(i, 1);\n
              },\n
            images = settings.images, // local copies for YUI compressor\n
            localization = settings.localization,\n
            color =\n
              {\n
                active: (typeof(settings.color.active)).toString().toLowerCase() == \'string\' ? new Color({ ahex: !settings.window.alphaSupport && settings.color.active ? settings.color.active.substring(0, 6) + \'ff\' : settings.color.active }) : new Color({ ahex: !settings.window.alphaSupport && settings.color.active.val(\'ahex\') ? settings.color.active.val(\'ahex\').substring(0, 6) + \'ff\' : settings.color.active.val(\'ahex\') }),\n
                current: (typeof(settings.color.active)).toString().toLowerCase() == \'string\' ? new Color({ ahex: !settings.window.alphaSupport && settings.color.active ? settings.color.active.substring(0, 6) + \'ff\' : settings.color.active }) : new Color({ ahex: !settings.window.alphaSupport && settings.color.active.val(\'ahex\') ? settings.color.active.val(\'ahex\').substring(0, 6) + \'ff\' : settings.color.active.val(\'ahex\') }),\n
                quickList: settings.color.quickList\n
              };\n
          $.extend(true, $this, // public properties, methods, and callbacks\n
            {\n
              commitCallback: commitCallback, // commitCallback function can be overridden to return the selected color to a method you specify when the user clicks "OK"\n
              liveCallback: liveCallback, // liveCallback function can be overridden to return the selected color to a method you specify in live mode (continuous update)\n
              cancelCallback: cancelCallback, // cancelCallback function can be overridden to a method you specify when the user clicks "Cancel"\n
              color: color,\n
              show: show,\n
              hide: hide,\n
              destroy: destroy // destroys this control entirely, removing all events and objects, and removing itself from the List\n
            });\n
          List.push($this);\n
          setTimeout(\n
            function()\n
            {\n
              initialize.call($this);\n
            }, 0);\n
        });\n
    };\n
  $.fn.jPicker.defaults = /* jPicker defaults - you can change anything in this section (such as the clientPath to your images) without fear of breaking the program */\n
      {\n
      window:\n
        {\n
          title: null, /* any title for the jPicker window itself - displays "Drag Markers To Pick A Color" if left null */\n
          effects:\n
          {\n
            type: \'slide\', /* effect used to show/hide an expandable picker. Acceptable values "slide", "show", "fade" */\n
            speed:\n
            {\n
              show: \'slow\', /* duration of "show" effect. Acceptable values are "fast", "slow", or time in ms */\n
              hide: \'fast\' /* duration of "hide" effect. Acceptable values are "fast", "slow", or time in ms */\n
            }\n
          },\n
          position:\n
          {\n
            x: \'screenCenter\', /* acceptable values "left", "center", "right", "screenCenter", or relative px value */\n
            y: \'top\' /* acceptable values "top", "bottom", "center", or relative px value */\n
          },\n
          expandable: false, /* default to large static picker - set to true to make an expandable picker (small icon with popup) - set automatically when binded to input element */\n
          liveUpdate: true, /* set false if you want the user to have to click "OK" before the binded input box updates values (always "true" for expandable picker) */\n
          alphaSupport: false, /* set to true to enable alpha picking */\n
          alphaPrecision: 0, /* set decimal precision for alpha percentage display - hex codes do not map directly to percentage integers - range 0-2 */\n
          updateInputColor: true /* set to false to prevent binded input colors from changing */\n
        },\n
      color:\n
        {\n
          mode: \'h\', /* acceptabled values "h" (hue), "s" (saturation), "v" (value), "r" (red), "g" (green), "b" (blue), "a" (alpha) */\n
          active: new Color({ ahex: \'#ffcc00ff\' }), /* acceptable values are any declared $.jPicker.Color object or string HEX value (e.g. #ffc000) WITH OR WITHOUT the "#" prefix */\n
          quickList: /* the quick pick color list */\n
            [\n
              new Color({ h: 360, s: 33, v: 100 }), /* acceptable values are any declared $.jPicker.Color object or string HEX value (e.g. #ffc000) WITH OR WITHOUT the "#" prefix */\n
              new Color({ h: 360, s: 66, v: 100 }),\n
              new Color({ h: 360, s: 100, v: 100 }),\n
              new Color({ h: 360, s: 100, v: 75 }),\n
              new Color({ h: 360, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 100 }),\n
              new Color({ h: 30, s: 33, v: 100 }),\n
              new Color({ h: 30, s: 66, v: 100 }),\n
              new Color({ h: 30, s: 100, v: 100 }),\n
              new Color({ h: 30, s: 100, v: 75 }),\n
              new Color({ h: 30, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 90 }),\n
              new Color({ h: 60, s: 33, v: 100 }),\n
              new Color({ h: 60, s: 66, v: 100 }),\n
              new Color({ h: 60, s: 100, v: 100 }),\n
              new Color({ h: 60, s: 100, v: 75 }),\n
              new Color({ h: 60, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 80 }),\n
              new Color({ h: 90, s: 33, v: 100 }),\n
              new Color({ h: 90, s: 66, v: 100 }),\n
              new Color({ h: 90, s: 100, v: 100 }),\n
              new Color({ h: 90, s: 100, v: 75 }),\n
              new Color({ h: 90, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 70 }),\n
              new Color({ h: 120, s: 33, v: 100 }),\n
              new Color({ h: 120, s: 66, v: 100 }),\n
              new Color({ h: 120, s: 100, v: 100 }),\n
              new Color({ h: 120, s: 100, v: 75 }),\n
              new Color({ h: 120, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 60 }),\n
              new Color({ h: 150, s: 33, v: 100 }),\n
              new Color({ h: 150, s: 66, v: 100 }),\n
              new Color({ h: 150, s: 100, v: 100 }),\n
              new Color({ h: 150, s: 100, v: 75 }),\n
              new Color({ h: 150, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 50 }),\n
              new Color({ h: 180, s: 33, v: 100 }),\n
              new Color({ h: 180, s: 66, v: 100 }),\n
              new Color({ h: 180, s: 100, v: 100 }),\n
              new Color({ h: 180, s: 100, v: 75 }),\n
              new Color({ h: 180, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 40 }),\n
              new Color({ h: 210, s: 33, v: 100 }),\n
              new Color({ h: 210, s: 66, v: 100 }),\n
              new Color({ h: 210, s: 100, v: 100 }),\n
              new Color({ h: 210, s: 100, v: 75 }),\n
              new Color({ h: 210, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 30 }),\n
              new Color({ h: 240, s: 33, v: 100 }),\n
              new Color({ h: 240, s: 66, v: 100 }),\n
              new Color({ h: 240, s: 100, v: 100 }),\n
              new Color({ h: 240, s: 100, v: 75 }),\n
              new Color({ h: 240, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 20 }),\n
              new Color({ h: 270, s: 33, v: 100 }),\n
              new Color({ h: 270, s: 66, v: 100 }),\n
              new Color({ h: 270, s: 100, v: 100 }),\n
              new Color({ h: 270, s: 100, v: 75 }),\n
              new Color({ h: 270, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 10 }),\n
              new Color({ h: 300, s: 33, v: 100 }),\n
              new Color({ h: 300, s: 66, v: 100 }),\n
              new Color({ h: 300, s: 100, v: 100 }),\n
              new Color({ h: 300, s: 100, v: 75 }),\n
              new Color({ h: 300, s: 100, v: 50 }),\n
              new Color({ h: 180, s: 0, v: 0 }),\n
              new Color({ h: 330, s: 33, v: 100 }),\n
              new Color({ h: 330, s: 66, v: 100 }),\n
              new Color({ h: 330, s: 100, v: 100 }),\n
              new Color({ h: 330, s: 100, v: 75 }),\n
              new Color({ h: 330, s: 100, v: 50 }),\n
              new Color()\n
            ]\n
        },\n
      images:\n
        {\n
          clientPath: \'/jPicker/images/\', /* Path to image files */\n
          colorMap:\n
          {\n
            width: 256,\n
            height: 256,\n
            arrow:\n
            {\n
              file: \'mappoint.gif\', /* ColorMap arrow icon */\n
              width: 15,\n
              height: 15\n
            }\n
          },\n
          colorBar:\n
          {\n
            width: 20,\n
            height: 256,\n
            arrow:\n
            {\n
              file: \'rangearrows.gif\', /* ColorBar arrow icon */\n
              width: 20,\n
              height: 7\n
            }\n
          },\n
          picker:\n
          {\n
            file: \'picker.gif\', /* Color Picker icon */\n
            width: 25,\n
            height: 24\n
          }\n
        },\n
      localization: /* alter these to change the text presented by the picker (e.g. different language) */\n
        {\n
          text:\n
          {\n
            title: \'Drag Markers To Pick A Color\',\n
            newColor: \'new\',\n
            currentColor: \'current\',\n
            ok: \'OK\',\n
            cancel: \'Cancel\'\n
          },\n
          tooltips:\n
          {\n
            colors:\n
            {\n
              newColor: \'New Color - Press &ldquo;OK&rdquo; To Commit\',\n
              currentColor: \'Click To Revert To Original Color\'\n
            },\n
            buttons:\n
            {\n
              ok: \'Commit To This Color Selection\',\n
              cancel: \'Cancel And Revert To Original Color\'\n
            },\n
            hue:\n
            {\n
              radio: \'Set To &ldquo;Hue&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Hue&rdquo; Value (0-360&deg;)\'\n
            },\n
            saturation:\n
            {\n
              radio: \'Set To &ldquo;Saturation&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Saturation&rdquo; Value (0-100%)\'\n
            },\n
            value:\n
            {\n
              radio: \'Set To &ldquo;Value&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Value&rdquo; Value (0-100%)\'\n
            },\n
            red:\n
            {\n
              radio: \'Set To &ldquo;Red&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Red&rdquo; Value (0-255)\'\n
            },\n
            green:\n
            {\n
              radio: \'Set To &ldquo;Green&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Green&rdquo; Value (0-255)\'\n
            },\n
            blue:\n
            {\n
              radio: \'Set To &ldquo;Blue&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Blue&rdquo; Value (0-255)\'\n
            },\n
            alpha:\n
            {\n
              radio: \'Set To &ldquo;Alpha&rdquo; Color Mode\',\n
              textbox: \'Enter A &ldquo;Alpha&rdquo; Value (0-100)\'\n
            },\n
            hex:\n
            {\n
              textbox: \'Enter A &ldquo;Hex&rdquo; Color Value (#000000-#ffffff)\',\n
              alpha: \'Enter A &ldquo;Alpha&rdquo; Value (#00-#ff)\'\n
            }\n
          }\n
        }\n
    };\n
})(jQuery, \'1.1.6\');

]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
