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
            <value> <string>ts52852702.09</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.jgraduate.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\n
 * jGraduate 0.4\n
 *\n
 * jQuery Plugin for a gradient picker\n
 *\n
 * Copyright (c) 2010 Jeff Schiller\n
 * http://blog.codedread.com/\n
 * Copyright (c) 2010 Alexis Deveria\n
 * http://a.deveria.com/\n
 *\n
 * Apache 2 License\n
\n
jGraduate( options, okCallback, cancelCallback )\n
\n
where options is an object literal:\n
  {\n
    window: { title: "Pick the start color and opacity for the gradient" },\n
    images: { clientPath: "images/" },\n
    paint: a Paint object,\n
    newstop: String of value "same", "inverse", "black" or "white" \n
         OR object with one or both values {color: #Hex color, opac: number 0-1}\n
  }\n
 \n
- the Paint object is:\n
  Paint {\n
    type: String, // one of "none", "solidColor", "linearGradient", "radialGradient"\n
    alpha: Number representing opacity (0-100),\n
    solidColor: String representing #RRGGBB hex of color,\n
    linearGradient: object of interface SVGLinearGradientElement,\n
    radialGradient: object of interface SVGRadialGradientElement,\n
  }\n
\n
$.jGraduate.Paint() -> constructs a \'none\' color\n
$.jGraduate.Paint({copy: o}) -> creates a copy of the paint o\n
$.jGraduate.Paint({hex: "#rrggbb"}) -> creates a solid color paint with hex = "#rrggbb"\n
$.jGraduate.Paint({linearGradient: o, a: 50}) -> creates a linear gradient paint with opacity=0.5\n
$.jGraduate.Paint({radialGradient: o, a: 7}) -> creates a radial gradient paint with opacity=0.07\n
$.jGraduate.Paint({hex: "#rrggbb", linearGradient: o}) -> throws an exception?\n
\n
- picker accepts the following object as input:\n
  {\n
    okCallback: function to call when Ok is pressed\n
    cancelCallback: function to call when Cancel is pressed\n
    paint: object describing the paint to display initially, if not set, then default to opaque white\n
  }\n
\n
- okCallback receives a Paint object\n
\n
 *\n
 */\n
 \n
(function() {\n
 \n
var ns = { svg: \'http://www.w3.org/2000/svg\', xlink: \'http://www.w3.org/1999/xlink\' };\n
if(!window.console) {\n
  window.console = new function() {\n
    this.log = function(str) {};\n
    this.dir = function(str) {};\n
  };\n
}\n
\n
$.jGraduate = { \n
  Paint:\n
    function(opt) {\n
      var options = opt || {};\n
      this.alpha = isNaN(options.alpha) ? 100 : options.alpha;\n
      // copy paint object\n
        if (options.copy) {\n
          this.type = options.copy.type;\n
          this.alpha = options.copy.alpha;\n
        this.solidColor = null;\n
        this.linearGradient = null;\n
        this.radialGradient = null;\n
\n
          switch(this.type) {\n
            case "none":\n
              break;\n
            case "solidColor":\n
              this.solidColor = options.copy.solidColor;\n
              break;\n
            case "linearGradient":\n
              this.linearGradient = options.copy.linearGradient.cloneNode(true);\n
              break;\n
            case "radialGradient":\n
              this.radialGradient = options.copy.radialGradient.cloneNode(true);\n
              break;\n
          }\n
        }\n
        // create linear gradient paint\n
        else if (options.linearGradient) {\n
          this.type = "linearGradient";\n
          this.solidColor = null;\n
          this.radialGradient = null;\n
          this.linearGradient = options.linearGradient.cloneNode(true);\n
        }\n
        // create linear gradient paint\n
        else if (options.radialGradient) {\n
          this.type = "radialGradient";\n
          this.solidColor = null;\n
          this.linearGradient = null;\n
          this.radialGradient = options.radialGradient.cloneNode(true);\n
        }\n
        // create solid color paint\n
        else if (options.solidColor) {\n
          this.type = "solidColor";\n
          this.solidColor = options.solidColor;\n
        }\n
        // create empty paint\n
        else {\n
          this.type = "none";\n
          this.solidColor = null;\n
          this.linearGradient = null;\n
          this.radialGradient = null;\n
        }\n
    }\n
};\n
\n
jQuery.fn.jGraduateDefaults = {\n
  paint: new $.jGraduate.Paint(),\n
  window: {\n
    pickerTitle: "Drag markers to pick a paint"\n
  },\n
  images: {\n
    clientPath: "images/"\n
  },\n
  newstop: \'inverse\' // same, inverse, black, white\n
};\n
\n
var isGecko = navigator.userAgent.indexOf(\'Gecko/\') >= 0;\n
\n
function setAttrs(elem, attrs) {\n
  if(isGecko) {\n
    for (var aname in attrs) elem.setAttribute(aname, attrs[aname]);\n
  } else {\n
    for (var aname in attrs) {\n
      var val = attrs[aname], prop = elem[aname];\n
      if(prop && prop.constructor === \'SVGLength\') {\n
        prop.baseVal.value = val;\n
      } else {\n
        elem.setAttribute(aname, val);\n
      }\n
    }\n
  }\n
}\n
\n
function mkElem(name, attrs, newparent) {\n
  var elem = document.createElementNS(ns.svg, name);\n
  setAttrs(elem, attrs);\n
  if(newparent) newparent.appendChild(elem);\n
  return elem;\n
}\n
\n
jQuery.fn.jGraduate =\n
  function(options) {\n
    var $arguments = arguments;\n
    return this.each( function() {\n
      var $this = $(this), $settings = $.extend(true, {}, jQuery.fn.jGraduateDefaults, options),\n
        id = $this.attr(\'id\'),\n
        idref = \'#\'+$this.attr(\'id\')+\' \';\n
      \n
            if (!idref)\n
            {\n
              alert(\'Container element must have an id attribute to maintain unique id strings for sub-elements.\');\n
              return;\n
            }\n
            \n
            var okClicked = function() {\n
              switch ( $this.paint.type ) {\n
                case "radialGradient":\n
                  $this.paint.linearGradient = null;\n
                  break;\n
                case "linearGradient":\n
                  $this.paint.radialGradient = null;\n
                  break;\n
                case "solidColor":\n
                  $this.paint.radialGradient = $this.paint.linearGradient = null;\n
                  break;\n
              }\n
              $.isFunction($this.okCallback) && $this.okCallback($this.paint);\n
              $this.hide();\n
            },\n
            cancelClicked = function() {\n
              $.isFunction($this.cancelCallback) && $this.cancelCallback();\n
              $this.hide();\n
            };\n
\n
            $.extend(true, $this, // public properties, methods, and callbacks\n
              {\n
                // make a copy of the incoming paint\n
                paint: new $.jGraduate.Paint({copy: $settings.paint}),\n
                okCallback: $.isFunction($arguments[1]) && $arguments[1] || null,\n
                cancelCallback: $.isFunction($arguments[2]) && $arguments[2] || null\n
              });\n
\n
      var pos = $this.position(),\n
        color = null;\n
      var $win = $(window);\n
\n
      if ($this.paint.type == "none") {\n
        $this.paint = $.jGraduate.Paint({solidColor: \'ffffff\'});\n
      }\n
      \n
            $this.addClass(\'jGraduate_Picker\');\n
            $this.html(\'<ul class="jGraduate_tabs">\' +\n
                    \'<li class="jGraduate_tab_color jGraduate_tab_current" data-type="col">Solid Color</li>\' +\n
                    \'<li class="jGraduate_tab_lingrad" data-type="lg">Linear Gradient</li>\' +\n
                    \'<li class="jGraduate_tab_radgrad" data-type="rg">Radial Gradient</li>\' +\n
                  \'</ul>\' +\n
                  \'<div class="jGraduate_colPick"></div>\' +\n
                  \'<div class="jGraduate_gradPick"></div>\' +\n
            \'<div class="jGraduate_LightBox"></div>\' +\n
            \'<div id="\' + id + \'_jGraduate_stopPicker" class="jGraduate_stopPicker"></div>\'\n
                  \n
                  \n
                  );\n
      var colPicker = $(idref + \'> .jGraduate_colPick\');\n
      var gradPicker = $(idref + \'> .jGraduate_gradPick\');\n
      \n
            gradPicker.html(\n
              \'<div id="\' + id + \'_jGraduate_Swatch" class="jGraduate_Swatch">\' +\n
                \'<h2 class="jGraduate_Title">\' + $settings.window.pickerTitle + \'</h2>\' +\n
                \'<div id="\' + id + \'_jGraduate_GradContainer" class="jGraduate_GradContainer"></div>\' +\n
                \'<div id="\' + id + \'_jGraduate_StopSlider" class="jGraduate_StopSlider"></div>\' +\n
              \'</div>\' + \n
              \'<div class="jGraduate_Form jGraduate_Points jGraduate_lg_field">\' +\n
                \'<div class="jGraduate_StopSection">\' +\n
                  \'<label class="jGraduate_Form_Heading">Begin Point</label>\' +\n
                  \'<div class="jGraduate_Form_Section">\' +\n
                    \'<label>x:</label>\' +\n
                    \'<input type="text" id="\' + id + \'_jGraduate_x1" size="3" title="Enter starting x value between 0.0 and 1.0"/>\' +\n
                    \'<label> y:</label>\' +\n
                    \'<input type="text" id="\' + id + \'_jGraduate_y1" size="3" title="Enter starting y value between 0.0 and 1.0"/>\' +\n
                  \'</div>\' +\n
                \'</div>\' +\n
                \'<div class="jGraduate_StopSection">\' +\n
                  \'<label class="jGraduate_Form_Heading">End Point</label>\' +\n
                  \'<div class="jGraduate_Form_Section">\' +\n
                    \'<label>x:</label>\' +\n
                    \'<input type="text" id="\' + id + \'_jGraduate_x2" size="3" title="Enter ending x value between 0.0 and 1.0"/>\' +\n
                    \'<label> y:</label>\' +\n
                    \'<input type="text" id="\' + id + \'_jGraduate_y2" size="3" title="Enter ending y value between 0.0 and 1.0"/>\' +\n
                  \'</div>\' +\n
                \'</div>\' +\n
              \'</div>\' +\n
              \'<div class="jGraduate_Form jGraduate_Points jGraduate_rg_field">\' +\n
          \'<div class="jGraduate_StopSection">\' +\n
            \'<label class="jGraduate_Form_Heading">Center Point</label>\' +\n
            \'<div class="jGraduate_Form_Section">\' +\n
              \'<label>x:</label>\' +\n
              \'<input type="text" id="\' + id + \'_jGraduate_cx" size="3" title="Enter x value between 0.0 and 1.0"/>\' +\n
              \'<label> y:</label>\' +\n
              \'<input type="text" id="\' + id + \'_jGraduate_cy" size="3" title="Enter y value between 0.0 and 1.0"/>\' +\n
            \'</div>\' +\n
          \'</div>\' +\n
          \'<div class="jGraduate_StopSection">\' +\n
            \'<label class="jGraduate_Form_Heading">Focal Point</label>\' +\n
            \'<div class="jGraduate_Form_Section">\' +\n
              \'<label>Match center: <input type="checkbox" checked="checked" id="\' + id + \'_jGraduate_match_ctr"/></label><br/>\' +\n
              \'<label>x:</label>\' +\n
              \'<input type="text" id="\' + id + \'_jGraduate_fx" size="3" title="Enter x value between 0.0 and 1.0"/>\' +\n
              \'<label> y:</label>\' +\n
              \'<input type="text" id="\' + id + \'_jGraduate_fy" size="3" title="Enter y value between 0.0 and 1.0"/>\' +\n
            \'</div>\' +\n
          \'</div>\' +\n
              \'</div>\' +\n
        \'<div class="jGraduate_StopSection jGraduate_SpreadMethod">\' +\n
          \'<label class="jGraduate_Form_Heading">Spread method</label>\' +\n
          \'<div class="jGraduate_Form_Section">\' +\n
            \'<select class="jGraduate_spreadMethod">\' +\n
              \'<option value=pad selected>Pad</option>\' +\n
              \'<option value=reflect>Reflect</option>\' +\n
              \'<option value=repeat>Repeat</option>\' +\n
            \'</select>\' + \n
          \'</div>\' +\n
        \'</div>\' +\n
              \'<div class="jGraduate_Form">\' +\n
                \'<div class="jGraduate_Slider jGraduate_RadiusField jGraduate_rg_field">\' +\n
            \'<label class="prelabel">Radius:</label>\' +\n
            \'<div id="\' + id + \'_jGraduate_Radius" class="jGraduate_SliderBar jGraduate_Radius" title="Click to set radius">\' +\n
              \'<img id="\' + id + \'_jGraduate_RadiusArrows" class="jGraduate_RadiusArrows" src="\' + $settings.images.clientPath + \'rangearrows2.gif">\' +\n
            \'</div>\' +\n
            \'<label><input type="text" id="\' + id + \'_jGraduate_RadiusInput" size="3" value="100"/>%</label>\' + \n
                \'</div>\' +\n
                \'<div class="jGraduate_Slider jGraduate_EllipField jGraduate_rg_field">\' +\n
            \'<label class="prelabel">Ellip:</label>\' +\n
            \'<div id="\' + id + \'_jGraduate_Ellip" class="jGraduate_SliderBar jGraduate_Ellip" title="Click to set Ellip">\' +\n
              \'<img id="\' + id + \'_jGraduate_EllipArrows" class="jGraduate_EllipArrows" src="\' + $settings.images.clientPath + \'rangearrows2.gif">\' +\n
            \'</div>\' +\n
            \'<label><input type="text" id="\' + id + \'_jGraduate_EllipInput" size="3" value="0"/>%</label>\' + \n
                \'</div>\' +\n
                \'<div class="jGraduate_Slider jGraduate_AngleField jGraduate_rg_field">\' +\n
            \'<label class="prelabel">Angle:</label>\' +\n
            \'<div id="\' + id + \'_jGraduate_Angle" class="jGraduate_SliderBar jGraduate_Angle" title="Click to set Angle">\' +\n
              \'<img id="\' + id + \'_jGraduate_AngleArrows" class="jGraduate_AngleArrows" src="\' + $settings.images.clientPath + \'rangearrows2.gif">\' +\n
            \'</div>\' +\n
            \'<label><input type="text" id="\' + id + \'_jGraduate_AngleInput" size="3" value="0"/>º&nbsp;</label>\' + \n
                \'</div>\' +\n
                \'<div class="jGraduate_Slider jGraduate_OpacField">\' +\n
            \'<label class="prelabel">Opac:</label>\' +\n
            \'<div id="\' + id + \'_jGraduate_Opac" class="jGraduate_SliderBar jGraduate_Opac" title="Click to set Opac">\' +\n
              \'<img id="\' + id + \'_jGraduate_OpacArrows" class="jGraduate_OpacArrows" src="\' + $settings.images.clientPath + \'rangearrows2.gif">\' +\n
            \'</div>\' +\n
            \'<label><input type="text" id="\' + id + \'_jGraduate_OpacInput" size="3" value="100"/>%</label>\' + \n
                \'</div>\' +\n
              \'</div>\' +\n
              \'<div class="jGraduate_OkCancel">\' +\n
                \'<input type="button" id="\' + id + \'_jGraduate_Ok" class="jGraduate_Ok" value="OK"/>\' +\n
                \'<input type="button" id="\' + id + \'_jGraduate_Cancel" class="jGraduate_Cancel" value="Cancel"/>\' +\n
              \'</div>\');\n
              \n
      // --------------\n
            // Set up all the SVG elements (the gradient, stops and rectangle)\n
            var MAX = 256, MARGINX = 0, MARGINY = 0, STOP_RADIUS = 15/2,\n
              SIZEX = MAX - 2*MARGINX, SIZEY = MAX - 2*MARGINY;\n
              \n
            var curType, curGradient, previewRect;  \n
            \n
      var attr_input = {};\n
            \n
            var SLIDERW = 145;\n
            $(\'.jGraduate_SliderBar\').width(SLIDERW);\n
      \n
      var container = $(\'#\' + id+\'_jGraduate_GradContainer\')[0];\n
      \n
      var svg = mkElem(\'svg\', {\n
        id: id + \'_jgraduate_svg\',\n
        width: MAX,\n
        height: MAX,\n
        xmlns: ns.svg\n
      }, container);\n
      \n
      // if we are sent a gradient, import it \n
      \n
      curType = curType || $this.paint.type;\n
      \n
      var grad = curGradient = $this.paint[curType];\n
      \n
      var gradalpha = $this.paint.alpha;\n
      \n
      var isSolid = curType === \'solidColor\';\n
      \n
      // Make any missing gradients\n
      switch ( curType ) {\n
        case "solidColor":\n
          // fall through\n
        case "linearGradient":\n
          if(!isSolid) {\n
            curGradient.id = id+\'_lg_jgraduate_grad\';\n
            grad = curGradient = svg.appendChild(curGradient);//.cloneNode(true));\n
          }\n
          mkElem(\'radialGradient\', {\n
            id: id + \'_rg_jgraduate_grad\'\n
          }, svg);\n
          if(curType === "linearGradient") break;\n
        case "radialGradient":\n
          if(!isSolid) {\n
            curGradient.id = id+\'_rg_jgraduate_grad\';\n
            grad = curGradient = svg.appendChild(curGradient);//.cloneNode(true));\n
          }\n
          mkElem(\'linearGradient\', {\n
            id: id + \'_lg_jgraduate_grad\',\n
            x1: 0,\n
            y1: 0,\n
            x2: 1,\n
            y2: 0\n
          }, svg);\n
      }\n
      \n
      if(isSolid) {\n
        grad = curGradient = $(\'#\' + id + \'_lg_jgraduate_grad\')[0];\n
        var color = $this.paint[curType];\n
        mkStop(0, \'#\' + color, 1);\n
        \n
        var type = typeof $settings.newstop;\n
        \n
        if(type === \'string\') {\n
          switch ( $settings.newstop ) {\n
            case \'same\':\n
              mkStop(1, \'#\' + color, 1);        \n
              break;\n
\n
            case \'inverse\':\n
              // Invert current color for second stop\n
              var inverted = \'\';\n
              if (color.length === 3) {\n
                color = color.split("").map(function(d){return d + "" + d}).join("");\n
              }\n
              for(var i = 0; i < 6; i += 2) {\n
                var ch = color.substr(i, 2);\n
                var inv = (255 - parseInt(color.substr(i, 2), 16)).toString(16);\n
                if(inv.length < 2) inv = 0 + inv;\n
                inverted += inv;\n
              }\n
              mkStop(1, \'#\' + inverted, 1);\n
              break;\n
            \n
            case \'white\':\n
              mkStop(1, \'#ffffff\', 1);\n
              break;\n
  \n
            case \'black\':\n
              mkStop(1, \'#000000\', 1);\n
              break;\n
          }\n
        } else if(type === \'object\'){\n
          var opac = (\'opac\' in $settings.newstop) ? $settings.newstop.opac : 1;\n
          mkStop(1, ($settings.newstop.color || \'#\' + color), opac);\n
        }\n
      }\n
\n
      \n
      var x1 = parseFloat(grad.getAttribute(\'x1\')||0.0),\n
        y1 = parseFloat(grad.getAttribute(\'y1\')||0.0),\n
        x2 = parseFloat(grad.getAttribute(\'x2\')||1.0),\n
        y2 = parseFloat(grad.getAttribute(\'y2\')||0.0);\n
        \n
      var cx = parseFloat(grad.getAttribute(\'cx\')||0.5),\n
        cy = parseFloat(grad.getAttribute(\'cy\')||0.5),\n
        fx = parseFloat(grad.getAttribute(\'fx\')|| cx),\n
        fy = parseFloat(grad.getAttribute(\'fy\')|| cy);\n
\n
      \n
      var previewRect = mkElem(\'rect\', {\n
        id: id + \'_jgraduate_rect\',\n
        x: MARGINX,\n
        y: MARGINY,\n
        width: SIZEX,\n
        height: SIZEY,\n
        fill: \'url(#\'+id+\'_jgraduate_grad)\',\n
        \'fill-opacity\': gradalpha/100\n
      }, svg);\n
      \n
      // stop visuals created here\n
      var beginCoord = $(\'<div/>\').attr({\n
        \'class\': \'grad_coord jGraduate_lg_field\',\n
        title: \'Begin Stop\'\n
      }).text(1).css({\n
        top: y1 * MAX,\n
        left: x1 * MAX\n
      }).data(\'coord\', \'start\').appendTo(container);\n
      \n
      var endCoord = beginCoord.clone().text(2).css({\n
        top: y2 * MAX,\n
        left: x2 * MAX\n
      }).attr(\'title\', \'End stop\').data(\'coord\', \'end\').appendTo(container);\n
    \n
      var centerCoord = $(\'<div/>\').attr({\n
        \'class\': \'grad_coord jGraduate_rg_field\',\n
        title: \'Center stop\'\n
      }).text(\'C\').css({\n
        top: cy * MAX,\n
        left: cx * MAX\n
      }).data(\'coord\', \'center\').appendTo(container);\n
      \n
      var focusCoord = centerCoord.clone().text(\'F\').css({\n
        top: fy * MAX,\n
        left: fx * MAX,\n
        display: \'none\'\n
      }).attr(\'title\', \'Focus point\').data(\'coord\', \'focus\').appendTo(container);\n
      \n
      focusCoord[0].id = id + \'_jGraduate_focusCoord\';\n
      \n
      var coords = $(idref + \' .grad_coord\');\n
      \n
      $.each([\'x1\', \'y1\', \'x2\', \'y2\', \'cx\', \'cy\', \'fx\', \'fy\'], function(i, attr) {\n
        var attrval = curGradient.getAttribute(attr);\n
        \n
        var isRadial = isNaN(attr[1]);\n
        \n
        if(!attrval) {\n
          // Set defaults\n
          if(isRadial) {\n
            // For radial points\n
            attrval = "0.5";\n
          } else {\n
            // Only x2 is 1\n
            attrval = attr === \'x2\' ? "1.0" : "0.0";\n
          }\n
        }\n
\n
        attr_input[attr] = $(\'#\'+id+\'_jGraduate_\' + attr)\n
          .val(attrval)\n
          .change(function() {\n
            // TODO: Support values < 0 and > 1 (zoomable preview?)\n
            if (isNaN(parseFloat(this.value)) || this.value < 0) {\n
              this.value = 0.0; \n
            } else if(this.value > 1) {\n
              this.value = 1.0;\n
            }\n
            \n
            if(!(attr[0] === \'f\' && !showFocus)) {\n
              if(isRadial && curType === \'radialGradient\' || !isRadial && curType === \'linearGradient\') {\n
                curGradient.setAttribute(attr, this.value);\n
              }\n
            }\n
            \n
            if(isRadial) {\n
              var $elem = attr[0] === "c" ? centerCoord : focusCoord;\n
            } else {\n
              var $elem = attr[1] === "1" ? beginCoord : endCoord;            \n
            }\n
            \n
            var cssName = attr.indexOf(\'x\') >= 0 ? \'left\' : \'top\';\n
            \n
            $elem.css(cssName, this.value * MAX);\n
        }).change();\n
      });\n
\n
      function mkStop(n, color, opac, sel, stop_elem) {\n
        var stop = stop_elem || mkElem(\'stop\',{\'stop-color\':color,\'stop-opacity\':opac,offset:n}, curGradient);\n
        if(stop_elem) {\n
          color = stop_elem.getAttribute(\'stop-color\');\n
          opac = stop_elem.getAttribute(\'stop-opacity\');\n
          n = stop_elem.getAttribute(\'offset\');\n
        } else {\n
          curGradient.appendChild(stop);\n
        }\n
        if(opac === null) opac = 1;\n
        \n
        var picker_d = \'M-6.2,0.9c3.6-4,6.7-4.3,6.7-12.4c-0.2,7.9,3.1,8.8,6.5,12.4c3.5,3.8,2.9,9.6,0,12.3c-3.1,2.8-10.4,2.7-13.2,0C-9.6,9.9-9.4,4.4-6.2,0.9z\';\n
        \n
        var pathbg = mkElem(\'path\',{\n
          d: picker_d,\n
          fill: \'url(#jGraduate_trans)\',\n
          transform: \'translate(\' + (10 + n * MAX) + \', 26)\'\n
        }, stopGroup);\n
        \n
        var path = mkElem(\'path\',{\n
          d: picker_d,\n
          fill: color,\n
          \'fill-opacity\': opac,\n
          transform: \'translate(\' + (10 + n * MAX) + \', 26)\',\n
          stroke: \'#000\',\n
          \'stroke-width\': 1.5\n
        }, stopGroup);\n
\n
        $(path).mousedown(function(e) {\n
          selectStop(this);\n
          drag = cur_stop;\n
          $win.mousemove(dragColor).mouseup(remDrags);\n
          stop_offset = stopMakerDiv.offset();\n
          e.preventDefault();\n
          return false;\n
        }).data(\'stop\', stop).data(\'bg\', pathbg).dblclick(function() {\n
          $(\'div.jGraduate_LightBox\').show();     \n
          var colorhandle = this;\n
          var stopOpacity = +stop.getAttribute(\'stop-opacity\') || 1;\n
          var stopColor = stop.getAttribute(\'stop-color\') || 1;\n
          var thisAlpha = (parseFloat(stopOpacity)*255).toString(16);\n
          while (thisAlpha.length < 2) { thisAlpha = "0" + thisAlpha; }\n
          color = stopColor.substr(1) + thisAlpha;\n
          $(\'#\'+id+\'_jGraduate_stopPicker\').css({\'left\': 100, \'bottom\': 15}).jPicker({\n
              window: { title: "Pick the start color and opacity for the gradient" },\n
              images: { clientPath: $settings.images.clientPath },\n
              color: { active: color, alphaSupport: true }\n
            }, function(color, arg2){\n
              stopColor = color.val(\'hex\') ? (\'#\'+color.val(\'hex\')) : "none";\n
              stopOpacity = color.val(\'a\') !== null ? color.val(\'a\')/256 : 1;\n
              colorhandle.setAttribute(\'fill\', stopColor);\n
              colorhandle.setAttribute(\'fill-opacity\', stopOpacity);\n
              stop.setAttribute(\'stop-color\', stopColor);\n
              stop.setAttribute(\'stop-opacity\', stopOpacity);\n
              $(\'div.jGraduate_LightBox\').hide();\n
              $(\'#\'+id+\'_jGraduate_stopPicker\').hide();\n
            }, null, function() {\n
              $(\'div.jGraduate_LightBox\').hide();\n
              $(\'#\'+id+\'_jGraduate_stopPicker\').hide();\n
            });\n
        });\n
        \n
        $(curGradient).find(\'stop\').each(function() {\n
          var cur_s = $(this);\n
          if(+this.getAttribute(\'offset\') > n) {\n
            if(!color) {\n
              var newcolor = this.getAttribute(\'stop-color\');\n
              var newopac = this.getAttribute(\'stop-opacity\');\n
              stop.setAttribute(\'stop-color\', newcolor);\n
              path.setAttribute(\'fill\', newcolor);\n
              stop.setAttribute(\'stop-opacity\', newopac === null ? 1 : newopac);\n
              path.setAttribute(\'fill-opacity\', newopac === null ? 1 : newopac);\n
            }\n
            cur_s.before(stop);\n
            return false;\n
          }\n
        });\n
        if(sel) selectStop(path);\n
        return stop;\n
      }\n
      \n
      function remStop() {\n
        delStop.setAttribute(\'display\', \'none\');\n
        var path = $(cur_stop);\n
        var stop = path.data(\'stop\');\n
        var bg = path.data(\'bg\');\n
        $([cur_stop, stop, bg]).remove();\n
      }\n
      \n
        \n
      var stops, stopGroup;\n
      \n
      var stopMakerDiv = $(\'#\' + id + \'_jGraduate_StopSlider\');\n
\n
      var cur_stop, stopGroup, stopMakerSVG, drag;\n
      \n
      var delStop = mkElem(\'path\',{\n
        d:\'m9.75,-6l-19.5,19.5m0,-19.5l19.5,19.5\',\n
        fill:\'none\',\n
        stroke:\'#D00\',\n
        \'stroke-width\':5,\n
        display:\'none\'\n
      }, stopMakerSVG);\n
\n
      \n
      function selectStop(item) {\n
        if(cur_stop) cur_stop.setAttribute(\'stroke\', \'#000\');\n
        item.setAttribute(\'stroke\', \'blue\');\n
        cur_stop = item;\n
        cur_stop.parentNode.appendChild(cur_stop);\n
      //  stops = $(\'stop\');\n
      //  opac_select.val(cur_stop.attr(\'fill-opacity\') || 1);\n
      //  root.append(delStop);\n
      }\n
      \n
      var stop_offset;\n
      \n
      function remDrags() {\n
        $win.unbind(\'mousemove\', dragColor);\n
        if(delStop.getAttribute(\'display\') !== \'none\') {\n
          remStop();\n
        }\n
        drag = null;\n
      }\n
      \n
      var scale_x = 1, scale_y = 1, angle = 0;\n
      var c_x = cx;\n
      var c_y = cy;\n
      \n
      function xform() {\n
        var rot = angle?\'rotate(\' + angle + \',\' + c_x + \',\' + c_y + \') \':\'\';\n
        if(scale_x === 1 && scale_y === 1) {\n
          curGradient.removeAttribute(\'gradientTransform\');\n
//          $(\'#ang\').addClass(\'dis\');\n
        } else {\n
          var x = -c_x * (scale_x-1);\n
          var y = -c_y * (scale_y-1);\n
          curGradient.setAttribute(\'gradientTransform\', rot + \'translate(\' + x + \',\' + y + \') scale(\' + scale_x + \',\' + scale_y + \')\');\n
//          $(\'#ang\').removeClass(\'dis\');\n
        }\n
      }\n
      \n
      function dragColor(evt) {\n
\n
        var x = evt.pageX - stop_offset.left;\n
        var y = evt.pageY - stop_offset.top;\n
        x = x < 10 ? 10 : x > MAX + 10 ? MAX + 10: x;\n
\n
        var xf_str = \'translate(\' + x + \', 26)\';\n
          if(y < -60 || y > 130) {\n
            delStop.setAttribute(\'display\', \'block\');\n
            delStop.setAttribute(\'transform\', xf_str);\n
          } else {\n
            delStop.setAttribute(\'display\', \'none\');\n
          }\n
        \n
        drag.setAttribute(\'transform\', xf_str);\n
        $.data(drag, \'bg\').setAttribute(\'transform\', xf_str);\n
        var stop = $.data(drag, \'stop\');\n
        var s_x = (x - 10) / MAX;\n
        \n
        stop.setAttribute(\'offset\', s_x);\n
        var last = 0;\n
        \n
        $(curGradient).find(\'stop\').each(function(i) {\n
          var cur = this.getAttribute(\'offset\');\n
          var t = $(this);\n
          if(cur < last) {\n
            t.prev().before(t);\n
            stops = $(curGradient).find(\'stop\');\n
          }\n
          last = cur;\n
        });\n
        \n
      }\n
      \n
      stopMakerSVG = mkElem(\'svg\', {\n
        width: \'100%\',\n
        height: 45\n
      }, stopMakerDiv[0]);\n
      \n
      var trans_pattern = mkElem(\'pattern\', {\n
        width: 16,\n
        height: 16,\n
        patternUnits: \'userSpaceOnUse\',\n
        id: \'jGraduate_trans\'\n
      }, stopMakerSVG);\n
      \n
      var trans_img = mkElem(\'image\', {\n
        width: 16,\n
        height: 16\n
      }, trans_pattern);\n
      \n
      var bg_image = $settings.images.clientPath + \'map-opacity.png\';\n
\n
      trans_img.setAttributeNS(ns.xlink, \'xlink:href\', bg_image);\n
      \n
      $(stopMakerSVG).on("click touchstart", function(evt) {\n
        stop_offset = stopMakerDiv.offset();\n
        var target = evt.target;\n
        if(target.tagName === \'path\') return;\n
        var x = evt.pageX - stop_offset.left - 8;\n
        x = x < 10 ? 10 : x > MAX + 10 ? MAX + 10: x;\n
        mkStop(x / MAX, 0, 0, true);\n
        evt.stopPropagation();\n
      });\n
      \n
      $(stopMakerSVG).mouseover(function() {\n
        stopMakerSVG.appendChild(delStop);\n
      });\n
      \n
      stopGroup = mkElem(\'g\', {}, stopMakerSVG);\n
      \n
      mkElem(\'line\', {\n
        x1: 10,\n
        y1: 15,\n
        x2: MAX + 10,\n
        y2: 15,\n
        \'stroke-width\': 2,\n
        stroke: \'#000\'\n
      }, stopMakerSVG);\n
      \n
      \n
      var spreadMethodOpt = gradPicker.find(\'.jGraduate_spreadMethod\').change(function() {\n
        curGradient.setAttribute(\'spreadMethod\', $(this).val());\n
      });\n
      \n
    \n
      // handle dragging the stop around the swatch\n
      var draggingCoord = null;\n
      \n
      var onCoordDrag = function(evt) {\n
        var x = evt.pageX - offset.left;\n
        var y = evt.pageY - offset.top;\n
\n
        // clamp stop to the swatch\n
        x = x < 0 ? 0 : x > MAX ? MAX : x;\n
        y = y < 0 ? 0 : y > MAX ? MAX : y;\n
        \n
        draggingCoord.css(\'left\', x).css(\'top\', y);\n
\n
        // calculate stop offset                \n
        var fracx = x / SIZEX;\n
        var fracy = y / SIZEY;\n
        \n
        var type = draggingCoord.data(\'coord\');\n
        var grad = curGradient;\n
        \n
        switch ( type ) {\n
          case \'start\':\n
            attr_input.x1.val(fracx);\n
            attr_input.y1.val(fracy);\n
            grad.setAttribute(\'x1\', fracx);\n
            grad.setAttribute(\'y1\', fracy);\n
            break;\n
          case \'end\':\n
            attr_input.x2.val(fracx);\n
            attr_input.y2.val(fracy);\n
            grad.setAttribute(\'x2\', fracx);\n
            grad.setAttribute(\'y2\', fracy);\n
            break;\n
          case \'center\':\n
            attr_input.cx.val(fracx);\n
            attr_input.cy.val(fracy);\n
            grad.setAttribute(\'cx\', fracx);\n
            grad.setAttribute(\'cy\', fracy);\n
            c_x = fracx;\n
            c_y = fracy;\n
            xform();\n
            break;\n
          case \'focus\':\n
            attr_input.fx.val(fracx);\n
            attr_input.fy.val(fracy);\n
            grad.setAttribute(\'fx\', fracx);\n
            grad.setAttribute(\'fy\', fracy);\n
            xform();\n
        }\n
        \n
        evt.preventDefault();\n
      }\n
      \n
      var onCoordUp = function() {\n
        draggingCoord = null;\n
        $win.unbind(\'mousemove\', onCoordDrag).unbind(\'mouseup\', onCoordUp);\n
      }\n
      \n
      // Linear gradient\n
//      (function() {\n
\n
      \n
      stops = curGradient.getElementsByTagNameNS(ns.svg, \'stop\');\n
\n
      // if there are not at least two stops, then \n
      if (numstops < 2) {\n
        while (numstops < 2) {\n
          curGradient.appendChild( document.createElementNS(ns.svg, \'stop\') );\n
          ++numstops;\n
        }\n
        stops = curGradient.getElementsByTagNameNS(ns.svg, \'stop\');\n
      }\n
      \n
      var numstops = stops.length;        \n
      for(var i = 0; i < numstops; i++) {\n
        mkStop(0, 0, 0, 0, stops[i]);\n
      }\n
      \n
      spreadMethodOpt.val(curGradient.getAttribute(\'spreadMethod\') || \'pad\');\n
\n
      var offset;\n
      \n
      // No match, so show focus point\n
      var showFocus = false; \n
      \n
      previewRect.setAttribute(\'fill-opacity\', gradalpha/100);\n
\n
      \n
      $(\'#\' + id + \' div.grad_coord\').mousedown(function(evt) {\n
        evt.preventDefault();\n
        draggingCoord = $(this);\n
        var s_pos = draggingCoord.offset();\n
        offset = draggingCoord.parent().offset();\n
        $win.mousemove(onCoordDrag).mouseup(onCoordUp);\n
      });\n
      \n
      // bind GUI elements\n
      $(\'#\'+id+\'_jGraduate_Ok\').bind(\'click touchstart\', function() {\n
        $this.paint.type = curType;\n
        $this.paint[curType] = curGradient.cloneNode(true);;\n
        $this.paint.solidColor = null;\n
        okClicked();\n
      });\n
      $(\'#\'+id+\'_jGraduate_Cancel\').bind(\'click touchstart\', function(paint) {\n
        cancelClicked();\n
      });\n
\n
      if(curType === \'radialGradient\') {\n
        if(showFocus) {\n
          focusCoord.show();        \n
        } else {\n
          focusCoord.hide();\n
          attr_input.fx.val("");\n
          attr_input.fy.val("");\n
        }\n
      }\n
\n
      $("#" + id + "_jGraduate_match_ctr")[0].checked = !showFocus;\n
      \n
      var lastfx, lastfy;\n
      \n
      $("#" + id + "_jGraduate_match_ctr").change(function() {\n
        showFocus = !this.checked;\n
        focusCoord.toggle(showFocus);\n
        attr_input.fx.val(\'\');\n
        attr_input.fy.val(\'\');\n
        var grad = curGradient;\n
        if(!showFocus) {\n
          lastfx = grad.getAttribute(\'fx\');\n
          lastfy = grad.getAttribute(\'fy\');\n
          grad.removeAttribute(\'fx\');\n
          grad.removeAttribute(\'fy\');\n
        } else {\n
          var fx = lastfx || .5;\n
          var fy = lastfy || .5;\n
          grad.setAttribute(\'fx\', fx);\n
          grad.setAttribute(\'fy\', fy);\n
          attr_input.fx.val(fx);\n
          attr_input.fy.val(fy);\n
        }\n
      });\n
      \n
      var stops = curGradient.getElementsByTagNameNS(ns.svg, \'stop\');\n
      var numstops = stops.length;\n
      // if there are not at least two stops, then \n
      if (numstops < 2) {\n
        while (numstops < 2) {\n
          curGradient.appendChild( document.createElementNS(ns.svg, \'stop\') );\n
          ++numstops;\n
        }\n
        stops = curGradient.getElementsByTagNameNS(ns.svg, \'stop\');\n
      }\n
      \n
      var slider;\n
      \n
      var setSlider = function(e) {\n
        var offset = slider.offset;\n
        var div = slider.parent;\n
        var x = (e.pageX - offset.left - parseInt(div.css(\'border-left-width\')));\n
        if (x > SLIDERW) x = SLIDERW;\n
        if (x <= 0) x = 0;\n
        var posx = x - 5;\n
        x /= SLIDERW;\n
        \n
        switch ( slider.type ) {\n
          case \'radius\':\n
            x = Math.pow(x * 2, 2.5);\n
            if(x > .98 && x < 1.02) x = 1;\n
            if (x <= .01) x = .01;\n
            curGradient.setAttribute(\'r\', x);\n
            break;\n
          case \'opacity\':\n
            $this.paint.alpha = parseInt(x*100);\n
            previewRect.setAttribute(\'fill-opacity\', x);\n
            break;\n
          case \'ellip\':\n
            scale_x = 1, scale_y = 1;\n
            if(x < .5) {\n
              x /= .5; // 0.001\n
              scale_x = x <= 0 ? .01 : x;\n
            } else if(x > .5) {\n
              x /= .5; // 2\n
              x = 2 - x;\n
              scale_y = x <= 0 ? .01 : x;\n
            } \n
            xform();\n
            x -= 1;\n
            if(scale_y === x + 1) {\n
              x = Math.abs(x);\n
            }\n
            break;\n
          case \'angle\':\n
            x = x - .5;\n
            angle = x *= 180;\n
            xform();\n
            x /= 100;\n
            break;\n
        }\n
        slider.elem.css({\'margin-left\':posx});\n
        x = Math.round(x*100);\n
        slider.input.val(x);\n
      };\n
      \n
      var ellip_val = 0, angle_val = 0;\n
      \n
      if(curType === \'radialGradient\') {\n
        var tlist = curGradient.gradientTransform.baseVal;\n
        if(tlist.numberOfItems === 2) {\n
          var t = tlist.getItem(0);\n
          var s = tlist.getItem(1);\n
          if(t.type === 2 && s.type === 3) {\n
            var m = s.matrix;\n
            if(m.a !== 1) {\n
              ellip_val = Math.round(-(1 - m.a) * 100); \n
            } else if(m.d !== 1) {\n
              ellip_val = Math.round((1 - m.d) * 100);\n
            } \n
          }\n
        } else if(tlist.numberOfItems === 3) {\n
          // Assume [R][T][S]\n
          var r = tlist.getItem(0);\n
          var t = tlist.getItem(1);\n
          var s = tlist.getItem(2);\n
          \n
          if(r.type === 4 \n
            && t.type === 2 \n
            && s.type === 3) {\n
\n
            angle_val = Math.round(r.angle);\n
            var m = s.matrix;\n
            if(m.a !== 1) {\n
              ellip_val = Math.round(-(1 - m.a) * 100); \n
            } else if(m.d !== 1) {\n
              ellip_val = Math.round((1 - m.d) * 100);\n
            } \n
            \n
          }\n
        }\n
      }\n
      \n
      var sliders = {\n
        radius: {\n
          handle: \'#\' + id + \'_jGraduate_RadiusArrows\',\n
          input: \'#\' + id + \'_jGraduate_RadiusInput\',\n
          val: (curGradient.getAttribute(\'r\') || .5) * 100\n
        },\n
        opacity: {\n
          handle: \'#\' + id + \'_jGraduate_OpacArrows\',\n
          input: \'#\' + id + \'_jGraduate_OpacInput\',\n
          val: $this.paint.alpha || 100\n
        },\n
        ellip: {\n
          handle: \'#\' + id + \'_jGraduate_EllipArrows\',\n
          input: \'#\' + id + \'_jGraduate_EllipInput\',\n
          val: ellip_val\n
        },\n
        angle: {\n
          handle: \'#\' + id + \'_jGraduate_AngleArrows\',\n
          input: \'#\' + id + \'_jGraduate_AngleInput\',\n
          val: angle_val\n
        }\n
      }\n
      \n
      $.each(sliders, function(type, data) {\n
        var handle = $(data.handle);\n
        handle.mousedown(function(evt) {\n
          var parent = handle.parent();\n
          slider = {\n
            type: type,\n
            elem: handle,\n
            input: $(data.input),\n
            parent: parent,\n
            offset: parent.offset()\n
          };\n
          $win.mousemove(dragSlider).mouseup(stopSlider);\n
          evt.preventDefault();\n
        });\n
        \n
        $(data.input).val(data.val).change(function() {\n
          var val = +this.value;\n
          var xpos = 0;\n
          var isRad = curType === \'radialGradient\';\n
          switch ( type ) {\n
            case \'radius\':\n
              if(isRad) curGradient.setAttribute(\'r\', val / 100);\n
              xpos = (Math.pow(val / 100, 1 / 2.5) / 2) * SLIDERW;\n
              break;\n
            \n
            case \'opacity\':\n
              $this.paint.alpha = val;\n
              previewRect.setAttribute(\'fill-opacity\', val / 100);\n
              xpos = val * (SLIDERW / 100);\n
              break;\n
              \n
            case \'ellip\':\n
              scale_x = scale_y = 1;\n
              if(val === 0) {\n
                xpos = SLIDERW * .5;\n
                break;\n
              }\n
              if(val > 99.5) val = 99.5;\n
              if(val > 0) {\n
                scale_y = 1 - (val / 100);\n
              } else {\n
                scale_x = - (val / 100) - 1;\n
              }\n
\n
              xpos = SLIDERW * ((val + 100) / 2) / 100;\n
              if(isRad) xform();\n
              break;\n
            \n
            case \'angle\':\n
              angle = val;\n
              xpos = angle / 180;\n
              xpos += .5;\n
              xpos *= SLIDERW;\n
              if(isRad) xform();\n
          }\n
          if(xpos > SLIDERW) {\n
            xpos = SLIDERW;\n
          } else if(xpos < 0) {\n
            xpos = 0;\n
          }\n
          handle.css({\'margin-left\': xpos - 5});\n
        }).change();\n
      });\n
      \n
      var dragSlider = function(evt) {\n
        setSlider(evt);\n
        evt.preventDefault();\n
      };\n
      \n
      var stopSlider = function(evt) {\n
        $win.unbind(\'mousemove\', dragSlider).unbind(\'mouseup\', stopSlider);\n
        slider = null;\n
      };\n
      \n
      \n
      // --------------\n
      var thisAlpha = ($this.paint.alpha*255/100).toString(16);\n
      while (thisAlpha.length < 2) { thisAlpha = "0" + thisAlpha; }\n
      thisAlpha = thisAlpha.split(".")[0];\n
      color = $this.paint.solidColor == "none" ? "" : $this.paint.solidColor + thisAlpha;\n
      \n
      if(!isSolid) {\n
        color = stops[0].getAttribute(\'stop-color\');\n
      }\n
      \n
      // This should be done somewhere else, probably\n
      $.extend($.fn.jPicker.defaults.window, {\n
        alphaSupport: true, effects: {type: \'show\',speed: 0}\n
      });\n
      \n
      colPicker.jPicker(\n
        {\n
          window: { title: $settings.window.pickerTitle },\n
          images: { clientPath: $settings.images.clientPath },\n
          color: { active: color, alphaSupport: true }\n
        },\n
        function(color) {\n
          $this.paint.type = "solidColor";\n
          $this.paint.alpha = color.val(\'ahex\') ? Math.round((color.val(\'a\') / 255) * 100) : 100;\n
          $this.paint.solidColor = color.val(\'hex\') ? color.val(\'hex\') : "none";\n
          $this.paint.radialGradient = null;\n
          okClicked(); \n
        },\n
        null,\n
        function(){ cancelClicked(); }\n
        );\n
\n
      \n
      var tabs = $(idref + \' .jGraduate_tabs li\');\n
      tabs.on("click touchstart", function() {\n
        tabs.removeClass(\'jGraduate_tab_current\');\n
        $(this).addClass(\'jGraduate_tab_current\');\n
        $(idref + " > div").hide();\n
        var type = $(this).attr(\'data-type\');\n
        var container = $(idref + \' .jGraduate_gradPick\').show();\n
        if(type === \'rg\' || type === \'lg\') {\n
          // Show/hide appropriate fields\n
          $(\'.jGraduate_\' + type + \'_field\').show();\n
          $(\'.jGraduate_\' + (type === \'lg\' ? \'rg\' : \'lg\') + \'_field\').hide();\n
          \n
          $(\'#\' + id + \'_jgraduate_rect\')[0].setAttribute(\'fill\', \'url(#\' + id + \'_\' + type + \'_jgraduate_grad)\');\n
          \n
          // Copy stops\n
          \n
          curType = type === \'lg\' ? \'linearGradient\' : \'radialGradient\';\n
          \n
          $(\'#\' + id + \'_jGraduate_OpacInput\').val($this.paint.alpha).change();\n
          \n
          var newGrad = $(\'#\' + id + \'_\' + type + \'_jgraduate_grad\')[0];\n
          \n
          if(curGradient !== newGrad) {\n
            var cur_stops = $(curGradient).find(\'stop\');  \n
            $(newGrad).empty().append(cur_stops);\n
            curGradient = newGrad;\n
            var sm = spreadMethodOpt.val();\n
            curGradient.setAttribute(\'spreadMethod\', sm);\n
          }\n
          showFocus = type === \'rg\' && curGradient.getAttribute(\'fx\') != null && !(cx == fx && cy == fy);\n
          $(\'#\' + id + \'_jGraduate_focusCoord\').toggle(showFocus);\n
          if(showFocus) {\n
            $(\'#\' + id + \'_jGraduate_match_ctr\')[0].checked = false;\n
          }\n
        } else {\n
          $(idref + \' .jGraduate_gradPick\').hide();\n
          $(idref + \' .jGraduate_colPick\').show();\n
        }\n
      });\n
      $(idref + " > div").hide();\n
      tabs.removeClass(\'jGraduate_tab_current\');\n
      var tab;\n
      switch ( $this.paint.type ) {\n
        case \'linearGradient\':\n
          tab = $(idref + \' .jGraduate_tab_lingrad\');\n
          break;\n
        case \'radialGradient\':\n
          tab = $(idref + \' .jGraduate_tab_radgrad\');\n
          break;\n
        default:\n
          tab = $(idref + \' .jGraduate_tab_color\');\n
          break;\n
      }\n
      $this.show();\n
      \n
      // jPicker will try to show after a 0ms timeout, so need to fire this after that\n
      setTimeout(function() {\n
        tab.addClass(\'jGraduate_tab_current\').click();  \n
      }, 10);\n
    });\n
  };\n
})();

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>41718</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
