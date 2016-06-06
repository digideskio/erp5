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
            <value> <string>ts52850506.93</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-shapes.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\r\n
 * ext-shapes.js\r\n
 *\r\n
 * Licensed under the Apache License, Version 2\r\n
 *\r\n
 * Copyright(c) 2010 Christian Tzurcanu\r\n
 * Copyright(c) 2010 Alexis Deveria\r\n
 *\r\n
 */\r\n
\r\n
methodDraw.addExtension("shapes", function() {\r\n
  \r\n
\r\n
  var current_d, cur_shape_id;\r\n
  var canv = methodDraw.canvas;\r\n
  var cur_shape;\r\n
  var start_x, start_y;\r\n
  var svgroot = canv.getRootElem();\r\n
  var lastBBox = {};\r\n
  \r\n
  // This populates the category list\r\n
  var categories = {\r\n
    basic: \'Basic\',\r\n
    object: \'Objects\',\r\n
    symbol: \'Symbols\',\r\n
    arrow: \'Arrows\',\r\n
    flowchart: \'Flowchart\',\r\n
    nature: \'Nature\',\r\n
    game: \'Cards & Chess\',\r\n
    dialog_balloon: \'Dialog balloons\',\r\n
    music: \'Music\',\r\n
    weather: \'Weather &amp; Time\',\r\n
    ui: \'User Interface\',\r\n
    social: \'Social Web\'\r\n
  };\r\n
  \r\n
  var library = {\r\n
    \'basic\': {\r\n
      data: {\r\n
        "star_points_5": "m1,116.58409l113.82668,0l35.17332,-108.13487l35.17334,108.13487l113.82666,0l-92.08755,66.83026l35.17514,108.13487l-92.08759,-66.83208l-92.08757,66.83208l35.17515,-108.13487l-92.08758,-66.83026z",\r\n
        \'donut\': \'m1,150l0,0c0,-82.29042 66.70958,-149 149,-149l0,0c39.51724,0 77.41599,15.69816 105.35889,43.64108c27.94293,27.94293 43.64111,65.84165 43.64111,105.35892l0,0c0,82.29041 -66.70958,149 -149,149l0,0c-82.29041,0 -149,-66.70959 -149,-149zm74.5,0l0,0c0,41.1452 33.35481,74.5 74.5,74.5c41.14522,0 74.5,-33.3548 74.5,-74.5c0,-41.1452 -33.3548,-74.5 -74.5,-74.5l0,0c-41.14519,0 -74.5,33.35481 -74.5,74.5z\',\r\n
        "triangle": "m1,280.375l149,-260.75l149,260.75z",\r\n
        "right_triangle": "m1,299l0,-298l298,298z",\r\n
        "diamond": "m1,150l149,-149l149,149l-149,149l-149,-149z",\r\n
        "pentagon": "m1.00035,116.97758l148.99963,-108.4053l148.99998,108.4053l-56.91267,175.4042l-184.1741,0l-56.91284,-175.4042z",\r\n
        "hexagon": "m1,149.99944l63.85715,-127.71428l170.28572,0l63.85713,127.71428l-63.85713,127.71428l-170.28572,0l-63.85715,-127.71428z",\r\n
        "septagon1": "m0.99917,191.06511l29.51249,-127.7108l119.48833,-56.83673l119.48836,56.83673l29.51303,127.7108l-82.69087,102.41679l-132.62103,0l-82.69031,-102.41679z",\r\n
        "heptagon": "m1,88.28171l87.28172,-87.28171l123.43653,0l87.28172,87.28171l0,123.43654l-87.28172,87.28172l-123.43653,0l-87.28172,-87.28172l0,-123.43654z",\r\n
        "decagon": "m1,150.00093l28.45646,-88.40318l74.49956,-54.63682l92.08794,0l74.50002,54.63682l28.45599,88.40318l-28.45599,88.40318l-74.50002,54.63681l-92.08794,0l-74.49956,-54.63681l-28.45646,-88.40318z",\r\n
        "dodecagon": "m1,110.07421l39.92579,-69.14842l69.14842,-39.92579l79.85159,0l69.14842,39.92579l39.92578,69.14842l0,79.85159l-39.92578,69.14842l-69.14842,39.92578l-79.85159,0l-69.14842,-39.92578l-39.92579,-69.14842l0,-79.85159z",\r\n
        "trapezoid": "m1,299l55.875,-298l186.25001,0l55.87498,298z",\r\n
        "dialog_balloon_1": "m0.99786,35.96579l0,0c0,-19.31077 15.28761,-34.96524 34.14583,-34.96524l15.52084,0l0,0l74.50001,0l139.68748,0c9.05606,0 17.74118,3.68382 24.14478,10.24108c6.40356,6.55726 10.00107,15.45081 10.00107,24.72416l0,87.41311l0,0l0,52.44785l0,0c0,19.31078 -15.2876,34.96524 -34.14584,34.96524l-139.68748,0l-97.32507,88.90848l22.82506,-88.90848l-15.52084,0c-18.85822,0 -34.14583,-15.65446 -34.14583,-34.96524l0,0l0,-52.44785l0,0z",\r\n
        \'heart\': \'m150,73c61,-175 300,0 0,225c-300,-225 -61,-400 0,-225z\',\r\n
        "cylinder": "m299.0007,83.77844c0,18.28676 -66.70958,33.11111 -149.00002,33.11111m149.00002,-33.11111l0,0c0,18.28676 -66.70958,33.11111 -149.00002,33.11111c-82.29041,0 -148.99997,-14.82432 -148.99997,-33.11111m0,0l0,0c0,-18.28674 66.70956,-33.1111 148.99997,-33.1111c82.29044,0 149.00002,14.82436 149.00002,33.1111l0,132.44449c0,18.28674 -66.70958,33.11105 -149.00002,33.11105c-82.29041,0 -148.99997,-14.82431 -148.99997,-33.11105z",\r\n
        "arrow_up": "m1.49805,149.64304l148.50121,-148.00241l148.50121,148.00241l-74.25061,0l0,148.71457l-148.5012,0l0,-148.71457z",\r\n
        "arrow_u_turn": "m1.00059,299.00055l0,-167.62497l0,0c0,-72.00411 58.37087,-130.37499 130.375,-130.37499l0,0l0,0c34.57759,0 67.73898,13.7359 92.18906,38.18595c24.45006,24.45005 38.18593,57.61144 38.18593,92.18904l0,18.625l37.24997,0l-74.49995,74.50002l-74.50002,-74.50002l37.25,0l0,-18.625c0,-30.8589 -25.0161,-55.87498 -55.87498,-55.87498l0,0l0,0c-30.85892,0 -55.875,25.01608 -55.875,55.87498l0,167.62497z",\r\n
        "arrow_left_up": "m0.99865,224.5l74.50004,-74.5l0,37.25l111.74991,0l0,-111.75l-37.25,0l74.5,-74.5l74.5,74.5l-37.25,0l0,186.25l-186.24989,0l0,37.25l-74.50005,-74.5z",\r\n
        "plaque": "m-0.00197,49.94376l0,0c27.5829,0 49.94327,-22.36036 49.94327,-49.94327l199.76709,0l0,0c0,27.5829 22.36037,49.94327 49.94325,49.94327l0,199.7671l0,0c-27.58289,0 -49.94325,22.36034 -49.94325,49.94325l-199.76709,0c0,-27.58292 -22.36037,-49.94325 -49.94327,-49.94325z",\r\n
        "page": "m249.3298,298.99744l9.9335,-39.73413l39.73413,-9.93355l-49.66763,49.66768l-248.33237,0l0,-298.00001l298.00001,0l0,248.33234",\r\n
        "cross": "m0.99844,99.71339l98.71494,0l0,-98.71495l101.26279,0l0,98.71495l98.71495,0l0,101.2628l-98.71495,0l0,98.71494l-101.26279,0l0,-98.71494l-98.71494,0z",\r\n
        "divide": "m150,0.99785l0,0c25.17819,0 45.58916,20.41097 45.58916,45.58916c0,25.17821 -20.41096,45.58916 -45.58916,45.58916c-25.17822,0 -45.58916,-20.41093 -45.58916,-45.58916c0,-25.1782 20.41093,-45.58916 45.58916,-45.58916zm0,296.25203c-25.17822,0 -45.58916,-20.41095 -45.58916,-45.58917c0,-25.17819 20.41093,-45.58916 45.58916,-45.58916c25.17819,0 45.58916,20.41096 45.58916,45.58916c0,25.17822 -20.41096,45.58917 -45.58916,45.58917zm-134.06754,-193.71518l268.13507,0l0,91.17833l-268.13507,0z",\r\n
        "minus": "m0.99887,102.39503l297.49445,0l0,95.2112l-297.49445,0z",\r\n
        "times": "m1.00089,73.36786l72.36697,-72.36697l76.87431,76.87368l76.87431,-76.87368l72.36765,72.36697l-76.87433,76.87431l76.87433,76.87431l-72.36765,72.36765l-76.87431,-76.87433l-76.87431,76.87433l-72.36697,-72.36765l76.87368,-76.87431l-76.87368,-76.87431z"\r\n
        \r\n
\r\n
      },\r\n
      buttons: []\r\n
    }\r\n
  };\r\n
  \r\n
  var cur_lib = library.basic;\r\n
  \r\n
  var mode_id = \'shapelib\';\r\n
  \r\n
  function loadIcons() {\r\n
    $(\'#shape_buttons\').empty();\r\n
    \r\n
    // Show lib ones\r\n
    $(\'#shape_buttons\').append(cur_lib.buttons);\r\n
  }\r\n
  \r\n
  function loadLibrary(cat_id) {\r\n
  \r\n
    var lib = library[cat_id];\r\n
    \r\n
    if(!lib) {\r\n
      $(\'#shape_buttons\').html(\'Loading...\');\r\n
      $.getJSON(\'extensions/shapelib/\' + cat_id + \'.json\', function(result, textStatus) {\r\n
        cur_lib = library[cat_id] = {\r\n
          data: result.data,\r\n
          size: result.size,\r\n
          fill: result.fill\r\n
        }\r\n
        makeButtons(cat_id, result);\r\n
        loadIcons();\r\n
      });\r\n
      return;\r\n
    }\r\n
    \r\n
    cur_lib = lib;\r\n
    if(!lib.buttons.length) makeButtons(cat_id, lib);\r\n
    loadIcons();\r\n
  }\r\n
  \r\n
  function makeButtons(cat, shapes) {\r\n
    var size = cur_lib.size || 300;\r\n
    var fill = cur_lib.fill || false;\r\n
    var off = size * .05;\r\n
    var vb = [-off, -off, size + off*2, size + off*2].join(\' \');\r\n
    var stroke = fill ? 0: (size/30);\r\n
    \r\n
    var shape_icon = new DOMParser().parseFromString(\r\n
      \'<svg xmlns="http://www.w3.org/2000/svg"><svg viewBox="\' + vb + \'"><path fill="#333" stroke="transparent" stroke-width="\' + stroke + \'" /><\\/svg><\\/svg>\',\r\n
      \'text/xml\');\r\n
\r\n
    var width = 40;\r\n
    var height = 40;\r\n
    shape_icon.documentElement.setAttribute(\'width\', width);\r\n
    shape_icon.documentElement.setAttribute(\'height\', height);\r\n
    var svg_elem = $(document.importNode(shape_icon.documentElement,true));\r\n
  \r\n
    var data = shapes.data;\r\n
    \r\n
    cur_lib.buttons = [];\r\n
  \r\n
    for(var id in data) {\r\n
      var path_d = data[id];\r\n
      var icon = svg_elem.clone();\r\n
      icon.find(\'path\').attr(\'d\', path_d);\r\n
      \r\n
      var icon_btn = icon.wrap(\'<div class="tool_button">\').parent().attr({\r\n
        id: mode_id + \'_\' + id,\r\n
        title: id\r\n
      });\r\n
      \r\n
      \r\n
      // Store for later use\r\n
      cur_lib.buttons.push(icon_btn[0]);\r\n
    }\r\n
    \r\n
  }\r\n
\r\n
  \r\n
  return {\r\n
    svgicons: "extensions/ext-shapes.xml",\r\n
    buttons: [{\r\n
      id: "tool_shapelib",\r\n
      type: "mode_flyout", // _flyout\r\n
      position: 6,\r\n
      title: "Shape library",\r\n
      icon: "extensions/ext-shapes.png",\r\n
      events: {\r\n
        "click": function() {\r\n
          canv.setMode(mode_id);\r\n
        }\r\n
      }\r\n
    }],\r\n
    callback: function() {\r\n
\r\n
    \r\n
      var btn_div = $(\'<div id="shape_buttons">\');\r\n
      $(\'#tools_shapelib > *\').wrapAll(btn_div);\r\n
      \r\n
      var shower = $(\'#tools_shapelib_show\');\r\n
\r\n
      \r\n
      loadLibrary(\'basic\');\r\n
      \r\n
      // Do mouseup on parent element rather than each button\r\n
      $(\'#shape_buttons\').mouseup(function(evt) {\r\n
        var btn = $(evt.target).closest(\'div.tool_button\');\r\n
        \r\n
        if(!btn.length) return;\r\n
        \r\n
        var copy = btn.children().clone().attr({width: 24, height: 24});\r\n
        shower.children(\':not(.flyout_arrow_horiz)\').remove();\r\n
        shower\r\n
          .append(copy)\r\n
          .attr(\'data-curopt\', \'#\' + btn[0].id) // This sets the current mode\r\n
          .mouseup();\r\n
        canv.setMode(mode_id);\r\n
        \r\n
        cur_shape_id = btn[0].id.substr((mode_id+\'_\').length);\r\n
        current_d = cur_lib.data[cur_shape_id];\r\n
        \r\n
        $(\'.tools_flyout\').fadeOut();\r\n
\r\n
      });\r\n
\r\n
//      \r\n
      var shape_cats = $(\'<div id="shape_cats">\');\r\n
      var cat_str = \'\';\r\n
      \r\n
      $.each(categories, function(id, label) {\r\n
        cat_str += \'<div data-cat=\' + id + \'>\' + label + \'</div>\';\r\n
      });\r\n
      \r\n
      shape_cats.html(cat_str).children().bind(\'mouseup\', function() {\r\n
        var catlink = $(this);\r\n
        catlink.siblings().removeClass(\'current\');\r\n
        catlink.addClass(\'current\');\r\n
        \r\n
        loadLibrary(catlink.attr(\'data-cat\'));\r\n
        // Get stuff\r\n
        \r\n
        return false;\r\n
      });\r\n
      \r\n
      shape_cats.children().eq(0).addClass(\'current\');\r\n
      \r\n
      $(\'#tools_shapelib\').prepend(shape_cats);\r\n
\r\n
      shower.mouseup(function() {\r\n
        canv.setMode(current_d ? mode_id : \'select\');\r\n
      });\r\n
\r\n
      \r\n
      $(\'#tool_shapelib\').remove();\r\n
      \r\n
      var h = $(\'#tools_shapelib\').height();\r\n
      $(\'#tools_shapelib\').css({\r\n
        \'margin-top\': -(h/2),\r\n
        \'margin-left\': 3\r\n
      });\r\n
\r\n
  \r\n
    },\r\n
    mouseDown: function(opts) {\r\n
      var mode = canv.getMode();\r\n
      if(mode !== mode_id) return;\r\n
      \r\n
      var e = opts.event;\r\n
      var x = start_x = opts.start_x;\r\n
      var y = start_y = opts.start_y;\r\n
      var cur_style = canv.getStyle();\r\n
      cur_shape = canv.addSvgElementFromJson({\r\n
        "element": "path",\r\n
        "curStyles": true,\r\n
        "attr": {\r\n
          "d": current_d,\r\n
          "id": canv.getNextId(),\r\n
          "opacity": cur_style.opacity / 2,\r\n
          "style": "pointer-events:none"\r\n
        }\r\n
      });\r\n
      cur_shape.setAttribute("d", current_d);\r\n
      // Make sure shape uses absolute values\r\n
      if(/[a-z]/.test(current_d)) {\r\n
        current_d = cur_lib.data[cur_shape_id] = canv.pathActions.convertPath(cur_shape);\r\n
        cur_shape.setAttribute(\'d\', current_d);\r\n
        canv.pathActions.fixEnd(cur_shape);\r\n
      }\r\n
      \r\n
      cur_shape.setAttribute(\'transform\', "translate(" + x + "," + y + ") scale(0.005) translate(" + -x + "," + -y + ")");      \r\n
//      console.time(\'b\');\r\n
      canv.recalculateDimensions(cur_shape);\r\n
      var tlist = canv.getTransformList(cur_shape);\r\n
      lastBBox = cur_shape.getBBox();\r\n
      totalScale = {\r\n
        sx: 1,\r\n
        sy: 1\r\n
      };\r\n
      return {\r\n
        started: true\r\n
      }\r\n
      // current_d\r\n
    },\r\n
    mouseMove: function(opts) {\r\n
      var mode = canv.getMode();\r\n
      if(mode !== mode_id) return;\r\n
      \r\n
      var zoom = canv.getZoom();\r\n
      var evt = opts.event\r\n
      \r\n
      var x = opts.mouse_x/zoom;\r\n
      var y = opts.mouse_y/zoom;\r\n
      \r\n
      var tlist = canv.getTransformList(cur_shape),\r\n
        box = cur_shape.getBBox(), \r\n
        left = box.x, top = box.y, width = box.width,\r\n
        height = box.height;\r\n
      var dx = (x-start_x), dy = (y-start_y);\r\n
\r\n
      var newbox = {\r\n
        \'x\': Math.min(start_x,x),\r\n
        \'y\': Math.min(start_y,y),\r\n
        \'width\': Math.abs(x-start_x),\r\n
        \'height\': Math.abs(y-start_y)\r\n
      };\r\n
\r\n
      var ts = null,\r\n
        tx = 0, ty = 0,\r\n
        sy = height ? (height+dy)/height : 1, \r\n
        sx = width ? (width+dx)/width : 1;\r\n
\r\n
      var sx = newbox.width / lastBBox.width;\r\n
      var sy = newbox.height / lastBBox.height;\r\n
      \r\n
      sx = sx || 1;\r\n
      sy = sy || 1;\r\n
      \r\n
      // Not perfect, but mostly works...\r\n
      \r\n
      if(x < start_x) {\r\n
        tx = lastBBox.width;\r\n
      }\r\n
      if(y < start_y) ty = lastBBox.height;\r\n
      \r\n
      // update the transform list with translate,scale,translate\r\n
      var translateOrigin = svgroot.createSVGTransform(),\r\n
        scale = svgroot.createSVGTransform(),\r\n
        translateBack = svgroot.createSVGTransform();\r\n
        \r\n
      translateOrigin.setTranslate(-(left+tx), -(top+ty));\r\n
      if(evt.shiftKey) {\r\n
        replaced = true\r\n
        var max = Math.min(Math.abs(sx), Math.abs(sy));\r\n
        sx = max * (sx < 0 ? -1 : 1);\r\n
        sy = max * (sy < 0 ? -1 : 1);\r\n
        if (totalScale.sx != totalScale.sy) {\r\n
          var multiplierX = (totalScale.sx > totalScale.sy) ? 1 : totalScale.sx/totalScale.sy;\r\n
          var multiplierY = (totalScale.sy > totalScale.sx) ? 1 : totalScale.sy/totalScale.sx;\r\n
          sx *= multiplierY\r\n
          sy *= multiplierX\r\n
        }\r\n
      }\r\n
      totalScale.sx *= sx;\r\n
      totalScale.sy *= sy;\r\n
      scale.setScale(sx,sy);\r\n
      translateBack.setTranslate(left+tx, top+ty);\r\n
      var N = tlist.numberOfItems;\r\n
      tlist.appendItem(translateBack);\r\n
      tlist.appendItem(scale);\r\n
      tlist.appendItem(translateOrigin);\r\n
\r\n
      canv.recalculateDimensions(cur_shape);\r\n
      lastBBox = cur_shape.getBBox();\r\n
    },\r\n
    mouseUp: function(opts) {\r\n
      var mode = canv.getMode();\r\n
      if(mode !== mode_id) return;\r\n
      \r\n
      if(opts.mouse_x == start_x && opts.mouse_y == start_y) {\r\n
        return {\r\n
          keep: false,\r\n
          element: cur_shape,\r\n
          started: false\r\n
        }\r\n
      }\r\n
      canv.setMode("select")\r\n
      return {\r\n
        keep: true,\r\n
        element: cur_shape,\r\n
        started: false\r\n
      }\r\n
    }   \r\n
  }\r\n
});\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>14351</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
