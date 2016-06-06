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
            <value> <string>ts52850625.4</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-connector.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * ext-connector.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 *\n
 */\n
 \n
methodDraw.addExtension("Connector", function(S) {\n
  var svgcontent = S.svgcontent,\n
    svgroot = S.svgroot,\n
    getNextId = S.getNextId,\n
    getElem = S.getElem,\n
    addElem = S.addSvgElementFromJson,\n
    selManager = S.selectorManager,\n
    curConfig = methodDraw.curConfig,\n
    started = false,\n
    start_x,\n
    start_y,\n
    cur_line,\n
    start_elem,\n
    end_elem,\n
    connections = [],\n
    conn_sel = ".se_connector",\n
    se_ns,\n
//      connect_str = "-SE_CONNECT-",\n
    selElems = [];\n
    \n
  elData = $.data;\n
    \n
  var lang_list = {\n
    "en":[\n
      {"id": "mode_connect", "title": "Connect two objects" }\n
    ],\n
    "fr":[\n
      {"id": "mode_connect", "title": "Connecter deux objets"}\n
    ]\n
  };\n
  \n
  function getOffset(side, line) {\n
    var give_offset = !!line.getAttribute(\'marker-\' + side);\n
//    var give_offset = $(line).data(side+\'_off\');\n
\n
    // TODO: Make this number (5) be based on marker width/height\n
    var size = line.getAttribute(\'stroke-width\') * 5;\n
    return give_offset ? size : 0;\n
  }\n
  \n
  function showPanel(on) {\n
    var conn_rules = $(\'#connector_rules\');\n
    if(!conn_rules.length) {\n
      conn_rules = $(\'<style id="connector_rules"><\\/style>\').appendTo(\'head\');\n
    } \n
    conn_rules.text(!on?"":"#tool_clone, #tool_topath, #tool_angle, #xy_panel { display: none !important; }");\n
    $(\'#connector_panel\').toggle(on);\n
  }\n
  \n
  function setPoint(elem, pos, x, y, setMid) {\n
    var pts = elem.points;\n
    var pt = svgroot.createSVGPoint();\n
    pt.x = x;\n
    pt.y = y;\n
    if(pos === \'end\') pos = pts.numberOfItems-1;\n
    // TODO: Test for this on init, then use alt only if needed\n
    try {\n
      pts.replaceItem(pt, pos);\n
    } catch(err) {\n
      // Should only occur in FF which formats points attr as "n,n n,n", so just split\n
      var pt_arr = elem.getAttribute("points").split(" ");\n
      for(var i=0; i< pt_arr.length; i++) {\n
        if(i == pos) {\n
          pt_arr[i] = x + \',\' + y;\n
        }\n
      }\n
      elem.setAttribute("points",pt_arr.join(" ")); \n
    }\n
    \n
    if(setMid) {\n
      // Add center point\n
      var pt_start = pts.getItem(0);\n
      var pt_end = pts.getItem(pts.numberOfItems-1);\n
      setPoint(elem, 1, (pt_end.x + pt_start.x)/2, (pt_end.y + pt_start.y)/2);\n
    }\n
  }\n
  \n
  function updateLine(diff_x, diff_y) {\n
    // Update line with element\n
    var i = connections.length;\n
    while(i--) {\n
      var conn = connections[i];\n
      var line = conn.connector;\n
      var elem = conn.elem;\n
      \n
      var pre = conn.is_start?\'start\':\'end\';\n
//            var sw = line.getAttribute(\'stroke-width\') * 5;\n
      \n
      // Update bbox for this element\n
      var bb = elData(line, pre+\'_bb\');\n
      bb.x = conn.start_x + diff_x;\n
      bb.y = conn.start_y + diff_y;\n
      elData(line, pre+\'_bb\', bb);\n
      \n
      var alt_pre = conn.is_start?\'end\':\'start\';\n
      \n
      // Get center pt of connected element\n
      var bb2 = elData(line, alt_pre+\'_bb\');\n
      var src_x = bb2.x + bb2.width/2;\n
      var src_y = bb2.y + bb2.height/2;\n
      \n
      // Set point of element being moved\n
      var pt = getBBintersect(src_x, src_y, bb, getOffset(pre, line)); // $(line).data(pre+\'_off\')?sw:0\n
      setPoint(line, conn.is_start?0:\'end\', pt.x, pt.y, true);\n
      \n
      // Set point of connected element\n
      var pt2 = getBBintersect(pt.x, pt.y, elData(line, alt_pre + \'_bb\'), getOffset(alt_pre, line));\n
      setPoint(line, conn.is_start?\'end\':0, pt2.x, pt2.y, true);\n
\n
    }\n
  }\n
  \n
  function findConnectors(elems) {\n
    if(!elems) elems = selElems;\n
    var connectors = $(svgcontent).find(conn_sel);\n
    connections = [];\n
\n
    // Loop through connectors to see if one is connected to the element\n
    connectors.each(function() {\n
      var start = elData(this, "c_start");\n
      var end = elData(this, "c_end");\n
      \n
      var parts = [getElem(start), getElem(end)];\n
      for(var i=0; i<2; i++) {\n
        var c_elem = parts[i];\n
        var add_this = false;\n
        // The connected element might be part of a selected group\n
        $(c_elem).parents().each(function() {\n
          if($.inArray(this, elems) !== -1) {\n
            // Pretend this element is selected\n
            add_this = true;\n
          }\n
        });\n
        \n
        if(!c_elem || !c_elem.parentNode) {\n
          $(this).remove();\n
          continue;\n
        }\n
        if($.inArray(c_elem, elems) !== -1 || add_this) {\n
          var bb = svgCanvas.getStrokedBBox([c_elem]);\n
          connections.push({\n
            elem: c_elem,\n
            connector: this,\n
            is_start: (i === 0),\n
            start_x: bb.x,\n
            start_y: bb.y\n
          }); \n
        }\n
      }\n
    });\n
  }\n
  \n
  function updateConnectors(elems) {\n
    // Updates connector lines based on selected elements\n
    // Is not used on mousemove, as it runs getStrokedBBox every time,\n
    // which isn\'t necessary there.\n
    findConnectors(elems);\n
    if(connections.length) {\n
      // Update line with element\n
      var i = connections.length;\n
      while(i--) {\n
        var conn = connections[i];\n
        var line = conn.connector;\n
        var elem = conn.elem;\n
\n
        var sw = line.getAttribute(\'stroke-width\') * 5;\n
        var pre = conn.is_start?\'start\':\'end\';\n
        \n
        // Update bbox for this element\n
        var bb = svgCanvas.getStrokedBBox([elem]);\n
        bb.x = conn.start_x;\n
        bb.y = conn.start_y;\n
        elData(line, pre+\'_bb\', bb);\n
        var add_offset = elData(line, pre+\'_off\');\n
      \n
        var alt_pre = conn.is_start?\'end\':\'start\';\n
        \n
        // Get center pt of connected element\n
        var bb2 = elData(line, alt_pre+\'_bb\');\n
        var src_x = bb2.x + bb2.width/2;\n
        var src_y = bb2.y + bb2.height/2;\n
        \n
        // Set point of element being moved\n
        var pt = getBBintersect(src_x, src_y, bb, getOffset(pre, line));\n
        setPoint(line, conn.is_start?0:\'end\', pt.x, pt.y, true);\n
        \n
        // Set point of connected element\n
        var pt2 = getBBintersect(pt.x, pt.y, elData(line, alt_pre + \'_bb\'), getOffset(alt_pre, line));\n
        setPoint(line, conn.is_start?\'end\':0, pt2.x, pt2.y, true);\n
        \n
        // Update points attribute manually for webkit\n
        if(navigator.userAgent.indexOf(\'AppleWebKit\') != -1) {\n
          var pts = line.points;\n
          var len = pts.numberOfItems;\n
          var pt_arr = Array(len);\n
          for(var j=0; j< len; j++) {\n
            var pt = pts.getItem(j);\n
            pt_arr[j] = pt.x + \',\' + pt.y;\n
          } \n
          line.setAttribute("points",pt_arr.join(" ")); \n
        }\n
\n
      }\n
    }\n
  }\n
  \n
  function getBBintersect(x, y, bb, offset) {\n
    if(offset) {\n
      offset -= 0;\n
      bb = $.extend({}, bb);\n
      bb.width += offset;\n
      bb.height += offset;\n
      bb.x -= offset/2;\n
      bb.y -= offset/2;\n
    }\n
  \n
    var mid_x = bb.x + bb.width/2;\n
    var mid_y = bb.y + bb.height/2;\n
    var len_x = x - mid_x;\n
    var len_y = y - mid_y;\n
    \n
    var slope = Math.abs(len_y/len_x);\n
    \n
    var ratio;\n
    \n
    if(slope < bb.height/bb.width) {\n
      ratio = (bb.width/2) / Math.abs(len_x);\n
    } else {\n
      ratio = (bb.height/2) / Math.abs(len_y);\n
    }\n
    \n
    \n
    return {\n
      x: mid_x + len_x * ratio,\n
      y: mid_y + len_y * ratio\n
    }\n
  }\n
  \n
  // Do once\n
  (function() {\n
    var gse = svgCanvas.groupSelectedElements;\n
    \n
    svgCanvas.groupSelectedElements = function() {\n
      svgCanvas.removeFromSelection($(conn_sel).toArray());\n
      return gse.apply(this, arguments);\n
    }\n
    \n
    var mse = svgCanvas.moveSelectedElements;\n
    \n
    svgCanvas.moveSelectedElements = function() {\n
      svgCanvas.removeFromSelection($(conn_sel).toArray());\n
      var cmd = mse.apply(this, arguments);\n
      updateConnectors();\n
      return cmd;\n
    }\n
    \n
    se_ns = svgCanvas.getEditorNS();\n
  }());\n
  \n
  // Do on reset\n
  function init() {\n
    // Make sure all connectors have data set\n
    $(svgcontent).find(\'*\').each(function() { \n
      var conn = this.getAttributeNS(se_ns, "connector");\n
      if(conn) {\n
        this.setAttribute(\'class\', conn_sel.substr(1));\n
        var conn_data = conn.split(\' \');\n
        var sbb = svgCanvas.getStrokedBBox([getElem(conn_data[0])]);\n
        var ebb = svgCanvas.getStrokedBBox([getElem(conn_data[1])]);\n
        $(this).data(\'c_start\',conn_data[0])\n
          .data(\'c_end\',conn_data[1])\n
          .data(\'start_bb\', sbb)\n
          .data(\'end_bb\', ebb);\n
        svgCanvas.getEditorNS(true);\n
      }\n
    });\n
//      updateConnectors();\n
  }\n
  \n
//    $(svgroot).parent().mousemove(function(e) {\n
// //       if(started \n
// //         || svgCanvas.getMode() != "connector"\n
// //         || e.target.parentNode.parentNode != svgcontent) return;\n
//      \n
//      console.log(\'y\')\n
// //       if(e.target.parentNode.parentNode === svgcontent) {\n
// //           \n
// //       }\n
//    });\n
  \n
  return {\n
    name: "Connector",\n
    svgicons: "images/conn.svg",\n
    buttons: [{\n
      id: "mode_connect",\n
      type: "mode",\n
      icon: "images/cut.png",\n
      title: "Connect two objects",\n
      includeWith: {\n
        button: \'#tool_line\',\n
        isDefault: false,\n
        position: 1\n
      },\n
      events: {\n
        \'click\': function() {\n
          svgCanvas.setMode("connector");\n
        }\n
      }\n
    }],\n
    addLangData: function(lang) {\n
      return {\n
        data: lang_list[lang]\n
      };\n
    },\n
    mouseDown: function(opts) {\n
      var e = opts.event;\n
      start_x = opts.start_x,\n
      start_y = opts.start_y;\n
      var mode = svgCanvas.getMode();\n
      \n
      if(mode == "connector") {\n
        \n
        if(started) return;\n
        \n
        var mouse_target = e.target;\n
        \n
        var parents = $(mouse_target).parents();\n
        \n
        if($.inArray(svgcontent, parents) != -1) {\n
          // Connectable element\n
          \n
          // If child of foreignObject, use parent\n
          var fo = $(mouse_target).closest("foreignObject");\n
          start_elem = fo.length ? fo[0] : mouse_target;\n
          \n
          // Get center of source element\n
          var bb = svgCanvas.getStrokedBBox([start_elem]);\n
          var x = bb.x + bb.width/2;\n
          var y = bb.y + bb.height/2;\n
          \n
          started = true;\n
          cur_line = addElem({\n
            "element": "polyline",\n
            "attr": {\n
              "id": getNextId(),\n
              "points": (x+\',\'+y+\' \'+x+\',\'+y+\' \'+start_x+\',\'+start_y),\n
              "stroke": \'#\' + curConfig.initStroke.color,\n
              "stroke-width": (!start_elem.stroke_width || start_elem.stroke_width == 0) ? curConfig.initStroke.width : start_elem.stroke_width,\n
              "fill": "none",\n
              "opacity": curConfig.initStroke.opacity,\n
              "style": "pointer-events:none"\n
            }\n
          });\n
          elData(cur_line, \'start_bb\', bb);\n
        }\n
        return {\n
          started: true\n
        };\n
      } else if(mode == "select") {\n
        findConnectors();\n
      }\n
    },\n
    mouseMove: function(opts) {\n
      var zoom = svgCanvas.getZoom();\n
      var e = opts.event;\n
      var x = opts.mouse_x/zoom;\n
      var y = opts.mouse_y/zoom;\n
      \n
      var diff_x = x - start_x,\n
        diff_y = y - start_y;\n
                \n
      var mode = svgCanvas.getMode();\n
      \n
      if(mode == "connector" && started) {\n
        \n
        var sw = cur_line.getAttribute(\'stroke-width\') * 3;\n
        // Set start point (adjusts based on bb)\n
        var pt = getBBintersect(x, y, elData(cur_line, \'start_bb\'), getOffset(\'start\', cur_line));\n
        start_x = pt.x;\n
        start_y = pt.y;\n
        \n
        setPoint(cur_line, 0, pt.x, pt.y, true);\n
        \n
        // Set end point\n
        setPoint(cur_line, \'end\', x, y, true);\n
      } else if(mode == "select") {\n
        var slen = selElems.length;\n
        \n
        while(slen--) {\n
          var elem = selElems[slen];\n
          // Look for selected connector elements\n
          if(elem && elData(elem, \'c_start\')) {\n
            // Remove the "translate" transform given to move\n
            svgCanvas.removeFromSelection([elem]);\n
            svgCanvas.getTransformList(elem).clear();\n
\n
          }\n
        }\n
        if(connections.length) {\n
          updateLine(diff_x, diff_y);\n
\n
          \n
        }\n
      } \n
    },\n
    mouseUp: function(opts) {\n
      var zoom = svgCanvas.getZoom();\n
      var e = opts.event,\n
        x = opts.mouse_x/zoom,\n
        y = opts.mouse_y/zoom,\n
        mouse_target = e.target;\n
      \n
      if(svgCanvas.getMode() == "connector") {\n
        var fo = $(mouse_target).closest("foreignObject");\n
        if(fo.length) mouse_target = fo[0];\n
        \n
        var parents = $(mouse_target).parents();\n
\n
        if(mouse_target == start_elem) {\n
          // Start line through click\n
          started = true;\n
          return {\n
            keep: true,\n
            element: null,\n
            started: started\n
          }           \n
        } else if($.inArray(svgcontent, parents) === -1) {\n
          // Not a valid target element, so remove line\n
          $(cur_line).remove();\n
          started = false;\n
          return {\n
            keep: false,\n
            element: null,\n
            started: started\n
          }\n
        } else {\n
          // Valid end element\n
          end_elem = mouse_target;\n
          \n
          var start_id = start_elem.id, end_id = end_elem.id;\n
          var conn_str = start_id + " " + end_id;\n
          var alt_str = end_id + " " + start_id;\n
          // Don\'t create connector if one already exists\n
          var dupe = $(svgcontent).find(conn_sel).filter(function() {\n
            var conn = this.getAttributeNS(se_ns, "connector");\n
            if(conn == conn_str || conn == alt_str) return true;\n
          });\n
          if(dupe.length) {\n
            $(cur_line).remove();\n
            return {\n
              keep: false,\n
              element: null,\n
              started: false\n
            }\n
          }\n
          \n
          var bb = svgCanvas.getStrokedBBox([end_elem]);\n
          \n
          var pt = getBBintersect(start_x, start_y, bb, getOffset(\'start\', cur_line));\n
          setPoint(cur_line, \'end\', pt.x, pt.y, true);\n
          $(cur_line)\n
            .data("c_start", start_id)\n
            .data("c_end", end_id)\n
            .data("end_bb", bb);\n
          se_ns = svgCanvas.getEditorNS(true);\n
          cur_line.setAttributeNS(se_ns, "se:connector", conn_str);\n
          cur_line.setAttribute(\'class\', conn_sel.substr(1));\n
          cur_line.setAttribute(\'opacity\', 1);\n
          svgCanvas.addToSelection([cur_line]);\n
          svgCanvas.moveToBottomSelectedElement();\n
          selManager.requestSelector(cur_line).showGrips(false);\n
          started = false;\n
          return {\n
            keep: true,\n
            element: cur_line,\n
            started: started\n
          }\n
        }\n
      }\n
    },\n
    selectedChanged: function(opts) {\n
      // TODO: Find better way to skip operations if no connectors are in use\n
      if(!$(svgcontent).find(conn_sel).length) return;\n
      \n
      if(svgCanvas.getMode() == \'connector\') {\n
        svgCanvas.setMode(\'select\');\n
      }\n
      \n
      // Use this to update the current selected elements\n
      selElems = opts.elems;\n
      \n
      var i = selElems.length;\n
      \n
      while(i--) {\n
        var elem = selElems[i];\n
        if(elem && elData(elem, \'c_start\')) {\n
          selManager.requestSelector(elem).showGrips(false);\n
          if(opts.selectedElement && !opts.multiselected) {\n
            // TODO: Set up context tools and hide most regular line tools\n
            showPanel(true);\n
          } else {\n
            showPanel(false);\n
          }\n
        } else {\n
          showPanel(false);\n
        }\n
      }\n
      updateConnectors();\n
    },\n
    elementChanged: function(opts) {\n
      var elem = opts.elems[0];\n
      if (elem && elem.tagName == \'svg\' && elem.id == "svgcontent") {\n
        // Update svgcontent (can change on import)\n
        svgcontent = elem;\n
        init();\n
      }\n
      \n
      // Has marker, so change offset\n
      if(elem && (\n
        elem.getAttribute("marker-start") ||\n
        elem.getAttribute("marker-mid") ||\n
        elem.getAttribute("marker-end")\n
      )) {\n
        var start = elem.getAttribute("marker-start");\n
        var mid = elem.getAttribute("marker-mid");\n
        var end = elem.getAttribute("marker-end");\n
        cur_line = elem;\n
        $(elem)\n
          .data("start_off", !!start)\n
          .data("end_off", !!end);\n
        \n
        if(elem.tagName == "line" && mid) {\n
          // Convert to polyline to accept mid-arrow\n
          \n
          var x1 = elem.getAttribute(\'x1\')-0;\n
          var x2 = elem.getAttribute(\'x2\')-0;\n
          var y1 = elem.getAttribute(\'y1\')-0;\n
          var y2 = elem.getAttribute(\'y2\')-0;\n
          var id = elem.id;\n
          \n
          var mid_pt = (\' \'+((x1+x2)/2)+\',\'+((y1+y2)/2) + \' \');\n
          var pline = addElem({\n
            "element": "polyline",\n
            "attr": {\n
              "points": (x1+\',\'+y1+ mid_pt +x2+\',\'+y2),\n
              "stroke": elem.getAttribute(\'stroke\'),\n
              "stroke-width": elem.getAttribute(\'stroke-width\'),\n
              "marker-mid": mid,\n
              "fill": "none",\n
              "opacity": elem.getAttribute(\'opacity\') || 1\n
            }\n
          });\n
          $(elem).after(pline).remove();\n
          svgCanvas.clearSelection();\n
          pline.id = id;\n
          svgCanvas.addToSelection([pline]);\n
          elem = pline;\n
        }\n
      }\n
      // Update line if it\'s a connector\n
      if(elem.getAttribute(\'class\') == conn_sel.substr(1)) {\n
        var start = getElem(elData(elem, \'c_start\'));\n
        updateConnectors([start]);\n
      } else {\n
        updateConnectors();\n
      }\n
    },\n
    toolButtonStateUpdate: function(opts) {\n
      if(opts.nostroke) {\n
        if ($(\'#mode_connect\').hasClass(\'tool_button_current\')) {\n
          clickSelect();\n
        }\n
      }\n
      $(\'#mode_connect\')\n
        .toggleClass(\'disabled\',opts.nostroke);\n
    }\n
  };\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>17890</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
