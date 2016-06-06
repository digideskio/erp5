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
            <value> <string>ts52850604.08</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-foreignobject.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * ext-foreignobject.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Jacques Distler \n
 * Copyright(c) 2010 Alexis Deveria \n
 *\n
 */\n
\n
methodDraw.addExtension("foreignObject", function(S) {\n
    var svgcontent = S.svgcontent,\n
      addElem = S.addSvgElementFromJson,\n
      selElems,\n
      svgns = "http://www.w3.org/2000/svg",\n
      xlinkns = "http://www.w3.org/1999/xlink",\n
      xmlns = "http://www.w3.org/XML/1998/namespace",\n
      xmlnsns = "http://www.w3.org/2000/xmlns/",\n
      se_ns = "http://svg-edit.googlecode.com",\n
      htmlns = "http://www.w3.org/1999/xhtml",\n
      mathns = "http://www.w3.org/1998/Math/MathML",\n
      editingforeign = false,\n
      svgdoc = S.svgroot.parentNode.ownerDocument,\n
      started,\n
      newFO;\n
      \n
      \n
    var properlySourceSizeTextArea = function(){\n
      // TODO: remove magic numbers here and get values from CSS\n
      var height = $(\'#svg_source_container\').height() - 80;\n
      $(\'#svg_source_textarea\').css(\'height\', height);\n
    };\n
\n
    function showPanel(on) {\n
      var fc_rules = $(\'#fc_rules\');\n
      if(!fc_rules.length) {\n
        fc_rules = $(\'<style id="fc_rules"><\\/style>\').appendTo(\'head\');\n
      } \n
      fc_rules.text(!on?"":" #tool_topath { display: none !important; }");\n
      $(\'#foreignObject_panel\').toggle(on);\n
    }\n
\n
    function toggleSourceButtons(on) {\n
      $(\'#tool_source_save, #tool_source_cancel\').toggle(!on);\n
      $(\'#foreign_save, #foreign_cancel\').toggle(on);\n
    }\n
    \n
      \n
    // Function: setForeignString(xmlString, elt)\n
    // This function sets the content of element elt to the input XML.\n
    //\n
    // Parameters:\n
    // xmlString - The XML text.\n
    // elt - the parent element to append to\n
    //\n
    // Returns:\n
    // This function returns false if the set was unsuccessful, true otherwise.\n
    function setForeignString(xmlString) {\n
      var elt = selElems[0];\n
      try {\n
        // convert string into XML document\n
        var newDoc = Utils.text2xml(\'<svg xmlns="\'+svgns+\'" xmlns:xlink="\'+xlinkns+\'">\'+xmlString+\'</svg>\');\n
        // run it through our sanitizer to remove anything we do not support\n
        S.sanitizeSvg(newDoc.documentElement);\n
        elt.parentNode.replaceChild(svgdoc.importNode(newDoc.documentElement.firstChild, true), elt);\n
        S.call("changed", [elt]);\n
        svgCanvas.clearSelection();\n
      } catch(e) {\n
        console.log(e);\n
        return false;\n
      }\n
  \n
      return true;\n
    };\n
\n
    function showForeignEditor() {\n
      var elt = selElems[0];\n
      if (!elt || editingforeign) return;\n
      editingforeign = true;\n
      toggleSourceButtons(true);\n
      elt.removeAttribute(\'fill\');\n
\n
      var str = S.svgToString(elt, 0);\n
      $(\'#svg_source_textarea\').val(str);\n
      $(\'#svg_source_editor\').fadeIn();\n
      properlySourceSizeTextArea();\n
      $(\'#svg_source_textarea\').focus();\n
    }\n
    \n
    function setAttr(attr, val) {\n
      svgCanvas.changeSelectedAttribute(attr, val);\n
      S.call("changed", selElems);\n
    }\n
    \n
    \n
    return {\n
      name: "foreignObject",\n
      svgicons: "extensions/foreignobject-icons.xml",\n
      buttons: [{\n
        id: "tool_foreign",\n
        type: "mode",\n
        title: "Foreign Object Tool",\n
        events: {\n
          \'click\': function() {\n
            svgCanvas.setMode(\'foreign\')\n
          }\n
        }\n
      },{\n
        id: "edit_foreign",\n
        type: "context",\n
        panel: "foreignObject_panel",\n
        title: "Edit ForeignObject Content",\n
        events: {\n
          \'click\': function() {\n
            showForeignEditor();\n
          }\n
        }\n
      }],\n
      \n
      context_tools: [{\n
        type: "input",\n
        panel: "foreignObject_panel",\n
        title: "Change foreignObject\'s width",\n
        id: "foreign_width",\n
        label: "w",\n
        size: 3,\n
        events: {\n
          change: function() {\n
            setAttr(\'width\', this.value);\n
          }\n
        }\n
      },{\n
        type: "input",\n
        panel: "foreignObject_panel",\n
        title: "Change foreignObject\'s height",\n
        id: "foreign_height",\n
        label: "h",\n
        events: {\n
          change: function() {\n
            setAttr(\'height\', this.value);\n
          }\n
        }\n
      }, {\n
        type: "input",\n
        panel: "foreignObject_panel",\n
        title: "Change foreignObject\'s font size",\n
        id: "foreign_font_size",\n
        label: "font-size",\n
        size: 2,\n
        defval: 16,\n
        events: {\n
          change: function() {\n
            setAttr(\'font-size\', this.value);\n
          }\n
        }\n
      }\n
      \n
      \n
      ],\n
      callback: function() {\n
        $(\'#foreignObject_panel\').hide();\n
\n
        var endChanges = function() {\n
          $(\'#svg_source_editor\').hide();\n
          editingforeign = false;\n
          $(\'#svg_source_textarea\').blur();\n
          toggleSourceButtons(false);\n
        }\n
\n
        // TODO: Needs to be done after orig icon loads\n
        setTimeout(function() {       \n
          // Create source save/cancel buttons\n
          var save = $(\'#tool_source_save\').clone()\n
            .hide().attr(\'id\', \'foreign_save\').unbind()\n
            .appendTo("#tool_source_back").click(function() {\n
              \n
              if (!editingforeign) return;\n
\n
              if (!setForeignString($(\'#svg_source_textarea\').val())) {\n
                $.confirm("Errors found. Revert to original?", function(ok) {\n
                  if(!ok) return false;\n
                  endChanges();\n
                });\n
              } else {\n
                endChanges();\n
              }\n
              // setSelectMode(); \n
            });\n
            \n
          var cancel = $(\'#tool_source_cancel\').clone()\n
            .hide().attr(\'id\', \'foreign_cancel\').unbind()\n
            .appendTo("#tool_source_back").click(function() {\n
              endChanges();\n
            });\n
          \n
        }, 3000);\n
      },\n
      mouseDown: function(opts) {\n
        var e = opts.event;\n
        \n
        if(svgCanvas.getMode() == "foreign") {\n
\n
          started = true;\n
          newFO = S.addSvgElementFromJson({\n
            "element": "foreignObject",\n
            "attr": {\n
              "x": opts.start_x,\n
              "y": opts.start_y,\n
              "id": S.getNextId(),\n
              "font-size": 16, //cur_text.font_size,\n
              "width": "48",\n
              "height": "20",\n
              "style": "pointer-events:inherit"\n
            }\n
          });\n
          var m = svgdoc.createElementNS(mathns, \'math\');\n
          m.setAttributeNS(xmlnsns, \'xmlns\', mathns);\n
          m.setAttribute(\'display\', \'inline\');\n
          var mi = svgdoc.createElementNS(mathns, \'mi\');\n
          mi.setAttribute(\'mathvariant\', \'normal\');\n
          mi.textContent = "\\u03A6";\n
          var mo = svgdoc.createElementNS(mathns, \'mo\');\n
          mo.textContent = "\\u222A";\n
          var mi2 = svgdoc.createElementNS(mathns, \'mi\');\n
          mi2.textContent = "\\u2133";\n
          m.appendChild(mi);\n
          m.appendChild(mo);\n
          m.appendChild(mi2);\n
          newFO.appendChild(m);\n
          return {\n
            started: true\n
          }\n
        }\n
      },\n
      mouseUp: function(opts) {\n
        var e = opts.event;\n
        if(svgCanvas.getMode() == "foreign" && started) {\n
          var attrs = $(newFO).attr(["width", "height"]);\n
          keep = (attrs.width != 0 || attrs.height != 0);\n
          svgCanvas.addToSelection([newFO], true);\n
\n
          return {\n
            keep: keep,\n
            element: newFO\n
          }\n
\n
        }\n
        \n
      },\n
      selectedChanged: function(opts) {\n
        // Use this to update the current selected elements\n
        selElems = opts.elems;\n
        \n
        var i = selElems.length;\n
        \n
        while(i--) {\n
          var elem = selElems[i];\n
          if(elem && elem.tagName == "foreignObject") {\n
            if(opts.selectedElement && !opts.multiselected) {\n
              $(\'#foreign_font_size\').val(elem.getAttribute("font-size"));\n
              $(\'#foreign_width\').val(elem.getAttribute("width"));\n
              $(\'#foreign_height\').val(elem.getAttribute("height"));\n
            \n
              showPanel(true);\n
            } else {\n
              showPanel(false);\n
            }\n
          } else {\n
            showPanel(false);\n
          }\n
        }\n
      },\n
      elementChanged: function(opts) {\n
        var elem = opts.elems[0];\n
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
            <value> <int>8312</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
