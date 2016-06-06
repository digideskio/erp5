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
            <value> <string>ts80066301.62</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-foreignobject.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
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
svgEditor.addExtension("foreignObject", function(S) {\n
\t\tvar svgcontent = S.svgcontent,\n
\t\t\taddElem = S.addSvgElementFromJson,\n
\t\t\tselElems,\n
\t\t\tsvgns = "http://www.w3.org/2000/svg",\n
\t\t\txlinkns = "http://www.w3.org/1999/xlink",\n
\t\t\txmlns = "http://www.w3.org/XML/1998/namespace",\n
\t\t\txmlnsns = "http://www.w3.org/2000/xmlns/",\n
\t\t\tse_ns = "http://svg-edit.googlecode.com",\n
\t\t\thtmlns = "http://www.w3.org/1999/xhtml",\n
\t\t\tmathns = "http://www.w3.org/1998/Math/MathML",\n
\t\t\teditingforeign = false,\n
\t\t\tsvgdoc = S.svgroot.parentNode.ownerDocument,\n
\t\t\tstarted,\n
\t\t\tnewFO;\n
\t\t\t\n
\t\t\t\n
\t\tvar properlySourceSizeTextArea = function(){\n
\t\t\t// TODO: remove magic numbers here and get values from CSS\n
\t\t\tvar height = $(\'#svg_source_container\').height() - 80;\n
\t\t\t$(\'#svg_source_textarea\').css(\'height\', height);\n
\t\t};\n
\n
\t\tfunction showPanel(on) {\n
\t\t\tvar fc_rules = $(\'#fc_rules\');\n
\t\t\tif(!fc_rules.length) {\n
\t\t\t\tfc_rules = $(\'<style id="fc_rules"><\\/style>\').appendTo(\'head\');\n
\t\t\t} \n
\t\t\tfc_rules.text(!on?"":" #tool_topath { display: none !important; }");\n
\t\t\t$(\'#foreignObject_panel\').toggle(on);\n
\t\t}\n
\n
\t\tfunction toggleSourceButtons(on) {\n
\t\t\t$(\'#tool_source_save, #tool_source_cancel\').toggle(!on);\n
\t\t\t$(\'#foreign_save, #foreign_cancel\').toggle(on);\n
\t\t}\n
\t\t\n
\t\t\t\n
\t\t// Function: setForeignString(xmlString, elt)\n
\t\t// This function sets the content of element elt to the input XML.\n
\t\t//\n
\t\t// Parameters:\n
\t\t// xmlString - The XML text.\n
\t\t// elt - the parent element to append to\n
\t\t//\n
\t\t// Returns:\n
\t\t// This function returns false if the set was unsuccessful, true otherwise.\n
\t\tfunction setForeignString(xmlString) {\n
\t\t\tvar elt = selElems[0];\n
\t\t\ttry {\n
\t\t\t\t// convert string into XML document\n
\t\t\t\tvar newDoc = Utils.text2xml(\'<svg xmlns="\'+svgns+\'" xmlns:xlink="\'+xlinkns+\'">\'+xmlString+\'</svg>\');\n
\t\t\t\t// run it through our sanitizer to remove anything we do not support\n
\t\t\t\tS.sanitizeSvg(newDoc.documentElement);\n
\t\t\t\telt.parentNode.replaceChild(svgdoc.importNode(newDoc.documentElement.firstChild, true), elt);\n
\t\t\t\tS.call("changed", [elt]);\n
\t\t\t\tsvgCanvas.clearSelection();\n
\t\t\t} catch(e) {\n
\t\t\t\tconsole.log(e);\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\n
\t\t\treturn true;\n
\t\t};\n
\n
\t\tfunction showForeignEditor() {\n
\t\t\tvar elt = selElems[0];\n
\t\t\tif (!elt || editingforeign) return;\n
\t\t\teditingforeign = true;\n
\t\t\ttoggleSourceButtons(true);\n
\t\t\telt.removeAttribute(\'fill\');\n
\n
\t\t\tvar str = S.svgToString(elt, 0);\n
\t\t\t$(\'#svg_source_textarea\').val(str);\n
\t\t\t$(\'#svg_source_editor\').fadeIn();\n
\t\t\tproperlySourceSizeTextArea();\n
\t\t\t$(\'#svg_source_textarea\').focus();\n
\t\t}\n
\t\t\n
\t\tfunction setAttr(attr, val) {\n
\t\t\tsvgCanvas.changeSelectedAttribute(attr, val);\n
\t\t\tS.call("changed", selElems);\n
\t\t}\n
\t\t\n
\t\t\n
\t\treturn {\n
\t\t\tname: "foreignObject",\n
\t\t\tsvgicons: "jquery_plugin/svg-editor/extensions/foreignobject-icons.xml",\n
\t\t\tbuttons: [{\n
\t\t\t\tid: "tool_foreign",\n
\t\t\t\ttype: "mode",\n
\t\t\t\ttitle: "Foreign Object Tool",\n
\t\t\t\tevents: {\n
\t\t\t\t\t\'click\': function() {\n
\t\t\t\t\t\tsvgCanvas.setMode(\'foreign\')\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},{\n
\t\t\t\tid: "edit_foreign",\n
\t\t\t\ttype: "context",\n
\t\t\t\tpanel: "foreignObject_panel",\n
\t\t\t\ttitle: "Edit ForeignObject Content",\n
\t\t\t\tevents: {\n
\t\t\t\t\t\'click\': function() {\n
\t\t\t\t\t\tshowForeignEditor();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}],\n
\t\t\t\n
\t\t\tcontext_tools: [{\n
\t\t\t\ttype: "input",\n
\t\t\t\tpanel: "foreignObject_panel",\n
\t\t\t\ttitle: "Change foreignObject\'s width",\n
\t\t\t\tid: "foreign_width",\n
\t\t\t\tlabel: "w",\n
\t\t\t\tsize: 3,\n
\t\t\t\tevents: {\n
\t\t\t\t\tchange: function() {\n
\t\t\t\t\t\tsetAttr(\'width\', this.value);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},{\n
\t\t\t\ttype: "input",\n
\t\t\t\tpanel: "foreignObject_panel",\n
\t\t\t\ttitle: "Change foreignObject\'s height",\n
\t\t\t\tid: "foreign_height",\n
\t\t\t\tlabel: "h",\n
\t\t\t\tevents: {\n
\t\t\t\t\tchange: function() {\n
\t\t\t\t\t\tsetAttr(\'height\', this.value);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}, {\n
\t\t\t\ttype: "input",\n
\t\t\t\tpanel: "foreignObject_panel",\n
\t\t\t\ttitle: "Change foreignObject\'s font size",\n
\t\t\t\tid: "foreign_font_size",\n
\t\t\t\tlabel: "font-size",\n
\t\t\t\tsize: 2,\n
\t\t\t\tdefval: 16,\n
\t\t\t\tevents: {\n
\t\t\t\t\tchange: function() {\n
\t\t\t\t\t\tsetAttr(\'font-size\', this.value);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t\n
\t\t\t],\n
\t\t\tcallback: function() {\n
\t\t\t\t$(\'#foreignObject_panel\').hide();\n
\n
\t\t\t\tvar endChanges = function() {\n
\t\t\t\t\t$(\'#svg_source_editor\').hide();\n
\t\t\t\t\teditingforeign = false;\n
\t\t\t\t\t$(\'#svg_source_textarea\').blur();\n
\t\t\t\t\ttoggleSourceButtons(false);\n
\t\t\t\t}\n
\n
\t\t\t\t// TODO: Needs to be done after orig icon loads\n
\t\t\t\tsetTimeout(function() {\t\t\t\t\n
\t\t\t\t\t// Create source save/cancel buttons\n
\t\t\t\t\tvar save = $(\'#tool_source_save\').clone()\n
\t\t\t\t\t\t.hide().attr(\'id\', \'foreign_save\').unbind()\n
\t\t\t\t\t\t.appendTo("#tool_source_back").click(function() {\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif (!editingforeign) return;\n
\n
\t\t\t\t\t\t\tif (!setForeignString($(\'#svg_source_textarea\').val())) {\n
\t\t\t\t\t\t\t\t$.confirm("Errors found. Revert to original?", function(ok) {\n
\t\t\t\t\t\t\t\t\tif(!ok) return false;\n
\t\t\t\t\t\t\t\t\tendChanges();\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tendChanges();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t// setSelectMode();\t\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t\n
\t\t\t\t\tvar cancel = $(\'#tool_source_cancel\').clone()\n
\t\t\t\t\t\t.hide().attr(\'id\', \'foreign_cancel\').unbind()\n
\t\t\t\t\t\t.appendTo("#tool_source_back").click(function() {\n
\t\t\t\t\t\t\tendChanges();\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t}, 3000);\n
\t\t\t},\n
\t\t\tmouseDown: function(opts) {\n
\t\t\t\tvar e = opts.event;\n
\t\t\t\t\n
\t\t\t\tif(svgCanvas.getMode() == "foreign") {\n
\n
\t\t\t\t\tstarted = true;\n
\t\t\t\t\tnewFO = S.addSvgElementFromJson({\n
\t\t\t\t\t\t"element": "foreignObject",\n
\t\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t\t"x": opts.start_x,\n
\t\t\t\t\t\t\t"y": opts.start_y,\n
\t\t\t\t\t\t\t"id": S.getNextId(),\n
\t\t\t\t\t\t\t"font-size": 16, //cur_text.font_size,\n
\t\t\t\t\t\t\t"width": "48",\n
\t\t\t\t\t\t\t"height": "20",\n
\t\t\t\t\t\t\t"style": "pointer-events:inherit"\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tvar m = svgdoc.createElementNS(mathns, \'math\');\n
\t\t\t\t\tm.setAttributeNS(xmlnsns, \'xmlns\', mathns);\n
\t\t\t\t\tm.setAttribute(\'display\', \'inline\');\n
\t\t\t\t\tvar mi = svgdoc.createElementNS(mathns, \'mi\');\n
\t\t\t\t\tmi.setAttribute(\'mathvariant\', \'normal\');\n
\t\t\t\t\tmi.textContent = "\\u03A6";\n
\t\t\t\t\tvar mo = svgdoc.createElementNS(mathns, \'mo\');\n
\t\t\t\t\tmo.textContent = "\\u222A";\n
\t\t\t\t\tvar mi2 = svgdoc.createElementNS(mathns, \'mi\');\n
\t\t\t\t\tmi2.textContent = "\\u2133";\n
\t\t\t\t\tm.appendChild(mi);\n
\t\t\t\t\tm.appendChild(mo);\n
\t\t\t\t\tm.appendChild(mi2);\n
\t\t\t\t\tnewFO.appendChild(m);\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\tstarted: true\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\tmouseUp: function(opts) {\n
\t\t\t\tvar e = opts.event;\n
\t\t\t\tif(svgCanvas.getMode() == "foreign" && started) {\n
\t\t\t\t\tvar attrs = $(newFO).attr(["width", "height"]);\n
\t\t\t\t\tkeep = (attrs.width != 0 || attrs.height != 0);\n
\t\t\t\t\tsvgCanvas.addToSelection([newFO], true);\n
\n
\t\t\t\t\treturn {\n
\t\t\t\t\t\tkeep: keep,\n
\t\t\t\t\t\telement: newFO\n
\t\t\t\t\t}\n
\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t},\n
\t\t\tselectedChanged: function(opts) {\n
\t\t\t\t// Use this to update the current selected elements\n
\t\t\t\tselElems = opts.elems;\n
\t\t\t\t\n
\t\t\t\tvar i = selElems.length;\n
\t\t\t\t\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar elem = selElems[i];\n
\t\t\t\t\tif(elem && elem.tagName == "foreignObject") {\n
\t\t\t\t\t\tif(opts.selectedElement && !opts.multiselected) {\n
\t\t\t\t\t\t\t$(\'#foreign_font_size\').val(elem.getAttribute("font-size"));\n
\t\t\t\t\t\t\t$(\'#foreign_width\').val(elem.getAttribute("width"));\n
\t\t\t\t\t\t\t$(\'#foreign_height\').val(elem.getAttribute("height"));\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t\tshowPanel(true);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tshowPanel(false);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tshowPanel(false);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\telementChanged: function(opts) {\n
\t\t\t\tvar elem = opts.elems[0];\n
\t\t\t}\n
\t\t};\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>7267</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
