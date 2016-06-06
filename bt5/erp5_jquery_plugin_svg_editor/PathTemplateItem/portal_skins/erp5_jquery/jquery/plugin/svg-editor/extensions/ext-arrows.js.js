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
            <value> <string>ts80066299.89</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-arrows.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * ext-arrows.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 *\n
 */\n
\n
 \n
svgEditor.addExtension("Arrows", function(S) {\n
\t\tvar svgcontent = S.svgcontent,\n
\t\t\taddElem = S.addSvgElementFromJson,\n
\t\t\tnonce = S.nonce,\n
\t\t\trandomize_ids = S.randomize_ids,\n
\t\t\tselElems;\n
\n
\t\tsvgCanvas.bind(\'setarrownonce\', setArrowNonce);\n
\t\tsvgCanvas.bind(\'unsetsetarrownonce\', unsetArrowNonce);\n
\t\t\t\n
\t\tvar lang_list = {\n
\t\t\t"en":[\n
\t\t\t\t{"id": "arrow_none", "textContent": "No arrow" }\n
\t\t\t],\n
\t\t\t"fr":[\n
\t\t\t\t{"id": "arrow_none", "textContent": "Sans flèche" }\n
\t\t\t]\n
\t\t};\n
\t\t\n
\t\tvar prefix = \'se_arrow_\';\n
\t\tif (randomize_ids) {\n
\t\t  var arrowprefix = prefix + nonce + \'_\';\n
\t\t} else {\n
\t\t  var arrowprefix = prefix;\n
\t\t}\n
\n
\t\tvar pathdata = {\n
\t\t\tfw: {d:"m0,0l10,5l-10,5l5,-5l-5,-5z", refx:8,  id: arrowprefix + \'fw\'},\n
\t\t\tbk: {d:"m10,0l-10,5l10,5l-5,-5l5,-5z", refx:2, id: arrowprefix + \'bk\'}\n
\t\t}\n
\t\t\n
\t\tfunction setArrowNonce(window, n) {\n
\t\t    randomize_ids = true;\n
\t\t    arrowprefix = prefix + n + \'_\';\n
 \t\t\tpathdata.fw.id = arrowprefix + \'fw\';\n
\t\t\tpathdata.bk.id = arrowprefix + \'bk\';\n
\t\t}\n
\n
\t\tfunction unsetArrowNonce(window) {\n
\t\t    randomize_ids = false;\n
\t\t    arrowprefix = prefix;\n
 \t\t\tpathdata.fw.id = arrowprefix + \'fw\';\n
\t\t\tpathdata.bk.id = arrowprefix + \'bk\';\n
\t\t}\n
\n
\t\tfunction getLinked(elem, attr) {\n
\t\t\tvar str = elem.getAttribute(attr);\n
\t\t\tif(!str) return null;\n
\t\t\tvar m = str.match(/\\(\\#(.*)\\)/);\n
\t\t\tif(!m || m.length !== 2) {\n
\t\t\t\treturn null;\n
\t\t\t}\n
\t\t\treturn S.getElem(m[1]);\n
\t\t}\n
\t\t\n
\t\tfunction showPanel(on) {\n
\t\t\t$(\'#arrow_panel\').toggle(on);\n
\t\t\t\n
\t\t\tif(on) {\n
\t\t\t\tvar el = selElems[0];\n
\t\t\t\tvar end = el.getAttribute("marker-end");\n
\t\t\t\tvar start = el.getAttribute("marker-start");\n
\t\t\t\tvar mid = el.getAttribute("marker-mid");\n
\t\t\t\tvar val;\n
\t\t\t\t\n
\t\t\t\tif(end && start) {\n
\t\t\t\t\tval = "both";\n
\t\t\t\t} else if(end) {\n
\t\t\t\t\tval = "end";\n
\t\t\t\t} else if(start) {\n
\t\t\t\t\tval = "start";\n
\t\t\t\t} else if(mid) {\n
\t\t\t\t\tval = "mid";\n
\t\t\t\t\tif(mid.indexOf("bk") != -1) {\n
\t\t\t\t\t\tval = "mid_bk";\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(!start && !mid && !end) {\n
\t\t\t\t\tval = "none";\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$("#arrow_list").val(val);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tfunction resetMarker() {\n
\t\t\tvar el = selElems[0];\n
\t\t\tel.removeAttribute("marker-start");\n
\t\t\tel.removeAttribute("marker-mid");\n
\t\t\tel.removeAttribute("marker-end");\n
\t\t}\n
\t\t\n
\t\tfunction addMarker(dir, type, id) {\n
\t\t\t// TODO: Make marker (or use?) per arrow type, since refX can be different\n
\t\t\tid = id || arrowprefix + dir;\n
\t\t\t\n
\t\t\tvar marker = S.getElem(id);\n
\n
\t\t\tvar data = pathdata[dir];\n
\t\t\t\n
\t\t\tif(type == "mid") {\n
\t\t\t\tdata.refx = 5;\n
\t\t\t}\n
\n
\t\t\tif(!marker) {\n
\t\t\t\tmarker = addElem({\n
\t\t\t\t\t"element": "marker",\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"viewBox": "0 0 10 10",\n
\t\t\t\t\t\t"id": id,\n
\t\t\t\t\t\t"refY": 5,\n
\t\t\t\t\t\t"markerUnits": "strokeWidth",\n
\t\t\t\t\t\t"markerWidth": 5,\n
\t\t\t\t\t\t"markerHeight": 5,\n
\t\t\t\t\t\t"orient": "auto",\n
\t\t\t\t\t\t"style": "pointer-events:none" // Currently needed for Opera\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\tvar arrow = addElem({\n
\t\t\t\t\t"element": "path",\n
\t\t\t\t\t"attr": {\n
\t\t\t\t\t\t"d": data.d,\n
\t\t\t\t\t\t"fill": "#000000"\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\tmarker.appendChild(arrow);\n
\t\t\t\tS.findDefs().appendChild(marker);\n
\t\t\t} \n
\t\t\t\n
\t\t\tmarker.setAttribute(\'refX\', data.refx);\n
\t\t\t\n
\t\t\treturn marker;\n
\t\t}\n
\t\t\n
\t\tfunction setArrow() {\n
\t\t\tvar type = this.value;\n
\t\t\tresetMarker();\n
\t\t\n
\t\t\tif(type == "none") {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\n
\t\t\t// Set marker on element\n
\t\t\tvar dir = "fw";\n
\t\t\tif(type == "mid_bk") {\n
\t\t\t\ttype = "mid";\n
\t\t\t\tdir = "bk";\n
\t\t\t} else if(type == "both") {\n
\t\t\t\taddMarker("bk", type);\n
\t\t\t\tsvgCanvas.changeSelectedAttribute("marker-start", "url(#" + pathdata.bk.id + ")");\n
\t\t\t\ttype = "end";\n
\t\t\t\tdir = "fw";\n
\t\t\t} else if (type == "start") {\n
\t\t\t\tdir = "bk";\n
\t\t\t}\n
\t\t\t\n
\t\t\taddMarker(dir, type);\n
\t\t\tsvgCanvas.changeSelectedAttribute("marker-"+type, "url(#" + pathdata[dir].id + ")");\n
\t\t\tS.call("changed", selElems);\n
\t\t}\n
\t\t\n
\t\tfunction colorChanged(elem) {\n
\t\t\tvar color = elem.getAttribute(\'stroke\');\n
\t\t\t\n
\t\t\tvar mtypes = [\'start\',\'mid\',\'end\'];\n
\t\t\tvar defs = S.findDefs();\n
\t\t\t\n
\t\t\t$.each(mtypes, function(i, type) {\n
\t\t\t\tvar marker = getLinked(elem, \'marker-\'+type);\n
\t\t\t\tif(!marker) return;\n
\t\t\t\t\n
\t\t\t\tvar cur_color = $(marker).children().attr(\'fill\');\n
\t\t\t\tvar cur_d = $(marker).children().attr(\'d\');\n
\t\t\t\tvar new_marker = null;\n
\t\t\t\tif(cur_color === color) return;\n
\t\t\t\t\n
\t\t\t\tvar all_markers = $(defs).find(\'marker\');\n
\t\t\t\t// Different color, check if already made\n
\t\t\t\tall_markers.each(function() {\n
\t\t\t\t\tvar attrs = $(this).children().attr([\'fill\', \'d\']);\n
\t\t\t\t\tif(attrs.fill === color && attrs.d === cur_d) {\n
\t\t\t\t\t\t// Found another marker with this color and this path\n
\t\t\t\t\t\tnew_marker = this;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tif(!new_marker) {\n
\t\t\t\t\t// Create a new marker with this color\n
\t\t\t\t\tvar last_id = marker.id;\n
\t\t\t\t\tvar dir = last_id.indexOf(\'_fw\') !== -1?\'fw\':\'bk\';\n
\t\t\t\t\t\n
\t\t\t\t\tnew_marker = addMarker(dir, type, arrowprefix + dir + all_markers.length);\n
\n
\t\t\t\t\t$(new_marker).children().attr(\'fill\', color);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$(elem).attr(\'marker-\'+type, "url(#" + new_marker.id + ")");\n
\t\t\t\t\n
\t\t\t\t// Check if last marker can be removed\n
\t\t\t\tvar remove = true;\n
\t\t\t\t$(S.svgcontent).find(\'line, polyline, path, polygon\').each(function() {\n
\t\t\t\t\tvar elem = this;\n
\t\t\t\t\t$.each(mtypes, function(j, mtype) {\n
\t\t\t\t\t\tif($(elem).attr(\'marker-\' + mtype) === "url(#" + marker.id + ")") {\n
\t\t\t\t\t\t\treturn remove = false;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tif(!remove) return false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t// Not found, so can safely remove\n
\t\t\t\tif(remove) {\n
\t\t\t\t\t$(marker).remove();\n
\t\t\t\t}\n
\n
\t\t\t});\n
\t\t\t\n
\t\t}\n
\t\t\n
\t\treturn {\n
\t\t\tname: "Arrows",\n
\t\t\tcontext_tools: [{\n
\t\t\t\ttype: "select",\n
\t\t\t\tpanel: "arrow_panel",\n
\t\t\t\ttitle: "Select arrow type",\n
\t\t\t\tid: "arrow_list",\n
\t\t\t\toptions: {\n
\t\t\t\t\tnone: "No arrow",\n
\t\t\t\t\tend: "----&gt;",\n
\t\t\t\t\tstart: "&lt;----",\n
\t\t\t\t\tboth: "&lt;---&gt;",\n
\t\t\t\t\tmid: "--&gt;--",\n
\t\t\t\t\tmid_bk: "--&lt;--"\n
\t\t\t\t},\n
\t\t\t\tdefval: "none",\n
\t\t\t\tevents: {\n
\t\t\t\t\tchange: setArrow\n
\t\t\t\t}\n
\t\t\t}],\n
\t\t\tcallback: function() {\n
\t\t\t\t$(\'#arrow_panel\').hide();\n
\t\t\t\t// Set ID so it can be translated in locale file\n
\t\t\t\t$(\'#arrow_list option\')[0].id = \'connector_no_arrow\';\n
\t\t\t},\n
\t\t\taddLangData: function(lang) {\n
\t\t\t\treturn {\n
\t\t\t\t\tdata: lang_list[lang]\n
\t\t\t\t};\n
\t\t\t},\n
\t\t\tselectedChanged: function(opts) {\n
\t\t\t\t\n
\t\t\t\t// Use this to update the current selected elements\n
\t\t\t\tselElems = opts.elems;\n
\t\t\t\t\n
\t\t\t\tvar i = selElems.length;\n
\t\t\t\tvar marker_elems = [\'line\',\'path\',\'polyline\',\'polygon\'];\n
\t\t\t\t\n
\t\t\t\twhile(i--) {\n
\t\t\t\t\tvar elem = selElems[i];\n
\t\t\t\t\tif(elem && $.inArray(elem.tagName, marker_elems) != -1) {\n
\t\t\t\t\t\tif(opts.selectedElement && !opts.multiselected) {\n
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
\t\t\t\tif(elem && (\n
\t\t\t\t\telem.getAttribute("marker-start") ||\n
\t\t\t\t\telem.getAttribute("marker-mid") ||\n
\t\t\t\t\telem.getAttribute("marker-end")\n
\t\t\t\t)) {\n
\t// \t\t\t\t\t\t\t\tvar start = elem.getAttribute("marker-start");\n
\t// \t\t\t\t\t\t\t\tvar mid = elem.getAttribute("marker-mid");\n
\t// \t\t\t\t\t\t\t\tvar end = elem.getAttribute("marker-end");\n
\t\t\t\t\t// Has marker, so see if it should match color\n
\t\t\t\t\tcolorChanged(elem);\n
\t\t\t\t}\n
\t\t\t\t\n
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
            <value> <int>7025</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
