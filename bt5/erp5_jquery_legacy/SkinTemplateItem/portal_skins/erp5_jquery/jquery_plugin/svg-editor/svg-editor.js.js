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
            <value> <string>ts80065743.79</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>svg-editor.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
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
            <value> <int>114964</int> </value>
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

/*\n
 * svg-editor.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 * Copyright(c) 2010 Pavol Rusnak\n
 * Copyright(c) 2010 Jeff Schiller\n
 * Copyright(c) 2010 Narendra Sisodiya\n
 *\n
 */\n
\n
(function() { \n
\t\n
\tif(!window.svgEditor) window.svgEditor = function($) {\n
\t\tvar svgCanvas;\n
\t\tvar Editor = {};\n
\t\tvar is_ready = false;\n
\t\t\n
\t\tvar defaultPrefs = {\n
\t\t\tlang:\'en\',\n
\t\t\ticonsize:\'m\',\n
\t\t\tbkgd_color:\'#FFF\',\n
\t\t\tbkgd_url:\'\',\n
\t\t\timg_save:\'embed\'\n
\t\t\t},\n
\t\t\tcurPrefs = {},\n
\t\t\t\n
\t\t\t// Note: Difference between Prefs and Config is that Prefs can be\n
\t\t\t// changed in the UI and are stored in the browser, config can not\n
\t\t\t\n
\t\t\tcurConfig = {\n
\t\t\t\tcanvas_expansion: 3,\n
\t\t\t\tdimensions: [640,480],\n
\t\t\t\tinitFill: {\n
\t\t\t\t\tcolor: \'FF0000\',  // solid red\n
\t\t\t\t\topacity: 1\n
\t\t\t\t},\n
\t\t\t\tinitStroke: {\n
\t\t\t\t\twidth: 5,\n
\t\t\t\t\tcolor: \'000000\',  // solid black\n
\t\t\t\t\topacity: 1\n
\t\t\t\t},\n
\t\t\t\tinitOpacity: 1,\n
\t\t\t\timgPath: \'jquery_plugin/svg-editor/images/\',\n
\t\t\t\tlangPath: \'jquery_plugin/svg-editor/locale/\',\n
\t\t\t\textPath: \'jquery_plugin/svg-editor/extensions/\',\n
\t\t\t\textensions: [\'ext-markers.js\',\'ext-connector.js\', \'ext-eyedropper.js\'],\n
\t\t\t\tinitTool: \'select\',\n
\t\t\t\twireframe: false\n
\t\t\t},\n
\t\t\tuiStrings = {\n
\t\t\t"invalidAttrValGiven":"Invalid value given",\n
\t\t\t"noContentToFitTo":"No content to fit to",\n
\t\t\t"layer":"Layer",\n
\t\t\t"dupeLayerName":"There is already a layer named that!",\n
\t\t\t"enterUniqueLayerName":"Please enter a unique layer name",\n
\t\t\t"enterNewLayerName":"Please enter the new layer name",\n
\t\t\t"layerHasThatName":"Layer already has that name",\n
\t\t\t"QmoveElemsToLayer":"Move selected elements to layer \\"%s\\"?",\n
\t\t\t"QwantToClear":"Do you want to clear the drawing?\\nThis will also erase your undo history!",\n
\t\t\t"QwantToOpen":"Do you want to open a new file?\\nThis will also erase your undo history!",\n
\t\t\t"QerrorsRevertToSource":"There were parsing errors in your SVG source.\\nRevert back to original SVG source?",\n
\t\t\t"QignoreSourceChanges":"Ignore changes made to SVG source?",\n
\t\t\t"featNotSupported":"Feature not supported",\n
\t\t\t"enterNewImgURL":"Enter the new image URL",\n
\t\t\t"defsFailOnSave": "NOTE: Due to a bug in your browser, this image may appear wrong (missing gradients or elements). It will however appear correct once actually saved.",\n
\t\t\t"loadingImage":"Loading image, please wait...",\n
\t\t\t"saveFromBrowser": "Select \\"Save As...\\" in your browser to save this image as a %s file.",\n
\t\t\t"noteTheseIssues": "Also note the following issues: ",\n
\t\t\t"ok":"OK",\n
\t\t\t"cancel":"Cancel",\n
\t\t\t"key_up":"Up",\n
\t\t\t"key_down":"Down",\n
\t\t\t"key_backspace":"Backspace",\n
\t\t\t"key_del":"Del"\n
\t\t};\n
\t\t\n
\t\tvar curPrefs = {}; //$.extend({}, defaultPrefs);\n
\t\t\n
\t\tEditor.curConfig = curConfig;\n
\t\t\n
\t\t// Store and retrieve preferences\n
\t\t$.pref = function(key, val) {\n
\t\t\tif(val) curPrefs[key] = val;\n
\t\t\tkey = \'svg-edit-\'+key;\n
\t\t\tvar host = location.hostname,\n
\t\t\t\tonweb = host && host.indexOf(\'.\') != -1,\n
\t\t\t\tstore = (val != undefined),\n
\t\t\t\tstorage = false;\n
\t\t\t// Some FF versions throw security errors here\n
\t\t\ttry { \n
\t\t\t\tif(window.localStorage) { // && onweb removed so Webkit works locally\n
\t\t\t\t\tstorage = localStorage;\n
\t\t\t\t}\n
\t\t\t} catch(e) {}\n
\t\t\ttry { \n
\t\t\t\tif(window.globalStorage && onweb) {\n
\t\t\t\t\tstorage = globalStorage[host];\n
\t\t\t\t}\n
\t\t\t} catch(e) {}\n
\t\t\t\n
\t\t\tif(storage) {\n
\t\t\t\tif(store) storage.setItem(key, val);\n
\t\t\t\t\telse if (storage.getItem(key)) return storage.getItem(key) + \'\'; // Convert to string for FF (.value fails in Webkit)\n
\t\t\t} else if(window.widget) {\n
\t\t\t\tif(store) widget.setPreferenceForKey(val, key);\n
\t\t\t\t\telse return widget.preferenceForKey(key);\n
\t\t\t} else {\n
\t\t\t\tif(store) {\n
\t\t\t\t\tvar d = new Date();\n
\t\t\t\t\td.setTime(d.getTime() + 31536000000);\n
\t\t\t\t\tval = encodeURIComponent(val);\n
\t\t\t\t\tdocument.cookie = key+\'=\'+val+\'; expires=\'+d.toUTCString();\n
\t\t\t\t} else {\n
\t\t\t\t\tvar result = document.cookie.match(new RegExp(key + "=([^;]+)"));\n
\t\t\t\t\treturn result?decodeURIComponent(result[1]):\'\';\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tEditor.setConfig = function(opts) {\n
\t\t\t$.each(opts, function(key, val) {\n
\t\t\t\t// Only allow prefs defined in defaultPrefs\n
\t\t\t\tif(key in defaultPrefs) {\n
\t\t\t\t\t$.pref(key, val);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t$.extend(true, curConfig, opts);\n
\t\t\tif(opts.extensions) {\n
\t\t\t\tcurConfig.extensions = opts.extensions;\n
\t\t\t}\n
\n
\t\t}\n
\t\t\n
\t\t// Extension mechanisms must call setCustomHandlers with two functions: opts.open and opts.save\n
\t\t// opts.open\'s responsibilities are:\n
\t\t// \t- invoke a file chooser dialog in \'open\' mode\n
\t\t//\t- let user pick a SVG file\n
\t\t//\t- calls setCanvas.setSvgString() with the string contents of that file\n
\t\t// opts.save\'s responsibilities are:\n
\t\t//\t- accept the string contents of the current document \n
\t\t//\t- invoke a file chooser dialog in \'save\' mode\n
\t\t// \t- save the file to location chosen by the user\n
\t\tEditor.setCustomHandlers = function(opts) {\n
\t\t\tif(opts.open) {\n
\t\t\t\t$(\'#tool_open\').show();\n
\t\t\t\tsvgCanvas.open = opts.open;\n
\t\t\t}\n
\t\t\tif(opts.save) {\n
\t\t\t\tshow_save_warning = false;\n
\t\t\t\tsvgCanvas.bind("saved", opts.save);\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tEditor.randomizeIds = function() {\n
\t\t\tsvgCanvas.randomizeIds(arguments)\n
\t\t}\n
\n
\t\tEditor.init = function() {\n
\t\t\t(function() {\n
\t\t\t\t// Load config/data from URL if given\n
\t\t\t\tvar urldata = $.deparam.querystring(true);\n
\t\t\t\tif(!$.isEmptyObject(urldata)) {\n
\t\t\t\t\tif(urldata.dimensions) {\n
\t\t\t\t\t\turldata.dimensions = urldata.dimensions.split(\',\');\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(urldata.extensions) {\n
\t\t\t\t\t\turldata.extensions = urldata.extensions.split(\',\');\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(urldata.bkgd_color) {\n
\t\t\t\t\t\turldata.bkgd_color = \'#\' + urldata.bkgd_color;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(urldata.bkgd_color) {\n
\t\t\t\t\t\turldata.bkgd_color = \'#\' + urldata.bkgd_color;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tsvgEditor.setConfig(urldata);\n
\t\t\t\t\t\n
\t\t\t\t\tvar src = urldata.source;\n
\t\t\t\t\tvar qstr = $.param.querystring();\n
\t\t\t\t\t\n
\t\t\t\t\tif(src) {\n
\t\t\t\t\t\tif(src.indexOf("data:") === 0) {\n
\t\t\t\t\t\t\t// plusses get replaced by spaces, so re-insert\n
\t\t\t\t\t\t\tsrc = src.replace(/ /g, "+");\n
\t\t\t\t\t\t\tEditor.loadFromDataURI(src);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tEditor.loadFromString(src);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else if(qstr.indexOf(\'paramurl=\') !== -1) {\n
\t\t\t\t\t\t// Get paramater URL (use full length of remaining location.href)\n
\t\t\t\t\t\tsvgEditor.loadFromURL(qstr.substr(9));\n
\t\t\t\t\t} else if(urldata.url) {\n
\t\t\t\t\t\tsvgEditor.loadFromURL(urldata.url);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t})();\n
\t\t\t\n
\t\t\tvar extFunc = function() {\n
\t\t\t\t$.each(curConfig.extensions, function() {\n
\t\t\t\t\t$.getScript(curConfig.extPath + this);\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\t// Load extensions\n
\t\t\t// Bit of a hack to run extensions in local Opera\n
\t\t\tif(window.opera && document.location.protocol === \'file:\') {\n
\t\t\t\tsetTimeout(extFunc, 1000);\n
\t\t\t} else {\n
\t\t\t\textFunc();\n
\t\t\t}\n
\t\t\t\n
\t\t\t$.svgIcons(curConfig.imgPath + \'svg_edit_icons.svg\', {\n
\t\t\t\tw:24, h:24,\n
\t\t\t\tid_match: false,\n
\t\t\t\tno_img: true,\n
\t\t\t\tfallback_path: curConfig.imgPath,\n
\t\t\t\tfallback:{\n
\t\t\t\t\t\'new_image\':\'clear.png\',\n
\t\t\t\t\t\'save\':\'save.png\',\n
\t\t\t\t\t\'open\':\'open.png\',\n
\t\t\t\t\t\'source\':\'source.png\',\n
\t\t\t\t\t\'docprops\':\'document-properties.png\',\n
\t\t\t\t\t\'wireframe\':\'wireframe.png\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'undo\':\'undo.png\',\n
\t\t\t\t\t\'redo\':\'redo.png\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'select\':\'select.png\',\n
\t\t\t\t\t\'select_node\':\'select_node.png\',\n
\t\t\t\t\t\'pencil\':\'fhpath.png\',\n
\t\t\t\t\t\'pen\':\'line.png\',\n
\t\t\t\t\t\'square\':\'square.png\',\n
\t\t\t\t\t\'rect\':\'rect.png\',\n
\t\t\t\t\t\'fh_rect\':\'freehand-square.png\',\n
\t\t\t\t\t\'circle\':\'circle.png\',\n
\t\t\t\t\t\'ellipse\':\'ellipse.png\',\n
\t\t\t\t\t\'fh_ellipse\':\'freehand-circle.png\',\n
\t\t\t\t\t\'path\':\'path.png\',\n
\t\t\t\t\t\'text\':\'text.png\',\n
\t\t\t\t\t\'image\':\'image.png\',\n
\t\t\t\t\t\'zoom\':\'zoom.png\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'clone\':\'clone.png\',\n
\t\t\t\t\t\'node_clone\':\'node_clone.png\',\n
\t\t\t\t\t\'delete\':\'delete.png\',\n
\t\t\t\t\t\'node_delete\':\'node_delete.png\',\n
\t\t\t\t\t\'group\':\'shape_group.png\',\n
\t\t\t\t\t\'ungroup\':\'shape_ungroup.png\',\n
\t\t\t\t\t\'move_top\':\'move_top.png\',\n
\t\t\t\t\t\'move_bottom\':\'move_bottom.png\',\n
\t\t\t\t\t\'to_path\':\'to_path.png\',\n
\t\t\t\t\t\'link_controls\':\'link_controls.png\',\n
\t\t\t\t\t\'reorient\':\'reorient.png\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'align_left\':\'align-left.png\',\n
\t\t\t\t\t\'align_center\':\'align-center\',\n
\t\t\t\t\t\'align_right\':\'align-right\',\n
\t\t\t\t\t\'align_top\':\'align-top\',\n
\t\t\t\t\t\'align_middle\':\'align-middle\',\n
\t\t\t\t\t\'align_bottom\':\'align-bottom\',\n
\t\t\n
\t\t\t\t\t\'go_up\':\'go-up.png\',\n
\t\t\t\t\t\'go_down\':\'go-down.png\',\n
\t\t\n
\t\t\t\t\t\'ok\':\'save.png\',\n
\t\t\t\t\t\'cancel\':\'cancel.png\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'arrow_right\':\'flyouth.png\',\n
\t\t\t\t\t\'arrow_down\':\'dropdown.gif\'\n
\t\t\t\t},\n
\t\t\t\tplacement: {\n
\t\t\t\t\t\'#logo\':\'logo\',\n
\t\t\t\t\n
\t\t\t\t\t\'#tool_clear div,#layer_new\':\'new_image\',\n
\t\t\t\t\t\'#tool_save div\':\'save\',\n
\t\t\t\t\t\'#tool_export div\':\'export\',\n
\t\t\t\t\t\'#tool_open div div\':\'open\',\n
\t\t\t\t\t\'#tool_import div div\':\'import\',\n
\t\t\t\t\t\'#tool_source\':\'source\',\n
\t\t\t\t\t\'#tool_docprops > div\':\'docprops\',\n
\t\t\t\t\t\'#tool_wireframe\':\'wireframe\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#tool_undo\':\'undo\',\n
\t\t\t\t\t\'#tool_redo\':\'redo\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#tool_select\':\'select\',\n
\t\t\t\t\t\'#tool_fhpath\':\'pencil\',\n
\t\t\t\t\t\'#tool_line\':\'pen\',\n
\t\t\t\t\t\'#tool_rect,#tools_rect_show\':\'rect\',\n
\t\t\t\t\t\'#tool_square\':\'square\',\n
\t\t\t\t\t\'#tool_fhrect\':\'fh_rect\',\n
\t\t\t\t\t\'#tool_ellipse,#tools_ellipse_show\':\'ellipse\',\n
\t\t\t\t\t\'#tool_circle\':\'circle\',\n
\t\t\t\t\t\'#tool_fhellipse\':\'fh_ellipse\',\n
\t\t\t\t\t\'#tool_path\':\'path\',\n
\t\t\t\t\t\'#tool_text,#layer_rename\':\'text\',\n
\t\t\t\t\t\'#tool_image\':\'image\',\n
\t\t\t\t\t\'#tool_zoom\':\'zoom\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#tool_clone,#tool_clone_multi\':\'clone\',\n
\t\t\t\t\t\'#tool_node_clone\':\'node_clone\',\n
\t\t\t\t\t\'#layer_delete,#tool_delete,#tool_delete_multi\':\'delete\',\n
\t\t\t\t\t\'#tool_node_delete\':\'node_delete\',\n
\t\t\t\t\t\'#tool_add_subpath\':\'add_subpath\',\n
\t\t\t\t\t\'#tool_openclose_path\':\'open_path\',\n
\t\t\t\t\t\'#tool_move_top\':\'move_top\',\n
\t\t\t\t\t\'#tool_move_bottom\':\'move_bottom\',\n
\t\t\t\t\t\'#tool_topath\':\'to_path\',\n
\t\t\t\t\t\'#tool_node_link\':\'link_controls\',\n
\t\t\t\t\t\'#tool_reorient\':\'reorient\',\n
\t\t\t\t\t\'#tool_group\':\'group\',\n
\t\t\t\t\t\'#tool_ungroup\':\'ungroup\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#tool_alignleft, #tool_posleft\':\'align_left\',\n
\t\t\t\t\t\'#tool_aligncenter, #tool_poscenter\':\'align_center\',\n
\t\t\t\t\t\'#tool_alignright, #tool_posright\':\'align_right\',\n
\t\t\t\t\t\'#tool_aligntop, #tool_postop\':\'align_top\',\n
\t\t\t\t\t\'#tool_alignmiddle, #tool_posmiddle\':\'align_middle\',\n
\t\t\t\t\t\'#tool_alignbottom, #tool_posbottom\':\'align_bottom\',\n
\t\t\t\t\t\'#cur_position\':\'align\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#linecap_butt,#cur_linecap\':\'linecap_butt\',\n
\t\t\t\t\t\'#linecap_round\':\'linecap_round\',\n
\t\t\t\t\t\'#linecap_square\':\'linecap_square\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#linejoin_miter,#cur_linejoin\':\'linejoin_miter\',\n
\t\t\t\t\t\'#linejoin_round\':\'linejoin_round\',\n
\t\t\t\t\t\'#linejoin_bevel\':\'linejoin_bevel\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#url_notice\':\'warning\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#layer_up\':\'go_up\',\n
\t\t\t\t\t\'#layer_down\':\'go_down\',\n
\t\t\t\t\t\'#layerlist td.layervis\':\'eye\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#tool_source_save,#tool_docprops_save\':\'ok\',\n
\t\t\t\t\t\'#tool_source_cancel,#tool_docprops_cancel\':\'cancel\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'#rwidthLabel, #iwidthLabel\':\'width\',\n
\t\t\t\t\t\'#rheightLabel, #iheightLabel\':\'height\',\n
\t\t\t\t\t\'#cornerRadiusLabel span\':\'c_radius\',\n
\t\t\t\t\t\'#angleLabel\':\'angle\',\n
\t\t\t\t\t\'#zoomLabel\':\'zoom\',\n
\t\t\t\t\t\'#tool_fill label\': \'fill\',\n
\t\t\t\t\t\'#tool_stroke .icon_label\': \'stroke\',\n
\t\t\t\t\t\'#group_opacityLabel\': \'opacity\',\n
\t\t\t\t\t\'#blurLabel\': \'blur\',\n
\t\t\t\t\t\'#font_sizeLabel\': \'fontsize\',\n
\t\t\t\t\t\n
\t\t\t\t\t\'.flyout_arrow_horiz\':\'arrow_right\',\n
\t\t\t\t\t\'.dropdown button, #main_button .dropdown\':\'arrow_down\',\n
\t\t\t\t\t\'#palette .palette_item:first, #fill_bg, #stroke_bg\':\'no_color\'\n
\t\t\t\t},\n
\t\t\t\tresize: {\n
\t\t\t\t\t\'#logo .svg_icon\': 32,\n
\t\t\t\t\t\'.flyout_arrow_horiz .svg_icon\': 5,\n
\t\t\t\t\t\'.layer_button .svg_icon, #layerlist td.layervis .svg_icon\': 14,\n
\t\t\t\t\t\'.dropdown button .svg_icon\': 7,\n
\t\t\t\t\t\'#main_button .dropdown .svg_icon\': 9,\n
\t\t\t\t\t\'.palette_item:first .svg_icon, #fill_bg .svg_icon, #stroke_bg .svg_icon\': 16,\n
\t\t\t\t\t\'.toolbar_button button .svg_icon\':16,\n
\t\t\t\t\t\'.stroke_tool div div .svg_icon\': 20,\n
\t\t\t\t\t\'#tools_bottom label .svg_icon\': 18\n
\t\t\t\t},\n
\t\t\t\tcallback: function(icons) {\n
\t\t\t\t\t$(\'.toolbar_button button > svg, .toolbar_button button > img\').each(function() {\n
\t\t\t\t\t\t$(this).parent().prepend(this);\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\t// Use small icons by default if not all left tools are visible\n
\t\t\t\t\tvar tleft = $(\'#tools_left\');\n
\t\t\t\t\tvar min_height = tleft.offset().top + tleft.outerHeight();\n
\t\t\t\t\tvar size = $.pref(\'iconsize\');\n
\t\t\t\t\tif(size && size != \'m\') {\n
\t\t\t\t\t\tsvgEditor.setIconSize(size);\t\t\t\t\n
\t\t\t\t\t} else if($(window).height() < min_height) {\n
\t\t\t\t\t\t// Make smaller\n
\t\t\t\t\t\tsvgEditor.setIconSize(\'s\');\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// Look for any missing flyout icons from plugins\n
\t\t\t\t\t$(\'.tools_flyout\').each(function() {\n
\t\t\t\t\t\tvar shower = $(\'#\' + this.id + \'_show\');\n
\t\t\t\t\t\tvar sel = shower.attr(\'data-curopt\');\n
\t\t\t\t\t\t// Check if there\'s an icon here\n
\t\t\t\t\t\tif(!shower.children(\'svg, img\').length) {\n
\t\t\t\t\t\t\tvar clone = $(sel).children().clone();\n
\t\t\t\t\t\t\tclone[0].removeAttribute(\'style\'); //Needed for Opera\n
\t\t\t\t\t\t\tshower.append(clone);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\tsvgEditor.runCallbacks();\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\tEditor.canvas = svgCanvas = new $.SvgCanvas(document.getElementById("svgcanvas"), curConfig);\n
\t\t\t\n
\t\t\tvar palette = ["#000000", "#3f3f3f", "#7f7f7f", "#bfbfbf", "#ffffff",\n
\t\t\t           "#ff0000", "#ff7f00", "#ffff00", "#7fff00",\n
\t\t\t           "#00ff00", "#00ff7f", "#00ffff", "#007fff",\n
\t\t\t           "#0000ff", "#7f00ff", "#ff00ff", "#ff007f",\n
\t\t\t           "#7f0000", "#7f3f00", "#7f7f00", "#3f7f00",\n
\t\t\t           "#007f00", "#007f3f", "#007f7f", "#003f7f",\n
\t\t\t           "#00007f", "#3f007f", "#7f007f", "#7f003f",\n
\t\t\t           "#ffaaaa", "#ffd4aa", "#ffffaa", "#d4ffaa",\n
\t\t\t           "#aaffaa", "#aaffd4", "#aaffff", "#aad4ff",\n
\t\t\t           "#aaaaff", "#d4aaff", "#ffaaff", "#ffaad4",\n
\t\t\t           ];\n
\t\n
\t\t\t\tisMac = false, //(navigator.platform.indexOf("Mac") != -1);\n
\t\t\t\tmodKey = "", //(isMac ? "meta+" : "ctrl+");\n
\t\t\t\tpath = svgCanvas.pathActions,\n
\t\t\t\tdefault_img_url = curConfig.imgPath + "logo.png",\n
\t\t\t\tworkarea = $("#workarea"),\n
\t\t\t\tshow_save_warning = false, \n
\t\t\t\texportWindow = null;\n
\n
\t\t\t// This sets up alternative dialog boxes. They mostly work the same way as\n
\t\t\t// their UI counterparts, expect instead of returning the result, a callback\n
\t\t\t// needs to be included that returns the result as its first parameter.\n
\t\t\t// In the future we may want to add additional types of dialog boxes, since \n
\t\t\t// they should be easy to handle this way.\n
\t\t\t(function() {\n
\t\t\t\t$(\'#dialog_container\').draggable({cancel:\'#dialog_content, #dialog_buttons *\'});\n
\t\t\t\tvar box = $(\'#dialog_box\'), btn_holder = $(\'#dialog_buttons\');\n
\t\t\t\t\n
\t\t\t\tvar dbox = function(type, msg, callback, defText) {\n
\t\t\t\t\t$(\'#dialog_content\').html(\'<p>\'+msg.replace(/\\n/g,\'</p><p>\')+\'</p>\')\n
\t\t\t\t\t\t.toggleClass(\'prompt\',(type==\'prompt\'));\n
\t\t\t\t\tbtn_holder.empty();\n
\t\t\t\t\t\n
\t\t\t\t\tvar ok = $(\'<input type="button" value="\' + uiStrings.ok + \'">\').appendTo(btn_holder);\n
\t\t\t\t\n
\t\t\t\t\tif(type != \'alert\') {\n
\t\t\t\t\t\t$(\'<input type="button" value="\' + uiStrings.cancel + \'">\')\n
\t\t\t\t\t\t\t.appendTo(btn_holder)\n
\t\t\t\t\t\t\t.click(function() { box.hide();callback(false)});\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(type == \'prompt\') {\n
\t\t\t\t\t\tvar input = $(\'<input type="text">\').prependTo(btn_holder);\n
\t\t\t\t\t\tinput.val(defText || \'\');\n
\t\t\t\t\t\tinput.bind(\'keydown\', \'return\', function() {ok.click();});\n
\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\tbox.show();\n
\t\t\t\t\t\n
\t\t\t\t\tok.click(function() { \n
\t\t\t\t\t\tbox.hide();\n
\t\t\t\t\t\tvar resp = (type == \'prompt\')?input.val():true;\n
\t\t\t\t\t\tif(callback) callback(resp);\n
\t\t\t\t\t}).focus();\n
\t\t\t\t\t\n
\t\t\t\t\tif(type == \'prompt\') input.focus();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$.alert = function(msg, cb) { dbox(\'alert\', msg, cb);};\n
\t\t\t\t$.confirm = function(msg, cb) {\tdbox(\'confirm\', msg, cb);};\n
\t\t\t\t$.prompt = function(msg, txt, cb) { dbox(\'prompt\', msg, cb, txt);};\n
\t\t\t}());\n
\t\t\t\n
\t\t\tvar setSelectMode = function() {\n
\t\t\t\t$(\'.tool_button_current\').removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
\t\t\t\t$(\'#tool_select\').addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
\t\t\t\t$(\'#styleoverrides\').text(\'#svgcanvas svg *{cursor:move;pointer-events:all} #svgcanvas svg{cursor:default}\');\n
\t\t\t\tsvgCanvas.setMode(\'select\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar togglePathEditMode = function(editmode, elems) {\n
\t\t\t\t$(\'#path_node_panel\').toggle(editmode);\n
\t\t\t\t$(\'#tools_bottom_2,#tools_bottom_3\').toggle(!editmode);\n
\t\t\t\tif(editmode) {\n
\t\t\t\t\t// Change select icon\n
\t\t\t\t\t$(\'.tool_button_current\').removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
\t\t\t\t\t$(\'#tool_select\').addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
\t\t\t\t\tsetIcon(\'#tool_select\', \'select_node\');\n
\t\t\t\t\tmultiselected = false;\n
\t\t\t\t\tif(elems.length) {\n
\t\t\t\t\t\tselectedElement = elems[0];\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tsetIcon(\'#tool_select\', \'select\');\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
\t\t\t// used to make the flyouts stay on the screen longer the very first time\n
\t\t\tvar flyoutspeed = 1250;\n
\t\t\tvar textBeingEntered = false;\n
\t\t\tvar selectedElement = null;\n
\t\t\tvar multiselected = false;\n
\t\t\tvar editingsource = false;\n
\t\t\tvar docprops = false;\n
\t\t\t\n
\t\t\tvar fillPaint = new $.jGraduate.Paint({solidColor: curConfig.initFill.color});\n
\t\t\tvar strokePaint = new $.jGraduate.Paint({solidColor: curConfig.initStroke.color});\n
\t\t\n
\t\t\tvar saveHandler = function(window,svg) {\n
\t\t\t\tshow_save_warning = false;\n
\t\t\t\n
\t\t\t\t// by default, we add the XML prolog back, systems integrating SVG-edit (wikis, CMSs) \n
\t\t\t\t// can just provide their own custom save handler and might not want the XML prolog\n
\t\t\t\tsvg = "<?xml version=\'1.0\'?>\\n" + svg;\n
\t\t\t\t\n
\t\t\t\t// Opens the SVG in new window, with warning about Mozilla bug #308590 when applicable\n
\t\t\t\t\n
\t\t\t\tvar win = window.open("data:image/svg+xml;base64," + Utils.encode64(svg));\n
\t\t\t\t\n
\t\t\t\t// Alert will only appear the first time saved OR the first time the bug is encountered\n
\t\t\t\tvar done = $.pref(\'save_notice_done\');\n
\t\t\t\tif(done !== "all") {\n
\t\t\n
\t\t\t\t\tvar note = uiStrings.saveFromBrowser.replace(\'%s\', \'SVG\');\n
\t\t\t\t\t\n
\t\t\t\t\t// Check if FF and has <defs/>\n
\t\t\t\t\tif(navigator.userAgent.indexOf(\'Gecko/\') !== -1) {\n
\t\t\t\t\t\tif(svg.indexOf(\'<defs\') !== -1) {\n
\t\t\t\t\t\t\tnote += "\\n\\n" + uiStrings.defsFailOnSave;\n
\t\t\t\t\t\t\t$.pref(\'save_notice_done\', \'all\');\n
\t\t\t\t\t\t\tdone = "all";\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t$.pref(\'save_notice_done\', \'part\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t$.pref(\'save_notice_done\', \'all\'); \n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(done !== \'part\') {\n
\t\t\t\t\t\twin.alert(note);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar exportHandler = function(window, data) {\n
\t\t\t\tvar issues = data.issues;\n
\t\t\t\t\n
\t\t\t\tif(!$(\'#export_canvas\').length) {\n
\t\t\t\t\t$(\'<canvas>\', {id: \'export_canvas\'}).hide().appendTo(\'body\');\n
\t\t\t\t}\n
\t\t\t\tvar c = $(\'#export_canvas\')[0];\n
\t\t\t\t\n
\t\t\t\tc.width = svgCanvas.contentW;\n
\t\t\t\tc.height = svgCanvas.contentH;\n
\t\t\t\tcanvg(c, data.svg);\n
\t\t\t\tvar datauri = c.toDataURL(\'image/png\');\n
\t\t\t\texportWindow.location.href = datauri;\n
\t\t\t\t\n
\t\t\t\tvar note = uiStrings.saveFromBrowser.replace(\'%s\', \'PNG\');\n
\t\t\t\t\n
\t\t\t\t// Check if there\'s issues\n
\n
\t\t\t\tif(issues.length) {\n
\t\t\t\t\tvar pre = "\\n \\u2022 ";\n
\t\t\t\t\tnote += ("\\n\\n" + uiStrings.noteTheseIssues + pre + issues.join(pre));\n
\t\t\t\t} \n
\t\t\t\texportWindow.alert(note);\n
\t\t\t};\n
\t\t\t\n
\t\t\t// called when we\'ve selected a different element\n
\t\t\tvar selectedChanged = function(window,elems) {\n
\t\t\t\tvar mode = svgCanvas.getMode();\n
\t\t\t\tvar is_node = (mode == "pathedit");\n
\t\t\t\t// if elems[1] is present, then we have more than one element\n
\t\t\t\tselectedElement = (elems.length == 1 || elems[1] == null ? elems[0] : null);\n
\t\t\t\tmultiselected = (elems.length >= 2 && elems[1] != null);\n
\t\t\t\tif (selectedElement != null) {\n
\t\t\t\t\t// unless we\'re already in always set the mode of the editor to select because\n
\t\t\t\t\t// upon creation of a text element the editor is switched into\n
\t\t\t\t\t// select mode and this event fires - we need our UI to be in sync\n
\t\t\t\t\t\n
\t\t\t\t\tif (mode != "multiselect" && !is_node) {\n
\t\t\t\t\t\tsetSelectMode();\n
\t\t\t\t\t\tupdateToolbar();\n
\t\t\t\t\t} \n
\t\t\t\t\t\n
\t\t\t\t} // if (elem != null)\n
\t\t\n
\t\t\t\t// Deal with pathedit mode\n
\t\t\t\ttogglePathEditMode(is_node, elems);\n
\t\t\t\tupdateContextPanel();\n
\t\t\t\tsvgCanvas.runExtensions("selectedChanged", {\n
\t\t\t\t\telems: elems,\n
\t\t\t\t\tselectedElement: selectedElement,\n
\t\t\t\t\tmultiselected: multiselected\n
\t\t\t\t});\n
\t\t\t};\n
\t\t\n
\t\t\t// called when any element has changed\n
\t\t\tvar elementChanged = function(window,elems) {\n
\t\t\t\tfor (var i = 0; i < elems.length; ++i) {\n
\t\t\t\t\tvar elem = elems[i];\n
\t\t\t\t\t\n
\t\t\t\t\t// if the element changed was the svg, then it could be a resolution change\n
\t\t\t\t\tif (elem && elem.tagName == "svg") {\n
\t\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t\tupdateCanvas();\n
\t\t\t\t\t} \n
\t\t\t\t\t// Update selectedElement if element is no longer part of the image.\n
\t\t\t\t\t// This occurs for the text elements in Firefox\n
\t\t\t\t\telse if(elem && selectedElement && selectedElement.parentNode == null\n
\t\t\t\t\t\t|| elem && elem.tagName == "path") {\n
\t\t\t\t\t\tselectedElement = elem;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tshow_save_warning = true;\n
\t\t\n
\t\t\t\t// we update the contextual panel with potentially new\n
\t\t\t\t// positional/sizing information (we DON\'T want to update the\n
\t\t\t\t// toolbar here as that creates an infinite loop)\n
\t\t\t\t// also this updates the history buttons\n
\t\t\n
\t\t\t\t// we tell it to skip focusing the text control if the\n
\t\t\t\t// text element was previously in focus\n
\t\t\t\tupdateContextPanel();\n
\t\t\t\t\n
\t\t\t\tsvgCanvas.runExtensions("elementChanged", {\n
\t\t\t\t\telems: elems\n
\t\t\t\t});\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar zoomChanged = function(window, bbox, autoCenter) {\n
\t\t\t\tvar scrbar = 15,\n
\t\t\t\t\tres = svgCanvas.getResolution(),\n
\t\t\t\t\tw_area = workarea,\n
\t\t\t\t\tcanvas_pos = $(\'#svgcanvas\').position();\n
\t\t\t\tw_area.css(\'cursor\',\'auto\');\n
\t\t\t\tvar z_info = svgCanvas.setBBoxZoom(bbox, w_area.width()-scrbar, w_area.height()-scrbar);\n
\t\t\t\tif(!z_info) return;\n
\t\t\t\tvar zoomlevel = z_info.zoom,\n
\t\t\t\t\tbb = z_info.bbox;\n
\t\t\t\t$(\'#zoom\').val(Math.round(zoomlevel*100));\n
\t\t\t\t\n
\t\t\t\tif(autoCenter) {\n
\t\t\t\t\tupdateCanvas();\n
\t\t\t\t} else {\n
\t\t\t\t\tupdateCanvas(false, {x: bb.x * zoomlevel + (bb.width * zoomlevel)/2, y: bb.y * zoomlevel + (bb.height * zoomlevel)/2});\n
\t\t\t\t}\n
\t\t\n
\t\t\t\tif(svgCanvas.getMode() == \'zoom\' && bb.width) {\n
\t\t\t\t\t// Go to select if a zoom box was drawn\n
\t\t\t\t\tsetSelectMode();\n
\t\t\t\t}\n
\t\t\t\tzoomDone();\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar flyout_funcs = {};\n
\t\t\t\n
\t\t\tvar setupFlyouts = function(holders) {\n
\t\t\t\t$.each(holders, function(hold_sel, btn_opts) {\n
\t\t\t\t\tvar buttons = $(hold_sel).children();\n
\t\t\t\t\tvar show_sel = hold_sel + \'_show\';\n
\t\t\t\t\tvar def = false;\n
\t\t\t\t\tbuttons.addClass(\'tool_button\')\n
\t\t\t\t\t\t.unbind(\'click mousedown mouseup\') // may not be necessary\n
\t\t\t\t\t\t.each(function(i) {\n
\t\t\t\t\t\t\t// Get this buttons options\n
\t\t\t\t\t\t\tvar opts = btn_opts[i];\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Remember the function that goes with this ID\n
\t\t\t\t\t\t\tflyout_funcs[opts.sel] = opts.fn;\n
\t\t\n
\t\t\t\t\t\t\tif(opts.isDefault) def = i;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Clicking the icon in flyout should set this set\'s icon\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar func = function() {\n
\t\t\t\t\t\t\t\tif($(this).hasClass(\'disabled\')) return false;\n
\t\t\t\t\t\t\t\tif (toolButtonClick(show_sel)) {\n
\t\t\t\t\t\t\t\t\topts.fn();\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tif(opts.icon) {\n
\t\t\t\t\t\t\t\t\tvar icon = $.getSvgIcon(opts.icon).clone();\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t// \n
\t\t\t\t\t\t\t\t\tvar icon = $(opts.sel).children().eq(0).clone();\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\tvar shower = $(show_sel);\n
\t\t\t\t\t\t\t\ticon[0].setAttribute(\'width\',shower.width());\n
\t\t\t\t\t\t\t\ticon[0].setAttribute(\'height\',shower.height());\n
\t\t\t\t\t\t\t\tshower.children(\':not(.flyout_arrow_horiz)\').remove();\n
\t\t\t\t\t\t\t\tshower.append(icon).attr(\'data-curopt\', opts.sel); // This sets the current mode\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t$(this).mouseup(func);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(opts.key) {\n
\t\t\t\t\t\t\t\t$(document).bind(\'keydown\', opts.key+\'\', func);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\tif(def) {\n
\t\t\t\t\t\t$(show_sel).attr(\'data-curopt\', btn_opts[def].sel);\n
\t\t\t\t\t} else if(!$(show_sel).attr(\'data-curopt\')) {\n
\t\t\t\t\t\t// Set first as default\n
\t\t\t\t\t\t$(show_sel).attr(\'data-curopt\', btn_opts[0].sel);\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar timer;\n
\t\t\t\t\t\n
\t\t\t\t\t// Clicking the "show" icon should set the current mode\n
\t\t\t\t\t$(show_sel).mousedown(function(evt) {\n
\t\t\t\t\t\tif($(show_sel).hasClass(\'disabled\')) return false;\n
\t\t\t\t\t\tvar holder = $(show_sel.replace(\'_show\',\'\'));\n
\t\t\t\t\t\tvar l = holder.css(\'left\');\n
\t\t\t\t\t\tvar w = holder.width()*-1;\n
\t\t\t\t\t\tvar time = holder.data(\'shown_popop\')?200:0;\n
\t\t\t\t\t\ttimer = setTimeout(function() {\n
\t\t\t\t\t\t\t// Show corresponding menu\n
\t\t\t\t\t\t\tholder.css(\'left\', w).show().animate({\n
\t\t\t\t\t\t\t\tleft: l\n
\t\t\t\t\t\t\t},150);\n
\t\t\t\t\t\t\tholder.data(\'shown_popop\',true);\n
\t\t\t\t\t\t},time);\n
\t\t\t\t\t\tevt.preventDefault();\n
\t\t\t\t\t}).mouseup(function() {\n
\t\t\t\t\t\tclearTimeout(timer);\n
\t\t\t\t\t\tvar opt = $(this).attr(\'data-curopt\');\n
\t\t\t\t\t\tif (toolButtonClick(show_sel)) {\n
\t\t\t\t\t\t\tflyout_funcs[opt]();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\t// \t$(\'#tools_rect\').mouseleave(function(){$(\'#tools_rect\').fadeOut();});\n
\t\t\t\t\t\n
\t\t\t\t\tvar pos = $(show_sel).position();\n
\t\t\t\t\t$(hold_sel).css({\'left\': pos.left+34, \'top\': pos.top+77});\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tsetFlyoutTitles();\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar makeFlyoutHolder = function(id, child) {\n
\t\t\t\tvar div = $(\'<div>\',{\n
\t\t\t\t\t\'class\': \'tools_flyout\',\n
\t\t\t\t\tid: id\n
\t\t\t\t}).appendTo(\'#svg_editor\').append(child);\n
\t\t\t\t\n
\t\t\t\treturn div;\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar setFlyoutPositions = function() {\n
\t\t\t\t$(\'.tools_flyout\').each(function() {\n
\t\t\t\t\tvar shower = $(\'#\' + this.id + \'_show\');\n
\t\t\t\t\tvar pos = shower.offset();\n
\t\t\t\t\tvar w = shower.outerWidth();\n
\t\t\t\t\t$(this).css({left: pos.left + w, top: pos.top});\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar setFlyoutTitles = function() {\n
\t\t\t\t$(\'.tools_flyout\').each(function() {\n
\t\t\t\t\tvar shower = $(\'#\' + this.id + \'_show\');\n
\t\t\t\t\tvar tooltips = [];\n
\t\t\t\t\t$(this).children().each(function() {\n
\t\t\t\t\t\ttooltips.push(this.title);\n
\t\t\t\t\t});\n
\t\t\t\t\tshower[0].title = tooltips.join(\' / \');\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar extAdded = function(window, ext) {\n
\t\t\n
\t\t\t\tvar cb_called = false;\n
\t\t\t\t\n
\t\t\t\tvar runCallback = function() {\n
\t\t\t\t\tif(ext.callback && !cb_called) {\n
\t\t\t\t\t\tcb_called = true;\n
\t\t\t\t\t\text.callback();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\n
\t\t\t\tvar btn_selects = [];\n
\t\t\n
\t\t\t\tif(ext.context_tools) {\n
\t\t\t\t\t$.each(ext.context_tools, function(i, tool) {\n
\t\t\t\t\t\t// Add select tool\n
\t\t\t\t\t\tvar cont_id = tool.container_id?(\' id="\' + tool.container_id + \'"\'):"";\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar panel = $(\'#\' + tool.panel);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// create the panel if it doesn\'t exist\n
\t\t\t\t\t\tif(!panel.length)\n
\t\t\t\t\t\t\tpanel = $(\'<div>\', {id: tool.panel}).appendTo("#tools_top");\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// TODO: Allow support for other types, or adding to existing tool\n
\t\t\t\t\t\tswitch (tool.type) {\n
\t\t\t\t\t\tcase \'tool_button\':\n
\t\t\t\t\t\t\tvar html = \'<div class="tool_button">\' + tool.id + \'</div>\';\n
\t\t\t\t\t\t\tvar div = $(html).appendTo(panel);\n
\t\t\t\t\t\t\tif (tool.events) {\n
\t\t\t\t\t\t\t\t$.each(tool.events, function(evt, func) {\n
\t\t\t\t\t\t\t\t\t$(div).bind(evt, func);\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'select\':\n
\t\t\t\t\t\t\tvar html = \'<label\' + cont_id + \'>\'\n
\t\t\t\t\t\t\t\t+ \'<select id="\' + tool.id + \'">\';\n
\t\t\t\t\t\t\t$.each(tool.options, function(val, text) {\n
\t\t\t\t\t\t\t\tvar sel = (val == tool.defval) ? " selected":"";\n
\t\t\t\t\t\t\t\thtml += \'<option value="\'+val+\'"\' + sel + \'>\' + text + \'</option>\';\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\thtml += "</select></label>";\n
\t\t\t\t\t\t\t// Creates the tool, hides & adds it, returns the select element\n
\t\t\t\t\t\t\tvar sel = $(html).appendTo(panel).find(\'select\');\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t$.each(tool.events, function(evt, func) {\n
\t\t\t\t\t\t\t\t$(sel).bind(evt, func);\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'button-select\': \n
\t\t\t\t\t\t\tvar html = \'<div id="\' + tool.id + \'" class="dropdown toolset" title="\' + tool.title + \'">\'\n
\t\t\t\t\t\t\t\t+ \'<div id="cur_\' + tool.id + \'" class="icon_label"></div><button></button></div>\';\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar list = $(\'<ul id="\' + tool.id + \'_opts"></ul>\').appendTo(\'#option_lists\');\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(tool.colnum) {\n
\t\t\t\t\t\t\t\tlist.addClass(\'optcols\' + tool.colnum);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Creates the tool, hides & adds it, returns the select element\n
\t\t\t\t\t\t\tvar dropdown = $(html).appendTo(panel).children();\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tbtn_selects.push({\n
\t\t\t\t\t\t\t\telem: (\'#\' + tool.id),\n
\t\t\t\t\t\t\t\tlist: (\'#\' + tool.id + \'_opts\'),\n
\t\t\t\t\t\t\t\ttitle: tool.title,\n
\t\t\t\t\t\t\t\tcallback: tool.events.change,\n
\t\t\t\t\t\t\t\tcur: (\'#cur_\' + tool.id)\n
\t\t\t\t\t\t\t});\n
\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'input\':\n
\t\t\t\t\t\t\tvar html = \'<label\' + cont_id + \'>\'\n
\t\t\t\t\t\t\t\t+ \'<span id="\' + tool.id + \'_label">\' \n
\t\t\t\t\t\t\t\t+ tool.label + \':</span>\'\n
\t\t\t\t\t\t\t\t+ \'<input id="\' + tool.id + \'" title="\' + tool.title\n
\t\t\t\t\t\t\t\t+ \'" size="\' + (tool.size || "4") + \'" value="\' + (tool.defval || "") + \'" type="text"/></label>\'\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Creates the tool, hides & adds it, returns the select element\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Add to given tool.panel\n
\t\t\t\t\t\t\tvar inp = $(html).appendTo(panel).find(\'input\');\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(tool.spindata) {\n
\t\t\t\t\t\t\t\tinp.SpinButton(tool.spindata);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(tool.events) {\n
\t\t\t\t\t\t\t\t$.each(tool.events, function(evt, func) {\n
\t\t\t\t\t\t\t\t\tinp.bind(evt, func);\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\tdefault:\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(ext.buttons) {\n
\t\t\t\t\tvar fallback_obj = {},\n
\t\t\t\t\t\tplacement_obj = {},\n
\t\t\t\t\t\tsvgicons = ext.svgicons;\n
\t\t\t\t\tvar holders = {};\n
\t\t\t\t\t\n
\t\t\t\t\n
\t\t\t\t\t// Add buttons given by extension\n
\t\t\t\t\t$.each(ext.buttons, function(i, btn) {\n
\t\t\t\t\t\tvar icon;\n
\t\t\t\t\t\tvar id = btn.id;\n
\t\t\t\t\t\tvar num = i;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Give button a unique ID\n
\t\t\t\t\t\twhile($(\'#\'+id).length) {\n
\t\t\t\t\t\t\tid = btn.id + \'_\' + (++num);\n
\t\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\t\tif(!svgicons) {\n
\t\t\t\t\t\t\ticon = $(\'<img src="\' + btn.icon + \'">\');\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tfallback_obj[id] = btn.icon;\n
\t\t\t\t\t\t\tvar svgicon = btn.svgicon?btn.svgicon:btn.id;\n
\t\t\t\t\t\t\tplacement_obj[\'#\' + id] = svgicon;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar cls, parent;\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Set button up according to its type\n
\t\t\t\t\t\tswitch ( btn.type ) {\n
\t\t\t\t\t\tcase \'mode\':\n
\t\t\t\t\t\t\tcls = \'tool_button\';\n
\t\t\t\t\t\t\tparent = "#tools_left";\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\tcase \'context\':\n
\t\t\t\t\t\t\tcls = \'tool_button\';\n
\t\t\t\t\t\t\tparent = "#" + btn.panel;\n
\t\t\t\t\t\t\t// create the panel if it doesn\'t exist\n
\t\t\t\t\t\t\tif(!$(parent).length)\n
\t\t\t\t\t\t\t\t$(\'<div>\', {id: btn.panel}).appendTo("#tools_top");\n
\t\t\t\t\t\t\tbreak;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar button = $(btn.list?\'<li/>\':\'<div/>\')\n
\t\t\t\t\t\t\t.attr("id", id)\n
\t\t\t\t\t\t\t.attr("title", btn.title)\n
\t\t\t\t\t\t\t.addClass(cls);\n
\t\t\t\t\t\tif(!btn.includeWith && !btn.list) {\n
\t\t\t\t\t\t\tbutton.appendTo(parent);\n
\t\t\t\t\t\t} else if(btn.list) {\n
\t\t\t\t\t\t\t// Add button to list\n
\t\t\t\t\t\t\tbutton.addClass(\'push_button\');\n
\t\t\t\t\t\t\t$(\'#\' + btn.list + \'_opts\').append(button);\n
 \t\t\t\t\t\t\tif(btn.isDefault) {\n
 \t\t\t\t\t\t\t\t$(\'#cur_\' + btn.list).append(button.children().clone());\n
 \t\t\t\t\t\t\t\tvar svgicon = btn.svgicon?btn.svgicon:btn.id;\n
\t \t\t\t\t\t\t\tplacement_obj[\'#cur_\' + btn.list] = svgicon;\n
 \t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} else if(btn.includeWith) {\n
\t\t\t\t\t\t\t// Add to flyout menu / make flyout menu\n
\t\t\t\t\t\t\tvar opts = btn.includeWith;\n
\t\t\t\t\t\t\t// opts.button, default, position\n
\t\t\t\t\t\t\tvar ref_btn = $(opts.button);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar flyout_holder = ref_btn.parent();\n
\t\t\t\t\t\t\t// Create a flyout menu if there isn\'t one already\n
\t\t\t\t\t\t\tif(!ref_btn.parent().hasClass(\'tools_flyout\')) {\n
\t\t\t\t\t\t\t\t// Create flyout placeholder\n
\t\t\t\t\t\t\t\tvar arr_div = $(\'<div>\',{id:\'flyout_arrow_horiz\'})\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\tvar tls_id = ref_btn[0].id.replace(\'tool_\',\'tools_\')\n
\t\t\t\t\t\t\t\tvar show_btn = ref_btn.clone()\n
\t\t\t\t\t\t\t\t\t.attr(\'id\',tls_id + \'_show\')\n
\t\t\t\t\t\t\t\t\t.append($(\'<div>\',{\'class\':\'flyout_arrow_horiz\'}));\n
\t\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\tref_btn.before(show_btn);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t// Create a flyout div\n
\t\t\t\t\t\t\t\tflyout_holder = makeFlyoutHolder(tls_id, ref_btn);\n
\t\t\t\t\t\t\t} \n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar ref_data = Actions.getButtonData(opts.button);\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tif(opts.isDefault) {\n
\t\t\t\t\t\t\t\tplacement_obj[\'#\' + tls_id + \'_show\'] = btn.id;\n
\t\t\t\t\t\t\t} \n
\t\t\t\t\t\t\t// TODO: Find way to set the current icon using the iconloader if this is not default\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Include data for extension button as well as ref button\n
\t\t\t\t\t\t\tvar cur_h = holders[\'#\'+flyout_holder[0].id] = [{\n
\t\t\t\t\t\t\t\tsel: \'#\'+id,\n
\t\t\t\t\t\t\t\tfn: btn.events.click,\n
\t\t\t\t\t\t\t\ticon: btn.id,\n
\t\t\t\t\t\t\t\tkey: btn.key,\n
\t\t\t\t\t\t\t\tisDefault: btn.includeWith?btn.includeWith.isDefault:0\n
\t\t\t\t\t\t\t}, ref_data];\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// {sel:\'#tool_rect\', fn: clickRect, evt: \'mouseup\', key: 4, parent: \'#tools_rect\', icon: \'rect\'}\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\tvar pos  = ("position" in opts)?opts.position:\'last\';\n
\t\t\t\t\t\t\tvar len = flyout_holder.children().length;\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Add at given position or end\n
\t\t\t\t\t\t\tif(!isNaN(pos) && pos >= 0 && pos < len) {\n
\t\t\t\t\t\t\t\tflyout_holder.children().eq(pos).before(button);\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tflyout_holder.append(button);\n
\t\t\t\t\t\t\t\tcur_h.reverse();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif(!svgicons) {\n
\t\t\t\t\t\t\tbutton.append(icon);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif(!btn.list) {\n
\t\t\t\t\t\t\t// Add given events to button\n
\t\t\t\t\t\t\t$.each(btn.events, function(name, func) {\n
\t\t\t\t\t\t\t\tif(name == "click") {\n
\t\t\t\t\t\t\t\t\tif(btn.type == \'mode\') {\n
\t\t\t\t\t\t\t\t\t\tif(btn.includeWith) {\n
\t\t\t\t\t\t\t\t\t\t\tbutton.bind(name, func);\n
\t\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\t\tbutton.bind(name, function() {\n
\t\t\t\t\t\t\t\t\t\t\t\tif(toolButtonClick(button)) {\n
\t\t\t\t\t\t\t\t\t\t\t\t\tfunc();\n
\t\t\t\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\tif(btn.key) {\n
\t\t\t\t\t\t\t\t\t\t\t$(document).bind(\'keydown\', btn.key, func);\n
\t\t\t\t\t\t\t\t\t\t\tif(btn.title) button.attr("title", btn.title + \' [\'+btn.key+\']\');\n
\t\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\t\tbutton.bind(name, func);\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tbutton.bind(name, func);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tsetupFlyouts(holders);\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\t$.each(btn_selects, function() {\n
\t\t\t\t\t\taddAltDropDown(this.elem, this.list, this.callback, {seticon: true}); \n
\t\t\t\t\t});\n
\n
\t\t\t\t\t\n
\t\t\t\t\t$.svgIcons(svgicons, {\n
\t\t\t\t\t\tw:24, h:24,\n
\t\t\t\t\t\tid_match: false,\n
\t\t\t\t\t\tno_img: true,\n
\t\t\t\t\t\tfallback: fallback_obj,\n
\t\t\t\t\t\tplacement: placement_obj,\n
\t\t\t\t\t\tcallback: function(icons) {\n
\t\t\t\t\t\t\t// Non-ideal hack to make the icon match the current size\n
\t\t\t\t\t\t\tif(curPrefs.iconsize && curPrefs.iconsize != \'m\') {\n
\t\t\t\t\t\t\t\tsetIconSize(curPrefs.iconsize, true);\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\trunCallback();\n
\t\t\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\trunCallback();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar getPaint = function(color, opac) {\n
\t\t\t\t// update the editor\'s fill paint\n
\t\t\t\tvar opts = null;\n
\t\t\t\tif (color.substr(0,5) == "url(#") {\n
\t\t\t\t\tvar grad = document.getElementById(color.substr(5,color.length-6));\n
\t\t\t\t\topts = { alpha: opac };\n
\t\t\t\t\topts[grad.tagName] = grad;\n
\t\t\t\t} \n
\t\t\t\telse if (color.substr(0,1) == "#") {\n
\t\t\t\t\topts = {\n
\t\t\t\t\t\talpha: opac,\n
\t\t\t\t\t\tsolidColor: color.substr(1)\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\topts = {\n
\t\t\t\t\t\talpha: opac,\n
\t\t\t\t\t\tsolidColor: \'none\'\n
\t\t\t\t\t};\n
\t\t\t\t}\n
\t\t\t\treturn new $.jGraduate.Paint(opts);\n
\t\t\t};\t\n
\t\t\n
\t\t\t// updates the toolbar (colors, opacity, etc) based on the selected element\n
\t\t\t// This function also updates the opacity and id elements that are in the context panel\n
\t\t\tvar updateToolbar = function() {\n
\t\t\t\tif (selectedElement != null && $.inArray(selectedElement.tagName, [\'image\', \'text\', \'foreignObject\', \'g\', \'a\']) === -1) {\n
\t\t\t\t\t// get opacity values\n
\t\t\t\t\tvar fillOpacity = parseFloat(selectedElement.getAttribute("fill-opacity"));\n
\t\t\t\t\tif (isNaN(fillOpacity)) {\n
\t\t\t\t\t\tfillOpacity = 1.0;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tvar strokeOpacity = parseFloat(selectedElement.getAttribute("stroke-opacity"));\n
\t\t\t\t\tif (isNaN(strokeOpacity)) {\n
\t\t\t\t\t\tstrokeOpacity = 1.0;\n
\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\t// update fill color and opacity\n
\t\t\t\t\tvar fillColor = selectedElement.getAttribute("fill")||"black";\n
\t\t\t\t\t// prevent undo on these canvas changes\n
\t\t\t\t\tsvgCanvas.setFillColor(fillColor, true);\n
\t\t\t\t\tsvgCanvas.setFillOpacity(fillOpacity, true);\n
\t\t\n
\t\t\t\t\t// update stroke color and opacity\n
\t\t\t\t\tvar strokeColor = selectedElement.getAttribute("stroke")||"none";\n
\t\t\t\t\t// prevent undo on these canvas changes\n
\t\t\t\t\tsvgCanvas.setStrokeColor(strokeColor, true);\n
\t\t\t\t\tsvgCanvas.setStrokeOpacity(strokeOpacity, true);\n
\t\t\n
\t\t\t\t\t// update the rect inside #fill_color\n
\t\t\t\t\t$("#stroke_color rect").attr({\n
\t\t\t\t\t\tfill: strokeColor,\n
\t\t\t\t\t\topacity: strokeOpacity\n
\t\t\t\t\t});\n
\n
\t\t\t\t\t// update the rect inside #fill_color\n
\t\t\t\t\t$("#fill_color rect").attr({\n
\t\t\t\t\t\tfill: fillColor,\n
\t\t\t\t\t\topacity: fillOpacity\n
\t\t\t\t\t});\n
\t\t\n
\t\t\t\t\tfillOpacity *= 100;\n
\t\t\t\t\tstrokeOpacity *= 100;\n
\t\t\t\t\t\n
\t\t\t\t\tfillPaint = getPaint(fillColor, fillOpacity);\n
\t\t\t\t\tstrokePaint = getPaint(strokeColor, strokeOpacity);\n
\t\t\t\t\t\n
\t\t\t\t\tfillOpacity = fillOpacity + " %";\n
\t\t\t\t\tstrokeOpacity = strokeOpacity + " %";\n
\t\t\n
\t\t\t\t\t// update fill color\n
\t\t\t\t\tif (fillColor == "none") {\n
\t\t\t\t\t\tfillOpacity = "N/A";\n
\t\t\t\t\t}\n
\t\t\t\t\tif (strokeColor == null || strokeColor == "" || strokeColor == "none") {\n
\t\t\t\t\t\tstrokeColor = "none";\n
\t\t\t\t\t\tstrokeOpacity = "N/A";\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t$(\'#stroke_width\').val(selectedElement.getAttribute("stroke-width")||1);\n
\t\t\t\t\t$(\'#stroke_style\').val(selectedElement.getAttribute("stroke-dasharray")||"none");\n
\n
\t\t\t\t\tvar attr = selectedElement.getAttribute("stroke-linejoin") || \'miter\';\n
\t\t\t\t\t\n
\t\t\t\t\tsetStrokeOpt($(\'#linejoin_\' + attr)[0]);\n
\t\t\t\t\t\n
\t\t\t\t\tattr = selectedElement.getAttribute("stroke-linecap") || \'butt\';\n
\t\t\t\t\t\n
\t\t\t\t\tsetStrokeOpt($(\'#linecap_\' + attr)[0]);\n
\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// All elements including image and group have opacity\n
\t\t\t\tif(selectedElement != null) {\n
\t\t\t\t\tvar opac_perc = ((selectedElement.getAttribute("opacity")||1.0)*100);\n
\t\t\t\t\t$(\'#group_opacity\').val(opac_perc);\n
\t\t\t\t\t$(\'#opac_slider\').slider(\'option\', \'value\', opac_perc);\n
\t\t\t\t\t$(\'#elem_id\').val(selectedElement.id);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tupdateToolButtonState();\n
\t\t\t};\n
\t\t\n
\t\t\t// updates the context panel tools based on the selected element\n
\t\t\tvar updateContextPanel = function() {\n
\t\t\t\tvar elem = selectedElement;\n
\t\t\t\t// If element has just been deleted, consider it null\n
\t\t\t\tif(elem != null && !elem.parentNode) elem = null;\n
\t\t\t\tvar currentLayer = svgCanvas.getCurrentLayer();\n
\t\t\t\tvar currentMode = svgCanvas.getMode();\n
\t\t\t\t// No need to update anything else in rotate mode\n
\t\t\t\tif (currentMode == \'rotate\' && elem != null) {\n
\t\t\t\t\tvar ang = svgCanvas.getRotationAngle(elem);\n
\t\t\t\t\t$(\'#angle\').val(ang);\n
\t\t\t\t\t$(\'#tool_reorient\').toggleClass(\'disabled\', ang == 0);\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\tvar is_node = currentMode == \'pathedit\'; //elem ? (elem.id && elem.id.indexOf(\'pathpointgrip\') == 0) : false;\n
\t\t\t\t$(\'#selected_panel, #multiselected_panel, #g_panel, #rect_panel, #circle_panel,\\\n
\t\t\t\t\t#ellipse_panel, #line_panel, #text_panel, #image_panel\').hide();\n
\t\t\t\tif (elem != null) {\n
\t\t\t\t\tvar elname = elem.nodeName;\n
\t\t\t\t\t\n
\t\t\t\t\t// If this is a link with no transform and one child, pretend\n
\t\t\t\t\t// its child is selected\n
// \t\t\t\t\tconsole.log(\'go\', elem)\n
// \t\t\t\t\tif(elname === \'a\') { // && !$(elem).attr(\'transform\')) {\n
// \t\t\t\t\t\telem = elem.firstChild;\n
// \t\t\t\t\t}\n
\n
\t\t\t\t\t\n
\t\t\t\t\tvar angle = svgCanvas.getRotationAngle(elem);\n
\t\t\t\t\t$(\'#angle\').val(angle);\n
\t\t\t\t\t\n
\t\t\t\t\tvar blurval = svgCanvas.getBlur(elem);\n
\t\t\t\t\t$(\'#blur\').val(blurval);\n
\t\t\t\t\t$(\'#blur_slider\').slider(\'option\', \'value\', blurval);\n
\t\t\t\t\t\n
\t\t\t\t\tif(svgCanvas.addedNew) {\n
\t\t\t\t\t\tif(elname == \'image\') {\n
\t\t\t\t\t\t\tpromptImgURL();\n
\t\t\t\t\t\t} else if(elname == \'text\') {\n
\t\t\t\t\t\t\t// TODO: Do something here for new text\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tif(!is_node && currentMode != \'pathedit\') {\n
\t\t\t\t\t\t$(\'#selected_panel\').show();\n
\t\t\t\t\t\t// Elements in this array already have coord fields\n
\t\t\t\t\t\tif($.inArray(elname, [\'line\', \'circle\', \'ellipse\']) != -1) {\n
\t\t\t\t\t\t\t$(\'#xy_panel\').hide();\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\tvar x,y;\n
\t\t\t\t\t\t\t// Get BBox vals for g, polyline and path\n
\t\t\t\t\t\t\tif($.inArray(elname, [\'g\', \'polyline\', \'path\']) != -1) {\n
\t\t\t\t\t\t\t\tvar bb = svgCanvas.getStrokedBBox([elem]);\n
\t\t\t\t\t\t\t\tif(bb) {\n
\t\t\t\t\t\t\t\t\tx = bb.x;\n
\t\t\t\t\t\t\t\t\ty = bb.y;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tx = elem.getAttribute(\'x\');\n
\t\t\t\t\t\t\t\ty = elem.getAttribute(\'y\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t$(\'#selected_x\').val(x || 0);\n
\t\t\t\t\t\t\t$(\'#selected_y\').val(y || 0);\n
\t\t\t\t\t\t\t$(\'#xy_panel\').show();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Elements in this array cannot be converted to a path\n
\t\t\t\t\t\tvar no_path = $.inArray(elname, [\'image\', \'text\', \'path\', \'g\', \'use\']) == -1;\n
\t\t\t\t\t\t$(\'#tool_topath\').toggle(no_path);\n
\t\t\t\t\t\t$(\'#tool_reorient\').toggle(elname == \'path\');\n
\t\t\t\t\t\t$(\'#tool_reorient\').toggleClass(\'disabled\', angle == 0);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tvar point = path.getNodePoint();\n
\t\t\t\t\t\t$(\'#tool_add_subpath\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\t\t\t$(\'#tool_node_delete\').toggleClass(\'disabled\', !path.canDeleteNodes);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Show open/close button based on selected point\n
\t\t\t\t\t\tsetIcon(\'#tool_openclose_path\', path.closed_subpath ? \'open_path\' : \'close_path\');\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif(point) {\n
\t\t\t\t\t\t\tvar seg_type = $(\'#seg_type\');\n
\t\t\t\t\t\t\t$(\'#path_node_x\').val(point.x);\n
\t\t\t\t\t\t\t$(\'#path_node_y\').val(point.y);\n
\t\t\t\t\t\t\tif(point.type) {\n
\t\t\t\t\t\t\t\tseg_type.val(point.type).removeAttr(\'disabled\');\n
\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\tseg_type.val(4).attr(\'disabled\',\'disabled\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t// update contextual tools here\n
\t\t\t\t\tvar panels = {\n
\t\t\t\t\t\tg: [],\n
\t\t\t\t\t\trect: [\'rx\',\'width\',\'height\'],\n
\t\t\t\t\t\timage: [\'width\',\'height\'],\n
\t\t\t\t\t\tcircle: [\'cx\',\'cy\',\'r\'],\n
\t\t\t\t\t\tellipse: [\'cx\',\'cy\',\'rx\',\'ry\'],\n
\t\t\t\t\t\tline: [\'x1\',\'y1\',\'x2\',\'y2\'], \n
\t\t\t\t\t\ttext: []\n
\t\t\t\t\t};\n
\t\t\t\t\t\n
\t\t\t\t\tvar el_name = elem.tagName;\n
\t\t\t\t\t\n
\t\t\t\t\tif(panels[el_name]) {\n
\t\t\t\t\t\tvar cur_panel = panels[el_name];\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t$(\'#\' + el_name + \'_panel\').show();\n
\t\t\t\n
\t\t\t\t\t\t$.each(cur_panel, function(i, item) {\n
\t\t\t\t\t\t\t$(\'#\' + el_name + \'_\' + item).val(elem.getAttribute(item) || 0);\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tif(el_name == \'text\') {\n
\t\t\t\t\t\t\t$(\'#text_panel\').css("display", "inline");\t\n
\t\t\t\t\t\t\tif (svgCanvas.getItalic()) {\n
\t\t\t\t\t\t\t\t$(\'#tool_italic\').addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\t\t$(\'#tool_italic\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\tif (svgCanvas.getBold()) {\n
\t\t\t\t\t\t\t\t$(\'#tool_bold\').addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\t\t$(\'#tool_bold\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t$(\'#font_family\').val(elem.getAttribute("font-family"));\n
\t\t\t\t\t\t\t$(\'#font_size\').val(elem.getAttribute("font-size"));\n
\t\t\t\t\t\t\t$(\'#text\').val(elem.textContent);\n
\t\t\t\t\t\t\tif (svgCanvas.addedNew) {\n
\t\t\t\t\t\t\t\t$(\'#text\').focus().select();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t} // text\n
\t\t\t\t\t\telse if(el_name == \'image\') {\n
\t\t\t\t\t\t\tvar xlinkNS="http://www.w3.org/1999/xlink";\n
\t\t\t\t\t\t\tvar href = elem.getAttributeNS(xlinkNS, "href");\n
\t\t\t\t\t\t\tsetImageURL(href);\n
\t\t\t\t\t\t} // image\n
\t\t\t\t\t}\n
\t\t\t\t} // if (elem != null)\n
\t\t\t\telse if (multiselected) {\n
\t\t\t\t\t$(\'#multiselected_panel\').show();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// update history buttons\n
\t\t\t\tif (svgCanvas.getUndoStackSize() > 0) {\n
\t\t\t\t\t$(\'#tool_undo\').removeClass( \'disabled\');\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\t$(\'#tool_undo\').addClass( \'disabled\');\n
\t\t\t\t}\n
\t\t\t\tif (svgCanvas.getRedoStackSize() > 0) {\n
\t\t\t\t\t$(\'#tool_redo\').removeClass( \'disabled\');\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\t$(\'#tool_redo\').addClass( \'disabled\');\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tsvgCanvas.addedNew = false;\n
\t\t\n
\t\t\t\tif ( (elem && !is_node)\t|| multiselected) {\n
\t\t\t\t\t// update the selected elements\' layer\n
\t\t\t\t\t$(\'#selLayerNames\').removeAttr(\'disabled\').val(currentLayer);\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\t$(\'#selLayerNames\').attr(\'disabled\', \'disabled\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\t$(\'#text\').focus( function(){ textBeingEntered = true; } );\n
\t\t\t$(\'#text\').blur( function(){ textBeingEntered = false; } );\n
\t\t  \n
\t\t\t// bind the selected event to our function that handles updates to the UI\n
\t\t\tsvgCanvas.bind("selected", selectedChanged);\n
\t\t\tsvgCanvas.bind("changed", elementChanged);\n
\t\t\tsvgCanvas.bind("saved", saveHandler);\n
\t\t\tsvgCanvas.bind("exported", exportHandler);\n
\t\t\tsvgCanvas.bind("zoomed", zoomChanged);\n
\t\t\tsvgCanvas.bind("extension_added", extAdded);\n
\t\t\tsvgCanvas.textActions.setInputElem($("#text")[0]);\n
\t\t\n
\t\t\tvar str = \'<div class="palette_item" data-rgb="none"></div>\'\n
\t\t\t$.each(palette, function(i,item){\n
\t\t\t\tstr += \'<div class="palette_item" style="background-color: \' + item + \';" data-rgb="\' + item + \'"></div>\';\n
\t\t\t});\n
\t\t\t$(\'#palette\').append(str);\n
\t\t\t\n
\t\t\t// Set up editor background functionality\n
\t\t\t// TODO add checkerboard as "pattern"\n
\t\t\tvar color_blocks = [\'#FFF\',\'#888\',\'#000\']; // ,\'url(data:image/gif;base64,R0lGODlhEAAQAIAAAP%2F%2F%2F9bW1iH5BAAAAAAALAAAAAAQABAAAAIfjG%2Bgq4jM3IFLJgpswNly%2FXkcBpIiVaInlLJr9FZWAQA7)\'];\n
\t\t\tvar str = \'\';\n
\t\t\t$.each(color_blocks, function() {\n
\t\t\t\tstr += \'<div class="color_block" style="background-color:\' + this + \';"></div>\';\n
\t\t\t});\n
\t\t\t$(\'#bg_blocks\').append(str);\n
\t\t\tvar blocks = $(\'#bg_blocks div\');\n
\t\t\tvar cur_bg = \'cur_background\';\n
\t\t\tblocks.each(function() {\n
\t\t\t\tvar blk = $(this);\n
\t\t\t\tblk.click(function() {\n
\t\t\t\t\tblocks.removeClass(cur_bg);\n
\t\t\t\t\t$(this).addClass(cur_bg);\n
\t\t\t\t});\n
\t\t\t});\n
\t\t\n
\t\t\tif($.pref(\'bkgd_color\')) {\n
\t\t\t\tsetBackground($.pref(\'bkgd_color\'), $.pref(\'bkgd_url\'));\n
\t\t\t} else if($.pref(\'bkgd_url\')) {\n
\t\t\t\t// No color set, only URL\n
\t\t\t\tsetBackground(defaultPrefs.bkgd_color, $.pref(\'bkgd_url\'));\n
\t\t\t}\n
\t\t\t\n
\t\t\tif($.pref(\'img_save\')) {\n
\t\t\t\tcurPrefs.img_save = $.pref(\'img_save\');\n
\t\t\t\t$(\'#image_save_opts input\').val([curPrefs.img_save]);\n
\t\t\t}\n
\t\t\n
\t\t\tvar changeRectRadius = function(ctl) {\n
\t\t\t\tsvgCanvas.setRectRadius(ctl.value);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar changeFontSize = function(ctl) {\n
\t\t\t\tsvgCanvas.setFontSize(ctl.value);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar changeStrokeWidth = function(ctl) {\n
\t\t\t\tvar val = ctl.value;\n
\t\t\t\tif(val == 0 && selectedElement && $.inArray(selectedElement.nodeName, [\'line\', \'polyline\']) != -1) {\n
\t\t\t\t\tval = ctl.value = 1;\n
\t\t\t\t}\n
\t\t\t\tsvgCanvas.setStrokeWidth(val);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar changeRotationAngle = function(ctl) {\n
\t\t\t\tsvgCanvas.setRotationAngle(ctl.value);\n
\t\t\t\t$(\'#tool_reorient\').toggleClass(\'disabled\', ctl.value == 0);\n
\t\t\t}\n
\t\t\tvar changeZoom = function(ctl) {\n
\t\t\t\tvar zoomlevel = ctl.value / 100;\n
\t\t\t\tvar zoom = svgCanvas.getZoom();\n
\t\t\t\tvar w_area = workarea;\n
\t\t\t\t\n
\t\t\t\tzoomChanged(window, {\n
\t\t\t\t\twidth: 0,\n
\t\t\t\t\theight: 0,\n
\t\t\t\t\t// center pt of scroll position\n
\t\t\t\t\tx: (w_area[0].scrollLeft + w_area.width()/2)/zoom, \n
\t\t\t\t\ty: (w_area[0].scrollTop + w_area.height()/2)/zoom,\n
\t\t\t\t\tzoom: zoomlevel\n
\t\t\t\t}, true);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar changeOpacity = function(ctl, val) {\n
\t\t\t\tif(val == null) val = ctl.value;\n
\t\t\t\t$(\'#group_opacity\').val(val);\n
\t\t\t\tif(!ctl || !ctl.handle) {\n
\t\t\t\t\t$(\'#opac_slider\').slider(\'option\', \'value\', val);\n
\t\t\t\t}\n
\t\t\t\tsvgCanvas.setOpacity(val/100);\n
\t\t\t}\n
\t\t\n
\t\t\tvar changeBlur = function(ctl, val, noUndo) {\n
\t\t\t\tif(val == null) val = ctl.value;\n
\t\t\t\t$(\'#blur\').val(val);\n
\t\t\t\tvar complete = false;\n
\t\t\t\tif(!ctl || !ctl.handle) {\n
\t\t\t\t\t$(\'#blur_slider\').slider(\'option\', \'value\', val);\n
\t\t\t\t\tcomplete = true;\n
\t\t\t\t}\n
\t\t\t\tif(noUndo) {\n
\t\t\t\t\tsvgCanvas.setBlurNoUndo(val);\t\n
\t\t\t\t} else {\n
\t\t\t\t\tsvgCanvas.setBlur(val, complete);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
\t\t\tvar operaRepaint = function() {\n
\t\t\t\t// Repaints canvas in Opera. Needed for stroke-dasharray change as well as fill change\n
\t\t\t\tif(!window.opera) return;\n
\t\t\t\t$(\'<p/>\').hide().appendTo(\'body\').remove();\n
\t\t\t}\n
\t\t\n
\t\t\t$(\'#stroke_style\').change(function(){\n
\t\t\t\tsvgCanvas.setStrokeAttr(\'stroke-dasharray\', $(this).val());\n
\t\t\t\toperaRepaint();\n
\t\t\t});\n
\n
\t\t\t$(\'#stroke_linejoin\').change(function(){\n
\t\t\t\tsvgCanvas.setStrokeAttr(\'stroke-linejoin\', $(this).val());\n
\t\t\t\toperaRepaint();\n
\t\t\t});\n
\n
\t\t\n
\t\t\t// Lose focus for select elements when changed (Allows keyboard shortcuts to work better)\n
\t\t\t$(\'select\').change(function(){$(this).blur();});\n
\t\t\n
\t\t\t// fired when user wants to move elements to another layer\n
\t\t\tvar promptMoveLayerOnce = false;\n
\t\t\t$(\'#selLayerNames\').change(function(){\n
\t\t\t\tvar destLayer = this.options[this.selectedIndex].value;\n
\t\t\t\tvar confirm_str = uiStrings.QmoveElemsToLayer.replace(\'%s\',destLayer);\n
\t\t\t\tvar moveToLayer = function(ok) {\n
\t\t\t\t\tif(!ok) return;\n
\t\t\t\t\tpromptMoveLayerOnce = true;\n
\t\t\t\t\tsvgCanvas.moveSelectedToLayer(destLayer);\n
\t\t\t\t\tsvgCanvas.clearSelection();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t}\n
\t\t\t\tif (destLayer) {\n
\t\t\t\t\tif(promptMoveLayerOnce) {\n
\t\t\t\t\t\tmoveToLayer(true);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t$.confirm(confirm_str, moveToLayer);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#font_family\').change(function() {\n
\t\t\t\tsvgCanvas.setFontFamily(this.value);\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#seg_type\').change(function() {\n
\t\t\t\tsvgCanvas.setSegType($(this).val());\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#text\').keyup(function(){\n
\t\t\t\tsvgCanvas.setTextContent(this.value);\n
\t\t\t});\n
\t\t  \n
\t\t\t$(\'#image_url\').change(function(){\n
\t\t\t\tsetImageURL(this.value); \n
\t\t\t});\n
\t\t\n
\t\t\t$(\'.attr_changer\').change(function() {\n
\t\t\t\tvar attr = this.getAttribute("data-attr");\n
\t\t\t\tvar val = this.value;\n
\t\t\t\tvar valid = svgCanvas.isValidUnit(attr, val);\n
\t\t\t\t\n
\t\t\t\tif(!valid) {\n
\t\t\t\t\t$.alert(uiStrings.invalidAttrValGiven);\n
\t\t\t\t\tthis.value = selectedElement.getAttribute(attr);\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t// if the user is changing the id, then de-select the element first\n
\t\t\t\t// change the ID, then re-select it with the new ID\n
\t\t\t\tif (attr == "id") {\n
\t\t\t\t\tvar elem = selectedElement;\n
\t\t\t\t\tsvgCanvas.clearSelection();\n
\t\t\t\t\telem.id = val;\n
\t\t\t\t\tsvgCanvas.addToSelection([elem],true);\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tsvgCanvas.changeSelectedAttribute(attr, val);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\t// Prevent selection of elements when shift-clicking\n
\t\t\t$(\'#palette\').mouseover(function() {\n
\t\t\t\tvar inp = $(\'<input type="hidden">\');\n
\t\t\t\t$(this).append(inp);\n
\t\t\t\tinp.focus().remove();\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'.palette_item\').click(function(evt){\n
\t\t\t\tvar picker = (evt.shiftKey ? "stroke" : "fill");\n
\t\t\t\tvar id = (evt.shiftKey ? \'#stroke_\' : \'#fill_\');\n
\t\t\t\tvar color = $(this).attr(\'data-rgb\');\n
\t\t\t\tvar rectbox = document.getElementById("gradbox_"+picker).parentNode.firstChild;\n
\t\t\t\tvar paint = null;\n
\t\t\n
\t\t\t\t// Webkit-based browsers returned \'initial\' here for no stroke\n
\t\t\t\tif (color == \'transparent\' || color == \'initial\') {\n
\t\t\t\t\tcolor = \'none\';\n
\t\t\t\t\t$(id + "opacity").html("N/A");\n
\t\t\t\t\tpaint = new $.jGraduate.Paint();\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tpaint = new $.jGraduate.Paint({alpha: 100, solidColor: color.substr(1)});\n
\t\t\t\t}\n
\t\t\t\trectbox.setAttribute("fill", color);\n
\t\t\t\trectbox.setAttribute("opacity", 1);\n
\t\t\t\t\n
\t\t\t\tif (evt.shiftKey) {\n
\t\t\t\t\tstrokePaint = paint;\n
\t\t\t\t\tif (svgCanvas.getStrokeColor() != color) {\n
\t\t\t\t\t\tsvgCanvas.setStrokeColor(color);\n
\t\t\t\t\t}\n
\t\t\t\t\tif (color != \'none\' && svgCanvas.getStrokeOpacity() != 1) {\n
\t\t\t\t\t\tsvgCanvas.setStrokeOpacity(1.0);\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\tfillPaint = paint;\n
\t\t\t\t\tif (svgCanvas.getFillColor() != color) {\n
\t\t\t\t\t\tsvgCanvas.setFillColor(color);\n
\t\t\t\t\t}\n
\t\t\t\t\tif (color != \'none\' && svgCanvas.getFillOpacity() != 1) {\n
\t\t\t\t\t\tsvgCanvas.setFillOpacity(1.0);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tupdateToolButtonState();\n
\t\t\t});\n
\t\t\n
\t\t\t$("#toggle_stroke_tools").toggle(function() {\n
\t\t\t\t$(".stroke_tool").css(\'display\',\'table-cell\');\n
\t\t\t\t$(this).text(\'<<\');\n
\t\t\t}, function() {\n
\t\t\t\t$(".stroke_tool").css(\'display\',\'none\');\n
\t\t\t\t$(this).text(\'>>\');\n
\t\t\t});\n
\t\t\n
\t\t\t// This is a common function used when a tool has been clicked (chosen)\n
\t\t\t// It does several common things:\n
\t\t\t// - removes the tool_button_current class from whatever tool currently has it\n
\t\t\t// - hides any flyouts\n
\t\t\t// - adds the tool_button_current class to the button passed in\n
\t\t\tvar toolButtonClick = function(button, fadeFlyouts) {\n
\t\t\t\tif ($(button).hasClass(\'disabled\')) return false;\n
\t\t\t\tif($(button).parent().hasClass(\'tools_flyout\')) return true;\n
\t\t\t\tvar fadeFlyouts = fadeFlyouts || \'normal\';\n
\t\t\t\t$(\'.tools_flyout\').fadeOut(fadeFlyouts);\n
\t\t\t\t$(\'#styleoverrides\').text(\'\');\n
\t\t\t\t$(\'.tool_button_current\').removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
\t\t\t\t$(button).addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
\t\t\t\t// when a tool is selected, we should deselect any currently selected elements\n
\t\t\t\tsvgCanvas.clearSelection();\n
\t\t\t\treturn true;\n
\t\t\t};\n
\t\t\t\n
\t\t\t(function() {\n
\t\t\t\tvar last_x = null, last_y = null, w_area = workarea[0], \n
\t\t\t\t\tpanning = false, keypan = false;\n
\t\t\t\t\n
\t\t\t\t$(\'#svgcanvas\').bind(\'mousemove mouseup\', function(evt) {\n
\t\t\t\t\tif(panning === false) return;\n
\n
\t\t\t\t\tw_area.scrollLeft -= (evt.clientX - last_x);\n
\t\t\t\t\tw_area.scrollTop -= (evt.clientY - last_y);\n
\t\t\t\t\t\n
\t\t\t\t\tlast_x = evt.clientX;\n
\t\t\t\t\tlast_y = evt.clientY;\n
\t\t\t\t\t\n
\t\t\t\t\tif(evt.type === \'mouseup\') panning = false;\n
\t\t\t\t\treturn false;\n
\t\t\t\t}).mousedown(function(evt) {\n
\t\t\t\t\tif(evt.button === 1 || keypan === true) {\n
\t\t\t\t\t\tpanning = true;\n
\t\t\t\t\t\tlast_x = evt.clientX;\n
\t\t\t\t\t\tlast_y = evt.clientY;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$(window).mouseup(function() {\n
\t\t\t\t\tpanning = false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$(document).bind(\'keydown\', \'space\', function(evt) {\n
\t\t\t\t\tsvgCanvas.spaceKey = keypan = true;\n
\t\t\t\t\tevt.preventDefault();\n
\t\t\t\t}).bind(\'keyup\', \'space\', function(evt) {\n
\t\t\t\t\tevt.preventDefault();\n
\t\t\t\t\tsvgCanvas.spaceKey = keypan = false;\n
\t\t\t\t});\n
\t\t\t}());\n
\t\t\t\n
\t\t\t\n
\t\t\tfunction setStrokeOpt(opt, changeElem) {\n
\t\t\t\tvar id = opt.id;\n
\t\t\t\tvar bits = id.split(\'_\');\n
\t\t\t\tvar pre = bits[0];\n
\t\t\t\tvar val = bits[1];\n
\t\t\t\n
\t\t\t\tif(changeElem) {\n
\t\t\t\t\tsvgCanvas.setStrokeAttr(\'stroke-\' + pre, val);\n
\t\t\t\t}\n
\t\t\t\toperaRepaint();\n
\t\t\t\tsetIcon(\'#cur_\' + pre , id, 20);\n
\t\t\t\t$(opt).addClass(\'current\').siblings().removeClass(\'current\');\n
\t\t\t}\n
\t\t\t\n
\t\t\t(function() {\n
\t\t\t\tvar button = $(\'#main_icon\');\n
\t\t\t\tvar overlay = $(\'#main_icon span\');\n
\t\t\t\tvar list = $(\'#main_menu\');\n
\t\t\t\tvar on_button = false;\n
\t\t\t\tvar height = 0;\n
\t\t\t\tvar js_hover = true;\n
\t\t\t\tvar set_click = false;\n
\t\t\t\t\n
\t\t\t\tvar hideMenu = function() {\n
\t\t\t\t\tlist.fadeOut(200);\n
\t\t\t\t};\n
\t\t\t\t\n
\t\t\t\t$(window).mouseup(function(evt) {\n
\t\t\t\t\tif(!on_button) {\n
\t\t\t\t\t\tbutton.removeClass(\'buttondown\');\n
\t\t\t\t\t\t// do not hide if it was the file input as that input needs to be visible \n
\t\t\t\t\t\t// for its change event to fire\n
\t\t\t\t\t\tif (evt.target.localName != "input") {\n
\t\t\t\t\t\t\tlist.fadeOut(200);\n
\t\t\t\t\t\t} else if(!set_click) {\n
\t\t\t\t\t\t\tset_click = true;\n
\t\t\t\t\t\t\t$(evt.target).click(function() {\n
\t\t\t\t\t\t\t\tlist.css(\'margin-left\',\'-9999px\').show();\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t}).mousedown(function() {\n
\t\t\t\t\t$(\'.tools_flyout:visible\').fadeOut();\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\toverlay.bind(\'mousedown\',function() {\n
\t\t\t\t\tif (!button.hasClass(\'buttondown\')) {\n
\t\t\t\t\t\tbutton.addClass(\'buttondown\').removeClass(\'buttonup\')\n
\t\t\t\t\t\t// Margin must be reset in case it was changed before;\n
\t\t\t\t\t\tlist.css(\'margin-left\',0).show();\n
\t\t\t\t\t\tif(!height) {\n
\t\t\t\t\t\t\theight = list.height();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t// Using custom animation as slideDown has annoying "bounce effect"\n
\t\t\t\t\t\tlist.css(\'height\',0).animate({\n
\t\t\t\t\t\t\t\'height\': height\n
\t\t\t\t\t\t},200);\n
\t\t\t\t\t\ton_button = true;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tbutton.removeClass(\'buttondown\').addClass(\'buttonup\');\n
\t\t\t\t\t\tlist.fadeOut(200);\n
\t\t\t\t\t}\n
\t\t\t\t}).hover(function() {\n
\t\t\t\t\ton_button = true;\n
\t\t\t\t}).mouseout(function() {\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tvar list_items = $(\'#main_menu li\');\n
\t\t\t\t\n
\t\t\t\t// Check if JS method of hovering needs to be used (Webkit bug)\n
\t\t\t\tlist_items.mouseover(function() {\n
\t\t\t\t\tjs_hover = ($(this).css(\'background-color\') == \'rgba(0, 0, 0, 0)\');\n
\t\t\t\t\t\n
\t\t\t\t\tlist_items.unbind(\'mouseover\');\n
\t\t\t\t\tif(js_hover) {\n
\t\t\t\t\t\tlist_items.mouseover(function() {\n
\t\t\t\t\t\t\tthis.style.backgroundColor = \'#FFC\';\n
\t\t\t\t\t\t}).mouseout(function() {\n
\t\t\t\t\t\t\tthis.style.backgroundColor = \'transparent\';\n
\t\t\t\t\t\t\treturn true;\n
\t\t\t\t\t\t});\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}());\n
\t\t\t\n
\t\t\tvar addDropDown = function(elem, callback, dropUp) {\n
\t\t\t\tvar button = $(elem).find(\'button\');\n
\t\t\t\tvar list = $(elem).find(\'ul\');\n
\t\t\t\tvar on_button = false;\n
\t\t\t\tif(dropUp) {\n
\t\t\t\t\t$(elem).addClass(\'dropup\');\n
\t\t\t\t}\n
\t\t\t\n
\t\t\t\t$(elem).find(\'li\').bind(\'mouseup\', callback);\n
\t\t\t\t\n
\t\t\t\t$(window).mouseup(function(evt) {\n
\t\t\t\t\tif(!on_button) {\n
\t\t\t\t\t\tbutton.removeClass(\'down\');\n
\t\t\t\t\t\tlist.hide();\n
\t\t\t\t\t}\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tbutton.bind(\'mousedown\',function() {\n
\t\t\t\t\tif (!button.hasClass(\'down\')) {\n
\t\t\t\t\t\tbutton.addClass(\'down\');\n
\t\t\t\t\t\tlist.show();\n
\t\t\t\t\t\ton_button = true;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tbutton.removeClass(\'down\');\n
\t\t\t\t\t\tlist.hide();\n
\t\t\t\t\t}\n
\t\t\t\t}).hover(function() {\n
\t\t\t\t\ton_button = true;\n
\t\t\t\t}).mouseout(function() {\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\t\n
\t\t\t// TODO: Combine this with addDropDown or find other way to optimize\n
\t\t\tvar addAltDropDown = function(elem, list, callback, opts) {\n
\t\t\t\tvar button = $(elem);\n
\t\t\t\tvar list = $(list);\n
\t\t\t\tvar on_button = false;\n
\t\t\t\tvar dropUp = opts.dropUp;\n
\t\t\t\tif(dropUp) {\n
\t\t\t\t\t$(elem).addClass(\'dropup\');\n
\t\t\t\t}\n
\t\t\t\tlist.find(\'li\').bind(\'mouseup\', function() {\n
\t\t\t\t\tif(opts.seticon) {\n
\t\t\t\t\t\tsetIcon(\'#cur_\' + button[0].id , $(this).children());\n
\t\t\t\t\t\t$(this).addClass(\'current\').siblings().removeClass(\'current\');\n
\t\t\t\t\t}\n
\t\t\t\t\tcallback.apply(this, arguments);\n
\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$(window).mouseup(function(evt) {\n
\t\t\t\t\tif(!on_button) {\n
\t\t\t\t\t\tbutton.removeClass(\'down\');\n
\t\t\t\t\t\tlist.hide();\n
\t\t\t\t\t\tlist.css({top:0, left:0});\n
\t\t\t\t\t}\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tvar height = list.height();\n
\t\t\t\t$(elem).bind(\'mousedown\',function() {\n
\t\t\t\t\tvar off = $(elem).offset();\n
\t\t\t\t\tif(dropUp) {\n
\t\t\t\t\t\toff.top -= list.height();\n
\t\t\t\t\t\toff.left += 8;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\toff.top += $(elem).height();\n
\t\t\t\t\t}\n
\t\t\t\t\t$(list).offset(off);\n
\t\t\t\t\t\n
\t\t\t\t\tif (!button.hasClass(\'down\')) {\n
\t\t\t\t\t\tbutton.addClass(\'down\');\n
\t\t\t\t\t\tlist.show();\n
\t\t\t\t\t\ton_button = true;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tbutton.removeClass(\'down\');\n
\t\t\t\t\t\t// CSS position must be reset for Webkit\n
\t\t\t\t\t\tlist.hide();\n
\t\t\t\t\t\tlist.css({top:0, left:0});\n
\t\t\t\t\t}\n
\t\t\t\t}).hover(function() {\n
\t\t\t\t\ton_button = true;\n
\t\t\t\t}).mouseout(function() {\n
\t\t\t\t\ton_button = false;\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\tif(opts.multiclick) {\n
\t\t\t\t\tlist.mousedown(function() {\n
\t\t\t\t\t\ton_button = true;\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\taddDropDown(\'#font_family_dropdown\', function() {\n
\t\t\t\tvar fam = $(this).text();\n
\t\t\t\t$(\'#font_family\').val($(this).text()).change();\n
\t\t\t});\n
\t\t\t\n
\t\t\taddDropDown(\'#opacity_dropdown\', function() {\n
\t\t\t\tif($(this).find(\'div\').length) return;\n
\t\t\t\tvar perc = parseInt($(this).text().split(\'%\')[0]);\n
\t\t\t\tchangeOpacity(false, perc);\n
\t\t\t}, true);\n
\t\t\t\n
\t\t\t// For slider usage, see: http://jqueryui.com/demos/slider/ \n
\t\t\t$("#opac_slider").slider({\n
\t\t\t\tstart: function() {\n
\t\t\t\t\t$(\'#opacity_dropdown li:not(.special)\').hide();\n
\t\t\t\t},\n
\t\t\t\tstop: function() {\n
\t\t\t\t\t$(\'#opacity_dropdown li\').show();\n
\t\t\t\t\t$(window).mouseup();\n
\t\t\t\t},\n
\t\t\t\tslide: function(evt, ui){\n
\t\t\t\t\tchangeOpacity(ui);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\n
\t\t\taddDropDown(\'#blur_dropdown\', function() {\n
\t\t\t});\n
\t\t\t\n
\t\t\tvar slideStart = false;\n
\t\t\t\n
\t\t\t$("#blur_slider").slider({\n
\t\t\t\tmax: 10,\n
\t\t\t\tstep: .1,\n
\t\t\t\tstop: function(evt, ui) {\n
\t\t\t\t\tslideStart = false;\n
\t\t\t\t\tchangeBlur(ui);\n
\t\t\t\t\t$(\'#blur_dropdown li\').show();\n
\t\t\t\t\t$(window).mouseup();\n
\t\t\t\t},\n
\t\t\t\tstart: function() {\n
\t\t\t\t\tslideStart = true;\n
\t\t\t\t},\n
\t\t\t\tslide: function(evt, ui){\n
\t\t\t\t\tchangeBlur(ui, null, slideStart);\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\n
\t\t\taddDropDown(\'#zoom_dropdown\', function() {\n
\t\t\t\tvar item = $(this);\n
\t\t\t\tvar val = item.attr(\'data-val\');\n
\t\t\t\tif(val) {\n
\t\t\t\t\tzoomChanged(window, val);\n
\t\t\t\t} else {\n
\t\t\t\t\tchangeZoom({value:parseInt(item.text())});\n
\t\t\t\t}\n
\t\t\t}, true);\n
\t\t\t\n
\t\t\taddAltDropDown(\'#stroke_linecap\', \'#linecap_opts\', function() {\n
\t\t\t\tsetStrokeOpt(this, true);\n
\t\t\t}, {dropUp: true});\n
\t\t\t\n
\t\t\taddAltDropDown(\'#stroke_linejoin\', \'#linejoin_opts\', function() {\n
\t\t\t\tsetStrokeOpt(this, true);\n
\t\t\t}, {dropUp: true});\n
\t\t\t\n
\t\t\taddAltDropDown(\'#tool_position\', \'#position_opts\', function() {\n
\t\t\t\tvar letter = this.id.replace(\'tool_pos\',\'\').charAt(0);\n
\t\t\t\tsvgCanvas.alignSelectedElements(letter, \'page\');\n
\t\t\t}, {multiclick: true});\n
\t\t\t\n
\t\t\t/*\n
\t\t\t\n
\t\t\tWhen a flyout icon is selected\n
\t\t\t\t(if flyout) {\n
\t\t\t\t- Change the icon\n
\t\t\t\t- Make pressing the button run its stuff\n
\t\t\t\t}\n
\t\t\t\t- Run its stuff\n
\t\t\t\n
\t\t\tWhen its shortcut key is pressed\n
\t\t\t\t- If not current in list, do as above\n
\t\t\t\t, else:\n
\t\t\t\t- Just run its stuff\n
\t\t\t\n
\t\t\t*/\n
\t\t\t\n
\t\t\t// Unfocus text input when workarea is mousedowned.\n
\t\t\t(function() {\n
\t\t\t\tvar inp;\n
\n
\t\t\t\tvar unfocus = function() {\n
\t\t\t\t\t$(inp).blur();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Do not include the #text input, as it needs to remain focused \n
\t\t\t\t// when clicking on an SVG text element.\n
\t\t\t\t$(\'#svg_editor input:text:not(#text)\').focus(function() {\n
\t\t\t\t\tinp = this;\n
\t\t\t\t\tworkarea.mousedown(unfocus);\n
\t\t\t\t}).blur(function() {\n
\t\t\t\t\tworkarea.unbind(\'mousedown\', unfocus);\n
\t\t\t\t});\n
\t\t\t}());\n
\n
\t\t\tvar clickSelect = function() {\n
\t\t\t\tif (toolButtonClick(\'#tool_select\')) {\n
\t\t\t\t\tsvgCanvas.setMode(\'select\');\n
\t\t\t\t\t$(\'#styleoverrides\').text(\'#svgcanvas svg *{cursor:move;pointer-events:all}, #svgcanvas svg{cursor:default}\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickFHPath = function() {\n
\t\t\t\tif (toolButtonClick(\'#tool_fhpath\')) {\n
\t\t\t\t\tsvgCanvas.setMode(\'fhpath\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickLine = function() {\n
\t\t\t\tif (toolButtonClick(\'#tool_line\')) {\n
\t\t\t\t\tsvgCanvas.setMode(\'line\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickSquare = function(){\n
\t\t\t\tsvgCanvas.setMode(\'square\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickRect = function(){\n
\t\t\t\tsvgCanvas.setMode(\'rect\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickFHRect = function(){\n
\t\t\t\tsvgCanvas.setMode(\'fhrect\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickCircle = function(){\n
\t\t\t\tsvgCanvas.setMode(\'circle\');\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickEllipse = function(){\n
\t\t\t\tsvgCanvas.setMode(\'ellipse\');\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickFHEllipse = function(){\n
\t\t\t\tsvgCanvas.setMode(\'fhellipse\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickImage = function(){\n
\t\t\t\tif (toolButtonClick(\'#tool_image\')) {\n
\t\t\t\t\tsvgCanvas.setMode(\'image\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickZoom = function(){\n
\t\t\t\tif (toolButtonClick(\'#tool_zoom\')) {\n
\t\t\t\t\tworkarea.css(\'cursor\',\'crosshair\');\n
\t\t\t\t\tsvgCanvas.setMode(\'zoom\');\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar dblclickZoom = function(){\n
\t\t\t\tif (toolButtonClick(\'#tool_zoom\')) {\n
\t\t\t\t\tzoomImage();\n
\t\t\t\t\tsetSelectMode();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickText = function(){\n
\t\t\t\ttoolButtonClick(\'#tool_text\');\n
\t\t\t\tsvgCanvas.setMode(\'text\');\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickPath = function(){\n
\t\t\t\ttoolButtonClick(\'#tool_path\');\n
\t\t\t\tsvgCanvas.setMode(\'path\');\n
\t\t\t};\n
\t\t\t\n
\t\t\t// Delete is a contextual tool that only appears in the ribbon if\n
\t\t\t// an element has been selected\n
\t\t\tvar deleteSelected = function() {\n
\t\t\t\tif (selectedElement != null || multiselected) {\n
\t\t\t\t\tsvgCanvas.deleteSelectedElements();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar moveToTopSelected = function() {\n
\t\t\t\tif (selectedElement != null) {\n
\t\t\t\t\tsvgCanvas.moveToTopSelectedElement();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar moveToBottomSelected = function() {\n
\t\t\t\tif (selectedElement != null) {\n
\t\t\t\t\tsvgCanvas.moveToBottomSelectedElement();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar convertToPath = function() {\n
\t\t\t\tif (selectedElement != null) {\n
\t\t\t\t\tsvgCanvas.convertToPath();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar reorientPath = function() {\n
\t\t\t\tif (selectedElement != null) {\n
\t\t\t\t\tpath.reorient();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
\t\t\tvar moveSelected = function(dx,dy) {\n
\t\t\t\tif (selectedElement != null || multiselected) {\n
\t\t\t\t\tsvgCanvas.moveSelectedElements(dx,dy);\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar linkControlPoints = function() {\n
\t\t\t\tvar linked = !$(\'#tool_node_link\').hasClass(\'push_button_pressed\');\n
\t\t\t\tif (linked)\n
\t\t\t\t\t$(\'#tool_node_link\').addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
\t\t\t\telse\n
\t\t\t\t\t$(\'#tool_node_link\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\t\t\n
\t\t\t\tpath.linkControlPoints(linked);\n
\t\t\t}\n
\t\t\n
\t\t\tvar clonePathNode = function() {\n
\t\t\t\tif (path.getNodePoint()) {\n
\t\t\t\t\tpath.clonePathNode();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar deletePathNode = function() {\n
\t\t\t\tif (path.getNodePoint()) {\n
\t\t\t\t\tpath.deletePathNode();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar addSubPath = function() {\n
\t\t\t\tvar button = $(\'#tool_add_subpath\');\n
\t\t\t\tvar sp = !button.hasClass(\'push_button_pressed\');\n
\t\t\t\tif (sp) {\n
\t\t\t\t\tbutton.addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
\t\t\t\t} else {\n
\t\t\t\t\tbutton.removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tpath.addSubPath(sp);\n
\t\t\t\t\n
\t\t\t};\n
\t\t\n
\t\t\tvar opencloseSubPath = function() {\n
\t\t\t\tpath.opencloseSubPath();\n
\t\t\t}\t\n
\t\t\t\n
\t\t\tvar selectNext = function() {\n
\t\t\t\tsvgCanvas.cycleElement(1);\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar selectPrev = function() {\n
\t\t\t\tsvgCanvas.cycleElement(0);\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar rotateSelected = function(cw) {\n
\t\t\t\tif (selectedElement == null || multiselected) return;\n
\t\t\t\tvar step = 5;\n
\t\t\t\tif(!cw) step *= -1;\n
\t\t\t\tvar new_angle = $(\'#angle\').val()*1 + step;\n
\t\t\t\tsvgCanvas.setRotationAngle(new_angle);\n
\t\t\t\tupdateContextPanel();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickClear = function(){\n
\t\t\t\tvar dims = curConfig.dimensions;\n
\t\t\t\t$.confirm(uiStrings.QwantToClear, function(ok) {\n
\t\t\t\t\tif(!ok) return;\n
\t\t\t\t\tsetSelectMode();\n
\t\t\t\t\tsvgCanvas.clear();\n
\t\t\t\t\tsvgCanvas.setResolution(dims[0], dims[1]);\n
\t\t\t\t\tupdateCanvas(true);\n
\t\t\t\t\tzoomImage();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\tupdateContextPanel();\n
\t\t\t\t});\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickBold = function(){\n
\t\t\t\tsvgCanvas.setBold( !svgCanvas.getBold() );\n
\t\t\t\tupdateContextPanel();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickItalic = function(){\n
\t\t\t\tsvgCanvas.setItalic( !svgCanvas.getItalic() );\n
\t\t\t\tupdateContextPanel();\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickSave = function(){\n
\t\t\t\t// In the future, more options can be provided here\n
\t\t\t\tvar saveOpts = {\n
\t\t\t\t\t\'images\': curPrefs.img_save,\n
\t\t\t\t\t\'round_digits\': 6\n
\t\t\t\t}\n
\t\t\t\tsvgCanvas.save(saveOpts);\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickExport = function() {\n
\t\t\t\t// Open placeholder window (prevents popup)\n
\t\t\t\tvar str = uiStrings.loadingImage;\n
\t\t\t\texportWindow = window.open("data:text/html;charset=utf-8,<title>" + str + "<\\/title><h1>" + str + "<\\/h1>");\n
\n
\t\t\t\tif(window.canvg) {\n
\t\t\t\t\tsvgCanvas.rasterExport();\n
\t\t\t\t} else {\n
\t\t\t\t\t$.getScript(\'canvg/rgbcolor.js\', function() {\n
\t\t\t\t\t\t$.getScript(\'canvg/canvg.js\', function() {\n
\t\t\t\t\t\t\tsvgCanvas.rasterExport();\n
\t\t\t\t\t\t});\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// by default, svgCanvas.open() is a no-op.\n
\t\t\t// it is up to an extension mechanism (opera widget, etc) \n
\t\t\t// to call setCustomHandlers() which will make it do something\n
\t\t\tvar clickOpen = function(){\n
\t\t\t\tsvgCanvas.open();\n
\t\t\t};\n
\t\t\tvar clickImport = function(){\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickUndo = function(){\n
\t\t\t\tif (svgCanvas.getUndoStackSize() > 0) {\n
\t\t\t\t\tsvgCanvas.undo();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar clickRedo = function(){\n
\t\t\t\tif (svgCanvas.getRedoStackSize() > 0) {\n
\t\t\t\t\tsvgCanvas.redo();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickGroup = function(){\n
\t\t\t\t// group\n
\t\t\t\tif (multiselected) {\n
\t\t\t\t\tsvgCanvas.groupSelectedElements();\n
\t\t\t\t}\n
\t\t\t\t// ungroup\n
\t\t\t\telse if(selectedElement && selectedElement.tagName == \'g\'){\n
\t\t\t\t\tsvgCanvas.ungroupSelectedElement();\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickClone = function(){\n
\t\t\t\tsvgCanvas.cloneSelectedElements();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar clickAlign = function() {\n
\t\t\t\tvar letter = this.id.replace(\'tool_align\',\'\').charAt(0);\n
\t\t\t\tsvgCanvas.alignSelectedElements(letter, $(\'#align_relative_to\').val());\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar zoomImage = function(multiplier) {\n
\t\t\t\tvar res = svgCanvas.getResolution();\n
\t\t\t\tmultiplier = multiplier?res.zoom * multiplier:1;\n
\t\t// \t\tsetResolution(res.w * multiplier, res.h * multiplier, true);\n
\t\t\t\t$(\'#zoom\').val(multiplier * 100);\n
\t\t\t\tsvgCanvas.setZoom(multiplier);\n
\t\t\t\tzoomDone();\n
\t\t\t\tupdateCanvas(true);\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar zoomDone = function() {\n
\t\t// \t\tupdateBgImage();\n
\t\t\t\tupdateWireFrame();\n
\t\t\t\t//updateCanvas(); // necessary?\n
\t\t\t}\n
\t\t\n
\t\t\tvar clickWireframe = function() {\n
\t\t\t\tvar wf = !$(\'#tool_wireframe\').hasClass(\'push_button_pressed\');\n
\t\t\t\tif (wf) \n
\t\t\t\t\t$(\'#tool_wireframe\').addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
\t\t\t\telse\n
\t\t\t\t\t$(\'#tool_wireframe\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
\t\t\t\tworkarea.toggleClass(\'wireframe\');\n
\t\t\t\t\n
\t\t\t\tif(supportsNonSS) return;\n
\t\t\t\tvar wf_rules = $(\'#wireframe_rules\');\n
\t\t\t\tif(!wf_rules.length) {\n
\t\t\t\t\twf_rules = $(\'<style id="wireframe_rules"><\\/style>\').appendTo(\'head\');\n
\t\t\t\t} else {\n
\t\t\t\t\twf_rules.empty();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tupdateWireFrame();\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar updateWireFrame = function() {\n
\t\t\t\t// Test support\n
\t\t\t\tif(supportsNonSS) return;\n
\t\t\n
\t\t\t\tvar rule = "#workarea.wireframe #svgcontent * { stroke-width: " + 1/svgCanvas.getZoom() + "px; }";\n
\t\t\t\t$(\'#wireframe_rules\').text(workarea.hasClass(\'wireframe\') ? rule : "");\n
\t\t\t}\n
\t\t\n
\t\t\tvar showSourceEditor = function(){\n
\t\t\t\tif (editingsource) return;\n
\t\t\t\teditingsource = true;\n
\t\t\t\tvar str = svgCanvas.getSvgString();\n
\t\t\t\t$(\'#svg_source_textarea\').val(str);\n
\t\t\t\t$(\'#svg_source_editor\').fadeIn();\n
\t\t\t\tproperlySourceSizeTextArea();\n
\t\t\t\t$(\'#svg_source_textarea\').focus();\n
\t\t\t};\n
\t\t\t\n
\t\t\t$(\'#svg_docprops_container\').draggable({cancel:\'button,fieldset\'});\n
\t\t\t\n
\t\t\tvar showDocProperties = function(){\n
\t\t\t\tif (docprops) return;\n
\t\t\t\tdocprops = true;\n
\t\t\t\t\n
\t\t\t\t// This selects the correct radio button by using the array notation\n
\t\t\t\t$(\'#image_save_opts input\').val([curPrefs.img_save]);\n
\t\t\t\t\n
\t\t\t\t// update resolution option with actual resolution\n
\t\t\t\tvar res = svgCanvas.getResolution();\n
\t\t\t\t$(\'#canvas_width\').val(res.w);\n
\t\t\t\t$(\'#canvas_height\').val(res.h);\n
\t\t\t\t$(\'#canvas_title\').val(svgCanvas.getDocumentTitle());\n
\t\t\t\t\n
\t\t\t\t// Update background color with current one\n
\t\t\t\tvar blocks = $(\'#bg_blocks div\');\n
\t\t\t\tvar cur_bg = \'cur_background\';\n
\t\t\t\tvar canvas_bg = $.pref(\'bkgd_color\');\n
\t\t\t\tvar url = $.pref(\'bkgd_url\');\n
\t\t// \t\tif(url) url = url[1];\n
\t\t\t\tblocks.each(function() {\n
\t\t\t\t\tvar blk = $(this);\n
\t\t\t\t\tvar is_bg = blk.css(\'background-color\') == canvas_bg;\n
\t\t\t\t\tblk.toggleClass(cur_bg, is_bg);\n
\t\t\t\t\tif(is_bg) $(\'#canvas_bg_url\').removeClass(cur_bg);\n
\t\t\t\t});\n
\t\t\t\tif(!canvas_bg) blocks.eq(0).addClass(cur_bg);\n
\t\t\t\tif(url) {\n
\t\t\t\t\t$(\'#canvas_bg_url\').val(url);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$(\'#svg_docprops\').fadeIn();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar properlySourceSizeTextArea = function(){\n
\t\t\t\t// TODO: remove magic numbers here and get values from CSS\n
\t\t\t\tvar height = $(\'#svg_source_container\').height() - 80;\n
\t\t\t\t$(\'#svg_source_textarea\').css(\'height\', height);\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar saveSourceEditor = function(){\n
\t\t\t\tif (!editingsource) return;\n
\t\t\n
\t\t\t\tvar saveChanges = function() {\n
\t\t\t\t\tsvgCanvas.clearSelection();\n
\t\t\t\t\thideSourceEditor();\n
\t\t\t\t\tzoomImage();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\tsetTitle(svgCanvas.getDocumentTitle());\n
\t\t\t\t}\n
\t\t\n
\t\t\t\tif (!svgCanvas.setSvgString($(\'#svg_source_textarea\').val())) {\n
\t\t\t\t\t$.confirm(uiStrings.QerrorsRevertToSource, function(ok) {\n
\t\t\t\t\t\tif(!ok) return false;\n
\t\t\t\t\t\tsaveChanges();\n
\t\t\t\t\t});\n
\t\t\t\t} else {\n
\t\t\t\t\tsaveChanges();\n
\t\t\t\t}\n
\t\t\t\tsetSelectMode();\t\t\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar setTitle = function(title) {\n
\t\t\t\tvar editor_title = $(\'title:first\').text().split(\':\')[0];\n
\t\t\t\tvar new_title = editor_title + (title?\': \' + title:\'\');\n
\t\t\t\t$(\'title:first\').text(new_title);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar saveDocProperties = function(){\n
\t\t\t\t// set title\n
\t\t\t\tvar new_title = $(\'#canvas_title\').val();\n
\t\t\t\tsetTitle(new_title);\n
\t\t\t\tsvgCanvas.setDocumentTitle(new_title);\n
\t\t\t\n
\t\t\t\t// update resolution\n
\t\t\t\tvar width = $(\'#canvas_width\'), w = width.val();\n
\t\t\t\tvar height = $(\'#canvas_height\'), h = height.val();\n
\t\t\n
\t\t\t\tif(w != "fit" && !svgCanvas.isValidUnit(\'width\', w)) {\n
\t\t\t\t\t$.alert(uiStrings.invalidAttrValGiven);\n
\t\t\t\t\twidth.parent().addClass(\'error\');\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\twidth.parent().removeClass(\'error\');\n
\t\t\t\t\n
\t\t\t\tif(h != "fit" && !svgCanvas.isValidUnit(\'height\', h)) {\n
\t\t\t\t\t$.alert(uiStrings.invalidAttrValGiven);\n
\t\t\t\t\theight.parent().addClass(\'error\');\n
\t\t\t\t\treturn false;\n
\t\t\t\t} \n
\t\t\t\t\n
\t\t\t\theight.parent().removeClass(\'error\');\n
\t\t\t\t\n
\t\t\t\tif(!svgCanvas.setResolution(w, h)) {\n
\t\t\t\t\t$.alert(uiStrings.noContentToFitTo);\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// set image save option\n
\t\t\t\tcurPrefs.img_save = $(\'#image_save_opts :checked\').val();\n
\t\t\t\t$.pref(\'img_save\',curPrefs.img_save);\n
\t\t\t\t\n
\t\t\t\t// set background\n
\t\t\t\tvar color = $(\'#bg_blocks div.cur_background\').css(\'background-color\') || \'#FFF\';\n
\t\t\t\tsetBackground(color, $(\'#canvas_bg_url\').val());\n
\t\t\t\t\n
\t\t\t\t// set language\n
\t\t\t\tvar lang = $(\'#lang_select\').val();\n
\t\t\t\tif(lang != curPrefs.lang) {\n
\t\t\t\t\tEditor.putLocale(lang);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// set icon size\n
\t\t\t\tsetIconSize($(\'#iconsize\').val());\n
\t\t\t\t\n
\t\t\t\tupdateCanvas();\n
\t\t\t\thideDocProperties();\n
\t\t\t};\n
\t\t\t\n
\t\t\tfunction setBackground(color, url) {\n
\t\t\t\tif(color == curPrefs.bkgd_color && url == curPrefs.bkgd_url) return;\n
\t\t\t\t$.pref(\'bkgd_color\', color);\n
\t\t\t\t$.pref(\'bkgd_url\', url);\n
\t\t\t\t\n
\t\t\t\t// This should be done in svgcanvas.js for the borderRect fill\n
\t\t\t\tsvgCanvas.setBackground(color, url);\n
\t\t\t}\n
\t\t\t\n
\t\t\tvar setIcon = Editor.setIcon = function(elem, icon_id, forcedSize) {\n
\t\t\t\tvar icon = (typeof icon_id == \'string\') ? $.getSvgIcon(icon_id).clone() : icon_id.clone();\n
\t\t\t\t$(elem).empty().append(icon);\n
\t\t\t\tif(forcedSize) {\n
\t\t\t\t\tvar obj = {};\n
\t\t\t\t\tobj[elem + \' .svg_icon\'] = forcedSize;\n
\t\t\t\t\t$.resizeSvgIcons(obj);\n
\t\t\t\t} else {\n
\t\t\t\t\tvar size = curPrefs.iconsize;\n
\t\t\t\t\tif(size && size !== \'m\') {\n
\t\t\t\t\t\tvar icon_sizes = { s:16, m:24, l:32, xl:48}, obj = {};\n
\t\t\t\t\t\tobj[elem + \' .svg_icon\'] = icon_sizes[size];\n
\t\t\t\t\t\t$.resizeSvgIcons(obj);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
\t\t\tvar setIconSize = Editor.setIconSize = function(size, force) {\n
\t\t\t\tif(size == curPrefs.size && !force) return;\n
\t\t\t\t$.pref(\'iconsize\', size);\n
\t\t\t\t$(\'#iconsize\').val(size);\n
\t\t\t\tvar icon_sizes = { s:16, m:24, l:32, xl:48 };\n
\t\t\t\tvar size_num = icon_sizes[size];\n
\t\t\t\t\n
\t\t\t\t// Change icon size\n
\t\t\t\t$(\'.tool_button, .push_button, .tool_button_current, .disabled, .icon_label, #url_notice, #tool_open\')\n
\t\t\t\t.find(\'> svg, > img\').each(function() {\n
\t\t\t\t\tthis.setAttribute(\'width\',size_num);\n
\t\t\t\t\tthis.setAttribute(\'height\',size_num);\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$.resizeSvgIcons({\n
\t\t\t\t\t\'.flyout_arrow_horiz > svg, .flyout_arrow_horiz > img\': size_num / 5,\n
\t\t\t\t\t\'#logo > svg, #logo > img\': size_num * 1.3,\n
\t\t\t\t\t\'#tools_bottom .icon_label > *\': (size_num === 16 ? 18 : size_num * .75)\n
\t\t\t\t});\n
\t\t\t\tif(size != \'s\') {\n
\t\t\t\t\t$.resizeSvgIcons({\'#layerbuttons svg, #layerbuttons img\': size_num * .6});\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Note that all rules will be prefixed with \'#svg_editor\' when parsed\n
\t\t\t\tvar cssResizeRules = {\n
\t\t\t\t\t".tool_button,\\\n
\t\t\t\t\t.push_button,\\\n
\t\t\t\t\t.tool_button_current,\\\n
\t\t\t\t\t.push_button_pressed,\\\n
\t\t\t\t\t.disabled,\\\n
\t\t\t\t\t.icon_label,\\\n
\t\t\t\t\t.tools_flyout .tool_button": {\n
\t\t\t\t\t\t\'width\': {s: \'16px\', l: \'32px\', xl: \'48px\'},\n
\t\t\t\t\t\t\'height\': {s: \'16px\', l: \'32px\', xl: \'48px\'},\n
\t\t\t\t\t\t\'padding\': {s: \'1px\', l: \'2px\', xl: \'3px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t".tool_sep": {\n
\t\t\t\t\t\t\'height\': {s: \'16px\', l: \'32px\', xl: \'48px\'},\n
\t\t\t\t\t\t\'margin\': {s: \'2px 2px\', l: \'2px 5px\', xl: \'2px 8px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#main_icon": {\n
\t\t\t\t\t\t\'width\': {s: \'31px\', l: \'53px\', xl: \'75px\'},\n
\t\t\t\t\t\t\'height\': {s: \'22px\', l: \'42px\', xl: \'64px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_top": {\n
\t\t\t\t\t\t\'left\': {s: \'36px\', l: \'60px\', xl: \'80px\'},\n
\t\t\t\t\t\t\'height\': {s: \'50px\', l: \'88px\', xl: \'125px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_left": {\n
\t\t\t\t\t\t\'width\': {s: \'22px\', l: \'30px\', xl: \'38px\'},\n
\t\t\t\t\t\t\'top\': {s: \'50px\', l: \'87px\', xl: \'125px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"div#workarea": {\n
\t\t\t\t\t\t\'left\': {s: \'27px\', l: \'46px\', xl: \'65px\'},\n
\t\t\t\t\t\t\'top\': {s: \'50px\', l: \'88px\', xl: \'125px\'},\n
\t\t\t\t\t\t\'bottom\': {s: \'55px\', l: \'98px\', xl: \'145px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_bottom": {\n
\t\t\t\t\t\t\'left\': {s: \'27px\', l: \'46px\', xl: \'65px\'},\n
\t\t\t\t\t\t\'height\': {s: \'58px\', l: \'98px\', xl: \'145px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#color_tools": {\n
\t\t\t\t\t\t\'border-spacing\': {s: \'0 1px\'},\n
\t\t\t\t\t\t\'margin-top\': {s: \'-1px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#color_tools .icon_label": {\n
\t\t\t\t\t\t\'width\': {l:\'43px\', xl: \'60px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t".color_tool": {\n
\t\t\t\t\t\t\'height\': {s: \'20px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tool_opacity": {\n
\t\t\t\t\t\t\'top\': {s: \'1px\'},\n
\t\t\t\t\t\t\'height\': {s: \'auto\', l:\'auto\', xl:\'auto\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_top input, #tools_bottom input": {\n
\t\t\t\t\t\t\'margin-top\': {s: \'2px\', l: \'4px\', xl: \'5px\'},\n
\t\t\t\t\t\t\'height\': {s: \'auto\', l: \'auto\', xl: \'auto\'},\n
\t\t\t\t\t\t\'border\': {s: \'1px solid #555\', l: \'auto\', xl: \'auto\'},\n
\t\t\t\t\t\t\'font-size\': {s: \'.9em\', l: \'1.2em\', xl: \'1.4em\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#zoom_panel": {\n
\t\t\t\t\t\t\'margin-top\': {s: \'3px\', l: \'4px\', xl: \'5px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#copyright, #tools_bottom .label": {\n
\t\t\t\t\t\t\'font-size\': {l: \'1.5em\', xl: \'2em\'},\n
\t\t\t\t\t\t\'line-height\': {s: \'15px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_bottom_2": {\n
\t\t\t\t\t\t\'width\': {l: \'295px\', xl: \'355px\'},\n
\t\t\t\t\t\t\'top\': {s: \'4px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_top > div, #tools_top": {\n
\t\t\t\t\t\t\'line-height\': {s: \'17px\', l: \'34px\', xl: \'50px\'}\n
\t\t\t\t\t}, \n
\t\t\t\t\t".dropdown button": {\n
\t\t\t\t\t\t\'height\': {s: \'18px\', l: \'34px\', xl: \'40px\'},\n
\t\t\t\t\t\t\'line-height\': {s: \'18px\', l: \'34px\', xl: \'40px\'},\n
\t\t\t\t\t\t\'margin-top\': {s: \'3px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tools_top label, #tools_bottom label": {\n
\t\t\t\t\t\t\'font-size\': {s: \'1em\', l: \'1.5em\', xl: \'2em\'},\n
\t\t\t\t\t\t\'height\': {s: \'25px\', l: \'42px\', xl: \'64px\'}\n
\t\t\t\t\t}, \n
\t\t\t\t\t"div.toolset": {\n
\t\t\t\t\t\t\'height\': {s: \'25px\', l: \'42px\', xl: \'64px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#tool_bold, #tool_italic": {\n
\t\t\t\t\t\t\'font-size\': {s: \'1.5em\', l: \'3em\', xl: \'4.5em\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#sidepanels": {\n
\t\t\t\t\t\t\'top\': {s: \'50px\', l: \'88px\', xl: \'125px\'},\n
\t\t\t\t\t\t\'bottom\': {s: \'51px\', l: \'68px\', xl: \'65px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t\'#layerbuttons\': {\n
\t\t\t\t\t\t\'width\': {l: \'130px\', xl: \'175px\'},\n
\t\t\t\t\t\t\'height\': {l: \'24px\', xl: \'30px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t\'#layerlist\': {\n
\t\t\t\t\t\t\'width\': {l: \'128px\', xl: \'150px\'}\n
\t\t\t\t\t},\t\t\t\n
\t\t\t\t\t\'.layer_button\': {\n
\t\t\t\t\t\t\'width\': {l: \'19px\', xl: \'28px\'},\n
\t\t\t\t\t\t\'height\': {l: \'19px\', xl: \'28px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"input.spin-button": {\n
\t\t\t\t\t\t\'background-image\': {l: "url(\'images/spinbtn_updn_big.png\')", xl: "url(\'images/spinbtn_updn_big.png\')"},\n
\t\t\t\t\t\t\'background-position\': {l: \'100% -5px\', xl: \'100% -2px\'},\n
\t\t\t\t\t\t\'padding-right\': {l: \'24px\', xl: \'24px\' }\n
\t\t\t\t\t},\n
\t\t\t\t\t"input.spin-button.up": {\n
\t\t\t\t\t\t\'background-position\': {l: \'100% -45px\', xl: \'100% -42px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"input.spin-button.down": {\n
\t\t\t\t\t\t\'background-position\': {l: \'100% -85px\', xl: \'100% -82px\'}\n
\t\t\t\t\t},\n
\t\t\t\t\t"#position_opts": {\n
\t\t\t\t\t\t\'width\': {all: (size_num*4) +\'px\'}\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t\t\n
\t\t\t\tvar rule_elem = $(\'#tool_size_rules\');\n
\t\t\t\tif(!rule_elem.length) {\n
\t\t\t\t\trule_elem = $(\'<style id="tool_size_rules"><\\/style>\').appendTo(\'head\');\n
\t\t\t\t} else {\n
\t\t\t\t\trule_elem.empty();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(size != \'m\') {\n
\t\t\t\t\tvar style_str = \'\';\n
\t\t\t\t\t$.each(cssResizeRules, function(selector, rules) {\n
\t\t\t\t\t\tselector = \'#svg_editor \' + selector.replace(/,/g,\', #svg_editor\');\n
\t\t\t\t\t\tstyle_str += selector + \'{\';\n
\t\t\t\t\t\t$.each(rules, function(prop, values) {\n
\t\t\t\t\t\t\tif(values[size] || values.all) {\n
\t\t\t\t\t\t\t\tstyle_str += (prop + \':\' + (values[size] || values.all) + \';\');\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\tstyle_str += \'}\';\n
\t\t\t\t\t});\n
\t\t\t\t\trule_elem.text(style_str);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tsetFlyoutPositions();\n
\t\t\t}\n
\t\t\n
\t\t\tvar cancelOverlays = function() {\n
\t\t\t\t$(\'#dialog_box\').hide();\n
\t\t\t\tif (!editingsource && !docprops) return;\n
\t\t\n
\t\t\t\tif (editingsource) {\n
\t\t\t\t\tvar oldString = svgCanvas.getSvgString();\n
\t\t\t\t\tif (oldString != $(\'#svg_source_textarea\').val()) {\n
\t\t\t\t\t\t$.confirm(uiStrings.QignoreSourceChanges, function(ok) {\n
\t\t\t\t\t\t\tif(ok) hideSourceEditor();\n
\t\t\t\t\t\t});\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\thideSourceEditor();\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\telse if (docprops) {\n
\t\t\t\t\thideDocProperties();\n
\t\t\t\t}\n
\t\t\n
\t\t\t};\n
\t\t\n
\t\t\tvar hideSourceEditor = function(){\n
\t\t\t\t$(\'#svg_source_editor\').hide();\n
\t\t\t\teditingsource = false;\n
\t\t\t\t$(\'#svg_source_textarea\').blur();\n
\t\t\t};\n
\t\t\t\n
\t\t\tvar hideDocProperties = function(){\n
\t\t\t\t$(\'#svg_docprops\').hide();\n
\t\t\t\t$(\'#canvas_width,#canvas_height\').removeAttr(\'disabled\');\n
\t\t\t\t$(\'#resolution\')[0].selectedIndex = 0;\n
\t\t\t\t$(\'#image_save_opts input\').val([curPrefs.img_save]);\n
\t\t\t\tdocprops = false;\n
\t\t\t};\n
\n
\t\t\tvar win_wh = {width:$(window).width(), height:$(window).height()};\n
\t\t\t\n
\t\t\t$(window).resize(function(evt) {\n
\t\t\t\tif (editingsource) {\n
\t\t\t\t\tproperlySourceSizeTextArea();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t$.each(win_wh, function(type, val) {\n
\t\t\t\t\tvar curval = $(window)[type]();\n
\t\t\t\t\tworkarea[0][\'scroll\' + (type===\'width\'?\'Left\':\'Top\')] -= (curval - val)/2;\n
\t\t\t\t\twin_wh[type] = curval;\n
\t\t\t\t});\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#url_notice\').click(function() {\n
\t\t\t\t$.alert(this.title);\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#change_image_url\').click(promptImgURL);\n
\t\t\t\n
\t\t\tfunction promptImgURL() {\n
\t\t\t\t$.prompt(uiStrings.enterNewImgURL, default_img_url, function(url) {\n
\t\t\t\t\tif(url) setImageURL(url);\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\n
\t\t\tfunction setImageURL(url) {\n
\t\t\t\tif(!url) url = default_img_url;\n
\t\t\t\t\n
\t\t\t\tsvgCanvas.setImageURL(url);\n
\t\t\t\t$(\'#image_url\').val(url);\n
\t\t\t\t\n
\t\t\t\tif(url.indexOf(\'data:\') === 0) {\n
\t\t\t\t\t// data URI found\n
\t\t\t\t\t$(\'#image_url\').hide();\n
\t\t\t\t\t$(\'#change_image_url\').show();\n
\t\t\t\t} else {\n
\t\t\t\t\t// regular URL\n
\t\t\t\t\t\n
\t\t\t\t\tsvgCanvas.embedImage(url, function(datauri) {\n
\t\t\t\t\t\tif(!datauri) {\n
\t\t\t\t\t\t\t// Couldn\'t embed, so show warning\n
\t\t\t\t\t\t\t$(\'#url_notice\').show();\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t$(\'#url_notice\').hide();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tdefault_img_url = url;\n
\t\t\t\t\t});\n
\t\t\t\t\t$(\'#image_url\').show();\n
\t\t\t\t\t$(\'#change_image_url\').hide();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
\t\t\t// added these event handlers for all the push buttons so they\n
\t\t\t// behave more like buttons being pressed-in and not images\n
\t\t\t(function() {\n
\t\t\t\tvar toolnames = [\'clear\',\'open\',\'save\',\'source\',\'delete\',\'delete_multi\',\'paste\',\'clone\',\'clone_multi\',\'move_top\',\'move_bottom\'];\n
\t\t\t\tvar all_tools = \'\';\n
\t\t\t\tvar cur_class = \'tool_button_current\';\n
\t\t\t\t\n
\t\t\t\t$.each(toolnames, function(i,item) {\n
\t\t\t\t\tall_tools += \'#tool_\' + item + (i==toolnames.length-1?\',\':\'\');\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$(all_tools).mousedown(function() {\n
\t\t\t\t\t$(this).addClass(cur_class);\n
\t\t\t\t}).bind(\'mousedown mouseout\', function() {\n
\t\t\t\t\t$(this).removeClass(cur_class);\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t$(\'#tool_undo, #tool_redo\').mousedown(function(){ \n
\t\t\t\t\tif (!$(this).hasClass(\'disabled\')) $(this).addClass(cur_class);\n
\t\t\t\t}).bind(\'mousedown mouseout\',function(){\n
\t\t\t\t\t$(this).removeClass(cur_class);}\n
\t\t\t\t);\n
\t\t\t}());\n
\t\t\n
\t\t\t// switch modifier key in tooltips if mac\n
\t\t\t// NOTE: This code is not used yet until I can figure out how to successfully bind ctrl/meta\n
\t\t\t// in Opera and Chrome\n
\t\t\tif (isMac) {\n
\t\t\t\tvar shortcutButtons = ["tool_clear", "tool_save", "tool_source", "tool_undo", "tool_redo", "tool_clone"];\n
\t\t\t\tvar i = shortcutButtons.length;\n
\t\t\t\twhile (i--) {\n
\t\t\t\t\tvar button = document.getElementById(shortcutButtons[i]);\n
\t\t\t\t\tvar title = button.title;\n
\t\t\t\t\tvar index = title.indexOf("Ctrl+");\n
\t\t\t\t\tbutton.title = [title.substr(0,index), "Cmd+", title.substr(index+5)].join(\'\');\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\t// TODO: go back to the color boxes having white background-color and then setting\n
\t\t\t//       background-image to none.png (otherwise partially transparent gradients look weird)\t\n
\t\t\tvar colorPicker = function(elem) {\n
\t\t\t\tvar picker = elem.attr(\'id\') == \'stroke_color\' ? \'stroke\' : \'fill\';\n
// \t\t\t\tvar opacity = (picker == \'stroke\' ? $(\'#stroke_opacity\') : $(\'#fill_opacity\'));\n
\t\t\t\tvar paint = (picker == \'stroke\' ? strokePaint : fillPaint);\n
\t\t\t\tvar title = (picker == \'stroke\' ? \'Pick a Stroke Paint and Opacity\' : \'Pick a Fill Paint and Opacity\');\n
\t\t\t\tvar was_none = false;\n
\t\t\t\tvar pos = elem.position();\n
\t\t\t\t$("#color_picker")\n
\t\t\t\t\t.draggable({cancel:\'.jPicker_table,.jGraduate_lgPick,.jGraduate_rgPick\'})\n
\t\t\t\t\t.css({\'left\': pos.left, \'bottom\': 50 - pos.top})\n
\t\t\t\t\t.jGraduate(\n
\t\t\t\t\t{ \n
\t\t\t\t\t\tpaint: paint,\n
\t\t\t\t\t\twindow: { pickerTitle: title },\n
\t\t\t\t\t\timages: { clientPath: "jgraduate/images/" }\n
\t\t\t\t\t},\n
\t\t\t\t\tfunction(p) {\n
\t\t\t\t\t\tpaint = new $.jGraduate.Paint(p);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\tvar oldgrad = document.getElementById("gradbox_"+picker);\n
\t\t\t\t\t\tvar svgbox = oldgrad.parentNode;\n
\t\t\t\t\t\tvar rectbox = svgbox.firstChild;\n
\t\t\t\t\t\tif (paint.type == "linearGradient" || paint.type == "radialGradient") {\n
\t\t\t\t\t\t\tsvgbox.removeChild(oldgrad);\n
\t\t\t\t\t\t\tvar newgrad = svgbox.appendChild(document.importNode(paint[paint.type], true));\n
\t\t\t\t\t\t\tsvgCanvas.fixOperaXML(newgrad, paint[paint.type])\n
\t\t\t\t\t\t\tnewgrad.id = "gradbox_"+picker;\n
\t\t\t\t\t\t\trectbox.setAttribute("fill", "url(#gradbox_" + picker + ")");\n
\t\t\t\t\t\t\trectbox.setAttribute("opacity", paint.alpha/100);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\trectbox.setAttribute("fill", paint.solidColor != "none" ? "#" + paint.solidColor : "none");\n
\t\t\t\t\t\t\trectbox.setAttribute("opacity", paint.alpha/100);\n
\t\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\t\tif (picker == \'stroke\') {\n
\t\t\t\t\t\t\tsvgCanvas.setStrokePaint(paint, true);\n
\t\t\t\t\t\t\tstrokePaint = paint;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\telse {\n
\t\t\t\t\t\t\tsvgCanvas.setFillPaint(paint, true);\n
\t\t\t\t\t\t\tfillPaint = paint;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tupdateToolbar();\n
\t\t\t\t\t\t$(\'#color_picker\').hide();\n
\t\t\t\t\t},\n
\t\t\t\t\tfunction(p) {\n
\t\t\t\t\t\t$(\'#color_picker\').hide();\n
\t\t\t\t\t});\n
\t\t\t};\n
\t\t\n
\t\t\tvar updateToolButtonState = function() {\n
\t\t\t\tvar bNoFill = (svgCanvas.getFillColor() == \'none\');\n
\t\t\t\tvar bNoStroke = (svgCanvas.getStrokeColor() == \'none\');\n
\t\t\t\tvar buttonsNeedingStroke = [ \'#tool_fhpath\', \'#tool_line\' ];\n
\t\t\t\tvar buttonsNeedingFillAndStroke = [ \'#tools_rect .tool_button\', \'#tools_ellipse .tool_button\', \'#tool_text\', \'#tool_path\'];\n
\t\t\t\tif (bNoStroke) {\n
\t\t\t\t\tfor (index in buttonsNeedingStroke) {\n
\t\t\t\t\t\tvar button = buttonsNeedingStroke[index];\n
\t\t\t\t\t\tif ($(button).hasClass(\'tool_button_current\')) {\n
\t\t\t\t\t\t\tclickSelect();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t$(button).addClass(\'disabled\');\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tfor (index in buttonsNeedingStroke) {\n
\t\t\t\t\t\tvar button = buttonsNeedingStroke[index];\n
\t\t\t\t\t\t$(button).removeClass(\'disabled\');\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\n
\t\t\t\tif (bNoStroke && bNoFill) {\n
\t\t\t\t\tfor (index in buttonsNeedingFillAndStroke) {\n
\t\t\t\t\t\tvar button = buttonsNeedingFillAndStroke[index];\n
\t\t\t\t\t\tif ($(button).hasClass(\'tool_button_current\')) {\n
\t\t\t\t\t\t\tclickSelect();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\t$(button).addClass(\'disabled\');\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tfor (index in buttonsNeedingFillAndStroke) {\n
\t\t\t\t\t\tvar button = buttonsNeedingFillAndStroke[index];\n
\t\t\t\t\t\t$(button).removeClass(\'disabled\');\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tsvgCanvas.runExtensions("toolButtonStateUpdate", {\n
\t\t\t\t\tnofill: bNoFill,\n
\t\t\t\t\tnostroke: bNoStroke\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t// Disable flyouts if all inside are disabled\n
\t\t\t\t$(\'.tools_flyout\').each(function() {\n
\t\t\t\t\tvar shower = $(\'#\' + this.id + \'_show\');\n
\t\t\t\t\tvar has_enabled = false;\n
\t\t\t\t\t$(this).children().each(function() {\n
\t\t\t\t\t\tif(!$(this).hasClass(\'disabled\')) {\n
\t\t\t\t\t\t\thas_enabled = true;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t});\n
\t\t\t\t\tshower.toggleClass(\'disabled\', !has_enabled);\n
\t\t\t\t});\n
\t\t\n
\t\t\t\toperaRepaint();\n
\t\t\t};\n
\t\t\n
\t\t\t// set up gradients to be used for the buttons\n
\t\t\tvar svgdocbox = new DOMParser().parseFromString(\n
\t\t\t\t\'<svg xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%"\\\n
\t\t\t\tfill="#\' + curConfig.initFill.color + \'" opacity="\' + curConfig.initFill.opacity + \'"/>\\\n
\t\t\t\t<linearGradient id="gradbox_">\\\n
\t\t\t\t\t\t<stop stop-color="#000" offset="0.0"/>\\\n
\t\t\t\t\t\t<stop stop-color="#FF0000" offset="1.0"/>\\\n
\t\t\t\t</linearGradient></svg>\', \'text/xml\');\n
\t\t\n
\t\t\tvar boxgrad = svgdocbox.getElementById(\'gradbox_\');\n
\t\t\tboxgrad.id = \'gradbox_fill\';\n
\t\t\tsvgdocbox.documentElement.setAttribute(\'width\',16.5);\n
\t\t\t$(\'#fill_color\').append( document.importNode(svgdocbox.documentElement,true) );\n
\t\t\t\n
\t\t\tboxgrad.id = \'gradbox_stroke\';\t\n
\t\t\tsvgdocbox.documentElement.setAttribute(\'width\',16.5);\n
\t\t\t$(\'#stroke_color\').append( document.importNode(svgdocbox.documentElement,true) );\n
\t\t\t$(\'#stroke_color rect\').attr({\n
\t\t\t\t\'fill\': \'#\' + curConfig.initStroke.color,\n
\t\t\t\t\'opacity\': curConfig.initStroke.opacity\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#stroke_width\').val(curConfig.initStroke.width);\n
\t\t\t$(\'#group_opacity\').val(curConfig.initOpacity * 100);\n
\t\t\t\n
\t\t\t// Use this SVG elem to test vectorEffect support\n
\t\t\tvar test_el = svgdocbox.documentElement.firstChild;\n
\t\t\ttest_el.setAttribute(\'style\',\'vector-effect:non-scaling-stroke\');\n
\t\t\tvar supportsNonSS = (test_el.style.vectorEffect == \'non-scaling-stroke\');\n
\t\t\ttest_el.removeAttribute(\'style\');\n
\t\t\t\n
\t\t\t// Use this to test support for blur element. Seems to work to test support in Webkit\n
\t\t\tvar blur_test = svgdocbox.createElementNS(\'http://www.w3.org/2000/svg\', \'feGaussianBlur\');\n
\t\t\tif(typeof blur_test.stdDeviationX === "undefined") {\n
\t\t\t\t$(\'#tool_blur\').hide();\n
\t\t\t}\n
\t\t\t$(blur_test).remove();\n
\t\t\t\n
\t\t\t// Test for embedImage support (use timeout to not interfere with page load)\n
\t\t\tsetTimeout(function() {\n
\t\t\t\tsvgCanvas.embedImage(\'images/logo.png\', function(datauri) {\n
\t\t\t\t\tif(!datauri) {\n
\t\t\t\t\t\t// Disable option\n
\t\t\t\t\t\t$(\'#image_save_opts [value=embed]\').attr(\'disabled\',\'disabled\');\n
\t\t\t\t\t\t$(\'#image_save_opts input\').val([\'ref\']);\n
\t\t\t\t\t\tcurPrefs.img_save = \'ref\';\n
\t\t\t\t\t\t$(\'#image_opt_embed\').css(\'color\',\'#666\').attr(\'title\',uiStrings.featNotSupported);\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t},1000);\n
\t\t\t\t\n
\t\t\t$(\'#fill_color, #tool_fill .icon_label\').click(function(){\n
\t\t\t\tcolorPicker($(\'#fill_color\'));\n
\t\t\t\tupdateToolButtonState();\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#stroke_color, #tool_stroke .icon_label\').click(function(){\n
\t\t\t\tcolorPicker($(\'#stroke_color\'));\n
\t\t\t\tupdateToolButtonState();\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#group_opacityLabel\').click(function() {\n
\t\t\t\t$(\'#opacity_dropdown button\').mousedown();\n
\t\t\t\t$(window).mouseup();\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#zoomLabel\').click(function() {\n
\t\t\t\t$(\'#zoom_dropdown button\').mousedown();\n
\t\t\t\t$(window).mouseup();\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#tool_move_top\').mousedown(function(evt){\n
\t\t\t\t$(\'#tools_stacking\').show();\n
\t\t\t\tevt.preventDefault();\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'.layer_button\').mousedown(function() { \n
\t\t\t\t$(this).addClass(\'layer_buttonpressed\');\n
\t\t\t}).mouseout(function() {\n
\t\t\t\t$(this).removeClass(\'layer_buttonpressed\');\n
\t\t\t}).mouseup(function() {\n
\t\t\t\t$(this).removeClass(\'layer_buttonpressed\');\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'.push_button\').mousedown(function() { \n
\t\t\t\tif (!$(this).hasClass(\'disabled\')) {\n
\t\t\t\t\t$(this).addClass(\'push_button_pressed\').removeClass(\'push_button\');\n
\t\t\t\t}\n
\t\t\t}).mouseout(function() {\n
\t\t\t\t$(this).removeClass(\'push_button_pressed\').addClass(\'push_button\');\n
\t\t\t}).mouseup(function() {\n
\t\t\t\t$(this).removeClass(\'push_button_pressed\').addClass(\'push_button\');\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#layer_new\').click(function() {\n
\t\t\t\tvar curNames = new Array(svgCanvas.getNumLayers());\n
\t\t\t\tfor (var i = 0; i < curNames.length; ++i) { curNames[i] = svgCanvas.getLayer(i); }\n
\t\t\t\t\n
\t\t\t\tvar j = (curNames.length+1);\n
\t\t\t\tvar uniqName = uiStrings.layer + " " + j;\n
\t\t\t\twhile ($.inArray(uniqName, curNames) != -1) {\n
\t\t\t\t\tj++;\n
\t\t\t\t\tuniqName = uiStrings.layer + " " + j;\n
\t\t\t\t}\n
\t\t\t\t$.prompt(uiStrings.enterUniqueLayerName,uniqName, function(newName) {\n
\t\t\t\t\tif (!newName) return;\n
\t\t\t\t\tif ($.inArray(newName, curNames) != -1) {\n
\t\t\t\t\t\t$.alert(uiStrings.dupeLayerName);\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\tsvgCanvas.createLayer(newName);\n
\t\t\t\t\tupdateContextPanel();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t$(\'#layerlist tr.layer:first\').addClass("layersel");\n
\t\t\t\t});\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#layer_delete\').click(function() {\n
\t\t\t\tif (svgCanvas.deleteCurrentLayer()) {\n
\t\t\t\t\tupdateContextPanel();\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t// This matches what SvgCanvas does\n
\t\t\t\t\t// TODO: make this behavior less brittle (svg-editor should get which\n
\t\t\t\t\t// layer is selected from the canvas and then select that one in the UI)\n
\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t$(\'#layerlist tr.layer:first\').addClass("layersel");\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#layer_up\').click(function() {\n
\t\t\t\t// find index position of selected option\n
\t\t\t\tvar curIndex = $(\'#layerlist tr.layersel\').prevAll().length;\n
\t\t\t\tif (curIndex > 0) {\n
\t\t\t\t\tvar total = $(\'#layerlist tr.layer\').length;\n
\t\t\t\t\tcurIndex--;\n
\t\t\t\t\tsvgCanvas.setCurrentLayerPosition(total-curIndex-1);\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t$(\'#layerlist tr.layer:eq(\'+curIndex+\')\').addClass("layersel");\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#layer_down\').click(function() {\n
\t\t\t\t// find index position of selected option\n
\t\t\t\tvar curIndex = $(\'#layerlist tr.layersel\').prevAll().length;\n
\t\t\t\tvar total = $(\'#layerlist tr.layer\').length;\n
\t\t\t\tif (curIndex < total-1) {\n
\t\t\t\t\tcurIndex++;\n
\t\t\t\t\tsvgCanvas.setCurrentLayerPosition(total-curIndex-1);\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t$(\'#layerlist tr.layer:eq(\'+curIndex+\')\').addClass("layersel");\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\n
\t\t\t$(\'#layer_rename\').click(function() {\n
\t\t\t\tvar curIndex = $(\'#layerlist tr.layersel\').prevAll().length;\n
\t\t\t\tvar oldName = $(\'#layerlist tr.layersel td.layername\').text();\n
\t\t\t\t$.prompt(uiStrings.enterNewLayerName,"", function(newName) {\n
\t\t\t\t\tif (!newName) return;\n
\t\t\t\t\tif (oldName == newName) {\n
\t\t\t\t\t\t$.alert(uiStrings.layerHasThatName);\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\n
\t\t\t\t\tvar curNames = new Array(svgCanvas.getNumLayers());\n
\t\t\t\t\tfor (var i = 0; i < curNames.length; ++i) { curNames[i] = svgCanvas.getLayer(i); }\n
\t\t\t\t\tif ($.inArray(newName, curNames) != -1) {\n
\t\t\t\t\t\t$.alert(uiStrings.layerHasThatName);\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tsvgCanvas.renameCurrentLayer(newName);\n
\t\t\t\t\tpopulateLayers();\n
\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t$(\'#layerlist tr.layer:eq(\'+curIndex+\')\').addClass("layersel");\n
\t\t\t\t});\n
\t\t\t});\n
\t\t\t\n
\t\t\tvar SIDEPANEL_MAXWIDTH = 300;\n
\t\t\tvar SIDEPANEL_OPENWIDTH = 150;\n
\t\t\tvar sidedrag = -1, sidedragging = false, allowmove = false;\n
\t\t\t\t\n
\t\t\tvar resizePanel = function(evt) {\n
\t\t\t\tif (!allowmove) return;\n
\t\t\t\tif (sidedrag == -1) return;\n
\t\t\t\tsidedragging = true;\n
\t\t\t\tvar deltax = sidedrag - evt.pageX;\n
\t\t\t\t\n
\t\t\t\tvar sidepanels = $(\'#sidepanels\');\n
\t\t\t\tvar sidewidth = parseInt(sidepanels.css(\'width\'));\n
\t\t\t\tif (sidewidth+deltax > SIDEPANEL_MAXWIDTH) {\n
\t\t\t\t\tdeltax = SIDEPANEL_MAXWIDTH - sidewidth;\n
\t\t\t\t\tsidewidth = SIDEPANEL_MAXWIDTH;\n
\t\t\t\t}\n
\t\t\t\telse if (sidewidth+deltax < 2) {\n
\t\t\t\t\tdeltax = 2 - sidewidth;\n
\t\t\t\t\tsidewidth = 2;\n
\t\t\t\t}\n
\t\n
\t\t\t\tif (deltax == 0) return;\n
\t\t\t\tsidedrag -= deltax;\n
\t\n
\t\t\t\tvar layerpanel = $(\'#layerpanel\');\n
\t\t\t\tworkarea.css(\'right\', parseInt(workarea.css(\'right\'))+deltax);\n
\t\t\t\tsidepanels.css(\'width\', parseInt(sidepanels.css(\'width\'))+deltax);\n
\t\t\t\tlayerpanel.css(\'width\', parseInt(layerpanel.css(\'width\'))+deltax);\n
\t\t\t}\n
\t\t\t\n
\t\t\t$(\'#sidepanel_handle\')\n
\t\t\t\t.mousedown(function(evt) {\n
\t\t\t\t\tsidedrag = evt.pageX;\n
\t\t\t\t\t$(window).mousemove(resizePanel);\n
\t\t\t\t\tallowmove = false;\n
\t\t\t\t\t// Silly hack for Chrome, which always runs mousemove right after mousedown\n
\t\t\t\t\tsetTimeout(function() {\n
\t\t\t\t\t\tallowmove = true;\n
\t\t\t\t\t}, 20);\n
\t\t\t\t})\n
\t\t\t\t.mouseup(function(evt) {\n
\t\t\t\t\tif (!sidedragging) toggleSidePanel();\n
\t\t\t\t\tsidedrag = -1;\n
\t\t\t\t\tsidedragging = false;\n
\t\t\t\t});\n
\n
\t\t\t$(window).mouseup(function() {\n
\t\t\t\tsidedrag = -1;\n
\t\t\t\tsidedragging = false;\n
\t\t\t\t$(\'#svg_editor\').unbind(\'mousemove\', resizePanel);\n
\t\t\t});\n
\t\t\t\n
\t\t\t// if width is non-zero, then fully close it, otherwise fully open it\n
\t\t\t// the optional close argument forces the side panel closed\n
\t\t\tvar toggleSidePanel = function(close){\n
\t\t\t\tvar w = parseInt($(\'#sidepanels\').css(\'width\'));\n
\t\t\t\tvar deltax = (w > 2 || close ? 2 : SIDEPANEL_OPENWIDTH) - w;\n
\t\t\t\tvar sidepanels = $(\'#sidepanels\');\n
\t\t\t\tvar layerpanel = $(\'#layerpanel\');\n
\t\t\t\tworkarea.css(\'right\', parseInt(workarea.css(\'right\'))+deltax);\n
\t\t\t\tsidepanels.css(\'width\', parseInt(sidepanels.css(\'width\'))+deltax);\n
\t\t\t\tlayerpanel.css(\'width\', parseInt(layerpanel.css(\'width\'))+deltax);\n
\t\t\t};\n
\t\t\t\n
\t\t\t// this function highlights the layer passed in (by fading out the other layers)\n
\t\t\t// if no layer is passed in, this function restores the other layers\n
\t\t\tvar toggleHighlightLayer = function(layerNameToHighlight) {\n
\t\t\t\tvar curNames = new Array(svgCanvas.getNumLayers());\n
\t\t\t\tfor (var i = 0; i < curNames.length; ++i) { curNames[i] = svgCanvas.getLayer(i); }\n
\t\t\t\n
\t\t\t\tif (layerNameToHighlight) {\n
\t\t\t\t\tfor (var i = 0; i < curNames.length; ++i) {\n
\t\t\t\t\t\tif (curNames[i] != layerNameToHighlight) {\n
\t\t\t\t\t\t\tsvgCanvas.setLayerOpacity(curNames[i], 0.5);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\telse {\n
\t\t\t\t\tfor (var i = 0; i < curNames.length; ++i) {\n
\t\t\t\t\t\tsvgCanvas.setLayerOpacity(curNames[i], 1.0);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\n
\t\t\tvar populateLayers = function(){\n
\t\t\t\tvar layerlist = $(\'#layerlist tbody\');\n
\t\t\t\tvar selLayerNames = $(\'#selLayerNames\');\n
\t\t\t\tlayerlist.empty();\n
\t\t\t\tselLayerNames.empty();\n
\t\t\t\tvar currentlayer = svgCanvas.getCurrentLayer();\n
\t\t\t\tvar layer = svgCanvas.getNumLayers();\n
\t\t\t\tvar icon = $.getSvgIcon(\'eye\');\n
\t\t\t\t// we get the layers in the reverse z-order (the layer rendered on top is listed first)\n
\t\t\t\twhile (layer--) {\n
\t\t\t\t\tvar name = svgCanvas.getLayer(layer);\n
\t\t\t\t\t// contenteditable=\\"true\\"\n
\t\t\t\t\tvar appendstr = "<tr class=\\"layer";\n
\t\t\t\t\tif (name == currentlayer) {\n
\t\t\t\t\t\tappendstr += " layersel"\n
\t\t\t\t\t}\n
\t\t\t\t\tappendstr += "\\">";\n
\t\t\t\t\t\n
\t\t\t\t\tif (svgCanvas.getLayerVisibility(name)) {\n
\t\t\t\t\t\tappendstr += "<td class=\\"layervis\\"/><td class=\\"layername\\" >" + name + "</td></tr>";\n
\t\t\t\t\t}\n
\t\t\t\t\telse {\n
\t\t\t\t\t\tappendstr += "<td class=\\"layervis layerinvis\\"/><td class=\\"layername\\" >" + name + "</td></tr>";\n
\t\t\t\t\t}\n
\t\t\t\t\tlayerlist.append(appendstr);\n
\t\t\t\t\tselLayerNames.append("<option value=\\"" + name + "\\">" + name + "</option>");\n
\t\t\t\t}\n
\t\t\t\tif(icon !== undefined) {\n
\t\t\t\t\tvar copy = icon.clone();\n
\t\t\t\t\t$(\'td.layervis\',layerlist).append(icon.clone());\n
\t\t\t\t\t$.resizeSvgIcons({\'td.layervis .svg_icon\':14});\n
\t\t\t\t}\n
\t\t\t\t// handle selection of layer\n
\t\t\t\t$(\'#layerlist td.layername\')\n
\t\t\t\t\t.click(function(evt){\n
\t\t\t\t\t\t$(\'#layerlist tr.layer\').removeClass("layersel");\n
\t\t\t\t\t\tvar row = $(this.parentNode);\n
\t\t\t\t\t\trow.addClass("layersel");\n
\t\t\t\t\t\tsvgCanvas.setCurrentLayer(this.textContent);\n
\t\t\t\t\t\tevt.preventDefault();\n
\t\t\t\t\t})\n
\t\t\t\t\t.mouseover(function(evt){\n
\t\t\t\t\t\t$(this).css({"font-style": "italic", "color":"blue"});\n
\t\t\t\t\t\ttoggleHighlightLayer(this.textContent);\n
\t\t\t\t\t})\n
\t\t\t\t\t.mouseout(function(evt){\n
\t\t\t\t\t\t$(this).css({"font-style": "normal", "color":"black"});\n
\t\t\t\t\t\ttoggleHighlightLayer();\n
\t\t\t\t\t});\n
\t\t\t\t$(\'#layerlist td.layervis\').click(function(evt){\n
\t\t\t\t\tvar row = $(this.parentNode).prevAll().length;\n
\t\t\t\t\tvar name = $(\'#layerlist tr.layer:eq(\' + row + \') td.layername\').text();\n
\t\t\t\t\tvar vis = $(this).hasClass(\'layerinvis\');\n
\t\t\t\t\tsvgCanvas.setLayerVisibility(name, vis);\n
\t\t\t\t\tif (vis) {\n
\t\t\t\t\t\t$(this).removeClass(\'layerinvis\');\n
\t\t\t\t\t}\n
\t\t\t\t\telse {\n
\t\t\t\t\t\t$(this).addClass(\'layerinvis\');\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t\n
\t\t\t\t// if there were too few rows, let\'s add a few to make it not so lonely\n
\t\t\t\tvar num = 5 - $(\'#layerlist tr.layer\').size();\n
\t\t\t\twhile (num-- > 0) {\n
\t\t\t\t\t// FIXME: there must a better way to do this\n
\t\t\t\t\tlayerlist.append("<tr><td style=\\"color:white\\">_</td><td/></tr>");\n
\t\t\t\t}\n
\t\t\t};\n
\t\t\tpopulateLayers();\n
\t\t\n
\t\t// \tfunction changeResolution(x,y) {\n
\t\t// \t\tvar zoom = svgCanvas.getResolution().zoom;\n
\t\t// \t\tsetResolution(x * zoom, y * zoom);\n
\t\t// \t}\n
\t\t\t\n
\t\t\tvar centerCanvas = function() {\n
\t\t\t\t// this centers the canvas vertically in the workarea (horizontal handled in CSS)\n
\t\t\t\tworkarea.css(\'line-height\', workarea.height() + \'px\');\n
\t\t\t};\n
\t\t\t\n
\t\t\t$(window).bind(\'load resize\', centerCanvas);\n
\t\t\n
\t\t\tfunction stepFontSize(elem, step) {\n
\t\t\t\tvar orig_val = elem.value-0;\n
\t\t\t\tvar sug_val = orig_val + step;\n
\t\t\t\tvar increasing = sug_val >= orig_val;\n
\t\t\t\tif(step === 0) return orig_val;\n
\t\t\t\t\n
\t\t\t\tif(orig_val >= 24) {\n
\t\t\t\t\tif(increasing) {\n
\t\t\t\t\t\treturn Math.round(orig_val * 1.1);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn Math.round(orig_val / 1.1);\n
\t\t\t\t\t}\n
\t\t\t\t} else if(orig_val <= 1) {\n
\t\t\t\t\tif(increasing) {\n
\t\t\t\t\t\treturn orig_val * 2;\t\t\t\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn orig_val / 2;\n
\t\t\t\t\t}\n
\t\t\t\t} else {\n
\t\t\t\t\treturn sug_val;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t\tfunction stepZoom(elem, step) {\n
\t\t\t\tvar orig_val = elem.value-0;\n
\t\t\t\tif(orig_val === 0) return 100;\n
\t\t\t\tvar sug_val = orig_val + step;\n
\t\t\t\tif(step === 0) return orig_val;\n
\t\t\t\t\n
\t\t\t\tif(orig_val >= 100) {\n
\t\t\t\t\treturn sug_val;\n
\t\t\t\t} else {\n
\t\t\t\t\tif(sug_val >= orig_val) {\n
\t\t\t\t\t\treturn orig_val * 2;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\treturn orig_val / 2;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t\n
\t\t// \tfunction setResolution(w, h, center) {\n
\t\t// \t\tupdateCanvas();\n
\t\t// // \t\tw-=0; h-=0;\n
\t\t// // \t\t$(\'#svgcanvas\').css( { \'width\': w, \'height\': h } );\n
\t\t// // \t\t$(\'#canvas_width\').val(w);\n
\t\t// // \t\t$(\'#canvas_height\').val(h);\n
\t\t// // \n
\t\t// // \t\tif(center) {\n
\t\t// // \t\t\tvar w_area = workarea;\n
\t\t// // \t\t\tvar scroll_y = h/2 - w_area.height()/2;\n
\t\t// // \t\t\tvar scroll_x = w/2 - w_area.width()/2;\n
\t\t// // \t\t\tw_area[0].scrollTop = scroll_y;\n
\t\t// // \t\t\tw_area[0].scrollLeft = scroll_x;\n
\t\t// // \t\t}\n
\t\t// \t}\n
\t\t\n
\t\t\t$(\'#resolution\').change(function(){\n
\t\t\t\tvar wh = $(\'#canvas_width,#canvas_height\');\n
\t\t\t\tif(!this.selectedIndex) {\n
\t\t\t\t\tif($(\'#canvas_width\').val() == \'fit\') {\n
\t\t\t\t\t\twh.removeAttr("disabled").val(100);\n
\t\t\t\t\t}\n
\t\t\t\t} else if(this.value == \'content\') {\n
\t\t\t\t\twh.val(\'fit\').attr("disabled","disabled");\n
\t\t\t\t} else {\n
\t\t\t\t\tvar dims = this.value.split(\'x\');\n
\t\t\t\t\t$(\'#canvas_width\').val(dims[0]);\n
\t\t\t\t\t$(\'#canvas_height\').val(dims[1]);\n
\t\t\t\t\twh.removeAttr("disabled");\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\n
\t\t\t//Prevent browser from erroneously repopulating fields\n
\t\t\t$(\'input,select\').attr("autocomplete","off");\n
\t\t\t\n
\t\t\t// Associate all button actions as well as non-button keyboard shortcuts\n
\t\t\tvar Actions = function() {\n
\t\t\t\t// sel:\'selector\', fn:function, evt:\'event\', key:[key, preventDefault, NoDisableInInput]\n
\t\t\t\tvar tool_buttons = [\n
\t\t\t\t\t{sel:\'#tool_select\', fn: clickSelect, evt: \'click\', key: 1},\n
\t\t\t\t\t{sel:\'#tool_fhpath\', fn: clickFHPath, evt: \'click\', key: 2},\n
\t\t\t\t\t{sel:\'#tool_line\', fn: clickLine, evt: \'click\', key: 3},\n
\t\t\t\t\t{sel:\'#tool_rect\', fn: clickRect, evt: \'mouseup\', key: 4, parent: \'#tools_rect\', icon: \'rect\'},\n
\t\t\t\t\t{sel:\'#tool_square\', fn: clickSquare, evt: \'mouseup\', key: \'Shift+4\', parent: \'#tools_rect\', icon: \'square\'},\n
\t\t\t\t\t{sel:\'#tool_fhrect\', fn: clickFHRect, evt: \'mouseup\', parent: \'#tools_rect\', icon: \'fh_rect\'},\n
\t\t\t\t\t{sel:\'#tool_ellipse\', fn: clickEllipse, evt: \'mouseup\', key: 5, parent: \'#tools_ellipse\', icon: \'ellipse\'},\n
\t\t\t\t\t{sel:\'#tool_circle\', fn: clickCircle, evt: \'mouseup\', key: \'Shift+5\', parent: \'#tools_ellipse\', icon: \'circle\'},\n
\t\t\t\t\t{sel:\'#tool_fhellipse\', fn: clickFHEllipse, evt: \'mouseup\', parent: \'#tools_ellipse\', icon: \'fh_ellipse\'},\n
\t\t\t\t\t{sel:\'#tool_path\', fn: clickPath, evt: \'click\', key: 6},\n
\t\t\t\t\t{sel:\'#tool_text\', fn: clickText, evt: \'click\', key: 7},\n
\t\t\t\t\t{sel:\'#tool_image\', fn: clickImage, evt: \'mouseup\', key: 8},\n
\t\t\t\t\t{sel:\'#tool_zoom\', fn: clickZoom, evt: \'mouseup\', key: 9},\n
\t\t\t\t\t{sel:\'#tool_clear\', fn: clickClear, evt: \'mouseup\', key: [modKey+\'N\', true]},\n
\t\t\t\t\t{sel:\'#tool_save\', fn: function() { editingsource?saveSourceEditor():clickSave()}, evt: \'mouseup\', key: [modKey+\'S\', true]},\n
\t\t\t\t\t{sel:\'#tool_export\', fn: clickExport, evt: \'mouseup\'},\n
\t\t\t\t\t{sel:\'#tool_open\', fn: clickOpen, evt: \'mouseup\', key: [modKey+\'O\', true]},\n
\t\t\t\t\t{sel:\'#tool_import\', fn: clickImport, evt: \'mouseup\'},\n
\t\t\t\t\t{sel:\'#tool_source\', fn: showSourceEditor, evt: \'click\', key: [\'U\', true]},\n
\t\t\t\t\t{sel:\'#tool_wireframe\', fn: clickWireframe, evt: \'click\', key: [\'F\', true]},\n
\t\t\t\t\t{sel:\'#tool_source_cancel,#svg_source_overlay,#tool_docprops_cancel\', fn: cancelOverlays, evt: \'click\', key: [\'esc\', false, false], hidekey: true},\n
\t\t\t\t\t{sel:\'#tool_source_save\', fn: saveSourceEditor, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_docprops_save\', fn: saveDocProperties, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_docprops\', fn: showDocProperties, evt: \'mouseup\', key: [modKey+\'P\', true]},\n
\t\t\t\t\t{sel:\'#tool_delete,#tool_delete_multi\', fn: deleteSelected, evt: \'click\', key: [\'del/backspace\', true]},\n
\t\t\t\t\t{sel:\'#tool_reorient\', fn: reorientPath, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_node_link\', fn: linkControlPoints, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_node_clone\', fn: clonePathNode, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_node_delete\', fn: deletePathNode, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_openclose_path\', fn: opencloseSubPath, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_add_subpath\', fn: addSubPath, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_move_top\', fn: moveToTopSelected, evt: \'click\', key: \'shift+up\'},\n
\t\t\t\t\t{sel:\'#tool_move_bottom\', fn: moveToBottomSelected, evt: \'click\', key: \'shift+down\'},\n
\t\t\t\t\t{sel:\'#tool_topath\', fn: convertToPath, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_undo\', fn: clickUndo, evt: \'click\', key: [modKey+\'Z\', true]},\n
\t\t\t\t\t{sel:\'#tool_redo\', fn: clickRedo, evt: \'click\', key: [modKey+\'Y\', true]},\n
\t\t\t\t\t{sel:\'#tool_clone,#tool_clone_multi\', fn: clickClone, evt: \'click\', key: [modKey+\'C\', true]},\n
\t\t\t\t\t{sel:\'#tool_group\', fn: clickGroup, evt: \'click\', key: [modKey+\'G\', true]},\n
\t\t\t\t\t{sel:\'#tool_ungroup\', fn: clickGroup, evt: \'click\'},\n
\t\t\t\t\t{sel:\'[id^=tool_align]\', fn: clickAlign, evt: \'click\'},\n
\t\t\t\t\t// these two lines are required to make Opera work properly with the flyout mechanism\n
\t\t// \t\t\t{sel:\'#tools_rect_show\', fn: clickRect, evt: \'click\'},\n
\t\t// \t\t\t{sel:\'#tools_ellipse_show\', fn: clickEllipse, evt: \'click\'},\n
\t\t\t\t\t{sel:\'#tool_bold\', fn: clickBold, evt: \'mousedown\'},\n
\t\t\t\t\t{sel:\'#tool_italic\', fn: clickItalic, evt: \'mousedown\'},\n
\t\t\t\t\t{sel:\'#sidepanel_handle\', fn: toggleSidePanel, key: [modKey+\'X\']},\n
\t\t\t\t\t\n
\t\t\t\t\t// Shortcuts not associated with buttons\n
\t\t\t\t\t{key: \'shift+left\', fn: function(){rotateSelected(0)}},\n
\t\t\t\t\t{key: \'shift+right\', fn: function(){rotateSelected(1)}},\n
\t\t\t\t\t{key: \'shift+O\', fn: selectPrev},\n
\t\t\t\t\t{key: \'shift+P\', fn: selectNext},\n
\t\t\t\t\t{key: [\'ctrl+up\', true], fn: function(){zoomImage(2);}},\n
\t\t\t\t\t{key: [\'ctrl+down\', true], fn: function(){zoomImage(.5);}},\n
\t\t\t\t\t{key: [\'up\', true], fn: function(){moveSelected(0,-1);}},\n
\t\t\t\t\t{key: [\'down\', true], fn: function(){moveSelected(0,1);}},\n
\t\t\t\t\t{key: [\'left\', true], fn: function(){moveSelected(-1,0);}},\n
\t\t\t\t\t{key: [\'right\', true], fn: function(){moveSelected(1,0);}},\n
\t\t\t\t\t{key: \'A\', fn: function(){svgCanvas.selectAllInCurrentLayer();}}\n
\t\t\t\t];\n
\t\t\t\t\n
\t\t\t\t// Tooltips not directly associated with a single function\n
\t\t\t\tvar key_assocs = {\n
\t\t\t\t\t\'4/Shift+4\': \'#tools_rect_show\',\n
\t\t\t\t\t\'5/Shift+5\': \'#tools_ellipse_show\'\n
\t\t\t\t};\n
\t\t\t\n
\t\t\t\treturn {\n
\t\t\t\t\tsetAll: function() {\n
\t\t\t\t\t\tvar flyouts = {};\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t$.each(tool_buttons, function(i, opts)  {\n
\t\t\t\t\t\t\t// Bind function to button\n
\t\t\t\t\t\t\tif(opts.sel) {\n
\t\t\t\t\t\t\t\tvar btn = $(opts.sel);\n
\t\t\t\t\t\t\t\tif(opts.evt) {\n
\t\t\t\t\t\t\t\t\tbtn[opts.evt](opts.fn);\n
\t\t\t\t\t\t\t\t}\n
\t\t\n
\t\t\t\t\t\t\t\t// Add to parent flyout menu\n
\t\t\t\t\t\t\t\tif(opts.parent) {\n
\t\t\t\t\t\t\t\t\tvar f_h = $(opts.parent);\n
\t\t\t\t\t\t\t\t\tif(!f_h.length) {\n
\t\t\t\t\t\t\t\t\t\tf_h = makeFlyoutHolder(opts.parent.substr(1));\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t\tf_h.append(btn);\n
\t\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t\tif(!$.isArray(flyouts[opts.parent])) {\n
\t\t\t\t\t\t\t\t\t\tflyouts[opts.parent] = [];\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\tflyouts[opts.parent].push(opts);\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t// Bind function to shortcut key\n
\t\t\t\t\t\t\tif(opts.key) {\n
\t\t\t\t\t\t\t\t// Set shortcut based on options\n
\t\t\t\t\t\t\t\tvar keyval, shortcut = \'\', disInInp = true, fn = opts.fn, pd = false;\n
\t\t\t\t\t\t\t\tif($.isArray(opts.key)) {\n
\t\t\t\t\t\t\t\t\tkeyval = opts.key[0];\n
\t\t\t\t\t\t\t\t\tif(opts.key.length > 1) pd = opts.key[1];\n
\t\t\t\t\t\t\t\t\tif(opts.key.length > 2) disInInp = opts.key[2];\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tkeyval = opts.key;\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tkeyval += \'\';\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t$.each(keyval.split(\'/\'), function(i, key) {\n
\t\t\t\t\t\t\t\t\t$(document).bind(\'keydown\', key, function(e) {\n
\t\t\t\t\t\t\t\t\t\tfn();\n
\t\t\t\t\t\t\t\t\t\tif(pd) {\n
\t\t\t\t\t\t\t\t\t\t\te.preventDefault();\n
\t\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\t\t// Prevent default on ALL keys?\n
\t\t\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t// Put shortcut in title\n
\t\t\t\t\t\t\t\tif(opts.sel && !opts.hidekey) {\n
\t\t\t\t\t\t\t\t\tvar new_title = btn.attr(\'title\').split(\'[\')[0] + \'[\' + keyval + \']\';\n
\t\t\t\t\t\t\t\t\tkey_assocs[keyval] = opts.sel;\n
\t\t\t\t\t\t\t\t\t// Disregard for menu items\n
\t\t\t\t\t\t\t\t\tif(!btn.parents(\'#main_menu\').length) {\n
\t\t\t\t\t\t\t\t\t\tbtn.attr(\'title\', new_title);\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Setup flyouts\n
\t\t\t\t\t\tsetupFlyouts(flyouts);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Misc additional actions\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t// Make "return" keypress trigger the change event\n
\t\t\t\t\t\t$(\'.attr_changer, #image_url\').bind(\'keydown\', \'return\', \n
\t\t\t\t\t\t\tfunction(evt) {$(this).change();evt.preventDefault();}\n
\t\t\t\t\t\t);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t$(\'#tool_zoom\').dblclick(dblclickZoom);\n
\t\t\t\t\t},\n
\t\t\t\t\tsetTitles: function() {\n
\t\t\t\t\t\t$.each(key_assocs, function(keyval, sel)  {\n
\t\t\t\t\t\t\tvar menu = ($(sel).parents(\'#main_menu\').length);\n
\t\t\t\t\t\t\n
\t\t\t\t\t\t\t$(sel).each(function() {\n
\t\t\t\t\t\t\t\tif(menu) {\n
\t\t\t\t\t\t\t\t\tvar t = $(this).text().split(\' [\')[0];\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tvar t = this.title.split(\' [\')[0];\t\t\t\t\t\t\t\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\tvar key_str = \'\';\n
\t\t\t\t\t\t\t\t// Shift+Up\n
\t\t\t\t\t\t\t\t$.each(keyval.split(\'/\'), function(i, key) {\n
\t\t\t\t\t\t\t\t\tvar mod_bits = key.split(\'+\'), mod = \'\';\n
\t\t\t\t\t\t\t\t\tif(mod_bits.length > 1) {\n
\t\t\t\t\t\t\t\t\t\tmod = mod_bits[0] + \'+\';\n
\t\t\t\t\t\t\t\t\t\tkey = mod_bits[1];\n
\t\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t\t\tkey_str += (i?\'/\':\'\') + mod + (uiStrings[\'key_\'+key] || key);\n
\t\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t\t\tif(menu) {\n
\t\t\t\t\t\t\t\t\tthis.lastChild.textContent = t +\' [\'+key_str+\']\';\n
\t\t\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t\t\tthis.title = t +\' [\'+key_str+\']\';\n
\t\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t\t});\n
\t\t\t\t\t\t});\n
\t\t\t\t\t},\n
\t\t\t\t\tgetButtonData: function(sel) {\n
\t\t\t\t\t\tvar b;\n
\t\t\t\t\t\t$.each(tool_buttons, function(i, btn) {\n
\t\t\t\t\t\t\tif(btn.sel === sel) b = btn;\n
\t\t\t\t\t\t});\n
\t\t\t\t\t\treturn b;\n
\t\t\t\t\t}\n
\t\t\t\t};\n
\t\t\t}();\n
\t\t\t\n
\t\t\tActions.setAll();\n
\t\t\t\n
\t\t\t// Select given tool\n
\t\t\tEditor.ready(function() {\n
\t\t\t\tvar itool = curConfig.initTool,\n
\t\t\t\t\tcontainer = $("#tools_left, #svg_editor .tools_flyout"),\n
\t\t\t\t\tpre_tool = container.find("#tool_" + itool),\n
\t\t\t\t\treg_tool = container.find("#" + itool);\n
\t\t\t\tif(pre_tool.length) {\n
\t\t\t\t\ttool = pre_tool;\n
\t\t\t\t} else if(reg_tool.length){\n
\t\t\t\t\ttool = reg_tool;\n
\t\t\t\t} else {\n
\t\t\t\t\ttool = $("#tool_select");\n
\t\t\t\t}\n
\t\t\t\ttool.click().mouseup();\n
\t\t\t\t\n
\t\t\t\tif(curConfig.wireframe) {\n
\t\t\t\t\t$(\'#tool_wireframe\').click();\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(curConfig.showlayers) {\n
\t\t\t\t\ttoggleSidePanel();\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\t$(\'#rect_rx\').SpinButton({ min: 0, max: 1000, step: 1, callback: changeRectRadius });\n
\t\t\t$(\'#stroke_width\').SpinButton({ min: 0, max: 99, step: 1, smallStep: 0.1, callback: changeStrokeWidth });\n
\t\t\t$(\'#angle\').SpinButton({ min: -180, max: 180, step: 5, callback: changeRotationAngle });\n
\t\t\t$(\'#font_size\').SpinButton({ step: 1, min: 0.001, stepfunc: stepFontSize, callback: changeFontSize });\n
\t\t\t$(\'#group_opacity\').SpinButton({ step: 5, min: 0, max: 100, callback: changeOpacity });\n
\t\t\t$(\'#blur\').SpinButton({ step: .1, min: 0, max: 10, callback: changeBlur });\n
\t\t\t$(\'#zoom\').SpinButton({ min: 0.001, max: 10000, step: 50, stepfunc: stepZoom, callback: changeZoom });\n
\t\t\t\n
\t\t\twindow.onbeforeunload = function() { \n
\t\t\t\t// Suppress warning if page is empty \n
\t\t\t\tif(svgCanvas.getHistoryPosition() === 0) {\n
\t\t\t\t\tshow_save_warning = false;\n
\t\t\t\t}\n
\n
\t\t\t\t// show_save_warning is set to "false" when the page is saved.\n
\t\t\t\tif(!curConfig.no_save_warning && show_save_warning) {\n
\t\t\t\t\t// Browser already asks question about closing the page\n
\t\t\t\t\treturn "There are unsaved changes."; \n
\t\t\t\t}\n
\t\t\t};\n
\t\t\t\n
\t\t\t// use HTML5 File API: http://www.w3.org/TR/FileAPI/\n
\t\t\t// if browser has HTML5 File API support, then we will show the open menu item\n
\t\t\t// and provide a file input to click.  When that change event fires, it will\n
\t\t\t// get the text contents of the file and send it to the canvas\n
\t\t\tif (window.FileReader) {\n
\t\t\t\tvar inp = $(\'<input type="file">\').change(function() {\n
\t\t\t\t\tvar f = this;\n
\t\t\t\t\tvar openFile = function(ok) {\n
\t\t\t\t\t\tif(!ok) return;\n
\t\t\t\t\t\tsvgCanvas.clear();\n
\t\t\t\t\t\tif(f.files.length==1) {\n
\t\t\t\t\t\t\tvar reader = new FileReader();\n
\t\t\t\t\t\t\treader.onloadend = function(e) {\n
\t\t\t\t\t\t\t\tsvgCanvas.setSvgString(e.target.result);\n
\t\t\t\t\t\t\t\tupdateCanvas();\n
\t\t\t\t\t\t\t};\n
\t\t\t\t\t\t\treader.readAsText(f.files[0]);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t\t$(\'#main_menu\').hide();\n
\t\t\t\t\tif(svgCanvas.getHistoryPosition() === 0) {\n
\t\t\t\t\t\topenFile(true);\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\t$.confirm(uiStrings.QwantToOpen, openFile);\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t$("#tool_open").show().prepend(inp);\n
\t\t\t\tvar inp2 = $(\'<input type="file">\').change(function() {\n
\t\t\t\t\t$(\'#main_menu\').hide();\n
\t\t\t\t\tif(this.files.length==1) {\n
\t\t\t\t\t\tvar reader = new FileReader();\n
\t\t\t\t\t\treader.onloadend = function(e) {\n
\t\t\t\t\t\t\tsvgCanvas.importSvgString(e.target.result);\n
\t\t\t\t\t\t\tupdateCanvas();\n
\t\t\t\t\t\t};\n
\t\t\t\t\t\treader.readAsText(this.files[0]);\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t\t$("#tool_import").show().prepend(inp2);\n
\t\t\t}\n
\t\t\t\n
\t\t\t\n
\t\t\tvar updateCanvas = function(center, new_ctr) {\n
\t\t\t\tvar w = workarea.width(), h = workarea.height();\n
\t\t\t\tvar w_orig = w, h_orig = h;\n
\t\t\t\tvar zoom = svgCanvas.getZoom();\n
\t\t\t\tvar w_area = workarea;\n
\t\t\t\tvar cnvs = $("#svgcanvas");\n
\t\t\t\t\n
\t\t\t\tvar old_ctr = {\n
\t\t\t\t\tx: w_area[0].scrollLeft + w_orig/2,\n
\t\t\t\t\ty: w_area[0].scrollTop + h_orig/2\n
\t\t\t\t};\n
\t\t\t\t\n
\t\t\t\tvar multi = curConfig.canvas_expansion;\n
\t\t\t\tw = Math.max(w_orig, svgCanvas.contentW * zoom * multi);\n
\t\t\t\th = Math.max(h_orig, svgCanvas.contentH * zoom * multi);\n
\t\t\t\t\n
\t\t\t\tif(w == w_orig && h == h_orig) {\n
\t\t\t\t\tworkarea.css(\'overflow\',\'hidden\');\n
\t\t\t\t} else {\n
\t\t\t\t\tworkarea.css(\'overflow\',\'scroll\');\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tvar old_can_y = cnvs.height()/2;\n
\t\t\t\tvar old_can_x = cnvs.width()/2;\n
\t\t\t\tcnvs.width(w).height(h);\n
\t\t\t\tvar new_can_y = h/2;\n
\t\t\t\tvar new_can_x = w/2;\n
\t\t\t\tvar offset = svgCanvas.updateCanvas(w, h);\n
\t\t\t\t\n
\t\t\t\tvar ratio = new_can_x / old_can_x;\n
\t\t\n
\t\t\t\tvar scroll_x = w/2 - w_orig/2;\n
\t\t\t\tvar scroll_y = h/2 - h_orig/2;\n
\t\t\t\t\n
\t\t\t\tif(!new_ctr) {\n
\t\t\n
\t\t\t\t\tvar old_dist_x = old_ctr.x - old_can_x;\n
\t\t\t\t\tvar new_x = new_can_x + old_dist_x * ratio;\n
\t\t\n
\t\t\t\t\tvar old_dist_y = old_ctr.y - old_can_y;\n
\t\t\t\t\tvar new_y = new_can_y + old_dist_y * ratio;\n
\t\t\n
\t\t\t\t\tnew_ctr = {\n
\t\t\t\t\t\tx: new_x,\n
\t\t\t\t\t\ty: new_y\n
\t\t\t\t\t};\n
\t\t\t\t\t\n
\t\t\t\t} else {\n
\t\t\t\t\tnew_ctr.x += offset.x,\n
\t\t\t\t\tnew_ctr.y += offset.y;\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\tif(center) {\n
\t\t\t\t\tw_area[0].scrollLeft = scroll_x;\n
\t\t\t\t\tw_area[0].scrollTop = scroll_y;\n
\t\t\t\t} else {\n
\t\t\t\t\tw_area[0].scrollLeft = new_ctr.x - w_orig/2;\n
\t\t\t\t\tw_area[0].scrollTop = new_ctr.y - h_orig/2;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\n
// \t\t\t$(function() {\n
\t\t\t\tupdateCanvas(true);\n
// \t\t\t});\n
\t\t\t\n
\t\t//\tvar revnums = "svg-editor.js ($Rev: 1592 $) ";\n
\t\t//\trevnums += svgCanvas.getVersion();\n
\t\t//\t$(\'#copyright\')[0].setAttribute("title", revnums);\n
\t\t\n
\t\t\tvar good_langs = [];\n
\n
\t\t\t$(\'#lang_select option\').each(function() {\n
\t\t\t\tgood_langs.push(this.value);\n
\t\t\t});\n
\t\t\t\n
// \t\t\tvar lang = (\'lang\' in curPrefs) ? curPrefs.lang : null;\n
\t\t\tEditor.putLocale(null, good_langs);\n
\t\t\t\n
\t\t\ttry{\n
\t\t\t\tjson_encode = function(obj){\n
\t\t\t  //simple partial JSON encoder implementation\n
\t\t\t  if(window.JSON && JSON.stringify) return JSON.stringify(obj);\n
\t\t\t  var enc = arguments.callee; //for purposes of recursion\n
\t\t\t  if(typeof obj == "boolean" || typeof obj == "number"){\n
\t\t\t\t  return obj+\'\' //should work...\n
\t\t\t  }else if(typeof obj == "string"){\n
\t\t\t\t//a large portion of this is stolen from Douglas Crockford\'s json2.js\n
\t\t\t\treturn \'"\'+\n
\t\t\t\t\t  obj.replace(\n
\t\t\t\t\t\t/[\\\\\\"\\x00-\\x1f\\x7f-\\x9f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/g\n
\t\t\t\t\t  , function (a) {\n
\t\t\t\t\t\treturn \'\\\\u\' + (\'0000\' + a.charCodeAt(0).toString(16)).slice(-4);\n
\t\t\t\t\t  })\n
\t\t\t\t\t  +\'"\'; //note that this isn\'t quite as purtyful as the usualness\n
\t\t\t  }else if(obj.length){ //simple hackish test for arrayish-ness\n
\t\t\t\tfor(var i = 0; i < obj.length; i++){\n
\t\t\t\t  obj[i] = enc(obj[i]); //encode every sub-thingy on top\n
\t\t\t\t}\n
\t\t\t\treturn "["+obj.join(",")+"]";\n
\t\t\t  }else{\n
\t\t\t\tvar pairs = []; //pairs will be stored here\n
\t\t\t\tfor(var k in obj){ //loop through thingys\n
\t\t\t\t  pairs.push(enc(k)+":"+enc(obj[k])); //key: value\n
\t\t\t\t}\n
\t\t\t\treturn "{"+pairs.join(",")+"}" //wrap in the braces\n
\t\t\t  }\n
\t\t\t}\n
\t\t\t  window.addEventListener("message", function(e){\n
\t\t\t\tvar cbid = parseInt(e.data.substr(0, e.data.indexOf(";")));\n
\t\t\t\ttry{\n
\t\t\t\te.source.postMessage("SVGe"+cbid+";"+json_encode(eval(e.data)), e.origin);\n
\t\t\t  }catch(err){\n
\t\t\t\te.source.postMessage("SVGe"+cbid+";error:"+err.message, e.origin);\n
\t\t\t  }\n
\t\t\t}, false)\n
\t\t\t}catch(err){\n
\t\t\t  window.embed_error = err;\n
\t\t\t}\n
\t\t\t\n
\t\t\n
\t\t\n
\t\t\t// For Compatibility with older extensions\n
\t\t\t$(function() {\n
\t\t\t\twindow.svgCanvas = svgCanvas;\n
\t\t\t\tsvgCanvas.ready = svgEditor.ready;\n
\t\t\t});\n
\t\t\n
\t\t\n
\t\t\tEditor.setLang = function(lang, strings) {\n
\t\t\t\t$.pref(\'lang\', lang);\n
\t\t\t\t$(\'#lang_select\').val(lang);\n
\t\t\t\tif(strings) {\n
\t\t\t\t\t// $.extend will only replace the given strings\n
\t\t\t\t\tvar oldLayerName = $(\'#layerlist tr.layersel td.layername\').text();\n
\t\t\t\t\tvar rename_layer = (oldLayerName == uiStrings.layer + \' 1\');\n
\t\t\t\t\t\n
\t\t\t\t\t$.extend(uiStrings,strings);\n
\t\t\t\t\tsvgCanvas.setUiStrings(strings);\n
\t\t\t\t\tActions.setTitles();\n
\t\t\t\t\t\n
\t\t\t\t\tif(rename_layer) {\n
\t\t\t\t\t\tsvgCanvas.renameCurrentLayer(uiStrings.layer + \' 1\');\n
\t\t\t\t\t\tpopulateLayers();\t\t\t\t\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\tsvgCanvas.runExtensions("langChanged", lang);\n
\t\t\t\t\t\n
\t\t\t\t\t// Update flyout tooltips\n
\t\t\t\t\tsetFlyoutTitles();\n
\t\t\t\t\t\n
\t\t\t\t\t// Copy title for certain tool elements\n
\t\t\t\t\tvar elems = {\n
\t\t\t\t\t\t\'#stroke_color\': \'#tool_stroke .icon_label, #tool_stroke .color_block\',\n
\t\t\t\t\t\t\'#fill_color\': \'#tool_fill label, #tool_fill .color_block\',\n
\t\t\t\t\t\t\'#linejoin_miter\': \'#cur_linejoin\',\n
\t\t\t\t\t\t\'#linecap_butt\': \'#cur_linecap\'\n
\t\t\t\t\t}\n
\t\t\t\t\t\n
\t\t\t\t\t$.each(elems, function(source, dest) {\n
\t\t\t\t\t\t$(dest).attr(\'title\', $(source)[0].title);\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t\t// Copy alignment titles\n
\t\t\t\t\t$(\'#multiselected_panel div[id^=tool_align]\').each(function() {\n
\t\t\t\t\t\t$(\'#tool_pos\' + this.id.substr(10))[0].title = this.title;\n
\t\t\t\t\t});\n
\t\t\t\t\t\n
\t\t\t\t}\n
\t\t\t};\n
\t\t};\n
\t\t\n
\t\tvar callbacks = [];\n
\t\t\n
\t\tEditor.ready = function(cb) {\n
\t\t\tif(!is_ready) {\n
\t\t\t\tcallbacks.push(cb);\n
\t\t\t} else {\n
\t\t\t\tcb();\n
\t\t\t}\n
\t\t};\n
\n
\t\tEditor.runCallbacks = function() {\n
\t\t\t$.each(callbacks, function() {\n
\t\t\t\tthis();\n
\t\t\t});\n
\t\t\tis_ready = true;\n
\t\t};\n
\t\t\n
\t\tEditor.loadFromString = function(str) {\n
\t\t\tEditor.ready(function() {\n
\t\t\t\tsvgCanvas.setSvgString(str);\n
\t\t\t});\n
\t\t};\n
\t\t\n
\t\tEditor.loadFromURL = function(url) {\n
\t\t\tEditor.ready(function() {\n
\t\t\t\t$.ajax({\n
\t\t\t\t\t\'url\': url,\n
\t\t\t\t\t\'dataType\': \'text\',\n
\t\t\t\t\tsuccess: svgCanvas.setSvgString,\n
\t\t\t\t\terror: function(xhr, stat, err) {\n
\t\t\t\t\t\tif(xhr.responseText) {\n
\t\t\t\t\t\t\tsvgCanvas.setSvgString(xhr.responseText);\n
\t\t\t\t\t\t} else {\n
\t\t\t\t\t\t\t$.alert("Unable to load from URL. Error: \\n"+err+\'\');\n
\t\t\t\t\t\t}\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t});\n
\t\t};\n
\t\t\n
\t\tEditor.loadFromDataURI = function(str) {\n
\t\t\tEditor.ready(function() {\n
\t\t\t\tsvgCanvas.setSvgString(str);\n
\t\t\t\tvar pre = \'data:image/svg+xml;base64,\';\n
\t\t\t\tvar src = str.substring(pre.length);\n
\t\t\t\tsvgCanvas.setSvgString(Utils.decode64(src));\n
\t\t\t});\n
\t\t};\n
\t\t\n
\t\tEditor.addExtension = function() {\n
\t\t\tvar args = arguments;\n
\t\t\t$(function() {\n
\t\t\t\tsvgCanvas.addExtension.apply(this, args);\n
\t\t\t});\n
\t\t};\n
\n
\t\treturn Editor;\n
\t}(jQuery);\n
\t\n
\t// Run init once DOM is loaded\n
\t$(svgEditor.init);\n
\t\n
})();\n
\n
// ?iconsize=s&bkgd_color=555\n
\n
// svgEditor.setConfig({\n
// // \timgPath: \'foo\',\n
// \tdimensions: [800, 600],\n
// \tcanvas_expansion: 5,\n
// \tinitStroke: {\n
// \t\tcolor: \'0000FF\',\n
// \t\twidth: 3.5,\n
// \t\topacity: .5\n
// \t},\n
// \tinitFill: {\n
// \t\tcolor: \'550000\',\n
// \t\topacity: .75\n
// \t},\n
// \textensions: [\'ext-helloworld.js\']\n
// })\n


]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
