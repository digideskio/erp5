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
            <value> <string>ts52850521.6</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-server_opensave.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * ext-server_opensave.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 *\n
 */\n
\n
methodDraw.addExtension("server_opensave", {\n
  callback: function() {\n
\n
    //var save_svg_action = \'extensions/filesave.php\';\n
    //var save_png_action = \'extensions/filesave.php\';\n
  \n
    // Create upload target (hidden iframe)\n
    var target = $(\'<iframe name="output_frame" />\').hide().appendTo(\'body\');\n
  \n
    //methodDraw.setCustomHandlers({\n
    //  save: function(win, data) {\n
    //    var svg = "<?xml version=\\"1.0\\"?>\\n" + data;\n
    //    \n
    //    var title = svgCanvas.getDocumentTitle();\n
    //    var filename = title.replace(/[^a-z0-9\\.\\_\\-]+/gi, \'_\');\n
    //    \n
    //    var form = $(\'<form>\').attr({\n
    //      method: \'post\',\n
    //      action: save_svg_action,\n
    //      target: \'output_frame\'\n
    //    })  .append(\'<input type="hidden" name="output_svg" value="\' + encodeURI(svg) + \'">\')\n
    //      .append(\'<input type="hidden" name="filename" value="\' + filename + \'">\')\n
    //      .appendTo(\'body\')\n
    //      .submit().remove();\n
    //  },\n
    //  pngsave: function(win, data) {\n
    //    var issues = data.issues;\n
    //    \n
    //    if(!$(\'#export_canvas\').length) {\n
    //      $(\'<canvas>\', {id: \'export_canvas\'}).hide().appendTo(\'body\');\n
    //    }\n
    //    var c = $(\'#export_canvas\')[0];\n
    //    \n
    //    c.width = svgCanvas.contentW;\n
    //    c.height = svgCanvas.contentH;\n
    //    canvg(c, data.svg, {renderCallback: function() {\n
    //      var datauri = c.toDataURL(\'image/png\');\n
    //      \n
    //      var uiStrings = methodDraw.uiStrings;\n
    //      var note = \'\';\n
    //      \n
    //      // Check if there\'s issues\n
    //      if(issues.length) {\n
    //        var pre = "\\n \\u2022 ";\n
    //        note += ("\\n\\n" + pre + issues.join(pre));\n
    //      } \n
    //      \n
    //      if(note.length) {\n
    //        alert(note);\n
    //      }\n
    //      \n
    //      var title = svgCanvas.getDocumentTitle();\n
    //      var filename = title.replace(/[^a-z0-9\\.\\_\\-]+/gi, \'_\');\n
    //      \n
    //      var form = $(\'<form>\').attr({\n
    //        method: \'post\',\n
    //        action: save_png_action,\n
    //        target: \'output_frame\'\n
    //      })  .append(\'<input type="hidden" name="output_png" value="\' + datauri + \'">\')\n
    //        .append(\'<input type="hidden" name="filename" value="\' + filename + \'">\')\n
    //        .appendTo(\'body\')\n
    //        .submit().remove();\n
    //    }});\n
    //\n
    //    \n
    //  }\n
    //});\n
  \n
    // Do nothing if client support is found\n
    if(window.FileReader) return;\n
    \n
    var cancelled = false;\n
  \n
    // Change these to appropriate script file\n
    var open_svg_action = \'extensions/fileopen.php?type=load_svg\';\n
    var import_svg_action = \'extensions/fileopen.php?type=import_svg\';\n
    var import_img_action = \'extensions/fileopen.php?type=import_img\';\n
    \n
    // Set up function for PHP uploader to use\n
    methodDraw.processFile = function(str64, type) {\n
      if(cancelled) {\n
        cancelled = false;\n
        return;\n
      }\n
    \n
      $(\'#dialog_box\').hide();\n
    \n
      if(type != \'import_img\') {\n
        var xmlstr = svgCanvas.Utils.decode64(str64);\n
      }\n
      \n
      switch ( type ) {\n
        case \'load_svg\':\n
          svgCanvas.clear();\n
          svgCanvas.setSvgString(xmlstr);\n
          methodDraw.updateCanvas();\n
          break;\n
        case \'import_svg\':\n
          svgCanvas.importSvgString(xmlstr);\n
          methodDraw.updateCanvas();          \n
          break;\n
        case \'import_img\':\n
          svgCanvas.setGoodImage(str64);\n
          break;\n
      }\n
    }\n
  \n
    // Create upload form\n
    var open_svg_form = $(\'<form>\');\n
    open_svg_form.attr({\n
      enctype: \'multipart/form-data\',\n
      method: \'post\',\n
      action: open_svg_action,\n
      target: \'output_frame\'\n
    });\n
    \n
    // Create import form\n
    var import_svg_form = open_svg_form.clone().attr(\'action\', import_svg_action);\n
    \n
    // Create image form\n
    var import_img_form = open_svg_form.clone().attr(\'action\', import_img_action);\n
    \n
    // It appears necessory to rebuild this input every time a file is \n
    // selected so the same file can be picked and the change event can fire.\n
    function rebuildInput(form) {\n
      form.empty();\n
      var inp = $(\'<input type="file" name="svg_file">\').appendTo(form);\n
      \n
      \n
      function submit() {\n
        // This submits the form, which returns the file data using methodDraw.uploadSVG\n
        form.submit();\n
        \n
        rebuildInput(form);\n
        $.process_cancel("Uploading...", function() {\n
          cancelled = true;\n
          $(\'#dialog_box\').hide();\n
        });\n
      }\n
      \n
      if(form[0] == open_svg_form[0]) {\n
        inp.change(function() {\n
          // This takes care of the "are you sure" dialog box\n
          methodDraw.openPrep(function(ok) {\n
            if(!ok) {\n
              rebuildInput(form);\n
              return;\n
            }\n
            submit();\n
          });\n
        });\n
      } else {\n
        inp.change(function() {\n
          // This submits the form, which returns the file data using methodDraw.uploadSVG\n
          submit();\n
        });\n
      }\n
    }\n
    \n
    // Create the input elements\n
    rebuildInput(open_svg_form);\n
    rebuildInput(import_svg_form);\n
    rebuildInput(import_img_form);\n
\n
    // Add forms to buttons\n
    $("#tool_open").show().prepend(open_svg_form);\n
    $("#tool_import").show().prepend(import_svg_form);\n
    $("#tool_image").prepend(import_img_form);\n
  }\n
});\n
\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>5524</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
