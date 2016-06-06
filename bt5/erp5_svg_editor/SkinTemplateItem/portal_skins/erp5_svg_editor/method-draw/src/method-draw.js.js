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
            <value> <string>ts52852051.2</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>method-draw.js</string> </value>
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
            <value> <int>151420</int> </value>
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
 * Licensed under the MIT License\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 * Copyright(c) 2010 Pavol Rusnak\n
 * Copyright(c) 2010 Jeff Schiller\n
 * Copyright(c) 2010 Narendra Sisodiya\n
* Copyright(c)  2012 Mark MacKay\n
 *\n
 */\n
\n
// Dependencies:\n
// 1) units.js\n
// 2) browser.js\n
// 3) svgcanvas.js\n
\n
(function() {\n
  document.addEventListener("touchstart", touchHandler, true);\n
  document.addEventListener("touchmove", touchHandler, true);\n
  document.addEventListener("touchend", touchHandler, true);\n
  document.addEventListener("touchcancel", touchHandler, true);\n
  \n
  if(!window.methodDraw) window.methodDraw = function($) {\n
    var svgCanvas;\n
    var Editor = {};\n
    var is_ready = false;\n
    curConfig = {\n
      canvas_expansion: 1, \n
      dimensions: [580,400], \n
      initFill: {color: \'fff\', opacity: 1},\n
      initStroke: {width: 1.5, color: \'000\', opacity: 1},\n
      initOpacity: 1,\n
      imgPath: \'images/\',\n
      extPath: \'extensions/\',\n
      jGraduatePath: \'lib/jgraduate/images/\',\n
      extensions: [],\n
      initTool: \'select\',\n
      wireframe: false,\n
      colorPickerCSS: false,\n
      gridSnapping: false,\n
      gridColor: "#000",\n
      baseUnit: \'px\',\n
      snappingStep: 10,\n
      showRulers: (svgedit.browser.isTouch()) ? false : true,\n
      show_outside_canvas: false,\n
      no_save_warning: true,\n
      initFont: \'Helvetica, Arial, sans-serif\'\n
    },\n
      uiStrings = Editor.uiStrings = {\n
        common: {\n
          "ok":"OK",\n
          "cancel":"Cancel",\n
          "key_up":"Up",\n
          "key_down":"Down",\n
          "key_backspace":"Backspace",\n
          "key_del":"Del"\n
  \n
        },\n
        // This is needed if the locale is English, since the locale strings are not read in that instance.\n
        layers: {\n
          "layer":"Layer"\n
        },\n
        notification: {\n
          "invalidAttrValGiven":"Invalid value given",\n
          "noContentToFitTo":"No content to fit to",\n
          "dupeLayerName":"There is already a layer named that!",\n
          "enterUniqueLayerName":"Please enter a unique layer name",\n
          "enterNewLayerName":"Please enter the new layer name",\n
          "layerHasThatName":"Layer already has that name",\n
          "QmoveElemsToLayer":"Move selected elements to layer \\"%s\\"?",\n
          "QwantToClear":"<strong>Do you want to clear the drawing?</strong>\\nThis will also erase your undo history",\n
          "QwantToOpen":"Do you want to open a new file?\\nThis will also erase your undo history",\n
          "QerrorsRevertToSource":"There were parsing errors in your SVG source.\\nRevert back to original SVG source?",\n
          "QignoreSourceChanges":"Ignore changes made to SVG source?",\n
          "featNotSupported":"Feature not supported",\n
          "enterNewImgURL":"Enter the new image URL",\n
          "defsFailOnSave": "NOTE: Due to a bug in your browser, this image may appear wrong (missing gradients or elements). It will however appear correct once actually saved.",\n
          "loadingImage":"Loading image, please wait...",\n
          "saveFromBrowser": "Select \\"Save As...\\" in your browser to save this image as a %s file.",\n
          "noteTheseIssues": "Also note the following issues: ",\n
          "unsavedChanges": "There are unsaved changes.",\n
          "enterNewLinkURL": "Enter the new hyperlink URL",\n
          "errorLoadingSVG": "Error: Unable to load SVG data",\n
          "URLloadFail": "Unable to load from URL",\n
          "retrieving": \'Retrieving "%s" ...\'\n
        }\n
      };\n
    \n
\n
    var curPrefs = {}; //$.extend({}, defaultPrefs);\n
    var customHandlers = {};\n
    Editor.curConfig = curConfig;\n
    Editor.tool_scale = 1;\n
    \n
    Editor.setConfig = function(opts) {\n
      $.extend(true, curConfig, opts);\n
      if(opts.extensions) {\n
        curConfig.extensions = opts.extensions;\n
      }\n
    }\n
    \n
    // Extension mechanisms must call setCustomHandlers with two functions: opts.open and opts.save\n
    // opts.open\'s responsibilities are:\n
    //  - invoke a file chooser dialog in \'open\' mode\n
    //  - let user pick a SVG file\n
    //  - calls setCanvas.setSvgString() with the string contents of that file\n
    // opts.save\'s responsibilities are:\n
    //  - accept the string contents of the current document \n
    //  - invoke a file chooser dialog in \'save\' mode\n
    //  - save the file to location chosen by the user\n
    Editor.setCustomHandlers = function(opts) {\n
      Editor.ready(function() {\n
        if(opts.open) {\n
          $(\'#tool_open > input[type="file"]\').remove();\n
          $(\'#tool_open\').show();\n
          svgCanvas.open = opts.open;\n
        }\n
        if(opts.save) {\n
          Editor.show_save_warning = false;\n
          svgCanvas.bind("saved", opts.save);\n
        }\n
        if(opts.pngsave) {\n
          svgCanvas.bind("exported", opts.pngsave);\n
        }\n
        customHandlers = opts;\n
      });\n
    }\n
    \n
    Editor.randomizeIds = function() {\n
      svgCanvas.randomizeIds(arguments)\n
    }\n
\n
    Editor.init = function() {\n
      // For external openers\n
      (function() {\n
        // let the opener know SVG Edit is ready\n
        var w = window.opener;\n
        if (w) {\n
              try {\n
            var methodDrawReadyEvent = w.document.createEvent("Event");\n
            methodDrawReadyEvent.initEvent("methodDrawReady", true, true);\n
            w.document.documentElement.dispatchEvent(methodDrawReadyEvent);\n
              }\n
          catch(e) {}\n
        }\n
      })();\n
\n
\n
      $("body").toggleClass("touch", svgedit.browser.isTouch());\n
      $("#canvas_width").val(curConfig.dimensions[0]);\n
      $("#canvas_height").val(curConfig.dimensions[1]);\n
      \n
      var extFunc = function() {\n
        $.each(curConfig.extensions, function() {\n
          var extname = this;\n
          $.getScript(curConfig.extPath + extname, function(d) {\n
            // Fails locally in Chrome 5\n
            if(!d) {\n
              var s = document.createElement(\'script\');\n
              s.src = curConfig.extPath + extname;\n
              document.querySelector(\'head\').appendChild(s);\n
            }\n
          });\n
        });\n
      }\n
      \n
      // Load extensions\n
      // Bit of a hack to run extensions in local Opera/IE9\n
      if(document.location.protocol === \'file:\') {\n
        setTimeout(extFunc, 100);\n
      } else {\n
        extFunc();\n
      }\n
      $.svgIcons(curConfig.imgPath + \'svg_edit_icons.svg\', {\n
        w:27, h:27,\n
        id_match: false,\n
        no_img: true, // Opera & Firefox 4 gives odd behavior w/images\n
        fallback_path: curConfig.imgPath,\n
        fallback:{\n
          \'logo\':\'logo.png\',\n
          \'select\':\'select.png\',\n
          \'select_node\':\'select_node.png\',\n
          \'pencil\':\'pencil.png\',\n
          \'pen\':\'line.png\',\n
          \'rect\':\'square.png\',\n
          \'ellipse\':\'ellipse.png\',\n
          \'path\':\'path.png\',\n
          \'text\':\'text.png\',\n
          \'image\':\'image.png\',\n
          \'zoom\':\'zoom.png\',\n
          \'delete\':\'delete.png\',\n
          \'spapelib\':\'shapelib.png\',\n
          \'node_delete\':\'node_delete.png\',        \n
          \'align_left\':\'align-left.png\',\n
          \'align_center\':\'align-center.png\',\n
          \'align_right\':\'align-right.png\',\n
          \'align_top\':\'align-top.png\',\n
          \'align_middle\':\'align-middle.png\',\n
          \'align_bottom\':\'align-bottom.png\',\n
          \'arrow_right\':\'flyouth.png\',\n
          \'arrow_down\':\'dropdown.gif\'\n
        },\n
        placement: {\n
          \'#logo\':\'logo\',\n
          \'#tool_select\':\'select\',\n
          \'#tool_fhpath\':\'pencil\',\n
          \'#tool_line\':\'pen\',\n
          \'#tool_rect,#tools_rect_show\':\'rect\',\n
          \'#tool_ellipse,#tools_ellipse_show\':\'ellipse\',\n
          \'#tool_path\':\'path\',\n
          \'#tool_text,#layer_rename\':\'text\',\n
          \'#tool_image\':\'image\',\n
          \'#tool_zoom\':\'zoom\',\n
          \'#tool_node_clone\':\'node_clone\',\n
          \'#tool_node_delete\':\'node_delete\',\n
          \'#tool_add_subpath\':\'add_subpath\',\n
          \'#tool_openclose_path\':\'open_path\',\n
          \'#tool_alignleft, #tool_posleft\':\'align_left\',\n
          \'#tool_aligncenter, #tool_poscenter\':\'align_center\',\n
          \'#tool_alignright, #tool_posright\':\'align_right\',\n
          \'#tool_aligntop, #tool_postop\':\'align_top\',\n
          \'#tool_alignmiddle, #tool_posmiddle\':\'align_middle\',\n
          \'#tool_alignbottom, #tool_posbottom\':\'align_bottom\',\n
          \'#cur_position\':\'align\',\n
          \'#zoomLabel\':\'zoom\'\n
        },\n
        resize: {\n
          \'#logo .svg_icon\': 15,\n
          \'.flyout_arrow_horiz .svg_icon\': 5,\n
          \'#fill_bg .svg_icon, #stroke_bg .svg_icon\': svgedit.browser.isTouch() ? 24 : 24,\n
          \'.palette_item:first .svg_icon\': svgedit.browser.isTouch() ? 30 : 16,\n
          \'#zoomLabel .svg_icon\': 16,\n
          \'#zoom_dropdown .svg_icon\': 7\n
        },\n
        callback: function(icons) {\n
          $(\'.toolbar_button button > svg, .toolbar_button button > img\').each(function() {\n
            $(this).parent().prepend(this);\n
          });\n
          $(\'.tool_button, .tool_button_current\').addClass("loaded")\n
          var tleft = $(\'#tools_left\');\n
          if (tleft.length != 0) {\n
            var min_height = tleft.offset().top + tleft.outerHeight();\n
          }\n
          \n
          // Look for any missing flyout icons from plugins\n
          $(\'.tools_flyout\').each(function() {\n
            var shower = $(\'#\' + this.id + \'_show\');\n
            var sel = shower.attr(\'data-curopt\');\n
            // Check if there\'s an icon here\n
            if(!shower.children(\'svg, img\').length) {\n
              var clone = $(sel).children().clone();\n
              if(clone.length) {\n
                clone[0].removeAttribute(\'style\'); //Needed for Opera\n
                shower.append(clone);\n
              }\n
            }\n
          });\n
          methodDraw.runCallbacks();\n
          \n
          setTimeout(function() {\n
            $(\'.flyout_arrow_horiz:empty\').each(function() {\n
              $(this).append($.getSvgIcon(\'arrow_right\').width(5).height(5));\n
            });\n
          }, 1);\n
        }\n
      });\n
      \n
      $(\'#rulers\').on("dblclick", function(e){\n
        $("#base_unit_container").css({\n
          top: e.pageY-10,\n
          left: e.pageX-50,\n
          display: \'block\'\n
        })\n
      })\n
      $("#base_unit_container")\n
        .on("mouseleave mouseenter", function(e){\n
          t = setTimeout(function(){$("#base_unit_container").fadeOut(500)}, 200)\n
          if(event.type == "mouseover") clearTimeout(t)  \n
        })\n
      $("#base_unit")\n
        .on("change", function(e) {\n
          savePreferences();\n
        });\n
\n
      Editor.canvas = svgCanvas = new $.SvgCanvas(document.getElementById("svgcanvas"), curConfig);\n
      Editor.show_save_warning = false;\n
      Editor.paintBox = {fill: null, stroke:null, canvas:null};\n
      var palette = ["#444444", "#482816", "#422C10", "#3B2F0E", "#32320F", \n
                     "#293414", "#1F361B", "#153723", "#0C372C", \n
                     "#083734", "#0E353B", "#1A333F", "#273141", \n
                     "#332D40", "#3E2A3C", "#462735", "#4B252D", \n
                     "#4D2425", "#4C261D", "#666666", "#845335", "#7B572D", \n
                     "#6F5C2A", "#62612C", "#546433", "#46673D", \n
                     "#396849", "#306856", "#2D6862", "#33666C", \n
                     "#426373", "#535F75", "#645A73", "#74556D", \n
                     "#805064", "#884D58", "#8B4D4B", "#894F3F", \n
                     "#999999", "#C48157", "#B8874D", "#A98E49", "#97944B", \n
                     "#849854", "#729C62", "#619E73", "#559E84", \n
                     "#529D94", "#5B9BA2", "#6D97AB", "#8391AE", \n
                     "#9A8AAB", "#AF84A3", "#BF7E96", "#C97A86", \n
                     "#CE7975", "#CC7C65", "#BBBBBB", "#FFB27C", "#FABA6F", \n
                     "#E6C36A", "#CFCA6D", "#B8D078", "#A0D58A",\n
                     "#8CD79F", "#7DD8B5", "#7AD6CA", "#84D3DB", \n
                     "#9ACEE6", "#B6C7EA", "#D3BEE7", "#EDB6DC", \n
                     "#FFAFCC", "#FFAAB8", "#FFA9A2", "#FFAC8D", \n
                     "#DDDDDD", "#FFE7A2", "#FFF093", "#FFFA8D", "#FFFF91", \n
                     "#EEFF9F", "#D1FFB4", "#B9FFCE", "#A8FFE9", \n
                     "#A4FFFF", "#B1FFFF", "#CBFFFF", "#EDFFFF", \n
                     "#FFF5FF", "#FFEBFF", "#FFE2FF", "#FFDCEC", \n
                     "#FFDBD2", "#FFDFB8"\n
                 ],\n
        isMac = (navigator.platform.indexOf("Mac") >= 0),\n
        isWebkit = (navigator.userAgent.indexOf("AppleWebKit") >= 0),\n
        modKey = (isMac ? "meta+" : "ctrl+"), // ⌘\n
        path = svgCanvas.pathActions,\n
        undoMgr = svgCanvas.undoMgr,\n
        Utils = svgedit.utilities,\n
        default_img_url = curConfig.imgPath + "placeholder.svg",\n
        workarea = $("#workarea"),\n
        canv_menu = $("#cmenu_canvas"),\n
        exportWindow = null, \n
        tool_scale = 1,\n
        ui_context = \'toolbars\',\n
        orig_source = \'\';\n
        \n
\n
      // This puts the correct shortcuts in the menus\n
      if (!isMac) {\n
       $(\'.shortcut\').each(function(){\n
         var text = $(this).text();\n
         $(this).text(text.split("⌘").join("Ctrl+"))\n
       }); \n
      }\n
\n
      // This sets up alternative dialog boxes. They mostly work the same way as\n
      // their UI counterparts, expect instead of returning the result, a callback\n
      // needs to be included that returns the result as its first parameter.\n
      // In the future we may want to add additional types of dialog boxes, since \n
      // they should be easy to handle this way.\n
      (function() {\n
        $(\'#dialog_container\').draggable({cancel:\'#dialog_content, #dialog_buttons *\', containment: \'window\'});\n
        var box = $(\'#dialog_box\'), btn_holder = $(\'#dialog_buttons\');\n
        \n
        var dbox = function(type, msg, callback, defText) {\n
          $(\'#dialog_content\').html(\'<p>\'+msg.replace(/\\n/g,\'</p><p>\')+\'</p>\')\n
            .toggleClass(\'prompt\',(type==\'prompt\'));\n
          btn_holder.empty();\n
          \n
          var ok = $(\'<input type="button" value="\' + uiStrings.common.ok + \'">\').appendTo(btn_holder);\n
        \n
          if(type != \'alert\') {\n
            $(\'<input type="button" value="\' + uiStrings.common.cancel + \'">\')\n
              .appendTo(btn_holder)\n
              .on("click touchstart", function() { box.hide();callback(false)});\n
          }\n
          \n
          if(type == \'prompt\') {\n
            var input = $(\'<input type="text">\').prependTo(btn_holder);\n
            input.val(defText || \'\');\n
            input.bind(\'keydown\', \'return\', function() {ok.trigger("click touchstart");});\n
          }\n
          \n
          if(type == \'process\') {\n
            ok.hide();\n
          }\n
    \n
          box.show();\n
          \n
          ok.on("click touchstart", function() { \n
            box.hide();\n
            var resp = (type == \'prompt\')?input.val():true;\n
            if(callback) callback(resp);\n
          }).focus();\n
          \n
          if(type == \'prompt\') input.focus();\n
        }\n
        \n
        $.alert = function(msg, cb) { dbox(\'alert\', msg, cb);};\n
        $.confirm = function(msg, cb) { dbox(\'confirm\', msg, cb);};\n
        $.process_cancel = function(msg, cb) {  dbox(\'process\', msg, cb);};\n
        $.prompt = function(msg, txt, cb) { dbox(\'prompt\', msg, cb, txt);};\n
      }());\n
      \n
      var setSelectMode = function() {\n
        var curr = $(\'.tool_button_current\');\n
        if(curr.length && curr[0].id !== \'tool_select\') {\n
          curr.removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
          $(\'#tool_select\').addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
        }\n
        svgCanvas.setMode(\'select\');\n
      };\n
      \n
      var setEyedropperMode = function() {\n
        var curr = $(\'.tool_button_current\');\n
        if(curr.length && curr[0].id !== \'tool_eyedropper\') {\n
          curr.removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
          $(\'#tool_eyedropper\').addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
        }\n
        svgCanvas.setMode(\'eyedropper\');\n
      }\n
      \n
      var togglePathEditMode = function(editmode, elems) {\n
        $(\'#tools_bottom_2,#tools_bottom_3\').toggle(!editmode);\n
        if(editmode) {\n
          // Change select icon\n
          $(\'.context_panel\').hide();\n
          $(\'#path_node_panel\').show();\n
          $(\'.tool_button_current\').removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
          $(\'#tool_select\').addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
          setIcon(\'#tool_select\', \'select_node\');\n
          multiselected = false;\n
        } else {\n
          if (elems[0]) {\n
            var selector = svgCanvas.selectorManager.requestSelector(elems[0])\n
            selector.reset(elems[0]);\n
            selector.selectorRect.setAttribute(\'display\', \'inline\');\n
          }\n
          \n
          setIcon(\'#tool_select\', \'select\');\n
        }\n
      }\n
    \n
      // used to make the flyouts stay on the screen longer the very first time\n
      var flyoutspeed = 1250;\n
      var textBeingEntered = false;\n
      var selectedElement = null;\n
      var multiselected = false;\n
      var editingsource = false;\n
      var docprops = false;\n
      var preferences = false;\n
      var cur_context = \'\';\n
      \n
      var saveHandler = function(window,svg) {\n
        Editor.show_save_warning = false;\n
      \n
        // by default, we add the XML prolog back, systems integrating SVG-edit (wikis, CMSs) \n
        // can just provide their own custom save handler and might not want the XML prolog\n
        svg = \'<?xml version="1.0"?>\\n\' + svg;\n
        \n
        // Opens the SVG in new window, with warning about Mozilla bug #308590 when applicable\n
        \n
        var ua = navigator.userAgent;\n
\n
        // Chrome 5 (and 6?) don\'t allow saving, show source instead ( http://code.google.com/p/chromium/issues/detail?id=46735 )\n
        // IE9 doesn\'t allow standalone Data URLs ( https://connect.microsoft.com/IE/feedback/details/542600/data-uri-images-fail-when-loaded-by-themselves )\n
        if(~ua.indexOf(\'MSIE\')) {\n
          showSourceEditor(0,true);\n
          return; \n
        }\n
        var win = window.open("data:image/svg+xml;base64," + Utils.encode64(svg));\n
        \n
        // Alert will only appear the first time saved OR the first time the bug is encountered\n
        var done = $.pref(\'save_notice_done\');\n
        if(done !== "all") {\n
    \n
          var note = uiStrings.notification.saveFromBrowser.replace(\'%s\', \'SVG\');\n
          \n
          // Check if FF and has <defs/>\n
          if(ua.indexOf(\'Gecko/\') !== -1) {\n
            if(svg.indexOf(\'<defs\') !== -1) {\n
              note += "\\n\\n" + uiStrings.notification.defsFailOnSave;\n
              $.pref(\'save_notice_done\', \'all\');\n
              done = "all";\n
            } else {\n
              $.pref(\'save_notice_done\', \'part\');\n
            }\n
          } else {\n
            $.pref(\'save_notice_done\', \'all\'); \n
          }\n
          \n
          if(done !== \'part\') {\n
            win.alert(note);\n
          }\n
        }\n
      };\n
      \n
      var exportHandler = function(window, data) {\n
        var issues = data.issues;\n
        \n
        if(!$(\'#export_canvas\').length) {\n
          $(\'<canvas>\', {id: \'export_canvas\'}).hide().appendTo(\'body\');\n
        }\n
        var c = $(\'#export_canvas\')[0];\n
        \n
        c.width = svgCanvas.contentW;\n
        c.height = svgCanvas.contentH;\n
        canvg(c, data.svg, {renderCallback: function() {\n
          var datauri = c.toDataURL(\'image/png\');\n
          exportWindow.location.href = datauri;\n
          var done = $.pref(\'export_notice_done\');\n
          if(done !== "all") {\n
            var note = uiStrings.notification.saveFromBrowser.replace(\'%s\', \'PNG\');\n
            \n
            // Check if there\'s issues\n
            if(issues.length) {\n
              var pre = "\\n \\u2022 ";\n
              note += ("\\n\\n" + uiStrings.notification.noteTheseIssues + pre + issues.join(pre));\n
            } \n
            \n
            // Note that this will also prevent the notice even though new issues may appear later.\n
            // May want to find a way to deal with that without annoying the user\n
            $.pref(\'export_notice_done\', \'all\'); \n
            exportWindow.alert(note);\n
          }\n
        }});\n
      };\n
      \n
      // called when we\'ve selected a different element\n
      var selectedChanged = function(window,elems) {        \n
        var mode = svgCanvas.getMode();\n
        if(mode === "select") setSelectMode();\n
        if (mode === "pathedit") return updateContextPanel();\n
        // if elems[1] is present, then we have more than one element\n
        selectedElement = (elems.length == 1 || elems[1] == null ? elems[0] : null);\n
        elems = elems.filter(Boolean)\n
        multiselected = (elems.length >= 2) ? elems : false;\n
        if (svgCanvas.elementsAreSame(multiselected)) selectedElement = multiselected[0]\n
        if (selectedElement != null) {\n
          $(\'#multiselected_panel\').hide()\n
          updateToolbar();\n
          if (multiselected.length) {//multiselected elements are the same\n
            $(\'#tools_top\').addClass(\'multiselected\')\n
          }\n
        }\n
        else if (multiselected.length) {\n
          $(\'.context_panel\').hide()\n
          $(\'#tools_top\').removeClass(\'multiselected\')\n
          $(\'#multiselected_panel\').show()\n
        }\n
        else {\n
          $(\'.context_panel\').hide()\n
          $(\'#canvas_panel\').show()\n
          $(\'#tools_top\').removeClass(\'multiselected\')\n
        }\n
        svgCanvas.runExtensions("selectedChanged", {\n
          elems: elems,\n
          selectedElement: selectedElement,\n
          multiselected: multiselected\n
        });\n
      };\n
    \n
      // Call when part of element is in process of changing, generally\n
      // on mousemove actions like rotate, move, etc.\n
      var elementTransition = function(window,elems) {\n
        var mode = svgCanvas.getMode();\n
        var elem = elems[0];\n
        \n
        if(!elem) return;\n
        \n
        multiselected = (elems.length >= 2 && elems[1] != null) ? elems : null;\n
        // Only updating fields for single elements for now\n
        if(!multiselected) {\n
          switch ( mode ) {\n
            case "rotate":\n
              var ang = svgCanvas.getRotationAngle(elem);\n
              $(\'#angle\').val(Math.round(ang));\n
              rotateCursor(ang);\n
              $(\'#tool_reorient\').toggleClass(\'disabled\', ang == 0);\n
              break;\n
            \n
            // TODO: Update values that change on move/resize, etc\n
//            case "select":\n
//            case "resize":\n
//              break;\n
          }\n
        }\n
        svgCanvas.runExtensions("elementTransition", {\n
          elems: elems\n
        });\n
      };\n
    \n
      // called when any element has changed\n
      var elementChanged = function(window,elems) {\n
        var mode = svgCanvas.getMode();\n
        if(mode === "select") {\n
          setSelectMode();\n
        }\n
        \n
        for (var i = 0; i < elems.length; ++i) {\n
          var elem = elems[i];\n
          \n
          // if the element changed was the svg, then it could be a resolution change\n
          if (elem && elem.tagName === "svg") {\n
            //populateLayers();\n
            updateCanvas();\n
          } \n
          // Update selectedElement if element is no longer part of the image.\n
          // This occurs for the text elements in Firefox\n
          else if(elem && selectedElement && selectedElement.parentNode == null) {\n
//            || elem && elem.tagName == "path" && !multiselected) { // This was added in r1430, but not sure why\n
            selectedElement = elem;\n
          }\n
        }\n
        \n
        Editor.show_save_warning = true;\n
    \n
        // we update the contextual panel with potentially new\n
        // positional/sizing information (we DON\'T want to update the\n
        // toolbar here as that creates an infinite loop)\n
        // also this updates the history buttons\n
    \n
        // we tell it to skip focusing the text control if the\n
        // text element was previously in focus\n
        updateContextPanel();\n
        \n
        // In the event a gradient was flipped:\n
        if(selectedElement && mode === "select") {\n
          Editor.paintBox.fill.update();\n
          Editor.paintBox.stroke.update();\n
        }\n
        \n
        svgCanvas.runExtensions("elementChanged", {\n
          elems: elems\n
        });\n
      };\n
      \n
      var zoomChanged = function(window, bbox, autoCenter) {\n
        var scrbar = 15,\n
          res = svgCanvas.getResolution(),\n
          w_area = workarea,\n
          canvas_pos = $(\'#svgcanvas\').position();\n
        var z_info = svgCanvas.setBBoxZoom(bbox, w_area.width()-scrbar, w_area.height()-scrbar);\n
        if(!z_info) return;\n
        var zoomlevel = z_info.zoom,\n
          bb = z_info.bbox;\n
        \n
        if(zoomlevel < .001) {\n
          changeZoom({value: .1});\n
          return;\n
        }\n
        if (typeof animatedZoom != \'undefined\') window.cancelAnimationFrame(animatedZoom)\n
        // zoom duration 500ms\n
        var start = Date.now();\n
        var duration = 500;\n
        var diff = (zoomlevel) - (res.zoom)\n
        var zoom = $(\'#zoom\')[0]\n
        var current_zoom = res.zoom\n
        var animateZoom = function(timestamp) {\n
          var progress = Date.now() - start\n
          var tick = progress / duration\n
          tick = (Math.pow((tick-1), 3) +1);\n
          svgCanvas.setZoom(current_zoom + (diff*tick));\n
          updateCanvas();\n
          if (tick < 1 && tick > -.90) {\n
            window.animatedZoom = requestAnimationFrame(animateZoom)\n
          }\n
          else {\n
            $("#zoom").val(parseInt(zoomlevel*100))\n
            $("option", "#zoom_select").removeAttr("selected")\n
            $("option[value="+ parseInt(zoomlevel*100) +"]", "#zoom_select").attr("selected", "selected")\n
          }\n
        }\n
        animateZoom()\n
        \n
        \n
        \n
        //if(autoCenter) {\n
        //  updateCanvas();\n
        //} else {\n
        //  updateCanvas(false, {x: bb.x * zoomlevel + (bb.width * zoomlevel)/2, y: bb.y * zoomlevel + (bb.height * zoomlevel)/2});\n
        //}\n
    \n
        if(svgCanvas.getMode() == \'zoom\' && bb.width) {\n
          // Go to select if a zoom box was drawn\n
          setSelectMode();\n
        }\n
        \n
        zoomDone();\n
      }\n
      \n
      $(\'#cur_context_panel\').delegate(\'a\', \'click\', function() {\n
        var link = $(this);\n
        if(link.attr(\'data-root\')) {\n
          svgCanvas.leaveContext();\n
        } else {\n
          svgCanvas.setContext(link.text());\n
        }\n
        svgCanvas.clearSelection();\n
        return false;\n
      });\n
      \n
      var contextChanged = function(win, context) {\n
        \n
        var link_str = \'\';\n
        if(context) {\n
          var str = \'\';\n
          link_str = \'<a href="#" data-root="y">\' + svgCanvas.getCurrentDrawing().getCurrentLayerName() + \'</a>\';\n
          \n
          $(context).parentsUntil(\'#svgcontent > g\').andSelf().each(function() {\n
            if(this.id) {\n
              str += \' > \' + this.id;\n
              if(this !== context) {\n
                link_str += \' > <a href="#">\' + this.id + \'</a>\';\n
              } else {\n
                link_str += \' > \' + this.id;\n
              }\n
            }\n
          });\n
\n
          cur_context = str;\n
        } else {\n
          cur_context = null;\n
        }\n
        $(\'#cur_context_panel\').toggle(!!context).html(link_str);\n
\n
      }\n
      \n
      // Makes sure the current selected paint is available to work with\n
      var prepPaints = function() {\n
        Editor.paintBox.fill.prep();\n
        Editor.paintBox.stroke.prep();\n
      }\n
      \n
      var flyout_funcs = {};\n
      \n
      var setupFlyouts = function(holders) {\n
        $.each(holders, function(hold_sel, btn_opts) {\n
          var buttons = $(hold_sel).children();\n
          var show_sel = hold_sel + \'_show\';\n
          var shower = $(show_sel);\n
          var def = false;\n
          buttons.addClass(\'tool_button\')\n
            .unbind(\'click mousedown mouseup\') // may not be necessary\n
            .each(function(i) {\n
              // Get this buttons options\n
              var opts = btn_opts[i];\n
              \n
              // Remember the function that goes with this ID\n
              flyout_funcs[opts.sel] = opts.fn;\n
\n
              if(opts.isDefault) def = i;\n
\n
              // Clicking the icon in flyout should set this set\'s icon\n
              var func = function(event) {\n
                var options = opts;\n
                //find the currently selected tool if comes from keystroke\n
                if (event.type === "keydown") {\n
                  var flyoutIsSelected = $(options.parent + "_show").hasClass(\'tool_button_current\'); \n
                  var currentOperation = $(options.parent + "_show").attr("data-curopt");\n
                  $.each(holders[opts.parent], function(i, tool){\n
                    if (tool.sel == currentOperation) {\n
                      if(!event.shiftKey || !flyoutIsSelected) {\n
                        options = tool;\n
                      }\n
                      else {\n
                        options = holders[opts.parent][i+1] || holders[opts.parent][0];\n
                      }\n
                    }\n
                  });\n
                }\n
                if($(this).hasClass(\'disabled\')) return false;\n
                if (toolButtonClick(show_sel)) {\n
                  options.fn();\n
                }\n
                if(options.icon) {\n
                  var icon = $.getSvgIcon(options.icon, true);\n
                } else {\n
                  var icon = $(options.sel).children().eq(0).clone();\n
                }\n
\n
                icon[0].setAttribute(\'width\',shower.width());\n
                icon[0].setAttribute(\'height\',shower.height());\n
                shower.children(\':not(.flyout_arrow_horiz)\').remove();\n
                shower.append(icon).attr(\'data-curopt\', options.sel); // This sets the current mode\n
              }\n
\n
              $(this).mouseup(func);\n
\n
              if(opts.key) {\n
                $(document).bind(\'keydown\', opts.key[0] + " shift+" + opts.key[0], func);\n
              }\n
            });\n
\n
          if(def) {\n
            shower.attr(\'data-curopt\', btn_opts[def].sel);\n
          } else if(!shower.attr(\'data-curopt\')) {\n
            // Set first as default\n
            shower.attr(\'data-curopt\', btn_opts[0].sel);\n
          }\n
          \n
          var timer;\n
          \n
          var pos = $(show_sel).position();\n
          $(hold_sel).css({\'left\': pos.left+34, \'top\': pos.top+77});\n
          \n
          // Clicking the "show" icon should set the current mode\n
          shower.mousedown(function(evt) {\n
            $(\'#workarea\').one("mousedown", function(){$(\'#tools_shapelib\').hide()})\n
            if ($(\'#tools_shapelib\').is(":visible")) toolButtonClick(show_sel, false);\n
            if(shower.hasClass(\'disabled\')) return false;\n
            var holder = $(hold_sel);\n
            var l = pos.left+34;\n
            var w = holder.width()*-1;\n
            var time = holder.data(\'shown_popop\')?200:0;\n
            timer = setTimeout(function() {\n
              // Show corresponding menu\n
              if(!shower.data(\'isLibrary\')) {\n
                holder.css(\'left\', w).show().animate({\n
                  left: l\n
                },50);\n
              } else {\n
                holder.css(\'left\', l).show();\n
              }\n
              holder.data(\'shown_popop\',true);\n
            },time);\n
            evt.preventDefault();\n
          }).mouseup(function(evt) {\n
            clearTimeout(timer);\n
            var opt = $(this).attr(\'data-curopt\');\n
            // Is library and popped up, so do nothing\n
            if(shower.data(\'isLibrary\') && $(show_sel.replace(\'_show\',\'\')).is(\':visible\')) {\n
              toolButtonClick(show_sel, true);\n
              return;\n
            }\n
            if (toolButtonClick(show_sel) && (opt in flyout_funcs)) {\n
              flyout_funcs[opt]();\n
            }\n
          });\n
          \n
          //  $(\'#tools_rect\').mouseleave(function(){$(\'#tools_rect\').fadeOut();});\n
        });\n
        \n
        setFlyoutTitles();\n
      }\n
      \n
      var makeFlyoutHolder = function(id, child) {\n
        var div = $(\'<div>\',{\n
          \'class\': \'tools_flyout\',\n
          id: id\n
        }).appendTo(\'#svg_editor\').append(child);\n
        \n
        return div;\n
      }\n
      \n
      var setFlyoutPositions = function() {\n
        $(\'.tools_flyout\').each(function() {\n
          var shower = $(\'#\' + this.id + \'_show\');\n
          var pos = shower.offset();\n
          var w = shower.outerWidth();\n
          $(this).css({left: (pos.left + w)*tool_scale, top: pos.top});\n
        });\n
      }\n
      \n
      var setFlyoutTitles = function() {\n
        $(\'.tools_flyout\').each(function() {\n
          var shower = $(\'#\' + this.id + \'_show\');\n
          if(shower.data(\'isLibrary\')) return;\n
          \n
          var tooltips = [];\n
          $(this).children().each(function() {\n
            tooltips.push(this.title);\n
          });\n
          shower[0].title = tooltips.join(\' / \');\n
        });\n
      }\n
\n
      var resize_timer;     \n
      \n
      var extAdded = function(window, ext) {\n
    \n
        var cb_called = false;\n
        var resize_done = false;\n
        var cb_ready = true; // Set to false to delay callback (e.g. wait for $.svgIcons)\n
        \n
        function prepResize() {\n
          if(resize_timer) {\n
            clearTimeout(resize_timer);\n
            resize_timer = null;\n
          }\n
          if(!resize_done) {\n
            resize_timer = setTimeout(function() {\n
              resize_done = true;\n
              setIconSize(curPrefs.iconsize);\n
            }, 50); \n
          }\n
        }\n
\n
        \n
        var runCallback = function() {\n
          if(ext.callback && !cb_called && cb_ready) {\n
            cb_called = true;\n
            ext.callback();\n
          }\n
        }\n
    \n
        var btn_selects = [];\n
    \n
        if(ext.context_tools) {\n
          $.each(ext.context_tools, function(i, tool) {\n
            // Add select tool\n
            var cont_id = tool.container_id?(\' id="\' + tool.container_id + \'"\'):"";\n
            \n
            var panel = $(\'#\' + tool.panel);\n
            \n
            // create the panel if it doesn\'t exist\n
            if(!panel.length)\n
              panel = $(\'<div>\', {id: tool.panel}).appendTo("#tools_top").hide();\n
            \n
            // TODO: Allow support for other types, or adding to existing tool\n
            switch (tool.type) {\n
            case \'tool_button\':\n
              var html = \'<div class="tool_button">\' + tool.id + \'</div>\';\n
              var div = $(html).appendTo(panel);\n
              if (tool.events) {\n
                $.each(tool.events, function(evt, func) {\n
                  $(div).bind(evt, func);\n
                });\n
              }\n
              break;\n
            case \'select\':\n
              var html = \'<label\' + cont_id + \'>\'\n
                + \'<select id="\' + tool.id + \'">\';\n
              $.each(tool.options, function(val, text) {\n
                var sel = (val == tool.defval) ? " selected":"";\n
                html += \'<option value="\'+val+\'"\' + sel + \'>\' + text + \'</option>\';\n
              });\n
              html += "</select></label>";\n
              // Creates the tool, hides & adds it, returns the select element\n
              var sel = $(html).appendTo(panel).find(\'select\');\n
              \n
              $.each(tool.events, function(evt, func) {\n
                $(sel).bind(evt, func);\n
              });\n
              break;\n
            case \'button-select\': \n
              var html = \'<div id="\' + tool.id + \'" class="dropdown toolset" title="\' + tool.title + \'">\'\n
                + \'<div id="cur_\' + tool.id + \'" class="icon_label"></div><button></button></div>\';\n
              \n
              var list = $(\'<ul id="\' + tool.id + \'_opts"></ul>\').appendTo(\'#option_lists\');\n
              if(tool.colnum) {\n
                list.addClass(\'optcols\' + tool.colnum);\n
              }\n
              \n
              // Creates the tool, hides & adds it, returns the select element\n
              var dropdown = $(html).appendTo(panel).children();\n
              \n
              btn_selects.push({\n
                elem: (\'#\' + tool.id),\n
                list: (\'#\' + tool.id + \'_opts\'),\n
                title: tool.title,\n
                callback: tool.events.change,\n
                cur: (\'#cur_\' + tool.id)\n
              });\n
\n
              break;\n
            case \'input\':\n
              var html = \'<label\' + cont_id + \'>\'\n
                + \'<span id="\' + tool.id + \'_label">\' \n
                + tool.label + \':</span>\'\n
                + \'<input id="\' + tool.id + \'" title="\' + tool.title\n
                + \'" size="\' + (tool.size || "4") + \'" value="\' + (tool.defval || "") + \'" type="text"/></label>\'\n
                \n
              // Creates the tool, hides & adds it, returns the select element\n
              \n
              // Add to given tool.panel\n
              var inp = $(html).appendTo(panel).find(\'input\');\n
              \n
              if(tool.spindata) {\n
                inp.SpinButton(tool.spindata);\n
              }\n
              \n
              if(tool.events) {\n
                $.each(tool.events, function(evt, func) {\n
                  inp.bind(evt, func);\n
                });\n
              }\n
              break;\n
              \n
            default:\n
              break;\n
            }\n
          });\n
        }\n
        \n
        if(ext.buttons) {\n
          var fallback_obj = {},\n
            placement_obj = {},\n
            svgicons = ext.svgicons;\n
          var holders = {};\n
          \n
        \n
          // Add buttons given by extension\n
          $.each(ext.buttons, function(i, btn) {\n
            var icon;\n
            var id = btn.id;\n
            var num = i;\n
            // Give button a unique ID\n
            while($(\'#\'+id).length) {\n
              id = btn.id + \'_\' + (++num);\n
            }\n
            if(!svgicons) {\n
              icon = (btn.type == "menu") ? "" : $(\'<img src="\' + btn.icon + \'">\');\n
            } else {\n
              fallback_obj[id] = btn.icon;\n
              var svgicon = btn.svgicon ? btn.svgicon : btn.id;\n
              if(btn.type == \'app_menu\') {\n
                placement_obj[\'#\' + id + \' > div\'] = svgicon;\n
              } else {\n
                placement_obj[\'#\' + id] = svgicon;\n
              }\n
            }\n
            \n
            var cls, parent;\n
            \n
            \n
            \n
            // Set button up according to its type\n
            switch ( btn.type ) {\n
            case \'mode_flyout\':\n
            case \'mode\':\n
              cls = \'tool_button\';\n
              if(btn.cls) {\n
                cls += " " + btn.cls;\n
              }\n
              parent = "#tools_left";\n
              break;\n
            case \'context\':\n
              cls = \'tool_button\';\n
              parent = "#" + btn.panel;\n
              // create the panel if it doesn\'t exist\n
              if(!$(parent).length)\n
                $(\'<div>\', {id: btn.panel}).appendTo("#tools_top");\n
              break;\n
            case \'menu\':\n
              cls = \'menu_item tool_button\';\n
              parent = "#" + (btn.after || btn.panel);\n
              break;\n
            case \'app_menu\':\n
              cls = \'\';\n
              parent = btn.parent || \'#main_menu ul\';\n
              // create the panel if it doesn\'t exist\n
              if(!$(parent).length)\n
                $(\'<div>\', {id: btn.panel}).appendTo("#tools_top");\n
              break;\n
            }\n
            \n
            var button = $((btn.list || btn.type == \'app_menu\')?\'<li/>\':\'<div/>\')\n
              .attr("id", id)\n
              .attr("title", btn.title)\n
              .addClass(cls);\n
            if(!btn.includeWith && !btn.list) {\n
              if("position" in btn) {\n
                $(parent).children().eq(btn.position).before(button);\n
              } else {\n
                if (btn.type != "menu" || !btn.after) button.appendTo(parent);\n
                else $(parent).after(button);\n
              }\n
\n
              if(btn.type ==\'mode_flyout\') {\n
              // Add to flyout menu / make flyout menu\n
  //              var opts = btn.includeWith;\n
  //              // opts.button, default, position\n
                var ref_btn = $(button);\n
                \n
                var flyout_holder = ref_btn.parent();\n
                // Create a flyout menu if there isn\'t one already\n
                if(!ref_btn.parent().hasClass(\'tools_flyout\')) {\n
                  // Create flyout placeholder\n
                  var tls_id = ref_btn[0].id.replace(\'tool_\',\'tools_\')\n
                  var show_btn = ref_btn.clone()\n
                    .attr(\'id\',tls_id + \'_show\')\n
                    .append($(\'<div>\',{\'class\':\'flyout_arrow_horiz\'}));\n
                    \n
                  ref_btn.before(show_btn);\n
                \n
                  // Create a flyout div\n
                  flyout_holder = makeFlyoutHolder(tls_id, ref_btn);\n
                  flyout_holder.data(\'isLibrary\', true);\n
                  show_btn.data(\'isLibrary\', true);\n
                } \n
                \n
                \n
                \n
  //              var ref_data = Actions.getButtonData(opts.button);\n
                \n
                placement_obj[\'#\' + tls_id + \'_show\'] = btn.id;\n
                // TODO: Find way to set the current icon using the iconloader if this is not default\n
                \n
                // Include data for extension button as well as ref button\n
                var cur_h = holders[\'#\'+flyout_holder[0].id] = [{\n
                  sel: \'#\'+id,\n
                  fn: btn.events.click,\n
                  icon: btn.id,\n
                  //key: btn.key,\n
                  isDefault: true\n
                }, ref_data];\n
\n
              } else if(btn.type == \'app_menu\' || btn.type == \'menu\') {\n
                button.append(btn.title);\n
              }\n
              \n
            } else if(btn.list) {\n
              // Add button to list\n
              button.addClass(\'push_button\');\n
              $(\'#\' + btn.list + \'_opts\').append(button);\n
              if(btn.isDefault) {\n
                $(\'#cur_\' + btn.list).append(button.children().clone());\n
                var svgicon = btn.svgicon?btn.svgicon:btn.id;\n
                placement_obj[\'#cur_\' + btn.list] = svgicon;\n
              }\n
            } else if(btn.includeWith) {\n
              // Add to flyout menu / make flyout menu\n
              var opts = btn.includeWith;\n
              // opts.button, default, position\n
              var ref_btn = $(opts.button);\n
              \n
              var flyout_holder = ref_btn.parent();\n
              // Create a flyout menu if there isn\'t one already\n
              if(!ref_btn.parent().hasClass(\'tools_flyout\')) {\n
                // Create flyout placeholder\n
                var tls_id = ref_btn[0].id.replace(\'tool_\',\'tools_\')\n
                var show_btn = ref_btn.clone()\n
                  .attr(\'id\',tls_id + \'_show\')\n
                  .append($(\'<div>\',{\'class\':\'flyout_arrow_horiz\'}));\n
                  \n
                ref_btn.before(show_btn);\n
              \n
                // Create a flyout div\n
                flyout_holder = makeFlyoutHolder(tls_id, ref_btn);\n
              } \n
              \n
              var ref_data = Actions.getButtonData(opts.button);\n
              \n
              if(opts.isDefault) {\n
                placement_obj[\'#\' + tls_id + \'_show\'] = btn.id;\n
              } \n
              // TODO: Find way to set the current icon using the iconloader if this is not default\n
              \n
              // Include data for extension button as well as ref button\n
              var cur_h = holders[\'#\'+flyout_holder[0].id] = [{\n
                sel: \'#\'+id,\n
                fn: btn.events.click,\n
                icon: btn.id,\n
                key: btn.key,\n
                isDefault: btn.includeWith?btn.includeWith.isDefault:0\n
              }, ref_data];\n
              \n
              // {sel:\'#tool_rect\', fn: clickRect, evt: \'mouseup\', key: 4, parent: \'#tools_rect\', icon: \'rect\'}\n
                \n
              var pos  = ("position" in opts)?opts.position:\'last\';\n
              var len = flyout_holder.children().length;\n
              \n
              // Add at given position or end\n
              if(!isNaN(pos) && pos >= 0 && pos < len) {\n
                flyout_holder.children().eq(pos).before(button);\n
              } else {\n
                flyout_holder.append(button);\n
                cur_h.reverse();\n
              }\n
            } \n
            \n
            if(!svgicons) {\n
              button.append(icon);\n
            }\n
            \n
            if(!btn.list) {\n
              // Add given events to button\n
              $.each(btn.events, function(name, func) {\n
                if(name == "click") {\n
                  if(btn.type == \'mode\') {\n
                    if(btn.includeWith) {\n
                      button.bind(name, func);\n
                    } else {\n
                      button.bind(name, function() {\n
                        if(toolButtonClick(button)) {\n
                          func();\n
                        }\n
                      });\n
                    }\n
                    if(btn.key) {\n
                      $(document).bind(\'keydown\', btn.key, func);\n
                      if(btn.title) button.attr("title", btn.title + \' [\'+btn.key+\']\');\n
                    }\n
                  } else {\n
                    button.bind(name, func);\n
                  }\n
                } else {\n
                  button.bind(name, func);\n
                }\n
              });\n
            }\n
            setupFlyouts(holders);\n
          });\n
          \n
          $.each(btn_selects, function() {\n
            addAltDropDown(this.elem, this.list, this.callback, {seticon: true}); \n
          });\n
          \n
          if (svgicons)\n
            cb_ready = false; // Delay callback\n
\n
          $.svgIcons(svgicons, {\n
            w:27, h:27,\n
            id_match: false,\n
            no_img: (!isWebkit),\n
            fallback: fallback_obj,\n
            placement: placement_obj,\n
            callback: function(icons) {\n
              // Non-ideal hack to make the icon match the current size\n
              if(curPrefs.iconsize && curPrefs.iconsize != \'m\') {\n
                prepResize();\n
              }\n
              cb_ready = true; // Ready for callback\n
              runCallback();\n
            }\n
        \n
          });\n
        }\n
        \n
        runCallback();\n
      };\n
      \n
      var getPaint = function(color, opac, type) {\n
        // update the editor\'s fill paint\n
        var opts = null;\n
        if (color.indexOf("url(#") === 0) {\n
          var refElem = svgCanvas.getRefElem(color);\n
          if(refElem) {\n
            refElem = refElem.cloneNode(true);\n
          } else {\n
            refElem =  $("#" + type + "_color defs *")[0];\n
          }\n
          \n
          opts = { alpha: opac };\n
          opts[refElem.tagName] = refElem;\n
        } \n
        else if (color.indexOf("#") === 0) {\n
          opts = {\n
            alpha: opac,\n
            solidColor: color.substr(1)\n
          };\n
        }\n
        else {\n
          opts = {\n
            alpha: opac,\n
            solidColor: \'none\'\n
          };\n
        }\n
        return new $.jGraduate.Paint(opts);\n
      };  \n
      \n
      // set the canvas properties at init\n
      var res = svgCanvas.getResolution();\n
      if(curConfig.baseUnit !== "px") {\n
        res.w = svgedit.units.convertUnit(res.w) + curConfig.baseUnit;\n
        res.h = svgedit.units.convertUnit(res.h) + curConfig.baseUnit;\n
      }\n
      \n
      var createBackground = function(fill) {\n
        svgCanvas.createLayer("background")\n
        cur_shape = svgCanvas.addSvgElementFromJson({\n
          "element": "rect",\n
          "attr": {\n
            "x": -1,\n
            "y": -1,\n
            "width": res.w+2,\n
            "height": res.h+2,\n
            "stroke": "none",\n
            "id": "canvas_background",\n
            "opacity": 1,\n
            "fill": fill || "#fff",\n
            "style": "pointer-events:none"\n
          }\n
        });\n
        svgCanvas.setCurrentLayer("Layer 1")\n
        svgCanvas.setCurrentLayerPosition("1")\n
      }\n
      \n
      // create a new layer background if it doesn\'t exist\n
      if (!document.getElementById(\'canvas_background\')) createBackground();\n
      var fill = document.getElementById(\'canvas_background\').getAttribute("fill");\n
      \n
      // updates the toolbar (colors, opacity, etc) based on the selected element\n
      // This function also updates the opacity and id elements that are in the context panel\n
      var updateToolbar = function() {\n
        if (selectedElement != null) {\n
          switch ( selectedElement.tagName ) {\n
          case \'use\':\n
            $(".context_panel").hide();\n
            $("#use_panel").show();\n
            break;\n
          case \'image\':\n
            $(".context_panel").hide();\n
            $("#image_panel").show();\n
            break;\n
          case \'foreignObject\':\n
            $(".context_panel").hide();\n
            break;\n
          case \'g\':\n
          case \'a\':\n
            // Look for common styles\n
            var gWidth = null;\n
            \n
            var childs = selectedElement.getElementsByTagName(\'*\');\n
            for(var i = 0, len = childs.length; i < len; i++) {\n
              var swidth = childs[i].getAttribute("stroke-width");\n
              if(i === 0) {\n
                gWidth = swidth;\n
              } else if(gWidth !== swidth) {\n
                gWidth = null;\n
              }\n
            }\n
            \n
            $(\'#stroke_width\').val(gWidth === null ? "0" : gWidth);\n
            updateContextPanel();\n
            break;\n
          default:\n
            //removed because multiselect shouldnt set color\n
            //Editor.paintBox.fill.update(false);\n
            //Editor.paintBox.stroke.update(false);\n
            \n
            $(\'#stroke_width\').val(selectedElement.getAttribute("stroke-width") || 0);\n
            var dash = selectedElement.getAttribute("stroke-dasharray") || "none"\n
            $(\'option\', \'#stroke_style\').removeAttr(\'selected\');\n
            $(\'#stroke_style option[value="\'+ dash +\'"]\').attr("selected", "selected");\n
            $(\'#stroke_style\').trigger(\'change\');\n
\n
            $.fn.dragInput.updateCursor($(\'#stroke_width\')[0])\n
            $.fn.dragInput.updateCursor($(\'#blur\')[0])\n
          }\n
  \n
        }\n
        \n
        // All elements including image and group have opacity\n
        if(selectedElement != null) {\n
          var opac_perc = ((selectedElement.getAttribute("opacity")||1.0)*100);\n
          $(\'#group_opacity\').val(opac_perc);\n
          $.fn.dragInput.updateCursor($(\'#group_opacity\')[0])\n
        }\n
      };\n
    \n
      var setImageURL = Editor.setImageURL = function(url) {\n
        if(!url) url = default_img_url;\n
        \n
        svgCanvas.setImageURL(url);\n
        $(\'#image_url\').val(url);\n
      }\n
    \n
      var setInputWidth = function(elem) {\n
        var w = Math.min(Math.max(12 + elem.value.length * 6, 50), 300);\n
        $(elem).width(w);\n
      }\n
    \n
      // updates the context panel tools based on the selected element\n
      var updateContextPanel = function(e) {\n
      var elem = selectedElement;\n
        // If element has just been deleted, consider it null\n
        if(elem != null && !elem.parentNode) elem = null;\n
        if (multiselected && multiselected[0] != null && !multiselected[0].parentNode) multiselected = false;\n
        \n
        var currentLayerName = svgCanvas.getCurrentDrawing().getCurrentLayerName();\n
        var currentMode = svgCanvas.getMode();\n
        var unit = curConfig.baseUnit !== \'px\' ? curConfig.baseUnit : null;\n
        var is_node = currentMode == \'pathedit\'; //elem ? (elem.id && elem.id.indexOf(\'pathpointgrip\') == 0) : false;\n
        \n
        if (is_node) {\n
          $(\'.context_panel\').hide();\n
          $(\'#path_node_panel\').show();\n
          $(\'#stroke_panel\').hide();\n
          var point = path.getNodePoint();\n
          $(\'#tool_add_subpath\').removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
          $(\'#tool_node_delete\').toggleClass(\'disabled\', !path.canDeleteNodes);\n
          \n
          // Show open/close button based on selected point\n
          setIcon(\'#tool_openclose_path\', path.closed_subpath ? \'open_path\' : \'close_path\');\n
          \n
          if(point) {\n
            var seg_type = $(\'#seg_type\');\n
            if(unit) {\n
              point.x = svgedit.units.convertUnit(point.x);\n
              point.y = svgedit.units.convertUnit(point.y);\n
            }\n
            $(\'#path_node_x\').val(Math.round(point.x));\n
            $(\'#path_node_y\').val(Math.round(point.y));\n
            if(point.type) {\n
              seg_type.val(point.type).removeAttr(\'disabled\');\n
              $("#seg_type_label").html(point.type == 4 ? "Straight" : "Curve")\n
            } else {\n
              seg_type.val(4).attr(\'disabled\',\'disabled\');\n
            }\n
          }\n
          $("#tools_top").removeClass("multiselected")        \n
          $("#stroke_panel").hide();\n
          $("#canvas_panel").hide();\n
          return;\n
        }\n
        \n
        var menu_items = $(\'#cmenu_canvas li\');\n
        $(\'.context_panel\').hide();\n
        $(\'.menu_item\', \'#edit_menu\').addClass(\'disabled\');\n
        $(\'.menu_item\', \'#object_menu\').addClass(\'disabled\');\n
        \n
        \n
        //hack to show the proper multialign box\n
        if (multiselected) {\n
          multiselected = multiselected.filter(Boolean);\n
          elem = (svgCanvas.elementsAreSame(multiselected)) ? multiselected[0] : null\n
          if (elem) $("#tools_top").addClass("multiselected")\n
        }\n
\n
        if (!elem && !multiselected) {\n
          $("#tools_top").removeClass("multiselected")        \n
          $("#stroke_panel").hide();\n
          $("#canvas_panel").show();\n
        }\n
    \n
        if (elem != null) {\n
          $("#stroke_panel").show();\n
          var elname = elem.nodeName;\n
          var angle = svgCanvas.getRotationAngle(elem);\n
          $(\'#angle\').val(Math.round(angle));\n
          \n
          var blurval = svgCanvas.getBlur(elem);\n
          $(\'#blur\').val(blurval);\n
          if(!is_node && currentMode != \'pathedit\') {\n
            $(\'#selected_panel\').show();\n
            $(\'.action_selected\').removeClass(\'disabled\');\n
            // Elements in this array already have coord fields\n
            var x, y\n
            if([\'g\', \'polyline\', \'path\'].indexOf(elname) >= 0) {\n
              var bb = svgCanvas.getStrokedBBox([elem]);\n
              if(bb) {\n
                x = bb.x;\n
                y = bb.y;\n
              }\n
            }\n
            \n
            if(unit) {\n
              x = svgedit.units.convertUnit(x);\n
              y = svgedit.units.convertUnit(y);\n
            }\n
\n
            $("#" + elname +"_x").val(Math.round(x))\n
            $("#" + elname +"_y").val(Math.round(y))\n
            if (elname === "polyline") {\n
              //we\'re acting as if polylines were paths\n
              $("#path_x").val(Math.round(x))\n
              $("#path_y").val(Math.round(y))\n
            }\n
                      \n
            // Elements in this array cannot be converted to a path\n
            var no_path = [\'image\', \'text\', \'path\', \'g\', \'use\'].indexOf(elname) == -1;\n
            if (no_path) $(\'.action_path_convert_selected\').removeClass(\'disabled\');\n
            if (elname === "path") $(\'.action_path_selected\').removeClass(\'disabled\');\n
  \n
          }\n
          \n
          var link_href = null;\n
          if (el_name === \'a\') {\n
            link_href = svgCanvas.getHref(elem);\n
            $(\'#g_panel\').show();\n
          }\n
          \n
          if(elem.parentNode.tagName === \'a\') {\n
            if(!$(elem).siblings().length) {\n
              $(\'#a_panel\').show();\n
              link_href = svgCanvas.getHref(elem.parentNode);\n
            }\n
          }\n
          \n
          // Hide/show the make_link buttons\n
          $(\'#tool_make_link, #tool_make_link\').toggle(!link_href);\n
          \n
          if(link_href) {\n
            $(\'#link_url\').val(link_href);\n
          }\n
          \n
          // update contextual tools here\n
          var panels = {\n
            g: [],\n
            a: [],\n
            rect: [\'rx\',\'width\',\'height\', \'x\', \'y\'],\n
            image: [\'width\',\'height\', \'x\', \'y\'],\n
            circle: [\'cx\',\'cy\',\'r\'],\n
            ellipse: [\'cx\',\'cy\',\'rx\',\'ry\'],\n
            line: [\'x1\',\'y1\',\'x2\',\'y2\'], \n
            text: [\'x\', \'y\'],\n
            \'use\': [],\n
            path : []\n
          };\n
          \n
          var el_name = elem.tagName;\n
          \n
          if($(elem).data(\'gsvg\')) {\n
            $(\'#g_panel\').show();\n
          }\n
          \n
          if (el_name == "path" || el_name == "polyline") {\n
            $(\'#path_panel\').show();\n
          }\n
          \n
          if(panels[el_name]) {\n
            var cur_panel = panels[el_name];\n
            $(\'#\' + el_name + \'_panel\').show();\n
            \n
            // corner radius has to live in a different panel\n
            // because otherwise it changes the position of the \n
            // of the elements\n
            if(el_name == "rect") $("#cornerRadiusLabel").show()\n
            else $("#cornerRadiusLabel").hide()\n
            \n
            $.each(cur_panel, function(i, item) {\n
              var attrVal = elem.getAttribute(item);\n
              if(curConfig.baseUnit !== \'px\' && elem[item]) {\n
                var bv = elem[item].baseVal.value;\n
                attrVal = svgedit.units.convertUnit(bv);\n
              }\n
              \n
              //update the draginput cursors\n
              var name_item = document.getElementById(el_name + \'_\' + item);\n
              name_item.value = Math.round(attrVal) || 0;\n
              if (name_item.getAttribute("data-cursor") === "true") {\n
                $.fn.dragInput.updateCursor(name_item );\n
              }\n
            });\n
            \n
            if(el_name == \'text\') {\n
              var font_family = elem.getAttribute("font-family");\n
              var select = document.getElementById("font_family_dropdown");\n
              select.selectedIndex = 3\n
              \n
              $(\'#text_panel\').css("display", "inline");  \n
              $(\'#tool_italic\').toggleClass(\'active\', svgCanvas.getItalic())\n
              $(\'#tool_bold\').toggleClass(\'active\', svgCanvas.getBold())\n
              $(\'#font_family\').val(font_family);\n
              $(\'#font_size\').val(elem.getAttribute("font-size"));\n
              $(\'#text\').val(elem.textContent);\n
              $(\'#preview_font\').text(font_family.split(",")[0].replace(/\'/g, "")).css(\'font-family\', font_family);\n
              if (svgCanvas.addedNew) {\n
                // Timeout needed for IE9\n
                setTimeout(function() {\n
                  $(\'#text\').focus().select();\n
                },100);\n
              }\n
            } // text\n
            else if(el_name == \'image\') {\n
              setImageURL(svgCanvas.getHref(elem));\n
            } // image\n
            else if(el_name === \'g\' || el_name === \'use\') {\n
              $(\'#container_panel\').show();\n
              $(\'.action_group_selected\').removeClass(\'disabled\');\n
              var title = svgCanvas.getTitle();\n
            }\n
          }\n
          menu_items[(el_name === \'g\' ? \'en\':\'dis\') + \'ableContextMenuItems\'](\'#ungroup\');\n
          menu_items[((el_name === \'g\' || !multiselected) ? \'dis\':\'en\') + \'ableContextMenuItems\'](\'#group\');\n
        }\n
        \n
        if (multiselected) {\n
          $(\'#multiselected_panel\').show();\n
          $(\'.action_multi_selected\').removeClass(\'disabled\');\n
          menu_items\n
            .enableContextMenuItems(\'#group\')\n
            .disableContextMenuItems(\'#ungroup\');\n
        } \n
        \n
        if (!elem) {\n
          menu_items.disableContextMenuItems(\'#delete,#cut,#copy,#group,#ungroup,#move_front,#move_up,#move_down,#move_back\');\n
        }\n
        \n
        // update history buttons\n
        if (undoMgr.getUndoStackSize() > 0) {\n
          $(\'#tool_undo\').removeClass( \'disabled\');\n
        }\n
        else {\n
          $(\'#tool_undo\').addClass( \'disabled\');\n
        }\n
        if (undoMgr.getRedoStackSize() > 0) {\n
          $(\'#tool_redo\').removeClass( \'disabled\');\n
        }\n
        else {\n
          $(\'#tool_redo\').addClass( \'disabled\');\n
        }\n
        \n
        svgCanvas.addedNew = false;\n
        \n
        if ( (elem && !is_node) || multiselected) {\n
          // update the selected elements\' layer\n
          $(\'#selLayerNames\').removeAttr(\'disabled\').val(currentLayerName);\n
          \n
          // Enable regular menu options\n
          canv_menu.enableContextMenuItems(\'#delete,#cut,#copy,#move_front,#move_up,#move_down,#move_back\');\n
        }\n
      };\n
    \n
      $(\'#text\').on("focus", function(e){ textBeingEntered = true; } );\n
      $(\'#text\').on("blur", function(){ textBeingEntered = false; } );\n
      \n
      // bind the selected event to our function that handles updates to the UI\n
      svgCanvas.bind("selected", selectedChanged);\n
      svgCanvas.bind("transition", elementTransition);\n
      svgCanvas.bind("changed", elementChanged);\n
      svgCanvas.bind("saved", saveHandler);\n
      svgCanvas.bind("exported", exportHandler);\n
      svgCanvas.bind("zoomed", zoomChanged);\n
      svgCanvas.bind("contextset", contextChanged);\n
      svgCanvas.bind("extension_added", extAdded);\n
      svgCanvas.textActions.setInputElem($("#text")[0]);\n
    \n
      var str = \'<div class="palette_item transparent" data-rgb="none"></div>\\\n
                <div class="palette_item black" data-rgb="#000000"></div>\\\n
                <div class="palette_item white" data-rgb="#ffffff"></div>\'\n
      palette.forEach(function(item, i){\n
        str += \'<div class="palette_item" style="background-color: \' + item + \';" data-rgb="\' + item + \'"></div>\';\n
      });\n
      $(\'#palette\').append(str);\n
      \n
      var changeFontSize = function(ctl) {\n
        svgCanvas.setFontSize(ctl.value);\n
      }\n
      \n
      var changeStrokeWidth = function(ctl) {\n
        var val = ctl.value;\n
        if(val == 0 && selectedElement && [\'line\', \'polyline\'].indexOf(selectedElement.nodeName) >= 0) {\n
          val = ctl.value = 1;\n
        }\n
        svgCanvas.setStrokeWidth(val);\n
      }\n
      \n
      //cache\n
      var $indicator = $(\'#tool_angle_indicator\')\n
      var $reorient = $(\'#tool_reorient\')\n
      \n
      rotateCursor = function(angle){\n
        var rotate_string = \'rotate(\'+ angle + \'deg)\'\n
        $indicator.css({\n
          \'-webkit-transform\': rotate_string,\n
          \'-moz-transform\': rotate_string,\n
          \'-o-transform\': rotate_string,\n
          \'-ms-transform\': rotate_string,\n
          \'transform\': rotate_string\n
        });\n
      }\n
      \n
      var changeRotationAngle = function(ctl) {\n
        var preventUndo = true;\n
        svgCanvas.setRotationAngle(ctl.value, preventUndo);\n
        rotateCursor(ctl.value)\n
        $(\'#tool_reorient\').toggleClass(\'disabled\', ctl.value == 0);\n
      }\n
      \n
      var changeZoom = function(ctl) {\n
        var zoomlevel = ctl.value / 100;\n
        if(zoomlevel < .001) {\n
          ctl.value = .1;\n
          return;\n
        }\n
        var zoom = svgCanvas.getZoom();\n
        var w_area = workarea;\n
        zoomChanged(window, {\n
          width: 0,\n
          height: 0,\n
          // center pt of scroll position\n
          x: (w_area[0].scrollLeft + w_area.width()/2)/zoom, \n
          y: (w_area[0].scrollTop + w_area.height()/2)/zoom,\n
          zoom: zoomlevel\n
        }, true);\n
      }\n
      \n
      var changeBlur = function(ctl, completed) {\n
        val = ctl.value;\n
        $(\'#blur\').val(val);\n
        if (completed) {\n
          svgCanvas.setBlur(val, true);\n
        }\n
        else {\n
          svgCanvas.setBlurNoUndo(val);\n
        }\n
      }\n
    \n
      var operaRepaint = function() {\n
        // Repaints canvas in Opera. Needed for stroke-dasharray change as well as fill change\n
        if(!window.opera) return;\n
        $(\'<p/>\').hide().appendTo(\'body\').remove();\n
      }\n
    \n
      $(\'#stroke_style\').change(function(){\n
        svgCanvas.setStrokeAttr(\'stroke-dasharray\', $(this).val());\n
        $("#stroke_style_label").html(this.options[this.selectedIndex].text)\n
        operaRepaint();\n
      });\n
      \n
      $(\'#seg_type\').change(function() {\n
        svgCanvas.setSegType($(this).val());\n
        $("#seg_type_label").html(this.options[this.selectedIndex].text)\n
      });\n
    \n
      // Lose focus for select elements when changed (Allows keyboard shortcuts to work better)\n
      $(\'select\').change(function(){$(this).blur();});\n
    \n
      $(\'#font_family\').change(function() {\n
        svgCanvas.setFontFamily(this.value);\n
      });\n
        \n
      $(\'#text\').keyup(function(){\n
        svgCanvas.setTextContent(this.value);\n
      });\n
      \n
      changeAttribute = function(el, completed) {\n
        var attr = el.getAttribute("data-attr");\n
        var multiplier = el.getAttribute("data-multiplier") || 1;\n
        multiplier = parseFloat(multiplier);\n
        var val = el.value * multiplier;\n
        var valid = svgedit.units.isValidUnit(attr, val, selectedElement);\n
        if(!valid) {\n
          $.alert(uiStrings.notification.invalidAttrValGiven);\n
          el.value = selectedElement.getAttribute(attr);\n
          return false;\n
        }\n
        //if (!noUndo) svgCanvas.changeSelectedAttribute(attr, val);\n
        svgCanvas.changeSelectedAttributeNoUndo(attr, val);\n
      };\n
      \n
      picking = false;\n
      $(document).on("mouseup", function(){picking = false;})\n
\n
      $(\'#palette\').on("mousemove mousedown touchstart touchmove", ".palette_item", function(evt){\n
        evt.preventDefault();\n
\n
        if (evt.type == "mousedown") picking = true;\n
        if (picking) {\n
          var isStroke = $(\'#tool_stroke\').hasClass(\'active\');\n
          var picker = isStroke ? "stroke" : "fill";\n
          var color = $(this).attr(\'data-rgb\');\n
          var paint = null;\n
          var noUndo = true;\n
          if (evt.type == "mousedown") noUndo = false \n
          // Webkit-based browsers returned \'initial\' here for no stroke\n
          if (color === \'transparent\' || color === \'initial\' || color === \'#none\') {\n
            color = \'none\';\n
            paint = new $.jGraduate.Paint();\n
          }\n
          else {\n
            paint = new $.jGraduate.Paint({alpha: 100, solidColor: color.substr(1)});\n
          }\n
          \n
          Editor.paintBox[picker].setPaint(paint);\n
          \n
          if (isStroke) {\n
            svgCanvas.setColor(\'stroke\', color, noUndo);\n
            if (color != \'none\' && svgCanvas.getStrokeOpacity() != 1) {\n
              svgCanvas.setPaintOpacity(\'stroke\', 1.0);\n
            }\n
          } else {\n
            svgCanvas.setColor(\'fill\', color, noUndo);\n
            if (color != \'none\' && svgCanvas.getFillOpacity() != 1) {\n
              svgCanvas.setPaintOpacity(\'fill\', 1.0);\n
            }\n
          }\n
        }\n
      }).bind(\'contextmenu\', function(e) {e.preventDefault()});\n
    \n
      $("#toggle_stroke_tools").toggle(function() {\n
        $(".stroke_tool").css(\'display\',\'table-cell\');\n
        $(this).addClass(\'expanded\');\n
        resetScrollPos();\n
      }, function() {\n
        $(".stroke_tool").css(\'display\',\'none\');\n
        $(this).removeClass(\'expanded\');\n
        resetScrollPos();\n
      });\n
    \n
      // This is a common function used when a tool has been clicked (chosen)\n
      // It does several common things:\n
      // - removes the tool_button_current class from whatever tool currently has it\n
      // - hides any flyouts\n
      // - adds the tool_button_current class to the button passed in\n
      var toolButtonClick = function(button, noHiding) {\n
        if ($(button).hasClass(\'disabled\')) return false;\n
        if($(button).parent().hasClass(\'tools_flyout\')) return true;\n
        var fadeFlyouts = fadeFlyouts || \'normal\';\n
        if(!noHiding) {\n
          $(\'.tools_flyout\').fadeOut(fadeFlyouts);\n
        }\n
        $(\'#styleoverrides\').text(\'\');\n
        $(\'.tool_button_current\').removeClass(\'tool_button_current\').addClass(\'tool_button\');\n
        $(button).addClass(\'tool_button_current\').removeClass(\'tool_button\');\n
        return true;\n
      };\n
      \n
      (function() {\n
        var last_x = null, last_y = null, w_area = workarea[0], \n
          panning = false, keypan = false;\n
        \n
        var move_pan = function(evt) {    \n
            if(panning === false) return;\n
\n
            w_area.scrollLeft -= (evt.clientX - last_x);\n
            w_area.scrollTop -= (evt.clientY - last_y);\n
            last_x = evt.clientX;\n
            last_y = evt.clientY;\n
            if(evt.type === \'mouseup\' || evt.type === \'touchend\') panning = false;\n
            return false;\n
        }\n
        \n
        var start_pan = function(evt) {\n
          if(evt.button === 1 || keypan === true || (evt.originalEvent.touches && evt.originalEvent.touches.length >= 2)) {\n
            panning = true;\n
            last_x = evt.clientX;\n
            last_y = evt.clientY;\n
            return false;\n
          }\n
        }\n
        \n
        $(\'#svgcanvas\')\n
          .on(\'mousemove mouseup touchend\', move_pan)\n
          .on("mousedown touchmove", start_pan)\n
        \n
        $(window).mouseup(function() {\n
          panning = false;\n
        });\n
        \n
        $(document).bind(\'keydown\', \'space\', function(evt) {\n
          evt.preventDefault();\n
          svgCanvas.spaceKey = keypan = true;\n
          \n
        }).bind(\'keyup\', \'space\', function(evt) {\n
          evt.preventDefault();\n
          svgCanvas.spaceKey = keypan = false;\n
        }).bind(\'keydown\', \'alt\', function(evt) {\n
          if(svgCanvas.getMode() === \'zoom\') {\n
            workarea.addClass(\'out\');\n
          }\n
        }).bind(\'keyup\', \'alt\', function(evt) {\n
          if(svgCanvas.getMode() === \'zoom\') {\n
            workarea.removeClass(\'out\');\n
          }\n
        })\n
      }());\n
      \n
      \n
      function setStrokeOpt(opt, changeElem) {\n
        var id = opt.id;\n
        var bits = id.split(\'_\');\n
        var pre = bits[0];\n
        var val = bits[1];\n
      \n
        if(changeElem) {\n
          svgCanvas.setStrokeAttr(\'stroke-\' + pre, val);\n
        }\n
        operaRepaint();\n
        setIcon(\'#cur_\' + pre , id, 20);\n
        $(opt).addClass(\'current\').siblings().removeClass(\'current\');\n
      }\n
      \n
      //menu handling\n
      var menus = $(\'.menu\');\n
      var blinker = function(e) {\n
        e.target.style.background = "#fff";\n
        setTimeout(function(){e.target.style.background = "#ddd";}, 50);\n
        setTimeout(function(){e.target.style.background = "#fff";}, 150);\n
        setTimeout(function(){e.target.style.background = "#ddd";}, 200);\n
        setTimeout(function(){e.target.style.background = "";}, 200);\n
        setTimeout(function(){$(\'#menu_bar\').removeClass(\'active\')}, 220);\n
        return false;\n
      }\n
      var closer = function(e){\n
        if (e.target.nodeName && e.target.nodeName.toLowerCase() === "input") return false;\n
        if (!$(e.target).hasClass("menu_title") && !$(e.target).parent().hasClass("menu_title")) {\n
          if(!$(e.target).hasClass("disabled") && $(e.target).hasClass("menu_item")) blinker(e)\n
          else $(\'#menu_bar\').removeClass(\'active\')\n
\n
        }  \n
      }\n
      \n
      $(\'.menu_item\').on(\'mousedown touchstart\', function(e){blinker(e)});\n
      $("svg, body").on(\'mousedown  touchstart\', function(e){closer(e)});\n
      \n
      var accumulatedDelta = 0\n
      $(\'#workarea\').on(\'mousewheel\', function(e, delta, deltaX, deltaY){\n
        if (e.altKey || e.ctrlKey) {\n
          e.preventDefault();\n
          zoom = parseInt($("#zoom").val())\n
          $("#zoom").val(parseInt(zoom + deltaY*(e.altKey ? 10 : 5))).change()\n
        }\n
      });\n
      \n
      $(\'.menu_title\')\n
        .on(\'mousedown\', function() {\n
          $("#tools_shapelib").hide()\n
          $("#menu_bar").toggleClass(\'active\');\n
          menus.removeClass(\'open\');\n
          $(this).parent().addClass(\'open\');\n
        })\n
        .on(\'mouseover\', function() {\n
           menus.removeClass(\'open\');\n
           $(this).parent().addClass(\'open\');\n
         });\n
\n
      \n
      // Made public for UI customization.\n
      // TODO: Group UI functions into a public methodDraw.ui interface.\n
      Editor.addDropDown = function(elem, callback, dropUp) {\n
        if ($(elem).length == 0) return; // Quit if called on non-existant element\n
        var button = $(elem).find(\'button\');\n
        \n
        var list = $(elem).find(\'ul\').attr(\'id\', $(elem)[0].id + \'-list\');\n
        \n
        if(!dropUp) {\n
          // Move list to place where it can overflow container\n
          $(\'#option_lists\').append(list);\n
        }\n
        \n
        var on_button = false;\n
        if(dropUp) {\n
          $(elem).addClass(\'dropup\');\n
        }\n
      \n
        list.find(\'li\').bind(\'mouseup\', callback);\n
        \n
        $(window).mouseup(function(evt) {\n
          if(!on_button) {\n
            button.removeClass(\'down\');\n
            list.hide();\n
          }\n
          on_button = false;\n
        });\n
        \n
        button.bind(\'mousedown\',function() {\n
          if (!button.hasClass(\'down\')) {\n
            button.addClass(\'down\');\n
            \n
            if(!dropUp) {\n
              var pos = $(elem).offset();\n
              // position slider\n
              list.css({\n
                top: pos.top,\n
                left: pos.left - 110\n
              });\n
            }\n
            list.show();\n
            \n
            on_button = true;\n
          } else {\n
            button.removeClass(\'down\');\n
            list.hide();\n
          }\n
        }).hover(function() {\n
          on_button = true;\n
        }).mouseout(function() {\n
          on_button = false;\n
        });\n
      }\n
      \n
      // TODO: Combine this with addDropDown or find other way to optimize\n
      var addAltDropDown = function(elem, list, callback, opts) {\n
        var button = $(elem);\n
        var list = $(list);\n
        var on_button = false;\n
        var dropUp = opts.dropUp;\n
        if(dropUp) {\n
          $(elem).addClass(\'dropup\');\n
        }\n
        list.find(\'li\').bind(\'mouseup\', function() {\n
          if(opts.seticon) {\n
            setIcon(\'#cur_\' + button[0].id , $(this).children());\n
            $(this).addClass(\'current\').siblings().removeClass(\'current\');\n
          }\n
          callback.apply(this, arguments);\n
\n
        });\n
        \n
        $(window).mouseup(function(evt) {\n
          if(!on_button) {\n
            button.removeClass(\'down\');\n
            list.hide();\n
            list.css({top:0, left:0});\n
          }\n
          on_button = false;\n
        });\n
        \n
        var height = list.height();\n
        $(elem).bind(\'mousedown\',function() {\n
          var off = $(elem).offset();\n
          if(dropUp) {\n
            off.top -= list.height();\n
            off.left += 8;\n
          } else {\n
            off.top += $(elem).height();\n
          }\n
          $(list).offset(off);\n
          \n
          if (!button.hasClass(\'down\')) {\n
            button.addClass(\'down\');\n
            list.show();\n
            on_button = true;\n
            return false;\n
          } else {\n
            button.removeClass(\'down\');\n
            // CSS position must be reset for Webkit\n
            list.hide();\n
            list.css({top:0, left:0});\n
          }\n
        }).hover(function() {\n
          on_button = true;\n
        }).mouseout(function() {\n
          on_button = false;\n
        });\n
        \n
        if(opts.multiclick) {\n
          list.mousedown(function() {\n
            on_button = true;\n
          });\n
        }\n
      }\n
      \n
      $(\'#font_family_dropdown\').change(function() {\n
        var fam = this.options[this.selectedIndex].value\n
        var fam_display = this.options[this.selectedIndex].text\n
        $(\'#preview_font\').html(fam_display).css("font-family", fam);\n
        $(\'#font_family\').val(fam).change();\n
      });\n
      \n
      $(\'div\', \'#position_opts\').each(function(){\n
        this.addEventListener("mouseup", function(){\n
          var letter = this.id.replace(\'tool_pos\',\'\').charAt(0);\n
          svgCanvas.alignSelectedElements(letter, \'page\');\n
        })\n
      });\n
      \n
      /*\n
      \n
      When a flyout icon is selected\n
        (if flyout) {\n
        - Change the icon\n
        - Make pressing the button run its stuff\n
        }\n
        - Run its stuff\n
      \n
      When its shortcut key is pressed\n
        - If not current in list, do as above\n
        , else:\n
        - Just run its stuff\n
      \n
      */\n
      \n
      // Unfocus text input when workarea is mousedowned.\n
      (function() {\n
        var inp;\n
        var unfocus = function() {\n
          $(inp).blur();\n
        }\n
        \n
        $(\'#svg_editor\').find(\'button, select, input:not(#text)\').focus(function() {\n
          inp = this;\n
          ui_context = \'toolbars\';\n
          workarea.mousedown(unfocus);\n
        }).blur(function() {\n
          ui_context = \'canvas\';\n
          workarea.unbind(\'mousedown\', unfocus);\n
          // Go back to selecting text if in textedit mode\n
          if(svgCanvas.getMode() == \'textedit\') {\n
            $(\'#text\').focus();\n
          }\n
        });\n
        \n
      }());\n
\n
      var clickSelect = function() {\n
        if (toolButtonClick(\'#tool_select\')) {\n
          svgCanvas.setMode(\'select\');\n
        }\n
      };\n
    \n
      var clickFHPath = function() {\n
        if (toolButtonClick(\'#tool_fhpath\')) {\n
          svgCanvas.setMode(\'fhpath\');\n
        }\n
      };\n
    \n
      var clickLine = function() {\n
        if (toolButtonClick(\'#tool_line\')) {\n
          svgCanvas.setMode(\'line\');\n
        }\n
      };\n
    \n
      var clickSquare = function(){\n
        if (toolButtonClick(\'#tool_square\')) {\n
          svgCanvas.setMode(\'square\');\n
        }\n
      };\n
      \n
      var clickRect = function(){\n
        if (toolButtonClick(\'#tool_rect\')) {\n
          svgCanvas.setMode(\'rect\');\n
        }\n
      };\n
      \n
      var clickFHRect = function(){\n
        if (toolButtonClick(\'#tool_fhrect\')) {\n
          svgCanvas.setMode(\'fhrect\');\n
        }\n
      };\n
      \n
      var clickCircle = function(){\n
        if (toolButtonClick(\'#tool_circle\')) {\n
          svgCanvas.setMode(\'circle\');\n
        }\n
      };\n
    \n
      var clickEllipse = function(){\n
        if (toolButtonClick(\'#tool_ellipse\')) {\n
          svgCanvas.setMode(\'ellipse\');\n
        }\n
      };\n
    \n
      var clickFHEllipse = function(){\n
        if (toolButtonClick(\'#tool_fhellipse\')) {\n
          svgCanvas.setMode(\'fhellipse\');\n
        }\n
      };\n
      \n
      var clickImage = function(){\n
        if (toolButtonClick(\'#tool_image\')) {\n
          svgCanvas.setMode(\'image\');\n
        }\n
      };\n
    \n
      var clickZoom = function(){\n
        if (toolButtonClick(\'#tool_zoom\')) {\n
          svgCanvas.setMode(\'zoom\');\n
        }\n
      };\n
    \n
      var dblclickZoom = function(){\n
        if (toolButtonClick(\'#tool_zoom\')) {\n
          zoomImage();\n
          setSelectMode();\n
        }\n
      };\n
    \n
      var clickText = function(){\n
        if (toolButtonClick(\'#tool_text\')) {\n
          svgCanvas.setMode(\'text\');\n
        }\n
      };\n
      \n
      var clickPath = function(){\n
        if (toolButtonClick(\'#tool_path\')) {\n
          svgCanvas.setMode(\'path\');\n
        }\n
      };\n
\n
      // Delete is a contextual tool that only appears in the ribbon if\n
      // an element has been selected\n
      var deleteSelected = function() {\n
        if (selectedElement != null || multiselected) {\n
          svgCanvas.deleteSelectedElements();\n
        }\n
        if (path.getNodePoint()) {\n
          path.deletePathNode();\n
        }\n
      };\n
    \n
      var cutSelected = function() {\n
        if (selectedElement != null || multiselected) {\n
          flash($(\'#edit_menu\'));\n
          svgCanvas.cutSelectedElements();\n
        }\n
      };\n
      \n
      var copySelected = function() {\n
        if (selectedElement != null || multiselected) {\n
          flash($(\'#edit_menu\'));\n
          svgCanvas.copySelectedElements();\n
        }\n
      };\n
      \n
      var pasteSelected = function() {\n
        flash($(\'#edit_menu\'));\n
        var zoom = svgCanvas.getZoom();       \n
        var x = (workarea[0].scrollLeft + workarea.width()/2)/zoom  - svgCanvas.contentW; \n
        var y = (workarea[0].scrollTop + workarea.height()/2)/zoom  - svgCanvas.contentH;\n
        svgCanvas.pasteElements(\'point\', x, y); \n
      }\n
      \n
      var moveToTopSelected = function() {\n
        if (selectedElement != null) {\n
          flash($(\'#object_menu\'));\n
          svgCanvas.moveToTopSelectedElement();\n
        }\n
      };\n
      \n
      var moveToBottomSelected = function() {\n
        if (selectedElement != null) {\n
          flash($(\'#object_menu\'));\n
          svgCanvas.moveToBottomSelectedElement();\n
        }\n
      };\n
      \n
      var moveUpSelected = function() {\n
        if (selectedElement != null) {\n
        flash($(\'#object_menu\'));\n
          svgCanvas.moveUpDownSelected("Up");\n
        }\n
      };\n
\n
      var moveDownSelected = function() {\n
        if (selectedElement != null) {\n
          flash($(\'#object_menu\'));\n
          svgCanvas.moveUpDownSelected("Down");\n
        }\n
      };\n
      \n
      var moveUpDownSelected = function(dir) {\n
        if (selectedElement != null) {\n
          flash($(\'#object_menu\'));\n
          svgCanvas.moveUpDownSelected(dir);\n
        }\n
      };\n
\n
      var convertToPath = function() {\n
        if (selectedElement != null) {\n
          svgCanvas.convertToPath();\n
          var elems = svgCanvas.getSelectedElems()\n
          svgCanvas.selectorManager.requestSelector(elems[0]).reset(elems[0])\n
          svgCanvas.selectorManager.requestSelector(elems[0]).selectorRect.setAttribute("display", "none");\n
          svgCanvas.setMode("pathedit")\n
          path.toEditMode(elems[0]);\n
          svgCanvas.clearSelection();\n
          updateContextPanel();\n
        }\n
      }\n
      \n
      var reorientPath = function() {\n
        if (selectedElement != null) {\n
          path.reorient();\n
        }\n
      }\n
    \n
      var makeHyperlink = function() {\n
        if (selectedElement != null || multiselected) {\n
          $.prompt(uiStrings.notification.enterNewLinkURL, "http://", function(url) {\n
            if(url) svgCanvas.makeHyperlink(url);\n
          });\n
        }\n
      }\n
    \n
      var moveSelected = function(dx,dy) {\n
        if (selectedElement != null || multiselected) {\n
          if(curConfig.gridSnapping) {\n
            // Use grid snap value regardless of zoom level\n
            var multi = svgCanvas.getZoom() * curConfig.snappingStep;\n
            dx *= multi;\n
            dy *= multi;\n
          }\n
          $(\'input\').blur()\n
          svgCanvas.moveSelectedElements(dx,dy);\n
        }\n
      };\n
    \n
      var linkControlPoints = function() {\n
      //  var linked = document.getElementById(\'tool_node_link\').checked;\n
      //  path.linkControlPoints(linked);\n
      }\n
    \n
      var clonePathNode = function() {\n
        if (path.getNodePoint()) {\n
          path.clonePathNode();\n
        }\n
      };\n
      \n
      var deletePathNode = function() {\n
        if (path.getNodePoint()) {\n
          path.deletePathNode();\n
        }\n
      };\n
    \n
      var addSubPath = function() {\n
        var button = $(\'#tool_add_subpath\');\n
        var sp = !button.hasClass(\'push_button_pressed\');\n
        if (sp) {\n
          button.addClass(\'push_button_pressed\').removeClass(\'tool_button\');\n
        } else {\n
          button.removeClass(\'push_button_pressed\').addClass(\'tool_button\');\n
        }\n
        \n
        path.addSubPath(sp);\n
        \n
      };\n
    \n
      var opencloseSubPath = function() {\n
        path.opencloseSubPath();\n
      } \n
      \n
      var selectNext = function() {\n
        svgCanvas.cycleElement(1);\n
      };\n
      \n
      var selectPrev = function() {\n
        svgCanvas.cycleElement(0);\n
      };\n
      \n
      var rotateSelected = function(cw,step) {\n
        if (selectedElement == null || multiselected) return;\n
        if(!cw) step *= -1;\n
        var new_angle = $(\'#angle\').val()*1 + step;\n
        svgCanvas.setRotationAngle(new_angle);\n
        updateContextPanel();\n
      };\n
      \n
      var clickClear = function(){\n
        var dims = curConfig.dimensions;\n
        $.confirm(uiStrings.notification.QwantToClear, function(ok) {\n
          if(!ok) return;\n
          setSelectMode();\n
          svgCanvas.clear();\n
          svgCanvas.setResolution(dims[0], dims[1]);\n
          updateCanvas(true);\n
          zoomImage();\n
          updateContextPanel();\n
          prepPaints();\n
          svgCanvas.runExtensions(\'onNewDocument\');\n
        });\n
      };\n
      \n
      var clickBold = function(){\n
        svgCanvas.setBold( !svgCanvas.getBold() );\n
        updateContextPanel();\n
      };\n
      \n
      var clickItalic = function(){\n
        svgCanvas.setItalic( !svgCanvas.getItalic() );\n
        updateContextPanel();\n
      };\n
      \n
      var clickExport = function() {\n
        // Open placeholder window (prevents popup)\n
        if(!customHandlers.pngsave)  {\n
          var str = uiStrings.notification.loadingImage;\n
          exportWindow = window.open("data:text/html;charset=utf-8,<title>" + str + "<\\/title><h1>" + str + "<\\/h1>");\n
        }\n
\n
        if(window.canvg) {\n
          svgCanvas.rasterExport();\n
        } else {\n
          $.getScript(\'canvg/rgbcolor.js\', function() {\n
            $.getScript(\'canvg/canvg.js\', function() {\n
              svgCanvas.rasterExport();\n
            });\n
          });\n
        }\n
      }\n
      \n
      // by default, svgCanvas.open() is a no-op.\n
      // it is up to an extension mechanism (opera widget, etc) \n
      // to call setCustomHandlers() which will make it do something\n
      var clickOpen = function(){\n
        svgCanvas.open();\n
      };\n
      var clickImport = function(){\n
      };\n
      \n
      var flash = function($menu){\n
        var menu_title = $menu.prev();\n
        menu_title.css({\n
          "background": "white",\n
          "color": "black"\n
        });\n
        setTimeout(function(){menu_title.removeAttr("style")}, 200);\n
      }\n
      \n
      var clickUndo = function(){\n
        if (undoMgr.getUndoStackSize() > 0) {\n
          flash($(\'#edit_menu\'));\n
          undoMgr.undo();\n
        }\n
      };\n
    \n
      var clickRedo = function(){\n
        if (undoMgr.getRedoStackSize() > 0) {\n
          flash($(\'#edit_menu\'));\n
          undoMgr.redo();\n
        }\n
      };\n
      \n
      var clickGroup = function(){\n
        // group\n
        if (multiselected) {\n
          flash($(\'#object_menu\'));\n
          svgCanvas.groupSelectedElements();\n
        }\n
        // ungroup\n
        else if(selectedElement){\n
          flash($(\'#object_menu\'));\n
          svgCanvas.ungroupSelectedElement();\n
        }\n
      };\n
      \n
      var clickClone = function(){\n
        flash($(\'#edit_menu\'));\n
        svgCanvas.cloneSelectedElements(20,20);\n
      };\n
      \n
      var clickAlign = function() {\n
        var let

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

ter = this.id.replace(\'tool_align\',\'\').charAt(0);\n
        svgCanvas.alignSelectedElements(letter, $(\'#align_relative_to\').val());\n
      };\n
      \n
      var clickSwitch = function() {\n
        var stroke_rect = document.querySelector(\'#tool_stroke rect\');\n
        $("#tool_stroke").toggleClass(\'active\')\n
        $("#tool_fill").toggleClass(\'active\')\n
        var fill_rect = document.querySelector(\'#tool_fill rect\');\n
        var fill_color = fill_rect.getAttribute("fill");\n
        var stroke_color = stroke_rect.getAttribute("fill");\n
        var stroke_opacity = parseFloat(stroke_rect.getAttribute("stroke-opacity"));\n
        if (isNaN(stroke_opacity)) {stroke_opacity = 100;}\n
        var fill_opacity = parseFloat(fill_rect.getAttribute("fill-opacity"));\n
        if (isNaN(fill_opacity)) {fill_opacity = 100;}\n
        var stroke = getPaint(stroke_color, stroke_opacity, "stroke");\n
        var fill = getPaint(fill_color, fill_opacity, "fill");\n
        Editor.paintBox.fill.setPaint(stroke, true);\n
        Editor.paintBox.stroke.setPaint(fill, true);\n
        \n
      };\n
      \n
      var zoomImage = function(multiplier) {\n
        var res = svgCanvas.getResolution();\n
        multiplier = multiplier?res.zoom * multiplier:1;\n
    //    setResolution(res.w * multiplier, res.h * multiplier, true);\n
        $(\'#zoom\').val(multiplier * 100);\n
        svgCanvas.setZoom(multiplier);\n
        zoomDone();\n
        updateCanvas(true);\n
      };\n
      \n
      var zoomDone = function() {\n
    //    updateBgImage();\n
        updateWireFrame();\n
        //updateCanvas(); // necessary?\n
      }\n
    \n
      var clickWireframe = function() {\n
        flash($(\'#view_menu\'));\n
        var wf = !$(\'#tool_wireframe\').hasClass(\'push_button_pressed\');\n
        if (wf) \n
          $(\'#tool_wireframe\').addClass(\'push_button_pressed\');\n
        else\n
          $(\'#tool_wireframe\').removeClass(\'push_button_pressed\');\n
        workarea.toggleClass(\'wireframe\');\n
        \n
        if(supportsNonSS) return;\n
        var wf_rules = $(\'#wireframe_rules\');\n
        if(!wf_rules.length) {\n
          wf_rules = $(\'<style id="wireframe_rules"><\\/style>\').appendTo(\'head\');\n
        } else {\n
          wf_rules.empty();\n
        }\n
        \n
        updateWireFrame();\n
      }\n
      \n
      var clickSnapGrid = function() {\n
        flash($(\'#view_menu\'));\n
        var sg = !$(\'#tool_snap\').hasClass(\'push_button_pressed\');\n
        if (sg) \n
          $(\'#tool_snap\').addClass(\'push_button_pressed\');\n
        else\n
          $(\'#tool_snap\').removeClass(\'push_button_pressed\');   \n
        curConfig.gridSnapping = sg;\n
      }\n
      \n
      var minimizeModal = function() {\n
        \n
        if (window.self != window.top) { //we\'re in an iframe\n
          top.exit_fullscreen();\n
        }\n
      }\n
      \n
      var clickRulers = function() {\n
        flash($(\'#view_menu\'));\n
        var rulers = !$(\'#tool_rulers\').hasClass(\'push_button_pressed\');\n
        if (rulers) {\n
          $(\'#tool_rulers\').addClass(\'push_button_pressed\');\n
          $(\'#show_rulers\').attr("checked", true);\n
          curConfig.showRulers = true;\n
        }\n
        else {\n
          $(\'#tool_rulers\').removeClass(\'push_button_pressed\');\n
          $(\'#show_rulers\').attr("checked", false);\n
          curConfig.showRulers = false;\n
        }\n
        $(\'#rulers\').toggle(!!curConfig.showRulers)\n
      }\n
      \n
      var updateWireFrame = function() {\n
        // Test support\n
        if(supportsNonSS) return;\n
    \n
        var rule = "#workarea.wireframe #svgcontent * { stroke-width: " + 1/svgCanvas.getZoom() + "px; }";\n
        $(\'#wireframe_rules\').text(workarea.hasClass(\'wireframe\') ? rule : "");\n
      }\n
    \n
      var showSourceEditor = function(e, forSaving){\n
        if (editingsource) return;\n
        flash($(\'#view_menu\'));\n
        editingsource = true;\n
        \n
        $(\'#save_output_btns\').toggle(!!forSaving);\n
        $(\'#tool_source_back\').toggle(!forSaving);\n
        \n
        var str = orig_source = svgCanvas.getSvgString();\n
        $(\'#svg_source_textarea\').val(str);\n
        $(\'#svg_source_editor\').fadeIn();\n
        $(\'#svg_source_textarea\').focus().select();\n
      };\n
      \n
      var clickSave = function(){\n
        flash($(\'#file_menu\'));\n
        // In the future, more options can be provided here\n
        var saveOpts = {\n
          \'images\': curPrefs.img_save,\n
          \'round_digits\': 6\n
        }\n
        svgCanvas.save(saveOpts);\n
      };\n
      \n
      var saveSourceEditor = function(){\n
        if (!editingsource) return;\n
    \n
        var saveChanges = function() {\n
          svgCanvas.clearSelection();\n
          hideSourceEditor();\n
          zoomImage();\n
          prepPaints();\n
        }\n
    \n
        if (!svgCanvas.setSvgString($(\'#svg_source_textarea\').val())) {\n
          $.confirm(uiStrings.notification.QerrorsRevertToSource, function(ok) {\n
            if(!ok) return false;\n
            saveChanges();\n
          });\n
        } else {\n
          saveChanges();\n
        }\n
        setSelectMode();    \n
      };\n
      \n
      function setBackground(color, url) {\n
//        if(color == curPrefs.bkgd_color && url == curPrefs.bkgd_url) return;\n
        $.pref(\'bkgd_color\', color);\n
        $.pref(\'bkgd_url\', url);\n
        \n
        // This should be done in svgcanvas.js for the borderRect fill\n
        svgCanvas.setBackground(color, url);\n
      }\n
      \n
      var setIcon = Editor.setIcon = function(elem, icon_id, forcedSize) {\n
        var icon = (typeof icon_id === \'string\') ? $.getSvgIcon(icon_id, true) : icon_id.clone();\n
        if(!icon) {\n
          console.log(\'NOTE: Icon image missing: \' + icon_id);\n
          return;\n
        }\n
\n
        $(elem).find("img").replaceWith(icon);\n
      }\n
    \n
      var ua_prefix;\n
      (ua_prefix = function() {\n
        var regex = /^(Moz|Webkit|Khtml|O|ms|Icab)(?=[A-Z])/;\n
        var someScript = document.getElementsByTagName(\'script\')[0];\n
        for(var prop in someScript.style) {\n
          if(regex.test(prop)) {\n
            // test is faster than match, so it\'s better to perform\n
            // that on the lot and match only when necessary\n
            return prop.match(regex)[0];\n
          }\n
        }\n
      \n
        // Nothing found so far?\n
        if(\'WebkitOpacity\' in someScript.style) return \'Webkit\';\n
        if(\'KhtmlOpacity\' in someScript.style) return \'Khtml\';\n
        \n
        return \'\';\n
      }());\n
      \n
      var scaleElements = function(elems, scale) {\n
        var prefix = \'-\' + ua_prefix.toLowerCase() + \'-\';\n
        \n
        var sides = [\'top\', \'left\', \'bottom\', \'right\'];\n
      \n
        elems.each(function() {\n
//          console.log(\'go\', scale);\n
\n
          // Handled in CSS\n
          // this.style[ua_prefix + \'Transform\'] = \'scale(\' + scale + \')\';\n
        \n
          var el = $(this);\n
          \n
          var w = el.outerWidth() * (scale - 1);\n
          var h = el.outerHeight() * (scale - 1);\n
          var margins = {};\n
          \n
          for(var i = 0; i < 4; i++) {\n
            var s = sides[i];\n
            \n
            var cur = el.data(\'orig_margin-\' + s);\n
            if(cur == null) {\n
              cur = parseInt(el.css(\'margin-\' + s));\n
              // Cache the original margin\n
              el.data(\'orig_margin-\' + s, cur);\n
            }\n
            var val = cur * scale;\n
            if(s === \'right\') {\n
              val += w;\n
            } else if(s === \'bottom\') {\n
              val += h;\n
            }\n
            \n
            el.css(\'margin-\' + s, val);\n
//            el.css(\'outline\', \'1px solid red\');\n
          }\n
        });\n
      }\n
      \n
      var setIconSize = Editor.setIconSize = function(size, force) {\n
        if(size == curPrefs.size && !force) return;\n
//        return;\n
//        var elems = $(\'.tool_button, .push_button, .tool_button_current, .disabled, .icon_label, #url_notice, #tool_open\');\n
        \n
        var sel_toscale = \'#tools_top .toolset, #editor_panel > *, #history_panel > *,\\\n
        #main_button, #tools_left > *, #path_node_panel > *, #multiselected_panel > *,\\\n
        #g_panel > *, #tool_font_size > *, .tools_flyout\';\n
        \n
        var elems = $(sel_toscale);\n
        \n
        var scale = 1;\n
        \n
        if(typeof size == \'number\') {\n
          scale = size;\n
        } else {\n
          var icon_sizes = { s:.75, m:1, l:1.25, xl:1.5 };\n
          scale = icon_sizes[size];\n
        }\n
        \n
        Editor.tool_scale = tool_scale = scale;\n
        \n
        setFlyoutPositions();       \n
        var hidden_ps = elems.parents(\':hidden\');\n
        hidden_ps.css(\'visibility\', \'hidden\').show();\n
        scaleElements(elems, scale);\n
        hidden_ps.css(\'visibility\', \'visible\').hide();\n
        \n
        var rule_elem = $(\'#tool_size_rules\');\n
        if(!rule_elem.length) {\n
          rule_elem = $(\'<style id="tool_size_rules"><\\/style>\').appendTo(\'head\');\n
        } else {\n
          rule_elem.empty();\n
        }\n
        \n
        if(size != \'m\') {\n
          var style_str = \'\';\n
          $.each(cssResizeRules, function(selector, rules) {\n
            selector = \'#svg_editor \' + selector.replace(/,/g,\', #svg_editor\');\n
            style_str += selector + \'{\';\n
            $.each(rules, function(prop, values) {\n
              if(typeof values === \'number\') {\n
                var val = (values * scale) + \'px\';\n
              } else if(values[size] || values.all) {\n
                var val = (values[size] || values.all);\n
              }\n
              style_str += (prop + \':\' + val + \';\');\n
            });\n
            style_str += \'}\';\n
          });\n
          //this.style[ua_prefix + \'Transform\'] = \'scale(\' + scale + \')\';\n
          var prefix = \'-\' + ua_prefix.toLowerCase() + \'-\';\n
          style_str += (sel_toscale + \'{\' + prefix + \'transform: scale(\' + scale + \');}\'\n
          + \' #svg_editor div.toolset .toolset {\' + prefix + \'transform: scale(1); margin: 1px !important;}\' // Hack for markers\n
          + \' #svg_editor .ui-slider {\' + prefix + \'transform: scale(\' + (1/scale) + \');}\' // Hack for sliders\n
          );\n
          rule_elem.text(style_str);\n
        }\n
        \n
        setFlyoutPositions();\n
      }\n
    \n
      var cancelOverlays = function() {\n
        $(\'#dialog_box\').hide();\n
        if (!editingsource && !docprops && !preferences) {\n
          if(cur_context) {\n
            svgCanvas.leaveContext();\n
          }\n
          return;\n
        };\n
    \n
        if (editingsource) {\n
          if (orig_source !== $(\'#svg_source_textarea\').val()) {\n
            $.confirm(uiStrings.notification.QignoreSourceChanges, function(ok) {\n
              if(ok) hideSourceEditor();\n
            });\n
          } else {\n
            hideSourceEditor();\n
          }\n
        }\n
        else if (docprops) {\n
          hideDocProperties();\n
        } else if (preferences) {\n
          hidePreferences();\n
        }\n
        resetScrollPos();\n
      };\n
    \n
      var hideSourceEditor = function(){\n
        $(\'#svg_source_editor\').hide();\n
        editingsource = false;\n
        $(\'#svg_source_textarea\').blur();\n
      };\n
\n
      var win_wh = {width:$(window).width(), height:$(window).height()};\n
      \n
      var resetScrollPos = $.noop, curScrollPos;\n
      \n
      /* Fix for Issue 781: Drawing area jumps to top-left corner on window resize (IE9)\n
      if(svgedit.browser.isIE()) {\n
        (function() {\n
          resetScrollPos = function() {\n
            if(workarea[0].scrollLeft === 0 \n
            && workarea[0].scrollTop === 0) {\n
              workarea[0].scrollLeft = curScrollPos.left;\n
              workarea[0].scrollTop = curScrollPos.top;\n
            }\n
          }\n
        \n
          curScrollPos = {\n
            left: workarea[0].scrollLeft,\n
            top: workarea[0].scrollTop\n
          };\n
          \n
          $(window).resize(resetScrollPos);\n
          methodDraw.ready(function() {\n
            // TODO: Find better way to detect when to do this to minimize\n
            // flickering effect\n
            setTimeout(function() {\n
              resetScrollPos();\n
            }, 500);\n
          });\n
          \n
          workarea.scroll(function() {\n
            curScrollPos = {\n
              left: workarea[0].scrollLeft,\n
              top: workarea[0].scrollTop\n
            };\n
          });\n
        }());\n
      }*/\n
      \n
      $(window).resize(function(evt) {\n
          updateCanvas();\n
      });\n
      \n
      (function() {\n
        workarea.scroll(function() {\n
          // TODO:  jQuery\'s scrollLeft/Top() wouldn\'t require a null check\n
          if ($(\'#ruler_x\').length != 0) {\n
            $(\'#ruler_x\')[0].scrollLeft = workarea[0].scrollLeft;\n
          }\n
          if ($(\'#ruler_y\').length != 0) {\n
            $(\'#ruler_y\')[0].scrollTop = workarea[0].scrollTop; \n
          }\n
        });\n
\n
      }());\n
      \n
      $(\'#url_notice\').click(function() {\n
        $.alert(this.title);\n
      });\n
      \n
      $(\'#change_image_url\').click(promptImgURL);\n
      \n
      function promptImgURL() {\n
        var curhref = svgCanvas.getHref(selectedElement);\n
        curhref = curhref.indexOf("data:") === 0?"":curhref;\n
        $.prompt(uiStrings.notification.enterNewImgURL, curhref, function(url) {\n
          if(url) setImageURL(url);\n
        });\n
      }\n
      \n
      // TODO: go back to the color boxes having white background-color and then setting\n
      //       background-image to none.png (otherwise partially transparent gradients look weird)  \n
      var colorPicker = function(elem) {\n
        var picker = elem[0].id == \'stroke_color\' ? \'stroke\' : \'fill\';\n
        var is_background = elem[0].id == "canvas_color"\n
        if (is_background) picker = \'canvas\'\n
//        var opacity = (picker == \'stroke\' ? $(\'#stroke_opacity\') : $(\'#fill_opacity\'));\n
        var paint = Editor.paintBox[picker].paint;\n
        \n
        var title = (picker == \'stroke\' ? \'Pick a Stroke Paint and Opacity\' : \'Pick a Fill Paint and Opacity\');\n
        var was_none = false;\n
        var pos = is_background ? {\'right\': 175, \'top\': 50} : {\'left\': 50, \'bottom\': 50}\n
        \n
        $("#color_picker")\n
          .draggable({cancel:\'.jGraduate_tabs, .jGraduate_colPick, .jGraduate_gradPick, .jPicker\', containment: \'window\'})\n
          .removeAttr("style")\n
          .css(pos)\n
          .jGraduate(\n
          { \n
            paint: paint,\n
            window: { pickerTitle: title },\n
            images: { clientPath: curConfig.jGraduatePath },\n
            newstop: \'inverse\'\n
          },\n
          function(p) {\n
            paint = new $.jGraduate.Paint(p);\n
            \n
            Editor.paintBox[picker].setPaint(paint);\n
            svgCanvas.setPaint(picker, paint);\n
            \n
            $(\'#color_picker\').hide();\n
          },\n
          function(p) {\n
            $(\'#color_picker\').hide();\n
          });\n
      };\n
    \n
      var PaintBox = function(container, type) {\n
        var background = document.getElementById("canvas_background");\n
        var cur = {color: "fff", opacity: 1}\n
        if (type == "stroke") cur = curConfig[\'initStroke\'];\n
        if (type == "fill") cur = curConfig[\'initFill\'];\n
        if (type == "canvas" && background) {\n
              var rgb = background.getAttribute("fill").match(/^rgb\\((\\d+),\\s*(\\d+),\\s*(\\d+)\\)$/);\n
              if (rgb) {\n
                var hex =   ("0" + parseInt(rgb[1],10).toString(16)).slice(-2) +\n
                              ("0" + parseInt(rgb[2],10).toString(16)).slice(-2) +\n
                              ("0" + parseInt(rgb[3],10).toString(16)).slice(-2);\n
                cur = {color: hex, opacity: 1}\n
              }\n
        }\n
\n
        // set up gradients to be used for the buttons\n
        var svgdocbox = new DOMParser().parseFromString(\n
          \'<svg xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%"\\\n
          fill="#\' + cur.color + \'" opacity="\' + cur.opacity + \'"/>\\\n
          <defs><linearGradient id="gradbox_"/></defs></svg>\', \'text/xml\');\n
        var docElem = svgdocbox.documentElement;\n
        \n
        docElem = $(container)[0].appendChild(document.importNode(docElem, true));\n
        if (type === \'canvas\') docElem.setAttribute(\'width\',60.5);\n
        else docElem.setAttribute(\'width\',"100%");\n
        \n
        this.rect = docElem.firstChild;\n
        this.defs = docElem.getElementsByTagName(\'defs\')[0];\n
        this.grad = this.defs.firstChild;\n
        this.paint = new $.jGraduate.Paint({solidColor: cur.color});\n
        this.type = type;\n
\n
        this.setPaint = function(paint, apply, noUndo) {\n
          this.paint = paint;\n
          var fillAttr = "none";\n
          var ptype = paint.type;\n
          var opac = paint.alpha / 100;\n
          switch ( ptype ) {\n
            case \'solidColor\':\n
              fillAttr = (paint[ptype] == \'none\' || paint[ptype] == \'one\') ? \'none\' : "#" + paint[ptype];\n
              break;\n
            case \'linearGradient\':\n
            case \'radialGradient\':\n
              this.defs.removeChild(this.grad);\n
              this.grad = this.defs.appendChild(paint[ptype]);\n
              var id = this.grad.id = \'gradbox_\' + this.type;\n
              fillAttr = "url(#" + id + \')\';\n
          }\n
          this.rect.setAttribute(\'fill\', fillAttr);\n
          this.rect.setAttribute(\'opacity\', opac);\n
\n
          if (this.type == "canvas") {\n
            //recache background in case it changed\n
            var background = document.getElementById("canvas_background");\n
            if (background) {\n
              res = svgCanvas.getResolution()\n
              background.setAttribute("x", -1);\n
              background.setAttribute("y", -1);\n
              background.setAttribute("width", res.w+2);\n
              background.setAttribute("height", res.h+2);\n
              if (fillAttr.indexOf("url") == -1) background.setAttribute(\'fill\', fillAttr)\n
            }\n
            else createBackground(fillAttr)\n
          }\n
          \n
          if(apply) {\n
            svgCanvas.setColor(this.type, fillAttr, true);\n
            svgCanvas.setPaintOpacity(this.type, opac, true);\n
          }\n
          \n
        }\n
        \n
        this.update = function(apply) {\n
          if(!selectedElement) return;\n
          var type = this.type;\n
          switch ( selectedElement.tagName ) {\n
          case \'use\':\n
          case \'image\':\n
          case \'foreignObject\':\n
            // These elements don\'t have fill or stroke, so don\'t change \n
            // the current value\n
            return;\n
          case \'g\':\n
          case \'a\':\n
            var gPaint = null;\n
          \n
            var childs = selectedElement.getElementsByTagName(\'*\');\n
            for(var i = 0, len = childs.length; i < len; i++) {\n
              var elem = childs[i];\n
              var p = elem.getAttribute(type);\n
              if(i === 0) {\n
                gPaint = p;\n
              } else if(gPaint !== p) {\n
                gPaint = null;\n
                break;\n
              }\n
            }\n
            if(gPaint === null) {\n
              // No common color, don\'t update anything\n
              var paintColor = null;\n
              return;\n
            }\n
            var paintColor = gPaint;\n
            \n
            var paintOpacity = 1;\n
            break;\n
          default:\n
            var paintOpacity = parseFloat(selectedElement.getAttribute(type + "-opacity"));\n
            if (isNaN(paintOpacity)) {\n
              paintOpacity = 1.0;\n
            }\n
            \n
            var defColor = type === "fill" ? "black" : "none";\n
            var paintColor = selectedElement.getAttribute(type) || defColor;\n
          }\n
          if(apply) {\n
            svgCanvas.setColor(type, paintColor, true);\n
            svgCanvas.setPaintOpacity(type, paintOpacity, true);\n
          }\n
\n
          paintOpacity *= 100;          \n
          \n
          var paint = getPaint(paintColor, paintOpacity, type);\n
          // update the rect inside #fill_color/#stroke_color\n
          this.setPaint(paint);\n
        }\n
        \n
        this.prep = function() {\n
          var ptype = this.paint.type;\n
        \n
          switch ( ptype ) {\n
            case \'linearGradient\':\n
            case \'radialGradient\':\n
              var paint = new $.jGraduate.Paint({copy: this.paint});\n
              svgCanvas.setPaint(type, paint);\n
          }\n
        }\n
      };\n
      \n
      Editor.paintBox.fill = new PaintBox(\'#fill_color\', \'fill\');\n
      Editor.paintBox.stroke = new PaintBox(\'#stroke_color\', \'stroke\');\n
      Editor.paintBox.canvas = new PaintBox(\'#canvas_color\', \'canvas\');\n
\n
      $(\'#stroke_width\').val(curConfig.initStroke.width);\n
      $(\'#group_opacity\').val(curConfig.initOpacity * 100);\n
      \n
      // Use this SVG elem to test vectorEffect support\n
      var test_el = Editor.paintBox.fill.rect.cloneNode(false);\n
      test_el.setAttribute(\'style\',\'vector-effect:non-scaling-stroke\');\n
      var supportsNonSS = (test_el.style.vectorEffect === \'non-scaling-stroke\');\n
      test_el.removeAttribute(\'style\');\n
      var svgdocbox = Editor.paintBox.fill.rect.ownerDocument;\n
      // Use this to test support for blur element. Seems to work to test support in Webkit\n
      var blur_test = svgdocbox.createElementNS(\'http://www.w3.org/2000/svg\', \'feGaussianBlur\');\n
      if(typeof blur_test.stdDeviationX === "undefined") {\n
        $(\'#tool_blur\').hide();\n
      }\n
      $(blur_test).remove();\n
\n
      \n
      \n
      // Test for embedImage support (use timeout to not interfere with page load)\n
      setTimeout(function() {\n
        svgCanvas.embedImage(\'images/placeholder.svg\', function(datauri) {\n
          if(!datauri) {\n
            // Disable option\n
            $(\'#image_save_opts [value=embed]\').attr(\'disabled\',\'disabled\');\n
            $(\'#image_save_opts input\').val([\'ref\']);\n
            curPrefs.img_save = \'ref\';\n
            $(\'#image_opt_embed\').css(\'color\',\'#666\').attr(\'title\',uiStrings.notification.featNotSupported);\n
          }\n
        });\n
      },1000);\n
        \n
      $(\'#tool_fill\').click(function(){\n
        if ($(\'#tool_fill\').hasClass(\'active\')) {\n
          colorPicker($(\'#fill_color\'));\n
        }\n
        else {\n
          $(\'#tool_fill\').addClass(\'active\');\n
          $("#tool_stroke").removeClass(\'active\');\n
        }\n
      });\n
      \n
      $(\'#tool_stroke\').on("click", function(){\n
        if ($(\'#tool_stroke\').hasClass(\'active\')) {\n
          colorPicker($(\'#stroke_color\'));\n
        }\n
        else {\n
          $(\'#tool_stroke\').addClass(\'active\');\n
          $("#tool_fill").removeClass(\'active\');\n
        }\n
      });\n
      \n
      $(\'#tool_canvas\').on("click touchstart", function(){\n
          colorPicker($(\'#canvas_color\'));\n
      });\n
      \n
      $(\'#tool_stroke\').on("touchstart", function(){\n
          $(\'#tool_stroke\').addClass(\'active\');\n
          $("#tool_fill").removeClass(\'active\');\n
          colorPicker($(\'#stroke_color\'));\n
      });\n
\n
      $(\'#tool_fill\').on("touchstart", function(){\n
          $(\'#tool_fill\').addClass(\'active\');\n
          $("#tool_stroke").removeClass(\'active\');\n
          colorPicker($(\'#fill_color\'));\n
      });\n
      \n
      $(\'#zoom_select\').on("change", function() {\n
        var val = this.options[this.selectedIndex].text\n
        val = val.split("%")[0]\n
        $("#zoom").val(val).trigger("change")\n
      });\n
    \n
      $(\'.push_button\').mousedown(function() { \n
        if (!$(this).hasClass(\'disabled\')) {\n
          $(this).addClass(\'push_button_pressed\').removeClass(\'push_button\');\n
        }\n
      }).mouseout(function() {\n
        $(this).removeClass(\'push_button_pressed\').addClass(\'push_button\');\n
      }).mouseup(function() {\n
        $(this).removeClass(\'push_button_pressed\').addClass(\'push_button\');\n
      });\n
      \n
    \n
    //  function changeResolution(x,y) {\n
    //    var zoom = svgCanvas.getResolution().zoom;\n
    //    setResolution(x * zoom, y * zoom);\n
    //  }\n
      \n
      var centerCanvas = function() {\n
        // this centers the canvas vertically in the workarea (horizontal handled in CSS)\n
        workarea.css(\'line-height\', workarea.height() + \'px\');\n
      };\n
      \n
      $(window).bind(\'load resize\', centerCanvas);\n
    \n
      function stepFontSize(elem, step) {\n
        var orig_val = elem.value-0;\n
        var sug_val = orig_val + step;\n
        var increasing = sug_val >= orig_val;\n
        if(step === 0) return orig_val;\n
        \n
        if(orig_val >= 24) {\n
          if(increasing) {\n
            return Math.round(orig_val * 1.1);\n
          } else {\n
            return Math.round(orig_val / 1.1);\n
          }\n
        } else if(orig_val <= 1) {\n
          if(increasing) {\n
            return orig_val * 2;      \n
          } else {\n
            return orig_val / 2;\n
          }\n
        } else {\n
          return sug_val;\n
        }\n
      }\n
      \n
      function stepZoom(elem, step) {\n
        var orig_val = elem.value-0;\n
        if(orig_val === 0) return 100;\n
        var sug_val = orig_val + step;\n
        if(step === 0) return orig_val;\n
        \n
        if(orig_val >= 100) {\n
          return sug_val;\n
        } else {\n
          if(sug_val >= orig_val) {\n
            return orig_val * 2;\n
          } else {\n
            return orig_val / 2;\n
          }\n
        }\n
      }\n
        \n
    var changeCanvasSize = function(ctl){\n
      var width = $("#canvas_width");\n
      var height = $("#canvas_height");\n
      var w = width.val();\n
      var h = height.val()\n
      \n
      if(w != "fit" && !svgedit.units.isValidUnit(\'width\', w)) {\n
        $.alert(uiStrings.notification.invalidAttrValGiven);\n
        width.parent().addClass(\'error\');\n
        return false;\n
      }\n
\n
      width.parent().removeClass(\'error\');\n
\n
      if(h != "fit" && !svgedit.units.isValidUnit(\'height\', h)) {\n
        $.alert(uiStrings.notification.invalidAttrValGiven);\n
        height.parent().addClass(\'error\');\n
        return false;\n
      } \n
      height.parent().removeClass(\'error\');\n
      if(!svgCanvas.setResolution(w, h)) {\n
        $.alert(uiStrings.notification.noContentToFitTo);\n
        var dims = svgCanvas.getResolution()\n
        width.val(dims.w)\n
        height.val(dims.h)\n
        return false;\n
      }\n
       updateCanvas();\n
    }\n
    \n
    \n
      $(\'#resolution\').change(function(){\n
        var w = $(\'#canvas_width\')[0];\n
        var h = $(\'#canvas_height\')[0];\n
        if(!this.selectedIndex) {\n
          $(\'#resolution_label\').html("Custom");\n
          w.removeAttribute("readonly");\n
          w.focus();\n
          w.select();\n
          if(w.value == \'fit\') {\n
            w.value = 100\n
            h.value = 100\n
          }\n
        } else if(this.value == \'content\') {\n
          w.value = \'fit\'\n
          h.value = \'fit\'\n
          changeCanvasSize();\n
          var res = svgCanvas.getResolution()\n
          w.value = res.w\n
          h.value = res.h\n
          \n
        } else {\n
          var dims = this.value.split(\'x\');\n
          dims[0] = parseInt(dims[0]); \n
          dims[1] = parseInt(dims[1]);\n
          var diff_w = dims[0] - w.value;\n
          var diff_h = dims[1] - h.value;\n
          //animate\n
          var start = Date.now();\n
          var duration = 1000;\n
          var animateCanvasSize = function(timestamp) {\n
            var progress = Date.now() - start;\n
            var tick = progress / duration;\n
            tick = (Math.pow((tick-1), 3) +1);\n
            w.value = (dims[0] - diff_w + (tick*diff_w)).toFixed(0);\n
            h.value = (dims[1] - diff_h + (tick*diff_h)).toFixed(0);\n
            changeCanvasSize();\n
            if (tick >= 1) {\n
              var res = svgCanvas.getResolution()\n
              $(\'#canvas_width\').val(res.w.toFixed())\n
              $(\'#canvas_height\').val(res.h.toFixed())\n
              $(\'#resolution_label\').html("<div class=\'pull\'>" + res.w + "<span>×</span></br>" + res.h + "</div>");\n
            }\n
            else {\n
              requestAnimationFrame(animateCanvasSize)\n
            }\n
          }\n
          animateCanvasSize()\n
\n
        }\n
      });\n
      \n
      $(\'#zoom\').change(function(){\n
        changeZoom(this)\n
      })\n
    \n
      //Prevent browser from erroneously repopulating fields\n
      $(\'input,select\').attr("autocomplete","off");\n
      \n
      // Associate all button actions as well as non-button keyboard shortcuts\n
      var Actions = function() {\n
        // sel:\'selector\', fn:function, evt:\'event\', key:[key, preventDefault, NoDisableInInput]\n
        var tool_buttons = [\n
          {sel:\'#tool_select\', fn: clickSelect, evt: \'click\', key: [\'V\', true]},\n
          {sel:\'#tool_fhpath\', fn: clickFHPath, evt: \'click\', key: [\'Q\', true]},\n
          {sel:\'#tool_line\', fn: clickLine, evt: \'click\', key: [\'L\', true]},\n
          {sel:\'#tool_rect\', fn: clickRect, evt: \'click\', key: [\'R\', true], icon: \'rect\'},\n
          {sel:\'#tool_ellipse\', fn: clickEllipse, evt: \'mouseup\', key: [\'C\', true], icon: \'ellipse\'},\n
          //{sel:\'#tool_circle\', fn: clickCircle, evt: \'mouseup\', icon: \'circle\'},\n
          //{sel:\'#tool_fhellipse\', fn: clickFHEllipse, evt: \'mouseup\', parent: \'#tools_ellipse\', icon: \'fh_ellipse\'},\n
          {sel:\'#tool_path\', fn: clickPath, evt: \'click\', key: [\'P\', true]},\n
          {sel:\'#tool_text\', fn: clickText, evt: \'click\', key: [\'T\', true]},\n
          {sel:\'#tool_image\', fn: clickImage, evt: \'mouseup\'},\n
          {sel:\'#tool_zoom\', fn: clickZoom, evt: \'mouseup\', key: [\'Z\', true]},\n
          {sel:\'#tool_clear\', fn: clickClear, evt: \'mouseup\', key: [modKey + \'N\', true]},\n
          {sel:\'#tool_save\', fn: function() { editingsource ? saveSourceEditor(): clickSave() }, evt: \'mouseup\', key: [modKey + \'S\', true]},\n
          {sel:\'#tool_export\', fn: clickExport, evt: \'mouseup\'},\n
          {sel:\'#tool_open\', fn: clickOpen, evt: \'mouseup\'},\n
          {sel:\'#tool_import\', fn: clickImport, evt: \'mouseup\'},\n
          {sel:\'#tool_source\', fn: showSourceEditor, evt: \'click\', key: [modKey + \'U\', true]},\n
          {sel:\'#tool_wireframe\', fn: clickWireframe, evt: \'click\'},\n
          {sel:\'#tool_snap\', fn: clickSnapGrid, evt: \'click\'},\n
          {sel:\'#tool_rulers\', fn: clickRulers, evt: \'click\'},\n
          {sel:\'#tool_source_cancel,#svg_source_overlay,#tool_docprops_cancel,#tool_prefs_cancel\', fn: cancelOverlays, evt: \'click\', key: [\'esc\', false, false], hidekey: true},\n
          {sel:\'#tool_source_save\', fn: saveSourceEditor, evt: \'click\'},\n
          {sel:\'#tool_delete,#tool_delete_multi\', fn: deleteSelected, evt: \'click\', key: [\'del/backspace\', true]},\n
          {sel:\'#tool_reorient\', fn: reorientPath, evt: \'click\'},\n
          {sel:\'#tool_node_link\', fn: linkControlPoints, evt: \'change\'},\n
          {sel:\'#tool_node_clone\', fn: clonePathNode, evt: \'click\'},\n
          {sel:\'#tool_node_delete\', fn: deletePathNode, evt: \'click\'},\n
          {sel:\'#tool_openclose_path\', fn: opencloseSubPath, evt: \'click\'},\n
          {sel:\'#tool_add_subpath\', fn: addSubPath, evt: \'click\'},\n
          {sel:\'#tool_move_top\', fn: moveToTopSelected, evt: \'click\', key: modKey + \'shift+up\'},\n
          {sel:\'#tool_move_bottom\', fn: moveToBottomSelected, evt: \'click\', key: modKey + \'shift+down\'},\n
          {sel:\'#tool_move_up\', fn: moveUpSelected, evt:\'click\', key: [modKey+\'up\', true]},\n
          {sel:\'#tool_move_down\', fn: moveDownSelected, evt:\'click\', key: [modKey+\'down\', true]},\n
          {sel:\'#tool_topath\', fn: convertToPath, evt: \'click\'},\n
          {sel:\'#tool_make_link,#tool_make_link_multi\', fn: makeHyperlink, evt: \'click\'},\n
          {sel:\'#tool_clone,#tool_clone_multi\', fn: clickClone, evt: \'click\', key: [modKey + \'D\', true]},\n
          {sel:\'#tool_group\', fn: clickGroup, evt: \'click\', key: [modKey + \'G\', true]},\n
          {sel:\'#tool_ungroup\', fn: clickGroup, evt: \'click\', key: modKey + \'shift+G\'},\n
          {sel:\'#tool_unlink_use\', fn: clickGroup, evt: \'click\'},\n
          {sel:\'[id^=tool_align]\', fn: clickAlign, evt: \'click\'},\n
          {sel:\'#tool_undo\', fn: clickUndo, evt: \'click\', key: modKey + \'z\'},\n
          {sel:\'#tool_redo\', fn: clickRedo, evt: \'click\', key: [\'y\', true]},\n
          {sel:\'#tool_cut\', fn: cutSelected, evt: \'click\', key: [modKey+\'x\', true]},\n
          {sel:\'#tool_copy\', fn: copySelected, evt: \'click\', key: modKey+\'c\'},\n
          {sel:\'#tool_paste\', fn: pasteSelected, evt: \'click\', key: modKey+\'v\'},\n
          {sel:\'#tool_switch\', fn: clickSwitch, evt: \'click\', key: [\'x\', true]},\n
          {sel:\'#tool_bold\', fn: clickBold, evt: \'mousedown\', key: [modKey + \'B\', true]},\n
          {sel:\'#tool_italic\', fn: clickItalic, evt: \'mousedown\',  key: [modKey + \'I\', true]},\n
          //{sel:\'#sidepanel_handle\', fn: toggleSidePanel, key: [\'X\']},\n
          {sel:\'#copy_save_done\', fn: cancelOverlays, evt: \'click\'},\n
          \n
          // Shortcuts not associated with buttons\n
          \n
          {key: \'ctrl+left\', fn: function(){rotateSelected(0,1)}},\n
          {key: \'ctrl+right\', fn: function(){rotateSelected(1,1)}},\n
          {key: \'ctrl+shift+left\', fn: function(){rotateSelected(0,5)}},          \n
          {key: \'ctrl+shift+right\', fn: function(){rotateSelected(1,5)}},\n
          {key: \'shift+O\', fn: selectPrev},\n
          {key: \'shift+P\', fn: selectNext},\n
          {key: [modKey+\'+\', true], fn: function(){zoomImage(2);}},\n
          {key: [modKey+\'-\', true], fn: function(){zoomImage(.5);}},\n
          {key: [\'up\', true], fn: function(){moveSelected(0,-1);}},\n
          {key: [\'down\', true], fn: function(){moveSelected(0,1);}},\n
          {key: [\'left\', true], fn: function(){moveSelected(-1,0);}},\n
          {key: [\'right\', true], fn: function(){moveSelected(1,0);}},\n
          {key: \'shift+up\', fn: function(){moveSelected(0,-10)}},\n
          {key: \'shift+down\', fn: function(){moveSelected(0,10)}},\n
          {key: \'shift+left\', fn: function(){moveSelected(-10,0)}},\n
          {key: \'shift+right\', fn: function(){moveSelected(10,0)}},\n
          {key: [\'alt+up\', true], fn: function(){svgCanvas.cloneSelectedElements(0,-1)}},\n
          {key: [\'alt+down\', true], fn: function(){svgCanvas.cloneSelectedElements(0,1)}},\n
          {key: [\'alt+left\', true], fn: function(){svgCanvas.cloneSelectedElements(-1,0)}},\n
          {key: [\'alt+right\', true], fn: function(){svgCanvas.cloneSelectedElements(1,0)}},\n
          {key: [\'alt+shift+up\', true], fn: function(){svgCanvas.cloneSelectedElements(0,-10)}},\n
          {key: [\'alt+shift+down\', true], fn: function(){svgCanvas.cloneSelectedElements(0,10)}},\n
          {key: [\'alt+shift+left\', true], fn: function(){svgCanvas.cloneSelectedElements(-10,0)}},\n
          {key: [\'alt+shift+right\', true], fn: function(){svgCanvas.cloneSelectedElements(10,0)}},  \n
          {key: modKey + \'A\', fn: function(){svgCanvas.selectAllInCurrentLayer();}},\n
          {key: \'I\', fn: function(){setEyedropperMode()}},\n
\n
          // Standard shortcuts\n
          {key: modKey + \'shift+z\', fn: clickRedo},\n
          {key: \'esc\', fn: minimizeModal}\n
        ];\n
        \n
        // Tooltips not directly associated with a single function\n
        var key_assocs = {\n
          \'4/Shift+4\': \'#tools_rect_show\',\n
          \'5/Shift+5\': \'#tools_ellipse_show\'\n
        };\n
      \n
        return {\n
          setAll: function() {\n
            var flyouts = {};\n
            \n
            $.each(tool_buttons, function(i, opts)  {       \n
              // Bind function to button\n
              if(opts.sel) {\n
                var btn = $(opts.sel);\n
                if (btn.length == 0) return true; // Skip if markup does not exist\n
                if(opts.evt) {\n
                  if (svgedit.browser.isTouch() && opts.evt === "click") opts.evt = "mousedown" \n
                  btn[opts.evt](opts.fn);\n
                }\n
    \n
                // Add to parent flyout menu, if able to be displayed\n
                if(opts.parent && $(opts.parent + \'_show\').length != 0) {\n
                  var f_h = $(opts.parent);\n
                  if(!f_h.length) {\n
                    f_h = makeFlyoutHolder(opts.parent.substr(1));\n
                  }\n
                  \n
                  f_h.append(btn);\n
                  \n
                  if(!$.isArray(flyouts[opts.parent])) {\n
                    flyouts[opts.parent] = [];\n
                  }\n
                  flyouts[opts.parent].push(opts);\n
                }\n
              }\n
              \n
              \n
              // Bind function to shortcut key\n
              if(opts.key) {\n
                // Set shortcut based on options\n
                var keyval, shortcut = \'\', disInInp = true, fn = opts.fn, pd = false;\n
                if($.isArray(opts.key)) {\n
                  keyval = opts.key[0];\n
                  if(opts.key.length > 1) pd = opts.key[1];\n
                  if(opts.key.length > 2) disInInp = opts.key[2];\n
                } else {\n
                  keyval = opts.key;\n
                }\n
                keyval += \'\';\n
                if (svgedit.browser.isMac && keyval.indexOf("+") != -1) {\n
                  var modifier_key =  keyval.split("+")[0];\n
                  if (modifier_key == "ctrl") keyval.replace("ctrl", "cmd")\n
                }\n
                \n
                $.each(keyval.split(\'/\'), function(i, key) {\n
                  $(document).bind(\'keydown\', key, function(e) {\n
                    fn();\n
                    if(pd) {\n
                      e.preventDefault();\n
                    }\n
                    // Prevent default on ALL keys?\n
                    return false;\n
                  });\n
                });\n
                \n
                // Put shortcut in title\n
                if(opts.sel && !opts.hidekey && btn.attr(\'title\')) {\n
                  var new_title = btn.attr(\'title\').split(\'[\')[0] + \' (\' + keyval + \')\';\n
                  key_assocs[keyval] = opts.sel;\n
                  // Disregard for menu items\n
                  if(!btn.parents(\'#main_menu\').length) {\n
                    btn.attr(\'title\', new_title);\n
                  }\n
                }\n
              }\n
            });\n
            \n
            // Setup flyouts\n
            setupFlyouts(flyouts);\n
            \n
            $(window).bind(\'keydown\', \'tab\', function(e) {\n
              if(ui_context === \'canvas\') {\n
                e.preventDefault();\n
                selectNext();\n
              }\n
            }).bind(\'keydown\', \'shift+tab\', function(e) {\n
              if(ui_context === \'canvas\') {\n
                e.preventDefault();\n
                selectPrev();\n
              }\n
            });\n
            \n
            $(\'#tool_zoom\').dblclick(dblclickZoom);\n
          },\n
          setTitles: function() {\n
            $.each(key_assocs, function(keyval, sel)  {\n
              var menu = ($(sel).parents(\'#main_menu\').length);\n
            \n
              $(sel).each(function() {\n
                if(menu) {\n
                  var t = $(this).text().split(\' [\')[0];\n
                } else {\n
                  var t = this.title.split(\' [\')[0];              \n
                }\n
                var key_str = \'\';\n
                // Shift+Up\n
                $.each(keyval.split(\'/\'), function(i, key) {\n
                  var mod_bits = key.split(\'+\'), mod = \'\';\n
                  if(mod_bits.length > 1) {\n
                    mod = mod_bits[0] + \'+\';\n
                    key = mod_bits[1];\n
                  }\n
                  key_str += (i?\'/\':\'\') + mod + (uiStrings[\'key_\'+key] || key);\n
                });\n
                if(menu) {\n
                  this.lastChild.textContent = t +\' [\'+key_str+\']\';\n
                } else {\n
                  this.title = t +\' [\'+key_str+\']\';\n
                }\n
              });\n
            });\n
          },\n
          getButtonData: function(sel) {\n
            var b;\n
            $.each(tool_buttons, function(i, btn) {\n
              if(btn.sel === sel) b = btn;\n
            });\n
            return b;\n
          }\n
        };\n
      }();\n
      \n
      Actions.setAll();\n
      \n
      // Select given tool\n
      Editor.ready(function() {\n
        var tool,\n
          itool = curConfig.initTool,\n
          container = $("#tools_left, #svg_editor .tools_flyout"),\n
          pre_tool = container.find("#tool_" + itool),\n
          reg_tool = container.find("#" + itool);\n
        if(pre_tool.length) {\n
          tool = pre_tool;\n
        } else if(reg_tool.length){\n
          tool = reg_tool;\n
        } else {\n
          tool = $("#tool_select");\n
        }\n
        tool.click().mouseup();\n
        \n
        if(curConfig.wireframe) {\n
          $(\'#tool_wireframe\').click();\n
        }\n
        \n
        if(curConfig.showlayers) {\n
          toggleSidePanel();\n
        }\n
        \n
        $(\'#rulers\').toggle(!!curConfig.showRulers);\n
      });\n
    \n
      \n
      $(\'#canvas_height\').dragInput({ min: 10,   max: null,  step: 10,  callback: changeCanvasSize,    cursor: false, dragAdjust: .1         }); \n
      $(\'#canvas_width\') .dragInput({ min: 10,   max: null,  step: 10,  callback: changeCanvasSize,    cursor: false, dragAdjust: .1         });                         \n
      $(\'#rect_width\')   .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         }); \n
      $(\'#rect_height\')  .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#ellipse_cx\')   .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#ellipse_cy\')   .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#ellipse_rx\')   .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#ellipse_ry\')   .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $("#image_height") .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#circle_cx\')    .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#circle_cy\')    .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#circle_r\')     .dragInput({ min: 1,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $("#image_height") .dragInput({ min: 0,    max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#selected_x\')   .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#selected_y\')   .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $("#path_node_x")  .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $("#path_node_y")  .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $("#image_width")  .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#line_x1\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#line_x2\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#line_y1\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#line_y2\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#path_x\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#path_y\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#rect_x\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#rect_y\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#g_x\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#g_y\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#image_x\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#text_y\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#text_x\')       .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#image_y\')      .dragInput({ min: null, max: null,  step:  1,  callback: changeAttribute,     cursor: false                         });\n
      $(\'#rect_rx\')      .dragInput({ min: 0,    max: 100,   step:  1,  callback: changeAttribute,    cursor: true                          });\n
      $(\'#stroke_width\') .dragInput({ min: 0,    max: 99,    step:  1,  callback: changeStrokeWidth,   cursor: true, smallStep: 0.1, start: 1.5          });\n
      $(\'#angle\')        .dragInput({ min: -180, max: 180,   step:  1,  callback: changeRotationAngle, cursor: false, dragAdjust: 0.5      });\n
      $(\'#font_size\')    .dragInput({ min: 1, max: 250, step: 1, callback: changeFontSize, cursor: true, stepfunc: stepFontSize, dragAdjust: .15 });\n
      $(\'#group_opacity\').dragInput({ min: 0,    max: 100,   step:  5,  callback: changeAttribute,       cursor: true,  start: 100             });\n
      $(\'#blur\')         .dragInput({ min: 0,    max: 10,    step: .1,  callback: changeBlur,          cursor: true,  start: 0               });\n
        // Set default zoom \n
      $(\'#zoom\').val(svgCanvas.getZoom() * 100);\n
      \n
      $("#workarea").contextMenu({\n
          menu: \'cmenu_canvas\',\n
          inSpeed: 0\n
        },\n
        function(action, el, pos) {\n
          switch ( action ) {\n
            case \'delete\':\n
              deleteSelected();\n
              break;\n
            case \'cut\':\n
              cutSelected();\n
              break;\n
            case \'copy\':\n
              copySelected();\n
              break;\n
            case \'paste\':\n
              svgCanvas.pasteElements();\n
              break;\n
            case \'paste_in_place\':\n
              svgCanvas.pasteElements(\'in_place\');\n
              break;\n
            case \'group\':\n
              svgCanvas.groupSelectedElements();\n
              break;\n
            case \'ungroup\':         \n
              svgCanvas.ungroupSelectedElement();  \n
              break;\n
            case \'move_front\':\n
              moveToTopSelected();\n
              break;\n
            case \'move_up\':\n
              moveUpDownSelected(\'Up\');\n
              break;\n
            case \'move_down\':\n
              moveUpDownSelected(\'Down\');\n
              break;\n
            case \'move_back\':\n
              moveToBottomSelected();\n
              break;\n
              default:\n
              if(svgedit.contextmenu && svgedit.contextmenu.hasCustomHandler(action)){\n
                svgedit.contextmenu.getCustomHandler(action).call();\n
                }\n
                break;\n
          }\n
          \n
      });\n
      \n
      $(\'.contextMenu li\').mousedown(function(ev) {\n
        ev.preventDefault();\n
      })\n
      \n
      $(\'#cmenu_canvas li\').disableContextMenu();\n
      canv_menu.enableContextMenuItems(\'#delete,#cut,#copy\');\n
      \n
      window.onbeforeunload = function() { \n
        // Suppress warning if page is empty \n
        if(undoMgr.getUndoStackSize() === 0) {\n
          Editor.show_save_warning = false;\n
        }\n
\n
        // show_save_warning is set to "false" when the page is saved.\n
        if(!curConfig.no_save_warning && Editor.show_save_warning) {\n
          // Browser already asks question about closing the page\n
          return uiStrings.notification.unsavedChanges; \n
        }\n
      };\n
      \n
      Editor.openPrep = function(func) {\n
        $(\'#main_menu\').hide();\n
        if(undoMgr.getUndoStackSize() === 0) {\n
          func(true);\n
        } else {\n
          $.confirm(uiStrings.notification.QwantToOpen, func);\n
        }\n
      }\n
            \n
      if (window.FileReader) {\n
        \n
        var import_image = function(e) {\n
          e.stopPropagation();\n
          e.preventDefault();\n
          $("#workarea").removeAttr("style");\n
          $(\'#main_menu\').hide();\n
          var file = null;\n
          if (e.type == "drop") file = e.dataTransfer.files[0]\n
          else file = this.files[0];\n
          if (file) {\n
            if(file.type.indexOf("image") != -1) {\n
              //detected an image\n
            \n
              //svg handing\n
              if(file.type.indexOf("svg") != -1) {\n
                var reader = new FileReader();\n
                reader.onloadend = function(e) {\n
                  svgCanvas.importSvgString(e.target.result, true);\n
                  svgCanvas.ungroupSelectedElement()\n
                  svgCanvas.ungroupSelectedElement()\n
                  svgCanvas.groupSelectedElements()\n
                  svgCanvas.alignSelectedElements("m", "page")\n
                  svgCanvas.alignSelectedElements("c", "page")\n
                };\n
                reader.readAsText(file);\n
              }\n
          \n
              //image handling\n
              else {\n
                var reader = new FileReader();\n
                reader.onloadend = function(e) {\n
                  // lets insert the new image until we know its dimensions\n
                  insertNewImage = function(img_width, img_height){\n
                      var newImage = svgCanvas.addSvgElementFromJson({\n
                      "element": "image",\n
                      "attr": {\n
                        "x": 0,\n
                        "y": 0,\n
                        "width": img_width,\n
                        "height": img_height,\n
                        "id": svgCanvas.getNextId(),\n
                        "style": "pointer-events:inherit"\n
                      }\n
                    });\n
                    svgCanvas.setHref(newImage, e.target.result);\n
                    svgCanvas.selectOnly([newImage])\n
                    svgCanvas.alignSelectedElements("m", "page")\n
                    svgCanvas.alignSelectedElements("c", "page")\n
                    updateContextPanel();\n
                  }\n
                  // put a placeholder img so we know the default dimensions\n
                  var img_width = 100;\n
                  var img_height = 100;\n
                  var img = new Image()\n
                  img.src = e.target.result\n
                  document.body.appendChild(img);\n
                  img.onload = function() {\n
                    img_width = img.offsetWidth\n
                    img_height = img.offsetHeight\n
                    insertNewImage(img_width, img_height);\n
                    document.body.removeChild(img);\n
                  }\n
                };\n
                reader.readAsDataURL(file)\n
              }\n
            }\n
          }\n
        }\n
        \n
        var workarea = $("#workarea")\n
        \n
        function onDragEnter(e) {\n
          e.stopPropagation();\n
          e.preventDefault();\n
          workarea.css({\n
            "-webkit-transform": "scale3d(1.1,1.1,1)",\n
            "-moz-transform": "scale3d(1.1,1.1,1)",\n
            "-o-transform": "scale(1.1)",\n
            "-ms-transform": "scale3d(1.1,1.1,1)",\n
            "transform": "scale3d(1.1,1.1,1)"\n
          })\n
\n
        }\n
\n
        function onDragOver(e) {\n
          e.stopPropagation();\n
          e.preventDefault();\n
        }\n
\n
        function onDragLeave(e) {\n
          workarea.removeAttr("style")\n
          e.stopPropagation();\n
          e.preventDefault();\n
        }\n
\n
      workarea[0].addEventListener(\'dragenter\', onDragEnter, false);\n
        workarea[0].addEventListener(\'dragover\', onDragOver, false);\n
        workarea[0].addEventListener(\'dragleave\', onDragLeave, false);\n
        workarea[0].addEventListener(\'drop\', import_image, false);\n
        \n
        var open = $(\'<input type="file">\').change(function() {\n
          var f = this;\n
          Editor.openPrep(function(ok) {\n
            if(!ok) return;\n
            svgCanvas.clear();\n
            if(f.files.length==1) {\n
              var reader = new FileReader();\n
              reader.onloadend = function(e) {\n
                loadSvgString(e.target.result);\n
                updateCanvas();\n
              };\n
              reader.readAsText(f.files[0]);\n
            }\n
          });\n
        });\n
        $("#tool_open").show().prepend(open);\n
        \n
        var img_import = $(\'<input type="file">\').change(import_image);\n
        $("#tool_import").show().prepend(img_import);\n
      }\n
\n
      \n
      var updateCanvas = Editor.updateCanvas = function(center, new_ctr) {\n
        var w = workarea.width(), h = workarea.height();\n
        var w_orig = w, h_orig = h;\n
        var zoom = svgCanvas.getZoom();\n
        var w_area = workarea;\n
        var cnvs = $("#svgcanvas");\n
        \n
        var old_ctr = {\n
          x: w_area[0].scrollLeft + w_orig/2,\n
          y: w_area[0].scrollTop + h_orig/2\n
        };\n
        \n
        var multi = curConfig.canvas_expansion;\n
        w = Math.max(w_orig, svgCanvas.contentW * zoom * multi);\n
        h = Math.max(h_orig, svgCanvas.contentH * zoom * multi);\n
        \n
        if(w == w_orig && h == h_orig) {\n
          workarea.css(\'overflow\',\'hidden\');\n
        } else {\n
          workarea.css(\'overflow\',\'scroll\');\n
        }\n
        \n
        var old_can_y = cnvs.height()/2;\n
        var old_can_x = cnvs.width()/2;\n
        cnvs.width(w).height(h);\n
        var new_can_y = h/2;\n
        var new_can_x = w/2;\n
        var offset = svgCanvas.updateCanvas(w, h);\n
        \n
        var ratio = new_can_x / old_can_x;\n
    \n
        var scroll_x = w/2 - w_orig/2;\n
        var scroll_y = h/2 - h_orig/2;\n
        \n
        if(!new_ctr) {\n
    \n
          var old_dist_x = old_ctr.x - old_can_x;\n
          var new_x = new_can_x + old_dist_x * ratio;\n
    \n
          var old_dist_y = old_ctr.y - old_can_y;\n
          var new_y = new_can_y + old_dist_y * ratio;\n
    \n
          new_ctr = {\n
            x: new_x,\n
            y: new_y\n
          };\n
          \n
        } else {\n
          new_ctr.x += offset.x,\n
          new_ctr.y += offset.y;\n
        }\n
        \n
        //width.val(offset.x)\n
        //height.val(offset.y)\n
        \n
        if(center) {\n
          // Go to top-left for larger documents\n
          if(svgCanvas.contentW > w_area.width()) {\n
            // Top-left\n
            workarea[0].scrollLeft = offset.x - 10;\n
            workarea[0].scrollTop = offset.y - 10;\n
          } else {\n
            // Center\n
            w_area[0].scrollLeft = scroll_x;\n
            w_area[0].scrollTop = scroll_y;\n
          }\n
        } else {\n
          w_area[0].scrollLeft = new_ctr.x - w_orig/2;\n
          w_area[0].scrollTop = new_ctr.y - h_orig/2;\n
        }\n
        if(curConfig.showRulers) {\n
          updateRulers(cnvs, zoom);\n
          workarea.scroll();\n
        }\n
      }\n
      \n
      // Make [1,2,5] array\n
      var r_intervals = [];\n
      for(var i = .1; i < 1E5; i *= 10) {\n
        r_intervals.push(1 * i);\n
        r_intervals.push(2 * i);\n
        r_intervals.push(5 * i);\n
      }\n
      \n
      function updateRulers(scanvas, zoom) {\n
        var workarea = document.getElementById("workarea");\n
        var title_show = document.getElementById("title_show");\n
        var offset_x = 66;\n
        var offset_y = 48;\n
        if(!zoom) zoom = svgCanvas.getZoom();\n
        if(!scanvas) scanvas = $("#svgcanvas");\n
        \n
        var limit = 30000;\n
        \n
        var c_elem = svgCanvas.getContentElem();\n
        \n
        var units = svgedit.units.getTypeMap();\n
        var unit = units[curConfig.baseUnit]; // 1 = 1px\n
      \n
        for(var d = 0; d < 2; d++) {\n
          var is_x = (d === 0);\n
          var dim = is_x ? \'x\' : \'y\';\n
          var lentype = is_x?\'width\':\'height\';\n
          var content_d = c_elem.getAttribute(dim)-0;\n
          \n
          var $hcanv_orig = $(\'#ruler_\' + dim + \' canvas:first\');\n
          \n
          // Bit of a hack to fully clear the canvas in Safari & IE9\n
          $hcanv = $hcanv_orig.clone();\n
          $hcanv_orig.replaceWith($hcanv);\n
          \n
          var hcanv = $hcanv[0];\n
          \n
          // Set the canvas size to the width of the container\n
          var ruler_len = scanvas[lentype]()*2;\n
          var total_len = ruler_len;\n
          hcanv.parentNode.style[lentype] = total_len + \'px\';\n
          \n
          var canv_count = 1;\n
          var ctx_num = 0;\n
          var ctx_arr;\n
          var ctx = hcanv.getContext("2d");\n
          \n
          ctx.fillStyle = "rgb(200,0,0)"; \n
          ctx.fillRect(0,0,hcanv.width,hcanv.height); \n
          \n
          // Remove any existing canvasses\n
          $hcanv.siblings().remove();\n
          \n
          // Create multiple canvases when necessary (due to browser limits)\n
          if(ruler_len >= limit) {\n
            var num = parseInt(ruler_len / limit) + 1;\n
            ctx_arr = Array(num);\n
            ctx_arr[0] = ctx;\n
            for(var i = 1; i < num; i++) {\n
              hcanv[lentype] = limit;\n
              var copy = hcanv.cloneNode(true);\n
              hcanv.parentNode.appendChild(copy);\n
              ctx_arr[i] = copy.getContext(\'2d\');\n
            }\n
            \n
            copy[lentype] = ruler_len % limit;\n
            \n
            // set copy width to last\n
            ruler_len = limit;\n
          }\n
          \n
          hcanv[lentype] = ruler_len;\n
          \n
          var u_multi = unit * zoom;\n
          \n
          // Calculate the main number interval\n
          var raw_m = 50 / u_multi;\n
          var multi = 1;\n
          for(var i = 0; i < r_intervals.length; i++) {\n
            var num = r_intervals[i];\n
            multi = num;\n
            if(raw_m <= num) {\n
              break;\n
            }\n
          }\n
          \n
          var big_int = multi * u_multi;\n
          ctx.font = "normal 9px \'Lucida Grande\', sans-serif";\n
          ctx.fillStyle = "#777";\n
\n
          var ruler_d = ((content_d / u_multi) % multi) * u_multi;\n
          var label_pos = ruler_d - big_int;\n
          for (; ruler_d < total_len; ruler_d += big_int) {\n
            label_pos += big_int;\n
            var real_d = ruler_d - content_d;\n
\n
            var cur_d = Math.round(ruler_d) + .5;\n
            if(is_x) {\n
              ctx.moveTo(cur_d, 15);\n
              ctx.lineTo(cur_d, 0);\n
            } else {\n
              ctx.moveTo(15, cur_d);\n
              ctx.lineTo(0, cur_d);\n
            }\n
  \n
            var num = (label_pos - content_d) / u_multi;\n
            var label;\n
            if(multi >= 1) {\n
              label = Math.round(num);\n
            } else {\n
              var decs = (multi+\'\').split(\'.\')[1].length;\n
              label = num.toFixed(decs)-0;\n
            }\n
            \n
            // Do anything special for negative numbers?\n
//            var is_neg = label < 0;\n
//            real_d2 = Math.abs(real_d2);\n
            \n
            // Change 1000s to Ks\n
            if(label !== 0 && label !== 1000 && label % 1000 === 0) {\n
              label = (label / 1000) + \'K\';\n
            }\n
            \n
            if(is_x) {\n
              ctx.fillText(label, ruler_d+2, 8);\n
              ctx.fillStyle = "#777";\n
            } else {\n
              var str = (label+\'\').split(\'\');\n
              for(var i = 0; i < str.length; i++) {\n
                ctx.fillText(str[i], 1, (ruler_d+9) + i*9);\n
                ctx.fillStyle = "#777";\n
              }\n
            }\n
            \n
            var part = big_int / 10;\n
            for(var i = 1; i < 10; i++) {\n
              var sub_d = Math.round(ruler_d + part * i) + .5;\n
              if(ctx_arr && sub_d > ruler_len) {\n
                ctx_num++;\n
                ctx.stroke();\n
                if(ctx_num >= ctx_arr.length) {\n
                  i = 10;\n
                  ruler_d = total_len;\n
                  continue;\n
                }\n
                ctx = ctx_arr[ctx_num];\n
                ruler_d -= limit;\n
                sub_d = Math.round(ruler_d + part * i) + .5;\n
              }\n
              \n
              var line_num = (i % 2)?12:10;\n
              if(is_x) {\n
                ctx.moveTo(sub_d, 15);\n
                ctx.lineTo(sub_d, line_num);\n
              } else {\n
                ctx.moveTo(15, sub_d);\n
                ctx.lineTo(line_num ,sub_d);\n
              }\n
            }\n
          }\n
          ctx.strokeStyle = "#666";\n
          ctx.stroke();\n
        }\n
      }\n
    \n
//      $(function() {\n
        updateCanvas(true);\n
//      });\n
      \n
    //  var revnums = "svg-editor.js ($Rev: 2083 $) ";\n
    //  revnums += svgCanvas.getVersion();\n
    //  $(\'#copyright\')[0].setAttribute("title", revnums);\n
    \n
      // Callback handler for embedapi.js\n
      try{\n
        var json_encode = function(obj){\n
        //simple partial JSON encoder implementation\n
        if(window.JSON && JSON.stringify) return JSON.stringify(obj);\n
        var enc = arguments.callee; //for purposes of recursion\n
        if(typeof obj == "boolean" || typeof obj == "number"){\n
          return obj+\'\' //should work...\n
        }else if(typeof obj == "string"){\n
        //a large portion of this is stolen from Douglas Crockford\'s json2.js\n
        return \'"\'+\n
            obj.replace(\n
            /[\\\\\\"\\x00-\\x1f\\x7f-\\x9f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/g\n
            , function (a) {\n
            return \'\\\\u\' + (\'0000\' + a.charCodeAt(0).toString(16)).slice(-4);\n
            })\n
            +\'"\'; //note that this isn\'t quite as purtyful as the usualness\n
        }else if(obj.length){ //simple hackish test for arrayish-ness\n
        for(var i = 0; i < obj.length; i++){\n
          obj[i] = enc(obj[i]); //encode every sub-thingy on top\n
        }\n
        return "["+obj.join(",")+"]";\n
        }else{\n
        var pairs = []; //pairs will be stored here\n
        for(var k in obj){ //loop through thingys\n
          pairs.push(enc(k)+":"+enc(obj[k])); //key: value\n
        }\n
        return "{"+pairs.join(",")+"}" //wrap in the braces\n
        }\n
      }\n
        window.addEventListener("message", function(e){\n
        var cbid = parseInt(e.data.substr(0, e.data.indexOf(";")));\n
        try{\n
          e.source.postMessage("SVGe"+cbid+";"+json_encode(eval(e.data)), "*");\n
        }catch(err){          \n
          e.source.postMessage("SVGe"+cbid+";error:"+err.message, "*");\n
        }\n
      }, false)\n
      }catch(err){\n
        window.embed_error = err;\n
      }\n
      \n
    \n
    \n
      // For Compatibility with older extensions\n
      $(function() {\n
        window.svgCanvas = svgCanvas;\n
        svgCanvas.ready = methodDraw.ready;\n
      });\n
    \n
    \n
      Editor.setLang = function(lang, allStrings) {\n
        $.pref(\'lang\', lang);\n
        $(\'#lang_select\').val(lang);\n
        if(allStrings) {\n
        \n
          var notif = allStrings.notification;\n
          \n
          svgCanvas.runExtensions("langChanged", lang);\n
          \n
          // Update flyout tooltips\n
          setFlyoutTitles();\n
          \n
          // Copy title for certain tool elements\n
          var elems = {\n
            \'#stroke_color\': \'#tool_stroke .icon_label, #tool_stroke .color_block\',\n
            \'#fill_color\': \'#tool_fill label, #tool_fill .color_block\',\n
            \'#linejoin_miter\': \'#cur_linejoin\',\n
            \'#linecap_butt\': \'#cur_linecap\'\n
          }\n
          \n
          $.each(elems, function(source, dest) {\n
            $(dest).attr(\'title\', $(source)[0].title);\n
          });\n
          \n
          // Copy alignment titles\n
          $(\'#multiselected_panel div[id^=tool_align]\').each(function() {\n
            $(\'#tool_pos\' + this.id.substr(10))[0].title = this.title;\n
          });\n
          \n
        }\n
      };\n
    };\n
    \n
    var callbacks = [];\n
    \n
    function loadSvgString(str, callback) {\n
      var success = svgCanvas.setSvgString(str) !== false;\n
      callback = callback || $.noop;\n
      if(success) {\n
        callback(true);\n
      } else {\n
        $.alert(uiStrings.notification.errorLoadingSVG, function() {\n
          callback(false);\n
        });\n
      }\n
    }\n
    \n
    Editor.ready = function(cb) {\n
      if(!is_ready) {\n
        callbacks.push(cb);\n
      } else {\n
        cb();\n
      }\n
    };\n
\n
    Editor.runCallbacks = function() {\n
      $.each(callbacks, function() {\n
        this();\n
      });\n
      is_ready = true;\n
    };\n
    \n
    Editor.loadFromString = function(str) {\n
      Editor.ready(function() {\n
        loadSvgString(str);\n
      });\n
    };\n
    \n
    Editor.loadFromURL = function(url, opts) {\n
      if(!opts) opts = {};\n
\n
      var cache = opts.cache;\n
      var cb = opts.callback;\n
    \n
      Editor.ready(function() {\n
        $.ajax({\n
          \'url\': url,\n
          \'dataType\': \'text\',\n
          cache: !!cache,\n
          success: function(str) {\n
            loadSvgString(str, cb);\n
          },\n
          error: function(xhr, stat, err) {\n
            if(xhr.status != 404 && xhr.responseText) {\n
              loadSvgString(xhr.responseText, cb);\n
            } else {\n
              $.alert(uiStrings.notification.URLloadFail + ": \\n"+err+\'\', cb);\n
            }\n
          }\n
        });\n
      });\n
    };\n
    \n
    Editor.loadFromDataURI = function(str) {\n
      Editor.ready(function() {\n
        var pre = \'data:image/svg+xml;base64,\';\n
        var src = str.substring(pre.length);\n
        loadSvgString(svgedit.utilities.decode64(src));\n
      });\n
    };\n
    \n
    Editor.addExtension = function() {\n
      var args = arguments;\n
      \n
      // Note that we don\'t want this on Editor.ready since some extensions\n
      // may want to run before then (like server_opensave).\n
      $(function() {\n
        if(svgCanvas) svgCanvas.addExtension.apply(this, args);\n
      });\n
    };\n
\n
    return Editor;\n
  }(jQuery);\n
  \n
  // Run init once DOM is loaded\n
  $(methodDraw.init);\n
  \n
\n
})();

]]></string> </value>
        </item>
        <item>
            <key> <string>next</string> </key>
            <value>
              <none/>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
