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
            <value> <string>ts52850638.07</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-closepath.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * ext-closepath.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Jeff Schiller\n
 *\n
 */\n
\n
// This extension adds a simple button to the contextual panel for paths\n
// The button toggles whether the path is open or closed\n
methodDraw.addExtension("ClosePath", function(S) {\n
    var selElems,\n
      updateButton = function(path) {\n
        var seglist = path.pathSegList,\n
          closed = seglist.getItem(seglist.numberOfItems - 1).pathSegType==1,\n
          showbutton = closed ? \'#tool_openpath\' : \'#tool_closepath\',\n
          hidebutton = closed ? \'#tool_closepath\' : \'#tool_openpath\';\n
          $(hidebutton).hide();\n
          $(showbutton).show();\n
      },\n
      showPanel = function(on) {\n
        $(\'#closepath_panel\').toggle(on);\n
        if (on) {\n
          var path = selElems[0];\n
          if (path) updateButton(path);\n
        }\n
      },\n
    \n
      toggleClosed = function() {\n
        var path = selElems[0];\n
        if (path) {\n
          var seglist = path.pathSegList,\n
            last = seglist.numberOfItems - 1;         \n
          // is closed\n
          if(seglist.getItem(last).pathSegType == 1) {\n
            seglist.removeItem(last);\n
          }\n
          else {\n
            seglist.appendItem(path.createSVGPathSegClosePath());\n
          }\n
          updateButton(path);\n
        }\n
      };\n
    \n
    return {\n
      name: "ClosePath",\n
      svgicons: "extensions/closepath_icons.svg",\n
      buttons: [{\n
        id: "tool_openpath",\n
        type: "context",\n
        panel: "closepath_panel",\n
        title: "Open path",\n
        events: {\n
          \'click\': function() {\n
            toggleClosed();\n
          }\n
        }\n
      },\n
      {\n
        id: "tool_closepath",\n
        type: "context",\n
        panel: "closepath_panel",\n
        title: "Close path",\n
        events: {\n
          \'click\': function() {\n
            toggleClosed();\n
          }\n
        }\n
      }],\n
      callback: function() {\n
        $(\'#closepath_panel\').hide();\n
      },\n
      selectedChanged: function(opts) {\n
        selElems = opts.elems;\n
        var i = selElems.length;\n
        \n
        while(i--) {\n
          var elem = selElems[i];\n
          if(elem && elem.tagName == \'path\') {\n
            if(opts.selectedElement && !opts.multiselected) {\n
              showPanel(true);\n
            } else {\n
              showPanel(false);\n
            }\n
          } else {\n
            showPanel(false);\n
          }\n
        }\n
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
            <value> <int>2447</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
