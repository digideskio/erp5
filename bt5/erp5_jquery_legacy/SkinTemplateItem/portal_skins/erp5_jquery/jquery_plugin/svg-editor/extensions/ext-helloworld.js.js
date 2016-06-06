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
            <value> <string>ts80066302.54</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ext-helloworld.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>/*\n
 * ext-helloworld.js\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 *\n
 */\n
 \n
/* \n
\tThis is a very basic SVG-Edit extension. It adds a "Hello World" button in\n
\tthe left panel. Clicking on the button, and then the canvas will show the\n
 \tuser the point on the canvas that was clicked on.\n
*/\n
 \n
svgEditor.addExtension("Hello World", function() {\n
\n
\t\treturn {\n
\t\t\tname: "Hello World",\n
\t\t\t// For more notes on how to make an icon file, see the source of\n
\t\t\t// the hellorworld-icon.xml\n
\t\t\tsvgicons: "jquery_plugin/svg-editor/extensions/helloworld-icon.xml",\n
\t\t\t\n
\t\t\t// Multiple buttons can be added in this array\n
\t\t\tbuttons: [{\n
\t\t\t\t// Must match the icon ID in helloworld-icon.xml\n
\t\t\t\tid: "hello_world", \n
\t\t\t\t\n
\t\t\t\t// This indicates that the button will be added to the "mode"\n
\t\t\t\t// button panel on the left side\n
\t\t\t\ttype: "mode", \n
\t\t\t\t\n
\t\t\t\t// Tooltip text\n
\t\t\t\ttitle: "Say \'Hello World\'", \n
\t\t\t\t\n
\t\t\t\t// Events\n
\t\t\t\tevents: {\n
\t\t\t\t\t\'click\': function() {\n
\t\t\t\t\t\t// The action taken when the button is clicked on.\n
\t\t\t\t\t\t// For "mode" buttons, any other button will \n
\t\t\t\t\t\t// automatically be de-pressed.\n
\t\t\t\t\t\tsvgCanvas.setMode("hello_world");\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}],\n
\t\t\t// This is triggered when the main mouse button is pressed down \n
\t\t\t// on the editor canvas (not the tool panels)\n
\t\t\tmouseDown: function() {\n
\t\t\t\t// Check the mode on mousedown\n
\t\t\t\tif(svgCanvas.getMode() == "hello_world") {\n
\t\t\t\t\n
\t\t\t\t\t// The returned object must include "started" with \n
\t\t\t\t\t// a value of true in order for mouseUp to be triggered\n
\t\t\t\t\treturn {started: true};\n
\t\t\t\t}\n
\t\t\t},\n
\t\t\t\n
\t\t\t// This is triggered from anywhere, but "started" must have been set\n
\t\t\t// to true (see above). Note that "opts" is an object with event info\n
\t\t\tmouseUp: function(opts) {\n
\t\t\t\t// Check the mode on mouseup\n
\t\t\t\tif(svgCanvas.getMode() == "hello_world") {\n
\t\t\t\t\tvar zoom = svgCanvas.getZoom();\n
\t\t\t\t\t\n
\t\t\t\t\t// Get the actual coordinate by dividing by the zoom value\n
\t\t\t\t\tvar x = opts.mouse_x / zoom;\n
\t\t\t\t\tvar y = opts.mouse_y / zoom;\n
\t\t\t\t\t\n
\t\t\t\t\tvar text = "Hello World!\\n\\nYou clicked here: " \n
\t\t\t\t\t\t+ x + ", " + y;\n
\t\t\t\t\t\t\n
\t\t\t\t\t// Show the text using the custom alert function\n
\t\t\t\t\t$.alert(text);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t};\n
});\n
\n
</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>2198</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
