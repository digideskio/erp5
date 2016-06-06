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
            <value> <string>ts63778282.19</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>require-erp5.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>// JavaScript file that is used to load ERP5\'s JavaScript depenencies\n
require.config({\n
  paths: {\n
    "erp5_form": "gadget-style-lib/erp5_form",\n
    route: "gadget-style-lib/route",\n
    url: "gadget-style-lib/url",\n
    jquery: "jquery/core/jquery",\n
    renderjs: "jquery/plugin/renderjs/renderjs",\n
    "jquery-ui": "jquery/ui/js/jquery-ui.min",\n
    "jquery.jqGrid.src": "jquery/plugin/jqgrid/jquery.jqGrid.src",\n
    "grid.locale-en": "jquery/plugin/jqgrid/i18n/grid.locale-en"\n
  },\n
  shim: {\n
    erp5: ["jquery"],\n
    erp5_xhtml_appearance: ["erp5"],\n
    erp5_knowledge_box: ["jquery", "jquery-ui"],\n
    route: ["jquery"],\n
    url: ["jquery"],\n
    "jquery-ui": ["jquery"],\n
    "jquery.jqGrid.src": ["jquery"],\n
    "grid.locale-en": ["jquery.jqGrid.src"]\n
  }\n
});\n
\n
require(["erp5_xhtml_appearance", "erp5_knowledge_box", "erp5", "erp5_form", "erp5_ui",\n
         "renderjs", "jquery", "jquery-ui", "route", "url",\n
        "jquery.jqGrid.src", "grid.locale-en"],\n
        function(domReady) {\n
          RenderJs.init();\n
          RenderJs.bindReady(function (){\n
            $.url.onhashchange(function () {\n
              //console.log("go to route", $.url.getPath());\n
              RenderJs.RouteGadget.go($.url.getPath(),\n
                function () {\n
                  //console.log("bad route");\n
                  // All routes have been deleted by fail.\n
                  // So recreate the default routes using RouteGadget\n
                  RenderJs.RouteGadget.init();\n
                });\n
            });\n
          });\n
});\n
</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1524</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
