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
            <value> <string>ts25570625.27</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>stringfield.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>/*global window, rJS */\n
(function(window, rJS) {\n
    "use strict";\n
    rJS(window).ready(function(gadget) {\n
        return gadget.getElement().push(function(element) {\n
            gadget.element = element;\n
        });\n
    }).declareMethod("render", function(options) {\n
        var input = this.element.querySelector("input");\n
        input.setAttribute("value", options.value || "");\n
        input.setAttribute("name", options.key);\n
        input.setAttribute("title", options.property_definition.description);\n
    }).declareMethod("getContent", function() {\n
        var input = this.element.querySelector("input"), result = {};\n
        result[input.getAttribute("name")] = input.value;\n
        return result;\n
    });\n
})(window, rJS);</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>734</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
