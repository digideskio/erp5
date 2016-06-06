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
            <value> <string>ts25570624.3</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>listfield.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*global window, rJS, Handlebars */\n
/*jslint nomen: true */\n
(function(window, rJS, Handlebars) {\n
    "use strict";\n
    /////////////////////////////////////////////////////////////////\n
    // Handlebars\n
    /////////////////////////////////////////////////////////////////\n
    // Precompile the templates while loading the first gadget instance\n
    var gadget_klass = rJS(window), option_source = gadget_klass.__template_element.getElementById("option-template").innerHTML, option_template = Handlebars.compile(option_source), selected_option_source = gadget_klass.__template_element.getElementById("selected-option-template").innerHTML, selected_option_template = Handlebars.compile(selected_option_source);\n
    gadget_klass.ready(function(g) {\n
        return g.getElement().push(function(element) {\n
            g.element = element;\n
        });\n
    }).declareMethod("render", function(options) {\n
        var select = this.element.getElementsByTagName("select")[0], i, template, tmp = "";\n
        select.setAttribute("name", options.key);\n
        for (i = 0; i < options.property_definition.enum.length; i += 1) {\n
            if (options.property_definition.enum[i] === options.value) {\n
                template = selected_option_template;\n
            } else {\n
                template = option_template;\n
            }\n
            // XXX value and text are always same in json schema\n
            tmp += template({\n
                value: options.property_definition.enum[i],\n
                text: options.property_definition.enum[i]\n
            });\n
        }\n
        select.innerHTML += tmp;\n
    }).declareMethod("getContent", function() {\n
        var select = this.element.getElementsByTagName("select")[0], result = {};\n
        result[select.getAttribute("name")] = select.options[select.selectedIndex].value;\n
        return result;\n
    });\n
})(window, rJS, Handlebars);

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1870</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
