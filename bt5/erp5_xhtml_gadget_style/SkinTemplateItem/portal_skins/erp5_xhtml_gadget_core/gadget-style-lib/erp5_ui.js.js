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
            <value> <string>ts63878317.05</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>erp5_ui.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// Contains ERP5 UI\'s build javascript code\n
\n
var ERP5UI = ( function () {\n
\n
  function addOptionTagDict(dom, list) {\n
    $.each(list, function (index,value) {\n
      if (value.url!==undefined) {\n
        dom.append(\'<option value="\' + value.url + \'">\'  + value.title + \'</option>\');\n
      }\n
      else {\n
          dom.append(\'<option disabled="disabled">-- \'  + value.title + \' --</option>\');\n
      }\n
    });\n
  }\n
  return {\n
\n
    updateNavigationBox: function () {\n
      /*\n
       * Used by navigation_box gadget. Added here to reduce number of .js files.\n
       */\n
      $.ajax({\n
              url: "ERP5Site_getNavigationBoxActionList",\n
              dataType: "json",\n
              success: function (data) {\n
                        var module_dom = $(\'select[name="select_module"]\'),\n
                            search_type_dom = $(\'select[name="field_your_search_portal_type"]\'),\n
                            language_dom = $(\'select[name="select_language"]\'),\n
                            favorite_dom = $(\'select[name="select_favorite"]\');\n
                        ERP5Form.addOptionTagList(module_dom, data.module_list, "");\n
                        ERP5Form.addOptionTagList(search_type_dom, data.search_portal_type_list, "");\n
                        ERP5Form.addOptionTagDictList(language_dom, data.language_list);\n
\n
                        // add global actions\n
                        addOptionTagDict(favorite_dom, data.favourite_dict.ordered_global_action_list);\n
                        // add user action\n
                        favorite_dom.append(\'<option disabled="disabled">-- User --</option>\');\n
                        addOptionTagDict(favorite_dom, data.favourite_dict.user_action_list);\n
                     }\n
          });\n
    },\n
\n
    updateContextBox: function () {\n
      /*\n
       * Used by context_box gadget. Added here to reduce number of .js files.\n
       */\n
      $.ajax({\n
              url: "ERP5Site_getContextBoxActionList",\n
              dataType: "json",\n
              success: function (data) {\n
                        var jump_dom = $(\'select[name="select_jump"]\'),\n
                            action_dom = $(\'select[name="select_action"]\');\n
                            console.log(data);\n
                        addOptionTagDict(jump_dom, data.object_jump_list);\n
                        addOptionTagDict(jump_dom, data.type_info_list);\n
                        addOptionTagDict(jump_dom, data.workflow_list);\n
                        addOptionTagDict(action_dom, data.visible_allowed_content_type_list);\n
                        addOptionTagDict(action_dom, data.document_template_list);\n
                        addOptionTagDict(action_dom, data.object_workflow_action_list);\n
                        addOptionTagDict(action_dom, data.object_action_list);\n
                        addOptionTagDict(action_dom, data.object_view_list);\n
                        addOptionTagDict(action_dom, data.folder_action_list);\n
                     }\n
          });\n
    }\n
\n
}} ());\n
\n
\n
\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>2993</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
