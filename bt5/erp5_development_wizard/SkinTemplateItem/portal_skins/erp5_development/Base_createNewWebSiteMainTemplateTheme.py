<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>Script_magic</string> </key>
            <value> <int>3</int> </value>
        </item>
        <item>
            <key> <string>_bind_names</string> </key>
            <value>
              <object>
                <klass>
                  <global name="NameAssignments" module="Shared.DC.Scripts.Bindings"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_asgns</string> </key>
                        <value>
                          <dictionary>
                            <item>
                                <key> <string>name_container</string> </key>
                                <value> <string>container</string> </value>
                            </item>
                            <item>
                                <key> <string>name_context</string> </key>
                                <value> <string>context</string> </value>
                            </item>
                            <item>
                                <key> <string>name_m_self</string> </key>
                                <value> <string>script</string> </value>
                            </item>
                            <item>
                                <key> <string>name_subpath</string> </key>
                                <value> <string>traverse_subpath</string> </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>_body</string> </key>
            <value> <string encoding="cdata"><![CDATA[

skin_folder = getattr(context.portal_skins, skin_folder_id)\n
\n
# Maybe this is a bit ugly, and lxml should be used\n
template = context.portal_skins.erp5_development.template_theme_web_main\n
template_source = template.document_src()\n
template_body_top, template_body_bottom = template_source.split("<!-- SPLIT -->")\n
new_code = context.ERP5Site_updateCodeWithMainContent(html_text, main_div_class_name)\n
new_code_0 = new_code.replace("<body>", template_body_top)\n
new_code_1 = new_code_0.replace("</body>", template_body_bottom)\n
new_code_2 = new_code_1.replace("\'__REPLACE_CSS__\'", css_tales)\n
final_code = new_code_2.replace("\'__REPLACE_JS__\'", js_tales)\n
\n
\n
skin_folder.manage_addProduct[\'PageTemplates\'].manage_addPageTemplate(main_template_id, "Default Template")\n
getattr(skin_folder, main_template_id).write(final_code)\n
\n
return "OK"\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>html_text, main_template_id, skin_folder_id, css_tales, js_tales, main_div_class_name</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_createNewWebSiteMainTemplateTheme</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
