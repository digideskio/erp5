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
            <value> <string>selection_name = \'%s_list_mode_proxy_selection\' % proxy_field_selection_name\n
selection_tool = context.getPortalObject().portal_selections\n
\n
selection_tool.setSelectionParamsFor(selection_name,\n
                              dict(proxy_form_id=proxy_form_id,\n
                                   proxy_field_id=proxy_field_id))\n
\n
return context.Base_viewListModeRenderer(REQUEST=container.REQUEST)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>proxy_field_selection_name=\'\', proxy_form_id=\'\', proxy_field_id=\'listbox\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_viewListMode</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
