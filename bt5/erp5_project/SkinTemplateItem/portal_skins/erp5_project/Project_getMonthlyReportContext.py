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
            <value> <string>context = context.asContext(object_dict=object_dict,\n
         summary_dict=summary_dict,\n
         column_list=column_list,\n
         project_dict=project_dict,\n
         monthly_project_to_display_dict=monthly_project_to_display_dict,\n
         is_total=is_total,\n
         full_date_string=full_date_string)\n
\n
return context\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>object_dict, summary_dict, column_list, project_dict, monthly_project_to_display_dict,is_total, full_date_string,**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Project_getMonthlyReportContext</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
