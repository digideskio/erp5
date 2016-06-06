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
            <value> <string>from Products.ERP5Form.Report import ReportSection\n
result=[]\n
request = context.REQUEST\n
\n
selection_columns = [(\'ticket_title\', \'Title\')]\n
selection_columns.append((\'ticket_type\', \'Module\'))\n
selection_columns.append((\'resource\',\'Type\'))\n
#Add dynamicaly event states columns to the form\n
#The name of column must be without spaces\n
for event_state in context.ERP5Site_getWorkflowStateItemList(\n
    portal_type=context.getPortalEventTypeList(), state_var=\'simulation_state\', translate=False):\n
  if event_state[1]!=\'deleted\':\n
    selection_columns.append((event_state[1],event_state[0]))\n
selection_columns.append((\'total\', \'Total\'))\n
\n
result.append(ReportSection(\n
              path=context.getPhysicalPath(),\n
              selection_columns=selection_columns,\n
              listbox_display_mode=\'FlatListMode\',\n
              form_id=\'EventModule_viewEventDetailedList\'))\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>EventModule_getEventDetailedReportSectionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
