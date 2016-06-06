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
            <value> <string>"""\n
  Update the test report\n
"""\n
\n
result_list = context.restrictedTraverse(\'/erp5/portal_tests/\' + zuite_id).objectValues(\'Zuite Results\')\n
result_list = sorted(result_list, key=lambda x: x.getId())\n
context.setTestReport(sorted(result_list[-1].objectValues(), key=lambda x: x.getId())[-1])\n
\n
return context.Base_redirect(\'TestPage_viewTestReport\', portal_status_message=context.Base_translateString(\'Test Report updated\'))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>zuite_id</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestPage_updateReport</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
