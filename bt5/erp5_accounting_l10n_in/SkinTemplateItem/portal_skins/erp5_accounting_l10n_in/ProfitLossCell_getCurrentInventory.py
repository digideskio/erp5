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
            <value> <string>organisation_id = context.restrictedTraverse(request[\'organisation\']).getUid()\n
account = context.portal_categories.restrictedTraverse(\'account_module/\'+account_name)\n
\n
extstr = \'\'\n
if column == 2:\n
  extstr=\'2\'\n
\n
return context.portal_simulation.getInventory(\n
node_uid = account.getUid(),\n
section_id = organisation_id,\n
at_date=request[\'at_date\'+extstr],\n
from_date=request[\'from_date\'+extstr])\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>account_name, request, column=1</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ProfitLossCell_getCurrentInventory</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
