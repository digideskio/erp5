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
  This scripts add the balance of every gap account in the list \'account_id_list\'\n
  it use portal_simulation.getInventory. \n
\n
  The following REQUEST keys are mandatory : \n
      at_date\n
\n
  those are optional : \n
      gap_base\n
      simulation_state\n
      resource\n
      section_category\n
\n
  those are ignored from the request and should explicitely passed as keywords args to this script : \n
      from_date\n
  \n
  parameters keywords to this script overrides REQUEST keys\n
\n
"""\n
portal = context.getPortalObject()\n
request = context.REQUEST\n
\n
kw = dict(kwd)\n
kw[\'simulation_state\'] = kwd.get(\'simulation_state\', request.get(\'simulation_state\'))\n
kw["section_category"] = kwd.get(\'section_category\', request.get(\'section_category\'))\n
kw["at_date"] = request[\'at_date\'].latestTime()\n
at_date = kwd.get(\'at_date\', request[\'at_date\'])\n
kw[\'at_date\'] = at_date.latestTime()\n
\n
if request.get(\'account_id_list_conversion_script_id\'):\n
  account_id_list_conversion_script = getattr(portal, request[\'account_id_list_conversion_script_id\'])\n
  kw[\'node_category\'] = account_id_list_conversion_script(account_id_list)\n
else:\n
  kw[\'node_category\'] = account_id_list\n
\n
context.log(kw)\n
\n
return portal.portal_simulation.getInventoryAssetPrice(**kw) or 0.0\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>account_id_list, **kwd</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getFiscalReportBalance</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
