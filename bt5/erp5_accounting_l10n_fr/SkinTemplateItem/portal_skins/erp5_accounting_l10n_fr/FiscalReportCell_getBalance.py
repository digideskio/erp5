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

"""\n
  This script adds accounts value.\n
"""\n
\n
request = context.REQUEST\n
\n
include_debtor   = True\n
include_creditor = True\n
if debtor_only  : include_creditor = False\n
if creditor_only: include_debtor   = False\n
\n
gap_base = request.get(\'gap_base\', kwd.get(\'gap_base\', \'gap/fr/pcg/\'))\n
getURL   = lambda gap_id: context.GAPCategory_getURLFromId(gap_id, gap_base)\n
\n
\n
kw = dict(kwd)\n
kw[\'simulation_state\'] = kwd.get(\'simulation_state\', request.get(\'simulation_state\', [\'stopped\', \'delivered\']))\n
kw["section_category"]  = kwd.get("section_category",\n
                            "group/%s"%context.restrictedTraverse(request.get("organisation")).getGroup())\n
kw[\'to_date\'] = kwd.get(\'at_date\', request[\'at_date\']) +1\n
kw[\'where_expression\'] = " section.portal_type = \'Organisation\' "\n
\n
sum = 0.0\n
for accountNumber in accounts:\n
  # we get all acounts strict member of this GAP category\n
  gap = context.restrictedTraverse("portal_categories/" + getURL(accountNumber))\n
  for account in gap.getGapRelatedValueList(portal_type=\'Account\') :\n
    result = context.getPortalObject().portal_simulation.getInventoryAssetPrice(node_uid = account.getUid(), **kw)\n
    if (result < 0 and include_creditor) or \\\n
       (result > 0 and include_debtor):\n
      sum += result\n
\n
return sum\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>accounts, debtor_only=False, creditor_only=False, **kwd</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>FiscalReportCell_getBalance</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
