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
            <value> <string>kwd = context.ERP5Accounting_getParams(selection_name)\n
# cleanup unsupported catalog parameters\n
kwd.pop(\'period_start_date\', None)\n
kwd.pop(\'detailed_from_date_summary\', None)\n
\n
if kw.get(\'stat\'):\n
  selection_params = context.portal_selections.getSelectionParamsFor(selection_name)\n
  selection_domain = context.portal_selections.getSelectionDomainDictFor(selection_name)\n
  if callable(selection_domain):\n
    selection_domain = selection_domain()\n
  selection_report = context.portal_selections.getSelectionReportDictFor(selection_name)\n
  if selection_domain:\n
    kwd[\'selection_domain\'] = selection_domain\n
  if selection_report:\n
    kwd[\'selection_report\'] = selection_report\n
  if context.portal_selections.getSelectionInvertModeFor(selection_name):\n
    kwd[\'stock.node_uid\'] = context.portal_selections.getSelectionInvertModeUidListFor(selection_name)\n
  # is list filtered ?\n
  elif \'title\' in selection_params or \\\n
      \'preferred_gap_id\' in selection_params or\\\n
      \'id\' in selection_params or \\\n
      \'translated_validation_state_title\' in selection_params:\n
    selection_params[\'ignore_unknown_columns\'] = True\n
    # if yes, apply the same filter here\n
    kwd[\'stock.node_uid\'] = [x.uid for x in\n
                         context.portal_catalog(**selection_params)]\n
  else:\n
    kwd[\'portal_type\'] = context.getPortalAccountingMovementTypeList()\n
  return context.portal_simulation.getInventoryStat( **kwd )[0][\'stock_uid\']\n
\n
kwd[\'stock.node_uid\'] = brain.uid\n
\n
return context.portal_simulation.getInventoryStat( **kwd )[0][\'stock_uid\']\n
# vim: syntax=python\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>selection=None, brain=None, selection_name=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getAccountingTransactionCount</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
