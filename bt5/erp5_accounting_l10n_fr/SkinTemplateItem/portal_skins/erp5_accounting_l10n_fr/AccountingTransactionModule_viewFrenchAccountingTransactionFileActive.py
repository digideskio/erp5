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
            <value> <string>import random\n
portal = context.getPortalObject()\n
at_date = at_date.latestTime()\n
\n
section_uid_list = portal.Base_getSectionUidListForSectionCategory(\n
  section_category, section_category_strict)\n
\n
from_date = portal.Base_getAccountingPeriodStartDateForSectionCategory(\n
  section_category, at_date)\n
\n
# XXX we need proxy role for that\n
active_process = portal.portal_activities.newActiveProcess()\n
\n
priority = 4\n
\n
for portal_type in portal.getPortalAccountingTransactionTypeList():\n
  # XXX we need proxy role for that\n
  this_portal_type_active_process = portal.portal_activities.newActiveProcess()\n
  context.AccountingTransactionModule_viewFrenchAccountingTransactionFileForPortalType(\n
    portal_type,\n
    section_uid_list,\n
    from_date,\n
    at_date,\n
    simulation_state,\n
    active_process.getRelativeUrl(),\n
    this_portal_type_active_process.getRelativeUrl(),\n
    tag,\n
    aggregate_tag,\n
    priority)\n
\n
context.activate(after_tag=(tag, aggregate_tag)).AccountingTransactionModule_aggregateFrenchAccountingTransactionFile(\n
  at_date,\n
  active_process.getRelativeUrl(),\n
  user_name=user_name)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>section_category, section_category_strict, at_date, simulation_state, user_name, tag, aggregate_tag, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_viewFrenchAccountingTransactionFileActive</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
