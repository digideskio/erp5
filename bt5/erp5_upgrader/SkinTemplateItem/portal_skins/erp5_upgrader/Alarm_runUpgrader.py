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
  Run Upgrader\n
\n
  IMPORTANT: Don\'t use the constraint_type upgrader to data migration or big amount of objects,\n
  because this step is suppose to run all constraints in the same transaction. \n
  To not kill the instance, searchAndActivate will be used if countResults() > REINDEX_SPLIT_COUNT\n
"""\n
\n
REINDEX_SPLIT_COUNT = 100\n
portal = context.getPortalObject()\n
portal_alarms = portal.portal_alarms\n
active_process = context.newActiveProcess()\n
\n
# We should not run upgrader if pre upgrade was not solved or never executed \n
alarm = getattr(portal_alarms, \'upgrader_check_pre_upgrade\')\n
if not(force) and alarm.sense() in (None, True):\n
  active_process.postActiveResult(summary=context.getTitle(),\n
      severity=1,\n
      detail=["Is required solve Pre Upgrade first. You need run active sense once at least on this alarm"])\n
  return\n
\n
_, type_per_constraint_type = context.Base_getConstraintTypeListPerPortalType()\n
portal_type_list = type_per_constraint_type.get(\'upgrader\', [])\n
\n
tool_portal_type = \'Template Tool\' \n
if tool_portal_type in portal_type_list:\n
  portal_type_list.remove(tool_portal_type)\n
\n
method_kw = {\'fixit\': True,\n
  \'filter\': {"constraint_type": \'upgrader\'},\n
  \'active_process\': active_process.getRelativeUrl()}\n
\n
portal.portal_templates.Base_postCheckConsistencyResult(**method_kw)\n
for portal_type in portal_type_list:\n
  if portal.portal_catalog.countResults(\n
      portal_type=portal_type_list)[0][0] > REINDEX_SPLIT_COUNT:\n
    portal.portal_catalog.searchAndActivate(\'Base_postCheckConsistencyResult\',\n
      activate_kw=activate_kw,\n
      portal_type=portal_type,\n
      method_kw=method_kw)\n
  else:\n
    for result in portal.portal_catalog(portal_type=portal_type):\n
      result.Base_postCheckConsistencyResult(**method_kw)\n
\n
context.setEnabled(False)\n
return\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>force=0, activate_kw={}, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Alarm_runUpgrader</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
