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
            <value> <string>from Products.ERP5Type.Errors import ProgrammingError\n
\n
zTrimInventoryCacheFromDateOnCatalog = getattr(context, \'SimulationTool_zTrimInventoryCacheFromDateOnCatalog\', None)\n
if zTrimInventoryCacheFromDateOnCatalog is None:\n
  return\n
\n
min_date = None\n
for loop_item in xrange(len(uid)):\n
    if not isInventoryMovement[loop_item] and isMovement[loop_item] and getResourceUid[loop_item]:\n
        if getDestinationUid[loop_item] and getStopDate[loop_item]:\n
            if min_date:\n
                min_date = min(min_date, getStopDate[loop_item])\n
            else:\n
                min_date = getStopDate[loop_item]\n
        if getSourceUid[loop_item] and getStartDate[loop_item]:\n
            if min_date:\n
                min_date = min(min_date, getStartDate[loop_item])\n
            else:\n
                min_date = getStartDate[loop_item]\n
\n
try:\n
    zTrimInventoryCacheFromDateOnCatalog(uid_list=uid, min_date=min_date)\n
except ProgrammingError:\n
    # Create table if it does not exits\n
    # Then no need to flush an empty table\n
    context.SimulationTool_zCreateInventoryCache()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>uid, isMovement, isInventoryMovement, getResourceUid, getDestinationUid, getStopDate, getSourceUid, getStartDate</string> </value>
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
            <value> <string>SQLCatalog_trimInventoryCacheOnCatalog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
