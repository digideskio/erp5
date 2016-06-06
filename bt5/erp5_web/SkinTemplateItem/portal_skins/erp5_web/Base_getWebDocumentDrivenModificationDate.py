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
            <value> <string>from Products.ERP5Type.Cache import CachingMethod\n
\n
def getLatestModificationDate():\n
  document = context.getPortalObject().portal_catalog(\n
    portal_type=("Web Section", "Web Site",) + context.getPortalDocumentTypeList(),\n
    sort_on=((\'modification_date\', \'descending\'),),\n
    select_list=(\'modification_date\',),\n
    limit=1,\n
    )\n
  if document:\n
    return document[0].modification_date\n
  return getattr(context, \'getModificationDate\', context.modified)()\n
\n
getLatestModificationDate = CachingMethod(\n
  getLatestModificationDate,\n
  id="Base_getWebDocumentDrivenModificationDate",\n
  cache_factory="erp5_content_short",\n
  )\n
\n
return getLatestModificationDate()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getWebDocumentDrivenModificationDate</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
