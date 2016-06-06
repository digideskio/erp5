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
  Returns the list of owners of the given context. Owners\n
  are normally Person objects in ERP5. However, this behaviour\n
  could be extended in the future or for specific projects.\n
\n
  NOTE: we usually asume that there is only a single owner\n
  or that, at least,  only the first owner matters for\n
  the "My Documents" list.\n
\n
  TODO:\n
  - how can we make sure that is is consistent with \n
    ERP5Site_getAuthenticatedMemberPersonValue \n
    in erp5_base ?\n
"""\n
from zExceptions import Unauthorized\n
owner_value_list = []\n
try:\n
  owner_id_list = [i[0] for i in context.get_local_roles() if \'Owner\' in i[1]]\n
except Unauthorized:\n
  owner_id_list = []\n
\n
if len(owner_id_list):\n
  return context.portal_catalog(portal_type=\'Person\', reference=owner_id_list)\n
else:\n
  return []\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getOwnerValueList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
