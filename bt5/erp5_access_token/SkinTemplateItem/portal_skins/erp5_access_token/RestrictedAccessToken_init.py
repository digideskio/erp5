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
            <value> <string>alpha = \'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\'\n
random_id = \'\'\n
for i in range(0,128):\n
  random_id += random.choice(alpha)\n
\n
# Define Reference from ID provided by portal_ids\n
portal = context.getPortalObject()\n
type_definition = context.getTypeInfo()\n
\n
short_portal_type = type_definition.getShortTitle()\n
if not short_portal_type:\n
  short_portal_type = \'\'.join(s for s in type_definition.getId() if s.isupper())\n
\n
id_group = (\'reference\', short_portal_type)\n
default = 1\n
new_id = portal.portal_ids.generateNewId(id_group=id_group, default=default)\n
reference = \'%s-%s%s\' % (short_portal_type, new_id, random_id)\n
\n
context.setReference(reference)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>RestrictedAccessToken_init</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
