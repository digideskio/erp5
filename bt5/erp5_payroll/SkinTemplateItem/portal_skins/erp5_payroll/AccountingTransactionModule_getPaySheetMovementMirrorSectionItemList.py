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
            <value> <string>item_list = [(\'\', \'\')]\n
portal = context.getPortalObject()\n
getobject = portal.portal_catalog.getobject\n
\n
for x in portal.portal_simulation.getInventoryList(\n
                              portal_type=(\'Pay Sheet Cell\',\n
                                           \'Pay Sheet Line\'),\n
                              group_by_resource=0,\n
                              group_by_section=0,\n
                              group_by_mirror_section=1):\n
  mirror_section_uid = x.mirror_section_uid\n
  if mirror_section_uid:\n
    mirror_section = getobject(mirror_section_uid)\n
    if mirror_section.getPortalType() == \'Organisation\':\n
      item_list.append((mirror_section.getTitle(),\n
                        mirror_section.getRelativeUrl()))\n
\n
item_list.sort(key=lambda a:a[0])\n
return item_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_getPaySheetMovementMirrorSectionItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
