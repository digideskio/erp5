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
            <value> <string>from Products.ERP5Type.Message import translateString\n
cb_data = context.manage_copyObjects(\n
     ids=[r.getId() for r in context.contentValues(portal_type=\'Role Information\')])\n
\n
if portal_type_group_list is not None:\n
  for ti in context.portal_types.contentValues():\n
    if ti == context or ti.getId() in portal_type_list:\n
      continue\n
    for group in ti.getTypeGroupList():\n
      if group in portal_type_group_list:\n
        portal_type_list.append(ti.getId())\n
        break\n
\n
for ti in portal_type_list:\n
  destination_portal_type = context.portal_types[ti]\n
  if remove_existing_roles:\n
    destination_portal_type.manage_delObjects(ids=[r.getId() for r in\n
            destination_portal_type.contentValues(portal_type=\'Role Information\')])\n
\n
  destination_portal_type.manage_pasteObjects(cb_data)\n
 \n
return context.Base_redirect(form_id,\n
  keep_items=dict(portal_status_message=translateString(\'Roles copied in ${type_list}\',\n
                          mapping=dict(type_list=\', \'.join(portal_type_list)))))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>remove_existing_roles, portal_type_list, portal_type_group_list=None, form_id=\'view\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BaseType_copyRoleList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
