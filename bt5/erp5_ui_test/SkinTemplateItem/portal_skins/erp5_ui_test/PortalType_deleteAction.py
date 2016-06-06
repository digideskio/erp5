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
            <value> <string>"""Delete an action on a type informations from types tool.\n
"""\n
assert context.meta_type in (\'ERP5 Type Information\', \'ERP5 Base Type\'), context.meta_type\n
\n
if context.meta_type == \'ERP5 Type Information\':\n
  existing_actions_indexs = []\n
  for idx, ai in enumerate(context.listActions()):\n
    if ai.getId() == id:\n
      existing_actions_indexs.append(idx)\n
\n
  if existing_actions_indexs:\n
    context.deleteActions(existing_actions_indexs)\n
else:\n
  existing_actions_ids = []\n
  for action in context.objectValues(spec=\'ERP5 Action Information\'):\n
    if action.getReference() == id:\n
      existing_actions_ids.append(action.getId())\n
  if existing_actions_ids:\n
    context.manage_delObjects(existing_actions_ids)\n
\n
return \'Set Successfully.\'\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>id=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PortalType_deleteAction</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
