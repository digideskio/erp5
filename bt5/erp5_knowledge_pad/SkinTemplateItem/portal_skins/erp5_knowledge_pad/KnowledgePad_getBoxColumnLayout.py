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
            <value> <string>if real_context is None:\n
  real_context = context\n
layout = []\n
added_box_ids = []\n
all_box_ids = []\n
boxes = context.contentValues(portal_type = \'Knowledge Box\', \n
                              checked_permission = \'View\')\n
isAnon = context.portal_membership.isAnonymousUser()\n
validation_state_map = {1: (\'public\',),\n
                        0: (\'visible\', \'invisible\', \'public\',)}\n
boxes = filter(lambda x: x.getValidationState() in validation_state_map[isAnon] and x.test(real_context), boxes)\n
for box in boxes:\n
  all_box_ids.append(box.getId())\n
\n
user_layout = getattr(context, \'user_layout\', None)\n
# read layout from pad\n
if user_layout is not None:\n
  sections = user_layout.split(\'##\')\n
  for section in sections:\n
    section_layout = []\n
    boxes = filter(lambda x: x.strip()!=\'\', section.split(\'|\'))\n
    for box in boxes:\n
      box_id = box.replace(\'box_\',\'\').replace(\'_main\',\'\')\n
      ## must exists\n
      if box_id in all_box_ids:\n
        section_layout.append(box_id)\n
        added_box_ids.append(box_id)\n
    layout.append(section_layout)\n
else:\n
  return [all_box_ids]\n
\n
# add new boxes to first column\n
for box_id in all_box_ids:\n
  if not box_id in added_box_ids:\n
    layout[0].append(box_id)\n
return layout\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>real_context=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>KnowledgePad_getBoxColumnLayout</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Get user\'s layout of boxes for a pad</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
