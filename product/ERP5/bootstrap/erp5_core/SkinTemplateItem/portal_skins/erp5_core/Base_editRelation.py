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

# Updates relation of an ERP5 document\n
from Products.ERP5Type.Message import Message\n
from Products.Formulator.Errors import ValidationError\n
from Products.ERP5Form.MultiRelationField import SUB_FIELD_ID\n
\n
if listbox_uid is not None:\n
  selection_tool = context.getPortalObject().portal_selections\n
  selected_uids = selection_tool.updateSelectionCheckedUidList(\n
              selection_name, listbox_uid, uids)\n
  uids = selection_tool.getSelectionCheckedUidsFor(selection_name)\n
\n
old_request = dict(saved_form_data)\n
\n
field = getattr(context, form_id).get_field(field_id)\n
field_key = field.generate_field_key()\n
if old_request.has_key(\'sub_index\'):\n
  if len(uids) > 0:\n
    # XXX Hardcoded\n
    sub_field_key = field.generate_subfield_key("%s_%s" % (SUB_FIELD_ID, old_request[\'sub_index\']), key=field_key)\n
    old_request[sub_field_key] = str(uids[0])\n
else:\n
  # XXX Not very dynamic...\n
  sub_field_key = field.generate_subfield_key(SUB_FIELD_ID, key=field_key)\n
  old_request[sub_field_key] = uids\n
  old_request[field_key] = uids\n
\n
request = container.REQUEST\n
request_form = request.form\n
for k in request_form.keys():\n
  del request_form[k]\n
\n
request.form.update(old_request)\n
edit_method = getattr(context, request_form.get(\'form_action\', \'Base_edit\'))\n
return edit_method(form_id,\n
                   ignore_layout=request.get(\'ignore_layout\', True),\n
                   selection_index=old_request.get(\'selection_index\', 0),\n
                   selection_name=old_request.get(\'selection_name\', \'\'))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, field_id, selection_index, selection_name, uids, listbox_uid, saved_form_data, batch_mode=0, object_uid=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_editRelation</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
