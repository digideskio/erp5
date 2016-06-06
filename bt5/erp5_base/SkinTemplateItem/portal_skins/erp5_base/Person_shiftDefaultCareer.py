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
            <value> <string>from Products.CMFActivity.Errors import ActivityPendingError\n
Base_translateString = context.Base_translateString\n
\n
person = context\n
career_list = []\n
\n
default_career = None\n
if \'default_career\' in person.objectIds():\n
  default_career = person[\'default_career\']\n
\n
if default_career is None:\n
  # No default career.\n
  message = Base_translateString(\'Current career must exist.\')\n
  return context.Base_redirect(form_id=form_id,\n
                               selection_name=selection_name,\n
                               selection_index=selection_index,\n
                               keep_items={\'portal_status_message\': message})\n
else:\n
  # Copy and paste the default career.\n
  # Change IDs\n
  new_id = person.generateNewId()\n
  try:\n
    default_career.setId(new_id)\n
  except ActivityPendingError, error:\n
    message = Base_translateString("%s" % error)\n
    return context.Base_redirect(form_id=form_id,\n
                                 selection_name=selection_name,\n
                                 selection_index=selection_index,\n
                                 keep_items={\'portal_status_message\': message})\n
\n
  new_start_date = default_career.getStopDate()\n
\n
  cb_data = person.manage_copyObjects(ids=(new_id,))\n
  copied = person.manage_pasteObjects(cb_data)\n
\n
  new_default_career = getattr(person, copied[0][\'new_id\'])\n
\n
  new_default_career.edit(\n
    id=\'default_career\',\n
    start_date=new_start_date,\n
    stop_date=None)\n
\n
  message = Base_translateString(\'Last career step terminated. New career step added.\')\n
  return context.Base_redirect(form_id=form_id,\n
                               selection_name=selection_name,\n
                               selection_index=selection_index,\n
                               keep_items={\'portal_status_message\': message})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>selection_name=\'\', selection_index=\'0\', form_id=\'view\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Person_shiftDefaultCareer</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
