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
            <value> <string>computer = context\n
Base_translateString = context.Base_translateString\n
computer_model_portal_type = \'Computer Model\'\n
\n
computer_model = computer.getSpecialiseValue(\n
  portal_type=computer_model_portal_type)\n
\n
if computer_model is None:\n
  message = Base_translateString(\'No Computer Model.\')\n
  result = False\n
else :\n
  category_list = [\n
    \'cpu_core\',\n
    \'cpu_frequency\',\n
    \'cpu_type\',\n
    \'function\',\n
    \'group\',\n
    \'local_area_network_type\',\n
    \'memory_size\',\n
    \'memory_type\',\n
    \'role\',\n
    \'region\',\n
    \'storage_capacity\',\n
    \'storage_interface\',\n
    \'storage_redundancy\',\n
    \'wide_area_network_type\'\n
  ]\n
\n
  new_category_dict = {}\n
  for category in category_list:\n
    if force or not computer.getPropertyList(category):\n
      v = computer_model.getPropertyList(category)\n
      if v:\n
        new_category_dict[category] = v\n
\n
  if new_category_dict:\n
    computer.edit(**new_category_dict)\n
    message = Base_translateString(\'Computer Model applied.\')\n
    result = True\n
  else:\n
    message = Base_translateString(\'No changes applied.\')\n
    result = False\n
\n
if not batch_mode:\n
  return context.Base_redirect(form_id,\n
          keep_items=dict(portal_status_message=message))\n
else:\n
  return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=\'view\', batch_mode=0, force=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Computer_applyComputerModel</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
