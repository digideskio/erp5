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
Get security categories from the Assignments of the Person the document\n
is addressed to (destination). Can be multiple destination persons.\n
"""\n
\n
category_list = []\n
\n
# We look for valid assignments of destination users\n
for person_object in object.getDestinationValueList(portal_type=\'Person\'):\n
  for assignment in person_object.contentValues(filter={\'portal_type\': \'Assignment\'}):\n
    if assignment.getValidationState() == \'open\':\n
      category_dict = {}\n
      for base_category in base_category_list:\n
        if base_category == \'follow_up\':\n
          category_value = assignment.getDestinationProject()\n
        else:\n
          category_value = assignment.getProperty(base_category)\n
        if category_value not in (None, \'\'):\n
          category_dict[base_category] = category_value\n
        else:\n
          raise RuntimeError, "Error: \'%s\' property is required in order to update person security group"  % (base_category)\n
      category_list.append(category_dict)\n
\n
return category_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>base_category_list, user_name, object, portal_type</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Type_getSecurityCategoryFromDestinationAssignment</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
