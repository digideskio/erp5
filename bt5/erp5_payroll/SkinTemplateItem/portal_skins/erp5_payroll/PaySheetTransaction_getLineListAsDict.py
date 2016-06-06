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
            <value> <string>\'\'\'\n
  this script get all paysheet lines in the int_index order with all the amounts\n
  displayed in the lisbox\n
\'\'\'\n
line_list = context.PaySheetTransaction_getMovementList(sort_on=[(\'int_index\',\n
                                                                  \'ascending\')])\n
def addProperties(line, line_dict, property_list):\n
  for property in property_list:\n
    line_dict[property] = getattr(line, property, None)\n
  return line_dict\n
\n
line_dict_list = []\n
property_list = [ \'slice\',\n
                  \'base_contribution_list\',\n
                  \'base_application_list\',\n
                  \'base_name\',\n
                  \'base\',\n
                  \'employer_price\',\n
                  \'employer_quantity\',\n
                  \'employee_price\',\n
                  \'employee_quantity\',\n
                  \'causality\',\n
                ]\n
for line in line_list:\n
  if line.getResourceId() == \'total_employee_contributions\':\n
    continue\n
  line_dict = {\n
      \'group\'  : line.getSourceSectionTitle(),\n
      \'source_section_title\': line.getSourceSectionTitle(),\n
      \'title\'  : line.getTitle(),\n
      \'service\' : getattr(line, \'service\', None),\n
      \'employer_total_price\' : getattr(line, \'employer_total_price\', None),\n
      \'employee_total_price\' : getattr(line, \'employee_total_price\', None),\n
      }\n
\n
  addProperties(line=line, line_dict=line_dict, property_list=property_list)\n
\n
  line_dict_list.append(line_dict)\n
\n
return line_dict_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PaySheetTransaction_getLineListAsDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
