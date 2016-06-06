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
This script returns a list of dictionaries which represent\n
the security groups to define a local role. It extracts\n
the categories from the current membership criterion\n
of a Predicate. It is useful in the following cases:\n
\n
- assign a security group to a Web Section\n
  based on the member ship criterion.\n
\n
The parameters are\n
\n
  base_category_list -- list of acceptable base categories\n
                        (used to filter part of the criteria)\n
  user_name          -- the user identifier (not used)\n
  object             -- object which we want to assign roles to\n
  portal_type        -- portal type of object\n
"""\n
\n
category_list = []\n
\n
if object is None:\n
  return []\n
\n
criterion_list = object.getMembershipCriterionCategoryList()\n
for criterion in criterion_list:\n
  id_list = criterion.split(\'/\')\n
  base_category = id_list[0]\n
  if base_category in base_category_list:\n
    category = \'/\'.join(id_list[1:])\n
    category_list.append({base_category : category})\n
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
            <value> <string>ERP5Type_getSecurityCategoryFromMembershipCriterion</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
