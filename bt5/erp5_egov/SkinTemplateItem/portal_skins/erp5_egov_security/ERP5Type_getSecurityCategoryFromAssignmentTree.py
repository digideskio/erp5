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

"""\n
A script returning security categories from a Person\'s assignments.\n
\n
Differences to the stock implementation:\n
\n
*  if category is follow_up, we look for destination_project\n
\n
* if category not strict, we return not only the category, but also all its parents\n
  (unless we say it is strict)\n
"""\n
\n
from Products.ERP5Type.Log import log\n
\n
category_list = []\n
\n
person_module = context.portal_url.getPortalObject().getDefaultModule(\'Person\')\n
# It is better to keep getObject(), in this script this\n
# prevent a very strange bug, sometimes without getObject the\n
# assignment is not found\n
person_object_list = [x.getObject() for x in person_module.searchFolder(portal_type=\'Person\', reference=user_name)]\n
\n
if len(person_object_list) != 1:\n
  if len(person_object_list) > 1:\n
    raise ConsistencyError, "Error: There is more than one Person with reference \'%s\'" % user_name\n
  else:\n
    # if a person_object was not found in the module, we do nothing more\n
    # this happens for example when a manager with no associated person object\n
    # creates a person_object for a new user\n
    return []\n
\n
person_object = person_object_list[0]\n
\n
# We look for valid assignments of this user\n
for assignment in person_object.contentValues(filter={\'portal_type\': \'Assignment\'}):\n
  category_dict = {}\n
  if assignment.getValidationState() == \'open\':\n
    try:\n
      for base_category in base_category_list:\n
        if base_category == \'follow_up\':\n
          category_value = assignment.getDestinationProject()\n
        else:\n
          category_value = assignment.getProperty(base_category)\n
          #XXX the role is not aquire in the assignment get if from the user_object\n
          if base_category==\'role\' and category_value in (None, \'\'):\n
            category_value = person_object.getRole()\n
\n
        if category_value not in (None, \'\'):\n
          if root: category_value=category_value.split(\'/\')[0]\n
          category_dict[base_category] = category_value\n
        else:\n
          raise RuntimeError, "Error: \'%s\' property is required in order to update person security group"  % (base_category)\n
      category_list.append(category_dict)\n
      # if not strict, we go up the hierarchy (because if you work in group/a/b/c, chances are you \n
      # are working in group/a/b, too :)\n
      if not strict:\n
        grouplist = category_value.split(\'/\')\n
        for i in range(1,len(grouplist)):\n
          cdict = category_dict.copy()\n
          cdict[base_category] = \'/\'.join(grouplist[:-i])\n
          category_list.append(cdict)\n
    except RuntimeError,e:\n
      log(str(e))\n
\n
return category_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>base_category_list, user_name, object, portal_type, strict=False, root=False</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Type_getSecurityCategoryFromAssignmentTree</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
