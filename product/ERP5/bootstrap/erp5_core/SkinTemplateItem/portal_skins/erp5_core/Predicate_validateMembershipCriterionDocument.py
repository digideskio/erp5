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
            <value> <string># XXX the name of this script is bad as the context is not a predicate\n
\n
category_list = request.get(\'field_my_membership_criterion_base_category_list\', [])\n
if not same_type(category_list, []):\n
  category_list = [category_list]\n
multimembership_criterion_base_category_list = request.get(\'field_my_multimembership_criterion_base_category_list\', [])\n
if not same_type(multimembership_criterion_base_category_list, []):\n
  multimembership_criterion_base_category_list = [multimembership_criterion_base_category_list]\n
category_list += [i for i in multimembership_criterion_base_category_list \\\n
                  if i not in category_list]\n
portal_categories = context.getPortalObject().portal_categories\n
\n
for item in item_list:\n
  base_category, relative_url = item.split(\'/\', 1)\n
  if base_category not in category_list or \\\n
      portal_categories.restrictedTraverse(relative_url, None) is None:\n
    return 0\n
return 1\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>item_list, request</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Predicate_validateMembershipCriterionDocument</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
