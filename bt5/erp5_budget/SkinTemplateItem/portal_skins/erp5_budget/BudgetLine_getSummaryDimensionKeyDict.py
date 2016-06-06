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
            <value> <string>"""Returns a dictionnary of dependant variation categories for this budget\n
line.\n
This can be used to know if a budget cell aggregates the values from other\n
budget cells.\n
For example, the returned dictionnary can be:\n
  { \'function/f\': [\'function/f/f1\', \'function/f/f2\'],\n
    \'source/account_type/asset\': [\'source/account_type/asset/cash\'], }\n
As we can see on the example, only individual categories are returned, not cell\n
coordinates.\n
"""\n
# look on the budget model to see which base categories are used for non strict\n
# membership. We will only update summaries for thoses axis\n
non_strict_base_category_set = {}\n
budget_model = context.getParentValue().getSpecialiseValue()\n
if budget_model is not None:\n
  for budget_variation in budget_model.contentValues(\n
        portal_type=context.getPortalBudgetVariationTypeList()):\n
    if budget_variation.isMemberOf(\'budget_variation/budget_cell\') \\\n
        and budget_variation.getInventoryAxis() in (\n
            \'movement\',\n
            \'node_category\',\n
            \'mirror_node_category\',\n
            \'section_category\',\n
            \'mirror_section_category\',\n
            \'function_category\',\n
            \'project_category\',\n
            \'payment_category\',):\n
\n
      non_strict_base_category_set[\n
          budget_variation.getProperty(\'variation_base_category\')] = True\n
  \n
def reversed(seq):\n
  seq = seq[::]\n
  seq.sort(reverse=True)\n
  return seq\n
\n
# build a dict of dependant dimensions\n
dependant_dimensions_dict = {}\n
for bc in non_strict_base_category_set.keys():\n
  vcl = reversed(context.getVariationCategoryList(base_category_list=(bc,)))\n
  for vc in vcl:\n
    dependant_vc_list = [other_vc for other_vc in vcl\n
                          if other_vc.startswith(\'%s/\' % vc)\n
                          and other_vc not in dependant_dimensions_dict]\n
    if dependant_vc_list:\n
      dependant_dimensions_dict[vc] = dependant_vc_list\n
\n
return dependant_dimensions_dict\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BudgetLine_getSummaryDimensionKeyDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
