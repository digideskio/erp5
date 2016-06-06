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
            <value> <string># Remove empty items\n
item_list = filter(lambda x: x not in [(\'\',\'\'), [\'\',\'\']],\\\n
                   item_list)\n
\n
sub_field_dict = {}\n
split_depth = 1\n
\n
# Build a dict of title to display, based on the titles of corresponding\n
# budget variations, and a dict of indexes for sorting.\n
# Also build a list of line level variations, for which we only choose one value.\n
base_category_title_dict = {}\n
base_category_int_index_dict = {}\n
budget_line = container.REQUEST.get(\'here\')\n
line_level_variation_list = []\n
if budget_line is not None:\n
  budget_model =budget_line.getParentValue().getSpecialiseValue()\n
  if budget_model is not None:\n
    for budget_variation in budget_model.contentValues():\n
      if budget_variation.hasTitle():\n
        base_category_title_dict[\n
          budget_variation.getProperty(\'variation_base_category\')\n
          ] =  budget_variation.getTranslatedTitle()\n
      base_category_int_index_dict[\n
          budget_variation.getProperty(\'variation_base_category\')\n
          ] =  budget_variation.getIntIndex()\n
      if budget_variation.isMemberOf(\'budget_variation/budget_line\'):\n
        line_level_variation_list.append(budget_variation.getProperty(\'variation_base_category\'))\n
\n
resolveCategory = context.getPortalObject().portal_categories.resolveCategory\n
\n
for item in item_list:\n
  # Get value of the item\n
  item_value = item[int(not is_right_display)]\n
\n
  # Hash key from item_value\n
  item_split = string.split(item_value, \'/\')\n
  item_key = string.join(item_split[:split_depth] , \'/\' )\n
  base_category = item_split[0]\n
  multi = True\n
\n
  if item_key in line_level_variation_list:\n
    multi = False\n
\n
  if not sub_field_dict.has_key(item_key):\n
    # Create property dict\n
    sub_field_property_dict = default_sub_field_property_dict.copy()\n
    sub_field_property_dict[\'key\'] = item_key\n
    sub_field_property_dict[\'required\'] = 0\n
    sub_field_property_dict[\'field_type\'] = multi and \'MultiListField\' or \'ListField\'\n
    sub_field_property_dict[\'size\'] = multi and 15 or 1\n
    sub_field_property_dict[\'item_list\'] = [(\'\',\'\')]\n
    sub_field_property_dict[\'value\'] = []\n
    sub_field_dict[item_key] = sub_field_property_dict\n
\n
  sub_field_dict[item_key][\'item_list\'] =\\\n
     sub_field_dict[item_key][\'item_list\'] + [item]\n
\n
  if item_value in value_list:\n
    if multi:\n
      sub_field_dict[item_key][\'value\'] =\\\n
        sub_field_dict[item_key][\'value\'] + [item_value]\n
    else:\n
      sub_field_dict[item_key][\'value\'] = item_value\n
\n
  sub_field_dict[item_key][\'int_index\'] = base_category_int_index_dict.get(\n
                                                    base_category, -1)\n
\n
  if base_category in base_category_title_dict:\n
    sub_field_dict[item_key][\'title\'] = base_category_title_dict[base_category]\n
  else:\n
    base_category_value = resolveCategory(base_category)\n
    if base_category_value is not None:\n
      sub_field_dict[item_key][\'title\'] = base_category_value.getTranslatedTitle()\n
    else:\n
      sub_field_dict[item_key][\'title\'] = base_category\n
\n
return sorted(sub_field_dict.values(), key=lambda d:d[\'int_index\'])\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>item_list, value_list, default_sub_field_property_dict={}, is_right_display=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BudgetLine_hashVariationCategoryList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
