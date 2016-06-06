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

editable_property_id_list = (\'id\', \'title\', \'short_title\', \'reference\',\n
                             \'codification\', \'int_index\', \'description\')\n
\n
def getHeaderTitle(property_id):\n
  return \' \'.join([s.capitalize() for s in property_id.split(\'_\')])\n
\n
cat_info_list = []\n
for base_cat_id in context.REQUEST[\'category_list\']:\n
  base_cat = context.portal_categories[base_cat_id]\n
  d = {\'base_cat\': base_cat}\n
  d[\'cat_list\'] = cat_list = []\n
  d[\'max_cat_depth\'] = max_cat_depth = 0\n
  cat_info_list.append(d)\n
  temporary_category_list = []\n
  for cat in context.portal_catalog(portal_type=\'Category\',\n
                                    sort_on=((\'path\', \'ascending\'),),# This sorting is not enough.\n
                                    limit=None,\n
                                    **{\'default_%s_uid\' % (base_cat.getId(),): base_cat.getUid()}):\n
    cat_relative_url_path_list = cat.getRelativeUrl().split(\'/\')\n
    cat_depth = len(cat_relative_url_path_list)\n
    temporary_category_list.append((cat_relative_url_path_list, cat))\n
    if cat_depth > d[\'max_cat_depth\']:\n
      d[\'max_cat_depth\'] = cat_depth\n
  # Sort by split path by Python, if you sort with "/" by MySQL, then the result will be like (\'A\',\'A_B/1\',\'A_B/2\',\'A/1\',\'A/2\')\n
  temporary_category_list.sort()\n
  d[\'cat_list\'] = [i[1] for i in temporary_category_list]\n
\n
result = []\n
for cat_info in cat_info_list:\n
  table_dict = {\'name\': cat_info[\'base_cat\'].getId()}\n
  table_dict[\'row_list\'] = row_list = []\n
  result.append(table_dict)\n
\n
  # make headers\n
  header_dict = {}\n
  table_dict[\'header_row\'] = header_dict\n
\n
  cat_list = cat_info[\'cat_list\']\n
  if cat_list:\n
    max_cat_depth = cat_info[\'max_cat_depth\']\n
    header_dict[\'path_cell_list\'] = [\'\'] * (max_cat_depth - 1)\n
    header_dict[\'path_cell_list\'][0] = \'Path\'\n
    header_dict[\'category_property_list\'] = [getHeaderTitle(property_id)\n
                                             for property_id in editable_property_id_list]\n
    for cat in cat_list:\n
      path_cell_list = [\'\'] * (max_cat_depth - 1)\n
      path_cell_list[len(cat.getRelativeUrl().split(\'/\')) - 2] = \'*\'\n
      category_property_list = map(cat.getProperty, editable_property_id_list)\n
      row_list.append({\n
        \'path_cell_list\': path_cell_list,\n
        \'category_property_list\': category_property_list,\n
        })\n
  else:\n
    header_dict[\'path_cell_list\'] = [\'Path\']\n
    header_dict[\'category_property_list\'] = []\n
\n
return result\n
#vim: filetype=python\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CategoryTool_constructCategoryTableToExport</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
