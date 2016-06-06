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

request = context.REQUEST\n
\n
project_line_portal_type = \'Project Line\'\n
\n
domain_list = []\n
\n
here = context.REQUEST[\'here\']\n
portal = context.getPortalObject()\n
form_id=request.get(\'form_id\')\n
selection_name = request.get(\'selection_name\')\n
params = portal.portal_selections.getSelectionParamsFor(selection_name, request)\n
object_path = request.get(\'object_path\')\n
if object_path is None:\n
  object_path = context.REQUEST.get(\'URL1\').split(\'/\')[-1]\n
search_path = \'project_module/%s/%%\' % object_path\n
category_list = []\n
\n
if depth == 0:\n
  # Get start date and stop date from document\n
  from_date = request.get(\'from_date\')\n
  at_date = request.get(\'at_date\')\n
  current_month = None\n
  # We must initialize from_date at the beginning of the month\n
  current_date = from_date\n
  is_total = here.is_total\n
  if is_total:\n
    category_list.append(here.getObject().asContext(title=here.full_date_string,\n
                                                    string_index=here.full_date_string,\n
                                                    ))\n
  else:\n
    month_dict = request.form.get(\'month_dict\', None)\n
    if month_dict is None:\n
      month_dict = {}\n
      current_date_year = current_date.year()\n
      current_date_month = current_date.month()\n
      at_date_year = at_date.year()\n
      at_date_month = at_date.month()\n
      while True:\n
        month_dict[(current_date_year, current_date_month)] = 1\n
        if current_date_year == at_date_year and current_date_month == at_date_month:\n
          break\n
        current_date_month += 1\n
        if current_date_month == 13:\n
          current_date_month = 0\n
          current_date_year += 1\n
      request.form[\'month_dict\'] = month_dict\n
\n
    category_list = []\n
    #i = 1\n
    month_dict_list = month_dict.keys()\n
    month_dict_list.sort()\n
    for year, month in month_dict_list:\n
      category_list.append(here.getObject().asContext(title="%s - %s" % (year, month),\n
                                                      string_index="%s-%s" % (year, month),\n
                                                      ))\n
      #i += 1\n
\n
else:\n
  object_dict = here.object_dict\n
  string_index = getattr(parent, \'string_index\')\n
  object_sub_dict = object_dict.get(string_index, {})\n
  object_url_dict = {}\n
  project_to_display_dict = here.monthly_project_to_display_dict.get(string_index, {})\n
  if depth == 1:\n
    category_list = [here.project_dict[x] for x in project_to_display_dict.keys() if\n
                        here.project_dict.has_key(x)]\n
  else:\n
    parent_category_list = parent.getMembershipCriterionCategoryList()\n
    category_list = []\n
    # Very specific to the monthly report, if no data, we do not display the current tree part\n
    # sor first, for performance, build a dict with all relative urls of project line that will\n
    # need to be displayed for this month\n
    object_dict = here.object_dict\n
\n
    object_sub_dict = object_dict.get(getattr(parent, \'string_index\'), {})\n
    object_url_dict = {}\n
    for parent_category in parent_category_list:\n
      parent_category = \'/\'.join(parent_category.split(\'/\')[1:])\n
      if project_to_display_dict.has_key(parent_category):\n
\tparent_category_object = context.restrictedTraverse(parent_category)\n
\tcategory_child_list = parent_category_object.contentValues(portal_type=project_line_portal_type)\n
\t#category_list.append(parent_category_object)\n
\tfor category_child in category_child_list:\n
\t  if project_to_display_dict.has_key(category_child.getRelativeUrl()):\n
\t    category_list.append(category_child)\n
\n
\n
i = 0\n
for category in category_list:\n
  string_index = getattr(category, \'string_index\', None)\n
  if string_index is None:\n
    string_index = getattr(parent, \'string_index\')\n
  domain_kw = {}\n
  if depth >= 1:\n
    domain_kw[\'membership_criterion_base_category\'] = (\'source_project\', )\n
    domain_kw[\'membership_criterion_category\'] = (\'source_project/\' + category.getRelativeUrl(),)\n
  domain = parent.generateTempDomain(id = \'%s_%s\' % (depth, i))\n
  domain.edit(title = category.getTitle(),\n
              domain_generator_method_id = script.id,\n
              criterion_property_list = [\'string_index\'] ,\n
              string_index = string_index,\n
              uid = category.getUid(),\n
              **domain_kw)\n
  domain.setCriterion(\'string_index\', identity=string_index)\n
  domain_list.append(domain)\n
  i += 1\n
\n
return domain_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>depth, parent, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Project_generateMonthDomain</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
