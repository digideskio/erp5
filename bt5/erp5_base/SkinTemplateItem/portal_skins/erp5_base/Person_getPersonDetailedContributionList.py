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
            <value> <string>from Products.PythonScripts.standard import Object\n
from Products.ZSQLCatalog.SQLCatalog import Query\n
from Products.ERP5Type.DateUtils import atTheEndOfPeriod\n
request = container.REQUEST\n
from_date = request.get(\'from_date\', None)\n
to_date = request.get(\'at_date\', None)\n
aggregation_level = request.get(\'aggregation_level\', None)\n
portal = context.getPortalObject()\n
module_list = []\n
for module_id in portal.objectIds(spec=(\'ERP5 Folder\',)):\n
    module = portal.restrictedTraverse(module_id, None)\n
    if module is not None:\n
      if portal.portal_membership.checkPermission(\'View\', module):\n
        module_list.append(module)\n
module_list.sort(key=lambda x: x.getTitle())\n
\n
# build document portal type list\n
portal_type_list = []\n
extend = portal_type_list.extend\n
for module in module_list:\n
  extend(module.ERP5Folder_getUnrestrictedContentTypeList())\n
\n
# compute sql params, we group and order by date and portal type\n
if aggregation_level == "year":\n
  sql_format = "%Y"\n
elif aggregation_level == "month":\n
  sql_format = "%Y-%m"\n
elif aggregation_level == "week":\n
  sql_format = "%Y-%u"\n
elif aggregation_level == "day":\n
  sql_format = "%Y-%m-%d"\n
if to_date is not None:\n
  to_date = atTheEndOfPeriod(to_date, period=aggregation_level)\n
params = {"creation_date":(from_date, to_date)}\n
query=None\n
if from_date is not None and to_date is not None:\n
  params = {"creation_date":(from_date, to_date)}\n
  query = Query(range="minmax", **params)\n
elif from_date is not None:\n
  params = {"creation_date":from_date}\n
  query = Query(range="min", **params)\n
elif to_date is not None:\n
  params = {"creation_date":to_date}\n
  query = Query(range="max", **params)\n
select_expression = {\'date\' : \'DATE_FORMAT(creation_date, "%s")\'%sql_format, \'portal_type\' : None}\n
group_by = [\'DATE_FORMAT(creation_date, "%s")\' % sql_format, \'portal_type\']\n
\n
# count number of object created by the user for each type of document\n
reference = kw.get(\'person_reference_list\', context.getReference())\n
result_list = context.portal_catalog.countResults(select_expression=select_expression,\n
                                                  portal_type=portal_type_list,limit=None,\n
                                                  owner=reference,query=query,\n
                                                  group_by_expression=group_by)\n
\n
# build result dict per portal_type then period\n
portal_type_count_dict = {}\n
for result in result_list:\n
  if portal_type_count_dict.has_key(result[2]):\n
    portal_type_count_dict[result[2]][result[1]] = result[0]\n
  else:\n
    portal_type_count_dict[result[2]] = {result[1]:result[0]}\n
\n
# now filled the listbox with count results\n
line_list = []\n
append = line_list.append\n
period_count_dict = {}\n
for portal_type in portal_type_list:\n
    if portal_type_count_dict.has_key(portal_type):\n
      period_count = portal_type_count_dict[portal_type]\n
      obj = Object(uid="new_")\n
      obj["document_type"] = context.Base_translateString(portal_type)\n
    else:\n
      continue\n
    line_counter = 0\n
    for period in period_list:\n
      if period_count.has_key(period):\n
        obj[period] = period_count[period]\n
        line_counter += period_count[period]\n
        if period_count_dict.has_key(period):\n
          period_count_dict[period] = period_count_dict[period] + period_count[period]\n
        else:\n
          period_count_dict[period] = period_count[period]\n
      else:\n
        obj[period] = 0\n
    obj[\'total\'] = line_counter\n
    append(obj)\n
\n
# sort lines\n
def cmpType(a, b):\n
  return cmp(a[\'document_type\'], b[\'document_type\'])\n
\n
line_list.sort(cmpType)\n
\n
# build stat line\n
obj = Object(uid="new_")\n
obj["document_type"] = \'Total\'\n
line_counter = 0\n
for period in period_list:\n
  if period_count_dict.has_key(period):\n
    obj[period] = period_count_dict[period]\n
    line_counter += period_count_dict[period]\n
  else:\n
    obj[period] = 0\n
obj[\'total\'] = line_counter\n
request.set(\'stat_line\', [obj,])\n
\n
return line_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>period_list, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Person_getPersonDetailedContributionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
