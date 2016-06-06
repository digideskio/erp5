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

from Products.ZSQLCatalog.SQLCatalog import Query\n
request = context.REQUEST\n
\n
object_dict = {} # it contains required temp object to display the listbox\n
                 # with the amount of time per worker/month/project line\n
total_object_dict = {} # this is for listbox with amount of time\n
                       # per worker/project line\n
\n
column_list= []\n
worker_column_list = []\n
portal = context.getPortalObject()\n
temp_object_container = portal.project_module.newContent(temp_object=1)\n
\n
# find all Tasks\n
inventory_kw = {}\n
if context.getPortalType() == \'Project\':\n
  inventory_kw[\'project_uid\'] = [x.uid for x in portal.portal_catalog(\n
     relative_url=\'%s/%%\' % context.getRelativeUrl())] + [context.getUid()]\n
worker_title_list = request.get(\'worker_title_list\')\n
if worker_title_list is not None and len(worker_title_list):\n
  worker_uid_list = [x.uid for x in portal.portal_catalog(\n
                              portal_type=\'Person\',title=worker_title_list)]\n
  if len(worker_uid_list):\n
    inventory_kw[\'node_uid\'] = worker_uid_list\n
\n
from_date = request.get(\'from_date\', None)\n
if from_date is None:\n
  from_date = context.getStartDate()\n
  request.set(\'from_date\',from_date)\n
at_date = request.get(\'at_date\', None)\n
if at_date is None:\n
  at_date = context.getStopDate()\n
  request.set(\'at_date\',at_date)\n
simulation_state_set = set(request.get(\'simulation_state\', []))\n
full_date_string = "%s-%s -> %s-%s" % (from_date.year(), from_date.month(),\n
                                    at_date.year(), at_date.month())\n
\n
result_list = []\n
# We will use inventory API in order to find all quantities\n
# Launch report only if we have restrictive parameters in inventory_kw,\n
# otherwise getInventoryList will take all task reports and this will\n
# kill the current node\n
if len(inventory_kw):\n
  before_confirmed_task_state_set = set(portal.getPortalPlannedOrderStateList() + \\\n
           portal.getPortalDraftOrderStateList())\n
  task_state_set = simulation_state_set.intersection(before_confirmed_task_state_set)\n
  if len(task_state_set):\n
    result_list.extend(portal.portal_simulation.getInventoryList(\n
                  simulation_state = [x for x in task_state_set],\n
                  portal_type=[\'Task Line\', \'Simulation Movement\'],\n
                  from_date=from_date,\n
                  at_date=at_date, **inventory_kw))\n
\n
  task_report_state_set = simulation_state_set.difference(before_confirmed_task_state_set)\n
  if len(task_report_state_set):\n
    result_list.extend(portal.portal_simulation.getInventoryList(\n
                  simulation_state = [x for x in task_report_state_set],\n
                  portal_type=\'Task Report Line\',\n
                  from_date=from_date,\n
                  at_date=at_date, **inventory_kw))\n
\n
monthly_worker_quantity_dict = {} # Used to get quantity per month and per worker\n
                                  # and per project line\n
monthly_project_to_display_dict = {} # Used to get project urls to display per month\n
                                     # in the report tree\n
total_project_to_display_dict = {} # Used to get project urls to display in the summary\n
total_worker_quantity_dict = {} # Used to get quantity per project line and per worker for\n
                           # the full period\n
full_date_total_worker_quantity_dict = \\\n
  total_worker_quantity_dict.setdefault(full_date_string, {})\n
full_date_total_object_dict = total_object_dict.setdefault(full_date_string, {})\n
full_date_total_project_to_display_dict = \\\n
  total_project_to_display_dict.setdefault(full_date_string, {})\n
\n
\n
source_uid_dict = {}\n
project_uid_dict = {}\n
project_relative_url_dict = {}\n
\n
def fillDictWithParentAndChildRelativeUrls(my_dict, document_url):\n
  if my_dict.get(document_url) is None:\n
    splitted_document_url = document_url.split(\'/\')\n
    for x in xrange(0, len(splitted_document_url)):\n
      my_dict[\'/\'.join(splitted_document_url[0:x+1])] = 1\n
\n
\n
def getNextMonthStart(date):\n
  """\n
  return the next month date of the param date\n
  """\n
  if date.month()==12:\n
    return DateTime(date.year()+1, date.month(), 1)\n
  else:\n
    return DateTime(date.year(), date.month()+1, 1)\n
\n
for task_line in result_list:\n
  # initialize some variables\n
  source_uid = task_line.node_uid\n
  if source_uid is None:\n
    # This should not happens, so display an error message\n
    raise ValueError, context.Base_translateString(\\\n
        "This task should have a source : ${task_relative_url}",\n
        mapping = {\'task_relative_url\': task_line.getRelativeUrl()})\n
  source_dict = source_uid_dict.get(source_uid, None)\n
  if source_dict is None:\n
    source_value = task_line.getSourceValue()\n
    source_dict = {\'title\': source_value.getTitle(),\n
                   \'relative_url\': source_value.getRelativeUrl()}\n
    source_uid_dict[source_uid] = source_dict\n
  source_title = source_dict[\'title\']\n
  source_relative_url = source_dict[\'relative_url\']\n
  start_date_task = task_line.date\n
  stop_date_task = task_line.mirror_date\n
  year_start_date = start_date_task.year()\n
  month_start_date = start_date_task.month()\n
\n
  # create a list with people who works on the task\n
  current_column = (source_relative_url, source_title)\n
  if current_column not in worker_column_list:\n
    worker_column_list.append(current_column)\n
  project_uid = task_line.project_uid\n
  project_dict = project_uid_dict.get(project_uid, None)\n
  if project_dict is None:\n
    project_value = task_line.getSourceProjectValue()\n
    project_dict = {\'relative_url\': project_value.getRelativeUrl(),\n
                    \'title\': project_value.getTitle()}\n
    project_uid_dict[project_uid] = project_dict\n
    project_relative_url_dict[\'/\'.join(project_value.getRelativeUrl().split(\'/\')[0:2])] = 1\n
  quantity = - task_line.inventory\n
  project_relative_url = project_dict[\'relative_url\']\n
  full_date_total_worker_quantity_dict[source_relative_url] = \\\n
    full_date_total_worker_quantity_dict.get(source_relative_url, 0) + quantity\n
  if not full_date_total_object_dict.has_key(project_relative_url):\n
    temp_object = temp_object_container.newContent(portal_type = \'Project Line\',\n
                temp_object=1,\n
                string_index = full_date_string,\n
                category_list = [\'source_project/%s\' % project_relative_url])\n
    full_date_total_object_dict[project_relative_url] = temp_object\n
  current_temp_object = full_date_total_object_dict[project_relative_url]\n
  object_quantity = quantity + current_temp_object.getProperty(source_relative_url, 0)\n
  current_temp_object.setProperty(source_relative_url, object_quantity)\n
\n
  # diff in day between the begin and the end of the task\n
  diff_day = stop_date_task - start_date_task + 1\n
\n
  fillDictWithParentAndChildRelativeUrls(full_date_total_project_to_display_dict, \n
     project_relative_url)\n
\n
  timekeeper = start_date_task\n
  while timekeeper <= stop_date_task :\n
    next_timekeeper = getNextMonthStart(timekeeper)\n
    string_index = "%s-%s" % ( timekeeper.year(), timekeeper.month())\n
    quantity_dict = object_dict.setdefault(string_index, {})\n
    \n
    worker_quantity_dict = monthly_worker_quantity_dict.setdefault(string_index, {})\n
    project_to_display_dict = monthly_project_to_display_dict.setdefault(string_index, {})\n
    fillDictWithParentAndChildRelativeUrls(project_to_display_dict, project_relative_url)\n
    \n
    if not quantity_dict.has_key(project_relative_url):\n
      temp_object = temp_object_container.newContent(portal_type = \'Project Line\',\n
                  temp_object=1,\n
                  string_index = string_index,\n
                  category_list = [\'source_project/%s\' % project_relative_url])\n
      quantity_dict[project_relative_url] = temp_object\n
    current_temp_object = quantity_dict[project_relative_url]\n
    current_month_quantity = (min(next_timekeeper,stop_date_task+1) - timekeeper )/ diff_day * quantity\n
    object_quantity = current_month_quantity + current_temp_object.getProperty(source_relative_url, 0)\n
    worker_quantity_dict[source_relative_url] = worker_quantity_dict.get(source_relative_url, 0) + current_month_quantity\n
    current_temp_object.setProperty(source_relative_url, object_quantity)\n
    timekeeper = next_timekeeper\n
\n
# Now build temp objects for quantity per month and per worker\n
summary_dict = {}\n
for string_index, worker_quantity_dict in monthly_worker_quantity_dict.items():\n
  temp_object = temp_object_container.newContent(portal_type = \'Project Line\',\n
              temp_object=1,\n
              string_index = string_index)\n
  summary_dict[string_index] = temp_object\n
  for source_relative_url, quantity in worker_quantity_dict.items():\n
    temp_object.setProperty(source_relative_url, quantity)\n
\n
# Now build temp objects for quantity per worker\n
total_summary_dict = {}\n
for string_index, worker_quantity_dict in total_worker_quantity_dict.items():\n
  temp_object = temp_object_container.newContent(portal_type = \'Project Line\',\n
              temp_object=1,\n
              string_index = string_index)\n
  total_summary_dict[string_index] = temp_object\n
  for source_relative_url, quantity in worker_quantity_dict.items():\n
    temp_object.setProperty(source_relative_url, quantity)\n
\n
column_list.extend(worker_column_list)\n
\n
selection_name = \'project_monthly_report_selection\'\n
portal.portal_selections.setListboxDisplayMode(request, \'ReportTreeMode\',\n
                                              selection_name=selection_name)\n
\n
result = []\n
from Products.ERP5Form.Report import ReportSection\n
param_dict = {}\n
\n
project_dict = {}\n
for project_relative_url in project_relative_url_dict.keys():\n
  project_dict[project_relative_url] = portal.restrictedTraverse(project_relative_url)\n
param_list = [object_dict, summary_dict, column_list, project_dict,\n
              monthly_project_to_display_dict, False, full_date_string]\n
\n
result.append(ReportSection(\n
              path=context.getPhysicalPath(),\n
              param_list=param_list,\n
              method_id=\'Project_getMonthlyReportContext\',\n
              listbox_display_mode=\'ReportTreeMode\',\n
              form_id=\'Project_viewMonthlyReportData\'))\n
\n
param_list = [total_object_dict, total_summary_dict, column_list, project_dict,\n
              total_project_to_display_dict, True, full_date_string]\n
result.append(ReportSection(\n
              path=context.getPhysicalPath(),\n
              param_list=param_list,\n
              method_id=\'Project_getMonthlyReportContext\',\n
              listbox_display_mode=\'ReportTreeMode\',\n
              form_id=\'Project_viewMonthlySummaryReportData\'))\n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Project_getMonthlyReportSectionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
