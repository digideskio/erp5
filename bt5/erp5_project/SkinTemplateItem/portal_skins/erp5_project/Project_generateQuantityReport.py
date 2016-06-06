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

# This is what we want to display in the report\n
# project_month     worker1    worker2    worker3\n
#    january           34              32             15\n
#    february          10              14             20\n
\n
def getYearAndMonth(date):\n
  if date is None:\n
    return(None,None)\n
  return (date.year(),date.Month())\n
\n
\n
def getMonthDict(line):\n
  start_date = line.getStartDate()\n
  stop_date = line.getStopDate()\n
  month_dict={}\n
  if getYearAndMonth(start_date) == getYearAndMonth(stop_date):\n
    month_dict={getYearAndMonth(start_date):line.getQuantity() or 0}\n
  else:\n
    nb_days = (stop_date-start_date)*86400\n
    current_date = start_date\n
    previous_current_date = start_date\n
    quantity = line.getQuantity() or 0\n
    while current_date < stop_date:\n
      previous_current_date = current_date\n
      year_and_month = getYearAndMonth(current_date)\n
      while previous_current_date.month()==current_date.month() and current_date < stop_date:\n
        current_date = current_date + 1\n
      month_dict[year_and_month] = quantity / nb_days * (current_date-previous_current_date) * 86400\n
      \n
      \n
  return month_dict\n
\n
def getTotalQuantity(line,worker):\n
  quantity = {}\n
  child_list = line.objectValues()\n
  if len(child_list)>0:\n
    for child in child_list:\n
      child_quantity = getTotalQuantity(child,worker)\n
      for key,value in child_quantity.items():\n
        if not quantity.has_key(key):\n
          quantity[key] = 0\n
        quantity[key] = quantity[key] + value\n
  else:\n
    if worker in line.getSourceValueList() or (line.getSourceValue() is None and worker is None):\n
      quantity = getMonthDict(line)\n
  return quantity\n
\n
listbox = []\n
worker_list = context.getSourceValueList() + [None]\n
worker_quantity = {}\n
for worker in worker_list:\n
  worker_quantity[worker] = getTotalQuantity(context,worker)\n
\n
month_list = []\n
current_date = context.getStartDate()\n
month_list.append(getYearAndMonth(current_date))\n
from DateTime import DateTime\n
while getYearAndMonth(current_date)!=getYearAndMonth(context.getStopDate()):\n
  start_date_day = context.getStartDate().day()\n
  previous_current_date = current_date\n
  current_date = current_date + 1\n
  while current_date.day() != start_date_day and current_date-previous_current_date<31:\n
    current_date = current_date + 1\n
  month_list.append(getYearAndMonth(current_date))\n
   \n
month_list.append((None,None))\n
total_dict = {}\n
total_dict[\'year\'] = \'Total\'\n
total_dict[\'month\'] = \'Total\'\n
for year,month in month_list:\n
  listbox_line = {}\n
  listbox_line[\'year\'] = year\n
  listbox_line[\'month\'] = month\n
  for worker in worker_list:\n
    quantity = 0\n
    if worker_quantity[worker].has_key((year,month)):\n
      quantity = worker_quantity[worker][(year,month)]\n
    worker_title = \'unknown\'\n
    if worker is not None:\n
      worker_title = worker.getTitle()\n
    total_dict[worker_title] = total_dict.get(worker_title,0) + quantity\n
    listbox_line[worker_title] = quantity\n
  listbox.append(listbox_line)  \n
listbox.append(total_dict)\n
\n
\n
\n
context.Base_updateDialogForm(listbox=listbox)\n
\n
return context.Project_viewQuantityReport(listbox=listbox)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Project_generateQuantityReport</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
