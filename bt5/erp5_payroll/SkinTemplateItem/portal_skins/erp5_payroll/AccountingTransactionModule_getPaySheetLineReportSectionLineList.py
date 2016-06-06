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
from DateTime import DateTime\n
\n
request = context.REQUEST\n
portal = context.getPortalObject()\n
translateString = portal.Base_translateString\n
\n
section_category = request[\'section_category\']\n
section_uid_list = portal.Base_getSectionUidListForSectionCategory(section_category)\n
\n
# currency precision\n
currency = portal.Base_getCurrencyForSection(section_category)\n
precision = portal.account_module.getQuantityPrecisionFromResource(currency)\n
request.set(\'precision\', precision)\n
\n
from_date = None\n
if request.get(\'from_date\'):\n
  from_date = DateTime(request[\'from_date\'])\n
at_date = DateTime(request[\'at_date\'])\n
simulation_state = request[\'simulation_state\']\n
resource = request[\'resource\']\n
\n
portal_simulation = context.getPortalObject().portal_simulation\n
\n
employee_params = {\n
    \'group_by_node\' : 1,\n
    \'group_by_variation\': 1,\n
    \'section_uid\' : section_uid_list,\n
    \'contribution_share_uid\' : context.portal_categories.contribution_share.employee.getUid(),\n
    \'at_date\' : at_date,\n
    \'from_date\' : from_date,\n
    \'simulation_state\' : simulation_state,\n
    \'precision\' : precision,\n
    \'resource\' : resource\n
  }\n
\n
employer_params = {\n
    \'group_by_node\' : 1,\n
    \'group_by_variation\': 1,\n
    \'section_uid\' : section_uid_list,\n
    \'contribution_share_uid\' : context.portal_categories.contribution_share.employer.getUid(),\n
    \'at_date\' : at_date,\n
    \'from_date\' : from_date,\n
    \'simulation_state\' : simulation_state,\n
    \'precision\' : precision,\n
    \'resource\' : resource\n
  }\n
\n
if request.get(\'mirror_section\'):\n
  mirror_section = request[\'mirror_section\']\n
  employee_params[\'mirror_section\'] = mirror_section\n
  employer_params[\'mirror_section\'] = mirror_section\n
\n
employee_inventory_list = portal_simulation.getInventoryList(**employee_params)\n
employer_inventory_list = portal_simulation.getInventoryList(**employer_params)\n
\n
inventory_list = {}\n
\n
employee_total = 0\n
employer_total = 0\n
base_total = 0\n
\n
i = 0\n
for inventory in employee_inventory_list:\n
  price = - (inventory.total_price or 0)\n
  movement = inventory.getObject()\n
  employee = movement.getDestinationValue()\n
  salary_range = movement.getSalaryRange()\n
  salary_range_title = movement.getSalaryRange() and\\\n
                          movement.getSalaryRangeValue().getTranslatedTitle()\n
\n
  i = i + 1\n
  inventory_list[(employee.getUid(), salary_range)] = Object(id=i,\n
               employee_career_reference=employee.getCareerReference(),\n
               employee_title=employee.getTitle(),\n
               employee_career_function=employee.getCareerFunctionTitle(),\n
               salary_range=salary_range,\n
               salary_range_title=salary_range_title,\n
               employee=price,\n
               base=inventory.quantity, )\n
  employee_total += price\n
  base_total += inventory.quantity\n
\n
for inventory in employer_inventory_list:\n
  price = - (inventory.total_price or 0)\n
  movement = inventory.getObject()\n
  employee = movement.getDestinationValue()\n
  salary_range = movement.getSalaryRange()\n
  salary_range_title = movement.getSalaryRange() and\\\n
                          movement.getSalaryRangeValue().getTranslatedTitle()\n
\n
  key = (employee.getUid(), salary_range)\n
  if key not in inventory_list:\n
    inventory_list[key] = Object(id=i,\n
               employee_career_reference=employee.getCareerReference(),\n
               employee_title=employee.getTitle(),\n
               employee_career_function=employee.getCareerFunctionTitle(),\n
               employee=0,\n
               salary_range=salary_range,\n
               salary_range_title=salary_range_title,\n
               base=inventory.quantity, )\n
    base_total += inventory.quantity\n
    i = i + 1\n
\n
  employee = inventory.getDestinationValue()\n
  inventory_list[key].employer = price\n
  inventory_list[key].total = inventory_list[key].employee + price\n
  employer_total += price\n
\n
total = employee_total + employer_total\n
\n
request.set(\'employee_total\', employee_total)\n
request.set(\'employer_total\', employer_total)\n
request.set(\'base_total\', base_total)\n
request.set(\'total\', total)\n
\n
\n
sorted_inventory_list = []\n
sorted_inventory_list = inventory_list.values()\n
\n
# sort by salary range, and add intermediate sums if needed\n
def sort_method(a, b):\n
  salary_range_diff = cmp(a.salary_range, b.salary_range)\n
  if salary_range_diff:\n
    return salary_range_diff\n
  employee_career_reference_diff = cmp(a.employee_career_reference,\n
                                       b.employee_career_reference)\n
  if employee_career_reference_diff:\n
    return employee_career_reference_diff\n
  return cmp(a.employee_title, b.employee_title)\n
\n
sorted_inventory_list.sort(sort_method)\n
\n
i = 0\n
intermediate_base_total = 0\n
intermediate_employee_total = 0\n
intermediate_employer_total = 0\n
\n
multiple_salary_range = 0\n
if sorted_inventory_list:\n
  new_inventory_list = []\n
\n
  current_salary_range = sorted_inventory_list[0][\'salary_range\']\n
  current_salary_range_title = sorted_inventory_list[0][\'salary_range_title\']\n
\n
  for inventory in sorted_inventory_list:\n
    i = i+1\n
    inventory[\'id\'] = i\n
\n
    if inventory[\'salary_range\'] != current_salary_range:\n
      multiple_salary_range = 1\n
      new_inventory_list.append(Object(\n
               employee_title=translateString(\'Total ${salary_range_title}\',\n
                     mapping=dict(salary_range_title=current_salary_range_title)),\n
               base=intermediate_base_total,\n
               employee=intermediate_employee_total,\n
               employer=intermediate_employer_total))\n
\n
      intermediate_base_total = 0\n
      intermediate_employee_total = 0\n
      intermediate_employer_total = 0\n
\n
      current_salary_range = inventory[\'salary_range\']\n
      current_salary_range_title = inventory[\'salary_range_title\']\n
\n
    intermediate_base_total += inventory[\'base\']\n
    intermediate_employee_total += inventory.get(\'employee\', 0)\n
    intermediate_employer_total += inventory.get(\'employer\', 0)\n
    new_inventory_list.append(inventory)\n
\n
  if multiple_salary_range:\n
    new_inventory_list.append(Object(\n
           employee_title=translateString(\'Total ${salary_range_title}\',\n
                 mapping=dict(salary_range_title=current_salary_range_title)),\n
           base=intermediate_base_total,\n
           employee=intermediate_employee_total,\n
           employer=intermediate_employer_total))\n
     \n
  return new_inventory_list\n
\n
\n
return []\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_getPaySheetLineReportSectionLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
