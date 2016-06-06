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
            <value> <string>from Products.ERP5Type.Message import translateString\n
\n
request= context.REQUEST\n
\n
if not listbox:\n
  listbox = request.get(\'listbox\', [])\n
  if isinstance(listbox, dict):\n
    # structure of listbox value is different than the one fetch from parameters\n
    repaired_listbox = []\n
    for key in listbox:\n
      item = listbox[key]\n
      item[\'listbox_key\'] = key\n
      repaired_listbox.append(item)\n
    listbox = repaired_listbox\n
\n
line_list = context.Delivery_getSolverDecisionList(listbox=listbox)\n
\n
def displayParallelChangeMessage():\n
  message = translateString("Workflow state may have been updated by other user. Please try again.")\n
  return context.Base_redirect(form_id, keep_items={\'portal_status_message\': message}, **kw)\n
\n
# if we are not divergence any more\n
if len(line_list) == 0:\n
  return displayParallelChangeMessage()\n
\n
line = None\n
for listbox_dict in listbox:\n
  listbox_key = listbox_dict[\'listbox_key\']\n
  line = [x for x in line_list if x.getPath() == listbox_key][0]\n
  uid = line.getUid()\n
  for property in (\'solver\', \'solver_configuration\', \'delivery_solver\', \'comment\',):\n
    value = listbox_dict.get(property, None)\n
    key = \'field_listbox_%s_%s\' % (property, uid)\n
    request.form[key] = request.other[key] = value\n
    if property == \'solver_configuration\':\n
      if value is not None:\n
        line.updateConfiguration(**value.as_dict())\n
    else:\n
      line.setProperty(property, value)\n
\n
# if divergence solving is already ongoing and will be fixed by activities\n
if line is None:\n
  return displayParallelChangeMessage()\n
\n
solver_process = line.getParentValue()\n
solver_process.buildTargetSolverList()\n
solver_process.solve()\n
\n
return context.Base_redirect(form_id,\n
  keep_items=dict(portal_status_message=\n
         translateString(\'Divergence solvers started in background.\')))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=\'view\', listbox=[], **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Delivery_submitSolveDivergenceDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
