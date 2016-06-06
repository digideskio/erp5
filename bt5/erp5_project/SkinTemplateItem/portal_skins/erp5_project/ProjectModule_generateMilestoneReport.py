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

"""\n
This script is in charge to retrive all milestones that\n
match report parameters, then sort them and prepare data\n
that will allows to generate temp objects for listbox\n
"""\n
listbox = []\n
portal = context.getPortalObject()\n
\n
sql_kw = {}\n
if project_validation_state_list is not None and \\\n
    len(project_validation_state_list):\n
  sql_kw[\'validation_state\'] = project_validation_state_list\n
\n
project_list = portal.portal_catalog(portal_type=\'Project\', **sql_kw)\n
project_uid_list = [x.uid for x in project_list]\n
\n
sql_kw = {}\n
\n
select_dict = {}\n
select_dict[\'title\'] = None\n
select_dict[\'description\'] = None\n
select_dict[\'parent_title\'] = None\n
milestone_list = []\n
portal_catalog = portal.portal_catalog\n
# Check for some extra properties that are not necessarly\n
# in the catalog. We need by the way to check if\n
# hasColumn exists, it is new and is not installed yet everywhere\n
hasColumn = getattr(portal_catalog, \'hasColumn\', None)\n
if hasColumn is not None:\n
  for property in [\'outcome_description\']:\n
    if hasColumn(property):\n
      select_dict[property] = None\n
\n
if len(project_uid_list):\n
  milestone_list = [x for x in portal.portal_catalog(parent_uid=project_uid_list,\n
                       portal_type=\'Project Milestone\', select_dict=select_dict, **sql_kw)]\n
                \n
milestone_list.sort(key = lambda x: (x.parent_title, getattr(x, \'stop_date\', None), x.title))\n
\n
for milestone in milestone_list:\n
  # We wish to display the project only for the first milestone\n
  # of this project\n
\n
  # XXX These two statements below filter the result,\n
  # we can increase speed by filtering directly from the database.\n
  if from_date is not None:\n
    if milestone.getStartDate() < from_date:\n
      continue\n
  if at_date is not None:\n
    if milestone.getStopDate() >= at_date:\n
      continue\n
  line_kw = {}\n
  line_kw[\'project_title\'] = milestone.parent_title\n
  line_kw[\'milestone_title\'] = milestone.title\n
  line_kw[\'stop_date\'] = getattr(milestone, \'stop_date\', None)\n
  line_kw[\'milestone_description\'] = milestone.getProperty(\'description\')\n
  line_kw[\'milestone_outcome_description\'] = milestone.getProperty(\'outcome_description\')\n
  listbox.append(line_kw)\n
\n
context.Base_updateDialogForm(listbox=listbox, empty_line_number=0)\n
return context.ProjectModule_viewMilestoneReport()\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>from_date=None, at_date=None, project_validation_state_list=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ProjectModule_generateMilestoneReport</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
