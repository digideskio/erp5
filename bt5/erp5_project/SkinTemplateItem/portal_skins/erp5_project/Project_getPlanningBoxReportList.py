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
            <value> <string># Get the objects based on domain used\n
\n
selection_tool = context.portal_selections\n
selection = selection_tool.getSelectionFor(\'project_planning_selection\')\n
\n
if selection is not None:\n
  if selection.report_path in (\'task_module_domain\', \'project_person_domain\'):\n
    kw[\'source_project_relative_url\'] = (context.getRelativeUrl(), \'%s/%%\' % context.getRelativeUrl())\n
  elif selection.report_path == \'project_person_task_report_domain\':\n
    # It was required filter to one specific portal type\n
    kw[\'portal_type\'] = [\'Task Report\']\n
    kw[\'source_project_relative_url\'] = (context.getRelativeUrl(), \'%s/%%\' % context.getRelativeUrl())\n
  elif selection.report_path == \'project_projectline_domain\':\n
    kw[\'source_project_relative_url\'] = (context.getRelativeUrl(), \'%s/%%\' % context.getRelativeUrl())\n
  elif selection.report_path in (\'task_report_module_domain\', \'project_project_task_report_domain\'):\n
    # It was required filter to one specific portal type\n
    kw[\'portal_type\'] = [\'Task Report\']\n
    kw[\'source_project_relative_url\'] = (context.getRelativeUrl(), \'%s/%%\' % context.getRelativeUrl())\n
  elif selection.report_path == \'parent\':\n
    return context.searchFolder(**kw)\n
  else:\n
    raise NotImplementedError, "Unknow domain %s" % selection.report_path\n
\n
  return context.portal_catalog(**kw)\n
\n
else:\n
  return context.searchFolder(**kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Project_getPlanningBoxReportList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
