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
            <value> <string>"""Uninstall business template"""\n
# Uninstall test business templates before the test\n
bt_list = context.portal_templates.getInstalledBusinessTemplatesList()\n
for bt in bt_list:\n
  if bt.getTitle().startswith(\'test_\'):\n
    bt.uninstall()\n
\n
# modify repository list information\n
if end:\n
  # set default repository list when test is finished\n
  repository_list = [\'http://www.erp5.org/dists/snapshot/bt5\']\n
else:\n
  # just used test repository to not display to many bt and thus have listbox\n
  # with many pages\n
  repository_list = [\'http://www.erp5.org/dists/snapshot/test_bt5\']\n
\n
context.portal_templates.updateRepositoryBusinessTemplateList(repository_list)\n
\n
return \'Reset Successfully.\'\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>end=0</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BTZuite_reset</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Reset conditions of BTZuite</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
