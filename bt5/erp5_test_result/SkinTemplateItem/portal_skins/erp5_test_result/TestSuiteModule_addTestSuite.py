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
            <value> <string>vcs_list = context[\'vcs_repository_list\']\n
test_suite_repository = context.TestSuiteRepository.newContent(\n
                  branch = vcs_list[\'branch\'],\n
                  buildout_section_id = vcs_list[\'buildout_section_id\'],\n
                  git_url = vcs_list[\'git_url\'],\n
                  profile_path = vcs_list[\'profile_path\']\n
             )\n
\n
test_suite = context.newContent(\n
                    title=title,\n
                    test_suite_title = config[\'test_suite_title\'],\n
                    test_suite = config[\'test_suite\'],\n
                    int_index = config[\'int_index\'],\n
                    vcs_repository = test_suite_repository\n
                    ) \n
\n
if batch_mode:\n
 return test_suite\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>title, config,batch_mode = False </string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestSuiteModule_addTestSuite</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
