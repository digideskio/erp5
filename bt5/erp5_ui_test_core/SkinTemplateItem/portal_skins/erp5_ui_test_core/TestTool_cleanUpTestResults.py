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
            <value> <string>portal_tests = container.portal_tests\n
if test_zuite_relative_url is not None:\n
  # we care for a specific test zuite\n
  portal_tests = portal_tests.restrictedTraverse(test_zuite_relative_url,\\\n
                                                 portal_tests)\n
# remove test results from previous test runs\n
portal_tests.manage_delObjects([x.getId() \\\n
          for x in portal_tests.objectValues(\'Zuite Results\')])\n
print "OK"\n
return printed\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>test_zuite_relative_url=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestTool_cleanUpTestResults</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Clean up test results from previous test runs</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
