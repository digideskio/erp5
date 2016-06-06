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

# This script is called when you invoke a browser with "?auto=true" to portal_tests.\n
# FIXME: this script should send the result by email.\n
\n
get = request.form.get\n
\n
# Summary.\n
result = [\'Report on Functional Tests\', \'\']\n
result.append(\'Passed: %s\' % (get(\'result\').lower() == \'passed\' and \'Yes\' or \'No\'))\n
result.append(\'Total Time: %s\' % get(\'totalTime\'))\n
result.append(\'Passed Tests: %s\' % get(\'numTestPasses\'))\n
result.append(\'Failed Tests: %s\' % get(\'numTestFailures\'))\n
result.append(\'Passed Commands: %s\' % get(\'numCommandPasses\'))\n
result.append(\'Failed Commands: %s\' % get(\'numCommandFailures\'))\n
result.append(\'Commands with Errors: %s\' % get(\'numCommandErrors\'))\n
result.append(\'\')\n
\n
# Details.\n
table_list = []\n
for key in request.form.keys():\n
  if key.startswith(\'testTable\'):\n
    prefix, num = key.split(\'.\')\n
    table_list.append((prefix, int(num)))\n
table_list.sort()\n
for table in table_list:\n
  key = \'%s.%d\' % table\n
  html = get(key)\n
\n
  # Ugly, but get the title somehow.\n
  i = html.index(\'<td\')\n
  start = html.index(\'>\', i) + 1\n
  end = html.index(\'<\', start)\n
  title = html[start:end]\n
\n
  # Count passes and failures.\n
  num_passed_commands = html.count(\'bgcolor="#cfffcf"\', end)\n
  num_failed_commands = html.count(\'bgcolor="#ffcfcf"\', end)\n
  result.append(\'%s: %d passed, %d failed\' % (title, num_passed_commands, num_failed_commands))\n
\n
return \'\\n\'.join(result)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>request</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestTool_reportResult</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
