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

\'\'\'\n
  this script is just made to have a simple visual render of the paysheet\n
  calculation\n
\'\'\'\n
\n
line_dict_list = context.PaySheetTransaction_getLineListAsDict()\n
\n
title_list = [\'Designation\\t\\t\', \'Base\', \'Employer Rate\', \'Employer Share\', \n
    \'Employee Rate\', \'Employee Share\']\n
\n
print \'\\t\\t\'.join(title_list)\n
print \'\'\n
\n
def rightPad(string, length):\n
  string=str(string)\n
  if len(string)>length:\n
    return string[:length]\n
  return string + \' \' * (length - len(string))\n
\n
for line in line_dict_list:\n
  string_to_display = []\n
  string_to_display.append(rightPad(line[\'title\'], 40))\n
  string_to_display.append(rightPad(line[\'base\'], 16))\n
\n
  if line.has_key(\'employer_quantity\'):\n
    string_to_display.append(rightPad(str(line[\'employer_price\']), 24))\n
    string_to_display.append(rightPad(str(line[\'employer_quantity\']), 24))\n
  else:\n
    string_to_display.append(rightPad(\' \', 24))\n
    string_to_display.append(rightPad(\' \', 24))\n
\n
  if line.has_key(\'employee_quantity\'):\n
    string_to_display.append(rightPad(str(line[\'employee_price\']), 24))\n
    string_to_display.append(rightPad(str(line[\'employee_quantity\']), 24))\n
  else:\n
    string_to_display.append(rightPad(\' \', 24))\n
    string_to_display.append(rightPad(\' \', 24))\n
\n
  print \'\'.join(string_to_display)\n
\n
return printed\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PaySheetTransaction_viewPaySheetTransactionAsText</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
