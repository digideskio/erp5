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
            <value> <string>"""\n
  Generic random string generator.\n
  \n
"""\n
from random import choice\n
from string import letters, digits\n
\n
character_set = \'\'\n
if include_letters:\n
  character_set = \'%s%s\' %(character_set, letters)\n
if include_digits:\n
  character_set = \'%s%s\' %(character_set, digits)\n
return \'\'.join([choice(character_set) for i in range(int(string_length))])\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>string_length=10, include_letters=1, include_digits=1</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_generateRandomString</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
