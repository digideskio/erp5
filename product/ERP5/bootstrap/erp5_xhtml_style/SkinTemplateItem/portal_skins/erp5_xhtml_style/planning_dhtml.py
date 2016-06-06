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
Copyright (c) 2002 Nexedi SARL and Contributors. All Rights Reserved.\n
            Thomas Bernard   <thomas@nexedi.com>\n
\n
This program is Free Software; you can redistribute it and/or\n
modify it under the terms of the GNU General Public License\n
as published by the Free Software Foundation; either version 2\n
of the License, or (at your option) any later version.\n
\n
This program is distributed in the hope that it will be useful,\n
but WITHOUT ANY WARRANTY; without even the implied warranty of\n
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n
GNU General Public License for more details.\n
\n
You should have received a copy of the GNU General Public License\n
along with this program; if not, write to the Free Software\n
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.\n
"""\n
\n
"""\n
This script builds a string with all necessary data to allow block\n
moving and resizing\n
"""\n
\n
block_string = \',\'.join([\'"%s"\' % block.name for block in planning.content if \\\n
                                not context.PlanningBox_isFrozenBlock(block=block)])\n
\n
return \'<script type="text/javascript">SET_DHTML(%s,\' \\\n
       \'"top"+CURSOR_N_RESIZE+VERTICAL, \' \\\n
       \'"right"+CURSOR_E_RESIZE+HORIZONTAL, \' \\\n
       \'"bottom"+CURSOR_S_RESIZE+VERTICAL, \' \\\n
       \'"left"+CURSOR_W_RESIZE+HORIZONTAL\' \\\n
       \');</script>\' % block_string\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>planning</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>planning_dhtml</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
