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
            <value> <string># Example code:\n
\n
# Import a standard function, and get the HTML request and response objects.\n
from Products.PythonScripts.standard import html_quote\n
request = container.REQUEST\n
RESPONSE =  request.RESPONSE\n
\n
# Return a string identifying this script.\n
print "This is the", script.meta_type, \'"%s"\' % script.getId(),\n
if script.title:\n
    print "(%s)" % html_quote(script.title),\n
print "in", container.absolute_url()\n
return printed\n
</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Movement_statBalance</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
