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
            <value> <string>""" \n
  Make sure the objects about to be created do not exist already\n
"""\n
\n
portal = context.getPortalObject()\n
\n
for x in portal.discussion_thread_module.objectValues():\n
  if x.getTitle() == "Thread 1":\n
    portal.discussion_thread_module.deleteContent(x.getId())\n
  if x.getTitle() == "Thread 2":\n
    portal.discussion_thread_module.deleteContent(x.getId())\n
  if x.getTitle() == "Thread 3":\n
    portal.discussion_thread_module.deleteContent(x.getId())\n
\n
return \'Reset Successfully.\'\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>testPredecessorCreateDiscussionThreadReset</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Reset before running</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
