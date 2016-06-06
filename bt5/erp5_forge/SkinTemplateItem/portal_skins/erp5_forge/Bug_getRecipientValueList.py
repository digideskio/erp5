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
            <value> <string># Define Recipents\n
project = context.getDestinationProjectValue()\n
portal = context.getPortalObject()\n
if project is not None:\n
  recipient_list = [ i.getParentValue() for i in project.getDestinationProjectRelatedValueList(portal_type="Assignment")]\n
else:\n
  recipient_list = context.getDestinationValueList() + context.getSourceValueList()\n
\n
#If highest level of severity is reach, send Notifications also to source_decision\n
if context.getBugSeverityUid():\n
  bug_severity_list = portal.portal_categories.bug_severity.getCategoryChildValueList(sort_on=\'int_index\')\n
  if bug_severity_list and\\\n
     bug_severity_list[-1].getUid() ==\\\n
     context.getBugSeverityUid():\n
    recipient_list.extend(context.getSourceDecisionValueList())\n
return recipient_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Bug_getRecipientValueList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
