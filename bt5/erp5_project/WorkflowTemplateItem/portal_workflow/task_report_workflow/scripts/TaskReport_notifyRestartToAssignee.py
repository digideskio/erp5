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
            <value> <string>task_report = state_change[\'object\']\n
portal = task_report.getPortalObject()\n
\n
# Notify assignee\n
source_person = task_report.getSourceValue(portal_type="Person")\n
destination_decision_person = task_report.getDestinationDecisionValue(portal_type="Person")\n
if destination_decision_person is None:\n
  destination_decision_person = task_report.getDestinationValue(portal_type="Person")\n
\n
# send notification only if the source have a valid email and is a user in the\n
# system that can view the task report\n
if source_person is not None \\\n
      and destination_decision_person is not None\\\n
      and source_person.getDefaultEmailText() \\\n
      and source_person.getReference():\n
  if len(portal.acl_users.erp5_users.getUserByLogin(source_person.getReference())):\n
    message = """\n
Restarted task has been assigned to you by %(assignor)s.\n
\n
This task is named: %(title)s\n
\n
Description: \n
%(comment)s\n
\n
Start Date: %(start_date)s\n
Stop Date: %(stop_date)s\n
\n
Please visit ERP5: %(url)s\n
""" % {\n
       \'assignor\': destination_decision_person.getTitle(),\n
       \'title\'   : task_report.getTitle(),\n
       \'url\'     : \'%s/%s/view\' % (task_report.ERP5Site_getAbsoluteUrl(),\n
                              task_report.getRelativeUrl()),\n
       \'comment\' : task_report.getComment(),\n
       \'start_date\': task_report.getStartDate().Date(),\n
       \'stop_date\': task_report.getStopDate().Date(),\n
      }\n
    portal.portal_notifications.sendMessage(sender=destination_decision_person, recipient=source_person,\n
                                          subject="[ERP5 Task]  Restarted Task Assigned to You ", message=message)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TaskReport_notifyRestartToAssignee</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
