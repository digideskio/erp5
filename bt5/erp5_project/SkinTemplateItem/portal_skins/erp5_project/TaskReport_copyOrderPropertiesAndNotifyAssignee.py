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
            <value> <string>if related_simulation_movement_path_list is None:\n
  raise RuntimeError, \'related_simulation_movement_path_list is missing. Update ERP5 Product.\'\n
\n
if REQUEST is not None:\n
  from zExceptions import Unauthorized\n
  raise Unauthorized(script.id)\n
\n
task_report = context\n
portal = task_report.getPortalObject()\n
\n
# First, copy Order properties\n
task_report.PackingList_copyOrderProperties()\n
\n
related_order = task_report.getCausalityValue()\n
\n
if task_report.getSimulationState() == \'draft\':\n
  task_report.edit(\n
    comment=related_order.getComment(),\n
    description = related_order.getDescription(),\n
    delivery_mode=related_order.getDeliveryMode(),\n
    incoterm=related_order.getIncoterm(),\n
    source_administration_value=related_order.getSourceAdministrationValue(),\n
    destination_decision_value=related_order.getDestinationDecisionValue(),\n
    title=related_order.getTitle()\n
  )\n
\n
# If security definitions are implemented on the packing list, it is time to apply them\n
task_report.assignRoleToSecurityGroup()\n
\n
# Notify the requester.\n
source_person = task_report.getSourceValue(portal_type="Person")\n
destination_decision_person = task_report.getDestinationDecisionValue(portal_type="Person")\n
if destination_decision_person is None:\n
  destination_decision_person = task_report.getDestinationValue(portal_type="Person")\n
\n
# We send a message only if the requester has an email\n
# and the assignee has one too and is an user that can view the task report.\n
if (\n
      source_person is not None and\n
      source_person.getDefaultEmailText() and # XXX Add unit test: check if task confirmation works if assignee has no mail\n
      destination_decision_person is not None and\n
      destination_decision_person.getDefaultEmailText() and\n
      destination_decision_person.getReference()\n
    ):\n
  if len(portal.acl_users.erp5_users.getUserByLogin(source_person.getReference())):\n
    message = """A new task has been assigned to you by %(assignor)s.\n
\n
This task is named: %(title)s\n
\n
Description: \n
%(description)s\n
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
       \'description\' : task_report.getDescription(),\n
       \'start_date\': task_report.getStartDate().Date(),\n
       \'stop_date\': task_report.getStopDate().Date(),\n
      }\n
    portal.portal_notifications.sendMessage(sender=destination_decision_person,\n
                                            recipient=source_person, \n
                                            subject="[ERP5 Task] %s" % task_report.getTitle(), \n
                                            message=message)\n
\n
task_report.Delivery_confirm()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>related_simulation_movement_path_list=None, REQUEST=None</string> </value>
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
            <value> <string>TaskReport_copyOrderPropertiesAndNotifyAssignee</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
