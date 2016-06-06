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
            <value> <string># this script allows to create a new follow up ticket for a given event\n
portal = context.getPortalObject()\n
event = context\n
\n
operator_list = event.getDestinationList()\n
try:\n
  source_value = portal.ERP5Site_getAuthenticatedMemberPersonValue()\n
  if source_value:\n
    operator_list.append(source_value.getRelativeUrl())\n
except ValueError:\n
  source_value = None\n
source_section = portal.portal_preferences.getPreferredSection(),\n
\n
\n
resource_kw = {\n
  "Campaign" : "follow_up_campaign_resource",\n
  "Meeting" : "follow_up_meeting_resource",\n
  "Sale Opportunity" : "follow_up_sale_opportunity_resource",\n
  "Support Request" : "follow_up_support_request_resource",\n
}\n
\n
resource = None\n
if follow_up_ticket_type in resource_kw:\n
  resource = kw.get(resource_kw[follow_up_ticket_type], None)\n
\n
\n
module = portal.getDefaultModule(follow_up_ticket_type)\n
ticket = module.newContent(\n
            portal_type=follow_up_ticket_type,\n
            title=follow_up_ticket_title,\n
            start_date=event.getStartDate(),\n
            destination_decision_list=event.getSourceList(),\n
            # destination_section=event.getSourceSection() or event.getSource(),\n
            source_trade_set=operator_list,\n
            source_value=source_value,\n
            source_section=source_section,\n
            resource=resource,\n
           )\n
if follow_up_ticket_type == \'Support Request\':\n
  ticket.setCausalityValue(event)\n
\n
follow_up_list = event.getFollowUpList()\n
follow_up_list.append(ticket.getRelativeUrl())\n
event.edit(follow_up_list=follow_up_list)\n
\n
if portal.portal_workflow.isTransitionPossible(\n
    ticket, \'submit\'):\n
  ticket.submit()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>follow_up_ticket_title="Sale Opportunity", follow_up_ticket_type=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_createFollowUpTicket</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
