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
            <value> <string>from Products.PythonScripts.standard import Object\n
request = container.REQUEST\n
portal = context.getPortalObject()\n
\n
request_start_date = request.get(\'from_date\', None)\n
request_stop_date = request.get(\'at_date\', None)\n
request_ticket_type = request.get(\'sale_opportunity_type\', None)\n
request_validation_state = request.get(\'sale_opportunity_state\', None)\n
\n
future_state_list = portal.Event_getFutureStateList()\n
past_state_list = portal.Event_getPastStateList()\n
\n
line_list = []\n
\n
# Prepare the parameters to filter\n
query_dict = {}\n
if request_start_date:\n
  query_dict[\'delivery.start_date\'] = dict(range=\'min\', query=request_start_date)\n
if request_stop_date:\n
  query_dict[\'delivery.stop_date\'] = dict(range=\'ngt\', \n
                                     query=request_stop_date.latestTime())\n
if request_validation_state:\n
  query_dict[\'simulation_state\'] = request_validation_state\n
if request_ticket_type:\n
  query_dict[\'default_resource_uid\'] =  [portal.restrictedTraverse(x).getUid() \n
                                          for x in request_ticket_type]\n
section_uid = context.Base_getSectionUidListForSectionCategory(request.get(\'section_category\',None))\n
\n
# Make the search using parameters\n
ticketlist=portal.portal_catalog.searchResults(portal_type="Sale Opportunity",\n
                                                source_section_uid=section_uid,\n
                                                sort_on=\'title\',\n
                                                **query_dict) \n
\n
# Get every result object\n
for r_ticket in ticketlist:\n
  ticket=r_ticket.getObject()\n
  future = 0\n
  past = 0\n
  #count future follow-up events\n
  future=int(portal.portal_catalog.countResults(portal_type=portal.getPortalEventTypeList(),\n
                                              follow_up_uid=ticket.getUid(),\n
                                              simulation_state=future_state_list)[0][0])\n
  #count past follow-up events\n
  past=int(portal.portal_catalog.countResults(portal_type=portal.getPortalEventTypeList(),\n
                                              follow_up_uid=ticket.getUid(),\n
                                              simulation_state=past_state_list)[0][0])\n
  #count past causality events\n
  past+=int(portal.portal_catalog.countResults(event_causality_ticket_uid=ticket.getUid(),\n
                                              portal_type=portal.getPortalEventTypeList(),\n
                                              simulation_state=past_state_list)[0][0])\n
  #count future causality events\n
  future+=int(portal.portal_catalog.countResults(event_causality_ticket_uid=ticket.getUid(),\n
                                              portal_type=portal.getPortalEventTypeList(),\n
                                              simulation_state=future_state_list)[0][0])  \n
  line_list.append(Object(uid=\'new_\',\n
                   title = ticket.getTitle(),\n
                   ticket_type = ticket.getResourceTranslatedTitle(),\n
                   stop_date = ticket.getStopDate(),\n
                   start_date = ticket.getStartDate(),\n
                   destination_section = ticket.getDestinationSectionTitle(),\n
                   destination_decision = ticket.getDestinationDecisionTitle(),\n
                   source_decision = ticket.getSourceDecisionTitle(),\n
                   source = ticket.getSourceTitle(),\n
                   validation_state = ticket.getTranslatedSimulationStateTitle(),\n
                   future = future,\n
                   past = past))\n
\n
if line_list == []:\n
  line_list.append(Object(uid=\'new_\'))\n
return line_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SaleOpportunityModule_getSaleOpportunityStatusLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
