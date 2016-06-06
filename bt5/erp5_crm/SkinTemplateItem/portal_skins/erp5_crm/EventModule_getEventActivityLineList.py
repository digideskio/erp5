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
\n
#define the list of ticket types\n
ticket_type_list = portal.getPortalTicketTypeList()\n
\n
#define the list of incoming or outgoing simulation states\n
direction_state_list=kw[\'direction\']\n
line_list = []\n
column_totals={}\n
column_totals[\'unassigned\']=0\n
for ticket_type in ticket_type_list:\n
  # XXX why replace ?\n
  column_totals[ticket_type.replace(\' \',\'\')]=0\n
total_count=0\n
    \n
# Prepare the parameters to filter\n
query_dict = {}\n
if request_start_date:\n
  query_dict[\'delivery.start_date\'] = dict(range=\'min\', query=request_start_date)\n
if request_stop_date:\n
  query_dict[\'delivery.stop_date\'] = dict(range=\'ngt\', \n
                                     query=request_stop_date.latestTime())\n
\n
#Get direction workfolow state list (simulation states)\n
for state in portal.ERP5Site_getWorkflowStateItemList(\n
     portal_type=portal.getPortalEventTypeList(), state_var=\'simulation_state\'):\n
  if state[1] in direction_state_list:\n
    #count number of objects in state with request parameters\n
    obj = Object(uid="new_")\n
    obj[\'validation_state\']=state[0]\n
    obj[\'unassigned\']=0\n
    total_count_line=0\n
    #add all ticket types columns\n
    for ticket_type in ticket_type_list:\n
      obj[ticket_type.replace(\' \',\'\')]=0\n
    #search all events in actual state  \n
    event_list=portal.portal_catalog.searchResults(\n
                                  portal_type=portal.getPortalEventTypeList(),\n
                                  simulation_state=state[1],\n
                                  **query_dict)\n
    for revent in event_list:\n
      event=revent.getObject()\n
      #count number of objects in state-ticket type with request parameters\n
      total_count_line+=1\n
      #Follow-up has priority\n
      if not event.getFollowUpUid() == None:\n
        ticket_type=portal.restrictedTraverse(\n
                                          event.getFollowUp()).getPortalType()\n
      else:\n
        if not event.getCausalityUid() == None:\n
          event_rel=portal.restrictedTraverse(event.getCausality())\n
          #check relationship of the event with ticket by causality\n
          if not event_rel.getFollowUpUid() == None:\n
            ticket_type=portal.restrictedTraverse(\n
                                      event_rel.getFollowUp()).getPortalType()\n
          else:\n
            #Unassigned\n
            ticket_type=\'unassigned\'\n
        else:\n
          #Unassigned\n
          ticket_type=\'unassigned\'\n
      obj[ticket_type.replace(\' \',\'\')]=obj[ticket_type.replace(\' \',\'\')]+1\n
      column_totals[ticket_type.replace(\' \',\'\')]=column_totals[\n
                                                ticket_type.replace(\' \',\'\')]+1\n
    obj[\'total\']=total_count_line\n
    total_count+=total_count_line\n
    line_list.append(obj)\n
                          \n
# Store the stat line in request\n
obj = Object(uid="new_")\n
obj[\'validation_state\']=portal.Base_translateString(\'Total\')\n
obj[\'total\']=total_count\n
for ticket_type in context.getPortalTicketTypeList():\n
  # XXX why replace ?\n
  obj[ticket_type.replace(\' \',\'\')]=column_totals[ticket_type.replace(\' \',\'\')]\n
obj[\'unassigned\']=column_totals[\'unassigned\']\n
line_stats_list=[]\n
line_stats_list.append(obj)\n
request.set(\'stat_line\',line_stats_list)\n
\n
#Sort the result by validation_state\n
def comparator(x, y):\n
  return cmp(x[\'validation_state\'], y[\'validation_state\'])\n
line_list.sort(comparator)\n
\n
return line_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>EventModule_getEventActivityLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
