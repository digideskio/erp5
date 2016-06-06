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
XXX duplicated here because original one is using woelfel.start_date sql table to\n
filter out public holiday lines\n
"""\n
assert context.getPortalType() == "Group Calendar Assignment"\n
portal = context.getPortalObject()\n
period_list = []\n
# look when we workers should be available with time tables\n
group_calendar = context.getSpecialiseValue()\n
if group_calendar is not None:\n
  context.log("group_calendar", group_calendar)\n
  period_dict = {}\n
  for period in group_calendar.objectValues(portal_type=portal.getPortalCalendarPeriodTypeList()):\n
    period_list.append(period)\n
    period_dict[period.getStartDate().Day()] = period.getQuantity()\n
  # And then we subscract not working days\n
  start_date = context.getStartDate()\n
  if start_date is not None:\n
    stop_date = context.getStopDate()\n
    if stop_date is None:\n
      # We assume that there is a periodicity_stop_date correctly define on time table line\n
      assert len(period_list) > 0 # this should be always the case in Woelfel\n
      stop_date = period_list[0].getPeriodicityStopDate()\n
    if stop_date is not None:\n
      region_uid = group_calendar.getRegionUid()\n
      if region_uid:\n
        # Get all public holidays containers matching the right country\n
        catalog_kw = {}\n
        for public_holiday in portal.portal_catalog(portal_type="Public Holiday Line",\n
                          parent_region_uid=region_uid, validation_state="validated", **catalog_kw):\n
          public_holiday = public_holiday.getObject()\n
          if public_holiday.getStartDate() >= start_date and public_holiday.getStopDate() < stop_date:\n
            quantity = - period_dict[public_holiday.getStartDate().Day()] * (1 - public_holiday.getQuantity())\n
            if quantity:\n
              period_list.append(public_holiday.asContext(quantity=quantity, stop_date=public_holiday.getStartDate()+1))\n
return period_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>GroupCalendarAssignment_getPeriodList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
