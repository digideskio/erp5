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
            <value> <string>"""\n
  This script sets all standard (non-movable) holidays for polish calendar\n
  on context Group Calendar Period.\n
  Year defaults to current year.\n
"""\n
if year is None:\n
  year = DateTime().year()\n
part_holiday_list = [\'01-01\',\'05-01\',\'05-03\',\'08-15\',\'11-01\',\'11-11\',\'12-25\',\'12-26\']\n
holiday_list = [\'-\'.join((str(year),holiday))  for holiday in part_holiday_list]\n
\n
for day in holiday_list:\n
   holiday = DateTime(day)\n
   context.newContent(portal_type = \'Calendar Exception\',\n
                      exception_date = holiday)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>year=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>GroupPresencePeriod_setPolishHolidayExceptions</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
