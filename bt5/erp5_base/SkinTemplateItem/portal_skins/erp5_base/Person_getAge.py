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

"""Returns the age of the person at the current date or at the given `at_date`.\n
If `year` is true, return the integer value, otherwise returns a translated\n
string.\n
"""\n
from DateTime import DateTime\n
from Products.ERP5Type.DateUtils import getIntervalBetweenDates\n
Base_translateString = context.Base_translateString\n
\n
birthday = context.getBirthday()\n
if birthday is None:\n
  return None\n
\n
if at_date is None:\n
  at_date = DateTime()\n
\n
interval_dict = getIntervalBetweenDates(from_date=birthday,\n
                                        to_date=at_date)\n
if year:\n
  return interval_dict[\'year\']\n
\n
# mapping contains year, month & day\n
return Base_translateString("${year} years old", mapping=interval_dict)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>at_date=None, year=False</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Person_getAge</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
