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
from ZODB.POSException import ConflictError\n
from zExceptions import Unauthorized\n
Base_translateString = context.Base_translateString\n
\n
serial = context.REQUEST[\'serial\']\n
next_serial = context.REQUEST[\'next_serial\']\n
\n
try:\n
  context.HistoricalRevisions[serial]\n
except (ConflictError, Unauthorized):\n
  raise\n
except Exception: # POSKeyError\n
  return [Object(property_name=Base_translateString(\'Historical revisions are\'\n
                      \' not available, maybe the database has been packed\'))]\n
\n
if next_serial == \'0.0.0.0\':\n
  new_getProperty = context.getProperty\n
else:\n
  new = context.HistoricalRevisions[next_serial]\n
  new_getProperty = new.getProperty\n
old = context.HistoricalRevisions[serial]\n
result = []\n
\n
binary_data_explanation = Base_translateString("Binary data can\'t be displayed")\n
base_error_message = Base_translateString(\'(value retrieval failed)\')\n
\n
for prop_dict in context.getPropertyMap():\n
  prop = prop_dict[\'id\']\n
  error = False\n
  try:\n
    current_value = context.getProperty(prop)\n
  except TypeError:\n
    error = True\n
    current_value = base_error_message\n
  try:\n
    old_value = old.getProperty(prop)\n
  except TypeError:\n
    error = True\n
    old_value = base_error_message\n
  try:\n
    new_value = new_getProperty(prop)\n
  except TypeError:\n
    error = True\n
    new_value = base_error_message\n
  if new_value != old_value or error:\n
    # check if values are unicode convertible (binary are not)\n
    if isinstance(new_value, (str, unicode)):\n
      try:\n
        unicode(str(new_value), \'utf-8\')\n
      except UnicodeDecodeError:\n
        new_value = binary_data_explanation\n
    if isinstance(old_value, (str, unicode)):\n
      try:\n
        unicode(str(old_value), \'utf-8\')\n
      except UnicodeDecodeError:\n
        old_value = binary_data_explanation\n
    if isinstance(current_value, (str, unicode)):\n
      try:\n
        unicode(str(current_value), \'utf-8\')\n
      except UnicodeDecodeError:\n
        current_value = binary_data_explanation\n
\n
    result.append( Object( property_name=prop,\n
                           new_value=new_value,\n
                           old_value=old_value,\n
                           current_value=current_value))\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getHistoricalComparisonDifferenceList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
