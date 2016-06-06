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

non_reflected_portal_type = []\n
item_container_type_list = []\n
\n
log = 0\n
result = True\n
\n
if log:\n
  context.log("object = %s" %(context,), "archive = %s" %(predicate,))\n
\n
# items and their container go in all catalog\n
ptype = context.getPortalType()\n
if context.isItemType():\n
  return True\n
if ptype in item_container_type_list:\n
  return True\n
\n
if getattr(context, \'getExplanationValue\', None) is not None:\n
  try:\n
    explanation_value = context.getExplanationValue()\n
  except AttributeError:\n
    context.log("Archive_test, getExplanationValue failed", "obj = %s" %(context,))\n
    explanation_value = None\n
  if explanation_value is not None and explanation_value.getPortalType() \\\n
         in item_container_type_list:\n
    return True\n
\n
# Except those we don\'t want\n
if ptype not in non_reflected_portal_type:\n
  # Object not delivery or movement goes in all archive\n
  if not(context.providesIMovement() or context.isDelivery()):\n
    if log:\n
      context.log(" - document is not Movement/Delivery", "")\n
    return True\n
else:\n
  result = result and True\n
  if log:\n
    context.log(" - result after reflected", "%s" %result)\n
\n
# Check Date\n
if getattr(context, \'getStopDate\', None) is not None:\n
  max_stop_date = predicate.getStopDateRangeMax()\n
  min_stop_date = predicate.getStopDateRangeMin()\n
  if log:\n
    context.log("obj stop date %s" %context.getStopDate(), "min %s, max %s" %(min_stop_date, max_stop_date))\n
  if max_stop_date is not None:\n
    result = result and (context.getStopDate() < max_stop_date)\n
  if min_stop_date is not None:\n
    result = result and (context.getStopDate() >= min_stop_date)\n
if log:\n
  context.log("result after date", result)\n
\n
\n
# XXX must manage specific case like Applied Rule, where do we want them to go ?\n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>predicate=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Archive_test</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
