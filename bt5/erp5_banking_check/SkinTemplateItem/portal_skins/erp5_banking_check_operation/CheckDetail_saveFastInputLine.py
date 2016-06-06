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

portal = context.getPortalObject()\n
N_ = portal.Base_translateString\n
\n
request  = context.REQUEST\n
message = N_("No+Lines+Created.")\n
redirect_url = \'%s/view?%s\' % ( context.absolute_url()\n
                              , \'portal_status_message=%s\' % message\n
                              )\n
\n
# The fast input contain no line, just return.\n
if listbox is None:\n
  return request[ \'RESPONSE\' ].redirect( redirect_url )\n
\n
# get the list of movement we need to create\n
# First call the first scripts wich check many things\n
error_value = 0\n
field_error_dict = {}\n
if check:\n
  (error_value, field_error_dict) = context.CheckDelivery_generateCheckDetailInputDialog(\n
                                     listbox=listbox,batch_mode=1,**kw)\n
\n
request = context.REQUEST\n
resource = request.get(\'resource\',None)\n
previous_resource = request.get(\'previous_resource\',None)\n
line_portal_type = "Checkbook Reception Line"\n
\n
if (error_value or (previous_resource not in(\'\',None) and previous_resource!=resource)):\n
  return context.CheckDelivery_generateCheckDetailInputDialog(\n
                                     listbox=listbox,batch_mode=0,**kw)\n
\n
item_model = context.getPortalObject().restrictedTraverse(resource)\n
\n
item_module_id = \'checkbook_module\'\n
if item_model.getPortalType()==\'Check\':\n
  item_module_id = \'check_module\'\n
\n
create_line = 0\n
aggregate_data_list = []\n
context.log(\'CheckDetail_saveFastInputLine, listbox\',listbox)\n
number_of_line_created = 0\n
for line in listbox:\n
  add_line = 0\n
  quantity = line[\'quantity\']\n
  price = line.get(\'price\',None)\n
  price_currency = line.get(\'price_currency\',None)\n
  line_kw_dict = {}\n
  line_kw_dict[\'resource\'] = resource\n
  line_kw_dict[\'quantity\'] = quantity\n
  if price not in (\'\',None):\n
    add_line = 1\n
    line_kw_dict[\'price\'] = price\n
  if price_currency not in (\'\',None):\n
    line_kw_dict[\'price_currency\'] = price_currency\n
  destination_payment_relative_url = line.get(\'destination_payment_relative_url\',None)\n
  if destination_payment_relative_url not in (None,\'\'):\n
    add_line = 1\n
    line_kw_dict[\'destination_payment\'] = destination_payment_relative_url\n
  destination_trade_relative_url = line.get(\'destination_trade_relative_url\',None)\n
  if destination_trade_relative_url not in (None,\'\'):\n
    line_kw_dict[\'destination_trade\'] = destination_trade_relative_url\n
  reference_range_min = line.get(\'reference_range_min\',None)\n
  if reference_range_min not in (None,\'\'):\n
    line_kw_dict[\'reference_range_min\'] = reference_range_min\n
    add_line = 1\n
  reference_range_max = line.get(\'reference_range_max\',None)\n
  if reference_range_max not in (None,\'\'):\n
    line_kw_dict[\'reference_range_max\'] = reference_range_max\n
    add_line = 1\n
  check_amount_relative_url = line.get(\'check_amount\',None)\n
  if check_amount_relative_url not in (None,\'\'):\n
    if check_amount_relative_url.startswith(\'check_amount\'):\n
      check_amount_relative_url = check_amount_relative_url[len(\'check_amount/\'):]\n
    line_kw_dict[\'check_amount\'] = check_amount_relative_url\n
  check_type_relative_url = line.get(\'check_type\',None)\n
  if check_type_relative_url not in (None,\'\'):\n
    if check_type_relative_url.startswith(\'check_type\'):\n
      check_type_relative_url = check_type_relative_url[len(\'check_type/\'):]\n
    line_kw_dict[\'check_type\'] = check_type_relative_url\n
    check_type = context.getPortalObject().restrictedTraverse(check_type_relative_url)\n
    line_kw_dict[\'price\'] = check_type.getPrice()\n
    line_kw_dict[\'price_currency\'] = check_type.getParentValue().getPriceCurrency()\n
  if add_line:\n
    number_of_line_created += 1\n
    context.newContent(portal_type=line_portal_type,**line_kw_dict)\n
\n
if number_of_line_created>0:\n
  message = N_("Lines+Created.")\n
  redirect_url = \'%s/view?%s\' % ( context.absolute_url()\n
                                , \'portal_status_message=%s\' % message\n
                                )\n
request[ \'RESPONSE\' ].redirect( redirect_url )\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=None, check=1, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CheckDetail_saveFastInputLine</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
