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

# Look at all items availables for the source and then\n
# display them on a listbox so that the user will be able\n
# to select them\n
from DateTime import DateTime\n
\n
class Dummy:\n
  pass\n
\n
dummy = Dummy()\n
node = kw.get(\'node\',dummy)\n
vault = kw.get(\'vault\',dummy)\n
\n
if limit is None:\n
  limit = (0, -1)\n
list_start, list_length = limit\n
\n
if item_portal_type_list is None:\n
  item_portal_type_list = ["Checkbook","Check"]\n
\n
if listbox is None:\n
\n
  if vault is not dummy:\n
    node = vault\n
  if node is dummy:\n
    node = None\n
  if node is None:\n
    node = context.getBaobabSource()\n
\n
  if at_date is None:\n
    at_date = DateTime()\n
  item_list = []\n
  listbox = []\n
  if node is not None or disable_node:\n
    getCurrentTrackingList = context.portal_simulation.getCurrentTrackingList\n
#     context.log(\'Delivery_viewCheckbookInputDialog\', getCurrentTrackingList(at_date=at_date, node=node,src__=1,where_expression="item_catalog.portal_type=\'Check\' or item_catalog.portal_type=\'Checkbook\'"))\n
    if disable_node:\n
      node=None\n
\n
    kw = {}\n
    if reference not in (None, \'\'):\n
      kw[\'aggregate_uid\'] = [x.uid for x in context.getPortalObject().portal_catalog(\n
        destination_payment_internal_bank_account_number=reference,\n
        portal_type=(\'Check\', \'Checkbook\')\n
      )]\n
\n
    if checkbook_model not in (None, \'\'):\n
      checkbook_model_uid = context.getPortalObject().restrictedTraverse(checkbook_model).getUid()\n
      kw[\'resource_uid\'] = checkbook_model_uid\n
\n
    search_criterion = \'\'\n
    if title not in (None, \'\'):\n
      # FIXME: this doesn\'t work with current catalog and simulation tool\n
      #        build a SQL statement to bypass this limitation\n
      #kw[\'item_catalog.title\'] = title\n
      search_criterion = " AND item_catalog.title LIKE \'%s\'" % title\n
\n
    current_tracking_list = getCurrentTrackingList(\n
      to_date=at_date,\n
      node=node,\n
      where_expression="item_catalog.portal_type=\'Check\' or item_catalog.portal_type=\'Checkbook\' %s" % search_criterion,\n
      **kw)\n
\n
    if count is True:\n
      return len(current_tracking_list)\n
\n
    item_index = -1\n
    for item in current_tracking_list:\n
      item = item.getObject()\n
      exclude=0\n
      if model_filter_dict is not None:\n
        resource = item.getResourceValue()\n
        for property,value in model_filter_dict.items():\n
          if resource.getProperty(property)!=value:\n
            exclude=1\n
      if destination_payment is not None:\n
        if destination_payment!=item.getDestinationPayment():\n
          exclude=1\n
      if not exclude:\n
        item_portal_type = item.getPortalType()\n
        if item_portal_type  in item_portal_type_list:\n
          if item_portal_type==\'Check\' and item.getSimulationState() not in (\'draft\',\'confirmed\'):\n
            continue\n
          if simulation_state is not None:\n
            if item.getSimulationState()!=simulation_state:\n
              continue\n
          item_dict = {}\n
          if item_portal_type==\'Check\':\n
            item_dict[\'reference_range_max\'] = item.getReference()\n
            item_dict[\'reference_range_min\'] = item.getReference()\n
          else:\n
            item_dict[\'reference_range_min\'] = item.getReferenceRangeMin()\n
            item_dict[\'reference_range_max\'] = item.getReferenceRangeMax()\n
          item_dict[\'resource_title\'] = item.getResourceTitle()\n
          item_dict[\'destination_trade\'] = item.getDestinationTradeTitle()\n
          item_dict[\'check_amount_title\'] = item.getCheckAmountTitle()\n
          item_dict[\'internal_bank_account_number\'] = \'\'\n
          destination_payment_value = item.getDestinationPaymentValue()\n
          if destination_payment_value is not None:\n
            internal_bank_account_number = destination_payment_value.getInternalBankAccountNumber()\n
            item_dict[\'internal_bank_account_number\'] = internal_bank_account_number\n
            item_dict[\'account_owner\'] = item.getDestinationPaymentTitle()\n
          item_dict[\'recept_date\'] = item.getStartDate()\n
          item_dict[\'selection\'] = 0\n
          item_dict[\'uid\'] = \'new_%s\' %(item.getUid(),)\n
          item_index += 1\n
          if item_index < list_start:\n
            continue\n
          listbox.append(item_dict)\n
          if list_length != -1 and len(listbox) >= list_length:\n
            break\n
\n
return listbox\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=None, item_portal_type_list=None,destination_payment=None,model_filter_dict=None,batch_mode=0,simulation_state=None,disable_node=0,at_date=None,reference=None,checkbook_model=None,title=None,limit=None,count=False,**kw</string> </value>
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
            <value> <string>Delivery_getCheckbookList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
