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

# TODO: this script is not well tested and not fully implemented\n
# TODO: this is actually PaymentCondition_getDueDate\n
\n
from DateTime import DateTime\n
\n
if context.getPortalType() == \'Payment Condition\':\n
  delivery = context.getParentValue()\n
  payment_condition = context\n
else:\n
  delivery = context\n
  payment_condition = context.getDefaultPaymentConditionValue()\n
\n
# Absolute payment date has priority\n
if payment_condition.getPaymentDate():\n
  return payment_condition.getPaymentDate()\n
\n
def OrderDateGetter(invoice):\n
  def getter():\n
    packing_list = invoice.getCausalityValue(\n
                     portal_type=context.getPortalDeliveryTypeList())\n
    if packing_list:\n
      order = packing_list.getCausalityValue(\n
                     portal_type=context.getPortalOrderTypeList())\n
      return order.getStartDate() # TODO start or stop ? -> based on source/destination\n
  return getter\n
\n
def PackingListDateGetter(invoice):\n
  def getter():\n
    packing_list = invoice.getCausalityValue(\n
                     portal_type=context.getPortalDeliveryTypeList())\n
    if packing_list:\n
      return packing_list.getStartDate() # TODO start or stop ? -> based on source/destination\n
  return getter\n
\n
case = {\n
  \'invoice\':      delivery.getStartDate,\n
  \'order\':        OrderDateGetter(delivery),\n
  \'packing list\': PackingListDateGetter(delivery),\n
}\n
\n
due_date = case.get(payment_condition.getTradeDate(), delivery.getStartDate)()\n
due_date += payment_condition.getPaymentTerm(0)\n
\n
pat = payment_condition.getPaymentAdditionalTerm()\n
\n
if payment_condition.getPaymentEndOfMonth():\n
  i = 0\n
  month = due_date.month()\n
  while (month == (due_date + i).month()):\n
    i += 1\n
  due_date = (due_date + i - 1)\n
  if pat:\n
    due_date += pat\n
else:\n
  if pat:\n
    i = 0\n
    month = due_date.month()\n
    while (month == (due_date + i).month()):\n
      i -= 1\n
    due_date = (due_date + i + pat)\n
\n
return due_date\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TradeCondition_getDueDate</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
