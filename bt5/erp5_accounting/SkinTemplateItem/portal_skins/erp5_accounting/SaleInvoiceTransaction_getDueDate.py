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

packing_list_list = context.getCausalityValueList(portal_type=\'Sale Packing List\')\n
\n
if len(packing_list_list) > 0:\n
  packing_list = packing_list_list[0]\n
  order = packing_list.getCausalityValue(portal_type=\'Sale Order\')\n
  from DateTime import DateTime\n
  due_date = order.getPaymentConditionPaymentDate( DateTime() )\n
  pat = None #order.getPaymentAdditionalTerm()\n
else:\n
  due_date = context.getStartDate()\n
  pat = None\n
\n
due_date += context.getPaymentConditionPaymentTerm(30)\n
peom = context.getPaymentEndOfMonth()\n
\n
if peom:\n
  i = 0\n
  month = due_date.month()\n
  while (month == (due_date + i).month()):\n
    i += 1\n
  due_date = (due_date + i - 1)\n
\n
  if pat != None:\n
    due_date += pat\n
\n
else:\n
  if pat != None:\n
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
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SaleInvoiceTransaction_getDueDate</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
