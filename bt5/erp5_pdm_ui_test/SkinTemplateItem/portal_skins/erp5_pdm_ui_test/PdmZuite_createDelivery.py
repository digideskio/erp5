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
            <value> <string>from DateTime import DateTime\n
\n
portal = context.getPortalObject()\n
order_portal_type = "Sale Order"\n
order_line_portal_type = "Sale Order Line"\n
delivery_portal_type = "Sale Packing List"\n
delivery_line_portal_type = "Sale Packing List Line"\n
\n
delivery_id = "erp5_pdm_ui_test_delivery"\n
delivery_title = "erp5_pdm_ui_test_delivery_title"\n
\n
source_node_id = "erp5_pdm_ui_test_source_node"\n
destination_node_id = "erp5_pdm_ui_test_destination_node"\n
\n
resource_id = "erp5_pdm_ui_test_product"\n
business_process = \'business_process_module/erp5_default_business_process\'\n
\n
quantity = 1\n
\n
# Create an order or a packing list\n
if state in [\'planned\', \'ordered\']:\n
  module = portal.getDefaultModule(order_portal_type)\n
  order = module.newContent(\n
    portal_type=order_portal_type,\n
    id=delivery_id,\n
    title=delivery_title,\n
    source=\'organisation_module/%s\' % source_node_id,\n
    source_section=\'organisation_module/%s\' % source_node_id,\n
    destination=\'organisation_module/%s\' % destination_node_id,\n
    destination_section=\'organisation_module/%s\' % destination_node_id,\n
    specialise=business_process,\n
    start_date=DateTime(),\n
  )\n
  order_line = order.newContent(\n
    portal_type=order_line_portal_type,\n
    resource=\'product_module/%s\' % resource_id,\n
    quantity=1,\n
  )\n
  order.portal_workflow.doActionFor(order, \'plan_action\')\n
  if state == \'ordered\':\n
    order.portal_workflow.doActionFor(order, \'order_action\')\n
  delivery = order\n
\n
else:\n
  module = portal.getDefaultModule(delivery_portal_type)\n
  delivery = module.newContent(\n
    portal_type=delivery_portal_type,\n
    id=delivery_id,\n
    title=delivery_title,\n
    source=\'organisation_module/%s\' % source_node_id,\n
    destination=\'organisation_module/%s\' % destination_node_id,\n
    specialise=business_process,\n
    start_date=DateTime(),\n
  )\n
  delivery_line = delivery.newContent(\n
    portal_type=delivery_line_portal_type,\n
    resource=\'product_module/%s\' % resource_id,\n
    quantity=1,\n
  )\n
  for next_state, transition in [\n
#     (\'draft\', \'confirm_action\'),\n
#     (\'confirmed\', \'set_ready_action\'),\n
#     (\'ready\', \'start_action\'),\n
#     (\'start\', \'stop_action\'),\n
#     (\'stopped\', \'deliver_action\'),\n
    (\'draft\', \'confirm\'),\n
    (\'confirmed\', \'setReady\'),\n
    (\'ready\', \'start\'),\n
    (\'started\', \'stop\'),\n
    (\'stopped\', \'deliver\'),\n
  ]:\n
    if state != next_state:\n
#       delivery.portal_workflow.doActionFor(delivery, transition)\n
      getattr(delivery, transition)()\n
    else:\n
      break\n
\n
if delivery.getSimulationState() != state:\n
  raise ImplementationError, \'Delivery state is %s and not %s\' % (delivery.getSimulationState(), state)\n
\n
return "Delivery Created."\n
\n
# vim: syntax=python\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PdmZuite_createDelivery</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
