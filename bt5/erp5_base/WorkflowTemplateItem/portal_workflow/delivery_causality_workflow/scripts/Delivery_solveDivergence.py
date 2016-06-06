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
            <value> <string>delivery = state_change[\'object\']\n
delivery_solve_property_dict = state_change[\'kwargs\'].get(\'delivery_solve_property_dict\', {})\n
divergence_to_accept_list = state_change[\'kwargs\'].get(\'divergence_to_accept_list\', [])\n
divergence_to_adopt_list = state_change[\'kwargs\'].get(\'divergence_to_adopt_list\', [])\n
\n
if len(delivery_solve_property_dict) or len(divergence_to_accept_list) \\\n
    or len(divergence_to_adopt_list):\n
  delivery_relative_url = delivery.getRelativeUrl()\n
  delivery_builder_list = delivery.getBuilderList()\n
  if len(delivery_solve_property_dict):\n
    for delivery_builder in delivery_builder_list:\n
      delivery_builder.solveDeliveryGroupDivergence(delivery_relative_url,\n
                                                    property_dict=delivery_solve_property_dict)\n
  for delivery_builder in delivery_builder_list:\n
    delivery_builder.solveDivergence(delivery_relative_url,\n
                                     divergence_to_accept_list=divergence_to_accept_list,\n
                                     divergence_to_adopt_list=divergence_to_adopt_list)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
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
            <value> <string>Delivery_solveDivergence</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
