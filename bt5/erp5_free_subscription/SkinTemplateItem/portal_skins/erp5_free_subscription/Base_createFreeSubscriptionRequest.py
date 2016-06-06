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
            <value> <string>portal = context.getPortalObject()\n
if portal.Base_getHMACHexdigest(portal.Base_getEventHMACKey(), event_id) != hmac:\n
  from zExceptions import Unauthorized\n
  raise Unauthorized\n
\n
event = portal.event_module[event_id]\n
\n
# First create a request\n
request = portal.free_subscription_request_module.newContent(\n
  source=event.getSource(),\n
  destination=event.getDestination(),\n
  resource = event.getResource(),\n
  free_subscription_request_type="unsubscription",\n
  causality_value=event,\n
  )\n
  \n
free_subscription_list = portal.portal_catalog(portal_type="Free Subscription",\n
  default_resource_uid=event.getResourceUid(),\n
  default_source_uid=event.getSourceUid(),\n
  default_destination_uid=event.getDestinationUid())\n
\n
if len(free_subscription_list) != 1:\n
  raise ValueError("Impossible to find the free subscription (%d)" %\n
    (len(free_subscription_list)))\n
free_subscription = free_subscription_list[0].getObject()\n
request.setFollowUpValue(free_subscription)\n
\n
request.submit()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>event_id, hmac</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_createFreeSubscriptionRequest</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
