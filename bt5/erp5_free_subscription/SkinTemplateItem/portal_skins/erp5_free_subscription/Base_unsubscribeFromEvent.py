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
            <value> <string>"""This script is indented to be used in email as a link for people to \n
unsubscribe from a mailling\n
"""\n
portal = context.getPortalObject()\n
request = context.REQUEST\n
event_id = request[\'id\']\n
\n
user = portal.ERP5Site_getAuthenticatedMemberPersonValue()\n
# If we have a logged in user it\'s probably a backoffice agent.\n
if user is None:\n
  # If the referer contains the url of the event we are probably viewing the event\n
  # from ERP5 interface. We do not want to mark the event as delivered in that case\n
  # It can also be from fckeditor, in this case we don\'t have the event url in REFERER.\n
  if not ( (\'/event_module/%s\' % event_id) in request.HTTP_REFERER or \'fckeditor\' in request.HTTP_REFERER):\n
    if portal.Base_getHMACHexdigest(portal.Base_getEventHMACKey(), event_id) != request["hash"]:\n
      from zExceptions import Unauthorized\n
      raise Unauthorized()\n
    \n
    portal.portal_activities.activate(\n
      activity="SQLQueue").Base_createFreeSubscriptionRequest(\n
          event_id=request[\'id\'], \n
          hmac=request["hash"])\n
\n
# serve the web-page that will display a "Sucessfully unsubscribe" message\n
return context.index_html(request, request.RESPONSE, format=None)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_unsubscribeFromEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
