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

"""\n
Return the list of unread acknowledgements for the  user currently\n
connected. This script will use efficiently caches in order to slow\n
down as less a possible the user interface\n
"""\n
from DateTime import DateTime\n
\n
user_name = str(context.portal_membership.getAuthenticatedMember())\n
\n
def getUnreadAcknowledgementListForUser(user_name=None):\n
  # We give the portal type "Mass Notification" for now, we can\n
  # have a getPortalAcknowledgeableTypeList method in the future\n
  portal_acknowledgements = getattr(context.getPortalObject(),\n
                                    "portal_acknowledgements", None)\n
  result = []\n
  if portal_acknowledgements is not None:\n
    result = context.portal_acknowledgements.getUnreadDocumentUrlList(\n
              user_name=user_name, portal_type="Site Message")\n
  return result\n
\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
# Cache for every user the list of url of not acknowledge documents\n
getUnreadAcknowledgementList = CachingMethod(getUnreadAcknowledgementListForUser,\n
                                        "getUnreadAcknowledgementListForUser")\n
portal = context.getPortalObject()\n
return_list = []\n
url_list = getUnreadAcknowledgementList(user_name=user_name)\n
# For every not acknowledge document, check that documents are still not\n
# acknowledged and return them for the user interface\n
if len(url_list) > 0:\n
  acknowledgement_list = context.portal_acknowledgements.getUnreadAcknowledgementList(\n
\t\t  url_list=url_list, user_name=user_name)\n
  for acknowledgement in acknowledgement_list:\n
    #bulletin = acknowledgement.getCausalityValue()\n
    #event = bulletin.getFollowUpRelatedValue()\n
    text_content = acknowledgement.getTextContent()\n
    return_list.append({\n
\t  "title": acknowledgement.getTitle(),\n
\t  "text_content": text_content,\n
\t  "acknowledge_url": "AcknowledgementTool_acknowledge?acknowledgement_url=%s" % \\\n
             acknowledgement.getCausality()})\n
\n
return return_list\n


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
            <value> <string>AcknowledgementTool_getUserUnreadAcknowledgementList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
