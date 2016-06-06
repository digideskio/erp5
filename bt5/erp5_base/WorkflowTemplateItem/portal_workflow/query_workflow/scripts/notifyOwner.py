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
            <value> <string>"""\n
This script tries to send a message to the appropriate recipient\n
from the appropriate sender. It uses portal_notifications\n
and the getObject API of ERP5Catalog.\n
This script has a proxy role to make sure we can find person documents in the\n
catalog.\n
"""\n
from Products.ERP5Type.Log import log\n
\n
object = sci[\'object\']\n
portal = sci.getPortal()\n
translateString = portal.Base_translateString\n
portal_catalog = portal.portal_catalog\n
\n
# Get the owner\n
owner = object.getViewPermissionOwner()\n
owner_value = portal_catalog.getResultValue(portal_type=\'Person\', reference=owner)\n
\n
# Get the authenticated user\n
user = portal.portal_membership.getAuthenticatedMember().getUserName()\n
user_value = portal_catalog.getResultValue(portal_type=\'Person\', reference=user)\n
\n
# If users are not defined, we need to log and return\n
if not owner or owner_value is None:\n
  # We keep a trace because this is the best we\n
  # can do (preventing answers is even worse)\n
  log("ERP5 Query Workflow", "No owner defined")\n
  return\n
if not user or user_value is None:\n
  # We keep a trace because this is the best we\n
  # can do (preventing answers is even worse)\n
  log("ERP5 Query Workflow", "Current user is not defined")\n
  return\n
\n
# Build the message and translate it\n
subject = translateString("Query was answered.")\n
msg = """The Query ID ${id} which you posted has been answered by ${user}\n
\n
Question:\n
\n
${question}\n
\n
Answer:\n
\n
${answer}\n
""" \n
msg = translateString(msg, \n
             mapping=dict(id=object.getId(),\n
                          subject=subject,\n
                          user=user_value.getTitle(),\n
                          question=object.getDescription(),\n
                          answer=object.getTextContent())\n
            )\n
\n
# We can now notify the owner through the notification tool\n
portal.portal_notifications.sendMessage(\n
         sender=user, recipient=owner, subject=subject, message=msg)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>sci</string> </value>
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
            <value> <string>notifyOwner</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
