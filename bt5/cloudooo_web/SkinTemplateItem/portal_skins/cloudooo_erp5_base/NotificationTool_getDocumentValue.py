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
 This script is part of ERP5 Base\n
\n
 The default implementation searches for\n
 documents which are in the user language if any\n
 with same reference.\n
"""\n
#XXX : Diff with standart version by using proxy role auditor to allow\n
#      anonymous to find email. May be change workflow instead of this\n
#      Remove as possible hardcoding on default_language\n
\n
\n
portal = context.getPortalObject()\n
portal_catalog = portal.portal_catalog\n
# The list of portal types here should be large enough to include\n
# all portal_types defined in the various sections so that\n
# href tags which point to a document by reference can still work.\n
valid_portal_type_list = (\'Notification Message\',)\n
\n
# Find the applicable language\n
if language is None:\n
  language = portal.Localizer.get_selected_language()\n
\n
# Find the default language\n
default_language = portal.Localizer.get_default_language() or \'en\'\n
\n
if validation_state is None:\n
  validation_state = (\'validated\',)\n
\n
# Search the catalog for all documents matching the reference\n
# this will only return documents which are accessible by the user\n
\n
notification_message_list = portal_catalog(reference=reference,\n
                                           portal_type=valid_portal_type_list,\n
                                           validation_state=validation_state,\n
                                           language=language,\n
                                           sort_on=[(\'version\', \'descending\')],\n
                                           group_by=(\'reference\',),\n
                                           **kw)\n
\n
if len(notification_message_list) == 0 and language != default_language:\n
  # Search again with English as a fallback.\n
  notification_message_list = portal_catalog(reference=reference,\n
                                             portal_type=valid_portal_type_list,\n
                                             validation_state=validation_state,\n
                                             language=default_language,\n
                                             sort_on=[(\'version\', \'descending\')],\n
                                             group_by=(\'reference\',),\n
                                             **kw)\n
\n
if len(notification_message_list) == 0:\n
  # Search again without the language\n
  notification_message_list = portal_catalog(reference=reference,\n
                                             portal_type=valid_portal_type_list,\n
                                             validation_state=validation_state,\n
                                             sort_on=[(\'version\', \'descending\')],\n
                                             group_by=(\'reference\',),\n
                                             **kw)\n
\n
if len(notification_message_list) == 0:\n
  # Default returns None\n
  notification_message = None\n
else:\n
  # Try to get the first page on the list\n
  notification_message = notification_message_list[0]\n
  notification_message = notification_message.getObject()\n
\n
# return the Notification Message\n
return notification_message\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>reference, language=None, validation_state=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Auditor</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>NotificationTool_getDocumentValue</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
