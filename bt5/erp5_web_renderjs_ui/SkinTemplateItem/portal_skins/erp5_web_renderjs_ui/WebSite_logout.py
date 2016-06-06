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
            <key> <string>_Access_contents_information_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_bindings_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_cache_settings_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_permissions_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Copy_or_Move_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Delete_objects_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Manage_WebDAV_Locks_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Manage_properties_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Take_ownership_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Undo_changes_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_View_management_screens_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_Lock_items_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_Unlock_items_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_access_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
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
  Default logout handler, overwritten to give website specific portal status message.\n
"""\n
website = context.getWebSiteValue()\n
REQUEST = context.REQUEST\n
if REQUEST.has_key(\'portal_skin\'):\n
  context.portal_skins.clearSkinCookie()\n
REQUEST.RESPONSE.expireCookie(\'__ac\', path=\'/\')\n
REQUEST.RESPONSE.setHeader(\'Location\', came_from or context.getPermanentURL(context))\n
REQUEST.RESPONSE.setStatus(303)\n
# REQUEST.RESPONSE.redirect(came_from or context.getPermanentURL(context));\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>came_from=\'\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSite_logout</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Logout handler</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
