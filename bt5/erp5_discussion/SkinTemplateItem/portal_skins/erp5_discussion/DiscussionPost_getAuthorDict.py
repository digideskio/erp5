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
  Get author details.\n
"""\n
portal = context.getPortalObject()\n
\n
author = context.getSourceValue()\n
result = {\'author_url\': None,\n
          \'author_signature\': None,\n
          \'author_title\': context.Base_translateString(\'Unknown User\'),\n
          \'author_thumbnail_url\': None}\n
\n
if author is not None:\n
  result[\'author_url\'] = \'%s/view\' %author.getAbsoluteUrl()\n
  result[\'author_signature\'] = portal.ERP5Site_getUserPreferredForumSettingsDict(author.getReference())[\'preferred_forum_signature\']\n
  result[\'author_title\'] = author.getTitle()\n
  thumbnail = author.getDefaultImage()\n
  if thumbnail is not None and thumbnail.hasData():\n
    result[\'author_thumbnail_url\'] = thumbnail.absolute_url()\n
\n
return result\n
</string> </value>
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
            <value> <string>DiscussionPost_getAuthorDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
