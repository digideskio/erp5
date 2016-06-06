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
  Creates a Test|Web Page (with no text) and generates the first chapter/slide\n
"""\n
\n
portal_type = \'Test Page\'\n
\n
if context.getPortalType() == "Web Page Module":\n
  # This should be much more clever\n
  portal_type = \'Web Page\'\n
\n
from Products.ERP5Type.Document import newTempBase\n
translateString = context.Base_translateString\n
portal_status_message = translateString("%s created. You can now add your first chapter." % portal_type)\n
\n
page = context.newContent(portal_type=portal_type,\n
                          title = title)\n
\n
session = context.ERP5RunMyDocs_acquireSession()\n
session[\'title\'] = title\n
session[\'author\'] = author\n
session[\'author_mail\'] = author_mail\n
session[\'test_page_path\'] = page.getPath()\n
session[\'listbox\'] = [newTempBase(context.getPortalObject(), \'\',\n
                   title = title,\n
                   uid = \'0\',\n
                   int_index = 0,\n
                   image_id = \'\',\n
                   slide_type = \'Master\',\n
                   text_content = text_content,\n
                   slide_content = slide_content,\n
                   file = False,\n
                   tested = False\n
                 )]\n
\n
return context.Base_redirect(\'TestPageModule_viewChapterCreationWizard\', \n
                             keep_items = dict(portal_status_message=portal_status_message))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>title, author, author_mail, text_content, slide_content, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestPageModule_createTestPage</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
