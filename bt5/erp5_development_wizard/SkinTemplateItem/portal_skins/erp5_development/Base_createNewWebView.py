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
  Create new report dialog\n
"""\n
\n
MARKER = [\'\', None]\n
portal_skins = context.getPortalObject().portal_skins\n
\n
if priority in MARKER:\n
  priority = 100.0\n
\n
if create_skin_id not in MARKER:\n
  # create skin\n
  skin_folder = context.Base_createSkinFolder(create_skin_id)\n
else:\n
  skin_folder = getattr(portal_skins, selected_skin_id)\n
\n
portal_type = context.getPortalType()\n
\n
# create\n
if web_form_id in MARKER:\n
  web_form_id = \'%s_view%sAsWeb\' % (portal_type.replace(\' \', \'\'), \n
                                    web_view_title.replace(" ", ""))\n
\n
skin_folder.manage_addProduct[\'ERP5Form\'].addERP5Form(web_form_id)\n
web_form = getattr(skin_folder, web_form_id)\n
context.editForm(web_form, {\'action\': \'Base_edit\'})\n
context.editForm(web_form, {\'pt\': \'form_view\'})\n
\n
web_form.manage_addField(\'my_title\', \'Title\', \'ProxyField\')\n
field = getattr(web_form, \'my_title\')\n
field.manage_edit_xmlrpc(dict(\n
      form_id=\'Base_viewFieldLibrary\', field_id=\'my_title\'))\n
\n
portal_type_document = context.portal_types[portal_type]\n
action = portal_type_document.newContent(portal_type="Action Information")\n
action.edit(reference="%s_view_as_web" % (web_view_title.lower().replace(" ", "_")),\n
            title=web_view_title,\n
            action="string:${object_url}/%s" % web_form_id,\n
            action_type="object_view",\n
            priority=priority,\n
            action_permission="View")\n
\n
return context.Base_redirect(web_form_id, \n
                             keep_items=dict(portal_status_message="Web View Successfuly created"))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>web_view_title, web_form_id=None, priority=None, create_skin_id=None, selected_skin_id=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_createNewWebView</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
