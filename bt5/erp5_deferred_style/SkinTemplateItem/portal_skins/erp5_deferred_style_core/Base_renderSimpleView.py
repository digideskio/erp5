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
            <value> <string># Render a "normal" form or an OOo template in an activity and send it by email\n
from Products.ERP5Type.Message import translateString\n
portal = context.getPortalObject()\n
request = portal.REQUEST\n
request.form.update(request_form)\n
\n
if skin_name and skin_name != \'None\': # make_query serializes None as \'None\'\n
  portal.portal_skins.changeSkin(skin_name)\n
\n
with portal.Localizer.translationContext(localizer_language):\n
  report_data = getattr(context, deferred_style_dialog_method)(**params)\n
\n
  attachment_name_list = [x[len(\' filename=\'):] for x in (request.RESPONSE.getHeader(\n
                        \'content-disposition\') or \'\').split(\';\')\n
                            if x.startswith(\' filename=\')]\n
  if attachment_name_list:\n
    attachment_name, = attachment_name_list\n
  else:\n
    assert \'inline\' in (request.RESPONSE.getHeader(\'content-disposition\') or \'\')\n
    attachment_name = \'index.html\'\n
  if attachment_name.startswith(\'"\'):\n
    attachment_name = attachment_name[1:]\n
  if attachment_name.endswith(\'"\'):\n
    attachment_name = attachment_name[:-1]\n
  attachment_list = (\n
    {\'mime_type\': (request.RESPONSE.getHeader(\'content-type\') or \'application/octet-stream;\').split(\';\')[0],\n
     \'content\': \'%s\' % report_data,\n
     \'name\': attachment_name},)\n
\n
  portal.ERP5Site_notifyReportComplete(\n
    user_name=user_name,\n
    subject=str(translateString(attachment_name.rsplit(\'.\', 1)[0])),\n
    message=\'\',\n
    attachment_list=attachment_list)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>localizer_language, skin_name, request_form, deferred_style_dialog_method, user_name, params</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_renderSimpleView</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
