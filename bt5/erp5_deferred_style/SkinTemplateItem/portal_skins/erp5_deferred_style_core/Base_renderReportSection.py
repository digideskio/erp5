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
            <value> <string>request = container.REQUEST\n
request.other.update(request_other)\n
\n
portal = context.getPortalObject()\n
\n
with portal.Localizer.translationContext(localizer_language):\n
  portal.portal_skins.changeSkin(skin_name)\n
\n
  # for unicode encoding\n
  request.RESPONSE.setHeader("Content-Type", "application/xml; charset=utf-8")\n
  render_prefix = \'x%s\' % report_section_idx\n
  report_section.pushReport(portal, render_prefix=render_prefix)\n
\n
  if report_section.getFormId():\n
    form = getattr(context, report_section.getFormId())\n
  else:\n
    form = None\n
\n
  selection_name = request.get(\'prefixed_selection_name\')\n
  data = context.render_report_section.pt_render(\n
                extra_context=dict(form=form,\n
                                   first=report_section_idx == 0,\n
                                   report_section=report_section,\n
                                   render_prefix=render_prefix))\n
\n
  report_section.popReport(portal, render_prefix=render_prefix)\n
\n
return report_section_idx, data.encode(\'utf8\').encode(\'bz2\')\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>localizer_language, skin_name, report_section, report_section_idx, request_other</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_renderReportSection</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
