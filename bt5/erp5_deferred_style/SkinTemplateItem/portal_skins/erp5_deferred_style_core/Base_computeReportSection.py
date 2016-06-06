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
            <value> <string>portal = context.getPortalObject()\n
N_ = portal.Base_translateString\n
\n
form = context.restrictedTraverse(form)\n
request = container.REQUEST\n
request.other.update(request_other)\n
\n
if form.meta_type == \'ERP5 Report\':\n
  report_section_list = getattr(context, form.report_method)()\n
elif form.meta_type == \'ERP5 Form\':\n
  report_section_list = []\n
  for field in form.get_fields():\n
    if field.getRecursiveTemplateField().meta_type == \'ReportBox\':\n
      report_section_list.extend(field.render())\n
else:\n
  raise ValueError, \'form meta_type (%r) unknown\' %(form.meta_type,)\n
\n
# Rebuild request_other as report section can have modify request content\n
request_other = {}\n
for k, v in request.items():\n
  if k not in (\'TraversalRequestNameStack\', \'AUTHENTICATED_USER\', \'URL\',\n
      \'SERVER_URL\', \'AUTHENTICATION_PATH\', \'USER_PREF_LANGUAGES\', \'PARENTS\',\n
      \'PUBLISHED\', \'AcceptLanguage\', \'AcceptCharset\', \'RESPONSE\', \'SESSION\',\n
      \'ACTUAL_URL\'):\n
    # XXX proxy fields stores a cache in request.other that cannot be pickled\n
    if same_type(k, \'\') and str(k).startswith(\'field__proxyfield\'):\n
      continue\n
    # Remove FileUpload parameters\n
    elif getattr(v, \'headers\', \'\'):\n
      continue\n
    request_other[k] = v\n
\n
localizer_language = portal.Localizer.get_selected_language()\n
active_process = portal.portal_activities.newActiveProcess()\n
\n
for idx, report_section in enumerate(report_section_list):\n
  if report_section.getPath():\n
    doc = report_section.getObject(portal)\n
  else:\n
    doc = context\n
  doc.activate(activity=\'SQLQueue\',\n
               active_process=active_process,\n
               tag=tag,\n
               priority=priority,\n
              ).Base_renderReportSection(skin_name=skin_name,\n
                                         localizer_language=localizer_language,\n
                                         report_section=report_section,\n
                                         report_section_idx=idx,\n
                                         request_other=request_other)\n
\n
activity_context = context\n
if activity_context == portal:\n
  # portal is not an active object\n
  activity_context = portal.portal_simulation\n
\n
activity_context.activate(activity=\'SQLQueue\', after_tag=tag, priority=priority).Base_report(\n
           active_process_url=active_process.getRelativeUrl(),\n
           skin_name=skin_name,\n
           localizer_language=localizer_language,\n
           title=N_(form.getProperty(\'title\')),\n
           request_other=request_other,\n
           form_path=form.getPhysicalPath(),\n
           user_name=user_name,\n
           format=format,\n
           report_section_count=len(report_section_list)\n
          )\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form, request_other, user_name, tag, skin_name, format, priority, **kw</string> </value>
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
            <value> <string>Base_computeReportSection</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
