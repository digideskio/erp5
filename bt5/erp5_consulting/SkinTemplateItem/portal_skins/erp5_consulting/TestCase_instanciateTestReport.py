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
            <value> <string>test_report = context.getPortalObject().test_report_module.newContent(portal_type = \'Test Report\'\n
  , specialise_value = context\n
  , title = context.getTitle()\n
  , description = context.getDescription()\n
  , requirement_value_list = context.getRequirementValueList()\n
)\n
\n
translate_actors = {}\n
\n
for o in context.contentValues(filter={\'portal_type\': \'Test Case Actor\'}):\n
  test_report_actor = test_report.newContent(portal_type = \'Test Report Actor\'\n
    , description = o.getDescription()\n
    , group = o.getGroup()\n
    , group_free_text = o.getGroupFreeText()\n
    , int_index = o.getIntIndex()\n
    , site_free_text = o.getSiteFreeText()\n
    , title = o.getTitle()\n
    , use_case_actor_role_list = o.getUseCaseActorRoleList()\n
    )\n
  translate_actors[o] = test_report_actor\n
\n
for o in context.contentValues(filter={\'portal_type\': \'Test Case Step\'}):\n
  test_report.newContent(portal_type = \'Test Report Step\'\n
    , description = o.getDescription()\n
    , int_index = o.getIntIndex()\n
    , requirement_list = o.getRequirementList()\n
    , title = o.getTitle()\n
    , source_section_value = translate_actors[o.getSourceSectionValue()]\n
    )\n
\n
return context.REQUEST.RESPONSE.redirect("%s?portal_status_message=Test+Report+Created." % (test_report.absolute_url(), ))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestCase_instanciateTestReport</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
