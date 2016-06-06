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
            <value> <string>if clean:\n
  context.Zuite_tearDownIncomingEventTest()\n
\n
portal = context.getPortalObject()\n
howto_dict = context.Zuite_getHowToInfo() \n
isTransitionPossible = portal.portal_workflow.isTransitionPossible\n
\n
# in testExpressUserDocumentationIncomingEvent we relly that loged in user is an ERP5 Person\n
logged_in_user = str(context.portal_membership.getAuthenticatedMember())\n
current_person = context.portal_catalog.getResultValue(portal_type=\'Person\', \n
                                                       reference=logged_in_user)\n
if current_person is None:\n
  pass\n
  #return \'You need to be logged with an ERP5User for this test %s\' %logged_in_user\n
\n
# check if there is already the euro curency on the instance\n
currency = context.portal_catalog.getResultValue(portal_type=\'Currency\',\n
                                                 title=howto_dict[\'incoming_event_howto_currency_title\'])\n
if currency is None:\n
  currency = portal.currency_module.newContent(portal_type=\'Currency\',\n
                                               title=howto_dict[\'incoming_event_howto_currency_title\'],\n
                                               reference=howto_dict[\'incoming_event_howto_currency_tag\'],\n
                                               id=howto_dict[\'incoming_event_howto_currency_tag\'],\n
                                               base_unit_quantity=0.01)\n
\n
if isTransitionPossible(currency, \'validate\'):\n
  currency.validate()\n
\n
organisation = portal.organisation_module.newContent(portal_type=\'Organisation\',\n
                                                     title=howto_dict[\'incoming_event_howto_organisation_title\'],\n
                                                     corporate_name=howto_dict[\'incoming_event_howto_organisation_title\'],\n
                                                    )\n
organisation.validate()\n
\n
person = portal.person_module.newContent(portal_type=\'Person\',\n
                                         title=howto_dict[\'incoming_event_howto_person_title\'],\n
                                         career_subordination_title=howto_dict[\'incoming_event_howto_organisation_title\'],\n
                                         default_email_text=howto_dict[\'incoming_event_howto_person_email\'])\n
person.validate()\n
\n
person2 = portal.person_module.newContent(portal_type=\'Person\',\n
                                          title=howto_dict[\'incoming_event_howto_person2_title\'],\n
                                          career_subordination_title=howto_dict[\'incoming_event_howto_organisation_title\'],\n
                                          default_email_text=howto_dict[\'incoming_event_howto_person2_email\'])\n
person2.validate()\n
\n
campaign = portal.campaign_module.newContent(portal_type=\'Campaign\',\n
                                             title=howto_dict[\'incoming_event_howto_campaign_title\'],\n
                                             reference=howto_dict[\'incoming_event_howto_campaign_reference\'],\n
                                             resource=\'service_module/marketing_sales\',\n
                                             source_section=organisation.getRelativeUrl(),\n
                                             source_decision=person.getRelativeUrl(),\n
                                             source=person2.getRelativeUrl(),\n
                                             destination=organisation.getRelativeUrl(),\n
                                             source_trade_list=[person.getRelativeUrl()],\n
                                             quantity_unit=\'time/day\',\n
                                             start_date=\'2000/10/10\',\n
                                             stop_date=\'3000/10/10\',\n
                                             quantity=9,\n
                                             price=20,\n
                                             price_currency=currency.getRelativeUrl())\n
campaign.validate()\n
\n
service = getattr(portal.service_module, howto_dict[\'incoming_event_howto_service_id\'], None)\n
if service is None:\n
  service = portal.service_module.newContent(portal_type=\'Service\',\n
                                             id=howto_dict[\'incoming_event_howto_service_id\'],\n
                                             title=howto_dict[\'incoming_event_howto_service_title\'])\n
  service.setUseValue(getattr(portal.portal_categories.use, howto_dict[\'incoming_event_howto_service_id\']))\n
  service.validate()\n
\n
system_preference_id = \'test_functional_system_preference\'\n
system_preference = getattr(portal.portal_preferences, system_preference_id, None)\n
if system_preference is None:\n
  system_preference = portal.portal_preferences.newContent(portal_type=\'System Preference\',\n
                                                           id=system_preference_id)\n
\n
if isTransitionPossible(system_preference, \'enable\'):\n
  system_preference.enable()\n
\n
system_preference.setPreferredEventResourceList([service.getRelativeUrl()])\n
system_preference.setPreferredEventUseList([howto_dict[\'incoming_event_howto_service_id\']])\n
\n
pref = getattr(context.portal_preferences, howto_dict[\'howto_preference_id\'], None)\n
if pref is None:\n
  pref = context.portal_preferences.newContent(portal_type="Preference",\n
                                               id=howto_dict[\'howto_preference_id\'])\n
\n
if isTransitionPossible(pref, \'enable\'):\n
  pref.enable()\n
\n
pref.setPriority(3)\n
pref.setPreferredTextEditor(\'text_area\')\n
\n
context.portal_caches.clearAllCache()\n
\n
return "Init Ok"\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>clean=True</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Zuite_setUpIncomingEventTest</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
