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
            <value> <string encoding="cdata"><![CDATA[

portal = context.getPortalObject()\n
hmac = portal.Base_getHMACHexdigest(key=portal.Base_getEventHMACKey(), message=event_value.getId())\n
\n
def getSubstitutionMappingDict():\n
  destination = event_value.getDestinationValue()\n
  kw[\'event_value_source_title\'] = event_value.getSourceTitle()\n
\n
  if destination is not None:\n
    kw[\'third_party_reference\'] = destination.getDestinationReference()\n
    kw[\'address\'] = (destination.getDefaultAddressText() or \'\').upper()\n
    kw[\'email\'] = destination.getDefaultEmailText() or \'\'\n
    kw[\'telephone\'] = destination.getDefaultTelephoneText() or \'\'\n
    kw[\'mobile\'] = destination.getMobileTelephoneText() or \'\'\n
    kw[\'creation_date\'] = destination.getCreationDate()\n
\n
    if destination.getPortalType() == \'Person\':\n
      kw[\'first_name\'] = destination.getFirstName()\n
      kw[\'last_name\'] = destination.getLastName()\n
      kw[\'social_title\'] = destination.getSocialTitleTranslatedTitle("")\n
      kw[\'third_party_name\'] = destination.getTitle()\n
      if destination.getSocialTitle():\n
        kw[\'third_party_name\'] = "%s %s" % (destination.getSocialTitleTranslatedTitle() or \'\',\n
                                                    destination.getTitle())\n
    elif destination.getPortalType() == \'Organisation\':\n
      kw[\'social_title\'] = str(portal.Base_translateString("Participant"))\n
      kw[\'third_party_name\'] = destination.getCorporateName() or destination.getTitle()\n
\n
\n
    # Backward compatibility\n
    kw["destination_title"] = destination.getTitle()\n
    kw["destination_portal_type"] = destination.getTranslatedPortalType()\n
    kw["destination_social_title"] = destination.getProperty(\'social_title_translated_title\')\n
    kw["destination_reference"] = destination.getReference()\n
  else:\n
    kw["destination_title"] = ""\n
    kw["destination_portal_type"] = ""\n
    kw["destination_social_title"] = ""\n
    kw["destination_reference"] = ""\n
\n
  kw[\'event_value_start_date\'] = event_value.getStartDate()\n
  kw[\'event_value_nature\'] = event_value.getResourceReference()\n
  kw[\'event_value_reference\'] = event_value.getReference()\n
  kw[\'ticket_reference\'] = event_value.getDefaultFollowUpReference()\n
  hmac = portal.Base_getHMACHexdigest(key=portal.Base_getEventHMACKey(), message=event_value.getId())\n
  kw["image_parameters"] = "/Base_openEvent?id=%s&hash=%s" %(event_value.getId(), hmac)\n
  kw["newsletter_parameters"] = "/Base_readEvent?id=%s&hash=%s" %(event_value.getId(), hmac)\n
  kw["unsubscribe_parameters"] = "/Base_unsubscribeFromEvent?id=%s&hash=%s" %(event_value.getId(), hmac)\n
\n
  # Backward compatibility\n
  kw["source_title"] = event_value.getSourceTitle() or \'\',\n
  kw["document_parameters"] = "/Base_readEvent?id=%s&hash=%s" %(event_value.getId(), hmac),\n
\n
\n
  return kw\n
\n
if context.hasLanguage():\n
  with context.getPortalObject().Localizer.translationContext(context.getLanguage()):\n
    return getSubstitutionMappingDict()\n
return getSubstitutionMappingDict()\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>event_value, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>NotificationMessage_getSubstitutionMappingDictFromEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
