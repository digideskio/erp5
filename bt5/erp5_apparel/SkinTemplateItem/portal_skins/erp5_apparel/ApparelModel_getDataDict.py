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
            <value> <string>translateString = context.Base_translateString\n
portal = context.getPortalObject()\n
portal_preferences = portal.portal_preferences\n
\n
def getFieldAsString(field):\n
  return \', \'.join(getFieldAsLineList(field))\n
\n
def getFieldAsLineList(field):\n
  """Returns the text as a list of lines."""\n
  field = field or \'\'\n
  text = field.replace(\'\\r\', \'\')\n
  text_list = text.split(\'\\n\')\n
  return [x for x in text_list if x]\n
\n
def getOneLineAddress(text, region):\n
  text_list = [getFieldAsString(text)]\n
  if region:\n
    text_list.append(region)\n
  return \', \'.join(text_list)\n
\n
def getPhoneAndFax(phone, fax):\n
  s = \'\'\n
  if phone:\n
    s += \'%s: %s\' % (translateString(\'Tel\'), phone)\n
  if fax:\n
    if s: s += \', \'\n
    s += \'%s: %s\' % (translateString(\'Fax\'), fax)\n
  return s\n
\n
def getPreferredOrganisation():\n
  organisation = None\n
  organisation_url = portal_preferences.getPreferredSection()\n
  if organisation_url:\n
    organisation = portal.restrictedTraverse(organisation_url)\n
  return organisation\n
\n
def getDelayTitle():\n
  if not context.getSaleSupplyLineMinDelay() and not context.getSaleSupplyLineMaxDelay():\n
    return None\n
  return translateString(\'${begin} to ${end} Weeks\',\n
      mapping=dict(begin=int(context.getSaleSupplyLineMinDelay()/7.) or 0,\n
                   end=int(context.getSaleSupplyLineMaxDelay()/7.) or 0))\n
\n
def getMorphologyTitle():\n
  apparel_morphology_list = context.contentValues(portal_type=\'Apparel Model Morphology Variation\')\n
  apparel_morphology_title_list = [x.getTitle() for x in apparel_morphology_list]\n
  return \', \'.join(apparel_morphology_title_list)\n
\n
def getShapeMainImagePath():\n
  apparel_shape = context.getSpecialiseValue(portal_type=\'Apparel Shape\')\n
  if apparel_shape:\n
    technical_drawing_list = apparel_shape.contentValues(portal_type=\'Apparel Technical Drawing\')\n
    if len(technical_drawing_list):\n
      return technical_drawing_list[0].absolute_url()\n
  return None\n
\n
def getPrototype():\n
  for colour_variation in context.contentValues(portal_type=\'Apparel Model Colour Variation\'):\n
    if colour_variation.isPrototype():\n
      return colour_variation\n
  return None\n
\n
def unicodeDict(d):\n
  for k, v in d.items():\n
    if isinstance(v, str):\n
      d.update({k:unicode(v, \'utf8\')})\n
  return d\n
\n
data_dict = {\n
  \'delay_title\': getDelayTitle() or \'\',\n
  \'morphology_title\': getMorphologyTitle() or \'\',\n
  \'shape_main_image_path\': getShapeMainImagePath() or \'\',\n
  \'prototype_title\': getPrototype() is not None and \\\n
      getPrototype().getDestinationReference() or \'\',\n
  \'prototype_image_path\': getPrototype() is not None and getPrototype().absolute_url() or \'\',\n
  \'preferred_organisation_image_path\': getPreferredOrganisation() is not None\\\n
      and getPreferredOrganisation().getDefaultImageAbsoluteUrl() or \'\',\n
  \'preferred_organisation_corporate_name\': getPreferredOrganisation() is not None\\\n
      and (getPreferredOrganisation().getCorporateName() or\\\n
        getPreferredOrganisation().getTitle()) or \'\',\n
  \'preferred_organisation_address\': getOneLineAddress(\n
            getPreferredOrganisation() is not None and\\\n
              getPreferredOrganisation().getDefaultAddressText() or \'\',\n
            getPreferredOrganisation() is not None and\\\n
              getPreferredOrganisation().getDefaultAddressRegionTitle() or \'\'),\n
  \'preferred_organisation_telfax\': getPhoneAndFax(\n
            getPreferredOrganisation() is not None and\\\n
              getPreferredOrganisation().getTelephoneText() or \'\',\n
            getPreferredOrganisation() is not None and\\\n
              getPreferredOrganisation().getFaxText() or \'\'),\n
  }\n
\n
return data_dict\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ApparelModel_getDataDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
