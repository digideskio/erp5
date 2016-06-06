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
request = context.REQUEST\n
\n
# display only title line instead of description\n
use_line_title =  request.get(\'use_line_title\', 0)\n
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
def getProductAndLineDesc(prod_desc, line_desc):\n
  line_list = []\n
  if line_desc:\n
    line_list.extend(getFieldAsLineList(line_desc))\n
  elif prod_desc:\n
    line_list.extend(getFieldAsLineList(prod_desc))\n
  return line_list\n
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
def getEmail(email):\n
  s = \'\'\n
  if email:\n
    s += \'%s: %s\' % (translateString(\'Email\'), email)\n
  return s\n
\n
def getVatId(vat_id):\n
  s = \'\'\n
  if vat_id:\n
    s += \'%s: %s\' % (translateString(\'VAT ID\'), vat_id)\n
  return s\n
\n
def getCorporateRegCode(reg_code):\n
  s = \'\'\n
  if reg_code:\n
    s += \'%s: %s\' % (translateString(\'Corporate Registration Code\'), reg_code)\n
  return s\n
\n
def getSocialCapital(reg_cap):\n
  s = \'\'\n
  if reg_cap:\n
    s += \'%s: %s€\' % (translateString(\'Social Capital\'), reg_cap)\n
  return s\n
\n
preferred_date_order = context.getPortalObject().portal_preferences\\\n
                                          .getPreferredDateOrder() or \'ymd\'\n
separator = \'/\'\n
def getOrderedDate(date):\n
  if date is None:\n
    return \'\'\n
  pattern = separator.join([\'%%%s\' % s for s in list(preferred_date_order)])\n
  pattern = pattern.replace(\'y\', \'Y\')\n
  return date.strftime(pattern)\n
\n
def getPaymentConditionText(order):\n
  if \'custom\' == order.getPaymentConditionTradeDate():\n
    return getOrderedDate(order.getPaymentConditionPaymentDate())\n
  end_of_month = order.getPaymentConditionPaymentEndOfMonth()\n
  days = order.getPaymentConditionPaymentTerm()\n
  if days:\n
    if end_of_month:\n
      return translateString("${days} Days End of Month", mapping=dict(days=days))\n
    return translateString("${days} Days", mapping=dict(days=days))\n
  elif end_of_month:\n
    return translateString("End of Month") \n
  return getOrderedDate(order.getStartDate())\n
\n
def getTaxLineList(order):\n
  tax_line_list = [line for line in\n
       order.contentValues(portal_type=order.getPortalTaxMovementTypeList())\n
       if line.getTotalPrice()]\n
  tax_line_list.sort(key=lambda line:line.getTitle())\n
  return tax_line_list\n
\n
line_base_contribution_list = []\n
number = 0\n
tax_free_line_totalprice = 0\n
line_list = []\n
line_not_tax = []\n
line_tax = []\n
line_tax_no_rate = {}\n
total_price = 0.0\n
total_tax_price = 0.0\n
number_line_not_tax = 0\n
\n
def unicodeDict(d):\n
  for k, v in d.items():\n
    if isinstance(v, str):\n
      d.update({k:unicode(v, \'utf8\')})\n
  return d\n
\n
\n
for line in getSubLineList(context):\n
  prod_desc = line.getResource() is not None and \\\n
           line.getResourceValue().getDescription() or (\n
    request.get(\'international_form\') and line.getResourceTitle() or line.getResourceTranslatedTitle() )\n
  if use_line_title:\n
    desc = (line.getTitle(), )\n
  else:\n
    desc = getProductAndLineDesc(prod_desc, line.getDescription())\n
  if getattr(line, \'hasLineContent\', None) is not None\\\n
        and line.hasLineContent()\\\n
        or getattr(line, \'hasCellContent\', None) is not None\\\n
        and line.hasCellContent():\n
    # summary\n
    line_dict = {\n
      \'style_name\': \'Item_20_Table_20_Title\',\n
      \'left_style_name\': \'Item_20_Table_20_Title_20_Left\',\n
      \'right_style_name\': \'Item_20_Table_20_Title_20_Right\',\n
      \'index\': line.getReference() or line.getIntIndex(),\n
      \'source_reference\': getSourceReference(line),\n
      \'reference\': line.getResource() is not None\\\n
                      and line.getResourceValue().getReference() or \'\',\n
      \'description\': desc,\n
      \'total_quantity\': \'\',\n
      \'quantity_unit\': \'\',\n
      \'stop_date\': \'\',\n
      \'base_price\': \'\',\n
      \'total_price\': \'\',\n
      \'specialise_title\': \'\',\n
    }\n
  else:\n
    if line.getPortalType().endswith(\'Cell\'):\n
      display_id = \'translated_title\'\n
      if request.get(\'international_form\'):\n
        display_id = \'title\'\n
      variation_description = \', \'.join([x[0] for x in line.getVariationCategoryItemList(display_id=display_id)])\n
      desc = (\'%s %s\' % (desc[0], variation_description), )\n
    is_tax = 0\n
    for tax_use in (context.getPortalObject().portal_preferences.getPreferredTaxUseList() or ["use/trade/tax"]):\n
      if line.isMemberOf(tax_use):\n
        is_tax = 1\n
        break\n
\n
    #set the not_tax_line with the tax_number and the tax_line with the tax_name\n
    tax_number=\'\'\n
    tax_name=\'\'\n
    if not is_tax:\n
      if line.getBaseContributionList()==[]:\n
        tax_number=\'0\'\n
      else:\n
        for contribution in line.getBaseContributionList():\n
          if contribution not in line_base_contribution_list:\n
            line_base_contribution_list.append(contribution)\n
          if tax_number==\'\':\n
            tax_number=str(line_base_contribution_list.index(contribution)+1)\n
          else:\n
            tax_number=tax_number+\',\'+str(line_base_contribution_list.index(contribution)+1)\n
    else:\n
      tax_name=line.getBaseApplication()\n
    line_dict = {\n
      \'style_name\': \'Table_20_Contents\',\n
      \'left_style_name\': \'Table_20_Contents_20_Left\',\n
      \'right_style_name\': \'Table_20_Contents_20_Right\',\n
      \'index\': line.getReference() or line.getIntIndex(),\n
      \'source_reference\': getSourceReference(line),\n
      \'reference\': line.getResource() is not None\\\n
                      and line.getResourceValue().getReference() or \'\',\n
      \'description\': desc,\n
      \'base_contribution\':line.getBaseContribution() or None,\n
      \'use_type\':line.getResourceValue().getUse() or \'\',\n
      \'use_type_tax\':is_tax,\n
      \'total_quantity\': line.getTotalQuantity() or \'\',\n
      \'tax_name\':tax_name or \'\',\n
      \'tax_number\':tax_number or \'\',\n
      \'quantity_unit\': line.getQuantityUnitTranslatedTitle() or (\n
        line.getResource() and line.getResourceValue().getQuantityUnitTranslatedTitle()) or \'\',\n
      \'stop_date\': getOrderedDate(line.getStopDate()) or \'\',\n
      \'base_price\': line.getPrice() or \'\',\n
      \'total_price\': line.getTotalPrice() or 0,\n
      \'specialise_title\' : line.getProperty(\'specialise_title\', \'\'),\n
    }\n
\n
    if line_dict[\'use_type_tax\']:\n
      if line.getQuantity():\n
        total_tax_price+=line.getTotalPrice() or 0.0\n
        line_tax.append(unicodeDict(line_dict.copy()))\n
    else:\n
      number_line_not_tax = number_line_not_tax+1\n
      line_dict[\'number_not_tax_line\'] = number_line_not_tax\n
      total_price += line.getTotalPrice() or 0.0\n
      line_not_tax.append(unicodeDict(line_dict.copy()))\n
      #if one line of product hasn\'t tax, the tax table need to add a taxrate=0 line\n
      if line_dict[\'base_contribution\'] is None:\n
        tax_free_line_totalprice = tax_free_line_totalprice + line_dict[\'total_price\']\n
        line_tax_no_rate = {\n
            \'tax_name\': None ,\n
            \'total_quantity\': tax_free_line_totalprice,\n
            \'base_price\':  0.00 ,\n
            \'total_price\': 0.00 ,\n
        }\n
  line_list.append(unicodeDict(line_dict.copy()))\n
if line_tax_no_rate != {} :\n
  line_tax.append(unicodeDict(line_tax_no_rate.copy()))\n
for line_each in line_tax:\n
  if line_each[\'tax_name\'] in line_base_contribution_list :\n
    number_tax_line=line_base_contribution_list.index(line_each[\'tax_name\'])+1\n
  else:\n
    number_tax_line=0\n
  line_each.update({\'number_tax_line\': number_tax_line})\n
line_tax.sort(key=lambda obj:obj.get(\'number_tax_line\'))\n
\n
inch_cm_ratio = 2.54 / 100.0\n
\n
class EmptyOrganisation:\n
  """Used for default when organisation is not found.\n
  """\n
  def getTitle(self):\n
    return \'\'\n
  def getDefaultAddressText(self):\n
    return \'\'\n
  def getDefaultAddressRegionTitle(self):\n
    return \'\'\n
  def getTelephoneText(self):\n
    return \'\'\n
  def getFaxText(self):\n
    return \'\'\n
  def getEmailText(self):\n
    return \'\'\n
  def getDefaultImagePath(self):\n
    return \'\'\n
  def getDefaultImageHeight(self):\n
    return 0\n
  def getDefaultImageWidth(self):\n
    return 0\n
  def getProperty(self, prop, d=\'\'):\n
    return d\n
\n
source = context.getSourceValue()\n
if source is None:\n
  source = EmptyOrganisation()\n
\n
destination = context.getDestinationValue()\n
if destination is None:\n
  destination = EmptyOrganisation()\n
\n
source_section = context.getSourceSectionValue()\n
if source_section is None:\n
  source_section = EmptyOrganisation()\n
\n
destination_section = context.getDestinationSectionValue()\n
if destination_section is None:\n
  destination_section = EmptyOrganisation()\n
\n
source_administration = context.getSourceAdministrationValue(\n
                              portal_type=\'Organisation\')\n
if source_administration is None:\n
  source_administration = context.getSourceSectionValue()\n
if source_administration is None:\n
  source_administration = EmptyOrganisation()\n
\n
destination_administration = context.getDestinationAdministrationValue(\n
                              portal_type=\'Organisation\')\n
if destination_administration is None:\n
  destination_administration = context.getDestinationSectionValue()\n
if destination_administration is None:\n
  destination_administration = EmptyOrganisation()\n
\n
source_decision = context.getSourceDecisionValue()\n
if source_decision is None:\n
  source_decision = EmptyOrganisation()\n
\n
destination_decision = context.getDestinationDecisionValue()\n
if destination_decision is None:\n
  destination_decision = EmptyOrganisation()\n
\n
if context.getPortalType() in context.getPortalObject().getPortalOrderTypeList():\n
  report_title = context.getSimulationState() == "draft" and "Draft Order" or "Order"\n
else:\n
  report_title = context.getSimulationState() == "draft" and "Draft Packing List" or "Packing List"\n
  \n
data_dict = {\n
  \'report_title\' : report_title,\n
  \'source_section_title\': source_section.getProperty(\'corporate_name\') or\\\n
                            source_section.getTitle(),\n
  \'source_section_image_path\': source_section.getDefaultImagePath() or \'\',\n
  \'source_section_image_width\': source_section.getDefaultImageWidth() is not None\\\n
          and source_section.getDefaultImageWidth() \\\n
              * inch_cm_ratio or \'\',\n
  \'source_section_image_height\': source_section.getDefaultImageHeight() is not None\\\n
          and source_section.getDefaultImageHeight() \\\n
              * inch_cm_ratio or \'\',\n
  \'source_section_address\': getOneLineAddress(\n
          source_section.getDefaultAddressText() or \'\',\n
          source_section.getDefaultAddressRegionTitle() or \'\'),\n
  \'source_section_telfax\': getPhoneAndFax(source_section.getTelephoneText() or \'\',\n
          source_section.getFaxText() or \'\'),\n
  \'source_section_email\': getEmail(source_section.getEmailText() or \'\'),\n
  \'source_section_vatid\': getVatId(getattr(source_section, \'getVatCode\', None)\\\n
                           is not None and\\\n
                           source_section.getVatCode() or \'\'),\n
  \'source_section_corporateregcode\': getCorporateRegCode(getattr(source_section, \'getCorporateRegistrationCode\', None)\\\n
                           is not None and\\\n
                           source_section.getCorporateRegistrationCode() or \'\'),\n
  \'source_section_registeredcapital\': getSocialCapital(getattr(source_section, \'getSocialCapital\', None)\\\n
                           is not None and\\\n
                           source_section.getSocialCapital() or \'\'),\n
                          \n
  \'source_administration_title\': \\\n
      source_administration.getProperty(\'corporate_name\') \\\n
      or source_administration.getTitle(),\n
  \'source_administration_address\': getOneLineAddress(\n
                                      source_administration.getDefaultAddressText(),\n
                                      source_administration.getDefaultAddressRegionTitle()),\n
  \'source_administration_telfax\':\n
          getPhoneAndFax(source_administration.getProperty(\'telephone_text\', \'\'),\n
                         source_administration.getProperty(\'fax_text\', \'\')),\n
  \'source_administration_email\':\n
          getEmail(source_administration.getProperty(\'email_text\', \'\')),\n
  \'source_administration_vatid\':\n
          getVatId(source_administration.getProperty(\'vat_code\', \'\')),\n
  \'source_administration_registeredcapital\':\n
          getSocialCapital(source_administration.getProperty(\'social_capital\', \'\')),\n
  \'source_administration_corporateregcode\':\n
          getCorporateRegCode(source_administration.getProperty(\'corporate_registration_code\', \'\')),\n
\n
  \'source_title\': source.getProperty(\'corporate_name\') or source.getTitle(),\n
  \'source_address\': getOneLineAddress(\n
          source.getDefaultAddressText() or \'\',\n
          source.getDefaultAddressRegionTitle() or \'\'),\n
  \'source_telfax\': getPhoneAndFax(source.getTelephoneText() or \'\',\n
          source.getFaxText() or \'\'),\n
  \'source_email\': getEmail(source.getEmailText() or \'\'),\n
  \'source_vatid\': getVatId(source.getProperty(\'vat_code\', \'\') or \'\'),\n
\n
  \'source_decision_title\': context.getSourceDecisionTitle() or \'\',\n
  \'source_decision_image_path\': context.getSourceDecisionValue(portal_type=\'Organisation\') is not None\\\n
          and context.getSourceDecisionValue(portal_type=\'Organisation\').getDefaultImagePath() or \'\',\n
  \'source_decision_image_width\': context.getSourceDecisionValue(portal_type=\'Organisation\') is not None\\\n
          and context.getSourceDecisionValue(portal_type=\'Organisation\').getDefaultImageWidth() is not None\\\n
          and context.getSourceDecisionValue(portal_type=\'Organisation\').getDefaultImageWidth() \\\n
              * inch_cm_ratio or \'\',\n
  \'source_decision_image_height\': context.getSourceDecisionValue(portal_type=\'Organisation\') is not None\\\n
          and context.getSourceDecisionValue(portal_type=\'Organisation\').getDefaultImageHeight() is not None\\\n
          and context.getSourceDecisionValue(portal_type=\'Organisation\').getDefaultImageHeight() \\\n
              * inch_cm_ratio or \'\',\n
  \'source_decision_address\':getOneLineAddress(\n
          source_decision is not None and \n
              source_decision.getDefaultAddressText() or \'\',\n
          source_decision is not None and \\\n
              source_decision.getDefaultAddressRegionTitle() or \'\'),\n
  \'source_decision_telfax\': getPhoneAndFax(source_decision is not None and\n
          source_decision.getTelephoneText() or \'\',\n
      source_decision is not None and \\\n
          source_decision.getFaxText() or \'\'),\n
  \'source_decision_email\': getEmail(source_decision is not None and\n
      source_decision.getEmailText() or \'\'),\n
  \'source_decision_vatid\': getVatId(source_decision is not None and\\\n
                           getattr(source_decision, \'getVatCode\', None)\\\n
                           is not None and\\\n
                           source_decision.getVatCode() or \'\'),\n
\n
  \'destination_title\': destination.getProperty(\'corporate_name\') or destination.getTitle(),\n
  \'destination_address\': getOneLineAddress(\n
      destination.getDefaultAddressText() or \'\',\n
      destination.getDefaultAddressRegionTitle() or \'\'),\n
  \'destination_telfax\': getPhoneAndFax(destination.getTelephoneText() or \'\',\n
      destination.getFaxText() or \'\'),\n
  \'destination_email\': getEmail(destination.getEmailText() or \'\'),\n
  \'destination_vatid\': getVatId(destination.getProperty(\'vat_code\', \'\') or \'\'),\n
\n
  \'destination_section_title\': destination_section.getProperty(\'corporate_name\') or \\\n
                                  destination_section.getTitle(),\n
  \'destination_section_image_path\': destination_section.getDefaultImagePath(),\n
  \'destination_section_image_width\': destination_section.getDefaultImageWidth() is not None\\\n
      and destination_section.getDefaultImageWidth() * inch_cm_ratio or \'\',\n
  \'destination_section_image_height\': destination_section.getDefaultImageHeight() is not None\\\n
      and destination_section.getDefaultImageHeight() * inch_cm_ratio or \'\',\n
  \'destination_section_address\': getOneLineAddress(\n
      destination_section.getDefaultAddressText() or \'\',\n
      destination_section.getDefaultAddressRegionTitle() or \'\'),\n
  \'destination_section_telfax\': getPhoneAndFax(\n
      destination_section.getTelephoneText() or \'\',\n
      destination_section.getFaxText() or \'\'),\n
  \'destination_section_email\': getEmail(destination_section.getEmailText() or \'\'),\n
  \'destination_section_vatid\': getVatId(getattr(destination_section, \'getVatCode\', None)\\\n
                           is not None and\\\n
                           destination_section.getVatCode() or \'\'),\n
\n
  \'destination_administration_title\':\\\n
    destination_administration.getProperty(\'corporate_name\') or \\\n
                                destination_administration.getTitle(),\n
  \'destination_administration_address\': getOneLineAddress(\n
                                      destination_administration.getDefaultAddressText(),\n
                                      destination_administration.getDefaultAddressRegionTitle()),\n
  \'destination_administration_telfax\':\n
          getPhoneAndFax(destination_administration.getProperty(\'telephone_text\', \'\'),\n
                         destination_administration.getProperty(\'fax_text\', \'\')),\n
  \'destination_administration_email\':\n
          getEmail(destination_administration.getProperty(\'email_text\', \'\')),\n
  \'destination_administration_vatid\':\n
          getVatId(destination_administration.getProperty(\'vat_code\', \'\')),\n
  \'destination_administration_registeredcapital\':\n
          getSocialCapital(destination_administration.getProperty(\'social_capital\', \'\')),\n
  \'destination_administration_corporateregcode\':\n
          getCorporateRegCode(destination_administration.getProperty(\'corporate_registration_code\', \'\')),\n
\n
  \'destination_decision_title\': context.getDestinationDecisionTitle() or \'\',\n
  \'destination_decision_telfax\': getPhoneAndFax(destination_decision.getTelephoneText() or \'\',\n
      destination_decision.getFaxText() or \'\'),\n
  \'destination_decision_email\': getEmail(destination_decision.getEmailText() or \'\'),\n
\n
  \'reference\': context.getReference() or \'\',\n
  \'start_date\': getOrderedDate(context.getStartDate()) or \'\',\n
  \'stop_date\': getOrderedDate(context.getStopDate()) or \'\',\n
  \'creation_date\': getOrderedDate(context.getCreationDate()) or \'\',\n
  \'currency\': context.getPriceCurrencyReference() or \'\',\n
  \'payment_condition\': getPaymentConditionText(context),\n
  \'delivery_mode\': context.getDeliveryModeTranslatedTitle() or \'\',\n
  \'incoterm\': context.getIncoterm() and context.getIncotermValue().getCodification() or \'\',\n
  \'total_price\':total_price+total_tax_price,\n
  \'total_price_exclude_tax\': total_price,\n
  \'total_tax_price\':total_tax_price,\n
  \'total_price_novat\': total_price, # BBB\n
  \'vat_list\': getTaxLineList(context), # BBB\n
  \'vat_total_price\':total_tax_price, # BBB\n
  \'description\': getFieldAsLineList(context.getDescription()),\n
  \'specialise_title\': context.getProperty(\'specialise_title\',\'\'),\n
  \'line_tax\':line_tax,\n
  \'line_not_tax\':line_not_tax,\n
  \'line_list\': line_list,\n
}\n
\n
return unicodeDict(data_dict)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>getSourceReference, getSubLineList</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Delivery_getODTDataDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
