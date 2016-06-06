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
            <value> <string>from Products.PythonScripts.standard import Object\n
line_list = []\n
request = context.REQUEST\n
portal = context.getPortalObject()\n
portal_selections = portal.portal_selections\n
selection_name = \'accounting_selection\'\n
selection_params = portal_selections.getSelectionParamsFor(selection_name)\n
\n
section_category = selection_params.get(\'section_category\')\n
section_category_strict = selection_params.get(\'section_category_strict\')\n
\n
\n
def isSource(accounting_transaction):\n
  if section_category:\n
    source_section = accounting_transaction.getSourceSectionValue()\n
    if source_section is None:\n
      return False\n
    group = source_section.getGroup(base=True)\n
    if section_category_strict:\n
      return group == section_category\n
    return (group or \'\').startswith(section_category)\n
  return accounting_transaction.AccountingTransaction_isSourceView()\n
\n
def isDestination(accounting_transaction):\n
  if section_category:\n
    destination_section = accounting_transaction.getDestinationSectionValue()\n
    if destination_section is None:\n
      return False\n
    group = destination_section.getGroup(base=True)\n
    if section_category_strict:\n
      return group == section_category\n
    return (group or \'\').startswith(section_category)\n
  return accounting_transaction.AccountingTransaction_isDestinationView()\n
\n
\n
if section_category:\n
  currency = portal.Base_getCurrencyForSection(section_category)\n
  request.set(\'currency\', currency)\n
  request.set(\'precision\',\n
      portal.account_module.getQuantityPrecisionFromResource(currency))\n
\n
checked_uid_list = \\\n
    portal_selections.getSelectionCheckedUidsFor(selection_name)\n
if checked_uid_list:\n
  getObject = portal.portal_catalog.getObject\n
  delivery_list = [getObject(uid) for uid in checked_uid_list]\n
else:\n
  params = portal_selections.getSelectionParamsFor(selection_name)\n
  params[\'limit\'] = None # XXX potentially very big report\n
  delivery_list = portal_selections.callSelectionFor(\n
                                        selection_name,\n
                                        context=context,\n
                                        params=params)\n
\n
\n
account_reference_cache = {}\n
def getAccountReference(node):\n
  try:\n
    return account_reference_cache[node]\n
  except KeyError:\n
    if node is not None:\n
      reference = node.Account_getGapId()\n
    else:\n
      reference = \'\'\n
    account_reference_cache[node] = reference\n
    return reference\n
\n
def getTitle(document):\n
  if document is not None:\n
    return document.getTranslatedTitle()\n
  return \'\'\n
\n
bank_account_title_cache = {}\n
def getBankAccountTitle(bank_account):\n
  try:\n
    return bank_account_title_cache[bank_account]\n
  except KeyError:\n
    pass\n
\n
  if bank_account is not None:\n
    reference = bank_account.getReference()\n
    title = bank_account.getTitle()\n
    if reference and reference != title:\n
      value = "%s - %s" % (reference, title)\n
    else:\n
      value = title\n
  else:\n
    value = \'\'\n
  bank_account_title_cache[bank_account] = value\n
  return value\n
\n
accounting_currency_reference_cache = {}\n
def getAccountingCurrencyReference(section_relative_url):\n
  try:\n
    return accounting_currency_reference_cache[section_relative_url]\n
  except KeyError:\n
    reference = \'\'\n
    if section_relative_url:\n
      section = portal.restrictedTraverse(section_relative_url, None)\n
      if section is not None:\n
        reference = section.getProperty(\'price_currency_reference\')\n
    accounting_currency_reference_cache[section_relative_url] = reference\n
    return reference\n
\n
\n
portal_type = context.getPortalAccountingMovementTypeList()\n
\n
displayed_delivery_dict = {}\n
for delivery in delivery_list:\n
  if delivery.uid in displayed_delivery_dict: continue\n
  displayed_delivery_dict[delivery.uid] = True\n
  delivery = delivery.getObject()\n
  is_source = isSource(delivery)\n
  is_destination = isDestination(delivery)\n
\n
  for movement in delivery.getMovementList(portal_type=portal_type):\n
\n
    if is_source:\n
      node = movement.getSourceValue(portal_type=\'Account\')\n
      node_title = \'\'\n
      node_account_type_title = \'\'\n
      node_financial_section_title = \'\'\n
      if node is not None:\n
        node_title = node.getTranslatedTitle()\n
        node_account_type_title = node.getAccountTypeTranslatedTitle()\n
        node_financial_section_title = \\\n
          node.getFinancialSectionTranslatedTitle()\n
\n
        line_list.append(Object(\n
        title=movement.hasTitle() and movement.getTitle() or\n
                     delivery.getTitle(),\n
        int_index=movement.getIntIndex(),\n
        string_index=movement.getStringIndex(),\n
        parent_description=delivery.getDescription(),\n
        parent_comment=delivery.getComment(),\n
        parent_reference=delivery.getReference(),\n
        specific_reference=delivery.getSourceReference(),\n
        node_reference=getAccountReference(node),\n
        node_title=node_title,\n
        node_account_type_title=node_account_type_title,\n
        node_financial_section_title=node_financial_section_title,\n
        section_title=movement.getSourceSectionTitle(),\n
        payment_title=getBankAccountTitle(movement.getSourcePaymentValue()),\n
        payment_mode=movement.getPaymentModeTranslatedTitle(),\n
        mirror_section_title=movement.getDestinationSectionTitle(),\n
        mirror_payment_title=getBankAccountTitle(movement.getDestinationPaymentValue()),\n
        mirror_section_region_title=movement.getDestinationSection() and\n
          movement.getDestinationSectionValue().getRegionTranslatedTitle(),\n
        function_title=getTitle(movement.getSourceFunctionValue()),\n
        function_reference=movement.getSourceFunctionReference(),\n
        project_title=getTitle(movement.getSourceProjectValue()),\n
        funding_title=getTitle(movement.getSourceFundingValue()),\n
        funding_reference=movement.getSourceFundingReference(),\n
        product_line=movement.getProductLineTranslatedTitle(),\n
        date=movement.getStartDate(),\n
        debit_price=movement.getSourceInventoriatedTotalAssetDebit(),\n
        credit_price=movement.getSourceInventoriatedTotalAssetCredit(),\n
        price=(movement.getSourceInventoriatedTotalAssetCredit() - movement.getSourceInventoriatedTotalAssetDebit()),\n
        currency=getAccountingCurrencyReference(movement.getSourceSection()),\n
        debit=movement.getSourceDebit(),\n
        credit=movement.getSourceCredit(),\n
        quantity=(movement.getSourceCredit() - movement.getSourceDebit()),\n
        resource=movement.getResourceReference(),\n
        quantity_precision=movement.getQuantityPrecisionFromResource(movement.getResource()),\n
        translated_portal_type=movement.getTranslatedPortalType(),\n
        parent_translated_portal_type=delivery.getTranslatedPortalType(),\n
        translated_simulation_state_title=movement.getTranslatedSimulationStateTitle(),))\n
\n
    if is_destination:\n
      node = movement.getDestinationValue(portal_type=\'Account\')\n
      node_title = \'\'\n
      node_account_type_title = \'\'\n
      node_financial_section_title = \'\'\n
      if node is not None:\n
        node_title = node.getTranslatedTitle()\n
        node_account_type_title = node.getAccountTypeTranslatedTitle()\n
        node_financial_section_title = \\\n
          node.getFinancialSectionTranslatedTitle()\n
\n
        line_list.append(Object(\n
        title=movement.hasTitle() and movement.getTitle() or\n
                     delivery.getTitle(),\n
        int_index=movement.getIntIndex(),\n
        string_index=movement.getStringIndex(),\n
        parent_description=delivery.getDescription(),\n
        parent_comment=delivery.getComment(),\n
        parent_reference=delivery.getReference(),\n
        specific_reference=delivery.getDestinationReference(),\n
        node_reference=getAccountReference(node),\n
        node_title=node_title,\n
        node_account_type_title=node_account_type_title,\n
        node_financial_section_title=node_financial_section_title,\n
        section_title=movement.getDestinationSectionTitle(),\n
        payment_title=getBankAccountTitle(movement.getDestinationPaymentValue()),\n
        payment_mode=movement.getPaymentModeTranslatedTitle(),\n
        mirror_section_title=movement.getSourceSectionTitle(),\n
        mirror_section_region_title=movement.getSourceSection() and\n
          movement.getSourceSectionValue().getRegionTranslatedTitle(),\n
        mirror_payment_title=getBankAccountTitle(movement.getSourcePaymentValue()),\n
        function_title=getTitle(movement.getDestinationFunctionValue()),\n
        function_reference=movement.getDestinationFunctionReference(),\n
        funding_title=getTitle(movement.getDestinationFundingValue()),\n
        funding_reference=movement.getDestinationFundingReference(),\n
        project_title=getTitle(movement.getDestinationProjectValue()),\n
        product_line=movement.getProductLineTranslatedTitle(),\n
        date=movement.getStopDate(),\n
        debit_price=movement.getDestinationInventoriatedTotalAssetDebit(),\n
        credit_price=movement.getDestinationInventoriatedTotalAssetCredit(),\n
        price=(movement.getDestinationInventoriatedTotalAssetCredit() - movement.getDestinationInventoriatedTotalAssetDebit()),\n
        currency=getAccountingCurrencyReference(movement.getDestinationSection()),\n
        debit=movement.getDestinationDebit(),\n
        credit=movement.getDestinationCredit(),\n
        quantity=(movement.getDestinationCredit() - movement.getDestinationDebit()),\n
        resource=movement.getResourceReference(),\n
        quantity_precision=movement.getQuantityPrecisionFromResource(movement.getResource()),\n
        translated_portal_type=movement.getTranslatedPortalType(),\n
        parent_translated_portal_type=delivery.getTranslatedPortalType(),\n
        translated_simulation_state_title=movement.getTranslatedSimulationStateTitle(),))\n
\n
\n
return line_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_getAccountingLineReportLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
