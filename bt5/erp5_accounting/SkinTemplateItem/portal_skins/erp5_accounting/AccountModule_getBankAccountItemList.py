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
            <value> <string>"""Returns an item list of the acceptable bank accounts.\n
If `organisation` is passed, then we only show bank accounts available for that\n
organisation, using the following policy:\n
 - if organisation contains bank accounts directly, only those bank accounts\n
   can be selected\n
 - if organisation higher in the group hierarchy contains bank accounts, bank\n
   accounts from parent organisations can be selected\n
 - it means a higher in the group cannot use bank account from organisations\n
   below, maybe we\'ll want to change this ...\n
\n
If organisation is not passed, this script will return all bank accounts\n
applicable for section_category and section_category_strict_membership.\n
"""\n
portal = context.getPortalObject()\n
\n
search_kw = dict(portal_type=portal.getPortalPaymentNodeTypeList())\n
if skip_invalidated_bank_accounts:\n
  search_kw[\'validation_state\'] = \'!=invalidated\'\n
\n
if organisation:\n
  organisation_value = portal.restrictedTraverse(organisation)\n
\n
  # if organisation contains bank accounts, only take into account those.\n
  bank_account_list = organisation_value.searchFolder(**search_kw)\n
\n
    # else we lookup in parent organisations\n
  if not bank_account_list:\n
    group_value = organisation_value.getGroupValue(None)\n
    if group_value is not None:\n
      uid_list = []\n
      while group_value.getPortalType() != \'Base Category\':\n
        uid_list.append(group_value.getUid())\n
        group_value = group_value.getParentValue()\n
      search_kw[\'parent_strict_group_uid\'] = uid_list\n
      search_kw[\'parent_portal_type\'] = \'Organisation\'\n
      bank_account_list = portal.portal_catalog(**search_kw)\n
\n
else:\n
  if section_category is None:\n
    section_category = portal.portal_preferences\\\n
        .getPreferredAccountingTransactionSectionCategory()\n
  section_uid = portal.Base_getSectionUidListForSectionCategory(\n
                               section_category=section_category,\n
                               strict_membership=section_category_strict_membership)\n
  search_kw[\'parent_uid\'] = section_uid\n
  bank_account_list = portal.portal_catalog(**search_kw)\n
\n
\n
item_list = [(\'\', \'\')]\n
for bank in bank_account_list:\n
  bank = bank.getObject()\n
     \n
  if bank.getReference() and bank.getTitle() \\\n
                  and bank.getReference() != bank.getTitle():\n
    item_list.append((\'%s - %s\' % ( bank.getReference(),\n
                                    bank.getTitle() or \n
                                    bank.getSourceFreeText() or\n
                                    bank.getSourceTitle()),\n
                                    bank.getRelativeUrl()))\n
  else:\n
    item_list.append(( bank.getReference() or\n
                       bank.getTitle() or \n
                       bank.getSourceFreeText() or\n
                       bank.getSourceTitle(),\n
                       bank.getRelativeUrl() ))\n
\n
return item_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>organisation=None, skip_invalidated_bank_accounts=0, section_category=None, section_category_strict_membership=False</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getBankAccountItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
