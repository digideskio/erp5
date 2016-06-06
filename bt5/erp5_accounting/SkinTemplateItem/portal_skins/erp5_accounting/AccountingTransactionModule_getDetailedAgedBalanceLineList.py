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

from Products.ZSQLCatalog.SQLCatalog import Query, ComplexQuery\n
from Products.PythonScripts.standard import Object\n
portal = context.getPortalObject()\n
\n
assert account_type in (\'account_type/asset/receivable\', \'account_type/liability/payable\')\n
\n
currency = context.Base_getCurrencyForSection(section_category)\n
precision = context.account_module.getQuantityPrecisionFromResource(currency)\n
# we set the precision in request, for formatting on editable fields\n
portal.REQUEST.set(\'precision\', precision)\n
\n
section_uid = portal.Base_getSectionUidListForSectionCategory(\n
  section_category, section_category_strict)\n
\n
grouping_query = ComplexQuery(\n
      Query(grouping_reference=None),\n
      Query(grouping_date=at_date, range="min"),\n
      operator="OR")\n
      \n
account_number_memo = {}\n
def getAccountNumber(account_url):\n
  try:\n
    return account_number_memo[account_url]\n
  except KeyError:\n
    account_number_memo[account_url] =\\\n
      portal.restrictedTraverse(account_url).Account_getGapId()\n
  return account_number_memo[account_url]\n
\n
section_title_memo = {}\n
def getSectionTitle(uid):\n
  try:\n
    return section_title_memo[uid]\n
  except KeyError:\n
    section_title_memo[uid] =\\\n
      portal.portal_catalog.getObject(uid).getTranslatedTitle()\n
  return section_title_memo[uid]\n
\n
last_period_id = \'period_%s\' % len(period_list)\n
line_list = []\n
\n
for brain in portal.portal_simulation.getMovementHistoryList(\n
                                at_date=at_date,\n
                                simulation_state=simulation_state,\n
                                node_category_strict_membership=account_type,\n
                                portal_type=portal.getPortalAccountingMovementTypeList(),\n
                                section_uid=section_uid,\n
                                grouping_query=grouping_query,\n
                                sort_on=((\'stock.mirror_section_uid\', \'ASC\'),\n
                                         (\'stock.date\', \'ASC\'),\n
                                         (\'stock.uid\', \'ASC\'))):\n
  movement = brain.getObject()\n
  transaction = movement.getParentValue()\n
\n
  total_price = brain.total_price or 0\n
  if account_type == \'account_type/liability/payable\':\n
    total_price = - total_price\n
  \n
  line = Object(uid=\'new_\',\n
                mirror_section_title=getSectionTitle(brain.mirror_section_uid),\n
                mirror_section_uid=brain.mirror_section_uid,\n
                total_price=total_price,)\n
\n
  if detail:\n
    # Detailed version of the aged balance report needs to get properties from\n
    # the movement or transactions, but summary does not. This conditional is\n
    # here so that we do not load objects when running in summary mode.\n
    line[\'explanation_title\'] = movement.hasTitle() and movement.getTitle() or transaction.getTitle()\n
    line[\'reference\'] = transaction.getReference()\n
    line[\'portal_type\'] = transaction.getTranslatedPortalType()\n
    line[\'date\'] = brain.date\n
    if brain.mirror_section_uid == movement.getSourceSectionUid() and brain.mirror_node_uid == movement.getSourceUid():\n
      line[\'specific_reference\'] = transaction.getDestinationReference()\n
      line[\'gap_id\'] = getAccountNumber(movement.getDestination())\n
    else:\n
      line[\'specific_reference\'] = transaction.getSourceReference()\n
      line[\'gap_id\'] = getAccountNumber(movement.getSource())\n
      assert brain.mirror_section_uid == movement.getDestinationSectionUid()\n
\n
  # Note that we use date_utc because date would load the object and we are just\n
  # interested in the difference of days.\n
  age = int(at_date - brain.date_utc)\n
  line[\'age\'] = age\n
  if age < 0:\n
    line[\'period_future\'] = total_price\n
  elif age <= period_list[0]:\n
    line[\'period_0\'] = total_price\n
  else:\n
    for idx, period in enumerate(period_list):\n
      if age <= period:\n
        line[\'period_%s\' % idx] = total_price\n
        break\n
    else:\n
      line[last_period_id] = total_price\n
 \n
  line_list.append(line)\n
\n
return line_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>at_date, section_category, section_category_strict, simulation_state, period_list, account_type, detail=True, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_getDetailedAgedBalanceLineList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
