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
            <value> <string>"""Set grouping reference for selected lines.\n
Used as a fast input dialog action.\n
"""\n
from ZTUtils import make_query\n
from ZODB.POSException import ConflictError\n
portal = context.getPortalObject()\n
getobject = portal.portal_catalog.getobject\n
stool = portal.portal_selections\n
Base_translateString = portal.Base_translateString\n
psm = Base_translateString(\'Nothing matches.\')\n
request = container.REQUEST\n
precision = request.get(\'precision\', 2)\n
\n
# update selected uids \n
stool.updateSelectionCheckedUidList(\n
    list_selection_name, uids=uids, listbox_uid=listbox_uid, REQUEST=request)\n
uids = stool.getSelectionCheckedUidsFor(list_selection_name)\n
\n
# XXX when should it be validated ?\n
if node == \'\':\n
  node = context.REQUEST.get(\'field_your_node\', node)\n
if mirror_section == \'\':\n
  mirror_section = context.REQUEST.get(\'field_your_mirror_section\',\n
                                        mirror_section)\n
if grouping == \'\':\n
  grouping = request.get(\'your_grouping\',\n
                         request.get(\'field_your_grouping\',\n
                                     grouping))\n
\n
# edit selection for dialog parameters\n
portal.portal_selections.setSelectionParamsFor(\n
              \'grouping_reference_fast_input_selection\',\n
              params=dict(node=node,\n
                          grouping=grouping,\n
                          mirror_section=mirror_section))\n
\n
# calculate total selected amount \n
total_selected_amount = 0\n
if uids:\n
  for uid in uids:\n
    line = getobject(uid)\n
    if line.AccountingTransaction_isSourceView(): # XXX not optimal !\n
      total_selected_amount += (line.getSourceInventoriatedTotalAssetPrice() or 0)\n
    else:\n
      total_selected_amount += (line.getDestinationInventoriatedTotalAssetPrice() or 0)\n
request.set(\'total_selected_amount\', total_selected_amount)\n
\n
if update:\n
  request.set(\'portal_status_message\', Base_translateString(\'Updated\'))\n
  return context.AccountingTransactionModule_viewGroupingFastInputDialog(request)\n
  \n
\n
# otherwise, try to group...\n
if grouping == \'grouping\':\n
  grouped_line_list = context.AccountingTransaction_guessGroupedLines(\n
                        accounting_transaction_line_uid_list=uids)\n
  if grouped_line_list:\n
    psm = Base_translateString(\'${grouped_line_count} lines grouped.\',\n
                               mapping=dict(grouped_line_count=len(grouped_line_list)))\n
\n
    # make sure nothing will be checked next time\n
    stool.setSelectionCheckedUidsFor(list_selection_name, [])\n
\n
    # we check if we can mark some transaction as payed.\n
    transaction_list = {}\n
    for line in grouped_line_list:\n
      transaction_list[portal.restrictedTraverse(line).getParentValue()] = 1\n
\n
    for transaction in transaction_list.keys():\n
      if transaction.getPortalType() == \'Balance Transfer Transaction\':\n
        transaction = transaction.getCausalityValue()\n
      # Check if this document has a payment_state\n
      if getattr(transaction, \'getPaymentState\', None) is not None:\n
        # if all [recievable|payable] lines were grouped, we can mark this\n
        # invoice as payed.\n
        cleared = 1\n
\n
        line_list = transaction.getMovementList(\n
                       portal_type=portal.getPortalAccountingMovementTypeList())\n
        for btt in transaction.getCausalityRelatedValueList(\n
                           portal_type=\'Balance Transfer Transaction\'):\n
          if btt.getSimulationState() == \'delivered\':\n
            for btt_line in btt.getMovementList():\n
              line_list.append(btt_line)\n
\n
        for line in line_list:\n
          if line.getParentValue().AccountingTransaction_isSourceView():\n
            account = line.getSourceValue(portal_type=\'Account\')\n
          else:\n
            account = line.getDestinationValue(portal_type=\'Account\')\n
          if account is not None and account.getAccountTypeId() in ( \'payable\',\n
                                                                     \'receivable\' ):\n
            if line.getRelativeUrl() not in grouped_line_list:\n
              if not line.getGroupingReference():\n
                cleared = 0\n
\n
        if cleared and transaction.getPaymentState() != \'cleared\':\n
          if transaction.AccountingTransaction_isSourceView():\n
            date = transaction.getStartDate()\n
          else:\n
            date = transaction.getStopDate()\n
          # XXX specific !\n
          try:\n
            portal.portal_workflow.doActionFor(transaction, \'clear_action\',\n
                                               payment_date=date)\n
          except ConflictError:\n
            raise\n
          except:\n
            # Workflow action not supported\n
            pass\n
\n
# or to ungroup based on how we are called.\n
else:\n
  assert grouping == \'ungrouping\'\n
  # XXX is uids multi page safe here ?\n
  line_list = [getobject(line_uid) for line_uid in uids]\n
  ungrouped_line_list = []\n
\n
  for line in line_list:\n
    if line.getGroupingReference():\n
      ungrouped_line_list.extend(line.AccountingTransactionLine_resetGroupingReference())\n
  \n
  psm = Base_translateString(\'${ungrouped_line_count} lines ungrouped.\',\n
                             mapping=dict(ungrouped_line_count=len(ungrouped_line_list)))\n
\n
  # make sure nothing will be checked next time\n
  stool.setSelectionCheckedUidsFor(list_selection_name, [])\n
\n
request.set(\'portal_status_message\', psm)\n
return context.AccountingTransactionModule_viewGroupingFastInputDialog(request)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>uids=[], listbox=None, listbox_uid=[], list_selection_name=\'\', grouping=\'\', node=\'\', mirror_section=\'\', update=0, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_setGroupingReference</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
