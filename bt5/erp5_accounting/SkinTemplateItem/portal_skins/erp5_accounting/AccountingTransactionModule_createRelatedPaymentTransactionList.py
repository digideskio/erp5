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

from Products.ERP5Type.Message import translateString\n
try:\n
  from zExceptions import Redirect\n
except:\n
  Redirect = \'Redirect\'\n
portal = context.getPortalObject()\n
stool = portal.portal_selections\n
getObject = portal.portal_catalog.getObject\n
countMessage = portal.portal_activities.countMessage\n
invoice_type_list = portal.getPortalInvoiceTypeList()\n
\n
stool.updateSelectionCheckedUidList(selection_name, listbox_uid, uids)\n
selection_uid_list = context.portal_selections.getSelectionCheckedUidsFor(\n
                                                       selection_name)\n
if selection_uid_list:\n
  object_list = [getObject(uid) for uid in selection_uid_list]\n
else:\n
  object_list = stool.callSelectionFor(selection_name)\n
\n
# update selection params, because it\'ll be used in the selection dialog.\n
stool.setSelectionParamsFor(\'accounting_create_related_payment_selection\',\n
          params=dict(node_for_related_payment=node,\n
                      payment_mode_for_related_payment=payment_mode,\n
                      payment_for_related_payment=payment))\n
\n
# XXX prevent to call this on the whole module:\n
if len(object_list) >= 1000:\n
  return context.REQUEST.RESPONSE.redirect(\n
    "%s/view?portal_status_message=%s" % (\n
        context.absolute_url(), translateString(\n
         \'Refusing to process more than 1000 objects, check your selection.\')))\n
\n
tag = \'payment_creation_%s\' % random.randint(0, 1000)\n
activated = 0\n
for obj in object_list:\n
  if obj.portal_type in invoice_type_list:\n
    obj = obj.getObject()\n
    if countMessage(path=obj.getPath(),\n
                    method_id=\'Invoice_createRelatedPaymentTransaction\'):\n
      raise Redirect, "%s/view?portal_status_message=%s" % (\n
                context.absolute_url(), translateString(\n
        \'Payment creation already in progress, abandon.\'))\n
    obj.activate(tag=tag).Invoice_createRelatedPaymentTransaction(\n
                                                  node=node,\n
                                                  payment_mode=payment_mode,\n
                                                  payment=payment,\n
                                                  batch_mode=1)\n
    activated += 1\n
\n
if not activated:\n
  return context.REQUEST.RESPONSE.redirect(\n
    "%s/view?portal_status_message=%s" % (\n
        context.absolute_url(), translateString(\'No invoice in your selection.\')))\n
\n
# activate something on the folder\n
context.activate(after_tag=tag).getTitle()\n
\n
return context.REQUEST.RESPONSE.redirect(\n
    "%s/view?portal_status_message=%s" % (\n
        context.absolute_url(), translateString(\n
          \'Payments creation for ${activated_invoice_count} on\'\n
          \' ${total_selection_count} invoices in progress.\',\n
          mapping=dict(activated_invoice_count=activated,\n
                       total_selection_count=len(object_list)))))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>node, payment_mode, payment, selection_index=None, uids=[], listbox_uid=[],selection_name=\'\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_createRelatedPaymentTransactionList</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
