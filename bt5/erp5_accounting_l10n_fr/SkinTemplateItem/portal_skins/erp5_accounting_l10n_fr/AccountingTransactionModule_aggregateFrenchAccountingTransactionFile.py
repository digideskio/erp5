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
            <value> <string>from cStringIO import StringIO\n
import zipfile\n
from Products.ERP5Type.Message import translateString\n
\n
portal = context.getPortalObject()\n
active_process = portal.restrictedTraverse(active_process)\n
\n
# XXX we need proxy role for this\n
result_list = active_process.getResultList()\n
\n
fec_file = context.AccountingTransactionModule_viewComptabiliteAsFECXML(\n
      at_date=at_date,\n
      result_list=result_list)\n
\n
zipbuffer = StringIO()\n
zipfilename = at_date.strftime(\'FEC-%Y.zip\')\n
zipfileobj = zipfile.ZipFile(zipbuffer, \'w\', compression=zipfile.ZIP_DEFLATED)\n
zipfileobj.writestr(\'FEC.xml\', fec_file.encode(\'utf8\'))\n
zipfileobj.close()\n
\n
attachment_list = (\n
    {\'mime_type\': \'application/zip\',\n
     \'content\': zipbuffer.getvalue(),\n
     \'name\': zipfilename, }, )\n
\n
portal.ERP5Site_notifyReportComplete(\n
    user_name=user_name,\n
    subject=unicode(translateString(\'French Accounting Transaction File\')),\n
    message=\'\',\n
    attachment_list=attachment_list)\n
\n
# delete no longer needed active process\n
active_process.getParentValue().manage_delObjects(ids=[active_process.getId()])\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>at_date, active_process, user_name</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransactionModule_aggregateFrenchAccountingTransactionFile</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
