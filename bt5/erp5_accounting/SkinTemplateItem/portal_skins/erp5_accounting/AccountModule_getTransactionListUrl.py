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
            <value> <string>from ZTUtils import make_query\n
from Products.PythonScripts.standard import html_quote\n
\n
index = context.portal_selections.getSelectionIndexFor(selection_name)\n
object = brain.getObject()\n
\n
# this is for domain_tree mode\n
if object.getPortalType() == "Category" : \n
 return "#"\n
\n
method = \'Account_viewAccountingTransactionList\'\n
kw = { \'selection_index\': str(index),\n
       \'selection_name\' : selection_name, \n
       \'reset\' : \'1\', \n
     }\n
\n
return html_quote(\'%s/%s?%s\' % (object.absolute_url(), method, make_query(kw)))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>brain=None, selection=None, selection_name=None, **kwd</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getTransactionListUrl</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
