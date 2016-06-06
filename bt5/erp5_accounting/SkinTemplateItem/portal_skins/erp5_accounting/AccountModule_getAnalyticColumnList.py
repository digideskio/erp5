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
            <value> <string>"""Returns the list of columns to use in accounting reports (GL, account statement, journal)\n
"""\n
from Products.ZSQLCatalog.SQLCatalog import Query\n
portal = context.getPortalObject()\n
request = portal.REQUEST\n
\n
# cache the title in the request, it will be used by Movement_getProjectTitle\n
# and Movement_getFunctionTitle scripts\n
request.other[\'Movement_getProjectTitle.project_title_dict\'\n
    ] = project_title_dict = {}\n
request.other[\'Movement_getFunctionTitle.function_title_dict\'\n
    ] = function_title_dict = {}\n
request.other[\'Movement_getFundingTitle.funding_title_dict\'\n
    ] = funding_title_dict = {}\n
\n
analytic_column_list = ()\n
funding_item_list = context.AccountingTransactionLine_getFundingItemList()\n
if funding_item_list:\n
  analytic_column_list += ((\'funding\', context.AccountingTransactionLine_getFundingBaseCategoryTitle()),)\n
for v, k in funding_item_list:\n
  if k:\n
    if k == \'None\' or isinstance(k, Query):\n
      funding_title_dict[None] = \'\'\n
    else:\n
      funding_title_dict[portal.portal_categories.restrictedTraverse(k).getUid()] = v\n
\n
function_item_list = context.AccountingTransactionLine_getFunctionItemList()\n
if function_item_list:\n
  analytic_column_list += ((\'function\', context.AccountingTransactionLine_getFunctionBaseCategoryTitle()),)\n
for v, k in function_item_list:\n
  if k:\n
    if k == \'None\' or isinstance(k, Query):\n
      function_title_dict[None] = \'\'\n
    else:\n
      function_title_dict[portal.portal_categories.restrictedTraverse(k).getUid()] = v\n
\n
project_item_list = context.AccountingTransactionLine_getProjectItemList()\n
if project_item_list:\n
  analytic_column_list += ((\'project\', \'Project\'),)\n
for v, k in project_item_list:\n
  if k:\n
    if k == \'None\' or isinstance(k, Query):\n
      project_title_dict[None] = \'\'\n
    else:\n
      project_title_dict[portal.portal_categories.restrictedTraverse(k).getUid()] = v\n
\n
for base_category in \\\n
    portal.portal_preferences.getPreferredAccountingTransactionLineAnalyticBaseCategoryList() or []:\n
  title = portal.portal_categories.restrictedTraverse(base_category).getTitle()\n
  analytic_column_list += ((\'%s_translated_title\' % base_category, title),)\n
\n
return analytic_column_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountModule_getAnalyticColumnList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
