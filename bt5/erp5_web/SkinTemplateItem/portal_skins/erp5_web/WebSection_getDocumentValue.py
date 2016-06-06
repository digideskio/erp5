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

"""\n
 This script is part of ERP5 Web\n
\n
 ERP5 Web is a business template of ERP5 which provides a way\n
 to create web sites which can display selected\n
 ERP5 contents through multiple custom web layouts.\n
\n
 The default implementation searches for\n
 documents which are in the user language if any\n
 and which reference is equal to the name parameter.\n
\n
 Other implementations are possible: ex. display the last\n
 version in the closest language rather than\n
 the latest version in the user language.\n
\n
 NOTE:\n
 - the portal parameter was introduced to\n
   fix acquisition issues within the _aq_dynamic\n
   lookup from WebSection class.\n
"""\n
from Products.ZSQLCatalog.SQLCatalog import SimpleQuery, ComplexQuery\n
if portal is None: portal = context.getPortalObject()\n
portal_catalog = portal.portal_catalog\n
# The list of portal types here should be large enough to include\n
# all portal_types defined in the various sections so that\n
# href tags which point to a document by reference can still work.\n
valid_portal_type_list = portal.getPortalDocumentTypeList()\n
\n
# Find the applicable language\n
if language is None:\n
  language = portal.Localizer.get_selected_language()\n
\n
if validation_state is None:\n
  validation_state = (\'released\', \'released_alive\', \'published\', \'published_alive\',\n
                      \'shared\', \'shared_alive\', \'public\', \'validated\')\n
\n
if effective_date is None:\n
  if now is None:\n
    now = DateTime()\n
  effective_date = ComplexQuery(\n
    SimpleQuery(effective_date=None),\n
    SimpleQuery(effective_date=now, comparison_operator=\'<=\'),\n
    logical_operator=\'or\',\n
  )\n
\n
# Note: In sorts, NULL is considered lesser than non-NULL. So in descending\n
# sort, NULLs will be listed after non-NULLs, which is perfect for\n
# effective_date, which defines the date at which content becomes effective.\n
# None (NULL) effective date hence means "effective since infinite in te past".\n
base_sort = ((\'effective_date\', \'descending\'), )\n
\n
# Search the catalog for all documents matching the reference\n
# this will only return documents which are accessible by the user\n
web_page_list = portal_catalog(reference=name,\n
                               effective_date=effective_date,\n
                               portal_type=valid_portal_type_list,\n
                               validation_state=validation_state,\n
                               language=(language, \'\'),\n
                               sort_on=((\'language\', \'descending\'), ) + base_sort,\n
                               limit=1,\n
                               **kw)\n
\n
if len(web_page_list) == 0 and language != \'en\':\n
  # Search again with English as a fallback.\n
  web_page_list = portal_catalog(reference=name,\n
                                 effective_date=effective_date,\n
                                 portal_type=valid_portal_type_list,\n
                                 validation_state=validation_state,\n
                                 language=\'en\',\n
                                 sort_on=base_sort,\n
                                 limit=1,\n
                                 **kw)\n
\n
if len(web_page_list) == 0:\n
  # Search again without the language\n
  web_page_list = portal_catalog(reference=name,\n
                                 effective_date=effective_date,\n
                                 portal_type=valid_portal_type_list,\n
                                 validation_state=validation_state,\n
                                 sort_on=base_sort,\n
                                 limit=1,\n
                                 **kw)\n
\n
if len(web_page_list) == 0:\n
  # Default returns None\n
  web_page = None\n
else:\n
  # Try to get the first page on the list\n
  web_page = web_page_list[0]\n
  web_page = web_page.getObject()\n
\n
# return the web page\n
return web_page\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>name, portal=None, language=None, validation_state=None, effective_date=None, now=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSection_getDocumentValue</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
