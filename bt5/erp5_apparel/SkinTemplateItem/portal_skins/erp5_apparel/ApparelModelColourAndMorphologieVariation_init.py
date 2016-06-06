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
            <value> <string>"""\n
This script select the good base category according to the portal_type and if\n
the category is in variation range\n
"""\n
\n
portal_type = context.getPortalType()\n
if portal_type in context.getPortalVariationTypeList():\n
  portal_type = context.getParentValue().getPortalType()\n
\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
def getIndividualVariationBaseCategoryList(portal_type):\n
  result = []\n
  #xxx default preference value [] for fix a bug\n
  method_name = \'getPreferred%sIndividualVariationBaseCategoryList\' % portal_type.replace(\' \', \'\')\n
  method = getattr(context.portal_preferences, method_name)\n
  url_list = method([])\n
  for url in url_list:\n
    base_category = context.portal_categories[url]\n
    result.append((base_category.getTranslatedTitle(), base_category.getRelativeUrl()))\n
  return result\n
\n
getIndividualVariationBaseCategoryList = CachingMethod(getIndividualVariationBaseCategoryList,\n
    id=(script.id, context.Localizer.get_selected_language()),\n
    cache_factory=\'erp5_ui_long\')\n
\n
base_category_list = [y for x, y in getIndividualVariationBaseCategoryList(portal_type)]\n
\n
if context.getPortalType() == \'Apparel Model Colour Variation\' and \'colour\' in base_category_list:\n
  context.edit(variation_base_category_list=(\'colour\',))\n
elif context.getPortalType() == \'Apparel Model Morphology Variation\' and \'morphology\' in base_category_list:\n
  context.edit(variation_base_category_list=(\'morphology\',))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>*args, **kw</string> </value>
        </item>
        <item>
            <key> <string>guard</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ApparelModelColourAndMorphologieVariation_init</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Guard" module="Products.DCWorkflow.Guard"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>roles</string> </key>
            <value>
              <tuple>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
