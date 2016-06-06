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
            <value> <string>resource_dict = {}\n
resource_dict = {\'resource_relative_url\':resource, \'variation_text\':variation_text}\n
\n
if cache_dict is None:\n
  cache_dict = {}\n
cache_title_category_url = cache_dict.setdefault(\'cache_title_category_url\',{})\n
cache_translated_title_category_url = cache_dict.setdefault(\'cache_translated_title_category_url\',{})\n
cache_resource_portal_type = cache_dict.setdefault(\'cache_resource_portal_type\', {})\n
cache_resource = cache_dict.setdefault(\'cache_resource\', {})\n
cache_translated_portal_type = cache_dict.setdefault(\'cache_translated_portal_type\', {})\n
cache_translated_simulation_state = cache_dict.setdefault(\'cache_translated_simulation_state\', {})\n
\n
\n
#def getVariationTitleList(variation_text):\n
#  return [getTitleFromCategoryUrl(x) for x in variation_text.split(\'\\n\')]\n
\n
def getTitleFromCategoryUrl(category):\n
  result = cache_title_category_url.get(category, None)\n
  if result is None:\n
    result = context.portal_categories.getCategoryValue(category).getTitle()\n
    cache_title_category_url[category] = result\n
  return result\n
\n
def getTranslatedTitleFromCategoryUrl(category):\n
  result = cache_translated_title_category_url.get(category, None)\n
  if result is None:\n
    result = context.portal_categories.getCategoryValue(category).getTranslatedTitle()\n
    cache_translated_title_category_url[category] = result\n
  return result\n
\n
\n
for variation in variation_text.split(\'\\n\'):\n
  if variation.startswith(\'cash_status\'):\n
    resource_dict[\'cash_status\'] = variation\n
    resource_dict[\'cash_status_title\'] = getTitleFromCategoryUrl(variation)\n
    resource_dict[\'cash_status_translated_title\'] = getTranslatedTitleFromCategoryUrl(variation)\n
  elif variation.startswith(\'emission_letter\'):\n
    resource_dict[\'emission_letter\'] = variation\n
    resource_dict[\'emission_letter_title\'] = getTitleFromCategoryUrl(variation)\n
    resource_dict[\'emission_letter_translated_title\'] = getTranslatedTitleFromCategoryUrl(variation)\n
  elif variation.startswith(\'variation\'):\n
    resource_dict[\'variation\'] = variation\n
    resource_dict[\'variation_title\'] = getTitleFromCategoryUrl(variation)\n
    resource_dict[\'variation_translated_title\'] = getTranslatedTitleFromCategoryUrl(variation)\n
\n
#resource_dict[\'variation_text_title\'] = \' \'.join(getVariationTitleList(resource))\n
\n
\n
current_resource_portal_type = cache_resource_portal_type.get(resource, None)\n
if current_resource_portal_type is None:\n
  portal = context.getPortalObject()\n
  resource_value = portal.restrictedTraverse(resource)\n
  current_resource_portal_type = resource_value.getPortalType()\n
  cache_resource_portal_type[resource] = current_resource_portal_type\n
  resource_info_dict = {}\n
  resource_info_dict[\'base_price\'] = resource_value.getBasePrice()\n
  resource_info_dict[\'resource_title\'] = resource_value.getTitle()\n
  resource_info_dict[\'resource_id\'] = resource_value.getId()\n
  #context.log(\'resource_value\',resource_value.getRelativeUrl())\n
  try:\n
    resource_info_dict[\'resource_translated_title\'] = resource_value.getTranslatedTitle()\n
  except KeyError:\n
    resource_info_dict[\'resource_translated_title\'] = resource_value.getTitle()\n
  resource_info_dict[\'price_currency_title\'] = resource_value.getPriceCurrencyTitle()\n
  resource_info_dict[\'price_currency_id\'] = resource_value.getPriceCurrencyId()\n
  resource_info_dict[\'price_currency\'] = resource_value.getPriceCurrency()\n
  resource_info_dict[\'resource_portal_type\'] = current_resource_portal_type\n
  cache_resource[resource] = resource_info_dict\n
\n
# Should not be None\n
resource_dict.update(cache_resource.get(resource))\n
  \n
##############\n
#movement =None\n
#resource_dict[\'explanation_translated_relative_url\'] = \'xx\'\n
###########\n
if movement is not None: # case of history\n
#  movement = portal.restrictedTraverse(movement)\n
#  explanation_value = movement\n
#  if getattr(movement,\'getExplanationValue\',None) is not None:\n
#    explanation_value = movement.getExplanationValue()\n
#  resource_dict[\'explanation_relative_url\'] = explanation_value.getRelativeUrl()\n
#  source_reference = explanation_value.getSourceReference() or \'\'\n
#  resource_dict[\'source_reference\'] = source_reference\n
#  if display_simulation_state:\n
#    resource_dict[\'simulation_state_title\'] = movement.getTranslatedSimulationStateTitle()\n
#  resource_dict[\'explanation_translated_relative_url\'] = "%s/%s" % \\\n
#        (explanation_value.getTranslatedPortalType(),source_reference)\n
  catalog_explanation = cache_dict[\'cache_explanation\'][explanation_uid]\n
  resource_dict[\'explanation_relative_url\'] = catalog_explanation.relative_url\n
  source_reference = catalog_explanation.source_reference\n
  resource_dict[\'source_reference\'] = catalog_explanation.source_reference\n
  explanation_portal_type = catalog_explanation.portal_type\n
  if display_simulation_state:\n
    simulation_state = catalog_explanation.simulation_state\n
    resource_dict[\'simulation_state\'] = simulation_state\n
    simulation_state_title = cache_translated_simulation_state.get((explanation_portal_type,simulation_state), None)\n
    if simulation_state_title is None:\n
      portal = context.getPortalObject()\n
      movement = portal.restrictedTraverse(movement)\n
      simulation_state_title = movement.getTranslatedSimulationStateTitle()\n
      cache_translated_simulation_state[(explanation_portal_type,simulation_state)] = simulation_state_title\n
    resource_dict[\'simulation_state_title\'] = simulation_state_title\n
  translated_portal_type = cache_translated_portal_type.get(explanation_portal_type, None)\n
  if translated_portal_type is None:\n
    translated_portal_type = context.Base_translateString(explanation_portal_type)\n
    cache_translated_portal_type[explanation_portal_type] = translated_portal_type\n
  resource_dict[\'explanation_translated_relative_url\'] = \'%s/%s\' % \\\n
      (translated_portal_type, source_reference)\n
\n
\n
\n
return resource_dict\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>resource, variation_text, movement=None, display_simulation_state=0, explanation_uid=None, cache_dict=None</string> </value>
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
            <value> <string>Base_getResourceInformationDictFromUrlAndVariation</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
