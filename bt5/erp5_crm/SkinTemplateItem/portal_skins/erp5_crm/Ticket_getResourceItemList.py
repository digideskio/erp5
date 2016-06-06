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
portal_type (None, string)\n
  Ignored if use_relative_url is not None.\n
  Used to determine use_relative_url, using preference settings for given\n
  portal type.\n
  When None, context\'s portal_type is used.\n
include_context (bool)\n
  Add context\'s category to return value if not already present.\n
empty_item (bool)\n
  Controls presence of [\'\', \'\'] element in result.\n
indent_category (bool)\n
  When true, category captions are indented.\n
  When false, categories captions are paths, relative to topmost category (not\n
  necessarily a Base Category !).\n
indent_resource (bool)\n
  When true, resource captions are indented.\n
  When false, resource captions are not indented.\n
compact (bool)\n
  When true, getCompactTranslatedTitle is used to generate captions.\n
  When false, getTranslatedTitle is used to generate captions.\n
empty_category (bool)\n
  When true, categories with no resource children (at any depth) are present\n
  in result.\n
  When false, categories with no resource children (at any depth) are pruned\n
  from result.\n
use_relative_url (None, string)\n
  The "use"-category-relative path of category to start recursing from.\n
\n
When indent_category, indent_resource and compact are simultaneously not\n
provided (or None), a default is built from\n
getPreferredCategoryChildItemListMethodId.\n
"""\n
# Note: a possible improvement would be to merge consecutive disabled entries.\n
# This is difficult though, because it requires splitting work a lot,\n
# increasing complexity significantly for such little improvement:\n
# - non-child categories must not be concatenated (empty /1/12/ must not be\n
#   merged with a following /2/)\n
# - all resource child must be properly indented\n
# It is much simpler if only "empty_category=False" case is handled.\n
from Products.ERP5Type.Cache import CachingMethod\n
portal = context.getPortalObject()\n
portal_preferences = portal.portal_preferences\n
if use_relative_url is None:\n
  use_relative_url = portal_preferences.getPreference(\n
    \'preferred_\' + (portal_type or context.getPortalType()).lower().replace(\' \', \'_\') + \'_use\',\n
  )\n
if indent_category == indent_resource == compact == None:\n
  indent_category, indent_resource, compact = {\n
    \'getCategoryChildTranslatedCompactLogicalPathItemList\': (False, False, True),\n
    \'getCategoryChildTranslatedLogicalPathItemList\': (False, True, False),\n
    \'getCategoryChildTranslatedIndentedCompactTitleItemList\': (True, False, True),\n
    \'getCategoryChildTranslatedIndentedTitleItemList\': (True, True, False),\n
  }.get(portal_preferences.getPreferredCategoryChildItemListMethodId(), (True, True, False))\n
\n
accessor_id = \'getCompactTranslatedTitle\' if compact else \'getTranslatedTitle\'\n
\n
def getResourceItemList():\n
  INDENT = \'\\xc2\\xa0\' * 2 # UTF-8 Non-breaking space\n
  RESOURCE_INDENT = INDENT if indent_resource else \'\'\n
  getResourceTitle = lambda resource, category, depth: RESOURCE_INDENT * depth + getattr(resource, accessor_id)()\n
  if indent_category:\n
    def getCategoryTitle(category, depth):\n
      return INDENT * depth + getattr(category, accessor_id)()\n
  else:\n
    def getCategoryTitle_(category, depth):\n
      result = []\n
      append = result.append\n
      for _ in xrange(depth + 1):\n
        append(getattr(category, accessor_id)())\n
        category = category.getParentValue()\n
      return \'/\'.join(result[::-1])\n
    if indent_resource:\n
      getCategoryTitle = getCategoryTitle_\n
    else:\n
      getCategoryTitle = lambda category, depth: None\n
      def getResourceTitle(resource, category, depth):\n
        resource_title = getattr(resource, accessor_id)()\n
        # depth - 1 because we are at category\'s child level\n
        category_path = getCategoryTitle_(category, depth - 1)\n
        if category_path:\n
          return category_path + \'/\' + resource_title\n
        return resource_title\n
  def recurse(category, depth):\n
    child_list, resource_list = category.Category_getUseCategoryListAndResourceList()\n
    # Resources before child categories, to avoid ambiguity when resources are not indented\n
    result = sorted(\n
      [(getResourceTitle(x, category, depth), x.getRelativeUrl()) for x in resource_list],\n
      key=lambda x: x[0],\n
    )\n
    append = result.append\n
    extend = result.extend\n
    for _, caption, grand_child_list in sorted(\n
          [(x.getIntIndex(), getCategoryTitle(x, depth), recurse(x, depth + 1)) for x in child_list],\n
          key=lambda x: x[:2],\n
        ):\n
      if grand_child_list or empty_category:\n
        if caption is not None:\n
          append((caption, None))\n
        extend(grand_child_list)\n
    return result\n
  category = portal.portal_categories.getCategoryValue(use_relative_url, base_category=\'use\')\n
  if category is None:\n
    return []\n
  return recurse(category, 0)\n
\n
result = CachingMethod(\n
  getResourceItemList,\n
  id=(\n
    script.id,\n
    context.Localizer.get_selected_language(),\n
    bool(indent_resource),\n
    bool(indent_category),\n
    accessor_id,\n
    bool(empty_category),\n
    use_relative_url,\n
  ),\n
  cache_factory=\'erp5_ui_long\',\n
)()\n
if empty_item:\n
  prefix = [(\'\', \'\')]\n
else:\n
  prefix = []\n
if include_context:\n
  context_resource_value = context.getResourceValue()\n
  context_resource = context.getResource()\n
  if context_resource_value is not None and context_resource not in [x for _, x in result]:\n
    prefix.append((getattr(context_resource_value, accessor_id)(), context_resource))\n
return prefix + result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>portal_type=None, include_context=True, empty_item=True, indent_category=None, indent_resource=None, compact=None, empty_category=False, use_relative_url=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Ticket_getResourceItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
