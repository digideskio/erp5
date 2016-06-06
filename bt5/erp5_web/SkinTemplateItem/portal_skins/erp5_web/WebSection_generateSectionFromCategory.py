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
  This scripts browses recursively a to generate a mirror structure\n
  within the current Web Section. It sets predicate parameters\n
  on all categories excluding itself.\n
\n
  category -- the category to use\n
"""\n
from ZODB.POSException import ConflictError\n
portal = context.getPortalObject()\n
translateString = context.Base_translateString\n
category_tool = context.portal_categories\n
global section_count\n
section_count = 0\n
failed_list = []\n
portal_type_list = portal.getPortalDocumentTypeList() + portal.getPortalResourceTypeList()\n
valid_char = "abcdefghijklmnopqrstuvwxyz0123456789-_"\n
\n
def getNiceID(s):\n
  if not s: return None\n
  s = s.lower()\n
  s = s.split()\n
  s = \'-\'.join(s)\n
  s = filter(lambda c: c in valid_char, s)\n
  s = s.replace(\'_\', \'-\')\n
  return s\n
\n
def createWebSectionFromCategoryValue(container, category, depth, section_id=None):\n
  global section_count\n
  if section_id is None:\n
    try:\n
      # Check if this category looks like an int\n
      section_id = int(category.getId())\n
      # Looks like an int, so it should be converted into\n
      # something nicer based on the reference or on the title\n
      if category.hasReference():\n
        section_id = getNiceID(category.getReference())\\\n
                  or getNiceID(category.getTitle()) or getNiceID(category.getId())\n
      if category.hasShortTitle():\n
        section_id = getNiceID(category.getShortTitle())\\\n
                  or getNiceID(category.getTitle()) or getNiceID(category.getId())\n
      else:\n
        section_id = getNiceID(category.getTitle()) or getNiceID(category.getId())\n
    except ValueError:\n
      if not generate_nice_id:\n
        # It is not an int, so it can be used as is\n
        section_id = category.getId()\n
      else:\n
        if category.hasReference():\n
          section_id = getNiceID(category.getReference())\\\n
                  or getNiceID(category.getTitle()) or getNiceID(category.getId())\n
        if category.hasShortTitle():\n
          section_id = getNiceID(category.getShortTitle())\\\n
                  or getNiceID(category.getTitle()) or getNiceID(category.getId())\n
        else:\n
          section_id = getNiceID(category.getTitle()) or getNiceID(category.getId())\n
  # Create a new Web Section if necessary\n
  new_section = None\n
  if section_id not in container.contentIds():\n
    section_count += 1\n
    try:\n
      # If we are not browsing a standard Category tree, we\n
      # must add a trailing base_category_id\n
      if category.getPortalType() not in (\'Category\', \'Base Category\'):\n
        category_url = \'%s/%s\' % (base_category_id, category.getRelativeUrl())\n
      else:\n
        category_url = category.getRelativeUrl()\n
      new_section = container.newContent( portal_type = \'Web Section\'\n
                                        , id          = section_id\n
                                        , title       = category.getTitle()\n
                                        , description = category.getDescription()\n
                                        , visible     = True\n
                                        , membership_criterion_base_category = (base_category_id,)\n
                                        , membership_criterion_category      = (category_url,)\n
                                        , criterion_property_list = [\'portal_type\']\n
                                        )\n
      new_section.setCriterion(\'portal_type\', identity=portal_type_list)\n
      new_section.updateLocalRolesOnSecurityGroups()\n
    except ConflictError:\n
      raise\n
    except:\n
      failed_list.append(category.getRelativeUrl())\n
  else:\n
    new_section = container[section_id]\n
    # If we are not browsing a standard Category tree, we\n
    # must add a trailing base_category_id\n
    if category.getPortalType() not in (\'Category\', \'Base Category\'):\n
      category_url = \'%s/%s\' % (base_category_id, category.getRelativeUrl())\n
    else:\n
      category_url = category.getRelativeUrl()\n
    if update_existing:\n
      new_section.edit(title       = category.getTitle()\n
                     , description = category.getDescription()\n
                     , visible     = True\n
                     , membership_criterion_base_category = (base_category_id,)\n
                     , membership_criterion_category      = (category_url,)\n
                     , criterion_property_list = [\'portal_type\']\n
                     )\n
      new_section.setCriterion(\'portal_type\', identity=portal_type_list)\n
      new_section.updateLocalRolesOnSecurityGroups()\n
  # Call the function recursively\n
  if new_section is not None:\n
    # It is possible to browse objects which are not categories\n
    # ex. Projects\n
    if depth > 0:\n
      for sub_category in category.contentValues():\n
        createWebSectionFromCategoryValue(new_section, sub_category, depth - 1)\n
  # Remove sections which have no counterpart in categories\n
  if remove_missing:\n
    # XXX Not implemented yet\n
    pass\n
\n
# Call the recursive section generator for each category\n
my_category_value = category_tool.restrictedTraverse(category)\n
base_category_id = my_category_value.getBaseCategory().getId()\n
createWebSectionFromCategoryValue(context, my_category_value, depth, section_id=section_id)\n
\n
# Update section settings\n
if update_existing:\n
  section_value = getattr(context, section_id)\n
  if \'/\' in category:\n
    category_url = category\n
  else:\n
    # use the base category as a category to select all\n
    category_url = \'%s/%s\' % (category, category) \n
  section_value.edit(membership_criterion_base_category = (base_category_id,),\n
                     membership_criterion_category = (category_url,),\n
                     criterion_property_list = [\'portal_type\'])\n
  section_value.setCriterion(\'portal_type\', identity=portal_type_list)\n
\n
  section_value.updateLocalRolesOnSecurityGroups()\n
\n
\n
# Warn about failures if any\n
if failed_list:\n
  return context.Base_redirect(form_id,\n
    keep_items = dict(portal_status_message = translateString("Generated ${section_count} sections for the web site. Failed with ${failed_text}.",\n
    mapping = dict(section_count = section_count,\n
                 failed_text = \', \'.join(failed_list)))))\n
\n
\n
return context.Base_redirect(form_id,\n
  keep_items = dict(portal_status_message = translateString("Generated ${section_count} sections for the Web Site.",\n
    mapping = dict(section_count = section_count))))\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>category, section_id, depth=1, generate_nice_id=False, update_existing=0, remove_missing=0, form_id=\'view\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSection_generateSectionFromCategory</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
