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
  Make SQLCatalog parse given search string and generate an Abstract Syntax Tree.\n
  Then, walk this tree and categorize criterion by type (and their alias, see code).\n
  \n
  Example:\n
  * input:\n
  word_to_search_for "exact_phrase" +containing_all_the_words -without_word created:1w reference:nxd-test version:001 language:en contributor_title:John mine:yes newest:yes\n
\n
  * output\n
   {\'newest\': \'yes\', \n
   \'reference\': \'nxd-test\', \n
   \'language\': \'en\', \n
   \'mine\': \'yes\', \n
   \'searchabletext\': \'word_to_search_for exact_phrase +containing_all_the_words -without_word John\', \n
   \'version\': \'001\', \n
   \'creation_from\': DateTime(\'2010/02/23 13:11:11.698 GMT+2\')}\n
"""\n
from DateTime import DateTime\n
\n
def render_filetype_list(filetype_list):\n
  return [\'%%.%s\' % (x, ) for x in filetype_list]\n
\n
def render_state_list(state_list):\n
  # Note: also used to render type list\n
  result = []\n
  append = result.append\n
  for state in state_list:\n
    if state != \'all\':\n
      append(state)\n
  return result\n
\n
def render_date_range(date_range_list):\n
  result = []\n
  append = result.append\n
  now = DateTime()\n
  for date_range in date_range_list:\n
    # XXX: original version used a regex, but we can\'t import\n
    # "re" module here, so fallback on hand-crafted parsing.\n
    # Original regex: \'(\\d)([wmy]).*\'\n
    # State meaning:\n
    #   0: we expect only decimals\n
    #   1: we expect one of \'w\', \'m\', or \'y\'\n
    state = 0\n
    duration_char_list = []\n
    multiplicator = None\n
    for char in date_range:\n
      if state == 0:\n
        if \'0\' <= char <= \'9\':\n
          duration_char_list.append(char)\n
        else:\n
          state = 1\n
      if state == 1:\n
        if len(duration_char_list):\n
          if char == \'w\':\n
            multiplicator = 7\n
          elif char == \'m\':\n
            multiplicator = 30\n
          elif char == \'y\':\n
            multiplicator = 365\n
        break\n
    if multiplicator is not None:\n
      duration = int(\'\'.join(duration_char_list))\n
      append(now - duration * multiplicator)\n
  return result\n
\n
criterion_alias_dict = {\n
  \'state\':            (\'simulation_state\', render_state_list),\n
  \'type\':             (\'portal_type\',      render_state_list),\n
  \'filetype\':         (\'source_reference\', render_filetype_list),\n
  \'file\':             (\'source_reference\', None),\n
  \'created\':          (\'creation_from\',    render_date_range),\n
  \'simulation_state\': (True, None),\n
  \'language\':         (True, None),\n
  \'version\':          (True, None),\n
  \'reference\':        (True, None),\n
  \'portal_type\':      (True, None),\n
  \'source_reference\': (True, None),\n
  \'creation_from\':    (True, None),\n
  \'searchabletext\':   (True, None),\n
  # indicates user search only within owned documents\n
  \'mine\':             (True, None),\n
  # indicates user search only the newest versions\n
  \'newest\':           (True, None),\n
  # indicates user search for documents by contributor title  \n
  \'contributor_title\':(True, None),\n
  # indicates user search mode (boolean or with with query expansion)\n
  \'mode\':             (True, None),\n
}\n
\n
DEFAULT_CRITERION_ALIAS = \'searchabletext\'\n
\n
def resolveCriterion(criterion_alias, criterion_value_list):\n
  initial_criterion_alias = criterion_alias\n
  # XXX: should be a set\n
  seen_alias_dict = {} # Protection against endless loops\n
  while True:\n
    next_alias, value_list_renderer = criterion_alias_dict.get(criterion_alias, (DEFAULT_CRITERION_ALIAS, None))\n
    if value_list_renderer is not None:\n
      criterion_value_list = value_list_renderer(criterion_value_list)\n
    if next_alias is True:\n
      break\n
    seen_alias_dict[criterion_alias] = None\n
    if next_alias in seen_alias_dict:\n
      raise Exeption, \'Endless alias loop detected: lookup of %r reached alias %r twice\' % (initial_criterion_alias, next_alias)\n
    criterion_alias = next_alias\n
  return criterion_alias, criterion_value_list\n
\n
def recurseSyntaxNode(node, criterion=DEFAULT_CRITERION_ALIAS):\n
  if node.isColumn():\n
    result = recurseSyntaxNode(node.getSubNode(), criterion=node.getColumnName())\n
  else:\n
    result = {}\n
    if node.isLeaf():\n
      result[criterion] = [node.getValue()]\n
    else:\n
      for subnode in node.getNodeList():\n
        for criterion, value_list in recurseSyntaxNode(subnode, criterion=criterion).items():\n
          result.setdefault(criterion, []).extend(value_list)\n
  return result\n
\n
def acceptAllColumns(column):\n
  return True\n
\n
node = context.getPortalObject().portal_catalog.getSQLCatalog().parseSearchText(searchstring, search_key=\'FullTextKey\', is_valid=acceptAllColumns)\n
result =  {}\n
if node is None:\n
  result[\'searchabletext\'] = searchstring\n
else:\n
  for criterion, value_list in recurseSyntaxNode(node).items():\n
    criterion, value_list = resolveCriterion(criterion, value_list)\n
    result.setdefault(criterion, []).extend(value_list)\n
  filtered_result = {}\n
  for criterion, value_list in result.items():\n
    if len(value_list) > 0:\n
      filtered_result[criterion] = value_list\n
  result = filtered_result\n
  for criterion, value_list in result.items():\n
    # XXX: yuck\n
    if criterion == \'searchabletext\':\n
      result[\'searchabletext\'] = \' \'.join(value_list)\n
    if len(value_list) == 1:\n
      result[criterion] = value_list[0]\n
  if \'searchabletext\' not in result:\n
    result[\'searchabletext\'] = \'\'\n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>searchstring</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_parseSearchString</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
