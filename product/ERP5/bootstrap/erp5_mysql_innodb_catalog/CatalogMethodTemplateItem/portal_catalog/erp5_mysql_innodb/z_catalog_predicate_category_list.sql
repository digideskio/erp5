<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>allow_simple_one_argument_traversal</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>uid\r\n
predicate_property_dict\r\n
isPredicate\r\n
getObject</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_hook</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_catalog_predicate_category_list</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>1000</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

DELETE FROM\n
  predicate_category\n
WHERE\n
<dtml-in uid>\n
  uid=<dtml-sqlvar sequence-item type="int"><dtml-if sequence-end><dtml-else> OR </dtml-if>\n
</dtml-in>\n
;\n
\n
<dtml-var "\'\\0\'">\n
\n
<dtml-let predicate_list="[]">\n
  <dtml-in prefix="loop" expr="_.range(_.len(uid))">\n
    <dtml-if "isPredicate[loop_item]">\n
      <dtml-if expr="_.len(predicate_property_dict[loop_item]) > 0">\n
        <dtml-call expr="predicate_list.append(loop_item)">\n
      </dtml-if>\n
    </dtml-if>\n
  </dtml-in>\n
  <dtml-if expr="_.len(predicate_list) > 0">\n
REPLACE INTO predicate_category VALUES \n
    <dtml-in prefix="loop" expr="predicate_list">\n
      <dtml-if sequence-start><dtml-else>,</dtml-if>\n
      <dtml-if "predicate_property_dict[loop_item].has_key(\'membership_criterion_category_list\')">\n
        <dtml-let uid_list="portal_categories.CategoryTool_getPreferredPredicateCategoryParentUidItemList(predicate_property_dict[loop_item][\'membership_criterion_category_list\'], getObject[loop_item])">\n
          <dtml-if uid_list>\n
            <dtml-in "uid_list">\n
(<dtml-sqlvar expr="uid[loop_item]" type="int">, <dtml-var "_[\'sequence-item\'][0]" >, <dtml-var "_[\'sequence-item\'][1]" >, <dtml-var "_[\'sequence-item\'][2]" >)\n
              <dtml-if sequence-end><dtml-else>,</dtml-if>\n
            </dtml-in> \n
          <dtml-else>\n
(<dtml-sqlvar expr="uid[loop_item]" type="int">, 0, 0,1)\n
          </dtml-if>\n
        </dtml-let>\n
      <dtml-else>\n
(<dtml-sqlvar expr="uid[loop_item]" type="int">, 0, 0,1)\n
      </dtml-if>\n
    </dtml-in>\n
  </dtml-if>\n
</dtml-let>\n


]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
