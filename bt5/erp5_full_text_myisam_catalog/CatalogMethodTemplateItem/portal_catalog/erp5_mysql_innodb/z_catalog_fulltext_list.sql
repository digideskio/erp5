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
SearchableText</string> </value>
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
            <value> <string>erp5_sql_deferred_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_catalog_fulltext_list</string> </value>
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

<dtml-let document_list="[]" delete_list="[]">\n
  <dtml-in prefix="loop" expr="_.range(_.len(uid))">\n
    <dtml-if "SearchableText[loop_item]">\n
      <dtml-call expr="document_list.append(loop_item)">\n
    <dtml-else>\n
      <dtml-call expr="delete_list.append(loop_item)">\n
    </dtml-if>\n
  </dtml-in>\n
  <dtml-if expr="_.len(document_list) > 0">\n
REPLACE INTO\n
  full_text\n
VALUES\n
    <dtml-in prefix="loop" expr="document_list">\n
( \n
  <dtml-sqlvar expr="uid[loop_item]" type="int">,\n
  <dtml-sqlvar expr="SearchableText[loop_item]" type="string" optional>\n
)<dtml-unless sequence-end>,</dtml-unless>\n
    </dtml-in>\n
  </dtml-if>\n
  <dtml-if expr="_.len(delete_list) > 0">\n
<dtml-var sql_delimiter>\n
DELETE FROM\n
  full_text\n
WHERE uid IN\n
( \n
    <dtml-in prefix="loop" expr="delete_list">\n
  <dtml-sqlvar expr="uid[loop_item]" type="int"><dtml-unless sequence-end>,</dtml-unless>\n
    </dtml-in>\n
)\n
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
