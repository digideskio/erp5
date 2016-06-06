<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_col</string> </key>
            <value>
              <list>
                <dictionary>
                  <item>
                      <key> <string>name</string> </key>
                      <value> <string>path</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>0</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>t</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>24</int> </value>
                  </item>
                </dictionary>
              </list>
            </value>
        </item>
        <item>
            <key> <string>allow_simple_one_argument_traversal</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>delta:int=0</string> </value>
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
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_zGetLatestIndexedObjectList</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

SELECT\n
  uid, path\n
FROM\n
  catalog\n
WHERE\n
  path != \'reserved\'\n
  AND CURRENT_TIMESTAMP - indexation_timestamp <= <dtml-sqlvar delta type="int">\n
ORDER BY\n
  indexation_timestamp DESC

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
