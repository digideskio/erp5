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
                      <value> <string>uid</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>0</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>l</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>0</int> </value>
                  </item>
                </dictionary>
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
                      <value> <int>0</int> </value>
                  </item>
                </dictionary>
                <dictionary>
                  <item>
                      <key> <string>name</string> </key>
                      <value> <string>title</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>1</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>t</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>0</int> </value>
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
            <value> <string>context\r\n
</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string>ZSQLCatalog.zsqlbrain</string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string>ZSQLBrain</string> </value>
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
            <value> <string>FooModule_zGetModifiedFooList</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

SELECT\n
  uid, path, CONCAT(\'Foo \', title) AS title\n
FROM\n
  catalog\n
WHERE\n
  portal_type = \'Foo\'\n
  AND parent_uid = <dtml-var "context.getUid()">\n
ORDER BY\n
  id\n
LIMIT 1000\n


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
