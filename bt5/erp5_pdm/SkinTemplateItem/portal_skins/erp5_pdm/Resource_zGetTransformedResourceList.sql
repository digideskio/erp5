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
                      <value> <int>23</int> </value>
                  </item>
                </dictionary>
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
                      <value> <int>5</int> </value>
                  </item>
                </dictionary>
              </list>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string>resource_uid</string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Resource_zGetTransformedResourceList</string> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

select distinct\n
  catalog.uid, catalog.relative_url, catalog.title\n
from\n
  transformation \n
join \n
  catalog on transformation.transformed_uid=catalog.uid\n
\n
where\n
  <dtml-sqltest resource_uid column="transformation.uid" type=int multiple>

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
