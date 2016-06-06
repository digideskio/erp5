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
            <value> <string>isDelivery\r\n
uid\r\n
getSourceUid\r\n
getDestinationUid\r\n
getSourceSectionUid\r\n
getDestinationSectionUid\r\n
getResourceUid\r\n
getStartDate\r\n
getStartDateRangeMin\r\n
getStartDateRangeMax\r\n
getStopDate\r\n
getStopDateRangeMin\r\n
getStopDateRangeMax</string> </value>
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
            <value> <string>z_catalog_delivery_list</string> </value>
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

<dtml-let delivery_list="[]">\n
  <dtml-in prefix="loop" expr="_.range(_.len(uid))">\n
    <dtml-if "isDelivery[loop_item]">\n
      <dtml-call expr="delivery_list.append(loop_item)">\n
    </dtml-if>\n
  </dtml-in>\n
  <dtml-if expr="_.len(delivery_list) > 0">\n
REPLACE INTO\n
  delivery\n
VALUES\n
    <dtml-in prefix="loop" expr="delivery_list">\n
( \n
  <dtml-sqlvar expr="uid[loop_item]" type="int">,\n
  <dtml-sqlvar expr="getSourceUid[loop_item]" type="int" optional>,\n
  <dtml-sqlvar expr="getDestinationUid[loop_item]" type="int" optional>,\n
  <dtml-sqlvar expr="getSourceSectionUid[loop_item]" type="int" optional>,\n
  <dtml-sqlvar expr="getDestinationSectionUid[loop_item]" type="int" optional>,\n
  <dtml-sqlvar expr="getResourceUid[loop_item]" type="int" optional>,\n
  <dtml-sqlvar expr="getStartDate[loop_item]" type="datetime" optional>,\n
  <dtml-sqlvar expr="getStartDateRangeMin[loop_item]" type="datetime" optional>,\n
  <dtml-sqlvar expr="getStartDateRangeMax[loop_item]" type="datetime" optional>,\n
  <dtml-sqlvar expr="getStopDate[loop_item]" type="datetime" optional>,\n
  <dtml-sqlvar expr="getStopDateRangeMin[loop_item]" type="datetime" optional>,\n
  <dtml-sqlvar expr="getStopDateRangeMax[loop_item]" type="datetime" optional>\n
)\n
<dtml-if sequence-end><dtml-else>,</dtml-if>\n
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
