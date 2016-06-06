<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="SQL" module="Products.ZSQLMethods.SQL"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Use_Database_Methods_Permission</string> </key>
            <value>
              <list>
                <string>Member</string>
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
            <value> <string>node_uid:list\r\n
section_uid:list\r\n
simulation_state:list\r\n
portal_type:list\r\n
at_date</string> </value>
        </item>
        <item>
            <key> <string>cache_time_</string> </key>
            <value> <int>0</int> </value>
        </item>
        <item>
            <key> <string>class_file_</string> </key>
            <value> <string>InventoryBrain</string> </value>
        </item>
        <item>
            <key> <string>class_name_</string> </key>
            <value> <string>MovementHistoryListBrain</string> </value>
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
            <value> <string>Base_zGetNotGroupedMovementList</string> </value>
        </item>
        <item>
            <key> <string>max_cache_</string> </key>
            <value> <int>100</int> </value>
        </item>
        <item>
            <key> <string>max_rows_</string> </key>
            <value> <int>10000000</int> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string encoding="cdata"><![CDATA[

<dtml-comment>Returns all movements <= at_date which does not have a grouping\n
reference or having a grouping reference with movements where date is after the\n
at_date. \n
\n
Here, a group of movement means:\n
 section_uid is from section_uid:list, or is the same if section_uid is not passed.\n
 mirror_section_uid is the same\n
 node_uid is the same\n
 grouping_reference is the same\n
\n
XXX now that grouping_date exists, this script will become useless.\n
Please consider using grouping date query with getMovementHistoryList instead of\n
using this obsolete script.\n
\n
</dtml-comment>\n
\n
( SELECT catalog.path as path,\n
         catalog.uid as uid,\n
         mirror_section.relative_url as mirror_section_relative_url,\n
         mirror_section.title as mirror_section_title,\n
         stock.mirror_section_uid,\n
         stock.date as date_utc,\n
         stock.node_uid as node_uid,\n
         IFNULL(stock.total_price, 0) as total_price,\n
         IFNULL(stock.quantity, 0) as total_quantity\n
\n
  FROM catalog, stock LEFT JOIN catalog AS mirror_section on \n
        ( stock.mirror_section_uid = mirror_section.uid )\n
\n
  WHERE stock.node_uid in (<dtml-in node_uid><dtml-var sequence-item>\n
         <dtml-unless sequence-end>, </dtml-unless></dtml-in>) and\n
       <dtml-if simulation_state>\n
        stock.simulation_state in (<dtml-in simulation_state>\n
            <dtml-sqlvar sequence-item type="string">\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in simulation_state> ) and\n
       </dtml-if>\n
        stock.portal_type in (<dtml-in portal_type>\n
            <dtml-sqlvar sequence-item type="string">\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in portal_type> ) and\n
       <dtml-if section_uid>\n
        stock.section_uid in (<dtml-in section_uid><dtml-var sequence-item>\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in section_uid> ) and\n
       </dtml-if>\n
        catalog.uid=stock.uid and\n
        stock.date <= <dtml-sqlvar "at_date" type="datetime"> and\n
        catalog.grouping_reference is NULL\n
) UNION (\n
  SELECT\n
      catalog.path as path,\n
      catalog.uid as uid,\n
      mirror_section.relative_url as mirror_section_relative_url,\n
      mirror_section.title as mirror_section_title,\n
      stock.mirror_section_uid,\n
      stock.date as date_utc,\n
      stock.node_uid as node_uid,\n
      IFNULL(stock.total_price, 0) as total_price,\n
      IFNULL(stock.quantity, 0) as total_quantity\n
\n
  FROM  catalog AS catalog_2, stock AS stock_2, \n
        catalog AS catalog, stock AS stock LEFT JOIN catalog AS mirror_section\n
        ON ( stock.mirror_section_uid = mirror_section.uid )\n
\n
  WHERE stock.node_uid in (<dtml-in node_uid><dtml-var sequence-item>\n
         <dtml-unless sequence-end>, </dtml-unless></dtml-in>) and\n
       <dtml-if simulation_state>\n
        stock.simulation_state in (<dtml-in simulation_state>\n
            <dtml-sqlvar sequence-item type="string">\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in simulation_state> ) and\n
       </dtml-if>\n
        stock.portal_type in (<dtml-in portal_type>\n
            <dtml-sqlvar sequence-item type="string">\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in portal_type> ) and\n
       <dtml-if section_uid>\n
        stock.section_uid in (<dtml-in section_uid><dtml-var sequence-item>\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in section_uid> ) and\n
       </dtml-if>\n
        stock.date <= <dtml-sqlvar "at_date" type="datetime"> and\n
        catalog.uid = stock.uid and\n
        catalog_2.uid = stock_2.uid and\n
        catalog.grouping_reference = catalog_2.grouping_reference and\n
        catalog.grouping_reference is not NULL and\n
       <dtml-if section_uid>\n
        stock_2.section_uid in (<dtml-in section_uid><dtml-var sequence-item>\n
         <dtml-unless sequence-end>, </dtml-unless> </dtml-in section_uid> ) and\n
       <dtml-else>\n
        stock_2.section_uid = stock.section_uid and\n
       </dtml-if>\n
        stock.mirror_section_uid = stock_2.mirror_section_uid and\n
        stock_2.simulation_state != \'cancelled\' and\n
        stock.node_uid = stock_2.node_uid\n
  GROUP BY catalog.uid, stock.uid\n
  HAVING max(stock_2.date) > <dtml-sqlvar "at_date" type="datetime">\n
)\n
\n
ORDER BY mirror_section_title, date_utc

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Obsolete.</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
