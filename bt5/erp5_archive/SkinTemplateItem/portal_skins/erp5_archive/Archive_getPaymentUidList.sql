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
                      <value> <string>payment_uid</string> </value>
                  </item>
                  <item>
                      <key> <string>null</string> </key>
                      <value> <int>1</int> </value>
                  </item>
                  <item>
                      <key> <string>type</string> </key>
                      <value> <string>l</string> </value>
                  </item>
                  <item>
                      <key> <string>width</string> </key>
                      <value> <int>4</int> </value>
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
            <value> <string>account_uid_list</string> </value>
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
            <value> <string>Archive_getPaymentUidList</string> </value>
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

select distinct(stock.payment_uid) \n
from stock \n
where \n
  (1)\n
  <dtml-if account_uid_list>\n
    and\n
    stock.payment_uid in (\n
     <dtml-in account_uid_list>\n
       <dtml-unless sequence-start>, </dtml-unless>\n
       <dtml-sqlvar sequence-item type="int">\n
     </dtml-in>\n
     ) \n
  </dtml-if>\n
  and stock.payment_uid is not NULL  \n
  and stock.payment_uid != ""

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
