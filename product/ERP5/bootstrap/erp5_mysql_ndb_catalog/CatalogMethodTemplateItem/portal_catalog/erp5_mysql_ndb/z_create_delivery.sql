<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <tuple>
        <tuple>
          <string>Products.ZSQLMethods.SQL</string>
          <string>SQL</string>
        </tuple>
        <none/>
      </tuple>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>__ac_local_roles__</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>_arg</string> </key>
            <value>
              <object>
                <klass>
                  <global name="Args" module="Shared.DC.ZRDB.Aqueduct"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_data</string> </key>
                        <value>
                          <dictionary/>
                        </value>
                    </item>
                    <item>
                        <key> <string>_keys</string> </key>
                        <value>
                          <list/>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
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
            <value> <string></string> </value>
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
            <value> <string>z_create_delivery</string> </value>
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
            <value> <string>CREATE TABLE `delivery` (\n
  `uid` BIGINT UNSIGNED NOT NULL,\n
  `source_uid` BIGINT UNSIGNED default \'0\',\n
  `destination_uid` BIGINT UNSIGNED default \'0\',\n
  `source_section_uid` BIGINT UNSIGNED default \'0\',\n
  `destination_section_uid` BIGINT UNSIGNED default \'0\',\n
  `resource_uid` BIGINT UNSIGNED default \'0\',\n
  `start_date` datetime default NULL,\n
  `start_date_range_min` datetime default NULL,\n
  `start_date_range_max` datetime default NULL,\n
  `stop_date` datetime default NULL,\n
  `stop_date_range_min` datetime default NULL,\n
  `stop_date_range_max` datetime default NULL,\n
  PRIMARY KEY (`uid`),\n
  KEY `source_uid` (`source_uid`),\n
  KEY `destination_uid` (`destination_uid`),\n
  KEY `source_section_uid` (`source_section_uid`),\n
  KEY `destination_section_uid` (`destination_section_uid`),\n
  KEY `resource_uid` (`resource_uid`)\n
) TYPE=ndb\n
</string> </value>
        </item>
        <item>
            <key> <string>template</string> </key>
            <value>
              <object>
                <klass>
                  <global name="SQL" module="Shared.DC.ZRDB.DA"/>
                </klass>
                <none/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>__name__</string> </key>
                        <value> <string encoding="cdata"><![CDATA[

<string>

]]></string> </value>
                    </item>
                    <item>
                        <key> <string>_vars</string> </key>
                        <value>
                          <dictionary/>
                        </value>
                    </item>
                    <item>
                        <key> <string>globals</string> </key>
                        <value>
                          <dictionary/>
                        </value>
                    </item>
                    <item>
                        <key> <string>raw</string> </key>
                        <value> <string>CREATE TABLE `delivery` (\n
  `uid` BIGINT UNSIGNED NOT NULL,\n
  `source_uid` BIGINT UNSIGNED default \'0\',\n
  `destination_uid` BIGINT UNSIGNED default \'0\',\n
  `source_section_uid` BIGINT UNSIGNED default \'0\',\n
  `destination_section_uid` BIGINT UNSIGNED default \'0\',\n
  `resource_uid` BIGINT UNSIGNED default \'0\',\n
  `start_date` datetime default NULL,\n
  `start_date_range_min` datetime default NULL,\n
  `start_date_range_max` datetime default NULL,\n
  `stop_date` datetime default NULL,\n
  `stop_date_range_min` datetime default NULL,\n
  `stop_date_range_max` datetime default NULL,\n
  PRIMARY KEY (`uid`),\n
  KEY `source_uid` (`source_uid`),\n
  KEY `destination_uid` (`destination_uid`),\n
  KEY `source_section_uid` (`source_section_uid`),\n
  KEY `destination_section_uid` (`destination_section_uid`),\n
  KEY `resource_uid` (`resource_uid`)\n
) TYPE=ndb\n
</string> </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
