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
              <tuple/>
            </value>
        </item>
        <item>
            <key> <string>arguments_src</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>connection_id</string> </key>
            <value> <string>erp5_sql_connection</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>z_create_versioning</string> </value>
        </item>
        <item>
            <key> <string>src</string> </key>
            <value> <string>CREATE TABLE `versioning` (\n
  `uid` BIGINT UNSIGNED NOT NULL,\n
  `version` varchar(10) default \'\',\n
  `language` varchar(5) default \'\',\n
  `revision` varchar(10) default \'\',\n
  `subject_set_uid` INT UNSIGNED,\n
  `effective_date` datetime default NULL,\n
  `expiration_date` datetime default NULL,\n
  `creation_date_index` INT,\n
  `frequency_index` INT,\n
  PRIMARY KEY  (`uid`),\n
  KEY `version` (`version`),\n
  KEY `language` (`language`),\n
  KEY `subject_set_uid` (`subject_set_uid`),\n
  KEY `effective_date` (`effective_date`),\n
  KEY `expiration_date` (`expiration_date`),\n
  KEY `frequency_index` (`creation_date_index`, `frequency_index`)\n
) ENGINE=InnoDB;\n
</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
