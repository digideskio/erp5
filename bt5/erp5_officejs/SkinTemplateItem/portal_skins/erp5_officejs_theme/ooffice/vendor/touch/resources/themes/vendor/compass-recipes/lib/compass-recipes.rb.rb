<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts44314673.14</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>compass-recipes.rb</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-ruby</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

require "compass"\n
\n
# for background_noise\n
require "chunky_png"\n
require "base64"\n
require File.join(File.dirname(__FILE__), \'compass-recipes\', \'sass_extensions\')\n
\n
Compass::Frameworks.register("recipes", :path => "#{File.dirname(__FILE__)}/..")

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>241</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
