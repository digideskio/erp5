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
            <value> <string>ts44308812.77</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>PlanarSpinner.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>﻿/*\r\n
 * (c) Copyright Ascensio System SIA 2010-2015\r\n
 *\r\n
 * This program is a free software product. You can redistribute it and/or \r\n
 * modify it under the terms of the GNU Affero General Public License (AGPL) \r\n
 * version 3 as published by the Free Software Foundation. In accordance with \r\n
 * Section 7(a) of the GNU AGPL its Section 15 shall be amended to the effect \r\n
 * that Ascensio System SIA expressly excludes the warranty of non-infringement\r\n
 * of any third-party rights.\r\n
 *\r\n
 * This program is distributed WITHOUT ANY WARRANTY; without even the implied \r\n
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR  PURPOSE. For \r\n
 * details, see the GNU AGPL at: http://www.gnu.org/licenses/agpl-3.0.html\r\n
 *\r\n
 * You can contact Ascensio System SIA at Lubanas st. 125a-25, Riga, Latvia,\r\n
 * EU, LV-1021.\r\n
 *\r\n
 * The  interactive user interfaces in modified source and object code versions\r\n
 * of the Program must display Appropriate Legal Notices, as required under \r\n
 * Section 5 of the GNU AGPL version 3.\r\n
 *\r\n
 * Pursuant to Section 7(b) of the License you must retain the original Product\r\n
 * logo when distributing the program. Pursuant to Section 7(e) we decline to\r\n
 * grant you any rights under trademark law for use of our trademarks.\r\n
 *\r\n
 * All the Product\'s GUI elements, including illustrations and icon sets, as\r\n
 * well as technical writing content are licensed under the terms of the\r\n
 * Creative Commons Attribution-ShareAlike 4.0 International. See the License\r\n
 * terms at http://creativecommons.org/licenses/by-sa/4.0/legalcode\r\n
 *\r\n
 */\r\n
 Ext.define("Common.component.PlanarSpinner", {\r\n
    extend: "Ext.field.Spinner",\r\n
    xtype: "planarspinnerfield",\r\n
    config: {},\r\n
    constructor: function () {\r\n
        var me = this;\r\n
        me.callParent(arguments);\r\n
        me.addCls("planar-spinner");\r\n
    },\r\n
    updateComponent: function (newComponent) {\r\n
        this.callParent(arguments);\r\n
        var innerElement = this.innerElement,\r\n
        cls = this.getCls();\r\n
        if (newComponent) {\r\n
            this.spinDownButton = Ext.widget("button", {\r\n
                cls: "x-button x-button-base " + cls + "-button " + cls + "-button-down",\r\n
                iconCls: "spinner-down"\r\n
            });\r\n
            this.spinUpButton = Ext.widget("button", {\r\n
                cls: "x-button x-button-base " + cls + "-button " + cls + "-button-up",\r\n
                iconCls: "spinner-up"\r\n
            });\r\n
            this.downRepeater = this.createRepeater(this.spinDownButton.element, this.onSpinDown);\r\n
            this.upRepeater = this.createRepeater(this.spinUpButton.element, this.onSpinUp);\r\n
        }\r\n
    },\r\n
    updateGroupButtons: function (newGroupButtons, oldGroupButtons) {\r\n
        var me = this,\r\n
        innerElement = me.innerElement,\r\n
        cls = me.getBaseCls() + "-grouped-buttons";\r\n
        me.getComponent();\r\n
        if (newGroupButtons != oldGroupButtons) {\r\n
            if (newGroupButtons) {\r\n
                this.addCls(cls);\r\n
                innerElement.insertFirst(me.spinDownButton.element);\r\n
                innerElement.appendChild(me.spinUpButton.element);\r\n
            } else {\r\n
                this.removeCls(cls);\r\n
                innerElement.insertFirst(me.spinDownButton.element);\r\n
                innerElement.appendChild(me.spinUpButton.element);\r\n
            }\r\n
        }\r\n
    }\r\n
});</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3368</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
