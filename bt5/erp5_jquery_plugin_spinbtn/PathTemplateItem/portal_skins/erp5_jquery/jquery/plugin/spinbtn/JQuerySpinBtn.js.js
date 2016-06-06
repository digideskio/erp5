<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts80003855.5</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>JQuerySpinBtn.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/* SpinButton control\n
 *\n
 * Adds bells and whistles to any ordinary textbox to\n
 * make it look and feel like a SpinButton Control.\n
 *\n
 * Originally written by George Adamson, Software Unity (george.jquery@softwareunity.com) August 2006.\n
 * - Added min/max options\n
 * - Added step size option\n
 * - Added bigStep (page up/down) option\n
 *\n
 * Modifications made by Mark Gibson, (mgibson@designlinks.net) September 2006:\n
 * - Converted to jQuery plugin\n
 * - Allow limited or unlimited min/max values\n
 * - Allow custom class names, and add class to input element\n
 * - Removed global vars\n
 * - Reset (to original or through config) when invalid value entered\n
 * - Repeat whilst holding mouse button down (with initial pause, like keyboard repeat)\n
 * - Support mouse wheel in Firefox\n
 * - Fix double click in IE\n
 * - Refactored some code and renamed some vars\n
 *\n
 * Modifications by Jeff Schiller, June 2009:\n
 * - provide callback function for when the value changes based on the following\n
 *   http://www.mail-archive.com/jquery-en@googlegroups.com/msg36070.html\n
 * Modifications by Jeff Schiller, July 2009:\n
 * - improve styling for widget in Opera\n
 * - consistent key-repeat handling cross-browser\n
 * Modifications by Alexis Deveria, October 2009:\n
 * - provide "stepfunc" callback option to allow custom function to run when changing a value\n
 * - Made adjustValue(0) only run on certain keyup events, not all.\n
 *\n
 * Tested in IE6, Opera9, Firefox 1.5\n
 * v1.0  11 Aug 2006 - George Adamson\t- First release\n
 * v1.1     Aug 2006 - George Adamson\t- Minor enhancements\n
 * v1.2  27 Sep 2006 - Mark Gibson\t\t- Major enhancements\n
 * v1.3a 28 Sep 2006 - George Adamson\t- Minor enhancements\n
 * v1.4  18 Jun 2009 - Jeff Schiller    - Added callback function\n
 * v1.5  06 Jul 2009 - Jeff Schiller    - Fixes for Opera.  \n
 * v1.6  13 Oct 2009 - Alexis Deveria   - Added stepfunc function  \n
 * v1.7  21 Oct 2009 - Alexis Deveria   - Minor fixes\n
 *                                        Fast-repeat for keys and live updating as you type.\n
 * v1.8  12 Jan 2010 - Benjamin Thomas  - Fixes for mouseout behavior.\n
 *                                        Added smallStep\n
 \n
 Sample usage:\n
 \n
\t// Create group of settings to initialise spinbutton(s). (Optional)\n
\tvar myOptions = {\n
\t\t\t\t\tmin: 0,\t\t\t\t\t\t// Set lower limit.\n
\t\t\t\t\tmax: 100,\t\t\t\t\t// Set upper limit.\n
\t\t\t\t\tstep: 1,\t\t\t\t\t// Set increment size.\n
\t\t\t\t\tsmallStep: 0.5,\t\t\t\t// Set shift-click increment size.\n
\t\t\t\t\tspinClass: mySpinBtnClass,\t// CSS class to style the spinbutton. (Class also specifies url of the up/down button image.)\n
\t\t\t\t\tupClass: mySpinUpClass,\t\t// CSS class for style when mouse over up button.\n
\t\t\t\t\tdownClass: mySpinDnClass\t// CSS class for style when mouse over down button.\n
\t\t\t\t\t}\n
 \n
\t$(document).ready(function(){\n
\n
\t\t// Initialise INPUT element(s) as SpinButtons: (passing options if desired)\n
\t\t$("#myInputElement").SpinButton(myOptions);\n
\n
\t});\n
 \n
 */\n
$.fn.SpinButton = function(cfg){\n
\treturn this.each(function(){\n
\n
\t\tthis.repeating = false;\n
\t\t\n
\t\t// Apply specified options or defaults:\n
\t\t// (Ought to refactor this some day to use $.extend() instead)\n
\t\tthis.spinCfg = {\n
\t\t\t//min: cfg && cfg.min ? Number(cfg.min) : null,\n
\t\t\t//max: cfg && cfg.max ? Number(cfg.max) : null,\n
\t\t\tmin: cfg && !isNaN(parseFloat(cfg.min)) ? Number(cfg.min) : null,\t// Fixes bug with min:0\n
\t\t\tmax: cfg && !isNaN(parseFloat(cfg.max)) ? Number(cfg.max) : null,\n
\t\t\tstep: cfg && cfg.step ? Number(cfg.step) : 1,\n
\t\t\tstepfunc: cfg && cfg.stepfunc ? cfg.stepfunc : false,\n
\t\t\tpage: cfg && cfg.page ? Number(cfg.page) : 10,\n
\t\t\tupClass: cfg && cfg.upClass ? cfg.upClass : \'up\',\n
\t\t\tdownClass: cfg && cfg.downClass ? cfg.downClass : \'down\',\n
\t\t\treset: cfg && cfg.reset ? cfg.reset : this.value,\n
\t\t\tdelay: cfg && cfg.delay ? Number(cfg.delay) : 500,\n
\t\t\tinterval: cfg && cfg.interval ? Number(cfg.interval) : 100,\n
\t\t\t_btn_width: 20,\n
\t\t\t_direction: null,\n
\t\t\t_delay: null,\n
\t\t\t_repeat: null,\n
\t\t\tcallback: cfg && cfg.callback ? cfg.callback : null\n
\t\t};\n
\n
\t\t// if a smallStep isn\'t supplied, use half the regular step\n
\t\tthis.spinCfg.smallStep = cfg && cfg.smallStep ? cfg.smallStep : this.spinCfg.step/2;\n
\t\t\n
\t\tthis.adjustValue = function(i){\n
\t\t\tvar v;\n
\t\t\tif(isNaN(this.value)) {\n
\t\t\t\tv = this.spinCfg.reset;\n
\t\t\t} else if($.isFunction(this.spinCfg.stepfunc)) {\n
\t\t\t\tv = this.spinCfg.stepfunc(this, i);\n
\t\t\t} else {\n
\t\t\t\t// weirdest javascript bug ever: 5.1 + 0.1 = 5.199999999\n
\t\t\t\tv = Number((Number(this.value) + Number(i)).toFixed(5));\n
\t\t\t}\n
\t\t\tif (this.spinCfg.min !== null) v = Math.max(v, this.spinCfg.min);\n
\t\t\tif (this.spinCfg.max !== null) v = Math.min(v, this.spinCfg.max);\n
\t\t\tthis.value = v;\n
\t\t\tif ($.isFunction(this.spinCfg.callback)) this.spinCfg.callback(this);\n
\t\t};\n
\t\t\n
\t\t$(this)\n
\t\t.addClass(cfg && cfg.spinClass ? cfg.spinClass : \'spin-button\')\n
\t\t\n
\t\t.mousemove(function(e){\n
\t\t\t// Determine which button mouse is over, or not (spin direction):\n
\t\t\tvar x = e.pageX || e.x;\n
\t\t\tvar y = e.pageY || e.y;\n
\t\t\tvar el = e.target || e.srcElement;\n
\t\t\tvar height = $(el).outerHeight()/2;\n
\t\t\tvar direction = \n
\t\t\t\t(x > coord(el,\'offsetLeft\') + el.offsetWidth - this.spinCfg._btn_width)\n
\t\t\t\t? ((y < coord(el,\'offsetTop\') + height) ? 1 : -1) : 0;\n
\t\t\t\n
\t\t\tif (direction !== this.spinCfg._direction) {\n
\t\t\t\t// Style up/down buttons:\n
\t\t\t\tswitch(direction){\n
\t\t\t\t\tcase 1: // Up arrow:\n
\t\t\t\t\t\t$(this).removeClass(this.spinCfg.downClass).addClass(this.spinCfg.upClass);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tcase -1: // Down arrow:\n
\t\t\t\t\t\t$(this).removeClass(this.spinCfg.upClass).addClass(this.spinCfg.downClass);\n
\t\t\t\t\t\tbreak;\n
\t\t\t\t\tdefault: // Mouse is elsewhere in the textbox\n
\t\t\t\t\t\t$(this).removeClass(this.spinCfg.upClass).removeClass(this.spinCfg.downClass);\n
\t\t\t\t}\n
\t\t\t\t\n
\t\t\t\t// Set spin direction:\n
\t\t\t\tthis.spinCfg._direction = direction;\n
\t\t\t}\n
\t\t})\n
\t\t\n
\t\t.mouseout(function(){\n
\t\t\t// Reset up/down buttons to their normal appearance when mouse moves away:\n
\t\t\t$(this).removeClass(this.spinCfg.upClass).removeClass(this.spinCfg.downClass);\n
\t\t\tthis.spinCfg._direction = null;\n
\t\t\twindow.clearInterval(this.spinCfg._repeat);\n
\t\t\twindow.clearTimeout(this.spinCfg._delay);\n
\t\t})\n
\t\t\n
\t\t.mousedown(function(e){\n
\t\t\tif ( e.button === 0 && this.spinCfg._direction != 0) {\n
\t\t\t\t// Respond to click on one of the buttons:\n
\t\t\t\tvar self = this;\n
\t\t\t\tvar stepSize = e.shiftKey ? self.spinCfg.smallStep : self.spinCfg.step\n
\n
\t\t\t\tvar adjust = function() {\n
\t\t\t\t\tself.adjustValue(self.spinCfg._direction * stepSize);\n
\t\t\t\t};\n
\t\t\t\n
\t\t\t\tadjust();\n
\t\t\t\t\n
\t\t\t\t// Initial delay before repeating adjustment\n
\t\t\t\tself.spinCfg._delay = window.setTimeout(function() {\n
\t\t\t\t\tadjust();\n
\t\t\t\t\t// Repeat adjust at regular intervals\n
\t\t\t\t\tself.spinCfg._repeat = window.setInterval(adjust, self.spinCfg.interval);\n
\t\t\t\t}, self.spinCfg.delay);\n
\t\t\t}\n
\t\t})\n
\t\t\n
\t\t.mouseup(function(e){\n
\t\t\t// Cancel repeating adjustment\n
\t\t\twindow.clearInterval(this.spinCfg._repeat);\n
\t\t\twindow.clearTimeout(this.spinCfg._delay);\n
\t\t})\n
\t\t\n
\t\t.dblclick(function(e) {\n
\t\t\tif ($.browser.msie)\n
\t\t\t\tthis.adjustValue(this.spinCfg._direction * this.spinCfg.step);\n
\t\t})\n
\t\t\n
\t\t.keydown(function(e){\n
\t\t\t// Respond to up/down arrow keys.\n
\t\t\tswitch(e.keyCode){\n
\t\t\t\tcase 38: this.adjustValue(this.spinCfg.step);  break; // Up\n
\t\t\t\tcase 40: this.adjustValue(-this.spinCfg.step); break; // Down\n
\t\t\t\tcase 33: this.adjustValue(this.spinCfg.page);  break; // PageUp\n
\t\t\t\tcase 34: this.adjustValue(-this.spinCfg.page); break; // PageDown\n
\t\t\t}\n
\t\t})\n
\t\t\n
\t\t/*\n
\t\thttp://unixpapa.com/js/key.html describes the current state-of-affairs for\n
\t\tkey repeat events:\n
\t\t- Safari 3.1 changed their model so that keydown is reliably repeated going forward\n
\t\t- Firefox and Opera still only repeat the keypress event, not the keydown\n
\t\t*/\n
\t\t.keypress(function(e){\n
\t\t\tif (this.repeating) {\n
\t\t\t\t// Respond to up/down arrow keys.\n
\t\t\t\tswitch(e.keyCode){\n
\t\t\t\t\tcase 38: this.adjustValue(this.spinCfg.step);  break; // Up\n
\t\t\t\t\tcase 40: this.adjustValue(-this.spinCfg.step); break; // Down\n
\t\t\t\t\tcase 33: this.adjustValue(this.spinCfg.page);  break; // PageUp\n
\t\t\t\t\tcase 34: this.adjustValue(-this.spinCfg.page); break; // PageDown\n
\t\t\t\t}\n
\t\t\t} \n
\t\t\t// we always ignore the first keypress event (use the keydown instead)\n
\t\t\telse {\n
\t\t\t\tthis.repeating = true;\n
\t\t\t}\n
\t\t})\n
\t\t\n
\t\t// clear the \'repeating\' flag\n
\t\t.keyup(function(e) {\n
\t\t\tthis.repeating = false;\n
\t\t\tswitch(e.keyCode){\n
\t\t\t\tcase 38: // Up\n
\t\t\t\tcase 40: // Down\n
\t\t\t\tcase 33: // PageUp\n
\t\t\t\tcase 34: // PageDown\n
\t\t\t\tcase 13: this.adjustValue(0); break; // Enter/Return\n
\t\t\t}\n
\t\t})\n
\t\t\n
\t\t.bind("mousewheel", function(e){\n
\t\t\t// Respond to mouse wheel in IE. (It returns up/dn motion in multiples of 120)\n
\t\t\tif (e.wheelDelta >= 120)\n
\t\t\t\tthis.adjustValue(this.spinCfg.step);\n
\t\t\telse if (e.wheelDelta <= -120)\n
\t\t\t\tthis.adjustValue(-this.spinCfg.step);\n
\t\t\t\n
\t\t\te.preventDefault();\n
\t\t})\n
\t\t\n
\t\t.change(function(e){\n
\t\t\tthis.adjustValue(0);\n
\t\t});\n
\t\t\n
\t\tif (this.addEventListener) {\n
\t\t\t// Respond to mouse wheel in Firefox\n
\t\t\tthis.addEventListener(\'DOMMouseScroll\', function(e) {\n
\t\t\t\tif (e.detail > 0)\n
\t\t\t\t\tthis.adjustValue(-this.spinCfg.step);\n
\t\t\t\telse if (e.detail < 0)\n
\t\t\t\t\tthis.adjustValue(this.spinCfg.step);\n
\t\t\t\t\n
\t\t\t\te.preventDefault();\n
\t\t\t}, false);\n
\t\t}\n
\t});\n
\t\n
\tfunction coord(el,prop) {\n
\t\tvar c = el[prop], b = document.body;\n
\t\t\n
\t\twhile ((el = el.offsetParent) && (el != b)) {\n
\t\t\tif (!$.browser.msie || (el.currentStyle.position != \'relative\'))\n
\t\t\t\tc += el[prop];\n
\t\t}\n
\t\t\n
\t\treturn c;\n
\t}\n
};\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>9261</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
