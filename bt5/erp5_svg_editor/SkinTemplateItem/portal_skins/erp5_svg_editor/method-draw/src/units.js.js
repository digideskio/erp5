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
            <value> <string>anonymous_http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts52851982.79</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>units.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/**\n
 * Package: svgedit.units\n
 *\n
 * Licensed under the Apache License, Version 2\n
 *\n
 * Copyright(c) 2010 Alexis Deveria\n
 * Copyright(c) 2010 Jeff Schiller\n
 */\n
\n
// Dependencies:\n
// 1) jQuery\n
\n
var svgedit = svgedit || {};\n
\n
(function() {\n
\n
if (!svgedit.units) {\n
  svgedit.units = {};\n
}\n
\n
var w_attrs = [\'x\', \'x1\', \'cx\', \'rx\', \'width\'];\n
var h_attrs = [\'y\', \'y1\', \'cy\', \'ry\', \'height\'];\n
var unit_attrs = $.merge([\'r\',\'radius\'], w_attrs);\n
\n
var unitNumMap = {\n
  \'%\':  2,\n
  \'em\': 3,\n
  \'ex\': 4,\n
  \'px\': 5,\n
  \'cm\': 6,\n
  \'mm\': 7,\n
  \'in\': 8,\n
  \'pt\': 9,\n
  \'pc\': 10\n
};\n
\n
$.merge(unit_attrs, h_attrs);\n
\n
// Container of elements.\n
var elementContainer_;\n
\n
/**\n
 * Stores mapping of unit type to user coordinates.\n
 */\n
var typeMap_ = {px: 1};\n
\n
/**\n
 * ElementContainer interface\n
 *\n
 * function getBaseUnit() - returns a string of the base unit type of the container ("em")\n
 * function getElement() - returns an element in the container given an id\n
 * function getHeight() - returns the container\'s height\n
 * function getWidth() - returns the container\'s width\n
 * function getRoundDigits() - returns the number of digits number should be rounded to\n
 */\n
\n
/**\n
 * Function: svgedit.units.init()\n
 * Initializes this module.\n
 *\n
 * Parameters:\n
 * elementContainer - an object implementing the ElementContainer interface.\n
 */\n
svgedit.units.init = function(elementContainer) {\n
  elementContainer_ = elementContainer;\n
\n
  var svgns = \'http://www.w3.org/2000/svg\';\n
\n
  // Get correct em/ex values by creating a temporary SVG.\n
  var svg = document.createElementNS(svgns, \'svg\');\n
  document.body.appendChild(svg);\n
  var rect = document.createElementNS(svgns,\'rect\');\n
  rect.setAttribute(\'width\',"1em");\n
  rect.setAttribute(\'height\',"1ex");\n
  rect.setAttribute(\'x\',"1in");\n
  svg.appendChild(rect);\n
  var bb = rect.getBBox();\n
  document.body.removeChild(svg);\n
\n
  var inch = bb.x;\n
  typeMap_[\'em\'] = bb.width;\n
  typeMap_[\'ex\'] = bb.height;\n
  typeMap_[\'in\'] = inch;\n
  typeMap_[\'cm\'] = inch / 2.54;\n
  typeMap_[\'mm\'] = inch / 25.4;\n
  typeMap_[\'pt\'] = inch / 72;\n
  typeMap_[\'pc\'] = inch / 6;\n
  typeMap_[\'%\'] = 0;\n
};\n
\n
// Group: Unit conversion functions\n
\n
// Function: svgedit.units.getTypeMap\n
// Returns the unit object with values for each unit\n
svgedit.units.getTypeMap = function() {\n
  return typeMap_;\n
};\n
\n
// Function: svgedit.units.shortFloat\n
// Rounds a given value to a float with number of digits defined in save_options\n
//\n
// Parameters: \n
// val - The value as a String, Number or Array of two numbers to be rounded\n
//\n
// Returns:\n
// If a string/number was given, returns a Float. If an array, return a string\n
// with comma-seperated floats\n
svgedit.units.shortFloat = function(val) {\n
  var digits = elementContainer_.getRoundDigits();\n
  if(!isNaN(val)) {\n
    // Note that + converts to Number\n
    return +((+val).toFixed(digits));\n
  } else if($.isArray(val)) {\n
    return svgedit.units.shortFloat(val[0]) + \',\' + svgedit.units.shortFloat(val[1]);\n
  }\n
  return parseFloat(val).toFixed(digits) - 0;\n
};\n
\n
// Function: svgedit.units.convertUnit\n
// Converts the number to given unit or baseUnit\n
svgedit.units.convertUnit = function(val, unit) {\n
  unit = unit || elementContainer_.getBaseUnit();\n
//  baseVal.convertToSpecifiedUnits(unitNumMap[unit]);\n
//  var val = baseVal.valueInSpecifiedUnits;\n
//  baseVal.convertToSpecifiedUnits(1);\n
  return svgedit.unit.shortFloat(val / typeMap_[unit]);\n
};\n
\n
// Function: svgedit.units.setUnitAttr\n
// Sets an element\'s attribute based on the unit in its current value.\n
//\n
// Parameters: \n
// elem - DOM element to be changed\n
// attr - String with the name of the attribute associated with the value\n
// val - String with the attribute value to convert\n
svgedit.units.setUnitAttr = function(elem, attr, val) {\n
  if(!isNaN(val)) {\n
    // New value is a number, so check currently used unit\n
    var old_val = elem.getAttribute(attr);\n
    \n
    // Enable this for alternate mode\n
//    if(old_val !== null && (isNaN(old_val) || elementContainer_.getBaseUnit() !== \'px\')) {\n
//      // Old value was a number, so get unit, then convert\n
//      var unit;\n
//      if(old_val.substr(-1) === \'%\') {\n
//        var res = getResolution();\n
//        unit = \'%\';\n
//        val *= 100;\n
//        if(w_attrs.indexOf(attr) >= 0) {\n
//          val = val / res.w;\n
//        } else if(h_attrs.indexOf(attr) >= 0) {\n
//          val = val / res.h;\n
//        } else {\n
//          return val / Math.sqrt((res.w*res.w) + (res.h*res.h))/Math.sqrt(2);\n
//        }\n
//      } else {\n
//        if(elementContainer_.getBaseUnit() !== \'px\') {\n
//          unit = elementContainer_.getBaseUnit();\n
//        } else {\n
//          unit = old_val.substr(-2);\n
//        }\n
//        val = val / typeMap_[unit];\n
//      }\n
//    \n
//    val += unit;\n
//    }\n
  }\n
  elem.setAttribute(attr, val);\n
};\n
\n
var attrsToConvert = {\n
  "line": [\'x1\', \'x2\', \'y1\', \'y2\'],\n
  "circle": [\'cx\', \'cy\', \'r\'],\n
  "ellipse": [\'cx\', \'cy\', \'rx\', \'ry\'],\n
  "foreignObject": [\'x\', \'y\', \'width\', \'height\'],\n
  "rect": [\'x\', \'y\', \'width\', \'height\'],\n
  "image": [\'x\', \'y\', \'width\', \'height\'],\n
  "use": [\'x\', \'y\', \'width\', \'height\'],\n
  "text": [\'x\', \'y\']\n
};\n
\n
// Function: svgedit.units.convertAttrs\n
// Converts all applicable attributes to the configured baseUnit\n
//\n
// Parameters:\n
// element - a DOM element whose attributes should be converted\n
svgedit.units.convertAttrs = function(element) {\n
  var elName = element.tagName;\n
  var unit = elementContainer_.getBaseUnit();\n
  var attrs = attrsToConvert[elName];\n
  if(!attrs) return;\n
  var len = attrs.length\n
  for(var i = 0; i < len; i++) {\n
    var attr = attrs[i];\n
    var cur = element.getAttribute(attr);\n
    if(cur) {\n
      if(!isNaN(cur)) {\n
        element.setAttribute(attr, (cur / typeMap_[unit]) + unit);\n
      } else {\n
        // Convert existing?\n
      }\n
    }\n
  }\n
};\n
\n
// Function: svgedit.units.convertToNum\n
// Converts given values to numbers. Attributes must be supplied in \n
// case a percentage is given\n
//\n
// Parameters:\n
// attr - String with the name of the attribute associated with the value\n
// val - String with the attribute value to convert\n
svgedit.units.convertToNum = function(attr, val) {\n
  // Return a number if that\'s what it already is\n
  if(!isNaN(val)) return val-0;\n
  \n
  if(val.substr(-1) === \'%\') {\n
    // Deal with percentage, depends on attribute\n
    var num = val.substr(0, val.length-1)/100;\n
    var width = elementContainer_.getWidth();\n
    var height = elementContainer_.getHeight();\n
    \n
    if(w_attrs.indexOf(attr) >= 0) {\n
      return num * width;\n
    } else if(h_attrs.indexOf(attr) >= 0) {\n
      return num * height;\n
    } else {\n
      return num * Math.sqrt((width*width) + (height*height))/Math.sqrt(2);\n
    }\n
  } else {\n
    var unit = val.substr(-2);\n
    var num = val.substr(0, val.length-2);\n
    // Note that this multiplication turns the string into a number\n
    return num * typeMap_[unit];\n
  }\n
};\n
\n
// Function: svgedit.units.isValidUnit\n
// Check if an attribute\'s value is in a valid format\n
//\n
// Parameters: \n
// attr - String with the name of the attribute associated with the value\n
// val - String with the attribute value to check\n
svgedit.units.isValidUnit = function(attr, val, selectedElement) {\n
  var valid = false;\n
  if(unit_attrs.indexOf(attr) >= 0) {\n
    // True if it\'s just a number\n
    if(!isNaN(val)) {\n
      valid = true;\n
    } else {\n
    // Not a number, check if it has a valid unit\n
      val = val.toLowerCase();\n
      $.each(typeMap_, function(unit) {\n
        if(valid) return;\n
        var re = new RegExp(\'^-?[\\\\d\\\\.]+\' + unit + \'$\');\n
        if(re.test(val)) valid = true;\n
      });\n
    }\n
  } else if (attr == "id") {\n
    // if we\'re trying to change the id, make sure it\'s not already present in the doc\n
    // and the id value is valid.\n
\n
    var result = false;\n
    // because getElem() can throw an exception in the case of an invalid id\n
    // (according to http://www.w3.org/TR/xml-id/ IDs must be a NCName)\n
    // we wrap it in an exception and only return true if the ID was valid and\n
    // not already present\n
    try {\n
      var elem = elementContainer_.getElement(val);\n
      result = (elem == null || elem === selectedElement);\n
    } catch(e) {}\n
    return result;\n
  } else {\n
    valid = true;\n
  }\n
  \n
  return valid;\n
};\n
\n
\n
})();

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>8165</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
