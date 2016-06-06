<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="DTMLMethod" module="OFS.DTMLMethod"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>BespinEmbedded.js</string> </value>
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
            <value> <string encoding="cdata"><![CDATA[

/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
if (typeof(bespin) === \'undefined\') {\n
    bespin = {};\n
}\n
\n
if (typeof(document) !== \'undefined\') {\n
    var link = document.getElementById("bespin_base");\n
    if (link) {\n
        var href = link.href;\n
        bespin.base = href.substring(href.length - 1) !== "/" ? href + "/" : href;\n
    } else {\n
        bespin.base = "";\n
    }\n
}\n
\n
\n
(function() {\n
/*! @license\n
==========================================================================\n
Tiki 1.0 - CommonJS Runtime\n
copyright 2009-2010, Apple Inc., Sprout Systems Inc., and contributors.\n
\n
Permission is hereby granted, free of charge, to any person obtaining a \n
copy of this software and associated documentation files (the "Software"), \n
to deal in the Software without restriction, including without limitation \n
the rights to use, copy, modify, merge, publish, distribute, sublicense, \n
and/or sell copies of the Software, and to permit persons to whom the \n
Software is furnished to do so, subject to the following conditions:\n
\n
The above copyright notice and this permission notice shall be included in \n
all copies or substantial portions of the Software.\n
\n
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR \n
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, \n
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE \n
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER \n
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING \n
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER \n
DEALINGS IN THE SOFTWARE.\n
\n
Tiki is part of the SproutCore project.\n
\n
SproutCore and the SproutCore logo are trademarks of Sprout Systems, Inc.\n
\n
For more information visit http://www.sproutcore.com/tiki\n
\n
==========================================================================\n
@license */\n
\n
/*globals tiki ENV ARGV ARGS */\n
\n
"use modules false";\n
"use loader false";\n
\n
/**\n
  Implements a very simple handler for the loader registration API so that\n
  additional scripts can load without throwing exceptions.  This loader can\n
  also return module instances for modules registered with an actual factory\n
  function.\n
  \n
  Note that this stub loader cannot be used on its own.  You must load the \n
  regular tiki package as well, which will replace this loader as soon as it\n
  is fetched.\n
*/\n
if ("undefined" === typeof tiki) { var tiki = function() {\n
  \n
  var T_UNDEFINED = \'undefined\',\n
      queue = [];\n
        \n
  // save a registration method in a queue to be replayed later once the \n
  // real loader is available.\n
  function _record(method, args) {\n
    queue.push({ m: method, a: args });\n
  }\n
  \n
  var tiki = {\n
    \n
    // used to detect when real loader should replace this one\n
    isBootstrap: true,\n
    \n
    // log of actions to be replayed later\n
    queue: queue, \n
    \n
    // helpers just record into queue\n
    register: function(packageId, opts) { \n
      \n
      // this hack will make unit tests work for tiki by adding core_test to\n
      // the list of dependencies.\n
      if (packageId.match(/^tiki/) && this.ENV) {\n
        if ((this.ENV.app === \'tiki\') && (this.ENV.mode === \'test\')) {\n
          if (!opts.dependencies) opts.dependencies = {};\n
          opts.dependencies[\'core_test\'] = \'~\';\n
        }\n
      }\n
      \n
      _record(\'register\', arguments);\n
       return this;  \n
    },\n
    \n
    // Keep these around just in case we need them in the end...\n
    // script:   function() { \n
    //   _record(\'script\', arguments); \n
    //   return this; \n
    // },\n
    // \n
    // stylesheet: function() { \n
    //   _record(\'stylesheet\', arguments); \n
    //   return this; \n
    // },\n
\n
    // modules actually get saved as well a recorded so you can use them.\n
    module: function(moduleId, factory) {\n
      if (moduleId.match(/\\:tiki$/)) this.tikiFactory = factory;\n
      _record(\'module\', arguments);\n
      return this ;\n
    },\n
\n
    // load the tikiFactory \n
    start: function() {\n
      var exp = {}, ret;\n
      this.tikiFactory(null, exp, null); // no require or module!\n
      ret = exp.Browser.start(this.ENV, this.ARGS, queue);\n
      queue = null;\n
      return ret ;\n
    }\n
    \n
  };\n
  \n
  if (T_UNDEFINED !== typeof ENV) tiki.ENV = ENV;\n
  if (T_UNDEFINED !== typeof ARGV) tiki.ARGS = ARGV; // for older versions\n
  if (T_UNDEFINED !== typeof ARGS) tiki.ARGS = ARGS;\n
  \n
  return tiki;\n
  \n
}(); }\n
\n
\n
tiki.register(\'::tiki/1.0.0\', {\n
"name": "tiki",\n
"version": "1.0.0"\n
});\n
\n
tiki.module(\'::tiki/1.0.0:tiki\', function(require, exports, module) {\n
// ==========================================================================\n
// Project:   Tiki - CommonJS Runtime\n
// Copyright: ©2009-2010 Apple Inc. All rights reserved.\n
// License:   Licened under MIT license (see __preamble__.js)\n
// ==========================================================================\n
/*jslint evil:true */\n
\n
/**\n
  @file \n
  \n
  This file implements the core building blocks needed to implement the \n
  tiki runtime in an environment.  If you can require this one module, you can\n
  setup a runtime that will load additional packages.\n
  \n
  It is important that this module NOT require() any other modules since a\n
  functioning require() statement may not be available.  The module can \n
  populate, but not replace, the exports object.\n
\n
  To configure a Tiki runtime, you need to create a Sandbox and Loader \n
  instance from this API with one or more loader Sources.  The BrowserSource\n
  object implements the basic source you need to work in the browser.  The\n
  Repository object implemented in the server-side only \'file\' API can be \n
  used to load from a local repository of packages.\n
*/\n
\n
// used for type checking.  This allows the type strings to be minified.\n
var T_FUNCTION = \'function\',\n
    T_STRING   = \'string\',\n
    T_UNDEFINED = \'undefined\';\n
    \n
    \n
var IS_CANONICAL = /^::/; // must begin with ::\n
var isCanonicalId = function(id) {\n
  return !!IS_CANONICAL.exec(id);\n
};  \n
\n
var DEBUG = function() {\n
  exports.debug.apply(this, arguments);\n
};\n
\n
exports.debug = function() {\n
  var msg = Array.prototype.join.call(arguments, \'\');\n
  require(\'sys\').debug(msg);\n
};\n
\n
// ..........................................................\n
// CORE UTILITIES\n
// \n
\n
var TMP_ARY = [];\n
\n
/**\n
  Tests whether the passed object is an array or not.\n
*/\n
var isArray;\n
\n
if (Array.isArray) {\n
  isArray = Array.isArray;\n
} else {\n
  isArray = function(obj) {\n
    if (\'object\' !== typeof obj) return false;\n
    if (obj instanceof Array) return true;\n
    return obj.constructor && (obj.constructor.name===\'Array\');\n
  };\n
}\n
exports.isArray = isArray;\n
\n
/**\n
  Create a new object with the passed object as the prototype.\n
*/\n
var createObject;\n
if (Object.create) {\n
  createObject = Object.create;\n
} else {\n
  var K = function() {},\n
      Kproto = K.prototype;\n
  createObject = function(obj) {\n
    if (!obj) obj = Object.prototype;\n
    K.prototype = obj;\n
    \n
    var ret = new K();\n
    ret.prototype = obj;\n
    K.prototype = Kproto;\n
    \n
    return ret ;\n
  };\n
}\n
exports.createObject = createObject;\n
\n
var _constructor, _extend, extend;\n
\n
// returns a new constructor function with clean closure...\n
_constructor = function() {\n
  return function() {\n
    if (this.init) return this.init.apply(this, arguments);\n
    else return this;\n
  };\n
};\n
\n
_extend = function() {\n
  return extend(this);\n
};\n
\n
/**\n
  Creates a "subclass" of the passed constructor.  The default constructor\n
  will call look for a local "init" method and call it.\n
  \n
  If you don\'t pass an initial constructor, this will create a new based \n
  object.\n
*/\n
extend = function(Constructor) {\n
  var Ret = _constructor();\n
  Ret.prototype = createObject(Constructor.prototype);\n
  Ret.prototype.constructor = Ret;\n
  Ret.super_ = Constructor;\n
  Ret.extend = _extend;\n
  return Ret;\n
};\n
exports.extend = extend;\n
\n
/**\n
  Invokes the passed fn on each item in the array in parallel.  Invokes\n
  done when finished.\n
  \n
  # Example\n
  \n
      parallel([1,2,3], function(item, done) {\n
        // do something with item\n
        done();\n
      })(function(err) {\n
        // invoked when done, err if there was an error\n
      });\n
      \n
  @param {Array} array \n
    items to iterate\n
    \n
  @param {Function} fn\n
    callback to invoke\n
    \n
  @returns {void}\n
*/\n
var parallel = function(array, fn) {\n
  if (fn && !fn.displayName) fn.displayName = \'parallel#fn\';\n
  \n
  return function(done) {\n
    if (array.length === 0) return done(null, []);\n
    \n
    var len = array.length,\n
        cnt = len,\n
        cancelled = false,\n
        idx;\n
\n
    var tail = function(err) {\n
      if (cancelled) return; // nothing to do\n
\n
      if (err) {\n
        cancelled = true;\n
        return done(err);\n
      }\n
\n
      if (--cnt <= 0) done(); \n
    };\n
    tail.displayName = \'parallel#tail\';\n
\n
    for(idx=0;idx<len;idx++) fn(array[idx], tail);\n
  };\n
};\n
parallel.displayName = \'parallel\';\n
\n
/**\n
  @private\n
  \n
  Implements the sync map() on all platforms\n
*/\n
var map;\n
if (Array.prototype.map) {\n
  map = function(array, fn) {\n
    return array.map(fn);\n
  };\n
\n
} else {\n
  map = function(array, fn) {\n
    var idx, len = array.length, ret = [];\n
    for(idx=0;idx<len;idx++) {\n
      ret[idx] = fn(array[idx], idx);\n
    }\n
    return ret ;\n
  };\n
}\n
map.displayName = \'map\';\n
\n
\n
var PENDING = \'pending\',\n
    READY   = \'ready\',\n
    RUNNING = \'running\';\n
    \n
/**\n
  Returns a function that will execute the continuable exactly once and \n
  then cache the result.  Invoking the same return function more than once\n
  will simply return the old result. \n
  \n
  This is a good replacement for promises in many cases.\n
  \n
  h3. Example\n
  \n
  {{{\n
    // load a file only once\n
    var loadit = Co.once(Co.fs.loadFile(pathToFile));\n
\n
    loadit(function(content) { \n
      // loads the file\n
    });\n
    \n
    loadit(function(content) {\n
      // if already loaded, just invokes with past content\n
    });\n
    \n
  }}}\n
  \n
  @param {Function} cont\n
    Continuable to invoke \n
    \n
  @returns {Function} \n
    A new continuable that will only execute once then returns the cached\n
    result.\n
*/\n
var once = function(action, context) {\n
  var state = PENDING,\n
      queue = [],\n
      makePending = false,\n
      args  = null;\n
\n
  var ret = function(callback) {\n
    if (!context) context = this;\n
    \n
    // cont has already finished, just invoke callback based on result\n
    switch(state) {\n
      \n
      // already resolved, invoke callback immediately\n
      case READY:\n
        callback.apply(null, args);\n
        break;\n
\n
      // action has started running but hasn\'t finished yet\n
      case RUNNING:\n
        queue.push(callback);\n
        break;\n
        \n
      // action has not started yet\n
      case PENDING:\n
        queue.push(callback);\n
        state = RUNNING;\n
\n
        action.call(context, function(err) {\n
          args  = Array.prototype.slice.call(arguments);\n
          \n
          var oldQueue = queue, oldArgs = args;\n
\n
          if (makePending) {\n
            state = PENDING;\n
            queue = [];\n
            args  = null; \n
            makePending = false;\n
\n
          } else {\n
            state = READY;\n
            queue = null;\n
          }\n
          \n
          if (oldQueue) {\n
            oldQueue.forEach(function(q) { q.apply(null, oldArgs); });\n
          }\n
        });\n
        break;\n
    }\n
    return this;\n
  };\n
  ret.displayName = \'once#handler\';\n
\n
  // allow the action to be reset so it is called again\n
  ret.reset = function() {\n
    switch(state) {\n
      \n
      // already run, need to reset\n
      case READY: \n
        state = PENDING;\n
        queue = [];\n
        args  = null;\n
        break;\n
        \n
      // in process - set makePending so that resolving will reset to pending\n
      case RUNNING:\n
        makePending = true;\n
        break;\n
        \n
      // otherwise ignore pending since there is nothing to reset\n
    }\n
  };\n
  ret.reset.displayName = \'once#handler.reset\';\n
  \n
  return ret ;\n
};\n
exports.once = once;\n
\n
\n
/**\n
  Iterate over a property, setting display names on functions as needed.\n
  Call this on your own exports to setup display names for debugging.\n
*/\n
var displayNames = function(obj, root) {\n
  var k,v;\n
  for(k in obj) {\n
    if (!obj.hasOwnProperty(k)) continue ;\n
    v = obj[k];\n
    if (\'function\' === typeof v) {\n
      if (!v.displayName) {\n
        v.displayName = root ? (root+\'.\'+k) : k;\n
        displayNames(v.prototype, v.displayName);\n
      }\n
      \n
    }\n
  }\n
  return obj;\n
};\n
\n
// ..........................................................\n
// ERRORS\n
// \n
\n
var NotFound = extend(Error);\n
NotFound.prototype.init = function(canonicalId, pkgId) {\n
  var msg = canonicalId+\' not found\';\n
  if (pkgId) {\n
    if (T_STRING === typeof pkgId) msg = msg+\' \'+pkgId;\n
    else msg = msg+\' in package \'+(pkgId.id || \'(unknown)\');\n
  }\n
  this.message = msg;\n
  return this;\n
};\n
exports.NotFound = NotFound;\n
\n
var InvalidPackageDef = extend(Error);\n
InvalidPackageDef.prototype.init = function(def, reason) {\n
  if (\'undefined\' !== typeof JSON) def = JSON.stringify(def);\n
  this.message = "Invalid package definition. "+reason+" "+def;\n
};\n
exports.InvalidPackageDef = InvalidPackageDef;\n
\n
// ..........................................................\n
// semver\n
// \n
\n
// ..........................................................\n
// NATCOMPARE\n
// \n
// Used with thanks to Kristof Coomans \n
// Find online at http://sourcefrog.net/projects/natsort/natcompare.js\n
// Cleaned up JSLint errors\n
\n
/*\n
natcompare.js -- Perform \'natural order\' comparisons of strings in JavaScript.\n
Copyright (C) 2005 by SCK-CEN (Belgian Nucleair Research Centre)\n
Written by Kristof Coomans <kristof[dot]coomans[at]sckcen[dot]be>\n
\n
Based on the Java version by Pierre-Luc Paour, of which this is more or less a straight conversion.\n
Copyright (C) 2003 by Pierre-Luc Paour <natorder@paour.com>\n
\n
The Java version was based on the C version by Martin Pool.\n
Copyright (C) 2000 by Martin Pool <mbp@humbug.org.au>\n
\n
This software is provided \'as-is\', without any express or implied\n
warranty.  In no event will the authors be held liable for any damages\n
arising from the use of this software.\n
\n
Permission is granted to anyone to use this software for any purpose,\n
including commercial applications, and to alter it and redistribute it\n
freely, subject to the following restrictions:\n
\n
1. The origin of this software must not be misrepresented; you must not\n
claim that you wrote the original software. If you use this software\n
in a product, an acknowledgment in the product documentation would be\n
appreciated but is not required.\n
2. Altered source versions must be plainly marked as such, and must not be\n
misrepresented as being the original software.\n
3. This notice may not be removed or altered from any source distribution.\n
*/\n
var natcompare = function() {\n
  \n
  var isWhitespaceChar = function(a) {\n
    var charCode = a.charCodeAt(0);\n
    return charCode <= 32;\n
  };\n
\n
  var isDigitChar = function(a) {\n
    var charCode = a.charCodeAt(0);\n
    return ( charCode >= 48  && charCode <= 57 );\n
  };\n
\n
  var compareRight = function(a,b) {\n
    var bias = 0,\n
        ia   = 0,\n
        ib   = 0,\n
        ca, cb;\n
\n
    // The longest run of digits wins.  That aside, the greatest\n
    // value wins, but we can\'t know that it will until we\'ve scanned\n
    // both numbers to know that they have the same magnitude, so we\n
    // remember it in BIAS.\n
    for (;; ia++, ib++) {\n
      ca = a.charAt(ia);\n
      cb = b.charAt(ib);\n
\n
      if (!isDigitChar(ca) && !isDigitChar(cb)) return bias;\n
      else if (!isDigitChar(ca)) return -1;\n
      else if (!isDigitChar(cb)) return +1;\n
      else if (ca < cb) if (bias === 0) bias = -1;\n
      else if (ca > cb) if (bias === 0) bias = +1;\n
      else if (ca === 0 && cb === 0) return bias;\n
    }\n
  };\n
\n
  var natcompare = function(a,b) {\n
\n
    var ia  = 0, \n
    ib  = 0,\n
    nza = 0, \n
    nzb = 0,\n
    ca, cb, result;\n
\n
    while (true) {\n
      // only count the number of zeroes leading the last number compared\n
      nza = nzb = 0;\n
\n
      ca = a.charAt(ia);\n
      cb = b.charAt(ib);\n
\n
      // skip over leading spaces or zeros\n
      while ( isWhitespaceChar( ca ) || ca ==\'0\' ) {\n
        if (ca == \'0\') nza++;\n
        else nza = 0; // only count consecutive zeroes\n
        ca = a.charAt(++ia);\n
      }\n
\n
      while ( isWhitespaceChar( cb ) || cb == \'0\') {\n
        if (cb == \'0\') nzb++;\n
        else nzb = 0; // only count consecutive zeroes\n
        cb = b.charAt(++ib);\n
      }\n
\n
      // process run of digits\n
      if (isDigitChar(ca) && isDigitChar(cb)) {\n
        if ((result = compareRight(a.substring(ia), b.substring(ib))) !== 0) {\n
          return result;\n
        }\n
      }\n
\n
      // The strings compare the same.  Perhaps the caller\n
      // will want to call strcmp to break the tie.\n
      if (ca === 0 && cb === 0) return nza - nzb;\n
\n
      if (ca < cb) return -1;\n
      else if (ca > cb) return +1;\n
\n
      ++ia; ++ib;\n
    }\n
  };\n
\n
  return natcompare;\n
}();\n
exports.natcompare = natcompare;\n
\n
// ..........................................................\n
// PUBLIC API\n
// \n
\n
// Support Methods\n
var invalidVers = function(vers) {\n
  return new Error(\'\' + vers + \' is an invalid version string\');\n
};\n
invalidVers.displayName = \'invalidVers\';\n
\n
var compareNum = function(vers1, vers2, num1, num2) {\n
  num1 = Number(num1);\n
  num2 = Number(num2);\n
  if (isNaN(num1)) throw invalidVers(vers1);\n
  if (isNaN(num2)) throw invalidVers(vers2);\n
  return num1 - num2 ;\n
};\n
compareNum.displayName = \'compareNum\';\n
\n
\n
var vparse;\n
var semver = {\n
  \n
  /**\n
    Parse the version number into its components.  Returns result of a regex.\n
  */\n
  parse: function(vers) {\n
    var ret = vers.match(/^(=|~)?([\\d]+?)(\\.([\\d]+?)(\\.(.+))?)?$/);\n
    if (!ret) return null; // no match\n
    return [ret, ret[2], ret[4] || \'0\', ret[6] || \'0\', ret[1]];\n
  },\n
\n
\n
  /**\n
    Returns the major version number of a version string. \n
\n
    @param {String} vers\n
      version string\n
\n
    @returns {Number} version number or null if could not be parsed\n
  */\n
  major: function(vers) {\n
    return Number(vparse(vers)[1]);\n
  },\n
\n
  /**\n
    Returns the minor version number of a version string\n
\n
\n
    @param {String} vers\n
      version string\n
\n
    @returns {Number} version number or null if could not be parsed\n
  */\n
  minor: function(vers) {\n
    return Number(vparse(vers)[2]);\n
  },\n
\n
  /**\n
    Returns the patch of a version string.  The patch value is always a string\n
    not a number\n
  */\n
  patch: function(vers) {\n
    var ret = vparse(vers)[3];\n
    return isNaN(Number(ret)) ? ret : Number(ret);\n
  },\n
\n
  STRICT: \'strict\',\n
  NORMAL: \'normal\',\n
\n
  /**\n
    Returns the comparison mode.  Will be one of NORMAL or STRICT\n
  */\n
  mode: function(vers) {\n
    var ret = vparse(vers)[4];\n
    return ret === \'=\' ? semver.STRICT : semver.NORMAL;\n
  },\n
\n
  /**\n
    Compares two patch strings using the proper matching formula defined by\n
    semver.org.  Returns:\n
    \n
    @param {String} patch1 first patch to compare\n
    @param {String} patch2 second patch to compare\n
    @returns {Number} -1 if patch1 < patch2, 1 if patch1 > patch2, 0 if equal \n
  */\n
  comparePatch: function(patch1, patch2) {\n
    var num1, num2;\n
\n
    if (patch1 === patch2) return 0; // equal\n
\n
    num1   = Number(patch1);\n
    num2   = Number(patch2);\n
\n
    if (isNaN(num1)) {\n
      if (isNaN(num2)) {\n
        // do lexigraphic comparison\n
        return natcompare(patch1, patch2);\n
\n
      } else return -1; // num2 is a number therefore num1 < num2\n
\n
    // num1 is a number but num2 is not so num1 > num2\n
    } else if (isNaN(num2)) {\n
      return 1 ;\n
    } else {\n
      return num1<num2 ? -1 : (num1>num2 ? 1 : 0) ;\n
    }\n
  },\n
\n
  /**\n
    Compares two version strings, using natural sorting for the patch.\n
  */\n
  compare: function(vers1, vers2) {\n
    var ret ;\n
\n
    if (vers1 === vers2) return 0;\n
    if (vers1) vers1 = vparse(vers1);\n
    if (vers2) vers2 = vparse(vers2);\n
\n
    if (!vers1 && !vers2) return 0;\n
    if (!vers1) return -1; \n
    if (!vers2) return 1; \n
\n
\n
    ret = compareNum(vers1[0], vers2[0], vers1[1], vers2[1]);\n
    if (ret === 0) {\n
      ret = compareNum(vers1[0], vers2[0], vers1[2], vers2[2]);\n
      if (ret === 0) ret = semver.comparePatch(vers1[3], vers2[3]);\n
    }\n
\n
    return (ret < 0) ? -1 : (ret>0 ? 1 : 0);\n
  },\n
\n
  /**\n
    Returns true if the second version string represents a version compatible \n
    with the first version.  In general this means the second version must be\n
    greater than or equal to the first version but its major version must not \n
    be different.\n
  */\n
  compatible: function(reqVers, curVers) {\n
    if (!reqVers) return true; // always compatible with no version\n
    if (reqVers === curVers) return true; // fast path\n
\n
    // make sure these parse - or else treat them like null\n
    if (reqVers && !vparse(reqVers)) reqVers = null;\n
    if (curVers && !vparse(curVers)) curVers = null;\n
\n
    // try fast paths again in case they changed state\n
    if (!reqVers) return true; // always compatible with no version\n
    if (reqVers === curVers) return true; // fast path\n
    \n
    // strict mode, must be an exact (semantic) match\n
    if (semver.mode(reqVers) === semver.STRICT) {\n
      return curVers && (semver.compare(reqVers, curVers)===0);\n
\n
    } else {\n
      if (!curVers) return true; // if no vers, always assume compat\n
\n
      // major vers\n
      if (semver.major(reqVers) !== semver.major(curVers)) return false; \n
      return semver.compare(reqVers, curVers) <= 0;\n
    }\n
  },\n
\n
  /**\n
    Normalizes version numbers so that semantically equivalent will be treated \n
    the same.\n
  */\n
  normalize: function(vers) {\n
    var patch;\n
\n
    if (!vers || vers.length===0) return null;\n
    vers = semver.parse(vers);\n
    if (!vers) return null;\n
\n
    patch = Number(vers[3]);\n
    if (isNaN(patch)) patch = vers[3];\n
\n
    return [Number(vers[1]), Number(vers[2]), patch].join(\'.\');\n
  }\n
  \n
};\n
exports.semver = semver;\n
vparse = semver.parse;\n
\n
\n
// ..........................................................\n
// FACTORY\n
// \n
\n
/**\n
  @constructor\n
  \n
  A factory knows how to instantiate a new module for a sandbox, including \n
  generating the require() method used by the module itself.  You can return\n
  custom factories when you install a plugin.  Your module should export\n
  loadFactory().\n
  \n
  The default factory here actually expects to receive a module descriptor\n
  as generated by the build tools.\n
*/\n
var Factory = exports.extend(Object);\n
exports.Factory = Factory;\n
\n
Factory.prototype.init = function(moduleId, pkg, factory) {\n
  this.id  = moduleId;\n
  this.pkg = pkg;\n
  this.factory = factory;\n
};\n
\n
/**\n
  Actually generates a new set of exports for the named sandbox.  The sandbox\n
  must return a module object that can be used to generate the factory.\n
  \n
  If the current value of the local factory is a string, then we will actually\n
  eval/compile the factory as well.\n
  \n
  @param sandbox {Sandbox}\n
    The sandbox the will own the module instance\n
    \n
  @param module {Module}\n
    The module object the exports will belong to\n
    \n
  @returns {Hash} exports from instantiated module\n
*/\n
Factory.prototype.call = function(sandbox, module) {\n
\n
  // get the factory function, evaluate if needed\n
  var func = this.factory,\n
      filename = this.__filename,\n
      dirname  = this.__dirname;\n
      \n
  if (T_STRING === typeof(func)) {\n
    func = this.factory = Factory.compile(func, this.pkg.id+\':\'+this.id);\n
  }\n
\n
  // generate a nested require for this puppy\n
  var req = sandbox.createRequire(module),\n
      exp = module.exports;\n
  func.call(exp, req, exp, module, filename, dirname);\n
  return module.exports;\n
};\n
\n
\n
// standard wrapper around a module.  replace item[1] with a string and join.\n
var MODULE_WRAPPER = [\n
  \'(function(require, exports, module) {\',\n
  null,\n
  \'\\n});\\n//@ sourceURL=\',\n
  null,\n
  \'\\n\'];\n
\n
/**\n
  Evaluates the passed string.  Returns a function.\n
  \n
  @param moduleText {String}\n
    The module text to compile\n
    \n
  @param moduleId {String}\n
    Optional moduleId.  If provided will be used for debug\n
    \n
  @returns {Function} compiled factory\n
*/\n
Factory.compile = function(moduleText, moduleId) {\n
  var ret;\n
  \n
  MODULE_WRAPPER[1] = moduleText;\n
  MODULE_WRAPPER[3] = moduleId || \'(unknown module)\';\n
  \n
  ret = MODULE_WRAPPER.join(\'\');\n
  ret = eval(ret);\n
  \n
  MODULE_WRAPPER[1] = MODULE_WRAPPER[3] = null;\n
  return ret;\n
};\n
\n
exports.Factory = Factory;\n
\n
// ..........................................................\n
// MODULE\n
// \n
\n
/**\n
  A Module describes a single module, including its id, ownerPackage, and\n
  the actual module exports once the module has been instantiated.  It also\n
  implements the resource() method which can lookup a resource on the module\'s\n
  package.\n
*/\n
var Module = exports.extend(Object);\n
exports.Module = Module;\n
\n
Module.prototype.init = function(id, ownerPackage, sandbox) {\n
  this.id           = id;\n
  this.ownerPackage = ownerPackage;\n
  this.exports      = {};\n
  var module        = this;\n
  \n
  /**\n
    Lookup a resource on the module\'s ownerPackage.  Returns a URL or path \n
    for the discovered resource.  The method used to detect the module or \n
    package is implemented in the package.\n
    \n
    Note that this method is generated for each module we create because some\n
    code will try to pluck this method off of the module and call it in a\n
    different context.\n
    \n
    @param resourceId {String}\n
      Full or partial name of resource to retrieve\n
      \n
    @param done {Function}\n
      Optional.  Makes the resource discovery asyncronous\n
      \n
    @returns {String} url or path if not called async\n
  */\n
  this.resource = function(id) {\n
    return sandbox.resource(id, module.id, ownerPackage);\n
  };\n
};\n
\n
// ..........................................................\n
// PACKAGE\n
// \n
\n
/**\n
  Package expects you to register the package with a config having the \n
  following keys:\n
  \n
    {\n
      "name": "name-of-package" (vs canonical id)\n
      "version": current version of package (if known)\n
      \n
      // these are dependencies you require to run.  If the package is \n
      // async loaded, these will be the ones loaded\n
      "dependencies": {\n
         "package-name": "version"\n
      },\n
      \n
      // these map a specific package-name/version to a canonicalId that must\n
      // be registered for the package to be loaded.  You may include \n
      // additional packages here that may be referenced but are not required\n
      // to run (for example - lazy loaded packages)\n
      //\n
      // This also forms the universe of packages this particular package can\n
      // reference.\n
      //\n
      "tiki:packages": {\n
        "package-name": [\n
          { "version": "1.0.0", "id": "canonicalId", "url": "url" }\n
        ]\n
      },\n
\n
      // ids mapped to urls.  all of these scripts must be loaded for this \n
      // package to be considered ready \n
      "tiki:scripts": {\n
        "id": "url"\n
      },\n
      \n
      // stylesheets that must be loaded for this package to be considered\n
      // ready.  The id is used so that the URL can load from a relative path\n
      // that may move around and still be accurate.\n
      "tiki:stylesheets": {\n
        "id": "url",\n
        "id": "url"\n
      },\n
      \n
      // maps asset paths for non-JS and non-CSS assets to URLs.  Used to \n
      // progrmatically load images, etc.\n
      "tiki:resources": {\n
        "asset/path": "url",\n
        "asset/path": "url"\n
      }\n
    }\n
\n
  This registration ensures that the package and it\'s related assets are \n
  loaded.\n
*/\n
     \n
var Package = exports.extend(Object);\n
exports.Package = Package;\n
\n
Package.prototype.init = function(id, config) {\n
  if (!isCanonicalId(id)) id = \'::\'+id; // normalize\n
  this.id = id;\n
  this.config = config;\n
  this.isReady = true;\n
};\n
\n
// ..........................................................\n
// Package Configs\n
// \n
\n
/**\n
  Retrieves the named config property.  This method can be overidden by \n
  subclasses to perform more advanced processing on the key data\n
  \n
  @param {String} key\n
    The key to retrieve\n
    \n
  @returns {Object} the key value or undefined\n
*/\n
Package.prototype.get = function(key) {\n
  return this.config ? this.config[key] : undefined;\n
};\n
\n
/**\n
  Updates the named config property.\n
\n
  @param {String} key\n
    The key to update\n
    \n
  @param {Object} value\n
    The object value to change\n
    \n
  @returns {Package} receiver\n
*/\n
Package.prototype.set = function(key, value) {\n
  if (!this.config) this.config = {};\n
  this.config[key] = value;\n
  return this;\n
};\n
\n
/**\n
  Determines the required version of the named packageId, if any, specified\n
  in this package.\n
  \n
  @param {String} packageId\n
    The packageId to lookup\n
    \n
  @returns {String} The required version or null (meaning any)\n
*/\n
Package.prototype.requiredVersion = function(packageId) { \n
  var deps = this.get(\'dependencies\');\n
  return deps ? deps[packageId] : null;\n
};\n
\n
// ..........................................................\n
// Nested Packages\n
// \n
\n
/**\n
  Attempts to match the passed packageId and version to the receiver or a \n
  nested package inside the receiver.  If a match is found, returns the \n
  packages canonicalId.  Otherwise returns null.  \n
  \n
  This does not search remote sources for the package.  It only looks at \n
  what packages are available locally.\n
  \n
  This method is called after a package version has been checked for \n
  compatibility with the package dependencies.  It is not necessary to \n
  validate the requested version against any dependencies.\n
  \n
  @param {String} packageId\n
    The package id to look up\n
\n
  @param {String} vers\n
    The expected version.  If null, then return the newest version for the \n
    package.\n
    \n
  @param {String} Canonical packageId or null\n
*/\n
Package.prototype.canonicalPackageId = function(packageId, vers) {\n
  if ((packageId === this.get(\'name\')) && \n
      semver.compatible(vers, this.get(\'version\'))) {\n
      return this.id;\n
  }\n
  return null;\n
};\n
\n
/**\n
  Returns the receiver or an instance of a nested package if it matches the\n
  canonicalId passed here.  This method will only be called with a canonicalId\n
  returned from a previous call to Package#canonicalPackageId.\n
  \n
  If the package identified by the canonicalId is not available locally for\n
  some reason, return null.\n
  \n
  @param {String} canonicalId \n
    The canonical packageId.\n
    \n
  @returns {Package} a package instance or null\n
*/\n
Package.prototype.packageFor = function(canonicalId) {\n
  if (canonicalId === this.id) return this;\n
  return null;\n
};\n
\n
/**\n
  Verifies that the package identified by the passed canonical id is available\n
  locally and ready for use.  If it is not available, this method should \n
  attempt to download the package from a remote source.\n
  \n
  Invokes the `done` callback when complete.\n
  \n
  If for some reason you cannot download and install the package you should\n
  invoke the callback with an error object describing the reason.  There are\n
  a number of standard errors defined on Package such as NotFound.\n
  \n
  @param {String} canonicalId\n
    The canonical packageId\n
    \n
  @param {Function} done\n
    Callback to invoke with result.  Pass an error object if the package \n
    could not be loaded for some reason.  Otherwise invoke with no params\n
    \n
  @returns {void}\n
*/\n
Package.prototype.ensurePackage = function(canonicalId, done) {\n
  if (canonicalId === this.id) return done();\n
  else return done(new NotFound(canonicalId, this));\n
};\n
\n
/**\n
  Returns all packages in the package including the package itself and any \n
  nested packages.  Default just returns self.\n
*/\n
Package.prototype.catalogPackages = function() {\n
  return [this];\n
};\n
\n
// ..........................................................\n
// Package Module Loading\n
// \n
\n
/**\n
  Detects whether the moduleId exists in the current package.\n
  \n
  @param {String} moduleId\n
    The moduleId to check\n
    \n
  @returns {Boolean} true if the module exists\n
*/\n
Package.prototype.exists = function(moduleId) {\n
  return !!(this.factories && this.factories[moduleId]);\n
};\n
\n
/**\n
  Returns a Factory object for the passed moduleId or null if no matching\n
  factory could be found.\n
  \n
  @param {String} moduleId\n
    The moduleId to check\n
    \n
  @returns {Factory} factory object\n
*/\n
Package.prototype.load = function(moduleId) {\n
  return this.factories ? this.factories[moduleId] : null;\n
};\n
\n
// ..........................................................\n
// LOADER\n
// \n
\n
// potentially optimize to avoid memory churn.\n
var joinPackageId = function joinPackageId(packageId, moduleId) {\n
  return packageId+\':\'+moduleId;\n
};\n
\n
/**\n
  A loader is responsible for finding and loading factory functions.  The \n
  primary purpose of the loader is to find packages and modules in those \n
  packages.  The loader typically relies on one or more sources to actually\n
  find a particular package.\n
*/\n
var Loader = exports.extend(Object);\n
exports.Loader = Loader;\n
\n
Loader.prototype.init = function(sources) {\n
  this.sources = sources || [];\n
  this.clear();\n
};\n
\n
/**\n
  Clear caches in the loader causing future requests to go back to the \n
  sources.\n
*/\n
Loader.prototype.clear = function() {\n
  this.factories = {};\n
  this.canonicalIds = {};\n
  this.packages ={};\n
  this.packageSources = {};\n
  this.canonicalPackageIds = {};\n
};\n
\n
/**\n
  The default package.  This can be replaced but normally it is empty, meaning\n
  it will never match a module.\n
  \n
  @property {Package}\n
*/\n
Loader.prototype.defaultPackage = new Package(\'default\', { \n
  name: "default" \n
});\n
\n
/**\n
  The anonymous package.  This can be used when loading files outside of a \n
  package.\n
  \n
  @property {Package}\n
*/\n
Loader.prototype.anonymousPackage = new Package(\'(anonymous)\', { \n
  name: "(anonymous)"\n
});\n
\n
\n
/**\n
\n
  Discovers the canonical id for a module.  A canonicalId is a valid URN that\n
  can be used to uniquely identify a module.\n
  that looks like:\n
  \n
    ::packageId:moduleId\n
    \n
  For example:\n
  \n
    ::sproutcore-runtime/1.2.0:mixins/enumerable\n
  \n
  Canonical Ids are discovered according to the following algorithm:\n
  \n
  1.  If you pass in an already canonicalId, return it\n
  2.  If you pass in a relative moduleId, it will be expanded and attached\n
      to the workingPackage.\n
  3.  If you pass in a moduleId with a packageId embedded, lookup the latest\n
      version of the package that is compatible with the passed workingPackage\n
  4.  If you pass a moduleId with no packageId embedded, then first look\n
      for the module on the workingPackage.  \n
  5.  If not found there, look for a packageId with the same name.  If that is \n
      found, return either packageId:index or packageId:packageId as module.  \n
  6.  Otherwise, assume it is part of the default package. \n
\n
  @param {String} moduleId\n
    The moduleId to lookup.  May be a canonicalId, packageId:moduleId, \n
    absolute moduleId or relative moduleId\n
    \n
  @param {String} curModuleId\n
    Optional.  moduleId of the module requesting the lookup.  Only needed if\n
    the moduleId param might be relative.\n
    \n
  @param {Package} workingPackage\n
    The working package making the request.  When searching for a package,\n
    only use packages that are compatible with the workingPackage.\n
    \n
    This parameter is also optional, though if you omit it, this method \n
    assumes the anonymousPackage.\n
    \n
  @returns {void}\n
*/\n
Loader.prototype.canonical = function(moduleId, curModuleId, workingPackage) {\n
  \n
  var cache, cacheId, idx, packageId, canonicalId, pkg, ret; \n
  \n
  // NORMALIZE PARAMS\n
  // normalize params - curModuleId can be omitted (though relative ids won\'t)\n
  // work\n
  if (curModuleId && (T_STRING !== typeof curModuleId)) {\n
    workingPackage = curModuleId;\n
    curModuleId = null;\n
  }\n
  \n
  // return immediately if already canonical\n
  if (isCanonicalId(moduleId)) return moduleId;\n
  \n
  // if no workingPackage, assume anonymous\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  \n
  // Resolve moduleId - may return canonical\n
  moduleId = this._resolve(moduleId, curModuleId, workingPackage);\n
  if (isCanonicalId(moduleId)) return moduleId;\n
  \n
  // then lookup in cache\n
  cacheId = workingPackage ? workingPackage.id : \'(null)\';\n
  cache = this.canonicalIds;\n
  if (!cache) cache = this.canonicalIds = {};\n
  if (!cache[cacheId]) cache[cacheId] = {};\n
  cache = cache[cacheId];\n
  if (cache[moduleId]) return cache[moduleId];\n
  cacheId = moduleId; // save for later\n
\n
  // Not Found in Cache.  Do a lookup\n
  idx = moduleId.indexOf(\':\');\n
  if (idx>=0) {\n
    packageId = moduleId.slice(0,idx);\n
    moduleId  = moduleId.slice(idx+1);\n
    if (moduleId[0]===\'/\') {\n
      throw new Error(\'Absolute path not allowed with packageId\');\n
    }\n
  }\n
\n
  // if packageId is provided, just resolve packageId to a canonicalId\n
  ret = null;\n
  if (packageId && (packageId.length>0)) {\n
    canonicalId = this._canonicalPackageId(packageId, null, workingPackage);\n
    if (canonicalId) ret = joinPackageId(canonicalId, moduleId);\n
\n
  // no packageId is provided, we\'ll need to do a little more searching\n
  } else {\n
\n
    // first look in workingPackage for match...\n
    if (workingPackage && workingPackage.exists(moduleId)) {\n
      ret = joinPackageId(workingPackage.id, moduleId);\n
      \n
    // not in working package, look for packageId:index or\n
    // packageId:packageId\n
    } else {\n
      canonicalId = this._canonicalPackageId(moduleId, null, workingPackage);\n
      if (canonicalId) pkg = this._packageFor(canonicalId, workingPackage);\n
      if (pkg) {\n
        if (pkg.exists(\'index\')) ret = joinPackageId(pkg.id, \'index\');\n
        else if (pkg.exists(moduleId)) ret = joinPackageId(pkg.id,moduleId);\n
      }\n
    }\n
    \n
    // not in working package and isn\'t a package itself, assume default\n
    // package.  If there is no defaultPackage, return with the working\n
    // package.  This will fail but at least the error will be more \n
    // helpful\n
    if (!ret) {\n
      if (this.defaultPackage) packageId = this.defaultPackage.id;\n
      else if (this.workingPackage) packageId = this.workingPackage.id;\n
      else if (this.anonymousPackage) packageId = this.anonymousPackage.id;\n
      else return packageId = null;\n
      \n
      if (packageId) ret = joinPackageId(packageId, moduleId);\n
    }\n
  }\n
\n
  // save to cache and return\n
  cache[cacheId] = ret;\n
  return ret ;\n
};\n
  \n
/**\n
\n
  Loads a factory for the named canonical module Id.  If you did not obtain\n
  the canonical module id through the loader\'s canonical() method, then you\n
  must also pass a workingPackage property so that the loader can locate the\n
  package that owns the module.\n
  \n
  The returns factory function can be used to actually generate a module.\n
  \n
  @param {String} canonicalId\n
    A canonical module id\n
    \n
  @param {Package} workingPackage\n
    Optional working package.  Only required if you pass in a canonical id\n
    that you did not obtain from the loader\'s canonical() method.\n
    \n
  @returns {void}\n
  \n
*/\n
Loader.prototype.load = function(canonicalId, workingPackage, sandbox) {\n
\n
  var cache, ret, idx, packageId, moduleId, pkg;\n
  \n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  \n
  cache = this.factories;\n
  if (!cache) cache = this.factories = {};\n
  if (cache[canonicalId]) return cache[canonicalId];\n
\n
  // not in cache - load from package\n
  idx       = canonicalId.indexOf(\':\',2);\n
  packageId = canonicalId.slice(0,idx);\n
  moduleId  = canonicalId.slice(idx+1);\n
\n
  pkg = this._packageFor(packageId, workingPackage);\n
  \n
//@if(debug)\n
  if (!pkg) DEBUG(\'Loader#load - \'+packageId+\' not found for \'+moduleId);\n
//@endif\n
\n
  if (!pkg) return null; // not found\n
  \n
  ret = pkg.load(moduleId, sandbox);\n
  cache[canonicalId] = ret;\n
  return ret ;\n
};\n
\n
/**\n
  Returns a catalog of all known packages visible to the workingPackage.\n
  The catalog is simply an array of package objects in no particular order\n
*/\n
Loader.prototype.catalogPackages = function(workingPackage) {\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  var catalog = [], sources, idx, len, seen = {};\n
  if (this.defaultPackage) catalog.push(this.defaultPackage);\n
  \n
  // anonymous package is never visible unless it is working..\n
  //if (this.anonymousPackage) ret.push(this.anonymousPackage);\n
\n
  // append any packages with versions that haven\'t been seen already\n
  var append = function(packages) {\n
    var idx, len, check, cur;\n
    \n
    if (!packages) return; // nothing to do\n
    len = packages.length;\n
    for(idx=0;idx<len;idx++) {\n
      cur = packages[idx];\n
      check = seen[cur.get(\'name\')];\n
      if (!check) check = seen[cur.get(\'name\')] = {};      \n
      if (!check[cur.get(\'version\')]) {\n
        catalog.push(cur);\n
        check[cur.get(\'version\')] = cur;\n
      }\n
    }\n
  };\n
  \n
  if (workingPackage) append(workingPackage.catalogPackages());\n
\n
  sources = this.sources;\n
  len = sources.length;\n
  for(idx=0;idx<len;idx++) append(sources[idx].catalogPackages());\n
  \n
  seen = null; // no longer needed.\n
  return catalog;\n
};\n
\n
/**\n
  Discovers the canonical id for a package.  A cnaonicalID is a URN that can\n
  be used to uniquely identify a package.  It looks like: \n
  \n
    ::packageId\n
  \n
  for example:\n
  \n
    ::sproutcore-datastore/1.2.0/1ef3ab23ce23ff938\n
\n
  If you need to perform some low-level operation on a package, this method\n
  is the best way to identify the package you want to work with specifically.\n
  \n
  ## Examples\n
  \n
  Find a compatible package named \'foo\' in the current owner module:\n
  \n
      loader.canonicalPackage(\'foo\', ownerPackage, function(err, pkg) {\n
        // process response\n
      });\n
      \n
  Find the package named \'foo\', exactly version \'1.0.0\'.  This may return a\n
  packes nested in the ownerPackage:\n
  \n
      loader.canonicalPackage(\'foo\', \'=1.0.0\', ownerPackage, function(err, pkg) {\n
        // process response\n
      });\n
  \n
  Find the latest version of \'foo\' installed in the system - not specific to \n
  any particular package\n
  \n
      loader.canonicalPackage(\'foo\', loader.anonymousPackage, function(err, pkg) {\n
        // process result\n
      });\n
      \n
  @param {String|Package} packageId\n
    The packageId to load.  If you pass a package, the package itself will\n
    be returned.\n
    \n
  @param {String} vers \n
    The required version.  Pass null or omit this parameter to use the latest\n
    version (compatible with the workingPackage).\n
    \n
  @param {Package} workingPackage\n
    The working package.  This method will search in this package first for\n
    nested packages.  It will also consult the workingPackage to determine \n
    the required version if you don\'t name a version explicitly.\n
    \n
    You may pass null or omit this parameter, in which case the anonymous\n
    package will be used for context.\n
    \n
  @param {Function} done \n
    Callback.  Invoked with an error and the loaded package.  If no matching\n
    package can be found, invoked with null for the package.\n
\n
  @returns {void}\n
*/\n
Loader.prototype.canonicalPackageId = function(packageId, vers, workingPackage) {\n
\n
  var idx;\n
\n
  // fast path in case you pass in a package already\n
  if (packageId instanceof Package) return packageId.id;\n
\n
  // fast path packageId is already canonical - slice of moduleId first\n
  if (isCanonicalId(packageId)) {\n
    idx = packageId.indexOf(\':\', 2);\n
    if (idx>=0) packageId = packageId.slice(0,idx);\n
    return packageId;\n
  }\n
  \n
  // normalize the params.  vers may be omitted\n
  if (vers && (T_STRING !== typeof vers)) {\n
    workingPackage = vers;\n
    vers = null;\n
  }  \n
\n
  // must always have a package\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  \n
  // if packageId includes a moduleId, slice it off\n
  idx = packageId.indexOf(\':\');\n
  if (idx>=0) packageId = packageId.slice(0, idx);\n
  \n
  // now we can just pass onto internal primitive\n
  return this._canonicalPackageId(packageId, vers, workingPackage);\n
};\n
\n
\n
/**\n
  Primitive returns the package instance for the named canonicalId.  You can\n
  pass in a canonicalId for a package only or a package and module.  In either\n
  case, this method will only return the package instance itself.\n
  \n
  Note that to load a canonicalId that was not resolved through the \n
  canonicalPackageId() or canonical() method, you will need to also pass in\n
  a workingPackage so the loader can find the package.\n
  \n
  @param {String} canonicalId\n
    The canonicalId to load a package for.  May contain only the packageId or\n
    a moduleId as well.\n
    \n
  @param {Package} workingPackage\n
    Optional workingPackage used to locate the package.  This is only needed\n
    if you request a canonicalId that you did not obtain through the \n
    canonical*() methods on the loader.\n
\n
  @returns {void}\n
*/\n
Loader.prototype.packageFor = function(canonicalId, workingPackage){\n
\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  \n
  // remove moduleId\n
  var idx = canonicalId.indexOf(\':\', 2);\n
  if (idx>=0) canonicalId = canonicalId.slice(0, idx);\n
\n
  return this._packageFor(canonicalId, workingPackage);\n
};\n
\n
/**\n
  Verifies that the named canonicalId is ready for use, including any of its\n
  dependencies.  You can pass in either a canonical packageId only or a \n
  moduleId.   In either case, this method will actually only check the package\n
  properties for dependency resolution since dependencies are not tracked for\n
  individual modules.\n
  \n
  @param {String} canonicalId\n
    The canonicalId to use for lookup\n
    \n
  @param \n
*/\n
Loader.prototype.ready = function(canonicalId, workingPackage) {\n
\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  \n
  // strip out moduleId\n
  var idx = canonicalId.indexOf(\':\', 2), \n
      moduleId, pkg;\n
  \n
  if (idx >= 0) {\n
    moduleId    = canonicalId.slice(idx+1);\n
    canonicalId = canonicalId.slice(0, idx);\n
  }\n
  \n
  if (this._packageReady(canonicalId, workingPackage, {})) {\n
    pkg = this._packageFor(canonicalId, workingPackage);\n
    if (!pkg) return false;\n
    return !!pkg.exists(moduleId);\n
  } else return false;\n
  \n
};\n
\n
/**\n
  Ensures the package that maps to the passed packageId/vers combo and all\n
  of its known dependencies are loaded and ready for use.  If anything is not\n
  loaded, it will load them also.  \n
  \n
  Invokes the passed callback when loading is complete.\n
  \n
  This method ends up calling ensurePackage() on one or more of its sources\n
  to get the actual packages to load.\n
  \n
  @param {String} packageId\n
    The packageID to load.  May be a packageId name or a canonical packageId\n
    \n
  @param {String} vers\n
    Optional version used to constrain the compatible package\n
    \n
  @param {Package} workingPackage\n
    Optional working package used to match the packageId.  If the package \n
    might be nested you should always pass a workingPackage.  Default assumes\n
    anonymousPackage.\n
    \n
  @param {Function} done\n
    Callback invoked when package is loaded.  Passes an error if there was an\n
    error.  Otherwise no params.\n
    \n
  @returns {void}\n
*/\n
Loader.prototype.ensurePackage = function(packageId, vers, workingPackage, done) {\n
\n
  // normalize params\n
  if (vers && (T_STRING !== typeof vers)) {\n
    done = workingPackage ;\n
    workingPackage = vers;\n
    vers = null;\n
  }\n
\n
  if (workingPackage && (T_FUNCTION === typeof workingPackage)) {\n
    done = workingPackage;\n
    workingPackage = null;\n
  }\n
  \n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
\n
  this._ensurePackage(packageId, vers, workingPackage, {}, done);\n
};\n
\n
/**\n
  @private\n
  \n
  Primitive for ensurePackage().  Does no param normalization.  Called \n
  recursively for dependencies.\n
*/\n
Loader.prototype._ensurePackage = function(packageId, vers, workingPackage, seen, done) {\n
\n
  var loader = this, canonicalId, source;\n
  \n
  // find the canonicalId and source to ask to ensure...\n
  canonicalId = this._canonicalPackageId(packageId, vers, workingPackage);\n
  if (!canonicalId) {\n
    return done(new NotFound(packageId, workingPackage));\n
  }\n
\n
  if (seen[canonicalId]) return done(); // success\n
  seen[canonicalId] = true;\n
\n
  source = this._sourceForCanonicalPackageId(canonicalId, workingPackage);\n
  if (!source) {\n
    return done(new NotFound(canonicalId, workingPackage));\n
  }\n
\n
  source.ensurePackage(canonicalId, function(err) {\n
    var pkg, deps, packageId, packageIds;\n
\n
    if (err) return done(err);\n
    pkg = loader.packageFor(canonicalId, workingPackage);\n
    if (!pkg) {\n
      return done(new NotFound(canonicalId, workingPackage));\n
    }\n
\n
    deps = pkg.get(\'dependencies\');\n
    if (!deps) return done(); // nothing to do\n
    \n
    // map deps to array to we can process in parallel\n
    packageIds = [];\n
    for(packageId in deps) {\n
      if (!deps.hasOwnProperty(packageId)) continue;\n
      packageIds.push({ packageId: packageId, vers: deps[packageId] });\n
    }\n
    \n
    parallel(packageIds, function(info, done) {\n
      loader._ensurePackage(info.packageId, info.vers, pkg, seen, done);\n
    })(done);\n
\n
  });\n
  \n
};\n
\n
/**\n
  @private\n
  \n
  Discovers the canonical packageId for the named packageId, version and \n
  working package.  This will also store in cache the source where you can\n
  locare and load the associated package, if needed.\n
  \n
  This primitive is used by all other package methods to resolve a package\n
  into a canonicalId that can be used to reference a specific package instance\n
  \n
  It does not perform any error checking on passed in parameters which is why\n
  it should never be called directly outside of the Loader itself.\n
  \n
  @param {String|Package} packageId\n
    The packageId to load.  If you pass a package, the package itself will\n
    be returned.\n
    \n
  @param {String} vers \n
    The required version.  Pass null or omit this parameter to use the latest\n
    version (compatible with the workingPackage).\n
    \n
  @param {Package} workingPackage\n
    The working package.  This method will search in this package first for\n
    nested packages.  It will also consult the workingPackage to determine \n
    the required version if you don\'t name a version explicitly.\n
    \n
  @returns {String}\n
*/\n
Loader.prototype._canonicalPackageId = function(packageId, vers, workingPackage) {\n
\n
  // fast paths\n
  if (packageId instanceof Package) return packageId.id;\n
  if (isCanonicalId(packageId)) return packageId;\n
  if ((packageId === \'default\') && this.defaultPackage) {\n
    return this.defaultPackage.id;\n
  }\n
  \n
  var cache = this.canonicalPackageIds,\n
      cacheId, sources, ret, idx, len, source;\n
\n
  // use anonymousPackage if no workingPackage is provided\n
  if (!workingPackage) workingPackage = this.anonymousPackage;\n
  if (!workingPackage) throw new Error(\'working package is required\');\n
\n
  // if packageId is already canonical, vers must be null, otherwise lookup\n
  // vers in working package\n
  if (!vers) vers = workingPackage.requiredVersion(packageId);\n
  \n
  // look in cache...\n
  cacheId = workingPackage.id;\n
  if (!cache) cache = this.canonicalPackageIds = {};\n
  if (!cache[cacheId]) cache[cacheId] = {};\n
  cache = cache[cacheId];\n
  if (!cache[packageId]) cache[packageId] = {};\n
  cache = cache[packageId];\n
  if (cache[vers]) return cache[vers];\n
\n
  sources = this.sources;\n
\n
  // first, ask the workingPackage  \n
  ret = workingPackage.canonicalPackageId(packageId, vers);\n
  source = workingPackage;\n
  \n
\n
  // not found - make sure there isn\'t another incompatible version in \n
  // workingPackage.  nested packages superceed all other packages so if there\n
  // is an incompatible nested version we need to throw an error.\n
  if (!ret) {\n
    ret = workingPackage.canonicalPackageId(packageId, null);\n
    if (ret) {\n
      throw new Error(\n
        workingPackage.get(\'name\')+" contains an incompatible nested"+\n
        " package "+packageId+" (expected: "+vers+")");\n
    }\n
  }\n
  \n
    \n
  // next, if not found in the workingPackage, then ask each of our \n
  // sources in turn until a match is found.  When found, return\n
  if (!ret && sources) {\n
    len = sources.length;\n
    for(idx=0;!ret && (idx<len);idx++) {\n
      source = sources[idx];\n
      ret = source.canonicalPackageId(packageId, vers);\n
    }\n
  }\n
  \n
  if (ret) this._cachePackageSource(ret, workingPackage, source);\n
  cache[vers] = ret;\n
  return ret ;\n
};\n
\n
// add a function to the cache that will immediately return the source\n
Loader.prototype._cachePackageSource = function(id, workingPackage, source) {\n
  var scache = this.packageSources, pkgId = workingPackage.id;\n
  \n
  if (!scache) scache = this.packageSources = {};\n
  if (!scache[pkgId]) scache[pkgId] = {};\n
  scache = scache[pkgId];\n
  scache[id] = source;\n
};\n
\n
/**\n
  Looks up the source for the named canonicalId in the cache.  Returns null\n
  if no match is found.\n
*/\n
Loader.prototype._sourceForCanonicalPackageId = function(canonicalId, workingPackage) {\n
  var scache = this.packageSources, \n
      wpackageId = workingPackage.id, \n
      pkg, sources, len, idx, ret;\n
\n
  if (!scache) scache = this.packageSources = {};\n
  if (!scache[wpackageId]) scache[wpackageId] = {};\n
  scache = scache[wpackageId];\n
  if (scache[canonicalId]) return scache[canonicalId];\n
  \n
  sources = this.sources;\n
    \n
  // first, ask the workingPackage to find any matching package (since it \n
  // can only have one version).  Then check the returned version against \n
  // the expected version.  \n
  if (workingPackage) {\n
    pkg = workingPackage.packageFor(canonicalId);\n
    if (pkg) ret = workingPackage; \n
  }\n
  \n
  if (!ret && sources) {\n
    len = sources.length;\n
    for(idx=0;!ret && (idx<len); idx++) {\n
      ret = sources[idx];\n
      if (!ret.packageFor(canonicalId)) ret = null;\n
    }\n
  }\n
  \n
  scache[canonicalId] = ret;\n
  return ret ;\n
};\n
\n
/**\n
  Primitive actually loads a package from a canonicalId.  Throws an exception\n
  if source for package is not already in cache.  Also caches loaded package.\n
*/\n
Loader.prototype._packageFor = function(canonicalId, workingPackage) {\n
  var cache, source, ret;\n
\n
  // special case - if default packageId just get the default package.\n
  if (this.defaultPackage && (canonicalId === this.defaultPackage.id)) {\n
    return this.defaultPackage;\n
  }\n
  \n
  // try to resolve out of cache\n
  cache = this.packages;\n
  if (!cache) cache = this.packages = {};\n
  if (cache[canonicalId]) return cache[canonicalId];\n
\n
  source = this._sourceForCanonicalPackageId(canonicalId, workingPackage);\n
  if (source) ret = source.packageFor(canonicalId);\n
  cache[canonicalId] = ret;\n
  return ret ;\n
};\n
\n
/**\n
  Primitive simply checks to see if the named canonicalId is ready or not\n
  along with any dependencies\n
*/\n
Loader.prototype._packageReady = function(canonicalId, workingPackage, seen) {\n
  var cache = this.packages, pkg, deps, packageId, vers;\n
\n
  // if we\'ve already seen this package, exit immediately\n
  if (seen[canonicalId]) return true;\n
  seen[canonicalId] = true;\n
  \n
  // first try to find the package for the receiver\n
  pkg = this._packageFor(canonicalId, workingPackage);\n
  if (!pkg) return false; // nothing to do.\n
\n
  // look at dependencies. make sure they are also loaded\n
  deps = pkg.get(\'dependencies\');\n
  for(packageId in deps) {\n
    if (!deps.hasOwnProperty(packageId)) continue;\n
    vers = deps[packageId];\n
    canonicalId = this._canonicalPackageId(packageId, vers, pkg);\n
    if (!canonicalId) return false;\n
    return this._packageReady(canonicalId, pkg, seen);\n
  }\n
  \n
  return true;\n
};\n
\n
/**\n
  Take a relative or fully qualified module name as well as an optional\n
  base module Id name and returns a fully qualified module name.  If you \n
  pass a relative module name and no baseId, throws an exception.\n
\n
  Any embedded package name will remain in-tact.\n
\n
  resolve(\'foo\', \'bar\', \'my_package\') => \'foo\'\n
  resolve(\'./foo\', \'bar/baz\', \'my_package\') => \'my_package:bar/foo\'\n
  resolve(\'/foo/bar/baz\', \'bar/baz\', \'my_package\') => \'default:/foo/bar/baz\'\n
  resolve(\'foo/../bar\', \'baz\', \'my_package\') => \'foo/bar\'\n
  resolve(\'your_package:foo\', \'baz\', \'my_package\') => \'your_package:foo\'\n
\n
  If the returned id does not include a packageId then the canonical() \n
  method will attempt to resolve the ID by searching the default package, \n
  then the current package, then looking for a package by the same name.\n
\n
  @param {String} moduleId relative or fully qualified module id\n
  @param {String} baseId fully qualified base id\n
  @returns {String} fully qualified name\n
*/\n
Loader.prototype._resolve = function(moduleId, curModuleId, pkg){\n
  var path, len, idx, part, parts, packageId, err;\n
\n
  // if id does not contain a packageId and it starts with a / then \n
  // return with anonymous package id.\n
  if (moduleId[0]===\'/\' && moduleId.indexOf(\':\')<0) {\n
    return this.anonymousPackage.id + \':\' + moduleId;\n
  }\n
\n
  // contains relative components?\n
  if (moduleId.match(/(^\\.\\.?\\/)|(\\/\\.\\.?\\/)|(\\/\\.\\.?\\/?$)/)) {\n
\n
    // if we have a packageId embedded, get that first\n
    if ((idx=moduleId.indexOf(\':\'))>=0) {\n
      packageId = moduleId.slice(0,idx);\n
      moduleId  = moduleId.slice(idx+1);\n
      path      = []; // path must always be absolute.\n
\n
    // if no package ID, then use baseId if first component is . or ..\n
    } else if (moduleId.match(/^\\.\\.?\\//)) {\n
      if (!curModuleId) {\n
        throw new Error("id required to resolve relative id: "+moduleId);\n
      }\n
\n
      // if base moduleId contains a packageId return an error\n
      if (curModuleId.indexOf(\':\')>=0) {\n
        throw new Error("current moduleId cannot contain packageId");\n
      }\n
        \n
      // use the pkg.id (which will be canonical)\n
      if (pkg) packageId = pkg.id;\n
\n
      // work from current moduleId as base.  Ignore current module name\n
      path = curModuleId.split(\'/\');\n
      path.pop(); \n
\n
    } else path = [];\n
\n
    // iterate through path components and update path\n
    parts = moduleId.split(\'/\');\n
    len   = parts.length;\n
    for(idx=0;idx<len;idx++) {\n
      part = parts[idx];\n
      if (part === \'..\') {\n
        if (path.length<1) throw new Error("invalid path: "+moduleId);\n
        path.pop();\n
\n
      } else if (part !== \'.\') path.push(part);\n
    }\n
\n
    moduleId = path.join(\'/\');\n
    if (packageId) moduleId = joinPackageId(packageId, moduleId);\n
  }\n
\n
  return moduleId ;\n
};\n
\n
\n
// ..........................................................\n
// SANDBOX\n
// \n
\n
/**\n
  A Sandbox maintains a cache of instantiated modules.  Whenever a modules \n
  is instantiated, it will always be owned by a single sandbox.  This way\n
  when you required the same module more than once, you will always get the\n
  same module.\n
  \n
  Each sandbox is owned by a single loader, which is responsible for providing\n
  the sandbox with Factory objects to instantiate new modules.\n
  \n
  A sandbox can also have a \'main\' module which can be used as a primary\n
  entry point for finding other related modules.\n
  \n
*/\n
var Sandbox = exports.extend(Object);\n
exports.Sandbox = Sandbox;\n
\n
Sandbox.prototype.init = function(loader, env, args, mainModuleId) {\n
  this.loader = loader;\n
  this.env    = env;\n
  this.args   = args;\n
  if (mainModuleId) this.main(mainModuleId);\n
\n
  this.clear();\n
};\n
\n
Sandbox.prototype.catalogPackages = function(workingPackage) {\n
  return this.loader.catalogPackages(workingPackage);\n
};\n
\n
Sandbox.prototype.createRequire = function(module) {\n
  \n
  var sandbox = this,\n
      curId   = module.id,\n
      curPkg  = module.ownerPackage,\n
      reqd;\n
      \n
  // basic synchronous require\n
  var req = function(moduleId, packageId) {\n
    if (packageId && moduleId.indexOf(\':\')<0) {\n
      if (packageId.isPackage) packageId = packageId.id;\n
      moduleId = packageId+\':\'+moduleId;\n
    }\n
    return sandbox.require(moduleId, curId, curPkg);\n
  };\n
  reqd = req.displayName = (curId||\'(unknown)\')+\'#require\';\n
\n
  // expose any native require.  Mostly used by seed\n
  req.nativeRequire = sandbox.nativeRequire;\n
  \n
  // async version - packageId is optional\n
  req.ensure = function(moduleIds, done) {\n
    // always normalize moduleId to an array\n
    if (!isArray(moduleIds)) {\n
      moduleIds = Array.prototype.slice.call(arguments);\n
      done = moduleIds.pop();\n
    }\n
\n
    // ensure each module is loaded \n
    parallel(moduleIds, function(moduleId, done) {\n
      sandbox.ensure(moduleId, curId, curPkg, done);\n
\n
    })(function(err) { \n
      if (err) return done(err);\n
      if (done.length<=1) return done(); // don\'t lookup modules themselves\n
      \n
      done(null, map(moduleIds, function(moduleId) {\n
        return sandbox.require(moduleId, curId, curPkg);\n
      }));\n
    });\n
  };\n
  req.ensure.displayName = reqd+\'.ensure\';\n
  \n
  // return true if the passed module or modules are ready for use right now\n
  // this is like calling ensure() but it won\'t load anything that isn\'t \n
  // actually ready\n
  req.ready = function(moduleIds) {\n
    var idx, len ;\n
    \n
    // always normalize moduleId to an array\n
    if (!isArray(moduleIds)) {\n
      moduleIds = Array.prototype.slice.call(arguments);\n
    }\n
\n
    len = moduleIds.length;\n
    for(idx=0;idx<len;idx++) {\n
      if (!sandbox.ready(moduleIds[idx], curId, curPkg)) return false;\n
    }\n
    return true;\n
  };\n
  req.ready.displayName = reqd+\'.ready\';\n
\n
  /**\n
    Returns the package for the named packageId and optional version from\n
    the perspective of the current package.  This invokes a similar method \n
    on the sandbox, which will pass it along to the loader, though a secure\n
    sandbox may actually wrap the responses as well.\n
    \n
    This method only acts on packages available locally.  To get possibly\n
    remote packages, you must first call require.ensurePackage() to ensure\n
    the package and its dependencies have been loaded.\n
    \n
    @param {String} packageId\n
      The packageId to load\n
      \n
    @param {String} vers\n
      Optional version\n
      \n
    @returns {Package} the package or null\n
  */\n
  req.packageFor = function(packageId, vers) {\n
    return sandbox.packageFor(packageId, vers, curPkg);\n
  };\n
  req.packageFor.displayName = reqd+\'.packageFor\';\n
  \n
  /**\n
    Asynchronously loads the named package and any dependencies if needed.\n
    This is only required if you suspect your package may not be available \n
    locally.  If your callback accepts only one parameter, then the packages\n
    will be loaded but not instantiated. The first parameter is always an \n
    error object or null.\n
    \n
    If your callback accepts more than one parameter, then the packages will\n
    be instantiated and passed to your callback as well.\n
  \n
    If a package cannot be loaded for some reason, your callback will be \n
    invoked with an error of type NotFound.\n
    \n
    @param {String} packageId\n
      The packageId to load\n
    \n
    @param {String} vers\n
      Optional version\n
\n
    @param {Function} done\n
      Callback invoked once packages have loaded.\n
    \n
    @returns {Package} the package or null\n
  */\n
  req.ensurePackage = function(packageId, vers, done) {\n
    sandbox.ensurePackage(packageId, vers, curPkg, function(err) {\n
      if (err) return done(err);\n
      if (done.length <= 1) return done();\n
      done(null, sandbox.packageFor(packageId, vers, curPkg));\n
    });\n
  };\n
  req.ensurePackage.displayName = reqd+\'.ensurePackage.displayName\';\n
  \n
  /**\n
    Returns a catalog of all packages visible to the current module without\n
    any additional loading.  This may be an expensive operation; you should\n
    only use it when necessary to detect plugins, etc.\n
  */\n
  req.catalogPackages = function() {\n
    return sandbox.catalogPackages(curPkg);\n
  };\n
  \n
  // mark main module in sandbox\n
  req.main = sandbox.main();\n
  req.env  = sandbox.env;\n
  req.args = sandbox.args;\n
  req.sandbox = sandbox;\n
  req.loader  = sandbox.loader;\n
  \n
  req.isTiki = true; // walk like a duck\n
  \n
  return req;\n
};\n
\n
// ..........................................................\n
// RESOLVING MODULE IDS\n
// \n
\n
Sandbox.prototype.Module = Module;\n
\n
/**\n
  Retrieves a module object for the passed moduleId.  You can also pass \n
  optional package information, including an optional curModuleId and a\n
  workingPackage.  You MUST pass at least a workingPackage.\n
  \n
  The returned module object represents the module but the module exports may\n
  not yet be instantiated.  Use require() to retrieve the module exports.\n
  \n
  @param {String} moduleId\n
    The module id to lookup.  Should include a nested packageId\n
    \n
  @param {String} curModuleId\n
    Optional current module id to resolve relative modules.\n
    \n
  @param {Package} workingPackage\n
    The working package making the request\n
    \n
  @returns {void}\n
*/\n
Sandbox.prototype.module = function(moduleId, curModuleId, workingPackage) {\n
\n
  var ret, canonicalId, cache, packageId, idx, pkg;\n
  \n
  // assume canonicalId will normalize params\n
  canonicalId = this.loader.canonical(moduleId, curModuleId, workingPackage);\n
  if (!canonicalId) throw(new NotFound(moduleId, workingPackage));\n
\n
  // get out of cache first\n
  cache = this.modules;\n
  if (!cache) cache = this.modules = {};\n
  if (ret = cache[canonicalId]) return ret;\n
  \n
  // not in cache...add it\n
  idx       = canonicalId.indexOf(\':\', 2);\n
  moduleId  = canonicalId.slice(idx+1);\n
  packageId = canonicalId.slice(0, idx);\n
  pkg = this.loader.packageFor(packageId, workingPackage);\n
  if (!pkg) throw(new NotFound(packageId, workingPackage));\n
  ret = cache[canonicalId] = new this.Module(moduleId, pkg, this);\n
  \n
  return ret ;\n
};\n
\n
/**\n
  Returns the main module for the sandbox.  This should only be called \n
  from the factory when it is setting main on itself.  Otherwise the main\n
  module may not exist yet.\n
  \n
  Note that the mainModule will be resolved using the anonymousPackage so\n
  the named module must be visible from there.\n
*/\n
Sandbox.prototype.main = function(newMainModuleId, workingPackage) {\n
  if (newMainModuleId !== undefined) {\n
    this._mainModule = null;\n
    this._mainModuleId = newMainModuleId;\n
    this._mainModuleWorkingPackage = workingPackage;\n
    return this;\n
    \n
  } else {\n
    if (!this._mainModule && this._mainModuleId) {\n
      workingPackage = this._mainModuleWorkingPackage;\n
      this._mainModule = this.module(this._mainModuleId, workingPackage);\n
    }\n
    return this._mainModule;\n
  }\n
};\n
\n
/**\n
  Returns the exports for the named module.\n
\n
  @param {String} moduleId\n
    The module id to lookup.  Should include a nested packageId\n
  \n
  @param {String} curModuleId\n
    Optional current module id to resolve relative modules.\n
  \n
  @param {Package} workingPackage\n
    The working package making the request\n
  \n
  @param {Function} done\n
    Callback to invoke when the module has been retrieved.\n
  \n
  @returns {void}\n
*/\n
Sandbox.prototype.require = function(moduleId, curModuleId, workingPackage) {\n
\n
  var ret, canonicalId, cache, used, factory, module, exp;\n
  \n
  // assume canonical() will normalize params\n
  canonicalId = this.loader.canonical(moduleId, curModuleId, workingPackage);\n
  if (!canonicalId) throw new NotFound(moduleId, workingPackage);\n
\n
  // return out of cache\n
  cache = this.exports; used  = this.usedExports;\n
  if (!cache) cache = this.exports = {};\n
  if (!used)  used  = this.usedExports = {};\n
  if (ret = cache[canonicalId]) {\n
    ret = ret.exports;\n
    if (!used[canonicalId]) used[canonicalId] = ret;\n
    return ret;\n
  }\n
\n
  // not in cache, get factory, module, and run function...\n
  factory = this.loader.load(canonicalId, workingPackage, this);\n
  if (!factory) throw(new NotFound(canonicalId, workingPackage));\n
\n
  module  = this.module(canonicalId, workingPackage);\n
  cache[canonicalId] = module;\n
\n
  exp = factory.call(this, module);\n
  module.exports = exp;\n
  \n
  // check for cyclical refs\n
  if (used[canonicalId] && (used[canonicalId] !== exp)) {\n
    throw new Error("cyclical requires() in "+canonicalId);\n
  }\n
\n
  return exp;\n
};\n
\n
/**\n
  Returns true if the given module is ready. This checks the local cache \n
  first then hands this off to the loader.\n
*/\n
Sandbox.prototype.ready = function(moduleId, curModuleId, workingPackage) {\n
  // assume canonicalPackageId() will normalize params\n
  var id = this.loader.canonical(moduleId, curModuleId, workingPackage);\n
  return id ? this.loader.ready(id) : false;\n
};\n
\n
/**\n
  Ensures the passed moduleId and all of its dependencies are available in\n
  the local domain.  If any dependencies are not available locally, attempts\n
  to retrieve them from a remote server.\n
  \n
  You don\'t usually call this method directly.  Instead you should call the \n
  require.ensure() method defined on a module\'s local require() method.\n
  \n
*/\n
Sandbox.prototype.ensure = function(moduleId, curModuleId, workingPackage, done) {\n
\n
  var id, loader, packageId, idx;\n
  \n
  // normalize params so that done is in right place\n
  if (curModuleId && (T_STRING !== typeof curModuleId)) {\n
    done = workingPackage;\n
    workingPackage = curModuleId;\n
    curModuleId = null;\n
  }\n
  \n
  if (workingPackage && (T_FUNCTION === typeof workingPackage)) {\n
    done = workingPackage ;\n
    workingPackage = null;\n
  }\n
  \n
  id = this.loader.canonical(moduleId, curModuleId, workingPackage);\n
  if (!id) return done(new NotFound(moduleId, workingPackage));\n
  \n
  idx       = id.indexOf(\':\', 2);\n
  moduleId  = id.slice(idx+1);\n
  packageId = id.slice(0, idx);\n
  loader    = this.loader;\n
\n
  loader.ensurePackage(packageId, workingPackage, function(err) {\n
    if (err) return done(err);\n
    var pkg = loader.packageFor(packageId, workingPackage);\n
    if (!pkg.exists(moduleId)) done(new NotFound(moduleId, pkg));\n
    else done(); // all clear\n
  });\n
};\n
\n
/**\n
  TODO: document\n
*/\n
Sandbox.prototype.packageFor = function(packageId, vers, workingPackage) {\n
\n
  // assume canonicalPackageId() will normalize params\n
  var id = this.loader.canonicalPackageId(packageId, vers, workingPackage);\n
  if (!id) return null;\n
  return this.loader.packageFor(id);\n
};\n
\n
/** \n
  TODO: document\n
*/\n
Sandbox.prototype.ensurePackage = function(packageId, vers, workingPackage, done) {\n
\n
  // normalize params so that done is in right place\n
  if (vers && (T_STRING !== typeof vers)) {\n
    done = workingPackage;\n
    workingPackage = vers;\n
    vers = null;\n
  }\n
  \n
  if (workingPackage && (T_FUNCTION === typeof workingPackage)) {\n
    done = workingPackage ;\n
    workingPackage = null;\n
  }\n
  \n
  var id = this.loader.canonicalPackageId(packageId, vers, workingPackage);\n
  if (!id) return done(new NotFound(packageId, workingPackage));\n
  this.loader.ensurePackage(id, done);\n
};\n
\n
\n
/**\n
  Returns the path or URL to a resource in the named package. \n
*/\n
Sandbox.prototype.resource = function(resourceId, moduleId, ownerPackage) {\n
  if (!ownerPackage.resource) return null;\n
  return ownerPackage.resource(resourceId, moduleId);\n
};\n
\n
/**\n
  Clears the sandbox.  requiring modules will cause them to be reinstantied\n
*/\n
Sandbox.prototype.clear = function() {\n
  this.exports = {};\n
  this.modules = {};\n
  this.usedExports = {};\n
  return this;\n
};\n
\n
// ..........................................................\n
// BROWSER\n
// \n
\n
// Implements a default loader source for use in the browser.  This object\n
// should also be set as the "require" global on the browser to allow for\n
// module registrations\n
\n
var Browser = exports.extend(Object);\n
exports.Browser = Browser;\n
\n
Browser.prototype.init = function() {\n
  this._ready  = {};\n
  this._unload = {};\n
  \n
  this.clear();\n
};\n
\n
/**\n
  Reset the browser caches.  This would require all packages and modules \n
  to register themselves.  You should also clear the associated loader and\n
  sandbox if you use this.\n
*/\n
Browser.prototype.clear = function() {\n
  this.packageInfoByName = {}; // stores package info sorted by name/version\n
  this.packageInfoById   = {}; // stores package info sorted by id\n
  this.packages    = {}; // instantiated packages\n
  this.factories   = {}; // registered module factories by id\n
\n
  this.stylesheetActions = {}; // resolvable stylesheet load actions\n
  this.scriptActions     = {}; // resolvable script actions\n
  this.ensureActions     = {}; // resolvable package actions\n
};\n
\n
/**\n
  Configures a basic sandbox environment based on the browser.  Now you can\n
  register and require from it.\n
  \n
  @returns {Browser} new instance\n
*/\n
Browser.start = function(env, args, queue) {\n
  // build new chain of objects and setup require.\n
  var browser, len, idx, action;\n
  \n
  browser         = new Browser();\n
  browser.loader  = new Loader([browser]);\n
  browser.sandbox = new Sandbox(browser.loader, env, args);\n
  browser.queue   = queue;\n
\n
  var mod = { \n
    id: \'index\', \n
    ownerPackage: browser.loader.anonymousPackage \n
  };\n
\n
  browser.require = browser.sandbox.createRequire(mod);\n
  // TODO: amend standard CommonJS methods for loading modules when they\n
  // are standardized\n
  \n
  return browser;\n
};\n
\n
Browser.prototype.replay = function() {\n
  var queue = this.queue,\n
      len   = queue ? queue.length : 0,\n
      idx, action;\n
      \n
  this.queue = null;\n
  for(idx=0;idx<len;idx++) {\n
    action = queue[idx];\n
    this[action.m].apply(this, action.a);\n
  }\n
  \n
  return this;\n
};\n
\n
// safe - in place of preamble start()\n
Browser.prototype.start = function() {\n
  return this;\n
};\n
\n
/**\n
  Makes all dependencies of the passed canonical packageId global.  Used\n
  for backwards compatibility with non-CommonJS libraries.\n
*/\n
Browser.prototype.global = function(canonicalId) {\n
  if (!domAvailable && !xhrAvailable) return this;  // don\'t work out of brsr\n
  var GLOBAL = (function() { return this; })();\n
  \n
  var globals, pkg, deps, packageId, exports, keys, key, idx, len;\n
  \n
  globals = this.globals;\n
  if (!globals) globals = this.globals = {};\n
\n
  pkg = this.packageFor(canonicalId);\n
  if (!pkg) throw new Error(canonicalId+\' package not found\');\n
  \n
  deps = pkg.get(\'dependencies\');\n
  if (!deps) return this; // nothing to do\n
  \n
  for(packageId in deps) {\n
    if (!deps.hasOwnProperty(packageId)) continue;\n
    canonicalId  = this.loader.canonical(packageId, pkg);\n
    if (globals[canonicalId]) continue;\n
    globals[canonicalId] = true;\n
    \n
    // some cases a dependency refers to a package that is itself not \n
    // using modules.  In this case just ignore\n
    if (!this.sandbox.ready(packageId, pkg)) continue;\n
    \n
    exports = this.sandbox.require(packageId, pkg);\n
    if (keys = exports.__globals__) {\n
      len = keys.length;\n
      for(idx=0;idx<len;idx++) {\n
        key = keys[idx];\n
        GLOBAL[key] = exports[key];\n
      }\n
\n
    // no __globals__ key is defined so just iterate through any exported\n
    // properties. this should actually be the more common case\n
    } else {\n
      for(key in exports) {\n
        if (!exports.hasOwnProperty(key)) continue;\n
        GLOBAL[key] = exports[key];\n
      }\n
    }\n
    \n
  }\n
\n
  return this;\n
};\n
\n
// ..........................................................\n
// Ready & Unload Handlers\n
// \n
\n
var buildInvocation = function(args) {\n
  var context, method;\n
  \n
  if (args.length === 1) {\n
    context = null;\n
    method  = args[0];\n
    args = Array.prototype.slice.call(args, 1);\n
  } else {\n
    context = args[0];\n
    method  = args[1];\n
    args    = Array.prototype.slice.call(args, 2);\n
  }\n
\n
  return { target: context, method: method, args: args };\n
};\n
\n
var queueListener = function(base, queueName, args) {\n
  if (!base[queueName]) base[queueName] = [];\n
  base[queueName].push(buildInvocation(args));\n
};\n
\n
/**\n
  Invoke the passed callback when the document is ready.  You can pass \n
  either an object/function or a moduleId and property name plus additional\n
  arguments.\n
*/\n
Browser.prototype.addReadyListener = function(context, method) {\n
  if (this._ready && this._ready.isReady) {\n
    this._invoke(buildInvocation(arguments));\n
  } else {\n
    this._setupReadyListener();\n
    queueListener(this._ready, \'queue\', arguments);\n
  }\n
};\n
\n
/**\n
  Invoke the passed callback just after any ready listeners have fired but\n
  just before the main moduleId is required.  This is primarily provided as \n
  a way for legacy environments to hook in their own main function.\n
*/\n
Browser.prototype.addMainListener = function(context, method) {\n
  if (this._ready && this._ready.isReady) {\n
    this._invoke(buildInvocation(arguments));\n
  } else {\n
    this._setupReadyListener();\n
    queueListener(this._ready, \'mqueue\', arguments);\n
  }\n
};\n
\n
/**\n
  Invoke the passed callback when the browser is about to unload.\n
*/\n
Browser.prototype.addUnloadListener = function(context, method) {\n
  if (this._unload && this._unload.isUnloading) {\n
    this._invoke(buildInvocation(arguments));\n
  } else {\n
    this._setupUnloadListener();\n
    queueListener(this._unload, \'queue\', arguments);\n
  }\n
};\n
\n
\n
Browser.prototype._invoke = function(inv) {\n
  var target = inv.target, method = inv.method;\n
  if (T_STRING === typeof target) target = this.require(target);\n
  if (T_STRING === typeof method) method = target[method];\n
  if (method) method.apply(target, inv.args);\n
  inv.target = inv.method = inv.args = null;\n
};\n
\n
Browser.prototype._setupReadyListener = function() {\n
  if (this._ready.setup) return this;\n
  this._ready.setup =true;\n
  \n
  var ready = this._ready, source = this, fire;\n
  \n
  fire = function() {\n
    if (ready.isReady) return;\n
    ready.isReady = true;\n
    \n
    // first cleanup any listeners so they don\'t fire again\n
    if (ready.cleanup) ready.cleanup();\n
    ready.cleanup = null;\n
    \n
    var q, len, idx;\n
    \n
    q = ready.queue;\n
    len = q ? q.length : 0;\n
    ready.queue = null;\n
    for(idx=0;idx<len;idx++) source._invoke(q[idx]);\n
    \n
    q = ready.mqueue;\n
    len = q ? q.length : 0 ;\n
    ready.mqueue = null;\n
    for(idx=0;idx<len;idx++) source._invoke(q[idx]);\n
\n
    source._runMain(); // get main module.\n
  };\n
      \n
  // always listen for onready event - detect based on platform\n
  // those code is derived from jquery 1.3.1\n
  // server-side JS\n
  if (T_UNDEFINED === typeof document) {\n
    // TODO: handler server-side JS cases here\n
\n
  // Mozilla, Opera, webkit nightlies\n
  } else if (document.addEventListener) {\n
\n
    // cleanup handler to be called whenever any registered listener fires\n
    // should prevent additional listeners from firing\n
    ready.cleanup = function() {\n
      document.removeEventListener(\'DOMContentLoaded\', fire, false);\n
      document.removeEventListener(\'load\', fire, false);\n
    };\n
\n
    // register listeners\n
    document.addEventListener(\'DOMContentLoaded\', fire, false);\n
    document.addEventListener(\'load\', fire, false);\n
\n
  // IE\n
  } else if (document.attachEvent) {\n
\n
    // cleanup handler - should cleanup all registered listeners\n
    ready.cleanup = function() {\n
      document.detachEvent(\'onreadystatechange\', fire);\n
      document.detachEvent(\'onload\', fire);\n
      ready.ieHandler = null; // will stop the ieHandler from firing again\n
    };\n
\n
    // listen for readystate and load events\n
    document.attachEvent(\'onreadystatechange\', fire);\n
    document.attachEvent(\'onload\', fire);\n
\n
    // also if IE and no an iframe, continually check to see if the document \n
    // is ready\n
    // NOTE: DO NOT CHANGE TO ===, FAILS IN IE.\n
    if ( document.documentElement.doScroll && window == window.top ) {\n
      ready.ieHandler = function() {\n
\n
        // If IE is used, use the trick by Diego Perini\n
        // http://javascript.nwbox.com/IEContentLoaded/\n
        if (ready.ieHandler && !ready.isReady) {\n
          try {\n
            document.documentElement.doScroll("left");\n
          } catch( error ) {\n
            setTimeout( ready.ieHandler, 0 );\n
            return;\n
          }\n
        }\n
\n
        // and execute any waiting functions\n
        fire();\n
      };\n
\n
      ready.ieHandler();\n
    }\n
\n
  }  \n
};\n
\n
Browser._scheduleUnloadListener = function() {\n
  if (this._unload.setup) return this;\n
  this._unload.setup =true;\n
  \n
  var unload = this._unload, source = this, fire;\n
\n
  unload.isUnloading = false;\n
  fire = function() { \n
    if (unload.isUnloading) return;\n
    unload.isUnloading = true;\n
    \n
    if (unload.cleanup) unload.cleanup();\n
    unload.cleanup = null;\n
    \n
    var q = unload.queue,\n
        len = q ? q.length : 0,\n
        idx, inv;\n
        \n
    unload.queue = null;\n
    for(idx=0;idx<len;idx++) source._invoke(q[idx]);\n
  };\n
\n
  if (T_UNDEFINED === typeof document) {\n
    // TODO: Handle server-side JS mode\n
    \n
  } else if (document.addEventListener) {\n
    unload.cleanup = function() {\n
      document.removeEventListener(\'unload\', fire);\n
    };\n
    document.addEventListener(\'unload\', fire, false);\n
    \n
  } else if (document.attachEvent) {\n
    unload.cleanup = function() {\n
      document.detachEvent(\'onunload\', fire);\n
    };\n
    document.attachEvent(\'unload\', fire);\n
  }\n
  \n
};\n
\n
// ..........................................................\n
// Registration API\n
// \n
\n
/**\n
  Sets the main moduleId on the sandbox.  This module will be automatically\n
  required after all other ready and main handlers have run when the document\n
  is ready.\n
  \n
  @param {String} moduleId\n
    A moduleId with packageId included ideally.  Can be canonicalId.\n
    \n
  @returns {void}\n
*/\n
Browser.prototype.main = function(moduleId, method) {\n
  if (this.sandbox) this.sandbox.main(moduleId);\n
  this._setupReadyListener(); // make sure we listen for ready event\n
  this._main = { id: moduleId, method: method };\n
};\n
\n
Browser.prototype._runMain = function() {\n
  if (!this._main) return ;\n
  \n
  var moduleId = this._main.id,\n
      method   = this._main.method,\n
      req      = this.require;\n
  \n
  if (!moduleId || !req) return ;\n
  this._main = null;\n
\n
  // async load any main module dependencies if needed then require\n
  req.ensure(moduleId, function(err) {\n
    if (err) throw err;\n
    var exp = req(moduleId);\n
    if (T_STRING === typeof method) method = exp[method];\n
    if (method) method.call(exp);\n
  });\n
};\n
\n
\n
// creates a new action that will invoke the passed value then setup the\n
// resolve() method to wait on response\n
Browser.prototype._action  = function(action) {\n
  var ret;\n
  \n
  ret = once(function(done) {\n
    ret.resolve = function(err, val) {\n
      ret.resolve = null; // no more...\n
      done(err, val);\n
    };\n
    action(); \n
  });\n
  return ret;\n
  \n
};\n
\n
Browser.prototype._resolve = function(dict, key, value) {\n
  \n
  // for pushed content, just create the action function\n
  if (!dict[key]) dict[key] = function(done) { done(null, value); };\n
  \n
  // if a value already exists, call resolve if still valid\n
  else if (dict[key].resolve) dict[key].resolve(null, value);\n
  return this;\n
};\n
\n
Browser.prototype._fail = function(dict, key, err) {\n
  if (dict[key].resolve) dict[key].resolve(err);\n
};\n
\n
var T_SCRIPT     = \'script\',\n
    T_STYLESHEET = \'stylesheet\',\n
    T_RESOURCE   = \'resource\';\n
    \n
/**\n
  Normalizes package info, expanding some compacted items out to full \n
  info needed.\n
*/\n
Browser.prototype._normalize = function(def, packageId) {\n
  if (!isCanonicalId(packageId)) packageId = \'::\'+packageId;\n
  def.id = packageId;\n
  def.version = semver.normalize(def.version);\n
  def[\'tiki:external\'] = !!def[\'tiki:external\']; \n
  def[\'tiki:private\']  = !!def[\'tiki:private\'];  // ditto\n
\n
  // expand list of resources\n
  var base = def[\'tiki:base\']; \n
  if (def[\'tiki:resources\']) {\n
\n
    def[\'tiki:resources\'] = map(def[\'tiki:resources\'], function(item) {\n
      \n
      // expand a simple string into a default entry\n
      if (T_STRING === typeof item) {\n
        item = { \n
          id: packageId+\':\'+item,\n
          name: item \n
        };\n
      }\n
\n
      // must have an item name or you can\'t lookup the resource\n
      if (!item.name) {\n
        throw new InvalidPackageDef(def, \'resources must have a name\');\n
      }\n
\n
      if (!item.id) {\n
        item.id = packageId+\':\'+item.name;\n
      }\n
      if (!isCanonicalId(item.id)) item.id = \'::\'+item.id;\n
      \n
      // assume type from ext if one is provided\n
      if (!item.type) {\n
        if (item.name.match(/\\.js$/)) item.type = T_SCRIPT;\n
        else if (item.name.match(/\\.css$/)) item.type = T_STYLESHEET;\n
        else item.type = T_RESOURCE;\n
      }\n
      \n
      if (!item.url) {\n
        if (base) item.url = base+\'/\'+item.name;\n
        else item.url = item.id+item.name;\n
      }\n
      \n
      return item;\n
    });\n
  }\n
   \n
  // always have a nested and dependencies hash, even if it is empty\n
  if (!def.dependencies) def.dependencies = {};\n
\n
  var nested = def[\'tiki:nested\'], key;\n
  if (nested) {\n
    for(key in nested) {\n
      if (!nested.hasOwnProperty(key)) continue;\n
      if (!isCanonicalId(nested[key])) nested[key] = \'::\'+nested[key];\n
    }\n
    \n
  } else def[\'tiki:nested\'] = {};\n
  \n
  return def;\n
};\n
\n
/**\n
  Register new package information.\n
*/\n
Browser.prototype.register = function(packageId, def) {\n
  var reg, replace, name, vers, idx = -1;\n
  \n
  // normalize some basics...\n
  def = this._normalize(def, packageId);\n
  packageId = def.id; // make sure to get normalized packageId\n
\n
  // see if a pkg with same id is registered.  if so, replace it only if \n
  // the new one is not external and the old one is\n
  reg = this.packageInfoById;\n
  if (!reg) reg = this.packageInfoById = {};\n
  if (reg[packageId]) {\n
    if (!reg[packageId][\'tiki:external\']) return this;\n
    replace = reg[packageId];\n
  }\n
  reg[packageId] = def;\n
  \n
  if (def.name) {\n
    name = def.name;\n
    vers = def.version;\n
    \n
    reg = this.packageInfoByName;\n
    if (!reg) reg = this.packageInfoByName = {};\n
    if (!reg[name]) reg[name] = {};\n
    reg = reg[name];\n
    \n
    // update list of packageIds matching version...\n
    if (!reg[vers] || (reg[vers].length<=1)) {\n
      reg[vers] = [def];\n
    } else {\n
      if (replace) idx = reg[vers].indexOf(replace);\n
      if (idx>=0) {\n
        reg[vers] = reg[vers].slice(0, idx).concat(reg[vers].slice(idx+1));\n
      }\n
      reg[vers].push(def);\n
    }\n
    \n
  }\n
  \n
  return this;\n
};\n
\n
/**\n
  Main registration API for all modules.  Simply registers a module for later\n
  use by a package.\n
*/\n
Browser.prototype.module = function(key, def) {\n
  if (!isCanonicalId(key)) key = \'::\'+key;\n
  this.factories[key] = def;\n
  return this; \n
};\n
\n
/**\n
  Register a script that has loaded\n
*/\n
Browser.prototype.script = function(scriptId) {\n
  if (!isCanonicalId(scriptId)) scriptId = \'::\'+scriptId;\n
  this._resolve(this.scriptActions, scriptId, true);\n
};\n
\n
/**\n
  Register a stylesheet that has loaded.\n
*/\n
Browser.prototype.stylesheet = function(stylesheetId) {\n
  if (!isCanonicalId(stylesheetId)) stylesheetId = \'::\'+stylesheetId;\n
  this._resolve(this.stylesheetActions, stylesheetId, true);\n
};\n
\n
// ..........................................................\n
// Called by Loader\n
//\n
\n
var domAvailable = T_UNDEFINED !== typeof document && document.createElement;\n
var xhrAvailable = T_UNDEFINED !== typeof XMLHttpRequest;\n
\n
/**\n
  Whether to use XHR by default. If true, XHR is tried first to fetch script\n
  resources; script tag injection is only used as a fallback if XHR fails. If\n
  false (the default if the DOM is available), script tag injection is tried\n
  first, and XHR is used as the fallback.\n
*/\n
Browser.prototype.xhr = !domAvailable;\n
\n
/**\n
  Whether to automatically wrap the fetched JavaScript in tiki.module() and\n
  tiki.script() calls. With this on, CommonJS modules will "just work" without\n
  preprocessing. Setting this to true requires, and implies, that XHR will be\n
  used to fetch the files.\n
*/\n
Browser.prototype.autowrap = false;\n
\n
var findPublicPackageInfo = function(infos) {\n
  if (!infos) return null;\n
  \n
  var loc = infos.length;\n
  while(--loc>=0) {\n
    if (!infos[loc][\'tiki:private\']) return infos[loc];\n
  }\n
  return null;\n
};\n
\n
/**\n
  Find the canonical package ID for the passed package ID and optional \n
  version.  This will look through all the registered package infos, only\n
  searching those that are not private, but including external references.\n
*/\n
Browser.prototype.canonicalPackageId = function(packageId, vers) {\n
  var info = this.packageInfoByName[packageId],\n
      ret, cur, cvers, rvers;\n
  \n
  if (vers) vers = semver.normalize(vers);\n
  if (!info) return null; // not found\n
  \n
  // see if we have caught a lucky break\n
  if (info[vers] && (info[vers].length===1)) return info[vers][0].id;\n
\n
  // need to search...\n
  for(cvers in info) {\n
    if (!info.hasOwnProperty(cvers)) continue;\n
    if (!semver.compatible(vers, cvers)) continue;\n
    if (!ret || (semver.compare(rvers, cvers)<0)) {\n
      ret = findPublicPackageInfo(info[cvers]);\n
      if (ret) rvers = cvers; \n
    }\n
  }\n
  \n
  return ret ? ret.id : null;\n
};\n
\n
// get package for canonicalId, instantiate if needed\n
Browser.prototype.packageFor = function(canonicalId) {\n
  var ret = this.packages[canonicalId];\n
  if (ret) return ret ;\n
\n
  // instantiate if needed\n
  ret = this.packageInfoById[canonicalId];\n
  if (ret && !ret[\'tiki:external\']) { // external refs can\'t be instantiated\n
    ret = new this.Package(canonicalId, ret, this);\n
    this.packages[canonicalId] = ret;\n
    return ret ;\n
  }\n
\n
  return null ; // not found\n
};\n
\n
/**\n
  Ensures the named canonical packageId and all of its dependent scripts are\n
  loaded.\n
*/\n
Browser.prototype.ensurePackage = function(canonicalId, done) {\n
  var action = this.ensureActions[canonicalId];\n
  if (action) return action(done); // add another listener\n
  \n
  // no action get - get the package info and start one.\n
  var info = this.packageInfoById[canonicalId];\n
  if (!info) {\n
    return done(new NotFound(canonicalId, \'browser package info\'));\n
  }\n
  \n
  var source = this;\n
  \n
  action = once(function(done) {\n
    var cnt = 1, ready = false, cancelled;\n
    \n
    // invoked when an action finishes.  Will resolve this action\n
    // when all of them finish.\n
    var cleanup = function(err) {\n
      if (cancelled) return;\n
      if (err) {\n
        cancelled = true;\n
        return done(err);\n
      }\n
      \n
      cnt = cnt-1;\n
      if (cnt<=0 && ready) return done(null, info);\n
    };\n
\n
    // proactively kick off any known packages.  If a dependent package\n
    // is not known here just skip it for now.  This is just an optimization\n
    // anyway.  The Loader will take care of ensuring all dependencies are\n
    // really met.\n
    var dependencies = info.dependencies,\n
        nested       = info[\'tiki:nested\'],\n
        packageId, vers, depInfo, curId;\n
\n
    for(packageId in dependencies) {\n
      if (!dependencies.hasOwnProperty(packageId)) continue;\n
      curId = nested[packageId];\n
      if (!curId) {\n
        vers = dependencies[packageId];\n
        curId = source.canonicalPackageId(packageId, vers);\n
      }\n
      \n
      if (curId && source.packageInfoById[canonicalId]) {\n
        cnt++;\n
        source.ensurePackage(curId, cleanup);\n
      }\n
    }\n
    \n
    // step through resources and kick off each script and stylesheet\n
    var resources = info[\'tiki:resources\'], \n
        lim = resources ? resources.length : 0,\n
        loc, rsrc;\n
    for(loc=0;loc<lim;loc++) {\n
      rsrc = resources[loc];\n
      if (rsrc.type === T_RESOURCE) continue;\n
      if (rsrc.type === T_SCRIPT) {\n
        cnt++;\n
        source.ensureScript(rsrc.id, rsrc.url, cleanup);\n
      } else if (rsrc.type === T_STYLESHEET) {\n
        cnt++;\n
        source.ensureStylesheet(rsrc.id, rsrc.url, cleanup);\n
      }\n
    }\n
      \n
    // done, set ready to true so that the final handler can fire\n
    ready = true;\n
    cleanup(); \n
    \n
  });\n
  \n
  this.ensureActions[canonicalId] = action;\n
  action(done); // kick off\n
};\n
\n
Browser.prototype.ensureScript = function(id, url, done) {\n
  var action = this.scriptActions[id];\n
  if (action) return action(done);\n
  \n
  var source = this;\n
  action = this._action(function() {\n
    source._loadScript(id, url);\n
  });\n
  \n
  this.scriptActions[id] = action;\n
  return action(done);\n
};\n
\n
Browser.prototype.ensureStylesheet = function(id, url, done) {\n
  var action = this.stylesheetActions[id];\n
  if (action) return action(done);\n
  \n
  var source = this;\n
  action = this._action(function() {\n
    source._loadStylesheet(id, url);\n
  });\n
\n
  this.stylesheetActions[id] = action;\n
  return action(done);\n
};\n
\n
Browser.prototype._injectScript = function(id, url) {\n
  var body, el;\n
\n
  body = document.body;\n
  el = document.createElement(\'script\');\n
  el.src = url;\n
  body.appendChild(el);\n
  body = el = null;\n
};\n
\n
Browser.prototype._xhrScript = function(id, url) {\n
  var autowrap = this.autowrap;\n
\n
  var req = new XMLHttpRequest();\n
  req.open(\'GET\', url, true);\n
  req.onreadystatechange = function(evt) {\n
    // Accept 200 or 0 for local file requests.\n
    if (req.readyState !== 4 || (req.status !== 200 && req.status !== 0)) {\n
      return;\n
    }\n
\n
    var src = req.responseText;\n
    if (autowrap) {\n
      src = "tiki.module(\'" + id + "\', function(require, exports, module) {" +\n
        src + "});" + "tiki.script(\'" + id + "\');";\n
    }\n
\n
    // Add a Firebug-style sourceURL parameter to help debugging.\n
    eval(src + "\\n//@ sourceURL=" + url);\n
\n
    // Immediately return after the eval. The script may have stomped all over\n
    // our local state.\n
  };\n
\n
  req.send(null);\n
};\n
\n
Browser.prototype._loadScript = function(id, url) {\n
    if (this.autowrap) {\n
        this.xhr = true;\n
        if (!xhrAvailable) {\n
            DEBUG(\'Autowrap is on but XHR is not available. Danger ahead.\');\n
        }\n
    }\n
\n
    if (xhrAvailable && domAvailable) {\n
        if (this.xhr) {\n
            try {\n
                return this._xhrScript(id, url);\n
            } catch (e) {\n
                return this._injectScript(id, url);\n
            }\n
        } else {\n
            try {\n
                return this._injectScript(id, url);\n
            } catch (e) {\n
                return this._xhrScript(id, url);\n
            }\n
        }\n
    } else if (xhrAvailable) {\n
        return this._xhrScript(id, url);\n
    } else if (domAvailable) {\n
        return this._injectScript(id, url);\n
    }\n
\n
    DEBUG(\'Browser#_loadScript() not supported on this platform.\');\n
    this.script(id);\n
};\n
\n
if (domAvailable) {\n
  // actually loads the stylesheet.  separated out to ease unit testing\n
  Browser.prototype._loadStylesheet = function(id, url) {\n
    var body, el;\n
    \n
    body = document.getElementsByTagName(\'head\')[0] || document.body;\n
    el   = document.createElement(\'link\');\n
    el.rel = \'stylesheet\';\n
    el.href = url;\n
    el.type = \'text/css\';\n
    body.appendChild(el);\n
    el = body = null;\n
\n
    this.stylesheet(id); // no onload support - just notify now.\n
  };\n
} else {\n
  // actually loads the stylesheet.  separated out to ease unit testing\n
  Browser.prototype._loadStylesheet = function(id, url) {\n
    DEBUG(\'Browser#_loadStylesheet() not supported on this platform.\');\n
    this.stylesheet(id);\n
  };\n
}\n
\n
\n
\n
// ..........................................................\n
// BROWSER PACKAGE\n
// \n
\n
/**\n
  Special edition of Package designed to work with the Browser source.  This\n
  kind of package knows how to get its data out of the Browser source on \n
  demand.\n
*/\n
var BrowserPackage = Package.extend();\n
Browser.prototype.Package = BrowserPackage;\n
\n
BrowserPackage.prototype.init = function(id, config, source) {\n
  Package.prototype.init.call(this, id, config);\n
  this.source = source;\n
};\n
\n
// if not self, look for nested packages\n
BrowserPackage.prototype.canonicalPackageId = function(packageId, vers) {\n
  var ret, nested, info;\n
  \n
  ret = Package.prototype.canonicalPackageId.call(this, packageId, vers);\n
  if (ret) return ret ;\n
  \n
  nested = this.get(\'tiki:nested\') || {}; \n
  ret = nested[packageId];\n
  if (!ret) return null;\n
\n
  info = this.source.packageInfoById[ret];\n
  return info && semver.compatible(vers,info.version) ? ret : null;\n
};\n
\n
BrowserPackage.prototype.packageFor = function(canonicalId) {\n
  var ret = Package.prototype.packageFor.call(this, canonicalId);\n
  return ret ? ret : this.source.packageFor(canonicalId);\n
};\n
\n
BrowserPackage.prototype.ensurePackage = function(canonicalId, done) {\n
  if (canonicalId === this.id) return done(); \n
  this.source.ensurePackage(canonicalId, done);\n
};\n
\n
BrowserPackage.prototype.catalogPackages = function() {\n
  var ret = [this], nested, key;\n
\n
  nested = this.get(\'tiki:nested\') || {};\n
  for(key in nested) {\n
    if (!nested.hasOwnProperty(key)) continue;\n
    ret.push(this.source.packageFor(nested[key]));\n
  }\n
  \n
  return ret ;\n
};\n
\n
BrowserPackage.prototype.exists = function(moduleId) {\n
  var canonicalId = this.id+\':\'+moduleId;\n
  return !!this.source.factories[canonicalId];\n
};\n
\n
BrowserPackage.prototype.load = function(moduleId) {\n
  var canonicalId, factory;\n
  \n
  canonicalId = this.id+\':\'+moduleId;\n
  factory  = this.source.factories[canonicalId];\n
  return factory ? new this.Factory(moduleId, this, factory) : null;\n
};\n
\n
BrowserPackage.prototype.Factory = Factory;\n
\n
\n
displayNames(exports, \'tiki\');\n
\n
});\n
// ==========================================================================\n
// Project:   Tiki - CommonJS Runtime\n
// Copyright: ©2009-2010 Apple Inc. All rights reserved.\n
// License:   Licened under MIT license (see __preamble__.js)\n
// ==========================================================================\n
/*globals tiki ENV ARGS */\n
\n
// This postamble runs when the loader and supporting modules are all \n
// registered, allowing the real loader to replace the bootstrap version.\n
// it is not wrapped as a module so that it can run immediately.\n
"use modules false";\n
"use loader false";\n
\n
// note that the loader.start method is safe so that calling this more than\n
// once will only setup the default loader once.\n
tiki = tiki.start();\n
tiki.replay(); // replay queue\n
\n
bespin.tiki = tiki;\n
})();\n
\n
;bespin.tiki.register("::bespin", {\n
    name: "bespin",\n
    dependencies: {  }\n
});bespin.bootLoaded = true;\n
bespin.tiki.module("bespin:plugins",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
require("globals");\n
\n
var Promise = require("promise").Promise;\n
var group = require("promise").group;\n
var builtins = require("builtins");\n
var console = require("console").console;\n
var util = require("util/util");\n
var Trace = require("util/stacktrace").Trace;\n
var proxy = require(\'proxy\');\n
\n
var r = require;\n
\n
var loader = require.loader;\n
var browser = loader.sources[0];\n
\n
var USER_DEACTIVATED    = \'USER\';\n
var DEPENDS_DEACTIVATED = \'DEPENDS\';\n
\n
/**\n
 * Split an extension pointer from module/path#objectName into an object of the\n
 * type { modName:"module/path", objName:"objectName" } using a pluginName\n
 * as the base to which roots the pointer\n
 */\n
var _splitPointer = function(pluginName, pointer) {\n
    if (!pointer) {\n
        return undefined;\n
    }\n
\n
    var parts = pointer.split("#");\n
    var modName;\n
\n
    // this allows syntax like #foo\n
    // which is equivalent to PluginName:index#foo\n
    if (parts[0]) {\n
        modName = pluginName + ":" + parts[0];\n
    } else {\n
        modName = pluginName;\n
    }\n
\n
    return {\n
        modName: modName,\n
        objName: parts[1]\n
    };\n
};\n
\n
var _retrieveObject = function(pointerObj) {\n
    var module = r(pointerObj.modName);\n
    if (pointerObj.objName) {\n
        return module[pointerObj.objName];\n
    }\n
    return module;\n
};\n
\n
/**\n
 * An Extension represents some code that can be lazy-loaded when needed.\n
 * @constructor\n
 */\n
exports.Extension = function(metadata) {\n
    this.pluginName = null;\n
\n
    for (property in metadata) {\n
        if (metadata.hasOwnProperty(property)) {\n
            this[property] = metadata[property];\n
        }\n
    }\n
\n
    this._observers = [];\n
};\n
\n
exports.Extension.prototype = {\n
    /**\n
     * Asynchronously load the actual code represented by this Extension\n
     * @param callback Function to call when the load has finished (deprecated)\n
     * @param property Extension property to load (default \'pointer\')\n
     * @returns A promise to be fulfilled on completion. Preferred over using the\n
     * <tt>callback</tt> parameter.\n
     */\n
    load: function(callback, property, catalog) {\n
        catalog = catalog || exports.catalog;\n
        var promise = new Promise();\n
\n
        var onComplete = function(func) {\n
            if (callback) {\n
                callback(func);\n
            }\n
            promise.resolve(func);\n
        };\n
\n
        var pointerVal = this[property || \'pointer\'];\n
        if (util.isFunction(pointerVal)) {\n
            onComplete(pointerVal);\n
            return promise;\n
        }\n
\n
        var pointerObj = _splitPointer(this.pluginName, pointerVal);\n
\n
        if (!pointerObj) {\n
            console.error(\'Extension cannot be loaded because it has no \\\'pointer\\\'\');\n
            console.log(this);\n
\n
            promise.reject(new Error(\'Extension has no \\\'pointer\\\' to call\'));\n
            return promise;\n
        }\n
\n
        var pluginName = this.pluginName;\n
        catalog.loadPlugin(pluginName).then(function() {\n
            require.ensure(pointerObj.modName, function() {\n
                var func = _retrieveObject(pointerObj);\n
                onComplete(func);\n
\n
                // TODO: consider caching \'func\' to save looking it up again\n
                // Something like: this._setPointer(property, data);\n
            });\n
        }, function(err) {\n
            console.error(\'Failed to load plugin \', pluginName, err);\n
        });\n
\n
        return promise;\n
    },\n
\n
    /**\n
     * Loads this extension and passes the result to the callback.\n
     * Any time this extension changes, the callback is called with the new value.\n
     * Note that if this extension goes away, the callback will be called with\n
     * undefined.\n
     * <p>observingPlugin is required, because if that plugin is torn down,\n
     * all of its observing callbacks need to be torn down as well.\n
     */\n
    observe: function(observingPlugin, callback, property) {\n
        this._observers.push({\n
            plugin: observingPlugin,\n
            callback: callback,\n
            property: property\n
        });\n
        this.load(callback, property);\n
    },\n
\n
    /**\n
     * Returns the name of the plugin that provides this extension.\n
     */\n
    getPluginName: function() {\n
        return this.pluginName;\n
    },\n
\n
    /**\n
     *\n
     */\n
    _getLoaded: function(property) {\n
        var pointerObj = this._getPointer(property);\n
        return _retrieveObject(pointerObj);\n
    }\n
};\n
\n
/**\n
 * An ExtensionPoint is a get of Extensions grouped under the same name\n
 * for fast access.\n
 * @constructor\n
 */\n
exports.ExtensionPoint = function(name, catalog) {\n
    this.name = name;\n
    this.catalog = catalog;\n
\n
    this.pluginName = undefined;\n
    this.indexOn = undefined;\n
\n
    this.extensions = [];\n
    this.handlers = [];\n
};\n
\n
/**\n
 * Implementation of ExtensionPoint\n
 */\n
exports.ExtensionPoint.prototype = {\n
    /**\n
    * Retrieves the list of plugins which provide extensions\n
    * for this extension point.\n
    */\n
    getImplementingPlugins: function() {\n
        var pluginSet = {};\n
        this.extensions.forEach(function(ext) {\n
            pluginSet[ext.pluginName] = true;\n
        });\n
        var matches = Object.keys(pluginSet);\n
        matches.sort();\n
        return matches;\n
    },\n
\n
    /**\n
     * Get the name of the plugin that defines this extension point.\n
     */\n
    getDefiningPluginName: function() {\n
        return this.pluginName;\n
    },\n
\n
    /**\n
     * If we are keeping an index (an indexOn property is set on the\n
     * extension point), you can look up an extension by key.\n
     */\n
    getByKey: function(key) {\n
        var indexOn = this.indexOn;\n
\n
        if (!indexOn) {\n
            return undefined;\n
        }\n
\n
        for (var i = 0; i < this.extensions.length; i++) {\n
            if (this.extensions[i][indexOn] == key) {\n
                return this.extensions[i];\n
            }\n
        }\n
        return undefined;\n
    },\n
\n
    register: function(extension) {\n
        var catalog = this.catalog;\n
        this.extensions.push(extension);\n
        this.handlers.forEach(function(handler) {\n
            if (handler.register) {\n
                handler.load(function(register) {\n
                    if (!register) {\n
                        console.error(\'missing register function for pluginName=\', extension.pluginName, ", extension=", extension.name);\n
                    } else {\n
                         register(extension, catalog);\n
                    }\n
                }, "register", catalog);\n
            }\n
        });\n
    },\n
\n
    unregister: function(extension) {\n
        var catalog = this.catalog;\n
        this.extensions.splice(this.extensions.indexOf(extension), 1);\n
        this.handlers.forEach(function(handler) {\n
            if (handler.unregister) {\n
                handler.load(function(unregister) {\n
                    if (!unregister) {\n
                        console.error(\'missing unregister function for pluginName=\', extension.pluginName, ", extension=", extension.name);\n
                    } else {\n
                         unregister(extension, catalog);\n
                    }\n
                }, "unregister", catalog);\n
            }\n
        });\n
    },\n
\n
    /**\n
     * Order the extensions by a plugin order.\n
     */\n
    orderExtensions: function(pluginOrder) {\n
        var orderedExt = [];\n
\n
        for (var i = 0; i < pluginOrder.length; i++) {\n
            var n = 0;\n
            while (n != this.extensions.length) {\n
                if (this.extensions[n].pluginName === pluginOrder[i]) {\n
                    orderedExt.push(this.extensions[n]);\n
                    this.extensions.splice(n, 1);\n
                } else {\n
                    n ++;\n
                }\n
            }\n
        }\n
\n
        this.extensions = orderedExt.concat(this.extensions);\n
    }\n
};\n
\n
/**\n
 * A Plugin is a set of Extensions that are loaded as a unit\n
 * @constructor\n
 */\n
exports.Plugin = function(metadata) {\n
    // Should be provided in the metadata\n
    this.catalog = null;\n
    this.name = null;\n
    this.provides = [];\n
    this.stylesheets = [];\n
    this.reloadURL = null;\n
    this.reloadPointer = null;\n
\n
    for (property in metadata) {\n
        if (metadata.hasOwnProperty(property)) {\n
            this[property] = metadata[property];\n
        }\n
    }\n
};\n
\n
/**\n
 * Implementation of Plugin\n
 */\n
exports.Plugin.prototype = {\n
    register: function() {\n
        this.provides.forEach(function(extension) {\n
            var ep = this.catalog.getExtensionPoint(extension.ep, true);\n
            ep.register(extension);\n
        }, this);\n
    },\n
\n
    unregister: function() {\n
        this.provides.forEach(function(extension) {\n
            var ep = this.catalog.getExtensionPoint(extension.ep, true);\n
            ep.unregister(extension);\n
        }, this);\n
    },\n
\n
    _getObservers: function() {\n
        var result = {};\n
        this.provides.forEach(function(extension) {\n
            console.log(\'ep: \', extension.ep);\n
            console.log(extension._observers);\n
            result[extension.ep] = extension._observers;\n
        });\n
        return result;\n
    },\n
\n
    /**\n
     * Figure out which plugins depend on a given plugin. This\n
     * will allow the reload behavior to unregister/reregister\n
     * all of the plugins that depend on the one being reloaded.\n
     * If firstLevelOnly is true, only direct dependent plugins are listed.\n
     */\n
    _findDependents: function(pluginList, dependents, firstLevelOnly) {\n
        var pluginName = this.name;\n
        var self = this;\n
        pluginList.forEach(function(testPluginName) {\n
            if (testPluginName == pluginName) {\n
                return;\n
            }\n
            var plugin = self.catalog.plugins[testPluginName];\n
            if (plugin && plugin.dependencies) {\n
                for (dependName in plugin.dependencies) {\n
                    if (dependName == pluginName && !dependents[testPluginName]) {\n
                        dependents[testPluginName] = {\n
                            keepModule: false\n
                        };\n
                        if (!firstLevelOnly) {\n
                            plugin._findDependents(pluginList, dependents);\n
                        }\n
                    }\n
                }\n
            }\n
        });\n
    },\n
\n
    /**\n
     * Removes the plugin from Tiki\'s registries.\n
     * As with the new multiple Bespins, this only clears the current sandbox.\n
     */\n
    _cleanup: function(leaveLoader) {\n
        // Remove the css files.\n
        this.stylesheets.forEach(function(stylesheet) {\n
            var links = document.getElementsByTagName(\'link\');\n
            for (var i = 0; i < links.length; i++) {\n
                if (links[i].href.indexOf(stylesheet.url) != -1) {\n
                    links[i].parentNode.removeChild(links[i]);\n
                    break;\n
                }\n
            }\n
        });\n
\n
        // Remove all traces of the plugin.\n
        var pluginName = this.name;\n
\n
        var nameMatch = new RegExp("^" + pluginName + \'$\');\n
        var moduleMatch = new RegExp(\'^::\' + pluginName + \':\');\n
        var packageMatch = new RegExp("^::" + pluginName + \'$\');\n
\n
        var sandbox = require.sandbox;\n
        var loader = require.loader;\n
        var source = browser;\n
\n
        if (!leaveLoader) {\n
            // Clear the loader.\n
            _removeFromObject(moduleMatch, loader.factories);\n
            _removeFromObject(packageMatch, loader.canonicalIds);\n
            _removeFromObject(packageMatch, loader.canonicalPackageIds);\n
            _removeFromObject(packageMatch, loader.packageSources);\n
            _removeFromObject(packageMatch, loader.packages);\n
\n
            // Clear the source.\n
            _removeFromObject(nameMatch, source.packageInfoByName);\n
            _removeFromObject(moduleMatch, source.factories);\n
            _removeFromObject(moduleMatch, source.scriptActions);\n
            _removeFromObject(moduleMatch, source.stylesheetActions);\n
            _removeFromObject(packageMatch, source.packages);\n
            _removeFromObject(packageMatch, source.ensureActions);\n
            _removeFromObject(packageMatch, source.packageInfoById);\n
        }\n
\n
        // Clear the sandbox.\n
        _removeFromObject(moduleMatch, sandbox.exports);\n
        _removeFromObject(moduleMatch, sandbox.modules);\n
        _removeFromObject(moduleMatch, sandbox.usedExports);\n
    },\n
\n
    /**\n
     * reloads the plugin and reinitializes all\n
     * dependent plugins\n
     */\n
    reload: function(callback) {\n
        // TODO: Broken. Needs to be updated to the latest Tiki.\n
\n
        // All reloadable plugins will have a reloadURL\n
        if (!this.reloadURL) {\n
            return;\n
        }\n
\n
        if (this.reloadPointer) {\n
            var pointer = _splitPointer(this.name, this.reloadPointer);\n
            func = _retrieveObject(pointer);\n
            if (func) {\n
                func();\n
            } else {\n
                console.error("Reload function could not be loaded. Aborting reload.");\n
                return;\n
            }\n
        }\n
\n
        // find all of the dependents recursively so that\n
        // they can all be unregistered\n
        var dependents = {};\n
\n
        var pluginList = Object.keys(this.catalog.plugins);\n
\n
        this._findDependents(pluginList, dependents);\n
\n
        var reloadDescription = {\n
            pluginName: this.name,\n
            dependents: dependents\n
        };\n
\n
        for (var dependName in dependents) {\n
            var plugin = this.catalog.plugins[dependName];\n
            if (plugin.preRefresh) {\n
                var parts = _splitPointer(dependName, plugin.preRefresh);\n
                func = _retrieveObject(parts);\n
                if (func) {\n
                    // the preRefresh call can return an object\n
                    // that includes attributes:\n
                    // keepModule (true to keep the module object)\n
                    // callPointer (pointer to call at the end of reloading)\n
                    dependents[dependName] = func(reloadDescription);\n
                }\n
            }\n
        }\n
\n
        // notify everyone that this plugin is going away\n
        this.unregister();\n
\n
        for (dependName in dependents) {\n
            this.catalog.plugins[dependName].unregister();\n
        }\n
\n
        this._cleanup(this.name);\n
\n
        // clear the sandbox of modules from all of the dependent plugins\n
        var fullModList = [];\n
        var sandbox = require.sandbox;\n
\n
        var modulesKey = Object.keys(sandbox.modules);\n
        var i = modulesKey.length;\n
        var dependRegexes = [];\n
        for (dependName in dependents) {\n
            // check to see if the module stated that it shouldn\'t be\n
            // refreshed\n
            if (!dependents[dependName].keepModule) {\n
                dependRegexes.push(new RegExp("^::" + dependName + ":"));\n
            }\n
        }\n
\n
        var nameMatch = new RegExp("^::" + this.name + ":");\n
\n
        while (--i >= 0) {\n
            var item = modulesKey[i];\n
            if (nameMatch.exec(item)) {\n
                fullModList.push(item);\n
            } else {\n
                var j = dependRegexes.length;\n
                while (--j >= 0) {\n
                    if (dependRegexes[j].exec(item)) {\n
                        fullModList.push(item);\n
                        break;\n
                    }\n
                }\n
            }\n
        }\n
\n
        // Remove the modules of the dependent plugins from the sandbox.\n
        fullModList.forEach(function(item) {\n
            delete sandbox.exports[item];\n
            delete sandbox.modules[item];\n
            delete sandbox.usedExports[item];\n
        });\n
\n
        // reload the plugin metadata\n
        var onLoad = function() {\n
            // actually load the plugin, so that it\'s ready\n
            // for any dependent plugins\n
            this.catalog.loadPlugin(this.name).then(function() {\n
                // re-register all of the dependent plugins\n
                for (dependName in dependents) {\n
                    this.catalog.plugins[dependName].register();\n
                }\n
\n
                for (dependName in dependents) {\n
                    if (dependents[dependName].callPointer) {\n
                        var parts = _splitPointer(dependName,\n
                            dependents[dependName].callPointer);\n
                        var func = _retrieveObject(parts);\n
                        if (func) {\n
                            func(reloadDescription);\n
                        }\n
                    }\n
                }\n
\n
                if (callback) {\n
                    // at long last, reloading is done.\n
                    callback();\n
                }\n
            }.bind(this));\n
        }.bind(this);\n
\n
        // TODO: There should be more error handling then just logging\n
        // to the command line.\n
        var onError = function() {\n
            console.error(\'Failed to load metadata from \' + this.reloadURL);\n
        }.bind(this);\n
\n
        this.catalog.loadMetadataFromURL(this.reloadURL).then(onLoad, onError);\n
    }\n
};\n
\n
var _setPath = function(root, path, value) {\n
    var segments = path.split(\'.\');\n
    var current = root;\n
    var top = segments.length - 1;\n
    if (top > 0) {\n
        for (var i = 0; i < top; i++) {\n
            current = current[segments[i]];\n
        }\n
    }\n
    current[top] = value;\n
};\n
\n
exports.Catalog = function() {\n
    this.points = {};\n
    this.plugins = {};\n
    this.metadata = {};\n
\n
    this.USER_DEACTIVATED = USER_DEACTIVATED;\n
    this.DEPENDS_DEACTIVATED = DEPENDS_DEACTIVATED;\n
\n
    // Stores the deactivated plugins. Plugins deactivated by the user have the\n
    // value USER_DEACTIVATED. If a plugin is deactivated because a required\n
    // plugin is deactivated, then the value is a DEPENDS_DEACTIVATED.\n
    this.deactivatedPlugins = {};\n
    this._extensionsOrdering = [];\n
    this.instances = {};\n
    this.instancesLoadPromises = {};\n
    this._objectDescriptors = {};\n
\n
    // Stores the child catalogs.\n
    this.children = [];\n
\n
    // set up the "extensionpoint" extension point.\n
    // it indexes on name.\n
    var ep = this.getExtensionPoint("extensionpoint", true);\n
    ep.indexOn = "name";\n
    this.registerMetadata(builtins.metadata);\n
};\n
\n
exports.Catalog.prototype = {\n
\n
    /**\n
     * Returns true if the extension is shared.\n
     */\n
    shareExtension: function(ext) {\n
        return this.plugins[ext.pluginName].share;\n
    },\n
\n
    /**\n
     * Returns true, if the plugin is loaded (checks if there is a module in the\n
     * current sandbox).\n
     */\n
    isPluginLoaded: function(pluginName) {\n
        var usedExports = Object.keys(require.sandbox.usedExports);\n
\n
        return usedExports.some(function(item) {\n
            return item.indexOf(\'::\' + pluginName + \':\') == 0;\n
        });\n
    },\n
\n
    /**\n
     * Registers information about an instance that will be tracked\n
     * by the catalog. The first parameter is the name used for looking up\n
     * the object. The descriptor should contain:\n
     * - factory (optional): name of the factory extension used to create the\n
     *                       object. defaults to the same value as the name\n
     *                       property.\n
     * - arguments (optional): array that is passed in if the factory is a\n
     *                      function.\n
     * - objects (optional): object that describes other objects that are\n
     *                      required when constructing this one (see below)\n
     *\n
     * The objects object defines objects that must be created before this\n
     * one and how they should be passed in. The key defines how they\n
     * are passed in, and the value is the name of the object to pass in.\n
     * You define how they are passed in relative to the arguments\n
     * array, using a very simple interface of dot separated keys.\n
     * For example, if you have an arguments array of [null, {foo: null}, "bar"]\n
     * you can have an object array like this:\n
     * {\n
     *  "0": "myCoolObject",\n
     *  "1.foo": "someOtherObject"\n
     * }\n
     *\n
     * which will result in arguments like this:\n
     * [myCoolObject, {foo: someOtherObject}, "bar"]\n
     * where myCoolObject and someOtherObject are the actual objects\n
     * created elsewhere.\n
     *\n
     * If the plugin containing the factory is reloaded, the object will\n
     * be recreated. The object will also be recreated if objects passed in\n
     * are reloaded.\n
     *\n
     * This method returns nothing and does not actually create the objects.\n
     * The objects are created via the createObject method and retrieved\n
     * via the getObject method.\n
     */\n
    registerObject: function(name, descriptor) {\n
        this._objectDescriptors[name] = descriptor;\n
    },\n
\n
    /**\n
     * Stores an object directly in the instance cache. This should\n
     * not generally be used because reloading cannot work with\n
     * these objects.\n
     */\n
    _setObject: function(name, obj) {\n
        this.instances[name] = obj;\n
    },\n
\n
    /**\n
     * Creates an object with a previously registered descriptor.\n
     *\n
     * Returns a promise that will be resolved (with the created object)\n
     * once the object has been made. The promise will be resolved\n
     * immediately if the instance is already there.\n
     *\n
     * throws an exception if the object is not registered or if\n
     * the factory cannot be found.\n
     */\n
    createObject: function(name) {\n
        // console.log("Creating", name);\n
\n
        // If there is already a loading promise for this instance, then\n
        // return this one.\n
        if (this.instancesLoadPromises[name] !== undefined) {\n
            // console.log("Already have one (it\'s very nice)");\n
            return this.instancesLoadPromises[name];\n
        }\n
\n
        var descriptor = this._objectDescriptors[name];\n
        if (descriptor === undefined) {\n
            throw new Error(\'Tried to create object "\' + name +\n
                \'" but that object is not registered.\');\n
        }\n
\n
        var factoryName = descriptor.factory || name;\n
        var ext = this.getExtensionByKey("factory", factoryName);\n
        if (ext === undefined) {\n
            throw new Error(\'When creating object "\' + name +\n
                \'", there is no factory called "\' + factoryName +\n
                \'" available."\');\n
        }\n
\n
        // If this is a child catalog and the extension is shared, then\n
        // as the master/parent catalog to create the object.\n
        if (this.parent && this.shareExtension(ext)) {\n
            return this.instancesLoadPromises[name] = this.parent.createObject(name);\n
        }\n
\n
        // Otherwise create a new loading promise (which is returned at the\n
        // end of the function) and create the instance.\n
        var pr = this.instancesLoadPromises[name] = new Promise();\n
\n
        var factoryArguments = descriptor.arguments || [];\n
        var argumentPromises = [];\n
        if (descriptor.objects) {\n
            var objects = descriptor.objects;\n
            for (var key in objects) {\n
                var objectName = objects[key];\n
                var ropr = this.createObject(objectName);\n
                argumentPromises.push(ropr);\n
                // key is changing, so we need to hang onto the\n
                // current value\n
                ropr.location = key;\n
                ropr.then(function(obj) {\n
                    _setPath(factoryArguments, ropr.location, obj);\n
                });\n
            }\n
        }\n
\n
        group(argumentPromises).then(function() {\n
            ext.load().then(function(factory) {\n
                // console.log("Got factory for ", name);\n
                var action = ext.action;\n
                var obj;\n
\n
                if (action === "call") {\n
                    obj = factory.apply(factory, factoryArguments);\n
                } else if (action === "new") {\n
                    if (factoryArguments.length > 1) {\n
                        pr.reject(new Error(\'For object \' + name + \', create a simple factory function and change the action to call because JS cannot handle this case.\'));\n
                        return;\n
                    }\n
                    obj = new factory(factoryArguments[0]);\n
                } else if (action === "value") {\n
                    obj = factory;\n
                } else {\n
                    pr.reject(new Error("Create action must be call|new|value. " +\n
                            "Found" + action));\n
                    return;\n
                }\n
\n
                this.instances[name] = obj;\n
                pr.resolve(obj);\n
            }.bind(this));\n
        }.bind(this));\n
\n
        return pr;\n
    },\n
\n
    /**\n
     * Retrieve a registered object. Returns undefined\n
     * if the instance has not been created.\n
     */\n
    getObject: function(name) {\n
        return this.instances[name] || (this.parent ? this.parent.getObject(name) : undefined);\n
    },\n
\n
    /** Retrieve an extension point object by name, optionally creating it if it\n
    * does not exist.\n
    */\n
    getExtensionPoint: function(name, create) {\n
        if (create && this.points[name] === undefined) {\n
            this.points[name] = new exports.ExtensionPoint(name, this);\n
        }\n
        return this.points[name];\n
    },\n
\n
    /**\n
     * Retrieve the list of extensions for the named extension point.\n
     * If none are defined, this will return an empty array.\n
     */\n
    getExtensions: function(name) {\n
        var ep = this.getExtensionPoint(name);\n
        if (ep === undefined) {\n
            return [];\n
        }\n
        return ep.extensions;\n
    },\n
\n
    /**\n
     * Sets the order of the plugin\'s extensions. Note that this orders *only*\n
     * Extensions and nothing else (load order of CSS files e.g.)\n
     */\n
    orderExtensions: function(pluginOrder) {\n
        pluginOrder = pluginOrder || this._extensionsOrdering;\n
\n
        for (name in this.points) {\n
            this.points[name].orderExtensions(pluginOrder);\n
        }\n
        this._extensionsOrdering = pluginOrder;\n
    },\n
\n
    /**\n
     * Returns the current plugin exentions ordering.\n
     */\n
    getExtensionsOrdering: function() {\n
        return this._extensionsOrdering;\n
    },\n
\n
    /**\n
     * Look up an extension in an indexed extension point by the given key. If\n
     * the extension point or the key are unknown, undefined will be returned.\n
     */\n
    getExtensionByKey: function(name, key) {\n
        var ep = this.getExtensionPoint(name);\n
        if (ep === undefined) {\n
            return undefined;\n
        }\n
\n
        return ep.getByKey(key);\n
    },\n
\n
    // Topological sort algorithm from Wikipedia, credited to Tarjan 1976.\n
    //     http://en.wikipedia.org/wiki/Topological_sort\n
    _toposort: function(metadata) {\n
        var sorted = [];\n
        var visited = {};\n
        var visit = function(key) {\n
            if (key in visited || !(key in metadata)) {\n
                return;\n
            }\n
\n
            visited[key] = true;\n
            var depends = metadata[key].dependencies;\n
            if (!util.none(depends)) {\n
                for (var dependName in depends) {\n
                    visit(dependName);\n
                }\n
            }\n
\n
            sorted.push(key);\n
        };\n
\n
        for (var key in metadata) {\n
            visit(key);\n
        }\n
\n
        return sorted;\n
    },\n
\n
    /**\n
     * Register new metadata. If the current catalog is not the master catalog,\n
     * then the master catalog registerMetadata function is called. The master\n
     * catalog then makes some basic operations on the metadata and calls the\n
     * _registerMetadata function on all the child catalogs and for itself as\n
     * well.\n
     */\n
    registerMetadata: function(metadata) {\n
        // If we are the master catalog, then store the metadata.\n
        if (this.parent) {\n
            this.parent.registerMetadata(metadata);\n
        } else {\n
            for (var pluginName in metadata) {\n
                var md = metadata[pluginName];\n
                if (md.errors) {\n
                    console.error("Plugin ", pluginName, " has errors:");\n
                    md.errors.forEach(function(error) {\n
                        console.error(error);\n
                    });\n
                    delete metadata[pluginName];\n
                    continue;\n
                }\n
\n
                if (md.dependencies) {\n
                    md.depends = Object.keys(md.dependencies);\n
                }\n
\n
                md.name = pluginName;\n
                md.version = null;\n
\n
                var packageId = browser.canonicalPackageId(pluginName);\n
                if (packageId === null) {\n
                    browser.register(\'::\' + pluginName, md);\n
                    continue;\n
                }\n
            }\n
\n
            // Save the new metadata.\n
            util.mixin(this.metadata, util.clone(metadata, true));\n
\n
            // Tell every child about the new metadata.\n
            this.children.forEach(function(child) {\n
                child._registerMetadata(util.clone(metadata, true));\n
            });\n
            // Register the metadata in the master catalog as well.\n
            this._registerMetadata(util.clone(metadata, true));\n
        }\n
    },\n
\n
    /**\n
     * Registers plugin metadata. See comments inside of the function.\n
     */\n
    _registerMetadata: function(metadata) {\n
        var pluginName, plugin;\n
        var plugins = this.plugins;\n
\n
        this._toposort(metadata).forEach(function(name) {\n
            // If the plugin is already registered.\n
            if (this.plugins[name]) {\n
                // Check if the plugin is loaded.\n
                if (this.isPluginLoaded(name)) {\n
                    // If the plugin is loaded, then the metadata/plugin/extensions\n
                    // have to stay the way they are at the moment.\n
                    return;\n
                } else {\n
                    // If the plugin is not loaded and the plugin is already\n
                    // registerd, then remove the plugin.\n
                    //\n
                    // Reason: As new metadata arrives, this might also mean,\n
                    // that the factory in the tiki.loader has changed. If the\n
                    // old plugins/extensions would stay, they might not fit to\n
                    // the new factory. As such, the plugin has to be updated,\n
                    // which is achieved by unregister the plugin and then add it\n
                    // later in this function again.\n
                    var plugin = this.plugins[name];\n
                    plugin.unregister();\n
                }\n
            }\n
\n
            var md = metadata[name];\n
            var activated = !(this.deactivatedPlugins[name]);\n
\n
            // Check if all plugins this one depends on are activated as well.\n
            if (activated && md.depends && md.depends.length != 0) {\n
                var works = md.depends.some(function(name) {\n
                    return !(this.deactivatedPlugins[name]);\n
                }, this);\n
                // At least one depending plugin is not activated -> this plugin\n
                // can\'t be activated. Mark this plugin as deactivated.\n
                if (!works) {\n
                    this.deactivatedPlugins[name] = DEPENDS_DEACTIVATED;\n
                    activated = false;\n
                }\n
            }\n
\n
            md.catalog = this;\n
            md.name = name;\n
            plugin = new exports.Plugin(md);\n
            plugins[name] = plugin;\n
\n
            // Skip if the plugin is not activated.\n
            if (md.provides) {\n
                var provides = md.provides;\n
                for (var i = 0; i < provides.length; i++) {\n
                    var extension = new exports.Extension(provides[i]);\n
                    extension.pluginName = name;\n
                    provides[i] = extension;\n
\n
                    var epname = extension.ep;\n
                    // This special treatment is required for the extension point\n
                    // definition. TODO: Refactor the code so that this is no\n
                    // longer necessary.\n
                    if (epname == "extensionpoint" && extension.name == \'extensionpoint\') {\n
                        exports.registerExtensionPoint(extension, this, false);\n
                    } else {\n
                        // Only register the extension if the plugin is activated.\n
                        // TODO: This should handle extension points and\n
                        if (activated) {\n
                            var ep = this.getExtensionPoint(extension.ep, true);\n
                            ep.register(extension);\n
\n
                        // Even if the plugin is deactivated, the ep need to\n
                        // be registered. Call the registerExtensionPoint\n
                        // function manually, but pass as third argument \'true\'\n
                        // which indicates, that the plugin is deactivated and\n
                        // prevents the handlers on the ep to get registered.\n
                        } else if (epname == "extensionpoint") {\n
                            exports.registerExtensionPoint(extension, this, true);\n
                        }\n
                    }\n
                }\n
            } else {\n
                md.provides = [];\n
            }\n
        }, this);\n
\n
        for (pluginName in metadata) {\n
            this._checkLoops(pluginName, plugins, []);\n
        }\n
\n
        this.orderExtensions();\n
    },\n
\n
    /**\n
     * Loads the named plugin, returning a promise called\n
     * when the plugin is loaded. This function is a convenience\n
     * for unusual situations and debugging only. Generally,\n
     * you should load plugins by calling load() on an Extension\n
     * object.\n
     */\n
    loadPlugin: function(pluginName) {\n
        var pr = new Promise();\n
        var plugin = this.plugins[pluginName];\n
        if (plugin.objects) {\n
            var objectPromises = [];\n
            plugin.objects.forEach(function(objectName) {\n
                objectPromises.push(this.createObject(objectName));\n
            }.bind(this));\n
            group(objectPromises).then(function() {\n
                require.ensurePackage(pluginName, function() {\n
                    pr.resolve();\n
                });\n
            });\n
        } else {\n
            require.ensurePackage(pluginName, function(err) {\n
                if (err) {\n
                    pr.reject(err);\n
                } else {\n
                    pr.resolve();\n
                }\n
            });\n
        }\n
        return pr;\n
    },\n
\n
    /**\n
     * Retrieve metadata from the server. Returns a promise that is\n
     * resolved when the metadata has been loaded.\n
     */\n
    loadMetadataFromURL: function(url, type) {\n
        var pr = new Promise();\n
        proxy.xhr(\'GET\', url, true).then(function(response) {\n
            this.registerMetadata(JSON.parse(response));\n
            pr.resolve();\n
        }.bind(this), function(err) {\n
            pr.reject(err);\n
        });\n
\n
        return pr;\n
    },\n
\n
    /**\n
     * Dactivates a plugin. If no plugin was deactivated, then a string is\n
     * returned which contains the reason why deactivating was not possible.\n
     * Otherwise the plugin is deactivated as well as all plugins that depend on\n
     * this plugin and a array is returned holding all depending plugins that were\n
     * deactivated.\n
     *\n
     * @param pluginName string Name of the plugin to deactivate\n
     * @param recursion boolean True if the funciton is called recursive.\n
     */\n
    deactivatePlugin: function(pluginName, recursion) {\n
        var plugin = this.plugins[pluginName];\n
        if (!plugin) {\n
            // Deactivate the plugin only if the user called the function.\n
            if (!recursion) {\n
                this.deactivatedPlugins[pluginName] = USER_DEACTIVATED;\n
            }\n
            return \'There is no plugin named "\' + pluginName + \'" in this catalog.\';\n
        }\n
\n
        if (this.deactivatedPlugins[pluginName]) {\n
            // If the plugin is already deactivated but the user explicip wants\n
            // to deactivate the plugin, then store true as deactivation reason.\n
            if (!recursion) {\n
                this.deactivatedPlugins[pluginName] = USER_DEACTIVATED;\n
            }\n
            return \'The plugin "\' + pluginName + \'" is already deactivated\';\n
        }\n
\n
        // If the function is called within a recursion, then mark the plugin\n
        // as DEPENDS_DEACTIVATED otherwise as USER_DEACTIVATED.\n
        this.deactivatedPlugins[pluginName] = (recursion ? DEPENDS_DEACTIVATED\n
                                                          : USER_DEACTIVATED);\n
\n
        // Get all plugins that depend on this plugin.\n
        var dependents = {};\n
        var deactivated = [];\n
        plugin._findDependents(Object.keys(this.plugins), dependents, true);\n
\n
        // Deactivate all dependent plugins.\n
        Object.keys(dependents).forEach(function(plugin) {\n
            var ret = this.deactivatePlugin(plugin, true);\n
            if (Array.isArray(ret)) {\n
                deactivated = deactivated.concat(ret);\n
            }\n
        }, this);\n
\n
        // Deactivate this plugin.\n
        plugin.unregister();\n
\n
        if (recursion) {\n
            deactivated.push(pluginName);\n
        }\n
\n
        return deactivated;\n
    },\n
\n
    /**\n
     * Activates a plugin. If the plugin can\'t be activated a string is returned\n
     * explaining why. Otherwise the plugin is activated, all plugins that depend\n
     * on this plugin are tried to activated and an array with all the activated\n
     * depending plugins is returned.\n
     * Note: Depending plugins are not activated if they user called\n
     * deactivatePlugin on them to deactivate them explicit.\n
     *\n
     * @param pluginName string Name of the plugin to activate.\n
     * @param recursion boolean True if the funciton is called recursive.\n
     */\n
    activatePlugin: function(pluginName, recursion) {\n
        var plugin = this.plugins[pluginName];\n
        if (!plugin) {\n
            return \'There is no plugin named "\' + pluginName + \'" in this catalog.\';\n
        }\n
\n
        if (!this.deactivatedPlugins[pluginName]) {\n
            return \'The plugin "\' + pluginName + \'" is already activated\';\n
        }\n
\n
        // Don\'t activate this plugin if the user explicip deactivated this one\n
        // and the plugin activation call is called beacuse another plugin\n
        // this one depended on was activated.\n
        if (recursion && this.deactivatedPlugins[pluginName] === USER_DEACTIVATED) {\n
            return;\n
        }\n
\n
        // Check if all dependent plugins are activated.\n
        if (plugin.depends && plugin.depends.length != 0) {\n
            var works = plugin.depends.some(function(plugin) {\n
                return !this.deactivatedPlugins[plugin];\n
            }, this);\n
\n
            if (!works) {\n
                // The user activated the plugin but some of the dependent\n
                // plugins are still deactivated. Change the deactivation reason\n
                // to DEPENDS_DEACTIVATED.\n
                this.deactivatedPlugins[pluginName] = DEPENDS_DEACTIVATED;\n
                return \'Can not activate plugin "\' + pluginName +\n
                        \'" as some of its dependent plugins are not activated\';\n
            }\n
        }\n
\n
        // Activate this plugin.\n
        plugin.register();\n
        this.orderExtensions();\n
        delete this.deactivatedPlugins[pluginName];\n
\n
        // Try to activate all the plugins that depend on this one.\n
        var activated = [];\n
        var dependents = {};\n
        plugin._findDependents(Object.keys(this.plugins), dependents, true);\n
        Object.keys(dependents).forEach(function(pluginName) {\n
            var ret = this.activatePlugin(pluginName, true);\n
            if (Array.isArray(ret)) {\n
                activated = activated.concat(ret);\n
            }\n
        }, this);\n
\n
        if (recursion) {\n
            activated.push(pluginName);\n
        }\n
\n
        return activated;\n
    },\n
\n
    /**\n
     * Removes a plugin, unregistering it and cleaning up.\n
     */\n
    removePlugin: function(pluginName) {\n
        var plugin = this.plugins[pluginName];\n
        if (plugin == undefined) {\n
            throw new Error("Attempted to remove plugin " + pluginName\n
                                            + " which does not exist.");\n
        }\n
\n
        plugin.unregister();\n
        plugin._cleanup(true /* leaveLoader */);\n
        delete this.metadata[pluginName];\n
        delete this.plugins[pluginName];\n
    },\n
\n
    /**\n
     * for the given plugin, get the first part of the URL required to\n
     * get at that plugin\'s resources (images, etc.).\n
     */\n
    getResourceURL: function(pluginName) {\n
        var link = document.getElementById("bespin_base");\n
        var base = "";\n
        if (link) {\n
            base += link.href;\n
            if (!util.endsWith(base, "/")) {\n
                base += "/";\n
            }\n
        }\n
        var plugin = this.plugins[pluginName];\n
        if (plugin == undefined) {\n
            return undefined;\n
        }\n
        return base + plugin.resourceURL;\n
    },\n
\n
    /**\n
     * Check the dependency graph to ensure we don\'t have cycles.\n
     */\n
    _checkLoops: function(pluginName, data, trail) {\n
        var circular = false;\n
        trail.forEach(function(node) {\n
            if (pluginName === node) {\n
                console.error("Circular dependency", pluginName, trail);\n
                circular = true;\n
            }\n
        });\n
        if (circular) {\n
            return true;\n
        }\n
        trail.push(pluginName);\n
        if (!data[pluginName]) {\n
            console.error("Missing metadata for ", pluginName);\n
        } else {\n
            if (data[pluginName].dependencies) {\n
                for (var dependency in data[pluginName].dependencies) {\n
                    var trailClone = trail.slice();\n
                    var errors = this._checkLoops(dependency, data, trailClone);\n
                    if (errors) {\n
                        console.error("Errors found when looking at ", pluginName);\n
                        return true;\n
                    }\n
                }\n
            }\n
        }\n
        return false;\n
    },\n
\n
    /**\n
     * Retrieve an array of the plugin objects.\n
     * The opts object can include the following options:\n
     * onlyType (string): only include plugins of this type\n
     * sortBy (array): list of keys to sort by (the primary sort is first).\n
     *                 default is sorted alphabetically by name.\n
     */\n
    getPlugins: function(opts) {\n
        var result = [];\n
        var onlyType = opts.onlyType;\n
\n
        for (var key in this.plugins) {\n
            var plugin = this.plugins[key];\n
\n
            // apply the filter\n
            if ((onlyType && plugin.type && plugin.type != onlyType)\n
                || plugin.name == "bespin") {\n
                continue;\n
            }\n
\n
            result.push(plugin);\n
        }\n
\n
        var sortBy = opts.sortBy;\n
        if (!sortBy) {\n
            sortBy = ["name"];\n
        }\n
\n
        var sortfunc = function(a, b) {\n
            for (var i = 0; i < sortBy.length; i++) {\n
                key = sortBy[i];\n
                if (a[key] < b[key]) {\n
                    return -1;\n
                } else if (b[key] < a[key]) {\n
                    return 1;\n
                }\n
            }\n
            return 0;\n
        };\n
\n
        result.sort(sortfunc);\n
        return result;\n
    },\n
\n
    /**\n
     * Returns a promise to retrieve the object at the given property path,\n
     * loading the plugin if necessary.\n
     */\n
    loadObjectForPropertyPath: function(path, context) {\n
        var promise = new Promise();\n
        var parts = /^([^:]+):([^#]+)#(.*)$/.exec(path);\n
        if (parts === null) {\n
            throw new Error("loadObjectForPropertyPath: malformed path: \'" +\n
                path + "\'");\n
        }\n
\n
        var pluginName = parts[1];\n
        if (pluginName === "") {\n
            if (util.none(context)) {\n
                throw new Error("loadObjectForPropertyPath: no plugin name " +\n
                    "supplied and no context is present");\n
            }\n
\n
            pluginName = context;\n
        }\n
\n
        require.ensurePackage(pluginName, function() {\n
            promise.resolve(this.objectForPropertyPath(path));\n
        }.bind(this));\n
\n
        return promise;\n
    },\n
\n
    /**\n
     * Finds the object for the passed path or array of path components.  This is\n
     * the standard method used in SproutCore to traverse object paths.\n
     * @param path {String} the path\n
     * @param root {Object} optional root object.  window is used otherwise\n
     * @param stopAt {Integer} optional point to stop searching the path.\n
     * @returns {Object} the found object or undefined.\n
     */\n
    objectForPropertyPath: function(path, root, stopAt) {\n
        stopAt = (stopAt == undefined) ? path.length : stopAt;\n
        if (!root) {\n
            root = window;\n
        }\n
\n
        var hashed = path.split("#");\n
        if (hashed.length !== 1) {\n
            var module = require(hashed[0]);\n
            if (module === undefined) {\n
                return undefined;\n
            }\n
\n
            path = hashed[1];\n
            root = module;\n
            stopAt = stopAt - hashed[0].length;\n
        }\n
\n
        var loc = 0;\n
        while (root && loc < stopAt) {\n
            var nextDotAt = path.indexOf(\'.\', loc);\n
            if (nextDotAt < 0 || nextDotAt > stopAt) {\n
                nextDotAt = stopAt;\n
            }\n
            var key = path.slice(loc, nextDotAt);\n
            root = root[key];\n
            loc = nextDotAt + 1;\n
        }\n
\n
        if (loc < stopAt) {\n
            root = undefined; // hit a dead end. :(\n
        }\n
\n
        return root;\n
    },\n
\n
    /**\n
     * Publish <tt>value</tt> to all plugins that match both <tt>ep</tt> and\n
     * <tt>key</tt>.\n
     * @param source {object} The source calling the publish function.\n
     * @param epName {string} An extension point (indexed by the catalog) to which\n
     * we publish the information.\n
     * @param key {string} A key to which we publish (linearly searched, allowing\n
     * for regex matching).\n
     * @param value {object} The data to be passed to the subscribing function.\n
     */\n
    publish: function(source, epName, key, value) {\n
        var ep = this.getExtensionPoint(epName);\n
\n
        if (this.shareExtension(ep)) {\n
            if (this.parent) {\n
                this.parent.publish(source, epName, key, value);\n
            } else {\n
                this.children.forEach(function(child) {\n
                    child._publish(source, epName, key, value);\n
                });\n
                this._publish(source, epName, key, value);\n
            }\n
        } else {\n
            this._publish(source, epName, key, value);\n
        }\n
    },\n
\n
    _publish: function(source, epName, key, value) {\n
        var subscriptions = this.getExtensions(epName);\n
        subscriptions.forEach(function(sub) {\n
            // compile regexes only once\n
            if (sub.match && !sub.regexp) {\n
                sub.regexp = new RegExp(sub.match);\n
            }\n
            if (sub.regexp && sub.regexp.test(key)\n
                    || sub.key === key\n
                    || (util.none(sub.key) && util.none(key))) {\n
                sub.load().then(function(handler) {\n
                    handler(source, key, value);\n
                });\n
            }\n
        });\n
    },\n
\n
    /**\n
     * The subscribe side of #publish for use when the object which will\n
     * publishes is created dynamically.\n
     * @param ep The extension point name to subscribe to\n
     * @param metadata An object containing:\n
     * <ul>\n
     * <li>pointer: A function which should be called on matching publish().\n
     * This can also be specified as a pointer string, however if you can do\n
     * that, you should be placing the metadata in package.json.\n
     * <li>key: A string that exactly matches the key passed to the publish()\n
     * function. For smarter matching, you can use \'match\' instead...\n
     * <li>match: A regexp to be used in place of key\n
     * </ul>\n
     */\n
    registerExtension: function(ep, metadata) {\n
        var extension = new exports.Extension(metadata);\n
        extension.pluginName = \'__dynamic\';\n
        this.getExtensionPoint(ep).register(extension);\n
    }\n
};\n
\n
/**\n
 * Register handler for extension points.\n
 * The argument `deactivated` is set to true or false when this method is called\n
 * by the _registerMetadata function.\n
 */\n
exports.registerExtensionPoint = function(extension, catalog, deactivated) {\n
    var ep = catalog.getExtensionPoint(extension.name, true);\n
    ep.description = extension.description;\n
    ep.pluginName = extension.pluginName;\n
    ep.params = extension.params;\n
    if (extension.indexOn) {\n
        ep.indexOn = extension.indexOn;\n
    }\n
\n
    if (!deactivated && (extension.register || extension.unregister)) {\n
        exports.registerExtensionHandler(extension, catalog);\n
    }\n
};\n
\n
/**\n
 * Register handler for extension handler.\n
 */\n
exports.registerExtensionHandler = function(extension, catalog) {\n
    // Don\'t add the extension handler if there is a master/partent catalog\n
    // and this plugin is shared. The extension handlers are only added\n
    // inside of the master catalog.\n
    if (catalog.parent && catalog.shareExtension(extension)) {\n
        return;\n
    }\n
\n
    var ep = catalog.getExtensionPoint(extension.name, true);\n
    ep.handlers.push(extension);\n
    if (extension.register) {\n
        // Store the current extensions to this extension point. We can\'t\n
        // use the ep.extensions array within the load-callback-function, as\n
        // the array at that point in time also contains extensions that got\n
        // registered by calling the handler.register function directly.\n
        // As such, using the ep.extensions in the load-callback-function\n
        // would result in calling the handler\'s register function on a few\n
        // extensions twice.\n
        var extensions = util.clone(ep.extensions);\n
\n
        extension.load(function(register) {\n
            if (!register) {\n
                throw extension.name + " is not ready";\n
            }\n
            extensions.forEach(function(ext) {\n
                // console.log(\'call register on:\', ext)\n
                register(ext, catalog);\n
            });\n
        }, "register", catalog);\n
    }\n
};\n
\n
/**\n
 * Unregister handler for extension point.\n
 */\n
exports.unregisterExtensionPoint = function(extension, catalog) {\n
    // Note: When an extensionPoint is unregistered, the extension point itself\n
    // stays but the handler goes away.\n
    // DISCUSS: Is this alright? The other option is to remove the ep completly.\n
    // The downside of this is, that when the ep arrives later again, it has\n
    // to look for extension handlers bound to this ep and add them all again.\n
    if (extension.register || extension.unregister) {\n
        exports.unregisterExtensionHandler(extension);\n
    }\n
};\n
\n
/**\n
 * Unregister handler for extension handler.\n
 */\n
exports.unregisterExtensionHandler = function(extension, catalog) {\n
    // Don\'t remove the extension handler if there is a master/partent catalog\n
    // and this plugin is shared. The extension handlers are only added\n
    // inside of the master catalog.\n
    if (catalog.parent && catalog.shareExtension(extension)) {\n
        return;\n
    }\n
\n
    var ep = catalog.getExtensionPoint(extension.name, true);\n
    if (ep.handlers.indexOf(extension) == -1) {\n
        return;\n
    }\n
    ep.handlers.splice(ep.handlers.indexOf(extension), 1);\n
    if (extension.unregister) {\n
        // Store the current extensions to this extension point. We can\'t\n
        // use the ep.extensions array within the load-callback-function, as\n
        // the array at that point in time also contains extensions that got\n
        // registered by calling the handler.register function directly.\n
        // As such, using the ep.extensions in the load-callback-function\n
        // would result in calling the handler\'s register function on a few\n
        // extensions twice.\n
        var extensions = util.clone(ep.extensions);\n
\n
        extension.load(function(unregister) {\n
            if (!unregister) {\n
                throw extension.name + " is not ready";\n
            }\n
            extensions.forEach(function(ext) {\n
                // console.log(\'call register on:\', ext)\n
                unregister(ext);\n
            });\n
        }, "unregister");\n
    }\n
};\n
\n
exports.catalog = new exports.Catalog();\n
\n
var _removeFromList = function(regex, array, matchFunc) {\n
    var i = 0;\n
    while (i < array.length) {\n
        if (regex.exec(array[i])) {\n
            var item = array.splice(i, 1);\n
            if (matchFunc) {\n
                matchFunc(item);\n
            }\n
            continue;\n
        }\n
        i++;\n
    }\n
};\n
\n
var _removeFromObject = function(regex, obj) {\n
    var keys = Object.keys(obj);\n
    var i = keys.length;\n
    while (--i > 0) {\n
        if (regex.exec(keys[i])) {\n
            delete obj[keys[i]];\n
        }\n
    }\n
};\n
\n
exports.getUserPlugins = function() {\n
    return exports.catalog.getPlugins({ onlyType: \'user\' });\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:sandbox",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var tiki = require(\'tiki\');\n
var util = require(\'bespin:util/util\');\n
var catalog = require(\'bespin:plugins\').catalog;\n
\n
/**\n
 * A sandbox can only be used from inside of the `master` catalog.\n
 */\n
if (catalog.parent) {\n
    throw new Error(\'The sandbox module can\\\'t be used inside of a slave catalog!\');\n
}\n
\n
/**\n
 * A special Bespin subclass of the tiki sandbox class. When the sandbox is\n
 * created, the catalog for the new sandbox is setup based on the catalog\n
 * data that is already in the so called `master` catalog.\n
 */\n
var Sandbox = function() {\n
    // Call the default constructor. This creates a new tiki sandbox.\n
    tiki.Sandbox.call(this, bespin.tiki.require.loader, {}, []);\n
\n
    // Register the plugins from the main catalog in the sandbox catalog.\n
    var sandboxCatalog = this.require(\'bespin:plugins\').catalog;\n
\n
    // Set the parent catalog for the sandbox catalog. This makes the sandbox\n
    // be a slave catalog of the master catalog.\n
    sandboxCatalog.parent = catalog;\n
    catalog.children.push(sandboxCatalog);\n
\n
    // Copy over a few things from the master catalog.\n
    sandboxCatalog.deactivatePlugin = util.clone(catalog.deactivatePlugin);\n
    sandboxCatalog._extensionsOrdering = util.clone(catalog._extensionsOrdering);\n
\n
    // Register the metadata from the master catalog.\n
    sandboxCatalog._registerMetadata(util.clone(catalog.metadata, true));\n
};\n
\n
Sandbox.prototype = new tiki.Sandbox();\n
\n
/**\n
 * Overrides the standard tiki.Sandbox.require function. If the requested\n
 * module/plugin is shared between the sandboxes, then the require function\n
 * on the `master` sandbox is called. Otherwise it calls the overridden require\n
 * function.\n
 */\n
Sandbox.prototype.require = function(moduleId, curModuleId, workingPackage) {\n
    // assume canonical() will normalize params\n
    var canonicalId = this.loader.canonical(moduleId, curModuleId, workingPackage);\n
    // Get the plugin name.\n
    var pluginName = canonicalId.substring(2).split(\':\')[0];\n
\n
    // Check if this module should be shared.\n
    if (catalog.plugins[pluginName].share) {\n
        // The module is shared, so require it from the main sandbox.\n
        return bespin.tiki.sandbox.require(moduleId, curModuleId, workingPackage);\n
    } else {\n
        // This module is not shared, so use the normal require function.\n
        return tiki.Sandbox.prototype.require.call(this, moduleId,\n
                                                    curModuleId, workingPackage);\n
    }\n
}\n
\n
// Expose the sandbox.\n
exports.Sandbox = Sandbox;\n
\n
});\n
\n
bespin.tiki.module("bespin:promise",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var console = require(\'bespin:console\').console;\n
var Trace = require(\'bespin:util/stacktrace\').Trace;\n
\n
/**\n
 * A promise can be in one of 2 states.\n
 * The ERROR and SUCCESS states are terminal, the PENDING state is the only\n
 * start state.\n
 */\n
var ERROR = -1;\n
var PENDING = 0;\n
var SUCCESS = 1;\n
\n
/**\n
 * We give promises and ID so we can track which are outstanding\n
 */\n
var _nextId = 0;\n
\n
/**\n
 * Debugging help if 2 things try to complete the same promise.\n
 * This can be slow (especially on chrome due to the stack trace unwinding) so\n
 * we should leave this turned off in normal use.\n
 */\n
var _traceCompletion = false;\n
\n
/**\n
 * Outstanding promises. Handy list for debugging only.\n
 */\n
exports._outstanding = [];\n
\n
/**\n
 * Recently resolved promises. Also for debugging only.\n
 */\n
exports._recent = [];\n
\n
/**\n
 * Create an unfulfilled promise\n
 */\n
exports.Promise = function () {\n
    this._status = PENDING;\n
    this._value = undefined;\n
    this._onSuccessHandlers = [];\n
    this._onErrorHandlers = [];\n
\n
    // Debugging help\n
    this._id = _nextId++;\n
    //this._createTrace = new Trace(new Error());\n
    exports._outstanding[this._id] = this;\n
};\n
\n
/**\n
 * Yeay for RTTI.\n
 */\n
exports.Promise.prototype.isPromise = true;\n
\n
/**\n
 * Have we either been resolve()ed or reject()ed?\n
 */\n
exports.Promise.prototype.isComplete = function() {\n
    return this._status != PENDING;\n
};\n
\n
/**\n
 * Have we resolve()ed?\n
 */\n
exports.Promise.prototype.isResolved = function() {\n
    return this._status == SUCCESS;\n
};\n
\n
/**\n
 * Have we reject()ed?\n
 */\n
exports.Promise.prototype.isRejected = function() {\n
    return this._status == ERROR;\n
};\n
\n
/**\n
 * Take the specified action of fulfillment of a promise, and (optionally)\n
 * a different action on promise rejection.\n
 */\n
exports.Promise.prototype.then = function(onSuccess, onError) {\n
    if (typeof onSuccess === \'function\') {\n
        if (this._status === SUCCESS) {\n
            onSuccess.call(null, this._value);\n
        } else if (this._status === PENDING) {\n
            this._onSuccessHandlers.push(onSuccess);\n
        }\n
    }\n
\n
    if (typeof onError === \'function\') {\n
        if (this._status === ERROR) {\n
            onError.call(null, this._value);\n
        } else if (this._status === PENDING) {\n
            this._onErrorHandlers.push(onError);\n
        }\n
    }\n
\n
    return this;\n
};\n
\n
/**\n
 * Like then() except that rather than returning <tt>this</tt> we return\n
 * a promise which\n
 */\n
exports.Promise.prototype.chainPromise = function(onSuccess) {\n
    var chain = new exports.Promise();\n
    chain._chainedFrom = this;\n
    this.then(function(data) {\n
        try {\n
            chain.resolve(onSuccess(data));\n
        } catch (ex) {\n
            chain.reject(ex);\n
        }\n
    }, function(ex) {\n
        chain.reject(ex);\n
    });\n
    return chain;\n
};\n
\n
/**\n
 * Supply the fulfillment of a promise\n
 */\n
exports.Promise.prototype.resolve = function(data) {\n
    return this._complete(this._onSuccessHandlers, SUCCESS, data, \'resolve\');\n
};\n
\n
/**\n
 * Renege on a promise\n
 */\n
exports.Promise.prototype.reject = function(data) {\n
    return this._complete(this._onErrorHandlers, ERROR, data, \'reject\');\n
};\n
\n
/**\n
 * Internal method to be called on resolve() or reject().\n
 * @private\n
 */\n
exports.Promise.prototype._complete = function(list, status, data, name) {\n
    // Complain if we\'ve already been completed\n
    if (this._status != PENDING) {\n
        console.group(\'Promise already closed\');\n
        console.error(\'Attempted \' + name + \'() with \', data);\n
        console.error(\'Previous status = \', this._status,\n
                \', previous value = \', this._value);\n
        console.trace();\n
\n
        if (this._completeTrace) {\n
            console.error(\'Trace of previous completion:\');\n
            this._completeTrace.log(5);\n
        }\n
        console.groupEnd();\n
        return this;\n
    }\n
\n
    if (_traceCompletion) {\n
        this._completeTrace = new Trace(new Error());\n
    }\n
\n
    this._status = status;\n
    this._value = data;\n
\n
    // Call all the handlers, and then delete them\n
    list.forEach(function(handler) {\n
        handler.call(null, this._value);\n
    }, this);\n
    this._onSuccessHandlers.length = 0;\n
    this._onErrorHandlers.length = 0;\n
\n
    // Remove the given {promise} from the _outstanding list, and add it to the\n
    // _recent list, pruning more than 20 recent promises from that list.\n
    delete exports._outstanding[this._id];\n
    exports._recent.push(this);\n
    while (exports._recent.length > 20) {\n
        exports._recent.shift();\n
    }\n
\n
    return this;\n
};\n
\n
\n
/**\n
 * Takes an array of promises and returns a promise that that is fulfilled once\n
 * all the promises in the array are fulfilled\n
 * @param group The array of promises\n
 * @return the promise that is fulfilled when all the array is fulfilled\n
 */\n
exports.group = function(promiseList) {\n
    if (!(promiseList instanceof Array)) {\n
        promiseList = Array.prototype.slice.call(arguments);\n
    }\n
\n
    // If the original array has nothing in it, return now to avoid waiting\n
    if (promiseList.length === 0) {\n
        return new exports.Promise().resolve([]);\n
    }\n
\n
    var groupPromise = new exports.Promise();\n
    var results = [];\n
    var fulfilled = 0;\n
\n
    var onSuccessFactory = function(index) {\n
        return function(data) {\n
            results[index] = data;\n
            fulfilled++;\n
            // If the group has already failed, silently drop extra results\n
            if (groupPromise._status !== ERROR) {\n
                if (fulfilled === promiseList.length) {\n
                    groupPromise.resolve(results);\n
                }\n
            }\n
        };\n
    };\n
\n
    promiseList.forEach(function(promise, index) {\n
        var onSuccess = onSuccessFactory(index);\n
        var onError = groupPromise.reject.bind(groupPromise);\n
        promise.then(onSuccess, onError);\n
    });\n
\n
    return groupPromise;\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:util/scratchcanvas",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require(\'bespin:util/util\');\n
\n
/**\n
 * A invisible singleton canvas on the page, useful whenever a canvas context\n
 * is needed (e.g. for computing text sizes), but an actual canvas isn\'t handy\n
 * at the moment.\n
 * @constructor\n
 */\n
var ScratchCanvas = function() {\n
    this._canvas = document.getElementById(\'bespin-scratch-canvas\');\n
\n
    // It\'s possible that another ScratchCanvas instance in another sandbox\n
    // exists on the page. If so, we assume they\'re compatible, and use\n
    // that one.\n
    if (util.none(this._canvas)) {\n
        this._canvas = document.createElement(\'canvas\');\n
        this._canvas.id = \'bespin-scratch-canvas\';\n
        this._canvas.width = 400;\n
        this._canvas.height = 300;\n
        this._canvas.style.position = \'absolute\';\n
        this._canvas.style.top = "-10000px";\n
        this._canvas.style.left = "-10000px";\n
        document.body.appendChild(this._canvas);\n
    }\n
};\n
\n
ScratchCanvas.prototype.getContext = function() {\n
    return this._canvas.getContext(\'2d\');\n
};\n
\n
/**\n
 * Returns the width in pixels of the given string ("M", by default) in the\n
 * given font.\n
 */\n
ScratchCanvas.prototype.measureStringWidth = function(font, str) {\n
    if (util.none(str)) {\n
        str = "M";\n
    }\n
\n
    var context = this.getContext();\n
    context.save();\n
    context.font = font;\n
    var width = context.measureText(str).width;\n
    context.restore();\n
    return width;\n
};\n
\n
var singleton = null;\n
\n
/**\n
 * Returns the instance of the scratch canvas on the page, creating it if\n
 * necessary.\n
 */\n
exports.get = function() {\n
    if (singleton === null) {\n
        singleton = new ScratchCanvas();\n
    }\n
    return singleton;\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:util/cookie",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
/**\n
 * Adds escape sequences for special characters in regular expressions\n
 * @param {String} str a String with special characters to be left unescaped\n
 */\n
var escapeString = function(str, except){\n
    return str.replace(/([\\.$?*|{}\\(\\)\\[\\]\\\\\\/\\+^])/g, function(ch){\n
        if(except && except.indexOf(ch) != -1){\n
            return ch;\n
        }\n
        return "\\\\" + ch;\n
    });\n
};\n
\n
/**\n
 * Get a cookie value by name\n
 * @param {String} name The cookie value to retrieve\n
 * @return The value, or undefined if the cookie was not found\n
 */\n
exports.get = function(name) {\n
    var matcher = new RegExp("(?:^|; )" + escapeString(name) + "=([^;]*)");\n
    var matches = document.cookie.match(matcher);\n
    return matches ? decodeURIComponent(matches[1]) : undefined;\n
};\n
\n
/**\n
 * Set a cookie value\n
 * @param {String} name The cookie value to alter\n
 * @param {String} value The new value for the cookie\n
 * @param {Object} props (Optional) cookie properties. One of:<ul>\n
 * <li>expires: Date|String|Number|null If a number, the number of days from\n
 * today at which the cookie will expire. If a date, the date past which the\n
 * cookie will expire. If expires is in the past, the cookie will be deleted.\n
 * If expires is omitted or is 0, the cookie will expire either directly (ff3)\n
 * or when the browser closes\n
 * <li>path: String|null The path to use for the cookie.\n
 * <li>domain: String|null The domain to use for the cookie.\n
 * <li>secure: Boolean|null Whether to only send the cookie on secure connections\n
 * </ul>\n
 */\n
exports.set = function(name, value, props) {\n
    props = props || {};\n
\n
    if (typeof props.expires == "number") {\n
        var date = new Date();\n
        date.setTime(date.getTime() + props.expires * 24 * 60 * 60 * 1000);\n
        props.expires = date;\n
    }\n
    if (props.expires && props.expires.toUTCString) {\n
        props.expires = props.expires.toUTCString();\n
    }\n
\n
    value = encodeURIComponent(value);\n
    var updatedCookie = name + "=" + value, propName;\n
    for (propName in props) {\n
        updatedCookie += "; " + propName;\n
        var propValue = props[propName];\n
        if (propValue !== true) {\n
            updatedCookie += "=" + propValue;\n
        }\n
    }\n
\n
    document.cookie = updatedCookie;\n
};\n
\n
/**\n
 * Remove a cookie by name. Depending on the browser, the cookie will either\n
 * be deleted directly or at browser close.\n
 * @param {String} name The cookie value to retrieve\n
 */\n
exports.remove = function(name) {\n
    exports.set(name, "", { expires: -1 });\n
};\n
\n
/**\n
 * Use to determine if the current browser supports cookies or not.\n
 * @return Returns true if user allows cookies, false otherwise\n
 */\n
exports.isSupported = function() {\n
    if (!("cookieEnabled" in navigator)) {\n
        exports.set("__djCookieTest__", "CookiesAllowed");\n
        navigator.cookieEnabled = exports.get("__djCookieTest__") == "CookiesAllowed";\n
        if (navigator.cookieEnabled) {\n
            exports.remove("__djCookieTest__");\n
        }\n
    }\n
    return navigator.cookieEnabled;\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:util/util",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
/**\n
 * Create an object representing a de-serialized query section of a URL.\n
 * Query keys with multiple values are returned in an array.\n
 * <p>Example: The input "foo=bar&foo=baz&thinger=%20spaces%20=blah&zonk=blarg&"\n
 * Produces the output object:\n
 * <pre>{\n
 *   foo: [ "bar", "baz" ],\n
 *   thinger: " spaces =blah",\n
 *   zonk: "blarg"\n
 * }\n
 * </pre>\n
 * <p>Note that spaces and other urlencoded entities are correctly handled\n
 * @see dojo.queryToObject()\n
 * While dojo.queryToObject() is mainly for URL query strings, this version\n
 * allows to specify a separator character\n
 */\n
exports.queryToObject = function(str, seperator) {\n
    var ret = {};\n
    var qp = str.split(seperator || "&");\n
    var dec = decodeURIComponent;\n
    qp.forEach(function(item) {\n
        if (item.length) {\n
            var parts = item.split("=");\n
            var name = dec(parts.shift());\n
            var val = dec(parts.join("="));\n
            if (exports.isString(ret[name])){\n
                ret[name] = [ret[name]];\n
            }\n
            if (Array.isArray(ret[name])){\n
                ret[name].push(val);\n
            } else {\n
                ret[name] = val;\n
            }\n
        }\n
    });\n
    return ret;\n
};\n
\n
/**\n
 * Takes a name/value mapping object and returns a string representing a\n
 * URL-encoded version of that object for use in a GET request\n
 * <p>For example, given the input:\n
 * <code>{ blah: "blah", multi: [ "thud", "thonk" ] }</code>\n
 * The following string would be returned:\n
 * <code>"blah=blah&multi=thud&multi=thonk"</code>\n
 * @param map {Object} The object to convert\n
 * @return {string} A URL-encoded version of the input\n
 */\n
exports.objectToQuery = function(map) {\n
    // FIXME: need to implement encodeAscii!!\n
    var enc = encodeURIComponent;\n
    var pairs = [];\n
    var backstop = {};\n
    for (var name in map) {\n
        var value = map[name];\n
        if (value != backstop[name]) {\n
            var assign = enc(name) + "=";\n
            if (value.isArray) {\n
                for (var i = 0; i < value.length; i++) {\n
                    pairs.push(assign + enc(value[i]));\n
                }\n
            } else {\n
                pairs.push(assign + enc(value));\n
            }\n
        }\n
    }\n
    return pairs.join("&");\n
};\n
\n
/**\n
 * Holds the count to keep a unique value for setTimeout\n
 * @private See rateLimit()\n
 */\n
var nextRateLimitId = 0;\n
\n
/**\n
 * Holds the timeouts so they can be cleared later\n
 * @private See rateLimit()\n
 */\n
var rateLimitTimeouts = {};\n
\n
/**\n
 * Delay calling some function to check that it\'s not called again inside a\n
 * maxRate. The real function is called after maxRate ms unless the return\n
 * value of this function is called before, in which case the clock is restarted\n
 */\n
exports.rateLimit = function(maxRate, scope, func) {\n
    if (maxRate) {\n
        var rateLimitId = nextRateLimitId++;\n
\n
        return function() {\n
            if (rateLimitTimeouts[rateLimitId]) {\n
                clearTimeout(rateLimitTimeouts[rateLimitId]);\n
            }\n
\n
            rateLimitTimeouts[rateLimitId] = setTimeout(function() {\n
                func.apply(scope, arguments);\n
                delete rateLimitTimeouts[rateLimitId];\n
            }, maxRate);\n
        };\n
    }\n
};\n
\n
/**\n
 * Return true if it is a String\n
 */\n
exports.isString = function(it) {\n
    return (typeof it == "string" || it instanceof String);\n
};\n
\n
/**\n
 * Returns true if it is a Boolean.\n
 */\n
exports.isBoolean = function(it) {\n
    return (typeof it == \'boolean\');\n
};\n
\n
/**\n
 * Returns true if it is a Number.\n
 */\n
exports.isNumber = function(it) {\n
    return (typeof it == \'number\' && isFinite(it));\n
};\n
\n
/**\n
 * Hack copied from dojo.\n
 */\n
exports.isObject = function(it) {\n
    return it !== undefined &&\n
        (it === null || typeof it == "object" ||\n
        Array.isArray(it) || exports.isFunction(it));\n
};\n
\n
/**\n
 * Is the passed object a function?\n
 * From dojo.isFunction()\n
 */\n
exports.isFunction = (function() {\n
    var _isFunction = function(it) {\n
        var t = typeof it; // must evaluate separately due to bizarre Opera bug. See #8937\n
        //Firefox thinks object HTML element is a function, so test for nodeType.\n
        return it && (t == "function" || it instanceof Function) && !it.nodeType; // Boolean\n
    };\n
\n
    return exports.isSafari ?\n
        // only slow this down w/ gratuitious casting in Safari (not WebKit)\n
        function(/*anything*/ it) {\n
            if (typeof it == "function" && it == "[object NodeList]") {\n
                return false;\n
            }\n
            return _isFunction(it); // Boolean\n
        } : _isFunction;\n
})();\n
\n
/**\n
 * A la Prototype endsWith(). Takes a regex excluding the \'$\' end marker\n
 */\n
exports.endsWith = function(str, end) {\n
    if (!str) {\n
        return false;\n
    }\n
    return str.match(new RegExp(end + "$"));\n
};\n
\n
/**\n
 * A la Prototype include().\n
 */\n
exports.include = function(array, item) {\n
    return array.indexOf(item) > -1;\n
};\n
\n
/**\n
 * Like include, but useful when you\'re checking for a specific\n
 * property on each object in the list...\n
 *\n
 * Returns null if the item is not in the list, otherwise\n
 * returns the index of the item.\n
 */\n
exports.indexOfProperty = function(array, propertyName, item) {\n
    for (var i = 0; i < array.length; i++) {\n
        if (array[i][propertyName] == item) {\n
            return i;\n
        }\n
    }\n
    return null;\n
};\n
\n
/**\n
 * A la Prototype last().\n
 */\n
exports.last = function(array) {\n
    if (Array.isArray(array)) {\n
        return array[array.length - 1];\n
    }\n
};\n
\n
/**\n
 * Knock off any undefined items from the end of an array\n
 */\n
exports.shrinkArray = function(array) {\n
    var newArray = [];\n
\n
    var stillAtBeginning = true;\n
    array.reverse().forEach(function(item) {\n
        if (stillAtBeginning && item === undefined) {\n
            return;\n
        }\n
\n
        stillAtBeginning = false;\n
\n
        newArray.push(item);\n
    });\n
\n
    return newArray.reverse();\n
};\n
\n
/**\n
 * Create an array\n
 * @param number The size of the new array to create\n
 * @param character The item to put in the array, defaults to \' \'\n
 */\n
exports.makeArray = function(number, character) {\n
    if (number < 1) {\n
        return []; // give us a normal number please!\n
    }\n
    if (!character){character = \' \';}\n
\n
    var newArray = [];\n
    for (var i = 0; i < number; i++) {\n
        newArray.push(character);\n
    }\n
    return newArray;\n
};\n
\n
/**\n
 * Repeat a string a given number of times.\n
 * @param string String to repeat\n
 * @param repeat Number of times to repeat\n
 */\n
exports.repeatString = function(string, repeat) {\n
    var newstring = \'\';\n
\n
    for (var i = 0; i < repeat; i++) {\n
        newstring += string;\n
    }\n
\n
    return newstring;\n
};\n
\n
/**\n
 * Given a row, find the number of leading spaces.\n
 * E.g. an array with the string "  aposjd" would return 2\n
 * @param row The row to hunt through\n
 */\n
exports.leadingSpaces = function(row) {\n
    var numspaces = 0;\n
    for (var i = 0; i < row.length; i++) {\n
        if (row[i] == \' \' || row[i] == \'\' || row[i] === undefined) {\n
            numspaces++;\n
        } else {\n
            return numspaces;\n
        }\n
    }\n
    return numspaces;\n
};\n
\n
/**\n
 * Given a row, find the number of leading tabs.\n
 * E.g. an array with the string "\\t\\taposjd" would return 2\n
 * @param row The row to hunt through\n
 */\n
exports.leadingTabs = function(row) {\n
    var numtabs = 0;\n
    for (var i = 0; i < row.length; i++) {\n
        if (row[i] == \'\\t\' || row[i] == \'\' || row[i] === undefined) {\n
            numtabs++;\n
        } else {\n
            return numtabs;\n
        }\n
    }\n
    return numtabs;\n
};\n
\n
/**\n
 * Given a row, extract a copy of the leading spaces or tabs.\n
 * E.g. an array with the string "\\t    \\taposjd" would return an array with the\n
 * string "\\t    \\t".\n
 * @param row The row to hunt through\n
 */\n
exports.leadingWhitespace = function(row) {\n
    var leading = [];\n
    for (var i = 0; i < row.length; i++) {\n
        if (row[i] == \' \' || row[i] == \'\\t\' || row[i] == \'\' || row[i] === undefined) {\n
            leading.push(row[i]);\n
        } else {\n
            return leading;\n
        }\n
    }\n
    return leading;\n
};\n
\n
/**\n
 * Given a camelCaseWord convert to "Camel Case Word"\n
 */\n
exports.englishFromCamel = function(camel) {\n
    camel.replace(/([A-Z])/g, function(str) {\n
        return " " + str.toLowerCase();\n
    }).trim();\n
};\n
\n
/**\n
 * I hate doing this, but we need some way to determine if the user is on a Mac\n
 * The reason is that users have different expectations of their key combinations.\n
 *\n
 * Take copy as an example, Mac people expect to use CMD or APPLE + C\n
 * Windows folks expect to use CTRL + C\n
 */\n
exports.OS = {\n
    LINUX: \'LINUX\',\n
    MAC: \'MAC\',\n
    WINDOWS: \'WINDOWS\'\n
};\n
\n
var ua = navigator.userAgent;\n
var av = navigator.appVersion;\n
\n
/** Is the user using a browser that identifies itself as Linux */\n
exports.isLinux = av.indexOf("Linux") >= 0;\n
\n
/** Is the user using a browser that identifies itself as Windows */\n
exports.isWindows = av.indexOf("Win") >= 0;\n
\n
/** Is the user using a browser that identifies itself as WebKit */\n
exports.isWebKit = parseFloat(ua.split("WebKit/")[1]) || undefined;\n
\n
/** Is the user using a browser that identifies itself as Chrome */\n
exports.isChrome = parseFloat(ua.split("Chrome/")[1]) || undefined;\n
\n
/** Is the user using a browser that identifies itself as Mac OS */\n
exports.isMac = av.indexOf("Macintosh") >= 0;\n
\n
/* Is this Firefox or related? */\n
exports.isMozilla = av.indexOf(\'Gecko/\') >= 0;\n
\n
if (ua.indexOf("AdobeAIR") >= 0) {\n
    exports.isAIR = 1;\n
}\n
\n
/**\n
 * Is the user using a browser that identifies itself as Safari\n
 * See also:\n
 * - http://developer.apple.com/internet/safari/faq.html#anchor2\n
 * - http://developer.apple.com/internet/safari/uamatrix.html\n
 */\n
var index = Math.max(av.indexOf("WebKit"), av.indexOf("Safari"), 0);\n
if (index && !exports.isChrome) {\n
    // try to grab the explicit Safari version first. If we don\'t get\n
    // one, look for less than 419.3 as the indication that we\'re on something\n
    // "Safari 2-ish".\n
    exports.isSafari = parseFloat(av.split("Version/")[1]);\n
    if (!exports.isSafari || parseFloat(av.substr(index + 7)) <= 419.3) {\n
        exports.isSafari = 2;\n
    }\n
}\n
\n
if (ua.indexOf("Gecko") >= 0 && !exports.isWebKit) {\n
    exports.isMozilla = parseFloat(av);\n
}\n
\n
/**\n
 * Return a exports.OS constant\n
 */\n
exports.getOS = function() {\n
    if (exports.isMac) {\n
        return exports.OS[\'MAC\'];\n
    } else if (exports.isLinux) {\n
        return exports.OS[\'LINUX\'];\n
    } else {\n
        return exports.OS[\'WINDOWS\'];\n
    }\n
};\n
\n
/** Returns true if the DOM element "b" is inside the element "a". */\n
if (typeof(document) !== \'undefined\' && document.compareDocumentPosition) {\n
    exports.contains = function(a, b) {\n
        return a.compareDocumentPosition(b) & 16;\n
    };\n
} else {\n
    exports.contains = function(a, b) {\n
        return a !== b && (a.contains ? a.contains(b) : true);\n
    };\n
}\n
\n
/**\n
 * Prevents propagation and clobbers the default action of the passed event\n
 */\n
exports.stopEvent = function(ev) {\n
    ev.preventDefault();\n
    ev.stopPropagation();\n
};\n
\n
/**\n
 * Create a random password of the given length (default 16 chars)\n
 */\n
exports.randomPassword = function(length) {\n
    length = length || 16;\n
    var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";\n
    var pass = "";\n
    for (var x = 0; x < length; x++) {\n
        var charIndex = Math.floor(Math.random() * chars.length);\n
        pass += chars.charAt(charIndex);\n
    }\n
    return pass;\n
};\n
\n
/**\n
 * Is the passed object free of members, i.e. are there any enumerable\n
 * properties which the objects claims as it\'s own using hasOwnProperty()\n
 */\n
exports.isEmpty = function(object) {\n
    for (var x in object) {\n
        if (object.hasOwnProperty(x)) {\n
            return false;\n
        }\n
    }\n
    return true;\n
};\n
\n
/**\n
 * Does the name of a project indicate that it is owned by someone else\n
 * TODO: This is a major hack. We really should have a File object that include\n
 * separate owner information.\n
 */\n
exports.isMyProject = function(project) {\n
    return project.indexOf("+") == -1;\n
};\n
\n
/**\n
 * Format a date as dd MMM yyyy\n
 */\n
exports.formatDate = function (date) {\n
    if (!date) {\n
        return "Unknown";\n
    }\n
    return date.getDate() + " " +\n
        exports.formatDate.shortMonths[date.getMonth()] + " " +\n
        date.getFullYear();\n
};\n
\n
/**\n
 * Month data for exports.formatDate\n
 */\n
exports.formatDate.shortMonths = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ];\n
\n
/**\n
 * Add a CSS class to the list of classes on the given node\n
 */\n
exports.addClass = function(node, className) {\n
    var parts = className.split(/\\s+/);\n
    var cls = " " + node.className + " ";\n
    for (var i = 0, len = parts.length, c; i < len; ++i) {\n
        c = parts[i];\n
        if (c && cls.indexOf(" " + c + " ") < 0) {\n
            cls += c + " ";\n
        }\n
    }\n
    node.className = cls.trim();\n
};\n
\n
/**\n
 * Remove a CSS class from the list of classes on the given node\n
 */\n
exports.removeClass = function(node, className) {\n
    var cls;\n
    if (className !== undefined) {\n
        var parts = className.split(/\\s+/);\n
        cls = " " + node.className + " ";\n
        for (var i = 0, len = parts.length; i < len; ++i) {\n
            cls = cls.replace(" " + parts[i] + " ", " ");\n
        }\n
        cls = cls.trim();\n
    } else {\n
        cls = "";\n
    }\n
    if (node.className != cls) {\n
        node.className = cls;\n
    }\n
};\n
\n
/**\n
 * Add or remove a CSS class from the list of classes on the given node\n
 * depending on the value of <tt>include</tt>\n
 */\n
exports.setClass = function(node, className, include) {\n
    if (include) {\n
        exports.addClass(node, className);\n
    } else {\n
        exports.removeClass(node, className);\n
    }\n
};\n
\n
/**\n
 * Is the passed object either null or undefined (using ===)\n
 */\n
exports.none = function(obj) {\n
    return obj === null || obj === undefined;\n
};\n
\n
/**\n
 * Creates a clone of the passed object.  This function can take just about\n
 * any type of object and create a clone of it, including primitive values\n
 * (which are not actually cloned because they are immutable).\n
 * If the passed object implements the clone() method, then this function\n
 * will simply call that method and return the result.\n
 * @param object {Object} the object to clone\n
 * @returns {Object} the cloned object\n
 */\n
exports.clone = function(object, deep) {\n
    if (Array.isArray(object) && !deep) {\n
        return object.slice();\n
    }\n
\n
    if (typeof object === \'object\' || Array.isArray(object)) {\n
        if (object === null) {\n
            return null;\n
        }\n
\n
        var reply = (Array.isArray(object) ? [] : {});\n
        for (var key in object) {\n
            if (deep && (typeof object[key] === \'object\'\n
                            || Array.isArray(object[key]))) {\n
                reply[key] = exports.clone(object[key], true);\n
            } else {\n
                 reply[key] = object[key];\n
            }\n
        }\n
        return reply;\n
    }\n
\n
    if (object.clone && typeof(object.clone) === \'function\') {\n
        return object.clone();\n
    }\n
\n
    // That leaves numbers, booleans, undefined. Doesn\'t it?\n
    return object;\n
};\n
\n
\n
/**\n
 * Helper method for extending one object with another\n
 * Copies all properties from source to target. Returns the extended target\n
 * object.\n
 * Taken from John Resig, http://ejohn.org/blog/javascript-getters-and-setters/.\n
 */\n
exports.mixin = function(a, b) {\n
    for (var i in b) {\n
        var g = b.__lookupGetter__(i);\n
        var s = b.__lookupSetter__(i);\n
\n
        if (g || s) {\n
            if (g) {\n
                a.__defineGetter__(i, g);\n
            }\n
            if (s) {\n
                a.__defineSetter__(i, s);\n
            }\n
        } else {\n
            a[i] = b[i];\n
        }\n
    }\n
\n
    return a;\n
};\n
\n
/**\n
 * Basically taken from Sproutcore.\n
 * Replaces the count items from idx with objects.\n
 */\n
exports.replace = function(arr, idx, amt, objects) {\n
    return arr.slice(0, idx).concat(objects).concat(arr.slice(idx + amt));\n
};\n
\n
/**\n
 * Return true if the two frames match.  You can also pass only points or sizes.\n
 * @param r1 {Rect} the first rect\n
 * @param r2 {Rect} the second rect\n
 * @param delta {Float} an optional delta that allows for rects that do not match exactly. Defaults to 0.1\n
 * @returns {Boolean} true if rects match\n
 */\n
exports.rectsEqual = function(r1, r2, delta) {\n
    if (!r1 || !r2) {\n
        return r1 == r2;\n
    }\n
\n
    if (!delta && delta !== 0) {\n
        delta = 0.1;\n
    }\n
\n
    if ((r1.y != r2.y) && (Math.abs(r1.y - r2.y) > delta)) {\n
        return false;\n
    }\n
\n
    if ((r1.x != r2.x) && (Math.abs(r1.x - r2.x) > delta)) {\n
        return false;\n
    }\n
\n
    if ((r1.width != r2.width) && (Math.abs(r1.width - r2.width) > delta)) {\n
        return false;\n
    }\n
\n
    if ((r1.height != r2.height) && (Math.abs(r1.height - r2.height) > delta)) {\n
        return false;\n
    }\n
\n
    return true;\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:util/stacktrace",function(require,exports,module) {\n
// Changed to suit the specific needs of running within Bespin\n
\n
// Domain Public by Eric Wendelin http://eriwen.com/ (2008)\n
//                  Luke Smith http://lucassmith.name/ (2008)\n
//                  Loic Dachary <loic@dachary.org> (2008)\n
//                  Johan Euphrosine <proppy@aminche.com> (2008)\n
//                  Øyvind Sean Kinsey http://kinsey.no/blog\n
//\n
// Information and discussions\n
// http://jspoker.pokersource.info/skin/test-printstacktrace.html\n
// http://eriwen.com/javascript/js-stack-trace/\n
// http://eriwen.com/javascript/stacktrace-update/\n
// http://pastie.org/253058\n
// http://browsershots.org/http://jspoker.pokersource.info/skin/test-printstacktrace.html\n
//\n
\n
//\n
// guessFunctionNameFromLines comes from firebug\n
//\n
// Software License Agreement (BSD License)\n
//\n
// Copyright (c) 2007, Parakey Inc.\n
// All rights reserved.\n
//\n
// Redistribution and use of this software in source and binary forms, with or without modification,\n
// are permitted provided that the following conditions are met:\n
//\n
// * Redistributions of source code must retain the above\n
//   copyright notice, this list of conditions and the\n
//   following disclaimer.\n
//\n
// * Redistributions in binary form must reproduce the above\n
//   copyright notice, this list of conditions and the\n
//   following disclaimer in the documentation and/or other\n
//   materials provided with the distribution.\n
//\n
// * Neither the name of Parakey Inc. nor the names of its\n
//   contributors may be used to endorse or promote products\n
//   derived from this software without specific prior\n
//   written permission of Parakey Inc.\n
//\n
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR\n
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND\n
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR\n
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER\n
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT\n
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n
\n
var util = require(\'bespin:util/util\');\n
var console = require("bespin:console").console;\n
\n
/**\n
 * Different browsers create stack traces in different ways.\n
 * <strike>Feature</strike> Browser detection baby ;).\n
 */\n
var mode = (function() {\n
\n
    // We use SC\'s browser detection here to avoid the "break on error"\n
    // functionality provided by Firebug. Firebug tries to do the right\n
    // thing here and break, but it happens every time you load the page.\n
    // bug 554105\n
    if (util.isMozilla) {\n
        return \'firefox\';\n
    } else if (util.isOpera) {\n
        return \'opera\';\n
    } else if (util.isSafari) {\n
        return \'other\';\n
    }\n
\n
    // SC doesn\'t do any detection of Chrome at this time.\n
\n
    // this is the original feature detection code that is used as a\n
    // fallback.\n
    try {\n
        (0)();\n
    } catch (e) {\n
        if (e.arguments) {\n
            return \'chrome\';\n
        }\n
        if (e.stack) {\n
            return \'firefox\';\n
        }\n
        if (window.opera && !(\'stacktrace\' in e)) { //Opera 9-\n
            return \'opera\';\n
        }\n
    }\n
    return \'other\';\n
})();\n
\n
/**\n
 *\n
 */\n
function stringifyArguments(args) {\n
    for (var i = 0; i < args.length; ++i) {\n
        var argument = args[i];\n
        if (typeof argument == \'object\') {\n
            args[i] = \'#object\';\n
        } else if (typeof argument == \'function\') {\n
            args[i] = \'#function\';\n
        } else if (typeof argument == \'string\') {\n
            args[i] = \'"\' + argument + \'"\';\n
        }\n
    }\n
    return args.join(\',\');\n
}\n
\n
/**\n
 * Extract a stack trace from the format emitted by each browser.\n
 */\n
var decoders = {\n
    chrome: function(e) {\n
        var stack = e.stack;\n
        if (!stack) {\n
            console.log(e);\n
            return [];\n
        }\n
        return stack.replace(/^.*?\\n/, \'\').\n
                replace(/^.*?\\n/, \'\').\n
                replace(/^.*?\\n/, \'\').\n
                replace(/^[^\\(]+?[\\n$]/gm, \'\').\n
                replace(/^\\s+at\\s+/gm, \'\').\n
                replace(/^Object.<anonymous>\\s*\\(/gm, \'{anonymous}()@\').\n
                split(\'\\n\');\n
    },\n
\n
    firefox: function(e) {\n
        var stack = e.stack;\n
        if (!stack) {\n
            console.log(e);\n
            return [];\n
        }\n
        // stack = stack.replace(/^.*?\\n/, \'\');\n
        stack = stack.replace(/(?:\\n@:0)?\\s+$/m, \'\');\n
        stack = stack.replace(/^\\(/gm, \'{anonymous}(\');\n
        return stack.split(\'\\n\');\n
    },\n
\n
    // Opera 7.x and 8.x only!\n
    opera: function(e) {\n
        var lines = e.message.split(\'\\n\'), ANON = \'{anonymous}\',\n
            lineRE = /Line\\s+(\\d+).*?script\\s+(http\\S+)(?:.*?in\\s+function\\s+(\\S+))?/i, i, j, len;\n
\n
        for (i = 4, j = 0, len = lines.length; i < len; i += 2) {\n
            if (lineRE.test(lines[i])) {\n
                lines[j++] = (RegExp.$3 ? RegExp.$3 + \'()@\' + RegExp.$2 + RegExp.$1 : ANON + \'()@\' + RegExp.$2 + \':\' + RegExp.$1) +\n
                \' -- \' +\n
                lines[i + 1].replace(/^\\s+/, \'\');\n
            }\n
        }\n
\n
        lines.splice(j, lines.length - j);\n
        return lines;\n
    },\n
\n
    // Safari, Opera 9+, IE, and others\n
    other: function(curr) {\n
        var ANON = \'{anonymous}\', fnRE = /function\\s*([\\w\\-$]+)?\\s*\\(/i, stack = [], j = 0, fn, args;\n
\n
        var maxStackSize = 10;\n
        while (curr && stack.length < maxStackSize) {\n
            fn = fnRE.test(curr.toString()) ? RegExp.$1 || ANON : ANON;\n
            args = Array.prototype.slice.call(curr[\'arguments\']);\n
            stack[j++] = fn + \'(\' + stringifyArguments(args) + \')\';\n
\n
            //Opera bug: if curr.caller does not exist, Opera returns curr (WTF)\n
            if (curr === curr.caller && window.opera) {\n
                //TODO: check for same arguments if possible\n
                break;\n
            }\n
            curr = curr.caller;\n
        }\n
        return stack;\n
    }\n
};\n
\n
/**\n
 *\n
 */\n
function NameGuesser() {\n
}\n
\n
NameGuesser.prototype = {\n
\n
    sourceCache: {},\n
\n
    ajax: function(url) {\n
        var req = this.createXMLHTTPObject();\n
        if (!req) {\n
            return;\n
        }\n
        req.open(\'GET\', url, false);\n
        req.setRequestHeader(\'User-Agent\', \'XMLHTTP/1.0\');\n
        req.send(\'\');\n
        return req.responseText;\n
    },\n
\n
    createXMLHTTPObject: function() {\n
\t    // Try XHR methods in order and store XHR factory\n
        var xmlhttp, XMLHttpFactories = [\n
            function() {\n
                return new XMLHttpRequest();\n
            }, function() {\n
                return new ActiveXObject(\'Msxml2.XMLHTTP\');\n
            }, function() {\n
                return new ActiveXObject(\'Msxml3.XMLHTTP\');\n
            }, function() {\n
                return new ActiveXObject(\'Microsoft.XMLHTTP\');\n
            }\n
        ];\n
        for (var i = 0; i < XMLHttpFactories.length; i++) {\n
            try {\n
                xmlhttp = XMLHttpFactories[i]();\n
                // Use memoization to cache the factory\n
                this.createXMLHTTPObject = XMLHttpFactories[i];\n
                return xmlhttp;\n
            } catch (e) {}\n
        }\n
    },\n
\n
    getSource: function(url) {\n
        if (!(url in this.sourceCache)) {\n
            this.sourceCache[url] = this.ajax(url).split(\'\\n\');\n
        }\n
        return this.sourceCache[url];\n
    },\n
\n
    guessFunctions: function(stack) {\n
        for (var i = 0; i < stack.length; ++i) {\n
            var reStack = /{anonymous}\\(.*\\)@(\\w+:\\/\\/([-\\w\\.]+)+(:\\d+)?[^:]+):(\\d+):?(\\d+)?/;\n
            var frame = stack[i], m = reStack.exec(frame);\n
            if (m) {\n
                var file = m[1], lineno = m[4]; //m[7] is character position in Chrome\n
                if (file && lineno) {\n
                    var functionName = this.guessFunctionName(file, lineno);\n
                    stack[i] = frame.replace(\'{anonymous}\', functionName);\n
                }\n
            }\n
        }\n
        return stack;\n
    },\n
\n
    guessFunctionName: function(url, lineNo) {\n
        try {\n
            return this.guessFunctionNameFromLines(lineNo, this.getSource(url));\n
        } catch (e) {\n
            return \'getSource failed with url: \' + url + \', exception: \' + e.toString();\n
        }\n
    },\n
\n
    guessFunctionNameFromLines: function(lineNo, source) {\n
        var reFunctionArgNames = /function ([^(]*)\\(([^)]*)\\)/;\n
        var reGuessFunction = /[\'"]?([0-9A-Za-z_]+)[\'"]?\\s*[:=]\\s*(function|eval|new Function)/;\n
        // Walk backwards from the first line in the function until we find the line which\n
        // matches the pattern above, which is the function definition\n
        var line = \'\', maxLines = 10;\n
        for (var i = 0; i < maxLines; ++i) {\n
            line = source[lineNo - i] + line;\n
            if (line !== undefined) {\n
                var m = reGuessFunction.exec(line);\n
                if (m) {\n
                    return m[1];\n
                }\n
                else {\n
                    m = reFunctionArgNames.exec(line);\n
                }\n
                if (m && m[1]) {\n
                    return m[1];\n
                }\n
            }\n
        }\n
        return \'(?)\';\n
    }\n
};\n
\n
var guesser = new NameGuesser();\n
\n
var frameIgnorePatterns = [\n
    /http:\\/\\/localhost:4020\\/sproutcore.js:/\n
];\n
\n
exports.ignoreFramesMatching = function(regex) {\n
    frameIgnorePatterns.push(regex);\n
};\n
\n
/**\n
 * Create a stack trace from an exception\n
 * @param ex {Error} The error to create a stacktrace from (optional)\n
 * @param guess {Boolean} If we should try to resolve the names of anonymous functions\n
 */\n
exports.Trace = function Trace(ex, guess) {\n
    this._ex = ex;\n
    this._stack = decoders[mode](ex);\n
\n
    if (guess) {\n
        this._stack = guesser.guessFunctions(this._stack);\n
    }\n
};\n
\n
/**\n
 * Log to the console a number of lines (default all of them)\n
 * @param lines {number} Maximum number of lines to wrote to console\n
 */\n
exports.Trace.prototype.log = function(lines) {\n
    if (lines <= 0) {\n
        // You aren\'t going to have more lines in your stack trace than this\n
        // and it still fits in a 32bit integer\n
        lines = 999999999;\n
    }\n
\n
    var printed = 0;\n
    for (var i = 0; i < this._stack.length && printed < lines; i++) {\n
        var frame = this._stack[i];\n
        var display = true;\n
        frameIgnorePatterns.forEach(function(regex) {\n
            if (regex.test(frame)) {\n
                display = false;\n
            }\n
        });\n
        if (display) {\n
            console.debug(frame);\n
            printed++;\n
        }\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
// BEGIN VERSION BLOCK\n
/** The core version of the Bespin system */\n
exports.versionNumber = \'tip\';\n
\n
/** The version number to display to users */\n
exports.versionCodename = \'DEVELOPMENT MODE\';\n
\n
/** The version number of the API (to ensure that the client and server are talking the same language) */\n
exports.apiVersion = \'dev\';\n
\n
// END VERSION BLOCK\n
\n
\n
});\n
\n
bespin.tiki.module("bespin:globals",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
/*\n
* Installs ES5 and SproutCore monkeypatches as needed.\n
*/\n
var installGlobals = function() {\n
    /**\n
     * Array detector.\n
     * Firefox 3.5 and Safari 4 have this already. Chrome 4 however ...\n
     * Note to Dojo - your isArray is still broken: instanceof doesn\'t work with\n
     * Arrays taken from a different frame/window.\n
     */\n
    if (!Array.isArray) {\n
        Array.isArray = function(data) {\n
            return (data && Object.prototype.toString.call(data) == "[object Array]");\n
        };\n
    }\n
\n
    /**\n
     * Retrieves the list of keys on an object.\n
     */\n
    if (!Object.keys) {\n
        Object.keys = function(obj) {\n
            var k, ret = [];\n
            for (k in obj) {\n
                if (obj.hasOwnProperty(k)) {\n
                    ret.push(k);\n
                }\n
            }\n
            return ret;\n
        };\n
    }\n
\n
    if (!Function.prototype.bind) {\n
        // From Narwhal\n
        Function.prototype.bind = function () {\n
            var args = Array.prototype.slice.call(arguments);\n
            var self = this;\n
            var bound = function () {\n
                return self.call.apply(\n
                    self,\n
                    args.concat(\n
                        Array.prototype.slice.call(arguments)\n
                    )\n
                );\n
            };\n
            bound.name = this.name;\n
            bound.displayName = this.displayName;\n
            bound.length = this.length;\n
            bound.unbound = self;\n
            return bound;\n
        };\n
    }\n
};\n
\n
// Narwhal\'s shim for ES5 defineProperty\n
\n
// ES5 15.2.3.6\n
if (!Object.defineProperty) {\n
    Object.defineProperty = function(object, property, descriptor) {\n
        var has = Object.prototype.hasOwnProperty;\n
        if (typeof descriptor == "object" && object.__defineGetter__) {\n
            if (has.call(descriptor, "value")) {\n
                if (!object.__lookupGetter__(property) && !object.__lookupSetter__(property)) {\n
                    // data property defined and no pre-existing accessors\n
                    object[property] = descriptor.value;\n
                }\n
                if (has.call(descriptor, "get") || has.call(descriptor, "set")) {\n
                    // descriptor has a value property but accessor already exists\n
                    throw new TypeError("Object doesn\'t support this action");\n
                }\n
            }\n
            // fail silently if "writable", "enumerable", or "configurable"\n
            // are requested but not supported\n
            /*\n
            // alternate approach:\n
            if ( // can\'t implement these features; allow false but not true\n
            !(has.call(descriptor, "writable") ? descriptor.writable : true) ||\n
            !(has.call(descriptor, "enumerable") ? descriptor.enumerable : true) ||\n
            !(has.call(descriptor, "configurable") ? descriptor.configurable : true)\n
            )\n
            throw new RangeError(\n
            "This implementation of Object.defineProperty does not " +\n
            "support configurable, enumerable, or writable."\n
            );\n
            */\n
            else if (typeof descriptor.get == "function") {\n
                object.__defineGetter__(property, descriptor.get);\n
            }\n
            if (typeof descriptor.set == "function") {\n
                object.__defineSetter__(property, descriptor.set);\n
            }\n
        }\n
        return object;\n
    };\n
}\n
\n
// ES5 15.2.3.7\n
if (!Object.defineProperties) {\n
    Object.defineProperties = function(object, properties) {\n
        for (var property in properties) {\n
            if (Object.prototype.hasOwnProperty.call(properties, property)) {\n
                Object.defineProperty(object, property, properties[property]);\n
            }\n
        }\n
        return object;\n
    };\n
}\n
\n
\n
\n
installGlobals();\n
\n
});\n
\n
bespin.tiki.module("bespin:console",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require("util/util");\n
\n
/**\n
 * This object represents a "safe console" object that forwards debugging\n
 * messages appropriately without creating a dependency on Firebug in Firefox.\n
 */\n
\n
// We could prefer to copy the methods on window.console to exports.console\n
// one by one because then we could be sure of using the safe subset that is\n
// implemented on all browsers, however this doesn\'t work properly everywhere\n
// ...\n
\n
var noop = function() {\n
};\n
\n
// These are the functions that are available in Chrome 4/5, Safari 4\n
// and Firefox 3.6. Don\'t add to this list without checking browser support\n
var NAMES = [\n
    "assert", "count", "debug", "dir", "dirxml", "error", "group", "groupEnd",\n
    "info", "log", "profile", "profileEnd", "time", "timeEnd", "trace", "warn"\n
];\n
\n
if (typeof(window) === \'undefined\') {\n
    // We\'re in a web worker. Forward to the main thread so the messages\n
    // will show up.\n
    var console = {};\n
    NAMES.forEach(function(name) {\n
        console[name] = function() {\n
            var args = Array.prototype.slice.call(arguments);\n
            var msg = { op: \'log\', method: name, args: args };\n
            postMessage(JSON.stringify(msg));\n
        };\n
    });\n
\n
    exports.console = console;\n
} else if (util.isSafari || util.isChrome) {\n
    // Webkit\'s output functions are bizarre because they get confused if \'this\'\n
    // is not window.console, so we just copy it all across\n
    exports.console = window.console;\n
} else {\n
    // So we\'re not in Webkit, but we may still be no console object (in the\n
    // case of Firefox without Firebug)\n
    exports.console = { };\n
\n
    // For each of the console functions, copy them if they exist, stub if not\n
    NAMES.forEach(function(name) {\n
        if (window.console && window.console[name]) {\n
            exports.console[name] = window.console[name];\n
        } else {\n
            exports.console[name] = noop;\n
        }\n
    });\n
}\n
\n
\n
});\n
\n
bespin.tiki.module("bespin:builtins",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
exports.metadata =\n
{\n
    "bespin":\n
    {\n
        "provides":\n
        [\n
            {\n
                "ep": "extensionpoint",\n
                "name": "extensionpoint",\n
                "indexOx": "name",\n
                "register": "plugins#registerExtensionPoint",\n
                "unregister": "plugins#unregisterExtensionPoint",\n
                "description": "Defines a new extension point",\n
                "params": [\n
                    {\n
                        "name": "name",\n
                        "type": "string",\n
                        "description": "the extension point\'s name",\n
                        "required": true\n
                    },\n
                    {\n
                        "name": "description",\n
                        "type": "string",\n
                        "description": "description of what the extension point is for"\n
                    },\n
                    {\n
                        "name": "params",\n
                        "type": "array of objects",\n
                        "description": "parameters that provide the metadata for a given extension. Each object should have name and description, minimally. It can also have a \'type\' (eg string, pointer, or array) and required to denote whether or not this parameter must be present on the extension."\n
                    },\n
                    {\n
                        "name": "indexOn",\n
                        "type": "string",\n
                        "description": "You can provide an \'indexOn\' property to name a property of extensions through which you\'d like to be able to easily look up the extension."\n
                    },\n
                    {\n
                        "name": "register",\n
                        "type": "pointer",\n
                        "description": "function that is called when a new extension is discovered. Note that this should be used sparingly, because it will cause your plugin to be loaded whenever a matching plugin appears."\n
                    },\n
                    {\n
                        "name": "unregister",\n
                        "type": "pointer",\n
                        "description": "function that is called when an extension is removed. Note that this should be used sparingly, because it will cause your plugin to be loaded whenever a matching plugin appears."\n
                    }\n
                ]\n
            },\n
            {\n
                "ep": "extensionpoint",\n
                "name": "extensionhandler",\n
                "register": "plugins#registerExtensionHandler",\n
                "unregister": "plugins#unregisterExtensionHandler",\n
                "description": "Used to attach listeners ",\n
                "params": [\n
                    {\n
                        "name": "name",\n
                        "type": "string",\n
                        "description": "name of the extension point to listen to",\n
                        "required": true\n
                    },\n
                    {\n
                        "name": "register",\n
                        "type": "pointer",\n
                        "description": "function that is called when a new extension is discovered. Note that this should be used sparingly, because it will cause your plugin to be loaded whenever a matching plugin appears."\n
                    },\n
                    {\n
                        "name": "unregister",\n
                        "type": "pointer",\n
                        "description": "function that is called when an extension is removed. Note that this should be used sparingly, because it will cause your plugin to be loaded whenever a matching plugin appears."\n
                    }\n
                ]\n
            },\n
            {\n
                "ep": "extensionpoint",\n
                "name": "factory",\n
                "description": "Provides a factory for singleton components. Each extension needs to provide a name, a pointer and an action. The action can be \'call\' (if the pointer refers to a function), \'new\' (if the pointer refers to a traditional JS object) or \'value\' (if the pointer refers to the object itself that is the component).",\n
                "indexOn": "name"\n
            },\n
            {\n
                "ep": "factory",\n
                "name": "hub",\n
                "action": "create",\n
                "pointer": "util/hub#Hub"\n
            },\n
            {\n
                "ep": "extensionpoint",\n
                "name": "command",\n
                "description": "Editor commands/actions. TODO: list parameters here."\n
            }\n
        ]\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("bespin:proxy",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var util = require("util/util");\n
var Promise = require("promise").Promise;\n
\n
exports.xhr = function(method, url, async, beforeSendCallback) {\n
    var pr = new Promise();\n
\n
    if (!bespin.proxy || !bespin.proxy.xhr) {\n
        var req = new XMLHttpRequest();\n
        req.onreadystatechange = function() {\n
            if (req.readyState !== 4) {\n
                return;\n
            }\n
\n
            var status = req.status;\n
            if (status !== 0 && status !== 200) {\n
                var error = new Error(req.responseText + \' (Status \' + req.status + ")");\n
                error.xhr = req;\n
                pr.reject(error);\n
                return;\n
            }\n
\n
            pr.resolve(req.responseText);\n
        }.bind(this);\n
\n
        req.open("GET", url, async);\n
        if (beforeSendCallback) {\n
            beforeSendCallback(req);\n
        }\n
        req.send();\n
    } else {\n
        bespin.proxy.xhr.call(this, method, url, async, beforeSendCallback, pr);\n
    }\n
\n
    return pr;\n
};\n
\n
exports.Worker = function(url) {\n
    if (!bespin.proxy || !bespin.proxy.worker) {\n
        return new Worker(url);\n
    } else {\n
        return new bespin.proxy.worker(url);\n
    }\n
};\n
\n
});\n
;bespin.tiki.register("::settings", {\n
    name: "settings",\n
    dependencies: { "types": "0.0.0" }\n
});\n
bespin.tiki.module("settings:commands",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var env = require(\'environment\').env;\n
\n
var settings = require(\'settings\').settings;\n
\n
/**\n
 * \'set\' command\n
 */\n
exports.setCommand = function(args, request) {\n
    var html;\n
\n
    if (!args.setting) {\n
        var settingsList = settings._list();\n
        html = \'\';\n
        // first sort the settingsList based on the key\n
        settingsList.sort(function(a, b) {\n
            if (a.key < b.key) {\n
                return -1;\n
            } else if (a.key == b.key) {\n
                return 0;\n
            } else {\n
                return 1;\n
            }\n
        });\n
\n
        settingsList.forEach(function(setting) {\n
            html += \'<a class="setting" href="https://wiki.mozilla.org/Labs/Bespin/Settings#\' +\n
                    setting.key +\n
                    \'" title="View external documentation on setting: \' +\n
                    setting.key +\n
                    \'" target="_blank">\' +\n
                    setting.key +\n
                    \'</a> = \' +\n
                    setting.value +\n
                    \'<br/>\';\n
        });\n
    } else {\n
        if (args.value === undefined) {\n
            html = \'<strong>\' + args.setting + \'</strong> = \' + settings.get(args.setting);\n
        } else {\n
            html = \'Setting: <strong>\' + args.setting + \'</strong> = \' + args.value;\n
            settings.set(args.setting, args.value);\n
        }\n
    }\n
\n
    request.done(html);\n
};\n
\n
/**\n
 * \'unset\' command\n
 */\n
exports.unsetCommand = function(args, request) {\n
    settings.resetValue(args.setting);\n
    request.done(\'Reset \' + args.setting + \' to default: \' + settings.get(args.setting));\n
};\n
\n
});\n
\n
bespin.tiki.module("settings:cookie",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var cookie = require(\'bespin:util/cookie\');\n
\n
/**\n
 * Save the settings in a cookie\n
 * This code has not been tested since reboot\n
 * @constructor\n
 */\n
exports.CookiePersister = function() {\n
};\n
\n
exports.CookiePersister.prototype = {\n
    loadInitialValues: function(settings) {\n
        settings._loadDefaultValues().then(function() {\n
            var data = cookie.get(\'settings\');\n
            settings._loadFromObject(JSON.parse(data));\n
        }.bind(this));\n
    },\n
\n
    persistValue: function(settings, key, value) {\n
        try {\n
            // Aggregate the settings into a file\n
            var data = {};\n
            settings._getSettingNames().forEach(function(key) {\n
                data[key] = settings.get(key);\n
            });\n
\n
            var stringData = JSON.stringify(data);\n
            cookie.set(\'settings\', stringData);\n
        } catch (ex) {\n
            console.error(\'Unable to JSONify the settings! \' + ex);\n
            return;\n
        }\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("settings:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
/**\n
 * This plug-in manages settings.\n
 *\n
 * <p>Some quick terminology: A _Choice_, is something that the application\n
 * offers as a way to customize how it works. For each _Choice_ there will be\n
 * a number of _Options_ but ultimately the user will have a _Setting_ for each\n
 * _Choice_. This _Setting_ maybe the default for that _Choice_.\n
 *\n
 * <p>It provides an API for controlling the known settings. This allows us to\n
 * provide better GUI/CLI support. See setting.js\n
 * <p>It provides 3 implementations of a setting store:<ul>\n
 * <li>MemorySettings: i.e. temporary, non-persistent. Useful in textarea\n
 * replacement type scenarios. See memory.js\n
 * <li>CookieSettings: Stores the data in a cookie. Generally not practical as\n
 * it slows client server communication (if any). See cookie.js\n
 * <li>ServerSettings: Stores data on a server using the <tt>server</tt> API.\n
 * See server.js\n
 * </ul>\n
 * <p>It is expected that an HTML5 storage option will be developed soon. This\n
 * plug-in did contain a prototype Gears implementation, however this was never\n
 * maintained, and has been deleted due to bit-rot.\n
 * <p>This plug-in also provides commands to manipulate the settings from the\n
 * command_line and canon plug-ins.\n
 *\n
 * <p>TODO:<ul>\n
 * <li>Check what happens when we alter settings from the UI\n
 * <li>Ensure that values can be bound in a SC sense\n
 * <li>Convert all subscriptions to bindings.\n
 * <li>Implement HTML5 storage option\n
 * <li>Make all settings have a \'description\' member and use that in set|unset\n
 * commands.\n
 * <li>When the command system is re-worked to include more GUI interaction,\n
 * expose data in settings to that system.\n
 * </ul>\n
 *\n
 * <p>For future versions of the API it might be better to decrease the\n
 * dependency on settings, and increase it on the system with a setting.\n
 * e.g. Now:\n
 * <pre>\n
 * setting.addSetting({ name:\'foo\', ... });\n
 * settings.set(\'foo\', \'bar\');\n
 * </pre>\n
 * <p>Vs the potentially better:\n
 * <pre>\n
 * var foo = setting.addSetting({ name:\'foo\', ... });\n
 * foo.value = \'bar\';\n
 * </pre>\n
 * <p>Comparison:\n
 * <ul>\n
 * <li>The latter version gains by forcing access to the setting to be through\n
 * the plug-in providing it, so there wouldn\'t be any hidden dependencies.\n
 * <li>It\'s also more compact.\n
 * <li>It could provide access to to other methods e.g. <tt>foo.reset()</tt>\n
 * and <tt>foo.onChange(function(val) {...});</tt> (but see SC binding)\n
 * <li>On the other hand dependencies are so spread out right now that it\'s\n
 * probably hard to do this easily. We should move to this in the future.\n
 * </ul>\n
 */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var console = require(\'bespin:console\').console;\n
var Promise = require(\'bespin:promise\').Promise;\n
var groupPromises = require(\'bespin:promise\').group;\n
\n
var types = require(\'types:types\');\n
\n
/**\n
 * Find and configure the settings object.\n
 * @see MemorySettings.addSetting()\n
 */\n
exports.addSetting = function(settingExt) {\n
    require(\'settings\').settings.addSetting(settingExt);\n
};\n
\n
/**\n
 * Fetch an array of the currently known settings\n
 */\n
exports.getSettings = function() {\n
    return catalog.getExtensions(\'setting\');\n
};\n
\n
/**\n
 * Something of a hack to allow the set command to give a clearer definition\n
 * of the type to the command line.\n
 */\n
exports.getTypeSpecFromAssignment = function(typeSpec) {\n
    var assignments = typeSpec.assignments;\n
    var replacement = \'text\';\n
\n
    if (assignments) {\n
        // Find the assignment for \'setting\' so we can get it\'s value\n
        var settingAssignment = null;\n
        assignments.forEach(function(assignment) {\n
            if (assignment.param.name === \'setting\') {\n
                settingAssignment = assignment;\n
            }\n
        });\n
\n
        if (settingAssignment) {\n
            var settingName = settingAssignment.value;\n
            if (settingName && settingName !== \'\') {\n
                var settingExt = catalog.getExtensionByKey(\'setting\', settingName);\n
                if (settingExt) {\n
                    replacement = settingExt.type;\n
                }\n
            }\n
        }\n
    }\n
\n
    return replacement;\n
};\n
\n
/**\n
 * A base class for all the various methods of storing settings.\n
 * <p>Usage:\n
 * <pre>\n
 * // Create manually, or require \'settings\' from the container.\n
 * // This is the manual version:\n
 * var settings = require(\'bespin:plugins\').catalog.getObject(\'settings\');\n
 * // Add a new setting\n
 * settings.addSetting({ name:\'foo\', ... });\n
 * // Display the default value\n
 * alert(settings.get(\'foo\'));\n
 * // Alter the value, which also publishes the change etc.\n
 * settings.set(\'foo\', \'bar\');\n
 * // Reset the value to the default\n
 * settings.resetValue(\'foo\');\n
 * </pre>\n
 * @class\n
 */\n
exports.MemorySettings = function() {\n
};\n
\n
exports.MemorySettings.prototype = {\n
    /**\n
     * Storage for the setting values\n
     */\n
    _values: {},\n
\n
    /**\n
     * Storage for deactivated values\n
     */\n
    _deactivated: {},\n
\n
    /**\n
     * A Persister is able to store settings. It is an object that defines\n
     * two functions:\n
     * loadInitialValues(settings) and persistValue(settings, key, value).\n
     */\n
    setPersister: function(persister) {\n
        this._persister = persister;\n
        if (persister) {\n
            persister.loadInitialValues(this);\n
        }\n
    },\n
\n
    /**\n
     * Read accessor\n
     */\n
    get: function(key) {\n
        return this._values[key];\n
    },\n
\n
    /**\n
     * Override observable.set(key, value) to provide type conversion and\n
     * validation.\n
     */\n
    set: function(key, value) {\n
        var settingExt = catalog.getExtensionByKey(\'setting\', key);\n
        if (!settingExt) {\n
            // If there is no definition for this setting, then warn the user\n
            // and store the setting in raw format. If the setting gets defined,\n
            // the addSetting() function is called which then takes up the\n
            // here stored setting and calls set() to convert the setting.\n
            console.warn(\'Setting not defined: \', key, value);\n
            this._deactivated[key] = value;\n
        }\n
        else if (typeof value == \'string\' && settingExt.type == \'string\') {\n
            // no conversion needed\n
            this._values[key] = value;\n
        }\n
        else {\n
            var inline = false;\n
\n
            types.fromString(value, settingExt.type).then(function(converted) {\n
                inline = true;\n
                this._values[key] = converted;\n
\n
                // Inform subscriptions of the change\n
                catalog.publish(this, \'settingChange\', key, converted);\n
            }.bind(this), function(ex) {\n
                console.error(\'Error setting\', key, \': \', ex);\n
            });\n
\n
            if (!inline) {\n
                console.warn(\'About to set string version of \', key, \'delaying typed set.\');\n
                this._values[key] = value;\n
            }\n
        }\n
\n
        this._persistValue(key, value);\n
        return this;\n
    },\n
\n
    /**\n
     * Function to add to the list of available settings.\n
     * <p>Example usage:\n
     * <pre>\n
     * var settings = require(\'bespin:plugins\').catalog.getObject(\'settings\');\n
     * settings.addSetting({\n
     *     name: \'tabsize\', // For use in settings.get(\'X\')\n
     *     type: \'number\',  // To allow value checking.\n
     *     defaultValue: 4  // Default value for use when none is directly set\n
     * });\n
     * </pre>\n
     * @param {object} settingExt Object containing name/type/defaultValue members.\n
     */\n
    addSetting: function(settingExt) {\n
        if (!settingExt.name) {\n
            console.error(\'Setting.name == undefined. Ignoring.\', settingExt);\n
            return;\n
        }\n
\n
        if (!settingExt.defaultValue === undefined) {\n
            console.error(\'Setting.defaultValue == undefined\', settingExt);\n
        }\n
\n
        types.isValid(settingExt.defaultValue, settingExt.type).then(function(valid) {\n
            if (!valid) {\n
                console.warn(\'!Setting.isValid(Setting.defaultValue)\', settingExt);\n
            }\n
\n
            // The value can be\n
            // 1) the value of a setting that is not activated at the moment\n
            //       OR\n
            // 2) the defaultValue of the setting.\n
            var value = this._deactivated[settingExt.name] ||\n
                    settingExt.defaultValue;\n
\n
            // Set the default value up.\n
            this.set(settingExt.name, value);\n
        }.bind(this), function(ex) {\n
            console.error(\'Type error \', ex, \' ignoring setting \', settingExt);\n
        });\n
    },\n
\n
    /**\n
     * Reset the value of the <code>key</code> setting to it\'s default\n
     */\n
    resetValue: function(key) {\n
        var settingExt = catalog.getExtensionByKey(\'setting\', key);\n
        if (settingExt) {\n
            this.set(key, settingExt.defaultValue);\n
        } else {\n
            console.log(\'ignore resetValue on \', key);\n
        }\n
    },\n
\n
    resetAll: function() {\n
        this._getSettingNames().forEach(function(key) {\n
            this.resetValue(key);\n
        }.bind(this));\n
    },\n
\n
    /**\n
     * Make a list of the valid type names\n
     */\n
    _getSettingNames: function() {\n
        var typeNames = [];\n
        catalog.getExtensions(\'setting\').forEach(function(settingExt) {\n
            typeNames.push(settingExt.name);\n
        });\n
        return typeNames;\n
    },\n
\n
    /**\n
     * Retrieve a list of the known settings and their values\n
     */\n
    _list: function() {\n
        var reply = [];\n
        this._getSettingNames().forEach(function(setting) {\n
            reply.push({\n
                \'key\': setting,\n
                \'value\': this.get(setting)\n
            });\n
        }.bind(this));\n
        return reply;\n
    },\n
\n
    /**\n
     * delegates to the persister. no-op if there\'s no persister.\n
     */\n
    _persistValue: function(key, value) {\n
        var persister = this._persister;\n
        if (persister) {\n
            persister.persistValue(this, key, value);\n
        }\n
    },\n
\n
    /**\n
     * Delegates to the persister, otherwise sets up the defaults if no\n
     * persister is available.\n
     */\n
    _loadInitialValues: function() {\n
        var persister = this._persister;\n
        if (persister) {\n
            persister.loadInitialValues(this);\n
        } else {\n
            this._loadDefaultValues();\n
        }\n
    },\n
\n
    /**\n
     * Prime the local cache with the defaults.\n
     */\n
    _loadDefaultValues: function() {\n
        return this._loadFromObject(this._defaultValues());\n
    },\n
\n
    /**\n
     * Utility to load settings from an object\n
     */\n
    _loadFromObject: function(data) {\n
        var promises = [];\n
        // take the promise action out of the loop to avoid closure problems\n
        var setterFactory = function(keyName) {\n
            return function(value) {\n
                this.set(keyName, value);\n
            };\n
        };\n
\n
        for (var key in data) {\n
            if (data.hasOwnProperty(key)) {\n
                var valueStr = data[key];\n
                var settingExt = catalog.getExtensionByKey(\'setting\', key);\n
                if (settingExt) {\n
                    // TODO: We shouldn\'t just ignore values without a setting\n
                    var promise = types.fromString(valueStr, settingExt.type);\n
                    var setter = setterFactory(key);\n
                    promise.then(setter);\n
                    promises.push(promise);\n
                }\n
            }\n
        }\n
\n
        // Promise.group (a.k.a groupPromises) gives you a list of all the data\n
        // in the grouped promises. We don\'t want that in case we change how\n
        // this works with ignored settings (see above).\n
        // So we do this to hide the list of promise resolutions.\n
        var replyPromise = new Promise();\n
        groupPromises(promises).then(function() {\n
            replyPromise.resolve();\n
        });\n
        return replyPromise;\n
    },\n
\n
    /**\n
     * Utility to grab all the settings and export them into an object\n
     */\n
    _saveToObject: function() {\n
        var promises = [];\n
        var reply = {};\n
\n
        this._getSettingNames().forEach(function(key) {\n
            var value = this.get(key);\n
            var settingExt = catalog.getExtensionByKey(\'setting\', key);\n
            if (settingExt) {\n
                // TODO: We shouldn\'t just ignore values without a setting\n
                var promise = types.toString(value, settingExt.type);\n
                promise.then(function(value) {\n
                    reply[key] = value;\n
                });\n
                promises.push(promise);\n
            }\n
        }.bind(this));\n
\n
        var replyPromise = new Promise();\n
        groupPromises(promises).then(function() {\n
            replyPromise.resolve(reply);\n
        });\n
        return replyPromise;\n
    },\n
\n
    /**\n
     * The default initial settings\n
     */\n
    _defaultValues: function() {\n
        var defaultValues = {};\n
        catalog.getExtensions(\'setting\').forEach(function(settingExt) {\n
            defaultValues[settingExt.name] = settingExt.defaultValue;\n
        });\n
        return defaultValues;\n
    }\n
};\n
\n
exports.settings = new exports.MemorySettings();\n
\n
});\n
;bespin.tiki.register("::canon", {\n
    name: "canon",\n
    dependencies: { "environment": "0.0.0", "events": "0.0.0", "settings": "0.0.0" }\n
});\n
bespin.tiki.module("canon:history",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Trace = require(\'bespin:util/stacktrace\').Trace;\n
var catalog = require(\'bespin:plugins\').catalog;\n
\n
/**\n
 * Current requirements are around displaying the command line, and provision\n
 * of a \'history\' command and cursor up|down navigation of history.\n
 * <p>Future requirements could include:\n
 * <ul>\n
 * <li>Multiple command lines\n
 * <li>The ability to recall key presses (i.e. requests with no output) which\n
 * will likely be needed for macro recording or similar\n
 * <li>The ability to store the command history either on the server or in the\n
 * browser local storage.\n
 * </ul>\n
 * <p>The execute() command doesn\'t really live here, except as part of that\n
 * last future requirement, and because it doesn\'t really have anywhere else to\n
 * live.\n
 */\n
\n
/**\n
 * The array of requests that wish to announce their presence\n
 */\n
exports.requests = [];\n
\n
/**\n
 * How many requests do we store?\n
 */\n
var maxRequestLength = 100;\n
\n
/**\n
 * Called by Request instances when some output (or a cell to async() happens)\n
 */\n
exports.addRequestOutput = function(request) {\n
    exports.requests.push(request);\n
    // This could probably be optimized with some maths, but 99.99% of the\n
    // time we will only be off by one, and I\'m feeling lazy.\n
    while (exports.requests.length > maxRequestLength) {\n
        exports.requests.shiftObject();\n
    }\n
\n
    catalog.publish(this, \'addedRequestOutput\', null, request);\n
};\n
\n
/**\n
 * Execute a new command.\n
 * This is basically an error trapping wrapper around request.command(...)\n
 */\n
exports.execute = function(args, request) {\n
    // Check the function pointed to in the meta-data exists\n
    if (!request.command) {\n
        request.doneWithError(\'Command not found.\');\n
        return;\n
    }\n
\n
    try {\n
        request.command(args, request);\n
    } catch (ex) {\n
        var trace = new Trace(ex, true);\n
        console.group(\'Error executing command \\\'\' + request.typed + \'\\\'\');\n
        console.log(\'command=\', request.commandExt);\n
        console.log(\'args=\', args);\n
        console.error(ex);\n
        trace.log(3);\n
        console.groupEnd();\n
\n
        request.doneWithError(ex);\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("canon:request",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var Event = require(\'events\').Event;\n
var history = require(\'canon:history\');\n
\n
/**\n
 * To create an invocation, you need to do something like this (all the ctor\n
 * args are optional):\n
 * <pre>\n
 * var request = new Request({\n
 *     command: command,\n
 *     commandExt: commandExt,\n
 *     args: args,\n
 *     typed: typed\n
 * });\n
 * </pre>\n
 */\n
exports.Request = function(options) {\n
    options = options || {};\n
\n
    // Will be used in the keyboard case and the cli case\n
    this.command = options.command;\n
    this.commandExt = options.commandExt;\n
\n
    // Will be used only in the cli case\n
    this.args = options.args;\n
    this.typed = options.typed;\n
\n
    // Have we been initialized?\n
    this._begunOutput = false;\n
\n
    this.start = new Date();\n
    this.end = null;\n
    this.completed = false;\n
    this.error = false;\n
\n
    this.changed = new Event();\n
};\n
\n
/**\n
 * Lazy init to register with the history should only be done on output.\n
 * init() is expensive, and won\'t be used in the majority of cases\n
 */\n
exports.Request.prototype._beginOutput = function() {\n
    this._begunOutput = true;\n
    this.outputs = [];\n
\n
    history.addRequestOutput(this);\n
};\n
\n
/**\n
 * Sugar for:\n
 * <pre>request.error = true; request.done(output);</pre>\n
 */\n
exports.Request.prototype.doneWithError = function(content) {\n
    this.error = true;\n
    this.done(content);\n
};\n
\n
/**\n
 * Declares that this function will not be automatically done when\n
 * the command exits\n
 */\n
exports.Request.prototype.async = function() {\n
    if (!this._begunOutput) {\n
        this._beginOutput();\n
    }\n
};\n
\n
/**\n
 * Complete the currently executing command with successful output.\n
 * @param output Either DOM node, an SproutCore element or something that\n
 * can be used in the content of a DIV to create a DOM node.\n
 */\n
exports.Request.prototype.output = function(content) {\n
    if (!this._begunOutput) {\n
        this._beginOutput();\n
    }\n
\n
    if (typeof content !== \'string\' && !(content instanceof Node)) {\n
        content = content.toString();\n
    }\n
\n
    this.outputs.push(content);\n
    this.changed();\n
\n
    return this;\n
};\n
\n
/**\n
 * All commands that do output must call this to indicate that the command\n
 * has finished execution.\n
 */\n
exports.Request.prototype.done = function(content) {\n
    this.completed = true;\n
    this.end = new Date();\n
    this.duration = this.end.getTime() - this.start.getTime();\n
\n
    if (content) {\n
        this.output(content);\n
    } else {\n
        this.changed();\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("canon:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::syntax_directory", {\n
    name: "syntax_directory",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("syntax_directory:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
"define metadata";\n
({\n
    "description": "Catalogs the available syntax engines",\n
    "dependencies": {},\n
    "environments": { "main": true, "worker": true },\n
    "provides": [\n
        {\n
            "ep": "extensionhandler",\n
            "name": "syntax",\n
            "register": "#discoveredNewSyntax"\n
        }\n
    ]\n
});\n
"end";\n
\n
var plugins = require("bespin:plugins");\n
\n
function SyntaxInfo(ext) {\n
    this.extension = ext;\n
    this.name = ext.name;\n
    this.fileExts = ext.hasOwnProperty(\'fileexts\') ? ext.fileexts : [];\n
}\n
\n
/**\n
 * Stores metadata for all of the syntax plugins.\n
 *\n
 * @exports syntaxDirectory as syntax_directory:syntaxDirectory\n
 */\n
var syntaxDirectory = {\n
    _fileExts: {},\n
    _syntaxInfo: {},\n
\n
    get: function(syntaxName) {\n
        return this._syntaxInfo[syntaxName];\n
    },\n
\n
    hasSyntax: function(syntax) {\n
        return this._syntaxInfo.hasOwnProperty(syntax);\n
    },\n
\n
    register: function(extension) {\n
        var syntaxInfo = new SyntaxInfo(extension);\n
        this._syntaxInfo[syntaxInfo.name] = syntaxInfo;\n
\n
        var fileExts = this._fileExts;\n
        syntaxInfo.fileExts.forEach(function(fileExt) {\n
            fileExts[fileExt] = syntaxInfo.name;\n
        });\n
    },\n
\n
    syntaxForFileExt: function(fileExt) {\n
        fileExt = fileExt.toLowerCase();\n
        var fileExts = this._fileExts;\n
        return fileExts.hasOwnProperty(fileExt) ? fileExts[fileExt] : \'plain\';\n
    }\n
};\n
\n
function discoveredNewSyntax(syntaxExtension) {\n
    syntaxDirectory.register(syntaxExtension);\n
}\n
\n
exports.syntaxDirectory = syntaxDirectory;\n
exports.discoveredNewSyntax = discoveredNewSyntax;\n
\n
\n
});\n
;bespin.tiki.register("::environment", {\n
    name: "environment",\n
    dependencies: { "settings": "0.0.0" }\n
});\n
bespin.tiki.module("environment:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
"define metadata";\n
({\n
    "dependencies": {\n
        "settings": "0.0.0"\n
    }\n
});\n
"end";\n
\n
var util = require(\'bespin:util/util\');\n
var console = require(\'bespin:console\').console;\n
var catalog = require("bespin:plugins").catalog;\n
var settings = require(\'settings\').settings;\n
\n
/**\n
 * The environment plays a similar role to the environment under unix.\n
 * Bespin does not currently have a concept of variables, (i.e. things the user\n
 * directly changes, however it does have a number of pre-defined things that\n
 * are changed by the system.\n
 * <p>The role of the Environment is likely to be expanded over time.\n
 */\n
exports.Environment = function() {\n
    // The current command line pushes this value into here\n
    this.commandLine = null;\n
\n
    // Fire the sizeChanged event when the window is resized.\n
    window.addEventListener(\'resize\', this.dimensionsChanged.bind(this), false);\n
};\n
\n
Object.defineProperties(exports.Environment.prototype, {\n
\n
    /**\n
     * Provides a get() and set() function to set and get settings.\n
     */\n
    settings: {\n
        value: {\n
            set: function(key, value) {\n
                if (util.none(key)) {\n
                    throw new Error(\'setSetting(): key must be supplied\');\n
                }\n
                if (util.none(value)) {\n
                    throw new Error(\'setSetting(): value must be supplied\');\n
                }\n
\n
                settings.set(key, value);\n
            },\n
            \n
            get: function(key) {\n
                if (util.none(key)) {\n
                    throw new Error(\'getSetting(): key must be supplied\');\n
                }\n
                return settings.get(key);\n
            }\n
        }\n
    },\n
\n
    dimensionsChanged: {\n
        value: function() {\n
            catalog.publish(this, \'dimensionsChanged\');\n
        }\n
    },\n
\n
    /**\n
     * Retrieves the EditSession\n
     */\n
    session: {\n
        get: function() {\n
            return catalog.getObject(\'session\');\n
        }\n
    },\n
\n
    /**\n
     * Gets the currentView from the session.\n
     */\n
    view: {\n
        get: function() {\n
            if (!this.session) {\n
                // This can happen if the session is being reloaded.\n
                return null;\n
            }\n
            return this.session.currentView;\n
        }\n
    },\n
\n
    /**\n
     * Gets the currentEditor from the session.\n
     */\n
    editor: {\n
        get: function() {\n
            if (!this.session) {\n
                // This can happen if the session is being reloaded.\n
                return null;\n
            }\n
            return this.session.currentView.editor;\n
        }\n
    },\n
\n
    /**\n
     * Returns the currently-active syntax contexts.\n
     */\n
    contexts: {\n
        get: function() {\n
            // when editorapp is being refreshed, the textView is not available.\n
            if (!this.view) {\n
                return [];\n
            }\n
\n
            var syntaxManager = this.view.editor.layoutManager.syntaxManager;\n
            var pos = this.view.getSelectedRange().start;\n
            return syntaxManager.contextsAtPosition(pos);\n
        }\n
    },\n
\n
    /**\n
     * The current Buffer from the session\n
     */\n
    buffer: {\n
        get: function() {\n
            if (!this.session) {\n
                console.error("command attempted to get buffer but there\'s no session");\n
                return undefined;\n
            }\n
            return this.view.editor.buffer;\n
        }\n
    },\n
\n
    /**\n
     * The current editor model might not always be easy to find so you should\n
     * use <code>instruction.model</code> to access the view where\n
     * possible.\n
     */\n
    model: {\n
        get: function() {\n
            if (!this.buffer) {\n
                console.error(\'Session has no current buffer\');\n
                return undefined;\n
            }\n
            return this.view.editor.layoutManager.textStorage;\n
        }\n
    },\n
\n
    /**\n
     * gets the current file from the session\n
     */\n
    file: {\n
        get: function() {\n
            if (!this.buffer) {\n
                console.error(\'Session has no current buffer\');\n
                return undefined;\n
            }\n
            return this.buffer.file;\n
        }\n
    },\n
\n
    /**\n
     * If files are available, this will get them. Perhaps we need some other\n
     * mechanism for populating these things from the catalog?\n
     */\n
    files: {\n
        get: function() {\n
            return catalog.getObject(\'files\');\n
        }\n
    }\n
});\n
\n
/**\n
 * The global environment used throughout this Bespin instance.\n
 */\n
exports.env = new exports.Environment();\n
\n
});\n
;bespin.tiki.register("::traits", {\n
    name: "traits",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("traits:index",function(require,exports,module) {\n
// Copyright (C) 2010 Google Inc.\n
//\n
// Licensed under the Apache License, Version 2.0 (the "License");\n
// you may not use this file except in compliance with the License.\n
// You may obtain a copy of the License at\n
//\n
// http://www.apache.org/licenses/LICENSE-2.0\n
//\n
// Unless required by applicable law or agreed to in writing, software\n
// distributed under the License is distributed on an "AS IS" BASIS,\n
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n
// See the License for the specific language governing permissions and\n
// limitations under the License.\n
\n
// See http://code.google.com/p/es-lab/wiki/Traits\n
// for background on traits and a description of this library\n
\n
"define metadata";\n
({\n
    "description": "Traits library, traitsjs.org",\n
    "dependencies": {},\n
    "provides": []\n
});\n
"end";\n
\n
// --- Begin traits-0.1.js ---\n
\n
exports.Trait = (function(){\n
\n
  // == Ancillary functions ==\n
  \n
  // this signals that the current ES implementation supports properties,\n
  // so probably also accessor properties\n
  var SUPPORTS_DEFINEPROP = !!Object.defineProperty;\n
\n
  var call = Function.prototype.call;\n
\n
  /**\n
   * An ad hoc version of bind that only binds the \'this\' parameter.\n
   */\n
  var bindThis = Function.prototype.bind\n
    ? function(fun, self) { return Function.prototype.bind.call(fun, self); }\n
    : function(fun, self) {\n
        function funcBound(var_args) {\n
          return fun.apply(self, arguments);\n
        }\n
        return funcBound;\n
      };\n
\n
  var hasOwnProperty = bindThis(call, Object.prototype.hasOwnProperty);\n
  var slice = bindThis(call, Array.prototype.slice);\n
    \n
  // feature testing such that traits.js runs on both ES3 and ES5\n
  var forEach = Array.prototype.forEach\n
      ? bindThis(call, Array.prototype.forEach)\n
      : function(arr, fun) {\n
          for (var i = 0, len = arr.length; i < len; i++) { fun(arr[i]); }\n
        };\n
      \n
  var freeze = Object.freeze || function(obj) { return obj; };\n
  var getPrototypeOf = Object.getPrototypeOf || function(obj) { return Object.prototype };\n
  var getOwnPropertyNames = Object.getOwnPropertyNames ||\n
      function(obj) {\n
        var props = [];\n
        for (var p in obj) { if (hasOwnProperty(obj,p)) { props.push(p); } }\n
        return props;\n
      };\n
  var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor ||\n
      function(obj, name) {\n
        return {\n
          value: obj[name],\n
          enumerable: true,\n
          writable: true,\n
          configurable: true\n
        };\n
      };\n
  var defineProperty = Object.defineProperty ||\n
      function(obj, name, pd) {\n
        obj[name] = pd.value;\n
      };\n
  var defineProperties = Object.defineProperties ||\n
      function(obj, propMap) {\n
        for (var name in propMap) {\n
          if (hasOwnProperty(propMap, name)) {\n
            defineProperty(obj, name, propMap[name]);\n
          }\n
        }\n
      };\n
  var Object_create = Object.create ||\n
      function(proto, propMap) {\n
        var self;\n
        function dummy() {};\n
        dummy.prototype = proto || Object.prototype;\n
        self = new dummy();\n
        if (propMap) {\n
          defineProperties(self, propMap);          \n
        }\n
        return self;\n
      };\n
  var getOwnProperties = Object.getOwnProperties ||\n
      function(obj) {\n
        var map = {};\n
        forEach(getOwnPropertyNames(obj), function (name) {\n
          map[name] = getOwnPropertyDescriptor(obj, name);\n
        });\n
        return map;\n
      };\n
  \n
  // end of ES3 - ES5 compatibility functions\n
  \n
  function makeConflictAccessor(name) {\n
    var accessor = function(var_args) {\n
      throw new Error("Conflicting property: "+name);\n
    };\n
    freeze(accessor.prototype);\n
    return freeze(accessor);\n
  };\n
\n
  function makeRequiredPropDesc(name) {\n
    return freeze({\n
      value: undefined,\n
      enumerable: false,\n
      required: true\n
    });\n
  }\n
  \n
  function makeConflictingPropDesc(name) {\n
    var conflict = makeConflictAccessor(name);\n
    if (SUPPORTS_DEFINEPROP) {\n
      return freeze({\n
       get: conflict,\n
       set: conflict,\n
       enumerable: false,\n
       conflict: true\n
      }); \n
    } else {\n
      return freeze({\n
        value: conflict,\n
        enumerable: false,\n
        conflict: true\n
      });\n
    }\n
  }\n
  \n
  /**\n
   * Are x and y not observably distinguishable?\n
   */\n
  function identical(x, y) {\n
    if (x === y) {\n
      // 0 === -0, but they are not identical\n
      return x !== 0 || 1/x === 1/y;\n
    } else {\n
      // NaN !== NaN, but they are identical.\n
      // NaNs are the only non-reflexive value, i.e., if x !== x,\n
      // then x is a NaN.\n
      return x !== x && y !== y;\n
    }\n
  }\n
\n
  // Note: isSameDesc should return true if both\n
  // desc1 and desc2 represent a \'required\' property\n
  // (otherwise two composed required properties would be turned into a conflict)\n
  function isSameDesc(desc1, desc2) {\n
    // for conflicting properties, don\'t compare values because\n
    // the conflicting property values are never equal\n
    if (desc1.conflict && desc2.conflict) {\n
      return true;\n
    } else {\n
      return (   desc1.get === desc2.get\n
              && desc1.set === desc2.set\n
              && identical(desc1.value, desc2.value)\n
              && desc1.enumerable === desc2.enumerable\n
              && desc1.required === desc2.required\n
              && desc1.conflict === desc2.conflict); \n
    }\n
  }\n
  \n
  function freezeAndBind(meth, self) {\n
    return freeze(bindThis(meth, self));\n
  }\n
\n
  /* makeSet([\'foo\', ...]) => { foo: true, ...}\n
   *\n
   * makeSet returns an object whose own properties represent a set.\n
   *\n
   * Each string in the names array is added to the set.\n
   *\n
   * To test whether an element is in the set, perform:\n
   *   hasOwnProperty(set, element)\n
   */\n
  function makeSet(names) {\n
    var set = {};\n
    forEach(names, function (name) {\n
      set[name] = true;\n
    });\n
    return freeze(set);\n
  }\n
\n
  // == singleton object to be used as the placeholder for a required property ==\n
  \n
  var required = freeze({ toString: function() { return \'<Trait.required>\'; } });\n
\n
  // == The public API methods ==\n
\n
  /**\n
   * var newTrait = trait({ foo:required, ... })\n
   *\n
   * @param object an object record (in principle an object literal)\n
   * @returns a new trait describing all of the own properties of the object\n
   *          (both enumerable and non-enumerable)\n
   *\n
   * As a general rule, \'trait\' should be invoked with an\n
   * object literal, since the object merely serves as a record\n
   * descriptor. Both its identity and its prototype chain are irrelevant.\n
   * \n
   * Data properties bound to function objects in the argument will be flagged\n
   * as \'method\' properties. The prototype of these function objects is frozen.\n
   * \n
   * Data properties bound to the \'required\' singleton exported by this module\n
   * will be marked as \'required\' properties.\n
   *\n
   * The <tt>trait</tt> function is pure if no other code can witness the\n
   * side-effects of freezing the prototypes of the methods. If <tt>trait</tt>\n
   * is invoked with an object literal whose methods are represented as\n
   * in-place anonymous functions, this should normally be the case.\n
   */\n
  function trait(obj) {\n
    var map = {};\n
    forEach(getOwnPropertyNames(obj), function (name) {\n
      var pd = getOwnPropertyDescriptor(obj, name);\n
      if (pd.value === required) {\n
        pd = makeRequiredPropDesc(name);\n
      } else if (typeof pd.value === \'function\') {\n
        pd.method = true;\n
        if (\'prototype\' in pd.value) {\n
          freeze(pd.value.prototype);\n
        }\n
      } else {\n
        if (pd.get && pd.get.prototype) { freeze(pd.get.prototype); }\n
        if (pd.set && pd.set.prototype) { freeze(pd.set.prototype); }\n
      }\n
      map[name] = pd;\n
    });\n
    return map;\n
  }\n
\n
  /**\n
   * var newTrait = compose(trait_1, trait_2, ..., trait_N)\n
   *\n
   * @param trait_i a trait object\n
   * @returns a new trait containing the combined own properties of\n
   *          all the trait_i.\n
   * \n
   * If two or more traits have own properties with the same name, the new\n
   * trait will contain a \'conflict\' property for that name. \'compose\' is\n
   * a commutative and associative operation, and the order of its\n
   * arguments is not significant.\n
   *\n
   * If \'compose\' is invoked with < 2 arguments, then:\n
   *   compose(trait_1) returns a trait equivalent to trait_1\n
   *   compose() returns an empty trait\n
   */\n
  function compose(var_args) {\n
    var traits = slice(arguments, 0);\n
    var newTrait = {};\n
    \n
    forEach(traits, function (trait) {\n
      forEach(getOwnPropertyNames(trait), function (name) {\n
        var pd = trait[name];\n
        if (hasOwnProperty(newTrait, name) &&\n
            !newTrait[name].required) {\n
          \n
          // a non-required property with the same name was previously defined\n
          // this is not a conflict if pd represents a \'required\' property itself:\n
          if (pd.required) {\n
            return; // skip this property, the required property is now present\n
          }\n
            \n
          if (!isSameDesc(newTrait[name], pd)) {\n
            // a distinct, non-required property with the same name\n
            // was previously defined by another trait => mark as conflicting property\n
            newTrait[name] = makeConflictingPropDesc(name); \n
          } // else,\n
          // properties are not in conflict if they refer to the same value\n
          \n
        } else {\n
          newTrait[name] = pd;\n
        }\n
      });\n
    });\n
    \n
    return freeze(newTrait);\n
  }\n
\n
  /* var newTrait = exclude([\'name\', ...], trait)\n
   *\n
   * @param names a list of strings denoting property names.\n
   * @param trait a trait some properties of which should be excluded.\n
   * @returns a new trait with the same own properties as the original trait,\n
   *          except that all property names appearing in the first argument\n
   *          are replaced by required property descriptors.\n
   *\n
   * Note: exclude(A, exclude(B,t)) is equivalent to exclude(A U B, t)\n
   */\n
  function exclude(names, trait) {\n
    var exclusions = makeSet(names);\n
    var newTrait = {};\n
    \n
    forEach(getOwnPropertyNames(trait), function (name) {\n
      // required properties are not excluded but ignored\n
      if (!hasOwnProperty(exclusions, name) || trait[name].required) {\n
        newTrait[name] = trait[name];\n
      } else {\n
        // excluded properties are replaced by required properties\n
        newTrait[name] = makeRequiredPropDesc(name);\n
      }\n
    });\n
    \n
    return freeze(newTrait);\n
  }\n
\n
  /**\n
   * var newTrait = override(trait_1, trait_2, ..., trait_N)\n
   *\n
   * @returns a new trait with all of the combined properties of the argument traits.\n
   *          In contrast to \'compose\', \'override\' immediately resolves all conflicts\n
   *          resulting from this composition by overriding the properties of later\n
   *          traits. Trait priority is from left to right. I.e. the properties of the\n
   *          leftmost trait are never overridden.\n
   *\n
   *  override is associative:\n
   *    override(t1,t2,t3) is equivalent to override(t1, override(t2, t3)) or\n
   *    to override(override(t1, t2), t3)\n
   *  override is not commutative: override(t1,t2) is not equivalent to override(t2,t1)\n
   *\n
   * override() returns an empty trait\n
   * override(trait_1) returns a trait equivalent to trait_1\n
   */\n
  function override(var_args) {\n
    var traits = slice(arguments, 0);\n
    var newTrait = {};\n
    forEach(traits, function (trait) {\n
      forEach(getOwnPropertyNames(trait), function (name) {\n
        var pd = trait[name];\n
        // add this trait\'s property to the composite trait only if\n
        // - the trait does not yet have this property\n
        // - or, the trait does have the property, but it\'s a required property\n
        if (!hasOwnProperty(newTrait, name) || newTrait[name].required) {\n
          newTrait[name] = pd;\n
        }\n
      });\n
    });\n
    return freeze(newTrait);\n
  }\n
  \n
  /**\n
   * var newTrait = override(dominantTrait, recessiveTrait)\n
   *\n
   * @returns a new trait with all of the properties of dominantTrait\n
   *          and all of the properties of recessiveTrait not in dominantTrait\n
   *\n
   * Note: override is associative:\n
   *   override(t1, override(t2, t3)) is equivalent to override(override(t1, t2), t3)\n
   */\n
  /*function override(frontT, backT) {\n
    var newTrait = {};\n
    // first copy all of backT\'s properties into newTrait\n
    forEach(getOwnPropertyNames(backT), function (name) {\n
      newTrait[name] = backT[name];\n
    });\n
    // now override all these properties with frontT\'s properties\n
    forEach(getOwnPropertyNames(frontT), function (name) {\n
      var pd = frontT[name];\n
      // frontT\'s required property does not override the provided property\n
      if (!(pd.required && hasOwnProperty(newTrait, name))) {\n
        newTrait[name] = pd; \n
      }      \n
    });\n
    \n
    return freeze(newTrait);\n
  }*/\n
\n
  /**\n
   * var newTrait = rename(map, trait)\n
   *\n
   * @param map an object whose own properties serve as a mapping from\n
            old names to new names.\n
   * @param trait a trait object\n
   * @returns a new trait with the same properties as the original trait,\n
   *          except that all properties whose name is an own property\n
   *          of map will be renamed to map[name], and a \'required\' property\n
   *          for name will be added instead.\n
   *\n
   * rename({a: \'b\'}, t) eqv compose(exclude([\'a\'],t),\n
   *                                 { a: { required: true },\n
   *                                   b: t[a] })\n
   *\n
   * For each renamed property, a required property is generated.\n
   * If the map renames two properties to the same name, a conflict is generated.\n
   * If the map renames a property to an existing unrenamed property, a conflict is generated.\n
   *\n
   * Note: rename(A, rename(B, t)) is equivalent to rename(\\n -> A(B(n)), t)\n
   * Note: rename({...},exclude([...], t)) is not eqv to exclude([...],rename({...}, t))\n
   */\n
  function rename(map, trait) {\n
    var renamedTrait = {};\n
    forEach(getOwnPropertyNames(trait), function (name) {\n
      // required props are never renamed\n
      if (hasOwnProperty(map, name) && !trait[name].required) {\n
        var alias = map[name]; // alias defined in map\n
        if (hasOwnProperty(renamedTrait, alias) && !renamedTrait[alias].required) {\n
          // could happen if 2 props are mapped to the same alias\n
          renamedTrait[alias] = makeConflictingPropDesc(alias);\n
        } else {\n
          // add the property under an alias\n
          renamedTrait[alias] = trait[name];\n
        }\n
        // add a required property under the original name\n
        // but only if a property under the original name does not exist\n
        // such a prop could exist if an earlier prop in the trait was previously\n
        // aliased to this name\n
        if (!hasOwnProperty(renamedTrait, name)) {\n
          renamedTrait[name] = makeRequiredPropDesc(name);     \n
        }\n
      } else { // no alias defined\n
        if (hasOwnProperty(renamedTrait, name)) {\n
          // could happen if another prop was previously aliased to name\n
          if (!trait[name].required) {\n
            renamedTrait[name] = makeConflictingPropDesc(name);            \n
          }\n
          // else required property overridden by a previously aliased property\n
          // and otherwise ignored\n
        } else {\n
          renamedTrait[name] = trait[name];\n
        }\n
      }\n
    });\n
    \n
    return freeze(renamedTrait);\n
  }\n
  \n
  /**\n
   * var newTrait = resolve({ oldName: \'newName\', excludeName: undefined, ... }, trait)\n
   *\n
   * This is a convenience function combining renaming and exclusion. It can be implemented\n
   * as <tt>rename(map, exclude(exclusions, trait))</tt> where map is the subset of\n
   * mappings from oldName to newName and exclusions is an array of all the keys that map\n
   * to undefined (or another falsy value).\n
   *\n
   * @param resolutions an object whose own properties serve as a mapping from\n
            old names to new names, or to undefined if the property should be excluded\n
   * @param trait a trait object\n
   * @returns a resolved trait with the same own properties as the original trait.\n
   *\n
   * In a resolved trait, all own properties whose name is an own property\n
   * of resolutions will be renamed to resolutions[name] if it is truthy,\n
   * or their value is changed into a required property descriptor if\n
   * resolutions[name] is falsy.\n
   *\n
   * Note, it\'s important to _first_ exclude, _then_ rename, since exclude\n
   * and rename are not associative, for example:\n
   * rename({a: \'b\'}, exclude([\'b\'], trait({ a:1,b:2 }))) eqv trait({b:1})\n
   * exclude([\'b\'], rename({a: \'b\'}, trait({ a:1,b:2 }))) eqv trait({b:Trait.required})\n
   *\n
   * writing resolve({a:\'b\', b: undefined},trait({a:1,b:2})) makes it clear that\n
   * what is meant is to simply drop the old \'b\' and rename \'a\' to \'b\'\n
   */\n
  function resolve(resolutions, trait) {\n
    var renames = {};\n
    var exclusions = [];\n
    // preprocess renamed and excluded properties\n
    for (var name in resolutions) {\n
      if (hasOwnProperty(resolutions, name)) {\n
        if (resolutions[name]) { // old name -> new name\n
          renames[name] = resolutions[name];\n
        } else { // name -> undefined\n
          exclusions.push(name);\n
        }\n
      }\n
    }\n
    return rename(renames, exclude(exclusions, trait));\n
  }\n
\n
  /**\n
   * var obj = create(proto, trait)\n
   *\n
   * @param proto denotes the prototype of the completed object\n
   * @param trait a trait object to be turned into a complete object\n
   * @returns an object with all of the properties described by the trait.\n
   * @throws \'Missing required property\' the trait still contains a required property.\n
   * @throws \'Remaining conflicting property\' if the trait still contains a conflicting property.\n
   *\n
   * Trait.create is like Object.create, except that it generates\n
   * high-integrity or final objects. In addition to creating a new object\n
   * from a trait, it also ensures that:\n
   *    - an exception is thrown if \'trait\' still contains required properties\n
   *    - an exception is thrown if \'trait\' still contains conflicting properties\n
   *    - the object is and all of its accessor and method properties are frozen\n
   *    - the \'this\' pseudovariable in all accessors and methods of the object is\n
   *      bound to the composed object.\n
   *\n
   *  Use Object.create instead of Trait.create if you want to create\n
   *  abstract or malleable objects. Keep in mind that for such objects:\n
   *    - no exception is thrown if \'trait\' still contains required properties\n
   *      (the properties are simply dropped from the composite object)\n
   *    - no exception is thrown if \'trait\' still contains conflicting properties\n
   *      (these properties remain as conflicting properties in the composite object)\n
   *    - neither the object nor its accessor and method properties are frozen\n
   *    - the \'this\' pseudovariable in all accessors and methods of the object is\n
   *      left unbound.\n
   */\n
  function create(proto, trait) {\n
    var self = Object_create(proto);\n
    var properties = {};\n
  \n
    forEach(getOwnPropertyNames(trait), function (name) {\n
      var pd = trait[name];\n
      // check for remaining \'required\' properties\n
      // Note: it\'s OK for the prototype to provide the properties\n
      if (pd.required && !(name in proto)) {\n
        throw new Error(\'Missing required property: \'+name);\n
      } else if (pd.conflict) { // check for remaining conflicting properties\n
        throw new Error(\'Remaining conflicting property: \'+name);\n
      } else if (\'value\' in pd) { // data property\n
        // freeze all function properties and their prototype\n
        if (pd.method) { // the property is meant to be used as a method\n
          // bind \'this\' in trait method to the composite object\n
          properties[name] = {\n
            value: freezeAndBind(pd.value, self),\n
            enumerable: pd.enumerable,\n
            configurable: pd.configurable,\n
            writable: pd.writable\n
          };\n
        } else {\n
          properties[name] = pd;\n
        }\n
      } else { // accessor property\n
        properties[name] = {\n
          get: pd.get ? freezeAndBind(pd.get, self) : undefined,\n
          set: pd.set ? freezeAndBind(pd.set, self) : undefined,\n
          enumerable: pd.enumerable,\n
          configurable: pd.configurable,\n
          writable: pd.writable            \n
        };\n
      }\n
    });\n
\n
    defineProperties(self, properties);\n
    return freeze(self);\n
  }\n
\n
  /** A shorthand for create(Object.prototype, trait({...}), options) */\n
  function object(record, options) {\n
    return create(Object.prototype, trait(record), options);\n
  }\n
\n
  /**\n
   * Tests whether two traits are equivalent. T1 is equivalent to T2 iff\n
   * both describe the same set of property names and for all property\n
   * names n, T1[n] is equivalent to T2[n]. Two property descriptors are\n
   * equivalent if they have the same value, accessors and attributes.\n
   *\n
   * @return a boolean indicating whether the two argument traits are equivalent.\n
   */\n
  function eqv(trait1, trait2) {\n
    var names1 = getOwnPropertyNames(trait1);\n
    var names2 = getOwnPropertyNames(trait2);\n
    var name;\n
    if (names1.length !== names2.length) {\n
      return false;\n
    }\n
    for (var i = 0; i < names1.length; i++) {\n
      name = names1[i];\n
      if (!trait2[name] || !isSameDesc(trait1[name], trait2[name])) {\n
        return false;\n
      }\n
    }\n
    return true;\n
  }\n
  \n
  // if this code is ran in ES3 without an Object.create function, this\n
  // library will define it on Object:\n
  if (!Object.create) {\n
    Object.create = Object_create;\n
  }\n
  // ES5 does not by default provide Object.getOwnProperties\n
  // if it\'s not defined, the Traits library defines this utility function on Object\n
  if(!Object.getOwnProperties) {\n
    Object.getOwnProperties = getOwnProperties;\n
  }\n
  \n
  // expose the public API of this module\n
  function Trait(record) {\n
    // calling Trait as a function creates a new atomic trait\n
    return trait(record);\n
  }\n
  Trait.required = freeze(required);\n
  Trait.compose = freeze(compose);\n
  Trait.resolve = freeze(resolve);\n
  Trait.override = freeze(override);\n
  Trait.create = freeze(create);\n
  Trait.eqv = freeze(eqv);\n
  Trait.object = freeze(object); // not essential, cf. create + trait\n
  return freeze(Trait);\n
  \n
})();\n
\n
// --- End traits-0.1.js ---\n
\n
\n
});\n
;bespin.tiki.register("::underscore", {\n
    name: "underscore",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("underscore:index",function(require,exports,module) {\n
// Underscore.js\n
// (c) 2010 Jeremy Ashkenas, DocumentCloud Inc.\n
// Underscore is freely distributable under the terms of the MIT license.\n
// Portions of Underscore are inspired by or borrowed from Prototype.js,\n
// Oliver Steele\'s Functional, and John Resig\'s Micro-Templating.\n
// For all details and documentation:\n
// http://documentcloud.github.com/underscore\n
\n
"define metadata";\n
({\n
    "description": "Functional Programming Aid for Javascript. Works well with jQuery."\n
});\n
"end";\n
\n
(function() {\n
  // ------------------------- Baseline setup ---------------------------------\n
\n
  // Establish the root object, "window" in the browser, or "global" on the server.\n
  var root = this;\n
\n
  // Save the previous value of the "_" variable.\n
  var previousUnderscore = root._;\n
\n
  // Establish the object that gets thrown to break out of a loop iteration.\n
  var breaker = typeof StopIteration !== \'undefined\' ? StopIteration : \'__break__\';\n
\n
  // Quick regexp-escaping function, because JS doesn\'t have RegExp.escape().\n
  var escapeRegExp = function(s) { return s.replace(/([.*+?^${}()|[\\]\\/\\\\])/g, \'\\\\$1\'); };\n
\n
  // Save bytes in the minified (but not gzipped) version:\n
  var ArrayProto = Array.prototype, ObjProto = Object.prototype;\n
\n
  // Create quick reference variables for speed access to core prototypes.\n
  var slice                 = ArrayProto.slice,\n
      unshift               = ArrayProto.unshift,\n
      toString              = ObjProto.toString,\n
      hasOwnProperty        = ObjProto.hasOwnProperty,\n
      propertyIsEnumerable  = ObjProto.propertyIsEnumerable;\n
\n
  // All ECMA5 native implementations we hope to use are declared here.\n
  var\n
    nativeForEach      = ArrayProto.forEach,\n
    nativeMap          = ArrayProto.map,\n
    nativeReduce       = ArrayProto.reduce,\n
    nativeReduceRight  = ArrayProto.reduceRight,\n
    nativeFilter       = ArrayProto.filter,\n
    nativeEvery        = ArrayProto.every,\n
    nativeSome         = ArrayProto.some,\n
    nativeIndexOf      = ArrayProto.indexOf,\n
    nativeLastIndexOf  = ArrayProto.lastIndexOf,\n
    nativeIsArray      = Array.isArray,\n
    nativeKeys         = Object.keys;\n
\n
  // Create a safe reference to the Underscore object for use below.\n
  var _ = function(obj) { return new wrapper(obj); };\n
\n
  // Export the Underscore object for CommonJS.\n
  if (typeof exports !== \'undefined\') exports._ = _;\n
\n
  // Export underscore to global scope.\n
  root._ = _;\n
\n
  // Current version.\n
  _.VERSION = \'1.0.2\';\n
\n
  // ------------------------ Collection Functions: ---------------------------\n
\n
  // The cornerstone, an each implementation.\n
  // Handles objects implementing forEach, arrays, and raw objects.\n
  // Delegates to JavaScript 1.6\'s native forEach if available.\n
  var each = _.forEach = function(obj, iterator, context) {\n
    try {\n
      if (nativeForEach && obj.forEach === nativeForEach) {\n
        obj.forEach(iterator, context);\n
      } else if (_.isNumber(obj.length)) {\n
        for (var i = 0, l = obj.length; i < l; i++) iterator.call(context, obj[i], i, obj);\n
      } else {\n
        for (var key in obj) {\n
          if (hasOwnProperty.call(obj, key)) iterator.call(context, obj[key], key, obj);\n
        }\n
      }\n
    } catch(e) {\n
      if (e != breaker) throw e;\n
    }\n
    return obj;\n
  };\n
\n
  // Return the results of applying the iterator to each element.\n
  // Delegates to JavaScript 1.6\'s native map if available.\n
  _.map = function(obj, iterator, context) {\n
    if (nativeMap && obj.map === nativeMap) return obj.map(iterator, context);\n
    var results = [];\n
    each(obj, function(value, index, list) {\n
      results.push(iterator.call(context, value, index, list));\n
    });\n
    return results;\n
  };\n
\n
  // Reduce builds up a single result from a list of values, aka inject, or foldl.\n
  // Delegates to JavaScript 1.8\'s native reduce if available.\n
  _.reduce = function(obj, memo, iterator, context) {\n
    if (nativeReduce && obj.reduce === nativeReduce) return obj.reduce(_.bind(iterator, context), memo);\n
    each(obj, function(value, index, list) {\n
      memo = iterator.call(context, memo, value, index, list);\n
    });\n
    return memo;\n
  };\n
\n
  // The right-associative version of reduce, also known as foldr. Uses\n
  // Delegates to JavaScript 1.8\'s native reduceRight if available.\n
  _.reduceRight = function(obj, memo, iterator, context) {\n
    if (nativeReduceRight && obj.reduceRight === nativeReduceRight) return obj.reduceRight(_.bind(iterator, context), memo);\n
    var reversed = _.clone(_.toArray(obj)).reverse();\n
    return _.reduce(reversed, memo, iterator, context);\n
  };\n
\n
  // Return the first value which passes a truth test.\n
  _.detect = function(obj, iterator, context) {\n
    var result;\n
    each(obj, function(value, index, list) {\n
      if (iterator.call(context, value, index, list)) {\n
        result = value;\n
        _.breakLoop();\n
      }\n
    });\n
    return result;\n
  };\n
\n
  // Return all the elements that pass a truth test.\n
  // Delegates to JavaScript 1.6\'s native filter if available.\n
  _.filter = function(obj, iterator, context) {\n
    if (nativeFilter && obj.filter === nativeFilter) return obj.filter(iterator, context);\n
    var results = [];\n
    each(obj, function(value, index, list) {\n
      iterator.call(context, value, index, list) && results.push(value);\n
    });\n
    return results;\n
  };\n
\n
  // Return all the elements for which a truth test fails.\n
  _.reject = function(obj, iterator, context) {\n
    var results = [];\n
    each(obj, function(value, index, list) {\n
      !iterator.call(context, value, index, list) && results.push(value);\n
    });\n
    return results;\n
  };\n
\n
  // Determine whether all of the elements match a truth test.\n
  // Delegates to JavaScript 1.6\'s native every if available.\n
  _.every = function(obj, iterator, context) {\n
    iterator = iterator || _.identity;\n
    if (nativeEvery && obj.every === nativeEvery) return obj.every(iterator, context);\n
    var result = true;\n
    each(obj, function(value, index, list) {\n
      if (!(result = result && iterator.call(context, value, index, list))) _.breakLoop();\n
    });\n
    return result;\n
  };\n
\n
  // Determine if at least one element in the object matches a truth test.\n
  // Delegates to JavaScript 1.6\'s native some if available.\n
  _.some = function(obj, iterator, context) {\n
    iterator = iterator || _.identity;\n
    if (nativeSome && obj.some === nativeSome) return obj.some(iterator, context);\n
    var result = false;\n
    each(obj, function(value, index, list) {\n
      if (result = iterator.call(context, value, index, list)) _.breakLoop();\n
    });\n
    return result;\n
  };\n
\n
  // Determine if a given value is included in the array or object using \'===\'.\n
  _.include = function(obj, target) {\n
    if (nativeIndexOf && obj.indexOf === nativeIndexOf) return obj.indexOf(target) != -1;\n
    var found = false;\n
    each(obj, function(value) {\n
      if (found = value === target) _.breakLoop();\n
    });\n
    return found;\n
  };\n
\n
  // Invoke a method with arguments on every item in a collection.\n
  _.invoke = function(obj, method) {\n
    var args = _.rest(arguments, 2);\n
    return _.map(obj, function(value) {\n
      return (method ? value[method] : value).apply(value, args);\n
    });\n
  };\n
\n
  // Convenience version of a common use case of map: fetching a property.\n
  _.pluck = function(obj, key) {\n
    return _.map(obj, function(value){ return value[key]; });\n
  };\n
\n
  // Return the maximum item or (item-based computation).\n
  _.max = function(obj, iterator, context) {\n
    if (!iterator && _.isArray(obj)) return Math.max.apply(Math, obj);\n
    var result = {computed : -Infinity};\n
    each(obj, function(value, index, list) {\n
      var computed = iterator ? iterator.call(context, value, index, list) : value;\n
      computed >= result.computed && (result = {value : value, computed : computed});\n
    });\n
    return result.value;\n
  };\n
\n
  // Return the minimum element (or element-based computation).\n
  _.min = function(obj, iterator, context) {\n
    if (!iterator && _.isArray(obj)) return Math.min.apply(Math, obj);\n
    var result = {computed : Infinity};\n
    each(obj, function(value, index, list) {\n
      var computed = iterator ? iterator.call(context, value, index, list) : value;\n
      computed < result.computed && (result = {value : value, computed : computed});\n
    });\n
    return result.value;\n
  };\n
\n
  // Sort the object\'s values by a criterion produced by an iterator.\n
  _.sortBy = function(obj, iterator, context) {\n
    return _.pluck(_.map(obj, function(value, index, list) {\n
      return {\n
        value : value,\n
        criteria : iterator.call(context, value, index, list)\n
      };\n
    }).sort(function(left, right) {\n
      var a = left.criteria, b = right.criteria;\n
      return a < b ? -1 : a > b ? 1 : 0;\n
    }), \'value\');\n
  };\n
\n
  // Use a comparator function to figure out at what index an object should\n
  // be inserted so as to maintain order. Uses binary search.\n
  _.sortedIndex = function(array, obj, iterator) {\n
    iterator = iterator || _.identity;\n
    var low = 0, high = array.length;\n
    while (low < high) {\n
      var mid = (low + high) >> 1;\n
      iterator(array[mid]) < iterator(obj) ? low = mid + 1 : high = mid;\n
    }\n
    return low;\n
  };\n
\n
  // Convert anything iterable into a real, live array.\n
  _.toArray = function(iterable) {\n
    if (!iterable)                return [];\n
    if (iterable.toArray)         return iterable.toArray();\n
    if (_.isArray(iterable))      return iterable;\n
    if (_.isArguments(iterable))  return slice.call(iterable);\n
    return _.values(iterable);\n
  };\n
\n
  // Return the number of elements in an object.\n
  _.size = function(obj) {\n
    return _.toArray(obj).length;\n
  };\n
\n
  // -------------------------- Array Functions: ------------------------------\n
\n
  // Get the first element of an array. Passing "n" will return the first N\n
  // values in the array. Aliased as "head". The "guard" check allows it to work\n
  // with _.map.\n
  _.first = function(array, n, guard) {\n
    return n && !guard ? slice.call(array, 0, n) : array[0];\n
  };\n
\n
  // Returns everything but the first entry of the array. Aliased as "tail".\n
  // Especially useful on the arguments object. Passing an "index" will return\n
  // the rest of the values in the array from that index onward. The "guard"\n
   //check allows it to work with _.map.\n
  _.rest = function(array, index, guard) {\n
    return slice.call(array, _.isUndefined(index) || guard ? 1 : index);\n
  };\n
\n
  // Get the last element of an array.\n
  _.last = function(array) {\n
    return array[array.length - 1];\n
  };\n
\n
  // Trim out all falsy values from an array.\n
  _.compact = function(array) {\n
    return _.filter(array, function(value){ return !!value; });\n
  };\n
\n
  // Return a completely flattened version of an array.\n
  _.flatten = function(array) {\n
    return _.reduce(array, [], function(memo, value) {\n
      if (_.isArray(value)) return memo.concat(_.flatten(value));\n
      memo.push(value);\n
      return memo;\n
    });\n
  };\n
\n
  // Return a version of the array that does not contain the specified value(s).\n
  _.without = function(array) {\n
    var values = _.rest(arguments);\n
    return _.filter(array, function(value){ return !_.include(values, value); });\n
  };\n
\n
  // Produce a duplicate-free version of the array. If the array has already\n
  // been sorted, you have the option of using a faster algorithm.\n
  _.uniq = function(array, isSorted) {\n
    return _.reduce(array, [], function(memo, el, i) {\n
      if (0 == i || (isSorted === true ? _.last(memo) != el : !_.include(memo, el))) memo.push(el);\n
      return memo;\n
    });\n
  };\n
\n
  // Produce an array that contains every item shared between all the\n
  // passed-in arrays.\n
  _.intersect = function(array) {\n
    var rest = _.rest(arguments);\n
    return _.filter(_.uniq(array), function(item) {\n
      return _.every(rest, function(other) {\n
        return _.indexOf(other, item) >= 0;\n
      });\n
    });\n
  };\n
\n
  // Zip together multiple lists into a single array -- elements that share\n
  // an index go together.\n
  _.zip = function() {\n
    var args = _.toArray(arguments);\n
    var length = _.max(_.pluck(args, \'length\'));\n
    var results = new Array(length);\n
    for (var i = 0; i < length; i++) results[i] = _.pluck(args, String(i));\n
    return results;\n
  };\n
\n
  // If the browser doesn\'t supply us with indexOf (I\'m looking at you, MSIE),\n
  // we need this function. Return the position of the first occurence of an\n
  // item in an array, or -1 if the item is not included in the array.\n
  // Delegates to JavaScript 1.8\'s native indexOf if available.\n
  _.indexOf = function(array, item) {\n
    if (nativeIndexOf && array.indexOf === nativeIndexOf) return array.indexOf(item);\n
    for (var i = 0, l = array.length; i < l; i++) if (array[i] === item) return i;\n
    return -1;\n
  };\n
\n
\n
  // Delegates to JavaScript 1.6\'s native lastIndexOf if available.\n
  _.lastIndexOf = function(array, item) {\n
    if (nativeLastIndexOf && array.lastIndexOf === nativeLastIndexOf) return array.lastIndexOf(item);\n
    var i = array.length;\n
    while (i--) if (array[i] === item) return i;\n
    return -1;\n
  };\n
\n
  // Generate an integer Array containing an arithmetic progression. A port of\n
  // the native Python range() function. See:\n
  // http://docs.python.org/library/functions.html#range\n
  _.range = function(start, stop, step) {\n
    var a     = _.toArray(arguments);\n
    var solo  = a.length <= 1;\n
    var start = solo ? 0 : a[0], stop = solo ? a[0] : a[1], step = a[2] || 1;\n
    var len   = Math.ceil((stop - start) / step);\n
    if (len <= 0) return [];\n
    var range = new Array(len);\n
    for (var i = start, idx = 0; true; i += step) {\n
      if ((step > 0 ? i - stop : stop - i) >= 0) return range;\n
      range[idx++] = i;\n
    }\n
  };\n
\n
  // ----------------------- Function Functions: ------------------------------\n
\n
  // Create a function bound to a given object (assigning \'this\', and arguments,\n
  // optionally). Binding with arguments is also known as \'curry\'.\n
  _.bind = function(func, obj) {\n
    var args = _.rest(arguments, 2);\n
    return function() {\n
      return func.apply(obj || {}, args.concat(_.toArray(arguments)));\n
    };\n
  };\n
\n
  // Bind all of an object\'s methods to that object. Useful for ensuring that\n
  // all callbacks defined on an object belong to it.\n
  _.bindAll = function(obj) {\n
    var funcs = _.rest(arguments);\n
    if (funcs.length == 0) funcs = _.functions(obj);\n
    each(funcs, function(f) { obj[f] = _.bind(obj[f], obj); });\n
    return obj;\n
  };\n
\n
  // Delays a function for the given number of milliseconds, and then calls\n
  // it with the arguments supplied.\n
  _.delay = function(func, wait) {\n
    var args = _.rest(arguments, 2);\n
    return setTimeout(function(){ return func.apply(func, args); }, wait);\n
  };\n
\n
  // Defers a function, scheduling it to run after the current call stack has\n
  // cleared.\n
  _.defer = function(func) {\n
    return _.delay.apply(_, [func, 1].concat(_.rest(arguments)));\n
  };\n
\n
  // Returns the first function passed as an argument to the second,\n
  // allowing you to adjust arguments, run code before and after, and\n
  // conditionally execute the original function.\n
  _.wrap = function(func, wrapper) {\n
    return function() {\n
      var args = [func].concat(_.toArray(arguments));\n
      return wrapper.apply(wrapper, args);\n
    };\n
  };\n
\n
  // Returns a function that is the composition of a list of functions, each\n
  // consuming the return value of the function that follows.\n
  _.compose = function() {\n
    var funcs = _.toArray(arguments);\n
    return function() {\n
      var args = _.toArray(arguments);\n
      for (var i=funcs.length-1; i >= 0; i--) {\n
        args = [funcs[i].apply(this, args)];\n
      }\n
      return args[0];\n
    };\n
  };\n
\n
  // ------------------------- Object Functions: ------------------------------\n
\n
  // Retrieve the names of an object\'s properties.\n
  // Delegates to ECMA5\'s native Object.keys\n
  _.keys = nativeKeys || function(obj) {\n
    if (_.isArray(obj)) return _.range(0, obj.length);\n
    var keys = [];\n
    for (var key in obj) if (hasOwnProperty.call(obj, key)) keys.push(key);\n
    return keys;\n
  };\n
\n
  // Retrieve the values of an object\'s properties.\n
  _.values = function(obj) {\n
    return _.map(obj, _.identity);\n
  };\n
\n
  // Return a sorted list of the function names available on the object.\n
  _.functions = function(obj) {\n
    return _.filter(_.keys(obj), function(key){ return _.isFunction(obj[key]); }).sort();\n
  };\n
\n
  // Extend a given object with all the properties in passed-in object(s).\n
  _.extend = function(obj) {\n
    each(_.rest(arguments), function(source) {\n
      for (var prop in source) obj[prop] = source[prop];\n
    });\n
    return obj;\n
  };\n
\n
  // Create a (shallow-cloned) duplicate of an object.\n
  _.clone = function(obj) {\n
    if (_.isArray(obj)) return obj.slice(0);\n
    return _.extend({}, obj);\n
  };\n
\n
  // Invokes interceptor with the obj, and then returns obj.\n
  // The primary purpose of this method is to "tap into" a method chain, in order to perform operations on intermediate results within the chain.\n
  _.tap = function(obj, interceptor) {\n
    interceptor(obj);\n
    return obj;\n
  };\n
\n
  // Perform a deep comparison to check if two objects are equal.\n
  _.isEqual = function(a, b) {\n
    // Check object identity.\n
    if (a === b) return true;\n
    // Different types?\n
    var atype = typeof(a), btype = typeof(b);\n
    if (atype != btype) return false;\n
    // Basic equality test (watch out for coercions).\n
    if (a == b) return true;\n
    // One is falsy and the other truthy.\n
    if ((!a && b) || (a && !b)) return false;\n
    // One of them implements an isEqual()?\n
    if (a.isEqual) return a.isEqual(b);\n
    // Check dates\' integer values.\n
    if (_.isDate(a) && _.isDate(b)) return a.getTime() === b.getTime();\n
    // Both are NaN?\n
    if (_.isNaN(a) && _.isNaN(b)) return true;\n
    // Compare regular expressions.\n
    if (_.isRegExp(a) && _.isRegExp(b))\n
      return a.source     === b.source &&\n
             a.global     === b.global &&\n
             a.ignoreCase === b.ignoreCase &&\n
             a.multiline  === b.multiline;\n
    // If a is not an object by this point, we can\'t handle it.\n
    if (atype !== \'object\') return false;\n
    // Check for different array lengths before comparing contents.\n
    if (a.length && (a.length !== b.length)) return false;\n
    // Nothing else worked, deep compare the contents.\n
    var aKeys = _.keys(a), bKeys = _.keys(b);\n
    // Different object sizes?\n
    if (aKeys.length != bKeys.length) return false;\n
    // Recursive comparison of contents.\n
    for (var key in a) if (!(key in b) || !_.isEqual(a[key], b[key])) return false;\n
    return true;\n
  };\n
\n
  // Is a given array or object empty?\n
  _.isEmpty = function(obj) {\n
    if (_.isArray(obj) || _.isString(obj)) return obj.length === 0;\n
    for (var key in obj) if (hasOwnProperty.call(obj, key)) return false;\n
    return true;\n
  };\n
\n
  // Is a given value a DOM element?\n
  _.isElement = function(obj) {\n
    return !!(obj && obj.nodeType == 1);\n
  };\n
\n
  // Is a given value an array?\n
  // Delegates to ECMA5\'s native Array.isArray\n
  _.isArray = nativeIsArray || function(obj) {\n
    return !!(obj && obj.concat && obj.unshift && !obj.callee);\n
  };\n
\n
  // Is a given variable an arguments object?\n
  _.isArguments = function(obj) {\n
    return obj && obj.callee;\n
  };\n
\n
  // Is a given value a function?\n
  _.isFunction = function(obj) {\n
    return !!(obj && obj.constructor && obj.call && obj.apply);\n
  };\n
\n
  // Is a given value a string?\n
  _.isString = function(obj) {\n
    return !!(obj === \'\' || (obj && obj.charCodeAt && obj.substr));\n
  };\n
\n
  // Is a given value a number?\n
  _.isNumber = function(obj) {\n
    return (obj === +obj) || (toString.call(obj) === \'[object Number]\');\n
  };\n
\n
  // Is a given value a boolean?\n
  _.isBoolean = function(obj) {\n
    return obj === true || obj === false;\n
  };\n
\n
  // Is a given value a date?\n
  _.isDate = function(obj) {\n
    return !!(obj && obj.getTimezoneOffset && obj.setUTCFullYear);\n
  };\n
\n
  // Is the given value a regular expression?\n
  _.isRegExp = function(obj) {\n
    return !!(obj && obj.test && obj.exec && (obj.ignoreCase || obj.ignoreCase === false));\n
  };\n
\n
  // Is the given value NaN -- this one is interesting. NaN != NaN, and\n
  // isNaN(undefined) == true, so we make sure it\'s a number first.\n
  _.isNaN = function(obj) {\n
    return _.isNumber(obj) && isNaN(obj);\n
  };\n
\n
  // Is a given value equal to null?\n
  _.isNull = function(obj) {\n
    return obj === null;\n
  };\n
\n
  // Is a given variable undefined?\n
  _.isUndefined = function(obj) {\n
    return typeof obj == \'undefined\';\n
  };\n
\n
  // -------------------------- Utility Functions: ----------------------------\n
\n
  // Run Underscore.js in noConflict mode, returning the \'_\' variable to its\n
  // previous owner. Returns a reference to the Underscore object.\n
  _.noConflict = function() {\n
    root._ = previousUnderscore;\n
    return this;\n
  };\n
\n
  // Keep the identity function around for default iterators.\n
  _.identity = function(value) {\n
    return value;\n
  };\n
\n
  // Run a function n times.\n
  _.times = function (n, iterator, context) {\n
    for (var i = 0; i < n; i++) iterator.call(context, i);\n
  };\n
\n
  // Break out of the middle of an iteration.\n
  _.breakLoop = function() {\n
    throw breaker;\n
  };\n
\n
  // Add your own custom functions to the Underscore object, ensuring that\n
  // they\'re correctly added to the OOP wrapper as well.\n
  _.mixin = function(obj) {\n
    each(_.functions(obj), function(name){\n
      addToWrapper(name, _[name] = obj[name]);\n
    });\n
  };\n
\n
  // Generate a unique integer id (unique within the entire client session).\n
  // Useful for temporary DOM ids.\n
  var idCounter = 0;\n
  _.uniqueId = function(prefix) {\n
    var id = idCounter++;\n
    return prefix ? prefix + id : id;\n
  };\n
\n
  // By default, Underscore uses ERB-style template delimiters, change the\n
  // following template settings to use alternative delimiters.\n
  _.templateSettings = {\n
    start       : \'<%\',\n
    end         : \'%>\',\n
    interpolate : /<%=(.+?)%>/g\n
  };\n
\n
  // JavaScript templating a-la ERB, pilfered from John Resig\'s\n
  // "Secrets of the JavaScript Ninja", page 83.\n
  // Single-quote fix from Rick Strahl\'s version.\n
  // With alterations for arbitrary delimiters.\n
  _.template = function(str, data) {\n
    var c  = _.templateSettings;\n
    var endMatch = new RegExp("\'(?=[^"+c.end.substr(0, 1)+"]*"+escapeRegExp(c.end)+")","g");\n
    var fn = new Function(\'obj\',\n
      \'var p=[],print=function(){p.push.apply(p,arguments);};\' +\n
      \'with(obj){p.push(\\\'\' +\n
      str.replace(/[\\r\\t\\n]/g, " ")\n
         .replace(endMatch,"\\t")\n
         .split("\'").join("\\\\\'")\n
         .split("\\t").join("\'")\n
         .replace(c.interpolate, "\',$1,\'")\n
         .split(c.start).join("\');")\n
         .split(c.end).join("p.push(\'")\n
         + "\');}return p.join(\'\');");\n
    return data ? fn(data) : fn;\n
  };\n
\n
  // ------------------------------- Aliases ----------------------------------\n
\n
  _.each     = _.forEach;\n
  _.foldl    = _.inject       = _.reduce;\n
  _.foldr    = _.reduceRight;\n
  _.select   = _.filter;\n
  _.all      = _.every;\n
  _.any      = _.some;\n
  _.head     = _.first;\n
  _.tail     = _.rest;\n
  _.methods  = _.functions;\n
\n
  // ------------------------ Setup the OOP Wrapper: --------------------------\n
\n
  // If Underscore is called as a function, it returns a wrapped object that\n
  // can be used OO-style. This wrapper holds altered versions of all the\n
  // underscore functions. Wrapped objects may be chained.\n
  var wrapper = function(obj) { this._wrapped = obj; };\n
\n
  // Helper function to continue chaining intermediate results.\n
  var result = function(obj, chain) {\n
    return chain ? _(obj).chain() : obj;\n
  };\n
\n
  // A method to easily add functions to the OOP wrapper.\n
  var addToWrapper = function(name, func) {\n
    wrapper.prototype[name] = function() {\n
      var args = _.toArray(arguments);\n
      unshift.call(args, this._wrapped);\n
      return result(func.apply(_, args), this._chain);\n
    };\n
  };\n
\n
  // Add all of the Underscore functions to the wrapper object.\n
  _.mixin(_);\n
\n
  // Add all mutator Array functions to the wrapper.\n
  each([\'pop\', \'push\', \'reverse\', \'shift\', \'sort\', \'splice\', \'unshift\'], function(name) {\n
    var method = ArrayProto[name];\n
    wrapper.prototype[name] = function() {\n
      method.apply(this._wrapped, arguments);\n
      return result(this._wrapped, this._chain);\n
    };\n
  });\n
\n
  // Add all accessor Array functions to the wrapper.\n
  each([\'concat\', \'join\', \'slice\'], function(name) {\n
    var method = ArrayProto[name];\n
    wrapper.prototype[name] = function() {\n
      return result(method.apply(this._wrapped, arguments), this._chain);\n
    };\n
  });\n
\n
  // Start chaining a wrapped Underscore object.\n
  wrapper.prototype.chain = function() {\n
    this._chain = true;\n
    return this;\n
  };\n
\n
  // Extracts the result from a wrapped and chained object.\n
  wrapper.prototype.value = function() {\n
    return this._wrapped;\n
  };\n
\n
})();\n
\n
exports._.noConflict();\n
});\n
;bespin.tiki.register("::worker_manager", {\n
    name: "worker_manager",\n
    dependencies: { "canon": "0.0.0", "events": "0.0.0", "underscore": "0.0.0" }\n
});\n
bespin.tiki.module("worker_manager:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
"define metadata";\n
({\n
    "description": "Manages a web worker on the browser side",\n
    "dependencies": {\n
        "canon": "0.0.0",\n
        "events": "0.0.0",\n
        "underscore": "0.0.0"\n
    },\n
    "provides": [\n
        {\n
            "ep": "command",\n
            "name": "worker",\n
            "description": "Low-level web worker control (for plugin development)"\n
        },\n
        {\n
            "ep": "command",\n
            "name": "worker restart",\n
            "description": "Restarts all web workers (for plugin development)",\n
            "pointer": "#workerRestartCommand"\n
        }\n
    ]\n
});\n
"end";\n
\n
if (window == null) {\n
    throw new Error(\'The "worker_manager" plugin can only be loaded in the \' +\n
        \'browser, not a web worker. Use "worker" instead.\');\n
}\n
\n
var proxy = require(\'bespin:proxy\');\n
var plugins = require(\'bespin:plugins\');\n
var console = require(\'bespin:console\').console;\n
var _ = require(\'underscore\')._;\n
var Event = require(\'events\').Event;\n
var Promise = require(\'bespin:promise\').Promise;\n
var env = require(\'environment\').env;\n
\n
var workerManager = {\n
    _workers: [],\n
\n
    add: function(workerSupervisor) {\n
        this._workers.push(workerSupervisor);\n
    },\n
\n
    remove: function(workerSupervisor) {\n
        this._workers = _(this._workers).without(workerSupervisor);\n
    },\n
\n
    restartAll: function() {\n
        var workers = this._workers;\n
        _(workers).invoke(\'kill\');\n
        _(workers).invoke(\'start\');\n
    }\n
};\n
\n
function WorkerSupervisor(pointer) {\n
    var m = /^([^#:]+)(?::([^#:]+))?#([^#:]+)$/.exec(pointer);\n
    if (m == null) {\n
        throw new Error(\'WorkerSupervisor: invalid pointer specification: "\' +\n
            pointer + \'"\');\n
    }\n
\n
    var packageId = m[1], target = m[3];\n
    var moduleId = packageId + ":" + (m[2] != null ? m[2] : "index");\n
    var base = bespin != null && bespin.base != null ? bespin.base : "";\n
\n
    this._packageId = packageId;\n
    this._moduleId = moduleId;\n
    this._base = base;\n
    this._target = target;\n
\n
    this._worker = null;\n
    this._currentId = 0;\n
\n
    this.started = new Event();\n
}\n
\n
WorkerSupervisor.prototype = {\n
    _onError: function(ev) {\n
        this._worker = null;\n
        workerManager.remove(this);\n
\n
        console.error("WorkerSupervisor: worker failed at file " +\n
            ev.filename + ":" + ev.lineno + "; fix the worker and use " +\n
            "\'worker restart\' to restart it");\n
    },\n
\n
    _onMessage: function(ev) {\n
        var msg = JSON.parse(ev.data);\n
        switch (msg.op) {\n
        case \'finish\':\n
            if (msg.id === this._currentId) {\n
                var promise = this._promise;\n
\n
                // We have to set the promise to null first, in case the user\'s\n
                // then() handler on the promise decides to send another\n
                // message to the object.\n
                this._promise = null;\n
\n
                promise.resolve(msg.result);\n
            }\n
            break;\n
\n
        case \'log\':\n
            console[msg.method].apply(console, msg.args);\n
            break;\n
        }\n
    },\n
\n
    _promise: null,\n
\n
    /** An event that fires whenever the worker is started or restarted. */\n
    started: null,\n
\n
    /**\n
     * Terminates the worker. After this call, the worker can be restarted via\n
     * a call to start().\n
     */\n
    kill: function() {\n
        var oldPromise = this._promise;\n
        if (oldPromise != null) {\n
            oldPromise.reject("killed");\n
            this._promise = null;\n
        }\n
\n
        this._worker.terminate();\n
        this._worker = null;\n
        workerManager.remove(this);\n
    },\n
\n
    /**\n
     * Invokes a method on the target running in the worker and returns a\n
     * promise that will resolve to the result of that method.\n
     */\n
    send: function(method, args) {\n
        var oldPromise = this._promise;\n
        if (oldPromise != null) {\n
            oldPromise.reject("interrupted");\n
            this._currentId++;\n
        }\n
\n
        var id = this._currentId;\n
        var promise = new Promise();\n
        this._promise = promise;\n
\n
        var msg = { op: \'invoke\', id: id, method: method, args: args };\n
        this._worker.postMessage(JSON.stringify(msg));\n
\n
        return promise;\n
    },\n
\n
    /**\n
     * Starts the worker. Immediately after this method is called, the\n
     * "started" event will fire.\n
     */\n
    start: function() {\n
        if (this._worker != null) {\n
            throw new Error("WorkerSupervisor: worker already started");\n
        }\n
\n
        var base = this._base, target = this._target;\n
        var packageId = this._packageId, moduleId = this._moduleId;\n
\n
        var worker = new proxy.Worker(base + "BespinEmbedded.js");\n
\n
        worker.onmessage = this._onMessage.bind(this);\n
        worker.onerror = this._onError.bind(this);\n
\n
        var msg = {\n
            op:     \'load\',\n
            base:   base,\n
            pkg:    packageId,\n
            module: moduleId,\n
            target: target\n
        };\n
        worker.postMessage(JSON.stringify(msg));\n
\n
        this._worker = worker;\n
        this._currentId = 0;\n
\n
        workerManager.add(this);\n
\n
        this.started();\n
    }\n
};\n
\n
function workerRestartCommand(args, req) {\n
    workerManager.restartAll();\n
}\n
\n
exports.WorkerSupervisor = WorkerSupervisor;\n
exports.workerManager = workerManager;\n
exports.workerRestartCommand = workerRestartCommand;\n
\n
\n
});\n
;bespin.tiki.register("::events", {\n
    name: "events",\n
    dependencies: { "traits": "0.0.0" }\n
});\n
bespin.tiki.module("events:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
exports.Event = function() {\n
    var handlers = [];\n
    var evt = function() {\n
        var args = arguments;\n
        handlers.forEach(function(handler) { handler.func.apply(null, args); });\n
    };\n
\n
    /**\n
     * Adds a new handler via\n
     *  a) evt.add(handlerFunc)\n
     *  b) evt.add(reference, handlerFunc)\n
     */\n
    evt.add = function() {\n
        if (arguments.length == 1) {\n
            handlers.push({\n
                ref: arguments[0],\n
                func: arguments[0]\n
            });\n
        } else {\n
            handlers.push({\n
                ref: arguments[0],\n
                func: arguments[1]\n
            });\n
        }\n
    };\n
\n
    evt.remove = function(ref) {\n
        var notEqual = function(other) { return ref !== other.ref; };\n
        handlers = handlers.filter(notEqual);\n
    };\n
\n
    evt.removeAll = function() {\n
        handlers = [];\n
    };\n
\n
    return evt;\n
};\n
\n
\n
});\n
;bespin.tiki.register("::types", {\n
    name: "types",\n
    dependencies: {  }\n
});\n
bespin.tiki.module("types:basic",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var console = require(\'bespin:console\').console;\n
var Promise = require(\'bespin:promise\').Promise;\n
\n
var r = require;\n
\n
/**\n
 * These are the basic types that we accept. They are vaguely based on the\n
 * Jetpack settings system (https://wiki.mozilla.org/Labs/Jetpack/JEP/24)\n
 * although clearly more restricted.\n
 * <p>In addition to these types, Jetpack also accepts range, member, password\n
 * that we are thinking of adding in the short term.\n
 */\n
\n
/**\n
 * \'text\' is the default if no type is given.\n
 */\n
exports.text = {\n
    isValid: function(value, typeExt) {\n
        return typeof value == \'string\';\n
    },\n
\n
    toString: function(value, typeExt) {\n
        return value;\n
    },\n
\n
    fromString: function(value, typeExt) {\n
        return value;\n
    }\n
};\n
\n
/**\n
 * We don\'t currently plan to distinguish between integers and floats\n
 */\n
exports.number = {\n
    isValid: function(value, typeExt) {\n
        if (isNaN(value)) {\n
            return false;\n
        }\n
        if (value === null) {\n
            return false;\n
        }\n
        if (value === undefined) {\n
            return false;\n
        }\n
        if (value === Infinity) {\n
            return false;\n
        }\n
        return typeof value == \'number\';// && !isNaN(value);\n
    },\n
\n
    toString: function(value, typeExt) {\n
        if (!value) {\n
            return null;\n
        }\n
        return \'\' + value;\n
    },\n
\n
    fromString: function(value, typeExt) {\n
        if (!value) {\n
            return null;\n
        }\n
        var reply = parseInt(value, 10);\n
        if (isNaN(reply)) {\n
            throw new Error(\'Can\\\'t convert "\' + value + \'" to a number.\');\n
        }\n
        return reply;\n
    }\n
};\n
\n
/**\n
 * true/false values\n
 */\n
exports.bool = {\n
    isValid: function(value, typeExt) {\n
        return typeof value == \'boolean\';\n
    },\n
\n
    toString: function(value, typeExt) {\n
        return \'\' + value;\n
    },\n
\n
    fromString: function(value, typeExt) {\n
        if (value === null) {\n
            return null;\n
        }\n
\n
        if (!value.toLowerCase) {\n
            return !!value;\n
        }\n
\n
        var lower = value.toLowerCase();\n
        if (lower == \'true\') {\n
            return true;\n
        } else if (lower == \'false\') {\n
            return false;\n
        }\n
\n
        return !!value;\n
    }\n
};\n
\n
/**\n
 * A JSON object\n
 * TODO: Check to see how this works out.\n
 */\n
exports.object = {\n
    isValid: function(value, typeExt) {\n
        return typeof value == \'object\';\n
    },\n
\n
    toString: function(value, typeExt) {\n
        return JSON.stringify(value);\n
    },\n
\n
    fromString: function(value, typeExt) {\n
        return JSON.parse(value);\n
    }\n
};\n
\n
/**\n
 * One of a known set of options\n
 */\n
exports.selection = {\n
    isValid: function(value, typeExt) {\n
        if (typeof value != \'string\') {\n
            return false;\n
        }\n
\n
        if (!typeExt.data) {\n
            console.error(\'Missing data on selection type extension. Skipping\');\n
            return true;\n
        }\n
\n
        var match = false;\n
        typeExt.data.forEach(function(option) {\n
            if (value == option) {\n
                match = true;\n
            }\n
        });\n
\n
        return match;\n
    },\n
\n
    toString: function(value, typeExt) {\n
        return value;\n
    },\n
\n
    fromString: function(value, typeExt) {\n
        // TODO: should we validate and return null if invalid?\n
        return value;\n
    },\n
\n
    resolveTypeSpec: function(extension, typeSpec) {\n
        var promise = new Promise();\n
\n
        if (typeSpec.data) {\n
            // If we\'ve got the data already - just use it\n
            extension.data = typeSpec.data;\n
            promise.resolve();\n
        } else if (typeSpec.pointer) {\n
            catalog.loadObjectForPropertyPath(typeSpec.pointer).then(function(obj) {\n
                var reply = obj(typeSpec);\n
                if (typeof reply.then === \'function\') {\n
                    reply.then(function(data) {\n
                        extension.data = data;\n
                        promise.resolve();\n
                    });\n
                } else {\n
                    extension.data = reply;\n
                    promise.resolve();\n
                }\n
            }, function(ex) {\n
                promise.reject(ex);\n
            });\n
        } else {\n
            // No extra data available\n
            console.warn(\'Missing data/pointer for selection\', typeSpec);\n
            promise.resolve();\n
        }\n
\n
        return promise;\n
    }\n
};\n
\n
});\n
\n
bespin.tiki.module("types:types",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var catalog = require(\'bespin:plugins\').catalog;\n
var console = require(\'bespin:console\').console;\n
var Promise = require(\'bespin:promise\').Promise;\n
\n
/**\n
 * Get the simple text-only, no-param version of a typeSpec.\n
 */\n
exports.getSimpleName = function(typeSpec) {\n
    if (!typeSpec) {\n
        throw new Error(\'null|undefined is not a valid typeSpec\');\n
    }\n
\n
    if (typeof typeSpec == \'string\') {\n
        return typeSpec;\n
    }\n
\n
    if (typeof typeSpec == \'object\') {\n
        if (!typeSpec.name) {\n
            throw new Error(\'Missing name member to typeSpec\');\n
        }\n
\n
        return typeSpec.name;\n
    }\n
\n
    throw new Error(\'Not a typeSpec: \' + typeSpec);\n
};\n
\n
/**\n
 * 2 typeSpecs are considered equal if their simple names are the same.\n
 */\n
exports.equals = function(typeSpec1, typeSpec2) {\n
    return exports.getSimpleName(typeSpec1) == exports.getSimpleName(typeSpec2);\n
};\n
\n
/**\n
 * A deferred type is one where we hope to find out what the type is just\n
 * in time to use it. For example the \'set\' command where the type of the 2nd\n
 * param is defined by the 1st param.\n
 * @param typeSpec An object type spec with name = \'deferred\' and a pointer\n
 * which to call through catalog.loadObjectForPropertyPath (passing in the\n
 * original typeSpec as a parameter). This function is expected to return either\n
 * a new typeSpec, or a promise of a typeSpec.\n
 * @returns A promise which resolves to the new type spec from the pointer.\n
 */\n
exports.undeferTypeSpec = function(typeSpec) {\n
    // Deferred types are specified by the return from the pointer\n
    // function.\n
    var promise = new Promise();\n
    if (!typeSpec.pointer) {\n
        promise.reject(new Error(\'Missing deferred pointer\'));\n
        return promise;\n
    }\n
\n
    catalog.loadObjectForPropertyPath(typeSpec.pointer).then(function(obj) {\n
        var reply = obj(typeSpec);\n
        if (typeof reply.then === \'function\') {\n
            reply.then(function(newTypeSpec) {\n
                promise.resolve(newTypeSpec);\n
            }, function(ex) {\n
                promise.reject(ex);\n
            });\n
        } else {\n
            promise.resolve(reply);\n
        }\n
    }, function(ex) {\n
        promise.reject(ex);\n
    });\n
\n
    return promise;\n
};\n
\n
// Warning: These next 2 functions are virtually cut and paste from\n
// command_line:typehint.js\n
// If you change this, there are probably parallel changes to be made there\n
// There are 2 differences between the functions:\n
// - We lookup type|typehint in the catalog\n
// - There is a concept of a default typehint, where there is no similar\n
//   thing for types. This is sensible, because hints are optional nice\n
//   to have things. Not so for types.\n
// Whilst we could abstract out the changes, I\'m not sure this simplifies\n
// already complex code\n
\n
/**\n
 * Given a string, look up the type extension in the catalog\n
 * @param name The type name. Object type specs are not allowed\n
 * @returns A promise that resolves to a type extension\n
 */\n
function resolveObjectType(typeSpec) {\n
    var promise = new Promise();\n
    var ext = catalog.getExtensionByKey(\'type\', typeSpec.name);\n
    if (ext) {\n
        promise.resolve({ ext: ext, typeSpec: typeSpec });\n
    } else {\n
        promise.reject(new Error(\'Unknown type: \' + typeSpec.name));\n
    }\n
    return promise;\n
};\n
\n
/**\n
 * Look-up a typeSpec and find a corresponding type extension. This function\n
 * does not attempt to load the type or go through the resolution process,\n
 * for that you probably want #resolveType()\n
 * @param typeSpec A string containing the type name or an object with a name\n
 * and other type parameters e.g. { name: \'selection\', data: [ \'one\', \'two\' ] }\n
 * @return a promise that resolves to an object containing the resolved type\n
 * extension and the typeSpec used to resolve the type (which could be different\n
 * from the passed typeSpec if this was deferred). The object will be in the\n
 * form { ext:... typeSpec:... }\n
 */\n
function resolveTypeExt(typeSpec) {\n
    if (typeof typeSpec === \'string\') {\n
        return resolveObjectType({ name: typeSpec });\n
    }\n
\n
    if (typeof typeSpec === \'object\') {\n
        if (typeSpec.name === \'deferred\') {\n
            var promise = new Promise();\n
            exports.undeferTypeSpec(typeSpec).then(function(newTypeSpec) {\n
                resolveTypeExt(newTypeSpec).then(function(reply) {\n
                    promise.resolve(reply);\n
                }, function(ex) {\n
                    promise.reject(ex);\n
                });\n
            });\n
            return promise;\n
        } else {\n
            return resolveObjectType(typeSpec);\n
        }\n
    }\n
\n
    throw new Error(\'Unknown typeSpec type: \' + typeof typeSpec);\n
};\n
\n
/**\n
 * Do all the nastiness of: converting the typeSpec to an extension, then\n
 * asynchronously loading the extension to a type and then calling\n
 * resolveTypeSpec if the loaded type defines it.\n
 * @param typeSpec a string or object defining the type to resolve\n
 * @returns a promise which resolves to an object containing the type and type\n
 * extension as follows: { type:... ext:... }\n
 * @see #resolveTypeExt\n
 */\n
exports.resolveType = function(typeSpec) {\n
    var promise = new Promise();\n
\n
    resolveTypeExt(typeSpec).then(function(data) {\n
        data.ext.load(function(type) {\n
            // We might need to resolve the typeSpec in a custom way\n
            if (typeof type.resolveTypeSpec === \'function\') {\n
                type.resolveTypeSpec(data.ext, data.typeSpec).then(function() {\n
                    promise.resolve({ type: type, ext: data.ext });\n
                }, function(ex) {\n
                    promise.reject(ex);\n
                });\n
            } else {\n
                // Nothing to resolve - just go\n
                promise.resolve({ type: type, ext: data.ext });\n
            }\n
        });\n
    }, function(ex) {\n
        promise.reject(ex);\n
    });\n
\n
    return promise;\n
};\n
\n
/**\n
 * Convert some data from a string to another type as specified by\n
 * <tt>typeSpec</tt>.\n
 */\n
exports.fromString = function(stringVersion, typeSpec) {\n
    var promise = new Promise();\n
    exports.resolveType(typeSpec).then(function(typeData) {\n
        promise.resolve(typeData.type.fromString(stringVersion, typeData.ext));\n
    });\n
    return promise;\n
};\n
\n
/**\n
 * Convert some data from an original type to a string as specified by\n
 * <tt>typeSpec</tt>.\n
 */\n
exports.toString = function(objectVersion, typeSpec) {\n
    var promise = new Promise();\n
    exports.resolveType(typeSpec).then(function(typeData) {\n
        promise.resolve(typeData.type.toString(objectVersion, typeData.ext));\n
    });\n
    return promise;\n
};\n
\n
/**\n
 * Convert some data from an original type to a string as specified by\n
 * <tt>typeSpec</tt>.\n
 */\n
exports.isValid = function(originalVersion, typeSpec) {\n
    var promise = new Promise();\n
    exports.resolveType(typeSpec).then(function(typeData) {\n
        promise.resolve(typeData.type.isValid(originalVersion, typeData.ext));\n
    });\n
    return promise;\n
};\n
\n
});\n
\n
bespin.tiki.module("types:index",function(require,exports,module) {\n
\n
});\n
;bespin.tiki.register("::syntax_manager", {\n
    name: "syntax_manager",\n
    dependencies: { "worker_manager": "0.0.0", "events": "0.0.0", "underscore": "0.0.0", "syntax_directory": "0.0.0" }\n
});\n
bespin.tiki.module("syntax_manager:index",function(require,exports,module) {\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
var _ = require(\'underscore\')._;\n
var Event = require(\'events\').Event;\n
var WorkerSupervisor = require(\'worker_manager\').WorkerSupervisor;\n
var console = require(\'bespin:console\').console;\n
var rangeutils = require(\'rangeutils:utils/range\');\n
var syntaxDirectory = require(\'syntax_directory\').syntaxDirectory;\n
\n
// The number of lines to highlight at once.\n
var GRANULARITY = 100;\n
\n
// Replaces elements at position i in dest with the elements of src. If i is\n
// beyond the end of dest, expands dest with copies of fill.\n
function replace(dest, i, src, fill) {\n
    while (dest.length < i) {\n
        dest.push(_(fill).clone());\n
    }\n
\n
    var args = [ i, src.length ].concat(src);\n
    Array.prototype.splice.apply(dest, args);\n
    return dest;\n
}\n
\n
// A simple key-value store in which each key is paired with a corresponding\n
// line. When the syntax information is updated for a line, the symbols from\n
// those lines are wiped out and replaced with the new symbols.\n
function Symbols() {\n
    this._lines = [];\n
    this._syms = {};\n
}\n
\n
Symbols.prototype = {\n
    get: function(sym) {\n
        return this._syms["-" + sym];\n
    },\n
\n
    replaceLine: function(row, newSymbols) {\n
        var lines = this._lines, syms = this._syms;\n
        if (row < lines.length && _(lines[row]).isArray()) {\n
            _(lines[row]).each(function(ident) { delete syms["-" + ident]; });\n
        }\n
\n
        function stripLeadingDash(s) { return s.substring(1); }\n
        lines[row] = _(newSymbols).keys().map(stripLeadingDash);\n
\n
        _(syms).extend(newSymbols);\n
    }\n
};\n
\n
function Context(syntaxInfo, syntaxManager) {\n
    this._syntaxInfo = syntaxInfo;\n
    this._syntaxManager = syntaxManager;\n
\n
    this._invalidRow = 0;\n
    this._states = [];\n
    this._active = false;\n
\n
    this.symbols = new Symbols;\n
}\n
\n
Context.prototype = {\n
    _annotate: function() {\n
        if (this._invalidRow == null) {\n
            throw new Error("syntax_manager.Context: attempt to annotate " +\n
                "without any invalid row");\n
        }\n
        if (!this._active) {\n
            throw new Error("syntax_manager.Context: attempt to annotate " +\n
                "while inactive");\n
        }\n
\n
        if (this._worker == null) {\n
            this._createWorker();\n
            return;\n
        }\n
\n
        var lines = this._syntaxManager.getTextLines();\n
        var row = this._invalidRow;\n
        var state = row === 0 ? this.getName() + \':start\' : this._states[row];\n
        var lastRow = Math.min(lines.length, row + GRANULARITY);\n
        lines = lines.slice(row, lastRow);\n
\n
        var runRange = {\n
            start: { row: row, col: 0 },\n
            end: { row: lastRow - 1, col: _(lines).last().length }\n
        };\n
\n
        var pr = this._worker.send(\'annotate\', [ state, lines, runRange ]);\n
        pr.then(_(this._annotationFinished).bind(this, row, lastRow));\n
    },\n
\n
    _annotationFinished: function(row, lastRow, result) {\n
        if (!this._active) {\n
            return;\n
        }\n
\n
        var syntaxManager = this._syntaxManager;\n
        syntaxManager.mergeAttrs(row, result.attrs);\n
        syntaxManager.mergeSymbols(row, result.symbols);\n
\n
        replace(this._states, row, result.states);\n
\n
        if (lastRow >= this._getRowCount()) {\n
            this._invalidRow = null;    // We\'re done!\n
            this._active = false;\n
            return;\n
        }\n
\n
        this._invalidRow = lastRow;\n
        this._annotate();\n
    },\n
\n
    _createWorker: function() {\n
        var syntaxInfo = this._syntaxInfo;\n
        if (syntaxInfo == null) {\n
            return false;\n
        }\n
\n
        var worker = new WorkerSupervisor("syntax_worker#syntaxWorker");\n
        this._worker = worker;\n
\n
        worker.started.add(this._workerStarted.bind(this));\n
        worker.start();\n
\n
        return true;\n
    },\n
\n
    _getRowCount: function() {\n
        return this._syntaxManager.getTextLines().length;\n
    },\n
\n
    _workerStarted: function() {\n
        this._worker.send(\'loadSyntax\', [ this._syntaxInfo.name ]);\n
        if (this._active) {\n
            this._annotate();\n
        }\n
    },\n
\n
    // Switches on this syntax context and begins annotation. It is the\n
    // caller\'s responsibility to ensure that there exists an invalid row\n
    // before calling this. (Typically the caller ensures this by calling cut()\n
    // first.)\n
    activateAndAnnotate: function() {\n
        this._active = true;\n
        this._annotate();\n
    },\n
\n
    contextsAtPosition: function(pos) {\n
        var syntaxInfo = this._syntaxInfo;\n
        if (syntaxInfo == null) {\n
            return [ \'plain\' ];\n
        }\n
\n
        return [ syntaxInfo.name ];             // FIXME\n
    },\n
\n
    // Invalidates the syntax context at a row.\n
    cut: function(row) {\n
        var endRow = this._getRowCount();\n
        if (row < 0 || row >= endRow) {\n
            throw new Error("Attempt to cut the context at an invalid row");\n
        }\n
\n
        if (this._invalidRow != null && this._invalidRow < row) {\n
            return;\n
        }\n
        this._invalidRow = row;\n
\n
        // Mark ourselves as inactive, so that if the web worker was working on\n
        // a series of rows we know to discard its results.\n
        this._active = false;\n
    },\n
\n
    getName: function() {\n
        return this._syntaxInfo.name;\n
    },\n
\n
    kill: function() {\n
        var worker = this._worker;\n
        if (worker == null) {\n
            return;\n
        }\n
\n
        worker.kill();\n
        this._worker = null;\n
    }\n
};\n
\n
/**\n
 * The syntax manager coordinates a series of syntax contexts, each run in a\n
 * separate web worker. It receives text editing notifications, updates and\n
 * stores the relevant syntax attributes, and provides marked-up text as the\n
 * layout manager requests it.\n
 *\n
 * @constructor\n
 * @exports SyntaxManager as syntax_manager:SyntaxManager\n
 */\n
function SyntaxManager(layoutManager) {\n
    this.layoutManager = layoutManager;\n
\n
    /** Called whenever the attributes have been updated. */\n
    this.attrsChanged = new Event;\n
\n
    /** Called whenever the syntax (file type) has been changed. */\n
    this.syntaxChanged = new Event;\n
\n
    this._context = null;\n
    this._invalidRows = null;\n
    this._contextRanges = null;\n
    this._attrs = [];\n
    this._symbols = new Symbols;\n
    this._syntax = \'plain\';\n
\n
    this._reset();\n
}\n
\n
SyntaxManager.prototype = {\n
    /** @lends SyntaxManager */\n
\n
    _getTextStorage: function() {\n
        return this.layoutManager.textStorage;\n
    },\n
\n
    // Invalidates all the highlighting and recreates the workers.\n
    _reset: function() {\n
        var ctx = this._context;\n
        if (ctx != null) {\n
            ctx.kill();\n
            this._context = null;\n
        }\n
\n
        var syn = this._syntax;\n
        var syntaxInfo = syn === \'plain\' ? null : syntaxDirectory.get(syn);\n
\n
        ctx = new Context(syntaxInfo, this);\n
        this._context = ctx;\n
        ctx.activateAndAnnotate();\n
    },\n
\n
    attrsChanged: null,\n
    syntaxChanged: null,\n
\n
    /** Returns the contexts that are active at the position pos. */\n
    contextsAtPosition: function(pos) {\n
        return this._context.contextsAtPosition(pos);\n
    },\n
\n
    /**\n
     * Returns the attributes most recently delivered from the syntax engine.\n
     * Does not instruct the engine to perform any work; use invalidateRow()\n
     * for that.\n
     */\n
    getAttrsForRows: function(startRow, endRow) {\n
        return this._attrs.slice(startRow, endRow);\n
    },\n
\n
    /**\n
     * Returns the metadata currently associated with the given symbol, or null\n
     * if the symbol is unknown.\n
     */\n
    getSymbol: function(ident) {\n
        return this._symbols.get(ident);\n
    },\n
\n
    /** Returns the current syntax. */\n
    getSyntax: function() {\n
        return this._syntax;\n
    },\n
\n
    /** A convenience function to return the lines from the text storage. */\n
    getTextLines: function() {\n
        return this._getTextStorage().lines;\n
    },\n
\n
    /** Marks the text as needing an update starting at the given row. */\n
    invalidateRow: function(row) {\n
        var ctx = this._context;\n
        ctx.cut(row);\n
        ctx.activateAndAnnotate();\n
    },\n
\n
    /**\n
     * Merges the supplied attributes into the text, overwriting the attributes\n
     * that were there previously.\n
     */\n
    mergeAttrs: function(startRow, newAttrs) {\n
        replace(this._attrs, startRow, newAttrs, []);\n
        this.attrsChanged(startRow, startRow + newAttrs.length);\n
    },\n
\n
    /**\n
     * Merges the supplied symbols into the symbol store, overwriting any\n
     * symbols previously defined on those lines.\n
     */\n
    mergeSymbols: function(startRow, newSymbols) {\n
        var symbols = this._symbols;\n
        _(newSymbols).each(function(lineSyms, i) {\n
            symbols.replaceLine(startRow + i, lineSyms);\n
        });\n
    },\n
\n
    /**\n
     * Sets the syntax and invalidates all the highlighting. If no syntax\n
     * plugin is available, sets the syntax to "plain".\n
     */\n
    setSyntax: function(syntax) {\n
        this._syntax = syntaxDirectory.hasSyntax(syntax) ? syntax : \'plain\';\n
        this.syntaxChanged(syntax);\n
        this._reset();\n
    },\n
\n
    /** Sets the syntax appropriately for a file extension. */\n
    setSyntaxFromFileExt: function(fileExt) {\n
        return this.setSyntax(syntaxDirectory.syntaxForFileExt(fileExt));\n
    }\n
};\n
\n
exports.SyntaxManager = SyntaxManager;\n
\n
\n
});\n
\n
bespin.tiki.require("bespin:plugins").catalog.registerMetadata({"traits": {"resourceURL": "resources/traits/", "description": "Traits library, traitsjs.org", "dependencies": {}, "testmodules": [], "provides": [], "type": "plugins/thirdparty", "name": "traits"}, "settings": {"resourceURL": "resources/settings/", "description": "Infrastructure and commands for managing user preferences", "share": true, "dependencies": {"types": "0.0"}, "testmodules": [], "provides": [{"description": "Storage for the customizable Bespin settings", "pointer": "index#settings", "ep": "appcomponent", "name": "settings"}, {"indexOn": "name", "description": "A setting is something that the application offers as a way to customize how it works", "register": "index#addSetting", "ep": "extensionpoint", "name": "setting"}, {"description": "A settingChange is a way to be notified of changes to a setting", "ep": "extensionpoint", "name": "settingChange"}, {"pointer": "commands#setCommand", "description": "define and show settings", "params": [{"defaultValue": null, "type": {"pointer": "settings:index#getSettings", "name": "selection"}, "name": "setting", "description": "The name of the setting to display or alter"}, {"defaultValue": null, "type": {"pointer": "settings:index#getTypeSpecFromAssignment", "name": "deferred"}, "name": "value", "description": "The new value for the chosen setting"}], "ep": "command", "name": "set"}, {"pointer": "commands#unsetCommand", "description": "unset a setting entirely", "params": [{"type": {"pointer": "settings:index#getSettings", "name": "selection"}, "name": "setting", "description": "The name of the setting to return to defaults"}], "ep": "command", "name": "unset"}], "type": "plugins/supported", "name": "settings"}, "canon": {"resourceURL": "resources/canon/", "name": "canon", "environments": {"main": true, "worker": false}, "dependencies": {"environment": "0.0.0", "events": "0.0.0", "settings": "0.0.0"}, "testmodules": [], "provides": [{"indexOn": "name", "description": "A command is a bit of functionality with optional typed arguments which can do something small like moving the cursor around the screen, or large like cloning a project from VCS.", "ep": "extensionpoint", "name": "command"}, {"description": "An extension point to be called whenever a new command begins output.", "ep": "extensionpoint", "name": "addedRequestOutput"}, {"description": "A dimensionsChanged is a way to be notified of changes to the dimension of Bespin", "ep": "extensionpoint", "name": "dimensionsChanged"}, {"description": "How many typed commands do we recall for reference?", "defaultValue": 50, "type": "number", "ep": "setting", "name": "historyLength"}, {"action": "create", "pointer": "history#InMemoryHistory", "ep": "factory", "name": "history"}], "type": "plugins/supported", "description": "Manages commands"}, "events": {"resourceURL": "resources/events/", "description": "Dead simple event implementation", "dependencies": {"traits": "0.0"}, "testmodules": ["tests/test"], "provides": [], "type": "plugins/supported", "name": "events"}, "environment": {"testmodules": [], "dependencies": {"settings": "0.0.0"}, "resourceURL": "resources/environment/", "name": "environment", "type": "plugins/supported"}, "bespin": {"testmodules": [], "resourceURL": "resources/bespin/", "name": "bespin", "environments": {"main": true, "worker": true}, "type": "plugins/boot"}, "underscore": {"testmodules": [], "type": "plugins/thirdparty", "resourceURL": "resources/underscore/", "description": "Functional Programming Aid for Javascript. Works well with jQuery.", "name": "underscore"}, "worker_manager": {"resourceURL": "resources/worker_manager/", "description": "Manages a web worker on the browser side", "dependencies": {"canon": "0.0.0", "events": "0.0.0", "underscore": "0.0.0"}, "testmodules": [], "provides": [{"description": "Low-level web worker control (for plugin development)", "ep": "command", "name": "worker"}, {"description": "Restarts all web workers (for plugin development)", "pointer": "#workerRestartCommand", "ep": "command", "name": "worker restart"}], "type": "plugins/supported", "name": "worker_manager"}, "syntax_directory": {"resourceURL": "resources/syntax_directory/", "name": "syntax_directory", "environments": {"main": true, "worker": true}, "dependencies": {}, "testmodules": [], "provides": [{"register": "#discoveredNewSyntax", "ep": "extensionhandler", "name": "syntax"}], "type": "plugins/supported", "description": "Catalogs the available syntax engines"}, "types": {"resourceURL": "resources/types/", "description": "Defines parameter types for commands", "testmodules": ["tests/testTypes", "tests/testBasic"], "provides": [{"indexOn": "name", "description": "Commands can accept various arguments that the user enters or that are automatically supplied by the environment. Those arguments have types that define how they are supplied or completed. The pointer points to an object with methods convert(str value) and getDefault(). Both functions have `this` set to the command\'s `takes` parameter. If getDefault is not defined, the default on the command\'s `takes` is used, if there is one. The object can have a noInput property that is set to true to reflect that this type is provided directly by the system. getDefault must be defined in that case.", "ep": "extensionpoint", "name": "type"}, {"description": "Text that the user needs to enter.", "pointer": "basic#text", "ep": "type", "name": "text"}, {"description": "A JavaScript number", "pointer": "basic#number", "ep": "type", "name": "number"}, {"description": "A true/false value", "pointer": "basic#bool", "ep": "type", "name": "boolean"}, {"description": "An object that converts via JavaScript", "pointer": "basic#object", "ep": "type", "name": "object"}, {"description": "A string that is constrained to be one of a number of pre-defined values", "pointer": "basic#selection", "ep": "type", "name": "selection"}, {"description": "A type which we don\'t understand from the outset, but which we hope context can help us with", "ep": "type", "name": "deferred"}], "type": "plugins/supported", "name": "types"}, "syntax_manager": {"resourceURL": "resources/syntax_manager/", "name": "syntax_manager", "environments": {"main": true, "worker": false}, "dependencies": {"worker_manager": "0.0.0", "events": "0.0.0", "underscore": "0.0.0", "syntax_directory": "0.0.0"}, "testmodules": [], "provides": [], "type": "plugins/supported", "description": "Provides syntax highlighting services for the editor"}});\n
/* ***** BEGIN LICENSE BLOCK *****\n
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n
 *\n
 * The contents of this file are subject to the Mozilla Public License Version\n
 * 1.1 (the "License"); you may not use this file except in compliance with\n
 * the License. You may obtain a copy of the License at\n
 * http://www.mozilla.org/MPL/\n
 *\n
 * Software distributed under the License is distributed on an "AS IS" basis,\n
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n
 * for the specific language governing rights and limitations under the\n
 * License.\n
 *\n
 * The Original Code is Bespin.\n
 *\n
 * The Initial Developer of the Original Code is\n
 * Mozilla.\n
 * Portions created by the Initial Developer are Copyright (C) 2009\n
 * the Initial Developer. All Rights Reserved.\n
 *\n
 * Contributor(s):\n
 *   Bespin Team (bespin@mozilla.com)\n
 *\n
 * Alternatively, the contents of this file may be used under the terms of\n
 * either the GNU General Public License Version 2 or later (the "GPL"), or\n
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),\n
 * in which case the provisions of the GPL or the LGPL are applicable instead\n
 * of those above. If you wish to allow use of your version of this file only\n
 * under the terms of either the GPL or the LGPL, and not to allow others to\n
 * use your version of this file under the terms of the MPL, indicate your\n
 * decision by deleting the provisions above and replace them with the notice\n
 * and other provisions required by the GPL or the LGPL. If you do not delete\n
 * the provisions above, a recipient may use your version of this file under\n
 * the terms of any one of the MPL, the GPL or the LGPL.\n
 *\n
 * ***** END LICENSE BLOCK ***** */\n
\n
// Responsible for loading the second script (BespinMain \n
// or BespinWorker)\n
\n
// check to see if we\'re in a worker\n
if (typeof(window) === "undefined") {\n
    importScripts("BespinWorker.js");\n
} else {\n
    (function() {\n
        var mainscript = document.createElement("script");\n
        mainscript.setAttribute("src", bespin.base + "BespinMain.js");\n
        var head = document.getElementsByTagName("head")[0];\n
        head.appendChild(mainscript);\n
    })();\n
}\n


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
