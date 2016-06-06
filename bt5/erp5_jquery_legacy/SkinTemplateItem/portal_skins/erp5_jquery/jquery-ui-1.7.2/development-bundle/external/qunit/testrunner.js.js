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
            <value> <string>ts65545388.09</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>testrunner.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * QUnit - jQuery unit testrunner\n
 * \n
 * http://docs.jquery.com/QUnit\n
 *\n
 * Copyright (c) 2008 John Resig, Jörn Zaefferer\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * $Id: testrunner.js 6173 2009-02-02 20:09:32Z jeresig $\n
 */\n
\n
(function($) {\n
\n
// Tests for equality any JavaScript type and structure without unexpected results.\n
// Discussions and reference: http://philrathe.com/articles/equiv\n
// Test suites: http://philrathe.com/tests/equiv\n
// Author: Philippe Rathé <prathe@gmail.com>\n
var equiv = function () {\n
\n
    var innerEquiv; // the real equiv function\n
    var callers = []; // stack to decide between skip/abort functions\n
\n
    // Determine what is o.\n
    function hoozit(o) {\n
        if (typeof o === "string") {\n
            return "string";\n
\n
        } else if (typeof o === "boolean") {\n
            return "boolean";\n
\n
        } else if (typeof o === "number") {\n
\n
            if (isNaN(o)) {\n
                return "nan";\n
            } else {\n
                return "number";\n
            }\n
\n
        } else if (typeof o === "undefined") {\n
            return "undefined";\n
\n
        // consider: typeof null === object\n
        } else if (o === null) {\n
            return "null";\n
\n
        // consider: typeof [] === object\n
        } else if (o instanceof Array) {\n
            return "array";\n
        \n
        // consider: typeof new Date() === object\n
        } else if (o instanceof Date) {\n
            return "date";\n
\n
        // consider: /./ instanceof Object;\n
        //           /./ instanceof RegExp;\n
        //          typeof /./ === "function"; // => false in IE and Opera,\n
        //                                          true in FF and Safari\n
        } else if (o instanceof RegExp) {\n
            return "regexp";\n
\n
        } else if (typeof o === "object") {\n
            return "object";\n
\n
        } else if (o instanceof Function) {\n
            return "function";\n
        }\n
    }\n
\n
    // Call the o related callback with the given arguments.\n
    function bindCallbacks(o, callbacks, args) {\n
        var prop = hoozit(o);\n
        if (prop) {\n
            if (hoozit(callbacks[prop]) === "function") {\n
                return callbacks[prop].apply(callbacks, args);\n
            } else {\n
                return callbacks[prop]; // or undefined\n
            }\n
        }\n
    }\n
\n
    var callbacks = function () {\n
\n
        // for string, boolean, number and null\n
        function useStrictEquality(b, a) {\n
            return a === b;\n
        }\n
\n
        return {\n
            "string": useStrictEquality,\n
            "boolean": useStrictEquality,\n
            "number": useStrictEquality,\n
            "null": useStrictEquality,\n
            "undefined": useStrictEquality,\n
\n
            "nan": function (b) {\n
                return isNaN(b);\n
            },\n
\n
            "date": function (b, a) {\n
                return hoozit(b) === "date" && a.valueOf() === b.valueOf();\n
            },\n
\n
            "regexp": function (b, a) {\n
                return hoozit(b) === "regexp" &&\n
                    a.source === b.source && // the regex itself\n
                    a.global === b.global && // and its modifers (gmi) ...\n
                    a.ignoreCase === b.ignoreCase &&\n
                    a.multiline === b.multiline;\n
            },\n
\n
            // - skip when the property is a method of an instance (OOP)\n
            // - abort otherwise,\n
            //   initial === would have catch identical references anyway\n
            "function": function () {\n
                var caller = callers[callers.length - 1];\n
                return caller !== Object &&\n
                        typeof caller !== "undefined";\n
            },\n
\n
            "array": function (b, a) {\n
                var i;\n
                var len;\n
\n
                // b could be an object literal here\n
                if ( ! (hoozit(b) === "array")) {\n
                    return false;\n
                }\n
\n
                len = a.length;\n
                if (len !== b.length) { // safe and faster\n
                    return false;\n
                }\n
                for (i = 0; i < len; i++) {\n
                    if( ! innerEquiv(a[i], b[i])) {\n
                        return false;\n
                    }\n
                }\n
                return true;\n
            },\n
\n
            "object": function (b, a) {\n
                var i;\n
                var eq = true; // unless we can proove it\n
                var aProperties = [], bProperties = []; // collection of strings\n
\n
                // comparing constructors is more strict than using instanceof\n
                if ( a.constructor !== b.constructor) {\n
                    return false;\n
                }\n
\n
                // stack constructor before traversing properties\n
                callers.push(a.constructor);\n
\n
                for (i in a) { // be strict: don\'t ensures hasOwnProperty and go deep\n
\n
                    aProperties.push(i); // collect a\'s properties\n
\n
                    if ( ! innerEquiv(a[i], b[i])) {\n
                        eq = false;\n
                    }\n
                }\n
\n
                callers.pop(); // unstack, we are done\n
\n
                for (i in b) {\n
                    bProperties.push(i); // collect b\'s properties\n
                }\n
\n
                // Ensures identical properties name\n
                return eq && innerEquiv(aProperties.sort(), bProperties.sort());\n
            }\n
        };\n
    }();\n
\n
    innerEquiv = function () { // can take multiple arguments\n
        var args = Array.prototype.slice.apply(arguments);\n
        if (args.length < 2) {\n
            return true; // end transition\n
        }\n
\n
        return (function (a, b) {\n
            if (a === b) {\n
                return true; // catch the most you can\n
\n
            } else if (typeof a !== typeof b || a === null || b === null || typeof a === "undefined" || typeof b === "undefined") {\n
                return false; // don\'t lose time with error prone cases\n
\n
            } else {\n
                return bindCallbacks(a, callbacks, [b, a]);\n
            }\n
\n
        // apply transition with (1..n) arguments\n
        })(args[0], args[1]) && arguments.callee.apply(this, args.splice(1, args.length -1));\n
    };\n
\n
    return innerEquiv;\n
}(); // equiv\n
\n
var GETParams = $.map( location.search.slice(1).split(\'&\'), decodeURIComponent ),\n
\tngindex = $.inArray("noglobals", GETParams),\n
\tnoglobals = ngindex !== -1;\n
\n
if( noglobals )\n
\tGETParams.splice( ngindex, 1 );\n
\t\n
var config = {\n
\tstats: {\n
\t\tall: 0,\n
\t\tbad: 0\n
\t},\n
\tqueue: [],\n
\t// block until document ready\n
\tblocking: true,\n
\t//restrict modules/tests by get parameters\n
\tfilters: GETParams,\n
\tisLocal: !!(window.location.protocol == \'file:\')\n
};\n
\n
// public API as global methods\n
$.extend(window, {\n
\ttest: test,\n
\tmodule: module,\n
\texpect: expect,\n
\tok: ok,\n
\tequals: equals,\n
\tstart: start,\n
\tstop: stop,\n
\treset: reset,\n
\tisLocal: config.isLocal,\n
\tsame: function(a, b, message) {\n
\t\tpush(equiv(a, b), a, b, message);\n
\t},\n
\tQUnit: {\n
\t\tequiv: equiv,\n
\t\tok: ok,\n
\t\tdone: function(failures, total){},\n
\t\tlog: function(result, message){}\n
\t},\n
\t// legacy methods below\n
\tisSet: isSet,\n
\tisObj: isObj,\n
\tcompare: function() {\n
\t\tthrow "compare is deprecated - use same() instead";\n
\t},\n
\tcompare2: function() {\n
\t\tthrow "compare2 is deprecated - use same() instead";\n
\t},\n
\tserialArray: function() {\n
\t\tthrow "serialArray is deprecated - use jsDump.parse() instead";\n
\t},\n
\tq: q,\n
\tt: t,\n
\turl: url,\n
\ttriggerEvent: triggerEvent\n
});\n
\n
$(window).load(function() {\n
\t$(\'#userAgent\').html(navigator.userAgent);\n
\tvar head = $(\'<div class="testrunner-toolbar"><label for="filter-pass">Hide passed tests</label></div>\').insertAfter("#userAgent");\n
\t$(\'<input type="checkbox" id="filter-pass" />\').attr("disabled", true).prependTo(head).click(function() {\n
\t\t$(\'li.pass\')[this.checked ? \'hide\' : \'show\']();\n
\t});\n
\t$(\'<input type="checkbox" id="filter-missing">\').attr("disabled", true).appendTo(head).click(function() {\n
\t\t$("li.fail:contains(\'missing test - untested code is broken code\')").parent(\'ol\').parent(\'li.fail\')[this.checked ? \'hide\' : \'show\']();\n
\t});\n
\t$("#filter-missing").after(\'<label for="filter-missing">Hide missing tests (untested code is broken code)</label>\');\n
\trunTest();\t\n
});\n
\n
function synchronize(callback) {\n
\tconfig.queue.push(callback);\n
\tif(!config.blocking) {\n
\t\tprocess();\n
\t}\n
}\n
\n
function process() {\n
\twhile(config.queue.length && !config.blocking) {\n
\t\tconfig.queue.shift()();\n
\t}\n
}\n
\n
function stop(timeout) {\n
\tconfig.blocking = true;\n
\tif (timeout)\n
\t\tconfig.timeout = setTimeout(function() {\n
\t\t\tQUnit.ok( false, "Test timed out" );\n
\t\t\tstart();\n
\t\t}, timeout);\n
}\n
function start() {\n
\t// A slight delay, to avoid any current callbacks\n
\tsetTimeout(function() {\n
\t\tif(config.timeout)\n
\t\t\tclearTimeout(config.timeout);\n
\t\tconfig.blocking = false;\n
\t\tprocess();\n
\t}, 13);\n
}\n
\n
function validTest( name ) {\n
\tvar i = config.filters.length,\n
\t\trun = false;\n
\n
\tif( !i )\n
\t\treturn true;\n
\t\n
\twhile( i-- ){\n
\t\tvar filter = config.filters[i],\n
\t\t\tnot = filter.charAt(0) == \'!\';\n
\t\tif( not ) \n
\t\t\tfilter = filter.slice(1);\n
\t\tif( name.indexOf(filter) != -1 )\n
\t\t\treturn !not;\n
\t\tif( not )\n
\t\t\trun = true;\n
\t}\n
\treturn run;\n
}\n
\n
function runTest() {\n
\tconfig.blocking = false;\n
\tvar started = +new Date;\n
\tconfig.fixture = document.getElementById(\'main\').innerHTML;\n
\tconfig.ajaxSettings = $.ajaxSettings;\n
\tsynchronize(function() {\n
\t\t$(\'<p id="testresult" class="result"/>\').html([\'Tests completed in \',\n
\t\t\t+new Date - started, \' milliseconds.<br/>\',\n
\t\t\t\'<span class="bad">\', config.stats.bad, \'</span> tests of <span class="all">\', config.stats.all, \'</span> failed.\']\n
\t\t\t.join(\'\'))\n
\t\t\t.appendTo("body");\n
\t\t$("#banner").addClass(config.stats.bad ? "fail" : "pass");\n
\t\tQUnit.done( config.stats.bad, config.stats.all );\n
\t});\n
}\n
\n
var pollution;\n
\n
function saveGlobal(){\n
\tpollution = [ ];\n
\t\n
\tif( noglobals )\n
\t\tfor( var key in window )\n
\t\t\tpollution.push(key);\n
}\n
function checkPollution( name ){\n
\tvar old = pollution;\n
\tsaveGlobal();\n
\t\n
\tif( pollution.length > old.length ){\n
\t\tok( false, "Introduced global variable(s): " + diff(old, pollution).join(", ") );\n
\t\tconfig.expected++;\n
\t}\n
}\n
\n
function diff( clean, dirty ){\n
\treturn $.grep( dirty, function(name){\n
\t\treturn $.inArray( name, clean ) == -1;\n
\t});\n
}\n
\n
function test(name, callback) {\n
\tif(config.currentModule)\n
\t\tname = config.currentModule + " module: " + name;\n
\tvar lifecycle = $.extend({\n
\t\tsetup: function() {},\n
\t\tteardown: function() {}\n
\t}, config.moduleLifecycle);\n
\t\n
\tif ( !validTest(name) )\n
\t\treturn;\n
\t\n
\tsynchronize(function() {\n
\t\tconfig.assertions = [];\n
\t\tconfig.expected = null;\n
\t\ttry {\n
\t\t\tif( !pollution )\n
\t\t\t\tsaveGlobal();\n
\t\t\tlifecycle.setup();\n
\t\t} catch(e) {\n
\t\t\tQUnit.ok( false, "Setup failed on " + name + ": " + e.message );\n
\t\t}\n
\t})\n
\tsynchronize(function() {\n
\t\ttry {\n
\t\t\tcallback();\n
\t\t} catch(e) {\n
\t\t\tif( typeof console != "undefined" && console.error && console.warn ) {\n
\t\t\t\tconsole.error("Test " + name + " died, exception and test follows");\n
\t\t\t\tconsole.error(e);\n
\t\t\t\tconsole.warn(callback.toString());\n
\t\t\t}\n
\t\t\tQUnit.ok( false, "Died on test #" + (config.assertions.length + 1) + ": " + e.message );\n
\t\t\t// else next test will carry the responsibility\n
\t\t\tsaveGlobal();\n
\t\t}\n
\t});\n
\tsynchronize(function() {\n
\t\ttry {\n
\t\t\tcheckPollution();\n
\t\t\tlifecycle.teardown();\n
\t\t} catch(e) {\n
\t\t\tQUnit.ok( false, "Teardown failed on " + name + ": " + e.message );\n
\t\t}\n
\t})\n
\tsynchronize(function() {\n
\t\ttry {\n
\t\t\treset();\n
\t\t} catch(e) {\n
\t\t\tif( typeof console != "undefined" && console.error && console.warn ) {\n
\t\t\t\tconsole.error("reset() failed, following Test " + name + ", exception and reset fn follows");\n
\t\t\t\tconsole.error(e);\n
\t\t\t\tconsole.warn(reset.toString());\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tif(config.expected && config.expected != config.assertions.length) {\n
\t\t\tQUnit.ok( false, "Expected " + config.expected + " assertions, but " + config.assertions.length + " were run" );\n
\t\t}\n
\t\t\n
\t\tvar good = 0, bad = 0;\n
\t\tvar ol  = $("<ol/>").hide();\n
\t\tconfig.stats.all += config.assertions.length;\n
\t\tfor ( var i = 0; i < config.assertions.length; i++ ) {\n
\t\t\tvar assertion = config.assertions[i];\n
\t\t\t$("<li/>").addClass(assertion.result ? "pass" : "fail").text(assertion.message || "(no message)").appendTo(ol);\n
\t\t\tassertion.result ? good++ : bad++;\n
\t\t}\n
\t\tconfig.stats.bad += bad;\n
\t\n
\t\tvar b = $("<strong/>").html(name + " <b style=\'color:black;\'>(<b class=\'fail\'>" + bad + "</b>, <b class=\'pass\'>" + good + "</b>, " + config.assertions.length + ")</b>")\n
\t\t.click(function(){\n
\t\t\t$(this).next().toggle();\n
\t\t})\n
\t\t.dblclick(function(event) {\n
\t\t\tvar target = $(event.target).filter("strong").clone();\n
\t\t\tif ( target.length ) {\n
\t\t\t\ttarget.children().remove();\n
\t\t\t\tlocation.href = location.href.match(/^(.+?)(\\?.*)?$/)[1] + "?" + encodeURIComponent($.trim(target.text()));\n
\t\t\t}\n
\t\t});\n
\t\t\n
\t\t$("<li/>").addClass(bad ? "fail" : "pass").append(b).append(ol).appendTo("#tests");\n
\t\n
\t\tif(bad) {\n
\t\t\t$("#filter-pass").attr("disabled", null);\n
\t\t\t$("#filter-missing").attr("disabled", null);\n
\t\t}\n
\t});\n
}\n
\n
// call on start of module test to prepend name to all tests\n
function module(name, lifecycle) {\n
\tconfig.currentModule = name;\n
\tconfig.moduleLifecycle = lifecycle;\n
}\n
\n
/**\n
 * Specify the number of expected assertions to gurantee that failed test (no assertions are run at all) don\'t slip through.\n
 */\n
function expect(asserts) {\n
\tconfig.expected = asserts;\n
}\n
\n
/**\n
 * Resets the test setup. Useful for tests that modify the DOM.\n
 */\n
function reset() {\n
\t$("#main").html( config.fixture );\n
\t$.event.global = {};\n
\t$.ajaxSettings = $.extend({}, config.ajaxSettings);\n
}\n
\n
/**\n
 * Asserts true.\n
 * @example ok( $("a").size() > 5, "There must be at least 5 anchors" );\n
 */\n
function ok(a, msg) {\n
\tQUnit.log(a, msg);\n
\n
\tconfig.assertions.push({\n
\t\tresult: !!a,\n
\t\tmessage: msg\n
\t});\n
}\n
\n
/**\n
 * Asserts that two arrays are the same\n
 */\n
function isSet(a, b, msg) {\n
\tfunction serialArray( a ) {\n
\t\tvar r = [];\n
\t\t\n
\t\tif ( a && a.length )\n
\t        for ( var i = 0; i < a.length; i++ ) {\n
\t            var str = a[i].nodeName;\n
\t            if ( str ) {\n
\t                str = str.toLowerCase();\n
\t                if ( a[i].id )\n
\t                    str += "#" + a[i].id;\n
\t            } else\n
\t                str = a[i];\n
\t            r.push( str );\n
\t        }\n
\t\n
\t\treturn "[ " + r.join(", ") + " ]";\n
\t}\n
\tvar ret = true;\n
\tif ( a && b && a.length != undefined && a.length == b.length ) {\n
\t\tfor ( var i = 0; i < a.length; i++ )\n
\t\t\tif ( a[i] != b[i] )\n
\t\t\t\tret = false;\n
\t} else\n
\t\tret = false;\n
\tQUnit.ok( ret, !ret ? (msg + " expected: " + serialArray(b) + " result: " + serialArray(a)) : msg );\n
}\n
\n
/**\n
 * Asserts that two objects are equivalent\n
 */\n
function isObj(a, b, msg) {\n
\tvar ret = true;\n
\t\n
\tif ( a && b ) {\n
\t\tfor ( var i in a )\n
\t\t\tif ( a[i] != b[i] )\n
\t\t\t\tret = false;\n
\n
\t\tfor ( i in b )\n
\t\t\tif ( a[i] != b[i] )\n
\t\t\t\tret = false;\n
\t} else\n
\t\tret = false;\n
\n
    QUnit.ok( ret, msg );\n
}\n
\n
/**\n
 * Returns an array of elements with the given IDs, eg.\n
 * @example q("main", "foo", "bar")\n
 * @result [<div id="main">, <span id="foo">, <input id="bar">]\n
 */\n
function q() {\n
\tvar r = [];\n
\tfor ( var i = 0; i < arguments.length; i++ )\n
\t\tr.push( document.getElementById( arguments[i] ) );\n
\treturn r;\n
}\n
\n
/**\n
 * Asserts that a select matches the given IDs\n
 * @example t("Check for something", "//[a]", ["foo", "baar"]);\n
 * @result returns true if "//[a]" return two elements with the IDs \'foo\' and \'baar\'\n
 */\n
function t(a,b,c) {\n
\tvar f = $(b);\n
\tvar s = "";\n
\tfor ( var i = 0; i < f.length; i++ )\n
\t\ts += (s && ",") + \'"\' + f[i].id + \'"\';\n
\tisSet(f, q.apply(q,c), a + " (" + b + ")");\n
}\n
\n
/**\n
 * Add random number to url to stop IE from caching\n
 *\n
 * @example url("data/test.html")\n
 * @result "data/test.html?10538358428943"\n
 *\n
 * @example url("data/test.php?foo=bar")\n
 * @result "data/test.php?foo=bar&10538358345554"\n
 */\n
function url(value) {\n
\treturn value + (/\\?/.test(value) ? "&" : "?") + new Date().getTime() + "" + parseInt(Math.random()*100000);\n
}\n
\n
/**\n
 * Checks that the first two arguments are equal, with an optional message.\n
 * Prints out both actual and expected values.\n
 *\n
 * Prefered to ok( actual == expected, message )\n
 *\n
 * @example equals( $.format("Received {0} bytes.", 2), "Received 2 bytes." );\n
 *\n
 * @param Object actual\n
 * @param Object expected\n
 * @param String message (optional)\n
 */\n
function equals(actual, expected, message) {\n
\tpush(expected == actual, actual, expected, message);\n
}\n
\n
function push(result, actual, expected, message) {\n
\tmessage = message || (result ? "okay" : "failed");\n
\tQUnit.ok( result, result ? message + ": " + expected : message + ", expected: " + jsDump.parse(expected) + " result: " + jsDump.parse(actual) );\n
}\n
\n
/**\n
 * Trigger an event on an element.\n
 *\n
 * @example triggerEvent( document.body, "click" );\n
 *\n
 * @param DOMElement elem\n
 * @param String type\n
 */\n
function triggerEvent( elem, type, event ) {\n
\tif ( $.browser.mozilla || $.browser.opera ) {\n
\t\tevent = document.createEvent("MouseEvents");\n
\t\tevent.initMouseEvent(type, true, true, elem.ownerDocument.defaultView,\n
\t\t\t0, 0, 0, 0, 0, false, false, false, false, 0, null);\n
\t\telem.dispatchEvent( event );\n
\t} else if ( $.browser.msie ) {\n
\t\telem.fireEvent("on"+type);\n
\t}\n
}\n
\n
})(jQuery);\n
\n
/**\n
 * jsDump\n
 * Copyright (c) 2008 Ariel Flesler - aflesler(at)gmail(dot)com | http://flesler.blogspot.com\n
 * Licensed under BSD (http://www.opensource.org/licenses/bsd-license.php)\n
 * Date: 5/15/2008\n
 * @projectDescription Advanced and extensible data dumping for Javascript.\n
 * @version 1.0.0\n
 * @author Ariel Flesler\n
 * @link {http://flesler.blogspot.com/2008/05/jsdump-pretty-dump-of-any-javascript.html}\n
 */\n
(function(){\n
\tfunction quote( str ){\n
\t\treturn \'"\' + str.toString().replace(/"/g, \'\\\\"\') + \'"\';\n
\t};\n
\tfunction literal( o ){\n
\t\treturn o + \'\';\t\n
\t};\n
\tfunction join( pre, arr, post ){\n
\t\tvar s = jsDump.separator(),\n
\t\t\tbase = jsDump.indent();\n
\t\t\tinner = jsDump.indent(1);\n
\t\tif( arr.join )\n
\t\t\tarr = arr.join( \',\' + s + inner );\n
\t\tif( !arr )\n
\t\t\treturn pre + post;\n
\t\treturn [ pre, inner + arr, base + post ].join(s);\n
\t};\n
\tfunction array( arr ){\n
\t\tvar i = arr.length,\tret = Array(i);\t\t\t\t\t\n
\t\tthis.up();\n
\t\twhile( i-- )\n
\t\t\tret[i] = this.parse( arr[i] );\t\t\t\t\n
\t\tthis.down();\n
\t\treturn join( \'[\', ret, \']\' );\n
\t};\n
\t\n
\tvar reName = /^function (\\w+)/;\n
\t\n
\tvar jsDump = window.jsDump = {\n
\t\tparse:function( obj, type ){//type is used mostly internally, you can fix a (custom)type in advance\n
\t\t\tvar\tparser = this.parsers[ type || this.typeOf(obj) ];\n
\t\t\ttype = typeof parser;\t\t\t\n
\t\t\t\n
\t\t\treturn type == \'function\' ? parser.call( this, obj ) :\n
\t\t\t\t   type == \'string\' ? parser :\n
\t\t\t\t   this.parsers.error;\n
\t\t},\n
\t\ttypeOf:function( obj ){\n
\t\t\tvar type = typeof obj,\n
\t\t\t\tf = \'function\';//we\'ll use it 3 times, save it\n
\t\t\treturn type != \'object\' && type != f ? type :\n
\t\t\t\t!obj ? \'null\' :\n
\t\t\t\tobj.exec ? \'regexp\' :// some browsers (FF) consider regexps functions\n
\t\t\t\tobj.getHours ? \'date\' :\n
\t\t\t\tobj.scrollBy ?  \'window\' :\n
\t\t\t\tobj.nodeName == \'#document\' ? \'document\' :\n
\t\t\t\tobj.nodeName ? \'node\' :\n
\t\t\t\tobj.item ? \'nodelist\' : // Safari reports nodelists as functions\n
\t\t\t\tobj.callee ? \'arguments\' :\n
\t\t\t\tobj.call || obj.constructor != Array && //an array would also fall on this hack\n
\t\t\t\t\t(obj+\'\').indexOf(f) != -1 ? f : //IE reports functions like alert, as objects\n
\t\t\t\t\'length\' in obj ? \'array\' :\n
\t\t\t\ttype;\n
\t\t},\n
\t\tseparator:function(){\n
\t\t\treturn this.multiline ?\tthis.HTML ? \'<br />\' : \'\\n\' : this.HTML ? \'&nbsp;\' : \' \';\n
\t\t},\n
\t\tindent:function( extra ){// extra can be a number, shortcut for increasing-calling-decreasing\n
\t\t\tif( !this.multiline )\n
\t\t\t\treturn \'\';\n
\t\t\tvar chr = this.indentChar;\n
\t\t\tif( this.HTML )\n
\t\t\t\tchr = chr.replace(/\\t/g,\'   \').replace(/ /g,\'&nbsp;\');\n
\t\t\treturn Array( this._depth_ + (extra||0) ).join(chr);\n
\t\t},\n
\t\tup:function( a ){\n
\t\t\tthis._depth_ += a || 1;\n
\t\t},\n
\t\tdown:function( a ){\n
\t\t\tthis._depth_ -= a || 1;\n
\t\t},\n
\t\tsetParser:function( name, parser ){\n
\t\t\tthis.parsers[name] = parser;\n
\t\t},\n
\t\t// The next 3 are exposed so you can use them\n
\t\tquote:quote, \n
\t\tliteral:literal,\n
\t\tjoin:join,\n
\t\t//\n
\t\t_depth_: 1,\n
\t\t// This is the list of parsers, to modify them, use jsDump.setParser\n
\t\tparsers:{\n
\t\t\twindow: \'[Window]\',\n
\t\t\tdocument: \'[Document]\',\n
\t\t\terror:\'[ERROR]\', //when no parser is found, shouldn\'t happen\n
\t\t\tunknown: \'[Unknown]\',\n
\t\t\t\'null\':\'null\',\n
\t\t\tundefined:\'undefined\',\n
\t\t\t\'function\':function( fn ){\n
\t\t\t\tvar ret = \'function\',\n
\t\t\t\t\tname = \'name\' in fn ? fn.name : (reName.exec(fn)||[])[1];//functions never have name in IE\n
\t\t\t\tif( name )\n
\t\t\t\t\tret += \' \' + name;\n
\t\t\t\tret += \'(\';\n
\t\t\t\t\n
\t\t\t\tret = [ ret, this.parse( fn, \'functionArgs\' ), \'){\'].join(\'\');\n
\t\t\t\treturn join( ret, this.parse(fn,\'functionCode\'), \'}\' );\n
\t\t\t},\n
\t\t\tarray: array,\n
\t\t\tnodelist: array,\n
\t\t\targuments: array,\n
\t\t\tobject:function( map ){\n
\t\t\t\tvar ret = [ ];\n
\t\t\t\tthis.up();\n
\t\t\t\tfor( var key in map )\n
\t\t\t\t\tret.push( this.parse(key,\'key\') + \': \' + this.parse(map[key]) );\n
\t\t\t\tthis.down();\n
\t\t\t\treturn join( \'{\', ret, \'}\' );\n
\t\t\t},\n
\t\t\tnode:function( node ){\n
\t\t\t\tvar open = this.HTML ? \'&lt;\' : \'<\',\n
\t\t\t\t\tclose = this.HTML ? \'&gt;\' : \'>\';\n
\t\t\t\t\t\n
\t\t\t\tvar tag = node.nodeName.toLowerCase(),\n
\t\t\t\t\tret = open + tag;\n
\t\t\t\t\t\n
\t\t\t\tfor( var a in this.DOMAttrs ){\n
\t\t\t\t\tvar val = node[this.DOMAttrs[a]];\n
\t\t\t\t\tif( val )\n
\t\t\t\t\t\tret += \' \' + a + \'=\' + this.parse( val, \'attribute\' );\n
\t\t\t\t}\n
\t\t\t\treturn ret + close + open + \'/\' + tag + close;\n
\t\t\t},\n
\t\t\tfunctionArgs:function( fn ){//function calls it internally, it\'s the arguments part of the function\n
\t\t\t\tvar l = fn.length;\n
\t\t\t\tif( !l ) return \'\';\t\t\t\t\n
\t\t\t\t\n
\t\t\t\tvar args = Array(l);\n
\t\t\t\twhile( l-- )\n
\t\t\t\t\targs[l] = String.fromCharCode(97+l);//97 is \'a\'\n
\t\t\t\treturn \' \' + args.join(\', \') + \' \';\n
\t\t\t},\n
\t\t\tkey:quote, //object calls it internally, the key part of an item in a map\n
\t\t\tfunctionCode:\'[code]\', //function calls it internally, it\'s the content of the function\n
\t\t\tattribute:quote, //node calls it internally, it\'s an html attribute value\n
\t\t\tstring:quote,\n
\t\t\tdate:quote,\n
\t\t\tregexp:literal, //regex\n
\t\t\tnumber:literal,\n
\t\t\t\'boolean\':literal\n
\t\t},\n
\t\tDOMAttrs:{//attributes to dump from nodes, name=>realName\n
\t\t\tid:\'id\',\n
\t\t\tname:\'name\',\n
\t\t\t\'class\':\'className\'\n
\t\t},\n
\t\tHTML:false,//if true, entities are escaped ( <, >, \\t, space and \\n )\n
\t\tindentChar:\'   \',//indentation unit\n
\t\tmultiline:true //if true, items in a collection, are separated by a \\n, else just a space.\n
\t};\n
\n
})();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <long>22048</long> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
