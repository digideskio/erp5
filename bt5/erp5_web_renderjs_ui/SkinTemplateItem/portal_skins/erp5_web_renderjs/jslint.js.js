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
            <value> <string>ts21078299.16</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jslint.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// jslint.js\n
// 2014-04-21\n
\n
// Copyright (c) 2002 Douglas Crockford  (www.JSLint.com)\n
\n
// Permission is hereby granted, free of charge, to any person obtaining a copy\n
// of this software and associated documentation files (the "Software"), to deal\n
// in the Software without restriction, including without limitation the rights\n
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n
// copies of the Software, and to permit persons to whom the Software is\n
// furnished to do so, subject to the following conditions:\n
\n
// The above copyright notice and this permission notice shall be included in\n
// all copies or substantial portions of the Software.\n
\n
// The Software shall be used for Good, not Evil.\n
\n
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n
// SOFTWARE.\n
\n
// WARNING: JSLint will hurt your feelings.\n
\n
// JSLINT is a global function. It takes two parameters.\n
\n
//     var myResult = JSLINT(source, option);\n
\n
// The first parameter is either a string or an array of strings. If it is a\n
// string, it will be split on \'\\n\' or \'\\r\'. If it is an array of strings, it\n
// is assumed that each string represents one line. The source can be a\n
// JavaScript text or a JSON text.\n
\n
// The second parameter is an optional object of options that control the\n
// operation of JSLINT. Most of the options are booleans: They are all\n
// optional and have a default value of false. One of the options, predef,\n
// can be an array of names, which will be used to declare global variables,\n
// or an object whose keys are used as global names, with a boolean value\n
// that determines if they are assignable.\n
\n
// If it checks out, JSLINT returns true. Otherwise, it returns false.\n
\n
// If false, you can inspect JSLINT.errors to find out the problems.\n
// JSLINT.errors is an array of objects containing these properties:\n
\n
//  {\n
//      line      : The line (relative to 0) at which the lint was found\n
//      character : The character (relative to 0) at which the lint was found\n
//      reason    : The problem\n
//      evidence  : The text line in which the problem occurred\n
//      raw       : The raw message before the details were inserted\n
//      a         : The first detail\n
//      b         : The second detail\n
//      c         : The third detail\n
//      d         : The fourth detail\n
//  }\n
\n
// If a stopping error was found, a null will be the last element of the\n
// JSLINT.errors array. A stopping error means that JSLint was not confident\n
// enough to continue. It does not necessarily mean that the error was\n
// especially heinous.\n
\n
// You can request a data structure that contains JSLint\'s results.\n
\n
//     var myData = JSLINT.data();\n
\n
// It returns a structure with this form:\n
\n
//     {\n
//         errors: [\n
//             {\n
//                 line: NUMBER,\n
//                 character: NUMBER,\n
//                 reason: STRING,\n
//                 evidence: STRING\n
//             }\n
//         ],\n
//         functions: [\n
//             {\n
//                 name: STRING,\n
//                 line: NUMBER,\n
//                 level: NUMBER,\n
//                 parameter: [\n
//                     STRING\n
//                 ],\n
//                 var: [\n
//                     STRING\n
//                 ],\n
//                 exception: [\n
//                     STRING\n
//                 ],\n
//                 closure: [\n
//                     STRING\n
//                 ],\n
//                 outer: [\n
//                     STRING\n
//                 ],\n
//                 global: [\n
//                     STRING\n
//                 ],\n
//                 label: [\n
//                     STRING\n
//                 ]\n
//             }\n
//         ],\n
//         global: [\n
//             STRING\n
//         ],\n
//         member: {\n
//             STRING: NUMBER\n
//         },\n
//         json: BOOLEAN\n
//     }\n
\n
// You can request a Function Report, which shows all of the functions\n
// and the parameters and vars that they use. This can be used to find\n
// implied global variables and other problems. The report is in HTML and\n
// can be inserted into an HTML <body>. It should be given the result of the\n
// JSLINT.data function.\n
\n
//     var myReport = JSLINT.report(data);\n
\n
// You can request an HTML error report.\n
\n
//     var myErrorReport = JSLINT.error_report(data);\n
\n
// You can obtain an object containing all of the properties found in the\n
// file. JSLINT.property contains an object containing a key for each\n
// property used in the program, the value being the number of times that\n
// property name was used in the file.\n
\n
// You can request a properties report, which produces a list of the program\'s\n
// properties in the form of a /*properties*/ declaration.\n
\n
//      var myPropertyReport = JSLINT.properties_report(JSLINT.property);\n
\n
// You can obtain the parse tree that JSLint constructed while parsing. The\n
// latest tree is kept in JSLINT.tree. A nice stringification can be produced\n
// with\n
\n
//     JSON.stringify(JSLINT.tree, [\n
//         \'string\',  \'arity\', \'name\',  \'first\',\n
//         \'second\', \'third\', \'block\', \'else\'\n
//     ], 4));\n
\n
// You can request a context coloring table. It contains information that can be\n
// applied to the file that was analyzed. Context coloring colors functions\n
// based on their nesting level, and variables on the color of the functions\n
// in which they are defined.\n
\n
//      var myColorization = JSLINT.color(data);\n
\n
// It returns an array containing objects of this form:\n
\n
//      {\n
//          from: COLUMN,\n
//          thru: COLUMN,\n
//          line: ROW,\n
//          level: 0 or higher\n
//      }\n
\n
// JSLint provides three inline directives. They look like slashstar comments,\n
// and allow for setting options, declaring global variables, and establishing a\n
// set of allowed property names.\n
\n
// These directives respect function scope.\n
\n
// The jslint directive is a special comment that can set one or more options.\n
// For example:\n
\n
/*jslint\n
    evil: true, nomen: true, regexp: true, todo: true\n
*/\n
\n
// The current option set is\n
\n
//     ass        true, if assignment expressions should be allowed\n
//     bitwise    true, if bitwise operators should be allowed\n
//     browser    true, if the standard browser globals should be predefined\n
//     closure    true, if Google Closure idioms should be tolerated\n
//     continue   true, if the continuation statement should be tolerated\n
//     debug      true, if debugger statements should be allowed\n
//     devel      true, if logging should be allowed (console, alert, etc.)\n
//     eqeq       true, if == should be allowed\n
//     evil       true, if eval should be allowed\n
//     forin      true, if for in statements need not filter\n
//     indent     the indentation factor\n
//     maxerr     the maximum number of errors to allow\n
//     maxlen     the maximum length of a source line\n
//     newcap     true, if constructor names capitalization is ignored\n
//     node       true, if Node.js globals should be predefined\n
//     nomen      true, if names may have dangling _\n
//     passfail   true, if the scan should stop on first error\n
//     plusplus   true, if increment/decrement should be allowed\n
//     properties true, if all property names must be declared with /*properties*/\n
//     regexp     true, if the . should be allowed in regexp literals\n
//     rhino      true, if the Rhino environment globals should be predefined\n
//     unparam    true, if unused parameters should be tolerated\n
//     sloppy     true, if the \'use strict\'; pragma is optional\n
//     stupid     true, if really stupid practices are tolerated\n
//     sub        true, if all forms of subscript notation are tolerated\n
//     todo       true, if TODO comments are tolerated\n
//     vars       true, if multiple var statements per function should be allowed\n
//     white      true, if sloppy whitespace is tolerated\n
\n
// The properties directive declares an exclusive list of property names.\n
// Any properties named in the program that are not in the list will\n
// produce a warning.\n
\n
// For example:\n
\n
/*properties\n
    \'\\b\', \'\\t\', \'\\n\', \'\\f\', \'\\r\', \'!\', \'!=\', \'!==\', \'"\', \'%\', \'\\\'\', \'(begin)\',\n
    \'(error)\', \'*\', \'+\', \'-\', \'/\', \'<\', \'<=\', \'==\', \'===\', \'>\', \'>=\', \'\\\\\', a,\n
    a_label, a_scope, already_defined, and, apply, arguments, arity, ass,\n
    assign, assignment_expression, assignment_function_expression, at, avoid_a,\n
    b, bad_assignment, bad_constructor, bad_in_a, bad_invocation, bad_new,\n
    bad_number, bad_operand, bad_wrap, bitwise, block, break, breakage, browser,\n
    c, call, charAt, charCodeAt, character, closure, code, color, combine_var,\n
    comments, conditional_assignment, confusing_a, confusing_regexp,\n
    constructor_name_a, continue, control_a, couch, create, d, dangling_a, data,\n
    dead, debug, deleted, devel, disrupt, duplicate_a, edge, edition, elif,\n
    else, empty_block, empty_case, empty_class, entityify, eqeq, error_report,\n
    errors, evidence, evil, exception, exec, expected_a_at_b_c, expected_a_b,\n
    expected_a_b_from_c_d, expected_id_a, expected_identifier_a,\n
    expected_identifier_a_reserved, expected_number_a, expected_operator_a,\n
    expected_positive_a, expected_small_a, expected_space_a_b,\n
    expected_string_a, f, first, flag, floor, forEach, for_if, forin, from,\n
    fromCharCode, fud, function, function_block, function_eval, function_loop,\n
    function_statement, function_strict, functions, global, hasOwnProperty, id,\n
    identifier, identifier_function, immed, implied_evil, indent, indexOf,\n
    infix_in, init, insecure_a, isAlpha, isArray, isDigit, isNaN, join, jslint,\n
    json, keys, kind, label, labeled, lbp, leading_decimal_a, led, left, length,\n
    level, line, loopage, master, match, maxerr, maxlen, message, missing_a,\n
    missing_a_after_b, missing_property, missing_space_a_b, missing_use_strict,\n
    mode, move_invocation, move_var, n, name, name_function, nested_comment,\n
    newcap, node, nomen, not, not_a_constructor, not_a_defined, not_a_function,\n
    not_a_label, not_a_scope, not_greater, nud, number, octal_a, open, outer,\n
    parameter, parameter_a_get_b, parameter_arguments_a, parameter_set_a,\n
    params, paren, passfail, plusplus, pop, postscript, predef, properties,\n
    properties_report, property, prototype, push, quote, r, radix, raw,\n
    read_only, reason, redefinition_a_b, regexp, relation, replace, report,\n
    reserved, reserved_a, rhino, right, scanned_a_b, scope, search, second,\n
    shift, slash_equal, slice, sloppy, sort, split, statement, statement_block,\n
    stop, stopping, strange_loop, strict, string, stupid, sub, subscript,\n
    substr, supplant, sync_a, t, tag_a_in_b, test, third, thru, toString, todo,\n
    todo_comment, token, tokens, too_long, too_many, trailing_decimal_a, tree,\n
    unclosed, unclosed_comment, unclosed_regexp, unescaped_a, unexpected_a,\n
    unexpected_char_a, unexpected_comment, unexpected_label_a,\n
    unexpected_property_a, unexpected_space_a_b, unexpected_typeof_a,\n
    uninitialized_a, unnecessary_else, unnecessary_initialize, unnecessary_use,\n
    unparam, unreachable_a_b, unsafe, unused_a, url, use_array, use_braces,\n
    use_nested_if, use_object, use_or, use_param, use_spaces, used,\n
    used_before_a, var, var_a_not, var_loop, vars, varstatement, warn, warning,\n
    was, weird_assignment, weird_condition, weird_new, weird_program,\n
    weird_relation, weird_ternary, white, wrap, wrap_immediate, wrap_regexp,\n
    write_is_wrong, writeable\n
*/\n
\n
// The global directive is used to declare global variables that can\n
// be accessed by the program. If a declaration is true, then the variable\n
// is writeable. Otherwise, it is read-only.\n
\n
// We build the application inside a function so that we produce only a single\n
// global variable. That function will be invoked immediately, and its return\n
// value is the JSLINT function itself. That function is also an object that\n
// can contain data and other functions.\n
\n
var JSLINT = (function () {\n
    \'use strict\';\n
\n
    function array_to_object(array, value) {\n
\n
// Make an object from an array of keys and a common value.\n
\n
        var i, length = array.length, object = Object.create(null);\n
        for (i = 0; i < length; i += 1) {\n
            object[array[i]] = value;\n
        }\n
        return object;\n
    }\n
\n
\n
    var allowed_option = {\n
            ass       : true,\n
            bitwise   : true,\n
            browser   : true,\n
            closure   : true,\n
            continue  : true,\n
            couch     : true,\n
            debug     : true,\n
            devel     : true,\n
            eqeq      : true,\n
            evil      : true,\n
            forin     : true,\n
            indent    :   10,\n
            maxerr    : 1000,\n
            maxlen    :  256,\n
            newcap    : true,\n
            node      : true,\n
            nomen     : true,\n
            passfail  : true,\n
            plusplus  : true,\n
            properties: true,\n
            regexp    : true,\n
            rhino     : true,\n
            unparam   : true,\n
            sloppy    : true,\n
            stupid    : true,\n
            sub       : true,\n
            todo      : true,\n
            vars      : true,\n
            white     : true\n
        },\n
        anonname,       // The guessed name for anonymous functions.\n
\n
// These are operators that should not be used with the ! operator.\n
\n
        bang = {\n
            \'<\'  : true,\n
            \'<=\' : true,\n
            \'==\' : true,\n
            \'===\': true,\n
            \'!==\': true,\n
            \'!=\' : true,\n
            \'>\'  : true,\n
            \'>=\' : true,\n
            \'+\'  : true,\n
            \'-\'  : true,\n
            \'*\'  : true,\n
            \'/\'  : true,\n
            \'%\'  : true\n
        },\n
        begin,          // The root token\n
        block_var,     // vars defined in the current block\n
\n
// browser contains a set of global names that are commonly provided by a\n
// web browser environment.\n
\n
        browser = array_to_object([\n
            \'clearInterval\', \'clearTimeout\', \'document\', \'event\', \'FormData\',\n
            \'frames\', \'history\', \'Image\', \'localStorage\', \'location\', \'name\',\n
            \'navigator\', \'Option\', \'parent\', \'screen\', \'sessionStorage\',\n
            \'setInterval\', \'setTimeout\', \'Storage\', \'window\', \'XMLHttpRequest\'\n
        ], false),\n
\n
// bundle contains the text messages.\n
\n
        bundle = {\n
            a_label: "\'{a}\' is a statement label.",\n
            a_scope: "\'{a}\' used out of scope.",\n
            already_defined: "\'{a}\' is already defined.",\n
            and: "The \'&&\' subexpression should be wrapped in parens.",\n
            assignment_expression: "Unexpected assignment expression.",\n
            assignment_function_expression: "Expected an assignment or " +\n
                "function call and instead saw an expression.",\n
            avoid_a: "Avoid \'{a}\'.",\n
            bad_assignment: "Bad assignment.",\n
            bad_constructor: "Bad constructor.",\n
            bad_in_a: "Bad for in variable \'{a}\'.",\n
            bad_invocation: "Bad invocation.",\n
            bad_new: "Do not use \'new\' for side effects.",\n
            bad_number: "Bad number \'{a}\'.",\n
            bad_operand: "Bad operand.",\n
            bad_wrap: "Do not wrap function literals in parens unless they " +\n
                "are to be immediately invoked.",\n
            combine_var: "Combine this with the previous \'var\' statement.",\n
            conditional_assignment: "Expected a conditional expression and " +\n
                "instead saw an assignment.",\n
            confusing_a: "Confusing use of \'{a}\'.",\n
            confusing_regexp: "Confusing regular expression.",\n
            constructor_name_a: "A constructor name \'{a}\' should start with " +\n
                "an uppercase letter.",\n
            control_a: "Unexpected control character \'{a}\'.",\n
            dangling_a: "Unexpected dangling \'_\' in \'{a}\'.",\n
            deleted: "Only properties should be deleted.",\n
            duplicate_a: "Duplicate \'{a}\'.",\n
            empty_block: "Empty block.",\n
            empty_case: "Empty case.",\n
            empty_class: "Empty class.",\n
            evil: "eval is evil.",\n
            expected_a_b: "Expected \'{a}\' and instead saw \'{b}\'.",\n
            expected_a_b_from_c_d: "Expected \'{a}\' to match \'{b}\' from line " +\n
                "{c} and instead saw \'{d}\'.",\n
            expected_a_at_b_c: "Expected \'{a}\' at column {b}, not column {c}.",\n
            expected_id_a: "Expected an id, and instead saw #{a}.",\n
            expected_identifier_a: "Expected an identifier and instead saw \'{a}\'.",\n
            expected_identifier_a_reserved: "Expected an identifier and " +\n
                "instead saw \'{a}\' (a reserved word).",\n
            expected_number_a: "Expected a number and instead saw \'{a}\'.",\n
            expected_operator_a: "Expected an operator and instead saw \'{a}\'.",\n
            expected_positive_a: "Expected a positive number and instead saw \'{a}\'",\n
            expected_small_a: "Expected a small positive integer and instead saw \'{a}\'",\n
            expected_space_a_b: "Expected exactly one space between \'{a}\' and \'{b}\'.",\n
            expected_string_a: "Expected a string and instead saw \'{a}\'.",\n
            for_if: "The body of a for in should be wrapped in an if " +\n
                "statement to filter unwanted properties from the prototype.",\n
            function_block: "Function statements should not be placed in blocks." +\n
                "Use a function expression or move the statement to the top of " +\n
                "the outer function.",\n
            function_eval: "The Function constructor is eval.",\n
            function_loop: "Don\'t make functions within a loop.",\n
            function_statement: "Function statements are not invocable. " +\n
                "Wrap the whole function invocation in parens.",\n
            function_strict: "Use the function form of \'use strict\'.",\n
            identifier_function: "Expected an identifier in an assignment " +\n
                "and instead saw a function invocation.",\n
            implied_evil: "Implied eval is evil. Pass a function instead of a string.",\n
            infix_in: "Unexpected \'in\'. Compare with undefined, or use the " +\n
                "hasOwnProperty method instead.",\n
            insecure_a: "Insecure \'{a}\'.",\n
            isNaN: "Use the isNaN function to compare with NaN.",\n
            leading_decimal_a: "A leading decimal point can be confused with a dot: \'.{a}\'.",\n
            missing_a: "Missing \'{a}\'.",\n
            missing_a_after_b: "Missing \'{a}\' after \'{b}\'.",\n
            missing_property: "Missing property name.",\n
            missing_space_a_b: "Missing space between \'{a}\' and \'{b}\'.",\n
            missing_use_strict: "Missing \'use strict\' statement.",\n
            move_invocation: "Move the invocation into the parens that " +\n
                "contain the function.",\n
            move_var: "Move \'var\' declarations to the top of the function.",\n
            name_function: "Missing name in function statement.",\n
            nested_comment: "Nested comment.",\n
            not: "Nested not.",\n
            not_a_constructor: "Do not use {a} as a constructor.",\n
            not_a_defined: "\'{a}\' has not been fully defined yet.",\n
            not_a_function: "\'{a}\' is not a function.",\n
            not_a_label: "\'{a}\' is not a label.",\n
            not_a_scope: "\'{a}\' is out of scope.",\n
            not_greater: "\'{a}\' should not be greater than \'{b}\'.",\n
            octal_a: "Don\'t use octal: \'{a}\'. Use \'\\\\u....\' instead.",\n
            parameter_arguments_a: "Do not mutate parameter \'{a}\' when using \'arguments\'.",\n
            parameter_a_get_b: "Unexpected parameter \'{a}\' in get {b} function.",\n
            parameter_set_a: "Expected parameter (value) in set {a} function.",\n
            radix: "Missing radix parameter.",\n
            read_only: "Read only.",\n
            redefinition_a_b: "Redefinition of \'{a}\' from line {b}.",\n
            reserved_a: "Reserved name \'{a}\'.",\n
            scanned_a_b: "{a} ({b}% scanned).",\n
            slash_equal: "A regular expression literal can be confused with \'/=\'.",\n
            statement_block: "Expected to see a statement and instead saw a block.",\n
            stopping: "Stopping.",\n
            strange_loop: "Strange loop.",\n
            strict: "Strict violation.",\n
            subscript: "[\'{a}\'] is better written in dot notation.",\n
            sync_a: "Unexpected sync method: \'{a}\'.",\n
            tag_a_in_b: "A \'<{a}>\' must be within \'<{b}>\'.",\n
            todo_comment: "Unexpected TODO comment.",\n
            too_long: "Line too long.",\n
            too_many: "Too many errors.",\n
            trailing_decimal_a: "A trailing decimal point can be confused " +\n
                "with a dot: \'.{a}\'.",\n
            unclosed: "Unclosed string.",\n
            unclosed_comment: "Unclosed comment.",\n
            unclosed_regexp: "Unclosed regular expression.",\n
            unescaped_a: "Unescaped \'{a}\'.",\n
            unexpected_a: "Unexpected \'{a}\'.",\n
            unexpected_char_a: "Unexpected character \'{a}\'.",\n
            unexpected_comment: "Unexpected comment.",\n
            unexpected_label_a: "Unexpected label \'{a}\'.",\n
            unexpected_property_a: "Unexpected /*property*/ \'{a}\'.",\n
            unexpected_space_a_b: "Unexpected space between \'{a}\' and \'{b}\'.",\n
            unexpected_typeof_a: "Unexpected \'typeof\'. " +\n
                "Use \'===\' to compare directly with {a}.",\n
            uninitialized_a: "Uninitialized \'{a}\'.",\n
            unnecessary_else: "Unnecessary \'else\' after disruption.",\n
            unnecessary_initialize: "It is not necessary to initialize \'{a}\' " +\n
                "to \'undefined\'.",\n
            unnecessary_use: "Unnecessary \'use strict\'.",\n
            unreachable_a_b: "Unreachable \'{a}\' after \'{b}\'.",\n
            unsafe: "Unsafe character.",\n
            unused_a: "Unused \'{a}\'.",\n
            url: "JavaScript URL.",\n
            use_array: "Use the array literal notation [].",\n
            use_braces: "Spaces are hard to count. Use {{a}}.",\n
            use_nested_if: "Expected \'else { if\' and instead saw \'else if\'.",\n
            use_object: "Use the object literal notation {} or Object.create(null).",\n
            use_or: "Use the || operator.",\n
            use_param: "Use a named parameter.",\n
            use_spaces: "Use spaces, not tabs.",\n
            used_before_a: "\'{a}\' was used before it was defined.",\n
            var_a_not: "Variable {a} was not declared correctly.",\n
            var_loop: "Don\'t declare variables in a loop.",\n
            weird_assignment: "Weird assignment.",\n
            weird_condition: "Weird condition.",\n
            weird_new: "Weird construction. Delete \'new\'.",\n
            weird_program: "Weird program.",\n
            weird_relation: "Weird relation.",\n
            weird_ternary: "Weird ternary.",\n
            wrap_immediate: "Wrap an immediate function invocation in " +\n
                "parentheses to assist the reader in understanding that the " +\n
                "expression is the result of a function, and not the " +\n
                "function itself.",\n
            wrap_regexp: "Wrap the /regexp/ literal in parens to " +\n
                "disambiguate the slash operator.",\n
            write_is_wrong: "document.write can be a form of eval."\n
        },\n
        closure = array_to_object([\n
            \'goog\'\n
        ], false),\n
        comments,\n
        comments_off,\n
        couch = array_to_object([\n
            \'emit\', \'getRow\', \'isArray\', \'log\', \'provides\', \'registerType\',\n
            \'require\', \'send\', \'start\', \'sum\', \'toJSON\'\n
        ], false),\n
\n
        descapes = {\n
            \'b\': \'\\b\',\n
            \'t\': \'\\t\',\n
            \'n\': \'\\n\',\n
            \'f\': \'\\f\',\n
            \'r\': \'\\r\',\n
            \'"\': \'"\',\n
            \'/\': \'/\',\n
            \'\\\\\': \'\\\\\',\n
            \'!\': \'!\'\n
        },\n
\n
        devel = array_to_object([\n
            \'alert\', \'confirm\', \'console\', \'Debug\', \'opera\', \'prompt\', \'WSH\'\n
        ], false),\n
        directive,\n
        escapes = {\n
            \'\\b\': \'\\\\b\',\n
            \'\\t\': \'\\\\t\',\n
            \'\\n\': \'\\\\n\',\n
            \'\\f\': \'\\\\f\',\n
            \'\\r\': \'\\\\r\',\n
            \'\\\'\': \'\\\\\\\'\',\n
            \'"\' : \'\\\\"\',\n
            \'/\' : \'\\\\/\',\n
            \'\\\\\': \'\\\\\\\\\'\n
        },\n
\n
        funct,          // The current function\n
\n
        functions,      // All of the functions\n
        global_funct,   // The global body\n
        global_scope,   // The global scope\n
        in_block,       // Where function statements are not allowed\n
        indent,\n
        itself,         // JSLINT itself\n
        json_mode,\n
        lex,            // the tokenizer\n
        lines,\n
        lookahead,\n
        node = array_to_object([\n
            \'Buffer\', \'clearImmediate\', \'clearInterval\', \'clearTimeout\',\n
            \'console\', \'exports\', \'global\', \'module\', \'process\',\n
            \'require\', \'setImmediate\', \'setInterval\', \'setTimeout\',\n
            \'__dirname\', \'__filename\'\n
        ], false),\n
        node_js,\n
        numbery = array_to_object([\'indexOf\', \'lastIndexOf\', \'search\'], true),\n
        next_token,\n
        option,\n
        predefined,     // Global variables defined by option\n
        prereg,\n
        prev_token,\n
        property,\n
        protosymbol,\n
        regexp_flag = array_to_object([\'g\', \'i\', \'m\'], true),\n
        return_this = function return_this() {\n
            return this;\n
        },\n
        rhino = array_to_object([\n
            \'defineClass\', \'deserialize\', \'gc\', \'help\', \'load\', \'loadClass\',\n
            \'print\', \'quit\', \'readFile\', \'readUrl\', \'runCommand\', \'seal\',\n
            \'serialize\', \'spawn\', \'sync\', \'toint32\', \'version\'\n
        ], false),\n
\n
        scope,      // An object containing an object for each variable in scope\n
        semicolon_coda = array_to_object([\';\', \'"\', \'\\\'\', \')\'], true),\n
\n
// standard contains the global names that are provided by the\n
// ECMAScript standard.\n
\n
        standard = array_to_object([\n
            \'Array\', \'Boolean\', \'Date\', \'decodeURI\', \'decodeURIComponent\',\n
            \'encodeURI\', \'encodeURIComponent\', \'Error\', \'eval\', \'EvalError\',\n
            \'Function\', \'isFinite\', \'isNaN\', \'JSON\', \'Map\', \'Math\', \'Number\',\n
            \'Object\', \'parseInt\', \'parseFloat\', \'Promise\', \'Proxy\',\n
            \'RangeError\', \'ReferenceError\', \'Reflect\', \'RegExp\', \'Set\',\n
            \'String\', \'Symbol\', \'SyntaxError\', \'System\', \'TypeError\',\n
            \'URIError\', \'WeakMap\', \'WeakSet\'\n
        ], false),\n
\n
        strict_mode,\n
        syntax = Object.create(null),\n
        token,\n
        tokens,\n
        var_mode,\n
        warnings,\n
\n
// Regular expressions. Some of these are stupidly long.\n
\n
// carriage return, carriage return linefeed, or linefeed\n
        crlfx = /\\r\\n?|\\n/,\n
// unsafe characters that are silently deleted by one or more browsers\n
        cx = /[\\u0000-\\u0008\\u000a-\\u001f\\u007f-\\u009f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/,\n
// identifier\n
        ix = /^([a-zA-Z_$][a-zA-Z0-9_$]*)$/,\n
// javascript url\n
        jx = /^(?:javascript|jscript|ecmascript|vbscript)\\s*:/i,\n
// star slash\n
        lx = /\\*\\/|\\/\\*/,\n
// characters in strings that need escapement\n
        nx = /[\\u0000-\\u001f\'\\\\\\u007f-\\u009f\\u00ad\\u0600-\\u0604\\u070f\\u17b4\\u17b5\\u200c-\\u200f\\u2028-\\u202f\\u2060-\\u206f\\ufeff\\ufff0-\\uffff]/g,\n
// sync\n
        syx = /Sync$/,\n
// comment todo\n
        tox = /^\\W*to\\s*do(?:\\W|$)/i,\n
// token\n
        tx = /^\\s*([(){}\\[\\]\\?.,:;\'"~#@`]|={1,3}|\\/(\\*(jslint|properties|property|members?|globals?)?|=|\\/)?|\\*[\\/=]?|\\+(?:=|\\++)?|-(?:=|-+)?|[\\^%]=?|&[&=]?|\\|[|=]?|>{1,3}=?|<(?:[\\/=!]|\\!(\\[|--)?|<=?)?|\\!(\\!|==?)?|[a-zA-Z_$][a-zA-Z0-9_$]*|[0-9]+(?:[xX][0-9a-fA-F]+|\\.[0-9]*)?(?:[eE][+\\-]?[0-9]+)?)/;\n
\n
\n
    if (typeof String.prototype.entityify !== \'function\') {\n
        String.prototype.entityify = function () {\n
            return this\n
                .replace(/&/g, \'&amp;\')\n
                .replace(/</g, \'&lt;\')\n
                .replace(/>/g, \'&gt;\');\n
        };\n
    }\n
\n
    if (typeof String.prototype.isAlpha !== \'function\') {\n
        String.prototype.isAlpha = function () {\n
            return (this >= \'a\' && this <= \'z\\uffff\') ||\n
                (this >= \'A\' && this <= \'Z\\uffff\');\n
        };\n
    }\n
\n
    if (typeof String.prototype.isDigit !== \'function\') {\n
        String.prototype.isDigit = function () {\n
            return (this >= \'0\' && this <= \'9\');\n
        };\n
    }\n
\n
    if (typeof String.prototype.supplant !== \'function\') {\n
        String.prototype.supplant = function (o) {\n
            return this.replace(/\\{([^{}]*)\\}/g, function (a, b) {\n
                var replacement = o[b];\n
                return typeof replacement === \'string\' ||\n
                    typeof replacement === \'number\' ? replacement : a;\n
            });\n
        };\n
    }\n
\n
\n
    function sanitize(a) {\n
\n
//  Escapify a troublesome character.\n
\n
        return escapes[a] ||\n
            \'\\\\u\' + (\'0000\' + a.charCodeAt().toString(16)).slice(-4);\n
    }\n
\n
\n
    function add_to_predefined(group) {\n
        Object.keys(group).forEach(function (name) {\n
            predefined[name] = group[name];\n
        });\n
    }\n
\n
\n
    function assume() {\n
        if (option.browser) {\n
            add_to_predefined(browser);\n
            option.browser = false;\n
        }\n
        if (option.closure) {\n
            add_to_predefined(closure);\n
        }\n
        if (option.couch) {\n
            add_to_predefined(couch);\n
            option.couch = false;\n
        }\n
        if (option.devel) {\n
            add_to_predefined(devel);\n
            option.devel = false;\n
        }\n
        if (option.node) {\n
            add_to_predefined(node);\n
            option.node = false;\n
            node_js = true;\n
        }\n
        if (option.rhino) {\n
            add_to_predefined(rhino);\n
            option.rhino = false;\n
        }\n
    }\n
\n
\n
// Produce an error warning.\n
\n
    function artifact(tok) {\n
        if (!tok) {\n
            tok = next_token;\n
        }\n
        return tok.id === \'(number)\' ? tok.number : tok.string;\n
    }\n
\n
    function quit(message, line, character) {\n
        throw {\n
            name: \'JSLintError\',\n
            line: line,\n
            character: character,\n
            message: bundle.scanned_a_b.supplant({\n
                a: bundle[message] || message,\n
                b: Math.floor((line / lines.length) * 100)\n
            })\n
        };\n
    }\n
\n
    function warn(code, line, character, a, b, c, d) {\n
        var warning = {         // ~~\n
            id: \'(error)\',\n
            raw: bundle[code] || code,\n
            code: code,\n
            evidence: lines[line - 1] || \'\',\n
            line: line,\n
            character: character,\n
            a: a || artifact(this),\n
            b: b,\n
            c: c,\n
            d: d\n
        };\n
        warning.reason = warning.raw.supplant(warning);\n
        itself.errors.push(warning);\n
        if (option.passfail) {\n
            quit(\'stopping\', line, character);\n
        }\n
        warnings += 1;\n
        if (warnings >= option.maxerr) {\n
            quit(\'too_many\', line, character);\n
        }\n
        return warning;\n
    }\n
\n
    function stop(code, line, character, a, b, c, d) {\n
        var warning = warn(code, line, character, a, b, c, d);\n
        quit(\'stopping\', warning.line, warning.character);\n
    }\n
\n
    function expected_at(at) {\n
        if (!option.white && next_token.from !== at) {\n
            next_token.warn(\'expected_a_at_b_c\', \'\', at, next_token.from);\n
        }\n
    }\n
\n
// lexical analysis and token construction\n
\n
    lex = (function lex() {\n
        var character, c, from, length, line, pos, source_row;\n
\n
// Private lex methods\n
\n
        function next_line() {\n
            var at;\n
            character = 1;\n
            source_row = lines[line];\n
            line += 1;\n
            if (source_row === undefined) {\n
                return false;\n
            }\n
            at = source_row.search(/\\t/);\n
            if (at >= 0) {\n
                if (option.white) {\n
                    source_row = source_row.replace(/\\t/g, \' \');\n
                } else {\n
                    warn(\'use_spaces\', line, at + 1);\n
                }\n
            }\n
            at = source_row.search(cx);\n
            if (at >= 0) {\n
                warn(\'unsafe\', line, at);\n
            }\n
            if (option.maxlen && option.maxlen < source_row.length) {\n
                warn(\'too_long\', line, source_row.length);\n
            }\n
            return true;\n
        }\n
\n
// Produce a token object.  The token inherits from a syntax symbol.\n
\n
        function it(type, value) {\n
            var id, the_token;\n
            if (type === \'(string)\') {\n
                if (jx.test(value)) {\n
                    warn(\'url\', line, from);\n
                }\n
            }\n
            the_token = Object.create(syntax[(\n
                type === \'(punctuator)\' || (type === \'(identifier)\' &&\n
                        Object.prototype.hasOwnProperty.call(syntax, value))\n
                    ? value\n
                    : type\n
            )] || syntax[\'(error)\']);\n
            if (type === \'(identifier)\') {\n
                the_token.identifier = true;\n
                if (value === \'__iterator__\' || value === \'__proto__\') {\n
                    stop(\'reserved_a\', line, from, value);\n
                } else if (!option.nomen &&\n
                        (value.charAt(0) === \'_\' ||\n
                        value.charAt(value.length - 1) === \'_\')) {\n
                    warn(\'dangling_a\', line, from, value);\n
                }\n
            }\n
            if (type === \'(number)\') {\n
                the_token.number = +value;\n
            } else if (value !== undefined) {\n
                the_token.string = String(value);\n
            }\n
            the_token.line = line;\n
            the_token.from = from;\n
            the_token.thru = character;\n
            if (comments.length) {\n
                the_token.comments = comments;\n
                comments = [];\n
            }\n
            id = the_token.id;\n
            prereg = id && (\n
                (\'(,=:[!&|?{};~+-*%^<>\'.indexOf(id.charAt(id.length - 1)) >= 0) ||\n
                id === \'return\' || id === \'case\'\n
            );\n
            return the_token;\n
        }\n
\n
        function match(x) {\n
            var exec = x.exec(source_row), first;\n
            if (exec) {\n
                length = exec[0].length;\n
                first = exec[1];\n
                c = first.charAt(0);\n
                source_row = source_row.slice(length);\n
                from = character + length - first.length;\n
                character += length;\n
                return first;\n
            }\n
            for (;;) {\n
                if (!source_row) {\n
                    if (!option.white) {\n
                        warn(\'unexpected_char_a\', line, character - 1, \'(space)\');\n
                    }\n
                    return;\n
                }\n
                c = source_row.charAt(0);\n
                if (c !== \' \') {\n
                    break;\n
                }\n
                source_row = source_row.slice(1);\n
                character += 1;\n
            }\n
            stop(\'unexpected_char_a\', line, character, c);\n
\n
        }\n
\n
        function string(x) {\n
            var ch, at = 0, r = \'\', result;\n
\n
            function hex(n) {\n
                var i = parseInt(source_row.substr(at + 1, n), 16);\n
                at += n;\n
                if (i >= 32 && i <= 126 &&\n
                        i !== 34 && i !== 92 && i !== 39) {\n
                    warn(\'unexpected_a\', line, character, \'\\\\\');\n
                }\n
                character += n;\n
                ch = String.fromCharCode(i);\n
            }\n
\n
            if (json_mode && x !== \'"\') {\n
                warn(\'expected_a_b\', line, character, \'"\', x);\n
            }\n
\n
            for (;;) {\n
                while (at >= source_row.length) {\n
                    at = 0;\n
                    if (!next_line()) {\n
                        stop(\'unclosed\', line - 1, from);\n
                    }\n
                }\n
                ch = source_row.charAt(at);\n
                if (ch === x) {\n
                    character += 1;\n
                    source_row = source_row.slice(at + 1);\n
                    result = it(\'(string)\', r);\n
                    result.quote = x;\n
                    return result;\n
                }\n
                if (ch < \' \') {\n
                    if (ch === \'\\n\' || ch === \'\\r\') {\n
                        break;\n
                    }\n
                    warn(\'control_a\', line, character + at,\n
                        source_row.slice(0, at));\n
                } else if (ch === \'\\\\\') {\n
                    at += 1;\n
                    character += 1;\n
                    ch = source_row.charAt(at);\n
                    switch (ch) {\n
                    case \'\':\n
                        warn(\'unexpected_a\', line, character, \'\\\\\');\n
                        next_line();\n
                        at = -1;\n
                        break;\n
                    case \'\\\'\':\n
                        if (json_mode) {\n
                            warn(\'unexpected_a\', line, character, \'\\\\\\\'\');\n
                        }\n
                        break;\n
                    case \'u\':\n
                        hex(4);\n
                        break;\n
                    case \'v\':\n
                        if (json_mode) {\n
                            warn(\'unexpected_a\', line, character, \'\\\\v\');\n
                        }\n
                        ch = \'\\v\';\n
                        break;\n
                    case \'x\':\n
                        if (json_mode) {\n
                            warn(\'unexpected_a\', line, character, \'\\\\x\');\n
                        }\n
                        hex(2);\n
                        break;\n
                    default:\n
                        if (typeof descapes[ch] !== \'string\') {\n
                            warn(ch >= \'0\' && ch <= \'7\' ? \'octal_a\' : \'unexpected_a\',\n
                                line, character, \'\\\\\' + ch);\n
                        } else {\n
                            ch = descapes[ch];\n
                        }\n
                    }\n
                }\n
                r += ch;\n
                character += 1;\n
                at += 1;\n
            }\n
        }\n
\n
        function number(snippet) {\n
            var digit;\n
            if (source_row.charAt(0).isAlpha()) {\n
                warn(\'expected_space_a_b\',\n
                    line, character, c, source_row.charAt(0));\n
            }\n
            if (c === \'0\') {\n
                digit = snippet.charAt(1);\n
                if (digit.isDigit()) {\n
                    if (token.id !== \'.\') {\n
                        warn(\'unexpected_a\', line, character, snippet);\n
                    }\n
                } else if (json_mode && (digit === \'x\' || digit === \'X\')) {\n
                    warn(\'unexpected_a\', line, character, \'0x\');\n
                }\n
            }\n
            if (snippet.slice(snippet.length - 1) === \'.\') {\n
                warn(\'trailing_decimal_a\', line, character, snippet);\n
            }\n
            digit = +snippet;\n
            if (!isFinite(digit)) {\n
                warn(\'bad_number\', line, character, snippet);\n
            }\n
            snippet = digit;\n
            return it(\'(number)\', snippet);\n
        }\n
\n
        function comment(snippet, type) {\n
            if (comments_off) {\n
                warn(\'unexpected_comment\', line, character);\n
            } else if (!option.todo && tox.test(snippet)) {\n
                warn(\'todo_comment\', line, character);\n
            }\n
            comments.push({\n
                id: type,\n
                from: from,\n
                thru: character,\n
                line: line,\n
                string: snippet\n
            });\n
        }\n
\n
        function regexp() {\n
            var at = 0,\n
                b,\n
                bit,\n
                depth = 0,\n
                flag = \'\',\n
                high,\n
                letter,\n
                low,\n
                potential,\n
                quote,\n
                result;\n
            for (;;) {\n
                b = true;\n
                c = source_row.charAt(at);\n
                at += 1;\n
                switch (c) {\n
                case \'\':\n
                    stop(\'unclosed_regexp\', line, from);\n
                    return;\n
                case \'/\':\n
                    if (depth > 0) {\n
                        warn(\'unescaped_a\', line, from + at, \'/\');\n
                    }\n
                    c = source_row.slice(0, at - 1);\n
                    potential = Object.create(regexp_flag);\n
                    for (;;) {\n
                        letter = source_row.charAt(at);\n
                        if (potential[letter] !== true) {\n
                            break;\n
                        }\n
                        potential[letter] = false;\n
                        at += 1;\n
                        flag += letter;\n
                    }\n
                    if (source_row.charAt(at).isAlpha()) {\n
                        stop(\'unexpected_a\', line, from, source_row.charAt(at));\n
                    }\n
                    character += at;\n
                    source_row = source_row.slice(at);\n
                    quote = source_row.charAt(0);\n
                    if (quote === \'/\' || quote === \'*\') {\n
                        stop(\'confusing_regexp\', line, from);\n
                    }\n
                    result = it(\'(regexp)\', c);\n
                    result.flag = flag;\n
                    return result;\n
                case \'\\\\\':\n
                    c = source_row.charAt(at);\n
                    if (c < \' \') {\n
                        warn(\'control_a\', line, from + at, String(c));\n
                    } else if (c === \'<\') {\n
                        warn(\'unexpected_a\', line, from + at, \'\\\\\');\n
                    }\n
                    at += 1;\n
                    break;\n
                case \'(\':\n
                    depth += 1;\n
                    b = false;\n
                    if (source_row.charAt(at) === \'?\') {\n
                        at += 1;\n
                        switch (source_row.charAt(at)) {\n
                        case \':\':\n
                        case \'=\':\n
                        case \'!\':\n
                            at += 1;\n
                            break;\n
                        default:\n
                            warn(\'expected_a_b\', line, from + at,\n
                                \':\', source_row.charAt(at));\n
                        }\n
                    }\n
                    break;\n
                case \'|\':\n
                    b = false;\n
                    break;\n
                case \')\':\n
                    if (depth === 0) {\n
                        warn(\'unescaped_a\', line, from + at, \')\');\n
                    } else {\n
                        depth -= 1;\n
                    }\n
                    break;\n
                case \' \':\n
                    pos = 1;\n
                    while (source_row.charAt(at) === \' \') {\n
                        at += 1;\n
                        pos += 1;\n
                    }\n
                    if (pos > 1) {\n
                        warn(\'use_braces\', line, from + at, pos);\n
                    }\n
                    break;\n
                case \'[\':\n
                    c = source_row.charAt(at);\n
                    if (c === \'^\') {\n
                        at += 1;\n
                        if (!option.regexp) {\n
                            warn(\'insecure_a\', line, from + at, c);\n
                        } else if (source_row.charAt(at) === \']\') {\n
                            stop(\'unescaped_a\', line, from + at, \'^\');\n
                        }\n
                    }\n
                    bit = false;\n
                    if (c === \']\') {\n
                        warn(\'empty_class\', line, from + at - 1);\n
                        bit = true;\n
                    }\n
klass:              do {\n
                        c = source_row.charAt(at);\n
                        at += 1;\n
                        switch (c) {\n
                        case \'[\':\n
                        case \'^\':\n
                            warn(\'unescaped_a\', line, from + at, c);\n
                            bit = true;\n
                            break;\n
                        case \'-\':\n
                            if (bit) {\n
                                bit = false;\n
                            } else {\n
                                warn(\'unescaped_a\', line, from + at, \'-\');\n
                                bit = true;\n
                            }\n
                            break;\n
                        case \']\':\n
                            if (!bit) {\n
                                warn(\'unescaped_a\', line, from + at - 1, \'-\');\n
                            }\n
                            break klass;\n
                        case \'\\\\\':\n
                            c = source_row.charAt(at);\n
                            if (c < \' \') {\n
                                warn(\'control_a\', line, from + at, String(c));\n
                            } else if (c === \'<\') {\n
                                warn(\'unexpected_a\', line, from + at, \'\\\\\');\n
                            }\n
                            at += 1;\n
                            bit = true;\n
                            break;\n
                        case \'/\':\n
                            warn(\'unescaped_a\', line, from + at - 1, \'/\');\n
                            bit = true;\n
                            break;\n
                        default:\n
                            bit = true;\n
                        }\n
                    } while (c);\n
                    break;\n
                case \'.\':\n
                    if (!option.regexp) {\n
                        warn(\'insecure_a\', line, from + at, c);\n
                    }\n
                    break;\n
                case \']\':\n
                case \'?\':\n
                case \'{\':\n
                case \'}\':\n
                case \'+\':\n
                case \'*\':\n
                    warn(\'unescaped_a\', line, from + at, c);\n
                    break;\n
                }\n
                if (b) {\n
                    switch (source_row.charAt(at)) {\n
                    case \'?\':\n
                    case \'+\':\n
                    case \'*\':\n
                        at += 1;\n
                        if (source_row.charAt(at) === \'?\') {\n
                            at += 1;\n
                        }\n
                        break;\n
                    case \'{\':\n
                        at += 1;\n
                        c = source_row.charAt(at);\n
                        if (c < \'0\' || c > \'9\') {\n
                            warn(\'expected_number_a\', line,\n
                                from + at, c);\n
                        }\n
                        at += 1;\n
                        low = +c;\n
                        for (;;) {\n
                            c = source_row.charAt(at);\n
                            if (c < \'0\' || c > \'9\') {\n
                                break;\n
                            }\n
                            at += 1;\n
                            low = +c + (low * 10);\n
                        }\n
                        high = low;\n
                        if (c === \',\') {\n
                            at += 1;\n
                            high = Infinity;\n
                            c = source_row.charAt(at);\n
                            if (c >= \'0\' && c <= \'9\') {\n
                                at += 1;\n
                                high = +c;\n
                                for (;;) {\n
                                    c = source_row.charAt(at);\n
                                    if (c < \'0\' || c > \'9\') {\n
                                        break;\n
                                    }\n
                                    at += 1;\n
                                    high = +c + (high * 10);\n
                                }\n
                            }\n
                        }\n
                        if (source_row.charAt(at) !== \'}\') {\n
                            warn(\'expected_a_b\', line, from + at,\n
                                \'}\', c);\n
                        } else {\n
                            at += 1;\n
                        }\n
                        if (source_row.charAt(at) === \'?\') {\n
                            at += 1;\n
                        }\n
                        if (low > high) {\n
                            warn(\'not_greater\', line, from + at,\n
                                low, high);\n
                        }\n
                        break;\n
                    }\n
                }\n
            }\n
            c = source_row.slice(0, at - 1);\n
            character += at;\n
            source_row = source_row.slice(at);\n
            return it(\'(regexp)\', c);\n
        }\n
\n
// Public lex methods\n
\n
        return {\n
            init: function (source) {\n
                if (typeof source === \'string\') {\n
                    lines = source.split(crlfx);\n
                } else {\n
                    lines = source;\n
                }\n
                line = 0;\n
                next_line();\n
                from = 1;\n
            },\n
\n
// token -- this is called by advance to get the next token.\n
\n
            token: function () {\n
                var first, i, snippet;\n
\n
                for (;;) {\n
                    while (!source_row) {\n
                        if (!next_line()) {\n
                            return it(\'(end)\');\n
                        }\n
                    }\n
                    snippet = match(tx);\n
                    if (snippet) {\n
\n
//      identifier\n
\n
                        first = snippet.charAt(0);\n
                        if (first.isAlpha() || first === \'_\' || first === \'$\') {\n
                            return it(\'(identifier)\', snippet);\n
                        }\n
\n
//      number\n
\n
                        if (first.isDigit()) {\n
                            return number(snippet);\n
                        }\n
                        switch (snippet) {\n
\n
//      string\n
\n
                        case \'"\':\n
                        case "\'":\n
                            return string(snippet);\n
\n
//      // comment\n
\n
                        case \'//\':\n
                            comment(source_row, \'//\');\n
                            source_row = \'\';\n
                            break;\n
\n
//      /* comment\n
\n
                        case \'/*\':\n
                            for (;;) {\n
                                i = source_row.search(lx);\n
                                if (i >= 0) {\n
                                    break;\n
                                }\n
                                character = source_row.length;\n
                                comment(source_row);\n
                                from = 0;\n
                                if (!next_line()) {\n
                                    stop(\'unclosed_comment\', line, character);\n
                                }\n
                            }\n
                            comment(source_row.slice(0, i), \'/*\');\n
                            character += i + 2;\n
                            if (source_row.charAt(i) === \'/\') {\n
                                stop(\'nested_comment\', line, character);\n
                            }\n
                            source_row = source_row.slice(i + 2);\n
                            break;\n
\n
                        case \'\':\n
                            break;\n
//      /\n
                        case \'/\':\n
                            if (token.id === \'/=\') {\n
                                stop(\'slash_equal\', line, from);\n
                            }\n
                            return prereg\n
                                ? regexp()\n
                                : it(\'(punctuator)\', snippet);\n
\n
//      punctuator\n
                        default:\n
                            return it(\'(punctuator)\', snippet);\n
                        }\n
                    }\n
                }\n
            }\n
        };\n
    }());\n
\n
    function define(kind, token) {\n
\n
// Define a name.\n
\n
        var name = token.string,\n
            master = scope[name];       // The current definition of the name\n
\n
// vars are created with a deadzone, so that the expression that initializes\n
// the var cannot access the var. Functions are not writeable.\n
\n
        token.dead = false;\n
        token.init = false;\n
        token.kind = kind;\n
        token.master = master;\n
        token.used = 0;\n
        token.writeable = true;\n
\n
// Global variables are a little weird. They can be defined multiple times.\n
// Some predefined global vars are (or should) not be writeable.\n
\n
        if (kind === \'var\' && funct === global_funct) {\n
            if (!master) {\n
                if (predefined[name] === false) {\n
                    token.writeable = false;\n
                }\n
                global_scope[name] = token;\n
            }\n
        } else {\n
\n
// It is an error if the name has already been defined in this scope, except\n
// when reusing an exception variable name.\n
\n
            if (master) {\n
                if (master.function === funct) {\n
                    if (master.kind !== \'exception\' || kind !== \'exception\' ||\n
                            !master.dead) {\n
                        token.warn(\'already_defined\', name);\n
                    }\n
                } else if (master.function !== global_funct) {\n
                    if (kind === \'var\') {\n
                        token.warn(\'redefinition_a_b\', name, master.line);\n
                    }\n
                }\n
            }\n
            scope[name] = token;\n
            if (kind === \'var\') {\n
                block_var.push(name);\n
            }\n
        }\n
    }\n
\n
    function peek(distance) {\n
\n
// Peek ahead to a future token. The distance is how far ahead to look. The\n
// default is the next token.\n
\n
        var found, slot = 0;\n
\n
        distance = distance || 0;\n
        while (slot <= distance) {\n
            found = lookahead[slot];\n
            if (!found) {\n
                found = lookahead[slot] = lex.token();\n
            }\n
            slot += 1;\n
        }\n
        return found;\n
    }\n
\n
\n
    function advance(id, match) {\n
\n
// Produce the next token, also looking for programming errors.\n
\n
        if (indent) {\n
\n
// If indentation checking was requested, then inspect all of the line breakings.\n
// The var statement is tricky because the names might be aligned or not. We\n
// look at the first line break after the var to determine the programmer\'s\n
// intention.\n
\n
            if (var_mode && next_token.line !== token.line) {\n
                if ((var_mode !== indent || !next_token.edge) &&\n
                        next_token.from === indent.at -\n
                        (next_token.edge ? option.indent : 0)) {\n
                    var dent = indent;\n
                    for (;;) {\n
                        dent.at -= option.indent;\n
                        if (dent === var_mode) {\n
                            break;\n
                        }\n
                        dent = dent.was;\n
                    }\n
                    dent.open = false;\n
                }\n
                var_mode = null;\n
            }\n
            if (next_token.id === \'?\' && indent.mode === \':\' &&\n
                    token.line !== next_token.line) {\n
                indent.at -= option.indent;\n
            }\n
            if (indent.open) {\n
\n
// If the token is an edge.\n
\n
                if (next_token.edge) {\n
                    if (next_token.edge === \'label\') {\n
                        expected_at(1);\n
                    } else if (next_token.edge === \'case\' || indent.mode === \'statement\') {\n
                        expected_at(indent.at - option.indent);\n
                    } else if (indent.mode !== \'array\' || next_token.line !== token.line) {\n
                        expected_at(indent.at);\n
                    }\n
\n
// If the token is not an edge, but is the first token on the line.\n
\n
                } else if (next_token.line !== token.line) {\n
                    if (next_token.from < indent.at + (indent.mode ===\n
                            \'expression\' ? 0 : option.indent)) {\n
                        expected_at(indent.at + option.indent);\n
                    }\n
                    indent.wrap = true;\n
                }\n
            } else if (next_token.line !== token.line) {\n
                if (next_token.edge) {\n
                    expected_at(indent.at);\n
                } else {\n
                    indent.wrap = true;\n
                    if (indent.mode === \'statement\' || indent.mode === \'var\') {\n
                        expected_at(indent.at + option.indent);\n
                    } else if (next_token.from < indent.at + (indent.mode ===\n
                            \'expression\' ? 0 : option.indent)) {\n
                        expected_at(indent.at + option.indent);\n
                    }\n
                }\n
            }\n
        }\n
\n
        switch (token.id) {\n
        case \'(number)\':\n
            if (next_token.id === \'.\') {\n
                next_token.warn(\'trailing_decimal_a\');\n
            }\n
            break;\n
        case \'-\':\n
            if (next_token.id === \'-\' || next_token.id === \'--\') {\n
                next_token.warn(\'confusing_a\');\n
            }\n
            break;\n
        case \'+\':\n
            if (next_token.id === \'+\' || next_token.id === \'++\') {\n
                next_token.warn(\'confusing_a\');\n
            }\n
            break;\n
        }\n
        if (token.id === \'(string)\' || token.identifier) {\n
            anonname = token.string;\n
        }\n
\n
        if (id && next_token.id !== id) {\n
            if (match) {\n
                next_token.warn(\'expected_a_b_from_c_d\', id,\n
                    match.id, match.line, artifact());\n
            } else if (!next_token.identifier || next_token.string !== id) {\n
                next_token.warn(\'expected_a_b\', id, artifact());\n
            }\n
        }\n
        prev_token = token;\n
        token = next_token;\n
        next_token = lookahead.shift() || lex.token();\n
        next_token.function = funct;\n
        tokens.push(next_token);\n
    }\n
\n
\n
    function do_globals() {\n
        var name, writeable;\n
        for (;;) {\n
            if (next_token.id !== \'(string)\' && !next_token.identifier) {\n
                return;\n
            }\n
            name = next_token.string;\n
            advance();\n
            writeable = false;\n
            if (next_token.id === \':\') {\n
                advance(\':\');\n
                switch (next_token.id) {\n
                case \'true\':\n
                    writeable = predefined[name] !== false;\n
                    advance(\'true\');\n
                    break;\n
                case \'false\':\n
                    advance(\'false\');\n
                    break;\n
                default:\n
                    next_token.stop(\'unexpected_a\');\n
                }\n
            }\n
            predefined[name] = writeable;\n
            if (next_token.id !== \',\') {\n
                return;\n
            }\n
            advance(\',\');\n
        }\n
    }\n
\n
\n
    function do_jslint() {\n
        var name, value;\n
        while (next_token.id === \'(string)\' || next_token.identifier) {\n
            name = next_token.string;\n
            if (!allowed_option[name]) {\n
                next_token.stop(\'unexpected_a\');\n
            }\n
            advance();\n
            if (next_token.id !== \':\') {\n
                next_token.stop(\'expected_a_b\', \':\', artifact());\n
            }\n
            advance(\':\');\n
            if (typeof allowed_option[name] === \'number\') {\n
                value = next_token.number;\n
                if (value > allowed_option[name] || value <= 0 ||\n
                        Math.floor(value) !== value) {\n
                    next_token.stop(\'expected_small_a\');\n
                }\n
                option[name] = value;\n
            } else {\n
                if (next_token.id === \'true\') {\n
                    option[name] = true;\n
                } else if (next_token.id === \'false\') {\n
                    option[name] = false;\n
                } else {\n
                    next_token.stop(\'unexpected_a\');\n
                }\n
            }\n
            advance();\n
            if (next_token.id === \',\') {\n
                advance(\',\');\n
            }\n
        }\n
        assume();\n
    }\n
\n
\n
    function do_properties() {\n
        var name;\n
        option.properties = true;\n
        for (;;) {\n
            if (next_token.id !== \'(string)\' && !next_token.identifier) {\n
                return;\n
            }\n
            name = next_token.string;\n
            advance();\n
            if (next_token.id === \':\') {\n
                for (;;) {\n
                    advance();\n
                    if (next_token.id !== \'(string)\' && !next_token.identifier) {\n
                        break;\n
                    }\n
                }\n
            }\n
            property[name] = 0;\n
            if (next_token.id !== \',\') {\n
                return;\n
            }\n
            advance(\',\');\n
        }\n
    }\n
\n
\n
    directive = function directive() {\n
        var command = this.id,\n
            old_comments_off = comments_off,\n
            old_indent = indent;\n
        comments_off = true;\n
        indent = null;\n
        if (next_token.line === token.line && next_token.from === token.thru) {\n
            next_token.warn(\'missing_space_a_b\', artifact(token), artifact());\n
        }\n
        if (lookahead.length > 0) {\n
            this.warn(\'unexpected_a\');\n
        }\n
        switch (command) {\n
        case \'/*properties\':\n
        case \'/*property\':\n
        case \'/*members\':\n
        case \'/*member\':\n
            do_properties();\n
            break;\n
        case \'/*jslint\':\n
            do_jslint();\n
            break;\n
        case \'/*globals\':\n
        case \'/*global\':\n
            do_globals();\n
            break;\n
        default:\n
            this.stop(\'unexpected_a\');\n
        }\n
        comments_off = old_comments_off;\n
        advance(\'*/\');\n
        indent = old_indent;\n
    };\n
\n
\n
// Indentation intention\n
\n
    function edge(mode) {\n
        next_token.edge = indent ? indent.open && (mode || \'edge\') : \'\';\n
    }\n
\n
\n
    function step_in(mode) {\n
        var open;\n
        if (typeof mode === \'number\') {\n
            indent = {\n
                at: +mode,\n
                open: true,\n
                was: indent\n
            };\n
        } else if (!indent) {\n
            indent = {\n
                at: 1,\n
                mode: \'statement\',\n
                open: true\n
            };\n
        } else if (mode === \'statement\') {\n
            indent = {\n
                at: indent.at,\n
                open: true,\n
                was: indent\n
            };\n
        } else {\n
            open = mode === \'var\' || next_token.line !== token.line;\n
            indent = {\n
                at: (open || mode === \'control\'\n
                    ? indent.at + option.indent\n
                    : indent.at) + (indent.wrap ? option.indent : 0),\n
                mode: mode,\n
                open: open,\n
                was: indent\n
            };\n
            if (mode === \'var\' && open) {\n
                var_mode = indent;\n
            }\n
        }\n
    }\n
\n
    function step_out(id, symbol) {\n
        if (id) {\n
            if (indent && indent.open) {\n
                indent.at -= option.indent;\n
                edge();\n
            }\n
            advance(id, symbol);\n
        }\n
        if (indent) {\n
            indent = indent.was;\n
        }\n
    }\n
\n
// Functions for conformance of whitespace.\n
\n
    function one_space(left, right) {\n
        left = left || token;\n
        right = right || next_token;\n
        if (right.id !== \'(end)\' && !option.white &&\n
                (token.line !== right.line ||\n
                token.thru + 1 !== right.from)) {\n
            right.warn(\'expected_space_a_b\', artifact(token), artifact(right));\n
        }\n
    }\n
\n
    function one_space_only(left, right) {\n
        left = left || token;\n
        right = right || next_token;\n
        if (right.id !== \'(end)\' && (left.line !== right.line ||\n
                (!option.white && left.thru + 1 !== right.from))) {\n
            right.warn(\'expected_space_a_b\', artifact(left), artifact(right));\n
        }\n
    }\n
\n
    function no_space(left, right) {\n
        left = left || token;\n
        right = right || next_token;\n
        if ((!option.white) &&\n
                left.thru !== right.from && left.line === right.line) {\n
            right.warn(\'unexpected_space_a_b\', artifact(left), artifact(right));\n
        }\n
    }\n
\n
    function no_space_only(left, right) {\n
        left = left || token;\n
        right = right || next_token;\n
        if (right.id !== \'(end)\' && (left.line !== right.line ||\n
                (!option.white && left.thru !== right.from))) {\n
            right.warn(\'unexpected_space_a_b\', artifact(left), artifact(right));\n
        }\n
    }\n
\n
    function spaces(left, right) {\n
        if (!option.white) {\n
            left = left || token;\n
            right = right || next_token;\n
            if (left.thru === right.from && left.line === right.line) {\n
                right.warn(\'missing_space_a_b\', artifact(left), artifact(right));\n
            }\n
        }\n
    }\n
\n
    function comma() {\n
        if (next_token.id !== \',\') {\n
            warn(\'expected_a_b\', token.line, token.thru, \',\', artifact());\n
        } else {\n
            if (!option.white) {\n
                no_space_only();\n
            }\n
            advance(\',\');\n
            spaces();\n
        }\n
    }\n
\n
\n
    function semicolon() {\n
        if (next_token.id !== \';\') {\n
            warn(\'expected_a_b\', token.line, token.thru, \';\', artifact());\n
        } else {\n
            if (!option.white) {\n
                no_space_only();\n
            }\n
            advance(\';\');\n
            if (semicolon_coda[next_token.id] !== true) {\n
                spaces();\n
            }\n
        }\n
    }\n
\n
    function use_strict() {\n
        if (next_token.string === \'use strict\') {\n
            if (strict_mode) {\n
                next_token.warn(\'unnecessary_use\');\n
            }\n
            edge();\n
            advance();\n
            semicolon();\n
            strict_mode = true;\n
            return true;\n
        }\n
        return false;\n
    }\n
\n
\n
    function are_similar(a, b) {\n
        if (a === b) {\n
            return true;\n
        }\n
        if (Array.isArray(a)) {\n
            if (Array.isArray(b) && a.length === b.length) {\n
                var i;\n
                for (i = 0; i < a.length; i += 1) {\n
                    if (!are_similar(a[i], b[i])) {\n
                        return false;\n
                    }\n
                }\n
                return true;\n
            }\n
            return false;\n
        }\n
        if (Array.isArray(b)) {\n
            return false;\n
        }\n
        if (a.id === \'(number)\' && b.id === \'(number)\') {\n
            return a.number === b.number;\n
        }\n
        if (a.arity === b.arity && a.string === b.string) {\n
            switch (a.arity) {\n
            case undefined:\n
                return a.string === b.string;\n
            case \'prefix\':\n
            case \'suffix\':\n
                return a.id === b.id && are_similar(a.first, b.first) &&\n
                    a.id !== \'{\' && a.id !== \'[\';\n
            case \'infix\':\n
                return are_similar(a.first, b.first) &&\n
                    are_similar(a.second, b.second);\n
            case \'ternary\':\n
                return are_similar(a.first, b.first) &&\n
                    are_similar(a.second, b.second) &&\n
                    are_similar(a.third, b.third);\n
            case \'function\':\n
            case \'regexp\':\n
                return false;\n
            default:\n
                return true;\n
            }\n
        }\n
        if (a.id === \'.\' && b.id === \'[\' && b.arity === \'infix\') {\n
            return a.second.string === b.second.string && b.second.id === \'(string)\';\n
        }\n
        if (a.id === \'[\' && a.arity === \'infix\' && b.id === \'.\') {\n
            return a.second.string === b.second.string && a.second.id === \'(string)\';\n
        }\n
        return false;\n
    }\n
\n
\n
// This is the heart of JSLINT, the Pratt parser. In addition to parsing, it\n
// is looking for ad hoc lint patterns. We add .fud to Pratt\'s model, which is\n
// like .nud except that it is only used on the first token of a statement.\n
// Having .fud makes it much easier to define statement-oriented languages like\n
// JavaScript. I retained Pratt\'s nomenclature.\n
\n
// .nud     Null denotation\n
// .fud     First null denotation\n
// .led     Left denotation\n
//  lbp     Left binding power\n
//  rbp     Right binding power\n
\n
// They are elements of the parsing method called Top Down Operator Precedence.\n
\n
    function expression(rbp, initial) {\n
\n
// rbp is the right binding power.\n
// initial indicates that this is the first expression of a statement.\n
\n
        var left;\n
        if (next_token.id === \'(end)\') {\n
            token.stop(\'unexpected_a\', next_token.id);\n
        }\n
        advance();\n
        if (initial) {\n
            anonname = \'anonymous\';\n
        }\n
        if (initial === true && token.fud) {\n
            left = token.fud();\n
        } else {\n
            if (token.nud) {\n
                left = token.nud();\n
            } else {\n
                if (next_token.id === \'(number)\' && token.id === \'.\') {\n
                    token.warn(\'leading_decimal_a\', artifact());\n
                    advance();\n
                    return token;\n
                }\n
                token.stop(\'expected_identifier_a\', artifact(token));\n
            }\n
            while (rbp < next_token.lbp) {\n
                advance();\n
                left = token.led(left);\n
            }\n
        }\n
        if (left && left.assign && !initial) {\n
            if (!option.ass) {\n
                left.warn(\'assignment_expression\');\n
            }\n
            if (left.id !== \'=\' && left.first.master) {\n
                left.first.master.used = true;\n
            }\n
        }\n
        return left;\n
    }\n
\n
    protosymbol = {\n
        nud: function () {\n
            this.stop(\'unexpected_a\');\n
        },\n
        led: function () {\n
            this.stop(\'expected_operator_a\');\n
        },\n
        warn: function (code, a, b, c, d) {\n
            if (!this.warning) {\n
                this.warning = warn(code, this.line || 0, this.from || 0,\n
                    a || artifact(this), b, c, d);\n
            }\n
        },\n
        stop: function (code, a, b, c, d) {\n
            this.warning = undefined;\n
            this.warn(code, a, b, c, d);\n
            return quit(\'stopping\', this.line, this.character);\n
        },\n
        lbp: 0\n
    };\n
\n
// Functional constructors for making the symbols that will be inherited by\n
// tokens.\n
\n
    function symbol(s, bp) {\n
        var x = syntax[s];\n
        if (!x) {\n
            x = Object.create(protosymbol);\n
            x.id = x.string = s;\n
            x.lbp = bp || 0;\n
            syntax[s] = x;\n
        }\n
        return x;\n
    }\n
\n
    function postscript(x) {\n
        x.postscript = true;\n
        return x;\n
    }\n
\n
    function ultimate(s) {\n
        var x = symbol(s, 0);\n
        x.from = 1;\n
        x.thru = 1;\n
        x.line = 0;\n
        x.edge = \'edge\';\n
        x.string = s;\n
        return postscript(x);\n
    }\n
\n
    function reserve_name(x) {\n
        var c = x.id.charAt(0);\n
        if ((c >= \'a\' && c <= \'z\') || (c >= \'A\' && c <= \'Z\')) {\n
            x.identifier = x.reserved = true;\n
        }\n
        return x;\n
    }\n
\n
    function stmt(s, f) {\n
        var x = symbol(s);\n
        x.fud = f;\n
        return reserve_name(x);\n
    }\n
\n
    function disrupt_stmt(s, f) {\n
        var x = stmt(s, f);\n
        x.disrupt = true;\n
    }\n
\n
    function labeled_stmt(s, f) {\n
        var x = stmt(s, function labeled() {\n
            var the_statement;\n
            if (funct.breakage) {\n
                funct.breakage.push(this);\n
            } else {\n
                funct.breakage = [this];\n
            }\n
            the_statement = f.apply(this);\n
            if (funct.breakage.length > 1) {\n
                funct.breakage.pop();\n
            } else {\n
                delete funct.breakage;\n
            }\n
            return the_statement;\n
        });\n
        x.labeled = true;\n
    }\n
\n
    function prefix(s, f) {\n
        var x = symbol(s, 150);\n
        reserve_name(x);\n
        x.nud = function () {\n
            var that = this;\n
            that.arity = \'prefix\';\n
            if (typeof f === \'function\') {\n
                that = f(that);\n
                if (that.arity !== \'prefix\') {\n
                    return that;\n
                }\n
            } else {\n
                if (s === \'typeof\') {\n
                    one_space();\n
                } else {\n
                    no_space_only();\n
                }\n
                that.first = expression(150);\n
            }\n
            switch (that.id) {\n
            case \'++\':\n
            case \'--\':\n
                if (!option.plusplus) {\n
                    that.warn(\'unexpected_a\');\n
                } else if ((!that.first.identifier || that.first.reserved) &&\n
                        that.first.id !== \'.\' && that.first.id !== \'[\') {\n
                    that.warn(\'bad_operand\');\n
                }\n
                break;\n
            default:\n
                if (that.first.arity === \'prefix\' ||\n
                        that.first.arity === \'function\') {\n
                    that.warn(\'unexpected_a\');\n
                }\n
            }\n
            return that;\n
        };\n
        return x;\n
    }\n
\n
\n
    function type(s, t, nud) {\n
        var x = symbol(s);\n
        x.arity = t;\n
        if (nud) {\n
            x.nud = nud;\n
        }\n
        return x;\n
    }\n
\n
\n
    function reserve(s, f) {\n
        var x = symbol(s);\n
        x.identifier = x.reserved = true;\n
        if (typeof f === \'function\') {\n
            x.nud = f;\n
        }\n
        return x;\n
    }\n
\n
\n
    function constant(name) {\n
        var x = reserve(name);\n
        x.string = name;\n
        x.nud = return_this;\n
        return x;\n
    }\n
\n
\n
    function reservevar(s, v) {\n
        return reserve(s, function () {\n
            if (typeof v === \'function\') {\n
                v(this);\n
            }\n
            return this;\n
        });\n
    }\n
\n
\n
    function infix(s, p, f, w) {\n
        var x = symbol(s, p);\n
        reserve_name(x);\n
        x.led = function (left) {\n
            this.arity = \'infix\';\n
            if (!w) {\n
                spaces(prev_token, token);\n
                spaces();\n
            }\n
            if (!option.bitwise && this.bitwise) {\n
                this.warn(\'unexpected_a\');\n
            }\n
            if (typeof f === \'function\') {\n
                return f(left, this);\n
            }\n
            this.first = left;\n
            this.second = expression(p);\n
            return this;\n
        };\n
        return x;\n
    }\n
\n
    function expected_relation(node, message) {\n
        if (node.assign) {\n
            node.warn(message || \'conditional_assignment\');\n
        }\n
        return node;\n
    }\n
\n
    function expected_condition(node, message) {\n
        switch (node.id) {\n
        case \'[\':\n
        case \'-\':\n
            if (node.arity !== \'infix\') {\n
                node.warn(message || \'weird_condition\');\n
            }\n
            break;\n
        case \'false\':\n
        case \'function\':\n
        case \'Infinity\':\n
        case \'NaN\':\n
        case \'null\':\n
        case \'true\':\n
        case \'undefined\':\n
        case \'void\':\n
        case \'(number)\':\n
        case \'(regexp)\':\n
        case \'(string)\':\n
        case \'{\':\n
        case \'?\':\n
        case \'~\':\n
            node.warn(message || \'weird_condition\');\n
            break;\n
        case \'(\':\n
            if (node.first.id === \'new\' ||\n
                    (node.first.string === \'Boolean\') ||\n
                    (node.first.id === \'.\' &&\n
                        numbery[node.first.second.string] === true)) {\n
                node.warn(message || \'weird_condition\');\n
            }\n
            break;\n
        }\n
        return node;\n
    }\n
\n
    function check_relation(node) {\n
        switch (node.arity) {\n
        case \'prefix\':\n
            switch (node.id) {\n
            case \'{\':\n
            case \'[\':\n
                node.warn(\'unexpected_a\');\n
                break;\n
            case \'!\':\n
                node.warn(\'confusing_a\');\n
                break;\n
            }\n
            break;\n
        case \'function\':\n
        case \'regexp\':\n
            node.warn(\'unexpected_a\');\n
            break;\n
        default:\n
            if (node.id  === \'NaN\') {\n
                node.warn(\'isNaN\');\n
            } else if (node.relation) {\n
                node.warn(\'weird_relation\');\n
            }\n
        }\n
        return node;\n
    }\n
\n
\n
    function relation(s, eqeq) {\n
        var x = infix(s, 100, function (left, that) {\n
            check_relation(left);\n
            if (eqeq && !option.eqeq) {\n
                that.warn(\'expected_a_b\', eqeq, that.id);\n
            }\n
            var right = expression(100);\n
            if (are_similar(left, right) ||\n
                    ((left.id === \'(string)\' || left.id === \'(number)\') &&\n
                    (right.id === \'(string)\' || right.id === \'(number)\'))) {\n
                that.warn(\'weird_relation\');\n
            } else if (left.id === \'typeof\') {\n
                if (right.id !== \'(string)\') {\n
                    right.warn("expected_string_a", artifact(right));\n
                } else if (right.string === \'undefined\' ||\n
                        right.string === \'null\') {\n
                    left.warn("unexpected_typeof_a", right.string);\n
                }\n
            } else if (right.id === \'typeof\') {\n
                if (left.id !== \'(string)\') {\n
                    left.warn("expected_string_a", artifact(left));\n
                } else if (left.string === \'undefined\' ||\n
                        left.string === \'null\') {\n
                    right.warn("unexpected_typeof_a", left.string);\n
                }\n
            }\n
            that.first = left;\n
            that.second = check_relation(right);\n
            return that;\n
        });\n
        x.relation = true;\n
        return x;\n
    }\n
\n
    function lvalue(that, s) {\n
        var master;\n
        if (that.identifier) {\n
            master = scope[that.string];\n
            if (master) {\n
                if (scope[that.string].writeable !== true) {\n
                    that.warn(\'read_only\');\n
                }\n
                master.used -= 1;\n
                if (s === \'=\') {\n
                    master.init = true;\n
                }\n
            }\n
        } else if (that.id === \'.\' || that.id === \'[\') {\n
            if (!that.first || that.first.string === \'arguments\') {\n
                that.warn(\'bad_assignment\');\n
            }\n
        } else {\n
            that.warn(\'bad_assignment\');\n
        }\n
    }\n
\n
\n
    function assignop(s, op) {\n
        var x = infix(s, 20, function (left, that) {\n
            var next;\n
            that.first = left;\n
            lvalue(left, s);\n
            that.second = expression(20);\n
            if (that.id === \'=\' && are_similar(that.first, that.second)) {\n
                that.warn(\'weird_assignment\');\n
            }\n
            next = that;\n
            while (next_token.id === \'=\') {\n
                lvalue(next.second, \'=\');\n
                next_token.first = next.second;\n
                next.second = next_token;\n
                next = next_token;\n
                advance(\'=\');\n
                next.second = expression(20);\n
            }\n
            return that;\n
        });\n
        x.assign = true;\n
        if (op) {\n
            if (syntax[op].bitwise) {\n
                x.bitwise = true;\n
            }\n
        }\n
        return x;\n
    }\n
\n
\n
    function bitwise(s, p) {\n
        var x = infix(s, p, \'number\');\n
        x.bitwise = true;\n
        return x;\n
    }\n
\n
\n
    function suffix(s) {\n
        var x = symbol(s, 150);\n
        x.led = function (left) {\n
            no_space_only(prev_token, token);\n
            if (!option.plusplus) {\n
                this.warn(\'unexpected_a\');\n
            } else if ((!left.identifier || left.reserved) &&\n
                    left.id !== \'.\' && left.id !== \'[\') {\n
                this.warn(\'bad_operand\');\n
            }\n
            this.first = left;\n
            this.arity = \'suffix\';\n
            return this;\n
        };\n
        return x;\n
    }\n
\n
\n
    function optional_identifier(variable) {\n
        if (next_token.identifier) {\n
            advance();\n
            if (token.reserved && variable) {\n
                token.warn(\'expected_identifier_a_reserved\');\n
            }\n
            return token.string;\n
        }\n
    }\n
\n
\n
    function identifier(variable) {\n
        var i = optional_identifier(variable);\n
        if (!i) {\n
            next_token.stop(token.id === \'function\' && next_token.id === \'(\'\n
                ? \'name_function\'\n
                : \'expected_identifier_a\');\n
        }\n
        return i;\n
    }\n
\n
\n
    function statement() {\n
\n
        var label, preamble, the_statement;\n
\n
// We don\'t like the empty statement.\n
\n
        if (next_token.id === \';\') {\n
            next_token.warn(\'unexpected_a\');\n
            semicolon();\n
            return;\n
        }\n
\n
// Is this a labeled statement?\n
\n
        if (next_token.identifier && !next_token.reserved && peek().id === \':\') {\n
            edge(\'label\');\n
            label = next_token;\n
            advance();\n
            advance(\':\');\n
            define(\'label\', label);\n
            if (next_token.labeled !== true || funct === global_funct) {\n
                label.stop(\'unexpected_label_a\');\n
            } else if (jx.test(label.string + \':\')) {\n
                label.warn(\'url\');\n
            }\n
            next_token.label = label;\n
            label.init = true;\n
            label.statement = next_token;\n
        }\n
\n
// Parse the statement.\n
\n
        preamble = next_token;\n
        if (token.id !== \'else\') {\n
            edge();\n
        }\n
        step_in(\'statement\');\n
        the_statement = expression(0, true);\n
        if (the_statement) {\n
\n
// Look for the final semicolon.\n
\n
            if (the_statement.arity === \'statement\') {\n
                if (the_statement.id === \'switch\' ||\n
                        (the_statement.block && the_statement.id !== \'do\')) {\n
                    spaces();\n
                } else {\n
                    semicolon();\n
                }\n
            } else {\n
\n
// If this is an expression statement, determine if it is acceptable.\n
// We do not like\n
//      new Blah;\n
// statements. If it is to be used at all, new should only be used to make\n
// objects, not side effects. The expression statements we do like do\n
// assignment or invocation or delete.\n
\n
                if (the_statement.id === \'(\') {\n
                    if (the_statement.first.id === \'new\') {\n
                        next_token.warn(\'bad_new\');\n
                    }\n
                } else if (the_statement.id === \'++\' ||\n
                        the_statement.id === \'--\') {\n
                    lvalue(the_statement.first);\n
                } else if (!the_statement.assign &&\n
                        the_statement.id !== \'delete\') {\n
                    if (!option.closure || !preamble.comments) {\n
                        preamble.warn(\'assignment_function_expression\');\n
                    }\n
                }\n
                semicolon();\n
            }\n
        }\n
        step_out();\n
        if (label) {\n
            label.dead = true;\n
        }\n
        return the_statement;\n
    }\n
\n
\n
    function statements() {\n
        var array = [], disruptor, the_statement;\n
\n
// A disrupt statement may not be followed by any other statement.\n
// If the last statement is disrupt, then the sequence is disrupt.\n
\n
        while (next_token.postscript !== true) {\n
            if (next_token.id === \';\') {\n
                next_token.warn(\'unexpected_a\');\n
                semicolon();\n
            } else {\n
                if (next_token.string === \'use strict\') {\n
                    if ((!node_js) || funct !== global_funct || array.length > 0) {\n
                        next_token.warn(\'function_strict\');\n
                    }\n
                    use_strict();\n
                }\n
                if (disruptor) {\n
                    next_token.warn(\'unreachable_a_b\', next_token.string,\n
                        disruptor.string);\n
                    disruptor = null;\n
                }\n
                the_statement = statement();\n
                if (the_statement) {\n
                    array.push(the_statement);\n
                    if (the_statement.disrupt) {\n
                        disruptor = the_statement;\n
                        array.disrupt = true;\n
                    }\n
                }\n
            }\n
        }\n
        return array;\n
    }\n
\n
\n
    function block(kind) {\n
\n
// A block is a sequence of statements wrapped in braces.\n
\n
        var array,\n
            curly = next_token,\n
            old_block_var = block_var,\n
            old_in_block = in_block,\n
            old_strict_mode = strict_mode;\n
\n
        in_block = kind !== \'function\' && kind !== \'try\' && kind !== \'catch\';\n
        block_var = [];\n
        if (curly.id === \'{\') {\n
            spaces();\n
            advance(\'{\');\n
            step_in();\n
            if (kind === \'function\' && !use_strict() && !old_strict_mode &&\n
                    !option.sloppy && funct.level === 1) {\n
                next_token.warn(\'missing_use_strict\');\n
            }\n
            array = statements();\n
            strict_mode = old_strict_mode;\n
            step_out(\'}\', curly);\n
        } else if (in_block) {\n
            curly.stop(\'expected_a_b\', \'{\', artifact());\n
        } else {\n
            curly.warn(\'expected_a_b\', \'{\', artifact());\n
            array = [statement()];\n
            array.disrupt = array[0].disrupt;\n
        }\n
        if (kind !== \'catch\' && array.length === 0 && !option.debug) {\n
            curly.warn(\'empty_block\');\n
        }\n
        block_var.forEach(function (name) {\n
            scope[name].dead = true;\n
        });\n
        block_var = old_block_var;\n
        in_block = old_in_block;\n
        return array;\n
    }\n
\n
\n
    function tally_property(name) {\n
        if (option.properties && typeof property[name] !== \'number\') {\n
            token.warn(\'unexpected_property_a\', name);\n
        }\n
        if (property[name]) {\n
            property[name] += 1;\n
        } else {\n
            property[name] = 1;\n
        }\n
    }\n
\n
\n
// ECMAScript parser\n
\n
    (function () {\n
        var x = symbol(\'(identifier)\');\n
        x.nud = function () {\n
            var name = this.string,\n
                master = scope[name],\n
                writeable;\n
\n
// If the master is not in scope, then we may have an undeclared variable.\n
// Check the predefined list. If it was predefined, create the global\n
// variable.\n
\n
            if (!master) {\n
                writeable = predefined[name];\n
                if (typeof writeable === \'boolean\') {\n
                    global_scope[name] = master = {\n
                        dead: false,\n
                        function: global_funct,\n
                        kind: \'var\',\n
                        string: name,\n
                        writeable: writeable\n
                    };\n
\n
// But if the variable is not in scope, and is not predefined, and if we are not\n
// in the global scope, then we have an undefined variable error.\n
\n
                } else {\n
                    token.warn(\'used_before_a\');\n
                }\n
            } else {\n
                this.master = master;\n
            }\n
\n
// Annotate uses that cross scope boundaries.\n
\n
            if (master) {\n
                if (master.kind === \'label\') {\n
                    this.warn(\'a_label\');\n
                } else {\n
                    if (master.dead === true || master.dead === funct) {\n
                        this.warn(\'a_scope\');\n
                    }\n
                    master.used += 1;\n
                    if (master.function !== funct) {\n
                        if (master.function === global_funct) {\n
                            funct.global.push(name);\n
                        } else {\n
                            master.function.closure.push(name);\n
                            funct.outer.push(name);\n
                        }\n
                    }\n
                }\n
            }\n
            return this;\n
        };\n
        x.identifier = true;\n
    }());\n
\n
\n
// Build the syntax table by declaring the syntactic elements.\n
\n
    type(\'(array)\', \'array\');\n
    type(\'(function)\', \'function\');\n
    type(\'(number)\', \'number\', return_this);\n
    type(\'(object)\', \'object\');\n
    type(\'(string)\', \'string\', return_this);\n
    type(\'(boolean)\', \'boolean\', return_this);\n
    type(\'(regexp)\', \'regexp\', return_this);\n
\n
    ultimate(\'(begin)\');\n
    ultimate(\'(end)\');\n
    ultimate(\'(error)\');\n
    postscript(symbol(\'}\'));\n
    symbol(\')\');\n
    symbol(\']\');\n
    postscript(symbol(\'"\'));\n
    postscript(symbol(\'\\\'\'));\n
    symbol(\';\');\n
    symbol(\':\');\n
    symbol(\',\');\n
    symbol(\'#\');\n
    symbol(\'@\');\n
    symbol(\'*/\');\n
    postscript(reserve(\'case\'));\n
    reserve(\'catch\');\n
    postscript(reserve(\'default\'));\n
    reserve(\'else\');\n
    reserve(\'finally\');\n
\n
    reservevar(\'arguments\', function (x) {\n
        if (strict_mode && funct === global_funct) {\n
            x.warn(\'strict\');\n
        }\n
        funct.arguments = true;\n
    });\n
    reservevar(\'eval\');\n
    constant(\'false\', \'boolean\');\n
    constant(\'Infinity\', \'number\');\n
    constant(\'NaN\', \'number\');\n
    constant(\'null\', \'\');\n
    reservevar(\'this\', function (x) {\n
        if (strict_mode && funct.statement && funct.name.charAt(0) > \'Z\') {\n
            x.warn(\'strict\');\n
        }\n
    });\n
    constant(\'true\', \'boolean\');\n
    constant(\'undefined\', \'\');\n
\n
    infix(\'?\', 30, function (left, that) {\n
        step_in(\'?\');\n
        that.first = expected_condition(expected_relation(left));\n
        that.second = expression(0);\n
        spaces();\n
        step_out();\n
        var colon = next_token;\n
        advance(\':\');\n
        step_in(\':\');\n
        spaces();\n
        that.third = expression(10);\n
        that.arity = \'ternary\';\n
        if (are_similar(that.second, that.third)) {\n
            colon.warn(\'weird_ternary\');\n
        } else if (are_similar(that.first, that.second)) {\n
            that.warn(\'use_or\');\n
        }\n
        step_out();\n
        return that;\n
    });\n
\n
    infix(\'||\', 40, function (left, that) {\n
        function paren_check(that) {\n
            if (that.id === \'&&\' && !that.paren) {\n
                that.warn(\'and\');\n
            }\n
            return that;\n
        }\n
\n
        that.first = paren_check(expected_condition(expected_relation(left)));\n
        that.second = paren_check(expected_relation(expression(40)));\n
        if (are_similar(that.first, that.second)) {\n
            that.warn(\'weird_condition\');\n
        }\n
        return that;\n
    });\n
\n
    infix(\'&&\', 50, function (left, that) {\n
        that.first = expected_condition(expected_relation(left));\n
        that.second = expected_relation(expression(50));\n
        if (are_similar(that.first, that.second)) {\n
            that.warn(\'weird_condition\');\n
        }\n
        return that;\n
    });\n
\n
    prefix(\'void\', function (that) {\n
        that.first = expression(0);\n
        that.warn(\'expected_a_b\', \'undefined\', \'void\');\n
        return that;\n
    });\n
\n
    bitwise(\'|\', 70);\n
    bitwise(\'^\', 80);\n
    bitwise(\'&\', 90);\n
\n
    relation(\'==\', \'===\');\n
    relation(\'===\');\n
    relation(\'!=\', \'!==\');\n
    relation(\'!==\');\n
    relation(\'<\');\n
    relation(\'>\');\n
    relation(\'<=\');\n
    relation(\'>=\');\n
\n
    bitwise(\'<<\', 120);\n
    bitwise(\'>>\', 120);\n
    bitwise(\'>>>\', 120);\n
\n
    infix(\'in\', 120, function (left, that) {\n
        that.warn(\'infix_in\');\n
        that.left = left;\n
        that.right = expression(130);\n
        return that;\n
    });\n
    infix(\'instanceof\', 120);\n
    infix(\'+\', 130, function (left, that) {\n
        if (left.id === \'(number)\') {\n
            if (left.number === 0) {\n
                left.warn(\'unexpected_a\', \'0\');\n
            }\n
        } else if (left.id === \'(string)\') {\n
            if (left.string === \'\') {\n
                left.warn(\'expected_a_b\', \'String\', \'\\\'\\\'\');\n
            }\n
        }\n
        var right = expression(130);\n
        if (right.id === \'(number)\') {\n
            if (right.number === 0) {\n
                right.warn(\'unexpected_a\', \'0\');\n
            }\n
        } else if (right.id === \'(string)\') {\n
            if (right.string === \'\') {\n
                right.warn(\'expected_a_b\', \'String\', \'\\\'\\\'\');\n
            }\n
        }\n
        if (left.id === right.id) {\n
            if (left.id === \'(string)\' || left.id === \'(number)\') {\n
                if (left.id === \'(string)\') {\n
                    left.string += right.string;\n
                    if (jx.test(left.string)) {\n
                        left.warn(\'url\');\n
                    }\n
                } else {\n
                    left.number += right.number;\n
                }\n
                left.thru = right.thru;\n
                return left;\n
            }\n
        }\n
        that.first = left;\n
        that.second = right;\n
        return that;\n
    });\n
    prefix(\'+\');\n
    prefix(\'+++\', function () {\n
        token.warn(\'confusing_a\');\n
        this.first = expression(150);\n
        this.arity = \'prefix\';\n
        return this;\n
    });\n
    infix(\'+++\', 130, function (left) {\n
        token.warn(\'confusing_a\');\n
        this.first = left;\n
        this.second = expression(130);\n
        return this;\n
    });\n
    infix(\'-\', 130, function (left, that) {\n
        if ((left.id === \'(number)\' && left.number === 0) || left.id === \'(string)\') {\n
            left.warn(\'unexpected_a\');\n
        }\n
        var right = expression(130);\n
        if ((right.id === \'(number)\' && right.number === 0) || right.id === \'(string)\') {\n
            right.warn(\'unexpected_a\');\n
        }\n
        if (left.id === right.id && left.id === \'(number)\') {\n
            left.number -= right.number;\n
            left.thru = right.thru;\n
            return left;\n
        }\n
        that.first = left;\n
        that.second = right;\n
        return that;\n
    });\n
    prefix(\'-\');\n
    prefix(\'---\', function () {\n
        token.warn(\'confusing_a\');\n
        this.first = expression(150);\n
        this.arity = \'prefix\';\n
        return this;\n
    });\n
    infix(\'---\', 130, function (left) {\n
        token.warn(\'confusing_a\');\n
        this.first = left;\n
        this.second = expression(130);\n
        return this;\n
    });\n
    infix(\'*\', 140, function (left, that) {\n
        if ((left.id === \'(number)\' && (left.number === 0 || left.number === 1)) || left.id === \'(string)\') {\n
            left.warn(\'unexpected_a\');\n
        }\n
        var right = expression(140);\n
        if ((right.id === \'(number)\' && (right.number === 0 || right.number === 1)) || right.id === \'(string)\') {\n
            right.warn(\'unexpected_a\');\n
        }\n
        if (left.id === right.id && left.id === \'(number)\') {\n
            left.number *= right.number;\n
            left.thru = right.thru;\n
            return left;\n
        }\n
        that.first = left;\n
        that.second = right;\n
        return that;\n
    });\n
    infix(\'/\', 140, function (left, that) {\n
        if ((left.id === \'(number)\' && left.number === 0) || left.id === \'(string)\') {\n
            left.warn(\'unexpected_a\');\n
        }\n
        var right = expression(140);\n
        if ((right.id === \'(number)\' && (right.number === 0 || right.number === 1)) || right.id === \'(string)\') {\n
            right.warn(\'unexpected_a\');\n
        }\n
        if (left.id === right.id && left.id === \'(number)\') {\n
            left.number /= right.number;\n
            left.thru = right.thru;\n
            return left;\n
        }\n
        that.first = left;\n
        that.second = right;\n
        return that;\n
    });\n
    infix(\'%\', 140, function (left, that) {\n
        if ((left.id === \'(number)\' && (left.number === 0 || left.number === 1)) || left.id === \'(string)\') {\n
            left.warn(\'unexpected_a\');\n
        }\n
        var right = expression(140);\n
        if ((right.id === \'(number)\' && right.number === 0) || right.id === \'(string)\') {\n
            right.warn(\'unexpected_a\');\n
        }\n
        if (left.id === right.id && left.id === \'(number)\') {\n
            left.number %= right.number;\n
            left.thru = right.thru;\n
            return left;\n
        }\n
        that.first = left;\n
        that.second = right;\n
        return that;\n
    });\n
\n
    suffix(\'++\');\n
    prefix(\'++\');\n
\n
    suffix(\'--\');\n
    prefix(\'--\');\n
    prefix(\'delete\', function (that) {\n
        one_space();\n
        var p = expression(0);\n
        if (!p || (p.id !== \'.\' && p.id !== \'[\')) {\n
            next_token.warn(\'deleted\');\n
        }\n
        that.first = p;\n
        return that;\n
    });\n
\n
\n
    prefix(\'~\', function (that) {\n
        no_space_only();\n
        if (!option.bitwise) {\n
            that.warn(\'unexpected_a\');\n
        }\n
        that.first = expression(150);\n
        return that;\n
    });\n
    function banger(that) {\n
        no_space_only();\n
        that.first = expected_condition(expression(150));\n
        if (bang[that.first.id] === that || that.first.assign) {\n
            that.warn(\'confusing_a\');\n
        }\n
        return that;\n
    }\n
    prefix(\'!\', banger);\n
    prefix(\'!!\', banger);\n
    prefix(\'typeof\');\n
    prefix(\'new\', function (that) {\n
        one_space();\n
        var c = expression(160), n, p, v;\n
        that.first = c;\n
        if (c.id !== \'function\') {\n
            if (c.identifier) {\n
                switch (c.string) {\n
                case \'Object\':\n
                    token.warn(\'use_object\');\n
                    break;\n
                case \'Array\':\n
                    if (next_token.id === \'(\') {\n
                        p = next_token;\n
                        p.first = this;\n
                        advance(\'(\');\n
                        if (next_token.id !== \')\') {\n
                            n = expression(0);\n
                            p.second = [n];\n
                            if (n.id === \'(string)\' || next_token.id === \',\') {\n
                                p.warn(\'use_array\');\n
                            }\n
                            while (next_token.id === \',\') {\n
                                advance(\',\');\n
                                p.second.push(expression(0));\n
                            }\n
                        } else {\n
                            token.warn(\'use_array\');\n
                        }\n
                        advance(\')\', p);\n
                        return p;\n
                    }\n
                    token.warn(\'use_array\');\n
                    break;\n
                case \'Number\':\n
                case \'String\':\n
                case \'Boolean\':\n
                case \'Math\':\n
                case \'JSON\':\n
                    c.warn(\'not_a_constructor\');\n
                    break;\n
                case \'Function\':\n
                    if (!option.evil) {\n
                        next_token.warn(\'function_eval\');\n
                    }\n
                    break;\n
                case \'Date\':\n
                case \'RegExp\':\n
                case \'this\':\n
                    break;\n
                default:\n
                    if (c.id !== \'function\') {\n
                        v = c.string.charAt(0);\n
                        if (!option.newcap && (v < \'A\' || v > \'Z\')) {\n
                            token.warn(\'constructor_name_a\');\n
                        }\n
                    }\n
                }\n
            } else {\n
                if (c.id !== \'.\' && c.id !== \'[\' && c.id !== \'(\') {\n
                    token.warn(\'bad_constructor\');\n
                }\n
            }\n
        } else {\n
            that.warn(\'weird_new\');\n
        }\n
        if (next_token.id !== \'(\') {\n
            next_token.warn(\'missing_a\', \'()\');\n
        }\n
        return that;\n
    });\n
\n
    infix(\'(\', 160, function (left, that) {\n
        var e, p;\n
        if (indent && indent.mode === \'expression\') {\n
            no_space(prev_token, token);\n
        } else {\n
            no_space_only(prev_token, token);\n
        }\n
        if (!left.immed && left.id === \'function\') {\n
            next_token.warn(\'wrap_immediate\');\n
        }\n
        p = [];\n
        if (left.identifier) {\n
            if (left.string.match(/^[A-Z]([A-Z0-9_$]*[a-z][A-Za-z0-9_$]*)?$/)) {\n
                if (left.string !== \'Number\' && left.string !== \'String\' &&\n
                        left.string !== \'Boolean\' && left.string !== \'Date\') {\n
                    if (left.string === \'Math\') {\n
                        left.warn(\'not_a_function\');\n
                    } else if (left.string === \'Object\') {\n
                        token.warn(\'use_object\');\n
                    } else if (left.string === \'Array\' || !option.newcap) {\n
                        left.warn(\'missing_a\', \'new\');\n
                    }\n
                }\n
            } else if (left.string === \'JSON\') {\n
                left.warn(\'not_a_function\');\n
            }\n
        } else if (left.id === \'.\') {\n
            if (left.second.string === \'split\' &&\n
                    left.first.id === \'(string)\') {\n
                left.second.warn(\'use_array\');\n
            }\n
        }\n
        step_in();\n
        if (next_token.id !== \')\') {\n
            no_space();\n
            for (;;) {\n
                edge();\n
                e = expression(10);\n
                if (left.string === \'Boolean\' && (e.id === \'!\' || e.id === \'~\')) {\n
                    e.warn(\'weird_condition\');\n
                }\n
                p.push(e);\n
                if (next_token.id !== \',\') {\n
                    break;\n
                }\n
                comma();\n
            }\n
        }\n
        no_space();\n
        step_out(\')\', that);\n
        if (typeof left === \'object\') {\n
            if (left.string === \'parseInt\' && p.length === 1) {\n
                left.warn(\'radix\');\n
            } else if (left.string === \'String\' && p.length >= 1 && p[0].id === \'(string)\') {\n
                left.warn(\'unexpected_a\');\n
            }\n
            if (!option.evil) {\n
                if (left.string === \'eval\' || left.string === \'Function\' ||\n
                        left.string === \'execScript\') {\n
                    left.warn(\'evil\');\n
                } else if (p[0] && p[0].id === \'(string)\' &&\n
                        (left.string === \'setTimeout\' ||\n
                        left.string === \'setInterval\')) {\n
                    left.warn(\'implied_evil\');\n
                }\n
            }\n
            if (!left.identifier && left.id !== \'.\' && left.id !== \'[\' &&\n
                    left.id !== \'(\' && left.id !== \'&&\' && left.id !== \'||\' &&\n
                    left.id !== \'?\') {\n
                left.warn(\'bad_invocation\');\n
            }\n
            if (left.id === \'.\') {\n
                if (p.length > 0 &&\n
                        left.first && left.first.first &&\n
                        are_similar(p[0], left.first.first)) {\n
                    if (left.second.string === \'call\' ||\n
                            (left.second.string === \'apply\' && (p.length === 1 ||\n
                            (p[1].arity === \'prefix\' && p[1].id === \'[\')))) {\n
                        left.second.warn(\'unexpected_a\');\n
                    }\n
                }\n
                if (left.second.string === \'toString\') {\n
                    if (left.first.id === \'(string)\' || left.first.id === \'(number)\') {\n
                        left.second.warn(\'unexpected_a\');\n
                    }\n
                }\n
            }\n
        }\n
        that.first = left;\n
        that.second = p;\n
        return that;\n
    }, true);\n
\n
    prefix(\'(\', function (that) {\n
        step_in(\'expression\');\n
        no_space();\n
        edge();\n
        if (next_token.id === \'function\') {\n
            next_token.immed = true;\n
        }\n
        var value = expression(0);\n
        value.paren = true;\n
        no_space();\n
        step_out(\')\', that);\n
        if (value.id === \'function\') {\n
            switch (next_token.id) {\n
            case \'(\':\n
                next_token.warn(\'move_invocation\');\n
                break;\n
            case \'.\':\n
            case \'[\':\n
                next_token.warn(\'unexpected_a\');\n
                break;\n
            default:\n
                that.warn(\'bad_wrap\');\n
            }\n
        } else if (!value.arity) {\n
            if (!option.closure || !that.comments) {\n
                that.warn(\'unexpected_a\');\n
            }\n
        }\n
        return value;\n
    });\n
\n
    infix(\'.\', 170, function (left, that) {\n
        no_space(prev_token, token);\n
        no_space();\n
        var name = identifier();\n
        if (typeof name === \'string\') {\n
            tally_property(name);\n
        }\n
        that.first = left;\n
        that.second = token;\n
        if (left && left.string === \'arguments\' &&\n
                (name === \'callee\' || name === \'caller\')) {\n
            left.warn(\'avoid_a\', \'arguments.\' + name);\n
        } else if (!option.evil && left && left.string === \'document\' &&\n
                (name === \'write\' || name === \'writeln\')) {\n
            left.warn(\'write_is_wrong\');\n
        } else if (!option.stupid && syx.test(name)) {\n
            token.warn(\'sync_a\');\n
        }\n
        if (!option.evil && (name === \'eval\' || name === \'execScript\')) {\n
            next_token.warn(\'evil\');\n
        }\n
        return that;\n
    }, true);\n
\n
    infix(\'[\', 170, function (left, that) {\n
        var e, s;\n
        no_space_only(prev_token, token);\n
        no_space();\n
        step_in();\n
        edge();\n
        e = expression(0);\n
        switch (e.id) {\n
        case \'(number)\':\n
            if (e.id === \'(number)\' && left.id === \'arguments\') {\n
                left.warn(\'use_param\');\n
            }\n
            break;\n
        case \'(string)\':\n
            if (!option.evil &&\n
                    (e.string === \'eval\' || e.string === \'execScript\')) {\n
                e.warn(\'evil\');\n
            } else if (!option.sub && ix.test(e.string)) {\n
                s = syntax[e.string];\n
                if (!s || !s.reserved) {\n
                    e.warn(\'subscript\');\n
                }\n
            }\n
            tally_property(e.string);\n
            break;\n
        }\n
        step_out(\']\', that);\n
        no_space(prev_token, token);\n
        that.first = left;\n
        that.second = e;\n
        return that;\n
    }, true);\n
\n
    prefix(\'[\', function (that) {\n
        that.first = [];\n
        step_in(\'array\');\n
        while (next_token.id !== \'(end)\') {\n
            while (next_token.id === \',\') {\n
                next_token.warn(\'unexpected_a\');\n
                advance(\',\');\n
            }\n
            if (next_token.id === \']\') {\n
                break;\n
            }\n
            indent.wrap = false;\n
            edge();\n
            that.first.push(expression(10));\n
            if (next_token.id === \',\') {\n
                comma();\n
                if (next_token.id === \']\') {\n
                    token.warn(\'unexpected_a\');\n
                    break;\n
                }\n
            } else {\n
                break;\n
            }\n
        }\n
        step_out(\']\', that);\n
        return that;\n
    }, 170);\n
\n
\n
    function property_name() {\n
        var id = optional_identifier();\n
        if (!id) {\n
            if (next_token.id === \'(string)\') {\n
                id = next_token.string;\n
                advance();\n
            } else if (next_token.id === \'(number)\') {\n
                id = next_token.number.toString();\n
                advance();\n
            }\n
        }\n
        return id;\n
    }\n
\n
\n
\n
    assignop(\'=\');\n
    assignop(\'+=\', \'+\');\n
    assignop(\'-=\', \'-\');\n
    assignop(\'*=\', \'*\');\n
    assignop(\'/=\', \'/\').nud = function () {\n
        next_token.stop(\'slash_equal\');\n
    };\n
    assignop(\'%=\', \'%\');\n
    assignop(\'&=\', \'&\');\n
    assignop(\'|=\', \'|\');\n
    assignop(\'^=\', \'^\');\n
    assignop(\'<<=\', \'<<\');\n
    assignop(\'>>=\', \'>>\');\n
    assignop(\'>>>=\', \'>>>\');\n
\n
    function function_parameters() {\n
        var id, parameters = [], paren = next_token;\n
        advance(\'(\');\n
        token.function = funct;\n
        step_in();\n
        no_space();\n
        if (next_token.id !== \')\') {\n
            for (;;) {\n
                edge();\n
                id = identifier();\n
                define(\'parameter\', token);\n
                parameters.push(id);\n
                token.init = true;\n
                token.writeable = true;\n
                if (next_token.id !== \',\') {\n
                    break;\n
                }\n
                comma();\n
            }\n
        }\n
        no_space();\n
        step_out(\')\', paren);\n
        return parameters;\n
    }\n
\n
    function do_function(func, name) {\n
        var old_funct = funct,\n
            old_option = option,\n
            old_scope = scope;\n
        scope = Object.create(old_scope);\n
        funct = {\n
            closure: [],\n
            global: [],\n
            level: old_funct.level + 1,\n
            line: next_token.line,\n
            loopage: 0,\n
            name: name || \'\\\'\' + (anonname || \'\').replace(nx, sanitize) + \'\\\'\',\n
            outer: [],\n
            scope: scope\n
        };\n
        funct.parameter = function_parameters();\n
        func.function = funct;\n
        option = Object.create(old_option);\n
        functions.push(funct);\n
        if (name) {\n
            func.name = name;\n
            func.string = name;\n
            define(\'function\', func);\n
            func.init = true;\n
            func.used += 1;\n
        }\n
        func.writeable = false;\n
        one_space();\n
        func.block = block(\'function\');\n
        Object.keys(scope).forEach(function (name) {\n
            var master = scope[name];\n
            if (!master.used && master.kind !== \'exception\' &&\n
                    (master.kind !== \'parameter\' || !option.unparam)) {\n
                master.warn(\'unused_a\');\n
            } else if (!master.init) {\n
                master.warn(\'uninitialized_a\');\n
            }\n
        });\n
        funct = old_funct;\n
        option = old_option;\n
        scope = old_scope;\n
    }\n
\n
    prefix(\'{\', function (that) {\n
        var get, i, j, name, set, seen = Object.create(null);\n
        that.first = [];\n
        step_in();\n
        while (next_token.id !== \'}\') {\n
            indent.wrap = false;\n
\n
// JSLint recognizes the ES5 extension for get/set in object literals,\n
// but requires that they be used in pairs.\n
\n
            edge();\n
            if (next_token.string === \'get\' && peek().id !== \':\') {\n
                get = next_token;\n
                advance(\'get\');\n
                one_space_only();\n
                name = next_token;\n
                i = property_name();\n
                if (!i) {\n
                    next_token.stop(\'missing_property\');\n
                }\n
                get.string = \'\';\n
                do_function(get);\n
                if (funct.loopage) {\n
                    get.warn(\'function_loop\');\n
                }\n
                if (get.function.parameter.length) {\n
                    get.warn(\'parameter_a_get_b\', get.function.parameter[0], i);\n
                }\n
                comma();\n
                set = next_token;\n
                spaces();\n
                edge();\n
                advance(\'set\');\n
                set.string = \'\';\n
                one_space_only();\n
                j = property_name();\n
                if (i !== j) {\n
                    token.stop(\'expected_a_b\', i, j || next_token.string);\n
                }\n
                do_function(set);\n
                if (set.block.length === 0) {\n
                    token.warn(\'missing_a\', \'throw\');\n
                }\n
                if (set.function.parameter.length === 0) {\n
                    set.stop(\'parameter_set_a\', \'value\');\n
                } else if (set.function.parameter[0] !== \'value\') {\n
                    set.stop(\'expected_a_b\', \'value\',\n
                        set.function.parameter[0]);\n
                }\n
                name.first = [get, set];\n
            } else {\n
                name = next_token;\n
                i = property_name();\n
                if (typeof i !== \'string\') {\n
                    next_token.stop(\'missing_property\');\n
                }\n
                advance(\':\');\n
                spaces();\n
                name.first = expression(10);\n
            }\n
            that.first.push(name);\n
            if (seen[i] === true) {\n
                next_token.warn(\'duplicate_a\', i);\n
            }\n
            seen[i] = true;\n
            tally_property(i);\n
            if (next_token.id !== \',\') {\n
                break;\n
            }\n
            for (;;) {\n
                comma();\n
                if (next_token.id !== \',\') {\n
                    break;\n
                }\n
                next_token.warn(\'unexpected_a\');\n
            }\n
            if (next_token.id === \'}\') {\n
                token.warn(\'unexpected_a\');\n
            }\n
        }\n
        step_out(\'}\', that);\n
        return that;\n
    });\n
\n
    stmt(\'{\', function () {\n
        next_token.warn(\'statement_block\');\n
        this.arity = \'statement\';\n
        this.block = statements();\n
        this.disrupt = this.block.disrupt;\n
        advance(\'}\', this);\n
        return this;\n
    });\n
\n
    stmt(\'/*global\', directive);\n
    stmt(\'/*globals\', directive);\n
    stmt(\'/*jslint\', directive);\n
    stmt(\'/*member\', directive);\n
    stmt(\'/*members\', directive);\n
    stmt(\'/*property\', directive);\n
    stmt(\'/*properties\', directive);\n
\n
    stmt(\'var\', function () {\n
\n
// JavaScript does not have block scope. It only has function scope. So,\n
// declaring a variable in a block can have unexpected consequences.\n
\n
// var.first will contain an array, the array containing name tokens\n
// and assignment tokens.\n
\n
        var assign, id, name;\n
\n
        if (funct.loopage) {\n
            next_token.warn(\'var_loop\');\n
        } else if (funct.varstatement && !option.vars) {\n
            next_token.warn(\'combine_var\');\n
        }\n
        if (funct !== global_funct) {\n
            funct.varstatement = true;\n
        }\n
        this.arity = \'statement\';\n
        this.first = [];\n
        step_in(\'var\');\n
        for (;;) {\n
            name = next_token;\n
            id = identifier(true);\n
            define(\'var\', name);\n
            name.dead = funct;\n
            if (next_token.id === \'=\') {\n
                if (funct === global_funct && !name.writeable) {\n
                    name.warn(\'read_only\');\n
                }\n
                assign = next_token;\n
                assign.first = name;\n
                spaces();\n
                advance(\'=\');\n
                spaces();\n
                if (next_token.id === \'undefined\') {\n
                    token.warn(\'unnecessary_initialize\', id);\n
                }\n
                if (peek(0).id === \'=\' && next_token.identifier) {\n
                    next_token.stop(\'var_a_not\');\n
                }\n
                assign.second = expression(0);\n
                assign.arity = \'infix\';\n
                name.init = true;\n
                this.first.push(assign);\n
            } else {\n
                this.first.push(name);\n
            }\n
            name.dead = false;\n
            name.writeable = true;\n
            if (next_token.id !== \',\') {\n
                break;\n
            }\n
            comma();\n
            indent.wrap = false;\n
            if (var_mode && next_token.line === token.line &&\n
                    this.first.length === 1) {\n
                var_mode = null;\n
                indent.open = false;\n
                indent.at -= option.indent;\n
            }\n
            spaces();\n
            edge();\n
        }\n
        var_mode = null;\n
        step_out();\n
        return this;\n
    });\n
\n
    stmt(\'function\', function () {\n
        one_space();\n
        if (in_block) {\n
            token.warn(\'function_block\');\n
        }\n
        var name = next_token,\n
            id = identifier(true);\n
        define(\'var\', name);\n
        if (!name.writeable) {\n
            name.warn(\'read_only\');\n
        }\n
        name.init = true;\n
        name.statement = true;\n
        no_space();\n
        this.arity = \'statement\';\n
        do_function(this, id);\n
        if (next_token.id === \'(\' && next_token.line === token.line) {\n
            next_token.stop(\'function_statement\');\n
        }\n
        return this;\n
    });\n
\n
    prefix(\'function\', function (that) {\n
        var id = optional_identifier(true), name;\n
        if (id) {\n
            name = token;\n
            no_space();\n
        } else {\n
            id = \'\';\n
            one_space();\n
        }\n
        do_function(that, id);\n
        if (name) {\n
            name.function = that.function;\n
        }\n
        if (funct.loopage) {\n
            that.warn(\'function_loop\');\n
        }\n
        switch (next_token.id) {\n
        case \';\':\n
        case \'(\':\n
        case \')\':\n
        case \',\':\n
        case \']\':\n
        case \'}\':\n
        case \':\':\n
        case \'(end)\':\n
            break;\n
        case \'.\':\n
            if (peek().string !== \'bind\' || peek(1).id !== \'(\') {\n
                next_token.warn(\'unexpected_a\');\n
            }\n
            break;\n
        default:\n
            next_token.stop(\'unexpected_a\');\n
        }\n
        that.arity = \'function\';\n
        return that;\n
    });\n
\n
    stmt(\'if\', function () {\n
        var paren = next_token;\n
        one_space();\n
        advance(\'(\');\n
        step_in(\'control\');\n
        no_space();\n
        edge();\n
        this.arity = \'statement\';\n
        this.first = expected_condition(expected_relation(expression(0)));\n
        no_space();\n
        step_out(\')\', paren);\n
        one_space();\n
        this.block = block(\'if\');\n
        if (next_token.id === \'else\') {\n
            if (this.block.disrupt) {\n
                next_token.warn(this.elif ? \'use_nested_if\' : \'unnecessary_else\');\n
            }\n
            one_space();\n
            advance(\'else\');\n
            one_space();\n
            if (next_token.id === \'if\') {\n
                next_token.elif = true;\n
                this.else = statement(true);\n
            } else {\n
                this.else = block(\'else\');\n
            }\n
            if (this.else.disrupt && this.block.disrupt) {\n
                this.disrupt = true;\n
            }\n
        }\n
        return this;\n
    });\n
\n
    stmt(\'try\', function () {\n
\n
// try.first    The catch variable\n
// try.second   The catch clause\n
// try.third    The finally clause\n
// try.block    The try block\n
\n
        var exception_variable, paren;\n
        one_space();\n
        this.arity = \'statement\';\n
        this.block = block(\'try\');\n
        if (next_token.id === \'catch\') {\n
            one_space();\n
            advance(\'catch\');\n
            one_space();\n
            paren = next_token;\n
            advance(\'(\');\n
            step_in(\'control\');\n
            no_space();\n
            edge();\n
            exception_variable = next_token;\n
            this.first = identifier();\n
            define(\'exception\', exception_variable);\n
            exception_variable.init = true;\n
            no_space();\n
            step_out(\')\', paren);\n
            one_space();\n
            this.second = block(\'catch\');\n
            if (this.second.length) {\n
                if (this.first === \'ignore\') {\n
                    exception_variable.warn(\'unexpected_a\');\n
                }\n
            } else {\n
                if (this.first !== \'ignore\') {\n
                    exception_variable.warn(\'expected_a_b\', \'ignore\',\n
                        exception_variable.string);\n
                }\n
            }\n
            exception_variable.dead = true;\n
        }\n
        if (next_token.id === \'finally\') {\n
            one_space();\n
            advance(\'finally\');\n
            one_space();\n
            this.third = block(\'finally\');\n
        } else if (!this.second) {\n
            next_token.stop(\'expected_a_b\', \'catch\', artifact());\n
        }\n
        return this;\n
    });\n
\n
    labeled_stmt(\'while\', function () {\n
        one_space();\n
        var paren = next_token;\n
        funct.loopage += 1;\n
        advance(\'(\');\n
        step_in(\'control\');\n
        no_space();\n
        edge();\n
        this.arity = \'statement\';\n
        this.first = expected_relation(expression(0));\n
        if (this.first.id !== \'true\') {\n
            expected_condition(this.first, \'unexpected_a\');\n
        }\n
        no_space();\n
        step_out(\')\', paren);\n
        one_space();\n
        this.block = block(\'while\');\n
        if (this.block.disrupt) {\n
            prev_token.warn(\'strange_loop\');\n
        }\n
        funct.loopage -= 1;\n
        return this;\n
    });\n
\n
    reserve(\'with\');\n
\n
    labeled_stmt(\'switch\', function () {\n
\n
// switch.first         the switch expression\n
// switch.second        the array of cases. A case is \'case\' or \'default\' token:\n
//    case.first        the array of case expressions\n
//    case.second       the array of statements\n
// If all of the arrays of statements are disrupt, then the switch is disrupt.\n
\n
        var cases = [],\n
            old_in_block = in_block,\n
            particular,\n
            that = token,\n
            the_case = next_token;\n
\n
        function find_duplicate_case(value) {\n
            if (are_similar(particular, value)) {\n
                value.warn(\'duplicate_a\');\n
            }\n
        }\n
\n
        one_space();\n
        advance(\'(\');\n
        no_space();\n
        step_in();\n
        this.arity = \'statement\';\n
        this.first = expected_condition(expected_relation(expression(0)));\n
        no_space();\n
        step_out(\')\', the_case);\n
        one_space();\n
        advance(\'{\');\n
        step_in();\n
        in_block = true;\n
        this.second = [];\n
        if (that.from !== next_token.from && !option.white) {\n
            next_token.warn(\'expected_a_at_b_c\', next_token.string, that.from, next_token.from);\n
        }\n
        while (next_token.id === \'case\') {\n
            the_case = next_token;\n
            the_case.first = [];\n
            the_case.arity = \'case\';\n
            for (;;) {\n
                spaces();\n
                edge(\'case\');\n
                advance(\'case\');\n
                one_space();\n
                particular = expression(0);\n
                cases.forEach(find_duplicate_case);\n
                cases.push(particular);\n
                the_case.first.push(particular);\n
                if (particular.id === \'NaN\') {\n
                    particular.warn(\'unexpected_a\');\n
                }\n
                no_space_only();\n
                advance(\':\');\n
                if (next_token.id !== \'case\') {\n
                    break;\n
                }\n
            }\n
            spaces();\n
            the_case.second = statements();\n
            if (the_case.second && the_case.second.length > 0) {\n
                if (!the_case.second[the_case.second.length - 1].disrupt) {\n
                    next_token.warn(\'missing_a_after_b\', \'break\', \'case\');\n
                }\n
            } else {\n
                next_token.warn(\'empty_case\');\n
            }\n
            this.second.push(the_case);\n
        }\n
        if (this.second.length === 0) {\n
            next_token.warn(\'missing_a\', \'case\');\n
        }\n
        if (next_token.id === \'default\') {\n
            spaces();\n
            the_case = next_token;\n
            the_case.arity = \'case\';\n
            edge(\'case\');\n
            advance(\'default\');\n
            no_space_only();\n
            advance(\':\');\n
            spaces();\n
            the_case.second = statements();\n
            if (the_case.second && the_case.second.length > 0) {\n
                this.disrupt = the_case.second[the_case.second.length - 1].disrupt;\n
            } else {\n
                the_case.warn(\'empty_case\');\n
            }\n
            this.second.push(the_case);\n
        }\n
        if (this.break) {\n
            this.disrupt = false;\n
        }\n
        spaces();\n
        step_out(\'}\', this);\n
        in_block = old_in_block;\n
        return this;\n
    });\n
\n
    stmt(\'debugger\', function () {\n
        if (!option.debug) {\n
            this.warn(\'unexpected_a\');\n
        }\n
        this.arity = \'statement\';\n
        return this;\n
    });\n
\n
    labeled_stmt(\'do\', function () {\n
        funct.loopage += 1;\n
        one_space();\n
        this.arity = \'statement\';\n
        this.block = block(\'do\');\n
        if (this.block.disrupt) {\n
            prev_token.warn(\'strange_loop\');\n
        }\n
        one_space();\n
        advance(\'while\');\n
        var paren = next_token;\n
        one_space();\n
        advance(\'(\');\n
        step_in();\n
        no_space();\n
        edge();\n
        this.first = expected_condition(expected_relation(expression(0)), \'unexpected_a\');\n
        no_space();\n
        step_out(\')\', paren);\n
        funct.loopage -= 1;\n
        return this;\n
    });\n
\n
    labeled_stmt(\'for\', function () {\n
\n
        var blok, filter, master, ok = false, paren = next_token, value;\n
        this.arity = \'statement\';\n
        funct.loopage += 1;\n
        advance(\'(\');\n
        if (next_token.id === \';\') {\n
            no_space();\n
            advance(\';\');\n
            no_space();\n
            advance(\';\');\n
            no_space();\n
            advance(\')\');\n
            blok = block(\'for\');\n
        } else {\n
            step_in(\'control\');\n
            spaces(this, paren);\n
            no_space();\n
            if (next_token.id === \'var\') {\n
                next_token.stop(\'move_var\');\n
            }\n
            edge();\n
            if (peek(0).id === \'in\') {\n
                this.forin = true;\n
                value = expression(1000);\n
                master = value.master;\n
                if (!master) {\n
                    value.stop(\'bad_in_a\');\n
                }\n
                if (master.kind !== \'var\' || master.function !== funct ||\n
                        !master.writeable || master.dead) {\n
                    value.warn(\'bad_in_a\');\n
                }\n
                master.init = true;\n
                master.used -= 1;\n
                this.first = value;\n
                advance(\'in\');\n
                this.second = expression(20);\n
                step_out(\')\', paren);\n
                blok = block(\'for\');\n
                if (!option.forin) {\n
                    if (blok.length === 1 && typeof blok[0] === \'object\') {\n
                        if (blok[0].id === \'if\' && !blok[0].else) {\n
                            filter = blok[0].first;\n
                            while (filter.id === \'&&\') {\n
                                filter = filter.first;\n
                            }\n
                            switch (filter.id) {\n
                            case \'===\':\n
                            case \'!==\':\n
                                ok = filter.first.id === \'[\'\n
                                    ? are_similar(filter.first.first, this.second) &&\n
                                        are_similar(filter.first.second, this.first)\n
                                    : filter.first.id === \'typeof\' &&\n
                                        filter.first.first.id === \'[\' &&\n
                                        are_similar(filter.first.first.first, this.second) &&\n
                                        are_similar(filter.first.first.second, this.first);\n
                                break;\n
                            case \'(\':\n
                                ok = filter.first.id === \'.\' && ((\n
                                    are_similar(filter.first.first, this.second) &&\n
                                    filter.first.second.string === \'hasOwnProperty\' &&\n
                                    are_similar(filter.second[0], this.first)\n
                                ) || (\n
                                    filter.first.first.id === \'.\' &&\n
                                    filter.first.first.first.first &&\n
                                    filter.first.first.first.first.string === \'Object\' &&\n
                                    filter.first.first.first.id === \'.\' &&\n
                                    filter.first.first.first.second.string === \'prototype\' &&\n
                                    filter.first.first.second.string === \'hasOwnProperty\' &&\n
                                    filter.first.second.string === \'call\' &&\n
                                    are_similar(filter.second[0], this.second) &&\n
                                    are_similar(filter.second[1], this.first)\n
                                ));\n
                                break;\n
                            }\n
                        } else if (blok[0].id === \'switch\') {\n
                            ok = blok[0].id === \'switch\' &&\n
                                blok[0].first.id === \'typeof\' &&\n
                                blok[0].first.first.id === \'[\' &&\n
                                are_similar(blok[0].first.first.first, this.second) &&\n
                                are_similar(blok[0].first.first.second, this.first);\n
                        }\n
                    }\n
                    if (!ok) {\n
                        this.warn(\'for_if\');\n
                    }\n
                }\n
            } else {\n
                edge();\n
                this.first = [];\n
                for (;;) {\n
                    this.first.push(expression(0, \'for\'));\n
                    if (next_token.id !== \',\') {\n
                        break;\n
                    }\n
                    comma();\n
                }\n
                semicolon();\n
                edge();\n
                this.second = expected_relation(expression(0));\n
                if (this.second.id !== \'true\') {\n
                    expected_condition(this.second, \'unexpected_a\');\n
                }\n
                semicolon(token);\n
                if (next_token.id === \';\') {\n
                    next_token.stop(\'expected_a_b\', \')\', \';\');\n
                }\n
                this.third = [];\n
                edge();\n
                for (;;) {\n
                    this.third.push(expression(0, \'for\'));\n
                    if (next_token.id !== \',\') {\n
                        break;\n
                    }\n
                    comma();\n
                }\n
                no_space();\n
                step_out(\')\', paren);\n
                one_space();\n
                blok = block(\'for\');\n
            }\n
        }\n
        if (blok.disrupt) {\n
            prev_token.warn(\'strange_loop\');\n
        }\n
        this.block = blok;\n
        funct.loopage -= 1;\n
        return this;\n
    });\n
\n
    function optional_label(that) {\n
        var label = next_token.string,\n
            master;\n
        that.arity = \'statement\';\n
        if (!funct.breakage || (!option.continue && that.id === \'continue\')) {\n
            that.warn(\'unexpected_a\');\n
        } else if (next_token.identifier && token.line === next_token.line) {\n
            one_space_only();\n
            master = scope[label];\n
            if (!master || master.kind !== \'label\') {\n
                next_token.warn(\'not_a_label\');\n
            } else if (master.dead || master.function !== funct) {\n
                next_token.warn(\'not_a_scope\');\n
            } else {\n
                master.used += 1;\n
                if (that.id === \'break\') {\n
                    master.statement.break = true;\n
                }\n
                if (funct.breakage[funct.breakage.length - 1] === master.statement) {\n
                    next_token.warn(\'unexpected_a\');\n
                }\n
            }\n
            that.first = next_token;\n
            advance();\n
        } else {\n
            if (that.id === \'break\') {\n
                funct.breakage[funct.breakage.length - 1].break = true;\n
            }\n
        }\n
        return that;\n
\n
    }\n
\n
    disrupt_stmt(\'break\', function () {\n
        return optional_label(this);\n
    });\n
\n
    disrupt_stmt(\'continue\', function () {\n
        return optional_label(this);\n
    });\n
\n
    disrupt_stmt(\'return\', function () {\n
        if (funct === global_funct) {\n
            this.warn(\'unexpected_a\');\n
        }\n
        this.arity = \'statement\';\n
        if (next_token.id !== \';\' && next_token.line === token.line) {\n
            if (option.closure) {\n
                spaces();\n
            } else {\n
                one_space_only();\n
            }\n
            if (next_token.id === \'/\' || next_token.id === \'(regexp)\') {\n
                next_token.warn(\'wrap_regexp\');\n
            }\n
            this.first = expression(0);\n
            if (this.first.assign) {\n
                this.first.warn(\'unexpected_a\');\n
            }\n
        }\n
        return this;\n
    });\n
\n
    disrupt_stmt(\'throw\', function () {\n
        this.arity = \'statement\';\n
        one_space_only();\n
        this.first = expression(20);\n
        return this;\n
    });\n
\n
\n
//  Superfluous reserved words\n
\n
    reserve(\'class\');\n
    reserve(\'const\');\n
    reserve(\'enum\');\n
    reserve(\'export\');\n
    reserve(\'extends\');\n
    reserve(\'import\');\n
    reserve(\'super\');\n
\n
// Harmony reserved words\n
\n
    reserve(\'implements\');\n
    reserve(\'interface\');\n
    reserve(\'let\');\n
    reserve(\'package\');\n
    reserve(\'private\');\n
    reserve(\'protected\');\n
    reserve(\'public\');\n
    reserve(\'static\');\n
    reserve(\'yield\');\n
\n
\n
// Parse JSON\n
\n
    function json_value() {\n
\n
        function json_object() {\n
            var brace = next_token, object = Object.create(null);\n
            advance(\'{\');\n
            if (next_token.id !== \'}\') {\n
                while (next_token.id !== \'(end)\') {\n
                    while (next_token.id === \',\') {\n
                        next_token.warn(\'unexpected_a\');\n
                        advance(\',\');\n
                    }\n
                    if (next_token.id !== \'(string)\') {\n
                        next_token.warn(\'expected_string_a\');\n
                    }\n
                    if (object[next_token.string] === true) {\n
                        next_token.warn(\'duplicate_a\');\n
                    } else if (next_token.string === \'__proto__\') {\n
                        next_token.warn(\'dangling_a\');\n
                    } else {\n
                        object[next_token.string] = true;\n
                    }\n
                    advance();\n
                    advance(\':\');\n
                    json_value();\n
                    if (next_token.id !== \',\') {\n
                        break;\n
                    }\n
                    advance(\',\');\n
                    if (next_token.id === \'}\') {\n
                        token.warn(\'unexpected_a\');\n
                        break;\n
                    }\n
                }\n
            }\n
            advance(\'}\', brace);\n
        }\n
\n
        function json_array() {\n
            var bracket = next_token;\n
            advance(\'[\');\n
            if (next_token.id !== \']\') {\n
                while (next_token.id !== \'(end)\') {\n
                    while (next_token.id === \',\') {\n
                        next_token.warn(\'unexpected_a\');\n
                        advance(\',\');\n
                    }\n
                    json_value();\n
                    if (next_token.id !== \',\') {\n
                        break;\n
                    }\n
                    advance(\',\');\n
                    if (next_token.id === \']\') {\n
                        token.warn(\'unexpected_a\');\n
                        break;\n
                    }\n
                }\n
            }\n
            advance(\']\', bracket);\n
        }\n
\n
        switch (next_token.id) {\n
        case \'{\':\n
            json_object();\n
            break;\n
        case \'[\':\n
            json_array();\n
            break;\n
        case \'true\':\n
        case \'false\':\n
        case \'null\':\n
        case \'(number)\':\n
        case \'(string)\':\n
            advance();\n
            break;\n
        case \'-\':\n
            advance(\'-\');\n
            no_space_only();\n
            advance(\'(number)\');\n
            break;\n
        default:\n
            next_token.stop(\'unexpected_a\');\n
        }\n
    }\n
\n
\n
// The actual JSLINT function itself.\n
\n
    itself = function JSLint(the_source, the_option) {\n
\n
        var i, predef, tree;\n
        itself.errors = [];\n
        itself.tree = \'\';\n
        itself.properties = \'\';\n
        begin = prev_token = token = next_token =\n
            Object.create(syntax[\'(begin)\']);\n
        tokens = [];\n
        predefined = Object.create(null);\n
        add_to_predefined(standard);\n
        property = Object.create(null);\n
        if (the_option) {\n
            option = Object.create(the_option);\n
            predef = option.predef;\n
            if (predef) {\n
                if (Array.isArray(predef)) {\n
                    for (i = 0; i < predef.length; i += 1) {\n
                        predefined[predef[i]] = true;\n
                    }\n
                } else if (typeof predef === \'object\') {\n
                    add_to_predefined(predef);\n
                }\n
            }\n
        } else {\n
            option = Object.create(null);\n
        }\n
        option.indent = +option.indent || 4;\n
        option.maxerr = +option.maxerr || 50;\n
        global_scope = scope = Object.create(null);\n
        global_funct = funct = {\n
            scope: scope,\n
            loopage: 0,\n
            level: 0\n
        };\n
        functions = [funct];\n
        block_var = [];\n
\n
        comments = [];\n
        comments_off = false;\n
        in_block = false;\n
        indent = null;\n
        json_mode = false;\n
        lookahead = [];\n
        node_js = false;\n
        prereg = true;\n
        strict_mode = false;\n
        var_mode = null;\n
        warnings = 0;\n
        lex.init(the_source);\n
\n
        assume();\n
\n
        try {\n
            advance();\n
            if (next_token.id === \'(number)\') {\n
                next_token.stop(\'unexpected_a\');\n
            } else {\n
                switch (next_token.id) {\n
                case \'{\':\n
                case \'[\':\n
                    comments_off = true;\n
                    json_mode = true;\n
                    json_value();\n
                    break;\n
                default:\n
\n
// If the first token is a semicolon, ignore it. This is sometimes used when\n
// files are intended to be appended to files that may be sloppy. A sloppy\n
// file may be depending on semicolon insertion on its last line.\n
\n
                    step_in(1);\n
                    if (next_token.id === \';\' && !node_js) {\n
                        next_token.edge = true;\n
                        advance(\';\');\n
                    }\n
                    tree = statements();\n
                    begin.first = tree;\n
                    itself.tree = begin;\n
                    if (tree.disrupt) {\n
                        prev_token.warn(\'weird_program\');\n
                    }\n
                }\n
            }\n
            indent = null;\n
            advance(\'(end)\');\n
            itself.property = property;\n
        } catch (e) {\n
            if (e) {        // ~~\n
                itself.errors.push({\n
                    reason    : e.message,\n
                    line      : e.line || next_token.line,\n
                    character : e.character || next_token.from\n
                }, null);\n
            }\n
        }\n
        return itself.errors.length === 0;\n
    };\n
\n
    function unique(array) {\n
        array = array.sort();\n
        var i, length = 0, previous, value;\n
        for (i = 0; i < array.length; i += 1) {\n
            value = array[i];\n
            if (value !== previous) {\n
                array[length] = value;\n
                previous = value;\n
                length += 1;\n
            }\n
        }\n
        array.length = length;\n
        return array;\n
    }\n
\n
// Data summary.\n
\n
    itself.data = function () {\n
        var data = {functions: []},\n
            function_data,\n
            i,\n
            the_function,\n
            the_scope;\n
        data.errors = itself.errors;\n
        data.json = json_mode;\n
        data.global = unique(Object.keys(global_scope));\n
\n
        function selects(name) {\n
            var kind = the_scope[name].kind;\n
            switch (kind) {\n
            case \'var\':\n
            case \'exception\':\n
            case \'label\':\n
                function_data[kind].push(name);\n
                break;\n
            }\n
        }\n
\n
        for (i = 1; i < functions.length; i += 1) {\n
            the_function = functions[i];\n
            function_data = {\n
                name: the_function.name,\n
                line: the_function.line,\n
                level: the_function.level,\n
                parameter: the_function.parameter,\n
                var: [],\n
                exception: [],\n
                closure: unique(the_function.closure),\n
                outer: unique(the_function.outer),\n
                global: unique(the_function.global),\n
                label: []\n
            };\n
            the_scope = the_function.scope;\n
            Object.keys(the_scope).forEach(selects);\n
            function_data.var.sort();\n
            function_data.exception.sort();\n
            function_data.label.sort();\n
            data.functions.push(function_data);\n
        }\n
        data.tokens = tokens;\n
        return data;\n
    };\n
\n
    itself.error_report = function (data) {\n
        var evidence, i, output = [], warning;\n
        if (data.errors.length) {\n
            if (data.json) {\n
                output.push(\'<cite>JSON: bad.</cite><br>\');\n
            }\n
            for (i = 0; i < data.errors.length; i += 1) {\n
                warning = data.errors[i];\n
                if (warning) {\n
                    evidence = warning.evidence || \'\';\n
                    output.push(\'<cite>\');\n
                    if (isFinite(warning.line)) {\n
                        output.push(\'<address>line \' +\n
                            String(warning.line) +\n
                            \' character \' + String(warning.character) +\n
                            \'</address>\');\n
                    }\n
                    output.push(warning.reason.entityify() + \'</cite>\');\n
                    if (evidence) {\n
                        output.push(\'<pre>\' + evidence.entityify() + \'</pre>\');\n
                    }\n
                }\n
            }\n
        }\n
        return output.join(\'\');\n
    };\n
\n
\n
    itself.report = function (data) {\n
        var dl, i, j, names, output = [], the_function;\n
\n
        function detail(h, array) {\n
            var comma_needed = false;\n
            if (array.length) {\n
                output.push("<dt>" + h + "</dt><dd>");\n
                array.forEach(function (item) {\n
                    output.push((comma_needed ? \', \' : \'\') + item);\n
                    comma_needed = true;\n
                });\n
                output.push("</dd>");\n
            }\n
        }\n
\n
        output.push(\'<dl class=level0>\');\n
        if (data.global.length) {\n
            detail(\'global\', data.global);\n
            dl = true;\n
        } else if (data.json) {\n
            if (!data.errors.length) {\n
                output.push("<dt>JSON: good.</dt>");\n
            }\n
        } else {\n
            output.push("<dt><i>No new global variables introduced.</i></dt>");\n
        }\n
        if (dl) {\n
            output.push("</dl>");\n
        } else {\n
            output[0] = \'\';\n
        }\n
\n
        if (data.functions) {\n
            for (i = 0; i < data.functions.length; i += 1) {\n
                the_function = data.functions[i];\n
                names = [];\n
                if (the_function.params) {\n
                    for (j = 0; j < the_function.params.length; j += 1) {\n
                        names[j] = the_function.params[j].string;\n
                    }\n
                }\n
                output.push(\'<dl class=level\' + the_function.level +\n
                    \'><address>line \' + String(the_function.line) +\n
                    \'</address>\' + the_function.name.entityify());\n
                detail(\'parameter\', the_function.parameter);\n
                detail(\'variable\', the_function.var);\n
                detail(\'exception\', the_function.exception);\n
                detail(\'closure\', the_function.closure);\n
                detail(\'outer\', the_function.outer);\n
                detail(\'global\', the_function.global);\n
                detail(\'label\', the_function.label);\n
                output.push(\'</dl>\');\n
            }\n
        }\n
        return output.join(\'\');\n
    };\n
\n
    itself.properties_report = function (property) {\n
        if (!property) {\n
            return \'\';\n
        }\n
        var i,\n
            key,\n
            keys = Object.keys(property).sort(),\n
            mem = \'   \',\n
            name,\n
            not_first = false,\n
            output = [\'/*properties\'];\n
        for (i = 0; i < keys.length; i += 1) {\n
            key = keys[i];\n
            if (property[key] > 0) {\n
                if (not_first) {\n
                    mem += \',\';\n
                }\n
                name = ix.test(key)\n
                    ? key\n
                    : \'\\\'\' + key.replace(nx, sanitize) + \'\\\'\';\n
                if (mem.length + name.length >= 80) {\n
                    output.push(mem);\n
                    mem = \'    \';\n
                } else {\n
                    mem += \' \';\n
                }\n
                mem += name;\n
                not_first = true;\n
            }\n
        }\n
        output.push(mem, \'*/\\n\');\n
        return output.join(\'\\n\');\n
    };\n
\n
    itself.color = function (data) {\n
        var from,\n
            i = 1,\n
            level,\n
            line,\n
            result = [],\n
            thru,\n
            data_token = data.tokens[0];\n
        while (data_token && data_token.id !== \'(end)\') {\n
            from = data_token.from;\n
            line = data_token.line;\n
            thru = data_token.thru;\n
            level = data_token.function.level;\n
            do {\n
                thru = data_token.thru;\n
                data_token = data.tokens[i];\n
                i += 1;\n
            } while (data_token && data_token.line === line &&\n
                    data_token.from - thru < 5 &&\n
                    level === data_token.function.level);\n
            result.push({\n
                line: line,\n
                level: level,\n
                from: from,\n
                thru: thru\n
            });\n
        }\n
        return result;\n
    };\n
\n
    itself.jslint = itself;\n
\n
    itself.edition = \'2014-04-08\';\n
\n
    return itself;\n
}());

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>144477</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
