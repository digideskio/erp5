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
            <value> <string>ts21897134.39</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>puppet.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// CodeMirror, copyright (c) by Marijn Haverbeke and others\n
// Distributed under an MIT license: http://codemirror.net/LICENSE\n
\n
(function(mod) {\n
  if (typeof exports == "object" && typeof module == "object") // CommonJS\n
    mod(require("../../lib/codemirror"));\n
  else if (typeof define == "function" && define.amd) // AMD\n
    define(["../../lib/codemirror"], mod);\n
  else // Plain browser env\n
    mod(CodeMirror);\n
})(function(CodeMirror) {\n
"use strict";\n
\n
CodeMirror.defineMode("puppet", function () {\n
  // Stores the words from the define method\n
  var words = {};\n
  // Taken, mostly, from the Puppet official variable standards regex\n
  var variable_regex = /({)?([a-z][a-z0-9_]*)?((::[a-z][a-z0-9_]*)*::)?[a-zA-Z0-9_]+(})?/;\n
\n
  // Takes a string of words separated by spaces and adds them as\n
  // keys with the value of the first argument \'style\'\n
  function define(style, string) {\n
    var split = string.split(\' \');\n
    for (var i = 0; i < split.length; i++) {\n
      words[split[i]] = style;\n
    }\n
  }\n
\n
  // Takes commonly known puppet types/words and classifies them to a style\n
  define(\'keyword\', \'class define site node include import inherits\');\n
  define(\'keyword\', \'case if else in and elsif default or\');\n
  define(\'atom\', \'false true running present absent file directory undef\');\n
  define(\'builtin\', \'action augeas burst chain computer cron destination dport exec \' +\n
    \'file filebucket group host icmp iniface interface jump k5login limit log_level \' +\n
    \'log_prefix macauthorization mailalias maillist mcx mount nagios_command \' +\n
    \'nagios_contact nagios_contactgroup nagios_host nagios_hostdependency \' +\n
    \'nagios_hostescalation nagios_hostextinfo nagios_hostgroup nagios_service \' +\n
    \'nagios_servicedependency nagios_serviceescalation nagios_serviceextinfo \' +\n
    \'nagios_servicegroup nagios_timeperiod name notify outiface package proto reject \' +\n
    \'resources router schedule scheduled_task selboolean selmodule service source \' +\n
    \'sport ssh_authorized_key sshkey stage state table tidy todest toports tosource \' +\n
    \'user vlan yumrepo zfs zone zpool\');\n
\n
  // After finding a start of a string (\'|") this function attempts to find the end;\n
  // If a variable is encountered along the way, we display it differently when it\n
  // is encapsulated in a double-quoted string.\n
  function tokenString(stream, state) {\n
    var current, prev, found_var = false;\n
    while (!stream.eol() && (current = stream.next()) != state.pending) {\n
      if (current === \'$\' && prev != \'\\\\\' && state.pending == \'"\') {\n
        found_var = true;\n
        break;\n
      }\n
      prev = current;\n
    }\n
    if (found_var) {\n
      stream.backUp(1);\n
    }\n
    if (current == state.pending) {\n
      state.continueString = false;\n
    } else {\n
      state.continueString = true;\n
    }\n
    return "string";\n
  }\n
\n
  // Main function\n
  function tokenize(stream, state) {\n
    // Matches one whole word\n
    var word = stream.match(/[\\w]+/, false);\n
    // Matches attributes (i.e. ensure => present ; \'ensure\' would be matched)\n
    var attribute = stream.match(/(\\s+)?\\w+\\s+=>.*/, false);\n
    // Matches non-builtin resource declarations\n
    // (i.e. "apache::vhost {" or "mycustomclasss {" would be matched)\n
    var resource = stream.match(/(\\s+)?[\\w:_]+(\\s+)?{/, false);\n
    // Matches virtual and exported resources (i.e. @@user { ; and the like)\n
    var special_resource = stream.match(/(\\s+)?[@]{1,2}[\\w:_]+(\\s+)?{/, false);\n
\n
    // Finally advance the stream\n
    var ch = stream.next();\n
\n
    // Have we found a variable?\n
    if (ch === \'$\') {\n
      if (stream.match(variable_regex)) {\n
        // If so, and its in a string, assign it a different color\n
        return state.continueString ? \'variable-2\' : \'variable\';\n
      }\n
      // Otherwise return an invalid variable\n
      return "error";\n
    }\n
    // Should we still be looking for the end of a string?\n
    if (state.continueString) {\n
      // If so, go through the loop again\n
      stream.backUp(1);\n
      return tokenString(stream, state);\n
    }\n
    // Are we in a definition (class, node, define)?\n
    if (state.inDefinition) {\n
      // If so, return def (i.e. for \'class myclass {\' ; \'myclass\' would be matched)\n
      if (stream.match(/(\\s+)?[\\w:_]+(\\s+)?/)) {\n
        return \'def\';\n
      }\n
      // Match the rest it the next time around\n
      stream.match(/\\s+{/);\n
      state.inDefinition = false;\n
    }\n
    // Are we in an \'include\' statement?\n
    if (state.inInclude) {\n
      // Match and return the included class\n
      stream.match(/(\\s+)?\\S+(\\s+)?/);\n
      state.inInclude = false;\n
      return \'def\';\n
    }\n
    // Do we just have a function on our hands?\n
    // In \'ensure_resource("myclass")\', \'ensure_resource\' is matched\n
    if (stream.match(/(\\s+)?\\w+\\(/)) {\n
      stream.backUp(1);\n
      return \'def\';\n
    }\n
    // Have we matched the prior attribute regex?\n
    if (attribute) {\n
      stream.match(/(\\s+)?\\w+/);\n
      return \'tag\';\n
    }\n
    // Do we have Puppet specific words?\n
    if (word && words.hasOwnProperty(word)) {\n
      // Negates the initial next()\n
      stream.backUp(1);\n
      // Acutally move the stream\n
      stream.match(/[\\w]+/);\n
      // We want to process these words differently\n
      // do to the importance they have in Puppet\n
      if (stream.match(/\\s+\\S+\\s+{/, false)) {\n
        state.inDefinition = true;\n
      }\n
      if (word == \'include\') {\n
        state.inInclude = true;\n
      }\n
      // Returns their value as state in the prior define methods\n
      return words[word];\n
    }\n
    // Is there a match on a reference?\n
    if (/(^|\\s+)[A-Z][\\w:_]+/.test(word)) {\n
      // Negate the next()\n
      stream.backUp(1);\n
      // Match the full reference\n
      stream.match(/(^|\\s+)[A-Z][\\w:_]+/);\n
      return \'def\';\n
    }\n
    // Have we matched the prior resource regex?\n
    if (resource) {\n
      stream.match(/(\\s+)?[\\w:_]+/);\n
      return \'def\';\n
    }\n
    // Have we matched the prior special_resource regex?\n
    if (special_resource) {\n
      stream.match(/(\\s+)?[@]{1,2}/);\n
      return \'special\';\n
    }\n
    // Match all the comments. All of them.\n
    if (ch == "#") {\n
      stream.skipToEnd();\n
      return "comment";\n
    }\n
    // Have we found a string?\n
    if (ch == "\'" || ch == \'"\') {\n
      // Store the type (single or double)\n
      state.pending = ch;\n
      // Perform the looping function to find the end\n
      return tokenString(stream, state);\n
    }\n
    // Match all the brackets\n
    if (ch == \'{\' || ch == \'}\') {\n
      return \'bracket\';\n
    }\n
    // Match characters that we are going to assume\n
    // are trying to be regex\n
    if (ch == \'/\') {\n
      stream.match(/.*?\\//);\n
      return \'variable-3\';\n
    }\n
    // Match all the numbers\n
    if (ch.match(/[0-9]/)) {\n
      stream.eatWhile(/[0-9]+/);\n
      return \'number\';\n
    }\n
    // Match the \'=\' and \'=>\' operators\n
    if (ch == \'=\') {\n
      if (stream.peek() == \'>\') {\n
          stream.next();\n
      }\n
      return "operator";\n
    }\n
    // Keep advancing through all the rest\n
    stream.eatWhile(/[\\w-]/);\n
    // Return a blank line for everything else\n
    return null;\n
  }\n
  // Start it all\n
  return {\n
    startState: function () {\n
      var state = {};\n
      state.inDefinition = false;\n
      state.inInclude = false;\n
      state.continueString = false;\n
      state.pending = false;\n
      return state;\n
    },\n
    token: function (stream, state) {\n
      // Strip the spaces, but regex will account for them eitherway\n
      if (stream.eatSpace()) return null;\n
      // Go through the main process\n
      return tokenize(stream, state);\n
    }\n
  };\n
});\n
\n
CodeMirror.defineMIME("text/x-puppet", "puppet");\n
\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>7574</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
