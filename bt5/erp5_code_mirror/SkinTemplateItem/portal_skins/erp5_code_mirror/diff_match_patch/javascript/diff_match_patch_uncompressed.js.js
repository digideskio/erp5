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
            <value> <string>ts21898048.7</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>diff_match_patch_uncompressed.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>76493</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Pdata" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/**\n
 * Diff Match and Patch\n
 *\n
 * Copyright 2006 Google Inc.\n
 * http://code.google.com/p/google-diff-match-patch/\n
 *\n
 * Licensed under the Apache License, Version 2.0 (the "License");\n
 * you may not use this file except in compliance with the License.\n
 * You may obtain a copy of the License at\n
 *\n
 *   http://www.apache.org/licenses/LICENSE-2.0\n
 *\n
 * Unless required by applicable law or agreed to in writing, software\n
 * distributed under the License is distributed on an "AS IS" BASIS,\n
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n
 * See the License for the specific language governing permissions and\n
 * limitations under the License.\n
 */\n
\n
/**\n
 * @fileoverview Computes the difference between two texts to create a patch.\n
 * Applies the patch onto another text, allowing for errors.\n
 * @author fraser@google.com (Neil Fraser)\n
 */\n
\n
/**\n
 * Class containing the diff, match and patch methods.\n
 * @constructor\n
 */\n
function diff_match_patch() {\n
\n
  // Defaults.\n
  // Redefine these in your program to override the defaults.\n
\n
  // Number of seconds to map a diff before giving up (0 for infinity).\n
  this.Diff_Timeout = 1.0;\n
  // Cost of an empty edit operation in terms of edit characters.\n
  this.Diff_EditCost = 4;\n
  // At what point is no match declared (0.0 = perfection, 1.0 = very loose).\n
  this.Match_Threshold = 0.5;\n
  // How far to search for a match (0 = exact location, 1000+ = broad match).\n
  // A match this many characters away from the expected location will add\n
  // 1.0 to the score (0.0 is a perfect match).\n
  this.Match_Distance = 1000;\n
  // When deleting a large block of text (over ~64 characters), how close do\n
  // the contents have to be to match the expected contents. (0.0 = perfection,\n
  // 1.0 = very loose).  Note that Match_Threshold controls how closely the\n
  // end points of a delete need to match.\n
  this.Patch_DeleteThreshold = 0.5;\n
  // Chunk size for context length.\n
  this.Patch_Margin = 4;\n
\n
  // The number of bits in an int.\n
  this.Match_MaxBits = 32;\n
}\n
\n
\n
//  DIFF FUNCTIONS\n
\n
\n
/**\n
 * The data structure representing a diff is an array of tuples:\n
 * [[DIFF_DELETE, \'Hello\'], [DIFF_INSERT, \'Goodbye\'], [DIFF_EQUAL, \' world.\']]\n
 * which means: delete \'Hello\', add \'Goodbye\' and keep \' world.\'\n
 */\n
var DIFF_DELETE = -1;\n
var DIFF_INSERT = 1;\n
var DIFF_EQUAL = 0;\n
\n
/** @typedef {{0: number, 1: string}} */\n
diff_match_patch.Diff;\n
\n
\n
/**\n
 * Find the differences between two texts.  Simplifies the problem by stripping\n
 * any common prefix or suffix off the texts before diffing.\n
 * @param {string} text1 Old string to be diffed.\n
 * @param {string} text2 New string to be diffed.\n
 * @param {boolean=} opt_checklines Optional speedup flag. If present and false,\n
 *     then don\'t run a line-level diff first to identify the changed areas.\n
 *     Defaults to true, which does a faster, slightly less optimal diff.\n
 * @param {number} opt_deadline Optional time when the diff should be complete\n
 *     by.  Used internally for recursive calls.  Users should set DiffTimeout\n
 *     instead.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 */\n
diff_match_patch.prototype.diff_main = function(text1, text2, opt_checklines,\n
    opt_deadline) {\n
  // Set a deadline by which time the diff must be complete.\n
  if (typeof opt_deadline == \'undefined\') {\n
    if (this.Diff_Timeout <= 0) {\n
      opt_deadline = Number.MAX_VALUE;\n
    } else {\n
      opt_deadline = (new Date).getTime() + this.Diff_Timeout * 1000;\n
    }\n
  }\n
  var deadline = opt_deadline;\n
\n
  // Check for null inputs.\n
  if (text1 == null || text2 == null) {\n
    throw new Error(\'Null input. (diff_main)\');\n
  }\n
\n
  // Check for equality (speedup).\n
  if (text1 == text2) {\n
    if (text1) {\n
      return [[DIFF_EQUAL, text1]];\n
    }\n
    return [];\n
  }\n
\n
  if (typeof opt_checklines == \'undefined\') {\n
    opt_checklines = true;\n
  }\n
  var checklines = opt_checklines;\n
\n
  // Trim off common prefix (speedup).\n
  var commonlength = this.diff_commonPrefix(text1, text2);\n
  var commonprefix = text1.substring(0, commonlength);\n
  text1 = text1.substring(commonlength);\n
  text2 = text2.substring(commonlength);\n
\n
  // Trim off common suffix (speedup).\n
  commonlength = this.diff_commonSuffix(text1, text2);\n
  var commonsuffix = text1.substring(text1.length - commonlength);\n
  text1 = text1.substring(0, text1.length - commonlength);\n
  text2 = text2.substring(0, text2.length - commonlength);\n
\n
  // Compute the diff on the middle block.\n
  var diffs = this.diff_compute_(text1, text2, checklines, deadline);\n
\n
  // Restore the prefix and suffix.\n
  if (commonprefix) {\n
    diffs.unshift([DIFF_EQUAL, commonprefix]);\n
  }\n
  if (commonsuffix) {\n
    diffs.push([DIFF_EQUAL, commonsuffix]);\n
  }\n
  this.diff_cleanupMerge(diffs);\n
  return diffs;\n
};\n
\n
\n
/**\n
 * Find the differences between two texts.  Assumes that the texts do not\n
 * have any common prefix or suffix.\n
 * @param {string} text1 Old string to be diffed.\n
 * @param {string} text2 New string to be diffed.\n
 * @param {boolean} checklines Speedup flag.  If false, then don\'t run a\n
 *     line-level diff first to identify the changed areas.\n
 *     If true, then run a faster, slightly less optimal diff.\n
 * @param {number} deadline Time when the diff should be complete by.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_compute_ = function(text1, text2, checklines,\n
    deadline) {\n
  var diffs;\n
\n
  if (!text1) {\n
    // Just add some text (speedup).\n
    return [[DIFF_INSERT, text2]];\n
  }\n
\n
  if (!text2) {\n
    // Just delete some text (speedup).\n
    return [[DIFF_DELETE, text1]];\n
  }\n
\n
  var longtext = text1.length > text2.length ? text1 : text2;\n
  var shorttext = text1.length > text2.length ? text2 : text1;\n
  var i = longtext.indexOf(shorttext);\n
  if (i != -1) {\n
    // Shorter text is inside the longer text (speedup).\n
    diffs = [[DIFF_INSERT, longtext.substring(0, i)],\n
             [DIFF_EQUAL, shorttext],\n
             [DIFF_INSERT, longtext.substring(i + shorttext.length)]];\n
    // Swap insertions for deletions if diff is reversed.\n
    if (text1.length > text2.length) {\n
      diffs[0][0] = diffs[2][0] = DIFF_DELETE;\n
    }\n
    return diffs;\n
  }\n
\n
  if (shorttext.length == 1) {\n
    // Single character string.\n
    // After the previous speedup, the character can\'t be an equality.\n
    return [[DIFF_DELETE, text1], [DIFF_INSERT, text2]];\n
  }\n
\n
  // Check to see if the problem can be split in two.\n
  var hm = this.diff_halfMatch_(text1, text2);\n
  if (hm) {\n
    // A half-match was found, sort out the return data.\n
    var text1_a = hm[0];\n
    var text1_b = hm[1];\n
    var text2_a = hm[2];\n
    var text2_b = hm[3];\n
    var mid_common = hm[4];\n
    // Send both pairs off for separate processing.\n
    var diffs_a = this.diff_main(text1_a, text2_a, checklines, deadline);\n
    var diffs_b = this.diff_main(text1_b, text2_b, checklines, deadline);\n
    // Merge the results.\n
    return diffs_a.concat([[DIFF_EQUAL, mid_common]], diffs_b);\n
  }\n
\n
  if (checklines && text1.length > 100 && text2.length > 100) {\n
    return this.diff_lineMode_(text1, text2, deadline);\n
  }\n
\n
  return this.diff_bisect_(text1, text2, deadline);\n
};\n
\n
\n
/**\n
 * Do a quick line-level diff on both strings, then rediff the parts for\n
 * greater accuracy.\n
 * This speedup can produce non-minimal diffs.\n
 * @param {string} text1 Old string to be diffed.\n
 * @param {string} text2 New string to be diffed.\n
 * @param {number} deadline Time when the diff should be complete by.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_lineMode_ = function(text1, text2, deadline) {\n
  // Scan the text on a line-by-line basis first.\n
  var a = this.diff_linesToChars_(text1, text2);\n
  text1 = a.chars1;\n
  text2 = a.chars2;\n
  var linearray = a.lineArray;\n
\n
  var diffs = this.diff_main(text1, text2, false, deadline);\n
\n
  // Convert the diff back to original text.\n
  this.diff_charsToLines_(diffs, linearray);\n
  // Eliminate freak matches (e.g. blank lines)\n
  this.diff_cleanupSemantic(diffs);\n
\n
  // Rediff any replacement blocks, this time character-by-character.\n
  // Add a dummy entry at the end.\n
  diffs.push([DIFF_EQUAL, \'\']);\n
  var pointer = 0;\n
  var count_delete = 0;\n
  var count_insert = 0;\n
  var text_delete = \'\';\n
  var text_insert = \'\';\n
  while (pointer < diffs.length) {\n
    switch (diffs[pointer][0]) {\n
      case DIFF_INSERT:\n
        count_insert++;\n
        text_insert += diffs[pointer][1];\n
        break;\n
      case DIFF_DELETE:\n
        count_delete++;\n
        text_delete += diffs[pointer][1];\n
        break;\n
      case DIFF_EQUAL:\n
        // Upon reaching an equality, check for prior redundancies.\n
        if (count_delete >= 1 && count_insert >= 1) {\n
          // Delete the offending records and add the merged ones.\n
          diffs.splice(pointer - count_delete - count_insert,\n
                       count_delete + count_insert);\n
          pointer = pointer - count_delete - count_insert;\n
          var a = this.diff_main(text_delete, text_insert, false, deadline);\n
          for (var j = a.length - 1; j >= 0; j--) {\n
            diffs.splice(pointer, 0, a[j]);\n
          }\n
          pointer = pointer + a.length;\n
        }\n
        count_insert = 0;\n
        count_delete = 0;\n
        text_delete = \'\';\n
        text_insert = \'\';\n
        break;\n
    }\n
    pointer++;\n
  }\n
  diffs.pop();  // Remove the dummy entry at the end.\n
\n
  return diffs;\n
};\n
\n
\n
/**\n
 * Find the \'middle snake\' of a diff, split the problem in two\n
 * and return the recursively constructed diff.\n
 * See Myers 1986 paper: An O(ND) Difference Algorithm and Its Variations.\n
 * @param {string} text1 Old string to be diffed.\n
 * @param {string} text2 New string to be diffed.\n
 * @param {number} deadline Time at which to bail if not yet complete.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_bisect_ = function(text1, text2, deadline) {\n
  // Cache the text lengths to prevent multiple calls.\n
  var text1_length = text1.length;\n
  var text2_length = text2.length;\n
  var max_d = Math.ceil((text1_length + text2_length) / 2);\n
  var v_offset = max_d;\n
  var v_length = 2 * max_d;\n
  var v1 = new Array(v_length);\n
  var v2 = new Array(v_length);\n
  // Setting all elements to -1 is faster in Chrome & Firefox than mixing\n
  // integers and undefined.\n
  for (var x = 0; x < v_length; x++) {\n
    v1[x] = -1;\n
    v2[x] = -1;\n
  }\n
  v1[v_offset + 1] = 0;\n
  v2[v_offset + 1] = 0;\n
  var delta = text1_length - text2_length;\n
  // If the total number of characters is odd, then the front path will collide\n
  // with the reverse path.\n
  var front = (delta % 2 != 0);\n
  // Offsets for start and end of k loop.\n
  // Prevents mapping of space beyond the grid.\n
  var k1start = 0;\n
  var k1end = 0;\n
  var k2start = 0;\n
  var k2end = 0;\n
  for (var d = 0; d < max_d; d++) {\n
    // Bail out if deadline is reached.\n
    if ((new Date()).getTime() > deadline) {\n
      break;\n
    }\n
\n
    // Walk the front path one step.\n
    for (var k1 = -d + k1start; k1 <= d - k1end; k1 += 2) {\n
      var k1_offset = v_offset + k1;\n
      var x1;\n
      if (k1 == -d || (k1 != d && v1[k1_offset - 1] < v1[k1_offset + 1])) {\n
        x1 = v1[k1_offset + 1];\n
      } else {\n
        x1 = v1[k1_offset - 1] + 1;\n
      }\n
      var y1 = x1 - k1;\n
      while (x1 < text1_length && y1 < text2_length &&\n
             text1.charAt(x1) == text2.charAt(y1)) {\n
        x1++;\n
        y1++;\n
      }\n
      v1[k1_offset] = x1;\n
      if (x1 > text1_length) {\n
        // Ran off the right of the graph.\n
        k1end += 2;\n
      } else if (y1 > text2_length) {\n
        // Ran off the bottom of the graph.\n
        k1start += 2;\n
      } else if (front) {\n
        var k2_offset = v_offset + delta - k1;\n
        if (k2_offset >= 0 && k2_offset < v_length && v2[k2_offset] != -1) {\n
          // Mirror x2 onto top-left coordinate system.\n
          var x2 = text1_length - v2[k2_offset];\n
          if (x1 >= x2) {\n
            // Overlap detected.\n
            return this.diff_bisectSplit_(text1, text2, x1, y1, deadline);\n
          }\n
        }\n
      }\n
    }\n
\n
    // Walk the reverse path one step.\n
    for (var k2 = -d + k2start; k2 <= d - k2end; k2 += 2) {\n
      var k2_offset = v_offset + k2;\n
      var x2;\n
      if (k2 == -d || (k2 != d && v2[k2_offset - 1] < v2[k2_offset + 1])) {\n
        x2 = v2[k2_offset + 1];\n
      } else {\n
        x2 = v2[k2_offset - 1] + 1;\n
      }\n
      var y2 = x2 - k2;\n
      while (x2 < text1_length && y2 < text2_length &&\n
             text1.charAt(text1_length - x2 - 1) ==\n
             text2.charAt(text2_length - y2 - 1)) {\n
        x2++;\n
        y2++;\n
      }\n
      v2[k2_offset] = x2;\n
      if (x2 > text1_length) {\n
        // Ran off the left of the graph.\n
        k2end += 2;\n
      } else if (y2 > text2_length) {\n
        // Ran off the top of the graph.\n
        k2start += 2;\n
      } else if (!front) {\n
        var k1_offset = v_offset + delta - k2;\n
        if (k1_offset >= 0 && k1_offset < v_length && v1[k1_offset] != -1) {\n
          var x1 = v1[k1_offset];\n
          var y1 = v_offset + x1 - k1_offset;\n
          // Mirror x2 onto top-left coordinate system.\n
          x2 = text1_length - x2;\n
          if (x1 >= x2) {\n
            // Overlap detected.\n
            return this.diff_bisectSplit_(text1, text2, x1, y1, deadline);\n
          }\n
        }\n
      }\n
    }\n
  }\n
  // Diff took too long and hit the deadline or\n
  // number of diffs equals number of characters, no commonality at all.\n
  return [[DIFF_DELETE, text1], [DIFF_INSERT, text2]];\n
};\n
\n
\n
/**\n
 * Given the location of the \'middle snake\', split the diff in two parts\n
 * and recurse.\n
 * @param {string} text1 Old string to be diffed.\n
 * @param {string} text2 New string to be diffed.\n
 * @param {number} x Index of split point in text1.\n
 * @param {number} y Index of split point in text2.\n
 * @param {number} deadline Time at which to bail if not yet complete.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_bisectSplit_ = function(text1, text2, x, y,\n
    deadline) {\n
  var text1a = text1.substring(0, x);\n
  var text2a = text2.substring(0, y);\n
  var text1b = text1.substring(x);\n
  var text2b = text2.substring(y);\n
\n
  // Compute both diffs serially.\n
  var diffs = this.diff_main(text1a, text2a, false, deadline);\n
  var diffsb = this.diff_main(text1b, text2b, false, deadline);\n
\n
  return diffs.concat(diffsb);\n
};\n
\n
\n
/**\n
 * Split two texts into an array of strings.  Reduce the texts to a string of\n
 * hashes where each Unicode character represents one line.\n
 * @param {string} text1 First string.\n
 * @param {string} text2 Second string.\n
 * @return {{chars1: string, chars2: string, lineArray: !Array.<string>}}\n
 *     An object containing the encoded text1, the encoded text2 and\n
 *     the array of unique strings.\n
 *     The zeroth element of the array of unique strings is intentionally blank.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_linesToChars_ = function(text1, text2) {\n
  var lineArray = [];  // e.g. lineArray[4] == \'Hello\\n\'\n
  var lineHash = {};   // e.g. lineHash[\'Hello\\n\'] == 4\n
\n
  // \'\\x00\' is a valid character, but various debuggers don\'t like it.\n
  // So we\'ll insert a junk entry to avoid generating a null character.\n
  lineArray[0] = \'\';\n
\n
  /**\n
   * Split a text into an array of strings.  Reduce the texts to a string of\n
   * hashes where each Unicode character represents one line.\n
   * Modifies linearray and linehash through being a closure.\n
   * @param {string} text String to encode.\n
   * @return {string} Encoded string.\n
   * @private\n
   */\n
  function diff_linesToCharsMunge_(text) {\n
    var chars = \'\';\n
    // Walk the text, pulling out a substring for each line.\n
    // text.split(\'\\n\') would would temporarily double our memory footprint.\n
    // Modifying text would create many large strings to garbage collect.\n
    var lineStart = 0;\n
    var lineEnd = -1;\n
    // Keeping our own length variable is faster than looking it up.\n
    var lineArrayLength = lineArray.length;\n
    while (lineEnd < text.length - 1) {\n
      lineEnd = text.indexOf(\'\\n\', lineStart);\n
      if (lineEnd == -1) {\n
        lineEnd = text.length - 1;\n
      }\n
      var line = text.substring(lineStart, lineEnd + 1);\n
      lineStart = lineEnd + 1;\n
\n
      if (lineHash.hasOwnProperty ? lineHash.hasOwnProperty(line) :\n
          (lineHash[line] !== undefined)) {\n
        chars += String.fromCharCode(lineHash[line]);\n
      } else {\n
        chars += String.fromCharCode(lineArrayLength);\n
        lineHash[line] = lineArrayLength;\n
        lineArray[lineArrayLength++] = line;\n
      }\n
    }\n
    return chars;\n
  }\n
\n
  var chars1 = diff_linesToCharsMunge_(text1);\n
  var chars2 = diff_linesToCharsMunge_(text2);\n
  return {chars1: chars1, chars2: chars2, lineArray: lineArray};\n
};\n
\n
\n
/**\n
 * Rehydrate the text in a diff from a string of line hashes to real lines of\n
 * text.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @param {!Array.<string>} lineArray Array of unique strings.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_charsToLines_ = function(diffs, lineArray) {\n
  for (var x = 0; x < diffs.length; x++) {\n
    var chars = diffs[x][1];\n
    var text = [];\n
    for (var y = 0; y < chars.length; y++) {\n
      text[y] = lineArray[chars.charCodeAt(y)];\n
    }\n
    diffs[x][1] = text.join(\'\');\n
  }\n
};\n
\n
\n
/**\n
 * Determine the common prefix of two strings.\n
 * @param {string} text1 First string.\n
 * @param {string} text2 Second string.\n
 * @return {number} The number of characters common to the start of each\n
 *     string.\n
 */\n
diff_match_patch.prototype.diff_commonPrefix = function(text1, text2) {\n
  // Quick check for common null cases.\n
  if (!text1 || !text2 || text1.charAt(0) != text2.charAt(0)) {\n
    return 0;\n
  }\n
  // Binary search.\n
  // Performance analysis: http://neil.fraser.name/news/2007/10/09/\n
  var pointermin = 0;\n
  var pointermax = Math.min(text1.length, text2.length);\n
  var pointermid = pointermax;\n
  var pointerstart = 0;\n
  while (pointermin < pointermid) {\n
    if (text1.substring(pointerstart, pointermid) ==\n
        text2.substring(pointerstart, pointermid)) {\n
      pointermin = pointermid;\n
      pointerstart = pointermin;\n
    } else {\n
      pointermax = pointermid;\n
    }\n
    pointermid = Math.floor((pointermax - pointermin) / 2 + pointermin);\n
  }\n
  return pointermid;\n
};\n
\n
\n
/**\n
 * Determine the common suffix of two strings.\n
 * @param {string} text1 First string.\n
 * @param {string} text2 Second string.\n
 * @return {number} The number of characters common to the end of each string.\n
 */\n
diff_match_patch.prototype.diff_commonSuffix = function(text1, text2) {\n
  // Quick check for common null cases.\n
  if (!text1 || !text2 ||\n
      text1.charAt(text1.length - 1) != text2.charAt(text2.length - 1)) {\n
    return 0;\n
  }\n
  // Binary search.\n
  // Performance analysis: http://neil.fraser.name/news/2007/10/09/\n
  var pointermin = 0;\n
  var pointermax = Math.min(text1.length, text2.length);\n
  var pointermid = pointermax;\n
  var pointerend = 0;\n
  while (pointermin < pointermid) {\n
    if (text1.substring(text1.length - pointermid, text1.length - pointerend) ==\n
        text2.substring(text2.length - pointermid, text2.length - pointerend)) {\n
      pointermin = pointermid;\n
      pointerend = pointermin;\n
    } else {\n
      pointermax = pointermid;\n
    }\n
    pointermid = Math.floor((pointermax - pointermin) / 2 + pointermin);\n
  }\n
  return pointermid;\n
};\n
\n
\n
/**\n
 * Determine if the suffix of one string is the prefix of another.\n
 * @param {string} text1 First string.\n
 * @param {string} text2 Second string.\n
 * @return {number} The number of characters common to the end of the first\n
 *     string and the start of the second string.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_commonOverlap_ = function(text1, text2) {\n
  // Cache the text lengths to prevent multiple calls.\n
  var text1_length = text1.length;\n
  var text2_length = text2.length;\n
  // Eliminate the null case.\n
  if (text1_length == 0 || text2_length == 0) {\n
    return 0;\n
  }\n
  // Truncate the longer string.\n
  if (text1_length > text2_length) {\n
    text1 = text1.substring(text1_length - text2_length);\n
  } else if (text1_length < text2_length) {\n
    text2 = text2.substring(0, text1_length);\n
  }\n
  var text_length = Math.min(text1_length, text2_length);\n
  // Quick check for the worst case.\n
  if (text1 == text2) {\n
    return text_length;\n
  }\n
\n
  // Start by looking for a single character match\n
  // and increase length until no match is found.\n
  // Performance analysis: http://neil.fraser.name/news/2010/11/04/\n
  var best = 0;\n
  var length = 1;\n
  while (true) {\n
    var pattern = text1.substring(text_length - length);\n
    var found = text2.indexOf(pattern);\n
    if (found == -1) {\n
      return best;\n
    }\n
    length += found;\n
    if (found == 0 || text1.substring(text_length - length) ==\n
        text2.substring(0, length)) {\n
      best = length;\n
      length++;\n
    }\n
  }\n
};\n
\n
\n
/**\n
 * Do the two texts share a substring which is at least half the length of the\n
 * longer text?\n
 * This speedup can produce non-minimal diffs.\n
 * @param {string} text1 First string.\n
 * @param {string} text2 Second string.\n
 * @return {Array.<string>} Five element Array, containing the prefix of\n
 *     text1, the suffix of text1, the prefix of text2, the suffix of\n
 *     text2 and the common middle.  Or null if there was no match.\n
 * @private\n
 */\n
diff_match_patch.prototype.diff_halfMatch_ = function(text1, text2) {\n
  if (this.Diff_Timeout <= 0) {\n
    // Don\'t risk returning a non-optimal diff if we have unlimited time.\n
    return null;\n
  }\n
  var longtext = text1.length > text2.length ? text1 : text2;\n
  var shorttext = text1.length > text2.length ? text2 : text1;\n
  if (longtext.length < 4 || shorttext.length * 2 < longtext.length) {\n
    return null;  // Pointless.\n
  }\n
  var dmp = this;  // \'this\' becomes \'window\' in a closure.\n
\n
  /**\n
   * Does a substring of shorttext exist within longtext such that the substring\n
   * is at least half the length of longtext?\n
   * Closure, but does not reference any external variables.\n
   * @param {string} longtext Longer string.\n
   * @param {string} shorttext Shorter string.\n
   * @param {number} i Start index of quarter length substring within longtext.\n
   * @return {Array.<string>} Five element Array, containing the prefix of\n
   *     longtext, the suffix of longtext, the prefix of shorttext, the suffix\n
   *     of shorttext and the common middle.  Or null if there was no match.\n
   * @private\n
   */\n
  function diff_halfMatchI_(longtext, shorttext, i) {\n
    // Start with a 1/4 length substring at position i as a seed.\n
    var seed = longtext.substring(i, i + Math.floor(longtext.length / 4));\n
    var j = -1;\n
    var best_common = \'\';\n
    var best_longtext_a, best_longtext_b, best_shorttext_a, best_shorttext_b;\n
    while ((j = shorttext.indexOf(seed, j + 1)) != -1) {\n
      var prefixLength = dmp.diff_commonPrefix(longtext.substring(i),\n
                                               shorttext.substring(j));\n
      var suffixLength = dmp.diff_commonSuffix(longtext.substring(0, i),\n
                                               shorttext.substring(0, j));\n
      if (best_common.length < suffixLength + prefixLength) {\n
        best_common = shorttext.substring(j - suffixLength, j) +\n
            shorttext.substring(j, j + prefixLength);\n
        best_longtext_a = longtext.substring(0, i - suffixLength);\n
        best_longtext_b = longtext.substring(i + prefixLength);\n
        best_shorttext_a = shorttext.substring(0, j - suffixLength);\n
        best_shorttext_b = shorttext.substring(j + prefixLength);\n
      }\n
    }\n
    if (best_common.length * 2 >= longtext.length) {\n
      return [best_longtext_a, best_longtext_b,\n
              best_shorttext_a, best_shorttext_b, best_common];\n
    } else {\n
      return null;\n
    }\n
  }\n
\n
  // First check if the second quarter is the seed for a half-match.\n
  var hm1 = diff_halfMatchI_(longtext, shorttext,\n
                             Math.ceil(longtext.length / 4));\n
  // Check again based on the third quarter.\n
  var hm2 = diff_halfMatchI_(longtext, shorttext,\n
                             Math.ceil(longtext.length / 2));\n
  var hm;\n
  if (!hm1 && !hm2) {\n
    return null;\n
  } else if (!hm2) {\n
    hm = hm1;\n
  } else if (!hm1) {\n
    hm = hm2;\n
  } else {\n
    // Both matched.  Select the longest.\n
    hm = hm1[4].length > hm2[4].length ? hm1 : hm2;\n
  }\n
\n
  // A half-match was found, sort out the return data.\n
  var text1_a, text1_b, text2_a, text2_b;\n
  if (text1.length > text2.length) {\n
    text1_a = hm[0];\n
    text1_b = hm[1];\n
    text2_a = hm[2];\n
    text2_b = hm[3];\n
  } else {\n
    text2_a = hm[0];\n
    text2_b = hm[1];\n
    text1_a = hm[2];\n
    text1_b = hm[3];\n
  }\n
  var mid_common = hm[4];\n
  return [text1_a, text1_b, text2_a, text2_b, mid_common];\n
};\n
\n
\n
/**\n
 * Reduce the number of edits by eliminating semantically trivial equalities.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 */\n
diff_match_patch.prototype.diff_cleanupSemantic = function(diffs) {\n
  var changes = false;\n
  var equalities = [];  // Stack of indices where equalities are found.\n
  var equalitiesLength = 0;  // Keeping our own length var is faster in JS.\n
  /** @type {?string} */\n
  var lastequality = null;\n
  // Always equal to diffs[equalities[equalitiesLength - 1]][1]\n
  var pointer = 0;  // Index of current position.\n
  // Number of characters that changed prior to the equality.\n
  var length_insertions1 = 0;\n
  var length_deletions1 = 0;\n
  // Number of characters that changed after the equality.\n
  var length_insertions2 = 0;\n
  var length_deletions2 = 0;\n
  while (pointer < diffs.length) {\n
    if (diffs[pointer][0] == DIFF_EQUAL) {  // Equality found.\n
      equalities[equalitiesLength++] = pointer;\n
      length_insertions1 = length_insertions2;\n
      length_deletions1 = length_deletions2;\n
      length_insertions2 = 0;\n
      length_deletions2 = 0;\n
      lastequality = diffs[pointer][1];\n
    } else {  // An insertion or deletion.\n
      if (diffs[pointer][0] == DIFF_INSERT) {\n
        length_insertions2 += diffs[pointer][1].length;\n
      } else {\n
        length_deletions2 += diffs[pointer][1].length;\n
      }\n
      // Eliminate an equality that is smaller or equal to the edits on both\n
      // sides of it.\n
      if (lastequality && (lastequality.length <=\n
          Math.max(length_insertions1, length_deletions1)) &&\n
          (lastequality.length <= Math.max(length_insertions2,\n
                                           length_deletions2))) {\n
        // Duplicate record.\n
        diffs.splice(equalities[equalitiesLength - 1], 0,\n
                     [DIFF_DELETE, lastequality]);\n
        // Change second copy to insert.\n
        diffs[equalities[equalitiesLength - 1] + 1][0] = DIFF_INSERT;\n
        // Throw away the equality we just deleted.\n
        equalitiesLength--;\n
        // Throw away the previous equality (it needs to be reevaluated).\n
        equalitiesLength--;\n
        pointer = equalitiesLength > 0 ? equalities[equalitiesLength - 1] : -1;\n
        length_insertions1 = 0;  // Reset the counters.\n
        length_deletions1 = 0;\n
        length_insertions2 = 0;\n
        length_deletions2 = 0;\n
        lastequality = null;\n
        changes = true;\n
      }\n
    }\n
    pointer++;\n
  }\n
\n
  // Normalize the diff.\n
  if (changes) {\n
    this.diff_cleanupMerge(diffs);\n
  }\n
  this.diff_cleanupSemanticLossless(diffs);\n
\n
  // Find any overlaps between deletions and insertions.\n
  // e.g: <del>abcxxx</del><ins>xxxdef</ins>\n
  //   -> <del>abc</del>xxx<ins>def</ins>\n
  // e.g: <del>xxxabc</del><ins>defxxx</ins>\n
  //   -> <ins>def</ins>xxx<del>abc</del>\n
  // Only extract an overlap if it is as big as the edit ahead or behind it.\n
  pointer = 1;\n
  while (pointer < diffs.length) {\n
    if (diffs[pointer - 1][0] == DIFF_DELETE &&\n
        diffs[pointer][0] == DIFF_INSERT) {\n
      var deletion = diffs[pointer - 1][1];\n
      var insertion = diffs[pointer][1];\n
      var overlap_length1 = this.diff_commonOverlap_(deletion, insertion);\n
      var overlap_length2 = this.diff_commonOverlap_(insertion, deletion);\n
      if (overlap_length1 >= overlap_length2) {\n
        if (overlap_length1 >= deletion.length / 2 ||\n
            overlap_length1 >= insertion.length / 2) {\n
          // Overlap found.  Insert an equality and trim the surrounding edits.\n
          diffs.splice(pointer, 0,\n
              [DIFF_EQUAL, insertion.substring(0, overlap_length1)]);\n
          diffs[pointer - 1][1] =\n
              deletion.substring(0, deletion.length - overlap_length1);\n
          diffs[pointer + 1][1] = insertion.substring(overlap_length1);\n
          pointer++;\n
        }\n
      } else {\n
        if (overlap_length2 >= deletion.length / 2 ||\n
            overlap_length2 >= insertion.length / 2) {\n
          // Reverse overlap found.\n
          // Insert an equality and swap and trim the surrounding edits.\n
          diffs.splice(pointer, 0,\n
              [DIFF_EQUAL, deletion.substring(0, overlap_length2)]);\n
          diffs[pointer - 1][0] = DIFF_INSERT;\n
          diffs[pointer - 1][1] =\n
              insertion.substring(0, insertion.length - overlap_length2);\n
          diffs[pointer + 1][0] = DIFF_DELETE;\n
          diffs[pointer + 1][1] =\n
              deletion.substring(overlap_length2);\n
          pointer++;\n
        }\n
      }\n
      pointer++;\n
    }\n
    pointer++;\n
  }\n
};\n
\n
\n
/**\n
 * Look for single edits surrounded on both sides by equalities\n
 * which can be shifted sideways to align the edit to a word boundary.\n
 * e.g: The c<ins>at c</ins>ame. -> The <ins>cat </ins>came.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 */\n
diff_match_patch.prototype.diff_cleanupSemanticLossless = function(diffs) {\n
  /**\n
   * Given two strings, compute a score representing whether the internal\n
   * boundary falls on logical boundaries.\n
   * Scores range from 6 (best) to 0 (worst).\n
   * Closure, but does not reference any external variables.\n
   * @param {string} one First string.\n
   * @param {string} two Second string.\n
   * @return {number} The score.\n
   * @private\n
   */\n
  function diff_cleanupSemanticScore_(one, two) {\n
    if (!one || !two) {\n
      // Edges are the best.\n
      return 6;\n
    }\n
\n
    // Each port of this function behaves slightly differently due to\n
    // subtle differences in each language\'s definition of things like\n
    // \'whitespace\'.  Since this function\'s purpose is largely cosmetic,\n
    // the choice has been made to use each language\'s native features\n
    // rather than force total conformity.\n
    var char1 = one.charAt(one.length - 1);\n
    var char2 = two.charAt(0);\n
    var nonAlphaNumeric1 = char1.match(diff_match_patch.nonAlphaNumericRegex_);\n
    var nonAlphaNumeric2 = char2.match(diff_match_patch.nonAlphaNumericRegex_);\n
    var whitespace1 = nonAlphaNumeric1 &&\n
        char1.match(diff_match_patch.whitespaceRegex_);\n
    var whitespace2 = nonAlphaNumeric2 &&\n
        char2.match(diff_match_patch.whitespaceRegex_);\n
    var lineBreak1 = whitespace1 &&\n
        char1.match(diff_match_patch.linebreakRegex_);\n
    var lineBreak2 = whitespace2 &&\n
        char2.match(diff_match_patch.linebreakRegex_);\n
    var blankLine1 = lineBreak1 &&\n
        one.match(diff_match_patch.blanklineEndRegex_);\n
    var blankLine2 = lineBreak2 &&\n
        two.match(diff_match_patch.blanklineStartRegex_);\n
\n
    if (blankLine1 || blankLine2) {\n
      // Five points for blank lines.\n
      return 5;\n
    } else if (lineBreak1 || lineBreak2) {\n
      // Four points for line breaks.\n
      return 4;\n
    } else if (nonAlphaNumeric1 && !whitespace1 && whitespace2) {\n
      // Three points for end of sentences.\n
      return 3;\n
    } else if (whitespace1 || whitespace2) {\n
      // Two points for whitespace.\n
      return 2;\n
    } else if (nonAlphaNumeric1 || nonAlphaNumeric2) {\n
      // One point for non-alphanumeric.\n
      return 1;\n
    }\n
    return 0;\n
  }\n
\n
  var pointer = 1;\n
  // Intentionally ignore the first and last element (don\'t need checking).\n
  while (pointer < diffs.length - 1) {\n
    if (diffs[pointer - 1][0] == DIFF_EQUAL &&\n
        diffs[pointer + 1][0] == DIFF_EQUAL) {\n
      // This is a single edit surrounded by equalities.\n
      var equality1 = diffs[pointer - 1][1];\n
      var edit = diffs[pointer][1];\n
      var equality2 = diffs[pointer + 1][1];\n
\n
      // First, shift the edit as far left as possible.\n
      var commonOffset = this.diff_commonSuffix(equality1, edit);\n
      if (commonOffset) {\n
        var commonString = edit.substring(edit.length - commonOffset);\n
        equality1 = equality1.substring(0, equality1.length - commonOffset);\n
        edit = commonString + edit.substring(0, edit.length - commonOffset);\n
        equality2 = commonString + equality2;\n
      }\n
\n
      // Second, step character by character right, looking for the best fit.\n
      var bestEquality1 = equality1;\n
      var bestEdit = edit;\n
      var bestEquality2 = equality2;\n
      var bestScore = diff_cleanupSemanticScore_(equality1, edit) +\n
          diff_cleanupSemanticScore_(edit, equality2);\n
      while (edit.charAt(0) === equality2.charAt(0)) {\n
        equality1 += edit.charAt(0);\n
        edit = edit.substring(1) + equality2.charAt(0);\n
        equality2 = equality2.substring(1);\n
        var score = diff_cleanupSemanticScore_(equality1, edit) +\n
            diff_cleanupSemanticScore_(edit, equality2);\n
        // The >= encourages trailing rather than leading whitespace on edits.\n
        if (score >= bestScore) {\n
          bestScore = score;\n
          bestEquality1 = equality1;\n
          bestEdit = edit;\n
          bestEquality2 = equality2;\n
        }\n
      }\n
\n
      if (diffs[pointer - 1][1] != bestEquality1) {\n
        // We have an improvement, save it back to the diff.\n
        if (bestEquality1) {\n
          diffs[pointer - 1][1] = bestEquality1;\n
        } else {\n
          diffs.splice(pointer - 1, 1);\n
          pointer--;\n
        }\n
        diffs[pointer][1] = bestEdit;\n
        if (bestEquality2) {\n
          diffs[pointer + 1][1] = bestEquality2;\n
        } else {\n
          diffs.splice(pointer + 1, 1);\n
          pointer--;\n
        }\n
      }\n
    }\n
    pointer++;\n
  }\n
};\n
\n
// Define some regex patterns for matching boundaries.\n
diff_match_patch.nonAlphaNumericRegex_ = /[^a-zA-Z0-9]/;\n
diff_match_patch.whitespaceRegex_ = /\\s/;\n
diff_match_patch.linebreakRegex_ = /[\\r\\n]/;\n
diff_match_patch.blanklineEndRegex_ = /\\n\\r?\\n$/;\n
diff_match_patch.blanklineStartRegex_ = /^\\r?\\n\\r?\\n/;\n
\n
/**\n
 * Reduce the number of edits by eliminating operationally trivial equalities.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 */\n
diff_match_patch.prototype.diff_cleanupEfficiency = function(diffs) {\n
  var changes = false;\n
  var equalities = [];  // Stack of indices where equalities are found.\n
  var equalitiesLength = 0;  // Keeping our own length var is faster in JS.\n
  /** @type {?string} */\n
  var lastequality = null;\n
  // Always equal to diffs[equalities[equalitiesLength - 1]][1]\n
  var pointer = 0;  // Index of current position.\n
  // Is there an insertion operation before the last equality.\n
  var pre_ins = false;\n
  // Is there a deletion operation before the last equality.\n
  var pre_del = false;\n
  // Is there an insertion operation after the last equality.\n
  var post_ins = false;\n
  // Is there a deletion operation after the last equality.\n
  var post_del = false;\n
  while (pointer < diffs.length) {\n
    if (diffs[pointer][0] == DIFF_EQUAL) {  // Equality found.\n
      if (diffs[pointer][1].length < this.Diff_EditCost &&\n
          (post_ins || post_del)) {\n
        // Candidate found.\n
        equalities[equalitiesLength++] = pointer;\n
        pre_ins = post_ins;\n
        pre_del = post_del;\n
        lastequality = diffs[pointer][1];\n
      } else {\n
        // Not a candidate, and can never become one.\n
        equalitiesLength = 0;\n
        lastequality = null;\n
      }\n
      post_ins = post_del = false;\n
    } else {  // An insertion or deletion.\n
      if (diffs[pointer][0] == DIFF_DELETE) {\n
        post_del = true;\n
      } else {\n
        post_ins = true;\n
      }\n
      /*\n
       * Five types to be split:\n
       * <ins>A</ins><del>B</del>XY<ins>C</ins><del>D</del>\n
       * <ins>A</ins>X<ins>C</ins><del>D</del>\n
       * <ins>A</ins><del>B</del>X<ins>C</ins>\n
       * <ins>A</del>X<ins>C</ins><del>D</del>\n
       * <ins>A</ins><del>B</del>X<del>C</del>\n
       */\n
      if (lastequality && ((pre_ins && pre_del && post_ins && post_del) ||\n
                           ((lastequality.length < this.Diff_EditCost / 2) &&\n
                            (pre_ins + pre_del + post_ins + post_del) == 3))) {\n
        // Duplicate record.\n
        diffs.splice(equalities[equalitiesLength - 1], 0,\n
                     [DIFF_DELETE, lastequality]);\n
        // Change second copy to insert.\n
        diffs[equalities[equalitiesLength - 1] + 1][0] = DIFF_INSERT;\n
        equalitiesLength--;  // Throw away the equality we just deleted;\n
        lastequality = null;\n
        if (pre_ins && pre_del) {\n
          // No changes made which could affect previous entry, keep going.\n
          post_ins = post_del = true;\n
          equalitiesLength = 0;\n
        } else {\n
          equalitiesLength--;  // Throw away the previous equality.\n
          pointer = equalitiesLength > 0 ?\n
              equalities[equalitiesLength - 1] : -1;\n
          post_ins = post_del = false;\n
        }\n
        changes = true;\n
      }\n
    }\n
    pointer++;\n
  }\n
\n
  if (changes) {\n
    this.diff_cleanupMerge(diffs);\n
  }\n
};\n
\n
\n
/**\n
 * Reorder and merge like edit sections.  Merge equalities.\n
 * Any edit section can move as long as it doesn\'t cross an equality.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 */\n
diff_match_patch.prototype.diff_cleanupMerge = function(diffs) {\n
  diffs.push([DIFF_EQUAL, \'\']);  // Add a dummy entry at the end.\n
  var pointer = 0;\n
  var count_delete = 0;\n
  var count_insert = 0;\n
  var text_delete = \'\';\n
  var text_insert = \'\';\n
  var commonlength;\n
  while (pointer < diffs.length) {\n
    switch (diffs[pointer][0]) {\n
      case DIFF_INSERT:\n
        count_insert++;\n
        text_insert += diffs[pointer][1];\n
        pointer++;\n
        break;\n
      case DIFF_DELETE:\n
        count_delete++;\n
        text_delete += diffs[pointer][1];\n
        pointer++;\n
        break;\n
      case DIFF_EQUAL:\n
        // Upon reaching an equality, check for prior redundancies.\n
        if (count_delete + count_insert > 1) {\n
          if (count_delete !== 0 && count_insert !== 0) {\n
            // Factor out any common prefixies.\n
            commonlength = this.diff_commonPrefix(text_insert, text_delete);\n
            if (commonlength !== 0) {\n
              if ((pointer - count_delete - count_insert) > 0 &&\n
                  diffs[pointer - count_delete - count_insert - 1][0] ==\n
                  DIFF_EQUAL) {\n
                diffs[pointer - count_delete - count_insert - 1][1] +=\n
                    text_insert.substring(0, commonlength);\n
              } else {\n
                diffs.splice(0, 0, [DIFF_EQUAL,\n
                                    text_insert.substring(0, commonlength)]);\n
                pointer++;\n
              }\n
              text_insert = text_insert.substring(commonlength);\n
              text_delete = text_delete.substring(commonlength);\n
            }\n
            // Factor out any common suffixies.\n
            commonlength = this.diff_commonSuffix(text_insert, text_delete);\n
            if (commonlength !== 0) {\n
              diffs[pointer][1] = text_insert.substring(text_insert.length -\n
                  commonlength) + diffs[pointer][1];\n
              text_insert = text_insert.substring(0, text_insert.length -\n
                  commonlength);\n
              text_delete = text_delete.substring(0, text_delete.length -\n
                  commonlength);\n
            }\n
          }\n
          // Delete the offending records and add the merged ones.\n
          if (count_delete === 0) {\n
            diffs.splice(pointer - count_insert,\n
                count_delete + count_insert, [DIFF_INSERT, text_insert]);\n
          } else if (count_insert === 0) {\n
            diffs.splice(pointer - count_delete,\n
                count_delete + count_insert, [DIFF_DELETE, text_delete]);\n
          } else {\n
            diffs.splice(pointer - count_delete - count_insert,\n
                count_delete + count_insert, [DIFF_DELETE, text_delete],\n
                [DIFF_INSERT, text_insert]);\n
          }\n
          pointer = pointer - count_delete - count_insert +\n
                    (count_delete ? 1 : 0) + (count_insert ? 1 : 0) + 1;\n
        } else if (pointer !== 0 && diffs[pointer - 1][0] == DIFF_EQUAL) {\n
          // Merge this equality with the previous one.\n
          diffs[pointer - 1][1] += diffs[pointer][1];\n
          diffs.splice(pointer, 1);\n
        } else {\n
          pointer++;\n
        }\n
        count_insert = 0;\n
        count_delete = 0;\n
        text_delete = \'\';\n
        text_insert = \'\';\n
        break;\n
    }\n
  }\n
  if (diffs[diffs.length - 1][1] === \'\') {\n
    diffs.pop();  // Remove the dummy entry at the end.\n
  }\n
\n
  // Second pass: look for single edits surrounded on both sides by equalities\n
  // which can be shifted sideways to eliminate an equality.\n
  // e.g: A<ins>BA</ins>C -> <ins>AB</ins>AC\n
  var changes = false;\n
  pointer = 1;\n
  // Intentionally ignore the first and last element (don\'t need checking).\n
  while (pointer < diffs.length - 1) {\n
    if (diffs[pointer - 1][0] == DIFF_EQUAL &&\n
        diffs[pointer + 1][0] == DIFF_EQUAL) {\n
      // This is a single edit surrounded by equalities.\n
      if (diffs[pointer][1].substring(diffs[pointer][1].length -\n
          diffs[pointer - 1][1].length) == diffs[pointer - 1][1]) {\n
        // Shift the edit over the previous equality.\n
        diffs[pointer][1] = diffs[pointer - 1][1] +\n
            diffs[pointer][1].substring(0, diffs[pointer][1].length -\n
                                        diffs[pointer - 1][1].length);\n
        diffs[pointer + 1][1] = diffs[pointer - 1][1] + diffs[pointer + 1][1];\n
        diffs.splice(pointer - 1, 1);\n
        changes = true;\n
      } else if (diffs[pointer][1].substring(0, diffs[pointer + 1][1].length) ==\n
          diffs[pointer + 1][1]) {\n
        // Shift the edit over the next equality.\n
        diffs[pointer - 1][1] += diffs[pointer + 1][1];\n
        diffs[pointer][1] =\n
            diffs[pointer][1].substring(diffs[pointer + 1][1].length) +\n
            diffs[pointer + 1][1];\n
        diffs.splice(pointer + 1, 1);\n
        changes = true;\n
      }\n
    }\n
    pointer++;\n
  }\n
  // If shifts were made, the diff needs reordering and another shift sweep.\n
  if (changes) {\n
    this.diff_cleanupMerge(diffs);\n
  }\n
};\n
\n
\n
/**\n
 * loc is a location in text1, compute and return the equivalent location in\n
 * text2.\n
 * e.g. \'The cat\' vs \'The big cat\', 1->1, 5->8\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @param {number} loc Location within text1.\n
 * @return {number} Location within text2.\n
 */\n
diff_match_patch.prototype.diff_xIndex = function(diffs, loc) {\n
  var chars1 = 0;\n
  var chars2 = 0;\n
  var last_chars1 = 0;\n
  var last_chars2 = 0;\n
  var x;\n
  for (x = 0; x < diffs.length; x++) {\n
    if (diffs[x][0] !== DIFF_INSERT) {  // Equality or deletion.\n
      chars1 += diffs[x][1].length;\n
    }\n
    if (diffs[x][0] !== DIFF_DELETE) {  // Equality or insertion.\n
      chars2 += diffs[x][1].length;\n
    }\n
    if (chars1 > loc) {  // Overshot the location.\n
      break;\n
    }\n
    last_chars1 = chars1;\n
    last_chars2 = chars2;\n
  }\n
  // Was the location was deleted?\n
  if (diffs.length != x && diffs[x][0] === DIFF_DELETE) {\n
    return last_chars2;\n
  }\n
  // Add the remaining character length.\n
  return last_chars2 + (loc - last_chars1);\n
};\n
\n
\n
/**\n
 * Convert a diff array into a pretty HTML report.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @return {string} HTML representation.\n
 */\n
diff_match_patch.prototype.diff_prettyHtml = function(diffs) {\n
  var html = [];\n
  var pattern_amp = /&/g;\n
  var pattern_lt = /</g;\n
  var pattern_gt = />/g;\n
  var pattern_para = /\\n/g;\n
  for (var x = 0; x < diffs.length; x++) {\n
    var op = diffs[x][0];    // Operation (insert, delete, equal)\n
    var data = diffs[x][1];  // Text of change.\n
    var text = data.replace(pattern_amp, \'&amp;\').replace(pattern_lt, \'&lt;\')\n
        .replace(pattern_gt, \'&gt;\').replace(pattern_para, \'&para;<br>\');\n
    switch (op) {\n
      case DIFF_INSERT:\n
        html[x] = \'<ins style="background:#e6ffe6;">\' + text + \'</ins>\';\n
        break;\n
      case DIFF_DELETE:\n
        html[x] = \'<del style="background:#ffe6e6;">\' + text + \'</del>\';\n
        break;\n
      case DIFF_EQUAL:\n
        html[x] = \'<span>\' + text + \'</span>\';\n
        break;\n
    }\n
  }\n
  return html.join(\'\');\n
};\n
\n
\n
/**\n
 * Compute and return the source text (all equalities and deletions).\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @return {string} Source text.\n
 */\n
diff_match_patch.prototype.diff_text1 = function(diffs) {\n
  var text = [];\n
  for (var x = 0; x < diffs.length; x++) {\n
    if (diffs[x][0] !== DIFF_INSERT) {\n
      text[x] = diffs[x][1];\n
    }\n
  }\n
  return text.join(\'\');\n
};\n
\n
\n
/**\n
 * Compute and return the destination text (all equalities and insertions).\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @return {string} Destination text.\n
 */\n
diff_match_patch.prototype.diff_text2 = function(diffs) {\n
  var text = [];\n
  for (var x = 0; x < diffs.length; x++) {\n
    if (diffs[x][0] !== DIFF_DELETE) {\n
      text[x] = diffs[x][1];\n
    }\n
  }\n
  return text.join(\'\');\n
};\n
\n
\n
/**\n
 * Compute the Levenshtein distance; the number of inserted, deleted or\n
 * substituted characters.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @return {number} Number of changes.\n
 */\n
diff_match_patch.prototype.diff_levenshtein = function(diffs) {\n
  var levenshtein = 0;\n
  var insertions = 0;\n
  var deletions = 0;\n
  for (var x = 0; x < diffs.length; x++) {\n
    var op = diffs[x][0];\n
    var data = diffs[x][1];\n
    switch (op) {\n
      case DIFF_INSERT:\n
        insertions += data.length;\n
        break;\n
      case DIFF_DELETE:\n
        deletions += data.length;\n
        break;\n
      case DIFF_EQUAL:\n
        // A deletion and an insertion is one substitution.\n
        levenshtein += Math.max(insertions, deletions);\n
        insertions = 0;\n
        deletions = 0;\n
        break;\n
    }\n
  }\n
  levenshtein += Math.max(insertions, deletions);\n
  return levenshtein;\n
};\n
\n
\n
/**\n
 * Crush the diff into an encoded string which describes the operations\n
 * required to transform text1 into text2.\n
 * E.g. =3\\t-2\\t+ing  -> Keep 3 chars, delete 2 chars, insert \'ing\'.\n
 * Operations are tab-separated.  Inserted text is escaped using %xx notation.\n
 * @param {!Array.<!diff_match_patch.Diff>} diffs Array of diff tuples.\n
 * @return {string} Delta text.\n
 */\n
diff_match_patch.prototype.diff_toDelta = function(diffs) {\n
  var text = [];\n
  for (var x = 0; x < diffs.length; x++) {\n
    switch (diffs[x][0]) {\n
      case DIFF_INSERT:\n
        text[x] = \'+\' + encodeURI(diffs[x][1]);\n
        break;\n
      case DIFF_DELETE:\n
        text[x] = \'-\' + diffs[x][1].length;\n
        break;\n
      case DIFF_EQUAL:\n
        text[x] = \'=\' + diffs[x][1].length;\n
        break;\n
    }\n
  }\n
  return text.join(\'\\t\').replace(/%20/g, \' \');\n
};\n
\n
\n
/**\n
 * Given the original text1, and an encoded string which describes the\n
 * operations required to transform text1 into text2, compute the full diff.\n
 * @param {string} text1 Source string for the diff.\n
 * @param {string} delta Delta text.\n
 * @return {!Array.<!diff_match_patch.Diff>} Array of diff tuples.\n
 * @throws {!Error} If invalid input.\n
 */\n
diff_match_patch.prototype.diff_fromDelta = function(text1, delta) {\n
  var diffs = [];\n
  var diffsLength = 0;  // Keeping our own length var is faster in JS.\n
  var pointer = 0;  // Cursor in text1\n
  var tokens = delta.split(/\\t/g);\n
  for (var x = 0; x < tokens.length; x++) {\n
    // Each token begins with a one character parameter which specifies the\n
    // operation of this token (delete, insert, equality).\n
    var param = tokens[x].substring(1);\n
    switch (tokens[x].charAt(0)) {\n
      case \'+\':\n
        try {\n
          diffs[diffsLength++] = [DIFF_INSERT, decodeURI(param)];\n
        } catch (ex) {\n
          // Malformed URI sequence.\n
          throw new Error(\'Illegal escape in diff_fromDelta: \' + param);\n
        }\n
        break;\n
      case \'-\':\n
        // Fall through.\n
      case \'=\':\n
        var n = parseInt(param, 10);\n
        if (isNaN(n) || n < 0) {\n
          throw new Error(\'Invalid number in diff_fromDelta: \' + param);\n
        }\n
        var text = text1.substring(pointer, pointer += n);\n
        if (tokens[x].charAt(0) == \'=\') {\n
          diffs[diffsLength++] = [DIFF_EQUAL, text];\n
        } else {\n
          diffs[diffsLength++] = [DIFF_DELETE, text];\n
        }\n
        break;\n
      default:\n
        // Blank tokens are ok (from a trailing \\t).\n
        // Anything else is an error.\n
        if (tokens[x]) {\n
          throw new Error(\'Invalid diff operation in diff_fromDelta: \' +\n
                          tokens[x]);\n
        }\n
    }\n
  }\n
  if (pointer != text1.length) {\n
    throw new Error(\'Delta length (\' + pointer +\n
        \') does not equal source text length (\' + text1.length + \').\');\n
  }\n
  return diffs;\n
};\n
\n
\n
//  MATCH FUNCTIONS\n
\n
\n
/**\n
 * Locate the best instance of \'pattern\' in \'text\' near \'loc\'.\n
 * @param {string} text The text to search.\n
 * @param {string} pattern The pattern to search for.\n
 * @param {number} loc The location to search around.\n
 * @return {number} Best match index or -1.\n
 */\n
diff_match_patch.prototype.match_main = function(text, pattern, loc) {\n
  // Check for null inputs.\n
  if (text == null || pattern == null || loc == null) {\n
    throw new Error(\'Null input. (match_main)\');\n
  }\n
\n
  loc = Math.max(0, Math.min(loc, text.length));\n
  if (text == pattern) {\n
    // Shortcut (potentially not guaranteed by the algorithm)\n
    return 0;\n
  } else if (!text.length) {\n
    // Nothing to match.\n
    return -1;\n
  } else if (text.substring(loc, loc + pattern.length) == pattern) {\n
    // Perfect match at the perfect spot!  (Includes case of null pattern)\n
    return loc;\n
  } else {\n
    // Do a fuzzy compare.\n
    return this.match_bitap_(text, pattern, loc);\n
  }\n
};\n
\n
\n
/**\n
 * Locate the best instance of \'pattern\' in \'text\' near \'loc\' using the\n
 * Bitap algorithm.\n
 * @param {string} text The text to search.\n
 * @param {string} pattern The pattern to search for.\n
 * @param {number} loc The location to search around.\n
 * @return {number} Best match index or -1.\n
 * @private\n
 */\n
diff_match_patch.prototype.match_bitap_ = function(text, pattern, loc) {\n
  if (pattern.length > this.Match_MaxBits) {\n
    throw new Error(\'Pattern too long for this browser.\');\n
  }\n
\n
  // Initialise the alphabet.\n
  var s = this.match_alphabet_(pattern);\n
\n
  var dmp = this;  // \'this\' becomes \'window\' in a closure.\n
\n
  /**\n
   * Compute and return the score for a match with e errors and x location.\n
   * Accesses loc and pattern through being a closure.\n
   * @param {number} e Number of errors in match.\n
   * @param {number} x Location of match.\n
   * @return {number} Overall score for match (0.0 = good, 1.0 = bad).\n
   * @private\n
   */\n
  function match_bitapScore_(e, x) {\n
    var accuracy = e / pattern.length;\n
    var proximity = Math.abs(loc - x);\n
    if (!dmp.Match_Distance) {\n
      // Dodge divide by zero error.\n
      return proximity ? 1.0 : accuracy;\n
    }\n
    return accuracy + (proximity / dmp.Match_Distance);\n
  }\n
\n
  // Highest score beyond which we give up.\n
  var score_threshold = this.Match_Threshold;\n
  // Is there a nearby exact match? (speedup)\n
  var best_loc = text.indexOf(pattern, loc);\n
  if (best_loc != -1) {\n
    score_threshold = Math.min(match_bitapScore_(0, best_loc), score_threshold);\n
    // What about in the other direction? (speedup)\n
    best_loc = text.lastIndexOf(pattern, loc + pattern.length);\n
    if (best_loc != -1) {\n
      score_threshold =\n
          Math.min(match_bitapScore_(0, best_loc), score_threshold);\n
    }\n
  }\n
\n
  // Initialise the bit arrays.\n
  var matchmask = 1 << (pattern.length - 1);\n
  best_loc = -1;\n
\n
  var bin_min, bin_mid;\n
  var bin_max = pattern.length + text.length;\n
  var last_rd;\n
  for (var d = 0; d < pattern.length; d++) {\n
    // Scan for the best match; each iteration allows for one more error.\n
    // Run a binary search to determine how far from \'loc\' we can stray at this\n
    // error level.\n
    bin_min = 0;\n
    bin_mid = bin_max;\n
    while (bin_min < bin_mid) {\n
      if (match_bitapScore_(d, loc + bin_mid) <= score_threshold) {\n
        bin_min = bin_mid;\n
      } else {\n
        bin_max = bin_mid;\n
      }\n
      bin_mid = Math.floor((bin_max - bin_min) / 2 + bin_min);\n
    }\n
    // Use the result from this iteration as the maximum for the next.\n
    bin_max = bin_mid;\n
    var start = Math.max(1, loc - bin_mid + 1);\n
    var finish = Math.min(loc + bin_mid, text.length) + pattern.length;\n
\n
    var rd = Array(finish + 2);\n
    rd[finish + 1] = (1 << d) - 1;\n
    for (var j = finish; j >= start; j--) {\n
      // The alphabet (s) is a sparse hash, so the following line generates\n
      // warnings.\n
      var charMatch = s[text.charAt(j - 1)];\n
      if (d === 0) {  // First pass: exact match.\n
        rd[j] = ((rd[j + 1] << 1) | 1) & charMatch;\n
      } else {  // Subsequent passes: fuzzy match.\n
        rd[j] = (((rd[j + 1] << 1) | 1) & charMatch) |\n
                (((last_rd[j + 1] | last_rd[j]) << 1) | 1) |\n
                last_rd[j + 1];\n
      }\n
      if (rd[j] & matchmask) {\n
        var score = match_bitapScore_(d, j - 1);\n
        // This match will almost certainly be better than any existing match.\n
        // But check anyway.\n
        if (score <= score_threshold) {\n
          // Told you so.\n
          score_threshold = score;\n
          best_loc = j - 1;\n
          if (best_loc > loc) {\n
            // When passing loc, don\'t exceed our current distance from loc.\n
            start = Math.max(1, 2 * loc - best_loc);\n
          } else {\n
            // Already passed loc, downhill from here on in.\n
            break;\n
          }\n
        }\n
      }\n
    }\n
    // No hope for a (better) match at greater error levels.\n
    if (match_bitapScore_(d + 1, loc) > score_threshold) {\n
      break;\n
    }\n
    last_rd = rd;\n
  }\n
  return best_loc;\n
};\n
\n
\n
/**\n
 * Initialise the alphabet for the Bitap algorithm.\n
 * @param {string} pattern The text to encode.\n
 * @return {!Object} Hash of character locations.\n
 * @private\n
 */\n
diff_match_patch.prototype.match_alphabet_ = function(pattern) {\n
  var s = {};\n
  for (var i = 0; i < pattern.length; i++) {\n
    s[pattern.charAt(i)] = 0;\n
  }\n
  for (var i = 0; i < pattern.length; i++) {\n
    s[pattern.charAt(i)] |= 1 << (pattern.length - i - 1);\n
  }\n
  return s;\n
};\n
\n
\n
//  PATCH FUNCTIONS\n
\n
\n
/**\n
 * Increase the context until it is unique,\n
 * but don\'t let the pattern expand beyond Match_MaxBits.\n
 * @param {!diff_match_patch.patch_obj} patch The patch to grow.\n
 * @param {string} text Source text.\n
 * @private\n
 */\n
diff_match_patch.prototype.patch_addContext_ = function(patch, text) {\n
  if (text.length == 0) {\n
    return;\n
  }\n
  var pattern = text.substring(patch.start2, patch.start2 + patch.length1);\n
  var padding = 0;\n
\n
  // Look for the first and last matches of pattern in text.  If two different\n
  // matches are found, increase the pattern length.\n
  while (text.indexOf(pattern) != text.lastIndexOf(pattern) &&\n
         pattern.length < this.Match_MaxBits - this.Patch_Margin -\n
         this.Patch_Margin) {\n
    padding += this.Patch_Margin;\n
    pattern = text.substring(patch.start2 - padding,\n
                             patch.start2 + patch.length1 + padding);\n
  }\n
  // Add one chunk for good luck.\n
  padding += this.Patch_Margin;\n
\n
  // Add the prefix.\n
  var prefix = text.substring(patch.start2 - padding, patch.start2);\n
  if (prefix) {\n
    patch.diffs.unshift([DIFF_EQUAL, prefix]);\n
  }\n
  // Add the suffix.\n
  var suffix = text.substring(patch.start2 + patch.length1,\n
                              patch.start2 + patch.length1 + padding);\n
  if (suffix) {\n
    patch.diffs.push([DIFF_EQUAL, suffix]);\n
  }\n
\n
  // Roll back the start points.\n
  patch.start1 -= prefix.length;\n
  patch.start2 -= prefix.length;\n
  // Extend the lengths.\n
  patch.length1 += prefix.length + suffix.length;\n
  patch.length2 += prefix.length + suffix.length;\n
};\n
\n
\n
/**\n
 * Compute a list of patches to turn text1 into text2.\n
 * Use diffs if provided, otherwise compute it ourselves.\n
 * There are four ways to call this function, depending on what data is\n
 * available to the caller:\n
 * Method 1:\n
 * a = text1, b = text2\n
 * Method 2:\n
 * a = diffs\n
 * Method 3 (optimal):\n
 * a = text1, b = diffs\n
 * Method 4 (deprecated, use method 3):\n
 * a = text1, b = text2, c = diffs\n
 *\n
 * @param {string|!Array.<!diff_match_patch.Diff>} a text1 (methods 1,3,4) or\n
 * Array of diff tuples for text1 to text2 (method 2).\n
 * @param {string|!Array.<!diff_match_patch.Diff>} opt_b text2 (methods 1,4) or\n
 * Array of diff tuples for text1 to text2 (method 3) or undefined (method 2).\n
 * @param {string|!Array.<!diff_match_patch.Diff>} opt_c Array of diff tuples\n
 * for text1 to text2 (method 4) or undefined (methods 1,2,3).\n
 * @return {!Array.<!diff_match_patch.patch_obj>} Array of Patch objects.\n
 */\n
diff_match_patch.prototype.patch_make = function(a, opt_b, opt_c) {\n
  var text1, diffs;\n
  if (typeof a == \'string\' && typeof opt_b == \'string\' &&\n
      typeof opt_c == \'undefined\') {\n
    // Method 1: text1, text2\n
    // Compute diffs from text1 and text2.\n
    text1 = /** @type {string} */(a);\n
    diffs = this.diff_main(text1, /** @type {string} */(opt_b), true);\n
    if (diffs.length > 2) {\n
      this.diff_cleanupSemantic(diffs);\n
      this.diff_cleanupEfficiency(diffs);\n
    }\n
  } else if (a && typeof a == \'object\' && typeof opt_b == \'undefined\' &&\n
      typeof opt_c == \'undefined\') {\n
    // Method 2: diffs\n
    // Compute text1 from diffs.\n
    diffs = /** @type {!Array.<!diff_match_patch.Diff>} */(a);\n
    text1 = this.diff_text1(diffs);\n
  } else if (typeof a == \'string\' && opt_b && typeof opt_b == \'object\' &&\n
      typeof opt_c == \'undefined\') {\n
    // Method 3: text1, diffs\n
    text1 = /** @type {string} */(a);\n
    diffs = /** @type {!Array.<!diff_match_patch.Diff>} */(opt_b);\n
  } else if (typeof a == \'string\' && typeof opt_b == \'string\' &&\n
      opt_c && typeof opt_c == \'object\') {\n
    // Method 4: text1, text2, diffs\n
    // text2 is not used.\n
    text1 = /** @type {string} */(a);\n
    diffs = /** @type {!Array.<!diff_match_patch.Diff>} */(opt_c);\n
  } else {\n
    throw new Error(\'Unknown call format to patch_make.\');\n
  }\n
\n
  if (diffs.length === 0) {\n
    return [];  // Get rid of the null case.\n
  }\n
  var patches = [];\n
  var patch = new diff_match_patch.patch_obj();\n
  var patchDiffLength = 0;  // Keeping our own length var is faster in JS.\n
  var char_count1 = 0;  // Number of characters into the text1 string.\n
  var char_count2 = 0;  // Number of characters into the text2 string.\n
  // Start with text1 (prepatch_text) and apply the diffs until we arrive at\n
  // text2 (postpatch_text).  We recreate the patches one by one to determine\n
  // context info.\n
  var prepatch_text = text1;\n
  var postpatch_text = text1;\n
  for (var x = 0; x < diffs.length; x++) {\n
    var diff_type = diffs[x][0];\n
    var diff_text = diffs[x][1];\n
\n
    if (!patchDiffLength && diff_type !== DIFF_EQUAL) {\n
      // A new patch starts here.\n
      patch.start1 = char_count1;\n
      patch.start2 = char_count2;\n
    }\n
\n
    switch (diff_type) {\n
      case DIFF_INSERT:\n
        patch.diffs[patchDiffLength++] = diffs[x];\n
        patch.length2 += diff_text.length;\n
        postpatch_text = postpatch_text.substring(0, char_count2) + diff_text +\n
                         postpatch_text.substring(char_count2);\n
        break;\n
      case DIFF_DELETE:\n
        patch.length1 += diff_text.length;\n
        patch.diffs[patchDiffLength++] = diffs[x];\n
        postpatch_text = postpatch_text.substring(0, char_count2) +\n
                         postpatch_text.substring(char_count2 +\n
                             diff_text.length);\n
        break;\n
      case DIFF_EQUAL:\n
        if (diff_text.length <= 2 * this.Patch_Margin &&\n
            patchDiffLength && diffs.length != x + 1) {\n
          // Small equality inside a patch.\n
          patch.diffs[patchDiffLength++] = diffs[x];\n
          patch.length1 += diff_text.length;\n
          patch.length2 += diff_text.length;\n
        } else if (diff_text.length >= 2 * this.Patch_Margin) {\n
          // Time for a new patch.\n
          if (patchDiffLength) {\n
            this.patch_addContext_(patch, prepatch_text);\n
            patches.push(patch);\n
            patch = new diff_match_patch.patch_obj();\n
            patchDiffLength = 0;\n
            // Unlike Unidiff, our patch lists have a rolling context.\n
            // http://code.google.com/p/google-diff-match-patch/wiki/Unidiff\n
            // Update prepatch text & pos to reflect the application of the\n
            // just completed patch.\n
            prepatch_text = postpatch_text;\n
            char_count1 = char_count2;\n
          }\n
        }\n
        break;\n
    }\n
\n
    // Update the current character count.\n
    if (diff_type !== DIFF_INSERT) {\n
      char_count1 += diff_text.length;\n
    }\n
    if (diff_type !== DIFF_DELETE) {\n
      char_count2 += diff_text.length;\n
    }\n
  }\n
  // Pick up the leftover patch if not empty.\n
  if (patchDiffLength) {\n
    this.patch_addContext_(patch, prepatch_text);\n
    patches.push(patch);\n
  }\n
\n
  return patches;\n
};\n
\n
\n
/**\n
 * Given an array of patches, return another array that is identical.\n
 * @param {!Array.<!diff_match_patch.patch_obj>} patches Array of Patch objects.\n
 * @return {!Array.<!diff_match_patch.patch_obj>} Array of Patch objects.\n
 */\n
diff_match_patch.prototype.patch_deepCopy = function(patches) {\n
  // Making deep copies is hard in JavaScript.\n
  var patchesCopy = [];\n
  for (var x = 0; x < patches.length; x++) {\n
    var patch = patches[x];\n
    var patchCopy = new diff_match_patch.patch_obj();\n
    patchCopy.diffs = [];\n
    for (var y = 0; y < patch.diffs.length; y++) {\n
      patchCopy.diffs[y] = patch.diffs[y].slice();\n
    }\n
    patchCopy.start1 = patch.start1;\n
    patchCopy.start2 = patch.start2;\n
    patchCopy.length1 = patch.length1;\n
    patchCopy.length2 = patch.length2;\n
    patchesCopy[x] = patchCopy;\n
  }\n
  return patchesCopy;\n
};\n
\n
\n
/**\n
 * Merge a set of patches onto the text.  Return a patched text, as well\n
 * as a list of true/false values indicating which patches were applied.\n
 * @param {!Array.<!diff_match_patch.patch_obj>} patches Array of Patch objects.\n
 * @param {string} text Old text.\n
 * @return {!Array.<string|!Array.<boolean>>} Two element Array, containing the\n
 *      new text and an array of boolean values.\n
 */\n
diff_match_patch.prototype.patch_apply = function(patches, text) {\n
  if (patches.length == 0) {\n
    return [text, []];\n
  }\n
\n
  // Deep copy the patches so that no changes are made to originals.\n
  patches = this.patch_deepCopy(patches);\n
\n
  var nullPadding = this.patch_addPadding(patches);\n
  text = nullPadding + text + nullPadding;\n
\n
  this.patch_splitMax(patches);\n
  // delta keeps track of the offset between the expected and actual location\n
  // of the previous patch.  If there are patches expected at positions 10 and\n
  // 20, but the first patch was found at 12, delta is 2 and the second patch\n
  // has an effective expected position of 22.\n
  var delta = 0;\n
  var results = [];\n
  for (var x = 0; x < patches.length; x++) {\n
    var expected_loc = patches[x].start2 + delta;\n
    var text1 = this.diff_text1(patches[x].diffs);\n
    var start_loc;\n
    var end_loc = -1;\n
    if (text1.length > this.Match_MaxBits) {\n
      // patch_splitMax will only provide an oversized pattern in the case of\n
      // a monster delete.\n
      start_loc = this.match_main(text, text1.substring(0, this.Match_MaxBits),\n
                                  expected_loc);\n
      if (start_loc != -1) {\n
        end_loc = this.match_main(text,\n
            text1.substring(text1.length - this.Match_MaxBits),\n
            expected_loc + text1.length - this.Match_MaxBits);\n
        if (end_loc == -1 || start_loc >= end_loc) {\n
          // Can\'t find valid trailing context.  Drop this patch.\n
          start_loc = -1;\n
        }\n
      }\n
    } else {\n
      start_loc = this.match_main(text, text1, expected_loc);\n
    }\n
    if (start_loc == -1) {\n
      // No match found.  :(\n
      results[x] = false;\n
      // Subtract the delta for this failed patch from subsequent patches.\n
      delta -= patches[x].length2 - patches[x].length1;\n
    } else {\n
      // Found a match.  :)\n
      results[x] = true;\n
      delta = start_loc - expected_loc;\n
      var text2;\n
      if (end_loc == -1) {\n
        text2 = text.substring(start_loc, start_loc + text1.length);\n
      } else {\n
        text2 = text.substring(start_loc, end_loc + this.Match_MaxBits);\n
      }\n
      if (text1 == text2) {\n
        // Perfect match, just shove the replacement text in.\n
        text = text.substring(0, start_loc) +\n
               this.diff_text2(patches[x].diffs) +\n
               text.substring(start_loc + text1.length);\n
      } else {\n
        // Imperfect match.  Run a diff to get a framework of equivalent\n
        // indices.\n
        var diffs = this.diff_main(text1, text2, false);\n
        if (text1.length > this.Match_MaxBits &&\n
            this.diff_levenshtein(diffs) / text1.length >\n
            this.Patch_DeleteThreshold) {\n
          // The end points match, but the content is unacceptably bad.\n
          results[x] = false;\n
        } else {\n
          this.diff_cleanupSemanticLossless(diffs);\n
          var index1 = 0;\n
          var index2;\n
          for (var y = 0; y < patches[x].diffs.length; y++) {\n
            var mod = patches[x].diffs[y];\n
            if (mod[0] !== DIFF_EQUAL) {\n
              index2 = this.diff_xIndex(diffs, index1);\n
            }\n
            if (mod[0] === DIFF_INSERT) {  // Insertion\n
              text = text.substring(0, start_loc + index2) + mod[1] +\n
                     text.substring(start_loc + index2);\n
            } else if (mod[0] === DIFF_DELETE) {  // Deletion\n
              text = text.substring(0, start_loc + index2) +\n
                     text.substring(start_loc + this.diff_xIndex(diffs,\n
                         index1 + mod[1].length));\n
            }\n
            if (mod[0] !== DIFF_DELETE) {\n
              index1 += mod[1].length;\n
            }\n
          }\n
        }\n
      }\n
    }\n
  }\n
  // Strip the padding off.\n
  text = text.substring(nullPadding.length, text.length - nullPadding.length);\n
  return [text, results];\n
};\n
\n
\n
/**\n
 * Add some padding on text start and end so that edges can match something.\n
 * Intended to be called only from within patch_apply.\n
 * @param {!Array.<!diff_match_patch.patch_obj>} patches Array of Patch objects.\n
 * @return {string} The padding string added to each side.\n
 */\n
diff_match_patch.prototype.patch_addPadding = function(patches) {\n
  var paddingLength = this.Patch_Margin;\n
  var nullPadding = \'\';\n
  for (var x = 1; x <= paddingLength; x++) {\n
    nullPadding += String.fromCharCode(x);\n
  }\n
\n
  // Bump all the patches forward.\n
  for (var x = 0; x < patches.length; x++) {\n
    patches[x].start1 += paddingLength;\n
    patches[x].start2 += paddingLength;\n
  }\n
\n
  // Add some padding on start of first diff.\n
  var patch = patches[0];\n
  var diffs = patch.diffs;\n
  if (diffs.length == 0 || diffs[0][0] != DIFF_EQUAL) {\n
    // Add nullPadding equality.\n
    diffs.unshift([DIFF_EQUAL, nullPadding]);\n
    patch.start1 -= paddingLength;  // Should be 0.\n
    patch.start2 -= paddingLength;  // Should be 0.\n
    patch.length1 += paddingLength;\n
    patch.length2 += paddingLength;\n
  } else if (paddingLength > diffs[0][1].length) {\n
    // Grow first equality.\n
    var extraLength = paddingLength - diffs[0][1].length;\n
    diffs[0][1] = nullPadding.substring(diffs[0][1].length) + diffs[0][1];\n
    patch.start1 -= extraLength;\n
    patch.start2 -= extraLength;\n
    patch.length1 += extraLength;\n
    patch.length2 += extraLength;\n
  }\n
\n
  // Add some padding on end of last diff.\n
  patch = patches[patches.length - 1];\n
  diffs = patch.diffs;\n
  if (diffs.length == 0 || diffs[diffs.length - 1][0] != DIFF_EQUAL) {\n
    // Add nullPadding equality.\n
    diffs.push([DIFF_EQUAL, nullPadding]);\n
    patch.length1 += paddingLength;\n
    patch.length2 += paddingLength;\n
  } else if (paddingLength > diffs[diffs.length - 1][1].length) {\n
    // Grow last equality.\n
    var extraLength = paddingLength - diffs[diffs.length - 1][1].length;\n
    diffs[diffs.length - 1][1] += nullPadding.substring(0, extraLength);\n
    patch.length1 += extraLength;\n
    patch.length2 += extraLength;\n
  }\n
\n
  return nullPadding;\n
};\n
\n
\n
/**\n
 * Look through the patches and break up any which are longer than the maximum\n
 * limit of the match algorithm.\n
 * Intended to be called only from within patch_apply.\n
 * @param {!Array.<!diff_match_patch.patch_obj>} patches Array of Patch objects.\n
 */\n
diff_match_patch.prototype.patch_splitMax = function(patches) {\n
  var patch_size = this.Match_MaxBits;\n
  for (var x = 0; x < patches.length; x++) {\n
    if (patches[x].length1 <= patch_size) {\n
      continue;\n
    }\n
    var bigpatch = patches[x];\n
    // Remove the big old patch.\n
    patches.splice(x--, 1);\n
    var start1 = bigpatch.start1;\n
    var start2 = bigpatch.start2;\n
    var precontext = \'\';\n
    while (bigpatch.diffs.length !== 0) {\n
      // Create one of several smaller patches.\n
      var patch = new diff_match_patch.patch_obj();\n
      var empty = true;\n
      patch.start1 = start1 - precontext.length;\n
      patch.start2 = start2 - precontext.length;\n
      if (precontext !== \'\') {\n
        patch.length1 = patch.length2 = precontext.length;\n
        patch.diffs.push([DIFF_EQUAL, precontext]);\n
      }\n
      while (bigpatch.diffs.length !== 0 &&\n
             patch.length1 < patch_size - this.Patch_Margin) {\n
        var diff_type = bigpatch.diffs[0][0];\n
        var diff_text = bigpatch.diffs[0][1];\n
        if (diff_type === DIFF_INSERT) {\n
          // Insertions are harmless.\n
          patch.length2 += diff_text.length;\n
          start2 += diff_text.length;\n
          patch.diffs.push(bigpatch.diffs.shift());\n
          empty = false;\n
        } else if (diff_type === DIFF_DELETE && patch.diffs.length == 1 &&\n
                   patch.diffs[0][0] == DIFF_EQUAL &&\n
                   diff_text.length > 2 * patch_size) {\n
          // This is a large deletion.  Let it pass in one chunk.\n
          patch.length1 += diff_text.length;\n
          start1 += diff_text.length;\n
          empty = false;\n
          patch.diffs.push([diff_type, diff_text]);\n
          bigpatch.diffs.shift();\n
        } else {\n
          // Deletion or equality.  Only take as much as we can stomach.\n
          diff_text = diff_text.substring(0,\n
              patch_size - patch.length1 - this.Patch_Margin);\n
          patch.length1 += diff_text.length;\n
          start1 += diff_text.length;\n
          if (diff_type === DIFF_EQUAL) {\n
            patch.length2 += diff_text.length;\n
            start2 += diff_text.length;\n
          } else {\n
            empty = false;\n
          }\n
          patch.diffs.push([diff_type, diff_text]);\n
          if (diff_text == bigpatch.diffs[0][1]) {\n
            bigpatch.diffs.shift();\n
          } else {\n
            bigpatch.diffs[0][1] =\n
                bigpatch.diffs[0][1].substring(diff_text.length);\n
          }\n
        }\n
      }\n
      // Compute the head context for the next patch.\n
      precontext = this.diff_text2(patch.diffs);\n
      precontext =\n
          precontext.substring(precontext.length - this.Patch_Margin);\n
      // Append the end context for this patch.\n
      var postcontext = this.diff_text1(bigpatch.diffs)\n
                            .substring(0, this.Patch_Margin);\n
      if (postcontext !== \'\') {\n
        patch.length1 += postcontext.length;\n
        patch.length2 += postcontext.length;\n
        if (patch.diffs.length !== 0 &&\n
            patch.diffs[patch.diffs.length - 1][0] === DIFF_EQUAL) {\n
          patch.diffs[patch.diffs.length - 1][1] += postcontext;\n
        } else {\n
          patch.diffs.push([DIFF_EQUAL, postcontext]);\n
        }\n
      }\n
      if (!empty) {\n
        patches.splice(++x, 0, patch);\n
      }\n
    }\n
  }\n
};\n
\n
\n
/**\n
 * Take a list of patches and return a textual representation.\n
 * @param {!Array.<!diff_match_patch.patch_obj>} patches Array of Patch objects.\n
 * @return {string} Text representation of patches.\n
 */\n
diff_match_patch.prototype.patch_toText = function(patches) {\n
  var text = [];\n
  for (var x = 0; x < patches.length; x++) {\n
    text[x] = patches[x];\n
  }\n
  return text.join(\'\');\n
};\n
\n
\n
/**\n
 * Parse a textual representation of patches and return a list of Patch objects.\n
 * @param {string} textline Text representation of patches.\n
 * @return {!Array.<!diff_match_patch.patch_obj>} Array of Patch objects.\n
 * @throws {!Error} If invalid input.\n
 */\n
diff_match_patch.prototype.patch_fromText = function(textline) {\n
  var patches = [];\n
  if (!textline) {\n
    return patches;\n
  }\n
  var text = textline.split(\'\\n\');\n
  var textPointer = 0;\n
  var patchHeader = /^@@ -(\\d+),?(\\d*) \\+(\\d+),?(\\d*) @@$/;\n
  while (textPointer < text.length) {\n
    var m = text[textPointer].match(patchHeader);\n
    if (!m) {\n
      throw new Error(\'Invalid patch string: \' + text[textPointer]);\n
    }\n
    var patch = new diff_match_patch.patch_obj();\n
    patches.push(patch);\n
    patch.start1 = parseInt(m[1], 10);\n
    if (m[2] === \'\') {\n
      patch.start1--;\n
      patch.length1 = 1;\n
    } else if (m[2] == \'0\') {\n
      patch.length1 = 0;\n
    } else {\n
      patch.start1--;\n
      patch.length1 = parseInt(m[2], 10);\n
    }\n
\n
    patch.start2 = parseInt(m[3], 10);\n
    if (m[4] === \'\') {\n
      patch.start2--;\n
      patch.length2 = 1;\n
    } else if (m[4] == \'0\') {\n
      patch.length2 = 0;\n
    } else {\n
      patch.start2--;\n
      patch.length2 = parseInt(m[4], 10);\n
    }\n
    textPointer++;\n
\n
    while (textPointer < text.length) {\n
      var sign = text[textPointer].charAt(0);\n
      try {\n
        var line = decodeURI(text[textPointer].substring(1));\n
      } catch (ex) {\n
        // Malformed URI sequence.\n
        throw new Error(\'Illegal escape in patch_fromText: \' + line);\n
      }\n
      if (sign == \'-\') {\n
        // Deletion.\n
        patch.diffs.push([DIFF_DELETE, line]);\n
      } else if (sign == \'+\') {\n
        // Insertion.\n
        patch.diffs.push([DIFF_INSERT, line]);\n
      } else if (sign == \' \') {\n
        // Minor equality.\n
        patch.diffs.push([DIFF_EQUAL, line]);\n
      } else if (sign == \'@\') {\n
        // Start of next patch.\n
        break;\n
      } else if (sign === \'\') {\n
        // Blank line?  Whatever.\n
      } else {\n
        // WTF?\n
        throw new Error(\'Invalid patch mode "\' + sign + \'" in: \' + line);\n
      }\n
      textPointer++;\n
    }\n
  }\n
  return patches;\n
};\n
\n
\n
/**\n
 * Class representing one patch operation.\n
 * @constructor\n
 */\n
diff_match_patch.patch_obj = function() {\n
  /** @type {!Array.<!diff_match_patch.Diff>} */\n
  this.diffs = [];\n
  /** @type {?number} */\n
  this.start1 = null;\n
  /** @type {?number} */\n
  this.start2 = null;\n
  /** @type {number} */\n
  this.length1 = 0;\n
  /** @type {number} */\n
  this.length2 = 0;\n
};\n
\n
\n
/**\n
 * Emmulate GNU diff\'s format.\n
 * Header: @@ -382,8 +481,9 @@\n
 * Indicies are printed as 1-based, not 0-based.\n
 * @return {string} The GNU diff string.\n
 */\n
diff_match_patch.patch_obj.prototype.toString = function() {\n
  var coords1, coords2;\n
  if (this.length1 === 0) {\n
    coords1 = this.start1 + \',0\';\n
  } else if (this.length1 == 1) {\n
    coords1 = this.start1 + 1;\n
  } else {\n
    coords1 = (this.start1 + 1) + \',\' + this.length1;\n
  }\n
  if (this.length2 === 0) {\n
    coords2 = this.start2 + \',0\';\n
  } else if (this.length2 == 1) {\n
    coords2 = this.start2 + 1;\n
  } else {\n
    coords2 = (this.start2 + 1) + \',\' + this.length2;\n
  }\n
  var text = [\'@@ -\' + coords1 + \' +\' + coords2 + \' @@\\n\'];\n
  var op;\n
  // Escape the body of the patch with %xx notation.\n
  for (var x = 0; x < this.diffs.length; x++) {\n
    switch (this.diffs[x][0]) {\n
      case DIFF_INSERT:\n
        op = \'+\';\n
        break;\n
      case DIFF_DELETE:\n
        op = \'-\';\n
        break;\n
      case DIFF_EQUAL:\n
        op = \' \';\n
        break;\n
    }\n
    text[x + 1] = op + encodeURI(this.diffs[x][1]) + \'\\n\';\n
  }\n
  return text.join(\'\').replace(/%20/g, \' \');\n
};\n
\n
\n
// Export these global variables so that they survive Google\'s JS compiler.\n
// In a browser, \'this\' will be \'window\'.\n
// Users of node.js should \'require\' the uncompressed version since Google\'s\n
// JS compiler may break the following exports for non-browser environments.\n
this[\'diff_match_patch\'] = diff_match_patch;\n
this[\'DIFF_DELETE\'] = DIFF_DELETE;\n
this[\'DIFF_INSERT\'] = DIFF_INSERT;\n
this[\'DIFF_EQUAL\'] = DIFF_EQUAL;\n


]]></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
