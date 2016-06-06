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
            <value> <string>ts92828861.19</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>password.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* Copyright (c) 2014 Nexedi\n
 *                    Vincent Pelletier <vincent@nexedi.com>\n
 *\n
 * WARNING: This program as such is intended to be used by professional\n
 * programmers who take the whole responsability of assessing all potential\n
 * consequences resulting from its eventual inadequacies and bugs\n
 * End users who are looking for a ready-to-use solution with commercial\n
 * garantees and support are strongly adviced to contract a Free Software\n
 * Service Company\n
 *\n
 * This program is Free Software; you can redistribute it and/or\n
 * modify it under the terms of the GNU General Public License\n
 * as published by the Free Software Foundation; either version 2\n
 * of the License, or (at your option) any later version.\n
 *\n
 * This program is distributed in the hope that it will be useful,\n
 * but WITHOUT ANY WARRANTY; without even the implied warranty of\n
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n
 * GNU General Public License for more details.\n
 *\n
 * You should have received a copy of the GNU General Public License\n
 * along with this program; if not, write to the Free Software\n
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.\n
 */\n
/*jslint browser: true, bitwise: true, unparam: true, indent: 2, maxlen: 80 */\n
\n
function SequenceDetector(sequence, wrap, start, character_score,\n
    is_lower, is_upper) {\n
  "use strict";\n
  this.sequence = sequence;\n
  this.wrap = wrap;\n
  this.index = start;\n
  this.variety = character_score;\n
  this.has_lower = is_lower;\n
  this.has_upper = is_upper;\n
  this.matched = 1;\n
  this.direction = 0;\n
}\n
\n
SequenceDetector.prototype.eq = function (index, character) {\n
  "use strict";\n
  if (this.wrap) {\n
    index %= this.sequence.length;\n
  }\n
  return this.sequence.charAt(index) === character;\n
};\n
\n
SequenceDetector.prototype.next = function (character, character_score,\n
    is_lower, is_upper) {\n
  "use strict";\n
  if (this.direction === 0) {\n
    /* second char of the supposed sequence, guess direction */\n
    if (this.eq(this.index + 1, character)) {\n
      this.direction = 1;\n
    } else if (this.eq(this.index - 1,  character)) {\n
      this.direction = -1;\n
    } else {\n
      /* not a sequence */\n
      return false;\n
    }\n
  } else if (!this.eq(this.index + this.direction, character)) {\n
    /* sequence ended */\n
    return false;\n
  }\n
  this.index += this.direction;\n
  this.matched += 1;\n
  this.variety += character_score;\n
  this.has_lower |= is_lower;\n
  this.has_upper |= is_upper;\n
  return true;\n
};\n
\n
function SequenceDetectorFactory(sequence, wrap) {\n
  "use strict";\n
  this.sequence = sequence;\n
  this.wrap = wrap;\n
}\n
\n
SequenceDetectorFactory.prototype.getDetector = function (character,\n
    character_score, is_lower, is_upper) {\n
  "use strict";\n
  var index = this.sequence.indexOf(character);\n
  if (index === -1) {\n
    return null;\n
  }\n
  return new SequenceDetector(this.sequence, this.wrap, index, character_score,\n
    is_lower, is_upper);\n
};\n
\n
function PasswordValidator() {\n
  "use strict";\n
  /* Double all sequences so crossing sequence boundaries still counts as\n
   * sequence. */\n
  var orig_sequences = this.SEQUENCES,\n
    sequences = [],\n
    sequence,\n
    i;\n
  this.SEQUENCES = sequences;\n
  for (i = 0; i < orig_sequences.length; i += 1) {\n
    sequence = orig_sequences[i];\n
    sequences.push(new SequenceDetectorFactory(sequence[0], sequence[1]));\n
  }\n
}\n
window.PasswordValidator = PasswordValidator;\n
\n
\n
/* Uniqueness is a reweard for not reusing the same character several times.\n
 * SCORE_UNIQUE increase this reward, SCORE_UNIQUE_DIVISOR is the divisor\n
 * used to determine the score of repetitions. */\n
PasswordValidator.prototype.SCORE_UNIQUE = 1;\n
/* Obviously:\n
 * - zero is will cause errors\n
 * - negative values will give non-linear scores\n
 * - values between zero and one will reward for repetitions (you do not want\n
 *   this)\n
 * - use Infinity to only reward unique chars */\n
PasswordValidator.prototype.SCORE_UNIQUE_DIVISOR = 1.5;\n
PasswordValidator.prototype.SCORE_UPPER = 1;\n
PasswordValidator.prototype.SCORE_LOWER = 1;\n
/* Password variety is the number of unique chars in it. Score is computed\n
 * as the variety elevated to the power of SCORE_VARIETY, and added to\n
 * password score. */\n
PasswordValidator.prototype.SCORE_VARIETY = 2;\n
/* Sequences are SEQUENCE_THRESHOLD or more consecutive chars in password which\n
 * are in direct or reverse order of any of SEQUENCES. */\n
PasswordValidator.prototype.SEQUENCE_THRESHOLD = 3;\n
PasswordValidator.prototype.SEQUENCES = [\n
  ["abcdefghijklmnopqrstuvwxyz", true],\n
  ["0123456789", true],\n
  /* azerty */\n
  ["azertyuiop", false],\n
  ["qsdfghjklm", false],\n
  ["wxcvbn", false],\n
  /* qwerty */\n
  ["qwertyuiop", false],\n
  ["asdfghjkl", false],\n
  ["zxcvbnm", false],\n
  /* qwertz */\n
  ["qwertzuiop", false],\n
  ["yxcvbnm", false]\n
];\n
/* Classes are types of characters. Password should contain chars from as\n
 * many classes as possible. Score is computed as the number of found class\n
 * elevated to the power of SCORE_CLASS, and added to password score.\n
 * Upper and lower case are treated separately, but are handled as classes. */\n
PasswordValidator.prototype.SCORE_CLASS = 3;\n
PasswordValidator.prototype.CLASSES = [\n
  /\\d/,\n
  /\\W/\n
];\n
/* Padding is appended to password internally for code simplicity. It must not\n
 * be present in any provided password. The null character seems like a\n
 * reasonable choice. */\n
PasswordValidator.prototype.PADDING = "\\x00";\n
\n
/* Ranges have a low threshold, CSS-friendly name, and human-readable caption.\n
 */\n
/* Weakest password range name. */\n
PasswordValidator.prototype.RANGE_BASE = "too-weak";\n
/* Above-weakest range definition, as threshold and range name pairs. */\n
PasswordValidator.prototype.RANGE_THRESHOLDS = [\n
  [54, "weak"],\n
  [70, "medium"],\n
  [90, "strong"]\n
];\n
/* Range name to human-friendly caption mapping. Override for l10n. */\n
PasswordValidator.prototype.RANGE_CAPTION = {\n
  "too-weak": "Too weak",\n
  "weak": "Weak",\n
  "medium": "Medium",\n
  "strong": "Strong"\n
};\n
/* Ignore given sequences when wholy found in a password. Unlike SEQUENCES,\n
 * BLACKLIST entries are char-order-sensitive. Some entries come from the 2013\n
 * top-25 most common passwords, ignoring those already getting a poor score\n
 * from other criterions. */\n
PasswordValidator.prototype.BLACKLIST = [\n
  "password",\n
  "iloveyou",\n
  "admin",\n
  "letmein",\n
  "monkey",\n
  "sunshine",\n
  "shadow",\n
  "princess",\n
  "trustno1"\n
];\n
\n
PasswordValidator.prototype.getScoreRange = function (score) {\n
  "use strict";\n
  var range = this.RANGE_BASE, i;\n
  for (i = 0; i < this.RANGE_THRESHOLDS.length; i += 1) {\n
    if (score < this.RANGE_THRESHOLDS[i][0]) {\n
      break;\n
    }\n
    range = this.RANGE_THRESHOLDS[i][1];\n
  }\n
  return range;\n
};\n
\n
PasswordValidator.prototype.getScore = function (value, tracer) {\n
  "use strict";\n
  var variety = 0,\n
    variety_map = {},\n
    padded_value,\n
    lower,\n
    upper,\n
    is_lower,\n
    is_upper,\n
    has_lower = 0,\n
    has_upper = 0,\n
    sequences = [],\n
    new_sequences,\n
    sequence_matched,\n
    sequence = null,\n
    current_value,\n
    current_lower,\n
    value_index,\n
    character_score,\n
    class_count = 0,\n
    class_index,\n
    current_substring,\n
    current_blacklist,\n
    class_pattern,\n
    lazy_tracer,\n
    i;\n
  variety_map[this.PADDING] = 0;\n
  if (tracer === undefined) {\n
    lazy_tracer = function () {};\n
  } else {\n
    lazy_tracer = function () {\n
      /* concatenate message, to reduce cost when tracer is undefined */\n
      var offset = arguments[0],\n
        message = arguments[1],\n
        i;\n
      for (i = 2; i < arguments.length; i += 1) {\n
        message += arguments[i];\n
      }\n
      tracer(offset, message);\n
    };\n
  }\n
  if (value.indexOf(this.PADDING) !== -1) {\n
    throw "input contains padding char";\n
  }\n
  padded_value = value + this.PADDING;\n
  upper = padded_value.toLocaleUpperCase();\n
  lower = padded_value.toLocaleLowerCase();\n
  for (value_index = 0; value_index < padded_value.length; value_index += 1) {\n
    current_substring = lower.substr(value_index);\n
    for (i = 0; i < this.BLACKLIST.length; i += 1) {\n
      current_blacklist = this.BLACKLIST[i];\n
      if (current_substring.substr(0, current_blacklist.length\n
          ) === current_blacklist) {\n
        value_index += current_blacklist.length;\n
        break;\n
      }\n
    }\n
    current_value = padded_value.charAt(value_index);\n
    current_lower = lower.charAt(value_index);\n
    is_lower = current_value !== upper.charAt(value_index) &&\n
               current_value === lower.charAt(value_index);\n
    is_upper = current_value !== lower.charAt(value_index) &&\n
               current_value === upper.charAt(value_index);\n
    character_score = variety_map[current_lower];\n
    if (character_score === undefined) {\n
      character_score = this.SCORE_UNIQUE;\n
    }\n
    lazy_tracer(value_index, "variety:", character_score);\n
    variety_map[current_lower] = character_score / this.SCORE_UNIQUE_DIVISOR;\n
    new_sequences = [];\n
    sequence_matched = false;\n
    for (i = 0; i < sequences.length; i += 1) {\n
      sequence = sequences[i];\n
      if (sequence.next(current_lower, character_score, is_lower, is_upper)) {\n
        lazy_tracer(value_index, "sequence still matching ", sequence.sequence,\n
          " at ", sequence.index, " going ", sequence.direction);\n
        new_sequences.push(sequence);\n
      /* First sequence is always the longest match known yet. This is an\n
       * imperfect way of choosing the sequence which eats most chars, but it\n
       * should be sufficiently close to best result.\n
       * Exemple of it going wrong:\n
       *   password = "12345";\n
       *   SEQUENCES = [["123", false], ["2345", false]];\n
       * First sequence will match for 3 chars, and second will get discarded\n
       * although it could have eaten 4.\n
       * Likewise for\n
       *   SEQUENCES = [["123", false], ["1234", false]];\n
       * so overall it\'s mostly a matter of which sequences are defined and in\n
       * which order.\n
       */\n
      } else if (i === 0 &&\n
          sequence.matched >= this.SEQUENCE_THRESHOLD) {\n
        lazy_tracer(value_index, "sequence done matching ", sequence.sequence);\n
        sequence_matched = true;\n
        /* matching sequences count as a single neither upper- nor lower-case,\n
         * unique character. That latest caracteristic is too laxist, but\n
         * costly to verify. */\n
        variety += 1;\n
        new_sequences = [];\n
        break;\n
      }\n
    }\n
    if (!sequence_matched && sequences.length !== 0 && (\n
        new_sequences.length === 0 || (\n
          new_sequences[0].matched <= sequences[0].matched &&\n
          new_sequences[0] !== sequences[0]\n
        )\n
      )) {\n
      /* Best candidates all ended */\n
      sequence = sequences[0];\n
      lazy_tracer(value_index,\n
        "sequence best candidates failed matching, accepting variety:",\n
        sequence.variety, " lower:", sequence.has_lower,\n
        " upper:", sequence.has_upper);\n
      variety += sequence.variety;\n
      has_lower |= sequence.has_lower;\n
      has_upper |= sequence.has_upper;\n
      new_sequences = [];\n
    }\n
    sequences = new_sequences;\n
    for (i = 0; i < this.SEQUENCES.length; i += 1) {\n
      sequence = this.SEQUENCES[i].getDetector(current_lower, character_score,\n
        is_lower, is_upper);\n
      if (sequence !== null) {\n
        lazy_tracer(value_index, "sequence candidate ", sequence.sequence,\n
          " at ", sequence.index);\n
        sequences.push(sequence);\n
      }\n
    }\n
    if (sequences.length === 0) {\n
      lazy_tracer(value_index,\n
        "no matching sequence, accepting variety:", character_score,\n
        " lower:", is_lower, " upper:", is_upper);\n
      variety += character_score;\n
      has_lower |= is_lower;\n
      has_upper |= is_upper;\n
    }\n
  }\n
  if (has_lower) {\n
    lazy_tracer(value_index, "has lower");\n
    class_count += this.SCORE_LOWER;\n
  }\n
  if (has_upper) {\n
    lazy_tracer(value_index, "has upper");\n
    class_count += this.SCORE_UPPER;\n
  }\n
  for (class_index = 0; class_index < this.CLASSES.length; class_index += 1) {\n
    class_pattern = this.CLASSES[class_index];\n
    if (value.match(class_pattern)) {\n
      lazy_tracer(value_index, "matches ", class_pattern);\n
      class_count += 1;\n
    }\n
  }\n
  return Math.pow(variety, this.SCORE_VARIETY) +\n
         Math.pow(class_count, this.SCORE_CLASS);\n
};\n
\n
if ($.hasOwnProperty("validator")) {\n
  $.validator.addMethod("passwordMetter", function (value, element, params) {\n
    "use strict";\n
    var metter,\n
      /* use untrimmed value */\n
      password = element.value,\n
      optional = this.optional(element),\n
      validator = params.validator,\n
      score,\n
      range,\n
      score_percent,\n
      parent;\n
    if (params.hasOwnProperty("metter")) {\n
      metter = params.metter;\n
    } else {\n
      parent = $(element).parent();\n
      parent.append(\'<div class="password-meter" style="display:none"><div class="password-meter-message"></div><div class="password-meter-bg"><div class="password-meter-bar"></div></div></div>\');\n
      params.metter = metter = parent.find(".password-meter");\n
    }\n
    metter.hide();\n
    if (!optional || password.length) {\n
      score = validator.getScore(password);\n
      range = validator.getScoreRange(score);\n
      score_percent = Math.round(Math.min(1,\n
        score / validator.RANGE_THRESHOLDS[validator.RANGE_THRESHOLDS.length - 1\n
          ][0]) * 100);\n
      metter.find(".password-meter-bar")\n
        .removeClass()\n
        .addClass("password-meter-bar")\n
        .addClass("password-meter-" + range)\n
        .width(score_percent + "%");\n
      metter.find(".password-meter-message")\n
        .removeClass()\n
        .addClass("password-meter-message")\n
        .addClass("password-meter-message-" + range)\n
        .text(validator.RANGE_CAPTION[range]);\n
      metter.show();\n
      return range !== validator.RANGE_BASE;\n
    }\n
    return optional;\n
  }, "");\n
}

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>13252</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>jquery.validate.password.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
