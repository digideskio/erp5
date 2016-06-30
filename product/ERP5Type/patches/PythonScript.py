##############################################################################
#
# Copyright (c) 2001 Zope Corporation and Contributors. All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.0 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
from Products.PythonScripts.PythonScript import PythonScript
from App.special_dtml import DTMLFile
from .. import _dtmldir
from ..Guard import Guard
from . import PatchClass
from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from OFS.misc_ import p_
from App.ImageFile import ImageFile
from Acquisition import aq_base, aq_parent
from zExceptions import Forbidden

### Guards

from Products.DCWorkflow.Guard import Guard as DCGuard
DCGuard.__call__ = Guard.__call__.__func__

_guard_manage_options = (
  {
    'label':'Guard',
    'action':'manage_guardForm',
  },
)

_guard_form = DTMLFile(
  'editGuardForm', _dtmldir)

def manage_guardForm(self, REQUEST, manage_tabs_message=None):
  '''
  '''
  return self._guard_form(REQUEST,
                          management_view='Guard',
                          manage_tabs_message=manage_tabs_message,
    )

def manage_setGuard(self, props=None, REQUEST=None):
  '''
  '''
  Guard._edit(self, 'guard', props or REQUEST)
  if REQUEST is not None:
    return self.manage_guardForm(REQUEST, 'Properties changed.')

def getGuard(self):
  guard = self.guard
  if guard is None:
    return Guard().__of__(self)  # Create a temporary guard.
  return guard

def checkGuard(aq_parent=aq_parent):
  def checkGuard(self, _exec=False):
    guard = self.guard
    if guard is None or guard(aq_parent(self)):
      return 1
    if _exec:
      raise Forbidden('Calling %s %s is denied by Guard.'
                      % (self.meta_type, self.id))
  return checkGuard
checkGuard = checkGuard()

def _addGuardResult(aq_parent=aq_parent):
  def _addGuardResult(self, pos, args, kw):
    if pos < 0:
      raise ValueError("The only allowed default value for"
                      " '_guard_result' argument is None")
    if '_guard_result' in kw:
      raise TypeError("%s() got an unexpected keyword argument '_guard_result'"
                      % self.id)
    guard = self.guard
    if guard is None:
      raise ValueError("Can't set '_guard_result': no Guard defined")
    if pos < len(args):
      return args[:pos] + (guard(aq_parent(self)),) + args[pos:]
    kw['_guard_result'] = guard(aq_parent(self))
    return args
  return _addGuardResult
_addGuardResult = _addGuardResult()

def extractGuardResultArgument(args, defaults):
  if '_guard_result' in args:
    i = args.index('_guard_result')
    if defaults:
      j = i - len(args) + len(defaults)
      if j >= 0:
        if defaults[i] is not None:
          i = -1
        defaults = defaults[:j] + defaults[j+1:]
    return args[:i] + args[i+1:], defaults, i
  return args, defaults, None

def addGuard(cls, set_permission):
  security = cls.security

  cls.guard = None
  cls.getGuard = getGuard
  cls.checkGuard = checkGuard
  cls._addGuardResult = _addGuardResult

  cls.manage_options += _guard_manage_options
  cls._guard_form = _guard_form

  security.declareProtected('View management screens', 'manage_guardForm')
  cls.manage_guardForm = manage_guardForm

  security.declareProtected(set_permission, 'manage_setGuard')
  cls.manage_setGuard = manage_setGuard

###

class _(PatchClass(PythonScript)):

  security = ClassSecurityInfo()

  # Add proxy role icon in ZMI

  def om_icons(self):
    """Return a list of icon URLs to be displayed by an ObjectManager"""
    if self._proxy_roles:
      return {'path': 'p_/PythonScript_ProxyRole_icon',
              'alt': 'Proxy Roled Python Script',
              'title': 'This script has proxy role.'},
    return {'path': 'misc_/PythonScripts/pyscript.gif',
            'alt': self.meta_type, 'title': self.meta_type},

  p_.PythonScript_ProxyRole_icon = \
    ImageFile('pyscript_proxyrole.gif', globals())

  # Patch for displaying textearea in full window instead of
  # remembering a quantity of lines to display in a cookie
  manage = manage_editDocument = manage_main = ZPythonScriptHTML_editForm = \
  manage_editForm = DTMLFile("pyScriptEdit", _dtmldir)
  manage_editForm._setName('manage_editForm')

  # Guards

  _guard_result = None

  def __call__(self, *args, **kw):
    '''Calls the script.'''
    if self._guard_result is None:
      self.checkGuard(True)
    else:
      args = self._addGuardResult(self._guard_result, args, kw)
    return self._orig_bindAndExec(args, kw, None)

  security.declarePublic("render")
  render = __call__

  # For __render_with_namespace__ (we prefer to monkey-patch __call__
  # because it's called more often, and this makes debugging easier)
  _orig_bindAndExec = PythonScript._bindAndExec
  def _bindAndExec(self, args, kw, caller_namespace):
    return self(*args, **kw) # caller_namespace not used by PythonScript

  assert '_setFuncSignature' not in PythonScript.__dict__
  def _setFuncSignature(self, defaults, varnames, argcount):
    args, defaults, guard_result = extractGuardResultArgument(
      list(varnames[:argcount]), defaults)
    if guard_result is not None:
      self._guard_result = guard_result
    # XXX: For code that guesses the presence of *,** arguments (e.g. Alarms).
    #      A proper solution is to have a func_code with co_flags.
    n = len(args)
    for x in 'args', 'kw':
      if len(varnames) <= argcount:
        break
      if varnames[argcount] == x:
        args.append(x)
        argcount += 1
    super(PythonScript, self)._setFuncSignature(defaults, tuple(args), n)

addGuard(PythonScript, 'Change Python Scripts')

InitializeClass(PythonScript)
