##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################

from inspect import getargs
from types import MethodType
from Products.ExternalMethod.ExternalMethod import *
from Shared.DC.Scripts.Signature import FuncCode
from Products.ERP5Type.Globals import InitializeClass
from zLOG import LOG, WARNING
from . import PatchClass
from .PythonScript import addGuard, extractGuardResultArgument

class _(PatchClass(ExternalMethod)):

    reloadIfChanged = getFuncDefaults = getFuncCode = filepath = None

    @property
    def func_defaults(self):
        return self._getFunction()[1]

    @property
    def func_code(self):
        return self._getFunction()[2]

    def getFunction(self, reload=False):
        return self._getFunction(reload)[0]

    def _getFunction(self, reload=False):
        try:
            component_module = __import__(
                'erp5.component.extension.' + self._module,
                fromlist="*", level=0)
        except ImportError, e:
            if str(e) != "No module named " + self._module:
                # Fall back loudly if a component exists but is broken.
                # XXX: We used __import__ instead of
                #      erp5.component.extension.find_load_module
                #      because the latter is much slower.
                # XXX: Should we also fall back on FS if the module imports
                #      successfully but does not contain the wanted function?
                LOG("ERP5Type.dynamic", WARNING,
                    "Could not load Component module %r"
                    % ('erp5.component.extension.' + self._module),
                    error=1)
            if not reload:
                from Globals import DevelopmentMode
                if DevelopmentMode:
                    try:
                        last_read, path = self._v_fs
                    except AttributeError:
                        last_read = None
                        path = getPath('Extensions', self._module,
                                       suffixes=('', 'py', 'pyc'))
                    ts = os.stat(path)[stat.ST_MTIME]
                    if last_read != ts:
                        self._v_fs = ts, path
                        reload = True
            f = getObject(self._module, self._function, reload)
        else:
            f = getattr(component_module, self._function)
        try:
            _f = self._v_f
            if _f[0] is f:
                return _f
        except AttributeError:
            pass
        args, varargs, keywords = getargs(f.func_code)
        if isinstance(f, MethodType):
          del args[0]
        has_self = args[0] == 'self' if args else 0
        args, defaults, guard_result = extractGuardResultArgument(
            args[has_self:], f.func_defaults)
        # XXX: Same as for PythonScript
        n = len(args)
        if varargs:
            args.append(varargs)
        if keywords:
            args.append(keywords)
        self._v_f = _f = (f, defaults, FuncCode(args, n),
                          has_self, guard_result)
        return _f

    def __call__(self, *args, **kw):
        """Call an ExternalMethod

        Calling an External Method is roughly equivalent to calling
        the original actual function from Python.  Positional and
        keyword parameters can be passed as usual.  Note however that
        if first argument is 'self', and only in this case, the
        acquisition parent is passed as first positional parameter.
        """
        _f = self._getFunction()
        __traceback_info__ = args, kw, _f[1]

        if _f[4] is None:
          self.checkGuard(True)
        else:
          args = self._addGuardResult(_f[4], args, kw)

        if _f[3]:
            return _f[0](self.aq_parent, *args, **kw)
        return _f[0](*args, **kw)

    security = ClassSecurityInfo()

addGuard(ExternalMethod, change_external_methods)

InitializeClass(ExternalMethod)
