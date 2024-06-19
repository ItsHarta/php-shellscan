#!/usr/bin/python
# example how to deal with the depcache

import apt
import sys, os
import copy
import time

from apt.progress.base import InstallProgress

class TextInstallProgress(InstallProgress):
	def __init__(self):
		apt.progress.base.InstallProgress.__init__(self)
		self.last = 0.0
	def updateInterface(self):
		InstallProgress.updateInterface(self)
		if self.last >= self.percent:
			return
		sys.stdout.write("\r[%s] %s\n" %(self.percent, self.status))
		sys.stdout.flush()
		self.last = self.percent
	def error(self, errorstr):
		print(f'Error installing {self.current_package}')

cache = apt.Cache(apt.progress.text.OpProgress())

fprogress = apt.progress.text.AcquireProgress()
iprogress = TextInstallProgress()

pkg_name = "incron"
pkg = cache[pkg_name]

# install or remove, the importend thing is to keep us busy :)
print(f'installing {pkg_name}')
pkg.mark_install()
try:
    res = cache.commit(fprogress, iprogress)
    print(f'Successfully installed {pkg_name}')
except Exception as e:
    print(f'Error installing {pkg_name}: {e}')

sys.exit(0)