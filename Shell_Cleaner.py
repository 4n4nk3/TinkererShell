import autorun
import sys
import os

if os.name == "nt":
	platform = "windows"
elif os.name == "posix":
	platform = "posix"
else:
	sys.exit("System not supported!")

if autorun.exists("SecurityPyUpdater"):
	print('Autorun exists!\nRemoving it...\n')
	try:
		autorun.remove("SecurityPyUpdater")
	except Exception as exception:
		print(exception)

if platform == 'windows':
	target_to_autostart = str(Path.home()) + os.path.normcase('/demo/sec_upd.exe')
else:
	target_to_autostart = str(Path.home()) + '/.Xsec_upd'

if os.path.isfile(target_to_autostart):
	print('File exist in default path!\nDeleting it...\n')
	try:
		os.remove(target_to_autostart)
	except Exception as exception:
		print(exception)
