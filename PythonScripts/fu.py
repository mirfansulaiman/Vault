
import os, time

a1 = 'timeout 15s ./chrome --js-flags="expose-gc" ../out/fuzz-'
a2 = '.html &> ../log'
a3 = '.txt'

from os import listdir
from os.path import isfile, join
off = [f for f in listdir('../out') if isfile(join('../out', f))]
import subprocess

z = len(off)

for i in range(z):
	with open("/home/yn/log.txt", "a") as foo:
		c = a1+str(i)+a2+str(i)+a3
		foo.write('\n\n'+c+'\n')
		result = subprocess.check_output(c, shell=True)
		foo.write('-------------------------------------------------------------------------------------------\n')
		print i
		print "-------------------------------------------------------------------------------------------"
		foo.write(result+'\n')
		print result
