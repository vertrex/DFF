#!/usr/bin/python
import sys, os, subprocess

from time import time
from datetime import timedelta, datetime

class Stats():
  def __init__(self):
    self.__totalDumps = 0
    self.__doneProcessing = [] 
    self.__failProcessing = []
    self.startTime = time()

  def setTotalDumps(self, total):
    self.__totalDumps = total

  def doneProcessing(self, dumpPath):
    self.__doneProcessing.append(dumpPath)

  def failProcessing(self, dumpPath):
    self.__failProcessing.append(dumpPath)

  def totalTime(self):
   return  str(timedelta(seconds=time() - self.startTime))

  def generate(self):
    stats = "Results:\n"
    stats += "Parsed : " + str(self.__totalDumps) + " dumps in " + self.totalTime() + "\n"
    stats += "Ok : " + str(len(self.__doneProcessing)) + "\n"
    stats += "Failed : " + str(len(self.__failProcessing))  + "\n"
    for dump in self.__failProcessing:
       stats += "\t " + dump + "\n"
    return stats

class AutoReport():
  def __init__(self):
    self.stats = Stats()

  def walk(self, path):
    dumpsPath = []
    for root, dirs, files in os.walk(path, topdown=False):
      for name in files:
        dumpsPath.append((root, name,))
    return dumpsPath

  def filterDirectory(self, pathList):
    filteredList = []
    extension = ['.raw', ".dd"]#, '.e01', '.aff', '.bin']
    dontWalk = ["appz", "arx", "builders", "carver_crash", "goinfre"]
    for pathName in pathList:
      path, name = pathName
      if path in dontWalk:
        continue
      if name.rfind('.'):
        nameExt = name[name.rfind('.'):]
      for ext in extension:
        if nameExt.capitalize() == ext.capitalize():
          filteredList.append((path, name, nameExt, ))
          break
    return filteredList

  def createLogFile(self, logfile):
    self.logFile = open(logfile, 'w')

  def log(self, msg):
    print msg
    self.logFile.write(msg + "\n") #FLUSH ?

  def mkdir(self, directory):
    try:
      os.mkdir(directory)
    except: 
      pass

  def execExtractor(self, pathList, extractionDirectory):
    extractionDirectory += datetime.now().strftime("%Y-%m-%d %H:%M") + "/"
    self.mkdir(extractionDirectory) 
    self.createLogFile(extractionDirectory + "dff-auto-report.log")
    msg = datetime.now().strftime("%Y-%m-%d %H:%M") + "\n"
    msg += 'Runing on ' + str(sys.argv[1]) + ' ' + str(sys.argv[2])
    self.log(msg)

    totalTimeStart = time()
    current = 1
    msg = 'Will run on ' +  str(len(pathList)) + ' dumps :'
    self.stats.setTotalDumps(len(pathList))
    self.log(msg)
    for pathName in pathList:
      path, name, ext = pathName
      msg = "\t" + str(os.path.join(path, name))
      self.log(msg)

    for pathName in pathList:
      timeStart = time()
      path, name, ext = pathName
      #os.mkdir(extractionDirectory + '/' + dumpName) 
      nameWoExt = name[:len(name) - len(ext)]
      lastDir = path[path.rfind('/') + 1:]
      extDir = lastDir + '_' + nameWoExt
      extDir = extDir.replace('.', '_')
      extDir = extDir.replace(' ', '_')
      extDir = extractionDirectory + '/' + extDir
       
      dumpPath = os.path.join(path, name)

      self.mkdir(extDir)
      stdoutLog = open(extDir + "/dff-auto-report-stdout.stdoutLog", 'w')
      stderrLog = open(extDir + "/dff-auto-report-stdout.stderrLog", 'w')
      msg = 'Launching : "./dff-report ' + dumpPath + ' ' + extDir + '" (' + str(current) + '/' + str(len(pathList)) + ')'
      self.log(msg)
      ret = subprocess.call(['./dff-report.py', dumpPath, extDir], stdout=stdoutLog, stderr=stderrLog)
      if ret == 42:
        self.stats.doneProcessing(dumpPath)  #add time for each in stats ?
        msg =  '[OK] duration : ' +  str(timedelta(seconds=time() - timeStart)) 
        self.log(msg)
      else:
        self.stats.failProcessing(dumpPath) #add time for each in stats ? 
        msg =  '[FAIL] duration : ' +  str(timedelta(seconds=time() - timeStart)) 
        self.log(msg)
      current += 1
      stdoutLog.close()
      stderrLog.close()
      
    self.log(self.stats.generate())
    self.logFile.close()

if len(sys.argv) == 3:
  print 'Walking on', sys.argv[1], " extracting report to : ", sys.argv[2]  
  autoReport = AutoReport() 
  dumpsPath = autoReport.walk(sys.argv[1])
  filteredList = autoReport.filterDirectory(dumpsPath)
  autoReport.execExtractor(filteredList, sys.argv[2]) 
else:
  print 'dff-auto-report dumps_root_directory report_extraction_directory'

#calcul du temps
#kill if temps depasser (comte pas ds les stats)

#stats

#info machine/os 
#usage de la ram possible ? par dump / giga/noeud ?

#nombre de dump parser  "
#extraction successful / extraction failed ( crash , temps limit depasser

#temps total
#temps moyen par dump
#temps moyen par giga
#temps moyen par noeud
#passage des module en commande line a dff-report.py ?
