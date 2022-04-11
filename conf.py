import configparser
import sys
import os
config = configparser.ConfigParser()
try:
     config.read('icom.conf')
except:
     logger.error("configuration file \'icom.conf\' missing")
     exit(0) 
for sect in config.sections():
      for k,v in config.items(sect):
        if('location') in k:
          print(k,v)
          try:
           os.mkdir(v, 0o755)
          except:
           pass

if __name__ == "__main__":
 from util import createLogger
  
 initialize(logger)
 for sect in config.sections():
   print('Section:', sect)
   for k,v in config.items(sect):
      print(' {} = {}'.format(k,v))
   print(config.get('Settings', 'icomServer'))
