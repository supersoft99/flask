# logging_example.py
import logging
import os
from conf import config
import re

logPath = config.get('Settings', 'logLocation')
logExtn = config.get('Settings', 'logSuffix')
print(logPath, logExtn)
# Create a custom logger
def createLogger(name, level= 'info'):
  print("create logger", level, name)
  logfile= (logPath + name + logExtn)
  logger = logging.getLogger(logPath + name)

  print(__name__, name, level, logfile)
  
  # Create handlers
  c_handler = logging.StreamHandler()
  f_handler = logging.FileHandler(logfile)
  if level == 'info':
     c_handler.setLevel(logging.INFO)
     f_handler.setLevel(logging.INFO)
  if level == 'warning':
     c_handler.setLevel(logging.WARN)
     f_handler.setLevel(logging.WARN)
  else:
     f_handler.setLevel(logging.DEBUG)
     c_handler.setLevel(logging.DEBUG)

  # Create formatters and add it to handlers
  c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
  f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  c_handler.setFormatter(c_format)
  f_handler.setFormatter(f_format)

  # Add handlers to the logger
  logger.addHandler(c_handler)
  logger.addHandler(f_handler)
  if os.path.exists(logfile):
    print("log file exists, appending")
  #  return logger
  return logger 

# Make a regular expression for validating an Email
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Define a function for
# for validating an Email
def validateEmail(email):

	# pass the regular expression
	# and the string into the fullmatch() method
	if not re.fullmatch(regex, email):
		print("Invalid Email", email)
		return False

	return True 

# Driver Code
if __name__ == '__main__':

	# Enter the email
	email = "ankitrai326@gmail.com"

	# calling run function
	validateEmail(email)

	email = "my.ownsite@our-earth.org"
	validateEmail(email)

	email = "ankitrai326.com"
	validateEmail(email)

	logger = createLogger("test", "debug")
	logger.warn("test warn")
	logger.info("test inf")
	logger.debug("test deb")
