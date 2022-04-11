import pickle
from conf import config
from os.path import exists
import json
from util import createLogger



class MftDb:
  def __init__(self):
     self.logger = createLogger("db", "debug")
     self.logger.error("Init db")
     self.dbfile = config.get('Settings', 'dbfile')
     self.loadDb()

  def addApprover(self, approver):
      self.logger.error("approver ", approver)
      print(self.db)
      if approver not in self.db['SDEApprovers']:
         self.db['SDEApprovers'] += [approver]

  def getApprovers(self, user):
     l = ' '.join(i+'@nxp.com ' for i in self.db['SDEApprovers'] if i != user)
     print(l)
     return l
  def isSdeUser(self, user):
     return user in self.db['SDEUsers']

  def addUser(self, user):
    self.logger.info("user", user, "added")
    if user not in self.db['SDEUsers']:
       self.db['SDEUsers'] += [user]
       return
    print(user, "exists")

  def loadDb(self):
    try:
     with open(self.dbfile) as json_file:
       self.db = json.load(json_file)
       print(self.db)
    except:
         print("Unable to load ", self.dbfile)
         exit(0)
    self.showDb()

  def writeDb(self):
    with open(self.dbfile, 'w') as json_file:
     json.dump(self.db, json_file)

  def showDb(self):
    print("Users")
    print(self.db['SDEUsers'])
    print(self.db['SDEApprovers'])

if __name__ == "__main__":
  db = MftDb()
  db.addUser('sriram')
  db.addUser('sriram')
  db.addApprover('anton')
  db.addApprover('matt')
  db.addApprover('anton')
  db.addApprover('birk')
  db.showDb()
  print(db.isSdeUser('sriram'))
  print(db.getApprovers('anton'))
  db.writeDb()
