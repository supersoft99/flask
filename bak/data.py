# importing the module
import json
 
# Opening JSON file
def loadFromJson():
  with open('data.json') as json_file:
    data = json.load(json_file)
 
    # Print the type of data variable
    print("Type:", type(data))
 
    # Print the data of dictionary
    print("\nSDE Users:", data['SDEUsers'])
    print("\nSDE IP Approver groups:", data['SDEApproverGroups']['IP'])
    print("\nSDE Non IP Approver groups:", data['SDEApproverGroups']['NonIP'])
