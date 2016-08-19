import requests
from pymongo import MongoClient

#VT Config
vtkey_intel = ""
vt_intel = True
vtkey_mass = ""
vt_mass = True

#Mongo Config
mongo_server = 'localhost'
mongo_port = 27017
mongodb = 'vt_test'

try:
    client = MongoClient(mongo_server, mongo_port)
    db = client[mongodb]
except Exception as e:
    print "Error: " + str(e)

def pull_vt_feed():
    url = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=" + vtkey_intel
    r = requests.get(url)
    thejson = r.json()
    count = 0
    
    try:
        for alert in thejson['notifications']:
            vt_feed_to_mongo(alert)
            count += 1
        return "Mongo Insert Successful: " + str(count)
    except Exception as e:
        print "Error inserting data into Mongo: " + str(e)
    
def vt_feed_to_mongo(data):
    sample_collection = db.samples
    stats_collection = db.stats
    id = data['id']
    rulename = data['ruleset_name']
    
    #duplicate check
    if sample_collection.find_one({"id" : id}):
        pass
    else:
        #stats
        if sample_collection.find_one({"ruleset_name" : rulename}):
            stats_collection.update({"rulename":rulename},{'$inc':{"count":1}})
        else:
            stats_collection.insert({"rulename":rulename, "count" : 1})
        sample_collection.insert(data)
        
def delete_vt_alert(id)

print pull_vt_feed()