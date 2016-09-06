import requests
import json
import urllib2
from pymongo import MongoClient
from ConfigParser import SafeConfigParser

config = SafeConfigParser()
config.read('settings.ini')

#Pull in config file values
try:
    #Server Config
    mongo_server = config.get('MongoConfig', 'mongo_server')
    mongo_port = config.getint('MongoConfig', 'mongo_port')
    mongodb = config.get('MongoConfig', 'mongodb')
    
    #VT Config
    vtkey_intel = config.get('VTConfig', 'vtkey_intel')
    vt_intel = config.getboolean('VTConfig', 'vt_intel')
    vtkey_mass = config.get('VTConfig', 'vtkey_mass')
    vt_mass = config.getboolean('VTConfig', 'vt_mass')
    vt_del = config.getboolean('VTConfig', 'vt_del')
     
except Exception as e:
    print "Error in Config File: " + str(e)

#Connect to Mongo
try:
    client = MongoClient(mongo_server, mongo_port)
    db = client[mongodb]
    sample_collection = db.samples
    stats_collection = db.stats
except Exception as e:
    print "Error: " + str(e)

    
def pull_vt_feed():
    # Pull VT Json feed
    url = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=" + vtkey_intel
    r = requests.get(url)
    thejson = r.json()
    count = 0
    
    try:
        for alert in thejson['notifications']:
            if(vt_feed_to_mongo(alert)):
                count +=1
        print "Processed Alerts: " + str(count)
    except Exception as e:
        print "Error: " + str(e)
    
def vt_feed_to_mongo(data):
    # Create stats on rulenames
    # Check if alert ID already exist

    id = data['id']
    sha1 = data['sha1']
    rulename = data['ruleset_name']
    
    # Duplicate check
    if sample_collection.find_one({"id" : id}):
        if vt_del == True:
            delete_vt_alert(id)
    else:
        # Process Stats
        if sample_collection.find_one({"ruleset_name" : rulename}):
            stats_collection.update({"rulename":rulename},{'$inc':{"count":1}})
        else:
            stats_collection.insert({"rulename":rulename, "count":1})
            
        sample_collection.insert(data)
        vt_mass_query(id,sha1)
        
        if vt_del == True:
            delete_vt_alert(id)
        return True
        
def delete_vt_alert(id):
    # Delete Alert from VT
    theID = [id]
    url = "https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key=" + vtkey_intel
    headers = {'Content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(theID), headers=headers)
    response = r.json()
    data = response
    if data['deleted'] != data['received']:
        print "Could not delete: " + str(id)
    else:
        print "Deleted Alert: " + str(id)
        
def vt_mass_query(id,hash):
    # Retrieve more VT data from Private API
    url = "https://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=" + vtkey_mass + "&resource=" + hash
    r = requests.get(url)
    thejson = r.json()
    
    if sample_collection.find_one({"id":id}):
        for key in thejson:
            try:
                if "\"." in thejson[key]:
                    print thejson[key] 
                    #theValue = thejson[key].replace("\".","\"_")
                else:
                    theValue = thejson[key]
                sample_collection.update({"id":id},{"$set":{key:theValue}},upsert=True)
            except Exception as e:
                pass
                print str(e)
                
    
pull_vt_feed()
#vt_mass_query(4943105168637952,"3446d7082d5dcbb62e2caaf9f684cc309931d2a0")