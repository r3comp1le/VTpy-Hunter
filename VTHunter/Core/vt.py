import requests
import json
from pymongo import MongoClient
from pymongo.son_manipulator import SONManipulator
from configparser import SafeConfigParser

class KeyTransform(SONManipulator):
    """Transforms keys going to database and restores them coming out.

    This allows keys with dots in them to be used (but does break searching on
    them unless the find command also uses the transform).

    Example & test:
        # To allow `.` (dots) in keys
        import pymongo
        client = pymongo.MongoClient("mongodb://localhost")
        db = client['delete_me']
        db.add_son_manipulator(KeyTransform(".", "_dot_"))
        db['mycol'].remove()
        db['mycol'].update({'_id': 1}, {'127.0.0.1': 'localhost'}, upsert=True,
                           manipulate=True)
        print db['mycol'].find().next()
        print db['mycol'].find({'127_dot_0_dot_0_dot_1': 'localhost'}).next()

    Note: transformation could be easily extended to be more complex.
    """

    def __init__(self, replace, replacement):
        self.replace = replace
        self.replacement = replacement

    def transform_key(self, key):
        """Transform key for saving to database."""
        return key.replace(self.replace, self.replacement)

    def revert_key(self, key):
        """Restore transformed key returning from database."""
        return key.replace(self.replacement, self.replace)

    def transform_incoming(self, son, collection):
        """Recursively replace all keys that need transforming."""
        for (key, value) in son.items():
            if self.replace in key:
                if isinstance(value, dict):
                    son[self.transform_key(key)] = self.transform_incoming(
                        son.pop(key), collection)
                else:
                    son[self.transform_key(key)] = son.pop(key)
            elif isinstance(value, dict):  # recurse into sub-docs
                son[key] = self.transform_incoming(value, collection)
        return son

    def transform_outgoing(self, son, collection):
        """Recursively restore all transformed keys."""
        for (key, value) in son.items():
            if self.replacement in key:
                if isinstance(value, dict):
                    son[self.revert_key(key)] = self.transform_outgoing(
                        son.pop(key), collection)
                else:
                    son[self.revert_key(key)] = son.pop(key)
            elif isinstance(value, dict):  # recurse into sub-docs
                son[key] = self.transform_outgoing(value, collection)
        return son

config = SafeConfigParser()
config.read('settings.ini')

# Pull in config file values
try:
    # Server Config
    mongo_server = config.get('MongoConfig', 'mongo_server')
    mongo_port = config.getint('MongoConfig', 'mongo_port')
    mongodb = config.get('MongoConfig', 'mongodb')

    # VT Config
    vtkey_intel = config.get('VTConfig', 'vtkey_intel')
    vt_intel = config.getboolean('VTConfig', 'vt_intel')
    vtkey_mass = config.get('VTConfig', 'vtkey_mass')
    vt_mass = config.getboolean('VTConfig', 'vt_mass')
    vt_del = config.getboolean('VTConfig', 'vt_del')

except Exception as e:
    print("Error in Config File: " + str(e))

# Connect to Mongo
try:
    client = MongoClient(mongo_server, mongo_port)
    db = client[mongodb]
    db.add_son_manipulator(KeyTransform(".", "_dot_"))
    sample_collection = db.samples
    stats_collection = db.stats
except Exception as e:
    print("Error: " + str(e))


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
        print("Processed Alerts: " + str(count))
    except Exception as e:
        print("Error: " + str(e))

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
        print("Could not delete: " + str(id))
    else:
        print("Deleted Alert: " + str(id))

def sanitize_json_for_mongo(j):
    if len(j.keys()) == 0:
        return j

def vt_mass_query(id,hash):
    # Retrieve more VT data from Private API
    url = "https://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=" + vtkey_mass + "&resource=" + hash
    r = requests.get(url)
    thejson = r.json()
    for k in thejson.keys():
        sample_collection.update(
            { "id" : id },
            { "$set" : { k : thejson[k] } },
            upsert=True,
            manipulate=True
        )

#pull_vt_feed()
vt_mass_query(5850533070503936, "19a6e53ab4f20f52e52b25b3d4f1d8e10355e1e4dc672f23b4215462525c7adc")
