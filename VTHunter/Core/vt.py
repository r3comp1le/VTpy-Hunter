import requests
import json
import importlib
import os
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


class VTHunter(object):

    def __init__(self):
        self.config = SafeConfigParser()
        self.config.read('settings.ini')
        import pdb
        pdb.set_trace()

        # Server Config
        mongo_server = self.config.get('MongoConfig', 'mongo_server')
        mongo_port = self.config.getint('MongoConfig', 'mongo_port')
        mongodb = self.config.get('MongoConfig', 'mongodb')

        # VT Config
        self.vtkey_intel = self.config.get('VTConfig', 'vtkey_intel')
        self.vt_intel = self.config.getboolean('VTConfig', 'vt_intel')
        self.vtkey_mass = self.config.get('VTConfig', 'vtkey_mass')
        self.vt_mass = self.config.getboolean('VTConfig', 'vt_mass')
        self.vt_del = self.config.getboolean('VTConfig', 'vt_del')

        # File download self.config
        self.vt_downloads = self.config.get('VTConfig',
                                            'file_download_directory')

        # Connect to Mongo
        try:
            self.client = MongoClient(mongo_server, mongo_port)
            self.db = self.client[mongodb]
            self.db.add_son_manipulator(KeyTransform(".", "_dot_"))
            self.sample_collection = self.db.samples
            self.stats_collection = self.db.stats
        except Exception as e:
            print("Error: " + str(e))

    def pull_vt_feed(self):
        # Pull VT Json feed
        url = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=" + self.vtkey_intel
        r = requests.get(url)
        thejson = r.json()
        count = 0

        try:
            for alert in thejson['notifications']:
                if(self.vt_feed_to_mongo(alert)):
                    count += 1
            print("Processed Alerts: " + str(count))
        except Exception as e:
            print("Error: " + str(e))

    def vt_feed_to_mongo(self, data):
        # Create stats on rulenames
        # Check if alert ID already exist

        id = data['id']
        sha1 = data['sha1']
        rulename = data['ruleset_name']

        # Duplicate check
        if self.sample_collection.find_one({"id" : id}):
            if self.vt_del:
                self.delete_vt_alert(id)
        else:
            # Process Stats
            if self.sample_collection.find_one({"ruleset_name" : rulename}):
                self.stats_collection.update({"rulename":rulename},{'$inc':{"count":1}})
            else:
                self.stats_collection.insert({"rulename":rulename, "count":1})

            self.sample_collection.insert(data)
            self.vt_mass_query(id, sha1)

            if self.vt_del:
                self.delete_vt_alert(id)
            return True

    def delete_vt_alert(self, id):
        # Delete Alert from VT
        theID = [id]
        url = "https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key=" + self.vtkey_intel
        headers = {'Content-type': 'application/json'}
        r = requests.post(url, data=json.dumps(theID), headers=headers)
        response = r.json()
        data = response
        if data['deleted'] != data['received']:
            print("Could not delete: " + str(id))
        else:
            print("Deleted Alert: " + str(id))

    def vt_mass_query(self, id, hash):
        # Retrieve more VT data from Private API
        url = "https://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=" + self.vtkey_intel + "&resource=" + hash
        r = requests.get(url)
        thejson = r.json()
        for k in thejson.keys():
            self.sample_collection.update(
                { "id" : id },
                { "$set" : { k : thejson[k] } },
                upsert=True,
                manipulate=True
            )

    def load_analysis_modules(self):
        '''
        loads all the analysis modules that are enabled in the
        self.configuration

        :returns: list
        '''
        analysis_modules = []
        for section in self.config:
            if "analysis_module_" in section:
                if not self.config.getboolean(section, "enabled"):
                    continue

                module_name = self.config.get(section, "module")
                try:
                    _module = importlib.import_module(module_name)
                except Exception as e:
                    print("Unable to import module {0}: {1}"
                          .format(module_name, str(e)))
                    continue

                class_name = self.config.get(section, "class")
                try:
                    module_class = getattr(_module, class_name)
                except Exception as e:
                    print("Unable to load module class {0}: {1}"
                          .format(module_class, str(e)))
                    continue

                try:
                    analysis_module = module_class(str(section))
                except Exception as e:
                    print("Unable to load analysis module {0}: {1}"
                          .format(section, str(e)))
                    continue

                analysis_modules.append(analysis_module)

        return analysis_modules

    def run_analysis(self, hash):
        '''
        Runs analysis modules on the given hash

        :param hash: The hash of the file to download and run.
        :type hash: str
        '''
        # Download the file first
        import pdb
        pdb.set_trace()
        dl_path = os.path.join(self.vt_downloads, hash)
        try:
            print('Downloading hash {}'.format(hash))
            params = {'hash': hash, 'apikey': self.vtkey_intel}
            r = requests.get('https://www.virustotal.com/vtapi/v2/file/download',
                             params=params)
            if r.status_code == 200:
                downloaded_file = r.content
                if len(downloaded_file) > 0:
                    # TODO: Could pull out the original filename from the
                    # VT data and save the filename as that.
                    fout = open(dl_path, 'wb')
                    fout.write(downloaded_file)
                    fout.close()
            else:
                print('Received status code {0} and message {1}'
                      .format(r.status_code, r.content))
                return False
        except Exception as e:
            print("Exception: {0}".format(e))
            return False

        modules = self.load_analysis_modules()
        for m in modules:
            m.analyze_sample(dl_path)



