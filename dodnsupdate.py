#!/usr/bin/env python

import argparse
import ipgetter
import json
import os
import sys
import time


class DoDNSUpdater:
    def __init__(self, conf):
        """
        Initialise the updater object.
        :param conf: the file from which to read the conf
        :return:
        """

        self._config = conf
        self.mailer = None

        if not os.path.isfile(self._config):
            print prepare_output('Config file not found ({}).'.format(self._config))
            sys.exit(1)
        else:
            try:
                with open(self._config, 'r') as f:
                    j = json.load(f)
                self.token = j['token']
                self.domain = j['domain']
                self.rec_id = j['rec_id']
            except Exception as e:
                print prepare_output('Config Error: {}'.format(e))
                sys.exit(1)

        self.headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer '+self.token}
        self.api_url = 'https://api.digitalocean.com/v2/domains/{}/records/{}'.format(self.domain, self.rec_id)

        self.update_info = "{}/{}".format(self.domain, self.rec_id)

    def get_existing_ip(self):

        r = requests.get(self.api_url, headers=self.headers)
        if 'message' in r.json():
            print prepare_output(r.json()['message'])
            sys.exit(1)
        else:
            return r.json()['domain_record']['data']

    def set_new_ip(self, external_ip):

        data = {'data': external_ip}
        r = requests.put(self.api_url, data=json.dumps(data), headers=self.headers)
        if 'message' in r.json():
            print prepare_output(r.json()['message'])
            sys.exit(1)
        else:
            return r.json()['domain_record']['data']

    def update(self):

	external_ip = ipgetter.myip()

	if not external_ip:
		print prepare_output("Couldn't get external IP!")
		sys.exit(1)

        existing_ip = self.get_existing_ip()

        if external_ip == existing_ip:
            msg = 'IP is already up-to-date ({}).'.format(existing_ip)
        else:
            msg = 'IP changed from {} to {}.'.format(existing_ip, self.set_new_ip(external_ip))

        msg = self.update_info + ' ' + msg
        print prepare_output(msg)

def prepare_output(str, with_crlf=False):
    """
    Format the output string by prefixing timestamp and (optionally) adding a \n to the end.
    :param str: the text t
    :param with_crlf: Append a \n (or not)
    :return: the formatted string
    """
    s = '[{}] {}'.format(time.strftime('%Y-%m-%d %X'), str)
    return s+'\n' if with_crlf else s

if __name__ == '__main__':
    argp = argparse.ArgumentParser()
    argp.add_argument('conf', help='read config from this file')
    args = argp.parse_args()

    dns_updater = DoDNSUpdater(args.conf)
    dns_updater.update()
