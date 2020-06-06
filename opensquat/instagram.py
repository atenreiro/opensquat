# -*- coding: utf-8 -*-
# Module: instagram.py
"""
openSquat

(c) CERT-MZ

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import json
import requests


class Instagram:
    """Class responsible for Instagram interactions

    To use:
        Instagram().main(user)

    Attribute:
        user: IG username

    Return:
        self.user: a json list containing information about the user
    """

    def __init__(self):
        self.user = None

    def check_user(self):

        r = requests.get(
            'https://www.instagram.com/web/search/topsearch/?query=' +

            self.user, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' +
                'AppleWebKit/537.36 (KHTML, like Gecko)' +
                'Chrome/74.0.3729.169 Safari/537.36'}
                ).text

        if json.loads(r).get("message") == 'rate limited':
            print(
                '[*] Instagram rate limited reached.' +
                'Try again in a few minutes.')
            return False

        try:
            for i in range(len(json.loads(r)['users'])):
    	        if json.loads(r)['users'][i]['user']['username'] == self.user:
                    return json.loads(r)['users'][i]['user']
        except:
            return False

    def set_user(self, user):
        self.user = user

    def main(self, user):
        self.set_user(user)
        return self.check_user()
# EOF
