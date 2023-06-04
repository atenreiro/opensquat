# -*- coding: utf-8 -*-
# Module: output.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import json
import csv
from datetime import date


class SaveFile:

    """
    The SaveFile is responsible for the file saving operations.

    To use:
        Domain().main(keywords, confidence, domains)

    Attribute:
        type: file type (txt, csv, json)
        today: today's date in the format yyyy-mm-dd
        filename: output file name
        content: file content to be saved
    """

    def __init__(self):
        self.type = None
        self.today = date.today().strftime("%Y-%m-%d")
        self.filename = None
        self.content = []

    def as_json(self):
        """
        save to json.

        Args:
            none

        Return
            none
        """
        with open(self.filename, "w") as f_json:
            json.dump(self.content, f_json)
        f_json.close()

    def as_csv(self):
        """
        save to csv.

        Args:
            none

        Return
            none
        """
        with open(self.filename, "w") as f_csv:
            file_csv = csv.writer(
                f_csv, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
            )
            file_csv.writerow(self.content)
        f_csv.close()

    def as_text(self):
        """
        save to plain text.

        Args:
            none

        Return
            none
        """
        with open(self.filename, "w") as f:
            for item in self.content:
                f.write(item + "\n")
        f.close()

    def set_content(self, file_content):
        self.content = file_content

    def set_filename(self, file_name):
        self.filename = file_name

    def set_filetype(self, file_type):
        self.type = file_type

    def main(self, file_name, file_type, file_content):
        """
        main function that will call other functions.

        Args:
            file_name: file name (duh)
            file_type: file type (txt, json or csv)
            file_content: file content to be saved

        Return:
            none
        """
        self.set_filename(file_name)
        self.set_filetype(file_type)
        self.set_content(file_content)

        if file_type == "json":
            self.as_json()
        elif file_type == "csv":
            self.as_csv()
        else:
            self.as_text()
