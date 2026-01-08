# -*- coding: utf-8 -*-
# Module: feed_manager.py
"""
FeedManager module for openSquat.
Handles checking and downloading of domain feeds.
"""
import requests
import hashlib
import os
from colorama import Fore, Style
from opensquat import __VERSION__

class FeedManager:
    def __init__(self, url="https://feeds.opensquat.com/", backup_url="https://feeds-backup.opensquat.com/opensquat-nrd-free.txt"):
        self.url = url
        self.backup_url = backup_url
        self.url_file = "domain-names.txt"
        self.user_agent = "openSquat-" + __VERSION__

    def check_latest_feeds(self, local_filename):
        """
        Checks if the local feed file is up to date by comparing MD5 checksums.
        """
        url_md5 = self.url + self.url_file + ".md5"
        print("[*] Checking for the latest feeds...")
        
        headers = {'User-Agent': self.user_agent}

        try:
            response = requests.get(url_md5, headers=headers)
        except requests.exceptions.RequestException:
            return False

        if response.status_code != 200:
            return False

        latest_checksum = response.content.decode('utf-8').strip()
        response.close()

        if os.path.exists(local_filename):
            try:
                with open(local_filename, "rb") as f:
                    local_checksum = hashlib.md5(f.read()).hexdigest()

                if latest_checksum == local_checksum:
                    print("[*] You have the latest feeds\n")
                    return True
                else:
                    return False
            except Exception:
                return False
        return False

    def download(self, local_filename):
        """
        Downloads the latest registered domains.
        """
        download_url = self.url + self.url_file
        print("[*] Downloading fresh domain list:", self.url_file)

        headers = {'User-Agent': self.user_agent}
        try:
            response = requests.get(download_url, stream=True, headers=headers)
            
            # Fault tolerance
            if response.status_code in (403, 404):
                print(
                    Style.BRIGHT + Fore.RED + "[ERROR]", self.url_file, "not found," +
                    "trying the backup URL." + Style.RESET_ALL
                )
                download_url = self.backup_url
                print("[*] Downloading fresh domain list from backup URL", download_url)
                response = requests.get(download_url, stream=True, headers=headers)

            if response.status_code != 200:
                print(Style.BRIGHT + Fore.RED + f"[ERROR] Failed to download feeds (Status: {response.status_code})" + Style.RESET_ALL)
                exit(-1)

            # Get content size (handling chunked encoding where header might be missing)
            total_size = int(response.headers.get("content-length", 0))
            data = response.content
            
            if total_size == 0:
                total_size = len(data)

            total_size_mb = round(float(total_size / 1024 / 1024), 2)

            if total_size == 0:
                print(
                    Style.BRIGHT + Fore.RED + "[ERROR]", self.url_file, "not found or empty, " +
                    "Please notify the authors or try again later." + Style.RESET_ALL
                )
                exit(-1)

            print("[*] Download volume:", total_size_mb, "MB")

            with open(local_filename, "wb") as f:
                f.write(data)
            
            return True

        except Exception as e:
            print(Style.BRIGHT + Fore.RED + f"[ERROR] Exception during download: {e}" + Style.RESET_ALL)
            exit(-1)

    def ensure_feeds(self, local_filename):
        """
        Ensures that the feed file exists and is up to date.
        """
        if local_filename == "": # Should not happen if defaults are set correctly, but for safety
             local_filename = self.url_file
             
        # If user provided a custom path that is NOT the default/downloaded one, 
        # typically we assume they manage it, but here we cover the default logic.
        # The logic in app.py was: if domain_filename == "" (or default), check/download.
        # We will handle the check here.
        
        if not self.check_latest_feeds(local_filename):
            self.download(local_filename)
