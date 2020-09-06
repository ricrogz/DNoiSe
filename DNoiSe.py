#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import os
import random
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

import dns.resolver
import pandas
import requests
import yaml

CONFIG_FILE = "config.yml"
DEFAULT_CONFIG = {
    # Set working directory - any generated files will be stored here.
    "work_dir": os.getcwd(),
    # IPs / host names whose queries are to be ignored when analyzing
    # traffic patterns
    "excluded_hosts": ["127.0.0.1", "localhost"],
    # IP / host of the pi-hole instance. "127.0.0.1" is valid only when running
    # on the same host as pi-hole.
    "pihole_admin_url": "http://127.0.0.1/admin",
    "log_file": "dnoise.log",
    "domains_file": "domains.sqlite",
    # Log every fake DNS query. Very slow, DO NOT USE in production.
    "debugging": False
}
TOP_DOMAINS_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/" \
  "top-1m.csv.zip"
PIHOLE_API_URL_FMT = "{}/api.php?getAllQueries&from={}&until={}&auth={}"

LOG_INTERVAL = 300
QUERY_INTERVAL = 60


def get_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f)
    else:
        logging.error(f"Configuration file {CONFIG_FILE} not found, aborting.")
        exit(1)

    # Check for the required pi-hole encoded admin password.
    # This cam be copied over from /etc/pihole/setupVars.conf
    if "auth_token" not in cfg:
        logging.error(f"Configuration file {CONFIG_FILE} does not contain the "
                      "required 'auth_token' element, aboring.")
        exit(1)

    # Set default values for anything not in the config file
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v

    cfg["excluded_hosts"] = set(cfg["excluded_hosts"])

    return cfg


def wait_for_connection():
    # A simple loop that makes sure we have an Internet connection: it can take
    # a while for pi-hole to get up and running after a reboot.
    while True:
        try:
            urllib.request.urlopen("http://example.com")
            logging.info("Got network connection.")
            return
        except urllib.error.URLError:
            logging.info("Network not up yet, retrying in 10 seconds.")
            time.sleep(10)


def download_domains(cfg):
    # Download the top 1M domain list if we don't have it yet.
    domains_file = os.path.join(cfg["work_dir"], cfg["domains_file"])
    local_top_file = os.path.join(cfg["work_dir"], "top-1m.csv.zip")

    # Download the Cisco Umbrella list. More info:
    # https://s3-us-west-1.amazonaws.com/umbrella-static/index.html
    try:
        logging.info("Downloading the domains file")
        urllib.request.urlretrieve(TOP_DOMAINS_URL, local_top_file)
    except Exception:
        logging.error("Failed downloading the domains file. Quitting.")
        exit(1)

    # Create a SQLite database and import the domain list
    logging.info(f"Creating domains database {domains_file}")
    with sqlite3.connect(domains_file) as db:
        try:
            db.execute("CREATE TABLE Domains (ID INT PRIMARY KEY,"
                       " Domain TEXT)")
            df = pandas.read_csv(local_top_file,
                                 compression='zip',
                                 names=["ID", "Domain"])
            df.to_sql("Domains", db, if_exists="append", index=False)

            os.remove(local_top_file)
        except Exception:
            logging.error("Failed importing domains. Quitting.")
            exit(1)

    # Running this on 1st gen Raspberry Pi can take up to 10 minutes.
    # Be patient.
    logging.info("Domains database successfully created.")


def format_time(timestamp):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def get_pihole_queries(cfg, start, end):
    # This will give us a list of all DNS queries that pi-hole handled in
    # the past 5 minutes.
    while True:
        try:
            all_queries = requests.get(
                PIHOLE_API_URL_FMT.format(cfg["pihole_ip"], start, end,
                                          cfg["auth_token"]))
            break
        except Exception:
            logging.warn("API request failed. Retrying in 15 seconds.")
            time.sleep(15)

    return json.loads(all_queries.text)


def filter_queries(cfg, all_queries):
    """
    When determining the rate of DNS queries on the network, we don't want
    our past fake queries to skew the statistics, therefore we filter out
    queries made by this machine.
    We want the types of our fake queries (A/AAA/PTR/…) to proportionally
    match those of the real traffic.
    """
    query_types = []
    try:
        for a in all_queries["data"]:
            if a[3] not in cfg["excluded_hosts"]:
                query_types.append(a[1])
    except Exception:
        logging.error("Got badly formatted pi-hole API response, quitting.")
        exit(1)

    # Default to A request if pi-hole logs are empty
    if len(query_types) == 0:
        query_types.append("A")

    return query_types


def get_random_domain(domains_file):
    # Pick a random domain from the top 1M list
    rand = str(random.randint(1, 1000000))
    with sqlite3.connect(domains_file) as db:
        cursor = db.cursor()
        cursor.execute(f"SELECT Domain FROM Domains WHERE ID={rand}")
        return cursor.fetchone()[0]


def main():
    cfg = get_config()
    logfile = os.path.join(cfg["work_dir"], cfg["log_file"])
    log_level = logging.DEBUG if cfg["debugging"] else logging.INFO
    logging.basicConfig(format='%(asctime)s -- %(message)s',
                        filename=logfile,
                        filemode='w',
                        level=log_level)

    domains_file = os.path.join(cfg["work_dir"], cfg["domains_file"])
    if not os.path.isfile(domains_file):
        logging.info("Domains file not found, downloading domains")
        download_domains(cfg)

    wait_for_connection()

    while True:
        """
        We want the fake queries to blend in with the organic traffic expected
        at each given time of the day, so instead of having a static delay
        between individual queries, we'll sample the network activity over
        the past 5 minutes and base the frequency on that. We want to add
        roughly 10% of additional activity in fake queries.
        """
        time_until = int(time.time())
        time_from = time_until - LOG_INTERVAL

        all_queries = get_pihole_queries(cfg, time_from, time_until)
        query_types = filter_queries(cfg, all_queries)

        total_queries = len(all_queries["data"])
        valid_queries = len(query_types)
        interval = float(LOG_INTERVAL) / valid_queries

        logging.debug(
            f"In the interval from {format_time(time_from)} until "
            f"{format_time(time_until)}, there was on average 1 request "
            f"every {interval:0.2f} s. Total queries: {total_queries}, of "
            f"which {total_queries - valid_queries} are local queries "
            "(excluded).")

        # We want to re-sample our "queries per last 5 min" rate
        # every minute.
        time_until += QUERY_INTERVAL
        interval *= 10
        while time.time() < time_until:
            domain = get_random_domain(domains_file)

            logging.debug(f"Querying {domain}")

            try:
                dns.resolver.query(domain, random.choice(query_types))
            except Exception:
                logging.debug(f"Query failed, running another query")
                continue

            # Since we want to add only about 10% of extra DNS queries, we
            # multiply the wait time by 10, then add a small random delay.
            time.sleep(interval + random.uniform(0, 2))


if __name__ == '__main__':
    main()
