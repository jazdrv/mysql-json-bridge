#!/usr/bin/env python

#{{{
# Copyright 2012 Major Hayden
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#}}}

"""MySQL <-> JSON bridge"""

#libs {{{

import MySQLdb as dbapi
import datetime,decimal,json,logging,os,csv,yaml,urllib,sys
from urlparse import urlparse
from tornado.database import Connection
from flask import Flask, Response, abort, request
from cStringIO import StringIO

#libs }}}

app = Flask(__name__)
app.debug = True

def data_file(fname):
    """Helps us find non-python files installed by setuptools"""
    """Return the path to a data file of ours."""
    return os.path.join(os.path.split(__file__)[0], fname)
#yaml + logger  {{{

if not app.debug:
    logyaml = ""
    with open(data_file('config/log.yml'), 'r') as f:
        logyaml = yaml.load(f)
    try:
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        if logyaml['type'] == "file":
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                logyaml['logfile'], backupCount=logyaml['backupCount'])
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            app.logger.addHandler(file_handler)
        elif logyaml['type'] == 'syslog':
            from logging.handlers import SysLogHandler
            syslog_handler = SysLogHandler()
            syslog_handler.setLevel(logging.INFO)
            syslog_handler.setFormatter(formatter)
            app.logger.addHandler(syslog_handler)
    except:
        pass

#yaml + logger }}}

def jsonify(f):
    """Decorator to return JSON easily"""
    def inner(*args, **kwargs):
        jsonstring = json.dumps(f(*args, **kwargs), default=json_fixup)
        return Response(jsonstring, mimetype='application/json')
    return inner
    
def processMethod(f):
    """Decorator to return JSON or CSV easily"""
    def inner(*args, **kwargs):
        data = f(*args,**kwargs)
        method = data[0];
        results = data[1];
        if method=='csv':
            desc = data[2];
            old_stdout = sys.stdout
            sys.stdout = stdout = StringIO()
            #writer = csv.writer(sys.stdout,dialect='excel')
            writer = csv.writer(sys.stdout,quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow([i[0] for i in desc])
            for item in results:
                writer.writerow(item)
            sys.stdout = old_stdout
            response = stdout.getvalue()
            print response
            return Response(response, mimetype='text/csv')
        if method=='json':
            jsonstring = json.dumps(results, default=json_fixup)
            return Response(jsonstring, mimetype='application/json')
    return inner
    
def json_fixup(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    else:
        return None
def read_config():
    with open(data_file('config/databases.yml'), 'r') as f:
        databases = yaml.load(f)
    return databases
def get_db_creds(database):
    """Pull the database credentials from our YAML file"""

    databases = read_config()
    mysql_uri = databases.get(database)

    # If the database doesn't exist in the yaml, we're done
    if not mysql_uri:
        return False

    # Parse the URL in the .yml file
    try:
        o = urlparse(mysql_uri)
        creds = {
            'host':         o.hostname,
            'database':     o.path[1:],
            'user':         o.username,
            'password':     o.password,
        }
    except:
        creds = False

    return creds

# Handles the listing of available databases{{{
@app.route("/list", methods=['GET'])
def return_database_list():
    databases = read_config()
    data = {'databases': databases.keys()}
    return Response(json.dumps(data), mimetype='application/json')

#}}}
# This is what receives our SQL queries (json){{{

@app.route("/query/<database>", methods=['POST'])
@jsonify

def do_query(database=None):
    # Pick up the database credentials
    app.logger.warning("%s requesting access to %s database" % (
        request.remote_addr, database))
    creds = get_db_creds(database)

    # If we couldn't find corresponding credentials, throw a 404
    if creds == False:
        return {"ERROR": "Unable to find credentials matching %s." % database}
        abort(404)

    # Prepare the database connection
    app.logger.debug("Connecting to %s database (%s)" % (
        database, request.remote_addr))
    db = Connection(**creds)

    # See if we received a query
    sql = request.form.get('sql')
    if not sql:
        return {"ERROR": "SQL query missing from request."}

    # If the query has a percent sign, we need to excape it
    if '%' in sql:
        sql = sql.replace('%', '%%')

    # Attempt to run the query
    try:
        app.logger.info("%s attempting to run \" %s \" against %s database" % (
            request.remote_addr, sql, database))
        results = db.query(sql)
    except Exception, e:
        return {"ERROR": ": ".join(str(i) for i in e.args)}

    # Disconnect from the DB
    db.close()

    return {'result': results}

#}}}

# Alt query method (csv/json){{{

#@app.route("/query1/<database>/<sql>/<csv>", methods=['GET'])
@app.route("/<method>/<database>/<sql>", methods=['GET'])
@processMethod
def do_query1(method=None,database=None,sql=None):

    desc = None
    sql = sql.replace('+',' ')
    app.logger.info("aft.sql: %s" % sql)
    app.logger.warning("%s requesting access to %s database" % (
        request.remote_addr, database))
    creds = get_db_creds(database)
    if creds == False:
        return {"ERROR": "Unable to find credentials matching %s." % database}
        abort(404)
    app.logger.debug("Connecting to %s database (%s)" % (
        database, request.remote_addr))
    if '%' in sql:
        sql = sql.replace('%', '%%')

    if method=='json':
        try:
            app.logger.info("%s attempting to run \" %s \" against %s database" % (
                request.remote_addr, sql, database))
            db = Connection(**creds)
            results = db.query(sql)
            db.close()
        except Exception, e:
            results = {"ERROR": ": ".join(str(i) for i in e.args)}
        results = {'result': results}

    elif method=='csv':
        try:
            app.logger.info("%s attempting to run \" %s \" against %s database" % (
                request.remote_addr, sql, database))
            dbServer = creds['host']
            dbPass = creds['password']
            dbUser = creds['user']
            dbDB = creds['database']
            db = dbapi.connect(host=dbServer,user=dbUser,passwd=dbPass,db=dbDB)
            cur = db.cursor()
            cur.execute(sql)
            results = cur.fetchall()
            desc = cur.description
        except Exception, e:
            results = "ERROR: "+join(str(i) for i in e.args)
    else:
        sys.exit()

    return [method,results,desc]

#}}}

if __name__ == "__main__":
    app.run(host='0.0.0.0')

