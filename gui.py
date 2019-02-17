#! /usr/bin/env python3

import os
import sqlite3


from flask import Flask, render_template, request, send_from_directory, redirect, flash

app = Flask(__name__)
app._static_folder = "static"
app.secret_key = 'very secure'.encode('utf-8')


global db_conn
db_conn = None
global db
db = None


@app.route('/')
def main():
    global db_conn
    global db
    if db_conn is None:
        db_conn = sqlite3.connect('dee-ns.db')
    if db is None:
        db = db_conn.cursor()

    db.execute("SELECT DomainName FROM \"config.Blacklist\"")
    bl_result = [i[0] for i in db.fetchall()]

    db.execute("SELECT DeviceID, FriendlyName, IPAddress FROM \"config.Devices\"")
    devs = db.fetchall()

    dev_lists = dict()

    for dev in devs:
        db.execute("SELECT DomainName FROM \"config.Whitelist\" WHERE Device = ?", (dev[0],))
        whites = set([i[0] for i in db.fetchall()])

        db.execute("SELECT Domain FROM Queuries WHERE Client = ? AND Fullfilled = 1", (dev[2],))
        full_reqs = set([i[0] for i in db.fetchall()])

        db.execute("SELECT Domain FROM Queuries WHERE Client = ? AND Fullfilled = 0", (dev[2],))
        blckd_reqs = set([i[0] for i in db.fetchall()])

        dev_lists[dev[0]] = (dev[1], dev[2], whites | full_reqs | blckd_reqs,  whites, full_reqs, blckd_reqs, dev[0])

    return render_template("index.html", blacklist=bl_result, dev = dev_lists)

@app.route("/add-blacklist", methods=['POST'])
def add_blacklist():
    if 'URL' in request.form:
        db.execute("INSERT OR IGNORE INTO 'config.Blacklist' (DomainName) VALUES (?)", (request.form['URL'],))
    return redirect("/")

@app.route("/remove-blacklist")
def remove_blacklist():
    if request.args.get("URL") is not None:
        db.execute("DELETE FROM \"config.Blacklist\" WHERE DomainName = ?", (request.args.get("URL"),))
    return redirect("/")

@app.route("/white_checked")
def white_checked():
    if request.args.get("id") is not None and request.args.get("checked") is not None:
        if request.args.get("checked") == "true":
            db.execute("INSERT OR IGNORE INTO \"config.Whitelist\" (DomainName, Device) VALUES (?, ?)", (request.args.get('id').split(' ')[1], request.args.get('id').split(" ")[0]))
        else:
            db.execute("DELETE FROM \"config.Whitelist\" WHERE DomainName = ? and Device = ?", (request.args.get('id').split(' ')[1], request.args.get('id').split(" ")[0]))
    return redirect("/")

@app.route('/static/js/<path:path>')
def send_js(path):
    return send_from_directory('static/js/', path)

@app.route('/static/css/<path:path>')
def send_css(path):
    return send_from_directory('static/css', path)

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404




if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=8080, debug = True)
    except (KeyboardInterrupt, SystemExit):
        pass
    except:
        raise
    finally:
        print("Goodbye")

        if db_conn is not None:
            db_conn.commit()
            db_conn.close()
