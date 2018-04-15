import sqlite3
import os

class DATA():
    def CHEK_ARP_DATA_IN_TABLE(host_ip, host_mac):
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""SELECT Host_ip FROM ARP_data_host_ids WHERE Host_ip="%s" and Host_mac="%s";""" % (host_ip, host_mac))
        if cur.fetchall() == []:
            return False
        else:
            return True

    def INSERT_ARP_DATA(host_ip, host_mac):
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""INSERT INTO ARP_data_host_ids VALUES(NULL,"%s","%s");""" % (host_ip, host_mac))
        con.commit()

    def GET_ALL_DATA_ARP_HOST():
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""SELECT * FROM ARP_data_host_ids;""")
        return cur.fetchall()

    def GET_ALL_DATA_SIGNAL():
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""SELECT * FROM static_value_all_signal;""")
        return cur.fetchall()

    def GET_ALL_DATA():
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""SELECT * FROM static_value_all;""")
        return cur.fetchall()

    def CREATE():
            try:
                os.system("rm static_data_serv.db")  # clear data base

                con = sqlite3.connect("static_data_serv.db")
                cur = con.cursor()
                cur.execute("""CREATE TABLE static_value_all(id INTEGER PRIMARY KEY AUTOINCREMENT,
                										Warning_id INT,
                										Value INT);""")
                cur.execute("""CREATE TABLE static_value_all_signal(id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                        IP_host CHAR,
                                										Warning_id INT,
                                										Value CHAR);""")
                cur.execute("""CREATE TABLE ARP_data_host_ids(id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                                                Host_ip CHAR,
                                                                Host_mac CHAR);""")

                for index_warning in range(100,131):
                    cur.execute("""INSERT INTO static_value_all VALUES(NULL,"%i","%i");""" % (index_warning, 0))
                    con.commit()
                return True
            except:
                return False

    def INSERT_DATA_VALUE_SIGNAL(warning_id,host,data_print_on_display):
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""INSERT INTO static_value_all_signal VALUES(NULL,"%s","%i","%s");""" % (host,warning_id,data_print_on_display ))
        con.commit()

    def UPDATE_DATA_VALUE_STATIC(warning_id):
        con = sqlite3.connect("static_data_serv.db")
        cur = con.cursor()
        cur.execute("""UPDATE static_value_all SET Value = Value + 1 WHERE Warning_id = {0};""".format(warning_id))
        con.commit()