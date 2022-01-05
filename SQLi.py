import threading

import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
flag = False

# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page
    is SQL Injection vulnerable from its `response`"""

    # Bypassing the URL to check the vulnerable
    RightPass = ["correct", "welcome", "admin", "logged in", "successfully"]
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "check the manual that (corresponds to|fits) your MySQL server version",
        "MySqlException",

        # SQL Server
        "unclosed quotation mark after the character string",
        "SQLServer JDBC Driver",

        # Oracle
        "quoted string not properly terminated",
        "Oracle error",
        "SQL command not properly ended",
        "OracleException",

        # PostgreSQL
        "valid PostgreSQL result",
        "PostgreSQL query failed",
        "PSQLException",

        # Microsoft SQL Server
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "Unclosed quotation mark after the character string",

        # Microsoft Access
        "JET Database Engine",
        "Access Database Engine",
        "ODBC Microsoft Access",

        # IBM DB2
        "DB2 SQL error",
        "DB2Exception",

        # Informix
        "Informix ODBC Driver",
        "ODBC Informix driver",
        "IfxException",

        # Firebird
        "Dynamic SQL Error",

        # SQLite
        "sqlite3.OperationalError:",
        "SQLiteException",

        # SAP MaxDB
        "DriverSapDB",

        # Sybase
        "Sybase message",
        "SybSQLException",

        # Ingres
        "Ingres SQLSTATE",

        # FrontBase
        "Syntax error 1. Missing",}

    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    for right in RightPass:
        # Return True if one of the RightPass is found in the content
        if right in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url, file):

    payloads = open(file, "r+")
    lines = payloads.readlines()
    fix = []
    for i in lines:
        i = i.replace("\n", "")
        fix.append(i)
    # for every payload inject URL
    for i in fix:

        new_url = f"{url}{i}"
        # print(f"[!] Trying{new_url}")
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceede for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            break


    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in fix:
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)

            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", "payload = " + c)
                print("[+] Form:")
                print(form_details)
                break


if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    # Try it !
    # http://testphp.vulnweb.com/artists.php?artist=1


    print("SQLi is an open-source tool used in penetration testing to detect and exploit SQL injection flaws.\nSQLi automates the process of detecting and exploiting SQL injection.\nSQL Injection attacks can take control of databases that utilize SQL.\nThey can affect any website or web app that may have a SQL database linked to it, such as MySQL, SQL Server, Oracle and many others.\n")

    # divide payload into files to minimize running time
    files = ["payload2.txt", "payload1.txt", "payload3.txt", "payload4.txt"]
    myTh = []
    # divide work to 4 thread to speed up the excution time
    for i in range(4):
        th = threading.Thread(name=f"Thread {i}", target=scan_sql_injection, args=(url, files[i]))
        th.start()
        myTh.append(th)

    for i in myTh:
        if i.is_alive():
            i.join()
        else:
            pass
