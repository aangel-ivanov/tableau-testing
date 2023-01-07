#!/usr/bin/env python

import os
import re
import sys
import time
import json

import hashlib
import collections
import logging
import unittest
import requests

import tableaudocumentapi as TDA
import tableauserverclient as TSC


class TableauSiteUserInfo:

    tableauserver = None
    siteexception = None

    valid = False
    datadict = {}

    def __init__(self, in_site_name="", in_site_luid="",
                 in_site_url="", in_user_name="", in_user_luid="", in_auth_token="", in_server=None):

        self.datadict["site_name"] = in_site_name
        self.datadict["site_luid"] = in_site_luid
        self.datadict["site_url"] = in_site_url
        self.datadict["user_name"] = in_user_name
        self.datadict["user_luid"] = in_user_luid
        self.datadict["auth_token"] = in_auth_token
        self.tableauserver = in_server
        self.valid = in_site_name and in_site_luid and in_user_name and in_user_luid\
            and in_auth_token and in_server is not None


def hide_pass(s):

    if s is not None and s != "":

        m = hashlib.sha256()
        m.update(s.encode("utf-8"))
        r = m.digest()

    else:

        return ""

    return str(r[0]) + str(r[1]) + str(r[2])


def check_is_https(url_server):

    is_https = False
    tserver = url_server.lower()
    if tserver.startswith(r"https://"):
        is_https = True
        tserver = tserver[8:]
    elif tserver.startswith(r"http://"):
        tserver = tserver[7:]

    return is_https, tserver


def get_site_url(sitename):

    if (sitename is not None and sitename == "Default"):
        return ""

    return sitename.lower()


def get_myhostname():

    hserver = socket.gethostname().lower()
    if hserver.endswith(r'.tsi.lan'):
        hserver = hserver[:-8]
    elif hserver.endswith(r'.internal.salesforce.com'):
        hserver = hserver[:-24]
    elif hserver.endswith(r'.salesforce.com'):
        hserver = hserver[:-15]

    return hserver


def get_myservername(server):

    myserver = server
    if server.endswith(r'/'):
        myserver = server[:len(server) - 1]

    _, tserver = check_is_https(myserver)
    if tserver.endswith(r'.tsi.lan'):
        tserver = tserver[:-8]
    elif tserver.endswith(r'.internal.salesforce.com'):
        tserver = tserver[:-24]
    elif tserver.endswith(r'.salesforce.com'):
        tserver = tserver[:-15]

    tserver = get_myhostname() if (
        tserver == r'localhost' or tserver == r'default') else tserver

    return tserver


def get_tableauserver_version(protocol, tserver, site_url, print_info=False):

    server_name = f"{protocol}://{tserver}"
    build_num = "near.0.0000.0000"
    server_ver = 0
    build_int = 0

    try:

        server = TSC.Server(
            server_name,
            use_server_version=True,
            http_options={"verify": False}
        )

        server_info = server.server_info.get()
        build_num = server_info.build_number

    except Exception as e:

        if "Invalid version: 'Unknown'" == str(e):
            pass
        elif "got an unexpected keyword argument 'http_options'" not in str(e):
            logging.error(
                f"!FAILED:: get tableauserver_version failed because of exception '{e}'\n")

    def represents_int(s):

        try:
            rc = int(s)
            return rc
        except ValueError:
            return 0

    re_match = re.search(r"(.+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", build_num)
    server_ver = represents_int(re_match.group(1))
    build_int = represents_int(
        re_match.group(2) +
        re_match.group(3) +
        re_match.group(4)
    )

    if print_info:
        print(build_num)
        logging.debug(
            f"Server version {server_ver}, build number {build_num} ({build_int})")
    else:
        logging.info(
            f"Server version {server_ver}, build number {build_num} ({build_int})")

    return server_ver, build_num


def sign_in_server_rest(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name
):

    site_url = get_site_url(site_name)

    if token_tableauvalue is None:

        tableau_auth = TSC.TableauAuth(
            username_tableau,
            password_tableau,
            site_url
        )

        logging.info(f"Attempting to signin with username:: {server_name}/#/site/{site_url}/home")
        logging.debug(
            "Signin TableauAuth {}::{} as user {} token_tableauname={},{}".
            format(server_name, site_name, username_tableau,
                   token_tableauname, hide_pass(token_tableauvalue)))

    else:

        tableau_auth = TSC.PersonalAccessTokenAuth(
            token_tableauname,
            token_tableauvalue,
            site_url
        )

        logging.info(f"Attempting to signin with usertoken:: {server_name}/#/site/{site_url}/home")
        logging.debug(
            "REST Sign in PersonalAccessTokenAuth({}) {}::{} as {}, {}".
            format(username_tableau, server_name, site_name,
                   token_tableauname, hide_pass(token_tableauvalue)))

    server = TSC.Server(
        server_name,
        use_server_version=True,
        http_options={"verify": False}
    )

    rc = TableauSiteUserInfo()

    try:

        server.auth.sign_in(tableau_auth)

    except Exception as e:

        rc.valid = False
        rc.siteexception = e
        logging.info(f"!FAILED to sign in due to exception: '{e}'\n")
        return rc

    rc = TableauSiteUserInfo(
        site_name,
        server.site_id,
        site_url,
        username_tableau,
        server.user_id if server is not None and server.user_id is not None else "default",
        server.auth_token,
        server
    )

    logging.debug(
        f"Request login stats::\n\n{json.dumps(rc.datadict, indent=4, sort_keys=True)}\n")

    return rc


def get_xsrf_token(session):

    xsrf_token = ""

    try:

        cookies = session.cookies.get_dict(
        ) if session is not None and session.cookies is not None else None
        xsrf_token = cookies["XSRF-TOKEN"] if cookies is not None and "XSRF-TOKEN" in cookies else ""

    except KeyError as k:
        logging.debug(f"KeyError:: {k}", exc_info=True)
        pass
    except BaseException as e:
        logging.debug(e, exc_info=True)
        pass
    except Exception as e:
        logging.debug(e, exc_info=True)
        pass

    return xsrf_token


def get_workgroup_sessionid(session):

    workgroup_session_id = ""

    try:

        cookies = session.cookies.get_dict(
        ) if session is not None and session.cookies is not None else None
        workgroup_session_id = cookies["workgroup_session_id"]\
            if cookies is not None and "workgroup_session_id" in cookies else ""

    except KeyError as k:
        logging.debug(f"KeyError:: {k}", exc_info=True)
        pass
    except BaseException as e:
        logging.debug(e, exc_info=True)
        pass
    except Exception as e:
        logging.debug(e, exc_info=True)
        pass

    return workgroup_session_id


def get_hid_cookie(session):

    hid_cookie = ""

    try:

        cookies = session.cookies.get_dict() \
            if session is not None and session.cookies is not None else None

        hid_cookie = cookies["hid"] if cookies is not None and "hid" in cookies else ""

    except KeyError as k:
        logging.info(f"KeyError:: {k}", exc_info=True)
        pass
    except BaseException as e:
        logging.info(e, exc_info=True)
        pass
    except Exception as e:
        logging.info(e, exc_info=True)
        pass

    return hid_cookie


def get_vizql_sessionid(http_result):

    vizql_session_id = None

    vizql_session_id = http_result.headers["X-Session-Id"]\
        if http_result.ok and http_result.headers is not None and "X-Session-Id"\
        in http_result.headers else None

    return vizql_session_id


def prepare_headers_withtoken(session, include_content_type="", info=None):

    xsrf_token = get_xsrf_token(session)
    workgroup_session_id = get_workgroup_sessionid(session)

    if (workgroup_session_id is None or workgroup_session_id == ""):
        if (info is not None or info.datadict is not None and "auth_token" in info.datadict):
            workgroup_session_id = info.datadict["auth_token"]

    if include_content_type == "":

        headers = {
            "Accept": "application/xml,application/json,text/javascript,text/plain,*/*",
            "Connection": "Keep-Alive",
            "X-XSRF-TOKEN": xsrf_token
        }

    else:

        headers = {
            "Accept": "application/xml,application/json,text/javascript,text/plain,*/*",
            "Content-Type": include_content_type,
            "Connection": "Keep-Alive",
            "X-XSRF-TOKEN": xsrf_token
        }

    return headers


def prepare_headers_simpleview(session, info):

    xsrf_token = get_xsrf_token(session)
    if (xsrf_token is None or xsrf_token == ""):
        if (info is not None or info.datadict is not None and "auth_token" in info.datadict):
            xsrf_token = info.datadict["auth_token"]

    workgroup_session_id = get_workgroup_sessionid(session)
    if (workgroup_session_id is None or workgroup_session_id == ""):
        if (info is not None or info.datadict is not None and "auth_token" in info.datadict):
            workgroup_session_id = info.datadict["auth_token"]

    cookie = "XSRF-TOKEN=abcxyz; workgroup_session_id=" + workgroup_session_id
    headers = {
        "Accept": "application/xml,application/json,text/javascript,text/plain,*/*",
        "Connection": "Keep-Alive",

        "X-XSRF-TOKEN": "abcxyz",
        "Cookie": cookie
    }

    return headers


def prepare_cookies(session):

    hid_cookie = get_hid_cookie(session)

    cookies = {}
    if hid_cookie:
        cookies = {
            'hid': hid_cookie
        }

    return cookies


class VizportalClientAPI:

    def __init__(self, protocol, host, site_name, site_url,
                 username_tableau, password_tableau, personal_tokenname, personal_tokenvalue):

        self.protocol = protocol
        self.host = host
        self.servername = f"{self.protocol}://{self.host}"
        self.site_name = site_name
        self.site_url = site_url
        self.use_site = site_url is not None and site_url != "" and site_url != "default"
        self.vcuser = username_tableau
        self.vcpassword = password_tableau
        self.vctoken_name = personal_tokenname
        self.vctoken_value = personal_tokenvalue
        self.real_dsid = None
        self.vizql_session = None
        self.vizport_session = None
        self.tableauserver = None
        self.info = None

        import rsa
        import binascii

    def create_session(self, request_rest_session=True, log_error=True):

        if request_rest_session or self.vctoken_value is not None:
            if log_error:
                logging.debug(
                    "VizportalClient API session using token '{}://{}','{}'::'{}'".
                    format(self.protocol, self.host, self.site_name, self.vctoken_name))

            return self.create_session_restapi(log_error)

        if log_error:
            logging.debug(
                "VizportalClient API session '{}://{}'::'{}', using username '{}'".
                format(self.protocol, self.host, self.site_name, self.vcuser))

        return self.create_session_vizportalapi()

    def create_session_restapi(self, log_error=True):

        logging.debug(
            "Session restapi '{}://{}','{}'::token (name, value)=('{}','{}')".
            format(self.protocol, self.host, self.site_name, self.vctoken_name, self.vctoken_value))

        rc = sign_in_server_rest(
            self.servername,
            self.vcuser,
            self.vcpassword,
            self.vctoken_name,
            self.vctoken_value,
            self.site_name
        )

        self.info = rc if rc is not None else None
        self.tableauserver = rc.tableauserver if rc is not None else None
        self.vizport_session = rc.tableauserver._session if rc.tableauserver is not None else None

        return self.vizport_session

    def create_session_vizportalapi(self, log_error=True):

        if log_error:
            logging.debug("Session vizportalapi '{}://{}','{}'::('{}','{}')".
                          format(self.protocol, self.host, self.site_name,
                                 self.vctoken_name, self.vctoken_value))

        http_res = None

        class RSACipher:

            def __init__(self, raw_pubkey):

                try:

                    result = raw_pubkey.json()["result"]
                    key_id = result["keyId"]
                    key = result["key"]

                except KeyError as err:

                    exc_t, _, exc_tb = sys.exc_info()
                    response_error = "RSA Cipher:: '{}' not in '{}'".format(
                        err.message, json_response(raw_pubkey)
                    )

                    raise exc_t(response_error).with_traceback(exc_tb)

                self.key, self.key_id = (
                    rsa.PublicKey(int(key["n"], base=16),
                                  int(key["e"], base=16)),
                    key_id
                )

            def encrypt(self, raw_msg):
                byte_string = rsa.encrypt(
                    str(raw_msg).encode("ascii"), self.key)
                ciphertext = binascii.hexlify(byte_string).decode("ascii")
                return ciphertext, self.key_id

            def decrypt(self, enc_msg):
                raise "Not implemented"

        try:

            self.vizport_session = requests.Session()

            http_res = self.vizport_session.post(
                "{protocol}://{host}/vizportal/api/web/v1/generatePublicKey".format(
                    protocol=self.protocol, host=self.host),
                data=r'{ "method": "generatePublicKey", "params":{} }',
                verify=False
            )

            if http_res.status_code == 200:

                cipher = RSACipher(http_res)
                ciphertext, key_id = cipher.encrypt(self.vcpassword)

                login_url = "{protocol}://{host}/vizportal/api/web/v1/login".format(
                    protocol=self.protocol, host=self.host)

                params = (
                    r'{ "username": "'
                    + self.vcuser
                    + '", "encryptedPassword": "'
                    + ciphertext
                    + r'", "keyId": "'
                    + key_id
                    + r'"}'
                )

                body = r'{"method": "login", "params": ' + params + r" }"

                logging.debug("login url={}, headers={}, body={}".format(
                    login_url, "", body))

                http_res = self.vizport_session.post(login_url, data=body)

            if http_res.status_code == 200 and self.use_site:

                switch_site_url = "{protocol}://{host}/vizportal/api/web/v1/switchSite".format(
                    protocol=self.protocol, host=self.host)

                body = (
                    r'{"method": "switchSite", "params": { "urlName": "'
                    + self.site_url
                    + '" }}'
                )

                headers = prepare_headers_withtoken(self.vizport_session)

                http_res = self.vizport_session.post(
                    switch_site_url, headers=headers, data=body)

                if http_res.status_code != 200:

                    raise Exception("switch_site_url={}, status_code={}".format(
                        switch_site_url, http_res.status_code
                    )
                    )

                logging.debug("SUCCESS:: create_session:: switch_site_url={}, status_code={}\n".format(
                    switch_site_url, http_res.status_code)
                )

        except Exception as e:

            logging.error(
                "!FAILED:: create_session:: exception: '{0}'\n".format(e))

        return self.vizport_session

    def sanitize(self, workbook, dashboard, worksheet=""):

        workbook_clean = workbook.replace('"', "")
        workbook_clean = workbook_clean.replace(" ", "")

        dashboard_clean = dashboard.replace('"', "")
        dashboard_clean = dashboard_clean.replace(" ", "")

        worksheet_clean = worksheet.replace('"', "")
        worksheet_clean = worksheet_clean.replace(" ", "")

        return (workbook_clean, dashboard_clean, worksheet_clean)

    def openviz_in_viewmode_simple(
            self,
            workbook,
            dashboard,
            worksheet
    ):

        http_res = None
        vizql_session_id = None
        workbook_clean, dashboard_clean, worksheet_clean = self.sanitize(
            workbook, dashboard if dashboard else worksheet, worksheet
        )

        try:

            if not self.use_site:
                openviz_url = "{p}://{h}/views/{w}/{d}?:embed=y".format(
                    p=self.protocol,
                    h=self.host,
                    w=workbook_clean,
                    d=dashboard_clean,
                )
            else:
                openviz_url = "{p}://{h}/t/{s}/views/{w}/{d}?:embed=y".format(
                    p=self.protocol,
                    s=self.site_url,
                    h=self.host,
                    w=workbook_clean,
                    d=dashboard_clean
                )

            headers = prepare_headers_simpleview(
                self.vizport_session, self.info)

            cookies = prepare_cookies(self.vizport_session)

            http_res = requests.get(
                openviz_url,
                headers=headers,
                cookies=cookies,
                timeout=60
            )

            logging.info(f"GET {openviz_url} returned {http_res.status_code}")

            headers = prepare_headers_simpleview(
                self.vizport_session, self.info)

            vizql_session_id = get_vizql_sessionid(http_res)

            bootstrap_url = "{p}://{h}/vizql/w/{w}/v/{d}/bootstrapSession/sessions/{sid}?sheet_id={ssh}"\
                .format(p=self.protocol, h=self.host, w=workbook_clean, d=dashboard_clean,
                        sid=vizql_session_id if vizql_session_id else None, ssh=dashboard)

            cookies = prepare_cookies(self.vizport_session)

            data = {
                "worksheetPortSize": '{"w":156,"h":732}',
                "dashboardPortSize": '{"w":331,"h":800}',
                "renderMapsClientSide": "true",
                "isBrowserRendering": "true",
                "browserRenderingThreshold": "100",
                "formatDataValueLocally": "false",
                "clientNum": "",
                "navType": "Nav",
                "navSrc": "Top",
                "devicePixelRatio": "1",
                "clientRenderPixelLimit": "25000000",
                "sheet_id": dashboard,
                "showParams": '{ "checkpoint": false, "refresh": false, "refreshUnmodified": false }',
                "filterTileSize": "200",
                "locale": "en_US",
                "language": "en",
                "verboseMode": "false",
                "session_feature_flags": "{}",
                "keychain_version": "2"
            }

            http_res = requests.post(
                bootstrap_url,
                headers=headers,
                cookies=cookies,
                data=data
            )

            logging.info(
                f"POST {bootstrap_url} [{len(http_res.text)}] returned {http_res.status_code}\n")

            if not http_res.ok or len(http_res.text) < 100:

                if http_res.ok:
                    logging.info(f"http_res.text={http_res.text}\n")

                raise Exception(
                    "bootstrap={}, headers={}, cookies={}, vizql={}, status={}".format(
                        bootstrap_url, headers, cookies, vizql_session_id, http_res.status_code))

            logging.info(
                f"SUCCESS:: SIMPLE_VIEW {self.site_url}, {workbook}, {dashboard}")

        except Exception as e:

            logging.error(
                f"!FAILED:: openviz in_viewmode_simple (2):: exception: '{e}'")

        self.vizql_session = 0 if vizql_session_id is None else vizql_session_id

    def logoff(self):

        logout_url = "{protocol}://{host}/vizportal/api/clientxml/auth/logout?format=xml&language=en"\
                     .format(protocol=self.protocol, host=self.host)
        logging.debug("logout_url={}, headers={}".format(logout_url, ""))

        self.vizport_session.get(logout_url)


class TestAPI(unittest.TestCase):

    def __init__(
        self,
        testname,
        protocol,
        host,
        site_name,
        site_url,
        username,
        password,
        personal_tokenname,
        personal_tokenvalue,
        configdir,
        verifyrecoutput,
        query_params,
        server_version,
        printstats,
        abortOnError,
        workbook="",
        dashboard="",
        worksheet=""
    ):

        super(TestAPI, self).__init__(testname)
        self.protocol = protocol
        self.host = host
        self.site_name = site_name
        self.site_url = site_url
        self.username = username
        self.password = password
        self.personal_tokenname = personal_tokenname
        self.personal_tokenvalue = personal_tokenvalue
        self.configdir = configdir
        self.verifyrecoutput = verifyrecoutput
        self.query_params = query_params
        self.server_version = server_version
        self.printstats = printstats
        self.abortOnError = abortOnError
        self.workbook = workbook
        self.dashboard = dashboard
        self.worksheet = worksheet

        self.vizportal_api = VizportalClientAPI(
            self.protocol,
            self.host,
            self.site_name,
            self.site_url,
            self.username,
            self.password,
            self.personal_tokenname,
            self.personal_tokenvalue
        )

    def test_view_simple(self):

        status_createsession = self.test_vizportal_logon()
        if status_createsession == False:
            if self.abortOnError:
                self.assertEqual(status_createsession, True)
            else:
                return

        vizportal_api = self.vizportal_api
        vizportal_api.openviz_in_viewmode_simple(
            self.workbook, self.dashboard, self.worksheet)
        self.test_vizportal_logoff()

    def test_vizportal_logon(self, request_rest_session=True):

        self.vizport_session = None
        return self.vizportal_api.create_session(
            request_rest_session=request_rest_session, log_error=True)

    def test_vizportal_logoff(self):

        if self.vizport_session is not None:
            self.vizportal_api.logoff()
            self.vizport_session = None


def tableau_exists_workbook(server, workbook):

    local_paths = []
    all_workbooks, pagination_item = server.workbooks.get()

    req_option = TSC.RequestOptions()
    req_option.filter.add(
        TSC.Filter(
            TSC.RequestOptions.Field.Name,
            TSC.RequestOptions.Operator.Equals,
            workbook
        )
    )

    found_workbook, pagination_item = server.workbooks.get(req_option)

    logging.info(
        f"there are {pagination_item.total_available} workbooks on site '{workbook}'")

    return len(found_workbook) > 0


def make_writeable(root_dir):

    try:

        for root, dirs, files in os.walk(root_dir):
            for fname in files:
                full_path = os.path.join(root, fname)
                os.chmod(full_path, stat.S_IWRITE | stat.S_IRUSR)

    except:
        pass


def get_activedirectory_users():
    return\
        [
            r'tsi.lan\atao',
            r'tsi.lan\iivanov',
            r'tsi.lan\nstefanovic'
        ]


def file_is_workbook(filename):
    return filename.endswith("twb") or filename.endswith("twbx")


def file_is_datasource(filename):
    return filename.endswith("tds") or filename.endswith("tdsx")


def get_filename_from_path(file_path):
    return os.path.splitext(os.path.basename(file_path))[0]


def tableau_update_conninfo(connection, files_to_update):
    if len(files_to_update) == 0:
        return

    logging.info("")
    logging.info("")
    logging.info(
        "--------------------- UPDATE LOCAL CONNECTIONS ------------------------")
    logging.info(
        "-----------------------------------------------------------------------")

    for file_to_update in files_to_update:
        datasources = []
        logging.info(
            "-- Updating Connection Info of {}".format(file_to_update))

        datasources.append(TDA.Datasource.from_file(file_to_update))
        logging.info("-- Info for Datasource: {0}".format(file_to_update))

        for datasource in datasources:
            for conn in datasource.connections:
                for attr in connection:
                    if connection[attr] != "":
                        setattr(conn, attr, connection[attr])

            if file_is_datasource(file_to_update):
                passwd = ""
                if len(datasource.connections) > 0:
                    passwd = (
                        datasource.connections[0].password
                        if hasattr(datasource.connections[0], "password")
                        else ""
                    )

                datasource.save()

                srv = datasource.connections[0].server if len(
                    datasource.connections) > 0 else "None"
                dbn = datasource.connections[0].dbname if len(
                    datasource.connections) > 0 else "None"
                usr = datasource.connections[0].username if len(
                    datasource.connections) > 0 else "None"

                logging.info(
                  f"   {datasource.name}|{datasource.version}|{srv},{dbn},{usr},{hide_pass(passwd)}")

        logging.info(
            "----------------------------------------------------------")


def tableau_publish_datasources(
    server,
    connection,
    files_to_publish,
    project,
    append_conn_to_name=False,
    update_conninfo=True
):
    rc = True
    if len(files_to_publish) == 0:
        return rc

    logging.info("")
    logging.info("")
    logging.info(
        "----------------------- UPLOAD DATASOURCES ----------------------------")

    if project is None:
        raise LookupError("No project could be found to upload datasources to")

    failed_datasources = []

    ds_item = TSC.DatasourceItem(project.id)
    conn_credentials = None

    if append_conn_to_name and "dbclass" in connection:

        ds_item.name += "-" + connection["dbclass"]

    if update_conninfo:

        passwd = (connection["password"] if "password" in connection else "")
        conn_credentials = TSC.ConnectionCredentials(
            connection["username"], passwd, embed=True)
        logging.debug(
            f"datasources.publish connection '{conn_credentials.name},{hide_pass(passwd)}'")

    for file_to_publish in files_to_publish:
        logging.info(
            "-----------------------------------------------------------------------")

        try:
            ds_item.name = get_filename_from_path(file_to_publish)

            time.sleep(5)
            logging.info(f"datasources.publish '{file_to_publish}'")

            if update_conninfo:

                new_datasrc = server.datasources.publish(
                    ds_item,
                    file_to_publish,
                    TSC.Server.PublishMode.Overwrite,
                    conn_credentials
                )

            else:

                new_datasrc = server.datasources.publish(
                    ds_item,
                    file_to_publish,
                    TSC.Server.PublishMode.Overwrite
                )

            logging.info(
                f"SUCCESS:: datasources.publish '{new_datasrc.name},{new_datasrc.id}'")

        except Exception as e:

            logging.info(
                f"!FAILED:: datasources.publish '{ds_item.name}' because of exception '{e}'\n")
            failed_datasources.append(file_to_publish)

    logging.debug("Delaying 3 sec, so that the datasoure show up fully...")
    time.sleep(5)

    if len(failed_datasources) > 0:
        logging.info("")
        logging.info("")
        logging.info(
            "-------------------------- FAILED DATASOURCES --------------------------------")
        logging.info([get_filename_from_path(fp) for fp in failed_datasources])
        logging.info("")

    more_failed = collections.deque(failed_datasources)
    max_attempts = 1 * len(more_failed)
    num_attempts = 0

    while more_failed and num_attempts < max_attempts:

        failed_to_publish = more_failed.pop()
        num_attempts += 1
        time.sleep(5)

        logging.info(
            f"ATTEMPT {num_attempts}:: datasource.publish '{failed_to_publish}'")

        try:
            ds_item.name = get_filename_from_path(failed_to_publish)

            if update_conninfo:
                new_datasource = server.datasources.publish(
                    ds_item,
                    failed_to_publish,
                    TSC.Server.PublishMode.Overwrite,
                    conn_credentials
                )

            else:

                new_datasource = server.datasources.publish(
                    ds_item,
                    failed_to_publish,
                    TSC.Server.PublishMode.Overwrite,
                )

            logging.info(
                f"SUCCESS:: datasources.publish '{new_datasource.name},{new_datasource.id}'")

        except Exception as e:

            logging.info(
                f"!FAILED:: datasources.publish '{ds_item.name}' because of exception '{e}'\n")
            more_failed.appendleft(failed_to_publish)

    if len(more_failed) > 0:
        logging.info("")
        logging.info("")
        logging.info(
            "----------------------- FAILED AFTER RETRIES DATASOURCES -----------------------------")
        logging.info([get_filename_from_path(fp) for fp in more_failed])
        logging.info("")
        rc = False

    logging.debug("Delaying 5 sec, so that the datasoure show up fully...")
    time.sleep(5)

    return rc


def tableau_publish_workbooks(
    server,
    connection,
    files_to_publish,
    project,
    append_conn_to_name=False,
    update_conninfo=True
):

    rc = True
    if len(files_to_publish) == 0:
        return rc

    logging.info("")
    logging.info("")
    logging.info(
        "----------------------- UPLOAD WORKBOOKS ----------------------------")

    if project is None:
        raise LookupError("No project could be found to upload workbooks to")

    failed_workbooks = []

    wb_item = TSC.WorkbookItem(project.id)

    if append_conn_to_name and "dbclass" in connection:
        wb_item.name += "-" + connection["dbclass"]

    if update_conninfo:

        passwd = (connection["password"] if "password" in connection else "")
        connection_creds = TSC.ConnectionCredentials(
            connection["username"], passwd, embed=True)

        logging.debug(
            f"Workbooks.publish connection '{connection_creds.name},{connection_creds.password}'")

    for file_to_publish in files_to_publish:
        logging.info(
            "---------------------------------------------------------------------")

        try:

            wb_item.name = get_filename_from_path(file_to_publish)

            time.sleep(5)
            logging.info(f"Workbooks.publish '{file_to_publish}'")

            new_workbook = server.workbooks.publish(
                wb_item,
                file_to_publish,
                TSC.Server.PublishMode.Overwrite
            )

            logging.info(
                f"SUCCESS:: workbooks.publish '{new_workbook.name},{new_workbook.id}'")

        except Exception as e:

            logging.info(
                f"!FAILED:: workbooks.publish '{wb_item.name}' because of exception '{e}'\n")

    if len(failed_workbooks) > 0:
        logging.info("")
        logging.info("")
        logging.info(
            "-------------------------- FAILED WORKBOOKS --------------------------------")
        logging.info([get_filename_from_path(fp) for fp in failed_workbooks])
        logging.info("")

    more_failed = collections.deque(failed_workbooks)
    max_attempts = 1 * len(more_failed)
    num_attempts = 0

    while more_failed and num_attempts < max_attempts:

        failed_to_publish = more_failed.pop()
        num_attempts += 1
        time.sleep(5)

        logging.info(
            f"ATTEMPT {num_attempts}:: workbooks.publish '{failed_to_publish}'")

        try:
            wb_item.name = get_filename_from_path(failed_to_publish)

            if update_conninfo:

                new_workbook = server.workbooks.publish(
                    wb_item,
                    failed_to_publish,
                    TSC.Server.PublishMode.Overwrite,
                    connection_creds
                )

            else:

                new_workbook = server.workbooks.publish(
                    wb_item,
                    failed_to_publish,
                    TSC.Server.PublishMode.Overwrite
                )

            logging.info(
                f"SUCCESS:: workbooks.publish '{new_workbook.name},{new_workbook.id}'")

        except Exception as e:

            logging.info(
                f"!FAILED:: workbooks.publish '{wb_item.name}' because of exception '{e}'\n")

    if len(more_failed) > 0:
        logging.info("")
        logging.info("")
        logging.info(
            "----------------------- FAILED AFTER RETRIES WORKBOOKS -----------------------------")
        logging.info([get_filename_from_path(fp) for fp in more_failed])
        logging.info("")
        rc = False

    logging.debug("Delaying 5 sec, so that the workbooks show up fully...")
    time.sleep(5)

    return rc


def create_site(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name
):
    logging.debug(
        f"Creating site {site_name}:: ({server_name}, {username_tableau})")

    if get_site_url(site_name) == "":
        return ""

    token_name = token_tableauname
    token_value = token_tableauvalue

    if token_value is None:

        tableau_auth = TSC.TableauAuth(
            username_tableau, password_tableau
        )

        logging.info(
            "Create Site with TableauAuth {}::{} as user {} token_tableauname={}".
            format(server_name, site_name, username_tableau, token_tableauname))

    else:

        tableau_auth = TSC.PersonalAccessTokenAuth(
            token_name, token_value
        )

        logging.info(
            "Create Site with PersonalAccessTokenAuth {}::{} as user {} token_name={}".
            format(server_name, site_name, username_tableau, token_name))

    server = TSC.Server(
        server_name,
        use_server_version=True,
        http_options={"verify": False}
    )

    try:

        server.auth.sign_in(tableau_auth)

    except Exception as e:
        if "got an unexpected keyword argument 'http_options'" not in str(e):
            logging.info(
                f"!FAILED:: create site sign in to '{server_name}' because of exception '{e}'\n")

    rec_site = None
    errmsg = ""

    try:

        content_users = TSC.SiteItem.AdminMode.ContentAndUsers
        new_site = TSC.SiteItem(
            name=site_name,
            content_url=site_name.lower(),
            admin_mode=content_users,
            user_quota=30,
            storage_quota=1000,
            disable_subscriptions=True
        )
        rec_site = server.sites.create(new_site)

    except Exception as e:
        errmsg = str(e)

    if rec_site is not None and not errmsg:
        site_id = rec_site.id
        site_name = rec_site.name
        site_url = rec_site.content_url
        site_ste = rec_site.state
        logging.info(
            f"SUCCESS:: created site:: {site_id}, {site_name}, {site_url}, {site_ste}")
    else:
        logging.info(
            f"!FAILED:: could not create site '{site_name}' because of exception '{errmsg}'\n")
        return ""

    site_url = rec_site.content_url if rec_site is not None and rec_site.content_url else ""

    if token_value is None:
        tableau_auth_site = TSC.TableauAuth(
            username_tableau,
            password_tableau,
            rec_site.name)

        logging.info(
            "Create site signin TableauAuth {}::{} as user {} token_tableauname={}".
            format(server_name, site_name, username_tableau, token_tableauname))

    else:

        tableau_auth_site = TSC.PersonalAccessTokenAuth(
            token_name,
            token_value,
            rec_site.name)

        logging.info(
            "Sign in {} PersonalAccessTokenAuth {}::{} as user {} token_name={}".
            format(username_tableau, server_name, site_name, username_tableau, token_value))

    server = TSC.Server(
        server_name,
        use_server_version=True,
        http_options={"verify": False}
    )

    try:

        server.auth.sign_in(tableau_auth_site)

    except Exception as e:
        if "got an unexpected keyword argument 'http_options'" not in str(e):
            logging.info(
                f"!FAILED:: create site sign in to '{server_name}' because of exception '{e}'\n")

    allusers = get_activedirectory_users()
    for user in allusers:

        try:
            newU = TSC.UserItem(user, 'SiteAdministrator')
            newU = server.users.add(newU)
            logging.info(
                f"Add user to site {rec_site.name}:: ({newU.name}, {newU.site_role})")

        except Exception as e:
            logging.info(
                f"!FAILED:: to add {user} to site {rec_site.name} because of exception '{e}'")

    return site_url


def delete_site(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name
):
    logging.debug(
        f"To delete site '{server_name}'::('{username_tableau}','{site_name}')")

    if get_site_url(site_name) == "":
        return ""

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        logging.info(
            f"!FAILED:: remove site '{server_name}' because of exception '{rc.siteexception}'\n")
        return

    server = rc.tableauserver

    try:

        server.sites.delete(server.sites.get_by_name(site_name).id)
        errmsg = ""

    except Exception as e:

        errmsg = str(e)

    if not errmsg:
        logging.info(f"SUCCESS:: deleted site: '{site_name}'")
    else:
        logging.info(
            f"!FAILED:: to delete site '{site_name}' exception '{errmsg}'. Site likely doen't exist")


def verify_logon(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name
):

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        print(
            "!FAILED:: verify logon ({}, {}, {}) with exception {}".
            format(server_name, username_tableau, site_name, rc.siteexception))
        set_recutility_exitcode(499)

    print(json.dumps(rc.datadict, indent=4, sort_keys=True))
    print(
        f"SUCCESS:: verify logon ({server_name},{username_tableau},hide_pass(password_tableau))")

    return True


def exists_site(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name
):

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        err = f"!FAILED:: sign in '{server_name}','{site_name}', exception '{rc.siteexception}'."
        logging.debug(err + " Site likely doesn't exist\n")
        set_recutility_exitcode(122)

    logging.info(
        f"EXISTS: site:: '{rc.datadict['site_name']}' with id '{rc.datadict['site_luid']}'")
    sys.stdout.write("True\n")

    return True


def create_project(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name,
    site_content_url,
    project_name
):

    logging.debug(
        "Creating project '{}' on site '{}':: ({}, {}, {})".
        format(project_name, site_name, server_name, username_tableau, token_tableauname))

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        logging.info(
            f"!FAILED:: create project '{server_name}' with exception {rc.siteexception}")
        return

    server = rc.tableauserver
    project = None

    try:

        request_options = TSC.RequestOptions()
        request_options.filter.add(TSC.Filter(TSC.RequestOptions.Field.Name,
                                              TSC.RequestOptions.Operator.Equals,
                                              project_name)
                                   )

        all_project_items = list(TSC.Pager(server.projects, request_options))
        logging.debug(f"all_project_items = {all_project_items}")

        for proj in all_project_items:
            logging.debug(f"proj.name = {proj.name}")

            if proj.name == project_name:
                project = proj
                logging.debug(f"FOUND proj.name = {proj.name}")
                break

    except Exception as e:
        logging.info(
            f"!FAILED:: create project auth.sign in '{server_name}' exception '{e}'\n")
        project = None

    if project is not None:
        logging.info(
            f"EXISTS: create project:: project '{project_name}' id '{project.id}' already exists")
        return

    logging.debug("Creating project: {}".format(project_name))

    if project_name == "Default":
        raise LookupError("The default project could not be created")

    try:

        project_item = TSC.ProjectItem(name=project_name)
        project_item.content_permissions = "ManagedByOwner"

        project = server.projects.create(project_item)
        time.sleep(10)

    except Exception as e:
        errmsg = str(e)

    if project is not None:
        logging.info(
            f"SUCCESS:: created project '{project_name}', with id '{project.id}'")
    else:
        logging.info(
            r"!FAILED:: to create '{project_name}' because of exception '{errmsg}'\n")


def delete_project(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name,
    site_content_url,
    project_name
):

    logging.debug(
        f"Deleting '{project_name}' on '{site_name}':: ({server_name}, {username_tableau})")

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        logging.info(
            f"!FAILED:: delete project '{server_name}' with exception {rc.siteexception}")
        return

    server = rc.tableauserver

    project = None

    try:
        all_project_items, pagination_item = server.projects.get()
        for proj in all_project_items:
            if proj.name.lower() == project_name.lower():
                project = proj
                break

        if project is None:

            logging.info(
                f"DOES NOT EXIST: delete project:: '{project_name}' doesn't exist")
            return

    except Exception as e:

        project = None

    if project_name == "Default":
        raise LookupError("The default project could not be deleted")

    rid = project.id

    try:

        project_item = TSC.ProjectItem(name=project.name)
        project_item.content_permissions = "ManagedByOwner"

        project = server.projects.delete(project.id)
        errmsg = ""
        time.sleep(5)

    except Exception as e:
        errmsg = str(e)

    if not errmsg:
        logging.info(
            f"SUCCESS:: deleted project: '{project_name}' with id '{rid}'")
    else:
        logging.info(
            f"!FAILED:: to delete project '{project_name}' because of exception '{errmsg}'\n")


def exists_project(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name,
    site_content_url,
    project_name
):

    logging.debug(
        f"Verifying '{project_name}' on '{site_name}':: ({server_name}, {username_tableau})")

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:
        logging.debug(
            f"!FAILED:: exists project '{server_name}' with exception {rc.siteexception}")
        return False

    server = rc.tableauserver
    project = None

    try:
        request_options = TSC.RequestOptions()
        request_options.filter.add(TSC.Filter(TSC.RequestOptions.Field.Name,
                                              TSC.RequestOptions.Operator.Equals,
                                              project_name)
                                   )

        all_project_items = list(TSC.Pager(server.projects, request_options))
        logging.debug(f"all_project_items = {all_project_items}")

        for proj in all_project_items:
            logging.debug(f"proj.name = {proj.name}")

            if proj.name == project_name:
                project = proj
                logging.debug(f"FOUND proj.name = {proj.name}")
                break

    except Exception as e:

        logging.info(f"!FAILED to find project because of '{e}'\n")
        project = None

    if project is None:
        logging.info(
            f"DOES NOT EXIST: project:: '{project_name}' doesn't exist")
        sys.stdout.write("False\n")
        set_recutility_exitcode(123)
        return False

    logging.info(f"EXISTS: project:: '{project.name}' with id '{project.id}'")
    sys.stdout.write("True\n")

    return True


def upload_content(
    server_name,
    username_tableau,
    password_tableau,
    token_tableauname,
    token_tableauvalue,
    site_name,
    site_content_url,
    contentdir,
    connection,
    test_content_loaded_file,
    project_name,
    append_conn_to_name=False,
    update_conninfo=True,
    force_createproject=True
):

    res = True

    rc = sign_in_server_rest(
        server_name,
        username_tableau,
        password_tableau,
        token_tableauname,
        token_tableauvalue,
        site_name
    )

    if not rc.valid or rc.tableauserver is None:

        logging.info(
            f"!FAILED:: Project {project_name} doesn't exist. Exception '{rc.siteexception}'")
        return res

    server = rc.tableauserver

    site_contentdir = contentdir
    site_url = site_content_url
    project_name = project_name
    con_dir = contentdir
    con_info = update_conninfo

    logging.info(
      f"Uploading '{project_name}'::('{server_name}','{site_url}','{con_dir}',{con_info})")

    is_content_loaded = False

    if test_content_loaded_file is not None:
        is_content_loaded = tableau_exists_workbook(
            server, test_content_loaded_file
        )

    if is_content_loaded:

        logging.debug(
            "Upload content:: Content already uploaded. Skipping upload.")
        return res

    make_writeable(contentdir)
    twbs2upload = []
    tdss2upload = []

    try:
        for file in os.listdir(contentdir):
            if file_is_workbook(file):
                twbs2upload.append(os.path.join(contentdir, file))
            elif file_is_datasource(file):
                tdss2upload.append(os.path.join(contentdir, file))
    except:
        pass

    if update_conninfo:
        tableau_update_conninfo(connection, tdss2upload)

    project = None

    try:

        request_options = TSC.RequestOptions()
        request_options.filter.add(TSC.Filter(TSC.RequestOptions.Field.Name,
                                              TSC.RequestOptions.Operator.Equals,
                                              project_name)
                                   )

        all_project_items = list(TSC.Pager(server.projects, request_options))
        logging.debug(f"all_project_items = {all_project_items}")

        for proj in all_project_items:
            logging.debug(f"proj.name = {proj.name}")

            if proj.name == project_name:
                project = proj
                logging.debug(f"FOUND proj.name = {proj.name}")
                break

    except Exception as e:
        logging.info(f"!FAILED to find project because of '{e}'\n")
        project = None

    if project is not None:

        res = tableau_publish_datasources(
            server,
            connection,
            tdss2upload,
            project,
            append_conn_to_name,
            update_conninfo
        )

        if res:
            res = tableau_publish_workbooks(
                server,
                connection,
                twbs2upload,
                project,
                append_conn_to_name,
                update_conninfo
            )
    else:

        logging.info(
            f"Upload content:: Project {project_name} doesn't exist. Skipping upload.")

    return res


def get_filename_base(filename):
    spath, sfile = os.path.split(filename)
    fbase, fext = os.path.splitext(sfile)
    return fbase


def get_thisshortname():
    return get_filename_base(__file__)


def setup_logging(args, parent=False):

    import datetime as mydt

    if args.debug:
        logging.basicConfig(
            format="%(levelname)8s %(process)s [%(asctime)s %(filename)s:%(lineno)d]\t%(message)s",
            datefmt="%H:%M:%S",
            level=logging.DEBUG
        )
    else:
        logging.basicConfig(
            format="%(levelname)8s %(process)s [%(asctime)s]\t%(message)s",
            level=logging.INFO
        )
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO
        )
        logging.getLogger().setLevel(logging.INFO)

    if not os.path.exists("logs"):
        os.makedirs("logs")

    proctype = "parent"
    logfname = os.path.join(
        "logs",
        mydt.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%S")
        + "-"
        + get_thisshortname()
        + "-"
        + proctype
        + "-"
        + str(os.getpid())
        + ".log"
    )
    fileHandler = logging.FileHandler(logfname)
    fileHandler.setFormatter(
        logging.Formatter(
            "%(levelname)8s [%(asctime)s  %(filename)s:%(lineno)d]  %(message)s",
            datefmt="%H:%M:%S",
        ))
    logging.getLogger().addHandler(fileHandler)
    logging.debug("logger :: {}, all args :: {}".format(logfname, args))


def set_recutility_exitcode(ret, doexit=True):
    logging.debug(f"set_recutility_exitcode returning {ret},{doexit}")

    if doexit:
        sys.exit(ret)


def main(args, parent=False, num_children=0):

    if len(sys.argv) == 1:
        print(
            "Invalid command line options configuration or none specified. Try --help"
        )
        set_recutility_exitcode(128)

    setup_logging(args, parent)
    set_recutility_exitcode(0, doexit=False)

    use_https = check_is_https(args.server)[0] or args.usehttps
    protocol = r"https" if use_https else r"http"

    if args.server == "localhost":
        server = "localhost"
    else:
        server = get_myservername(args.server)

    servertableau = r"https://" + server if use_https else r"http://" + server

    username_tableau = args.usernametableau
    password_tableau = args.passwordtableau

    personal_tokenname = args.personaltokenname
    personal_tokenvalue = args.personaltokenvalue

    server_version, build_number = get_tableauserver_version(
        protocol, server, "", args.serverversion
    )

    if args.serverversion:
        logging.debug(
            "Tableau Server version is: {}, build number is: {}".format(
                server_version, build_number))
        return 0

    connection_username = args.usernameconnection
    connection_password = args.passwordconnection

    if args.verifylogon:

        return verify_logon(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename
        )

    if args.existssite:

        return exists_site(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename
        )

    if args.existsproject:

        return exists_project(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename,
            args.sitename.lower(),
            args.projectname
        )

    num_viewtests_simple = int(
        args.runviewtestssimple) if int(
        args.runviewtestssimple) > 0 else 0

    if num_viewtests_simple > 0:
        test_type = "view_simple"

    if (
        num_viewtests_simple == 0
        and not args.verifylogon
        and not args.deletesite
        and not args.createsite
        and not args.createproject
        and not args.deleteproject
        and not args.uploadcontent
    ):
        print(
            "Invalid command line options configuration or none specified. Try --help"
        )
        set_recutility_exitcode(116)

    if args.deletesite:

        delete_site(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename
        )

    if args.createsite:

        create_site(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename
        )

    if args.deleteproject:

        delete_project(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename,
            get_site_url(args.sitename),
            args.projectname
        )

    if args.createproject:

        create_project(
            servertableau,
            username_tableau,
            password_tableau,
            personal_tokenname,
            personal_tokenvalue,
            args.sitename,
            get_site_url(args.sitename),
            args.projectname
        )

    if args.deletesite or args.createsite or args.deleteproject or args.createproject:
        return 0

    content_dir = args.contentdir
    project_name = args.projectname

    site_content_url = "" if args.siteurl == "default" else args.siteurl
    content_dir = "content" if not content_dir else content_dir

    if not project_name:

        project_name = (
            os.path.basename(os.path.dirname(content_dir + os.sep))
            if os.path.isdir(content_dir)
            else ""
        )

    DBCLASS = "postgres"
    DBSERVER = "pgsql968.online-db.prod.tableautools.com"
    DBPORT = "5432"
    DBNAME = "testworkgroup"

    if args.uploadcontent:

        site_name = args.sitename
        site_url = get_site_url(site_name)

        if content_dir != "content":

            res = True
            update_conninfo = True
            append_conn_to_name = False
            force_createproject = False

            myconnection = {}

            if connection_username and connection_username != "default":

                myconnection = {
                    "username": connection_username,
                    "password": connection_password,
                    "server": DBSERVER,
                    "dbname": DBNAME,
                    "port": DBPORT,
                    "dbclass": DBCLASS
                }

            res = upload_content(
                servertableau,
                username_tableau,
                password_tableau,
                personal_tokenname,
                personal_tokenvalue,
                args.sitename,
                site_url,
                content_dir,
                myconnection,
                None,
                project_name,
                append_conn_to_name=False,
                update_conninfo=not args.donotmodifyds and bool(myconnection),
                force_createproject=True
            )

            if not res:
                logging.error(
                    "!FAILED:: upload content failed to test content")
                set_recutility_exitcode(158)

            return 0

    if num_viewtests_simple == 0:
        return 0

    query_params = {
        "dbname": DBNAME,
        "port": DBPORT,
        "dbclass": DBCLASS,
        "server": DBSERVER
    }

    if num_viewtests_simple == 1:

        suite = unittest.TestSuite()

        suite.addTest(
            TestAPI(
                "test_view_simple",
                protocol,
                server,
                args.sitename,
                get_site_url(args.sitename),
                username_tableau,
                password_tableau,
                personal_tokenname,
                personal_tokenvalue,
                ".",
                True,
                query_params,
                server_version,
                "all",
                True,
                workbook=args.workbook,
                dashboard=args.dashboard,
                worksheet=args.worksheet
            )
        )

        logging.info(
            f"SIMPLE_VIEW {args.sitename}:: {args.workbook},{args.dashboard},{args.worksheet}")

        result = unittest.TextTestRunner(verbosity=0).run(suite)

    return 0


if __name__ == "__main__":

    import random
    import argparse

    try:

        random.seed()
        parser = argparse.ArgumentParser(
            description="""Script to run the recommendations trainer right now""",
            add_help=False
        )

        parser.add_argument(
            "--debug",
            help="print additional debug statements",
            dest="debug",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--server",
            help="tableau server machine name",
            dest="server",
            action="store",
            default="default"
        )
        parser.add_argument(
            "--personal-token-name",
            help='tableau personal token name',
            dest="personaltokenname",
            action="store",
            default=r"default"
        )
        parser.add_argument(
            "--personal-token-value",
            help='tableau personal token value',
            dest="personaltokenvalue",
            action="store",
            default=r"default"
        )
        parser.add_argument(
            "--username-tableau",
            help='tableau server username',
            dest="usernametableau",
            action="store",
            default=r"default"
        )
        parser.add_argument(
            "--password-tableau",
            help='tableau server password',
            dest="passwordtableau",
            action="store",
            default=r"default"
        )
        parser.add_argument(
            "--username-connection",
            help='data connection username',
            dest="usernameconnection",
            action="store",
            default="default"
        )
        parser.add_argument(
            "--password-connection",
            help='data connection password',
            dest="passwordconnection",
            action="store",
            default="default"
        )
        parser.add_argument(
            "--donotmodify-ds",
            help='use local Postgres database name',
            dest="donotmodifyds",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--upload-content",
            help="upload the TDS and TWB files in the content directory",
            dest="uploadcontent",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--delete-site",
            help="removes specified site from the tableau server",
            dest="deletesite",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--create-site",
            help="creates specified site on the tableau server",
            dest="createsite",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--exists-site",
            help="verifies if specified site exists on the tableau server",
            dest="existssite",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--exists-project",
            help="verifies if specified project exists on the specified server/site",
            dest="existsproject",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--create-project",
            help="creates specified project on specified site on the tableau server",
            dest="createproject",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--delete-project",
            help="deletes specified project on specified site on the tableau server",
            dest="deleteproject",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--local-directory",
            help=argparse.SUPPRESS,
            dest="contentdir",
            action="store",
            default=""
        )
        parser.add_argument(
            "--site-name",
            help='tableau server site to use. default "Default"',
            dest="sitename",
            action="store",
            default="Default"
        )
        parser.add_argument(
            "--project-name",
            help="tableau server project name. default is the same as content dir",
            dest="projectname",
            action="store",
            default=""
        )
        parser.add_argument(
            "--run-viewtests-simple",
            help='run simulated simple VIEW tests for recorded views',
            dest="runviewtestssimple",
            action="store",
            default=1
        )
        parser.add_argument(
            "--use-https",
            help=argparse.SUPPRESS,
            dest="usehttps",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--server-version",
            help="get the Tableau Server version",
            dest="serverversion",
            action="store_true",
            default=False
        )
        parser.add_argument(
            "--workbook",
            help="tableau server workbook name",
            dest="workbook",
            action="store",
            default=""
        )
        parser.add_argument(
            "--dashboard",
            help="tableau server dashboard name",
            dest="dashboard",
            action="store",
            default=""
        )
        parser.add_argument(
            "--worksheet",
            help="tableau server worksheet name",
            dest="worksheet",
            action="store",
            default=""
        )
        parser.add_argument(
            "--verify-logon",
            help=argparse.SUPPRESS,
            dest="verifylogon",
            action="store_true",
            default=False
        )

        parser_ex = argparse.ArgumentParser(parents=[parser])
        args_ex = parser_ex.parse_args()
        args_ex.siteurl = args_ex.sitename.lower()

        ret = main(args_ex, parent=True, num_children=0)

    except Exception as e:

        logging.info(f"General runtime exception caught. Root cause is: {e}")
        print(f"General runtime exception caught. Root cause is: {e}")
        raise

# The End
