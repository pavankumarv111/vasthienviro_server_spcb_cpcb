import json
import base64
import os
# from Crypto.Cipher import AES
import csv
import zipfile
import time
import requests
import binascii
import pytz
from datetime import datetime, timedelta
from requests_toolbelt import MultipartEncoder
import mysql.connector

# from Crypto.PublicKey import RSA
# import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5  # For signature/Verify Signature
# from Crypto.Cipher import PKCS1_v1_5  # For encryption
# from Crypto import Random
# from Crypto import Hash
# from Crypto.Hash import SHA256
import urllib.request

BLOCK_SIZE = 32
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * '#', 'utf-8')
unpad = lambda s: s

appcb_variants = ["Andhra Pradesh", "Gujarat", "Rajasthan", "Maharashtra", "Maharashtra", "Karnataka"]
haryana_variants = ["Haryana", "Bihar", "Delhi"]
tspcb_variants = ["Telangana"]
jharkhand_variants = ["Jharkhand", "JHARKHAND"]
madhya_pradesh_variants = ["Madhya Pradesh", "Kerala", "Odisha"]




def encrypt(raw, spcb_aes_key):
    raw = pad(raw)
    iv = bytes(16 * '\x00', 'utf-8')
    cipher = AES.new(spcb_aes_key.encode('utf8'), AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(raw))


def createHeaderAuthorization(spcb_aes_key, SIGNATURE_STR1):
    text = SIGNATURE_STR1
    encrypted = encrypt(text, spcb_aes_key)  # + unix_time1
    authorization = "Basic " + encrypted.decode('utf-8')
    return authorization


def encryptaes(spcb_txt, spcb_aes_key):
    text = spcb_txt
    text1 = pad(text).decode('utf-8')
    encrypted = encrypt(text1, spcb_aes_key)  # + unix_time1
    return encrypted.decode('utf-8')


def encryptaes_mppcb(mppcb_date_line_6, mppcb_date_line_7, spcb_aes_key):
    line0 = "\n"
    line1 = "INDUSTRY NAME".ljust(72)[0:70] + "\n"
    line2 = "INDUSTRY ADDRESS".ljust(72)[0:70] + "\n"
    line3 = "INDUSTRY STATE".ljust(72)[0:70] + "\n"
    line4 = "INDIA".ljust(72)[0:70] + "\n"

    line5 = "    3    3\n"

    final_MPPCB_format = line0 + line1 + line2 + line3 + line4 + line5 + mppcb_date_line_6 + mppcb_date_line_7
    # print("text before encryption::" + pad(final_MPPCB_format).decode('utf-8'))
    text = pad(final_MPPCB_format).decode('utf-8')
    encrypted = encrypt(text, spcb_aes_key)
    # print("encryption::::" + str(encrypted))

    return encrypted.decode('utf-8')


def encrypt_with_rsa(plain_text,key_name):
    with urllib.request.urlopen("https://spcb.s3.ap-south-1.amazonaws.com/"+str(key_name)) as url:
        server_key = url.read()
    # First Public Key Encryption
    cipher_pub_obj = PKCS1_v1_5.new(RSA.importKey(server_key))
    _secret_byte_obj = cipher_pub_obj.encrypt(plain_text.encode())
    return _secret_byte_obj


def to_sign_with_private_key(plain_text, key_name):
    # Private key signature
    with urllib.request.urlopen("https://spcb.s3.ap-south-1.amazonaws.com/" + str(key_name)) as url:
        ss = url.read()
    signer_pri_obj = sign_PKCS1_v1_5.new(RSA.importKey(ss))
    rand_hash = Hash.SHA256.new()
    rand_hash.update(plain_text.encode())
    signature = signer_pri_obj.sign(rand_hash)
    return signature


def lambda_handler(event, context):
    global datetime_ist
    IST = pytz.timezone('Asia/Kolkata')

    datetime_ist = datetime.now(IST) - timedelta(seconds=40)
    timestampnormal2 = str(datetime_ist.strftime("%Y-%m-%dT%H:%M:%SZ"))
    timestampnormal = datetime_ist.strftime("%Y%m%d%H%M%S")
    timestampnormaltspcb = datetime_ist.strftime("%Y-%m-%d %H:%M:00")

    timestampnormal3 = str(datetime_ist.strftime("%Y%m%d%H%M"))[2:]

    timestampunix = str(int(str(time.time())[0:10]) - 40)
    other = ""
    spcb_aes_key = ""
    spcb_txt = ""
    spcb_site_id = ""
    spcb_monitoring_id = ""
    cpcb_industry_id = ""
    cpcb_station_id = ""
    spcb_station_id = ""
    spcb_username = ''
    spcb_password = ''
    tspcb_device_id = ''
    SOFTWARE_VERSION_ID = "ver_2.0"
    cpcb_data = []
    haryana_variants_data = []
    tspcb_variants_data = []
    jspcb_data = []
    mppcb_data_line_6 = ""
    mppcb_data_line_7 = ""
    spcb_state = ""
    responseText1 = ""
    responseText2 = ""
    responseText3 = ""
    server_error = ""
    url = "http://aprtpms.ap.gov.in/APPCB/realTimeUpload"
    data = json.loads(event)

    try:
        cmd = data['cmd']
        if cmd == '1':
            key_name = data['key_name']
            signature_string = data['signature_string']
            server_key_name = "mppcb_server.pem"
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "ency_data": str(base64.b64encode(encrypt_with_rsa(signature_string,server_key_name)))[2:-1],
                    "signature_data": str(base64.b64encode(to_sign_with_private_key(signature_string, key_name)))[2:-1]
                }),
            }
        else:
            key = data['key']
            sitedetail = data['sitedetail']
            return {
                "statusCode": 200,
                "body": str(encryptaes(sitedetail, key)),
            }
    except Exception as e:
        pass

    try:
        industry_id = data['industry_id']
        station_id = data['station_id']
        reading = data['reading']
        parameter_id = data['parameter_id']
        exceedance = data['exceedance']
        license = data['license']
        datentime = data['datentime']
        time_issue = True
        try:
            calibration = data['calibration']
        except Exception as e:
            calibration = '0'

        IST = pytz.timezone('Asia/Kolkata')
        datetime_ist = datetime.now(IST)
        if calibration == '1':
            now = datetime_ist.strftime('%Y-%m-%d %H:%M:%S')
        else:
            now = datetime_ist.strftime('%Y-%m-%d %H:%M:00')
        fmt = '%Y-%m-%d %H:%M:%S'
        minutes_diff = 200

        datetime_main = str(datetime_ist)
        minutes = datetime_main[14:16]

        if time_issue == True or time_issue == "True":
            datentime = now

        try:
            datetime_start = datetime.strptime(str(datentime), fmt)
            datetime_end = datetime.strptime(str(now), fmt)
            minutes_diff = (datetime_end - datetime_start).total_seconds() / 60
        except Exception as e:
            other = str(e)
            server_error = server_error + str(e)

        if minutes_diff < 20 and minutes_diff > -20:
            mydb = mysql.connector.connect(
                host="database-1.cr2jqoftaead.ap-south-1.rds.amazonaws.com",
                user="vasthi",
                password="+9k3ghAvyfKWE2$y",
                database="vasthi_enviro"
            )

            mycursor = mydb.cursor()
            name_str = ""
            value_format_str = ""
            val = (datentime, station_id)
            val1 = list(val)
            message = "Successfully Submitted!"
            exceedance_count = 0
            param_storage = {}
            cpcb_storage = {}
            for i in range(len(parameter_id)):
                name_str = name_str + "," + str(parameter_id[i])
                value_format_str = value_format_str + "," + "%s"
                val1.append(reading[i])
                param_storage[parameter_id[i]] = reading[i]
                cpcb_storage[parameter_id[i]] = reading[i]
                sql_param = "UPDATE stations SET last_updated = %s,last_val=%s WHERE industry_id = %s AND station_id= %s AND parameter_name = %s"
                val_param = (datentime, reading[i], industry_id, station_id, parameter_id[i][10:])
                mycursor.execute(sql_param, val_param)
                try:
                    if exceedance[i]:
                        exceedance_sql = "INSERT INTO exceedence_reports (datentime, industry_id,station_id,parameter_id,reading) VALUES (%s, %s, %s, %s, %s)"
                        val_exceedance = (datentime, industry_id, station_id, parameter_id[i][10:], reading[i])
                        mycursor.execute(exceedance_sql, val_exceedance)
                        exceedance_count = exceedance_count + 1
                        message = "Successfully Submitted! & Parameter Exceedance Noted & Num of Parameter Exceeded = "
                except Exception as e:
                    server_error = server_error + str(e)

            sql = "INSERT INTO readings.readings_"+str(industry_id)+" (datentime,station_id" + name_str + ") VALUES (%s, %s" + value_format_str + ")"
            sal_ind = "UPDATE industries SET data_fetched = %s where industry_id = %s"

            val_ind = (datentime, industry_id)
            mycursor.execute(sal_ind, val_ind)
            val2 = tuple(val1)
            mycursor.execute(sql, val2)

            val_fetch = (industry_id, station_id)
            val_fetch1 = list(val_fetch)

            sql = "SELECT stations.parameter_name,stations.cpcb_device_name,stations.cpcb_paramter_name,stations.cpcb_Unit," \
                  "stations.state_analyser_id,stations.state_paramter_id,stations.state_parameter_name,stations.state_unit_id, " \
                  "stations_details.id,stations_details.state_station_name,stations_details.cpcb_station_name, industries.industry_id, " \
                  "industries.cpcb_site_id,industries.state_site_id,industries.state_encryption,industries.state,stations.spcb_show_hide," \
                  "stations.cpcb_show_hide,stations.state_unit, industries.tspcb_username, industries.tspcb_password," \
                  "stations_details.tspcb_device_id, industries.pm10_siteid FROM stations " \
                  "LEFT JOIN stations_details ON stations_details.id = stations.station_id " \
                  "LEFT JOIN industries ON industries.industry_id = stations.industry_id WHERE stations.industry_id = %s AND  stations.station_id = %s"
            val_fetch12 = tuple(val_fetch1)
            mycursor.execute(sql, val_fetch12)
            myresult = mycursor.fetchall()

            mydb.commit()
            mycursor.close()
            mydb.close()

            result_fetched = json.loads(json.dumps(myresult))

            for spcb_param_count in range(len(result_fetched)):
                try:
                    param_value = param_storage["parameter_" + result_fetched[spcb_param_count][0]]
                except Exception as e:
                    param_value = ''
                param_analyser = result_fetched[spcb_param_count][4]
                spcb_param_id = result_fetched[spcb_param_count][5]
                spcb_param_name = result_fetched[spcb_param_count][6]
                spcb_unit_id = result_fetched[spcb_param_count][7]
                spcb_monitoring_id = result_fetched[spcb_param_count][9]
                spcb_site_id = result_fetched[spcb_param_count][13]
                spcb_aes_key = result_fetched[spcb_param_count][14]
                cpcb_industry_id = result_fetched[spcb_param_count][12]
                cpcb_station_id = result_fetched[spcb_param_count][10]
                spcb_show_hide = result_fetched[spcb_param_count][16]
                cpcb_show_hide = result_fetched[spcb_param_count][17]
                spcb_state = result_fetched[spcb_param_count][15]
                spcb_unit_name = result_fetched[spcb_param_count][18]
                spcb_station_id = result_fetched[spcb_param_count][9]
                spcb_username = result_fetched[spcb_param_count][19]
                spcb_password = result_fetched[spcb_param_count][20]
                tspcb_device_id = result_fetched[spcb_param_count][21]

                if spcb_show_hide == '1':
                    if spcb_state in appcb_variants and param_value != '' and param_value is not None:
                        spcb_txt = spcb_txt + str(spcb_site_id) + "," + str(spcb_site_id) + "," + str(
                            spcb_monitoring_id) + "," + str(param_analyser) + "," + str(spcb_param_id) + "," + str(
                            spcb_param_name) + "," + \
                                   str(param_value) + "," + str(spcb_unit_id) + "," + str("U") + "," + str(
                            param_value) + "," + str(
                            timestampunix) + "," + str("0") + "," + str("0")

                        if spcb_param_count != len(result_fetched) - 1 and spcb_txt != "":
                            spcb_txt = spcb_txt + "\r\n"
                    elif spcb_state in haryana_variants and param_value != '' and param_value is not None:
                        haryana_variants_data.append(
                            {'params': [{'timestamp': int(str(timestampunix) + "000"), 'flag': 'U',
                                         'parameter': result_fetched[spcb_param_count][6],
                                         'unit': result_fetched[spcb_param_count][18],
                                         'value': param_value}],
                             'deviceId': result_fetched[spcb_param_count][4]})
                    elif spcb_state in tspcb_variants and param_value != '' and param_value is not None:
                        tspcb_variants_data.append(
                            {"Unit": spcb_unit_name, "Flags": "", "Variablename": spcb_param_name,
                             "Value": param_value})
                    elif spcb_state in madhya_pradesh_variants and param_value != '' and param_value is not None:
                        mppcb_data_line_6 = mppcb_data_line_6 + "  1" + spcb_param_id.ljust(3)[0:3] + \
                                            spcb_param_id.ljust(16)[0:16] + spcb_unit_name.ljust(10)[0:10] + \
                                            param_analyser.ljust(18)[0:18] + "    3          0     0\n" + \
                                            spcb_site_id[5:].rjust(5)[-5:] + spcb_station_id.ljust(20)[0:20] + \
                                            "   020.257744 85.8361335           \n"
                        mppcb_data_line_7 = mppcb_data_line_7 + spcb_param_id.ljust(3)[0:3] + \
                                            spcb_site_id[5:].rjust(5)[-5:] + "    1" + \
                                            timestampnormal3 + " 0 0 0 0 1 0 0 0 0 1 0 0 0 0 1   1   0    1\nU" + \
                                            str(param_value).ljust(4) + "\n"
                    elif spcb_state in jharkhand_variants and param_value != '' and param_value is not None and (
                            minutes == '00' or minutes == '15' or minutes == '30' or minutes == '45'):
                        if spcb_param_name == "pm10":
                            jspcb_url = "https://jsac.jharkhand.gov.in/Pollution/WebService.asmx/GET_PM_DATA?"
                            VENDOR_ID = 14
                            spcb_site_id = result_fetched[spcb_param_count][22]
                        else:
                            jspcb_url = "https://jsac.jharkhand.gov.in/pollution/WebService.asmx/getdata?"
                            VENDOR_ID = 16
                        data = jspcb_url + "vender_id=" + str(VENDOR_ID) + "&industry_id=" + str(
                            spcb_site_id) + "&stationId=" + str(spcb_station_id) + "&analyserId=" + str(
                            param_analyser) + "&processValue=" + str(
                            param_value) + "&scaledValue=1000&flag=1&timestamp=" + str(
                            timestampnormal2) + "&unit=" + str(spcb_unit_id) + "&parameter=" + str(spcb_param_name)
                        jspcb_data.append(data)
                if cpcb_show_hide == '1' and param_value != '' and param_value is not None:
                    cpcb_data.append({'params': [{'timestamp': int(str(timestampunix) + "000"), 'flag': 'U',
                                                  'parameter': result_fetched[spcb_param_count][2],
                                                  'unit': result_fetched[spcb_param_count][3], 'value': param_value}],
                                      'deviceId': result_fetched[spcb_param_count][1]})

            response_str = {"status": "success", "Message": message + str(exceedance_count)}
            responseText1 = json.dumps(response_str)
        else:
            response_str = {"status": "fail", "Other": other,
                            "Message": "Time is not proper and has a difference of " + str(minutes_diff) + " minutes"}
            responseText1 = json.dumps(response_str)


    except mysql.connector.IntegrityError as e:
        response_str = {"status": "fail", "message": str(e)}
        responseText1 = json.dumps(response_str)

    try:
        if spcb_txt != "" and spcb_state in appcb_variants:
            spcb_txt = spcb_txt.strip()
            name = str(spcb_site_id) + "_" + str(spcb_monitoring_id) + "_" + str(timestampnormal) + str(".zip")
            csv_name = str(spcb_site_id) + "_" + str(spcb_monitoring_id) + "_" + str(timestampnormal) + str(".csv")

            if spcb_state == "Andhra Pradesh":
                url = "http://aprtpms.ap.gov.in/APPCB/realTimeUpload"
                SOFTWARE_VERSION_ID = "ver_2.0"
            elif spcb_state == "Gujarat":
                url = "http://aprtpms.ap.gov.in/GPCB/realTimeUpload"
                SOFTWARE_VERSION_ID = "ver_2.0"
            elif spcb_state == "Rajasthan":
                # url = "http://164.100.222.253/GLensServer/upload"
                url = "http://103.203.138.50/GLensServer/upload"
                SOFTWARE_VERSION_ID = "ver_2.0"
            elif spcb_state == "Maharashtra":
                url = "http://onlinecems.ecmpcb.in/mpcb/realtimeUpload"
                SOFTWARE_VERSION_ID = "ver_1.0"
            elif spcb_state == "Karnataka":
                url = "https://onlinekspcb.com/KSPCBServer/realtimeUpload"
                SOFTWARE_VERSION_ID = "ver_2.3"

            SIGNATURE_STR1 = spcb_site_id + "," + SOFTWARE_VERSION_ID + "," + str(timestampnormal2) + "," + spcb_aes_key

            with open('tmp/metadata.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(
                    ['SITE_ID', 'SITE_ID', 'MONITORING_ID', 'ANALYZER_ID', 'PARAMETER_ID', 'PARAMETER_NAME',
                     'READING', 'UNIT_ID', 'DATA_QUALITY_CODE', 'RAW_READING', 'UNIX_TIMESTAMP',
                     'CALIBRATION_FLAG', 'MAINTENANCE_FLAG'])
                file.close()

            with open("tmp/" + csv_name, 'w+', newline='') as file:
                writer = csv.writer(file)
                if spcb_state == "Rajasthan":
                    text1 = spcb_txt
                else:
                    text1 = encryptaes(spcb_txt, spcb_aes_key)
                text1 = str(text1)
                writer.writerow(
                    [text1])
            zf = zipfile.ZipFile("tmp/" + name, "w")
            files = [csv_name, 'metadata.csv']
            for filename in files:
                zf.write(os.path.join('', 'tmp/', filename), filename)
            zf.close()

            boundary = binascii.hexlify(os.urandom(16)).decode('ascii')
            files = {'file': (name, open("tmp/" + name, 'rb'))}
            m = MultipartEncoder(files, boundary=boundary)
            header = {
                'Timestamp': timestampnormal2,
                'siteId': spcb_site_id,
                'Date': timestampnormal2,
                'Content-Type': m.content_type,
                'Authorization': createHeaderAuthorization(spcb_aes_key, SIGNATURE_STR1),
            }

            x = requests.post(url, headers=header, data=m.to_string())
            responseText2 = str(x.text)
        elif haryana_variants_data != [] and spcb_state in haryana_variants:
            spcb_url = 'http://rtdms.cpcb.gov.in/v1.0/industry/' + spcb_site_id + '/station/' + spcb_station_id + '/data'
            api_token = "Basic NzIzYzRjODM1NzkwNDBiMzlhOWQ5ZjAzNjBjYTg2ZTI="

            if spcb_state == "Haryana":
                spcb_url = 'http://164.100.160.248/hrcpcb-api/api/industry/' + spcb_site_id + '/station/' + spcb_station_id + '/data'
                api_token = 'Basic MTMwMjIwMTlfdmFzdGhpX2VuZ2luZWVyc19wdnRfbHRkXzE1Mzg1OQ=='
            elif spcb_state == "Bihar":
                spcb_url = 'http://bpcbcems.nic.in/bpcpcb-api/api/industry/' + spcb_site_id + '/station/' + spcb_station_id + '/data'
                api_token = "Basic MTEwNzIwMjJfdmFzdGhpX2luc3RydW1lbnRzX3B2dF9sdGRfMTA1OTUy=="
            elif spcb_state == "Delhi":
                spcb_url = 'https://dpcccems.nic.in/dlcpcb-api/api/industry/' + spcb_site_id + '/station/' + spcb_station_id + '/data'
                api_token = 'Basic MjcwNTIwMTlfdmFzdGhpXzE2NTMwOA=='
                datetime_ist = datetime.now(IST) - timedelta(minutes=15)
                timestampnormal2 = str(datetime_ist.strftime("%Y-%m-%dT%H:%M:%SZ"))

            headers = {'Timestamp': timestampnormal2,
                       'Date': timestampnormal2,
                       'Content-Type': 'application/json',
                       'Content-Disposition': 'form-data',
                       'Authorization': api_token
                       }
            r1 = requests.post(spcb_url, data=json.dumps(haryana_variants_data), headers=headers)
            responseText2 = str(r1.text)
        elif tspcb_variants_data != [] and spcb_state in tspcb_variants:
            data1 = {
                "additionalInfo": {
                    "SoftwareNameVersion": "Vasthi_v2",
                    "Longitude": "78.638153",
                    "Lattitude": "17.376431"
                },
                "Name": spcb_username,
                "Password": spcb_password,
                "Variables": tspcb_variants_data,
                "Datetime": timestampnormaltspcb,
                "DeviceID": int(tspcb_device_id),
                "FunctionName": 53

            }
            headers = {'Content-Type': 'application/json'}
            url_tspcb = 'http://183.82.41.227:8080/enviroconnect/'
            r1 = requests.post(url_tspcb, data=json.dumps(data1), headers=headers,
                               timeout=10)
            responseText2 = str(r1.text) + str(data1)
        elif mppcb_data_line_6 != '' and spcb_state in madhya_pradesh_variants:

            mppcb_url = "http://esc.mp.gov.in/MPPCBServer/realtimeUpload"
            mppcb_version = "ver1.0"
            server_key_name = "mppcb_server.pem"
            if spcb_state == "Madhya Pradesh":
                mppcb_url = "http://esc.mp.gov.in/MPPCBServer/realtimeUpload"
                mppcb_version = "ver1.0"
                server_key_name = "mppcb_server.pem"
                datetime_ist = datetime.now(IST) - timedelta(minutes=4)
                timestampnormal2 = str(datetime_ist.strftime("%Y-%m-%dT%H:%M:%SZ"))
                timestampnormal = datetime_ist.strftime("%Y%m%d%H%M%S")
            elif spcb_state == "Kerala":
                mppcb_url = "http://keralapcb.glensserver.com/KSPCBGLensServer/realTimeUpload"
                mppcb_version = "ver_3.0"
                server_key_name = "kspcb_server.pem"
                datetime_ist = datetime.now(IST) - timedelta(minutes=7)
                timestampnormal2 = str(datetime_ist.strftime("%Y-%m-%dT%H:%M:%SZ"))
                timestampnormal = datetime_ist.strftime("%Y%m%d%H%M%S")
            elif spcb_state == "Odisha":
                mppcb_url = "http://ospcb-rtdas.com/OSPCBRTDASServer/realtimeUpload"
                mppcb_version = "ver1.0"
                server_key_name = "ospcb_server.pem"

            name = str(spcb_site_id) + "_" + str(spcb_station_id) + "_" + str(timestampnormal) + str(".zip")
            csv_name = str(spcb_site_id) + "_" + str(spcb_station_id) + "_" + str(timestampnormal) + str(".dat")
            SIGNATURE_STR = spcb_site_id + '^' + mppcb_version + '^' + timestampnormal2
            with open("tmp/" + csv_name, 'w', newline='') as file:
                writer = csv.writer(file)
                text2 = encryptaes_mppcb(mppcb_data_line_6, mppcb_data_line_7, spcb_aes_key)
                writer.writerow(
                    [text2])

            zf = zipfile.ZipFile("tmp/" + name, "w")
            files = [csv_name]
            for filename in files:
                zf.write(os.path.join('', 'tmp/', filename), filename)
            zf.close()

            boundary = binascii.hexlify(os.urandom(16)).decode('ascii')
            files = {'file': (name, open("tmp/" + name, 'rb'))}
            m = MultipartEncoder(files, boundary=boundary)
            ency_data = str(base64.b64encode(encrypt_with_rsa(SIGNATURE_STR,server_key_name)))[2:-1]
            authorization = "Basic " + ency_data
            signature_data = str(base64.b64encode(to_sign_with_private_key(SIGNATURE_STR, str(spcb_site_id) + ".ppk")))[
                             2:-1]

            header = {
                'Timestamp': timestampnormal2,
                'siteId': spcb_site_id,
                'Signature': signature_data,
                'Date': timestampnormal2,
                'Content-Type': m.content_type,
                'Content-Disposition': 'form-data',
                'Authorization': authorization,

            }
            x = requests.post(mppcb_url, headers=header, data=m.to_string(),
                              timeout=10)
            responseText2 = x.text
        elif jspcb_data != [] and spcb_state in jharkhand_variants:
            for jspcb_count in range(len(jspcb_data)):
                responseText2 = responseText2 + str(requests.get(jspcb_data[jspcb_count]).text)
    except Exception as e:
        responseText2 = str(e)

    try:
        if cpcb_data != []:
            headers = {
                'Timestamp': timestampnormal2,
                'Date': timestampnormal2,
                'Content-Type': 'application/json',
                'Content-Disposition': 'form-data',
                'Authorization': "Basic NzIzYzRjODM1NzkwNDBiMzlhOWQ5ZjAzNjBjYTg2ZTI="
            }
            cpcb_url = 'http://rtdms.cpcb.gov.in/v1.0/industry/' + cpcb_industry_id + '/station/' + cpcb_station_id + '/data'
            r1 = requests.post(cpcb_url, data=json.dumps(cpcb_data), headers=headers)
            responseText3 = str(r1.text)
    except Exception as e:
        responseText3 = str(e)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": str(responseText1),
            "spcb": str(responseText2),
            "cpcb": str(responseText3),
            "others": str(server_error)
        }),
    }

print(lambda_handler(json.dumps(
    '{"cmd":102, "data": "9999,26-08-2022 12:46:00,1,247,1,1,67,10,0", "device_id":"VE0010"}'

#
#   {
#     "industry_id": "453",
#     "station_id": "920",
#     "reading": [
#       0.0,
#       157722.578
#     ],
#     "parameter_id": [
#       "parameter_2",
#       "parameter_94"
#     ],
#     "exceedance": [
#       False,
#       False
#     ],
#     "datentime": "2022-04-07 20:08:00",
#     "cmd": "31",
#     "license": ""
#   }
), ''))
