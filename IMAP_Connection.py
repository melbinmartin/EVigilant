#!/usr/bin/env python3

import sys
import time 
import re
import imaplib
import email
import pprint
from termcolor import colored
import os 
from urlextract import URLExtract 
from linkChecker import * 
from attachments_checker import *

#print(GetStatus())
#print(GetStatus2())

usermail = 'somelife48@gmail.com'
userpassword = 'rdxm fasv tzsz nuno'
api_key = '658a08fb4bfed92acd52df9f5a02b66405e984f0e85cb0f0a7804bd6fd4c9913'

def Main_Function():
    global usermail, userpassword, api_key
    print(colored('[+] New Mail Received !!','green'))
    print()
    itemlist = data[0].split()
    #print(itemlist)
    mostrecent = itemlist[-1]
    y=print("printing most recent email id ")
    print(mostrecent)
    print()
    result,email_data = imap.uid('fetch',mostrecent,'(RFC822)')
    raw_email = email_data[0][1].decode('utf-8')
    email_message = email.message_from_string(raw_email)
    print("From    : " + email_message['from'])
    print("To      : "+ email_message['to'])
    if(email_message['subject'] != ""):
        print("Subject : "+ email_message['subject'])
    print()
    print("-" * 70)
    print()

    email_info = {}
    links_info = []
    attachments_info = []

    # Modify your code to capture information
    email_info['from'] = email_message['from']
    email_info['to'] = email_message['to']
    email_info['subject'] = email_message['subject']

    
    #print("making email unread")
    # This is in working condition    
    
    #res1,data1 = imap.uid('store',mostrecent,'-FLAGS','(\\Seen)')   
    
    #print("Response : ",res1)    
    for item in email_message.walk():
        #print("Item 1 : "+item)
        if(item.get_content_type() == 'text/html'):
            #print(item)
            #print("="*78)
            t = str(item)
            # Calling function link Extactor 
            print(colored('[+] Extracting all the links...','green'))
            print()
            link_extractor(t)
            print()
            print("-"*70)
            print()        
    print(colored('[+] Retrieving all the Attachments...','green'))
    print(colored('[+] Creating a Directory [Attachments] to Store attachments ...','green'))
    print()


    for item in email_message.walk():
        if item.get_content_type() == 'text/html':
            # Extract links
            links_info.extend(link_extractor(t))

    for item in email_message.walk():
        if item.get_content_maintype() != 'multipart' and item.get('Content-Disposition') is not None:
            # Extract attachment filenames
            attachments_info.append(item.get_filename())

    # Your existing code here

    return email_info, links_info, attachments_info
    path_dir = os.getcwd() + "/Attachments/"
    #print("printing path for directory !!!!!!!!! "+ path_dir)
    if(os.path.isdir(path_dir)):
        pass
    else:
        os.system("mkdir Attachments")
    for item in email_message.walk():
        if(item.get_content_maintype() != 'multipart' and item.get('Content-Disposition') is not None ):
            # To download the file we use item.get_payload(decode=True)
            # To get the file name we use item.get_filename()
            # Make a directory and save all the attachment in that folder 
            print(item.get_filename())
            file_name = item.get_filename()
            if bool(file_name):
                subpath = os.getcwd()
                subpath = subpath + "/Attachments/"
                filepath = os.path.join(subpath,file_name)
                #filepath = os.path.join('/root/Email_Virus_Checker/attachments/',file_namie)
                #print("file Path : " + filepath)
                if not os.path.isfile(filepath):
                    fpo = open(filepath,"wb")
                    fpo.write(item.get_payload(decode=True))
                    fpo.close()    
            #fp = open("/root/attachments/","wb")
            #fp.write(item.get_payload(decode=True))
            #fp.close()
    print()
    print("-" * 70)
    print()
    print(colored('[+] Scanning Triggered For Links','green'))
    print() 
    # Link Scanner at this place :
    
    linkchecker(api_key)
    
    print()
    print("-"*70)
    print()
    print(colored('[+] Scanning Triggered for Attachments','green'))
    print(colored('[+] It may takes some time Sit Back and Relax ','yellow'))
    print() 
    # Attachments Scanner at this place : 
    time.sleep(60)    
    attachments_checker(api_key)
    
    print()
    print("-" * 70)
    print()
    if (GetStatus() == False or GetStatus2() == False):
        error()
    else:
        print(colored('NO WARNING !! Your Email is Clean ','green'))
        
        #imap.uid('store',mostrecent,'-FLAGS','(\\Seen)')   

    print()
    print("-"*70)
    print()
    return x,y
     	

# Error Messages 
def error():
    print(colored(" [-] WARNING !! We Found Some Malicious thing in your mail !!!",'red'))
    t = input(colored(' Do You Want to Delete this mail y/n :','red'))
    if(t == 'y' or t == 'Y'):
        print(colored(' [+] Deleting Email...','yellow'))
        res2,data2 = imap.uid('store',mostrecent,'+FLAGS','(\\Deleted)')
        imap.expunge()
        #Imap Expunge Method Permanently removes all the messages marked as deleted from the currently selected folder
        print(colored(" [+] Email Deleted ",'green'))
        
    else:
        print(colored('Okay ...','red'))
        print()

# Initialize variables to capture outputs
    
# Prining banner 


print(os.getcwd())

def link_extractor(paragraph):
    extractor = URLExtract()
    urls = extractor.find_urls(paragraph)
    file_links = open("links.txt","w")
    for links in urls :
        print(links)
        file_links.write(links+"\n")

    
usermail = usermail
userpassword = userpassword
api_key = api_key

imap_host = 'imap.gmail.com'
imap_user = usermail
imap_pass = userpassword

pass1 = False
# Connect to host over ssl 

imap = imaplib.IMAP4_SSL(imap_host)

try :
    imap.login(imap_user,imap_pass)
    print()
    print("-"*70)
    print()
    print(colored('[+] Login Successful !!!','green'))
    print()
    print(colored('[+] Starting Your Server ','green'))
    print()
    print("-"*70)
    print()
    # Now this try block get green signal 
    pass1 = True
except:
    print()
    print("-"*70)
    print()
    print(colored('[-] Invalid Credentials !!!','red'))
    print()
    print(colored('[-] Cannot Start the Server ','red'))
    print()
    print("-"*70)
    print()
print(colored("[+] Started Fetching all the mails...",'green'))
print()

#print()
#print("-"*70)
#print()
while True :
    if pass1:
        stat, cnt = imap.select('INBOX')
        result, data = imap.uid('search',None , 'ALL')
        (retcode,message) = imap.uid('search',"UNSEEN")
        #print(retcode)
        length = len(message[0].split())
        #print(length)
        if(length != 0):
            #print(colored(" [+] New Message Found !!!",'green'))
            print()
            Main_Function()
            final_path = os.getcwd()
            #final_path2 = final_path + "/links.txt"
            #final_path = final_path + "/Attachments/"
            # Deleting all the unneccecary file  
            os.system("rmdir /s /q Attachments")
            os.system("del links.txt")
            
        else:
            continue

