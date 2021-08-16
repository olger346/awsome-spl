# Awsome SPL
is just a cheat sheet for newbies who are learning splunk. Splunk documentation sometimes sucks or is difficult to use when you are newbie so... Use it, and Happy Splunking. Please dont forget to especify the index where is stored the data

## Ip Address
Linux Auth.log regex to capture ssh ip attempts.  
`...| rex "\s(?<Ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\s"`

## Username
For this entry we have modify /etc/sshd_config and enable SyslogFacility AUTHPRIV (almost all linux) 
Linux auth.log User ssh 
`...|rex "\s\bfor\b\s(?<user>\w{1,20})"`

## Time
Linux auth.log regex for Linux timestamp  
`(?<time>^\S{1}\w{2}\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})`  
You can find several Timestmamps on this page
https://help.sumologic.com/03Send-Data/Sources/04Reference-Information-for-Sources/Timestamps%2C-Time-Zones%2C-Time-Ranges%2C-and-Date-Formats

## Hostname
Linux auth.log hostname  
`rex "\s(?<hostname>[a-z]{1,20}\d{1,4}\s)" ` 
## Gauge visual
`index=* (rec_type_simple="FILELOG EVENT" OR rec_type_simple="FILELOG MALWARE EVENT" OR rec_type_simple="MALWARE EVENT") | rex "\bsrc_ip=\b(?<srcip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"| search srcip="10.48.10.139" | stats count as counter | gauge counter 300 500 700`

## Single value
`index=* (rec_type_simple="FILELOG EVENT" OR rec_type_simple="FILELOG MALWARE EVENT" OR rec_type_simple="MALWARE EVENT") | rex "\bsrc_ip=\b(?<srcip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"| search srcip="10.48.10.139" | stats count as counter | gauge 10 50 100`

## Sendmail
`... | sendemail to="elvis@splunk.com,john@splunk.com" format=raw subject=myresults server=mail.splunk.com sendresults=true`

Desde <https://docs.splunk.com/Documentation/Splunk/8.0.3/SearchReference/Sendemail> 

## Contar los usuarios NA en "windows Server 2008"
`* index="*" severity_id="severity_id=\"*\"" | where searchmatch("Windows Server 2008") | stats count(eval(user="N/A")) as null`

## Evaluar si las Ips son internas o externas (cidrmatch for local IPs) | Evaluate if a IP address is internal or external
`index="*" severity_id="1" | eval islocal=case(cidrmatch("10.0.0.0/8",dest_ip),"Local",cidrmatch("172.16.0.0/16",dest_ip),"Local", true(),"Externa") | table dest_ip islocal`

## Timechart Single Value (EPO McAfee critical events)
`* index="*" severity_id="1"| timechart count`

## Eval function examples
### Copy a value of a field
let's suppose that you want to copy the value of a field, in this case the field to copy is the signature of a malware so we'll have  
a query like this.
`*index=your_index | eval storage_var=signature   `

### Apply hash to a field using eval
to hash a string, timestamp or eny value we have to use **eval** function in order to get the hash of that field value
Splunk supports SHA1, MD5, SHA256 and SHA512 functions in version 8.0.0, dont forget to change **md5()** function to another one
`*index=your_index | eval md5_hash=md5(field_to_hash)`

### convert timestampt to Human readable format using eval
usually indexed time is represented by the field **_time**, working with JSON data is very common to have timestamp, the next function will return the date in ISO 8601
`*index=your_index | eval time=strftime(_time, "%Y-%m-%dT%H:%M:%S.%Q")`  

### Using eval to find not null values in a field
To find not null values we can use a function called **isnotnull()**
`*index=your_index | eval not_null_values=isnotnull(field)`

## Access JSON Objects from Logs
Is just simple as a class in some programing language, in order to access objects, just specify the (.) in the object  
`{ [-]
   event: { [-]
     CommandLine: "C:\Program Files (x86)\Internet Explorer\IEXPLORE.EXE"
     ComputerName: Hacker-PC
     DetectDescription: A process using Force Data Execution Prevention (Force DEP) tried to execute non-executable memory. The process was blocked.
     DetectId: SomeRandomCode
     DetectName: Blocked Exploit
     DocumentsAccessed: [ [+]]
}`  
In order to access the Object in this case it would be `event.CompurerName` To get the Name of the computer

### AD Created User Accounts  
   `index=*win* EventCode=4720 
| table dest_nt_domain SAM_Account_Name User_Principal_Name Account_Expires src_user src_user_phone 
| rename dest_nt_domain AS "Dominio" SAM_Account_Name AS "Username" User_Princial_Name AS "Correo" Account_Expires AS "Fecha de Expiración" src_user AS "Creado por" src_user_phone AS "No. de Telefono"`
