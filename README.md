# Building-Block
Cyber System Security Plan 

CONFIDENTIAL
	

Building Block
CYBER SYSTEM SECURITY PLAN 


Approvals

__________________________________
Jane Doe

  
Table of Contents
1	System Description	3
1.1	System Attributes	3
1.2	System Description and Mission	3
1.3	Security Requirements	3
1.4	System Environment	4
1.5	Network Diagram(s)	5
1.6	Dependencies and Interconnections	6
2	Plan of Action and Milestones	7
3	Security Controls	8
3.1	Access Management	8
3.1.1	EXAMPLE: Account Management	8
3.2	Personnel Security	9
3.3	Security Awareness and Training	9
3.4	Physical Security	9
3.5	System Communication Protection	9
3.6	Remote Access	9
3.7	Change Management	9
3.8	Malicious Software Protection	9
3.9	Logging Configuration	9
3.10	Media Protection	9
4	Cyber Security Incident Response Plan	10
5	Recovery Plan	11
6	Contacts – Vendor, Supplier, Internal	12



  
1	System Description
1.1	System Attributes
System Name	Trojan Bricks – Building Block
Impact Categorization	Security Category design and marketing information = {(confidentiality, moderate), (integrity, high), (availability, moderate)}
System Owner	•	Jane Doe
•	System Administrator
•	Trojan Bricks
•	Little Rock, AR
•	1 501 123 4567
•	Jane_Doe@trojanbricks.com
Security Manager	•	Scott White
•	Security Administrator
•	Trojan Bricks
•	Little Rock, AR
•	1 501 123 4567
•	Scott_White@trojanbricks.com
Primary System Administrator(s)	•	Jane Doe
•	System Administrator
•	Trojan Bricks
•	Little Rock, AR
•	1 501 123 4567
•	Jane_Doe@trojanbricks.com
Primary System Users	Trojan Brick employees, customers and vendors
1.2	System Description and Mission
The Trojan Bricks system is a general support system.  The system contains a single internet facing web server with a back-end database server, and active directory server, a file server, and a firewall. The web server itself is in a DMZ while the active directory, file server, and database server are all in an internal network that is separated from the DMZ with a firewall.
The back-end database server uses mysql and contains tables for products, customers, and orders. The Active Directory server is used to manage all employee and contractor accounts. The file server contains folders for Accounting, Board Documents, Engineering and Design, Human Resources, Marketing, and User Shares. 
The web server is accessible to the public via the internet. The back-end server has limited accessibility to front-end users, accounting, and ITWorks!. The Active Directory server is accessible by ITWorks! and Trojan Bricks Cyber Security Consultants. The File server has various levels of accessibility for each employee, department, ITWorks!, and Evolution.
1.3	Security Requirements
Requirement	Impact	Description
Confidentiality	Med	Customer accounts are protected to secure the customers identity and payment information. Trojan Bricks patents, deigns, and future plans are protected to prevent theft of organizational assets and undesired exposure of organizational plans. These protections are made from outside and within.
Integrity	High	The prevention of unauthorized modification or destruction of product design, marketing schemes, and package design is the primary task of the security system. 
Availability	Med	The webserver and back-end database will be available to customers for shopping and checking on order status will always be protected. The file will also be protected to ensure that staff availability is secured.
 
 
1.4	System Environment
Trojan Bricks is a small company with a managed system environment. As mentioned in section 1.2, the system contains a single internet facing web server with a back-end database server, an active directory server, a file server, and a firewall. The web server is in a DMZ with a firewall between it and the internal network. There are multiple desktop computers through out the network with multiple user access as well as mobile devices such as laptops, tablets, and phones. 
Special security concerns consist of unsecured wireless network, multiple users and false authentication, unsecured vendor access, malware and ransomware, phishing, improper data backup, and water sprinklers. With multiple users being present, user privileges are a special concern as well.  

1.5	Network Diagram(s)
  
1.6	Dependencies and Interconnections
●	Name of System: Building Block
●	Organization: ITWorks!
●	Type of interconnection: Internet, VPN
●	Authorizations for interconnection: ISA, MOU
●	Date of Agreement: 01/01/2020
●	FIPS 199 Category: SC information system = {(confidentiality, moderate), (integrity, moderate), (availability, moderate)}
●	Certified and Accredited
●	Jane Doe – Primary System Administrator


•	Name of System: Building Block
•	Organization: Evolution
•	Type of interconnection: Internet, VPN
•	Authorizations for interconnection: ISA, MOU
•	Date of Agreement: 01/01/2020
•	FIPS 199 Category: SC administrative information = {(confidentiality, Moderate), (integrity, Moderate), (availability, Low)}
•	Certified and Accredited
•	Jane Doe – Primary System Administrator

  
2	Plan of Action and Milestones
Use this section to specify a plan of action to address unmet or partially met security control objectives or to track vulnerability mitigation.
POAM ID	Security Control/Issue	Plan of Action	Responsible	Milestone Date
ACCESS CONTROL
001	AC-2-A  Trojan Bricks identifies and selects the following types of information system accounts to support organizational missions/business functions: individual, group, administrator, and certificate publishers. These groups are established to assign access to members of Trojan Bricks and prevent access to non-members.	Define and implement each type of information system account through Active Directory and PowerShell.	Scott White

Security Administrator

Trojan Bricks	2/21/2020
002	AC-2-C  Trojan Bricks establishes conditions for group and role membership to ensure integrity, confidentiality, and availability of protected information systems and the information stored within.	Trojan Bricks assigns proper privileges to each user and user group in accordance with Trojan Bricks policies.	Scott White

Security Administrator

Trojan Bricks	2/21/2020
003	AC-7-A  Trojan Bricks enforces a limit of three consecutive invalid logon attempts by a user during a twenty four hour period to prevent malicious users from accessing the Trojan Bricks information system.	A user lockout mechanism is implemented through the Server Manager, setting the lockout as stated. 	Scott White

Security Administrator

Trojan Bricks	2/21/2020
004	AC-7-B  Trojan Bricks automatically locks the account until released by the administrator when the maximum number of unsuccessful attempts is exceeded to prevent malicious users from accessing the Trojan Bricks information system.	Trojan Bricks implements the lockout through the Server Manager, blocking the user account until released by the administrator.	Scott White

Security Administrator

Trojan Bricks	2/21/2020
AUDIT AND ACCOUNTABILTY
005	AU-2-A  Trojan Bricks determines that the information system is capable of auditing the following events: Directory service replication, directory service access, and directory service changes, to mitigate damages caused by unwanted changes to the information system files. 	Trojan Bricks operates Windows Server 2019. The system has the capability to audit directory service activity through Group Policy Management.	Scott White

Security Administrator

Trojan Bricks	4/29/2020
006	AU-2-B  Coordinates the security audit function with other organizational entities requiring audit-related information to enhance mutual support and to help guide the selection of auditable events.	In Active Directory, auditing is given full control to audit all permissions.	Scott White

Security Administrator

Trojan Bricks	4/29/2020
007	AU-2-C  Trojan Bricks provides a rationale for why the auditable events are deemed to be adequate to support after-the-fact investigations of security incidents.	Trojan Bricks utilizes the information of the audited events to support after-the-fact investigations of security incidents by providing a detailed report highlighting the evidence found in the audit files related to the investigation.  	Scott White

Security Administrator

Trojan Bricks	4/29/2020
008	AU-2-D  Trojan Bricks determines that the following events are to be audited within the information system: Directory service replication, directory service access, and directory service changes.	In Group Policy Management, DS Access audit events are set to Success and Failure. In Active Directory, auditing is given full control to audit all permissions. 	Scott White

Security Administrator

Trojan Bricks	4/29/2020
SYSTEM AND COMMUNICATIONS PROTECTION
009	SC-7-A  Trojan Bricks Information System monitors and controls communications at the external boundary of the system and at key internal boundaries within the system to prevent intrusion from malicious users.	The Information System monitors communications at the external boundary by implementing monitoring tools through the FortiGate server capturing packets, logging session traffic, and ssl certificate inspections on incoming information being received by ports2 and/or 3 from port 1. The same is done with information transmitted to port 2 from port 3 and port 1.	Scott White

Security Administrator


Trojan Bricks	4/29/2020
010	SC-7-B  Trojan Bricks Information System implements subnetworks for publicly accessible system components that are physically separated from internal organizational networks, allowing public users to access the web server but not the internal private Trojan Bricks network.	In the IPv4 settings in the FortiGate interface, multiple subnetworks have been created to help strengthen security and narrow traffic flow within the Trojan Bricks system.	Scott White

Security Administrator


Trojan Bricks	4/29/2020
011	SC-7-C  Trojan Bricks Information System connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.	The Trojan Bricks network Is divided into an inner network and a DMZ where the Trojan Bricks Web Server exists. The division is created by a FortiGate Firewall that also divides the DMZ and the inner network to the internet. The firewall is a boundary protection device that contains many security features which Trojan Bricks implements.	Scott White

Security Administrator


Trojan Bricks	4/29/2020
012	SC-8  The information system protects the integrity and confidentiality of transmitted information including, but not limited to, customer information, order information, board documents, employee information, and designs through logical means to prevent the unauthorized disclosure of information and to detect changes to information during transmission. Failure to produce protection for transmitted information can lead to loss of integrity and confidentiality in documents transmitted over the Trojan Bricks network, to customers, and consultants.	Trojan Bricks implements an SSL certificate on the information system’s web server for secure encryption to protect transmitted information.	Scott White

Security Administrator


Trojan Bricks	3/14/2020
013	SC-8-1  The Trojan Bricks information system implements cryptographic mechanisms to prevent unauthorized disclosure of information during transmission.
	Implement  Symmetric AES-128 Encryption and Decryption algorithm key cryptosystem within the Trojan Bricks network and TLS for HTTPS connection with entities outside the Trojan Bricks firewall.	Scott White

Security Administrator


Trojan Bricks	3/14/2020
014	SC-12 Trojan Bricks establishes and manages cryptographic keys for required cryptography employed within the information system in accordance with TLS and Kerberos management systems. The purpose of the key management system is proper generation, exchange, storing, using, replacing and destroying of keys for protection of the cryptographic system preventing integrity and confidentiality from being compromised by advisories. 	Implement Kerberos key management within the Trojan Bricks network and Https for the Trojan Bricks Server.
	Scott White

Security Administrator


Trojan Bricks	3/14/2020
SYSTEM INFORMATION INTEGRITY
015	SI-3-A: Trojan Bricks implements malicious code protection mechanisms at information system entry and exit points to detect malicious code for prevention of downloading and execution of malware that may successfully penetrate the network system through email attachment, buffer overflow, etc. 	Trojan Bricks prohibits the use of personal smart devices, computers, and internet ready devices unless specified by administration. Trojan Bricks implements Windows Defender for detection and eradication of malicious software. Input and output activity are scanned and monitored.	Scott White

Security Administrator


Trojan Bricks	4/10/2020
016	SI-3-B: Trojan Bricks updates malicious code protection mechanisms whenever new releases are available to remain up to date and current on anti-virus and anti-malware updates to ensure the system is as current as possible to avoid malware intrusion.	Trojan Bricks protocol sets Windows Defender to check updates for Anti-virus and Anti-malware upon start-up, every 3 hours, and real time updates from Microsoft. 	Scott White

Security Administrator


Trojan Bricks	4/10/2020
017	SI-3-C: Trojan Bricks configures malicious code protection mechanisms that produces scans of the information upon start-up, every 2 hours and real time scans of files from external sources at the servers as the files are downloaded, opened, or executed in accordance with organizational security policy and block or quarantine malicious code and send an alert to the administrator in response to malicious code detection to ensure malicious code does not successfully run on the system and the administrator is aware of the risk.	Trojan Bricks configures Windows Defender to scan downloads, emails, and attachments at real time. Periodic scans are set for every 2 hours. Input and output activities are monitored at the server. 	Scott White

Security Administrator


Trojan Bricks	4/10/2020
018	SI-3-D: Trojan Bricks addresses the receipt of false positives during malicious code detection with protocol addressing backup, recovery, and detection adjustments to ensure that false positives are kept at a minimum to avoid costly setbacks of losing wanted processes and programs.	Trojan Bricks configures Windows Defender to use system restore points for quick recovery due to a false positive. Any false positive encountered will be listed as a safe threat to assure it will not be flagged again.	Scott White

Security Administrator


Trojan Bricks	4/10/2020
019	SI-2-A: Trojan Bricks identifies, reports, and corrects information system flaws to prevent and/or recover from exploitation of vulnerabilities by an adversary that can potentially harm integrity, availability, and confidentiality.	Trojan Bricks documents and logs system activity, monitoring failures, unexpected closures, timeouts, etc. generating reports directed to the IT department, Microsoft, etc. Trojan Bricks also regularly checks for published documentation regarding software flaws and patches.   Trojan Bricks enforces protocol pertaining to the corrective actions regarding software patching.	Scott White

Security Administrator


Trojan Bricks	4/17/2020
020	SI-2-B: Trojan Bricks test software and firmware updates related to flaw redemption for effectiveness and potential side effects before installation to ensure flaw related vulnerabilities are corrected, system functionality is not compromised, and updated software is not further flawed.	Trojan Bricks test software and firmware updates in a virtual sandbox for potential problems with compatibility. Protocol is followed to address any flaws found in the tested updates. All actions are logged and documented.	Scott White

Security Administrator


Trojan Bricks	4/17/2020
021	SI-2-C: Trojan Bricks installs security-relevant software and firmware updates within 14 days of the release of updates to allow time for functionality testing before system wide implementation. High risk vulnerability patches are tested and applied within 24 hours of release.	Trojan Bricks accesses the updates and the risk level of noted vulnerabilities. High risk vulnerabilities are addressed in high priority fashion. All other updates are tested and implemented within a two-week period of being reported.	Scott White

Security Administrator


Trojan Bricks	4/17/2020

  
3	Security Controls
3.1	Access Management
3.1.1	Account Management

Requirement:	Trojan Bricks defines and creates group and individual accounts. Accounts are created and assigned by the following organizational guidelines:
•	Individual accounts are created strictly for members of the Trojan Bricks organization
•	Group accounts are created only when necessary for Trojan Bricks organizational functions
Control Reference:	NIST 800-53, AC-2-A
Last Review and Update:	2020-May-2
Implementation:
Users and user groups are defined and created in Active Directory Users and Computers  as shown below.

                 

Requirement:	Trojan Bricks defines group and individual memberships according to member role in the organization by the following standard:
•	Individual members are assigned group memberships according to the individuals job role in Trojan Bricks
•	For an individual to gain an account in the Trojan Bricks system, the individual must be a member of the Trojan Bricks organization
•	For a group to be created in the Trojan Bricks system, the group must exist in the Trojan Bricks organization
•	Group and individual memberships are granted permissions and access to file based on what is necessary for the membership
Control Reference:	NIST 800-53, AC-2-C
Last Review and Update:	2020-May-2
Implementation:


3.1.2	Unsuccessful Logon Attempts

Requirement:	Trojan Bricks enforces a logon policy as follows:
•	Three unsuccessful logon attempts within a two hour period will lock the users account
Control Reference:	NIST 800-53, AC-7-A
Last Review and Update:	2020-May-2
Implementation:
  Account lockout is set to 3 invalid attempts within 120 minutes through Group Policy Management.

 



Requirement:	Trojan Bricks ensures account security by ensuring a locked user account remains locked until an administrator unlocks the account by user requests.
Control Reference:	NIST 800-53, AC-7-B
Last Review and Update:	2020-May-2
Implementation:
Account lockout duration is set to zero in Group Policy Management to leave the account locked unitl the administrator manually unlocks the account.

 



3.2	Personnel Security
Currently Under Construction


3.3	Security Awareness and Training
Currently Under Construction


3.4	Physical Security
Currently Under Construction


3.5	System Communication Protection
3.5.1	Boundary Protection
Requirement:	Trojan Bricks runs a FortiGate firewall that implements subnetworks and logs traffic between the DMZ and the internet and between the DMZ and the Active Directory Server
Control Reference:	NIST 800-53, SC-7-A
Last Review and Update:	2020-May-2
Implementation:
  

IPv4 Policies are created and edited to control and monitor data flow on inner and outer endpoints within the Trojan Bricks network.





Requirement:	Trojan Bricks creates subnetworks to aid in prevention of public access to the internal network of Trojan Bricks
Control Reference:	NIST 800-53, SC-7-B
Last Review and Update:	2020-May-2
Implementation:
The IPv4 policy is used to create subnetworks in the FortiGate firewall policies.

 









Requirement:	Trojan Bricks only connects to the Web Server and the internet through a controlled firewall that implements subnetworks, restrictions, and monitoring of communications in accordance to the Trojan Bricks Security Architecture
Control Reference:	NIST 800-53, SC-7-C
Last Review and Update:	2020-May-2
Implementation:
  

Trojan Bricks implements the FortiGate Firewall separating the Web Server into a DMZ, placing a security between the internet and the Web Server. The firewall also separates the internal network form the Web Server and the internet. Restrictions on traffic flow are placed through the firewall to prevent unwanted traffic from entering the inner network.

3.5.2	Transmission Confidentiality and Integrity
Requirement:	System manager implements key management systems to generate, exchange, store, use, replace and destroy keys used for encryption and decryption of communication within the Trojan Bricks network and with the Trojan Bricks web server.
•	Key generation must produce 128-bits for symmetric key algorithms and 2048 bits for public and private keys
•	Symmetric key usage for closed network and Server/Client authentication with TLS
•	Key exchange must use nonce keys and time stamps
•	 Trusted Platform Module for key storage
•	Key replacement every 18 months
•	Deactivated and compromised keys must be securely deleted
Control Reference:	NIST 800-53, SC-8/SC-8(1)
Last Review and Update:	2020-Mar-14
Implementation:
128-bit encryption and key wrapping via Kerberos within the local Trojan Blocks network. TLS encryption with public private key exchange with nonce and time stamps for web server communication.



3.5.2 	Cryptographic Key Establish
Requirement:	System manager implements key management systems to generate, exchange, store, use, replace and destroy keys used for encryption and decryption of communication within the Trojan Bricks network and with the Trojan Bricks web server.
•	Key generation must produce 128-bits for symmetric key algorithms and 2048 bits for public and private keys
•	Symmetric key usage for closed network and Server/Client authentication with TLS
•	Key exchange must use nonce keys and time stamps
•	 Trusted Platform Module for key storage
•	Key replacement every 18 months
•	Deactivated and compromised keys must be securely deleted
Control Reference:	NIST 800-53, SC-12
Last Review and Update:	2020-Mar-14
Implementation:
Kerberos is set up through Active Directory on the local network with 128-bit encryption with key life cycles of 18-month periods. TLS Server set up on the web server for 2048-bit asymmetric key encryption and exchange. Installation of TPM in the Kerberos authentication system and within the web server.

3.6	Remote Access
Currently Under Construction


3.7	Change Management
Currently Under Construction




3.8	Malicious Software Protection


3.8.1	Flaw Remediation

Requirement:	Trojan Bricks Information System Administrators check for updates daily on software utilized by the organization. Notifications are also received for updates posted by manufacturers. When updates, patches, hotfixes, etc. are identified, they are documented and corrected within the amount of time determined by the administration.
Control Reference:	NIST 800-53, SI-2-A
Last Review and Update:	2020-May-2
Implementation:
Administrators are notified about updates and patches. Once notified they document the update and install.
 

Requirement:	Software updates must be tested before installation to ensure there are no negative effects in the system due to the new update. Updates are to be done in a virtual environment for testing to keep the Information System protected
Control Reference:	NIST 800-53, SI-2-B
Last Review and Update:	2020-May-2
Implementation:
Installation of Windows Defender ATP is required to implement a sandbox for virtualization to allow updates to be applied for testing without effecting the Information System






Requirement:	Trojan Bricks requires updates to be tested and applied within 14 days of notification. Hot fixes, patches, and high risk updates are tested and installed within 24 hours.
Control Reference:	NIST 800-53, SI-2-C
Last Review and Update:	2020-May-2
Implementation:
Time limits are set for updates in the Group Policy Management Windows Update.
 

3.8.2	Malicious Code Protection
Requirement:	•	System Manager configures the Windows Defender for optimal malware intrusion detection. Incoming and outgoing files are scanned at the web server. All emails, downloads, and attachments are scanned at real time.
Control Reference:	NIST 800-53, SI-3(A)
Last Review and Update:	2020-April-14
Implementation:
Windows Defender is configured for scanning of all incoming and outgoing activity. Windows defender also scans all emails, downloads, and attachments. 
 



Requirement:	Malicious Code Protection Mechanisms will always be up to date . The system administrator will ensure that updates are scheduled reasonably to keep the system up to date and protected while not interfering with daily traffic.
Control Reference:	NIST 800-53, SI-3(B)
Last Review and Update:	2020-April-10
Implementation:
Signature updates are checked upon startup. They are also checked every 3 hours after startup. Real-time definition updates are running from Microsoft updates. Upon startup the latest virus and spyware definitions are checked. 




Requirement:	Periodic and real-time scans are required of system files, processes, executables, emails, downloads, and attachments to check for signatures within files.
Control Reference:	NIST 800-53, SI-3(C)
Last Review and Update:	2020-April 10
Implementation:
Windows Defender performs periodic quick scans every 2 hours and full scans including all mapped network drives every 12 hours.  


Requirement:	System Manager shall maintain protocol for false positives in malware detection to ensure recovery, non-repetition, and mitigation. 
Control Reference:	NIST 800-53, SI-3(D)
Last Review and Update:	2020-April-10
Implementation:
System Manager configures Windows Defender to contain restore points in the system for necessary system restoration due to false positives. Administrator is notified and the false checked executable is marked as safe to avoid second false detection in Windows Defender Antivirus/Threats.




3.9	Logging Configuration

3.9.1	Audit Events
Requirement:	Trojan Bricks inner network contains Active Directory, which allows Trojan Bricks to audit Directory service Replication, Access, and Changes.
Control Reference:	NIST 800-53, AU-2-A
Last Review and Update:	2020-May-2
Implementation:
Audit events for directory service replication, access, and changes are set to audit success and failures through the group policy management in the Active Directory.

 

Requirement:	Trojan Bricks audits other information to improve security in the information system by auditing: 
•	Account logon events
•	Account management
•	Directory service access
•	Logon events
•	Object access
•	Policy change
•	Privilege use
•	Process tracking
•	System events
Control Reference:	NIST 800-53, AU-2-B
Last Review and Update:	2020-May-2
Implementation:
The audit policy in local policies are all set to audit the success and failure as shown below

 

Requirement:	Trojan Bricks audits a wide variety of actions in the information system to help track malicious activity for ease of locating where and when any malicious activities may have taken place and also by what user account was used to take such action.
Control Reference:	NIST 800-53, AU-2-C
Last Review and Update:	2020-May-2
Implementation:
Trojan Bricks is prepared to write a full report documenting audited processes and the reasoning for the auditing. If malicious activity does occur and a report is required to be created, Trojan Bricks will present all audited actions related to the incident with reasoning as to why auditing was necessary. 

Requirement:	Trojan Bricks determines auditing all permission events, local events, and directory service events is required for information system security.
Control Reference:	NIST 800-53, AU-2-D
Last Review and Update:	2020-May-2
Implementation:
Trojan Bricks has defined a large scale audit policy through the group policy management and placed every user of the system within the group policy.

 

3.10	Media Protection
Currently Under Construction
 
4	Cyber Security Incident Response Plan
Currently Under Construction
  
5	Recovery Plan
Currently Under Construction
  
6	Contacts – Vendor, Supplier, Internal
<See NIST 800-18, Section 3.5>
Company	Contact	Phone Number	Email Address	URL	Support Credentials	Special Instructions
						

