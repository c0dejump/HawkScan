Changelog:
----------

- 2.3
---------
	Started: Add proxy function (--proxy proxy.lst) [In progress]
	New: Adding path disclosure recon
	New: Detecting potential hidden directory
	Updated: dichawk endpoints
---------

- 2.2
---------
	New: Wiki created !
	Fixed: any bugs and redesign titles pre-scan
	Changed: waybacktool module deleted by a personal module (less slow)
---------

- 2.1
---------
	New: Option -nfs (not first step) to pass the first recon steps
	Fixed: Any bug with the download file and bypass forbidden when differents options
	New: Google cse search (buckets...)
	New: Add LICENSE & PyPI version and stats
---------

- 2.0
---------
	Redefining priorities/tasks
	New: Let's debug certificate subdomains results
	New: Display the current bypass number during scan ("CB:")
	New: Easter egg for xmas :)
	Updated: Fix any bugs

---------

- 1.9.9
---------
	New: Cloudflare protection detection in live
	Updated: Bugs correction with backup extension scan
---------

- 1.9.8
---------
	Updated: New ways to bypass forbidden (Thanks @yunem_se !)
	Updated: New socketio endpoints
	Updated: New words in dichawk.txt
---------

- 1.9.7
---------
	Updated: New logo by @__PH4NTOM__!
---------

- 1.9.6
---------
	Fixed:	 Any bugs
	Updated: Little style modifications
---------

- 1.9.5
---------
	Fixed: A pass on the source code, more speedy
---------

- 1.9.4
---------
	Added: 	Function "vim_backup" to test backup vim during scan when any -b option
---------

- 1.9.3
---------
	Updated: New banner
	Fixed:	 Multiple website with file which contain url

- 1.9.2:
---------
	Updated: code review & optimisation
	Updated: Multiple new paths/words in dichawk.txt
---------

- 1.9.1
---------
	Added: 	 Option "-f" for scanning multiple website to one time. Ex: ```-f urls_file.txt```
	Updated: Clean code & directory
---------

- 1.9
---------
	Fixed: Fixed percentage & line count bug during scan
	Added: Display errors number in live during scan 
---------

- 1.8.8
---------
	Added: Output file format function. Available formats: json, csv, txt. Ex: ```-of json```, ```-o /tmp/Target -of csv```
---------

- 1.8.7
---------
	Fixed: Reduction of false positives number
	Added: Header of Hawkscan when your typing "head hawkscan.py"
---------

- 1.8.6
---------
	Fixed:	 Any bugs: Thread modification, header parameters, bypass forbidden & any others...
	Added: 	 google module in requirements/setup
	Updated: Deleted degoogle modules/script, google dork works now with the "googlesearch" module
	Updated: A little style modification
	Updated: Default thread now 30
---------

- 1.8.5:
---------
	Added: 	A new restriction bypass feature, that test "post,put,patch & option" requests methods on a restriction page
	Fixed: 	The little style display problems
---------

- 1.8.4
---------
	Fixed: 	Better display of live lines
	Added: 	A new file to manage the modules to launches
---------

- 1.8.3
---------
	Fixed: 	Bug in socketio module
	Fixed: 	Add size bytes during th error scan
	Added: 	Words in wordlist
---------

- 1.8.2
---------
	Updated: New logo made by Cyber_Ph4ntoM
	Updated:  Code review
	Updated:  Add multiple words in dichawk.txt
---------

- 1.8.1
---------
	Updated:  Style refont
	Fixed:    Mutliple bugs
---------

- 1.8
---------
	Update:   you can choose your backup file when you scan, EX:
		-b: default all backup file
		-b .bck, .old, .bak: just these backups

- 1.7.9
---------
	Updated:  dico.txt → dichawk.txt (dico.txt it was to simple for a personal dictionary :)
	Fixed:    Bug on parsing JS
---------

- 1.7.8
---------
	Fixed:    Bug on the exclude function
	Fixed:    Bug on the bypass forbidden function
	Added:    News header value in bypass forbidden function
---------

- 1.7.7
---------
	Updated:  Rrefont helping style
	Added:    Notify when scan completed (Only work on Linux)
---------

- 1.7.6
---------
	Added: New function added: check_socketio(), to check the websocket requests during the first step. That can potentially leak any informations (path, message, users...). Adding too in JS verification to check if any endpoint look like socketio.
	Fixed: Reducted false positive number
---------

- 1.7.5
---------
	Deleted: WhoIs function (useless)
	Updated: Style refont
---------

- 1.7.4
---------
	Updated: Dockerfile
	Added: A resume of commands (url, threads...) during the begin scan
---------

- 1.7.3
---------
	Updated: setup.py
---------

- 1.7.2
---------
	Updated: Add new content in google dork, dico and javascript recon
	Updated: Real setup.py :)
---------

- 1.7.1
---------
	Fixed: Any bugs
	Modified: Raw output, modification for any integration
---------

- 1.7
---------
	Added: Function "check_backup_domain" added, test before start "domain.zip/rar etc.."
	Added: New option (-ffs) to force the first step of scan during the first running (waf, vhosts, wayback etc...)
---------

- 1.6.9
---------
	Added: multiple excludes (only number or bytes number), exemple: --exclude 403,500 // --exclude 1337b,500...
---------

- 1.6.8
---------
	Fixed: Bugs
	Modified: function "check_ip" which check if the IP o the website was different by domain name => Now: check_vhost
---------

- 1.6.7
---------
	Added: Option --auth for HTTP authentification. Exemple --auth admin:admin
	Fixed: Bugs
---------

- 1.6.6
---------
	Faster
	Updated: Less FP with bypass forbidden function
	Updated: Less errors in princpal script
	Updated: Little modifications in report
	Fixed: Style and system bugs
	Added: Auto resize relative to window
---------

- 1.6
---------
	Added: "degoogle" tools for google dork queries, more fast and less of google captcha
	Updated: Code optimization
---------

- 1.5.9.1
---------
	Fixed: System bugs
---------

- 1.5.9
---------
	Started: Code optimization
	Updated: Changed changelog.md + Readme.md
---------

- 1.5.8
---------
	Updated: file and directory function management
			A directory of the website is automatically create like: "website_date/".	
			And if the directory exist an other directory is created like: "website date_hour/"
---------

- 1.5.7
---------
	Added: Function to try if the website IP is different of the website domain
	Updated: dico.txt
---------
	
- 1.5.6
---------
	Fixed: system bugs
	Added: New exclude type, now you can exclude a number of byte with "b" at the end in your number, like: --exclude 550b
---------
	
- 1.5.5
---------
	Added: Google dork requests at the first scan
---------
	
- 1.5.4
---------
	Added: Option "--js" for scan and analyse JS
	Deleted: "dryscrape" librarie for the moment, many error with it, I'll remake it later
---------
	
- 1.5.3
---------
	Added: Setup.py, you can just doing "python setup.py"
---------
	
- 1.5.2
---------
	Added: Try differents bypass for 403 code error
	Updated: dico.txt
---------
	
- 1.5.1
---------
	New banner
	Fix bugs
---------
	
- 1.5
---------
	~~Auto activate JS during scan if the webite is full JS (website 2.0)~~
---------
	
- 1.4
---------
	Add: Dockerfile
---------
	
- 1.3.3
---------
	Add: New function which try automatically if it's possible scanning with "localhost" host
---------
	
- 1.3.2
---------
	Replace: "--cookie" by "-H" for different header values; ex: -H "Host:test" // -H "Authentification:cookie" (not space after ":" or "=")
---------
	
- 1.3.1
---------
	Code review
	New logo
	Adding Changelog
---------
	
- 1.2
---------
	Adding news words in dico.txt (old dico_extra.txt)
	Adding extensions in backup check test function, option -b (.json, .xml, .bkp...) => very long
	Test bypass of waf rate limited in real time (X-Originating-IP...)
	Exclude response http code (--exclude 403)
	Filter on response http code in report
---------
	
- 1.0
---------
  	Better management Threads
	Add news words in dico_extra.txt
	New style for the report
	Errors log management
---------