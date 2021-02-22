Changelog:
----------
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