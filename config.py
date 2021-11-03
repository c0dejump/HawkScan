# coding: utf-8

WARNING = "\033[31m[!] \033[0m"
SERV_ERR = "\033[33m[!] \033[0m"
FORBI = "\033[31m[x] \033[0m"
PLUS = "\033[32m[+] \033[0m"
INFO = "\033[34m[i] \033[0m"
LESS = "\033[33m[-] \033[0m"
LINE = "\033[34m-\033[0m" * 50
BACK = "\033[36m[B] \033[0m"
S3 = "\033[33m[S3] \033[0m"
EXCL = "\033[33m[E] \033[0m"
BYP = "\033[34m[BYPASSED] \033[0m"
JS = "\033[33m[JavaScript] \033[0m"
WAF = "\033[36m[WAF] \033[0m"


#Default backup extension while your test with the "-b" option
EXT_B = ['.db', '.swp', '.yml', '.xsd', '.xml', '.wml', '.bkp', '.rar', '.zip', '.7z', '.bak', '.bac', '.BAK', '.NEW', '.old', 
            '.bkf', '.bok', '.cgi', '.dat', '.ini', '.log', '.key', '.conf', '.env', '_bak', '_old', '.bak1', '.json', '.lock', 
            '.save', '.atom', '.action', '_backup', '.backup', '.config', '?stats=1', '/authorize/', '.md', '.gz', 
            '.txt', '~', '%01', "(1)"]

MINI_B = ['(1)', '.bkp', '.bak', '.bac', '.BAK', '.NEW', '.old', '_bak', '_old', '.bak1', '_backup', '.backup', '~']
