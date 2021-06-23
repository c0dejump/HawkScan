import os

def auto_update():
    """
    auto_update: for update the tool
    """
    updt = 0
    print("{}Checking update...".format(INFO))
    os.system("git pull origin master > /dev/null 2>&1 > git_status.txt")
    with open("git_status.txt", "r") as gs:
        for s in gs:
            if "Already up to date" not in s:
                updt = 1
    if updt == 1:
        print("{}A new version was be donwload\n".format(INFO))
        os.system("cd ../ && rm -rf HawkScan && git clone https://github.com/c0dejump/HawkScan.git")
    else:
        print("{}Nothing update found".format(INFO))
        os.system("rm -rf git_status.txt")