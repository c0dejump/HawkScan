from modules.check_cms import check_cms
from modules.check_socketio import check_socketio
from modules.google_dorks import query_dork, query_cse
from modules.detect_waf import detect_wafw00f

class check_modules:
    """
    check_modules: To manage all module launches
    """

    def run_all_modules(self, beforeStart, url, directory, dire, thread):

        ########## Native modules ##########

        checkCms = check_cms()
        checkSocketio = check_socketio()

        """
        In Progress
        #TODO
        prescan = False
        if prescan:
            dw = detect_wafw00f(url, directory, thread)
            pre_scan(dw, url)
        """

        beforeStart.get_header(url, directory)
        beforeStart.get_dns(url, directory)
        beforeStart.letsdebug(url)
        result, v = checkCms.detect_cms(url, directory)
        if result:
            checkCms.cve_cms(result, v)
        dw = detect_wafw00f(url, directory, thread)
        beforeStart.wayback_check(dire, directory)
        beforeStart.gitpast(url)
        query_cse(url, directory)
        query_dork(url, directory)
        beforeStart.firebaseio(url)
        beforeStart.check_localhost(url)
        beforeStart.check_vhost(dire, url)
        beforeStart.check_backup_domain(dire, url)
        checkSocketio.main_socketio(url)
        if dw:
            return dw

        ########## Personal modules ##########