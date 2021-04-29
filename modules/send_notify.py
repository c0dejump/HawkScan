from notifypy import Notify


def notify_scan_completed():
	notification = Notify()
	notification.title = "Hawkscan"
	notification.message = "Scan completed"
	notification.send()