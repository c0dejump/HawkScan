
from notifypy import Notify


def notify_scan_completed():
	"""
	notify_scan_completed: Send a notification when the scan if finish (only works on Linux)
	"""
	notification = Notify()
	notification.title = "Hawkscan"
	notification.message = "Scan completed"
	notification.send()

if __name__ == '__main__':
	notify_scan_completed()