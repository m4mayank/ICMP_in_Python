class TimeToLiveExpired(Exception):
    def __init__(self, dest):
        message = f"Ping to {dest} failed! Time exceeded: Time To Live expired"
        super().__init__(message)


class Timeout(Exception):
    def __init__(self, timeout, dest):
        message = f"Request timeout for ICMP packet to {dest}."
        if timeout is not None:
            message += " (Timeout={}s)".format(timeout)
        super().__init__(message)
