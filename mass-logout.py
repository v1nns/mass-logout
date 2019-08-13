#!/usr/bin/python3
import cookiemanager;

if __name__ == "__main__":
    cj = cookiemanager.chrome().logout_from_sites()
    # for cookie in cj:
    #     print ('name', cookie.name, 'value', cookie.value, 'domain', cookie.domain)