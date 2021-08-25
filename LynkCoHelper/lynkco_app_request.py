#!/usr/bin/python3

import requests
import ddddocr
import os
import platform
import base64
from com.uestcit.api.gateway.sdk import lynco_api_auth as authsdk
from com.uestcit.api.gateway.sdk.util import UUIDUtil

class lynkco_app_request():
    """接口请求封装类"""
    def __init__(self, app_key, app_secret):
        self.__host = 'https://app-services.lynkco.com.cn:443'
        self.__app_key = app_key
        self.__app_secret = app_secret
        self.__lynco_api_auth = authsdk.LyncoApiAuth(app_key = self.__app_key, app_secret = self.__app_secret)
        pass

    def login(self, username, password):
        """APP端登录"""
        uuid = UUIDUtil.get_uuid()
        verifyCodeRes = self.get_verify_code(uuid);
        verifyCode = self.get_verify_code_str(verifyCodeRes['data'])
        params = { 'deviceType': 'ANDROID', 'username': username, 'password': password, 'verificationCode': verifyCode, 'nonce': uuid}
        response = requests.post(self.__host + '/auth/login/login/v2', params = params, data = {}, auth = self.__lynco_api_auth, proxies = {});
        return response.json()
       
    def member_info(self, token, userid):
        """APP端获取用户信息（CO币余额等信息）"""
        params = { 'id': userid }
        headers = { 'token': token }
        response = requests.get(self.__host + '/app/member/service/memberInFo', params = params, data = {}, auth = self.__lynco_api_auth, proxies = {}, headers = headers);
        return response.json()

    def get_co_by_share(self, token, userid):
        """APP端每日分享获取5Co币，每天可以操作3次"""
        params = { 'accountId': userid, 'type': 3 }
        headers = { 'token': token }
        response = requests.post(self.__host + '/app/v1/task/reporting', params = params, data = {}, auth = self.__lynco_api_auth, proxies = {}, headers = headers);
        return response.json()
    def get_verify_code(self, uuid):
        params = {'mobile':uuid}
        response = requests.get(self.__host + '/auth/login/verifycode/image', params = params, data = {}, auth = self.__lynco_api_auth, proxies = {});
        return response.json()
    def get_verify_code_str(self, imgdata):
        sysstr = platform.system()
        file_dir = ""
        file_path = ""
        if(sysstr == 'Windows'):
            file_dir = os.getcwd() + "\\com\\image"
            file_path = file_dir + "\\0.jpg"
        else:
            file_dir = os.getcwd() + "/com/image"
            file_path = file_dir + "/0.jpg"
        if not os.path.exists(file_dir):
            os.mkdir(file_dir)
        with open(file_path, 'wb') as f:
            f.write(base64.b64decode(imgdata))
        ocr = ddddocr.DdddOcr()
        with open(file_path, 'rb') as f:
            img_bytes = f.read()
        res = ocr.classification(img_bytes)
        print("验证码:"+res)
        return res