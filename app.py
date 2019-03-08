from flask import Flask, request, jsonify
from helper import WXBizMsgCrypt

app = Flask(__name__)

corp_id = 'wwdbdd26e737810033'
Token = 'NmKdkjn2KS'
EncodingAESKey = 'w9oL3Y2IYXOSTXO91CpgSalUWpHTQTk9x2BuGoE19Kt'


@app.route('/', methods=['POST', 'GET'])
def hello_world():
    req = request.values

    echostr = req.get('echostr')

    # echostr = 'KKRCgXtg6CffOdcapC0qCTffFS18Weo9Y8Eid4XynJeBAkQ2E5Wvob3NHOTJUVvs9g+I5D0XeevcxGfL+80tHA=='
    crypt = WXBizMsgCrypt(EncodingAESKey, Token, corp_id)

    verification_url = crypt.verification_url(echostr)

    print(verification_url)
    msg = verification_url[0]

    resp = msg
    print(msg)
    return resp


if __name__ == '__main__':
    app.run()
